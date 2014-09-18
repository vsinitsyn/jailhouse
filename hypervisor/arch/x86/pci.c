/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2014
 *
 * Authors:
 *  Ivan Kolchin <ivan.kolchin@siemens.com>
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/control.h>
#include <jailhouse/mmio.h>
#include <jailhouse/pci.h>
#include <jailhouse/printk.h>
#include <jailhouse/utils.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <asm/pci.h>
#include <asm/vm.h>

/* protects the root bridge's PIO interface to the PCI config space */
static DEFINE_SPINLOCK(pci_lock);

/**
 * arch_pci_read_config() - Read from PCI config space via PIO method
 * @bdf:	16-bit bus/device/function ID of target
 * @address:	Config space access address
 * @size:	Access size (1, 2 or 4 bytes)
 *
 * Return: read value
 */
u32 arch_pci_read_config(u16 bdf, u16 address, unsigned int size)
{
	u16 port = PCI_REG_DATA_PORT + (address & 0x3);
	u32 value;

	spin_lock(&pci_lock);

	outl(PCI_ADDR_ENABLE | (bdf << PCI_ADDR_BDF_SHIFT) |
	     (address & PCI_ADDR_REGNUM_MASK), PCI_REG_ADDR_PORT);
	if (size == 1)
		value = inb(port);
	else if (size == 2)
		value = inw(port);
	else
		value = inl(port);

	spin_unlock(&pci_lock);

	return value;
}

/**
 * arch_pci_write_config() - Write to PCI config space via PIO method
 * @bdf:	16-bit bus/device/function ID of target
 * @address:	Config space access address
 * @value:	Value to be written
 * @size:	Access size (1, 2 or 4 bytes)
 */
void arch_pci_write_config(u16 bdf, u16 address, u32 value, unsigned int size)
{
	u16 port = PCI_REG_DATA_PORT + (address & 0x3);

	spin_lock(&pci_lock);

	outl(PCI_ADDR_ENABLE | (bdf << PCI_ADDR_BDF_SHIFT) |
	     (address & PCI_ADDR_REGNUM_MASK), PCI_REG_ADDR_PORT);
	if (size == 1)
		outb(value, port);
	else if (size == 2)
		outw(value, port);
	else
		outl(value, port);

	spin_unlock(&pci_lock);
}

/**
 * set_rax_reg() - Set value of RAX in guest register set
 * @guest_regs:	Guest register set
 * @value_new:	New value to be written
 * @size:	Access size (1, 2 or 4 bytes)
 */
static void set_rax_reg(struct registers *guest_regs,
	u32 value_new, u8 size)
{
	u64 value_old = guest_regs->rax;
	/* 32-bit access is special, since it clears all the upper
	 *  part of RAX. Another types of access leave it intact */
	u64 mask = (size == 4 ? BYTE_MASK(8) : BYTE_MASK(size));

	guest_regs->rax = (value_old & ~mask) | (value_new & mask);
}

/**
 * get_rax_reg() - Get value of RAX from guest register set
 * @guest_regs:	Guest register set
 * @size:	Access size (1, 2 or 4 bytes)
 *
 * Return: Register value
 */
static u32 get_rax_reg(struct registers *guest_regs, u8 size)
{
	return guest_regs->rax & BYTE_MASK(size);
}

/**
 * data_port_in_handler() - Handler for IN accesses to data port
 * @guest_regs:		Guest register set
 * @device:		Structure describing PCI device
 * @address:		Config space access address
 * @size:		Access size (1, 2 or 4 bytes)
 *
 * Return: 1 if handled successfully, -1 on access error
 */
static int
data_port_in_handler(struct registers *guest_regs, struct pci_device *device,
		     u16 address, unsigned int size)
{
	u32 reg_data;

	if (pci_cfg_read_moderate(device, address,
				  size, &reg_data) == PCI_ACCESS_PERFORM)
		reg_data = arch_pci_read_config(device->info->bdf, address,
						size);

	set_rax_reg(guest_regs, reg_data, size);

	return 1;
}

/**
 * data_port_out_handler() - Handler for OUT accesses to data port
 * @guest_regs:		Guest register set
 * @device:		Structure describing PCI device
 * @address:		Config space access address
 * @size:		Access size (1, 2 or 4 bytes)
 *
 * Return: 1 if handled successfully, -1 on access error
 */
static int
data_port_out_handler(struct registers *guest_regs, struct pci_device *device,
		      u16 address, unsigned int size)
{
	u32 reg_data = get_rax_reg(guest_regs, size);
	enum pci_access access;

	access = pci_cfg_write_moderate(device, address, size, reg_data);
	if (access == PCI_ACCESS_REJECT)
		return -1;
	if (access == PCI_ACCESS_PERFORM)
		arch_pci_write_config(device->info->bdf, address, reg_data,
				      size);
	return 1;
}

/**
 * x86_pci_config_handler() - Handler for accesses to PCI config space
 * @guest_regs:		Guest register set
 * @cell:		Issuing cell
 * @port:		I/O port number of this access
 * @dir_in:		True for input, false for output
 * @size:		Size of access in bytes (1, 2 or 4 bytes)
 *
 * Return: 1 if handled successfully, 0 if unhandled, -1 on access error
 */
int x86_pci_config_handler(struct registers *guest_regs, struct cell *cell,
			   u16 port, bool dir_in, unsigned int size)
{
	struct pci_device *device;
	u32 addr_port_val;
	u16 bdf, address;
	int result = 0;

	if (port == PCI_REG_ADDR_PORT) {
		/* only 4-byte accesses are valid */
		if (size != 4)
			goto invalid_access;

		if (dir_in)
			set_rax_reg(guest_regs, cell->pci_addr_port_val, size);
		else
			cell->pci_addr_port_val =
				get_rax_reg(guest_regs, size);
		result = 1;
	} else if (port >= PCI_REG_DATA_PORT &&
		   port < (PCI_REG_DATA_PORT + 4)) {
		/* overflowing accesses are invalid */
		if (port + size > PCI_REG_DATA_PORT + 4)
			goto invalid_access;

		/*
		 * Decode which register in PCI config space is accessed. It is
		 * essential to store the address port value locally so that we
		 * are not affected by concurrent manipulations by other CPUs
		 * of this cell.
		 */
		addr_port_val = cell->pci_addr_port_val;

		bdf = addr_port_val >> PCI_ADDR_BDF_SHIFT;
		device = pci_get_assigned_device(cell, bdf);

		address = (addr_port_val & PCI_ADDR_REGNUM_MASK) +
			port - PCI_REG_DATA_PORT;

		if (dir_in)
			result = data_port_in_handler(guest_regs, device,
						      address, size);
		else
			result = data_port_out_handler(guest_regs, device,
						       address, size);
		if (result < 0)
			goto invalid_access;
	}

	return result;

invalid_access:
	panic_printk("FATAL: Invalid PCI config %s, port: %x, size %d, "
		     "address port: %x\n", dir_in ? "read" : "write", port,
		     size, cell->pci_addr_port_val);
	return -1;

}

int arch_pci_add_device(struct cell *cell, struct pci_device *device)
{
	return iommu_add_pci_device(cell, device);
}

void arch_pci_remove_device(struct pci_device *device)
{
	iommu_remove_pci_device(device);
}

static union x86_msi_vector pci_get_x86_msi_vector(struct pci_device *device)
{
	union pci_msi_registers *regs = &device->msi_registers;
	bool msi_64bits = device->info->msi_64bits;
	union x86_msi_vector msi;

	msi.raw.address = msi_64bits ? regs->msg64.address :
				       regs->msg32.address;
	msi.raw.data = msi_64bits ? regs->msg64.data : regs->msg32.data;
	return msi;
}

static struct apic_irq_message
pci_translate_msi_vector(struct pci_device *device, unsigned int vector,
			 unsigned int legacy_vectors, union x86_msi_vector msi)
{
	struct apic_irq_message irq_msg = { .valid = 0 };
	unsigned int idx;

	if (iommu_cell_ir_emulation(device->cell)) {
		if (!msi.remap.remapped)
			return irq_msg;

		idx = msi.remap.int_index | (msi.remap.int_index15 << 15);
		if (msi.remap.shv)
			idx += msi.remap.subhandle;
		return iommu_get_remapped_root_int(device->info->iommu,
						   device->info->bdf,
						   vector, idx);
	}

	irq_msg.vector = msi.native.vector;
	if (legacy_vectors > 1) {
		irq_msg.vector &= ~(legacy_vectors - 1);
		irq_msg.vector |= vector;
	}
	irq_msg.delivery_mode = msi.native.delivery_mode;
	irq_msg.level_triggered = 0;
	irq_msg.dest_logical = msi.native.dest_logical;
	irq_msg.redir_hint = msi.native.redir_hint;
	irq_msg.valid = 1;
	irq_msg.destination = msi.native.destination;

	return irq_msg;
}

void pci_suppress_msi(struct pci_device *device,
		      const struct jailhouse_pci_capability *cap)
{
	unsigned int n, vectors = pci_enabled_msi_vectors(device);
	const struct jailhouse_pci_device *info = device->info;
	struct apic_irq_message irq_msg;
	union x86_msi_vector msi = {
		.native.dest_logical = 1,
		.native.redir_hint = 1,
		.native.address = MSI_ADDRESS_VALUE,
	};

	if (!(pci_read_config(info->bdf, PCI_CFG_COMMAND, 2) & PCI_CMD_MASTER))
		return;

	/*
	 * Disable delivery by setting no destination CPU bit in logical
	 * addressing mode.
	 */
	if (info->msi_64bits)
		pci_write_config(info->bdf, cap->start + 8, 0, 4);
	pci_write_config(info->bdf, cap->start + 4, (u32)msi.raw.address, 4);

	/*
	 * Inject MSI vectors to avoid losing events while suppressed.
	 * Linux can handle rare spurious interrupts.
	 */
	msi = pci_get_x86_msi_vector(device);
	for (n = 0; n < vectors; n++) {
		irq_msg = pci_translate_msi_vector(device, n, vectors, msi);
		apic_send_irq(irq_msg);
	}
}

static u32 pci_get_x86_msi_remap_address(unsigned int index)
{
	union x86_msi_vector msi = {
		.remap.int_index15 = index >> 15,
		.remap.shv = 1,
		.remap.remapped = 1,
		.remap.int_index = index,
		.remap.address = MSI_ADDRESS_VALUE,
	};

	return (u32)msi.raw.address;
}

int pci_update_msi(struct pci_device *device,
		   const struct jailhouse_pci_capability *cap)
{
	unsigned int n, vectors = pci_enabled_msi_vectors(device);
	union x86_msi_vector msi = pci_get_x86_msi_vector(device);
	const struct jailhouse_pci_device *info = device->info;
	struct apic_irq_message irq_msg;
	u16 bdf = info->bdf;
	int result = 0;

	if (vectors == 0)
		return 0;

	for (n = 0; n < vectors; n++) {
		irq_msg = pci_translate_msi_vector(device, n, vectors, msi);
		result = iommu_map_interrupt(device->cell, bdf, n, irq_msg);
		// HACK for QEMU
		if (result == -ENOSYS) {
			for (n = 1; n < (info->msi_64bits ? 4 : 3); n++)
				pci_write_config(bdf, cap->start + n * 4,
					device->msi_registers.raw[n], 4);
			return 0;
		}
		if (result < 0)
			return result;
	}

	/* set result to the base index again */
	result -= vectors - 1;

	pci_write_config(bdf, cap->start + (info->msi_64bits ? 12 : 8), 0, 2);

	if (info->msi_64bits)
		pci_write_config(bdf, cap->start + 8, 0, 4);
	pci_write_config(bdf, cap->start + 4,
			 pci_get_x86_msi_remap_address(result), 4);

	return 0;
}

int pci_update_msix_vector(struct pci_device *device, unsigned int index)
{
	union x86_msi_vector msi = {
		.raw.address = device->msix_vectors[index].field.address,
		.raw.data = device->msix_vectors[index].field.data,
	};
	struct apic_irq_message irq_msg;
	int result;

	if (!device->msix_registers.field.enable)
		return 0;

	irq_msg = pci_translate_msi_vector(device, index, 0, msi);
	result = iommu_map_interrupt(device->cell, device->info->bdf, index,
				   irq_msg);
	// HACK for QEMU
	if (result == -ENOSYS) {
		mmio_write64(&device->msix_table[index].field.address,
			     device->msix_vectors[index].field.address);
		mmio_write32(&device->msix_table[index].field.data,
			     device->msix_vectors[index].field.data);
		return 0;
	}
	if (result < 0)
		return result;

	mmio_write64(&device->msix_table[index].field.address,
		     pci_get_x86_msi_remap_address(result));
	mmio_write32(&device->msix_table[index].field.data, 0);

	return 0;
}
