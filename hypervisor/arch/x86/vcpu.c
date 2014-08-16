/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013
 * Copyright (c) Valentine Sinitsyn, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/control.h>
#include <jailhouse/mmio.h>
#include <jailhouse/paging.h>
#include <jailhouse/pci.h>
#include <jailhouse/printk.h>
#include <jailhouse/string.h>

#include <asm/ioapic.h>
#include <asm/types.h>
#include <asm/pci.h>
#include <asm/percpu.h>
#include <asm/vcpu.h>

/* Can be overriden in vendor-specific code if needed */
const u8 *vcpu_get_inst_bytes(struct per_cpu *cpu_data,
		              const struct guest_paging_structures *pg_structs,
			      unsigned long pc, unsigned int *size)
	__attribute__((weak, alias("vcpu_map_inst")));

const u8 *vcpu_map_inst(struct per_cpu *cpu_data,
			const struct guest_paging_structures *pg_structs,
			unsigned long pc, unsigned int *size)
{
	unsigned short bytes_avail;
	u8 *page = NULL;

	if (!size || !*size)
		goto out_err;
	page = page_map_get_guest_page(cpu_data, pg_structs, pc,
				       PAGE_READONLY_FLAGS);
	if (!page)
		goto out_err;

	/* Number of bytes available before page boundary */
	bytes_avail = (~(pc & PAGE_OFFS_MASK) & PAGE_OFFS_MASK) + 1;
	if (*size > bytes_avail)
		*size = bytes_avail;

	return &page[pc & PAGE_OFFS_MASK];

out_err:
	return NULL;
}

int vcpu_cell_init(struct cell *cell)
{
	const u8 *pio_bitmap = jailhouse_cell_pio_bitmap(cell->config);
	u32 pio_bitmap_size = cell->config->pio_bitmap_size;
	struct vcpu_io_bitmap cell_iobm, root_cell_iobm;
	unsigned int n, pm_timer_addr;
	u32 size;
	int err;
	u8 *b;

	/* PM timer has to be provided */
	if (system_config->platform_info.x86.pm_timer_address == 0)
		return -EINVAL;

	err = vcpu_vendor_cell_init(cell);
	if (err) {
		vcpu_cell_exit(cell);
		return err;
	}

	vcpu_vendor_get_cell_io_bitmap(cell, &cell_iobm);
	memset(cell_iobm.data, -1, cell_iobm.size);

	for (n = 0; n < 2; n++) {
		size = pio_bitmap_size <= PAGE_SIZE ?
			pio_bitmap_size : PAGE_SIZE;
		memcpy(cell_iobm.data + n * PAGE_SIZE, pio_bitmap, size);
		pio_bitmap += size;
		pio_bitmap_size -= size;
	}

	if (cell != &root_cell) {
		/*
		 * Shrink PIO access of root cell corresponding to new cell's
		 * access rights.
		 */
		vcpu_vendor_get_cell_io_bitmap(&root_cell, &root_cell_iobm);
		pio_bitmap = jailhouse_cell_pio_bitmap(cell->config);
		pio_bitmap_size = cell->config->pio_bitmap_size;
		for (b = root_cell_iobm.data; pio_bitmap_size > 0;
		     b++, pio_bitmap++, pio_bitmap_size--)
			*b |= ~*pio_bitmap;
	}

	/* permit access to the PM timer */
	pm_timer_addr = system_config->platform_info.x86.pm_timer_address;
	for (n = 0; n < 4; n++, pm_timer_addr++) {
		b = cell_iobm.data;
		b[pm_timer_addr / 8] &= ~(1 << (pm_timer_addr % 8));
	}

	return 0;
}

void vcpu_cell_exit(struct cell *cell)
{
	const u8 *root_pio_bitmap =
		jailhouse_cell_pio_bitmap(root_cell.config);
	const u8 *pio_bitmap = jailhouse_cell_pio_bitmap(cell->config);
	u32 pio_bitmap_size = cell->config->pio_bitmap_size;
	struct vcpu_io_bitmap root_cell_iobm;
	u8 *b;

	vcpu_vendor_get_cell_io_bitmap(&root_cell, &root_cell_iobm);

	if (root_cell.config->pio_bitmap_size < pio_bitmap_size)
		pio_bitmap_size = root_cell.config->pio_bitmap_size;

	for (b = root_cell_iobm.data; pio_bitmap_size > 0;
	     b++, pio_bitmap++, root_pio_bitmap++, pio_bitmap_size--)
		*b &= *pio_bitmap | *root_pio_bitmap;

	vcpu_vendor_cell_exit(cell);
}

void vcpu_handle_hypercall(struct registers *guest_regs,
			   struct per_cpu *cpu_data)
{
	bool long_mode = !!(vcpu_get_efer(cpu_data) & EFER_LMA);
	unsigned long arg_mask = long_mode ? (u64)-1 : (u32)-1;
	unsigned long code = guest_regs->rax;

	vcpu_skip_emulated_instruction(cpu_data, X86_INST_LEN_VMCALL);

	if ((!long_mode && vcpu_get_rflags(cpu_data) & X86_RFLAGS_VM) ||
	    (vcpu_get_cs_selector(cpu_data) & 3) != 0) {
		guest_regs->rax = -EPERM;
		return;
	}

	guest_regs->rax = hypercall(cpu_data, code, guest_regs->rdi & arg_mask,
				    guest_regs->rsi & arg_mask);
	if (guest_regs->rax == -ENOSYS)
		printk("CPU %d: Unknown vmcall %d, RIP: %p\n",
		       cpu_data->cpu_id, code,
		       vcpu_get_rip(cpu_data) - X86_INST_LEN_VMCALL);

	if (code == JAILHOUSE_HC_DISABLE && guest_regs->rax == 0)
		vcpu_deactivate_vmm(guest_regs, cpu_data);
}

bool vcpu_handle_io_access(struct registers *guest_regs,
			   struct per_cpu *cpu_data)
{
	struct vcpu_io_intercept io;

	vcpu_vendor_get_io_intercept(cpu_data, &io);

	/* string and REP-prefixed instructions are not supported */
	if (io.rep_or_str)
		goto invalid_access;

	if (x86_pci_config_handler(guest_regs, cpu_data->cell, io.port, io.in,
				   io.size) == 1) {
		vcpu_skip_emulated_instruction(cpu_data, io.inst_len);
		return true;
	}

invalid_access:
	panic_printk("FATAL: Invalid PIO %s, port: %x size: %d\n",
		     io.in ? "read" : "write", io.port, io.size);
	panic_printk("PCI address port: %x\n",
		     cpu_data->cell->pci_addr_port_val);
	return false;
}

bool vcpu_handle_pt_violation(struct registers *guest_regs,
			      struct per_cpu *cpu_data)
{
	struct guest_paging_structures pg_structs;
	struct vcpu_pf_intercept pf;
	struct mmio_access access;
	int result = 0;
	u32 val;

	vcpu_vendor_get_pf_intercept(cpu_data, &pf);

	if (!vcpu_get_guest_paging_structs(&pg_structs, cpu_data))
		goto invalid_access;

	access = mmio_parse(cpu_data, vcpu_get_rip(cpu_data),
			    &pg_structs, pf.is_write);
	if (!access.inst_len || access.size != 4)
		goto invalid_access;

	if (pf.is_write)
		val = ((unsigned long *)guest_regs)[access.reg];

	result = ioapic_access_handler(cpu_data->cell, pf.is_write,
			               pf.phys_addr, &val);
	if (result == 0)
		result = pci_mmio_access_handler(cpu_data->cell, pf.is_write,
						 pf.phys_addr, &val);

	if (result == 1) {
		if (!pf.is_write)
			((unsigned long *)guest_regs)[access.reg] = val;
		vcpu_skip_emulated_instruction(cpu_data, access.inst_len);
		return true;
	}

invalid_access:
	/* report only unhandled access failures */
	if (result == 0)
		panic_printk("FATAL: Invalid MMIO/RAM %s, addr: %p\n",
			     pf.is_write ? "write" : "read", pf.phys_addr);
	return false;
}
