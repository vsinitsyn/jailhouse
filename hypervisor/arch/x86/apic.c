/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/processor.h>
#include <jailhouse/paging.h>
#include <jailhouse/printk.h>
#include <jailhouse/control.h>
#include <jailhouse/mmio.h>
#include <asm/apic.h>
#include <asm/bitops.h>
#include <asm/control.h>

#define XAPIC_REG(x2apic_reg)		((x2apic_reg) << 4)

bool using_x2apic;
u8 apic_to_cpu_id[] = { [0 ... APIC_MAX_PHYS_ID] = CPU_ID_INVALID };

/* Initialized for x2APIC, adjusted for xAPIC during init */
u32 apic_reserved_bits[] = {
	[0x00 ... 0x07] = -1,
	[0x08]          = 0xffffff00,	/* TPR */
	[0x09 ... 0x0a] = -1,
	[0x0b]          = 0,		/* EOI */
	[0x0c ... 0x0e] = -1,
	[0x0f]          = 0xfffffe00,	/* SVR */
	[0x10 ... 0x2e] = -1,
	[0x2f]          = 0xfffef800,	/* CMCI */
	[0x30]          = 0xfff33000,	/* ICR (0..31) */
	[0x31]          = -1,
	[0x32]          = 0xfff8ff00,	/* Timer */
	[0x33 ... 0x34] = 0xfffef800,	/* Thermal, Perf */
	[0x35 ... 0x36] = 0xfff0f800,	/* LINT0, LINT1 */
	[0x37]          = 0xfff8ff00,	/* Error */
	[0x38]		= 0,		/* Initial Counter */
	[0x39 ... 0x3d] = -1,
	[0x3e]		= 0xfffffff4,	/* DCR */
	[0x3f]		= 0xffffff00,	/* Self IPI */
};
static void *xapic_page;

static struct {
	u32 (*read)(unsigned int reg);
	u32 (*read_id)(void);
	void (*write)(unsigned int reg, u32 val);
	void (*send_ipi)(u32 apic_id, u32 icr_lo);
} apic_ops;

static u32 read_xapic(unsigned int reg)
{
	return mmio_read32(xapic_page + XAPIC_REG(reg));
}

static u32 read_xapic_id(void)
{
	return mmio_read32_field(xapic_page + XAPIC_REG(APIC_REG_ID),
				 XAPIC_DEST_MASK);
}

static void write_xapic(unsigned int reg, u32 val)
{
	mmio_write32(xapic_page + XAPIC_REG(reg), val);
}

static void send_xapic_ipi(u32 apic_id, u32 icr_lo)
{
	while (read_xapic(APIC_REG_ICR) & APIC_ICR_DS_PENDING)
		cpu_relax();
	mmio_write32(xapic_page + XAPIC_REG(APIC_REG_ICR_HI),
		     apic_id << XAPIC_DEST_SHIFT);
	mmio_write32(xapic_page + XAPIC_REG(APIC_REG_ICR), icr_lo);
}

static u32 read_x2apic(unsigned int reg)
{
	return read_msr(MSR_X2APIC_BASE + reg);
}

static u32 read_x2apic_id(void)
{
	return read_msr(MSR_X2APIC_BASE + APIC_REG_ID);
}

static void write_x2apic(unsigned int reg, u32 val)
{
	write_msr(MSR_X2APIC_BASE + reg, val);
}

static void send_x2apic_ipi(u32 apic_id, u32 icr_lo)
{
	write_msr(MSR_X2APIC_BASE + APIC_REG_ICR,
		  ((unsigned long)apic_id) << 32 | icr_lo);
}

int phys_processor_id(void)
{
	return apic_ops.read_id();
}

int apic_cpu_init(struct per_cpu *cpu_data)
{
	unsigned int apic_id = phys_processor_id();
	unsigned int cpu_id = cpu_data->cpu_id;
	u32 ldr;

	printk("(APIC ID %d) ", apic_id);

	if (apic_id > APIC_MAX_PHYS_ID || cpu_id == CPU_ID_INVALID)
		return -ERANGE;
	if (apic_to_cpu_id[apic_id] != CPU_ID_INVALID)
		return -EBUSY;
	/* only flat mode with LDR corresponding to logical ID supported */
	if (!using_x2apic) {
		ldr = apic_ops.read(APIC_REG_LDR);
		if (apic_ops.read(APIC_REG_DFR) != 0xffffffff ||
		    (ldr != 0 && ldr != 1UL << (cpu_id + XAPIC_DEST_SHIFT)))
			return -EIO;
	}

	apic_to_cpu_id[apic_id] = cpu_id;
	cpu_data->apic_id = apic_id;

	cpu_data->sipi_vector = -1;

	return 0;
}

int apic_init(void)
{
	unsigned long apicbase = read_msr(MSR_IA32_APICBASE);
	int err;

	if (apicbase & APIC_BASE_EXTD) {
		apic_ops.read = read_x2apic;
		apic_ops.read_id = read_x2apic_id;
		apic_ops.write = write_x2apic;
		apic_ops.send_ipi = send_x2apic_ipi;
		using_x2apic = true;
	} else if (apicbase & APIC_BASE_EN) {
		xapic_page = page_alloc(&remap_pool, 1);
		if (!xapic_page)
			return -ENOMEM;
		err = paging_create(&hv_paging_structs, XAPIC_BASE, PAGE_SIZE,
				    (unsigned long)xapic_page,
				    PAGE_DEFAULT_FLAGS | PAGE_FLAG_UNCACHED,
				    PAGING_NON_COHERENT);
		if (err)
			return err;
		apic_ops.read = read_xapic;
		apic_ops.read_id = read_xapic_id;
		apic_ops.write = write_xapic;
		apic_ops.send_ipi = send_xapic_ipi;

		/* adjust reserved bits to xAPIC mode */
		apic_reserved_bits[0x0d] = 0; /* LDR, separately filtered */
		apic_reserved_bits[0x0e] = 0; /* DFR, separately filtered */
		apic_reserved_bits[0x31] = 0x00ffffff; /* ICR (32..63) */
		apic_reserved_bits[0x3f] = -1; /* no Self IPI register */
	} else
		return -EIO;

	printk("Using x%sAPIC\n", using_x2apic ? "2" : "");

	return 0;
}

void apic_send_nmi_ipi(struct per_cpu *target_data)
{
	apic_ops.send_ipi(target_data->apic_id,
			  APIC_ICR_DLVR_NMI |
			  APIC_ICR_DEST_PHYSICAL |
			  APIC_ICR_LV_ASSERT |
			  APIC_ICR_TM_EDGE |
			  APIC_ICR_SH_NONE);
}

void apic_send_irq(struct apic_irq_message irq_msg)
{
	u32 delivery_mode = irq_msg.delivery_mode << APIC_ICR_DLVR_SHIFT;

	/* IA-32 SDM 10.6: "lowest priority IPI [...] should be avoided" */
	if (delivery_mode == APIC_ICR_DLVR_LOWPRI) {
		delivery_mode = APIC_ICR_DLVR_FIXED;
		/* Fixed mode performs a multicast, so reduce the number of
		 * receivers to one. */
		if (irq_msg.dest_logical && irq_msg.destination != 0)
			irq_msg.destination = 1UL << ffsl(irq_msg.destination);
	}
	apic_ops.send_ipi(irq_msg.destination,
			  irq_msg.vector | delivery_mode |
			  (irq_msg.dest_logical ? APIC_ICR_DEST_LOGICAL : 0) |
			  APIC_ICR_LV_ASSERT |
			  (irq_msg.level_triggered ? APIC_ICR_TM_LEVEL : 0) |
			  APIC_ICR_SH_NONE);
}

void apic_irq_handler(struct per_cpu *cpu_data)
{
	cpu_data->num_clear_apic_irqs++;
	if (cpu_data->num_clear_apic_irqs > 256)
		/*
		 * Do not try to ack infinitely. Once we should have handled
		 * all possible vectors, raise the task priority to prevent
		 * further interrupts. TPR will be cleared again on exit from
		 * apic_clear(). This way we will leave with some bits in IRR
		 * set - better than spinning endlessly.
		 */
		apic_ops.write(APIC_REG_TPR, 0xff);

	apic_ops.write(APIC_REG_EOI, APIC_EOI_ACK);
}

static void apic_mask_lvt(unsigned int reg)
{
	unsigned int val = apic_ops.read(reg);

	if (!(val & APIC_LVT_MASKED))
		apic_ops.write(reg, val | APIC_LVT_MASKED);
}

void apic_clear(struct per_cpu *cpu_data)
{
	unsigned int maxlvt = (apic_ops.read(APIC_REG_LVR) >> 16) & 0xff;
	int n;

	apic_mask_lvt(APIC_REG_LVTERR);
	if (maxlvt >= 6)
		apic_mask_lvt(APIC_REG_LVTCMCI);
	apic_mask_lvt(APIC_REG_LVTT);
	if (maxlvt >= 5)
		apic_mask_lvt(APIC_REG_LVTTHMR);
	if (maxlvt >= 4)
		apic_mask_lvt(APIC_REG_LVTPC);
	apic_mask_lvt(APIC_REG_LVT0);
	apic_mask_lvt(APIC_REG_LVT1);

	for (n = APIC_NUM_INT_REGS-1; n >= 0; n--)
		while (apic_ops.read(APIC_REG_ISR0 + n) != 0)
			apic_ops.write(APIC_REG_EOI, APIC_EOI_ACK);

	apic_ops.write(APIC_REG_TPR, 0);
	cpu_data->num_clear_apic_irqs = 0;
	enable_irq();
	cpu_relax();
	disable_irq();
	apic_ops.write(APIC_REG_TPR, 0);
}

static bool apic_valid_ipi_mode(struct per_cpu *cpu_data, u32 lo_val)
{
	switch (lo_val & APIC_ICR_DLVR_MASK) {
	case APIC_ICR_DLVR_INIT:
	case APIC_ICR_DLVR_FIXED:
	case APIC_ICR_DLVR_LOWPRI:
	case APIC_ICR_DLVR_NMI:
	case APIC_ICR_DLVR_SIPI:
		break;
	default:
		panic_printk("FATAL: Unsupported APIC delivery mode, "
			     "ICR.lo=%x\n", lo_val);
		return false;
	}

	switch (lo_val & APIC_ICR_SH_MASK) {
	case APIC_ICR_SH_NONE:
	case APIC_ICR_SH_SELF:
		break;
	default:
		panic_printk("FATAL: Unsupported shorthand, ICR.lo=%x\n",
			     lo_val);
		return false;
	}
	return true;
}

static void apic_send_ipi(struct per_cpu *cpu_data, unsigned int target_cpu_id,
			  u32 orig_icr_hi, u32 icr_lo)
{
	if (!cell_owns_cpu(cpu_data->cell, target_cpu_id)) {
		printk("WARNING: CPU %d specified IPI destination outside "
		       "cell boundaries, ICR.hi=%x\n",
		       cpu_data->cpu_id, orig_icr_hi);
		return;
	}

	switch (icr_lo & APIC_ICR_DLVR_MASK) {
	case APIC_ICR_DLVR_NMI:
		/* TODO: must be sent via hypervisor */
		printk("Ignoring NMI IPI\n");
		break;
	case APIC_ICR_DLVR_INIT:
		x86_send_init_sipi(target_cpu_id, X86_INIT, -1);
		break;
	case APIC_ICR_DLVR_SIPI:
		x86_send_init_sipi(target_cpu_id, X86_SIPI,
				   icr_lo & APIC_ICR_VECTOR_MASK);
		break;
	default:
		apic_ops.send_ipi(per_cpu(target_cpu_id)->apic_id, icr_lo);
	}
}

static void apic_send_logical_dest_ipi(struct per_cpu *cpu_data,
				       unsigned long dest, u32 lo_val,
				       u32 hi_val)
{
	unsigned int target_cpu_id = CPU_ID_INVALID;
	unsigned int logical_id;
	unsigned int cluster_id;
	unsigned int apic_id;

	if (using_x2apic) {
		cluster_id = (dest & X2APIC_DEST_CLUSTER_ID_MASK) >>
			X2APIC_DEST_CLUSTER_ID_SHIFT;
		dest &= X2APIC_DEST_LOGICAL_ID_MASK;
		while (dest != 0) {
			logical_id = ffsl(dest);
			dest &= ~(1UL << logical_id);
			apic_id = logical_id |
				(cluster_id << X2APIC_CLUSTER_ID_SHIFT);
			if (apic_id <= APIC_MAX_PHYS_ID)
				target_cpu_id = apic_to_cpu_id[apic_id];
			apic_send_ipi(cpu_data, target_cpu_id, hi_val, lo_val);
		}
	} else
		while (dest != 0) {
			target_cpu_id = ffsl(dest);
			dest &= ~(1UL << target_cpu_id);
			apic_send_ipi(cpu_data, target_cpu_id, hi_val, lo_val);
		}
}

bool apic_handle_icr_write(struct per_cpu *cpu_data, u32 lo_val, u32 hi_val)
{
	unsigned int target_cpu_id;
	unsigned long dest;

	if (!apic_valid_ipi_mode(cpu_data, lo_val))
		return false;

	if ((lo_val & APIC_ICR_SH_MASK) == APIC_ICR_SH_SELF) {
		apic_ops.write(APIC_REG_ICR, (lo_val & APIC_ICR_VECTOR_MASK) |
					     APIC_ICR_DLVR_FIXED |
					     APIC_ICR_TM_EDGE |
					     APIC_ICR_SH_SELF);
		return true;
	}

	dest = hi_val;
	if (!using_x2apic)
		dest >>= XAPIC_DEST_SHIFT;

	if (lo_val & APIC_ICR_DEST_LOGICAL) {
		lo_val &= ~APIC_ICR_DEST_LOGICAL;
		apic_send_logical_dest_ipi(cpu_data, dest, lo_val, hi_val);
	} else {
		target_cpu_id = CPU_ID_INVALID;
		if (dest <= APIC_MAX_PHYS_ID)
			target_cpu_id = apic_to_cpu_id[dest];
		apic_send_ipi(cpu_data, target_cpu_id, hi_val, lo_val);
	}
	return true;
}

static bool apic_accessing_reserved_bits(unsigned int reg, u32 val)
{
	if ((apic_reserved_bits[reg] & val) == 0)
		return false;

	printk("FATAL: Trying to set reserved APIC bits "
	       "(reg %02x, value %08x)\n", reg, val);
	return true;
}

static bool apic_invalid_lvt_delivery_mode(unsigned int reg, u32 val)
{
	if (val & APIC_LVT_MASKED ||
	    (val & APIC_LVT_DLVR_MASK) == APIC_LVT_DLVR_FIXED ||
	    (val & APIC_LVT_DLVR_MASK) == APIC_LVT_DLVR_NMI)
		return false;

	printk("FATAL: Setting invalid LVT delivery mode "
	       "(reg %02x, value %08x)\n", reg, val);
	return true;
}

unsigned int apic_mmio_access(struct registers *guest_regs,
			      struct per_cpu *cpu_data, unsigned long rip,
			      const struct guest_paging_structures *pg_structs,
			      unsigned int reg, bool is_write)
{
	struct mmio_access access;
	u32 val;

	access = mmio_parse(rip, pg_structs, is_write);
	if (access.inst_len == 0)
		return 0;
	if (access.size != 4) {
		panic_printk("FATAL: Unsupported APIC access width %d\n",
			     access.size);
		return 0;
	}
	if (is_write) {
		val = ((unsigned long *)guest_regs)[access.reg];
		if (apic_accessing_reserved_bits(reg, val))
			return 0;

		if (reg == APIC_REG_ICR) {
			if (!apic_handle_icr_write(cpu_data, val,
					apic_ops.read(APIC_REG_ICR_HI)))
				return 0;
		} else if (reg == APIC_REG_LDR &&
			 val != 1UL << (cpu_data->cpu_id + XAPIC_DEST_SHIFT)) {
			panic_printk("FATAL: Unsupported change to LDR: %x\n",
				     val);
			return 0;
		} else if (reg == APIC_REG_DFR && val != 0xffffffff) {
			panic_printk("FATAL: Unsupported change to DFR: %x\n",
				     val);
			return 0;
		} else if (reg >= APIC_REG_LVTCMCI && reg <= APIC_REG_LVTERR &&
			   apic_invalid_lvt_delivery_mode(reg, val))
			return 0;
		else
			apic_ops.write(reg, val);
	} else {
		val = apic_ops.read(reg);
		((unsigned long *)guest_regs)[access.reg] = val;
	}
	return access.inst_len;
}

bool x2apic_handle_write(struct registers *guest_regs,
			 struct per_cpu *cpu_data)
{
	u32 reg = guest_regs->rcx - MSR_X2APIC_BASE;
	u32 val = guest_regs->rax;

	if (apic_accessing_reserved_bits(reg, val))
		return false;

	if (reg == APIC_REG_SELF_IPI)
		/* TODO: emulate */
		printk("Unhandled x2APIC self IPI write\n");
	else if (reg == APIC_REG_ICR)
		return apic_handle_icr_write(cpu_data, val, guest_regs->rdx);
	else if (reg >= APIC_REG_LVTCMCI && reg <= APIC_REG_LVTERR &&
		 apic_invalid_lvt_delivery_mode(reg, val))
		return false;
	else
		apic_ops.write(reg, val);
	return true;
}

/* must only be called for readable registers */
void x2apic_handle_read(struct registers *guest_regs)
{
	u32 reg = guest_regs->rcx - MSR_X2APIC_BASE;

	guest_regs->rax &= ~0xffffffffUL;
	if (reg == APIC_REG_ID)
		guest_regs->rax |= apic_ops.read_id();
	else
		guest_regs->rax |= apic_ops.read(reg);

	guest_regs->rdx &= ~0xffffffffUL;
	if (reg == APIC_REG_ICR)
		guest_regs->rdx |= apic_ops.read(reg + 1);
}

/**
 * Filter a logical destination mask against the cell's CPU set.
 * @param cell		Target cell
 * @param destination	Logical destination mask (redirection hint enabled)
 *
 * @return Logical destination mask with invalid target CPUs removed.
 */
u32 x2apic_filter_logical_dest(struct cell *cell, u32 destination)
{
	unsigned int apic_id, logical_id, cluster_id;
	u32 dest;

	cluster_id = (destination & X2APIC_DEST_CLUSTER_ID_MASK) >>
		X2APIC_DEST_CLUSTER_ID_SHIFT;
	dest = destination & X2APIC_DEST_LOGICAL_ID_MASK;
	while (dest != 0) {
		logical_id = ffsl(dest);
		dest &= ~(1UL << logical_id);
		apic_id = logical_id | (cluster_id << X2APIC_CLUSTER_ID_SHIFT);
		if (apic_id > APIC_MAX_PHYS_ID ||
		    !cell_owns_cpu(cell, apic_to_cpu_id[apic_id]))
			destination &= ~(1UL << logical_id);
	}
	return destination;
}
