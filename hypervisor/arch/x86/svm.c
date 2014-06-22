/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013
 *
 * Authors:
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * Based on vmx.c written by Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/entry.h>
#include <jailhouse/control.h>
#include <jailhouse/mmio.h>
#include <jailhouse/paging.h>
#include <jailhouse/pci.h>
#include <jailhouse/printk.h>
#include <jailhouse/processor.h>
#include <jailhouse/paging.h>
#include <jailhouse/string.h>

#include <asm/apic.h>
#include <asm/amd_iommu.h>
#include <asm/atomic.h>
#include <asm/control.h>
#include <asm/ioapic.h>
#include <asm/paging.h>
#include <asm/pci.h>
#include <asm/percpu.h>
#include <asm/svm.h>

#define SVM_CR0_CLEARED_BITS	(~(X86_CR0_CD | X86_CR0_NW))

bool has_avic = false;

static u32 current_asid = 1; /* ASID 0 is for host mode */

static const struct segment invalid_seg = { 0 };

static struct paging npt_paging[NPT_PAGE_DIR_LEVELS];

static u8 __attribute__((aligned(PAGE_SIZE))) msrpm[][0x2000/4] = {
	[ SVM_MSRPM_0000 ] = {
		[      0/4 ...  0x017/4 ] = 0,    /* 0x01b (w) */
		[  0x018/4 ...  0x01b/4 ] = 0x80,
		[  0x01c/4 ...  0x7ff/4 ] = 0,
		[  0x800/4 ...  0x803/4 ] = 0x90, /* 0x802 (r), 0x803 (r) */
		[  0x804/4 ...  0x807/4 ] = 0,
		[  0x808/4 ...  0x80b/4 ] = 0x13, /* 0x808 (rw), 0x80a (r) */
		[  0x80c/4 ...  0x80f/4 ] = 0xc8, /* 0x80d (w), 0x80f (rw) */
		[  0x810/4 ...  0x813/4 ] = 0x55, /* 0x810 - 0x813 (r) */
		[  0x813/4 ...  0x817/4 ] = 0x55, /* 0x813 - 0x817 (r) */
		[  0x818/4 ...  0x81b/4 ] = 0x55, /* 0x818 - 0x81b (r) */
		[  0x81c/4 ...  0x81f/4 ] = 0x55, /* 0x81c - 0x81f (r) */
		[  0x820/4 ...  0x823/4 ] = 0x55, /* 0x820 - 0x823 (r) */
		[  0x824/4 ...  0x827/4 ] = 0x55, /* 0x823 - 0x827 (r) */
		[  0x828/4 ...  0x82b/4 ] = 0x03, /* 0x828 (rw) */
		[  0x82c/4 ...  0x82f/4 ] = 0xc0, /* 0x82f (rw) */
		[  0x830/4 ...  0x833/4 ] = 0xf3, /* 0x830 (rw), 0x832 (rw), 0x833 (rw) */
		[  0x834/4 ...  0x837/4 ] = 0xff, /* 0x834 - 0x837 (rw) */
		[  0x838/4 ...  0x83b/4 ] = 0x07, /* 0x838 (rw), 0x839 (r) */
		[  0x83c/4 ...  0x83f/4 ] = 0x70, /* 0x83e (rw), 0x83f (r) */
		[  0x840/4 ... 0x1fff/4 ] = 0,
	},
	[ SVM_MSRPM_C000 ] = {
		[      0/4 ...  0x07f/4 ] = 0,
		[  0x080/4 ...  0x083/4 ] = 0x02, /* 0x080 (w) */
		[  0x084/4 ... 0x1fff/4 ] = 0
	},
	[ SVM_MSRPM_C001 ] = {
		[      0/4 ... 0x1fff/4 ] = 0,
	},
	[ SVM_MSRPM_RESV ] = {
		[      0/4 ... 0x1fff/4 ] = 0,
	}
};

void *avic_page;

static int svm_check_features(void)
{
	/* SVM is available */
	if (!(cpuid_ecx(0x80000001) & 0x04))
		return -ENODEV;

	/* Nested paging */
	if (!(cpuid_edx(0x8000000A) & 0x01))
		return -EIO;

	/* Decode assists */
	if (!(cpuid_edx(0x8000000A) & 0x07))
		return -EIO;

	/* AVIC support */
	if (cpuid_edx(0x8000000A) & 0x2000)
		has_avic = true;

	return 0;
}

static void svm_set_svm_segment_from_dtr(struct svm_segment *svm_segment,
		                          const struct desc_table_reg *dtr)
{
	struct svm_segment tmp = { 0 };

	if (dtr) {
		tmp.base = dtr->base;
		tmp.limit = dtr->limit & 0xffff;
	}

	*svm_segment = tmp;
}

/* TODO: struct segment needs to be x86 generic, not VMX-specific one here */
static void svm_set_svm_segment_from_segment(struct svm_segment *svm_segment,
		                              const struct segment *segment)
{
	u32 ar;

	svm_segment->selector = segment->selector;

	if (segment->access_rights == 0x10000)
		svm_segment->access_rights = 0;
	else {
		ar = segment->access_rights;
		svm_segment->access_rights = ((ar & 0xf000) >> 4) | (ar & 0x00ff);
	}

	svm_segment->limit = segment->limit;
	svm_segment->base = segment->base;
}

static bool svm_set_cell_config(struct cell *cell, struct vmcb *vmcb)
{
	/* No real need for this function; used for consistency with vmx.c */
	vmcb->iopm_base_pa = page_map_hvirt2phys(cell->svm.iopm);
	vmcb->n_cr3 = page_map_hvirt2phys(cell->svm.npt_structs.root_table);

	return true;
}

static int vmcb_setup(struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	u32 asid, nasid = cpuid_ebx(0x8000000A);

	asid = atomic_post_inc(current_asid);
	if (asid >= nasid)
		return false;

	memset(vmcb, sizeof(struct vmcb), 0);

	vmcb->cr0 = read_cr0() & SVM_CR0_CLEARED_BITS;
	vmcb->cr3 = cpu_data->linux_cr3;
	vmcb->cr4 = read_cr4();

	svm_set_svm_segment_from_segment(&vmcb->cs, &cpu_data->linux_cs);
	svm_set_svm_segment_from_segment(&vmcb->ds, &cpu_data->linux_ds);
	svm_set_svm_segment_from_segment(&vmcb->es, &cpu_data->linux_es);
	svm_set_svm_segment_from_segment(&vmcb->fs, &cpu_data->linux_fs);
	svm_set_svm_segment_from_segment(&vmcb->gs, &cpu_data->linux_gs);
	svm_set_svm_segment_from_segment(&vmcb->ss, &invalid_seg);
	svm_set_svm_segment_from_segment(&vmcb->tr, &cpu_data->linux_tss);

	svm_set_svm_segment_from_dtr(&vmcb->ldtr, NULL);
	svm_set_svm_segment_from_dtr(&vmcb->gdtr, &cpu_data->linux_gdtr);
	svm_set_svm_segment_from_dtr(&vmcb->idtr, &cpu_data->linux_idtr);

	vmcb->cpl = 0; /* Linux runs in ring 0 before migration */

	vmcb->rflags = 0x02;
	/* Indicate success to the caller of arch_entry */
	vmcb->rax = 0;
	vmcb->rsp = cpu_data->linux_sp +
		(NUM_ENTRY_REGS + 1) * sizeof(unsigned long);
	vmcb->rip = cpu_data->linux_ip;

	vmcb->sysenter_cs = read_msr(MSR_IA32_SYSENTER_CS);
	vmcb->sysenter_eip = read_msr(MSR_IA32_SYSENTER_EIP);
	vmcb->sysenter_esp = read_msr(MSR_IA32_SYSENTER_ESP);
	vmcb->star = read_msr(MSR_STAR);
	vmcb->lstar = read_msr(MSR_LSTAR);
	vmcb->cstar = read_msr(MSR_CSTAR);
	vmcb->sfmask = read_msr(MSR_SFMASK);
	vmcb->kerngsbase = read_msr(MSR_KERNGS_BASE);

	vmcb->dr6 = 0x00000ff0;
	vmcb->dr7 = 0x00000400;

	/* Make the hypervisor visible */
	vmcb->efer = (cpu_data->linux_efer | EFER_SVME);

	/* Linux uses custom PAT setting */
	vmcb->g_pat = read_msr(MSR_IA32_PAT);

	vmcb->general1_intercepts |= GENERAL1_INTERCEPT_NMI;
	vmcb->general1_intercepts |= GENERAL1_INTERCEPT_CR0_SEL_WRITE;
	/* TODO: Do we need this for SVM ? */
	/* vmcb->general1_intercepts |= GENERAL1_INTERCEPT_CPUID; */
	vmcb->general1_intercepts |= GENERAL1_INTERCEPT_IOIO_PROT;
	vmcb->general1_intercepts |= GENERAL1_INTERCEPT_MSR_PROT;
	vmcb->general1_intercepts |= GENERAL1_INTERCEPT_SHUTDOWN_EVT;

	vmcb->general2_intercepts |= GENERAL2_INTERCEPT_VMRUN; /* Required */
	vmcb->general2_intercepts |= GENERAL2_INTERCEPT_VMMCALL;

	vmcb->msrpm_base_pa = page_map_hvirt2phys(msrpm);

	vmcb->np_enable = 1;
	vmcb->guest_asid = asid;

	return svm_set_cell_config(cpu_data->cell, vmcb);
}

unsigned long arch_page_map_gphys2phys(struct per_cpu *cpu_data,
				       unsigned long gphys)
{
	return page_map_virt2phys(&cpu_data->cell->svm.npt_structs, gphys);
}

int svm_init(void)
{
	unsigned long vm_cr;
	int err;

	err = svm_check_features();
	if (err)
		return err;

	vm_cr = read_msr(MSR_VM_CR);
	if (vm_cr & VM_CR_SVMDIS)
		/* SVM disabled in BIOS */
		return -EPERM;

	/* Nested paging is the same as the native one */
	memcpy(npt_paging, x86_64_paging, sizeof(npt_paging));

	/* This is always false for AMD now (except in nested SVM);
	   see Sect. 16.3.1 in APMv2 */
	if (using_x2apic) {
		/* allow direct x2APIC access except for ICR writes */
		memset(msrpm[SVM_MSRPM_0000], 0, sizeof(msrpm[SVM_MSRPM_0000]));
		msrpm[SVM_MSRPM_0000][0x830/4] = 0x02;
	} else {
		if (!has_avic) {
			avic_page = page_alloc(&remap_pool, 1);
			if (!avic_page)
				return -ENOMEM;
		}
	}

	return svm_cell_init(&root_cell);
}

/*
 * TODO: This is an almost 100% copy of vmx_cell_init(), except for the
 * has_avic branch, iopm copy loop condition and error_out. Refactor the common parts.
 */
int svm_cell_init(struct cell *cell)
{
	struct jailhouse_cell_desc *config = cell->config;
	const u8 *pio_bitmap = jailhouse_cell_pio_bitmap(config);
	u32 pio_bitmap_size = config->pio_bitmap_size;
	unsigned int n, pm_timer_addr;
	int err;
	u32 size;
	u64 flags;
	u8 *b;

	/* PM timer has to be provided */
	if (system_config->platform_info.x86.pm_timer_address == 0)
		return -EINVAL;

	/* build root NPT of cell */
	cell->svm.npt_structs.root_paging = npt_paging;
	cell->svm.npt_structs.root_table = page_alloc(&mem_pool, 1);
	if (!cell->svm.npt_structs.root_table)
		return -ENOMEM;

	if (!has_avic) {
		/* Map xAPIC as is; reads are passed, writes are trapped */
		err = page_map_create(&cell->svm.npt_structs, XAPIC_BASE,
				      PAGE_SIZE, XAPIC_BASE,
				      PAGE_READONLY_FLAGS | PAGE_FLAG_UNCACHED,
				      PAGE_MAP_NON_COHERENT);
	} else {
		err = page_map_create(&cell->svm.npt_structs,
				      page_map_hvirt2phys(avic_page),
				      PAGE_SIZE, XAPIC_BASE,
				      PAGE_DEFAULT_FLAGS | PAGE_FLAG_UNCACHED,
				      PAGE_MAP_NON_COHERENT);
	}

	if (err) {
		svm_cell_exit(cell);
		return err;
	}

	memset(cell->svm.iopm, -1, sizeof(cell->svm.iopm));

	for (n = 0; n < 3; n++) {
		size = pio_bitmap_size <= PAGE_SIZE ?
			pio_bitmap_size : PAGE_SIZE;
		memcpy(cell->svm.iopm + n * PAGE_SIZE, pio_bitmap, size);
		pio_bitmap += size;
		pio_bitmap_size -= size;
	}

	if (cell != &root_cell) {
		/*
		 * Shrink PIO access of root cell corresponding to new cell's
		 * access rights.
		 */
		pio_bitmap = jailhouse_cell_pio_bitmap(cell->config);
		pio_bitmap_size = cell->config->pio_bitmap_size;
		for (b = root_cell.svm.iopm; pio_bitmap_size > 0;
				b++, pio_bitmap++, pio_bitmap_size--)
			*b |= ~*pio_bitmap;
	}

	/* permit access to the PM timer */
	pm_timer_addr = system_config->platform_info.x86.pm_timer_address;
	for (n = 0; n < 4; n++, pm_timer_addr++) {
		b = cell->svm.iopm;
		b[pm_timer_addr / 8] &= ~(1 << (pm_timer_addr % 8));
	}

	return 0;
}

/*
 * TODO: These two functions are almost 100% copy of their vmx counterparts
 * (sans page flags). Refactor them.
 */

int svm_map_memory_region(struct cell *cell,
			  const struct jailhouse_memory *mem)
{
	u64 phys_start = mem->phys_start;
	u32 flags = 0;

	if (mem->flags & JAILHOUSE_MEM_READ)
		flags |= PAGE_FLAG_PRESENT;
	if (mem->flags & JAILHOUSE_MEM_WRITE)
		flags |= PAGE_FLAG_RW;
	if (mem->flags & JAILHOUSE_MEM_EXECUTE)
		flags |= PAGE_FLAG_EXECUTE;
	if (mem->flags & JAILHOUSE_MEM_COMM_REGION)
		phys_start = page_map_hvirt2phys(&cell->comm_page);

	return page_map_create(&cell->svm.npt_structs, phys_start, mem->size,
			       mem->virt_start, flags, PAGE_MAP_NON_COHERENT);
}

int svm_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	return page_map_destroy(&cell->svm.npt_structs, mem->virt_start,
				mem->size, PAGE_MAP_NON_COHERENT);
}

void svm_cell_exit(struct cell *cell)
{
	/* TODO: Implement */
}

int svm_cpu_init(struct per_cpu *cpu_data)
{
	unsigned long efer;
	int err;

	err = svm_check_features();
	if (err)
		return err;

	efer = read_msr(MSR_EFER);
	if (efer & EFER_SVME)
		return -EBUSY;

	efer |= EFER_SVME;
	write_msr(MSR_EFER, efer);

	/* TODO: Set cpu_data->vmx_state equivalent? */

	if (!vmcb_setup(cpu_data))
		return -EIO;

	write_msr(MSR_VM_HSAVE_PA, page_map_hvirt2phys(cpu_data->host_state));

	return 0;
}

void svm_cpu_exit(struct per_cpu *cpu_data)
{
	unsigned long efer;

	/* TODO: Check cpu_data->vmx_state equivalent, and reset it */

	efer = read_msr(MSR_EFER);
	efer &= ~EFER_SVME;
	write_msr(MSR_EFER, efer);

	write_msr(MSR_VM_HSAVE_PA, 0);
}

void svm_cpu_activate_vmm(struct per_cpu *cpu_data)
{
	unsigned long vmcb_pa, host_stack;

	vmcb_pa = page_map_hvirt2phys(&cpu_data->vmcb);
	host_stack = (unsigned long)cpu_data->stack + sizeof(cpu_data->stack);

	/* Clear host-mode MSRs */
	write_msr(MSR_IA32_SYSENTER_CS, 0);
	write_msr(MSR_IA32_SYSENTER_EIP, 0);
	write_msr(MSR_IA32_SYSENTER_ESP, 0);

	write_msr(MSR_STAR, 0);
	write_msr(MSR_LSTAR, 0);
	write_msr(MSR_CSTAR, 0);
	write_msr(MSR_SFMASK, 0);
	write_msr(MSR_KERNGS_BASE, 0);

	/*
	 * XXX: We don't set our own PAT here but rather rely on Linux PAT
	 * settigs (and MTRRs). Potentially, a malicious Linux root cell can
	 * set values different from what we expect, and interfere with APIC
	 * virtualization in non-AVIC mode.
	 */

	/* We enter Linux at the point arch_entry would return to as well.
	 * rax is cleared to signal success to the caller. */
	asm volatile(
		"clgi\n\t"
		"mov (%%rdi),%%r15\n\t"
		"mov 0x8(%%rdi),%%r14\n\t"
		"mov 0x10(%%rdi),%%r13\n\t"
		"mov 0x18(%%rdi),%%r12\n\t"
		"mov 0x20(%%rdi),%%rbx\n\t"
		"mov 0x28(%%rdi),%%rbp\n\t"
		"mov %0, %%rax\n\t"
		"vmload\n\t"
		"vmrun\n\t"
		"vmsave\n\t"
		/* Restore hypervisor stack */
		"mov %2, %%rsp\n\t"
		"jmp vm_exit"
		: /* no output */
		/* FIXME: Why can't we use "m" (vmcb_pa) here? */
		: "l" (vmcb_pa), "D" (cpu_data->linux_reg), "m" (host_stack)
		: "memory", "r15", "r14", "r13", "r12", "rbx", "rbp", "rax", "cc");
	__builtin_unreachable();
}

static void __attribute__((noreturn))
svm_cpu_deactivate_vmm(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	unsigned long *stack = (unsigned long *)vmcb->rsp;
	unsigned long linux_ip = vmcb->rip;

	/* We are leaving - set the GIF */
	asm volatile ("stgi" : : : "memory");

	/*
	 * Restore the MSRs.
	 *
	 * XXX: One could argue this is better to be done in
	 * arch_cpu_restore(), however, it would require changes
	 * to cpu_data to store STAR and friends.
	 */
	write_msr(MSR_STAR, vmcb->star);
	write_msr(MSR_LSTAR, vmcb->lstar);
	write_msr(MSR_CSTAR, vmcb->cstar);
	write_msr(MSR_SFMASK, vmcb->sfmask);
	write_msr(MSR_KERNGS_BASE, vmcb->kerngsbase);

	cpu_data->linux_cr3 = vmcb->cr3;

	cpu_data->linux_gdtr.base = vmcb->gdtr.base;
	cpu_data->linux_gdtr.limit = vmcb->gdtr.limit;
	cpu_data->linux_idtr.base = vmcb->idtr.base;
	cpu_data->linux_idtr.limit = vmcb->idtr.limit;

	cpu_data->linux_cs.selector = vmcb->cs.selector;

	cpu_data->linux_tss.selector = vmcb->tr.selector;

	cpu_data->linux_efer = vmcb->efer & (~EFER_SVME);
	cpu_data->linux_fs.base = vmcb->fs.base;
	cpu_data->linux_gs.base = vmcb->gs.base;

	cpu_data->linux_sysenter_cs = vmcb->sysenter_cs;
	cpu_data->linux_sysenter_eip = vmcb->sysenter_eip;
	cpu_data->linux_sysenter_esp = vmcb->sysenter_esp;

	cpu_data->linux_ds.selector = vmcb->ds.selector;
	cpu_data->linux_es.selector = vmcb->es.selector;
	cpu_data->linux_fs.selector = vmcb->fs.selector;
	cpu_data->linux_gs.selector = vmcb->gs.selector;

	arch_cpu_restore(cpu_data);

	stack--;
	*stack = linux_ip;

	asm volatile (
		"mov %%rbx,%%rsp\n\t"
		"pop %%r15\n\t"
		"pop %%r14\n\t"
		"pop %%r13\n\t"
		"pop %%r12\n\t"
		"pop %%r11\n\t"
		"pop %%r10\n\t"
		"pop %%r9\n\t"
		"pop %%r8\n\t"
		"pop %%rdi\n\t"
		"pop %%rsi\n\t"
		"pop %%rbp\n\t"
		"add $8,%%rsp\n\t"
		"pop %%rbx\n\t"
		"pop %%rdx\n\t"
		"pop %%rcx\n\t"
		"mov %%rax,%%rsp\n\t"
		"xor %%rax,%%rax\n\t"
		"ret"
		: : "a" (stack), "b" (guest_regs));
	__builtin_unreachable();
}

static void svm_cpu_reset(struct registers *guest_regs,
			  struct per_cpu *cpu_data, unsigned int sipi_vector)
{
	/* TODO: Implement */
}

static void svm_skip_emulated_instruction(unsigned int inst_len, struct vmcb *vmcb)
{
	vmcb->rip += inst_len;
}

static void update_efer(struct vmcb *vmcb)
{
	unsigned long efer = vmcb->efer;

	if ((efer & (EFER_LME | EFER_LMA)) != EFER_LME)
		return;

	efer |= EFER_LMA;

	vmcb->efer = efer;
}

/*
 * TODO: This is almost a complete copy of vmx_handle_hypercall (sans vmcb access).
 * Refactor common parts.
 */
static void svm_handle_hypercall(struct registers *guest_regs,
				 struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	bool long_mode = !!(vmcb->efer & EFER_LMA);
	unsigned long arg_mask = long_mode ? (u64)-1 : (u32)-1;
	unsigned long code = guest_regs->rax;

	svm_skip_emulated_instruction(X86_INST_LEN_VMCALL, vmcb);

	if ((!(vmcb->efer & EFER_LMA) &&
	      vmcb->rflags & X86_RFLAGS_VM) ||
	     (vmcb->cs.selector & 3) != 0) {
		vmcb->rax = -EPERM;
		return;
	}

	guest_regs->rax = hypercall(cpu_data, code, guest_regs->rdi & arg_mask,
				    guest_regs->rsi & arg_mask);
	if (guest_regs->rax == -ENOSYS)
		printk("CPU %d: Unknown vmcall %d, RIP: %p\n",
				cpu_data->cpu_id, guest_regs->rax,
				vmcb->rip - X86_INST_LEN_VMCALL);

	if (code == JAILHOUSE_HC_DISABLE && guest_regs->rax == 0)
		svm_cpu_deactivate_vmm(guest_regs, cpu_data);
}

static bool svm_handle_cr(struct registers *guest_regs,
			  struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	unsigned long reg, val;

	if (!(vmcb->exitinfo1 & (1UL << 63))) {
		panic_printk("FATAL: Unsupported CR access (LMSW or CLTS)\n");
		return false;
	}

	reg = vmcb->exitinfo1 & 0x07;

	if (reg == 4)
		val = vmcb->rsp;
	else
		val = ((unsigned long *)guest_regs)[15 - reg];

	svm_skip_emulated_instruction(X86_INST_LEN_MOV_TO_CR, vmcb);
	/* TODO: better check for #GP reasons */
	vmcb->cr0 = val & SVM_CR0_CLEARED_BITS;
	if (val & X86_CR0_PG)
		update_efer(vmcb);

	return true;
}

static bool svm_handle_msr_read(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	if (guest_regs->rcx >= MSR_X2APIC_BASE &&
	    guest_regs->rcx <= MSR_X2APIC_END) {
		svm_skip_emulated_instruction(X86_INST_LEN_RDMSR,
				&cpu_data->vmcb);
		x2apic_handle_read(guest_regs);
		return true;
	} else {
		panic_printk("FATAL: Unhandled MSR read: %08x\n",
				guest_regs->rcx);
		return false;
	}
}

static bool svm_handle_msr_write(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	bool result = true;

	if (guest_regs->rcx >= MSR_X2APIC_BASE &&
	    guest_regs->rcx <= MSR_X2APIC_END) {
		result = x2apic_handle_write(guest_regs, cpu_data);
		goto out;
	}
	if (guest_regs->rcx == MSR_EFER &&
	    !(guest_regs->rax & EFER_SVME)) {
		panic_printk("Ignoring guest attempt to clear SVME\n");
		/* TODO: Maybe simple inject #GP or similar into the guest? */
	}

	result = false;
	panic_printk("FATAL: Unhandled MSR write: %x\n",
			guest_regs->rcx);
out:
	if (result)
		svm_skip_emulated_instruction(X86_INST_LEN_WRMSR, vmcb);
	return result;
}

static bool
svm_get_guest_paging_structs(struct guest_paging_structures *pg_structs, struct vmcb *vmcb)
{
	if (vmcb->efer & EFER_LMA) {
		pg_structs->root_paging = x86_64_paging;
		pg_structs->root_table_gphys =
			vmcb->cr3 & 0x000ffffffffff000UL;
	} else if ((vmcb->cr0 & X86_CR0_PG) &&
		   !(vmcb->cr4 & X86_CR4_PAE)) {
		pg_structs->root_paging = i386_paging;
		pg_structs->root_table_gphys =
			vmcb->cr3 & 0xfffff000UL;
	} else {
		printk("FATAL: Unsupported paging mode\n");
		return false;
	}
	return true;
}

/*
 * TODO: This handles unaccelerated (non-AVIC) access. AVIC should
 * be treated separately in svm_handle_avic_access().
 */
static bool svm_handle_apic_access(struct registers *guest_regs,
				   struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	struct guest_paging_structures pg_structs;
	unsigned int inst_len, offset;
	bool is_write;

	/* The caller is responsible for sanity checks */
	is_write = !!(vmcb->exitinfo1 & 0x2);
	offset = vmcb->exitinfo2 - XAPIC_BASE;

	if (offset & 0x00f)
		goto out_err;

	/*
         * TODO: Need an abstraction layer for mmio_parse() to use
	 * vmcb->guest_bytes instead of the page table walk when 
	 * vmcb->bytes_fetched is non-zero and vmcb->exitcode == VMEXIT_NPF.
	 */
	if (!svm_get_guest_paging_structs(&pg_structs, vmcb))
		goto out_err;

	inst_len = apic_mmio_access(guest_regs, cpu_data,
			vmcb->rip,
			&pg_structs, offset >> 4,
			is_write);
	if (!inst_len)
		goto out_err;

	svm_skip_emulated_instruction(inst_len, vmcb);
	return true;

out_err:
	panic_printk("FATAL: Unhandled APIC access, "
			"offset %d, is_write: %d\n", offset, is_write);
	return false;
}

/*
 * TODO: This is almost a complete copy of vmx_handle_ept_access (sans vmcb access).
 * Refactor common parts.
 */
static bool svm_handle_npf(struct registers *guest_regs,
		           struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	u64 phys_addr = vmcb->exitinfo2;
	struct guest_paging_structures pg_structs;
	struct mmio_access access;
	int result = 0;
	bool is_write;
	u32 val;

	is_write = !!(vmcb->exitinfo1 & 0x2);

	if (!svm_get_guest_paging_structs(&pg_structs, vmcb))
		goto invalid_access;

	access = mmio_parse(cpu_data, vmcb->rip,
			    &pg_structs, is_write);
	if (!access.inst_len || access.size != 4)
		goto invalid_access;

	if (is_write)
		val = ((unsigned long *)guest_regs)[access.reg];

	result = ioapic_access_handler(cpu_data->cell, is_write, phys_addr,
				       &val);
	if (result == 0)
		result = pci_mmio_access_handler(cpu_data->cell, is_write,
						 phys_addr, &val);

	if (result == 1) {
		if (!is_write)
			((unsigned long *)guest_regs)[access.reg] = val;
		svm_skip_emulated_instruction(access.inst_len, vmcb);
		return true;
	}

invalid_access:
	/* report only unhandled access failures */
	if (result == 0)
		panic_printk("FATAL: Invalid MMIO/RAM %s, addr: %p\n",
			     is_write ? "write" : "read", phys_addr);
	return false;
}

/*
 * TODO: This is almost a complete copy of vmx_handle_io_access (sans vmcb access).
 * Refactor common parts.
 */
static bool svm_handle_io_access(struct registers *guest_regs,
				 struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;

	/* parse exit info for I/O instructions (see APM, 15.10.2 ) */
	u64 exitinfo = vmcb->exitinfo1;
	u16 port = (exitinfo >> 16) & 0xFFFF;
	bool dir_in = exitinfo & 0x1;
	unsigned int size = (exitinfo >> 4) & 0x7;

	/* string and REP-prefixed instructions are not supported */
	if (exitinfo & 0x0a)
		goto invalid_access;

	if (x86_pci_config_handler(guest_regs, cpu_data->cell, port, dir_in,
				   size) == 1) {
		/* Skip the port access instruction */
		vmcb->rip = vmcb->exitinfo2;
		return true;
	}

invalid_access:
	panic_printk("FATAL: Invalid PIO %s, port: %x size: %d\n",
		     dir_in ? "read" : "write", port, size);
	panic_printk("PCI address port: %x\n",
		     cpu_data->cell->pci_addr_port_val);
	return false;
}

static void dump_guest_regs(struct registers *guest_regs, struct vmcb *vmcb)
{
	panic_printk("RIP: %p RSP: %p FLAGS: %x\n", vmcb->rip,
		     vmcb->rsp, vmcb->rflags);
	panic_printk("RAX: %p RBX: %p RCX: %p\n", guest_regs->rax,
		     guest_regs->rbx, guest_regs->rcx);
	panic_printk("RDX: %p RSI: %p RDI: %p\n", guest_regs->rdx,
		     guest_regs->rsi, guest_regs->rdi);
	panic_printk("CS: %x BASE: %p AR-BYTES: %x EFER.LMA %d\n",
		     vmcb->cs.selector,
		     vmcb->cs.base,
		     vmcb->cs.access_rights,
		     (vmcb->efer & EFER_LMA));
	panic_printk("CR0: %p CR3: %p CR4: %p\n", vmcb->cr0,
		     vmcb->cr3, vmcb->cr4);
	panic_printk("EFER: %p\n", vmcb->efer);
}

void svm_handle_exit(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	int sipi_vector;
	bool res = false;

	cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_TOTAL]++;

	switch (vmcb->exitcode) {
		case VMEXIT_INVALID:
			panic_printk("FATAL: VM-Entry failure, error %d\n", vmcb->exitcode);
			dump_guest_regs(guest_regs, vmcb);
			return;
		case VMEXIT_NMI:
			cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_MANAGEMENT]++;
			sipi_vector = x86_handle_events(cpu_data);
			if (sipi_vector >= 0) {
				printk("CPU %d received SIPI, vector %x\n",
						cpu_data->cpu_id, sipi_vector);
				svm_cpu_reset(guest_regs, cpu_data, sipi_vector);
			}
			amd_iommu_check_pending_faults(cpu_data);
			return;
		case VMEXIT_CPUID:
			/* FIXME: We are not intercepting CPUID now */
			return;
		case VMEXIT_VMMCALL:
			svm_handle_hypercall(guest_regs, cpu_data);
			return;
		case VMEXIT_CR0_WRITE:
			cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_CR]++;
			if (svm_handle_cr(guest_regs, cpu_data))
				return;
			break;
		case VMEXIT_MSR:
			cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_MSR]++;
			if (!vmcb->exitinfo1)
				res = svm_handle_msr_read(guest_regs, cpu_data);
			else
				res = svm_handle_msr_write(guest_regs, cpu_data);
			if (res)
				return;
			break;
		case VMEXIT_NPF:
			if (!has_avic &&
			    (vmcb->exitinfo1 & 0x7) == 0x7 &&
			    vmcb->exitinfo2 >= XAPIC_BASE &&
			    vmcb->exitinfo2 < XAPIC_BASE + PAGE_SIZE) {
				/* APIC access in non-AVIC mode */
				cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_XAPIC]++;
				if (svm_handle_apic_access(guest_regs, cpu_data))
					return;
			} else {
				/* General MMIO (IOAPIC, PCI etc) */
				cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_MMIO]++;
				if (svm_handle_npf(guest_regs, cpu_data))
					return;
			}

			panic_printk("FATAL: Unhandled Nested Page Fault for (%p), "
					"error code is %04x", vmcb->exitinfo2,
					vmcb->exitinfo1 & 0xf);
			break;
		case VMEXIT_XSETBV:
			/* TODO: This is very much like vmx_handle_exit() code.
			   Refactor common parts */
			cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_XSETBV]++;
			if (guest_regs->rax & X86_XCR0_FP &&
			    (guest_regs->rax & ~cpuid_eax(0x0d)) == 0 &&
			    guest_regs->rcx == 0 && guest_regs->rdx == 0) {
				svm_skip_emulated_instruction(X86_INST_LEN_XSETBV, vmcb);
				asm volatile(
					"xsetbv"
					: /* no output */
					: "a" (guest_regs->rax), "c" (0), "d" (0));
				return;
			}
			panic_printk("FATAL: Invalid xsetbv parameters: "
					"xcr[%d] = %08x:%08x\n", guest_regs->rcx,
					guest_regs->rdx, guest_regs->rax);
			break;
		case VMEXIT_IOIO:
			cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_PIO]++;
			if (svm_handle_io_access(guest_regs, cpu_data))
				return;
			break;
		/* TODO: Handle VMEXIT_AVIC_NOACCEL and VMEXIT_AVIC_INCOMPLETE_IPI */
	}
	dump_guest_regs(guest_regs, vmcb);
	panic_halt(cpu_data);
}

void svm_cpu_park(struct per_cpu *cpu_data)
{
	/* TODO: Implement */
}

void svm_tlb_flush(struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;

	if (cpuid_edx(0x8000000A) & 0x60) {
		/* FIXME: Use symbolic names */
		vmcb->tlb_control = 0x03;
	} else {
		vmcb->tlb_control = 0x01;
	}
}
