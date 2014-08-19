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
 * Based on vmx.c written by Jan Kiszka.
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
#include <jailhouse/utils.h>

#include <asm/apic.h>
#include <asm/amd_iommu.h>
#include <asm/control.h>
#include <asm/ioapic.h>
#include <asm/iommu.h>
#include <asm/paging.h>
#include <asm/pci.h>
#include <asm/percpu.h>
#include <asm/svm.h>
#include <asm/vmcb.h>
#include <asm/vcpu.h>

#define SVM_CR0_CLEARED_BITS	(~(X86_CR0_CD | X86_CR0_NW))

static bool has_avic, has_assists;

static const struct segment invalid_seg;

static struct paging npt_paging[NPT_PAGE_DIR_LEVELS];

static u8 __attribute__((aligned(PAGE_SIZE))) msrpm[][0x2000/4] = {
	[ SVM_MSRPM_0000 ] = {
		[      0/4 ...  0x017/4 ] = 0,    /* 0x01b (w) */
		[  0x018/4 ...  0x01b/4 ] = 0x80,
		[  0x01c/4 ...  0x7ff/4 ] = 0,
		[  0x800/4 ...  0x803/4 ] = 0x90, /* 0x802 (r), 0x803 (r) */
		[  0x804/4 ...  0x807/4 ] = 0,
		[  0x808/4 ...  0x80b/4 ] = 0x93, /* 0x808 (rw), 0x80a (r), 0x80b (w) */
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

/* This page is mapped so the code begins at 0x000ffff0 */
static u8 __attribute__((aligned(PAGE_SIZE))) parking_code[PAGE_SIZE] = {
	[ 0xff0 ] = 0xfa, /* 1: cli */
	[ 0xff1 ] = 0xf4, /*    hlt */
	[ 0xff2 ] = 0xeb,
	[ 0xff3 ] = 0xfc  /*    jmp 1b */
};

static void *parked_mode_npt;

static void *avic_page;

static int svm_check_features(void)
{
	/* SVM is available */
	if (!(cpuid_ecx(0x80000001) & X86_FEATURE_SVM))
		return -ENODEV;

	/* Nested paging */
	if (!(cpuid_edx(0x8000000A) & X86_FEATURE_NP))
		return -EIO;

	/* Decode assists */
	if ((cpuid_edx(0x8000000A) & X86_FEATURE_DECODE_ASSISTS))
		has_assists = true;

	/* AVIC support */
	if (cpuid_edx(0x8000000A) & X86_FEATURE_AVIC)
		has_avic = true;

	return 0;
}

static void set_svm_segment_from_dtr(struct svm_segment *svm_segment,
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
static void set_svm_segment_from_segment(struct svm_segment *svm_segment,
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

static bool vcpu_set_cell_config(struct cell *cell, struct vmcb *vmcb)
{
	/* No real need for this function; used for consistency with vmx.c */
	vmcb->iopm_base_pa = page_map_hvirt2phys(cell->svm.iopm);
	vmcb->n_cr3 = page_map_hvirt2phys(cell->svm.npt_structs.root_table);

	return true;
}

static int vmcb_setup(struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;

	memset(vmcb, sizeof(struct vmcb), 0);

	vmcb->cr0 = read_cr0() & SVM_CR0_CLEARED_BITS;
	vmcb->cr3 = cpu_data->linux_cr3;
	vmcb->cr4 = read_cr4();

	set_svm_segment_from_segment(&vmcb->cs, &cpu_data->linux_cs);
	set_svm_segment_from_segment(&vmcb->ds, &cpu_data->linux_ds);
	set_svm_segment_from_segment(&vmcb->es, &cpu_data->linux_es);
	set_svm_segment_from_segment(&vmcb->fs, &cpu_data->linux_fs);
	set_svm_segment_from_segment(&vmcb->gs, &cpu_data->linux_gs);
	set_svm_segment_from_segment(&vmcb->ss, &invalid_seg);
	set_svm_segment_from_segment(&vmcb->tr, &cpu_data->linux_tss);

	set_svm_segment_from_dtr(&vmcb->ldtr, NULL);
	set_svm_segment_from_dtr(&vmcb->gdtr, &cpu_data->linux_gdtr);
	set_svm_segment_from_dtr(&vmcb->idtr, &cpu_data->linux_idtr);

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
	/* No more than one guest owns the CPU */
	vmcb->guest_asid = 1;

	/* Explicitly mark all of the state as new */
	vmcb->clean_bits = 0;

	return vcpu_set_cell_config(cpu_data->cell, vmcb);
}

unsigned long arch_page_map_gphys2phys(struct per_cpu *cpu_data,
				       unsigned long gphys)
{
	return page_map_virt2phys(&cpu_data->cell->svm.npt_structs, gphys);
}

static void npt_set_next_pt(pt_entry_t pte, unsigned long next_pt)
{
	/* See APMv2, Section 15.25.5 */
       *pte = (next_pt & 0x000ffffffffff000UL) |
	       (PAGE_DEFAULT_FLAGS | PAGE_FLAG_US);
}

int vcpu_vendor_init(void)
{
	struct paging_structures parking_pt;
	unsigned long vm_cr;
	int err, n;

	err = svm_check_features();
	if (err)
		return err;

	vm_cr = read_msr(MSR_VM_CR);
	if (vm_cr & VM_CR_SVMDIS)
		/* SVM disabled in BIOS */
		return -EPERM;

	/* Nested paging is the same as the native one */
	memcpy(npt_paging, x86_64_paging, sizeof(npt_paging));
	for(n = 0; n < NPT_PAGE_DIR_LEVELS; n++)
		npt_paging[n].set_next_pt = npt_set_next_pt;

	/* Map guest parking code (shared between cells and CPUs) */
	parking_pt.root_paging = npt_paging;
	parking_pt.root_table = parked_mode_npt = page_alloc(&mem_pool, 1);
	if (!parked_mode_npt)
		return -ENOMEM;
	err = page_map_create(&parking_pt, page_map_hvirt2phys(parking_code),
			PAGE_SIZE, 0x000ff000,
			PAGE_READONLY_FLAGS | PAGE_FLAG_US,
			PAGE_MAP_NON_COHERENT);
	if (err)
		return err;

	/* This is always false for AMD now (except in nested SVM);
	   see Sect. 16.3.1 in APMv2 */
	if (using_x2apic) {
		/* allow direct x2APIC access except for ICR writes */
		memset(msrpm[SVM_MSRPM_0000], 0, sizeof(msrpm[SVM_MSRPM_0000]));
		msrpm[SVM_MSRPM_0000][0x830/4] = 0x02;
	} else {
		if (has_avic) {
			avic_page = page_alloc(&remap_pool, 1);
			if (!avic_page)
				return -ENOMEM;
		}
	}

	return vcpu_cell_init(&root_cell);
}

int vcpu_vendor_cell_init(struct cell *cell)
{
	u64 flags;
	int err;

	/* build root NPT of cell */
	cell->svm.npt_structs.root_paging = npt_paging;
	cell->svm.npt_structs.root_table = page_alloc(&mem_pool, 1);
	if (!cell->svm.npt_structs.root_table)
		return -ENOMEM;

	if (!has_avic) {
		/*
		 * Map xAPIC as is; reads are passed, writes are trapped.
		 *
		 * FIXME: This is known not to work in nested SVM setup, so
		 * for now, all access is traped (here and in
		 * vcpu_handle_exit() as well).
		 */
		flags = PAGE_READONLY_FLAGS |
			/* PAGE_FLAG_US | */
			PAGE_FLAG_WRITETHROUGH |
			PAGE_FLAG_UNCACHED;
		err = page_map_create(&cell->svm.npt_structs, XAPIC_BASE,
				      PAGE_SIZE, XAPIC_BASE,
				      flags,
				      PAGE_MAP_NON_COHERENT);
	} else {
		flags = PAGE_DEFAULT_FLAGS | PAGE_FLAG_UNCACHED;
		err = page_map_create(&cell->svm.npt_structs,
				      page_map_hvirt2phys(avic_page),
				      PAGE_SIZE, XAPIC_BASE,
				      flags,
				      PAGE_MAP_NON_COHERENT);
	}

	return err;
}

/*
 * TODO: These two functions are almost 100% copy of their vmx counterparts
 * (sans page flags). Refactor them.
 */
int vcpu_map_memory_region(struct cell *cell,
			  const struct jailhouse_memory *mem)
{
	u64 phys_start = mem->phys_start;
	u32 flags = PAGE_FLAG_US; /* See APMv2, Section 15.25.5 */

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

int vcpu_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	return page_map_destroy(&cell->svm.npt_structs, mem->virt_start,
				mem->size, PAGE_MAP_NON_COHERENT);
}

void vcpu_vendor_cell_exit(struct cell *cell)
{
	page_map_destroy(&cell->svm.npt_structs, XAPIC_BASE, PAGE_SIZE,
			 PAGE_MAP_NON_COHERENT);
	page_free(&mem_pool, cell->svm.npt_structs.root_table, 1);
}

int vcpu_init(struct per_cpu *cpu_data)
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

	cpu_data->svm_state = SVMON;

	if (!vmcb_setup(cpu_data))
		return -EIO;

	write_msr(MSR_VM_HSAVE_PA, page_map_hvirt2phys(cpu_data->host_state));

	return 0;
}

void vcpu_exit(struct per_cpu *cpu_data)
{
	unsigned long efer;

	if (cpu_data->svm_state == SVMOFF)
		return;

	cpu_data->svm_state = SVMOFF;

	efer = read_msr(MSR_EFER);
	efer &= ~EFER_SVME;
	write_msr(MSR_EFER, efer);

	write_msr(MSR_VM_HSAVE_PA, 0);
}

void vcpu_activate_vmm(struct per_cpu *cpu_data)
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
		: "m" (vmcb_pa), "D" (cpu_data->linux_reg), "m" (host_stack)
		: "memory", "r15", "r14", "r13", "r12", "rbx", "rbp", "rax", "cc");
	__builtin_unreachable();
}

void __attribute__((noreturn))
vcpu_deactivate_vmm(struct registers *guest_regs, struct per_cpu *cpu_data)
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

static void vcpu_reset(struct per_cpu *cpu_data, unsigned int sipi_vector)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	unsigned long val;
	bool ok = true;

	vmcb->cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;
	vmcb->cr4 = 0;
	vmcb->cr4 = 0;

	vmcb->rflags = 0x02;

	val = 0;
	if (sipi_vector == APIC_BSP_PSEUDO_SIPI) {
		val = 0xfff0;
		sipi_vector = 0xf0;
	}
	vmcb->rip = val;
	vmcb->rsp = 0;

	vmcb->cs.selector = sipi_vector << 8;
	vmcb->cs.base = sipi_vector << 12;
	vmcb->cs.limit = 0xffff;
	vmcb->cs.access_rights = 0x009b;

	vmcb->ds.selector = 0;
	vmcb->ds.base = 0;
	vmcb->ds.limit = 0xffff;
	vmcb->ds.access_rights = 0x0093;

	vmcb->es.selector = 0;
	vmcb->es.base = 0;
	vmcb->es.limit = 0xffff;
	vmcb->es.access_rights = 0x0093;

	vmcb->fs.selector = 0;
	vmcb->fs.base = 0;
	vmcb->fs.limit = 0xffff;
	vmcb->fs.access_rights = 0x0093;

	vmcb->gs.selector = 0;
	vmcb->gs.base = 0;
	vmcb->gs.limit = 0xffff;
	vmcb->gs.access_rights = 0x0093;

	vmcb->ss.selector = 0;
	vmcb->ss.base = 0;
	vmcb->ss.limit = 0xffff;
	vmcb->ss.access_rights = 0x0093;

	vmcb->tr.selector = 0;
	vmcb->tr.base = 0;
	vmcb->tr.limit = 0xffff;
	vmcb->tr.access_rights = 0x008b;

	vmcb->ldtr.selector = 0;
	vmcb->ldtr.base = 0;
	vmcb->ldtr.limit = 0xffff;
	vmcb->ldtr.access_rights = 0x0082;

	vmcb->gdtr.selector = 0;
	vmcb->gdtr.base = 0;
	vmcb->gdtr.limit = 0xffff;
	vmcb->gdtr.access_rights = 0;

	vmcb->idtr.selector = 0;
	vmcb->idtr.base = 0;
	vmcb->idtr.limit = 0xffff;
	vmcb->idtr.access_rights = 0;

	vmcb->efer = 0;

	/* These MSRs are undefined on reset */
	vmcb->star = 0;
	vmcb->lstar = 0;
	vmcb->cstar = 0;
	vmcb->sfmask = 0;
	vmcb->sysenter_cs = 0;
	vmcb->sysenter_eip = 0;
	vmcb->sysenter_esp = 0;
	vmcb->kerngsbase = 0;

	vmcb->g_pat = 0x0007040600070406;

	vmcb->dr7 = 0x00000400;

	/* Almost all of the guest state changed */
	vmcb->clean_bits = 0;

	ok &= vcpu_set_cell_config(cpu_data->cell, vmcb);

	/* This is always false, but to be consistent with vmx.c... */
	if (!ok) {
		panic_printk("FATAL: CPU reset failed\n");
		panic_stop(cpu_data);
	}
}

inline void vcpu_skip_emulated_instruction(struct per_cpu *cpu_data, unsigned int inst_len)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	vmcb->rip += inst_len;
}

static void update_efer(struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	unsigned long efer = vmcb->efer;

	if ((efer & (EFER_LME | EFER_LMA)) != EFER_LME)
		return;

	efer |= EFER_LMA;

	/* Flush TLB on LMA/LME change: See APMv2, Sect. 15.16 */
	if ((vmcb->efer ^ efer) & EFER_LMA)
		vcpu_tlb_flush(cpu_data);

	vmcb->efer = efer;
	vmcb->clean_bits &= ~CLEAN_BITS_CRX;
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
	} else if (!(vmcb->cr0 & X86_CR0_PG)) {
		/*
		 * Can be in non-paged protected mode as well, but
		 * the translation mechanism will stay the same ayway.
		 */
		pg_structs->root_paging = realmode_paging;
		/*
		 * This will make page_map_get_guest_page map the page
		 * that also contains the bootstrap code and, thus, is
		 * always present in a cell.
		 */
		pg_structs->root_table_gphys = 0xff000;
	} else {
		printk("FATAL: Unsupported paging mode\n");
		return false;
	}
	return true;
}

static bool x86_parse_mov_to_cr(struct per_cpu *cpu_data,
				unsigned long pc,
				unsigned char reg,
				unsigned long *gpr)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	struct guest_paging_structures pg_structs;
	/* No prefixes are supported yet */
	u8 opcodes[] = {0x0f, 0x22}, modrm;
	unsigned int remaining, size = 0;
	unsigned long cs_base;
	bool ok = false;
	const u8 *inst = NULL;
	int n;

	remaining = ARRAY_SIZE(opcodes);
	if (!svm_get_guest_paging_structs(&pg_structs, vmcb))
		goto out;
	cs_base = (vmcb->efer & EFER_LMA) ? 0 : vmcb->cs.base;

	if (!size) {
		size = remaining;
		inst = vcpu_map_inst(cpu_data, &pg_structs,
				     cs_base + pc, &size);
		if (!inst)
			goto out;
		remaining -= size;
		pc += size;
	}

	for (n = 0; n < ARRAY_SIZE(opcodes); n++, inst++) {
		if (*inst != opcodes[n])
			goto out;

		if (!size) {
			size = remaining;
			inst = vcpu_map_inst(cpu_data, &pg_structs,
					     cs_base + pc, &size);
			if (!inst)
				goto out;
			remaining -= size;
			pc += size;
		}
	}

	if (!size) {
		size = remaining;
		inst = vcpu_map_inst(cpu_data, &pg_structs,
				     cs_base + pc, &size);
		if (!inst)
			goto out;
		remaining -= size;
		pc += size;
	}

	modrm = *inst;

	if (((modrm & 0x38) >> 3) != reg)
		goto out;

	if (gpr)
		*gpr = (modrm & 0x7);

	ok = true;
out:
	return ok;
}

/*
 * XXX: The only visible reason to have this function (vmx.c consistency
 * aside) is to prevent cells from setting invalid CD+NW combinations that
 * result in no more than VMEXIT_INVALID. Maybe we can get along without it
 * altogether?
 */
static bool svm_handle_cr(struct registers *guest_regs,
			  struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	unsigned long reg, val;
	bool ok = true;

	if (has_assists) {
		if (!(vmcb->exitinfo1 & (1UL << 63))) {
			panic_printk("FATAL: Unsupported CR access (LMSW or CLTS)\n");
			ok = false;
			goto out;
		}
		reg = vmcb->exitinfo1 & 0x07;
	} else {
		if (!x86_parse_mov_to_cr(cpu_data, vmcb->rip, 0, &reg)) {
			panic_printk("FATAL: Unable to parse MOV-to-CR instruction\n");
			ok = false;
			goto out;
		}
	};

	if (reg == 4)
		val = vmcb->rsp;
	else
		val = ((unsigned long *)guest_regs)[15 - reg];

	vcpu_skip_emulated_instruction(cpu_data, X86_INST_LEN_MOV_TO_CR);
	/* Flush TLB on PG/WP/CD/NW  change: See APMv2, Sect. 15.16 */
	if ((val ^ vmcb->cr0) & (X86_CR0_PG | X86_CR0_WP | X86_CR0_CD | X86_CR0_NW))
		vcpu_tlb_flush(cpu_data);
	/* TODO: better check for #GP reasons */
	vmcb->cr0 = val & SVM_CR0_CLEARED_BITS;
	if (val & X86_CR0_PG)
		update_efer(cpu_data);
	vmcb->clean_bits &= ~CLEAN_BITS_CRX;

out:
	return ok;
}

static bool svm_handle_msr_read(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	if (guest_regs->rcx >= MSR_X2APIC_BASE &&
	    guest_regs->rcx <= MSR_X2APIC_END) {
		vcpu_skip_emulated_instruction(cpu_data, X86_INST_LEN_RDMSR);
		x2apic_handle_read(guest_regs);
		return true;
	} else {
		panic_printk("FATAL: Unhandled MSR read: %x\n",
				guest_regs->rcx);
		return false;
	}
}

static bool svm_handle_msr_write(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	unsigned long efer;
	bool result = true;

	if (guest_regs->rcx >= MSR_X2APIC_BASE &&
	    guest_regs->rcx <= MSR_X2APIC_END) {
		result = x2apic_handle_write(guest_regs, cpu_data);
		goto out;
	}
	if (guest_regs->rcx == MSR_EFER) {
		/* Never let a guest to disable SVME; see APMv2, Sect. 3.1.7 */
		efer = (guest_regs->rax & 0xffffffff) |
			(guest_regs->rdx << 32) | EFER_SVME;
		/* Flush TLB on LME/NXE change: See APMv2, Sect. 15.16 */
		if ((efer ^ vmcb->efer) & (EFER_LME | EFER_NXE))
			vcpu_tlb_flush(cpu_data);
		vmcb->efer = efer;
		vmcb->clean_bits &= ~CLEAN_BITS_CRX;
		goto out;
	}

	result = false;
	panic_printk("FATAL: Unhandled MSR write: %x\n",
			guest_regs->rcx);
out:
	if (result)
		vcpu_skip_emulated_instruction(cpu_data, X86_INST_LEN_WRMSR);
	return result;
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

	if (!svm_get_guest_paging_structs(&pg_structs, vmcb))
		goto out_err;

	inst_len = apic_mmio_access(guest_regs, cpu_data,
			vmcb->rip,
			&pg_structs, offset >> 4,
			is_write);
	if (!inst_len)
		goto out_err;

	vcpu_skip_emulated_instruction(cpu_data, inst_len);
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
		vcpu_skip_emulated_instruction(cpu_data, access.inst_len);
		return true;
	}

invalid_access:
	/* report only unhandled access failures */
	if (result == 0)
		panic_printk("FATAL: Invalid MMIO/RAM %s, addr: %p\n",
			     is_write ? "write" : "read", phys_addr);
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

void vcpu_handle_exit(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	int sipi_vector;
	bool res = false;

	cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_TOTAL]++;
	/*
	 * All guest state is marked unmodified; individual handlers must clear
	 * the bits as needed.
	 */
	vmcb->clean_bits = 0xffffffff;

	switch (vmcb->exitcode) {
		case VMEXIT_INVALID:
			panic_printk("FATAL: VM-Entry failure, error %d\n", vmcb->exitcode);
			dump_guest_regs(guest_regs, vmcb);
			return;
		case VMEXIT_NMI:
			cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_MANAGEMENT]++;
			/* Temporarily enable GIF to consume pending NMI */
			asm volatile("stgi; clgi" : : : "memory");
			sipi_vector = x86_handle_events(cpu_data);
			if (sipi_vector >= 0) {
				printk("CPU %d received SIPI, vector %x\n",
						cpu_data->cpu_id, sipi_vector);
				vcpu_reset(cpu_data, sipi_vector);
				memset(guest_regs, 0, sizeof(*guest_regs));
			}
			iommu_check_pending_faults(cpu_data);
			return;
		case VMEXIT_CPUID:
			/* FIXME: We are not intercepting CPUID now */
			return;
		case VMEXIT_VMMCALL:
			vcpu_handle_hypercall(guest_regs, cpu_data);
			return;
		case VMEXIT_CR0_SEL_WRITE:
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
			    /* (vmcb->exitinfo1 & 0x7) == 0x7 && */
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
					"error code is %x\n", vmcb->exitinfo2,
					vmcb->exitinfo1 & 0xf);
			break;
		case VMEXIT_XSETBV:
			/* TODO: This is very much like vmx_handle_exit() code.
			   Refactor common parts */
			cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_XSETBV]++;
			if (guest_regs->rax & X86_XCR0_FP &&
			    (guest_regs->rax & ~cpuid_eax(0x0d)) == 0 &&
			    guest_regs->rcx == 0 && guest_regs->rdx == 0) {
				vcpu_skip_emulated_instruction(cpu_data, X86_INST_LEN_XSETBV);
				asm volatile(
					"xsetbv"
					: /* no output */
					: "a" (guest_regs->rax), "c" (0), "d" (0));
				return;
			}
			panic_printk("FATAL: Invalid xsetbv parameters: "
					"xcr[%d] = %x:%x\n", guest_regs->rcx,
					guest_regs->rdx, guest_regs->rax);
			break;
		case VMEXIT_IOIO:
			cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_PIO]++;
			if (vcpu_handle_io_access(guest_regs, cpu_data))
				return;
			break;
		/* TODO: Handle VMEXIT_AVIC_NOACCEL and VMEXIT_AVIC_INCOMPLETE_IPI */
		default:
			panic_printk("FATAL: Unexpected #VMEXIT, exitcode %x, "
					"exitinfo1 %p exitinfo2 %p\n",
					vmcb->exitcode, vmcb->exitinfo1,
					vmcb->exitinfo2);
	}
	dump_guest_regs(guest_regs, vmcb);
	panic_halt(cpu_data);
}

void vcpu_park(struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;

	vcpu_reset(cpu_data, APIC_BSP_PSEUDO_SIPI);
	/* No need to clear VMCB Clean bit: vcpu_reset() already does this */
	vmcb->n_cr3 = page_map_hvirt2phys(parked_mode_npt);

	vcpu_tlb_flush(cpu_data);
}

void vcpu_nmi_handler(struct per_cpu *cpu_data)
{
	printk("Consuming pending NMI on CPU %d\n", cpu_data->cpu_id);
}

void vcpu_tlb_flush(struct per_cpu *cpu_data)
{
	struct vmcb *vmcb = &cpu_data->vmcb;

	if (cpuid_edx(0x8000000A) & X86_FEATURE_FLUSH_BY_ASID) {
		/* FIXME: Use symbolic names */
		vmcb->tlb_control = 0x03;
	} else {
		vmcb->tlb_control = 0x01;
	}
}

u64 vcpu_get_efer(struct per_cpu *cpu_data)
{
	return cpu_data->vmcb.efer;
}

u64 vcpu_get_rflags(struct per_cpu *cpu_data)
{
	return cpu_data->vmcb.rflags;
}

u16 vcpu_get_cs_selector(struct per_cpu *cpu_data)
{
	return cpu_data->vmcb.cs.selector;
}

u64 vcpu_get_rip(struct per_cpu *cpu_data)
{
	return cpu_data->vmcb.rip;
}

const u8 *vcpu_get_inst_bytes(struct per_cpu *cpu_data,
		              const struct guest_paging_structures *pg_structs,
			      unsigned long pc, unsigned int *size)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	unsigned long start;

	if (has_assists) {
		if (!size || !*size)
			return NULL;
		start = vmcb->rip - pc;
		if (start < vmcb->bytes_fetched) {
			*size = vmcb->bytes_fetched - start;
			return &vmcb->guest_bytes[start];
		} else {
			return NULL;
		}
	} else {
		return vcpu_map_inst(cpu_data, pg_structs, pc, size);
	}
}

void vcpu_vendor_get_cell_io_bitmap(struct cell *cell,
		                    struct vcpu_io_bitmap *iobm)
{
	if (iobm) {
		iobm->data = cell->svm.iopm;
		iobm->size = sizeof(cell->svm.iopm);
	}
}

void vcpu_vendor_get_io_intercept(struct per_cpu *cpu_data,
		                  struct vcpu_io_intercept *out)
{
	struct vmcb *vmcb = &cpu_data->vmcb;
	u64 exitinfo = vmcb->exitinfo1;

	/* parse exit info for I/O instructions (see APM, 15.10.2 ) */
	if (out) {
		out->port = (exitinfo >> 16) & 0xFFFF;
		out->size = (exitinfo >> 4) & 0x7;
		out->in = !!(exitinfo & 0x1);
		out->inst_len = vmcb->exitinfo2 - vmcb->rip;
		out->rep_or_str = !!(exitinfo & 0x0a);
	}
}
