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
#include <jailhouse/paging.h>
#include <jailhouse/processor.h>
#include <jailhouse/paging.h>
#include <jailhouse/string.h>

#include <asm/apic.h>
#include <asm/atomic.h>
#include <asm/paging.h>
#include <asm/percpu.h>
#include <asm/svm.h>

bool decode_assists = false, has_avic = false;

static u32 current_asid = 1; /* ASID 0 is for host mode */

static const struct segment invalid_seg = {
	.access_rights = 0x0000
};

static struct paging npt_paging[NPT_PAGE_DIR_LEVELS];

static u8 __attribute__((aligned(PAGE_SIZE))) msrpm[][0x2000/4] = {
	[ SVM_MSRPM_0000 ] = {
		[      0/4 ...  0x7ff/4 ] = 0,
		[  0x800/4 ...  0x803/4 ] = 0x90, /* 0x802 (r), 0x803 (r) */
		[  0x804/4 ...  0x807/4 ] = 0,
		[  0x808/4 ...  0x80b/4 ] = 0x13, /* 0x808 (rw), 0x80a (r) */
		[  0x80c/4 ...  0x80f/4 ] = 0x88, /* 0x80d (w), 0x80f (w) */
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
	if (cpuid_edx(0x8000000A) & 0x07)
		decode_assists = true;

	if (cpuid_edx(0x8000000A) & 0x2000)
		has_avic = true;

	return 0;
}

static void svm_set_guest_segment_from_dtr(struct segment *segment, struct desc_table_reg *dtr)
{
	struct segment tmp = { 0 };

	if (dtr)
		tmp.limit = dtr->limit & 0xffff;

	*segment = tmp;
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

	vmcb->cr0 = read_cr0() & ~(X86_CR0_CD | X86_CR0_NW);
	vmcb->cr3 = read_cr3();
	vmcb->cr4 = read_cr4();

	vmcb->cs = cpu_data->linux_cs;
	vmcb->ds = cpu_data->linux_ds;
	vmcb->es = cpu_data->linux_es;
	vmcb->fs = cpu_data->linux_fs;
	vmcb->gs = cpu_data->linux_gs;
	vmcb->ss = invalid_seg;
	vmcb->tr = cpu_data->linux_tss;
	
	svm_set_guest_segment_from_dtr(&vmcb->ldtr, NULL);
	svm_set_guest_segment_from_dtr(&vmcb->gdtr, &cpu_data->linux_gdtr);
	svm_set_guest_segment_from_dtr(&vmcb->idtr, &cpu_data->linux_idtr);
	
	vmcb->cpl = 0; /* Linux runs in ring 0 before migration */

	vmcb->rflags = 0x02;
	vmcb->rsp = cpu_data->linux_sp +
		(NUM_ENTRY_REGS + 1) * sizeof(unsigned long);
	vmcb->rip = cpu_data->linux_ip;
	vmcb->sysenter_cs = read_msr(MSR_IA32_SYSENTER_CS);
	vmcb->sysenter_eip = read_msr(MSR_IA32_SYSENTER_EIP);
	vmcb->sysenter_esp = read_msr(MSR_IA32_SYSENTER_ESP);

	vmcb->dr6 = 0x00000ff0;
	vmcb->dr7 = 0x00000400;

	/* Make the hypervisor visible */
	vmcb->efer = (cpu_data->linux_efer | EFER_SVME);

	/* TODO: switch PAT, PERF */

	vmcb->general1_intercepts |= GENERAL1_INTERCEPT_NMI;
	vmcb->general1_intercepts |= GENERAL1_INTERCEPT_CR0_SEL_WRITE;
	/* TODO: Do we need this for SVM ? */
	/* vmcb->general1_intercepts |= GENERAL1_INTERCEPT_CPUID; */
	vmcb->general1_intercepts |= GENERAL1_INTERCEPT_IOIO_PROT;
	vmcb->general1_intercepts |= GENERAL1_INTERCEPT_MSR_PROT;

	vmcb->general2_intercepts |= GENERAL2_INTERCEPT_VMRUN; /* Required */

	vmcb->msrpm_base_pa = page_map_hvirt2phys(msrpm);

	vmcb->np_enable = 1;
	vmcb->guest_asid = asid;

	return svm_set_cell_config(cpu_data->cell, vmcb);
}

unsigned long arch_page_map_gphys2phys(struct per_cpu *cpu_data,
				       unsigned long gphys)
{
	/* TODO: Implement */
	return page_map_virt2phys(/* Nested paging struct */ NULL, gphys);
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

	/* TODO: Check for x2apic, modify the msr bitmap */

	return 0;
}

int svm_cell_init(struct cell *cell)
{
	/* TODO: Implement */
	return 0;
}

void svm_root_cell_shrink(struct jailhouse_cell_desc *config)
{
	/* TODO: Implement */
}

int svm_map_memory_region(struct cell *cell,
			  const struct jailhouse_memory *mem)
{
	/* TODO: Implement */
	return 0;
}

int svm_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	/* TODO: Implement */
	return 0;
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
	/* TODO: Implement */
	__builtin_unreachable();
}

void svm_handle_exit(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	/* TODO: Implement */
}

void svm_entry_failure(struct per_cpu *cpu_data)
{
	/* TODO: Implement */
}

void svm_cpu_park(void)
{
	/* TODO: Implement */
}

void svm_tlb_flush(struct per_cpu *cpu_data)
{
	/* TODO: Implement */
}
