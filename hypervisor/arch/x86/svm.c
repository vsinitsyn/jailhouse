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

#include <asm/apic.h>
#include <asm/percpu.h>
#include <asm/svm.h>

bool decode_assists = false;

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
		decode_assists = true;

	/* TODO: Check for AVIC, set a flag if it is present somewhere */

	return 0;
}


static int vmcb_setup(struct per_cpu *cpu_data)
{
	/* TODO: Need trap efer access to prevent SVME change; see Sect. 3.1.7 */

	return 0;
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

void svm_cpu_park(struct per_cpu *cpu_data)
{
	/* TODO: Implement */
}

void svm_tlb_flush(void)
{
	/* TODO: Implement */
}
