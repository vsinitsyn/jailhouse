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

#ifndef _JAILHOUSE_ASM_PROCESSOR_H
#define _JAILHOUSE_ASM_PROCESSOR_H

#include <asm/types.h>

#define X86_FEATURE_VMX					(1 << 5)
#define X86_FEATURE_GBPAGES				(1 << 26)
#define X86_FEATURE_RDTSCP				(1 << 27)

#define X86_FEATURE_SVM					(1 << 2)
#define X86_FEATURE_NP					(1 << 0)
#define X86_FEATURE_FLUSH_BY_ASID			(1 << 6)
#define X86_FEATURE_DECODE_ASSISTS			(1 << 7)
#define X86_FEATURE_AVIC				(1 << 13)

#define X86_RFLAGS_VM					(1 << 17)

#define X86_CR0_PE					0x00000001
#define X86_CR0_ET					0x00000010
#define X86_CR0_WP					0x00010000
#define X86_CR0_NW					0x20000000
#define X86_CR0_CD					0x40000000
#define X86_CR0_PG					0x80000000

#define X86_CR4_PAE					0x00000020
#define X86_CR4_PGE					0x00000080
#define X86_CR4_VMXE					0x00002000

#define X86_XCR0_FP					0x00000001

#define MSR_IA32_APICBASE				0x0000001b
#define MSR_IA32_FEATURE_CONTROL			0x0000003a
#define MSR_IA32_PAT					0x00000277
#define MSR_IA32_SYSENTER_CS				0x00000174
#define MSR_IA32_SYSENTER_ESP				0x00000175
#define MSR_IA32_SYSENTER_EIP				0x00000176
#define MSR_IA32_VMX_BASIC				0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS			0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS			0x00000482
#define MSR_IA32_VMX_EXIT_CTLS				0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS				0x00000484
#define MSR_IA32_VMX_MISC				0x00000485
#define MSR_IA32_VMX_CR0_FIXED0				0x00000486
#define MSR_IA32_VMX_CR0_FIXED1				0x00000487
#define MSR_IA32_VMX_CR4_FIXED0				0x00000488
#define MSR_IA32_VMX_CR4_FIXED1				0x00000489
#define MSR_IA32_VMX_PROCBASED_CTLS2			0x0000048b
#define MSR_IA32_VMX_EPT_VPID_CAP			0x0000048c
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS		0x0000048e
#define MSR_X2APIC_BASE					0x00000800
#define MSR_X2APIC_ICR					0x00000830
#define MSR_X2APIC_SELF_IPI				0x0000083f
#define MSR_X2APIC_END					MSR_X2APIC_SELF_IPI
#define MSR_EFER					0xc0000080
#define MSR_STAR					0xc0000081
#define MSR_LSTAR					0xc0000082
#define MSR_CSTAR					0xc0000083
#define MSR_SFMASK					0xc0000084
#define MSR_FS_BASE					0xc0000100
#define MSR_GS_BASE					0xc0000101
#define MSR_KERNGS_BASE					0xc0000102

#define FEATURE_CONTROL_LOCKED				(1 << 0)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1 << 2)

#define EFER_LME					0x00000100
#define EFER_LMA					0x00000400
#define EFER_NXE					0x00000800

#define GDT_DESC_NULL					0
#define GDT_DESC_CODE					1
#define GDT_DESC_TSS					2
#define GDT_DESC_TSS_HI					3
#define NUM_GDT_DESC					4

#define X86_INST_LEN_CPUID				2
#define X86_INST_LEN_RDMSR				2
#define X86_INST_LEN_WRMSR				2
#define X86_INST_LEN_VMCALL				3
#define X86_INST_LEN_MOV_TO_CR				3
#define X86_INST_LEN_XSETBV				3

#define X86_REX_CODE					4

#define X86_OP_MOV_TO_MEM				0x89
#define X86_OP_MOV_FROM_MEM				0x8b

#define NMI_VECTOR					2

#define DESC_TSS_BUSY					(1UL << (9 + 32))
#define DESC_PRESENT					(1UL << (15 + 32))
#define DESC_CODE_DATA					(1UL << (12 + 32))
#define DESC_PAGE_GRAN					(1UL << (23 + 32))

#ifndef __ASSEMBLY__

struct registers {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rdi;
	unsigned long rsi;
	unsigned long rbp;
	unsigned long unused;
	unsigned long rbx;
	unsigned long rdx;
	unsigned long rcx;
	unsigned long rax;
};

struct desc_table_reg {
	u16 limit;
	u64 base;
} __attribute__((packed));

struct segment {
	u64 base;
	u32 limit;
	u32 access_rights;
	u16 selector;
};

static unsigned long __force_order;

static inline void cpu_relax(void)
{
	asm volatile("rep; nop" : : : "memory");
}

static inline void memory_barrier(void)
{
	asm volatile("mfence" : : : "memory");
}

static inline void __cpuid(unsigned int *eax, unsigned int *ebx,
			   unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
	    : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
	    : "0" (*eax), "2" (*ecx)
	    : "memory");
}

static inline void cpuid(unsigned int op, unsigned int *eax, unsigned int *ebx,
			 unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = 0;
	__cpuid(eax, ebx, ecx, edx);
}

#define CPUID_REG(reg)						\
static inline unsigned int cpuid_##reg(unsigned int op)		\
{								\
	unsigned int eax, ebx, ecx, edx;			\
								\
	cpuid(op, &eax, &ebx, &ecx, &edx);			\
	return reg;						\
}

CPUID_REG(eax)
CPUID_REG(ebx)
CPUID_REG(ecx)
CPUID_REG(edx)

static inline unsigned long read_cr0(void)
{
	unsigned long cr0;

	asm volatile("mov %%cr0,%0" : "=r" (cr0), "=m" (__force_order));
	return cr0;
}

static inline void write_cr0(unsigned long val)
{
	asm volatile("mov %0,%%cr0" : : "r" (val), "m" (__force_order));
}

static inline unsigned long read_cr3(void)
{
	unsigned long cr3;

	asm volatile("mov %%cr3,%0" : "=r" (cr3), "=m" (__force_order));
	return cr3;
}

static inline void write_cr3(unsigned long val)
{
	asm volatile("mov %0,%%cr3" : : "r" (val), "m" (__force_order));
}

static inline unsigned long read_cr4(void)
{
	unsigned long cr4;

	asm volatile("mov %%cr4,%0" : "=r" (cr4), "=m" (__force_order));
	return cr4;
}

static inline void write_cr4(unsigned long val)
{
	asm volatile("mov %0,%%cr4" : : "r" (val), "m" (__force_order));
}

static inline unsigned long read_msr(unsigned int msr)
{
	u32 low, high;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
	return low | ((unsigned long)high << 32);
}

static inline void write_msr(unsigned int msr, unsigned long val)
{
	asm volatile("wrmsr"
		: /* no output */
		: "c" (msr), "a" (val), "d" (val >> 32)
		: "memory");
}

static inline void read_gdtr(struct desc_table_reg *val)
{
	asm volatile("sgdtq %0" : "=m" (*val));
}

static inline void write_gdtr(struct desc_table_reg *val)
{
	asm volatile("lgdtq %0" : : "m" (*val));
}

static inline void read_idtr(struct desc_table_reg *val)
{
	asm volatile("sidtq %0" : "=m" (*val));
}

static inline void write_idtr(struct desc_table_reg *val)
{
	asm volatile("lidtq %0" : : "m" (*val));
}

static inline void enable_irq(void)
{
	asm volatile("sti");
}

static inline void disable_irq(void)
{
	asm volatile("cli");
}

#endif /* !__ASSEMBLY__ */

#endif /* !_JAILHOUSE_ASM_PROCESSOR_H */
