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

#ifndef _JAILHOUSE_ASM_PERCPU_H
#define _JAILHOUSE_ASM_PERCPU_H

#include <jailhouse/types.h>
#include <asm/paging.h>
#include <asm/processor.h>

#include <jailhouse/hypercall.h>

#define NUM_ENTRY_REGS			6

/* Keep in sync with struct per_cpu! */
#define PERCPU_SIZE_SHIFT		14
#define PERCPU_STACK_END		PAGE_SIZE
#define PERCPU_LINUX_SP			PERCPU_STACK_END

#ifndef __ASSEMBLY__

#include <asm/cell.h>
#include <asm/spinlock.h>
#include <asm/vmx.h>

/**
 * @defgroup Per-CPU Per-CPU Subsystem
 *
 * The per-CPU subsystem provides a CPU-local state structure and accessors.
 *
 * @{
 */

/** Per-CPU states. */
struct per_cpu {
	/* Keep these two in sync with defines above! */
	/** Stack used while in hypervisor mode. */
	u8 stack[PAGE_SIZE];
	/** Linux stack pointer, used for handover to hypervisor. */
	unsigned long linux_sp;

	/** Self reference, required for this_cpu_data(). */
	struct per_cpu *cpu_data;
	/** Logical CPU ID (same as Linux). */
	unsigned int cpu_id;
	/** Physical APIC ID. */
	u32 apic_id;
	/** Owning cell. */
	struct cell *cell;

	/** Statistic counters. */
	u32 stats[JAILHOUSE_NUM_CPU_STATS];

	/** Linux states, used for handover to/from hypervisor. @{ */
	struct desc_table_reg linux_gdtr;
	struct desc_table_reg linux_idtr;
	unsigned long linux_reg[NUM_ENTRY_REGS];
	unsigned long linux_ip;
	unsigned long linux_cr3;
	struct segment linux_cs;
	struct segment linux_ds;
	struct segment linux_es;
	struct segment linux_fs;
	struct segment linux_gs;
	struct segment linux_tss;
	unsigned long linux_efer;
	unsigned long linux_sysenter_cs;
	unsigned long linux_sysenter_eip;
	unsigned long linux_sysenter_esp;
	/** @} */
	/** True when CPU is initialized by hypervisor. */
	bool initialized;
	union {
		/** VMX initialization state */
		enum vmx_state vmx_state;
		/** SVM initialization state */
		enum {SVMOFF = 0, SVMON} svm_state;
	};

	/**
	 * Lock protecting CPU state changes done for control tasks.
	 *
	 * The lock protects the following fields (unless CPU is suspended):
	 * @li per_cpu::suspend_cpu
	 * @li per_cpu::cpu_suspended (except for spinning on it to become
	 *                             true)
	 * @li per_cpu::wait_for_sipi
	 * @li per_cpu::init_signaled
	 * @li per_cpu::sipi_vector
	 * @li per_cpu::flush_vcpu_caches
	 */
	spinlock_t control_lock;

	/** Set to true for instructing the CPU to suspend. */
	volatile bool suspend_cpu;
	/** True if CPU is waiting for SIPI. */
	volatile bool wait_for_sipi;
	/** True if CPU is suspended. */
	volatile bool cpu_suspended;
	/** Set to true for pending an INIT signal. */
	bool init_signaled;
	/** Pending SIPI vector; -1 if none is pending. */
	int sipi_vector;
	/** Set to true for a pending TLB flush for the paging layer that does
	 *  host physical <-> guest physical memory mappings */
	bool flush_vcpu_caches;
	/** Set to true for instructing the CPU to disable hypervisor mode. */
	bool shutdown_cpu;
	/** State of the shutdown process. Possible values:
	 * @li SHUTDOWN_NONE: no shutdown in progress
	 * @li SHUTDOWN_STARTED: shutdown in progress
	 * @li negative error code: shutdown failed
	 */
	int shutdown_state;
	/** True if CPU violated a cell boundary or cause some other failure in
	 * guest mode. */
	bool failed;

	/** Number of iterations to clear pending APIC IRQs. */
	unsigned int num_clear_apic_irqs;

	union {
		struct {
			/** VMXON region, required by VMX. */
			struct vmcs vmxon_region
				__attribute__((aligned(PAGE_SIZE)));
			/** VMCS of this CPU, required by VMX. */
			struct vmcs vmcs
				__attribute__((aligned(PAGE_SIZE)));
		};
		struct {
			/* TODO: Add VMCB block here */
			/** SVM Host save area; opaque to us. */
			u8 host_state[PAGE_SIZE]
				__attribute__((aligned(PAGE_SIZE)));
		};
	};
} __attribute__((aligned(PAGE_SIZE)));

/**
 * Define CPU-local accessor for a per-CPU field.
 * @param field		Field name.
 *
 * The accessor will have the form of a function, returning the correspondingly
 * typed field value: @c this_field().
 */
#define DEFINE_PER_CPU_ACCESSOR(field)					    \
static inline typeof(((struct per_cpu *)0)->field) this_##field(void)	    \
{									    \
	typeof(((struct per_cpu *)0)->field) tmp;			    \
									    \
	asm volatile(							    \
		"mov %%gs:%1,%0\n\t"					    \
		: "=&q" (tmp)						    \
		: "m" (*(u8 *)__builtin_offsetof(struct per_cpu, field)));  \
	return tmp;							    \
}

/**
 * Retrieve the data structure of the current CPU.
 *
 * @return Pointer to per-CPU data structure.
 */
static inline struct per_cpu *this_cpu_data(void);
DEFINE_PER_CPU_ACCESSOR(cpu_data)

/**
 * Retrieve the ID of the current CPU.
 *
 * @return CPU ID.
 */
static inline unsigned int this_cpu_id(void);
DEFINE_PER_CPU_ACCESSOR(cpu_id)

/**
 * Retrieve the cell owning the current CPU.
 *
 * @return Pointer to cell.
 */
static inline struct cell *this_cell(void);
DEFINE_PER_CPU_ACCESSOR(cell)

/**
 * Retrieve the data structure of the specified CPU.
 * @param cpu	ID of the target CPU.
 *
 * @return Pointer to per-CPU data structure.
 */
static inline struct per_cpu *per_cpu(unsigned int cpu)
{
	struct per_cpu *cpu_data;

	asm volatile(
		"lea __page_pool(%%rip),%0\n\t"
		"add %1,%0\n\t"
		: "=&qm" (cpu_data)
		: "qm" ((unsigned long)cpu << PERCPU_SIZE_SHIFT));
	return cpu_data;
}

/** @} **/

/* Validate defines */
#define CHECK_ASSUMPTION(assume)	((void)sizeof(char[1 - 2*!(assume)]))

static inline void __check_assumptions(void)
{
	struct per_cpu cpu_data;

	CHECK_ASSUMPTION(sizeof(struct per_cpu) == (1 << PERCPU_SIZE_SHIFT));
	CHECK_ASSUMPTION(sizeof(cpu_data.stack) == PERCPU_STACK_END);
	CHECK_ASSUMPTION(__builtin_offsetof(struct per_cpu, linux_sp) ==
			 PERCPU_LINUX_SP);
}
#endif /* !__ASSEMBLY__ */

#endif /* !_JAILHOUSE_ASM_PERCPU_H */
