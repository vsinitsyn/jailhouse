/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013
 *
 * Authors:
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef _JAILHOUSE_ASM_SVM_H
#define _JAILHOUSE_ASM_SVM_H

#include <asm/percpu.h>

#include <jailhouse/cell-config.h>

#define EFER_SVME	(1UL << 12)
#define VM_CR_SVMDIS	(1UL << 4)

#define MSR_VM_CR	0xc0010114
#define MSR_VM_HSAVE_PA	0xc0010117

extern bool decode_assists;

int svm_init(void);

int svm_cell_init(struct cell *cell);
void svm_root_cell_shrink(struct jailhouse_cell_desc *config);
int svm_map_memory_region(struct cell *cell,
			  const struct jailhouse_memory *mem);
int svm_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem);
void svm_cell_exit(struct cell *cell);

int svm_cpu_init(struct per_cpu *cpu_data);
void svm_cpu_exit(struct per_cpu *cpu_data);

void __attribute__((noreturn)) svm_cpu_activate_vmm(struct per_cpu *cpu_data);
void svm_handle_exit(struct registers *guest_regs, struct per_cpu *cpu_data);
void svm_entry_failure(struct per_cpu *cpu_data);

void svm_cpu_park(struct per_cpu *cpu_data);

void svm_tlb_flush(void);

#endif
