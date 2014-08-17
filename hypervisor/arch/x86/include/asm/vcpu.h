/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Valentine Sinitsyn, 2014
 *
 * Authors:
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef _JAILHOUSE_ASM_VCPU_H
#define _JAILHOUSE_ASM_VCPU_H

#include <asm/percpu.h>
#include <asm/types.h>

#include <jailhouse/cell-config.h>

struct vcpu_io_bitmap {
	u8 *data;
	u32 size;
};

int vcpu_vendor_init(void);

int vcpu_cell_init(struct cell *cell);
int vcpu_vendor_cell_init(struct cell *cell);

int vcpu_map_memory_region(struct cell *cell,
			  const struct jailhouse_memory *mem);
int vcpu_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem);

void vcpu_cell_exit(struct cell *cell);
void vcpu_vendor_cell_exit(struct cell *cell);

int vcpu_init(struct per_cpu *cpu_data);
void vcpu_exit(struct per_cpu *cpu_data);

void __attribute__((noreturn)) vcpu_activate_vmm(struct per_cpu *cpu_data);
void vcpu_handle_exit(struct registers *guest_regs, struct per_cpu *cpu_data);

void vcpu_park(struct per_cpu *cpu_data);

void vcpu_nmi_handler(struct per_cpu *cpu_data);

void vcpu_tlb_flush(struct per_cpu *cpu_data);

void vcpu_entry_failure(struct per_cpu *cpu_data);

/*
 * vcpu_map_inst() and vcpu_get_inst_bytes() contract:
 *
 * On input, *size gives the number of bytes to get.
 * On output, *size is the number of bytes available.
 *
 * If the function fails (returns NULL), *size is undefined.
 */

const u8 *vcpu_map_inst(struct per_cpu *cpu_data,
			const struct guest_paging_structures *pg_structs,
			unsigned long pc, unsigned int *size);

const u8 *vcpu_get_inst_bytes(struct per_cpu *cpu_data,
			      const struct guest_paging_structures *pg_structs,
			      unsigned long pc, unsigned int *size);

void vcpu_vendor_get_cell_io_bitmap(struct cell *cell,
		                    struct vcpu_io_bitmap *out);

inline void vcpu_skip_emulated_instruction(struct per_cpu *cpu_data,
		                           unsigned int inst_len);

#endif
