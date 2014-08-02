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

#ifndef _JAILHOUSE_ASM_IOMMU_H
#define _JAILHOUSE_ASM_IOMMU_H

#include <asm/cell.h>

#include <jailhouse/cell-config.h>

int iommu_init(void);

int iommu_cell_init(struct cell *cell);
int iommu_map_memory_region(struct cell *cell,
			  const struct jailhouse_memory *mem);
int iommu_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem);
void iommu_cell_exit(struct cell *cell);

void iommu_config_commit(struct cell *cell_added_removed);

void iommu_shutdown(void);

void iommu_check_pending_faults(struct per_cpu *cpu_data);

#endif
