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

#ifndef _JAILHOUSE_ASM_AMD_IOMMU_H
#define _JAILHOUSE_ASM_AMD_IOMMU_H

#include <asm/cell.h>

#include <jailhouse/cell-config.h>

int amd_iommu_init(void);

int amd_iommu_cell_init(struct cell *cell);
void amd_iommu_root_cell_shrink(struct jailhouse_cell_desc *config);
int amd_iommu_map_memory_region(struct cell *cell,
			  const struct jailhouse_memory *mem);
int amd_iommu_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem);
void amd_iommu_cell_exit(struct cell *cell);

void amd_iommu_shutdown(void);

void amd_iommu_check_pending_faults(struct per_cpu *cpu_data);

#endif