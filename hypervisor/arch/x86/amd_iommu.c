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

#include <asm/amd_iommu.h>


int amd_iommu_init(void)
{
	/* TODO: Implement */
	return 0;
}

int amd_iommu_cell_init(struct cell *cell)
{
	/* TODO: Implement */
	return 0;
}

int amd_iommu_map_memory_region(struct cell *cell,
				const struct jailhouse_memory *mem)
{
	/* TODO: Implement */
	return 0;
}
int amd_iommu_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	/* TODO: Implement */
	return 0;
}

void amd_iommu_cell_exit(struct cell *cell)
{
	/* TODO: Implement */
}

void amd_iommu_config_commit(struct cell *cell_added_removed)
{
	/* TODO: Implement */
}

void amd_iommu_shutdown(void)
{
	/* TODO: Implement */
}

void amd_iommu_check_pending_faults(struct per_cpu *cpu_data)
{
	/* TODO: Implement */
}
