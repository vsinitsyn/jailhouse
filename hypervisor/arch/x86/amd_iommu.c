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

#include <asm/iommu.h>

int iommu_init(void)
{
	/* TODO: Implement */
	return 0;
}

int iommu_cell_init(struct cell *cell)
{
	/* TODO: Implement */
	return 0;
}

int iommu_map_memory_region(struct cell *cell,
				const struct jailhouse_memory *mem)
{
	/* TODO: Implement */
	return 0;
}
int iommu_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	/* TODO: Implement */
	return 0;
}

int iommu_add_pci_device(struct cell *cell, struct pci_device *device)
{
	/* TODO: Implement */
	return 0;
}

void iommu_remove_pci_device(struct pci_device *device)
{
	/* TODO: Implement */
}

void iommu_cell_exit(struct cell *cell)
{
	/* TODO: Implement */
}

void iommu_config_commit(struct cell *cell_added_removed)
{
	/* TODO: Implement */
}

void iommu_shutdown(void)
{
	/* TODO: Implement */
}

void iommu_check_pending_faults(struct per_cpu *cpu_data)
{
	/* TODO: Implement */
}
