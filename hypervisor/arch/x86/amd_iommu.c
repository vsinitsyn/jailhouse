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

#include <jailhouse/printk.h>

#include <asm/apic.h>
#include <asm/iommu.h>

int iommu_init(void)
{
	printk("WARNING: AMD IOMMU support is not implemented yet\n");
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

struct apic_irq_message iommu_get_remapped_root_int(
		unsigned int iommu, u16 device_id,
		unsigned int vector, unsigned int remap_index)
{
	struct apic_irq_message dummy;

	/* TODO: Implement */
	return dummy;
}

int iommu_map_interrupt(struct cell *cell, u16 device_id, unsigned int vector,
		struct apic_irq_message irq_msg)
{
	/* TODO: Implement */
	return -ENOSYS;
}

void iommu_shutdown(void)
{
	/* TODO: Implement */
}

void iommu_check_pending_faults(struct per_cpu *cpu_data)
{
	/* TODO: Implement */
}

int iommu_mmio_access_handler(bool is_write, u64 addr, u32 *value)
{
	/* TODO: Implement */
	return 0;
}

bool iommu_cell_ir_emulation(struct cell *cell)
{
	/* TODO: Implement */
	return false;
}
