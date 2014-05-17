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

#include <jailhouse/pci.h>

#include <asm/cell.h>

#include <jailhouse/cell-config.h>

int amd_iommu_init(void);

int amd_iommu_cell_init(struct cell *cell);
int amd_iommu_map_memory_region(struct cell *cell,
			  const struct jailhouse_memory *mem);
int amd_iommu_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem);
int amd_iommu_add_pci_device(struct cell *cell, struct pci_device *device);
void amd_iommu_remove_pci_device(struct pci_device *device);

struct apic_irq_message
amd_iommu_get_remapped_root_int(unsigned int iommu, u16 device_id,
		unsigned int vector, unsigned int remap_index);
int amd_iommu_map_interrupt(struct cell *cell, u16 device_id, unsigned int vector,
		struct apic_irq_message irq_msg);

void amd_iommu_cell_exit(struct cell *cell);

void amd_iommu_config_commit(struct cell *cell_added_removed);

void amd_iommu_shutdown(void);

void amd_iommu_check_pending_faults(struct per_cpu *cpu_data);

int amd_iommu_mmio_access_handler(bool is_write, u64 addr, u32 *value);

bool amd_iommu_cell_ir_emulation(struct cell *cell);

#endif
