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

#ifndef _JAILHOUSE_ASM_CELL_H
#define _JAILHOUSE_ASM_CELL_H

#include <jailhouse/paging.h>

#include <jailhouse/cell-config.h>
#include <jailhouse/hypercall.h>

struct pci_device;

/** Cell-related states. */
/* TODO: factor out arch-independent bits, define struct arch_cell */
struct cell {
	union {
		struct {
			/** PIO access bitmap. */
			u8 *io_bitmap;
			/** Paging structures used for cell CPUs. */
			struct paging_structures ept_structs;
		} vmx; /**< Intel VMX-specific fields. */
	};

	union {
		struct {
			/** Paging structures used for DMA requests. */
			struct paging_structures pg_structs;
			/** True if interrupt remapping support is emulated for this
			 * cell. */
			bool ir_emulation;
		} vtd; /**< Intel VT-d specific fields. */
	};

	/** ID of the cell. */
	unsigned int id;
	/** Number of pages used for storing cell-specific states and
	 * configuration data. */
	unsigned int data_pages;
	/** Pointer to static cell description. */
	struct jailhouse_cell_desc *config;

	/** Pointer to cell's CPU set. */
	struct cpu_set *cpu_set;
	/** Stores the cell's CPU set if small enough. */
	struct cpu_set small_cpu_set;

	/** True while the cell can be loaded by the root cell. */
	bool loadable;

	/** Pointer to next cell in the system. */
	struct cell *next;

	/** List of PCI devices assigned to this cell. */
	struct pci_device *pci_devices;
	/** List of PCI devices assigned to this cell that support MSI-X. */
	struct pci_device *msix_device_list;
	/** Shadow value of PCI config space address port register. */
	u32 pci_addr_port_val;

	/** Shadow value of IOAPIC index register. */
	u32 ioapic_index_reg_val;
	/** IOAPIC ID as used for interrupt remapping. */
	u16 ioapic_id;
	/** IOMMU unit responsible for the IOAPIC. */
	u8 ioapic_iommu;
	/** Bitmap of IOAPIC pins assigned to this cell. */
	u64 ioapic_pin_bitmap;

	union {
		/** Communication region. */
		struct jailhouse_comm_region comm_region;
		/** Padding to full page size. */
		u8 padding[PAGE_SIZE];
	} __attribute__((aligned(PAGE_SIZE))) comm_page;
	/**< Page containing the communication region (shared with cell). */
};

extern struct cell root_cell;

#endif /* !_JAILHOUSE_ASM_CELL_H */
