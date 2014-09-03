/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Minimal configuration for PCI demo inmate:
 * 1 CPU, 1 MB RAM, 1 serial port, 1 Intel HDA PCI device
 *
 * Copyright (c) Siemens AG, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/types.h>
#include <jailhouse/cell-config.h>

#define ARRAY_SIZE(a) sizeof(a) / sizeof(a[0])

struct {
	struct jailhouse_cell_desc cell;
	__u64 cpus[1];
	struct jailhouse_memory mem_regions[3];
	__u8 pio_bitmap[0x2000];
	struct jailhouse_pci_device pci_devices[1];
	struct jailhouse_pci_capability pci_caps[1];
} __attribute__((packed)) config = {
	.cell = {
		.name = "pci-demo",
		.flags = JAILHOUSE_CELL_PASSIVE_COMMREG,

		.cpu_set_size = sizeof(config.cpus),
		.num_memory_regions = ARRAY_SIZE(config.mem_regions),
		.num_irqchips = 0,
		.pio_bitmap_size = ARRAY_SIZE(config.pio_bitmap),
		.num_pci_devices = ARRAY_SIZE(config.pci_devices),
		.num_pci_caps = ARRAY_SIZE(config.pci_caps),
	},

	.cpus = {
		0x4,
	},

	.mem_regions = {
		/* RAM */ {
			.phys_start = 0x3be00000,
			.virt_start = 0,
			.size = 0x00100000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_EXECUTE | JAILHOUSE_MEM_LOADABLE,
		},
		/* communication region */ {
			.virt_start = 0x00100000,
			.size = 0x00001000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_COMM_REGION,
		},
		/* HDA BAR0 */ {
			.phys_start = 0xfebf0000,
			.virt_start = 0xfebf0000,
			.size = 0x00004000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE,
		},
	},

	.pio_bitmap = {
		[     0/8 ...  0x2f7/8] = -1,
		[ 0x2f8/8 ...  0x2ff/8] = 0, /* serial2 */
		[ 0x300/8 ... 0xdfff/8] = -1,
#ifdef CONFIG_UART_OXPCIE952
		[0xe000/8 ... 0xe007/8] = 0, /* OXPCIe952 serial2 */
#else
		[0xe000/8 ... 0xe007/8] = -1,
#endif
		[0xe008/8 ... 0xffff/8] = -1,
	},

	.pci_devices = {
		{ /* Intel HDA @00:1b.0 */
			.type = JAILHOUSE_PCI_TYPE_DEVICE,
			.domain = 0x0000,
			.bdf = 0x00d8,
			.caps_start = 0,
			.num_caps = 1,
		},
	},

	.pci_caps = {
		{ /* Intel HDA @00:1b.0 */
			.id = 0x5,
			.start = 0x60,
			.len = 14,
			.flags = JAILHOUSE_PCICAPS_WRITE,
		},
	},
};
