/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Minimal configuration for demo inmates, 1 CPU, 1 MB RAM, 1 serial port
 *
 * Copyright (c) Siemens AG, 2013
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
	struct jailhouse_memory mem_regions[2];
	__u8 pio_bitmap[0x2000];
} __attribute__((packed)) config = {
	.cell = {
		.name = "apic-demo",

		.cpu_set_size = sizeof(config.cpus),
		.num_memory_regions = ARRAY_SIZE(config.mem_regions),
		.num_irqchips = 0,
		.pio_bitmap_size = ARRAY_SIZE(config.pio_bitmap),
		.num_pci_devices = 0,
	},

	.cpus = {
		0x8,
	},

	.mem_regions = {
		/* RAM */ {
			.phys_start = 0x3bf00000,
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
	},

	.pio_bitmap = {
		[     0/8 ...  0x3f7/8] = -1,
		[ 0x3f8/8 ...  0x3ff/8] = 0, /* serial1 */
		[ 0x400/8 ... 0xe00f/8] = -1,
#ifdef CONFIG_UART_OXPCIE952
		[0xe010/8 ... 0xe017/8] = 0, /* OXPCIe952 serial1 */
#else
		[0xe010/8 ... 0xe017/8] = -1,
#endif
		[0xe018/8 ... 0xffff/8] = -1,
	},
};
