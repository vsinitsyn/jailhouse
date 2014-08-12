/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Test configuration for QEMU VM, 1 GB RAM, 64 MB hypervisor (-8 K ACPI)
 * Command line:
 * qemu-system-x86_64 /path/to/image -m 1G -enable-kvm -smp 4 \
 *  -virtfs local,path=/local/path,security_model=passthrough,mount_tag=host \
 *  -cpu kvm64,-kvm_pv_eoi,-kvm_steal_time,-kvm_asyncpf,-kvmclock,+vmx,+x2apic
 *
 * For AMD-based setups:
 * qemu-system-x86_64 /path/to/image -m 1G -enable-kvm -smp 4 \
 *  -virtfs local,path=/local/path,security_model=passthrough,mount_tag=host \
 *  -cpu host,-kvm_pv_eoi,-kvm_steal_time,-kvm_asyncpf,-kvmclock,+svm,+x2apic
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

#include <linux/types.h>
#include <jailhouse/cell-config.h>

#define ARRAY_SIZE(a) sizeof(a) / sizeof(a[0])

struct {
	struct jailhouse_system header;
	__u64 cpus[1];
	struct jailhouse_memory mem_regions[5];
	struct jailhouse_irqchip irqchips[1];
	__u8 pio_bitmap[0x2000];
	struct jailhouse_pci_device pci_devices[7];
	struct jailhouse_pci_capability pci_caps[1];
} __attribute__((packed)) config = {
	.header = {
		.hypervisor_memory = {
			.phys_start = 0x3c000000,
			.size = 0x4000000 - 0x2000,
		},
		.platform_info.x86 = {
			/* .mmconfig_base = ?, */
			/* .mmconfig_end_bus = ?, */
			.pm_timer_address = 0xb008,
		},
		.root_cell = {
			.name = "QEMU Linux VM 2.0",

			.cpu_set_size = sizeof(config.cpus),
			.num_memory_regions = ARRAY_SIZE(config.mem_regions),
			.num_irqchips = ARRAY_SIZE(config.irqchips),
			.pio_bitmap_size = ARRAY_SIZE(config.pio_bitmap),
			.num_pci_devices = ARRAY_SIZE(config.pci_devices),
			.num_pci_caps = ARRAY_SIZE(config.pci_caps),
		},
	},

	.cpus = {
		0xf,
	},

	.mem_regions = {
		/* RAM */ {
			.phys_start = 0x0,
			.virt_start = 0x0,
			.size = 0x3c000000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE |
				JAILHOUSE_MEM_EXECUTE | JAILHOUSE_MEM_DMA,
		},
		/* ACPI */ {
			.phys_start = 0x3fffe000,
			.virt_start = 0x3fffe000,
			.size = 0x2000,
			.flags = JAILHOUSE_MEM_READ,
		},
		/* PCI */ {
			.phys_start = 0x40000000,
			.virt_start = 0x40000000,
			.size = 0xbec00000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE,
		},
		/* not safe until we catch MSIs via interrupt remapping */
		/* HPET */ {
			.phys_start = 0xfed00000,
			.virt_start = 0xfed00000,
			.size = 0x1000,
			.flags = JAILHOUSE_MEM_READ | JAILHOUSE_MEM_WRITE,
		},
	},

	.irqchips = {
		/* IOAPIC */ {
			.address = 0xfec00000,
			.pin_bitmap = 0xffffff,
		},
	},

	.pio_bitmap = {
		[     0/8 ...   0x1f/8] = -1,
		[  0x20/8 ...   0x27/8] = 0xfc, /* HACK: PIC */
		[  0x28/8 ...   0x3f/8] = -1,
		[  0x40/8 ...   0x47/8] = 0xf0, /* PIT */
		[  0x48/8 ...   0x5f/8] = -1,
		[  0x60/8 ...   0x67/8] = 0xec, /* HACK: 8042, PC speaker - and more */
		[  0x68/8 ...   0x6f/8] = -1,
		[  0x70/8 ...   0x77/8] = 0xfc, /* rtc */
		[  0x78/8 ...   0x7f/8] = -1,
		[  0x80/8 ...   0x87/8] = 0xfe, /* port 80 (delays) */
		[  0x88/8 ...   0x9f/8] = -1,
		[  0xa0/8 ...   0xa7/8] = 0xfc, /* HACK: PIC2 */
		[  0xa8/8 ...  0x1f6/8] = -1,
		[ 0x170/8 ...  0x177/8] = 0, /* ide */
		[ 0x178/8 ...  0x1ef/8] = -1,
		[ 0x1f0/8 ...  0x1f7/8] = 0, /* ide */
		[ 0x1f8/8 ...  0x2f7/8] = -1,
		[ 0x2f8/8 ...  0x2ff/8] = 0, /* serial2 */
		[ 0x300/8 ...  0x36f/8] = -1,
		[ 0x370/8 ...  0x377/8] = 0xbf, /* ide */
		[ 0x378/8 ...  0x3af/8] = -1,
		[ 0x3b0/8 ...  0x3df/8] = 0, /* VGA */
		[ 0x3e0/8 ...  0x3ef/8] = -1,
		[ 0x3f0/8 ...  0x3f7/8] = 0xbf, /* ide */
		[ 0x3f8/8 ... 0x5657/8] = -1,
		[0x5658/8 ... 0x565f/8] = 0xf0, /* vmport */
		[0x5660/8 ... 0xbfff/8] = -1,
		[0xc000/8 ... 0xc0ff/8] = 0, /* PCI devices */
		[0xc100/8 ... 0xffff/8] = -1,
	},

	.pci_devices = {
		{
			.type = JAILHOUSE_PCI_TYPE_DEVICE,
			.domain = 0x0000,
			.bdf = 0x0000
		},
		{ /* 440fx: ISA bridge */
			.type = JAILHOUSE_PCI_TYPE_DEVICE,
			.domain = 0x0000,
			.bdf = 0x0008
		},
		{ /* 440fx: IDE */
			.type = JAILHOUSE_PCI_TYPE_DEVICE,
			.domain = 0x0000,
			.bdf = 0x0009
		},
		{ /* 440fx: SMBus */
			.type = JAILHOUSE_PCI_TYPE_DEVICE,
			.domain = 0x0000,
			.bdf = 0x000b
		},
		{ /* 440fx: VGA */
			.type = JAILHOUSE_PCI_TYPE_DEVICE,
			.domain = 0x0000,
			.bdf = 0x0010
		},
		{ /* 440fx: e1000 */
			.type = JAILHOUSE_PCI_TYPE_DEVICE,
			.domain = 0x0000,
			.bdf = 0x0018
		},
		{ /* 440fx: virtio-9p-pci */
			.type = JAILHOUSE_PCI_TYPE_DEVICE,
			.domain = 0x0000,
			.bdf = 0x0020,
			.caps_start = 0,
			.num_caps = 1
		}
	},

	.pci_caps = {
		{ /* virtio-9p-pci */
			.id = 0x11,
			.start = 0x40,
			.len = 12,
			.flags = JAILHOUSE_PCICAPS_WRITE,
		}
	}
};
