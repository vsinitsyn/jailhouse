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

#ifndef _JAILHOUSE_ASM_VMCS_H
#define _JAILHOUSE_ASM_VMCS_H

struct vmcs {
	u32 revision_id:31;
	u32 shadow_indicator:1;
	u32 abort_indicator;
	u64 data[(PAGE_SIZE - 4 - 4) / 8];
} __attribute__((packed));

#endif
