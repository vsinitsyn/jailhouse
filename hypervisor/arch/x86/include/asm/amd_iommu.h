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

#ifndef _JAILHOUSE_ASM_AMD_IOMMU_H
#define _JAILHOUSE_ASM_AMD_IOMMU_H

#include <jailhouse/types.h>

#define AMD_IOMMU_PTE_P			(1ULL <<  0)
#define AMD_IOMMU_PTE_IR		(1ULL << 61)
#define AMD_IOMMU_PTE_IW		(1ULL << 62)

#define AMD_IOMMU_PAGE_DEFAULT_FLAGS	(AMD_IOMMU_PTE_IW | AMD_IOMMU_PTE_IR | \
					 AMD_IOMMU_PTE_P)
#define AMD_IOMMU_MAX_PAGE_TABLE_LEVELS	6

#define CAPS_IOMMU_BASE_HI		0x08
#define CAPS_IOMMU_BASE_LOW		0x04
#define IOMMU_CAP_ENABLE		(1 << 0)
#define IOMMU_CAP_EFR			(1 << 27)

/*
 * TODO: Check this. Also, make naming more consistent,
 * i.e. MMIO_CONTROL_* instead of CONTROL etc.
 */
#define CONTROL_SMIF_EN			(1 << 22)
#define CONTROL_SMIFLOG_EN		(1 << 24)
#define CONTROL_SEG_SUP_SHIFT		34
#define CONTROL_SEG_SUP_MASK		0x7

#define CONTROL_IOMMU_EN		(1 << 0)
#define CONTROL_EVT_LOG_EN		(1 << 2)
#define CONTROL_EVT_INT_EN		(1 << 3)
#define CONTROL_COMM_WAIT_INT_EN	(1 << 4)
#define CONTROL_CMD_BUF_EN		(1 << 12)

#define FEATURE_SMI_FSUP_MASK		0x30000
#define FEATURE_SMI_FSUP_SHIFT		16

#define FEATURE_SMI_FRC_MASK		0x1c0000
#define FEATURE_SMI_FRC_SHIFT		18

#define FEATURE_SEG_SUP_MASK		0xc000000000
#define FEATURE_SEG_SUP_SHIFT   	38

#define FEATURE_HATS_MASK		0xc00
#define FEATURE_HATS_SHIFT		10

#define FEATURE_HE_SUP_MASK		0x80
#define FEATURE_HE_SUP_SHIFT		7

#define MMIO_DEV_TABLE_BASE		0x0000

#define MMIO_CMD_BUF_OFFSET		0x0008
#define MMIO_CONTROL_OFFSET		0x0018
#define MMIO_EXT_FEATURES		0x0030
#define MMIO_SMI_FREG0_OFFSET		0x0060
#define MMIO_DEV_TABLE_SEG_BASE		0x0100
#define MMIO_CMD_HEAD_OFFSET		0x2000
#define MMIO_CMD_TAIL_OFFSET		0x2008

#define MMIO_EVT_LOG_OFFSET		0x0010
#define MMIO_EVT_HEAD_OFFSET		0x2010
#define MMIO_EVT_TAIL_OFFSET		0x2018

#define MMIO_STATUS_OFFSET		0x2020
# define MMIO_STATUS_EVT_OVERFLOW_MASK	(1 << 0) 
# define MMIO_STATUS_EVT_INT_MASK 	(1 << 1)
# define MMIO_STATUS_EVT_RUN_MASK 	(1 << 3)

#define MMIO_HEV_UPPER_OFFSET		0x0050
#define MMIO_HEV_LOWER_OFFSET		0x0050
#define MMIO_HEV_OFFSET			0x0050

#define MMIO_HEV_VALID			(1 << 1)
#define MMIO_HEV_OVERFLOW		(1 << 2)

#define SMI_FREG_LOCKED			(1 << 17)
#define SMI_FREG_VALID			(1 << 16)

#define DTE_VALID			(1 << 0)
#define DTE_TRANSLATION_VALID		(1 << 1)

#define DTE_MODE_SHIFT			0x09
#define DTE_MODE_MASK			0x07ULL

#define DTE_SUPPRESS_EVENTS		(1ULL << 33)
#define DTE_CACHE_DISABLE		(1ULL << 37)

#define DEV_TABLE_SEG_MAX		8
#define DEV_TABLE_SIZE			0x200000

#define BUF_LEN_EXPONENT_SHIFT		56

#define CMD_COMPL_WAIT			0x01
# define CMD_COMPL_WAIT_STORE_MASK	(1 << 0)
# define CMD_COMPL_WAIT_INT_MASK	(1 << 1)

#define CMD_INV_DEVTAB_ENTRY		0x02

#define CMD_INV_IOMMU_PAGES		0x03
# define CMD_INV_IOMMU_PAGES_SIZE_MASK	(1 << 0)
# define CMD_INV_IOMMU_PAGES_PDE_MASK	(1 << 1)

#define CMD_SET_TYPE(cmd, type)	((cmd)->data[1] |= ((type & 0x7) << 28))

#define EVENT_TYPE_ILL_CMD_ERR		0x05
#define EVENT_TYPE_CMD_HW_ERR		0x06
#define EVENT_TYPE_EVT_CNT_ZERO		0x0a

#define MSI_ADDRESS_SHIFT		20

struct dev_table_entry {
	u64 data[4];
} __attribute__((packed));

struct cmd_buf_entry {
	u32 data[4];
} __attribute__((packed));

struct evt_log_entry {
	u32 data[4];
} __attribute__((packed));

#endif
