/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Valentine Sinitsyn, 2015
 *
 * Authors:
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef _JAILHOUSE_ASM_AMD_IOMMU_PAGING_H
#define _JAILHOUSE_ASM_AMD_IOMMU_PAGING_H

#include <jailhouse/paging.h>

#define AMD_IOMMU_PTE_P			(1ULL <<  0)
#define AMD_IOMMU_PTE_IR		(1ULL << 61)
#define AMD_IOMMU_PTE_IW		(1ULL << 62)

#define AMD_IOMMU_PAGE_DEFAULT_FLAGS	(AMD_IOMMU_PTE_IW | AMD_IOMMU_PTE_IR | \
					 AMD_IOMMU_PTE_P)
#define AMD_IOMMU_MAX_PAGE_TABLE_LEVELS	6

extern const struct paging amd_iommu_paging[];

#endif
