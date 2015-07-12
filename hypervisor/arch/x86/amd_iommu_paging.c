/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2014
 * Copyright (c) Valentine Sinitsyn, 2015
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/paging.h>
#include <jailhouse/string.h>

#include <asm/amd_iommu.h>
#include <asm/amd_iommu_paging.h>

/* TODO: Using DTE_* here is not clean, refactor it */
#define AMD_IOMMU_PTE_MODE_MASK (DTE_MODE_MASK << DTE_MODE_SHIFT)
#define PM_LEVEL_ENC(x)         (((x) << DTE_MODE_SHIFT) & AMD_IOMMU_PTE_MODE_MASK)

static bool amd_iommu_entry_valid(pt_entry_t pte, unsigned long flags)
{
	return (*pte & flags) == flags;
}

static unsigned long amd_iommu_get_flags(pt_entry_t pte)
{
	return *pte & 0x7800000000000001;
}

/* TODO: Return my macros after debugging */
static void amd_iommu_set_next_pt_l6(pt_entry_t pte, unsigned long next_pt)
{
	*pte = (next_pt & 0x000ffffffffff000UL) | PM_LEVEL_ENC(5) |
		AMD_IOMMU_PAGE_DEFAULT_FLAGS;
}

static void amd_iommu_set_next_pt_l5(pt_entry_t pte, unsigned long next_pt)
{
	*pte = (next_pt & 0x000ffffffffff000UL) | PM_LEVEL_ENC(4) |
		AMD_IOMMU_PAGE_DEFAULT_FLAGS;
}


static void amd_iommu_set_next_pt_l4(pt_entry_t pte, unsigned long next_pt)
{
	*pte = (next_pt & 0x000ffffffffff000UL) | PM_LEVEL_ENC(3) |
		AMD_IOMMU_PAGE_DEFAULT_FLAGS;
}

static void amd_iommu_set_next_pt_l3(pt_entry_t pte, unsigned long next_pt)
{
	*pte = (next_pt & 0x000ffffffffff000UL) | PM_LEVEL_ENC(2) |
		AMD_IOMMU_PAGE_DEFAULT_FLAGS;
}

static void amd_iommu_set_next_pt_l2(pt_entry_t pte, unsigned long next_pt)
{
	*pte = (next_pt & 0x000ffffffffff000UL) | PM_LEVEL_ENC(1) |
		AMD_IOMMU_PAGE_DEFAULT_FLAGS;
}

static void amd_iommu_clear_entry(pt_entry_t pte)
{
	*pte = 0;
}

static bool amd_iommu_page_table_empty(page_table_t page_table)
{
	pt_entry_t pte;
	int n;

	for (n = 0, pte = page_table; n < PAGE_SIZE / sizeof(u64); n++, pte++)
		if (amd_iommu_entry_valid(pte, AMD_IOMMU_PTE_P))
			return false;
	return true;
}

static pt_entry_t amd_iommu_get_entry_l6(page_table_t page_table,
				      unsigned long virt)
{
	return &page_table[(virt >> 57) & 0x7f];
}

static pt_entry_t amd_iommu_get_entry_l5(page_table_t page_table,
				      unsigned long virt)
{
	return &page_table[(virt >> 48) & 0x1ff];
}

static pt_entry_t amd_iommu_get_entry_l4(page_table_t page_table,
				      unsigned long virt)
{
	return &page_table[(virt >> 39) & 0x1ff];
}

static pt_entry_t amd_iommu_get_entry_l3(page_table_t page_table,
				      unsigned long virt)
{
	return &page_table[(virt >> 30) & 0x1ff];
}

static pt_entry_t amd_iommu_get_entry_l2(page_table_t page_table,
				      unsigned long virt)
{
	return &page_table[(virt >> 21) & 0x1ff];
}

static pt_entry_t amd_iommu_get_entry_l1(page_table_t page_table,
				      unsigned long virt)
{
	return &page_table[(virt >> 12) & 0x1ff];
}

/* amd_iommu_set_terminal_lX(): set Next Level to 0 */
static void amd_iommu_set_terminal_l5(pt_entry_t pte, unsigned long phys,
				   unsigned long flags)
{
	*pte = (phys & 0x000f000000000000UL) | flags;
}

static void amd_iommu_set_terminal_l4(pt_entry_t pte, unsigned long phys,
				   unsigned long flags)
{
	*pte = (phys & 0x000fff8000000000UL) | flags;
}


static void amd_iommu_set_terminal_l3(pt_entry_t pte, unsigned long phys,
				   unsigned long flags)
{
	*pte = (phys & 0x000fffffc0000000UL) | flags;
}

static void amd_iommu_set_terminal_l2(pt_entry_t pte, unsigned long phys,
				   unsigned long flags)
{
	*pte = (phys & 0x000fffffffe00000UL) | flags;
}

static void amd_iommu_set_terminal_l1(pt_entry_t pte, unsigned long phys,
				   unsigned long flags)
{
	*pte = (phys & 0x000ffffffffff000UL) | flags;
}

/* TODO: amd_iommu_get_phys(): support Next Level = 7 as well */
static unsigned long amd_iommu_get_phys_l5(pt_entry_t pte, unsigned long virt)
{
	if ((*pte & AMD_IOMMU_PTE_MODE_MASK) != 0)
		return INVALID_PHYS_ADDR;
	return (*pte & 0x000f000000000000UL) |
	       (virt & 0x0000ffffffffffffUL);
}

static unsigned long amd_iommu_get_phys_l4(pt_entry_t pte, unsigned long virt)
{
	if (!(*pte & AMD_IOMMU_PTE_MODE_MASK))
		return INVALID_PHYS_ADDR;
	return (*pte & 0x000fff8000000000UL) |
	       (virt & 0x00000007ffffffffUL);
}


static unsigned long amd_iommu_get_phys_l3(pt_entry_t pte, unsigned long virt)
{
	if ((*pte & AMD_IOMMU_PTE_MODE_MASK) != 0)
		return INVALID_PHYS_ADDR;
	return (*pte & 0x000fffffc0000000UL) |
	       (virt & 0x000000003fffffffUL);
}

static unsigned long amd_iommu_get_phys_l2(pt_entry_t pte, unsigned long virt)
{
	if ((*pte & AMD_IOMMU_PTE_MODE_MASK) != 0)
		return INVALID_PHYS_ADDR;
	return (*pte & 0x000fffffffe00000UL) |
	       (virt & 0x00000000001fffffUL);
}

static unsigned long amd_iommu_get_phys_l1(pt_entry_t pte, unsigned long virt)
{
	return (*pte & 0x000ffffffffff000UL) |
	       (virt & 0x0000000000000fffUL);
}

static unsigned long amd_iommu_get_next_pt(pt_entry_t pte)
{
	return *pte & 0x000ffffffffff000UL;
}

#define AMD_IOMMU_PAGING_COMMON					\
	.entry_valid		= amd_iommu_entry_valid,		\
	.get_flags		= amd_iommu_get_flags,		\
	.clear_entry		= amd_iommu_clear_entry,		\
	.page_table_empty	= amd_iommu_page_table_empty

const struct paging amd_iommu_paging[AMD_IOMMU_MAX_PAGE_TABLE_LEVELS] = {
	{
		AMD_IOMMU_PAGING_COMMON,
		.get_entry	= amd_iommu_get_entry_l6,
		/* set_terminal not valid */
		.get_phys	= paging_get_phys_invalid,
		.set_next_pt	= amd_iommu_set_next_pt_l6,
		.get_next_pt	= amd_iommu_get_next_pt,
	},
	{
		.page_size	= 256ULL * 1024 * 1024 * 1024 * 1024,
		AMD_IOMMU_PAGING_COMMON,
		.get_entry	= amd_iommu_get_entry_l5,
		.set_terminal	= amd_iommu_set_terminal_l5,
		.get_phys	= amd_iommu_get_phys_l5,
		.set_next_pt	= amd_iommu_set_next_pt_l5,
		.get_next_pt	= amd_iommu_get_next_pt,
	},
	{
		.page_size	= 512ULL * 1024 * 1024 * 1024,
		AMD_IOMMU_PAGING_COMMON,
		.get_entry	= amd_iommu_get_entry_l4,
		.set_terminal	= amd_iommu_set_terminal_l4,
		.get_phys	= amd_iommu_get_phys_l4,
		.set_next_pt	= amd_iommu_set_next_pt_l4,
		.get_next_pt	= amd_iommu_get_next_pt,
	},
	{
		.page_size	= 1024 * 1024 * 1024,
		AMD_IOMMU_PAGING_COMMON,
		.get_entry	= amd_iommu_get_entry_l3,
		.set_terminal	= amd_iommu_set_terminal_l3,
		.get_phys	= amd_iommu_get_phys_l3,
		.set_next_pt	= amd_iommu_set_next_pt_l3,
		.get_next_pt	= amd_iommu_get_next_pt,
	},
	{
		.page_size	= 2 * 1024 * 1024,
		AMD_IOMMU_PAGING_COMMON,
		.get_entry	= amd_iommu_get_entry_l2,
		.set_terminal	= amd_iommu_set_terminal_l2,
		.get_phys	= amd_iommu_get_phys_l2,
		.set_next_pt	= amd_iommu_set_next_pt_l2,
		.get_next_pt	= amd_iommu_get_next_pt,
	},
	{
		.page_size	= PAGE_SIZE,
		AMD_IOMMU_PAGING_COMMON,
		.get_entry	= amd_iommu_get_entry_l1,
		.set_terminal	= amd_iommu_set_terminal_l1,
		.get_phys	= amd_iommu_get_phys_l1,
		/* set_next_pt, get_next_pt not valid */
	},
};
