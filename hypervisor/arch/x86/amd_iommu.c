/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Valentine Sinitsyn, 2014
 *
 * Authors:
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * Commands posting and event log parsing code, as well as many defines
 * were adapted from Linux's amd_iommu driver written by Joerg Roedel
 * and Leo Duran.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/entry.h>
#include <jailhouse/cell.h>
#include <jailhouse/cell-config.h>
#include <jailhouse/control.h>
#include <jailhouse/mmio.h>
#include <jailhouse/pci.h>
#include <jailhouse/printk.h>
#include <jailhouse/string.h>
#include <jailhouse/types.h>
#include <asm/amd_iommu.h>
#include <asm/amd_iommu_paging.h>
#include <asm/apic.h>
#include <asm/iommu.h>
#include <asm/percpu.h>

/* Allocate minimum space possible (4K or 256 entries) */

#define buffer_size(name, entry)	((1 << name##_LEN_EXPONENT) * \
					  sizeof(entry))

#define CMD_BUF_LEN_EXPONENT	8
#define EVT_LOG_LEN_EXPONENT	8

#define CMD_BUF_SIZE		buffer_size(CMD_BUF, struct cmd_buf_entry)
#define EVT_LOG_SIZE		buffer_size(EVT_LOG, struct evt_log_entry)

#define BITS_PER_SHORT		16

static struct amd_iommu {
	int idx;
	void *mmio_base;
	int mmio_size;
	/* Command Buffer, Event Log */
	unsigned char *cmd_buf_base;
	unsigned char *evt_log_base;
	/* Device table */
	void *devtable_segments[DEV_TABLE_SEG_MAX];
	u8 dev_tbl_seg_sup;
	u32 cmd_tail_ptr;

	u16 bdf;
	u16 msi_cap;

	/* ACPI overrides for feature bits */
	union {
		u32 raw;
		struct {
			u8 __pad0:7;
			u8 he_sup:1;
			u32 __pad1:22;
			u8 hats:2;
		};
	} features;
} iommu_units[JAILHOUSE_MAX_IOMMU_UNITS];

#define for_each_iommu(iommu) for(iommu = iommu_units; \
		                  iommu < iommu_units + iommu_units_count; \
		                  iommu++)

#define to_u64(hi, lo)	((u64)(hi) << 32 | (lo))

static unsigned int iommu_units_count;

static unsigned int fault_reporting_cpu_id;

/*
 * XXX: The initial idea was to have this equals to minimum value for
 * all IOMMUs in the system. It's not clear how to reuse paging.c functions
 * for 6 page table levels, so we'll just set it to constant value of four.
 */
static int amd_iommu_pt_levels = 4;

/*
 * Real AMD IOMMU paging structures: a least common denominator for all IOMMUs
 * in the current system.
 */
static struct paging real_amd_iommu_paging[AMD_IOMMU_MAX_PAGE_TABLE_LEVELS];

static unsigned long amd_iommu_get_efr(struct amd_iommu *iommu)
{
	return mmio_read64(iommu->mmio_base + MMIO_EXT_FEATURES);
}

/*
 * Following functions return various feature bits from EFR or
 * IVRS ACPI table. The latter takes precedence as per Sect. 5.
 * Note there is no indicator flag for ACPI overrides; we rely on
 * the assumption that at least one feature bit will be set in
 * the IVRS.
 */
static unsigned int amd_iommu_get_hats(struct amd_iommu *iommu)
{
	unsigned long efr = amd_iommu_get_efr(iommu);

	if (iommu->features.raw)
		return iommu->features.hats;

	return (efr & FEATURE_HATS_MASK) >> FEATURE_HATS_SHIFT;
}

static unsigned int amd_iommu_get_he_sup(struct amd_iommu *iommu)
{
	unsigned long efr = amd_iommu_get_efr(iommu);

	if (iommu->features.raw)
		return iommu->features.he_sup;

	return (efr & FEATURE_HE_SUP_MASK) >> FEATURE_HE_SUP_SHIFT;
}

static int amd_iommu_init_mmio(struct amd_iommu *entry,
			       struct jailhouse_iommu *iommu)
{
	int err = -ENOMEM;

	/* Allocate MMIO space (configured in amd_iommu_init_pci()) */
	entry->mmio_base = page_alloc(&remap_pool, PAGES(iommu->size));
	if (!entry->mmio_base)
		goto out;
	entry->mmio_size = iommu->size;

	err = paging_create(&hv_paging_structs, iommu->base, iommu->size,
			    (unsigned long)entry->mmio_base,
			    PAGE_DEFAULT_FLAGS | PAGE_FLAG_DEVICE,
			    PAGING_NON_COHERENT);
	if (err)
		goto out_free_mmio;

	return 0;

out_free_mmio:
	page_free(&remap_pool, entry->mmio_base, PAGES(iommu->size));
out:
	return err;
}

static int amd_iommu_init_buffers(struct amd_iommu *entry,
				  struct jailhouse_iommu *iommu)
{
	int err = -ENOMEM;

	/* Allocate and configure command buffer */
	entry->cmd_buf_base = page_alloc(&mem_pool, PAGES(CMD_BUF_SIZE));
	if (!entry->cmd_buf_base)
		goto out;

	mmio_write64(entry->mmio_base + MMIO_CMD_BUF_OFFSET,
		     paging_hvirt2phys(entry->cmd_buf_base) |
		     ((u64)CMD_BUF_LEN_EXPONENT << BUF_LEN_EXPONENT_SHIFT));

	entry->cmd_tail_ptr = 0;

	/* Allocate and configure event log */
	entry->evt_log_base = page_alloc(&mem_pool, PAGES(EVT_LOG_SIZE));
	if (!entry->evt_log_base)
		goto out_free_cmd_buf;

	mmio_write64(entry->mmio_base + MMIO_EVT_LOG_OFFSET,
		     paging_hvirt2phys(entry->evt_log_base) |
		     ((u64)EVT_LOG_LEN_EXPONENT << BUF_LEN_EXPONENT_SHIFT));

	return 0;

out_free_cmd_buf:
	page_free(&mem_pool, entry->cmd_buf_base, PAGES(CMD_BUF_SIZE));
out:
	return trace_error(err);
}

static int amd_iommu_init_pci(struct amd_iommu *entry,
			      struct jailhouse_iommu *iommu)
{
	u64 caps_header;
	u32 lo, hi;

	entry->bdf = iommu->amd_bdf;

	/* Check alignment */
	if (iommu->size & (iommu->size - 1))
		return trace_error(-EINVAL);

	/* Check that EFR is supported */
	caps_header = pci_read_config(entry->bdf, iommu->amd_cap, 4);
	if (!(caps_header & IOMMU_CAP_EFR))
		return trace_error(-EINVAL);

	lo = pci_read_config(
			entry->bdf, iommu->amd_cap + CAPS_IOMMU_BASE_LOW, 4);
	hi = pci_read_config(
			entry->bdf, iommu->amd_cap + CAPS_IOMMU_BASE_HI, 4);

	if ((lo & IOMMU_CAP_ENABLE) &&
			(to_u64(hi, lo & ~IOMMU_CAP_ENABLE) != iommu->base)) {
		printk("FATAL: IOMMU %d config is locked in invalid state. "
		       "Please reboot your system and try again.\n", entry->idx);
		return trace_error(-EPERM);
	}

	/* Should be configured by BIOS, but we want to be sure */
	pci_write_config(entry->bdf,
			 iommu->amd_cap + CAPS_IOMMU_BASE_HI,
			 (u32)(iommu->base >> 32), 4);
	pci_write_config(entry->bdf,
			 iommu->amd_cap + CAPS_IOMMU_BASE_LOW,
			 (u32)(iommu->base & 0xffffffff) | IOMMU_CAP_ENABLE,
			 4);

	/* Store MSI capability pointer */
	entry->msi_cap = pci_find_capability_by_id(entry->bdf, PCI_CAP_MSI);
	if (!entry->msi_cap)
		return trace_error(-EINVAL);

	return 0;
}

static int amd_iommu_init_features(struct amd_iommu *entry,
				   struct jailhouse_iommu *iommu)
{
	unsigned char smi_filter_regcnt;
	u64 efr, ctrl_reg = 0, smi_freg = 0, val;
	unsigned int n, hats;
	void *reg_base;

	entry->features.raw = iommu->amd_features;

	efr = amd_iommu_get_efr(entry);

	/* Minimum HATS wins */
	hats = amd_iommu_get_hats(entry);
	if (amd_iommu_pt_levels < 0 || amd_iommu_pt_levels > hats + 4)
		amd_iommu_pt_levels = hats + 4;

	/*
	 * Require SMI Filter support. Enable and lock filter but
	 * mark all entries as invalid to disable SMI delivery.
	 */
	if (!(efr & FEATURE_SMI_FSUP_MASK))
		return trace_error(-EINVAL);

	smi_filter_regcnt = (1 << (efr & FEATURE_SMI_FRC_MASK) >>
		FEATURE_SMI_FRC_SHIFT);
	for (n = 0; n < smi_filter_regcnt; n++) {
		reg_base = entry->mmio_base + MMIO_SMI_FREG0_OFFSET + (n << 3);
		smi_freg = mmio_read64(reg_base);

		if (!(smi_freg & SMI_FREG_LOCKED)) {
			/*
			 * Program unlocked register the way we need:
			 * invalid and locked.
			 */
			mmio_write64(reg_base, SMI_FREG_LOCKED);
		}
		else if (smi_freg & SMI_FREG_VALID) {
			/*
			 * The register is locked and programed
			 * the way we don't want - error.
			 */
			printk("ERROR: SMI Filter register %d is locked "
			       "and can't be reprogrammed. Please reboot "
			       "and check no other component uses the "
			       "IOMMU %d.\n", n, entry->idx);
			return trace_error(-EPERM);
		}
		/*
		 * The register is locked, but programmed
		 * the way we need - OK to go.
		 */
	}

	ctrl_reg |= (CONTROL_SMIF_EN | CONTROL_SMIFLOG_EN);

	/* Enable maximum Device Table segmentation possible */
	entry->dev_tbl_seg_sup = (efr & FEATURE_SEG_SUP_MASK) >>
		FEATURE_SEG_SUP_SHIFT;
	if (entry->dev_tbl_seg_sup) {
		val = entry->dev_tbl_seg_sup & CONTROL_SEG_SUP_MASK;
		ctrl_reg |= val << CONTROL_SEG_SUP_SHIFT;
	}

	mmio_write64(entry->mmio_base + MMIO_CONTROL_OFFSET, ctrl_reg);

	return 0;
}

static void amd_iommu_enable_command_processing(struct amd_iommu *iommu)
{
	u64 ctrl_reg;

	ctrl_reg = mmio_read64(iommu->mmio_base + MMIO_CONTROL_OFFSET);
	ctrl_reg |= CONTROL_IOMMU_EN | CONTROL_CMD_BUF_EN |
			CONTROL_EVT_LOG_EN | CONTROL_EVT_INT_EN;
	mmio_write64(iommu->mmio_base + MMIO_CONTROL_OFFSET, ctrl_reg);
}

unsigned int iommu_mmio_count_regions(struct cell *cell)
{
	return cell == &root_cell ? iommu_count_units() : 0;
}

int iommu_init(void)
{
	const struct paging *toplevel_paging = &amd_iommu_paging[0];
	struct jailhouse_iommu *iommu;
	struct amd_iommu *entry;
	unsigned int n;
	int err;

	iommu = &system_config->platform_info.x86.iommu_units[0];
	for (n = 0; iommu->base && n < iommu_count_units(); iommu++, n++) {
		entry = &iommu_units[iommu_units_count];

		entry->idx = n;

		/* Protect against accidental VT-d configs. */
		if (!iommu->amd_bdf)
			return trace_error(-EINVAL);

		/* Initialize PCI registers */
		err = amd_iommu_init_pci(entry, iommu);
		if (err)
			return err;

		/* Initialize MMIO space */
		err = amd_iommu_init_mmio(entry, iommu);
		if (err)
			return err;

		/* Setup IOMMU features */
		err = amd_iommu_init_features(entry, iommu);
		if (err)
			return err;

		/* Initialize command buffer and event log */
		err = amd_iommu_init_buffers(entry, iommu);
		if (err)
			return err;

		/* Enable the IOMMU */
		amd_iommu_enable_command_processing(entry);

		iommu_units_count++;
	}

	if (amd_iommu_pt_levels > AMD_IOMMU_MAX_PAGE_TABLE_LEVELS)
		return trace_error(-ERANGE);

	toplevel_paging += AMD_IOMMU_MAX_PAGE_TABLE_LEVELS - amd_iommu_pt_levels;
	memcpy(real_amd_iommu_paging, toplevel_paging,
			sizeof(struct paging) * amd_iommu_pt_levels);

	/*
	 * Real page table has less levels than amd_iommu_paging - setup new
	 * top level paging structure.
	 */
	if (amd_iommu_pt_levels != AMD_IOMMU_MAX_PAGE_TABLE_LEVELS) {
		real_amd_iommu_paging[0].page_size = 0;
		real_amd_iommu_paging[0].get_phys = paging_get_phys_invalid;
	}

	return iommu_cell_init(&root_cell);
}

int iommu_cell_init(struct cell *cell)
{
	// HACK for QEMU
	if (iommu_units_count == 0)
		return 0;

	if (cell->id > 0xffff)
		return trace_error(-ERANGE);

	cell->arch.amd_iommu.pg_structs.root_paging = real_amd_iommu_paging;
	cell->arch.amd_iommu.pg_structs.root_table = page_alloc(&mem_pool, 1);
	if (!cell->arch.amd_iommu.pg_structs.root_table)
		return trace_error(-ENOMEM);

	return 0;
}

static void amd_iommu_completion_wait(struct amd_iommu *iommu);

#define CMD_BUF_DRAIN_MAX_ATTEMPTS	8

static void amd_iommu_submit_command(struct amd_iommu *iommu,
				     struct cmd_buf_entry *cmd)
{
	u32 head, next_tail, bytes_free;
	unsigned char *cur_ptr;
	static bool drain = false;
	static int drain_attempts = 0;

again:
	head = mmio_read64(iommu->mmio_base + MMIO_CMD_HEAD_OFFSET);
	next_tail = (iommu->cmd_tail_ptr + sizeof(*cmd)) % CMD_BUF_SIZE;
	/* XXX: Learn why this works :) */
	bytes_free = (head - next_tail) % CMD_BUF_SIZE;

	/* Leave some space for COMPLETION_WAIT that drains the buffer. */
	if (bytes_free < 2 * sizeof(*cmd) && !drain) {
		/* Drain the buffer */
		drain = true;
		amd_iommu_completion_wait(iommu);
		drain = false;
		goto again;
	}

	if (drain) {
		/* Ensure we won't drain the buffer indefinitely */
		if (++drain_attempts > CMD_BUF_DRAIN_MAX_ATTEMPTS) {
			panic_printk("FATAL: IOMMU %d: "
				     "Failed to drain the command buffer\n",
				     iommu->idx);
			panic_park();
		}
	} else {
		/* Buffer drained - reset the counter */
		drain_attempts = 0;
	}

	cur_ptr = &iommu->cmd_buf_base[iommu->cmd_tail_ptr];
	memcpy(cur_ptr, cmd, sizeof(*cmd));

	/* Just to be sure. */
	arch_paging_flush_cpu_caches(cur_ptr, sizeof(*cmd));

	iommu->cmd_tail_ptr = next_tail;
}

int iommu_map_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	unsigned long flags = AMD_IOMMU_PTE_P, zero_bits;

	// HACK for QEMU
	if (iommu_units_count == 0)
		return 0;

	/*
	 * Check that the address is not outside scope of current page
	 * tables (given their level). Each level adds 9 bits and the offset
	 * is 12 bits long, so no bits higher than this should be set.
	 */
	if (amd_iommu_pt_levels != AMD_IOMMU_MAX_PAGE_TABLE_LEVELS) {
		zero_bits = ~((1ULL << (amd_iommu_pt_levels * 9 + 12)) - 1);
		if (mem->virt_start & zero_bits)
			return trace_error(-ERANGE);
	}

	if (!(mem->flags & JAILHOUSE_MEM_DMA))
		return 0;

	if (mem->flags & JAILHOUSE_MEM_READ)
		flags |= AMD_IOMMU_PTE_IR;
	if (mem->flags & JAILHOUSE_MEM_WRITE)
		flags |= AMD_IOMMU_PTE_IW;

	return paging_create(&cell->arch.amd_iommu.pg_structs, mem->phys_start,
			mem->size, mem->virt_start, flags, PAGING_COHERENT);
}

int iommu_unmap_memory_region(struct cell *cell,
			      const struct jailhouse_memory *mem)
{
	/*
         * TODO: This is almost a complete copy of vtd.c counterpart
	 * (sans QEMU hack). Think of unification.
	 */

	// HACK for QEMU
	if (iommu_units_count == 0)
		return 0;

	if (!(mem->flags & JAILHOUSE_MEM_DMA))
		return 0;

	return paging_destroy(&cell->arch.amd_iommu.pg_structs, mem->virt_start,
			mem->size, PAGING_COHERENT);
}

static void amd_iommu_inv_dte(struct amd_iommu *iommu, u16 device_id)
{
	/* Double braces to please GCC */
	struct cmd_buf_entry invalidate_dte = {{ 0 }};

	invalidate_dte.data[0] = device_id;
	CMD_SET_TYPE(&invalidate_dte, CMD_INV_DEVTAB_ENTRY);

	amd_iommu_submit_command(iommu, &invalidate_dte);
}

static struct dev_table_entry * get_dev_table_entry(struct amd_iommu *iommu,
						    u16 bdf, bool allocate)
{
	struct dev_table_entry *devtable_seg;
	u8 seg_idx, seg_shift;
	u64 reg_base, reg_val;
	u16 seg_mask;
	u32 seg_size;

	/*
         * FIXME: Device Table Segmentation is UNTESTED, as I don't have the hardware
	 * which supports this feature.
	 */
	if (!iommu->dev_tbl_seg_sup) {
		seg_mask = 0;
		seg_idx = 0;
		seg_size = DEV_TABLE_SIZE;
	} else {
		seg_shift = BITS_PER_SHORT - iommu->dev_tbl_seg_sup;
		seg_mask = ~((1 << seg_shift) - 1);
		seg_idx = (seg_mask & bdf) >> seg_shift;
		seg_size = DEV_TABLE_SIZE / (1 << iommu->dev_tbl_seg_sup);
	}

	/*
	 * Device table segmentation is tricky in Jailhouse. As cells can
	 * "share" the IOMMU, we don't know maximum bdf in each segment
	 * because cells are initialized independently. Thus, we can't simply
	 * adjust segment sizes for our maximum bdfs.
	 *
	 * The next best things is to lazily allocate segments as we add
	 * device using maximum possible size for segments. In the worst case
	 * scenario, we waste around 2M chunk per IOMMU.
	 */
	devtable_seg = iommu->devtable_segments[seg_idx];
	if (!devtable_seg) {
		/* If we are not permitted to allocate, just fail */
		if (!allocate)
			return NULL;

		devtable_seg = page_alloc(&mem_pool, PAGES(seg_size));
		if (!devtable_seg)
			return NULL;
		iommu->devtable_segments[seg_idx] = devtable_seg;

		if (!seg_idx)
			reg_base = MMIO_DEV_TABLE_BASE;
		else
			reg_base = MMIO_DEV_TABLE_SEG_BASE + (seg_idx - 1) * 8;

		/* Size in Kbytes = (m + 1) * 4, see Sect 3.3.6 */
		reg_val = paging_hvirt2phys(devtable_seg) |
			(seg_size / PAGE_SIZE - 1);
		mmio_write64(iommu->mmio_base + reg_base, reg_val);
	}

	return &devtable_seg[bdf & ~seg_mask];
}

int iommu_add_pci_device(struct cell *cell, struct pci_device *device)
{
	struct dev_table_entry *dte = NULL;
	struct amd_iommu *iommu;
	u8 iommu_idx;
	int err = 0;
	u16 bdf;

	// HACK for QEMU
	if (iommu_units_count == 0)
		return 0;

	if (device->info->type == JAILHOUSE_PCI_TYPE_IVSHMEM)
		return 0;

	iommu_idx = device->info->iommu;
	if (iommu_idx > JAILHOUSE_MAX_IOMMU_UNITS) {
		err = -ERANGE;
		goto out;
	}

	iommu = &iommu_units[iommu_idx];
	bdf = device->info->bdf;

	dte = get_dev_table_entry(iommu, bdf, true);
	if (!dte) {
		err = -ENOMEM;
		goto out;
	}

	memset(dte, 0, sizeof(*dte));

	/* DomainID */
	dte->data[1] = cell->id & 0xffff;

	/* Translation information */
	dte->data[0] = AMD_IOMMU_PTE_IR | AMD_IOMMU_PTE_IW |
		paging_hvirt2phys(cell->arch.amd_iommu.pg_structs.root_table) |
		((amd_iommu_pt_levels & DTE_MODE_MASK) << DTE_MODE_SHIFT) |
		DTE_TRANSLATION_VALID | DTE_VALID;

	/* TODO: Interrupt remapping. For now, just forward them unmapped. */

	/* Flush caches, just to be sure. */
	arch_paging_flush_cpu_caches(dte, sizeof(*dte));

	amd_iommu_inv_dte(iommu, bdf);

out:
	return trace_error(err);
}

void iommu_remove_pci_device(struct pci_device *device)
{
	struct dev_table_entry *dte = NULL;
	struct amd_iommu *iommu;
	u8 iommu_idx;
	u16 bdf;

	// HACK for QEMU
	if (iommu_units_count == 0)
		return;

	if (device->info->type == JAILHOUSE_PCI_TYPE_IVSHMEM)
		return;

	iommu_idx = device->info->iommu;
	if (iommu_idx > JAILHOUSE_MAX_IOMMU_UNITS)
		return;

	iommu = &iommu_units[iommu_idx];
	bdf = device->info->bdf;

	dte = get_dev_table_entry(iommu, bdf, false);
	if (!dte)
		return;

	/* Clear *_VALID flags */
	dte->data[0] = 0;

	/* Flush caches, just to be sure. */
	arch_paging_flush_cpu_caches(dte, sizeof(*dte));

	amd_iommu_inv_dte(iommu, bdf);
}

void iommu_cell_exit(struct cell *cell)
{
	/* TODO: Again, this a copy of vtd.c:iommu_cell_exit */
	// HACK for QEMU
	if (iommu_units_count == 0)
		return;

	page_free(&mem_pool, cell->arch.amd_iommu.pg_structs.root_table, 1);
}

static void wait_for_zero(volatile u64 *sem, unsigned long mask)
{
	/*
         * TODO: We should really have some sort of timeout here,
	 * otherwise there is a risk of looping indefinitely blocking
	 * the hypervisor. However, this requires some sort of time
	 * keeping, so let's postpone this till the time it will be
	 * available in Jailhouse.
	 */
	while (*sem & mask)
		cpu_relax();
}

static void amd_iommu_invalidate_pages(struct amd_iommu *iommu,
				       u16 domain_id)
{
	/* Double braces to please GCC */
	struct cmd_buf_entry invalidate_pages = {{ 0 }};

	/*
	 * Flush everything, including PDEs, in whole address range, i.e.
	 * 0x7ffffffffffff000 with S bit (see Sect. 2.2.3).
	 */
	invalidate_pages.data[1] = domain_id;
	invalidate_pages.data[2] = 0xfffff000 |
		CMD_INV_IOMMU_PAGES_SIZE_MASK |
		CMD_INV_IOMMU_PAGES_PDE_MASK;
	invalidate_pages.data[3] = 0x7fffffff;
	CMD_SET_TYPE(&invalidate_pages, CMD_INV_IOMMU_PAGES);

	amd_iommu_submit_command(iommu, &invalidate_pages);
}

static void amd_iommu_completion_wait(struct amd_iommu *iommu)
{
	/* Double braces to please GCC */
	struct cmd_buf_entry completion_wait = {{ 0 }};
	volatile u64 sem = 1;
	long addr;

	addr = paging_hvirt2phys(&sem);

	completion_wait.data[0] = (addr & 0xfffffff8UL) |
		CMD_COMPL_WAIT_STORE_MASK;
	completion_wait.data[1] = (addr & 0x000fffff00000000UL) >> 32;
	CMD_SET_TYPE(&completion_wait, CMD_COMPL_WAIT);

	amd_iommu_submit_command(iommu, &completion_wait);
	mmio_write64(iommu->mmio_base + MMIO_CMD_TAIL_OFFSET,
			iommu->cmd_tail_ptr);

	wait_for_zero(&sem, -1);
}

/* Parts of this code derives from vtd_init_fault_nmi(). */
static void amd_iommu_init_fault_nmi(void)
{
	union pci_msi_registers msi = {{ 0 }};
	struct per_cpu *cpu_data;
	struct amd_iommu *iommu;
	int n;

	/*
	 * This assumes that at least one bit is set somewhere because we
	 * don't support configurations where Linux is left with no CPUs.
	 */
	for (n = 0; root_cell.cpu_set->bitmap[n] == 0; n++)
		/* Empty loop */;
	cpu_data = per_cpu(ffsl(root_cell.cpu_set->bitmap[n]));

	/*
	 * Save this value globally to avoid multiple reports of the same
	 * case from different CPUs.
	 */
	fault_reporting_cpu_id = cpu_data->cpu_id;

	for_each_iommu(iommu) {
		msi.raw[0] = pci_read_config(iommu->bdf, iommu->msi_cap, 4);

		/* Disable MSI during interrupt reprogramming */
		msi.msg32.enable = 0;
		pci_write_config(iommu->bdf, iommu->msi_cap, msi.raw[0], 4);

		/* Send NMI to fault_reporting_cpu */
		msi.msg64.address = (MSI_ADDRESS_VALUE << MSI_ADDRESS_SHIFT) |
			            ((cpu_data->apic_id << 12) & 0xff000);
		msi.msg64.data = MSI_DM_NMI;

		/* Enable MSI back */
		msi.msg32.enable = 1;

		/* Write new MSI capabilty block */
		for (n = 3; n >= 0; n--)
			pci_write_config(iommu->bdf, iommu->msi_cap + 4 * n,
					 msi.raw[n], 4);
	}

	/*
	 * There is a race window in between we change fault_reporting_cpu_id
	 * and actually reprogram the MSI. To prevent event loss, signal an
	 * interrupt when done, so iommu_check_pending_faults() is called
	 * upon completion even if no further NMIs due to events would occurr.
	 *
	 * Note we can't simply use CMD_COMPL_WAIT_INT_MASK in
	 * amd_iommu_completion_wait(), as it seems that IOMMU either signal
	 * an interrupt or do memory write, but not both.
	 */
	 apic_send_nmi_ipi(cpu_data);
}

void iommu_config_commit(struct cell *cell_added_removed)
{
	struct amd_iommu *iommu;

	/* Ensure we'll get NMI on comletion, or if anything goes wrong. */
	if (cell_added_removed)
		amd_iommu_init_fault_nmi();

	for_each_iommu(iommu) {
		/* Flush caches */
		if (cell_added_removed) {
			amd_iommu_invalidate_pages(iommu,
					cell_added_removed->id & 0xffff);
			amd_iommu_invalidate_pages(iommu,
					root_cell.id & 0xffff);
		}
		/* Execute all commands in the buffer */
		amd_iommu_completion_wait(iommu);
	}
}

struct apic_irq_message iommu_get_remapped_root_int(unsigned int iommu,
						    u16 device_id,
						    unsigned int vector,
						    unsigned int remap_index)
{
	struct apic_irq_message dummy = { .valid = 0 };

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
	struct amd_iommu *iommu;
	u64 ctrl_reg;
	u32 seg_size;
	int n, err;
	void *ptr;

	for_each_iommu(iommu) {
		/* Disable the IOMMU */
		ctrl_reg = mmio_read64(iommu->mmio_base + MMIO_CONTROL_OFFSET);
		ctrl_reg &= ~(CONTROL_IOMMU_EN | CONTROL_CMD_BUF_EN |
			CONTROL_EVT_LOG_EN | CONTROL_EVT_INT_EN);
		mmio_write64(iommu->mmio_base + MMIO_CONTROL_OFFSET, ctrl_reg);

		/* Free Device Table (and segments) */
		seg_size = DEV_TABLE_SIZE / (1 << iommu->dev_tbl_seg_sup);
		for (n = 0; n < DEV_TABLE_SEG_MAX; n++) {
			ptr = iommu->devtable_segments[n];
			if (ptr)
				page_free(&mem_pool, ptr, PAGES(seg_size));
		}

		/* Free Command Buffer and Event Log */
		page_free(&mem_pool, iommu->cmd_buf_base,
				PAGES(CMD_BUF_SIZE));

		/* Free Event Log */
		page_free(&mem_pool, iommu->evt_log_base,
				PAGES(EVT_LOG_SIZE));

		/* Free MMIO */
		err = paging_destroy(&hv_paging_structs,
				(unsigned long)iommu->mmio_base,
				iommu->mmio_size, PAGING_NON_COHERENT);
		if (err < 0) {
			printk("ERROR: IOMMU %d: Unable to destroy "
			       "MMIO page mappings\n", iommu->idx);
			/*
			 * There is not much more else we can do,
			 * as we are shutting down already.
			 */
		}
		page_free(&remap_pool, iommu->mmio_base,
				PAGES(iommu->mmio_size));
	}
}

static void amd_iommu_print_event(struct amd_iommu *iommu,
		                  struct evt_log_entry *entry)
{
	u8 evt_code = (entry->data[1] >> 28) & 0xf;
	u64 op1, op2;

	op1 = to_u64(entry->data[1] & 0x0fffffff, entry->data[0]);
	op2 = to_u64(entry->data[3], entry->data[2]);

	/* TODO: Can we handle these errors more gracefully? */
	if (evt_code == EVENT_TYPE_ILL_CMD_ERR) {
		printk("FATAL: IOMMU %d reported ILLEGAL_COMMAND_ERROR\n",
				iommu->idx);
		panic_stop();
	}

	if (evt_code == EVENT_TYPE_CMD_HW_ERR) {
		printk("FATAL: IOMMU %d reported COMMAND_HARDWARE_ERROR\n",
				iommu->idx);
		panic_stop();
	}

	/*
	 * TODO: For now, very basic printer. Consider adapting
	 * iommu_print_event() from the Linux kerel (amd_iommu.c).
	 */
	printk("AMD IOMMU %d reported event\n", iommu->idx);
	/* Exclude EVENT_COUNTER_ZERO, as it doesn't report domain ID. */
	if (evt_code != EVENT_TYPE_EVT_CNT_ZERO)
		printk(" DeviceId (bus:dev.func): %02x:%02x.%x\n",
				PCI_BDF_PARAMS(entry->data[0] & 0xffff));

	printk(" EventCode: %lx Operand 1: %lx, Operand 2: %lx\n",
			evt_code, op1, op2);
}

static void amd_iommu_restart_event_log(struct amd_iommu *iommu)
{
	void *base = iommu->mmio_base;

	wait_for_zero(base + MMIO_STATUS_OFFSET, MMIO_STATUS_EVT_RUN_MASK);

	mmio_write64_field(base + MMIO_CONTROL_OFFSET, CONTROL_EVT_LOG_EN, 0);

	/* Simply start from the scratch */
	mmio_write64(base + MMIO_EVT_HEAD_OFFSET, 0);
	mmio_write64(base + MMIO_EVT_TAIL_OFFSET, 0);

	/* Clear EventOverflow (RW1C) */
	mmio_write64_field(base + MMIO_STATUS_OFFSET,
			MMIO_STATUS_EVT_OVERFLOW_MASK, 1);

	/* Bring logging back */
	mmio_write64_field(base + MMIO_CONTROL_OFFSET, CONTROL_EVT_LOG_EN, 1);
}

static void amd_iommu_poll_events(struct amd_iommu *iommu)
{
	struct evt_log_entry *evt;
	u32 head, tail;
	u64 status;

	status = mmio_read64(iommu->mmio_base + MMIO_STATUS_OFFSET);

	if (status & MMIO_STATUS_EVT_OVERFLOW_MASK) {
		printk("IOMMU %d: Event Log overflow occurred, "
				"some events were lost!\n", iommu->idx);
		amd_iommu_restart_event_log(iommu);
	}

	while (status & MMIO_STATUS_EVT_INT_MASK) {
		/* Clear EventLogInt (RW1C) */
		mmio_write64_field(iommu->mmio_base + MMIO_STATUS_OFFSET,
				MMIO_STATUS_EVT_INT_MASK, 1);

		head = mmio_read32(iommu->mmio_base + MMIO_EVT_HEAD_OFFSET);
		tail = mmio_read32(iommu->mmio_base + MMIO_EVT_TAIL_OFFSET);

		while (head != tail) {
			evt = (struct evt_log_entry *)(
					iommu->evt_log_base + head);
			amd_iommu_print_event(iommu, evt);
			head = (head + sizeof(*evt)) % EVT_LOG_SIZE;
		}

		mmio_write32(iommu->evt_log_base + MMIO_EVT_HEAD_OFFSET, head);

		/* Re-read status to catch new events, as Linux does */
		status = mmio_read64(iommu->mmio_base + MMIO_STATUS_OFFSET);
	}
}

void iommu_check_pending_faults(void)
{
	/* TODO: Implement */
}

bool iommu_cell_emulates_ir(struct cell *cell)
{
	/* TODO: Implement */
	return false;
}
