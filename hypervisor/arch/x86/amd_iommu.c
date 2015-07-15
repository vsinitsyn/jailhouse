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

int iommu_map_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	/* TODO: Implement */
	return 0;
}
int iommu_unmap_memory_region(struct cell *cell,
			      const struct jailhouse_memory *mem)
{
	/* TODO: Implement */
	return 0;
}

int iommu_add_pci_device(struct cell *cell, struct pci_device *device)
{
	/* TODO: Implement */
	return 0;
}

void iommu_remove_pci_device(struct pci_device *device)
{
	/* TODO: Implement */
}

void iommu_cell_exit(struct cell *cell)
{
	/* TODO: Again, this a copy of vtd.c:iommu_cell_exit */
	// HACK for QEMU
	if (iommu_units_count == 0)
		return;

	page_free(&mem_pool, cell->arch.amd_iommu.pg_structs.root_table, 1);
}

void iommu_config_commit(struct cell *cell_added_removed)
{
	/* TODO: Implement */
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

void iommu_check_pending_faults(void)
{
	/* TODO: Implement */
}

bool iommu_cell_emulates_ir(struct cell *cell)
{
	/* TODO: Implement */
	return false;
}
