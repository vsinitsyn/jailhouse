/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Valentine Sinitsyn, 2014, 2015
 * Copyright (c) Siemens AG, 2016
 *
 * Authors:
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * Commands posting and event log parsing code, as well as many defines
 * were adapted from Linux's amd_iommu driver written by Joerg Roedel
 * and Leo Duran.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/cell.h>
#include <jailhouse/cell-config.h>
#include <jailhouse/control.h>
#include <jailhouse/mmio.h>
#include <jailhouse/pci.h>
#include <jailhouse/printk.h>
#include <jailhouse/string.h>
#include <asm/amd_iommu.h>
#include <asm/apic.h>
#include <asm/ioapic.h>
#include <asm/iommu.h>

#define CAPS_IOMMU_HEADER_REG		0x00
#define  CAPS_IOMMU_EFR_SUP		(1 << 27)
#define CAPS_IOMMU_BASE_LOW_REG		0x04
#define  CAPS_IOMMU_ENABLE		(1 << 0)
#define CAPS_IOMMU_BASE_HI_REG		0x08

#define ACPI_REPORTING_HE_SUP		(1 << 7)

#define AMD_DEV_TABLE_BASE_REG		0x0000
#define AMD_CMD_BUF_BASE_REG		0x0008
#define AMD_EVT_LOG_BASE_REG		0x0010
#define AMD_CONTROL_REG			0x0018
#define  AMD_CONTROL_IOMMU_EN		(1UL << 0)
#define  AMD_CONTROL_EVT_LOG_EN		(1UL << 2)
#define  AMD_CONTROL_EVT_INT_EN		(1UL << 3)
#define  AMD_CONTROL_COMM_WAIT_INT_EN	(1UL << 4)
#define  AMD_CONTROL_CMD_BUF_EN		(1UL << 12)
#define  AMD_CONTROL_SMIF_EN		(1UL << 22)
#define  AMD_CONTROL_SMIFLOG_EN		(1UL << 24)
#define  AMD_CONTROL_SEG_EN_MASK	BIT_MASK(36, 34)
#define  AMD_CONTROL_SEG_EN_SHIFT	34
#define AMD_EXT_FEATURES_REG		0x0030
#define  AMD_EXT_FEAT_HE_SUP		(1UL << 7)
#define  AMD_EXT_FEAT_SMI_FSUP		(1UL << 16)
#define  AMD_EXT_FEAT_SMI_FSUP_MASK	BIT_MASK(17, 16)
#define  AMD_EXT_FEAT_SMI_FRC_MASK	BIT_MASK(20, 18)
#define  AMD_EXT_FEAT_SMI_FRC_SHIFT	18
#define  AMD_EXT_FEAT_SEG_SUP_MASK	BIT_MASK(39, 38)
#define  AMD_EXT_FEAT_SEG_SUP_SHIFT   	38
#define AMD_HEV_UPPER_REG		0x0040
#define AMD_HEV_LOWER_REG		0x0048
#define AMD_HEV_STATUS_REG		0x0050
#define  AMD_HEV_VALID			(1UL << 1)
#define  AMD_HEV_OVERFLOW		(1UL << 2)
#define AMD_SMI_FILTER0_REG		0x0060
#define  AMD_SMI_FILTER_VALID		(1UL << 16)
#define  AMD_SMI_FILTER_LOCKED		(1UL << 17)
#define AMD_DEV_TABLE_SEG1_REG		0x0100
#define AMD_CMD_BUF_HEAD_REG		0x2000
#define AMD_CMD_BUF_TAIL_REG		0x2008
#define AMD_EVT_LOG_HEAD_REG		0x2010
#define AMD_EVT_LOG_TAIL_REG		0x2018
#define AMD_STATUS_REG			0x2020
# define AMD_STATUS_EVT_OVERFLOW	(1UL << 0)
# define AMD_STATUS_EVT_LOG_INT		(1UL << 1)
# define AMD_STATUS_EVT_LOG_RUN		(1UL << 3)

struct dev_table_entry {
	u64 raw64[4];
} __attribute__((packed));

#define DTE_VALID			(1UL << 0)
#define DTE_TRANSLATION_VALID		(1UL << 1)
#define DTE_PAGING_MODE_4_LEVEL		(4UL << 9)
#define DTE_IR				(1UL << 61)
#define DTE_IW				(1UL << 62)

#define DTE_IV				(1UL << 0)
#define DTE_INT_TAB_LEN_SHIFT		1
#define DTE_INTCTL_ABORT		(0UL << 60)
#define DTE_INTCTL_REMAP		(2UL << 60)

#define DEV_TABLE_SEG_MAX		8

union buf_entry {
	u32 raw32[4];
	u64 raw64[2];
	struct {
		u32 pad0;
		u32 pad1:28;
		u32 type:4;
	};
} __attribute__((packed));

#define CMD_COMPL_WAIT			0x01
# define CMD_COMPL_WAIT_STORE		(1 << 0)
# define CMD_COMPL_WAIT_INT		(1 << 1)

#define CMD_INV_DEVTAB_ENTRY		0x02

#define CMD_INV_IOMMU_PAGES		0x03
# define CMD_INV_IOMMU_PAGES_SIZE	(1 << 0)
# define CMD_INV_IOMMU_PAGES_PDE	(1 << 1)

#define CMD_INV_INT_TABLE		0x05

#define EVENT_TYPE_ILL_DEV_TAB_ENTRY	0x01
#define EVENT_TYPE_PAGE_TAB_HW_ERR	0x04
#define EVENT_TYPE_ILL_CMD_ERR		0x05
#define EVENT_TYPE_CMD_HW_ERR		0x06
#define EVENT_TYPE_IOTLB_INV_TIMEOUT	0x07
#define EVENT_TYPE_INV_PPR_REQ		0x09

#define BUF_LEN_EXPONENT_SHIFT		56

/* Allocate minimum space possible (4K or 256 entries) */
#define BUF_SIZE(name, entry)		((1UL << name##_LEN_EXPONENT) * \
					  sizeof(entry))

#define CMD_BUF_LEN_EXPONENT		8
#define EVT_LOG_LEN_EXPONENT		8

#define CMD_BUF_SIZE			BUF_SIZE(CMD_BUF, union buf_entry)
#define EVT_LOG_SIZE			BUF_SIZE(EVT_LOG, union buf_entry)

#define BITS_PER_SHORT			16

#define AMD_IOMMU_MAX_PAGE_TABLE_LEVELS	4

#define MAX_INT_REMAP_TABLE_ORDER	11

union irte {
	struct {
		u32 valid:1;
		u32 sup_iopf:1;
		u32 int_type:3;
		u32 rq_eoi:1;
		u32 destination_mode:1;
		u32 guest_mode:1;
		u32 destination:8;
		u32 vector:8;
		u32 pad0:8;
	};
	u32 raw32;
} __attribute__((packed));

#define REGION_ALLOCATED	0x8000U

struct remap_region {
	u16 base_index;
	u8 count;
	u8 iommu;
};

static struct remap_region *device_remap_regions;
static u16 max_device_id;

static struct amd_iommu {
	int idx;
	void *mmio_base;
	/* Command Buffer, Event Log */
	unsigned char *cmd_buf_base;
	unsigned char *evt_log_base;
	/* Device table */
	void *devtable_segments[DEV_TABLE_SEG_MAX];
	u8 dev_tbl_seg_sup;
	u32 cmd_tail_ptr;
	bool he_supported;
	u16 max_dev_id;
} iommu_units[JAILHOUSE_MAX_IOMMU_UNITS];

#define for_each_iommu(iommu) for (iommu = iommu_units; \
				   iommu < iommu_units + iommu_units_count; \
				   iommu++)

static unsigned int iommu_units_count;

/*
 * Interrupt remapping is not emulated on AMD,
 * thus we have no MMIO to intercept.
 */
unsigned int iommu_mmio_count_regions(struct cell *cell)
{
	return 0;
}

bool iommu_cell_emulates_ir(struct cell *cell)
{
	return false;
}

static void * alloc_zero_pages(unsigned int size)
{
	void *data;

	data = page_alloc(&mem_pool, PAGES(size));
	if (data)
		memset(data, 0, size);

	return data;
}

static int amd_iommu_init_pci(struct amd_iommu *entry,
			      struct jailhouse_iommu *iommu)
{
	u64 caps_header, hi, lo;

	/* Check alignment */
	if (iommu->size & (iommu->size - 1))
		return trace_error(-EINVAL);

	/* Check that EFR is supported */
	caps_header = pci_read_config(iommu->amd_bdf, iommu->amd_base_cap, 4);
	if (!(caps_header & CAPS_IOMMU_EFR_SUP))
		return trace_error(-EIO);

	lo = pci_read_config(iommu->amd_bdf,
			     iommu->amd_base_cap + CAPS_IOMMU_BASE_LOW_REG, 4);
	hi = pci_read_config(iommu->amd_bdf,
			     iommu->amd_base_cap + CAPS_IOMMU_BASE_HI_REG, 4);

	if (lo & CAPS_IOMMU_ENABLE &&
	    ((hi << 32) | lo) != (iommu->base | CAPS_IOMMU_ENABLE)) {
		printk("FATAL: IOMMU %d config is locked in invalid state.\n",
		       entry->idx);
		return trace_error(-EPERM);
	}

	/* Should be configured by BIOS, but we want to be sure */
	pci_write_config(iommu->amd_bdf,
			 iommu->amd_base_cap + CAPS_IOMMU_BASE_HI_REG,
			 (u32)(iommu->base >> 32), 4);
	pci_write_config(iommu->amd_bdf,
			 iommu->amd_base_cap + CAPS_IOMMU_BASE_LOW_REG,
			 (u32)(iommu->base & 0xffffffff) | CAPS_IOMMU_ENABLE,
			 4);

	/* Allocate and map MMIO space */
	entry->mmio_base = page_alloc(&remap_pool, PAGES(iommu->size));
	if (!entry->mmio_base)
		return -ENOMEM;

	return paging_create(&hv_paging_structs, iommu->base, iommu->size,
			     (unsigned long)entry->mmio_base,
			     PAGE_DEFAULT_FLAGS | PAGE_FLAG_DEVICE,
			     PAGING_NON_COHERENT);
}

static int amd_iommu_init_features(struct amd_iommu *entry,
				   struct jailhouse_iommu *iommu)
{
	u64 efr = mmio_read64(entry->mmio_base + AMD_EXT_FEATURES_REG);
	unsigned char smi_filter_regcnt;
	u64 val, ctrl_reg = 0, smi_freg = 0;
	unsigned int n;
	void *reg_base;

	/*
	 * Require SMI Filter support. Enable and lock filter but
	 * mark all entries as invalid to disable SMI delivery.
	 */
	if ((efr & AMD_EXT_FEAT_SMI_FSUP_MASK) != AMD_EXT_FEAT_SMI_FSUP)
		return trace_error(-EIO);

	/* Figure out if hardware events are supported. */
	if (iommu->amd_features)
		entry->he_supported =
			iommu->amd_features & ACPI_REPORTING_HE_SUP;
	else
		entry->he_supported = efr & AMD_EXT_FEAT_HE_SUP;

	smi_filter_regcnt = (1 << (efr & AMD_EXT_FEAT_SMI_FRC_MASK) >>
		AMD_EXT_FEAT_SMI_FRC_SHIFT);
	for (n = 0; n < smi_filter_regcnt; n++) {
		reg_base = entry->mmio_base + AMD_SMI_FILTER0_REG + (n << 3);
		smi_freg = mmio_read64(reg_base);

		if (!(smi_freg & AMD_SMI_FILTER_LOCKED)) {
			/*
			 * Program unlocked register the way we need:
			 * invalid and locked.
			 */
			mmio_write64(reg_base, AMD_SMI_FILTER_LOCKED);
		} else if (smi_freg & AMD_SMI_FILTER_VALID) {
			/*
			 * The register is locked and programed
			 * the way we don't want - error.
			 */
			printk("ERROR: SMI Filter register %d is locked "
			       "and can't be reprogrammed.\n"
			       "Reboot and check no other component uses the "
			       "IOMMU %d.\n", n, entry->idx);
			return trace_error(-EPERM);
		}
		/*
		 * The register is locked, but programmed
		 * the way we need - OK to go.
		 */
	}

	ctrl_reg |= (AMD_CONTROL_SMIF_EN | AMD_CONTROL_SMIFLOG_EN);

	/* Enable maximum Device Table segmentation possible */
	entry->dev_tbl_seg_sup = (efr & AMD_EXT_FEAT_SEG_SUP_MASK) >>
		AMD_EXT_FEAT_SEG_SUP_SHIFT;
	if (entry->dev_tbl_seg_sup) {
		val = (u64)entry->dev_tbl_seg_sup << AMD_CONTROL_SEG_EN_SHIFT;
		ctrl_reg |= val & AMD_CONTROL_SEG_EN_MASK;
	}

	mmio_write64(entry->mmio_base + AMD_CONTROL_REG, ctrl_reg);

	return 0;
}

static int amd_iommu_init_buffers(struct amd_iommu *entry,
				  struct jailhouse_iommu *iommu)
{
	/* Allocate and configure command buffer */
	entry->cmd_buf_base = page_alloc(&mem_pool, PAGES(CMD_BUF_SIZE));
	if (!entry->cmd_buf_base)
		return -ENOMEM;

	mmio_write64(entry->mmio_base + AMD_CMD_BUF_BASE_REG,
		     paging_hvirt2phys(entry->cmd_buf_base) |
		     ((u64)CMD_BUF_LEN_EXPONENT << BUF_LEN_EXPONENT_SHIFT));

	entry->cmd_tail_ptr = 0;

	/* Allocate and configure event log */
	entry->evt_log_base = page_alloc(&mem_pool, PAGES(EVT_LOG_SIZE));
	if (!entry->evt_log_base)
		return -ENOMEM;

	mmio_write64(entry->mmio_base + AMD_EVT_LOG_BASE_REG,
		     paging_hvirt2phys(entry->evt_log_base) |
		     ((u64)EVT_LOG_LEN_EXPONENT << BUF_LEN_EXPONENT_SHIFT));

	return 0;
}

static void amd_iommu_enable_command_processing(struct amd_iommu *iommu)
{
	u64 ctrl_reg;

	ctrl_reg = mmio_read64(iommu->mmio_base + AMD_CONTROL_REG);
	ctrl_reg |= AMD_CONTROL_IOMMU_EN | AMD_CONTROL_CMD_BUF_EN |
		AMD_CONTROL_EVT_LOG_EN | AMD_CONTROL_EVT_INT_EN;
	mmio_write64(iommu->mmio_base + AMD_CONTROL_REG, ctrl_reg);
}

int iommu_init(void)
{
	struct jailhouse_iommu *iommu;
	struct amd_iommu *entry;
	unsigned int n;
	int err;

	n = iommu_get_remap_table_order();
	if (n >= MAX_INT_REMAP_TABLE_ORDER)
		return trace_error(-EINVAL);

	int_remap_table_size_log2 = n;

	iommu = &system_config->platform_info.x86.iommu_units[0];
	for (n = 0; iommu->base && n < iommu_count_units(); iommu++, n++) {
		entry = &iommu_units[iommu_units_count];

		/* Protect against accidental VT-d configs. */
		if (!iommu->amd_bdf)
			return trace_error(-EINVAL);

		/* Protect against old configs. */
		if (!iommu->amd_max_dev_id)
			return trace_error(-EINVAL);

		entry->idx = n;
		entry->max_dev_id = iommu->amd_max_dev_id;
		if (entry->max_dev_id > max_device_id)
			max_device_id = entry->max_dev_id;

		printk("AMD IOMMU @0x%lx/0x%x\n", iommu->base, iommu->size);

		/* Initialize PCI registers and MMIO space */
		err = amd_iommu_init_pci(entry, iommu);
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

	n = (max_device_id + 1) * sizeof(struct remap_region);
	device_remap_regions = alloc_zero_pages(n);
	if (!device_remap_regions)
		return -ENOMEM;

	return iommu_cell_init(&root_cell);
}

#define IRTE_ALLOCATED	(~1U)

/*
 * XXX: this is modelled after vtd_reserve_int_remap_region().
 * Maybe consolidate both.
 */
static int amd_iommu_find_remap_region(struct cell *cell, u8 count)
{
	union irte *remap_table = cell->arch.amd_iommu.int_remap_table;
	int n, start = -E2BIG;

	for (n = 0; n < system_config->interrupt_limit; n++) {
		if (remap_table[n].raw32) {
			start = -E2BIG;
			continue;
		}
		if (start < 0)
			start = n;
		if (n + 1 == start + count) {
			return start;
		}
	}
	return trace_error(-E2BIG);
}

static int amd_iommu_reserve_remap_region(struct cell *cell, u16 device_id,
		                          u8 count, u8 iommu)
{
	union irte *remap_table = cell->arch.amd_iommu.int_remap_table;
	struct remap_region *region;
	int base_index, n;

	if (device_id > max_device_id)
		return trace_error(-ERANGE);

	region = &device_remap_regions[device_id];

	if (count == 0 || region->base_index & REGION_ALLOCATED)
		return 0; /* Nothing to do */

	base_index = amd_iommu_find_remap_region(cell, count);
	if (base_index < 0)
		return base_index;

	printk("Reserving %u interrupt(s) for device %04x "
			"at index %d\n", count, device_id, base_index);
	region->base_index = (u16)base_index | REGION_ALLOCATED;
	region->count = count;
	region->iommu = iommu;

	for (n = base_index; n < base_index + count; n++)
		remap_table[n].raw32 = IRTE_ALLOCATED;

	return 0;
}

static void amd_iommu_free_remap_region(struct cell *cell, u16 device_id)
{
	union irte *remap_table = cell->arch.amd_iommu.int_remap_table;
	struct remap_region *region;
	int base_index, n;

	if (device_id > max_device_id)
		return;

	region = &device_remap_regions[device_id];
	base_index = region->base_index & ~REGION_ALLOCATED;
	if (base_index == region->base_index)
		return; /* Not allocated */

	for (n = base_index; n < base_index + region->count; n++)
		remap_table[n].raw32 = 0;
	region->base_index &= ~REGION_ALLOCATED;

	return;
}

static int amd_iommu_add_ioapic(struct cell *cell,
			        const struct jailhouse_irqchip *irqchip);

#define IRQCHIP_DEVICE_ID(x)	((x)->id & 0xffff)
#define IRQCHIP_IOMMU_ID(x)	(((x)->id >> 16) & 0xffff)

static struct dev_table_entry *get_dev_table_entry(struct amd_iommu *iommu,
						   u16 bdf, bool allocate);

static int amd_iommu_cell_init_ioapic(struct cell *cell)
{
	const struct jailhouse_irqchip *irqchip =
		jailhouse_cell_irqchips(cell->config);
	unsigned int n;
	int err;

	for (n = 0; n < cell->config->num_irqchips; n++, irqchip++) {
		err = amd_iommu_reserve_remap_region(
				cell, IRQCHIP_DEVICE_ID(irqchip),
				IOAPIC_NUM_PINS, IRQCHIP_IOMMU_ID(irqchip));
		if (err)
			return err;

		err = amd_iommu_add_ioapic(cell, irqchip);
		if (err)
			return err;
	}

	return 0;
}

int iommu_cell_init(struct cell *cell)
{
	unsigned int size = 1 << int_remap_table_size_log2;
	int err;

	// HACK for QEMU
	if (iommu_units_count == 0)
		return 0;

	if (cell->id > 0xffff)
		return trace_error(-ERANGE);

	cell->arch.amd_iommu.int_remap_table = alloc_zero_pages(size);
	if (!cell->arch.amd_iommu.int_remap_table)
		return trace_error(-ENOMEM);

	err = amd_iommu_cell_init_ioapic(cell);
	if (err) {
		iommu_cell_exit(cell);
		return trace_error(err);
	}

	return 0;
}

static void amd_iommu_completion_wait(struct amd_iommu *iommu);

static void amd_iommu_submit_command(struct amd_iommu *iommu,
				     union buf_entry *cmd, bool draining)
{
	u32 head, next_tail, bytes_free;
	unsigned char *cur_ptr;

	head = mmio_read64(iommu->mmio_base + AMD_CMD_BUF_HEAD_REG);
	next_tail = (iommu->cmd_tail_ptr + sizeof(*cmd)) % CMD_BUF_SIZE;
	bytes_free = (head - next_tail) % CMD_BUF_SIZE;

	/* Leave space for COMPLETION_WAIT that drains the buffer. */
	if (bytes_free < (2 * sizeof(*cmd)) && !draining)
		/* Drain the buffer */
		amd_iommu_completion_wait(iommu);

	cur_ptr = &iommu->cmd_buf_base[iommu->cmd_tail_ptr];
	memcpy(cur_ptr, cmd, sizeof(*cmd));

	/* Just to be sure. */
	arch_paging_flush_cpu_caches(cur_ptr, sizeof(*cmd));

	iommu->cmd_tail_ptr =
		(iommu->cmd_tail_ptr + sizeof(*cmd)) % CMD_BUF_SIZE;
}

u64 amd_iommu_get_memory_region_flags(const struct jailhouse_memory *mem)
{
	unsigned long flags = AMD_IOMMU_PTE_P;

	if (!(mem->flags & JAILHOUSE_MEM_DMA))
		return 0;

	if (mem->flags & JAILHOUSE_MEM_READ)
		flags |= AMD_IOMMU_PTE_IR;
	if (mem->flags & JAILHOUSE_MEM_WRITE)
		flags |= AMD_IOMMU_PTE_IW;

	return flags;
}

int iommu_map_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	/*
	 * Check that the address is not outside the scope of the page tables.
	 * With 4 levels, we only support 48 address bits.
	 */
	if (mem->virt_start & BIT_MASK(63, 48))
		return trace_error(-E2BIG);

	/* vcpu_map_memory_region already did the actual work. */
	return 0;
}

int iommu_unmap_memory_region(struct cell *cell,
			      const struct jailhouse_memory *mem)
{
	/* vcpu_map_memory_region already did the actual work. */
	return 0;
}

static void amd_iommu_inv_dte(struct amd_iommu *iommu, u16 device_id)
{
	union buf_entry invalidate_dte = {{ 0 }};

	invalidate_dte.raw32[0] = device_id;
	invalidate_dte.type = CMD_INV_DEVTAB_ENTRY;

	amd_iommu_submit_command(iommu, &invalidate_dte, false);
}

static void amd_iommu_inv_int_table(struct amd_iommu *iommu, u16 device_id)
{
	union buf_entry invalidate_int_table = {{ 0 }};

	invalidate_int_table.raw32[0] = device_id;
	invalidate_int_table.type = CMD_INV_INT_TABLE;

	amd_iommu_submit_command(iommu, &invalidate_int_table, false);
}

static struct dev_table_entry *get_dev_table_entry(struct amd_iommu *iommu,
						   u16 bdf, bool allocate)
{
	struct dev_table_entry *devtable_seg;
	u16 seg_mask, first_bdf, seg_entries;
	u8 seg_idx, seg_shift, n_segs;
	u64 reg_base, reg_val;
	unsigned int n;
	u32 seg_size;

	if (!iommu->dev_tbl_seg_sup) {
		seg_mask = 0;
		seg_idx = 0;
		seg_size = iommu->max_dev_id * sizeof(*devtable_seg);
	} else {
		seg_shift = BITS_PER_SHORT - iommu->dev_tbl_seg_sup;
		seg_mask = ~((1 << seg_shift) - 1);
		seg_idx = (seg_mask & bdf) >> seg_shift;

		n_segs = 1 << iommu->dev_tbl_seg_sup;
		seg_entries = 0xffff / n_segs;

		first_bdf = seg_entries * seg_idx;
		if (iommu->max_dev_id < first_bdf + seg_entries)
			seg_entries = iommu->max_dev_id - first_bdf + 1;

		seg_size = seg_entries * sizeof(*devtable_seg);
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

		/*
		 * Initialize all entries to paging mode 0, IR & IW cleared so
		 * that DMA requests are blocked.
		 */
		for (n = 0; n < seg_size / sizeof(struct dev_table_entry); n++)
			devtable_seg[n].raw64[0] =
				DTE_VALID | DTE_TRANSLATION_VALID;

		if (!seg_idx)
			reg_base = AMD_DEV_TABLE_BASE_REG;
		else
			reg_base = AMD_DEV_TABLE_SEG1_REG + (seg_idx - 1) * 8;

		/* Size in Kbytes = (m + 1) * 4, see Sect 3.3.6 */
		reg_val = paging_hvirt2phys(devtable_seg) |
			(seg_size / PAGE_SIZE - 1);
		mmio_write64(iommu->mmio_base + reg_base, reg_val);
	}

	return &devtable_seg[bdf & ~seg_mask];
}

static u16 amd_iommu_get_device_id(const struct jailhouse_pci_device *info)
{
	return (info->flags & JAILHOUSE_PCI_FLAGS_ALIAS) ?
		info->alias_bdf : info->bdf;
}

static int amd_iommu_add_ioapic(struct cell *cell,
				const struct jailhouse_irqchip *irqchip)
{
	struct dev_table_entry *dte = NULL;
	union irte *int_table_root;
	struct amd_iommu *iommu;
	u16 device_id;
	u8 iommu_id;

	device_id = IRQCHIP_DEVICE_ID(irqchip);
	iommu_id = IRQCHIP_IOMMU_ID(irqchip);

	iommu = &iommu_units[iommu_id];

	dte = get_dev_table_entry(iommu, device_id, true);
	if (!dte)
		return -ENOMEM;

	memset(dte, 0, sizeof(*dte));

	int_table_root = cell->arch.amd_iommu.int_remap_table;

	dte->raw64[2] = DTE_INTCTL_REMAP | paging_hvirt2phys(int_table_root) |
		(int_remap_table_size_log2 << DTE_INT_TAB_LEN_SHIFT) | DTE_IV;

	/* Flush caches, just to be sure. */
	arch_paging_flush_cpu_caches(dte, sizeof(*dte));

	amd_iommu_inv_dte(iommu, device_id);

	return 0;
}

int iommu_add_pci_device(struct cell *cell, struct pci_device *device)
{
	unsigned int max_vectors = MAX(device->info->num_msi_vectors,
				       device->info->num_msix_vectors);
	struct dev_table_entry *dte = NULL;
	union irte *int_table_root;
	struct amd_iommu *iommu;
	u16 bdf;
	int err;

	// HACK for QEMU
	if (iommu_units_count == 0)
		return 0;

	if (device->info->type == JAILHOUSE_PCI_TYPE_IVSHMEM)
		return 0;

	if (device->info->iommu >= JAILHOUSE_MAX_IOMMU_UNITS)
		return trace_error(-ERANGE);

	iommu = &iommu_units[device->info->iommu];
	bdf = amd_iommu_get_device_id(device->info);

	err = amd_iommu_reserve_remap_region(cell, bdf, max_vectors,
			device->info->iommu);
	if (err)
		return err;

	dte = get_dev_table_entry(iommu, bdf, true);
	if (!dte) {
		err = -ENOMEM;
		goto out_err;
	}

	memset(dte, 0, sizeof(*dte));

	/* DomainID */
	dte->raw64[1] = cell->id & 0xffff;

	/* Translation information */
	dte->raw64[0] = DTE_IR | DTE_IW |
		paging_hvirt2phys(cell->arch.svm.npt_iommu_structs.root_table) |
		DTE_PAGING_MODE_4_LEVEL | DTE_TRANSLATION_VALID | DTE_VALID;

	int_table_root = cell->arch.amd_iommu.int_remap_table;

	dte->raw64[2] = DTE_INTCTL_REMAP | paging_hvirt2phys(int_table_root) |
		(int_remap_table_size_log2 << DTE_INT_TAB_LEN_SHIFT) | DTE_IV;

	/* Flush caches, just to be sure. */
	arch_paging_flush_cpu_caches(dte, sizeof(*dte));

	amd_iommu_inv_dte(iommu, bdf);

	return 0;

out_err:
	amd_iommu_free_remap_region(cell, bdf);
	return err;
}

static void amd_iommu_remove_ioapic(struct cell *cell,
		                    const struct jailhouse_irqchip *irqchip)
{
	struct dev_table_entry *dte = NULL;
	struct amd_iommu *iommu;
	u16 device_id;
	u8 iommu_id;

	device_id = IRQCHIP_DEVICE_ID(irqchip);
	iommu_id = IRQCHIP_IOMMU_ID(irqchip);

	iommu = &iommu_units[iommu_id];
	dte = get_dev_table_entry(iommu, device_id, false);
	if (!dte)
		return;

	/* Target-abort interrupt messages we may receive. */
	dte->raw64[2] = DTE_INTCTL_ABORT | DTE_IV;

	/* Flush caches, just to be sure. */
	arch_paging_flush_cpu_caches(dte, sizeof(*dte));

	amd_iommu_free_remap_region(cell, device_id);

	amd_iommu_inv_dte(iommu, device_id);
}

void iommu_remove_pci_device(struct pci_device *device)
{
	struct dev_table_entry *dte = NULL;
	struct amd_iommu *iommu;
	u16 bdf;

	// HACK for QEMU
	if (iommu_units_count == 0)
		return;

	if (device->info->type == JAILHOUSE_PCI_TYPE_IVSHMEM)
		return;

	iommu = &iommu_units[device->info->iommu];
	bdf = amd_iommu_get_device_id(device->info);

	dte = get_dev_table_entry(iommu, bdf, false);
	if (!dte)
		return;

	/*
	 * Set Mode to 0 (translation disabled) and clear IR and IW to block
	 * DMA requests until the entry is reprogrammed for its new owner.
	 */
	dte->raw64[0] = DTE_VALID | DTE_TRANSLATION_VALID;

	/* Target-abort interrupt messages we may receive. */
	dte->raw64[2] = DTE_INTCTL_ABORT | DTE_IV;

	/* Free the interrupt remapping region */
	amd_iommu_free_remap_region(device->cell, bdf);

	/* Flush caches, just to be sure. */
	arch_paging_flush_cpu_caches(dte, sizeof(*dte));

	amd_iommu_inv_dte(iommu, bdf);
}

void iommu_cell_exit(struct cell *cell)
{
	const struct jailhouse_irqchip *irqchip =
		jailhouse_cell_irqchips(cell->config);
	unsigned int n, size;

	size = 1 << int_remap_table_size_log2;

	page_free(&mem_pool, cell->arch.amd_iommu.int_remap_table,
			PAGES(size));

	for (n = 0; n < cell->config->num_irqchips; n++, irqchip++)
		amd_iommu_remove_ioapic(cell, irqchip);
}

static void wait_for_zero(volatile u64 *sem, unsigned long mask)
{
	while (*sem & mask)
		cpu_relax();
}

static void amd_iommu_invalidate_pages(struct amd_iommu *iommu,
				       u16 domain_id)
{
	union buf_entry invalidate_pages = {{ 0 }};

	/*
	 * Flush everything, including PDEs, in whole address range, i.e.
	 * 0x7ffffffffffff000 with S bit (see Sect. 2.2.3).
	 */
	invalidate_pages.raw32[1] = domain_id;
	invalidate_pages.raw32[2] = 0xfffff000 | CMD_INV_IOMMU_PAGES_SIZE |
		CMD_INV_IOMMU_PAGES_PDE;
	invalidate_pages.raw32[3] = 0x7fffffff;
	invalidate_pages.type = CMD_INV_IOMMU_PAGES;

	amd_iommu_submit_command(iommu, &invalidate_pages, false);
}

static void amd_iommu_completion_wait(struct amd_iommu *iommu)
{
	union buf_entry completion_wait = {{ 0 }};
	volatile u64 sem = 1;
	long addr;

	addr = paging_hvirt2phys(&sem);

	completion_wait.raw32[0] = (addr & BIT_MASK(31, 3)) |
		CMD_COMPL_WAIT_STORE;
	completion_wait.raw32[1] = (addr & BIT_MASK(51, 32)) >> 32;
	completion_wait.type = CMD_COMPL_WAIT;

	amd_iommu_submit_command(iommu, &completion_wait, true);
	mmio_write64(iommu->mmio_base + AMD_CMD_BUF_TAIL_REG,
		     iommu->cmd_tail_ptr);

	wait_for_zero(&sem, -1);
}

static void amd_iommu_init_fault_nmi(void)
{
	union x86_msi_vector msi_vec = {{ 0 }};
	union pci_msi_registers msi_reg;
	struct per_cpu *cpu_data;
	struct amd_iommu *iommu;
	int n;

	cpu_data = iommu_select_fault_reporting_cpu();

	/* Send NMI to fault reporting CPU */
	msi_vec.native.address = MSI_ADDRESS_VALUE;
	msi_vec.native.destination = cpu_data->apic_id;

	msi_reg.msg32.enable = 1;
	msi_reg.msg64.address = msi_vec.raw.address;
	msi_reg.msg64.data = MSI_DM_NMI;

	for_each_iommu(iommu) {
		struct jailhouse_iommu *cfg =
		    &system_config->platform_info.x86.iommu_units[iommu->idx];

		/* Disable MSI during interrupt reprogramming. */
		pci_write_config(cfg->amd_bdf, cfg->amd_msi_cap + 2 , 0, 2);

		/*
		 * Write new MSI capability block, re-enabling interrupts with
		 * the last word.
		 */
		for (n = 3; n >= 0; n--)
			pci_write_config(cfg->amd_bdf, cfg->amd_msi_cap + 4 * n,
					 msi_reg.raw[n], 4);
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

	// HACK for QEMU
	if (iommu_units_count == 0)
		return;

	/* Ensure we'll get NMI on completion, or if anything goes wrong. */
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

	/* This is never called */
	return dummy;
}

int iommu_map_interrupt(struct cell *cell, u16 device_id, unsigned int vector,
			struct apic_irq_message irq_msg)
{
	union irte *remap_table = cell->arch.amd_iommu.int_remap_table;
	struct remap_region *remap_region;
	struct amd_iommu *iommu;
	union irte *irte;
	u16 base_index;
	int err;

	// HACK for QEMU
	if (iommu_units_count == 0)
		return -ENOSYS;

	remap_region = &device_remap_regions[device_id];
	base_index = remap_region->base_index & ~REGION_ALLOCATED;
	if (base_index == remap_region->base_index)
		return -EINVAL; /* Not allocated */

	if (vector >= system_config->interrupt_limit ||
	    base_index >= system_config->interrupt_limit - vector)
		return -ERANGE;

	irte = &remap_table[base_index + vector];
	iommu = &iommu_units[remap_region->iommu];

	err = iommu_validate_irq_msg(cell, &irq_msg);
	if (err)
		return err;

	irte->raw32 = 0;
	/* XXX: Level-triggered vs edge-triggered? */
	irte->vector = irq_msg.vector;
	irte->destination = irq_msg.destination;
	irte->guest_mode = 0; /* Always off unless we enable AVIC */
	irte->destination_mode = irq_msg.dest_logical;
	irte->int_type = irq_msg.delivery_mode;
	irte->valid = 1;

	/* Flush caches, just to be sure. */
	arch_paging_flush_cpu_caches(irte, sizeof(*irte));

	amd_iommu_inv_int_table(iommu, device_id);
	amd_iommu_completion_wait(iommu);

	return base_index + vector;
}

void iommu_shutdown(void)
{
	struct amd_iommu *iommu;
	u64 ctrl_reg;

	for_each_iommu(iommu) {
		/* Disable the IOMMU */
		ctrl_reg = mmio_read64(iommu->mmio_base + AMD_CONTROL_REG);
		ctrl_reg &= ~(AMD_CONTROL_IOMMU_EN | AMD_CONTROL_CMD_BUF_EN |
			AMD_CONTROL_EVT_LOG_EN | AMD_CONTROL_EVT_INT_EN);
		mmio_write64(iommu->mmio_base + AMD_CONTROL_REG, ctrl_reg);
	}

	/* No need to free anything as we know Jailhouse is shutting down */
}

static void amd_iommu_print_event(struct amd_iommu *iommu,
				  union buf_entry *entry)
{
	printk("AMD IOMMU %d reported event\n", iommu->idx);
	printk(" EventCode: %lx, Operand 1: %lx, Operand 2: %lx\n",
	       entry->type, entry->raw64[0], entry->raw64[1]);
	switch (entry->type) {
		case EVENT_TYPE_ILL_DEV_TAB_ENTRY...EVENT_TYPE_PAGE_TAB_HW_ERR:
		case EVENT_TYPE_IOTLB_INV_TIMEOUT...EVENT_TYPE_INV_PPR_REQ:
			printk(" DeviceId (bus:dev.func): %02x:%02x.%x\n",
			       PCI_BDF_PARAMS(entry->raw32[0] & 0xffff));
			break;
		case EVENT_TYPE_ILL_CMD_ERR:
		case EVENT_TYPE_CMD_HW_ERR:
			panic_printk("FATAL: IOMMU %d command error\n");
			panic_stop();
	}
}

static void amd_iommu_restart_event_log(struct amd_iommu *iommu)
{
	void *base = iommu->mmio_base;

	wait_for_zero(base + AMD_STATUS_REG, AMD_STATUS_EVT_LOG_RUN);

	mmio_write64_field(base + AMD_CONTROL_REG, AMD_CONTROL_EVT_LOG_EN, 0);

	/* Simply start from the scratch */
	mmio_write64(base + AMD_EVT_LOG_HEAD_REG, 0);
	mmio_write64(base + AMD_EVT_LOG_TAIL_REG, 0);

	/* Clear EventOverflow (RW1C) */
	mmio_write64_field(base + AMD_STATUS_REG, AMD_STATUS_EVT_OVERFLOW, 1);

	/* Bring logging back */
	mmio_write64_field(base + AMD_CONTROL_REG, AMD_CONTROL_EVT_LOG_EN, 1);
}

static void amd_iommu_poll_events(struct amd_iommu *iommu)
{
	union buf_entry *evt;
	u32 head, tail;
	u64 status;

	status = mmio_read64(iommu->mmio_base + AMD_STATUS_REG);

	if (status & AMD_STATUS_EVT_OVERFLOW) {
		printk("IOMMU %d: Event Log overflow occurred, "
		       "some events were lost!\n", iommu->idx);
		amd_iommu_restart_event_log(iommu);
	}

	while (status & AMD_STATUS_EVT_LOG_INT) {
		/* Clear EventLogInt (RW1C) */
		mmio_write64_field(iommu->mmio_base + AMD_STATUS_REG,
				   AMD_STATUS_EVT_LOG_INT, 1);

		head = mmio_read32(iommu->mmio_base + AMD_EVT_LOG_HEAD_REG);
		tail = mmio_read32(iommu->mmio_base + AMD_EVT_LOG_TAIL_REG);

		while (head != tail) {
			evt = (union buf_entry *)(iommu->evt_log_base + head);
			amd_iommu_print_event(iommu, evt);
			head = (head + sizeof(*evt)) % EVT_LOG_SIZE;
		}

		mmio_write32(iommu->evt_log_base + AMD_EVT_LOG_HEAD_REG, head);

		/* Re-read status to catch new events, as Linux does */
		status = mmio_read64(iommu->mmio_base + AMD_STATUS_REG);
	}
}

static void amd_iommu_handle_hardware_event(struct amd_iommu *iommu)
{
	union buf_entry hev_entry;
	u64 hev;

	hev = mmio_read64(iommu->mmio_base + AMD_HEV_STATUS_REG);

	/* Check if hardware event is present and print it */
	if (hev & AMD_HEV_VALID) {
		if (hev & AMD_HEV_OVERFLOW)
			printk("IOMMU %d: Hardware Event Overflow occurred, "
			       "some events were lost!\n", iommu->idx);
		hev_entry.raw64[0] =
			mmio_read64(iommu->mmio_base + AMD_HEV_UPPER_REG);
		hev_entry.raw64[1] =
			mmio_read64(iommu->mmio_base + AMD_HEV_LOWER_REG);

		amd_iommu_print_event(iommu, &hev_entry);

		/* Clear Hardware Event */
		mmio_write64(iommu->mmio_base + AMD_HEV_STATUS_REG, 0);
	}
}

void iommu_check_pending_faults(void)
{
	struct amd_iommu *iommu;

	if (this_cpu_data()->cpu_id != fault_reporting_cpu_id)
		return;

	for_each_iommu(iommu) {
		if (iommu->he_supported)
			amd_iommu_handle_hardware_event(iommu);
		amd_iommu_poll_events(iommu);
	}
}
