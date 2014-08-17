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

#include <jailhouse/entry.h>
#include <jailhouse/paging.h>
#include <jailhouse/processor.h>
#include <jailhouse/printk.h>
#include <jailhouse/string.h>
#include <jailhouse/control.h>
#include <jailhouse/hypercall.h>
#include <asm/apic.h>
#include <asm/control.h>
#include <asm/io.h>
#include <asm/ioapic.h>
#include <asm/iommu.h>
#include <asm/pci.h>
#include <asm/vcpu.h>
#include <asm/vmcs.h>
#include <asm/vmx.h>
#include <asm/vtd.h>

static const struct segment invalid_seg = {
	.access_rights = 0x10000
};

/* bit cleared: direct access allowed */
static u8 __attribute__((aligned(PAGE_SIZE))) msr_bitmap[][0x2000/8] = {
	[ VMX_MSR_BMP_0000_READ ] = {
		[      0/8 ...  0x7ff/8 ] = 0,
		[  0x800/8 ...  0x807/8 ] = 0x0c, /* 0x802, 0x803 */
		[  0x808/8 ...  0x80f/8 ] = 0xa5, /* 0x808, 0x80a, 0x80d, 0x80f */
		[  0x810/8 ...  0x817/8 ] = 0xff, /* 0x810 - 0x817 */
		[  0x818/8 ...  0x81f/8 ] = 0xff, /* 0x818 - 0x81f */
		[  0x820/8 ...  0x827/8 ] = 0xff, /* 0x820 - 0x827 */
		[  0x828/8 ...  0x82f/8 ] = 0x81, /* 0x828, 0x82f */
		[  0x830/8 ...  0x837/8 ] = 0xfd, /* 0x830, 0x832 - 0x837 */
		[  0x838/8 ...  0x83f/8 ] = 0x43, /* 0x838, 0x839, 0x83e */
		[  0x840/8 ... 0x1fff/8 ] = 0,
	},
	[ VMX_MSR_BMP_C000_READ ] = {
		[      0/8 ... 0x1fff/8 ] = 0,
	},
	[ VMX_MSR_BMP_0000_WRITE ] = {
		[      0/8 ...   0x17/8 ] = 0,
		[   0x18/8 ...   0x1f/8 ] = 0x08, /* 0x01b */
		[   0x20/8 ...  0x7ff/8 ] = 0,
		[  0x808/8 ...  0x80f/8 ] = 0x89, /* 0x808, 0x80b, 0x80f */
		[  0x810/8 ...  0x827/8 ] = 0,
		[  0x828/8 ...  0x82f/8 ] = 0x81, /* 0x828, 0x82f */
		[  0x830/8 ...  0x837/8 ] = 0xfd, /* 0x830, 0x832 - 0x837 */
		[  0x838/8 ...  0x83f/8 ] = 0xc1, /* 0x838, 0x83e, 0x83f */
		[  0x840/8 ... 0x1fff/8 ] = 0,
	},
	[ VMX_MSR_BMP_C000_WRITE ] = {
		[      0/8 ... 0x1fff/8 ] = 0,
	},
};
static u8 __attribute__((aligned(PAGE_SIZE))) apic_access_page[PAGE_SIZE];
static struct paging ept_paging[EPT_PAGE_DIR_LEVELS];
static u32 enable_rdtscp;

static bool vmxon(struct per_cpu *cpu_data)
{
	unsigned long vmxon_addr;
	u8 ok;

	vmxon_addr = page_map_hvirt2phys(&cpu_data->vmxon_region);
	asm volatile(
		"vmxon (%1)\n\t"
		"seta %0"
		: "=rm" (ok)
		: "r" (&vmxon_addr), "m" (vmxon_addr)
		: "memory", "cc");
	return ok;
}

static bool vmcs_clear(struct per_cpu *cpu_data)
{
	unsigned long vmcs_addr = page_map_hvirt2phys(&cpu_data->vmcs);
	u8 ok;

	asm volatile(
		"vmclear (%1)\n\t"
		"seta %0"
		: "=qm" (ok)
		: "r" (&vmcs_addr), "m" (vmcs_addr)
		: "memory", "cc");
	return ok;
}

static bool vmcs_load(struct per_cpu *cpu_data)
{
	unsigned long vmcs_addr = page_map_hvirt2phys(&cpu_data->vmcs);
	u8 ok;

	asm volatile(
		"vmptrld (%1)\n\t"
		"seta %0"
		: "=qm" (ok)
		: "r" (&vmcs_addr), "m" (vmcs_addr)
		: "memory", "cc");
	return ok;
}

static inline unsigned long vmcs_read64(unsigned long field)
{
	unsigned long value;

	asm volatile("vmread %1,%0" : "=r" (value) : "r" (field) : "cc");
	return value;
}

static inline u16 vmcs_read16(unsigned long field)
{
	return vmcs_read64(field);
}

static inline u32 vmcs_read32(unsigned long field)
{
	return vmcs_read64(field);
}

static bool vmcs_write64(unsigned long field, unsigned long val)
{
	u8 ok;

	asm volatile(
		"vmwrite %1,%2\n\t"
		"setnz %0"
		: "=qm" (ok)
		: "r" (val), "r" (field)
		: "cc");
	if (!ok)
		printk("FATAL: vmwrite %08lx failed, error %d, caller %p\n",
		       field, vmcs_read32(VM_INSTRUCTION_ERROR),
		       __builtin_return_address(0));
	return ok;
}

static bool vmcs_write16(unsigned long field, u16 value)
{
	return vmcs_write64(field, value);
}

static bool vmcs_write32(unsigned long field, u32 value)
{
	return vmcs_write64(field, value);
}

static int vmx_check_features(void)
{
	unsigned long vmx_proc_ctrl, vmx_proc_ctrl2, ept_cap;
	unsigned long vmx_pin_ctrl, vmx_basic;

	if (!(cpuid_ecx(1) & X86_FEATURE_VMX))
		return -ENODEV;

	vmx_basic = read_msr(MSR_IA32_VMX_BASIC);

	/* require VMCS size <= PAGE_SIZE,
	 * VMCS memory access type == write back and
	 * availability of TRUE_*_CTLS */
	if (((vmx_basic >> 32) & 0x1fff) > PAGE_SIZE ||
	    ((vmx_basic >> 50) & 0xf) != EPT_TYPE_WRITEBACK ||
	    !(vmx_basic & (1UL << 55)))
		return -EIO;

	/* require NMI exiting and preemption timer support */
	vmx_pin_ctrl = read_msr(MSR_IA32_VMX_PINBASED_CTLS) >> 32;
	if (!(vmx_pin_ctrl & PIN_BASED_NMI_EXITING) ||
	    !(vmx_pin_ctrl & PIN_BASED_VMX_PREEMPTION_TIMER))
		return -EIO;

	/* require I/O and MSR bitmap as well as secondary controls support */
	vmx_proc_ctrl = read_msr(MSR_IA32_VMX_PROCBASED_CTLS) >> 32;
	if (!(vmx_proc_ctrl & CPU_BASED_USE_IO_BITMAPS) ||
	    !(vmx_proc_ctrl & CPU_BASED_USE_MSR_BITMAPS) ||
	    !(vmx_proc_ctrl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS))
		return -EIO;

	/* require disabling of CR3 access interception */
	vmx_proc_ctrl = read_msr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
	if (vmx_proc_ctrl &
	    (CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING))
		return -EIO;

	/* require APIC access, EPT and unrestricted guest mode support */
	vmx_proc_ctrl2 = read_msr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32;
	ept_cap = read_msr(MSR_IA32_VMX_EPT_VPID_CAP);
	if (!(vmx_proc_ctrl2 & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES) ||
	    !(vmx_proc_ctrl2 & SECONDARY_EXEC_ENABLE_EPT) ||
	    (ept_cap & EPT_MANDATORY_FEATURES) != EPT_MANDATORY_FEATURES ||
	    !(ept_cap & (EPT_INVEPT_SINGLE | EPT_INVEPT_GLOBAL)) ||
	    !(vmx_proc_ctrl2 & SECONDARY_EXEC_UNRESTRICTED_GUEST))
		return -EIO;

	/* require RDTSCP if present in CPUID */
	if (cpuid_edx(0x80000001) & X86_FEATURE_RDTSCP) {
		enable_rdtscp = SECONDARY_EXEC_RDTSCP;
		if (!(vmx_proc_ctrl2 & SECONDARY_EXEC_RDTSCP))
			return -EIO;
	}

	/* require activity state HLT */
	if (!(read_msr(MSR_IA32_VMX_MISC) & VMX_MISC_ACTIVITY_HLT))
		return -EIO;

	return 0;
}

static void ept_set_next_pt(pt_entry_t pte, unsigned long next_pt)
{
	*pte = (next_pt & 0x000ffffffffff000UL) | EPT_FLAG_READ |
		EPT_FLAG_WRITE | EPT_FLAG_EXECUTE;
}

int vcpu_vendor_init(void)
{
	unsigned int n;
	int err;

	err = vmx_check_features();
	if (err)
		return err;

	/* derive ept_paging from very similar x86_64_paging */
	memcpy(ept_paging, x86_64_paging, sizeof(ept_paging));
	for (n = 0; n < EPT_PAGE_DIR_LEVELS; n++)
		ept_paging[n].set_next_pt = ept_set_next_pt;
	if (!(read_msr(MSR_IA32_VMX_EPT_VPID_CAP) & EPT_1G_PAGES))
		ept_paging[1].page_size = 0;
	if (!(read_msr(MSR_IA32_VMX_EPT_VPID_CAP) & EPT_2M_PAGES))
		ept_paging[2].page_size = 0;

	if (using_x2apic) {
		/* allow direct x2APIC access except for ICR writes */
		memset(&msr_bitmap[VMX_MSR_BMP_0000_READ][MSR_X2APIC_BASE/8],
		       0, (MSR_X2APIC_END - MSR_X2APIC_BASE + 1)/8);
		memset(&msr_bitmap[VMX_MSR_BMP_0000_WRITE][MSR_X2APIC_BASE/8],
		       0, (MSR_X2APIC_END - MSR_X2APIC_BASE + 1)/8);
		msr_bitmap[VMX_MSR_BMP_0000_WRITE][MSR_X2APIC_ICR/8] = 0x01;
	}

	return vcpu_cell_init(&root_cell);
}

unsigned long arch_page_map_gphys2phys(struct per_cpu *cpu_data,
				       unsigned long gphys)
{
	return page_map_virt2phys(&cpu_data->cell->vmx.ept_structs, gphys);
}

int vcpu_vendor_cell_init(struct cell *cell)
{
	/* build root EPT of cell */
	cell->vmx.ept_structs.root_paging = ept_paging;
	cell->vmx.ept_structs.root_table = page_alloc(&mem_pool, 1);
	if (!cell->vmx.ept_structs.root_table)
		return -ENOMEM;

	return page_map_create(&cell->vmx.ept_structs,
			       page_map_hvirt2phys(apic_access_page),
			       PAGE_SIZE, XAPIC_BASE,
			       EPT_FLAG_READ|EPT_FLAG_WRITE|EPT_FLAG_WB_TYPE,
			       PAGE_MAP_NON_COHERENT);
}

int vcpu_map_memory_region(struct cell *cell,
			  const struct jailhouse_memory *mem)
{
	u64 phys_start = mem->phys_start;
	u32 flags = EPT_FLAG_WB_TYPE;

	if (mem->flags & JAILHOUSE_MEM_READ)
		flags |= EPT_FLAG_READ;
	if (mem->flags & JAILHOUSE_MEM_WRITE)
		flags |= EPT_FLAG_WRITE;
	if (mem->flags & JAILHOUSE_MEM_EXECUTE)
		flags |= EPT_FLAG_EXECUTE;
	if (mem->flags & JAILHOUSE_MEM_COMM_REGION)
		phys_start = page_map_hvirt2phys(&cell->comm_page);

	return page_map_create(&cell->vmx.ept_structs, phys_start, mem->size,
			       mem->virt_start, flags, PAGE_MAP_NON_COHERENT);
}

int vcpu_unmap_memory_region(struct cell *cell,
			    const struct jailhouse_memory *mem)
{
	return page_map_destroy(&cell->vmx.ept_structs, mem->virt_start,
				mem->size, PAGE_MAP_NON_COHERENT);
}

void vcpu_vendor_cell_exit(struct cell *cell)
{
	page_map_destroy(&cell->vmx.ept_structs, XAPIC_BASE, PAGE_SIZE,
			 PAGE_MAP_NON_COHERENT);
	page_free(&mem_pool, cell->vmx.ept_structs.root_table, 1);
}

static void vmx_invept(void)
{
	unsigned long ept_cap = read_msr(MSR_IA32_VMX_EPT_VPID_CAP);
	struct {
		u64 eptp;
		u64 reserved;
	} descriptor;
	u64 type;
	u8 ok;

	descriptor.reserved = 0;
	if (ept_cap & EPT_INVEPT_SINGLE) {
		type = VMX_INVEPT_SINGLE;
		descriptor.eptp = vmcs_read64(EPT_POINTER);
	} else {
		type = VMX_INVEPT_GLOBAL;
		descriptor.eptp = 0;
	}
	asm volatile(
		"invept (%1),%2\n\t"
		"seta %0\n\t"
		: "=qm" (ok)
		: "r" (&descriptor), "r" (type)
		: "memory", "cc");

	if (!ok) {
		panic_printk("FATAL: invept failed, error %d\n",
			     vmcs_read32(VM_INSTRUCTION_ERROR));
		panic_stop(NULL);
	}
}

/* To make prototype compatible with svm_tlb_flush() */
void vcpu_tlb_flush(struct per_cpu *cpu_data __attribute__((unused)))
{
	vmx_invept();
}

static bool vmx_set_guest_cr(int cr, unsigned long val)
{
	unsigned long fixed0, fixed1, required1;
	bool ok = true;

	fixed0 = read_msr(cr ? MSR_IA32_VMX_CR4_FIXED0
			     : MSR_IA32_VMX_CR0_FIXED0);
	fixed1 = read_msr(cr ? MSR_IA32_VMX_CR4_FIXED1
			     : MSR_IA32_VMX_CR0_FIXED1);
	required1 = fixed0 & fixed1;
	if (cr == 0) {
		fixed1 &= ~(X86_CR0_NW | X86_CR0_CD);
		required1 &= ~(X86_CR0_PE | X86_CR0_PG);
		required1 |= X86_CR0_ET;
	} else {
		/* keeps the hypervisor visible */
		val |= X86_CR4_VMXE;
	}
	ok &= vmcs_write64(cr ? GUEST_CR4 : GUEST_CR0,
			   (val & fixed1) | required1);
	ok &= vmcs_write64(cr ? CR4_READ_SHADOW : CR0_READ_SHADOW, val);
	ok &= vmcs_write64(cr ? CR4_GUEST_HOST_MASK : CR0_GUEST_HOST_MASK,
			   required1 | ~fixed1);

	return ok;
}

static bool vcpu_set_cell_config(struct cell *cell)
{
	u8 *io_bitmap;
	bool ok = true;

	io_bitmap = cell->vmx.io_bitmap;
	ok &= vmcs_write64(IO_BITMAP_A, page_map_hvirt2phys(io_bitmap));
	ok &= vmcs_write64(IO_BITMAP_B,
			   page_map_hvirt2phys(io_bitmap + PAGE_SIZE));

	ok &= vmcs_write64(EPT_POINTER,
			page_map_hvirt2phys(cell->vmx.ept_structs.root_table) |
			EPT_TYPE_WRITEBACK | EPT_PAGE_WALK_LEN);

	return ok;
}

static bool vmx_set_guest_segment(const struct segment *seg,
				  unsigned long selector_field)
{
	bool ok = true;

	ok &= vmcs_write16(selector_field, seg->selector);
	ok &= vmcs_write64(selector_field + GUEST_SEG_BASE, seg->base);
	ok &= vmcs_write32(selector_field + GUEST_SEG_LIMIT, seg->limit);
	ok &= vmcs_write32(selector_field + GUEST_SEG_AR_BYTES,
			   seg->access_rights);
	return ok;
}

static bool vmcs_setup(struct per_cpu *cpu_data)
{
	struct desc_table_reg dtr;
	unsigned long val;
	bool ok = true;

	ok &= vmcs_write64(HOST_CR0, read_cr0());
	ok &= vmcs_write64(HOST_CR3, read_cr3());
	ok &= vmcs_write64(HOST_CR4, read_cr4());

	ok &= vmcs_write16(HOST_CS_SELECTOR, GDT_DESC_CODE * 8);
	ok &= vmcs_write16(HOST_DS_SELECTOR, 0);
	ok &= vmcs_write16(HOST_ES_SELECTOR, 0);
	ok &= vmcs_write16(HOST_SS_SELECTOR, 0);
	ok &= vmcs_write16(HOST_FS_SELECTOR, 0);
	ok &= vmcs_write16(HOST_GS_SELECTOR, 0);
	ok &= vmcs_write16(HOST_TR_SELECTOR, GDT_DESC_TSS * 8);

	ok &= vmcs_write64(HOST_FS_BASE, 0);
	ok &= vmcs_write64(HOST_GS_BASE, 0);
	ok &= vmcs_write64(HOST_TR_BASE, 0);

	read_gdtr(&dtr);
	ok &= vmcs_write64(HOST_GDTR_BASE, dtr.base);
	read_idtr(&dtr);
	ok &= vmcs_write64(HOST_IDTR_BASE, dtr.base);

	ok &= vmcs_write64(HOST_IA32_EFER, EFER_LMA | EFER_LME);

	ok &= vmcs_write32(HOST_IA32_SYSENTER_CS, 0);
	ok &= vmcs_write64(HOST_IA32_SYSENTER_EIP, 0);
	ok &= vmcs_write64(HOST_IA32_SYSENTER_ESP, 0);

	ok &= vmcs_write64(HOST_RSP, (unsigned long)cpu_data->stack +
			   sizeof(cpu_data->stack));
	ok &= vmcs_write64(HOST_RIP, (unsigned long)vm_exit);

	ok &= vmx_set_guest_cr(0, read_cr0());
	ok &= vmx_set_guest_cr(4, read_cr4());

	ok &= vmcs_write64(GUEST_CR3, cpu_data->linux_cr3);

	ok &= vmx_set_guest_segment(&cpu_data->linux_cs, GUEST_CS_SELECTOR);
	ok &= vmx_set_guest_segment(&cpu_data->linux_ds, GUEST_DS_SELECTOR);
	ok &= vmx_set_guest_segment(&cpu_data->linux_es, GUEST_ES_SELECTOR);
	ok &= vmx_set_guest_segment(&cpu_data->linux_fs, GUEST_FS_SELECTOR);
	ok &= vmx_set_guest_segment(&cpu_data->linux_gs, GUEST_GS_SELECTOR);
	ok &= vmx_set_guest_segment(&invalid_seg, GUEST_SS_SELECTOR);
	ok &= vmx_set_guest_segment(&cpu_data->linux_tss, GUEST_TR_SELECTOR);
	ok &= vmx_set_guest_segment(&invalid_seg, GUEST_LDTR_SELECTOR);

	ok &= vmcs_write64(GUEST_GDTR_BASE, cpu_data->linux_gdtr.base);
	ok &= vmcs_write32(GUEST_GDTR_LIMIT, cpu_data->linux_gdtr.limit);
	ok &= vmcs_write64(GUEST_IDTR_BASE, cpu_data->linux_idtr.base);
	ok &= vmcs_write32(GUEST_IDTR_LIMIT, cpu_data->linux_idtr.limit);

	ok &= vmcs_write64(GUEST_RFLAGS, 0x02);
	ok &= vmcs_write64(GUEST_RSP, cpu_data->linux_sp +
			   (NUM_ENTRY_REGS + 1) * sizeof(unsigned long));
	ok &= vmcs_write64(GUEST_RIP, cpu_data->linux_ip);

	ok &= vmcs_write32(GUEST_SYSENTER_CS,
			   read_msr(MSR_IA32_SYSENTER_CS));
	ok &= vmcs_write64(GUEST_SYSENTER_EIP,
			   read_msr(MSR_IA32_SYSENTER_EIP));
	ok &= vmcs_write64(GUEST_SYSENTER_ESP,
			   read_msr(MSR_IA32_SYSENTER_ESP));

	ok &= vmcs_write64(GUEST_DR7, 0x00000400);
	ok &= vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	ok &= vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	ok &= vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	ok &= vmcs_write64(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	ok &= vmcs_write64(GUEST_IA32_EFER, cpu_data->linux_efer);

	// TODO: switch PAT, PERF */

	ok &= vmcs_write64(VMCS_LINK_POINTER, -1UL);
	ok &= vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);

	val = read_msr(MSR_IA32_VMX_PINBASED_CTLS);
	val |= PIN_BASED_NMI_EXITING;
	ok &= vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, val);

	ok &= vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, 0);

	val = read_msr(MSR_IA32_VMX_PROCBASED_CTLS);
	val |= CPU_BASED_USE_IO_BITMAPS | CPU_BASED_USE_MSR_BITMAPS |
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	val &= ~(CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING);
	ok &= vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, val);

	ok &= vmcs_write64(MSR_BITMAP, page_map_hvirt2phys(msr_bitmap));

	val = read_msr(MSR_IA32_VMX_PROCBASED_CTLS2);
	val |= SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
		SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_UNRESTRICTED_GUEST |
		enable_rdtscp;
	ok &= vmcs_write32(SECONDARY_VM_EXEC_CONTROL, val);

	ok &= vmcs_write64(APIC_ACCESS_ADDR,
			   page_map_hvirt2phys(apic_access_page));

	ok &= vcpu_set_cell_config(cpu_data->cell);

	ok &= vmcs_write32(EXCEPTION_BITMAP, 0);

	val = read_msr(MSR_IA32_VMX_EXIT_CTLS);
	val |= VM_EXIT_HOST_ADDR_SPACE_SIZE | VM_EXIT_SAVE_IA32_EFER |
		VM_EXIT_LOAD_IA32_EFER;
	ok &= vmcs_write32(VM_EXIT_CONTROLS, val);

	ok &= vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	ok &= vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	ok &= vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);

	val = read_msr(MSR_IA32_VMX_ENTRY_CTLS);
	val |= VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_IA32_EFER;
	ok &= vmcs_write32(VM_ENTRY_CONTROLS, val);

	ok &= vmcs_write64(CR4_GUEST_HOST_MASK, 0);

	ok &= vmcs_write32(CR3_TARGET_COUNT, 0);

	return ok;
}

int vcpu_init(struct per_cpu *cpu_data)
{
	unsigned long cr4, feature_ctrl, mask;
	u32 revision_id;
	int err;

	cr4 = read_cr4();
	if (cr4 & X86_CR4_VMXE)
		return -EBUSY;

	err = vmx_check_features();
	if (err)
		return err;

	revision_id = (u32)read_msr(MSR_IA32_VMX_BASIC);
	cpu_data->vmxon_region.revision_id = revision_id;
	cpu_data->vmxon_region.shadow_indicator = 0;
	cpu_data->vmcs.revision_id = revision_id;
	cpu_data->vmcs.shadow_indicator = 0;

	// TODO: validate CR0

	/* Note: We assume that TXT is off */
	feature_ctrl = read_msr(MSR_IA32_FEATURE_CONTROL);
	mask = FEATURE_CONTROL_LOCKED |
		FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	if ((feature_ctrl & mask) != mask) {
		if (feature_ctrl & FEATURE_CONTROL_LOCKED)
			return -ENODEV;

		feature_ctrl |= mask;
		write_msr(MSR_IA32_FEATURE_CONTROL, feature_ctrl);
	}

	write_cr4(cr4 | X86_CR4_VMXE);
	// TODO: validate CR4

	if (!vmxon(cpu_data))  {
		write_cr4(cr4);
		return -EIO;
	}

	cpu_data->vmx_state = VMXON;

	if (!vmcs_clear(cpu_data) ||
	    !vmcs_load(cpu_data) ||
	    !vmcs_setup(cpu_data))
		return -EIO;

	cpu_data->vmx_state = VMCS_READY;

	return 0;
}

void vcpu_exit(struct per_cpu *cpu_data)
{
	if (cpu_data->vmx_state == VMXOFF)
		return;

	cpu_data->vmx_state = VMXOFF;
	/* Write vmx_state to ensure that vmx_schedule_vmexit stops accessing
	 * the VMCS (a compiler barrier would be sufficient, in fact). */
	memory_barrier();

	vmcs_clear(cpu_data);
	asm volatile("vmxoff" : : : "cc");
	write_cr4(read_cr4() & ~X86_CR4_VMXE);
}

void vcpu_activate_vmm(struct per_cpu *cpu_data)
{
	/* We enter Linux at the point arch_entry would return to as well.
	 * rax is cleared to signal success to the caller. */
	asm volatile(
		"mov (%%rdi),%%r15\n\t"
		"mov 0x8(%%rdi),%%r14\n\t"
		"mov 0x10(%%rdi),%%r13\n\t"
		"mov 0x18(%%rdi),%%r12\n\t"
		"mov 0x20(%%rdi),%%rbx\n\t"
		"mov 0x28(%%rdi),%%rbp\n\t"
		"vmlaunch\n\t"
		"pop %%rbp"
		: /* no output */
		: "a" (0), "D" (cpu_data->linux_reg)
		: "memory", "r15", "r14", "r13", "r12", "rbx", "rbp", "cc");

	panic_printk("FATAL: vmlaunch failed, error %d\n",
		     vmcs_read32(VM_INSTRUCTION_ERROR));
	panic_stop(cpu_data);
}

void __attribute__((noreturn))
vcpu_deactivate_vmm(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	unsigned long *stack = (unsigned long *)vmcs_read64(GUEST_RSP);
	unsigned long linux_ip = vmcs_read64(GUEST_RIP);

	cpu_data->linux_cr3 = vmcs_read64(GUEST_CR3);

	cpu_data->linux_gdtr.base = vmcs_read64(GUEST_GDTR_BASE);
	cpu_data->linux_gdtr.limit = vmcs_read64(GUEST_GDTR_LIMIT);
	cpu_data->linux_idtr.base = vmcs_read64(GUEST_IDTR_BASE);
	cpu_data->linux_idtr.limit = vmcs_read64(GUEST_IDTR_LIMIT);

	cpu_data->linux_cs.selector = vmcs_read32(GUEST_CS_SELECTOR);

	cpu_data->linux_tss.selector = vmcs_read32(GUEST_TR_SELECTOR);

	cpu_data->linux_efer = vmcs_read64(GUEST_IA32_EFER);
	cpu_data->linux_fs.base = vmcs_read64(GUEST_FS_BASE);
	cpu_data->linux_gs.base = vmcs_read64(GUEST_GS_BASE);

	cpu_data->linux_sysenter_cs = vmcs_read32(GUEST_SYSENTER_CS);
	cpu_data->linux_sysenter_eip = vmcs_read64(GUEST_SYSENTER_EIP);
	cpu_data->linux_sysenter_esp = vmcs_read64(GUEST_SYSENTER_ESP);

	cpu_data->linux_ds.selector = vmcs_read16(GUEST_DS_SELECTOR);
	cpu_data->linux_es.selector = vmcs_read16(GUEST_ES_SELECTOR);
	cpu_data->linux_fs.selector = vmcs_read16(GUEST_FS_SELECTOR);
	cpu_data->linux_gs.selector = vmcs_read16(GUEST_GS_SELECTOR);

	arch_cpu_restore(cpu_data);

	stack--;
	*stack = linux_ip;

	asm volatile (
		"mov %%rbx,%%rsp\n\t"
		"pop %%r15\n\t"
		"pop %%r14\n\t"
		"pop %%r13\n\t"
		"pop %%r12\n\t"
		"pop %%r11\n\t"
		"pop %%r10\n\t"
		"pop %%r9\n\t"
		"pop %%r8\n\t"
		"pop %%rdi\n\t"
		"pop %%rsi\n\t"
		"pop %%rbp\n\t"
		"add $8,%%rsp\n\t"
		"pop %%rbx\n\t"
		"pop %%rdx\n\t"
		"pop %%rcx\n\t"
		"mov %%rax,%%rsp\n\t"
		"xor %%rax,%%rax\n\t"
		"ret"
		: : "a" (stack), "b" (guest_regs));
	__builtin_unreachable();
}

static void vcpu_reset(struct per_cpu *cpu_data, unsigned int sipi_vector)
{
	unsigned long val;
	bool ok = true;

	ok &= vmx_set_guest_cr(0, X86_CR0_NW | X86_CR0_CD | X86_CR0_ET);
	ok &= vmx_set_guest_cr(4, 0);

	ok &= vmcs_write64(GUEST_CR3, 0);

	ok &= vmcs_write64(GUEST_RFLAGS, 0x02);
	ok &= vmcs_write64(GUEST_RSP, 0);

	val = 0;
	if (sipi_vector == APIC_BSP_PSEUDO_SIPI) {
		val = 0xfff0;
		sipi_vector = 0xf0;
	}
	ok &= vmcs_write64(GUEST_RIP, val);

	ok &= vmcs_write16(GUEST_CS_SELECTOR, sipi_vector << 8);
	ok &= vmcs_write64(GUEST_CS_BASE, sipi_vector << 12);
	ok &= vmcs_write32(GUEST_CS_LIMIT, 0xffff);
	ok &= vmcs_write32(GUEST_CS_AR_BYTES, 0x0009b);

	ok &= vmcs_write16(GUEST_DS_SELECTOR, 0);
	ok &= vmcs_write64(GUEST_DS_BASE, 0);
	ok &= vmcs_write32(GUEST_DS_LIMIT, 0xffff);
	ok &= vmcs_write32(GUEST_DS_AR_BYTES, 0x00093);

	ok &= vmcs_write16(GUEST_ES_SELECTOR, 0);
	ok &= vmcs_write64(GUEST_ES_BASE, 0);
	ok &= vmcs_write32(GUEST_ES_LIMIT, 0xffff);
	ok &= vmcs_write32(GUEST_ES_AR_BYTES, 0x00093);

	ok &= vmcs_write16(GUEST_FS_SELECTOR, 0);
	ok &= vmcs_write64(GUEST_FS_BASE, 0);
	ok &= vmcs_write32(GUEST_FS_LIMIT, 0xffff);
	ok &= vmcs_write32(GUEST_FS_AR_BYTES, 0x00093);

	ok &= vmcs_write16(GUEST_GS_SELECTOR, 0);
	ok &= vmcs_write64(GUEST_GS_BASE, 0);
	ok &= vmcs_write32(GUEST_GS_LIMIT, 0xffff);
	ok &= vmcs_write32(GUEST_GS_AR_BYTES, 0x00093);

	ok &= vmcs_write16(GUEST_SS_SELECTOR, 0);
	ok &= vmcs_write64(GUEST_SS_BASE, 0);
	ok &= vmcs_write32(GUEST_SS_LIMIT, 0xffff);
	ok &= vmcs_write32(GUEST_SS_AR_BYTES, 0x00093);

	ok &= vmcs_write16(GUEST_TR_SELECTOR, 0);
	ok &= vmcs_write64(GUEST_TR_BASE, 0);
	ok &= vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	ok &= vmcs_write32(GUEST_TR_AR_BYTES, 0x0008b);

	ok &= vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	ok &= vmcs_write64(GUEST_LDTR_BASE, 0);
	ok &= vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	ok &= vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	ok &= vmcs_write64(GUEST_GDTR_BASE, 0);
	ok &= vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);
	ok &= vmcs_write64(GUEST_IDTR_BASE, 0);
	ok &= vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);

	ok &= vmcs_write64(GUEST_IA32_EFER, 0);

	ok &= vmcs_write32(GUEST_SYSENTER_CS, 0);
	ok &= vmcs_write64(GUEST_SYSENTER_EIP, 0);
	ok &= vmcs_write64(GUEST_SYSENTER_ESP, 0);

	ok &= vmcs_write64(GUEST_DR7, 0x00000400);
	ok &= vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	ok &= vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	ok &= vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	ok &= vmcs_write64(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	val = vmcs_read32(VM_ENTRY_CONTROLS);
	val &= ~VM_ENTRY_IA32E_MODE;
	ok &= vmcs_write32(VM_ENTRY_CONTROLS, val);

	ok &= vcpu_set_cell_config(cpu_data->cell);

	if (!ok) {
		panic_printk("FATAL: CPU reset failed\n");
		panic_stop(cpu_data);
	}
}

static void vcpu_schedule_vmexit(struct per_cpu *cpu_data)
{
	u32 pin_based_ctrl;

	if (cpu_data->vmx_state != VMCS_READY)
		return;

	pin_based_ctrl = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);
	pin_based_ctrl |= PIN_BASED_VMX_PREEMPTION_TIMER;
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, pin_based_ctrl);
}

void vcpu_park(struct per_cpu *cpu_data)
{
	vcpu_reset(cpu_data, 0);
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_HLT);
}

void vcpu_nmi_handler(struct per_cpu *cpu_data)
{
	vcpu_schedule_vmexit(cpu_data);
}

static void vmx_disable_preemption_timer(void)
{
	u32 pin_based_ctrl = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);

	pin_based_ctrl &= ~PIN_BASED_VMX_PREEMPTION_TIMER;
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, pin_based_ctrl);
}

inline void vcpu_skip_emulated_instruction(struct per_cpu *cpu_data,
		                           unsigned int inst_len)
{
	vmcs_write64(GUEST_RIP, vmcs_read64(GUEST_RIP) + inst_len);
}

static void update_efer(void)
{
	unsigned long efer = vmcs_read64(GUEST_IA32_EFER);

	if ((efer & (EFER_LME | EFER_LMA)) != EFER_LME)
		return;

	efer |= EFER_LMA;
	vmcs_write64(GUEST_IA32_EFER, efer);
	vmcs_write32(VM_ENTRY_CONTROLS,
		     vmcs_read32(VM_ENTRY_CONTROLS) | VM_ENTRY_IA32E_MODE);
}

static bool vmx_handle_cr(struct registers *guest_regs,
			  struct per_cpu *cpu_data)
{
	u64 exit_qualification = vmcs_read64(EXIT_QUALIFICATION);
	unsigned long cr, reg, val;

	cr = exit_qualification & 0xf;
	reg = (exit_qualification >> 8) & 0xf;

	switch ((exit_qualification >> 4) & 3) {
	case 0: /* move to cr */
		if (reg == 4)
			val = vmcs_read64(GUEST_RSP);
		else
			val = ((unsigned long *)guest_regs)[15 - reg];

		if (cr == 0 || cr == 4) {
			vcpu_skip_emulated_instruction(cpu_data,
					X86_INST_LEN_MOV_TO_CR);
			/* TODO: check for #GP reasons */
			vmx_set_guest_cr(cr, val);
			if (cr == 0 && val & X86_CR0_PG)
				update_efer();
			return true;
		}
		break;
	default:
		break;
	}
	panic_printk("FATAL: Unhandled CR access, qualification %x\n",
		     exit_qualification);
	return false;
}

bool vcpu_get_guest_paging_structs(
		struct guest_paging_structures *pg_structs,
		struct per_cpu *cpu_data)
{
	if (vmcs_read32(VM_ENTRY_CONTROLS) & VM_ENTRY_IA32E_MODE) {
		pg_structs->root_paging = x86_64_paging;
		pg_structs->root_table_gphys =
			vmcs_read64(GUEST_CR3) & 0x000ffffffffff000UL;
	} else if (vmcs_read64(GUEST_CR0) & X86_CR0_PG &&
		 !(vmcs_read64(GUEST_CR4) & X86_CR4_PAE)) {
		pg_structs->root_paging = i386_paging;
		pg_structs->root_table_gphys =
			vmcs_read64(GUEST_CR3) & 0xfffff000UL;
	} else {
		printk("FATAL: Unsupported paging mode\n");
		return false;
	}
	return true;
}

static bool vmx_handle_apic_access(struct registers *guest_regs,
				   struct per_cpu *cpu_data)
{
	struct guest_paging_structures pg_structs;
	unsigned int inst_len, offset;
	u64 qualification;
	bool is_write;

	qualification = vmcs_read64(EXIT_QUALIFICATION);

	switch (qualification & APIC_ACCESS_TYPE_MASK) {
	case APIC_ACCESS_TYPE_LINEAR_READ:
	case APIC_ACCESS_TYPE_LINEAR_WRITE:
		is_write = !!(qualification & APIC_ACCESS_TYPE_LINEAR_WRITE);
		offset = qualification & APIC_ACCESS_OFFSET_MASK;
		if (offset & 0x00f)
			break;

		if (!vcpu_get_guest_paging_structs(&pg_structs, cpu_data))
			break;

		inst_len = apic_mmio_access(guest_regs, cpu_data,
					    vmcs_read64(GUEST_RIP),
					    &pg_structs, offset >> 4,
					    is_write);
		if (!inst_len)
			break;

		vcpu_skip_emulated_instruction(cpu_data, inst_len);
		return true;
	}
	panic_printk("FATAL: Unhandled APIC access, "
		     "qualification %x\n", qualification);
	return false;
}

static void dump_vm_exit_details(u32 reason)
{
	panic_printk("qualification %x\n", vmcs_read64(EXIT_QUALIFICATION));
	panic_printk("vectoring info: %x interrupt info: %x\n",
		     vmcs_read32(IDT_VECTORING_INFO_FIELD),
		     vmcs_read32(VM_EXIT_INTR_INFO));
	if (reason == EXIT_REASON_EPT_VIOLATION ||
	    reason == EXIT_REASON_EPT_MISCONFIG)
		panic_printk("guest phys addr %p guest linear addr: %p\n",
			     vmcs_read64(GUEST_PHYSICAL_ADDRESS),
			     vmcs_read64(GUEST_LINEAR_ADDRESS));
}

static void dump_guest_regs(struct registers *guest_regs)
{
	panic_printk("RIP: %p RSP: %p FLAGS: %x\n", vmcs_read64(GUEST_RIP),
		     vmcs_read64(GUEST_RSP), vmcs_read64(GUEST_RFLAGS));
	panic_printk("RAX: %p RBX: %p RCX: %p\n", guest_regs->rax,
		     guest_regs->rbx, guest_regs->rcx);
	panic_printk("RDX: %p RSI: %p RDI: %p\n", guest_regs->rdx,
		     guest_regs->rsi, guest_regs->rdi);
	panic_printk("CS: %x BASE: %p AR-BYTES: %x EFER.LMA %d\n",
		     vmcs_read64(GUEST_CS_SELECTOR),
		     vmcs_read64(GUEST_CS_BASE),
		     vmcs_read32(GUEST_CS_AR_BYTES),
		     !!(vmcs_read32(VM_ENTRY_CONTROLS) & VM_ENTRY_IA32E_MODE));
	panic_printk("CR0: %p CR3: %p CR4: %p\n", vmcs_read64(GUEST_CR0),
		     vmcs_read64(GUEST_CR3), vmcs_read64(GUEST_CR4));
	panic_printk("EFER: %p\n", vmcs_read64(GUEST_IA32_EFER));
}

void vcpu_handle_exit(struct registers *guest_regs, struct per_cpu *cpu_data)
{
	u32 reason = vmcs_read32(VM_EXIT_REASON);
	int sipi_vector;

	cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_TOTAL]++;

	switch (reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		asm volatile("int %0" : : "i" (NMI_VECTOR));
		/* fall through */
	case EXIT_REASON_PREEMPTION_TIMER:
		cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_MANAGEMENT]++;
		vmx_disable_preemption_timer();
		sipi_vector = x86_handle_events(cpu_data);
		if (sipi_vector >= 0) {
			printk("CPU %d received SIPI, vector %x\n",
			       cpu_data->cpu_id, sipi_vector);
			vcpu_reset(cpu_data, sipi_vector);
			memset(guest_regs, 0, sizeof(*guest_regs));
		}
		iommu_check_pending_faults(cpu_data);
		return;
	case EXIT_REASON_CPUID:
		vcpu_skip_emulated_instruction(cpu_data,
				X86_INST_LEN_CPUID);
		guest_regs->rax &= 0xffffffff;
		guest_regs->rbx &= 0xffffffff;
		guest_regs->rcx &= 0xffffffff;
		guest_regs->rdx &= 0xffffffff;
		__cpuid((u32 *)&guest_regs->rax, (u32 *)&guest_regs->rbx,
			(u32 *)&guest_regs->rcx, (u32 *)&guest_regs->rdx);
		return;
	case EXIT_REASON_VMCALL:
		vcpu_handle_hypercall(guest_regs, cpu_data);
		return;
	case EXIT_REASON_CR_ACCESS:
		cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_CR]++;
		if (vmx_handle_cr(guest_regs, cpu_data))
			return;
		break;
	case EXIT_REASON_MSR_READ:
		cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_MSR]++;
		if (guest_regs->rcx >= MSR_X2APIC_BASE &&
		    guest_regs->rcx <= MSR_X2APIC_END) {
			vcpu_skip_emulated_instruction(cpu_data,
					X86_INST_LEN_RDMSR);
			x2apic_handle_read(guest_regs);
			return;
		}
		panic_printk("FATAL: Unhandled MSR read: %08x\n",
			     guest_regs->rcx);
		break;
	case EXIT_REASON_MSR_WRITE:
		cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_MSR]++;
		if (guest_regs->rcx >= MSR_X2APIC_BASE &&
		    guest_regs->rcx <= MSR_X2APIC_END) {
			if (!x2apic_handle_write(guest_regs, cpu_data))
				break;
			vcpu_skip_emulated_instruction(cpu_data,
					X86_INST_LEN_WRMSR);
			return;
		}
		panic_printk("FATAL: Unhandled MSR write: %08x\n",
			     guest_regs->rcx);
		break;
	case EXIT_REASON_APIC_ACCESS:
		cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_XAPIC]++;
		if (vmx_handle_apic_access(guest_regs, cpu_data))
			return;
		break;
	case EXIT_REASON_XSETBV:
		cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_XSETBV]++;
		if (guest_regs->rax & X86_XCR0_FP &&
		    (guest_regs->rax & ~cpuid_eax(0x0d)) == 0 &&
		    guest_regs->rcx == 0 && guest_regs->rdx == 0) {
			vcpu_skip_emulated_instruction(cpu_data,
					X86_INST_LEN_XSETBV);
			asm volatile(
				"xsetbv"
				: /* no output */
				: "a" (guest_regs->rax), "c" (0), "d" (0));
			return;
		}
		panic_printk("FATAL: Invalid xsetbv parameters: "
			     "xcr[%d] = %08x:%08x\n", guest_regs->rcx,
			     guest_regs->rdx, guest_regs->rax);
		break;
	case EXIT_REASON_IO_INSTRUCTION:
		cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_PIO]++;
		if (vcpu_handle_io_access(guest_regs, cpu_data))
			return;
		break;
	case EXIT_REASON_EPT_VIOLATION:
		cpu_data->stats[JAILHOUSE_CPU_STAT_VMEXITS_MMIO]++;
		if (vcpu_handle_pt_violation(guest_regs, cpu_data))
			return;
		break;
	default:
		panic_printk("FATAL: %s, reason %d\n",
			     (reason & EXIT_REASONS_FAILED_VMENTRY) ?
			     "VM-Entry failure" : "Unhandled VM-Exit",
			     (u16)reason);
		dump_vm_exit_details(reason);
		break;
	}
	dump_guest_regs(guest_regs);
	panic_halt(cpu_data);
}

void vcpu_entry_failure(struct per_cpu *cpu_data)
{
	panic_printk("FATAL: vmresume failed, error %d\n",
		     vmcs_read32(VM_INSTRUCTION_ERROR));
	panic_stop(cpu_data);
}

void vcpu_vendor_get_cell_io_bitmap(struct cell *cell,
		                    struct vcpu_io_bitmap *iobm)
{
	if (iobm) {
		iobm->data = cell->vmx.io_bitmap;
		iobm->size = sizeof(cell->vmx.io_bitmap);
	}
}

u64 vcpu_get_efer(struct per_cpu *cpu_data)
{
	return vmcs_read64(GUEST_IA32_EFER);
}

u64 vcpu_get_rflags(struct per_cpu *cpu_data)
{
	return vmcs_read64(GUEST_RFLAGS);
}

u16 vcpu_get_cs_selector(struct per_cpu *cpu_data)
{
	return vmcs_read16(GUEST_CS_SELECTOR);
}

u64 vcpu_get_rip(struct per_cpu *cpu_data)
{
	return vmcs_read64(GUEST_RIP);
}

void vcpu_vendor_get_io_intercept(struct per_cpu *cpu_data,
		                  struct vcpu_io_intercept *out)
{
	u64 exitq = vmcs_read64(EXIT_QUALIFICATION);

	/* parse exit qualification for I/O instructions (see SDM, 27.2.1 ) */
	if (out) {
		out->port = (exitq >> 16) & 0xFFFF;
		out->size = (exitq & 0x3) + 1;
		out->in = !!((exitq & 0x8) >> 3);
		out->inst_len = vmcs_read64(VM_EXIT_INSTRUCTION_LEN);
		out->rep_or_str = !!(exitq & 0x30);
	}
}

void vcpu_vendor_get_pf_intercept(struct per_cpu *cpu_data,
		                  struct vcpu_pf_intercept *out)
{
	u64 exitq = vmcs_read64(EXIT_QUALIFICATION);

	if (out) {
		out->phys_addr = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
		/* We don't enable dirty/accessed bit updated in EPTP,
		 * so only read of write flags can be set, not both. */
		out->is_write = !!(exitq & 0x2);
	}
}
