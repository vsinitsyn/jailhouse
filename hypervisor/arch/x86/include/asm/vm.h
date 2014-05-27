#ifndef _JAILHOUSE_ASM_VM_H
#define _JAILHOUSE_ASM_VM_H

#ifdef ENABLE_VMX

/* VT-x functions */

#include <asm/vmx.h>
#include <asm/vtd.h>

#define vm_init				vmx_init

#define vm_cell_init			vmx_cell_init

#define vm_map_memory_region		vmx_map_memory_region
#define vm_unmap_memory_region		vmx_unmap_memory_region

#define vm_cell_exit			vmx_cell_exit

#define vm_cpu_init			vmx_cpu_init
#define vm_cpu_exit			vmx_cpu_exit

#define vm_cpu_activate_vmm		vmx_cpu_activate_vmm
#define vm_tlb_flush			vmx_tlb_flush

#define vm_cpu_park			vmx_cpu_park

/* VT-d methods */

#define iommu_init			vtd_init

#define iommu_cell_init			vtd_cell_init
#define iommu_map_memory_region		vtd_map_memory_region
#define iommu_unmap_memory_region	vtd_unmap_memory_region
#define iommu_add_pci_device		vtd_add_pci_device
#define iommu_remove_pci_device		vtd_remove_pci_device

#define iommu_get_remapped_root_int	vtd_get_remapped_root_int
#define iommu_map_interrupt		vtd_map_interrupt

#define iommu_cell_exit			vtd_cell_exit

#define iommu_config_commit		vtd_config_commit

#define iommu_shutdown			vtd_shutdown

#define iommu_check_pending_faults	vtd_check_pending_faults

#define iommu_mmio_access_handler	vtd_mmio_access_handler
#define iommu_cell_ir_emulation		vtd_cell_ir_emulation

#endif /* ENABLE_VMX */

#ifdef ENABLE_SVM

#include <asm/svm.h>
#include <asm/amd_iommu.h>

/* SVM methods */

#define vm_init				svm_init

#define vm_cell_init			svm_cell_init

#define vm_map_memory_region		svm_map_memory_region
#define vm_unmap_memory_region		svm_unmap_memory_region

#define vm_cell_exit			svm_cell_exit

#define vm_cpu_init			svm_cpu_init
#define vm_cpu_exit			svm_cpu_exit

#define vm_cpu_activate_vmm		svm_cpu_activate_vmm
#define vm_tlb_flush			svm_tlb_flush

#define vm_cpu_park			svm_cpu_park

/* IOMMU methods */

#define iommu_init			amd_iommu_init

#define iommu_cell_init			amd_iommu_cell_init
#define iommu_map_memory_region		amd_iommu_map_memory_region
#define iommu_unmap_memory_region	amd_iommu_unmap_memory_region
#define iommu_add_pci_device		amd_iommu_add_pci_device
#define iommu_remove_pci_device		amd_iommu_remove_pci_device
#define iommu_get_remapped_root_int	amd_iommu_get_remapped_root_int
#define iommu_map_interrupt		amd_iommu_map_interrupt
#define iommu_cell_exit			amd_iommu_cell_exit

#define iommu_config_commit		amd_iommu_config_commit

#define iommu_shutdown			amd_iommu_shutdown

#define iommu_check_pending_faults	amd_iommu_check_pending_faults

#define iommu_mmio_access_handler	amd_iommu_mmio_access_handler
#define iommu_cell_ir_emulation		amd_iommu_cell_ir_emulation
#endif /* ENABLE_SVM */

#endif /* _JAILHOUSE_ASM_VM_H */
