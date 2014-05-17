#ifndef _JAILHOUSE_ASM_VM_H
#define _JAILHOUSE_ASM_VM_H

#ifdef ENABLE_VMX

/* VT-x functions */

#include <asm/vmx.h>
#include <asm/vtd.h>

#define vm_init				vmx_init

#define vm_cell_init			vmx_cell_init
#define vm_root_cell_shrink		vmx_root_cell_shrink

#define vm_map_memory_region		vmx_map_memory_region
#define vm_unmap_memory_region		vmx_unmap_memory_region

#define vm_cell_exit			vmx_cell_exit

#define vm_cpu_init			vmx_cpu_init
#define vm_cpu_exit			vmx_cpu_exit

#define vm_cpu_activate_vmm		vmx_cpu_activate_vmm
#define vm_maps_flush_all		vmx_invept

#define vm_cpu_park			vmx_cpu_park

/* VT-d methods */

#define iommu_init			vtd_init

#define iommu_cell_init			vtd_cell_init
#define iommu_root_cell_shrink		vtd_root_cell_shrink
#define iommu_map_memory_region		vtd_map_memory_region
#define iommu_unmap_memory_region	vtd_unmap_memory_region
#define iommu_cell_exit			vtd_cell_exit

#define iommu_shutdown			vtd_shutdown

#define iommu_check_pending_faults	vtd_check_pending_faults

#endif /* ENABLE_VMX */

#ifdef ENABLE_SVM

#include <asm/svm.h>
#include <asm/amd_iommu.h>

/* SVM methods */

#define vm_init				svm_init

#define vm_cell_init			svm_cell_init
#define vm_root_cell_shrink		svm_root_cell_shrink

#define vm_map_memory_region		svm_map_memory_region
#define vm_unmap_memory_region		svm_unmap_memory_region

#define vm_cell_exit			svm_cell_exit

#define vm_cpu_init			svm_cpu_init
#define vm_cpu_exit			svm_cpu_exit

#define vm_cpu_activate_vmm		svm_cpu_activate_vmm
#define vm_maps_flush_all		svm_tlb_flush_all

#define vm_cpu_park			svm_cpu_park

/* IOMMU methods */

#define iommu_init			amd_iommu_init

#define iommu_cell_init			amd_iommu_cell_init
#define iommu_root_cell_shrink		amd_iommu_root_cell_shrink
#define iommu_map_memory_region		amd_iommu_map_memory_region
#define iommu_unmap_memory_region	amd_iommu_unmap_memory_region
#define iommu_cell_exit			amd_iommu_cell_exit

#define iommu_shutdown			amd_iommu_shutdown

#define iommu_check_pending_faults	amd_iommu_check_pending_faults

#endif /* ENABLE_SVM */

#endif /* _JAILHOUSE_ASM_VM_H */