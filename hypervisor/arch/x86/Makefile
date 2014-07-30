#
# Jailhouse, a Linux-based partitioning hypervisor
#
# Copyright (c) Siemens AG, 2013
# Copyright (c) Valentine Sinitsyn, 2014
#
# Authors:
#  Jan Kiszka <jan.kiszka@siemens.com>
#  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
#
# This work is licensed under the terms of the GNU GPL, version 2.  See
# the COPYING file in the top-level directory.
#

COMMON_OBJECTS := apic.o dbg-write.o entry.o setup.o control.o mmio.o \
	 paging.o ../../pci.o pci.o ioapic.o i8042.o

# Can't list built-in-{amd,intel}.o in obj-y together, because Kbuild will
# try to build both vmx.o and svm.o then. However, headers like <asm/percpu.h>
# are configured either for SVM or for VMX (not both), so this will certainly fail.
ifneq ($(jailhouse-amd_DEFS),)
obj-y := built-in-amd.o
else
obj-y := built-in-intel.o
endif

built-in-amd-y += $(COMMON_OBJECTS) svm.o amd_iommu.o

built-in-intel-y += $(COMMON_OBJECTS) vmx.o vtd.o

$(obj)/built-in-amd.o: c_flags += $(jailhouse-amd_DEFS)
$(obj)/built-in-amd.o: a_flags += $(jailhouse-amd_DEFS)

$(obj)/built-in-intel.o: c_flags += $(jailhouse-intel_DEFS)
$(obj)/built-in-intel.o: a_flags += $(jailhouse-intel_DEFS)
