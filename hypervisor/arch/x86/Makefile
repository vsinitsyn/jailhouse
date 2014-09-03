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
	 paging.o ../../pci.o pci.o ioapic.o vcpu.o

# Avoid building built-in-amd.o and built-in-intel.o simultaneously, as
# it will certainly fail (only jailhouse-amd_DEFS or jailhouse-intel_DEFS
# are passed to this Makefile, but not both).
obj-y := $(subst $(obj)/,,$(MAKECMDGOALS))

define BUILD_JAILHOUSE_VARIANT_template
$$(obj)/%-$(1).o: c_flags += $$(jailhouse-$(1)_DEFS)
$$(obj)/%-$(1).o: a_flags += $$(jailhouse-$(1)_DEFS)

$$(obj)/%-$(1).o: $$(obj)/%.S
	$$(call if_changed_dep,as_o_S)

$$(obj)/%-$(1).o: $$(obj)/%.c
	$$(call if_changed_rule,cc_o_c)

built-in-$(1)-y += $(2)
endef

$(eval $(call BUILD_JAILHOUSE_VARIANT_template,amd,$(COMMON_OBJECTS:.o=-amd.o) svm-amd.o amd_iommu-amd.o))
$(eval $(call BUILD_JAILHOUSE_VARIANT_template,intel,$(COMMON_OBJECTS:.o=-intel.o) vmx-intel.o vtd-intel.o))
