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

LINUXINCLUDE := -I$(src)/arch/$(SRCARCH)/include -I$(src)/include
KBUILD_CFLAGS := -g -Os -Wall -Wstrict-prototypes -Wtype-limits \
		 -Wmissing-declarations -Wmissing-prototypes \
		 -fno-strict-aliasing -fno-pic -fno-common \
		 -fno-stack-protector -fno-builtin-ffsl

ifeq ($(SRCARCH),x86)
KBUILD_CFLAGS += -mcmodel=kernel
KBUILD_CPPFLAGS += -m64
BUILD_VARIANTS := amd intel
jailhouse-amd_DEFS += -DENABLE_SVM
jailhouse-intel_DEFS += -DENABLE_VMX
endif

ifneq ($(wildcard $(src)/include/jailhouse/config.h),)
KBUILD_CFLAGS += -include $(src)/include/jailhouse/config.h
endif

define filechk_version
	$(src)/../scripts/gen_version_h $(src)/..
endef

clean-files := $(obj)/include/jailhouse/version.h

$(obj)/include/jailhouse/version.h: $(src)/Makefile FORCE
	$(call filechk,version)

define BUILD_JAILHOUSE_template
# hypervisor-y sources reference headers in asm, which may depend
# on the architecture variant. This forces rebuilding of hypervisor-y
# objects for each such variant.
ifneq ($(1),)
$$(obj)/%$(1).o: c_flags += $$(jailhouse$(1)_DEFS)
$$(obj)/%$(1).o: $$(obj)/%.c
	$$(call if_changed_rule,cc_o_c)
endif

# XXX: Do we really need to rebuild built-in.o every time make runs?
$$(obj)/arch/$$(SRCARCH)/built-in$(1).o: FORCE
	$$(Q)$$(MAKE) $$(build)=$$(obj)/arch/$$(SRCARCH) \
	              jailhouse$(1)_DEFS=$$(jailhouse$(1)_DEFS) \
	              $$@

always += jailhouse$(1).bin

hypervisor$(1)-y := setup$(1).o printk$(1).o paging$(1).o control$(1).o lib$(1).o \
	arch/$$(SRCARCH)/built-in$(1).o hypervisor.lds
targets += $$(hypervisor$(1)-y)

$$(obj)/setup$1.o: $$(obj)/include/jailhouse/version.h

HYPERVISOR$(1)_OBJS = $$(addprefix $$(obj)/,$$(hypervisor$(1)-y))

LDFLAGS_hypervisor$(1).o := -T

targets += hypervisor$(1).o
$$(obj)/hypervisor$(1).o: $$(src)/hypervisor.lds $$(HYPERVISOR$(1)_OBJS)
	$$(call if_changed,ld)

OBJCOPYFLAGS_jailhouse$(1).bin := -O binary -R .eh_frame

targets += jailhouse$(1).bin
$$(obj)/jailhouse$(1).bin: $$(obj)/hypervisor$(1).o
	$$(call if_changed,objcopy)
endef

ifneq ($(BUILD_VARIANTS),)
$(foreach variant,$(BUILD_VARIANTS),\
	$(eval $(call BUILD_JAILHOUSE_template,-$(variant))))
else
$(eval $(call BUILD_JAILHOUSE_template,))
endif
