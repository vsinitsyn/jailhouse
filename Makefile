#
# Jailhouse, a Linux-based partitioning hypervisor
#
# Copyright (c) Siemens AG, 2013
#
# Authors:
#  Jan Kiszka <jan.kiszka@siemens.com>
#
# This work is licensed under the terms of the GNU GPL, version 2.  See
# the COPYING file in the top-level directory.
#

subdir-y := hypervisor configs inmates

obj-m := jailhouse.o

ccflags-y := -I$(src)/hypervisor/arch/$(SRCARCH)/include \
	     -I$(src)/hypervisor/include

jailhouse-y := driver.o

# out-of-tree build

KERNELDIR = /lib/modules/`uname -r`/build

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) SUBDIRS=`pwd` $@

firmware_install:
	cp hypervisor/jailhouse*.bin /lib/firmware/

install: modules_install firmware_install
	depmod -aq

.PHONY: modules_install install clean firmware_install
