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

#ifndef _JAILHOUSE_ASM_SVM_H
#define _JAILHOUSE_ASM_SVM_H

#define EFER_SVME		(1UL << 12)
#define VM_CR_SVMDIS		(1UL << 4)

#define MSR_VM_CR		0xc0010114
#define MSR_VM_HSAVE_PA		0xc0010117

#define SVM_MSRPM_0000		0
#define SVM_MSRPM_C000		1
#define SVM_MSRPM_C001		2
#define SVM_MSRPM_RESV		3

#define NPT_PAGE_DIR_LEVELS	4

extern bool decode_assists;

#endif
