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
 *
 * Derived from Linux kernel code.
 */

#ifndef _JAILHOUSE_GEN_DEFINES_H
#define _JAILHOUSE_GEN_DEFINES_H

#define DEFINE(sym, val) \
        asm volatile("\n=>" #sym " %0 " #val : : "i" (val))

#define BLANK() asm volatile("\n=>" : : )

#define OFFSET(sym, str, mem) \
	DEFINE(sym, __builtin_offsetof(struct str, mem))

#define COMMENT(x) \
	asm volatile("\n=>#" x)

#endif
