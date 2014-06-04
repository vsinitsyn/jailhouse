/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013
 *
 * Authors:
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef _JAILHOUSE_ASM_ATOMIC_H
#define _JAILHOUSE_ASM_ATOMIC_H

#include <asm/types.h>

static inline u32 __xadd(u32 *dest, u32 src)
{
	asm volatile ("lock; xaddl %0, %1"
                      : "+r" (src), "+m" (*dest)
                      : : "cc");
	return src;
}

#define atomic_post_inc(x) __xadd(&(x), 1)

#endif
