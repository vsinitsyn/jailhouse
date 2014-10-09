/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <inmate.h>

#ifdef CONFIG_UART_OXPCIE952
#define UART_BASE		0xe000
#else
#define UART_BASE		0x2f8
#endif

void inmate_main(void)
{
	unsigned long long start, now;
	int n;

	printk_uart_base = UART_BASE;
	printk("Hello from this tiny cell!\n");

	pm_timer_init();

	start = pm_timer_read();
	for (n = 0; n < 10; n++) {
		do {
			now = pm_timer_read();
			cpu_relax();
		} while (now - start < 1000000000ULL);
		start += 1000000000ULL;
		printk("PM Timer: %11lu\n", now);
	}
}
