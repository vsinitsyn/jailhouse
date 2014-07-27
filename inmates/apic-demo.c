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
#include <jailhouse/hypercall.h>

#ifdef CONFIG_UART_OXPCIE952
#define UART_BASE		0xe010
#else
#define UART_BASE		0x3f8
#endif
#define UART_LSR		0x5
#define UART_LSR_THRE		0x20
#define UART_IDLE_LOOPS		100

#define NS_PER_MSEC		1000000UL
#define NS_PER_SEC		1000000000UL

#define NUM_IDT_DESC		33
#define APIC_TIMER_VECTOR	32

#define X2APIC_EOI		0x80b
#define X2APIC_SPIV		0x80f
#define X2APIC_LVTT		0x832
#define X2APIC_TMICT		0x838
#define X2APIC_TMCCT		0x839
#define X2APIC_TDCR		0x83e

#define APIC_EOI_ACK		0

static u32 idt[NUM_IDT_DESC * 4];
static unsigned long apic_frequency;
static unsigned long expected_time;
static unsigned long min = -1, max;

static struct jailhouse_comm_region *comm_region =
	(struct jailhouse_comm_region *)0x100000UL;

struct desc_table_reg {
	u16 limit;
	u64 base;
} __attribute__((packed));

static inline unsigned long read_msr(unsigned int msr)
{
	u32 low, high;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
	return low | ((unsigned long)high << 32);
}

static inline void write_msr(unsigned int msr, unsigned long val)
{
	asm volatile("wrmsr"
		: /* no output */
		: "c" (msr), "a" (val), "d" (val >> 32)
		: "memory");
}

static inline void write_idtr(struct desc_table_reg *val)
{
	asm volatile("lidtq %0" : : "m" (*val));
}

void irq_handler(void)
{
	unsigned long delta;

	write_msr(X2APIC_EOI, APIC_EOI_ACK);

	delta = read_pm_timer(comm_region) - expected_time;
	if (delta < min)
		min = delta;
	if (delta > max)
		max = delta;
	printk("Timer fired, jitter: %6ld ns, min: %6ld ns, max: %6ld ns\n",
	       delta, min, max);

	expected_time += 100 * NS_PER_MSEC;
	write_msr(X2APIC_TMICT, (expected_time - read_pm_timer(comm_region)) *
				apic_frequency / NS_PER_SEC);
}

static void init_apic(void)
{
	unsigned long entry = (unsigned long)irq_entry + FSEGMENT_BASE;
	struct desc_table_reg dtr;
	unsigned long start, end;
	unsigned long tmr;

	write_msr(X2APIC_SPIV, 0x1ff);

	write_msr(X2APIC_TDCR, 3);

	start = read_pm_timer(comm_region);
	write_msr(X2APIC_TMICT, 0xffffffff);

	while (read_pm_timer(comm_region) - start < 100 * NS_PER_MSEC)
		cpu_relax();

	end = read_pm_timer(comm_region);
	tmr = read_msr(X2APIC_TMCCT);

	apic_frequency = (0xffffffff - tmr) * NS_PER_SEC / (end - start);

	printk("Calibrated APIC frequency: %lu kHz\n",
	       (apic_frequency * 16 + 500) / 1000);

	idt[APIC_TIMER_VECTOR * 4] = (entry & 0xffff) | (INMATE_CS64 << 16);
	idt[APIC_TIMER_VECTOR * 4 + 1] = 0x8e00 | (entry & 0xffff0000);
	idt[APIC_TIMER_VECTOR * 4 + 2] = entry >> 32;

	dtr.limit = NUM_IDT_DESC * 16 - 1;
	dtr.base = (u64)&idt;
	write_idtr(&dtr);

	write_msr(X2APIC_LVTT, APIC_TIMER_VECTOR);
	expected_time = read_pm_timer(comm_region);
	write_msr(X2APIC_TMICT, 1);

	asm volatile("sti");
}

void inmate_main(void)
{
	bool terminate = false;
	unsigned int n;

	printk_uart_base = UART_BASE;
	do {
		for (n = 0; n < UART_IDLE_LOOPS; n++)
			if (!(inb(UART_BASE + UART_LSR) & UART_LSR_THRE))
				break;
	} while (n < UART_IDLE_LOOPS);

	comm_region->cell_state = JAILHOUSE_CELL_RUNNING_LOCKED;

	init_apic();

	while (!terminate) {
		asm volatile("hlt");

		switch (comm_region->msg_to_cell) {
		case JAILHOUSE_MSG_SHUTDOWN_REQUEST:
			printk("Rejecting first shutdown request - "
			       "try again!\n");
			jailhouse_send_reply_from_cell(comm_region,
					JAILHOUSE_MSG_REQUEST_DENIED);
			terminate = true;
			break;
		default:
			jailhouse_send_reply_from_cell(comm_region,
					JAILHOUSE_MSG_UNKNOWN);
			break;
		}
	}

	for (n = 0; n < 10; n++)
		asm volatile("hlt");

	printk("Stopped APIC demo\n");
	comm_region->cell_state = JAILHOUSE_CELL_SHUT_DOWN;

	asm volatile("cli; hlt");
}
