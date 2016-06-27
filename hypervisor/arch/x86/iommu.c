/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2014, 2015
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/control.h>
#include <asm/apic.h>
#include <asm/iommu.h>

unsigned int fault_reporting_cpu_id;

unsigned int iommu_count_units(void)
{
	unsigned int units = 0;

	while (units < JAILHOUSE_MAX_IOMMU_UNITS &&
	       system_config->platform_info.x86.iommu_units[units].base)
		units++;
	return units;
}

struct per_cpu *iommu_select_fault_reporting_cpu(void)
{
	struct per_cpu *cpu_data;
	unsigned int n;

	/* This assumes that at least one bit is set somewhere because we
	 * don't support configurations where Linux is left with no CPUs. */
	for (n = 0; root_cell.cpu_set->bitmap[n] == 0; n++)
		/* Empty loop */;
	cpu_data = per_cpu(ffsl(root_cell.cpu_set->bitmap[n]));

	/* Save this value globally to avoid multiple reports of the same
	 * case from different CPUs */
	fault_reporting_cpu_id = cpu_data->cpu_id;

	return cpu_data;
}

int iommu_validate_irq_msg(struct cell *cell, struct apic_irq_message *irq_msg)
{
	/*
	 * Validate delivery mode and destination(s).
	 * Note that we do support redirection hint only in logical
	 * destination mode.
	 */
	if ((irq_msg->delivery_mode != APIC_MSG_DLVR_FIXED &&
	     irq_msg->delivery_mode != APIC_MSG_DLVR_LOWPRI) ||
	    irq_msg->dest_logical != irq_msg->redir_hint)
		return -EINVAL;
	if (!apic_filter_irq_dest(cell, irq_msg))
		return -EPERM;

	return 0;
}
