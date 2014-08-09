/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013
 * Copyright (c) Valentine Sinitsyn, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <jailhouse/mmio.h>
#include <jailhouse/paging.h>
#include <jailhouse/printk.h>

#include <asm/vcpu.h>

union opcode {
	u8 raw;
	struct { /* REX */
		u8 b:1, x:1, r:1, w:1;
		u8 code:4;
	} __attribute__((packed)) rex;
	struct {
		u8 rm:3;
		u8 reg:3;
		u8 mod:2;
	} __attribute__((packed)) modrm;
	struct {
		u8 base:3;
		u8 index:3;
		u8 ss:2;
	} __attribute__((packed)) sib;
};

struct mmio_access mmio_parse(struct per_cpu *cpu_data, unsigned long pc,
			      const struct guest_paging_structures *pg_structs,
			      bool is_write)
{
	struct mmio_access access = { .inst_len = 0 };
	unsigned int remaining = 15, size = 0;
	bool has_rex_r = false;
	const u8 *inst = NULL;
	bool does_write;
	union opcode op[3];

restart:
	if (!size) {
		size = remaining;
		inst = vcpu_get_inst_bytes(cpu_data, pg_structs, pc, &size);
		if (!inst)
			goto error_noinst;
		remaining -= size;
		pc += size;
	}

	op[0].raw = *inst;
	if (op[0].rex.code == X86_REX_CODE) {
		/* REX.W is simply over-read since it is only affects the
		 * memory address in our supported modes which we get from the
		 * virtualization support. */
		if (op[0].rex.r)
			has_rex_r = true;
		if (op[0].rex.x)
			goto error_unsupported;

		inst++; size--;
		access.inst_len++;
		goto restart;
	}
	switch (op[0].raw) {
	case X86_OP_MOV_TO_MEM:
		access.inst_len += 2;
		access.size = 4;
		does_write = true;
		break;
	case X86_OP_MOV_FROM_MEM:
		access.inst_len += 2;
		access.size = 4;
		does_write = false;
		break;
	default:
		goto error_unsupported;
	}

	inst++; size--;
	if (!size) {
		size = remaining;
		inst = vcpu_get_inst_bytes(cpu_data, pg_structs, pc, &size);
		if (!inst)
			goto error_noinst;
		remaining -= size;
		pc += size;
	}

	op[1].raw = *inst;
	switch (op[1].modrm.mod) {
	case 0:
		if (op[1].modrm.rm == 5) /* 32-bit displacement */
			goto error_unsupported;
		else if (op[1].modrm.rm != 4) /* no SIB */
			break;

		inst++; size--;
		if (!size) {
			size = remaining;
			inst = vcpu_get_inst_bytes(cpu_data, pg_structs, pc, &size);
			if (!inst)
				goto error_noinst;
			remaining -= size;
			pc += size;
		}

		op[2].raw = *inst;
		if (op[2].sib.ss != 0 || op[2].sib.index != 4 ||
		    op[2].sib.base != 5)
			goto error_unsupported;
		access.inst_len += 5;
		break;
	case 1:
	case 2:
		if (op[1].modrm.rm == 4) /* SIB */
			goto error_unsupported;
		access.inst_len += op[1].modrm.mod == 1 ? 1 : 4;
		break;
	default:
		goto error_unsupported;
	}
	if (has_rex_r)
		access.reg = 7 - op[1].modrm.reg;
	else if (op[1].modrm.reg == 4)
		goto error_unsupported;
	else
		access.reg = 15 - op[1].modrm.reg;

	if (does_write != is_write)
		goto error_inconsitent;

	return access;

error_noinst:
	panic_printk("FATAL: unable to get MMIO instruction\n");
	goto error;

error_unsupported:
	panic_printk("FATAL: unsupported instruction\n");
	goto error;

error_inconsitent:
	panic_printk("FATAL: inconsistent access, expected %s instruction\n",
		     is_write ? "write" : "read");
error:
	access.inst_len = 0;
	return access;
}
