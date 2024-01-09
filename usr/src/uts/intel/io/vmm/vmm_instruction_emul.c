/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2012 Sandvine, Inc.
 * Copyright (c) 2012 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2021 Oxide Computer Company
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/pcpu.h>
#include <sys/systm.h>
#include <sys/proc.h>

#include <machine/vmparam.h>
#include <machine/vmm.h>
#include <sys/vmm_kernel.h>
#include <sys/vmm_vm.h>

#include <sys/vmm_instruction_emul.h>
#include <x86/psl.h>
#include <x86/specialreg.h>

#include "vmm_ioport.h"

enum vie_status {
	VIES_INIT		= (1U << 0),
	VIES_MMIO		= (1U << 1),
	VIES_INOUT		= (1U << 2),
	VIES_OTHER		= (1U << 3),
	VIES_INST_FETCH		= (1U << 4),
	VIES_INST_DECODE	= (1U << 5),
	VIES_PENDING_MMIO	= (1U << 6),
	VIES_PENDING_INOUT	= (1U << 7),
	VIES_REPEAT		= (1U << 8),
	VIES_USER_FALLBACK	= (1U << 9),
	VIES_COMPLETE		= (1U << 10),
};

/* State of request to perform emulated access (inout or MMIO) */
enum vie_req {
	VR_NONE,
	VR_PENDING,
	VR_DONE,
};

struct vie_mmio {
	uint64_t		data;
	uint64_t		gpa;
	uint8_t			bytes;
	enum vie_req		state;
};

struct vie_op {
	uint8_t		op_byte;	/* actual opcode byte */
	uint8_t		op_type;	/* type of operation (e.g. MOV) */
	uint16_t	op_flags;
};

#define	VIE_INST_SIZE	15
struct vie {
	uint8_t		inst[VIE_INST_SIZE];	/* instruction bytes */
	uint8_t		num_valid;		/* size of the instruction */
	uint8_t		num_processed;

	uint8_t		addrsize:4, opsize:4;	/* address and operand sizes */
	uint8_t		rex_w:1,		/* REX prefix */
			rex_r:1,
			rex_x:1,
			rex_b:1,
			rex_present:1,
			repz_present:1,		/* REP/REPE/REPZ prefix */
			repnz_present:1,	/* REPNE/REPNZ prefix */
			opsize_override:1,	/* Operand size override */
			addrsize_override:1,	/* Address size override */
			segment_override:1;	/* Segment override */

	uint8_t		mod:2,			/* ModRM byte */
			reg:4,
			rm:4;

	uint8_t		ss:2,			/* SIB byte */
			vex_present:1,		/* VEX prefixed */
			vex_l:1,		/* L bit */
			index:4,		/* SIB byte */
			base:4;			/* SIB byte */

	uint8_t		disp_bytes;
	uint8_t		imm_bytes;

	uint8_t		scale;

	uint8_t		vex_reg:4,	/* vvvv: first source reg specifier */
			vex_pp:2,	/* pp */
			_sparebits:2;

	uint8_t		_sparebytes[2];

	int		base_register;		/* VM_REG_GUEST_xyz */
	int		index_register;		/* VM_REG_GUEST_xyz */
	int		segment_register;	/* VM_REG_GUEST_xyz */

	int64_t		displacement;		/* optional addr displacement */
	int64_t		immediate;		/* optional immediate operand */

	struct vie_op	op;			/* opcode description */

	enum vie_status	status;

	struct vm_guest_paging paging;		/* guest paging state */

	uint64_t	mmio_gpa;		/* faulting GPA */
	struct vie_mmio	mmio_req_read;
	struct vie_mmio	mmio_req_write;

	struct vm_inout	inout;			/* active in/out op */
	enum vie_req	inout_req_state;
	uint32_t	inout_req_val;		/* value from userspace */
};


/* struct vie_op.op_type */
enum {
	VIE_OP_TYPE_NONE = 0,
	VIE_OP_TYPE_MOV,
	VIE_OP_TYPE_MOVSX,
	VIE_OP_TYPE_MOVZX,
	VIE_OP_TYPE_MOV_CR,
	VIE_OP_TYPE_AND,
	VIE_OP_TYPE_OR,
	VIE_OP_TYPE_SUB,
	VIE_OP_TYPE_TWO_BYTE,
	VIE_OP_TYPE_PUSH,
	VIE_OP_TYPE_CMP,
	VIE_OP_TYPE_POP,
	VIE_OP_TYPE_MOVS,
	VIE_OP_TYPE_GROUP1,
	VIE_OP_TYPE_STOS,
	VIE_OP_TYPE_BITTEST,
	VIE_OP_TYPE_TWOB_GRP15,
	VIE_OP_TYPE_ADD,
	VIE_OP_TYPE_TEST,
	VIE_OP_TYPE_BEXTR,
	VIE_OP_TYPE_CLTS,
	VIE_OP_TYPE_MUL,
	VIE_OP_TYPE_LAST
};

/* struct vie_op.op_flags */
#define	VIE_OP_F_IMM		(1 << 0)  /* 16/32-bit immediate operand */
#define	VIE_OP_F_IMM8		(1 << 1)  /* 8-bit immediate operand */
#define	VIE_OP_F_MOFFSET	(1 << 2)  /* 16/32/64-bit immediate moffset */
#define	VIE_OP_F_NO_MODRM	(1 << 3)
#define	VIE_OP_F_NO_GLA_VERIFICATION	(1 << 4)
#define	VIE_OP_F_REG_REG	(1 << 5)  /* special-case for mov-cr */

static const struct vie_op three_byte_opcodes_0f38[256] = {
	[0xF7] = {
		.op_byte = 0xF7,
		.op_type = VIE_OP_TYPE_BEXTR,
	},
};

static const struct vie_op two_byte_opcodes[256] = {
	[0x06] = {
		.op_byte = 0x06,
		.op_type = VIE_OP_TYPE_CLTS,
		.op_flags = VIE_OP_F_NO_MODRM | VIE_OP_F_NO_GLA_VERIFICATION
	},
	[0x20] = {
		.op_byte = 0x20,
		.op_type = VIE_OP_TYPE_MOV_CR,
		.op_flags = VIE_OP_F_REG_REG | VIE_OP_F_NO_GLA_VERIFICATION
	},
	[0x22] = {
		.op_byte = 0x22,
		.op_type = VIE_OP_TYPE_MOV_CR,
		.op_flags = VIE_OP_F_REG_REG | VIE_OP_F_NO_GLA_VERIFICATION
	},
	[0xAE] = {
		.op_byte = 0xAE,
		.op_type = VIE_OP_TYPE_TWOB_GRP15,
	},
	[0xAF] = {
		.op_byte = 0xAF,
		.op_type = VIE_OP_TYPE_MUL,
	},
	[0xB6] = {
		.op_byte = 0xB6,
		.op_type = VIE_OP_TYPE_MOVZX,
	},
	[0xB7] = {
		.op_byte = 0xB7,
		.op_type = VIE_OP_TYPE_MOVZX,
	},
	[0xBA] = {
		.op_byte = 0xBA,
		.op_type = VIE_OP_TYPE_BITTEST,
		.op_flags = VIE_OP_F_IMM8,
	},
	[0xBE] = {
		.op_byte = 0xBE,
		.op_type = VIE_OP_TYPE_MOVSX,
	},
};

static const struct vie_op one_byte_opcodes[256] = {
	[0x03] = {
		.op_byte = 0x03,
		.op_type = VIE_OP_TYPE_ADD,
	},
	[0x0F] = {
		.op_byte = 0x0F,
		.op_type = VIE_OP_TYPE_TWO_BYTE
	},
	[0x0B] = {
		.op_byte = 0x0B,
		.op_type = VIE_OP_TYPE_OR,
	},
	[0x2B] = {
		.op_byte = 0x2B,
		.op_type = VIE_OP_TYPE_SUB,
	},
	[0x39] = {
		.op_byte = 0x39,
		.op_type = VIE_OP_TYPE_CMP,
	},
	[0x3B] = {
		.op_byte = 0x3B,
		.op_type = VIE_OP_TYPE_CMP,
	},
	[0x88] = {
		.op_byte = 0x88,
		.op_type = VIE_OP_TYPE_MOV,
	},
	[0x89] = {
		.op_byte = 0x89,
		.op_type = VIE_OP_TYPE_MOV,
	},
	[0x8A] = {
		.op_byte = 0x8A,
		.op_type = VIE_OP_TYPE_MOV,
	},
	[0x8B] = {
		.op_byte = 0x8B,
		.op_type = VIE_OP_TYPE_MOV,
	},
	[0xA1] = {
		.op_byte = 0xA1,
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_MOFFSET | VIE_OP_F_NO_MODRM,
	},
	[0xA3] = {
		.op_byte = 0xA3,
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_MOFFSET | VIE_OP_F_NO_MODRM,
	},
	[0xA4] = {
		.op_byte = 0xA4,
		.op_type = VIE_OP_TYPE_MOVS,
		.op_flags = VIE_OP_F_NO_MODRM | VIE_OP_F_NO_GLA_VERIFICATION
	},
	[0xA5] = {
		.op_byte = 0xA5,
		.op_type = VIE_OP_TYPE_MOVS,
		.op_flags = VIE_OP_F_NO_MODRM | VIE_OP_F_NO_GLA_VERIFICATION
	},
	[0xAA] = {
		.op_byte = 0xAA,
		.op_type = VIE_OP_TYPE_STOS,
		.op_flags = VIE_OP_F_NO_MODRM | VIE_OP_F_NO_GLA_VERIFICATION
	},
	[0xAB] = {
		.op_byte = 0xAB,
		.op_type = VIE_OP_TYPE_STOS,
		.op_flags = VIE_OP_F_NO_MODRM | VIE_OP_F_NO_GLA_VERIFICATION
	},
	[0xC6] = {
		/* XXX Group 11 extended opcode - not just MOV */
		.op_byte = 0xC6,
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_IMM8,
	},
	[0xC7] = {
		.op_byte = 0xC7,
		.op_type = VIE_OP_TYPE_MOV,
		.op_flags = VIE_OP_F_IMM,
	},
	[0x23] = {
		.op_byte = 0x23,
		.op_type = VIE_OP_TYPE_AND,
	},
	[0x80] = {
		/* Group 1 extended opcode */
		.op_byte = 0x80,
		.op_type = VIE_OP_TYPE_GROUP1,
		.op_flags = VIE_OP_F_IMM8,
	},
	[0x81] = {
		/* Group 1 extended opcode */
		.op_byte = 0x81,
		.op_type = VIE_OP_TYPE_GROUP1,
		.op_flags = VIE_OP_F_IMM,
	},
	[0x83] = {
		/* Group 1 extended opcode */
		.op_byte = 0x83,
		.op_type = VIE_OP_TYPE_GROUP1,
		.op_flags = VIE_OP_F_IMM8,
	},
	[0x8F] = {
		/* XXX Group 1A extended opcode - not just POP */
		.op_byte = 0x8F,
		.op_type = VIE_OP_TYPE_POP,
	},
	[0xF6] = {
		/* XXX Group 3 extended opcode - not just TEST */
		.op_byte = 0xF6,
		.op_type = VIE_OP_TYPE_TEST,
		.op_flags = VIE_OP_F_IMM8,
	},
	[0xF7] = {
		/* XXX Group 3 extended opcode - not just TEST */
		.op_byte = 0xF7,
		.op_type = VIE_OP_TYPE_TEST,
		.op_flags = VIE_OP_F_IMM,
	},
	[0xFF] = {
		/* XXX Group 5 extended opcode - not just PUSH */
		.op_byte = 0xFF,
		.op_type = VIE_OP_TYPE_PUSH,
	}
};

/* struct vie.mod */
#define	VIE_MOD_INDIRECT		0
#define	VIE_MOD_INDIRECT_DISP8		1
#define	VIE_MOD_INDIRECT_DISP32		2
#define	VIE_MOD_DIRECT			3

/* struct vie.rm */
#define	VIE_RM_SIB			4
#define	VIE_RM_DISP32			5

#define	GB				(1024 * 1024 * 1024)


/*
 * Paging defines, previously pulled in from machine/pmap.h
 */
#define	PG_V	(1 << 0) /* Present */
#define	PG_RW	(1 << 1) /* Read/Write */
#define	PG_U	(1 << 2) /* User/Supervisor */
#define	PG_A	(1 << 5) /* Accessed */
#define	PG_M	(1 << 6) /* Dirty */
#define	PG_PS	(1 << 7) /* Largepage */

/*
 * Paging except defines, previously pulled in from machine/pmap.h
 */
#define	PGEX_P		(1 << 0) /* Non-present/Protection */
#define	PGEX_W		(1 << 1) /* Read/Write */
#define	PGEX_U		(1 << 2) /* User/Supervisor */
#define	PGEX_RSV	(1 << 3) /* (Non-)Reserved */
#define	PGEX_I		(1 << 4) /* Instruction */


static enum vm_reg_name gpr_map[16] = {
	VM_REG_GUEST_RAX,
	VM_REG_GUEST_RCX,
	VM_REG_GUEST_RDX,
	VM_REG_GUEST_RBX,
	VM_REG_GUEST_RSP,
	VM_REG_GUEST_RBP,
	VM_REG_GUEST_RSI,
	VM_REG_GUEST_RDI,
	VM_REG_GUEST_R8,
	VM_REG_GUEST_R9,
	VM_REG_GUEST_R10,
	VM_REG_GUEST_R11,
	VM_REG_GUEST_R12,
	VM_REG_GUEST_R13,
	VM_REG_GUEST_R14,
	VM_REG_GUEST_R15
};

static const char *gpr_name_map[][16] = {
	[1] = {
		"a[hl]", "c[hl]", "d[hl]", "b[hl]", "spl", "bpl", "sil", "dil",
		"r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
	},
	[2] = {
		"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
		"r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
	},
	[4] = {
		"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
		"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
	},
	[8] = {
		"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
	},
};

static enum vm_reg_name cr_map[16] = {
	VM_REG_GUEST_CR0,
	VM_REG_LAST,
	VM_REG_GUEST_CR2,
	VM_REG_GUEST_CR3,
	VM_REG_GUEST_CR4,
	VM_REG_LAST,
	VM_REG_LAST,
	VM_REG_LAST,
	VM_REG_LAST,
	VM_REG_LAST,
	VM_REG_LAST,
	VM_REG_LAST,
	VM_REG_LAST,
	VM_REG_LAST,
	VM_REG_LAST,
	VM_REG_LAST
};

static uint64_t size2mask[] = {
	[1] = 0xff,
	[2] = 0xffff,
	[4] = 0xffffffff,
	[8] = 0xffffffffffffffff,
};


static int vie_mmio_read(struct vie *vie, struct vm *vm, int cpuid,
    uint64_t gpa, uint64_t *rval, int bytes);
static int vie_mmio_write(struct vie *vie, struct vm *vm, int cpuid,
    uint64_t gpa, uint64_t wval, int bytes);
static int vie_calculate_gla(enum vm_cpu_mode cpu_mode, enum vm_reg_name seg,
    struct seg_desc *desc, uint64_t offset, int length, int addrsize,
    int prot, uint64_t *gla);
static int vie_canonical_check(enum vm_cpu_mode cpu_mode, uint64_t gla);
static int vie_alignment_check(int cpl, int size, uint64_t cr0, uint64_t rf,
    uint64_t gla);
static uint64_t vie_size2mask(int size);

struct vie *
vie_alloc()
{
	return (kmem_zalloc(sizeof (struct vie), KM_SLEEP));
}

void
vie_free(struct vie *vie)
{
	kmem_free(vie, sizeof (struct vie));
}

enum vm_reg_name
vie_regnum_map(uint8_t regnum)
{
	VERIFY3U(regnum, <, 16);
	return (gpr_map[regnum]);
}

const char *
vie_regnum_name(uint8_t regnum, uint8_t size)
{
	VERIFY3U(regnum, <, 16);
	VERIFY(size == 1 || size == 2 || size == 4 || size == 8);
	return (gpr_name_map[size][regnum]);
}

static void
vie_calc_bytereg(struct vie *vie, enum vm_reg_name *reg, int *lhbr)
{
	*lhbr = 0;
	*reg = gpr_map[vie->reg];

	/*
	 * 64-bit mode imposes limitations on accessing legacy high byte
	 * registers (lhbr).
	 *
	 * The legacy high-byte registers cannot be addressed if the REX
	 * prefix is present. In this case the values 4, 5, 6 and 7 of the
	 * 'ModRM:reg' field address %spl, %bpl, %sil and %dil respectively.
	 *
	 * If the REX prefix is not present then the values 4, 5, 6 and 7
	 * of the 'ModRM:reg' field address the legacy high-byte registers,
	 * %ah, %ch, %dh and %bh respectively.
	 */
	if (!vie->rex_present) {
		if (vie->reg & 0x4) {
			*lhbr = 1;
			*reg = gpr_map[vie->reg & 0x3];
		}
	}
}

static int
vie_read_bytereg(struct vie *vie, struct vm *vm, int vcpuid, uint8_t *rval)
{
	uint64_t val;
	int error, lhbr;
	enum vm_reg_name reg;

	vie_calc_bytereg(vie, &reg, &lhbr);
	error = vm_get_register(vm, vcpuid, reg, &val);

	/*
	 * To obtain the value of a legacy high byte register shift the
	 * base register right by 8 bits (%ah = %rax >> 8).
	 */
	if (lhbr)
		*rval = val >> 8;
	else
		*rval = val;
	return (error);
}

static int
vie_write_bytereg(struct vie *vie, struct vm *vm, int vcpuid, uint8_t byte)
{
	uint64_t origval, val, mask;
	int error, lhbr;
	enum vm_reg_name reg;

	vie_calc_bytereg(vie, &reg, &lhbr);
	error = vm_get_register(vm, vcpuid, reg, &origval);
	if (error == 0) {
		val = byte;
		mask = 0xff;
		if (lhbr) {
			/*
			 * Shift left by 8 to store 'byte' in a legacy high
			 * byte register.
			 */
			val <<= 8;
			mask <<= 8;
		}
		val |= origval & ~mask;
		error = vm_set_register(vm, vcpuid, reg, val);
	}
	return (error);
}

static int
vie_update_register(struct vm *vm, int vcpuid, enum vm_reg_name reg,
    uint64_t val, int size)
{
	int error;
	uint64_t origval;

	switch (size) {
	case 1:
	case 2:
		error = vm_get_register(vm, vcpuid, reg, &origval);
		if (error)
			return (error);
		val &= size2mask[size];
		val |= origval & ~size2mask[size];
		break;
	case 4:
		val &= 0xffffffffUL;
		break;
	case 8:
		break;
	default:
		return (EINVAL);
	}

	error = vm_set_register(vm, vcpuid, reg, val);
	return (error);
}

static int
vie_repeat(struct vie *vie)
{
	vie->status |= VIES_REPEAT;

	/*
	 * Clear out any cached operation values so the repeated instruction can
	 * begin without using that stale state.  Other state, such as the
	 * decoding results, are kept around as it will not vary between
	 * iterations of a rep-prefixed instruction.
	 */
	if ((vie->status & VIES_MMIO) != 0) {
		vie->mmio_req_read.state = VR_NONE;
		vie->mmio_req_write.state = VR_NONE;
	} else if ((vie->status & VIES_INOUT) != 0) {
		vie->inout_req_state = VR_NONE;
	} else {
		panic("unexpected emulation state");
	}

	return (EAGAIN);
}

#define	RFLAGS_STATUS_BITS    (PSL_C | PSL_PF | PSL_AF | PSL_Z | PSL_N | PSL_V)

/*
 * Return the status flags that would result from doing (x - y).
 */
/* BEGIN CSTYLED */
#define	GETCC(sz)							\
static ulong_t								\
getcc##sz(uint##sz##_t x, uint##sz##_t y)				\
{									\
	ulong_t rflags;							\
									\
	__asm __volatile("sub %2,%1; pushfq; popq %0" :			\
	    "=r" (rflags), "+r" (x) : "m" (y));				\
	return (rflags);						\
} struct __hack
/* END CSTYLED */

GETCC(8);
GETCC(16);
GETCC(32);
GETCC(64);

static ulong_t
getcc(int opsize, uint64_t x, uint64_t y)
{
	KASSERT(opsize == 1 || opsize == 2 || opsize == 4 || opsize == 8,
	    ("getcc: invalid operand size %d", opsize));

	if (opsize == 1)
		return (getcc8(x, y));
	else if (opsize == 2)
		return (getcc16(x, y));
	else if (opsize == 4)
		return (getcc32(x, y));
	else
		return (getcc64(x, y));
}

/*
 * Macro creation of functions getaddflags{8,16,32,64}
 */
/* BEGIN CSTYLED */
#define	GETADDFLAGS(sz)							\
static ulong_t								\
getaddflags##sz(uint##sz##_t x, uint##sz##_t y)				\
{									\
	ulong_t rflags;							\
									\
	__asm __volatile("add %2,%1; pushfq; popq %0" :			\
	    "=r" (rflags), "+r" (x) : "m" (y));				\
	return (rflags);						\
} struct __hack
/* END CSTYLED */

GETADDFLAGS(8);
GETADDFLAGS(16);
GETADDFLAGS(32);
GETADDFLAGS(64);

static ulong_t
getaddflags(int opsize, uint64_t x, uint64_t y)
{
	KASSERT(opsize == 1 || opsize == 2 || opsize == 4 || opsize == 8,
	    ("getaddflags: invalid operand size %d", opsize));

	if (opsize == 1)
		return (getaddflags8(x, y));
	else if (opsize == 2)
		return (getaddflags16(x, y));
	else if (opsize == 4)
		return (getaddflags32(x, y));
	else
		return (getaddflags64(x, y));
}

/*
 * Macro creation of functions getimulflags{16,32,64}
 */
/* BEGIN CSTYLED */
#define	GETIMULFLAGS(sz)						\
static ulong_t								\
getimulflags##sz(uint##sz##_t x, uint##sz##_t y)			\
{									\
	ulong_t rflags;							\
									\
	__asm __volatile("imul %2,%1; pushfq; popq %0" :		\
	    "=r" (rflags), "+r" (x) : "m" (y));				\
	return (rflags);						\
} struct __hack
/* END CSTYLED */

GETIMULFLAGS(16);
GETIMULFLAGS(32);
GETIMULFLAGS(64);

static ulong_t
getimulflags(int opsize, uint64_t x, uint64_t y)
{
	KASSERT(opsize == 2 || opsize == 4 || opsize == 8,
	    ("getimulflags: invalid operand size %d", opsize));

	if (opsize == 2)
		return (getimulflags16(x, y));
	else if (opsize == 4)
		return (getimulflags32(x, y));
	else
		return (getimulflags64(x, y));
}

/*
 * Return the status flags that would result from doing (x & y).
 */
/* BEGIN CSTYLED */
#define	GETANDFLAGS(sz)							\
static ulong_t								\
getandflags##sz(uint##sz##_t x, uint##sz##_t y)				\
{									\
	ulong_t rflags;							\
									\
	__asm __volatile("and %2,%1; pushfq; popq %0" :			\
	    "=r" (rflags), "+r" (x) : "m" (y));				\
	return (rflags);						\
} struct __hack
/* END CSTYLED */

GETANDFLAGS(8);
GETANDFLAGS(16);
GETANDFLAGS(32);
GETANDFLAGS(64);

static ulong_t
getandflags(int opsize, uint64_t x, uint64_t y)
{
	KASSERT(opsize == 1 || opsize == 2 || opsize == 4 || opsize == 8,
	    ("getandflags: invalid operand size %d", opsize));

	if (opsize == 1)
		return (getandflags8(x, y));
	else if (opsize == 2)
		return (getandflags16(x, y));
	else if (opsize == 4)
		return (getandflags32(x, y));
	else
		return (getandflags64(x, y));
}

static int
vie_emulate_mov_cr(struct vie *vie, struct vm *vm, int vcpuid)
{
	uint64_t val;
	int err;
	enum vm_reg_name gpr = gpr_map[vie->rm];
	enum vm_reg_name cr = cr_map[vie->reg];

	uint_t size = 4;
	if (vie->paging.cpu_mode == CPU_MODE_64BIT) {
		size = 8;
	}

	switch (vie->op.op_byte) {
	case 0x20:
		/*
		 * MOV control register (ModRM:reg) to reg (ModRM:r/m)
		 * 20/r:	mov r32, CR0-CR7
		 * 20/r:	mov r64, CR0-CR7
		 * REX.R + 20/0:	mov r64, CR8
		 */
		if (vie->paging.cpl != 0) {
			vm_inject_gp(vm, vcpuid);
			vie->num_processed = 0;
			return (0);
		}
		err = vm_get_register(vm, vcpuid, cr, &val);
		if (err != 0) {
			/* #UD for access to non-existent CRs */
			vm_inject_ud(vm, vcpuid);
			vie->num_processed = 0;
			return (0);
		}
		err = vie_update_register(vm, vcpuid, gpr, val, size);
		break;
	case 0x22: {
		/*
		 * MOV reg (ModRM:r/m) to control register (ModRM:reg)
		 * 22/r:	mov CR0-CR7, r32
		 * 22/r:	mov CR0-CR7, r64
		 * REX.R + 22/0:	mov CR8, r64
		 */
		uint64_t old, diff;

		if (vie->paging.cpl != 0) {
			vm_inject_gp(vm, vcpuid);
			vie->num_processed = 0;
			return (0);
		}
		err = vm_get_register(vm, vcpuid, cr, &old);
		if (err != 0) {
			/* #UD for access to non-existent CRs */
			vm_inject_ud(vm, vcpuid);
			vie->num_processed = 0;
			return (0);
		}
		err = vm_get_register(vm, vcpuid, gpr, &val);
		VERIFY0(err);
		val &= size2mask[size];
		diff = old ^ val;

		switch (cr) {
		case VM_REG_GUEST_CR0:
			if ((diff & CR0_PG) != 0) {
				uint64_t efer;

				err = vm_get_register(vm, vcpuid,
				    VM_REG_GUEST_EFER, &efer);
				VERIFY0(err);

				/* Keep the long-mode state in EFER in sync */
				if ((val & CR0_PG) != 0 &&
				    (efer & EFER_LME) != 0) {
					efer |= EFER_LMA;
				}
				if ((val & CR0_PG) == 0 &&
				    (efer & EFER_LME) != 0) {
					efer &= ~EFER_LMA;
				}

				err = vm_set_register(vm, vcpuid,
				    VM_REG_GUEST_EFER, efer);
				VERIFY0(err);
			}
			/* TODO: enforce more of the #GP checks */
			err = vm_set_register(vm, vcpuid, cr, val);
			VERIFY0(err);
			break;
		case VM_REG_GUEST_CR2:
		case VM_REG_GUEST_CR3:
		case VM_REG_GUEST_CR4:
			/* TODO: enforce more of the #GP checks */
			err = vm_set_register(vm, vcpuid, cr, val);
			break;
		default:
			/* The cr_map mapping should prevent this */
			panic("invalid cr %d", cr);
		}
		break;
	}
	default:
		return (EINVAL);
	}
	return (err);
}

static int
vie_emulate_mov(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, size;
	enum vm_reg_name reg;
	uint8_t byte;
	uint64_t val;

	size = vie->opsize;
	error = EINVAL;

	switch (vie->op.op_byte) {
	case 0x88:
		/*
		 * MOV byte from reg (ModRM:reg) to mem (ModRM:r/m)
		 * 88/r:	mov r/m8, r8
		 * REX + 88/r:	mov r/m8, r8 (%ah, %ch, %dh, %bh not available)
		 */
		size = 1;	/* override for byte operation */
		error = vie_read_bytereg(vie, vm, vcpuid, &byte);
		if (error == 0) {
			error = vie_mmio_write(vie, vm, vcpuid, gpa, byte,
			    size);
		}
		break;
	case 0x89:
		/*
		 * MOV from reg (ModRM:reg) to mem (ModRM:r/m)
		 * 89/r:	mov r/m16, r16
		 * 89/r:	mov r/m32, r32
		 * REX.W + 89/r	mov r/m64, r64
		 */
		reg = gpr_map[vie->reg];
		error = vm_get_register(vm, vcpuid, reg, &val);
		if (error == 0) {
			val &= size2mask[size];
			error = vie_mmio_write(vie, vm, vcpuid, gpa, val, size);
		}
		break;
	case 0x8A:
		/*
		 * MOV byte from mem (ModRM:r/m) to reg (ModRM:reg)
		 * 8A/r:	mov r8, r/m8
		 * REX + 8A/r:	mov r8, r/m8
		 */
		size = 1;	/* override for byte operation */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val, size);
		if (error == 0)
			error = vie_write_bytereg(vie, vm, vcpuid, val);
		break;
	case 0x8B:
		/*
		 * MOV from mem (ModRM:r/m) to reg (ModRM:reg)
		 * 8B/r:	mov r16, r/m16
		 * 8B/r:	mov r32, r/m32
		 * REX.W 8B/r:	mov r64, r/m64
		 */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val, size);
		if (error == 0) {
			reg = gpr_map[vie->reg];
			error = vie_update_register(vm, vcpuid, reg, val, size);
		}
		break;
	case 0xA1:
		/*
		 * MOV from seg:moffset to AX/EAX/RAX
		 * A1:		mov AX, moffs16
		 * A1:		mov EAX, moffs32
		 * REX.W + A1:	mov RAX, moffs64
		 */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val, size);
		if (error == 0) {
			reg = VM_REG_GUEST_RAX;
			error = vie_update_register(vm, vcpuid, reg, val, size);
		}
		break;
	case 0xA3:
		/*
		 * MOV from AX/EAX/RAX to seg:moffset
		 * A3:		mov moffs16, AX
		 * A3:		mov moffs32, EAX
		 * REX.W + A3:	mov moffs64, RAX
		 */
		error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RAX, &val);
		if (error == 0) {
			val &= size2mask[size];
			error = vie_mmio_write(vie, vm, vcpuid, gpa, val, size);
		}
		break;
	case 0xC6:
		/*
		 * MOV from imm8 to mem (ModRM:r/m)
		 * C6/0		mov r/m8, imm8
		 * REX + C6/0	mov r/m8, imm8
		 */
		size = 1;	/* override for byte operation */
		val = vie->immediate;
		error = vie_mmio_write(vie, vm, vcpuid, gpa, val, size);
		break;
	case 0xC7:
		/*
		 * MOV from imm16/imm32 to mem (ModRM:r/m)
		 * C7/0		mov r/m16, imm16
		 * C7/0		mov r/m32, imm32
		 * REX.W + C7/0	mov r/m64, imm32 (sign-extended to 64-bits)
		 */
		val = vie->immediate & size2mask[size];
		error = vie_mmio_write(vie, vm, vcpuid, gpa, val, size);
		break;
	default:
		break;
	}

	return (error);
}

static int
vie_emulate_movx(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, size;
	enum vm_reg_name reg;
	uint64_t val;

	size = vie->opsize;
	error = EINVAL;

	switch (vie->op.op_byte) {
	case 0xB6:
		/*
		 * MOV and zero extend byte from mem (ModRM:r/m) to
		 * reg (ModRM:reg).
		 *
		 * 0F B6/r		movzx r16, r/m8
		 * 0F B6/r		movzx r32, r/m8
		 * REX.W + 0F B6/r	movzx r64, r/m8
		 */

		/* get the first operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val, 1);
		if (error)
			break;

		/* get the second operand */
		reg = gpr_map[vie->reg];

		/* zero-extend byte */
		val = (uint8_t)val;

		/* write the result */
		error = vie_update_register(vm, vcpuid, reg, val, size);
		break;
	case 0xB7:
		/*
		 * MOV and zero extend word from mem (ModRM:r/m) to
		 * reg (ModRM:reg).
		 *
		 * 0F B7/r		movzx r32, r/m16
		 * REX.W + 0F B7/r	movzx r64, r/m16
		 */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val, 2);
		if (error)
			return (error);

		reg = gpr_map[vie->reg];

		/* zero-extend word */
		val = (uint16_t)val;

		error = vie_update_register(vm, vcpuid, reg, val, size);
		break;
	case 0xBE:
		/*
		 * MOV and sign extend byte from mem (ModRM:r/m) to
		 * reg (ModRM:reg).
		 *
		 * 0F BE/r		movsx r16, r/m8
		 * 0F BE/r		movsx r32, r/m8
		 * REX.W + 0F BE/r	movsx r64, r/m8
		 */

		/* get the first operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val, 1);
		if (error)
			break;

		/* get the second operand */
		reg = gpr_map[vie->reg];

		/* sign extend byte */
		val = (int8_t)val;

		/* write the result */
		error = vie_update_register(vm, vcpuid, reg, val, size);
		break;
	default:
		break;
	}
	return (error);
}

/*
 * Helper function to calculate and validate a linear address.
 */
static int
vie_get_gla(struct vie *vie, struct vm *vm, int vcpuid, int opsize,
    int addrsize, int prot, enum vm_reg_name seg, enum vm_reg_name gpr,
    uint64_t *gla)
{
	struct seg_desc desc;
	uint64_t cr0, val, rflags;
	int error;
	struct vm_guest_paging *paging;

	paging = &vie->paging;

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_CR0, &cr0);
	KASSERT(error == 0, ("%s: error %d getting cr0", __func__, error));

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	KASSERT(error == 0, ("%s: error %d getting rflags", __func__, error));

	error = vm_get_seg_desc(vm, vcpuid, seg, &desc);
	KASSERT(error == 0, ("%s: error %d getting segment descriptor %d",
	    __func__, error, seg));

	error = vm_get_register(vm, vcpuid, gpr, &val);
	KASSERT(error == 0, ("%s: error %d getting register %d", __func__,
	    error, gpr));

	if (vie_calculate_gla(paging->cpu_mode, seg, &desc, val, opsize,
	    addrsize, prot, gla)) {
		if (seg == VM_REG_GUEST_SS)
			vm_inject_ss(vm, vcpuid, 0);
		else
			vm_inject_gp(vm, vcpuid);
		return (-1);
	}

	if (vie_canonical_check(paging->cpu_mode, *gla)) {
		if (seg == VM_REG_GUEST_SS)
			vm_inject_ss(vm, vcpuid, 0);
		else
			vm_inject_gp(vm, vcpuid);
		return (-1);
	}

	if (vie_alignment_check(paging->cpl, opsize, cr0, rflags, *gla)) {
		vm_inject_ac(vm, vcpuid, 0);
		return (-1);
	}

	return (0);
}

static int
vie_emulate_movs(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	struct vm_copyinfo copyinfo[2];
	uint64_t dstaddr, srcaddr, dstgpa, srcgpa, val;
	uint64_t rcx, rdi, rsi, rflags;
	int error, fault, opsize, seg, repeat;
	struct vm_guest_paging *paging;

	opsize = (vie->op.op_byte == 0xA4) ? 1 : vie->opsize;
	val = 0;
	error = 0;
	paging = &vie->paging;

	/*
	 * XXX although the MOVS instruction is only supposed to be used with
	 * the "rep" prefix some guests like FreeBSD will use "repnz" instead.
	 *
	 * Empirically the "repnz" prefix has identical behavior to "rep"
	 * and the zero flag does not make a difference.
	 */
	repeat = vie->repz_present | vie->repnz_present;

	if (repeat) {
		error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RCX, &rcx);
		KASSERT(!error, ("%s: error %d getting rcx", __func__, error));

		/*
		 * The count register is %rcx, %ecx or %cx depending on the
		 * address size of the instruction.
		 */
		if ((rcx & vie_size2mask(vie->addrsize)) == 0) {
			error = 0;
			goto done;
		}
	}

	/*
	 *	Source		Destination	Comments
	 *	--------------------------------------------
	 * (1)  memory		memory		n/a
	 * (2)  memory		mmio		emulated
	 * (3)  mmio		memory		emulated
	 * (4)  mmio		mmio		emulated
	 *
	 * At this point we don't have sufficient information to distinguish
	 * between (2), (3) and (4). We use 'vm_copy_setup()' to tease this
	 * out because it will succeed only when operating on regular memory.
	 *
	 * XXX the emulation doesn't properly handle the case where 'gpa'
	 * is straddling the boundary between the normal memory and MMIO.
	 */

	seg = vie->segment_override ? vie->segment_register : VM_REG_GUEST_DS;
	if (vie_get_gla(vie, vm, vcpuid, opsize, vie->addrsize, PROT_READ, seg,
	    VM_REG_GUEST_RSI, &srcaddr) != 0) {
		goto done;
	}

	error = vm_copy_setup(vm, vcpuid, paging, srcaddr, opsize, PROT_READ,
	    copyinfo, nitems(copyinfo), &fault);
	if (error == 0) {
		if (fault)
			goto done;	/* Resume guest to handle fault */

		/*
		 * case (2): read from system memory and write to mmio.
		 */
		vm_copyin(vm, vcpuid, copyinfo, &val, opsize);
		vm_copy_teardown(vm, vcpuid, copyinfo, nitems(copyinfo));
		error = vie_mmio_write(vie, vm, vcpuid, gpa, val, opsize);
		if (error)
			goto done;
	} else {
		/*
		 * 'vm_copy_setup()' is expected to fail for cases (3) and (4)
		 * if 'srcaddr' is in the mmio space.
		 */

		if (vie_get_gla(vie, vm, vcpuid, opsize, vie->addrsize,
		    PROT_WRITE, VM_REG_GUEST_ES, VM_REG_GUEST_RDI,
		    &dstaddr) != 0) {
			goto done;
		}

		error = vm_copy_setup(vm, vcpuid, paging, dstaddr, opsize,
		    PROT_WRITE, copyinfo, nitems(copyinfo), &fault);
		if (error == 0) {
			if (fault)
				goto done;    /* Resume guest to handle fault */

			/*
			 * case (3): read from MMIO and write to system memory.
			 *
			 * A MMIO read can have side-effects so we
			 * commit to it only after vm_copy_setup() is
			 * successful. If a page-fault needs to be
			 * injected into the guest then it will happen
			 * before the MMIO read is attempted.
			 */
			error = vie_mmio_read(vie, vm, vcpuid, gpa, &val,
			    opsize);

			if (error == 0) {
				vm_copyout(vm, vcpuid, &val, copyinfo, opsize);
			}
			/*
			 * Regardless of whether the MMIO read was successful or
			 * not, the copy resources must be cleaned up.
			 */
			vm_copy_teardown(vm, vcpuid, copyinfo,
			    nitems(copyinfo));
			if (error != 0) {
				goto done;
			}
		} else {
			/*
			 * Case (4): read from and write to mmio.
			 *
			 * Commit to the MMIO read/write (with potential
			 * side-effects) only after we are sure that the
			 * instruction is not going to be restarted due
			 * to address translation faults.
			 */
			error = vm_gla2gpa(vm, vcpuid, paging, srcaddr,
			    PROT_READ, &srcgpa, &fault);
			if (error || fault)
				goto done;

			error = vm_gla2gpa(vm, vcpuid, paging, dstaddr,
			    PROT_WRITE, &dstgpa, &fault);
			if (error || fault)
				goto done;

			error = vie_mmio_read(vie, vm, vcpuid, srcgpa, &val,
			    opsize);
			if (error)
				goto done;

			error = vie_mmio_write(vie, vm, vcpuid, dstgpa, val,
			    opsize);
			if (error)
				goto done;
		}
	}

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RSI, &rsi);
	KASSERT(error == 0, ("%s: error %d getting rsi", __func__, error));

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RDI, &rdi);
	KASSERT(error == 0, ("%s: error %d getting rdi", __func__, error));

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	KASSERT(error == 0, ("%s: error %d getting rflags", __func__, error));

	if (rflags & PSL_D) {
		rsi -= opsize;
		rdi -= opsize;
	} else {
		rsi += opsize;
		rdi += opsize;
	}

	error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RSI, rsi,
	    vie->addrsize);
	KASSERT(error == 0, ("%s: error %d updating rsi", __func__, error));

	error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RDI, rdi,
	    vie->addrsize);
	KASSERT(error == 0, ("%s: error %d updating rdi", __func__, error));

	if (repeat) {
		rcx = rcx - 1;
		error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RCX,
		    rcx, vie->addrsize);
		KASSERT(!error, ("%s: error %d updating rcx", __func__, error));

		/*
		 * Repeat the instruction if the count register is not zero.
		 */
		if ((rcx & vie_size2mask(vie->addrsize)) != 0)
			return (vie_repeat(vie));
	}
done:
	return (error);
}

static int
vie_emulate_stos(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, opsize, repeat;
	uint64_t val;
	uint64_t rcx, rdi, rflags;

	opsize = (vie->op.op_byte == 0xAA) ? 1 : vie->opsize;
	repeat = vie->repz_present | vie->repnz_present;

	if (repeat) {
		error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RCX, &rcx);
		KASSERT(!error, ("%s: error %d getting rcx", __func__, error));

		/*
		 * The count register is %rcx, %ecx or %cx depending on the
		 * address size of the instruction.
		 */
		if ((rcx & vie_size2mask(vie->addrsize)) == 0)
			return (0);
	}

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RAX, &val);
	KASSERT(!error, ("%s: error %d getting rax", __func__, error));

	error = vie_mmio_write(vie, vm, vcpuid, gpa, val, opsize);
	if (error)
		return (error);

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RDI, &rdi);
	KASSERT(error == 0, ("%s: error %d getting rdi", __func__, error));

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	KASSERT(error == 0, ("%s: error %d getting rflags", __func__, error));

	if (rflags & PSL_D)
		rdi -= opsize;
	else
		rdi += opsize;

	error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RDI, rdi,
	    vie->addrsize);
	KASSERT(error == 0, ("%s: error %d updating rdi", __func__, error));

	if (repeat) {
		rcx = rcx - 1;
		error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RCX,
		    rcx, vie->addrsize);
		KASSERT(!error, ("%s: error %d updating rcx", __func__, error));

		/*
		 * Repeat the instruction if the count register is not zero.
		 */
		if ((rcx & vie_size2mask(vie->addrsize)) != 0)
			return (vie_repeat(vie));
	}

	return (0);
}

static int
vie_emulate_and(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, size;
	enum vm_reg_name reg;
	uint64_t result, rflags, rflags2, val1, val2;

	size = vie->opsize;
	error = EINVAL;

	switch (vie->op.op_byte) {
	case 0x23:
		/*
		 * AND reg (ModRM:reg) and mem (ModRM:r/m) and store the
		 * result in reg.
		 *
		 * 23/r		and r16, r/m16
		 * 23/r		and r32, r/m32
		 * REX.W + 23/r	and r64, r/m64
		 */

		/* get the first operand */
		reg = gpr_map[vie->reg];
		error = vm_get_register(vm, vcpuid, reg, &val1);
		if (error)
			break;

		/* get the second operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val2, size);
		if (error)
			break;

		/* perform the operation and write the result */
		result = val1 & val2;
		error = vie_update_register(vm, vcpuid, reg, result, size);
		break;
	case 0x81:
	case 0x83:
		/*
		 * AND mem (ModRM:r/m) with immediate and store the
		 * result in mem.
		 *
		 * 81 /4		and r/m16, imm16
		 * 81 /4		and r/m32, imm32
		 * REX.W + 81 /4	and r/m64, imm32 sign-extended to 64
		 *
		 * 83 /4		and r/m16, imm8 sign-extended to 16
		 * 83 /4		and r/m32, imm8 sign-extended to 32
		 * REX.W + 83/4		and r/m64, imm8 sign-extended to 64
		 */

		/* get the first operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val1, size);
		if (error)
			break;

		/*
		 * perform the operation with the pre-fetched immediate
		 * operand and write the result
		 */
		result = val1 & vie->immediate;
		error = vie_mmio_write(vie, vm, vcpuid, gpa, result, size);
		break;
	default:
		break;
	}
	if (error)
		return (error);

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	if (error)
		return (error);

	/*
	 * OF and CF are cleared; the SF, ZF and PF flags are set according
	 * to the result; AF is undefined.
	 *
	 * The updated status flags are obtained by subtracting 0 from 'result'.
	 */
	rflags2 = getcc(size, result, 0);
	rflags &= ~RFLAGS_STATUS_BITS;
	rflags |= rflags2 & (PSL_PF | PSL_Z | PSL_N);

	error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, rflags, 8);
	return (error);
}

static int
vie_emulate_or(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, size;
	enum vm_reg_name reg;
	uint64_t result, rflags, rflags2, val1, val2;

	size = vie->opsize;
	error = EINVAL;

	switch (vie->op.op_byte) {
	case 0x0B:
		/*
		 * OR reg (ModRM:reg) and mem (ModRM:r/m) and store the
		 * result in reg.
		 *
		 * 0b/r		or r16, r/m16
		 * 0b/r		or r32, r/m32
		 * REX.W + 0b/r	or r64, r/m64
		 */

		/* get the first operand */
		reg = gpr_map[vie->reg];
		error = vm_get_register(vm, vcpuid, reg, &val1);
		if (error)
			break;

		/* get the second operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val2, size);
		if (error)
			break;

		/* perform the operation and write the result */
		result = val1 | val2;
		error = vie_update_register(vm, vcpuid, reg, result, size);
		break;
	case 0x81:
	case 0x83:
		/*
		 * OR mem (ModRM:r/m) with immediate and store the
		 * result in mem.
		 *
		 * 81 /1		or r/m16, imm16
		 * 81 /1		or r/m32, imm32
		 * REX.W + 81 /1	or r/m64, imm32 sign-extended to 64
		 *
		 * 83 /1		or r/m16, imm8 sign-extended to 16
		 * 83 /1		or r/m32, imm8 sign-extended to 32
		 * REX.W + 83/1		or r/m64, imm8 sign-extended to 64
		 */

		/* get the first operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val1, size);
		if (error)
			break;

		/*
		 * perform the operation with the pre-fetched immediate
		 * operand and write the result
		 */
		result = val1 | vie->immediate;
		error = vie_mmio_write(vie, vm, vcpuid, gpa, result, size);
		break;
	default:
		break;
	}
	if (error)
		return (error);

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	if (error)
		return (error);

	/*
	 * OF and CF are cleared; the SF, ZF and PF flags are set according
	 * to the result; AF is undefined.
	 *
	 * The updated status flags are obtained by subtracting 0 from 'result'.
	 */
	rflags2 = getcc(size, result, 0);
	rflags &= ~RFLAGS_STATUS_BITS;
	rflags |= rflags2 & (PSL_PF | PSL_Z | PSL_N);

	error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, rflags, 8);
	return (error);
}

static int
vie_emulate_cmp(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, size;
	uint64_t regop, memop, op1, op2, rflags, rflags2;
	enum vm_reg_name reg;

	size = vie->opsize;
	switch (vie->op.op_byte) {
	case 0x39:
	case 0x3B:
		/*
		 * 39/r		CMP r/m16, r16
		 * 39/r		CMP r/m32, r32
		 * REX.W 39/r	CMP r/m64, r64
		 *
		 * 3B/r		CMP r16, r/m16
		 * 3B/r		CMP r32, r/m32
		 * REX.W + 3B/r	CMP r64, r/m64
		 *
		 * Compare the first operand with the second operand and
		 * set status flags in EFLAGS register. The comparison is
		 * performed by subtracting the second operand from the first
		 * operand and then setting the status flags.
		 */

		/* Get the register operand */
		reg = gpr_map[vie->reg];
		error = vm_get_register(vm, vcpuid, reg, &regop);
		if (error)
			return (error);

		/* Get the memory operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &memop, size);
		if (error)
			return (error);

		if (vie->op.op_byte == 0x3B) {
			op1 = regop;
			op2 = memop;
		} else {
			op1 = memop;
			op2 = regop;
		}
		rflags2 = getcc(size, op1, op2);
		break;
	case 0x80:
	case 0x81:
	case 0x83:
		/*
		 * 80 /7		cmp r/m8, imm8
		 * REX + 80 /7		cmp r/m8, imm8
		 *
		 * 81 /7		cmp r/m16, imm16
		 * 81 /7		cmp r/m32, imm32
		 * REX.W + 81 /7	cmp r/m64, imm32 sign-extended to 64
		 *
		 * 83 /7		cmp r/m16, imm8 sign-extended to 16
		 * 83 /7		cmp r/m32, imm8 sign-extended to 32
		 * REX.W + 83 /7	cmp r/m64, imm8 sign-extended to 64
		 *
		 * Compare mem (ModRM:r/m) with immediate and set
		 * status flags according to the results.  The
		 * comparison is performed by subtracting the
		 * immediate from the first operand and then setting
		 * the status flags.
		 *
		 */
		if (vie->op.op_byte == 0x80)
			size = 1;

		/* get the first operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &op1, size);
		if (error)
			return (error);

		rflags2 = getcc(size, op1, vie->immediate);
		break;
	default:
		return (EINVAL);
	}
	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	if (error)
		return (error);
	rflags &= ~RFLAGS_STATUS_BITS;
	rflags |= rflags2 & RFLAGS_STATUS_BITS;

	error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, rflags, 8);
	return (error);
}

static int
vie_emulate_test(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, size;
	uint64_t op1, rflags, rflags2;

	size = vie->opsize;
	error = EINVAL;

	switch (vie->op.op_byte) {
	case 0xF6:
		/*
		 * F6 /0		test r/m8, imm8
		 *
		 * Test mem (ModRM:r/m) with immediate and set status
		 * flags according to the results.  The comparison is
		 * performed by anding the immediate from the first
		 * operand and then setting the status flags.
		 */
		if ((vie->reg & 7) != 0)
			return (EINVAL);

		size = 1;	/* override for byte operation */

		error = vie_mmio_read(vie, vm, vcpuid, gpa, &op1, size);
		if (error)
			return (error);

		rflags2 = getandflags(size, op1, vie->immediate);
		break;
	case 0xF7:
		/*
		 * F7 /0		test r/m16, imm16
		 * F7 /0		test r/m32, imm32
		 * REX.W + F7 /0	test r/m64, imm32 sign-extended to 64
		 *
		 * Test mem (ModRM:r/m) with immediate and set status
		 * flags according to the results.  The comparison is
		 * performed by anding the immediate from the first
		 * operand and then setting the status flags.
		 */
		if ((vie->reg & 7) != 0)
			return (EINVAL);

		error = vie_mmio_read(vie, vm, vcpuid, gpa, &op1, size);
		if (error)
			return (error);

		rflags2 = getandflags(size, op1, vie->immediate);
		break;
	default:
		return (EINVAL);
	}
	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	if (error)
		return (error);

	/*
	 * OF and CF are cleared; the SF, ZF and PF flags are set according
	 * to the result; AF is undefined.
	 */
	rflags &= ~RFLAGS_STATUS_BITS;
	rflags |= rflags2 & (PSL_PF | PSL_Z | PSL_N);

	error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, rflags, 8);
	return (error);
}

static int
vie_emulate_bextr(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	uint64_t src1, src2, dst, rflags;
	unsigned start, len, size;
	int error;
	struct vm_guest_paging *paging;

	size = vie->opsize;
	error = EINVAL;
	paging = &vie->paging;

	/*
	 * VEX.LZ.0F38.W0 F7 /r		BEXTR r32a, r/m32, r32b
	 * VEX.LZ.0F38.W1 F7 /r		BEXTR r64a, r/m64, r64b
	 *
	 * Destination operand is ModRM:reg.  Source operands are ModRM:r/m and
	 * Vex.vvvv.
	 *
	 * Operand size is always 32-bit if not in 64-bit mode (W1 is ignored).
	 */
	if (size != 4 && paging->cpu_mode != CPU_MODE_64BIT)
		size = 4;

	/*
	 * Extracts contiguous bits from the first /source/ operand (second
	 * operand) using an index and length specified in the second /source/
	 * operand (third operand).
	 */
	error = vie_mmio_read(vie, vm, vcpuid, gpa, &src1, size);
	if (error)
		return (error);
	error = vm_get_register(vm, vcpuid, gpr_map[vie->vex_reg], &src2);
	if (error)
		return (error);
	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	if (error)
		return (error);

	start = (src2 & 0xff);
	len = (src2 & 0xff00) >> 8;

	/* If no bits are extracted, the destination register is cleared. */
	dst = 0;

	/* If START exceeds the operand size, no bits are extracted. */
	if (start > size * 8)
		goto done;
	/* Length is bounded by both the destination size and start offset. */
	if (start + len > size * 8)
		len = (size * 8) - start;
	if (len == 0)
		goto done;

	if (start > 0)
		src1 = (src1 >> start);
	if (len < 64)
		src1 = src1 & ((1ull << len) - 1);
	dst = src1;

done:
	error = vie_update_register(vm, vcpuid, gpr_map[vie->reg], dst, size);
	if (error)
		return (error);

	/*
	 * AMD: OF, CF cleared; SF/AF/PF undefined; ZF set by result.
	 * Intel: ZF is set by result; AF/SF/PF undefined; all others cleared.
	 */
	rflags &= ~RFLAGS_STATUS_BITS;
	if (dst == 0)
		rflags |= PSL_Z;
	error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, rflags,
	    8);
	return (error);
}

static int
vie_emulate_add(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, size;
	uint64_t nval, rflags, rflags2, val1, val2;
	enum vm_reg_name reg;

	size = vie->opsize;
	error = EINVAL;

	switch (vie->op.op_byte) {
	case 0x03:
		/*
		 * ADD r/m to r and store the result in r
		 *
		 * 03/r			ADD r16, r/m16
		 * 03/r			ADD r32, r/m32
		 * REX.W + 03/r		ADD r64, r/m64
		 */

		/* get the first operand */
		reg = gpr_map[vie->reg];
		error = vm_get_register(vm, vcpuid, reg, &val1);
		if (error)
			break;

		/* get the second operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val2, size);
		if (error)
			break;

		/* perform the operation and write the result */
		nval = val1 + val2;
		error = vie_update_register(vm, vcpuid, reg, nval, size);
		break;
	default:
		break;
	}

	if (!error) {
		rflags2 = getaddflags(size, val1, val2);
		error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS,
		    &rflags);
		if (error)
			return (error);

		rflags &= ~RFLAGS_STATUS_BITS;
		rflags |= rflags2 & RFLAGS_STATUS_BITS;
		error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RFLAGS,
		    rflags, 8);
	}

	return (error);
}

static int
vie_emulate_sub(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, size;
	uint64_t nval, rflags, rflags2, val1, val2;
	enum vm_reg_name reg;

	size = vie->opsize;
	error = EINVAL;

	switch (vie->op.op_byte) {
	case 0x2B:
		/*
		 * SUB r/m from r and store the result in r
		 *
		 * 2B/r		SUB r16, r/m16
		 * 2B/r		SUB r32, r/m32
		 * REX.W + 2B/r	SUB r64, r/m64
		 */

		/* get the first operand */
		reg = gpr_map[vie->reg];
		error = vm_get_register(vm, vcpuid, reg, &val1);
		if (error)
			break;

		/* get the second operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val2, size);
		if (error)
			break;

		/* perform the operation and write the result */
		nval = val1 - val2;
		error = vie_update_register(vm, vcpuid, reg, nval, size);
		break;
	default:
		break;
	}

	if (!error) {
		rflags2 = getcc(size, val1, val2);
		error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS,
		    &rflags);
		if (error)
			return (error);

		rflags &= ~RFLAGS_STATUS_BITS;
		rflags |= rflags2 & RFLAGS_STATUS_BITS;
		error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RFLAGS,
		    rflags, 8);
	}

	return (error);
}

static int
vie_emulate_mul(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error, size;
	uint64_t rflags, rflags2, val1, val2;
	__int128_t nval;
	enum vm_reg_name reg;
	ulong_t (*getflags)(int, uint64_t, uint64_t) = NULL;

	size = vie->opsize;
	error = EINVAL;

	switch (vie->op.op_byte) {
	case 0xAF:
		/*
		 * Multiply the contents of a destination register by
		 * the contents of a register or memory operand and
		 * put the signed result in the destination register.
		 *
		 * AF/r		IMUL r16, r/m16
		 * AF/r		IMUL r32, r/m32
		 * REX.W + AF/r	IMUL r64, r/m64
		 */

		getflags = getimulflags;

		/* get the first operand */
		reg = gpr_map[vie->reg];
		error = vm_get_register(vm, vcpuid, reg, &val1);
		if (error != 0)
			break;

		/* get the second operand */
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val2, size);
		if (error != 0)
			break;

		/* perform the operation and write the result */
		nval = (int64_t)val1 * (int64_t)val2;

		error = vie_update_register(vm, vcpuid, reg, nval, size);

		DTRACE_PROBE4(vie__imul,
		    const char *, vie_regnum_name(vie->reg, size),
		    uint64_t, val1, uint64_t, val2, __uint128_t, nval);

		break;
	default:
		break;
	}

	if (error == 0) {
		rflags2 = getflags(size, val1, val2);
		error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS,
		    &rflags);
		if (error)
			return (error);

		rflags &= ~RFLAGS_STATUS_BITS;
		rflags |= rflags2 & RFLAGS_STATUS_BITS;
		error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RFLAGS,
		    rflags, 8);

		DTRACE_PROBE2(vie__imul__rflags,
		    uint64_t, rflags, uint64_t, rflags2);
	}

	return (error);
}

static int
vie_emulate_stack_op(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	struct vm_copyinfo copyinfo[2];
	struct seg_desc ss_desc;
	uint64_t cr0, rflags, rsp, stack_gla, val;
	int error, fault, size, stackaddrsize, pushop;
	struct vm_guest_paging *paging;

	val = 0;
	size = vie->opsize;
	pushop = (vie->op.op_type == VIE_OP_TYPE_PUSH) ? 1 : 0;
	paging = &vie->paging;

	/*
	 * From "Address-Size Attributes for Stack Accesses", Intel SDL, Vol 1
	 */
	if (paging->cpu_mode == CPU_MODE_REAL) {
		stackaddrsize = 2;
	} else if (paging->cpu_mode == CPU_MODE_64BIT) {
		/*
		 * "Stack Manipulation Instructions in 64-bit Mode", SDM, Vol 3
		 * - Stack pointer size is always 64-bits.
		 * - PUSH/POP of 32-bit values is not possible in 64-bit mode.
		 * - 16-bit PUSH/POP is supported by using the operand size
		 *   override prefix (66H).
		 */
		stackaddrsize = 8;
		size = vie->opsize_override ? 2 : 8;
	} else {
		/*
		 * In protected or compatibility mode the 'B' flag in the
		 * stack-segment descriptor determines the size of the
		 * stack pointer.
		 */
		error = vm_get_seg_desc(vm, vcpuid, VM_REG_GUEST_SS, &ss_desc);
		KASSERT(error == 0, ("%s: error %d getting SS descriptor",
		    __func__, error));
		if (SEG_DESC_DEF32(ss_desc.access))
			stackaddrsize = 4;
		else
			stackaddrsize = 2;
	}

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_CR0, &cr0);
	KASSERT(error == 0, ("%s: error %d getting cr0", __func__, error));

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	KASSERT(error == 0, ("%s: error %d getting rflags", __func__, error));

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RSP, &rsp);
	KASSERT(error == 0, ("%s: error %d getting rsp", __func__, error));
	if (pushop) {
		rsp -= size;
	}

	if (vie_calculate_gla(paging->cpu_mode, VM_REG_GUEST_SS, &ss_desc,
	    rsp, size, stackaddrsize, pushop ? PROT_WRITE : PROT_READ,
	    &stack_gla)) {
		vm_inject_ss(vm, vcpuid, 0);
		return (0);
	}

	if (vie_canonical_check(paging->cpu_mode, stack_gla)) {
		vm_inject_ss(vm, vcpuid, 0);
		return (0);
	}

	if (vie_alignment_check(paging->cpl, size, cr0, rflags, stack_gla)) {
		vm_inject_ac(vm, vcpuid, 0);
		return (0);
	}

	error = vm_copy_setup(vm, vcpuid, paging, stack_gla, size,
	    pushop ? PROT_WRITE : PROT_READ, copyinfo, nitems(copyinfo),
	    &fault);
	if (error || fault)
		return (error);

	if (pushop) {
		error = vie_mmio_read(vie, vm, vcpuid, gpa, &val, size);
		if (error == 0)
			vm_copyout(vm, vcpuid, &val, copyinfo, size);
	} else {
		vm_copyin(vm, vcpuid, copyinfo, &val, size);
		error = vie_mmio_write(vie, vm, vcpuid, gpa, val, size);
		rsp += size;
	}
	vm_copy_teardown(vm, vcpuid, copyinfo, nitems(copyinfo));

	if (error == 0) {
		error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RSP, rsp,
		    stackaddrsize);
		KASSERT(error == 0, ("error %d updating rsp", error));
	}
	return (error);
}

static int
vie_emulate_push(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error;

	/*
	 * Table A-6, "Opcode Extensions", Intel SDM, Vol 2.
	 *
	 * PUSH is part of the group 5 extended opcodes and is identified
	 * by ModRM:reg = b110.
	 */
	if ((vie->reg & 7) != 6)
		return (EINVAL);

	error = vie_emulate_stack_op(vie, vm, vcpuid, gpa);
	return (error);
}

static int
vie_emulate_pop(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error;

	/*
	 * Table A-6, "Opcode Extensions", Intel SDM, Vol 2.
	 *
	 * POP is part of the group 1A extended opcodes and is identified
	 * by ModRM:reg = b000.
	 */
	if ((vie->reg & 7) != 0)
		return (EINVAL);

	error = vie_emulate_stack_op(vie, vm, vcpuid, gpa);
	return (error);
}

static int
vie_emulate_group1(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	int error;

	switch (vie->reg & 7) {
	case 0x1:	/* OR */
		error = vie_emulate_or(vie, vm, vcpuid, gpa);
		break;
	case 0x4:	/* AND */
		error = vie_emulate_and(vie, vm, vcpuid, gpa);
		break;
	case 0x7:	/* CMP */
		error = vie_emulate_cmp(vie, vm, vcpuid, gpa);
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

static int
vie_emulate_bittest(struct vie *vie, struct vm *vm, int vcpuid, uint64_t gpa)
{
	uint64_t val, rflags;
	int error, bitmask, bitoff;

	/*
	 * 0F BA is a Group 8 extended opcode.
	 *
	 * Currently we only emulate the 'Bit Test' instruction which is
	 * identified by a ModR/M:reg encoding of 100b.
	 */
	if ((vie->reg & 7) != 4)
		return (EINVAL);

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, &rflags);
	KASSERT(error == 0, ("%s: error %d getting rflags", __func__, error));

	error = vie_mmio_read(vie, vm, vcpuid, gpa, &val, vie->opsize);
	if (error)
		return (error);

	/*
	 * Intel SDM, Vol 2, Table 3-2:
	 * "Range of Bit Positions Specified by Bit Offset Operands"
	 */
	bitmask = vie->opsize * 8 - 1;
	bitoff = vie->immediate & bitmask;

	/* Copy the bit into the Carry flag in %rflags */
	if (val & (1UL << bitoff))
		rflags |= PSL_C;
	else
		rflags &= ~PSL_C;

	error = vie_update_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, rflags, 8);
	KASSERT(error == 0, ("%s: error %d updating rflags", __func__, error));

	return (0);
}

static int
vie_emulate_twob_group15(struct vie *vie, struct vm *vm, int vcpuid,
    uint64_t gpa)
{
	int error;
	uint64_t buf;

	switch (vie->reg & 7) {
	case 0x7:	/* CLFLUSH, CLFLUSHOPT, and SFENCE */
		if (vie->mod == 0x3) {
			/*
			 * SFENCE.  Ignore it, VM exit provides enough
			 * barriers on its own.
			 */
			error = 0;
		} else {
			/*
			 * CLFLUSH, CLFLUSHOPT.  Only check for access
			 * rights.
			 */
			error = vie_mmio_read(vie, vm, vcpuid, gpa, &buf, 1);
		}
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

static int
vie_emulate_clts(struct vie *vie, struct vm *vm, int vcpuid)
{
	uint64_t val;
	int error __maybe_unused;

	if (vie->paging.cpl != 0) {
		vm_inject_gp(vm, vcpuid);
		vie->num_processed = 0;
		return (0);
	}

	error = vm_get_register(vm, vcpuid, VM_REG_GUEST_CR0, &val);
	ASSERT(error == 0);

	/* Clear %cr0.TS */
	val &= ~CR0_TS;

	error = vm_set_register(vm, vcpuid, VM_REG_GUEST_CR0, val);
	ASSERT(error == 0);

	return (0);
}

static int
vie_mmio_read(struct vie *vie, struct vm *vm, int cpuid, uint64_t gpa,
    uint64_t *rval, int bytes)
{
	int err;

	if (vie->mmio_req_read.state == VR_DONE) {
		ASSERT(vie->mmio_req_read.bytes == bytes);
		ASSERT(vie->mmio_req_read.gpa == gpa);

		*rval = vie->mmio_req_read.data;
		return (0);
	}

	err = vm_service_mmio_read(vm, cpuid, gpa, rval, bytes);
	if (err == 0) {
		/*
		 * A successful read from an in-kernel-emulated device may come
		 * with side effects, so stash the result in case it's used for
		 * an instruction which subsequently needs to issue an MMIO
		 * write to userspace.
		 */
		ASSERT(vie->mmio_req_read.state == VR_NONE);

		vie->mmio_req_read.bytes = bytes;
		vie->mmio_req_read.gpa = gpa;
		vie->mmio_req_read.data = *rval;
		vie->mmio_req_read.state = VR_DONE;

	} else if (err == ESRCH) {
		/* Hope that userspace emulation can fulfill this read */
		vie->mmio_req_read.bytes = bytes;
		vie->mmio_req_read.gpa = gpa;
		vie->mmio_req_read.state = VR_PENDING;
		vie->status |= VIES_PENDING_MMIO;
	} else if (err < 0) {
		/*
		 * The MMIO read failed in such a way that fallback to handling
		 * in userspace is required.
		 */
		vie->status |= VIES_USER_FALLBACK;
	}
	return (err);
}

static int
vie_mmio_write(struct vie *vie, struct vm *vm, int cpuid, uint64_t gpa,
    uint64_t wval, int bytes)
{
	int err;

	if (vie->mmio_req_write.state == VR_DONE) {
		ASSERT(vie->mmio_req_write.bytes == bytes);
		ASSERT(vie->mmio_req_write.gpa == gpa);

		return (0);
	}

	err = vm_service_mmio_write(vm, cpuid, gpa, wval, bytes);
	if (err == 0) {
		/*
		 * A successful write to an in-kernel-emulated device probably
		 * results in side effects, so stash the fact that such a write
		 * succeeded in case the operation requires other work.
		 */
		vie->mmio_req_write.bytes = bytes;
		vie->mmio_req_write.gpa = gpa;
		vie->mmio_req_write.data = wval;
		vie->mmio_req_write.state = VR_DONE;
	} else if (err == ESRCH) {
		/* Hope that userspace emulation can fulfill this write */
		vie->mmio_req_write.bytes = bytes;
		vie->mmio_req_write.gpa = gpa;
		vie->mmio_req_write.data = wval;
		vie->mmio_req_write.state = VR_PENDING;
		vie->status |= VIES_PENDING_MMIO;
	} else if (err < 0) {
		/*
		 * The MMIO write failed in such a way that fallback to handling
		 * in userspace is required.
		 */
		vie->status |= VIES_USER_FALLBACK;
	}
	return (err);
}

int
vie_emulate_mmio(struct vie *vie, struct vm *vm, int vcpuid)
{
	int error;
	uint64_t gpa;

	if ((vie->status & (VIES_INST_DECODE | VIES_MMIO)) !=
	    (VIES_INST_DECODE | VIES_MMIO)) {
		return (EINVAL);
	}

	gpa = vie->mmio_gpa;

	switch (vie->op.op_type) {
	case VIE_OP_TYPE_GROUP1:
		error = vie_emulate_group1(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_POP:
		error = vie_emulate_pop(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_PUSH:
		error = vie_emulate_push(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_CMP:
		error = vie_emulate_cmp(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_MOV:
		error = vie_emulate_mov(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_MOVSX:
	case VIE_OP_TYPE_MOVZX:
		error = vie_emulate_movx(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_MOVS:
		error = vie_emulate_movs(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_STOS:
		error = vie_emulate_stos(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_AND:
		error = vie_emulate_and(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_OR:
		error = vie_emulate_or(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_SUB:
		error = vie_emulate_sub(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_BITTEST:
		error = vie_emulate_bittest(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_TWOB_GRP15:
		error = vie_emulate_twob_group15(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_ADD:
		error = vie_emulate_add(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_TEST:
		error = vie_emulate_test(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_BEXTR:
		error = vie_emulate_bextr(vie, vm, vcpuid, gpa);
		break;
	case VIE_OP_TYPE_MUL:
		error = vie_emulate_mul(vie, vm, vcpuid, gpa);
		break;
	default:
		error = EINVAL;
		break;
	}

	if (error == ESRCH) {
		/* Return to userspace with the mmio request */
		return (-1);
	}

	return (error);
}

static int
vie_emulate_inout_port(struct vie *vie, struct vm *vm, int vcpuid,
    uint32_t *eax)
{
	uint32_t mask, val;
	bool in;
	int err;

	mask = vie_size2mask(vie->inout.bytes);
	in = (vie->inout.flags & INOUT_IN) != 0;

	if (!in) {
		val = *eax & mask;
	}

	if (vie->inout_req_state != VR_DONE) {
		err = vm_ioport_access(vm, vcpuid, in, vie->inout.port,
		    vie->inout.bytes, &val);
		val &= mask;
	} else {
		/*
		 * This port access was handled in userspace and the result was
		 * injected in to be handled now.
		 */
		val = vie->inout_req_val & mask;
		vie->inout_req_state = VR_NONE;
		err = 0;
	}

	if (err == ESRCH) {
		vie->status |= VIES_PENDING_INOUT;
		vie->inout_req_state = VR_PENDING;
		return (err);
	} else if (err != 0) {
		return (err);
	}

	if (in) {
		*eax = (*eax & ~mask) | val;
	}
	return (0);
}

static enum vm_reg_name
vie_inout_segname(const struct vie *vie)
{
	uint8_t segidx = vie->inout.segment;
	const enum vm_reg_name segmap[] = {
		VM_REG_GUEST_ES,
		VM_REG_GUEST_CS,
		VM_REG_GUEST_SS,
		VM_REG_GUEST_DS,
		VM_REG_GUEST_FS,
		VM_REG_GUEST_GS,
	};
	const uint8_t maxidx = (sizeof (segmap) / sizeof (segmap[0]));

	if (segidx >= maxidx) {
		panic("unexpected segment index %u", segidx);
	}
	return (segmap[segidx]);
}

static int
vie_emulate_inout_str(struct vie *vie, struct vm *vm, int vcpuid)
{
	uint8_t bytes, addrsize;
	uint64_t index, count = 0, gla, rflags;
	int prot, err, fault;
	bool in, repeat;
	enum vm_reg_name seg_reg, idx_reg;
	struct vm_copyinfo copyinfo[2];

	in = (vie->inout.flags & INOUT_IN) != 0;
	bytes = vie->inout.bytes;
	addrsize = vie->inout.addrsize;
	prot = in ? PROT_WRITE : PROT_READ;

	ASSERT(bytes == 1 || bytes == 2 || bytes == 4);
	ASSERT(addrsize == 2 || addrsize == 4 || addrsize == 8);

	idx_reg = (in) ? VM_REG_GUEST_RDI : VM_REG_GUEST_RSI;
	seg_reg = vie_inout_segname(vie);
	err = vm_get_register(vm, vcpuid, idx_reg, &index);
	ASSERT(err == 0);
	index = index & vie_size2mask(addrsize);

	repeat = (vie->inout.flags & INOUT_REP) != 0;

	/* Count register */
	if (repeat) {
		err = vm_get_register(vm, vcpuid, VM_REG_GUEST_RCX, &count);
		count &= vie_size2mask(addrsize);

		if (count == 0) {
			/*
			 * If we were asked to emulate a REP INS/OUTS when the
			 * count register is zero, no further work is required.
			 */
			return (0);
		}
	} else {
		count = 1;
	}

	gla = 0;
	if (vie_get_gla(vie, vm, vcpuid, bytes, addrsize, prot, seg_reg,
	    idx_reg, &gla) != 0) {
		/* vie_get_gla() already injected the appropriate fault */
		return (0);
	}

	/*
	 * The INS/OUTS emulate currently assumes that the memory target resides
	 * within the guest system memory, rather than a device MMIO region.  If
	 * such a case becomes a necessity, that additional handling could be
	 * put in place.
	 */
	err = vm_copy_setup(vm, vcpuid, &vie->paging, gla, bytes, prot,
	    copyinfo, nitems(copyinfo), &fault);

	if (err) {
		/* Unrecoverable error */
		return (err);
	} else if (fault) {
		/* Resume guest to handle fault */
		return (0);
	}

	if (!in) {
		vm_copyin(vm, vcpuid, copyinfo, &vie->inout.eax, bytes);
	}

	err = vie_emulate_inout_port(vie, vm, vcpuid, &vie->inout.eax);

	if (err == 0 && in) {
		vm_copyout(vm, vcpuid, &vie->inout.eax, copyinfo, bytes);
	}

	vm_copy_teardown(vm, vcpuid, copyinfo, nitems(copyinfo));

	if (err == 0) {
		err = vm_get_register(vm, vcpuid, VM_REG_GUEST_RFLAGS,
		    &rflags);
		ASSERT(err == 0);

		/* Update index */
		if (rflags & PSL_D) {
			index -= bytes;
		} else {
			index += bytes;
		}

		/* Update index register */
		err = vie_update_register(vm, vcpuid, idx_reg, index, addrsize);
		ASSERT(err == 0);

		/*
		 * Update count register only if the instruction had a repeat
		 * prefix.
		 */
		if ((vie->inout.flags & INOUT_REP) != 0) {
			count--;
			err = vie_update_register(vm, vcpuid, VM_REG_GUEST_RCX,
			    count, addrsize);
			ASSERT(err == 0);

			if (count != 0) {
				return (vie_repeat(vie));
			}
		}
	}

	return (err);
}

int
vie_emulate_inout(struct vie *vie, struct vm *vm, int vcpuid)
{
	int err = 0;

	if ((vie->status & VIES_INOUT) == 0) {
		return (EINVAL);
	}

	if ((vie->inout.flags & INOUT_STR) == 0) {
		/*
		 * For now, using the 'rep' prefixes with plain (non-string)
		 * in/out is not supported.
		 */
		if ((vie->inout.flags & INOUT_REP) != 0) {
			return (EINVAL);
		}

		err = vie_emulate_inout_port(vie, vm, vcpuid, &vie->inout.eax);
		if (err == 0 && (vie->inout.flags & INOUT_IN) != 0) {
			/*
			 * With the inX access now a success, the result needs
			 * to be stored in the guest %rax.
			 */
			err = vm_set_register(vm, vcpuid, VM_REG_GUEST_RAX,
			    vie->inout.eax);
			VERIFY0(err);
		}
	} else {
		vie->status &= ~VIES_REPEAT;
		err = vie_emulate_inout_str(vie, vm, vcpuid);

	}
	if (err < 0) {
		/*
		 * Access to an I/O port failed in such a way that fallback to
		 * handling in userspace is required.
		 */
		vie->status |= VIES_USER_FALLBACK;
	} else if (err == ESRCH) {
		ASSERT(vie->status & VIES_PENDING_INOUT);
		/* Return to userspace with the in/out request */
		err = -1;
	}

	return (err);
}

int
vie_emulate_other(struct vie *vie, struct vm *vm, int vcpuid)
{
	int error;

	if ((vie->status & (VIES_INST_DECODE | VIES_OTHER)) !=
	    (VIES_INST_DECODE | VIES_OTHER)) {
		return (EINVAL);
	}

	switch (vie->op.op_type) {
	case VIE_OP_TYPE_CLTS:
		error = vie_emulate_clts(vie, vm, vcpuid);
		break;
	case VIE_OP_TYPE_MOV_CR:
		error = vie_emulate_mov_cr(vie, vm, vcpuid);
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

void
vie_reset(struct vie *vie)
{
	vie->status = 0;
	vie->num_processed = vie->num_valid = 0;
}

void
vie_advance_pc(struct vie *vie, uint64_t *nextrip)
{
	VERIFY((vie->status & VIES_REPEAT) == 0);

	*nextrip += vie->num_processed;
	vie_reset(vie);
}

void
vie_exitinfo(const struct vie *vie, struct vm_exit *vme)
{
	if (vie->status & VIES_USER_FALLBACK) {
		/*
		 * Despite the fact that the instruction was successfully
		 * decoded, some aspect of the emulation failed in such a way
		 * that it is left up to userspace to complete the operation.
		 */
		vie_fallback_exitinfo(vie, vme);
	} else if (vie->status & VIES_MMIO) {
		vme->exitcode = VM_EXITCODE_MMIO;
		if (vie->mmio_req_read.state == VR_PENDING) {
			vme->u.mmio.gpa = vie->mmio_req_read.gpa;
			vme->u.mmio.data = 0;
			vme->u.mmio.bytes = vie->mmio_req_read.bytes;
			vme->u.mmio.read = 1;
		} else if (vie->mmio_req_write.state == VR_PENDING) {
			vme->u.mmio.gpa = vie->mmio_req_write.gpa;
			vme->u.mmio.data = vie->mmio_req_write.data &
			    vie_size2mask(vie->mmio_req_write.bytes);
			vme->u.mmio.bytes = vie->mmio_req_write.bytes;
			vme->u.mmio.read = 0;
		} else {
			panic("bad pending MMIO state");
		}
	} else if (vie->status & VIES_INOUT) {
		vme->exitcode = VM_EXITCODE_INOUT;
		vme->u.inout.port = vie->inout.port;
		vme->u.inout.bytes = vie->inout.bytes;
		if ((vie->inout.flags & INOUT_IN) != 0) {
			vme->u.inout.flags = INOUT_IN;
			vme->u.inout.eax = 0;
		} else {
			vme->u.inout.flags = 0;
			vme->u.inout.eax = vie->inout.eax &
			    vie_size2mask(vie->inout.bytes);
		}
	} else {
		panic("no pending operation");
	}
}

/*
 * In the case of a decoding or verification failure, bailing out to userspace
 * to do the instruction emulation is our only option for now.
 */
void
vie_fallback_exitinfo(const struct vie *vie, struct vm_exit *vme)
{
	if ((vie->status & VIES_INST_FETCH) == 0) {
		bzero(&vme->u.inst_emul, sizeof (vme->u.inst_emul));
	} else {
		ASSERT(sizeof (vie->inst) == sizeof (vme->u.inst_emul.inst));

		bcopy(vie->inst, vme->u.inst_emul.inst, sizeof (vie->inst));
		vme->u.inst_emul.num_valid = vie->num_valid;
	}
	vme->exitcode = VM_EXITCODE_INST_EMUL;
}

void
vie_cs_info(const struct vie *vie, struct vm *vm, int vcpuid, uint64_t *cs_base,
    int *cs_d)
{
	struct seg_desc cs_desc;
	int error __maybe_unused;

	error = vm_get_seg_desc(vm, vcpuid, VM_REG_GUEST_CS, &cs_desc);
	ASSERT(error == 0);

	/* Initialization required for the paging info to be populated */
	VERIFY(vie->status & VIES_INIT);
	switch (vie->paging.cpu_mode) {
	case CPU_MODE_REAL:
		*cs_base = cs_desc.base;
		*cs_d = 0;
		break;
	case CPU_MODE_PROTECTED:
	case CPU_MODE_COMPATIBILITY:
		*cs_base = cs_desc.base;
		*cs_d = SEG_DESC_DEF32(cs_desc.access) ? 1 : 0;
		break;
	default:
		*cs_base = 0;
		*cs_d = 0;
		break;
	}
}

bool
vie_pending(const struct vie *vie)
{
	/*
	 * These VIE status bits indicate conditions which must be addressed
	 * through either device IO fulfillment (with corresponding
	 * vie_fulfill_*()) or complete userspace emulation (followed by a
	 * vie_reset()).
	 */
	const enum vie_status of_interest =
	    VIES_PENDING_MMIO | VIES_PENDING_INOUT | VIES_USER_FALLBACK;

	return ((vie->status & of_interest) != 0);
}

bool
vie_needs_fetch(const struct vie *vie)
{
	if (vie->status & VIES_INST_FETCH) {
		ASSERT(vie->num_valid != 0);
		return (false);
	}
	return (true);
}

static int
vie_alignment_check(int cpl, int size, uint64_t cr0, uint64_t rf, uint64_t gla)
{
	KASSERT(size == 1 || size == 2 || size == 4 || size == 8,
	    ("%s: invalid size %d", __func__, size));
	KASSERT(cpl >= 0 && cpl <= 3, ("%s: invalid cpl %d", __func__, cpl));

	if (cpl != 3 || (cr0 & CR0_AM) == 0 || (rf & PSL_AC) == 0)
		return (0);

	return ((gla & (size - 1)) ? 1 : 0);
}

static int
vie_canonical_check(enum vm_cpu_mode cpu_mode, uint64_t gla)
{
	uint64_t mask;

	if (cpu_mode != CPU_MODE_64BIT)
		return (0);

	/*
	 * The value of the bit 47 in the 'gla' should be replicated in the
	 * most significant 16 bits.
	 */
	mask = ~((1UL << 48) - 1);
	if (gla & (1UL << 47))
		return ((gla & mask) != mask);
	else
		return ((gla & mask) != 0);
}

static uint64_t
vie_size2mask(int size)
{
	KASSERT(size == 1 || size == 2 || size == 4 || size == 8,
	    ("vie_size2mask: invalid size %d", size));
	return (size2mask[size]);
}

static int
vie_calculate_gla(enum vm_cpu_mode cpu_mode, enum vm_reg_name seg,
    struct seg_desc *desc, uint64_t offset, int length, int addrsize,
    int prot, uint64_t *gla)
{
	uint64_t firstoff, low_limit, high_limit, segbase;
	int glasize, type;

	KASSERT(seg >= VM_REG_GUEST_ES && seg <= VM_REG_GUEST_GS,
	    ("%s: invalid segment %d", __func__, seg));
	KASSERT(length == 1 || length == 2 || length == 4 || length == 8,
	    ("%s: invalid operand size %d", __func__, length));
	KASSERT((prot & ~(PROT_READ | PROT_WRITE)) == 0,
	    ("%s: invalid prot %x", __func__, prot));

	firstoff = offset;
	if (cpu_mode == CPU_MODE_64BIT) {
		KASSERT(addrsize == 4 || addrsize == 8, ("%s: invalid address "
		    "size %d for cpu_mode %d", __func__, addrsize, cpu_mode));
		glasize = 8;
	} else {
		KASSERT(addrsize == 2 || addrsize == 4, ("%s: invalid address "
		    "size %d for cpu mode %d", __func__, addrsize, cpu_mode));
		glasize = 4;
		/*
		 * If the segment selector is loaded with a NULL selector
		 * then the descriptor is unusable and attempting to use
		 * it results in a #GP(0).
		 */
		if (SEG_DESC_UNUSABLE(desc->access))
			return (-1);

		/*
		 * The processor generates a #NP exception when a segment
		 * register is loaded with a selector that points to a
		 * descriptor that is not present. If this was the case then
		 * it would have been checked before the VM-exit.
		 */
		KASSERT(SEG_DESC_PRESENT(desc->access),
		    ("segment %d not present: %x", seg, desc->access));

		/*
		 * The descriptor type must indicate a code/data segment.
		 */
		type = SEG_DESC_TYPE(desc->access);
		KASSERT(type >= 16 && type <= 31, ("segment %d has invalid "
		    "descriptor type %x", seg, type));

		if (prot & PROT_READ) {
			/* #GP on a read access to a exec-only code segment */
			if ((type & 0xA) == 0x8)
				return (-1);
		}

		if (prot & PROT_WRITE) {
			/*
			 * #GP on a write access to a code segment or a
			 * read-only data segment.
			 */
			if (type & 0x8)			/* code segment */
				return (-1);

			if ((type & 0xA) == 0)		/* read-only data seg */
				return (-1);
		}

		/*
		 * 'desc->limit' is fully expanded taking granularity into
		 * account.
		 */
		if ((type & 0xC) == 0x4) {
			/* expand-down data segment */
			low_limit = desc->limit + 1;
			high_limit = SEG_DESC_DEF32(desc->access) ?
			    0xffffffff : 0xffff;
		} else {
			/* code segment or expand-up data segment */
			low_limit = 0;
			high_limit = desc->limit;
		}

		while (length > 0) {
			offset &= vie_size2mask(addrsize);
			if (offset < low_limit || offset > high_limit)
				return (-1);
			offset++;
			length--;
		}
	}

	/*
	 * In 64-bit mode all segments except %fs and %gs have a segment
	 * base address of 0.
	 */
	if (cpu_mode == CPU_MODE_64BIT && seg != VM_REG_GUEST_FS &&
	    seg != VM_REG_GUEST_GS) {
		segbase = 0;
	} else {
		segbase = desc->base;
	}

	/*
	 * Truncate 'firstoff' to the effective address size before adding
	 * it to the segment base.
	 */
	firstoff &= vie_size2mask(addrsize);
	*gla = (segbase + firstoff) & vie_size2mask(glasize);
	return (0);
}

void
vie_init_mmio(struct vie *vie, const char *inst_bytes, uint8_t inst_length,
    const struct vm_guest_paging *paging, uint64_t gpa)
{
	KASSERT(inst_length <= VIE_INST_SIZE,
	    ("%s: invalid instruction length (%d)", __func__, inst_length));

	bzero(vie, sizeof (struct vie));

	vie->base_register = VM_REG_LAST;
	vie->index_register = VM_REG_LAST;
	vie->segment_register = VM_REG_LAST;
	vie->status = VIES_INIT | VIES_MMIO;

	if (inst_length != 0) {
		bcopy(inst_bytes, vie->inst, inst_length);
		vie->num_valid = inst_length;
		vie->status |= VIES_INST_FETCH;
	}

	vie->paging = *paging;
	vie->mmio_gpa = gpa;
}

void
vie_init_inout(struct vie *vie, const struct vm_inout *inout, uint8_t inst_len,
    const struct vm_guest_paging *paging)
{
	bzero(vie, sizeof (struct vie));

	vie->status = VIES_INIT | VIES_INOUT;

	vie->inout = *inout;
	vie->paging = *paging;

	/*
	 * Since VMX/SVM assists already decoded the nature of the in/out
	 * instruction, let the status reflect that.
	 */
	vie->status |= VIES_INST_FETCH | VIES_INST_DECODE;
	vie->num_processed = inst_len;
}

void
vie_init_other(struct vie *vie, const struct vm_guest_paging *paging)
{
	bzero(vie, sizeof (struct vie));

	vie->base_register = VM_REG_LAST;
	vie->index_register = VM_REG_LAST;
	vie->segment_register = VM_REG_LAST;
	vie->status = VIES_INIT | VIES_OTHER;

	vie->paging = *paging;
}

int
vie_fulfill_mmio(struct vie *vie, const struct vm_mmio *result)
{
	struct vie_mmio *pending;

	if ((vie->status & VIES_MMIO) == 0 ||
	    (vie->status & VIES_PENDING_MMIO) == 0) {
		return (EINVAL);
	}

	if (result->read) {
		pending = &vie->mmio_req_read;
	} else {
		pending = &vie->mmio_req_write;
	}

	if (pending->state != VR_PENDING ||
	    pending->bytes != result->bytes || pending->gpa != result->gpa) {
		return (EINVAL);
	}

	if (result->read) {
		pending->data = result->data & vie_size2mask(pending->bytes);
	}
	pending->state = VR_DONE;
	vie->status &= ~VIES_PENDING_MMIO;

	return (0);
}

int
vie_fulfill_inout(struct vie *vie, const struct vm_inout *result)
{
	if ((vie->status & VIES_INOUT) == 0 ||
	    (vie->status & VIES_PENDING_INOUT) == 0) {
		return (EINVAL);
	}
	if ((vie->inout.flags & INOUT_IN) != (result->flags & INOUT_IN) ||
	    vie->inout.bytes != result->bytes ||
	    vie->inout.port != result->port) {
		return (EINVAL);
	}

	if (result->flags & INOUT_IN) {
		vie->inout_req_val = result->eax &
		    vie_size2mask(vie->inout.bytes);
	}
	vie->inout_req_state = VR_DONE;
	vie->status &= ~(VIES_PENDING_INOUT);

	return (0);
}

uint64_t
vie_mmio_gpa(const struct vie *vie)
{
	return (vie->mmio_gpa);
}

static int
pf_error_code(int usermode, int prot, int rsvd, uint64_t pte)
{
	int error_code = 0;

	if (pte & PG_V)
		error_code |= PGEX_P;
	if (prot & PROT_WRITE)
		error_code |= PGEX_W;
	if (usermode)
		error_code |= PGEX_U;
	if (rsvd)
		error_code |= PGEX_RSV;
	if (prot & PROT_EXEC)
		error_code |= PGEX_I;

	return (error_code);
}

static void
ptp_release(vm_page_t **vmp)
{
	if (*vmp != NULL) {
		(void) vmp_release(*vmp);
		*vmp = NULL;
	}
}

static void *
ptp_hold(struct vm *vm, int vcpu, uintptr_t gpa, size_t len, vm_page_t **vmp)
{
	vm_client_t *vmc = vm_get_vmclient(vm, vcpu);
	const uintptr_t hold_gpa = gpa & PAGEMASK;

	/* Hold must not cross a page boundary */
	VERIFY3U(gpa + len, <=, hold_gpa + PAGESIZE);

	if (*vmp != NULL) {
		(void) vmp_release(*vmp);
	}

	*vmp = vmc_hold(vmc, hold_gpa, PROT_READ | PROT_WRITE);
	if (*vmp == NULL) {
		return (NULL);
	}

	return ((caddr_t)vmp_get_writable(*vmp) + (gpa - hold_gpa));
}

static int
_vm_gla2gpa(struct vm *vm, int vcpuid, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *guest_fault, bool check_only)
{
	int nlevels, pfcode;
	int ptpshift = 0, ptpindex = 0;
	uint64_t ptpphys;
	uint64_t *ptpbase = NULL, pte = 0, pgsize = 0;
	vm_page_t *cookie = NULL;
	const bool usermode = paging->cpl == 3;
	const bool writable = (prot & PROT_WRITE) != 0;

	*guest_fault = 0;
restart:
	ptpphys = paging->cr3;		/* root of the page tables */
	ptp_release(&cookie);

	if (vie_canonical_check(paging->cpu_mode, gla)) {
		/*
		 * XXX assuming a non-stack reference otherwise a stack fault
		 * should be generated.
		 */
		if (!check_only)
			vm_inject_gp(vm, vcpuid);
		*guest_fault = 1;
		return (0);
	}

	if (paging->paging_mode == PAGING_MODE_FLAT) {
		*gpa = gla;
		return (0);
	}

	if (paging->paging_mode == PAGING_MODE_32) {
		uint32_t *ptpbase32, pte32;

		nlevels = 2;
		while (--nlevels >= 0) {
			/* Zero out the lower 12 bits. */
			ptpphys &= ~0xfff;

			ptpbase32 = ptp_hold(vm, vcpuid, ptpphys, PAGE_SIZE,
			    &cookie);

			if (ptpbase32 == NULL) {
				return (EFAULT);
			}

			ptpshift = PAGE_SHIFT + nlevels * 10;
			ptpindex = (gla >> ptpshift) & 0x3FF;
			pgsize = 1UL << ptpshift;

			pte32 = ptpbase32[ptpindex];

			if ((pte32 & PG_V) == 0 ||
			    (usermode && (pte32 & PG_U) == 0) ||
			    (writable && (pte32 & PG_RW) == 0)) {
				if (!check_only) {
					pfcode = pf_error_code(usermode, prot,
					    0, pte32);
					vm_inject_pf(vm, vcpuid, pfcode, gla);
				}

				ptp_release(&cookie);
				*guest_fault = 1;
				return (0);
			}

			/*
			 * Emulate the x86 MMU's management of the accessed
			 * and dirty flags. While the accessed flag is set
			 * at every level of the page table, the dirty flag
			 * is only set at the last level providing the guest
			 * physical address.
			 */
			if (!check_only && (pte32 & PG_A) == 0) {
				if (atomic_cmpset_32(&ptpbase32[ptpindex],
				    pte32, pte32 | PG_A) == 0) {
					goto restart;
				}
			}

			/* XXX must be ignored if CR4.PSE=0 */
			if (nlevels > 0 && (pte32 & PG_PS) != 0)
				break;

			ptpphys = pte32;
		}

		/* Set the dirty bit in the page table entry if necessary */
		if (!check_only && writable && (pte32 & PG_M) == 0) {
			if (atomic_cmpset_32(&ptpbase32[ptpindex],
			    pte32, pte32 | PG_M) == 0) {
				goto restart;
			}
		}

		/* Zero out the lower 'ptpshift' bits */
		pte32 >>= ptpshift; pte32 <<= ptpshift;
		*gpa = pte32 | (gla & (pgsize - 1));
		ptp_release(&cookie);
		return (0);
	}

	if (paging->paging_mode == PAGING_MODE_PAE) {
		/* Zero out the lower 5 bits and the upper 32 bits */
		ptpphys &= 0xffffffe0UL;

		ptpbase = ptp_hold(vm, vcpuid, ptpphys, sizeof (*ptpbase) * 4,
		    &cookie);
		if (ptpbase == NULL) {
			return (EFAULT);
		}

		ptpindex = (gla >> 30) & 0x3;

		pte = ptpbase[ptpindex];

		if ((pte & PG_V) == 0) {
			if (!check_only) {
				pfcode = pf_error_code(usermode, prot, 0, pte);
				vm_inject_pf(vm, vcpuid, pfcode, gla);
			}

			ptp_release(&cookie);
			*guest_fault = 1;
			return (0);
		}

		ptpphys = pte;

		nlevels = 2;
	} else {
		nlevels = 4;
	}

	while (--nlevels >= 0) {
		/* Zero out the lower 12 bits and the upper 12 bits */
		ptpphys &= 0x000ffffffffff000UL;

		ptpbase = ptp_hold(vm, vcpuid, ptpphys, PAGE_SIZE, &cookie);
		if (ptpbase == NULL) {
			return (EFAULT);
		}

		ptpshift = PAGE_SHIFT + nlevels * 9;
		ptpindex = (gla >> ptpshift) & 0x1FF;
		pgsize = 1UL << ptpshift;

		pte = ptpbase[ptpindex];

		if ((pte & PG_V) == 0 ||
		    (usermode && (pte & PG_U) == 0) ||
		    (writable && (pte & PG_RW) == 0)) {
			if (!check_only) {
				pfcode = pf_error_code(usermode, prot, 0, pte);
				vm_inject_pf(vm, vcpuid, pfcode, gla);
			}

			ptp_release(&cookie);
			*guest_fault = 1;
			return (0);
		}

		/* Set the accessed bit in the page table entry */
		if (!check_only && (pte & PG_A) == 0) {
			if (atomic_cmpset_64(&ptpbase[ptpindex],
			    pte, pte | PG_A) == 0) {
				goto restart;
			}
		}

		if (nlevels > 0 && (pte & PG_PS) != 0) {
			if (pgsize > 1 * GB) {
				if (!check_only) {
					pfcode = pf_error_code(usermode, prot,
					    1, pte);
					vm_inject_pf(vm, vcpuid, pfcode, gla);
				}

				ptp_release(&cookie);
				*guest_fault = 1;
				return (0);
			}
			break;
		}

		ptpphys = pte;
	}

	/* Set the dirty bit in the page table entry if necessary */
	if (!check_only && writable && (pte & PG_M) == 0) {
		if (atomic_cmpset_64(&ptpbase[ptpindex], pte, pte | PG_M) == 0)
			goto restart;
	}
	ptp_release(&cookie);

	/* Zero out the lower 'ptpshift' bits and the upper 12 bits */
	pte >>= ptpshift; pte <<= (ptpshift + 12); pte >>= 12;
	*gpa = pte | (gla & (pgsize - 1));
	return (0);
}

int
vm_gla2gpa(struct vm *vm, int vcpuid, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *guest_fault)
{

	return (_vm_gla2gpa(vm, vcpuid, paging, gla, prot, gpa, guest_fault,
	    false));
}

int
vm_gla2gpa_nofault(struct vm *vm, int vcpuid, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *guest_fault)
{

	return (_vm_gla2gpa(vm, vcpuid, paging, gla, prot, gpa, guest_fault,
	    true));
}

int
vie_fetch_instruction(struct vie *vie, struct vm *vm, int vcpuid, uint64_t rip,
    int *faultptr)
{
	struct vm_copyinfo copyinfo[2];
	int error, prot;

	if ((vie->status & VIES_INIT) == 0) {
		return (EINVAL);
	}

	prot = PROT_READ | PROT_EXEC;
	error = vm_copy_setup(vm, vcpuid, &vie->paging, rip, VIE_INST_SIZE,
	    prot, copyinfo, nitems(copyinfo), faultptr);
	if (error || *faultptr)
		return (error);

	vm_copyin(vm, vcpuid, copyinfo, vie->inst, VIE_INST_SIZE);
	vm_copy_teardown(vm, vcpuid, copyinfo, nitems(copyinfo));
	vie->num_valid = VIE_INST_SIZE;
	vie->status |= VIES_INST_FETCH;
	return (0);
}

static int
vie_peek(struct vie *vie, uint8_t *x)
{

	if (vie->num_processed < vie->num_valid) {
		*x = vie->inst[vie->num_processed];
		return (0);
	} else
		return (-1);
}

static void
vie_advance(struct vie *vie)
{

	vie->num_processed++;
}

static bool
segment_override(uint8_t x, int *seg)
{

	switch (x) {
	case 0x2E:
		*seg = VM_REG_GUEST_CS;
		break;
	case 0x36:
		*seg = VM_REG_GUEST_SS;
		break;
	case 0x3E:
		*seg = VM_REG_GUEST_DS;
		break;
	case 0x26:
		*seg = VM_REG_GUEST_ES;
		break;
	case 0x64:
		*seg = VM_REG_GUEST_FS;
		break;
	case 0x65:
		*seg = VM_REG_GUEST_GS;
		break;
	default:
		return (false);
	}
	return (true);
}

static int
decode_prefixes(struct vie *vie, enum vm_cpu_mode cpu_mode, int cs_d)
{
	uint8_t x;

	while (1) {
		if (vie_peek(vie, &x))
			return (-1);

		if (x == 0x66)
			vie->opsize_override = 1;
		else if (x == 0x67)
			vie->addrsize_override = 1;
		else if (x == 0xF3)
			vie->repz_present = 1;
		else if (x == 0xF2)
			vie->repnz_present = 1;
		else if (segment_override(x, &vie->segment_register))
			vie->segment_override = 1;
		else
			break;

		vie_advance(vie);
	}

	/*
	 * From section 2.2.1, "REX Prefixes", Intel SDM Vol 2:
	 * - Only one REX prefix is allowed per instruction.
	 * - The REX prefix must immediately precede the opcode byte or the
	 *   escape opcode byte.
	 * - If an instruction has a mandatory prefix (0x66, 0xF2 or 0xF3)
	 *   the mandatory prefix must come before the REX prefix.
	 */
	if (cpu_mode == CPU_MODE_64BIT && x >= 0x40 && x <= 0x4F) {
		vie->rex_present = 1;
		vie->rex_w = x & 0x8 ? 1 : 0;
		vie->rex_r = x & 0x4 ? 1 : 0;
		vie->rex_x = x & 0x2 ? 1 : 0;
		vie->rex_b = x & 0x1 ? 1 : 0;
		vie_advance(vie);
	}

	/*
	 * § 2.3.5, "The VEX Prefix", SDM Vol 2.
	 */
	if ((cpu_mode == CPU_MODE_64BIT ||
	    cpu_mode == CPU_MODE_COMPATIBILITY) && x == 0xC4) {
		const struct vie_op *optab;

		/* 3-byte VEX prefix. */
		vie->vex_present = 1;

		vie_advance(vie);
		if (vie_peek(vie, &x))
			return (-1);

		/*
		 * 2nd byte: [R', X', B', mmmmm[4:0]].  Bits are inverted
		 * relative to REX encoding.
		 */
		vie->rex_r = x & 0x80 ? 0 : 1;
		vie->rex_x = x & 0x40 ? 0 : 1;
		vie->rex_b = x & 0x20 ? 0 : 1;

		switch (x & 0x1F) {
		case 0x2:
			/* 0F 38. */
			optab = three_byte_opcodes_0f38;
			break;
		case 0x1:
			/* 0F class - nothing handled here yet. */
			/* FALLTHROUGH */
		case 0x3:
			/* 0F 3A class - nothing handled here yet. */
			/* FALLTHROUGH */
		default:
			/* Reserved (#UD). */
			return (-1);
		}

		vie_advance(vie);
		if (vie_peek(vie, &x))
			return (-1);

		/* 3rd byte: [W, vvvv[6:3], L, pp[1:0]]. */
		vie->rex_w = x & 0x80 ? 1 : 0;

		vie->vex_reg = ((~(unsigned)x & 0x78u) >> 3);
		vie->vex_l = !!(x & 0x4);
		vie->vex_pp = (x & 0x3);

		/* PP: 1=66 2=F3 3=F2 prefixes. */
		switch (vie->vex_pp) {
		case 0x1:
			vie->opsize_override = 1;
			break;
		case 0x2:
			vie->repz_present = 1;
			break;
		case 0x3:
			vie->repnz_present = 1;
			break;
		}

		vie_advance(vie);

		/* Opcode, sans literal prefix prefix. */
		if (vie_peek(vie, &x))
			return (-1);

		vie->op = optab[x];
		if (vie->op.op_type == VIE_OP_TYPE_NONE)
			return (-1);

		vie_advance(vie);
	}

	/*
	 * Section "Operand-Size And Address-Size Attributes", Intel SDM, Vol 1
	 */
	if (cpu_mode == CPU_MODE_64BIT) {
		/*
		 * Default address size is 64-bits and default operand size
		 * is 32-bits.
		 */
		vie->addrsize = vie->addrsize_override ? 4 : 8;
		if (vie->rex_w)
			vie->opsize = 8;
		else if (vie->opsize_override)
			vie->opsize = 2;
		else
			vie->opsize = 4;
	} else if (cs_d) {
		/* Default address and operand sizes are 32-bits */
		vie->addrsize = vie->addrsize_override ? 2 : 4;
		vie->opsize = vie->opsize_override ? 2 : 4;
	} else {
		/* Default address and operand sizes are 16-bits */
		vie->addrsize = vie->addrsize_override ? 4 : 2;
		vie->opsize = vie->opsize_override ? 4 : 2;
	}
	return (0);
}

static int
decode_two_byte_opcode(struct vie *vie)
{
	uint8_t x;

	if (vie_peek(vie, &x))
		return (-1);

	vie->op = two_byte_opcodes[x];

	if (vie->op.op_type == VIE_OP_TYPE_NONE)
		return (-1);

	vie_advance(vie);
	return (0);
}

static int
decode_opcode(struct vie *vie)
{
	uint8_t x;

	if (vie_peek(vie, &x))
		return (-1);

	/* Already did this via VEX prefix. */
	if (vie->op.op_type != VIE_OP_TYPE_NONE)
		return (0);

	vie->op = one_byte_opcodes[x];

	if (vie->op.op_type == VIE_OP_TYPE_NONE)
		return (-1);

	vie_advance(vie);

	if (vie->op.op_type == VIE_OP_TYPE_TWO_BYTE)
		return (decode_two_byte_opcode(vie));

	return (0);
}

static int
decode_modrm(struct vie *vie, enum vm_cpu_mode cpu_mode)
{
	uint8_t x;
	/*
	 * Handling mov-to/from-cr is special since it is not issuing
	 * mmio/pio requests and can be done in real mode.  We must bypass some
	 * of the other existing decoding restrictions for it.
	 */
	const bool is_movcr = ((vie->op.op_flags & VIE_OP_F_REG_REG) != 0);

	if (vie->op.op_flags & VIE_OP_F_NO_MODRM)
		return (0);

	if (cpu_mode == CPU_MODE_REAL && !is_movcr)
		return (-1);

	if (vie_peek(vie, &x))
		return (-1);

	vie->mod = (x >> 6) & 0x3;
	vie->rm =  (x >> 0) & 0x7;
	vie->reg = (x >> 3) & 0x7;

	/*
	 * A direct addressing mode makes no sense in the context of an EPT
	 * fault. There has to be a memory access involved to cause the
	 * EPT fault.
	 */
	if (vie->mod == VIE_MOD_DIRECT && !is_movcr)
		return (-1);

	if ((vie->mod == VIE_MOD_INDIRECT && vie->rm == VIE_RM_DISP32) ||
	    (vie->mod != VIE_MOD_DIRECT && vie->rm == VIE_RM_SIB)) {
		/*
		 * Table 2-5: Special Cases of REX Encodings
		 *
		 * mod=0, r/m=5 is used in the compatibility mode to
		 * indicate a disp32 without a base register.
		 *
		 * mod!=3, r/m=4 is used in the compatibility mode to
		 * indicate that the SIB byte is present.
		 *
		 * The 'b' bit in the REX prefix is don't care in
		 * this case.
		 */
	} else {
		vie->rm |= (vie->rex_b << 3);
	}

	vie->reg |= (vie->rex_r << 3);

	/* SIB */
	if (vie->mod != VIE_MOD_DIRECT && vie->rm == VIE_RM_SIB)
		goto done;

	vie->base_register = gpr_map[vie->rm];

	switch (vie->mod) {
	case VIE_MOD_INDIRECT_DISP8:
		vie->disp_bytes = 1;
		break;
	case VIE_MOD_INDIRECT_DISP32:
		vie->disp_bytes = 4;
		break;
	case VIE_MOD_INDIRECT:
		if (vie->rm == VIE_RM_DISP32) {
			vie->disp_bytes = 4;
			/*
			 * Table 2-7. RIP-Relative Addressing
			 *
			 * In 64-bit mode mod=00 r/m=101 implies [rip] + disp32
			 * whereas in compatibility mode it just implies disp32.
			 */

			if (cpu_mode == CPU_MODE_64BIT)
				vie->base_register = VM_REG_GUEST_RIP;
			else
				vie->base_register = VM_REG_LAST;
		}
		break;
	}

done:
	vie_advance(vie);

	return (0);
}

static int
decode_sib(struct vie *vie)
{
	uint8_t x;

	/* Proceed only if SIB byte is present */
	if (vie->mod == VIE_MOD_DIRECT || vie->rm != VIE_RM_SIB)
		return (0);

	if (vie_peek(vie, &x))
		return (-1);

	/* De-construct the SIB byte */
	vie->ss = (x >> 6) & 0x3;
	vie->index = (x >> 3) & 0x7;
	vie->base = (x >> 0) & 0x7;

	/* Apply the REX prefix modifiers */
	vie->index |= vie->rex_x << 3;
	vie->base |= vie->rex_b << 3;

	switch (vie->mod) {
	case VIE_MOD_INDIRECT_DISP8:
		vie->disp_bytes = 1;
		break;
	case VIE_MOD_INDIRECT_DISP32:
		vie->disp_bytes = 4;
		break;
	}

	if (vie->mod == VIE_MOD_INDIRECT &&
	    (vie->base == 5 || vie->base == 13)) {
		/*
		 * Special case when base register is unused if mod = 0
		 * and base = %rbp or %r13.
		 *
		 * Documented in:
		 * Table 2-3: 32-bit Addressing Forms with the SIB Byte
		 * Table 2-5: Special Cases of REX Encodings
		 */
		vie->disp_bytes = 4;
	} else {
		vie->base_register = gpr_map[vie->base];
	}

	/*
	 * All encodings of 'index' are valid except for %rsp (4).
	 *
	 * Documented in:
	 * Table 2-3: 32-bit Addressing Forms with the SIB Byte
	 * Table 2-5: Special Cases of REX Encodings
	 */
	if (vie->index != 4)
		vie->index_register = gpr_map[vie->index];

	/* 'scale' makes sense only in the context of an index register */
	if (vie->index_register < VM_REG_LAST)
		vie->scale = 1 << vie->ss;

	vie_advance(vie);

	return (0);
}

static int
decode_displacement(struct vie *vie)
{
	int n, i;
	uint8_t x;

	union {
		char	buf[4];
		int8_t	signed8;
		int32_t	signed32;
	} u;

	if ((n = vie->disp_bytes) == 0)
		return (0);

	if (n != 1 && n != 4)
		panic("decode_displacement: invalid disp_bytes %d", n);

	for (i = 0; i < n; i++) {
		if (vie_peek(vie, &x))
			return (-1);

		u.buf[i] = x;
		vie_advance(vie);
	}

	if (n == 1)
		vie->displacement = u.signed8;		/* sign-extended */
	else
		vie->displacement = u.signed32;		/* sign-extended */

	return (0);
}

static int
decode_immediate(struct vie *vie)
{
	int i, n;
	uint8_t x;
	union {
		char	buf[4];
		int8_t	signed8;
		int16_t	signed16;
		int32_t	signed32;
	} u;

	/* Figure out immediate operand size (if any) */
	if (vie->op.op_flags & VIE_OP_F_IMM) {
		/*
		 * Section 2.2.1.5 "Immediates", Intel SDM:
		 * In 64-bit mode the typical size of immediate operands
		 * remains 32-bits. When the operand size if 64-bits, the
		 * processor sign-extends all immediates to 64-bits prior
		 * to their use.
		 */
		if (vie->opsize == 4 || vie->opsize == 8)
			vie->imm_bytes = 4;
		else
			vie->imm_bytes = 2;
	} else if (vie->op.op_flags & VIE_OP_F_IMM8) {
		vie->imm_bytes = 1;
	}

	if ((n = vie->imm_bytes) == 0)
		return (0);

	KASSERT(n == 1 || n == 2 || n == 4,
	    ("%s: invalid number of immediate bytes: %d", __func__, n));

	for (i = 0; i < n; i++) {
		if (vie_peek(vie, &x))
			return (-1);

		u.buf[i] = x;
		vie_advance(vie);
	}

	/* sign-extend the immediate value before use */
	if (n == 1)
		vie->immediate = u.signed8;
	else if (n == 2)
		vie->immediate = u.signed16;
	else
		vie->immediate = u.signed32;

	return (0);
}

static int
decode_moffset(struct vie *vie)
{
	int i, n;
	uint8_t x;
	union {
		char	buf[8];
		uint64_t u64;
	} u;

	if ((vie->op.op_flags & VIE_OP_F_MOFFSET) == 0)
		return (0);

	/*
	 * Section 2.2.1.4, "Direct Memory-Offset MOVs", Intel SDM:
	 * The memory offset size follows the address-size of the instruction.
	 */
	n = vie->addrsize;
	KASSERT(n == 2 || n == 4 || n == 8, ("invalid moffset bytes: %d", n));

	u.u64 = 0;
	for (i = 0; i < n; i++) {
		if (vie_peek(vie, &x))
			return (-1);

		u.buf[i] = x;
		vie_advance(vie);
	}
	vie->displacement = u.u64;
	return (0);
}

/*
 * Verify that the 'guest linear address' provided as collateral of the nested
 * page table fault matches with our instruction decoding.
 */
int
vie_verify_gla(struct vie *vie, struct vm *vm, int cpuid, uint64_t gla)
{
	int error;
	uint64_t base, segbase, idx, gla2;
	enum vm_reg_name seg;
	struct seg_desc desc;

	ASSERT((vie->status & VIES_INST_DECODE) != 0);

	/*
	 * If there was no valid GLA context with the exit, or the decoded
	 * instruction acts on more than one address, verification is done.
	 */
	if (gla == VIE_INVALID_GLA ||
	    (vie->op.op_flags & VIE_OP_F_NO_GLA_VERIFICATION) != 0) {
		return (0);
	}

	base = 0;
	if (vie->base_register != VM_REG_LAST) {
		error = vm_get_register(vm, cpuid, vie->base_register, &base);
		if (error) {
			printf("verify_gla: error %d getting base reg %d\n",
			    error, vie->base_register);
			return (-1);
		}

		/*
		 * RIP-relative addressing starts from the following
		 * instruction
		 */
		if (vie->base_register == VM_REG_GUEST_RIP)
			base += vie->num_processed;
	}

	idx = 0;
	if (vie->index_register != VM_REG_LAST) {
		error = vm_get_register(vm, cpuid, vie->index_register, &idx);
		if (error) {
			printf("verify_gla: error %d getting index reg %d\n",
			    error, vie->index_register);
			return (-1);
		}
	}

	/*
	 * From "Specifying a Segment Selector", Intel SDM, Vol 1
	 *
	 * In 64-bit mode, segmentation is generally (but not
	 * completely) disabled.  The exceptions are the FS and GS
	 * segments.
	 *
	 * In legacy IA-32 mode, when the ESP or EBP register is used
	 * as the base, the SS segment is the default segment.  For
	 * other data references, except when relative to stack or
	 * string destination the DS segment is the default.  These
	 * can be overridden to allow other segments to be accessed.
	 */
	if (vie->segment_override) {
		seg = vie->segment_register;
	} else if (vie->base_register == VM_REG_GUEST_RSP ||
	    vie->base_register == VM_REG_GUEST_RBP) {
		seg = VM_REG_GUEST_SS;
	} else {
		seg = VM_REG_GUEST_DS;
	}
	if (vie->paging.cpu_mode == CPU_MODE_64BIT &&
	    seg != VM_REG_GUEST_FS && seg != VM_REG_GUEST_GS) {
		segbase = 0;
	} else {
		error = vm_get_seg_desc(vm, cpuid, seg, &desc);
		if (error) {
			printf("verify_gla: error %d getting segment"
			    " descriptor %d", error, vie->segment_register);
			return (-1);
		}
		segbase = desc.base;
	}

	gla2 = segbase + base + vie->scale * idx + vie->displacement;
	gla2 &= size2mask[vie->addrsize];
	if (gla != gla2) {
		printf("verify_gla mismatch: segbase(0x%0lx)"
		    "base(0x%0lx), scale(%d), index(0x%0lx), "
		    "disp(0x%0lx), gla(0x%0lx), gla2(0x%0lx)\n",
		    segbase, base, vie->scale, idx, vie->displacement,
		    gla, gla2);
		return (-1);
	}

	return (0);
}

int
vie_decode_instruction(struct vie *vie, struct vm *vm, int cpuid, int cs_d)
{
	enum vm_cpu_mode cpu_mode;

	if ((vie->status & VIES_INST_FETCH) == 0) {
		return (EINVAL);
	}

	cpu_mode = vie->paging.cpu_mode;

	if (decode_prefixes(vie, cpu_mode, cs_d))
		return (-1);

	if (decode_opcode(vie))
		return (-1);

	if (decode_modrm(vie, cpu_mode))
		return (-1);

	if (decode_sib(vie))
		return (-1);

	if (decode_displacement(vie))
		return (-1);

	if (decode_immediate(vie))
		return (-1);

	if (decode_moffset(vie))
		return (-1);

	vie->status |= VIES_INST_DECODE;

	return (0);
}
