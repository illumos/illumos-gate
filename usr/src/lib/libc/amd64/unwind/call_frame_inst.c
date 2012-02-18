/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * interface used by unwind support to query frame descriptor info
 */

#ifndef _LIBCRUN_
#include "lint.h"
#endif
#include <sys/types.h>
#include "stack_unwind.h"
#include "unwind_context.h"
#include "reg_num.h"

enum CFA_ops {
	DW_CFA_nop = 0x00,
	DW_CFA_set_loc = 0x01,
	DW_CFA_advance_loc1 = 0x02,
	DW_CFA_advance_loc2 = 0x03,
	DW_CFA_advance_loc4 = 0x04,
	DW_CFA_offset_extended = 0x05,
	DW_CFA_restore_extended = 0x06,
	DW_CFA_undefined = 0x07,
	DW_CFA_same_value = 0x08,
	DW_CFA_register = 0x09,
	DW_CFA_remember_state = 0x0a,
	DW_CFA_restore_state = 0x0b,
	DW_CFA_def_cfa = 0x0c,
	DW_CFA_def_cfa_register = 0x0d,
	DW_CFA_def_cfa_offset = 0x0e,
	DW_CFA_def_cfa_expression = 0x0f,
	DW_CFA_expression = 0x10,
	DW_CFA_offset_extended_sf = 0x11,
	DW_CFA_def_cfa_sf = 0x12,
	DW_CFA_def_cfa_offset_sf = 0x13,
	/* skip 9 values */
	DW_CFA_SUNW_advance_loc = 0x1d,
	DW_CFA_SUNW_offset = 0x1e,
	DW_CFA_SUNW_restore = 0x1f,
	DW_CFA_advance_loc = 0x40,
	DW_CFA_offset = 0x80,
	DW_CFA_restore = 0xc0
};

struct operation_desc {
	enum operand_desc op1;
	enum operand_desc op2;
};

struct operation_desc cfa_operations[] = {
	{NO_OPR, NO_OPR},	/* DW_CFA_nop */
	{ADDR, NO_OPR},		/* DW_CFA_set_loc - address */
	{UNUM8, NO_OPR},	/* DW_CFA_advance_loc1 - delta */
	{UNUM16, NO_OPR},	/* DW_CFA_advance_loc2 - delta */
	{UNUM32, NO_OPR},	/* DW_CFA_advance_loc4 - delta */
	{ULEB128, ULEB128_FAC},	/* DW_CFA_offset_extended - reg, */
				/* data factored offset */
	{ULEB128, NO_OPR},	/* DW_CFA_restore_extended - register */
	{ULEB128, NO_OPR},	/* DW_CFA_undefined - register */
	{ULEB128, NO_OPR},	/* DW_CFA_same_value - register */
	{ULEB128, ULEB128_SREG}, /* DW_CFA_register - register, register */
	{NO_OPR, NO_OPR},	/* DW_CFA_remember_state */
	{NO_OPR, NO_OPR},	/* DW_CFA_restore_state */
	{ULEB128_SREG, ULEB128}, /* DW_CFA_def_cfa - register, offset */
	{ULEB128_SREG, NO_OPR},	/* DW_CFA_def_cfa_register - register */
	{ULEB128, NO_OPR},	/* DW_CFA_def_cfa_offset - offset */
	{BLOCK, NO_OPR},	/* DW_CFA_def_cfa_expression - expression */
	{ULEB128, BLOCK},	/* DW_CFA_expression - reg, expression */
	{ULEB128, SLEB128_FAC},	/* DW_CFA_offset_extended_sf - reg, */
				/* data factored offset */
	{ULEB128_SREG, SLEB128_FAC},	/* DW_CFA_def_cfa_sf - reg, */
					/* data factored offset */
	{SLEB128_FAC, NO_OPR},	/* DW_CFA_def_cfa_offset_sf - */
				/* data fctored offset */
	{NO_OPR, NO_OPR},
	{NO_OPR, NO_OPR},
	{NO_OPR, NO_OPR},
	{NO_OPR, NO_OPR},
	{NO_OPR, NO_OPR},
	{NO_OPR, NO_OPR},
	{NO_OPR, NO_OPR},
	{NO_OPR, NO_OPR},
	{NO_OPR, NO_OPR},
	{UNUM6_CFAC, NO_OPR},	/* DW_CFA_SUNW_advance_loc - */
				/* code factored delta */
	{UNUM6, ULEB128_FAC},	/* DW_CFA_SUNW_offset - reg */
				/* data factored offset */
	{UNUM6, NO_OPR}		/* DW_CFA_SUNW_restore */
};

uint64_t interpret_ops(void *data, void *data_end,
		ptrdiff_t reloc, uint64_t current_loc, uint64_t pc,
		struct register_state f_state[],
		struct register_state f_start_state[],
		int daf, int caf, int enc);

/*
 * The entry-point state of old_ctx defines the current
 * suspended state of the caller (in new_ctx). If the old info
 * will not be refered to again, old_ctx == new_ctx is OK
 */
void
_Unw_Propagate_Registers(struct _Unwind_Context *old_ctx,
	struct _Unwind_Context *new_ctx)
{
	new_ctx->current_regs[SP_RSP] = old_ctx->cfa;
	new_ctx->pc = old_ctx->ra;
	new_ctx->current_regs[FP_RBP] = old_ctx->entry_regs[FP_RBP];
	new_ctx->current_regs[GPR_RBX] = old_ctx->entry_regs[GPR_RBX];
	new_ctx->current_regs[EIR_R12] = old_ctx->entry_regs[EIR_R12];
	new_ctx->current_regs[EIR_R13] = old_ctx->entry_regs[EIR_R13];
	new_ctx->current_regs[EIR_R14] = old_ctx->entry_regs[EIR_R14];
	new_ctx->current_regs[EIR_R15] = old_ctx->entry_regs[EIR_R15];
}

void
fix_cfa(struct _Unwind_Context *ctx, struct register_state *rs)
{
	switch (rs[CF_ADDR].rule) {
	default:
		ctx->cfa = 0;
		break;
	case register_rule:	/* CFA = offset + source_reg */
		ctx->cfa = (ctx->current_regs)[rs[CF_ADDR].source_reg] +
		    rs[CF_ADDR].offset;
		break;
	case constant_rule:	/* CFA = offset */
		ctx->cfa = rs[CF_ADDR].offset;
		break;
	case indirect_rule:	/* CFA = *(offset + source_reg) */
		ctx->cfa = *(uint64_t *)
		    (ctx->current_regs[rs[CF_ADDR].source_reg] +
		    rs[CF_ADDR].offset);
		break;
	}
	ctx->entry_regs[SP_RSP] = ctx->cfa;
}

void
fix_ra(struct _Unwind_Context *ctx, struct register_state *rs)
{
	switch (rs[RET_ADD].rule) {
	case undefined_rule:
	default:
		ctx->ra = 0;
		break;
	case offset_rule:	/* RA = *(offset + CFA) */
		ctx->ra = *(uint64_t *)(ctx->cfa + rs[RET_ADD].offset);
		break;
	case register_rule:	/* RA = offset + source_reg */
		ctx->ra = ctx->current_regs[rs[RET_ADD].source_reg] +
		    rs[RET_ADD].offset;
		break;
	case indirect_rule:	/* RA = *(offset + source_reg) */
		ctx->ra = *(uint64_t *)
		    (ctx->current_regs[rs[RET_ADD].source_reg] +
		    rs[RET_ADD].offset);
		break;
	}
}

void
fix_reg(struct _Unwind_Context *ctx, struct register_state *rs, int index)
{
	switch (rs[index].rule) {
	default:
		ctx->entry_regs[index] = ctx->current_regs[index];
		break;
	case offset_rule:	/* target_reg = *(offset + CFA) */
		ctx->entry_regs[index] = *(uint64_t *)
		    (ctx->cfa + rs[index].offset);
		break;
	case is_offset_rule:	/* target_reg = offset + CFA */
		ctx->entry_regs[index] = ctx->cfa + rs[index].offset;
		break;
	case register_rule:	/* target_reg = offset + source_reg */
		ctx->entry_regs[index] =
		    ctx->current_regs[rs[index].source_reg] +
		    rs[index].offset;
		break;
	case constant_rule:	/* target_reg = offset */
		ctx->entry_regs[index] = rs[index].offset;
		break;
	case indirect_rule:	/* target_reg = *(offset + source_reg) */
		ctx->entry_regs[index] = *(uint64_t *)
		    (ctx->current_regs[rs[index].source_reg] +
		    rs[index].offset);
		break;
	}
}


/*
 * Input: f->{cie_ops, cie_ops_end, fde_ops, fde_ops_end}
 *			+ location of DWARF opcodes
 *		  ctx->{current_regs, pc}
 *			+ register values and pc at point of suspension
 * Output: ctx->{entry_regs, cfa, ra}
 *			+ register values when function was entered
 *			+ Cannonical Frame Address
 *			+ return address
 */
uint64_t
_Unw_Rollback_Registers(struct eh_frame_fields *f,
	struct _Unwind_Context *ctx)
{
	/* GPRs, RET_ADD, and CF_ADDR */
	struct register_state func_state[18];
	struct register_state func_start_state[18];
	struct register_state nop = { 0, undefined_rule, 0 };
	int i;
	uint64_t  first_pc;

	if (f == 0) {
		/*
		 * When no FDE we assume all routines have a frame pointer
		 * and pass back existing callee saves registers
		 */
		if (ctx->current_regs[FP_RBP] < ctx->current_regs[SP_RSP]) {
			ctx->cfa = 0;
			ctx->ra = 0;
			ctx->pc = 0;
			return (0);
		}
		ctx->entry_regs[FP_RBP] = ((uint64_t *)
		    (ctx->current_regs[FP_RBP]))[0];
		ctx->cfa = ctx->current_regs[FP_RBP] + 16;
		ctx->entry_regs[SP_RSP] = ctx->cfa;
		ctx->entry_regs[GPR_RBX] = ctx->current_regs[GPR_RBX];
		ctx->entry_regs[EIR_R12] = ctx->current_regs[EIR_R12];
		ctx->entry_regs[EIR_R13] = ctx->current_regs[EIR_R13];
		ctx->entry_regs[EIR_R14] = ctx->current_regs[EIR_R14];
		ctx->entry_regs[EIR_R15] = ctx->current_regs[EIR_R15];
		ctx->ra = ((uint64_t *)ctx->cfa)[-1];
		return (ctx->cfa);
	}

	for (i = 0; i < 18; i++)
		func_start_state[i] = nop;
	first_pc = interpret_ops(f->cie_ops, f->cie_ops_end,
	    f->cie_reloc, ctx->func, ctx->pc, func_start_state, 0,
	    f->data_align, f->code_align, f->code_enc);
	for (i = 0; i < 18; i++)
		func_state[i] = func_start_state[i];
	(void) interpret_ops(f->fde_ops, f->fde_ops_end,
	    f->fde_reloc, first_pc, ctx->pc, func_state, func_start_state,
	    f->data_align, f->code_align, f->code_enc);

	fix_cfa(ctx, func_state);
	if (ctx->cfa < ctx->current_regs[SP_RSP]) {
		ctx->cfa = 0;
		ctx->ra = 0;
		ctx->pc = 0;
		return (0);
	}
	fix_ra(ctx, func_state);
	fix_reg(ctx, func_state, GPR_RBX);
	fix_reg(ctx, func_state, FP_RBP);
	fix_reg(ctx, func_state, EIR_R12);
	fix_reg(ctx, func_state, EIR_R13);
	fix_reg(ctx, func_state, EIR_R14);
	fix_reg(ctx, func_state, EIR_R15);

	return (ctx->cfa);
}

/*
 * remap two-bit opcodes into a separate range or grab eight-bit opcode
 * and advance pointer past it.
 */
static enum CFA_ops
separate_op(void **pp)
{
	uint8_t c = **((uint8_t **)pp);

	if (c & 0xc0) {
		switch (c & 0xc0) {
		case DW_CFA_advance_loc:
			return (DW_CFA_SUNW_advance_loc);
		case DW_CFA_offset:
			return (DW_CFA_SUNW_offset);
		case DW_CFA_restore:
			return (DW_CFA_SUNW_restore);
		}
	} else {
		*pp = (void *)((*(intptr_t *)pp) + 1);
	}
	return (c);
}

static uint64_t
extractuleb(void **datap)
{
	uint8_t *data = *(uint8_t **)datap;
	uint64_t res = 0;
	int more = 1;
	int shift = 0;
	int val;

	while (more) {
		val = (*data) & 0x7f;
		more = ((*data++) & 0x80) >> 7;
		res = res | val << shift;
		shift += 7;
	}
	*datap = (void *)data;
	return (res);
}

static uint64_t
extractsleb(void** datap)
{
	uint8_t *data = *datap;
	int64_t res = 0;
	int more = 1;
	int shift = 0;
	unsigned int val;

	while (more) {
		val = (*data) & 0x7f;
		more = ((*data++) & 0x80) >> 7;
		res = res | val<< shift;
		shift += 7;
	}
	*datap = (void*) data;
	res = (res << (64 - shift)) >> (64 - shift);
	return (res);
}

static uint64_t get_encoded_val(void **datap, ptrdiff_t reloc, int enc);

/*
 * do all field extractions needed for CFA operands and encoded FDE
 * fields
 */
uint64_t
_Unw_get_val(void **datap, ptrdiff_t reloc,
	enum operand_desc opr, int daf, int caf, int enc)
{
	intptr_t data = (intptr_t)*datap;
	uint64_t res;
	char *dp, *rp;

	switch (opr) {
	case NO_OPR:
		res = 0;
		break;
	case ULEB128_FAC:
		return (daf * extractuleb(datap));
	case ULEB128:
		return (extractuleb(datap));
	case ULEB128_SREG:
		res = (uint64_t)(*((uint8_t *)data));
		data += 1;
		switch (res) {
			/* verify that register is one which is being tracked */
		case GPR_RBX:
		case FP_RBP:
		case SP_RSP:
		case EIR_R12:
		case EIR_R13:
		case EIR_R14:
		case EIR_R15:
			break;
		default:
			res = BAD_REG;
			break;
		}
		break;
	case UNUM6:
		res = (uint64_t)(0x3f & *((uint8_t *)data));
		data += 1;
		break;
	case UNUM8:
		res = (uint64_t)(*((uint8_t *)data));
		data += 1;
		break;
	case UNUM16:
		res = (uint64_t)(*((uint16_t *)data));
		data += 2;
		break;
	case UNUM32:
		res = (uint64_t)(*((uint32_t *)data));
		data += 4;
		break;
	case UNUM6_CFAC:
		res = caf * (uint64_t)(0x3f & *((uint8_t *)data));
		data += 1;
		break;
	case UNUM8_CFAC:
		res = caf * (uint64_t)(*((uint8_t *)data));
		data += 1;
		break;
	case UNUM16_CFAC:
		res = caf * (uint64_t)(*((uint16_t *)data));
		data += 2;
		break;
	case UNUM32_CFAC:
		res = caf * (uint64_t)(*((uint32_t *)data));
		data += 4;
		break;
	case UNUM64:
		res = (uint64_t)(*((uint64_t *)data));
		data += 8;
		break;
	case SNUM8:
		res = (uint64_t)(int64_t)(*((int8_t *)data));
		data += 1;
		break;
	case SNUM16:
		res = (uint64_t)(int64_t)(*((int16_t *)data));
		data += 2;
		break;
	case SNUM32:
		res = (uint64_t)(int64_t)(*((int32_t *)data));
		data += 4;
		break;
	case SNUM64:
		res = (uint64_t)(*((int64_t *)data));
		data += 8;
		break;
	case SLEB128_FAC:
		return (daf * extractsleb(datap));
	case SLEB128:
		return (extractsleb(datap));
	case ZTSTRING:
		/* max length of augmentation string is 4 */
		rp = (char *)&res;
		dp = (char *)data;
		while (*rp++ = *dp++)
			;
		data = (intptr_t)dp;
		break;
	case ADDR:
		return (get_encoded_val(datap, reloc, enc));
	case SIZE:
		return (get_encoded_val(datap, reloc, enc & 0x7));
	case BLOCK:
		res = 0;  /* not implemented */
		break;
	}
	*datap = (void*)data;
	return (res);
}

static uint64_t
get_encoded_val(void **datap, ptrdiff_t reloc, int enc)
{
	int val = enc & 0xf;
	int rel = (enc >> 4) & 0xf;
	intptr_t loc = ((intptr_t)*datap) + reloc;
	uint64_t res = 0;

	switch (val) {
	case 0x01:
		res = _Unw_get_val(datap, reloc, ULEB128, 1, 1, 0);
		break;
	case 0x2:
		res = _Unw_get_val(datap, reloc, UNUM16, 1, 1, 0);
		break;
	case 0x3:
		res = _Unw_get_val(datap, reloc, UNUM32, 1, 1, 0);
		break;
	case 0x04:
		res = _Unw_get_val(datap, reloc, UNUM64, 1, 1, 0);
		break;
	case 0x09:
		res = _Unw_get_val(datap, reloc, SLEB128, 1, 1, 0);
		break;
	case 0x0a:
		res = _Unw_get_val(datap, reloc, SNUM16, 1, 1, 0);
		break;
	case 0x0b:
		res = _Unw_get_val(datap, reloc, SNUM32, 1, 1, 0);
		break;
	case 0x0c:
		res = _Unw_get_val(datap, reloc, SNUM64, 1, 1, 0);
		break;
	}

	switch (rel) {
	case 0:
		break;
	case 1:
		if (res != 0)
			res += loc;
		break;
	default:
		/* remainder not implemented */
		break;
	}
	return (res);
}


int interpret_op(void **datap, ptrdiff_t reloc,
	uint64_t *reached_pc_p, uint64_t pc,
	struct register_state f_state[],
	struct register_state f_start_state[],
	int daf, int caf, int enc);

uint64_t
interpret_ops(void *data, void *data_end,
	ptrdiff_t reloc,
	uint64_t start_pc, uint64_t pc,
	struct register_state f_state[],
	struct register_state f_start_state[],
	int daf, int caf, int enc)
{
	void *d = data;
	uint64_t reached_pc = start_pc;

	while (d < data_end) {
		if (interpret_op(&d, reloc, &reached_pc, pc,
		    f_state, f_start_state, daf, caf, enc))
			break;
	}
	return (reached_pc);
}

int
interpret_op(void **datap, ptrdiff_t reloc,
	uint64_t *reached_pc_p, uint64_t pc,
	struct register_state f_state[],
	struct register_state f_start_state[],
	int daf, int caf, int enc)
{
	enum CFA_ops op = separate_op(datap);
	enum operand_desc opr1 = (cfa_operations[op]).op1;
	enum operand_desc opr2 = (cfa_operations[op]).op2;

	uint64_t val1 = _Unw_get_val(datap, reloc, opr1, daf, caf, enc);
	uint64_t val2 = _Unw_get_val(datap, reloc, opr2, daf, caf, enc);
	if ((opr1 == ULEB128_SREG && val1 == BAD_REG) ||
	    (opr2 == ULEB128_SREG && val2 == BAD_REG))
		return (0);
	switch (op) {
	case DW_CFA_nop:
		break;
	case DW_CFA_set_loc:
		if (val1 > pc)
			return (1);
		*reached_pc_p = val1;
		break;
	case DW_CFA_advance_loc1:
	case DW_CFA_advance_loc2:
	case DW_CFA_advance_loc4:
		if (*reached_pc_p + val1 > pc)
			return (1);
		*reached_pc_p += val1;
		break;
	case DW_CFA_offset_extended:
		f_state[val1].rule = offset_rule;
		f_state[val1].source_reg = CF_ADDR;
		f_state[val1].offset = val2;
		break;
	case DW_CFA_restore_extended:
		if (f_start_state != 0)
			f_state[val1] = f_start_state[val1];
		break;
	case DW_CFA_undefined:
		f_state[val1].rule = undefined_rule;
		break;
	case DW_CFA_same_value:
		f_state[val1].rule = same_value_rule;
		break;
	case DW_CFA_register:
		f_state[val1].rule = register_rule;
		f_state[val1].source_reg = val2;
		f_state[val1].offset = 0;
		break;
	case DW_CFA_remember_state:
		break;
	case DW_CFA_restore_state:
		break;
	case DW_CFA_def_cfa:
		f_state[CF_ADDR].rule = register_rule;
		f_state[CF_ADDR].source_reg = val1;
		f_state[CF_ADDR].offset = val2;
		break;
	case DW_CFA_def_cfa_register:
		f_state[CF_ADDR].source_reg = val1;
		break;
	case DW_CFA_def_cfa_offset:
		f_state[CF_ADDR].offset = val1;
		break;
	case DW_CFA_def_cfa_expression:
		break;
	case DW_CFA_expression:
		break;
	case DW_CFA_offset_extended_sf:
		f_state[val1].rule = offset_rule;
		f_state[val1].source_reg = CF_ADDR;
		f_state[val1].offset = val2;
		break;
	case DW_CFA_def_cfa_sf:
		f_state[CF_ADDR].rule = register_rule;
		f_state[CF_ADDR].source_reg = val1;
		f_state[CF_ADDR].offset = val2;
		break;
	case DW_CFA_def_cfa_offset_sf:
		f_state[CF_ADDR].offset = val1;
		break;
	case DW_CFA_SUNW_advance_loc:
		if (*reached_pc_p + val1 > pc)
			return (1);
		*reached_pc_p += val1;
		break;
	case DW_CFA_SUNW_offset:
		f_state[val1].rule = offset_rule;
		f_state[val1].source_reg = CF_ADDR;
		f_state[val1].offset = val2;
		break;
	case DW_CFA_SUNW_restore:
		if (f_start_state != 0)
			f_state[val1] = f_start_state[val1];
		break;
	}
	return (0);
}
