/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Public interface for AMD64 Unwind context
 */

#ifndef _UNWIND_CONTEXT_H
#define	_UNWIND_CONTEXT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * implementation of context structure
 *
 * Register arrays are indexed as specified in reg_num.h
 */
struct _Unwind_Context {
	uint64_t	entry_regs[16];
	uint64_t	current_regs[16];
	uint64_t	cfa;
	uint64_t	pc;
	uint64_t	ra;
	void		*fde;
	_Unwind_Personality_Fn	pfn;
	uint64_t	func;
	void		*lsda;
	uint64_t	range;
};

enum register_rule {
	undefined_rule,
	same_value_rule,	/* target_reg = target_reg */
	offset_rule,		/* target_reg = *(offset + CFA) */
	is_offset_rule,		/* target_reg = offset + CFA */
	register_rule,		/* target_reg = offset + source_reg */
	constant_rule,		/* target_reg = offset */
	indirect_rule		/* target_reg = *(offset + source_reg) */
};

struct register_state {
	uint64_t	offset;
	enum register_rule	rule;
	unsigned char	source_reg;
};

struct eh_frame_fields {
	void		*cie_ops;
	void		*cie_ops_end;
	ptrdiff_t	cie_reloc;
	int		code_align;
	int		data_align;
	int		code_enc;
	void		*fde_ops;
	void		*fde_ops_end;
	ptrdiff_t	fde_reloc;
};

_Unwind_Reason_Code
_Unw_very_boring_personality(int version, int actions, uint64_t exclass,
		struct _Unwind_Exception *exception_object,
		struct _Unwind_Context *ctx);
/*
 * Starting withe an initialized context (from a ucontext)
 * the following routines are sufficient to implement a non-destructive
 * stack walk if modified to access the target processes memory. These
 * routines refer to the local address of an item using names containing
 * `data' names containing `reloc' give the correction to get target
 * process location.
 */

/* ================== find function ====================== */

/*
 * Computes the func and fde fields using pc as the lookup key.
 * Return is 0 or address of fde
 *
 * This is the only function that look into .eh_frame_hdr
 */
void *_Unw_EhfhLookup(struct _Unwind_Context *ctx);

/* =================== analyze function ================== */

/*
 * Fills in personality_fn and lsda fields of the context based
 * the fde entry which must be valid and also partially unpacks
 * fde and cie into *f
 *
 * This is one of two functions that look inside fde's
 */
struct eh_frame_fields *_Unw_Decode_FDE(struct eh_frame_fields *f,
		struct _Unwind_Context *ctx);

/*
 * Computes register values at entry to function based on current
 * register values, pc and fde values in a context
 *
 * This is the other function which looks inside fde's and
 * the only one to look at CFA operations
 *
 * If 'f' is NULL (because no fde was found), a default calculation
 * assuming an FP is done.
 */
uint64_t _Unw_Rollback_Registers(struct eh_frame_fields *f,
		struct _Unwind_Context *ctx);

/* ================= register propagation =============== */

/*
 * Fills in the current register context for the caller
 * based on computed at-entry state of callee
 */
void
_Unw_Propagate_Registers(struct _Unwind_Context *old_ctx,
		struct _Unwind_Context *new_ctx);

/* ================================================= */
enum operand_desc {
	NO_OPR,
	ULEB128_FAC,
	ULEB128,
	ULEB128_SREG,
	SLEB128,
	SLEB128_FAC,
	ADDR,
	SIZE,
	ZTSTRING,
	UNUM6,
	UNUM6_CFAC,
	UNUM8,
	UNUM8_CFAC,
	UNUM16,
	UNUM16_CFAC,
	UNUM32,
	UNUM32_CFAC,
	UNUM64,
	SNUM8,
	SNUM16,
	SNUM32,
	SNUM64,
	BLOCK
};

uint64_t _Unw_get_val(void **datap, ptrdiff_t reloc,
		enum operand_desc opr,
		int daf, int caf, int enc);

#endif	/* _UNWIND_CONTEXT_H */
