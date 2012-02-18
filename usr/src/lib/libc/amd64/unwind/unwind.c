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
 * UNWIND - Unwind library
 */

/*
 * ===================== stack walk ====================
 *
 * Stack walk-back starts with the user code at the top of the stack
 * calling a language specific support routine which calls the generic
 * unwind code. The unwind code captures
 * information which can be used to partially build an _Unwind_Context
 * for the user code containing:
 *
 *    callee saves registers <current values>
 *    PC
 *    %rbp
 *    %rsp
 *
 * Using that pc location the unwind info for the function is found.
 * Then the CFA operations encoded in the unwind info are interepreted to get
 *
 *    callee saves registers <values on entry>
 *    the return address
 *    cannonical frame address
 *
 * completing the context for the user function (See
 * _Unw_Rollback_Registers()) .
 *
 * The values computed above are equivalent to the info which would have been
 * captured from the caller and are used to initialize the callers context
 * (see _Unw_Propagate_Registers()) which can be completed.
 *
 * Using the same two-step procedure
 * context records for each frame down the stack may be constructed
 * in turn.  The ABI defined interface to _Unwind_Context provides
 * access to
 *
 *    callee saves registers <current values>
 *    current PC
 *    frame pointer
 *
 * and allows changing
 *
 *    PC
 *    values of integer argument registers
 *
 * (changed values take effect if context is "installed" - think
 * setcontext(2))
 *
 */

/*
 *
 * |                              |
 * | local storage for start()    | <FP == 0>
 * |                              |
 * --------------------------------.
 * |                              |
 * |     ..........               |
 * |                              | <-  CFA for bar()
 * --------------------------------.
 * |                              |
 * | local storage for bar()      |
 * |                              | <-  SP for bar(), CFA for foo()
 * ................................
 * |  pc for bar()                |
 * --------------------------------
 * |                              |
 * | local storage for foo()      |
 * |                              | <-  SP for foo(), CFA for ex_throw()
 * ................................
 * | pc for foo() - PC3           |
 * ................................
 * | saved RBP from foo() - BP3   | <-  FP for ex_throw() == FP2
 * --------------------------------
 * |                              |
 * | local storage for ex_throw() |
 * |                              | <- SP for ex_throw(), CFA for Unw()
 * ................................
 * | pc for ex_throw() - PC2      |
 * ................................
 * | saved RBP from ex_throw()    | <- FP for Unw() == FP1
 * --------------------------------
 * |                              |
 * | local storage for Unw()      |
 * |                              | <- SP for Unw() == SP1
 *
 * We know that Unw() and ex_throw save and have an FP
 *
 */

#ifdef _LIBCRUN_
#define	_Unwind_DeleteException  _SUNW_Unwind_DeleteException
#define	_Unwind_ForcedUnwind  _SUNW_Unwind_ForcedUnwind
#define	_Unwind_GetCFA  _SUNW_Unwind_GetCFA
#define	_Unwind_GetGR  _SUNW_Unwind_GetGR
#define	_Unwind_GetIP  _SUNW_Unwind_GetIP
#define	_Unwind_GetLanguageSpecificData _SUNW_Unwind_GetLanguageSpecificData
#define	_Unwind_GetRegionStart  _SUNW_Unwind_GetRegionStart
#define	_Unwind_RaiseException  _SUNW_Unwind_RaiseException
#define	_Unwind_Resume  _SUNW_Unwind_Resume
#define	_Unwind_SetGR  _SUNW_Unwind_SetGR
#define	_Unwind_SetIP  _SUNW_Unwind_SetIP
#else
#pragma weak _SUNW_Unwind_DeleteException = _Unwind_DeleteException
#pragma weak _SUNW_Unwind_ForcedUnwind = _Unwind_ForcedUnwind
#pragma weak _SUNW_Unwind_GetCFA = _Unwind_GetCFA
#pragma weak _SUNW_Unwind_GetGR = _Unwind_GetGR
#pragma weak _SUNW_Unwind_GetIP = _Unwind_GetIP
#pragma weak _SUNW_Unwind_GetLanguageSpecificData = \
		_Unwind_GetLanguageSpecificData
#pragma weak _SUNW_Unwind_GetRegionStart = _Unwind_GetRegionStart
#pragma weak _SUNW_Unwind_RaiseException = _Unwind_RaiseException
#pragma weak _SUNW_Unwind_Resume = _Unwind_Resume
#pragma weak _SUNW_Unwind_SetGR = _Unwind_SetGR
#pragma weak _SUNW_Unwind_SetIP = _Unwind_SetIP
#endif

#include "lint.h"
#include <string.h>
#include "stack_unwind.h"
#include "reg_num.h"
#include "unwind_context.h"

const _Unwind_Action _UA_SEARCH_PHASE = 1;
const _Unwind_Action _UA_CLEANUP_PHASE = 2;
const _Unwind_Action _UA_HANDLER_FRAME = 4;
const _Unwind_Action _UA_FORCE_UNWIND = 8;

void _Unw_capture_regs(uint64_t *regs);
void _Unw_jmp(uint64_t pc, uint64_t *regs);

static void
copy_ctx(struct _Unwind_Context *ctx1, struct _Unwind_Context *ctx2)
{
	if (ctx1 != ctx2) {
		(void) memcpy(ctx2, ctx1, sizeof (*ctx2));
	}
}

static _Unwind_Personality_Fn
ctx_who(struct _Unwind_Context *ctx)
{
	return (ctx->pfn);
}

/* ARGSUSED */
_Unwind_Reason_Code
_Unw_very_boring_personality(int version, int actions, uint64_t exclass,
	struct _Unwind_Exception *exception_object,
	struct _Unwind_Context *ctx)
{
	_Unwind_Reason_Code res = _URC_CONTINUE_UNWIND;
	uint64_t fp;

	fp =  _Unwind_GetCFA(ctx);
	if (fp == 0 || _Unwind_GetIP(ctx) == 0) {
		return (_URC_END_OF_STACK);
	}
	return (res);
}

/*
 * The only static variables in this code - changed by debugging hook below
 */
static int using_ehf = 1;
static uintptr_t def_per_fcn = (uintptr_t)&_Unw_very_boring_personality;

void
_SUNW_Unw_set_defaults(int use, uintptr_t def_per)
{
	using_ehf = use;
	def_per_fcn = def_per;
}

static void
complete_context(struct _Unwind_Context *ctx)
{
	struct eh_frame_fields sf;
	struct eh_frame_fields *sfp = 0;

	ctx->pfn = (_Unwind_Personality_Fn)def_per_fcn;
	ctx->lsda = 0;
	ctx->func = 0;
	ctx->range = 0;
	ctx->fde = 0;
	if (using_ehf && (0 != _Unw_EhfhLookup(ctx))) {
		sfp = _Unw_Decode_FDE(&sf, ctx);
	}
	(void) _Unw_Rollback_Registers(sfp, ctx);
}

/*
 * input: FP1 (or FP2 if from _Unwind_Resume (from_landing_pad))
 *
 * FP2 = FP1[0];
 * BP3 = FP2[0];
 * PC3 = FP2[1];
 * SP3 = FP2 + 16;
 *
 * output: PC3, SP3, and BP3
 *
 * remaining callee saves registers are also captured in context
 */
static void
finish_capture(struct _Unwind_Context *ctx, int from_landing_pad)
{
	uint64_t fp1 = ctx->current_regs[FP_RBP];
	uint64_t fp2 = from_landing_pad ? fp1 : ((uint64_t *)fp1)[0];

	ctx->pc = ((uint64_t *)fp2)[1];
	ctx->current_regs[SP_RSP] = fp2 + 16;
	ctx->current_regs[FP_RBP] = ((uint64_t *)fp2)[0];
	complete_context(ctx);
}

static int
down_one(struct _Unwind_Context *old_ctx, struct _Unwind_Context *new_ctx)
{
	uint64_t old_cfa = old_ctx->cfa;
	uint64_t old_pc = old_ctx->pc;
	uint64_t new_cfa;

	if (old_cfa == 0 || old_pc == 0) {
		new_ctx->pc = 0;
		new_ctx->cfa = 0;
		new_ctx->ra = 0;
		return (1);
	}
	if (old_ctx->ra == 0) {
		new_ctx->pc = 0;
		new_ctx->cfa = 0;
		new_ctx->ra = 0;
		return (0);
	}
	/* now shift ----------------------------- */
	_Unw_Propagate_Registers(old_ctx, new_ctx);
	complete_context(new_ctx);
	new_cfa = new_ctx->cfa;
	if ((new_cfa < old_cfa) || (new_cfa & 7)) {
		new_ctx->pc = 0;
		new_ctx->cfa = 0;
		new_ctx->ra = 0;
	}
	return (0);
}

static void
jmp_ctx(struct _Unwind_Context *ctx)
{
	_Unw_jmp(ctx->pc, ctx->current_regs);
}

/*
 * Here starts the real work - the entry points from either a language
 * runtime or directly from user code.
 *
 * The two ..._Body functions are intended as private interfaces for
 * Sun code as well so should remain accessible.
 */
_Unwind_Reason_Code
_Unwind_RaiseException_Body(struct _Unwind_Exception *exception_object,
	struct _Unwind_Context *entry_ctx, int phase)
{
	struct _Unwind_Context context;
	struct _Unwind_Context *ctx = &context;
	_Unwind_Reason_Code res;

	if (phase & _UA_SEARCH_PHASE) {
		finish_capture(entry_ctx, 0);
		copy_ctx(entry_ctx, ctx);

		for (;;) {
			res = (*ctx_who(ctx))(1, phase,
			    exception_object->exception_class,
			    exception_object, ctx);
			if (res != _URC_CONTINUE_UNWIND)
				break;
			if (down_one(ctx, ctx))
				return (_URC_FATAL_PHASE1_ERROR);
		}
		switch (res) {
		case _URC_HANDLER_FOUND:
			exception_object->private_2 = _Unwind_GetCFA(ctx);
			break;
		default:
			return (res);
		}
	} else {
		finish_capture(entry_ctx, 1);
		if (down_one(entry_ctx, entry_ctx))
			return (_URC_FATAL_PHASE2_ERROR);
	}

	phase = _UA_CLEANUP_PHASE;
	copy_ctx(entry_ctx, ctx);

	for (;;) {
		if (exception_object->private_2 == _Unwind_GetCFA(ctx)) {
			phase |= _UA_HANDLER_FRAME;
		}
		res = (*ctx_who(ctx))(1, phase,
		    exception_object->exception_class,
		    exception_object, ctx);
		if ((phase & _UA_HANDLER_FRAME) && res != _URC_INSTALL_CONTEXT)
			return (_URC_FATAL_PHASE2_ERROR);
		if (res != _URC_CONTINUE_UNWIND)
			break;
		if (down_one(ctx, ctx))
			return (_URC_FATAL_PHASE2_ERROR);
	}
	switch (res) {
	case _URC_INSTALL_CONTEXT:
		exception_object->private_1 = 0;
		jmp_ctx(ctx); /* does not return */
		break;
	default:
		break;
	}
	return (res);
}

_Unwind_Reason_Code
_Unwind_RaiseException(struct _Unwind_Exception *exception_object)
{
	struct _Unwind_Context entry_context;
	struct _Unwind_Context *entry_ctx = &entry_context;

	_Unw_capture_regs(entry_ctx->current_regs);

	return (_Unwind_RaiseException_Body(exception_object, entry_ctx,
	    _UA_SEARCH_PHASE));
}

_Unwind_Reason_Code
_Unwind_ForcedUnwind_Body(struct _Unwind_Exception *exception_object,
	_Unwind_Stop_Fn stop, void *stop_parameter,
	struct _Unwind_Context *ctx, int resume)
{
	_Unwind_Reason_Code res;
	int phase = _UA_CLEANUP_PHASE | _UA_FORCE_UNWIND;

	int again;
	int doper;

	finish_capture(ctx, resume);
	if (resume && down_one(ctx, ctx))
		return (_URC_FATAL_PHASE2_ERROR);

	do {
		again = 0;
		doper = 0;
		res = (*stop)(1, phase,
		    exception_object->exception_class,
		    exception_object, ctx, stop_parameter);
		switch (res) {
		case _URC_CONTINUE_UNWIND:
			/* keep going - don't call personality */
			again = 1;
			break;
		case _URC_NO_REASON:
			/* keep going - do call personality */
			again = 1;
			doper = 1;
			break;
		case _URC_NORMAL_STOP:  /* done */
			break;
		case _URC_INSTALL_CONTEXT:  /* resume execution */
			break;
		default:		/* failure */
			break;
		}
		if (doper) {
			res = (*ctx_who(ctx))(1, phase,
			    exception_object->exception_class,
			    exception_object, ctx);
		}
		switch (res) {
		case _URC_INSTALL_CONTEXT:
			exception_object->private_1 = (uint64_t)stop;
			exception_object->private_2 = (uint64_t)stop_parameter;
			jmp_ctx(ctx); /* does not return */
			break;
		case _URC_CONTINUE_UNWIND:
		case _URC_NO_REASON:
			break;
		case _URC_END_OF_STACK:
			ctx->cfa = ctx->ra = ctx->pc = 0;
			res = (*stop)(1, phase,
			    exception_object->exception_class,
			    exception_object, ctx, stop_parameter);
			return (_URC_END_OF_STACK);
		default:
			again = 0;
			break;
		}
		if (again) {
			if (down_one(ctx, ctx)) {
				return (_URC_FATAL_PHASE2_ERROR);
			}
		}
	} while (again);

	return (res);
}

_Unwind_Reason_Code
_Unwind_ForcedUnwind(struct _Unwind_Exception *exception_object,
	_Unwind_Stop_Fn stop, void *stop_parameter)
{
	struct _Unwind_Context context;
	struct _Unwind_Context *ctx = &context;

	_Unw_capture_regs(ctx->current_regs);

	return (_Unwind_ForcedUnwind_Body(exception_object, stop,
	    stop_parameter, ctx, 0));
}

void
_Unwind_Resume(struct _Unwind_Exception *exception_object)
{

	struct _Unwind_Context context;
	struct _Unwind_Context *ctx = &context;

	_Unw_capture_regs(ctx->current_regs);

	if (exception_object->private_1)
		(void) _Unwind_ForcedUnwind_Body(exception_object,
		    (_Unwind_Stop_Fn)exception_object->private_1,
		    (void *)exception_object->private_2,
		    ctx, 1);
	else
		(void) _Unwind_RaiseException_Body(exception_object, ctx,
		    _UA_CLEANUP_PHASE);
}

/* Calls destructor function for exception object */
void
_Unwind_DeleteException(struct _Unwind_Exception *exception_object)
{
	if (exception_object->exception_cleanup != 0)
		(*(exception_object->exception_cleanup))(_URC_NO_REASON,
		    exception_object);
}


/*
 * stack frame context accessors defined in ABI
 * (despite all the dire text in the ABI these are reliable Get/Set routines)
 * Note: RA is handled as GR value
 */
uint64_t
_Unwind_GetGR(struct _Unwind_Context *context, int index)
{
	uint64_t res = 0;
	if (index <= EIR_R15) {
		res = context->current_regs[index];
	} else if (index == RET_ADD) {
		res = context->ra;
	}
	return (res);
}


void
_Unwind_SetGR(struct _Unwind_Context *context, int index,
uint64_t new_value)
{
	if (index <= EIR_R15) {
		context->current_regs[index] = new_value;
	} else if (index == RET_ADD) {
		context->ra = new_value;
	}
}


uint64_t
_Unwind_GetIP(struct _Unwind_Context *context)
{
	return (context->pc);
}

void
_Unwind_SetIP(struct _Unwind_Context *context, uint64_t new_value)
{
	context->pc = new_value;
}


void *
_Unwind_GetLanguageSpecificData(struct _Unwind_Context *context)
{
	return (context->lsda);
}


uint64_t
_Unwind_GetRegionStart(struct _Unwind_Context *context)
{
	return (context->func);
}

uint64_t
_Unwind_GetCFA(struct _Unwind_Context *context)
{
	return (context->cfa);
}
