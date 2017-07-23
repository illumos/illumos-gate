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
 * Public interfaces for AMD64 Unwind routines
 */

#ifndef _STACK_UNWIND_H
#define	_STACK_UNWIND_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__amd64)	/* none of this is valid except for AMD64 */

typedef enum {
	_URC_NO_REASON = 0,
	_URC_FOREIGN_EXCEPTION_CAUGHT = 1,
	_URC_FATAL_PHASE2_ERROR = 2,
	_URC_FATAL_PHASE1_ERROR = 3,
	_URC_NORMAL_STOP = 4,
	_URC_END_OF_STACK = 5,
	_URC_HANDLER_FOUND = 6,
	_URC_INSTALL_CONTEXT = 7,
	_URC_CONTINUE_UNWIND = 8
} _Unwind_Reason_Code;

typedef int _Unwind_Action;
extern const _Unwind_Action _UA_SEARCH_PHASE;
extern const _Unwind_Action _UA_CLEANUP_PHASE;
extern const _Unwind_Action _UA_HANDLER_FRAME;
extern const _Unwind_Action _UA_FORCE_UNWIND;

struct _Unwind_Exception;
struct _Unwind_Context;


/*
 * Signature of language specific call back for deleting exception object
 */
typedef void (*_Unwind_Exception_Cleanup_Fn)(
	_Unwind_Reason_Code reason,
	struct _Unwind_Exception *exc);

/*
 * Header preceding language specific exception object
 * For Sun C++ these fields are the beginning of the
 * language specific structure.
 */
struct _Unwind_Exception {
	uint64_t exception_class;
	_Unwind_Exception_Cleanup_Fn exception_cleanup;
	uint64_t private_1;
	uint64_t private_2;
};

/*
 * Signature for language specific routine - address is in eh_frame CIE.
 * During phase one it predicts whether exception would be caught at this
 * frame and during phase two selects a handler as predicted.  An action
 * of _UA_FORCE_UNWIND will prevent any catch block from being selected.
 *
 * The personality function is the only call back used when
 * _Unwind_RaiseException() is called.
 */
typedef _Unwind_Reason_Code (*_Unwind_Personality_Fn)(
	int version,
	_Unwind_Action actions,
	uint64_t exceptionClass,
	struct _Unwind_Exception *exceptionObject,
	struct _Unwind_Context *context);

/*
 * Signature of callback function that is used when _Unwind_ForcedUnwind()
 * is called.  It is called at every step of walkback and that can control
 * the execution of the personality routine at each frame.
 */
typedef _Unwind_Reason_Code (*_Unwind_Stop_Fn)(
	int version,
	_Unwind_Action actions,
	uint64_t exceptionClass,
	struct _Unwind_Exception *exceptionObject,
	struct _Unwind_Context *context,
	void *stop_parameter);

/*
 * Here begins the external functional interface
 */

/*
 * Used to implement C++ throw - starts walkback with caller's caller.
 * The routine in the middle must use %rbp as a frame pointer
 */
_Unwind_Reason_Code _Unwind_RaiseException(
	struct _Unwind_Exception *exception_object);

/*
 * Used (with different stop functions) for POSIX thread cancellation
 * and stack walking - starts walkback with caller's caller.
 *
 * Note: must be called by a routine which has a real FP and doesn't use
 * callee saves registers.
 */
_Unwind_Reason_Code _Unwind_ForcedUnwind(
	struct _Unwind_Exception *exception_object,
	_Unwind_Stop_Fn stop,
	void *stop_parameter);

/*
 * Used to resume unwinding at end of cleanup (not catch) code
 * Assumes that caller is language specific cleanup code and
 * pops the stack one level before resuming walk.
 */
void _Unwind_Resume(struct _Unwind_Exception *exception_object);

/*
 * Calls destructor function for exception object
 */
void _Unwind_DeleteException(struct _Unwind_Exception *exception_object);
/*
 * {
 *	(*(exception_object->exception_cleanup))(_URC_NO_REASON,
 *		exception_object);
 * }
 */


#if 0

extern "C" _Unwind_Reason_Code
__example_stop_fn(int version, int actions, uint64_t exclass,
    struct _Unwind_Exception *exception_object,
    struct _Unwind_Context *ctx, void *_Sa)
{
	_Unwind_Reason_Code res;

	uint64_t fp = _Unwind_GetCFA(ctx);

	if (fp == 0 || _Unwind_GetGR(ctx, RET_ADD) == 0) {
		if (no_return)
			die;
		res = _URC_END_OF_STACK;
	} else {
		/*
		 * Your logic here:
		 * res = ........
		 */
	}
	switch (res) {
	case _URC_NO_REASON:
		/*
		 * framework will call personality routine for current context
		 * then then move one frame back the stack and call here with
		 * updated context. POSIX thread cancellation uses this pattern.
		 *
		 * If this path is taken the exception object passed must have
		 * been constructed by the same language system supplying the
		 * personality routines. i.e. foreign exceptions are not
		 * implemented.
		 *
		 * The Sun Microsystems C++ runtime contains the routine
		 *
		 *	_ex_unwind(_Unwind_Stop_fn sfunc, void *sfunc_arg)
		 *
		 * which is a wrapper around _Unwind_ForcedUnwind that
		 * sets up a C++ exception object.
		 *
		 * Once this path is taken, the stack frame from which
		 * _Unwind_ForcedUnwind was called is not guaranteed to
		 * still exist. Thus the return codes listed below which
		 * result in that call returning are rendered bogus.
		 *
		 * A thread reaching the end of the stack during cancellation
		 * must die instead of returning _URC_END_OF_STACK.
		 */
		break;
	case _URC_CONTINUE_UNWIND:
		/*
		 * framework will move one frame back the stack and
		 * call here with updated context
		 *
		 * The exception record supplied to _Unwind_ForcedUnwind
		 * need only contain the header and may be stack allocated
		 * if this function will never allow the personality
		 * function to run (as in a trace generator).
		 */
		break;
	case _URC_INSTALL_CONTEXT:
		/*
		 * framework will resume execution of user code at location
		 * specified by (altered) context
		 */
		_Unwind_Delete_Exception(res, exception_object);
		break;
	case _URC_NORMAL_STOP:
		/*
		 * call to _Unwind_ForcedUnwind will return _URC_NORMAL_STOP
		 */
		_Unwind_Delete_Exception(res, exception_object);
		break;
	case _URC_END_OF_STACK:
		/*
		 * call to _Unwind_ForcedUnwind will return _URC_END_OF_STACK
		 */
		_Unwind_Delete_Exception(res, exception_object);
		break;
	case _URC_FOREIGN_EXCEPTION_CAUGHT:
	case _URC_FATAL_PHASE2_ERROR:
	case _URC_FATAL_PHASE1_ERROR:
	case _URC_HANDLER_FOUND:
		/*
		 * call to _Unwind_ForcedUnwind will return
		 * _URC_FATAL_PHASE2_ERROR
		 */
		_Unwind_Delete_Exception(res, exception_object);
		break;
	}
	return (res);
}

#endif

/*
 * Stack frame context accessors defined in ABI
 * (despite all the dire text in the ABI these are reliable Get/Set routines)
 * Note: RA is handled as a GR value
 */

/*
 * Valid Index values for _Unwind_GetGR
 */
#define	GPR_RBX	3	/* callee saves */
#define	FP_RBP	6	/* callee saves (optional frame pointer) */
#define	SP_RSP	7	/* callee saves */
#define	EIR_R12	12	/* callee saves */
#define	EIR_R13	13	/* callee saves */
#define	EIR_R14	14	/* callee saves */
#define	EIR_R15	15	/* callee saves */
#define	RET_ADD	16	/* virtual register - really caller's PC */

/*
 * Valid Index values for _Unwind_SetGR
 */
#define	GPR_RDX	1	/* landing pad parameter */
#define	GPR_RCX	2	/* landing pad parameter */
#define	GPR_RSI	4	/* landing pad parameter */
#define	GPR_RDI	5	/* landing pad parameter */

uint64_t _Unwind_GetGR(struct _Unwind_Context *context, int index);

void _Unwind_SetGR(struct _Unwind_Context *context, int index,
	uint64_t new_value);

uint64_t _Unwind_GetCFA(struct _Unwind_Context *context);

uint64_t _Unwind_GetIP(struct _Unwind_Context *context);

void _Unwind_SetIP(struct _Unwind_Context *context, uint64_t new_value);

void *_Unwind_GetLanguageSpecificData(struct _Unwind_Context *context);

uint64_t _Unwind_GetRegionStart(struct _Unwind_Context *context);

#endif	/* __amd64 */

#ifdef	__cplusplus
}
#endif

#endif	/* _STACK_UNWIND_H */
