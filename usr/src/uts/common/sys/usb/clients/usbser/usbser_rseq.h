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
 */

#ifndef _SYS_USB_USBSER_USBSER_RSEQ_H
#define	_SYS_USB_USBSER_USBSER_RSEQ_H


/*
 * Reversible sequence (rseq) is a data-driven mechanism to execute several
 * subfunctions, called steps, and subsequently execute them in the reverse
 * order - these opposite actions are further referred to as 'do' and 'undo'.
 * If one of the intermediate steps fails, the previously executed steps are
 * undone in reverse order. Debugging facilities are also provided.
 *
 * rseq is primarily aimed to simplify multistep driver attach()/detach()
 * implementations, where each step can potentially fail and undoing previous
 * ones typically involve either goto's or bit-fields (indicating what has been
 * done so far).
 */

#include <sys/types.h>
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct rseq rseq_t;

/*
 * rseq function type
 *
 * uintptr_t is used to accomodate both integer and pointer argument types
 */
typedef uintptr_t (*rseq_func_t)(uintptr_t);

/* step callback is called after each step */
typedef int (*rseq_cb_t)(rseq_t *rseq, int num, uintptr_t arg);

/* values returned by step callback */
enum {
	RSEQ_OK		= 0,	/* continue to execute steps */
	RSEQ_UNDO	= 1,	/* rseq_do() only: step failed, undo all */
	RSEQ_ABORT	= 2	/* stop rseq execution and return immediately */
};

/*
 * rseq step
 */
typedef struct rseq_step {
	rseq_func_t	s_func;		/* step function; ignored if NULL */
	char		*s_name;	/* step name string */
	rseq_cb_t	s_cb;		/* step callback; NULL is equivalent */
					/* to a callback returning RSEQ_OK */
	uintptr_t	s_rval;		/* s_func's return value */
} rseq_step_t;

/*
 * rseq entry
 */
struct rseq {
	rseq_step_t	r_do;	/* do step */
	rseq_step_t	r_undo;	/* undo step */
};

_NOTE(SCHEME_PROTECTS_DATA("one per call", rseq rseq_step))

/*
 * rseq_do(), rseq_undo()
 *
 * Arguments:
 *	rseq	- array of rseq entries;
 *	num	- number of entries in the array;
 *	arg	- argument passed to the step functions;
 *	flags	- should be 0, no flags defined yet;
 *
 * Return values:
 *	If an intermediate step failed, value returned by respective callback.
 *	Otherwise RSEQ_OK.
 */
int rseq_do(rseq_t *rseq, int num, uintptr_t arg, int flags);
int rseq_undo(rseq_t *rseq, int num, uintptr_t arg, int flags);


/*
 * To use rseq debugging, rseq_do_debug() and rseq_undo_debug() are provided.
 * They are similar to their non-debug counterparts, except for additional
 * arguments: scenario type and scenario arguments.
 */
int rseq_do_debug(rseq_t *rseq, int num, uintptr_t arg, int flags,
		int scenario, uintptr_t sarg1, uintptr_t sarg2);
int rseq_undo_debug(rseq_t *rseq, int num, uintptr_t arg, int flags,
		int scenario, uintptr_t sarg1, uintptr_t sarg2);

/*
 * Debug scenarios
 */
enum {
	/*
	 * simulate step failure: instead of executing step number sarg2,
	 * rseq will set s_rval to sarg1 and invoke the step callback.
	 */
	RSEQ_DBG_FAIL_ONE,
	/*
	 * same as RSEQ_DBG_FAIL_ONE, but step number is chosen randomly.
	 */
	RSEQ_DBG_FAIL_ONE_RANDOM,
	/*
	 * simulate each step failure one-by-one, to cover all failure paths.
	 * in pseudo code:
	 *
	 * for i = 0..num
	 *	RSEQ_DBG_FAIL_ONE of the i-th step;
	 *
	 */
	RSEQ_DBG_FAIL_ONEBYONE
};


/*
 * convenience macros for rseq definition
 */
#define	RSEQT(func, cb)	{ (rseq_func_t)(func), #func, (rseq_cb_t)(cb), 0 }
#define	RSEQE(f1, cb1, f2, cb2) { RSEQT(f1, cb1), RSEQT(f2, cb2) }

/*
 * Example:
 *
 * #define MY_RSEQ(f1, f2) RSEQE(f1, my_do_cb, f2, my_undo_cb)
 *
 * rseq_t my_rseq[] = {
 *	MY_RSEQ(my_first_do, my_first_undo),
 *	MY_RSEQ(my_second_do, my_second_undo),
 *	...
 * };
 *
 * int my_do_cb(rseq_t *rseq, int num)
 * 	{ return (rseq[num].rval == 0) ? RSEQ_OK : RSEQ_UNDO; }
 *
 * int my_undo_cb(rseq_t *rseq, int num)
 *	{ return RSEQ_OK; }
 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSER_USBSER_RSEQ_H */
