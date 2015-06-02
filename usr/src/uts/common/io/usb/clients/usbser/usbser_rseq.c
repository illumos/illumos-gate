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


/*
 * rseq implementation
 */

#include <sys/usb/clients/usbser/usbser_rseq.h>

#ifdef _KERNEL
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
/*LINTED E_STATIC_UNUSED*/
static long rseq_random();
#define	random	rseq_random
#else
#include <assert.h>
#define	ASSERT	assert
#include <stdlib.h>
#endif


/*ARGSUSED*/
static int
rseq_do_common(rseq_t *rseq, int num, uintptr_t arg, int flags, int fail_err,
		uintptr_t fail_num)
{
	int		i;
	rseq_step_t	*s;
	int		rval = RSEQ_OK;

	for (i = 0; i < num; i++) {
		s = &rseq[i].r_do;

		if (s->s_func == NULL) {
			continue;
		}
		s->s_rval = (i != fail_num) ? s->s_func(arg) : fail_err;
		rval = (s->s_cb) ? (s->s_cb(rseq, i, arg)) : RSEQ_OK;

		if (rval == RSEQ_UNDO) {
			(void) rseq_undo(rseq, i, arg, flags);
			break;
		} else if (rval == RSEQ_ABORT) {
			break;
		}
		ASSERT(rval == RSEQ_OK);
	}
	return (rval);
}


/*ARGSUSED*/
static int
rseq_undo_common(rseq_t *rseq, int num, uintptr_t arg, int flags, int fail_err,
		uintptr_t fail_num)
{
	int		i;
	rseq_step_t	*s;
	int		rval = RSEQ_OK;

	for (i = num - 1; i >= 0; i--) {
		s = &rseq[i].r_undo;

		if (s->s_func == NULL) {
			continue;
		}
		s->s_rval = (i != fail_num) ? s->s_func(arg) : fail_err;
		rval = (s->s_cb) ? (s->s_cb(rseq, i, arg)) : RSEQ_OK;

		if (rval == RSEQ_ABORT) {
			break;
		}
		ASSERT(rval == RSEQ_OK);
	}
	return (rval);
}


int
rseq_do(rseq_t *rseq, int num, uintptr_t arg, int flags)
{
	return (rseq_do_common(rseq, num, arg, flags, 0, -1));
}


int
rseq_undo(rseq_t *rseq, int num, uintptr_t arg, int flags)
{
	return (rseq_undo_common(rseq, num, arg, flags, 0, -1));
}

#ifdef DEBUG

#ifndef __lock_lint

static int
rseq_debug(rseq_t *rseq, int num, uintptr_t arg, int flags, int scenario,
		uintptr_t sarg1, uintptr_t sarg2,
		int (*func)(rseq_t *, int, uintptr_t, int, int, uintptr_t))
{
	int	rnd, rval = RSEQ_OK, i;

	switch (scenario) {
	case RSEQ_DBG_FAIL_ONE:
		rval = func(rseq, num, arg, flags, sarg1, sarg2);
		break;
	case RSEQ_DBG_FAIL_ONE_RANDOM:
		rnd = random() % num;
		rval = func(rseq, num, arg, flags, sarg1, rnd);
		break;
	case RSEQ_DBG_FAIL_ONEBYONE:
		for (i = 0; i < num; i++) {
			rval = func(rseq, num, arg, flags, sarg1, i);
			/*
			 * when aborted, the undo path is not executed, so we
			 * can't continue without the risk of resource leakage.
			 */
			if (rval == RSEQ_ABORT) {
				break;
			}
		}
		break;
	default:
		ASSERT(!"rseq_debug: incorrect debug scenario");
		rval = RSEQ_ABORT;
	}
	return (rval);
}


int
rseq_do_debug(rseq_t *rseq, int num, uintptr_t arg, int flags, int scenario,
		uintptr_t sarg1, uintptr_t sarg2)
{
	return (rseq_debug(rseq, num, arg, flags, scenario, sarg1, sarg2,
	    rseq_do_common));
}


int
rseq_undo_debug(rseq_t *rseq, int num, uintptr_t arg, int flags, int scenario,
		uintptr_t sarg1, uintptr_t sarg2)
{
	return (rseq_debug(rseq, num, arg, flags, scenario, sarg1, sarg2,
	    rseq_undo_common));
}

#ifdef _KERNEL
static long
rseq_random()
{
	return (ddi_get_lbolt());
}
#endif /* _KERNEL */

#endif /* __lock_lint */

#endif /* DEBUG */
