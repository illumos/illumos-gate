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

#include "lint.h"
#include "thr_uberdata.h"
#include <dlfcn.h>

/*
 * This is common code for sparc, sparcv9, and i386.
 * The amd64 unwind code is vastly different from this.
 * Look under the amd64-specific directory structure for details.
 */

/*
 * _ex_unwind() is provided by libC, but if libC is not loaded we
 * need to call a local version of _ex_unwind() which does exactly
 * the same thing except for calling C++ destructors.
 *
 * Note that neither of these literally "returns twice" as, for eg, setjmp
 * does, but they induce unusual control flow which the compiler should treat
 * in the same manner (make all registers dead, etc.).
 */
extern	void	_ex_clnup_handler(void *, void (*)(void *)) __RETURNS_TWICE;
extern	void	_ex_unwind_local(void) __RETURNS_TWICE;

/*
 * _t_cancel(fp):calls cleanup handlers if there are any in
 *		 frame (fp), and calls _ex_unwind() to call
 *		 destructors if libC has been linked.
 *
 * Control comes here from _thrp_unwind.  Logically:
 *
 *	_thrp_unwind: first arg = current fp;
 *	    jump _t_cancel;
 *
 * We could have called _t_cancel(_getfp) from thr_exit()
 * but _ex_unwind() also calls _t_cancel() and it does after
 * poping out the two frames.  If _ex_unwind() passes the current
 * fp, then it will be invalid.  For a caller of _thrp_unwind()
 * it looks as if it is calling _t_cancel(fp).
 *
 * _t_cancel will eventually call _thrp_exit().
 * It never returns from _t_cancel().
 *
 */
void
_t_cancel(void *fp)
{
	ulwp_t *self = curthread;
	__cleanup_t *head;
	void (*fptr)(void (*func)(void *), void *arg);

	/* Do this once per thread exit, not once per unwind frame */
	if (self->ul_ex_unwind == NULL &&
	    (self->ul_ex_unwind = dlsym(RTLD_PROBE, "_ex_unwind")) == NULL)
		self->ul_ex_unwind = (void *)-1;

	if (self->ul_ex_unwind == (void *)-1)
		fptr = NULL;
	else
		fptr = (void (*)())self->ul_ex_unwind;

	if (fp == NULL) {
		_thrp_exit();
		thr_panic("_t_cancel(): _thrp_exit() returned");
	}

	if ((head = self->ul_clnup_hdr) != NULL && fp == head->fp) {
		self->ul_clnup_hdr = head->next;
		/* execute the cleanup handler */
		_ex_clnup_handler(head->arg, head->func);
		thr_panic("_t_cancel(): _ex_clnup_handler() returned");
	}

	if (fptr != NULL && self->ul_unwind) {
		/* libC is loaded and thread is canceled, call libC version */
		(*fptr)(_thrp_unwind, NULL);
		thr_panic("_t_cancel(): _ex_unwind() returned");
	} else if (head != NULL) {
		/* libC not present, call local version */
		_ex_unwind_local();
		thr_panic("_t_cancel(): _ex_unwind_local() returned");
	} else {
		/* libC not present and no cleanup handlers, exit here */
		_thrp_exit();
		thr_panic("_t_cancel(): _thrp_exit() returned");
	}
	/* never returns here */
}
