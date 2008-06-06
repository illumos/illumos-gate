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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "thr_uberdata.h"
#include "stack_unwind.h"
#include "reg_num.h"
#include <dlfcn.h>

/*
 * Due to the subtle mysteries of the amd64 unwind interfaces, the
 * "Canonical Frame Address" is 16 bytes higher in memory than the
 * value of the frame pointer (%fp).
 */
#define	CFA_ADJUST	16

/* ARGSUSED */
static _Unwind_Reason_Code
posix_stop_func(
	int version,
	_Unwind_Action _Unwind_actions,
	uint64_t exceptionClass,
	struct _Unwind_Exception *exceptionObject,
	struct _Unwind_Context *context,
	void *func_arg)
{
	__cleanup_t **headp = (__cleanup_t **)func_arg;
	__cleanup_t *head;
	uint64_t cfa;

	/*
	 * If we have reached the origin of the stack, exit now.
	 */
	cfa = _Unwind_GetCFA(context);
	if (cfa == 0 || _Unwind_GetGR(context, RET_ADD) == 0) {
		_Unwind_DeleteException(exceptionObject);
		_thrp_exit();
		thr_panic("posix_stop_func(): _thrp_exit() returned");
	}

	/*
	 * Call all Posix cleanup handlers for this frame.
	 */
	while ((head = *headp) != NULL &&
	    (caddr_t)cfa == head->fp + CFA_ADJUST) {
		*headp = head->next;
		(*head->func)(head->arg);
	}

	return (_URC_NO_REASON);
}

/*
 * _ex_unwind() is provided by libCrun to perform stack unwinding
 * and calling C++ destructors as needed, interleaved with calling
 * Posix cleanup handlers along the way.  If libCrun is not present
 * we just need to call the Posix cleanup handlers.
 */

/* ARGSUSED */
void
_thrp_unwind(void *dummy)
{
	ulwp_t *self = curthread;
	__cleanup_t **headp = &self->ul_clnup_hdr;
	__cleanup_t *head;
	void (*fptr)(_Unwind_Stop_Fn, void *);

	/* Do this once per thread exit, not once per unwind frame */
	if (self->ul_ex_unwind == NULL &&
	    (self->ul_ex_unwind = dlsym(RTLD_PROBE, "_ex_unwind")) == NULL)
		self->ul_ex_unwind = (void *)-1;

	if (self->ul_ex_unwind == (void *)-1)
		fptr = NULL;
	else
		fptr = (void (*)())self->ul_ex_unwind;

	/*
	 * Call _ex_unwind() if it is present (C++ loaded),
	 * else just call the Posix cleanup handlers.
	 */
	if (fptr != NULL)
		(*fptr)(posix_stop_func, headp);

	/*
	 * Call all remaining Posix cleanup handlers.
	 */
	while ((head = *headp) != NULL) {
		*headp = head->next;
		(*head->func)(head->arg);
	}

	_thrp_exit();
	thr_panic("_thrp_unwind(): _thrp_exit() returned");
}
