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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/door.h>
#include <sys/stack.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>

int
door_finish_dispatch(caddr_t newsp)
{
	void lwp_setsp(klwp_t *, caddr_t);
	void lwp_clear_uwin(void);

	char bytes[MAX(MINFRAME, MINFRAME32)];
	size_t count;
	caddr_t biased_sp;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		count = MINFRAME;
		biased_sp = newsp - STACK_BIAS;
	} else {
		count = MINFRAME32;
		biased_sp = newsp;
	}

	/*
	 * We carefully zero out the stack frame we're pointing %sp at.
	 * This means that, upon returning to userland, the ins and locals
	 * will be zeroed, instead of acquiring whatever garbage was on the
	 * stack previously.  In particular, this makes sure %fp is NULL,
	 * so that stack traces are properly terminated.
	 */
	bzero(bytes, count);
	if (copyout(bytes, newsp, count) != 0)
		return (E2BIG);

	/*
	 * There may be some user register windows stashed away
	 * because our user thread stack wasn't available during some
	 * kernel overflows. We don't care about this saved user
	 * state since we are resetting our stack. Make sure we
	 * don't try to push these registers out to our stack
	 * later on when returning from this system call.
	 *
	 * We have guaranteed that no new user windows will be stored
	 * to the pcb save area at this point since a door server
	 * thread always does a full context switch (shuttle_switch,
	 * shuttle_resume) before making itself available for a door
	 * invocation.
	 */
	lwp_clear_uwin();
	lwp_setsp(ttolwp(curthread), biased_sp);
	return (0);
}

uintptr_t
door_final_sp(uintptr_t resultsp, size_t align, int datamodel)
{
	size_t minframe = (datamodel == DATAMODEL_NATIVE)?
	    MINFRAME : MINFRAME32;
	return (P2ALIGN(resultsp - minframe, align));
}
