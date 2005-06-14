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
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/stack.h>
#include <sys/privregs.h>

int
door_finish_dispatch(caddr_t newsp)
{
	void lwp_setsp(klwp_t *, caddr_t);

	/*
	 * If being traced, need to copy in syscall arguments for /proc
	 * before changing the sp.  In most cases, this will have no
	 * effect, since we'll have already done this in door_return().
	 */
	if (curthread->t_post_sys && PTOU(ttoproc(curthread))->u_systrap)
		(void) save_syscall_args();
	lwp_setsp(ttolwp(curthread), newsp);
	lwptoregs(ttolwp(curthread))->r_fp = 0;	/* stack ends here */

	return (0);
}

/*ARGSUSED*/
uintptr_t
door_final_sp(uintptr_t resultsp, size_t align, int datamodel)
{
	return (resultsp);
}
