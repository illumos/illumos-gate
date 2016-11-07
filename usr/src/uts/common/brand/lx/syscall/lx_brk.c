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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>

/*
 * The brk() system call needs to be in-kernel because Linux expects a call to
 * brk(0) to return the current breakpoint.  In Solaris, the process breakpoint
 * is setup and managed by libc.  Due to the way we link our libraries and the
 * need for Linux to manage its own breakpoint, this has to remain in the
 * kernel.
 */
extern intptr_t brk(caddr_t);

long
lx_brk(caddr_t nva)
{
	proc_t *p = curproc;
	klwp_t *lwp = ttolwp(curthread);

	if (nva != 0) {
		(void) brk(nva);

		/*
		 * Despite claims to the contrary in the manpage, when Linux
		 * brk() fails, errno is left unchanged.
		 */
		lwp->lwp_errno = 0;
	}
	return ((long)(p->p_brkbase + p->p_brksize));
}
