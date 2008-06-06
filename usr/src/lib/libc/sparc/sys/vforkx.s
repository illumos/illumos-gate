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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#include "SYS.h"
#include <assym.h>

/*
 * pid = vforkx(flags);
 * syscall trap: forksys(2, flags)
 *
 * pid = vfork();
 * syscall trap: forksys(2, 0)
 *
 * From the syscall:
 * %o1 == 0 in parent process, %o1 == 1 in child process.
 * %o0 == pid of child in parent, %o0 == pid of parent in child.
 *
 * The child gets a zero return value.
 * The parent gets the pid of the child.
 */

/*
 * Note that since the SPARC architecture maintains stack maintence
 * information (return pc, sp, fp) in the register windows, both parent
 * and child can execute in a common address space without conflict.
 *
 * We block all blockable signals while performing the vfork() system call
 * trap.  This enables us to set curthread->ul_vfork safely, so that we
 * don't end up in a signal handler with curthread->ul_vfork set wrong.
 */

	ENTRY_NP(vforkx)
	ba	0f
	mov	%o0, %o3		/* flags */
	ENTRY_NP(vfork)
	clr	%o3			/* flags = 0 */
0:
	mov	SIG_SETMASK, %o0	/* block all signals */
	set	MASKSET0, %o1
	set	MASKSET1, %o2
	SYSTRAP_2RVALS(lwp_sigmask)

	mov	%o3, %o1		/* flags */
	mov	2, %o0
	SYSTRAP_2RVALS(forksys)		/* vforkx(flags) */
	bcc,a,pt %icc, 1f
	tst	%o1

	mov	%o0, %o3		/* save the vfork() error number */

	mov	SIG_SETMASK, %o0	/* reinstate signals */
	ld	[%g7 + UL_SIGMASK], %o1
	ld	[%g7 + UL_SIGMASK + 4], %o2
	SYSTRAP_2RVALS(lwp_sigmask)

	ba	__cerror
	mov	%o3, %o0		/* restore the vfork() error number */

1:
	/*
	 * To determine if we are (still) a child of vfork(), the child
	 * increments curthread->ul_vfork by one and the parent decrements
	 * it by one.  If the result is zero, then we are not a child of
	 * vfork(), else we are.  We do this to deal with the case of
	 * a vfork() child calling vfork().
	 */
	bnz,pt	%icc, 2f
	ld	[%g7 + UL_VFORK], %g1
	brnz,a,pt %g1, 3f		/* don't let it go negative */
	sub	%g1, 1, %g1		/* curthread->ul_vfork--; */
	ba,a	3f
2:
	clr	%o0			/* zero the return value in the child */
	add	%g1, 1, %g1		/* curthread->ul_vfork++; */
3:
	st	%g1, [%g7 + UL_VFORK]
	/*
	 * Clear the schedctl interface in both parent and child.
	 * (The child might have modified the parent.)
	 */
	stn	%g0, [%g7 + UL_SCHEDCTL]
	stn	%g0, [%g7 + UL_SCHEDCTL_CALLED]
	mov	%o0, %o3		/* save the vfork() return value */

	mov	SIG_SETMASK, %o0	/* reinstate signals */
	ld	[%g7 + UL_SIGMASK], %o1
	ld	[%g7 + UL_SIGMASK + 4], %o2
	SYSTRAP_2RVALS(lwp_sigmask)

	retl
	mov	%o3, %o0		/* restore the vfork() return value */
	SET_SIZE(vfork)
	SET_SIZE(vforkx)
