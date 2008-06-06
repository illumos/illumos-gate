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

	.file	"%M%"

#include "SYS.h"

	ANSI_PRAGMA_WEAK(gettimeofday,function)

/*
 *  implements int gettimeofday(struct timeval *tp, void *tzp)
 *
 *	note that tzp is always ignored
 */

	ENTRY(gettimeofday)
/*
 *	use long long gethrestime()
 */
	pushq	%rdi		/* pointer to timeval */
	SYSFASTTRAP(GETHRESTIME)
/*
 *	gethrestime trap returns seconds in %eax, nsecs in %edx
 *	need to convert nsecs to usecs & store into area pointed
 *	to by struct timeval * argument.
 */
	popq	%rcx		/* pointer to timeval */
	jrcxz	1f		/* bail if we get a null pointer */
	movq	%rax, (%rcx)	/* store seconds into timeval ptr	 */
	movl	$274877907, %eax	/* divide by 1000 as impl. by gcc */
	imull	%edx		/* See Hacker's Delight pg 162 */
	sarl	$6, %edx	/* simplified by 0 <= nsec <= 1e9 */
	movq	%rdx, 8(%rcx)	/* store usecs into timeval ptr + 8. */
1:
	RETC			/* return 0 */
	SET_SIZE(gettimeofday)

