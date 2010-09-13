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

	.ident	"%Z%%M%	%I%	%E% SMI"

	.file	"muldiv.s"

#include <SYS.h>

	ENTRY(.udiv)
	wr	%g0, %g0, %y
	nop
	nop
	mov	%o0, %o3	! o3 gets remainder
	udiv	%o0, %o1, %o0	! o0 contains quotient a/b
	umul	%o0, %o1, %o4	! o4 contains q*b
	retl
	sub	%o3, %o4, %o3	! o3 gets a-q*b
	SET_SIZE(.udiv)

	ENTRY(.div)
	sra	%o0,31,%o4	! extend sign
	wr	%o4,%g0,%y
	cmp	%o1,0xffffffff	! is divisor -1?
	be,a	1f		! if yes
	subcc	%g0,%o0,%o0	! simply negate dividend
	mov	%o0,%o3 	! o3 gets remainder
	sdiv	%o0,%o1,%o0	! o0 contains quotient a/b
	smul	%o0,%o1,%o4	! o4 contains q*b
	retl
	sub	%o3,%o4,%o3	! o3 gets a-q*b
1:
	retl
	mov	%g0,%o3 	! remainder is 0
	SET_SIZE(.div)
