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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak fmaxf = __fmaxf

/*
 * fmax(x,y) returns the larger of x and y.  If just one of the
 * arguments is NaN, fmax returns the other argument.  If both
 * arguments are NaN, fmax returns NaN (ideally, one of the
 * argument NaNs).
 *
 * C99 does not require that fmax(-0,+0) = fmax(+0,-0) = +0, but
 * ideally fmax should satisfy this.
 *
 * C99 makes no mention of exceptions for fmax.  I suppose ideally
 * either fmax never raises any exceptions or else it raises the
 * invalid operation exception if and only if some argument is a
 * signaling NaN.  In the former case, fmax should always return
 * one of its arguments.  In the latter, fmax shouldn't return a
 * signaling NaN, although when both arguments are signaling NaNs,
 * this ideal is at odds with the stipulation that fmax should
 * always return one of its arguments.
 *
 * Commutativity of fmax follows from the properties listed above
 * except when both arguments are NaN.  In that case, fmax may be
 * declared commutative by fiat because there is no portable way
 * to tell different NaNs apart.  Ideally fmax would be truly com-
 * mutative for all arguments.
 *
 * On SPARC V8, fmax must involve tests and branches.  Ideally,
 * an implementation on SPARC V9 should avoid branching, using
 * conditional moves instead where necessary, and be as efficient
 * as possible in its use of other resources.
 *
 * It appears to be impossible to attain all of the aforementioned
 * ideals simultaneously.  The implementation below satisfies the
 * following (on SPARC):
 *
 * 1. fmax(x,y) returns the larger of x and y if neither x nor y
 *    is NaN and the non-NaN argument if just one of x or y is NaN.
 *    If both x and y are NaN, fmax(x,y) returns x unchanged.
 * 2. fmax(-0,+0) = fmax(+0,-0) = +0.
 * 3. If either argument is a signaling NaN, fmax raises the invalid
 *    operation exception.  Otherwise, it raises no exceptions.
 */

#include "libm.h"	/* for isgreaterequal macro */

float
__fmaxf(float x, float y) {
	/*
	 * On SPARC v8plus/v9, this could be implemented as follows
	 * (assuming %f0 = x, %f1 = y, return value left in %f0):
	 *
	 * fcmps	%fcc0,%f1,%f1
	 * fmovsu	%fcc0,%f0,%f1
	 * fcmps	%fcc0,%f0,%f1
	 * fmovsul	%fcc0,%f1,%f0
	 * st		%f0,[x]
	 * st		%f1,[y]
	 * ld		[x],%l0
	 * ld		[y],%l1
	 * and		%l0,%l1,%l2
	 * sethi	%hi(0x80000000),%l3
	 * andn		%l3,%l2,%l2
	 * andn		%l0,%l2,%l0
	 * st		%l0,[x]
	 * ld		[x],%f0
	 *
	 * If VIS instructions are available, use this code instead:
	 *
	 * fcmps	%fcc0,%f1,%f1
	 * fmovsu	%fcc0,%f0,%f1
	 * fcmps	%fcc0,%f0,%f1
	 * fmovsul	%fcc0,%f1,%f0
	 * fands	%f0,%f1,%f2
	 * fzeros	%f3
	 * fnegs	%f3,%f3
	 * fandnot2s %f3,%f2,%f2
	 * fandnot2s %f0,%f2,%f0
	 *
	 * If VIS 3.0 instructions are available, use this:
	 *
	 * flcmps	%fcc0,%f0,%f1
	 * fmovslg	%fcc0,%f1,%f0	! move if %fcc0 is 1 or 2
	 */

	union {
		unsigned i;
		float f;
	} xx, yy;
	unsigned s;

	/* if y is nan, replace it by x */
	if (y != y)
		y = x;

	/* if x is nan, replace it by y */
	if (x != x)
		x = y;

	/* At this point, x and y are either both numeric, or both NaN */
	if (!isnan(x) && !isgreaterequal(x, y))
		x = y;

	/*
	 * clear the sign of the result if either x or y has its sign clear
	 */
	xx.f = x;
	yy.f = y;
	s = ~(xx.i & yy.i) & 0x80000000;
	xx.i &= ~s;

	return (xx.f);
}
