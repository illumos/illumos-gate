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

#pragma weak fminf = __fminf

#include "libm.h"	/* for islessequal macro */

float
__fminf(float x, float y) {
	/*
	 * On SPARC v8plus/v9, this could be implemented as follows
	 * (assuming %f0 = x, %f1 = y, return value left in %f0):
	 *
	 * fcmps	%fcc0,%f1,%f1
	 * fmovsu	%fcc0,%f0,%f1
	 * fcmps	%fcc0,%f0,%f1
	 * fmovsug	%fcc0,%f1,%f0
	 * st		%f0,[x]
	 * st		%f1,[y]
	 * ld		[x],%l0
	 * ld		[y],%l1
	 * or		%l0,%l1,%l2
	 * sethi	%hi(0x80000000),%l3
	 * and		%l3,%l2,%l2
	 * or		%l0,%l2,%l0
	 * st		%l0,[x]
	 * ld		[x],%f0
	 *
	 * If VIS instructions are available, use this code instead:
	 *
	 * fcmps	%fcc0,%f1,%f1
	 * fmovsu	%fcc0,%f0,%f1
	 * fcmps	%fcc0,%f0,%f1
	 * fmovsug	%fcc0,%f1,%f0
	 * fors		%f0,%f1,%f2
	 * fzeros	%f3
	 * fnegs	%f3,%f3
	 * fands	%f3,%f2,%f2
	 * fors		%f0,%f2,%f0
	 *
	 * If VIS 3.0 instructions are available, use this:
	 *
	 * flcmps	%fcc0,%f0,%f1
	 * fmovsge	%fcc0,%f1,%f0	! move if %fcc0 is 0 or 2
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
	if (!isnan(x) && !islessequal(x, y))
		x = y;

	/*
	 * set the sign of the result if either x or y has its sign set
	 */
	xx.f = x;
	yy.f = y;
	s = (xx.i | yy.i) & 0x80000000;
	xx.i |= s;

	return (xx.f);
}
