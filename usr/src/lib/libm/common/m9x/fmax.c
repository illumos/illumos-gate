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

#pragma weak fmax = __fmax

/*
 * fmax(x,y) returns the larger of x and y.  If just one of the
 * arguments is NaN, fmax returns the other argument.  If both
 * arguments are NaN, fmax returns NaN.
 *
 * See fmaxf.c for a discussion of implementation trade-offs.
 */

#include "libm.h"	/* for isgreaterequal macro */
#include <fenv.h>

double
__fmax(double x, double y) {
	union {
		unsigned i[2];
		double d;
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
	xx.d = x;
	yy.d = y;
#if defined(__sparc)
	s = ~(xx.i[0] & yy.i[0]) & 0x80000000;
	xx.i[0] &= ~s;
#elif defined(__x86)
	s = ~(xx.i[1] & yy.i[1]) & 0x80000000;
	xx.i[1] &= ~s;
#else
#error Unknown architecture
#endif

	return (xx.d);
}
