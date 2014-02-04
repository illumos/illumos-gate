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

#if defined(ELFOBJ)
#pragma weak modf = __modf
#pragma weak _modf = __modf
#endif

/*
 * modf(x, iptr) decomposes x into an integral part and a fractional
 * part both having the same sign as x.  It stores the integral part
 * in *iptr and returns the fractional part.
 *
 * If x is infinite, modf sets *iptr to x and returns copysign(0.0,x).
 * If x is NaN, modf sets *iptr to x and returns x.
 *
 * If x is a signaling NaN, this code does not attempt to raise the
 * invalid operation exception.
 */

#include "libm.h"

double
__modf(double x, double *iptr) {
	union {
		unsigned i[2];
		double d;
	} xx, yy;
	unsigned hx, s;

	xx.d = x;
	hx = xx.i[HIWORD] & ~0x80000000;

	if (hx >= 0x43300000) {	/* x is NaN, infinite, or integral */
		*iptr = x;
		if (hx < 0x7ff00000 || (hx == 0x7ff00000 &&
			xx.i[LOWORD] == 0)) {
			xx.i[HIWORD] &= 0x80000000;
			xx.i[LOWORD] = 0;
		}
		return (xx.d);
	}

	if (hx < 0x3ff00000) {	/* |x| < 1 */
		xx.i[HIWORD] &= 0x80000000;
		xx.i[LOWORD] = 0;
		*iptr = xx.d;
		return (x);
	}

	/* split x at the binary point */
	s = xx.i[HIWORD] & 0x80000000;
	if (hx < 0x41400000) {
		yy.i[HIWORD] = xx.i[HIWORD] & ~((1 << (0x413 - (hx >> 20))) -
			1);
		yy.i[LOWORD] = 0;
	} else {
		yy.i[HIWORD] = xx.i[HIWORD];
		yy.i[LOWORD] = xx.i[LOWORD] & ~((1 << (0x433 - (hx >> 20))) -
			1);
	}
	*iptr = yy.d;
	xx.d -= yy.d;
	xx.i[HIWORD] = (xx.i[HIWORD] & ~0x80000000) | s;
							/* keep sign of x */
	return (xx.d);
}
