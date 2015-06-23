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

#pragma weak frexp = __frexp

/*
 * frexp(x, exp) returns the normalized significand of x and sets
 * *exp so that x = r*2^(*exp) where r is the return value.  If x
 * is finite and nonzero, 1/2 <= |r| < 1.
 *
 * If x is zero, infinite or NaN, frexp returns x and sets *exp = 0.
 * (The relevant standards do not specify *exp when x is infinite or
 * NaN, but this code sets it anyway.)
 *
 * If x is a signaling NaN, this code returns x without attempting
 * to raise the invalid operation exception.  If x is subnormal,
 * this code treats it as nonzero regardless of nonstandard mode.
 */

#include "libm.h"

double
__frexp(double x, int *exp) {
	union {
		unsigned i[2];
		double d;
	} xx, yy;
	double t;
	unsigned hx;
	int e;

	xx.d = x;
	hx = xx.i[HIWORD] & ~0x80000000;

	if (hx >= 0x7ff00000) { /* x is infinite or NaN */
		*exp = 0;
		return (x);
	}

	e = 0;
	if (hx < 0x00100000) { /* x is subnormal or zero */
		if ((hx | xx.i[LOWORD]) == 0) {
			*exp = 0;
			return (x);
		}

		/*
		 * normalize x by regarding it as an integer
		 *
		 * Here we use 32-bit integer arithmetic to avoid trapping
		 * or emulating 64-bit arithmetic.  If 64-bit arithmetic is
		 * available (e.g., in SPARC V9), do this instead:
		 *
		 *  long lx = ((long) hx << 32) | xx.i[LOWORD];
		 *  xx.d = (xx.i[HIWORD] < 0)? -lx : lx;
		 *
		 * If subnormal arithmetic doesn't trap, just multiply x by
		 * a power of two.
		 */
		yy.i[HIWORD] = 0x43300000 | hx;
		yy.i[LOWORD] = xx.i[LOWORD];
		t = yy.d;
		yy.i[HIWORD] = 0x43300000;
		yy.i[LOWORD] = 0;
		t -= yy.d; /* t = |x| scaled */
		xx.d = ((int)xx.i[HIWORD] < 0)? -t : t;
		hx = xx.i[HIWORD] & ~0x80000000;
		e = -1074;
	}

	/* now xx.d is normal */
	xx.i[HIWORD] = (xx.i[HIWORD] & ~0x7ff00000) | 0x3fe00000;
	*exp = e + (hx >> 20) - 0x3fe;
	return (xx.d);
}
