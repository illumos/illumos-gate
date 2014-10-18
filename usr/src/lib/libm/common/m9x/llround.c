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
#pragma weak llround = __llround
#if defined(__sparcv9) || defined(__amd64)
#pragma weak lround = __llround
#pragma weak __lround = __llround
#endif
#endif

/*
 * llround(x) rounds its argument to the nearest integer, rounding
 * ties away from zero, and converts the result to a 64 bit signed
 * integer.
 *
 * If x is NaN, infinite, or so large that the nearest integer
 * would exceed 64 bits, the invalid operation exception is raised.
 */

#include "libm.h"

long long
llround(double x) {
	union {
		unsigned i[2];
		double d;
	} xx;
	unsigned hx, sx, i;

	xx.d = x;
	hx = xx.i[HIWORD] & ~0x80000000;
	sx = xx.i[HIWORD] & 0x80000000;

	if (hx < 0x43300000) { /* |x| < 2^52 */
		/* handle |x| < 1 */
		if (hx < 0x3ff00000) {
			if (hx >= 0x3fe00000)
				return (sx ? -1LL : 1LL);
			return (0LL);
		}

		/* round x at the integer bit */
		if (hx < 0x41300000) {
			i = 1 << (0x412 - (hx >> 20));
			xx.i[HIWORD] = (xx.i[HIWORD] + i) & ~(i | (i - 1));
			xx.i[LOWORD] = 0;
		} else {
			i = 1 << (0x432 - (hx >> 20));
			xx.i[LOWORD] += i;
			if (xx.i[LOWORD] < i)
				xx.i[HIWORD]++;
			xx.i[LOWORD] &= ~(i | (i - 1));
		}
	}

	/* now x is nan, inf, or integral */
	return ((long long) xx.d);
}
