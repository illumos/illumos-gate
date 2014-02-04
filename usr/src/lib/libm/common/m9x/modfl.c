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
#pragma weak modfl = __modfl
#endif

#include "libm.h"

#if defined(__sparc)

long double
__modfl(long double x, long double *iptr) {
	union {
		unsigned i[4];
		long double q;
	} xx, yy;
	unsigned hx, s;

	xx.q = x;
	hx = xx.i[0] & ~0x80000000;

	if (hx >= 0x406f0000) {	/* x is NaN, infinite, or integral */
		*iptr = x;
		if (hx < 0x7fff0000 || (hx == 0x7fff0000 &&
			(xx.i[1] | xx.i[2] | xx.i[3]) == 0)) {
			xx.i[0] &= 0x80000000;
			xx.i[1] = xx.i[2] = xx.i[3] = 0;
		}
		return (xx.q);
	}

	if (hx < 0x3fff0000) {	/* |x| < 1 */
		xx.i[0] &= 0x80000000;
		xx.i[1] = xx.i[2] = xx.i[3] = 0;
		*iptr = xx.q;
		return (x);
	}

	/* split x at the binary point */
	s = xx.i[0] & 0x80000000;
	if (hx < 0x40100000) {
		yy.i[0] = xx.i[0] & ~((1 << (0x400f - (hx >> 16))) - 1);
		yy.i[1] = yy.i[2] = yy.i[3] = 0;
	} else if (hx < 0x40300000) {
		yy.i[0] = xx.i[0];
		yy.i[1] = xx.i[1] & ~((1 << (0x402f - (hx >> 16))) - 1);
		yy.i[2] = yy.i[3] = 0;
	} else if (hx < 0x40500000) {
		yy.i[0] = xx.i[0];
		yy.i[1] = xx.i[1];
		yy.i[2] = xx.i[2] & ~((1 << (0x404f - (hx >> 16))) - 1);
		yy.i[3] = 0;
	} else {
		yy.i[0] = xx.i[0];
		yy.i[1] = xx.i[1];
		yy.i[2] = xx.i[2];
		yy.i[3] = xx.i[3] & ~((1 << (0x406f - (hx >> 16))) - 1);
	}
	*iptr = yy.q;

	/*
	 * we could implement the following more efficiently than by using
	 * software emulation of fsubq, but we'll do it this way for now
	 * (and hope hardware support becomes commonplace)
	 */
	xx.q -= yy.q;
	xx.i[0] = (xx.i[0] & ~0x80000000) | s;	/* keep sign of x */
	return (xx.q);
}

#elif defined(__x86)

long double
__modfl(long double x, long double *iptr) {
	union {
		unsigned i[3];
		long double e;
	} xx, yy;
	unsigned hx, s;

	/*
	 * It might be faster to use one of the x86 fpops instead of
	 * the following.
	 */
	xx.e = x;
	hx = xx.i[2] & 0x7fff;

	if (hx >= 0x403e) {	/* x is NaN, infinite, or integral */
		*iptr = x;
		if (hx < 0x7fff || (hx == 0x7fff &&
			((xx.i[1] << 1) | xx.i[0]) == 0)) {
			xx.i[2] &= 0x8000;
			xx.i[1] = xx.i[0] = 0;
		}
		return (xx.e);
	}

	if (hx < 0x3fff) {	/* |x| < 1 */
		xx.i[2] &= 0x8000;
		xx.i[1] = xx.i[0] = 0;
		*iptr = xx.e;
		return (x);
	}

	/* split x at the binary point */
	s = xx.i[2] & 0x8000;
	yy.i[2] = xx.i[2];
	if (hx < 0x401f) {
		yy.i[1] = xx.i[1] & ~((1 << (0x401e - hx)) - 1);
		yy.i[0] = 0;
	} else {
		yy.i[1] = xx.i[1];
		yy.i[0] = xx.i[0] & ~((1 << (0x403e - hx)) - 1);
	}
	*iptr = yy.e;
	xx.e -= yy.e;
	xx.i[2] = (xx.i[2] & ~0x8000) | s;	/* keep sign of x */
	return (xx.e);
}

#else
#error Unknown architecture
#endif
