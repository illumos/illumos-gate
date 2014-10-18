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

#pragma weak csqrtl = __csqrtl

#include "libm.h"		/* fabsl/isinfl/sqrtl */
#include "complex_wrapper.h"
#include "longdouble.h"

/* INDENT OFF */
static const long double
	twom9001 = 2.6854002716003034957421765100615693043656e-2710L,
	twom4500 = 2.3174987687592429423263242862381544149252e-1355L,
	two8999 = 9.3095991180122343502582347372163290310934e+2708L,
	two4500 = 4.3149968987270974283777803545571722250806e+1354L,
	zero = 0.0L,
	half = 0.5L,
	two = 2.0L;
/* INDENT ON */

ldcomplex
csqrtl(ldcomplex z) {
	ldcomplex ans;
	long double x, y, t, ax, ay;
	int n, ix, iy, hx, hy;

	x = LD_RE(z);
	y = LD_IM(z);
	hx = HI_XWORD(x);
	hy = HI_XWORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	ay = fabsl(y);
	ax = fabsl(x);
	if (ix >= 0x7fff0000 || iy >= 0x7fff0000) {
		/* x or y is Inf or NaN */
		if (isinfl(y))
			LD_IM(ans) = LD_RE(ans) = ay;
		else if (isinfl(x)) {
			if (hx > 0) {
				LD_RE(ans) = ax;
				LD_IM(ans) = ay * zero;
			} else {
				LD_RE(ans) = ay * zero;
				LD_IM(ans) = ax;
			}
		} else
			LD_IM(ans) = LD_RE(ans) = ax + ay;
	} else if (y == zero) {
		if (hx >= 0) {
			LD_RE(ans) = sqrtl(ax);
			LD_IM(ans) = zero;
		} else {
			LD_IM(ans) = sqrtl(ax);
			LD_RE(ans) = zero;
		}
	} else if (ix >= iy) {
		n = (ix - iy) >> 16;
#if defined(__x86)		/* 64 significant bits */
		if (n >= 35)
#else				/* 113 significant bits  */
		if (n >= 60)
#endif
			t = sqrtl(ax);
		else if (ix >= 0x5f3f0000) {	/* x > 2**8000 */
			ax *= twom9001;
			y *= twom9001;
			t = two4500 * sqrtl(ax + sqrtl(ax * ax + y * y));
		} else if (iy <= 0x20bf0000) {	/* y < 2**-8000 */
			ax *= two8999;
			y *= two8999;
			t = twom4500 * sqrtl(ax + sqrtl(ax * ax + y * y));
		} else
			t = sqrtl(half * (ax + sqrtl(ax * ax + y * y)));

		if (hx >= 0) {
			LD_RE(ans) = t;
			LD_IM(ans) = ay / (t + t);
		} else {
			LD_IM(ans) = t;
			LD_RE(ans) = ay / (t + t);
		}
	} else {
		n = (iy - ix) >> 16;
#if defined(__x86)		/* 64 significant bits */
		if (n >= 35) {	/* } */
#else				/* 113 significant bits  */
		if (n >= 60) {
#endif
			if (n >= 120)
				t = sqrtl(half * ay);
			else if (iy >= 0x7ffe0000)
				t = sqrtl(half * ay + half * ax);
			else if (ix <= 0x00010000)
				t = half * (sqrtl(two * (ax + ay)));
			else
				t = sqrtl(half * (ax + ay));
		} else if (iy >= 0x5f3f0000) {	/* y > 2**8000 */
			ax *= twom9001;
			y *= twom9001;
			t = two4500 * sqrtl(ax + sqrtl(ax * ax + y * y));
		} else if (ix <= 0x20bf0000) {
			ax *= two8999;
			y *= two8999;
			t = twom4500 * sqrtl(ax + sqrtl(ax * ax + y * y));
		} else
			t = sqrtl(half * (ax + sqrtl(ax * ax + y * y)));

		if (hx >= 0) {
			LD_RE(ans) = t;
			LD_IM(ans) = ay / (t + t);
		} else {
			LD_IM(ans) = t;
			LD_RE(ans) = ay / (t + t);
		}
	}
	if (hy < 0)
		LD_IM(ans) = -LD_IM(ans);
	return (ans);
}
