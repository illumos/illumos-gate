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

#pragma weak __csqrt = csqrt

/* INDENT OFF */
/*
 * dcomplex csqrt(dcomplex z);
 *
 *                                         2    2    2
 * Let w=r+i*s = sqrt(x+iy). Then (r + i s)  = r  - s  + i 2sr = x + i y.
 *
 * Hence x = r*r-s*s, y = 2sr.
 *
 * Note that x*x+y*y = (s*s+r*r)**2. Thus, we have
 *                        ________
 *            2    2     / 2    2
 *	(1) r  + s  = \/ x  + y  ,
 *
 *            2    2
 *       (2) r  - s  = x
 *
 *	(3) 2sr = y.
 *
 * Perform (1)-(2) and (1)+(2), we obtain
 *
 *              2
 *	(4) 2 r   = hypot(x,y)+x,
 *
 *              2
 *       (5) 2*s   = hypot(x,y)-x
 *                       ________
 *                      / 2    2
 * where hypot(x,y) = \/ x  + y  .
 *
 * In order to avoid numerical cancellation, we use formula (4) for
 * positive x, and (5) for negative x. The other component is then
 * computed by formula (3).
 *
 *
 * ALGORITHM
 * ------------------
 *
 * (assume x and y are of medium size, i.e., no over/underflow in squaring)
 *
 * If x >=0 then
 *                       ________
 *	               /  2    2
 *	       2     \/  x  + y    +  x                y
 *            r =   ---------------------,      s = -------;    (6)
 *			       2                      2 r
 *
 * (note that we choose sign(s) = sign(y) to force r >=0).
 * Otherwise,
 *                       ________
 *	               /  2    2
 *	       2     \/  x  + y    -  x                y
 *            s =   ---------------------,      r = -------;    (7)
 *			       2                      2 s
 *
 * EXCEPTION:
 *
 * One may use the polar coordinate of a complex number to justify the
 * following exception cases:
 *
 * EXCEPTION CASES (conform to ISO/IEC 9899:1999(E)):
 *    csqrt(+-0+ i 0   ) =  0    + i 0
 *    csqrt( x + i inf ) =  inf  + i inf for all x (including NaN)
 *    csqrt( x + i NaN ) =  NaN  + i NaN with invalid for finite x
 *    csqrt(-inf+ iy   ) =  0    + i inf for finite positive-signed y
 *    csqrt(+inf+ iy   ) =  inf  + i 0   for finite positive-signed y
 *    csqrt(-inf+ i NaN) =  NaN  +-i inf
 *    csqrt(+inf+ i NaN) =  inf  + i NaN
 *    csqrt(NaN + i y  ) =  NaN  + i NaN for finite y
 *    csqrt(NaN + i NaN) =  NaN  + i NaN
 */
/* INDENT ON */

#include "libm.h"		/* fabs/sqrt */
#include "complex_wrapper.h"

/* INDENT OFF */
static const double
	two300 = 2.03703597633448608627e+90,
	twom300 = 4.90909346529772655310e-91,
	two599 = 2.07475778444049647926e+180,
	twom601 = 1.20495993255144205887e-181,
	two = 2.0,
	zero = 0.0,
	half = 0.5;
/* INDENT ON */

dcomplex
csqrt(dcomplex z) {
	dcomplex ans;
	double x, y, t, ax, ay;
	int n, ix, iy, hx, hy, lx, ly;

	x = D_RE(z);
	y = D_IM(z);
	hx = HI_WORD(x);
	lx = LO_WORD(x);
	hy = HI_WORD(y);
	ly = LO_WORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	ay = fabs(y);
	ax = fabs(x);
	if (ix >= 0x7ff00000 || iy >= 0x7ff00000) {
		/* x or y is Inf or NaN */
		if (ISINF(iy, ly))
			D_IM(ans) = D_RE(ans) = ay;
		else if (ISINF(ix, lx)) {
			if (hx > 0) {
				D_RE(ans) = ax;
				D_IM(ans) = ay * zero;
			} else {
				D_RE(ans) = ay * zero;
				D_IM(ans) = ax;
			}
		} else
			D_IM(ans) = D_RE(ans) = ax + ay;
	} else if ((iy | ly) == 0) {	/* y = 0 */
		if (hx >= 0) {
			D_RE(ans) = sqrt(ax);
			D_IM(ans) = zero;
		} else {
			D_IM(ans) = sqrt(ax);
			D_RE(ans) = zero;
		}
	} else if (ix >= iy) {
		n = (ix - iy) >> 20;
		if (n >= 30) {	/* x >> y or y=0 */
			t = sqrt(ax);
		} else if (ix >= 0x5f300000) {	/* x > 2**500 */
			ax *= twom601;
			y *= twom601;
			t = two300 * sqrt(ax + sqrt(ax * ax + y * y));
		} else if (iy < 0x20b00000) {	/* y < 2**-500 */
			ax *= two599;
			y *= two599;
			t = twom300 * sqrt(ax + sqrt(ax * ax + y * y));
		} else
			t = sqrt(half * (ax + sqrt(ax * ax + ay * ay)));
		if (hx >= 0) {
			D_RE(ans) = t;
			D_IM(ans) = ay / (t + t);
		} else {
			D_IM(ans) = t;
			D_RE(ans) = ay / (t + t);
		}
	} else {
		n = (iy - ix) >> 20;
		if (n >= 30) {	/* y >> x */
			if (n >= 60)
				t = sqrt(half * ay);
			else if (iy >= 0x7fe00000)
				t = sqrt(half * ay + half * ax);
			else if (ix <= 0x00100000)
				t = half * sqrt(two * (ay + ax));
			else
				t = sqrt(half * (ay + ax));
		} else if (iy >= 0x5f300000) {	/* y > 2**500 */
			ax *= twom601;
			y *= twom601;
			t = two300 * sqrt(ax + sqrt(ax * ax + y * y));
		} else if (ix < 0x20b00000) {	/* x < 2**-500 */
			ax *= two599;
			y *= two599;
			t = twom300 * sqrt(ax + sqrt(ax * ax + y * y));
		} else
			t = sqrt(half * (ax + sqrt(ax * ax + ay * ay)));
		if (hx >= 0) {
			D_RE(ans) = t;
			D_IM(ans) = ay / (t + t);
		} else {
			D_IM(ans) = t;
			D_RE(ans) = ay / (t + t);
		}
	}
	if (hy < 0)
		D_IM(ans) = -D_IM(ans);
	return (ans);
}
