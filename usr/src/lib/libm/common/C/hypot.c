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

#pragma weak __hypot = hypot

/* INDENT OFF */
/*
 * Hypot(x, y)
 * by K.C. Ng for SUN 4.0 libm, updated 3/11/2003.
 * Method :
 * A. When rounding is rounded-to-nearest:
 *	If z = x * x + y * y has error less than sqrt(2) / 2 ulp than
 *	sqrt(z) has error less than 1 ulp.
 *	So, compute sqrt(x*x+y*y) with some care as follows:
 *	Assume x > y > 0;
 *	1. Check whether save and set rounding to round-to-nearest
 *	2. if x > 2y  use
 *		xh*xh+(y*y+((x-xh)*(x+xh))) for x*x+y*y
 *	where xh = x with lower 32 bits cleared;  else
 *	3. if x <= 2y use
 *		x2h*yh+((x-y)*(x-y)+(x2h*(y-yh)+(x2-x2h)*y))
 *	where x2 = 2*x, x2h = 2x with lower 32 bits cleared, yh = y with
 *	lower 32 bits chopped.
 *
 * B. When rounding is not rounded-to-nearest:
 *	The following (magic) formula will yield an error less than 1 ulp.
 *	z = sqrt(x * x + y * y)
 *		hypot(x, y) = x + (y / ((x + z) / y))
 *
 * NOTE: DO NOT remove parenthsis!
 *
 * Special cases:
 *	hypot(x, y) is INF if x or y is +INF or -INF; else
 *	hypot(x, y) is NAN if x or y is NAN.
 *
 * Accuracy:
 * 	hypot(x, y) returns sqrt(x^2+y^2) with error less than 1 ulps
 *	(units in the last place)
 */

#include "libm.h"

static const double
	zero = 0.0,
	onep1u = 1.00000000000000022204e+00,	/* 0x3ff00000 1 = 1+2**-52 */
	twom53 = 1.11022302462515654042e-16,	/* 0x3ca00000 0 = 2**-53 */
	twom768 = 6.441148769597133308e-232,	/* 2^-768 */
	two768  = 1.552518092300708935e+231;	/* 2^768 */

/* INDENT ON */

double
hypot(double x, double y) {
	double xh, yh, w, ax, ay;
	int i, j, nx, ny, ix, iy, iscale = 0;
	unsigned lx, ly;

	ix = ((int *) &x)[HIWORD] & ~0x80000000;
	lx = ((int *) &x)[LOWORD];
	iy = ((int *) &y)[HIWORD] & ~0x80000000;
	ly = ((int *) &y)[LOWORD];
/*
 * Force ax = |x| ~>~ ay = |y|
 */
	if (iy > ix) {
		ax = fabs(y);
		ay = fabs(x);
		i = ix;
		ix = iy;
		iy = i;
		i = lx;
		lx = ly;
		ly = i;
	} else {
		ax = fabs(x);
		ay = fabs(y);
	}
	nx = ix >> 20;
	ny = iy >> 20;
	j  = nx - ny;
/*
 * x >= 2^500 (x*x or y*y may overflow)
 */
	if (nx >= 0x5f3) {
		if (nx == 0x7ff) {	/* inf or NaN, signal of sNaN */
			if (((ix - 0x7ff00000) | lx) == 0)
				return (ax == ay ? ay : ax);
			else if (((iy - 0x7ff00000) | ly) == 0)
				return (ay == ax ? ax : ay);
			else
				return (ax * ay);	/* + -> * for Cheetah */
		} else if (j > 32) {	/* x >> y */
			if (j <= 53)
				ay *= twom53;
			ax += ay;
			if (((int *) &ax)[HIWORD] == 0x7ff00000)
				ax = _SVID_libm_err(x, y, 4);
			return (ax);
		}
		ax *= twom768;
		ay *= twom768;
		iscale = 2;
		ix -= 768 << 20;
		iy -= 768 << 20;
	}
/*
 * y < 2^-450 (x*x or y*y may underflow)
 */
	else if (ny < 0x23d) {
		if ((ix | lx) == 0)
			return (ay);
		if ((iy | ly) == 0)
			return (ax);
		if (j > 53) 		/* x >> y */
			return (ax + ay);
		iscale = 1;
		ax *= two768;
		ay *= two768;
		if (nx == 0) {
			if (ax == zero)	/* guard subnormal flush to zero */
				return (ax);
			ix = ((int *) &ax)[HIWORD];
		} else
			ix += 768 << 20;
		if (ny == 0) {
			if (ay == zero)	/* guard subnormal flush to zero */
				return (ax * twom768);
			iy = ((int *) &ay)[HIWORD];
		} else
			iy += 768 << 20;
		j = (ix >> 20) - (iy >> 20);
		if (j > 32) {		/* x >> y */
			if (j <= 53)
				ay *= twom53;
			return ((ax + ay) * twom768);
		}
	} else if (j > 32) {		/* x >> y */
		if (j <= 53)
			ay *= twom53;
		return (ax + ay);
	}
/*
 * Medium range ax and ay with max{|ax/ay|,|ay/ax|} bounded by 2^32
 * First check rounding mode by comparing onep1u*onep1u with onep1u+twom53.
 * Make sure the computation is done at run-time.
 */
	if (((lx | ly) << 5) == 0) {
		ay = ay * ay;
		ax += ay / (ax + sqrt(ax * ax + ay));
	} else
	if (onep1u * onep1u != onep1u + twom53) {
	/* round-to-zero, positive, negative mode */
	/* magic formula with less than an ulp error */
		w = sqrt(ax * ax + ay * ay);
		ax += ay / ((ax + w) / ay);
	} else {
	/* round-to-nearest mode */
		w = ax - ay;
		if (w > ay) {
			((int *) &xh)[HIWORD] = ix;
			((int *) &xh)[LOWORD] = 0;
			ay = ay * ay + (ax - xh) * (ax + xh);
			ax = sqrt(xh * xh + ay);
		} else {
			ax = ax + ax;
			((int *) &xh)[HIWORD] = ix + 0x00100000;
			((int *) &xh)[LOWORD] = 0;
			((int *) &yh)[HIWORD] = iy;
			((int *) &yh)[LOWORD] = 0;
			ay = w * w + ((ax - xh) * yh + (ay - yh) * ax);
			ax = sqrt(xh * yh + ay);
		}
	}
	if (iscale > 0) {
		if (iscale == 1)
			ax *= twom768;
		else {
			ax *= two768;	/* must generate side effect here */
			if (((int *) &ax)[HIWORD] == 0x7ff00000)
				ax = _SVID_libm_err(x, y, 4);
		}
	}
	return (ax);
}
