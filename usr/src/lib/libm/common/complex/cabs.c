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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak cabs = __cabs

#include "libm_synonyms.h"
#include <math.h>
#include "complex_wrapper.h"

/*
 * If C were the only standard we cared about, cabs could just call
 * hypot.  Unfortunately, various other standards say that hypot must
 * call matherr and/or set errno to ERANGE when the result overflows.
 * Since cabs should do neither of these things, we have to either
 * make hypot a wrapper on another internal function or duplicate
 * the hypot implementation here.  I've chosen to do the latter.
 */

static const double
	zero = 0.0,
	onep1u = 1.00000000000000022204e+00,	/* 0x3ff00000 1 = 1+2**-52 */
	twom53 = 1.11022302462515654042e-16,	/* 0x3ca00000 0 = 2**-53 */
	twom768 = 6.441148769597133308e-232,	/* 2^-768 */
	two768  = 1.552518092300708935e+231;	/* 2^768 */

double
cabs(dcomplex z)
{
	double		x, y, xh, yh, w, ax, ay;
	int		i, j, nx, ny, ix, iy, iscale = 0;
	unsigned	lx, ly;

	x = D_RE(z);
	y = D_IM(z);

	ix = ((int *)&x)[HIWORD] & ~0x80000000;
	lx = ((int *)&x)[LOWORD];
	iy = ((int *)&y)[HIWORD] & ~0x80000000;
	ly = ((int *)&y)[LOWORD];

	/* force ax = |x| ~>~ ay = |y| */
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

	if (nx >= 0x5f3) {
		/* x >= 2^500 (x*x or y*y may overflow) */
		if (nx == 0x7ff) {
			/* inf or NaN, signal of sNaN */
			if (((ix - 0x7ff00000) | lx) == 0)
				return ((ax == ay)? ay : ax);
			else if (((iy - 0x7ff00000) | ly) == 0)
				return ((ay == ax)? ax : ay);
			else
				return (ax * ay);
		} else if (j > 32) {
			/* x >> y */
			if (j <= 53)
				ay *= twom53;
			ax += ay;
			return (ax);
		}
		ax *= twom768;
		ay *= twom768;
		iscale = 2;
		ix -= 768 << 20;
		iy -= 768 << 20;
	} else if (ny < 0x23d) {
		/* y < 2^-450 (x*x or y*y may underflow) */
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
			ix = ((int *)&ax)[HIWORD];
		} else {
			ix += 768 << 20;
		}
		if (ny == 0) {
			if (ay == zero)	/* guard subnormal flush to zero */
				return (ax * twom768);
			iy = ((int *)&ay)[HIWORD];
		} else {
			iy += 768 << 20;
		}
		j = (ix >> 20) - (iy >> 20);
		if (j > 32) {
			/* x >> y */
			if (j <= 53)
				ay *= twom53;
			return ((ax + ay) * twom768);
		}
	} else if (j > 32) {
		/* x >> y */
		if (j <= 53)
			ay *= twom53;
		return (ax + ay);
	}

	/*
	 * Medium range ax and ay with max{|ax/ay|,|ay/ax|} bounded by 2^32.
	 * First check rounding mode by comparing onep1u*onep1u with onep1u
	 * + twom53.  Make sure the computation is done at run-time.
	 */
	if (((lx | ly) << 5) == 0) {
		ay = ay * ay;
		ax += ay / (ax + sqrt(ax * ax + ay));
	} else if (onep1u * onep1u != onep1u + twom53) {
		/* round-to-zero, positive, negative mode */
		/* magic formula with less than an ulp error */
		w = sqrt(ax * ax + ay * ay);
		ax += ay / ((ax + w) / ay);
	} else {
		/* round-to-nearest mode */
		w = ax - ay;
		if (w > ay) {
			((int *)&xh)[HIWORD] = ix;
			((int *)&xh)[LOWORD] = 0;
			ay = ay * ay + (ax - xh) * (ax + xh);
			ax = sqrt(xh * xh + ay);
		} else {
			ax = ax + ax;
			((int *)&xh)[HIWORD] = ix + 0x00100000;
			((int *)&xh)[LOWORD] = 0;
			((int *)&yh)[HIWORD] = iy;
			((int *)&yh)[LOWORD] = 0;
			ay = w * w + ((ax - xh) * yh + (ay - yh) * ax);
			ax = sqrt(xh * yh + ay);
		}
	}
	if (iscale > 0) {
		if (iscale == 1)
			ax *= twom768;
		else
			ax *= two768;	/* must generate side effect here */
	}
	return (ax);
}
