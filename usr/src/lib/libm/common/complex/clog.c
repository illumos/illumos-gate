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

#pragma weak clog = __clog

/* INDENT OFF */
/*
 * dcomplex clog(dcomplex z);
 *
 *                    _________
 *                   / 2    2            -1   y
 * log(x+iy) = log(\/ x  + y    ) + i tan   (---)
 *                                            x
 *
 *              1       2    2         -1   y
 *           = --- log(x  + y ) + i tan   (---)
 *              2                           x
 *
 * Note that the arctangent ranges from -PI to +PI, thus the imaginary
 * part of clog is atan2(y,x).
 *
 * EXCEPTION CASES (conform to ISO/IEC 9899:1999(E)):
 *    clog(-0 + i 0   ) =  -inf + i pi
 *    clog( 0 + i 0   ) =  -inf + i 0
 *    clog( x + i inf ) =  -inf + i pi/2, for finite x
 *    clog( x + i NaN ) =  NaN  + i NaN with invalid for finite x
 *    clog(-inf + iy   )=  +inf + i pi, for finite positive-signed y
 *    clog(+inf + iy   )=  +inf + i 0 , for finite positive-signed y
 *    clog(-inf + i inf)=  inf  + i 3pi/4
 *    clog(+inf + i inf)=  inf  + i pi/4
 *    clog(+-inf+ i NaN)=  inf  + i NaN
 *    clog(NaN  + i y  )=  NaN  + i NaN for finite y
 *    clog(NaN  + i inf)=  inf  + i NaN
 *    clog(NaN  + i NaN)=  NaN  + i NaN
 */
/* INDENT ON */

#include <math.h>		/* atan2/fabs/log/log1p */
#include "complex_wrapper.h"
#include "libm_protos.h"	/* __k_clog_r */


static const double half = 0.5, one = 1.0;

dcomplex
__clog(dcomplex z) {
	dcomplex	ans;
	double		x, y, t, ax, ay, w;
	int		n, ix, iy, hx, hy;
	unsigned	lx, ly;

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
	D_IM(ans) = carg(z);
	if (ix < iy || (ix == iy && lx < ly)) {
		/* swap x and y to force ax >= ay */
		t = ax;
		ax = ay;
		ay = t;
		n = ix, ix = iy;
		iy = n;
		n = lx, lx = ly;
		ly = n;
	}
	n = (ix - iy) >> 20;
	if (ix >= 0x7ff00000) {	/* x or y is Inf or NaN */
		if (ISINF(ix, lx))
			D_RE(ans) = ax;
		else if (ISINF(iy, ly))
			D_RE(ans) = ay;
		else
			D_RE(ans) = ax * ay;
	} else if ((iy | ly) == 0) {
		D_RE(ans) = ((ix | lx) == 0)? -one / ax : log(ax);
	} else if (((0x3fffffff - ix) ^ (ix - 0x3fe00000)) >= 0) {
		/* 0.5 <= x < 2 */
		if (ix >= 0x3ff00000) {
			if (((ix - 0x3ff00000) | lx) == 0)
				D_RE(ans) = half * log1p(ay * ay);
			else if (n >= 60)
				D_RE(ans) = log(ax);
			else
				D_RE(ans) = half * (log1p(ay * ay + (ax -
				    one) * (ax + one)));
		} else if (n >= 60) {
			D_RE(ans) = log(ax);
		} else {
			D_RE(ans) = __k_clog_r(ax, ay, &w);
		}
	} else if (n >= 30) {
		D_RE(ans) = log(ax);
	} else if (ix < 0x5f300000 && iy >= 0x20b00000) {
		/* 2**-500< y < x < 2**500 */
		D_RE(ans) = half * log(ax * ax + ay * ay);
	} else {
		t = ay / ax;
		D_RE(ans) = log(ax) + half * log1p(t * t);
	}
	return (ans);
}
