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

#pragma weak catan = __catan

/* INDENT OFF */
/*
 * dcomplex catan(dcomplex z);
 *
 * If
 *     z = x + iy,
 *
 * then
 *          1       (    2x     )    1                2    2
 * Re w  =  - arctan(-----------)  = - ATAN2(2x, 1 - x  - y )
 *          2       (     2    2)    2
 *                  (1 - x  - y )
 *
 *               ( 2         2)
 *          1    (x  +  (y+1) )      1                  4y
 * Im w  =  - log(------------) .=  --- log [ 1 + ------------- ]
 *          4    ( 2         2)      4              2         2
 *               (x  +  (y-1) )                    x  +  (y-1)
 *
 *                 2    16  3                         y
 *         = t - 2t   + -- t  - ..., where t = -----------------
 *                      3                      x*x + (y-1)*(y-1)
 *
 * Note that: if catan( x, y) = ( u, v), then
 *               catan(-x, y) = (-u, v)
 *               catan( x,-y) = ( u,-v)
 *
 * Also,   catan(x,y) = -i*catanh(-y,x), or
 *        catanh(x,y) =  i*catan(-y,x)
 * So, if catanh(y,x) = (v,u), then catan(x,y) = -i*(-v,u) = (u,v), i.e.,
 *	  catan(x,y) = (u,v)
 *
 * EXCEPTION CASES (conform to ISO/IEC 9899:1999(E)):
 *    catan( 0  , 0   ) =  (0    ,  0   )
 *    catan( NaN, 0   ) =  (NaN  ,  0   )
 *    catan( 0  , 1   ) =  (0    ,  +inf) with divide-by-zero
 *    catan( inf, y   ) =  (pi/2 ,  0   ) for finite +y
 *    catan( NaN, y   ) =  (NaN  ,  NaN ) with invalid for finite y != 0
 *    catan( x  , inf ) =  (pi/2 ,  0   ) for finite +x
 *    catan( inf, inf ) =  (pi/2 ,  0   )
 *    catan( NaN, inf ) =  (NaN  ,  0   )
 *    catan( x  , NaN ) =  (NaN  ,  NaN ) with invalid for finite x
 *    catan( inf, NaN ) =  (pi/2 ,  +-0 )
 */
/* INDENT ON */

#include "libm.h"		/* atan/atan2/fabs/log/log1p */
#include "complex_wrapper.h"

/* INDENT OFF */
static const double
	pi_2 = 1.570796326794896558e+00,
	zero = 0.0,
	half = 0.5,
	two = 2.0,
	ln2 = 6.931471805599453094172321214581765680755e-0001,
	one = 1.0;
/* INDENT ON */

dcomplex
catan(dcomplex z) {
	dcomplex ans;
	double x, y, ax, ay, t;
	int hx, hy, ix, iy;
	unsigned lx, ly;

	x = D_RE(z);
	y = D_IM(z);
	ax = fabs(x);
	ay = fabs(y);
	hx = HI_WORD(x);
	lx = LO_WORD(x);
	hy = HI_WORD(y);
	ly = LO_WORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;

	/* x is inf or NaN */
	if (ix >= 0x7ff00000) {
		if (ISINF(ix, lx)) {
			D_RE(ans) = pi_2;
			D_IM(ans) = zero;
		} else {
			D_RE(ans) = x + x;
			if ((iy | ly) == 0 || (ISINF(iy, ly)))
				D_IM(ans) = zero;
			else
				D_IM(ans) = (fabs(y) - ay) / (fabs(y) - ay);
		}
	} else if (iy >= 0x7ff00000) {
		/* y is inf or NaN */
		if (ISINF(iy, ly)) {
			D_RE(ans) = pi_2;
			D_IM(ans) = zero;
		} else {
			D_RE(ans) = (fabs(x) - ax) / (fabs(x) - ax);
			D_IM(ans) = y;
		}
	} else if ((ix | lx) == 0) {
		/* INDENT OFF */
		/*
		 * x = 0
		 *      1                            1
		 * A = --- * atan2(2x, 1-x*x-y*y) = --- atan2(0,1-|y|)
		 *      2                            2
		 *
		 *     1     [  (y+1)*(y+1) ]   1          2      1         2y
		 * B = - log [ ------------ ] = - log (1+ ---) or - log(1+ ----)
		 *     4     [  (y-1)*(y-1) ]   2         y-1     2         1-y
		 */
		/* INDENT ON */
		t = one - ay;
		if (((iy - 0x3ff00000) | ly) == 0) {
			/* y=1: catan(0,1)=(0,+inf) with 1/0 signal */
			D_IM(ans) = ay / ax;
			D_RE(ans) = zero;
		} else if (iy >= 0x3ff00000) {	/* y>1 */
			D_IM(ans) = half * log1p(two / (-t));
			D_RE(ans) = pi_2;
		} else {		/* y<1 */
			D_IM(ans) = half * log1p((ay + ay) / t);
			D_RE(ans) = zero;
		}
	} else if (iy < 0x3e200000 || ((ix - iy) >> 20) >= 30) {
	/* INDENT OFF */
	/*
	 * Tiny y (relative to 1+|x|)
	 *     |y| < E*(1+|x|)
	 * where E=2**-29, -35, -60 for double, double extended, quad precision
	 *
	 *      1                           [ x<=1:   atan(x)
	 * A = --- * atan2(2x, 1-x*x-y*y) ~ [       1                 1+x
	 *      2                           [ x>=1: - atan2(2,(1-x)*(-----))
	 *                                          2                  x
	 *
	 *                               y/x
	 * B ~ t*(1-2t), where t = ----------------- is tiny
	 *                         x + (y-1)*(y-1)/x
	 */
		/* INDENT ON */
		if (ix < 0x3ff00000)
			D_RE(ans) = atan(ax);
		else
			D_RE(ans) = half * atan2(two, (one - ax) * (one +
				one / ax));
		if ((iy | ly) == 0) {
			D_IM(ans) = ay;
		} else {
			if (ix < 0x3e200000)
				t = ay / ((ay - one) * (ay - one));
			else if (ix > 0x41c00000)
				t = (ay / ax) / ax;
			else
				t = ay / (ax * ax + (ay - one) * (ay - one));
			D_IM(ans) = t * (one - (t + t));
		}
	} else if (iy >= 0x41c00000 && ((iy - ix) >> 20) >= 30) {
		/* INDENT OFF */
		/*
		 * Huge y relative to 1+|x|
		 *            |y| > Einv*(1+|x|), where Einv~2**(prec/2+3),
		 *            1
		 *       A ~ --- * atan2(2x, -y*y) ~ pi/2
		 *            2
		 *                                     y
		 *       B ~ t*(1-2t), where t = --------------- is tiny
		 *                                (y-1)*(y-1)
		 */
		/* INDENT ON */
		D_RE(ans) = pi_2;
		t = (ay / (ay - one)) / (ay - one);
		D_IM(ans) = t * (one - (t + t));
	} else if (((iy - 0x3ff00000) | ly) == 0) {
		/* INDENT OFF */
		/*
		 * y = 1
		 *      1                       1
		 * A = --- * atan2(2x, -x*x) = --- atan2(2,-x)
		 *      2                       2
		 *
		 *     1     [x*x + 4]   1          4     [ 0.5(log2-logx) if
		 * B = - log [-------] = - log (1+ ---) = [ |x|<E, else 0.25*
		 *     4     [  x*x  ]   4         x*x    [ log1p((2/x)*(2/x))
		 */
		/* INDENT ON */
		D_RE(ans) = half * atan2(two, -ax);
		if (ix < 0x3e200000)
			D_IM(ans) = half * (ln2 - log(ax));
		else {
			t = two / ax;
			D_IM(ans) = 0.25 * log1p(t * t);
		}
	} else if (ix >= 0x43900000) {
		/* INDENT OFF */
		/*
		 * Huge x:
		 * when |x| > 1/E^2,
		 *      1                           pi
		 * A ~ --- * atan2(2x, -x*x-y*y) ~ ---
		 *      2                           2
		 *                               y                 y/x
		 * B ~ t*(1-2t), where t = --------------- = (-------------- )/x
		 *                         x*x+(y-1)*(y-1)     1+((y-1)/x)^2
		 */
		/* INDENT ON */
		D_RE(ans) = pi_2;
		t = ((ay / ax) / (one + ((ay - one) / ax) * ((ay - one) /
			ax))) / ax;
		D_IM(ans) = t * (one - (t + t));
	} else if (ix < 0x38b00000) {
		/* INDENT OFF */
		/*
		 * Tiny x:
		 * when |x| < E^4,  (note that y != 1)
		 *      1                            1
		 * A = --- * atan2(2x, 1-x*x-y*y) ~ --- * atan2(2x,(1-y)*(1+y))
		 *      2                            2
		 *
		 *     1     [(y+1)*(y+1)]   1          2      1         2y
		 * B = - log [-----------] = - log (1+ ---) or - log(1+ ----)
		 *     4     [(y-1)*(y-1)]   2         y-1     2         1-y
		 */
		/* INDENT ON */
		D_RE(ans) = half * atan2(ax + ax, (one - ay) * (one + ay));
		if (iy >= 0x3ff00000)
			D_IM(ans) = half * log1p(two / (ay - one));
		else
			D_IM(ans) = half * log1p((ay + ay) / (one - ay));
	} else {
		/* INDENT OFF */
		/*
		 * normal x,y
		 *      1
		 * A = --- * atan2(2x, 1-x*x-y*y)
		 *      2
		 *
		 *     1     [x*x+(y+1)*(y+1)]   1               4y
		 * B = - log [---------------] = - log (1+ -----------------)
		 *     4     [x*x+(y-1)*(y-1)]   4         x*x + (y-1)*(y-1)
		 */
		/* INDENT ON */
		t = one - ay;
		if (iy >= 0x3fe00000 && iy < 0x40000000) {
			/* y close to 1 */
			D_RE(ans) = half * (atan2((ax + ax), (t * (one + ay) -
				ax * ax)));
		} else if (ix >= 0x3fe00000 && ix < 0x40000000) {
			/* x close to 1 */
			D_RE(ans) = half * atan2((ax + ax), ((one - ax) *
				(one + ax) - ay * ay));
		} else
			D_RE(ans) = half * atan2((ax + ax), ((one - ax * ax) -
				ay * ay));
		D_IM(ans) = 0.25 * log1p((4.0 * ay) / (ax * ax + t * t));
	}
	if (hx < 0)
		D_RE(ans) = -D_RE(ans);
	if (hy < 0)
		D_IM(ans) = -D_IM(ans);
	return (ans);
}
