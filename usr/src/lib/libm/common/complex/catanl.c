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

#pragma weak catanl = __catanl

/* INDENT OFF */
/*
 * ldcomplex catanl(ldcomplex z);
 *
 * Atan(z) return A + Bi where,
 *            1
 *	A = --- * atan2(2x, 1-x*x-y*y)
 *            2
 *
 *            1      [ x*x + (y+1)*(y+1) ]   1               4y
 *       B = --- log [ ----------------- ] = - log (1+ -----------------)
 *            4      [ x*x + (y-1)*(y-1) ]   4         x*x + (y-1)*(y-1)
 *
 *                 2    16  3                         y
 *         = t - 2t   + -- t  - ..., where t = -----------------
 *                      3                      x*x + (y-1)*(y-1)
 * Proof:
 * Let w = atan(z=x+yi) = A + B i. Then tan(w) = z.
 * Since sin(w) = (exp(iw)-exp(-iw))/(2i), cos(w)=(exp(iw)+exp(-iw))/(2),
 * Let p = exp(iw), then z = tan(w) = ((p-1/p)/(p+1/p))/i, or
 * iz = (p*p-1)/(p*p+1), or, after simplification,
 *	p*p = (1+iz)/(1-iz)			            ... (1)
 * LHS of (1) = exp(2iw) = exp(2i(A+Bi)) = exp(-2B)*exp(2iA)
 *            = exp(-2B)*(cos(2A)+i*sin(2A))	            ... (2)
 *              1-y+ix   (1-y+ix)*(1+y+ix)   1-x*x-y*y + 2xi
 * RHS of (1) = ------ = ----------------- = --------------- ... (3)
 *              1+y-ix    (1+y)**2 + x**2    (1+y)**2 + x**2
 *
 * Comparing the real and imaginary parts of (2) and (3), we have:
 * 	cos(2A) : 1-x*x-y*y = sin(2A) : 2x
 * and hence
 *	tan(2A) = 2x/(1-x*x-y*y), or
 *	A = 0.5 * atan2(2x, 1-x*x-y*y)	                    ... (4)
 *
 * For the imaginary part B, Note that |p*p| = exp(-2B), and
 *	|1+iz|   |i-z|   hypot(x,(y-1))
 *       |----| = |---| = --------------
 *	|1-iz|   |i+z|   hypot(x,(y+1))
 * Thus
 *                 x*x + (y+1)*(y+1)
 *	exp(4B) = -----------------, or
 *                 x*x + (y-1)*(y-1)
 *
 *            1     [x^2+(y+1)^2]   1             4y
 *       B =  - log [-----------] = - log(1+ -------------)  ... (5)
 *            4     [x^2+(y-1)^2]   4         x^2+(y-1)^2
 *
 * QED.
 *
 * Note that: if catan( x, y) = ( u, v), then
 *               catan(-x, y) = (-u, v)
 *               catan( x,-y) = ( u,-v)
 *
 * Also,   catan(x,y) = -i*catanh(-y,x), or
 *        catanh(x,y) =  i*catan(-y,x)
 * So, if catanh(y,x) = (v,u), then catan(x,y) = -i*(-v,u) = (u,v), i.e.,
 *         catan(x,y) = (u,v)
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

#include "libm.h"	/* atan2l/atanl/fabsl/isinfl/iszerol/log1pl/logl */
#include "complex_wrapper.h"
#include "longdouble.h"

/* INDENT OFF */
static const long double
zero = 0.0L,
one = 1.0L,
two = 2.0L,
half = 0.5L,
ln2 = 6.931471805599453094172321214581765680755e-0001L,
pi_2 = 1.570796326794896619231321691639751442098584699687552910487472L,
#if defined(__x86)
E = 2.910383045673370361328125000000000000000e-11L,	/* 2**-35 */
Einv = 3.435973836800000000000000000000000000000e+10L;	/* 2**+35 */
#else
E = 8.673617379884035472059622406959533691406e-19L,	/* 2**-60 */
Einv = 1.152921504606846976000000000000000000000e18L;	/* 2**+60 */
#endif
/* INDENT ON */

ldcomplex
catanl(ldcomplex z) {
	ldcomplex ans;
	long double x, y, t1, ax, ay, t;
	int hx, hy, ix, iy;

	x = LD_RE(z);
	y = LD_IM(z);
	ax = fabsl(x);
	ay = fabsl(y);
	hx = HI_XWORD(x);
	hy = HI_XWORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;

	/* x is inf or NaN */
	if (ix >= 0x7fff0000) {
		if (isinfl(x)) {
			LD_RE(ans) = pi_2;
			LD_IM(ans) = zero;
		} else {
			LD_RE(ans) = x + x;
			if (iszerol(y) || (isinfl(y)))
				LD_IM(ans) = zero;
			else
				LD_IM(ans) = (fabsl(y) - ay) / (fabsl(y) - ay);
		}
	} else if (iy >= 0x7fff0000) {
		/* y is inf or NaN */
		if (isinfl(y)) {
			LD_RE(ans) = pi_2;
			LD_IM(ans) = zero;
		} else {
			LD_RE(ans) = (fabsl(x) - ax) / (fabsl(x) - ax);
			LD_IM(ans) = y;
		}
	} else if (iszerol(x)) {
		/* INDENT OFF */
		/*
		 * x = 0
		 *      1                            1
		 * A = --- * atan2(2x, 1-x*x-y*y) = --- atan2(0,1-|y|)
		 *      2                            2
		 *
		 *     1     [ (y+1)*(y+1) ]   1          2      1         2y
		 * B = - log [ ----------- ] = - log (1+ ---) or - log(1+ ----)
		 *     4     [ (y-1)*(y-1) ]   2         y-1     2         1-y
		 */
		/* INDENT ON */
		t = one - ay;
		if (ay == one) {
			/* y=1: catan(0,1)=(0,+inf) with 1/0 signal */
			LD_IM(ans) = ay / ax;
			LD_RE(ans) = zero;
		} else if (ay > one) {	/* y>1 */
			LD_IM(ans) = half * log1pl(two / (-t));
			LD_RE(ans) = pi_2;
		} else {		/* y<1 */
			LD_IM(ans) = half * log1pl((ay + ay) / t);
			LD_RE(ans) = zero;
		}
	} else if (ay < E * (one + ax)) {
		/* INDENT OFF */
		/*
		 * Tiny y (relative to 1+|x|)
		 *     |y| < E*(1+|x|)
		 * where E=2**-29, -35, -60 for double, extended, quad precision
		 *
		 *     1                         [x<=1:   atan(x)
		 * A = - * atan2(2x,1-x*x-y*y) ~ [      1                 1+x
		 *     2                         [x>=1: - atan2(2,(1-x)*(-----))
		 *                                      2                  x
		 *
		 *                               y/x
		 * B ~ t*(1-2t), where t = ----------------- is tiny
		 *                         x + (y-1)*(y-1)/x
		 *
		 *                           y
		 * (when x < 2**-60, t = ----------- )
		 *                       (y-1)*(y-1)
		 */
		/* INDENT ON */
		if (ay == zero)
			LD_IM(ans) = ay;
		else {
			t1 = ay - one;
			if (ix < 0x3fc30000)
				t = ay / (t1 * t1);
			else if (ix > 0x403b0000)
				t = (ay / ax) / ax;
			else
				t = ay / (ax * ax + t1 * t1);
			LD_IM(ans) = t * (one - two * t);
		}
		if (ix < 0x3fff0000)
			LD_RE(ans) = atanl(ax);
		else
			LD_RE(ans) = half * atan2l(two, (one - ax) * (one +
				one / ax));

	} else if (ay > Einv * (one + ax)) {
		/* INDENT OFF */
		/*
		 * Huge y relative to 1+|x|
		 *     |y| > Einv*(1+|x|), where Einv~2**(prec/2+3),
		 *      1
		 * A ~ --- * atan2(2x, -y*y) ~ pi/2
		 *      2
		 *                               y
		 * B ~ t*(1-2t), where t = --------------- is tiny
		 *                          (y-1)*(y-1)
		 */
		/* INDENT ON */
		LD_RE(ans) = pi_2;
		t = (ay / (ay - one)) / (ay - one);
		LD_IM(ans) = t * (one - (t + t));
	} else if (ay == one) {
		/* INDENT OFF */
		/*
		 * y=1
		 *     1                      1
		 * A = - * atan2(2x, -x*x) = --- atan2(2,-x)
		 *     2                      2
		 *
		 *     1     [ x*x+4]   1          4     [ 0.5(log2-logx) if
		 * B = - log [ -----] = - log (1+ ---) = [ |x|<E, else 0.25*
		 *     4     [  x*x ]   4         x*x    [ log1p((2/x)*(2/x))
		 */
		/* INDENT ON */
		LD_RE(ans) = half * atan2l(two, -ax);
		if (ax < E)
			LD_IM(ans) = half * (ln2 - logl(ax));
		else {
			t = two / ax;
			LD_IM(ans) = 0.25L * log1pl(t * t);
		}
	} else if (ax > Einv * Einv) {
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
		LD_RE(ans) = pi_2;
		t = ((ay / ax) / (one + ((ay - one) / ax) * ((ay - one) /
			ax))) / ax;
		LD_IM(ans) = t * (one - (t + t));
	} else if (ax < E * E * E * E) {
		/* INDENT OFF */
		/*
		 * Tiny x:
		 * when |x| < E^4,  (note that y != 1)
		 *      1                            1
		 * A = --- * atan2(2x, 1-x*x-y*y) ~ --- * atan2(2x,1-y*y)
		 *      2                            2
		 *
		 *     1     [ (y+1)*(y+1) ]   1          2      1         2y
		 * B = - log [ ----------- ] = - log (1+ ---) or - log(1+ ----)
		 *     4     [ (y-1)*(y-1) ]   2         y-1     2         1-y
		 */
		/* INDENT ON */
		LD_RE(ans) = half * atan2l(ax + ax, (one - ay) * (one + ay));
		if (ay > one)	/* y>1 */
			LD_IM(ans) = half * log1pl(two / (ay - one));
		else		/* y<1 */
			LD_IM(ans) = half * log1pl((ay + ay) / (one - ay));
	} else {
		/* INDENT OFF */
		/*
		 * normal x,y
		 *      1
		 * A = --- * atan2(2x, 1-x*x-y*y)
		 *      2
		 *
		 *     1     [ x*x+(y+1)*(y+1) ]   1               4y
		 * B = - log [ --------------- ] = - log (1+ -----------------)
		 *     4     [ x*x+(y-1)*(y-1) ]   4         x*x + (y-1)*(y-1)
		 */
		/* INDENT ON */
		t = one - ay;
		if (iy >= 0x3ffe0000 && iy < 0x40000000) {
			/* y close to 1 */
			LD_RE(ans) = half * (atan2l((ax + ax), (t * (one +
				ay) - ax * ax)));
		} else if (ix >= 0x3ffe0000 && ix < 0x40000000) {
			/* x close to 1 */
			LD_RE(ans) = half * atan2l((ax + ax), ((one - ax) *
				(one + ax) - ay * ay));
		} else
			LD_RE(ans) = half * atan2l((ax + ax), ((one - ax *
				ax) - ay * ay));
		LD_IM(ans) = 0.25L * log1pl((4.0L * ay) / (ax * ax + t * t));
	}
	if (hx < 0)
		LD_RE(ans) = -LD_RE(ans);
	if (hy < 0)
		LD_IM(ans) = -LD_IM(ans);
	return (ans);
}
