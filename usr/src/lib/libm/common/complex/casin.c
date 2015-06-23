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

#pragma weak __casin = casin

/* INDENT OFF */
/*
 * dcomplex casin(dcomplex z);
 *
 * Alogrithm
 * (based on T.E.Hull, Thomas F. Fairgrieve and Ping Tak Peter Tang's
 * paper "Implementing the Complex Arcsine and Arccosine Functins Using
 * Exception Handling", ACM TOMS, Vol 23, pp 299-335)
 *
 * The principal value of complex inverse sine function casin(z),
 * where z = x+iy, can be defined by
 *
 * 	casin(z) = asin(B) + i sign(y) log (A + sqrt(A*A-1)),
 *
 * where the log function is the natural log, and
 *             ____________           ____________
 *       1    /     2    2      1    /     2    2
 *  A = ---  / (x+1)  + y   +  ---  / (x-1)  + y
 *       2 \/                   2 \/
 *             ____________           ____________
 *       1    /     2    2      1    /     2    2
 *  B = ---  / (x+1)  + y   -  ---  / (x-1)  + y   .
 *       2 \/                   2 \/
 *
 * The Branch cuts are on the real line from -inf to -1 and from 1 to inf.
 * The real and imaginary parts are based on Abramowitz and Stegun
 * [Handbook of Mathematic Functions, 1972].  The sign of the imaginary
 * part is chosen to be the generally considered the principal value of
 * this function.
 *
 * Notes:1. A is the average of the distances from z to the points (1,0)
 *          and (-1,0) in the complex z-plane, and in particular A>=1.
 *       2. B is in [-1,1], and A*B = x.
 *
 * Special notes: if casin( x, y) = ( u, v), then
 *		    casin(-x, y) = (-u, v),
 *		    casin( x,-y) = ( u,-v),
 *    in general, we have casin(conj(z))     =  conj(casin(z))
 *                       casin(-z)          = -casin(z)
 *			 casin(z)           =  pi/2 - cacos(z)
 *
 * EXCEPTION CASES (conform to ISO/IEC 9899:1999(E)):
 *    casin( 0 + i 0   ) =  0    + i 0
 *    casin( 0 + i NaN ) =  0    + i NaN
 *    casin( x + i inf ) =  0    + i inf for finite x
 *    casin( x + i NaN ) =  NaN  + i NaN with invalid for finite x != 0
 *    casin(inf + iy   ) =  pi/2 + i inf finite y
 *    casin(inf + i inf) =  pi/4 + i inf
 *    casin(inf + i NaN) =  NaN  + i inf
 *    casin(NaN + i y  ) =  NaN  + i NaN for finite y
 *    casin(NaN + i inf) =  NaN  + i inf
 *    casin(NaN + i NaN) =  NaN  + i NaN
 *
 * Special Regions (better formula for accuracy and for avoiding spurious
 * overflow or underflow) (all x and y are assumed nonnegative):
 *  case 1: y = 0
 *  case 2: tiny y relative to x-1: y <= ulp(0.5)*|x-1|
 *  case 3: tiny y: y < 4 sqrt(u), where u = minimum normal number
 *  case 4: huge y relative to x+1: y >= (1+x)/ulp(0.5)
 *  case 5: huge x and y: x and y >= sqrt(M)/8, where M = maximum normal number
 *  case 6: tiny x: x < 4 sqrt(u)
 *  --------
 *  case	1 & 2. y=0 or y/|x-1| is tiny. We have
 *             ____________              _____________
 *            /      2    2             /       y    2
 *           / (x+-1)  + y   =  |x+-1| / 1 + (------)
 *         \/                        \/       |x+-1|
 *
 *                                            1      y   2
 *                           ~  |x+-1| ( 1 + --- (------)  )
 *                                            2   |x+-1|
 *
 *                                           2
 *                                          y
 *                           =  |x+-1| + --------.
 *                                       2|x+-1|
 *
 *	Consequently, it is not difficult to see that
 *                                 2
 *                                y
 *                    [ 1 + ------------ ,  if x < 1,
 *                    [      2(1+x)(1-x)
 *                    [
 *                    [
 *                    [ x,                 if x = 1 (y = 0),
 *                    [
 *		A ~=  [             2
 *                    [        x * y
 *                    [ x + ------------ ,  if x > 1
 *                    [      2(1+x)(x-1)
 *
 *	and hence
 *                      ______                                 2
 *                     / 2                    y               y
 *               A + \/ A  - 1  ~  1 + ---------------- + -----------, if x < 1,
 *                                     sqrt((x+1)(1-x))   2(x+1)(1-x)
 *
 *
 *			       ~  x + sqrt((x-1)*(x+1)),              if x >= 1.
 *
 *                                         2
 *                                        y
 *                          [ x(1 - ------------), if x < 1,
 *                          [       2(1+x)(1-x)
 *		B = x/A  ~  [
 *                          [ 1,                  if x = 1,
 *			    [
 *                          [           2
 *                          [          y
 *                          [ 1 - ------------ ,   if x > 1,
 *                          [      2(1+x)(1-x)
 *	Thus
 *                            [ asin(x) + i y/sqrt((x-1)*(x+1)), if x <  1
 *		casin(x+i*y)=[
 *                            [ pi/2    + i log(x+sqrt(x*x-1)),  if x >= 1
 *
 *  case 3. y < 4 sqrt(u), where u = minimum normal x.
 *	After case 1 and 2, this will only occurs when x=1. When x=1, we have
 *	   A = (sqrt(4+y*y)+y)/2 ~ 1 + y/2 + y^2/8 + ...
 *	and
 *	   B = 1/A = 1 - y/2 + y^2/8 + ...
 * 	Since
 *	   asin(x) = pi/2-2*asin(sqrt((1-x)/2))
 *	   asin(x) = x + x^3/6 + x^5*3/40 + x^7*15/336 + ...
 *	we have, for the real part asin(B),
 *	   asin(1-y/2) ~ pi/2 - 2 asin(sqrt(y/4))
 *	               ~ pi/2 - sqrt(y)
 *	For the imaginary part,
 *	   log(A+sqrt(A*A-1)) ~ log(1+y/2+sqrt(2*y/2))
 *	                      = log(1+y/2+sqrt(y))
 *	                      = (y/2+sqrt(y)) - (y/2+sqrt(y))^2/2 + ...
 *	                      ~ sqrt(y) - y*(sqrt(y)+y/2)/2
 *	                      ~ sqrt(y)
 *
 *  case 4. y >= (x+1)ulp(0.5). In this case, A ~ y and B ~ x/y. Thus
 *	   real part = asin(B) ~ x/y (be careful, x/y may underflow)
 * 	and
 *	   imag part = log(y+sqrt(y*y-one))
 *
 *
 *  case 5. Both x and y are large: x and y > sqrt(M)/8, where M = maximum x
 *	In this case,
 *	   A ~ sqrt(x*x+y*y)
 *	   B ~ x/sqrt(x*x+y*y).
 *	Thus
 *	   real part = asin(B) = atan(x/y),
 *	   imag part = log(A+sqrt(A*A-1)) ~ log(2A)
 *	             = log(2) + 0.5*log(x*x+y*y)
 *	             = log(2) + log(y) + 0.5*log(1+(x/y)^2)
 *
 *  case 6. x < 4 sqrt(u). In this case, we have
 *	    A ~ sqrt(1+y*y), B = x/sqrt(1+y*y).
 *	Since B is tiny, we have
 *	    real part = asin(B) ~ B = x/sqrt(1+y*y)
 *	    imag part = log(A+sqrt(A*A-1)) = log (A+sqrt(y*y))
 *	              = log(y+sqrt(1+y*y))
 *	              = 0.5*log(y^2+2ysqrt(1+y^2)+1+y^2)
 *	              = 0.5*log(1+2y(y+sqrt(1+y^2)));
 *	              = 0.5*log1p(2y(y+A));
 *
 * 	casin(z) = asin(B) + i sign(y) log (A + sqrt(A*A-1)),
 */
/* INDENT ON */

#include "libm.h"		/* asin/atan/fabs/log/log1p/sqrt */
#include "complex_wrapper.h"

/* INDENT OFF */
static const double
	zero = 0.0,
	one = 1.0,
	E = 1.11022302462515654042e-16,			/* 2**-53 */
	ln2 = 6.93147180559945286227e-01,
	pi_2 = 1.570796326794896558e+00,
	pi_2_l = 6.123233995736765886e-17,
	pi_4 = 7.85398163397448278999e-01,
	Foursqrtu = 5.96667258496016539463e-154,	/* 2**(-509) */
	Acrossover = 1.5,
	Bcrossover = 0.6417,
	half = 0.5;
/* INDENT ON */

dcomplex
casin(dcomplex z) {
	double x, y, t, R, S, A, Am1, B, y2, xm1, xp1, Apx;
	int ix, iy, hx, hy;
	unsigned lx, ly;
	dcomplex ans;

	x = D_RE(z);
	y = D_IM(z);
	hx = HI_WORD(x);
	lx = LO_WORD(x);
	hy = HI_WORD(y);
	ly = LO_WORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	x = fabs(x);
	y = fabs(y);

	/* special cases */

	/* x is inf or NaN */
	if (ix >= 0x7ff00000) {	/* x is inf or NaN */
		if (ISINF(ix, lx)) {	/* x is INF */
			D_IM(ans) = x;
			if (iy >= 0x7ff00000) {
				if (ISINF(iy, ly))
					/* casin(inf + i inf) = pi/4 + i inf */
					D_RE(ans) = pi_4;
				else	/* casin(inf + i NaN) = NaN  + i inf  */
					D_RE(ans) = y + y;
			} else	/* casin(inf + iy) = pi/2 + i inf */
				D_RE(ans) = pi_2;
		} else {		/* x is NaN */
			if (iy >= 0x7ff00000) {
				/* INDENT OFF */
				/*
				 * casin(NaN + i inf) = NaN + i inf
				 * casin(NaN + i NaN) = NaN + i NaN
				 */
				/* INDENT ON */
				D_IM(ans) = y + y;
				D_RE(ans) = x + x;
			} else {
				/* casin(NaN + i y ) = NaN  + i NaN */
				D_IM(ans) = D_RE(ans) = x + y;
			}
		}
		if (hx < 0)
			D_RE(ans) = -D_RE(ans);
		if (hy < 0)
			D_IM(ans) = -D_IM(ans);
		return (ans);
	}

	/* casin(+0 + i 0  ) =  0   + i 0. */
	if ((ix | lx | iy | ly) == 0)
		return (z);

	if (iy >= 0x7ff00000) {	/* y is inf or NaN */
		if (ISINF(iy, ly)) {	/* casin(x + i inf) =  0   + i inf */
			D_IM(ans) = y;
			D_RE(ans) = zero;
		} else {		/* casin(x + i NaN) = NaN  + i NaN */
			D_IM(ans) = x + y;
			if ((ix | lx) == 0)
				D_RE(ans) = x;
			else
				D_RE(ans) = y;
		}
		if (hx < 0)
			D_RE(ans) = -D_RE(ans);
		if (hy < 0)
			D_IM(ans) = -D_IM(ans);
		return (ans);
	}

	if ((iy | ly) == 0) {	/* region 1: y=0 */
		if (ix < 0x3ff00000) {	/* |x| < 1 */
			D_RE(ans) = asin(x);
			D_IM(ans) = zero;
		} else {
			D_RE(ans) = pi_2;
			if (ix >= 0x43500000)	/* |x| >= 2**54 */
				D_IM(ans) = ln2 + log(x);
			else if (ix >= 0x3ff80000)	/* x > Acrossover */
				D_IM(ans) = log(x + sqrt((x - one) * (x +
					one)));
			else {
				xm1 = x - one;
				D_IM(ans) = log1p(xm1 + sqrt(xm1 * (x + one)));
			}
		}
	} else if (y <= E * fabs(x - one)) {	/* region 2: y < tiny*|x-1| */
		if (ix < 0x3ff00000) {	/* x < 1 */
			D_RE(ans) = asin(x);
			D_IM(ans) = y / sqrt((one + x) * (one - x));
		} else {
			D_RE(ans) = pi_2;
			if (ix >= 0x43500000) {	/* |x| >= 2**54 */
				D_IM(ans) = ln2 + log(x);
			} else if (ix >= 0x3ff80000)	/* x > Acrossover */
				D_IM(ans) = log(x + sqrt((x - one) * (x +
					one)));
			else
				D_IM(ans) = log1p((x - one) + sqrt((x - one) *
					(x + one)));
		}
	} else if (y < Foursqrtu) {	/* region 3 */
		t = sqrt(y);
		D_RE(ans) = pi_2 - (t - pi_2_l);
		D_IM(ans) = t;
	} else if (E * y - one >= x) {	/* region 4 */
		D_RE(ans) = x / y;	/* need to fix underflow cases */
		D_IM(ans) = ln2 + log(y);
	} else if (ix >= 0x5fc00000 || iy >= 0x5fc00000) {	/* x,y>2**509 */
		/* region 5: x+1 or y is very large (>= sqrt(max)/8) */
		t = x / y;
		D_RE(ans) = atan(t);
		D_IM(ans) = ln2 + log(y) + half * log1p(t * t);
	} else if (x < Foursqrtu) {
		/* region 6: x is very small, < 4sqrt(min) */
		A = sqrt(one + y * y);
		D_RE(ans) = x / A;	/* may underflow */
		if (iy >= 0x3ff80000)	/* if y > Acrossover */
			D_IM(ans) = log(y + A);
		else
			D_IM(ans) = half * log1p((y + y) * (y + A));
	} else {	/* safe region */
		y2 = y * y;
		xp1 = x + one;
		xm1 = x - one;
		R = sqrt(xp1 * xp1 + y2);
		S = sqrt(xm1 * xm1 + y2);
		A = half * (R + S);
		B = x / A;

		if (B <= Bcrossover)
			D_RE(ans) = asin(B);
		else {		/* use atan and an accurate approx to a-x */
			Apx = A + x;
			if (x <= one)
				D_RE(ans) = atan(x / sqrt(half * Apx * (y2 /
					(R + xp1) + (S - xm1))));
			else
				D_RE(ans) = atan(x / (y * sqrt(half * (Apx /
					(R + xp1) + Apx / (S + xm1)))));
		}
		if (A <= Acrossover) {
			/* use log1p and an accurate approx to A-1 */
			if (x < one)
				Am1 = half * (y2 / (R + xp1) + y2 / (S - xm1));
			else
				Am1 = half * (y2 / (R + xp1) + (S + xm1));
			D_IM(ans) = log1p(Am1 + sqrt(Am1 * (A + one)));
		} else {
			D_IM(ans) = log(A + sqrt(A * A - one));
		}
	}

	if (hx < 0)
		D_RE(ans) = -D_RE(ans);
	if (hy < 0)
		D_IM(ans) = -D_IM(ans);

	return (ans);
}
