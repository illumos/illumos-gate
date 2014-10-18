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

/* INDENT OFF */
/*
 * double __k_cexp(double x, int *n);
 * Returns the exponential of x in the form of 2**n * y, y=__k_cexp(x,&n).
 *
 * Method
 *   1. Argument reduction:
 *      Reduce x to an r so that |r| <= 0.5*ln2 ~ 0.34658.
 *	Given x, find r and integer k such that
 *
 *               x = k*ln2 + r,  |r| <= 0.5*ln2.
 *
 *      Here r will be represented as r = hi-lo for better
 *	accuracy.
 *
 *   2. Approximation of exp(r) by a special rational function on
 *	the interval [0,0.34658]:
 *	Write
 *	    R(r**2) = r*(exp(r)+1)/(exp(r)-1) = 2 + r*r/6 - r**4/360 + ...
 *      We use a special Remez algorithm on [0,0.34658] to generate
 * 	a polynomial of degree 5 to approximate R. The maximum error
 *	of this polynomial approximation is bounded by 2**-59. In
 *	other words,
 *	    R(z) ~ 2.0 + P1*z + P2*z**2 + P3*z**3 + P4*z**4 + P5*z**5
 *  	(where z=r*r, and the values of P1 to P5 are listed below)
 *	and
 *	    |                  5          |     -59
 *	    | 2.0+P1*z+...+P5*z   -  R(z) | <= 2
 *	    |                             |
 *	The computation of exp(r) thus becomes
 *                             2*r
 *		exp(r) = 1 + -------
 *		              R - r
 *                                 r*R1(r)
 *		       = 1 + r + ----------- (for better accuracy)
 *		                  2 - R1(r)
 *	where
 *			         2       4             10
 *		R1(r) = r - (P1*r  + P2*r  + ... + P5*r   ).
 *
 *   3. Return n = k and __k_cexp = exp(r).
 *
 * Special cases:
 *	exp(INF) is INF, exp(NaN) is NaN;
 *	exp(-INF) is 0, and
 *	for finite argument, only exp(0)=1 is exact.
 *
 * Range and Accuracy:
 *      When |x| is really big, say |x| > 50000, the accuracy
 *      is not important because the ultimate result will over or under
 *      flow. So we will simply replace n = 50000 and r = 0.0. For
 *      moderate size x, according to an error analysis, the error is
 *      always less than 1 ulp (unit in the last place).
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 */
/* INDENT ON */

#include "libm.h"		/* __k_cexp */
#include "complex_wrapper.h"	/* HI_WORD/LO_WORD */

/* INDENT OFF */
static const double
one = 1.0,
two128 = 3.40282366920938463463e+38,
halF[2]	= {
	0.5, -0.5,
},
ln2HI[2] = {
	6.93147180369123816490e-01,	/* 0x3fe62e42, 0xfee00000 */
	-6.93147180369123816490e-01,	/* 0xbfe62e42, 0xfee00000 */
},
ln2LO[2] = {
	1.90821492927058770002e-10,	/* 0x3dea39ef, 0x35793c76 */
	-1.90821492927058770002e-10,	/* 0xbdea39ef, 0x35793c76 */
},
invln2 = 1.44269504088896338700e+00,	/* 0x3ff71547, 0x652b82fe */
P1 = 1.66666666666666019037e-01,	/* 0x3FC55555, 0x5555553E */
P2 = -2.77777777770155933842e-03,	/* 0xBF66C16C, 0x16BEBD93 */
P3 = 6.61375632143793436117e-05,	/* 0x3F11566A, 0xAF25DE2C */
P4 = -1.65339022054652515390e-06,	/* 0xBEBBBD41, 0xC5D26BF1 */
P5 = 4.13813679705723846039e-08;	/* 0x3E663769, 0x72BEA4D0 */
/* INDENT ON */

double
__k_cexp(double x, int *n) {
	double hi = 0.0L, lo = 0.0L, c, t;
	int k, xsb;
	unsigned hx, lx;

	hx = HI_WORD(x);	/* high word of x */
	lx = LO_WORD(x);	/* low word of x */
	xsb = (hx >> 31) & 1;	/* sign bit of x */
	hx &= 0x7fffffff;	/* high word of |x| */

	/* filter out non-finite argument */
	if (hx >= 0x40e86a00) {	/* if |x| > 50000 */
		if (hx >= 0x7ff00000) {
			*n = 1;
			if (((hx & 0xfffff) | lx) != 0)
				return (x + x);	/* NaN */
			else
				return ((xsb == 0) ? x : 0.0);
							/* exp(+-inf)={inf,0} */
		}
		*n = (xsb == 0) ? 50000 : -50000;
		return (one + ln2LO[1] * ln2LO[1]);	/* generate inexact */
	}

	*n = 0;
	/* argument reduction */
	if (hx > 0x3fd62e42) {	/* if  |x| > 0.5 ln2 */
		if (hx < 0x3FF0A2B2) {	/* and |x| < 1.5 ln2 */
			hi = x - ln2HI[xsb];
			lo = ln2LO[xsb];
			k = 1 - xsb - xsb;
		} else {
			k = (int) (invln2 * x + halF[xsb]);
			t = k;
			hi = x - t * ln2HI[0];
					/* t*ln2HI is exact for t<2**20 */
			lo = t * ln2LO[0];
		}
		x = hi - lo;
		*n = k;
	} else if (hx < 0x3e300000) {	/* when |x|<2**-28 */
		return (one + x);
	} else
		k = 0;

	/* x is now in primary range */
	t = x * x;
	c = x - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
	if (k == 0)
		return (one - ((x * c) / (c - 2.0) - x));
	else {
		t = one - ((lo - (x * c) / (2.0 - c)) - hi);
		if (k > 128) {
			t *= two128;
			*n = k - 128;
		} else if (k > 0) {
			HI_WORD(t) += (k << 20);
			*n = 0;
		}
		return (t);
	}
}
