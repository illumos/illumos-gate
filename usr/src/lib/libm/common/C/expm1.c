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

#pragma weak __expm1 = expm1

/* INDENT OFF */
/*
 * expm1(x)
 * Returns exp(x)-1, the exponential of x minus 1.
 *
 * Method
 *   1. Arugment reduction:
 *	Given x, find r and integer k such that
 *
 *               x = k*ln2 + r,  |r| <= 0.5*ln2 ~ 0.34658
 *
 *      Here a correction term c will be computed to compensate
 *	the error in r when rounded to a floating-point number.
 *
 *   2. Approximating expm1(r) by a special rational function on
 *	the interval [0,0.34658]:
 *	Since
 *	    r*(exp(r)+1)/(exp(r)-1) = 2+ r^2/6 - r^4/360 + ...
 *	we define R1(r*r) by
 *	    r*(exp(r)+1)/(exp(r)-1) = 2+ r^2/6 * R1(r*r)
 *	That is,
 *	    R1(r**2) = 6/r *((exp(r)+1)/(exp(r)-1) - 2/r)
 *		     = 6/r * ( 1 + 2.0*(1/(exp(r)-1) - 1/r))
 *		     = 1 - r^2/60 + r^4/2520 - r^6/100800 + ...
 *      We use a special Reme algorithm on [0,0.347] to generate
 * 	a polynomial of degree 5 in r*r to approximate R1. The
 *	maximum error of this polynomial approximation is bounded
 *	by 2**-61. In other words,
 *	    R1(z) ~ 1.0 + Q1*z + Q2*z**2 + Q3*z**3 + Q4*z**4 + Q5*z**5
 *	where 	Q1  =  -1.6666666666666567384E-2,
 * 		Q2  =   3.9682539681370365873E-4,
 * 		Q3  =  -9.9206344733435987357E-6,
 * 		Q4  =   2.5051361420808517002E-7,
 * 		Q5  =  -6.2843505682382617102E-9;
 *  	(where z=r*r, and the values of Q1 to Q5 are listed below)
 *	with error bounded by
 *	    |                  5           |     -61
 *	    | 1.0+Q1*z+...+Q5*z   -  R1(z) | <= 2
 *	    |                              |
 *
 *	expm1(r) = exp(r)-1 is then computed by the following
 * 	specific way which minimize the accumulation rounding error:
 *			       2     3
 *			      r     r    [ 3 - (R1 + R1*r/2)  ]
 *	      expm1(r) = r + --- + --- * [--------------------]
 *		              2     2    [ 6 - r*(3 - R1*r/2) ]
 *
 *	To compensate the error in the argument reduction, we use
 *		expm1(r+c) = expm1(r) + c + expm1(r)*c
 *			   ~ expm1(r) + c + r*c
 *	Thus c+r*c will be added in as the correction terms for
 *	expm1(r+c). Now rearrange the term to avoid optimization
 * 	screw up:
 *		        (      2                                    2 )
 *		        ({  ( r    [ R1 -  (3 - R1*r/2) ]  )  }    r  )
 *	 expm1(r+c)~r - ({r*(--- * [--------------------]-c)-c} - --- )
 *	                ({  ( 2    [ 6 - r*(3 - R1*r/2) ]  )  }    2  )
 *                      (                                             )
 *
 *		   = r - E
 *   3. Scale back to obtain expm1(x):
 *	From step 1, we have
 *	   expm1(x) = either 2^k*[expm1(r)+1] - 1
 *		    = or     2^k*[expm1(r) + (1-2^-k)]
 *   4. Implementation notes:
 *	(A). To save one multiplication, we scale the coefficient Qi
 *	     to Qi*2^i, and replace z by (x^2)/2.
 *	(B). To achieve maximum accuracy, we compute expm1(x) by
 *	  (i)   if x < -56*ln2, return -1.0, (raise inexact if x != inf)
 *	  (ii)  if k=0, return r-E
 *	  (iii) if k=-1, return 0.5*(r-E)-0.5
 *        (iv)	if k=1 if r < -0.25, return 2*((r+0.5)- E)
 *					else	     return  1.0+2.0*(r-E);
 *	  (v)   if (k<-2||k>56) return 2^k(1-(E-r)) - 1 (or exp(x)-1)
 *	  (vi)  if k <= 20, return 2^k((1-2^-k)-(E-r)), else
 *	  (vii) return 2^k(1-((E+2^-k)-r))
 *
 * Special cases:
 *	expm1(INF) is INF, expm1(NaN) is NaN;
 *	expm1(-INF) is -1, and
 *	for finite argument, only expm1(0)=0 is exact.
 *
 * Accuracy:
 *	according to an error analysis, the error is always less than
 *	1 ulp (unit in the last place).
 *
 * Misc. info.
 *	For IEEE double
 *	    if x >  7.09782712893383973096e+02 then expm1(x) overflow
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 */
/* INDENT ON */

#include "libm_macros.h"
#include <math.h>

static const double xxx[] = {
/* one */		 1.0,
/* huge */		 1.0e+300,
/* tiny */		 1.0e-300,
/* o_threshold */	 7.09782712893383973096e+02,	/* 40862E42 FEFA39EF */
/* ln2_hi */		 6.93147180369123816490e-01,	/* 3FE62E42 FEE00000 */
/* ln2_lo */		 1.90821492927058770002e-10,	/* 3DEA39EF 35793C76 */
/* invln2 */		 1.44269504088896338700e+00,	/* 3FF71547 652B82FE */
/* scaled coefficients related to expm1 */
/* Q1 */		-3.33333333333331316428e-02,	/* BFA11111 111110F4 */
/* Q2 */		 1.58730158725481460165e-03,	/* 3F5A01A0 19FE5585 */
/* Q3 */		-7.93650757867487942473e-05,	/* BF14CE19 9EAADBB7 */
/* Q4 */		 4.00821782732936239552e-06,	/* 3ED0CFCA 86E65239 */
/* Q5 */		-2.01099218183624371326e-07	/* BE8AFDB7 6E09C32D */
};
#define	one		xxx[0]
#define	huge		xxx[1]
#define	tiny		xxx[2]
#define	o_threshold	xxx[3]
#define	ln2_hi		xxx[4]
#define	ln2_lo		xxx[5]
#define	invln2		xxx[6]
#define	Q1		xxx[7]
#define	Q2		xxx[8]
#define	Q3		xxx[9]
#define	Q4		xxx[10]
#define	Q5		xxx[11]

double
expm1(double x) {
	double y, hi, lo, c = 0.0L, t, e, hxs, hfx, r1;
	int k, xsb;
	unsigned hx;

	hx = ((unsigned *) &x)[HIWORD];		/* high word of x */
	xsb = hx & 0x80000000;			/* sign bit of x */
	if (xsb == 0)
		y = x;
	else
		y = -x;				/* y = |x| */
	hx &= 0x7fffffff;			/* high word of |x| */

	/* filter out huge and non-finite argument */
	/* for example exp(38)-1 is approximately 3.1855932e+16 */
	if (hx >= 0x4043687A) {
		/* if |x|>=56*ln2 (~38.8162...) */
		if (hx >= 0x40862E42) {		/* if |x|>=709.78... -> inf */
			if (hx >= 0x7ff00000) {
				if (((hx & 0xfffff) | ((int *) &x)[LOWORD])
					!= 0)
					return (x * x);	/* + -> * for Cheetah */
				else
					/* exp(+-inf)={inf,-1} */
					return (xsb == 0 ? x : -1.0);
			}
			if (x > o_threshold)
				return (huge * huge);	/* overflow */
		}
		if (xsb != 0) {		/* x < -56*ln2, return -1.0 w/inexact */
			if (x + tiny < 0.0)		/* raise inexact */
				return (tiny - one);	/* return -1 */
		}
	}

	/* argument reduction */
	if (hx > 0x3fd62e42) {			/* if  |x| > 0.5 ln2 */
		if (hx < 0x3FF0A2B2) {		/* and |x| < 1.5 ln2 */
			if (xsb == 0) {		/* positive number */
				hi = x - ln2_hi;
				lo = ln2_lo;
				k = 1;
			} else {
				/* negative number */
				hi = x + ln2_hi;
				lo = -ln2_lo;
				k = -1;
			}
		} else {
			/* |x| > 1.5 ln2 */
			k = (int) (invln2 * x + (xsb == 0 ? 0.5 : -0.5));
			t = k;
			hi = x - t * ln2_hi;	/* t*ln2_hi is exact here */
			lo = t * ln2_lo;
		}
		x = hi - lo;
		c = (hi - x) - lo; /* still at |x| > 0.5 ln2 */
	} else if (hx < 0x3c900000) {
		/* when |x|<2**-54, return x */
		t = huge + x;		/* return x w/inexact when x != 0 */
		return (x - (t - (huge + x)));
	} else
		/* |x| <= 0.5 ln2 */
		k = 0;

	/* x is now in primary range */
	hfx = 0.5 * x;
	hxs = x * hfx;
	r1 = one + hxs * (Q1 + hxs * (Q2 + hxs * (Q3 + hxs * (Q4 + hxs * Q5))));
	t = 3.0 - r1 * hfx;
	e = hxs * ((r1 - t) / (6.0 - x * t));
	if (k == 0) /* |x| <= 0.5 ln2 */
		return (x - (x * e - hxs));
	else {		/* |x| > 0.5 ln2 */
		e = (x * (e - c) - c);
		e -= hxs;
		if (k == -1)
			return (0.5 * (x - e) - 0.5);
		if (k == 1) {
			if (x < -0.25)
				return (-2.0 * (e - (x + 0.5)));
			else
				return (one + 2.0 * (x - e));
		}
		if (k <= -2 || k > 56) {	/* suffice to return exp(x)-1 */
			y = one - (e - x);
			((int *) &y)[HIWORD] += k << 20;
			return (y - one);
		}
		t = one;
		if (k < 20) {
			((int *) &t)[HIWORD] = 0x3ff00000 - (0x200000 >> k);
							/* t = 1 - 2^-k */
			y = t - (e - x);
			((int *) &y)[HIWORD] += k << 20;
		} else {
			((int *) &t)[HIWORD] = (0x3ff - k) << 20; /* 2^-k */
			y = x - (e + t);
			y += one;
			((int *) &y)[HIWORD] += k << 20;
		}
	}
	return (y);
}
