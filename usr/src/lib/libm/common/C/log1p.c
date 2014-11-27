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

#pragma weak __log1p = log1p

/* INDENT OFF */
/*
 * Method :
 *   1. Argument Reduction: find k and f such that
 *			1+x = 2^k * (1+f),
 *	   where  sqrt(2)/2 < 1+f < sqrt(2) .
 *
 *      Note. If k=0, then f=x is exact. However, if k != 0, then f
 *	may not be representable exactly. In that case, a correction
 *	term is need. Let u=1+x rounded. Let c = (1+x)-u, then
 *	log(1+x) - log(u) ~ c/u. Thus, we proceed to compute log(u),
 *	and add back the correction term c/u.
 *	(Note: when x > 2**53, one can simply return log(x))
 *
 *   2. Approximation of log1p(f).
 *	Let s = f/(2+f) ; based on log(1+f) = log(1+s) - log(1-s)
 *		 = 2s + 2/3 s**3 + 2/5 s**5 + .....,
 *		 = 2s + s*R
 *      We use a special Reme algorithm on [0,0.1716] to generate
 * 	a polynomial of degree 14 to approximate R The maximum error
 *	of this polynomial approximation is bounded by 2**-58.45. In
 *	other words,
 *		        2      4      6      8      10      12      14
 *	    R(z) ~ Lp1*s +Lp2*s +Lp3*s +Lp4*s +Lp5*s  +Lp6*s  +Lp7*s
 *  	(the values of Lp1 to Lp7 are listed in the program)
 *	and
 *	    |      2          14          |     -58.45
 *	    | Lp1*s +...+Lp7*s    -  R(z) | <= 2
 *	    |                             |
 *	Note that 2s = f - s*f = f - hfsq + s*hfsq, where hfsq = f*f/2.
 *	In order to guarantee error in log below 1ulp, we compute log
 *	by
 *		log1p(f) = f - (hfsq - s*(hfsq+R)).
 *
 *	3. Finally, log1p(x) = k*ln2 + log1p(f).
 *			     = k*ln2_hi+(f-(hfsq-(s*(hfsq+R)+k*ln2_lo)))
 *	   Here ln2 is splitted into two floating point number:
 *			ln2_hi + ln2_lo,
 *	   where n*ln2_hi is always exact for |n| < 2000.
 *
 * Special cases:
 *	log1p(x) is NaN with signal if x < -1 (including -INF) ;
 *	log1p(+INF) is +INF; log1p(-1) is -INF with signal;
 *	log1p(NaN) is that NaN with no signal.
 *
 * Accuracy:
 *	according to an error analysis, the error is always less than
 *	1 ulp (unit in the last place).
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following
 * constants. The decimal values may be used, provided that the
 * compiler will convert from decimal to binary accurately enough
 * to produce the hexadecimal values shown.
 *
 * Note: Assuming log() return accurate answer, the following
 *	 algorithm can be used to compute log1p(x) to within a few ULP:
 *
 *		u = 1+x;
 *		if (u == 1.0) return x ; else
 *			   return log(u)*(x/(u-1.0));
 *
 *	 See HP-15C Advanced Functions Handbook, p.193.
 */
/* INDENT ON */

#include "libm.h"

static const double xxx[] = {
/* ln2_hi */	6.93147180369123816490e-01,	/* 3fe62e42 fee00000 */
/* ln2_lo */	1.90821492927058770002e-10,	/* 3dea39ef 35793c76 */
/* two54 */	1.80143985094819840000e+16,	/* 43500000 00000000 */
/* Lp1 */	6.666666666666735130e-01,	/* 3FE55555 55555593 */
/* Lp2 */	3.999999999940941908e-01,	/* 3FD99999 9997FA04 */
/* Lp3 */	2.857142874366239149e-01,	/* 3FD24924 94229359 */
/* Lp4 */	2.222219843214978396e-01,	/* 3FCC71C5 1D8E78AF */
/* Lp5 */	1.818357216161805012e-01,	/* 3FC74664 96CB03DE */
/* Lp6 */	1.531383769920937332e-01,	/* 3FC39A09 D078C69F */
/* Lp7 */	1.479819860511658591e-01,	/* 3FC2F112 DF3E5244 */
/* zero */	0.0
};
#define	ln2_hi	xxx[0]
#define	ln2_lo	xxx[1]
#define	two54	xxx[2]
#define	Lp1	xxx[3]
#define	Lp2	xxx[4]
#define	Lp3	xxx[5]
#define	Lp4	xxx[6]
#define	Lp5	xxx[7]
#define	Lp6	xxx[8]
#define	Lp7	xxx[9]
#define	zero	xxx[10]

double
log1p(double x) {
	double	hfsq, f, c = 0.0, s, z, R, u;
	int	k, hx, hu, ax;

	hx = ((int *)&x)[HIWORD];		/* high word of x */
	ax = hx & 0x7fffffff;

	if (ax >= 0x7ff00000) { /* x is inf or nan */
		if (((hx - 0xfff00000) | ((int *)&x)[LOWORD]) == 0) /* -inf */
			return (_SVID_libm_err(x, x, 44));
		return (x * x);
	}

	k = 1;
	if (hx < 0x3FDA827A) {	/* x < 0.41422  */
		if (ax >= 0x3ff00000)	/* x <= -1.0 */
			return (_SVID_libm_err(x, x, x == -1.0 ? 43 : 44));
		if (ax < 0x3e200000) {	/* |x| < 2**-29 */
			if (two54 + x > zero &&	/* raise inexact */
			    ax < 0x3c900000)	/* |x| < 2**-54 */
				return (x);
			else
				return (x - x * x * 0.5);
		}
		if (hx > 0 || hx <= (int)0xbfd2bec3) {	/* -0.2929<x<0.41422 */
			k = 0;
			f = x;
			hu = 1;
		}
	}
	/* We will initialize 'c' here. */
	if (k != 0) {
		if (hx < 0x43400000) {
			u = 1.0 + x;
			hu = ((int *)&u)[HIWORD];	/* high word of u */
			k = (hu >> 20) - 1023;
			/*
			 * correction term
			 */
			c = k > 0 ? 1.0 - (u - x) : x - (u - 1.0);
			c /= u;
		} else {
			u = x;
			hu = ((int *)&u)[HIWORD];	/* high word of u */
			k = (hu >> 20) - 1023;
			c = 0;
		}
		hu &= 0x000fffff;
		if (hu < 0x6a09e) {	/* normalize u */
			((int *)&u)[HIWORD] = hu | 0x3ff00000;
		} else {			/* normalize u/2 */
			k += 1;
			((int *)&u)[HIWORD] = hu | 0x3fe00000;
			hu = (0x00100000 - hu) >> 2;
		}
		f = u - 1.0;
	}
	hfsq = 0.5 * f * f;
	if (hu == 0) {		/* |f| < 2**-20 */
		if (f == zero) {
			if (k == 0)
				return (zero);
			/* We already initialized 'c' before, when (k != 0) */
			c += k * ln2_lo;
			return (k * ln2_hi + c);
		}
		R = hfsq * (1.0 - 0.66666666666666666 * f);
		if (k == 0)
			return (f - R);
		return (k * ln2_hi - ((R - (k * ln2_lo + c)) - f));
	}
	s = f / (2.0 + f);
	z = s * s;
	R = z * (Lp1 + z * (Lp2 + z * (Lp3 + z * (Lp4 + z * (Lp5 +
		z * (Lp6 + z * Lp7))))));
	if (k == 0)
		return (f - (hfsq - s * (hfsq + R)));
	return (k * ln2_hi - ((hfsq - (s * (hfsq + R) +
		(k * ln2_lo + c))) - f));
}
