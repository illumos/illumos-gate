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

#pragma weak __asin = asin

/* INDENT OFF */
/*
 * asin(x)
 * Method :
 *	Since  asin(x) = x + x^3/6 + x^5*3/40 + x^7*15/336 + ...
 *	we approximate asin(x) on [0,0.5] by
 *		asin(x) = x + x*x^2*R(x^2)
 *	where
 *		R(x^2) is a rational approximation of (asin(x)-x)/x^3
 *	and its remez error is bounded by
 *		|(asin(x)-x)/x^3 - R(x^2)| < 2^(-58.75)
 *
 *	For x in [0.5,1]
 *		asin(x) = pi/2-2*asin(sqrt((1-x)/2))
 *	Let y = (1-x), z = y/2, s := sqrt(z), and pio2_hi+pio2_lo=pi/2;
 *	then for x>0.98
 *		asin(x) = pi/2 - 2*(s+s*z*R(z))
 *			= pio2_hi - (2*(s+s*z*R(z)) - pio2_lo)
 *	For x<=0.98, let pio4_hi = pio2_hi/2, then
 *		f = hi part of s;
 *		c = sqrt(z) - f = (z-f*f)/(s+f) 	...f+c=sqrt(z)
 *	and
 *		asin(x) = pi/2 - 2*(s+s*z*R(z))
 *			= pio4_hi+(pio4-2s)-(2s*z*R(z)-pio2_lo)
 *			= pio4_hi+(pio4-2f)-(2s*z*R(z)-(pio2_lo+2c))
 *
 * Special cases:
 *	if x is NaN, return x itself;
 *	if |x|>1, return NaN with invalid signal.
 *
 */
/* INDENT ON */

#include "libm_protos.h"	/* _SVID_libm_error */
#include "libm_macros.h"
#include <math.h>

/* INDENT OFF */
static const double xxx[] = {
/* one */	 1.00000000000000000000e+00,	/* 3FF00000, 00000000 */
/* huge */	 1.000e+300,
/* pio2_hi */	 1.57079632679489655800e+00,	/* 3FF921FB, 54442D18 */
/* pio2_lo */	 6.12323399573676603587e-17,	/* 3C91A626, 33145C07 */
/* pio4_hi */	 7.85398163397448278999e-01,	/* 3FE921FB, 54442D18 */
/* coefficient for R(x^2) */
/* pS0 */	 1.66666666666666657415e-01,	/* 3FC55555, 55555555 */
/* pS1 */	-3.25565818622400915405e-01,	/* BFD4D612, 03EB6F7D */
/* pS2 */	 2.01212532134862925881e-01,	/* 3FC9C155, 0E884455 */
/* pS3 */	-4.00555345006794114027e-02,	/* BFA48228, B5688F3B */
/* pS4 */	 7.91534994289814532176e-04,	/* 3F49EFE0, 7501B288 */
/* pS5 */	 3.47933107596021167570e-05,	/* 3F023DE1, 0DFDF709 */
/* qS1 */	-2.40339491173441421878e+00,	/* C0033A27, 1C8A2D4B */
/* qS2 */	 2.02094576023350569471e+00,	/* 40002AE5, 9C598AC8 */
/* qS3 */	-6.88283971605453293030e-01,	/* BFE6066C, 1B8D0159 */
/* qS4 */	 7.70381505559019352791e-02	/* 3FB3B8C5, B12E9282 */
};
#define	one	xxx[0]
#define	huge	xxx[1]
#define	pio2_hi	xxx[2]
#define	pio2_lo	xxx[3]
#define	pio4_hi	xxx[4]
#define	pS0	xxx[5]
#define	pS1	xxx[6]
#define	pS2	xxx[7]
#define	pS3	xxx[8]
#define	pS4	xxx[9]
#define	pS5	xxx[10]
#define	qS1	xxx[11]
#define	qS2	xxx[12]
#define	qS3	xxx[13]
#define	qS4	xxx[14]
/* INDENT ON */

double
asin(double x) {
	double t, w, p, q, c, r, s;
	int hx, ix, i;

	hx = ((int *) &x)[HIWORD];
	ix = hx & 0x7fffffff;
	if (ix >= 0x3ff00000) {	/* |x| >= 1 */
		if (((ix - 0x3ff00000) | ((int *) &x)[LOWORD]) == 0)
			/* asin(1)=+-pi/2 with inexact */
			return (x * pio2_hi + x * pio2_lo);
		else if (isnan(x))
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
			return (ix >= 0x7ff80000 ? x : (x - x) / (x - x));
			/* assumes sparc-like QNaN */
#else
			return (x - x) / (x - x);	/* asin(|x|>1) is NaN */
#endif
		else
			return (_SVID_libm_err(x, x, 2));
	} else if (ix < 0x3fe00000) {	/* |x| < 0.5 */
		if (ix < 0x3e400000) {	/* if |x| < 2**-27 */
			if ((i = (int) x) == 0)
				/* return x with inexact if x != 0 */
				return (x);
		}
		t = x * x;
		p = t * (pS0 + t * (pS1 + t * (pS2 + t * (pS3 +
			t * (pS4 + t * pS5)))));
		q = one + t * (qS1 + t * (qS2 + t * (qS3 + t * qS4)));
		w = p / q;
		return (x + x * w);
	}
	/* 1 > |x| >= 0.5 */
	w = one - fabs(x);
	t = w * 0.5;
	p = t * (pS0 + t * (pS1 + t * (pS2 + t * (pS3 + t * (pS4 + t * pS5)))));
	q = one + t * (qS1 + t * (qS2 + t * (qS3 + t * qS4)));
	s = sqrt(t);
	if (ix >= 0x3FEF3333) {	/* if |x| > 0.975 */
		w = p / q;
		t = pio2_hi - (2.0 * (s + s * w) - pio2_lo);
	} else {
		w = s;
		((int *) &w)[LOWORD] = 0;
		c = (t - w * w) / (s + w);
		r = p / q;
		p = 2.0 * s * r - (pio2_lo - 2.0 * c);
		q = pio4_hi - 2.0 * w;
		t = pio4_hi - (p - q);
	}
	return (hx > 0 ? t : -t);
}
