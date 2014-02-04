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

#pragma weak acos = __acos

/* INDENT OFF */
/*
 * acos(x)
 * Method :
 *	acos(x)  = pi/2 - asin(x)
 *	acos(-x) = pi/2 + asin(x)
 * For |x|<=0.5
 *	acos(x) = pi/2 - (x + x*x^2*R(x^2))	(see asin.c)
 * For x>0.5
 * 	acos(x) = pi/2 - (pi/2 - 2asin(sqrt((1-x)/2)))
 *		= 2asin(sqrt((1-x)/2))
 *		= 2s + 2s*z*R(z) 	...z=(1-x)/2, s=sqrt(z)
 *		= 2f + (2c + 2s*z*R(z))
 *     where f=hi part of s, and c = (z-f*f)/(s+f) is the correction term
 *     for f so that f+c ~ sqrt(z).
 * For x<-0.5
 *	acos(x) = pi - 2asin(sqrt((1-|x|)/2))
 *		= pi - 0.5*(s+s*z*R(z)), where z=(1-|x|)/2,s=sqrt(z)
 *
 * Special cases:
 *	if x is NaN, return x itself;
 *	if |x|>1, return NaN with invalid signal.
 *
 * Function needed: sqrt
 */
/* INDENT ON */

#include "libm_synonyms.h"	/* __acos, __sqrt, __isnan */
#include "libm_protos.h"	/* _SVID_libm_error */
#include "libm_macros.h"
#include <math.h>

/* INDENT OFF */
static const double xxx[] = {
/* one */	 1.00000000000000000000e+00,	/* 3FF00000, 00000000 */
/* pi */	 3.14159265358979311600e+00,	/* 400921FB, 54442D18 */
/* pio2_hi */	 1.57079632679489655800e+00,	/* 3FF921FB, 54442D18 */
/* pio2_lo */	 6.12323399573676603587e-17,	/* 3C91A626, 33145C07 */
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
#define	pi	xxx[1]
#define	pio2_hi	xxx[2]
#define	pio2_lo	xxx[3]
#define	pS0	xxx[4]
#define	pS1	xxx[5]
#define	pS2	xxx[6]
#define	pS3	xxx[7]
#define	pS4	xxx[8]
#define	pS5	xxx[9]
#define	qS1	xxx[10]
#define	qS2	xxx[11]
#define	qS3	xxx[12]
#define	qS4	xxx[13]
/* INDENT ON */

double
acos(double x) {
	double z, p, q, r, w, s, c, df;
	int hx, ix;

	hx = ((int *) &x)[HIWORD];
	ix = hx & 0x7fffffff;
	if (ix >= 0x3ff00000) {	/* |x| >= 1 */
		if (((ix - 0x3ff00000) | ((int *) &x)[LOWORD]) == 0) {
			/* |x| == 1 */
			if (hx > 0)	/* acos(1) = 0 */
				return (0.0);
			else		/* acos(-1) = pi */
				return (pi + 2.0 * pio2_lo);
		} else if (isnan(x))
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
			return (ix >= 0x7ff80000 ? x : (x - x) / (x - x));
			/* assumes sparc-like QNaN */
#else
			return (x - x) / (x - x);	/* acos(|x|>1) is NaN */
#endif
		else
			return (_SVID_libm_err(x, x, 1));
	}
	if (ix < 0x3fe00000) {	/* |x| < 0.5 */
		if (ix <= 0x3c600000)
			return (pio2_hi + pio2_lo);	/* if |x| < 2**-57 */
		z = x * x;
		p = z * (pS0 + z * (pS1 + z * (pS2 + z * (pS3 +
			z * (pS4 + z * pS5)))));
		q = one + z * (qS1 + z * (qS2 + z * (qS3 + z * qS4)));
		r = p / q;
		return (pio2_hi - (x - (pio2_lo - x * r)));
	} else if (hx < 0) {
		/* x < -0.5 */
		z = (one + x) * 0.5;
		p = z * (pS0 + z * (pS1 + z * (pS2 + z * (pS3 +
			z * (pS4 + z * pS5)))));
		q = one + z * (qS1 + z * (qS2 + z * (qS3 + z * qS4)));
		s = sqrt(z);
		r = p / q;
		w = r * s - pio2_lo;
		return (pi - 2.0 * (s + w));
	} else {
		/* x > 0.5 */
		z = (one - x) * 0.5;
		s = sqrt(z);
		df = s;
		((int *) &df)[LOWORD] = 0;
		c = (z - df * df) / (s + df);
		p = z * (pS0 + z * (pS1 + z * (pS2 + z * (pS3 +
			z * (pS4 + z * pS5)))));
		q = one + z * (qS1 + z * (qS2 + z * (qS3 + z * qS4)));
		r = p / q;
		w = r * s + c;
		return (2.0 * (df + w));
	}
}
