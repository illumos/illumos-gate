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

#pragma weak sinpil = __sinpil

/*
 * long double sinpil(long double x),
 * return long double precision sinl(pi*x).
 *
 * Algorithm, 10/17/2002, K.C. Ng
 * ------------------------------
 * Let y = |4x|, z = floor(y), and n = (int)(z mod 8.0) (displayed in binary).
 *	1. If y == z, then x is a multiple of pi/4. Return the following values:
 *             ---------------------------------------------------
 *               n  x mod 2    sin(x*pi)    cos(x*pi)   tan(x*pi)
 *             ---------------------------------------------------
 *              000  0.00       +0 ___       +1 ___      +0
 *              001  0.25       +\/0.5       +\/0.5      +1
 *              010  0.50       +1 ___       +0 ___      +inf
 *              011  0.75       +\/0.5       -\/0.5      -1
 *              100  1.00       -0 ___       -1 ___      +0
 *              101  1.25       -\/0.5       -\/0.5      +1
 *              110  1.50       -1 ___       -0 ___      +inf
 *              111  1.75       -\/0.5       +\/0.5      -1
 *             ---------------------------------------------------
 *      2. Otherwise,
 *             ---------------------------------------------------
 *               n     t        sin(x*pi)    cos(x*pi)   tan(x*pi)
 *             ---------------------------------------------------
 *              000  (y-z)/4	 sinpi(t)     cospi(t)    tanpi(t)
 *              001  (z+1-y)/4   cospi(t)     sinpi(t)	  1/tanpi(t)
 *              010  (y-z)/4	 cospi(t)    -sinpi(t)   -1/tanpi(t)
 *              011  (z+1-y)/4	 sinpi(t)    -cospi(t)	 -tanpi(t)
 *              100  (y-z)/4	-sinpi(t)    -cospi(t)    tanpi(t)
 *              101  (z+1-y)/4	-cospi(t)    -sinpi(t)	  1/tanpi(t)
 *              110  (y-z)/4	-cospi(t)     sinpi(t)	 -1/tanpi(t)
 *              111  (z+1-y)/4	-sinpi(t)     cospi(t)	 -tanpi(t)
 *             ---------------------------------------------------
 *
 * NOTE. This program compute sinpi/cospi(t<0.25) by __k_sin/cos(pi*t, 0.0).
 * This will return a result with error slightly more than one ulp (but less
 * than 2 ulp). If one wants accurate result,  one may break up pi*t in
 * high (tpi_h) and low (tpi_l) parts and call __k_sin/cos(tip_h, tip_lo)
 * instead.
 */

#include "libm.h"
#include "longdouble.h"

#define	I(q, m)	((int *) &(q))[m]
#define	U(q, m)	((unsigned *) &(q))[m]
#if defined(__LITTLE_ENDIAN) || defined(__x86)
#define	LDBL_MOST_SIGNIF_I(ld)	((I(ld, 2) << 16) | (0xffff & (I(ld, 1) >> 15)))
#define	LDBL_LEAST_SIGNIF_U(ld)	U(ld, 0)
#define	PREC	64
#define	PRECM1	63
#define	PRECM2	62
static const long double twoPRECM2 = 9.223372036854775808000000000000000e+18L;
#else
#define	LDBL_MOST_SIGNIF_I(ld)	I(ld, 0)
#define	LDBL_LEAST_SIGNIF_U(ld)	U(ld, sizeof (long double) / sizeof (int) - 1)
#define	PREC	113
#define	PRECM1	112
#define	PRECM2	111
static const long double twoPRECM2 = 5.192296858534827628530496329220096e+33L;
#endif

static const long double
zero	= 0.0L,
quater	= 0.25L,
one	= 1.0L,
pi	= 3.141592653589793238462643383279502884197e+0000L,
sqrth   = 0.707106781186547524400844362104849039284835937688474,
tiny    = 1.0e-100;

long double
sinpil(long double x) {
	long double y, z, t;
	int hx, n, k;
	unsigned lx;

	hx = LDBL_MOST_SIGNIF_I(x);
	lx = LDBL_LEAST_SIGNIF_U(x);
	k = ((hx & 0x7fff0000) >> 16) - 0x3fff;
	if (k >= PRECM2) {		/* |x| >= 2**(Prec-2) */
		if (k >= 16384)
			y = x - x;
		else {
			if (k >= PREC)
				y = zero;
			else if (k == PRECM1)
				y = (lx & 1) == 0 ? zero: -zero;
			else {	/* k = Prec - 2 */
				y = (lx & 1) == 0 ? zero : one;
				if ((lx & 2) != 0)
					y = -y;
			}
		}
	} else if (k < -2) 	/* |x| < 0.25 */
		y = __k_sinl(pi * fabsl(x), zero);
	else {
		/* y = |4x|, z = floor(y), and n = (int)(z mod 8.0) */
		y = 4.0L * fabsl(x);
		if (k < PRECM2) {
			z = y + twoPRECM2;
			n = LDBL_LEAST_SIGNIF_U(z) & 7;	/* 3 LSb of z */
			t = z - twoPRECM2;
			k = 0;
			if (t == y)
				k = 1;
			else if (t > y) {
				n -= 1;
				t = quater + (y - t) * quater;
			} else
				t = (y - t) * quater;
		} else { 	/* k = Prec-3 */
			n = LDBL_LEAST_SIGNIF_U(y) & 7;	/* 3 LSb of z */
			k = 1;
		}
		if (k) {	/* x = N/4 */
			if ((n & 1) != 0)
				y = sqrth + tiny;
			else
				y = (n & 2) == 0 ? zero : one;
			if ((n & 4) != 0)
				y = -y;
		} else {
			if ((n & 1) != 0)
				t = quater - t;
			if (((n + (n & 1)) & 2) == 0)
				y = __k_sinl(pi * t, zero);
			else
				y = __k_cosl(pi * t, zero);
			if ((n & 4) != 0)
				y = -y;
		}
	}
	return (hx >= 0 ? y : -y);
}
#undef U
#undef LDBL_LEAST_SIGNIF_U
#undef I
#undef LDBL_MOST_SIGNIF_I
