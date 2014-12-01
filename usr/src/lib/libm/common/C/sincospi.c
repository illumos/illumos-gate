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
 * void sincospi(double x, double *s, double *c)
 * *s = sin(pi*x); *c = cos(pi*x);
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
#include "libm_protos.h"
#include "libm_macros.h"
#include <math.h>
#if defined(__SUNPRO_C)
#include <sunmath.h>
#endif

static const double
	pi 	= 3.14159265358979323846,	/* 400921FB,54442D18 */
	sqrth_h = 0.70710678118654757273731092936941422522068023681640625,
	sqrth_l = -4.8336466567264565185935844299127932213411660131004e-17;
/* INDENT ON */

void
sincospi(double x, double *s, double *c) {
	double y, z, t;
	int n, ix, k;
	int hx = ((int *) &x)[HIWORD];
	unsigned h, lx = ((unsigned *) &x)[LOWORD];

	ix = hx & ~0x80000000;
	n = (ix >> 20) - 0x3ff;
	if (n >= 51) {			/* |x| >= 2**51 */
		if (n >= 1024)
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
			*s = *c = ix >= 0x7ff80000 ? x : x - x;
			/* assumes sparc-like QNaN */
#else
			*s = *c = x - x;
#endif
		else {
			if (n >= 53)  {
				*s = 0.0;
				*c = 1.0;
			}
			else if (n == 52)  {
				if ((lx & 1) == 0) {
					*s = 0.0;
					*c = 1.0;
				}
				else {
					*s = -0.0;
					*c = -1.0;
				}
			}
			else {	/* n == 51 */
				if ((lx & 1) == 0) {
					*s = 0.0;
					*c = 1.0;
				}
				else {
					*s = 1.0;
					*c = 0.0;
				}
				if ((lx & 2) != 0) {
					*s = -*s;
					*c = -*c;
				}
			}
		}
	}
	else if (n < -2) 	/* |x| < 0.25 */
		*s = __k_sincos(pi * fabs(x), 0.0, c);
	else {
		/* y = |4x|, z = floor(y), and n = (int)(z mod 8.0) */
		if (ix < 0x41C00000) {		/* |x| < 2**29 */
			y = 4.0 * fabs(x);
			n = (int) y;		/* exact */
			z = (double) n;
			k = z == y;
			t = (y - z) * 0.25;
		}
		else {				/* 2**29 <= |x| < 2**51 */
			y = fabs(x);
			k = 50 - n;
			n = lx >> k;
			h = n << k;
			((unsigned *) &z)[LOWORD] = h;
			((int *) &z)[HIWORD] = ix;
			k = h == lx;
			t = y - z;
		}
		if (k) {			/* x = N/4 */
			if ((n & 1) != 0)
				*s = *c = sqrth_h + sqrth_l;
			else
				if ((n & 2) == 0) {
					*s = 0.0;
					*c = 1.0;
				}
				else {
					*s = 1.0;
					*c = 0.0;
				}
				y = (n & 2) == 0 ? 0.0 : 1.0;
				if ((n & 4) != 0)
					*s = -*s;
				if (((n + 1) & 4) != 0)
					*c = -*c;
		}
		else {
			if ((n & 1) != 0)
				t = 0.25 - t;
			if (((n + (n & 1)) & 2) == 0)
				*s = __k_sincos(pi * t, 0.0, c);
			else
				*c = __k_sincos(pi * t, 0.0, s);
				if ((n & 4) != 0)
					*s = -*s;
				if (((n + 2) & 4) != 0)
					*c = -*c;
		}
	}
	if (hx < 0)
		*s = -*s;
}
