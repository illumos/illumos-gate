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

#pragma weak sqrt = __sqrt

#include "libm.h"

#ifdef __INLINE

extern double __inline_sqrt(double);

double
sqrt(double x) {
	double	z = __inline_sqrt(x);

	if (isnan(x))
		return (z);
	return ((x < 0.0)? _SVID_libm_err(x, x, 26) : z);
}

#else	/* defined(__INLINE) */

/*
 * Warning: This correctly rounded sqrt is extremely slow because it computes
 * the sqrt bit by bit using integer arithmetic.
 */

static const double big = 1.0e30, small = 1.0e-30;

double
sqrt(double x)
{
	double		z;
	unsigned	r, t1, s1, ix1, q1;
	int		ix0, s0, j, q, m, n, t;
	int		 *px = (int *)&x, *pz = (int *)&z;

	ix0 = px[HIWORD];
	ix1 = px[LOWORD];
	if ((ix0 & 0x7ff00000) == 0x7ff00000) { /* x is inf or NaN */
		if (ix0 == 0xfff00000 && ix1 == 0)
			return (_SVID_libm_err(x, x, 26));
		return (x + x);
	}
	if (((ix0 & 0x7fffffff) | ix1) == 0)	/* x is zero */
		return (x);

	/* extract exponent and significand */
	m = ilogb(x);
	z = scalbn(x, -m);
	ix0 = (pz[HIWORD] & 0x000fffff) | 0x00100000;
	ix1 = pz[LOWORD];
	n = m >> 1;
	if (n + n != m) {
		ix0 = (ix0 << 1) | (ix1 >> 31);
		ix1 <<= 1;
		m -= 1;
	}

	/* generate sqrt(x) bit by bit */
	ix0 = (ix0 << 1) | (ix1 >> 31);
	ix1 <<= 1;
	q = q1 = s0 = s1 = 0;
	r = 0x00200000;

	for (j = 1; j <= 22; j++) {
		t = s0 + r;
		if (t <= ix0) {
			s0 = t + r;
			ix0 -= t;
			q += r;
		}
		ix0 = (ix0 << 1) | (ix1 >> 31);
		ix1 <<= 1;
		r >>= 1;
	}

	r = 0x80000000;
	for (j = 1; j <= 32; j++) {
		t1 = s1 + r;
		t = s0;
		if (t < ix0 || (t == ix0 && t1 <= ix1)) {
			s1 = t1 + r;
			if ((t1 & 0x80000000) == 0x80000000 &&
			    (s1 & 0x80000000) == 0)
				s0 += 1;
			ix0 -= t;
			if (ix1 < t1)
				ix0 -= 1;
			ix1 -= t1;
			q1 += r;
		}
		ix0 = (ix0 << 1) | (ix1 >> 31);
		ix1 <<= 1;
		r >>= 1;
	}

	/* round */
	if ((ix0 | ix1) == 0)
		goto done;
	z = big - small;	/* trigger inexact flag */
	if (z < big)
		goto done;
	if (q1 == 0xffffffff) {
		q1 = 0;
		q += 1;
		goto done;
	}
	z = big + small;
	if (z > big) {
		if (q1 == 0xfffffffe)
			q += 1;
		q1 += 2;
		goto done;
	}
	q1 += (q1 & 1);
done:
	pz[HIWORD] = (q >> 1) + 0x3fe00000;
	pz[LOWORD] = q1 >> 1;
	if ((q & 1) == 1)
		pz[LOWORD] |= 0x80000000;
	return (scalbn(z, n));
}

#endif	/* defined(__INLINE) */
