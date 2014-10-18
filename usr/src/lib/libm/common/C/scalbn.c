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

#pragma weak scalbn = __scalbn

#include "libm.h"

static const double
	one	= 1.0,
	huge	= 1.0e300,
	tiny	= 1.0e-300,
	twom54	= 5.5511151231257827021181583404541015625e-17;

#if defined(USE_FPSCALE) || defined(__x86)
static const double two52 = 4503599627370496.0;
#else
/*
 * Normalize non-zero subnormal x and return biased exponent of x in [-51,0]
 */
static int
ilogb_biased(unsigned *px) {
	int s = 52;
	unsigned v = px[HIWORD] & ~0x80000000, w = px[LOWORD], t = v;

	if (t)
		s -= 32;
	else
		t = w;
	if (t & 0xffff0000)
		s -= 16, t >>= 16;
	if (t & 0xff00)
		s -= 8, t >>= 8;
	if (t & 0xf0)
		s -= 4, t >>= 4;
	t <<= 1;
	s -= (0xffffaa50 >> t) & 0x3;
	if (s < 32) {
		v = (v << s) | w >> (32 - s);
		w <<= s;
	} else {
		v = w << (s - 32);
		w = 0;
	}
	px[HIWORD] = (px[HIWORD] & 0x80000000) | v;
	px[LOWORD] = w;
	return (1 - s);
}
#endif	/* defined(USE_FPSCALE) */

double
scalbn(double x, int n) {
	int	*px, ix, hx, k;

	px = (int *)&x;
	ix = px[HIWORD];
	hx = ix & ~0x80000000;
	k = hx >> 20;

	if (k == 0x7ff)	/* x is inf or NaN */
		return (x * one);

	if (k == 0) {
		if ((hx | px[LOWORD]) == 0 || n == 0)
			return (x);
#if defined(USE_FPSCALE) || defined(__x86)
		x *= two52;
		ix = px[HIWORD];
		k = ((ix & ~0x80000000) >> 20) - 52;
#else
		k = ilogb_biased((unsigned *)px);
		ix = px[HIWORD];
#endif
		/* now k is in the range -51..0 */
		k += n;
		if (k > n)	/* integer overflow occurred */
			k = -100;
	} else {
		/* k is in the range 1..1023 */
		k += n;
		if (k < n)	/* integer overflow occurred */
			k = 0x7ff;
	}

	if (k > 0x7fe)
		return (huge * ((ix < 0)? -huge : huge));
	if (k < 1) {
		if (k <= -54)
			return (tiny * ((ix < 0)? -tiny : tiny));
		k += 54;
		px[HIWORD] = (ix & ~0x7ff00000) | (k << 20);
		return (x * twom54);
	}
	px[HIWORD] = (ix & ~0x7ff00000) | (k << 20);
	return (x);
}
