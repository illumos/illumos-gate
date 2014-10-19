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

#pragma weak remquof = __remquof

/* INDENT OFF */
/*
 * float remquof(float x, float y, int *quo) return remainderf(x,y) and an
 * integer pointer quo such that *quo = N mod (2**31),  where N is the
 * exact integeral part of x/y rounded to nearest even.
 *
 * remquof call internal fmodquof
 */

#include "libm.h"
#include "libm_synonyms.h"
#include "libm_protos.h"
#include <math.h>
extern float fabsf(float);

static const int
	is = (int) 0x80000000,
	im = 0x007fffff,
	ii = 0x7f800000,
	iu = 0x00800000;

static const float zero = 0.0F, half = 0.5F;
/* INDENT ON */

static float
fmodquof(float x, float y, int *quo) {
	float w;
	int hx, ix, iy, iz, k, ny, nd, m, sq;

	hx = *(int *) &x;
	ix = hx & 0x7fffffff;
	iy = *(int *) &y;
	sq = (iy ^ hx) & is;	/* sign of x/y */
	iy &= 0x7fffffff;

	/* purge off exception values */
	*quo = 0;
	if (ix >= ii || iy > ii || iy == 0) {
		w = x * y;
		w = w / w;
	} else if (ix <= iy) {
		if (ix < iy)
			w = x;	/* return x if |x|<|y| */
		else {
			*quo = 1 + (sq >> 30);
			w = zero * x;	/* return sign(x)*0.0  */
		}
	} else {
		/* INDENT OFF */
		/*
		 * scale x,y to "normal" with
		 *	ny = exponent of y
		 *	nd = exponent of x minus exponent of y
		 */
		/* INDENT ON */
		ny = iy >> 23;
		k = ix >> 23;

		/* special case for subnormal y or x */
		if (ny == 0) {
			ny = 1;
			while (iy < iu) {
				ny -= 1;
				iy += iy;
			}
			nd = k - ny;
			if (k == 0) {
				nd += 1;
				while (ix < iu) {
					nd -= 1;
					ix += ix;
				}
			} else
				ix = iu | (ix & im);
		} else {
			nd = k - ny;
			ix = iu | (ix & im);
			iy = iu | (iy & im);
		}
		/* INDENT OFF */
		/* fix point fmod for normalized ix and iy */
		/*
		 * while (nd--) {
		 *	iz = ix - iy;
		 *	if (iz < 0)
		 *		ix = ix + ix;
		 *	else if (iz == 0) {
		 *		*(int *) &w = is & hx;
		 *		return w;
		 *	} else
		 *		ix = iz + iz;
		 * }
		 */
		/* INDENT ON */
		/* unroll the above loop 4 times to gain performance */
		m = 0;
		k = nd >> 2;
		nd -= (k << 2);
		while (k--) {
			iz = ix - iy;
			if (iz >= 0) {
				m += 1;
				ix = iz + iz;
			} else
				ix += ix;
			m += m;
			iz = ix - iy;
			if (iz >= 0) {
				m += 1;
				ix = iz + iz;
			} else
				ix += ix;
			m += m;
			iz = ix - iy;
			if (iz >= 0) {
				m += 1;
				ix = iz + iz;
			} else
				ix += ix;
			m += m;
			iz = ix - iy;
			if (iz >= 0) {
				m += 1;
				ix = iz + iz;
			} else
				ix += ix;
			m += m;
			if (iz == 0) {
				iz = (k << 2) + nd;
				if (iz < 32)
					m <<= iz;
				else
					m = 0;
				m &= 0x7fffffff;
				*quo = sq >= 0 ? m : -m;
				*(int *) &w = is & hx;
				return (w);
			}
		}
		while (nd--) {
			iz = ix - iy;
			if (iz >= 0) {
				m += 1;
				ix = iz + iz;
			} else
				ix += ix;
			m += m;
		}
		/* end of unrolling */

		iz = ix - iy;
		if (iz >= 0) {
			m += 1;
			ix = iz;
		}
		m &= 0x7fffffff;
		*quo = sq >= 0 ? m : -m;

		/* convert back to floating value and restore the sign */
		if (ix == 0) {
			*(int *) &w = is & hx;
			return (w);
		}
		while (ix < iu) {
			ix += ix;
			ny -= 1;
		}
		while (ix > (iu + iu)) {
			ny += 1;
			ix >>= 1;
		}
		if (ny > 0)
			*(int *) &w = (is & hx) | (ix & im) | (ny << 23);
		else {		/* subnormal output */
			k = -ny + 1;
			ix >>= k;
			*(int *) &w = (is & hx) | ix;
		}
	}
	return (w);
}

float
remquof(float x, float y, int *quo) {
	int hx, hy, sx, sq;
	float v;

	hx = *(int *) &x;	/* high word of x */
	hy = *(int *) &y;	/* high word of y */
	sx = hx & is;		/* sign of x */
	sq = (hx ^ hy) & is;	/* sign of x/y */
	hx ^= sx;		/* |x| */
	hy &= 0x7fffffff;	/* |y| */

	/* purge off exception values: y is 0 or NaN, x is Inf or NaN */
	*quo = 0;
	if (hx >= ii || hy > ii || hy == 0) {
		v = x * y;
		return (v / v);
	}

	y = fabsf(y);
	x = fabsf(x);
	if (hy <= 0x7f7fffff) {
		x = fmodquof(x, y + y, quo);
		*quo = ((*quo) & 0x3fffffff) << 1;
	}
	if (hy < 0x01000000) {
		if (x + x > y) {
			*quo += 1;
			if (x == y)
				x = zero;
			else
				x -= y;
			if (x + x >= y) {
				x -= y;
				*quo += 1;
			}
		}
	} else {
		v = half * y;
		if (x > v) {
			*quo += 1;
			if (x == y)
				x = zero;
			else
				x -= y;
			if (x >= v) {
				x -= y;
				*quo += 1;
			}
		}
	}
	if (sq != 0)
		*quo = -(*quo);
	return (sx == 0 ? x : -x);
}
