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

#pragma weak __fmodf = fmodf

#include "libm.h"

/* INDENT OFF */
static const int
	is = (int)0x80000000,
	im = 0x007fffff,
	ii = 0x7f800000,
	iu = 0x00800000;
/* INDENT ON */

static const float zero	= 0.0;

float
fmodf(float x, float y) {
	float	w;
	int	hx, ix, iy, iz, k, ny, nd;

	hx = *(int *)&x;
	ix = hx & 0x7fffffff;
	iy = *(int *)&y & 0x7fffffff;

	/* purge off exception values */
	if (ix >= ii || iy > ii || iy == 0) {
		w = x * y;
		w = w / w;
	} else if (ix <= iy) {
		if (ix < iy)
			w = x;	/* return x if |x|<|y| */
		else
			w = zero * x;	/* return sign(x)*0.0 */
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
			} else {
				ix = iu | (ix & im);
			}
		} else {
			nd = k - ny;
			ix = iu | (ix & im);
			iy = iu | (iy & im);
		}

		/* fix point fmod for normalized ix and iy */
		/* INDENT OFF */
		/*
		 * while (nd--) {
		 * 	iz = ix - iy;
		 * if (iz < 0)
		 *	ix = ix + ix;
		 * else if (iz == 0) {
		 *	*(int *) &w = is & hx;
		 *	return w;
		 * }
		 * else
		 *	ix = iz + iz;
		 * }
		 */
		/* INDENT ON */
		/* unroll the above loop 4 times to gain performance */
		k = nd >> 2;
		nd -= k << 2;
		while (k--) {
			iz = ix - iy;
			if (iz >= 0)
				ix = iz + iz;
			else
				ix += ix;
			iz = ix - iy;
			if (iz >= 0)
				ix = iz + iz;
			else
				ix += ix;
			iz = ix - iy;
			if (iz >= 0)
				ix = iz + iz;
			else
				ix += ix;
			iz = ix - iy;
			if (iz >= 0)
				ix = iz + iz;
			else
				ix += ix;
			if (iz == 0) {
				*(int *)&w = is & hx;
				return (w);
			}
		}
		while (nd--) {
			iz = ix - iy;
			if (iz >= 0)
				ix = iz + iz;
			else
				ix += ix;
		}
		/* end of unrolling */

		iz = ix - iy;
		if (iz >= 0)
			ix = iz;

		/* convert back to floating value and restore the sign */
		if (ix == 0) {
			*(int *)&w = is & hx;
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
		if (ny > 0) {
			*(int *)&w = (is & hx) | (ix & im) | (ny << 23);
		} else {
			/* subnormal output */
			k = -ny + 1;
			ix >>= k;
			*(int *)&w = (is & hx) | ix;
		}
	}
	return (w);
}
