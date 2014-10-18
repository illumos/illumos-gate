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

#pragma weak sqrtf = __sqrtf

#include "libm.h"

#ifdef __INLINE

extern float __inline_sqrtf(float);

float
sqrtf(float x) {
	return (__inline_sqrtf(x));
}

#else	/* defined(__INLINE) */

static const float huge = 1.0e35F, tiny = 1.0e-35F, zero = 0.0f;

float
sqrtf(float x) {
	float	dz, w;
	int 	*pw = (int *)&w;
	int	ix, j, r, q, m, n, s, t;

	w = x;
	ix = pw[0];
	if (ix <= 0) {
		/* x is <= 0 or nan */
		j = ix & 0x7fffffff;
		if (j == 0)
			return (w);
		return ((w * zero) / zero);
	}

	if ((ix & 0x7f800000) == 0x7f800000) {
		/* x is +inf or nan */
		return (w * w);
	}

	m = ir_ilogb_(&w);
	n = -m;
	w = r_scalbn_(&w, (int *)&n);
	ix = (pw[0] & 0x007fffff) | 0x00800000;
	n = m / 2;
	if ((n + n) != m) {
		ix = ix + ix;
		m -= 1;
		n = m / 2;
	}

	/* generate sqrt(x) bit by bit */
	ix <<= 1;
	q = s = 0;
	r = 0x01000000;
	for (j = 1; j <= 25; j++) {
		t = s + r;
		if (t <= ix) {
			s = t + r;
			ix -= t;
			q += r;
		}
		ix <<= 1;
		r >>= 1;
	}
	if (ix == 0)
		goto done;

	/* raise inexact and determine the ambient rounding mode */
	dz = huge - tiny;
	if (dz < huge)
		goto done;
	dz = huge + tiny;
	if (dz > huge)
		q += 1;
	q += (q & 1);

done:
	pw[0] = (q >> 1) + 0x3f000000;
	return (r_scalbn_(&w, (int *)&n));
}

#endif	/* defined(__INLINE) */
