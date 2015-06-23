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

#pragma weak __scalblnf = scalblnf

#include "libm.h"
#include <float.h>		/* FLT_MAX, FLT_MIN */

static const float twom25f = 2.98023223876953125e-8F;
#if defined(__x86)
static const float two23f = 8388608.0F;
#else
/*
 * v: a non-zero subnormal |x|; returns [-22, 0]
 */
static int
ilogbf_biased(unsigned v) {
	int r = -22;

	if (v & 0xffff0000)
		r += 16, v >>= 16;
	if (v & 0xff00)
		r += 8, v >>= 8;
	if (v & 0xf0)
		r += 4, v >>= 4;
	v <<= 1;
	return (r + ((0xffffaa50 >> v) & 0x3));
}
#endif	/* defined(__x86) */

float
scalblnf(float x, long n) {
	int *px = (int *) &x, ix, k;

	ix = *px & ~0x80000000;
	k = ix >> 23;
	if (k == 0xff)
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
		return (ix > 0x7f800000 ? x * x : x);
#else
		return (x + x);
#endif
	if (ix == 0 || n == 0)
		return (x);
	if (k == 0) {
#if defined(__x86)
		x *= two23f;
		k = ((*px & ~0x80000000) >> 23) - 23;
#else
		k = ilogbf_biased(ix);
		*px = (*px & 0x80000000) | (ix << (-k + 1));
#endif
	}
	k += (int) n;
	if (n > 5000 || k > 0xfe)
		return (FLT_MAX * copysignf(FLT_MAX, x));
	if (n < -5000 || k <= -25)
		return (FLT_MIN * copysignf(FLT_MIN, x));
	if (k > 0) {
		*px = (*px & ~0x7f800000) | (k << 23);
		return (x);
	}
	k += 25;
	*px = (*px & ~0x7f800000) | (k << 23);
	return (x * twom25f);
}
