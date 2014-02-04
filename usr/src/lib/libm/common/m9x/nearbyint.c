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

#if defined(ELFOBJ)
#pragma weak nearbyint = __nearbyint
#endif

/*
 * nearbyint(x) returns the nearest fp integer to x in the direction
 * corresponding to the current rounding direction without raising
 * the inexact exception.
 *
 * nearbyint(x) is x unchanged if x is +/-0 or +/-inf.  If x is NaN,
 * nearbyint(x) is also NaN.
 */

#include "libm.h"
#include "fenv_synonyms.h"
#include <fenv.h>

double
__nearbyint(double x) {
	union {
		unsigned i[2];
		double d;
	} xx;
	unsigned hx, sx, i, frac;
	int rm, j;

	xx.d = x;
	sx = xx.i[HIWORD] & 0x80000000;
	hx = xx.i[HIWORD] & ~0x80000000;

	/* handle trivial cases */
	if (hx >= 0x43300000) {	/* x is nan, inf, or already integral */
		if (hx >= 0x7ff00000)	/* x is inf or nan */
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
			return (hx >= 0x7ff80000 ? x : x + x);
			/* assumes sparc-like QNaN */
#else
			return (x + x);
#endif
		return (x);
	} else if ((hx | xx.i[LOWORD]) == 0)	/* x is zero */
		return (x);

	/* get the rounding mode */
	rm = fegetround();

	/* flip the sense of directed roundings if x is negative */
	if (sx && (rm == FE_UPWARD || rm == FE_DOWNWARD))
		rm = (FE_UPWARD + FE_DOWNWARD) - rm;

	/* handle |x| < 1 */
	if (hx < 0x3ff00000) {
		if (rm == FE_UPWARD || (rm == FE_TONEAREST &&
			(hx >= 0x3fe00000 && ((hx & 0xfffff) | xx.i[LOWORD]))))
			xx.i[HIWORD] = sx | 0x3ff00000;
		else
			xx.i[HIWORD] = sx;
		xx.i[LOWORD] = 0;
		return (xx.d);
	}

	/* round x at the integer bit */
	j = 0x433 - (hx >> 20);
	if (j >= 32) {
		i = 1 << (j - 32);
		frac = ((xx.i[HIWORD] << 1) << (63 - j)) |
			(xx.i[LOWORD] >> (j - 32));
		if (xx.i[LOWORD] & (i - 1))
			frac |= 1;
		if (!frac)
			return (x);
		xx.i[LOWORD] = 0;
		xx.i[HIWORD] &= ~(i - 1);
		if ((rm == FE_UPWARD) || ((rm == FE_TONEAREST) &&
			((frac > 0x80000000u) || ((frac == 0x80000000) &&
			(xx.i[HIWORD] & i)))))
			xx.i[HIWORD] += i;
	} else {
		i = 1 << j;
		frac = (xx.i[LOWORD] << 1) << (31 - j);
		if (!frac)
			return (x);
		xx.i[LOWORD] &= ~(i - 1);
		if ((rm == FE_UPWARD) || ((rm == FE_TONEAREST) &&
			(frac > 0x80000000u || ((frac == 0x80000000) &&
			(xx.i[LOWORD] & i))))) {
			xx.i[LOWORD] += i;
			if (xx.i[LOWORD] == 0)
				xx.i[HIWORD]++;
		}
	}
	return (xx.d);
}
