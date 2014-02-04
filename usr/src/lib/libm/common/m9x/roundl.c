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
#pragma weak roundl = __roundl
#endif

#include "libm.h"

#if defined(__sparc)
long double
roundl(long double x) {
	union {
		unsigned i[4];
		long double q;
	} xx;
	unsigned hx, sx, v;
	int j;

	xx.q = x;
	sx = xx.i[0] & 0x80000000;
	hx = xx.i[0] & ~0x80000000;

	/* handle trivial cases */
	if (hx >= 0x406f0000) /* |x| >= 2^112 + ... or x is nan */
		return (hx >= 0x7fff0000 ? x + x : x);

	/* handle |x| < 1 */
	if (hx < 0x3fff0000) {
		if (hx >= 0x3ffe0000)
			return (sx ? -1.0L : 1.0L);
		return (sx ? -0.0L : 0.0L);
	}

	xx.i[0] = hx;
	j = 0x406f - (hx >> 16);		/* 1 <= j <= 112 */
	if (j >= 96) {				/* 96 <= j <= 112 */
		v = (1U << (j - 96)) >> 1;
		if (v) {
			if (xx.i[0] & v)
				xx.i[0] += v;
			xx.i[0] &= ~(v - 1);
		} else if (xx.i[1] & 0x80000000)
				++xx.i[0];
		xx.i[1] = xx.i[2] = xx.i[3] = 0;
	} else if (j >= 64) {			/* 64 <= j <= 95 */
		v = (1U << (j - 64)) >> 1;
		if (v) {
			if (xx.i[1] & v) {
				xx.i[1] += v;
				if (xx.i[1] < v)
					++xx.i[0];
			}
			xx.i[1] &= ~(v - 1);
		} else if (xx.i[2] & 0x80000000) {
				if (++xx.i[1] == 0)
					++xx.i[0];
		}
		xx.i[2] = xx.i[3] = 0;
	} else if (j >= 32) {			/* 32 <= j <= 63 */
		v = (1U << (j - 32)) >> 1;
		if (v) {
			if (xx.i[2] & v) {
				xx.i[2] += v;
				if (xx.i[2] < v) {
					if (++xx.i[1] == 0)
						++xx.i[0];
				}
			}
			xx.i[2] &= ~(v - 1);
		} else if (xx.i[3] & 0x80000000) {
				if (++xx.i[2] == 0) {
					if (++xx.i[1] == 0)
						++xx.i[0];
				}
		}
		xx.i[3] = 0;
	} else {				/* 1 <= j <= 31 */
		v = 1U << (j - 1);
		if (xx.i[3] & v) {
			xx.i[3] += v;
			if (xx.i[3] < v) {
				if (++xx.i[2] == 0) {
					if (++xx.i[1] == 0)
						++xx.i[0];
				}
			}
		}
		xx.i[3] &= ~(v - 1);
	}

	/* negate result if need be */
	if (sx)
		xx.i[0] |= 0x80000000;
	return (xx.q);
}
#elif defined(__x86)
long double
roundl(long double x) {
	union {
		unsigned i[3];
		long double e;
	} xx;
	int ex, sx, i;

	xx.e = x;
	ex = xx.i[2] & 0x7fff;
	sx = xx.i[2] & 0x8000;
	if (ex < 0x403e) {	/* |x| < 2^63 */
		if (ex < 0x3fff) {	/* |x| < 1 */
			if (ex >= 0x3ffe)
				return (sx ? -1.0L : 1.0L);
			return (sx ? -0.0L : 0.0L);
		}

		/* round x at the integer bit */
		if (ex < 0x401e) {
			i = 1 << (0x401d - ex);
			xx.i[1] = (xx.i[1] + i) & ~(i | (i - 1));
			xx.i[0] = 0;
		} else {
			i = 1 << (0x403d - ex);
			xx.i[0] += i;
			if (xx.i[0] < i)
				xx.i[1]++;
			xx.i[0] &= ~(i | (i - 1));
		}
		if (xx.i[1] == 0) {
			xx.i[2] = sx | ++ex;
			xx.i[1] = 0x80000000U;
		}
		return (xx.e);
	} else if (ex < 0x7fff)	/* x is integral */
		return (x);
	else			/* inf or nan */
		return (x + x);
}
#else
#error Unknown architecture
#endif	/* defined(__sparc) || defined(__x86) */
