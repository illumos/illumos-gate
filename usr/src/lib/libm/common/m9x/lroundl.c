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

#pragma weak __lroundl = lroundl

#include <sys/isa_defs.h>	/* _ILP32 */
#include "libm.h"

#if defined(_ILP32)
#if defined(__sparc)
long
lroundl(long double x) {
	union {
		unsigned i[4];
		long double q;
	} xx;
	union {
		unsigned i;
		float f;
	} tt;
	unsigned hx, sx, frac, l;
	int j;

	xx.q = x;
	sx = xx.i[0] & 0x80000000;
	hx = xx.i[0] & ~0x80000000;

	/* handle trivial cases */
	if (hx > 0x401e0000) { /* |x| > 2^31 + ... or x is nan */
		/* convert an out-of-range float */
		tt.i = sx | 0x7f000000;
		return ((long) tt.f);
	}

	/* handle |x| < 1 */
	if (hx < 0x3fff0000) {
		if (hx >= 0x3ffe0000)
			return (sx ? -1L : 1L);
		return (0L);
	}

	/* extract the integer and fractional parts of x */
	j = 0x406f - (hx >> 16);		/* 91 <= j <= 112 */
	xx.i[0] = 0x10000 | (xx.i[0] & 0xffff);
	if (j >= 96) {				/* 96 <= j <= 112 */
		l = xx.i[0] >> (j - 96);
		frac = ((xx.i[0] << 1) << (127 - j)) | (xx.i[1] >> (j - 96));
		if (((xx.i[1] << 1) << (127 - j)) | xx.i[2] | xx.i[3])
			frac |= 1;
	} else {				/* 91 <= j <= 95 */
		l = (xx.i[0] << (96 - j)) | (xx.i[1] >> (j - 64));
		frac = (xx.i[1] << (96 - j)) | (xx.i[2] >> (j - 64));
		if ((xx.i[2] << (96 - j)) | xx.i[3])
			frac |= 1;
	}

	/* round */
	if (frac >= 0x80000000U)
		l++;

	/* check for result out of range (note that z is |x| at this point) */
	if (l > 0x80000000U || (l == 0x80000000U && !sx)) {
		tt.i = sx | 0x7f000000;
		return ((long) tt.f);
	}

	/* negate result if need be */
	if (sx)
		l = -l;
	return ((long) l);
}
#elif defined(__x86)
long
lroundl(long double x) {
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
				return (sx ? -1L : 1L);
			return (0L);
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
	}

	/* now x is nan, inf, or integral */
	return ((long) xx.e);
}
#else
#error Unknown architecture
#endif	/* defined(__sparc) || defined(__x86) */
#else
#error Unsupported architecture
#endif	/* defined(_ILP32) */
