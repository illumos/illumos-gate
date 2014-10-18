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
#pragma weak llroundl = __llroundl
#if defined(__sparcv9) || defined(__amd64)
#pragma weak lroundl = __llroundl
#pragma weak __lroundl = __llroundl
#endif
#endif

#include "libm.h"

#if defined(__sparc)
long long
llroundl(long double x) {
	union {
		unsigned i[4];
		long double q;
	} xx;
	union {
		unsigned i[2];
		long long l;
	} zz;
	union {
		unsigned i;
		float f;
	} tt;
	unsigned hx, sx, frac;
	int j;

	xx.q = x;
	sx = xx.i[0] & 0x80000000;
	hx = xx.i[0] & ~0x80000000;

	/* handle trivial cases */
	if (hx > 0x403e0000) { /* |x| > 2^63 + ... or x is nan */
		/* convert an out-of-range float */
		tt.i = sx | 0x7f000000;
		return ((long long) tt.f);
	}

	/* handle |x| < 1 */
	if (hx < 0x3fff0000) {
		if (hx >= 0x3ffe0000)
			return (sx ? -1LL : 1LL);
		return (0LL);
	}

	/* extract the integer and fractional parts of x */
	j = 0x406f - (hx >> 16);
	xx.i[0] = 0x10000 | (xx.i[0] & 0xffff);
	if (j >= 96) {
		zz.i[0] = 0;
		zz.i[1] = xx.i[0] >> (j - 96);
		frac = ((xx.i[0] << 1) << (127 - j)) | (xx.i[1] >> (j - 96));
		if (((xx.i[1] << 1) << (127 - j)) | xx.i[2] | xx.i[3])
			frac |= 1;
	} else if (j >= 64) {
		zz.i[0] = xx.i[0] >> (j - 64);
		zz.i[1] = ((xx.i[0] << 1) << (95 - j)) | (xx.i[1] >> (j - 64));
		frac = ((xx.i[1] << 1) << (95 - j)) | (xx.i[2] >> (j - 64));
		if (((xx.i[2] << 1) << (95 - j)) | xx.i[3])
			frac |= 1;
	} else {
		zz.i[0] = ((xx.i[0] << 1) << (63 - j)) | (xx.i[1] >> (j - 32));
		zz.i[1] = ((xx.i[1] << 1) << (63 - j)) | (xx.i[2] >> (j - 32));
		frac = ((xx.i[2] << 1) << (63 - j)) | (xx.i[3] >> (j - 32));
		if ((xx.i[3] << 1) << (63 - j))
			frac |= 1;
	}

	/* round */
	if (frac >= 0x80000000u) {
		if (++zz.i[1] == 0)
			zz.i[0]++;
	}

	/* check for result out of range (note that z is |x| at this point) */
	if (zz.i[0] > 0x80000000u || (zz.i[0] == 0x80000000 && (zz.i[1] ||
		!sx))) {
		tt.i = sx | 0x7f000000;
		return ((long long) tt.f);
	}

	/* negate result if need be */
	if (sx) {
		zz.i[0] = ~zz.i[0];
		zz.i[1] = -zz.i[1];
		if (zz.i[1] == 0)
			zz.i[0]++;
	}

	return (zz.l);
}
#elif defined(__x86)
long long
llroundl(long double x) {
	union {
		unsigned i[3];
		long double e;
	} xx;
	int ex, sx, i;

	xx.e = x;
	ex = xx.i[2] & 0x7fff;
	sx = xx.i[2] & 0x8000;

	if (ex < 0x403e) { /* |x| < 2^63 */
		/* handle |x| < 1 */
		if (ex < 0x3fff) {
			if (ex >= 0x3ffe)
				return (sx ? -1LL : 1LL);
			return (0LL);
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
	return ((long long) xx.e);
}
#else
#error Unknown architecture
#endif
