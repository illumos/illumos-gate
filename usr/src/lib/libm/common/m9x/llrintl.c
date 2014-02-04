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
#pragma weak llrintl = __llrintl
#if defined(__sparcv9) || defined(__amd64)
#pragma weak lrintl = __llrintl
#pragma weak __lrintl = __llrintl
#endif
#endif

#include "libm.h"

#if defined(__sparc)

#include "fma.h"
#include "fenv_inlines.h"

long long
llrintl(long double x) {
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
	unsigned int hx, sx, frac, fsr;
	int rm, j;
	volatile float dummy;

	xx.q = x;
	sx = xx.i[0] & 0x80000000;
	hx = xx.i[0] & ~0x80000000;

	/* handle trivial cases */
	if (hx > 0x403e0000) { /* |x| > 2^63 + ... or x is nan */
		/* convert an out-of-range float */
		tt.i = sx | 0x7f000000;
		return ((long long) tt.f);
	} else if ((hx | xx.i[1] | xx.i[2] | xx.i[3]) == 0) /* x is zero */
		return (0LL);

	/* get the rounding mode */
	__fenv_getfsr32(&fsr);
	rm = fsr >> 30;

	/* flip the sense of directed roundings if x is negative */
	if (sx)
		rm ^= rm >> 1;

	/* handle |x| < 1 */
	if (hx < 0x3fff0000) {
		dummy = 1.0e30f; /* x is nonzero, so raise inexact */
		dummy += 1.0e-30f;
		if (rm == FSR_RP || (rm == FSR_RN && (hx >= 0x3ffe0000 &&
			((hx & 0xffff) | xx.i[1] | xx.i[2] | xx.i[3]))))
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
	if (frac && (rm == FSR_RP || (rm == FSR_RN && (frac > 0x80000000u ||
		(frac == 0x80000000 && (zz.i[1] & 1)))))) {
		if (++zz.i[1] == 0)
			zz.i[0]++;
	}

	/* check for result out of range (note that z is |x| at this point) */
	if (zz.i[0] > 0x80000000u || (zz.i[0] == 0x80000000 && (zz.i[1] ||
		!sx))) {
		tt.i = sx | 0x7f000000;
		return ((long long) tt.f);
	}

	/* raise inexact if need be */
	if (frac) {
		dummy = 1.0e30F;
		dummy += 1.0e-30F;
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
llrintl(long double x) {
	/*
	 * Note: The following code works on x86 (in the default rounding
	 * precision mode), but one ought to just use the fistpll instruction
	 * instead.
	 */
	union {
		unsigned i[3];
		long double e;
	} xx, yy;
	int ex;

	xx.e = x;
	ex = xx.i[2] & 0x7fff;

	if (ex < 0x403e) { /* |x| < 2^63 */
		/* add and subtract a power of two to round x to an integer */
		yy.i[2] = (xx.i[2] & 0x8000) | 0x403e;
		yy.i[1] = 0x80000000;
		yy.i[0] = 0;
		x = (x + yy.e) - yy.e;
	}

	/* now x is nan, inf, or integral */
	return ((long long) x);
}
#else
#error Unknown architecture
#endif
