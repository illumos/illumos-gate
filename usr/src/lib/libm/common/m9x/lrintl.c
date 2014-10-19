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
#pragma weak lrintl = __lrintl
#endif

#include <sys/isa_defs.h>	/* _ILP32 */
#include "libm.h"

#if defined(_ILP32)
#if defined(__sparc)

#include "fma.h"
#include "fenv_inlines.h"

long
lrintl(long double x) {
	union {
		unsigned int i[4];
		long double q;
	} xx;
	union {
		unsigned int i;
		float f;
	} tt;
	unsigned int hx, sx, frac, l, fsr;
	int rm, j;
	volatile float dummy;

	xx.q = x;
	sx = xx.i[0] & 0x80000000;
	hx = xx.i[0] & ~0x80000000;

	/* handle trivial cases */
	if (hx > 0x401e0000) { /* |x| > 2^31 + ... or x is nan */
		/* convert an out-of-range float */
		tt.i = sx | 0x7f000000;
		return ((long) tt.f);
	} else if ((hx | xx.i[1] | xx.i[2] | xx.i[3]) == 0) /* x is zero */
		return (0L);

	/* get the rounding mode */
	__fenv_getfsr32(&fsr);
	rm = fsr >> 30;

	/* flip the sense of directed roundings if x is negative */
	if (sx)
		rm ^= rm >> 1;

	/* handle |x| < 1 */
	if (hx < 0x3fff0000) {
		dummy = 1.0e30F; /* x is nonzero, so raise inexact */
		dummy += 1.0e-30F;
		if (rm == FSR_RP || (rm == FSR_RN && (hx >= 0x3ffe0000 &&
			((hx & 0xffff) | xx.i[1] | xx.i[2] | xx.i[3]))))
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
	if (frac && (rm == FSR_RP || (rm == FSR_RN && (frac > 0x80000000U ||
		(frac == 0x80000000 && (l & 1))))))
		l++;

	/* check for result out of range (note that z is |x| at this point) */
	if (l > 0x80000000U || (l == 0x80000000U && !sx)) {
		tt.i = sx | 0x7f000000;
		return ((long) tt.f);
	}

	/* raise inexact if need be */
	if (frac) {
		dummy = 1.0e30F;
		dummy += 1.0e-30F;
	}

	/* negate result if need be */
	if (sx)
		l = -l;
	return ((long) l);
}
#elif defined(__x86)
long
lrintl(long double x) {
	/*
	 * Note: The following code works on x86 (in the default rounding
	 * precision mode), but one ought to just use the fistpl instruction
	 * instead.
	 */
	union {
		unsigned i[3];
		long double e;
	} xx, yy;
	int ex;

	xx.e = x;
	ex = xx.i[2] & 0x7fff;
	if (ex < 0x403e) {	/* |x| < 2^63 */
		/* add and subtract a power of two to round x to an integer */
		yy.i[2] = (xx.i[2] & 0x8000) | 0x403e;
		yy.i[1] = 0x80000000;
		yy.i[0] = 0;
		x = (x + yy.e) - yy.e;
	}

	/* now x is nan, inf, or integral */
	return ((long) x);
}
#else
#error Unknown architecture
#endif	/* defined(__sparc) || defined(__x86) */
#else
#error Unsupported architecture
#endif	/* defined(_ILP32) */
