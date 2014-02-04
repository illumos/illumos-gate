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
#pragma weak nearbyintl = __nearbyintl
#endif

#include "libm.h"
#include "fma.h"
#include "fenv_inlines.h"

#if defined(__sparc)

static union {
	unsigned i;
	float f;
} snan = { 0x7f800001 };

long double
__nearbyintl(long double x) {
	union {
		unsigned i[4];
		long double q;
	} xx;
	unsigned hx, sx, i, frac;
	unsigned int fsr;
	int rm, j;
	volatile float	dummy;

	xx.q = x;
	sx = xx.i[0] & 0x80000000;
	hx = xx.i[0] & ~0x80000000;

	/* handle trivial cases */
	if (hx >= 0x406f0000) {	/* x is nan, inf, or already integral */
		/* check for signaling nan */
		if ((hx > 0x7fff0000 || (hx == 0x7fff0000 &&
			(xx.i[1] | xx.i[2] | xx.i[3]))) && !(hx & 0x8000)) {
			dummy = snan.f;
			dummy += snan.f;
			xx.i[0] = sx | hx | 0x8000;
		}
		return (xx.q);
	} else if ((hx | xx.i[1] | xx.i[2] | xx.i[3]) == 0)	/* x is zero */
		return (x);

	/* get the rounding mode */
	__fenv_getfsr32(&fsr);
	rm = fsr >> 30;

	/* flip the sense of directed roundings if x is negative */
	if (sx)
		rm ^= rm >> 1;

	/* handle |x| < 1 */
	if (hx < 0x3fff0000) {
		if (rm == FSR_RP || (rm == FSR_RN && (hx >= 0x3ffe0000 &&
			((hx & 0xffff) | xx.i[1] | xx.i[2] | xx.i[3]))))
			xx.i[0] = sx | 0x3fff0000;
		else
			xx.i[0] = sx;
		xx.i[1] = xx.i[2] = xx.i[3] = 0;
		return (xx.q);
	}

	/* round x at the integer bit */
	j = 0x406f - (hx >> 16);
	if (j >= 96) {
		i = 1 << (j - 96);
		frac = ((xx.i[0] << 1) << (127 - j)) | (xx.i[1] >> (j - 96));
		if ((xx.i[1] & (i - 1)) | xx.i[2] | xx.i[3])
			frac |= 1;
		if (!frac)
			return (x);
		xx.i[1] = xx.i[2] = xx.i[3] = 0;
		xx.i[0] &= ~(i - 1);
		if (rm == FSR_RP || (rm == FSR_RN && (frac > 0x80000000u ||
			(frac == 0x80000000 && (xx.i[0] & i)))))
			xx.i[0] += i;
	} else if (j >= 64) {
		i = 1 << (j - 64);
		frac = ((xx.i[1] << 1) << (95 - j)) | (xx.i[2] >> (j - 64));
		if ((xx.i[2] & (i - 1)) | xx.i[3])
			frac |= 1;
		if (!frac)
			return (x);
		xx.i[2] = xx.i[3] = 0;
		xx.i[1] &= ~(i - 1);
		if (rm == FSR_RP || (rm == FSR_RN && (frac > 0x80000000u ||
			(frac == 0x80000000 && (xx.i[1] & i))))) {
			xx.i[1] += i;
			if (xx.i[1] == 0)
				xx.i[0]++;
		}
	} else if (j >= 32) {
		i = 1 << (j - 32);
		frac = ((xx.i[2] << 1) << (63 - j)) | (xx.i[3] >> (j - 32));
		if (xx.i[3] & (i - 1))
			frac |= 1;
		if (!frac)
			return (x);
		xx.i[3] = 0;
		xx.i[2] &= ~(i - 1);
		if (rm == FSR_RP || (rm == FSR_RN && (frac > 0x80000000u ||
			(frac == 0x80000000 && (xx.i[2] & i))))) {
			xx.i[2] += i;
			if (xx.i[2] == 0)
				if (++xx.i[1] == 0)
					xx.i[0]++;
		}
	} else {
		i = 1 << j;
		frac = (xx.i[3] << 1) << (31 - j);
		if (!frac)
			return (x);
		xx.i[3] &= ~(i - 1);
		if (rm == FSR_RP || (rm == FSR_RN && (frac > 0x80000000u ||
			(frac == 0x80000000 && (xx.i[3] & i))))) {
			xx.i[3] += i;
			if (xx.i[3] == 0)
				if (++xx.i[2] == 0)
					if (++xx.i[1] == 0)
						xx.i[0]++;
		}
	}

	return (xx.q);
}

#elif defined(__x86)

/* inline template */
extern long double frndint(long double);

long double
__nearbyintl(long double x) {
	long double z;
	unsigned oldcwsw, cwsw;

	/* save the control and status words, mask the inexact exception */
	__fenv_getcwsw(&oldcwsw);
	cwsw = oldcwsw | 0x00200000;
	__fenv_setcwsw(&cwsw);

	z = frndint(x);

	/*
	 * restore the control and status words, preserving all but the
	 * inexact flag
	 */
	__fenv_getcwsw(&cwsw);
	oldcwsw |= (cwsw & 0x1f);
	__fenv_setcwsw(&oldcwsw);

	return (z);
}

#else
#error Unknown architecture
#endif
