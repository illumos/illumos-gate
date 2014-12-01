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

#pragma weak nearbyintf = __nearbyintf

#include "libm.h"
#include <fenv.h>

float
__nearbyintf(float x) {
	union {
		unsigned i;
		float f;
	} xx;
	unsigned hx, sx, i, frac;
	int rm;

	xx.f = x;
	sx = xx.i & 0x80000000;
	hx = xx.i & ~0x80000000;

	/* handle trivial cases */
	if (hx >= 0x4b000000) {	/* x is nan, inf, or already integral */
		if (hx > 0x7f800000)	/* x is nan */
			return (x * x);		/* + -> * for Cheetah */
		return (x);
	} else if (hx == 0)		/* x is zero */
		return (x);

	/* get the rounding mode */
	rm = fegetround();

	/* flip the sense of directed roundings if x is negative */
	if (sx && (rm == FE_UPWARD || rm == FE_DOWNWARD))
		rm = (FE_UPWARD + FE_DOWNWARD) - rm;

	/* handle |x| < 1 */
	if (hx < 0x3f800000) {
		if (rm == FE_UPWARD || (rm == FE_TONEAREST && hx > 0x3f000000))
			xx.i = sx | 0x3f800000;
		else
			xx.i = sx;
		return (xx.f);
	}

	/* round x at the integer bit */
	i = 1 << (0x96 - (hx >> 23));
	frac = hx & (i - 1);
	if (!frac)
		return (x);

	hx &= ~(i - 1);
	if (rm == FE_UPWARD || (rm == FE_TONEAREST && (frac > (i >> 1) ||
		((frac == (i >> 1)) && (hx & i)))))
		xx.i = sx | (hx + i);
	else
		xx.i = sx | hx;
	return (xx.f);
}

#if 0

/*
 * Alternate implementations for SPARC, x86, using fp ops.  These may
 * be faster depending on how expensive saving and restoring the fp
 * modes and status flags is.
 */

#include "libm.h"
#include "fma.h"

#if defined(__sparc)

float
__nearbyintf(float x) {
	union {
		unsigned i;
		float f;
	} xx, yy;
	float z;
	unsigned hx, sx, fsr, oldfsr;
	int rm;

	xx.f = x;
	sx = xx.i & 0x80000000;
	hx = xx.i & ~0x80000000;

	/* handle trivial cases */
	if (hx >= 0x4b000000)	/* x is nan, inf, or already integral */
		return (x + 0.0f);
	else if (hx == 0)	/* x is zero */
		return (x);

	/* save the fsr */
	__fenv_getfsr(&oldfsr);

	/* handle |x| < 1 */
	if (hx < 0x3f800000) {
		/* flip the sense of directed roundings if x is negative */
		rm = oldfsr >> 30;
		if (sx)
			rm ^= rm >> 1;
		if (rm == FSR_RP || (rm == FSR_RN && hx > 0x3f000000))
			xx.i = sx | 0x3f800000;
		else
			xx.i = sx;
		return (xx.f);
	}

	/* clear the inexact trap */
	fsr = oldfsr & ~FSR_NXM;
	__fenv_setfsr(&fsr);

	/* round x at the integer bit */
	yy.i = sx | 0x4b000000;
	z = (x + yy.f) - yy.f;

	/* restore the old fsr */
	__fenv_setfsr(&oldfsr);

	return (z);
}

#elif defined(__x86)

/* inline template */
extern long double frndint(long double);

float
__nearbyintf(float x) {
	long double z;
	unsigned oldcwsw, cwsw;

	/* save the control and status words, mask the inexact exception */
	__fenv_getcwsw(&oldcwsw);
	cwsw = oldcwsw | 0x00200000;
	__fenv_setcwsw(&cwsw);

	z = frndint((long double) x);

	/*
	 * restore the control and status words, preserving all but the
	 * inexact flag
	 */
	__fenv_getcwsw(&cwsw);
	oldcwsw |= (cwsw & 0x1f);
	__fenv_setcwsw(&oldcwsw);

	/* note: the value of z is representable in single precision */
	return (z);
}

#else
#error Unknown architecture
#endif

#endif
