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

#pragma weak fmaf = __fmaf

#include "libm.h"
#include "fma.h"
#include "fenv_inlines.h"

#if defined(__sparc)

/*
 * fmaf for SPARC: 32-bit single precision, big-endian
 */
float
__fmaf(float x, float y, float z) {
	union {
		unsigned i[2];
		double d;
	} xy, zz;
	unsigned u, s;
	int exy, ez;

	/*
	 * the following operations can only raise the invalid exception,
	 * and then only if either x*y is of the form Inf*0 or one of x,
	 * y, or z is a signaling NaN
	 */
	xy.d = (double) x * y;
	zz.d = (double) z;

	/*
	 * if the sum xy + z will be exact, just compute it and cast the
	 * result to float
	 */
	exy = (xy.i[0] >> 20) & 0x7ff;
	ez = (zz.i[0] >> 20) & 0x7ff;
	if ((ez - exy <= 4 && exy - ez <= 28) || exy == 0x7ff || exy == 0 ||
		ez == 0x7ff || ez == 0) {
		return ((float) (xy.d + zz.d));
	}

	/*
	 * collapse the tail of the smaller summand into a "sticky bit"
	 * so that the sum can be computed without error
	 */
	if (ez > exy) {
		if (ez - exy < 31) {
			u = xy.i[1];
			s = 2 << (ez - exy);
			if (u & (s - 1))
				u |= s;
			xy.i[1] = u & ~(s - 1);
		} else if (ez - exy < 51) {
			u = xy.i[0];
			s = 1 << (ez - exy - 31);
			if ((u & (s - 1)) | xy.i[1])
				u |= s;
			xy.i[0] = u & ~(s - 1);
			xy.i[1] = 0;
		} else {
			/* collapse all of xy into a single bit */
			xy.i[0] = (xy.i[0] & 0x80000000) | ((ez - 51) << 20);
			xy.i[1] = 0;
		}
	} else {
		if (exy - ez < 31) {
			u = zz.i[1];
			s = 2 << (exy - ez);
			if (u & (s - 1))
				u |= s;
			zz.i[1] = u & ~(s - 1);
		} else if (exy - ez < 51) {
			u = zz.i[0];
			s = 1 << (exy - ez - 31);
			if ((u & (s - 1)) | zz.i[1])
				u |= s;
			zz.i[0] = u & ~(s - 1);
			zz.i[1] = 0;
		} else {
			/* collapse all of zz into a single bit */
			zz.i[0] = (zz.i[0] & 0x80000000) | ((exy - 51) << 20);
			zz.i[1] = 0;
		}
	}

	return ((float) (xy.d + zz.d));
}

#elif defined(__x86)

#if defined(__amd64)
#define	NI	4
#else
#define	NI	3
#endif

/*
 * fmaf for x86: 32-bit single precision, little-endian
 */
float
__fmaf(float x, float y, float z) {
	union {
		unsigned i[NI];
		long double e;
	} xy, zz;
	unsigned u, s, cwsw, oldcwsw;
	int exy, ez;

	/* set rounding precision to 64 bits */
	__fenv_getcwsw(&oldcwsw);
	cwsw = (oldcwsw & 0xfcffffff) | 0x03000000;
	__fenv_setcwsw(&cwsw);

	/*
	 * the following operations can only raise the invalid exception,
	 * and then only if either x*y is of the form Inf*0 or one of x,
	 * y, or z is a signaling NaN
	 */
	xy.e = (long double) x * y;
	zz.e = (long double) z;

	/*
	 * if the sum xy + z will be exact, just compute it and cast the
	 * result to float
	 */
	exy = xy.i[2] & 0x7fff;
	ez = zz.i[2] & 0x7fff;
	if ((ez - exy <= 15 && exy - ez <= 39) || exy == 0x7fff || exy == 0 ||
		ez == 0x7fff || ez == 0) {
		goto cont;
	}

	/*
	 * collapse the tail of the smaller summand into a "sticky bit"
	 * so that the sum can be computed without error
	 */
	if (ez > exy) {
		if (ez - exy < 31) {
			u = xy.i[0];
			s = 2 << (ez - exy);
			if (u & (s - 1))
				u |= s;
			xy.i[0] = u & ~(s - 1);
		} else if (ez - exy < 62) {
			u = xy.i[1];
			s = 1 << (ez - exy - 31);
			if ((u & (s - 1)) | xy.i[0])
				u |= s;
			xy.i[1] = u & ~(s - 1);
			xy.i[0] = 0;
		} else {
			/* collapse all of xy into a single bit */
			xy.i[0] = 0;
			xy.i[1] = 0x80000000;
			xy.i[2] = (xy.i[2] & 0x8000) | (ez - 62);
		}
	} else {
		if (exy - ez < 62) {
			u = zz.i[1];
			s = 1 << (exy - ez - 31);
			if ((u & (s - 1)) | zz.i[0])
				u |= s;
			zz.i[1] = u & ~(s - 1);
			zz.i[0] = 0;
		} else {
			/* collapse all of zz into a single bit */
			zz.i[0] = 0;
			zz.i[1] = 0x80000000;
			zz.i[2] = (zz.i[2] & 0x8000) | (exy - 62);
		}
	}

cont:
	xy.e += zz.e;

	/* restore the rounding precision */
	__fenv_getcwsw(&cwsw);
	cwsw = (cwsw & 0xfcffffff) | (oldcwsw & 0x03000000);
	__fenv_setcwsw(&cwsw);

	return ((float) xy.e);
}

#if 0
/*
 * another fmaf for x86: assumes return value will be left in
 * long double (80-bit double extended) precision
 */
long double
__fmaf(float x, float y, float z) {
	/*
	 * Note: This implementation assumes the rounding precision mode
	 * is set to the default, rounding to 64 bit precision.  If this
	 * routine must work in non-default rounding precision modes, do
	 * the following instead:
	 *
	 *   long double t;
	 *
	 *   <set rp mode to round to 64 bit precision>
	 *   t = x * y;
	 *   <restore rp mode>
	 *   return t + z;
	 *
	 * Note that the code to change rounding precision must not alter
	 * the exception masks or flags, since the product x * y may raise
	 * an invalid operation exception.
	 */
	return ((long double) x * y + z);
}
#endif

#else
#error Unknown architecture
#endif
