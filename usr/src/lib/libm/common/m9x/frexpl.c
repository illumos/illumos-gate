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
#pragma weak frexpl = __frexpl
#endif

#include "libm.h"

#if defined(__sparc)

long double
__frexpl(long double x, int *exp) {
	union {
		unsigned i[4];
		long double q;
	} xx;
	unsigned hx;
	int e, s;

	xx.q = x;
	hx = xx.i[0] & ~0x80000000;

	if (hx >= 0x7fff0000) {	/* x is infinite or NaN */
		*exp = 0;
		return (x);
	}

	e = 0;
	if (hx < 0x00010000) {	/* x is subnormal or zero */
		if ((hx | xx.i[1] | xx.i[2] | xx.i[3]) == 0) {
			*exp = 0;
			return (x);
		}

		/* normalize x */
		s = xx.i[0] & 0x80000000;
		while ((hx | (xx.i[1] & 0xffff0000)) == 0) {
			hx = xx.i[1];
			xx.i[1] = xx.i[2];
			xx.i[2] = xx.i[3];
			xx.i[3] = 0;
			e -= 32;
		}
		while (hx < 0x10000) {
			hx = (hx << 1) | (xx.i[1] >> 31);
			xx.i[1] = (xx.i[1] << 1) | (xx.i[2] >> 31);
			xx.i[2] = (xx.i[2] << 1) | (xx.i[3] >> 31);
			xx.i[3] <<= 1;
			e--;
		}
		xx.i[0] = s | hx;
	}

	/* now xx.q is normal */
	xx.i[0] = (xx.i[0] & ~0x7fff0000) | 0x3ffe0000;
	*exp = e + (hx >> 16) - 0x3ffe;
	return (xx.q);
}

#elif defined(__x86)

long double
__frexpl(long double x, int *exp) {
	union {
		unsigned i[3];
		long double e;
	} xx;
	unsigned hx;
	int e;

	xx.e = x;
	hx = xx.i[2] & 0x7fff;

	if (hx >= 0x7fff) {	/* x is infinite or NaN */
		*exp = 0;
		return (x);
	}

	e = 0;
	if (hx < 0x0001) {	/* x is subnormal or zero */
		if ((xx.i[0] | xx.i[1]) == 0) {
			*exp = 0;
			return (x);
		}

		/* normalize x */
		xx.e *= 18446744073709551616.0L;	/* 2^64 */
		hx = xx.i[2] & 0x7fff;
		e = -64;
	}

	/* now xx.e is normal */
	xx.i[2] = (xx.i[2] & 0x8000) | 0x3ffe;
	*exp = e + hx - 0x3ffe;
	return (xx.e);
}

#else
#error Unknown architecture
#endif
