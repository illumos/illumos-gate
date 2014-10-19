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

#pragma weak fmod = __fmod

#include "libm.h"

static const double zero = 0.0;

/*
 * The following implementation assumes fast 64-bit integer arith-
 * metic.  This is fine for sparc because we build libm in v8plus
 * mode.  It's also fine for sparcv9 and amd64, although we have
 * assembly code on amd64.  For x86, it would be better to use
 * 32-bit code, but we have assembly for x86, too.
 */
double
fmod(double x, double y) {
	double		w;
	long long	hx, ix, iy, iz;
	int		nd, k, ny;

	hx = *(long long *)&x;
	ix = hx & ~0x8000000000000000ull;
	iy = *(long long *)&y & ~0x8000000000000000ull;

	/* handle special cases */
	if (iy == 0ll)
		return (_SVID_libm_err(x, y, 27));

	if (ix >= 0x7ff0000000000000ll || iy > 0x7ff0000000000000ll)
		return ((x * y) * zero);

	if (ix <= iy)
		return ((ix < iy)? x : x * zero);

	/*
	 * Set:
	 *	ny = true exponent of y
	 *	nd = true exponent of x minus true exponent of y
	 *	ix = normalized significand of x
	 *	iy = normalized significand of y
	 */
	ny = iy >> 52;
	k = ix >> 52;
	if (ny == 0) {
		/* y is subnormal, x could be normal or subnormal */
		ny = 1;
		while (iy < 0x0010000000000000ll) {
			ny -= 1;
			iy += iy;
		}
		nd = k - ny;
		if (k == 0) {
			nd += 1;
			while (ix < 0x0010000000000000ll) {
				nd -= 1;
				ix += ix;
			}
		} else {
			ix = 0x0010000000000000ll | (ix & 0x000fffffffffffffll);
		}
	} else {
		/* both x and y are normal */
		nd = k - ny;
		ix = 0x0010000000000000ll | (ix & 0x000fffffffffffffll);
		iy = 0x0010000000000000ll | (iy & 0x000fffffffffffffll);
	}

	/* perform fixed point mod */
	while (nd--) {
		iz = ix - iy;
		if (iz >= 0)
			ix = iz;
		ix += ix;
	}
	iz = ix - iy;
	if (iz >= 0)
		ix = iz;

	/* convert back to floating point and restore the sign */
	if (ix == 0ll)
		return (x * zero);
	while (ix < 0x0010000000000000ll) {
		ix += ix;
		ny -= 1;
	}
	while (ix > 0x0020000000000000ll) {	/* XXX can this ever happen? */
		ny += 1;
		ix >>= 1;
	}
	if (ny <= 0) {
		/* result is subnormal */
		k = -ny + 1;
		ix >>= k;
		*(long long *)&w = (hx & 0x8000000000000000ull) | ix;
		return (w);
	}
	*(long long *)&w = (hx & 0x8000000000000000ull) |
	    ((long long)ny << 52) | (ix & 0x000fffffffffffffll);
	return (w);
}
