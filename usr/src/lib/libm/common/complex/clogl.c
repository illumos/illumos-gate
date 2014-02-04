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

#pragma weak clogl = __clogl

#include "libm.h"	/* atan2l/fabsl/isinfl/log1pl/logl/__k_clog_rl */
#include "complex_wrapper.h"
#include "longdouble.h"

#if defined(__sparc)
#define	SIGP7	120
#define	HSIGP7	60
#elif defined(__x86)
#define	SIGP7	70
#define	HSIGP7	35
#endif

/* INDENT OFF */
static const long double zero = 0.0L, half = 0.5L, one = 1.0L;
/* INDENT ON */

ldcomplex
clogl(ldcomplex z) {
	ldcomplex ans;
	long double x, y, t, ax, ay;
	int n, ix, iy, hx, hy;

	x = LD_RE(z);
	y = LD_IM(z);
	hx = HI_XWORD(x);
	hy = HI_XWORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	ay = fabsl(y);
	ax = fabsl(x);
	LD_IM(ans) = atan2l(y, x);
	if (ix < iy || (ix == iy && ix < 0x7fff0000 && ax < ay)) {
			/* swap x and y to force ax>=ay */
		t = ax;
		ax = ay;
		ay = t;
		n = ix, ix = iy;
		iy = n;
	}
	n = (ix - iy) >> 16;
	if (ix >= 0x7fff0000) {	/* x or y is Inf or NaN */
		if (isinfl(ax))
			LD_RE(ans) = ax;
		else if (isinfl(ay))
			LD_RE(ans) = ay;
		else
			LD_RE(ans) = ax + ay;
	} else if (ay == zero)
		LD_RE(ans) = logl(ax);
	else if (((0x3fffffff - ix) ^ (ix - 0x3ffe0000)) >= 0) {
							/* 0.5 <= x < 2 */
		if (ix >= 0x3fff0000) {
			if (ax == one)
				LD_RE(ans) = half * log1pl(ay * ay);
			else if (n >= SIGP7)
				LD_RE(ans) = logl(ax);
			else
				LD_RE(ans) = half * (log1pl(ay * ay + (ax -
					one) * (ax + one)));
		} else if (n >= SIGP7)
			LD_RE(ans) = logl(ax);
		else
			LD_RE(ans) = __k_clog_rl(x, y, &t);
	} else if (n >= HSIGP7)
		LD_RE(ans) = logl(ax);
	else if (ix < 0x5f3f0000 && iy >= 0x20bf0000)
		/* 2**-8000 < y < x < 2**8000 */
		LD_RE(ans) = half * logl(ax * ax + ay * ay);
	else {
		t = ay / ax;
		LD_RE(ans) = logl(ax) + half * log1pl(t * t);
	}
	return (ans);
}
