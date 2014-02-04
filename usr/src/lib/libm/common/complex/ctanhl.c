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

#pragma weak ctanhl = __ctanhl

#include "libm.h"	/* expl/expm1l/fabsl/isinfl/isnanl/sincosl/sinl/tanhl */
#include "complex_wrapper.h"
#include "longdouble.h"

/* INDENT OFF */
static const long double four = 4.0L, two = 2.0L, one = 1.0L, zero = 0.0L;
/* INDENT ON */

ldcomplex
ctanhl(ldcomplex z) {
	long double r, u, v, t, x, y, S, C;
	int hx, ix, hy, iy;
	ldcomplex ans;

	x = LD_RE(z);
	y = LD_IM(z);
	hx = HI_XWORD(x);
	ix = hx & 0x7fffffff;
	hy = HI_XWORD(y);
	iy = hy & 0x7fffffff;
	x = fabsl(x);
	y = fabsl(y);

	if (y == zero) {	/* ctanh(x,0) = (x,0) for x = 0 or NaN */
		LD_RE(ans) = tanhl(x);
		LD_IM(ans) = zero;
	} else if (iy >= 0x7fff0000) {	/* y is inf or NaN */
		if (ix < 0x7fff0000)	/* catanh(finite x,inf/nan) is nan */
			LD_RE(ans) = LD_IM(ans) = y - y;
		else if (isinfl(x)) {	/* x is inf */
			LD_RE(ans) = one;
			LD_IM(ans) = zero;
		} else {
			LD_RE(ans) = x + y;
			LD_IM(ans) = y - y;
		}
	} else if (ix >= 0x4004e000) {
		/* INDENT OFF */
		/*
		 * |x| > 60 = prec/2 (14,28,34,60)
		 * ctanh z ~ 1 + i (sin2y)/(exp(2x))
		 */
		/* INDENT ON */
		LD_RE(ans) = one;
		if (iy < 0x7ffe0000)	/* t = sin(2y) */
			S = sinl(y + y);
		else {
			(void) sincosl(y, &S, &C);
			S = (S + S) * C;
		}
		if (ix >= 0x7ffe0000) {	/* |x| > max/2 */
			if (ix >= 0x7fff0000) {	/* |x| is inf or NaN */
				if (isnanl(x))	/* x is NaN */
					LD_RE(ans) = LD_IM(ans) = x + y;
				else
					LD_IM(ans) = zero * S;	/* x is inf */
			} else
				LD_IM(ans) = S * expl(-x);	/* underflow */
		} else
			LD_IM(ans) = (S + S) * expl(-(x + x));
							/* 2 sin 2y / exp(2x) */
	} else {
		/* INDENT OFF */
		/*
		 *                        t*t+2t
		 *    ctanh z = ---------------------------
		 *               t*t+[4(t+1)(cos y)](cos y)
		 *
		 *                  [4(t+1)(cos y)]*(sin y)
		 *              i --------------------------
		 *                t*t+[4(t+1)(cos y)](cos y)
		 */
		/* INDENT ON */
		sincosl(y, &S, &C);
		t = expm1l(x + x);
		r = (four * C) * (t + one);
		u = t * t;
		v = one / (u + r * C);
		LD_RE(ans) = (u + two * t) * v;
		LD_IM(ans) = (r * S) * v;
	}
	if (hx < 0)
		LD_RE(ans) = -LD_RE(ans);
	if (hy < 0)
		LD_IM(ans) = -LD_IM(ans);
	return (ans);
}
