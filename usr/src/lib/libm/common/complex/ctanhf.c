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

#pragma weak ctanhf = __ctanhf

#include "libm.h"		/* expf/expm1f/fabsf/sincosf/sinf/tanhf */
#include "complex_wrapper.h"

/* INDENT OFF */
static const float four = 4.0F, two = 2.0F, one = 1.0F, zero = 0.0F;
/* INDENT ON */

fcomplex
ctanhf(fcomplex z) {
	float r, u, v, t, x, y, S, C;
	int hx, ix, hy, iy;
	fcomplex ans;

	x = F_RE(z);
	y = F_IM(z);
	hx = THE_WORD(x);
	ix = hx & 0x7fffffff;
	hy = THE_WORD(y);
	iy = hy & 0x7fffffff;
	x = fabsf(x);
	y = fabsf(y);

	if (iy == 0) {		/* ctanh(x,0) = (x,0) for x = 0 or NaN */
		F_RE(ans) = tanhf(x);
		F_IM(ans) = zero;
	} else if (iy >= 0x7f800000) {	/* y is inf or NaN */
		if (ix < 0x7f800000)	/* catanh(finite x,inf/nan) is nan */
			F_RE(ans) = F_IM(ans) = y - y;
		else if (ix == 0x7f800000) {	/* x is inf */
			F_RE(ans) = one;
			F_IM(ans) = zero;
		} else {
			F_RE(ans) = x + y;
			F_IM(ans) = y - y;
		}
	} else if (ix >= 0x41600000) {
		/*
		 * |x| > 14 = prec/2 (14,28,34,60)
		 * ctanh z ~ 1 + i (sin2y)/(exp(2x))
		 */
		F_RE(ans) = one;
		if (iy < 0x7f000000)	/* t = sin(2y) */
			S = sinf(y + y);
		else {
			(void) sincosf(y, &S, &C);
			S = (S + S) * C;
		}
		if (ix >= 0x7f000000) {	/* |x| > max/2 */
			if (ix >= 0x7f800000) {	/* |x| is inf or NaN */
				if (ix > 0x7f800000)	/* x is NaN */
					F_RE(ans) = F_IM(ans) = x + y;
				else
					F_IM(ans) = zero * S;	/* x is inf */
			} else
				F_IM(ans) = S * expf(-x);	/* underflow */
		} else
			F_IM(ans) = (S + S) * expf(-(x + x));
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
		(void) sincosf(y, &S, &C);
		t = expm1f(x + x);
		r = (four * C) * (t + one);
		u = t * t;
		v = one / (u + r * C);
		F_RE(ans) = (u + two * t) * v;
		F_IM(ans) = (r * S) * v;
	}
	if (hx < 0)
		F_RE(ans) = -F_RE(ans);
	if (hy < 0)
		F_IM(ans) = -F_IM(ans);
	return (ans);
}
