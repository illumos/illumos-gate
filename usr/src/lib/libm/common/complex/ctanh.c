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

#pragma weak __ctanh = ctanh

/* INDENT OFF */
/*
 * dcomplex ctanh(dcomplex z);
 *
 *            tanh x  + i tan y      sinh 2x  +  i sin 2y
 * ctanh z = --------------------- = --------------------
 *           1 + i tanh(x)tan(y)       cosh 2x + cos 2y
 *
 * For |x| >= prec/2 (14,28,34,60 for single, double, double extended, quad),
 * we use
 *
 *                         1   2x                              2 sin 2y
 *    cosh 2x = sinh 2x = --- e    and hence  ctanh z = 1 + i -----------;
 *                         2                                       2x
 *                                                                e
 *
 * otherwise, to avoid cancellation, for |x| < prec/2,
 *                              2x     2
 *                            (e   - 1)        2       2
 *    cosh 2x + cos 2y = 1 + ------------ + cos y - sin y
 *                                 2x
 *                              2 e
 *
 *                        1    2x     2  -2x         2
 *                     = --- (e   - 1)  e     + 2 cos y
 *                        2
 * and
 *
 *                  [            2x      ]
 *               1  [  2x       e   - 1  ]
 *    sinh 2x = --- [ e  - 1 + --------- ]
 *               2  [               2x   ]
 *                  [              e     ]
 *                                             2x
 * Implementation notes:  let t = expm1(2x) = e   - 1, then
 *
 *                     1    [  t*t         2  ]              1    [      t  ]
 * cosh 2x + cos 2y = --- * [ ----- + 4 cos y ];  sinh 2x = --- * [ t + --- ]
 *                     2    [  t+1            ]              2    [     t+1 ]
 *
 * Hence,
 *
 *
 *                        t*t+2t                  [4(t+1)(cos y)]*(sin y)
 *    ctanh z = --------------------------- + i --------------------------
 *               t*t+[4(t+1)(cos y)](cos y)     t*t+[4(t+1)(cos y)](cos y)
 *
 * EXCEPTION (conform to ISO/IEC 9899:1999(E)):
 *      ctanh(0,0)=(0,0)
 *      ctanh(x,inf) = (NaN,NaN) for finite x
 *      ctanh(x,NaN) = (NaN,NaN) for finite x
 *      ctanh(inf,y) = 1+ i*0*sin(2y) for positive-signed finite y
 *      ctanh(inf,inf) = (1, +-0)
 *      ctanh(inf,NaN) = (1, +-0)
 *      ctanh(NaN,0) = (NaN,0)
 *      ctanh(NaN,y) = (NaN,NaN) for non-zero y
 *      ctanh(NaN,NaN) = (NaN,NaN)
 */
/* INDENT ON */

#include "libm.h"		/* exp/expm1/fabs/sin/tanh/sincos */
#include "complex_wrapper.h"

static const double four = 4.0, two = 2.0, one = 1.0, zero = 0.0;

dcomplex
ctanh(dcomplex z) {
	double t, r, v, u, x, y, S, C;
	int hx, ix, lx, hy, iy, ly;
	dcomplex ans;

	x = D_RE(z);
	y = D_IM(z);
	hx = HI_WORD(x);
	lx = LO_WORD(x);
	ix = hx & 0x7fffffff;
	hy = HI_WORD(y);
	ly = LO_WORD(y);
	iy = hy & 0x7fffffff;
	x = fabs(x);
	y = fabs(y);

	if ((iy | ly) == 0) {	/* ctanh(x,0) = (x,0) for x = 0 or NaN */
		D_RE(ans) = tanh(x);
		D_IM(ans) = zero;
	} else if (iy >= 0x7ff00000) {	/* y is inf or NaN */
		if (ix < 0x7ff00000)	/* catanh(finite x,inf/nan) is nan */
			D_RE(ans) = D_IM(ans) = y - y;
		else if (((ix - 0x7ff00000) | lx) == 0) {	/* x is inf */
			D_RE(ans) = one;
			D_IM(ans) = zero;
		} else {
			D_RE(ans) = x + y;
			D_IM(ans) = y - y;
		}
	} else if (ix >= 0x403c0000) {
		/*
		 * |x| > 28 = prec/2 (14,28,34,60)
		 * ctanh z ~ 1 + i (sin2y)/(exp(2x))
		 */
		D_RE(ans) = one;
		if (iy < 0x7fe00000)	/* t = sin(2y) */
			S = sin(y + y);
		else {
			(void) sincos(y, &S, &C);
			S = (S + S) * C;
		}
		if (ix >= 0x7fe00000) {	/* |x| > max/2 */
			if (ix >= 0x7ff00000) {	/* |x| is inf or NaN */
				if (((ix - 0x7ff00000) | lx) != 0)
					D_RE(ans) = D_IM(ans) = x + y;
								/* x is NaN */
				else
					D_IM(ans) = zero * S;	/* x is inf */
			} else
				D_IM(ans) = S * exp(-x);	/* underflow */
		} else
			D_IM(ans) = (S + S) * exp(-(x + x));
							/* 2 sin 2y / exp(2x) */
	} else {
		/* INDENT OFF */
		/*
		 *                        t*t+2t
		 *    ctanh z = --------------------------- +
		 *               t*t+[4(t+1)(cos y)](cos y)
		 *
		 *                  [4(t+1)(cos y)]*(sin y)
		 *              i --------------------------
		 *                t*t+[4(t+1)(cos y)](cos y)
		 */
		/* INDENT ON */
		(void) sincos(y, &S, &C);
		t = expm1(x + x);
		r = (four * C) * (t + one);
		u = t * t;
		v = one / (u + r * C);
		D_RE(ans) = (u + two * t) * v;
		D_IM(ans) = (r * S) * v;
	}
	if (hx < 0)
		D_RE(ans) = -D_RE(ans);
	if (hy < 0)
		D_IM(ans) = -D_IM(ans);
	return (ans);
}
