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

#pragma weak __ccosh = ccosh

/* INDENT OFF */
/*
 * dcomplex ccosh(dcomplex z);
 *
 *             z      -z       x                      -x
 *            e   +  e        e  (cos(y)+i*sin(y)) + e  (cos(-y)+i*sin(-y))
 * cosh z = -------------- =  ---------------------------------------------
 *                2                                2
 *                     x    -x                x    -x
 *           cos(y) ( e  + e  )  + i*sin(y) (e  - e   )
 *        = --------------------------------------------
 *                               2
 *
 *        =  cos(y) cosh(x)  + i sin(y) sinh(x)
 *
 * Implementation Note
 * -------------------
 *
 *             |x|    -|x|   |x|        -2|x|       -2|x|    -P-4
 * Note that  e   +- e    = e   ( 1 +- e     ). If e      < 2     , where
 *
 * P stands for the number of significant bits of the machine precision,
 *                                     |x|
 * then the result will be rounded to e   . Therefore, we have
 *
 *                 z
 *                e
 *     cosh z = -----  if |x| >= (P/2 + 2)*ln2
 *                2
 *
 * EXCEPTION (conform to ISO/IEC 9899:1999(E)):
 *      ccosh(0,0)=(1,0)
 *      ccosh(0,inf)=(NaN,+-0)
 *      ccosh(0,NaN)=(NaN,+-0)
 *      ccosh(x,inf) = (NaN,NaN) for finite non-zero x
 *      ccosh(x,NaN) = (NaN,NaN) for finite non-zero x
 *      ccosh(inf,0) = (inf, 0)
 *      ccosh(inf,y) = (inf*cos(y),inf*sin(y)) for finite non-zero y
 *      ccosh(inf,inf) = (+-inf,NaN)
 *      ccosh(inf,NaN) = (+inf,NaN)
 *      ccosh(NaN,0) = (NaN,+-0)
 *      ccosh(NaN,y) = (NaN,NaN) for non-zero y
 *      ccosh(NaN,NaN) = (NaN,NaN)
 */
/* INDENT ON */

#include "libm.h"		/* cosh/exp/fabs/scalbn/sinh/sincos/__k_cexp */
#include "complex_wrapper.h"

dcomplex
ccosh(dcomplex z) {
	double t, x, y, S, C;
	int hx, ix, lx, hy, iy, ly, n;
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

	(void) sincos(y, &S, &C);
	if (ix >= 0x403c0000) {	/* |x| > 28 = prec/2 (14,28,34,60) */
		if (ix >= 0x40862E42) {	/* |x| > 709.78... ~ log(2**1024) */
			if (ix >= 0x7ff00000) {	/* |x| is inf or NaN */
				if ((iy | ly) == 0) {
					D_RE(ans) = x;
					D_IM(ans) = y;
				} else if (iy >= 0x7ff00000) {
					D_RE(ans) = x;
					D_IM(ans) = x - y;
				} else {
					D_RE(ans) = C * x;
					D_IM(ans) = S * x;
				}
			} else {
				t = __k_cexp(x, &n);
						/* return exp(x)=t*2**n */
				D_RE(ans) = scalbn(C * t, n - 1);
				D_IM(ans) = scalbn(S * t, n - 1);
			}
		} else {
			t = exp(x) * 0.5;
			D_RE(ans) = C * t;
			D_IM(ans) = S * t;
		}
	} else {
		if ((ix | lx) == 0) {	/* x = 0, return (C,0) */
			D_RE(ans) = C;
			D_IM(ans) = 0.0;
		} else {
			D_RE(ans) = C * cosh(x);
			D_IM(ans) = S * sinh(x);
		}
	}
	if ((hx ^ hy) < 0)
		D_IM(ans) = -D_IM(ans);
	return (ans);
}
