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

#pragma weak ccoshl = __ccoshl

#include "libm.h"	/* coshl/expl/fabsl/scalbnl/sincosl/sinhl/__k_cexpl */
#include "complex_wrapper.h"

/* INDENT OFF */
static const long double zero = 0.0L, half = 0.5L;
/* INDENT ON */

ldcomplex
ccoshl(ldcomplex z) {
	long double t, x, y, S, C;
	int hx, ix, hy, iy, n;
	ldcomplex ans;

	x = LD_RE(z);
	y = LD_IM(z);
	hx = HI_XWORD(x);
	ix = hx & 0x7fffffff;
	hy = HI_XWORD(y);
	iy = hy & 0x7fffffff;
	x = fabsl(x);
	y = fabsl(y);

	(void) sincosl(y, &S, &C);
	if (ix >= 0x4004e000) {	/* |x| > 60 = prec/2 (14,28,34,60) */
		if (ix >= 0x400C62E4) {	/* |x| > 11356.52... ~ log(2**16384) */
			if (ix >= 0x7fff0000) {	/* |x| is inf or NaN */
				if (y == zero) {
					LD_RE(ans) = x;
					LD_IM(ans) = y;
				} else if (iy >= 0x7fff0000) {
					LD_RE(ans) = x;
					LD_IM(ans) = x - y;
				} else {
					LD_RE(ans) = C * x;
					LD_IM(ans) = S * x;
				}
			} else {
				t = __k_cexpl(x, &n);
						/* return exp(x)=t*2**n */
				LD_RE(ans) = scalbnl(C * t, n - 1);
				LD_IM(ans) = scalbnl(S * t, n - 1);
			}
		} else {
			t = expl(x) * half;
			LD_RE(ans) = C * t;
			LD_IM(ans) = S * t;
		}
	} else {
		if (x == zero) {	/* x = 0, return (C,0) */
			LD_RE(ans) = C;
			LD_IM(ans) = zero;
		} else {
			LD_RE(ans) = C * coshl(x);
			LD_IM(ans) = S * sinhl(x);
		}
	}
	if ((hx ^ hy) < 0)
		LD_IM(ans) = -LD_IM(ans);
	return (ans);
}
