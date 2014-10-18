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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak ccoshf = __ccoshf

#include "libm.h"
#include "complex_wrapper.h"

#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

static const float zero = 0.0F, half = 0.5F;

fcomplex
ccoshf(fcomplex z) {
	float		t, x, y, S, C;
	double		w;
	int		hx, ix, hy, iy, n;
	fcomplex	ans;

	x = F_RE(z);
	y = F_IM(z);
	hx = THE_WORD(x);
	ix = hx & 0x7fffffff;
	hy = THE_WORD(y);
	iy = hy & 0x7fffffff;
	x = fabsf(x);
	y = fabsf(y);

	sincosf(y, &S, &C);
	if (ix >= 0x41600000) {	/* |x| > 14 = prec/2 (14,28,34,60) */
		if (ix >= 0x42B171AA) {	/* |x| > 88.722... ~ log(2**128) */
			if (ix >= 0x7f800000) {	/* |x| is inf or NaN */
				if (iy == 0) {
					F_RE(ans) = x;
					F_IM(ans) = y;
				} else if (iy >= 0x7f800000) {
					F_RE(ans) = x;
					F_IM(ans) = x - y;
				} else {
					F_RE(ans) = C * x;
					F_IM(ans) = S * x;
				}
			} else {
#if defined(__i386) && !defined(__amd64)
				int	rp = __swapRP(fp_extended);
#endif
				/* return (C, S) * exp(x) / 2 */
				w = __k_cexp((double)x, &n);
				F_RE(ans) = (float)scalbn(C * w, n - 1);
				F_IM(ans) = (float)scalbn(S * w, n - 1);
#if defined(__i386) && !defined(__amd64)
				if (rp != fp_extended)
					(void) __swapRP(rp);
#endif
			}
		} else {
			t = expf(x) * half;
			F_RE(ans) = C * t;
			F_IM(ans) = S * t;
		}
	} else {
		if (ix == 0) {	/* x = 0, return (C,0) */
			F_RE(ans) = C;
			F_IM(ans) = zero;
		} else {
			F_RE(ans) = C * coshf(x);
			F_IM(ans) = S * sinhf(x);
		}
	}
	if ((hx ^ hy) < 0)
		F_IM(ans) = -F_IM(ans);
	return (ans);
}
