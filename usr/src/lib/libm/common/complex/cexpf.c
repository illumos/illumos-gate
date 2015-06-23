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

#pragma weak __cexpf = cexpf

#include "libm.h"
#include "complex_wrapper.h"

#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

static const float zero = 0.0F;

fcomplex
cexpf(fcomplex z) {
	fcomplex	ans;
	float		x, y, c, s;
	double		t;
	int		n, ix, iy, hx, hy;

	x = F_RE(z);
	y = F_IM(z);
	hx = THE_WORD(x);
	hy = THE_WORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	if (iy == 0) {		/* y = 0 */
		F_RE(ans) = expf(x);
		F_IM(ans) = y;
	} else if (ix == 0x7f800000) {	/* x is +-inf */
		if (hx < 0) {
			if (iy >= 0x7f800000) {
				F_RE(ans) = zero;
				F_IM(ans) = zero;
			} else {
				sincosf(y, &s, &c);
				F_RE(ans) = zero * c;
				F_IM(ans) = zero * s;
			}
		} else {
			if (iy >= 0x7f800000) {
				F_RE(ans) = x;
				F_IM(ans) = y - y;
			} else {
				sincosf(y, &s, &c);
				F_RE(ans) = x * c;
				F_IM(ans) = x * s;
			}
		}
	} else {
		sincosf(y, &s, &c);
		if (ix >= 0x42B171AA) {	/* |x| > 88.722... ~ log(2**128) */
#if defined(__i386) && !defined(__amd64)
			int	rp = __swapRP(fp_extended);
#endif
			t = __k_cexp(x, &n);
			F_RE(ans) = (float)scalbn(t * (double)c, n);
			F_IM(ans) = (float)scalbn(t * (double)s, n);
#if defined(__i386) && !defined(__amd64)
			if (rp != fp_extended)
				(void) __swapRP(rp);
#endif
		} else {
			t = expf(x);
			F_RE(ans) = t * c;
			F_IM(ans) = t * s;
		}
	}
	return (ans);
}
