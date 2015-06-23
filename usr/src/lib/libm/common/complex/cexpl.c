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

#pragma weak __cexpl = cexpl

#include "libm.h"		/* expl/isinfl/iszerol/scalbnl/sincosl */
#include "complex_wrapper.h"

extern int isinfl(long double);
extern int iszerol(long double);

/* INDENT OFF */
static const long double zero = 0.0L;
/* INDENT ON */

ldcomplex
cexpl(ldcomplex z) {
	ldcomplex ans;
	long double x, y, t, c, s;
	int n, ix, iy, hx, hy;

	x = LD_RE(z);
	y = LD_IM(z);
	hx = HI_XWORD(x);
	hy = HI_XWORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	if (iszerol(y)) {	/* y = 0 */
		LD_RE(ans) = expl(x);
		LD_IM(ans) = y;
	} else if (isinfl(x)) {	/* x is +-inf */
		if (hx < 0) {
			if (iy >= 0x7fff0000) {
				LD_RE(ans) = zero;
				LD_IM(ans) = zero;
			} else {
				sincosl(y, &s, &c);
				LD_RE(ans) = zero * c;
				LD_IM(ans) = zero * s;
			}
		} else {
			if (iy >= 0x7fff0000) {
				LD_RE(ans) = x;
				LD_IM(ans) = y - y;
			} else {
				(void) sincosl(y, &s, &c);
				LD_RE(ans) = x * c;
				LD_IM(ans) = x * s;
			}
		}
	} else {
		(void) sincosl(y, &s, &c);
		if (ix >= 0x400C62E4) {	/* |x| > 11356.52... ~ log(2**16384) */
			t = __k_cexpl(x, &n);
			LD_RE(ans) = scalbnl(t * c, n);
			LD_IM(ans) = scalbnl(t * s, n);
		} else {
			t = expl(x);
			LD_RE(ans) = t * c;
			LD_IM(ans) = t * s;
		}
	}
	return (ans);
}
