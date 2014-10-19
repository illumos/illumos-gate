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

#pragma weak cexp = __cexp

/* INDENT OFF */
/*
 * dcomplex cexp(dcomplex z);
 *
 *  x+iy    x
 * e     = e  (cos(y)+i*sin(y))
 *
 * Over/underflow issue
 * --------------------
 * exp(x) may be huge but cos(y) or sin(y) may be tiny. So we use
 * function __k_cexp(x,&n) to return exp(x) = __k_cexp(x,&n)*2**n.
 * Thus if exp(x+iy) = A + Bi and t = __k_cexp(x,&n), then
 *         A = t*cos(y)*2**n,   B = t*sin(y)*2**n
 *
 * Purge off all exceptional arguments:
 *	(x,0) --> (exp(x),0)         for all x, include inf and NaN
 *	(+inf, y) --> (+inf, NaN)    for inf, nan
 *	(-inf, y) --> (+-0, +-0)     for y = inf, nan
 *	(x,+-inf/NaN) --> (NaN,NaN)  for finite x
 * For all other cases, return
 *	(x,y) --> exp(x)*cos(y)+i*exp(x)*sin(y))
 *
 * Algorithm for out of range x and finite y
 *	1. compute exp(x) in factor form (t=__k_cexp(x,&n))*2**n
 *	2. compute sincos(y,&s,&c)
 *	3. compute t*s+i*(t*c), then scale back to 2**n and return.
 */
/* INDENT ON */

#include "libm.h"		/* exp/scalbn/sincos/__k_cexp */
#include "complex_wrapper.h"

static const double zero = 0.0;

dcomplex
cexp(dcomplex z) {
	dcomplex ans;
	double x, y, t, c, s;
	int n, ix, iy, hx, hy, lx, ly;

	x = D_RE(z);
	y = D_IM(z);
	hx = HI_WORD(x);
	lx = LO_WORD(x);
	hy = HI_WORD(y);
	ly = LO_WORD(y);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	if ((iy | ly) == 0) {	/* y = 0 */
		D_RE(ans) = exp(x);
		D_IM(ans) = y;
	} else if (ISINF(ix, lx)) {	/* x is +-inf */
		if (hx < 0) {
			if (iy >= 0x7ff00000) {
				D_RE(ans) = zero;
				D_IM(ans) = zero;
			} else {
				sincos(y, &s, &c);
				D_RE(ans) = zero * c;
				D_IM(ans) = zero * s;
			}
		} else {
			if (iy >= 0x7ff00000) {
				D_RE(ans) = x;
				D_IM(ans) = y - y;
			} else {
				(void) sincos(y, &s, &c);
				D_RE(ans) = x * c;
				D_IM(ans) = x * s;
			}
		}
	} else {
		(void) sincos(y, &s, &c);
		if (ix >= 0x40862E42) {	/* |x| > 709.78... ~ log(2**1024) */
			t = __k_cexp(x, &n);
			D_RE(ans) = scalbn(t * c, n);
			D_IM(ans) = scalbn(t * s, n);
		} else {
			t = exp(x);
			D_RE(ans) = t * c;
			D_IM(ans) = t * s;
		}
	}
	return (ans);
}
