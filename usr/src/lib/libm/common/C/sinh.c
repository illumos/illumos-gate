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

#pragma weak __sinh = sinh

/* INDENT OFF */
/*
 * sinh(x)
 * Code originated from 4.3bsd.
 * Modified by K.C. Ng for SUN 4.0 libm.
 * Method :
 *	1. reduce x to non-negative by sinh(-x) = - sinh(x).
 *	2.
 *
 *                                   expm1(x) + expm1(x)/(expm1(x)+1)
 *   0 <= x <= lnovft   : sinh(x) := --------------------------------
 *								       2
 *  lnovft <= x <  INF  : sinh(x) := exp(x-1024*ln2)*2**1023
 *
 *
 * Special cases:
 *	sinh(x) is x if x is +INF, -INF, or NaN.
 *	only sinh(0)=0 is exact for finite argument.
 *
 */
/* INDENT ON */

#include "libm.h"

static const double
	ln2hi = 6.93147180369123816490e-01,
	ln2lo = 1.90821492927058770002e-10,
	lnovft = 7.09782712893383973096e+02;

double
sinh(double x) {
	double	ox, r, t;

	ox = x;
	r = fabs(x);
	if (!finite(x))
		return (x * r);
	if (r < lnovft) {
		t = expm1(r);
		r = copysign((t + t / (1.0 + t)) * 0.5, x);
	} else {
		if (r < 1000.0)
			x = copysign(exp((r - 1024 * ln2hi) - 1024 * ln2lo), x);
		r = scalbn(x, 1023);
	}
	if (!finite(r))
		r = _SVID_libm_err(ox, ox, 25);
	return (r);
}
