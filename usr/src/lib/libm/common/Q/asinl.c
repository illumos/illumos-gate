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

#pragma weak __asinl = asinl

/*
 *	asinl(x) = atan2l(x,sqrt(1-x*x));
 *
 * For better accuracy, 1-x*x is computed as follows
 *	1-x*x                     if x <  0.5,
 *	2*(1-|x|)-(1-|x|)*(1-|x|) if x >= 0.5.
 *
 * Special cases:
 *	if x is NaN, return x itself;
 *	if |x|>1, return NaN with invalid signal.
 */

#include "libm.h"

static const long double zero = 0.0L, small = 1.0e-20L, half = 0.5L, one = 1.0L;
#ifndef lint
static const long double big = 1.0e+20L;
#endif

long double
asinl(long double x) {
	long double t, w;
	volatile long double dummy;

	w = fabsl(x);
	if (isnanl(x))
		return (x + x);
	else if (w <= half) {
		if (w < small) {
#ifndef lint
			dummy = w + big;
							/* inexact if w != 0 */
#endif
			return (x);
		} else
			return (atanl(x / sqrtl(one - x * x)));
	} else if (w < one) {
		t = one - w;
		w = t + t;
		return (atanl(x / sqrtl(w - t * t)));
	} else if (w == one)
		return (atan2l(x, zero));	/* asin(+-1) =  +- PI/2 */
	else
		return (zero / zero);		/* |x| > 1: invalid */
}
