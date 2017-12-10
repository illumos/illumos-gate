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

#pragma weak __tanhl = tanhl

/*
 * tanhl(x) returns the hyperbolic tangent of x
 *
 * Method :
 *	1. reduce x to non-negative:  tanhl(-x) = - tanhl(x).
 *	2.
 *	  0      <  x <=  small    :  tanhl(x) := x
 *					          -expm1l(-2x)
 *	  small  <  x <=  1        :  tanhl(x) := --------------
 *					         expm1l(-2x) + 2
 *							  2
 *	  1      <= x <= threshold :  tanhl(x) := 1 -  ---------------
 *						      expm1l(2x) + 2
 *     threshold <  x <= INF       :  tanhl(x) := 1.
 *
 * where
 *	single : 	small = 1.e-5		threshold = 11.0
 *	double : 	small = 1.e-10		threshold = 22.0
 *	quad   : 	small = 1.e-20		threshold = 45.0
 *
 * Note: threshold was chosen so that
 *		fl(1.0+2/(expm1(2*threshold)+2)) == 1.
 *
 * Special cases:
 *	tanhl(NaN) is NaN;
 *	only tanhl(0.0)=0.0 is exact for finite argument.
 */

#include "libm.h"
#include "longdouble.h"

static const long double small = 1.0e-20L, one = 1.0, two = 2.0,
#ifndef lint
	big = 1.0e+20L,
#endif
	threshold = 45.0L;

long double
tanhl(long double x) {
	long double t, y, z;
	int signx;
#ifndef lint
	volatile long double dummy __unused;
#endif

	if (isnanl(x))
		return (x + x);		/* x is NaN */
	signx = signbitl(x);
	t = fabsl(x);
	z = one;
	if (t <= threshold) {
		if (t > one)
			z = one - two / (expm1l(t + t) + two);
		else if (t > small) {
			y = expm1l(-t - t);
			z = -y / (y + two);
		} else {
#ifndef lint
			dummy = t + big;
							/* inexact if t != 0 */
#endif
			return (x);
		}
	} else if (!finitel(t))
		return (copysignl(one, x));
	else
		return (signx ? -z + small * small : z - small * small);
	return (signx ? -z : z);
}
