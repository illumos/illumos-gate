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

#pragma weak __tanh = tanh

/* INDENT OFF */
/*
 * TANH(X)
 * RETURN THE HYPERBOLIC TANGENT OF X
 * code based on 4.3bsd
 * Modified by K.C. Ng for sun 4.0, Jan 31, 1987
 *
 * Method :
 *	1. reduce x to non-negative by tanh(-x) = - tanh(x).
 *	2.
 *	    0      <  x <=  1.e-10 :  tanh(x) := x
 *					          -expm1(-2x)
 *	    1.e-10 <  x <=  1      :  tanh(x) := --------------
 *					         expm1(-2x) + 2
 *							  2
 *	    1      <= x <=  22.0   :  tanh(x) := 1 -  ---------------
 *						      expm1(2x) + 2
 *	    22.0   <  x <= INF     :  tanh(x) := 1.
 *
 *	Note: 22 was chosen so that fl(1.0+2/(expm1(2*22)+2)) == 1.
 *
 * Special cases:
 *	tanh(NaN) is NaN;
 *	only tanh(0)=0 is exact for finite argument.
 */

#include "libm.h"
#include "libm_protos.h"
#include <math.h>

static const double
	one = 1.0,
	two = 2.0,
	small = 1.0e-10,
	big = 1.0e10;
/* INDENT ON */

double
tanh(double x) {
	double t, y, z;
	int signx;
	volatile double dummy __unused;

	if (isnan(x))
		return (x * x);	/* + -> * for Cheetah */
	signx = signbit(x);
	t = fabs(x);
	z = one;
	if (t <= 22.0) {
		if (t > one)
			z = one - two / (expm1(t + t) + two);
		else if (t > small) {
			y = expm1(-t - t);
			z = -y / (y + two);
		} else {
			/* raise the INEXACT flag for non-zero t */
			dummy = t + big;
#ifdef lint
			dummy = dummy;
#endif
			return (x);
		}
	} else if (!finite(t))
		return (copysign(1.0, x));
	else
		return (signx == 1 ? -z + small * small : z - small * small);

	return (signx == 1 ? -z : z);
}
