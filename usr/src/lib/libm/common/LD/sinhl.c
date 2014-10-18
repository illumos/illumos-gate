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

#pragma weak sinhl = __sinhl

#include "libm.h"
#include "longdouble.h"

/* SINH(X)
 * RETURN THE HYPERBOLIC SINE OF X
 *
 * Method :
 *	1. reduce x to non-negative by SINH(-x) = - SINH(x).
 *	2. 
 *
 *	                                      EXPM1(x) + EXPM1(x)/(EXPM1(x)+1)
 *	    0 <= x <= lnovft     : SINH(x) := --------------------------------
 *			       		                      2
 *
 *     lnovft <= x <  INF	 : SINH(x) := EXP(x-MEP1*ln2)*2**ME
 *	
 * here
 *	lnovft		logarithm of the overflow threshold
 *			= MEP1*ln2 chopped to machine precision.
 *	ME		maximum exponent
 *	MEP1		maximum exponent plus 1
 *
 * Special cases:
 *	SINH(x) is x if x is +INF, -INF, or NaN.
 *	only SINH(0)=0 is exact for finite argument.
 *
 */

static const long double C[] = {
	0.5L,
	1.0L,
	1.135652340629414394879149e+04L,
	7.004447686242549087858985e-16L
};

#define	half	C[0]
#define	one	C[1]
#define	lnovft	C[2]
#define	lnovlo	C[3]

long double
sinhl(long double x)
{
	long double	r, t;

	if (!finitel(x))
		return (x + x);	/* x is INF or NaN */
	r = fabsl(x);
	if (r < lnovft) {
		t = expm1l(r);
		r = copysignl((t + t / (one + t)) * half, x);
	} else {
		r = copysignl(expl((r - lnovft) - lnovlo), x);
		r = scalbnl(r, 16383);
	}
	return (r);
}
