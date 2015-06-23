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

#pragma weak __sinhl = sinhl

#include "libm.h"
#include "longdouble.h"

/*
 * sinhl(X)
 * RETURN THE HYPERBOLIC SINE OF X
 *
 * Method :
 *	1. reduce x to non-negative by sinhl(-x) = - sinhl(x).
 *	2.
 *
 *					     expm1l(x) + expm1l(x)/(expm1l(x)+1)
 *	0 <= x <= lnovft	: sinhl(x) := --------------------------------
 *							     2
 *
 *     lnovft <= x <  INF	: sinhl(x) := expl(x-MEP1*ln2)*2**ME
 *
 * here
 *	lnovft:		logrithm of the overflow threshold
 *			= MEP1*ln2 chopped to machine precision.
 *	ME		maximum exponent
 *	MEP1		maximum exponent plus 1
 *
 * Special cases:
 *	sinhl(x) is x if x is +INF, -INF, or NaN.
 *	only sinhl(0)=0 is exact for finite argument.
 *
 */

#define	ME	16383
#define	MEP1	16384
#define	LNOVFT	1.135652340629414394949193107797076342845e+4L
		/* last 32 bits of LN2HI is zero */
#define	LN2HI   6.931471805599453094172319547495844850203e-0001L
#define	LN2LO   1.667085920830552208890449330400379754169e-0025L

static const long double
	half	= 0.5L,
	one	= 1.0L,
	ln2hi	= LN2HI,
	ln2lo	= LN2LO,
	lnovftL	= LNOVFT;

long double
sinhl(long double x) {
	long double r, t;

	if (!finitel(x))
		return (x + x);	/* sinh of NaN or +-INF is itself */
	r = fabsl(x);
	if (r < lnovftL) {
		t = expm1l(r);
		r = copysignl((t + t / (one + t)) * half, x);
	} else {
		r = copysignl(expl((r - MEP1 * ln2hi) - MEP1 * ln2lo), x);
		r = scalbnl(r, ME);
	}
	return (r);
}
