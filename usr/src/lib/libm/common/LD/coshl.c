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

#if defined(ELFOBJ)
#pragma weak coshl = __coshl
#endif

#include "libm.h"
#include "longdouble.h"

/*
 * COSH(X)
 * RETURN THE HYPERBOLIC COSINE OF X
 *
 * Method :
 *	1. Replace x by |x| (COSH(x) = COSH(-x)).
 *	2.
 *		                                        [ EXP(x) - 1 ]^2
 *	    0        <= x <= 0.3465  :  COSH(x) := 1 + -------------------
 *							   2*EXP(x)
 *
 *		                                   EXP(x) +  1/EXP(x)
 *	    0.3465   <= x <= thresh  :  COSH(x) := -------------------
 *							   2
 *	    thresh   <= x <= lnovft  :  COSH(x) := EXP(x)/2
 *	    lnovft   <= x <  INF     :  COSH(x) := SCALBN(EXP(x-MEP1*ln2),ME)
 *
 *
 * here
 *	0.3465		a number that is near one half of ln2.
 *	thresh		a number such that
 *				EXP(thresh)+EXP(-thresh)=EXP(thresh)
 *	lnovft		logarithm of the overflow threshold
 *			= MEP1*ln2 chopped to machine precision.
 *	ME		maximum exponent
 *	MEP1		maximum exponent plus 1
 *
 * Special cases:
 *	COSH(x) is |x| if x is +INF, -INF, or NaN.
 *	only COSH(0)=1 is exact for finite x.
 */

static const long double C[] = {
	0.5L,
	1.0L,
	0.3465L,
	45.0L,
	1.135652340629414394879149e+04L,
	7.004447686242549087858985e-16L,
	2.710505431213761085018632e-20L,		/* 2^-65 */
};

#define	half	C[0]
#define	one	C[1]
#define	thr1	C[2]
#define	thr2	C[3]
#define	lnovft	C[4]
#define	lnovlo	C[5]
#define	tinyl	C[6]

long double
coshl(long double x) {
	long double w, t;

	w = fabsl(x);
	if (!finitel(w))
		return (w + w);	/* x is INF or NaN */
	if (w < thr1) {
		if (w < tinyl)
			return (one + w);	/* inexact+directed rounding */
		t = expm1l(w);
		w = one + t;
		w = one + (t * t) / (w + w);
		return (w);
	}
	if (w < thr2) {
		t = expl(w);
		return (half * (t + one / t));
	}
	if (w <= lnovft)
		return (half * expl(w));
	return (scalbnl(expl((w - lnovft) - lnovlo), 16383));
}
