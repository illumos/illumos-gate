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

#pragma weak coshl = __coshl

#include "libm.h"
#include "longdouble.h"


/*
 * coshl(X)
 * RETURN THE HYPERBOLIC COSINE OF X
 *
 * Method :
 *	1. Replace x by |x| (coshl(x) = coshl(-x)).
 *	2.
 *		                                       [ expl(x) - 1 ]^2
 *	    0        <= x <= 0.3465 : coshl(x) := 1 + -------------------
 *							    2*expl(x)
 *
 *		                                  expl(x) + 1/expl(x)
 *	    0.3465   <= x <= thresh : coshl(x) := -------------------
 *							   2
 *	    thresh   <= x <= lnovft : coshl(x) := expl(x)/2
 *	    lnovft   <= x <  INF    : coshl(x) := scalbnl(expl(x-1024*ln2),1023)
 *
 * here
 *	thr1		a number that is near one half of ln2.
 *	thr2		a number such that
 *				expl(thresh)+expl(-thresh)=expl(thresh)
 *	lnovft:		logrithm of the overflow threshold
 *			= MEP1*ln2 chopped to machine precision.
 *	ME		maximum exponent
 *	MEP1		maximum exponent plus 1
 *
 * Special cases:
 *	coshl(x) is |x| if x is +INF, -INF, or NaN.
 *	only coshl(0)=1 is exact for finite x.
 */

#define	ME	16383
#define	MEP1	16384
#define	LNOVFT	1.135652340629414394949193107797076342845e+4L
		/* last 32 bits of LN2HI is zero */
#define	LN2HI   6.931471805599453094172319547495844850203e-0001L
#define	LN2LO   1.667085920830552208890449330400379754169e-0025L
#define	THR1	0.3465L
#define	THR2	45.L

static const long double
	half 	= 0.5L,
	tinyl	= 7.5e-37L,
	one	= 1.0L,
	ln2hi   = LN2HI,
	ln2lo   = LN2LO,
	lnovftL	= LNOVFT,
	thr1	= THR1,
	thr2	= THR2;

long double
coshl(long double x) {
	long double t, w;

	w = fabsl(x);
	if (!finitel(w))
		return (w + w);		/* x is INF or NaN */
	if (w < thr1) {
		t = w < tinyl ? w : expm1l(w);
		w = one + t;
		if (w != one)
			w = one + (t * t) / (w + w);
		return (w);
	} else if (w < thr2) {
		t = expl(w);
		return (half * (t + one / t));
	} else if (w <= lnovftL)
		return (half * expl(w));
	else {
		return (scalbnl(expl((w - MEP1 * ln2hi) - MEP1 * ln2lo), ME));
	}
}
