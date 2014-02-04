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

#pragma weak asinh = __asinh

/* INDENT OFF */
/*
 * asinh(x)
 * Method :
 *	Based on
 *		asinh(x) = sign(x) * log [ |x| + sqrt(x*x+1) ]
 *	we have
 *	asinh(x) := x  if  1+x*x == 1,
 *		 := sign(x)*(log(x)+ln2)) for large |x|, else
 *		 := sign(x)*log(2|x|+1/(|x|+sqrt(x*x+1))) if|x| > 2, else
 *		 := sign(x)*log1p(|x|+x^2/(1+sqrt(1+x^2)))
 */
/* INDENT ON */

#include "libm_synonyms.h"	/* __asinh */
#include "libm_macros.h"
#include <math.h>

static const double xxx[] = {
/* one */	1.00000000000000000000e+00,	/* 3FF00000, 00000000 */
/* ln2 */	6.93147180559945286227e-01,	/* 3FE62E42, FEFA39EF */
/* huge */	1.00000000000000000000e+300
};
#define	one	xxx[0]
#define	ln2	xxx[1]
#define	huge	xxx[2]

double
asinh(double x) {
	double t, w;
	int hx, ix;

	hx = ((int *) &x)[HIWORD];
	ix = hx & 0x7fffffff;
	if (ix >= 0x7ff00000)
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
		return (ix >= 0x7ff80000 ? x : x + x);
		/* assumes sparc-like QNaN */
#else
		return (x + x);	/* x is inf or NaN */
#endif
	if (ix < 0x3e300000) {	/* |x|<2**-28 */
		if (huge + x > one)
			return (x);	/* return x inexact except 0 */
	}
	if (ix > 0x41b00000) {	/* |x| > 2**28 */
		w = log(fabs(x)) + ln2;
	} else if (ix > 0x40000000) {
		/* 2**28 > |x| > 2.0 */
		t = fabs(x);
		w = log(2.0 * t + one / (sqrt(x * x + one) + t));
	} else {
		/* 2.0 > |x| > 2**-28 */
		t = x * x;
		w = log1p(fabs(x) + t / (one + sqrt(one + t)));
	}
	return (hx > 0 ? w : -w);
}
