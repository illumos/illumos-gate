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

#pragma weak __acosh = acosh

/* INDENT OFF */
/*
 * acosh(x)
 * Method :
 *	Based on
 *		acosh(x) = log [ x + sqrt(x*x-1) ]
 *	we have
 *		acosh(x) := log(x)+ln2,	if x is large; else
 *		acosh(x) := log(2x-1/(sqrt(x*x-1)+x)) if x > 2; else
 *		acosh(x) := log1p(t+sqrt(2.0*t+t*t)); where t = x-1.
 *
 * Special cases:
 *	acosh(x) is NaN with signal if x < 1.
 *	acosh(NaN) is NaN without signal.
 */
/* INDENT ON */

#include "libm_protos.h"	/* _SVID_libm_error */
#include "libm_macros.h"
#include <math.h>

static const double
	one = 1.0,
	ln2 = 6.93147180559945286227e-01;	/* 3FE62E42, FEFA39EF */

double
acosh(double x) {
	double t;
	int hx;

	hx = ((int *) &x)[HIWORD];
	if (hx < 0x3ff00000) {	/* x < 1 */
		if (isnan(x))
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
			return (hx >= 0xfff80000 ? x : (x - x) / (x - x));
			/* assumes sparc-like QNaN */
#else
			return (x - x) / (x - x);
#endif
		else
			return (_SVID_libm_err(x, x, 29));
	} else if (hx >= 0x41b00000) {
		/* x > 2**28 */
		if (hx >= 0x7ff00000) {	/* x is inf of NaN */
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
			return (hx >= 0x7ff80000 ? x : x + x);
			/* assumes sparc-like QNaN */
#else
			return (x + x);
#endif
		} else	/* acosh(huge)=log(2x) */
			return (log(x) + ln2);
	} else if (((hx - 0x3ff00000) | ((int *) &x)[LOWORD]) == 0) {
		return (0.0);	/* acosh(1) = 0 */
	} else if (hx > 0x40000000) {
		/* 2**28 > x > 2 */
		t = x * x;
		return (log(2.0 * x - one / (x + sqrt(t - one))));
	} else {
		/* 1 < x < 2 */
		t = x - one;
		return (log1p(t + sqrt(2.0 * t + t * t)));
	}
}
