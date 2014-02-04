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

#pragma weak rint = __rint

/*
 * rint(x) return x rounded to integral according to the rounding direction
 * rint(x) returns result with the same sign as x's,  including 0.0.
 */

#include "libm.h"

#if defined(__i386) && !defined(__amd64) && (!defined(__FLT_EVAL_METHOD__) || \
	__FLT_EVAL_METHOD__ != 0)
extern enum fp_precision_type __swapRP(enum fp_precision_type);
#define	DECLRP(x)	enum fp_precision_type x;
#define	SWAPRP(new, x)	x = __swapRP(new);
#define	RESTRP(x)	(void) __swapRP(x);
#else
#define	DECLRP(x)
#define	SWAPRP(new, x)
#define	RESTRP(x)
#endif

static const double
	two52 = 4503599627370496.0,
	zero = 0.0,
	one = 1.0;

double
rint(double x) {
	DECLRP(rp)
	double	t, w;
	int	ix, hx;

	ix = ((int *)&x)[HIWORD];
	hx = ix & ~0x80000000;

	if (hx >= 0x43300000)
		return (x * one);
	t = (ix < 0)? -two52 : two52;
	SWAPRP(fp_double, rp)		/* set precision mode to double */
	w = x + t;			/* x+sign(x)*2**52 rounded */
	RESTRP(rp)			/* restore precision mode */
	if (w == t)
		return ((ix < 0)? -zero : zero);
	return (w - t);
}
