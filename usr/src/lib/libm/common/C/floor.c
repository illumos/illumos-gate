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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak __floor = floor

/*
 * floor(x) returns the biggest integral value less than or equal to x.
 * NOTE: floor(x) returns result with the same sign as x's, including 0.
 *
 * Modified 8/4/04 for performance.
 */

#include "libm.h"

static const double
	zero = 0.0,
	one = 1.0,
	two52 = 4503599627370496.0;

double
floor(double x) {
	double	t, w;
	int	hx, lx, ix;

	hx = ((int *)&x)[HIWORD];
	lx = ((int *)&x)[LOWORD];
	ix = hx & ~0x80000000;
	if (ix >= 0x43300000)	/* return x if |x| >= 2^52, or x is NaN */
		return (x * one);
	t = (hx >= 0)? two52 : -two52;
	w = x + t;
	t = w - t;
	if (ix < 0x3ff00000) {
		if ((ix | lx) == 0)
			return (x);
		else
			return ((hx < 0)? -one : zero);
	}
	return ((t <= x)? t : t - one);
}
