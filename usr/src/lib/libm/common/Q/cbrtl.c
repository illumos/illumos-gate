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

#pragma weak cbrtl = __cbrtl

#include "libm.h"
#include "longdouble.h"

#define	n0	0

long double
cbrtl(long double x) {
	long double s, t, r, w, y;
	double dx, dy;
	int *py = (int *) &dy;
	int n, m, m3, sx;

	if (!finitel(x))
		return (x + x);
	if (iszerol(x))
		return (x);
	sx = signbitl(x);
	x = fabsl(x);
	n = ilogbl(x);
	m = n / 3;
	m3 = m + m + m;
	y = scalbnl(x, -m3);
	dx = (double) y;
	dy = cbrt(dx);
	py[1 - n0] += 2;
	if (py[1 - n0] == 0)
		py[n0] += 1;

	/* one step newton iteration to 113 bits with error < 0.667ulps */
	t = (long double) dy;
	t = scalbnl(t, m);
	s = t * t;
	r = x / s;
	w = t + t;
	r = (r - t) / (w + r);
	t += t * r;

	return (sx == 0 ? t : -t);
}
