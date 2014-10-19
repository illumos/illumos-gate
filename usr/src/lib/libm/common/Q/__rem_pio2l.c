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

/*
 * __rem_pio2l(x,y)
 *
 * return the remainder of x rem pi/2 in y[0]+y[1] by calling __rem_pio2m
 */

#ifndef FDLIBM_BASED
#include "libm.h"
extern int __rem_pio2m(double *, double *, int, int, int, const int *);
#else				/* FDLIBM_BASED */
#include "fdlibm.h"
#define	__rem_pio2m	__kernel_rem_pio2
#endif				/* FDLIBM_BASED */

#include "longdouble.h"

extern const int _TBL_ipio2l_inf[];

static const long double
	two24l = 16777216.0L,
	pio4   = 0.7853981633974483096156608458198757210495L;

int
__rem_pio2l(long double x, long double *y) {
	long double z, w;
	double t[5], v[5];
	int e0, i, nx, n, sign;
	const int *ipio2;

	sign = signbitl(x);
	z = fabsl(x);
	if (z <= pio4) {
		y[0] = x;
		y[1] = 0;
		return (0);
	}
	e0 = ilogbl(z) - 23;
	z = scalbnl(z, -e0);
	for (i = 0; i < 5; i++) {
		t[i] = (double) ((int) (z));
		z = (z - (long double) t[i]) * two24l;
	}
	nx = 5;
	while (t[nx - 1] == 0.0)
		nx--;		/* skip zero term */
	ipio2 = _TBL_ipio2l_inf;
	n = __rem_pio2m(t, v, e0, nx, 3, (const int *) ipio2);
	z = (long double) v[2] + (long double) v[1];
	w = (long double) v[0];
	y[0] = z + w;
	y[1] = z - (y[0] - w);
	if (sign == 1) {
		y[0] = -y[0];
		y[1] = -y[1];
		return (-n);
	}
	return (n);
}
