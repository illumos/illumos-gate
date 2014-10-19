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

#pragma weak exp2 = __exp2

/* INDENT OFF */
/*
 * exp2(x)
 * Code by K.C. Ng for SUN 4.0 libm.
 * Method :
 *	exp2(x) = 2**x = 2**((x-anint(x))+anint(x))
 *		= 2**anint(x)*2**(x-anint(x))
 *		= 2**anint(x)*exp((x-anint(x))*ln2)
 */
/* INDENT ON */

#include "libm.h"

static const double C[] = {
	0.0,
	1.0,
	0.5,
	6.93147180559945286227e-01,
	1.0e300,
	1.0e-300,
};

#define	zero	C[0]
#define	one	C[1]
#define	half	C[2]
#define	ln2	C[3]
#define	huge	C[4]
#define	tiny	C[5]

double
exp2(double x) {
	int	ix, hx, k;
	double	t;

	ix = ((int *)&x)[HIWORD];
	hx = ix & ~0x80000000;

	if (hx >= 0x4090e000) {	/* |x| >= 1080 or x is nan */
		if (hx >= 0x7ff00000) {	/* x is inf or nan */
			if (ix == 0xfff00000 && ((int *)&x)[LOWORD] == 0)
				return (zero);
			return (x * x);
		}
		t = (ix < 0)? tiny : huge;
		return (t * t);
	}

	if (hx < 0x3fe00000) {	/* |x| < 0.5 */
		if (hx < 0x3c000000)
			return (one + x);
		return (exp(ln2 * x));
	}

	k = (int)x;
	if (x != (double)k)
		k = (int)((ix < 0)? x - half : x + half);
	return (scalbn(exp(ln2 * (x - (double)k)), k));
}
