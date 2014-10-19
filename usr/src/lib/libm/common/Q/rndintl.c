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

#pragma weak aintl = __aintl
#pragma weak anintl = __anintl
#pragma weak irintl = __irintl
#pragma weak nintl = __nintl

/*
 * aintl(x)	return x chopped to integral value
 * anintl(x)	return sign(x)*(|x|+0.5) chopped to integral value
 * irintl(x)	return rint(x) in integer format
 * nintl(x)	return anint(x) in integer format
 *
 * NOTE: aintl(x), anintl(x), ceill(x), floorl(x), and rintl(x) return result
 * with the same sign as x's,  including 0.0.
 */

#include "libm.h"
#include "longdouble.h"

extern enum fp_direction_type __swapRD(enum fp_direction_type);

static const long double qone = 1.0L, qhalf = 0.5L, qmhalf = -0.5L;

long double
aintl(long double x) {
	long double t, w;

	if (!finitel(x))
		return (x + x);
	w = fabsl(x);
	t = rintl(w);
	if (t <= w)
		return (copysignl(t, x));	/* NaN or already aint(|x|) */
	else	/* |t|>|x| case */
		return (copysignl(t - qone, x));	/* |t-1|*sign(x) */
}

long double
anintl(long double x) {
	long double t, w, z;

	if (!finitel(x))
		return (x + x);
	w = fabsl(x);
	t = rintl(w);
	if (t == w)
		return (copysignl(t, x));
	z = t - w;
	if (z > qhalf)
		t = t - qone;
	else if (z <= qmhalf)
		t = t + qone;
	return (copysignl(t, x));
}

int
irintl(long double x) {
	enum fp_direction_type rd;

	rd = __swapRD(fp_nearest);
	(void) __swapRD(rd);	/* restore Rounding Direction */
	switch (rd) {
	case fp_nearest:
		if (x < 2147483647.5L && x >= -2147483648.5L)
			return ((int)rintl(x));
		break;
	case fp_tozero:
		if (x < 2147483648.0L && x > -2147483649.0L)
			return ((int)rintl(x));
		break;
	case fp_positive:
		if (x <= 2147483647.0L && x > -2147483649.0L)
			return ((int)rintl(x));
		break;
	case fp_negative:
		if (x < 2147483648.0L && x >= -2147483648.0L)
			return ((int)rintl(x));
		break;
	}
	return ((int)copysignl(1.0e100L, x));
}

int
nintl(long double x) {
	if ((x < 2147483647.5L) && (x > -2147483648.5L))
		return ((int)anintl(x));
	else
		return ((int)copysignl(1.0e100L, x));
}
