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

#pragma weak remainder = __remainder

/*
 * remainder(x,p)
 * Code originated from 4.3bsd.
 * Modified by K.C. Ng for SUN 4.0 libm.
 * Return :
 * 	returns  x REM p  =  x - [x/p]*p as if in infinite precise arithmetic,
 *	where [x/p] is the (inifinite bit) integer nearest x/p (in half way
 *	case choose the even one).
 * Method :
 *	Based on fmod() return x-[x/p]chopped*p exactly.
 */

#include "libm.h"

static const double zero = 0.0, half = 0.5;

double
remainder(double x, double p) {
	double	halfp;
	int	ix, hx, hp;

	ix = ((int *)&x)[HIWORD];
	hx = ix & ~0x80000000;
	hp = ((int *)&p)[HIWORD] & ~0x80000000;

	if (hp > 0x7ff00000 || (hp == 0x7ff00000 && ((int *)&p)[LOWORD] != 0))
		return (x * p);
	if (hx > 0x7ff00000 || (hx == 0x7ff00000 && ((int *)&x)[LOWORD] != 0))
		return (x * p);

	if ((hp | ((int *)&p)[LOWORD]) == 0 || hx == 0x7ff00000)
		return (_SVID_libm_err(x, p, 28));

	p = fabs(p);
	if (hp < 0x7fe00000)
		x = fmod(x, p + p);
	x = fabs(x);
	if (hp < 0x00200000) {
		if (x + x > p) {
			if (x == p)	/* avoid x-x=-0 in RM mode */
				return ((ix < 0)? -zero : zero);
			x -= p;
			if (x + x >= p)
				x -= p;
		}
	} else {
		halfp = half * p;
		if (x > halfp) {
			if (x == p)	/* avoid x-x=-0 in RM mode */
				return ((ix < 0)? -zero : zero);
			x -= p;
			if (x >= halfp)
				x -= p;
		}
	}
	return ((ix < 0)? -x : x);
}
