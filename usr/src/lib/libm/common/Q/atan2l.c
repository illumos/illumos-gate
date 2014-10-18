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
 * atan2l(y,x)
 *
 * Method :
 *	1. Reduce y to positive by atan2(y,x)=-atan2(-y,x).
 *	2. Reduce x to positive by (if x and y are unexceptional):
 *		ARG (x+iy) = arctan(y/x)	   ... if x > 0,
 *		ARG (x+iy) = pi - arctan[y/(-x)]   ... if x < 0,
 *
 * Special cases:
 *
 *	ATAN2((anything), NaN ) is NaN;
 *	ATAN2(NAN , (anything) ) is NaN;
 *	ATAN2(+-0, +(anything but NaN)) is +-0  ;
 *	ATAN2(+-0, -(anything but NaN)) is +-PI ;
 *	ATAN2(+-(anything but 0 and NaN), 0) is +-PI/2;
 *	ATAN2(+-(anything but INF and NaN), +INF) is +-0 ;
 *	ATAN2(+-(anything but INF and NaN), -INF) is +-PI;
 *	ATAN2(+-INF,+INF ) is +-PI/4 ;
 *	ATAN2(+-INF,-INF ) is +-3PI/4;
 *	ATAN2(+-INF, (anything but,0,NaN, and INF)) is +-PI/2;
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following constants.
 * The decimal values may be used, provided that the compiler will convert
 * from decimal to binary accurately enough to produce the hexadecimal values
 * shown.
 */

#pragma weak atan2l = __atan2l

#include "libm.h"
#include "longdouble.h"

static const long double
	zero	=  0.0L,
	tiny 	=  1.0e-40L,
	one	=  1.0L,
	half	=  0.5L,
	PI3o4	=  2.356194490192344928846982537459627163148L,
	PIo4	=  0.785398163397448309615660845819875721049L,
	PIo2	=  1.570796326794896619231321691639751442099L,
	PI	=  3.141592653589793238462643383279502884197L,
	PI_lo	=  8.671810130123781024797044026043351968762e-35L;

long double
atan2l(long double y, long double x) {
	long double t, z;
	int k, m, signy, signx;

	if (x != x || y != y)
		return (x + y);	/* return NaN if x or y is NAN */
	signy = signbitl(y);
	signx = signbitl(x);
	if (x == one)
		return (atanl(y));
	m = signy + signx + signx;

	/* when y = 0 */
	if (y == zero)
		switch (m) {
		case 0:
			return (y);	/* atan(+0,+anything) */
		case 1:
			return (y);	/* atan(-0,+anything) */
		case 2:
			return (PI + tiny);	/* atan(+0,-anything) */
		case 3:
			return (-PI - tiny);	/* atan(-0,-anything) */
		}

	/* when x = 0 */
	if (x == zero)
		return (signy == 1 ? -PIo2 - tiny : PIo2 + tiny);

	/* when x is INF */
	if (!finitel(x)) {
		if (!finitel(y)) {
			switch (m) {
			case 0:
				return (PIo4 + tiny);	/* atan(+INF,+INF) */
			case 1:
				return (-PIo4 - tiny);	/* atan(-INF,+INF) */
			case 2:
				return (PI3o4 + tiny);	/* atan(+INF,-INF) */
			case 3:
				return (-PI3o4 - tiny);	/* atan(-INF,-INF) */
			}
		} else {
			switch (m) {
			case 0:
				return (zero);	/* atan(+...,+INF) */
			case 1:
				return (-zero);	/* atan(-...,+INF) */
			case 2:
				return (PI + tiny);	/* atan(+...,-INF) */
			case 3:
				return (-PI - tiny);	/* atan(-...,-INF) */
			}
		}
	}
	/* when y is INF */
	if (!finitel(y))
		return (signy == 1 ? -PIo2 - tiny : PIo2 + tiny);

	/* compute y/x */
	x = fabsl(x);
	y = fabsl(y);
	t = PI_lo;
	k = (ilogbl(y) - ilogbl(x));

	if (k > 120)
		z = PIo2 + half * t;
	else if (m > 1 && k < -120)
		z = zero;
	else
		z = atanl(y / x);

	switch (m) {
	case 0:
		return (z);	/* atan(+,+) */
	case 1:
		return (-z);	/* atan(-,+) */
	case 2:
		return (PI - (z - t));	/* atan(+,-) */
	case 3:
		return ((z - t) - PI);	/* atan(-,-) */
	}
	/* NOTREACHED */
    return 0.0L;
}
