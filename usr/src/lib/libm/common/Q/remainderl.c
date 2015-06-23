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

#pragma weak __remainderl = remainderl

#include "libm.h"
#include "longdouble.h"

/*
 * remainderl(x,p)
 *	returns  x REM p  =  x - [x/p]*p as if in infinite
 *	precise arithmetic, where [x/p] is the (inifinite bit)
 *	integer nearest x/p (in half way case choose the even one).
 * Method :
 *	Based on fmodl() return x-[x/p]chopped*p exactly.
 */

#define	HFMAX	5.948657476786158825428796633140035080982e+4931L
#define	DBMIN	6.724206286224187012525355634643505205196e-4932L

static const long double
	zero = 0.0L,
	half = 0.5L,
	hfmax = HFMAX,	/* half of the maximum number */
	dbmin = DBMIN;	/* double of the minimum (normal) number */

long double
remainderl(long double x, long double p) {
	long double hp;
	int sx;

	if (isnanl(p))
		return (x + p);
	if (!finitel(x))
		return (x - x);
	p = fabsl(p);
	if (p <= hfmax)
		x = fmodl(x, p + p);
	sx = signbitl(x);
	x = fabsl(x);
	if (p < dbmin) {
		if (x + x > p) {
			if (x == p)
				x = zero;
			else
				x -= p;	/* avoid x-x=-0 in RM mode */
			if (x + x >= p)
				x -= p;
		}
	} else {
		hp = half * p;
		if (x > hp) {
			if (x == p)
				x = zero;
			else
				x -= p;	/* avoid x-x=-0 in RM mode */
			if (x >= hp)
				x -= p;
		}
	}
	return (sx == 0 ? x : -x);
}
