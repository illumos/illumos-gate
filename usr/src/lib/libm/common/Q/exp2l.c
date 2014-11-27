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

#pragma weak __exp2l = exp2l

#include "libm.h"
#include "longdouble.h"

/*
 *	exp2l(x) = 2**x = 2**((x-anint(x))+anint(x))
 *		 = 2**anint(x)*2**(x-anint(x))
 *		 = 2**anint(x)*exp((x-anint(x))*ln2)
 */

#define	TINY	1.0e-20L	/* single: 1e-5, double: 1e-10, quad: 1e-20 */
#define	OVFLEXP	16400		/* single: 130,  double  1030,  quad: 16400 */
#define	UNFLEXP	-16520		/* single:-155,  double -1080,  quad:-16520 */

static const long double
	zero = 0.0L,
	tiny = TINY * TINY,
	half = 0.5L,
	ln2 = 6.931471805599453094172321214581765680755e-0001L,
	one = 1.0L;

static const int
	ovflexp = OVFLEXP,
	unflexp = UNFLEXP;

long double
exp2l(long double x) {
	long double t;

	if (!finitel(x)) {
		if (isnanl(x) || x > zero)
			return (x + x);
		else
			return (zero);
	}
	t = fabsl(x);
	if (t < half) {
		if (t < tiny)
			return (one + x);
		else
			return (expl(ln2 * x));
	}
	t = anintl(x);
	if (t < ovflexp) {
		if (t >= unflexp)
			return (scalbnl(expl(ln2 * (x - t)), (int) t));
		else
			return (scalbnl(one, unflexp));	/* underflow */
	} else
		return (scalbnl(one, ovflexp));	/* overflow  */
}
