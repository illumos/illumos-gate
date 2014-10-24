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
 * log2l(x)
 * RETURN THE BASE 2 LOGARITHM OF X
 *
 * Method:
 *	purge off 0,INF, and NaN.
 *	n = ilogb(x)
 *	if (n<0) n+=1
 *	z = scalbn(x,-n)
 *	LOG2(x) = n + (1/ln2)*log(x)
 */

#pragma weak __log2l = log2l

#include "libm.h"
#include "longdouble.h"

static const long double
	zero 	= 0.0L,
	half	= 0.5L,
	one	= 1.0L,
	invln2	= 1.442695040888963407359924681001892137427e+0000L;

long double
log2l(long double x) {
	int n;

	if (x == zero || !finitel(x))
		return (logl(x));
	n = ilogbl(x);
	if (n < 0)
		n += 1;
	x = scalbnl(x, -n);
	if (x == half)
		return (n - one);
	return (n + invln2 * logl(x));
}
