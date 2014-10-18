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
 * arccosin function
 *			      ________
 *                           / 1 - x
 *	acos(x) = 2*atan2(  / -------- , 1 )
 *                        \/   1 + x
 *
 *			      ________
 *                           / 1 - x
 *		= 2*atan (  / -------- ) for non-exceptional x.
 *                        \/   1 + x
 *
 * Special cases:
 *	if x is NaN, return x itself;
 *	if |x|>1, return NaN with invalid signal.
 */

#pragma weak acosl = __acosl

#include "libm.h"

static const long double zero = 0.0L, one = 1.0L;

long double
acosl(long double x) {
	if (isnanl(x))
		return (x + x);
	else if (fabsl(x) < one)
		x = atanl(sqrtl((one - x) / (one + x)));
	else if (x == -one)
		x = atan2l(one, zero);	/* x <- PI */
	else if (x == one)
		x = zero;
	else {		/* |x| > 1  create invalid signal */
		return (zero / zero);
	}
	return (x + x);
}
