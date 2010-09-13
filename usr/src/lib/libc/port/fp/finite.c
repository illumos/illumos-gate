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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	IEEE recommended functions */

#pragma weak _finite = finite
#pragma weak _fpclass = fpclass
#pragma weak _unordered = unordered

#include "lint.h"
#include <values.h>
#include "fpparts.h"

#define	P754_NOFAULT 1		/* avoid generating extra code */
#include <ieeefp.h>

/*
 * FINITE(X)
 * finite(x) returns 1 if x > -inf and x < +inf and 0 otherwise
 * NaN returns 0
 */

int
finite(double x)
{
	return ((EXPONENT(x) != MAXEXP));
}

/*
 * UNORDERED(x,y)
 * unordered(x,y) returns 1 if x is unordered with y, otherwise
 * it returns 0; x is unordered with y if either x or y is NAN
 */

int
unordered(double x, double y)
{
	if ((EXPONENT(x) == MAXEXP) && (HIFRACTION(x) || LOFRACTION(x)))
		return (1);
	if ((EXPONENT(y) == MAXEXP) && (HIFRACTION(y) || LOFRACTION(y)))
		return (1);
	return (0);
}

/*
 * FPCLASS(X)
 * fpclass(x) returns the floating point class x belongs to
 */

fpclass_t
fpclass(double x)
{
	int	sign, exp;

	exp = EXPONENT(x);
	sign = SIGNBIT(x);
	if (exp == 0) { /* de-normal or zero */
		if (HIFRACTION(x) || LOFRACTION(x)) /* de-normal */
			return (sign ? FP_NDENORM : FP_PDENORM);
		else
			return (sign ? FP_NZERO : FP_PZERO);
	}
	if (exp == MAXEXP) { /* infinity or NaN */
		if ((HIFRACTION(x) == 0) && (LOFRACTION(x) == 0)) /* infinity */
			return (sign ? FP_NINF : FP_PINF);
		else
			if (QNANBIT(x))
			/* hi-bit of mantissa set - quiet nan */
				return (FP_QNAN);
			else	return (FP_SNAN);
	}
	/* if we reach here we have non-zero normalized number */
	return (sign ? FP_NNORM : FP_PNORM);
}
