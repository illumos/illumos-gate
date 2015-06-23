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

#pragma weak __atanhl = atanhl

#include "libm.h"

#define GENERIC	long double
#define	ATANH 	atanhl

/* ATANH(x)
 *                  1              2x                          x
 *	ATANH(x) = --- * LOG(1 + -------) = 0.5 * LOG1P(2 * --------)
 *                  2             1 - x                      1 - x
 * Note: to guarantee ATANH(-x) = -ATANH(x), we use
 *                 sign(x)             |x|
 *	ATANH(x) = ------- * LOG1P(2*-------).
 *                    2              1 - |x|
 *
 * Special cases:
 *	ATANH(x) is NaN if |x| > 1 with signal;
 *	ATANH(NaN) is that NaN with no signal;
 *	ATANH(+-1) is +-INF with signal.
 *
 */

#define	FABS 	fabsl
#define	LOG1P 	log1pl
#define	COPYSIGN 	copysignl


extern GENERIC 	FABS(),LOG1P(),COPYSIGN();

static GENERIC
zero	= (GENERIC) 0.0,
half 	= (GENERIC) 0.5,
one	= (GENERIC) 1.0;

GENERIC ATANH(x)
GENERIC x;
{
	GENERIC t;
	t = FABS(x);
	if (t == one) return x/zero;
	t = t/(one-t);
	return COPYSIGN(half,x)*LOG1P(t+t);
}
