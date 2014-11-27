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

/*
 *                   1              2x                           x
 *	atanhl(x) = --- * LOG(1 + -------) = 0.5 * log1pl(2 * --------)
 *                   2             1 - x                       1 - x
 * Note: to guarantee atanhl(-x) = -atanhl(x), we use
 *                  sign(x)              |x|
 *	atanhl(x) = ------- * log1pl(2*-------).
 *                     2               1 - |x|
 *
 * Special cases:
 *	atanhl(x) is NaN if |x| > 1 with signal;
 *	atanhl(NaN) is that NaN with no signal;
 *	atanhl(+-1) is +-INF with signal.
 *
 */

static const long double zero = 0.0L, half = 0.5L, one = 1.0L;

long double
atanhl(long double x) {
	long double t;

	t = fabsl(x);
	if (t == one)
		return (x / zero);
	t = t / (one - t);
	return (copysignl(half, x) * log1pl(t + t));
}
