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

#pragma weak __asinhl = asinhl

#include "libm.h"

static const long double
	ln2	= 6.931471805599453094172321214581765680755e-0001L,
	one	= 1.0L,
	big	= 1.0e+20L,
	tiny	= 1.0e-20L;

long double
asinhl(long double x) {
	long double t, w;
#ifndef lint
	volatile long double dummy __unused;
#endif

	w = fabsl(x);
	if (isnanl(x))
		return (x + x);	/* x is NaN */
	if (w < tiny) {
#ifndef lint
		dummy = x + big;	/* inexact if x != 0 */
#endif
		return (x);	/* tiny x */
	} else if (w < big) {
		t = one / w;
		return (copysignl(log1pl(w + w / (t + sqrtl(one + t * t))), x));
	} else
		return (copysignl(logl(w) + ln2, x));
}
