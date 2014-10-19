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

#pragma weak tan = __tan

/* INDENT OFF */
/*
 * tan(x)
 * Table look-up algorithm by K.C. Ng, November, 1989.
 *
 * kernel function:
 *	__k_tan		... tangent function on [-pi/4,pi/4]
 *	__rem_pio2	... argument reduction routine
 */
/* INDENT ON */

#include "libm.h"
#include "libm_synonyms.h"
#include "libm_protos.h"
#include <math.h>

double
tan(double x) {
	double y[2], z = 0.0;
	int n, ix;

	/* high word of x */
	ix = ((int *) &x)[HIWORD];

	/* |x| ~< pi/4 */
	ix &= 0x7fffffff;
	if (ix <= 0x3fe921fb)
		return (__k_tan(x, z, 0));

	/* tan(Inf or NaN) is NaN */
	else if (ix >= 0x7ff00000) {
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
		return (ix >= 0x7ff80000 ? x : x - x);	/* NaN */
		/* assumes sparc-like QNaN */
#else
		return (x - x);				/* NaN */
#endif
	}

	/* argument reduction needed */
	else {
		n = __rem_pio2(x, y);
		return (__k_tan(y[0], y[1], n & 1));
	}
}
