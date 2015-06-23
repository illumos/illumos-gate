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

#pragma weak frexpf = __frexpf

#include "libm.h"

float
__frexpf(float x, int *exp) {
	union {
		unsigned i;
		float f;
	} xx;
	unsigned hx;
	int e;

	xx.f = x;
	hx = xx.i & ~0x80000000;

	if (hx >= 0x7f800000) { /* x is infinite or NaN */
		*exp = 0;
		return (x);
	}

	e = 0;
	if (hx < 0x00800000) { /* x is subnormal or zero */
		if (hx == 0) {
			*exp = 0;
			return (x);
		}

		/* normalize x by regarding it as an integer */
		xx.f = (int) xx.i < 0 ? -(int) hx : (int) hx;
		hx = xx.i & ~0x80000000;
		e = -149;
	}

	/* now xx.f is normal */
	xx.i = (xx.i & ~0x7f800000) | 0x3f000000;
	*exp = e + (hx >> 23) - 0x7e;
	return (xx.f);
}
