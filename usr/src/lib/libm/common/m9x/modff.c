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

#pragma weak modff = __modff
#pragma weak _modff = __modff

#include "libm.h"

float
__modff(float x, float *iptr) {
	union {
		unsigned i;
		float f;
	} xx, yy;
	unsigned hx, s;

	xx.f = x;
	hx = xx.i & ~0x80000000;

	if (hx >= 0x4b000000) {	/* x is NaN, infinite, or integral */
		*iptr = x;
		if (hx <= 0x7f800000)
			xx.i &= 0x80000000;
		return (xx.f);
	}

	if (hx < 0x3f800000) {	/* |x| < 1 */
		xx.i &= 0x80000000;
		*iptr = xx.f;
		return (x);
	}

	/* split x at the binary point */
	s = xx.i & 0x80000000;
	yy.i = xx.i & ~((1 << (0x96 - (hx >> 23))) - 1);
	*iptr = yy.f;
	xx.f -= yy.f;
	xx.i = (xx.i & ~0x80000000) | s;
				/* restore sign in case difference is 0 */
	return (xx.f);
}
