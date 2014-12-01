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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak __scalbf = scalbf

#include "libm.h"

float
scalbf(float x, float y) {
	int	ix, iy, hx, hy, n;

	ix = *(int *)&x;
	iy = *(int *)&y;
	hx = ix & ~0x80000000;
	hy = iy & ~0x80000000;

	if (hx > 0x7f800000 || hy >= 0x7f800000) {
		/* x is nan or y is inf or nan */
		return ((iy < 0)? x / -y : x * y);
	}

	/* see if y is an integer without raising inexact */
	if (hy >= 0x4b000000) {
		/* |y| >= 2^23, so it must be an integer */
		n = (iy < 0)? -65000 : 65000;
	} else if (hy < 0x3f800000) {
		/* |y| < 1, so it must be zero or non-integer */
		return ((hy == 0)? x : (x - x) / (x - x));
	} else {
		if (hy & ((1 << (0x96 - (hy >> 23))) - 1))
			return ((y - y) / (y - y));
		n = (int)y;
	}
	return (scalbnf(x, n));
}
