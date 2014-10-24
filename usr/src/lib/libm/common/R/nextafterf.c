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

#pragma weak __nextafterf = nextafterf

#include "libm.h"

float
nextafterf(float x, float y) {
	float w;
	int *pw = (int *) &w;
	int *px = (int *) &x;
	int *py = (int *) &y;
	int ix, iy, iz;

	ix = px[0];
	iy = py[0];
	if ((ix & ~0x80000000) > 0x7f800000)
		return (x * y);		/* + -> * for Cheetah */
	if ((iy & ~0x80000000) > 0x7f800000)
		return (y * x);		/* + -> * for Cheetah */
	if (ix == iy || (ix | iy) == 0x80000000)
		return (y);		/* C99 requirement */
	if ((ix & ~0x80000000) == 0)
		iz = 1 | (iy & 0x80000000);
	else if (ix > 0) {
		if (ix > iy)
			iz = ix - 1;
		else
			iz = ix + 1;
	} else {
		if (iy < 0 && ix < iy)
			iz = ix + 1;
		else
			iz = ix - 1;
	}
	pw[0] = iz;
	ix = iz & 0x7f800000;
	if (ix == 0x7f800000) {
		/* raise overflow */
		volatile float t;

		*(int *) &t = 0x7f7fffff;
		t *= t;
	} else if (ix == 0) {
		/* raise underflow */
		volatile float t;

		*(int *) &t = 0x00800000;
		t *= t;
	}
	return (w);
}
