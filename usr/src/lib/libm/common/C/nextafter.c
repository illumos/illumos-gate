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

#pragma weak nextafter = __nextafter
#pragma weak _nextafter = __nextafter

#include "libm.h"
#include <float.h>		/* DBL_MIN */

double
nextafter(double x, double y) {
	int		hx, hy, k;
	double		ans;
	unsigned	lx;
	volatile double dummy;

	hx = ((int *)&x)[HIWORD];
	lx = ((int *)&x)[LOWORD];
	hy = ((int *)&y)[HIWORD];
	k = (hx & ~0x80000000) | lx;

	if (x == y)
		return (y);		/* C99 requirement */
	if (x != x || y != y)
		return (x * y);
	if (k == 0) {			/* x = 0 */
		k = hy & 0x80000000;
		((int *)&ans)[HIWORD] = k;
		((int *)&ans)[LOWORD] = 1;
	} else if (hx >= 0) {
		if (x > y) {
			((int *)&ans)[LOWORD] = lx - 1;
			k = (lx == 0)? hx - 1 : hx;
			((int *)&ans)[HIWORD] = k;
		} else {
			((int *)&ans)[LOWORD] = lx + 1;
			k  = (lx == 0xffffffff)? hx + 1 : hx;
			((int *)&ans)[HIWORD] = k;
		}
	} else {
		if (x < y) {
			((int *)&ans)[LOWORD] = lx - 1;
			k = (lx == 0)? hx - 1 : hx;
			((int *)&ans)[HIWORD] = k;
		} else {
			((int *)&ans)[LOWORD] = lx + 1;
			k  = (lx == 0xffffffff)? hx + 1 : hx;
			((int *)&ans)[HIWORD] = k;
		}
	}
	k = (k >> 20) & 0x7ff;
	if (k == 0x7ff) {
		/* overflow */
		return (_SVID_libm_err(x, y, 46));
#if !defined(__lint)
	} else if (k == 0) {
		/* underflow */
		dummy = DBL_MIN * copysign(DBL_MIN, x);
#endif
	}
	return (ans);
}
