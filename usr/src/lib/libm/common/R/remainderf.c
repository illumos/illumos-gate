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

#pragma weak __remainderf = remainderf

#include "libm.h"

float
remainderf(float x, float y) {
	if (isnanf(x) || isnanf(y))
		return (x * y);
	if (y == 0.0f || (*(int *) &x & ~0x80000000) == 0x7f800000) {
		/* y is 0 or x is infinite; raise invalid and return NaN */
		y = 0.0f;
		*(int *) &x = 0x7f800000;
		return (x * y);
	}
	return ((float) remainder((double) x, (double) y));
}
