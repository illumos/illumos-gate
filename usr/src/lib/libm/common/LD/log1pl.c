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

#if defined(ELFOBJ)
#pragma weak log1pl = __log1pl
#endif

/*
 * log1pl(x)
 * Kahan's trick based on log(1+x)/x being a slow varying function.
 */

#include "libm.h"

#if defined(__x86)
#define	__swapRD	__swap87RD
#endif
extern enum fp_direction_type __swapRD(enum fp_direction_type);

long double
log1pl(long double x) {
	long double y;
	enum fp_direction_type rd;

	if (x != x)
		return (x + x);
	if (x < -1.L)
		return (logl(x));
	rd = __swapRD(fp_nearest);
	y = 1.L + x;
	if (y != 1.L) {
		if (y == x)
			x = logl(x);
		else
			x *= logl(y) / (y - 1.L);
	}
	if (rd != fp_nearest)
		(void) __swapRD(rd);
	return (x);
}
