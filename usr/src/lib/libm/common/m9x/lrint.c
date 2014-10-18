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
#pragma weak lrint = __lrint
#endif

/*
 * lrint(x) rounds its argument to the nearest integer according
 * to the current rounding direction and converts the result to
 * a 32 bit signed integer.
 *
 * If x is NaN, infinite, or so large that the nearest integer
 * would exceed 32 bits, the invalid operation exception is raised.
 * If x is not an integer, the inexact exception is raised.
 */

#include <sys/isa_defs.h>	/* _ILP32 */
#include "libm.h"

#if defined(_ILP32)
long
lrint(double x) {
	/*
	 * Note: The following code works on x86 (in the default rounding
	 * precision mode), but one should just use the fistpl instruction
	 * instead.
	 */
	union {
		unsigned i[2];
		double d;
	} xx, yy;
	unsigned hx;

	xx.d = x;
	hx = xx.i[HIWORD] & ~0x80000000;
	if (hx < 0x43300000) { /* |x| < 2^52 */
		/* add and subtract a power of two to round x to an integer */
#if defined(__sparc)
		yy.i[HIWORD] = (xx.i[HIWORD] & 0x80000000) | 0x43300000;
#elif defined(__x86)
		yy.i[HIWORD] = (xx.i[HIWORD] & 0x80000000) | 0x43e00000;
#else
#error Unknown architecture
#endif
		yy.i[LOWORD] = 0;
		x = (x + yy.d) - yy.d;
	}

	/* now x is nan, inf, or integral */
	return ((long) x);
}
#else
#error Unsupported architecture
#endif	/* defined(_ILP32) */
