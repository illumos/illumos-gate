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
#pragma weak llroundf = __llroundf
#if defined(__sparcv9) || defined(__amd64)
#pragma weak lroundf = __llroundf
#pragma weak __lroundf = __llroundf
#endif
#endif

#include "libm.h"

long long
llroundf(float x) {
	union {
		unsigned i;
		float f;
	} xx;
	unsigned hx, sx, i;

	xx.f = x;
	hx = xx.i & ~0x80000000;
	sx = xx.i & 0x80000000;

	if (hx < 0x4b000000) { /* |x| < 2^23 */
		/* handle |x| < 1 */
		if (hx < 0x3f800000) {
			if (hx >= 0x3f000000)
				return (sx ? -1LL : 1LL);
			return (0LL);
		}

		/* round x at the integer bit */
		i = 1 << (0x95 - (hx >> 23));
		xx.i = (xx.i + i) & ~((i << 1) - 1);

		/*
		 * on LP32 architectures, we can just convert x to a 32-bit
		 * integer and sign-extend it
		 */
		return ((long) xx.f);
	}

	/* now x is nan, inf, or integral */
	return ((long long) x);
}
