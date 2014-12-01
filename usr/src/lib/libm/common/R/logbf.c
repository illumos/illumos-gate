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

#pragma weak __logbf = logbf

#include "libm.h"
#include "xpg6.h"	/* __xpg6 */
#define	_C99SUSv3_logb	_C99SUSv3_logb_subnormal_is_like_ilogb

#if defined(__x86)
static const float two25 = 33554432.0F;
#else
/*
 * v: a non-zero subnormal |x|
 */
static int
ilogbf_subnormal(unsigned v) {
	int r = -126 - 23;

	if (v & 0xffff0000)
		r += 16, v >>= 16;
	if (v & 0xff00)
		r += 8, v >>= 8;
	if (v & 0xf0)
		r += 4, v >>= 4;
	v <<= 1;
	return (r + ((0xffffaa50 >> v) & 0x3));
}
#endif	/* defined(__x86) */

static float
raise_division(float t) {
#pragma STDC FENV_ACCESS ON
	static const float zero = 0.0F;
	return (t / zero);
}

float
logbf(float x) {
	int k = *((int *) &x) & ~0x80000000;

	if (k < 0x00800000) {
		if (k == 0)
			return (raise_division(-1.0F));
		else if ((__xpg6 & _C99SUSv3_logb) != 0) {
#if defined(__x86)
			x *= two25;
			return ((float) (((*((int *) &x) & 0x7f800000) >> 23) -
				152));
#else
			return ((float) ilogbf_subnormal(k));
#endif
		} else
			return (-126.F);
	} else if (k < 0x7f800000)
		return ((float) ((k >> 23) - 127));
	else
		return (x * x);
}
