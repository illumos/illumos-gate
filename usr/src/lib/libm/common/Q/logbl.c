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

#pragma weak __logbl = logbl

#include "libm.h"
#include "xpg6.h"	/* __xpg6 */
#define	_C99SUSv3_logb	_C99SUSv3_logb_subnormal_is_like_ilogb

#if defined(__sparc)
#define	ISNORMALL(k, x)	(k != 0x7fff)			/* assuming k != 0 */
#define	X86PDNRM(k, x)
#define	XSCALE_OFFSET	0x406f				/* 0x3fff + 112 */
static const long double xscale = 5192296858534827628530496329220096.0L;
								/* 2^112 */
#elif defined(__x86)
/*
 * if pseudo-denormal, replace by the equivalent normal
 */
#define	X86PDNRM(k, x)	if (k == 0 && (((int *) &x)[1] & 0x80000000) != 0) \
				((int *) &x)[2] |= k = 1
#if defined(HANDLE_UNSUPPORTED)				/* assuming k != 0 */
#define	ISNORMALL(k, x)	(k != 0x7fff && (((int *) &x)[1] & 0x80000000) != 0)
#else
#define	ISNORMALL(k, x)	(k != 0x7fff)
#endif
#define	XSCALE_OFFSET	0x403e				/* 0x3fff + 63 */
static const long double xscale = 9223372036854775808.0L;	/* 2^63 */
#endif

static long double
raise_division(long double v) {
#pragma STDC FENV_ACCESS ON
	static const long double zero = 0.0L;
	return (v / zero);
}

long double
logbl(long double x) {
	int k = XBIASED_EXP(x);

	X86PDNRM(k, x);
	if (k == 0) {
		if (ISZEROL(x))
			return (raise_division(-1.0L));
		else if ((__xpg6 & _C99SUSv3_logb) != 0) {
			x *= xscale;		/* scale up by 2^112 or 2^63 */
			return (long double) (XBIASED_EXP(x) - XSCALE_OFFSET);
		} else
			return (-16382.L);
	} else if (ISNORMALL(k, x))
		return ((long double) (k - 0x3fff));
	else
		return (x * x);
}
