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
#pragma weak nexttowardl = __nexttowardl
#endif

#include "libm.h"
#include <float.h>		/* LDBL_MAX, LDBL_MIN */

#if defined(__sparc)
#define	n0	0
#define	n1	1
#define	n2	2
#define	n3	3
#define	X86PDNRM1(x)
#define	INC(px)	{ \
			if (++px[n3] == 0) \
				if (++px[n2] == 0) \
					if (++px[n1] == 0) \
						++px[n0]; \
		}
#define	DEC(px)	{ \
			if (--px[n3] == 0xffffffff) \
				if (--px[n2] == 0xffffffff) \
					if (--px[n1] == 0xffffffff) \
						--px[n0]; \
		}
#elif defined(__x86)
#define	n0	2
#define	n1	1
#define	n2	0
#define	n3	0
/*
 * if pseudo-denormal, replace by the equivalent normal
 */
#define	X86PDNRM1(x)	if (XBIASED_EXP(x) == 0 && (((int *) &x)[1] & \
				0x80000000) != 0) \
				((int *) &x)[2] |= 1
#define	INC(px)	{ \
			if (++px[n2] == 0) \
				if ((++px[n1] & ~0x80000000) == 0) \
					px[n1] = 0x80000000, ++px[n0]; \
		}
#define	DEC(px)	{ \
			if (--px[n2] == 0xffffffff) \
				if (--px[n1] == 0x7fffffff) \
					if ((--px[n0] & 0x7fff) != 0) \
						px[n1] |= 0x80000000; \
		}
#endif

long double
nexttowardl(long double x, long double y) {
	int *px = (int *) &x;
	int *py = (int *) &y;

	if (x == y)
		return (y);		/* C99 requirement */
	if (x != x || y != y)
		return (x * y);

	if (ISZEROL(x)) {	/* x == 0.0 */
		px[n0] = py[n0] & XSGNMSK;
		px[n1] = px[n2] = 0;
		px[n3] = 1;
	} else {
		X86PDNRM1(x);
		if ((px[n0] & XSGNMSK) == 0) {	/* x > 0.0 */
			if (x > y)	/* x > y */
				DEC(px)
			else
				INC(px)
		} else {
			if (x < y)	/* x < y */
				DEC(px)
			else
				INC(px)
		}
	}
#ifndef lint
	{
		volatile long double dummy;
		int k = XBIASED_EXP(x);

		if (k == 0)
			dummy = LDBL_MIN * copysignl(LDBL_MIN, x);
		else if (k == 0x7fff)
			dummy = LDBL_MAX * copysignl(LDBL_MAX, x);
	}
#endif
	return (x);
}
