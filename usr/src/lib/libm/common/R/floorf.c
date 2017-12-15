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

#pragma weak __ceilf = ceilf
#pragma weak __floorf = floorf

/* INDENT OFF */
/*
 * ceilf(x)	return the biggest integral value (in float) below x
 * floorf(x)	return the least integral value (in float) above x
 *
 * NOTE: ceilf(x) and floorf(x) return result
 * with the same sign as x's,  including 0.0F.
 */

#include "libm.h"

static const float xf[] = {
/* ZEROF */	0.0f,
/* ONEF */	1.0f,
/* MONEF */	-1.0f,
/* HUGEF */	1.0e30f,
};

#define	ZEROF	xf[0]
#define	ONEF	xf[1]
#define	MONEF	xf[2]
#define	HUGEF	xf[3]
/* INDENT ON */

float
ceilf(float x) {
	volatile float dummy __unused;
	int hx, k, j, ix;

	hx = *(int *) &x;
	ix = hx & ~0x80000000;
	k = ix >> 23;
	if (((k - 127) ^ (k - 150)) < 0) {
		k = (1 << (150 - k)) - 1;
		if ((k & hx) != 0)
			dummy = HUGEF + x;	/* raise inexact */
		j = k & (~(hx >> 31));
		*(int *) &x = (hx + j) & ~k;
		return (x);
	} else if (k <= 126) {
		dummy = HUGEF + x;
		if (hx > 0)
			return (ONEF);
		else if (ix == 0)
			return (x);
		else
			return (-ZEROF);
	} else
		/* signal invalid if x is a SNaN */
		return (x * ONEF);		/* +0 -> *1 for Cheetah */
}

float
floorf(float x) {
	volatile float dummy __unused;
	int hx, k, j, ix;

	hx = *(int *) &x;
	ix = hx & ~0x80000000;
	k = ix >> 23;
	if (((k - 127) ^ (k - 150)) < 0) {
		k = (1 << (150 - k)) - 1;
		if ((k & hx) != 0)
			dummy = HUGEF + x;	/* raise inexact */
		j = k & (hx >> 31);
		*(int *) &x = (hx + j) & ~k;
		return (x);
	} else if (k <= 126) {
		dummy = HUGEF + x;
		if (hx > 0)
			return (ZEROF);
		else if (ix == 0)
			return (x);
		else
			return (MONEF);
	} else
		/* signal invalid if x is a SNaN */
		return (x * ONEF);		/* +0 -> *1 for Cheetah */
}
