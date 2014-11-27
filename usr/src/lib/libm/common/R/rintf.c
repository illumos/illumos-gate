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

#pragma weak __rintf = rintf

/* INDENT OFF */
/*
 * aintf(x)	return x chopped to integral value
 * anintf(x)	return sign(x)*(|x|+0.5) chopped to integral value
 * irintf(x)	return rint(x) in integer format
 * nintf(x)	return anint(x) in integer format
 * rintf(x)	return x rounded to integral according to the rounding direction
 *
 * NOTE: rintf(x), aintf(x) and anintf(x) return results with the same sign as
 * x's,  including 0.0.
 */

#include "libm.h"

static const float xf[] = {
/* ZEROF */	0.0f,
/* TWO_23F */	8.3886080000e6f,
/* MTWO_23F */	-8.3886080000e6f,
/* ONEF */	1.0f,
/* MONEF */	-1.0f,
/* HALFF */	0.5f,
/* MHALFF */	-0.5f,
/* HUGEF */	1.0e30f,
};

#define	ZEROF		xf[0]
#define	TWO_23F		xf[1]
#define	MTWO_23F	xf[2]
#define	ONEF		xf[3]
#define	MONEF		xf[4]
#define	HALFF		xf[5]
#define	MHALFF		xf[6]
#define	HUGEF		xf[7]
/* INDENT ON */

float
aintf(float x) {
	int hx, k;
	float y;

	hx = *(int *) &x;
	k = (hx & ~0x80000000) >> 23;
	if (k < 150) {
		y = (float) ((int) x);
		/*
		 * make sure y has the same sign of x when |x|<0.5
		 * (i.e., y=0.0)
		 */
		return (((k - 127) & hx) < 0 ? -y : y);
	} else
		/* signal invalid if x is a SNaN */
		return (x * ONEF);		/* +0 -> *1 for Cheetah */
}

float
anintf(float x) {
	volatile float dummy;
	int hx, k, j, ix;

	hx = *(int *) &x;
	ix = hx & ~0x80000000;
	k = ix >> 23;
	if (((k - 127) ^ (k - 150)) < 0) {
		j = 1 << (149 - k);
		k = j + j - 1;
		if ((k & hx) != 0)
			dummy = HUGEF + x;	/* raise inexact */
		*(int *) &x = (hx + j) & ~k;
		return (x);
	} else if (k <= 126) {
		dummy = HUGEF + x;
		*(int *) &x = (0x3f800000 & ((125 - k) >> 31)) |
			(0x80000000 & hx);
		return (x);
	} else
		/* signal invalid if x is a SNaN */
		return (x * ONEF);		/* +0 -> *1 for Cheetah */
}

int
irintf(float x) {
	float v;
	int hx, k;

	hx = *(int *) &x;
	k = (hx & ~0x80000000) >> 23;
	v = xf[((k - 150) >> 31) & (1 - (hx >> 31))];
	return ((int) ((float) (x + v) - v));
}

int
nintf(float x) {
	int hx, ix, k, j, m;
	volatile float dummy;

	hx = *(int *) &x;
	k = (hx & ~0x80000000) >> 23;
	if (((k - 126) ^ (k - 150)) < 0) {
		ix = (hx & 0x00ffffff) | 0x800000;
		m = 149 - k;
		j = 1 << m;
		if ((ix & (j + j - 1)) != 0)
			dummy = HUGEF + x;
		hx = hx >> 31;
		return ((((ix + j) >> (m + 1)) ^ hx) - hx);
	} else
		return ((int) x);
}

float
rintf(float x) {
	float w, v;
	int hx, k;

	hx = *(int *) &x;
	k = (hx & ~0x80000000) >> 23;
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
	if (k >= 150)
		return (x * ONEF);
	v = xf[1 - (hx >> 31)];
#else
	v = xf[((k - 150) >> 31) & (1 - (hx >> 31))];
#endif
	w = (float) (x + v);
	if (k < 127 && w == v)
		return (ZEROF * x);
	else
		return (w - v);
}
