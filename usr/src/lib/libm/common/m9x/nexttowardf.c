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
#pragma weak nexttowardf = __nexttowardf
#endif

#include "libm.h"

static union {
	unsigned i;
	float f;
} C[] = {
	0x00800000,
	0x7f000000,
	0x7fffffff
};

#define	tiny	C[0].f
#define	huge	C[1].f
#define	qnan	C[2].f

#if defined(__sparc)

enum fcc_type {
	fcc_equal = 0,
	fcc_less = 1,
	fcc_greater = 2,
	fcc_unordered = 3
};

#ifdef __sparcv9
#define	_Q_cmp	_Qp_cmp
#endif

extern enum fcc_type _Q_cmp(const long double *, const long double *);

float
__nexttowardf(float x, long double y) {
	union {
		unsigned i;
		float f;
	} xx;
	union {
		unsigned i[4];
		long double q;
	} yy;
	long double lx;
	unsigned hx;
	volatile float dummy;
	enum fcc_type rel;

	/*
	 * It would be somewhat more efficient to check for NaN and
	 * zero operands before converting x to long double and then
	 * to code the comparison in line rather than calling _Q_cmp.
	 * However, since this code probably won't get used much,
	 * I'm opting in favor of simplicity instead.
	 */
	lx = xx.f = x;
	hx = xx.i & ~0x80000000;

	/* check for each of four possible orderings */
	rel = _Q_cmp(&lx, &y);
	if (rel == fcc_unordered)
		return (qnan);

	if (rel == fcc_equal) {
		if (hx == 0) {	/* x is zero; return zero with y's sign */
			yy.q = y;
			xx.i = yy.i[0];
			return (xx.f);
		}
		return (x);
	}

	if (rel == fcc_less) {
		if (hx == 0)	/* x is zero */
			xx.i = 0x00000001;
		else if ((int) xx.i >= 0)	/* x is positive */
			xx.i++;
		else
			xx.i--;
	} else {
		if (hx == 0)	/* x is zero */
			xx.i = 0x80000001;
		else if ((int) xx.i >= 0)	/* x is positive */
			xx.i--;
		else
			xx.i++;
	}

	/* raise exceptions as needed */
	hx = xx.i & ~0x80000000;
	if (hx == 0x7f800000) {
		dummy = huge;
		dummy *= huge;
	} else if (hx < 0x00800000) {
		dummy = tiny;
		dummy *= tiny;
	}

	return (xx.f);
}

#elif defined(__x86)

float
__nexttowardf(float x, long double y) {
	union {
		unsigned i;
		float f;
	} xx;
	unsigned hx;
	long double lx;
	volatile float dummy;

	lx = xx.f = x;
	hx = xx.i & ~0x80000000;

	/* check for each of four possible orderings */
	if (isunordered(lx, y))
		return ((float) (lx + y));

	if (lx == y)
		return ((float) y);

	if (lx < y) {
		if (hx == 0)	/* x is zero */
			xx.i = 0x00000001;
		else if ((int) xx.i >= 0)	/* x is positive */
			xx.i++;
		else
			xx.i--;
	} else {
		if (hx == 0)	/* x is zero */
			xx.i = 0x80000001;
		else if ((int) xx.i >= 0)	/* x is positive */
			xx.i--;
		else
			xx.i++;
	}

	/* raise exceptions as needed */
	hx = xx.i & ~0x80000000;
	if (hx == 0x7f800000) {
		dummy = huge;
		dummy *= huge;
	} else if (hx < 0x00800000) {
		dummy = tiny;
		dummy *= tiny;
	}

	return (xx.f);
}

#else
#error Unknown architecture
#endif
