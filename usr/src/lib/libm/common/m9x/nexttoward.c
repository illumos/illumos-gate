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
#pragma weak nexttoward = __nexttoward
#endif

/*
 * nexttoward(x, y) delivers the next representable number after x
 * in the direction of y.  If x and y are both zero, the result is
 * zero with the same sign as y.  If either x or y is NaN, the result
 * is NaN.
 *
 * If x != y and the result is infinite, overflow is raised; if
 * x != y and the result is subnormal or zero, underflow is raised.
 * (This is wrong, but it's what C99 apparently wants.)
 */

#include "libm.h"

#if defined(__sparc)

static union {
	unsigned i[2];
	double d;
} C[] = {
	0x00100000, 0,
	0x7fe00000, 0,
	0x7fffffff, 0xffffffff
};

#define	tiny	C[0].d
#define	huge	C[1].d
#define	qnan	C[2].d

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

double
__nexttoward(double x, long double y) {
	union {
		unsigned i[2];
		double d;
	} xx;
	union {
		unsigned i[4];
		long double q;
	} yy;
	long double lx;
	unsigned hx;
	volatile double	dummy;
	enum fcc_type rel;

	/*
	 * It would be somewhat more efficient to check for NaN and
	 * zero operands before converting x to long double and then
	 * to code the comparison in line rather than calling _Q_cmp.
	 * However, since this code probably won't get used much,
	 * I'm opting in favor of simplicity instead.
	 */
	lx = xx.d = x;
	hx = (xx.i[0] & ~0x80000000) | xx.i[1];

	/* check for each of four possible orderings */
	rel = _Q_cmp(&lx, &y);
	if (rel == fcc_unordered)
		return (qnan);

	if (rel == fcc_equal) {
		if (hx == 0) {	/* x is zero; return zero with y's sign */
			yy.q = y;
			xx.i[0] = yy.i[0];
			return (xx.d);
		}
		return (x);
	}

	if (rel == fcc_less) {
		if (hx == 0) {	/* x is zero */
			xx.i[0] = 0;
			xx.i[1] = 0x00000001;
		} else if ((int)xx.i[0] >= 0) {	/* x is positive */
			if (++xx.i[1] == 0)
				xx.i[0]++;
		} else {
			if (xx.i[1]-- == 0)
				xx.i[0]--;
		}
	} else {
		if (hx == 0) {	/* x is zero */
			xx.i[0] = 0x80000000;
			xx.i[1] = 0x00000001;
		} else if ((int)xx.i[0] >= 0) {	/* x is positive */
			if (xx.i[1]-- == 0)
				xx.i[0]--;
		} else {
			if (++xx.i[1] == 0)
				xx.i[0]++;
		}
	}

	/* raise exceptions as needed */
	hx = xx.i[0] & ~0x80000000;
	if (hx == 0x7ff00000) {
		dummy = huge;
		dummy *= huge;
	} else if (hx < 0x00100000) {
		dummy = tiny;
		dummy *= tiny;
	}

	return (xx.d);
}

#elif defined(__x86)

static union {
	unsigned i[2];
	double d;
} C[] = {
	0, 0x00100000,
	0, 0x7fe00000,
};

#define	tiny	C[0].d
#define	huge	C[1].d

double
__nexttoward(double x, long double y) {
	union {
		unsigned i[2];
		double d;
	} xx;
	unsigned hx;
	long double lx;
	volatile double	dummy;

	lx = xx.d = x;
	hx = (xx.i[1] & ~0x80000000) | xx.i[0];

	/* check for each of four possible orderings */
	if (isunordered(lx, y))
		return ((double) (lx + y));

	if (lx == y)
		return ((double) y);

	if (lx < y) {
		if (hx == 0) {	/* x is zero */
			xx.i[0] = 0x00000001;
			xx.i[1] = 0;
		} else if ((int)xx.i[1] >= 0) {	/* x is positive */
			if (++xx.i[0] == 0)
				xx.i[1]++;
		} else {
			if (xx.i[0]-- == 0)
				xx.i[1]--;
		}
	} else {
		if (hx == 0) {	/* x is zero */
			xx.i[0] = 0x00000001;
			xx.i[1] = 0x80000000;
		} else if ((int)xx.i[1] >= 0) {	/* x is positive */
			if (xx.i[0]-- == 0)
				xx.i[1]--;
		} else {
			if (++xx.i[0] == 0)
				xx.i[1]++;
		}
	}

	/* raise exceptions as needed */
	hx = xx.i[1] & ~0x80000000;
	if (hx == 0x7ff00000) {
		dummy = huge;
		dummy *= huge;
	} else if (hx < 0x00100000) {
		dummy = tiny;
		dummy *= tiny;
	}

	return (xx.d);
}

#else
#error Unknown architecture
#endif
