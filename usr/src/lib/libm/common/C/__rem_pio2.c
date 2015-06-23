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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * __rem_pio2(x, y) passes back a better-than-double-precision
 * approximation to x mod pi/2 in y[0]+y[1] and returns an integer
 * congruent mod 8 to the integer part of x/(pi/2).
 *
 * This implementation tacitly assumes that x is finite and at
 * least about pi/4 in magnitude.
 */

#include "libm.h"

extern const int _TBL_ipio2_inf[];

/* INDENT OFF */
/*
 * invpio2:  53 bits of 2/pi
 * pio2_1:   first  33 bit of pi/2
 * pio2_1t:  pi/2 - pio2_1
 * pio2_2:   second 33 bit of pi/2
 * pio2_2t:  pi/2 - pio2_2
 * pio2_3:   third  33 bit of pi/2
 * pio2_3t:  pi/2 - pio2_3
 */
static const double
	half	= 0.5,
	invpio2	= 0.636619772367581343075535,	/* 2^ -1  * 1.45F306DC9C883 */
	pio2_1	= 1.570796326734125614166,	/* 2^  0  * 1.921FB54400000 */
	pio2_1t	= 6.077100506506192601475e-11,	/* 2^-34  * 1.0B4611A626331 */
	pio2_2	= 6.077100506303965976596e-11,	/* 2^-34  * 1.0B4611A600000 */
	pio2_2t	= 2.022266248795950732400e-21,	/* 2^-69  * 1.3198A2E037073 */
	pio2_3	= 2.022266248711166455796e-21,	/* 2^-69  * 1.3198A2E000000 */
	pio2_3t	= 8.478427660368899643959e-32;	/* 2^-104 * 1.B839A252049C1 */
/* INDENT ON */

int
__rem_pio2(double x, double *y) {
	double	w, t, r, fn;
	double	tx[3];
	int	e0, i, j, nx, n, ix, hx, lx;

	hx = ((int *)&x)[HIWORD];
	ix = hx & 0x7fffffff;

	if (ix < 0x4002d97c) {
		/* |x| < 3pi/4, special case with n=1 */
		t = fabs(x) - pio2_1;
		if (ix != 0x3ff921fb) {	/* 33+53 bit pi is good enough */
			y[0] = t - pio2_1t;
			y[1] = (t - y[0]) - pio2_1t;
		} else {		/* near pi/2, use 33+33+53 bit pi */
			t -= pio2_2;
			y[0] = t - pio2_2t;
			y[1] = (t - y[0]) - pio2_2t;
		}
		if (hx < 0) {
			y[0] = -y[0];
			y[1] = -y[1];
			return (-1);
		}
		return (1);
	}

	if (ix <= 0x413921fb) {
		/* |x| <= 2^19 pi */
		t = fabs(x);
		n = (int)(t * invpio2 + half);
		fn = (double)n;
		r = t - fn * pio2_1;
		j = ix >> 20;
		w = fn * pio2_1t;	/* 1st round good to 85 bit */
		y[0] = r - w;
		i = j - ((((int *)y)[HIWORD] >> 20) & 0x7ff);
		if (i > 16) {	/* 2nd iteration (rare) */
			/* 2nd round good to 118 bit */
			if (i < 35) {
				t = r;	/* r-fn*pio2_2 may not be exact */
				w = fn * pio2_2;
				r = t - w;
				w = fn * pio2_2t - ((t - r) - w);
				y[0] = r - w;
			} else {
				r -= fn * pio2_2;
				w = fn * pio2_2t;
				y[0] = r - w;
				i = j - ((((int *)y)[HIWORD] >> 20) & 0x7ff);
				if (i > 49) {
					/* 3rd iteration (extremely rare) */
					if (i < 68) {
						t = r;
						w = fn * pio2_3;
						r = t - w;
						w = fn * pio2_3t -
						    ((t - r) - w);
						y[0] = r - w;
					} else {
						/*
						 * 3rd round good to 151 bits;
						 * covered all possible cases
						 */
						r -= fn * pio2_3;
						w = fn * pio2_3t;
						y[0] = r - w;
					}
				}
			}
		}
		y[1] = (r - y[0]) - w;
		if (hx < 0) {
			y[0] = -y[0];
			y[1] = -y[1];
			return (-n);
		}
		return (n);
	}

	e0 = (ix >> 20) - 1046;	/* e0 = ilogb(x)-23; */

	/* break x into three 24 bit pieces */
	lx = ((int *)&x)[LOWORD];
	i = (lx & 0x1f) << 19;
	tx[2] = (double)i;
	j = (lx >> 5) & 0xffffff;
	tx[1] = (double)j;
	tx[0] = (double)((((ix & 0xfffff) | 0x100000) << 3) |
	    ((unsigned)lx >> 29));
	nx = 3;
	if (i == 0) {
		/* skip zero term */
		nx--;
		if (j == 0)
			nx--;
	}
	n = __rem_pio2m(tx, y, e0, nx, 2, _TBL_ipio2_inf);
	if (hx < 0) {
		y[0] = -y[0];
		y[1] = -y[1];
		return (-n);
	}
	return (n);
}
