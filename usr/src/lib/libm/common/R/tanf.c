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

#pragma weak tanf = __tanf

#include "libm.h"

extern const int _TBL_ipio2_inf[];
extern int __rem_pio2m(double *, double *, int, int, int, const int *);
#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

static const double C[] = {
	1.0,
	4.46066928428959230679140546271810308098793029785e-0003,
	4.92165316309189027066395283327437937259674072266e+0000,
	-7.11410648161473480044492134766187518835067749023e-0001,
	4.08549808374053391446523164631798863410949707031e+0000,
	2.50411070398050927821032018982805311679840087891e+0000,
	1.11492064560251158411574579076841473579406738281e+0001,
	-1.50565540968422650891511693771462887525558471680e+0000,
	-1.81484378878349295050043110677506774663925170898e+0000,
	3.333335997532835641297409611782510896641e-0001,
	2.999997598248363761541668282006867229939e+00,
	0.636619772367581343075535,	/* 2^ -1  * 1.45F306DC9C883 */
	0.5,
	1.570796326734125614166,	/* 2^  0  * 1.921FB54400000 */
	6.077100506506192601475e-11,	/* 2^-34  * 1.0B4611A626331 */
};

#define	one	C[0]
#define	P0	C[1]
#define	P1	C[2]
#define	P2	C[3]
#define	P3	C[4]
#define	P4	C[5]
#define	P5	C[6]
#define	P6	C[7]
#define	P7	C[8]
#define	T0	C[9]
#define	T1	C[10]
#define	invpio2	C[11]
#define	half	C[12]
#define	pio2_1  C[13]
#define	pio2_t	C[14]

float
tanf(float x)
{
	double	y, z, w;
	float	f;
	int	n, ix, hx, hy;
	volatile int i;

	hx = *((int *)&x);
	ix = hx & 0x7fffffff;

	y = (double)x;

	if (ix <= 0x4016cbe4) {		/* |x| < 3*pi/4 */
		if (ix <= 0x3f490fdb) {		/* |x| < pi/4 */
			if (ix < 0x3c000000) {		/* |x| < 2**-7 */
				if (ix <= 0x39800000) {	/* |x| < 2**-12 */
					i = (int)y;
#ifdef lint
					i = i;
#endif
					return (x);
				}
				return ((float)((y * T0) * (T1 + y * y)));
			}
			z = y * y;
			return ((float)(((P0 * y) * (P1 + z * (P2 + z)) *
			    (P3 + z * (P4 + z))) *
			    (P5 + z * (P6 + z * (P7 + z)))));
		}
		if (hx > 0)
			y = (y - pio2_1) - pio2_t;
		else
			y = (y + pio2_1) + pio2_t;
		hy = ((int *)&y)[HIWORD] & ~0x80000000;
		if (hy < 0x3f800000) {		/* |y| < 2**-7 */
			z = (y * T0) * (T1 + y * y);
			return ((float)(-one / z));
		}
		z = y * y;
		w = ((P0 * y) * (P1 + z * (P2 + z)) * (P3 + z * (P4 + z))) *
		    (P5 + z * (P6 + z * (P7 + z)));
		return ((float)(-one / w));
	}

	if (ix <= 0x49c90fdb) {	/* |x| < 2^19*pi */
#if defined(__i386) && !defined(__amd64)
		int	rp;

		rp = __swapRP(fp_extended);
#endif
		w = y * invpio2;
		if (hx < 0)
			n = (int)(w - half);
		else
			n = (int)(w + half);
		y = (y - n * pio2_1) - n * pio2_t;
#if defined(__i386) && !defined(__amd64)
		if (rp != fp_extended)
			(void) __swapRP(rp);
#endif
	} else {
		if (ix >= 0x7f800000)
			return (x / x);	/* sin(Inf or NaN) is NaN */
		hy = ((int *)&y)[HIWORD];
		n = ((hy >> 20) & 0x7ff) - 1046;
		((int *)&w)[HIWORD] = (hy & 0xfffff) | 0x41600000;
		((int *)&w)[LOWORD] = ((int *)&y)[LOWORD];
		n = __rem_pio2m(&w, &y, n, 1, 0, _TBL_ipio2_inf);
		if (hy < 0) {
			y = -y;
			n = -n;
		}
	}

	hy = ((int *)&y)[HIWORD] & ~0x80000000;
	if (hy < 0x3f800000) {		/* |y| < 2**-7 */
		z = (y * T0) * (T1 + y * y);
		f = ((n & 1) == 0)? (float)z : (float)(-one / z);
		return (f);
	}
	z = y * y;
	w = ((P0 * y) * (P1 + z * (P2 + z)) * (P3 + z * (P4 + z))) *
	    (P5 + z * (P6 + z * (P7 + z)));
	f = ((n & 1) == 0)? (float)w : (float)(-one / w);
	return (f);
}
