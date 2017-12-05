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

#pragma weak __cosf = cosf

/*
 * See sincosf.c
 */

#include "libm.h"

extern const int _TBL_ipio2_inf[];
extern int __rem_pio2m(double *, double *, int, int, int, const int *);
#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

static const double C[] = {
	1.85735322054308378716204874632872525989806770558e-0003,
	-1.95035094218403635082921458859320791358115801259e-0004,
	5.38400550766074785970952495168558701485841707252e+0002,
	-3.31975110777873728964197739157371509422022905947e+0001,
	1.09349482127188401868272000389539985058873853699e-0003,
	-5.03324285989964979398034700054920226866107675091e-0004,
	2.43792880266971107750418061559602239831538067410e-0005,
	9.14499072605666582228127405245558035523741471271e+0002,
	-3.63151270591815439197122504991683846785293207730e+0001,
	0.636619772367581343075535,	/* 2^ -1  * 1.45F306DC9C883 */
	0.5,
	1.570796326734125614166,	/* 2^  0  * 1.921FB54400000 */
	6.077100506506192601475e-11,	/* 2^-34  * 1.0B4611A626331 */
};

#define	S0	C[0]
#define	S1	C[1]
#define	S2	C[2]
#define	S3	C[3]
#define	C0	C[4]
#define	C1	C[5]
#define	C2	C[6]
#define	C3	C[7]
#define	C4	C[8]
#define	invpio2	C[9]
#define	half	C[10]
#define	pio2_1  C[11]
#define	pio2_t	C[12]

float
cosf(float x)
{
	double	y, z, w;
	float	f;
	int	n, ix, hx, hy;
	volatile int i __unused;

	hx = *((int *)&x);
	ix = hx & 0x7fffffff;

	y = (double)x;

	if (ix <= 0x4016cbe4) {		/* |x| < 3*pi/4 */
		if (ix <= 0x3f490fdb) {		/* |x| < pi/4 */
			if (ix <= 0x39800000) {	/* |x| <= 2**-12 */
				i = (int)y;
#ifdef lint
				i = i;
#endif
				return (1.0f);
			}
			z = y * y;
			return ((float)(((C0 + z * C1) + (z * z) * C2) *
			    (C3 + z * (C4 + z))));
		} else if (hx > 0) {
			y = (y - pio2_1) - pio2_t;
			z = y * y;
			return ((float)-((y * (S0 + z * S1)) *
			    (S2 + z * (S3 + z))));
		} else {
			y = (y + pio2_1) + pio2_t;
			z = y * y;
			return ((float)((y * (S0 + z * S1)) *
			    (S2 + z * (S3 + z))));
		}
	} else if (ix <= 0x49c90fdb) {	/* |x| < 2^19*pi */
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
		n++;
#if defined(__i386) && !defined(__amd64)
		if (rp != fp_extended)
			(void) __swapRP(rp);
#endif
	} else {
		if (ix >= 0x7f800000)
			return (x / x); /* cos(Inf or NaN) is NaN */
		hy = ((int *)&y)[HIWORD];
		n = ((hy >> 20) & 0x7ff) - 1046;
		((int *)&w)[HIWORD] = (hy & 0xfffff) | 0x41600000;
		((int *)&w)[LOWORD] = ((int *)&y)[LOWORD];
		n = __rem_pio2m(&w, &y, n, 1, 0, _TBL_ipio2_inf) + 1;
	}

	if (n & 1) {
		/* compute cos y */
		z = y * y;
		f = (float)(((C0 + z * C1) + (z * z) * C2) *
		    (C3 + z * (C4 + z)));
	} else {
		/* compute sin y */
		z = y * y;
		f = (float)((y * (S0 + z * S1)) * (S2 + z * (S3 + z)));
	}

	return ((n & 2)? -f : f);
}
