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

#pragma weak sin = __sin

/* INDENT OFF */
/*
 * sin(x)
 * Accurate Table look-up algorithm by K.C. Ng, May, 1995.
 *
 * Algorithm: see sincos.c
 */

#include "libm.h"

static const double sc[] = {
/* ONE	= */  1.0,
/* NONE	= */ -1.0,
/*
 * |sin(x) - (x+pp1*x^3+pp2*x^5)| <= 2^-58.79 for |x| < 0.008
 */
/* PP1	= */ -0.166666666666316558867252052378889521480627858683055567,
/* PP2	= */   .008333315652997472323564894248466758248475374977974017927,
/*
 * |(sin(x) - (x+p1*x^3+...+p4*x^9)|
 * |------------------------------ | <= 2^-57.63 for |x| < 0.1953125
 * |                 x             |
 */
/* P1  	= */ -1.666666666666629669805215138920301589656e-0001,
/* P2  	= */  8.333333332390951295683993455280336376663e-0003,
/* P3  	= */ -1.984126237997976692791551778230098403960e-0004,
/* P4  	= */  2.753403624854277237649987622848330351110e-0006,
/*
 * |cos(x) - (1+qq1*x^2+qq2*x^4)| <= 2^-55.99 for |x| <= 0.008 (0x3f80624d)
 */
/* QQ1	= */ -0.4999999999975492381842911981948418542742729,
/* QQ2	= */  0.041666542904352059294545209158357640398771740,
/* PI_H	= */  3.1415926535897931159979634685,
/* PI_L    = */  1.22464679914735317722606593227425e-16,
/* PI_L0   = */  1.22464679914558443311283879205095e-16,
/* PI_L1   = */  1.768744113227140223300005233735517376e-28,
/* PI2_H   = */  6.2831853071795862319959269370,
/* PI2_L   = */  2.44929359829470635445213186454850e-16,
/* PI2_L0  = */  2.44929359829116886622567758410190e-16,
/* PI2_L1  = */  3.537488226454280446600010467471034752e-28,
};
/* INDENT ON */

#define	ONEA	sc
#define	ONE	sc[0]
#define	NONE	sc[1]
#define	PP1	sc[2]
#define	PP2	sc[3]
#define	P1	sc[4]
#define	P2	sc[5]
#define	P3	sc[6]
#define	P4	sc[7]
#define	QQ1	sc[8]
#define	QQ2	sc[9]
#define	PI_H	sc[10]
#define	PI_L	sc[11]
#define	PI_L0	sc[12]
#define	PI_L1	sc[13]
#define	PI2_H	sc[14]
#define	PI2_L	sc[15]
#define	PI2_L0	sc[16]
#define	PI2_L1	sc[17]

extern const double  _TBL_sincos[], _TBL_sincosx[];

double
sin(double x) {
	double	z, y[2], w, s, v, p, q;
	int	i, j, n, hx, ix, lx;

	hx = ((int *)&x)[HIWORD];
	lx = ((int *)&x)[LOWORD];
	ix = hx & ~0x80000000;

	if (ix <= 0x3fc50000) {	/* |x| < .1640625 */
		if (ix < 0x3e400000)	/* |x| < 2**-27 */
			if ((int)x == 0)
				return (x);
		z = x * x;
		if (ix < 0x3f800000)	/* |x| < 2**-8 */
			w = (z * x) * (PP1 + z * PP2);
		else
			w = (x * z) * ((P1 + z * P2) + (z * z) * (P3 + z * P4));
		return (x + w);
	}

	/* for .1640625 < x < M, */
	n = ix >> 20;
	if (n < 0x402) {	/* x < 8 */
		i = (((ix >> 12) & 0xff) | 0x100) >> (0x401 - n);
		j = i - 10;
		x = fabs(x);
		v = x - _TBL_sincosx[j];
		if (((j - 181) ^ (j - 201)) < 0) {
			/* near pi, sin(x) = sin(pi-x) */
			p = PI_H - x;
			i = ix - 0x400921fb;
			x = p + PI_L;
			if ((i | ((lx - 0x54442D00) & 0xffffff00)) == 0) {
				/* very close to pi */
				x = p + PI_L0;
				return ((hx >= 0)? x + PI_L1 : -(x + PI_L1));
			}
			z = x * x;
			if (((ix - 0x40092000) >> 11) == 0) {
				/* |pi-x|<2**-8 */
				w = PI_L + (z * x) * (PP1 + z * PP2);
			} else {
				w = PI_L + (z * x) * ((P1 + z * P2) +
				    (z * z) * (P3 + z * P4));
			}
			return ((hx >= 0)? p + w : -p - w);
		}
		s = v * v;
		if (((j - 382) ^ (j - 402)) < 0) {
			/* near 2pi, sin(x) = sin(x-2pi) */
			p = x - PI2_H;
			i = ix - 0x401921fb;
			x = p - PI2_L;
			if ((i | ((lx - 0x54442D00) & 0xffffff00)) == 0) {
				/* very close to 2pi */
				x = p - PI2_L0;
				return ((hx >= 0)? x - PI2_L1 : -(x - PI2_L1));
			}
			z = x * x;
			if (((ix - 0x40192000) >> 10) == 0) {
				/* |x-2pi|<2**-8 */
				w = (z * x) * (PP1 + z * PP2) - PI2_L;
			} else {
				w = (z * x) * ((P1 + z * P2) +
				    (z * z) * (P3 + z * P4)) - PI2_L;
			}
			return ((hx >= 0)? p + w : -p - w);
		}
		j <<= 1;
		w = _TBL_sincos[j+1];
		z = _TBL_sincos[j];
		p = v + (v * s) * (PP1 + s * PP2);
		q = s * (QQ1 + s * QQ2);
		v = w * p + z * q;
		return ((hx >= 0)? z + v : -z - v);
	}

	if (ix >= 0x7ff00000)	/* sin(Inf or NaN) is NaN */
		return (x / x);

	/* argument reduction needed */
	n = __rem_pio2(x, y);
	switch (n & 3) {
	case 0:
		return (__k_sin(y[0], y[1]));
	case 1:
		return (__k_cos(y[0], y[1]));
	case 2:
		return (-__k_sin(y[0], y[1]));
	default:
		return (-__k_cos(y[0], y[1]));
	}
}
