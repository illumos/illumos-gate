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

#pragma weak __sincos = sincos

/* INDENT OFF */
/*
 * sincos(x,s,c)
 * Accurate Table look-up algorithm by K.C. Ng, 2000.
 *
 * 1. Reduce x to x>0 by cos(-x)=cos(x), sin(-x)=-sin(x).
 * 2. For 0<= x < 8, let i = (64*x chopped)-10. Let d = x - a[i], where
 *    a[i] is a double that is close to (i+10.5)/64 (and hence |d|< 10.5/64)
 *    and such that sin(a[i]) and cos(a[i]) is close to a double (with error
 *    less than 2**-8 ulp). Then
 *
 *	cos(x) = cos(a[i]+d) = cos(a[i])cos(d) - sin(a[i])*sin(d)
 *	       = TBL_cos_a[i]*(1+QQ1*d^2+QQ2*d^4) -
 *			TBL_sin_a[i]*(d+PP1*d^3+PP2*d^5)
 *	       = TBL_cos_a[i] + (TBL_cos_a[i]*d^2*(QQ1+QQ2*d^2) -
 *			TBL_sin_a[i]*(d+PP1*d^3+PP2*d^5))
 *
 *      sin(x) = sin(a[i]+d) = sin(a[i])cos(d) + cos(a[i])*sin(d)
 *             = TBL_sin_a[i]*(1+QQ1*d^2+QQ2*d^4) +
 *			TBL_cos_a[i]*(d+PP1*d^3+PP2*d^5)
 *             = TBL_sin_a[i] + (TBL_sin_a[i]*d^2*(QQ1+QQ2*d^2) +
 *			TBL_cos_a[i]*(d+PP1*d^3+PP2*d^5))
 *
 *    Note: for x close to n*pi/2, special treatment is need for either
 *    sin or cos:
 *    i in [81, 100] (  pi/2 +-10.5/64 => tiny cos(x) = sin(pi/2-x)
 *    i in [181,200] (  pi   +-10.5/64 => tiny sin(x) = sin(pi-x)
 *    i in [282,301] (  3pi/2+-10.5/64 => tiny cos(x) = sin(x-3pi/2)
 *    i in [382,401] (  2pi  +-10.5/64 => tiny sin(x) = sin(x-2pi)
 *    i in [483,502] (  5pi/2+-10.5/64 => tiny cos(x) = sin(5pi/2-x)
 *
 * 3. For x >= 8.0, use kernel function __rem_pio2 to perform argument
 *    reduction and call __k_sincos_ to compute sin and cos.
 *
 * kernel function:
 *	__rem_pio2	... argument reduction routine
 *	__k_sincos_	... sine and cosine function on [-pi/4,pi/4]
 *
 * Method.
 *      Let S and C denote the sin and cos respectively on [-PI/4, +PI/4].
 *      1. Assume the argument x is reduced to y1+y2 = x-k*pi/2 in
 *	   [-pi/2 , +pi/2], and let n = k mod 4.
 *	2. Let S=S(y1+y2), C=C(y1+y2). Depending on n, we have
 *
 *          n        sin(x)      cos(x)        tan(x)
 *     ----------------------------------------------------------
 *	    0	       S	   C		 S/C
 *	    1	       C	  -S		-C/S
 *	    2	      -S	  -C		 S/C
 *	    3	      -C	   S		-C/S
 *     ----------------------------------------------------------
 *
 * Special cases:
 *      Let trig be any of sin, cos, or tan.
 *      trig(+-INF)  is NaN, with signals;
 *      trig(NaN)    is that NaN;
 *
 * Accuracy:
 *	TRIG(x) returns trig(x) nearly rounded (less than 1 ulp)
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
/* Q1  	= */ -0.5,
/* Q2  	= */  4.166666666500350703680945520860748617445e-0002,
/* Q3  	= */ -1.388888596436972210694266290577848696006e-0003,
/* Q4  	= */  2.478563078858589473679519517892953492192e-0005,
/* PIO2_H    = */  1.570796326794896557999,
/* PIO2_L    = */  6.123233995736765886130e-17,
/* PIO2_L0   = */  6.123233995727922165564e-17,
/* PIO2_L1   = */  8.843720566135701120255e-29,
/* PI_H      = */  3.1415926535897931159979634685,
/* PI_L      = */  1.22464679914735317722606593227425e-16,
/* PI_L0     = */  1.22464679914558443311283879205095e-16,
/* PI_L1     = */  1.768744113227140223300005233735517376e-28,
/* PI3O2_H   = */  4.712388980384689673997,
/* PI3O2_L   = */  1.836970198721029765839e-16,
/* PI3O2_L0  = */  1.836970198720396133587e-16,
/* PI3O2_L1  = */  6.336322524749201142226e-29,
/* PI2_H     = */  6.2831853071795862319959269370,
/* PI2_L     = */  2.44929359829470635445213186454850e-16,
/* PI2_L0    = */  2.44929359829116886622567758410190e-16,
/* PI2_L1    = */  3.537488226454280446600010467471034752e-28,
/* PI5O2_H   = */  7.853981633974482789995,
/* PI5O2_L   = */  3.061616997868382943065e-16,
/* PI5O2_L0  = */  3.061616997861941598865e-16,
/* PI5O2_L1  = */  6.441344200433640781982e-28,
};
/* INDENT ON */

#define	ONE		sc[0]
#define	PP1		sc[2]
#define	PP2		sc[3]
#define	P1		sc[4]
#define	P2		sc[5]
#define	P3		sc[6]
#define	P4		sc[7]
#define	QQ1		sc[8]
#define	QQ2		sc[9]
#define	Q1		sc[10]
#define	Q2		sc[11]
#define	Q3		sc[12]
#define	Q4		sc[13]
#define	PIO2_H		sc[14]
#define	PIO2_L		sc[15]
#define	PIO2_L0		sc[16]
#define	PIO2_L1		sc[17]
#define	PI_H		sc[18]
#define	PI_L		sc[19]
#define	PI_L0		sc[20]
#define	PI_L1		sc[21]
#define	PI3O2_H		sc[22]
#define	PI3O2_L		sc[23]
#define	PI3O2_L0	sc[24]
#define	PI3O2_L1	sc[25]
#define	PI2_H		sc[26]
#define	PI2_L		sc[27]
#define	PI2_L0		sc[28]
#define	PI2_L1		sc[29]
#define	PI5O2_H		sc[30]
#define	PI5O2_L		sc[31]
#define	PI5O2_L0	sc[32]
#define	PI5O2_L1	sc[33]
#define	PoS(x, z)	((x * z) * (PP1 + z * PP2))
#define	PoL(x, z)	((x * z) * ((P1 + z * P2) + (z * z) * (P3 + z * P4)))

extern const double _TBL_sincos[], _TBL_sincosx[];

void
sincos(double x, double *s, double *c) {
	double	z, y[2], w, t, v, p, q;
	int	i, j, n, hx, ix, lx;

	hx = ((int *)&x)[HIWORD];
	lx = ((int *)&x)[LOWORD];
	ix = hx & ~0x80000000;

	if (ix <= 0x3fc50000) {	/* |x| < 10.5/64 = 0.164062500 */
		if (ix < 0x3e400000) {	/* |x| < 2**-27 */
			if ((int)x == 0)
				*c = ONE;
			*s = x;
		} else {
			z = x * x;
			if (ix < 0x3f800000) {	/* |x| < 0.008 */
				q = z * (QQ1 + z * QQ2);
				p = PoS(x, z);
			} else {
				q = z * ((Q1 + z * Q2) + (z * z) *
				    (Q3 + z * Q4));
				p = PoL(x, z);
			}
			*c = ONE + q;
			*s = x + p;
		}
		return;
	}

	n = ix >> 20;
	i = (((ix >> 12) & 0xff) | 0x100) >> (0x401 - n);
	j = i - 10;
	if (n < 0x402) {	/* |x| < 8 */
		x = fabs(x);
		v = x - _TBL_sincosx[j];
		t = v * v;
		w = _TBL_sincos[(j<<1)];
		z = _TBL_sincos[(j<<1)+1];
		p = v + PoS(v, t);
		q = t * (QQ1 + t * QQ2);
		if ((((j - 81) ^ (j - 101)) |
		    ((j - 282) ^ (j - 302)) |
		    ((j - 483) ^ (j - 503)) |
		    ((j - 181) ^ (j - 201)) |
		    ((j - 382) ^ (j - 402))) < 0) {
			if (j <= 101) {
				/* near pi/2, cos(x) = sin(pi/2-x) */
				t = w * q + z * p;
				*s = (hx >= 0)? w + t : -w - t;
				p = PIO2_H - x;
				i = ix - 0x3ff921fb;
				x = p + PIO2_L;
				if ((i | ((lx - 0x54442D00) &
				    0xffffff00)) == 0) {
					/* very close to pi/2 */
					x = p + PIO2_L0;
					*c = x + PIO2_L1;
				} else {
					z = x * x;
					if (((ix - 0x3ff92000) >> 12) == 0) {
						/* |pi/2-x|<2**-8 */
						w = PIO2_L + PoS(x, z);
					} else {
						w = PIO2_L + PoL(x, z);
					}
					*c = p + w;
				}
			} else if (j <= 201) {
				/* near pi, sin(x) = sin(pi-x) */
				*c = z - (w * p - z * q);
				p = PI_H - x;
				i = ix - 0x400921fb;
				x = p + PI_L;
				if ((i | ((lx - 0x54442D00) &
				    0xffffff00)) == 0) {
					/* very close to pi */
					x = p + PI_L0;
					*s = (hx >= 0)? x + PI_L1 :
					    -(x + PI_L1);
				} else {
					z = x * x;
					if (((ix - 0x40092000) >> 11) == 0) {
						/* |pi-x|<2**-8 */
						w = PI_L + PoS(x, z);
					} else {
						w = PI_L + PoL(x, z);
					}
					*s = (hx >= 0)? p + w : -p - w;
				}
			} else if (j <= 302) {
				/* near 3/2pi, cos(x)=sin(x-3/2pi) */
				t = w * q + z * p;
				*s = (hx >= 0)? w + t : -w - t;
				p = x - PI3O2_H;
				i = ix - 0x4012D97C;
				x = p - PI3O2_L;
				if ((i | ((lx - 0x7f332100) &
				    0xffffff00)) == 0) {
					/* very close to 3/2pi */
					x = p - PI3O2_L0;
					*c = x - PI3O2_L1;
				} else {
					z = x * x;
					if (((ix - 0x4012D800) >> 9) == 0) {
						/* |3/2pi-x|<2**-8 */
						w = PoS(x, z) - PI3O2_L;
					} else {
						w = PoL(x, z) - PI3O2_L;
					}
					*c = p + w;
				}
			} else if (j <= 402) {
				/* near 2pi, sin(x)=sin(x-2pi) */
				*c = z - (w * p - z * q);
				p = x - PI2_H;
				i = ix - 0x401921fb;
				x = p - PI2_L;
				if ((i | ((lx - 0x54442D00) &
				    0xffffff00)) == 0) {
					/* very close to 2pi */
					x = p - PI2_L0;
					*s = (hx >= 0)? x - PI2_L1 :
					    -(x - PI2_L1);
				} else {
					z = x * x;
					if (((ix - 0x40192000) >> 10) == 0) {
						/* |x-2pi|<2**-8 */
						w = PoS(x, z) - PI2_L;
					} else {
						w = PoL(x, z) - PI2_L;
					}
					*s = (hx >= 0)? p + w : -p - w;
				}
			} else {
				/* near 5pi/2, cos(x) = sin(5pi/2-x) */
				t = w * q + z * p;
				*s = (hx >= 0)? w + t : -w - t;
				p = PI5O2_H - x;
				i = ix - 0x401F6A7A;
				x = p + PI5O2_L;
				if ((i | ((lx - 0x29553800) &
				    0xffffff00)) == 0) {
					/* very close to pi/2 */
					x = p + PI5O2_L0;
					*c = x + PI5O2_L1;
				} else {
					z = x * x;
					if (((ix - 0x401F6A7A) >> 7) == 0) {
						/* |5pi/2-x|<2**-8 */
						w = PI5O2_L + PoS(x, z);
					} else {
						w = PI5O2_L + PoL(x, z);
					}
					*c = p + w;
				}
			}
		} else {
			*c = z - (w * p - z * q);
			t = w * q + z * p;
			*s = (hx >= 0)? w + t : -w - t;
		}
		return;
	}

	if (ix >= 0x7ff00000) {
		*s = *c = x / x;
		return;
	}

	/* argument reduction needed */
	n = __rem_pio2(x, y);
	switch (n & 3) {
	case 0:
		*s = __k_sincos(y[0], y[1], c);
		break;
	case 1:
		*c = -__k_sincos(y[0], y[1], s);
		break;
	case 2:
		*s = -__k_sincos(y[0], y[1], c);
		*c = -*c;
		break;
	default:
		*c = __k_sincos(y[0], y[1], s);
		*s = -*s;
	}
}
