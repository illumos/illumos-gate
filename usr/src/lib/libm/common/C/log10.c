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

#pragma weak __log10 = log10

/* INDENT OFF */
/*
 * log10(x) = log(x)/log10
 *
 * Base on Table look-up algorithm with product polynomial
 * approximation for log(x).
 *
 * By K.C. Ng, Nov 29, 2004
 *
 * (a). For x in [1-0.125, 1+0.125], from log.c we have
 *	log(x) =  f + ((a1*f^2) *
 *		   ((a2 + (a3*f)*(a4+f)) + (f^3)*(a5+f))) *
 *		   (((a6 + f*(a7+f)) + (f^3)*(a8+f)) *
 *		   ((a9 + (a10*f)*(a11+f)) + (f^3)*(a12+f)))
 *	where f = x - 1.
 *	(i) modify a1 <- a1 / log10
 *	(ii) 1/log10 = 0.4342944819...
 *		     = 0.4375 - 0.003205518... (7 bit shift)
 *	     Let lgv = 0.4375 - 1/log10, then
 *	     lgv = 0.003205518096748172348871081083395...,
 *	(iii) f*0.4375 is exact because f has 3 trailing zero.
 *	(iv) Thus, log10(x) = f*0.4375 - (lgv*f - PPoly)
 *
 * (b). For 0.09375 <= x < 24
 *	Let j = (ix - 0x3fb80000) >> 15. Look up Y[j], 1/Y[j], and log(Y[j])
 *	from _TBL_log.c. Then
 *		log10(x)  = log10(Y[j]) + log10(1 + (x-Y[j])*(1/Y[j]))
 *			  = log(Y[j])(1/log10) + log10(1 + s)
 *	where
 *		s = (x-Y[j])*(1/Y[j])
 *	From log.c, we have log(1+s) =
 *				  2              2                     2
 *		(b s) (b + b s + s ) [b + b s + s (b + s)] (b + b s + s )
 *		  1     2   3          4   5        6        7   8
 *
 *	By setting b1 <- b1/log10, we have
 *		log10(x) = 0.4375 * T - (lgv * T - POLY(s))
 *
 * (c). Otherwise, get "n", the exponent of x, and then normalize x to
 *	z in [1,2). Then similar to (b) find a Y[i] that matches z to 5.5
 *	significant bits. Then
 *	    log(x) = n*ln2 + log(Y[i]) + log(z/Y[i]).
 *	    log10(x) = n*(ln2/ln10) + log10(z).
 *
 * Special cases:
 *	log10(x) is NaN with signal if x < 0 (including -INF) ;
 *	log10(+INF) is +INF; log10(0) is -INF with signal;
 *	log10(NaN) is that NaN with no signal.
 *
 * Maximum error observed: less than 0.89 ulp
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following constants.
 * The decimal values may be used, provided that the compiler will convert
 * from decimal to binary accurately enough to produce the hexadecimal values
 * shown.
 */
/* INDENT ON */

#include "libm.h"

extern const double _TBL_log[];

static const double P[] = {
/* ONE   */  1.0,
/* TWO52 */  4503599627370496.0,
/* LNAHI */  3.01029995607677847147e-01,	/* 3FD34413 50900000 */
/* LNALO */  5.63033480667509769841e-11,	/* 3DCEF3FD E623E256 */
/* A1    */ -2.9142521960136582507385480707044582802184e-02,
/* A2    */  1.99628461483039965074226529395673424005508422852e+0000,
/* A3    */  2.26812367662950720159642514772713184356689453125e+0000,
/* A4    */ -9.05030639084976384900471657601883634924888610840e-0001,
/* A5    */ -1.48275767132434044270894446526654064655303955078e+0000,
/* A6    */  1.88158320939722756293122074566781520843505859375e+0000,
/* A7    */  1.83309386046986411145098827546462416648864746094e+0000,
/* A8    */  1.24847063988317086291601754055591300129890441895e+0000,
/* A9    */  1.98372421445537705508854742220137268304824829102e+0000,
/* A10   */ -3.94711735767898475035764249696512706577777862549e-0001,
/* A11   */  3.07890395362954372160402272129431366920471191406e+0000,
/* A12   */ -9.60099585275022149311041630426188930869102478027e-0001,
/* B1    */ -5.4304894950350052960838096752491540286689e-02,
/* B2    */  1.87161713283355151891381127914642725337613123482e+0000,
/* B3    */ -1.89082956295731507978530316904652863740921020508e+0000,
/* B4    */ -2.50562891673640253387134180229622870683670043945e+0000,
/* B5    */  1.64822828085258366037635369139024987816810607910e+0000,
/* B6    */ -1.24409107065868340669112512841820716857910156250e+0000,
/* B7    */  1.70534231658220414296067701798165217041969299316e+0000,
/* B8    */  1.99196833784655646937267192697618156671524047852e+0000,
/* LGH   */  0.4375,
/* LGL   */  0.003205518096748172348871081083395,
/* LG10V */  0.43429448190325182765112891891660509576226,
};

#define	ONE   P[0]
#define	TWO52 P[1]
#define	LNAHI P[2]
#define	LNALO P[3]
#define	A1    P[4]
#define	A2    P[5]
#define	A3    P[6]
#define	A4    P[7]
#define	A5    P[8]
#define	A6    P[9]
#define	A7    P[10]
#define	A8    P[11]
#define	A9    P[12]
#define	A10   P[13]
#define	A11   P[14]
#define	A12   P[15]
#define	B1    P[16]
#define	B2    P[17]
#define	B3    P[18]
#define	B4    P[19]
#define	B5    P[20]
#define	B6    P[21]
#define	B7    P[22]
#define	B8    P[23]
#define	LGH   P[24]
#define	LGL   P[25]
#define	LG10V P[26]

double
log10(double x) {
	double	*tb, dn, dn1, s, z, r, w;
	int	i, hx, ix, n, lx;

	n = 0;
	hx = ((int *)&x)[HIWORD];
	ix = hx & 0x7fffffff;
	lx = ((int *)&x)[LOWORD];

	/* subnormal,0,negative,inf,nan */
	if ((hx + 0x100000) < 0x200000) {
		if (ix > 0x7ff00000 || (ix == 0x7ff00000 && lx != 0)) /* nan */
			return (x * x);
		if (((hx << 1) | lx) == 0)		/* zero */
			return (_SVID_libm_err(x, x, 18));
		if (hx < 0)				/* negative */
			return (_SVID_libm_err(x, x, 19));
		if (((hx - 0x7ff00000) | lx) == 0)	/* +inf */
			return (x);

		/* x must be positive and subnormal */
		x *= TWO52;
		n = -52;
		ix = ((int *)&x)[HIWORD];
		lx = ((int *)&x)[LOWORD];
	}

	i = ix >> 19;
	if (i >= 0x7f7 && i <= 0x806) {
		/* 0.09375 (0x3fb80000) <= x < 24 (0x40380000) */
		if (ix >= 0x3fec0000 && ix < 0x3ff20000) {
			/* 0.875 <= x < 1.125 */
			s = x - ONE;
			z = s * s;
			if (((ix - 0x3ff00000) | lx) == 0) /* x = 1 */
				return (z);
			r = (A10 * s) * (A11 + s);
			w = z * s;
			return (LGH * s - (LGL * s - ((A1 * z) *
				((A2 + (A3 * s) * (A4 + s)) + w * (A5 + s))) *
				(((A6 + s * (A7 + s)) + w * (A8 + s)) *
				((A9 + r) + w * (A12 + s)))));
		} else {
			i = (ix - 0x3fb80000) >> 15;
			tb = (double *)_TBL_log + (i + i + i);
			s = (x - tb[0]) * tb[1];
			return (LGH * tb[2] - (LGL * tb[2] - ((B1 * s) *
				(B2 + s * (B3 + s))) *
				(((B4 + s * B5) + (s * s) * (B6 + s)) *
				(B7 + s * (B8 + s)))));
		}
	} else {
		dn = (double)(n + ((ix >> 20) - 0x3ff));
		dn1 = dn * LNAHI;
		i = (ix & 0x000fffff) | 0x3ff00000;	/* scale x to [1,2] */
		((int *)&x)[HIWORD] = i;
		i = (i - 0x3fb80000) >> 15;
		tb = (double *)_TBL_log + (i + i + i);
		s = (x - tb[0]) * tb[1];
		dn = dn * LNALO + tb[2] * LG10V;
		return (dn1 + (dn + ((B1 * s) *
			(B2 + s * (B3 + s))) *
			(((B4 + s * B5) + (s * s) * (B6 + s)) *
			(B7 + s * (B8 + s)))));
	}
}
