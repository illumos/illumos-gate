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

#pragma weak log = __log

/* INDENT OFF */
/*
 * log(x)
 * Table look-up algorithm with product polynomial approximation.
 * By K.C. Ng, Oct 23, 2004. Updated Oct 18, 2005.
 *
 * (a). For x in [1-0.125, 1+0.1328125], using a special approximation:
 *	Let f = x - 1 and z = f*f.
 *	return f + ((a1*z) *
 *		   ((a2 + (a3*f)*(a4+f)) + (f*z)*(a5+f))) *
 *		   (((a6 + f*(a7+f)) + (f*z)*(a8+f)) *
 *		   ((a9 + (a10*f)*(a11+f)) + (f*z)*(a12+f)))
 * a1   -6.88821452420390473170286327331268694251775741577e-0002,
 * a2    1.97493380704769294631262255279580131173133850098e+0000,
 * a3    2.24963218866067560242072431719861924648284912109e+0000,
 * a4   -9.02975906958474405783476868236903101205825805664e-0001,
 * a5   -1.47391630715542865104339398385491222143173217773e+0000,
 * a6    1.86846544648220058704168877738993614912033081055e+0000,
 * a7    1.82277370459347465292410106485476717352867126465e+0000,
 * a8    1.25295479915214102994980294170090928673744201660e+0000,
 * a9    1.96709676945198275177517643896862864494323730469e+0000,
 * a10  -4.00127989749189894030934055990655906498432159424e-0001,
 * a11   3.01675528558798333733648178167641162872314453125e+0000,
 * a12  -9.52325445049240770778453679668018594384193420410e-0001,
 *
 *	with remez error |(log(1+f) - P(f))/f| <= 2**-56.81 and
 *
 * (b). For 0.09375 <= x < 24
 *	Use an 8-bit table look-up (3-bit for exponent and 5 bit for
 *	significand):
 *	Let ix stands for the high part of x in IEEE double format.
 *	Since 0.09375 <= x < 24, we have
 *			0x3fb80000 <= ix < 0x40380000.
 *	Let j = (ix - 0x3fb80000) >> 15. Then  0 <= j < 256. Choose
 *	a Y[j] such that HIWORD(Y[j]) ~ 0x3fb8400 + (j<<15) (the middle
 *	number between 0x3fb80000 + (j<<15) and 3fb80000 + ((j+1)<<15)),
 *	and at the same time 1/Y[j] as well as log(Y[j]) are very close
 *	to 53-bits floating point numbers.
 *	A table of Y[j], 1/Y[j], and log(Y[j]) are pre-computed and thus
 *		log(x)  = log(Y[j]) + log(1 + (x-Y[j])*(1/Y[j]))
 *			= log(Y[j]) + log(1 + s)
 *	where
 *		s = (x-Y[j])*(1/Y[j])
 *	We compute max (x-Y[j])*(1/Y[j]) for the chosen Y[j] and obtain
 *	|s| < 0.0154. By applying remez algorithm with Product Polynomial
 *	Approximiation, we find the following approximated of log(1+s)
 *		(b1*s)*(b2+s*(b3+s))*((b4+s*b5)+(s*s)*(b6+s))*(b7+s*(b8+s))
 *	with remez error |log(1+s) - P(s)| <= 2**-63.5
 *
 * (c). Otherwise, get "n", the exponent of x, and then normalize x to
 *	z in [1,2). Then similar to (b) find a Y[i] that matches z to 5.5
 *	significant bits. Then
 *	    log(x) = n*ln2 + log(Y[i]) + log(z/Y[i]).
 *
 * Special cases:
 *	log(x) is NaN with signal if x < 0 (including -INF) ;
 *	log(+INF) is +INF; log(0) is -INF with signal;
 *	log(NaN) is that NaN with no signal.
 *
 * Maximum error observed: less than 0.90 ulp
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
/* LN2HI */  6.93147180369123816490e-01,	/* 3fe62e42, fee00000 */
/* LN2LO */  1.90821492927058770002e-10,	/* 3dea39ef, 35793c76 */
/* A1    */ -6.88821452420390473170286327331268694251775741577e-0002,
/* A2    */  1.97493380704769294631262255279580131173133850098e+0000,
/* A3    */  2.24963218866067560242072431719861924648284912109e+0000,
/* A4    */ -9.02975906958474405783476868236903101205825805664e-0001,
/* A5    */ -1.47391630715542865104339398385491222143173217773e+0000,
/* A6    */  1.86846544648220058704168877738993614912033081055e+0000,
/* A7    */  1.82277370459347465292410106485476717352867126465e+0000,
/* A8    */  1.25295479915214102994980294170090928673744201660e+0000,
/* A9    */  1.96709676945198275177517643896862864494323730469e+0000,
/* A10   */ -4.00127989749189894030934055990655906498432159424e-0001,
/* A11   */  3.01675528558798333733648178167641162872314453125e+0000,
/* A12   */ -9.52325445049240770778453679668018594384193420410e-0001,
/* B1    */ -1.25041641589283658575482149899471551179885864258e-0001,
/* B2    */  1.87161713283355151891381127914642725337613123482e+0000,
/* B3    */ -1.89082956295731507978530316904652863740921020508e+0000,
/* B4    */ -2.50562891673640253387134180229622870683670043945e+0000,
/* B5    */  1.64822828085258366037635369139024987816810607910e+0000,
/* B6    */ -1.24409107065868340669112512841820716857910156250e+0000,
/* B7    */  1.70534231658220414296067701798165217041969299316e+0000,
/* B8    */  1.99196833784655646937267192697618156671524047852e+0000,
};

#define	ONE   P[0]
#define	TWO52 P[1]
#define	LN2HI P[2]
#define	LN2LO P[3]
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

double
log(double x) {
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
			return (_SVID_libm_err(x, x, 16));
		if (hx < 0)				/* negative */
			return (_SVID_libm_err(x, x, 17));
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
		if (ix >= 0x3fec0000 && ix < 0x3ff22000) {
			/* 0.875 <= x < 1.125 */
			s = x - ONE;
			z = s * s;
			if (((ix - 0x3ff00000) | lx) == 0) /* x = 1 */
				return (z);
			r = (A10 * s) * (A11 + s);
			w = z * s;
			return (s + ((A1 * z) *
				(A2 + ((A3 * s) * (A4 + s) + w * (A5 + s)))) *
				((A6 + (s * (A7 + s) + w * (A8 + s))) *
				(A9 + (r + w * (A12 + s)))));
		} else {
			i = (ix - 0x3fb80000) >> 15;
			tb = (double *)_TBL_log + (i + i + i);
			s = (x - tb[0]) * tb[1];
			return (tb[2] +  ((B1 * s) * (B2 + s * (B3 + s))) *
				(((B4 + s * B5) + (s * s) * (B6 + s)) *
				(B7 + s * (B8 + s))));
		}
	} else {
		dn = (double)(n + ((ix >> 20) - 0x3ff));
		dn1 = dn * LN2HI;
		i = (ix & 0x000fffff) | 0x3ff00000;	/* scale x to [1,2] */
		((int *)&x)[HIWORD] = i;
		i = (i - 0x3fb80000) >> 15;
		tb = (double *)_TBL_log + (i + i + i);
		s = (x - tb[0]) * tb[1];
		dn = dn * LN2LO + tb[2];
		return (dn1 + (dn + ((B1 * s) * (B2 + s * (B3 + s))) *
			(((B4 + s * B5) + (s * s) * (B6 + s)) *
			(B7 + s * (B8 + s)))));
	}
}
