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

#pragma weak __erf = erf
#pragma weak __erfc = erfc

/* INDENT OFF */
/*
 * double erf(double x)
 * double erfc(double x)
 *			     x
 *		      2      |\
 *     erf(x)  =  ---------  | exp(-t*t)dt
 *		   sqrt(pi) \|
 *			     0
 *
 *     erfc(x) =  1-erf(x)
 *  Note that
 *		erf(-x) = -erf(x)
 *		erfc(-x) = 2 - erfc(x)
 *
 * Method:
 *	1. For |x| in [0, 0.84375]
 *	    erf(x)  = x + x*R(x^2)
 *          erfc(x) = 1 - erf(x)           if x in [-.84375,0.25]
 *                  = 0.5 + ((0.5-x)-x*R)  if x in [0.25,0.84375]
 *	   where R = P/Q where P is an odd poly of degree 8 and
 *	   Q is an odd poly of degree 10.
 *						 -57.90
 *			| R - (erf(x)-x)/x | <= 2
 *
 *
 *	   Remark. The formula is derived by noting
 *          erf(x) = (2/sqrt(pi))*(x - x^3/3 + x^5/10 - x^7/42 + ....)
 *	   and that
 *          2/sqrt(pi) = 1.128379167095512573896158903121545171688
 *	   is close to one. The interval is chosen because the fix
 *	   point of erf(x) is near 0.6174 (i.e., erf(x)=x when x is
 *	   near 0.6174), and by some experiment, 0.84375 is chosen to
 *	   guarantee the error is less than one ulp for erf.
 *
 *      2. For |x| in [0.84375,1.25], let s = |x| - 1, and
 *         c = 0.84506291151 rounded to single (24 bits)
 *         	erf(x)  = sign(x) * (c  + P1(s)/Q1(s))
 *         	erfc(x) = (1-c)  - P1(s)/Q1(s) if x > 0
 *			  1+(c+P1(s)/Q1(s))    if x < 0
 *         	|P1/Q1 - (erf(|x|)-c)| <= 2**-59.06
 *	   Remark: here we use the taylor series expansion at x=1.
 *		erf(1+s) = erf(1) + s*Poly(s)
 *			 = 0.845.. + P1(s)/Q1(s)
 *	   That is, we use rational approximation to approximate
 *			erf(1+s) - (c = (single)0.84506291151)
 *	   Note that |P1/Q1|< 0.078 for x in [0.84375,1.25]
 *	   where
 *		P1(s) = degree 6 poly in s
 *		Q1(s) = degree 6 poly in s
 *
 *      3. For x in [1.25,1/0.35(~2.857143)],
 *         	erfc(x) = (1/x)*exp(-x*x-0.5625+R1/S1)
 *         	erf(x)  = 1 - erfc(x)
 *	   where
 *		R1(z) = degree 7 poly in z, (z=1/x^2)
 *		S1(z) = degree 8 poly in z
 *
 *      4. For x in [1/0.35,28]
 *         	erfc(x) = (1/x)*exp(-x*x-0.5625+R2/S2) if x > 0
 *			= 2.0 - (1/x)*exp(-x*x-0.5625+R2/S2) if -6<x<0
 *			= 2.0 - tiny		(if x <= -6)
 *         	erf(x)  = sign(x)*(1.0 - erfc(x)) if x < 6, else
 *         	erf(x)  = sign(x)*(1.0 - tiny)
 *	   where
 *		R2(z) = degree 6 poly in z, (z=1/x^2)
 *		S2(z) = degree 7 poly in z
 *
 *      Note1:
 *	   To compute exp(-x*x-0.5625+R/S), let s be a single
 *	   precision number and s := x; then
 *		-x*x = -s*s + (s-x)*(s+x)
 *	        exp(-x*x-0.5626+R/S) =
 *			exp(-s*s-0.5625)*exp((s-x)*(s+x)+R/S);
 *      Note2:
 *	   Here 4 and 5 make use of the asymptotic series
 *			  exp(-x*x)
 *		erfc(x) ~ ---------- * ( 1 + Poly(1/x^2) )
 *			  x*sqrt(pi)
 *	   We use rational approximation to approximate
 *      	g(s)=f(1/x^2) = log(erfc(x)*x) - x*x + 0.5625
 *	   Here is the error bound for R1/S1 and R2/S2
 *      	|R1/S1 - f(x)|  < 2**(-62.57)
 *      	|R2/S2 - f(x)|  < 2**(-61.52)
 *
 *      5. For inf > x >= 28
 *         	erf(x)  = sign(x) *(1 - tiny)  (raise inexact)
 *         	erfc(x) = tiny*tiny (raise underflow) if x > 0
 *			= 2 - tiny if x<0
 *
 *      7. Special case:
 *         	erf(0)  = 0, erf(inf)  = 1, erf(-inf) = -1,
 *         	erfc(0) = 1, erfc(inf) = 0, erfc(-inf) = 2,
 *   	erfc/erf(NaN) is NaN
 */
/* INDENT ON */

#include "libm_macros.h"
#include <math.h>

static const double xxx[] = {
/* tiny */	1e-300,
/* half */	5.00000000000000000000e-01,	/* 3FE00000, 00000000 */
/* one */	1.00000000000000000000e+00,	/* 3FF00000, 00000000 */
/* two */	2.00000000000000000000e+00,	/* 40000000, 00000000 */
/* erx */	8.45062911510467529297e-01,	/* 3FEB0AC1, 60000000 */
/*
 * Coefficients for approximation to  erf on [0,0.84375]
 */
/* efx */	 1.28379167095512586316e-01,	/* 3FC06EBA, 8214DB69 */
/* efx8 */	 1.02703333676410069053e+00,	/* 3FF06EBA, 8214DB69 */
/* pp0 */	 1.28379167095512558561e-01,	/* 3FC06EBA, 8214DB68 */
/* pp1 */	-3.25042107247001499370e-01,	/* BFD4CD7D, 691CB913 */
/* pp2 */	-2.84817495755985104766e-02,	/* BF9D2A51, DBD7194F */
/* pp3 */	-5.77027029648944159157e-03,	/* BF77A291, 236668E4 */
/* pp4 */	-2.37630166566501626084e-05,	/* BEF8EAD6, 120016AC */
/* qq1 */	 3.97917223959155352819e-01,	/* 3FD97779, CDDADC09 */
/* qq2 */	 6.50222499887672944485e-02,	/* 3FB0A54C, 5536CEBA */
/* qq3 */	 5.08130628187576562776e-03,	/* 3F74D022, C4D36B0F */
/* qq4 */	 1.32494738004321644526e-04,	/* 3F215DC9, 221C1A10 */
/* qq5 */	-3.96022827877536812320e-06,	/* BED09C43, 42A26120 */
/*
 * Coefficients for approximation to  erf  in [0.84375,1.25]
 */
/* pa0 */	-2.36211856075265944077e-03,	/* BF6359B8, BEF77538 */
/* pa1 */	 4.14856118683748331666e-01,	/* 3FDA8D00, AD92B34D */
/* pa2 */	-3.72207876035701323847e-01,	/* BFD7D240, FBB8C3F1 */
/* pa3 */	 3.18346619901161753674e-01,	/* 3FD45FCA, 805120E4 */
/* pa4 */	-1.10894694282396677476e-01,	/* BFBC6398, 3D3E28EC */
/* pa5 */	 3.54783043256182359371e-02,	/* 3FA22A36, 599795EB */
/* pa6 */	-2.16637559486879084300e-03,	/* BF61BF38, 0A96073F */
/* qa1 */	 1.06420880400844228286e-01,	/* 3FBB3E66, 18EEE323 */
/* qa2 */	 5.40397917702171048937e-01,	/* 3FE14AF0, 92EB6F33 */
/* qa3 */	 7.18286544141962662868e-02,	/* 3FB2635C, D99FE9A7 */
/* qa4 */	 1.26171219808761642112e-01,	/* 3FC02660, E763351F */
/* qa5 */	 1.36370839120290507362e-02,	/* 3F8BEDC2, 6B51DD1C */
/* qa6 */	 1.19844998467991074170e-02,	/* 3F888B54, 5735151D */
/*
 * Coefficients for approximation to  erfc in [1.25,1/0.35]
 */
/* ra0 */	-9.86494403484714822705e-03,	/* BF843412, 600D6435 */
/* ra1 */	-6.93858572707181764372e-01,	/* BFE63416, E4BA7360 */
/* ra2 */	-1.05586262253232909814e+01,	/* C0251E04, 41B0E726 */
/* ra3 */	-6.23753324503260060396e+01,	/* C04F300A, E4CBA38D */
/* ra4 */	-1.62396669462573470355e+02,	/* C0644CB1, 84282266 */
/* ra5 */	-1.84605092906711035994e+02,	/* C067135C, EBCCABB2 */
/* ra6 */	-8.12874355063065934246e+01,	/* C0545265, 57E4D2F2 */
/* ra7 */	-9.81432934416914548592e+00,	/* C023A0EF, C69AC25C */
/* sa1 */	 1.96512716674392571292e+01,	/* 4033A6B9, BD707687 */
/* sa2 */	 1.37657754143519042600e+02,	/* 4061350C, 526AE721 */
/* sa3 */	 4.34565877475229228821e+02,	/* 407B290D, D58A1A71 */
/* sa4 */	 6.45387271733267880336e+02,	/* 40842B19, 21EC2868 */
/* sa5 */	 4.29008140027567833386e+02,	/* 407AD021, 57700314 */
/* sa6 */	 1.08635005541779435134e+02,	/* 405B28A3, EE48AE2C */
/* sa7 */	 6.57024977031928170135e+00,	/* 401A47EF, 8E484A93 */
/* sa8 */	-6.04244152148580987438e-02,	/* BFAEEFF2, EE749A62 */
/*
 * Coefficients for approximation to  erfc in [1/.35,28]
 */
/* rb0 */	-9.86494292470009928597e-03,	/* BF843412, 39E86F4A */
/* rb1 */	-7.99283237680523006574e-01,	/* BFE993BA, 70C285DE */
/* rb2 */	-1.77579549177547519889e+01,	/* C031C209, 555F995A */
/* rb3 */	-1.60636384855821916062e+02,	/* C064145D, 43C5ED98 */
/* rb4 */	-6.37566443368389627722e+02,	/* C083EC88, 1375F228 */
/* rb5 */	-1.02509513161107724954e+03,	/* C0900461, 6A2E5992 */
/* rb6 */	-4.83519191608651397019e+02,	/* C07E384E, 9BDC383F */
/* sb1 */	 3.03380607434824582924e+01,	/* 403E568B, 261D5190 */
/* sb2 */	 3.25792512996573918826e+02,	/* 40745CAE, 221B9F0A */
/* sb3 */	 1.53672958608443695994e+03,	/* 409802EB, 189D5118 */
/* sb4 */	 3.19985821950859553908e+03,	/* 40A8FFB7, 688C246A */
/* sb5 */	 2.55305040643316442583e+03,	/* 40A3F219, CEDF3BE6 */
/* sb6 */	 4.74528541206955367215e+02,	/* 407DA874, E79FE763 */
/* sb7 */	-2.24409524465858183362e+01	/* C03670E2, 42712D62 */
};

#define	tiny	xxx[0]
#define	half	xxx[1]
#define	one	xxx[2]
#define	two	xxx[3]
#define	erx	xxx[4]
/*
 * Coefficients for approximation to  erf on [0,0.84375]
 */
#define	efx	xxx[5]
#define	efx8	xxx[6]
#define	pp0	xxx[7]
#define	pp1	xxx[8]
#define	pp2	xxx[9]
#define	pp3	xxx[10]
#define	pp4	xxx[11]
#define	qq1	xxx[12]
#define	qq2	xxx[13]
#define	qq3	xxx[14]
#define	qq4	xxx[15]
#define	qq5	xxx[16]
/*
 * Coefficients for approximation to  erf  in [0.84375,1.25]
 */
#define	pa0	xxx[17]
#define	pa1	xxx[18]
#define	pa2	xxx[19]
#define	pa3	xxx[20]
#define	pa4	xxx[21]
#define	pa5	xxx[22]
#define	pa6	xxx[23]
#define	qa1	xxx[24]
#define	qa2	xxx[25]
#define	qa3	xxx[26]
#define	qa4	xxx[27]
#define	qa5	xxx[28]
#define	qa6	xxx[29]
/*
 * Coefficients for approximation to  erfc in [1.25,1/0.35]
 */
#define	ra0	xxx[30]
#define	ra1	xxx[31]
#define	ra2	xxx[32]
#define	ra3	xxx[33]
#define	ra4	xxx[34]
#define	ra5	xxx[35]
#define	ra6	xxx[36]
#define	ra7	xxx[37]
#define	sa1	xxx[38]
#define	sa2	xxx[39]
#define	sa3	xxx[40]
#define	sa4	xxx[41]
#define	sa5	xxx[42]
#define	sa6	xxx[43]
#define	sa7	xxx[44]
#define	sa8	xxx[45]
/*
 * Coefficients for approximation to  erfc in [1/.35,28]
 */
#define	rb0	xxx[46]
#define	rb1	xxx[47]
#define	rb2	xxx[48]
#define	rb3	xxx[49]
#define	rb4	xxx[50]
#define	rb5	xxx[51]
#define	rb6	xxx[52]
#define	sb1	xxx[53]
#define	sb2	xxx[54]
#define	sb3	xxx[55]
#define	sb4	xxx[56]
#define	sb5	xxx[57]
#define	sb6	xxx[58]
#define	sb7	xxx[59]

double
erf(double x) {
	int hx, ix, i;
	double R, S, P, Q, s, y, z, r;

	hx = ((int *) &x)[HIWORD];
	ix = hx & 0x7fffffff;
	if (ix >= 0x7ff00000) {	/* erf(nan)=nan */
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
		if (ix >= 0x7ff80000)		/* assumes sparc-like QNaN */
			return (x);
#endif
		i = ((unsigned) hx >> 31) << 1;
		return ((double) (1 - i) + one / x);	/* erf(+-inf)=+-1 */
	}

	if (ix < 0x3feb0000) {	/* |x|<0.84375 */
		if (ix < 0x3e300000) {	/* |x|<2**-28 */
			if (ix < 0x00800000)	/* avoid underflow */
				return (0.125 * (8.0 * x + efx8 * x));
			return (x + efx * x);
		}
		z = x * x;
		r = pp0 + z * (pp1 + z * (pp2 + z * (pp3 + z * pp4)));
		s = one +
			z *(qq1 + z * (qq2 + z * (qq3 + z * (qq4 + z * qq5))));
		y = r / s;
		return (x + x * y);
	}
	if (ix < 0x3ff40000) {	/* 0.84375 <= |x| < 1.25 */
		s = fabs(x) - one;
		P = pa0 + s * (pa1 + s * (pa2 + s * (pa3 + s * (pa4 +
			s * (pa5 + s * pa6)))));
		Q = one + s * (qa1 + s * (qa2 + s * (qa3 + s * (qa4 +
			s * (qa5 + s * qa6)))));
		if (hx >= 0)
			return (erx + P / Q);
		else
			return (-erx - P / Q);
	}
	if (ix >= 0x40180000) {	/* inf > |x| >= 6 */
		if (hx >= 0)
			return (one - tiny);
		else
			return (tiny - one);
	}
	x = fabs(x);
	s = one / (x * x);
	if (ix < 0x4006DB6E) {	/* |x| < 1/0.35 */
		R = ra0 + s * (ra1 + s * (ra2 + s * (ra3 + s * (ra4 +
			s * (ra5 + s * (ra6 + s * ra7))))));
		S = one + s * (sa1 + s * (sa2 + s * (sa3 + s * (sa4 +
			s * (sa5 + s * (sa6 + s * (sa7 + s * sa8)))))));
	} else {			/* |x| >= 1/0.35 */
		R = rb0 + s * (rb1 + s * (rb2 + s * (rb3 + s * (rb4 +
			s * (rb5 + s * rb6)))));
		S = one + s * (sb1 + s * (sb2 + s * (sb3 + s * (sb4 +
			s * (sb5 + s * (sb6 + s * sb7))))));
	}
	z = x;
	((int *) &z)[LOWORD] = 0;
	r = exp(-z * z - 0.5625) * exp((z - x) * (z + x) + R / S);
	if (hx >= 0)
		return (one - r / x);
	else
		return (r / x - one);
}

double
erfc(double x) {
	int hx, ix;
	double R, S, P, Q, s, y, z, r;

	hx = ((int *) &x)[HIWORD];
	ix = hx & 0x7fffffff;
	if (ix >= 0x7ff00000) {	/* erfc(nan)=nan */
#if defined(FPADD_TRAPS_INCOMPLETE_ON_NAN)
		if (ix >= 0x7ff80000)		/* assumes sparc-like QNaN */
			return (x);
#endif
		/* erfc(+-inf)=0,2 */
		return ((double) (((unsigned) hx >> 31) << 1) + one / x);
	}

	if (ix < 0x3feb0000) {	/* |x| < 0.84375 */
		if (ix < 0x3c700000)	/* |x| < 2**-56 */
			return (one - x);
		z = x * x;
		r = pp0 + z * (pp1 + z * (pp2 + z * (pp3 + z * pp4)));
		s = one +
			z * (qq1 + z * (qq2 + z * (qq3 + z * (qq4 + z * qq5))));
		y = r / s;
		if (hx < 0x3fd00000) {	/* x < 1/4 */
			return (one - (x + x * y));
		} else {
			r = x * y;
			r += (x - half);
			return (half - r);
		}
	}
	if (ix < 0x3ff40000) {	/* 0.84375 <= |x| < 1.25 */
		s = fabs(x) - one;
		P = pa0 + s * (pa1 + s * (pa2 + s * (pa3 + s * (pa4 +
			s * (pa5 + s * pa6)))));
		Q = one + s * (qa1 + s * (qa2 + s * (qa3 + s * (qa4 +
			s * (qa5 + s * qa6)))));
		if (hx >= 0) {
			z = one - erx;
			return (z - P / Q);
		} else {
			z = erx + P / Q;
			return (one + z);
		}
	}
	if (ix < 0x403c0000) {	/* |x|<28 */
		x = fabs(x);
		s = one / (x * x);
		if (ix < 0x4006DB6D) {	/* |x| < 1/.35 ~ 2.857143 */
			R = ra0 + s * (ra1 + s * (ra2 + s * (ra3 + s * (ra4 +
				s * (ra5 + s * (ra6 + s * ra7))))));
			S = one + s * (sa1 + s * (sa2 + s * (sa3 + s * (sa4 +
				s * (sa5 + s * (sa6 + s * (sa7 + s * sa8)))))));
		} else {
			/* |x| >= 1/.35 ~ 2.857143 */
			if (hx < 0 && ix >= 0x40180000)
				return (two - tiny);	/* x < -6 */

			R = rb0 + s * (rb1 + s * (rb2 + s * (rb3 + s * (rb4 +
				s * (rb5 + s * rb6)))));
			S = one + s * (sb1 + s * (sb2 + s * (sb3 + s * (sb4 +
				s * (sb5 + s * (sb6 + s * sb7))))));
		}
		z = x;
		((int *) &z)[LOWORD] = 0;
		r = exp(-z * z - 0.5625) * exp((z - x) * (z + x) + R / S);
		if (hx > 0)
			return (r / x);
		else
			return (two - r / x);
	} else {
		if (hx > 0)
			return (tiny * tiny);
		else
			return (two - tiny);
	}
}
