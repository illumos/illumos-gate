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

#include "libm.h"		/* __k_atan2 */
#include "complex_wrapper.h"

/*
 * double __k_atan2(double y, double x, double *e)
 *
 * Compute atan2 with error terms.
 *
 * Important formula:
 *                  3       5
 *                 x       x
 * atan(x) = x - ----- + ----- - ...	(for x <= 1)
 *                 3       5
 *
 *           pi     1     1
 *         = --- - --- + --- - ...	(for x > 1)
 *                         3
 *            2     x    3x
 *
 * Arg(x + y i) = sign(y) * atan2(|y|, x)
 *              = sign(y) * atan(|y|/x)		  (for x > 0)
 *                sign(y) * (PI - atan(|y|/|x|))  (for x < 0)
 * Thus if x >> y (IEEE double: EXP(x) - EXP(y) >= 60):
 *	1. (x > 0): atan2(y,x) ~ y/x
 *	2. (x < 0): atan2(y,x) ~ sign(y) (PI - |y/x|))
 * Otherwise if x << y:
 *	atan2(y,x) ~ sign(y)*PI/2 - x/y
 *
 * __k_atan2 call static functions mx_poly, mx_atan
 */

/*
 * (void) mx_poly (double *z, double *a, double *e, int n)
 * return
 *	e = a  + z*(a  + z*(a  + ... z*(a  + e)...))
 *	     0       2       4           2n
 * Note:
 * 1.	e and coefficient ai are represented by two double numbers.
 *	For e, the first one contain the leading 24 bits rounded, and the
 *	second one contain the remaining 53 bits (total 77 bits accuracy).
 *	For ai, the first one contian the leading 53 bits rounded, and the
 *	second is the remaining 53 bits (total 106 bits accuracy).
 * 2.	z is an array of three doubles.
 * 	z[0] :	the rounded value of Z (the intended value of z)
 * 	z[1] :	the leading 24 bits of Z rounded
 * 	z[2] :	the remaining 53 bits of Z
 *		Note that z[0] = z[1]+z[2] rounded.
 *
 */

static void
mx_poly(const double *z, const double *a, double *e, int n) {
	double r, s, t, p_h, p_l, z_h, z_l, p;
	int i;

	n = n + n;
	p = e[0] + a[n];
	p_l = a[n + 1];
	p_h = (double) ((float) p);
	p   = a[n - 2] + z[0] * p;
	z_h = z[1]; z_l = z[2];
	p_l += e[0] - (p_h - a[n]);

	for (i = n - 2; i >= 2; i -= 2) {
	/* compute p = ai + z * p */
		t   = z_h * p_h;
		s   = z[0] * p_l + p_h * z_l;
		p_h = (double) ((float) p);
		s  += a[i + 1];
		r   = t - (p_h - a[i]);
		p   = a[i - 2] + z[0] * p;
		p_l = r + s;
	}
	e[0] = (double)((float) p);
	t   = z_h * p_h;
	s   = z[0] * p_l + p_h * z_l;
	r   = t - (e[0] - a[0]);
	e[1] = r + s;
}

/*
 * Table of constants for atan from 0.125 to 8
 *	0.125 -- 0x3fc00000  --- (increment at bit 16)
 *		 0x3fc10000
 *		 0x3fc20000
 *	...	...
 *		 0x401f0000
 *	8.000 -- 0x40200000	 (total: 97)
 * By K.C. Ng, March 9, 1989
 */

static const double TBL_atan_hi[] = {
1.243549945467614382e-01, 1.320397616146387620e-01, 1.397088742891636204e-01,
1.473614810886516302e-01, 1.549967419239409727e-01, 1.626138285979485676e-01,
1.702119252854744080e-01, 1.777902289926760471e-01, 1.853479499956947607e-01,
1.928843122579746439e-01, 2.003985538258785115e-01, 2.078899272022629863e-01,
2.153576996977380476e-01, 2.228011537593945213e-01, 2.302195872768437179e-01,
2.376123138654712419e-01, 2.449786631268641435e-01, 2.596296294082575118e-01,
2.741674511196587893e-01, 2.885873618940774099e-01, 3.028848683749714166e-01,
3.170557532091470287e-01, 3.310960767041321029e-01, 3.450021772071051318e-01,
3.587706702705721895e-01, 3.723984466767542023e-01, 3.858826693980737521e-01,
3.992207695752525431e-01, 4.124104415973872673e-01, 4.254496373700422662e-01,
4.383365598579578304e-01, 4.510696559885234436e-01, 4.636476090008060935e-01,
4.883339510564055352e-01, 5.123894603107377321e-01, 5.358112379604637043e-01,
5.585993153435624414e-01, 5.807563535676704136e-01, 6.022873461349641522e-01,
6.231993299340659043e-01, 6.435011087932843710e-01, 6.632029927060932861e-01,
6.823165548747480713e-01, 7.008544078844501923e-01, 7.188299996216245269e-01,
7.362574289814280970e-01, 7.531512809621944138e-01, 7.695264804056582975e-01,
7.853981633974482790e-01, 8.156919233162234217e-01, 8.441539861131710509e-01,
8.709034570756529758e-01, 8.960553845713439269e-01, 9.197196053504168578e-01,
9.420000403794636101e-01, 9.629943306809362058e-01, 9.827937232473290541e-01,
1.001483135694234639e+00, 1.019141344266349725e+00, 1.035841253008800145e+00,
1.051650212548373764e+00, 1.066630365315743623e+00, 1.080839000541168327e+00,
1.094328907321189925e+00, 1.107148717794090409e+00, 1.130953743979160375e+00,
1.152571997215667610e+00, 1.172273881128476303e+00, 1.190289949682531656e+00,
1.206817370285252489e+00, 1.222025323210989667e+00, 1.236059489478081863e+00,
1.249045772398254428e+00, 1.261093382252440387e+00, 1.272297395208717319e+00,
1.282740879744270757e+00, 1.292496667789785336e+00, 1.301628834009196156e+00,
1.310193935047555547e+00, 1.318242051016837113e+00, 1.325817663668032553e+00,
1.339705659598999565e+00, 1.352127380920954636e+00, 1.363300100359693845e+00,
1.373400766945015894e+00, 1.382574821490125894e+00, 1.390942827002418447e+00,
1.398605512271957618e+00, 1.405647649380269870e+00, 1.412141064608495311e+00,
1.418146998399631542e+00, 1.423717971406494032e+00, 1.428899272190732761e+00,
1.433730152484709031e+00, 1.438244794498222623e+00, 1.442473099109101931e+00,
1.446441332248135092e+00,
};

static const double TBL_atan_lo[] = {
-3.125324142453938311e-18, -1.276925400709959526e-17, 2.479758919089733066e-17,
5.409599147666297957e-18, 9.585415594114323829e-18, 7.784470643106252464e-18,
-3.541164079802125137e-18, 2.372599351477449041e-17, 4.180692268843078977e-18,
2.034098543938166622e-17, 3.139954287184449286e-18, 7.333160666520898500e-18,
4.738160130078732886e-19, -5.498822172446843173e-18, 1.231340452914270316e-17,
1.058231431371112987e-17, 1.069875561873445139e-17, 1.923875492461530410e-17,
8.261353575163771936e-18, -1.428369957377257085e-17, -1.101082790300136900e-17,
-1.893928924292642146e-17, -7.952610375793798701e-18, -2.293880475557830393e-17,
3.088733564861919217e-17, 1.961231150484565340e-17, 2.378822732491940868e-17,
2.246598105617042065e-17, 3.963462895355093301e-17, 2.331553074189288466e-17,
-2.494277030626540909e-17, 3.280735600183735558e-17, 2.269877745296168709e-17,
-1.137323618932958456e-17, -2.546278147285580353e-17, -4.063795683482557497e-18,
-5.455630548591626394e-18, -1.441464378193066908e-17, 2.950430737228402307e-17,
2.672403885140095079e-17, 1.583478505144428617e-17, -3.076054864429649001e-17,
6.943223671560007740e-18, -1.987626234335816123e-17, -2.147838844445698302e-17,
3.473937648299456719e-17, -2.425693465918206812e-17, -3.704991905602721293e-17,
3.061616997868383018e-17, -1.071456562778743077e-17, -4.841337011934916763e-17,
-2.269823590747287052e-17, 2.923876285774304890e-17, -4.057439412852767923e-17,
5.460837485846687627e-17, -3.986660595210752445e-18, 1.390331103123099845e-17,
9.438308023545392000e-17, 1.000401886936679889e-17, 3.194313981784503706e-17,
-9.650564731467513515e-17, -5.956589637160374564e-17, -1.567632251135907253e-17,
-5.490676155022364226e-18, 9.404471373566379412e-17, 7.123833804538446299e-17,
-9.159738508900378819e-17, 8.385188614028674371e-17, 7.683333629842068806e-17,
4.172467638861439118e-17, -2.979162864892849274e-17, 7.879752739459421280e-17,
-2.196203799612310905e-18, 3.242139621534960503e-17, 2.245875015034507026e-17,
-9.283188754266129476e-18, -6.830804768926660334e-17, -1.236918499824626670e-17,
8.745413734780278834e-17, -6.319394031144676258e-17, -8.824429373951136321e-17,
-2.599011860304134377e-17, 2.147674250751150961e-17, 1.093246171526936217e-16,
-3.307710355769516504e-17, -3.561490438648230100e-17, -9.843712133488842595e-17,
-2.324061182591627982e-17, -8.922630138234492386e-17, -9.573807110557223276e-17,
-8.263883782511013632e-17, 8.721870922223967507e-17, -6.457134743238754385e-17,
-4.396204466767636187e-17, -2.493019910264565554e-17, -1.105119435430315713e-16,
9.211323971545051565e-17,
};

/*
 * mx_atan(x,err)
 * Table look-up algorithm
 * By K.C. Ng, March 9, 1989
 *
 * Algorithm.
 *
 * The algorithm is based on atan(x)=atan(y)+atan((x-y)/(1+x*y)).
 * We use poly1(x) to approximate atan(x) for x in [0,1/8] with
 * error (relative)
 * 	|(atan(x)-poly1(x))/x|<= 2^-83.41
 *
 * and use poly2(x) to approximate atan(x) for x in [0,1/65] with
 * error
 *	|atan(x)-poly2(x)|<= 2^-86.8
 *
 * Here poly1 and poly2 are odd polynomial with the following form:
 *		x + x^3*(a1+x^2*(a2+...))
 *
 * (0). Purge off Inf and NaN and 0
 * (1). Reduce x to positive by atan(x) = -atan(-x).
 * (2). For x <= 1/8, use
 *	(2.1) if x < 2^(-prec/2), atan(x) =  x  with inexact flag raised
 *	(2.2) Otherwise
 *		atan(x) = poly1(x)
 * (3). For x >= 8 then (prec = 78)
 *	(3.1) if x >= 2^prec,     atan(x) = atan(inf) - pio2lo
 *	(3.2) if x >= 2^(prec/3), atan(x) = atan(inf) - 1/x
 *	(3.3) if x >  65,         atan(x) = atan(inf) - poly2(1/x)
 *	(3.4) Otherwise,	  atan(x) = atan(inf) - poly1(1/x)
 *
 * (4). Now x is in (0.125, 8)
 *      Find y that match x to 4.5 bit after binary (easy).
 *	If iy is the high word of y, then
 *		single : j = (iy - 0x3e000000) >> 19
 *		double : j = (iy - 0x3fc00000) >> 16
 *		quad   : j = (iy - 0x3ffc0000) >> 12
 *
 *	Let s = (x-y)/(1+x*y). Then
 *	atan(x) = atan(y) + poly1(s)
 *		= _TBL_atan_hi[j] + (_TBL_atan_lo[j] + poly2(s) )
 *
 *	Note. |s| <= 1.5384615385e-02 = 1/65. Maxium occurs at x = 1.03125
 *
 */

#define	P1 p[2]
#define	P4 p[8]
#define	P5 p[9]
#define	P6 p[10]
#define	P7 p[11]
#define	P8 p[12]
#define	P9 p[13]
static const double p[] = {
	1.0,
	0.0,
	-3.33333333333333314830e-01,	/* p1   = BFD55555 55555555 */
	-1.85030852238476921863e-17,	/* p1_l = BC755525 9783A49C */
	2.00000000000000011102e-01,	/* p2   = 3FC99999 9999999A */
	-1.27263196576150347368e-17,	/* p2_l = BC6D584B 0D874007 */
	-1.42857142857141405923e-01,	/* p3   = BFC24924 9249245E */
	-1.34258204847170493327e-17,	/* p3_l = BC6EF534 A112500D */
	1.11111111110486909803e-01,	/* p4   = 3FBC71C7 1C71176A */
	-9.09090907557387889470e-02,	/* p5   = BFB745D1 73B47A7D */
	7.69230541541713053189e-02,	/* p6   = 3FB3B13A B1E68DE6 */
	-6.66645815401964159097e-02,	/* p7   = BFB110EE 1584446A */
	5.87081768778560317279e-02,	/* p8   = 3FAE0EFF 87657733 */
	-4.90818147456113240690e-02,	/* p9   = BFA92140 6A524B5C */
};
#define	Q1 q[2]
#define	Q3 q[6]
#define	Q4 q[7]
#define	Q5 q[8]
static const double q[] = {
	1.0,
	0.0,
	-3.33333333333333314830e-01,	/* q1   = BFD55555 55555555 */
	-1.85022941571278638733e-17,	/* q1_l = BC7554E9 D20EFA66 */
	1.99999999999999927836e-01,	/* q2   = 3FC99999 99999997 */
	-1.28782564407438833398e-17,	/* q2_l = BC6DB1FB 17217417 */
	-1.42857142855492280642e-01,	/* q3   = BFC24924 92483C46 */
	1.11111097130183356096e-01,	/* q4   = 3FBC71C6 E06595CC */
	-9.08553303569109294013e-02,	/* q5   = BFB7424B 808CDA76 */
};
static const double
one = 1.0,
pio2hi = 1.570796326794896558e+00,
pio2lo = 6.123233995736765886e-17;

static double
mx_atan(double x, double *err) {
	double y, z, r, s, t, w, s_h, s_l, x_h, x_l, zz[3], ee[2], z_h,
		z_l, r_h, r_l, u, v;
	int ix, iy, sign, j;

	ix = ((int *) &x)[HIWORD];
	sign = ix & 0x80000000;
	ix ^= sign;

	/* for |x| < 1/8 */
	if (ix < 0x3fc00000) {
		if (ix < 0x3f300000) {	/* when |x| < 2**-12 */
			if (ix < 0x3d800000) {	/* if |x| < 2**-39 */
				*err = (double) ((int) x);
				return (x);
			}
			z = x * x;
			t = x * z * (q[2] + z * (q[4] + z * q[6]));
			r = x + t;
			*err = t - (r - x);
			return (r);
		}
		z = x * x;

		/* use double precision at p4 and on */
		ee[0] = z *
			(P4 + z *
			(P5 + z * (P6 + z * (P7 + z * (P8 + z * P9)))));

		x_h = (double) ((float) x);
		z_h = (double) ((float) z);
		x_l = x - x_h;
		z_l = (x_h * x_h - z_h);
		zz[0] = z;
		zz[1] = z_h;
		zz[2] = z_l + x_l * (x + x_h);

		/*
		 * compute (1+z*(p1+z*(p2+z*(p3+e)))) by call
		 * mx_poly
		 */

		mx_poly(zz, p, ee, 3);

		/* finally x*(1+z*(p1+...)) */
		r = x_h * ee[0];
		t = x * ee[1] + x_l * ee[0];
		s = t + r;
		*err = t - (s - r);
		return (s);
	}
	/* for |x| >= 8.0 */
	if (ix >= 0x40200000) {	/* x >=  8 */
		x = fabs(x);
		if (ix >= 0x42600000) {	/* x >=  2**39 */
			if (ix >= 0x44c00000) {	/* x >=  2**77 */
				y = -pio2lo;
			} else
				y = one / x - pio2lo;
			if (sign == 0) {
				t = pio2hi - y;
				*err = -(y - (pio2hi - t));
			} else {
				t = y - pio2hi;
				*err = y - (pio2hi + t);
			}
			return (t);
		} else {
			/* compute r = 1/x */
			r = one / x;
			z = r * r;
			if (ix < 0x40504000) {	/* 8 <  x <  65 */

				/* use double precision at p4 and on */
				ee[0] = z *
					(P4 + z *
					(P5 + z *
					(P6 + z * (P7 + z * (P8 + z * P9)))));
				x_h = (double) ((float) x);
				r_h = (double) ((float) r);
				z_h = (double) ((float) z);
				r_l = r * ((x_h - x) * r_h - (x_h * r_h - one));
				z_l = (r_h * r_h - z_h);
				zz[0] = z;
				zz[1] = z_h;
				zz[2] = z_l + r_l * (r + r_h);
				/*
				 * compute (1+z*(p1+z*(p2+z*(p3+e)))) by call
				 * mx_poly
				 */
				mx_poly(zz, p, ee, 3);
			} else { /* x < 65 < 2**39 */
				/* use double precision at q3 and on */
				ee[0] = z * (Q3 + z * (Q4 + z * Q5));
				x_h = (double) ((float) x);
				r_h = (double) ((float) r);
				z_h = (double) ((float) z);
				r_l = r * ((x_h - x) * r_h - (x_h * r_h - one));
				z_l = (r_h * r_h - z_h);
				zz[0] = z;
				zz[1] = z_h;
				zz[2] = z_l + r_l * (r + r_h);
				/*
				 * compute (1+z*(q1+z*(q2+e))) by call
				 * mx_poly
				 */
				mx_poly(zz, q, ee, 2);
			}
			/* pio2 - r*(1+...) */
			v = r_h * ee[0];
			t = pio2lo - (r * ee[1] + r_l * ee[0]);
			if (sign == 0) {
				s = pio2hi - v;
				t -= (v - (pio2hi - s));
			} else {
				s = v - pio2hi;
				t = -(t - (v - (s + pio2hi)));
			}
			w = s + t;
			*err = t - (w - s);
			return (w);
		}
	}
	/* now x is between 1/8 and 8 */
	((int *) &x)[HIWORD] = ix;
	iy = (ix + 0x00008000) & 0x7fff0000;
	((int *) &y)[HIWORD] = iy;
	((int *) &y)[LOWORD] = 0;
	j = (iy - 0x3fc00000) >> 16;

	w = (x - y);
	v = 1 / (one + x * y);
	s = w * v;
	z = s * s;
	/* use double precision at q3 and on */
	ee[0] = z * (Q3 + z * (Q4 + z * Q5));
	s_h = (double) ((float) s);
	z_h = (double) ((float) z);
	x_h = (double) ((float) x);
	t = (double) ((float) (one + x * y));
	r = -((x_h - x) * y - (x_h * y - (t - one)));
	s_l = -v * (s_h * r - (w - s_h * t));
	z_l = (s_h * s_h - z_h);
	zz[0] = z;
	zz[1] = z_h;
	zz[2] = z_l + s_l * (s + s_h);
	/* compute (1+z*(q1+z*(q2+e))) by call mx_poly */
	mx_poly(zz, q, ee, 2);
	v = s_h * ee[0];
	t = TBL_atan_lo[j] + (s * ee[1] + s_l * ee[0]);
	u = TBL_atan_hi[j];
	s = u + v;
	t += (v - (s - u));
	w = s + t;
	*err = t - (w - s);
	if (sign != 0) {
		w = -w;
		*err = -*err;
	}
	return (w);
}

static const double
	twom768 = 6.441148769597133308e-232,    /* 2^-768 */
	two768  = 1.552518092300708935e+231,    /* 2^768 */
	pi = 3.1415926535897931159979634685,
	pi_lo = 1.224646799147353177e-16,
	pio2 = 1.570796326794896558e+00,
	pio2_lo = 6.123233995736765886e-17,
	pio4 = 0.78539816339744827899949,
	pio4_lo = 3.061616997868382943e-17,
	pi3o4 = 2.356194490192344836998,
	pi3o4_lo = 9.184850993605148829195e-17;

double
__k_atan2(double y, double x, double *w) {
	double t, xh, th, t1, t2, w1, w2;
	int ix, iy, hx, hy, lx, ly;

	hy = ((int *) &y)[HIWORD];
	ly = ((int *) &y)[LOWORD];
	iy = hy & ~0x80000000;

	hx = ((int *) &x)[HIWORD];
	lx = ((int *) &x)[LOWORD];
	ix = hx & ~0x80000000;

	*w = 0.0;
	if (ix >= 0x7ff00000 || iy >= 0x7ff00000) {	/* ignore inexact */
		if (isnan(x) || isnan(y))
			return (x * y);
		else if (iy < 0x7ff00000) {
			if (hx >= 0) {	/* ATAN2(+-finite, +inf) is +-0 */
				*w *= y;
				return (*w);
			} else {	/* ATAN2(+-finite, -inf) is +-pi */
				*w = copysign(pi_lo, y);
				return (copysign(pi, y));
			}
		} else if (ix < 0x7ff00000) {
					/* ATAN2(+-inf, finite) is +-pi/2 */
			*w = (hy >= 0)? pio2_lo : -pio2_lo;
			return ((hy >= 0)? pio2 : -pio2);
		} else if (hx > 0) {	/* ATAN2(+-INF,+INF) = +-pi/4 */
			*w = (hy >= 0)? pio4_lo : -pio4_lo;
			return ((hy >= 0)? pio4 : -pio4);
		} else {		/* ATAN2(+-INF,-INF) = +-3pi/4 */
			*w = (hy >= 0)? pi3o4_lo : -pi3o4_lo;
			return ((hy >= 0)? pi3o4 : -pi3o4);
		}
	} else if ((ix | lx) == 0 || (iy | ly) == 0) {
		if ((iy | ly) == 0) {
			if (hx >= 0) /* ATAN2(+-0, +(0 <= x <= inf)) is +-0 */
				return (y);
			else { 	/* ATAN2(+-0, -(0 <= x <= inf)) is +-pi */
				*w = (hy >= 0)? pi_lo : -pi_lo;
				return ((hy >= 0)? pi : -pi);
			}
		} else { /* ATAN2(+-(anything but 0 and NaN), 0) is +-pi/2 */
			*w = (hy >= 0)? pio2_lo : -pio2_lo;
			return ((hy >= 0)? pio2 : -pio2);
		}
	} else if (iy - ix > 0x06400000) { /* |x/y| < 2 ** -100 */
		*w = (hy >= 0)? pio2_lo : -pio2_lo;
		return ((hy >= 0)? pio2 : -pio2);
	} else if (ix - iy > 0x06400000) { /* |y/x| < 2 ** -100 */
		if (hx < 0) {
			*w = (hy >= 0)? pi_lo : -pi_lo;
			return ((hy >= 0)? pi : -pi);
		} else {
			t = y / x;
			th = t;
			((int *) &th)[LOWORD] &= 0xf8000000;
			xh = x;
			((int *) &xh)[LOWORD] &= 0xf8000000;
			t1 = (x - xh) * t + xh * (t - th);
			t2 = y - xh * th;
			*w = (t2 - t1) / x;
			return (t);
		}
	} else {
		if (ix >= 0x5f300000) {
			x *= twom768;
			y *= twom768;
		} else if (ix < 0x23d00000) {
			x *= two768;
			y *= two768;
		}
		y = fabs(y);
		x = fabs(x);
		t = y / x;
		th = t;
		((int *) &th)[LOWORD] &= 0xf8000000;
		xh = x;
		((int *) &xh)[LOWORD] &= 0xf8000000;
		t1 = (x - xh) * t + xh * (t - th);
		t2 = y - xh * th;
		w1 = mx_atan(t, &w2);
		w2 += (t2 - t1) / (x + y * t);
		if (hx < 0) {
			t1 = pi - w1;
			t2 = pi - t1;
			w2 = (pi_lo - w2) - (w1 - t2);
			w1 = t1;
		}
		*w = (hy >= 0)? w2 : -w2;
		return ((hy >= 0)? w1 : -w1);
	}
}
