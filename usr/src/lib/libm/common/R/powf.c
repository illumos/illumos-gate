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

#pragma weak __powf = powf

#include "libm.h"
#include "xpg6.h"	/* __xpg6 */
#define	_C99SUSv3_pow	_C99SUSv3_pow_treats_Inf_as_an_even_int

#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

/* INDENT OFF */
static const double
	ln2 = 6.93147180559945286227e-01,	/* 0x3fe62e42, 0xfefa39ef */
	invln2 = 1.44269504088896338700e+00,	/* 0x3ff71547, 0x652b82fe */
	dtwo = 2.0,
	done = 1.0,
	dhalf = 0.5,
	d32 = 32.0,
	d1_32 = 0.03125,
	A0 = 1.999999999813723303647511146995966439250e+0000,
	A1 = 6.666910817935858533770138657139665608610e-0001,
	t0 = 2.000000000004777489262405315073203746943e+0000,
	t1 = 1.666663408349926379873111932994250726307e-0001;

static const double S[] = {
	1.00000000000000000000e+00,	/* 3FF0000000000000 */
	1.02189714865411662714e+00,	/* 3FF059B0D3158574 */
	1.04427378242741375480e+00,	/* 3FF0B5586CF9890F */
	1.06714040067682369717e+00,	/* 3FF11301D0125B51 */
	1.09050773266525768967e+00,	/* 3FF172B83C7D517B */
	1.11438674259589243221e+00,	/* 3FF1D4873168B9AA */
	1.13878863475669156458e+00,	/* 3FF2387A6E756238 */
	1.16372485877757747552e+00,	/* 3FF29E9DF51FDEE1 */
	1.18920711500272102690e+00,	/* 3FF306FE0A31B715 */
	1.21524735998046895524e+00,	/* 3FF371A7373AA9CB */
	1.24185781207348400201e+00,	/* 3FF3DEA64C123422 */
	1.26905095719173321989e+00,	/* 3FF44E086061892D */
	1.29683955465100964055e+00,	/* 3FF4BFDAD5362A27 */
	1.32523664315974132322e+00,	/* 3FF5342B569D4F82 */
	1.35425554693689265129e+00,	/* 3FF5AB07DD485429 */
	1.38390988196383202258e+00,	/* 3FF6247EB03A5585 */
	1.41421356237309514547e+00,	/* 3FF6A09E667F3BCD */
	1.44518080697704665027e+00,	/* 3FF71F75E8EC5F74 */
	1.47682614593949934623e+00,	/* 3FF7A11473EB0187 */
	1.50916442759342284141e+00,	/* 3FF82589994CCE13 */
	1.54221082540794074411e+00,	/* 3FF8ACE5422AA0DB */
	1.57598084510788649659e+00,	/* 3FF93737B0CDC5E5 */
	1.61049033194925428347e+00,	/* 3FF9C49182A3F090 */
	1.64575547815396494578e+00,	/* 3FFA5503B23E255D */
	1.68179283050742900407e+00,	/* 3FFAE89F995AD3AD */
	1.71861929812247793414e+00,	/* 3FFB7F76F2FB5E47 */
	1.75625216037329945351e+00,	/* 3FFC199BDD85529C */
	1.79470907500310716820e+00,	/* 3FFCB720DCEF9069 */
	1.83400808640934243066e+00,	/* 3FFD5818DCFBA487 */
	1.87416763411029996256e+00,	/* 3FFDFC97337B9B5F */
	1.91520656139714740007e+00,	/* 3FFEA4AFA2A490DA */
	1.95714412417540017941e+00,	/* 3FFF50765B6E4540 */
};

static const double TBL[] = {
	0.00000000000000000e+00,
	3.07716586667536873e-02,
	6.06246218164348399e-02,
	8.96121586896871380e-02,
	1.17783035656383456e-01,
	1.45182009844497889e-01,
	1.71850256926659228e-01,
	1.97825743329919868e-01,
	2.23143551314209765e-01,
	2.47836163904581269e-01,
	2.71933715483641758e-01,
	2.95464212893835898e-01,
	3.18453731118534589e-01,
	3.40926586970593193e-01,
	3.62905493689368475e-01,
	3.84411698910332056e-01,
	4.05465108108164385e-01,
	4.26084395310900088e-01,
	4.46287102628419530e-01,
	4.66089729924599239e-01,
	4.85507815781700824e-01,
	5.04556010752395312e-01,
	5.23248143764547868e-01,
	5.41597282432744409e-01,
	5.59615787935422659e-01,
	5.77315365034823613e-01,
	5.94707107746692776e-01,
	6.11801541105992941e-01,
	6.28608659422374094e-01,
	6.45137961373584701e-01,
	6.61398482245365016e-01,
	6.77398823591806143e-01,
};

static const float zero = 0.0F, one = 1.0F, huge = 1.0e25f, tiny = 1.0e-25f;
/* INDENT ON */

float
powf(float x, float y) {
	float	fx = x, fy = y;
	float	fz;
	int	ix, iy, jx, jy, k, iw, yisint;

	ix = *(int *)&x;
	iy = *(int *)&y;
	jx = ix & ~0x80000000;
	jy = iy & ~0x80000000;

	if (jy == 0)
		return (one);	/* x**+-0 = 1 */
	else if (ix == 0x3f800000 && (__xpg6 & _C99SUSv3_pow) != 0)
		return (one);	/* C99: 1**anything = 1 */
	else if (((0x7f800000 - jx) | (0x7f800000 - jy)) < 0)
		return (fx * fy);	/* at least one of x or y is NaN */
					/* includes Sun: 1**NaN = NaN */
	/* INDENT OFF */
	/*
	 * determine if y is an odd int
	 * yisint = 0 ... y is not an integer
	 * yisint = 1 ... y is an odd int
	 * yisint = 2 ... y is an even int
	 */
	/* INDENT ON */
	yisint = 0;
	if (ix < 0) {
		if (jy >= 0x4b800000) {
			yisint = 2;	/* |y|>=2**24: y must be even */
		} else if (jy >= 0x3f800000) {
			k = (jy >> 23) - 0x7f;	/* exponent */
			iw = jy >> (23 - k);
			if ((iw << (23 - k)) == jy)
				yisint = 2 - (iw & 1);
		}
	}

	/* special value of y */
	if ((jy & ~0x7f800000) == 0) {
		if (jy == 0x7f800000) {		/* y is +-inf */
			if (jx == 0x3f800000) {
				if ((__xpg6 & _C99SUSv3_pow) != 0)
					fz = one;
						/* C99: (-1)**+-inf is 1 */
				else
					fz = fy - fy;
						/* Sun: (+-1)**+-inf = NaN */
			} else if (jx > 0x3f800000) {
						/* (|x|>1)**+,-inf = inf,0 */
				if (iy > 0)
					fz = fy;
				else
					fz = zero;
			} else {		/* (|x|<1)**-,+inf = inf,0 */
				if (iy < 0)
					fz = -fy;
				else
					fz = zero;
			}
			return (fz);
		} else if (jy == 0x3f800000) {	/* y is +-1 */
			if (iy < 0)
				fx = one / fx;	/* y is -1 */
			return (fx);
		} else if (iy == 0x40000000) {	/* y is 2 */
			return (fx * fx);
		} else if (iy == 0x3f000000) {	/* y is 0.5 */
			if (jx != 0 && jx != 0x7f800000)
				return (sqrtf(x));
		}
	}

	/* special value of x */
	if ((jx & ~0x7f800000) == 0) {
		if (jx == 0x7f800000 || jx == 0 || jx == 0x3f800000) {
			/* x is +-0,+-inf,-1; set fz = |x|**y */
			*(int *)&fz = jx;
			if (iy < 0)
				fz = one / fz;
			if (ix < 0) {
				if (jx == 0x3f800000 && yisint == 0) {
					/* (-1)**non-int is NaN */
					fz = zero;
					fz /= fz;
				} else if (yisint == 1) {
					/* (x<0)**odd = -(|x|**odd) */
					fz = -fz;
				}
			}
			return (fz);
		}
	}

	/* (x<0)**(non-int) is NaN */
	if (ix < 0 && yisint == 0) {
		fz = zero;
		return (fz / fz);
	}

	/*
	 * compute exp(y*log(|x|))
	 * fx = *(float *) &jx;
	 * fz = (float) exp(((double) fy) * log((double) fx));
	 */
	{
		double	dx, dy, dz, ds;
		int	*px = (int *)&dx, *pz = (int *)&dz, i, n, m;
#if defined(__i386) && !defined(__amd64)
		int	rp = __swapRP(fp_extended);
#endif

		fx = *(float *)&jx;
		dx = (double)fx;

		/* compute log(x)/ln2 */
		i = px[HIWORD] + 0x4000;
		n = (i >> 20) - 0x3ff;
		pz[HIWORD] = i & 0xffff8000;
		pz[LOWORD] = 0;
		ds = (dx - dz) / (dx + dz);
		i = (i >> 15) & 0x1f;
		dz = ds * ds;
		dy = invln2 * (TBL[i] + ds * (A0 + dz * A1));
		if (n == 0)
			dz = (double)fy * dy;
		else
			dz = (double)fy * (dy + (double)n);

		/* compute exp2(dz=y*ln(x)) */
		i = pz[HIWORD];
		if ((i & ~0x80000000) >= 0x40640000) {	/* |z| >= 160.0 */
			fz = (i > 0)? huge : tiny;
			if (ix < 0 && yisint == 1)
				fz *= -fz;	/* (-ve)**(odd int) */
			else
				fz *= fz;
#if defined(__i386) && !defined(__amd64)
			if (rp != fp_extended)
				(void) __swapRP(rp);
#endif
			return (fz);
		}

		n = (int)(d32 * dz + (i > 0 ? dhalf : -dhalf));
		i = n & 0x1f;
		m = n >> 5;
		dy = ln2 * (dz - d1_32 * (double)n);
		dx = S[i] * (done - (dtwo * dy) / (dy * (done - dy * t1) - t0));
		if (m != 0)
			px[HIWORD] += m << 20;
		fz = (float)dx;
#if defined(__i386) && !defined(__amd64)
		if (rp != fp_extended)
			(void) __swapRP(rp);
#endif
	}

	/* end of computing exp(y*log(x)) */
	if (ix < 0 && yisint == 1)
		fz = -fz;	/* (-ve)**(odd int) */
	return (fz);
}
