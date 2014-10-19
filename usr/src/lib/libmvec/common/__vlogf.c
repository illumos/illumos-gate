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

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

/* float logf(float x)
 *
 * Method :
 *	1. Special cases:
 *		for x is negative, -Inf => QNaN + invalid;
 *		for x = 0		=> -Inf + divide-by-zero;
 *		for x = +Inf		=> Inf;
 *		for x = NaN		=> QNaN.
 *	2. Computes logarithm from:
 *		x = m * 2**n => log(x) = n * log(2) + log(m),
 *		m = [1, 2).
 *	Let m = m0 + dm, where m0 = 1 + k / 32,
 *		k = [0, 32],
 *		dm = [-1/64, 1/64].
 *	Then log(m) = log(m0 + dm) = log(m0) + log(1+y),
 *		where y = dm*(1/m0), y = [-1/66, 1/64].
 *	Then
 *		1/m0 is looked up in a table of 1, 1/(1+1/32), ..., 1/(1+32/32);
 *		log(m0) is looked up in a table of log(1), log(1+1/32),
 *		..., log(1+32/32).
 *		log(1+y) is computed using approximation:
 *		log(1+y) = ((a3*y + a2)*y + a1)*y*y + y.
 * Accuracy:
 *	The maximum relative error for the approximating
 *	polynomial is 2**(-28.41).  All calculations are of
 *	double precision.
 *	Maximum error observed: less than 0.545 ulp for the
 *	whole float type range.
 */

static const double __TBL_logf[] = {
	/* __TBL_logf[2*i] = log(1+i/32), i = [0, 32] */
	/* __TBL_logf[2*i+1] = 2**(-23)/(1+i/32), i = [0, 32] */
0.000000000000000000e+00, 1.192092895507812500e-07, 3.077165866675368733e-02,
1.155968868371212153e-07, 6.062462181643483994e-02, 1.121969784007352926e-07,
8.961215868968713805e-02, 1.089913504464285680e-07, 1.177830356563834557e-01,
1.059638129340277719e-07, 1.451820098444978890e-01, 1.030999260979729787e-07,
1.718502569266592284e-01, 1.003867701480263102e-07, 1.978257433299198675e-01,
9.781275040064102225e-08, 2.231435513142097649e-01, 9.536743164062500529e-08,
2.478361639045812692e-01, 9.304139672256097884e-08, 2.719337154836417580e-01,
9.082612537202380448e-08, 2.954642128938358980e-01, 8.871388989825581272e-08,
3.184537311185345887e-01, 8.669766512784091150e-08, 3.409265869705931928e-01,
8.477105034722222546e-08, 3.629054936893684746e-01, 8.292820142663043248e-08,
3.844116989103320559e-01, 8.116377160904255122e-08, 4.054651081081643849e-01,
7.947285970052082892e-08, 4.260843953109000881e-01, 7.785096460459183052e-08,
4.462871026284195297e-01, 7.629394531250000159e-08, 4.660897299245992387e-01,
7.479798560049019504e-08, 4.855078157817008244e-01, 7.335956280048077330e-08,
5.045560107523953119e-01, 7.197542010613207272e-08, 5.232481437645478684e-01,
7.064254195601851460e-08, 5.415972824327444091e-01, 6.935813210227272390e-08,
5.596157879354226594e-01, 6.811959402901785336e-08, 5.773153650348236132e-01,
6.692451343201754014e-08, 5.947071077466927758e-01, 6.577064251077586116e-08,
6.118015411059929409e-01, 6.465588585805084723e-08, 6.286086594223740942e-01,
6.357828776041666578e-08, 6.451379613735847007e-01, 6.253602074795082293e-08,
6.613984822453650159e-01, 6.152737525201612732e-08, 6.773988235918061429e-01,
6.055075024801586965e-08, 6.931471805599452862e-01, 5.960464477539062500e-08
};

static const double
	K3 = -2.49887584306188944706e-01,
	K2 =  3.33368809981254554946e-01,
	K1 = -5.00000008402474976565e-01;

static const union {
	int	i;
	float	f;
} inf = { 0x7f800000 };

#define INF	inf.f

#define PROCESS(N)								\
	iy##N = ival##N & 0x007fffff;						\
	ival##N = (iy##N + 0x20000) & 0xfffc0000;				\
	i##N  = ival##N >> 17;							\
	iy##N = iy##N - ival##N;						\
	ty##N = LN2 * (double) exp##N + __TBL_logf[i##N];			\
	yy##N = (double) iy##N * __TBL_logf[i##N + 1];				\
	yy##N = ((K3 * yy##N + K2) * yy##N + K1) * yy##N * yy##N + yy##N;	\
	y[0] = (float)(yy##N + ty##N);						\
	y += stridey;

#define PREPROCESS(N, index, label)						\
	ival##N = *(int*)x;							\
	value = x[0];								\
	x += stridex;								\
	exp##N = (ival##N >> 23) - 127;						\
	if ((ival##N & 0x7fffffff) >= 0x7f800000) /* X = NaN or Inf */	\
	{									\
		y[index] = value + INF;						\
		goto label;							\
	}									\
	if (ival##N < 0x00800000)						\
	{									\
		if (ival##N > 0)	/* X = denormal */			\
		{								\
			value = (float) ival##N;				\
			ival##N = *(int*) &value;				\
			exp##N = (ival##N >> 23) - (127 + 149);			\
		}								\
		else								\
		{								\
			value = 0.0f;						\
			y[index] = ((ival##N & 0x7fffffff) == 0) ?		\
				-1.0f / value : value / value;			\
			goto label;						\
		}								\
	}

void
__vlogf(int n, float * restrict x, int stridex, float * restrict y,
	int stridey)
{
	double	LN2 = __TBL_logf[64];		/* log(2) = 0.6931471805599453094 	*/
	double	yy0, yy1, yy2, yy3, yy4;
	double	ty0, ty1, ty2, ty3, ty4;
	float	value;
	int	i0, i1, i2, i3, i4;
	int	ival0, ival1, ival2, ival3, ival4;
	int	exp0, exp1, exp2, exp3, exp4;
	int	iy0, iy1, iy2, iy3, iy4;

	y -= stridey;

	for (; ;)
	{
begin:
		y += stridey;

		if (--n < 0)
			break;

		PREPROCESS(0, 0, begin)

		if (--n < 0)
			goto process1;

		PREPROCESS(1, stridey, process1)

		if (--n < 0)
			goto process2;

		PREPROCESS(2, (stridey << 1), process2)

		if (--n < 0)
			goto process3;

		PREPROCESS(3, (stridey << 1) + stridey, process3)

		if (--n < 0)
			goto process4;

		PREPROCESS(4, (stridey << 2), process4)

		iy0 = ival0 & 0x007fffff;
		iy1 = ival1 & 0x007fffff;
		iy2 = ival2 & 0x007fffff;
		iy3 = ival3 & 0x007fffff;
		iy4 = ival4 & 0x007fffff;

		ival0 = (iy0 + 0x20000) & 0xfffc0000;
		ival1 = (iy1 + 0x20000) & 0xfffc0000;
		ival2 = (iy2 + 0x20000) & 0xfffc0000;
		ival3 = (iy3 + 0x20000) & 0xfffc0000;
		ival4 = (iy4 + 0x20000) & 0xfffc0000;

		i0 = ival0 >> 17;
		i1 = ival1 >> 17;
		i2 = ival2 >> 17;
		i3 = ival3 >> 17;
		i4 = ival4 >> 17;

		iy0 = iy0 - ival0;
		iy1 = iy1 - ival1;
		iy2 = iy2 - ival2;
		iy3 = iy3 - ival3;
		iy4 = iy4 - ival4;

		ty0 = LN2 * (double) exp0 + __TBL_logf[i0];
		ty1 = LN2 * (double) exp1 + __TBL_logf[i1];
		ty2 = LN2 * (double) exp2 + __TBL_logf[i2];
		ty3 = LN2 * (double) exp3 + __TBL_logf[i3];
		ty4 = LN2 * (double) exp4 + __TBL_logf[i4];

		yy0 = (double) iy0 * __TBL_logf[i0 + 1];
		yy1 = (double) iy1 * __TBL_logf[i1 + 1];
		yy2 = (double) iy2 * __TBL_logf[i2 + 1];
		yy3 = (double) iy3 * __TBL_logf[i3 + 1];
		yy4 = (double) iy4 * __TBL_logf[i4 + 1];

		yy0 = ((K3 * yy0 + K2) * yy0 + K1) * yy0 * yy0 + yy0;
		yy1 = ((K3 * yy1 + K2) * yy1 + K1) * yy1 * yy1 + yy1;
		yy2 = ((K3 * yy2 + K2) * yy2 + K1) * yy2 * yy2 + yy2;
		yy3 = ((K3 * yy3 + K2) * yy3 + K1) * yy3 * yy3 + yy3;
		yy4 = ((K3 * yy4 + K2) * yy4 + K1) * yy4 * yy4 + yy4;

		y[0] = (float)(yy0 + ty0);
		y += stridey;
		y[0] = (float)(yy1 + ty1);
		y += stridey;
		y[0] = (float)(yy2 + ty2);
		y += stridey;
		y[0] = (float)(yy3 + ty3);
		y += stridey;
		y[0] = (float)(yy4 + ty4);
		continue;

process1:
		PROCESS(0)
		continue;

process2:
		PROCESS(0)
		PROCESS(1)
		continue;

process3:
		PROCESS(0)
		PROCESS(1)
		PROCESS(2)
		continue;

process4:
		PROCESS(0)
		PROCESS(1)
		PROCESS(2)
		PROCESS(3)
	}
}
