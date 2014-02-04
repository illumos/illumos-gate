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

#include "libm_synonyms.h"
#include "libm_inlines.h"

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

/* float rsqrtf(float x)
 *
 * Method :
 *	1. Special cases:
 *		for x = NaN				=> QNaN;
 *		for x = +Inf				=> 0;
 *		for x is negative, -Inf			=> QNaN + invalid;
 *		for x = +0				=> +Inf + divide-by-zero;
 *		for x = -0				=> -Inf + divide-by-zero.
 *	2. Computes reciprocal square root from:
 *		x = m * 2**n
 *	Where:
 *		m = [0.5, 2),
 *		n = ((exponent + 1) & ~1).
 *	Then:
 *		rsqrtf(x) = 1/sqrt( m * 2**n ) = (2 ** (-n/2)) * (1/sqrt(m))
 *	2. Computes 1/sqrt(m) from:
 *		1/sqrt(m) = (1/sqrt(m0)) * (1/sqrt(1 + (1/m0)*dm))
 *	Where:
 *		m = m0 + dm,
 *		m0 = 0.5 * (1 + k/64) for m = [0.5,         0.5+127/256), k = [0, 63];
 *		m0 = 1.0 * (0 + k/64) for m = [0.5+127/256, 1.0+127/128), k = [64, 127];
 *	Then:
 *		1/sqrt(m0), 1/m0 are looked up in a table,
 *		1/sqrt(1 + (1/m0)*dm) is computed using approximation:
 *			1/sqrt(1 + z) = ((a3 * z + a2) * z + a1) * z + a0
 *			where z = [-1/64, 1/64].
 *
 * Accuracy:
 *	The maximum relative error for the approximating
 *	polynomial is 2**(-27.87).
 *	Maximum error observed: less than 0.534 ulp for the
 *	whole float type range.
 */

#define sqrtf __sqrtf

extern float sqrtf(float);

static const double __TBL_rsqrtf[] = {
/*
i = [0,63]
 TBL[2*i  ] = 1 / (*(double*)&(0x3fe0000000000000ULL + (i << 46))) * 2**-24;
 TBL[2*i+1] = 1 / sqrtl(*(double*)&(0x3fe0000000000000ULL + (i << 46)));
i = [64,127]
 TBL[2*i  ] = 1 / (*(double*)&(0x3fe0000000000000ULL + (i << 46))) * 2**-23;
 TBL[2*i+1] = 1 / sqrtl(*(double*)&(0x3fe0000000000000ULL + (i << 46)));
*/
 1.1920928955078125000e-07, 1.4142135623730951455e+00,
 1.1737530048076923728e-07, 1.4032928308912466786e+00,
 1.1559688683712121533e-07, 1.3926212476455828160e+00,
 1.1387156016791044559e-07, 1.3821894809301762397e+00,
 1.1219697840073529256e-07, 1.3719886811400707760e+00,
 1.1057093523550724772e-07, 1.3620104492139977204e+00,
 1.0899135044642856803e-07, 1.3522468075656264297e+00,
 1.0745626100352112918e-07, 1.3426901732747025253e+00,
 1.0596381293402777190e-07, 1.3333333333333332593e+00,
 1.0451225385273972023e-07, 1.3241694217637887121e+00,
 1.0309992609797297870e-07, 1.3151918984428583315e+00,
 1.0172526041666667320e-07, 1.3063945294843617440e+00,
 1.0038677014802631022e-07, 1.2977713690461003537e+00,
 9.9083045860389616921e-08, 1.2893167424406084542e+00,
 9.7812750400641022247e-08, 1.2810252304406970492e+00,
 9.6574614319620251657e-08, 1.2728916546811681609e+00,
 9.5367431640625005294e-08, 1.2649110640673517647e+00,
 9.4190055941358019463e-08, 1.2570787221094177344e+00,
 9.3041396722560978838e-08, 1.2493900951088485751e+00,
 9.1920416039156631290e-08, 1.2418408411301324890e+00,
 9.0826125372023804482e-08, 1.2344267996967352996e+00,
 8.9757582720588234048e-08, 1.2271439821557927896e+00,
 8.8713889898255812722e-08, 1.2199885626608373279e+00,
 8.7694190014367814875e-08, 1.2129568697262453902e+00,
 8.6697665127840911497e-08, 1.2060453783110545167e+00,
 8.5723534058988761666e-08, 1.1992507023933782762e+00,
 8.4771050347222225457e-08, 1.1925695879998878812e+00,
 8.3839500343406599951e-08, 1.1859989066577618644e+00,
 8.2928201426630432481e-08, 1.1795356492391770864e+00,
 8.2036500336021511923e-08, 1.1731769201708264205e+00,
 8.1163771609042551220e-08, 1.1669199319831564665e+00,
 8.0309416118421050820e-08, 1.1607620001760186046e+00,
 7.9472859700520828922e-08, 1.1547005383792514621e+00,
 7.8653551868556699530e-08, 1.1487330537883810866e+00,
 7.7850964604591830522e-08, 1.1428571428571427937e+00,
 7.7064591224747481298e-08, 1.1370704872299222110e+00,
 7.6293945312500001588e-08, 1.1313708498984760276e+00,
 7.5538559715346535571e-08, 1.1257560715684669095e+00,
 7.4797985600490195040e-08, 1.1202240672224077489e+00,
 7.4071791565533974158e-08, 1.1147728228665882977e+00,
 7.3359562800480773303e-08, 1.1094003924504582947e+00,
 7.2660900297619054173e-08, 1.1041048949477667573e+00,
 7.1975420106132072725e-08, 1.0988845115895122806e+00,
 7.1302752628504667579e-08, 1.0937374832394612945e+00,
 7.0642541956018514597e-08, 1.0886621079036347126e+00,
 6.9994445240825691959e-08, 1.0836567383657542685e+00,
 6.9358132102272723904e-08, 1.0787197799411873955e+00,
 6.8733284065315314719e-08, 1.0738496883424388795e+00,
 6.8119594029017853361e-08, 1.0690449676496975862e+00,
 6.7516765763274335346e-08, 1.0643041683803828867e+00,
 6.6924513432017540145e-08, 1.0596258856520350822e+00,
 6.6342561141304348632e-08, 1.0550087574332591700e+00,
 6.5770642510775861156e-08, 1.0504514628777803509e+00,
 6.5208500267094023655e-08, 1.0459527207369814228e+00,
 6.4655885858050847233e-08, 1.0415112878465908608e+00,
 6.4112559086134451001e-08, 1.0371259576834630511e+00,
 6.3578287760416665784e-08, 1.0327955589886446131e+00,
 6.3052847365702481089e-08, 1.0285189544531601058e+00,
 6.2536020747950822927e-08, 1.0242950394631678002e+00,
 6.2027597815040656970e-08, 1.0201227409013413627e+00,
 6.1527375252016127325e-08, 1.0160010160015240377e+00,
 6.1035156250000001271e-08, 1.0119288512538813229e+00,
 6.0550750248015869655e-08, 1.0079052613579393416e+00,
 6.0073972687007873182e-08, 1.0039292882210537616e+00,
 1.1920928955078125000e-07, 1.0000000000000000000e+00,
 1.1737530048076923728e-07, 9.9227787671366762812e-01,
 1.1559688683712121533e-07, 9.8473192783466190203e-01,
 1.1387156016791044559e-07, 9.7735555485044178781e-01,
 1.1219697840073529256e-07, 9.7014250014533187638e-01,
 1.1057093523550724772e-07, 9.6308682468615358641e-01,
 1.0899135044642856803e-07, 9.5618288746751489704e-01,
 1.0745626100352112918e-07, 9.4942532655508271588e-01,
 1.0596381293402777190e-07, 9.4280904158206335630e-01,
 1.0451225385273972023e-07, 9.3632917756904454620e-01,
 1.0309992609797297870e-07, 9.2998110995055427441e-01,
 1.0172526041666667320e-07, 9.2376043070340119190e-01,
 1.0038677014802631022e-07, 9.1766293548224708854e-01,
 9.9083045860389616921e-08, 9.1168461167710357351e-01,
 9.7812750400641022247e-08, 9.0582162731567661407e-01,
 9.6574614319620251657e-08, 9.0007032074081916306e-01,
 9.5367431640625005294e-08, 8.9442719099991585541e-01,
 9.4190055941358019463e-08, 8.8888888888888883955e-01,
 9.3041396722560978838e-08, 8.8345220859877238162e-01,
 9.1920416039156631290e-08, 8.7811407991752277180e-01,
 9.0826125372023804482e-08, 8.7287156094396955996e-01,
 8.9757582720588234048e-08, 8.6772183127462465535e-01,
 8.8713889898255812722e-08, 8.6266218562750729415e-01,
 8.7694190014367814875e-08, 8.5769002787023584933e-01,
 8.6697665127840911497e-08, 8.5280286542244176928e-01,
 8.5723534058988761666e-08, 8.4799830400508802164e-01,
 8.4771050347222225457e-08, 8.4327404271156780613e-01,
 8.3839500343406599951e-08, 8.3862786937753464045e-01,
 8.2928201426630432481e-08, 8.3405765622829908246e-01,
 8.2036500336021511923e-08, 8.2956135578434020417e-01,
 8.1163771609042551220e-08, 8.2513699700703468931e-01,
 8.0309416118421050820e-08, 8.2078268166812329287e-01,
 7.9472859700520828922e-08, 8.1649658092772603446e-01,
 7.8653551868556699530e-08, 8.1227693210689522196e-01,
 7.7850964604591830522e-08, 8.0812203564176865456e-01,
 7.7064591224747481298e-08, 8.0403025220736967782e-01,
 7.6293945312500001588e-08, 8.0000000000000004441e-01,
 7.5538559715346535571e-08, 7.9602975216799132241e-01,
 7.4797985600490195040e-08, 7.9211803438133943089e-01,
 7.4071791565533974158e-08, 7.8826342253143455441e-01,
 7.3359562800480773303e-08, 7.8446454055273617811e-01,
 7.2660900297619054173e-08, 7.8072005835882651859e-01,
 7.1975420106132072725e-08, 7.7702868988581130782e-01,
 7.1302752628504667579e-08, 7.7338919123653082632e-01,
 7.0642541956018514597e-08, 7.6980035891950104876e-01,
 6.9994445240825691959e-08, 7.6626102817692109959e-01,
 6.9358132102272723904e-08, 7.6277007139647390321e-01,
 6.8733284065315314719e-08, 7.5932639660199918730e-01,
 6.8119594029017853361e-08, 7.5592894601845450619e-01,
 6.7516765763274335346e-08, 7.5257669470687782454e-01,
 6.6924513432017540145e-08, 7.4926864926535519107e-01,
 6.6342561141304348632e-08, 7.4600384659225105199e-01,
 6.5770642510775861156e-08, 7.4278135270820744296e-01,
 6.5208500267094023655e-08, 7.3960026163363878915e-01,
 6.4655885858050847233e-08, 7.3645969431865865307e-01,
 6.4112559086134451001e-08, 7.3335879762256905856e-01,
 6.3578287760416665784e-08, 7.3029674334022143256e-01,
 6.3052847365702481089e-08, 7.2727272727272729291e-01,
 6.2536020747950822927e-08, 7.2428596834014824513e-01,
 6.2027597815040656970e-08, 7.2133570773394584119e-01,
 6.1527375252016127325e-08, 7.1842120810709964029e-01,
 6.1035156250000001271e-08, 7.1554175279993270653e-01,
 6.0550750248015869655e-08, 7.1269664509979835376e-01,
 6.0073972687007873182e-08, 7.0988520753289097165e-01,
};

static const unsigned long long LCONST[] = {
0x3feffffffee7f18fULL,	/* A0 = 9.99999997962321453275e-01	*/
0xbfdffffffe07e52fULL,	/* A1 =-4.99999998166077580600e-01	*/
0x3fd801180ca296d9ULL,	/* A2 = 3.75066768969515586277e-01	*/
0xbfd400fc0bbb8e78ULL,	/* A3 =-3.12560092408808548438e-01	*/
};

static void
__vrsqrtf_n(int n, float * restrict px, int stridex, float * restrict py, int stridey);

#pragma no_inline(__vrsqrtf_n)

#define RETURN(ret)						\
{								\
	*py = (ret);						\
	py += stridey;						\
	if (n_n == 0)						\
	{							\
		spx = px; spy = py;				\
		ax0 = *(int*)px;				\
		continue;					\
	}							\
	n--;							\
	break;							\
}

void
__vrsqrtf(int n, float * restrict px, int stridex, float * restrict py, int stridey)
{
	float		*spx, *spy;
	int		ax0, n_n;
	float		res;
	float		FONE = 1.0f, FTWO = 2.0f;

	while (n > 1)
	{
		n_n = 0;
		spx = px;
		spy = py;
		ax0 = *(int*)px;
		for (; n > 1 ; n--)
		{
			px += stridex;
			if (ax0 >= 0x7f800000)	/* X = NaN or Inf	*/
			{
				res = *(px - stridex);
				RETURN (FONE / res)
			}

			py += stridey;

			if (ax0 < 0x00800000)		/* X = denormal, zero or negative	*/
			{
				py -= stridey;
				res = *(px - stridex);

				if ((ax0 & 0x7fffffff) == 0)	/* |X| = zero	*/
				{
					RETURN (FONE / res)
				}
				else if (ax0 >= 0)	/* X = denormal	*/
				{
					double		A0 = ((double*)LCONST)[0];	/*  9.99999997962321453275e-01	*/
					double		A1 = ((double*)LCONST)[1];	/* -4.99999998166077580600e-01	*/
					double		A2 = ((double*)LCONST)[2];	/*  3.75066768969515586277e-01	*/
					double		A3 = ((double*)LCONST)[3];	/* -3.12560092408808548438e-01	*/

					double		res0, xx0, tbl_div0, tbl_sqrt0;
					float		fres0;
					int		iax0, si0, iexp0;

					res = *(int*)&res;
					res *= FTWO;
					ax0 = *(int*)&res;
					iexp0 = ax0 >> 24;
					iexp0 = 0x3f + 0x4b - iexp0;
					iexp0 = iexp0 << 23;

					si0 = (ax0 >> 13) & 0x7f0;

					tbl_div0 = ((double*)((char*)__TBL_rsqrtf + si0))[0];
					tbl_sqrt0 = ((double*)((char*)__TBL_rsqrtf + si0))[1];
					iax0 = ax0 & 0x7ffe0000;
					iax0 = ax0 - iax0;
					xx0 = iax0 * tbl_div0;
					res0 = tbl_sqrt0 * (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);

					fres0 = res0;
					iexp0 += *(int*)&fres0;
					RETURN(*(float*)&iexp0)
				}
				else	/* X = negative	*/
				{
					RETURN (sqrtf(res))
				}
			}
			n_n++;
			ax0 = *(int*)px;
		}
		if (n_n > 0)
			__vrsqrtf_n(n_n, spx, stridex, spy, stridey);
	}

	if (n > 0)
	{
		ax0 = *(int*)px;

		if (ax0 >= 0x7f800000)	/* X = NaN or Inf	*/
		{
			res = *px;
			*py = FONE / res;
		}
		else if (ax0 < 0x00800000)	/* X = denormal, zero or negative	*/
		{
			res = *px;

			if ((ax0 & 0x7fffffff) == 0)	/* |X| = zero	*/
			{
				*py = FONE / res;
			}
			else if (ax0 >= 0)	/* X = denormal	*/
			{
				double		A0 = ((double*)LCONST)[0];	/*  9.99999997962321453275e-01	*/
				double		A1 = ((double*)LCONST)[1];	/* -4.99999998166077580600e-01	*/
				double		A2 = ((double*)LCONST)[2];	/*  3.75066768969515586277e-01	*/
				double		A3 = ((double*)LCONST)[3];	/* -3.12560092408808548438e-01	*/
				double		res0, xx0, tbl_div0, tbl_sqrt0;
				float		fres0;
				int		iax0, si0, iexp0;

				res = *(int*)&res;
				res *= FTWO;
				ax0 = *(int*)&res;
				iexp0 = ax0 >> 24;
				iexp0 = 0x3f + 0x4b - iexp0;
				iexp0 = iexp0 << 23;

				si0 = (ax0 >> 13) & 0x7f0;

				tbl_div0 = ((double*)((char*)__TBL_rsqrtf + si0))[0];
				tbl_sqrt0 = ((double*)((char*)__TBL_rsqrtf + si0))[1];
				iax0 = ax0 & 0x7ffe0000;
				iax0 = ax0 - iax0;
				xx0 = iax0 * tbl_div0;
				res0 = tbl_sqrt0 * (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);

				fres0 = res0;
				iexp0 += *(int*)&fres0;

				*(int*)py = iexp0;
			}
			else	/* X = negative	*/
			{
				*py = sqrtf(res);
			}
		}
		else
		{
			double		A0 = ((double*)LCONST)[0];	/*  9.99999997962321453275e-01	*/
			double		A1 = ((double*)LCONST)[1];	/* -4.99999998166077580600e-01	*/
			double		A2 = ((double*)LCONST)[2];	/*  3.75066768969515586277e-01	*/
			double		A3 = ((double*)LCONST)[3];	/* -3.12560092408808548438e-01	*/
			double		res0, xx0, tbl_div0, tbl_sqrt0;
			float		fres0;
			int		iax0, si0, iexp0;

			iexp0 = ax0 >> 24;
			iexp0 = 0x3f - iexp0;
			iexp0 = iexp0 << 23;

			si0 = (ax0 >> 13) & 0x7f0;

			tbl_div0 = ((double*)((char*)__TBL_rsqrtf + si0))[0];
			tbl_sqrt0 = ((double*)((char*)__TBL_rsqrtf + si0))[1];
			iax0 = ax0 & 0x7ffe0000;
			iax0 = ax0 - iax0;
			xx0 = iax0 * tbl_div0;
			res0 = tbl_sqrt0 * (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);

			fres0 = res0;
			iexp0 += *(int*)&fres0;

			*(int*)py = iexp0;
		}
	}
}

void
__vrsqrtf_n(int n, float * restrict px, int stridex, float * restrict py, int stridey)
{
	double		A0 = ((double*)LCONST)[0];	/*  9.99999997962321453275e-01	*/
	double		A1 = ((double*)LCONST)[1];	/* -4.99999998166077580600e-01	*/
	double		A2 = ((double*)LCONST)[2];	/*  3.75066768969515586277e-01	*/
	double		A3 = ((double*)LCONST)[3];	/* -3.12560092408808548438e-01	*/
	double		res0, xx0, tbl_div0, tbl_sqrt0;
	float		fres0;
	int		iax0, ax0, si0, iexp0;

#if defined(ARCH_v7) || defined(ARCH_v8)
	double		res1, xx1, tbl_div1, tbl_sqrt1;
	double		res2, xx2, tbl_div2, tbl_sqrt2;
	float		fres1, fres2;
	int		iax1, ax1, si1, iexp1;
	int		iax2, ax2, si2, iexp2;

	for(; n > 2 ; n -= 3)
	{
		ax0 = *(int*)px;
		px += stridex;

		ax1 = *(int*)px;
		px += stridex;

		ax2 = *(int*)px;
		px += stridex;

		iexp0 = ax0 >> 24;
		iexp1 = ax1 >> 24;
		iexp2 = ax2 >> 24;
		iexp0 = 0x3f - iexp0;
		iexp1 = 0x3f - iexp1;
		iexp2 = 0x3f - iexp2;

		iexp0 = iexp0 << 23;
		iexp1 = iexp1 << 23;
		iexp2 = iexp2 << 23;

		si0 = (ax0 >> 13) & 0x7f0;
		si1 = (ax1 >> 13) & 0x7f0;
		si2 = (ax2 >> 13) & 0x7f0;

		tbl_div0 = ((double*)((char*)__TBL_rsqrtf + si0))[0];
		tbl_div1 = ((double*)((char*)__TBL_rsqrtf + si1))[0];
		tbl_div2 = ((double*)((char*)__TBL_rsqrtf + si2))[0];
		tbl_sqrt0 = ((double*)((char*)__TBL_rsqrtf + si0))[1];
		tbl_sqrt1 = ((double*)((char*)__TBL_rsqrtf + si1))[1];
		tbl_sqrt2 = ((double*)((char*)__TBL_rsqrtf + si2))[1];
		iax0 = ax0 & 0x7ffe0000;
		iax1 = ax1 & 0x7ffe0000;
		iax2 = ax2 & 0x7ffe0000;
		iax0 = ax0 - iax0;
		iax1 = ax1 - iax1;
		iax2 = ax2 - iax2;
		xx0 = iax0 * tbl_div0;
		xx1 = iax1 * tbl_div1;
		xx2 = iax2 * tbl_div2;
		res0 = tbl_sqrt0 * (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);
		res1 = tbl_sqrt1 * (((A3 * xx1 + A2) * xx1 + A1) * xx1 + A0);
		res2 = tbl_sqrt2 * (((A3 * xx2 + A2) * xx2 + A1) * xx2 + A0);

		fres0 = res0;
		fres1 = res1;
		fres2 = res2;

		iexp0 += *(int*)&fres0;
		iexp1 += *(int*)&fres1;
		iexp2 += *(int*)&fres2;
		*(int*)py = iexp0;
		py += stridey;
		*(int*)py = iexp1;
		py += stridey;
		*(int*)py = iexp2;
		py += stridey;
	}
#endif
	for(; n > 0 ; n--)
	{
		ax0 = *(int*)px;
		px += stridex;

		iexp0 = ax0 >> 24;
		iexp0 = 0x3f - iexp0;
		iexp0 = iexp0 << 23;

		si0 = (ax0 >> 13) & 0x7f0;

		tbl_div0 = ((double*)((char*)__TBL_rsqrtf + si0))[0];
		tbl_sqrt0 = ((double*)((char*)__TBL_rsqrtf + si0))[1];
		iax0 = ax0 & 0x7ffe0000;
		iax0 = ax0 - iax0;
		xx0 = iax0 * tbl_div0;
		res0 = tbl_sqrt0 * (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);

		fres0 = res0;
		iexp0 += *(int*)&fres0;
		*(int*)py = iexp0;
		py += stridey;
	}
}

