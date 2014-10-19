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

#include <sys/isa_defs.h>
#include "libm_synonyms.h"
#include "libm_inlines.h"

#ifdef _LITTLE_ENDIAN
#define HI(x)	*(1+(int*)x)
#define LO(x)	*(unsigned*)x
#else
#define HI(x)	*(int*)x
#define LO(x)	*(1+(unsigned*)x)
#endif

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

/* float rhypotf(float x, float y)
 *
 * Method :
 *	1. Special cases:
 *		for x or y = Inf			=> 0;
 *		for x or y = NaN			=> QNaN;
 *		for x and y = 0				=> +Inf + divide-by-zero;
 *	2. Computes d = x * x + y * y;
 *	3. Computes reciprocal square root from:
 *		d = m * 2**n
 *	Where:
 *		m = [0.5, 2),
 *		n = ((exponent + 1) & ~1).
 *	Then:
 *		rsqrtf(d) = 1/sqrt( m * 2**n ) = (2 ** (-n/2)) * (1/sqrt(m))
 *	4. Computes 1/sqrt(m) from:
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
 *	Maximum error observed: less than 0.535 ulp after 3.000.000.000
 *	results.
 */

#pragma align 32 (__vlibm_TBL_rhypotf)

static const double __vlibm_TBL_rhypotf[] = {
/*
 i = [0,63]
 TBL[2*i+0] = 1.0 / (*(double*)&(0x3ff0000000000000LL + (i << 46)));
 TBL[2*i+1] = (double)(0.5/sqrtl(2) / sqrtl(*(double*)&(0x3ff0000000000000LL + (i << 46))));
 TBL[128+2*i+0] = 1.0 / (*(double*)&(0x3ff0000000000000LL + (i << 46)));
 TBL[128+2*i+1] = (double)(0.25 / sqrtl(*(double*)&(0x3ff0000000000000LL + (i << 46))));
*/
 1.0000000000000000000e+00, 3.5355339059327378637e-01,
 9.8461538461538467004e-01, 3.5082320772281166965e-01,
 9.6969696969696972388e-01, 3.4815531191139570399e-01,
 9.5522388059701490715e-01, 3.4554737023254405992e-01,
 9.4117647058823528106e-01, 3.4299717028501769400e-01,
 9.2753623188405798228e-01, 3.4050261230349943009e-01,
 9.1428571428571425717e-01, 3.3806170189140660742e-01,
 9.0140845070422537244e-01, 3.3567254331867563133e-01,
 8.8888888888888883955e-01, 3.3333333333333331483e-01,
 8.7671232876712323900e-01, 3.3104235544094717802e-01,
 8.6486486486486491287e-01, 3.2879797461071458287e-01,
 8.5333333333333338810e-01, 3.2659863237109043599e-01,
 8.4210526315789469010e-01, 3.2444284226152508843e-01,
 8.3116883116883122362e-01, 3.2232918561015211356e-01,
 8.2051282051282048435e-01, 3.2025630761017426229e-01,
 8.1012658227848100001e-01, 3.1822291367029204023e-01,
 8.0000000000000004441e-01, 3.1622776601683794118e-01,
 7.9012345679012341293e-01, 3.1426968052735443360e-01,
 7.8048780487804880757e-01, 3.1234752377721214378e-01,
 7.7108433734939763049e-01, 3.1046021028253312224e-01,
 7.6190476190476186247e-01, 3.0860669992418382490e-01,
 7.5294117647058822484e-01, 3.0678599553894819740e-01,
 7.4418604651162789665e-01, 3.0499714066520933198e-01,
 7.3563218390804596680e-01, 3.0323921743156134756e-01,
 7.2727272727272729291e-01, 3.0151134457776362918e-01,
 7.1910112359550559802e-01, 2.9981267559834456904e-01,
 7.1111111111111113825e-01, 2.9814239699997197031e-01,
 7.0329670329670335160e-01, 2.9649972666444046610e-01,
 6.9565217391304345895e-01, 2.9488391230979427160e-01,
 6.8817204301075274309e-01, 2.9329423004270660513e-01,
 6.8085106382978721751e-01, 2.9172998299578911663e-01,
 6.7368421052631577428e-01, 2.9019050004400465115e-01,
 6.6666666666666662966e-01, 2.8867513459481286553e-01,
 6.5979381443298967813e-01, 2.8718326344709527165e-01,
 6.5306122448979586625e-01, 2.8571428571428569843e-01,
 6.4646464646464651960e-01, 2.8426762180748055275e-01,
 6.4000000000000001332e-01, 2.8284271247461900689e-01,
 6.3366336633663367106e-01, 2.8143901789211672737e-01,
 6.2745098039215685404e-01, 2.8005601680560193723e-01,
 6.2135922330097081989e-01, 2.7869320571664707442e-01,
 6.1538461538461541878e-01, 2.7735009811261457369e-01,
 6.0952380952380957879e-01, 2.7602622373694168934e-01,
 6.0377358490566035432e-01, 2.7472112789737807015e-01,
 5.9813084112149528249e-01, 2.7343437080986532361e-01,
 5.9259259259259255970e-01, 2.7216552697590867815e-01,
 5.8715596330275232617e-01, 2.7091418459143856712e-01,
 5.8181818181818178992e-01, 2.6967994498529684888e-01,
 5.7657657657657657158e-01, 2.6846242208560971987e-01,
 5.7142857142857139685e-01, 2.6726124191242439654e-01,
 5.6637168141592919568e-01, 2.6607604209509572168e-01,
 5.6140350877192979340e-01, 2.6490647141300877054e-01,
 5.5652173913043478937e-01, 2.6375218935831479250e-01,
 5.5172413793103447510e-01, 2.6261286571944508772e-01,
 5.4700854700854706358e-01, 2.6148818018424535570e-01,
 5.4237288135593220151e-01, 2.6037782196164771520e-01,
 5.3781512605042014474e-01, 2.5928148942086576278e-01,
 5.3333333333333332593e-01, 2.5819888974716115326e-01,
 5.2892561983471075848e-01, 2.5712973861329002645e-01,
 5.2459016393442625681e-01, 2.5607375986579195004e-01,
 5.2032520325203257539e-01, 2.5503068522533534068e-01,
 5.1612903225806450180e-01, 2.5400025400038100942e-01,
 5.1200000000000001066e-01, 2.5298221281347033074e-01,
 5.0793650793650790831e-01, 2.5197631533948483540e-01,
 5.0393700787401574104e-01, 2.5098232205526344041e-01,
 1.0000000000000000000e+00, 2.5000000000000000000e-01,
 9.8461538461538467004e-01, 2.4806946917841690703e-01,
 9.6969696969696972388e-01, 2.4618298195866547551e-01,
 9.5522388059701490715e-01, 2.4433888871261044695e-01,
 9.4117647058823528106e-01, 2.4253562503633296910e-01,
 9.2753623188405798228e-01, 2.4077170617153839660e-01,
 9.1428571428571425717e-01, 2.3904572186687872426e-01,
 9.0140845070422537244e-01, 2.3735633163877067897e-01,
 8.8888888888888883955e-01, 2.3570226039551583908e-01,
 8.7671232876712323900e-01, 2.3408229439226113655e-01,
 8.6486486486486491287e-01, 2.3249527748763856860e-01,
 8.5333333333333338810e-01, 2.3094010767585029797e-01,
 8.4210526315789469010e-01, 2.2941573387056177213e-01,
 8.3116883116883122362e-01, 2.2792115291927589338e-01,
 8.2051282051282048435e-01, 2.2645540682891915352e-01,
 8.1012658227848100001e-01, 2.2501758018520479077e-01,
 8.0000000000000004441e-01, 2.2360679774997896385e-01,
 7.9012345679012341293e-01, 2.2222222222222220989e-01,
 7.8048780487804880757e-01, 2.2086305214969309541e-01,
 7.7108433734939763049e-01, 2.1952851997938069295e-01,
 7.6190476190476186247e-01, 2.1821789023599238999e-01,
 7.5294117647058822484e-01, 2.1693045781865616384e-01,
 7.4418604651162789665e-01, 2.1566554640687682354e-01,
 7.3563218390804596680e-01, 2.1442250696755896233e-01,
 7.2727272727272729291e-01, 2.1320071635561044232e-01,
 7.1910112359550559802e-01, 2.1199957600127200541e-01,
 7.1111111111111113825e-01, 2.1081851067789195153e-01,
 7.0329670329670335160e-01, 2.0965696734438366011e-01,
 6.9565217391304345895e-01, 2.0851441405707477061e-01,
 6.8817204301075274309e-01, 2.0739033894608505104e-01,
 6.8085106382978721751e-01, 2.0628424925175867233e-01,
 6.7368421052631577428e-01, 2.0519567041703082322e-01,
 6.6666666666666662966e-01, 2.0412414523193150862e-01,
 6.5979381443298967813e-01, 2.0306923302672380549e-01,
 6.5306122448979586625e-01, 2.0203050891044216364e-01,
 6.4646464646464651960e-01, 2.0100756305184241945e-01,
 6.4000000000000001332e-01, 2.0000000000000001110e-01,
 6.3366336633663367106e-01, 1.9900743804199783060e-01,
 6.2745098039215685404e-01, 1.9802950859533485772e-01,
 6.2135922330097081989e-01, 1.9706585563285863860e-01,
 6.1538461538461541878e-01, 1.9611613513818404453e-01,
 6.0952380952380957879e-01, 1.9518001458970662965e-01,
 6.0377358490566035432e-01, 1.9425717247145282696e-01,
 5.9813084112149528249e-01, 1.9334729780913270658e-01,
 5.9259259259259255970e-01, 1.9245008972987526219e-01,
 5.8715596330275232617e-01, 1.9156525704423027490e-01,
 5.8181818181818178992e-01, 1.9069251784911847580e-01,
 5.7657657657657657158e-01, 1.8983159915049979682e-01,
 5.7142857142857139685e-01, 1.8898223650461362655e-01,
 5.6637168141592919568e-01, 1.8814417367671945613e-01,
 5.6140350877192979340e-01, 1.8731716231633879777e-01,
 5.5652173913043478937e-01, 1.8650096164806276300e-01,
 5.5172413793103447510e-01, 1.8569533817705186074e-01,
 5.4700854700854706358e-01, 1.8490006540840969729e-01,
 5.4237288135593220151e-01, 1.8411492357966466327e-01,
 5.3781512605042014474e-01, 1.8333969940564226464e-01,
 5.3333333333333332593e-01, 1.8257418583505535814e-01,
 5.2892561983471075848e-01, 1.8181818181818182323e-01,
 5.2459016393442625681e-01, 1.8107149208503706128e-01,
 5.2032520325203257539e-01, 1.8033392693348646030e-01,
 5.1612903225806450180e-01, 1.7960530202677491007e-01,
 5.1200000000000001066e-01, 1.7888543819998317663e-01,
 5.0793650793650790831e-01, 1.7817416127494958844e-01,
 5.0393700787401574104e-01, 1.7747130188322274291e-01,
};

#define	fabsf	__fabsf

extern float fabsf(float);

static const double
	A0 = 9.99999997962321453275e-01,
	A1 =-4.99999998166077580600e-01,
	A2 = 3.75066768969515586277e-01,
	A3 =-3.12560092408808548438e-01;

static void
__vrhypotf_n(int n, float * restrict px, int stridex, float * restrict py,
	int stridey, float * restrict pz, int stridez);

#pragma no_inline(__vrhypotf_n)

#define RETURN(ret)						\
{								\
	*pz = (ret);						\
	pz += stridez;						\
	if (n_n == 0)						\
	{							\
		spx = px; spy = py; spz = pz;			\
		ay0 = *(int*)py;				\
		continue;					\
	}							\
	n--;							\
	break;							\
}


void
__vrhypotf(int n, float * restrict px, int stridex, float * restrict py,
	int stridey, float * restrict pz, int stridez)
{
	float		*spx, *spy, *spz;
	int		ax0, ay0, n_n;
	float		res, x0, y0;

	while (n > 1)
	{
		n_n = 0;
		spx = px;
		spy = py;
		spz = pz;
		ax0 = *(int*)px;
		ay0 = *(int*)py;
		for (; n > 1 ; n--)
		{
			ax0 &= 0x7fffffff;
			ay0 &= 0x7fffffff;

			px += stridex;

			if (ax0 >= 0x7f800000 || ay0 >= 0x7f800000)	/* X or Y = NaN or Inf	*/
			{
				x0 = *(px - stridex);
				y0 = *py;
				res = fabsf(x0) + fabsf(y0);
				if (ax0 == 0x7f800000) res = 0.0f;
				else if (ay0 == 0x7f800000) res = 0.0f;
				ax0 = *(int*)px;
				py += stridey;
				RETURN (res)
			}
			ax0 = *(int*)px;
			py += stridey;
			if (ay0 == 0)		/* Y = 0	*/
			{
				int tx = *(int*)(px - stridex) & 0x7fffffff;
				if (tx == 0)	/* X = 0	*/
				{
					RETURN (1.0f / 0.0f)
				}
			}
			pz += stridez;
			n_n++;
			ay0 = *(int*)py;
		}
		if (n_n > 0)
			__vrhypotf_n(n_n, spx, stridex, spy, stridey, spz, stridez);
	}
	if (n > 0)
	{
		ax0 = *(int*)px;
		ay0 = *(int*)py;
		x0 = *px;
		y0 = *py;

		ax0 &= 0x7fffffff;
		ay0 &= 0x7fffffff;

		if (ax0 >= 0x7f800000 || ay0 >= 0x7f800000)	/* X or Y = NaN or Inf	*/
		{
			res = fabsf(x0) + fabsf(y0);
			if (ax0 == 0x7f800000) res = 0.0f;
			else if (ay0 == 0x7f800000) res = 0.0f;
			*pz = res;
		}
		else if (ax0 == 0 && ay0 == 0)	/* X and Y = 0	*/
		{
			*pz = 1.0f / 0.0f;
		}
		else
		{
			double		xx0, res0, hyp0, h_hi0 = 0, dbase0 = 0;
			int		ibase0, si0, hyp0h;

			hyp0 = x0 * (double)x0 + y0 * (double)y0;

			ibase0 = HI(&hyp0);

			HI(&dbase0) = (0x60000000 - ((ibase0 & 0x7fe00000) >> 1));

			hyp0h = (ibase0 & 0x000fffff) | 0x3ff00000;
			HI(&hyp0) = hyp0h;
			HI(&h_hi0) = hyp0h & 0x7fffc000;

			ibase0 >>= 10;
			si0 = ibase0 & 0x7f0;
			xx0 = ((double*)((char*)__vlibm_TBL_rhypotf + si0))[0];

			xx0 = (hyp0 - h_hi0) * xx0;
			res0 = ((double*)((char*)__vlibm_TBL_rhypotf + si0))[1];
			res0 *= (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);
			res0 *= dbase0;
			*pz = res0;
		}
	}
}

static void
__vrhypotf_n(int n, float * restrict px, int stridex, float * restrict py,
	int stridey, float * restrict pz, int stridez)
{
	double		xx0, res0, hyp0, h_hi0 = 0, dbase0 = 0;
	double		xx1, res1, hyp1, h_hi1 = 0, dbase1 = 0;
	double		xx2, res2, hyp2, h_hi2 = 0, dbase2 = 0;
	float		x0, y0;
	float		x1, y1;
	float		x2, y2;
	int		ibase0, si0, hyp0h;
	int		ibase1, si1, hyp1h;
	int		ibase2, si2, hyp2h;

	for (; n > 2 ; n -= 3)
	{
		x0 = *px;
		px += stridex;
		x1 = *px;
		px += stridex;
		x2 = *px;
		px += stridex;

		y0 = *py;
		py += stridey;
		y1 = *py;
		py += stridey;
		y2 = *py;
		py += stridey;

		hyp0 = x0 * (double)x0 + y0 * (double)y0;
		hyp1 = x1 * (double)x1 + y1 * (double)y1;
		hyp2 = x2 * (double)x2 + y2 * (double)y2;

		ibase0 = HI(&hyp0);
		ibase1 = HI(&hyp1);
		ibase2 = HI(&hyp2);

		HI(&dbase0) = (0x60000000 - ((ibase0 & 0x7fe00000) >> 1));
		HI(&dbase1) = (0x60000000 - ((ibase1 & 0x7fe00000) >> 1));
		HI(&dbase2) = (0x60000000 - ((ibase2 & 0x7fe00000) >> 1));

		hyp0h = (ibase0 & 0x000fffff) | 0x3ff00000;
		hyp1h = (ibase1 & 0x000fffff) | 0x3ff00000;
		hyp2h = (ibase2 & 0x000fffff) | 0x3ff00000;
		HI(&hyp0) = hyp0h;
		HI(&hyp1) = hyp1h;
		HI(&hyp2) = hyp2h;
		HI(&h_hi0) = hyp0h & 0x7fffc000;
		HI(&h_hi1) = hyp1h & 0x7fffc000;
		HI(&h_hi2) = hyp2h & 0x7fffc000;

		ibase0 >>= 10;
		ibase1 >>= 10;
		ibase2 >>= 10;
		si0 = ibase0 & 0x7f0;
		si1 = ibase1 & 0x7f0;
		si2 = ibase2 & 0x7f0;
		xx0 = ((double*)((char*)__vlibm_TBL_rhypotf + si0))[0];
		xx1 = ((double*)((char*)__vlibm_TBL_rhypotf + si1))[0];
		xx2 = ((double*)((char*)__vlibm_TBL_rhypotf + si2))[0];

		xx0 = (hyp0 - h_hi0) * xx0;
		xx1 = (hyp1 - h_hi1) * xx1;
		xx2 = (hyp2 - h_hi2) * xx2;
		res0 = ((double*)((char*)__vlibm_TBL_rhypotf + si0))[1];
		res1 = ((double*)((char*)__vlibm_TBL_rhypotf + si1))[1];
		res2 = ((double*)((char*)__vlibm_TBL_rhypotf + si2))[1];
		res0 *= (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);
		res1 *= (((A3 * xx1 + A2) * xx1 + A1) * xx1 + A0);
		res2 *= (((A3 * xx2 + A2) * xx2 + A1) * xx2 + A0);
		res0 *= dbase0;
		res1 *= dbase1;
		res2 *= dbase2;
		*pz = res0;
		pz += stridez;
		*pz = res1;
		pz += stridez;
		*pz = res2;
		pz += stridez;
	}

	for (; n > 0 ; n--)
	{
		x0 = *px;
		px += stridex;

		y0 = *py;
		py += stridey;

		hyp0 = x0 * (double)x0 + y0 * (double)y0;

		ibase0 = HI(&hyp0);

		HI(&dbase0) = (0x60000000 - ((ibase0 & 0x7fe00000) >> 1));

		hyp0h = (ibase0 & 0x000fffff) | 0x3ff00000;
		HI(&hyp0) = hyp0h;
		HI(&h_hi0) = hyp0h & 0x7fffc000;

		ibase0 >>= 10;
		si0 = ibase0 & 0x7f0;
		xx0 = ((double*)((char*)__vlibm_TBL_rhypotf + si0))[0];

		xx0 = (hyp0 - h_hi0) * xx0;
		res0 = ((double*)((char*)__vlibm_TBL_rhypotf + si0))[1];
		res0 *= (((A3 * xx0 + A2) * xx0 + A1) * xx0 + A0);
		res0 *= dbase0;
		*pz = res0;
		pz += stridez;
	}
}

