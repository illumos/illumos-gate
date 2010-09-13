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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * If compiled without -DRF_INLINE_MACROS then needs -lm at link time
 * If compiled with -DRF_INLINE_MACROS then needs conv.il at compile time
 * (i.e. cc <compiler_flags> -DRF_INLINE_MACROS conv.il mont_mulf.c )
 */

#include <sys/types.h>
#include <math.h>

static const double TwoTo16 = 65536.0;
static const double TwoToMinus16 = 1.0/65536.0;
static const double Zero = 0.0;
static const double TwoTo32 = 65536.0 * 65536.0;
static const double TwoToMinus32 = 1.0 / (65536.0 * 65536.0);

#ifdef RF_INLINE_MACROS

double upper32(double);
double lower32(double, double);
double mod(double, double, double);

#else

static double
upper32(double x)
{
	return (floor(x * TwoToMinus32));
}


static double
lower32(double x, double y)
{
	return (x - TwoTo32 * floor(x * TwoToMinus32));
}

static double
mod(double x, double oneoverm, double m)
{
	return (x - m * floor(x * oneoverm));
}

#endif


static void
cleanup(double *dt, int from, int tlen)
{
	int i;
	double tmp, tmp1, x, x1;

	tmp = tmp1 = Zero;

	for (i = 2 * from; i < 2 * tlen; i += 2) {
		x = dt[i];
		x1 = dt[i + 1];
		dt[i] = lower32(x, Zero) + tmp;
		dt[i + 1] = lower32(x1, Zero) + tmp1;
		tmp = upper32(x);
		tmp1 = upper32(x1);
	}
}


void
conv_d16_to_i32(uint32_t *i32, double *d16, int64_t *tmp, int ilen)
{
	int i;
	int64_t t, t1,		/* Using int64_t and not uint64_t */
	    a, b, c, d;		/* because more efficient code is */
				/* generated this way, and there  */
				/* is no overflow.  */
	t1 = 0;
	a = (int64_t)d16[0];
	b = (int64_t)d16[1];
	for (i = 0; i < ilen - 1; i++) {
		c = (int64_t)d16[2 * i + 2];
		t1 += a & 0xffffffff;
		t = (a >> 32);
		d = (int64_t)d16[2 * i + 3];
		t1 += (b & 0xffff) << 16;
		t += (b >> 16) + (t1 >> 32);
		i32[i] = t1 & 0xffffffff;
		t1 = t;
		a = c;
		b = d;
	}
	t1 += a & 0xffffffff;
	t = (a >> 32);
	t1 += (b & 0xffff) << 16;
	i32[i] = t1 & 0xffffffff;
}

void
conv_i32_to_d32(double *d32, uint32_t *i32, int len)
{
	int i;

#pragma pipeloop(0)
	for (i = 0; i < len; i++)
		d32[i] = (double)(i32[i]);
}


void
conv_i32_to_d16(double *d16, uint32_t *i32, int len)
{
	int i;
	uint32_t a;

#pragma pipeloop(0)
	for (i = 0; i < len; i++) {
		a = i32[i];
		d16[2 * i] = (double)(a & 0xffff);
		d16[2 * i + 1] = (double)(a >> 16);
	}
}

#ifdef RF_INLINE_MACROS

void
i16_to_d16_and_d32x4(const double *,	/* 1/(2^16) */
			const double *,	/* 2^16 */
			const double *,	/* 0 */
			double *,	/* result16 */
			double *,	/* result32 */
			float *);	/* source - should be unsigned int* */
					/* converted to float* */

#else


static void
i16_to_d16_and_d32x4(const double *dummy1,	/* 1/(2^16) */
			const double *dummy2,	/* 2^16 */
			const double *dummy3,	/* 0 */
			double *result16,
			double *result32,
			float *src)	/* source - should be unsigned int* */
					/* converted to float* */
{
	uint32_t *i32;
	uint32_t a, b, c, d;

	i32 = (uint32_t *)src;
	a = i32[0];
	b = i32[1];
	c = i32[2];
	d = i32[3];
	result16[0] = (double)(a & 0xffff);
	result16[1] = (double)(a >> 16);
	result32[0] = (double)a;
	result16[2] = (double)(b & 0xffff);
	result16[3] = (double)(b >> 16);
	result32[1] = (double)b;
	result16[4] = (double)(c & 0xffff);
	result16[5] = (double)(c >> 16);
	result32[2] = (double)c;
	result16[6] = (double)(d & 0xffff);
	result16[7] = (double)(d >> 16);
	result32[3] = (double)d;
}

#endif


void
conv_i32_to_d32_and_d16(double *d32, double *d16, uint32_t *i32, int len)
{
	int i;
	uint32_t a;

#pragma pipeloop(0)
	for (i = 0; i < len - 3; i += 4) {
		i16_to_d16_and_d32x4(&TwoToMinus16, &TwoTo16, &Zero,
		    &(d16[2*i]), &(d32[i]), (float *)(&(i32[i])));
	}
	for (; i < len; i++) {
		a = i32[i];
		d32[i] = (double)(i32[i]);
		d16[2 * i] = (double)(a & 0xffff);
		d16[2 * i + 1] = (double)(a >> 16);
	}
}


static void
adjust_montf_result(uint32_t *i32, uint32_t *nint, int len)
{
	int64_t acc;
	int i;

	if (i32[len] > 0)
		i = -1;
	else {
		for (i = len - 1; i >= 0; i--) {
			if (i32[i] != nint[i]) break;
		}
	}
	if ((i < 0) || (i32[i] > nint[i])) {
		acc = 0;
		for (i = 0; i < len; i++) {
			acc = acc + (uint64_t)(i32[i]) - (uint64_t)(nint[i]);
			i32[i] = acc & 0xffffffff;
			acc = acc >> 32;
		}
	}
}


/*
 * the lengths of the input arrays should be at least the following:
 * result[nlen+1], dm1[nlen], dm2[2*nlen+1], dt[4*nlen+2], dn[nlen], nint[nlen]
 * all of them should be different from one another
 */
void mont_mulf_noconv(uint32_t *result,
			double *dm1, double *dm2, double *dt,
			double *dn, uint32_t *nint,
			int nlen, double dn0)
{
	int i, j, jj;
	double digit, m2j, a, b;
	double *pdm1, *pdm2, *pdn, *pdtj, pdn_0, pdm1_0;

	pdm1 = &(dm1[0]);
	pdm2 = &(dm2[0]);
	pdn = &(dn[0]);
	pdm2[2 * nlen] = Zero;

	if (nlen != 16) {
		for (i = 0; i < 4 * nlen + 2; i++)
			dt[i] = Zero;
		a = dt[0] = pdm1[0] * pdm2[0];
		digit = mod(lower32(a, Zero) * dn0, TwoToMinus16, TwoTo16);

		pdtj = &(dt[0]);
		for (j = jj = 0; j < 2 * nlen; j++, jj++, pdtj++) {
			m2j = pdm2[j];
			a = pdtj[0] + pdn[0] * digit;
			b = pdtj[1] + pdm1[0] * pdm2[j + 1] + a * TwoToMinus16;
			pdtj[1] = b;

#pragma pipeloop(0)
			for (i = 1; i < nlen; i++) {
				pdtj[2 * i] += pdm1[i] * m2j + pdn[i] * digit;
			}
			if (jj == 30) {
				cleanup(dt, j / 2 + 1, 2 * nlen + 1);
				jj = 0;
			}

			digit = mod(lower32(b, Zero) * dn0,
			    TwoToMinus16, TwoTo16);
		}
	} else {
		a = dt[0] = pdm1[0] * pdm2[0];

		dt[65] = dt[64] = dt[63] = dt[62] = dt[61] = dt[60] =
		    dt[59] = dt[58] = dt[57] = dt[56] = dt[55] =
		    dt[54] = dt[53] = dt[52] = dt[51] = dt[50] =
		    dt[49] = dt[48] = dt[47] = dt[46] = dt[45] =
		    dt[44] = dt[43] = dt[42] = dt[41] = dt[40] =
		    dt[39] = dt[38] = dt[37] = dt[36] = dt[35] =
		    dt[34] = dt[33] = dt[32] = dt[31] = dt[30] =
		    dt[29] = dt[28] = dt[27] = dt[26] = dt[25] =
		    dt[24] = dt[23] = dt[22] = dt[21] = dt[20] =
		    dt[19] = dt[18] = dt[17] = dt[16] = dt[15] =
		    dt[14] = dt[13] = dt[12] = dt[11] = dt[10] =
		    dt[9] = dt[8] = dt[7] = dt[6] = dt[5] = dt[4] =
		    dt[3] = dt[2] = dt[1] = Zero;

		pdn_0 = pdn[0];
		pdm1_0 = pdm1[0];

		digit = mod(lower32(a, Zero) * dn0, TwoToMinus16, TwoTo16);
		pdtj = &(dt[0]);

		for (j = 0; j < 32; j++, pdtj++) {

			m2j = pdm2[j];
			a = pdtj[0] + pdn_0 * digit;
			b = pdtj[1] + pdm1_0 * pdm2[j + 1] + a * TwoToMinus16;
			pdtj[1] = b;

			pdtj[2] += pdm1[1] *m2j + pdn[1] * digit;
			pdtj[4] += pdm1[2] *m2j + pdn[2] * digit;
			pdtj[6] += pdm1[3] *m2j + pdn[3] * digit;
			pdtj[8] += pdm1[4] *m2j + pdn[4] * digit;
			pdtj[10] += pdm1[5] *m2j + pdn[5] * digit;
			pdtj[12] += pdm1[6] *m2j + pdn[6] * digit;
			pdtj[14] += pdm1[7] *m2j + pdn[7] * digit;
			pdtj[16] += pdm1[8] *m2j + pdn[8] * digit;
			pdtj[18] += pdm1[9] *m2j + pdn[9] * digit;
			pdtj[20] += pdm1[10] *m2j + pdn[10] * digit;
			pdtj[22] += pdm1[11] *m2j + pdn[11] * digit;
			pdtj[24] += pdm1[12] *m2j + pdn[12] * digit;
			pdtj[26] += pdm1[13] *m2j + pdn[13] * digit;
			pdtj[28] += pdm1[14] *m2j + pdn[14] * digit;
			pdtj[30] += pdm1[15] *m2j + pdn[15] * digit;
			/* no need for cleanup, cannot overflow */
			digit = mod(lower32(b, Zero) * dn0,
			    TwoToMinus16, TwoTo16);
		}
	}

	conv_d16_to_i32(result, dt + 2 * nlen, (int64_t *)dt, nlen + 1);
	adjust_montf_result(result, nint, nlen);
}
