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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fp.h>
#include <externs.h>
#include <fps_ereport.h>

/* Traps enabled or disabled */
#define	T_ENABLED 1
#define	T_DISABLED 0

static int test_ieee754_exc_fields(int trapStatus,
    struct fps_test_ereport *report);
static int test_fccn(struct fps_test_ereport *report);
static int test_rounding(struct fps_test_ereport *report);

/*
 * Test data for testing the IEEE 754 exceptions.
 * The first 5 entries are for the 5 FP exception fields of the FSR
 */
static struct testws test_ws[] = {

	/*
	 * a_msw, a_lsw, b_msw,   b_lsw,  instr, fsr_tem0...,  fsr_tem1...,
	 * ecode
	 */

	{one_sp, nocare, maxm_sp, nocare, op_add_sp,
	FSR_TEM0_NX, FSR_TEM1_NX, E_NX},	/* inexact	 */
	{one_sp, nocare, zero_sp, nocare, op_div_sp,
	FSR_TEM0_DZ, FSR_TEM1_DZ, E_DZ},	/* div/zero */
	{min1_sp, nocare, min1_sp, nocare, op_mul_sp,
	FSR_TEM0_UF, FSR_TEM1_UF, E_UF},	/* unfl,inex */
	{maxm_sp, nocare, maxm_sp, nocare, op_mul_sp,
	FSR_TEM0_OF, FSR_TEM1_OF, E_OF},	/* overflow */
	{zero_sp, nocare, zero_sp, nocare, op_div_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},	/* not a valid */

	{maxn_sp, nocare, maxn_sp, nocare, op_add_sp,
	FSR_TEM0_OF_NX, FSR_CEXC_OF, E_OF},	/* 5-ovfl,inex */
	{maxn_sp, nocare, maxn_sp, nocare, op_mul_sp,
	FSR_TEM0_OF_NX, FSR_CEXC_OF, E_OF},	/* 5-ovfl,inex */
	{maxn_msw, maxn_lsw, maxn_msw, maxn_lsw, op_mul_dp,
	FSR_TEM0_OF_NX, FSR_CEXC_OF, E_OF},
	{one_msw, one_lsw, zero_msw, zero_lsw, op_div_dp,
	FSR_TEM1_DZ, FSR_TEM1_DZ, E_DZ},
	{one_sp, nocare, nn_sp, nocare, op_add_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},

	{one_msw, one_lsw, nn_msw, nn_lsw, op_add_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{one_sp, nocare, nn_sp, nocare, op_mul_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{one_msw, one_lsw, nn_msw, nn_lsw, op_mul_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{maxd_sp, nocare, two_sp, nocare, op_div_sp,
	FSR_TEM0_UF_NX, FSR_CEXC_UF, E_UF},	/* 8-a-denorm */
	{maxd_msw, maxd_lsw, two_msw, two_lsw, op_div_dp,
	FSR_TEM0_UF_NX, FSR_CEXC_UF, E_UF},

	{min1_sp, nocare, pi_4_sp, nocare, op_mul_sp,
	FSR_TEM0_UF_NX, FSR_CEXC_UF, E_UF},	/* 7-unfl,inex */
	{maxd_sp, nocare, half_sp, nocare, op_mul_sp,
	FSR_TEM0_UF_NX, FSR_CEXC_UF, E_UF},	/* 8 -a-denorm */
	{maxd_msw, maxd_lsw, half_msw, half_lsw, op_mul_dp,
	FSR_TEM0_UF_NX, FSR_CEXC_UF, E_UF},
	{half_sp, nocare, maxd_sp, nocare, op_mul_sp,
	FSR_TEM0_UF_NX, FSR_CEXC_UF, E_UF},	/* 9 -b-denorm */
	{half_msw, half_lsw, maxd_msw, maxd_lsw, op_mul_dp,
	FSR_TEM0_UF_NX, FSR_CEXC_UF, E_UF},

	{min1_msw, min1_lsw, pi_4_msw, pi_4_lsw, op_mul_dp,
	FSR_TEM0_UF_NX, FSR_CEXC_UF, E_UF},
	{nan_sp, nocare, zero_sp, nocare, op_add_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},	/* 12-a-nan */
	{nan_msw, nan_lsw, zero_msw, zero_lsw, op_add_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{zero_sp, nocare, nan_sp, nocare, op_add_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},	/* 13 -b-nan */
	{zero_sp, nocare, nan_msw, nan_lsw, op_add_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},

	{nan_sp, nocare, nan_sp, nocare, op_add_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},	/* 14 -ab-nan */
	{nan_msw, nan_lsw, nan_msw, nan_lsw, op_add_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{nan_sp, nocare, zero_sp, nocare, op_mul_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},	/* 11-a-nan */
	{nan_msw, nan_lsw, zero_msw, zero_lsw, op_mul_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{zero_sp, nocare, nan_sp, nocare, op_mul_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},	/* 13-b-nan */

	{zero_sp, nocare, nan_msw, nan_lsw, op_mul_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{nan_sp, nocare, nan_sp, nocare, op_mul_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},	/* 14-ab-nan */
	{nan_msw, nan_lsw, nan_msw, nan_lsw, op_mul_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},

	/* More IEEE 754 exceptions */

	/* (+inf) + (-inf) */
	{p_inf_sp, nocare, n_inf_sp, nocare, op_add_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{p_inf_msw, p_inf_lsw, n_inf_msw, n_inf_lsw, op_add_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},

	/* (0) * (+inf) */
	{zero_sp, nocare, p_inf_sp, nocare, op_mul_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{zero_msw, zero_lsw, p_inf_msw, p_inf_lsw, op_mul_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},

	/* (0) * (-inf) */
	{zero_sp, nocare, n_inf_sp, nocare, op_mul_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{zero_msw, zero_lsw, n_inf_msw, n_inf_lsw, op_mul_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},

	/* (+inf) / (+inf) */
	{p_inf_sp, nocare, p_inf_sp, nocare, op_div_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{p_inf_msw, p_inf_lsw, p_inf_msw, p_inf_lsw, op_div_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},

	/* (+inf) / (-inf) */
	{p_inf_sp, nocare, n_inf_sp, nocare, op_div_sp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{p_inf_msw, p_inf_lsw, n_inf_msw, n_inf_lsw, op_div_dp,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},

	/* sqrt(-1) */
	{m_one_sp, nocare, nocare, nocare, op_fsqrts,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},
	{m_one_msw, m_one_lsw, nocare, nocare, op_fsqrtd,
	FSR_TEM0_NV, FSR_TEM1_NV, E_NV},


{00, 00, 000, 000, 0000, 0x0, 0x0, 0x0}};

/* Data used in test_fccn() */

/* No. of fccn fields in the FSR */
#define	N_FCCN 4

#define	FSR_FCC0_MASK ((uint64_t)FSR_FCC)
#define	FSR_FCC1_MASK ((uint64_t)FSR_FCC1 << 32)
#define	FSR_FCC2_MASK ((uint64_t)FSR_FCC2 << 32)
#define	FSR_FCC3_MASK ((uint64_t)FSR_FCC3 << 32)

/*
 * No. of bits to shift a fcc field to the right so that its value occupies
 * the least significant bits
 */
#define	FSR_FCC0_SRL_N 10
#define	FSR_FCC1_SRL_N 32
#define	FSR_FCC2_SRL_N 34
#define	FSR_FCC3_SRL_N 36

static uint64_t fccMasks[] =
{
	FSR_FCC0_MASK,
	FSR_FCC1_MASK,
	FSR_FCC2_MASK,
	FSR_FCC3_MASK
};

static unsigned int fccShifts[] =
{
	FSR_FCC0_SRL_N,
	FSR_FCC1_SRL_N,
	FSR_FCC2_SRL_N,
	FSR_FCC3_SRL_N
};


/*
 * Data structure for the fccn test data. We are using only single-precision
 * comparisions
 */
typedef struct {
	char			*testId;
	unsigned int	val1;	/* Operand 1 */
	unsigned int	val2;	/* Operand 2 */

	/* The value of the fcc field after the FP operation */
	unsigned int	fccVal;
}FccData;

static FccData  fccData[] =
{
	{"test-0", 0xc0980000, 0xc0980000, 0},	/* -ve = -ve */
	{"test-1", 0x40980000, 0x40980000, 0},	/* +ve = +ve */

	{"test-2", 0xc0980000, 0x40980000, 1},	/* -ve < +ve */
	{"test-3", 0xc0980000, 0xc094cccd, 1},	/* -ve < -ve */
	{"test-4", 0x40980000, 0x40983958, 1},	/* +ve < +ve */

	{"test-5", 0x40980000, 0xc0980000, 2},	/* +ve > -ve */
	{"test-6", 0x40983958, 0x40980000, 2},	/* +ve > +ve */
	{"test-7", 0xc094cccd, 0xc0980000, 2},	/* -ve > -ve */

	{"test-8", 0xc094cccd, nan_sp, 3},	/* +ve ? NaN */
	{"test-9", nan_sp, 0xc094cccd, 3},	/* -ve ? NaN */
	{"test-10", nan_sp, nan_sp, 3},	/* NaN ? NaN */

};

#define	N_FCCDATA  (sizeof (fccData) / sizeof (FccData))

/* Data used in test_rounding() */
#define	FOUR_SP			0x40800000U
#define	THREE_SP		0x40400000U
#define	FOUR_DP_MSW		0x40100000U
#define	FOUR_DP_LSW		0x00000000U
#define	THREE_DP_MSW	0x40080000U
#define	THREE_DP_LSW	0x00000000U
#define	FSR_RD_MASK_Z	0xFFFFFFFF3FFFFFFFUL

/* No. of IEEE 754 rounding modes */
#define	N_RD_MODES		4

/* Data structure for the rounding test data */
typedef struct {
	char			*test_id;
	unsigned int	operand1_msw;
	unsigned int	operand1_lsw;
	unsigned int	operand2_msw;
	unsigned int	operand2_lsw;
	unsigned int	operation;
	uint64_t	    result_r2n;	/* Round to Nearest */
	uint64_t	    result_r2z;	/* Round to Zero */
	uint64_t	    result_r2pinf;	/* Round to +infinity */
	uint64_t	    result_r2ninf;	/* Round to -infinity */

}	RoundingData;


/* Strings for rounding modes */
static char	*rndModes[] =
{
	"Round to Nearest",
	"Round to Zero",
	"Round to +infinity",
	"Round to -infinity",
};

/* Rounding test data */
static RoundingData r_data[] =
{
	/* 4/3 SP */
	{"Test-0",
		FOUR_SP,
		nocare,
		THREE_SP,
		nocare,
		op_div_sp,
		0x3faaaaab,
		0x3faaaaaa,
		0x3faaaaab,
	0x3faaaaaa},

	/* 4/3 DP */
	{"Test-1",
		FOUR_DP_MSW,
		FOUR_DP_LSW,
		THREE_DP_MSW,
		THREE_DP_LSW,
		op_div_dp,
		0x3ff5555555555555,
		0x3ff5555555555555,
		0x3ff5555555555556,
	0x3ff5555555555555},

	{"Test-2",
		0xc0600018,
		nocare,
		0xc1700009,
		nocare,
		op_add_sp,
		0xc1940008,
		0xc1940007,
		0xc1940007,
	0xc1940008},

	{"Test-3",
		0x880c0000,
		0x00000018,
		0x882e0000,
		0x00000009,
		op_add_dp,
		0x8832800000000008,
		0x8832800000000007,
		0x8832800000000007,
	0x8832800000000008},

	/* 4/3 (DP) and convert to SP */
	{"Test-4",
		FOUR_DP_MSW,
		FOUR_DP_LSW,
		THREE_DP_MSW,
		THREE_DP_LSW,
		op_div_dp_c2sp,
		0x3faaaaab,
		0x3faaaaaa,
		0x3faaaaab,
	0x3faaaaaa},

	/*
	 * Convert a 64-bit *signed* integer to a single- precison FP number.
	 * The 64-bit signed number used here, 0x0x882e000000000009, is
	 * -0x77d1fffffffffff7 i.e -8633963435622662135.
	 */
	{"Test-5",
		0x882e0000,
		0x00000009,
		nocare,
		nocare,
		op_fxtos,
		0xdeefa400,
		0xdeefa3ff,
		0xdeefa3ff,
	0xdeefa400}

};

#define	R_DATA_N  (sizeof (r_data)/sizeof (RoundingData))

/*
 * fsr_test(struct fps_test_ereport *report) is the high level
 * caller of the functions that test the different fields of
 * the FSR. If an error is found, relevant data is stored in
 * report.
 */
int
fsr_test(struct fps_test_ereport *report)
{
	if (test_ieee754_exc_fields(T_DISABLED, report) != FPU_OK)
		return (FPU_FOROFFLINE);

	if (test_ieee754_exc_fields(T_ENABLED, report) != FPU_OK)
		return (FPU_FOROFFLINE);

	if (test_fccn(report) != FPU_OK)
		return (FPU_FOROFFLINE);

	if (test_rounding(report) != FPU_OK)
		return (FPU_FOROFFLINE);

	return (FPU_OK);
}

/*
 * test_ieee754_exc_fields(int trapStatus,
 * struct fps_test_ereport *report)tests the FSR.cexc,
 * and FSR.aexc fields. It can operate in two modes: traps
 * enabled and traps disabled.
 *
 * In the T_DISABLED (FSR.TEM=0) mode, it checks if the
 * FSR.cexc and FSR.aexc fields have been set correctly.
 *
 * In the T_ENABLED mode, it check if the
 * appropriate trap has been raised and the FSR.cexc field has the correct
 * value.
 *
 * If an error is found, relevant data is stored in report.
 */
static int
test_ieee754_exc_fields(int trapStatus, struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	int rval;
	uint64_t expected;
	uint64_t observed;
	uint64_t prev_fsr;
	uint64_t result_fsr;
	uint64_t t_fsr;
	unsigned long alsw;
	unsigned long amsw;
	unsigned long blsw;
	unsigned long bmsw;
	unsigned long exc_bits;
	unsigned long operation;

	rval = FPU_OK;
	prev_fsr = get_fsr();

	for (i = 0; test_ws[i].instr != 0; i++) {
		if (trapStatus == T_DISABLED) {
			set_fsr(prev_fsr & 0xFFFFFFFFF07FFC00);
		} else {
			t_fsr = prev_fsr & 0xFFFFFFFFF07FFC1F;
			t_fsr |= 0x000000000F800000;
			set_fsr(t_fsr);
		}

		trap_flag = trap_flag | TRAP_SOLICITED;

		amsw = test_ws[i].a_msw;
		alsw = test_ws[i].a_lsw;
		bmsw = test_ws[i].b_msw;
		blsw = test_ws[i].b_lsw;
		operation = test_ws[i].instr;

		if (trapStatus == T_DISABLED)
			exc_bits = test_ws[i].fsr_tem0_ieee754_exc;
		else
			exc_bits = test_ws[i].fsr_tem1_ieee754_exc;

		result_fsr = 0;
		fsr_at_trap = 0;

		switch (operation) {
		case op_add_sp:
			result_fsr = wadd_sp(amsw, bmsw);
			break;
		case op_add_dp:
			result_fsr = wadd_dp(amsw, alsw, bmsw, blsw);
			break;
		case op_div_sp:
			result_fsr = wdiv_sp(amsw, bmsw);
			break;
		case op_div_dp:
			result_fsr = wdiv_dp(amsw, alsw, bmsw, blsw);
			break;
		case op_mul_sp:
			result_fsr = wmult_sp(amsw, bmsw);
			break;
		case op_mul_dp:
			result_fsr = wmult_dp(amsw, alsw, bmsw, blsw);
			break;
		case op_fsqrts:
			result_fsr = wsqrt_sp(amsw);
			break;
		case op_fsqrtd:
			result_fsr = wsqrt_dp(((uint64_t)amsw << 32)
			    | alsw);
			break;
		default:
			break;
		}

		if (trapStatus == T_ENABLED) {
			if (!trap_flag) {
				result_fsr = fsr_at_trap;
			} else {
				rval = FPU_FOROFFLINE;
				observed = 1;
				expected = 0;
				(void) snprintf(err_data, sizeof (err_data),
				    "test: %d", i);
				setup_fps_test_struct(IS_EREPORT_INFO,
				    report, 6305, &observed, &expected,
				    1, 1, err_data);
			}
		}
		if ((result_fsr & exc_bits) != exc_bits) {
			rval = FPU_FOROFFLINE;
			observed = (uint64_t)(result_fsr & exc_bits);
			expected = (uint64_t)exc_bits;
			(void) snprintf(err_data, sizeof (err_data),
			    "test: %d, trapStatus: %d", i, trapStatus);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6308, &observed, &expected, 1, 1, err_data);
		}
	}

	set_fsr(prev_fsr);

	return (rval);
}

/*
 * test_fccn(struct fps_test_ereport *report)
 * test the fcc0, fcc1, fcc2, and fcc3 fields of the FSR. Single-
 * precision comparision operations are done using the test data given
 * in fccData[], and the resultant value in the fccN field is compared
 * against the value in fccData. Each test data is used with all the
 * four fcc fields.
 *
 * If an error is found, relevant data is stored in report.
 */
static int
test_fccn(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int fcc;
	int i;
	int rval;
	uint64_t expected;
	uint64_t fcc_mask;
	uint64_t observed;
	uint64_t prev_fsr;
	uint64_t result_fsr;
	unsigned int shiftBits;

#ifdef __lint
	uint64_t des_fcc;
	uint64_t res_fcc;
#else
	unsigned int des_fcc;
	unsigned int res_fcc;
#endif

	prev_fsr = get_fsr();
	rval = FPU_OK;
	set_fsr(prev_fsr & 0xFFFFFFFFF07FFC00);

	for (fcc = 0; fcc < N_FCCN; fcc++) {
		fcc_mask = fccMasks[fcc];
		shiftBits = fccShifts[fcc];

		for (i = 0; i < N_FCCDATA; i++) {
			des_fcc = fccData[i].fccVal;

			result_fsr = fcmps_fcc(fccData[i].val1,
			    fccData[i].val2, fcc);

			res_fcc = ((result_fsr & fcc_mask)
			    >> shiftBits);

			if (res_fcc != des_fcc) {
				rval = FPU_FOROFFLINE;
				expected = (uint64_t)des_fcc;
				observed = (uint64_t)res_fcc;
				(void) snprintf(err_data, sizeof (err_data),
				    "FSR.fcc: %d, FCC ID: %s"
				    "\nExpected: %lld"
				    "\nObserved: %lld",
				    fcc, fccData[i].testId, des_fcc,
				    res_fcc);
				setup_fps_test_struct(IS_EREPORT_INFO,
				    report, 6310, &observed, &expected,
				    1, 1, err_data);
				continue;
			}
		}
	}

	set_fsr(prev_fsr);

	return (rval);
}

/*
 * test_rounding(struct fps_test_ereport *report)
 * tests the 4 IEEE 754 rounding modes.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
test_rounding(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	int rval;
	uint64_t des_res;
	uint64_t expected;
	uint64_t fsr_rd_masked;
	uint64_t gsr_im_z;
	uint64_t observed;
	uint64_t oprnd;
	uint64_t oprnd1;
	uint64_t oprnd2;
	uint64_t prev_fsr;
	uint64_t prev_gsr;
	uint64_t rd;
	uint64_t result;
	uint64_t rmode;

	rval = FPU_OK;
	prev_fsr = get_fsr();
	fsr_rd_masked = prev_fsr & FSR_RD_MASK_Z;
	prev_gsr = get_gsr();
	gsr_im_z = prev_gsr & GSR_IM_ZERO;

	for (i = 0; i < R_DATA_N; i++) {
		for (rd = 0; rd < N_RD_MODES; rd++) {
			rmode = rd << 30;

			if (rd == 0)
				des_res = r_data[i].result_r2n;
			else if (rd == 1)
				des_res = r_data[i].result_r2z;
			else if (rd == 2)
				des_res = r_data[i].result_r2pinf;
			else if (rd == 3)
				des_res = r_data[i].result_r2ninf;

			switch (r_data[i].operation) {
			case op_add_sp:
				set_gsr(gsr_im_z);
				set_fsr(fsr_rd_masked | rmode);
				result = add_sp(r_data[i].operand1_msw,
				    r_data[i].operand2_msw);

				break;
			case op_add_dp:
				oprnd1 =
				    ((uint64_t)r_data[i].operand1_msw
				    << 32) | r_data[i].operand1_lsw;

				oprnd2 =
				    ((uint64_t)r_data[i].operand2_msw
				    << 32) | r_data[i].operand2_lsw;

				set_gsr(gsr_im_z);
				set_fsr(fsr_rd_masked | rmode);
				result = add_dp(oprnd1, oprnd2);

				break;
			case op_div_sp:
				set_gsr(gsr_im_z);
				set_fsr(fsr_rd_masked | rmode);
				result = div_sp(r_data[i].operand1_msw,
				    r_data[i].operand2_msw);

				break;
			case op_div_dp:
				oprnd1 =
				    ((uint64_t)r_data[i].operand1_msw
				    << 32) | r_data[i].operand1_lsw;

				oprnd2 =
				    ((uint64_t)r_data[i].operand2_msw
				    << 32) | r_data[i].operand2_lsw;

				set_gsr(gsr_im_z);
				set_fsr(fsr_rd_masked | rmode);
				result = div_dp(oprnd1, oprnd2);

				break;
			case op_div_dp_c2sp:
				oprnd1 =
				    ((uint64_t)r_data[i].operand1_msw
				    << 32) | r_data[i].operand1_lsw;

				oprnd2 =
				    ((uint64_t)r_data[i].operand2_msw
				    << 32) | r_data[i].operand2_lsw;

				set_gsr(gsr_im_z);
				set_fsr(fsr_rd_masked | rmode);
				result = div_dp(oprnd1, oprnd2);
				result = convert_dp_sp(result);

				break;
			case op_fxtos:
				oprnd =
				    ((uint64_t)r_data[i].operand1_msw
				    << 32) | r_data[i].operand1_lsw;
				set_gsr(gsr_im_z);
				set_fsr(fsr_rd_masked | rmode);
				result = long_float_s(oprnd);

				break;
			default:
				break;
			}

			if (result != des_res) {
				expected = (uint64_t)des_res;
				observed = (uint64_t)result;
				(void) snprintf(err_data, sizeof (err_data),
				    "FSR.RD: %d, %s, TestID: %s"
				    "\nExpected: %lld\nObserved: %lld",
				    rd, rndModes[rd], r_data[i].test_id,
				    des_res, result);
				setup_fps_test_struct(IS_EREPORT_INFO,
				    report, 6309, &observed, &expected,
				    1, 1, err_data);
				rval = FPU_FOROFFLINE;
			}
		}
	}

	set_gsr(prev_gsr);
	set_fsr(prev_fsr);

	return (rval);
}
