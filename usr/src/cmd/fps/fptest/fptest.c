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
 * Copyright 2008 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __lint
#pragma error_messages(off, E_VALUE_TYPE)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <math.h>
#include <sys/dditypes.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>
#include <sys/processor.h>
#include <sys/pset.h>
#include <time.h>
#include <kstat.h>
#include <fp.h>
#include <fptest.h>
#include <fpstestmsg.h>
#include <externs.h>
#include <fps_ereport.h>
#include <fps_defines.h>

#define	GetBoxStringLen SYS_NMLN
#define	NANO_IN_MILI 1000000
#define	MILI_IN_SEC 1000
#define	str_v9 "sparcv9"
#define	str_v9b "sparcv9+vis2"
#define	testname "fptest"

static int fps_exec_time = 0;
static int fps_verbose_msg = 0;
static int fpu_cpu = -1;
static int test_group = 1;
static int stress_level = 1;
static int limit_group = 1;
static int proc_fr;
static int lowstresslapagroup_len;
static int lowstresslapagroup1000_len;
static int lowstresslapagroup1500_len;
static int lowstresslapagroup2000_len;
static int medstresslapagroup_len;
static int highstresslapagroup_len;
static struct LapaGroup *lowstresslapagroup;

static void exe_time(hrtime_t timeStart);
static void process_fpu_args(int argc, char *argv[]);
static int check_proc(int cpu_id);
static int do_lapack(int unit, struct fps_test_ereport *report);
static int dpmath(struct fps_test_ereport *report);
static int is_cpu_on(int unit);
static int spmath(struct fps_test_ereport *report);
static int start_testing(int unit,
    struct fps_test_ereport *report);

/*
 * main(int argc, char *argv[])
 * is the main entry into the test.
 */
int
main(int argc, char *argv[])
{
	int test_ret;
	int procb;
	int proc_setb;
	int ret = 0;
	hrtime_t test_start;
	psetid_t opset = PS_NONE;
	processorid_t proc_used = PBIND_NONE;
	static struct fps_test_ereport ereport_data;

	/* these are % ( modulo ) values */
	lowstresslapagroup1000_len =
	    (sizeof (LowStressLapaGroup_1000) / sizeof (struct LapaGroup)) - 1;
	lowstresslapagroup1500_len =
	    (sizeof (LowStressLapaGroup_1500) / sizeof (struct LapaGroup)) - 1;
	lowstresslapagroup2000_len =
	    (sizeof (LowStressLapaGroup_2000) / sizeof (struct LapaGroup)) - 1;
	medstresslapagroup_len =
	    (sizeof (MedStressLapaGroup) / sizeof (struct LapaGroup)) - 1;
	highstresslapagroup_len =
	    (sizeof (HighStressLapaGroup) / sizeof (struct LapaGroup)) - 1;

	/* default frequency values */
	proc_fr = 1000;
	lowstresslapagroup_len = lowstresslapagroup1000_len;
	lowstresslapagroup = LowStressLapaGroup_1000;

	initialize_fps_test_struct(&ereport_data);

	process_fpu_args(argc, argv);

	fps_msg(fps_verbose_msg, gettext(FPSM_04), lowstresslapagroup_len,
	    medstresslapagroup_len, highstresslapagroup_len);

#ifdef V9B
	fps_msg(fps_verbose_msg, gettext(FPSM_03), testname, "V9B");
#else
	fps_msg(fps_verbose_msg, gettext(FPSM_03), testname, "V9");
#endif

	if (fpu_cpu < 0)
		return (FPU_INVALID_ARG);

	test_start = gethrtime();

	procb = processor_bind(P_PID, P_MYID, fpu_cpu, NULL);

	if (procb) {
		if ((pset_assign(PS_QUERY,
		    (processorid_t)fpu_cpu, &opset) == 0) &&
		    (opset != PS_NONE)) {
			proc_setb = pset_bind(opset, P_PID, P_MYID, NULL);
		}

		if (proc_setb) {
			return (FPU_BIND_FAIL);
		}

		procb = processor_bind(P_PID, P_MYID, fpu_cpu, NULL);

		if (procb) {
			pset_bind(PS_NONE, P_PID, P_MYID, NULL);
			return (FPU_BIND_FAIL);
		}
	}

	/* start testing */
	ereport_data.cpu_id = fpu_cpu;
	test_ret = start_testing(fpu_cpu, &ereport_data);

	if (test_ret == FPU_FOROFFLINE) {
		/*
		 * check bind and
		 * check if on supported plaform
		 */
		processor_bind(P_PID, P_MYID, PBIND_QUERY, &proc_used);

		if (proc_used != (processorid_t)fpu_cpu ||
		    proc_used == PBIND_NONE) {
			ret = FPU_BIND_FAIL;
			ereport_data.is_valid_cpu = 0;
		}

		if (check_proc(fpu_cpu) != 0) {
			ret = FPU_UNSUPPORT;
			ereport_data.is_valid_cpu = 0;
		}

		if (ret != FPU_UNSUPPORT) {
			if (fps_generate_ereport_struct(&ereport_data)
			    != 0)
				ret = FPU_EREPORT_INCOM;
			else
				ret = FPU_FOROFFLINE;
		}
	}

	if (fps_exec_time)
		exe_time(test_start);

	return (ret);
}

/*
 * exe_time(hrtime_t timeStart, int unit)
 * returns Execution time: H.M.S.Msec
 */
static void
exe_time(hrtime_t time_start)
{
	hrtime_t mili_now;
	hrtime_t mili_start;
	long hour;
	long minute;
	long second;
	long mili;
	long dif_mili;
	long mili_to_sec;

	mili_start = time_start / NANO_IN_MILI;
	mili_now = gethrtime() / NANO_IN_MILI;

	dif_mili = (long)(mili_now - mili_start);
	mili_to_sec = dif_mili / MILI_IN_SEC;
	hour = mili_to_sec / 3600;
	minute = (mili_to_sec - (hour * 3600)) / 60;
	second = (mili_to_sec - ((hour * 3600) + (minute * 60)));
	mili =
	    (dif_mili - ((second * 1000) + (((hour * 3600) +
	    (minute * 60)) * 1000)));

	printf("Execution time: %ldH.%ldM.%ldS.%ldMsec\n", hour, minute,
	    second, mili);
	fflush(NULL);
}

/*
 * start_testing(int unit, int argc, char *argv[],
 * struct fps_test_ereport *report) performs each sub-test
 * sequentially and stores any failed test information in
 * report.
 */
static int
start_testing(int unit, struct fps_test_ereport *report)
{
	int lim;
	int sdclimit;

	if (report == NULL)
		return (-1);

	/*
	 * The non-lapack logic will be executed when -p 0 OR -p ALL
	 */
	if ((0 == test_group) || (12345 == test_group)) {
		fps_msg(fps_verbose_msg, gettext(FPSM_01), unit, limit_group);

		/* turn on signal handlers */
		(void) winitfp();

		if (fpu_sysdiag(report) != 0) {
			return (FPU_FOROFFLINE);
		}

		/* turn off signal handlers */
		(void) restore_signals();

		if (spmath(report) != 0) {
			return (FPU_FOROFFLINE);
		}

		if (dpmath(report) != 0) {
			return (FPU_FOROFFLINE);
		}

		if (cbbcopy(report) != 0) {
			return (FPU_FOROFFLINE);
		}

		sdclimit = 100;

		if (limit_group == 2)
			sdclimit = 1000;
		if (limit_group == 3)
			sdclimit = 10000;

		if (cheetah_sdc_test(sdclimit, report) != 0) {
			return (FPU_FOROFFLINE);
		}

		lim = 100;

		if (limit_group == 2)
			lim = 1000;
		if (limit_group == 3)
			lim = 100000;

		if (fpu_fdivd(lim, report) != 0) {
			return (FPU_FOROFFLINE);
		}

		if (fpu_fmuld(lim, report) != 0) {
			return (FPU_FOROFFLINE);
		}

		if (fpu_fmulx(lim, report) != 0) {
			return (FPU_FOROFFLINE);
		}

#ifdef V9B

		lim = 10;

		if (limit_group == 2)
			lim = 100;
		if (limit_group == 3)
			lim = 1000;

		if (align_data(lim, unit, report) != 0) {
			return (FPU_FOROFFLINE);
		}

		if (vis_test(unit, report) != 0) {
			return (FPU_FOROFFLINE);
		}

#endif

		if (test_group == 0)
			return (FPU_OK);

	} /* end the non lapack area */

	if (do_lapack(unit, report) != 0)
		return (FPU_FOROFFLINE);

	return (FPU_OK);
}

/*
 * do_lapack(struct fps_test_ereport *report) calls the lapack
 * tests and stores any error info into report.
 */
static int
do_lapack(int unit, struct fps_test_ereport *report)
{
	int lapa_group_index;
	int lapa_loop_stress;
	int lapa_stress;
	int lapa_loop;
	int high_lim;
	int low_lim;

	fps_msg(fps_verbose_msg, gettext(FPSM_05), limit_group);

	switch (limit_group) {
	case 1:
		lapa_group_index = test_group % lowstresslapagroup_len;

		if (lapa_group_index <= 0)
			lapa_group_index = 1;

		low_lim = lowstresslapagroup[lapa_group_index].limLow;
		high_lim = lowstresslapagroup[lapa_group_index].limHigh;

		if (test_group == 12345) {
			low_lim = 1;
			high_lim =
			    lowstresslapagroup[lowstresslapagroup_len - 1]
			    .limHigh;
		}

		break;
	case 2:
		lapa_group_index = test_group % medstresslapagroup_len;

		if (lapa_group_index <= 0)
			lapa_group_index = 1;

		low_lim = MedStressLapaGroup[lapa_group_index].limLow;
		high_lim = MedStressLapaGroup[lapa_group_index].limHigh;

		if (test_group == 12345) {
			low_lim = 1;
			high_lim =
			    MedStressLapaGroup[medstresslapagroup_len - 1]
			    .limHigh;
		}
		break;
	case 3:
		lapa_group_index = test_group % highstresslapagroup_len;

		if (lapa_group_index <= 0)
			lapa_group_index = 1;

		low_lim = HighStressLapaGroup[lapa_group_index].limLow;
		high_lim = HighStressLapaGroup[lapa_group_index].limHigh;

		if (test_group == 12345) {
			low_lim = 1;
			high_lim =
			    HighStressLapaGroup[highstresslapagroup_len - 1]
			    .limHigh;
		}

		/* hidden arg -s X */
		if (stress_level > 4000) {
			low_lim = 1;
			high_lim = stress_level;
		}
		break;
	default:
		low_lim = 100;
		high_lim = 200;
		break;
	}

	if (low_lim < 1)
		low_lim = 101;

	if (high_lim > 10000)
		high_lim = 201;

	for (lapa_stress = low_lim; lapa_stress <= high_lim;
	    lapa_stress = lapa_stress + 1) {
		if (lapa_stress > 999) {
			for (lapa_loop = lapa_stress; lapa_loop <= high_lim;
			    lapa_loop = lapa_loop + 1000) {
				lapa_loop_stress = lapa_loop;

				if (lapa_loop_stress == 4000)
					lapa_loop_stress = 4016;
				if (lapa_loop_stress == 7000)
					lapa_loop_stress = 7016;
				if (lapa_loop_stress == 8000)
					lapa_loop_stress = 8034;

				if (slinpack_test(lapa_loop_stress, unit,
				    report, fps_verbose_msg))
					return (-4);
				if (dlinpack_test(lapa_loop_stress, unit,
				    report, fps_verbose_msg))
					return (-4);
			}
		break;
		}

		if (slinpack_test(lapa_stress, unit, report, fps_verbose_msg))
			return (-4);
		if (dlinpack_test(lapa_stress, unit, report, fps_verbose_msg))
			return (-4);
	}

	return (0);
}


/*
 * spmath(int unit, struct fps_test_ereport *report)
 * peforms basic tests of the arithmetic operations:
 * +, -, *, and /. If any errors, they are stored in
 * report.
 */
static int
spmath(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	float a;
	float ans;
	float b;
	float expect_ans;
	uint64_t expected;
	uint64_t observed;

	a = 1.2345;
	b = 0.9876;

#ifndef __lint
	ans = a + b;
#endif
	ans = a + b;
	expect_ans = 2.2221000;
	if (ans != expect_ans) {
		if (ans < (2.2221000 - SPMARGIN) ||
		    ans > (2.2221000 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6112, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = (a - b);
	expect_ans = 0.2469000;
	if (ans != expect_ans) {
		if (ans < (0.2469000 - SPMARGIN) ||
		    ans > (0.2469000 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6113, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a * b;
	expect_ans = 1.2191923;
	if (ans != expect_ans) {
		if (ans < (1.2191923 - SPMARGIN) ||
		    ans > (1.2191923 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6114, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a / b;
	expect_ans = 1.2500000;
	if (ans != expect_ans) {
		if (ans < (1.2500000 - SPMARGIN) ||
		    ans > (1.2500000 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6115, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a + (a - b);
	expect_ans = 1.4814000;
	if (ans != expect_ans) {
		if (ans < (1.4814000 - SPMARGIN) ||
		    ans > (1.4814000 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6116, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a - (a + b);
	expect_ans = -(0.9876000);
	if (ans != expect_ans) {
		if (ans < (-(0.9876000) - SPMARGIN) ||
		    ans > (-(0.9876000) + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6117, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a + (a * b);
	expect_ans = 2.4536924;
	if (ans != expect_ans) {
		if (ans < (2.4536924 - SPMARGIN) ||
		    ans > (2.4536924 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6118, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a - (a * b);
	expect_ans = 0.0153078;
	if (ans != expect_ans) {
		if (ans < (0.0153078 - SPMARGIN) ||
		    ans > (0.0153078 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6119, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a + (a / b);
	expect_ans = 2.4844999;
	if (ans != expect_ans) {
		if (ans < (2.4844999 - SPMARGIN) ||
		    ans > (2.4844999 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6120, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a - (a / b);
	expect_ans = expect_ans;
	if (ans != -(0.0155000)) {
		if (ans < (-(0.0155000) - SPMARGIN) ||
		    ans > (-(0.0155000) + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6121, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a * (a + b);
	expect_ans = 2.7431827;
	if (ans != expect_ans) {
		if (ans < (2.7431827 - SPMARGIN) ||
		    ans > (2.7431827 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6122, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a * (a - b);
	expect_ans = 0.3047981;
	if (ans != expect_ans) {
		if (ans < (0.3047981 - SPMARGIN) ||
		    ans > (0.3047981 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6123, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a / (a + b);
	expect_ans = 0.5555556;
	if (ans != expect_ans) {
		if (ans < (0.5555556 - SPMARGIN) ||
		    ans > (0.5555556 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6124, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a / (a - b);
	expect_ans = 4.9999995;
	if (ans != expect_ans) {
		if (ans < (4.9999995 - SPMARGIN) ||
		    ans > (4.9999995 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6125, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	ans = a * (a / b);
	expect_ans = 1.5431250;
	if (ans != expect_ans) {
		if (ans < (1.5431250 - SPMARGIN) ||
		    ans > (1.5431250 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6126, &observed, &expected, 1,
			    1, err_data);

		return (-2);
		}
	}

	ans = a / (a * b);
	expect_ans = 1.0125557;
	if (ans != expect_ans) {
		if (ans < (1.0125557 - SPMARGIN) ||
		    ans > (1.0125557 + SPMARGIN)) {
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.8f\nObserved: %.8f",
			    expect_ans, ans);
			expected = (uint64_t)(*(uint32_t *)&expect_ans);
			observed = (uint64_t)(*(uint32_t *)&ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6127, &observed, &expected, 1,
			    1, err_data);

			return (-2);
		}
	}

	return (0);
}

/*
 * dpmath(int unit, struct fps_test_ereport *report)
 * peforms basic tests of the arithmetic operations:
 * +, -, *, and /. It also performs tests of cos,
 * sine, tan, log, sqrt, and exp. If any errors,
 * they are stored in report.
 */
static int
dpmath(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	double a;
	double ans;
	double b;
	double expect_ans;
	double expect_ans2;
	double result;
	double x;
	uint64_t expected;
	uint64_t observed;

	a = 1.2345;
	b = 0.9876;

	ans = (a + b);
	expect_ans = 2.222100000000000;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6128, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = (a - b);
	expect_ans = 0.246899999999999;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6129, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a * b;
	expect_ans = 1.219192199999999;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6130, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a / b;
	expect_ans = 1.249999999999999;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6131, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a + (a - b);
	expect_ans = 1.481399999999999;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6132, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a - (a + b);
	expect_ans = -(0.987600000000000);
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6133, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a + (a * b);
	expect_ans = 2.453692200000000;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6134, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a - (a * b);
	expect_ans = 0.015307800000000;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6135, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a + (a / b);
	expect_ans = 2.484500000000000;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6136, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a - (a / b);
	expect_ans = -(0.015499999999999);
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6137, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a * (a + b);
	expect_ans = 2.743182449999999;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6138, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a * (a - b);
	expect_ans = 0.304798049999999;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6139, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}


	ans = a / (a + b);
	expect_ans = 0.555555555555555;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6140, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a / (a - b);
	expect_ans = 5.000000000000002;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6141, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a * (a / b);
	expect_ans = 1.543124999999999;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6142, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	ans = a / (a * b);
	expect_ans = 1.012555690562980;
	if (ans != expect_ans) {
		if (ans < (expect_ans - DPMARGIN) ||
		    ans > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&ans;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, ans);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6143, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	/* Start Double Precision test of trg functions */

	/* sin of values in the range of -2pi to +2pi   */
	result = sin(-(pi * 2));
	expect_ans = -(0.000000000820413);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6144, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin((pi * (-3)) / 2);
	expect_ans = 1.0000000000000000;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6145, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
#ifndef i86pc
		else if (result > (-(0.000000000000000) + DPMARGIN)) {
			expected = (uint64_t)-(0.000000000000000);
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    -0.000000000000000, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6146, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
#endif
	}

	result = sin(-(pi));
	expect_ans = 0.000000000410206;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6147, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin(-(pi / 2));
	expect_ans = -(1.0000000000000000);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6148, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin(0.0);
	expect_ans = 0.0000000000000000;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6149, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin(pi / 2);
	expect_ans = 1.0000000000000000;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6150, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin(pi);
	expect_ans = -(0.000000000410206);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6151, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin((pi * 3) / 2);
	expect_ans = -(1.0000000000000000);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6152, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin(pi * 2);
	expect_ans = 0.000000000820143;
	expect_ans2 = 0.00000000820143;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans2 + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6153, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	/* cos of values in the range of -2pi to +2pi   */
	result = cos(pi * (-2));
	expect_ans = 1.0000000000000000;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6154, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos((pi * (-3)) / 2);
	expect_ans = 0.000000000615310;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6155, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos(-pi);
	expect_ans = -(1.0000000000000000);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6156, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos(-(pi / 2));
	expect_ans = -(0.000000000205103);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6157, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos(0.0);
	expect_ans = 1.0000000000000000;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6158, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos(pi / 2);
	expect_ans = (-0.000000000205103);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6159, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos(pi);
	expect_ans = (-1.0000000000000000);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6160, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos((pi * 3) / 2);
	expect_ans = 0.000000000615310;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6161, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos(pi * 2);
	expect_ans = 1.0000000000000000;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6162, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	/* sin and cos of: pi/4, 3pi/4, 5pi/4 and 7pi/4  */
	result = sin(pi / 4);
	expect_ans = 0.707106781259062;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6163, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin((pi * 3) / 4);
	expect_ans = 0.707106780969002;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6164, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin((pi * 5) / 4);
	expect_ans = -(0.707106781549122);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6165, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = sin((pi * 7) / 4);
	expect_ans = -(0.707106780678942);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6166, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos(pi / 4);
	expect_ans = 0.707106781114032;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6167, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos((pi * 3) / 4);
	expect_ans = -(0.707106781404092);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6168, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos((pi * 5) / 4);
	expect_ans = -(0.707106780823972);
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6169, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	result = cos((pi * 7) / 4);
	expect_ans = 0.707106781694152;
	if (result != expect_ans) {
		if (result < (expect_ans - DPMARGIN) ||
		    result > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&result;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6170, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	/* exponential	 */
	x = exp(0.0);
	expect_ans = 1.0000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6171, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(1.0);
	expect_ans = 2.718281828459045;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6172, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(2.0);
	expect_ans = 7.389056098930650;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6173, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(5.0);
	expect_ans = 148.413159102576600;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6174, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(10.0);
	expect_ans = 22026.465794806718000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6175, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(-1.0);
	expect_ans = 0.367879441171442;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6176, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(-2.0);
	expect_ans = 0.135335283236612;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6177, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(-5.0);
	expect_ans = 0.006737946999085;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6178, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(-10.0);
	expect_ans = 0.000045399929762;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6179, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(log(1.0));
	expect_ans = 1.0000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6180, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = exp(log(10.0));
	expect_ans = 10.000000000000002;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6181, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	/* logarithms */
	x = log(1.0);
	expect_ans = 0.0000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
		expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6182, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = log(2.0);
	expect_ans = 0.693147180559945;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6183, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = log(10.0);
	expect_ans = 2.302585092994045;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6184, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = log(100.0);
	expect_ans = 4.605170185988091;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6185, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = log(exp(0.0));
	expect_ans = 0.0000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6186, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = log(exp(1.0));
	expect_ans = 1.0000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6187, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = log(exp(10.0));
	expect_ans = 10.0000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6188, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	/*
	 * These functions are supported by the 68881
	 * but not the FPA
	 */

	x = tan(-(2 * pi));
	expect_ans = -(0.000000000820414);
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6189, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan(-(7 * pi) / 4);
	expect_ans = 0.999999998564275;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6190, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan(-(5 * pi) / 4);
	expect_ans = -(1.000000001025517);
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),\
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6191, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan(-(pi));
	expect_ans = -(0.000000000410207);
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6192, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan(-(3 * pi) / 4);
	expect_ans = 0.999999999384690;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6193, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan(-(pi) / 4);
	expect_ans = -(1.000000000205103);
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6194, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan(0.0);
	expect_ans = 0.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6195, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan(pi / 4);
	expect_ans = 1.000000000205103;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6196, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan((3 * pi) / 4);
	expect_ans = -(0.999999999384690);
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6197, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan(pi);
	expect_ans = 0.000000000410207;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6198, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan((5 * pi) / 4);
	expect_ans = 1.000000001025517;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6199, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan((7 * pi) / 4);
	expect_ans = -(0.999999998564275);
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6200, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = tan((2 * pi));
	expect_ans = 0.000000000820414;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6201, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(0.0);
	expect_ans = 0.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6202, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(1.0);
	expect_ans = 1.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6203, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(4.0);
	expect_ans = 2.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6204, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(9.0);
	expect_ans = 3.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6205, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(16.0);
	expect_ans = 4.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6206, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(25.0);
	expect_ans = 5.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6207, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(36.0);
	expect_ans = 6.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6208, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(49.0);
	expect_ans = 7.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6209, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(64.0);
	expect_ans = 8.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6210, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(81.0);
	expect_ans = 9.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6211, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	x = sqrt(100.0);
	expect_ans = 10.000000000000000;
	if (x != expect_ans) {
		if (x < (expect_ans - DPMARGIN) ||
		    x > (expect_ans + DPMARGIN)) {
			expected = *(uint64_t *)&expect_ans;
			observed = *(uint64_t *)&x;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16f\nObserved: %.16f",
			    expect_ans, x);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6212, &observed, &expected, 1, 1,
			    err_data);

			return (-3);
		}
	}

	return (0);
}

/*
 * process_fpu_args(int argc, char *argv[])
 * processes the args passed into main()
 * and sets the appropriate global vars.
 */
static void
process_fpu_args(int argc, char *argv[])
{
	char l_buf[32];
	char *px;
	int opt;

	while ((opt = getopt(argc, argv, "s:d:p:f:vnhe")) != EOF) {
	switch (opt) {
		case 'P': /* -p N or -p all or no -p */
		case 'p':

			memset(l_buf, 0, sizeof (l_buf));
			test_group = -1;
			if (NULL != optarg) {
			strncpy(l_buf, optarg, 3);	/* -p all */
			if (!strncasecmp(l_buf, "all", 3)) {
				test_group = 12345;
				break;
				}
				test_group = atoi(optarg);
				if ((0 == test_group) && strcmp(optarg, "0"))
					test_group = -1;
			}

			if (test_group < 0) {
				_exit(FPU_INVALID_ARG);
			}
			break;
		case 'f': /* 1000,1500,2000 freq */
		case 'F':
			memset(l_buf, 0, sizeof (l_buf));
			if (NULL != optarg) {
				strncpy(l_buf, optarg, 5);	/* -f 1000 */
				proc_fr = atoi(optarg);

				switch (proc_fr) {
				case 1000 :
					lowstresslapagroup_len =
					    lowstresslapagroup1000_len;
					lowstresslapagroup =
					    LowStressLapaGroup_1000;
					break;
				case 1500 :
					lowstresslapagroup_len =
					    lowstresslapagroup1500_len;
					lowstresslapagroup =
					    LowStressLapaGroup_1500;
					break;
				case 2000 :
					lowstresslapagroup_len =
					    lowstresslapagroup2000_len;
					lowstresslapagroup =
					    LowStressLapaGroup_2000;
					break;
				default :
					if (proc_fr < 1500) {
						lowstresslapagroup_len =
						    lowstresslapagroup1000_len;
						lowstresslapagroup =
						    LowStressLapaGroup_1000;
						break;
					} else if (proc_fr < 2000) {
						lowstresslapagroup_len =
						    lowstresslapagroup1500_len;
						lowstresslapagroup =
						    LowStressLapaGroup_1500;
						break;
					} else {
						lowstresslapagroup_len =
						    lowstresslapagroup2000_len;
						lowstresslapagroup =
						    LowStressLapaGroup_2000;
						break;
					}
				}
			}
			break;
		case 'd':
			if (optarg == NULL)
				_exit(FPU_INVALID_ARG);

			fpu_cpu = atoi(optarg);

			if (fpu_cpu == 0 && strcmp(optarg, "0"))
				_exit(FPU_INVALID_ARG);

			if (is_cpu_on(fpu_cpu))
				_exit(FPU_BIND_FAIL);
			break;
		case 'E':
		case 'e':
			fps_exec_time = 1;
			break;
		case 'V':
		case 'v':
			fps_verbose_msg = 1;
			break;
		case 'S':
		case 's':
			memset(l_buf, 0, sizeof (l_buf));
			stress_level = 1;

			if (NULL != optarg) {
				strncpy(l_buf, optarg, 2);

				if (('X' != l_buf[0]) && (0 != l_buf[1]))
					l_buf[0] = 'E';

				switch (l_buf[0]) {
				case 'l':
				case 'L':
				case '1':
					stress_level = 1;
					limit_group = 1;
					break;
				case 'm':
				case 'M':
				case '2':
					stress_level = 1000;
					limit_group = 2;
					break;
				case 'h':
				case 'H':
				case '3':
					stress_level = 4000;
					limit_group = 3;
					break;
				case 'X':
					px = optarg + 1;
					stress_level = 10000;
					limit_group = 3;

					if (NULL != px) {
						stress_level = atoi(px);
						if ((0 == stress_level) ||
						    (stress_level > 10000) ||
						    (stress_level < 1000) ||
						    (0 != stress_level % 1000))
							stress_level = 10000;
					}
					break;
				default:
					stress_level = 1;
					limit_group = 1;
					break;
				}
			}
			break;
		default:
			_exit(FPU_INVALID_ARG);
			break;
		}
	}
}

/*
 * is_cpu_on(int unit) checks to see if processor
 * unit is online.
 */
static int
is_cpu_on(int unit)
{
	int proc_stat;

	proc_stat = p_online(unit, P_STATUS);

	if (P_ONLINE == proc_stat)
		return (0);

	return (1);
}

/*
 * check_proc(int cpu_id) checks to see that we're on an
 * fpscrubber supported processor specified by cpu_id.
 */
static int
check_proc(int cpu_id)
{
	char brand[40];
	kstat_ctl_t *kc;
	kstat_t *ksp;
	kstat_named_t *knp;


	/* grab kstat info */
	if ((kc = kstat_open()) == NULL)
		return (1);

	if ((ksp = kstat_lookup(kc, "cpu_info", (int)cpu_id, NULL)) == NULL) {
		kstat_close(kc);

		return (1);
	}

	if ((kstat_read(kc, ksp, NULL)) == -1) {
		kstat_close(kc);

		return (1);
	}

	if ((knp = kstat_data_lookup(ksp, "brand")) == NULL) {
		kstat_close(kc);

		return (1);
	}

	if ((snprintf(brand, MAX_CPU_BRAND, "%s",
	    KSTAT_NAMED_STR_PTR(knp))) < 0) {
		kstat_close(kc);

		return (1);
	}

	/* check against supported CPUs */

	if (strcmp(brand, USIII_KSTAT) != 0 &&
	    strcmp(brand, USIIIi_KSTAT) != 0 &&
	    strcmp(brand, USIIIP_KSTAT) != 0 &&
	    strcmp(brand, USIV_KSTAT) != 0 &&
	    strcmp(brand, USIVP_KSTAT) != 0) {
			kstat_close(kc);

			return (2);
	}

	kstat_close(kc);

	return (0);
}
