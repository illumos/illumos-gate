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

#ifdef __lint
#pragma error_messages(off, E_VALUE_TYPE)
#endif

#include <stdlib.h>
#include <unistd.h>
#include <fp.h>
#include <fps_ereport.h>

#define	EXPECTED	1.9999999999999998E+00

static void fdivd(double *f22, double *f2, double *f12);
static void fmuld(double *x, double *y, double *z, double *z1);
static void fmulx(uint64_t *rs1, uint64_t *rs2, uint64_t *rd);
int fpu_fdivd(int rloop, struct fps_test_ereport *report);
int fpu_fmuld(int rloop, struct fps_test_ereport *report);
int fpu_fmulx(int rloop, struct fps_test_ereport *report);

#ifdef V9B

/* Lint doesn't recognize .il files where these are defined */
#ifdef __lint

unsigned long fcmpgt16(double in1, double in2);
unsigned long fcmpne16(double in1, double in2);
unsigned long setgsr(unsigned long);

#else

extern float fpackfix(double num);
extern unsigned long fcmpgt16(double in1, double in2);
extern unsigned long fcmpne16(double in1, double in2);
extern unsigned long setgsr(unsigned long);

#endif

int align_data(int loop,
    struct fps_test_ereport *report);
int vis_test(struct fps_test_ereport *report);
static int align_error_create(char *err, uint32_t start, uint32_t offest,
    int loop, uint32_t count);
static int do_aligndata(uchar_t *from, uint32_t *offset, size_t sz,
    uchar_t *f0, uchar_t *f2, uint32_t bmask);
static int visgt16(struct fps_test_ereport *report);
static int visne16(struct fps_test_ereport *report);
static int vispackfix(struct fps_test_ereport *report);

#endif


/*
 * fpu_fdivd(int rloop, int unit, struct fps_test_ereport *report)
 * returns whether the correct value is calculated each time
 * rloop times. If an error is found, the relevant data is stored
 * in report. The test uses internally generated random double
 * precision within a certain range to conduct the following test:
 *
 * (a * 2^1022) / ((a+e) * 2^1021)
 *
 * which is guaranteed to fill the resulting mantissa with all ones.
 *
 */
int
fpu_fdivd(int rloop, struct fps_test_ereport *report)
{

	char err_data[MAX_INFO_SIZE];
	double expect_ans = EXPECTED;
	double f12 = 0;
	double f2;
	double f22;
	int loop = 0;
	uint64_t expect;
	uint64_t observe;

	srand48(1L);

	while (loop < rloop) {
		loop++;

		*(uint32_t *)& f22 = mrand48();
		*(uint32_t *)& f22 &= 0x80069fff;
		*(uint32_t *)& f22 |= 0x7fd69f00;

#ifdef __lint
		(void) f22;
#endif

		*((uint32_t *)& f22 + 1) = mrand48();
		*((uint32_t *)& f22 + 1) |= 0x00000001;

		*(uint64_t *)& f2 = *(uint64_t *)& f22 + 1;
		*(uint32_t *)& f2 &= 0x800FFFFF;
		*(uint32_t *)& f2 |= 0x7FC00000;
#ifdef __lint
		(void) f2;
#endif

		fdivd(&f22, &f2, &f12);

		if (f12 != expect_ans) {
			(void) snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16e,\nObserved: %.16e",
			    expect_ans, f12);
			expect = *(uint64_t *)&expect_ans;
			observe = *(uint64_t *)&f12;
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6340, &observe, &expect, 1, 1, err_data);

			return (-1);
		}
	}

	return (0);
}

/*
 * fdivd(uint64_t *rs1, uint64_t *rs2, uint64_t *rd)
 * performs the assembly level instructions for
 * fpu_fdivd.
 */
/* ARGSUSED */
static void
fdivd(double *f22, double *f2, double *f12)
{
	asm("ldd	[%i0], %f22");
	asm("ldd	[%i1], %f2");
	asm("fdivd   	%f22, %f2, %f12");
	asm("std	%f12,[%i2]");
	asm("membar #Sync");
}

/*
 * fpu_fmuld(int rloop, int unit, struct fps_test_ereport *report)
 * returns whether the correct value is calculated each time
 * rloop times. If an error is found, the relevant data is stored
 * in report. The goal is to check if (x * y) == (y * x). The
 * data pattern is important, and the back-to-back fmuld's are
 * important.
 */
int
fpu_fmuld(int rloop, struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	double x;
	double y;
	double z;
	double z1;
	int loop;
	uint64_t expect;
	uint64_t observe;
	uint64_t *px;
	uint64_t *py;

	loop = 0;
	px = (uint64_t *)& x;
	py = (uint64_t *)& y;
	*px = 0x2FEBD8507111CDE5UL;	/* 4865027 */
	*py = 0x2FE284A9A98EAA26UL;

#ifdef __lint
	(void) x;
	(void) y;
#endif

	while (loop < rloop) {
		loop++;
		z = z1 = 0.0;

		/*
		 * Data pattern and back-to-back fmuld() are
		 * important
		 */
		fmuld(&x, &y, &z, &z1);

		if (*(uint64_t *)&z != *(uint64_t *)&z1) {
			(void) snprintf(err_data, sizeof (err_data),
			    "\nExpected: %.16e,\nObserved: %.16e",
			    *(uint64_t *)&z, *(uint64_t *)&z1);
			expect = *(uint64_t *)&z;
			observe = *(uint64_t *)&z1;
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6341, &observe, &expect, 1, 1, err_data);

			return (-1);
		}
	}

	return (0);
}

/*
 * fmuld(double *x,double *y, double *z, double *z1)
 * performs the assembly level instructions for
 * fpu_fmuld.
 */
/* ARGSUSED */
static void
fmuld(double *x, double *y, double *z, double *z1)
{
	asm("ldd[%i0], %f0");
	asm("ldd[%i1], %f4");
	asm("fmuld%f0, %f4, %f2");
	asm("fmuld%f4, %f0, %f6");
	asm("std%f2, [%i2]");
	asm("std%f6, [%i3]");
	asm("membar #Sync");
}


/*
 * fpu_fmulx(int rloop, int unit, struct fps_test_ereport *report)
 * returns whether the correct value is calculated each time
 * rloop times. If an error is found, the relevant data is stored
 * in report. The goal is to check if (x * y) == (y * x) with
 * 64-bit intgers.
 */
int
fpu_fmulx(int rloop, struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int loop;
	int loop_lim;
	uint32_t *rs1;
	uint32_t *rs2;
	uint64_t expect;
	uint64_t observe;
	uint64_t v1;
	uint64_t v2;
	uint64_t vd1;
	uint64_t vd2;
	uint64_t *rd1;
	uint64_t *rd2;

	v1 = v2 = vd1 = vd2 = 0;
	loop = 0;
	loop_lim = rloop;

	if (loop_lim < 10)
		loop_lim = 10;

	if (loop_lim > 100000)
		loop_lim = 100000;

	rs1 = (uint32_t *)& v1;
	rs2 = (uint32_t *)& v2;
	rd1 = &vd1;
	rd2 = &vd2;

#ifdef __lint
	(void) v1;
	(void) v2;
#endif

	srand(0l);
	while (loop < loop_lim) {
		loop++;

#ifndef __lint

		*rs1 = mrand48();
		*(rs1 + 1) = mrand48();
		*rs2 = mrand48();
		*(rs2 + 1) = mrand48();
#endif

		/* LINTED */
		fmulx((uint64_t *)rs1, (uint64_t *)rs2, rd1);

		/* LINTED */
		fmulx((uint64_t *)rs2, (uint64_t *)rs1, rd2);

		if (*rd1 != *rd2) {
			expect = (uint64_t)*rd1;
			observe = (uint64_t)*rd2;
			(void) snprintf(err_data, sizeof (err_data),
			    "\nExpected: %lld\nObserved: %lld", *rd1, *rd2);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6356, &observe, &expect, 1, 1, err_data);

		return (-1);
		}
	}

	return (0);
}

/*
 * fmulx(uint64_t *rs1, uint64_t *rs2, uint64_t *rd)
 * performs the assembly level instructions for
 * fpu_fmulx.
 */
/* ARGSUSED */
static void
fmulx(uint64_t *rs1, uint64_t *rs2, uint64_t *rd)
{
	asm("ldx   [%i0], %l0");
	asm("ldx   [%i1], %l1");
	asm("mulx  %l0, %l1, %l2");
	asm("stx   %l2, [%i2]");
	asm("membar	#Sync");

}



#ifdef V9B

#pragma align 64  (f0)
#pragma align 8  (f2)

#define	MEMSIZE	2048*3

static uchar_t f0[64];
static uchar_t f2[8];

static uint32_t bmask[] = {0x01234567, 0x12345678,
			0x23456789, 0x3456789a,
			0x456789ab, 0x56789abc,
			0x6789abcd, 0x789abcde,
			0x89abcdef, 0x9abcdef0,
			0xabcdef01, 0xbcdef012,
			0xcdef0123, 0xdef01234,
			0xef012345, 0xf0123456,
			0x55555555, 0xaaaaaaaa,
			0x00000000, 0xffffffff};

#ifdef __lint

/*ARGSUSED*/
unsigned long
setgsr(unsigned long arg1)
{
	return (0);
}

/*ARGSUSED*/
float
fpackfix(double arg1)
{
	return (0.0);
}

/*ARGSUSED*/
unsigned long
fcmpne16(double arg1, double arg2)
{
	return (0);
}

/*ARGSUSED*/
unsigned long
fcmpgt16(double arg1, double arg2)
{
	return (0);
}

#endif /* LINT */

/*
 * align_data(int loop, struct fps_test_ereport *report)
 * returns whether a miscompare was found after running alignment tests
 * loop amount of times. If an error is found, relevant data is stored
 * in report. This test exercises the alignaddr and aligndata
 * instructions with different byte alignments to ensure proper
 * operation. These two instructions are used extensively by the kernel
 * to move data size greater than 512 bytes. User level memcpy and
 * memmove library also use these instructions for data size
 * greater than 256 bytes.
 */
int
align_data(int loop, struct fps_test_ereport *report)
{
	char err[MAX_INFO_SIZE];
	int test_ret;
	int nr_malloc;
	size_t memsize;
	struct timeval timeout;
	uchar_t c;
	uchar_t *pf0;
	uchar_t *pf2;
	uchar_t *src;
	uint32_t cnt;
	uint32_t i;
	uint32_t offset;
	uint32_t start;
	uint64_t expect[2];
	uint64_t observe[2];

	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;
	nr_malloc = 0;
	err[0] = '\0';

	/* Make sure memsize is 64 bytes aligned  with minimum of 64 bytes */
	memsize = MEMSIZE;
	memsize = memsize / 64 * 64;

	if (memsize < 64)
		memsize = 64;

	src = (uchar_t *)memalign(64, memsize + 64);

	while (src == NULL && nr_malloc < 10) {
		(void) select(1, NULL, NULL, NULL, &timeout);
		nr_malloc++;
		src = (uchar_t *)memalign(64, memsize + 64);
	}

	if (src == NULL)
		_exit(FPU_SYSCALL_FAIL);

	/* Initialize source array with sequential data */
	c = 0;

	for (i = 0; i < memsize + 64; i++)
		*(src + i) = c++;

	for (cnt = 0; cnt < loop; cnt++) {
		for (start = 1; start < 64; start += 1) {
			offset = 0;

			test_ret = do_aligndata(src + start, &offset,
			    memsize, f0, f2, bmask[cnt % 20]);

			/*
			 * Miscompare on the two aligndata
			 * instructions. Calculate offset to source
			 * array and get miscompare data
			 */

			if (test_ret != 0) {
				pf0 = f0 + offset % 64;
				pf2 = f2;

				for (i = 0; i < 8; i++) {
					if (*(pf0 + i) != *(pf2 + i))
						break;
				}

				(void) align_error_create(err, start,
				    offset + start + i, loop, cnt);
				expect[0] =
				    (uint64_t)(*(uint8_t *)
				    (src + offset + start + i));
				expect[1] = (uint64_t)0;
				observe[0] = (uint64_t)(*(uint8_t *)(pf0 + i));
				observe[1] = (uint64_t)(*(uint8_t *)(pf2 + i));
				setup_fps_test_struct(
				    IS_EREPORT_INFO,
				    report, 6344, observe,
				    expect, 1, 2, err);

				free(src);

				return (-1);
			}

			/*
			 * No miscompare on the aligndata
			 * instructions. Check to see whether the
			 * last 64 bytes matches the input
			 */
			if (test_ret == 0) {
				pf2 = src + offset + start;

				for (i = 0; i < 64; i++) {
					if (f0[i] != *(pf2 + i)) {

						(void) align_error_create(err,
						    start,
						    offset + start + i,
						    loop, cnt);
						expect[0] =
						    (uint64_t)(*(uint8_t *)
						    (pf2 + i));
						expect[1] = (uint64_t)0;
						observe[0] = (uint64_t)f0[i];
						observe[1] = (uint64_t)0;
						setup_fps_test_struct(
						    IS_EREPORT_INFO,
						    report, 6343, observe,
						    expect, 1, 1, err);

						free(src);
						return (-1);
					}
				}
			}
		}
	}

	free(src);

	return (0);
}

/*
 * align_error_create(char *err, int start, int offset, int loop, int count)
 * returns if a successful snprintf was performed when creating an align_data
 * error message for align_data.
 */
static int
align_error_create(char *err, uint32_t start,
	uint32_t offset, int loop, uint32_t count)
{
	if (err == NULL)
		return (-1);

	return snprintf(err, sizeof (err),
	    "Start = %2.2d offset = %2.2d loop = %d cnt = %d",
	    start, offset, loop, count);
}

/*
 * do_aligndata(uchar_t *from, uint32_t *offset, size_t sz,
 * uchar_t *f0, uchar_t *f2, uint32_t bmask) performs
 * the assembly lvl routines for align_data.
 */
/*ARGSUSED*/
static int
do_aligndata(uchar_t *from, uint32_t *offset, size_t sz,
	uchar_t *f0, uchar_t *f2, uint32_t bmask)
{
	int ret = 1;

	asm("bmask	%i5,%g0,%g0");
	/* produce GSR.offset and align %l0 to 8 bytes boundary */
	asm("alignaddr	%i0, %g0, %l0");
	/* %i0 then used as error register, assume error */
	asm("mov	1,%i0");
	/* %l1 used as offset counter */
	asm("mov	-8,%l1");
	asm("ldd	[%l0], %f0");

	asm("next_read:");

	asm("ldd	[%l0+8], %f2");
	asm("ldd	[%l0+0x10], %f4");
	asm("faligndata	%f0, %f2, %f32");
	asm("faligndata	%f0, %f2, %f48");
	asm("fcmpd	%fcc0,%f32,%f48");
	asm("fblg,pn	%fcc0,error");
	/* %l1 contains offset value */
	asm("add	%l1,8,%l1");
	/* 0 - 7 */

	asm("ldd	[%l0+0x18], %f6");
	asm("faligndata	%f2, %f4, %f34");
	asm("faligndata	%f2, %f4, %f48");
	asm("fcmpd	%fcc0,%f34,%f48");
	asm("fblg,pn	%fcc0,error");
	/* %l1 contains offset value */
	asm("add	%l1,8,%l1");
	/* 9 - 15 */

	asm("ldd	[%l0+0x20], %f8");
	asm("faligndata	%f4, %f6, %f36");
	asm("faligndata	%f4, %f6, %f48");
	asm("fcmpd	%fcc0,%f36,%f48");
	asm("fblg,pn	%fcc0,error");
	/* %l1 contains offset value */
	asm("add	%l1,8,%l1");
	/* 16 - 23 */

	asm("ldd	[%l0+0x28], %f10");
	asm("faligndata	%f6, %f8, %f38");
	asm("faligndata	%f6, %f8, %f48");
	asm("fcmpd	%fcc0,%f38,%f48");
	asm("fblg,pn	%fcc0,error");
	/* contains offset value */
	asm("add	%l1,8,%l1");
	/* 24 - 31 */

	asm("ldd	[%l0+0x28], %f10");
	asm("faligndata	%f8, %f10, %f40");
	asm("faligndata	%f8, %f10, %f48");
	asm("fcmpd	%fcc0,%f40,%f48");
	asm("fblg,pn	%fcc0,error");
	/* %l1 contains offset value */
	asm("add	%l1,8,%l1");
	/* 32 - 39 */

	asm("ldd	[%l0+0x30], %f12");
	asm("faligndata	%f10, %f12, %f42");
	asm("faligndata	%f10, %f12, %f48");
	asm("fcmpd	%fcc0,%f42,%f48");
	asm("fblg,pn	%fcc0,error");
	/* %l1 contains offset value */
	asm("add	%l1,8,%l1");
	/* 40 - 47 */

	asm("ldd	[%l0+0x38], %f14");
	asm("faligndata	%f12, %f14, %f44");
	asm("faligndata	%f12, %f14, %f48");
	asm("fcmpd	%fcc0,%f44,%f48");
	asm("fblg,pn	%fcc0,error");
	/* %l1 contains offset value */
	asm("add	%l1,8,%l1");
	/* 48 - 55 */

	asm("ldd	[%l0+0x40], %f0");
	asm("faligndata	%f14, %f0, %f46");
	asm("faligndata	%f14, %f0, %f48");
	asm("fcmpd	%fcc0,%f46,%f48");
	asm("fblg,pn	%fcc0,error");
	/* %l1 contains offset value */
	asm("add	%l1,8,%l1");
	/* 56 - 63 */

	asm("subcc	%i2,64,%i2");
	asm("bg		next_read");
	asm("add	%l0,64,%l0");

	/* no miscompare error */
	asm("mov	0,%i0");
	ret = 0;
	/* no error, move back to last 64 bytes boundary */
	asm("sub	%l1,56,%l1");

	asm("error:");
	asm("stda	%f32,[%i3]0xf0");
	asm("std	%f48,[%i4]");
	/* store offset value */
	asm("st 	%l1,[%i1]");
	asm("membar	#Sync");

	return (ret);
}

/*
 * vis_test(struct fps_test_ereport *report)
 * checks if various RISC operations are performed
 * succesfully. If an error is found, relevant data
 * is stored in report.
 */
int
vis_test(struct fps_test_ereport *report)
{
	int v1;
	int v2;
	int v3;

	v1 = visgt16(report);
	v2 = visne16(report);
	v3 = vispackfix(report);

	if ((0 != v1) || (0 != v2) || (0 != v3))
		return (-1);

	return (0);
}

/*
 * visgt16(struct fps_test_ereport *report)
 * does a greater-than compare instruction and returns if
 * successful or not. If an error, relevant data is
 * stored in report.
 */
static int
visgt16(struct fps_test_ereport *report)
{
	uint64_t expected;
	uint64_t observed;
	unsigned long a = 0x0000000000000001;
	unsigned long b = 0x8000000008000008;
	unsigned long c = fcmpgt16(*((double *)&a), *((double *)&b));

	if (c == 0x8)
		return (0);
	else {
		expected = (uint64_t)0x8;
		observed = (*(uint64_t *)&c);
		setup_fps_test_struct(NO_EREPORT_INFO, report,
		    6364, &observed, &expected, 1, 1);

		return (-1);
	}
}

/*
 * visne16(struct fps_test_ereport *report)
 * does a not-equal compare instruction and returns if
 * successful or not. If an error, relevant data is
 * stored in report.
 */
static int
visne16(struct fps_test_ereport *report)
{
	uint64_t expected;
	uint64_t observed;
	unsigned long a = 0x0000000000000001;
	unsigned long b = 0x0001000000001001;
	unsigned long c = fcmpne16(*((double *)&a), *((double *)&b));

	if (c == 0x9)
		return (0);
	else {
		expected = (uint64_t)0x9;
		observed = (*(uint64_t *)&c);
		setup_fps_test_struct(NO_EREPORT_INFO, report,
		    6365, &observed, &expected, 1, 1);

		return (-1);
	}
}

/*
 * vispackfix(struct fps_test_ereport *report)
 * does four 16-bit pack conversions to a lower precsion
 * format and returns if successful or not. If an error,
 * relevant data is stored in report.
 */
static int
vispackfix(struct fps_test_ereport *report)
{
	float b;
	uint64_t expected;
	uint64_t observed;
	unsigned int c;
	unsigned long a = 0x8008000008008008;
	unsigned long gsr = 0;

	(void) setgsr(gsr);

	b = fpackfix(*((double *)&a));
	c = *((unsigned int *)&b);

	if (c == 0x80080800)
		return (0);
	else {
		expected = (uint64_t)0x80080800;
		observed = (uint64_t)c;
		setup_fps_test_struct(NO_EREPORT_INFO, report,
		    6366, &observed, &expected, 1, 1);

		return (-1);
	}
}

#endif
