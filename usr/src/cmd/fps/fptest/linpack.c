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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <externs.h>
#include <fp.h>
#include <fps_ereport.h>
#include <fpstestmsg.h>
#include <linpack.h>

#ifdef __i386
#include "/shared/dp/mercury/latest/prod/include/cc/sunperf.h"
#else
#include <sunperf.h>
#endif

double fabs(double x);

extern void	___pl_dss_set_chip_cache_(int *cache_size);
static double dran(int iseed[4]);
static int LINSUB(REAL * residn, REAL * resid,
    REAL * eps, REAL * x11, REAL * xn1, int fps_verbose_msg);
static int MATGEN(REAL a[], int lda, int n, REAL b[], REAL * norma);
static REAL EPSLON(REAL x);
static void MXPY(int n1, REAL y[], int n2, int ldm, REAL x[], REAL m[]);

extern int errno;
static int LAPACK_ECACHE_SIZE = 8 * 1024 * 1024;
static int MAT_SIZE;

/*
 * LINPACK(int Stress, int unit, struct fps_test_ereport *report,
 * int fps_verbose_msg)
 * performs the single and double precision lapack test. If an
 * error is found, relevant data is collected and stored in report.
 */
int
LINPACK(int Stress, int unit, struct fps_test_ereport *report,
    int fps_verbose_msg)
{
	char err_data[MAX_INFO_SIZE];
	char l_buf[64];
	int c_index;
	int ret;
	REAL eps;
	REAL resid;
	REAL residn;
	REAL x11;
	REAL xn1;
	REAL EPS;
	REAL RESID;
	REAL RESIDN;
	REAL X11;
	REAL XN1;
	uint64_t expected[5];
	uint64_t observed[5];

#ifdef  FPS_LAPA_UNK
#ifndef DP
	if (Stress > 1000)
			return (0);
#endif /* DP */
#endif /* FPS_LAPA_UNK */

	if (Stress > 10000)
		return (0);

	/*
	 * make sure is no dependency on the E$ size Without this call the
	 * computed results will depend on the size of the E$ (
	 * sos10/libsunperf ) IIIi computed results != IV+/IV/III+/III ...
	 */
	___pl_dss_set_chip_cache_(&LAPACK_ECACHE_SIZE);

	c_index = Stress;

	if (2000 == c_index)
		c_index = 1001;
	if (3000 == c_index)
		c_index = 1002;
	if (4016 == c_index)
		c_index = 1003;
	if (5000 == c_index)
		c_index = 1004;
	if (6000 == c_index)
		c_index = 1005;
	if (7016 == c_index)
		c_index = 1006;
	if (8034 == c_index)
		c_index = 1007;
	if (9000 == c_index)
		c_index = 1008;
	if (10000 == c_index)
		c_index = 1009;

	(void) snprintf(l_buf, 63, "%s(%d,cpu=%d)", PREC, Stress, unit);
	fps_msg(fps_verbose_msg, gettext(FPSM_02), l_buf, unit);

	MAT_SIZE = Stress;
	ret = LINSUB(&residn, &resid, &eps, &x11, &xn1, fps_verbose_msg);

	if (2 == ret) {
		if (errno == EAGAIN || errno == ENOMEM)
			_exit(FPU_SYSCALL_TRYAGAIN);
		else
			_exit(FPU_SYSCALL_FAIL);
	}

#ifdef  FPS_LAPA_UNK
	RESIDN  = RESID   = X11 = XN1 = 0.0000000000000000e+00;

#ifdef DP
	EPS = 2.2204460492503131e-16;
#else /* DP */
	EPS = 1.1920928955078125e-07;
#endif /* DP */

#else /* FPS_LAPA_UNK */

	RESIDN = LinpValsA[c_index].residn;
	RESID = LinpValsA[c_index].resid;
	EPS = LinpValsA[c_index].eps;
	X11 = LinpValsA[c_index].x11;
	XN1 = LinpValsA[c_index].xn1;

#endif /* FPS_LAPA_UNK */

	if ((residn == RESIDN) && (resid == RESID) && (eps == EPS) &&
	    (x11 == X11) && (xn1 == XN1)) {

		return (0);
	} else {
		snprintf(err_data, sizeof (err_data),
		    "\nExpected: %.16e, %.16e, %.16e, %.16e, %.16e"
		    "\nObserved: %.16e, %.16e, %.16e, %.16e, %.16e",
		    RESIDN, RESID, EPS, X11, XN1, residn, resid, eps, x11, xn1);


#ifdef	DP
		observed[0] = *(uint64_t *)&residn;
		observed[1] = *(uint64_t *)&resid;
		observed[2] = *(uint64_t *)&eps;
		observed[3] = *(uint64_t *)&x11;
		observed[4] = *(uint64_t *)&xn1;
		expected[0] = *(uint64_t *)&RESIDN;
		expected[1] = *(uint64_t *)&RESID;
		expected[2] = *(uint64_t *)&EPS;
		expected[3] = *(uint64_t *)&X11;
		expected[4] = *(uint64_t *)&XN1;

		setup_fps_test_struct(IS_EREPORT_INFO, report,
		    6317, &observed, &expected, 5, 5, err_data);
#else
		observed[0] = (uint64_t)(*(uint32_t *)&residn);
		observed[1] = (uint64_t)(*(uint32_t *)&resid);
		observed[2] = (uint64_t)(*(uint32_t *)&eps);
		observed[3] = (uint64_t)(*(uint32_t *)&x11);
		observed[4] = (uint64_t)(*(uint32_t *)&xn1);
		expected[0] = (uint64_t)(*(uint32_t *)&RESIDN);
		expected[1] = (uint64_t)(*(uint32_t *)&RESID);
		expected[2] = (uint64_t)(*(uint32_t *)&EPS);
		expected[3] = (uint64_t)(*(uint32_t *)&X11);
		expected[4] = (uint64_t)(*(uint32_t *)&XN1);

		setup_fps_test_struct(IS_EREPORT_INFO, report,
		    6316, &observed, &expected, 5, 5, err_data);
#endif

		return (-1);
	}
}

/*
 * LINSUB(REAL *residn, REAL *resid, REAL *eps,
 * REAL *x11, REAL *xn1, int fps_verbose_msg)begins
 * the lapack calculation calls.
 */
static int
LINSUB(REAL *residn, REAL *resid,
	REAL *eps, REAL *x11, REAL *xn1,
	int fps_verbose_msg)
{
	int i;
	int lda;
	int n;
	int nr_malloc;
	REAL *a;
	REAL abs;
	REAL *b;
	REAL norma;
	REAL normx;
	REAL *x;
	struct timeval timeout;
	long info;
	long *ipvt;

	timeout.tv_sec = 0;
	timeout.tv_usec = 10000; /* microseconds, 10ms */
	nr_malloc = 0;

mallocAgain:

	a = (REAL *) malloc((MAT_SIZE + 8) * (MAT_SIZE + 1) *
	    (size_t)sizeof (REAL));
	b = (REAL *) malloc(MAT_SIZE * (size_t)sizeof (REAL));
	x = (REAL *) malloc(MAT_SIZE * (size_t)sizeof (REAL));

	ipvt = (long *)malloc(MAT_SIZE * (size_t)sizeof (long));

	if ((NULL == a) || (NULL == b) ||
	    (NULL == x) || (NULL == ipvt)) {
		if (NULL != a)
			free(a);
		if (NULL != b)
			free(b);
		if (NULL != x)
			free(x);
		if (NULL != ipvt)
			free(ipvt);

		/* sleep 10 ms. wait for 100 ms */
		if (nr_malloc++ < 11) {
			(void) select(1, NULL, NULL, NULL, &timeout);
			goto mallocAgain;
		}
		fps_msg(fps_verbose_msg,
		    "Malloc failed in lapack, matrix size %d",
		    MAT_SIZE);

		return (2);
	}
	lda = MAT_SIZE + 8;
	n = MAT_SIZE;

	(void) MATGEN(a, lda, n, b, &norma);
	GEFA(n, n, a, lda, ipvt, &info);
	GESL('N', n, 1, a, lda, ipvt, b, n, &info);
	free(ipvt);

	for (i = 0; i < n; i++) {
		x[i] = b[i];
	}

	(void) MATGEN((REAL *) a, lda, n, b, &norma);

	for (i = 0; i < n; i++) {
		b[i] = -b[i];
	}

	MXPY(n, b, n, lda, x, (REAL *) a);
	free(a);

	*resid = 0.0;
	normx = 0.0;

	for (i = 0; i < n; i++) {
		abs = (REAL)fabs((double)b[i]);
		*resid = (*resid > abs) ? *resid : abs;
		abs = (REAL)fabs((double)x[i]);
		normx = (normx > abs) ? normx : abs;
	}

	free(b);

	*eps = EPSLON((REAL) LP_ONE);

	*residn = *resid / (n * norma * normx * (*eps));

	*x11 = x[0] - 1;
	*xn1 = x[n - 1] - 1;

	free(x);

	return (0);
}

/*
 * dran(int iseed[4]) returns a random real number from a
 * uniform (0,1) distribution.
 */
static double
dran(int iseed[4])
{
	double r;
	double value;
	int ipw2;
	int it1;
	int it2;
	int it3;
	int it4;
	int m1;
	int m2;
	int m3;
	int m4;

	/* Set constants */
	m1 = 494;
	m2 = 322;
	m3 = 2508;
	m4 = 2549;
	ipw2 = 4096;
	r = 1.0 / ipw2;

	/* multiply the seed by the multiplier modulo 2**48 */
	it4 = iseed[3] * m4;
	it3 = it4 / ipw2;
	it4 = it4 - ipw2 * it3;
	it3 = it3 + iseed[2] * m4 + iseed[3] * m3;
	it2 = it3 / ipw2;
	it3 = it3 - ipw2 * it2;
	it2 = it2 + iseed[1] * m4 + iseed[2] * m3 + iseed[3] * m2;
	it1 = it2 / ipw2;
	it2 = it2 - ipw2 * it1;
	it1 = it1 + iseed[0] * m4 + iseed[1] * m3 + iseed[2] * m2 +
	    iseed[3] * m1;
	it1 = it1 % ipw2;

	/* return updated seed */
	iseed[0] = it1;
	iseed[1] = it2;
	iseed[2] = it3;
	iseed[3] = it4;

	/* convert 48-bit integer to a real number in the interval (0,1) */
	value = r * ((double)it1 + r * ((double)it2 + r * ((double)it3 +
	    r * ((double)it4))));

	return (value);
}

/*
 * MATGEN(REAL a[], int lda, int n, REAL b[], REAL *norma)
 * generates matrix a and b.
 */

#define	ALPHA 1.68750
static int
MATGEN(REAL a[], int lda, int n, REAL b[], REAL *norma)
{
	int		i;
	int		init[4];
	int		j;
	REAL	value;

	init[0] = 1;
	init[1] = 2;
	init[2] = 3;
	init[3] = 1325;
	*norma = LP_ZERO;
	for (j = 0; j < n; j++) {
		for (i = 0; i < n; i++) {
#ifdef FPS_LAPA_UNK
			a[lda*j+i] =
			    (i < j) ? (double)(i+1) : (double)(j+ALPHA);
			if (fabs(a[lda*j+i]) > *norma)
				*norma = fabs(a[lda*j+i]);
			} /* i */
#else
			value = (REAL) dran(init) - 0.5;
			a[lda * j + i] = value;
			value = fabs(value);
			if (value > *norma) {
				*norma = value;
			}
		} /* i */
#endif /* FPS_LAPA_UNK */
	} /* j */


	for (i = 0; i < n; i++) {
		b[i] = LP_ZERO;
	}
	for (j = 0; j < n; j++) {
		for (i = 0; i < n; i++) {
			b[i] = b[i] + a[lda * j + i];
		}
	}

	return (0);
}

/*
 * IAMAX(int n, REAL dx[])finds the index of element
 * having maximum absolute value.
 */
int
IAMAX(int n, REAL dx[])
{
	double abs;
	double dmax;
	int i;
	int itemp;

	if (n < 1)
		return (-1);
	if (n == 1)
		return (0);

	itemp = 0;
	dmax = fabs((double)dx[0]);

	for (i = 1; i < n; i++) {
		abs = fabs((double)dx[i]);
		if (abs > dmax) {
			itemp = i;
			dmax = abs;
		}
	}

	return (itemp);
}

/*
 * EPSLON(REAL x) estimates unit roundoff in
 * quantities of size x.
 */
static REAL
EPSLON(REAL x)
{
	REAL a;
	REAL abs;
	REAL b;
	REAL c;
	REAL eps;

	a = 4.0e0 / 3.0e0;
	eps = LP_ZERO;

	while (eps == LP_ZERO) {
		b = a - LP_ONE;
		c = b + b + b;
		eps = (REAL)fabs((double)(c - LP_ONE));
	}

	abs = (REAL)fabs((double)x);

	return (eps * abs);
}

/*
 * MXPY(int n1, REAL y[], int n2, int ldm, REAL x[], REAL m[])
 * multiplies matrix m times vector x and add the result to
 * vector y.
 */
static void
MXPY(int n1, REAL y[], int n2, int ldm, REAL x[], REAL m[])
{
	int i;
	int j;
	int jmin;

	/* cleanup odd vector */
	j = n2 % 2;
	if (j >= 1) {
		j = j - 1;
		for (i = 0; i < n1; i++)
			y[i] = (y[i]) + x[j] * m[ldm * j + i];
	}

	/* cleanup odd group of two vectors */
	j = n2 % 4;
	if (j >= 2) {
		j = j - 1;
		for (i = 0; i < n1; i++)
			y[i] = ((y[i])
			    + x[j - 1] * m[ldm * (j - 1) + i])
			    + x[j] * m[ldm * j + i];
	}

	/* cleanup odd group of four vectors */
	j = n2 % 8;
	if (j >= 4) {
		j = j - 1;
		for (i = 0; i < n1; i++)
			y[i] = ((((y[i])
			    + x[j - 3] * m[ldm * (j - 3) + i])
			    + x[j - 2] * m[ldm * (j - 2) + i])
			    + x[j - 1] * m[ldm * (j - 1) + i])
			    + x[j] * m[ldm * j + i];
	}

	/* cleanup odd group of eight vectors */
	j = n2 % 16;
	if (j >= 8) {
		j = j - 1;
		for (i = 0; i < n1; i++)
			y[i] = ((((((((y[i])
			    + x[j - 7] * m[ldm * (j - 7) + i])
			    + x[j - 6] * m[ldm * (j - 6) + i])
			    + x[j - 5] * m[ldm * (j - 5) + i])
			    + x[j - 4] * m[ldm * (j - 4) + i])
			    + x[j - 3] * m[ldm * (j - 3) + i])
			    + x[j - 2] * m[ldm * (j - 2) + i])
			    + x[j - 1] * m[ldm * (j - 1) + i])
			    + x[j] * m[ldm * j + i];
	}

	/* main loop - groups of sixteen vectors */
	jmin = (n2 % 16) + 16;
	for (j = jmin - 1; j < n2; j = j + 16) {
		for (i = 0; i < n1; i++)
			y[i] = ((((((((((((((((y[i])
			    + x[j - 15] * m[ldm * (j - 15) + i])
			    + x[j - 14] * m[ldm * (j - 14) + i])
			    + x[j - 13] * m[ldm * (j - 13) + i])
			    + x[j - 12] * m[ldm * (j - 12) + i])
			    + x[j - 11] * m[ldm * (j - 11) + i])
			    + x[j - 10] * m[ldm * (j - 10) + i])
			    + x[j - 9] * m[ldm * (j - 9) + i])
			    + x[j - 8] * m[ldm * (j - 8) + i])
			    + x[j - 7] * m[ldm * (j - 7) + i])
			    + x[j - 6] * m[ldm * (j - 6) + i])
			    + x[j - 5] * m[ldm * (j - 5) + i])
			    + x[j - 4] * m[ldm * (j - 4) + i])
			    + x[j - 3] * m[ldm * (j - 3) + i])
			    + x[j - 2] * m[ldm * (j - 2) + i])
			    + x[j - 1] * m[ldm * (j - 1) + i])
			    + x[j] * m[ldm * j + i];
	}
}
