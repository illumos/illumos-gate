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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MATH_H
#define	_MATH_H

#include <iso/math_iso.h>
#include <iso/math_c99.h>

#if __cplusplus >= 199711L
using std::abs;
using std::acos;
using std::asin;
using std::atan2;
using std::atan;
using std::ceil;
using std::cos;
using std::cosh;
using std::exp;
using std::fabs;
using std::floor;
using std::fmod;
using std::frexp;
using std::ldexp;
using std::log10;
using std::log;
using std::modf;
using std::pow;
using std::sin;
using std::sinh;
using std::sqrt;
using std::tan;
using std::tanh;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__cplusplus)
#define	exception	__math_exception
#endif

#ifndef __P
#ifdef __STDC__
#define	__P(p)	p
#else
#define	__P(p)	()
#endif
#endif	/* !defined(__P) */

#if defined(__EXTENSIONS__) || defined(_XOPEN_SOURCE) || \
	!defined(_STRICT_STDC) && !defined(_POSIX_C_SOURCE)
/*
 * SVID & X/Open
 */
#define	M_E		2.7182818284590452354
#define	M_LOG2E		1.4426950408889634074
#define	M_LOG10E	0.43429448190325182765
#define	M_LN2		0.69314718055994530942
#define	M_LN10		2.30258509299404568402
#define	M_PI		3.14159265358979323846
#define	M_PI_2		1.57079632679489661923
#define	M_PI_4		0.78539816339744830962
#define	M_1_PI		0.31830988618379067154
#define	M_2_PI		0.63661977236758134308
#define	M_2_SQRTPI	1.12837916709551257390
#define	M_SQRT2		1.41421356237309504880
#define	M_SQRT1_2	0.70710678118654752440

extern int signgam;

#define	MAXFLOAT	((float)3.40282346638528860e+38)

#if defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE)
/*
 * SVID
 */
enum version {libm_ieee = -1, c_issue_4, ansi_1, strict_ansi};

#ifdef __STDC__
extern const enum version _lib_version;
#else
extern enum version _lib_version;
#endif

struct exception {
	int type;
	char *name;
	double arg1;
	double arg2;
	double retval;
};

#define	HUGE		MAXFLOAT

#define	_ABS(x)		((x) < 0 ? -(x) : (x))

#define	_REDUCE(TYPE, X, XN, C1, C2)	{ \
	double x1 = (double)(TYPE)X, x2 = X - x1; \
	X = x1 - (XN) * (C1); X += x2; X -= (XN) * (C2); }

#define	DOMAIN		1
#define	SING		2
#define	OVERFLOW	3
#define	UNDERFLOW	4
#define	TLOSS		5
#define	PLOSS		6

#define	_POLY1(x, c)	((c)[0] * (x) + (c)[1])
#define	_POLY2(x, c)	(_POLY1((x), (c)) * (x) + (c)[2])
#define	_POLY3(x, c)	(_POLY2((x), (c)) * (x) + (c)[3])
#define	_POLY4(x, c)	(_POLY3((x), (c)) * (x) + (c)[4])
#define	_POLY5(x, c)	(_POLY4((x), (c)) * (x) + (c)[5])
#define	_POLY6(x, c)	(_POLY5((x), (c)) * (x) + (c)[6])
#define	_POLY7(x, c)	(_POLY6((x), (c)) * (x) + (c)[7])
#define	_POLY8(x, c)	(_POLY7((x), (c)) * (x) + (c)[8])
#define	_POLY9(x, c)	(_POLY8((x), (c)) * (x) + (c)[9])
#endif	/* defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE) */

/*
 * SVID & X/Open
 */
/* BEGIN adopted by C99 */
extern double erf __P((double));
extern double erfc __P((double));
extern double hypot __P((double, double));
extern double lgamma __P((double));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(erf, erfc, hypot)
#pragma does_not_write_global_data(erf, erfc, hypot)
#pragma no_side_effect(erf, erfc, hypot)
#endif

#if !defined(_STDC_C99) && _XOPEN_SOURCE - 0 < 600 && !defined(__C99FEATURES__)
extern int isnan __P((double));

#pragma does_not_read_global_data(isnan)
#pragma does_not_write_global_data(isnan)
#pragma no_side_effect(isnan)
#endif
/* END adopted by C99 */

#if defined(__EXTENSIONS__) || _XOPEN_SOURCE - 0 < 600
extern double gamma __P((double));		/* deprecated; use lgamma */
#endif
extern double j0 __P((double));
extern double j1 __P((double));
extern double jn __P((int, double));
extern double y0 __P((double));
extern double y1 __P((double));
extern double yn __P((int, double));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(j0, j1, jn, y0, y1, yn)
#pragma does_not_write_global_data(j0, j1, jn, y0, y1, yn)
#pragma no_side_effect(j0, j1, jn, y0, y1, yn)
#endif
#if defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE) || \
	_XOPEN_SOURCE - 0 >= 500 || \
	defined(_XOPEN_SOURCE) && _XOPEN_SOURCE_EXTENDED - 0 == 1
/*
 * SVID & XPG 4.2/5
 */
extern double scalb __P((double, double));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(scalb)
#pragma does_not_write_global_data(scalb)
#pragma no_side_effect(scalb)
#endif

/* BEGIN adopted by C99 */
extern double acosh __P((double));
extern double asinh __P((double));
extern double atanh __P((double));
extern double cbrt __P((double));
extern double logb __P((double));
extern double nextafter __P((double, double));
extern double remainder __P((double, double));

/*
 * XPG 4.2/5
 */
extern double expm1 __P((double));
extern int ilogb __P((double));
extern double log1p __P((double));
extern double rint __P((double));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(acosh, asinh, atanh, cbrt)
#pragma does_not_read_global_data(logb, nextafter, remainder)
#pragma does_not_read_global_data(expm1, ilogb, log1p, rint)
#pragma does_not_write_global_data(acosh, asinh, atanh, cbrt)
#pragma does_not_write_global_data(logb, nextafter, remainder)
#pragma does_not_write_global_data(expm1, ilogb, log1p, rint)
#pragma no_side_effect(acosh, asinh, atanh, cbrt)
#pragma no_side_effect(logb, nextafter, remainder)
#pragma no_side_effect(expm1, ilogb, log1p, rint)
#endif
/* END adopted by C99 */
#endif	/* defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE) || ... */

#if defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE)
/*
 * SVID
 */
extern int matherr __P((struct exception *));

/*
 * IEEE Test Vector
 */
extern double significand __P((double));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(significand)
#pragma does_not_write_global_data(significand)
#pragma no_side_effect(significand)
#endif

extern int signgamf;				/* deprecated; use signgam */
extern int signgaml;				/* deprecated; use signgam */

extern int isnanf __P((float));
extern int isnanl __P((long double));
extern float gammaf __P((float));		/* deprecated; use lgammaf */
extern float gammaf_r __P((float, int *));	/* deprecated; use lgammaf_r */
extern float j0f __P((float));
extern float j1f __P((float));
extern float jnf __P((int, float));
extern float lgammaf_r __P((float, int *));
extern float scalbf __P((float, float));
extern float significandf __P((float));
extern float y0f __P((float));
extern float y1f __P((float));
extern float ynf __P((int, float));
extern long double gammal __P((long double));	/* deprecated; use lgammal */
extern long double gammal_r __P((long double, int *));	/* deprecated */
extern long double j0l __P((long double));
extern long double j1l __P((long double));
extern long double jnl __P((int, long double));
extern long double lgammal_r __P((long double, int *));
extern long double scalbl __P((long double, long double));
extern long double significandl __P((long double));
extern long double y0l __P((long double));
extern long double y1l __P((long double));
extern long double ynl __P((int, long double));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(isnanf, isnanl)
#pragma does_not_write_global_data(isnanf, isnanl)
#pragma no_side_effect(isnanf, isnanl)
#pragma does_not_read_global_data(gammaf_r, j0f, j1f, jnf, lgammaf_r, scalbf)
#pragma does_not_read_global_data(significandf, y0f, y1f, ynf)
#pragma does_not_write_global_data(j0f, j1f, jnf, scalbf)
#pragma does_not_write_global_data(significandf, y0f, y1f, ynf)
#pragma no_side_effect(j0f, j1f, jnf, scalbf)
#pragma no_side_effect(significandf, y0f, y1f, ynf)
#pragma does_not_read_global_data(gammal_r, j0l, j1l, jnl, lgammal_r, scalbl)
#pragma does_not_read_global_data(significandl, y0l, y1l, ynl)
#pragma does_not_write_global_data(j0l, j1l, jnl, scalbl)
#pragma does_not_write_global_data(significandl, y0l, y1l, ynl)
#pragma no_side_effect(j0l, j1l, jnl, scalbl)
#pragma no_side_effect(significandl, y0l, y1l, ynl)
#endif

/*
 * for sin+cos->sincos transformation
 */
extern void sincos __P((double, double *, double *));
extern void sincosf __P((float, float *, float *));
extern void sincosl __P((long double, long double *, long double *));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(sincos, sincosf, sincosl)
#endif

/* BEGIN adopted by C99 */
/*
 * Functions callable from C, intended to support IEEE arithmetic.
 */
extern double copysign __P((double, double));
extern double scalbn __P((double, int));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(copysign, scalbn)
#pragma does_not_write_global_data(copysign, scalbn)
#pragma no_side_effect(copysign, scalbn)
#endif
/* END adopted by C99 */

/*
 * Reentrant version of gamma & lgamma; passes signgam back by reference
 * as the second argument; user must allocate space for signgam.
 */
extern double gamma_r __P((double, int *));	/* deprecated; use lgamma_r */
extern double lgamma_r __P((double, int *));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(gamma_r, lgamma_r)
#endif

/* BEGIN adopted by C99 */
extern float modff __P((float, float *));

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(modff)
#endif
/* END adopted by C99 */

#if defined(__EXTENSIONS__) || !defined(__cplusplus)
#include <floatingpoint.h>
#endif
#endif	/* defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE) */
#endif	/* defined(__EXTENSIONS__) || defined(_XOPEN_SOURCE) || ... */

#if defined(__cplusplus) && defined(__GNUC__)
#undef	exception
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _MATH_H */
