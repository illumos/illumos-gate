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

#ifndef _ISO_MATH_C99_H
#define	_ISO_MATH_C99_H

#include <sys/isa_defs.h>
#include <sys/feature_tests.h>

#ifdef __cplusplus
extern "C" {
#endif

#undef	FP_ZERO
#define	FP_ZERO		0
#undef	FP_SUBNORMAL
#define	FP_SUBNORMAL	1
#undef	FP_NORMAL
#define	FP_NORMAL	2
#undef	FP_INFINITE
#define	FP_INFINITE	3
#undef	FP_NAN
#define	FP_NAN		4

#if defined(_STDC_C99) || _XOPEN_SOURCE - 0 >= 600 || defined(__C99FEATURES__)
#if defined(__GNUC__)
#undef	HUGE_VAL
#define	HUGE_VAL	(__builtin_huge_val())
#undef	HUGE_VALF
#define	HUGE_VALF	(__builtin_huge_valf())
#undef	HUGE_VALL
#define	HUGE_VALL	(__builtin_huge_vall())
#undef	INFINITY
#define	INFINITY	(__builtin_inff())
#undef	NAN
#define	NAN		(__builtin_nanf(""))

/*
 * C99 7.12.3 classification macros
 */
#undef	isnan
#undef	isinf
#if __GNUC__ >= 4
#define	isnan(x)	__builtin_isnan(x)
#define	isinf(x)	__builtin_isinf(x)
#define	fpclassify(x)	__builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, \
    FP_SUBNORMAL, FP_ZERO, x)
#define	isfinite(x)	__builtin_isfinite(x)
#define	isnormal(x)	__builtin_isnormal(x)
#define	signbit(x)	__builtin_signbit(x)
#else  /* __GNUC__ >= 4 */
#define	isnan(x)	__extension__( \
			{ __typeof(x) __x_n = (x); \
			__builtin_isunordered(__x_n, __x_n); })
#define	isinf(x)	__extension__( \
			{ __typeof(x) __x_i = (x); \
			__x_i == (__typeof(__x_i)) INFINITY || \
			__x_i == (__typeof(__x_i)) (-INFINITY); })
#undef	isfinite
#define	isfinite(x)	__extension__( \
			{ __typeof(x) __x_f = (x); \
			!isnan(__x_f) && !isinf(__x_f); })
#undef	isnormal
#define	isnormal(x)	__extension__( \
			{ __typeof(x) __x_r = (x); isfinite(__x_r) && \
			(sizeof (__x_r) == sizeof (float) ? \
			__builtin_fabsf(__x_r) >= __FLT_MIN__ : \
			sizeof (__x_r) == sizeof (double) ? \
			__builtin_fabs(__x_r) >= __DBL_MIN__ : \
			__builtin_fabsl(__x_r) >= __LDBL_MIN__); })
#undef	fpclassify
#define	fpclassify(x)	__extension__( \
			{ __typeof(x) __x_c = (x); \
			isnan(__x_c) ? FP_NAN : \
			isinf(__x_c) ? FP_INFINITE : \
			isnormal(__x_c) ? FP_NORMAL : \
			__x_c == (__typeof(__x_c)) 0 ? FP_ZERO : \
			FP_SUBNORMAL; })
#undef	signbit
#if defined(_BIG_ENDIAN)
#define	signbit(x)	__extension__( \
			{ __typeof(x) __x_s = (x); \
			(int)(*(unsigned *)&__x_s >> 31); })
#elif defined(_LITTLE_ENDIAN)
#define	signbit(x)	__extension__( \
			{ __typeof(x) __x_s = (x); \
			(sizeof (__x_s) == sizeof (float) ? \
			(int)(*(unsigned *)&__x_s >> 31) : \
			sizeof (__x_s) == sizeof (double) ? \
			(int)(((unsigned *)&__x_s)[1] >> 31) : \
			(int)(((unsigned short *)&__x_s)[4] >> 15)); })
#endif	/* defined(_BIG_ENDIAN) */
#endif	/* __GNUC__ >= 4 */

/*
 * C99 7.12.14 comparison macros
 */
#undef	isgreater
#define	isgreater(x, y)		__builtin_isgreater(x, y)
#undef	isgreaterequal
#define	isgreaterequal(x, y)	__builtin_isgreaterequal(x, y)
#undef	isless
#define	isless(x, y)		__builtin_isless(x, y)
#undef	islessequal
#define	islessequal(x, y)	__builtin_islessequal(x, y)
#undef	islessgreater
#define	islessgreater(x, y)	__builtin_islessgreater(x, y)
#undef	isunordered
#define	isunordered(x, y)	__builtin_isunordered(x, y)
#else	/* defined(__GNUC__) */
#undef	HUGE_VAL
#define	HUGE_VAL	__builtin_huge_val
#undef	HUGE_VALF
#define	HUGE_VALF	__builtin_huge_valf
#undef	HUGE_VALL
#define	HUGE_VALL	__builtin_huge_vall
#undef	INFINITY
#define	INFINITY	__builtin_infinity
#undef	NAN
#define	NAN		__builtin_nan

/*
 * C99 7.12.3 classification macros
 */
#undef	fpclassify
#define	fpclassify(x)	__builtin_fpclassify(x)
#undef	isfinite
#define	isfinite(x)	__builtin_isfinite(x)
#undef	isinf
#define	isinf(x)	__builtin_isinf(x)
#undef	isnan
#define	isnan(x)	__builtin_isnan(x)
#undef	isnormal
#define	isnormal(x)	__builtin_isnormal(x)
#undef	signbit
#define	signbit(x)	__builtin_signbit(x)

/*
 * C99 7.12.14 comparison macros
 */
#undef	isgreater
#define	isgreater(x, y)		((x) __builtin_isgreater(y))
#undef	isgreaterequal
#define	isgreaterequal(x, y)	((x) __builtin_isgreaterequal(y))
#undef	isless
#define	isless(x, y)		((x) __builtin_isless(y))
#undef	islessequal
#define	islessequal(x, y)	((x) __builtin_islessequal(y))
#undef	islessgreater
#define	islessgreater(x, y)	((x) __builtin_islessgreater(y))
#undef	isunordered
#define	isunordered(x, y)	((x) __builtin_isunordered(y))
#endif	/* defined(__GNUC__) */
#endif	/* defined(_STDC_C99) || _XOPEN_SOURCE - 0 >= 600 || ... */

#if defined(__EXTENSIONS__) || defined(_STDC_C99) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(__C99FEATURES__)
#if defined(__FLT_EVAL_METHOD__) && __FLT_EVAL_METHOD__ - 0 == 0
typedef float float_t;
typedef double double_t;
#elif __FLT_EVAL_METHOD__ - 0 == 1
typedef double float_t;
typedef double double_t;
#elif __FLT_EVAL_METHOD__ - 0 == 2
typedef long double float_t;
typedef long double double_t;
#elif defined(__sparc) || defined(__amd64)
typedef float float_t;
typedef double double_t;
#elif defined(__i386)
typedef long double float_t;
typedef long double double_t;
#endif

#undef	FP_ILOGB0
#define	FP_ILOGB0	(-2147483647)
#undef	FP_ILOGBNAN
#define	FP_ILOGBNAN	2147483647

#undef	MATH_ERRNO
#define	MATH_ERRNO	1
#undef	MATH_ERREXCEPT
#define	MATH_ERREXCEPT	2
#undef	math_errhandling
#define	math_errhandling	MATH_ERREXCEPT

extern double acosh(double);
extern double asinh(double);
extern double atanh(double);

extern double exp2(double);
extern double expm1(double);
extern int ilogb(double);
extern double log1p(double);
extern double log2(double);
extern double logb(double);
extern double scalbn(double, int);
extern double scalbln(double, long int);

extern double cbrt(double);
extern double hypot(double, double);

extern double erf(double);
extern double erfc(double);
extern double lgamma(double);
extern double tgamma(double);

extern double nearbyint(double);
extern double rint(double);
extern long int lrint(double);
extern double round(double);
extern long int lround(double);
extern double trunc(double);

extern double remainder(double, double);
extern double remquo(double, double, int *);

extern double copysign(double, double);
extern double nan(const char *);
extern double nextafter(double, double);
extern double nexttoward(double, long double);

extern double fdim(double, double);
extern double fmax(double, double);
extern double fmin(double, double);

extern double fma(double, double, double);

extern float acosf(float);
extern float asinf(float);
extern float atanf(float);
extern float atan2f(float, float);
extern float cosf(float);
extern float sinf(float);
extern float tanf(float);

extern float acoshf(float);
extern float asinhf(float);
extern float atanhf(float);
extern float coshf(float);
extern float sinhf(float);
extern float tanhf(float);

extern float expf(float);
extern float exp2f(float);
extern float expm1f(float);
extern float frexpf(float, int *);
extern int ilogbf(float);
extern float ldexpf(float, int);
extern float logf(float);
extern float log10f(float);
extern float log1pf(float);
extern float log2f(float);
extern float logbf(float);
extern float modff(float, float *);
extern float scalbnf(float, int);
extern float scalblnf(float, long int);

extern float cbrtf(float);
extern float fabsf(float);
extern float hypotf(float, float);
extern float powf(float, float);
extern float sqrtf(float);

extern float erff(float);
extern float erfcf(float);
extern float lgammaf(float);
extern float tgammaf(float);

extern float ceilf(float);
extern float floorf(float);
extern float nearbyintf(float);
extern float rintf(float);
extern long int lrintf(float);
extern float roundf(float);
extern long int lroundf(float);
extern float truncf(float);

extern float fmodf(float, float);
extern float remainderf(float, float);
extern float remquof(float, float, int *);

extern float copysignf(float, float);
extern float nanf(const char *);
extern float nextafterf(float, float);
extern float nexttowardf(float, long double);

extern float fdimf(float, float);
extern float fmaxf(float, float);
extern float fminf(float, float);

extern float fmaf(float, float, float);

extern long double acosl(long double);
extern long double asinl(long double);
extern long double atanl(long double);
extern long double atan2l(long double, long double);
extern long double cosl(long double);
extern long double sinl(long double);
extern long double tanl(long double);

extern long double acoshl(long double);
extern long double asinhl(long double);
extern long double atanhl(long double);
extern long double coshl(long double);
extern long double sinhl(long double);
extern long double tanhl(long double);

extern long double expl(long double);
extern long double exp2l(long double);
extern long double expm1l(long double);
extern long double frexpl(long double, int *);
extern int ilogbl(long double);
extern long double ldexpl(long double, int);
extern long double logl(long double);
extern long double log10l(long double);
extern long double log1pl(long double);
extern long double log2l(long double);
extern long double logbl(long double);
extern long double modfl(long double, long double *);
extern long double scalbnl(long double, int);
extern long double scalblnl(long double, long int);

extern long double cbrtl(long double);
extern long double fabsl(long double);
extern long double hypotl(long double, long double);
extern long double powl(long double, long double);
extern long double sqrtl(long double);

extern long double erfl(long double);
extern long double erfcl(long double);
extern long double lgammal(long double);
extern long double tgammal(long double);

extern long double ceill(long double);
extern long double floorl(long double);
extern long double nearbyintl(long double);
extern long double rintl(long double);
extern long int lrintl(long double);
extern long double roundl(long double);
extern long int lroundl(long double);
extern long double truncl(long double);

extern long double fmodl(long double, long double);
extern long double remainderl(long double, long double);
extern long double remquol(long double, long double, int *);

extern long double copysignl(long double, long double);
extern long double nanl(const char *);
extern long double nextafterl(long double, long double);
extern long double nexttowardl(long double, long double);

extern long double fdiml(long double, long double);
extern long double fmaxl(long double, long double);
extern long double fminl(long double, long double);

extern long double fmal(long double, long double, long double);

#if !defined(_STRICT_STDC) && !defined(_NO_LONGLONG) || defined(_STDC_C99) || \
	defined(__C99FEATURES__)
extern long long int llrint(double);
extern long long int llround(double);

extern long long int llrintf(float);
extern long long int llroundf(float);

extern long long int llrintl(long double);
extern long long int llroundl(long double);
#endif

#if !defined(__cplusplus)
#pragma does_not_read_global_data(asinh, exp2, expm1)
#pragma does_not_read_global_data(ilogb, log2)
#pragma does_not_read_global_data(scalbn, scalbln, cbrt)
#pragma does_not_read_global_data(erf, erfc, tgamma)
#pragma does_not_read_global_data(nearbyint, rint, lrint, round, lround, trunc)
#pragma does_not_read_global_data(remquo)
#pragma does_not_read_global_data(copysign, nan, nexttoward)
#pragma does_not_read_global_data(fdim, fmax, fmin, fma)
#pragma does_not_write_global_data(asinh, exp2, expm1)
#pragma does_not_write_global_data(ilogb, log2)
#pragma does_not_write_global_data(scalbn, scalbln, cbrt)
#pragma does_not_write_global_data(erf, erfc, tgamma)
#pragma does_not_write_global_data(nearbyint, rint, lrint, round, lround, trunc)
#pragma does_not_write_global_data(copysign, nan, nexttoward)
#pragma does_not_write_global_data(fdim, fmax, fmin, fma)

#pragma does_not_read_global_data(acosf, asinf, atanf, atan2f)
#pragma does_not_read_global_data(cosf, sinf, tanf)
#pragma does_not_read_global_data(acoshf, asinhf, atanhf, coshf, sinhf, tanhf)
#pragma does_not_read_global_data(expf, exp2f, expm1f, frexpf, ilogbf, ldexpf)
#pragma does_not_read_global_data(logf, log10f, log1pf, log2f, logbf)
#pragma does_not_read_global_data(modff, scalbnf, scalblnf)
#pragma does_not_read_global_data(cbrtf, fabsf, hypotf, powf, sqrtf)
#pragma does_not_read_global_data(erff, erfcf, lgammaf, tgammaf)
#pragma does_not_read_global_data(ceilf, floorf, nearbyintf)
#pragma does_not_read_global_data(rintf, lrintf, roundf, lroundf, truncf)
#pragma does_not_read_global_data(fmodf, remainderf, remquof)
#pragma does_not_read_global_data(copysignf, nanf, nextafterf, nexttowardf)
#pragma does_not_read_global_data(fdimf, fmaxf, fminf, fmaf)
#pragma does_not_write_global_data(acosf, asinf, atanf, atan2f)
#pragma does_not_write_global_data(cosf, sinf, tanf)
#pragma does_not_write_global_data(acoshf, asinhf, atanhf, coshf, sinhf, tanhf)
#pragma does_not_write_global_data(expf, exp2f, expm1f, ilogbf, ldexpf)
#pragma does_not_write_global_data(logf, log10f, log1pf, log2f, logbf)
#pragma does_not_write_global_data(cbrtf, fabsf, hypotf, powf, sqrtf)
#pragma does_not_write_global_data(erff, erfcf, tgammaf)
#pragma does_not_write_global_data(ceilf, floorf, nearbyintf)
#pragma does_not_write_global_data(rintf, lrintf, roundf, lroundf, truncf)
#pragma does_not_write_global_data(fmodf, remainderf)
#pragma does_not_write_global_data(copysignf, nanf, nextafterf, nexttowardf)
#pragma does_not_write_global_data(fdimf, fmaxf, fminf, fmaf)

#pragma does_not_read_global_data(acosl, asinl, atanl, atan2l)
#pragma does_not_read_global_data(cosl, sinl, tanl)
#pragma does_not_read_global_data(acoshl, asinhl, atanhl, coshl, sinhl, tanhl)
#pragma does_not_read_global_data(expl, exp2l, expm1l, frexpl, ilogbl, ldexpl)
#pragma does_not_read_global_data(logl, log10l, log1pl, log2l, logbl)
#pragma does_not_read_global_data(modfl, scalbnl, scalblnl)
#pragma does_not_read_global_data(cbrtl, fabsl, hypotl, powl, sqrtl)
#pragma does_not_read_global_data(erfl, erfcl, lgammal, tgammal)
#pragma does_not_read_global_data(ceill, floorl, nearbyintl)
#pragma does_not_read_global_data(rintl, lrintl, roundl, lroundl, truncl)
#pragma does_not_read_global_data(fmodl, remainderl, remquol)
#pragma does_not_read_global_data(copysignl, nanl, nextafterl, nexttowardl)
#pragma does_not_read_global_data(fdiml, fmaxl, fminl, fmal)
#pragma does_not_write_global_data(acosl, asinl, atanl, atan2l)
#pragma does_not_write_global_data(cosl, sinl, tanl)
#pragma does_not_write_global_data(acoshl, asinhl, atanhl, coshl, sinhl, tanhl)
#pragma does_not_write_global_data(expl, exp2l, expm1l, ilogbl, ldexpl)
#pragma does_not_write_global_data(logl, log10l, log1pl, log2l, logbl)
#pragma does_not_write_global_data(cbrtl, fabsl, hypotl, powl, sqrtl)
#pragma does_not_write_global_data(erfl, erfcl, tgammal)
#pragma does_not_write_global_data(ceill, floorl, nearbyintl)
#pragma does_not_write_global_data(rintl, lrintl, roundl, lroundl, truncl)
#pragma does_not_write_global_data(fmodl, remainderl)
#pragma does_not_write_global_data(copysignl, nanl, nextafterl, nexttowardl)
#pragma does_not_write_global_data(fdiml, fmaxl, fminl, fmal)

#if !defined(_STRICT_STDC) && !defined(_NO_LONGLONG) || defined(_STDC_C99) || \
	defined(__C99FEATURES__)
#pragma does_not_read_global_data(llrint, llround)
#pragma does_not_read_global_data(llrintf, llroundf, llrintl, llroundl)
#pragma does_not_write_global_data(llrint, llround)
#pragma does_not_write_global_data(llrintf, llroundf, llrintl, llroundl)
#endif
#endif	/* !defined(__cplusplus) */

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(acosh, atanh, hypot, lgamma, log1p, logb)
#pragma does_not_read_global_data(nextafter, remainder)
#pragma does_not_write_global_data(acosh, atanh, hypot, log1p, logb)
#pragma does_not_write_global_data(nextafter, remainder)

#pragma no_side_effect(acosh, asinh, atanh, exp2, expm1)
#pragma no_side_effect(ilogb, log1p, log2, logb)
#pragma no_side_effect(scalbn, scalbln, cbrt, hypot)
#pragma no_side_effect(erf, erfc, tgamma)
#pragma no_side_effect(nearbyint, rint, lrint, round, lround, trunc)
#pragma no_side_effect(remainder)
#pragma no_side_effect(copysign, nan, nextafter, nexttoward)
#pragma no_side_effect(fdim, fmax, fmin, fma)

#pragma no_side_effect(acosf, asinf, atanf, atan2f)
#pragma no_side_effect(cosf, sinf, tanf, coshf, sinhf, tanhf)
#pragma no_side_effect(acoshf, asinhf, atanhf, coshf, sinhf, tanhf)
#pragma no_side_effect(expf, exp2f, expm1f, ilogbf, ldexpf)
#pragma no_side_effect(logf, log10f, log1pf, log2f, logbf)
#pragma no_side_effect(cbrtf, fabsf, hypotf, powf, sqrtf)
#pragma no_side_effect(erff, erfcf, tgammaf)
#pragma no_side_effect(ceilf, floorf, nearbyintf)
#pragma no_side_effect(rintf, lrintf, roundf, lroundf, truncf)
#pragma no_side_effect(fmodf, remainderf)
#pragma no_side_effect(copysignf, nanf, nextafterf, nexttowardf)
#pragma no_side_effect(fdimf, fmaxf, fminf, fmaf)

#pragma no_side_effect(acosl, asinl, atanl, atan2l)
#pragma no_side_effect(cosl, sinl, tanl, coshl, sinhl, tanhl)
#pragma no_side_effect(acoshl, asinhl, atanhl, coshl, sinhl, tanhl)
#pragma no_side_effect(expl, exp2l, expm1l, ilogbl, ldexpl)
#pragma no_side_effect(logl, log10l, log1pl, log2l, logbl)
#pragma no_side_effect(cbrtl, fabsl, hypotl, powl, sqrtl)
#pragma no_side_effect(erfl, erfcl, tgammal)
#pragma no_side_effect(ceill, floorl, nearbyintl)
#pragma no_side_effect(rintl, lrintl, roundl, lroundl, truncl)
#pragma no_side_effect(fmodl, remainderl)
#pragma no_side_effect(copysignl, nanl, nextafterl, nexttowardl)
#pragma no_side_effect(fdiml, fmaxl, fminl, fmal)

#if !defined(_STRICT_STDC) && !defined(_NO_LONGLONG) || defined(_STDC_C99) || \
	defined(__C99FEATURES__)
#pragma no_side_effect(llrint, llround, llrintf, llroundf, llrintl, llroundl)
#endif
#endif	/* defined(__MATHERR_ERRNO_DONTCARE) */
#endif	/* defined(__EXTENSIONS__) || defined(_STDC_C99) || ... */

#ifdef __cplusplus
}
#endif

#endif	/* _ISO_MATH_C99_H */
