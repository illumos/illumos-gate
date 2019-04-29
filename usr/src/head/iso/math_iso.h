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

#ifndef _ISO_MATH_ISO_H
#define	_ISO_MATH_ISO_H

#include <sys/feature_tests.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_STDC_C99) && _XOPEN_SOURCE - 0 < 600 && !defined(__C99FEATURES__)
typedef union _h_val {
	unsigned long _i[sizeof (double) / sizeof (unsigned long)];
	double _d;
} _h_val;

#ifdef __STDC__
extern const _h_val __huge_val;
#else
extern _h_val __huge_val;
#endif
#undef	HUGE_VAL
#define	HUGE_VAL __huge_val._d
#endif	/* !defined(_STDC_C99) && _XOPEN_SOURCE - 0 < 600 && ... */

#if __cplusplus >= 199711L
namespace std {
#endif

extern double acos(double);
extern double asin(double);
extern double atan(double);
extern double atan2(double, double);
extern double cos(double);
extern double sin(double);
extern double tan(double);

extern double cosh(double);
extern double sinh(double);
extern double tanh(double);

extern double exp(double);
extern double frexp(double, int *);
extern double ldexp(double, int);
extern double log(double);
extern double log10(double);
extern double modf(double, double *);

extern double pow(double, double);
extern double sqrt(double);

extern double ceil(double);
extern double fabs(double);
extern double floor(double);
extern double fmod(double, double);

#if defined(__MATHERR_ERRNO_DONTCARE)
#pragma does_not_read_global_data(acos, asin, atan, atan2)
#pragma does_not_read_global_data(cos, sin, tan, cosh, sinh, tanh)
#pragma does_not_read_global_data(exp, log, log10, pow, sqrt)
#pragma does_not_read_global_data(frexp, ldexp, modf)
#pragma does_not_read_global_data(ceil, fabs, floor, fmod)
#pragma does_not_write_global_data(acos, asin, atan, atan2)
#pragma does_not_write_global_data(cos, sin, tan, cosh, sinh, tanh)
#pragma does_not_write_global_data(exp, log, log10, pow, sqrt)
#pragma does_not_write_global_data(ldexp)
#pragma does_not_write_global_data(ceil, fabs, floor, fmod)
#pragma no_side_effect(acos, asin, atan, atan2)
#pragma no_side_effect(cos, sin, tan, cosh, sinh, tanh)
#pragma no_side_effect(exp, log, log10, pow, sqrt)
#pragma no_side_effect(ldexp)
#pragma no_side_effect(ceil, fabs, floor, fmod)
#endif

#if __cplusplus >= 199711L
extern float __acosf(float);
extern float __asinf(float);
extern float __atanf(float);
extern float __atan2f(float, float);
extern float __ceilf(float);
extern float __cosf(float);
extern float __coshf(float);
extern float __expf(float);
extern float __fabsf(float);
extern float __floorf(float);
extern float __fmodf(float, float);
extern float __frexpf(float, int *);
extern float __ldexpf(float, int);
extern float __logf(float);
extern float __log10f(float);
extern float __modff(float, float *);
extern float __powf(float, float);
extern float __sinf(float);
extern float __sinhf(float);
extern float __sqrtf(float);
extern float __tanf(float);
extern float __tanhf(float);

extern long double __acosl(long double);
extern long double __asinl(long double);
extern long double __atanl(long double);
extern long double __atan2l(long double, long double);
extern long double __ceill(long double);
extern long double __cosl(long double);
extern long double __coshl(long double);
extern long double __expl(long double);
extern long double __fabsl(long double);
extern long double __floorl(long double);
extern long double __fmodl(long double, long double);
extern long double __frexpl(long double, int *);
extern long double __ldexpl(long double, int);
extern long double __logl(long double);
extern long double __log10l(long double);
extern long double __modfl(long double, long double *);
extern long double __powl(long double, long double);
extern long double __sinl(long double);
extern long double __sinhl(long double);
extern long double __sqrtl(long double);
extern long double __tanl(long double);
extern long double __tanhl(long double);

extern "C++" {
#undef	__X
#undef	__Y
	inline double abs(double __X) { return fabs(__X); }

	inline double pow(double __X, int __Y) {
		return (pow(__X, (double)(__Y)));
	}

	inline float abs(float __X) { return __fabsf(__X); }
	inline float acos(float __X) { return __acosf(__X); }
	inline float asin(float __X) { return __asinf(__X); }
	inline float atan(float __X) { return __atanf(__X); }
	inline float atan2(float __X, float __Y) { return __atan2f(__X, __Y); }
	inline float ceil(float __X) { return __ceilf(__X); }
	inline float cos(float __X) { return __cosf(__X); }
	inline float cosh(float __X) { return __coshf(__X); }
	inline float exp(float __X) { return __expf(__X); }
	inline float fabs(float __X) { return __fabsf(__X); }
	inline float floor(float __X) { return __floorf(__X); }
	inline float fmod(float __X, float __Y) { return __fmodf(__X, __Y); }
	inline float frexp(float __X, int *__Y) { return __frexpf(__X, __Y); }
	inline float ldexp(float __X, int __Y) { return __ldexpf(__X, __Y); }
	inline float log(float __X) { return __logf(__X); }
	inline float log10(float __X) { return __log10f(__X); }
	inline float modf(float __X, float *__Y) { return __modff(__X, __Y); }
	inline float pow(float __X, float __Y) { return __powf(__X, __Y); }

	inline float pow(float __X, int __Y) {
		return (pow((double)(__X), (double)(__Y)));
	}

	inline float sin(float __X) { return __sinf(__X); }
	inline float sinh(float __X) { return __sinhf(__X); }
	inline float sqrt(float __X) { return __sqrtf(__X); }
	inline float tan(float __X) { return __tanf(__X); }
	inline float tanh(float __X) { return __tanhf(__X); }

	inline long double abs(long double __X) { return __fabsl(__X); }
	inline long double acos(long double __X) { return __acosl(__X); }
	inline long double asin(long double __X) { return __asinl(__X); }
	inline long double atan(long double __X) { return __atanl(__X); }

	inline long double atan2(long double __X, long double __Y) {
		return (__atan2l(__X, __Y));
	}

	inline long double ceil(long double __X) { return __ceill(__X); }
	inline long double cos(long double __X) { return __cosl(__X); }
	inline long double cosh(long double __X) { return __coshl(__X); }
	inline long double exp(long double __X) { return __expl(__X); }
	inline long double fabs(long double __X) { return __fabsl(__X); }
	inline long double floor(long double __X) { return __floorl(__X); }

	inline long double fmod(long double __X, long double __Y) {
		return (__fmodl(__X, __Y));
	}

	inline long double frexp(long double __X, int *__Y) {
		return (__frexpl(__X, __Y));
	}

	inline long double ldexp(long double __X, int __Y) {
		return (__ldexpl(__X, __Y));
	}

	inline long double log(long double __X) { return __logl(__X); }
	inline long double log10(long double __X) { return __log10l(__X); }

	inline long double modf(long double __X, long double *__Y) {
		return (__modfl(__X, __Y));
	}

	inline long double pow(long double __X, long double __Y) {
		return (__powl(__X, __Y));
	}

	inline long double pow(long double __X, int __Y) {
		return (__powl(__X, (long double) (__Y)));
	}

	inline long double sin(long double __X) { return __sinl(__X); }
	inline long double sinh(long double __X) { return __sinhl(__X); }
	inline long double sqrt(long double __X) { return __sqrtl(__X); }
	inline long double tan(long double __X) { return __tanl(__X); }
	inline long double tanh(long double __X) { return __tanhl(__X); }
}	/* end of extern "C++" */
#endif	/* __cplusplus >= 199711L */

#if __cplusplus >= 199711L
}	/* end of namespace std */
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _ISO_MATH_ISO_H */
