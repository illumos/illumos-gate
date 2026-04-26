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

/*
 * Declarations for C (and C++ global namespace)
 */

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

/*
 * ISO C++98 and later require float and long double overloads of
 * all C90 math functions.  The declarations are in the global
 * namespace. The namespace std gets them via "using ::" aliases
 * and the float and long double overloads as inlines.
 *
 * This global-primary layout ensures that when GCC's <cmath> does
 * "using ::log" to populate namespace std, only the double form
 * reaches ::.  GCC then appends its integer-covering template to
 * namespace std, making log(int) unambiguous.
 */

#if __cplusplus >= 199711L

/*
 * float variants of above
 */
extern float acosf(float);
extern float asinf(float);
extern float atanf(float);
extern float atan2f(float, float);
extern float ceilf(float);
extern float cosf(float);
extern float coshf(float);
extern float expf(float);
extern float fabsf(float);
extern float floorf(float);
extern float fmodf(float, float);
extern float frexpf(float, int *);
extern float ldexpf(float, int);
extern float logf(float);
extern float log10f(float);
extern float modff(float, float *);
extern float powf(float, float);
extern float sinf(float);
extern float sinhf(float);
extern float sqrtf(float);
extern float tanf(float);
extern float tanhf(float);

/*
 * long double variants of above
 */
extern long double acosl(long double);
extern long double asinl(long double);
extern long double atanl(long double);
extern long double atan2l(long double, long double);
extern long double ceill(long double);
extern long double cosl(long double);
extern long double coshl(long double);
extern long double expl(long double);
extern long double fabsl(long double);
extern long double floorl(long double);
extern long double fmodl(long double, long double);
extern long double frexpl(long double, int *);
extern long double ldexpl(long double, int);
extern long double logl(long double);
extern long double log10l(long double);
extern long double modfl(long double, long double *);
extern long double powl(long double, long double);
extern long double sinl(long double);
extern long double sinhl(long double);
extern long double sqrtl(long double);
extern long double tanl(long double);
extern long double tanhl(long double);

#endif	/* __cplusplus >= 199711L */

#ifdef __cplusplus
}
#endif

#if __cplusplus >= 199711L
extern "C++" {
namespace std {

	/*
	 * Each using declaration brings the double (C-standard) form
	 * into std::.  The float and long double overloads are defined
	 * as inlines below.
	 */
	using ::acos;
	using ::asin;
	using ::atan2;
	using ::atan;
	using ::ceil;
	using ::cos;
	using ::cosh;
	using ::exp;
	using ::fabs;
	using ::floor;
	using ::fmod;
	using ::frexp;
	using ::ldexp;
	using ::log10;
	using ::log;
	using ::modf;
	using ::pow;
	using ::sin;
	using ::sinh;
	using ::sqrt;
	using ::tan;
	using ::tanh;

	/*
	 * C++98 requires overloads of C90 math functions for float and
	 * long double arguments.  These inlines satisfy that requirement
	 * by delegating to the corresponding C99 named variants.
	 */
#undef	__X
#undef	__Y

	/* inline double pow(double, int) not needed */

	inline float acos(float __X) { return acosf(__X); }
	inline float asin(float __X) { return asinf(__X); }
	inline float atan(float __X) { return atanf(__X); }
	inline float atan2(float __X, float __Y) { return atan2f(__X, __Y); }
	inline float ceil(float __X) { return ceilf(__X); }
	inline float cos(float __X) { return cosf(__X); }
	inline float cosh(float __X) { return coshf(__X); }
	inline float exp(float __X) { return expf(__X); }
	inline float fabs(float __X) { return fabsf(__X); }
	inline float floor(float __X) { return floorf(__X); }
	inline float fmod(float __X, float __Y) { return fmodf(__X, __Y); }
	inline float frexp(float __X, int *__Y) { return frexpf(__X, __Y); }
	inline float ldexp(float __X, int __Y) { return ldexpf(__X, __Y); }
	inline float log(float __X) { return logf(__X); }
	inline float log10(float __X) { return log10f(__X); }
	inline float modf(float __X, float *__Y) { return modff(__X, __Y); }
	inline float pow(float __X, float __Y) { return powf(__X, __Y); }
	inline float sin(float __X) { return sinf(__X); }
	inline float sinh(float __X) { return sinhf(__X); }
	inline float sqrt(float __X) { return sqrtf(__X); }
	inline float tan(float __X) { return tanf(__X); }
	inline float tanh(float __X) { return tanhf(__X); }

	inline long double acos(long double __X) { return acosl(__X); }
	inline long double asin(long double __X) { return asinl(__X); }
	inline long double atan(long double __X) { return atanl(__X); }

	inline long double atan2(long double __X, long double __Y) {
		return (atan2l(__X, __Y));
	}

	inline long double ceil(long double __X) { return ceill(__X); }
	inline long double cos(long double __X) { return cosl(__X); }
	inline long double cosh(long double __X) { return coshl(__X); }
	inline long double exp(long double __X) { return expl(__X); }
	inline long double fabs(long double __X) { return fabsl(__X); }
	inline long double floor(long double __X) { return floorl(__X); }

	inline long double fmod(long double __X, long double __Y) {
		return (fmodl(__X, __Y));
	}

	inline long double frexp(long double __X, int *__Y) {
		return (frexpl(__X, __Y));
	}

	inline long double ldexp(long double __X, int __Y) {
		return (ldexpl(__X, __Y));
	}

	inline long double log(long double __X) { return logl(__X); }
	inline long double log10(long double __X) { return log10l(__X); }

	inline long double modf(long double __X, long double *__Y) {
		return (modfl(__X, __Y));
	}

	inline long double pow(long double __X, long double __Y) {
		return (powl(__X, __Y));
	}

	inline long double sin(long double __X) { return sinl(__X); }
	inline long double sinh(long double __X) { return sinhl(__X); }
	inline long double sqrt(long double __X) { return sqrtl(__X); }
	inline long double tan(long double __X) { return tanl(__X); }
	inline long double tanh(long double __X) { return tanhl(__X); }

/*
 * For compatibility with GCC and GLIBCXX, let either stdlib.h or math.h
 * provide both the integer and floating point abs() variants, regardless
 * which is included first.
 */
#ifndef _CXX_ABS_FLOAT_DEFINED
#define	_CXX_ABS_FLOAT_DEFINED
	inline double abs(double __X) { return fabs(__X); }
	inline float abs(float __X) { return fabsf(__X); }
	inline long double abs(long double __X) { return fabsl(__X); }
#endif /* !_CXX_ABS_FLOAT_DEFINED */

}  /* namespace std */

}  /* extern "C++" */
#endif	/* __cplusplus >= 199711L */

#endif	/* _ISO_MATH_ISO_H */
