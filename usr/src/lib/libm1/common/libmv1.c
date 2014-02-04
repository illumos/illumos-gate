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

#pragma weak _lib_version = __libm_lib_version
#pragma weak acos = __acos
#pragma weak acosh = __acosh
#pragma weak asin = __asin
#pragma weak asinh = __asinh
#pragma weak atan = __atan
#pragma weak atan2 = __atan2
#pragma weak atanh = __atanh
#pragma weak cbrt = __cbrt
#pragma weak ceil = __ceil
#pragma weak copysign = __copysign
#pragma weak cos = __cos
#pragma weak cosh = __cosh
#pragma weak erf = __erf
#pragma weak erfc = __erfc
#pragma weak exp = __exp
#pragma weak expm1 = __expm1
#pragma weak fabs = __fabs
#pragma weak floor = __floor
#pragma weak fmod = __fmod
#pragma weak gamma = __gamma
#pragma weak gamma_r = __gamma_r
#pragma weak hypot = __hypot
#pragma weak ilogb = __ilogb
#pragma weak isnan = __isnan
#pragma weak j0 = __j0
#pragma weak j1 = __j1
#pragma weak jn = __jn
#pragma weak lgamma = __lgamma
#pragma weak lgamma_r = __lgamma_r
#pragma weak log = __log
#pragma weak log10 = __log10
#pragma weak log1p = __log1p
#pragma weak logb = __logb
#pragma weak nextafter = __nextafter
#pragma weak pow = __pow
#pragma weak remainder = __remainder
#pragma weak rint = __rint
#pragma weak scalb = __scalb
#pragma weak scalbn = __scalbn
#pragma weak signgam = __signgam
#pragma weak significand = __significand
#pragma weak sin = __sin
#pragma weak sinh = __sinh
#pragma weak sqrt = __sqrt
#pragma weak tan = __tan
#pragma weak tanh = __tanh
#pragma weak y0 = __y0
#pragma weak y1 = __y1
#pragma weak yn = __yn

#include <math.h>

const enum version __libm_lib_version = libm_ieee;
int __signgam = 0;

#if !defined(__sparcv9) && !defined(__amd64)
/* ARGSUSED */
int *
__libm_errno(void) {
	return (0);
}
#endif

/* ARGSUSED */
int
__libm__rem_pio2(double x, double *y) {
	return (0);
}

/* ARGSUSED */
int
__libm__rem_pio2m(double *x, double *y, int e0, int nx, int p, const int *ip) {
	return (0);
}

/* ARGSUSED */
double
__acos(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__acosh(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__asin(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__asinh(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__atan(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__atan2(double y, double x) {
	return (0.0);
}

/* ARGSUSED */
double
__atanh(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__cbrt(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__ceil(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__copysign(double x, double y) {
	return (0.0);
}

/* ARGSUSED */
double
__cos(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__cosh(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__erf(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__erfc(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__exp(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__expm1(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__fabs(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__floor(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__fmod(double x, double y) {
	return (0.0);
}

/* ARGSUSED */
double
__gamma(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__gamma_r(double x, int *signgamp) {
	return (0.0);
}

/* ARGSUSED */
double
__hypot(double x, double y) {
	return (0.0);
}

/* ARGSUSED */
int
__ilogb(double x) {
	return (0);
}

/* ARGSUSED */
int
__isnan(double x) {
	return (0);
}

/* ARGSUSED */
double
__j0(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__j1(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__jn(int n, double y) {
	return (0.0);
}

/* ARGSUSED */
double
__lgamma(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__lgamma_r(double x, int *signgamp) {
	return (0.0);
}

/* ARGSUSED */
double
__log(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__log10(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__log1p(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__logb(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__nextafter(double x, double y) {
	return (0.0);
}

/* ARGSUSED */
double
__pow(double x, double y) {
	return (0.0);
}

/* ARGSUSED */
double
__remainder(double x, double y) {
	return (0.0);
}

/* ARGSUSED */
double
__rint(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__scalb(double x, double y) {
	return (0.0);
}

/* ARGSUSED */
double
__scalbn(double x, int n) {
	return (0.0);
}

/* ARGSUSED */
double
__significand(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__sin(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__sinh(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__sqrt(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__tan(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__tanh(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__y0(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__y1(double x) {
	return (0.0);
}

/* ARGSUSED */
double
__yn(int n, double x) {
	return (0.0);
}

/* ARGSUSED */
int
matherr(struct exception *excep) {
	return (0);
}

/* ARGSUSED */
float
__acosf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__asinf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__atanf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__atan2f(float y, float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__ceilf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__cosf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__coshf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__expf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__fabsf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__floorf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__fmodf(float x, float y) {
	return (0.0F);
}

/* ARGSUSED */
float
__frexpf(float x, int *e) {
	return (0.0F);
}

/* ARGSUSED */
float
__ldexpf(float x, int n) {
	return (0.0F);
}

/* ARGSUSED */
float
__logf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__log10f(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__modff(float x, float *iptr) {
	return (0.0F);
}

/* ARGSUSED */
float
__powf(float x, float y) {
	return (0.0F);
}

/* ARGSUSED */
float
__sinf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__sinhf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__sqrtf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__tanf(float x) {
	return (0.0F);
}

/* ARGSUSED */
float
__tanhf(float x) {
	return (0.0F);
}

/* ARGSUSED */
long double
__acosl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__asinl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__atanl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__atan2l(long double y, long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__ceill(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__cosl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__coshl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__expl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__fabsl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__floorl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__fmodl(long double x, long double y) {
	return (0.0L);
}

/* ARGSUSED */
long double
__frexpl(long double x, int *e) {
	return (0.0L);
}

/* ARGSUSED */
long double
__ldexpl(long double x, int n) {
	return (0.0L);
}

/* ARGSUSED */
long double
__logl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__log10l(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__modfl(long double x, long double *iptr) {
	return (0.0L);
}

/* ARGSUSED */
long double
__powl(long double x, long double y) {
	return (0.0L);
}

/* ARGSUSED */
long double
__sinl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__sinhl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__sqrtl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__tanl(long double x) {
	return (0.0L);
}

/* ARGSUSED */
long double
__tanhl(long double x) {
	return (0.0L);
}
