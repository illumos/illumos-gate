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

#ifndef _TGMATH_H
#define	_TGMATH_H

#if !defined(__cplusplus)

#include <math.h>
#include <complex.h>

/*
 * real-floating and complex
 */
#undef	acos
#define	acos(x)			__tgmath_acos(x)
#undef	asin
#define	asin(x)			__tgmath_asin(x)
#undef	atan
#define	atan(x)			__tgmath_atan(x)
#undef	acosh
#define	acosh(x)		__tgmath_acosh(x)
#undef	asinh
#define	asinh(x)		__tgmath_asinh(x)
#undef	atanh
#define	atanh(x)		__tgmath_atanh(x)
#undef	cos
#define	cos(x)			__tgmath_cos(x)
#undef	sin
#define	sin(x)			__tgmath_sin(x)
#undef	tan
#define	tan(x)			__tgmath_tan(x)
#undef	cosh
#define	cosh(x)			__tgmath_cosh(x)
#undef	sinh
#define	sinh(x)			__tgmath_sinh(x)
#undef	tanh
#define	tanh(x)			__tgmath_tanh(x)
#undef	exp
#define	exp(x)			__tgmath_exp(x)
#undef	log
#define	log(x)			__tgmath_log(x)
#undef	pow
#define	pow(x, y)		__tgmath_pow(x, y)
#undef	sqrt
#define	sqrt(x)			__tgmath_sqrt(x)
#undef	fabs
#define	fabs(x)			__tgmath_fabs(x)

/*
 * real-floating only
 */
#undef	atan2
#define	atan2(y, x)		__tgmath_atan2(y, x)
#undef	cbrt
#define	cbrt(x)			__tgmath_cbrt(x)
#undef	ceil
#define	ceil(x)			__tgmath_ceil(x)
#undef	copysign
#define	copysign(x, y)		__tgmath_copysign(x, y)
#undef	erf
#define	erf(x)			__tgmath_erf(x)
#undef	erfc
#define	erfc(x)			__tgmath_erfc(x)
#undef	exp2
#define	exp2(x)			__tgmath_exp2(x)
#undef	expm1
#define	expm1(x)		__tgmath_expm1(x)
#undef	fdim
#define	fdim(x, y)		__tgmath_fdim(x, y)
#undef	floor
#define	floor(x)		__tgmath_floor(x)
#undef	fma
#define	fma(x, y, z)		__tgmath_fma(x, y, z)
#undef	fmax
#define	fmax(x, y)		__tgmath_fmax(x, y)
#undef	fmin
#define	fmin(x, y)		__tgmath_fmin(x, y)
#undef	fmod
#define	fmod(x, y)		__tgmath_fmod(x, y)
#undef	frexp
#define	frexp(x, ip)		__tgmath_frexp(x, ip)
#undef	hypot
#define	hypot(x, y)		__tgmath_hypot(x, y)
#undef	ilogb
#define	ilogb(x)		__tgmath_ilogb(x)
#undef	ldexp
#define	ldexp(x, i)		__tgmath_ldexp(x, i)
#undef	lgamma
#define	lgamma(x)		__tgmath_lgamma(x)
#undef	llrint
#define	llrint(x)		__tgmath_llrint(x)
#undef	llround
#define	llround(x)		__tgmath_llround(x)
#undef	log10
#define	log10(x)		__tgmath_log10(x)
#undef	log1p
#define	log1p(x)		__tgmath_log1p(x)
#undef	log2
#define	log2(x)			__tgmath_log2(x)
#undef	logb
#define	logb(x)			__tgmath_logb(x)
#undef	lrint
#define	lrint(x)		__tgmath_lrint(x)
#undef	lround
#define	lround(x)		__tgmath_lround(x)
#undef	nearbyint
#define	nearbyint(x)		__tgmath_nearbyint(x)
#undef	nextafter
#define	nextafter(x, y)		__tgmath_nextafter(x, y)
#undef	nexttoward
#define	nexttoward(x, y)	__tgmath_nexttoward(x, y)
#undef	remainder
#define	remainder(x, y)		__tgmath_remainder(x, y)
#undef	remquo
#define	remquo(x, y, ip)	__tgmath_remquo(x, y, ip)
#undef	rint
#define	rint(x)			__tgmath_rint(x)
#undef	round
#define	round(x)		__tgmath_round(x)
#undef	scalbln
#define	scalbln(x, l)		__tgmath_scalbln(x, l)
#undef	scalbn
#define	scalbn(x, i)		__tgmath_scalbn(x, i)
#undef	tgamma
#define	tgamma(x)		__tgmath_tgamma(x)
#undef	trunc
#define	trunc(x)		__tgmath_trunc(x)

/*
 * complex only
 */
#undef	carg
#define	carg(x)			__tgmath_carg(x)
#undef	cimag
#define	cimag(x)		__tgmath_cimag(x)
#undef	conj
#define	conj(x)			__tgmath_conj(x)
#undef	cproj
#define	cproj(x)		__tgmath_cproj(x)
#undef	creal
#define	creal(x)		__tgmath_creal(x)

#endif	/* !defined(__cplusplus) */

#endif	/* _TGMATH_H */
