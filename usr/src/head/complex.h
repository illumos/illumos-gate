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

#ifndef _COMPLEX_H
#define	_COMPLEX_H

#ifdef	__cplusplus
extern "C" {
#endif

/* #if !defined(__cplusplus) */

/*
 * Compilation environments for Solaris must provide the _Imaginary datatype
 * and the compiler intrinsics _Complex_I and _Imaginary_I
 */
#if defined(__SUNPRO_C)
#define	_Complex_I	_Complex_I
#define	_Imaginary_I	_Imaginary_I
#else
#define	_Complex_I	1.0fi
#define	_Imaginary_I	1.0fi
#endif
#define	complex		_Complex
#define	imaginary	_Imaginary
#undef	I
#define	I		_Imaginary_I

extern float cabsf(float complex);
extern float cargf(float complex);
extern float cimagf(float complex);
extern float crealf(float complex);
extern float complex cacosf(float complex);
extern float complex cacoshf(float complex);
extern float complex casinf(float complex);
extern float complex casinhf(float complex);
extern float complex catanf(float complex);
extern float complex catanhf(float complex);
extern float complex ccosf(float complex);
extern float complex ccoshf(float complex);
extern float complex cexpf(float complex);
extern float complex clogf(float complex);
extern float complex conjf(float complex);
extern float complex cpowf(float complex, float complex);
extern float complex cprojf(float complex);
extern float complex csinf(float complex);
extern float complex csinhf(float complex);
extern float complex csqrtf(float complex);
extern float complex ctanf(float complex);
extern float complex ctanhf(float complex);

extern double cabs(double complex);
extern double carg(double complex);
extern double cimag(double complex);
extern double creal(double complex);
extern double complex cacos(double complex);
extern double complex cacosh(double complex);
extern double complex casin(double complex);
extern double complex casinh(double complex);
extern double complex catan(double complex);
extern double complex catanh(double complex);
extern double complex ccos(double complex);
extern double complex ccosh(double complex);
extern double complex cexp(double complex);
#if defined(__PRAGMA_REDEFINE_EXTNAME)
#pragma redefine_extname clog __clog
#else
#undef	clog
#define	clog	__clog
#endif
extern double complex clog(double complex);
extern double complex conj(double complex);
extern double complex cpow(double complex, double complex);
extern double complex cproj(double complex);
extern double complex csin(double complex);
extern double complex csinh(double complex);
extern double complex csqrt(double complex);
extern double complex ctan(double complex);
extern double complex ctanh(double complex);

extern long double cabsl(long double complex);
extern long double cargl(long double complex);
extern long double cimagl(long double complex);
extern long double creall(long double complex);
extern long double complex cacoshl(long double complex);
extern long double complex cacosl(long double complex);
extern long double complex casinhl(long double complex);
extern long double complex casinl(long double complex);
extern long double complex catanhl(long double complex);
extern long double complex catanl(long double complex);
extern long double complex ccoshl(long double complex);
extern long double complex ccosl(long double complex);
extern long double complex cexpl(long double complex);
extern long double complex clogl(long double complex);
extern long double complex conjl(long double complex);
extern long double complex cpowl(long double complex, long double complex);
extern long double complex cprojl(long double complex);
extern long double complex csinhl(long double complex);
extern long double complex csinl(long double complex);
extern long double complex csqrtl(long double complex);
extern long double complex ctanhl(long double complex);
extern long double complex ctanl(long double complex);

/* #endif */	/* !defined(__cplusplus) */
#ifdef	__cplusplus
}
#endif

#endif	/* _COMPLEX_H */
