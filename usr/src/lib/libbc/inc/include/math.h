/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * Math library definitions for all the public functions implemented in libm.a.
 */

#ifndef	__math_h
#define	__math_h

/*
 * Posix (actually ansi C) section
 */
#define	HUGE_VAL	(__infinity())	/* Produces IEEE Infinity. */


extern double	__infinity();
extern double	acos(/* double x */);
extern double	asin(/* double x */);
extern double	atan(/* double x */);
extern double	atan2(/* double y, double x */);
extern double	ceil(/* double x */);
extern double	cos(/* double x */);
extern double	cosh(/* double x */);
extern double	exp(/* double x */);
extern double	fabs(/* double x */);
extern double	floor(/* double x */);
extern double	fmod(/* double x, double y */);
extern double	frexp(/* double value, int *exp */);
extern double	ldexp(/* double value, int exp */);
extern double	log(/* double x */);
extern double	log10(/* double x */);
extern double	modf(/* double value, double *iptr */);
extern double	pow(/* double x, double y */);
extern double	sin(/* double x */);
extern double	sinh(/* double x */);
extern double	sqrt(/* double x */);
extern double	tan(/* double x */);
extern double	tanh(/* double x */);

#ifndef	_POSIX_SOURCE			/* the rest of the file is !POSIX */
#include <floatingpoint.h>		/* Contains definitions for types and
					 * functions implemented in libc.a.
					 */
extern double	acosh();
extern double	asinh();
extern double	atanh();
extern double	cbrt();
extern double	copysign();
extern double	erf();
extern double	erfc();
extern double	expm1();
extern int	finite();
extern double	hypot();
extern double	j0();
extern double	j1();
extern double	jn();
extern double	lgamma();
extern double	log1p();
extern double	rint();
extern double	y0();
extern double	y1();
extern double	yn();

/*
 * Sun definitions.
 */

/*
 * Implemented precisions for trigonometric argument reduction.
 */
enum fp_pi_type {
	fp_pi_infinite	= 0,	/* Infinite-precision approximation to pi. */
	fp_pi_66	= 1,	/* 66-bit approximation to pi. */
	fp_pi_53	= 2	/* 53-bit approximation to pi. */
};

/*
 * Pi precision to use for trigonometric argument reduction.
 */
extern enum	fp_pi_type fp_pi;

/*
 * Functions callable from C, intended to support IEEE arithmetic.
 */
extern enum	fp_class_type fp_class();
extern int	ieee_flags();
extern int	ieee_handler();
extern void	ieee_retrospective();
extern int	ilogb();
extern double	infinity();
extern int	irint();
extern int	isinf();
extern int	isnan();
extern int	isnormal();
extern int	issubnormal();
extern int	iszero();
extern double	logb();
extern double	max_normal();
extern double	max_subnormal();
extern double	min_normal();
extern double	min_subnormal();
extern double	nextafter();
extern void	nonstandard_arithmetic();
extern double	quiet_nan();
extern double	remainder();
extern double	scalb();
extern double	scalbn();
extern double	signaling_nan();
extern int	signbit();
extern double	significand();
extern void	standard_arithmetic();

/*
 * Other functions for C programmers.
 */
extern double	acospi();
extern double	aint();
extern double	anint();
extern double	annuity();
extern double	asinpi();
extern double	atan2pi();
extern double	atanpi();
extern double	compound();
extern double	cospi();
extern double	exp10();
extern double	exp2();
extern double	log2();
extern int	nint();
extern void	sincos();
extern void	sincospi();
extern double	sinpi();
extern double	tanpi();
extern int	matherr();


/*
 *	Single-precision functions callable from Fortran, Pascal, Modula-2, etc,
 *	take float* arguments instead of double and
 *	return FLOATFUNCTIONTYPE results instead of double.
 *	RETURNFLOAT is used to return a float function value without conversion
 *	to double.
 *	ASSIGNFLOAT is used to get the float value out of a FLOATFUNCTIONTYPE
 *	result.
 *	We don't want you to have to think about -fsingle2.
 *
 *	Some internal library functions pass float parameters as 32-bit values,
 *	disguised as FLOATPARAMETER.  FLOATPARAMETERVALUE(x) extracts the
 *	float value from the FLOATPARAMETER.
 */

/*	mc68000 returns float results in d0, same as int	*/

#ifdef	mc68000
#define	FLOATFUNCTIONTYPE	int
#define	RETURNFLOAT(x) 		return (*(int *)(&(x)))
#define	ASSIGNFLOAT(x,y)	*(int *)(&x) = y
#endif

/*	sparc returns float results in %f0, same as top half of double	*/

#ifdef	sparc
#define	FLOATFUNCTIONTYPE	double
#define	RETURNFLOAT(x) 		{ union {double _d; float _f } _kluge; _kluge._f = (x); return _kluge._d; }
#define	ASSIGNFLOAT(x,y)	{ union {double _d; float _f } _kluge; _kluge._d = (y); x = _kluge._f; }
#endif

/*	i386 returns float results on stack as extendeds, same as double */

#ifdef	i386
#define	FLOATFUNCTIONTYPE	float
#define	RETURNFLOAT(x) 		return (x)
#define	ASSIGNFLOAT(x,y)	x = y
#endif

/* So far everybody passes float parameters as 32 bits on stack, same as int. */

#define	FLOATPARAMETER		int
#define	FLOATPARAMETERVALUE(x)	(*(float *)(&(x)))

extern int		 ir_finite_();
extern enum fp_class_type ir_fp_class_();
extern int		 ir_ilogb_();
extern int		 ir_irint_();
extern int		 ir_isinf_();
extern int		 ir_isnan_();
extern int		 ir_isnormal_();
extern int		 ir_issubnormal_();
extern int		 ir_iszero_();
extern int		 ir_nint_();
extern int		 ir_signbit_();
extern void		 r_sincos_();
extern void		 r_sincospi_();
extern FLOATFUNCTIONTYPE r_acos_();
extern FLOATFUNCTIONTYPE r_acosh_();
extern FLOATFUNCTIONTYPE r_acospi_();
extern FLOATFUNCTIONTYPE r_aint_();
extern FLOATFUNCTIONTYPE r_anint_();
extern FLOATFUNCTIONTYPE r_annuity_();
extern FLOATFUNCTIONTYPE r_asin_();
extern FLOATFUNCTIONTYPE r_asinh_();
extern FLOATFUNCTIONTYPE r_asinpi_();
extern FLOATFUNCTIONTYPE r_atan2_();
extern FLOATFUNCTIONTYPE r_atan2pi_();
extern FLOATFUNCTIONTYPE r_atan_();
extern FLOATFUNCTIONTYPE r_atanh_();
extern FLOATFUNCTIONTYPE r_atanpi_();
extern FLOATFUNCTIONTYPE r_cbrt_();
extern FLOATFUNCTIONTYPE r_ceil_();
extern FLOATFUNCTIONTYPE r_compound_();
extern FLOATFUNCTIONTYPE r_copysign_();
extern FLOATFUNCTIONTYPE r_cos_();
extern FLOATFUNCTIONTYPE r_cosh_();
extern FLOATFUNCTIONTYPE r_cospi_();
extern FLOATFUNCTIONTYPE r_erf_();
extern FLOATFUNCTIONTYPE r_erfc_();
extern FLOATFUNCTIONTYPE r_exp10_();
extern FLOATFUNCTIONTYPE r_exp2_();
extern FLOATFUNCTIONTYPE r_exp_();
extern FLOATFUNCTIONTYPE r_expm1_();
extern FLOATFUNCTIONTYPE r_fabs_();
extern FLOATFUNCTIONTYPE r_floor_();
extern FLOATFUNCTIONTYPE r_fmod_();
extern FLOATFUNCTIONTYPE r_hypot_();
extern FLOATFUNCTIONTYPE r_infinity_();
extern FLOATFUNCTIONTYPE r_j0_();
extern FLOATFUNCTIONTYPE r_j1_();
extern FLOATFUNCTIONTYPE r_jn_();
extern FLOATFUNCTIONTYPE r_lgamma_();
extern FLOATFUNCTIONTYPE r_log10_();
extern FLOATFUNCTIONTYPE r_log1p_();
extern FLOATFUNCTIONTYPE r_log2_();
extern FLOATFUNCTIONTYPE r_log_();
extern FLOATFUNCTIONTYPE r_logb_();
extern FLOATFUNCTIONTYPE r_max_normal_();
extern FLOATFUNCTIONTYPE r_max_subnormal_();
extern FLOATFUNCTIONTYPE r_min_normal_();
extern FLOATFUNCTIONTYPE r_min_subnormal_();
extern FLOATFUNCTIONTYPE r_nextafter_();
extern FLOATFUNCTIONTYPE r_pow_();
extern FLOATFUNCTIONTYPE r_quiet_nan_();
extern FLOATFUNCTIONTYPE r_remainder_();
extern FLOATFUNCTIONTYPE r_rint_();
extern FLOATFUNCTIONTYPE r_scalb_();
extern FLOATFUNCTIONTYPE r_scalbn_();
extern FLOATFUNCTIONTYPE r_signaling_nan_();
extern FLOATFUNCTIONTYPE r_significand_();
extern FLOATFUNCTIONTYPE r_sin_();
extern FLOATFUNCTIONTYPE r_sinh_();
extern FLOATFUNCTIONTYPE r_sinpi_();
extern FLOATFUNCTIONTYPE r_sqrt_();
extern FLOATFUNCTIONTYPE r_tan_();
extern FLOATFUNCTIONTYPE r_tanh_();
extern FLOATFUNCTIONTYPE r_tanpi_();
extern FLOATFUNCTIONTYPE r_y0_();
extern FLOATFUNCTIONTYPE r_y1_();
extern FLOATFUNCTIONTYPE r_yn_();

/* 	Constants, variables, and functions from System V */

#define	_ABS(x) ((x) < 0 ? -(x) : (x))

#define	HUGE		(infinity())	/* For historical compatibility. */

#define	DOMAIN		1
#define	SING		2
#define	OVERFLOW	3
#define	UNDERFLOW	4
#define	TLOSS		5
#define	PLOSS		6

struct exception {
	int type;
	char *name;
	double arg1;
	double arg2;
	double retval;
};

/*
 * First three have to be defined exactly as in values.h including spacing!
 */
#define	M_LN2	0.69314718055994530942
#define	M_PI	3.14159265358979323846
#define	M_SQRT2	1.41421356237309504880

#define	M_E		2.7182818284590452354
#define	M_LOG2E		1.4426950408889634074
#define	M_LOG10E	0.43429448190325182765
#define	M_LN10		2.30258509299404568402
#define	M_PI_2		1.57079632679489661923
#define	M_PI_4		0.78539816339744830962
#define	M_1_PI		0.31830988618379067154
#define	M_2_PI		0.63661977236758134308
#define	M_2_SQRTPI	1.12837916709551257390
#define	M_SQRT1_2	0.70710678118654752440
#define	_REDUCE(TYPE, X, XN, C1, C2)	{ \
	double x1 = (double)(TYPE)X, x2 = X - x1; \
	X = x1 - (XN) * (C1); X += x2; X -= (XN) * (C2); }
#define	_POLY1(x, c)    ((c)[0] * (x) + (c)[1])
#define	_POLY2(x, c)    (_POLY1((x), (c)) * (x) + (c)[2])
#define	_POLY3(x, c)    (_POLY2((x), (c)) * (x) + (c)[3])
#define	_POLY4(x, c)    (_POLY3((x), (c)) * (x) + (c)[4])
#define	_POLY5(x, c)    (_POLY4((x), (c)) * (x) + (c)[5])
#define	_POLY6(x, c)    (_POLY5((x), (c)) * (x) + (c)[6])
#define	_POLY7(x, c)    (_POLY6((x), (c)) * (x) + (c)[7])
#define	_POLY8(x, c)    (_POLY7((x), (c)) * (x) + (c)[8])
#define	_POLY9(x, c)    (_POLY8((x), (c)) * (x) + (c)[9])

extern int	signgam;
/*
 *	Deprecated functions for compatibility with past.
 *	Changes planned for future.
 */

extern double cabs();	/* Use double hypot(x,y)
			 * Traditional cabs usage is confused -
			 * is its argument two doubles or one struct?
			 */
extern double drem();	/* Use double remainder(x,y)
			 * drem will disappear in a future release.
			 */
extern double gamma();	/* Use double lgamma(x)
			 * to compute log of gamma function.
			 * Name gamma is reserved for true gamma function
			 * to appear in a future release.
			 */
#endif	/* !_POSIX_SOURCE */
#endif	/* !__math_h */
