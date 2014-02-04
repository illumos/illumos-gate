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

#ifndef _LIBM_SYNONYMS_H
#define	_LIBM_SYNONYMS_H

#if defined(ELFOBJ) && !defined(lint)

#define	cabs			__cabs			/* C99 <complex.h> */
#define	cabsf			__cabsf			/* C99 <complex.h> */
#define	cabsl			__cabsl			/* C99 <complex.h> */
#define	cacos			__cacos			/* C99 <complex.h> */
#define	cacosf			__cacosf		/* C99 <complex.h> */
#define	cacosl			__cacosl		/* C99 <complex.h> */
#define	cacosh			__cacosh		/* C99 <complex.h> */
#define	cacoshf			__cacoshf		/* C99 <complex.h> */
#define	cacoshl			__cacoshl		/* C99 <complex.h> */
#define	carg			__carg			/* C99 <complex.h> */
#define	cargf			__cargf			/* C99 <complex.h> */
#define	cargl			__cargl			/* C99 <complex.h> */
#define	casin			__casin			/* C99 <complex.h> */
#define	casinf			__casinf		/* C99 <complex.h> */
#define	casinl			__casinl		/* C99 <complex.h> */
#define	casinh			__casinh		/* C99 <complex.h> */
#define	casinhf			__casinhf		/* C99 <complex.h> */
#define	casinhl			__casinhl		/* C99 <complex.h> */
#define	catan			__catan			/* C99 <complex.h> */
#define	catanf			__catanf		/* C99 <complex.h> */
#define	catanl			__catanl		/* C99 <complex.h> */
#define	catanh			__catanh		/* C99 <complex.h> */
#define	catanhf			__catanhf		/* C99 <complex.h> */
#define	catanhl			__catanhl		/* C99 <complex.h> */
#define	ccos			__ccos			/* C99 <complex.h> */
#define	ccosf			__ccosf			/* C99 <complex.h> */
#define	ccosl			__ccosl			/* C99 <complex.h> */
#define	ccosh			__ccosh			/* C99 <complex.h> */
#define	ccoshf			__ccoshf		/* C99 <complex.h> */
#define	ccoshl			__ccoshl		/* C99 <complex.h> */
#define	cexp			__cexp			/* C99 <complex.h> */
#define	cexpf			__cexpf			/* C99 <complex.h> */
#define	cexpl			__cexpl			/* C99 <complex.h> */
#define	cimag			__cimag			/* C99 <complex.h> */
#define	cimagf			__cimagf		/* C99 <complex.h> */
#define	cimagl			__cimagl		/* C99 <complex.h> */
#define	clog			__clog			/* C99 <complex.h> */
#define	clogf			__clogf			/* C99 <complex.h> */
#define	clogl			__clogl			/* C99 <complex.h> */
#define	conj			__conj			/* C99 <complex.h> */
#define	conjf			__conjf			/* C99 <complex.h> */
#define	conjl			__conjl			/* C99 <complex.h> */
#define	cpow			__cpow			/* C99 <complex.h> */
#define	cpowf			__cpowf			/* C99 <complex.h> */
#define	cpowl			__cpowl			/* C99 <complex.h> */
#define	cproj			__cproj			/* C99 <complex.h> */
#define	cprojf			__cprojf		/* C99 <complex.h> */
#define	cprojl			__cprojl		/* C99 <complex.h> */
#define	creal			__creal			/* C99 <complex.h> */
#define	crealf			__crealf		/* C99 <complex.h> */
#define	creall			__creall		/* C99 <complex.h> */
#define	csin			__csin			/* C99 <complex.h> */
#define	csinf			__csinf			/* C99 <complex.h> */
#define	csinl			__csinl			/* C99 <complex.h> */
#define	csinh			__csinh			/* C99 <complex.h> */
#define	csinhf			__csinhf		/* C99 <complex.h> */
#define	csinhl			__csinhl		/* C99 <complex.h> */
#define	csqrt			__csqrt			/* C99 <complex.h> */
#define	csqrtf			__csqrtf		/* C99 <complex.h> */
#define	csqrtl			__csqrtl		/* C99 <complex.h> */
#define	ctan			__ctan			/* C99 <complex.h> */
#define	ctanf			__ctanf			/* C99 <complex.h> */
#define	ctanl			__ctanl			/* C99 <complex.h> */
#define	ctanh			__ctanh			/* C99 <complex.h> */
#define	ctanhf			__ctanhf		/* C99 <complex.h> */
#define	ctanhl			__ctanhl		/* C99 <complex.h> */
#define	abrupt_underflow_	__abrupt_underflow_
#define	acos			__acos
#define	acosd			__acosd
#define	acosdf			__acosdf
#define	acosdl			__acosdl
#define	acosf			__acosf
#define	acosh			__acosh
#define	acoshf			__acoshf
#define	acoshl			__acoshl
#define	acosl			__acosl
#define	acosp			__acosp
#define	acospf			__acospf
#define	acospi			__acospi
#define	acospif			__acospif
#define	acospil			__acospil
#define	acospl			__acospl
#define	aint			__aint
#define	aintf			__aintf
#define	aintl			__aintl
#define	anint			__anint
#define	anintf			__anintf
#define	anintl			__anintl
#define	annuity			__annuity
#define	annuityf		__annuityf
#define	annuityl		__annuityl
#define	asin			__asin
#define	asind			__asind
#define	asindf			__asindf
#define	asindl			__asindl
#define	asinf			__asinf
#define	asinh			__asinh
#define	asinhf			__asinhf
#define	asinhl			__asinhl
#define	asinl			__asinl
#define	asinp			__asinp
#define	asinpf			__asinpf
#define	asinpi			__asinpi
#define	asinpif			__asinpif
#define	asinpil			__asinpil
#define	asinpl			__asinpl
#define	atan			__atan
#define	atan2			__atan2
#define	atan2d			__atan2d
#define	atan2df			__atan2df
#define	atan2dl			__atan2dl
#define	atan2f			__atan2f
#define	atan2l			__atan2l
#define	atan2pi			__atan2pi
#define	atan2pif		__atan2pif
#define	atan2pil		__atan2pil
#define	atand			__atand
#define	atandf			__atandf
#define	atandl			__atandl
#define	atanf			__atanf
#define	atanh			__atanh
#define	atanhf			__atanhf
#define	atanhl			__atanhl
#define	atanl			__atanl
#define	atanp			__atanp
#define	atanpf			__atanpf
#define	atanpi			__atanpi
#define	atanpif			__atanpif
#define	atanpil			__atanpil
#define	atanpl			__atanpl
#define	cbrt			__cbrt
#define	cbrtf			__cbrtf
#define	cbrtl			__cbrtl
#define	ceil			__ceil
#define	ceilf			__ceilf
#define	ceill			__ceill
#define	compound		__compound
#define	compoundf		__compoundf
#define	compoundl		__compoundl
#define	convert_external	__convert_external
#define	convert_external_	__convert_external_
#define	copysign		__copysign
#define	copysignf		__copysignf
#define	copysignl		__copysignl
#define	cos			__cos
#define	cosd			__cosd
#define	cosdf			__cosdf
#define	cosdl			__cosdl
#define	cosf			__cosf
#define	cosh			__cosh
#define	coshf			__coshf
#define	coshl			__coshl
#define	cosl			__cosl
#define	cosp			__cosp
#define	cospf			__cospf
#define	cospi			__cospi
#define	cospif			__cospif
#define	cospil			__cospil
#define	cospl			__cospl
#define	d_acos_			__d_acos_
#define	d_acosd_		__d_acosd_
#define	d_acosh_		__d_acosh_
#define	d_acosp_		__d_acosp_
#define	d_acospi_		__d_acospi_
#define	d_addran_		__d_addran_
#define	d_addrans_		__d_addrans_
#define	d_aint_			__d_aint_
#define	d_anint_		__d_anint_
#define	d_annuity_		__d_annuity_
#define	d_asin_			__d_asin_
#define	d_asind_		__d_asind_
#define	d_asinh_		__d_asinh_
#define	d_asinp_		__d_asinp_
#define	d_asinpi_		__d_asinpi_
#define	d_atan2_		__d_atan2_
#define	d_atan2d_		__d_atan2d_
#define	d_atan2pi_		__d_atan2pi_
#define	d_atan_			__d_atan_
#define	d_atand_		__d_atand_
#define	d_atanh_		__d_atanh_
#define	d_atanp_		__d_atanp_
#define	d_atanpi_		__d_atanpi_
#define	d_cbrt_			__d_cbrt_
#define	d_ceil_			__d_ceil_
#define	d_compound_		__d_compound_
#define	d_copysign_		__d_copysign_
#define	d_cos_			__d_cos_
#define	d_cosd_			__d_cosd_
#define	d_cosh_			__d_cosh_
#define	d_cosp_			__d_cosp_
#define	d_cospi_		__d_cospi_
#define	d_erf_			__d_erf_
#define	d_erfc_			__d_erfc_
#define	d_exp10_		__d_exp10_
#define	d_exp2_			__d_exp2_
#define	d_exp_			__d_exp_
#define	d_expm1_		__d_expm1_
#define	d_fabs_			__d_fabs_
#define	d_floor_		__d_floor_
#define	d_fmod_			__d_fmod_
#define	d_get_addrans_		__d_get_addrans_
#define	d_hypot_		__d_hypot_
#define	d_infinity_		__d_infinity_
#define	d_init_addrans_		__d_init_addrans_
#define	d_j0_			__d_j0_
#define	d_j1_			__d_j1_
#define	d_jn_			__d_jn_
#define	d_lcran_		__d_lcran_
#define	d_lcrans_		__d_lcrans_
#define	d_lgamma_		__d_lgamma_
#define	d_lgamma_r_		__d_lgamma_r_
#define	d_log10_		__d_log10_
#define	d_log1p_		__d_log1p_
#define	d_log2_			__d_log2_
#define	d_log_			__d_log_
#define	d_logb_			__d_logb_
#define	d_max_normal_		__d_max_normal_
#define	d_max_subnormal_	__d_max_subnormal_
#define	d_min_normal_		__d_min_normal_
#define	d_min_subnormal_	__d_min_subnormal_
#define	d_mwcran_		__d_mwcran_
#define	d_mwcrans_		__d_mwcrans_
#define	d_nextafter_		__d_nextafter_
#define	d_pow_			__d_pow_
#define	d_quiet_nan_		__d_quiet_nan_
#define	d_remainder_		__d_remainder_
#define	d_rint_			__d_rint_
#define	d_scalb_		__d_scalb_
#define	d_scalbn_		__d_scalbn_
#define	d_set_addrans_		__d_set_addrans_
#define	d_shufrans_		__d_shufrans_
#define	d_signaling_nan_	__d_signaling_nan_
#define	d_significand_		__d_significand_
#define	d_sin_			__d_sin_
#define	d_sincos_		__d_sincos_
#define	d_sincosd_		__d_sincosd_
#define	d_sincosp_		__d_sincosp_
#define	d_sincospi_		__d_sincospi_
#define	d_sind_			__d_sind_
#define	d_sinh_			__d_sinh_
#define	d_sinp_			__d_sinp_
#define	d_sinpi_		__d_sinpi_
#define	d_sqrt_			__d_sqrt_
#define	d_tan_			__d_tan_
#define	d_tand_			__d_tand_
#define	d_tanh_			__d_tanh_
#define	d_tanp_			__d_tanp_
#define	d_tanpi_		__d_tanpi_
#define	d_y0_			__d_y0_
#define	d_y1_			__d_y1_
#define	d_yn_			__d_yn_
#define	drem			__drem
#define	erf			__erf
#define	erfc			__erfc
#define	erfcf			__erfcf
#define	erfcl			__erfcl
#define	erff			__erff
#define	erfl			__erfl
#define	exp			__exp
#define	exp10			__exp10
#define	exp10f			__exp10f
#define	exp10l			__exp10l
#define	exp2			__exp2
#define	exp2f			__exp2f
#define	exp2l			__exp2l
#define	expf			__expf
#define	expl			__expl
#define	expm1			__expm1
#define	expm1f			__expm1f
#define	expm1l			__expm1l
#define	fabs			__fabs
#define	fabsf			__fabsf
#define	fabsl			__fabsl
#define	fdim			__fdim				/* C99 */
#define	fdimf			__fdimf				/* C99 */
#define	fdiml			__fdiml				/* C99 */
#define	finitef			__finitef
#define	finitel			__finitel
#define	floor			__floor
#define	floorf			__floorf
#define	floorl			__floorl
#define	fma			__fma				/* C99 */
#define	fmaf			__fmaf				/* C99 */
#define	fmal			__fmal				/* C99 */
#define	fmax			__fmax				/* C99 */
#define	fmaxf			__fmaxf				/* C99 */
#define	fmaxl			__fmaxl				/* C99 */
#define	fmin			__fmin				/* C99 */
#define	fminf			__fminf				/* C99 */
#define	fminl			__fminl				/* C99 */
#define	fmod			__fmod
#define	fmodf			__fmodf
#define	fmodl			__fmodl
#define	fp_class		__fp_class
#define	fp_classf		__fp_classf
#define	fp_classl		__fp_classl
#define	frexp			__frexp				/* S10 */
#define	frexpf			__frexpf			/* S10 */
#define	frexpl			__frexpl			/* S10 */
#define	gamma			__gamma
#define	gamma_r			__gamma_r
#define	gammaf			__gammaf
#define	gammaf_r		__gammaf_r
#define	gammal			__gammal
#define	gammal_r		__gammal_r
#define	gradual_underflow_	__gradual_underflow_
#define	hypot			__hypot
#define	hypotf			__hypotf
#define	hypotl			__hypotl
#define	i_addran_		__i_addran_
#define	i_addrans_		__i_addrans_
#define	i_get_addrans_		__i_get_addrans_
#define	i_get_lcrans_		__i_get_lcrans_
#define	i_get_mwcrans_		__i_get_mwcrans_
#define	i_init_addrans_		__i_init_addrans_
#define	i_init_lcrans_		__i_init_lcrans_
#define	i_init_mwcrans_		__i_init_mwcrans_
#define	i_lcran_		__i_lcran_
#define	i_lcrans_		__i_lcrans_
#define	i_llmwcran_		__i_llmwcran_
#define	i_llmwcrans_		__i_llmwcrans_
#define	i_mwcran_		__i_mwcran_
#define	i_mwcrans_		__i_mwcrans_
#define	i_set_addrans_		__i_set_addrans_
#define	i_set_lcrans_		__i_set_lcrans_
#define	i_set_mwcrans_		__i_set_mwcrans_
#define	i_shufrans_		__i_shufrans_
#define	id_finite_		__id_finite_
#define	id_fp_class_		__id_fp_class_
#define	id_ilogb_		__id_ilogb_
#define	id_irint_		__id_irint_
#define	id_isinf_		__id_isinf_
#define	id_isnan_		__id_isnan_
#define	id_isnormal_		__id_isnormal_
#define	id_issubnormal_		__id_issubnormal_
#define	id_iszero_		__id_iszero_
#define	id_nint_		__id_nint_
#define	id_signbit_		__id_signbit_
#define	ieee_flags		__ieee_flags
#define	ieee_flags_		__ieee_flags_
#define	ieee_handler		__ieee_handler
#define	ieee_handler_		__ieee_handler_
#define	ieee_handlers		__ieee_handlers
#define	ieee_retrospective	__ieee_retrospective
#define	ieee_retrospective_	__ieee_retrospective_
#define	ilogb			__ilogb
#define	ilogbf			__ilogbf
#define	ilogbl			__ilogbl
#define	infinity		__infinity
#define	infinityf		__infinityf
#define	infinityl		__infinityl
#define	iq_finite_		__iq_finite_
#define	iq_fp_class_		__iq_fp_class_
#define	iq_ilogb_		__iq_ilogb_
#define	iq_isinf_		__iq_isinf_
#define	iq_isnan_		__iq_isnan_
#define	iq_isnormal_		__iq_isnormal_
#define	iq_issubnormal_		__iq_issubnormal_
#define	iq_iszero_		__iq_iszero_
#define	iq_signbit_		__iq_signbit_
#define	ir_finite_		__ir_finite_
#define	ir_fp_class_		__ir_fp_class_
#define	ir_ilogb_		__ir_ilogb_
#define	ir_irint_		__ir_irint_
#define	ir_isinf_		__ir_isinf_
#define	ir_isnan_		__ir_isnan_
#define	ir_isnormal_		__ir_isnormal_
#define	ir_issubnormal_		__ir_issubnormal_
#define	ir_iszero_		__ir_iszero_
#define	ir_nint_		__ir_nint_
#define	ir_signbit_		__ir_signbit_
#define	irint			__irint
#define	irintf			__irintf
#define	irintl			__irintl
#define	isinf			__isinf
#define	isinff			__isinff
#define	isinfl			__isinfl
#define	isnan			__isnan
#define	isnanf			__isnanf
#define	isnanl			__isnanl
#define	isnormal		__isnormal
#define	isnormalf		__isnormalf
#define	isnormall		__isnormall
#define	issubnormal		__issubnormal
#define	issubnormalf		__issubnormalf
#define	issubnormall		__issubnormall
#define	iszero			__iszero
#define	iszerof			__iszerof
#define	iszerol			__iszerol
#define	j0			__j0
#define	j0f			__j0f
#define	j0l			__j0l
#define	j1			__j1
#define	j1f			__j1f
#define	j1l			__j1l
#define	jn			__jn
#define	jnf			__jnf
#define	jnl			__jnl
#define	ldexp			__ldexp				/* S10 */
#define	ldexpf			__ldexpf			/* S10 */
#define	ldexpl			__ldexpl			/* S10 */
#define	lgamma			__lgamma
#define	lgamma_r		__lgamma_r
#define	lgammaf			__lgammaf
#define	lgammaf_r		__lgammaf_r
#define	lgammal			__lgammal
#define	lgammal_r		__lgammal_r
#define	llrint			__llrint			/* C99 */
#define	llrintf			__llrintf			/* C99 */
#define	llrintl			__llrintl			/* C99 */
#define	llround			__llround			/* C99 */
#define	llroundf		__llroundf			/* C99 */
#define	llroundl		__llroundl			/* C99 */
#define	lrint			__lrint				/* C99 */
#define	lrintf			__lrintf			/* C99 */
#define	lrintl			__lrintl			/* C99 */
#define	lround			__lround			/* C99 */
#define	lroundf			__lroundf			/* C99 */
#define	lroundl			__lroundl			/* C99 */
#define	log			__log
#define	log10			__log10
#define	log10f			__log10f
#define	log10l			__log10l
#define	log1p			__log1p
#define	log1pf			__log1pf
#define	log1pl			__log1pl
#define	log2			__log2
#define	log2f			__log2f
#define	log2l			__log2l
#define	logb			__logb
#define	logbf			__logbf
#define	logbl			__logbl
#define	logf			__logf
#define	logl			__logl
#define	max_normal		__max_normal
#define	max_normalf		__max_normalf
#define	max_normall		__max_normall
#define	max_subnormal		__max_subnormal
#define	max_subnormalf		__max_subnormalf
#define	max_subnormall		__max_subnormall
#define	min_normal		__min_normal
#define	min_normalf		__min_normalf
#define	min_normall		__min_normall
#define	min_subnormal		__min_subnormal
#define	min_subnormalf		__min_subnormalf
#define	min_subnormall		__min_subnormall
#define	modf			__modf				/* S10 */
#define	modff			__modff				/* S10 */
#define	modfl			__modfl				/* S10 */
#define	nan			__nan				/* C99 */
#define	nanf			__nanf				/* C99 */
#define	nanl			__nanl				/* C99 */
#define	nearbyint		__nearbyint			/* C99 */
#define	nearbyintf		__nearbyintf			/* C99 */
#define	nearbyintl		__nearbyintl			/* C99 */
#define	nextafter		__nextafter
#define	nextafterf		__nextafterf
#define	nextafterl		__nextafterl
#define	nexttoward		__nexttoward			/* C99 */
#define	nexttowardf		__nexttowardf			/* C99 */
#define	nexttowardl		__nexttowardl			/* C99 */
#define	nint			__nint
#define	nintf			__nintf
#define	nintl			__nintl
#define	nonstandard_arithmetic	__nonstandard_arithmetic
#define	nonstandard_arithmetic_	__nonstandard_arithmetic_
#define	pow			__pow
#define	pow_di			__pow_di
#define	pow_li			__pow_li
#define	pow_ri			__pow_ri
#define	powf			__powf
#define	powl			__powl
#define	q_copysign_		__q_copysign_
#define	q_fabs_			__q_fabs_
#define	q_fmod_			__q_fmod_
#define	q_infinity_		__q_infinity_
#define	q_max_normal_		__q_max_normal_
#define	q_max_subnormal_	__q_max_subnormal_
#define	q_min_normal_		__q_min_normal_
#define	q_min_subnormal_	__q_min_subnormal_
#define	q_nextafter_		__q_nextafter_
#define	q_quiet_nan_		__q_quiet_nan_
#define	q_remainder_		__q_remainder_
#define	q_scalbn_		__q_scalbn_
#define	q_signaling_nan_	__q_signaling_nan_
#define	quiet_nan		__quiet_nan
#define	quiet_nanf		__quiet_nanf
#define	quiet_nanl		__quiet_nanl
#define	r_acos_			__r_acos_
#define	r_acosd_		__r_acosd_
#define	r_acosh_		__r_acosh_
#define	r_acosp_		__r_acosp_
#define	r_acospi_		__r_acospi_
#define	r_addran_		__r_addran_
#define	r_addrans_		__r_addrans_
#define	r_aint_			__r_aint_
#define	r_anint_		__r_anint_
#define	r_annuity_		__r_annuity_
#define	r_asin_			__r_asin_
#define	r_asind_		__r_asind_
#define	r_asinh_		__r_asinh_
#define	r_asinp_		__r_asinp_
#define	r_asinpi_		__r_asinpi_
#define	r_atan2_		__r_atan2_
#define	r_atan2d_		__r_atan2d_
#define	r_atan2pi_		__r_atan2pi_
#define	r_atan_			__r_atan_
#define	r_atand_		__r_atand_
#define	r_atanh_		__r_atanh_
#define	r_atanp_		__r_atanp_
#define	r_atanpi_		__r_atanpi_
#define	r_cbrt_			__r_cbrt_
#define	r_ceil_			__r_ceil_
#define	r_compound_		__r_compound_
#define	r_copysign_		__r_copysign_
#define	r_cos_			__r_cos_
#define	r_cosd_			__r_cosd_
#define	r_cosh_			__r_cosh_
#define	r_cosp_			__r_cosp_
#define	r_cospi_		__r_cospi_
#define	r_erf_			__r_erf_
#define	r_erfc_			__r_erfc_
#define	r_exp10_		__r_exp10_
#define	r_exp2_			__r_exp2_
#define	r_exp_			__r_exp_
#define	r_expm1_		__r_expm1_
#define	r_fabs_			__r_fabs_
#define	r_floor_		__r_floor_
#define	r_fmod_			__r_fmod_
#define	r_get_addrans_		__r_get_addrans_
#define	r_hypot_		__r_hypot_
#define	r_infinity_		__r_infinity_
#define	r_init_addrans_		__r_init_addrans_
#define	r_j0_			__r_j0_
#define	r_j1_			__r_j1_
#define	r_jn_			__r_jn_
#define	r_lcran_		__r_lcran_
#define	r_lcrans_		__r_lcrans_
#define	r_lgamma_		__r_lgamma_
#define	r_lgamma_r_		__r_lgamma_r_
#define	r_log10_		__r_log10_
#define	r_log1p_		__r_log1p_
#define	r_log2_			__r_log2_
#define	r_log_			__r_log_
#define	r_logb_			__r_logb_
#define	r_max_normal_		__r_max_normal_
#define	r_max_subnormal_	__r_max_subnormal_
#define	r_min_normal_		__r_min_normal_
#define	r_min_subnormal_	__r_min_subnormal_
#define	r_mwcran_		__r_mwcran_
#define	r_mwcrans_		__r_mwcrans_
#define	r_nextafter_		__r_nextafter_
#define	r_pow_			__r_pow_
#define	r_quiet_nan_		__r_quiet_nan_
#define	r_remainder_		__r_remainder_
#define	r_rint_			__r_rint_
#define	r_scalb_		__r_scalb_
#define	r_scalbn_		__r_scalbn_
#define	r_set_addrans_		__r_set_addrans_
#define	r_shufrans_		__r_shufrans_
#define	r_signaling_nan_	__r_signaling_nan_
#define	r_significand_		__r_significand_
#define	r_sin_			__r_sin_
#define	r_sincos_		__r_sincos_
#define	r_sincosd_		__r_sincosd_
#define	r_sincosp_		__r_sincosp_
#define	r_sincospi_		__r_sincospi_
#define	r_sind_			__r_sind_
#define	r_sinh_			__r_sinh_
#define	r_sinp_			__r_sinp_
#define	r_sinpi_		__r_sinpi_
#define	r_sqrt_			__r_sqrt_
#define	r_tan_			__r_tan_
#define	r_tand_			__r_tand_
#define	r_tanh_			__r_tanh_
#define	r_tanp_			__r_tanp_
#define	r_tanpi_		__r_tanpi_
#define	r_y0_			__r_y0_
#define	r_y1_			__r_y1_
#define	r_yn_			__r_yn_
#define	remainder		__remainder
#define	remainderf		__remainderf
#define	remainderl		__remainderl
#define	remquo			__remquo			/* C99 */
#define	remquof			__remquof			/* C99 */
#define	remquol			__remquol			/* C99 */
#define	rint			__rint
#define	rintf			__rintf
#define	rintl			__rintl
#define	round			__round				/* C99 */
#define	roundf			__roundf			/* C99 */
#define	roundl			__roundl			/* C99 */
#define	scalb			__scalb
#define	scalbf			__scalbf
#define	scalbl			__scalbl
#define	scalbln			__scalbln			/* C99 */
#define	scalblnf		__scalblnf			/* C99 */
#define	scalblnl		__scalblnl			/* C99 */
#define	scalbn			__scalbn
#define	scalbnf			__scalbnf
#define	scalbnl			__scalbnl
#define	sigfpe			__sigfpe
#define	sigfpe_			__sigfpe_
#define	signaling_nan		__signaling_nan
#define	signaling_nanf		__signaling_nanf
#define	signaling_nanl		__signaling_nanl
#define	signbit			__signbit
#define	signbitf		__signbitf
#define	signbitl		__signbitl
#define	signgam			__signgam
#define	signgamf		__signgamf
#define	signgaml		__signgaml
#define	significand		__significand
#define	significandf		__significandf
#define	significandl		__significandl
#define	sin			__sin
#define	sincos			__sincos
#define	sincosd			__sincosd
#define	sincosdf		__sincosdf
#define	sincosdl		__sincosdl
#define	sincosf			__sincosf
#define	sincosl			__sincosl
#define	sincosp			__sincosp
#define	sincospf		__sincospf
#define	sincospi		__sincospi
#define	sincospif		__sincospif
#define	sincospil		__sincospil
#define	sincospl		__sincospl
#define	sind			__sind
#define	sindf			__sindf
#define	sindl			__sindl
#define	sinf			__sinf
#define	sinh			__sinh
#define	sinhf			__sinhf
#define	sinhl			__sinhl
#define	sinl			__sinl
#define	sinp			__sinp
#define	sinpf			__sinpf
#define	sinpi			__sinpi
#define	sinpif			__sinpif
#define	sinpil			__sinpil
#define	sinpl			__sinpl
#define	smwcran_		__smwcran_
#define	sqrt			__sqrt
#define	sqrtf			__sqrtf
#define	sqrtl			__sqrtl
#define	standard_arithmetic	__standard_arithmetic
#define	standard_arithmetic_	__standard_arithmetic_
#define	tan			__tan
#define	tand			__tand
#define	tandf			__tandf
#define	tandl			__tandl
#define	tanf			__tanf
#define	tanh			__tanh
#define	tanhf			__tanhf
#define	tanhl			__tanhl
#define	tanl			__tanl
#define	tanp			__tanp
#define	tanpf			__tanpf
#define	tanpi			__tanpi
#define	tanpif			__tanpif
#define	tanpil			__tanpil
#define	tanpl			__tanpl
#define	tgamma			__tgamma			/* C99 */
#define	tgammaf			__tgammaf			/* C99 */
#define	tgammal			__tgammal			/* C99 */
#define	trunc			__trunc				/* C99 */
#define	truncf			__truncf			/* C99 */
#define	truncl			__truncl			/* C99 */
#define	u_addrans_		__u_addrans_
#define	u_lcrans_		__u_lcrans_
#define	u_llmwcran_		__u_llmwcran_
#define	u_llmwcrans_		__u_llmwcrans_
#define	u_mwcran_		__u_mwcran_
#define	u_mwcrans_		__u_mwcrans_
#define	u_shufrans_		__u_shufrans_
#define	y0			__y0
#define	y0f			__y0f
#define	y0l			__y0l
#define	y1			__y1
#define	y1f			__y1f
#define	y1l			__y1l
#define	yn			__yn
#define	ynf			__ynf
#define	ynl			__ynl

/*
 *  these are libdl entry points
 */
#define	dlclose			_dlclose
#define	dlopen			_dlopen
#define	dlsym			_dlsym

/*
 *  these are libc entry points
 */
#define	finite			_finite
#define	fpclass			_fpclass
#define	isnand			_isnand
#define	sigaction		_sigaction
#define	sigemptyset		_sigemptyset
#define	unordered		_unordered
#define	write			_write
#ifdef _REENTRANT
#define	mutex_lock		_mutex_lock
#define	mutex_unlock		_mutex_unlock
#define	thr_getspecific		_thr_getspecific
#define	thr_keycreate		_thr_keycreate
#define	thr_main		_thr_main
#define	thr_setspecific		_thr_setspecific
#endif

#endif /* defined(ELFOBJ) && !defined(lint) */

#endif	/* _LIBM_SYNONYMS_H */
