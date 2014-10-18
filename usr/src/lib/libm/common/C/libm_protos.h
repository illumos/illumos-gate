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

#ifndef _C_LIBM_PROTOS_H
#define	_C_LIBM_PROTOS_H

#ifdef LIBMOPT_BUILD
#define	_TBL_cos	__libmopt_TBL_cos
#define	_TBL_exp2_512	__libmopt_TBL_exp2_512
#define	_TBL_ipio2_inf	__libmopt_TBL_ipio2_inf
#define	_TBL_jlog_n1	__libmopt_TBL_jlog_n1
#define	_TBL_jlog_n2	__libmopt_TBL_jlog_n2
#define	_TBL_jlog_p1	__libmopt_TBL_jlog_p1
#define	_TBL_jlog_p2	__libmopt_TBL_jlog_p2
#define	_TBL_log10	__libmopt_TBL_log10
#define	_TBL_log2_14	__libmopt_TBL_log2_14
#define	_TBL_log2_9	__libmopt_TBL_log2_9
#define	_TBL_sin	__libmopt_TBL_sin
#define	_TBL_sincosx	__libmopt_TBL_sincosx
#define	_TBL_xexp	__libmopt_TBL_xexp
#define	_TBL_xlog	__libmopt_TBL_xlog
#define	__k_cos_	__libmopt__k_cos_
#define	__k_sin_	__libmopt__k_sin_
#define	__k_sincos_	__libmopt__k_sincos_
#define	__reduction	__libmopt__reduction
#define	__rem_pio2	__libmopt__rem_pio2
#define	__rem_pio2m	__libmopt__rem_pio2m
#else	/* defined(LIBMOPT_BUILD) */
#ifdef LIBM_BUILD
#define	_SVID_libm_err	__libm_SVID_libm_err	/* not used by -lsunmath */
#define	_TBL_atan	__libm_TBL_atan
#define	_TBL_atan1	__libm_TBL_atan1
#define	_TBL_atan_hi	__libm_TBL_atan_hi	/* not used by -lsunmath */
#define	_TBL_atan_lo	__libm_TBL_atan_lo	/* not used by -lsunmath */
#define	_TBL_exp2_hi	__libm_TBL_exp2_hi	/* not used by -lsunmath */
#define	_TBL_exp2_lo	__libm_TBL_exp2_lo	/* not used by -lsunmath */
#define	_TBL_ipio2_inf	__libm_TBL_ipio2_inf
#define	_TBL_log	__libm_TBL_log
#define	_TBL_log2_hi	__libm_TBL_log2_hi	/* not used by -lsunmath */
#define	_TBL_log2_lo	__libm_TBL_log2_lo	/* not used by -lsunmath */
#define	_TBL_log_hi	__libm_TBL_log_hi	/* not used by -lsunmath */
#define	_TBL_log_lo	__libm_TBL_log_lo	/* not used by -lsunmath */
#define	_TBL_sincos	__libm_TBL_sincos
#define	_TBL_sincosx	__libm_TBL_sincosx
#define	_TBL_tan_hi	__libm_TBL_tan_hi	/* not used by -lsunmath */
#define	_TBL_tan_lo	__libm_TBL_tan_lo	/* not used by -lsunmath */
#define	__k_cexp	__libm__k_cexp		/* C99 libm */
#define	__k_cexpl	__libm__k_cexpl		/* C99 libm */
#define	__k_clog_r	__libm__k_clog_r	/* C99 libm */
#define	__k_clog_rl	__libm__k_clog_rl	/* C99 libm */
#define	__k_atan2	__libm__k_atan2		/* C99 libm */
#define	__k_atan2l	__libm__k_atan2l	/* C99 libm */
#define	__k_cos		__libm__k_cos
#define	__k_lgamma	__libm__k_lgamma
#define	__k_sin		__libm__k_sin
#define	__k_sincos	__libm__k_sincos
#define	__k_tan		__libm__k_tan
#define	__reduction	__libm__reduction	/* i386 only */
#define	__rem_pio2	__libm__rem_pio2
#define	__rem_pio2m	__libm__rem_pio2m
#define	__k_cosf	__libm__k_cosf		/* C99 libm */
#define	__k_cosl	__libm__k_cosl		/* C99 libm */
#define	__k_lgammal	__libm__k_lgammal	/* C99 libm */
#define	__k_sincosf	__libm__k_sincosf	/* C99 libm */
#define	__k_sincosl	__libm__k_sincosl	/* C99 libm */
#define	__k_sinf	__libm__k_sinf		/* C99 libm */
#define	__k_sinl	__libm__k_sinl		/* C99 libm */
#define	__k_tanf	__libm__k_tanf		/* C99 libm */
#define	__k_tanl	__libm__k_tanl		/* C99 libm */
#define	__poly_libmq	__libm__poly_libmq	/* C99 libm */
#define	__rem_pio2l	__libm__rem_pio2l	/* C99 libm */
#define	_TBL_atanl_hi	__libm_TBL_atanl_hi	/* C99 libm */
#define	_TBL_atanl_lo	__libm_TBL_atanl_lo	/* C99 libm */
#define	_TBL_cosl_hi	__libm_TBL_cosl_hi	/* C99 libm */
#define	_TBL_cosl_lo	__libm_TBL_cosl_lo	/* C99 libm */
#define	_TBL_expl_hi	__libm_TBL_expl_hi	/* C99 libm */
#define	_TBL_expl_lo	__libm_TBL_expl_lo	/* C99 libm */
#define	_TBL_expm1l	__libm_TBL_expm1l	/* C99 libm */
#define	_TBL_expm1lx	__libm_TBL_expm1lx	/* C99 libm */
#define	_TBL_ipio2l_inf	__libm_TBL_ipio2l_inf	/* C99 libm */
#define	_TBL_logl_hi	__libm_TBL_logl_hi	/* C99 libm */
#define	_TBL_logl_lo	__libm_TBL_logl_lo	/* C99 libm */
#define	_TBL_r_atan_hi	__libm_TBL_r_atan_hi	/* C99 libm */
#define	_TBL_r_atan_lo	__libm_TBL_r_atan_lo	/* C99 libm */
#define	_TBL_sinl_hi	__libm_TBL_sinl_hi	/* C99 libm */
#define	_TBL_sinl_lo	__libm_TBL_sinl_lo	/* C99 libm */
#define	_TBL_tanl_hi	__libm_TBL_tanl_hi	/* C99 libm */
#define	_TBL_tanl_lo	__libm_TBL_tanl_lo	/* C99 libm */
#endif	/* defined(LIBM_BUILD) */
#endif	/* defined(LIBMOPT_BUILD) */

#ifndef _ASM
#ifdef __STDC__
#define	__P(p)	p
#else
#define	__P(p)	()
#endif

#include <sys/ieeefp.h>

extern double _SVID_libm_err __P((double, double, int));
extern double __k_cos __P((double, double));
extern double __k_cos_ __P((double *));
extern double __k_lgamma __P((double, int *));
extern double __k_sin __P((double, double));
extern double __k_sin_ __P((double *));
extern double __k_sincos __P((double, double, double *));
extern double __k_sincos_ __P((double *, double *));
extern double __k_tan __P((double, double, int));
extern double __k_cexp __P((double, int *));
extern long double __k_cexpl __P((long double, int *));
extern double __k_clog_r __P((double, double, double *));
extern long double __k_clog_rl __P((long double, long double, long double *));
extern double __k_atan2 __P((double, double, double *));
extern long double __k_atan2l __P((long double, long double, long double *));
extern int __rem_pio2 __P((double, double *));
extern int __rem_pio2m __P((double *, double *, int, int, int, const int *));

/*
 * entry points that are in-lined
 */
extern double copysign __P((double, double));
extern int finite __P((double));
extern enum fp_class_type fp_class __P((double));
extern double infinity __P((void));
extern int isinf __P((double));
extern int signbit __P((double));

/*
 * new C99 entry points
 */
extern double fdim __P((double, double));
extern double fma __P((double, double, double));
extern double fmax __P((double, double));
extern double fmin __P((double, double));
extern double frexp __P((double, int *));
extern double ldexp __P((double, int));
extern double modf __P((double, double *));
extern double nan __P((const char *));
extern double nearbyint __P((double));
extern double nexttoward __P((double, long double));
extern double remquo __P((double, double, int *));
extern double round __P((double));
extern double scalbln __P((double, long int));
extern double tgamma __P((double));
extern double trunc __P((double));
extern float fdimf __P((float, float));
extern float fmaf __P((float, float, float));
extern float fmaxf __P((float, float));
extern float fminf __P((float, float));
extern float frexpf __P((float, int *));
extern float ldexpf __P((float, int));
extern float modff __P((float, float *));
extern float nanf __P((const char *));
extern float nearbyintf __P((float));
extern float nextafterf __P((float, float));
extern float nexttowardf __P((float, long double));
extern float remquof __P((float, float, int *));
extern float roundf __P((float));
extern float scalblnf __P((float, long int));
extern float tgammaf __P((float));
extern float truncf __P((float));
extern long double frexpl(long double, int *);
extern long double fdiml __P((long double, long double));
extern long double fmal __P((long double, long double, long double));
extern long double fmaxl __P((long double, long double));
extern long double fminl __P((long double, long double));
extern long double ldexpl __P((long double, int));
extern long double modfl __P((long double, long double *));
extern long double nanl __P((const char *));
extern long double nearbyintl __P((long double));
extern long double nextafterl __P((long double, long double));
extern long double nexttowardl __P((long double, long double));
extern long double remquol __P((long double, long double, int *));
extern long double roundl __P((long double));
extern long double scalblnl __P((long double, long int));
extern long double tgammal __P((long double));
extern long double truncl __P((long double));
extern long int lrint __P((double));
extern long int lrintf __P((float));
extern long int lrintl __P((long double));
extern long int lround __P((double));
extern long int lroundf __P((float));
extern long int lroundl __P((long double));
extern long long int llrint __P((double));
extern long long int llrintf __P((float));
extern long long int llrintl __P((long double));
extern long long int llround __P((double));
extern long long int llroundf __P((float));
extern long long int llroundl __P((long double));
#endif	/* _ASM */

#endif	/* _C_LIBM_PROTOS_H */
