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

/*
 * Many symbols used to be namespaced with __libm to prevent collisions.  All
 * but these two were otherwise scoped local and directly bound, so that
 * collision could not occur.
 *
 * For reasons unknown, these two are global (but private).
 */
#define	__rem_pio2	__libm__rem_pio2
#define	__rem_pio2m	__libm__rem_pio2m

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
