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

#ifndef	_LD_LONGDOUBLE_H
#define	_LD_LONGDOUBLE_H
#include <sys/ieeefp.h>

extern long double __k_cosl(long double, long double);
extern long double __k_lgammal(long double, int *);
extern long double __k_sincosl(long double, long double, long double *);
extern long double __k_sinl(long double, long double);
extern long double __k_tanl(long double, long double, int);
extern long double __poly_libmq(long double, int, long double *);
extern int __rem_pio2l(long double, long double *);

extern long double acosdl(long double);
extern long double acoshl(long double);
extern long double acosl(long double);
extern long double acospil(long double);
extern long double acospl(long double);
extern long double aintl(long double);
extern long double anintl(long double);
extern long double annuityl(long double, long double);
extern long double asindl(long double);
extern long double asinhl(long double);
extern long double asinl(long double);
extern long double asinpil(long double);
extern long double asinpl(long double);
extern long double atan2dl(long double, long double);
extern long double atan2l(long double, long double);
extern long double atan2pil(long double, long double);
extern long double atandl(long double);
extern long double atanhl(long double);
extern long double atanl(long double);
extern long double atanpil(long double);
extern long double atanpl(long double);
extern long double cbrtl(long double);
extern long double ceill(long double);
extern long double compoundl(long double, long double);
extern long double copysignl(long double, long double);
extern long double cosdl(long double);
extern long double coshl(long double);
extern long double cosl(long double);
extern long double cospil(long double);
extern long double cospl(long double);
extern long double erfcl(long double);
extern long double erfl(long double);
extern long double exp10l(long double);
extern long double exp2l(long double);
extern long double expl(long double);
extern long double expm1l(long double);
extern long double fabsl(long double);
extern int finitel(long double);
extern long double floorl(long double);
extern long double fmodl(long double, long double);
extern enum fp_class_type fp_classl(long double);
extern long double gammal(long double);
extern long double hypotl(long double, long double);
extern int ilogbl(long double);
extern long double infinityl(void);
extern int irintl(long double);
extern int isinfl(long double);
extern int isnanl(long double);
extern int isnormall(long double);
extern int issubnormall(long double);
extern int iszerol(long double);
extern long double j0l(long double);
extern long double j1l(long double);
extern long double jnl(int, long double);
extern long double lgammal(long double);
extern long double log10l(long double);
extern long double log1pl(long double);
extern long double log2l(long double);
extern long double logbl(long double);
extern long double logl(long double);
extern long double max_normall(void);
extern long double max_subnormall(void);
extern long double min_normall(void);
extern long double min_subnormall(void);
extern long double nextafterl(long double, long double);
extern int nintl(long double);
extern long double pow_li(long double *, int *);
extern long double powl(long double, long double);
extern long double quiet_nanl(long);
extern long double remainderl(long double, long double);
extern long double rintl(long double);
extern long double scalbl(long double, long double);
extern long double scalbnl(long double, int);
extern long double signaling_nanl(long);
extern int signbitl(long double);
extern long double significandl(long double);
extern void sincosdl(long double, long double *, long double *);
extern void sincosl(long double, long double *, long double *);
extern void sincospil(long double, long double *, long double *);
extern void sincospl(long double, long double *, long double *);
extern long double sindl(long double);
extern long double sinhl(long double);
extern long double sinl(long double);
extern long double sinpil(long double);
extern long double sinpl(long double);
extern long double sqrtl(long double);
extern long double tandl(long double);
extern long double tanhl(long double);
extern long double tanl(long double);
extern long double tanpil(long double);
extern long double tanpl(long double);
extern long double y0l(long double);
extern long double y1l(long double);
extern long double ynl(int, long double);

extern long double q_copysign_(long double *, long double *);
extern long double q_fabs_(long double *);
extern int iq_finite_(long double *);
extern long double q_fmod_(long double *, long double *);
extern enum fp_class_type iq_fp_class_(long double *);
extern int iq_ilogb_(long double *);
extern long double q_infinity_(void);
extern int iq_isinf_(long double *);
extern int iq_isnan_(long double *);
extern int iq_isnormal_(long double *);
extern int iq_issubnormal_(long double *);
extern int iq_iszero_(long double *);
extern long double q_max_normal_(void);
extern long double q_max_subnormal_(void);
extern long double q_min_normal_(void);
extern long double q_min_subnormal_(void);
extern long double q_nextafter_(long double *, long double *);
extern long double q_quiet_nan_(long *);
extern long double q_remainder_(long double *, long double *);
extern long double q_scalbn_(long double *, int *);
extern long double q_signaling_nan_(long *);
extern int iq_signbit_(long double *);

#endif	/* _LD_LONGDOUBLE_H */
