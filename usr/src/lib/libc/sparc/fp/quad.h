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
 * Copyright (c) 1994-1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _QUAD_H
#define	_QUAD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Common definitions for quadruple precision emulation routines
 * (SPARC only)
 */

/* macros to simplify dealing with the diferences between V8 and V9 */
#ifdef __sparcv9

#define	Z		(*pz)
#define	QUAD_RETURN(x)	return

#else

#define	Z		z
#define	QUAD_RETURN(x)	return (x)

#endif

/* fsr definitions */

/* current exception bits */
#define	FSR_NXC		0x1
#define	FSR_DZC		0x2
#define	FSR_UFC		0x4
#define	FSR_OFC		0x8
#define	FSR_NVC		0x10
#define	FSR_CEXC	0x1f	/* mask for all cexc bits */

/* accrued exception bits */
#define	FSR_NXA		0x20
#define	FSR_DZA		0x40
#define	FSR_UFA		0x80
#define	FSR_OFA		0x100
#define	FSR_NVA		0x200

/* trap enable bits */
#define	FSR_NXM		0x00800000
#define	FSR_DZM		0x01000000
#define	FSR_UFM		0x02000000
#define	FSR_OFM		0x04000000
#define	FSR_NVM		0x08000000

/* rounding directions (shifted) */
#define	FSR_RN		0
#define	FSR_RZ		1
#define	FSR_RP		2
#define	FSR_RM		3

/*
 * in struct longdouble, msw implicitly consists of
 *	unsigned short	sign:1;
 *	unsigned short	exponent:15;
 *	unsigned short	frac1:16;
 */

/* structure used to access words within a quad */
union longdouble {
	struct {
		unsigned int	msw;
		unsigned int	frac2;
		unsigned int	frac3;
		unsigned int	frac4;
	} l;
	long double	d;	/* unused; just guarantees correct alignment */
};

/* macros used internally for readability */
#define	QUAD_ISNAN(x) \
	(((x).l.msw & 0x7fff0000) == 0x7fff0000 && \
	(((x).l.msw & 0xffff) | (x).l.frac2 | (x).l.frac3 | (x).l.frac4))

#define	QUAD_ISZERO(x) \
	(!(((x).l.msw & 0x7fffffff) | (x).l.frac2 | (x).l.frac3 | (x).l.frac4))

/* structure used to access words within a double */
union xdouble {
	struct {
		unsigned int	hi;
		unsigned int	lo;
	} l;
	double			d;
};

/* relationships returned by _Q_cmp and _Q_cmpe */
enum fcc_type {
	fcc_equal	= 0,
	fcc_less	= 1,
	fcc_greater	= 2,
	fcc_unordered	= 3
};

/* internal routines */
extern void __quad_mag_add(const union longdouble *,
	const union longdouble *, union longdouble *, unsigned int *);
extern void __quad_mag_sub(const union longdouble *,
	const union longdouble *, union longdouble *, unsigned int *);

/* inline templates */
extern void __quad_getfsrp(unsigned int *);
extern void __quad_setfsrp(const unsigned int *);
extern double __quad_dp_sqrt(double *);
extern void __quad_faddq(const union longdouble *, const union longdouble *,
	union longdouble *);
extern void __quad_fsubq(const union longdouble *, const union longdouble *,
	union longdouble *);
extern void __quad_fmulq(const union longdouble *, const union longdouble *,
	union longdouble *);
extern void __quad_fdivq(const union longdouble *, const union longdouble *,
	union longdouble *);
extern void __quad_fsqrtq(const union longdouble *, union longdouble *);
extern void __quad_fcmpq(const union longdouble *, const union longdouble *,
	unsigned int *);
extern void __quad_fcmpeq(const union longdouble *, const union longdouble *,
	unsigned int *);
extern void __quad_fstoq(const float *, union longdouble *);
extern void __quad_fdtoq(const double *, union longdouble *);
extern void __quad_fqtoi(const union longdouble *, int *);
extern void __quad_fqtos(const union longdouble *, float *);
extern void __quad_fqtod(const union longdouble *, double *);
#ifdef __sparcv9
extern void __quad_fqtox(const union longdouble *, long *);
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _QUAD_H */
