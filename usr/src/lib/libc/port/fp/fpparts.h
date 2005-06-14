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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Macros to pull apart parts of single and  double precision
 * floating point numbers in IEEE format
 * Be sure to include /usr/include/values.h before including
 * this file to get the required definition of _IEEE
 */

#if _IEEE
#if defined(__sparc)
/* byte order with high order bits at lowest address */

/* double precision */
typedef  union {
	struct {
		unsigned  sign	:1;
		unsigned  exp	:11;
		unsigned  hi	:20;
		unsigned  lo	:32;
	} fparts;
	struct {
		unsigned  sign	:1;
		unsigned  exp	:11;
		unsigned  qnan_bit	:1;
		unsigned  hi	:19;
		unsigned  lo	:32;
	} nparts;
	struct {
		unsigned hi;
		unsigned lo;
	} fwords;
	double	d;
} _dval;

/* single precision */
typedef  union {
	struct {
		unsigned sign	:1;
		unsigned exp	:8;
		unsigned fract	:23;
	} fparts;
	struct {
		unsigned sign	:1;
		unsigned exp	:8;
		unsigned qnan_bit	:1;
		unsigned fract	:22;
	} nparts;
	unsigned long	fword;
	float	f;
} _fval;


#elif defined(__i386) || defined(__amd64)
/* byte order with low order bits at lowest address */

/* double precision */
typedef  union {
	struct {
		unsigned  lo	:32;
		unsigned  hi	:20;
		unsigned  exp	:11;
		unsigned  sign	:1;
	} fparts;
	struct {
		unsigned  lo	:32;
		unsigned  hi	:19;
		unsigned  qnan_bit	:1;
		unsigned  exp	:11;
		unsigned  sign	:1;
	} nparts;
	struct {
		unsigned  lo	:32;
		unsigned  hi	:32;
	} fwords;
	double	d;
} _dval;

/* single precision */
typedef  union {
	struct {
		unsigned fract	:23;
		unsigned exp	:8;
		unsigned sign	:1;
	} fparts;
	struct {
		unsigned fract	:22;
		unsigned qnan_bit	:1;
		unsigned exp	:8;
		unsigned sign	:1;
	} nparts;
	unsigned long	fword;
	float	f;
} _fval;
#endif

/* parts of a double precision floating point number */
#define	SIGNBIT(X)	(((_dval *)&(X))->fparts.sign)
#define	EXPONENT(X)	(((_dval *)&(X))->fparts.exp)

#define	HIFRACTION(X)	(((_dval *)&(X))->fparts.hi)
#define	LOFRACTION(X)	(((_dval *)&(X))->fparts.lo)
#define	QNANBIT(X)	(((_dval *)&(X))->nparts.qnan_bit)
#define	HIWORD(X)	(((_dval *)&(X))->fwords.hi)
#define	LOWORD(X)	(((_dval *)&(X))->fwords.lo)

#define	MAXEXP	0x7ff /* maximum exponent of double */
#define	ISMAXEXP(X)	((EXPONENT(X)) == MAXEXP)

/* macros used to create quiet NaNs as return values */
#define	SETQNAN(X)	((((_dval *)&(X))->nparts.qnan_bit) = 0x1)
#define	HIQNAN(X)	((HIWORD(X)) = 0x7ff80000)
#define	LOQNAN(X)	((((_dval *)&(X))->fwords.lo) = 0x0)

/* macros used to extract parts of single precision values */
#define	FSIGNBIT(X)	(((_fval *)&(X))->fparts.sign)
#define	FEXPONENT(X)	(((_fval *)&(X))->fparts.exp)
#define	FFRACTION(X)	(((_fval *)&(X))->fparts.fract)

#define	FWORD(X)	(((_fval *)&(X))->fword)
#define	FQNANBIT(X)	(((_fval *)&(X))->nparts.qnan_bit)
#define	MAXEXPF	255 /* maximum exponent of single */
#define	FISMAXEXP(X)	((FEXPONENT(X)) == MAXEXPF)

#endif  /* _IEEE */
