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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_VALUES_H
#define	_VALUES_H

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These values work with any binary representation of integers
 * where the high-order bit contains the sign.
 */

/* a number used normally for size of a shift */
#define	BITSPERBYTE	8

#define	BITS(type)	(BITSPERBYTE * (long)sizeof (type))

/* short, regular and long ints with only the high-order bit turned on */
#define	HIBITS	((short)(1 << (BITS(short) - 1)))

#define	HIBITI	(1U << (BITS(int) - 1))
#define	HIBITL	(1UL << (BITS(long) - 1))

/* largest short, regular and long int */
#define	MAXSHORT	((short)~HIBITS)
#define	MAXINT		((int)(~HIBITI))
#define	MAXLONG		((long)(~HIBITL))

/*
 * various values that describe the binary floating-point representation
 * _EXPBASE	- the exponent base
 * DMAXEXP	- the maximum exponent of a double (as returned by frexp())
 * FMAXEXP	- the maximum exponent of a float  (as returned by frexp())
 * DMINEXP	- the minimum exponent of a double (as returned by frexp())
 * FMINEXP	- the minimum exponent of a float  (as returned by frexp())
 * MAXDOUBLE	- the largest double
 *			((_EXPBASE ** DMAXEXP) * (1 - (_EXPBASE ** -DSIGNIF)))
 * MAXFLOAT	- the largest float
 *			((_EXPBASE ** FMAXEXP) * (1 - (_EXPBASE ** -FSIGNIF)))
 * MINDOUBLE	- the smallest double (_EXPBASE ** (DMINEXP - 1))
 * MINFLOAT	- the smallest float (_EXPBASE ** (FMINEXP - 1))
 * DSIGNIF	- the number of significant bits in a double
 * FSIGNIF	- the number of significant bits in a float
 * DMAXPOWTWO	- the largest power of two exactly representable as a double
 * FMAXPOWTWO	- the largest power of two exactly representable as a float
 * _IEEE	- 1 if IEEE standard representation is used
 * _DEXPLEN	- the number of bits for the exponent of a double
 * _FEXPLEN	- the number of bits for the exponent of a float
 * _HIDDENBIT	- 1 if high-significance bit of mantissa is implicit
 * LN_MAXDOUBLE	- the natural log of the largest double  -- log(MAXDOUBLE)
 * LN_MINDOUBLE	- the natural log of the smallest double -- log(MINDOUBLE)
 * LN_MAXFLOAT	- the natural log of the largest float  -- log(MAXFLOAT)
 * LN_MINFLOAT	- the natural log of the smallest float -- log(MINFLOAT)
 */

/*
 * Currently, only IEEE-754 format is supported.
 */
#if defined(_IEEE_754)
#define	MAXDOUBLE	1.79769313486231570e+308
#define	MAXFLOAT	((float)3.40282346638528860e+38)
#define	MINDOUBLE	4.94065645841246544e-324
#define	MINFLOAT	((float)1.40129846432481707e-45)
#define	_IEEE		1
#define	_DEXPLEN	11
#define	_HIDDENBIT	1
#define	_LENBASE	1
#define	DMINEXP	(-(DMAXEXP + DSIGNIF - _HIDDENBIT - 3))
#define	FMINEXP	(-(FMAXEXP + FSIGNIF - _HIDDENBIT - 3))
#else
/* #error is strictly ansi-C, but works as well as anything for K&R systems. */
#error "ISA not supported"
#endif

#define	_EXPBASE	(1 << _LENBASE)
#define	_FEXPLEN	8
#define	DSIGNIF	(BITS(double) - _DEXPLEN + _HIDDENBIT - 1)
#define	FSIGNIF	(BITS(float)  - _FEXPLEN + _HIDDENBIT - 1)
#define	DMAXPOWTWO	((double)(1 << (BITS(int) - 2)) * \
				(1 << (DSIGNIF - BITS(int) + 1)))
#define	FMAXPOWTWO	((float)(1 << (FSIGNIF - 1)))
#define	DMAXEXP	((1 << (_DEXPLEN - 1)) - 1 + _IEEE)
#define	FMAXEXP	((1 << (_FEXPLEN - 1)) - 1 + _IEEE)
#define	LN_MAXDOUBLE	(M_LN2 * DMAXEXP)
#define	LN_MAXFLOAT	(float)(M_LN2 * FMAXEXP)
#define	LN_MINDOUBLE	(M_LN2 * (DMINEXP - 1))
#define	LN_MINFLOAT	(float)(M_LN2 * (FMINEXP - 1))
#define	H_PREC	(DSIGNIF % 2 ? (1 << DSIGNIF/2) * M_SQRT2 : 1 << DSIGNIF/2)
#define	FH_PREC \
	(float)(FSIGNIF % 2 ? (1 << FSIGNIF/2) * M_SQRT2 : 1 << FSIGNIF/2)
#define	X_EPS	(1.0/H_PREC)
#define	FX_EPS	(float)((float)1.0/FH_PREC)
#define	X_PLOSS	((double)(int)(M_PI * H_PREC))
#define	FX_PLOSS ((float)(int)(M_PI * FH_PREC))
#define	X_TLOSS	(M_PI * DMAXPOWTWO)
#define	FX_TLOSS (float)(M_PI * FMAXPOWTWO)
#define	M_LN2	0.69314718055994530942
#define	M_PI	3.14159265358979323846
#define	M_SQRT2	1.41421356237309504880
#define	MAXBEXP	DMAXEXP /* for backward compatibility */
#define	MINBEXP	DMINEXP /* for backward compatibility */
#define	MAXPOWTWO	DMAXPOWTWO /* for backward compatibility */

#ifdef	__cplusplus
}
#endif

#endif	/* _VALUES_H */
