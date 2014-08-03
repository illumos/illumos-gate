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

#ifndef _FLOAT_H
#define	_FLOAT_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__sparc)

extern int __flt_rounds(void);
#define	FLT_ROUNDS	__flt_rounds()

#else /* defined(__sparc) */

extern int __fltrounds(void);

#if defined(__amd64)
#define	FLT_ROUNDS	__fltrounds()
#else	/* defined(__amd64) */
extern int __flt_rounds;
#define	FLT_ROUNDS	__flt_rounds
#endif	/* defined(__amd64) */
#endif /* defined(__sparc) */

/* Introduced in ISO/IEC 9899:1999 standard */
#if defined(__EXTENSIONS__) || defined(_STDC_C99) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX))
#if defined(__FLT_EVAL_METHOD__)
#define	FLT_EVAL_METHOD __FLT_EVAL_METHOD__
#else
#define	FLT_EVAL_METHOD	-1
#endif /* defined(__FLT_EVAL_METHOD__) */
#endif /* defined(__EXTENSIONS__) || defined(_STDC_C99)... */

#define	FLT_RADIX	2
#define	FLT_MANT_DIG	24
#define	FLT_EPSILON	1.1920928955078125000000E-07F
#define	FLT_DIG		6
#define	FLT_MIN_EXP	(-125)
#define	FLT_MIN		1.1754943508222875079688E-38F
#define	FLT_MIN_10_EXP	(-37)
#define	FLT_MAX_EXP	(+128)
#define	FLT_MAX		3.4028234663852885981170E+38F
#define	FLT_MAX_10_EXP	(+38)

#define	DBL_MANT_DIG	53
#define	DBL_EPSILON	2.2204460492503130808473E-16
#define	DBL_DIG		15
#define	DBL_MIN_EXP	(-1021)
#define	DBL_MIN		2.2250738585072013830903E-308
#define	DBL_MIN_10_EXP	(-307)
#define	DBL_MAX_EXP	(+1024)
#define	DBL_MAX		1.7976931348623157081452E+308
#define	DBL_MAX_10_EXP	(+308)

/* Introduced in ISO/IEC 9899:1999 standard */
#if defined(__EXTENSIONS__) || defined(_STDC_C99) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX))
#if defined(__sparc)
#define	DECIMAL_DIG	36
#elif defined(__i386) || defined(__amd64)
#define	DECIMAL_DIG	21
#endif
#endif /* defined(__EXTENSIONS__) || defined(_STDC_C99)... */


#if defined(__i386) || defined(__amd64)

/* Follows IEEE standards for 80-bit floating point */
#define	LDBL_MANT_DIG	64
#define	LDBL_EPSILON	1.0842021724855044340075E-19L
#define	LDBL_DIG	18
#define	LDBL_MIN_EXP	(-16381)
#define	LDBL_MIN	3.3621031431120935062627E-4932L
#define	LDBL_MIN_10_EXP	(-4931)
#define	LDBL_MAX_EXP	(+16384)
#define	LDBL_MAX	1.1897314953572317650213E+4932L
#define	LDBL_MAX_10_EXP	(+4932)

#elif defined(__sparc)

/* Follows IEEE standards for 128-bit floating point */
#define	LDBL_MANT_DIG	113
#define	LDBL_EPSILON	1.925929944387235853055977942584927319E-34L
#define	LDBL_DIG	33
#define	LDBL_MIN_EXP	(-16381)
#define	LDBL_MIN	3.362103143112093506262677817321752603E-4932L
#define	LDBL_MIN_10_EXP	(-4931)
#define	LDBL_MAX_EXP	(+16384)
#define	LDBL_MAX	1.189731495357231765085759326628007016E+4932L
#define	LDBL_MAX_10_EXP	(+4932)

#else

#error "Unknown architecture!"

#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _FLOAT_H */
