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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <limits.h>.
 */

#ifndef _ISO_LIMITS_ISO_H
#define	_ISO_LIMITS_ISO_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Sizes of integral types
 */
#define	CHAR_BIT	8		/* max # of bits in a "char" */
#define	SCHAR_MIN	(-128)		/* min value of a "signed char" */
#define	SCHAR_MAX	127		/* max value of a "signed char" */
#define	UCHAR_MAX	255		/* max value of an "unsigned char" */

#define	MB_LEN_MAX	5

#if defined(_CHAR_IS_SIGNED)
#define	CHAR_MIN	SCHAR_MIN	/* min value of a "char" */
#define	CHAR_MAX	SCHAR_MAX	/* max value of a "char" */
#elif defined(_CHAR_IS_UNSIGNED)
#define	CHAR_MIN	0		/* min value of a "char" */
#define	CHAR_MAX	UCHAR_MAX	/* max value of a "char" */
#else
#error "chars are signed or unsigned"
#endif

#define	SHRT_MIN	(-32768)	/* min value of a "short int" */
#define	SHRT_MAX	32767		/* max value of a "short int" */
#define	USHRT_MAX	65535		/* max value of "unsigned short int" */
#define	INT_MIN		(-2147483647-1)	/* min value of an "int" */
#define	INT_MAX		2147483647	/* max value of an "int" */
#define	UINT_MAX	4294967295U	/* max value of an "unsigned int" */
#if defined(_LP64)
#define	LONG_MIN	(-9223372036854775807L-1L)
					/* min value of a "long int" */
#define	LONG_MAX	9223372036854775807L
					/* max value of a "long int" */
#define	ULONG_MAX	18446744073709551615UL
					/* max value of "unsigned long int" */
#else	/* _ILP32 */
#define	LONG_MIN	(-2147483647L-1L)
					/* min value of a "long int" */
#define	LONG_MAX	2147483647L	/* max value of a "long int" */
#define	ULONG_MAX	4294967295UL 	/* max value of "unsigned long int" */
#endif
#if !defined(_STRICT_STDC) || defined(_STDC_C99) || defined(__EXTENSIONS__)
#define	LLONG_MIN	(-9223372036854775807LL-1LL)
					/* min value of a long long */
#define	LLONG_MAX	9223372036854775807LL
					/* max value of a long long */
#define	ULLONG_MAX	18446744073709551615ULL
					/* max value of "unsigned long long */
#endif /* !defined(_STRICT_STDC) || defined(_STDC_C99)... */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_LIMITS_ISO_H */
