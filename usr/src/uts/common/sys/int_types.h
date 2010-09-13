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

#ifndef _SYS_INT_TYPES_H
#define	_SYS_INT_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file, <sys/int_types.h>, is part of the Sun Microsystems implementation
 * of <inttypes.h> defined in the ISO C standard, ISO/IEC 9899:1999
 * Programming language - C.
 *
 * Programs/Modules should not directly include this file.  Access to the
 * types defined in this file should be through the inclusion of one of the
 * following files:
 *
 *	<sys/types.h>		Provides only the "_t" types defined in this
 *				file which is a subset of the contents of
 *				<inttypes.h>.  (This can be appropriate for
 *				all programs/modules except those claiming
 *				ANSI-C conformance.)
 *
 *	<sys/inttypes.h>	Provides the Kernel and Driver appropriate
 *				components of <inttypes.h>.
 *
 *	<inttypes.h>		For use by applications.
 *
 * See these files for more details.
 */

#include <sys/feature_tests.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Basic / Extended integer types
 *
 * The following defines the basic fixed-size integer types.
 *
 * Implementations are free to typedef them to Standard C integer types or
 * extensions that they support. If an implementation does not support one
 * of the particular integer data types below, then it should not define the
 * typedefs and macros corresponding to that data type.  Note that int8_t
 * is not defined in -Xs mode on ISAs for which the ABI specifies "char"
 * as an unsigned entity because there is no way to define an eight bit
 * signed integral.
 */
#if defined(_CHAR_IS_SIGNED)
typedef char			int8_t;
#else
#if defined(__STDC__)
typedef signed char		int8_t;
#endif
#endif
typedef short			int16_t;
typedef int			int32_t;
#ifdef	_LP64
#define	_INT64_TYPE
typedef long			int64_t;
#else	/* _ILP32 */
#if defined(_LONGLONG_TYPE)
#define	_INT64_TYPE
typedef	long long		int64_t;
#endif
#endif

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
#ifdef	_LP64
typedef unsigned long		uint64_t;
#else	/* _ILP32 */
#if defined(_LONGLONG_TYPE)
typedef unsigned long long	uint64_t;
#endif
#endif

/*
 * intmax_t and uintmax_t are to be the longest (in number of bits) signed
 * and unsigned integer types supported by the implementation.
 */
#if defined(_INT64_TYPE)
typedef int64_t			intmax_t;
typedef uint64_t		uintmax_t;
#else
typedef int32_t			intmax_t;
typedef uint32_t		uintmax_t;
#endif

/*
 * intptr_t and uintptr_t are signed and unsigned integer types large enough
 * to hold any data pointer; that is, data pointers can be assigned into or
 * from these integer types without losing precision.
 */
#if defined(_LP64) || defined(_I32LPx)
typedef long			intptr_t;
typedef unsigned long		uintptr_t;
#else
typedef	int			intptr_t;
typedef	unsigned int		uintptr_t;
#endif

/*
 * The following define the fastest integer types that can hold the
 * specified number of bits.
 */
#if defined(_CHAR_IS_SIGNED)
typedef char			int_fast8_t;
#else
#if defined(__STDC__)
typedef signed char		int_fast8_t;
#endif
#endif
typedef int			int_fast16_t;
typedef int			int_fast32_t;
#ifdef	_LP64
typedef long			int_fast64_t;
#else	/* _ILP32 */
#if defined(_LONGLONG_TYPE)
typedef long long		int_fast64_t;
#endif
#endif

typedef unsigned char		uint_fast8_t;
typedef unsigned int		uint_fast16_t;
typedef unsigned int		uint_fast32_t;
#ifdef	_LP64
typedef unsigned long		uint_fast64_t;
#else	/* _ILP32 */
#if defined(_LONGLONG_TYPE)
typedef unsigned long long	uint_fast64_t;
#endif
#endif

/*
 * The following define the smallest integer types that can hold the
 * specified number of bits.
 */
#if defined(_CHAR_IS_SIGNED)
typedef char			int_least8_t;
#else
#if defined(__STDC__)
typedef signed char		int_least8_t;
#endif
#endif
typedef short			int_least16_t;
typedef int			int_least32_t;
#ifdef	_LP64
typedef long			int_least64_t;
#else	/* _ILP32 */
#if defined(_LONGLONG_TYPE)
typedef long long		int_least64_t;
#endif
#endif

typedef unsigned char		uint_least8_t;
typedef unsigned short		uint_least16_t;
typedef unsigned int		uint_least32_t;
#ifdef	_LP64
typedef unsigned long		uint_least64_t;
#else	/* _ILP32 */
#if defined(_LONGLONG_TYPE)
typedef unsigned long long	uint_least64_t;
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_INT_TYPES_H */
