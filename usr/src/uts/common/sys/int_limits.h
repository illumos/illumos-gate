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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_INT_LIMITS_H
#define	_SYS_INT_LIMITS_H

/*
 * This file, <sys/int_limits.h>, is part of the Sun Microsystems implementation
 * of <inttypes.h> as defined in the ISO C standard, ISO/IEC 9899:1999
 * Programming language - C.
 *
 * Programs/Modules should not directly include this file.  Access to the
 * types defined in this file should be through the inclusion of one of the
 * following files:
 *
 *	<limits.h>		This nested inclusion is disabled for strictly
 *				ANSI-C conforming compilations.  The *_MIN
 *				definitions are not visible to POSIX or XPG
 *				conforming applications (due to what may be
 *				a bug in the specification - this is under
 *				investigation)
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
 * Limits
 *
 * The following define the limits for the types defined in <sys/int_types.h>.
 *
 * INTMAX_MIN (minimum value of the largest supported signed integer type),
 * INTMAX_MAX (maximum value of the largest supported signed integer type),
 * and UINTMAX_MAX (maximum value of the largest supported unsigned integer
 * type) can be set to implementation defined limits.
 *
 * NOTE : A programmer can test to see whether an implementation supports
 * a particular size of integer by testing if the macro that gives the
 * maximum for that datatype is defined. For example, if #ifdef UINT64_MAX
 * tests false, the implementation does not support unsigned 64 bit integers.
 *
 * The type of these macros is intentionally unspecified.
 *
 * The types int8_t, int_least8_t, and int_fast8_t are not defined for ISAs
 * where the ABI specifies "char" as unsigned when the translation mode is
 * not ANSI-C.
 */
#define	INT8_MAX	(127)
#define	INT16_MAX	(32767)
#define	INT32_MAX	(2147483647)
#if defined(_LP64)
#define	INT64_MAX	(9223372036854775807L)
#elif defined(_LONGLONG_TYPE)
#define	INT64_MAX	(9223372036854775807LL)
#endif

#define	UINT8_MAX	(255U)
#define	UINT16_MAX	(65535U)
#define	UINT32_MAX	(4294967295U)
#if defined(_LP64)
#define	UINT64_MAX	(18446744073709551615UL)
#elif defined(_LONGLONG_TYPE)
#define	UINT64_MAX	(18446744073709551615ULL)
#endif

#ifdef INT64_MAX
#define	INTMAX_MAX	INT64_MAX
#else
#define	INTMAX_MAX	INT32_MAX
#endif

#ifdef UINT64_MAX
#define	UINTMAX_MAX	UINT64_MAX
#else
#define	UINTMAX_MAX	UINT32_MAX
#endif

#define	INT_LEAST8_MAX	INT8_MAX
#define	INT_LEAST16_MAX INT16_MAX
#define	INT_LEAST32_MAX INT32_MAX
#ifdef INT64_MAX
#define	INT_LEAST64_MAX INT64_MAX
#endif

#define	UINT_LEAST8_MAX	UINT8_MAX
#define	UINT_LEAST16_MAX UINT16_MAX
#define	UINT_LEAST32_MAX UINT32_MAX
#ifdef UINT64_MAX
#define	UINT_LEAST64_MAX UINT64_MAX
#endif

#define	INT_FAST8_MAX	INT8_MAX
#define	INT_FAST16_MAX INT16_MAX
#define	INT_FAST32_MAX INT32_MAX
#ifdef INT64_MAX
#define	INT_FAST64_MAX INT64_MAX
#endif

#define	UINT_FAST8_MAX	UINT8_MAX
#define	UINT_FAST16_MAX UINT16_MAX
#define	UINT_FAST32_MAX UINT32_MAX
#ifdef UINT64_MAX
#define	UINT_FAST64_MAX UINT64_MAX
#endif

/*
 * The following 2 macros are provided for testing whether the types
 * intptr_t and uintptr_t (integers large enough to hold a void *) are
 * defined in this header. They are needed in case the architecture can't
 * represent a pointer in any standard integral type.
 */
#if defined(_LP64) || defined(_I32LPx)
#define	INTPTR_MAX	INT64_MAX
#define	UINTPTR_MAX	UINT64_MAX
#else
#define	INTPTR_MAX	INT32_MAX
#define	UINTPTR_MAX	UINT32_MAX
#endif

/* Maximum limits of ptrdiff_t defined in <sys/types.h> */
#if defined(_LP64) || defined(_I32LPx)
#define	PTRDIFF_MAX	9223372036854775807L
#else
#define	PTRDIFF_MAX	2147483647
#endif

/*
 * Maximum value of a "size_t".  SIZE_MAX was previously defined
 * in <limits.h>, however, the standards specify it be defined
 * in <stdint.h>. The <stdint.h> headers includes this header as
 * does <limits.h>. The value of SIZE_MAX should not deviate
 * from the value of ULONG_MAX defined <sys/types.h>.
 */
#if defined(_LP64)
#define	SIZE_MAX	18446744073709551615UL
#else
#define	SIZE_MAX	4294967295UL
#endif

/* Maximum limit of sig_atomic_t defined in <sys/types.h> */
#ifndef SIG_ATOMIC_MAX
#define	SIG_ATOMIC_MAX	2147483647
#endif

/*
 * Maximum limit of wchar_t. The WCHAR_* macros are also
 * defined in <iso/wchar_iso.h>, but inclusion of that header
 * will break ISO/IEC C namespace.
 */
#ifndef	WCHAR_MAX
#define	WCHAR_MAX	2147483647
#endif

/* Maximum limit of wint_t */
#ifndef WINT_MAX
#define	WINT_MAX	2147483647
#endif

/*
 * It is probably a bug in the POSIX specification (IEEE-1003.1-1990) that
 * when including <limits.h> that the suffix _MAX is reserved but not the
 * suffix _MIN.  However, until that issue is resolved....
 */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || defined(_XPG6)

#define	INT8_MIN	(-128)
#define	INT16_MIN	(-32767-1)
#define	INT32_MIN	(-2147483647-1)
#if defined(_LP64)
#define	INT64_MIN	(-9223372036854775807L-1)
#elif defined(_LONGLONG_TYPE)
#define	INT64_MIN	(-9223372036854775807LL-1)
#endif

#ifdef INT64_MIN
#define	INTMAX_MIN	INT64_MIN
#else
#define	INTMAX_MIN	INT32_MIN
#endif

#define	INT_LEAST8_MIN	INT8_MIN
#define	INT_LEAST16_MIN	INT16_MIN
#define	INT_LEAST32_MIN INT32_MIN
#ifdef INT64_MIN
#define	INT_LEAST64_MIN	INT64_MIN
#endif

#define	INT_FAST8_MIN	INT8_MIN
#define	INT_FAST16_MIN	INT16_MIN
#define	INT_FAST32_MIN INT32_MIN
#ifdef INT64_MIN
#define	INT_FAST64_MIN	INT64_MIN
#endif

/* Minimum value of a pointer-holding signed integer type */
#if defined(_LP64) || defined(_I32LPx)
#define	INTPTR_MIN	INT64_MIN
#else
#define	INTPTR_MIN	INT32_MIN
#endif

/* Minimum limits of ptrdiff_t defined in <sys/types.h> */
#if defined(_LP64) || defined(_I32LPx)
#define	PTRDIFF_MIN	(-9223372036854775807L-1L)
#else
#define	PTRDIFF_MIN	(-2147483647-1)
#endif

/* Minimum limit of sig_atomic_t defined in <sys/types.h> */
#ifndef	SIG_ATOMIC_MIN
#define	SIG_ATOMIC_MIN	(-2147483647-1)
#endif

/*
 * Minimum limit of wchar_t. The WCHAR_* macros are also
 * defined in <iso/wchar_iso.h>, but inclusion of that header
 * will break ISO/IEC C namespace.
 */
#ifndef	WCHAR_MIN
#define	WCHAR_MIN	(-2147483647-1)
#endif

/* Minimum limit of wint_t */
#ifndef	WINT_MIN
#define	WINT_MIN	(-2147483647-1)
#endif

#endif	/* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) ... */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_INT_LIMITS_H */
