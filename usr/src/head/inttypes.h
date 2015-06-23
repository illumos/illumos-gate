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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _INTTYPES_H
#define	_INTTYPES_H

/*
 * This file, <inttypes.h>, is specified by the ISO C standard,
 * standard, ISO/IEC 9899:1999 Programming language - C and is
 * also defined by SUSv3.
 *
 * ISO	  International Organization for Standardization.
 * SUSv3  Single Unix Specification, Version 3
 */

#include <sys/feature_tests.h>
#include <sys/inttypes.h>

#if (!defined(_XOPEN_SOURCE) || defined(_XPG6)) || defined(_STDC_C99) || \
	defined(__EXTENSIONS__)
#include <sys/stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Inclusion of <stddef.h> breaks namespace, therefore define wchar_t */

/*
 * wchar_t is a built-in type in standard C++ and as such is not
 * defined here when using standard C++. However, the GNU compiler
 * fixincludes utility nonetheless creates its own version of this
 * header for use by gcc and g++. In that version it adds a redundant
 * guard for __cplusplus. To avoid the creation of a gcc/g++ specific
 * header we need to include the following magic comment:
 *
 * we must use the C++ compiler's type
 *
 * The above comment should not be removed or changed until GNU
 * gcc/fixinc/inclhack.def is updated to bypass this header.
 */
#if !defined(__cplusplus) || (__cplusplus < 199711L && !defined(__GNUG__))
#ifndef _WCHAR_T
#define	_WCHAR_T
#if defined(_LP64)
typedef	int	wchar_t;
#else
typedef	long	wchar_t;
#endif
#endif	/* !_WCHAR_T */
#endif	/* !__cplusplus || (__cplusplus < 199711L && !__GNUG__) */

#if (!defined(_XOPEN_SOURCE) || defined(_XPG6)) || defined(_STDC_C99) || \
	defined(__EXTENSIONS__)
typedef struct {
	intmax_t quot;
	intmax_t rem;
} imaxdiv_t;
#endif /* (!defined(_XOPEN_SOURCE) || defined(_XPG6)) ... */

#if !defined(_LP64) && !defined(_LONGLONG_TYPE)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname imaxabs	_imaxabs_c89
#pragma	redefine_extname imaxdiv	_imaxdiv_c89
#pragma	redefine_extname strtoimax	_strtoimax_c89
#pragma	redefine_extname strtoumax	_strtoumax_c89
#pragma	redefine_extname wcstoimax	_wcstoimax_c89
#pragma	redefine_extname wcstoumax	_wcstoumax_c89
#else
#define	imaxabs		_imaxabs_c89
#define	imaxdiv		_imaxdiv_c89
#define	strtoimax	_strtoimax_c89
#define	strtoumax	_strtoumax_c89
#define	wcstoimax	_wcstoimax_c89
#define	wcstoumax	_wcstoumax_c89
#endif
#endif /* !defined(_LP64) && !defined(_LONGLONG_TYPE) */

#if (!defined(_XOPEN_SOURCE) || defined(_XPG6)) || defined(_STDC_C99) || \
	defined(__EXTENSIONS__)

extern intmax_t  imaxabs(intmax_t);
extern imaxdiv_t imaxdiv(intmax_t, intmax_t);
extern intmax_t  strtoimax(const char *_RESTRICT_KYWD, char **_RESTRICT_KYWD,
	int);
extern uintmax_t strtoumax(const char *_RESTRICT_KYWD, char **_RESTRICT_KYWD,
	int);
extern intmax_t  wcstoimax(const wchar_t *_RESTRICT_KYWD,
	wchar_t **_RESTRICT_KYWD, int);
extern uintmax_t wcstoumax(const wchar_t *_RESTRICT_KYWD,
	wchar_t **_RESTRICT_KYWD, int);

#endif /* (!defined(_XOPEN_SOURCE) || defined(_XPG6)) ... */

#ifdef __cplusplus
}
#endif

#endif /* _INTTYPES_H */
