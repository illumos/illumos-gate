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
 * Copyright 2014 PALO, Richard.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <locale.h>.
 */

#ifndef _ISO_STDLIB_ISO_H
#define	_ISO_STDLIB_ISO_H

#include <sys/feature_tests.h>
#include <sys/null.h>

#ifdef	__cplusplus
extern "C" {
#endif

unsigned char __mb_cur_max(void);
#ifndef MB_CUR_MAX
#define	MB_CUR_MAX	(__mb_cur_max())
#endif

#if __cplusplus >= 199711L
namespace std {
#endif

typedef	struct {
	int	quot;
	int	rem;
} div_t;

typedef struct {
	long	quot;
	long	rem;
} ldiv_t;

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64)
typedef unsigned long	size_t;		/* size of something in bytes */
#else
typedef unsigned int    size_t;		/* (historical version) */
#endif
#endif	/* !_SIZE_T */

#define	EXIT_FAILURE	1
#define	EXIT_SUCCESS    0
#define	RAND_MAX	32767

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
typedef long	wchar_t;
#endif
#endif	/* !_WCHAR_T */
#endif	/* !defined(__cplusplus) ... */

#if !defined(_NORETURN_KYWD)
#if __STDC_VERSION__ - 0 >= 201112L
#define	_NORETURN_KYWD	_Noreturn
#else
#define	_NORETURN_KYWD
#endif	/* __STDC_VERSION__ - 0 >= 201112L */
#endif	/* !defined(_NORETURN_KYWD) */

extern _NORETURN_KYWD void abort(void) __NORETURN;
extern int abs(int);
extern int atexit(void (*)(void));
extern double atof(const char *);
extern int atoi(const char *);
extern long int atol(const char *);
extern void *bsearch(const void *, const void *, size_t, size_t,
	int (*)(const void *, const void *));
#if __cplusplus >= 199711L && defined(__SUNPRO_CC)
extern "C++" {
	void *bsearch(const void *, const void *, size_t, size_t,
		int (*)(const void *, const void *));
}
#endif /* __cplusplus >= 199711L && defined(__SUNPRO_CC) */
extern void *calloc(size_t, size_t);
extern div_t div(int, int);
extern _NORETURN_KYWD void exit(int)
	__NORETURN;
extern void free(void *);
extern char *getenv(const char *);
/*
 * Duplicated from math_iso.h for C++ abs() inlines below.
 */
#if __cplusplus >= 199711L
extern double fabs(double);
extern float fabsf(float);
extern long double fabsl(long double);
#endif
extern long int labs(long);
extern ldiv_t ldiv(long, long);
extern void *malloc(size_t);
extern int mblen(const char *, size_t);
extern size_t mbstowcs(wchar_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
	size_t);
extern int mbtowc(wchar_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, size_t);
extern void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
#if __cplusplus >= 199711L && defined(__SUNPRO_CC)
extern "C++" {
	void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
}
#endif /* __cplusplus >= 199711L && defined(__SUNPRO_CC) */
extern int rand(void);
extern void *realloc(void *, size_t);
extern void srand(unsigned int);
extern double strtod(const char *_RESTRICT_KYWD, char **_RESTRICT_KYWD);
extern long int strtol(const char *_RESTRICT_KYWD, char **_RESTRICT_KYWD, int);
extern unsigned long int strtoul(const char *_RESTRICT_KYWD,
	char **_RESTRICT_KYWD, int);
extern int system(const char *);
extern int wctomb(char *, wchar_t);
extern size_t wcstombs(char *_RESTRICT_KYWD, const wchar_t *_RESTRICT_KYWD,
	size_t);

#if __cplusplus >= 199711L
extern "C++" {
#undef	__X
#undef	__Y
	inline long   abs(long __X) { return labs(__X); }
	inline ldiv_t div(long __X, long __Y) { return ldiv(__X, __Y); }
/*
 * For compatibility with GCC and GLIBCXX, let either stdlib.h or math.h
 * provide both the integer and floating point abs() variants, regardless
 * which is included first.
 */
#ifndef _CXX_ABS_FLOAT_DEFINED
#define	_CXX_ABS_FLOAT_DEFINED
	inline double abs(double __X) { return fabs(__X); }
	inline float abs(float __X) { return fabsf(__X); }
	inline long double abs(long double __X) { return fabsl(__X); }
#endif /* !_CXX_ABS_FLOAT_DEFINED */
} /* extern C++ */
#endif /* __cplusplus */

#if __cplusplus >= 199711L
}
#endif /* end of namespace std */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_STDLIB_ISO_H */
