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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _STRING_H
#define	_STRING_H

#include <iso/string_iso.h>

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/string_iso.h>.
 */
#if __cplusplus >= 199711L
using std::size_t;
using std::memchr;
using std::memcmp;
using std::memcpy;
using std::memmove;
using std::memset;
using std::strcat;
using std::strchr;
using std::strcmp;
using std::strcoll;
using std::strcpy;
using std::strcspn;
using std::strerror;
using std::strlen;
using std::strncat;
using std::strncmp;
using std::strncpy;
using std::strpbrk;
using std::strrchr;
using std::strspn;
using std::strstr;
using std::strtok;
using std::strxfrm;
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__STDC__)

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_XPG6) || defined(_REENTRANT)
extern int strerror_r(int, char *, size_t);
#endif

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	(_POSIX_C_SOURCE - 0 >= 199506L) || defined(_REENTRANT)
extern char *strtok_r(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
	char **_RESTRICT_KYWD);
#endif

#if defined(__EXTENSIONS__) || !defined(_STRICT_STDC) || \
	defined(__XOPEN_OR_POSIX)
extern void *memccpy(void *_RESTRICT_KYWD, const void *_RESTRICT_KYWD,
		int, size_t);
#endif

#if !defined(_STRICT_SYMBOLS) || defined(_XPG7)

extern char *stpcpy(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD);
extern char *stpncpy(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, size_t);
extern char *strndup(const char *, size_t);
extern size_t strnlen(const char *, size_t);
extern char *strsignal(int);

#ifndef	_LOCALE_T
#define	_LOCALE_T
typedef struct _locale *locale_t;
#endif

extern int strcoll_l(const char *, const char *, locale_t);
extern size_t strxfrm_l(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    size_t, locale_t);
extern int strcasecmp_l(const char *, const char *, locale_t);
extern int strncasecmp_l(const char *, const char *, size_t, locale_t);

#endif /* defined(_STRICT_SYMBOLS) || defined(_XPG7) */

#if !defined(_STRICT_SYMBOLS)

/* Note that some of these are also declared in strings.h for XPG4_2+ */
extern int uucopy(const void *_RESTRICT_KYWD, void *_RESTRICT_KYWD, size_t);
extern int uucopystr(const void *_RESTRICT_KYWD, void *_RESTRICT_KYWD, size_t);
extern int ffs(int);
extern int ffsl(long);
extern int ffsll(long long);
extern int fls(int);
extern int flsl(long);
extern int flsll(long long);
extern void *memmem(const void *, size_t, const void *, size_t);
extern char *strcasestr(const char *, const char *);
extern char *strnstr(const char *, const char *, size_t);
extern size_t strlcpy(char *, const char *, size_t);
extern size_t strlcat(char *, const char *, size_t);
extern char *strsep(char **stringp, const char *delim);
extern char *strchrnul(const char *, int);
extern char *strcasestr_l(const char *, const char *, locale_t);
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, size_t);
#endif /* defined(__EXTENSIONS__)... */

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_XPG4_2)
extern char *strdup(const char *);
#endif

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX))
#if defined(__GNUC__)

/*
 * gcc provides this inlining facility but Studio C does not.
 * We should use it exclusively once Studio C also provides it.
 */
extern void *__builtin_alloca(size_t);

#define	strdupa(s)							\
	(__extension__(							\
	{								\
	char *__str = (char *)(s);					\
	strcpy((char *)__builtin_alloca(strlen(__str) + 1), __str);	\
	}))

#define	strndupa(s, n)							\
	(__extension__(							\
	{								\
	char *__str = (char *)(s);					\
	size_t __len = strnlen(__str, (n));				\
	(__str = strncpy((char *)__builtin_alloca(__len + 1),		\
	    __str, __len),						\
	__str[__len] = '\0', __str);					\
	}))

#else	/* __GNUC__ */

#if defined(unix)	/* excludes c99 */
/*
 * Studio C currently can't do the gcc-style inlining,
 * so we use thread-local storage instead.
 */
extern void *__builtin_alloca(size_t);
extern __thread char *__strdupa_str;
extern __thread size_t __strdupa_len;

#define	strdupa(s)							\
	(__strdupa_str = (char *)(s), 					\
	strcpy((char *)__builtin_alloca(strlen(__strdupa_str) + 1),	\
	    __strdupa_str))

#define	strndupa(s, n)							\
	(__strdupa_str = (char *)(s),					\
	__strdupa_len = strnlen(__strdupa_str, (n)),			\
	__strdupa_str = strncpy((char *)__builtin_alloca(__strdupa_len + 1), \
	    __strdupa_str, __strdupa_len),				\
	__strdupa_str[__strdupa_len] = '\0', __strdupa_str)
#endif	/* unix */

#endif	/* __GNUC__ */
#endif	/* __EXTENSIONS__ ... */

#else	/* __STDC__ */

#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	defined(_XPG6) || defined(_REENTRANT)
extern int strerror_r();
#endif

#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	(_POSIX_C_SOURCE - 0 >= 199506L) || defined(_REENTRANT)
extern char *strtok_r();
#endif

#if defined(__EXTENSIONS__) || !defined(_STRICT_STDC) || \
	defined(__XOPEN_OR_POSIX)
extern void *memccpy();
#endif

#if defined(_XPG7) || !defined(_STRICT_SYMBOLS)
extern int strcasecmp();
extern int strncasecmp();
extern int strcasecmp_l();
extern int strncasecmp_l();
extern char *stpcpy();
extern char *stpncpy();
extern char *strndup();
extern size_t strnlen();
extern char *strsignal();
#endif

#if !defined(_STRICT_SYMBOLS)
extern int uucopy();
extern int uucopystr();
extern int ffs();
extern int ffsl();
extern int ffsll();
extern int fls();
extern int flsl();
extern int flsll();
extern char *strcasestr();
extern char *strcasestr_l();
extern char *strnstr();
extern size_t strlcpy();
extern size_t strlcat();
extern char *strsep();
extern char *strchrnul();
#endif /* _STRICT_SYMBOLS */

#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2)
extern char *strdup();
#endif

#if defined(_XPG7) || !defined(_STRICT_SYMBOLS)
extern size_t strcoll_l();
extern size_t strxfrm_l();
#endif

#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _STRING_H */
