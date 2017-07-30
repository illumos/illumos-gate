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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _STDLIB_H
#define	_STDLIB_H

#include <iso/stdlib_iso.h>
#include <iso/stdlib_c99.h>
#include <iso/stdlib_c11.h>

#if defined(__EXTENSIONS__) || defined(_XPG4)
#include <sys/wait.h>
#endif

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/stdlib_iso.h>.
 */
#if __cplusplus >= 199711L
using std::div_t;
using std::ldiv_t;
using std::size_t;
using std::abort;
using std::abs;
using std::atexit;
using std::atof;
using std::atoi;
using std::atol;
using std::bsearch;
using std::calloc;
using std::div;
using std::exit;
using std::free;
using std::getenv;
using std::labs;
using std::ldiv;
using std::malloc;
using std::mblen;
using std::mbstowcs;
using std::mbtowc;
using std::qsort;
using std::rand;
using std::realloc;
using std::srand;
using std::strtod;
using std::strtol;
using std::strtoul;
using std::system;
using std::wcstombs;
using std::wctomb;
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _UID_T
#define	_UID_T
typedef	unsigned int	uid_t;		/* UID type		*/
#endif	/* !_UID_T */

/* large file compilation environment setup */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64

#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	mkstemp		mkstemp64
#pragma redefine_extname	mkstemps	mkstemps64
#pragma	redefine_extname	mkostemp	mkostemp64
#pragma	redefine_extname	mkostemps	mkostemps64
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#define	mkstemp			mkstemp64
#define	mkstemps		mkstemps64
#define	mkostemp		mkostemp64
#define	mkostemps		mkostemps64
#endif	/* __PRAGMA_REDEFINE_EXTNAME */

#endif	/* _FILE_OFFSET_BITS == 64 */

/* In the LP64 compilation environment, all APIs are already large file */
#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)

#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	mkstemp64	mkstemp
#pragma redefine_extname	mkstemps64	mkstemps
#pragma	redefine_extname	mkostemp64	mkostemp
#pragma	redefine_extname	mkostemps64	mkostemps
#else	/* __PRAGMA_REDEFINE_EXTNAME */
#define	mkstemp64		mkstemp
#define	mkstemps64		mkstemps
#define	mkostemp64		mkostemp
#define	mkostemps64		mkostemps
#endif	/* __PRAGMA_REDEFINE_EXTNAME */

#endif	/* _LP64 && _LARGEFILE64_SOURCE */

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	(_POSIX_C_SOURCE - 0 >= 199506L) || defined(_REENTRANT)
extern int rand_r(unsigned int *);
#endif

extern void _exithandle(void);

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(_POSIX_C_SOURCE)) || \
	defined(_XPG4)
extern double drand48(void);
extern double erand48(unsigned short *);
extern long jrand48(unsigned short *);
extern void lcong48(unsigned short *);
extern long lrand48(void);
extern long mrand48(void);
extern long nrand48(unsigned short *);
extern unsigned short *seed48(unsigned short *);
extern void srand48(long);
extern int putenv(char *);
extern void setkey(const char *);
#endif /* defined(__EXTENSIONS__) || !defined(_STRICT_STDC) ... */

/*
 * swab() has historically been in <stdlib.h> as delivered from AT&T
 * and continues to be visible in the default compilation environment.
 * As of Issue 4 of the X/Open Portability Guides, swab() was declared
 * in <unistd.h>. As a result, with respect to X/Open namespace the
 * swab() declaration in this header is only visible for the XPG3
 * environment.
 */
#if (defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC__) && !defined(_POSIX_C_SOURCE))) && \
	(!defined(_XOPEN_SOURCE) || (defined(_XPG3) && !defined(_XPG4)))
#ifndef	_SSIZE_T
#define	_SSIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef long	ssize_t;	/* size of something in bytes or -1 */
#else
typedef int	ssize_t;	/* (historical version) */
#endif
#endif	/* !_SSIZE_T */

extern void swab(const char *, char *, ssize_t);
#endif /* defined(__EXTENSIONS__) || !defined(_STRICT_STDC) ... */

#if defined(__EXTENSIONS__) || \
	!defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || \
	(defined(_LARGEFILE_SOURCE) && _FILE_OFFSET_BITS == 64)
extern int	mkstemp(char *);
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
extern int	mkstemps(char *, int);
#endif
#endif /* defined(__EXTENSIONS__) ... */

#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern int	mkstemp64(char *);
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
extern int	mkstemps64(char *, int);
#endif
#endif	/* _LARGEFILE64_SOURCE... */

#if !defined(_STRICT_SYMBOLS) || defined(_XPG7)
extern char	*mkdtemp(char *);
#endif	/* !defined(_STRICT_SYMBOLS) || defined(_XPG7) */

#if !defined(_STRICT_SYMBOLS)
extern int		mkostemp(char *, int);
extern int		mkostemps(char *, int, int);
#if defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
		!defined(__PRAGMA_REDEFINE_EXTNAME))
extern int		mkostemp64(char *, int);
extern int		mkostemps64(char *, int, int);
#endif	/* defined(_LARGEFILE64_SOURCE) || !((_FILE_OFFSET_BITS == 64) ... */
#endif	/* !defined(_STRICT_SYMBOLS) */

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_XPG4_2)
extern long a64l(const char *);
extern char *ecvt(double, int, int *_RESTRICT_KYWD, int *_RESTRICT_KYWD);
extern char *fcvt(double, int, int *_RESTRICT_KYWD, int *_RESTRICT_KYWD);
extern char *gcvt(double, int, char *);
extern int getsubopt(char **, char *const *, char **);
extern int  grantpt(int);
extern char *initstate(unsigned, char *, size_t);
extern char *l64a(long);
extern char *mktemp(char *);
extern char *ptsname(int);
extern long random(void);
extern char *realpath(const char *_RESTRICT_KYWD, char *_RESTRICT_KYWD);
extern char *setstate(const char *);
extern void srandom(unsigned);
extern int  unlockpt(int);
/* Marked LEGACY in SUSv2 and removed in SUSv3 */
#if !defined(_XPG6) || defined(__EXTENSIONS__)
extern int ttyslot(void);
extern void *valloc(size_t);
#endif /* !defined(_XPG6) || defined(__EXTENSIONS__) */
#endif /* defined(__EXTENSIONS__) || ... || defined(_XPG4_2) */

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_XPG6)
extern int posix_memalign(void **, size_t, size_t);
extern int posix_openpt(int);
extern int setenv(const char *, const char *, int);
extern int unsetenv(const char *);
#endif

#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX))
extern char *canonicalize_file_name(const char *);
extern int clearenv(void);
extern void closefrom(int);
extern int daemon(int, int);
extern int dup2(int, int);
extern int dup3(int, int, int);
extern int fdwalk(int (*)(void *, int), void *);
extern char *qecvt(long double, int, int *, int *);
extern char *qfcvt(long double, int, int *, int *);
extern char *qgcvt(long double, int, char *);
extern char *getcwd(char *, size_t);
extern const char *getexecname(void);

#ifndef	__GETLOGIN_DEFINED	/* Avoid duplicate in unistd.h */
#define	__GETLOGIN_DEFINED
#ifndef	__USE_LEGACY_LOGNAME__
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname getlogin getloginx
#else	/* __PRAGMA_REDEFINE_EXTNAME */
extern char *getloginx(void);
#define	getlogin	getloginx
#endif	/* __PRAGMA_REDEFINE_EXTNAME */
#endif	/* __USE_LEGACY_LOGNAME__ */
extern char *getlogin(void);
#endif	/* __GETLOGIN_DEFINED */

extern int getopt(int, char *const *, const char *);
extern char *optarg;
extern int optind, opterr, optopt;
extern char *getpass(const char *);
extern char *getpassphrase(const char *);
extern int getpw(uid_t, char *);
extern int isatty(int);
extern void *memalign(size_t, size_t);
extern char *ttyname(int);
extern char *mkdtemp(char *);
extern const char *getprogname(void);
extern void setprogname(const char *);

#if !defined(_STRICT_STDC) && defined(_LONGLONG_TYPE)
extern char *lltostr(long long, char *);
extern char *ulltostr(unsigned long long, char *);
#endif	/* !defined(_STRICT_STDC) && defined(_LONGLONG_TYPE) */

#endif /* defined(__EXTENSIONS__) || !defined(_STRICT_STDC) ... */

/* OpenBSD compatibility functions */
#if !defined(_STRICT_SYMBOLS)

#include <inttypes.h>
extern uint32_t arc4random(void);
extern void arc4random_buf(void *, size_t);
extern uint32_t arc4random_uniform(uint32_t);
extern void freezero(void *, size_t);
extern void *reallocarray(void *, size_t, size_t);
extern void *recallocarray(void *, size_t, size_t, size_t);
extern long long strtonum(const char *, long long, long long, const char **);

#endif	/* !_STRICT_SYBMOLS */


#ifdef	__cplusplus
}
#endif

#endif	/* _STDLIB_H */
