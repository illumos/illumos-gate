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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * declarations of functions found in libgen
 */

#ifndef _LIBGEN_H
#define	_LIBGEN_H

#include <sys/feature_tests.h>

#include <sys/types.h>
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#include <time.h>
#include <stdio.h>
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
extern "C" {
#endif

extern char *basename(char *);
extern char *dirname(char *);

#if !defined(_XPG6) || defined(__EXTENSIONS__)
extern char *regcmp(const char *, ...);
extern char *regex(const char *, const char *, ...);
#endif

#ifdef _REENTRANT
extern char **____loc1(void);
#define	__loc1 (*(____loc1()))
#elif !defined(_XPG6) || defined(__EXTENSIONS__)
extern char *__loc1;	/* Marked LEGACY in XPG5 and removed in XPG6 */
#endif /* _REENTRANT */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)

extern char *bgets(char *, size_t, FILE *, char *);
extern size_t bufsplit(char *, size_t, char **);

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	copylist	copylist64
#else
#define	copylist		copylist64
#endif
#endif	/* !_LP64 && _FILE_OFFSET_BITS == 64 */

#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	copylist64	copylist
#else
#define	copylist64		copylist
#endif
#endif	/* _LP64 && _LARGEFILE64_SOURCE */

extern char *copylist(const char *, off_t *);
#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern char *copylist64(const char *, off64_t *);
#endif	/* _LARGEFILE64_SOURCE... */

extern int eaccess(const char *, int);
extern int gmatch(const char *, const char *);
extern int isencrypt(const char *, size_t);
extern int mkdirp(const char *, mode_t);
extern int p2open(const char *, FILE *[2]);
extern int p2close(FILE *[2]);
extern char *pathfind(const char *, const char *, const char *);

#ifdef _REENTRANT
#define	__i_size (*(___i_size()))
#else
extern int __i_size;
#endif

extern int rmdirp(char *, char *);
extern char *strcadd(char *, const char *);
extern char *strccpy(char *, const char *);
extern char *streadd(char *, const char *, const char *);
extern char *strecpy(char *, const char *, const char *);
extern int strfind(const char *, const char *);
extern char *strrspn(const char *, const char *);
extern char *strtrns(const char *, const char *, const char *, char *);

#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBGEN_H */
