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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef	_FCNTL_H
#define	_FCNTL_H

#include <sys/feature_tests.h>
#if defined(__EXTENSIONS__) || defined(_XPG4)
#include <sys/stat.h>
#endif
#include <sys/types.h>
#include <sys/fcntl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__EXTENSIONS__) || defined(_XPG4)

/* Symbolic constants for the "lseek" routine. */

#ifndef	SEEK_SET
#define	SEEK_SET	0	/* Set file pointer to "offset" */
#endif

#ifndef	SEEK_CUR
#define	SEEK_CUR	1	/* Set file pointer to current plus "offset" */
#endif

#ifndef	SEEK_END
#define	SEEK_END	2	/* Set file pointer to EOF plus "offset" */
#endif
#endif /* defined(__EXTENSIONS__) || defined(_XPG4) */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#ifndef	SEEK_DATA
#define	SEEK_DATA	3	/* Set file pointer to next data past offset */
#endif

#ifndef	SEEK_HOLE
#define	SEEK_HOLE	4	/* Set file pointer to next hole past offset */
#endif
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */


/* large file compilation environment setup */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	open	open64
#pragma redefine_extname	creat	creat64
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
#pragma redefine_extname	posix_fadvise posix_fadvise64
#pragma redefine_extname	posix_fallocate posix_fallocate64
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || ... */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	defined(_ATFILE_SOURCE)
#pragma redefine_extname	openat	openat64
#pragma	redefine_extname	attropen attropen64
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) ... */
#else
#define	open			open64
#define	creat			creat64
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
#define	posix_fadvise		posix_fadvise64
#define	posix_fallocate		posix_fallocate64
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || ... */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	defined(_ATFILE_SOURCE)
#define	openat			openat64
#define	attropen		attropen64
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) ... */
#endif
#endif	/* !_LP64 && _FILE_OFFSET_BITS == 64 */

#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	open64	open
#pragma	redefine_extname	creat64	creat
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
#pragma redefine_extname	posix_fadvise64 posix_fadvise
#pragma redefine_extname	posix_fallocate64 posix_fallocate
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || ... */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	defined(_ATFILE_SOURCE)
#pragma	redefine_extname	openat64	openat
#pragma	redefine_extname	attropen64	attropen
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) ... */
#else
#define	open64				open
#define	creat64				creat
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
#define	posix_fadvise64			posix_fadvise
#define	posix_fallocate64		posix_fallocate
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || ... */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	defined(_ATFILE_SOURCE)
#define	openat64			openat
#define	attropen64			attropen
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) ... */
#endif
#endif	/* _LP64 && _LARGEFILE64_SOURCE */

extern int fcntl(int, int, ...);
extern int open(const char *, int, ...);
extern int creat(const char *, mode_t);
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
extern int posix_fadvise(int, off_t, off_t, int);
extern int posix_fallocate(int, off_t, off_t);
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || ... */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	defined(_ATFILE_SOURCE)
extern int openat(int, const char *, int, ...);
extern int attropen(const char *, const char *, int, ...);
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) ... */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)
extern int directio(int, int);
#endif

/* transitional large file interface versions */
#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern int open64(const char *, int, ...);
extern int creat64(const char *, mode_t);
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || defined(__EXTENSIONS__)
extern int posix_fadvise64(int, off64_t, off64_t, int);
extern int posix_fallocate64(int, off64_t, off64_t);
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG6) || ... */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	defined(_ATFILE_SOURCE)
extern int openat64(int, const char *, int, ...);
extern int attropen64(const char *, const char *, int, ...);
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) ... */
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _FCNTL_H */
