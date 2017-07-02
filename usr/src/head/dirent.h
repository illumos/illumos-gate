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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _DIRENT_H
#define	_DIRENT_H

#include <sys/feature_tests.h>

#include <sys/types.h>
#include <sys/dirent.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)

#define	MAXNAMLEN	512		/* maximum filename length */
#define	DIRBUF		8192		/* buffer size for fs-indep. dirs */

#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) */

#if !defined(__XOPEN_OR_POSIX)

typedef struct {
	int	dd_fd;		/* file descriptor */
	int	dd_loc;		/* offset in block */
	int	dd_size;	/* amount of valid data */
	char	*dd_buf;	/* directory block */
} DIR;				/* stream data from opendir() */


#else

typedef struct {
	int	d_fd;		/* file descriptor */
	int	d_loc;		/* offset in block */
	int	d_size;		/* amount of valid data */
	char	*d_buf;		/* directory block */
} DIR;				/* stream data from opendir() */

#endif /* !defined(__XOPEN_OR_POSIX) */

/* large file compilation environment setup */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	readdir	readdir64
#pragma	redefine_extname	scandir	scandir64
#pragma	redefine_extname	alphasort alphasort64
#else
#define	readdir			readdir64
#define	scandir			scandir64
#define	alphasort		alphasort64
#endif
#endif	/* _FILE_OFFSET_BITS == 64 */

/* In the LP64 compilation environment, all APIs are already large file */
#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	readdir64	readdir
#pragma	redefine_extname	scandir64	scandir
#pragma	redefine_extname	alphasort64	alphasort
#else
#define	readdir64		readdir
#define	scandir64		scandir
#define	alphsort64		alphasort
#endif
#endif	/* _LP64 && _LARGEFILE64_SOURCE */

extern DIR		*opendir(const char *);
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) || \
	defined(_ATFILE_SOURCE)
extern DIR		*fdopendir(int);
extern int		dirfd(DIR *);
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) ... */
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)
extern int		scandir(const char *, struct dirent *(*[]),
				int (*)(const struct dirent *),
				int (*)(const struct dirent **,
					const struct dirent **));
extern int		alphasort(const struct dirent **,
					const struct dirent **);
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) */
extern struct dirent	*readdir(DIR *);
#if defined(__EXTENSIONS__) || !defined(_POSIX_C_SOURCE) || \
	defined(_XOPEN_SOURCE)
extern long		telldir(DIR *);
extern void		seekdir(DIR *, long);
#endif /* defined(__EXTENSIONS__) || !defined(_POSIX_C_SOURCE) ... */
extern void		rewinddir(DIR *);
extern int		closedir(DIR *);

/* transitional large file interface */
#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern struct dirent64	*readdir64(DIR *);
#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)
extern int	scandir64(const char *, struct dirent64 *(*[]),
			int (*)(const struct dirent64 *),
			int (*)(const struct dirent64 **,
				const struct dirent64 **));
extern int	alphasort64(const struct dirent64 **, const struct dirent64 **);
#endif /* defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX) */
#endif

#if defined(__EXTENSIONS__) || !defined(_POSIX_C_SOURCE) || \
	defined(_XOPEN_SOURCE)
#define	rewinddir(dirp)	seekdir(dirp, 0L)
#endif

/*
 * readdir_r() prototype is defined here.
 *
 * There are several variations, depending on whether compatibility with old
 * POSIX draft specifications or the final specification is desired and on
 * whether the large file compilation environment is active.  To combat a
 * combinatorial explosion, enabling large files implies using the final
 * specification (since the definition of the large file environment
 * considerably postdates that of the final readdir_r specification).
 *
 * In the LP64 compilation environment, all APIs are already large file,
 * and since there are no 64-bit applications that can have seen the
 * draft implementation, again, we use the final POSIX specification.
 */

#if	defined(__EXTENSIONS__) || defined(_REENTRANT) || \
	!defined(__XOPEN_OR_POSIX) || (_POSIX_C_SOURCE - 0 >= 199506L) || \
	defined(_POSIX_PTHREAD_SEMANTICS)

#if	!defined(_LP64) && _FILE_OFFSET_BITS == 32

#if	(_POSIX_C_SOURCE - 0 >= 199506L) || defined(_POSIX_PTHREAD_SEMANTICS)

#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname readdir_r	__posix_readdir_r
extern int readdir_r(DIR *_RESTRICT_KYWD, struct dirent *_RESTRICT_KYWD,
		struct dirent **_RESTRICT_KYWD);
#else	/* __PRAGMA_REDEFINE_EXTNAME */

extern int __posix_readdir_r(DIR *_RESTRICT_KYWD,
    struct dirent *_RESTRICT_KYWD, struct dirent **_RESTRICT_KYWD);

#ifdef	__lint
#define	readdir_r	__posix_readdir_r
#else	/* !__lint */

static int
readdir_r(DIR *_RESTRICT_KYWD __dp, struct dirent *_RESTRICT_KYWD __ent,
    struct dirent **_RESTRICT_KYWD __res)
{
	return (__posix_readdir_r(__dp, __ent, __res));
}

#endif /* !__lint */
#endif /* __PRAGMA_REDEFINE_EXTNAME */

#else  /* (_POSIX_C_SOURCE - 0 >= 199506L) || ... */

extern struct dirent *readdir_r(DIR *__dp, struct dirent *__ent);

#endif  /* (_POSIX_C_SOURCE - 0 >= 199506L) || ... */

#else	/* !_LP64 && _FILE_OFFSET_BITS == 32 */

#if defined(_LP64)
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname readdir64_r	readdir_r
#else
#define	readdir64_r		readdir_r
#endif
#else	/* _LP64 */
#ifdef	__PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname readdir_r	readdir64_r
#else
#define	readdir_r		readdir64_r
#endif
#endif	/* _LP64 */
extern int readdir_r(DIR *_RESTRICT_KYWD, struct dirent *_RESTRICT_KYWD,
	struct dirent **_RESTRICT_KYWD);

#endif	/* !_LP64 && _FILE_OFFSET_BITS == 32 */

#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
/* transitional large file interface */
extern int readdir64_r(DIR *_RESTRICT_KYWD, struct dirent64 *_RESTRICT_KYWD,
	struct dirent64 **_RESTRICT_KYWD);
#endif

#endif /* defined(__EXTENSIONS__) || defined(_REENTRANT)... */

#ifdef	__cplusplus
}
#endif

#endif	/* _DIRENT_H */
