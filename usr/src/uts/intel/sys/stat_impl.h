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

#ifndef _SYS_STAT_IMPL_H
#define	_SYS_STAT_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/feature_tests.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_KERNEL)

#if defined(__i386)
/*
 * The implementation specific header for <sys/stat.h>
 * When compiling outside of the large file environment, the *stat source
 * symbols must lead to calls to corresponding _x*stat functions that supply
 * an initial version number argument identifying which binary stat structure
 * representation to use.  In the large file compilation environment, the
 * intermediate _x*stat functions and version numbers are unnecessary.
 * Instead, the source symbols map onto invocations of corresponding *stat64
 * functions with identical arguments.
 */

#if defined(__STDC__)

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) || \
	defined(_ATFILE_SOURCE)
extern int fstatat(int, const char *, struct stat *, int);
#endif /* defined (_ATFILE_SOURCE) */

#if _FILE_OFFSET_BITS == 32 && !defined(_LP64) && !defined(__lint)
static int fstat(int, struct stat *);
static int stat(const char *_RESTRICT_KYWD, struct stat *_RESTRICT_KYWD);
int _fxstat(const int, int, struct stat *);
int _xstat(const int, const char *, struct stat *);
#else
extern int fstat(int, struct stat *);
extern int stat(const char *_RESTRICT_KYWD, struct stat *_RESTRICT_KYWD);
#endif

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)
#if _FILE_OFFSET_BITS == 32 && !defined(_LP64) && !defined(__lint)
static int lstat(const char *_RESTRICT_KYWD, struct stat *_RESTRICT_KYWD);
#else
extern int lstat(const char *_RESTRICT_KYWD, struct stat *_RESTRICT_KYWD);
#endif
#if !defined(_LP64) && !defined(__lint)
static int mknod(const char *, mode_t, dev_t);
#else
extern int mknod(const char *, mode_t, dev_t);
#endif
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2)... */

#if !defined(_LP64) && (!defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || \
	defined(__EXTENSIONS__))
#if _FILE_OFFSET_BITS == 32
int _lxstat(const int, const char *, struct stat *);
#endif
int _xmknod(const int, const char *, mode_t, dev_t);
#endif /* !defined(_LP64) && (!defined(__XOPEN_OR_POSIX)... */


#else	/* !__STDC__ */

extern int fstatat();


#if _FILE_OFFSET_BITS == 32 && !defined(_LP64) && !defined(__lint)
static int fstat(), stat();
int _fxstat(), _xstat();
#else
extern int fstat(), stat();
#endif
#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)
#if _FILE_OFFSET_BITS == 32 && !defined(_LP64) && !defined(__lint)
static int lstat();
#else
extern int lstat();
#endif
#if !defined(_LP64) && !defined(__lint)
static int mknod();
#else
extern int mknod();
#endif
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) ... */

#if !defined(_LP64) && (!defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || \
	defined(__EXTENSIONS__))
#if _FILE_OFFSET_BITS == 32
int _lxstat();
#endif
int _xmknod();
#endif /* !defined(_LP64) && (!defined(__XOPEN_OR_POSIX) ... */

#endif /* defined(__STDC__) */

/*
 * NOTE: Application software should NOT program
 * to the _xstat interface.
 */

#if _FILE_OFFSET_BITS == 32 && !defined(_LP64) && !defined(__lint)

static int
#ifdef __STDC__
stat(const char *_RESTRICT_KYWD _path, struct stat *_RESTRICT_KYWD _buf)
#else
stat(_path, _buf)
char *_path;
struct stat *_buf;
#endif
{
	return (_xstat(_STAT_VER, _path, _buf));
}

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)
static int
#ifdef __STDC__
lstat(const char *_RESTRICT_KYWD _path, struct stat *_RESTRICT_KYWD _buf)
#else
lstat(_path, _buf)
char *_path;
struct stat *_buf;
#endif
{
	return (_lxstat(_STAT_VER, _path, _buf));
}
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2)... */

static int
#ifdef __STDC__
fstat(int _fd, struct stat *_buf)
#else
fstat(_fd, _buf)
int _fd;
struct stat *_buf;
#endif
{
	return (_fxstat(_STAT_VER, _fd, _buf));
}

#endif	/* _FILE_OFFSET_BITS == 32 && !defined(_LP64) ... */

#if !defined(_LP64) && !defined(__lint) && (!defined(__XOPEN_OR_POSIX) || \
	defined(_XPG4_2) || defined(__EXTENSIONS__))
static int
#ifdef __STDC__
mknod(const char *_path, mode_t _mode, dev_t _dev)
#else
mknod(_path, _mode, _dev)
char *_path;
mode_t _mode;
dev_t _dev;
#endif
{
	return (_xmknod(_MKNOD_VER, _path, _mode, _dev));
}
#endif /* !defined(_LP64) && !defined(__lint) && ... */

#else	/* !__i386 */

#if defined(__STDC__)

extern int fstat(int, struct stat *);
extern int stat(const char *_RESTRICT_KYWD, struct stat *_RESTRICT_KYWD);
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) || \
	defined(_ATFILE_SOURCE)
extern int fstatat(int, const char *, struct stat *, int);
#endif /* defined (_ATFILE_SOURCE) */

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)
extern int lstat(const char *_RESTRICT_KYWD, struct stat *_RESTRICT_KYWD);
extern int mknod(const char *, mode_t, dev_t);
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) ... */

#else	/* !__STDC__ */

extern int fstat(), stat(), fstatat();

#if !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2) || defined(__EXTENSIONS__)
extern int lstat(), mknod();
#endif /* !defined(__XOPEN_OR_POSIX) || defined(_XPG4_2)... */

#endif	/* !__STDC__ */

#endif	/* !__i386 */

#endif /* !defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STAT_IMPL_H */
