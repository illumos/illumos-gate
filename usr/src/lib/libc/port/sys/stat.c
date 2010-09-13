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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64

#pragma weak _fstatat64 = fstatat64
int
fstatat64(int fd, const char *name, struct stat64 *sb, int flags)
{
	return (syscall(SYS_fstatat64, fd, name, sb, flags));
}

#pragma weak _stat64 = stat64
int
stat64(const char *name, struct stat64 *sb)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_stat64, name, sb));
#else
	return (fstatat64(AT_FDCWD, name, sb, 0));
#endif
}

#pragma weak _lstat64 = lstat64
int
lstat64(const char *name, struct stat64 *sb)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_lstat64, name, sb));
#else
	return (fstatat64(AT_FDCWD, name, sb, AT_SYMLINK_NOFOLLOW));
#endif
}

#pragma weak _fstat64 = fstat64
int
fstat64(int fd, struct stat64 *sb)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_fstat64, fd, sb));
#else
	return (fstatat64(fd, NULL, sb, 0));
#endif
}

#else	/* !defined(_LP64) && _FILE_OFFSET_BITS == 64 */

#pragma weak _fstatat = fstatat
int
fstatat(int fd, const char *name, struct stat *sb, int flags)
{
	return (syscall(SYS_fstatat, fd, name, sb, flags));
}

#pragma weak _stat = stat
int
stat(const char *name, struct stat *sb)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_stat, name, sb));
#else
	return (fstatat(AT_FDCWD, name, sb, 0));
#endif
}

#pragma weak _lstat = lstat
int
lstat(const char *name, struct stat *sb)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_lstat, name, sb));
#else
	return (fstatat(AT_FDCWD, name, sb, AT_SYMLINK_NOFOLLOW));
#endif
}

#pragma weak _fstat = fstat
int
fstat(int fd, struct stat *sb)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_fstat, fd, sb));
#else
	return (fstatat(fd, NULL, sb, 0));
#endif
}

#endif	/* !defined(_LP64) && _FILE_OFFSET_BITS == 64 */
