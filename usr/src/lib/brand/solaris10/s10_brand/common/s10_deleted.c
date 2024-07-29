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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/file.h>
#include <sys/syscall.h>

#include <s10_brand.h>
#include <brand_misc.h>
#include <s10_misc.h>

/*
 * This file contains the emulation functions for all of the
 * obsolete system call traps that existed in Solaris 10 but
 * that have been deleted in the current version of Solaris.
 */

static int
s10_fstatat(sysret_t *rval,
    int fd, const char *path, struct stat *sb, int flags)
{
	return (__systemcall(rval, SYS_fstatat + 1024,
	    fd, path, sb, flags));
}

int
s10_stat(sysret_t *rval, const char *path, struct stat *sb)
{
	return (__systemcall(rval, SYS_fstatat + 1024,
	    AT_FDCWD, path, sb, 0));
}

int
s10_lstat(sysret_t *rval, const char *path, struct stat *sb)
{
	return (__systemcall(rval, SYS_fstatat + 1024,
	    AT_FDCWD, path, sb, AT_SYMLINK_NOFOLLOW));
}

int
s10_fstat(sysret_t *rval, int filedes, struct stat *sb)
{
	return (__systemcall(rval, SYS_fstatat + 1024,
	    filedes, NULL, sb, 0));
}

#if !defined(_LP64)

static int
s10_fstatat64(sysret_t *rval,
    int fd, const char *path, struct stat64 *sb, int flags)
{
	return (__systemcall(rval, SYS_fstatat64 + 1024,
	    fd, path, sb, flags));
}

int
s10_stat64(sysret_t *rval, const char *path, struct stat64 *sb)
{
	return (__systemcall(rval, SYS_fstatat64 + 1024,
	    AT_FDCWD, path, sb, 0));
}

int
s10_lstat64(sysret_t *rval, const char *path, struct stat64 *sb)
{
	return (__systemcall(rval, SYS_fstatat64 + 1024,
	    AT_FDCWD, path, sb, AT_SYMLINK_NOFOLLOW));
}

int
s10_fstat64(sysret_t *rval, int filedes, struct stat64 *sb)
{
	return (__systemcall(rval, SYS_fstatat64 + 1024,
	    filedes, NULL, sb, 0));
}

#endif	/* !_LP64 */

static int
s10_openat(sysret_t *rval, int fd, const char *path, int oflag, mode_t mode)
{
	return (__systemcall(rval, SYS_openat + 1024,
	    fd, path, oflag, mode));
}

int
s10_open(sysret_t *rval, char *path, int oflag, mode_t mode)
{
	return (__systemcall(rval, SYS_openat + 1024,
	    AT_FDCWD, path, oflag, mode));
}

int
s10_creat(sysret_t *rval, char *path, mode_t mode)
{
	return (__systemcall(rval, SYS_openat + 1024,
	    AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, mode));
}

#if !defined(_LP64)

static int
s10_openat64(sysret_t *rval, int fd, const char *path, int oflag, mode_t mode)
{
	return (__systemcall(rval, SYS_openat64 + 1024,
	    fd, path, oflag, mode));
}

int
s10_open64(sysret_t *rval, char *path, int oflag, mode_t mode)
{
	return (__systemcall(rval, SYS_openat64 + 1024,
	    AT_FDCWD, path, oflag, mode));
}

int
s10_creat64(sysret_t *rval, char *path, mode_t mode)
{
	return (__systemcall(rval, SYS_openat64 + 1024,
	    AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, mode));
}

#endif	/* !_LP64 */

int
s10_fork1(sysret_t *rval)
{
	return (__systemcall(rval, SYS_forksys + 1024, 0, 0));
}

int
s10_forkall(sysret_t *rval)
{
	return (__systemcall(rval, SYS_forksys + 1024, 1, 0));
}

int
s10_dup(sysret_t *rval, int fd)
{
	return (__systemcall(rval, SYS_fcntl + 1024, fd, F_DUPFD, 0, 0));
}

int
s10_poll(sysret_t *rval, struct pollfd *fds, nfds_t nfd, int timeout)
{
	timespec_t ts;
	timespec_t *tsp;

	if (timeout < 0)
		tsp = NULL;
	else {
		ts.tv_sec = timeout / MILLISEC;
		ts.tv_nsec = (timeout % MILLISEC) * MICROSEC;
		tsp = &ts;
	}

	return (__systemcall(rval, SYS_pollsys + 1024,
	    fds, nfd, tsp, NULL));
}

int
s10_lwp_mutex_lock(sysret_t *rval, void *mp)
{
	return (__systemcall(rval, SYS_lwp_mutex_timedlock + 1024,
	    mp, NULL, 0));
}

int
s10_lwp_sema_wait(sysret_t *rval, void *sp)
{
	return (__systemcall(rval, SYS_lwp_sema_timedwait + 1024,
	    sp, NULL, 0));
}

int
s10_chmod(sysret_t *rval, const char *name, mode_t mode)
{
	return (__systemcall(rval, SYS_fchmodat + 1024,
	    AT_FDCWD, name, mode, 0));
}

int
s10_fchmod(sysret_t *rval, int filedes, mode_t mode)
{
	return (__systemcall(rval, SYS_fchmodat + 1024,
	    filedes, NULL, mode, 0));
}

static int
s10_fchownat(sysret_t *rval,
    int fd, const char *name, uid_t uid, gid_t gid, int flag)
{
	return (__systemcall(rval, SYS_fchownat + 1024,
	    fd, name, uid, gid, flag));
}

int
s10_chown(sysret_t *rval, const char *name, uid_t uid, gid_t gid)
{
	return (__systemcall(rval, SYS_fchownat + 1024,
	    AT_FDCWD, name, uid, gid, 0));
}

int
s10_lchown(sysret_t *rval, const char *name, uid_t uid, gid_t gid)
{
	return (__systemcall(rval, SYS_fchownat + 1024,
	    AT_FDCWD, name, uid, gid, AT_SYMLINK_NOFOLLOW));
}

int
s10_fchown(sysret_t *rval, int filedes, uid_t uid, gid_t gid)
{
	return (__systemcall(rval, SYS_fchownat + 1024,
	    filedes, NULL, uid, gid, 0));
}

int
s10_mkdir(sysret_t *rval, const char *dname, int dmode)
{
	return (__systemcall(rval, SYS_mkdirat + 1024,
	    AT_FDCWD, dname, dmode));
}

int
s10_mknod(sysret_t *rval, const char *fname, int fmode, dev_t dev)
{
	return (__systemcall(rval, SYS_mknodat + 1024,
	    AT_FDCWD, fname, fmode, dev));
}

int
s10_link(sysret_t *rval, const char *path1, const char *path2)
{
	return (__systemcall(rval, SYS_linkat + 1024,
	    AT_FDCWD, path1, AT_FDCWD, path2, 0));
}

static int
s10_unlinkat(sysret_t *rval, int fd, const char *name, int flags)
{
	return (__systemcall(rval, SYS_unlinkat + 1024,
	    fd, name, flags));
}

int
s10_unlink(sysret_t *rval, const char *name)
{
	return (__systemcall(rval, SYS_unlinkat + 1024,
	    AT_FDCWD, name, 0));
}

int
s10_rmdir(sysret_t *rval, const char *name)
{
	return (__systemcall(rval, SYS_unlinkat + 1024,
	    AT_FDCWD, name, AT_REMOVEDIR));
}

static int
s10_renameat(sysret_t *rval,
    int oldfd, const char *oldname, int newfd, const char *newname)
{
	return (__systemcall(rval, SYS_renameat + 1024,
	    oldfd, oldname, newfd, newname));
}

int
s10_rename(sysret_t *rval, const char *oldname, const char *newname)
{
	return (__systemcall(rval, SYS_renameat + 1024,
	    AT_FDCWD, oldname, AT_FDCWD, newname));
}

int
s10_symlink(sysret_t *rval, const char *path1, const char *path2)
{
	return (__systemcall(rval, SYS_symlinkat +  1024,
	    path1, AT_FDCWD, path2));
}

int
s10_readlink(sysret_t *rval, const char *path, char *buf, size_t bufsize)
{
	return (__systemcall(rval, SYS_readlinkat +  1024,
	    AT_FDCWD, path, buf, bufsize));
}

static int
s10_faccessat(sysret_t *rval, int fd, const char *fname, int amode, int flag)
{
	return (__systemcall(rval, SYS_faccessat + 1024,
	    fd, fname, amode, flag));
}

int
s10_access(sysret_t *rval, const char *fname, int amode)
{
	return (__systemcall(rval, SYS_faccessat + 1024,
	    AT_FDCWD, fname, amode, 0));
}

int
s10_utime(sysret_t *rval, const char *path, const struct utimbuf *times)
{
	struct utimbuf ltimes;
	timespec_t ts[2];
	timespec_t *tsp;

	if (times == NULL) {
		tsp = NULL;
	} else {
		if (brand_uucopy(times, &ltimes, sizeof (ltimes)) != 0)
			return (EFAULT);
		ts[0].tv_sec = ltimes.actime;
		ts[0].tv_nsec = 0;
		ts[1].tv_sec = ltimes.modtime;
		ts[1].tv_nsec = 0;
		tsp = ts;
	}

	return (__systemcall(rval, SYS_utimesys + 1024, 1,
	    AT_FDCWD, path, tsp, 0));
}

int
s10_utimes(sysret_t *rval, const char *path, const struct timeval times[2])
{
	struct timeval ltimes[2];
	timespec_t ts[2];
	timespec_t *tsp;

	if (times == NULL) {
		tsp = NULL;
	} else {
		if (brand_uucopy(times, ltimes, sizeof (ltimes)) != 0)
			return (EFAULT);
		ts[0].tv_sec = ltimes[0].tv_sec;
		ts[0].tv_nsec = ltimes[0].tv_usec * 1000;
		ts[1].tv_sec = ltimes[1].tv_sec;
		ts[1].tv_nsec = ltimes[1].tv_usec * 1000;
		tsp = ts;
	}

	return (__systemcall(rval, SYS_utimesys + 1024, 1,
	    AT_FDCWD, path, tsp, 0));
}

static int
s10_futimesat(sysret_t *rval,
    int fd, const char *path, const struct timeval times[2])
{
	struct timeval ltimes[2];
	timespec_t ts[2];
	timespec_t *tsp;

	if (times == NULL) {
		tsp = NULL;
	} else {
		if (brand_uucopy(times, ltimes, sizeof (ltimes)) != 0)
			return (EFAULT);
		ts[0].tv_sec = ltimes[0].tv_sec;
		ts[0].tv_nsec = ltimes[0].tv_usec * 1000;
		ts[1].tv_sec = ltimes[1].tv_sec;
		ts[1].tv_nsec = ltimes[1].tv_usec * 1000;
		tsp = ts;
	}

	if (path == NULL)
		return (__systemcall(rval, SYS_utimesys + 1024, 0, fd, tsp));

	return (__systemcall(rval, SYS_utimesys + 1024, 1, fd, path, tsp, 0));
}

#if defined(__x86)

/* ARGSUSED */
int
s10_xstat(sysret_t *rval, int version, const char *path, struct stat *statb)
{
#if defined(__amd64)
	return (EINVAL);
#else
	if (version != _STAT_VER)
		return (EINVAL);
	return (__systemcall(rval, SYS_fstatat + 1024,
	    AT_FDCWD, path, statb, 0));
#endif
}

/* ARGSUSED */
int
s10_lxstat(sysret_t *rval, int version, const char *path, struct stat *statb)
{
#if defined(__amd64)
	return (EINVAL);
#else
	if (version != _STAT_VER)
		return (EINVAL);
	return (__systemcall(rval, SYS_fstatat + 1024,
	    AT_FDCWD, path, statb, AT_SYMLINK_NOFOLLOW));
#endif
}

/* ARGSUSED */
int
s10_fxstat(sysret_t *rval, int version, int fd, struct stat *statb)
{
#if defined(__amd64)
	return (EINVAL);
#else
	if (version != _STAT_VER)
		return (EINVAL);
	return (__systemcall(rval, SYS_fstatat + 1024,
	    fd, NULL, statb, 0));
#endif
}

/* ARGSUSED */
int
s10_xmknod(sysret_t *rval, int version, const char *path,
    mode_t mode, dev_t dev)
{
#if defined(__amd64)
	return (EINVAL);
#else
	if (version != _MKNOD_VER)
		return (EINVAL);
	return (__systemcall(rval, SYS_mknodat + 1024,
	    AT_FDCWD, path, mode, dev));
#endif
}

#endif	/* __x86 */

/*
 * This is the fsat() system call trap in s10.
 * It has been removed in the current system.
 */
int
s10_fsat(sysret_t *rval,
    int code, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{
	switch (code) {
	case 0:		/* openat */
		return (s10_openat(rval, (int)arg1,
		    (const char *)arg2, (int)arg3, (mode_t)arg4));
	case 1:		/* openat64 */
#if defined(_LP64)
		return (EINVAL);
#else
		return (s10_openat64(rval, (int)arg1,
		    (const char *)arg2, (int)arg3, (mode_t)arg4));
#endif
	case 2:		/* fstatat64 */
#if defined(_LP64)
		return (EINVAL);
#else
		return (s10_fstatat64(rval, (int)arg1,
		    (const char *)arg2, (struct stat64 *)arg3, (int)arg4));
#endif
	case 3:		/* fstatat */
		return (s10_fstatat(rval, (int)arg1,
		    (const char *)arg2, (struct stat *)arg3, (int)arg4));
	case 4:		/* fchownat */
		return (s10_fchownat(rval, (int)arg1, (char *)arg2,
		    (uid_t)arg3, (gid_t)arg4, (int)arg5));
	case 5:		/* unlinkat */
		return (s10_unlinkat(rval, (int)arg1, (char *)arg2,
		    (int)arg3));
	case 6:		/* futimesat */
		return (s10_futimesat(rval, (int)arg1,
		    (const char *)arg2, (const struct timeval *)arg3));
	case 7:		/* renameat */
		return (s10_renameat(rval, (int)arg1, (char *)arg2,
		    (int)arg3, (char *)arg4));
	case 8:		/* faccessat */
		return (s10_faccessat(rval, (int)arg1, (char *)arg2,
		    (int)arg3, (int)arg4));
	case 9:		/* openattrdirat */
		return (s10_openat(rval, (int)arg1,
		    (const char *)arg2, FXATTRDIROPEN, 0));
	}
	return (EINVAL);
}

/*
 * Interposition upon SYS_umount
 */
int
s10_umount(sysret_t *rval, const char *path)
{
	return (__systemcall(rval, SYS_umount2 + 1024, path, 0));
}
