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

#include <sys/isa_defs.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/sysmacros.h>
#include "libproc.h"

#ifdef _LP64
/*
 * in case of 64-bit *stat() and *stat64 library call and 32-bit subject
 * process convert 64-bit struct stat/stat64 into 32-bit struct stat64
 */
static void
stat64_32_to_n(struct stat64_32 *src, struct stat *dest)
{
	(void) memset(dest, 0, sizeof (*dest));
	dest->st_dev = DEVEXPL(src->st_dev);
	dest->st_ino = (ino_t)src->st_ino;
	dest->st_mode = (mode_t)src->st_mode;
	dest->st_nlink = (nlink_t)src->st_nlink;
	dest->st_uid = (uid_t)src->st_uid;
	dest->st_gid = (gid_t)src->st_gid;
	dest->st_rdev = DEVEXPL(src->st_rdev);
	dest->st_size = (off_t)src->st_size;
	TIMESPEC32_TO_TIMESPEC(&dest->st_atim, &src->st_atim);
	TIMESPEC32_TO_TIMESPEC(&dest->st_mtim, &src->st_mtim);
	TIMESPEC32_TO_TIMESPEC(&dest->st_ctim, &src->st_ctim);
	dest->st_blksize = (blksize_t)src->st_blksize;
	dest->st_blocks = (blkcnt_t)src->st_blocks;
	(void) memcpy(dest->st_fstype, src->st_fstype,
	    sizeof (dest->st_fstype));
}
#endif	/* _LP64 */

/*
 * stat() system call -- executed by subject process
 */
int
pr_stat(struct ps_prochandle *Pr, const char *path, struct stat *buf)
{
	sysret_t rval;			/* return value from stat() */
	argdes_t argd[4];		/* arg descriptors for fstatat() */
	argdes_t *adp = &argd[0];	/* first argument */
	int syscall;			/* SYS_fstatat or SYS_fstatat64 */
	int error;
#ifdef _LP64
	struct stat64_32 statb64_32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (stat(path, buf));

	if (Pstatus(Pr)->pr_dmodel != PR_MODEL_NATIVE) {
		/* 64-bit process controls 32-bit subject process */
		syscall = SYS_fstatat64;
	} else {
		syscall = SYS_fstatat;
	}

	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to path argument */

	adp->arg_value = 0;
	adp->arg_object = (void *)path;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(path) + 1;
	adp++;			/* move to buffer argument */

	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		adp->arg_object = &statb64_32;
		adp->arg_size = sizeof (statb64_32);
	} else {
		adp->arg_object = buf;
		adp->arg_size = sizeof (*buf);
	}
#else	/* _LP64 */
	adp->arg_object = buf;
	adp->arg_size = sizeof (*buf);
#endif	/* _LP64 */
	adp++;			/* move to flags argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, syscall, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		stat64_32_to_n(&statb64_32, buf);
#endif	/* _LP64 */
	return (0);
}

/*
 * lstat() system call -- executed by subject process
 */
int
pr_lstat(struct ps_prochandle *Pr, const char *path, struct stat *buf)
{
	sysret_t rval;			/* return value from stat() */
	argdes_t argd[4];		/* arg descriptors for fstatat() */
	argdes_t *adp = &argd[0];	/* first argument */
	int syscall;			/* SYS_fstatat or SYS_fstatat64 */
	int error;
#ifdef _LP64
	struct stat64_32 statb64_32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (lstat(path, buf));

	if (Pstatus(Pr)->pr_dmodel != PR_MODEL_NATIVE) {
		/* 64-bit process controls 32-bit subject process */
		syscall = SYS_fstatat64;
	} else {
		syscall = SYS_fstatat;
	}

	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to path argument */

	adp->arg_value = 0;
	adp->arg_object = (void *)path;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(path) + 1;
	adp++;			/* move to buffer argument */

	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		adp->arg_object = &statb64_32;
		adp->arg_size = sizeof (statb64_32);
	} else {
		adp->arg_object = buf;
		adp->arg_size = sizeof (*buf);
	}
#else	/* _LP64 */
	adp->arg_object = buf;
	adp->arg_size = sizeof (*buf);
#endif	/* _LP64 */
	adp++;			/* move to flags argument */

	adp->arg_value = AT_SYMLINK_NOFOLLOW;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, syscall, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		stat64_32_to_n(&statb64_32, buf);
#endif	/* _LP64 */
	return (0);
}

/*
 * fstat() system call -- executed by subject process
 */
int
pr_fstat(struct ps_prochandle *Pr, int fd, struct stat *buf)
{
	sysret_t rval;			/* return value from stat() */
	argdes_t argd[4];		/* arg descriptors for fstatat() */
	argdes_t *adp = &argd[0];	/* first argument */
	int syscall;			/* SYS_fstatat or SYS_fstatat64 */
	int error;
#ifdef _LP64
	struct stat64_32 statb64_32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (fstat(fd, buf));

	if (Pstatus(Pr)->pr_dmodel != PR_MODEL_NATIVE) {
		/* 64-bit process controls 32-bit subject process */
		syscall = SYS_fstatat64;
	} else {
		syscall = SYS_fstatat;
	}

	adp->arg_value = fd;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to path argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to buffer argument */

	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		adp->arg_object = &statb64_32;
		adp->arg_size = sizeof (statb64_32);
	} else {
		adp->arg_object = buf;
		adp->arg_size = sizeof (*buf);
	}
#else	/* _LP64 */
	adp->arg_object = buf;
	adp->arg_size = sizeof (*buf);
#endif	/* _LP64 */
	adp++;			/* move to flags argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, syscall, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		stat64_32_to_n(&statb64_32, buf);
#endif	/* _LP64 */
	return (0);
}

/*
 * stat64() system call -- executed by subject process
 */
int
pr_stat64(struct ps_prochandle *Pr, const char *path, struct stat64 *buf)
{
	sysret_t rval;			/* return value from stat() */
	argdes_t argd[4];		/* arg descriptors for fstatat() */
	argdes_t *adp = &argd[0];	/* first argument */
	int syscall;			/* SYS_fstatat or SYS_fstatat64 */
	int error;
#ifdef _LP64
	struct stat64_32 statb64_32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (stat64(path, buf));

	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		/*
		 * 32-bit native and
		 * 64-bit process controls 32-bit subject process
		 */
		syscall = SYS_fstatat64;
	} else {
		/* 64-bit native */
		syscall = SYS_fstatat;
	}

	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to path argument */

	adp->arg_value = 0;
	adp->arg_object = (void *)path;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(path) + 1;
	adp++;			/* move to buffer argument */

	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		adp->arg_object = &statb64_32;
		adp->arg_size = sizeof (statb64_32);
	} else {
		adp->arg_object = buf;
		adp->arg_size = sizeof (*buf);
	}
#else	/* _LP64 */
	adp->arg_object = buf;
	adp->arg_size = sizeof (*buf);
#endif	/* _LP64 */
	adp++;			/* move to flags argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, syscall, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		stat64_32_to_n(&statb64_32, (struct stat *)buf);
#endif	/* _LP64 */
	return (0);
}

/*
 * lstat64() system call -- executed by subject process
 */
int
pr_lstat64(struct ps_prochandle *Pr, const char *path, struct stat64 *buf)
{
	sysret_t rval;			/* return value from stat() */
	argdes_t argd[4];		/* arg descriptors for fstatat() */
	argdes_t *adp = &argd[0];	/* first argument */
	int syscall;			/* SYS_fstatat or SYS_fstatat64 */
	int error;
#ifdef _LP64
	struct stat64_32 statb64_32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (lstat64(path, buf));

	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		/*
		 * 32-bit native and
		 * 64-bit process controls 32-bit subject process
		 */
		syscall = SYS_fstatat64;
	} else {
		/* 64-bit native */
		syscall = SYS_fstatat;
	}

	adp->arg_value = AT_FDCWD;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to path argument */

	adp->arg_value = 0;
	adp->arg_object = (void *)path;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = strlen(path) + 1;
	adp++;			/* move to buffer argument */

	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		adp->arg_object = &statb64_32;
		adp->arg_size = sizeof (statb64_32);
	} else {
		adp->arg_object = buf;
		adp->arg_size = sizeof (*buf);
	}
#else	/* _LP64 */
	adp->arg_object = buf;
	adp->arg_size = sizeof (*buf);
#endif	/* _LP64 */
	adp++;			/* move to flags argument */

	adp->arg_value = AT_SYMLINK_NOFOLLOW;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, syscall, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		stat64_32_to_n(&statb64_32, (struct stat *)buf);
#endif	/* _LP64 */
	return (0);
}

/*
 * fstat64() system call -- executed by subject process
 */
int
pr_fstat64(struct ps_prochandle *Pr, int fd, struct stat64 *buf)
{
	sysret_t rval;			/* return value from stat() */
	argdes_t argd[4];		/* arg descriptors for fstatat() */
	argdes_t *adp = &argd[0];	/* first argument */
	int syscall;			/* SYS_fstatat or SYS_fstatat64 */
	int error;
#ifdef _LP64
	struct stat64_32 statb64_32;
#endif	/* _LP64 */

	if (Pr == NULL)		/* no subject process */
		return (fstat64(fd, buf));

	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		/*
		 * 32-bit native and
		 * 64-bit process controls 32-bit subject process
		 */
		syscall = SYS_fstatat64;
	} else {
		/* 64-bit native */
		syscall = SYS_fstatat;
	}

	adp->arg_value = fd;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to path argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;			/* move to buffer argument */

	adp->arg_value = 0;
	adp->arg_type = AT_BYREF;
	adp->arg_inout = AI_OUTPUT;
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		adp->arg_object = &statb64_32;
		adp->arg_size = sizeof (statb64_32);
	} else {
		adp->arg_object = buf;
		adp->arg_size = sizeof (*buf);
	}
#else	/* _LP64 */
	adp->arg_object = buf;
	adp->arg_size = sizeof (*buf);
#endif	/* _LP64 */
	adp++;			/* move to flags argument */

	adp->arg_value = 0;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;

	error = Psyscall(Pr, &rval, syscall, 4, &argd[0]);

	if (error) {
		errno = (error > 0)? error : ENOSYS;
		return (-1);
	}
#ifdef _LP64
	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32)
		stat64_32_to_n(&statb64_32, (struct stat *)buf);
#endif	/* _LP64 */
	return (0);
}
