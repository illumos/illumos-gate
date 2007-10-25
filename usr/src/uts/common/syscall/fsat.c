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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/debug.h>

extern int openat(int, char *, int, int);
extern int renameat(int, char *, int, char *);
extern int unlinkat(int, char *, int);
extern int fchownat(int, char *, uid_t, gid_t, int);
extern int fstatat(int, char *, struct stat *, int);
extern int futimesat(int, char *, struct timeval *);
extern int accessat(int, char *, int);
extern int openattrdirat(int, char *);
#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
extern int fstatat64_32(int, char *, struct stat64_32 *, int);
extern int fstatat32(int, char *, struct stat32 *, int);
extern int openat32(int, char *, int, int);
extern int fstatat64(int, char *, struct stat64 *, int);
extern int openat64(int, char *, int, int);
extern int fstatat64_32(int, char *, struct stat64_32 *, int);
#endif


/*
 * Handle all of the *at system calls
 *
 * subcodes:
 * 0 - openat
 * 1 - openat64
 * 2 - fstatat64
 * 3 - fstatat
 * 4 - fchownat
 * 5 - unlinkat
 * 6 - futimesat
 * 7 - renameat
 * 8 - accessat
 * 9 - openattrdirat
 *
 * The code for handling the at functionality exists in the file where the
 * base syscall is defined.  For example openat is in open.c
 */

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)

int
fsat32(int code, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4, uintptr_t arg5)
{
	switch (code) {

	case 0: /* openat */
#if defined(_LP64)
		return (openat32((int)arg1, (char *)arg2,
		    (int)arg3, (int)arg4));
#else
		return (openat((int)arg1, (char *)arg2,
		    (int)arg3, (int)arg4));
#endif
	case 1: /* openat64 */
		return (openat64((int)arg1, (char *)arg2,
		    (int)arg3, (int)arg4));
	case 2: /* fstatat64 */
#if defined(_LP64)
		return (fstatat64_32((int)arg1, (char *)arg2,
		    (struct stat64_32 *)arg3, (int)arg4));
#else
		return (fstatat64((int)arg1, (char *)arg2,
		    (struct stat64 *)arg3, (int)arg4));
#endif
	case 3: /* fstatat */
#if defined(_LP64)
		return (fstatat32((int)arg1, (char *)arg2,
		    (struct stat32 *)arg3, (int)arg4));
#else
		return (fstatat((int)arg1, (char *)arg2,
		    (struct stat *)arg3, (int)arg4));
#endif
	case 4: /* fchownat */
		return (fchownat((int)arg1, (char *)arg2,
		    (uid_t)arg3, (gid_t)arg4, (int)arg5));
	case 5: /* unlinkat */
		return (unlinkat((int)arg1, (char *)arg2, (int)arg3));
	case 6: /* futimesat */
		return (futimesat((int)arg1,
		    (char *)arg2, (struct timeval *)arg3));
	case 7: /* renameat */
		return (renameat((int)arg1, (char *)arg2, (int)arg3,
		    (char *)arg4));
	case 8: /* accessat */
		return (accessat((int)arg1, (char *)arg2, (int)arg3));
	case 9: /* openattrdirat */
		return (openattrdirat((int)arg1, (char *)arg2));
	default:
		return (set_errno(EINVAL));
	}
}

#endif

/*
 * For 64 kernels, use fsat64
 */

#if defined(_LP64)

int
fsat64(int code, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4, uintptr_t arg5)
{
	switch (code) {

	case 0: /* openat */
		return (openat((int)arg1, (char *)arg2,
		    (int)arg3, (int)arg4));
	case 1: /* openat64 */
		return (set_errno(ENOSYS));
	case 2: /* fstatat64 */
		return (set_errno(ENOSYS));
	case 3: /* fstatat */
		return (fstatat((int)arg1, (char *)arg2,
		    (struct stat *)arg3, (int)arg4));
	case 4: /* fchownat */
		return (fchownat((int)arg1, (char *)arg2,
		    (uid_t)arg3, (gid_t)arg4, (int)arg5));
	case 5: /* unlinkat */
		return (unlinkat((int)arg1, (char *)arg2, (int)arg3));
	case 6: /* futimesat */
		return (futimesat((int)arg1,
		    (char *)arg2, (struct timeval *)arg3));
	case 7: /* renameat */
		return (renameat((int)arg1, (char *)arg2, (int)arg3,
		    (char *)arg4));
	case 8: /* accessat */
		return (accessat((int)arg1, (char *)arg2, (int)arg3));
	case 9: /* openattrdirat */
		return (openattrdirat((int)arg1, (char *)arg2));
	default:
		return (set_errno(EINVAL));
	}
}
#endif
