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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/fcntl.h>

#pragma weak _fchownat = fchownat
int
fchownat(int fd, const char *name, uid_t uid, gid_t gid, int flags)
{
	return (syscall(SYS_fchownat, fd, name, uid, gid, flags));
}

#pragma weak _chown = chown
int
chown(const char *name, uid_t uid, gid_t gid)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_chown, name, uid, gid));
#else
	return (fchownat(AT_FDCWD, name, uid, gid, 0));
#endif
}

#pragma weak _lchown = lchown
int
lchown(const char *name, uid_t uid, gid_t gid)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_lchown, name, uid, gid));
#else
	return (fchownat(AT_FDCWD, name, uid, gid, AT_SYMLINK_NOFOLLOW));
#endif
}

#pragma weak _fchown = fchown
int
fchown(int filedes, uid_t uid, gid_t gid)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_fchown, filedes, uid, gid));
#else
	return (fchownat(filedes, NULL, uid, gid, 0));
#endif
}
