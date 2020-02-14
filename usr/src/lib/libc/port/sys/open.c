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
 *
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#include "lint.h"
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include "libc.h"

int
__openat(int dfd, const char *path, int oflag, mode_t mode)
{
	return (syscall(SYS_openat, dfd, path, oflag, mode));
}

int
__open(const char *path, int oflag, mode_t mode)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_open, path, oflag, mode));
#else
	return (__openat(AT_FDCWD, path, oflag, mode));
#endif
}

#if !defined(_LP64)

int
__openat64(int dfd, const char *path, int oflag, mode_t mode)
{
	return (syscall(SYS_openat64, dfd, path, oflag, mode));
}

int
__open64(const char *path, int oflag, mode_t mode)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_open64, path, oflag, mode));
#else
	return (__openat64(AT_FDCWD, path, oflag, mode));
#endif
}

#endif	/* !_LP64 */
