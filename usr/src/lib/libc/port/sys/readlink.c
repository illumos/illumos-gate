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

#include "lint.h"
#include <sys/syscall.h>
#include <sys/unistd.h>
#include <sys/fcntl.h>

ssize_t
readlinkat(int fd, const char *path, char *buf, size_t bufsize)
{
	sysret_t rval;
	int error;

	error = __systemcall(&rval, SYS_readlinkat, fd, path, buf, bufsize);
	if (error)
		(void) __set_errno(error);
	return ((ssize_t)rval.sys_rval1);
}

#pragma weak _readlink = readlink
ssize_t
readlink(const char *path, char *buf, size_t bufsize)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	sysret_t rval;
	int error;

	error = __systemcall(&rval, SYS_readlink, path, buf, bufsize);
	if (error)
		(void) __set_errno(error);
	return ((ssize_t)rval.sys_rval1);
#else
	return (readlinkat(AT_FDCWD, path, buf, bufsize));
#endif
}
