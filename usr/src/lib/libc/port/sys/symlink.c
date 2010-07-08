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

int
symlinkat(const char *path1, int fd, const char *path2)
{
	return (syscall(SYS_symlinkat, path1, fd, path2));
}

#pragma weak _symlink = symlink
int
symlink(const char *path1, const char *path2)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_symlink, path1, path2));
#else
	return (symlinkat(path1, AT_FDCWD, path2));
#endif
}
