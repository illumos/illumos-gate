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
#include <sys/stat.h>
#include <sys/fcntl.h>

int
mknodat(int fd, const char *path, mode_t mode, dev_t dev)
{
	return (syscall(SYS_mknodat, fd, path, mode, dev));
}

#pragma weak _mknod = mknod
int
mknod(const char *path, mode_t mode, dev_t dev)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_mknod, path, mode, dev));
#else
	return (mknodat(AT_FDCWD, path, mode, dev));
#endif
}
