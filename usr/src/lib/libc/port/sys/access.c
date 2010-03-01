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
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/fcntl.h>

int
faccessat(int fd, const char *fname, int amode, int flag)
{
	return (syscall(SYS_faccessat, fd, fname, amode, flag));
}

#pragma weak _access = access
int
access(const char *fname, int amode)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_access, fname, amode));
#else
	return (faccessat(AT_FDCWD, fname, amode, 0));
#endif
}
