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

#pragma weak _unlinkat = unlinkat
int
unlinkat(int fd, const char *name, int flags)
{
	return (syscall(SYS_unlinkat, fd, name, flags));
}

#pragma weak _unlink = unlink
int
unlink(const char *name)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_unlink, name));
#else
	return (unlinkat(AT_FDCWD, name, 0));
#endif
}

#pragma weak _rmdir = rmdir
int
rmdir(const char *name)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_rmdir, name));
#else
	return (unlinkat(AT_FDCWD, name, AT_REMOVEDIR));
#endif
}
