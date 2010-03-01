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
#include <sys/syscall.h>
#include <sys/fcntl.h>

int
renameat(int oldfd, const char *oldname, int newfd, const char *newname)
{
	return (syscall(SYS_renameat, oldfd, oldname, newfd, newname));
}

#pragma weak _rename = rename
int
rename(const char *oldname, const char *newname)
{
#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_rename, oldname, newname));
#else
	return (renameat(AT_FDCWD, oldname, AT_FDCWD, newname));
#endif
}
