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
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

extern	int __xpg4; /* defined in port/gen/xpg4.c; 0 if not xpg4/xpg4v2 */

int
linkat(int fd1, const char *path1, int fd2, const char *path2, int flag)
{
	return (syscall(SYS_linkat, fd1, path1, fd2, path2, flag));
}

#pragma	weak _link = link
int
link(const char *path1, const char *path2)
{
	/*
	 * XPG4v2 link() requires that the link count of a symbolic
	 * link target be updated rather than the link itself.  This
	 * matches SunOS 4.x and other BSD based implementations.
	 * However, the SVR4 merge apparently introduced the change
	 * that allowed link(src, dest) when "src" was a symbolic link,
	 * to create "dest" as a hard link to "src".  Hence, the link
	 * count of the symbolic link is updated rather than the target
	 * of the symbolic link. This latter behavior remains for
	 * non-XPG4 based environments. For a more detailed discussion,
	 * see bug 1256170.
	 */
	if (__xpg4 != 0)
		return (linkat(AT_FDCWD, path1, AT_FDCWD, path2,
		    AT_SYMLINK_FOLLOW));

#if defined(_RETAIN_OLD_SYSCALLS)
	return (syscall(SYS_link, path1, path2));
#else
	return (linkat(AT_FDCWD, path1, AT_FDCWD, path2, 0));
#endif
}
