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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/dirent.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/mode.h>
#include <sys/uio.h>
#include <sys/filio.h>
#include <sys/debug.h>

/*
 * Change mode of file.
 */
int
fchmodat(int fd, char *path, int mode, int flag)
{
	struct vattr vattr;
	int error;

	if (flag & ~AT_SYMLINK_NOFOLLOW)
		return (set_errno(EINVAL));

	if (flag & AT_SYMLINK_NOFOLLOW)
		return (set_errno(EOPNOTSUPP));

	vattr.va_mode = mode & MODEMASK;
	vattr.va_mask = AT_MODE;
	error = fsetattrat(fd, path, flag, &vattr);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * Change mode of file given path name.
 */
int
chmod(char *path, int mode)
{
	return (fchmodat(AT_FDCWD, path, mode, 0));
}

/*
 * Change mode of file given file descriptor.
 */
int
fchmod(int fd, int mode)
{
	return (fchmodat(fd, NULL, mode, 0));
}
