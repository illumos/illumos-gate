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

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <c2/audit.h>

/*
 * Unlink a file from a directory
 */
int
unlinkat(int fd, char *name, int flags)
{
	vnode_t *startvp;
	int error;

	if (name == NULL)
		return (set_errno(EFAULT));
	if ((error = fgetstartvp(fd, name, &startvp)) != 0)
		return (set_errno(error));
	if (AU_AUDITING() && startvp != NULL)
		audit_setfsat_path(1);

	error = vn_removeat(startvp, name, UIO_USERSPACE,
	    (flags == AT_REMOVEDIR) ? RMDIRECTORY : RMFILE);
	if (startvp != NULL)
		VN_RELE(startvp);
	if (error)
		return (set_errno(error));
	return (0);
}

int
unlink(char *name)
{
	return (unlinkat(AT_FDCWD, name, 0));
}

int
rmdir(char *name)
{
	return (unlinkat(AT_FDCWD, name, AT_REMOVEDIR));
}
