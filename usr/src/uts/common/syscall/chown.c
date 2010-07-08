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
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/var.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/mode.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/debug.h>
#include <c2/audit.h>

/*
 * Change ownership of file.
 */
int
fchownat(int fd, char *path, uid_t uid, gid_t gid, int flag)
{
	struct vattr 	vattr;
	int 		error;
	struct zone	*zone = crgetzone(CRED());

	if (uid != (uid_t)-1 && !VALID_UID(uid, zone) ||
	    gid != (gid_t)-1 && !VALID_GID(gid, zone)) {
		return (set_errno(EINVAL));
	}
	vattr.va_uid = uid;
	vattr.va_gid = gid;
	vattr.va_mask = 0;
	if (vattr.va_uid != -1)
		vattr.va_mask |= AT_UID;
	if (vattr.va_gid != -1)
		vattr.va_mask |= AT_GID;

	error = fsetattrat(fd, path, flag, &vattr);
	if (error)
		return (set_errno(error));
	return (0);
}

int
chown(char *path, uid_t uid, gid_t gid)
{
	return (fchownat(AT_FDCWD, path, uid, gid, 0));
}

int
lchown(char *path, uid_t uid, gid_t gid)
{
	return (fchownat(AT_FDCWD, path, uid, gid, AT_SYMLINK_NOFOLLOW));
}

int
fchown(int fd, uid_t uid, uid_t gid)
{
	return (fchownat(fd, NULL, uid, gid, 0));
}
