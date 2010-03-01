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
fchownat(int fd, char *name, uid_t uid, gid_t gid, int flags)
{
	vnode_t		*startvp, *vp;
	file_t 		*filefp;
	struct vattr 	vattr;
	int 		error = 0;
	char 		startchar;
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


	if (fd == AT_FDCWD && name == NULL)
		return (set_errno(EFAULT));

	if (name != NULL) {
		if (copyin(name, &startchar, sizeof (char)))
			return (set_errno(EFAULT));
	} else {
		startchar = '\0';
	}


	if (fd == AT_FDCWD)
		startvp = NULL;
	else {
		/*
		 * only get fd if not doing absolute lookup
		 */
		if (startchar != '/') {
			if ((filefp = getf(fd)) == NULL)
				return (set_errno(EBADF));
			startvp = filefp->f_vnode;
			VN_HOLD(startvp);
			releasef(fd);
		} else {
			startvp = NULL;
		}
	}

	if (audit_active)
		audit_setfsat_path(1);

	/*
	 * Do lookup for fchownat when name not NULL
	 */
	if (name != NULL) {
		if (error = lookupnameat(name, UIO_USERSPACE,
		    (flags == AT_SYMLINK_NOFOLLOW) ?
		    NO_FOLLOW : FOLLOW,
		    NULLVPP, &vp, startvp)) {
			if (startvp != NULL)
				VN_RELE(startvp);
			return (set_errno(error));
		}
	} else {
		vp = startvp;
		ASSERT(vp);
		VN_HOLD(vp);
	}

	if (vn_is_readonly(vp)) {
		error = EROFS;
	} else {
		error = VOP_SETATTR(vp, &vattr, 0, CRED(), NULL);
	}

	if (startvp != NULL)
		VN_RELE(startvp);
	if (vp != NULL)
		VN_RELE(vp);

	if (error != 0)
		return (set_errno(error));
	else
		return (error);
}

int
chown(char *fname, uid_t uid, gid_t gid)
{
	return (fchownat(AT_FDCWD, fname, uid, gid, 0));
}

int
lchown(char *fname, uid_t uid, gid_t gid)
{
	return (fchownat(AT_FDCWD, fname, uid, gid, AT_SYMLINK_NOFOLLOW));
}

int
fchown(int fd, uid_t uid, uid_t gid)
{
	return (fchownat(fd, NULL, uid, gid, 0));
}
