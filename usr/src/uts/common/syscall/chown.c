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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * nmflag has the following values
 *
 * 1 - Always do lookup.  i.e. chown, lchown.
 * 2 - Name is optional i.e. fchownat
 * 0 - Don't lookup name, vp is in file_p. i.e. fchown
 *
 */
int
cfchownat(int fd, char *name, int nmflag, uid_t uid, gid_t gid, int flags)
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

	if (nmflag == 1 || (nmflag == 2 && name != NULL)) {
		if (copyin(name, &startchar, sizeof (char)))
			return (set_errno(EFAULT));
	} else
		startchar = '\0';


	if (fd == AT_FDCWD)
		startvp = NULL;
	else {
		/*
		 * only get fd if not doing absolute lookup
		 */
		if (startchar != '/' || nmflag == 0) {
			if ((filefp = getf(fd)) == NULL) {
				return (set_errno(EBADF));
			}
			startvp = filefp->f_vnode;
			VN_HOLD(startvp);
			releasef(fd);
		} else {
			startvp = NULL;
		}
	}

	if ((nmflag == 2) && audit_active)
		audit_setfsat_path(1);

	/*
	 * Do lookups for chown, lchown and fchownat when name not NULL
	 */
	if ((nmflag == 2 && name != NULL) || nmflag == 1) {
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
/*
 * Change ownership of file given file name.
 */
int
chown(char *fname, uid_t uid, gid_t gid)
{
	return (cfchownat(AT_FDCWD, fname, 1, uid, gid, 0));
}

int
lchown(char *fname, uid_t uid, gid_t gid)
{
	return (cfchownat(AT_FDCWD, fname, 1, uid, gid, AT_SYMLINK_NOFOLLOW));
}

/*
 * Change ownership of file given file descriptor.
 */
int
fchown(int fd, uid_t uid, uid_t gid)
{
	return (cfchownat(fd, NULL, 0, uid, gid, 0));
}

int
fchownat(int fd, char *name, uid_t uid, gid_t gid, int flags)
{
	return (cfchownat(fd, name, 2, uid, gid, flags));

}
