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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/time.h>
#include <sys/debug.h>
#include <sys/model.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <c2/audit.h>

extern int	namesetattr(char *, enum symfollow, vattr_t *, int);
extern int	fdsetattr(int, vattr_t *);

static int
cfutimesat(int fd, char *fname, int nmflag, vattr_t *vap, int flags)
{

	file_t *fp;
	vnode_t *startvp, *vp;
	int error;
	char startchar;

	if (fd == AT_FDCWD && fname == NULL)
		return (set_errno(EFAULT));

	if (nmflag == 1 || (nmflag == 2 && fname != NULL)) {
		if (copyin(fname, &startchar, sizeof (char)))
			return (set_errno(EFAULT));
	} else
		startchar = '\0';

	if (fd == AT_FDCWD)
		startvp = NULL;
	else {

		/*
		 * is this absolute path?
		 */
		if (startchar != '/') {
			if ((fp = getf(fd)) == NULL) {
				return (set_errno(EBADF));
			}
			startvp = fp->f_vnode;
			VN_HOLD(startvp);
			releasef(fd);
		} else {
			startvp = NULL;
		}
	}

	if (audit_active)
		audit_setfsat_path(1);

	if ((nmflag == 1) || ((nmflag == 2) && (fname != NULL))) {
		if (error = lookupnameat(fname, UIO_USERSPACE, FOLLOW,
		    NULLVPP, &vp, startvp)) {
			if (startvp != NULL)
				VN_RELE(startvp);
			return (set_errno(error));
		}
	} else {
		vp = startvp;
		VN_HOLD(vp);
	}

	if (startvp != NULL) {
		VN_RELE(startvp);
	}

	if (vn_is_readonly(vp)) {
		error = EROFS;
	} else {
		error = VOP_SETATTR(vp, vap, flags, CRED(), NULL);
	}

	VN_RELE(vp);
	if (error != 0)
		return (set_errno(error));
	else
		return (0);
}

static int
get_utimesvattr(struct timeval *tvptr, struct vattr *vattr, int *flags)
{
	struct timeval tv[2];

	*flags = 0;

	if (tvptr != NULL) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyin(tvptr, tv, sizeof (tv)))
				return (EFAULT);
		} else {
			struct timeval32 tv32[2];

			if (copyin(tvptr, tv32, sizeof (tv32)))
				return (EFAULT);

			TIMEVAL32_TO_TIMEVAL(&tv[0], &tv32[0]);
			TIMEVAL32_TO_TIMEVAL(&tv[1], &tv32[1]);
		}

		if (tv[0].tv_usec < 0 || tv[0].tv_usec >= 1000000 ||
		    tv[1].tv_usec < 0 || tv[1].tv_usec >= 1000000)
			return (EINVAL);

		vattr->va_atime.tv_sec = tv[0].tv_sec;
		vattr->va_atime.tv_nsec = tv[0].tv_usec * 1000;
		vattr->va_mtime.tv_sec = tv[1].tv_sec;
		vattr->va_mtime.tv_nsec = tv[1].tv_usec * 1000;
		*flags |= ATTR_UTIME;
	} else {
		gethrestime(&vattr->va_atime);
		vattr->va_mtime = vattr->va_atime;
	}
	vattr->va_mask = AT_ATIME | AT_MTIME;

	return (0);
}
int
futimesat(int fd, char *fname, struct timeval *tvptr)
{
	struct vattr vattr;
	int flags = 0;
	int error;

	if ((error = get_utimesvattr(tvptr, &vattr, &flags)) != 0)
		return (set_errno(error));

	return (cfutimesat(fd, fname, 2, &vattr, flags));
}
/*
 * Set access/modify times on named file.
 */
int
utime(char *fname, time_t *tptr)
{
	time_t tv[2];
	struct vattr vattr;
	int flags = 0;

	if (tptr != NULL) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyin(tptr, tv, sizeof (tv)))
				return (set_errno(EFAULT));
		} else {
			time32_t tv32[2];

			if (copyin(tptr, &tv32, sizeof (tv32)))
				return (set_errno(EFAULT));

			tv[0] = (time_t)tv32[0];
			tv[1] = (time_t)tv32[1];
		}

		vattr.va_atime.tv_sec = tv[0];
		vattr.va_atime.tv_nsec = 0;
		vattr.va_mtime.tv_sec = tv[1];
		vattr.va_mtime.tv_nsec = 0;
		flags |= ATTR_UTIME;
	} else {
		gethrestime(&vattr.va_atime);
		vattr.va_mtime = vattr.va_atime;
	}

	vattr.va_mask = AT_ATIME|AT_MTIME;
	return (cfutimesat(AT_FDCWD, fname, 1, &vattr, flags));
}

/*
 * SunOS4.1 Buyback:
 * Set access/modify time on named file, with hi res timer
 */
int
utimes(char *fname, struct timeval *tvptr)
{
	struct vattr vattr;
	int flags = 0;
	int error;

	if ((error = get_utimesvattr(tvptr, &vattr, &flags)) != 0)
		return (set_errno(error));

	return (cfutimesat(AT_FDCWD, fname, 1, &vattr, flags));
}
