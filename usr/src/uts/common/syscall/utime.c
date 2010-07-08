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
#include <sys/stat.h>
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

static int
cfutimesat(int fd, char *fname, int nmflag, vattr_t *vap, int flags, int follow)
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
	} else {
		startchar = '\0';
	}

	if (fd == AT_FDCWD) {
		startvp = NULL;
	} else {
		/*
		 * is this absolute path?
		 */
		if (startchar != '/') {
			if ((fp = getf(fd)) == NULL)
				return (set_errno(EBADF));
			startvp = fp->f_vnode;
			VN_HOLD(startvp);
			releasef(fd);
		} else {
			startvp = NULL;
		}
	}

	if ((nmflag == 1) || ((nmflag == 2) && (fname != NULL))) {
		if (AU_AUDITING() && startvp != NULL)
			audit_setfsat_path(1);
		if ((error = lookupnameat(fname, UIO_USERSPACE,
		    follow, NULLVPP, &vp, startvp)) != 0) {
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
	return (0);
}

static int
get_timespec_vattr(timespec_t *tsptr, struct vattr *vattr, int *flags)
{
	timespec_t ts[2];
	timespec_t now;
	uint_t mask;

	if (tsptr != NULL) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyin(tsptr, ts, sizeof (ts)))
				return (EFAULT);
		} else {
			timespec32_t ts32[2];

			if (copyin(tsptr, ts32, sizeof (ts32)))
				return (EFAULT);
			TIMESPEC32_TO_TIMESPEC(&ts[0], &ts32[0]);
			TIMESPEC32_TO_TIMESPEC(&ts[1], &ts32[1]);
		}
		if (ts[0].tv_nsec == UTIME_NOW || ts[1].tv_nsec == UTIME_NOW)
			gethrestime(&now);
		mask = 0;
		if (ts[0].tv_nsec == UTIME_OMIT) {
			ts[0].tv_nsec = 0;
		} else {
			mask |= AT_ATIME;
			if (ts[0].tv_nsec == UTIME_NOW)
				ts[0] = now;
			else if (ts[0].tv_nsec < 0 || ts[0].tv_nsec >= NANOSEC)
				return (EINVAL);
		}
		if (ts[1].tv_nsec == UTIME_OMIT) {
			ts[1].tv_nsec = 0;
		} else {
			mask |= AT_MTIME;
			if (ts[1].tv_nsec == UTIME_NOW)
				ts[1] = now;
			else if (ts[1].tv_nsec < 0 || ts[1].tv_nsec >= NANOSEC)
				return (EINVAL);
		}
		vattr->va_atime = ts[0];
		vattr->va_mtime = ts[1];
		vattr->va_mask = mask;
		*flags = ATTR_UTIME;
	} else {
		gethrestime(&now);
		vattr->va_atime = now;
		vattr->va_mtime = now;
		vattr->va_mask = AT_ATIME | AT_MTIME;
		*flags = 0;
	}

	return (0);
}

int
futimens(int fd, timespec_t *tsptr)
{
	struct vattr vattr;
	int flags;
	int error;

	if ((error = get_timespec_vattr(tsptr, &vattr, &flags)) != 0)
		return (set_errno(error));

	return (cfutimesat(fd, NULL, 2, &vattr, flags, FOLLOW));
}

int
utimensat(int fd, char *fname, timespec_t *tsptr, int flag)
{
	struct vattr vattr;
	int flags;
	int error;

	if ((error = get_timespec_vattr(tsptr, &vattr, &flags)) != 0)
		return (set_errno(error));

	return (cfutimesat(fd, fname, 1, &vattr, flags,
	    (flag & AT_SYMLINK_NOFOLLOW)? NO_FOLLOW : FOLLOW));
}

int
utimesys(int code,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{
	switch (code) {
	case 0:
		return (futimens((int)arg1, (timespec_t *)arg2));
	case 1:
		return (utimensat((int)arg1, (char *)arg2,
		    (timespec_t *)arg3, (int)arg4));
	default:
		return (set_errno(EINVAL));
	}
}
