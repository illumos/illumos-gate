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
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/mode.h>
#include <sys/uio.h>
#include <sys/mkdev.h>
#include <sys/policy.h>
#include <sys/debug.h>
#include <c2/audit.h>

/*
 * Create a special file, a regular file, or a FIFO.
 * fname - pathname passed by user
 * fmode - mode of pathname
 * dev = device number - b/c specials only
 */
int
mknodat(int fd, char *fname, mode_t fmode, dev_t dev)
{
	vnode_t *startvp;
	vnode_t *vp;
	struct vattr vattr;
	int error;
	enum create why;

	/*
	 * Zero type is equivalent to a regular file.
	 */
	if ((fmode & S_IFMT) == 0)
		fmode |= S_IFREG;

	/*
	 * Must be privileged unless making a FIFO node.
	 */
	if (((fmode & S_IFMT) != S_IFIFO) && secpolicy_sys_devices(CRED()) != 0)
		return (set_errno(EPERM));
	/*
	 * Set up desired attributes and vn_create the file.
	 */
	vattr.va_type = IFTOVT(fmode);
	vattr.va_mode = fmode & MODEMASK;
	vattr.va_mask = AT_TYPE|AT_MODE;
	if (vattr.va_type == VCHR || vattr.va_type == VBLK) {
		if (get_udatamodel() != DATAMODEL_NATIVE)
			dev = expldev(dev);
		if (dev == NODEV || (getemajor(dev)) == (major_t)NODEV)
			return (set_errno(EINVAL));
		vattr.va_rdev = dev;
		vattr.va_mask |= AT_RDEV;
	}

	if (fname == NULL)
		return (set_errno(EFAULT));
	if ((error = fgetstartvp(fd, fname, &startvp)) != 0)
		return (set_errno(error));
	if (AU_AUDITING() && startvp != NULL)
		audit_setfsat_path(1);

	why = ((fmode & S_IFMT) == S_IFDIR) ? CRMKDIR : CRMKNOD;
	error = vn_createat(fname, UIO_USERSPACE, &vattr, EXCL, 0, &vp,
	    why, 0,  PTOU(curproc)->u_cmask, startvp);
	if (startvp != NULL)
		VN_RELE(startvp);
	if (error)
		return (set_errno(error));
	VN_RELE(vp);
	return (0);
}

int
mknod(char *fname, mode_t fmode, dev_t dev)
{
	return (mknodat(AT_FDCWD, fname, fmode, dev));
}
