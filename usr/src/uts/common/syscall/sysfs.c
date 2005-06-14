/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/fstyp.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/buf.h>
#include <sys/debug.h>
#include <sys/pathname.h>

/*
 * System call to map fstype numbers to names, and vice versa.
 */

static int sysfsind(char *);
static int sysfstyp(int, char *);

int
sysfs(int opcode, long a1, long a2)
{
	int error;

	switch (opcode) {
	case GETFSIND:
		error = sysfsind((char *)a1);
		break;
	case GETFSTYP:
		error = sysfstyp((int)a1, (char *)a2);
		break;
	case GETNFSTYP:
		/*
		 * Return number of fstypes configured in the system.
		 */
		return (nfstype - 1);
	default:
		error = set_errno(EINVAL);
	}

	return (error);
}

static int
sysfsind(char *fsname)
{
	/*
	 * Translate fs identifier to an index into the vfssw structure.
	 */
	struct vfssw *vswp;
	char fsbuf[FSTYPSZ];
	int retval;
	size_t len = 0;

	retval = copyinstr(fsname, fsbuf, FSTYPSZ, &len);
	if (retval == ENOENT)			/* XXX */
		retval = EINVAL;		/* XXX */
	if (len == 1)			/* Includes null byte */
		retval = EINVAL;
	if (retval)
		return (set_errno(retval));
	/*
	 * Search the vfssw table for the fs identifier
	 * and return the index.
	 */
	if ((vswp = vfs_getvfssw(fsbuf)) != NULL) {
		retval = vswp - vfssw;
		vfs_unrefvfssw(vswp);
		return (retval);
	}

	return (set_errno(EINVAL));
}

static int
sysfstyp(int index, char *cbuf)
{
	/*
	 * Translate fstype index into an fs identifier.
	 */
	char *src;
	struct vfssw *vswp;
	char *osrc;
	int error = 0;

	if (index <= 0 || index >= nfstype)
		return (set_errno(EINVAL));
	RLOCK_VFSSW();
	vswp = &vfssw[index];

	osrc = src = vswp->vsw_name;
	while (*src++)
		;

	if (copyout(osrc, cbuf, src - osrc))
		error = set_errno(EFAULT);
	RUNLOCK_VFSSW();
	return (error);
}
