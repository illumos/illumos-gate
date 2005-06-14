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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/user.h>
#include <sys/fstyp.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/dnlc.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/swap.h>
#include <sys/debug.h>
#include <sys/pathname.h>
#include <sys/cladm.h>

/*
 * System calls.
 */

/*
 * "struct mounta" defined in sys/vfs.h.
 */

/* ARGSUSED */
int
mount(long *lp, rval_t *rp)
{
	vnode_t *vp = NULL;
	struct vfs *vfsp;	/* dummy argument */
	int error;
	struct mounta *uap;
#if defined(_LP64)
	struct mounta native;

	/*
	 * Make a struct mounta if we are DATAMODEL_LP64
	 */
	uap = &native;
	uap->spec = (char *)*lp++;
	uap->dir = (char *)*lp++;
	uap->flags = (int)*lp++;
	uap->fstype = (char *)*lp++;
	uap->dataptr = (char *)*lp++;
	uap->datalen = (int)*lp++;
	uap->optptr = (char *)*lp++;
	uap->optlen = (int)*lp++;
#else	/* !defined(_LP64) */
	/*
	 * 32 bit kernels can take a shortcut and just cast
	 * the args array to the structure.
	 */
	uap = (struct mounta *)lp;
#endif	/* _LP64 */
	/*
	 * Resolve second path name (mount point).
	 */
	if (error = lookupname(uap->dir, UIO_USERSPACE, FOLLOW, NULLVPP, &vp))
		return (set_errno(error));

	/*
	 * Some mount flags are disallowed through the system call interface.
	 */
	uap->flags &= MS_MASK;

	if ((vp->v_flag & VPXFS) && ((uap->flags & MS_GLOBAL) != MS_GLOBAL)) {
		/*
		 * Clustering: if we're doing a mount onto the global
		 * namespace, and the mount is not a global mount, return
		 * an error.
		 */
		error = ENOTSUP;
	} else if (uap->flags & MS_GLOBAL) {
		/*
		 * Clustering: global mount specified.
		 */
		if ((cluster_bootflags & CLUSTER_BOOTED) == 0) {
			/*
			 * If we're not booted as a cluster,
			 * global mounts are not allowed.
			 */
			error = ENOTSUP;
		} else {
			error = domount("pxfs", uap, vp, CRED(), &vfsp);
			if (!error)
				VFS_RELE(vfsp);
		}
	} else {
		error = domount(NULL, uap, vp, CRED(), &vfsp);
		if (!error)
			VFS_RELE(vfsp);
	}
	VN_RELE(vp);
	rp->r_val2 = error;
	return (error ? set_errno(error) : 0);
}
