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
#include <sys/cred.h>
#include <sys/user.h>
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
#include <sys/poll.h>
#include <sys/kmem.h>
#include <sys/filio.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>
#include <sys/zone.h>

#include <sys/debug.h>
#include <c2/audit.h>
#include <fs/fs_subr.h>

/*
 * Change current working directory (".").
 */
static int	chdirec(vnode_t *, int ischroot, int do_traverse);

int
chdir(char *fname)
{
	vnode_t *vp;
	int error;
	int estale_retry = 0;

lookup:
	if (error = lookupname(fname, UIO_USERSPACE, FOLLOW, NULLVPP, &vp)) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		return (set_errno(error));
	}

	error = chdirec(vp, 0, 1);
	if (error) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		return (set_errno(error));
	}
	return (0);
}

/*
 * File-descriptor based version of 'chdir'.
 */
int
fchdir(int fd)
{
	vnode_t *vp;
	file_t *fp;
	int error;

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));
	vp = fp->f_vnode;
	VN_HOLD(vp);
	releasef(fd);
	error = chdirec(vp, 0, 0);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * Change notion of root ("/") directory.
 */
int
chroot(char *fname)
{
	vnode_t *vp;
	int error;
	int estale_retry = 0;

lookup:
	if (error = lookupname(fname, UIO_USERSPACE, FOLLOW, NULLVPP, &vp)) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		return (set_errno(error));
	}

	error = chdirec(vp, 1, 1);
	if (error) {
		if ((error == ESTALE) && fs_need_estale_retry(estale_retry++))
			goto lookup;
		return (set_errno(error));
	}
	return (0);
}

/*
 *	++++++++++++++++++++++++
 *	++  SunOS4.1 Buyback  ++
 *	++++++++++++++++++++++++
 * Change root directory with a user given fd
 */
int
fchroot(int fd)
{
	vnode_t *vp;
	file_t *fp;
	int error;

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));
	vp = fp->f_vnode;
	VN_HOLD(vp);
	releasef(fd);
	error = chdirec(vp, 1, 0);
	if (error)
		return (set_errno(error));
	return (0);
}

static int
chdirec(vnode_t *vp, int ischroot, int do_traverse)
{
	int error;
	vnode_t *oldvp;
	proc_t *pp = curproc;
	vnode_t **vpp;
	refstr_t *cwd;
	int newcwd = 1;

	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto bad;
	}
	if (error = VOP_ACCESS(vp, VEXEC, 0, CRED(), NULL))
		goto bad;

	/*
	 * The VOP_ACCESS() may have covered 'vp' with a new filesystem,
	 * if 'vp' is an autoFS vnode. Traverse the mountpoint so
	 * that we don't end up with a covered current directory.
	 */
	if (vn_mountedvfs(vp) != NULL && do_traverse) {
		if (error = traverse(&vp))
			goto bad;
	}

	/*
	 * Special chroot semantics: chroot is allowed if privileged
	 * or if the target is really a loopback mount of the root (or
	 * root of the zone) as determined by comparing dev and inode
	 * numbers
	 */
	if (ischroot) {
		struct vattr tattr;
		struct vattr rattr;
		vnode_t *zonevp = curproc->p_zone->zone_rootvp;

		tattr.va_mask = AT_FSID|AT_NODEID;
		if (error = VOP_GETATTR(vp, &tattr, 0, CRED(), NULL))
			goto bad;

		rattr.va_mask = AT_FSID|AT_NODEID;
		if (error = VOP_GETATTR(zonevp, &rattr, 0, CRED(), NULL))
			goto bad;

		if ((tattr.va_fsid != rattr.va_fsid ||
		    tattr.va_nodeid != rattr.va_nodeid) &&
		    (error = secpolicy_chroot(CRED())) != 0)
			goto bad;

		vpp = &PTOU(pp)->u_rdir;
	} else {
		vpp = &PTOU(pp)->u_cdir;
	}

	/* update abs cwd/root path see c2/audit.c */
	if (AU_AUDITING())
		audit_chdirec(vp, vpp);

	mutex_enter(&pp->p_lock);
	/*
	 * This bit of logic prevents us from overwriting u_cwd if we are
	 * changing to the same directory.  We set the cwd to NULL so that we
	 * don't try to do the lookup on the next call to getcwd().
	 */
	if (!ischroot && *vpp != NULL && vp != NULL && VN_CMP(*vpp, vp))
		newcwd = 0;

	oldvp = *vpp;
	*vpp = vp;
	if ((cwd = PTOU(pp)->u_cwd) != NULL && newcwd)
		PTOU(pp)->u_cwd = NULL;
	mutex_exit(&pp->p_lock);

	if (cwd && newcwd)
		refstr_rele(cwd);
	if (oldvp)
		VN_RELE(oldvp);
	return (0);

bad:
	VN_RELE(vp);
	return (error);
}
