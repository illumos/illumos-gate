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

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/fstyp.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/pathname.h>
#include <sys/policy.h>
#include <sys/zone.h>

#define	UMOUNT2_SET_ERRNO(e, is_syscall) ((is_syscall) ? set_errno((e)) : (e))

/*
 * The heart of the umount2 call - it is pulled out to allow kernel
 * level particpation when the only reference is the vfs pointer.
 *
 * Note that some of the callers may not be in the context of a
 * syscall (created by zthread_create() for example) and as such
 * may not have an associated curthread->t_lwp. This is handled
 * by is_syscall.
 */
int
umount2_engine(vfs_t *vfsp, int flag, cred_t *cr, int is_syscall)
{
	int	error;

	/*
	 * Protect the call to vn_vfswlock() with the vfs reflock.  This
	 * ensures vfs_vnodecovered will either be NULL (because someone
	 * beat us to the umount) or valid (because vfs_lock() prevents
	 * another umount from getting through here until we've called
	 * vn_vfswlock() on the covered vnode).
	 *
	 * At one point, we did the non-blocking version (vfs_lock()),
	 * and if it failed, bailed out with EBUSY.  However, dounmount()
	 * calls vfs_lock_wait() and we drop the vfs lock before calling
	 * dounmount(), so there's no difference between waiting here
	 * for the lock or waiting there because grabbed it as soon as
	 * we drop it below.  No returning with EBUSY at this point
	 * reduces the number of spurious unmount failures that happen
	 * as a side-effect of fsflush() and other mount and unmount
	 * operations that might be going on simultaneously.
	 */
	vfs_lock_wait(vfsp);

	/*
	 * Call vn_vfswlock() on the covered vnode so that dounmount()
	 * can do its thing.  It will call the corresponding vn_vfsunlock().
	 * Note that vfsp->vfs_vnodecovered can be NULL here, either because
	 * someone did umount on "/" or because someone beat us to the umount
	 * before we did the vfs_lock() above.  In these cases, vn_vfswlock()
	 * returns EBUSY and we just pass that up.  Also note that we're
	 * looking at a vnode without doing a VN_HOLD() on it.  This is
	 * safe because it can't go away while something is mounted on it
	 * and we're locking out other umounts at this point.
	 */
	if (vn_vfswlock(vfsp->vfs_vnodecovered)) {
		vfs_unlock(vfsp);
		VFS_RELE(vfsp);
		return (UMOUNT2_SET_ERRNO(EBUSY, is_syscall));
	}

	/*
	 * Now that the VVFSLOCK in the covered vnode is protecting this
	 * path, we don't need the vfs reflock or the hold on the vfs anymore.
	 */
	vfs_unlock(vfsp);
	VFS_RELE(vfsp);

	/*
	 * Perform the unmount.
	 */
	if ((error = dounmount(vfsp, flag, cr)) != 0)
		return (UMOUNT2_SET_ERRNO(error, is_syscall));
	return (0);
}

/*
 * New umount() system call (for force unmount flag and perhaps others later).
 */
int
umount2(char *pathp, int flag)
{
	struct pathname pn;
	struct vfs *vfsp;
	int error;

	/*
	 * Some flags are disallowed through the system call interface.
	 */
	flag &= MS_UMOUNT_MASK;

	/*
	 * Lookup user-supplied name by trying to match it against the
	 * mount points recorded at mount time.  If no match is found
	 * (which can happen if the path to the mount point is specified
	 * differently between mount & umount, or if a block device were
	 * passed to umount) then we fall back to calling lookupname()
	 * to find the vfs.  Doing it this way prevents calling lookupname()
	 * in most cases and that allows forcible umount to work even if
	 * lookupname() would hang (i.e. because an NFS server is dead).
	 */

	if (error = pn_get(pathp, UIO_USERSPACE, &pn))
		return (set_errno(error));

	/*
	 * Only a privileged user is allowed to bypass the security
	 * checks done by lookupname() and use the results from
	 * vfs_mntpoint2vfsp() instead.  It could be argued that the
	 * proper check is FILE_DAC_SEARCH but we put it all
	 * under the mount privilege.  Also, make sure the caller
	 * isn't in an environment with an alternate root (to the zone's root)
	 * directory, i.e. chroot(2).
	 */
	if (secpolicy_fs_unmount(CRED(), NULL) != 0 ||
	    (PTOU(curproc)->u_rdir != NULL &&
	    PTOU(curproc)->u_rdir != curproc->p_zone->zone_rootvp) ||
	    (vfsp = vfs_mntpoint2vfsp(pn.pn_path)) == NULL) {
		vnode_t *fsrootvp;

		/* fall back to lookupname() on path given to us */
		if (error = lookupname(pn.pn_path, UIO_SYSSPACE, FOLLOW,
		    NULLVPP, &fsrootvp)) {
			pn_free(&pn);
			return (set_errno(error));
		}
		/*
		 * Find the vfs to be unmounted.  The caller may have specified
		 * either the directory mount point (preferred) or else (for a
		 * disk-based file system) the block device which was mounted.
		 * Check to see which it is; if it's the device, search the VFS
		 * list to find the associated vfs entry.
		 */
		if (fsrootvp->v_flag & VROOT) {
			vfsp = fsrootvp->v_vfsp;
			VFS_HOLD(vfsp);
		} else if (fsrootvp->v_type == VBLK)
			vfsp = vfs_dev2vfsp(fsrootvp->v_rdev);
		else
			vfsp = NULL;

		VN_RELE(fsrootvp);

		if (vfsp == NULL) {
			pn_free(&pn);
			return (set_errno(EINVAL));
		}
	}
	pn_free(&pn);

	return (umount2_engine(vfsp, flag, CRED(), 1));
}
