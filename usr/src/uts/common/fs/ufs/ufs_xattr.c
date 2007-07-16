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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/dnlc.h>
#include <sys/pathname.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/mount.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_panic.h>
#include <sys/fs/ufs_quota.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <vm/seg.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/unistd.h>

int
ufs_xattr_getattrdir(
	vnode_t *dvp,
	struct inode **sip,
	int flags,
	struct cred *cr)
{
	struct vfs	*vfsp;
	struct inode	*ip, *sdp;
	int		error;

	ip = VTOI(dvp);
	if (flags & LOOKUP_XATTR) {
		if (ip && ((ip->i_oeftflag) != 0)) {
			vfsp = dvp->v_vfsp;

			error = ufs_iget(vfsp, ip->i_oeftflag, sip, cr);
			if (error)
				return (error);

			sdp = *sip;

			/*
			 * Make sure it really is an ATTRDIR
			 */
			if ((sdp->i_mode & IFMT) != IFATTRDIR) {
				cmn_err(CE_NOTE, "ufs_getattrdir: inode %d"
				    " points to attribute directory %d "
				    "which is not an attribute directory;"
				    "run fsck on file system",
				    (int)ip->i_number, (int)sdp->i_number);
				VN_RELE(ITOV(sdp));
				return (ENOENT);
			}
			ITOV(sdp)->v_type = VDIR;
			ITOV(sdp)->v_flag |= V_XATTRDIR;
			error = 0;
			goto out;
		} else if (flags & CREATE_XATTR_DIR) {
			error = ufs_xattrmkdir(ip, sip, 1, cr);
		} else {
			error = ENOENT;
				goto out;
		}

	} else if (flags & CREATE_XATTR_DIR) {
		error = ufs_xattrmkdir(ip, sip, 1, cr);
	} else {
		error = ENOENT;
	}
out:
	return (error);
}


/*
 * Unhook an attribute directory from a parent file/dir
 * Only do so, if we are the only user of the vnode.
 */
void
ufs_unhook_shadow(struct inode *ip, struct inode *sip)
{
	struct vnode		*datavp = ITOV(ip);
	struct vnode		*dirvp = ITOV(sip);
	int			hno;
	kmutex_t		*ihm;

	ASSERT(RW_WRITE_HELD(&sip->i_contents));
	ASSERT(RW_WRITE_HELD(&ip->i_contents));

	if (vn_is_readonly(ITOV(ip)))
		return;

	if (ip->i_ufsvfs == NULL || sip->i_ufsvfs == NULL)
		return;

	hno = INOHASH(ip->i_number);
	ihm = &ih_lock[hno];
	mutex_enter(ihm);

	mutex_enter(&datavp->v_lock);
	mutex_enter(&dirvp->v_lock);

	if (dirvp->v_count != 1 && datavp->v_count != 1) {
		mutex_exit(&dirvp->v_lock);
		mutex_exit(&datavp->v_lock);
		mutex_exit(ihm);
		return;
	}

	/*
	 * Delete shadow from ip
	 */

	sip->i_nlink -= 2;
	ufs_setreclaim(sip);
	TRANS_INODE(sip->i_ufsvfs, sip);
	sip->i_flag |= ICHG;
	sip->i_seq++;
	ITIMES_NOLOCK(sip);

	/*
	 * Update src file
	 */
	ip->i_oeftflag = 0;
	TRANS_INODE(ip->i_ufsvfs, ip);
	ip->i_flag |= ICHG;
	ip->i_seq++;
	ufs_iupdat(ip, 1);
	mutex_exit(&dirvp->v_lock);
	mutex_exit(&datavp->v_lock);
	mutex_exit(ihm);
}
