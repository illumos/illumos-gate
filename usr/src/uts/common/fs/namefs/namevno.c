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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * This file defines the vnode operations for mounted file descriptors.
 * The routines in this file act as a layer between the NAMEFS file
 * system and SPECFS/FIFOFS.  With the exception of nm_open(), nm_setattr(),
 * nm_getattr() and nm_access(), the routines simply apply the VOP operation
 * to the vnode representing the file descriptor.  This switches control
 * to the underlying file system to which the file descriptor belongs.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/pcb.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <vm/seg.h>
#include <sys/fs/namenode.h>
#include <sys/stream.h>
#include <fs/fs_subr.h>
#include <sys/policy.h>

/*
 * Create a reference to the vnode representing the file descriptor.
 * Then, apply the VOP_OPEN operation to that vnode.
 *
 * The vnode for the file descriptor may be switched under you.
 * If it is, search the hash list for an nodep - nodep->nm_filevp
 * pair. If it exists, return that nodep to the user.
 * If it does not exist, create a new namenode to attach
 * to the nodep->nm_filevp then place the pair on the hash list.
 *
 * Newly created objects are like children/nodes in the mounted
 * file system, with the parent being the initial mount.
 */
int
nm_open(vnode_t **vpp, int flag, cred_t *crp, caller_context_t *ct)
{
	struct namenode *nodep = VTONM(*vpp);
	int error = 0;
	struct namenode *newnamep;
	struct vnode *newvp;
	struct vnode *infilevp;
	struct vnode *outfilevp;

	/*
	 * If the vnode is switched under us, the corresponding
	 * VN_RELE for this VN_HOLD will be done by the file system
	 * performing the switch. Otherwise, the corresponding
	 * VN_RELE will be done by nm_close().
	 */
	infilevp = outfilevp = nodep->nm_filevp;
	VN_HOLD(outfilevp);

	if ((error = VOP_OPEN(&outfilevp, flag, crp, ct)) != 0) {
		VN_RELE(outfilevp);
		return (error);
	}
	if (infilevp != outfilevp) {
		/*
		 * See if the new filevp (outfilevp) is already associated
		 * with the mount point. If it is, then it already has a
		 * namenode associated with it.
		 */
		mutex_enter(&ntable_lock);
		if ((newnamep =
		    namefind(outfilevp, nodep->nm_mountpt)) != NULL) {
			struct vnode *vp = NMTOV(newnamep);

			VN_HOLD(vp);
			goto gotit;
		}

		newnamep = kmem_zalloc(sizeof (struct namenode), KM_SLEEP);
		newvp = vn_alloc(KM_SLEEP);
		newnamep->nm_vnode = newvp;

		mutex_init(&newnamep->nm_lock, NULL, MUTEX_DEFAULT, NULL);

		mutex_enter(&nodep->nm_lock);
		newvp->v_flag = ((*vpp)->v_flag | VNOMAP | VNOSWAP) & ~VROOT;
		vn_setops(newvp, vn_getops(*vpp));
		newvp->v_vfsp = &namevfs;
		newvp->v_stream = outfilevp->v_stream;
		newvp->v_type = outfilevp->v_type;
		newvp->v_rdev = outfilevp->v_rdev;
		newvp->v_data = (caddr_t)newnamep;
		vn_exists(newvp);
		bcopy(&nodep->nm_vattr, &newnamep->nm_vattr, sizeof (vattr_t));
		newnamep->nm_vattr.va_type = outfilevp->v_type;
		newnamep->nm_vattr.va_nodeid = namenodeno_alloc();
		newnamep->nm_vattr.va_size = (u_offset_t)0;
		newnamep->nm_vattr.va_rdev = outfilevp->v_rdev;
		newnamep->nm_flag = NMNMNT;
		newnamep->nm_filevp = outfilevp;
		newnamep->nm_filep = nodep->nm_filep;
		newnamep->nm_mountpt = nodep->nm_mountpt;
		mutex_exit(&nodep->nm_lock);

		/*
		 * Insert the new namenode into the hash list.
		 */
		nameinsert(newnamep);
gotit:
		mutex_exit(&ntable_lock);
		/*
		 * Release the above reference to the infilevp, the reference
		 * to the NAMEFS vnode, create a reference to the new vnode
		 * and return the new vnode to the user.
		 */
		VN_RELE(*vpp);
		*vpp = NMTOV(newnamep);
	}
	return (0);
}

/*
 * Close a mounted file descriptor.
 * Remove any locks and apply the VOP_CLOSE operation to the vnode for
 * the file descriptor.
 */
static int
nm_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *crp,
	caller_context_t *ct)
{
	struct namenode *nodep = VTONM(vp);
	int error = 0;

	(void) cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	error = VOP_CLOSE(nodep->nm_filevp, flag, count, offset, crp, ct);
	if (count == 1) {
		(void) VOP_FSYNC(nodep->nm_filevp, FSYNC, crp, ct);
		/*
		 * Before VN_RELE() we need to remove the vnode from
		 * the hash table.  We should only do so in the  NMNMNT case.
		 * In other cases, nodep->nm_filep keeps a reference
		 * to nm_filevp and the entry in the hash table doesn't
		 * hurt.
		 */
		if ((nodep->nm_flag & NMNMNT) != 0) {
			mutex_enter(&ntable_lock);
			nameremove(nodep);
			mutex_exit(&ntable_lock);
		}
		VN_RELE(nodep->nm_filevp);
	}
	return (error);
}

static int
nm_read(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *crp,
	caller_context_t *ct)
{
	return (VOP_READ(VTONM(vp)->nm_filevp, uiop, ioflag, crp, ct));
}

static int
nm_write(vnode_t *vp, struct uio *uiop, int ioflag, cred_t *crp,
	caller_context_t *ct)
{
	return (VOP_WRITE(VTONM(vp)->nm_filevp, uiop, ioflag, crp, ct));
}

static int
nm_ioctl(vnode_t *vp, int cmd, intptr_t arg, int mode, cred_t *cr, int *rvalp,
	caller_context_t *ct)
{
	return (VOP_IOCTL(VTONM(vp)->nm_filevp, cmd, arg, mode, cr, rvalp, ct));
}

/*
 * Return in vap the attributes that are stored in the namenode
 * structure.  Only the size is taken from the mounted object.
 */
/* ARGSUSED */
static int
nm_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *crp,
	caller_context_t *ct)
{
	struct namenode *nodep = VTONM(vp);
	struct vattr va;
	int error;

	mutex_enter(&nodep->nm_lock);
	bcopy(&nodep->nm_vattr, vap, sizeof (vattr_t));
	mutex_exit(&nodep->nm_lock);

	if ((va.va_mask = vap->va_mask & AT_SIZE) != 0) {
		if (error = VOP_GETATTR(nodep->nm_filevp, &va, flags, crp, ct))
			return (error);
		vap->va_size = va.va_size;
	}

	return (0);
}

/*
 * Standard access() like check.  Figure out which mode bits apply
 * to the caller then pass the missing mode bits to the secpolicy function.
 */
static int
nm_access_unlocked(void *vnp, int mode, cred_t *crp)
{
	struct namenode *nodep = vnp;
	int shift = 0;

	if (crgetuid(crp) != nodep->nm_vattr.va_uid) {
		shift += 3;
		if (!groupmember(nodep->nm_vattr.va_gid, crp))
			shift += 3;
	}

	return (secpolicy_vnode_access2(crp, NMTOV(nodep),
	    nodep->nm_vattr.va_uid, nodep->nm_vattr.va_mode << shift,
	    mode));
}
/*
 * Set the attributes of the namenode from the attributes in vap.
 */
/* ARGSUSED */
static int
nm_setattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *crp,
	caller_context_t *ctp)
{
	struct namenode *nodep = VTONM(vp);
	struct vattr *nmvap = &nodep->nm_vattr;
	long mask = vap->va_mask;
	int error = 0;

	/*
	 * Cannot set these attributes.
	 */
	if (mask & (AT_NOSET|AT_SIZE))
		return (EINVAL);

	(void) VOP_RWLOCK(nodep->nm_filevp, V_WRITELOCK_TRUE, ctp);
	mutex_enter(&nodep->nm_lock);

	/*
	 * Change ownership/group/time/access mode of mounted file
	 * descriptor.
	 */

	error = secpolicy_vnode_setattr(crp, vp, vap, nmvap, flags,
	    nm_access_unlocked, nodep);
	if (error)
		goto out;

	mask = vap->va_mask;
	/*
	 * If request to change mode, copy new
	 * mode into existing attribute structure.
	 */
	if (mask & AT_MODE)
		nmvap->va_mode = vap->va_mode & ~VSVTX;

	/*
	 * If request was to change user or group, turn off suid and sgid
	 * bits.
	 * If the system was configured with the "rstchown" option, the
	 * owner is not permitted to give away the file, and can change
	 * the group id only to a group of which they are a member.
	 */
	if (mask & AT_UID)
		nmvap->va_uid = vap->va_uid;
	if (mask & AT_GID)
		nmvap->va_gid = vap->va_gid;
	/*
	 * If request is to modify times, make sure user has write
	 * permissions on the file.
	 */
	if (mask & AT_ATIME)
		nmvap->va_atime = vap->va_atime;
	if (mask & AT_MTIME) {
		nmvap->va_mtime = vap->va_mtime;
		gethrestime(&nmvap->va_ctime);
	}
out:
	mutex_exit(&nodep->nm_lock);
	VOP_RWUNLOCK(nodep->nm_filevp, V_WRITELOCK_TRUE, ctp);
	return (error);
}

/*
 * Check mode permission on the namenode.  First nm_access_unlocked()
 * checks the bits on the name node, then an access check is performed
 * on the underlying file.
 */
/* ARGSUSED */
static int
nm_access(vnode_t *vp, int mode, int flags, cred_t *crp,
	caller_context_t *ct)
{
	struct namenode *nodep = VTONM(vp);
	int error;

	mutex_enter(&nodep->nm_lock);
	error = nm_access_unlocked(nodep, mode, crp);
	mutex_exit(&nodep->nm_lock);
	if (error == 0)
		return (VOP_ACCESS(nodep->nm_filevp, mode, flags, crp, ct));
	else
		return (error);
}

/*
 * We can get here if a creat or open with O_CREAT is done on a namefs
 * mount point, for example, as the object of a shell output redirection to
 * the mount point.
 */
/*ARGSUSED*/
static int
nm_create(vnode_t *dvp, char *name, vattr_t *vap, enum vcexcl excl,
	int mode, vnode_t **vpp, cred_t *cr, int flag,
	caller_context_t *ct, vsecattr_t *vsecp)
{
	int error;

	ASSERT(dvp && *name == '\0');
	if (excl == NONEXCL) {
		if (mode && (error = nm_access(dvp, mode, 0, cr, ct)) != 0)
			return (error);
		VN_HOLD(dvp);
		return (0);
	}
	return (EEXIST);
}

/*
 * Links are not allowed on mounted file descriptors.
 */
/*ARGSUSED*/
static int
nm_link(vnode_t *tdvp, vnode_t *vp, char *tnm, cred_t *crp,
	caller_context_t *ct, int flags)
{
	return (EXDEV);
}

static int
nm_fsync(vnode_t *vp, int syncflag, cred_t *crp, caller_context_t *ct)
{
	return (VOP_FSYNC(VTONM(vp)->nm_filevp, syncflag, crp, ct));
}

/* Free the namenode */
/* ARGSUSED */
static void
nm_inactive(vnode_t *vp, cred_t *crp, caller_context_t *ct)
{
	struct namenode *nodep = VTONM(vp);
	vfs_t *vfsp = vp->v_vfsp;

	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);
	if (--vp->v_count != 0) {
		mutex_exit(&vp->v_lock);
		return;
	}
	mutex_exit(&vp->v_lock);
	if (!(nodep->nm_flag & NMNMNT)) {
		ASSERT(nodep->nm_filep->f_vnode == nodep->nm_filevp);
		(void) closef(nodep->nm_filep);
	}
	vn_invalid(vp);
	vn_free(vp);
	if (vfsp != &namevfs)
		VFS_RELE(vfsp);
	namenodeno_free(nodep->nm_vattr.va_nodeid);
	kmem_free(nodep, sizeof (struct namenode));
}

static int
nm_fid(vnode_t *vp, struct fid *fidnodep, caller_context_t *ct)
{
	return (VOP_FID(VTONM(vp)->nm_filevp, fidnodep, ct));
}

static int
nm_rwlock(vnode_t *vp, int write, caller_context_t *ctp)
{
	return (VOP_RWLOCK(VTONM(vp)->nm_filevp, write, ctp));
}

static void
nm_rwunlock(vnode_t *vp, int write, caller_context_t *ctp)
{
	VOP_RWUNLOCK(VTONM(vp)->nm_filevp, write, ctp);
}

static int
nm_seek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	return (VOP_SEEK(VTONM(vp)->nm_filevp, ooff, noffp, ct));
}

/*
 * Return the vnode representing the file descriptor in vpp.
 */
static int
nm_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	struct vnode *rvp;

	vp = VTONM(vp)->nm_filevp;
	if (VOP_REALVP(vp, &rvp, ct) == 0)
		vp = rvp;
	*vpp = vp;
	return (0);
}

static int
nm_poll(vnode_t *vp, short events, int anyyet, short *reventsp,
	pollhead_t **phpp, caller_context_t *ct)
{
	return (VOP_POLL(VTONM(vp)->nm_filevp, events, anyyet, reventsp,
	    phpp, ct));
}

struct vnodeops *nm_vnodeops;

const fs_operation_def_t nm_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = nm_open },
	VOPNAME_CLOSE,		{ .vop_close = nm_close },
	VOPNAME_READ,		{ .vop_read = nm_read },
	VOPNAME_WRITE,		{ .vop_write = nm_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = nm_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = nm_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = nm_setattr },
	VOPNAME_ACCESS,		{ .vop_access = nm_access },
	VOPNAME_CREATE,		{ .vop_create = nm_create },
	VOPNAME_LINK,		{ .vop_link = nm_link },
	VOPNAME_FSYNC,		{ .vop_fsync = nm_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = nm_inactive },
	VOPNAME_FID,		{ .vop_fid = nm_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = nm_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = nm_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = nm_seek },
	VOPNAME_REALVP,		{ .vop_realvp = nm_realvp },
	VOPNAME_POLL,		{ .vop_poll = nm_poll },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	NULL,			NULL
};
