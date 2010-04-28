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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * vnode ops for the devfs
 *
 * For leaf vnode special files (VCHR|VBLK) specfs will always see the VOP
 * first because dv_find always performs leaf vnode substitution, returning
 * a specfs vnode with an s_realvp pointing to the devfs leaf vnode. This
 * means that the only leaf special file VOP operations that devfs will see
 * after VOP_LOOKUP are the ones that specfs forwards.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/policy.h>
#include <sys/modctl.h>
#include <sys/sunndi.h>
#include <fs/fs_subr.h>
#include <sys/fs/dv_node.h>

extern struct vattr	dv_vattr_dir, dv_vattr_file;
extern dev_t rconsdev;

/*
 * Open of devices (leaf nodes) is handled by specfs.
 * There is nothing to do to open a directory
 */
/*ARGSUSED*/
static int
devfs_open(struct vnode **vpp, int flag, struct cred *cred,
    caller_context_t *ct)
{
	struct dv_node	*dv = VTODV(*vpp);

	dcmn_err2(("devfs_open %s\n", dv->dv_name));
	ASSERT((*vpp)->v_type == VDIR);
	return (0);
}

/*
 * Close of devices (leaf nodes) is handled by specfs.
 * There is nothing much to do inorder to close a directory.
 */
/*ARGSUSED1*/
static int
devfs_close(struct vnode *vp, int flag, int count,
    offset_t offset, struct cred *cred, caller_context_t *ct)
{
	struct dv_node	*dv = VTODV(vp);

	dcmn_err2(("devfs_close %s\n", dv->dv_name));
	ASSERT(vp->v_type == VDIR);

	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	return (0);
}

/*
 * Read of devices (leaf nodes) is handled by specfs.
 * Read of directories is not supported.
 */
/*ARGSUSED*/
static int
devfs_read(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cred,
	struct caller_context *ct)
{
	dcmn_err2(("devfs_read %s\n", VTODV(vp)->dv_name));
	ASSERT(vp->v_type == VDIR);
	ASSERT(RW_READ_HELD(&VTODV(vp)->dv_contents));
	return (EISDIR);
}

/*
 * Write of devices (leaf nodes) is handled by specfs.
 * Write of directories is not supported.
 */
/*ARGSUSED*/
static int
devfs_write(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cred,
	struct caller_context *ct)
{
	dcmn_err2(("devfs_write %s\n", VTODV(vp)->dv_name));
	ASSERT(vp->v_type == VDIR);
	ASSERT(RW_WRITE_HELD(&VTODV(vp)->dv_contents));
	return (EISDIR);
}

/*
 * Ioctls to device (leaf nodes) is handled by specfs.
 * Ioctl to directories is not supported.
 */
/*ARGSUSED*/
static int
devfs_ioctl(struct vnode *vp, int cmd, intptr_t arg, int flag,
    struct cred *cred, int *rvalp, caller_context_t *ct)
{
	dcmn_err2(("devfs_ioctl %s\n", VTODV(vp)->dv_name));
	ASSERT(vp->v_type == VDIR);

	return (ENOTTY);	/* no ioctls supported */
}

/*
 * We can be asked directly about the attributes of directories, or
 * (via sp->s_realvp) about the filesystem attributes of special files.
 *
 * For directories, we just believe the attribute store
 * though we mangle the nodeid, fsid, and rdev to convince userland we
 * really are a different filesystem.
 *
 * For special files, a little more fakery is required.
 *
 * If the attribute store is not there (read only root), we believe our
 * memory based attributes.
 */
static int
devfs_getattr(struct vnode *vp, struct vattr *vap, int flags, struct cred *cr,
    caller_context_t *ct)
{
	struct dv_node	*dv = VTODV(vp);
	int		error = 0;
	uint_t		mask;

	/*
	 * Message goes to console only. Otherwise, the message
	 * causes devfs_getattr to be invoked again... infinite loop
	 */
	dcmn_err2(("?devfs_getattr %s\n", dv->dv_name));
	ASSERT(dv->dv_attr || dv->dv_attrvp);

	if (!(vp->v_type == VDIR || vp->v_type == VCHR || vp->v_type == VBLK)) {
		cmn_err(CE_WARN,	/* panic ? */
		    "?%s: getattr on vnode type %d", dvnm, vp->v_type);
		return (ENOENT);
	}

	rw_enter(&dv->dv_contents, RW_READER);
	if (dv->dv_attr) {
		/*
		 * obtain from the memory version of attribute.
		 * preserve mask for those that optimize.
		 * devfs specific fields are already merged on creation.
		 */
		mask = vap->va_mask;
		*vap = *dv->dv_attr;
		vap->va_mask = mask;
	} else {
		/* obtain from attribute store and merge */
		error = VOP_GETATTR(dv->dv_attrvp, vap, flags, cr, ct);
		dsysdebug(error, ("vop_getattr %s %d\n", dv->dv_name, error));
		dv_vattr_merge(dv, vap);
	}
	rw_exit(&dv->dv_contents);

	/*
	 * Restrict the permissions of the node fronting the console
	 * to 0600 with root as the owner.  This prevents a non-root
	 * user from gaining access to a serial terminal (like /dev/term/a)
	 * which is in reality serving as the console device (/dev/console).
	 */
	if (vp->v_rdev == rconsdev) {
		mode_t	rconsmask = S_IXUSR|S_IRWXG|S_IRWXO;
		vap->va_mode &= (~rconsmask);
		vap->va_uid = 0;
	}

	return (error);
}

static int devfs_unlocked_access(void *, int, struct cred *);

/*ARGSUSED4*/
static int
devfs_setattr_dir(
	struct dv_node *dv,
	struct vnode *vp,
	struct vattr *vap,
	int flags,
	struct cred *cr)
{
	struct vattr	*map;
	uint_t		mask;
	int		error = 0;
	struct vattr	vattr;

	ASSERT(dv->dv_attr || dv->dv_attrvp);

	ASSERT(vp->v_type == VDIR);
	ASSERT((dv->dv_flags & DV_NO_FSPERM) == 0);

	if (vap->va_mask & AT_NOSET)
		return (EINVAL);

	/* to ensure consistency, single thread setting of attributes */
	rw_enter(&dv->dv_contents, RW_WRITER);

again:	if (dv->dv_attr) {

		error = secpolicy_vnode_setattr(cr, vp, vap,
		    dv->dv_attr, flags, devfs_unlocked_access, dv);

		if (error)
			goto out;

		/*
		 * Apply changes to the memory based attribute. This code
		 * is modeled after the tmpfs implementation of memory
		 * based vnodes
		 */
		map = dv->dv_attr;
		mask = vap->va_mask;

		/* Change file access modes. */
		if (mask & AT_MODE) {
			map->va_mode &= S_IFMT;
			map->va_mode |= vap->va_mode & ~S_IFMT;
		}
		if (mask & AT_UID)
			map->va_uid = vap->va_uid;
		if (mask & AT_GID)
			map->va_gid = vap->va_gid;
		if (mask & AT_ATIME)
			map->va_atime = vap->va_atime;
		if (mask & AT_MTIME)
			map->va_mtime = vap->va_mtime;

		if (mask & (AT_MODE | AT_UID | AT_GID | AT_MTIME))
			gethrestime(&map->va_ctime);
	} else {
		/* use the backing attribute store */
		ASSERT(dv->dv_attrvp);

		/*
		 * See if we are changing something we care about
		 * the persistence of - return success if we don't care.
		 */
		if (vap->va_mask & (AT_MODE|AT_UID|AT_GID|AT_ATIME|AT_MTIME)) {
			/* Set the attributes */
			error = VOP_SETATTR(dv->dv_attrvp,
			    vap, flags, cr, NULL);
			dsysdebug(error,
			    ("vop_setattr %s %d\n", dv->dv_name, error));

			/*
			 * Some file systems may return EROFS for a setattr
			 * on a readonly file system.  In this case we create
			 * our own memory based attribute.
			 */
			if (error == EROFS) {
				/*
				 * obtain attributes from existing file
				 * that we will modify and switch to memory
				 * based attribute until attribute store is
				 * read/write.
				 */
				vattr = dv_vattr_dir;
				if (VOP_GETATTR(dv->dv_attrvp,
				    &vattr, flags, cr, NULL) == 0) {
					dv->dv_attr = kmem_alloc(
					    sizeof (struct vattr), KM_SLEEP);
					*dv->dv_attr = vattr;
					dv_vattr_merge(dv, dv->dv_attr);
					goto again;
				}
			}
		}
	}
out:
	rw_exit(&dv->dv_contents);
	return (error);
}


/*
 * Compare the uid/gid/mode changes requested for a setattr
 * operation with the same details of a node's default minor
 * perm information.  Return 0 if identical.
 */
static int
dv_setattr_cmp(struct vattr *map, mperm_t *mp)
{
	if ((map->va_mode & S_IAMB) != (mp->mp_mode & S_IAMB))
		return (1);
	if (map->va_uid != mp->mp_uid)
		return (1);
	if (map->va_gid != mp->mp_gid)
		return (1);
	return (0);
}


/*ARGSUSED4*/
static int
devfs_setattr(
	struct vnode *vp,
	struct vattr *vap,
	int flags,
	struct cred *cr,
	caller_context_t *ct)
{
	struct dv_node	*dv = VTODV(vp);
	struct dv_node	*ddv;
	struct vnode	*dvp;
	struct vattr	*map;
	uint_t		mask;
	int		error = 0;
	struct vattr	*free_vattr = NULL;
	struct vattr	*vattrp = NULL;
	mperm_t		mp;
	int		persist;

	/*
	 * Message goes to console only. Otherwise, the message
	 * causes devfs_getattr to be invoked again... infinite loop
	 */
	dcmn_err2(("?devfs_setattr %s\n", dv->dv_name));
	ASSERT(dv->dv_attr || dv->dv_attrvp);

	if (!(vp->v_type == VDIR || vp->v_type == VCHR || vp->v_type == VBLK)) {
		cmn_err(CE_WARN,	/* panic ? */
		    "?%s: getattr on vnode type %d", dvnm, vp->v_type);
		return (ENOENT);
	}

	if (vap->va_mask & AT_NOSET)
		return (EINVAL);

	/*
	 * If we are changing something we don't care about
	 * the persistence of, return success.
	 */
	if ((vap->va_mask &
	    (AT_MODE|AT_UID|AT_GID|AT_ATIME|AT_MTIME)) == 0)
		return (0);

	/*
	 * If driver overrides fs perm, disallow chmod
	 * and do not create attribute nodes.
	 */
	if (dv->dv_flags & DV_NO_FSPERM) {
		ASSERT(dv->dv_attr);
		if (vap->va_mask & (AT_MODE | AT_UID | AT_GID))
			return (EPERM);
		if ((vap->va_mask & (AT_ATIME|AT_MTIME)) == 0)
			return (0);
		rw_enter(&dv->dv_contents, RW_WRITER);
		if (vap->va_mask & AT_ATIME)
			dv->dv_attr->va_atime = vap->va_atime;
		if (vap->va_mask & AT_MTIME)
			dv->dv_attr->va_mtime = vap->va_mtime;
		rw_exit(&dv->dv_contents);
		return (0);
	}

	/*
	 * Directories are always created but device nodes are
	 * only used to persist non-default permissions.
	 */
	if (vp->v_type == VDIR) {
		ASSERT(dv->dv_attr || dv->dv_attrvp);
		return (devfs_setattr_dir(dv, vp, vap, flags, cr));
	}

	/*
	 * Allocate now before we take any locks
	 */
	vattrp = kmem_zalloc(sizeof (*vattrp), KM_SLEEP);

	/* to ensure consistency, single thread setting of attributes */
	rw_enter(&dv->dv_contents, RW_WRITER);

	/*
	 * We don't need to create an attribute node
	 * to persist access or modification times.
	 */
	persist = (vap->va_mask & (AT_MODE | AT_UID | AT_GID));

	/*
	 * If persisting something, get the default permissions
	 * for this minor to compare against what the attributes
	 * are now being set to.  Default ordering is:
	 *	- minor_perm match for this minor
	 *	- mode supplied by ddi_create_priv_minor_node
	 *	- devfs defaults
	 */
	if (persist) {
		if (dev_minorperm(dv->dv_devi, dv->dv_name, &mp) != 0) {
			mp.mp_uid = dv_vattr_file.va_uid;
			mp.mp_gid = dv_vattr_file.va_gid;
			mp.mp_mode = dv_vattr_file.va_mode;
			if (dv->dv_flags & DV_DFLT_MODE) {
				ASSERT((dv->dv_dflt_mode & ~S_IAMB) == 0);
				mp.mp_mode &= ~S_IAMB;
				mp.mp_mode |= dv->dv_dflt_mode;
				dcmn_err5(("%s: setattr priv default 0%o\n",
				    dv->dv_name, mp.mp_mode));
			} else {
				dcmn_err5(("%s: setattr devfs default 0%o\n",
				    dv->dv_name, mp.mp_mode));
			}
		} else {
			dcmn_err5(("%s: setattr minor perm default 0%o\n",
			    dv->dv_name, mp.mp_mode));
		}
	}

	/*
	 * If we don't have a vattr for this node, construct one.
	 */
	if (dv->dv_attr) {
		free_vattr = vattrp;
		vattrp = NULL;
	} else {
		ASSERT(dv->dv_attrvp);
		ASSERT(vp->v_type != VDIR);
		*vattrp = dv_vattr_file;
		error = VOP_GETATTR(dv->dv_attrvp, vattrp, 0, cr, ct);
		dsysdebug(error, ("vop_getattr %s %d\n", dv->dv_name, error));
		if (error)
			goto out;
		dv->dv_attr = vattrp;
		dv_vattr_merge(dv, dv->dv_attr);
		vattrp = NULL;
	}

	error = secpolicy_vnode_setattr(cr, vp, vap, dv->dv_attr,
	    flags, devfs_unlocked_access, dv);
	if (error) {
		dsysdebug(error, ("devfs_setattr %s secpolicy error %d\n",
		    dv->dv_name, error));
		goto out;
	}

	/*
	 * Apply changes to the memory based attribute. This code
	 * is modeled after the tmpfs implementation of memory
	 * based vnodes
	 */
	map = dv->dv_attr;
	mask = vap->va_mask;

	/* Change file access modes. */
	if (mask & AT_MODE) {
		map->va_mode &= S_IFMT;
		map->va_mode |= vap->va_mode & ~S_IFMT;
	}
	if (mask & AT_UID)
		map->va_uid = vap->va_uid;
	if (mask & AT_GID)
		map->va_gid = vap->va_gid;
	if (mask & AT_ATIME)
		map->va_atime = vap->va_atime;
	if (mask & AT_MTIME)
		map->va_mtime = vap->va_mtime;

	if (mask & (AT_MODE | AT_UID | AT_GID | AT_MTIME)) {
		gethrestime(&map->va_ctime);
	}

	/*
	 * A setattr to defaults means we no longer need the
	 * shadow node as a persistent store, unless there
	 * are ACLs.  Otherwise create a shadow node if one
	 * doesn't exist yet.
	 */
	if (persist) {
		if ((dv_setattr_cmp(map, &mp) == 0) &&
		    ((dv->dv_flags & DV_ACL) == 0)) {

			if (dv->dv_attrvp) {
				ddv = dv->dv_dotdot;
				ASSERT(ddv->dv_attrvp);
				error = VOP_REMOVE(ddv->dv_attrvp,
				    dv->dv_name, cr, ct, 0);
				dsysdebug(error,
				    ("vop_remove %s %s %d\n",
				    ddv->dv_name, dv->dv_name, error));

				if (error == EROFS)
					error = 0;
				VN_RELE(dv->dv_attrvp);
				dv->dv_attrvp = NULL;
			}
			ASSERT(dv->dv_attr);
		} else {
			if (mask & AT_MODE)
				dcmn_err5(("%s persisting mode 0%o\n",
				    dv->dv_name, vap->va_mode));
			if (mask & AT_UID)
				dcmn_err5(("%s persisting uid %d\n",
				    dv->dv_name, vap->va_uid));
			if (mask & AT_GID)
				dcmn_err5(("%s persisting gid %d\n",
				    dv->dv_name, vap->va_gid));

			if (dv->dv_attrvp == NULL) {
				dvp = DVTOV(dv->dv_dotdot);
				dv_shadow_node(dvp, dv->dv_name, vp,
				    NULL, NULLVP, cr,
				    DV_SHADOW_CREATE | DV_SHADOW_WRITE_HELD);
			}
			if (dv->dv_attrvp) {
				/* If map still valid do TIME for free. */
				if (dv->dv_attr == map) {
					mask = map->va_mask;
					map->va_mask =
					    vap->va_mask | AT_ATIME | AT_MTIME;
					error = VOP_SETATTR(dv->dv_attrvp, map,
					    flags, cr, NULL);
					map->va_mask = mask;
				} else {
					error = VOP_SETATTR(dv->dv_attrvp,
					    vap, flags, cr, NULL);
				}
				dsysdebug(error, ("vop_setattr %s %d\n",
				    dv->dv_name, error));
			}
			/*
			 * Some file systems may return EROFS for a setattr
			 * on a readonly file system.  In this case save
			 * as our own memory based attribute.
			 * NOTE: ufs is NOT one of these (see ufs_iupdat).
			 */
			if (dv->dv_attr && dv->dv_attrvp && error == 0) {
				vattrp = dv->dv_attr;
				dv->dv_attr = NULL;
			} else if (error == EROFS)
				error = 0;
		}
	}

out:
	rw_exit(&dv->dv_contents);

	if (vattrp)
		kmem_free(vattrp, sizeof (*vattrp));
	if (free_vattr)
		kmem_free(free_vattr, sizeof (*free_vattr));
	return (error);
}

static int
devfs_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	switch (cmd) {
	case _PC_ACL_ENABLED:
		/*
		 * We rely on the underlying filesystem for ACLs,
		 * so direct the query for ACL support there.
		 * ACL support isn't relative to the file
		 * and we can't guarantee that the dv node
		 * has an attribute node, so any valid
		 * attribute node will suffice.
		 */
		ASSERT(dvroot);
		ASSERT(dvroot->dv_attrvp);
		return (VOP_PATHCONF(dvroot->dv_attrvp, cmd, valp, cr, ct));
		/*NOTREACHED*/
	}

	return (fs_pathconf(vp, cmd, valp, cr, ct));
}

/*
 * Let avp handle security attributes (acl's).
 */
static int
devfs_getsecattr(struct vnode *vp, struct vsecattr *vsap, int flags,
    struct cred *cr, caller_context_t *ct)
{
	dvnode_t *dv = VTODV(vp);
	struct vnode *avp;
	int	error;

	dcmn_err2(("devfs_getsecattr %s\n", dv->dv_name));
	ASSERT(vp->v_type == VDIR || vp->v_type == VCHR || vp->v_type == VBLK);

	rw_enter(&dv->dv_contents, RW_READER);

	avp = dv->dv_attrvp;

	/* fabricate the acl */
	if (avp == NULL) {
		error = fs_fab_acl(vp, vsap, flags, cr, ct);
		rw_exit(&dv->dv_contents);
		return (error);
	}

	error = VOP_GETSECATTR(avp, vsap, flags, cr, ct);
	dsysdebug(error, ("vop_getsecattr %s %d\n", VTODV(vp)->dv_name, error));
	rw_exit(&dv->dv_contents);
	return (error);
}

/*
 * Set security attributes (acl's)
 *
 * Note that the dv_contents lock has already been acquired
 * by the caller's VOP_RWLOCK.
 */
static int
devfs_setsecattr(struct vnode *vp, struct vsecattr *vsap, int flags,
    struct cred *cr, caller_context_t *ct)
{
	dvnode_t *dv = VTODV(vp);
	struct vnode *avp;
	int	error;

	dcmn_err2(("devfs_setsecattr %s\n", dv->dv_name));
	ASSERT(vp->v_type == VDIR || vp->v_type == VCHR || vp->v_type == VBLK);
	ASSERT(RW_LOCK_HELD(&dv->dv_contents));

	/*
	 * Not a supported operation on drivers not providing
	 * file system based permissions.
	 */
	if (dv->dv_flags & DV_NO_FSPERM)
		return (ENOTSUP);

	/*
	 * To complete, the setsecattr requires an underlying attribute node.
	 */
	if (dv->dv_attrvp == NULL) {
		ASSERT(vp->v_type == VCHR || vp->v_type == VBLK);
		dv_shadow_node(DVTOV(dv->dv_dotdot), dv->dv_name, vp,
		    NULL, NULLVP, cr, DV_SHADOW_CREATE | DV_SHADOW_WRITE_HELD);
	}

	if ((avp = dv->dv_attrvp) == NULL) {
		dcmn_err2(("devfs_setsecattr %s: "
		    "cannot construct attribute node\n", dv->dv_name));
		return (fs_nosys());
	}

	/*
	 * The acl(2) system call issues a VOP_RWLOCK before setting an ACL.
	 * Since backing file systems expect the lock to be held before seeing
	 * a VOP_SETSECATTR ACL, we need to issue the VOP_RWLOCK to the backing
	 * store before forwarding the ACL.
	 */
	(void) VOP_RWLOCK(avp, V_WRITELOCK_TRUE, NULL);
	error = VOP_SETSECATTR(avp, vsap, flags, cr, ct);
	dsysdebug(error, ("vop_setsecattr %s %d\n", VTODV(vp)->dv_name, error));
	VOP_RWUNLOCK(avp, V_WRITELOCK_TRUE, NULL);

	/*
	 * Set DV_ACL if we have a non-trivial set of ACLs.  It is not
	 * necessary to hold VOP_RWLOCK since fs_acl_nontrivial only does
	 * VOP_GETSECATTR calls.
	 */
	if (fs_acl_nontrivial(avp, cr))
		dv->dv_flags |= DV_ACL;
	return (error);
}

/*
 * This function is used for secpolicy_setattr().  It must call an
 * access() like function while it is already holding the
 * dv_contents lock.  We only care about this when dv_attr != NULL;
 * so the unlocked access call only concerns itself with that
 * particular branch of devfs_access().
 */
static int
devfs_unlocked_access(void *vdv, int mode, struct cred *cr)
{
	struct dv_node *dv = vdv;
	int shift = 0;
	uid_t owner = dv->dv_attr->va_uid;

	/* Check access based on owner, group and public permissions. */
	if (crgetuid(cr) != owner) {
		shift += 3;
		if (groupmember(dv->dv_attr->va_gid, cr) == 0)
			shift += 3;
	}

	return (secpolicy_vnode_access2(cr, DVTOV(dv), owner,
	    dv->dv_attr->va_mode << shift, mode));
}

static int
devfs_access(struct vnode *vp, int mode, int flags, struct cred *cr,
    caller_context_t *ct)
{
	struct dv_node	*dv = VTODV(vp);
	int		res;

	dcmn_err2(("devfs_access %s\n", dv->dv_name));
	ASSERT(dv->dv_attr || dv->dv_attrvp);

	/* restrict console access to privileged processes */
	if ((vp->v_rdev == rconsdev) && secpolicy_console(cr) != 0) {
		return (EACCES);
	}

	rw_enter(&dv->dv_contents, RW_READER);
	if (dv->dv_attr && ((dv->dv_flags & DV_ACL) == 0)) {
		res = devfs_unlocked_access(dv, mode, cr);
	} else {
		res = VOP_ACCESS(dv->dv_attrvp, mode, flags, cr, ct);
	}
	rw_exit(&dv->dv_contents);
	return (res);
}

/*
 * Lookup
 *
 * Given the directory vnode and the name of the component, return
 * the corresponding held vnode for that component.
 *
 * Of course in these fictional filesystems, nothing's ever quite
 * -that- simple.
 *
 * devfs name	type		shadow (fs attributes)	type	comments
 * -------------------------------------------------------------------------
 * drv[@addr]	VDIR		drv[@addr]		VDIR	nexus driver
 * drv[@addr]:m	VCHR/VBLK	drv[@addr]:m		VREG	leaf driver
 * drv[@addr]	VCHR/VBLK	drv[@addr]:.default	VREG	leaf driver
 * -------------------------------------------------------------------------
 *
 * The following names are reserved for the attribute filesystem (which
 * could easily be another layer on top of this one - we simply need to
 * hold the vnode of the thing we're looking at)
 *
 * attr name	type		shadow (fs attributes)	type	comments
 * -------------------------------------------------------------------------
 * drv[@addr]	VDIR		-			-	attribute dir
 * minorname	VDIR		-			-	minorname
 * attribute	VREG		-			-	attribute
 * -------------------------------------------------------------------------
 *
 * Examples:
 *
 *	devfs:/devices/.../mm@0:zero		VCHR
 *	shadow:/.devices/.../mm@0:zero		VREG, fs attrs
 *	devfs:/devices/.../mm@0:/zero/attr	VREG, driver attribute
 *
 *	devfs:/devices/.../sd@0,0:a		VBLK
 *	shadow:/.devices/.../sd@0,0:a		VREG, fs attrs
 *	devfs:/devices/.../sd@0,0:/a/.type	VREG, "ddi_block:chan"
 *
 *	devfs:/devices/.../mm@0			VCHR
 *	shadow:/.devices/.../mm@0:.default	VREG, fs attrs
 *	devfs:/devices/.../mm@0:/.default/attr	VREG, driver attribute
 *	devfs:/devices/.../mm@0:/.default/.type	VREG, "ddi_pseudo"
 *
 *	devfs:/devices/.../obio			VDIR
 *	shadow:/devices/.../obio		VDIR, needed for fs attrs.
 *	devfs:/devices/.../obio:/.default/attr	VDIR, driver attribute
 *
 * We also need to be able deal with "old" devices that have gone away,
 * though I think that provided we return them with readdir, they can
 * be removed (i.e. they don't have to respond to lookup, though it might
 * be weird if they didn't ;-)
 *
 * Lookup has side-effects.
 *
 * - It will create directories and fs attribute files in the shadow hierarchy.
 * - It should cause non-SID devices to be probed (ask the parent nexi).
 */
/*ARGSUSED3*/
static int
devfs_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	ASSERT(dvp->v_type == VDIR);
	dcmn_err2(("devfs_lookup: %s\n", nm));
	return (dv_find(VTODV(dvp), nm, vpp, pnp, rdir, cred, 0));
}

/*
 * devfs nodes can't really be created directly by userland - however,
 * we do allow creates to find existing nodes:
 *
 * - any create fails if the node doesn't exist - EROFS.
 * - creating an existing directory read-only succeeds, otherwise EISDIR.
 * - exclusive creates fail if the node already exists - EEXIST.
 * - failure to create the snode for an existing device - ENOSYS.
 */
/*ARGSUSED2*/
static int
devfs_create(struct vnode *dvp, char *nm, struct vattr *vap, vcexcl_t excl,
    int mode, struct vnode **vpp, struct cred *cred, int flag,
    caller_context_t *ct, vsecattr_t *vsecp)
{
	int error;
	struct vnode *vp;

	dcmn_err2(("devfs_create %s\n", nm));
	error = dv_find(VTODV(dvp), nm, &vp, NULL, NULLVP, cred, 0);
	if (error == 0) {
		if (excl == EXCL)
			error = EEXIST;
		else if (vp->v_type == VDIR && (mode & VWRITE))
			error = EISDIR;
		else
			error = VOP_ACCESS(vp, mode, 0, cred, ct);

		if (error) {
			VN_RELE(vp);
		} else
			*vpp = vp;
	} else if (error == ENOENT)
		error = EROFS;

	return (error);
}

/*
 * If DV_BUILD is set, we call into nexus driver to do a BUS_CONFIG_ALL.
 * Otherwise, simply return cached dv_node's. Hotplug code always call
 * devfs_clean() to invalid the dv_node cache.
 */
/*ARGSUSED5*/
static int
devfs_readdir(struct vnode *dvp, struct uio *uiop, struct cred *cred, int *eofp,
    caller_context_t *ct, int flags)
{
	struct dv_node *ddv, *dv;
	struct dirent64 *de, *bufp;
	offset_t diroff;
	offset_t	soff;
	size_t reclen, movesz;
	int error;
	struct vattr va;
	size_t bufsz;

	ddv = VTODV(dvp);
	dcmn_err2(("devfs_readdir %s: offset %lld len %ld\n",
	    ddv->dv_name, uiop->uio_loffset, uiop->uio_iov->iov_len));
	ASSERT(ddv->dv_attr || ddv->dv_attrvp);
	ASSERT(RW_READ_HELD(&ddv->dv_contents));

	if (uiop->uio_loffset >= MAXOFF_T) {
		if (eofp)
			*eofp = 1;
		return (0);
	}

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (dvp->v_type != VDIR)
		return (ENOTDIR);

	/* Load the initial contents */
	if (ddv->dv_flags & DV_BUILD) {
		if (!rw_tryupgrade(&ddv->dv_contents)) {
			rw_exit(&ddv->dv_contents);
			rw_enter(&ddv->dv_contents, RW_WRITER);
		}

		/* recheck and fill */
		if (ddv->dv_flags & DV_BUILD)
			dv_filldir(ddv);

		rw_downgrade(&ddv->dv_contents);
	}

	soff = uiop->uio_loffset;
	bufsz = uiop->uio_iov->iov_len;
	de = bufp = kmem_alloc(bufsz, KM_SLEEP);
	movesz = 0;
	dv = (struct dv_node *)-1;

	/*
	 * Move as many entries into the uio structure as it will take.
	 * Special case "." and "..".
	 */
	diroff = 0;
	if (soff == 0) {				/* . */
		reclen = DIRENT64_RECLEN(strlen("."));
		if ((movesz + reclen) > bufsz)
			goto full;
		de->d_ino = (ino64_t)ddv->dv_ino;
		de->d_off = (off64_t)diroff + 1;
		de->d_reclen = (ushort_t)reclen;

		/* use strncpy(9f) to zero out uninitialized bytes */

		(void) strncpy(de->d_name, ".", DIRENT64_NAMELEN(reclen));
		movesz += reclen;
		de = (dirent64_t *)(intptr_t)((char *)de + reclen);
		dcmn_err3(("devfs_readdir: A: diroff %lld, soff %lld: '%s' "
		    "reclen %lu\n", diroff, soff, ".", reclen));
	}

	diroff++;
	if (soff <= 1) {				/* .. */
		reclen = DIRENT64_RECLEN(strlen(".."));
		if ((movesz + reclen) > bufsz)
			goto full;
		de->d_ino = (ino64_t)ddv->dv_dotdot->dv_ino;
		de->d_off = (off64_t)diroff + 1;
		de->d_reclen = (ushort_t)reclen;

		/* use strncpy(9f) to zero out uninitialized bytes */

		(void) strncpy(de->d_name, "..", DIRENT64_NAMELEN(reclen));
		movesz += reclen;
		de = (dirent64_t *)(intptr_t)((char *)de + reclen);
		dcmn_err3(("devfs_readdir: B: diroff %lld, soff %lld: '%s' "
		    "reclen %lu\n", diroff, soff, "..", reclen));
	}

	diroff++;
	for (dv = DV_FIRST_ENTRY(ddv); dv;
	    dv = DV_NEXT_ENTRY(ddv, dv), diroff++) {
		/* skip entries until at correct directory offset */
		if (diroff < soff)
			continue;

		/*
		 * hidden nodes are skipped (but they still occupy a
		 * directory offset).
		 */
		if (dv->dv_devi && ndi_dev_is_hidden_node(dv->dv_devi))
			continue;

		/*
		 * DDM_INTERNAL_PATH minor nodes are skipped for readdirs
		 * outside the kernel (but they still occupy a directory
		 * offset).
		 */
		if ((dv->dv_flags & DV_INTERNAL) && (cred != kcred))
			continue;

		reclen = DIRENT64_RECLEN(strlen(dv->dv_name));
		if ((movesz + reclen) > bufsz) {
			dcmn_err3(("devfs_readdir: C: diroff "
			    "%lld, soff %lld: '%s' reclen %lu\n",
			    diroff, soff, dv->dv_name, reclen));
			goto full;
		}
		de->d_ino = (ino64_t)dv->dv_ino;
		de->d_off = (off64_t)diroff + 1;
		de->d_reclen = (ushort_t)reclen;

		/* use strncpy(9f) to zero out uninitialized bytes */

		ASSERT(strlen(dv->dv_name) + 1 <=
		    DIRENT64_NAMELEN(reclen));
		(void) strncpy(de->d_name, dv->dv_name,
		    DIRENT64_NAMELEN(reclen));

		movesz += reclen;
		de = (dirent64_t *)(intptr_t)((char *)de + reclen);
		dcmn_err4(("devfs_readdir: D: diroff "
		    "%lld, soff %lld: '%s' reclen %lu\n", diroff, soff,
		    dv->dv_name, reclen));
	}

	/* the buffer is full, or we exhausted everything */
full:	dcmn_err3(("devfs_readdir: moving %lu bytes: "
	    "diroff %lld, soff %lld, dv %p\n",
	    movesz, diroff, soff, (void *)dv));

	if ((movesz == 0) && dv)
		error = EINVAL;		/* cannot be represented */
	else {
		error = uiomove(bufp, movesz, UIO_READ, uiop);
		if (error == 0) {
			if (eofp)
				*eofp = dv ? 0 : 1;
			uiop->uio_loffset = diroff;
		}

		va.va_mask = AT_ATIME;
		gethrestime(&va.va_atime);
		rw_exit(&ddv->dv_contents);
		(void) devfs_setattr(dvp, &va, 0, cred, ct);
		rw_enter(&ddv->dv_contents, RW_READER);
	}

	kmem_free(bufp, bufsz);
	return (error);
}

/*ARGSUSED*/
static int
devfs_fsync(struct vnode *vp, int syncflag, struct cred *cred,
    caller_context_t *ct)
{
	/*
	 * Message goes to console only. Otherwise, the message
	 * causes devfs_fsync to be invoked again... infinite loop
	 */
	dcmn_err2(("devfs_fsync %s\n", VTODV(vp)->dv_name));
	return (0);
}

/*
 * Normally, we leave the dv_node here at count of 0.
 * The node will be destroyed when dv_cleandir() is called.
 *
 * Stale dv_node's are already unlinked from the fs tree,
 * so dv_cleandir() won't find them. We destroy such nodes
 * immediately.
 */
/*ARGSUSED1*/
static void
devfs_inactive(struct vnode *vp, struct cred *cred, caller_context_t *ct)
{
	int destroy;
	struct dv_node *dv = VTODV(vp);

	dcmn_err2(("devfs_inactive: %s\n", dv->dv_name));
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);
	--vp->v_count;
	destroy = (DV_STALE(dv) && vp->v_count == 0);
	mutex_exit(&vp->v_lock);

	/* stale nodes cannot be rediscovered, destroy it here */
	if (destroy)
		dv_destroy(dv, 0);
}

/*
 * XXX Why do we need this?  NFS mounted /dev directories?
 * XXX Talk to peter staubach about this.
 */
/*ARGSUSED2*/
static int
devfs_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ct)
{
	struct dv_node	*dv = VTODV(vp);
	struct dv_fid	*dv_fid;

	if (fidp->fid_len < (sizeof (struct dv_fid) - sizeof (ushort_t))) {
		fidp->fid_len = sizeof (struct dv_fid) - sizeof (ushort_t);
		return (ENOSPC);
	}

	dv_fid = (struct dv_fid *)fidp;
	bzero(dv_fid, sizeof (struct dv_fid));
	dv_fid->dvfid_len = (int)sizeof (struct dv_fid) - sizeof (ushort_t);
	dv_fid->dvfid_ino = dv->dv_ino;
	/* dv_fid->dvfid_gen = dv->tn_gen; XXX ? */

	return (0);
}

/*
 * This pair of routines bracket all VOP_READ, VOP_WRITE
 * and VOP_READDIR requests.  The contents lock stops things
 * moving around while we're looking at them.
 *
 * Also used by file and record locking.
 */
/*ARGSUSED2*/
static int
devfs_rwlock(struct vnode *vp, int write_flag, caller_context_t *ct)
{
	dcmn_err2(("devfs_rwlock %s\n", VTODV(vp)->dv_name));
	rw_enter(&VTODV(vp)->dv_contents, write_flag ? RW_WRITER : RW_READER);
	return (write_flag);
}

/*ARGSUSED1*/
static void
devfs_rwunlock(struct vnode *vp, int write_flag, caller_context_t *ct)
{
	dcmn_err2(("devfs_rwunlock %s\n", VTODV(vp)->dv_name));
	rw_exit(&VTODV(vp)->dv_contents);
}

/*
 * XXX	Should probably do a better job of computing the maximum
 *	offset available in the directory.
 */
/*ARGSUSED1*/
static int
devfs_seek(struct vnode *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	ASSERT(vp->v_type == VDIR);
	dcmn_err2(("devfs_seek %s\n", VTODV(vp)->dv_name));
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

vnodeops_t *dv_vnodeops;

const fs_operation_def_t dv_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = devfs_open },
	VOPNAME_CLOSE,		{ .vop_close = devfs_close },
	VOPNAME_READ,		{ .vop_read = devfs_read },
	VOPNAME_WRITE,		{ .vop_write = devfs_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = devfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = devfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = devfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = devfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = devfs_lookup },
	VOPNAME_CREATE,		{ .vop_create = devfs_create },
	VOPNAME_READDIR,	{ .vop_readdir = devfs_readdir },
	VOPNAME_FSYNC,		{ .vop_fsync = devfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = devfs_inactive },
	VOPNAME_FID,		{ .vop_fid = devfs_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = devfs_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = devfs_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = devfs_seek },
	VOPNAME_PATHCONF,	{ .vop_pathconf = devfs_pathconf },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = devfs_setsecattr },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = devfs_getsecattr },
	NULL,			NULL
};
