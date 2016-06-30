/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/sdt.h>
#include <fs/fs_subr.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <sys/lx_brand.h>
#include <sys/brand.h>

#include "lxd.h"

static int
lxd_open(vnode_t **vpp, int flag, struct cred *cr, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(*vpp);
	vnode_t *vp = *vpp;
	vnode_t *rvp;
	vnode_t *oldvp;
	int error;

	if (ldn->lxdn_type == LXDNT_FRONT)
		return (0);

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	oldvp = vp;
	vp = rvp = REALVP(vp);
	/*
	 * Need to hold new reference to vp since VOP_OPEN() may
	 * decide to release it.
	 */
	VN_HOLD(vp);
	error = VOP_OPEN(&rvp, flag, cr, ct);

	if (!error && rvp != vp) {
		/*
		 * the FS which we called should have released the
		 * new reference on vp
		 */
		*vpp = lxd_make_back_node(rvp, VFSTOLXDM(oldvp->v_vfsp));

		if (IS_DEVVP(*vpp)) {
			vnode_t *svp;

			svp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
			VN_RELE(*vpp);
			if (svp == NULL)
				error = ENOSYS;
			else
				*vpp = svp;
		}
		VN_RELE(oldvp);
	} else {
		ASSERT(rvp->v_count > 1);
		VN_RELE(rvp);
	}

	return (error);
}

static int
lxd_close(vnode_t *vp, int flag, int count, offset_t offset, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT)
		return (0);

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_CLOSE(vp, flag, count, offset, cr, ct));
}

static int
lxd_read(vnode_t *vp, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT)
		return (ENOTSUP);

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_READ(vp, uiop, ioflag, cr, ct));
}

static int
lxd_write(vnode_t *vp, struct uio *uiop, int ioflag, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT)
		return (ENOTSUP);

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_WRITE(vp, uiop, ioflag, cr, ct));
}

static int
lxd_ioctl(vnode_t *vp, int cmd, intptr_t arg, int flag, struct cred *cr,
    int *rvalp, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT)
		return (ENOTSUP);

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_IOCTL(vp, cmd, arg, flag, cr, rvalp, ct));
}

static int
lxd_setfl(vnode_t *vp, int oflags, int nflags, cred_t *cr, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT)
		return (ENOTSUP);

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_SETFL(vp, oflags, nflags, cr, ct));
}

/*
 * Translate SunOS devt to Linux devt.
 */
static void
lxd_s2l_devt(dev_t dev, dev_t *rdev)
{
	lxd_minor_translator_t	*mt;
	int			i, j;
	major_t			maj = getmajor(dev);
	minor_t			min = getminor(dev);

	/* look for a devt translator for this major number */
	for (i = 0; lxd_devt_translators[i].lxd_xl_driver != NULL; i++) {
		if (lxd_devt_translators[i].lxd_xl_major == maj)
			break;
	}

	if (lxd_devt_translators[i].lxd_xl_driver != NULL) {
		/* try to translate the illumos devt to a linux devt */
		switch (lxd_devt_translators[i].lxd_xl_type) {
		case DTT_INVALID:
			ASSERT(0);
			break;

		case DTT_LIST:
			mt = lxd_devt_translators[i].xl_list;
			for (j = 0; mt[j].lxd_mt_path != NULL; j++) {
				if (mt[j].lxd_mt_minor == min) {
					ASSERT(mt[j].lxd_mt_minor < LX_MAXMIN);

					/* found a translation */
					*rdev = LX_MAKEDEVICE(
					    mt[j].lxd_mt_lx_major,
					    mt[j].lxd_mt_lx_minor);
					return;
				}
			}
			break;

		case DTT_CUSTOM:
			lxd_devt_translators[i].xl_custom(dev, rdev);
			return;
		}
	}

	/* we don't have a translator for this device */
	*rdev = LX_MAKEDEVICE(maj, min);
}

static int
lxd_getattr(vnode_t *vp, struct vattr *vap, int flags, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);
	int error;
	vnode_t *rvp;

	if (ldn->lxdn_type == LXDNT_FRONT) {
		mutex_enter(&ldn->lxdn_tlock);

		vap->va_type = vp->v_type;
		vap->va_mode = ldn->lxdn_mode & MODEMASK;
		vap->va_uid = ldn->lxdn_uid;
		vap->va_gid = ldn->lxdn_gid;
		vap->va_fsid = ldn->lxdn_fsid;
		vap->va_nodeid = (ino64_t)ldn->lxdn_nodeid;
		vap->va_nlink = ldn->lxdn_nlink;
		vap->va_size = (u_offset_t)ldn->lxdn_size;
		vap->va_atime = ldn->lxdn_atime;
		vap->va_mtime = ldn->lxdn_mtime;
		vap->va_ctime = ldn->lxdn_ctime;
		vap->va_blksize = PAGESIZE;
		vap->va_rdev = 0;	/* no devs in front */
		vap->va_seq = ldn->lxdn_seq;

		vap->va_nblocks = (fsblkcnt64_t)btodb(ptob(btopr(
		    vap->va_size)));
		mutex_exit(&ldn->lxdn_tlock);
		return (0);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	rvp = REALVP(vp);
	if ((error = VOP_GETATTR(rvp, vap, flags, cr, ct)))
		return (error);

	/* Skip devt translation for native programs */
	if (curproc->p_brand != &lx_brand) {
		return (0);
	} else {
		/*
		 * We also skip translation when called from the user-land
		 * emulation code.
		 */
		lx_lwp_data_t *lwpd = ttolxlwp(curthread);

		if (lwpd == NULL || lwpd->br_stack_mode != LX_STACK_MODE_BRAND)
			return (0);
	}

	if (rvp->v_type == VCHR) {
		dev_t ldev;

		lxd_s2l_devt(vap->va_rdev, &ldev);
		DTRACE_PROBE3(lxd__devxl, void *, rvp, void *, vap, int, ldev);
		vap->va_rdev = ldev;
	}

	return (0);
}

static int
lxd_setattr(vnode_t *vp, struct vattr *vap, int flags, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);
	lxd_mnt_t *lxdm = VTOLXDM(vp);
	int res;

	if (ldn->lxdn_type == LXDNT_FRONT) {
		int error = 0;
		struct vattr *set;
		long mask = vap->va_mask;

		/* Cannot set these attributes */
		if ((mask & AT_NOSET) || (mask & AT_XVATTR) ||
		    (mask & AT_MODE && vap->va_mode & (S_ISUID | S_ISGID)) ||
		    (mask & AT_SIZE))
			return (EINVAL);

		mutex_enter(&ldn->lxdn_tlock);

		set = &ldn->lxdn_attr;
		/*
		 * Change file access modes. Must be owner or have sufficient
		 * privileges.
		 */
		error = secpolicy_vnode_setattr(cr, vp, vap, set, flags,
		    lxd_naccess, ldn);
		if (error) {
			mutex_exit(&ldn->lxdn_tlock);
			return (error);
		}

		if (mask & AT_MODE) {
			set->va_mode &= S_IFMT;
			set->va_mode |= vap->va_mode & ~S_IFMT;
		}

		if (mask & AT_UID)
			set->va_uid = vap->va_uid;
		if (mask & AT_GID)
			set->va_gid = vap->va_gid;
		if (mask & AT_ATIME)
			set->va_atime = vap->va_atime;
		if (mask & AT_MTIME)
			set->va_mtime = vap->va_mtime;

		if (mask & (AT_UID | AT_GID | AT_MODE | AT_MTIME))
			gethrestime(&ldn->lxdn_ctime);

		mutex_exit(&ldn->lxdn_tlock);
		return (error);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	res = VOP_SETATTR(vp, vap, flags, cr, ct);
	if (res == 0 && (vap->va_mask & (AT_MODE | AT_UID | AT_GID))) {
		lxd_save_attrs(lxdm, vp);
	}
	return (res);
}

static int
lxd_access(vnode_t *vp, int mode, int flags, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		int error;

		mutex_enter(&ldn->lxdn_tlock);
		error = lxd_naccess(ldn, mode, cr);
		mutex_exit(&ldn->lxdn_tlock);
		return (error);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	if (mode & VWRITE) {
		if (vp->v_type == VREG && vn_is_readonly(vp))
			return (EROFS);
	}
	vp = REALVP(vp);
	return (VOP_ACCESS(vp, mode, flags, cr, ct));
}

static int
lxd_fsync(vnode_t *vp, int syncflag, struct cred *cr, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT)
		return (0);

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_FSYNC(vp, syncflag, cr, ct));
}

/* ARGSUSED */
static void
lxd_front_inactive(struct vnode *vp, struct cred *cred, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);
	lxd_mnt_t *lxdm = VTOLXDM(vp);

	ASSERT(ldn->lxdn_type == LXDNT_FRONT);
	rw_enter(&ldn->lxdn_rwlock, RW_WRITER);

	mutex_enter(&ldn->lxdn_tlock);
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);

	/*
	 * If we don't have the last hold or the link count is non-zero,
	 * there's little to do -- just drop our hold.
	 */
	if (vp->v_count > 1 || ldn->lxdn_nlink != 0) {
		vp->v_count--;

		mutex_exit(&vp->v_lock);
		mutex_exit(&ldn->lxdn_tlock);
		rw_exit(&ldn->lxdn_rwlock);
		return;
	}

	/*
	 * We have the last hold *and* the link count is zero, so this node is
	 * dead from the filesystem's viewpoint.
	 */
	if (ldn->lxdn_size != 0) {
		if (ldn->lxdn_vnode->v_type == VLNK)
			kmem_free(ldn->lxdn_symlink, ldn->lxdn_size + 1);
	}

	mutex_exit(&vp->v_lock);
	mutex_exit(&ldn->lxdn_tlock);

	vn_invalid(LDNTOV(ldn));

	mutex_enter(&lxdm->lxdm_contents);
	if (ldn->lxdn_next == NULL)
		lxdm->lxdm_rootnode->lxdn_prev = ldn->lxdn_prev;
	else
		ldn->lxdn_next->lxdn_prev = ldn->lxdn_prev;
	ldn->lxdn_prev->lxdn_next = ldn->lxdn_next;

	mutex_exit(&lxdm->lxdm_contents);
	rw_exit(&ldn->lxdn_rwlock);
	rw_destroy(&ldn->lxdn_rwlock);
	mutex_destroy(&ldn->lxdn_tlock);

	vn_free(LDNTOV(ldn));
	kmem_free(ldn, sizeof (lxd_node_t));
}

/*ARGSUSED*/
static void
lxd_inactive(vnode_t *vp, struct cred *cr, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		lxd_front_inactive(vp, cr, ct);
		return;
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	lxd_free_back_node(ldn);
}

/* ARGSUSED */
static int
lxd_fid(vnode_t *vp, struct fid *fidp, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT)
		return (ENOTSUP);

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_FID(vp, fidp, ct));
}

/*
 * For a front node lookup in the dirent hash table and return a shadow vnode
 * (lxd_node_t type) of type LXDNT_FRONT.
 *
 * For a back node, lookup nm name and return a shadow vnode (lxd_node_t type)
 * of the real vnode found.
 */
static int
lxd_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
    int flags, vnode_t *rdir, struct cred *cr, caller_context_t *ct,
    int *direntflags, pathname_t *realpnp)
{
	vnode_t *vp = NULL;
	int error;
	vnode_t *realdvp;
	lxd_mnt_t *lxdm = VTOLXDM(dvp);
	int doingdotdot = 0;
	lxd_node_t *ldn = VTOLDN(dvp);
	lxd_node_t *nldn = NULL;

	/*
	 * First check for front file which could be instantiated on either a
	 * front or back node (e.g. the top-level moint point directory node is
	 * a back node which can have front files created in it).
	 */

	/* disallow extended attrs */
	if (flags & LOOKUP_XATTR)
		return (EINVAL);

	/* Null component name is a synonym for dir being searched. */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

	rw_enter(&ldn->lxdn_rwlock, RW_READER);
	error = lxd_dirlookup(ldn, nm, &nldn, cr);
	rw_exit(&ldn->lxdn_rwlock);

	if (error == 0) {
		/* found */
		ASSERT(nldn != NULL);
		*vpp = LDNTOV(nldn);
		return (0);
	}

	/* At this point, if dir node is a front node, error */
	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (ENOENT);
	}

	realdvp = REALVP(dvp);

	if (nm[0] == '.' && nm[1] == '.' && nm[2] == '\0') {
		doingdotdot++;
		/*
		 * Handle ".." out of mounted filesystem
		 */
		while ((realdvp->v_flag & VROOT) && realdvp != rootdir) {
			realdvp = realdvp->v_vfsp->vfs_vnodecovered;
			ASSERT(realdvp != NULL);
		}
	}

	*vpp = NULL;	/* default(error) case */

	/*
	 * Do the normal lookup
	 */
	if ((error = VOP_LOOKUP(realdvp, nm, &vp, pnp, flags, rdir, cr,
	    ct, direntflags, realpnp)) != 0) {
		vp = NULL;
		goto out;
	}

	/*
	 * We do this check here to avoid returning a stale file handle to the
	 * caller.
	 */
	if (nm[0] == '.' && nm[1] == '\0') {
		ASSERT(vp == realdvp);
		VN_HOLD(dvp);
		VN_RELE(vp);
		*vpp = dvp;
		return (0);
	}

	if (doingdotdot) {
		*vpp = lxd_make_back_node(vp, lxdm);
		return (0);
	}

	/*
	 * If this vnode is mounted on, then we
	 * traverse to the vnode which is the root of
	 * the mounted file system.
	 */
	if ((error = traverse(&vp)) != 0)
		goto out;

	/*
	 * Make a lxd node for the real vnode.
	 */
	*vpp = lxd_make_back_node(vp, lxdm);
	if (vp->v_type != VDIR) {
		if (IS_DEVVP(*vpp)) {
			vnode_t *svp;

			svp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
			VN_RELE(*vpp);
			if (svp == NULL) {
				VN_RELE(vp);
				error = ENOSYS;
			} else {
				*vpp = svp;
			}
		}
		return (error);
	}

out:
	if (error != 0 && vp != NULL)
		VN_RELE(vp);

	return (error);
}

/*ARGSUSED*/
static int
lxd_create(vnode_t *dvp, char *nm, struct vattr *va, enum vcexcl exclusive,
    int mode, vnode_t **vpp, struct cred *cr, int flag, caller_context_t *ct,
    vsecattr_t *vsecp)
{
	int error;
	lxd_node_t *parent = VTOLDN(dvp);
	lxd_node_t *lnp = NULL;

	rw_enter(&parent->lxdn_rwlock, RW_READER);
	error = lxd_dirlookup(parent, nm, &lnp, cr);
	rw_exit(&parent->lxdn_rwlock);
	/*
	 * If this vnode already exists in lx devfs, we should pass the create
	 * operation through to the underlying resource it represents.  For
	 * existing back nodes, the VOP_CREATE is done directly against the
	 * returned lxd node with an empty name (to avoid a redunant lookup).
	 * For existing front nodes, an appropriate error must be chosen since
	 * they cannot represent regular files
	 */
	if (error == 0) {
		if (lnp->lxdn_type == LXDNT_BACK) {
			error = VOP_CREATE(lnp->lxdn_real_vp, "\0", va,
			    exclusive, mode, vpp, cr, flag, ct, vsecp);
		} else {
			if (exclusive == EXCL) {
				error = EEXIST;
			} else if (LDNTOV(lnp)->v_type == VDIR &&
			    (mode & S_IWRITE)) {
				error = EISDIR;
			} else {
				error = ENOTSUP;
			}
		}
		if (error != 0) {
			ldnode_rele(lnp);
		}
		return (error);
	}

	/*
	 * We cannot create files in the back devfs but we want to allow for
	 * O_CREAT on existing files.  Pass this through and let the back file
	 * system allow or deny it.
	 */
	if (parent->lxdn_type == LXDNT_BACK) {
		vnode_t *vp = NULL;

		if (*nm == '\0') {
			ASSERT(vpp && dvp == *vpp);
			vp = REALVP(*vpp);
		}
		if ((error = VOP_CREATE(REALVP(dvp), nm, va, exclusive, mode,
		    &vp, cr, flag, ct, vsecp)) == 0) {
			*vpp = lxd_make_back_node(vp, VFSTOLXDM(dvp->v_vfsp));
			if (IS_DEVVP(*vpp)) {
				vnode_t *svp;

				svp = specvp(*vpp, (*vpp)->v_rdev,
				    (*vpp)->v_type, cr);
				VN_RELE(*vpp);
				if (svp == NULL) {
					return (ENOSYS);
				}
				*vpp = svp;
			}
			return (0);
		}
		/*
		 * If we were unable to perform the VOP_CREATE for any reason
		 * other than sdev being read-only, we should bail.
		 */
		if (error != ENOTSUP && error != EROFS) {
			return (error);
		}
	}

	/*
	 * While we don't allow create data-containing files under LX devfs, we
	 * must allow VSOCK front nodes to be created so that paths such as
	 * /dev/log can be used as AF_UNIX sockets.
	 */
	if (va->va_type == VSOCK) {
		lxd_mnt_t *lxdm = VTOLXDM(parent->lxdn_vnode);

		lnp = NULL;
		rw_enter(&parent->lxdn_rwlock, RW_WRITER);
		error = lxd_direnter(lxdm, parent, nm, DE_CREATE, NULL, NULL,
		    va, &lnp, cr);
		rw_exit(&parent->lxdn_rwlock);

		if (error == 0) {
			*vpp = LDNTOV(lnp);
		} else if (lnp != NULL) {
			/*
			 * It's possible that a racing process created an entry
			 * at this name since we last performed the lookup.
			 */
			ldnode_rele(lnp);
		}
	} else {
		error = ENOTSUP;
	}

	return (error);
}

/* ARGSUSED */
static int
lxd_remove(vnode_t *dvp, char *nm, struct cred *cr, caller_context_t *ct,
    int flags)
{
	lxd_node_t *parent = VTOLDN(dvp);
	lxd_node_t *ldn = NULL;
	int error;

	/* can only remove existing front nodes */
	error = lxd_dirlookup(parent, nm, &ldn, cr);
	if (error) {
		return (error);
	}

	ASSERT(ldn != NULL);
	ASSERT(ldn->lxdn_type == LXDNT_FRONT);
	rw_enter(&parent->lxdn_rwlock, RW_WRITER);
	rw_enter(&ldn->lxdn_rwlock, RW_WRITER);

	error = lxd_dirdelete(parent, ldn, nm, DR_REMOVE, cr);

	rw_exit(&ldn->lxdn_rwlock);
	rw_exit(&parent->lxdn_rwlock);

	ldnode_rele(ldn);

	return (error);
}

/* ARGSUSED */
static int
lxd_link(vnode_t *tdvp, vnode_t *vp, char *tnm, struct cred *cr,
    caller_context_t *ct, int flags)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
lxd_rename(vnode_t *odvp, char *onm, vnode_t *ndvp, char *nnm, struct cred *cr,
    caller_context_t *ct, int flags)
{
	lxd_node_t *oldparent = VTOLDN(odvp);
	lxd_node_t *newparent;
	lxd_mnt_t *lxdm = VTOLXDM(oldparent->lxdn_vnode);
	lxd_node_t *fromnode = NULL;
	int error;
	int samedir = 0;

	if (!vn_matchops(ndvp, lxd_vnodeops)) {
		/* cannot rename out of this file system */
		return (EACCES);
	}

	mutex_enter(&lxdm->lxdm_renamelck);

	newparent = VTOLDN(ndvp);

	/*
	 * We can only rename front nodes.
	 */
	error = lxd_dirlookup(oldparent, onm, &fromnode, cr);
	if (error != 0) {
		/* not found in front */
		mutex_exit(&lxdm->lxdm_renamelck);
		return (error);
	}

	/*
	 * Make sure we can delete the old (source) entry.  This
	 * requires write permission on the containing directory.  If
	 * that directory is "sticky" it requires further checks.
	 */
	if ((error = lxd_naccess(oldparent, VWRITE, cr)) != 0)
		goto done;

	/*
	 * Check for renaming to or from '.' or '..' or that
	 * fromnode == oldparent
	 */
	if ((onm[0] == '.' &&
	    (onm[1] == '\0' || (onm[1] == '.' && onm[2] == '\0'))) ||
	    (nnm[0] == '.' &&
	    (nnm[1] == '\0' || (nnm[1] == '.' && nnm[2] == '\0'))) ||
	    (oldparent == fromnode)) {
		error = EINVAL;
		goto done;
	}

	samedir = (oldparent == newparent);

	/*
	 * Make sure we can search and rename into the destination directory.
	 */
	if (!samedir) {
		if ((error = lxd_naccess(newparent, VEXEC|VWRITE, cr)) != 0)
			goto done;
	}

	/*
	 * Link source to new target
	 */
	rw_enter(&newparent->lxdn_rwlock, RW_WRITER);
	error = lxd_direnter(lxdm, newparent, nnm, DE_RENAME,
	    oldparent, fromnode, (struct vattr *)NULL, (lxd_node_t **)NULL,
	    cr);
	rw_exit(&newparent->lxdn_rwlock);

	if (error)
		goto done;

	/*
	 * Unlink from source.
	 */
	rw_enter(&oldparent->lxdn_rwlock, RW_WRITER);
	rw_enter(&fromnode->lxdn_rwlock, RW_WRITER);

	error = lxd_dirdelete(oldparent, fromnode, onm, DR_RENAME, cr);

	/*
	 * The following handles the case where our source node was
	 * removed before we got to it.
	 */
	if (error == ENOENT)
		error = 0;

	rw_exit(&fromnode->lxdn_rwlock);
	rw_exit(&oldparent->lxdn_rwlock);

done:
	ldnode_rele(fromnode);
	mutex_exit(&lxdm->lxdm_renamelck);
	return (error);
}

/* ARGSUSED */
static int
lxd_mkdir(vnode_t *dvp, char *nm, struct vattr *va, vnode_t **vpp,
    struct cred *cr, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	int error;
	vnode_t *tvp;
	lxd_node_t *ndir = NULL;
	lxd_node_t *parent = VTOLDN(dvp);
	lxd_mnt_t *lxdm = VTOLXDM(parent->lxdn_vnode);

	/* check for existence in both front and back */
	if (lxd_lookup(dvp, nm, &tvp, NULL, 0, NULL, cr, ct, NULL, NULL) == 0) {
		/* The entry already exists */
		VN_RELE(tvp);
		return (EEXIST);
	}

	/* make front directory */
	rw_enter(&parent->lxdn_rwlock, RW_WRITER);
	error = lxd_direnter(lxdm, parent, nm, DE_MKDIR, NULL, NULL,
	    va, &ndir, cr);
	rw_exit(&parent->lxdn_rwlock);

	if (error != 0) {
		if (ndir != NULL)
			ldnode_rele(ndir);
	} else {
		*vpp = LDNTOV(ndir);
	}

	return (error);
}

static int
lxd_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		*vpp = vp;
		return (0);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	while (vn_matchops(vp, lxd_vnodeops))
		vp = REALVP(vp);

	if (VOP_REALVP(vp, vpp, ct) != 0)
		*vpp = vp;
	return (0);
}

/* ARGSUSED */
static int
lxd_rmdir(vnode_t *dvp, char *nm, vnode_t *cdir, struct cred *cr,
    caller_context_t *ct, int flags)
{
	int error;
	lxd_node_t *ldn;
	struct vnode *vp;
	lxd_node_t *parent = VTOLDN(dvp);

	/*
	 * Return error if trying to remove . or ..
	 */
	if (strcmp(nm, ".") == 0)
		return (EINVAL);
	if (strcmp(nm, "..") == 0)
		return (EEXIST);

	error = lxd_dirlookup(VTOLDN(dvp), nm, &ldn, cr);
	if (error != 0) {
		/* not found in front */
		return (error);
	}

	rw_enter(&parent->lxdn_rwlock, RW_WRITER);
	rw_enter(&ldn->lxdn_rwlock, RW_WRITER);

	vp = LDNTOV(ldn);
	if (vp == dvp || vp == cdir) {
		error = EINVAL;
		goto err;
	}

	if (ldn->lxdn_vnode->v_type != VDIR) {
		error = ENOTDIR;
		goto err;
	}

	mutex_enter(&ldn->lxdn_tlock);
	if (ldn->lxdn_nlink > 2) {
		mutex_exit(&ldn->lxdn_tlock);
		error = EEXIST;
		goto err;
	}
	mutex_exit(&ldn->lxdn_tlock);

	/* Check for an empty directory */
	if (ldn->lxdn_dirents > 2) {
		error = EEXIST;
		gethrestime(&ldn->lxdn_atime);
		goto err;
	}

	if (vn_vfswlock(vp)) {
		error = EBUSY;
		goto err;
	}
	if (vn_mountedvfs(vp) != NULL) {
		error = EBUSY;
		vn_vfsunlock(vp);
		goto err;
	}

	error = lxd_dirdelete(parent, ldn, nm, DR_RMDIR, cr);
	vn_vfsunlock(vp);

err:
	rw_exit(&ldn->lxdn_rwlock);
	rw_exit(&parent->lxdn_rwlock);
	ldnode_rele(ldn);

	return (error);
}

/* Not static so it can be used during mount. */
/* ARGSUSED */
int
lxd_symlink(vnode_t *dvp, char *nm, struct vattr *tva, char *tnm,
    struct cred *cr, caller_context_t *ct, int flags)
{
	lxd_node_t *parent = VTOLDN(dvp);
	lxd_mnt_t *lxdm = VTOLXDM(parent->lxdn_vnode);
	lxd_node_t *self = NULL;
	vnode_t *tvp;
	char *cp = NULL;
	int error;
	size_t len;

	/* this will check for existence in both front and back */
	if (lxd_lookup(dvp, nm, &tvp, NULL, 0, NULL, cr, ct, NULL, NULL) == 0) {
		/* The entry already exists */
		VN_RELE(tvp);
		return (EEXIST);
	}

	/* make symlink in the front */
	rw_enter(&parent->lxdn_rwlock, RW_WRITER);
	error = lxd_direnter(lxdm, parent, nm, DE_CREATE, NULL, NULL,
	    tva, &self, cr);
	rw_exit(&parent->lxdn_rwlock);

	if (error) {
		if (self != NULL)
			ldnode_rele(self);
		return (error);
	}

	len = strlen(tnm) + 1;
	cp = kmem_alloc(len, KM_NOSLEEP | KM_NORMALPRI);
	if (cp == NULL) {
		ldnode_rele(self);
		return (ENOSPC);
	}
	(void) strcpy(cp, tnm);

	self->lxdn_symlink = cp;
	self->lxdn_size = len - 1;
	ldnode_rele(self);

	return (error);
}

static int
lxd_readlink(vnode_t *vp, struct uio *uiop, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		int error;

		if (vp->v_type != VLNK)
			return (EINVAL);

		rw_enter(&ldn->lxdn_rwlock, RW_READER);
		error = uiomove(ldn->lxdn_symlink, ldn->lxdn_size, UIO_READ,
		    uiop);
		gethrestime(&ldn->lxdn_atime);
		rw_exit(&ldn->lxdn_rwlock);
		return (error);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_READLINK(vp, uiop, cr, ct));
}

static int
lx_merge_front(vnode_t *vp, struct uio *uiop, off_t req_off, int *eofp)
{
	lxd_node_t *ldn = VTOLDN(vp);
	struct dirent *sd;
	lxd_dirent_t *ldp;
	enum lxd_node_type type = ldn->lxdn_type;
	ssize_t uresid;
	off_t front_off;
	int error = 0;
	int sdlen;

	/* skip the front entries if the back read was incomplete */
	if (*eofp == 0)
		return (0);

	/*
	 * If this was a back node then reading that node has completed and we
	 * may have a partially full uio struct. eof should be set to true.
	 * Leave it set since we're likely to hit eof for the front nodes (if
	 * any).
	 */

	front_off = uiop->uio_offset + 1;
	sdlen = sizeof (struct dirent) + MAXPATHLEN;
	/* zalloc to ensure we don't have anything in the d_name buffer */
	sd = (struct dirent *)kmem_zalloc(sdlen, KM_SLEEP);
	ldp = ldn->lxdn_dir;
	while (ldp != NULL && (uresid = uiop->uio_resid) > 0) {
		int namelen;
		int reclen;

		/*
		 * Skip dot and dotdot for back nodes since we have them
		 * already.
		 */
		if (type == LXDNT_BACK &&
		    (strcmp(ldp->lddir_name, ".") == 0 ||
		    strcmp(ldp->lddir_name, "..") == 0)) {
			ldp = ldp->lddir_next;
			continue;
		}

		/*
		 * Might have previously had a partial readdir of the front
		 * nodes, and now we're back for more, or we may just be
		 * be doing a follow-up readdir after we've previously
		 * returned all front and back nodes.
		 */
		if (front_off > req_off) {
			namelen = strlen(ldp->lddir_name); /* no +1 needed */
			reclen = (int)DIRENT64_RECLEN(namelen);

			/*
			 * If the size of the data to transfer is greater
			 * than that requested, then we can't do it this
			 * transfer.
			 */
			if (reclen > uresid) {
				*eofp = 0;
				/* Buffer too small for any entries. */
				if (front_off == 0)
					error = EINVAL;
				break;
			}

			(void) strncpy(sd->d_name, ldp->lddir_name,
			    DIRENT64_NAMELEN(reclen));
			sd->d_reclen = (ushort_t)reclen;
			sd->d_ino = (ino_t)ldp->lddir_node->lxdn_nodeid;
			sd->d_off = front_off;

			/* uiomove will adjust iov_base properly */
			if ((error = uiomove((caddr_t)sd, reclen, UIO_READ,
			    uiop)) != 0) {
				*eofp = 0;
				break;
			}
		}

		/*
		 * uiomove() above updates both uio_resid and uio_offset by the
		 * same amount but we want uio_offset to change in increments
		 * of 1, which is different from the number of bytes being
		 * returned to the caller, so we set uio_offset explicitly,
		 * ignoring what uiomove() did.
		 */
		uiop->uio_offset = front_off;
		front_off++;

		ldp = ldp->lddir_next;
	}

	kmem_free(sd, sdlen);
	return (error);
}

static int
lxd_readdir(vnode_t *vp, struct uio *uiop, struct cred *cr, int *eofp,
    caller_context_t *ct, int flags)
{
	lxd_node_t *ldn = VTOLDN(vp);
	vnode_t *rvp;
	int res;
	off_t req_off;

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	req_off = uiop->uio_offset;

	/* First read the back node (if it is one) */
	if (ldn->lxdn_type == LXDNT_BACK) {
		rvp = REALVP(vp);
		res = VOP_READDIR(rvp, uiop, cr, eofp, ct, flags);
		if (res != 0)
			return (res);
	} else {
		/* setup for merge_front */
		ASSERT(ldn->lxdn_type == LXDNT_FRONT);
		/* caller should have already called lxd_rwlock */
		ASSERT(RW_READ_HELD(&ldn->lxdn_rwlock));

		*eofp = 1;
		/*
		 * The merge code starts the offset calculation from uio_offset,
		 * which is normally already set to the high value by the back
		 * code, but in this case we need to count up from 0.
		 */
		uiop->uio_offset = 0;
	}

	/*
	 * Our back nodes can also have front entries hanging on them so we
	 * need to merge those in. Or, we may simply have a front node (i.e. a
	 * front subdir).
	 */
	res = lx_merge_front(vp, uiop, req_off, eofp);
	return (res);
}

static int
lxd_rwlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		if (write_lock) {
			rw_enter(&ldn->lxdn_rwlock, RW_WRITER);
		} else {
			rw_enter(&ldn->lxdn_rwlock, RW_READER);
		}
		return (write_lock);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_RWLOCK(vp, write_lock, ct));
}

static void
lxd_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		rw_exit(&ldn->lxdn_rwlock);
		return;
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	VOP_RWUNLOCK(vp, write_lock, ct);
}

static int
lxd_seek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_SEEK(vp, ooff, noffp, ct));
}

static int
lxd_cmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{
	while (vn_matchops(vp1, lxd_vnodeops) &&
	    VTOLDN(vp1)->lxdn_type == LXDNT_BACK) {
		vp1 = REALVP(vp1);
	}
	while (vn_matchops(vp2, lxd_vnodeops) &&
	    VTOLDN(vp2)->lxdn_type == LXDNT_BACK) {
		vp2 = REALVP(vp2);
	}

	if (vn_matchops(vp1, lxd_vnodeops) || vn_matchops(vp2, lxd_vnodeops))
		return (vp1 == vp2);

	return (VOP_CMP(vp1, vp2, ct));
}

static int
lxd_frlock(vnode_t *vp, int cmd, struct flock64 *bfp, int flag, offset_t offset,
    struct flk_callback *flk_cbp, cred_t *cr, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_FRLOCK(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
}

static int
lxd_space(vnode_t *vp, int cmd, struct flock64 *bfp, int flag, offset_t offset,
    struct cred *cr, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_SPACE(vp, cmd, bfp, flag, offset, cr, ct));
}

static int
lxd_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *prot,
    struct page *parr[], size_t psz, struct seg *seg, caddr_t addr,
    enum seg_rw rw, struct cred *cr, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_GETPAGE(vp, off, len, prot, parr, psz, seg, addr, rw, cr,
	    ct));
}

static int
lxd_putpage(vnode_t *vp, offset_t off, size_t len, int flags, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_PUTPAGE(vp, off, len, flags, cr, ct));
}

static int
lxd_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp, size_t len,
    uchar_t prot, uchar_t maxprot, uint_t flags, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_MAP(vp, off, as, addrp, len, prot, maxprot, flags, cr, ct));
}

static int
lxd_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr, size_t len,
    uchar_t prot, uchar_t maxprot, uint_t flags, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_ADDMAP(vp, off, as, addr, len, prot, maxprot, flags, cr,
	    ct));
}

static int
lxd_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr, size_t len,
    uint_t prot, uint_t maxprot, uint_t flags, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_DELMAP(vp, off, as, addr, len, prot, maxprot, flags, cr,
	    ct));
}

static int
lxd_poll(vnode_t *vp, short events, int anyyet, short *reventsp,
    struct pollhead **phpp, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_POLL(vp, events, anyyet, reventsp, phpp, ct));
}

static int
lxd_dump(vnode_t *vp, caddr_t addr, offset_t bn, offset_t count,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_DUMP(vp, addr, bn, count, ct));
}

static int
lxd_pathconf(vnode_t *vp, int cmd, ulong_t *valp, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_PATHCONF(vp, cmd, valp, cr, ct));
}

static int
lxd_pageio(vnode_t *vp, struct page *pp, u_offset_t io_off, size_t io_len,
    int flags, cred_t *cr, caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_PAGEIO(vp, pp, io_off, io_len, flags, cr, ct));
}

static void
lxd_dispose(vnode_t *vp, page_t *pp, int fl, int dn, cred_t *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return;
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	if (vp != NULL && !VN_ISKAS(vp))
		VOP_DISPOSE(vp, pp, fl, dn, cr, ct);
}

static int
lxd_setsecattr(vnode_t *vp, vsecattr_t *secattr, int flags, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);
	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (ENOSYS);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	if (vn_is_readonly(vp))
		return (EROFS);

	vp = REALVP(vp);
	return (VOP_SETSECATTR(vp, secattr, flags, cr, ct));
}

static int
lxd_getsecattr(vnode_t *vp, vsecattr_t *secattr, int flags, struct cred *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (ENOSYS);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_GETSECATTR(vp, secattr, flags, cr, ct));
}

static int
lxd_shrlock(vnode_t *vp, int cmd, struct shrlock *shr, int flag, cred_t *cr,
    caller_context_t *ct)
{
	lxd_node_t *ldn = VTOLDN(vp);

	if (ldn->lxdn_type == LXDNT_FRONT) {
		return (EINVAL);
	}

	ASSERT(ldn->lxdn_type == LXDNT_BACK);
	vp = REALVP(vp);
	return (VOP_SHRLOCK(vp, cmd, shr, flag, cr, ct));
}

/*
 * Loopback vnode operations vector.
 */

struct vnodeops *lxd_vnodeops;

const fs_operation_def_t lxd_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = lxd_open },
	VOPNAME_CLOSE,		{ .vop_close = lxd_close },
	VOPNAME_READ,		{ .vop_read = lxd_read },
	VOPNAME_WRITE,		{ .vop_write = lxd_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = lxd_ioctl },
	VOPNAME_SETFL,		{ .vop_setfl = lxd_setfl },
	VOPNAME_GETATTR,	{ .vop_getattr = lxd_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = lxd_setattr },
	VOPNAME_ACCESS,		{ .vop_access = lxd_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = lxd_lookup },
	VOPNAME_CREATE,		{ .vop_create = lxd_create },
	VOPNAME_REMOVE,		{ .vop_remove = lxd_remove },
	VOPNAME_LINK,		{ .vop_link = lxd_link },
	VOPNAME_RENAME,		{ .vop_rename = lxd_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = lxd_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = lxd_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = lxd_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = lxd_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = lxd_readlink },
	VOPNAME_FSYNC,		{ .vop_fsync = lxd_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = lxd_inactive },
	VOPNAME_FID,		{ .vop_fid = lxd_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = lxd_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = lxd_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = lxd_seek },
	VOPNAME_CMP,		{ .vop_cmp = lxd_cmp },
	VOPNAME_FRLOCK,		{ .vop_frlock = lxd_frlock },
	VOPNAME_SPACE,		{ .vop_space = lxd_space },
	VOPNAME_REALVP,		{ .vop_realvp = lxd_realvp },
	VOPNAME_GETPAGE,	{ .vop_getpage = lxd_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = lxd_putpage },
	VOPNAME_MAP,		{ .vop_map = lxd_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = lxd_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = lxd_delmap },
	VOPNAME_POLL,		{ .vop_poll = lxd_poll },
	VOPNAME_DUMP,		{ .vop_dump = lxd_dump },
	VOPNAME_DUMPCTL,	{ .error = fs_error },
	VOPNAME_PATHCONF,	{ .vop_pathconf = lxd_pathconf },
	VOPNAME_PAGEIO,		{ .vop_pageio = lxd_pageio },
	VOPNAME_DISPOSE,	{ .vop_dispose = lxd_dispose },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = lxd_setsecattr },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = lxd_getsecattr },
	VOPNAME_SHRLOCK,	{ .vop_shrlock = lxd_shrlock },
	NULL,			NULL
};
