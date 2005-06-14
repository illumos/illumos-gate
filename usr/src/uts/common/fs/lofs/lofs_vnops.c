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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/fs/lofs_node.h>
#include <sys/fs/lofs_info.h>
#include <fs/fs_subr.h>
#include <vm/as.h>
#include <vm/seg.h>

#define	IS_ZONEDEVFS(vp) \
	(vtoli((vp)->v_vfsp)->li_flag & LO_ZONEDEVFS)

/*
 * These are the vnode ops routines which implement the vnode interface to
 * the looped-back file system.  These routines just take their parameters,
 * and then calling the appropriate real vnode routine(s) to do the work.
 */

static int
lo_open(vnode_t **vpp, int flag, struct cred *cr)
{
	vnode_t *vp = *vpp;
	vnode_t *rvp;
	vnode_t *oldvp;
	int error;

#ifdef LODEBUG
	lo_dprint(4, "lo_open vp %p cnt=%d realvp %p cnt=%d\n",
		vp, vp->v_count, realvp(vp), realvp(vp)->v_count);
#endif

	oldvp = vp;
	vp = rvp = realvp(vp);
	/*
	 * Need to hold new reference to vp since VOP_OPEN() may
	 * decide to release it.
	 */
	VN_HOLD(vp);
	error = VOP_OPEN(&rvp, flag, cr);

	if (!error && rvp != vp) {
		/*
		 * the FS which we called should have released the
		 * new reference on vp
		 */
		*vpp = makelonode(rvp, vtoli(oldvp->v_vfsp));
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
lo_close(
	vnode_t *vp,
	int flag,
	int count,
	offset_t offset,
	struct cred *cr)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_close vp %p realvp %p\n", vp, realvp(vp));
#endif
	vp = realvp(vp);
	return (VOP_CLOSE(vp, flag, count, offset, cr));
}

static int
lo_read(vnode_t *vp, struct uio *uiop, int ioflag, struct cred *cr,
	caller_context_t *ct)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_read vp %p realvp %p\n", vp, realvp(vp));
#endif
	vp = realvp(vp);
	return (VOP_READ(vp, uiop, ioflag, cr, ct));
}

static int
lo_write(vnode_t *vp, struct uio *uiop, int ioflag, struct cred *cr,
	caller_context_t *ct)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_write vp %p realvp %p\n", vp, realvp(vp));
#endif
	vp = realvp(vp);
	return (VOP_WRITE(vp, uiop, ioflag, cr, ct));
}

static int
lo_ioctl(
	vnode_t *vp,
	int cmd,
	intptr_t arg,
	int flag,
	struct cred *cr,
	int *rvalp)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_ioctl vp %p realvp %p\n", vp, realvp(vp));
#endif
	vp = realvp(vp);
	return (VOP_IOCTL(vp, cmd, arg, flag, cr, rvalp));
}

static int
lo_setfl(vnode_t *vp, int oflags, int nflags, cred_t *cr)
{
	vp = realvp(vp);
	return (VOP_SETFL(vp, oflags, nflags, cr));
}

static int
lo_getattr(
	vnode_t *vp,
	struct vattr *vap,
	int flags,
	struct cred *cr)
{
	int error;

#ifdef LODEBUG
	lo_dprint(4, "lo_getattr vp %p realvp %p\n", vp, realvp(vp));
#endif
	if (error = VOP_GETATTR(realvp(vp), vap, flags, cr))
		return (error);

	/*
	 * In zonedevfs mode, we pull a nasty trick; we make sure that
	 * the dev_t does *not* reflect the underlying device, so that
	 * no renames can occur to or from the /dev hierarchy.
	 */
	if (IS_ZONEDEVFS(vp)) {
		vap->va_fsid = expldev(vp->v_vfsp->vfs_fsid.val[0]);
	}

	return (0);
}

static int
lo_setattr(
	vnode_t *vp,
	struct vattr *vap,
	int flags,
	struct cred *cr,
	caller_context_t *ct)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_setattr vp %p realvp %p\n", vp, realvp(vp));
#endif
	if (IS_ZONEDEVFS(vp) && !IS_DEVVP(vp)) {
		return (EACCES);
	}
	vp = realvp(vp);
	return (VOP_SETATTR(vp, vap, flags, cr, ct));
}

static int
lo_access(vnode_t *vp, int mode, int flags, struct cred *cr)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_access vp %p realvp %p\n", vp, realvp(vp));
#endif
	if (mode & VWRITE) {
		if (vp->v_type == VREG && vn_is_readonly(vp))
			return (EROFS);
		if (IS_ZONEDEVFS(vp) && !IS_DEVVP(vp))
			return (EACCES);
	}
	vp = realvp(vp);
	return (VOP_ACCESS(vp, mode, flags, cr));
}

static int
lo_fsync(vnode_t *vp, int syncflag, struct cred *cr)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_fsync vp %p realvp %p\n", vp, realvp(vp));
#endif
	vp = realvp(vp);
	return (VOP_FSYNC(vp, syncflag, cr));
}

/*ARGSUSED*/
static void
lo_inactive(vnode_t *vp, struct cred *cr)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_inactive %p, realvp %p\n", vp, realvp(vp));
#endif
	freelonode(vtol(vp));
}

/* ARGSUSED */
static int
lo_fid(vnode_t *vp, struct fid *fidp)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_fid %p, realvp %p\n", vp, realvp(vp));
#endif
	vp = realvp(vp);
	return (VOP_FID(vp, fidp));
}

/*
 * Given a vnode of lofs type, lookup nm name and
 * return a shadow vnode (of lofs type) of the
 * real vnode found.
 *
 * Due to the nature of lofs, there is a potential
 * looping in path traversal.
 *
 * starting from the mount point of an lofs;
 * a loop is defined to be a traversal path
 * where the mount point or the real vnode of
 * the root of this lofs is encountered twice.
 * Once at the start of traversal and second
 * when the looping is found.
 *
 * When a loop is encountered, a shadow of the
 * covered vnode is returned to stop the looping.
 *
 * This normally works, but with the advent of
 * the new automounter, returning the shadow of the
 * covered vnode (autonode, in this case) does not
 * stop the loop.  Because further lookup on this
 * lonode will cause the autonode to call lo_lookup()
 * on the lonode covering it.
 *
 * example "/net/jurassic/net/jurassic" is a loop.
 * returning the shadow of the autonode corresponding to
 * "/net/jurassic/net/jurassic" will not terminate the
 * loop.   To solve this problem we allow the loop to go
 * through one more level component lookup.  If it hit
 * "net" after the loop as in "/net/jurassic/net/jurassic/net",
 * then returning the vnode covered by the autonode "net"
 * will terminate the loop.
 *
 * Lookup for dot dot has to be dealt with separately.
 * It will be nice to have a "one size fits all" kind
 * of solution, so that we don't have so many ifs statement
 * in the lo_lookup() to handle dotdot.  But, since
 * there are so many special cases to handle different
 * kinds looping above, we need special codes to handle
 * dotdot lookup as well.
 */
static int
lo_lookup(
	vnode_t *dvp,
	char *nm,
	vnode_t **vpp,
	struct pathname *pnp,
	int flags,
	vnode_t *rdir,
	struct cred *cr)
{
	vnode_t *vp = NULL, *tvp = NULL, *nonlovp;
	int error, is_indirectloop;
	vnode_t *realdvp = realvp(dvp);
	struct loinfo *li = vtoli(dvp->v_vfsp);
	int looping = 0;
	int doingdotdot = 0;
	int nosub = 0;

	/*
	 * If name is empty and no XATTR flags are set, then return
	 * dvp (empty name == lookup ".").  If an XATTR flag is set
	 * then we need to call VOP_LOOKUP to get the xattr dir.
	 */
	if (nm[0] == '\0' && ! (flags & (CREATE_XATTR_DIR|LOOKUP_XATTR))) {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}

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
	if (error = VOP_LOOKUP(realdvp, nm, &vp, pnp, flags, rdir, cr))
		goto out;

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
		if ((vtol(dvp))->lo_looping) {
			vfs_t *vfsp;

			error = vn_vfswlock_wait(realdvp);
			if (error)
				goto out;
			vfsp = vn_mountedvfs(realdvp);
			if (vfsp != NULL) {
				/*
				 * if looping get the actual found vnode
				 * instead of the vnode covered
				 * Here we have to hold the lock for realdvp
				 * since an unmount during the traversal to the
				 * root vnode would turn *vfsp into garbage
				 * which would be fatal.
				 */
				vfs_lock_wait(vfsp);
				vn_vfsunlock(realdvp);

				error = VFS_ROOT(vfsp, &tvp);

				vfs_unlock(vfsp);
				if (error)
					goto out;
				if ((tvp == li->li_rootvp)&&
				    (vp == realvp(tvp))) {
					/*
					 * we're back at the real vnode
					 * of the rootvp
					 *
					 * return the rootvp
					 * Ex: /mnt/mnt/..
					 * where / has been lofs-mounted
					 * onto /mnt.  Return the lofs
					 * node mounted at /mnt.
					 */
					*vpp = tvp;
					VN_RELE(vp);
					return (0);
				} else {
					/*
					 * We are returning from a covered
					 * node whose vfs_mountedhere is
					 * not pointing to vfs of the current
					 * root vnode.
					 * This is a condn where in we
					 * returned a covered node say Zc
					 * but Zc is not the cover of current
					 * root.
					 * i.e.., if X is the root vnode
					 * lookup(Zc,"..") is taking us to
					 * X.
					 * Ex: /net/X/net/X/net
					 * We are encountering cover of net.
					 * doing a dotdot from here means we
					 * to take the lookup to the same state
					 * that would have happened when we do
					 * lookup of any Y under /net/X/net/X
					 */
					VN_RELE(tvp);
					if (vp == realvp(li->li_rootvp)) {
						VN_RELE(vp);
						vp = li->li_rootvp;
						vp = vp->v_vfsp->
							vfs_vnodecovered;
						VN_HOLD(vp);
						*vpp = makelonode(vp, li);
						(vtol(*vpp))->lo_looping = 1;
						return (0);
					}
				}
			} else {
				/*
				 * We are returning from a looping dvp.
				 * If we are returning to rootvp return
				 * the covered node with looping bit set.
				 *
				 * This means we are not returning from cover
				 * but we should return to the root node by
				 * giving the covered node with looping flag
				 * set. We are returning from a non-covernode
				 * with looping bit set means we couldn't stop
				 * by giving the cover of root vnode.
				 *
				 *	Say X is the root vnode and lookup of
				 * X again under X returns Xc(due to looping
				 * condn). let Z=lookup(Xc,"path") and
				 * if lookup(Z,"..") returns  the root vp X
				 * return Xc with looping bit set or if a new
				 * node Z.. is returned make a shadow with a
				 * looping flag.
				 *
				 * Ex:- lookup of /net/X/net/X/Y/.. or
				 * lookup of /net/X/net/X/Y/Z/.. .
				 * In the first case we are returning to root
				 * we will return the cover of root with
				 * looping bit set.
				 */
				vn_vfsunlock(realdvp);
				if (vp == li->li_rootvp) {
					tvp = vp;
					vp = (vp)->v_vfsp->vfs_vnodecovered;
					VN_RELE(tvp);
					VN_HOLD(vp);
				}
				*vpp = makelonode(vp, li);
				(vtol(*vpp))->lo_looping = 1;
				return (0);
			}
		} else {
			/*
			 * No frills just make the shadow node.
			 */
			*vpp = makelonode(vp, li);
			return (0);
		}
	}

	nosub = (vtoli(dvp->v_vfsp)->li_flag & LO_NOSUB);

	/*
	 * If this vnode is mounted on, then we
	 * traverse to the vnode which is the root of
	 * the mounted file system.
	 */
	if (!nosub && (error = traverse(&vp)))
		goto out;

	/*
	 * Make a lnode for the real vnode.
	 */
	if (vp->v_type != VDIR || nosub) {
		*vpp = makelonode(vp, li);
		if (IS_DEVVP(*vpp)) {
			vnode_t *svp;

			svp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
			VN_RELE(*vpp);
			if (svp == NULL)
				error = ENOSYS;
			else
				*vpp = svp;
		}
		return (error);
	}

	/*
	 * if the found vnode (vp) is not of type lofs
	 * then we're just going to make a shadow of that
	 * vp and get out.
	 *
	 * If the found vnode (vp) is of lofs type, and
	 * we're not doing dotdot, check if we are
	 * looping.
	 */
	if (!doingdotdot && vfs_matchops(vp->v_vfsp, lo_vfsops)) {
		/*
		 * Check if we're looping, i.e.
		 * vp equals the root vp of the lofs, directly
		 * or indirectly, return the covered node.
		 */

		if (!(vtol(dvp))->lo_looping) {
			if (vp == li->li_rootvp) {
				/*
				 * Direct looping condn.
				 * Ex:- X is / mounted directory so lookup of
				 * /X/X is a direct looping condn.
				 */
				tvp = vp;
				vp = vp->v_vfsp->vfs_vnodecovered;
				VN_HOLD(vp);
				VN_RELE(tvp);
				looping++;
			} else {
				/*
				 * Indirect looping can be defined as
				 * real lookup returning rootvp of the current
				 * tree in any level of recursion.
				 *
				 * This check is useful if there are multiple
				 * levels of lofs indirections. Suppose vnode X
				 * in the current lookup has as its real vnode
				 * another lofs node. Y = realvp(X) Y should be
				 * a lofs node for the check to continue or Y
				 * is not the rootvp of X.
				 * Ex:- say X and Y are two vnodes
				 * say real(Y) is X and real(X) is Z
				 * parent vnode for X and Y is Z
				 * lookup(Y,"path") say we are looking for Y
				 * again under Y and we have to return Yc.
				 * but the lookup of Y under Y doesnot return
				 * Y the root vnode again here is why.
				 * 1. lookup(Y,"path of Y") will go to
				 * 2. lookup(real(Y),"path of Y") and then to
				 * 3. lookup(real(X),"path of Y").
				 * and now what lookup level 1 sees is the
				 * outcome of 2 but the vnode Y is due to
				 * lookup(Z,"path of Y") so we have to skip
				 * intermediate levels to find if in any level
				 * there is a looping.
				 */
				is_indirectloop = 0;
				nonlovp = vp;
				while (
				    vfs_matchops(nonlovp->v_vfsp, lo_vfsops) &&
				    !(is_indirectloop)) {
					if (li->li_rootvp  == nonlovp) {
						is_indirectloop++;
						break;
					}
					nonlovp = realvp(nonlovp);
				}

				if (is_indirectloop) {
					VN_RELE(vp);
					vp = nonlovp;
					vp = vp->v_vfsp->vfs_vnodecovered;
					VN_HOLD(vp);
					looping++;
				}
			}
		} else {
			/*
			 * come here only because of the interaction between
			 * the autofs and lofs.
			 *
			 * Lookup of "/net/X/net/X" will return a shadow of
			 * an autonode X_a which we call X_l.
			 *
			 * Lookup of anything under X_l, will trigger a call to
			 * auto_lookup(X_a,nm) which will eventually call
			 * lo_lookup(X_lr,nm) where X_lr is the root vnode of
			 * the current lofs.
			 *
			 * We come here only when we are called with X_l as dvp
			 * and look for something underneath.
			 *
			 * We need to find out if the vnode, which vp is
			 * shadowing, is the rootvp of the autofs.
			 *
			 */
			realdvp = realvp(dvp);
			while (vfs_matchops(realdvp->v_vfsp, lo_vfsops)) {
				realdvp = realvp(realdvp);
			}

			error = VFS_ROOT(realdvp->v_vfsp, &tvp);
			if (error)
				goto out;
			/*
			 * tvp now contains the rootvp of the vfs of the
			 * real vnode of dvp
			 */

			if (realvp(dvp)->v_vfsp == realvp(vp)->v_vfsp &&
			    tvp == realvp(vp)) {
				/*
				 * vp is the shadow of "net",
				 * the rootvp of autofs
				 */
				VN_RELE(vp);
				vp = tvp;	/* this is an autonode */

				/*
				 * Need to find the covered vnode
				 */
				vp = vp->v_vfsp->vfs_vnodecovered;
				ASSERT(vp);
				VN_HOLD(vp);
				VN_RELE(tvp);
			} else {
				VN_RELE(tvp);
			}
		}
	}
	*vpp = makelonode(vp, li);

	if ((looping) || ((vtol(dvp))->lo_looping && !doingdotdot)) {
		(vtol(*vpp))->lo_looping = 1;
	}

out:
	if (error != 0 && vp != NULL)
		VN_RELE(vp);
#ifdef LODEBUG
	lo_dprint(4,
	"lo_lookup dvp %x realdvp %x nm '%s' newvp %x real vp %x error %d\n",
		dvp, realvp(dvp), nm, *vpp, vp, error);
#endif
	return (error);
}

/*ARGSUSED*/
static int
lo_create(
	vnode_t *dvp,
	char *nm,
	struct vattr *va,
	enum vcexcl exclusive,
	int mode,
	vnode_t **vpp,
	struct cred *cr,
	int flag)
{
	int error;
	vnode_t *vp = NULL;

#ifdef LODEBUG
	lo_dprint(4, "lo_create vp %p realvp %p\n", dvp, realvp(dvp));
#endif
	if (*nm == '\0') {
		ASSERT(vpp && dvp == *vpp);
		vp = realvp(*vpp);
	}

	if (IS_ZONEDEVFS(dvp)) {
		/* Is this truly a create?  If so, fail */
		if (*vpp == NULL)
			return (EACCES);

		/* Is this an open of a non-special for writing?  If so, fail */
		if (*vpp != NULL && (mode & VWRITE) && !IS_DEVVP(*vpp))
			return (EACCES);
	}

	error = VOP_CREATE(realvp(dvp), nm, va, exclusive, mode, &vp, cr, flag);
	if (!error) {
		*vpp = makelonode(vp, vtoli(dvp->v_vfsp));
		if (IS_DEVVP(*vpp)) {
			vnode_t *svp;

			svp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
			VN_RELE(*vpp);
			if (svp == NULL)
				error = ENOSYS;
			else
				*vpp = svp;
		}
	}
	return (error);
}

static int
lo_remove(vnode_t *dvp, char *nm, struct cred *cr)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_remove vp %p realvp %p\n", dvp, realvp(dvp));
#endif
	if (IS_ZONEDEVFS(dvp))
		return (EACCES);
	dvp = realvp(dvp);
	return (VOP_REMOVE(dvp, nm, cr));
}

static int
lo_link(vnode_t *tdvp, vnode_t *vp, char *tnm, struct cred *cr)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_link vp %p realvp %p\n", vp, realvp(vp));
#endif
	while (vn_matchops(vp, lo_vnodeops)) {
		if (IS_ZONEDEVFS(vp))
			return (EACCES);
		vp = realvp(vp);
	}
	while (vn_matchops(tdvp, lo_vnodeops)) {
		if (IS_ZONEDEVFS(tdvp))
			return (EACCES);
		tdvp = realvp(tdvp);
	}
	if (vp->v_vfsp != tdvp->v_vfsp)
		return (EXDEV);
	return (VOP_LINK(tdvp, vp, tnm, cr));
}

static int
lo_rename(
	vnode_t *odvp,
	char *onm,
	vnode_t *ndvp,
	char *nnm,
	struct cred *cr)
{
	vnode_t *tnvp;

#ifdef LODEBUG
	lo_dprint(4, "lo_rename vp %p realvp %p\n", odvp, realvp(odvp));
#endif
	if (IS_ZONEDEVFS(odvp))
		return (EACCES);
	/*
	 * We need to make sure we're not trying to remove a mount point for a
	 * filesystem mounted on top of lofs, which only we know about.
	 */
	if (vn_matchops(ndvp, lo_vnodeops))	/* Not our problem. */
		goto rename;
	if (VOP_LOOKUP(ndvp, nnm, &tnvp, NULL, 0, NULL, cr) != 0)
		goto rename;
	if (tnvp->v_type != VDIR) {
		VN_RELE(tnvp);
		goto rename;
	}
	if (vn_mountedvfs(tnvp)) {
		VN_RELE(tnvp);
		return (EBUSY);
	}
	VN_RELE(tnvp);
rename:
	/*
	 * Since the case we're dealing with above can happen at any layer in
	 * the stack of lofs filesystems, we need to recurse down the stack,
	 * checking to see if there are any instances of a filesystem mounted on
	 * top of lofs. In order to keep on using the lofs version of
	 * VOP_RENAME(), we make sure that while the target directory is of type
	 * lofs, the source directory (the one used for getting the fs-specific
	 * version of VOP_RENAME()) is also of type lofs.
	 */
	if (vn_matchops(ndvp, lo_vnodeops)) {
		if (IS_ZONEDEVFS(ndvp))
			return (EACCES);
		ndvp = realvp(ndvp);	/* Check the next layer */
	} else {
		/*
		 * We can go fast here
		 */
		while (vn_matchops(odvp, lo_vnodeops)) {
			if (IS_ZONEDEVFS(odvp))
				return (EACCES);
			odvp = realvp(odvp);
		}
		if (odvp->v_vfsp != ndvp->v_vfsp)
			return (EXDEV);
	}
	return (VOP_RENAME(odvp, onm, ndvp, nnm, cr));
}

static int
lo_mkdir(
	vnode_t *dvp,
	char *nm,
	struct vattr *va,
	vnode_t **vpp,
	struct cred *cr)
{
	int error;

#ifdef LODEBUG
	lo_dprint(4, "lo_mkdir vp %p realvp %p\n", dvp, realvp(dvp));
#endif
	if (IS_ZONEDEVFS(dvp))
		return (EACCES);
	error = VOP_MKDIR(realvp(dvp), nm, va, vpp, cr);
	if (!error)
		*vpp = makelonode(*vpp, vtoli(dvp->v_vfsp));
	return (error);
}

static int
lo_realvp(vnode_t *vp, vnode_t **vpp)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_realvp %p\n", vp);
#endif
	while (vn_matchops(vp, lo_vnodeops))
		vp = realvp(vp);

	if (VOP_REALVP(vp, vpp) != 0)
		*vpp = vp;
	return (0);
}

static int
lo_rmdir(
	vnode_t *dvp,
	char *nm,
	vnode_t *cdir,
	struct cred *cr)
{
	vnode_t *rvp = cdir;

#ifdef LODEBUG
	lo_dprint(4, "lo_rmdir vp %p realvp %p\n", dvp, realvp(dvp));
#endif
	if (IS_ZONEDEVFS(dvp))
		return (EACCES);
	/* if cdir is lofs vnode ptr get its real vnode ptr */
	if (vn_matchops(dvp, vn_getops(rvp)))
		(void) lo_realvp(cdir, &rvp);
	dvp = realvp(dvp);
	return (VOP_RMDIR(dvp, nm, rvp, cr));
}

static int
lo_symlink(
	vnode_t *dvp,
	char *lnm,
	struct vattr *tva,
	char *tnm,
	struct cred *cr)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_symlink vp %p realvp %p\n", dvp, realvp(dvp));
#endif
	if (IS_ZONEDEVFS(dvp))
		return (EACCES);
	dvp = realvp(dvp);
	return (VOP_SYMLINK(dvp, lnm, tva, tnm, cr));
}

static int
lo_readlink(vnode_t *vp, struct uio *uiop, struct cred *cr)
{
	vp = realvp(vp);
	return (VOP_READLINK(vp, uiop, cr));
}

static int
lo_readdir(vnode_t *vp, struct uio *uiop, struct cred *cr, int *eofp)
{
#ifdef LODEBUG
	lo_dprint(4, "lo_readdir vp %p realvp %p\n", vp, realvp(vp));
#endif
	vp = realvp(vp);
	return (VOP_READDIR(vp, uiop, cr, eofp));
}

static int
lo_rwlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	vp = realvp(vp);
	return (VOP_RWLOCK(vp, write_lock, ct));
}

static void
lo_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ct)
{
	vp = realvp(vp);
	VOP_RWUNLOCK(vp, write_lock, ct);
}

static int
lo_seek(vnode_t *vp, offset_t ooff, offset_t *noffp)
{
	vp = realvp(vp);
	return (VOP_SEEK(vp, ooff, noffp));
}

static int
lo_cmp(vnode_t *vp1, vnode_t *vp2)
{
	while (vn_matchops(vp1, lo_vnodeops))
		vp1 = realvp(vp1);
	while (vn_matchops(vp2, lo_vnodeops))
		vp2 = realvp(vp2);
	return (VOP_CMP(vp1, vp2));
}

static int
lo_frlock(
	vnode_t *vp,
	int cmd,
	struct flock64 *bfp,
	int flag,
	offset_t offset,
	struct flk_callback *flk_cbp,
	cred_t *cr)
{
	vp = realvp(vp);
	return (VOP_FRLOCK(vp, cmd, bfp, flag, offset, flk_cbp, cr));
}

static int
lo_space(
	vnode_t *vp,
	int cmd,
	struct flock64 *bfp,
	int flag,
	offset_t offset,
	struct cred *cr,
	caller_context_t *ct)
{
	vp = realvp(vp);
	return (VOP_SPACE(vp, cmd, bfp, flag, offset, cr, ct));
}

static int
lo_getpage(
	vnode_t *vp,
	offset_t off,
	size_t len,
	uint_t *prot,
	struct page *parr[],
	size_t psz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cr)
{
	vp = realvp(vp);
	return (VOP_GETPAGE(vp, off, len, prot, parr, psz, seg, addr, rw, cr));
}

static int
lo_putpage(vnode_t *vp, offset_t off, size_t len, int flags, struct cred *cr)
{
	vp = realvp(vp);
	return (VOP_PUTPAGE(vp, off, len, flags, cr));
}

static int
lo_map(
	vnode_t *vp,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cr)
{
	vp = realvp(vp);
	return (VOP_MAP(vp, off, as, addrp, len, prot, maxprot, flags, cr));
}

static int
lo_addmap(
	vnode_t *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cr)
{
	vp = realvp(vp);
	return (VOP_ADDMAP(vp, off, as, addr, len, prot, maxprot, flags, cr));
}

static int
lo_delmap(
	vnode_t *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uint_t prot,
	uint_t maxprot,
	uint_t flags,
	struct cred *cr)
{
	vp = realvp(vp);
	return (VOP_DELMAP(vp, off, as, addr, len, prot, maxprot, flags, cr));
}

static int
lo_poll(
	vnode_t *vp,
	short events,
	int anyyet,
	short *reventsp,
	struct pollhead **phpp)
{
	vp = realvp(vp);
	return (VOP_POLL(vp, events, anyyet, reventsp, phpp));
}

static int
lo_dump(vnode_t *vp, caddr_t addr, int bn, int count)
{
	vp = realvp(vp);
	return (VOP_DUMP(vp, addr, bn, count));
}

static int
lo_pathconf(vnode_t *vp, int cmd, ulong_t *valp, struct cred *cr)
{
	vp = realvp(vp);
	return (VOP_PATHCONF(vp, cmd, valp, cr));
}

static int
lo_pageio(
	vnode_t *vp,
	struct page *pp,
	u_offset_t io_off,
	size_t io_len,
	int flags,
	cred_t *cr)
{
	vp = realvp(vp);
	return (VOP_PAGEIO(vp, pp, io_off, io_len, flags, cr));
}

static void
lo_dispose(vnode_t *vp, page_t *pp, int fl, int dn, cred_t *cr)
{
	vp = realvp(vp);
	if (vp != NULL && vp != &kvp)
		VOP_DISPOSE(vp, pp, fl, dn, cr);
}

static int
lo_setsecattr(vnode_t *vp, vsecattr_t *secattr, int flags, struct cred *cr)
{
	if (vn_is_readonly(vp))
		return (EROFS);
	vp = realvp(vp);
	return (VOP_SETSECATTR(vp, secattr, flags, cr));
}

static int
lo_getsecattr(vnode_t *vp, vsecattr_t *secattr, int flags, struct cred *cr)
{
	vp = realvp(vp);
	return (VOP_GETSECATTR(vp, secattr, flags, cr));
}

static int
lo_shrlock(vnode_t *vp, int cmd, struct shrlock *shr, int flag, cred_t *cr)
{
	vp = realvp(vp);
	return (VOP_SHRLOCK(vp, cmd, shr, flag, cr));
}

/*
 * Loopback vnode operations vector.
 */

struct vnodeops *lo_vnodeops;

const fs_operation_def_t lo_vnodeops_template[] = {
	VOPNAME_OPEN, lo_open,
	VOPNAME_CLOSE, lo_close,
	VOPNAME_READ, lo_read,
	VOPNAME_WRITE, lo_write,
	VOPNAME_IOCTL, lo_ioctl,
	VOPNAME_SETFL, lo_setfl,
	VOPNAME_GETATTR, lo_getattr,
	VOPNAME_SETATTR, lo_setattr,
	VOPNAME_ACCESS, lo_access,
	VOPNAME_LOOKUP, lo_lookup,
	VOPNAME_CREATE, lo_create,
	VOPNAME_REMOVE, lo_remove,
	VOPNAME_LINK, lo_link,
	VOPNAME_RENAME, lo_rename,
	VOPNAME_MKDIR, lo_mkdir,
	VOPNAME_RMDIR, lo_rmdir,
	VOPNAME_READDIR, lo_readdir,
	VOPNAME_SYMLINK, lo_symlink,
	VOPNAME_READLINK, lo_readlink,
	VOPNAME_FSYNC, lo_fsync,
	VOPNAME_INACTIVE, (fs_generic_func_p) lo_inactive,
	VOPNAME_FID, lo_fid,
	VOPNAME_RWLOCK, lo_rwlock,
	VOPNAME_RWUNLOCK, (fs_generic_func_p) lo_rwunlock,
	VOPNAME_SEEK, lo_seek,
	VOPNAME_CMP, lo_cmp,
	VOPNAME_FRLOCK, lo_frlock,
	VOPNAME_SPACE, lo_space,
	VOPNAME_REALVP, lo_realvp,
	VOPNAME_GETPAGE, lo_getpage,
	VOPNAME_PUTPAGE, lo_putpage,
	VOPNAME_MAP, (fs_generic_func_p) lo_map,
	VOPNAME_ADDMAP, (fs_generic_func_p) lo_addmap,
	VOPNAME_DELMAP, lo_delmap,
	VOPNAME_POLL, (fs_generic_func_p) lo_poll,
	VOPNAME_DUMP, lo_dump,
	VOPNAME_DUMPCTL, fs_error,		/* XXX - why? */
	VOPNAME_PATHCONF, lo_pathconf,
	VOPNAME_PAGEIO, lo_pageio,
	VOPNAME_DISPOSE, (fs_generic_func_p) lo_dispose,
	VOPNAME_SETSECATTR, lo_setsecattr,
	VOPNAME_GETSECATTR, lo_getsecattr,
	VOPNAME_SHRLOCK, lo_shrlock,
	NULL, NULL
};
