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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */


#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/fs/snode.h>
#include <sys/fs/fifonode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/user.h>
#include <sys/termios.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/autoconf.h>
#include <sys/esunddi.h>
#include <sys/flock.h>
#include <sys/modctl.h>

struct vfs spec_vfs;
static dev_t specdev;
struct kmem_cache *snode_cache;
int spec_debug = 0;

static struct snode *sfind(dev_t, vtype_t, struct vnode *);
static struct vnode *get_cvp(dev_t, vtype_t, struct snode *, int *);
static void sinsert(struct snode *);

struct vnode *
specvp_devfs(
	struct vnode	*realvp,
	dev_t		dev,
	vtype_t		vtyp,
	struct cred	*cr,
	dev_info_t	*dip)
{
	struct vnode	*vp;

	ASSERT(realvp && dip);
	vp = specvp(realvp, dev, vtyp, cr);
	ASSERT(vp);

	/* associate a dip hold with the common snode's s_dip pointer */
	spec_assoc_vp_with_devi(vp, dip);
	return (vp);
}

/*
 * Return a shadow special vnode for the given dev.
 * If no snode exists for this dev create one and put it
 * in a table hashed by <dev, realvp>.  If the snode for
 * this dev is already in the table return it (ref count is
 * incremented by sfind).  The snode will be flushed from the
 * table when spec_inactive calls sdelete.
 *
 * The fsid is inherited from the real vnode so that clones
 * can be found.
 *
 */
struct vnode *
specvp(
	struct vnode	*vp,
	dev_t		dev,
	vtype_t		type,
	struct cred	*cr)
{
	struct snode *sp;
	struct snode *nsp;
	struct snode *csp;
	struct vnode *svp;
	struct vattr va;
	int	rc;
	int	used_csp = 0;		/* Did we use pre-allocated csp */

	if (vp == NULL)
		return (NULL);
	if (vp->v_type == VFIFO)
		return (fifovp(vp, cr));

	ASSERT(vp->v_type == type);
	ASSERT(vp->v_rdev == dev);

	/*
	 * Pre-allocate snodes before holding any locks in case we block
	 */
	nsp = kmem_cache_alloc(snode_cache, KM_SLEEP);
	csp = kmem_cache_alloc(snode_cache, KM_SLEEP);

	/*
	 * Get the time attributes outside of the stable lock since
	 * this operation may block. Unfortunately, it may not have
	 * been required if the snode is in the cache.
	 */
	va.va_mask = AT_FSID | AT_TIMES;
	rc = VOP_GETATTR(vp, &va, 0, cr, NULL);	/* XXX may block! */

	mutex_enter(&stable_lock);
	if ((sp = sfind(dev, type, vp)) == NULL) {
		struct vnode *cvp;

		sp = nsp;	/* Use pre-allocated snode */
		svp = STOV(sp);

		sp->s_realvp	= vp;
		VN_HOLD(vp);
		sp->s_commonvp	= NULL;
		sp->s_dev	= dev;
		sp->s_dip	= NULL;
		sp->s_nextr	= NULL;
		sp->s_list	= NULL;
		sp->s_plcy	= NULL;
		sp->s_size	= 0;
		sp->s_flag	= 0;
		if (rc == 0) {
			/*
			 * Set times in snode to those in the vnode.
			 */
			sp->s_fsid = va.va_fsid;
			sp->s_atime = va.va_atime.tv_sec;
			sp->s_mtime = va.va_mtime.tv_sec;
			sp->s_ctime = va.va_ctime.tv_sec;
		} else {
			sp->s_fsid = specdev;
			sp->s_atime = 0;
			sp->s_mtime = 0;
			sp->s_ctime = 0;
		}
		sp->s_count	= 0;
		sp->s_mapcnt	= 0;

		vn_reinit(svp);
		svp->v_flag	= (vp->v_flag & VROOT);
		svp->v_vfsp	= vp->v_vfsp;
		VFS_HOLD(svp->v_vfsp);
		svp->v_type	= type;
		svp->v_rdev	= dev;
		(void) vn_copypath(vp, svp);
		if (type == VBLK || type == VCHR) {
			cvp = get_cvp(dev, type, csp, &used_csp);
			svp->v_stream = cvp->v_stream;

			sp->s_commonvp = cvp;
		}
		vn_exists(svp);
		sinsert(sp);
		mutex_exit(&stable_lock);
		if (used_csp == 0) {
			/* Didn't use pre-allocated snode so free it */
			kmem_cache_free(snode_cache, csp);
		}
	} else {
		mutex_exit(&stable_lock);
		/* free unused snode memory */
		kmem_cache_free(snode_cache, nsp);
		kmem_cache_free(snode_cache, csp);
	}
	return (STOV(sp));
}

/*
 * Return a special vnode for the given dev; no vnode is supplied
 * for it to shadow.  Always create a new snode and put it in the
 * table hashed by <dev, NULL>.  The snode will be flushed from the
 * table when spec_inactive() calls sdelete().  The association of
 * this node with a attached instance of hardware is not made until
 * spec_open time.
 *
 * N.B. Assumes caller takes on responsibility of making sure no one
 * else is creating a snode for (dev, type) at this time.
 */
struct vnode *
makespecvp(dev_t dev, vtype_t type)
{
	struct snode *sp;
	struct vnode *svp, *cvp;
	time_t now;

	sp = kmem_cache_alloc(snode_cache, KM_SLEEP);
	svp = STOV(sp);
	cvp = commonvp(dev, type);
	now = gethrestime_sec();

	sp->s_realvp	= NULL;
	sp->s_commonvp	= cvp;
	sp->s_dev	= dev;
	sp->s_dip	= NULL;
	sp->s_nextr	= NULL;
	sp->s_list	= NULL;
	sp->s_plcy	= NULL;
	sp->s_size	= 0;
	sp->s_flag	= 0;
	sp->s_fsid	= specdev;
	sp->s_atime	= now;
	sp->s_mtime	= now;
	sp->s_ctime	= now;
	sp->s_count	= 0;
	sp->s_mapcnt	= 0;

	vn_reinit(svp);
	svp->v_vfsp	= &spec_vfs;
	svp->v_stream	= cvp->v_stream;
	svp->v_type	= type;
	svp->v_rdev	= dev;

	vn_exists(svp);
	mutex_enter(&stable_lock);
	sinsert(sp);
	mutex_exit(&stable_lock);

	return (svp);
}


/*
 * This function is called from spec_assoc_vp_with_devi(). That function
 * associates a "new" dip with a common snode, releasing (any) old dip
 * in the process. This function (spec_assoc_fence()) looks at the "new dip"
 * and determines whether the snode should be fenced of or not. As the table
 * below indicates, the value of old-dip is a don't care for all cases.
 *
 * old-dip	new-dip		common-snode
 * =========================================
 * Don't care	NULL		unfence
 * Don't care	retired		fence
 * Don't care	not-retired	unfence
 *
 * Since old-dip value is a "don't care", it is not passed into this function.
 */
static void
spec_assoc_fence(dev_info_t *ndip, vnode_t *vp)
{
	int		fence;
	struct snode	*csp;

	ASSERT(vp);
	ASSERT(vn_matchops(vp, spec_getvnodeops()));

	fence = 0;
	if (ndip != NULL) {
		mutex_enter(&DEVI(ndip)->devi_lock);
		if (DEVI(ndip)->devi_flags & DEVI_RETIRED)
			fence = 1;
		mutex_exit(&DEVI(ndip)->devi_lock);
	}

	csp = VTOCS(vp);
	ASSERT(csp);

	/* SFENCED flag only set on common snode */
	mutex_enter(&csp->s_lock);
	if (fence)
		csp->s_flag |= SFENCED;
	else
		csp->s_flag &= ~SFENCED;
	mutex_exit(&csp->s_lock);

	FENDBG((CE_NOTE, "%sfenced common snode (%p) for new dip=%p",
	    fence ? "" : "un", (void *)csp, (void *)ndip));
}

/*
 * Associate the common snode with a devinfo node.  This is called from:
 *
 *   1) specvp_devfs to associate a specfs node with the dip attached
 *	by devfs.
 *
 *   2) spec_open after path reconstruction and attach.
 *
 *   3) From dacf processing to associate a makespecvp node with
 *	the dip that dacf postattach processing is being performed on.
 *	This association is made prior to open to avoid recursion issues.
 *
 *   4) From ddi_assoc_queue_with_devi to change vnode association as part of
 *	DL_ATTACH/DL_DETACH processing (SDIPSET already set).  The call
 *	from ddi_assoc_queue_with_devi may specify a NULL dip.
 *
 * We put an extra hold on the devinfo node passed in as we establish it as
 * the new s_dip pointer.  Any hold associated with the prior s_dip pointer
 * is released. The new hold will stay active until another call to
 * spec_assoc_vp_with_devi or until the common snode is destroyed by
 * spec_inactive after the last VN_RELE of the common node. This devinfo hold
 * transfers across a clone open except in the clone_dev case, where the clone
 * driver is no longer required after open.
 *
 * When SDIPSET is set and s_dip is NULL, the vnode has an association with
 * the driver even though there is currently no association with a specific
 * hardware instance.
 */
void
spec_assoc_vp_with_devi(struct vnode *vp, dev_info_t *dip)
{
	struct snode	*csp;
	dev_info_t	*olddip;

	ASSERT(vp);

	/*
	 * Don't establish a NULL association for a vnode associated with the
	 * clone driver.  The qassociate(, -1) call from a streams driver's
	 * open implementation to indicate support for qassociate has the
	 * side-effect of this type of spec_assoc_vp_with_devi call. This
	 * call should not change the the association of the pre-clone
	 * vnode associated with the clone driver, the post-clone newdev
	 * association will be established later by spec_clone().
	 */
	if ((dip == NULL) && (getmajor(vp->v_rdev) == clone_major))
		return;

	/* hold the new */
	if (dip)
		e_ddi_hold_devi(dip);

	csp = VTOS(VTOS(vp)->s_commonvp);
	mutex_enter(&csp->s_lock);
	olddip = csp->s_dip;
	csp->s_dip = dip;
	csp->s_flag |= SDIPSET;

	/* If association changes then invalidate cached size */
	if (olddip != dip)
		csp->s_flag &= ~SSIZEVALID;
	mutex_exit(&csp->s_lock);

	spec_assoc_fence(dip, vp);

	/* release the old */
	if (olddip)
		ddi_release_devi(olddip);
}

/*
 * Return the held dip associated with the specified snode.
 */
dev_info_t *
spec_hold_devi_by_vp(struct vnode *vp)
{
	struct snode	*csp;
	dev_info_t	*dip;

	ASSERT(vn_matchops(vp, spec_getvnodeops()));

	csp = VTOS(VTOS(vp)->s_commonvp);
	dip = csp->s_dip;
	if (dip)
		e_ddi_hold_devi(dip);
	return (dip);
}

/*
 * Find a special vnode that refers to the given device
 * of the given type.  Never return a "common" vnode.
 * Return NULL if a special vnode does not exist.
 * HOLD the vnode before returning it.
 */
struct vnode *
specfind(dev_t dev, vtype_t type)
{
	struct snode *st;
	struct vnode *nvp;

	mutex_enter(&stable_lock);
	st = stable[STABLEHASH(dev)];
	while (st != NULL) {
		if (st->s_dev == dev) {
			nvp = STOV(st);
			if (nvp->v_type == type && st->s_commonvp != nvp) {
				VN_HOLD(nvp);
				/* validate vnode is visible in the zone */
				if (nvp->v_path != NULL &&
				    ZONE_PATH_VISIBLE(nvp->v_path, curzone)) {
					mutex_exit(&stable_lock);
					return (nvp);
				}
				VN_RELE(nvp);
			}
		}
		st = st->s_next;
	}
	mutex_exit(&stable_lock);
	return (NULL);
}

/*
 * Loop through the snode cache looking for snodes referencing dip.
 *
 * This function determines if a devinfo node is "BUSY" from the perspective
 * of having an active vnode associated with the device, which represents a
 * dependency on the device's services.  This function is needed because a
 * devinfo node can have a non-zero devi_ref and still NOT be "BUSY" when,
 * for instance, the framework is manipulating the node (has an open
 * ndi_hold_devi).
 *
 * Returns:
 *	DEVI_REFERENCED		- if dip is referenced
 *	DEVI_NOT_REFERENCED	- if dip is not referenced
 */
int
devi_stillreferenced(dev_info_t *dip)
{
	struct snode	*sp;
	int		i;

	/* if no hold then there can't be an snode with s_dip == dip */
	if (e_ddi_devi_holdcnt(dip) == 0)
		return (DEVI_NOT_REFERENCED);

	mutex_enter(&stable_lock);
	for (i = 0; i < STABLESIZE; i++) {
		for (sp = stable[i]; sp != NULL; sp = sp->s_next) {
			if (sp->s_dip == dip) {
				mutex_exit(&stable_lock);
				return (DEVI_REFERENCED);
			}
		}
	}
	mutex_exit(&stable_lock);
	return (DEVI_NOT_REFERENCED);
}

/*
 * Given an snode, returns the open count and the dip
 * associated with that snode
 * Assumes the caller holds the appropriate locks
 * to prevent snode and/or dip from going away.
 * Returns:
 *	-1	No associated dip
 *	>= 0	Number of opens.
 */
int
spec_devi_open_count(struct snode *sp, dev_info_t **dipp)
{
	dev_info_t *dip;
	uint_t count;
	struct vnode *vp;

	ASSERT(sp);
	ASSERT(dipp);

	vp = STOV(sp);

	*dipp = NULL;

	/*
	 * We are only interested in common snodes. Only common snodes
	 * get their s_count fields bumped up on opens.
	 */
	if (sp->s_commonvp != vp || (dip = sp->s_dip) == NULL)
		return (-1);

	mutex_enter(&sp->s_lock);
	count = sp->s_count + sp->s_mapcnt;
	if (sp->s_flag & SLOCKED)
		count++;
	mutex_exit(&sp->s_lock);

	*dipp = dip;

	return (count);
}

/*
 * Given a device vnode, return the common
 * vnode associated with it.
 */
struct vnode *
common_specvp(struct vnode *vp)
{
	struct snode *sp;

	if ((vp->v_type != VBLK) && (vp->v_type != VCHR) ||
	    !vn_matchops(vp, spec_getvnodeops()))
		return (vp);
	sp = VTOS(vp);
	return (sp->s_commonvp);
}

/*
 * Returns a special vnode for the given dev.  The vnode is the
 * one which is "common" to all the snodes which represent the
 * same device.
 * Similar to commonvp() but doesn't acquire the stable_lock, and
 * may use a pre-allocated snode provided by caller.
 */
static struct vnode *
get_cvp(
	dev_t		dev,
	vtype_t		type,
	struct snode	*nsp,		/* pre-allocated snode */
	int		*used_nsp)	/* flag indicating if we use nsp */
{
	struct snode *sp;
	struct vnode *svp;

	ASSERT(MUTEX_HELD(&stable_lock));
	if ((sp = sfind(dev, type, NULL)) == NULL) {
		sp = nsp;		/* Use pre-allocated snode */
		*used_nsp = 1;		/* return value */
		svp = STOV(sp);

		sp->s_realvp	= NULL;
		sp->s_commonvp	= svp;		/* points to itself */
		sp->s_dev	= dev;
		sp->s_dip	= NULL;
		sp->s_nextr	= NULL;
		sp->s_list	= NULL;
		sp->s_plcy	= NULL;
		sp->s_size	= UNKNOWN_SIZE;
		sp->s_flag	= 0;
		sp->s_fsid	= specdev;
		sp->s_atime	= 0;
		sp->s_mtime	= 0;
		sp->s_ctime	= 0;
		sp->s_count	= 0;
		sp->s_mapcnt	= 0;

		vn_reinit(svp);
		svp->v_vfsp	= &spec_vfs;
		svp->v_type	= type;
		svp->v_rdev	= dev;
		vn_exists(svp);
		sinsert(sp);
	} else
		*used_nsp = 0;
	return (STOV(sp));
}

/*
 * Returns a special vnode for the given dev.  The vnode is the
 * one which is "common" to all the snodes which represent the
 * same device.  For use ONLY by SPECFS.
 */
struct vnode *
commonvp(dev_t dev, vtype_t type)
{
	struct snode *sp, *nsp;
	struct vnode *svp;

	/* Pre-allocate snode in case we might block */
	nsp = kmem_cache_alloc(snode_cache, KM_SLEEP);

	mutex_enter(&stable_lock);
	if ((sp = sfind(dev, type, NULL)) == NULL) {
		sp = nsp;		/* Use pre-alloced snode */
		svp = STOV(sp);

		sp->s_realvp	= NULL;
		sp->s_commonvp	= svp;		/* points to itself */
		sp->s_dev	= dev;
		sp->s_dip	= NULL;
		sp->s_nextr	= NULL;
		sp->s_list	= NULL;
		sp->s_plcy	= NULL;
		sp->s_size	= UNKNOWN_SIZE;
		sp->s_flag	= 0;
		sp->s_fsid	= specdev;
		sp->s_atime	= 0;
		sp->s_mtime	= 0;
		sp->s_ctime	= 0;
		sp->s_count	= 0;
		sp->s_mapcnt	= 0;

		vn_reinit(svp);
		svp->v_vfsp	= &spec_vfs;
		svp->v_type	= type;
		svp->v_rdev	= dev;
		vn_exists(svp);
		sinsert(sp);
		mutex_exit(&stable_lock);
	} else {
		mutex_exit(&stable_lock);
		/* Didn't need the pre-allocated snode */
		kmem_cache_free(snode_cache, nsp);
	}
	return (STOV(sp));
}

/*
 * Snode lookup stuff.
 * These routines maintain a table of snodes hashed by dev so
 * that the snode for an dev can be found if it already exists.
 */
struct snode *stable[STABLESIZE];
int		stablesz = STABLESIZE;
kmutex_t	stable_lock;

/*
 * Put a snode in the table.
 */
static void
sinsert(struct snode *sp)
{
	ASSERT(MUTEX_HELD(&stable_lock));
	sp->s_next = stable[STABLEHASH(sp->s_dev)];
	stable[STABLEHASH(sp->s_dev)] = sp;
}

/*
 * Remove an snode from the hash table.
 * The realvp is not released here because spec_inactive() still
 * needs it to do a spec_fsync().
 */
void
sdelete(struct snode *sp)
{
	struct snode *st;
	struct snode *stprev = NULL;

	ASSERT(MUTEX_HELD(&stable_lock));
	st = stable[STABLEHASH(sp->s_dev)];
	while (st != NULL) {
		if (st == sp) {
			if (stprev == NULL)
				stable[STABLEHASH(sp->s_dev)] = st->s_next;
			else
				stprev->s_next = st->s_next;
			break;
		}
		stprev = st;
		st = st->s_next;
	}
}

/*
 * Lookup an snode by <dev, type, vp>.
 * ONLY looks for snodes with non-NULL s_realvp members and
 * common snodes (with s_commonvp pointing to its vnode).
 *
 * If vp is NULL, only return commonvp. Otherwise return
 * shadow vp with both shadow and common vp's VN_HELD.
 */
static struct snode *
sfind(
	dev_t	dev,
	vtype_t	type,
	struct vnode *vp)
{
	struct snode *st;
	struct vnode *svp;

	ASSERT(MUTEX_HELD(&stable_lock));
	st = stable[STABLEHASH(dev)];
	while (st != NULL) {
		svp = STOV(st);
		if (st->s_dev == dev && svp->v_type == type &&
		    VN_CMP(st->s_realvp, vp) &&
		    (vp != NULL || st->s_commonvp == svp) &&
		    (vp == NULL || st->s_realvp->v_vfsp == vp->v_vfsp)) {
			VN_HOLD(svp);
			return (st);
		}
		st = st->s_next;
	}
	return (NULL);
}

/*
 * Mark the accessed, updated, or changed times in an snode
 * with the current time.
 */
void
smark(struct snode *sp, int flag)
{
	time_t	now = gethrestime_sec();

	/* check for change to avoid unnecessary locking */
	ASSERT((flag & ~(SACC|SUPD|SCHG)) == 0);
	if (((flag & sp->s_flag) != flag) ||
	    ((flag & SACC) && (sp->s_atime != now)) ||
	    ((flag & SUPD) && (sp->s_mtime != now)) ||
	    ((flag & SCHG) && (sp->s_ctime != now))) {
		/* lock and update */
		mutex_enter(&sp->s_lock);
		sp->s_flag |= flag;
		if (flag & SACC)
			sp->s_atime = now;
		if (flag & SUPD)
			sp->s_mtime = now;
		if (flag & SCHG)
			sp->s_ctime = now;
		mutex_exit(&sp->s_lock);
	}
}

/*
 * Return the maximum file offset permitted for this device.
 * -1 means unrestricted.  SLOFFSET is associated with D_64BIT.
 *
 * On a 32-bit kernel this will limit:
 *   o	D_64BIT devices to SPEC_MAXOFFSET_T.
 *   o	non-D_64BIT character drivers to a 32-bit offset (MAXOFF_T).
 */
offset_t
spec_maxoffset(struct vnode *vp)
{
	struct snode *sp = VTOS(vp);
	struct snode *csp = VTOS(sp->s_commonvp);

	if (vp->v_stream)
		return ((offset_t)-1);
	else if (csp->s_flag & SANYOFFSET)	/* D_U64BIT */
		return ((offset_t)-1);
#ifdef _ILP32
	if (csp->s_flag & SLOFFSET)		/* D_64BIT */
		return (SPEC_MAXOFFSET_T);
#endif	/* _ILP32 */
	return (MAXOFF_T);
}

/*ARGSUSED*/
static int
snode_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct snode *sp = buf;
	struct vnode *vp;

	vp = sp->s_vnode = vn_alloc(kmflags);
	if (vp == NULL) {
		return (-1);
	}
	vn_setops(vp, spec_getvnodeops());
	vp->v_data = sp;

	mutex_init(&sp->s_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sp->s_cv, NULL, CV_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED1*/
static void
snode_destructor(void *buf, void *cdrarg)
{
	struct snode *sp = buf;
	struct vnode *vp = STOV(sp);

	mutex_destroy(&sp->s_lock);
	cv_destroy(&sp->s_cv);

	vn_free(vp);
}


int
specinit(int fstype, char *name)
{
	static const fs_operation_def_t spec_vfsops_template[] = {
		VFSNAME_SYNC, { .vfs_sync = spec_sync },
		NULL, NULL
	};
	extern struct vnodeops *spec_vnodeops;
	extern const fs_operation_def_t spec_vnodeops_template[];
	struct vfsops *spec_vfsops;
	int error;
	dev_t dev;

	/*
	 * Associate vfs and vnode operations.
	 */
	error = vfs_setfsops(fstype, spec_vfsops_template, &spec_vfsops);
	if (error != 0) {
		cmn_err(CE_WARN, "specinit: bad vfs ops template");
		return (error);
	}

	error = vn_make_ops(name, spec_vnodeops_template, &spec_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "specinit: bad vnode ops template");
		return (error);
	}

	mutex_init(&stable_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&spec_syncbusy, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Create snode cache
	 */
	snode_cache = kmem_cache_create("snode_cache", sizeof (struct snode),
	    0, snode_constructor, snode_destructor, NULL, NULL, NULL, 0);

	/*
	 * Associate vfs operations with spec_vfs
	 */
	VFS_INIT(&spec_vfs, spec_vfsops, (caddr_t)NULL);
	if ((dev = getudev()) == -1)
		dev = 0;
	specdev = makedevice(dev, 0);
	return (0);
}

int
device_close(struct vnode *vp, int flag, struct cred *cr)
{
	struct snode *sp = VTOS(vp);
	enum vtype type = vp->v_type;
	struct vnode *cvp;
	dev_t dev;
	int error;

	dev = sp->s_dev;
	cvp = sp->s_commonvp;

	switch (type) {

	case VCHR:
		if (vp->v_stream) {
			if (cvp->v_stream != NULL)
				error = strclose(cvp, flag, cr);
			vp->v_stream = NULL;
		} else
			error = dev_close(dev, flag, OTYP_CHR, cr);
		break;

	case VBLK:
		/*
		 * On last close a block device we must
		 * invalidate any in-core blocks so that we
		 * can, for example, change floppy disks.
		 */
		(void) spec_putpage(cvp, (offset_t)0,
		    (size_t)0, B_INVAL|B_FORCE, cr, NULL);
		bflush(dev);
		binval(dev);
		error = dev_close(dev, flag, OTYP_BLK, cr);
		break;
	default:
		panic("device_close: not a device");
		/*NOTREACHED*/
	}

	return (error);
}

struct vnode *
makectty(vnode_t *ovp)
{
	vnode_t *vp;

	if (vp = makespecvp(ovp->v_rdev, VCHR)) {
		struct snode *sp;
		struct snode *csp;
		struct vnode *cvp;

		sp = VTOS(vp);
		cvp = sp->s_commonvp;
		csp = VTOS(cvp);
		mutex_enter(&csp->s_lock);
		csp->s_count++;
		mutex_exit(&csp->s_lock);
	}

	return (vp);
}

void
spec_snode_walk(int (*callback)(struct snode *sp, void *arg), void *arg)
{
	struct snode	*sp;
	int		i;

	ASSERT(callback);

	mutex_enter(&stable_lock);
	for (i = 0; i < STABLESIZE; i++) {
		for (sp = stable[i]; sp; sp = sp->s_next) {
			if (callback(sp, arg) != DDI_WALK_CONTINUE)
				goto out;
		}
	}
out:
	mutex_exit(&stable_lock);
}

int
spec_is_clone(vnode_t *vp)
{
	struct snode *sp;

	if (vn_matchops(vp, spec_getvnodeops())) {
		sp = VTOS(vp);
		return ((sp->s_flag & SCLONE) ? 1 : 0);
	}

	return (0);
}

int
spec_is_selfclone(vnode_t *vp)
{
	struct snode *sp;

	if (vn_matchops(vp, spec_getvnodeops())) {
		sp = VTOS(vp);
		return ((sp->s_flag & SSELFCLONE) ? 1 : 0);
	}

	return (0);
}

/*
 * We may be invoked with a NULL vp in which case we fence off
 * all snodes associated with dip
 */
int
spec_fence_snode(dev_info_t *dip, struct vnode *vp)
{
	struct snode	*sp;
	struct snode	*csp;
	int		retired;
	int		i;
	char		*path;
	int		emitted;

	ASSERT(dip);

	retired = 0;
	mutex_enter(&DEVI(dip)->devi_lock);
	if (DEVI(dip)->devi_flags & DEVI_RETIRED)
		retired = 1;
	mutex_exit(&DEVI(dip)->devi_lock);

	if (!retired)
		return (0);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);


	if (vp != NULL) {
		ASSERT(vn_matchops(vp, spec_getvnodeops()));
		csp = VTOCS(vp);
		ASSERT(csp);
		mutex_enter(&csp->s_lock);
		csp->s_flag |= SFENCED;
		mutex_exit(&csp->s_lock);
		FENDBG((CE_NOTE, "fenced off snode(%p) for dip: %s",
		    (void *)csp, path));
		kmem_free(path, MAXPATHLEN);
		return (0);
	}

	emitted = 0;
	mutex_enter(&stable_lock);
	for (i = 0; i < STABLESIZE; i++) {
		for (sp = stable[i]; sp != NULL; sp = sp->s_next) {
			ASSERT(sp->s_commonvp);
			csp = VTOS(sp->s_commonvp);
			if (csp->s_dip == dip) {
				/* fence off the common snode */
				mutex_enter(&csp->s_lock);
				csp->s_flag |= SFENCED;
				mutex_exit(&csp->s_lock);
				if (!emitted) {
					FENDBG((CE_NOTE, "fenced 1 of N"));
					emitted++;
				}
			}
		}
	}
	mutex_exit(&stable_lock);

	FENDBG((CE_NOTE, "fenced off all snodes for dip: %s", path));
	kmem_free(path, MAXPATHLEN);

	return (0);
}


int
spec_unfence_snode(dev_info_t *dip)
{
	struct snode	*sp;
	struct snode	*csp;
	int		i;
	char		*path;
	int		emitted;

	ASSERT(dip);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);

	emitted = 0;
	mutex_enter(&stable_lock);
	for (i = 0; i < STABLESIZE; i++) {
		for (sp = stable[i]; sp != NULL; sp = sp->s_next) {
			ASSERT(sp->s_commonvp);
			csp = VTOS(sp->s_commonvp);
			ASSERT(csp);
			if (csp->s_dip == dip) {
				/* unfence the common snode */
				mutex_enter(&csp->s_lock);
				csp->s_flag &= ~SFENCED;
				mutex_exit(&csp->s_lock);
				if (!emitted) {
					FENDBG((CE_NOTE, "unfenced 1 of N"));
					emitted++;
				}
			}
		}
	}
	mutex_exit(&stable_lock);

	FENDBG((CE_NOTE, "unfenced all snodes for dip: %s", path));
	kmem_free(path, MAXPATHLEN);

	return (0);
}

void
spec_size_invalidate(dev_t dev, vtype_t type)
{

	struct snode *csp;

	mutex_enter(&stable_lock);
	if ((csp = sfind(dev, type, NULL)) != NULL) {
		mutex_enter(&csp->s_lock);
		csp->s_flag &= ~SSIZEVALID;
		VN_RELE_ASYNC(STOV(csp), system_taskq);
		mutex_exit(&csp->s_lock);
	}
	mutex_exit(&stable_lock);
}
