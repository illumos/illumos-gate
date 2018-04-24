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
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 *  	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/t_lock.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/errno.h>
#include <sys/buf.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/dnlc.h>
#include <sys/vmsystm.h>
#include <sys/flock.h>
#include <sys/share.h>
#include <sys/cmn_err.h>
#include <sys/tiuser.h>
#include <sys/sysmacros.h>
#include <sys/callb.h>
#include <sys/acl.h>
#include <sys/kstat.h>
#include <sys/signal.h>
#include <sys/list.h>
#include <sys/zone.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>

#include <nfs/rnode.h>
#include <nfs/nfs_acl.h>
#include <nfs/lm.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>

static void	nfs3_attr_cache(vnode_t *, vattr_t *, vattr_t *, hrtime_t,
			cred_t *);
static int	nfs_getattr_cache(vnode_t *, struct vattr *);
static int	nfs_remove_locking_id(vnode_t *, int, char *, char *, int *);

struct mi_globals {
	kmutex_t	mig_lock;  /* lock protecting mig_list */
	list_t		mig_list;  /* list of NFS v2 or v3 mounts in zone */
	boolean_t	mig_destructor_called;
};

static zone_key_t mi_list_key;

/* Debugging flag for PC file shares. */
extern int	share_debug;

/*
 * Attributes caching:
 *
 * Attributes are cached in the rnode in struct vattr form.
 * There is a time associated with the cached attributes (r_attrtime)
 * which tells whether the attributes are valid. The time is initialized
 * to the difference between current time and the modify time of the vnode
 * when new attributes are cached. This allows the attributes for
 * files that have changed recently to be timed out sooner than for files
 * that have not changed for a long time. There are minimum and maximum
 * timeout values that can be set per mount point.
 */

int
nfs_waitfor_purge_complete(vnode_t *vp)
{
	rnode_t *rp;
	k_sigset_t smask;

	rp = VTOR(vp);
	if (rp->r_serial != NULL && rp->r_serial != curthread) {
		mutex_enter(&rp->r_statelock);
		sigintr(&smask, VTOMI(vp)->mi_flags & MI_INT);
		while (rp->r_serial != NULL) {
			if (!cv_wait_sig(&rp->r_cv, &rp->r_statelock)) {
				sigunintr(&smask);
				mutex_exit(&rp->r_statelock);
				return (EINTR);
			}
		}
		sigunintr(&smask);
		mutex_exit(&rp->r_statelock);
	}
	return (0);
}

/*
 * Validate caches by checking cached attributes. If the cached
 * attributes have timed out, then get new attributes from the server.
 * As a side affect, this will do cache invalidation if the attributes
 * have changed.
 *
 * If the attributes have not timed out and if there is a cache
 * invalidation being done by some other thread, then wait until that
 * thread has completed the cache invalidation.
 */
int
nfs_validate_caches(vnode_t *vp, cred_t *cr)
{
	int error;
	struct vattr va;

	if (ATTRCACHE_VALID(vp)) {
		error = nfs_waitfor_purge_complete(vp);
		if (error)
			return (error);
		return (0);
	}

	va.va_mask = AT_ALL;
	return (nfs_getattr_otw(vp, &va, cr));
}

/*
 * Validate caches by checking cached attributes. If the cached
 * attributes have timed out, then get new attributes from the server.
 * As a side affect, this will do cache invalidation if the attributes
 * have changed.
 *
 * If the attributes have not timed out and if there is a cache
 * invalidation being done by some other thread, then wait until that
 * thread has completed the cache invalidation.
 */
int
nfs3_validate_caches(vnode_t *vp, cred_t *cr)
{
	int error;
	struct vattr va;

	if (ATTRCACHE_VALID(vp)) {
		error = nfs_waitfor_purge_complete(vp);
		if (error)
			return (error);
		return (0);
	}

	va.va_mask = AT_ALL;
	return (nfs3_getattr_otw(vp, &va, cr));
}

/*
 * Purge all of the various NFS `data' caches.
 */
void
nfs_purge_caches(vnode_t *vp, int purge_dnlc, cred_t *cr)
{
	rnode_t *rp;
	char *contents;
	int size;
	int error;

	/*
	 * Purge the DNLC for any entries which refer to this file.
	 * Avoid recursive entry into dnlc_purge_vp() in case of a directory.
	 */
	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	if (vp->v_count > 1 &&
	    (vp->v_type == VDIR || purge_dnlc == NFS_PURGE_DNLC) &&
	    !(rp->r_flags & RINDNLCPURGE)) {
		/*
		 * Set the RINDNLCPURGE flag to prevent recursive entry
		 * into dnlc_purge_vp()
		 */
		if (vp->v_type == VDIR)
			rp->r_flags |= RINDNLCPURGE;
		mutex_exit(&rp->r_statelock);
		dnlc_purge_vp(vp);
		mutex_enter(&rp->r_statelock);
		if (rp->r_flags & RINDNLCPURGE)
			rp->r_flags &= ~RINDNLCPURGE;
	}

	/*
	 * Clear any readdir state bits and purge the readlink response cache.
	 */
	contents = rp->r_symlink.contents;
	size = rp->r_symlink.size;
	rp->r_symlink.contents = NULL;
	mutex_exit(&rp->r_statelock);

	if (contents != NULL) {

		kmem_free((void *)contents, size);
	}

	/*
	 * Flush the page cache.
	 */
	if (vn_has_cached_data(vp)) {
		error = VOP_PUTPAGE(vp, (u_offset_t)0, 0, B_INVAL, cr, NULL);
		if (error && (error == ENOSPC || error == EDQUOT)) {
			mutex_enter(&rp->r_statelock);
			if (!rp->r_error)
				rp->r_error = error;
			mutex_exit(&rp->r_statelock);
		}
	}

	/*
	 * Flush the readdir response cache.
	 */
	if (HAVE_RDDIR_CACHE(rp))
		nfs_purge_rddir_cache(vp);
}

/*
 * Purge the readdir cache of all entries
 */
void
nfs_purge_rddir_cache(vnode_t *vp)
{
	rnode_t *rp;
	rddir_cache *rdc;
	rddir_cache *nrdc;

	rp = VTOR(vp);
top:
	mutex_enter(&rp->r_statelock);
	rp->r_direof = NULL;
	rp->r_flags &= ~RLOOKUP;
	rp->r_flags |= RREADDIRPLUS;
	rdc = avl_first(&rp->r_dir);
	while (rdc != NULL) {
		nrdc = AVL_NEXT(&rp->r_dir, rdc);
		avl_remove(&rp->r_dir, rdc);
		rddir_cache_rele(rdc);
		rdc = nrdc;
	}
	mutex_exit(&rp->r_statelock);
}

/*
 * Do a cache check based on the post-operation attributes.
 * Then make them the new cached attributes.  If no attributes
 * were returned, then mark the attributes as timed out.
 */
void
nfs3_cache_post_op_attr(vnode_t *vp, post_op_attr *poap, hrtime_t t, cred_t *cr)
{
	vattr_t attr;

	if (!poap->attributes) {
		PURGE_ATTRCACHE(vp);
		return;
	}
	(void) nfs3_cache_fattr3(vp, &poap->attr, &attr, t, cr);
}

/*
 * Same as above, but using a vattr
 */
void
nfs3_cache_post_op_vattr(vnode_t *vp, post_op_vattr *poap, hrtime_t t,
    cred_t *cr)
{
	if (!poap->attributes) {
		PURGE_ATTRCACHE(vp);
		return;
	}
	nfs_attr_cache(vp, poap->fres.vap, t, cr);
}

/*
 * Do a cache check based on the weak cache consistency attributes.
 * These consist of a small set of pre-operation attributes and the
 * full set of post-operation attributes.
 *
 * If we are given the pre-operation attributes, then use them to
 * check the validity of the various caches.  Then, if we got the
 * post-operation attributes, make them the new cached attributes.
 * If we didn't get the post-operation attributes, then mark the
 * attribute cache as timed out so that the next reference will
 * cause a GETATTR to the server to refresh with the current
 * attributes.
 *
 * Otherwise, if we didn't get the pre-operation attributes, but
 * we did get the post-operation attributes, then use these
 * attributes to check the validity of the various caches.  This
 * will probably cause a flush of the caches because if the
 * operation succeeded, the attributes of the object were changed
 * in some way from the old post-operation attributes.  This
 * should be okay because it is the safe thing to do.  After
 * checking the data caches, then we make these the new cached
 * attributes.
 *
 * Otherwise, we didn't get either the pre- or post-operation
 * attributes.  Simply mark the attribute cache as timed out so
 * the next reference will cause a GETATTR to the server to
 * refresh with the current attributes.
 *
 * If an error occurred trying to convert the over the wire
 * attributes to a vattr, then simply mark the attribute cache as
 * timed out.
 */
void
nfs3_cache_wcc_data(vnode_t *vp, wcc_data *wccp, hrtime_t t, cred_t *cr)
{
	vattr_t bva;
	vattr_t ava;

	if (wccp->after.attributes) {
		if (fattr3_to_vattr(vp, &wccp->after.attr, &ava)) {
			PURGE_ATTRCACHE(vp);
			return;
		}
		if (wccp->before.attributes) {
			bva.va_ctime.tv_sec = wccp->before.attr.ctime.seconds;
			bva.va_ctime.tv_nsec = wccp->before.attr.ctime.nseconds;
			bva.va_mtime.tv_sec = wccp->before.attr.mtime.seconds;
			bva.va_mtime.tv_nsec = wccp->before.attr.mtime.nseconds;
			bva.va_size = wccp->before.attr.size;
			nfs3_attr_cache(vp, &bva, &ava, t, cr);
		} else
			nfs_attr_cache(vp, &ava, t, cr);
	} else {
		PURGE_ATTRCACHE(vp);
	}
}

/*
 * Set attributes cache for given vnode using nfsattr.
 *
 * This routine does not do cache validation with the attributes.
 *
 * If an error occurred trying to convert the over the wire
 * attributes to a vattr, then simply mark the attribute cache as
 * timed out.
 */
void
nfs_attrcache(vnode_t *vp, struct nfsfattr *na, hrtime_t t)
{
	rnode_t *rp;
	struct vattr va;

	if (!nattr_to_vattr(vp, na, &va)) {
		rp = VTOR(vp);
		mutex_enter(&rp->r_statelock);
		if (rp->r_mtime <= t)
			nfs_attrcache_va(vp, &va);
		mutex_exit(&rp->r_statelock);
	} else {
		PURGE_ATTRCACHE(vp);
	}
}

/*
 * Set attributes cache for given vnode using fattr3.
 *
 * This routine does not do cache validation with the attributes.
 *
 * If an error occurred trying to convert the over the wire
 * attributes to a vattr, then simply mark the attribute cache as
 * timed out.
 */
void
nfs3_attrcache(vnode_t *vp, fattr3 *na, hrtime_t t)
{
	rnode_t *rp;
	struct vattr va;

	if (!fattr3_to_vattr(vp, na, &va)) {
		rp = VTOR(vp);
		mutex_enter(&rp->r_statelock);
		if (rp->r_mtime <= t)
			nfs_attrcache_va(vp, &va);
		mutex_exit(&rp->r_statelock);
	} else {
		PURGE_ATTRCACHE(vp);
	}
}

/*
 * Do a cache check based on attributes returned over the wire.  The
 * new attributes are cached.
 *
 * If an error occurred trying to convert the over the wire attributes
 * to a vattr, then just return that error.
 *
 * As a side affect, the vattr argument is filled in with the converted
 * attributes.
 */
int
nfs_cache_fattr(vnode_t *vp, struct nfsfattr *na, vattr_t *vap, hrtime_t t,
    cred_t *cr)
{
	int error;

	error = nattr_to_vattr(vp, na, vap);
	if (error)
		return (error);
	nfs_attr_cache(vp, vap, t, cr);
	return (0);
}

/*
 * Do a cache check based on attributes returned over the wire.  The
 * new attributes are cached.
 *
 * If an error occurred trying to convert the over the wire attributes
 * to a vattr, then just return that error.
 *
 * As a side affect, the vattr argument is filled in with the converted
 * attributes.
 */
int
nfs3_cache_fattr3(vnode_t *vp, fattr3 *na, vattr_t *vap, hrtime_t t, cred_t *cr)
{
	int error;

	error = fattr3_to_vattr(vp, na, vap);
	if (error)
		return (error);
	nfs_attr_cache(vp, vap, t, cr);
	return (0);
}

/*
 * Use the passed in virtual attributes to check to see whether the
 * data and metadata caches are valid, cache the new attributes, and
 * then do the cache invalidation if required.
 *
 * The cache validation and caching of the new attributes is done
 * atomically via the use of the mutex, r_statelock.  If required,
 * the cache invalidation is done atomically w.r.t. the cache
 * validation and caching of the attributes via the pseudo lock,
 * r_serial.
 *
 * This routine is used to do cache validation and attributes caching
 * for operations with a single set of post operation attributes.
 */
void
nfs_attr_cache(vnode_t *vp, vattr_t *vap, hrtime_t t, cred_t *cr)
{
	rnode_t *rp;
	int mtime_changed = 0;
	int ctime_changed = 0;
	vsecattr_t *vsp;
	int was_serial;
	len_t preattr_rsize;
	boolean_t writeattr_set = B_FALSE;
	boolean_t cachepurge_set = B_FALSE;

	rp = VTOR(vp);

	mutex_enter(&rp->r_statelock);

	if (rp->r_serial != curthread) {
		klwp_t *lwp = ttolwp(curthread);

		was_serial = 0;
		if (lwp != NULL)
			lwp->lwp_nostop++;
		while (rp->r_serial != NULL) {
			if (!cv_wait_sig(&rp->r_cv, &rp->r_statelock)) {
				mutex_exit(&rp->r_statelock);
				if (lwp != NULL)
					lwp->lwp_nostop--;
				return;
			}
		}
		if (lwp != NULL)
			lwp->lwp_nostop--;
	} else
		was_serial = 1;

	if (rp->r_mtime > t) {
		if (!CACHE_VALID(rp, vap->va_mtime, vap->va_size))
			PURGE_ATTRCACHE_LOCKED(rp);
		mutex_exit(&rp->r_statelock);
		return;
	}

	/*
	 * Write thread after writing data to file on remote server,
	 * will always set RWRITEATTR to indicate that file on remote
	 * server was modified with a WRITE operation and would have
	 * marked attribute cache as timed out. If RWRITEATTR
	 * is set, then do not check for mtime and ctime change.
	 */
	if (!(rp->r_flags & RWRITEATTR)) {
		if (!CACHE_VALID(rp, vap->va_mtime, vap->va_size))
			mtime_changed = 1;

		if (rp->r_attr.va_ctime.tv_sec != vap->va_ctime.tv_sec ||
		    rp->r_attr.va_ctime.tv_nsec != vap->va_ctime.tv_nsec)
			ctime_changed = 1;
	} else {
		writeattr_set = B_TRUE;
	}

	preattr_rsize = rp->r_size;

	nfs_attrcache_va(vp, vap);

	/*
	 * If we have updated filesize in nfs_attrcache_va, as soon as we
	 * drop statelock we will be in transition of purging all
	 * our caches and updating them. It is possible for another
	 * thread to pick this new file size and read in zeroed data.
	 * stall other threads till cache purge is complete.
	 */
	if ((vp->v_type == VREG) && (rp->r_size != preattr_rsize)) {
		/*
		 * If RWRITEATTR was set and we have updated the file
		 * size, Server's returned file size need not necessarily
		 * be because of this Client's WRITE. We need to purge
		 * all caches.
		 */
		if (writeattr_set)
			mtime_changed = 1;

		if (mtime_changed && !(rp->r_flags & RINCACHEPURGE)) {
			rp->r_flags |= RINCACHEPURGE;
			cachepurge_set = B_TRUE;
		}
	}

	if (!mtime_changed && !ctime_changed) {
		mutex_exit(&rp->r_statelock);
		return;
	}

	rp->r_serial = curthread;

	mutex_exit(&rp->r_statelock);

	if (mtime_changed)
		nfs_purge_caches(vp, NFS_NOPURGE_DNLC, cr);

	if ((rp->r_flags & RINCACHEPURGE) && cachepurge_set) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags &= ~RINCACHEPURGE;
		cv_broadcast(&rp->r_cv);
		mutex_exit(&rp->r_statelock);
		cachepurge_set = B_FALSE;
	}

	if (ctime_changed) {
		(void) nfs_access_purge_rp(rp);
		if (rp->r_secattr != NULL) {
			mutex_enter(&rp->r_statelock);
			vsp = rp->r_secattr;
			rp->r_secattr = NULL;
			mutex_exit(&rp->r_statelock);
			if (vsp != NULL)
				nfs_acl_free(vsp);
		}
	}

	if (!was_serial) {
		mutex_enter(&rp->r_statelock);
		rp->r_serial = NULL;
		cv_broadcast(&rp->r_cv);
		mutex_exit(&rp->r_statelock);
	}
}

/*
 * Use the passed in "before" virtual attributes to check to see
 * whether the data and metadata caches are valid, cache the "after"
 * new attributes, and then do the cache invalidation if required.
 *
 * The cache validation and caching of the new attributes is done
 * atomically via the use of the mutex, r_statelock.  If required,
 * the cache invalidation is done atomically w.r.t. the cache
 * validation and caching of the attributes via the pseudo lock,
 * r_serial.
 *
 * This routine is used to do cache validation and attributes caching
 * for operations with both pre operation attributes and post operation
 * attributes.
 */
static void
nfs3_attr_cache(vnode_t *vp, vattr_t *bvap, vattr_t *avap, hrtime_t t,
    cred_t *cr)
{
	rnode_t *rp;
	int mtime_changed = 0;
	int ctime_changed = 0;
	vsecattr_t *vsp;
	int was_serial;
	len_t preattr_rsize;
	boolean_t writeattr_set = B_FALSE;
	boolean_t cachepurge_set = B_FALSE;

	rp = VTOR(vp);

	mutex_enter(&rp->r_statelock);

	if (rp->r_serial != curthread) {
		klwp_t *lwp = ttolwp(curthread);

		was_serial = 0;
		if (lwp != NULL)
			lwp->lwp_nostop++;
		while (rp->r_serial != NULL) {
			if (!cv_wait_sig(&rp->r_cv, &rp->r_statelock)) {
				mutex_exit(&rp->r_statelock);
				if (lwp != NULL)
					lwp->lwp_nostop--;
				return;
			}
		}
		if (lwp != NULL)
			lwp->lwp_nostop--;
	} else
		was_serial = 1;

	if (rp->r_mtime > t) {
		if (!CACHE_VALID(rp, avap->va_mtime, avap->va_size))
			PURGE_ATTRCACHE_LOCKED(rp);
		mutex_exit(&rp->r_statelock);
		return;
	}

	/*
	 * Write thread after writing data to file on remote server,
	 * will always set RWRITEATTR to indicate that file on remote
	 * server was modified with a WRITE operation and would have
	 * marked attribute cache as timed out. If RWRITEATTR
	 * is set, then do not check for mtime and ctime change.
	 */
	if (!(rp->r_flags & RWRITEATTR)) {
		if (!CACHE_VALID(rp, bvap->va_mtime, bvap->va_size))
			mtime_changed = 1;

		if (rp->r_attr.va_ctime.tv_sec != bvap->va_ctime.tv_sec ||
		    rp->r_attr.va_ctime.tv_nsec != bvap->va_ctime.tv_nsec)
			ctime_changed = 1;
	} else {
		writeattr_set = B_TRUE;
	}

	preattr_rsize = rp->r_size;

	nfs_attrcache_va(vp, avap);

	/*
	 * If we have updated filesize in nfs_attrcache_va, as soon as we
	 * drop statelock we will be in transition of purging all
	 * our caches and updating them. It is possible for another
	 * thread to pick this new file size and read in zeroed data.
	 * stall other threads till cache purge is complete.
	 */
	if ((vp->v_type == VREG) && (rp->r_size != preattr_rsize)) {
		/*
		 * If RWRITEATTR was set and we have updated the file
		 * size, Server's returned file size need not necessarily
		 * be because of this Client's WRITE. We need to purge
		 * all caches.
		 */
		if (writeattr_set)
			mtime_changed = 1;

		if (mtime_changed && !(rp->r_flags & RINCACHEPURGE)) {
			rp->r_flags |= RINCACHEPURGE;
			cachepurge_set = B_TRUE;
		}
	}

	if (!mtime_changed && !ctime_changed) {
		mutex_exit(&rp->r_statelock);
		return;
	}

	rp->r_serial = curthread;

	mutex_exit(&rp->r_statelock);

	if (mtime_changed)
		nfs_purge_caches(vp, NFS_NOPURGE_DNLC, cr);

	if ((rp->r_flags & RINCACHEPURGE) && cachepurge_set) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags &= ~RINCACHEPURGE;
		cv_broadcast(&rp->r_cv);
		mutex_exit(&rp->r_statelock);
		cachepurge_set = B_FALSE;
	}

	if (ctime_changed) {
		(void) nfs_access_purge_rp(rp);
		if (rp->r_secattr != NULL) {
			mutex_enter(&rp->r_statelock);
			vsp = rp->r_secattr;
			rp->r_secattr = NULL;
			mutex_exit(&rp->r_statelock);
			if (vsp != NULL)
				nfs_acl_free(vsp);
		}
	}

	if (!was_serial) {
		mutex_enter(&rp->r_statelock);
		rp->r_serial = NULL;
		cv_broadcast(&rp->r_cv);
		mutex_exit(&rp->r_statelock);
	}
}

/*
 * Set attributes cache for given vnode using virtual attributes.
 *
 * Set the timeout value on the attribute cache and fill it
 * with the passed in attributes.
 *
 * The caller must be holding r_statelock.
 */
void
nfs_attrcache_va(vnode_t *vp, struct vattr *va)
{
	rnode_t *rp;
	mntinfo_t *mi;
	hrtime_t delta;
	hrtime_t now;

	rp = VTOR(vp);

	ASSERT(MUTEX_HELD(&rp->r_statelock));

	now = gethrtime();

	mi = VTOMI(vp);

	/*
	 * Delta is the number of nanoseconds that we will
	 * cache the attributes of the file.  It is based on
	 * the number of nanoseconds since the last time that
	 * we detected a change.  The assumption is that files
	 * that changed recently are likely to change again.
	 * There is a minimum and a maximum for regular files
	 * and for directories which is enforced though.
	 *
	 * Using the time since last change was detected
	 * eliminates direct comparison or calculation
	 * using mixed client and server times.  NFS does
	 * not make any assumptions regarding the client
	 * and server clocks being synchronized.
	 */
	if (va->va_mtime.tv_sec != rp->r_attr.va_mtime.tv_sec ||
	    va->va_mtime.tv_nsec != rp->r_attr.va_mtime.tv_nsec ||
	    va->va_size != rp->r_attr.va_size)
		rp->r_mtime = now;

	if ((mi->mi_flags & MI_NOAC) || (vp->v_flag & VNOCACHE))
		delta = 0;
	else {
		delta = now - rp->r_mtime;
		if (vp->v_type == VDIR) {
			if (delta < mi->mi_acdirmin)
				delta = mi->mi_acdirmin;
			else if (delta > mi->mi_acdirmax)
				delta = mi->mi_acdirmax;
		} else {
			if (delta < mi->mi_acregmin)
				delta = mi->mi_acregmin;
			else if (delta > mi->mi_acregmax)
				delta = mi->mi_acregmax;
		}
	}
	rp->r_attrtime = now + delta;
	rp->r_attr = *va;
	/*
	 * Update the size of the file if there is no cached data or if
	 * the cached data is clean and there is no data being written
	 * out.
	 */
	if (rp->r_size != va->va_size &&
	    (!vn_has_cached_data(vp) ||
	    (!(rp->r_flags & RDIRTY) && rp->r_count == 0)))
		rp->r_size = va->va_size;
	nfs_setswaplike(vp, va);
	rp->r_flags &= ~RWRITEATTR;
}

/*
 * Fill in attribute from the cache.
 * If valid, then return 0 to indicate that no error occurred,
 * otherwise return 1 to indicate that an error occurred.
 */
static int
nfs_getattr_cache(vnode_t *vp, struct vattr *vap)
{
	rnode_t *rp;
	uint_t mask = vap->va_mask;

	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	if (ATTRCACHE_VALID(vp)) {
		/*
		 * Cached attributes are valid
		 */
		*vap = rp->r_attr;
		/*
		 * Set the caller's va_mask to the set of attributes
		 * that were requested ANDed with the attributes that
		 * are available.  If attributes were requested that
		 * are not available, those bits must be turned off
		 * in the callers va_mask.
		 */
		vap->va_mask &= mask;
		mutex_exit(&rp->r_statelock);
		return (0);
	}
	mutex_exit(&rp->r_statelock);
	return (1);
}

/*
 * Get attributes over-the-wire and update attributes cache
 * if no error occurred in the over-the-wire operation.
 * Return 0 if successful, otherwise error.
 */
int
nfs_getattr_otw(vnode_t *vp, struct vattr *vap, cred_t *cr)
{
	int error;
	struct nfsattrstat ns;
	int douprintf;
	mntinfo_t *mi;
	failinfo_t fi;
	hrtime_t t;

	mi = VTOMI(vp);
	fi.vp = vp;
	fi.fhp = NULL;		/* no need to update, filehandle not copied */
	fi.copyproc = nfscopyfh;
	fi.lookupproc = nfslookup;
	fi.xattrdirproc = acl_getxattrdir2;

	if (mi->mi_flags & MI_ACL) {
		error = acl_getattr2_otw(vp, vap, cr);
		if (mi->mi_flags & MI_ACL)
			return (error);
	}

	douprintf = 1;

	t = gethrtime();

	error = rfs2call(mi, RFS_GETATTR,
	    xdr_fhandle, (caddr_t)VTOFH(vp),
	    xdr_attrstat, (caddr_t)&ns, cr,
	    &douprintf, &ns.ns_status, 0, &fi);

	if (!error) {
		error = geterrno(ns.ns_status);
		if (!error)
			error = nfs_cache_fattr(vp, &ns.ns_attr, vap, t, cr);
		else {
			PURGE_STALE_FH(error, vp, cr);
		}
	}

	return (error);
}

/*
 * Return either cached ot remote attributes. If get remote attr
 * use them to check and invalidate caches, then cache the new attributes.
 */
int
nfsgetattr(vnode_t *vp, struct vattr *vap, cred_t *cr)
{
	int error;
	rnode_t *rp;

	/*
	 * If we've got cached attributes, we're done, otherwise go
	 * to the server to get attributes, which will update the cache
	 * in the process.
	 */
	error = nfs_getattr_cache(vp, vap);
	if (error)
		error = nfs_getattr_otw(vp, vap, cr);

	/* Return the client's view of file size */
	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	vap->va_size = rp->r_size;
	mutex_exit(&rp->r_statelock);

	return (error);
}

/*
 * Get attributes over-the-wire and update attributes cache
 * if no error occurred in the over-the-wire operation.
 * Return 0 if successful, otherwise error.
 */
int
nfs3_getattr_otw(vnode_t *vp, struct vattr *vap, cred_t *cr)
{
	int error;
	GETATTR3args args;
	GETATTR3vres res;
	int douprintf;
	failinfo_t fi;
	hrtime_t t;

	args.object = *VTOFH3(vp);
	fi.vp = vp;
	fi.fhp = (caddr_t)&args.object;
	fi.copyproc = nfs3copyfh;
	fi.lookupproc = nfs3lookup;
	fi.xattrdirproc = acl_getxattrdir3;
	res.fres.vp = vp;
	res.fres.vap = vap;

	douprintf = 1;

	t = gethrtime();

	error = rfs3call(VTOMI(vp), NFSPROC3_GETATTR,
	    xdr_nfs_fh3, (caddr_t)&args,
	    xdr_GETATTR3vres, (caddr_t)&res, cr,
	    &douprintf, &res.status, 0, &fi);

	if (error)
		return (error);

	error = geterrno3(res.status);
	if (error) {
		PURGE_STALE_FH(error, vp, cr);
		return (error);
	}

	/*
	 * Catch status codes that indicate fattr3 to vattr translation failure
	 */
	if (res.fres.status)
		return (res.fres.status);

	nfs_attr_cache(vp, vap, t, cr);
	return (0);
}

/*
 * Return either cached or remote attributes. If get remote attr
 * use them to check and invalidate caches, then cache the new attributes.
 */
int
nfs3getattr(vnode_t *vp, struct vattr *vap, cred_t *cr)
{
	int error;
	rnode_t *rp;

	/*
	 * If we've got cached attributes, we're done, otherwise go
	 * to the server to get attributes, which will update the cache
	 * in the process.
	 */
	error = nfs_getattr_cache(vp, vap);
	if (error)
		error = nfs3_getattr_otw(vp, vap, cr);

	/* Return the client's view of file size */
	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	vap->va_size = rp->r_size;
	mutex_exit(&rp->r_statelock);

	return (error);
}

vtype_t nf_to_vt[] = {
	VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK
};
/*
 * Convert NFS Version 2 over the network attributes to the local
 * virtual attributes.  The mapping between the UID_NOBODY/GID_NOBODY
 * network representation and the local representation is done here.
 * Returns 0 for success, error if failed due to overflow.
 */
int
nattr_to_vattr(vnode_t *vp, struct nfsfattr *na, struct vattr *vap)
{
	/* overflow in time attributes? */
#ifndef _LP64
	if (!NFS2_FATTR_TIME_OK(na))
		return (EOVERFLOW);
#endif

	vap->va_mask = AT_ALL;

	if (na->na_type < NFNON || na->na_type > NFSOC)
		vap->va_type = VBAD;
	else
		vap->va_type = nf_to_vt[na->na_type];
	vap->va_mode = na->na_mode;
	vap->va_uid = (na->na_uid == NFS_UID_NOBODY) ? UID_NOBODY : na->na_uid;
	vap->va_gid = (na->na_gid == NFS_GID_NOBODY) ? GID_NOBODY : na->na_gid;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_nodeid = na->na_nodeid;
	vap->va_nlink = na->na_nlink;
	vap->va_size = na->na_size;	/* keep for cache validation */
	/*
	 * nfs protocol defines times as unsigned so don't extend sign,
	 * unless sysadmin set nfs_allow_preepoch_time.
	 */
	NFS_TIME_T_CONVERT(vap->va_atime.tv_sec, na->na_atime.tv_sec);
	vap->va_atime.tv_nsec = (uint32_t)(na->na_atime.tv_usec * 1000);
	NFS_TIME_T_CONVERT(vap->va_mtime.tv_sec, na->na_mtime.tv_sec);
	vap->va_mtime.tv_nsec = (uint32_t)(na->na_mtime.tv_usec * 1000);
	NFS_TIME_T_CONVERT(vap->va_ctime.tv_sec, na->na_ctime.tv_sec);
	vap->va_ctime.tv_nsec = (uint32_t)(na->na_ctime.tv_usec * 1000);
	/*
	 * Shannon's law - uncompress the received dev_t
	 * if the top half of is zero indicating a response
	 * from an `older style' OS. Except for when it is a
	 * `new style' OS sending the maj device of zero,
	 * in which case the algorithm still works because the
	 * fact that it is a new style server
	 * is hidden by the minor device not being greater
	 * than 255 (a requirement in this case).
	 */
	if ((na->na_rdev & 0xffff0000) == 0)
		vap->va_rdev = nfsv2_expdev(na->na_rdev);
	else
		vap->va_rdev = expldev(na->na_rdev);

	vap->va_nblocks = na->na_blocks;
	switch (na->na_type) {
	case NFBLK:
		vap->va_blksize = DEV_BSIZE;
		break;

	case NFCHR:
		vap->va_blksize = MAXBSIZE;
		break;

	case NFSOC:
	default:
		vap->va_blksize = na->na_blocksize;
		break;
	}
	/*
	 * This bit of ugliness is a hack to preserve the
	 * over-the-wire protocols for named-pipe vnodes.
	 * It remaps the special over-the-wire type to the
	 * VFIFO type. (see note in nfs.h)
	 */
	if (NA_ISFIFO(na)) {
		vap->va_type = VFIFO;
		vap->va_mode = (vap->va_mode & ~S_IFMT) | S_IFIFO;
		vap->va_rdev = 0;
		vap->va_blksize = na->na_blocksize;
	}
	vap->va_seq = 0;
	return (0);
}

/*
 * Convert NFS Version 3 over the network attributes to the local
 * virtual attributes.  The mapping between the UID_NOBODY/GID_NOBODY
 * network representation and the local representation is done here.
 */
vtype_t nf3_to_vt[] = {
	VBAD, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO
};

int
fattr3_to_vattr(vnode_t *vp, fattr3 *na, struct vattr *vap)
{

#ifndef _LP64
	/* overflow in time attributes? */
	if (!NFS3_FATTR_TIME_OK(na))
		return (EOVERFLOW);
#endif
	if (!NFS3_SIZE_OK(na->size))
		/* file too big */
		return (EFBIG);

	vap->va_mask = AT_ALL;

	if (na->type < NF3REG || na->type > NF3FIFO)
		vap->va_type = VBAD;
	else
		vap->va_type = nf3_to_vt[na->type];
	vap->va_mode = na->mode;
	vap->va_uid = (na->uid == NFS_UID_NOBODY) ? UID_NOBODY : (uid_t)na->uid;
	vap->va_gid = (na->gid == NFS_GID_NOBODY) ? GID_NOBODY : (gid_t)na->gid;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_nodeid = na->fileid;
	vap->va_nlink = na->nlink;
	vap->va_size = na->size;

	/*
	 * nfs protocol defines times as unsigned so don't extend sign,
	 * unless sysadmin set nfs_allow_preepoch_time.
	 */
	NFS_TIME_T_CONVERT(vap->va_atime.tv_sec, na->atime.seconds);
	vap->va_atime.tv_nsec = (uint32_t)na->atime.nseconds;
	NFS_TIME_T_CONVERT(vap->va_mtime.tv_sec, na->mtime.seconds);
	vap->va_mtime.tv_nsec = (uint32_t)na->mtime.nseconds;
	NFS_TIME_T_CONVERT(vap->va_ctime.tv_sec, na->ctime.seconds);
	vap->va_ctime.tv_nsec = (uint32_t)na->ctime.nseconds;

	switch (na->type) {
	case NF3BLK:
		vap->va_rdev = makedevice(na->rdev.specdata1,
		    na->rdev.specdata2);
		vap->va_blksize = DEV_BSIZE;
		vap->va_nblocks = 0;
		break;
	case NF3CHR:
		vap->va_rdev = makedevice(na->rdev.specdata1,
		    na->rdev.specdata2);
		vap->va_blksize = MAXBSIZE;
		vap->va_nblocks = 0;
		break;
	case NF3REG:
	case NF3DIR:
	case NF3LNK:
		vap->va_rdev = 0;
		vap->va_blksize = MAXBSIZE;
		vap->va_nblocks = (u_longlong_t)
		    ((na->used + (size3)DEV_BSIZE - (size3)1) /
		    (size3)DEV_BSIZE);
		break;
	case NF3SOCK:
	case NF3FIFO:
	default:
		vap->va_rdev = 0;
		vap->va_blksize = MAXBSIZE;
		vap->va_nblocks = 0;
		break;
	}
	vap->va_seq = 0;
	return (0);
}

/*
 * Asynchronous I/O parameters.  nfs_async_threads is the high-water mark
 * for the demand-based allocation of async threads per-mount.  The
 * nfs_async_timeout is the amount of time a thread will live after it
 * becomes idle, unless new I/O requests are received before the thread
 * dies.  See nfs_async_putpage and nfs_async_start.
 */

int nfs_async_timeout = -1;	/* uninitialized */

static void	nfs_async_start(struct vfs *);
static void	nfs_async_pgops_start(struct vfs *);
static void	nfs_async_common_start(struct vfs *, int);

static void
free_async_args(struct nfs_async_reqs *args)
{
	rnode_t *rp;

	if (args->a_io != NFS_INACTIVE) {
		rp = VTOR(args->a_vp);
		mutex_enter(&rp->r_statelock);
		rp->r_count--;
		if (args->a_io == NFS_PUTAPAGE ||
		    args->a_io == NFS_PAGEIO)
			rp->r_awcount--;
		cv_broadcast(&rp->r_cv);
		mutex_exit(&rp->r_statelock);
		VN_RELE(args->a_vp);
	}
	crfree(args->a_cred);
	kmem_free(args, sizeof (*args));
}

/*
 * Cross-zone thread creation and NFS access is disallowed, yet fsflush() and
 * pageout(), running in the global zone, have legitimate reasons to do
 * VOP_PUTPAGE(B_ASYNC) on other zones' NFS mounts.  We avoid the problem by
 * use of a a per-mount "asynchronous requests manager thread" which is
 * signaled by the various asynchronous work routines when there is
 * asynchronous work to be done.  It is responsible for creating new
 * worker threads if necessary, and notifying existing worker threads
 * that there is work to be done.
 *
 * In other words, it will "take the specifications from the customers and
 * give them to the engineers."
 *
 * Worker threads die off of their own accord if they are no longer
 * needed.
 *
 * This thread is killed when the zone is going away or the filesystem
 * is being unmounted.
 */
void
nfs_async_manager(vfs_t *vfsp)
{
	callb_cpr_t cprinfo;
	mntinfo_t *mi;
	uint_t max_threads;

	mi = VFTOMI(vfsp);

	CALLB_CPR_INIT(&cprinfo, &mi->mi_async_lock, callb_generic_cpr,
	    "nfs_async_manager");

	mutex_enter(&mi->mi_async_lock);
	/*
	 * We want to stash the max number of threads that this mount was
	 * allowed so we can use it later when the variable is set to zero as
	 * part of the zone/mount going away.
	 *
	 * We want to be able to create at least one thread to handle
	 * asynchronous inactive calls.
	 */
	max_threads = MAX(mi->mi_max_threads, 1);
	/*
	 * We don't want to wait for mi_max_threads to go to zero, since that
	 * happens as part of a failed unmount, but this thread should only
	 * exit when the mount/zone is really going away.
	 *
	 * Once MI_ASYNC_MGR_STOP is set, no more async operations will be
	 * attempted: the various _async_*() functions know to do things
	 * inline if mi_max_threads == 0.  Henceforth we just drain out the
	 * outstanding requests.
	 *
	 * Note that we still create zthreads even if we notice the zone is
	 * shutting down (MI_ASYNC_MGR_STOP is set); this may cause the zone
	 * shutdown sequence to take slightly longer in some cases, but
	 * doesn't violate the protocol, as all threads will exit as soon as
	 * they're done processing the remaining requests.
	 */
	for (;;) {
		while (mi->mi_async_req_count > 0) {
			/*
			 * Paranoia: If the mount started out having
			 * (mi->mi_max_threads == 0), and the value was
			 * later changed (via a debugger or somesuch),
			 * we could be confused since we will think we
			 * can't create any threads, and the calling
			 * code (which looks at the current value of
			 * mi->mi_max_threads, now non-zero) thinks we
			 * can.
			 *
			 * So, because we're paranoid, we create threads
			 * up to the maximum of the original and the
			 * current value. This means that future
			 * (debugger-induced) lowerings of
			 * mi->mi_max_threads are ignored for our
			 * purposes, but who told them they could change
			 * random values on a live kernel anyhow?
			 */
			if (mi->mi_threads[NFS_ASYNC_QUEUE] <
			    MAX(mi->mi_max_threads, max_threads)) {
				mi->mi_threads[NFS_ASYNC_QUEUE]++;
				mutex_exit(&mi->mi_async_lock);
				VFS_HOLD(vfsp);	/* hold for new thread */
				(void) zthread_create(NULL, 0, nfs_async_start,
				    vfsp, 0, minclsyspri);
				mutex_enter(&mi->mi_async_lock);
			} else if (mi->mi_threads[NFS_ASYNC_PGOPS_QUEUE] <
			    NUM_ASYNC_PGOPS_THREADS) {
				mi->mi_threads[NFS_ASYNC_PGOPS_QUEUE]++;
				mutex_exit(&mi->mi_async_lock);
				VFS_HOLD(vfsp); /* hold for new thread */
				(void) zthread_create(NULL, 0,
				    nfs_async_pgops_start, vfsp, 0,
				    minclsyspri);
				mutex_enter(&mi->mi_async_lock);
			}
			NFS_WAKE_ASYNC_WORKER(mi->mi_async_work_cv);
			ASSERT(mi->mi_async_req_count != 0);
			mi->mi_async_req_count--;
		}

		mutex_enter(&mi->mi_lock);
		if (mi->mi_flags & MI_ASYNC_MGR_STOP) {
			mutex_exit(&mi->mi_lock);
			break;
		}
		mutex_exit(&mi->mi_lock);

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&mi->mi_async_reqs_cv, &mi->mi_async_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &mi->mi_async_lock);
	}
	/*
	 * Let everyone know we're done.
	 */
	mi->mi_manager_thread = NULL;
	cv_broadcast(&mi->mi_async_cv);

	/*
	 * There is no explicit call to mutex_exit(&mi->mi_async_lock)
	 * since CALLB_CPR_EXIT is actually responsible for releasing
	 * 'mi_async_lock'.
	 */
	CALLB_CPR_EXIT(&cprinfo);
	VFS_RELE(vfsp);	/* release thread's hold */
	zthread_exit();
}

/*
 * Signal (and wait for) the async manager thread to clean up and go away.
 */
void
nfs_async_manager_stop(vfs_t *vfsp)
{
	mntinfo_t *mi = VFTOMI(vfsp);

	mutex_enter(&mi->mi_async_lock);
	mutex_enter(&mi->mi_lock);
	mi->mi_flags |= MI_ASYNC_MGR_STOP;
	mutex_exit(&mi->mi_lock);
	cv_broadcast(&mi->mi_async_reqs_cv);
	while (mi->mi_manager_thread != NULL)
		cv_wait(&mi->mi_async_cv, &mi->mi_async_lock);
	mutex_exit(&mi->mi_async_lock);
}

int
nfs_async_readahead(vnode_t *vp, u_offset_t blkoff, caddr_t addr,
    struct seg *seg, cred_t *cr, void (*readahead)(vnode_t *,
    u_offset_t, caddr_t, struct seg *, cred_t *))
{
	rnode_t *rp;
	mntinfo_t *mi;
	struct nfs_async_reqs *args;

	rp = VTOR(vp);
	ASSERT(rp->r_freef == NULL);

	mi = VTOMI(vp);

	/*
	 * If addr falls in a different segment, don't bother doing readahead.
	 */
	if (addr >= seg->s_base + seg->s_size)
		return (-1);

	/*
	 * If we can't allocate a request structure, punt on the readahead.
	 */
	if ((args = kmem_alloc(sizeof (*args), KM_NOSLEEP)) == NULL)
		return (-1);

	/*
	 * If a lock operation is pending, don't initiate any new
	 * readaheads.  Otherwise, bump r_count to indicate the new
	 * asynchronous I/O.
	 */
	if (!nfs_rw_tryenter(&rp->r_lkserlock, RW_READER)) {
		kmem_free(args, sizeof (*args));
		return (-1);
	}
	mutex_enter(&rp->r_statelock);
	rp->r_count++;
	mutex_exit(&rp->r_statelock);
	nfs_rw_exit(&rp->r_lkserlock);

	args->a_next = NULL;
#ifdef DEBUG
	args->a_queuer = curthread;
#endif
	VN_HOLD(vp);
	args->a_vp = vp;
	ASSERT(cr != NULL);
	crhold(cr);
	args->a_cred = cr;
	args->a_io = NFS_READ_AHEAD;
	args->a_nfs_readahead = readahead;
	args->a_nfs_blkoff = blkoff;
	args->a_nfs_seg = seg;
	args->a_nfs_addr = addr;

	mutex_enter(&mi->mi_async_lock);

	/*
	 * If asyncio has been disabled, don't bother readahead.
	 */
	if (mi->mi_max_threads == 0) {
		mutex_exit(&mi->mi_async_lock);
		goto noasync;
	}

	/*
	 * Link request structure into the async list and
	 * wakeup async thread to do the i/o.
	 */
	if (mi->mi_async_reqs[NFS_READ_AHEAD] == NULL) {
		mi->mi_async_reqs[NFS_READ_AHEAD] = args;
		mi->mi_async_tail[NFS_READ_AHEAD] = args;
	} else {
		mi->mi_async_tail[NFS_READ_AHEAD]->a_next = args;
		mi->mi_async_tail[NFS_READ_AHEAD] = args;
	}

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		kstat_waitq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
		mutex_exit(&mi->mi_lock);
	}

	mi->mi_async_req_count++;
	ASSERT(mi->mi_async_req_count != 0);
	cv_signal(&mi->mi_async_reqs_cv);
	mutex_exit(&mi->mi_async_lock);
	return (0);

noasync:
	mutex_enter(&rp->r_statelock);
	rp->r_count--;
	cv_broadcast(&rp->r_cv);
	mutex_exit(&rp->r_statelock);
	VN_RELE(vp);
	crfree(cr);
	kmem_free(args, sizeof (*args));
	return (-1);
}

int
nfs_async_putapage(vnode_t *vp, page_t *pp, u_offset_t off, size_t len,
    int flags, cred_t *cr, int (*putapage)(vnode_t *, page_t *,
    u_offset_t, size_t, int, cred_t *))
{
	rnode_t *rp;
	mntinfo_t *mi;
	struct nfs_async_reqs *args;

	ASSERT(flags & B_ASYNC);
	ASSERT(vp->v_vfsp != NULL);

	rp = VTOR(vp);
	ASSERT(rp->r_count > 0);

	mi = VTOMI(vp);

	/*
	 * If we can't allocate a request structure, do the putpage
	 * operation synchronously in this thread's context.
	 */
	if ((args = kmem_alloc(sizeof (*args), KM_NOSLEEP)) == NULL)
		goto noasync;

	args->a_next = NULL;
#ifdef DEBUG
	args->a_queuer = curthread;
#endif
	VN_HOLD(vp);
	args->a_vp = vp;
	ASSERT(cr != NULL);
	crhold(cr);
	args->a_cred = cr;
	args->a_io = NFS_PUTAPAGE;
	args->a_nfs_putapage = putapage;
	args->a_nfs_pp = pp;
	args->a_nfs_off = off;
	args->a_nfs_len = (uint_t)len;
	args->a_nfs_flags = flags;

	mutex_enter(&mi->mi_async_lock);

	/*
	 * If asyncio has been disabled, then make a synchronous request.
	 * This check is done a second time in case async io was diabled
	 * while this thread was blocked waiting for memory pressure to
	 * reduce or for the queue to drain.
	 */
	if (mi->mi_max_threads == 0) {
		mutex_exit(&mi->mi_async_lock);
		goto noasync;
	}

	/*
	 * Link request structure into the async list and
	 * wakeup async thread to do the i/o.
	 */
	if (mi->mi_async_reqs[NFS_PUTAPAGE] == NULL) {
		mi->mi_async_reqs[NFS_PUTAPAGE] = args;
		mi->mi_async_tail[NFS_PUTAPAGE] = args;
	} else {
		mi->mi_async_tail[NFS_PUTAPAGE]->a_next = args;
		mi->mi_async_tail[NFS_PUTAPAGE] = args;
	}

	mutex_enter(&rp->r_statelock);
	rp->r_count++;
	rp->r_awcount++;
	mutex_exit(&rp->r_statelock);

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		kstat_waitq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
		mutex_exit(&mi->mi_lock);
	}

	mi->mi_async_req_count++;
	ASSERT(mi->mi_async_req_count != 0);
	cv_signal(&mi->mi_async_reqs_cv);
	mutex_exit(&mi->mi_async_lock);
	return (0);

noasync:
	if (args != NULL) {
		VN_RELE(vp);
		crfree(cr);
		kmem_free(args, sizeof (*args));
	}

	if (curproc == proc_pageout || curproc == proc_fsflush) {
		/*
		 * If we get here in the context of the pageout/fsflush,
		 * we refuse to do a sync write, because this may hang
		 * pageout (and the machine). In this case, we just
		 * re-mark the page as dirty and punt on the page.
		 *
		 * Make sure B_FORCE isn't set.  We can re-mark the
		 * pages as dirty and unlock the pages in one swoop by
		 * passing in B_ERROR to pvn_write_done().  However,
		 * we should make sure B_FORCE isn't set - we don't
		 * want the page tossed before it gets written out.
		 */
		if (flags & B_FORCE)
			flags &= ~(B_INVAL | B_FORCE);
		pvn_write_done(pp, flags | B_ERROR);
		return (0);
	}
	if (nfs_zone() != mi->mi_zone) {
		/*
		 * So this was a cross-zone sync putpage.  We pass in B_ERROR
		 * to pvn_write_done() to re-mark the pages as dirty and unlock
		 * them.
		 *
		 * We don't want to clear B_FORCE here as the caller presumably
		 * knows what they're doing if they set it.
		 */
		pvn_write_done(pp, flags | B_ERROR);
		return (EPERM);
	}
	return ((*putapage)(vp, pp, off, len, flags, cr));
}

int
nfs_async_pageio(vnode_t *vp, page_t *pp, u_offset_t io_off, size_t io_len,
    int flags, cred_t *cr, int (*pageio)(vnode_t *, page_t *, u_offset_t,
    size_t, int, cred_t *))
{
	rnode_t *rp;
	mntinfo_t *mi;
	struct nfs_async_reqs *args;

	ASSERT(flags & B_ASYNC);
	ASSERT(vp->v_vfsp != NULL);

	rp = VTOR(vp);
	ASSERT(rp->r_count > 0);

	mi = VTOMI(vp);

	/*
	 * If we can't allocate a request structure, do the pageio
	 * request synchronously in this thread's context.
	 */
	if ((args = kmem_alloc(sizeof (*args), KM_NOSLEEP)) == NULL)
		goto noasync;

	args->a_next = NULL;
#ifdef DEBUG
	args->a_queuer = curthread;
#endif
	VN_HOLD(vp);
	args->a_vp = vp;
	ASSERT(cr != NULL);
	crhold(cr);
	args->a_cred = cr;
	args->a_io = NFS_PAGEIO;
	args->a_nfs_pageio = pageio;
	args->a_nfs_pp = pp;
	args->a_nfs_off = io_off;
	args->a_nfs_len = (uint_t)io_len;
	args->a_nfs_flags = flags;

	mutex_enter(&mi->mi_async_lock);

	/*
	 * If asyncio has been disabled, then make a synchronous request.
	 * This check is done a second time in case async io was diabled
	 * while this thread was blocked waiting for memory pressure to
	 * reduce or for the queue to drain.
	 */
	if (mi->mi_max_threads == 0) {
		mutex_exit(&mi->mi_async_lock);
		goto noasync;
	}

	/*
	 * Link request structure into the async list and
	 * wakeup async thread to do the i/o.
	 */
	if (mi->mi_async_reqs[NFS_PAGEIO] == NULL) {
		mi->mi_async_reqs[NFS_PAGEIO] = args;
		mi->mi_async_tail[NFS_PAGEIO] = args;
	} else {
		mi->mi_async_tail[NFS_PAGEIO]->a_next = args;
		mi->mi_async_tail[NFS_PAGEIO] = args;
	}

	mutex_enter(&rp->r_statelock);
	rp->r_count++;
	rp->r_awcount++;
	mutex_exit(&rp->r_statelock);

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		kstat_waitq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
		mutex_exit(&mi->mi_lock);
	}

	mi->mi_async_req_count++;
	ASSERT(mi->mi_async_req_count != 0);
	cv_signal(&mi->mi_async_reqs_cv);
	mutex_exit(&mi->mi_async_lock);
	return (0);

noasync:
	if (args != NULL) {
		VN_RELE(vp);
		crfree(cr);
		kmem_free(args, sizeof (*args));
	}

	/*
	 * If we can't do it ASYNC, for reads we do nothing (but cleanup
	 * the page list), for writes we do it synchronously, except for
	 * proc_pageout/proc_fsflush as described below.
	 */
	if (flags & B_READ) {
		pvn_read_done(pp, flags | B_ERROR);
		return (0);
	}

	if (curproc == proc_pageout || curproc == proc_fsflush) {
		/*
		 * If we get here in the context of the pageout/fsflush,
		 * we refuse to do a sync write, because this may hang
		 * pageout/fsflush (and the machine). In this case, we just
		 * re-mark the page as dirty and punt on the page.
		 *
		 * Make sure B_FORCE isn't set.  We can re-mark the
		 * pages as dirty and unlock the pages in one swoop by
		 * passing in B_ERROR to pvn_write_done().  However,
		 * we should make sure B_FORCE isn't set - we don't
		 * want the page tossed before it gets written out.
		 */
		if (flags & B_FORCE)
			flags &= ~(B_INVAL | B_FORCE);
		pvn_write_done(pp, flags | B_ERROR);
		return (0);
	}

	if (nfs_zone() != mi->mi_zone) {
		/*
		 * So this was a cross-zone sync pageio.  We pass in B_ERROR
		 * to pvn_write_done() to re-mark the pages as dirty and unlock
		 * them.
		 *
		 * We don't want to clear B_FORCE here as the caller presumably
		 * knows what they're doing if they set it.
		 */
		pvn_write_done(pp, flags | B_ERROR);
		return (EPERM);
	}
	return ((*pageio)(vp, pp, io_off, io_len, flags, cr));
}

void
nfs_async_readdir(vnode_t *vp, rddir_cache *rdc, cred_t *cr,
    int (*readdir)(vnode_t *, rddir_cache *, cred_t *))
{
	rnode_t *rp;
	mntinfo_t *mi;
	struct nfs_async_reqs *args;

	rp = VTOR(vp);
	ASSERT(rp->r_freef == NULL);

	mi = VTOMI(vp);

	/*
	 * If we can't allocate a request structure, do the readdir
	 * operation synchronously in this thread's context.
	 */
	if ((args = kmem_alloc(sizeof (*args), KM_NOSLEEP)) == NULL)
		goto noasync;

	args->a_next = NULL;
#ifdef DEBUG
	args->a_queuer = curthread;
#endif
	VN_HOLD(vp);
	args->a_vp = vp;
	ASSERT(cr != NULL);
	crhold(cr);
	args->a_cred = cr;
	args->a_io = NFS_READDIR;
	args->a_nfs_readdir = readdir;
	args->a_nfs_rdc = rdc;

	mutex_enter(&mi->mi_async_lock);

	/*
	 * If asyncio has been disabled, then make a synchronous request.
	 */
	if (mi->mi_max_threads == 0) {
		mutex_exit(&mi->mi_async_lock);
		goto noasync;
	}

	/*
	 * Link request structure into the async list and
	 * wakeup async thread to do the i/o.
	 */
	if (mi->mi_async_reqs[NFS_READDIR] == NULL) {
		mi->mi_async_reqs[NFS_READDIR] = args;
		mi->mi_async_tail[NFS_READDIR] = args;
	} else {
		mi->mi_async_tail[NFS_READDIR]->a_next = args;
		mi->mi_async_tail[NFS_READDIR] = args;
	}

	mutex_enter(&rp->r_statelock);
	rp->r_count++;
	mutex_exit(&rp->r_statelock);

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		kstat_waitq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
		mutex_exit(&mi->mi_lock);
	}

	mi->mi_async_req_count++;
	ASSERT(mi->mi_async_req_count != 0);
	cv_signal(&mi->mi_async_reqs_cv);
	mutex_exit(&mi->mi_async_lock);
	return;

noasync:
	if (args != NULL) {
		VN_RELE(vp);
		crfree(cr);
		kmem_free(args, sizeof (*args));
	}

	rdc->entries = NULL;
	mutex_enter(&rp->r_statelock);
	ASSERT(rdc->flags & RDDIR);
	rdc->flags &= ~RDDIR;
	rdc->flags |= RDDIRREQ;
	/*
	 * Check the flag to see if RDDIRWAIT is set. If RDDIRWAIT
	 * is set, wakeup the thread sleeping in cv_wait_sig().
	 * The woken up thread will reset the flag to RDDIR and will
	 * continue with the readdir opeartion.
	 */
	if (rdc->flags & RDDIRWAIT) {
		rdc->flags &= ~RDDIRWAIT;
		cv_broadcast(&rdc->cv);
	}
	mutex_exit(&rp->r_statelock);
	rddir_cache_rele(rdc);
}

void
nfs_async_commit(vnode_t *vp, page_t *plist, offset3 offset, count3 count,
    cred_t *cr, void (*commit)(vnode_t *, page_t *, offset3, count3, cred_t *))
{
	rnode_t *rp;
	mntinfo_t *mi;
	struct nfs_async_reqs *args;
	page_t *pp;

	rp = VTOR(vp);
	mi = VTOMI(vp);

	/*
	 * If we can't allocate a request structure, do the commit
	 * operation synchronously in this thread's context.
	 */
	if ((args = kmem_alloc(sizeof (*args), KM_NOSLEEP)) == NULL)
		goto noasync;

	args->a_next = NULL;
#ifdef DEBUG
	args->a_queuer = curthread;
#endif
	VN_HOLD(vp);
	args->a_vp = vp;
	ASSERT(cr != NULL);
	crhold(cr);
	args->a_cred = cr;
	args->a_io = NFS_COMMIT;
	args->a_nfs_commit = commit;
	args->a_nfs_plist = plist;
	args->a_nfs_offset = offset;
	args->a_nfs_count = count;

	mutex_enter(&mi->mi_async_lock);

	/*
	 * If asyncio has been disabled, then make a synchronous request.
	 * This check is done a second time in case async io was diabled
	 * while this thread was blocked waiting for memory pressure to
	 * reduce or for the queue to drain.
	 */
	if (mi->mi_max_threads == 0) {
		mutex_exit(&mi->mi_async_lock);
		goto noasync;
	}

	/*
	 * Link request structure into the async list and
	 * wakeup async thread to do the i/o.
	 */
	if (mi->mi_async_reqs[NFS_COMMIT] == NULL) {
		mi->mi_async_reqs[NFS_COMMIT] = args;
		mi->mi_async_tail[NFS_COMMIT] = args;
	} else {
		mi->mi_async_tail[NFS_COMMIT]->a_next = args;
		mi->mi_async_tail[NFS_COMMIT] = args;
	}

	mutex_enter(&rp->r_statelock);
	rp->r_count++;
	mutex_exit(&rp->r_statelock);

	if (mi->mi_io_kstats) {
		mutex_enter(&mi->mi_lock);
		kstat_waitq_enter(KSTAT_IO_PTR(mi->mi_io_kstats));
		mutex_exit(&mi->mi_lock);
	}

	mi->mi_async_req_count++;
	ASSERT(mi->mi_async_req_count != 0);
	cv_signal(&mi->mi_async_reqs_cv);
	mutex_exit(&mi->mi_async_lock);
	return;

noasync:
	if (args != NULL) {
		VN_RELE(vp);
		crfree(cr);
		kmem_free(args, sizeof (*args));
	}

	if (curproc == proc_pageout || curproc == proc_fsflush ||
	    nfs_zone() != mi->mi_zone) {
		while (plist != NULL) {
			pp = plist;
			page_sub(&plist, pp);
			pp->p_fsdata = C_COMMIT;
			page_unlock(pp);
		}
		return;
	}
	(*commit)(vp, plist, offset, count, cr);
}

void
nfs_async_inactive(vnode_t *vp, cred_t *cr,
    void (*inactive)(vnode_t *, cred_t *, caller_context_t *))
{
	mntinfo_t *mi;
	struct nfs_async_reqs *args;

	mi = VTOMI(vp);

	args = kmem_alloc(sizeof (*args), KM_SLEEP);
	args->a_next = NULL;
#ifdef DEBUG
	args->a_queuer = curthread;
#endif
	args->a_vp = vp;
	ASSERT(cr != NULL);
	crhold(cr);
	args->a_cred = cr;
	args->a_io = NFS_INACTIVE;
	args->a_nfs_inactive = inactive;

	/*
	 * Note that we don't check mi->mi_max_threads here, since we
	 * *need* to get rid of this vnode regardless of whether someone
	 * set nfs3_max_threads/nfs_max_threads to zero in /etc/system.
	 *
	 * The manager thread knows about this and is willing to create
	 * at least one thread to accommodate us.
	 */
	mutex_enter(&mi->mi_async_lock);
	if (mi->mi_manager_thread == NULL) {
		rnode_t *rp = VTOR(vp);

		mutex_exit(&mi->mi_async_lock);
		crfree(cr);	/* drop our reference */
		kmem_free(args, sizeof (*args));
		/*
		 * We can't do an over-the-wire call since we're in the wrong
		 * zone, so we need to clean up state as best we can and then
		 * throw away the vnode.
		 */
		mutex_enter(&rp->r_statelock);
		if (rp->r_unldvp != NULL) {
			vnode_t *unldvp;
			char *unlname;
			cred_t *unlcred;

			unldvp = rp->r_unldvp;
			rp->r_unldvp = NULL;
			unlname = rp->r_unlname;
			rp->r_unlname = NULL;
			unlcred = rp->r_unlcred;
			rp->r_unlcred = NULL;
			mutex_exit(&rp->r_statelock);

			VN_RELE(unldvp);
			kmem_free(unlname, MAXNAMELEN);
			crfree(unlcred);
		} else {
			mutex_exit(&rp->r_statelock);
		}
		/*
		 * No need to explicitly throw away any cached pages.  The
		 * eventual rinactive() will attempt a synchronous
		 * VOP_PUTPAGE() which will immediately fail since the request
		 * is coming from the wrong zone, and then will proceed to call
		 * nfs_invalidate_pages() which will clean things up for us.
		 */
		rp_addfree(VTOR(vp), cr);
		return;
	}

	if (mi->mi_async_reqs[NFS_INACTIVE] == NULL) {
		mi->mi_async_reqs[NFS_INACTIVE] = args;
	} else {
		mi->mi_async_tail[NFS_INACTIVE]->a_next = args;
	}
	mi->mi_async_tail[NFS_INACTIVE] = args;
	/*
	 * Don't increment r_count, since we're trying to get rid of the vnode.
	 */

	mi->mi_async_req_count++;
	ASSERT(mi->mi_async_req_count != 0);
	cv_signal(&mi->mi_async_reqs_cv);
	mutex_exit(&mi->mi_async_lock);
}

static void
nfs_async_start(struct vfs *vfsp)
{
	nfs_async_common_start(vfsp, NFS_ASYNC_QUEUE);
}

static void
nfs_async_pgops_start(struct vfs *vfsp)
{
	nfs_async_common_start(vfsp, NFS_ASYNC_PGOPS_QUEUE);
}

/*
 * The async queues for each mounted file system are arranged as a
 * set of queues, one for each async i/o type.  Requests are taken
 * from the queues in a round-robin fashion.  A number of consecutive
 * requests are taken from each queue before moving on to the next
 * queue.  This functionality may allow the NFS Version 2 server to do
 * write clustering, even if the client is mixing writes and reads
 * because it will take multiple write requests from the queue
 * before processing any of the other async i/o types.
 *
 * XXX The nfs_async_common_start thread is unsafe in the light of the present
 * model defined by cpr to suspend the system. Specifically over the
 * wire calls are cpr-unsafe. The thread should be reevaluated in
 * case of future updates to the cpr model.
 */
static void
nfs_async_common_start(struct vfs *vfsp, int async_queue)
{
	struct nfs_async_reqs *args;
	mntinfo_t *mi = VFTOMI(vfsp);
	clock_t time_left = 1;
	callb_cpr_t cprinfo;
	int i;
	int async_types;
	kcondvar_t *async_work_cv;

	if (async_queue == NFS_ASYNC_QUEUE) {
		async_types = NFS_ASYNC_TYPES;
		async_work_cv = &mi->mi_async_work_cv[NFS_ASYNC_QUEUE];
	} else {
		async_types = NFS_ASYNC_PGOPS_TYPES;
		async_work_cv = &mi->mi_async_work_cv[NFS_ASYNC_PGOPS_QUEUE];
	}

	/*
	 * Dynamic initialization of nfs_async_timeout to allow nfs to be
	 * built in an implementation independent manner.
	 */
	if (nfs_async_timeout == -1)
		nfs_async_timeout = NFS_ASYNC_TIMEOUT;

	CALLB_CPR_INIT(&cprinfo, &mi->mi_async_lock, callb_generic_cpr, "nas");

	mutex_enter(&mi->mi_async_lock);
	for (;;) {
		/*
		 * Find the next queue containing an entry.  We start
		 * at the current queue pointer and then round robin
		 * through all of them until we either find a non-empty
		 * queue or have looked through all of them.
		 */
		for (i = 0; i < async_types; i++) {
			args = *mi->mi_async_curr[async_queue];
			if (args != NULL)
				break;
			mi->mi_async_curr[async_queue]++;
			if (mi->mi_async_curr[async_queue] ==
			    &mi->mi_async_reqs[async_types]) {
				mi->mi_async_curr[async_queue] =
				    &mi->mi_async_reqs[0];
			}
		}
		/*
		 * If we didn't find a entry, then block until woken up
		 * again and then look through the queues again.
		 */
		if (args == NULL) {
			/*
			 * Exiting is considered to be safe for CPR as well
			 */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);

			/*
			 * Wakeup thread waiting to unmount the file
			 * system only if all async threads are inactive.
			 *
			 * If we've timed-out and there's nothing to do,
			 * then get rid of this thread.
			 */
			if (mi->mi_max_threads == 0 || time_left <= 0) {
				--mi->mi_threads[async_queue];

				if (mi->mi_threads[NFS_ASYNC_QUEUE] == 0 &&
				    mi->mi_threads[NFS_ASYNC_PGOPS_QUEUE] == 0)
					cv_signal(&mi->mi_async_cv);
				CALLB_CPR_EXIT(&cprinfo);
				VFS_RELE(vfsp);	/* release thread's hold */
				zthread_exit();
				/* NOTREACHED */
			}
			time_left = cv_reltimedwait(async_work_cv,
			    &mi->mi_async_lock, nfs_async_timeout,
			    TR_CLOCK_TICK);

			CALLB_CPR_SAFE_END(&cprinfo, &mi->mi_async_lock);

			continue;
		}
		time_left = 1;

		/*
		 * Remove the request from the async queue and then
		 * update the current async request queue pointer.  If
		 * the current queue is empty or we have removed enough
		 * consecutive entries from it, then reset the counter
		 * for this queue and then move the current pointer to
		 * the next queue.
		 */
		*mi->mi_async_curr[async_queue] = args->a_next;
		if (*mi->mi_async_curr[async_queue] == NULL ||
		    --mi->mi_async_clusters[args->a_io] == 0) {
			mi->mi_async_clusters[args->a_io] =
			    mi->mi_async_init_clusters;
			mi->mi_async_curr[async_queue]++;
			if (mi->mi_async_curr[async_queue] ==
			    &mi->mi_async_reqs[async_types]) {
				mi->mi_async_curr[async_queue] =
				    &mi->mi_async_reqs[0];
			}
		}

		if (args->a_io != NFS_INACTIVE && mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_waitq_exit(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}

		mutex_exit(&mi->mi_async_lock);

		/*
		 * Obtain arguments from the async request structure.
		 */
		if (args->a_io == NFS_READ_AHEAD && mi->mi_max_threads > 0) {
			(*args->a_nfs_readahead)(args->a_vp, args->a_nfs_blkoff,
			    args->a_nfs_addr, args->a_nfs_seg,
			    args->a_cred);
		} else if (args->a_io == NFS_PUTAPAGE) {
			(void) (*args->a_nfs_putapage)(args->a_vp,
			    args->a_nfs_pp, args->a_nfs_off,
			    args->a_nfs_len, args->a_nfs_flags,
			    args->a_cred);
		} else if (args->a_io == NFS_PAGEIO) {
			(void) (*args->a_nfs_pageio)(args->a_vp,
			    args->a_nfs_pp, args->a_nfs_off,
			    args->a_nfs_len, args->a_nfs_flags,
			    args->a_cred);
		} else if (args->a_io == NFS_READDIR) {
			(void) ((*args->a_nfs_readdir)(args->a_vp,
			    args->a_nfs_rdc, args->a_cred));
		} else if (args->a_io == NFS_COMMIT) {
			(*args->a_nfs_commit)(args->a_vp, args->a_nfs_plist,
			    args->a_nfs_offset, args->a_nfs_count,
			    args->a_cred);
		} else if (args->a_io == NFS_INACTIVE) {
			(*args->a_nfs_inactive)(args->a_vp, args->a_cred, NULL);
		}

		/*
		 * Now, release the vnode and free the credentials
		 * structure.
		 */
		free_async_args(args);
		/*
		 * Reacquire the mutex because it will be needed above.
		 */
		mutex_enter(&mi->mi_async_lock);
	}
}

void
nfs_async_stop(struct vfs *vfsp)
{
	mntinfo_t *mi = VFTOMI(vfsp);

	/*
	 * Wait for all outstanding async operations to complete and for the
	 * worker threads to exit.
	 */
	mutex_enter(&mi->mi_async_lock);
	mi->mi_max_threads = 0;
	NFS_WAKEALL_ASYNC_WORKERS(mi->mi_async_work_cv);
	while (mi->mi_threads[NFS_ASYNC_QUEUE] != 0 ||
	    mi->mi_threads[NFS_ASYNC_PGOPS_QUEUE] != 0)
		cv_wait(&mi->mi_async_cv, &mi->mi_async_lock);
	mutex_exit(&mi->mi_async_lock);
}

/*
 * nfs_async_stop_sig:
 * Wait for all outstanding putpage operation to complete. If a signal
 * is deliver we will abort and return non-zero. If we can put all the
 * pages we will return 0. This routine is called from nfs_unmount and
 * nfs3_unmount to make these operations interruptible.
 */
int
nfs_async_stop_sig(struct vfs *vfsp)
{
	mntinfo_t *mi = VFTOMI(vfsp);
	ushort_t omax;
	int rval;

	/*
	 * Wait for all outstanding async operations to complete and for the
	 * worker threads to exit.
	 */
	mutex_enter(&mi->mi_async_lock);
	omax = mi->mi_max_threads;
	mi->mi_max_threads = 0;
	/*
	 * Tell all the worker threads to exit.
	 */
	NFS_WAKEALL_ASYNC_WORKERS(mi->mi_async_work_cv);
	while (mi->mi_threads[NFS_ASYNC_QUEUE] != 0 ||
	    mi->mi_threads[NFS_ASYNC_PGOPS_QUEUE] != 0) {
		if (!cv_wait_sig(&mi->mi_async_cv, &mi->mi_async_lock))
			break;
	}
	rval = (mi->mi_threads[NFS_ASYNC_QUEUE] != 0 ||
	    mi->mi_threads[NFS_ASYNC_PGOPS_QUEUE]  != 0); /* Interrupted */
	if (rval)
		mi->mi_max_threads = omax;
	mutex_exit(&mi->mi_async_lock);

	return (rval);
}

int
writerp(rnode_t *rp, caddr_t base, int tcount, struct uio *uio, int pgcreated)
{
	int pagecreate;
	int n;
	int saved_n;
	caddr_t saved_base;
	u_offset_t offset;
	int error;
	int sm_error;
	vnode_t *vp = RTOV(rp);

	ASSERT(tcount <= MAXBSIZE && tcount <= uio->uio_resid);
	ASSERT(nfs_rw_lock_held(&rp->r_rwlock, RW_WRITER));
	if (!vpm_enable) {
		ASSERT(((uintptr_t)base & MAXBOFFSET) + tcount <= MAXBSIZE);
	}

	/*
	 * Move bytes in at most PAGESIZE chunks. We must avoid
	 * spanning pages in uiomove() because page faults may cause
	 * the cache to be invalidated out from under us. The r_size is not
	 * updated until after the uiomove. If we push the last page of a
	 * file before r_size is correct, we will lose the data written past
	 * the current (and invalid) r_size.
	 */
	do {
		offset = uio->uio_loffset;
		pagecreate = 0;

		/*
		 * n is the number of bytes required to satisfy the request
		 *   or the number of bytes to fill out the page.
		 */
		n = (int)MIN((PAGESIZE - (offset & PAGEOFFSET)), tcount);

		/*
		 * Check to see if we can skip reading in the page
		 * and just allocate the memory.  We can do this
		 * if we are going to rewrite the entire mapping
		 * or if we are going to write to or beyond the current
		 * end of file from the beginning of the mapping.
		 *
		 * The read of r_size is now protected by r_statelock.
		 */
		mutex_enter(&rp->r_statelock);
		/*
		 * When pgcreated is nonzero the caller has already done
		 * a segmap_getmapflt with forcefault 0 and S_WRITE. With
		 * segkpm this means we already have at least one page
		 * created and mapped at base.
		 */
		pagecreate = pgcreated ||
		    ((offset & PAGEOFFSET) == 0 &&
		    (n == PAGESIZE || ((offset + n) >= rp->r_size)));

		mutex_exit(&rp->r_statelock);
		if (!vpm_enable && pagecreate) {
			/*
			 * The last argument tells segmap_pagecreate() to
			 * always lock the page, as opposed to sometimes
			 * returning with the page locked. This way we avoid a
			 * fault on the ensuing uiomove(), but also
			 * more importantly (to fix bug 1094402) we can
			 * call segmap_fault() to unlock the page in all
			 * cases. An alternative would be to modify
			 * segmap_pagecreate() to tell us when it is
			 * locking a page, but that's a fairly major
			 * interface change.
			 */
			if (pgcreated == 0)
				(void) segmap_pagecreate(segkmap, base,
				    (uint_t)n, 1);
			saved_base = base;
			saved_n = n;
		}

		/*
		 * The number of bytes of data in the last page can not
		 * be accurately be determined while page is being
		 * uiomove'd to and the size of the file being updated.
		 * Thus, inform threads which need to know accurately
		 * how much data is in the last page of the file.  They
		 * will not do the i/o immediately, but will arrange for
		 * the i/o to happen later when this modify operation
		 * will have finished.
		 */
		ASSERT(!(rp->r_flags & RMODINPROGRESS));
		mutex_enter(&rp->r_statelock);
		rp->r_flags |= RMODINPROGRESS;
		rp->r_modaddr = (offset & MAXBMASK);
		mutex_exit(&rp->r_statelock);

		if (vpm_enable) {
			/*
			 * Copy data. If new pages are created, part of
			 * the page that is not written will be initizliazed
			 * with zeros.
			 */
			error = vpm_data_copy(vp, offset, n, uio,
			    !pagecreate, NULL, 0, S_WRITE);
		} else {
			error = uiomove(base, n, UIO_WRITE, uio);
		}

		/*
		 * r_size is the maximum number of
		 * bytes known to be in the file.
		 * Make sure it is at least as high as the
		 * first unwritten byte pointed to by uio_loffset.
		 */
		mutex_enter(&rp->r_statelock);
		if (rp->r_size < uio->uio_loffset)
			rp->r_size = uio->uio_loffset;
		rp->r_flags &= ~RMODINPROGRESS;
		rp->r_flags |= RDIRTY;
		mutex_exit(&rp->r_statelock);

		/* n = # of bytes written */
		n = (int)(uio->uio_loffset - offset);

		if (!vpm_enable) {
			base += n;
		}
		tcount -= n;
		/*
		 * If we created pages w/o initializing them completely,
		 * we need to zero the part that wasn't set up.
		 * This happens on a most EOF write cases and if
		 * we had some sort of error during the uiomove.
		 */
		if (!vpm_enable && pagecreate) {
			if ((uio->uio_loffset & PAGEOFFSET) || n == 0)
				(void) kzero(base, PAGESIZE - n);

			if (pgcreated) {
				/*
				 * Caller is responsible for this page,
				 * it was not created in this loop.
				 */
				pgcreated = 0;
			} else {
				/*
				 * For bug 1094402: segmap_pagecreate locks
				 * page. Unlock it. This also unlocks the
				 * pages allocated by page_create_va() in
				 * segmap_pagecreate().
				 */
				sm_error = segmap_fault(kas.a_hat, segkmap,
				    saved_base, saved_n,
				    F_SOFTUNLOCK, S_WRITE);
				if (error == 0)
					error = sm_error;
			}
		}
	} while (tcount > 0 && error == 0);

	return (error);
}

int
nfs_putpages(vnode_t *vp, u_offset_t off, size_t len, int flags, cred_t *cr)
{
	rnode_t *rp;
	page_t *pp;
	u_offset_t eoff;
	u_offset_t io_off;
	size_t io_len;
	int error;
	int rdirty;
	int err;

	rp = VTOR(vp);
	ASSERT(rp->r_count > 0);

	if (!vn_has_cached_data(vp))
		return (0);

	ASSERT(vp->v_type != VCHR);

	/*
	 * If ROUTOFSPACE is set, then all writes turn into B_INVAL
	 * writes.  B_FORCE is set to force the VM system to actually
	 * invalidate the pages, even if the i/o failed.  The pages
	 * need to get invalidated because they can't be written out
	 * because there isn't any space left on either the server's
	 * file system or in the user's disk quota.  The B_FREE bit
	 * is cleared to avoid confusion as to whether this is a
	 * request to place the page on the freelist or to destroy
	 * it.
	 */
	if ((rp->r_flags & ROUTOFSPACE) ||
	    (vp->v_vfsp->vfs_flag & VFS_UNMOUNTED))
		flags = (flags & ~B_FREE) | B_INVAL | B_FORCE;

	if (len == 0) {
		/*
		 * If doing a full file synchronous operation, then clear
		 * the RDIRTY bit.  If a page gets dirtied while the flush
		 * is happening, then RDIRTY will get set again.  The
		 * RDIRTY bit must get cleared before the flush so that
		 * we don't lose this information.
		 *
		 * If there are no full file async write operations
		 * pending and RDIRTY bit is set, clear it.
		 */
		if (off == (u_offset_t)0 &&
		    !(flags & B_ASYNC) &&
		    (rp->r_flags & RDIRTY)) {
			mutex_enter(&rp->r_statelock);
			rdirty = (rp->r_flags & RDIRTY);
			rp->r_flags &= ~RDIRTY;
			mutex_exit(&rp->r_statelock);
		} else if (flags & B_ASYNC && off == (u_offset_t)0) {
			mutex_enter(&rp->r_statelock);
			if (rp->r_flags & RDIRTY && rp->r_awcount == 0) {
				rdirty = (rp->r_flags & RDIRTY);
				rp->r_flags &= ~RDIRTY;
			}
			mutex_exit(&rp->r_statelock);
		} else
			rdirty = 0;

		/*
		 * Search the entire vp list for pages >= off, and flush
		 * the dirty pages.
		 */
		error = pvn_vplist_dirty(vp, off, rp->r_putapage,
		    flags, cr);

		/*
		 * If an error occurred and the file was marked as dirty
		 * before and we aren't forcibly invalidating pages, then
		 * reset the RDIRTY flag.
		 */
		if (error && rdirty &&
		    (flags & (B_INVAL | B_FORCE)) != (B_INVAL | B_FORCE)) {
			mutex_enter(&rp->r_statelock);
			rp->r_flags |= RDIRTY;
			mutex_exit(&rp->r_statelock);
		}
	} else {
		/*
		 * Do a range from [off...off + len) looking for pages
		 * to deal with.
		 */
		error = 0;
#ifdef lint
		io_len = 0;
#endif
		eoff = off + len;
		mutex_enter(&rp->r_statelock);
		for (io_off = off; io_off < eoff && io_off < rp->r_size;
		    io_off += io_len) {
			mutex_exit(&rp->r_statelock);
			/*
			 * If we are not invalidating, synchronously
			 * freeing or writing pages use the routine
			 * page_lookup_nowait() to prevent reclaiming
			 * them from the free list.
			 */
			if ((flags & B_INVAL) || !(flags & B_ASYNC)) {
				pp = page_lookup(vp, io_off,
				    (flags & (B_INVAL | B_FREE)) ?
				    SE_EXCL : SE_SHARED);
			} else {
				pp = page_lookup_nowait(vp, io_off,
				    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
			}

			if (pp == NULL || !pvn_getdirty(pp, flags))
				io_len = PAGESIZE;
			else {
				err = (*rp->r_putapage)(vp, pp, &io_off,
				    &io_len, flags, cr);
				if (!error)
					error = err;
				/*
				 * "io_off" and "io_len" are returned as
				 * the range of pages we actually wrote.
				 * This allows us to skip ahead more quickly
				 * since several pages may've been dealt
				 * with by this iteration of the loop.
				 */
			}
			mutex_enter(&rp->r_statelock);
		}
		mutex_exit(&rp->r_statelock);
	}

	return (error);
}

void
nfs_invalidate_pages(vnode_t *vp, u_offset_t off, cred_t *cr)
{
	rnode_t *rp;

	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);
	while (rp->r_flags & RTRUNCATE)
		cv_wait(&rp->r_cv, &rp->r_statelock);
	rp->r_flags |= RTRUNCATE;
	if (off == (u_offset_t)0) {
		rp->r_flags &= ~RDIRTY;
		if (!(rp->r_flags & RSTALE))
			rp->r_error = 0;
	}
	rp->r_truncaddr = off;
	mutex_exit(&rp->r_statelock);
	(void) pvn_vplist_dirty(vp, off, rp->r_putapage,
	    B_INVAL | B_TRUNC, cr);
	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~RTRUNCATE;
	cv_broadcast(&rp->r_cv);
	mutex_exit(&rp->r_statelock);
}

static int nfs_write_error_to_cons_only = 0;
#define	MSG(x)	(nfs_write_error_to_cons_only ? (x) : (x) + 1)

/*
 * Print a file handle
 */
void
nfs_printfhandle(nfs_fhandle *fhp)
{
	int *ip;
	char *buf;
	size_t bufsize;
	char *cp;

	/*
	 * 13 == "(file handle:"
	 * maximum of NFS_FHANDLE / sizeof (*ip) elements in fh_buf times
	 *	1 == ' '
	 *	8 == maximum strlen of "%x"
	 * 3 == ")\n\0"
	 */
	bufsize = 13 + ((NFS_FHANDLE_LEN / sizeof (*ip)) * (1 + 8)) + 3;
	buf = kmem_alloc(bufsize, KM_NOSLEEP);
	if (buf == NULL)
		return;

	cp = buf;
	(void) strcpy(cp, "(file handle:");
	while (*cp != '\0')
		cp++;
	for (ip = (int *)fhp->fh_buf;
	    ip < (int *)&fhp->fh_buf[fhp->fh_len];
	    ip++) {
		(void) sprintf(cp, " %x", *ip);
		while (*cp != '\0')
			cp++;
	}
	(void) strcpy(cp, ")\n");

	zcmn_err(getzoneid(), CE_CONT, MSG("^%s"), buf);

	kmem_free(buf, bufsize);
}

/*
 * Notify the system administrator that an NFS write error has
 * occurred.
 */

/* seconds between ENOSPC/EDQUOT messages */
clock_t nfs_write_error_interval = 5;

void
nfs_write_error(vnode_t *vp, int error, cred_t *cr)
{
	mntinfo_t *mi;
	clock_t now;

	mi = VTOMI(vp);
	/*
	 * In case of forced unmount or zone shutdown, do not print any
	 * messages since it can flood the console with error messages.
	 */
	if (FS_OR_ZONE_GONE(mi->mi_vfsp))
		return;

	/*
	 * No use in flooding the console with ENOSPC
	 * messages from the same file system.
	 */
	now = ddi_get_lbolt();
	if ((error != ENOSPC && error != EDQUOT) ||
	    now - mi->mi_printftime > 0) {
		zoneid_t zoneid = mi->mi_zone->zone_id;

#ifdef DEBUG
		nfs_perror(error, "NFS%ld write error on host %s: %m.\n",
		    mi->mi_vers, VTOR(vp)->r_server->sv_hostname, NULL);
#else
		nfs_perror(error, "NFS write error on host %s: %m.\n",
		    VTOR(vp)->r_server->sv_hostname, NULL);
#endif
		if (error == ENOSPC || error == EDQUOT) {
			zcmn_err(zoneid, CE_CONT,
			    MSG("^File: userid=%d, groupid=%d\n"),
			    crgetuid(cr), crgetgid(cr));
			if (crgetuid(CRED()) != crgetuid(cr) ||
			    crgetgid(CRED()) != crgetgid(cr)) {
				zcmn_err(zoneid, CE_CONT,
				    MSG("^User: userid=%d, groupid=%d\n"),
				    crgetuid(CRED()), crgetgid(CRED()));
			}
			mi->mi_printftime = now +
			    nfs_write_error_interval * hz;
		}
		nfs_printfhandle(&VTOR(vp)->r_fh);
#ifdef DEBUG
		if (error == EACCES) {
			zcmn_err(zoneid, CE_CONT,
			    MSG("^nfs_bio: cred is%s kcred\n"),
			    cr == kcred ? "" : " not");
		}
#endif
	}
}

/* ARGSUSED */
static void *
nfs_mi_init(zoneid_t zoneid)
{
	struct mi_globals *mig;

	mig = kmem_alloc(sizeof (*mig), KM_SLEEP);
	mutex_init(&mig->mig_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&mig->mig_list, sizeof (mntinfo_t),
	    offsetof(mntinfo_t, mi_zone_node));
	mig->mig_destructor_called = B_FALSE;
	return (mig);
}

/*
 * Callback routine to tell all NFS mounts in the zone to stop creating new
 * threads.  Existing threads should exit.
 */
/* ARGSUSED */
static void
nfs_mi_shutdown(zoneid_t zoneid, void *data)
{
	struct mi_globals *mig = data;
	mntinfo_t *mi;

	ASSERT(mig != NULL);
again:
	mutex_enter(&mig->mig_lock);
	for (mi = list_head(&mig->mig_list); mi != NULL;
	    mi = list_next(&mig->mig_list, mi)) {

		/*
		 * If we've done the shutdown work for this FS, skip.
		 * Once we go off the end of the list, we're done.
		 */
		if (mi->mi_flags & MI_DEAD)
			continue;

		/*
		 * We will do work, so not done.  Get a hold on the FS.
		 */
		VFS_HOLD(mi->mi_vfsp);

		/*
		 * purge the DNLC for this filesystem
		 */
		(void) dnlc_purge_vfsp(mi->mi_vfsp, 0);

		mutex_enter(&mi->mi_async_lock);
		/*
		 * Tell existing async worker threads to exit.
		 */
		mi->mi_max_threads = 0;
		NFS_WAKEALL_ASYNC_WORKERS(mi->mi_async_work_cv);
		/*
		 * Set MI_ASYNC_MGR_STOP so the async manager thread starts
		 * getting ready to exit when it's done with its current work.
		 * Also set MI_DEAD to note we've acted on this FS.
		 */
		mutex_enter(&mi->mi_lock);
		mi->mi_flags |= (MI_ASYNC_MGR_STOP|MI_DEAD);
		mutex_exit(&mi->mi_lock);
		/*
		 * Wake up the async manager thread.
		 */
		cv_broadcast(&mi->mi_async_reqs_cv);
		mutex_exit(&mi->mi_async_lock);

		/*
		 * Drop lock and release FS, which may change list, then repeat.
		 * We're done when every mi has been done or the list is empty.
		 */
		mutex_exit(&mig->mig_lock);
		VFS_RELE(mi->mi_vfsp);
		goto again;
	}
	mutex_exit(&mig->mig_lock);
}

static void
nfs_mi_free_globals(struct mi_globals *mig)
{
	list_destroy(&mig->mig_list);	/* makes sure the list is empty */
	mutex_destroy(&mig->mig_lock);
	kmem_free(mig, sizeof (*mig));

}

/* ARGSUSED */
static void
nfs_mi_destroy(zoneid_t zoneid, void *data)
{
	struct mi_globals *mig = data;

	ASSERT(mig != NULL);
	mutex_enter(&mig->mig_lock);
	if (list_head(&mig->mig_list) != NULL) {
		/* Still waiting for VFS_FREEVFS() */
		mig->mig_destructor_called = B_TRUE;
		mutex_exit(&mig->mig_lock);
		return;
	}
	nfs_mi_free_globals(mig);
}

/*
 * Add an NFS mount to the per-zone list of NFS mounts.
 */
void
nfs_mi_zonelist_add(mntinfo_t *mi)
{
	struct mi_globals *mig;

	mig = zone_getspecific(mi_list_key, mi->mi_zone);
	mutex_enter(&mig->mig_lock);
	list_insert_head(&mig->mig_list, mi);
	mutex_exit(&mig->mig_lock);
}

/*
 * Remove an NFS mount from the per-zone list of NFS mounts.
 */
static void
nfs_mi_zonelist_remove(mntinfo_t *mi)
{
	struct mi_globals *mig;

	mig = zone_getspecific(mi_list_key, mi->mi_zone);
	mutex_enter(&mig->mig_lock);
	list_remove(&mig->mig_list, mi);
	/*
	 * We can be called asynchronously by VFS_FREEVFS() after the zone
	 * shutdown/destroy callbacks have executed; if so, clean up the zone's
	 * mi globals.
	 */
	if (list_head(&mig->mig_list) == NULL &&
	    mig->mig_destructor_called == B_TRUE) {
		nfs_mi_free_globals(mig);
		return;
	}
	mutex_exit(&mig->mig_lock);
}

/*
 * NFS Client initialization routine.  This routine should only be called
 * once.  It performs the following tasks:
 *	- Initalize all global locks
 * 	- Call sub-initialization routines (localize access to variables)
 */
int
nfs_clntinit(void)
{
#ifdef DEBUG
	static boolean_t nfs_clntup = B_FALSE;
#endif
	int error;

#ifdef DEBUG
	ASSERT(nfs_clntup == B_FALSE);
#endif

	error = nfs_subrinit();
	if (error)
		return (error);

	error = nfs_vfsinit();
	if (error) {
		/*
		 * Cleanup nfs_subrinit() work
		 */
		nfs_subrfini();
		return (error);
	}
	zone_key_create(&mi_list_key, nfs_mi_init, nfs_mi_shutdown,
	    nfs_mi_destroy);

	nfs4_clnt_init();

#ifdef DEBUG
	nfs_clntup = B_TRUE;
#endif

	return (0);
}

/*
 * This routine is only called if the NFS Client has been initialized but
 * the module failed to be installed. This routine will cleanup the previously
 * allocated/initialized work.
 */
void
nfs_clntfini(void)
{
	(void) zone_key_delete(mi_list_key);
	nfs_subrfini();
	nfs_vfsfini();
	nfs4_clnt_fini();
}

/*
 * nfs_lockrelease:
 *
 * Release any locks on the given vnode that are held by the current
 * process.
 */
void
nfs_lockrelease(vnode_t *vp, int flag, offset_t offset, cred_t *cr)
{
	flock64_t ld;
	struct shrlock shr;
	char *buf;
	int remote_lock_possible;
	int ret;

	ASSERT((uintptr_t)vp > KERNELBASE);

	/*
	 * Generate an explicit unlock operation for the entire file.  As a
	 * partial optimization, only generate the unlock if there is a
	 * lock registered for the file.  We could check whether this
	 * particular process has any locks on the file, but that would
	 * require the local locking code to provide yet another query
	 * routine.  Note that no explicit synchronization is needed here.
	 * At worst, flk_has_remote_locks() will return a false positive,
	 * in which case the unlock call wastes time but doesn't harm
	 * correctness.
	 *
	 * In addition, an unlock request is generated if the process
	 * is listed as possibly having a lock on the file because the
	 * server and client lock managers may have gotten out of sync.
	 * N.B. It is important to make sure nfs_remove_locking_id() is
	 * called here even if flk_has_remote_locks(vp) reports true.
	 * If it is not called and there is an entry on the process id
	 * list, that entry will never get removed.
	 */
	remote_lock_possible = nfs_remove_locking_id(vp, RLMPL_PID,
	    (char *)&(ttoproc(curthread)->p_pid), NULL, NULL);
	if (remote_lock_possible || flk_has_remote_locks(vp)) {
		ld.l_type = F_UNLCK;	/* set to unlock entire file */
		ld.l_whence = 0;	/* unlock from start of file */
		ld.l_start = 0;
		ld.l_len = 0;		/* do entire file */
		ret = VOP_FRLOCK(vp, F_SETLK, &ld, flag, offset, NULL, cr,
		    NULL);

		if (ret != 0) {
			/*
			 * If VOP_FRLOCK fails, make sure we unregister
			 * local locks before we continue.
			 */
			ld.l_pid = ttoproc(curthread)->p_pid;
			lm_register_lock_locally(vp, NULL, &ld, flag, offset);
#ifdef DEBUG
			nfs_perror(ret,
			    "NFS lock release error on vp %p: %m.\n",
			    (void *)vp, NULL);
#endif
		}

		/*
		 * The call to VOP_FRLOCK may put the pid back on the
		 * list.  We need to remove it.
		 */
		(void) nfs_remove_locking_id(vp, RLMPL_PID,
		    (char *)&(ttoproc(curthread)->p_pid), NULL, NULL);
	}

	/*
	 * As long as the vp has a share matching our pid,
	 * pluck it off and unshare it.  There are circumstances in
	 * which the call to nfs_remove_locking_id() may put the
	 * owner back on the list, in which case we simply do a
	 * redundant and harmless unshare.
	 */
	buf = kmem_alloc(MAX_SHR_OWNER_LEN, KM_SLEEP);
	while (nfs_remove_locking_id(vp, RLMPL_OWNER,
	    (char *)NULL, buf, &shr.s_own_len)) {
		shr.s_owner = buf;
		shr.s_access = 0;
		shr.s_deny = 0;
		shr.s_sysid = 0;
		shr.s_pid = curproc->p_pid;

		ret = VOP_SHRLOCK(vp, F_UNSHARE, &shr, flag, cr, NULL);
#ifdef DEBUG
		if (ret != 0) {
			nfs_perror(ret,
			    "NFS share release error on vp %p: %m.\n",
			    (void *)vp, NULL);
		}
#endif
	}
	kmem_free(buf, MAX_SHR_OWNER_LEN);
}

/*
 * nfs_lockcompletion:
 *
 * If the vnode has a lock that makes it unsafe to cache the file, mark it
 * as non cachable (set VNOCACHE bit).
 */

void
nfs_lockcompletion(vnode_t *vp, int cmd)
{
#ifdef DEBUG
	rnode_t *rp = VTOR(vp);

	ASSERT(nfs_rw_lock_held(&rp->r_lkserlock, RW_WRITER));
#endif

	if (cmd == F_SETLK || cmd == F_SETLKW) {
		if (!lm_safemap(vp)) {
			mutex_enter(&vp->v_lock);
			vp->v_flag |= VNOCACHE;
			mutex_exit(&vp->v_lock);
		} else {
			mutex_enter(&vp->v_lock);
			vp->v_flag &= ~VNOCACHE;
			mutex_exit(&vp->v_lock);
		}
	}
	/*
	 * The cached attributes of the file are stale after acquiring
	 * the lock on the file. They were updated when the file was
	 * opened, but not updated when the lock was acquired. Therefore the
	 * cached attributes are invalidated after the lock is obtained.
	 */
	PURGE_ATTRCACHE(vp);
}

/*
 * The lock manager holds state making it possible for the client
 * and server to be out of sync.  For example, if the response from
 * the server granting a lock request is lost, the server will think
 * the lock is granted and the client will think the lock is lost.
 * The client can tell when it is not positive if it is in sync with
 * the server.
 *
 * To deal with this, a list of processes for which the client is
 * not sure if the server holds a lock is attached to the rnode.
 * When such a process closes the rnode, an unlock request is sent
 * to the server to unlock the entire file.
 *
 * The list is kept as a singularly linked NULL terminated list.
 * Because it is only added to under extreme error conditions, the
 * list shouldn't get very big.  DEBUG kernels print a message if
 * the list gets bigger than nfs_lmpl_high_water.  This is arbitrarily
 * choosen to be 8, but can be tuned at runtime.
 */
#ifdef DEBUG
/* int nfs_lmpl_high_water = 8; */
int nfs_lmpl_high_water = 128;
int nfs_cnt_add_locking_id = 0;
int nfs_len_add_locking_id = 0;
#endif /* DEBUG */

/*
 * Record that the nfs lock manager server may be holding a lock on
 * a vnode for a process.
 *
 * Because the nfs lock manager server holds state, it is possible
 * for the server to get out of sync with the client.  This routine is called
 * from the client when it is no longer sure if the server is in sync
 * with the client.  nfs_lockrelease() will then notice this and send
 * an unlock request when the file is closed
 */
void
nfs_add_locking_id(vnode_t *vp, pid_t pid, int type, char *id, int len)
{
	rnode_t *rp;
	lmpl_t *new;
	lmpl_t *cur;
	lmpl_t **lmplp;
#ifdef DEBUG
	int list_len = 1;
#endif /* DEBUG */

#ifdef DEBUG
	++nfs_cnt_add_locking_id;
#endif /* DEBUG */
	/*
	 * allocate new lmpl_t now so we don't sleep
	 * later after grabbing mutexes
	 */
	ASSERT(len < MAX_SHR_OWNER_LEN);
	new = kmem_alloc(sizeof (*new), KM_SLEEP);
	new->lmpl_type = type;
	new->lmpl_pid = pid;
	new->lmpl_owner = kmem_alloc(len, KM_SLEEP);
	bcopy(id, new->lmpl_owner, len);
	new->lmpl_own_len = len;
	new->lmpl_next = (lmpl_t *)NULL;
#ifdef DEBUG
	if (type == RLMPL_PID) {
		ASSERT(len == sizeof (pid_t));
		ASSERT(pid == *(pid_t *)new->lmpl_owner);
	} else {
		ASSERT(type == RLMPL_OWNER);
	}
#endif

	rp = VTOR(vp);
	mutex_enter(&rp->r_statelock);

	/*
	 * Add this id to the list for this rnode only if the
	 * rnode is active and the id is not already there.
	 */
	ASSERT(rp->r_flags & RHASHED);
	lmplp = &(rp->r_lmpl);
	for (cur = rp->r_lmpl; cur != (lmpl_t *)NULL; cur = cur->lmpl_next) {
		if (cur->lmpl_pid == pid &&
		    cur->lmpl_type == type &&
		    cur->lmpl_own_len == len &&
		    bcmp(cur->lmpl_owner, new->lmpl_owner, len) == 0) {
			kmem_free(new->lmpl_owner, len);
			kmem_free(new, sizeof (*new));
			break;
		}
		lmplp = &cur->lmpl_next;
#ifdef DEBUG
		++list_len;
#endif /* DEBUG */
	}
	if (cur == (lmpl_t *)NULL) {
		*lmplp = new;
#ifdef DEBUG
		if (list_len > nfs_len_add_locking_id) {
			nfs_len_add_locking_id = list_len;
		}
		if (list_len > nfs_lmpl_high_water) {
			cmn_err(CE_WARN, "nfs_add_locking_id: long list "
			    "vp=%p is %d", (void *)vp, list_len);
		}
#endif /* DEBUG */
	}

#ifdef DEBUG
	if (share_debug) {
		int nitems = 0;
		int npids = 0;
		int nowners = 0;

		/*
		 * Count the number of things left on r_lmpl after the remove.
		 */
		for (cur = rp->r_lmpl; cur != (lmpl_t *)NULL;
		    cur = cur->lmpl_next) {
			nitems++;
			if (cur->lmpl_type == RLMPL_PID) {
				npids++;
			} else if (cur->lmpl_type == RLMPL_OWNER) {
				nowners++;
			} else {
				cmn_err(CE_PANIC, "nfs_add_locking_id: "
				    "unrecognized lmpl_type %d",
				    cur->lmpl_type);
			}
		}

		cmn_err(CE_CONT, "nfs_add_locking_id(%s): %d PIDs + %d "
		    "OWNs = %d items left on r_lmpl\n",
		    (type == RLMPL_PID) ? "P" : "O", npids, nowners, nitems);
	}
#endif

	mutex_exit(&rp->r_statelock);
}

/*
 * Remove an id from the lock manager id list.
 *
 * If the id is not in the list return 0.  If it was found and
 * removed, return 1.
 */
static int
nfs_remove_locking_id(vnode_t *vp, int type, char *id, char *rid, int *rlen)
{
	lmpl_t *cur;
	lmpl_t **lmplp;
	rnode_t *rp;
	int rv = 0;

	ASSERT(type == RLMPL_PID || type == RLMPL_OWNER);

	rp = VTOR(vp);

	mutex_enter(&rp->r_statelock);
	ASSERT(rp->r_flags & RHASHED);
	lmplp = &(rp->r_lmpl);

	/*
	 * Search through the list and remove the entry for this id
	 * if it is there.  The special case id == NULL allows removal
	 * of the first share on the r_lmpl list belonging to the
	 * current process (if any), without regard to further details
	 * of its identity.
	 */
	for (cur = rp->r_lmpl; cur != (lmpl_t *)NULL; cur = cur->lmpl_next) {
		if (cur->lmpl_type == type &&
		    cur->lmpl_pid == curproc->p_pid &&
		    (id == (char *)NULL ||
		    bcmp(cur->lmpl_owner, id, cur->lmpl_own_len) == 0)) {
			*lmplp = cur->lmpl_next;
			ASSERT(cur->lmpl_own_len < MAX_SHR_OWNER_LEN);
			if (rid != NULL) {
				bcopy(cur->lmpl_owner, rid, cur->lmpl_own_len);
				*rlen = cur->lmpl_own_len;
			}
			kmem_free(cur->lmpl_owner, cur->lmpl_own_len);
			kmem_free(cur, sizeof (*cur));
			rv = 1;
			break;
		}
		lmplp = &cur->lmpl_next;
	}

#ifdef DEBUG
	if (share_debug) {
		int nitems = 0;
		int npids = 0;
		int nowners = 0;

		/*
		 * Count the number of things left on r_lmpl after the remove.
		 */
		for (cur = rp->r_lmpl; cur != (lmpl_t *)NULL;
		    cur = cur->lmpl_next) {
			nitems++;
			if (cur->lmpl_type == RLMPL_PID) {
				npids++;
			} else if (cur->lmpl_type == RLMPL_OWNER) {
				nowners++;
			} else {
				cmn_err(CE_PANIC,
				    "nrli: unrecognized lmpl_type %d",
				    cur->lmpl_type);
			}
		}

		cmn_err(CE_CONT,
		"nrli(%s): %d PIDs + %d OWNs = %d items left on r_lmpl\n",
		    (type == RLMPL_PID) ? "P" : "O",
		    npids,
		    nowners,
		    nitems);
	}
#endif

	mutex_exit(&rp->r_statelock);
	return (rv);
}

void
nfs_free_mi(mntinfo_t *mi)
{
	ASSERT(mi->mi_flags & MI_ASYNC_MGR_STOP);
	ASSERT(mi->mi_manager_thread == NULL);
	ASSERT(mi->mi_threads[NFS_ASYNC_QUEUE] == 0 &&
	    mi->mi_threads[NFS_ASYNC_PGOPS_QUEUE] == 0);

	/*
	 * Remove the node from the global list before we start tearing it down.
	 */
	nfs_mi_zonelist_remove(mi);
	if (mi->mi_klmconfig) {
		lm_free_config(mi->mi_klmconfig);
		kmem_free(mi->mi_klmconfig, sizeof (struct knetconfig));
	}
	mutex_destroy(&mi->mi_lock);
	mutex_destroy(&mi->mi_remap_lock);
	mutex_destroy(&mi->mi_async_lock);
	mutex_destroy(&mi->mi_rnodes_lock);
	cv_destroy(&mi->mi_failover_cv);
	cv_destroy(&mi->mi_async_work_cv[NFS_ASYNC_QUEUE]);
	cv_destroy(&mi->mi_async_work_cv[NFS_ASYNC_PGOPS_QUEUE]);
	cv_destroy(&mi->mi_async_reqs_cv);
	cv_destroy(&mi->mi_async_cv);
	list_destroy(&mi->mi_rnodes);
	zone_rele_ref(&mi->mi_zone_ref, ZONE_REF_NFS);
	kmem_free(mi, sizeof (*mi));
}

static int
mnt_kstat_update(kstat_t *ksp, int rw)
{
	mntinfo_t *mi;
	struct mntinfo_kstat *mik;
	vfs_t *vfsp;
	int i;

	/* this is a read-only kstat. Bail out on a write */
	if (rw == KSTAT_WRITE)
		return (EACCES);

	/*
	 * We don't want to wait here as kstat_chain_lock could be held by
	 * dounmount(). dounmount() takes vfs_reflock before the chain lock
	 * and thus could lead to a deadlock.
	 */
	vfsp = (struct vfs *)ksp->ks_private;


	mi = VFTOMI(vfsp);

	mik = (struct mntinfo_kstat *)ksp->ks_data;

	(void) strcpy(mik->mik_proto, mi->mi_curr_serv->sv_knconf->knc_proto);
	mik->mik_vers = (uint32_t)mi->mi_vers;
	mik->mik_flags = mi->mi_flags;
	mik->mik_secmod = mi->mi_curr_serv->sv_secdata->secmod;
	mik->mik_curread = (uint32_t)mi->mi_curread;
	mik->mik_curwrite = (uint32_t)mi->mi_curwrite;
	mik->mik_retrans = mi->mi_retrans;
	mik->mik_timeo = mi->mi_timeo;
	mik->mik_acregmin = HR2SEC(mi->mi_acregmin);
	mik->mik_acregmax = HR2SEC(mi->mi_acregmax);
	mik->mik_acdirmin = HR2SEC(mi->mi_acdirmin);
	mik->mik_acdirmax = HR2SEC(mi->mi_acdirmax);
	for (i = 0; i < NFS_CALLTYPES + 1; i++) {
		mik->mik_timers[i].srtt = (uint32_t)mi->mi_timers[i].rt_srtt;
		mik->mik_timers[i].deviate =
		    (uint32_t)mi->mi_timers[i].rt_deviate;
		mik->mik_timers[i].rtxcur =
		    (uint32_t)mi->mi_timers[i].rt_rtxcur;
	}
	mik->mik_noresponse = (uint32_t)mi->mi_noresponse;
	mik->mik_failover = (uint32_t)mi->mi_failover;
	mik->mik_remap = (uint32_t)mi->mi_remap;
	(void) strcpy(mik->mik_curserver, mi->mi_curr_serv->sv_hostname);

	return (0);
}

void
nfs_mnt_kstat_init(struct vfs *vfsp)
{
	mntinfo_t *mi = VFTOMI(vfsp);

	/*
	 * Create the version specific kstats.
	 *
	 * PSARC 2001/697 Contract Private Interface
	 * All nfs kstats are under SunMC contract
	 * Please refer to the PSARC listed above and contact
	 * SunMC before making any changes!
	 *
	 * Changes must be reviewed by Solaris File Sharing
	 * Changes must be communicated to contract-2001-697@sun.com
	 *
	 */

	mi->mi_io_kstats = kstat_create_zone("nfs", getminor(vfsp->vfs_dev),
	    NULL, "nfs", KSTAT_TYPE_IO, 1, 0, mi->mi_zone->zone_id);
	if (mi->mi_io_kstats) {
		if (mi->mi_zone->zone_id != GLOBAL_ZONEID)
			kstat_zone_add(mi->mi_io_kstats, GLOBAL_ZONEID);
		mi->mi_io_kstats->ks_lock = &mi->mi_lock;
		kstat_install(mi->mi_io_kstats);
	}

	if ((mi->mi_ro_kstats = kstat_create_zone("nfs",
	    getminor(vfsp->vfs_dev), "mntinfo", "misc", KSTAT_TYPE_RAW,
	    sizeof (struct mntinfo_kstat), 0, mi->mi_zone->zone_id)) != NULL) {
		if (mi->mi_zone->zone_id != GLOBAL_ZONEID)
			kstat_zone_add(mi->mi_ro_kstats, GLOBAL_ZONEID);
		mi->mi_ro_kstats->ks_update = mnt_kstat_update;
		mi->mi_ro_kstats->ks_private = (void *)vfsp;
		kstat_install(mi->mi_ro_kstats);
	}
}

nfs_delmapcall_t *
nfs_init_delmapcall()
{
	nfs_delmapcall_t	*delmap_call;

	delmap_call = kmem_alloc(sizeof (nfs_delmapcall_t), KM_SLEEP);
	delmap_call->call_id = curthread;
	delmap_call->error = 0;

	return (delmap_call);
}

void
nfs_free_delmapcall(nfs_delmapcall_t *delmap_call)
{
	kmem_free(delmap_call, sizeof (nfs_delmapcall_t));
}

/*
 * Searches for the current delmap caller (based on curthread) in the list of
 * callers.  If it is found, we remove it and free the delmap caller.
 * Returns:
 *	0 if the caller wasn't found
 *	1 if the caller was found, removed and freed.  *errp is set to what
 * 	the result of the delmap was.
 */
int
nfs_find_and_delete_delmapcall(rnode_t *rp, int *errp)
{
	nfs_delmapcall_t	*delmap_call;

	/*
	 * If the list doesn't exist yet, we create it and return
	 * that the caller wasn't found.  No list = no callers.
	 */
	mutex_enter(&rp->r_statelock);
	if (!(rp->r_flags & RDELMAPLIST)) {
		/* The list does not exist */
		list_create(&rp->r_indelmap, sizeof (nfs_delmapcall_t),
		    offsetof(nfs_delmapcall_t, call_node));
		rp->r_flags |= RDELMAPLIST;
		mutex_exit(&rp->r_statelock);
		return (0);
	} else {
		/* The list exists so search it */
		for (delmap_call = list_head(&rp->r_indelmap);
		    delmap_call != NULL;
		    delmap_call = list_next(&rp->r_indelmap, delmap_call)) {
			if (delmap_call->call_id == curthread) {
				/* current caller is in the list */
				*errp = delmap_call->error;
				list_remove(&rp->r_indelmap, delmap_call);
				mutex_exit(&rp->r_statelock);
				nfs_free_delmapcall(delmap_call);
				return (1);
			}
		}
	}
	mutex_exit(&rp->r_statelock);
	return (0);
}
