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
 */

/*
 *  	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All Rights Reserved
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
#include <sys/disp.h>
#include <sys/atomic.h>
#include <sys/list.h>
#include <sys/sdt.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs_acl.h>

#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>

#include <sys/ddi.h>

/*
 * Arguments to page-flush thread.
 */
typedef struct {
	vnode_t *vp;
	cred_t *cr;
} pgflush_t;

#ifdef DEBUG
int nfs4_client_lease_debug;
int nfs4_sharedfh_debug;
int nfs4_fname_debug;

/* temporary: panic if v_type is inconsistent with r_attr va_type */
int nfs4_vtype_debug;

uint_t nfs4_tsd_key;
#endif

static time_t	nfs4_client_resumed = 0;
static	callb_id_t cid = 0;

static int	nfs4renew(nfs4_server_t *);
static void	nfs4_attrcache_va(vnode_t *, nfs4_ga_res_t *, int);
static void	nfs4_pgflush_thread(pgflush_t *);

static boolean_t nfs4_client_cpr_callb(void *, int);

struct mi4_globals {
	kmutex_t	mig_lock;  /* lock protecting mig_list */
	list_t		mig_list;  /* list of NFS v4 mounts in zone */
	boolean_t	mig_destructor_called;
};

static zone_key_t mi4_list_key;

/*
 * Attributes caching:
 *
 * Attributes are cached in the rnode in struct vattr form.
 * There is a time associated with the cached attributes (r_time_attr_inval)
 * which tells whether the attributes are valid. The time is initialized
 * to the difference between current time and the modify time of the vnode
 * when new attributes are cached. This allows the attributes for
 * files that have changed recently to be timed out sooner than for files
 * that have not changed for a long time. There are minimum and maximum
 * timeout values that can be set per mount point.
 */

/*
 * If a cache purge is in progress, wait for it to finish.
 *
 * The current thread must not be in the middle of an
 * nfs4_start_op/nfs4_end_op region.  Otherwise, there could be a deadlock
 * between this thread, a recovery thread, and the page flush thread.
 */
int
nfs4_waitfor_purge_complete(vnode_t *vp)
{
	rnode4_t *rp;
	k_sigset_t smask;

	rp = VTOR4(vp);
	if ((rp->r_serial != NULL && rp->r_serial != curthread) ||
	    ((rp->r_flags & R4PGFLUSH) && rp->r_pgflush != curthread)) {
		mutex_enter(&rp->r_statelock);
		sigintr(&smask, VTOMI4(vp)->mi_flags & MI4_INT);
		while ((rp->r_serial != NULL && rp->r_serial != curthread) ||
		    ((rp->r_flags & R4PGFLUSH) &&
		    rp->r_pgflush != curthread)) {
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
 * Validate caches by checking cached attributes. If they have timed out,
 * then get new attributes from the server.  As a side effect, cache
 * invalidation is done if the attributes have changed.
 *
 * If the attributes have not timed out and if there is a cache
 * invalidation being done by some other thread, then wait until that
 * thread has completed the cache invalidation.
 */
int
nfs4_validate_caches(vnode_t *vp, cred_t *cr)
{
	int error;
	nfs4_ga_res_t gar;

	if (ATTRCACHE4_VALID(vp)) {
		error = nfs4_waitfor_purge_complete(vp);
		if (error)
			return (error);
		return (0);
	}

	gar.n4g_va.va_mask = AT_ALL;
	return (nfs4_getattr_otw(vp, &gar, cr, 0));
}

/*
 * Fill in attribute from the cache.
 * If valid, then return 0 to indicate that no error occurred,
 * otherwise return 1 to indicate that an error occurred.
 */
static int
nfs4_getattr_cache(vnode_t *vp, struct vattr *vap)
{
	rnode4_t *rp;

	rp = VTOR4(vp);
	mutex_enter(&rp->r_statelock);
	mutex_enter(&rp->r_statev4_lock);
	if (ATTRCACHE4_VALID(vp)) {
		mutex_exit(&rp->r_statev4_lock);
		/*
		 * Cached attributes are valid
		 */
		*vap = rp->r_attr;
		mutex_exit(&rp->r_statelock);
		return (0);
	}
	mutex_exit(&rp->r_statev4_lock);
	mutex_exit(&rp->r_statelock);
	return (1);
}


/*
 * If returned error is ESTALE flush all caches.  The nfs4_purge_caches()
 * call is synchronous because all the pages were invalidated by the
 * nfs4_invalidate_pages() call.
 */
void
nfs4_purge_stale_fh(int errno, vnode_t *vp, cred_t *cr)
{
	struct rnode4 *rp = VTOR4(vp);

	/* Ensure that the ..._end_op() call has been done */
	ASSERT(tsd_get(nfs4_tsd_key) == NULL);

	if (errno != ESTALE)
		return;

	mutex_enter(&rp->r_statelock);
	rp->r_flags |= R4STALE;
	if (!rp->r_error)
		rp->r_error = errno;
	mutex_exit(&rp->r_statelock);
	if (nfs4_has_pages(vp))
		nfs4_invalidate_pages(vp, (u_offset_t)0, cr);
	nfs4_purge_caches(vp, NFS4_PURGE_DNLC, cr, FALSE);
}

/*
 * Purge all of the various NFS `data' caches.  If "asyncpg" is TRUE, the
 * page purge is done asynchronously.
 */
void
nfs4_purge_caches(vnode_t *vp, int purge_dnlc, cred_t *cr, int asyncpg)
{
	rnode4_t *rp;
	char *contents;
	vnode_t *xattr;
	int size;
	int pgflush;			/* are we the page flush thread? */

	/*
	 * Purge the DNLC for any entries which refer to this file.
	 */
	if (vp->v_count > 1 &&
	    (vp->v_type == VDIR || purge_dnlc == NFS4_PURGE_DNLC))
		dnlc_purge_vp(vp);

	/*
	 * Clear any readdir state bits and purge the readlink response cache.
	 */
	rp = VTOR4(vp);
	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~R4LOOKUP;
	contents = rp->r_symlink.contents;
	size = rp->r_symlink.size;
	rp->r_symlink.contents = NULL;

	xattr = rp->r_xattr_dir;
	rp->r_xattr_dir = NULL;

	/*
	 * Purge pathconf cache too.
	 */
	rp->r_pathconf.pc4_xattr_valid = 0;
	rp->r_pathconf.pc4_cache_valid = 0;

	pgflush = (curthread == rp->r_pgflush);
	mutex_exit(&rp->r_statelock);

	if (contents != NULL) {

		kmem_free((void *)contents, size);
	}

	if (xattr != NULL)
		VN_RELE(xattr);

	/*
	 * Flush the page cache.  If the current thread is the page flush
	 * thread, don't initiate a new page flush.  There's no need for
	 * it, and doing it correctly is hard.
	 */
	if (nfs4_has_pages(vp) && !pgflush) {
		if (!asyncpg) {
			(void) nfs4_waitfor_purge_complete(vp);
			nfs4_flush_pages(vp, cr);
		} else {
			pgflush_t *args;

			/*
			 * We don't hold r_statelock while creating the
			 * thread, in case the call blocks.  So we use a
			 * flag to indicate that a page flush thread is
			 * active.
			 */
			mutex_enter(&rp->r_statelock);
			if (rp->r_flags & R4PGFLUSH) {
				mutex_exit(&rp->r_statelock);
			} else {
				rp->r_flags |= R4PGFLUSH;
				mutex_exit(&rp->r_statelock);

				args = kmem_alloc(sizeof (pgflush_t),
				    KM_SLEEP);
				args->vp = vp;
				VN_HOLD(args->vp);
				args->cr = cr;
				crhold(args->cr);
				(void) zthread_create(NULL, 0,
				    nfs4_pgflush_thread, args, 0,
				    minclsyspri);
			}
		}
	}

	/*
	 * Flush the readdir response cache.
	 */
	nfs4_purge_rddir_cache(vp);
}

/*
 * Invalidate all pages for the given file, after writing back the dirty
 * ones.
 */

void
nfs4_flush_pages(vnode_t *vp, cred_t *cr)
{
	int error;
	rnode4_t *rp = VTOR4(vp);

	error = VOP_PUTPAGE(vp, (u_offset_t)0, 0, B_INVAL, cr, NULL);
	if (error == ENOSPC || error == EDQUOT) {
		mutex_enter(&rp->r_statelock);
		if (!rp->r_error)
			rp->r_error = error;
		mutex_exit(&rp->r_statelock);
	}
}

/*
 * Page flush thread.
 */

static void
nfs4_pgflush_thread(pgflush_t *args)
{
	rnode4_t *rp = VTOR4(args->vp);

	/* remember which thread we are, so we don't deadlock ourselves */
	mutex_enter(&rp->r_statelock);
	ASSERT(rp->r_pgflush == NULL);
	rp->r_pgflush = curthread;
	mutex_exit(&rp->r_statelock);

	nfs4_flush_pages(args->vp, args->cr);

	mutex_enter(&rp->r_statelock);
	rp->r_pgflush = NULL;
	rp->r_flags &= ~R4PGFLUSH;
	cv_broadcast(&rp->r_cv);
	mutex_exit(&rp->r_statelock);

	VN_RELE(args->vp);
	crfree(args->cr);
	kmem_free(args, sizeof (pgflush_t));
	zthread_exit();
}

/*
 * Purge the readdir cache of all entries which are not currently
 * being filled.
 */
void
nfs4_purge_rddir_cache(vnode_t *vp)
{
	rnode4_t *rp;

	rp = VTOR4(vp);

	mutex_enter(&rp->r_statelock);
	rp->r_direof = NULL;
	rp->r_flags &= ~R4LOOKUP;
	rp->r_flags |= R4READDIRWATTR;
	rddir4_cache_purge(rp);
	mutex_exit(&rp->r_statelock);
}

/*
 * Set attributes cache for given vnode using virtual attributes.  There is
 * no cache validation, but if the attributes are deemed to be stale, they
 * are ignored.  This corresponds to nfs3_attrcache().
 *
 * Set the timeout value on the attribute cache and fill it
 * with the passed in attributes.
 */
void
nfs4_attrcache_noinval(vnode_t *vp, nfs4_ga_res_t *garp, hrtime_t t)
{
	rnode4_t *rp = VTOR4(vp);

	mutex_enter(&rp->r_statelock);
	if (rp->r_time_attr_saved <= t)
		nfs4_attrcache_va(vp, garp, FALSE);
	mutex_exit(&rp->r_statelock);
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
nfs4_attr_cache(vnode_t *vp, nfs4_ga_res_t *garp,
    hrtime_t t, cred_t *cr, int async,
    change_info4 *cinfo)
{
	rnode4_t *rp;
	int mtime_changed = 0;
	int ctime_changed = 0;
	vsecattr_t *vsp;
	int was_serial, set_time_cache_inval, recov;
	vattr_t *vap = &garp->n4g_va;
	mntinfo4_t *mi = VTOMI4(vp);
	len_t preattr_rsize;
	boolean_t writemodify_set = B_FALSE;
	boolean_t cachepurge_set = B_FALSE;

	ASSERT(mi->mi_vfsp->vfs_dev == garp->n4g_va.va_fsid);

	/* Is curthread the recovery thread? */
	mutex_enter(&mi->mi_lock);
	recov = (VTOMI4(vp)->mi_recovthread == curthread);
	mutex_exit(&mi->mi_lock);

	rp = VTOR4(vp);
	mutex_enter(&rp->r_statelock);
	was_serial = (rp->r_serial == curthread);
	if (rp->r_serial && !was_serial) {
		klwp_t *lwp = ttolwp(curthread);

		/*
		 * If we're the recovery thread, then purge current attrs
		 * and bail out to avoid potential deadlock between another
		 * thread caching attrs (r_serial thread), recov thread,
		 * and an async writer thread.
		 */
		if (recov) {
			PURGE_ATTRCACHE4_LOCKED(rp);
			mutex_exit(&rp->r_statelock);
			return;
		}

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
	}

	/*
	 * If there is a page flush thread, the current thread needs to
	 * bail out, to prevent a possible deadlock between the current
	 * thread (which might be in a start_op/end_op region), the
	 * recovery thread, and the page flush thread.  Expire the
	 * attribute cache, so that any attributes the current thread was
	 * going to set are not lost.
	 */
	if ((rp->r_flags & R4PGFLUSH) && rp->r_pgflush != curthread) {
		PURGE_ATTRCACHE4_LOCKED(rp);
		mutex_exit(&rp->r_statelock);
		return;
	}

	if (rp->r_time_attr_saved > t) {
		/*
		 * Attributes have been cached since these attributes were
		 * probably made. If there is an inconsistency in what is
		 * cached, mark them invalid. If not, don't act on them.
		 */
		if (!CACHE4_VALID(rp, vap->va_mtime, vap->va_size))
			PURGE_ATTRCACHE4_LOCKED(rp);
		mutex_exit(&rp->r_statelock);
		return;
	}
	set_time_cache_inval = 0;
	if (cinfo) {
		/*
		 * Only directory modifying callers pass non-NULL cinfo.
		 */
		ASSERT(vp->v_type == VDIR);
		/*
		 * If the cache timeout either doesn't exist or hasn't expired,
		 * and dir didn't changed on server before dirmod op
		 * and dir didn't change after dirmod op but before getattr
		 * then there's a chance that the client's cached data for
		 * this object is current (not stale).  No immediate cache
		 * flush is required.
		 *
		 */
		if ((! rp->r_time_cache_inval || t < rp->r_time_cache_inval) &&
		    cinfo->before == rp->r_change &&
		    (garp->n4g_change_valid &&
		    cinfo->after == garp->n4g_change)) {

			/*
			 * If atomic isn't set, then the before/after info
			 * cannot be blindly trusted.  For this case, we tell
			 * nfs4_attrcache_va to cache the attrs but also
			 * establish an absolute maximum cache timeout.  When
			 * the timeout is reached, caches will be flushed.
			 */
			if (! cinfo->atomic)
				set_time_cache_inval = 1;
		} else {

			/*
			 * We're not sure exactly what changed, but we know
			 * what to do.  flush all caches for dir.  remove the
			 * attr timeout.
			 *
			 * a) timeout expired.  flush all caches.
			 * b) r_change != cinfo.before.  flush all caches.
			 * c) r_change == cinfo.before, but cinfo.after !=
			 *    post-op getattr(change).  flush all caches.
			 * d) post-op getattr(change) not provided by server.
			 *    flush all caches.
			 */
			mtime_changed = 1;
			ctime_changed = 1;
			rp->r_time_cache_inval = 0;
		}
	} else {
		/*
		 * Write thread after writing data to file on remote server,
		 * will always set R4WRITEMODIFIED to indicate that file on
		 * remote server was modified with a WRITE operation and would
		 * have marked attribute cache as timed out. If R4WRITEMODIFIED
		 * is set, then do not check for mtime and ctime change.
		 */
		if (!(rp->r_flags & R4WRITEMODIFIED)) {
			if (!CACHE4_VALID(rp, vap->va_mtime, vap->va_size))
				mtime_changed = 1;

			if (rp->r_attr.va_ctime.tv_sec !=
			    vap->va_ctime.tv_sec ||
			    rp->r_attr.va_ctime.tv_nsec !=
			    vap->va_ctime.tv_nsec)
				ctime_changed = 1;
		} else {
			writemodify_set = B_TRUE;
		}
	}

	preattr_rsize = rp->r_size;

	nfs4_attrcache_va(vp, garp, set_time_cache_inval);

	/*
	 * If we have updated filesize in nfs4_attrcache_va, as soon as we
	 * drop statelock we will be in transition of purging all
	 * our caches and updating them. It is possible for another
	 * thread to pick this new file size and read in zeroed data.
	 * stall other threads till cache purge is complete.
	 */
	if ((!cinfo) && (rp->r_size != preattr_rsize)) {
		/*
		 * If R4WRITEMODIFIED was set and we have updated the file
		 * size, Server's returned file size need not necessarily
		 * be because of this Client's WRITE. We need to purge
		 * all caches.
		 */
		if (writemodify_set)
			mtime_changed = 1;

		if (mtime_changed && !(rp->r_flags & R4INCACHEPURGE)) {
			rp->r_flags |= R4INCACHEPURGE;
			cachepurge_set = B_TRUE;
		}
	}

	if (!mtime_changed && !ctime_changed) {
		mutex_exit(&rp->r_statelock);
		return;
	}

	rp->r_serial = curthread;

	mutex_exit(&rp->r_statelock);

	/*
	 * If we're the recov thread, then force async nfs4_purge_caches
	 * to avoid potential deadlock.
	 */
	if (mtime_changed)
		nfs4_purge_caches(vp, NFS4_NOPURGE_DNLC, cr, recov ? 1 : async);

	if ((rp->r_flags & R4INCACHEPURGE) && cachepurge_set) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags &= ~R4INCACHEPURGE;
		cv_broadcast(&rp->r_cv);
		mutex_exit(&rp->r_statelock);
		cachepurge_set = B_FALSE;
	}

	if (ctime_changed) {
		(void) nfs4_access_purge_rp(rp);
		if (rp->r_secattr != NULL) {
			mutex_enter(&rp->r_statelock);
			vsp = rp->r_secattr;
			rp->r_secattr = NULL;
			mutex_exit(&rp->r_statelock);
			if (vsp != NULL)
				nfs4_acl_free_cache(vsp);
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
static void
nfs4_attrcache_va(vnode_t *vp, nfs4_ga_res_t *garp, int set_cache_timeout)
{
	rnode4_t *rp;
	mntinfo4_t *mi;
	hrtime_t delta;
	hrtime_t now;
	vattr_t *vap = &garp->n4g_va;

	rp = VTOR4(vp);

	ASSERT(MUTEX_HELD(&rp->r_statelock));
	ASSERT(vap->va_mask == AT_ALL);

	/* Switch to master before checking v_flag */
	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);

	now = gethrtime();

	mi = VTOMI4(vp);

	/*
	 * Only establish a new cache timeout (if requested).  Never
	 * extend a timeout.  Never clear a timeout.  Clearing a timeout
	 * is done by nfs4_update_dircaches (ancestor in our call chain)
	 */
	if (set_cache_timeout && ! rp->r_time_cache_inval)
		rp->r_time_cache_inval = now + mi->mi_acdirmax;

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
	if (vap->va_mtime.tv_sec != rp->r_attr.va_mtime.tv_sec ||
	    vap->va_mtime.tv_nsec != rp->r_attr.va_mtime.tv_nsec ||
	    vap->va_size != rp->r_attr.va_size) {
		rp->r_time_attr_saved = now;
	}

	if ((mi->mi_flags & MI4_NOAC) || (vp->v_flag & VNOCACHE))
		delta = 0;
	else {
		delta = now - rp->r_time_attr_saved;
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
	rp->r_time_attr_inval = now + delta;

	rp->r_attr = *vap;
	if (garp->n4g_change_valid)
		rp->r_change = garp->n4g_change;

	/*
	 * The attributes that were returned may be valid and can
	 * be used, but they may not be allowed to be cached.
	 * Reset the timers to cause immediate invalidation and
	 * clear r_change so no VERIFY operations will suceed
	 */
	if (garp->n4g_attrwhy == NFS4_GETATTR_NOCACHE_OK) {
		rp->r_time_attr_inval = now;
		rp->r_time_attr_saved = now;
		rp->r_change = 0;
	}

	/*
	 * If mounted_on_fileid returned AND the object is a stub,
	 * then set object's va_nodeid to the mounted over fid
	 * returned by server.
	 *
	 * If mounted_on_fileid not provided/supported, then
	 * just set it to 0 for now.  Eventually it would be
	 * better to set it to a hashed version of FH.  This
	 * would probably be good enough to provide a unique
	 * fid/d_ino within a dir.
	 *
	 * We don't need to carry mounted_on_fileid in the
	 * rnode as long as the client never requests fileid
	 * without also requesting mounted_on_fileid.  For
	 * now, it stays.
	 */
	if (garp->n4g_mon_fid_valid) {
		rp->r_mntd_fid = garp->n4g_mon_fid;

		if (RP_ISSTUB(rp))
			rp->r_attr.va_nodeid = rp->r_mntd_fid;
	}

	/*
	 * Check to see if there are valid pathconf bits to
	 * cache in the rnode.
	 */
	if (garp->n4g_ext_res) {
		if (garp->n4g_ext_res->n4g_pc4.pc4_cache_valid) {
			rp->r_pathconf = garp->n4g_ext_res->n4g_pc4;
		} else {
			if (garp->n4g_ext_res->n4g_pc4.pc4_xattr_valid) {
				rp->r_pathconf.pc4_xattr_valid = TRUE;
				rp->r_pathconf.pc4_xattr_exists =
				    garp->n4g_ext_res->n4g_pc4.pc4_xattr_exists;
			}
		}
	}
	/*
	 * Update the size of the file if there is no cached data or if
	 * the cached data is clean and there is no data being written
	 * out.
	 */
	if (rp->r_size != vap->va_size &&
	    (!vn_has_cached_data(vp) ||
	    (!(rp->r_flags & R4DIRTY) && rp->r_count == 0))) {
		rp->r_size = vap->va_size;
	}
	nfs_setswaplike(vp, vap);
	rp->r_flags &= ~R4WRITEMODIFIED;
}

/*
 * Get attributes over-the-wire and update attributes cache
 * if no error occurred in the over-the-wire operation.
 * Return 0 if successful, otherwise error.
 */
int
nfs4_getattr_otw(vnode_t *vp, nfs4_ga_res_t *garp, cred_t *cr, int get_acl)
{
	mntinfo4_t *mi = VTOMI4(vp);
	hrtime_t t;
	nfs4_recov_state_t recov_state;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	/* Save the original mount point security flavor */
	(void) save_mnt_secinfo(mi->mi_curr_serv);

recov_retry:

	if ((e.error = nfs4_start_fop(mi, vp, NULL, OH_GETATTR,
	    &recov_state, NULL))) {
		(void) check_mnt_secinfo(mi->mi_curr_serv, vp);
		return (e.error);
	}

	t = gethrtime();

	nfs4_getattr_otw_norecovery(vp, garp, &e, cr, get_acl);

	if (nfs4_needs_recovery(&e, FALSE, vp->v_vfsp)) {
		if (nfs4_start_recovery(&e, VTOMI4(vp), vp, NULL, NULL,
		    NULL, OP_GETATTR, NULL, NULL, NULL) == FALSE)  {
			nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_GETATTR,
			    &recov_state, 1);
			goto recov_retry;
		}
	}

	nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_GETATTR, &recov_state, 0);

	if (!e.error) {
		if (e.stat == NFS4_OK) {
			nfs4_attr_cache(vp, garp, t, cr, FALSE, NULL);
		} else {
			e.error = geterrno4(e.stat);

			nfs4_purge_stale_fh(e.error, vp, cr);
		}
	}

	/*
	 * If getattr a node that is a stub for a crossed
	 * mount point, keep the original secinfo flavor for
	 * the current file system, not the crossed one.
	 */
	(void) check_mnt_secinfo(mi->mi_curr_serv, vp);

	return (e.error);
}

/*
 * Generate a compound to get attributes over-the-wire.
 */
void
nfs4_getattr_otw_norecovery(vnode_t *vp, nfs4_ga_res_t *garp,
    nfs4_error_t *ep, cred_t *cr, int get_acl)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	int doqueue;
	rnode4_t *rp = VTOR4(vp);
	nfs_argop4 argop[2];

	args.ctag = TAG_GETATTR;

	args.array_len = 2;
	args.array = argop;

	/* putfh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	/* getattr */
	/*
	 * Unlike nfs version 2 and 3, where getattr returns all the
	 * attributes, nfs version 4 returns only the ones explicitly
	 * asked for. This creates problems, as some system functions
	 * (e.g. cache check) require certain attributes and if the
	 * cached node lacks some attributes such as uid/gid, it can
	 * affect system utilities (e.g. "ls") that rely on the information
	 * to be there. This can lead to anything from system crashes to
	 * corrupted information processed by user apps.
	 * So to ensure that all bases are covered, request at least
	 * the AT_ALL attribute mask.
	 */
	argop[1].argop = OP_GETATTR;
	argop[1].nfs_argop4_u.opgetattr.attr_request = NFS4_VATTR_MASK;
	if (get_acl)
		argop[1].nfs_argop4_u.opgetattr.attr_request |= FATTR4_ACL_MASK;
	argop[1].nfs_argop4_u.opgetattr.mi = VTOMI4(vp);

	doqueue = 1;

	rfs4call(VTOMI4(vp), &args, &res, cr, &doqueue, 0, ep);

	if (ep->error)
		return;

	if (res.status != NFS4_OK) {
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return;
	}

	*garp = res.array[1].nfs_resop4_u.opgetattr.ga_res;

	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
}

/*
 * Return either cached or remote attributes. If get remote attr
 * use them to check and invalidate caches, then cache the new attributes.
 */
int
nfs4getattr(vnode_t *vp, vattr_t *vap, cred_t *cr)
{
	int error;
	rnode4_t *rp;
	nfs4_ga_res_t gar;

	ASSERT(nfs4_consistent_type(vp));

	/*
	 * If we've got cached attributes, we're done, otherwise go
	 * to the server to get attributes, which will update the cache
	 * in the process. Either way, use the cached attributes for
	 * the caller's vattr_t.
	 *
	 * Note that we ignore the gar set by the OTW call: the attr caching
	 * code may make adjustments when storing to the rnode, and we want
	 * to see those changes here.
	 */
	rp = VTOR4(vp);
	error = 0;
	mutex_enter(&rp->r_statelock);
	if (!ATTRCACHE4_VALID(vp)) {
		mutex_exit(&rp->r_statelock);
		error = nfs4_getattr_otw(vp, &gar, cr, 0);
		mutex_enter(&rp->r_statelock);
	}

	if (!error)
		*vap = rp->r_attr;

	/* Return the client's view of file size */
	vap->va_size = rp->r_size;

	mutex_exit(&rp->r_statelock);

	ASSERT(nfs4_consistent_type(vp));

	return (error);
}

int
nfs4_attr_otw(vnode_t *vp, nfs4_tag_type_t tag_type,
    nfs4_ga_res_t *garp, bitmap4 reqbitmap, cred_t *cr)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	int doqueue;
	nfs_argop4 argop[2];
	mntinfo4_t *mi = VTOMI4(vp);
	bool_t needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	nfs4_ga_ext_res_t *gerp;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	args.ctag = tag_type;

	args.array_len = 2;
	args.array = argop;

	e.error = nfs4_start_fop(mi, vp, NULL, OH_GETATTR, &recov_state, NULL);
	if (e.error)
		return (e.error);

	/* putfh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(vp)->r_fh;

	/* getattr */
	argop[1].argop = OP_GETATTR;
	argop[1].nfs_argop4_u.opgetattr.attr_request = reqbitmap;
	argop[1].nfs_argop4_u.opgetattr.mi = mi;

	doqueue = 1;

	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "nfs4_attr_otw: %s call, rp %s", needrecov ? "recov" : "first",
	    rnode4info(VTOR4(vp))));

	rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, vp->v_vfsp);
	if (!needrecov && e.error) {
		nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_GETATTR, &recov_state,
		    needrecov);
		return (e.error);
	}

	if (needrecov) {
		bool_t abort;

		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4_attr_otw: initiating recovery\n"));

		abort = nfs4_start_recovery(&e, VTOMI4(vp), vp, NULL, NULL,
		    NULL, OP_GETATTR, NULL, NULL, NULL);
		nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_GETATTR, &recov_state,
		    needrecov);
		if (!e.error) {
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			e.error = geterrno4(res.status);
		}
		if (abort == FALSE)
			goto recov_retry;
		return (e.error);
	}

	if (res.status) {
		e.error = geterrno4(res.status);
	} else {
		gerp = garp->n4g_ext_res;
		bcopy(&res.array[1].nfs_resop4_u.opgetattr.ga_res,
		    garp, sizeof (nfs4_ga_res_t));
		garp->n4g_ext_res = gerp;
		if (garp->n4g_ext_res &&
		    res.array[1].nfs_resop4_u.opgetattr.ga_res.n4g_ext_res)
			bcopy(res.array[1].nfs_resop4_u.opgetattr.
			    ga_res.n4g_ext_res,
			    garp->n4g_ext_res, sizeof (nfs4_ga_ext_res_t));
	}
	(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	nfs4_end_fop(VTOMI4(vp), vp, NULL, OH_GETATTR, &recov_state,
	    needrecov);
	return (e.error);
}

/*
 * Asynchronous I/O parameters.  nfs_async_threads is the high-water mark
 * for the demand-based allocation of async threads per-mount.  The
 * nfs_async_timeout is the amount of time a thread will live after it
 * becomes idle, unless new I/O requests are received before the thread
 * dies.  See nfs4_async_putpage and nfs4_async_start.
 */

static void	nfs4_async_start(struct vfs *);
static void	nfs4_async_pgops_start(struct vfs *);
static void	nfs4_async_common_start(struct vfs *, int);

static void
free_async_args4(struct nfs4_async_reqs *args)
{
	rnode4_t *rp;

	if (args->a_io != NFS4_INACTIVE) {
		rp = VTOR4(args->a_vp);
		mutex_enter(&rp->r_statelock);
		rp->r_count--;
		if (args->a_io == NFS4_PUTAPAGE ||
		    args->a_io == NFS4_PAGEIO)
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
nfs4_async_manager(vfs_t *vfsp)
{
	callb_cpr_t cprinfo;
	mntinfo4_t *mi;
	uint_t max_threads;

	mi = VFTOMI4(vfsp);

	CALLB_CPR_INIT(&cprinfo, &mi->mi_async_lock, callb_generic_cpr,
	    "nfs4_async_manager");

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
	 * exit when the mount is really going away.
	 *
	 * Once MI4_ASYNC_MGR_STOP is set, no more async operations will be
	 * attempted: the various _async_*() functions know to do things
	 * inline if mi_max_threads == 0.  Henceforth we just drain out the
	 * outstanding requests.
	 *
	 * Note that we still create zthreads even if we notice the zone is
	 * shutting down (MI4_ASYNC_MGR_STOP is set); this may cause the zone
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
			 * (debugger-induced) alterations of
			 * mi->mi_max_threads are ignored for our
			 * purposes, but who told them they could change
			 * random values on a live kernel anyhow?
			 */
			if (mi->mi_threads[NFS4_ASYNC_QUEUE] <
			    MAX(mi->mi_max_threads, max_threads)) {
				mi->mi_threads[NFS4_ASYNC_QUEUE]++;
				mutex_exit(&mi->mi_async_lock);
				MI4_HOLD(mi);
				VFS_HOLD(vfsp);	/* hold for new thread */
				(void) zthread_create(NULL, 0, nfs4_async_start,
				    vfsp, 0, minclsyspri);
				mutex_enter(&mi->mi_async_lock);
			} else if (mi->mi_threads[NFS4_ASYNC_PGOPS_QUEUE] <
			    NUM_ASYNC_PGOPS_THREADS) {
				mi->mi_threads[NFS4_ASYNC_PGOPS_QUEUE]++;
				mutex_exit(&mi->mi_async_lock);
				MI4_HOLD(mi);
				VFS_HOLD(vfsp); /* hold for new thread */
				(void) zthread_create(NULL, 0,
				    nfs4_async_pgops_start, vfsp, 0,
				    minclsyspri);
				mutex_enter(&mi->mi_async_lock);
			}
			NFS4_WAKE_ASYNC_WORKER(mi->mi_async_work_cv);
			ASSERT(mi->mi_async_req_count != 0);
			mi->mi_async_req_count--;
		}

		mutex_enter(&mi->mi_lock);
		if (mi->mi_flags & MI4_ASYNC_MGR_STOP) {
			mutex_exit(&mi->mi_lock);
			break;
		}
		mutex_exit(&mi->mi_lock);

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&mi->mi_async_reqs_cv, &mi->mi_async_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &mi->mi_async_lock);
	}

	NFS4_DEBUG(nfs4_client_zone_debug, (CE_NOTE,
	    "nfs4_async_manager exiting for vfs %p\n", (void *)mi->mi_vfsp));
	/*
	 * Let everyone know we're done.
	 */
	mi->mi_manager_thread = NULL;
	/*
	 * Wake up the inactive thread.
	 */
	cv_broadcast(&mi->mi_inact_req_cv);
	/*
	 * Wake up anyone sitting in nfs4_async_manager_stop()
	 */
	cv_broadcast(&mi->mi_async_cv);
	/*
	 * There is no explicit call to mutex_exit(&mi->mi_async_lock)
	 * since CALLB_CPR_EXIT is actually responsible for releasing
	 * 'mi_async_lock'.
	 */
	CALLB_CPR_EXIT(&cprinfo);
	VFS_RELE(vfsp);	/* release thread's hold */
	MI4_RELE(mi);
	zthread_exit();
}

/*
 * Signal (and wait for) the async manager thread to clean up and go away.
 */
void
nfs4_async_manager_stop(vfs_t *vfsp)
{
	mntinfo4_t *mi = VFTOMI4(vfsp);

	mutex_enter(&mi->mi_async_lock);
	mutex_enter(&mi->mi_lock);
	mi->mi_flags |= MI4_ASYNC_MGR_STOP;
	mutex_exit(&mi->mi_lock);
	cv_broadcast(&mi->mi_async_reqs_cv);
	/*
	 * Wait for the async manager thread to die.
	 */
	while (mi->mi_manager_thread != NULL)
		cv_wait(&mi->mi_async_cv, &mi->mi_async_lock);
	mutex_exit(&mi->mi_async_lock);
}

int
nfs4_async_readahead(vnode_t *vp, u_offset_t blkoff, caddr_t addr,
    struct seg *seg, cred_t *cr, void (*readahead)(vnode_t *,
    u_offset_t, caddr_t, struct seg *, cred_t *))
{
	rnode4_t *rp;
	mntinfo4_t *mi;
	struct nfs4_async_reqs *args;

	rp = VTOR4(vp);
	ASSERT(rp->r_freef == NULL);

	mi = VTOMI4(vp);

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
	args->a_io = NFS4_READ_AHEAD;
	args->a_nfs4_readahead = readahead;
	args->a_nfs4_blkoff = blkoff;
	args->a_nfs4_seg = seg;
	args->a_nfs4_addr = addr;

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
	if (mi->mi_async_reqs[NFS4_READ_AHEAD] == NULL) {
		mi->mi_async_reqs[NFS4_READ_AHEAD] = args;
		mi->mi_async_tail[NFS4_READ_AHEAD] = args;
	} else {
		mi->mi_async_tail[NFS4_READ_AHEAD]->a_next = args;
		mi->mi_async_tail[NFS4_READ_AHEAD] = args;
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

static void
nfs4_async_start(struct vfs *vfsp)
{
	nfs4_async_common_start(vfsp, NFS4_ASYNC_QUEUE);
}

static void
nfs4_async_pgops_start(struct vfs *vfsp)
{
	nfs4_async_common_start(vfsp, NFS4_ASYNC_PGOPS_QUEUE);
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
 * XXX The nfs4_async_common_start thread is unsafe in the light of the present
 * model defined by cpr to suspend the system. Specifically over the
 * wire calls are cpr-unsafe. The thread should be reevaluated in
 * case of future updates to the cpr model.
 */
static void
nfs4_async_common_start(struct vfs *vfsp, int async_queue)
{
	struct nfs4_async_reqs *args;
	mntinfo4_t *mi = VFTOMI4(vfsp);
	clock_t time_left = 1;
	callb_cpr_t cprinfo;
	int i;
	extern int nfs_async_timeout;
	int async_types;
	kcondvar_t *async_work_cv;

	if (async_queue == NFS4_ASYNC_QUEUE) {
		async_types = NFS4_ASYNC_TYPES;
		async_work_cv = &mi->mi_async_work_cv[NFS4_ASYNC_QUEUE];
	} else {
		async_types = NFS4_ASYNC_PGOPS_TYPES;
		async_work_cv = &mi->mi_async_work_cv[NFS4_ASYNC_PGOPS_QUEUE];
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

				if (mi->mi_threads[NFS4_ASYNC_QUEUE] == 0 &&
				    mi->mi_threads[NFS4_ASYNC_PGOPS_QUEUE] == 0)
					cv_signal(&mi->mi_async_cv);
				CALLB_CPR_EXIT(&cprinfo);
				VFS_RELE(vfsp);	/* release thread's hold */
				MI4_RELE(mi);
				zthread_exit();
				/* NOTREACHED */
			}
			time_left = cv_reltimedwait(async_work_cv,
			    &mi->mi_async_lock, nfs_async_timeout,
			    TR_CLOCK_TICK);

			CALLB_CPR_SAFE_END(&cprinfo, &mi->mi_async_lock);

			continue;
		} else {
			time_left = 1;
		}

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

		if (args->a_io != NFS4_INACTIVE && mi->mi_io_kstats) {
			mutex_enter(&mi->mi_lock);
			kstat_waitq_exit(KSTAT_IO_PTR(mi->mi_io_kstats));
			mutex_exit(&mi->mi_lock);
		}

		mutex_exit(&mi->mi_async_lock);

		/*
		 * Obtain arguments from the async request structure.
		 */
		if (args->a_io == NFS4_READ_AHEAD && mi->mi_max_threads > 0) {
			(*args->a_nfs4_readahead)(args->a_vp,
			    args->a_nfs4_blkoff, args->a_nfs4_addr,
			    args->a_nfs4_seg, args->a_cred);
		} else if (args->a_io == NFS4_PUTAPAGE) {
			(void) (*args->a_nfs4_putapage)(args->a_vp,
			    args->a_nfs4_pp, args->a_nfs4_off,
			    args->a_nfs4_len, args->a_nfs4_flags,
			    args->a_cred);
		} else if (args->a_io == NFS4_PAGEIO) {
			(void) (*args->a_nfs4_pageio)(args->a_vp,
			    args->a_nfs4_pp, args->a_nfs4_off,
			    args->a_nfs4_len, args->a_nfs4_flags,
			    args->a_cred);
		} else if (args->a_io == NFS4_READDIR) {
			(void) ((*args->a_nfs4_readdir)(args->a_vp,
			    args->a_nfs4_rdc, args->a_cred));
		} else if (args->a_io == NFS4_COMMIT) {
			(*args->a_nfs4_commit)(args->a_vp, args->a_nfs4_plist,
			    args->a_nfs4_offset, args->a_nfs4_count,
			    args->a_cred);
		} else if (args->a_io == NFS4_INACTIVE) {
			nfs4_inactive_otw(args->a_vp, args->a_cred);
		}

		/*
		 * Now, release the vnode and free the credentials
		 * structure.
		 */
		free_async_args4(args);
		/*
		 * Reacquire the mutex because it will be needed above.
		 */
		mutex_enter(&mi->mi_async_lock);
	}
}

/*
 * nfs4_inactive_thread - look for vnodes that need over-the-wire calls as
 * part of VOP_INACTIVE.
 */

void
nfs4_inactive_thread(mntinfo4_t *mi)
{
	struct nfs4_async_reqs *args;
	callb_cpr_t cprinfo;
	vfs_t *vfsp = mi->mi_vfsp;

	CALLB_CPR_INIT(&cprinfo, &mi->mi_async_lock, callb_generic_cpr,
	    "nfs4_inactive_thread");

	for (;;) {
		mutex_enter(&mi->mi_async_lock);
		args = mi->mi_async_reqs[NFS4_INACTIVE];
		if (args == NULL) {
			mutex_enter(&mi->mi_lock);
			/*
			 * We don't want to exit until the async manager is done
			 * with its work; hence the check for mi_manager_thread
			 * being NULL.
			 *
			 * The async manager thread will cv_broadcast() on
			 * mi_inact_req_cv when it's done, at which point we'll
			 * wake up and exit.
			 */
			if (mi->mi_manager_thread == NULL)
				goto die;
			mi->mi_flags |= MI4_INACTIVE_IDLE;
			mutex_exit(&mi->mi_lock);
			cv_signal(&mi->mi_async_cv);
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&mi->mi_inact_req_cv, &mi->mi_async_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &mi->mi_async_lock);
			mutex_exit(&mi->mi_async_lock);
		} else {
			mutex_enter(&mi->mi_lock);
			mi->mi_flags &= ~MI4_INACTIVE_IDLE;
			mutex_exit(&mi->mi_lock);
			mi->mi_async_reqs[NFS4_INACTIVE] = args->a_next;
			mutex_exit(&mi->mi_async_lock);
			nfs4_inactive_otw(args->a_vp, args->a_cred);
			crfree(args->a_cred);
			kmem_free(args, sizeof (*args));
		}
	}
die:
	mutex_exit(&mi->mi_lock);
	mi->mi_inactive_thread = NULL;
	cv_signal(&mi->mi_async_cv);

	/*
	 * There is no explicit call to mutex_exit(&mi->mi_async_lock) since
	 * CALLB_CPR_EXIT is actually responsible for releasing 'mi_async_lock'.
	 */
	CALLB_CPR_EXIT(&cprinfo);

	NFS4_DEBUG(nfs4_client_zone_debug, (CE_NOTE,
	    "nfs4_inactive_thread exiting for vfs %p\n", (void *)vfsp));

	MI4_RELE(mi);
	zthread_exit();
	/* NOTREACHED */
}

/*
 * nfs_async_stop:
 * Wait for all outstanding putpage operations and the inactive thread to
 * complete; nfs4_async_stop_sig() without interruptibility.
 */
void
nfs4_async_stop(struct vfs *vfsp)
{
	mntinfo4_t *mi = VFTOMI4(vfsp);

	/*
	 * Wait for all outstanding async operations to complete and for
	 * worker threads to exit.
	 */
	mutex_enter(&mi->mi_async_lock);
	mi->mi_max_threads = 0;
	NFS4_WAKEALL_ASYNC_WORKERS(mi->mi_async_work_cv);
	while (mi->mi_threads[NFS4_ASYNC_QUEUE] != 0 ||
	    mi->mi_threads[NFS4_ASYNC_PGOPS_QUEUE] != 0)
		cv_wait(&mi->mi_async_cv, &mi->mi_async_lock);

	/*
	 * Wait for the inactive thread to finish doing what it's doing.  It
	 * won't exit until the last reference to the vfs_t goes away.
	 */
	if (mi->mi_inactive_thread != NULL) {
		mutex_enter(&mi->mi_lock);
		while (!(mi->mi_flags & MI4_INACTIVE_IDLE) ||
		    (mi->mi_async_reqs[NFS4_INACTIVE] != NULL)) {
			mutex_exit(&mi->mi_lock);
			cv_wait(&mi->mi_async_cv, &mi->mi_async_lock);
			mutex_enter(&mi->mi_lock);
		}
		mutex_exit(&mi->mi_lock);
	}
	mutex_exit(&mi->mi_async_lock);
}

/*
 * nfs_async_stop_sig:
 * Wait for all outstanding putpage operations and the inactive thread to
 * complete. If a signal is delivered we will abort and return non-zero;
 * otherwise return 0. Since this routine is called from nfs4_unmount, we
 * need to make it interruptible.
 */
int
nfs4_async_stop_sig(struct vfs *vfsp)
{
	mntinfo4_t *mi = VFTOMI4(vfsp);
	ushort_t omax;
	bool_t intr = FALSE;

	/*
	 * Wait for all outstanding putpage operations to complete and for
	 * worker threads to exit.
	 */
	mutex_enter(&mi->mi_async_lock);
	omax = mi->mi_max_threads;
	mi->mi_max_threads = 0;
	NFS4_WAKEALL_ASYNC_WORKERS(mi->mi_async_work_cv);
	while (mi->mi_threads[NFS4_ASYNC_QUEUE] != 0 ||
	    mi->mi_threads[NFS4_ASYNC_PGOPS_QUEUE] != 0) {
		if (!cv_wait_sig(&mi->mi_async_cv, &mi->mi_async_lock)) {
			intr = TRUE;
			goto interrupted;
		}
	}

	/*
	 * Wait for the inactive thread to finish doing what it's doing.  It
	 * won't exit until the a last reference to the vfs_t goes away.
	 */
	if (mi->mi_inactive_thread != NULL) {
		mutex_enter(&mi->mi_lock);
		while (!(mi->mi_flags & MI4_INACTIVE_IDLE) ||
		    (mi->mi_async_reqs[NFS4_INACTIVE] != NULL)) {
			mutex_exit(&mi->mi_lock);
			if (!cv_wait_sig(&mi->mi_async_cv,
			    &mi->mi_async_lock)) {
				intr = TRUE;
				goto interrupted;
			}
			mutex_enter(&mi->mi_lock);
		}
		mutex_exit(&mi->mi_lock);
	}
interrupted:
	if (intr)
		mi->mi_max_threads = omax;
	mutex_exit(&mi->mi_async_lock);

	return (intr);
}

int
nfs4_async_putapage(vnode_t *vp, page_t *pp, u_offset_t off, size_t len,
    int flags, cred_t *cr, int (*putapage)(vnode_t *, page_t *,
    u_offset_t, size_t, int, cred_t *))
{
	rnode4_t *rp;
	mntinfo4_t *mi;
	struct nfs4_async_reqs *args;

	ASSERT(flags & B_ASYNC);
	ASSERT(vp->v_vfsp != NULL);

	rp = VTOR4(vp);
	ASSERT(rp->r_count > 0);

	mi = VTOMI4(vp);

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
	args->a_io = NFS4_PUTAPAGE;
	args->a_nfs4_putapage = putapage;
	args->a_nfs4_pp = pp;
	args->a_nfs4_off = off;
	args->a_nfs4_len = (uint_t)len;
	args->a_nfs4_flags = flags;

	mutex_enter(&mi->mi_async_lock);

	/*
	 * If asyncio has been disabled, then make a synchronous request.
	 * This check is done a second time in case async io was diabled
	 * while this thread was blocked waiting for memory pressure to
	 * reduce or for the queue to drain.
	 */
	if (mi->mi_max_threads == 0) {
		mutex_exit(&mi->mi_async_lock);

		VN_RELE(vp);
		crfree(cr);
		kmem_free(args, sizeof (*args));
		goto noasync;
	}

	/*
	 * Link request structure into the async list and
	 * wakeup async thread to do the i/o.
	 */
	if (mi->mi_async_reqs[NFS4_PUTAPAGE] == NULL) {
		mi->mi_async_reqs[NFS4_PUTAPAGE] = args;
		mi->mi_async_tail[NFS4_PUTAPAGE] = args;
	} else {
		mi->mi_async_tail[NFS4_PUTAPAGE]->a_next = args;
		mi->mi_async_tail[NFS4_PUTAPAGE] = args;
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

	if (curproc == proc_pageout || curproc == proc_fsflush) {
		/*
		 * If we get here in the context of the pageout/fsflush,
		 * or we have run out of memory or we're attempting to
		 * unmount we refuse to do a sync write, because this may
		 * hang pageout/fsflush and the machine. In this case,
		 * we just re-mark the page as dirty and punt on the page.
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
		 * So this was a cross-zone sync putpage.
		 *
		 * We pass in B_ERROR to pvn_write_done() to re-mark the pages
		 * as dirty and unlock them.
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
nfs4_async_pageio(vnode_t *vp, page_t *pp, u_offset_t io_off, size_t io_len,
    int flags, cred_t *cr, int (*pageio)(vnode_t *, page_t *, u_offset_t,
    size_t, int, cred_t *))
{
	rnode4_t *rp;
	mntinfo4_t *mi;
	struct nfs4_async_reqs *args;

	ASSERT(flags & B_ASYNC);
	ASSERT(vp->v_vfsp != NULL);

	rp = VTOR4(vp);
	ASSERT(rp->r_count > 0);

	mi = VTOMI4(vp);

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
	args->a_io = NFS4_PAGEIO;
	args->a_nfs4_pageio = pageio;
	args->a_nfs4_pp = pp;
	args->a_nfs4_off = io_off;
	args->a_nfs4_len = (uint_t)io_len;
	args->a_nfs4_flags = flags;

	mutex_enter(&mi->mi_async_lock);

	/*
	 * If asyncio has been disabled, then make a synchronous request.
	 * This check is done a second time in case async io was diabled
	 * while this thread was blocked waiting for memory pressure to
	 * reduce or for the queue to drain.
	 */
	if (mi->mi_max_threads == 0) {
		mutex_exit(&mi->mi_async_lock);

		VN_RELE(vp);
		crfree(cr);
		kmem_free(args, sizeof (*args));
		goto noasync;
	}

	/*
	 * Link request structure into the async list and
	 * wakeup async thread to do the i/o.
	 */
	if (mi->mi_async_reqs[NFS4_PAGEIO] == NULL) {
		mi->mi_async_reqs[NFS4_PAGEIO] = args;
		mi->mi_async_tail[NFS4_PAGEIO] = args;
	} else {
		mi->mi_async_tail[NFS4_PAGEIO]->a_next = args;
		mi->mi_async_tail[NFS4_PAGEIO] = args;
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
nfs4_async_readdir(vnode_t *vp, rddir4_cache *rdc, cred_t *cr,
    int (*readdir)(vnode_t *, rddir4_cache *, cred_t *))
{
	rnode4_t *rp;
	mntinfo4_t *mi;
	struct nfs4_async_reqs *args;

	rp = VTOR4(vp);
	ASSERT(rp->r_freef == NULL);

	mi = VTOMI4(vp);

	/*
	 * If we can't allocate a request structure, skip the readdir.
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
	args->a_io = NFS4_READDIR;
	args->a_nfs4_readdir = readdir;
	args->a_nfs4_rdc = rdc;

	mutex_enter(&mi->mi_async_lock);

	/*
	 * If asyncio has been disabled, then skip this request
	 */
	if (mi->mi_max_threads == 0) {
		mutex_exit(&mi->mi_async_lock);

		VN_RELE(vp);
		crfree(cr);
		kmem_free(args, sizeof (*args));
		goto noasync;
	}

	/*
	 * Link request structure into the async list and
	 * wakeup async thread to do the i/o.
	 */
	if (mi->mi_async_reqs[NFS4_READDIR] == NULL) {
		mi->mi_async_reqs[NFS4_READDIR] = args;
		mi->mi_async_tail[NFS4_READDIR] = args;
	} else {
		mi->mi_async_tail[NFS4_READDIR]->a_next = args;
		mi->mi_async_tail[NFS4_READDIR] = args;
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
	mutex_enter(&rp->r_statelock);
	rdc->entries = NULL;
	/*
	 * Indicate that no one is trying to fill this entry and
	 * it still needs to be filled.
	 */
	rdc->flags &= ~RDDIR;
	rdc->flags |= RDDIRREQ;
	rddir4_cache_rele(rp, rdc);
	mutex_exit(&rp->r_statelock);
}

void
nfs4_async_commit(vnode_t *vp, page_t *plist, offset3 offset, count3 count,
    cred_t *cr, void (*commit)(vnode_t *, page_t *, offset3, count3,
    cred_t *))
{
	rnode4_t *rp;
	mntinfo4_t *mi;
	struct nfs4_async_reqs *args;
	page_t *pp;

	rp = VTOR4(vp);
	mi = VTOMI4(vp);

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
	args->a_io = NFS4_COMMIT;
	args->a_nfs4_commit = commit;
	args->a_nfs4_plist = plist;
	args->a_nfs4_offset = offset;
	args->a_nfs4_count = count;

	mutex_enter(&mi->mi_async_lock);

	/*
	 * If asyncio has been disabled, then make a synchronous request.
	 * This check is done a second time in case async io was diabled
	 * while this thread was blocked waiting for memory pressure to
	 * reduce or for the queue to drain.
	 */
	if (mi->mi_max_threads == 0) {
		mutex_exit(&mi->mi_async_lock);

		VN_RELE(vp);
		crfree(cr);
		kmem_free(args, sizeof (*args));
		goto noasync;
	}

	/*
	 * Link request structure into the async list and
	 * wakeup async thread to do the i/o.
	 */
	if (mi->mi_async_reqs[NFS4_COMMIT] == NULL) {
		mi->mi_async_reqs[NFS4_COMMIT] = args;
		mi->mi_async_tail[NFS4_COMMIT] = args;
	} else {
		mi->mi_async_tail[NFS4_COMMIT]->a_next = args;
		mi->mi_async_tail[NFS4_COMMIT] = args;
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

/*
 * nfs4_async_inactive - hand off a VOP_INACTIVE call to a thread.  The
 * reference to the vnode is handed over to the thread; the caller should
 * no longer refer to the vnode.
 *
 * Unlike most of the async routines, this handoff is needed for
 * correctness reasons, not just performance.  So doing operations in the
 * context of the current thread is not an option.
 */
void
nfs4_async_inactive(vnode_t *vp, cred_t *cr)
{
	mntinfo4_t *mi;
	struct nfs4_async_reqs *args;
	boolean_t signal_inactive_thread = B_FALSE;

	mi = VTOMI4(vp);

	args = kmem_alloc(sizeof (*args), KM_SLEEP);
	args->a_next = NULL;
#ifdef DEBUG
	args->a_queuer = curthread;
#endif
	args->a_vp = vp;
	ASSERT(cr != NULL);
	crhold(cr);
	args->a_cred = cr;
	args->a_io = NFS4_INACTIVE;

	/*
	 * Note that we don't check mi->mi_max_threads here, since we
	 * *need* to get rid of this vnode regardless of whether someone
	 * set nfs4_max_threads to zero in /etc/system.
	 *
	 * The manager thread knows about this and is willing to create
	 * at least one thread to accommodate us.
	 */
	mutex_enter(&mi->mi_async_lock);
	if (mi->mi_inactive_thread == NULL) {
		rnode4_t *rp;
		vnode_t *unldvp = NULL;
		char *unlname;
		cred_t *unlcred;

		mutex_exit(&mi->mi_async_lock);
		/*
		 * We just need to free up the memory associated with the
		 * vnode, which can be safely done from within the current
		 * context.
		 */
		crfree(cr);	/* drop our reference */
		kmem_free(args, sizeof (*args));
		rp = VTOR4(vp);
		mutex_enter(&rp->r_statelock);
		if (rp->r_unldvp != NULL) {
			unldvp = rp->r_unldvp;
			rp->r_unldvp = NULL;
			unlname = rp->r_unlname;
			rp->r_unlname = NULL;
			unlcred = rp->r_unlcred;
			rp->r_unlcred = NULL;
		}
		mutex_exit(&rp->r_statelock);
		/*
		 * No need to explicitly throw away any cached pages.  The
		 * eventual r4inactive() will attempt a synchronous
		 * VOP_PUTPAGE() which will immediately fail since the request
		 * is coming from the wrong zone, and then will proceed to call
		 * nfs4_invalidate_pages() which will clean things up for us.
		 *
		 * Throw away the delegation here so rp4_addfree()'s attempt to
		 * return any existing delegations becomes a no-op.
		 */
		if (rp->r_deleg_type != OPEN_DELEGATE_NONE) {
			(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER,
			    FALSE);
			(void) nfs4delegreturn(rp, NFS4_DR_DISCARD);
			nfs_rw_exit(&mi->mi_recovlock);
		}
		nfs4_clear_open_streams(rp);

		rp4_addfree(rp, cr);
		if (unldvp != NULL) {
			kmem_free(unlname, MAXNAMELEN);
			VN_RELE(unldvp);
			crfree(unlcred);
		}
		return;
	}

	if (mi->mi_manager_thread == NULL) {
		/*
		 * We want to talk to the inactive thread.
		 */
		signal_inactive_thread = B_TRUE;
	}

	/*
	 * Enqueue the vnode and wake up either the special thread (empty
	 * list) or an async thread.
	 */
	if (mi->mi_async_reqs[NFS4_INACTIVE] == NULL) {
		mi->mi_async_reqs[NFS4_INACTIVE] = args;
		mi->mi_async_tail[NFS4_INACTIVE] = args;
		signal_inactive_thread = B_TRUE;
	} else {
		mi->mi_async_tail[NFS4_INACTIVE]->a_next = args;
		mi->mi_async_tail[NFS4_INACTIVE] = args;
	}
	if (signal_inactive_thread) {
		cv_signal(&mi->mi_inact_req_cv);
	} else  {
		mi->mi_async_req_count++;
		ASSERT(mi->mi_async_req_count != 0);
		cv_signal(&mi->mi_async_reqs_cv);
	}

	mutex_exit(&mi->mi_async_lock);
}

int
writerp4(rnode4_t *rp, caddr_t base, int tcount, struct uio *uio, int pgcreated)
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
		ASSERT(!(rp->r_flags & R4MODINPROGRESS));
		mutex_enter(&rp->r_statelock);
		rp->r_flags |= R4MODINPROGRESS;
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
		rp->r_flags &= ~R4MODINPROGRESS;
		rp->r_flags |= R4DIRTY;
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
nfs4_putpages(vnode_t *vp, u_offset_t off, size_t len, int flags, cred_t *cr)
{
	rnode4_t *rp;
	page_t *pp;
	u_offset_t eoff;
	u_offset_t io_off;
	size_t io_len;
	int error;
	int rdirty;
	int err;

	rp = VTOR4(vp);
	ASSERT(rp->r_count > 0);

	if (!nfs4_has_pages(vp))
		return (0);

	ASSERT(vp->v_type != VCHR);

	/*
	 * If R4OUTOFSPACE is set, then all writes turn into B_INVAL
	 * writes.  B_FORCE is set to force the VM system to actually
	 * invalidate the pages, even if the i/o failed.  The pages
	 * need to get invalidated because they can't be written out
	 * because there isn't any space left on either the server's
	 * file system or in the user's disk quota.  The B_FREE bit
	 * is cleared to avoid confusion as to whether this is a
	 * request to place the page on the freelist or to destroy
	 * it.
	 */
	if ((rp->r_flags & R4OUTOFSPACE) ||
	    (vp->v_vfsp->vfs_flag & VFS_UNMOUNTED))
		flags = (flags & ~B_FREE) | B_INVAL | B_FORCE;

	if (len == 0) {
		/*
		 * If doing a full file synchronous operation, then clear
		 * the R4DIRTY bit.  If a page gets dirtied while the flush
		 * is happening, then R4DIRTY will get set again.  The
		 * R4DIRTY bit must get cleared before the flush so that
		 * we don't lose this information.
		 *
		 * If there are no full file async write operations
		 * pending and RDIRTY bit is set, clear it.
		 */
		if (off == (u_offset_t)0 &&
		    !(flags & B_ASYNC) &&
		    (rp->r_flags & R4DIRTY)) {
			mutex_enter(&rp->r_statelock);
			rdirty = (rp->r_flags & R4DIRTY);
			rp->r_flags &= ~R4DIRTY;
			mutex_exit(&rp->r_statelock);
		} else if (flags & B_ASYNC && off == (u_offset_t)0) {
			mutex_enter(&rp->r_statelock);
			if (rp->r_flags & R4DIRTY && rp->r_awcount == 0) {
				rdirty = (rp->r_flags & R4DIRTY);
				rp->r_flags &= ~R4DIRTY;
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
		 * reset the R4DIRTY flag.
		 */
		if (error && rdirty &&
		    (flags & (B_INVAL | B_FORCE)) != (B_INVAL | B_FORCE)) {
			mutex_enter(&rp->r_statelock);
			rp->r_flags |= R4DIRTY;
			mutex_exit(&rp->r_statelock);
		}
	} else {
		/*
		 * Do a range from [off...off + len) looking for pages
		 * to deal with.
		 */
		error = 0;
		io_len = 0;
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
nfs4_invalidate_pages(vnode_t *vp, u_offset_t off, cred_t *cr)
{
	rnode4_t *rp;

	rp = VTOR4(vp);
	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);
	mutex_enter(&rp->r_statelock);
	while (rp->r_flags & R4TRUNCATE)
		cv_wait(&rp->r_cv, &rp->r_statelock);
	rp->r_flags |= R4TRUNCATE;
	if (off == (u_offset_t)0) {
		rp->r_flags &= ~R4DIRTY;
		if (!(rp->r_flags & R4STALE))
			rp->r_error = 0;
	}
	rp->r_truncaddr = off;
	mutex_exit(&rp->r_statelock);
	(void) pvn_vplist_dirty(vp, off, rp->r_putapage,
	    B_INVAL | B_TRUNC, cr);
	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~R4TRUNCATE;
	cv_broadcast(&rp->r_cv);
	mutex_exit(&rp->r_statelock);
}

static int
nfs4_mnt_kstat_update(kstat_t *ksp, int rw)
{
	mntinfo4_t *mi;
	struct mntinfo_kstat *mik;
	vfs_t *vfsp;

	/* this is a read-only kstat. Bail out on a write */
	if (rw == KSTAT_WRITE)
		return (EACCES);


	/*
	 * We don't want to wait here as kstat_chain_lock could be held by
	 * dounmount(). dounmount() takes vfs_reflock before the chain lock
	 * and thus could lead to a deadlock.
	 */
	vfsp = (struct vfs *)ksp->ks_private;

	mi = VFTOMI4(vfsp);
	mik = (struct mntinfo_kstat *)ksp->ks_data;

	(void) strcpy(mik->mik_proto, mi->mi_curr_serv->sv_knconf->knc_proto);

	mik->mik_vers = (uint32_t)mi->mi_vers;
	mik->mik_flags = mi->mi_flags;
	/*
	 * The sv_secdata holds the flavor the client specifies.
	 * If the client uses default and a security negotiation
	 * occurs, sv_currsec will point to the current flavor
	 * selected from the server flavor list.
	 * sv_currsec is NULL if no security negotiation takes place.
	 */
	mik->mik_secmod = mi->mi_curr_serv->sv_currsec ?
	    mi->mi_curr_serv->sv_currsec->secmod :
	    mi->mi_curr_serv->sv_secdata->secmod;
	mik->mik_curread = (uint32_t)mi->mi_curread;
	mik->mik_curwrite = (uint32_t)mi->mi_curwrite;
	mik->mik_retrans = mi->mi_retrans;
	mik->mik_timeo = mi->mi_timeo;
	mik->mik_acregmin = HR2SEC(mi->mi_acregmin);
	mik->mik_acregmax = HR2SEC(mi->mi_acregmax);
	mik->mik_acdirmin = HR2SEC(mi->mi_acdirmin);
	mik->mik_acdirmax = HR2SEC(mi->mi_acdirmax);
	mik->mik_noresponse = (uint32_t)mi->mi_noresponse;
	mik->mik_failover = (uint32_t)mi->mi_failover;
	mik->mik_remap = (uint32_t)mi->mi_remap;

	(void) strcpy(mik->mik_curserver, mi->mi_curr_serv->sv_hostname);

	return (0);
}

void
nfs4_mnt_kstat_init(struct vfs *vfsp)
{
	mntinfo4_t *mi = VFTOMI4(vfsp);

	/*
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
		mi->mi_ro_kstats->ks_update = nfs4_mnt_kstat_update;
		mi->mi_ro_kstats->ks_private = (void *)vfsp;
		kstat_install(mi->mi_ro_kstats);
	}

	nfs4_mnt_recov_kstat_init(vfsp);
}

void
nfs4_write_error(vnode_t *vp, int error, cred_t *cr)
{
	mntinfo4_t *mi;
	clock_t now = ddi_get_lbolt();

	mi = VTOMI4(vp);
	/*
	 * In case of forced unmount, do not print any messages
	 * since it can flood the console with error messages.
	 */
	if (mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED)
		return;

	/*
	 * If the mount point is dead, not recoverable, do not
	 * print error messages that can flood the console.
	 */
	if (mi->mi_flags & MI4_RECOV_FAIL)
		return;

	/*
	 * No use in flooding the console with ENOSPC
	 * messages from the same file system.
	 */
	if ((error != ENOSPC && error != EDQUOT) ||
	    now - mi->mi_printftime > 0) {
		zoneid_t zoneid = mi->mi_zone->zone_id;

#ifdef DEBUG
		nfs_perror(error, "NFS%ld write error on host %s: %m.\n",
		    mi->mi_vers, VTOR4(vp)->r_server->sv_hostname, NULL);
#else
		nfs_perror(error, "NFS write error on host %s: %m.\n",
		    VTOR4(vp)->r_server->sv_hostname, NULL);
#endif
		if (error == ENOSPC || error == EDQUOT) {
			zcmn_err(zoneid, CE_CONT,
			    "^File: userid=%d, groupid=%d\n",
			    crgetuid(cr), crgetgid(cr));
			if (crgetuid(curthread->t_cred) != crgetuid(cr) ||
			    crgetgid(curthread->t_cred) != crgetgid(cr)) {
				zcmn_err(zoneid, CE_CONT,
				    "^User: userid=%d, groupid=%d\n",
				    crgetuid(curthread->t_cred),
				    crgetgid(curthread->t_cred));
			}
			mi->mi_printftime = now +
			    nfs_write_error_interval * hz;
		}
		sfh4_printfhandle(VTOR4(vp)->r_fh);
#ifdef DEBUG
		if (error == EACCES) {
			zcmn_err(zoneid, CE_CONT,
			    "nfs_bio: cred is%s kcred\n",
			    cr == kcred ? "" : " not");
		}
#endif
	}
}

/*
 * Return non-zero if the given file can be safely memory mapped.  Locks
 * are safe if whole-file (length and offset are both zero).
 */

#define	SAFE_LOCK(flk)	((flk).l_start == 0 && (flk).l_len == 0)

static int
nfs4_safemap(const vnode_t *vp)
{
	locklist_t	*llp, *next_llp;
	int		safe = 1;
	rnode4_t	*rp = VTOR4(vp);

	ASSERT(nfs_rw_lock_held(&rp->r_lkserlock, RW_WRITER));

	NFS4_DEBUG(nfs4_client_map_debug, (CE_NOTE, "nfs4_safemap: "
	    "vp = %p", (void *)vp));

	/*
	 * Review all the locks for the vnode, both ones that have been
	 * acquired and ones that are pending.  We assume that
	 * flk_active_locks_for_vp() has merged any locks that can be
	 * merged (so that if a process has the entire file locked, it is
	 * represented as a single lock).
	 *
	 * Note that we can't bail out of the loop if we find a non-safe
	 * lock, because we have to free all the elements in the llp list.
	 * We might be able to speed up this code slightly by not looking
	 * at each lock's l_start and l_len fields once we've found a
	 * non-safe lock.
	 */

	llp = flk_active_locks_for_vp(vp);
	while (llp) {
		NFS4_DEBUG(nfs4_client_map_debug, (CE_NOTE,
		    "nfs4_safemap: active lock (%" PRId64 ", %" PRId64 ")",
		    llp->ll_flock.l_start, llp->ll_flock.l_len));
		if (!SAFE_LOCK(llp->ll_flock)) {
			safe = 0;
			NFS4_DEBUG(nfs4_client_map_debug, (CE_NOTE,
			    "nfs4_safemap: unsafe active lock (%" PRId64
			    ", %" PRId64 ")", llp->ll_flock.l_start,
			    llp->ll_flock.l_len));
		}
		next_llp = llp->ll_next;
		VN_RELE(llp->ll_vp);
		kmem_free(llp, sizeof (*llp));
		llp = next_llp;
	}

	NFS4_DEBUG(nfs4_client_map_debug, (CE_NOTE, "nfs4_safemap: %s",
	    safe ? "safe" : "unsafe"));
	return (safe);
}

/*
 * Return whether there is a lost LOCK or LOCKU queued up for the given
 * file that would make an mmap request unsafe.  cf. nfs4_safemap().
 */

bool_t
nfs4_map_lost_lock_conflict(vnode_t *vp)
{
	bool_t conflict = FALSE;
	nfs4_lost_rqst_t *lrp;
	mntinfo4_t *mi = VTOMI4(vp);

	mutex_enter(&mi->mi_lock);
	for (lrp = list_head(&mi->mi_lost_state); lrp != NULL;
	    lrp = list_next(&mi->mi_lost_state, lrp)) {
		if (lrp->lr_op != OP_LOCK && lrp->lr_op != OP_LOCKU)
			continue;
		ASSERT(lrp->lr_vp != NULL);
		if (!VOP_CMP(lrp->lr_vp, vp, NULL))
			continue;	/* different file */
		if (!SAFE_LOCK(*lrp->lr_flk)) {
			conflict = TRUE;
			break;
		}
	}

	mutex_exit(&mi->mi_lock);
	return (conflict);
}

/*
 * nfs_lockcompletion:
 *
 * If the vnode has a lock that makes it unsafe to cache the file, mark it
 * as non cachable (set VNOCACHE bit).
 */

void
nfs4_lockcompletion(vnode_t *vp, int cmd)
{
	rnode4_t *rp = VTOR4(vp);

	ASSERT(nfs_rw_lock_held(&rp->r_lkserlock, RW_WRITER));
	ASSERT(!IS_SHADOW(vp, rp));

	if (cmd == F_SETLK || cmd == F_SETLKW) {

		if (!nfs4_safemap(vp)) {
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
	PURGE_ATTRCACHE4(vp);
}

/* ARGSUSED */
static void *
nfs4_mi_init(zoneid_t zoneid)
{
	struct mi4_globals *mig;

	mig = kmem_alloc(sizeof (*mig), KM_SLEEP);
	mutex_init(&mig->mig_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&mig->mig_list, sizeof (mntinfo4_t),
	    offsetof(mntinfo4_t, mi_zone_node));
	mig->mig_destructor_called = B_FALSE;
	return (mig);
}

/*
 * Callback routine to tell all NFSv4 mounts in the zone to start tearing down
 * state and killing off threads.
 */
/* ARGSUSED */
static void
nfs4_mi_shutdown(zoneid_t zoneid, void *data)
{
	struct mi4_globals *mig = data;
	mntinfo4_t *mi;
	nfs4_server_t *np;

	NFS4_DEBUG(nfs4_client_zone_debug, (CE_NOTE,
	    "nfs4_mi_shutdown zone %d\n", zoneid));
	ASSERT(mig != NULL);
	for (;;) {
		mutex_enter(&mig->mig_lock);
		mi = list_head(&mig->mig_list);
		if (mi == NULL) {
			mutex_exit(&mig->mig_lock);
			break;
		}

		NFS4_DEBUG(nfs4_client_zone_debug, (CE_NOTE,
		    "nfs4_mi_shutdown stopping vfs %p\n", (void *)mi->mi_vfsp));
		/*
		 * purge the DNLC for this filesystem
		 */
		(void) dnlc_purge_vfsp(mi->mi_vfsp, 0);
		/*
		 * Tell existing async worker threads to exit.
		 */
		mutex_enter(&mi->mi_async_lock);
		mi->mi_max_threads = 0;
		NFS4_WAKEALL_ASYNC_WORKERS(mi->mi_async_work_cv);
		/*
		 * Set the appropriate flags, signal and wait for both the
		 * async manager and the inactive thread to exit when they're
		 * done with their current work.
		 */
		mutex_enter(&mi->mi_lock);
		mi->mi_flags |= (MI4_ASYNC_MGR_STOP|MI4_DEAD);
		mutex_exit(&mi->mi_lock);
		mutex_exit(&mi->mi_async_lock);
		if (mi->mi_manager_thread) {
			nfs4_async_manager_stop(mi->mi_vfsp);
		}
		if (mi->mi_inactive_thread) {
			mutex_enter(&mi->mi_async_lock);
			cv_signal(&mi->mi_inact_req_cv);
			/*
			 * Wait for the inactive thread to exit.
			 */
			while (mi->mi_inactive_thread != NULL) {
				cv_wait(&mi->mi_async_cv, &mi->mi_async_lock);
			}
			mutex_exit(&mi->mi_async_lock);
		}
		/*
		 * Wait for the recovery thread to complete, that is, it will
		 * signal when it is done using the "mi" structure and about
		 * to exit
		 */
		mutex_enter(&mi->mi_lock);
		while (mi->mi_in_recovery > 0)
			cv_wait(&mi->mi_cv_in_recov, &mi->mi_lock);
		mutex_exit(&mi->mi_lock);
		/*
		 * We're done when every mi has been done or the list is empty.
		 * This one is done, remove it from the list.
		 */
		list_remove(&mig->mig_list, mi);
		mutex_exit(&mig->mig_lock);
		zone_rele_ref(&mi->mi_zone_ref, ZONE_REF_NFSV4);

		/*
		 * Release hold on vfs and mi done to prevent race with zone
		 * shutdown. This releases the hold in nfs4_mi_zonelist_add.
		 */
		VFS_RELE(mi->mi_vfsp);
		MI4_RELE(mi);
	}
	/*
	 * Tell each renew thread in the zone to exit
	 */
	mutex_enter(&nfs4_server_lst_lock);
	for (np = nfs4_server_lst.forw; np != &nfs4_server_lst; np = np->forw) {
		mutex_enter(&np->s_lock);
		if (np->zoneid == zoneid) {
			/*
			 * We add another hold onto the nfs4_server_t
			 * because this will make sure tha the nfs4_server_t
			 * stays around until nfs4_callback_fini_zone destroys
			 * the zone. This way, the renew thread can
			 * unconditionally release its holds on the
			 * nfs4_server_t.
			 */
			np->s_refcnt++;
			nfs4_mark_srv_dead(np);
		}
		mutex_exit(&np->s_lock);
	}
	mutex_exit(&nfs4_server_lst_lock);
}

static void
nfs4_mi_free_globals(struct mi4_globals *mig)
{
	list_destroy(&mig->mig_list);	/* makes sure the list is empty */
	mutex_destroy(&mig->mig_lock);
	kmem_free(mig, sizeof (*mig));
}

/* ARGSUSED */
static void
nfs4_mi_destroy(zoneid_t zoneid, void *data)
{
	struct mi4_globals *mig = data;

	NFS4_DEBUG(nfs4_client_zone_debug, (CE_NOTE,
	    "nfs4_mi_destroy zone %d\n", zoneid));
	ASSERT(mig != NULL);
	mutex_enter(&mig->mig_lock);
	if (list_head(&mig->mig_list) != NULL) {
		/* Still waiting for VFS_FREEVFS() */
		mig->mig_destructor_called = B_TRUE;
		mutex_exit(&mig->mig_lock);
		return;
	}
	nfs4_mi_free_globals(mig);
}

/*
 * Add an NFS mount to the per-zone list of NFS mounts.
 */
void
nfs4_mi_zonelist_add(mntinfo4_t *mi)
{
	struct mi4_globals *mig;

	mig = zone_getspecific(mi4_list_key, mi->mi_zone);
	mutex_enter(&mig->mig_lock);
	list_insert_head(&mig->mig_list, mi);
	/*
	 * hold added to eliminate race with zone shutdown -this will be
	 * released in mi_shutdown
	 */
	MI4_HOLD(mi);
	VFS_HOLD(mi->mi_vfsp);
	mutex_exit(&mig->mig_lock);
}

/*
 * Remove an NFS mount from the per-zone list of NFS mounts.
 */
int
nfs4_mi_zonelist_remove(mntinfo4_t *mi)
{
	struct mi4_globals *mig;
	int ret = 0;

	mig = zone_getspecific(mi4_list_key, mi->mi_zone);
	mutex_enter(&mig->mig_lock);
	mutex_enter(&mi->mi_lock);
	/* if this mi is marked dead, then the zone already released it */
	if (!(mi->mi_flags & MI4_DEAD)) {
		list_remove(&mig->mig_list, mi);
		mutex_exit(&mi->mi_lock);

		/* release the holds put on in zonelist_add(). */
		VFS_RELE(mi->mi_vfsp);
		MI4_RELE(mi);
		ret = 1;
	} else {
		mutex_exit(&mi->mi_lock);
	}

	/*
	 * We can be called asynchronously by VFS_FREEVFS() after the zone
	 * shutdown/destroy callbacks have executed; if so, clean up the zone's
	 * mi globals.
	 */
	if (list_head(&mig->mig_list) == NULL &&
	    mig->mig_destructor_called == B_TRUE) {
		nfs4_mi_free_globals(mig);
		return (ret);
	}
	mutex_exit(&mig->mig_lock);
	return (ret);
}

void
nfs_free_mi4(mntinfo4_t *mi)
{
	nfs4_open_owner_t	*foop;
	nfs4_oo_hash_bucket_t   *bucketp;
	nfs4_debug_msg_t	*msgp;
	int i;
	servinfo4_t 		*svp;

	/*
	 * Code introduced here should be carefully evaluated to make
	 * sure none of the freed resources are accessed either directly
	 * or indirectly after freeing them. For eg: Introducing calls to
	 * NFS4_DEBUG that use mntinfo4_t structure member after freeing
	 * the structure members or other routines calling back into NFS
	 * accessing freed mntinfo4_t structure member.
	 */
	mutex_enter(&mi->mi_lock);
	ASSERT(mi->mi_recovthread == NULL);
	ASSERT(mi->mi_flags & MI4_ASYNC_MGR_STOP);
	mutex_exit(&mi->mi_lock);
	mutex_enter(&mi->mi_async_lock);
	ASSERT(mi->mi_threads[NFS4_ASYNC_QUEUE] == 0 &&
	    mi->mi_threads[NFS4_ASYNC_PGOPS_QUEUE] == 0);
	ASSERT(mi->mi_manager_thread == NULL);
	mutex_exit(&mi->mi_async_lock);
	if (mi->mi_io_kstats) {
		kstat_delete(mi->mi_io_kstats);
		mi->mi_io_kstats = NULL;
	}
	if (mi->mi_ro_kstats) {
		kstat_delete(mi->mi_ro_kstats);
		mi->mi_ro_kstats = NULL;
	}
	if (mi->mi_recov_ksp) {
		kstat_delete(mi->mi_recov_ksp);
		mi->mi_recov_ksp = NULL;
	}
	mutex_enter(&mi->mi_msg_list_lock);
	while (msgp = list_head(&mi->mi_msg_list)) {
		list_remove(&mi->mi_msg_list, msgp);
		nfs4_free_msg(msgp);
	}
	mutex_exit(&mi->mi_msg_list_lock);
	list_destroy(&mi->mi_msg_list);
	if (mi->mi_fname != NULL)
		fn_rele(&mi->mi_fname);
	if (mi->mi_rootfh != NULL)
		sfh4_rele(&mi->mi_rootfh);
	if (mi->mi_srvparentfh != NULL)
		sfh4_rele(&mi->mi_srvparentfh);
	svp = mi->mi_servers;
	sv4_free(svp);
	mutex_destroy(&mi->mi_lock);
	mutex_destroy(&mi->mi_async_lock);
	mutex_destroy(&mi->mi_msg_list_lock);
	nfs_rw_destroy(&mi->mi_recovlock);
	nfs_rw_destroy(&mi->mi_rename_lock);
	nfs_rw_destroy(&mi->mi_fh_lock);
	cv_destroy(&mi->mi_failover_cv);
	cv_destroy(&mi->mi_async_reqs_cv);
	cv_destroy(&mi->mi_async_work_cv[NFS4_ASYNC_QUEUE]);
	cv_destroy(&mi->mi_async_work_cv[NFS4_ASYNC_PGOPS_QUEUE]);
	cv_destroy(&mi->mi_async_cv);
	cv_destroy(&mi->mi_inact_req_cv);
	/*
	 * Destroy the oo hash lists and mutexes for the cred hash table.
	 */
	for (i = 0; i < NFS4_NUM_OO_BUCKETS; i++) {
		bucketp = &(mi->mi_oo_list[i]);
		/* Destroy any remaining open owners on the list */
		foop = list_head(&bucketp->b_oo_hash_list);
		while (foop != NULL) {
			list_remove(&bucketp->b_oo_hash_list, foop);
			nfs4_destroy_open_owner(foop);
			foop = list_head(&bucketp->b_oo_hash_list);
		}
		list_destroy(&bucketp->b_oo_hash_list);
		mutex_destroy(&bucketp->b_lock);
	}
	/*
	 * Empty and destroy the freed open owner list.
	 */
	foop = list_head(&mi->mi_foo_list);
	while (foop != NULL) {
		list_remove(&mi->mi_foo_list, foop);
		nfs4_destroy_open_owner(foop);
		foop = list_head(&mi->mi_foo_list);
	}
	list_destroy(&mi->mi_foo_list);
	list_destroy(&mi->mi_bseqid_list);
	list_destroy(&mi->mi_lost_state);
	avl_destroy(&mi->mi_filehandles);
	kmem_free(mi, sizeof (*mi));
}
void
mi_hold(mntinfo4_t *mi)
{
	atomic_inc_32(&mi->mi_count);
	ASSERT(mi->mi_count != 0);
}

void
mi_rele(mntinfo4_t *mi)
{
	ASSERT(mi->mi_count != 0);
	if (atomic_dec_32_nv(&mi->mi_count) == 0) {
		nfs_free_mi4(mi);
	}
}

vnode_t    nfs4_xattr_notsupp_vnode;

void
nfs4_clnt_init(void)
{
	nfs4_vnops_init();
	(void) nfs4_rnode_init();
	(void) nfs4_shadow_init();
	(void) nfs4_acache_init();
	(void) nfs4_subr_init();
	nfs4_acl_init();
	nfs_idmap_init();
	nfs4_callback_init();
	nfs4_secinfo_init();
#ifdef	DEBUG
	tsd_create(&nfs4_tsd_key, NULL);
#endif

	/*
	 * Add a CPR callback so that we can update client
	 * lease after a suspend and resume.
	 */
	cid = callb_add(nfs4_client_cpr_callb, 0, CB_CL_CPR_RPC, "nfs4");

	zone_key_create(&mi4_list_key, nfs4_mi_init, nfs4_mi_shutdown,
	    nfs4_mi_destroy);

	/*
	 * Initialise the reference count of the notsupp xattr cache vnode to 1
	 * so that it never goes away (VOP_INACTIVE isn't called on it).
	 */
	nfs4_xattr_notsupp_vnode.v_count = 1;
}

void
nfs4_clnt_fini(void)
{
	(void) zone_key_delete(mi4_list_key);
	nfs4_vnops_fini();
	(void) nfs4_rnode_fini();
	(void) nfs4_shadow_fini();
	(void) nfs4_acache_fini();
	(void) nfs4_subr_fini();
	nfs_idmap_fini();
	nfs4_callback_fini();
	nfs4_secinfo_fini();
#ifdef	DEBUG
	tsd_destroy(&nfs4_tsd_key);
#endif
	if (cid)
		(void) callb_delete(cid);
}

/*ARGSUSED*/
static boolean_t
nfs4_client_cpr_callb(void *arg, int code)
{
	/*
	 * We get called for Suspend and Resume events.
	 * For the suspend case we simply don't care!
	 */
	if (code == CB_CODE_CPR_CHKPT) {
		return (B_TRUE);
	}

	/*
	 * When we get to here we are in the process of
	 * resuming the system from a previous suspend.
	 */
	nfs4_client_resumed = gethrestime_sec();
	return (B_TRUE);
}

void
nfs4_renew_lease_thread(nfs4_server_t *sp)
{
	int	error = 0;
	time_t	tmp_last_renewal_time, tmp_time, tmp_now_time, kip_secs;
	clock_t	tick_delay = 0;
	clock_t time_left = 0;
	callb_cpr_t cpr_info;
	kmutex_t cpr_lock;

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
	    "nfs4_renew_lease_thread: acting on sp 0x%p", (void*)sp));
	mutex_init(&cpr_lock, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cpr_info, &cpr_lock, callb_generic_cpr, "nfsv4Lease");

	mutex_enter(&sp->s_lock);
	/* sp->s_lease_time is set via a GETATTR */
	sp->last_renewal_time = gethrestime_sec();
	sp->lease_valid = NFS4_LEASE_UNINITIALIZED;
	ASSERT(sp->s_refcnt >= 1);

	for (;;) {
		if (!sp->state_ref_count ||
		    sp->lease_valid != NFS4_LEASE_VALID) {

			kip_secs = MAX((sp->s_lease_time >> 1) -
			    (3 * sp->propagation_delay.tv_sec), 1);

			tick_delay = SEC_TO_TICK(kip_secs);

			NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
			    "nfs4_renew_lease_thread: no renew : thread "
			    "wait %ld secs", kip_secs));

			NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
			    "nfs4_renew_lease_thread: no renew : "
			    "state_ref_count %d, lease_valid %d",
			    sp->state_ref_count, sp->lease_valid));

			mutex_enter(&cpr_lock);
			CALLB_CPR_SAFE_BEGIN(&cpr_info);
			mutex_exit(&cpr_lock);
			time_left = cv_reltimedwait(&sp->cv_thread_exit,
			    &sp->s_lock, tick_delay, TR_CLOCK_TICK);
			mutex_enter(&cpr_lock);
			CALLB_CPR_SAFE_END(&cpr_info, &cpr_lock);
			mutex_exit(&cpr_lock);

			NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
			    "nfs4_renew_lease_thread: no renew: "
			    "time left %ld", time_left));

			if (sp->s_thread_exit == NFS4_THREAD_EXIT)
				goto die;
			continue;
		}

		tmp_last_renewal_time = sp->last_renewal_time;

		tmp_time = gethrestime_sec() - sp->last_renewal_time +
		    (3 * sp->propagation_delay.tv_sec);

		NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
		    "nfs4_renew_lease_thread: tmp_time %ld, "
		    "sp->last_renewal_time %ld", tmp_time,
		    sp->last_renewal_time));

		kip_secs = MAX((sp->s_lease_time >> 1) - tmp_time, 1);

		tick_delay = SEC_TO_TICK(kip_secs);

		NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
		    "nfs4_renew_lease_thread: valid lease: sleep for %ld "
		    "secs", kip_secs));

		mutex_enter(&cpr_lock);
		CALLB_CPR_SAFE_BEGIN(&cpr_info);
		mutex_exit(&cpr_lock);
		time_left = cv_reltimedwait(&sp->cv_thread_exit, &sp->s_lock,
		    tick_delay, TR_CLOCK_TICK);
		mutex_enter(&cpr_lock);
		CALLB_CPR_SAFE_END(&cpr_info, &cpr_lock);
		mutex_exit(&cpr_lock);

		NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
		    "nfs4_renew_lease_thread: valid lease: time left %ld :"
		    "sp last_renewal_time %ld, nfs4_client_resumed %ld, "
		    "tmp_last_renewal_time %ld", time_left,
		    sp->last_renewal_time, nfs4_client_resumed,
		    tmp_last_renewal_time));

		if (sp->s_thread_exit == NFS4_THREAD_EXIT)
			goto die;

		if (tmp_last_renewal_time == sp->last_renewal_time ||
		    (nfs4_client_resumed != 0 &&
		    nfs4_client_resumed > sp->last_renewal_time)) {
			/*
			 * Issue RENEW op since we haven't renewed the lease
			 * since we slept.
			 */
			tmp_now_time = gethrestime_sec();
			error = nfs4renew(sp);
			/*
			 * Need to re-acquire sp's lock, nfs4renew()
			 * relinqueshes it.
			 */
			mutex_enter(&sp->s_lock);

			/*
			 * See if someone changed s_thread_exit while we gave
			 * up s_lock.
			 */
			if (sp->s_thread_exit == NFS4_THREAD_EXIT)
				goto die;

			if (!error) {
				/*
				 * check to see if we implicitly renewed while
				 * we waited for a reply for our RENEW call.
				 */
				if (tmp_last_renewal_time ==
				    sp->last_renewal_time) {
					/* no implicit renew came */
					sp->last_renewal_time = tmp_now_time;
				} else {
					NFS4_DEBUG(nfs4_client_lease_debug,
					    (CE_NOTE, "renew_thread: did "
					    "implicit renewal before reply "
					    "from server for RENEW"));
				}
			} else {
				/* figure out error */
				NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
				    "renew_thread: nfs4renew returned error"
				    " %d", error));
			}

		}
	}

die:
	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
	    "nfs4_renew_lease_thread: thread exiting"));

	while (sp->s_otw_call_count != 0) {
		NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
		    "nfs4_renew_lease_thread: waiting for outstanding "
		    "otw calls to finish for sp 0x%p, current "
		    "s_otw_call_count %d", (void *)sp,
		    sp->s_otw_call_count));
		mutex_enter(&cpr_lock);
		CALLB_CPR_SAFE_BEGIN(&cpr_info);
		mutex_exit(&cpr_lock);
		cv_wait(&sp->s_cv_otw_count, &sp->s_lock);
		mutex_enter(&cpr_lock);
		CALLB_CPR_SAFE_END(&cpr_info, &cpr_lock);
		mutex_exit(&cpr_lock);
	}
	mutex_exit(&sp->s_lock);

	nfs4_server_rele(sp);		/* free the thread's reference */
	nfs4_server_rele(sp);		/* free the list's reference */
	sp = NULL;

done:
	mutex_enter(&cpr_lock);
	CALLB_CPR_EXIT(&cpr_info);	/* drops cpr_lock */
	mutex_destroy(&cpr_lock);

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
	    "nfs4_renew_lease_thread: renew thread exit officially"));

	zthread_exit();
	/* NOT REACHED */
}

/*
 * Send out a RENEW op to the server.
 * Assumes sp is locked down.
 */
static int
nfs4renew(nfs4_server_t *sp)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[1];
	int doqueue = 1;
	int rpc_error;
	cred_t *cr;
	mntinfo4_t *mi;
	timespec_t prop_time, after_time;
	int needrecov = FALSE;
	nfs4_recov_state_t recov_state;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE, "nfs4renew"));

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

recov_retry:
	mi = sp->mntinfo4_list;
	VFS_HOLD(mi->mi_vfsp);
	mutex_exit(&sp->s_lock);
	ASSERT(mi != NULL);

	e.error = nfs4_start_op(mi, NULL, NULL, &recov_state);
	if (e.error) {
		VFS_RELE(mi->mi_vfsp);
		return (e.error);
	}

	/* Check to see if we're dealing with a marked-dead sp */
	mutex_enter(&sp->s_lock);
	if (sp->s_thread_exit == NFS4_THREAD_EXIT) {
		mutex_exit(&sp->s_lock);
		nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);
		VFS_RELE(mi->mi_vfsp);
		return (0);
	}

	/* Make sure mi hasn't changed on us */
	if (mi != sp->mntinfo4_list) {
		/* Must drop sp's lock to avoid a recursive mutex enter */
		mutex_exit(&sp->s_lock);
		nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);
		VFS_RELE(mi->mi_vfsp);
		mutex_enter(&sp->s_lock);
		goto recov_retry;
	}
	mutex_exit(&sp->s_lock);

	args.ctag = TAG_RENEW;

	args.array_len = 1;
	args.array = argop;

	argop[0].argop = OP_RENEW;

	mutex_enter(&sp->s_lock);
	argop[0].nfs_argop4_u.oprenew.clientid = sp->clientid;
	cr = sp->s_cred;
	crhold(cr);
	mutex_exit(&sp->s_lock);

	ASSERT(cr != NULL);

	/* used to figure out RTT for sp */
	gethrestime(&prop_time);

	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "nfs4renew: %s call, sp 0x%p", needrecov ? "recov" : "first",
	    (void*)sp));
	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE, "before: %ld s %ld ns ",
	    prop_time.tv_sec, prop_time.tv_nsec));

	DTRACE_PROBE2(nfs4__renew__start, nfs4_server_t *, sp,
	    mntinfo4_t *, mi);

	rfs4call(mi, &args, &res, cr, &doqueue, 0, &e);
	crfree(cr);

	DTRACE_PROBE2(nfs4__renew__end, nfs4_server_t *, sp,
	    mntinfo4_t *, mi);

	gethrestime(&after_time);

	mutex_enter(&sp->s_lock);
	sp->propagation_delay.tv_sec =
	    MAX(1, after_time.tv_sec - prop_time.tv_sec);
	mutex_exit(&sp->s_lock);

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE, "after : %ld s %ld ns ",
	    after_time.tv_sec, after_time.tv_nsec));

	if (e.error == 0 && res.status == NFS4ERR_CB_PATH_DOWN) {
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_delegreturn_all(sp);
		nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);
		VFS_RELE(mi->mi_vfsp);
		/*
		 * If the server returns CB_PATH_DOWN, it has renewed
		 * the lease and informed us that the callback path is
		 * down.  Since the lease is renewed, just return 0 and
		 * let the renew thread proceed as normal.
		 */
		return (0);
	}

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
	if (!needrecov && e.error) {
		nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);
		VFS_RELE(mi->mi_vfsp);
		return (e.error);
	}

	rpc_error = e.error;

	if (needrecov) {
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4renew: initiating recovery\n"));

		if (nfs4_start_recovery(&e, mi, NULL, NULL, NULL, NULL,
		    OP_RENEW, NULL, NULL, NULL) == FALSE) {
			nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);
			VFS_RELE(mi->mi_vfsp);
			if (!e.error)
				(void) xdr_free(xdr_COMPOUND4res_clnt,
				    (caddr_t)&res);
			mutex_enter(&sp->s_lock);
			goto recov_retry;
		}
		/* fall through for res.status case */
	}

	if (res.status) {
		if (res.status == NFS4ERR_LEASE_MOVED) {
			/*EMPTY*/
			/*
			 * XXX need to try every mntinfo4 in sp->mntinfo4_list
			 * to renew the lease on that server
			 */
		}
		e.error = geterrno4(res.status);
	}

	if (!rpc_error)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	nfs4_end_op(mi, NULL, NULL, &recov_state, needrecov);

	VFS_RELE(mi->mi_vfsp);

	return (e.error);
}

void
nfs4_inc_state_ref_count(mntinfo4_t *mi)
{
	nfs4_server_t	*sp;

	/* this locks down sp if it is found */
	sp = find_nfs4_server(mi);

	if (sp != NULL) {
		nfs4_inc_state_ref_count_nolock(sp, mi);
		mutex_exit(&sp->s_lock);
		nfs4_server_rele(sp);
	}
}

/*
 * Bump the number of OPEN files (ie: those with state) so we know if this
 * nfs4_server has any state to maintain a lease for or not.
 *
 * Also, marks the nfs4_server's lease valid if it hasn't been done so already.
 */
void
nfs4_inc_state_ref_count_nolock(nfs4_server_t *sp, mntinfo4_t *mi)
{
	ASSERT(mutex_owned(&sp->s_lock));

	sp->state_ref_count++;
	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
	    "nfs4_inc_state_ref_count: state_ref_count now %d",
	    sp->state_ref_count));

	if (sp->lease_valid == NFS4_LEASE_UNINITIALIZED)
		sp->lease_valid = NFS4_LEASE_VALID;

	/*
	 * If this call caused the lease to be marked valid and/or
	 * took the state_ref_count from 0 to 1, then start the time
	 * on lease renewal.
	 */
	if (sp->lease_valid == NFS4_LEASE_VALID && sp->state_ref_count == 1)
		sp->last_renewal_time = gethrestime_sec();

	/* update the number of open files for mi */
	mi->mi_open_files++;
}

void
nfs4_dec_state_ref_count(mntinfo4_t *mi)
{
	nfs4_server_t	*sp;

	/* this locks down sp if it is found */
	sp = find_nfs4_server_all(mi, 1);

	if (sp != NULL) {
		nfs4_dec_state_ref_count_nolock(sp, mi);
		mutex_exit(&sp->s_lock);
		nfs4_server_rele(sp);
	}
}

/*
 * Decrement the number of OPEN files (ie: those with state) so we know if
 * this nfs4_server has any state to maintain a lease for or not.
 */
void
nfs4_dec_state_ref_count_nolock(nfs4_server_t *sp, mntinfo4_t *mi)
{
	ASSERT(mutex_owned(&sp->s_lock));
	ASSERT(sp->state_ref_count != 0);
	sp->state_ref_count--;

	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
	    "nfs4_dec_state_ref_count: state ref count now %d",
	    sp->state_ref_count));

	mi->mi_open_files--;
	NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
	    "nfs4_dec_state_ref_count: mi open files %d, v4 flags 0x%x",
	    mi->mi_open_files, mi->mi_flags));

	/* We don't have to hold the mi_lock to test mi_flags */
	if (mi->mi_open_files == 0 &&
	    (mi->mi_flags & MI4_REMOVE_ON_LAST_CLOSE)) {
		NFS4_DEBUG(nfs4_client_lease_debug, (CE_NOTE,
		    "nfs4_dec_state_ref_count: remove mntinfo4 %p since "
		    "we have closed the last open file", (void*)mi));
		nfs4_remove_mi_from_server(mi, sp);
	}
}

bool_t
inlease(nfs4_server_t *sp)
{
	bool_t result;

	ASSERT(mutex_owned(&sp->s_lock));

	if (sp->lease_valid == NFS4_LEASE_VALID &&
	    gethrestime_sec() < sp->last_renewal_time + sp->s_lease_time)
		result = TRUE;
	else
		result = FALSE;

	return (result);
}


/*
 * Return non-zero if the given nfs4_server_t is going through recovery.
 */

int
nfs4_server_in_recovery(nfs4_server_t *sp)
{
	return (nfs_rw_lock_held(&sp->s_recovlock, RW_WRITER));
}

/*
 * Compare two shared filehandle objects.  Returns -1, 0, or +1, if the
 * first is less than, equal to, or greater than the second.
 */

int
sfh4cmp(const void *p1, const void *p2)
{
	const nfs4_sharedfh_t *sfh1 = (const nfs4_sharedfh_t *)p1;
	const nfs4_sharedfh_t *sfh2 = (const nfs4_sharedfh_t *)p2;

	return (nfs4cmpfh(&sfh1->sfh_fh, &sfh2->sfh_fh));
}

/*
 * Create a table for shared filehandle objects.
 */

void
sfh4_createtab(avl_tree_t *tab)
{
	avl_create(tab, sfh4cmp, sizeof (nfs4_sharedfh_t),
	    offsetof(nfs4_sharedfh_t, sfh_tree));
}

/*
 * Return a shared filehandle object for the given filehandle.  The caller
 * is responsible for eventually calling sfh4_rele().
 */

nfs4_sharedfh_t *
sfh4_put(const nfs_fh4 *fh, mntinfo4_t *mi, nfs4_sharedfh_t *key)
{
	nfs4_sharedfh_t *sfh, *nsfh;
	avl_index_t where;
	nfs4_sharedfh_t skey;

	if (!key) {
		skey.sfh_fh = *fh;
		key = &skey;
	}

	nsfh = kmem_alloc(sizeof (nfs4_sharedfh_t), KM_SLEEP);
	nsfh->sfh_fh.nfs_fh4_len = fh->nfs_fh4_len;
	/*
	 * We allocate the largest possible filehandle size because it's
	 * not that big, and it saves us from possibly having to resize the
	 * buffer later.
	 */
	nsfh->sfh_fh.nfs_fh4_val = kmem_alloc(NFS4_FHSIZE, KM_SLEEP);
	bcopy(fh->nfs_fh4_val, nsfh->sfh_fh.nfs_fh4_val, fh->nfs_fh4_len);
	mutex_init(&nsfh->sfh_lock, NULL, MUTEX_DEFAULT, NULL);
	nsfh->sfh_refcnt = 1;
	nsfh->sfh_flags = SFH4_IN_TREE;
	nsfh->sfh_mi = mi;
	NFS4_DEBUG(nfs4_sharedfh_debug, (CE_NOTE, "sfh4_get: new object (%p)",
	    (void *)nsfh));

	(void) nfs_rw_enter_sig(&mi->mi_fh_lock, RW_WRITER, 0);
	sfh = avl_find(&mi->mi_filehandles, key, &where);
	if (sfh != NULL) {
		mutex_enter(&sfh->sfh_lock);
		sfh->sfh_refcnt++;
		mutex_exit(&sfh->sfh_lock);
		nfs_rw_exit(&mi->mi_fh_lock);
		/* free our speculative allocs */
		kmem_free(nsfh->sfh_fh.nfs_fh4_val, NFS4_FHSIZE);
		kmem_free(nsfh, sizeof (nfs4_sharedfh_t));
		return (sfh);
	}

	avl_insert(&mi->mi_filehandles, nsfh, where);
	nfs_rw_exit(&mi->mi_fh_lock);

	return (nsfh);
}

/*
 * Return a shared filehandle object for the given filehandle.  The caller
 * is responsible for eventually calling sfh4_rele().
 */

nfs4_sharedfh_t *
sfh4_get(const nfs_fh4 *fh, mntinfo4_t *mi)
{
	nfs4_sharedfh_t *sfh;
	nfs4_sharedfh_t key;

	ASSERT(fh->nfs_fh4_len <= NFS4_FHSIZE);

#ifdef DEBUG
	if (nfs4_sharedfh_debug) {
		nfs4_fhandle_t fhandle;

		fhandle.fh_len = fh->nfs_fh4_len;
		bcopy(fh->nfs_fh4_val, fhandle.fh_buf, fhandle.fh_len);
		zcmn_err(mi->mi_zone->zone_id, CE_NOTE, "sfh4_get:");
		nfs4_printfhandle(&fhandle);
	}
#endif

	/*
	 * If there's already an object for the given filehandle, bump the
	 * reference count and return it.  Otherwise, create a new object
	 * and add it to the AVL tree.
	 */

	key.sfh_fh = *fh;

	(void) nfs_rw_enter_sig(&mi->mi_fh_lock, RW_READER, 0);
	sfh = avl_find(&mi->mi_filehandles, &key, NULL);
	if (sfh != NULL) {
		mutex_enter(&sfh->sfh_lock);
		sfh->sfh_refcnt++;
		NFS4_DEBUG(nfs4_sharedfh_debug, (CE_NOTE,
		    "sfh4_get: found existing %p, new refcnt=%d",
		    (void *)sfh, sfh->sfh_refcnt));
		mutex_exit(&sfh->sfh_lock);
		nfs_rw_exit(&mi->mi_fh_lock);
		return (sfh);
	}
	nfs_rw_exit(&mi->mi_fh_lock);

	return (sfh4_put(fh, mi, &key));
}

/*
 * Get a reference to the given shared filehandle object.
 */

void
sfh4_hold(nfs4_sharedfh_t *sfh)
{
	ASSERT(sfh->sfh_refcnt > 0);

	mutex_enter(&sfh->sfh_lock);
	sfh->sfh_refcnt++;
	NFS4_DEBUG(nfs4_sharedfh_debug,
	    (CE_NOTE, "sfh4_hold %p, new refcnt=%d",
	    (void *)sfh, sfh->sfh_refcnt));
	mutex_exit(&sfh->sfh_lock);
}

/*
 * Release a reference to the given shared filehandle object and null out
 * the given pointer.
 */

void
sfh4_rele(nfs4_sharedfh_t **sfhpp)
{
	mntinfo4_t *mi;
	nfs4_sharedfh_t *sfh = *sfhpp;

	ASSERT(sfh->sfh_refcnt > 0);

	mutex_enter(&sfh->sfh_lock);
	if (sfh->sfh_refcnt > 1) {
		sfh->sfh_refcnt--;
		NFS4_DEBUG(nfs4_sharedfh_debug, (CE_NOTE,
		    "sfh4_rele %p, new refcnt=%d",
		    (void *)sfh, sfh->sfh_refcnt));
		mutex_exit(&sfh->sfh_lock);
		goto finish;
	}
	mutex_exit(&sfh->sfh_lock);

	/*
	 * Possibly the last reference, so get the lock for the table in
	 * case it's time to remove the object from the table.
	 */
	mi = sfh->sfh_mi;
	(void) nfs_rw_enter_sig(&mi->mi_fh_lock, RW_WRITER, 0);
	mutex_enter(&sfh->sfh_lock);
	sfh->sfh_refcnt--;
	if (sfh->sfh_refcnt > 0) {
		NFS4_DEBUG(nfs4_sharedfh_debug, (CE_NOTE,
		    "sfh4_rele %p, new refcnt=%d",
		    (void *)sfh, sfh->sfh_refcnt));
		mutex_exit(&sfh->sfh_lock);
		nfs_rw_exit(&mi->mi_fh_lock);
		goto finish;
	}

	NFS4_DEBUG(nfs4_sharedfh_debug, (CE_NOTE,
	    "sfh4_rele %p, last ref", (void *)sfh));
	if (sfh->sfh_flags & SFH4_IN_TREE) {
		avl_remove(&mi->mi_filehandles, sfh);
		sfh->sfh_flags &= ~SFH4_IN_TREE;
	}
	mutex_exit(&sfh->sfh_lock);
	nfs_rw_exit(&mi->mi_fh_lock);
	mutex_destroy(&sfh->sfh_lock);
	kmem_free(sfh->sfh_fh.nfs_fh4_val, NFS4_FHSIZE);
	kmem_free(sfh, sizeof (nfs4_sharedfh_t));

finish:
	*sfhpp = NULL;
}

/*
 * Update the filehandle for the given shared filehandle object.
 */

int nfs4_warn_dupfh = 0;	/* if set, always warn about dup fhs below */

void
sfh4_update(nfs4_sharedfh_t *sfh, const nfs_fh4 *newfh)
{
	mntinfo4_t *mi = sfh->sfh_mi;
	nfs4_sharedfh_t *dupsfh;
	avl_index_t where;
	nfs4_sharedfh_t key;

#ifdef DEBUG
	mutex_enter(&sfh->sfh_lock);
	ASSERT(sfh->sfh_refcnt > 0);
	mutex_exit(&sfh->sfh_lock);
#endif
	ASSERT(newfh->nfs_fh4_len <= NFS4_FHSIZE);

	/*
	 * The basic plan is to remove the shared filehandle object from
	 * the table, update it to have the new filehandle, then reinsert
	 * it.
	 */

	(void) nfs_rw_enter_sig(&mi->mi_fh_lock, RW_WRITER, 0);
	mutex_enter(&sfh->sfh_lock);
	if (sfh->sfh_flags & SFH4_IN_TREE) {
		avl_remove(&mi->mi_filehandles, sfh);
		sfh->sfh_flags &= ~SFH4_IN_TREE;
	}
	mutex_exit(&sfh->sfh_lock);
	sfh->sfh_fh.nfs_fh4_len = newfh->nfs_fh4_len;
	bcopy(newfh->nfs_fh4_val, sfh->sfh_fh.nfs_fh4_val,
	    sfh->sfh_fh.nfs_fh4_len);

	/*
	 * XXX If there is already a shared filehandle object with the new
	 * filehandle, we're in trouble, because the rnode code assumes
	 * that there is only one shared filehandle object for a given
	 * filehandle.  So issue a warning (for read-write mounts only)
	 * and don't try to re-insert the given object into the table.
	 * Hopefully the given object will quickly go away and everyone
	 * will use the new object.
	 */
	key.sfh_fh = *newfh;
	dupsfh = avl_find(&mi->mi_filehandles, &key, &where);
	if (dupsfh != NULL) {
		if (!(mi->mi_vfsp->vfs_flag & VFS_RDONLY) || nfs4_warn_dupfh) {
			zcmn_err(mi->mi_zone->zone_id, CE_WARN, "sfh4_update: "
			    "duplicate filehandle detected");
			sfh4_printfhandle(dupsfh);
		}
	} else {
		avl_insert(&mi->mi_filehandles, sfh, where);
		mutex_enter(&sfh->sfh_lock);
		sfh->sfh_flags |= SFH4_IN_TREE;
		mutex_exit(&sfh->sfh_lock);
	}
	nfs_rw_exit(&mi->mi_fh_lock);
}

/*
 * Copy out the current filehandle for the given shared filehandle object.
 */

void
sfh4_copyval(const nfs4_sharedfh_t *sfh, nfs4_fhandle_t *fhp)
{
	mntinfo4_t *mi = sfh->sfh_mi;

	ASSERT(sfh->sfh_refcnt > 0);

	(void) nfs_rw_enter_sig(&mi->mi_fh_lock, RW_READER, 0);
	fhp->fh_len = sfh->sfh_fh.nfs_fh4_len;
	ASSERT(fhp->fh_len <= NFS4_FHSIZE);
	bcopy(sfh->sfh_fh.nfs_fh4_val, fhp->fh_buf, fhp->fh_len);
	nfs_rw_exit(&mi->mi_fh_lock);
}

/*
 * Print out the filehandle for the given shared filehandle object.
 */

void
sfh4_printfhandle(const nfs4_sharedfh_t *sfh)
{
	nfs4_fhandle_t fhandle;

	sfh4_copyval(sfh, &fhandle);
	nfs4_printfhandle(&fhandle);
}

/*
 * Compare 2 fnames.  Returns -1 if the first is "less" than the second, 0
 * if they're the same, +1 if the first is "greater" than the second.  The
 * caller (or whoever's calling the AVL package) is responsible for
 * handling locking issues.
 */

static int
fncmp(const void *p1, const void *p2)
{
	const nfs4_fname_t *f1 = p1;
	const nfs4_fname_t *f2 = p2;
	int res;

	res = strcmp(f1->fn_name, f2->fn_name);
	/*
	 * The AVL package wants +/-1, not arbitrary positive or negative
	 * integers.
	 */
	if (res > 0)
		res = 1;
	else if (res < 0)
		res = -1;
	return (res);
}

/*
 * Get or create an fname with the given name, as a child of the given
 * fname.  The caller is responsible for eventually releasing the reference
 * (fn_rele()).  parent may be NULL.
 */

nfs4_fname_t *
fn_get(nfs4_fname_t *parent, char *name, nfs4_sharedfh_t *sfh)
{
	nfs4_fname_t key;
	nfs4_fname_t *fnp;
	avl_index_t where;

	key.fn_name = name;

	/*
	 * If there's already an fname registered with the given name, bump
	 * its reference count and return it.  Otherwise, create a new one
	 * and add it to the parent's AVL tree.
	 *
	 * fname entries we are looking for should match both name
	 * and sfh stored in the fname.
	 */
again:
	if (parent != NULL) {
		mutex_enter(&parent->fn_lock);
		fnp = avl_find(&parent->fn_children, &key, &where);
		if (fnp != NULL) {
			/*
			 * This hold on fnp is released below later,
			 * in case this is not the fnp we want.
			 */
			fn_hold(fnp);

			if (fnp->fn_sfh == sfh) {
				/*
				 * We have found our entry.
				 * put an hold and return it.
				 */
				mutex_exit(&parent->fn_lock);
				return (fnp);
			}

			/*
			 * We have found an entry that has a mismatching
			 * fn_sfh. This could be a stale entry due to
			 * server side rename. We will remove this entry
			 * and make sure no such entries exist.
			 */
			mutex_exit(&parent->fn_lock);
			mutex_enter(&fnp->fn_lock);
			if (fnp->fn_parent == parent) {
				/*
				 * Remove ourselves from parent's
				 * fn_children tree.
				 */
				mutex_enter(&parent->fn_lock);
				avl_remove(&parent->fn_children, fnp);
				mutex_exit(&parent->fn_lock);
				fn_rele(&fnp->fn_parent);
			}
			mutex_exit(&fnp->fn_lock);
			fn_rele(&fnp);
			goto again;
		}
	}

	fnp = kmem_alloc(sizeof (nfs4_fname_t), KM_SLEEP);
	mutex_init(&fnp->fn_lock, NULL, MUTEX_DEFAULT, NULL);
	fnp->fn_parent = parent;
	if (parent != NULL)
		fn_hold(parent);
	fnp->fn_len = strlen(name);
	ASSERT(fnp->fn_len < MAXNAMELEN);
	fnp->fn_name = kmem_alloc(fnp->fn_len + 1, KM_SLEEP);
	(void) strcpy(fnp->fn_name, name);
	fnp->fn_refcnt = 1;

	/*
	 * This hold on sfh is later released
	 * when we do the final fn_rele() on this fname.
	 */
	sfh4_hold(sfh);
	fnp->fn_sfh = sfh;

	avl_create(&fnp->fn_children, fncmp, sizeof (nfs4_fname_t),
	    offsetof(nfs4_fname_t, fn_tree));
	NFS4_DEBUG(nfs4_fname_debug, (CE_NOTE,
	    "fn_get %p:%s, a new nfs4_fname_t!",
	    (void *)fnp, fnp->fn_name));
	if (parent != NULL) {
		avl_insert(&parent->fn_children, fnp, where);
		mutex_exit(&parent->fn_lock);
	}

	return (fnp);
}

void
fn_hold(nfs4_fname_t *fnp)
{
	atomic_inc_32(&fnp->fn_refcnt);
	NFS4_DEBUG(nfs4_fname_debug, (CE_NOTE,
	    "fn_hold %p:%s, new refcnt=%d",
	    (void *)fnp, fnp->fn_name, fnp->fn_refcnt));
}

/*
 * Decrement the reference count of the given fname, and destroy it if its
 * reference count goes to zero.  Nulls out the given pointer.
 */

void
fn_rele(nfs4_fname_t **fnpp)
{
	nfs4_fname_t *parent;
	uint32_t newref;
	nfs4_fname_t *fnp;

recur:
	fnp = *fnpp;
	*fnpp = NULL;

	mutex_enter(&fnp->fn_lock);
	parent = fnp->fn_parent;
	if (parent != NULL)
		mutex_enter(&parent->fn_lock);	/* prevent new references */
	newref = atomic_dec_32_nv(&fnp->fn_refcnt);
	if (newref > 0) {
		NFS4_DEBUG(nfs4_fname_debug, (CE_NOTE,
		    "fn_rele %p:%s, new refcnt=%d",
		    (void *)fnp, fnp->fn_name, fnp->fn_refcnt));
		if (parent != NULL)
			mutex_exit(&parent->fn_lock);
		mutex_exit(&fnp->fn_lock);
		return;
	}

	NFS4_DEBUG(nfs4_fname_debug, (CE_NOTE,
	    "fn_rele %p:%s, last reference, deleting...",
	    (void *)fnp, fnp->fn_name));
	if (parent != NULL) {
		avl_remove(&parent->fn_children, fnp);
		mutex_exit(&parent->fn_lock);
	}
	kmem_free(fnp->fn_name, fnp->fn_len + 1);
	sfh4_rele(&fnp->fn_sfh);
	mutex_destroy(&fnp->fn_lock);
	avl_destroy(&fnp->fn_children);
	kmem_free(fnp, sizeof (nfs4_fname_t));
	/*
	 * Recursivly fn_rele the parent.
	 * Use goto instead of a recursive call to avoid stack overflow.
	 */
	if (parent != NULL) {
		fnpp = &parent;
		goto recur;
	}
}

/*
 * Returns the single component name of the given fname, in a MAXNAMELEN
 * string buffer, which the caller is responsible for freeing.  Note that
 * the name may become invalid as a result of fn_move().
 */

char *
fn_name(nfs4_fname_t *fnp)
{
	char *name;

	ASSERT(fnp->fn_len < MAXNAMELEN);
	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	mutex_enter(&fnp->fn_lock);
	(void) strcpy(name, fnp->fn_name);
	mutex_exit(&fnp->fn_lock);

	return (name);
}


/*
 * fn_path_realloc
 *
 * This function, used only by fn_path, constructs
 * a new string which looks like "prepend" + "/" + "current".
 * by allocating a new string and freeing the old one.
 */
static void
fn_path_realloc(char **curses, char *prepend)
{
	int len, curlen = 0;
	char *news;

	if (*curses == NULL) {
		/*
		 * Prime the pump, allocate just the
		 * space for prepend and return that.
		 */
		len = strlen(prepend) + 1;
		news = kmem_alloc(len, KM_SLEEP);
		(void) strncpy(news, prepend, len);
	} else {
		/*
		 * Allocate the space  for a new string
		 * +1 +1 is for the "/" and the NULL
		 * byte at the end of it all.
		 */
		curlen = strlen(*curses);
		len = curlen + strlen(prepend) + 1 + 1;
		news = kmem_alloc(len, KM_SLEEP);
		(void) strncpy(news, prepend, len);
		(void) strcat(news, "/");
		(void) strcat(news, *curses);
		kmem_free(*curses, curlen + 1);
	}
	*curses = news;
}

/*
 * Returns the path name (starting from the fs root) for the given fname.
 * The caller is responsible for freeing.  Note that the path may be or
 * become invalid as a result of fn_move().
 */

char *
fn_path(nfs4_fname_t *fnp)
{
	char *path;
	nfs4_fname_t *nextfnp;

	if (fnp == NULL)
		return (NULL);

	path = NULL;

	/* walk up the tree constructing the pathname.  */

	fn_hold(fnp);			/* adjust for later rele */
	do {
		mutex_enter(&fnp->fn_lock);
		/*
		 * Add fn_name in front of the current path
		 */
		fn_path_realloc(&path, fnp->fn_name);
		nextfnp = fnp->fn_parent;
		if (nextfnp != NULL)
			fn_hold(nextfnp);
		mutex_exit(&fnp->fn_lock);
		fn_rele(&fnp);
		fnp = nextfnp;
	} while (fnp != NULL);

	return (path);
}

/*
 * Return a reference to the parent of the given fname, which the caller is
 * responsible for eventually releasing.
 */

nfs4_fname_t *
fn_parent(nfs4_fname_t *fnp)
{
	nfs4_fname_t *parent;

	mutex_enter(&fnp->fn_lock);
	parent = fnp->fn_parent;
	if (parent != NULL)
		fn_hold(parent);
	mutex_exit(&fnp->fn_lock);

	return (parent);
}

/*
 * Update fnp so that its parent is newparent and its name is newname.
 */

void
fn_move(nfs4_fname_t *fnp, nfs4_fname_t *newparent, char *newname)
{
	nfs4_fname_t *parent, *tmpfnp;
	ssize_t newlen;
	nfs4_fname_t key;
	avl_index_t where;

	/*
	 * This assert exists to catch the client trying to rename
	 * a dir to be a child of itself.  This happened at a recent
	 * bakeoff against a 3rd party (broken) server which allowed
	 * the rename to succeed.  If it trips it means that:
	 *	a) the code in nfs4rename that detects this case is broken
	 *	b) the server is broken (since it allowed the bogus rename)
	 *
	 * For non-DEBUG kernels, prepare for a recursive mutex_enter
	 * panic below from:  mutex_enter(&newparent->fn_lock);
	 */
	ASSERT(fnp != newparent);

	/*
	 * Remove fnp from its current parent, change its name, then add it
	 * to newparent. It might happen that fnp was replaced by another
	 * nfs4_fname_t with the same fn_name in parent->fn_children.
	 * In such case, fnp->fn_parent is NULL and we skip the removal
	 * of fnp from its current parent.
	 */
	mutex_enter(&fnp->fn_lock);
	parent = fnp->fn_parent;
	if (parent != NULL) {
		mutex_enter(&parent->fn_lock);
		avl_remove(&parent->fn_children, fnp);
		mutex_exit(&parent->fn_lock);
		fn_rele(&fnp->fn_parent);
	}

	newlen = strlen(newname);
	if (newlen != fnp->fn_len) {
		ASSERT(newlen < MAXNAMELEN);
		kmem_free(fnp->fn_name, fnp->fn_len + 1);
		fnp->fn_name = kmem_alloc(newlen + 1, KM_SLEEP);
		fnp->fn_len = newlen;
	}
	(void) strcpy(fnp->fn_name, newname);

again:
	mutex_enter(&newparent->fn_lock);
	key.fn_name = fnp->fn_name;
	tmpfnp = avl_find(&newparent->fn_children, &key, &where);
	if (tmpfnp != NULL) {
		/*
		 * This could be due to a file that was unlinked while
		 * open, or perhaps the rnode is in the free list.  Remove
		 * it from newparent and let it go away on its own.  The
		 * contorted code is to deal with lock order issues and
		 * race conditions.
		 */
		fn_hold(tmpfnp);
		mutex_exit(&newparent->fn_lock);
		mutex_enter(&tmpfnp->fn_lock);
		if (tmpfnp->fn_parent == newparent) {
			mutex_enter(&newparent->fn_lock);
			avl_remove(&newparent->fn_children, tmpfnp);
			mutex_exit(&newparent->fn_lock);
			fn_rele(&tmpfnp->fn_parent);
		}
		mutex_exit(&tmpfnp->fn_lock);
		fn_rele(&tmpfnp);
		goto again;
	}
	fnp->fn_parent = newparent;
	fn_hold(newparent);
	avl_insert(&newparent->fn_children, fnp, where);
	mutex_exit(&newparent->fn_lock);
	mutex_exit(&fnp->fn_lock);
}

#ifdef DEBUG
/*
 * Return non-zero if the type information makes sense for the given vnode.
 * Otherwise panic.
 */
int
nfs4_consistent_type(vnode_t *vp)
{
	rnode4_t *rp = VTOR4(vp);

	if (nfs4_vtype_debug && vp->v_type != VNON &&
	    rp->r_attr.va_type != VNON && vp->v_type != rp->r_attr.va_type) {
		cmn_err(CE_PANIC, "vnode %p type mismatch; v_type=%d, "
		    "rnode attr type=%d", (void *)vp, vp->v_type,
		    rp->r_attr.va_type);
	}

	return (1);
}
#endif /* DEBUG */
