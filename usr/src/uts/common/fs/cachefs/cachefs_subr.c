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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/uio.h>
#include <sys/tiuser.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/fbuf.h>
#include <sys/dnlc.h>
#include <sys/callb.h>
#include <sys/kobj.h>
#include <sys/rwlock.h>

#include <sys/vmsystm.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_log.h>
#include <sys/fs/cachefs_dir.h>

extern struct seg *segkmap;
caddr_t segmap_getmap();
int segmap_release();

extern struct cnode *cachefs_freeback;
extern struct cnode *cachefs_freefront;
extern cachefscache_t *cachefs_cachelist;

#ifdef CFSDEBUG
int cachefsdebug = 0;
#endif

int cachefs_max_threads = CFS_MAX_THREADS;
ino64_t cachefs_check_fileno = 0;
struct kmem_cache *cachefs_cache_kmcache = NULL;
struct kmem_cache *cachefs_req_cache = NULL;

static int
cachefs_async_populate_reg(struct cachefs_populate_req *, cred_t *,
    vnode_t *, vnode_t *);

/*
 * Cache routines
 */

/*
 * ------------------------------------------------------------------
 *
 *		cachefs_cache_create
 *
 * Description:
 *	Creates a cachefscache_t object and initializes it to
 *	be NOCACHE and NOFILL mode.
 * Arguments:
 * Returns:
 *	Returns a pointer to the created object or NULL if
 *	threads could not be created.
 * Preconditions:
 */

cachefscache_t *
cachefs_cache_create(void)
{
	cachefscache_t *cachep;
	struct cachefs_req *rp;

	/* allocate zeroed memory for the object */
	cachep = kmem_cache_alloc(cachefs_cache_kmcache, KM_SLEEP);

	bzero(cachep, sizeof (*cachep));

	cv_init(&cachep->c_cwcv, NULL, CV_DEFAULT, NULL);
	cv_init(&cachep->c_cwhaltcv, NULL, CV_DEFAULT, NULL);
	mutex_init(&cachep->c_contentslock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&cachep->c_fslistlock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&cachep->c_log_mutex, NULL, MUTEX_DEFAULT, NULL);

	/* set up the work queue and get the sync thread created */
	cachefs_workq_init(&cachep->c_workq);
	cachep->c_workq.wq_keepone = 1;
	cachep->c_workq.wq_cachep = cachep;
	rp = kmem_cache_alloc(cachefs_req_cache, KM_SLEEP);
	rp->cfs_cmd = CFS_NOOP;
	rp->cfs_cr = kcred;
	rp->cfs_req_u.cu_fs_sync.cf_cachep = cachep;
	crhold(rp->cfs_cr);
	cachefs_addqueue(rp, &cachep->c_workq);
	cachep->c_flags |= CACHE_NOCACHE | CACHE_NOFILL | CACHE_ALLOC_PENDING;

	return (cachep);
}

/*
 * ------------------------------------------------------------------
 *
 *		cachefs_cache_destroy
 *
 * Description:
 *	Destroys the cachefscache_t object.
 * Arguments:
 *	cachep	the cachefscache_t object to destroy
 * Returns:
 * Preconditions:
 *	precond(cachep)
 */

void
cachefs_cache_destroy(cachefscache_t *cachep)
{
	clock_t tend;
	int error = 0;
#ifdef CFSRLDEBUG
	uint_t index;
#endif /* CFSRLDEBUG */

	/* stop async threads */
	while (cachep->c_workq.wq_thread_count > 0)
		(void) cachefs_async_halt(&cachep->c_workq, 1);

	/* kill off the cachep worker thread */
	mutex_enter(&cachep->c_contentslock);
	while (cachep->c_flags & CACHE_CACHEW_THREADRUN) {
		cachep->c_flags |= CACHE_CACHEW_THREADEXIT;
		cv_signal(&cachep->c_cwcv);
		tend = lbolt + (60 * hz);
		(void) cv_timedwait(&cachep->c_cwhaltcv,
			&cachep->c_contentslock, tend);
	}

	if ((cachep->c_flags & CACHE_ALLOC_PENDING) == 0) {
		cachep->c_usage.cu_flags &= ~CUSAGE_ACTIVE;
		(void) cachefs_cache_rssync(cachep);
	}
	mutex_exit(&cachep->c_contentslock);

	/* if there is a cache */
	if ((cachep->c_flags & CACHE_NOCACHE) == 0) {
		if ((cachep->c_flags & CACHE_NOFILL) == 0) {
#ifdef CFSRLDEBUG
			/* blow away dangling rl debugging info */
			mutex_enter(&cachep->c_contentslock);
			for (index = 0;
			    index <= cachep->c_rlinfo.rl_entries;
			    index++) {
				rl_entry_t *rlent;

				error = cachefs_rl_entry_get(cachep, index,
									rlent);
				/*
				 * Since we are destroying the cache,
				 * better to ignore and proceed
				 */
				if (error)
					break;
				cachefs_rl_debug_destroy(rlent);
			}
			mutex_exit(&cachep->c_contentslock);
#endif /* CFSRLDEBUG */

			/* sync the cache */
			if (!error)
				cachefs_cache_sync(cachep);
		} else {
			/* get rid of any unused fscache objects */
			mutex_enter(&cachep->c_fslistlock);
			fscache_list_gc(cachep);
			mutex_exit(&cachep->c_fslistlock);
		}
		ASSERT(cachep->c_fslist == NULL);

		VN_RELE(cachep->c_resfilevp);
		VN_RELE(cachep->c_dirvp);
		VN_RELE(cachep->c_lockvp);
		VN_RELE(cachep->c_lostfoundvp);
	}

	if (cachep->c_log_ctl != NULL)
		cachefs_kmem_free(cachep->c_log_ctl,
		    sizeof (cachefs_log_control_t));
	if (cachep->c_log != NULL)
		cachefs_log_destroy_cookie(cachep->c_log);

	cv_destroy(&cachep->c_cwcv);
	cv_destroy(&cachep->c_cwhaltcv);
	mutex_destroy(&cachep->c_contentslock);
	mutex_destroy(&cachep->c_fslistlock);
	mutex_destroy(&cachep->c_log_mutex);

	kmem_cache_free(cachefs_cache_kmcache, cachep);
}

/*
 * ------------------------------------------------------------------
 *
 *		cachefs_cache_active_ro
 *
 * Description:
 *	Activates the cachefscache_t object for a read-only file system.
 * Arguments:
 *	cachep	the cachefscache_t object to activate
 *	cdvp	the vnode of the cache directory
 * Returns:
 *	Returns 0 for success, !0 if there is a problem with the cache.
 * Preconditions:
 *	precond(cachep)
 *	precond(cdvp)
 *	precond(cachep->c_flags & CACHE_NOCACHE)
 */

int
cachefs_cache_activate_ro(cachefscache_t *cachep, vnode_t *cdvp)
{
	cachefs_log_control_t *lc;
	vnode_t *labelvp = NULL;
	vnode_t *rifvp = NULL;
	vnode_t *lockvp = NULL;
	vnode_t *statevp = NULL;
	vnode_t *lostfoundvp = NULL;
	struct vattr *attrp = NULL;
	int error;

	ASSERT(cachep->c_flags & CACHE_NOCACHE);
	mutex_enter(&cachep->c_contentslock);

	attrp = cachefs_kmem_alloc(sizeof (struct vattr), KM_SLEEP);

	/* get the mode bits of the cache directory */
	attrp->va_mask = AT_ALL;
	error = VOP_GETATTR(cdvp, attrp, 0, kcred, NULL);
	if (error)
		goto out;

	/* ensure the mode bits are 000 to keep out casual users */
	if (attrp->va_mode & S_IAMB) {
		cmn_err(CE_WARN, "cachefs: Cache Directory Mode must be 000\n");
		error = EPERM;
		goto out;
	}

	/* Get the lock file */
	error = VOP_LOOKUP(cdvp, CACHEFS_LOCK_FILE, &lockvp, NULL, 0, NULL,
		kcred, NULL, NULL, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: activate_a: cache corruption"
			" run fsck.\n");
		goto out;
	}

	/* Get the label file */
	error = VOP_LOOKUP(cdvp, CACHELABEL_NAME, &labelvp, NULL, 0, NULL,
		kcred, NULL, NULL, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: activate_b: cache corruption"
			" run fsck.\n");
		goto out;
	}

	/* read in the label */
	error = vn_rdwr(UIO_READ, labelvp, (caddr_t)&cachep->c_label,
			sizeof (struct cache_label), 0LL, UIO_SYSSPACE,
			0, (rlim64_t)0, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: activate_c: cache corruption"
			" run fsck.\n");
		goto out;
	}

	/* Verify that we can handle the version this cache was created under */
	if (cachep->c_label.cl_cfsversion != CFSVERSION) {
		cmn_err(CE_WARN, "cachefs: Invalid Cache Version, run fsck\n");
		error = EINVAL;
		goto out;
	}

	/* Open the resource file */
	error = VOP_LOOKUP(cdvp, RESOURCE_NAME, &rifvp, NULL, 0, NULL, kcred,
	    NULL, NULL, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: activate_d: cache corruption"
			" run fsck.\n");
		goto out;
	}

	/*  Read the usage struct for this cache */
	error = vn_rdwr(UIO_READ, rifvp, (caddr_t)&cachep->c_usage,
			sizeof (struct cache_usage), 0LL, UIO_SYSSPACE, 0,
			(rlim64_t)0, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: activate_e: cache corruption"
			" run fsck.\n");
		goto out;
	}

	if (cachep->c_usage.cu_flags & CUSAGE_ACTIVE) {
		cmn_err(CE_WARN, "cachefs: cache not clean.  Run fsck\n");
		/* ENOSPC is what UFS uses for clean flag check */
		error = ENOSPC;
		goto out;
	}

	/*  Read the rlinfo for this cache */
	error = vn_rdwr(UIO_READ, rifvp, (caddr_t)&cachep->c_rlinfo,
	sizeof (cachefs_rl_info_t), (offset_t)sizeof (struct cache_usage),
			UIO_SYSSPACE, 0, 0, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: activate_f: cache corruption"
			" run fsck.\n");
		goto out;
	}

	/* Open the lost+found directory */
	error = VOP_LOOKUP(cdvp, CACHEFS_LOSTFOUND_NAME, &lostfoundvp,
	    NULL, 0, NULL, kcred, NULL, NULL, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: activate_g: cache corruption"
			" run fsck.\n");
		goto out;
	}

	VN_HOLD(rifvp);
	VN_HOLD(cdvp);
	VN_HOLD(lockvp);
	VN_HOLD(lostfoundvp);
	cachep->c_resfilevp = rifvp;
	cachep->c_dirvp = cdvp;
	cachep->c_lockvp = lockvp;
	cachep->c_lostfoundvp = lostfoundvp;

	/* get the cachep worker thread created */
	cachep->c_flags |= CACHE_CACHEW_THREADRUN;
	(void) thread_create(NULL, 0, cachefs_cachep_worker_thread,
	    cachep, 0, &p0, TS_RUN, minclsyspri);

	/* allocate the `logging control' field */
	mutex_enter(&cachep->c_log_mutex);
	cachep->c_log_ctl =
	    cachefs_kmem_zalloc(sizeof (cachefs_log_control_t), KM_SLEEP);
	lc = (cachefs_log_control_t *)cachep->c_log_ctl;

	/* if the LOG_STATUS_NAME file exists, read it in and set up logging */
	error = VOP_LOOKUP(cachep->c_dirvp, LOG_STATUS_NAME, &statevp,
	    NULL, 0, NULL, kcred, NULL, NULL, NULL);
	if (error == 0) {
		int vnrw_error;

		vnrw_error = vn_rdwr(UIO_READ, statevp, (caddr_t)lc,
		    sizeof (*lc), 0LL, UIO_SYSSPACE, 0, (rlim64_t)RLIM_INFINITY,
		    kcred, NULL);
		VN_RELE(statevp);

		if (vnrw_error == 0) {
			if ((cachep->c_log = cachefs_log_create_cookie(lc))
			    == NULL)
				cachefs_log_error(cachep, ENOMEM, 0);
			else if ((lc->lc_magic != CACHEFS_LOG_MAGIC) ||
			    (lc->lc_path[0] != '/') ||
			    (cachefs_log_logfile_open(cachep,
			    lc->lc_path) != 0))
				cachefs_log_error(cachep, EINVAL, 0);
		}
	} else {
		error = 0;
	}
	lc->lc_magic = CACHEFS_LOG_MAGIC;
	lc->lc_cachep = (uint64_t)(uintptr_t)cachep;
	mutex_exit(&cachep->c_log_mutex);

out:
	if (error == 0) {
		cachep->c_flags &= ~(CACHE_NOCACHE | CACHE_ALLOC_PENDING);
	}
	if (attrp)
		cachefs_kmem_free(attrp, sizeof (struct vattr));
	if (labelvp != NULL)
		VN_RELE(labelvp);
	if (rifvp != NULL)
		VN_RELE(rifvp);
	if (lockvp)
		VN_RELE(lockvp);
	if (lostfoundvp)
		VN_RELE(lostfoundvp);

	mutex_exit(&cachep->c_contentslock);
	return (error);
}

int
cachefs_stop_cache(cnode_t *cp)
{
	fscache_t *fscp = C_TO_FSCACHE(cp);
	cachefscache_t *cachep = fscp->fs_cache;
	filegrp_t *fgp;
	int i;
	clock_t tend;
	int error = 0;

	/* XXX verify lock-ordering for this function */

	mutex_enter(&cachep->c_contentslock);

	/*
	 * no work if we're already in nocache mode.  hopefully this
	 * will be the usual case.
	 */

	if (cachep->c_flags & CACHE_NOCACHE) {
		mutex_exit(&cachep->c_contentslock);
		return (0);
	}

	if ((cachep->c_flags & CACHE_NOFILL) == 0) {
		mutex_exit(&cachep->c_contentslock);
		return (EINVAL);
	}

	mutex_exit(&cachep->c_contentslock);

	/* We are already not caching if nfsv4 */
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) {
		return (0);
	}

#ifdef CFSDEBUG
	mutex_enter(&cachep->c_fslistlock);
	ASSERT(fscp == cachep->c_fslist);
	ASSERT(fscp->fs_next == NULL);
	mutex_exit(&cachep->c_fslistlock);

	printf("cachefs_stop_cache: resetting CACHE_NOCACHE\n");
#endif

	/* XXX should i worry about disconnected during boot? */
	error = cachefs_cd_access(fscp, 1, 1);
	if (error)
		goto out;

	error = cachefs_async_halt(&fscp->fs_workq, 1);
	ASSERT(error == 0);
	error = cachefs_async_halt(&cachep->c_workq, 1);
	ASSERT(error == 0);
	/* sigh -- best to keep going if async_halt failed. */
	error = 0;

	/* XXX current order: cnode, fgp, fscp, cache. okay? */

	cachefs_cnode_traverse(fscp, cachefs_cnode_disable_caching);

	for (i = 0; i < CFS_FS_FGP_BUCKET_SIZE; i++) {
		for (fgp = fscp->fs_filegrp[i]; fgp != NULL;
		fgp = fgp->fg_next) {
			mutex_enter(&fgp->fg_mutex);

			ASSERT((fgp->fg_flags &
			    (CFS_FG_WRITE | CFS_FG_UPDATED)) == 0);
			fgp->fg_flags |=
			    CFS_FG_ALLOC_FILE |
			    CFS_FG_ALLOC_ATTR;
			fgp->fg_flags &= ~CFS_FG_READ;

			if (fgp->fg_dirvp) {
				fgp->fg_flags |= CFS_FG_ALLOC_FILE;
				VN_RELE(fgp->fg_dirvp);
				fgp->fg_dirvp = NULL;
			}
			if (fgp->fg_attrvp) {
				fgp->fg_flags |= CFS_FG_ALLOC_ATTR;
				VN_RELE(fgp->fg_attrvp);
				fgp->fg_attrvp = NULL;
			}

			mutex_exit(&fgp->fg_mutex);
		}
	}

	mutex_enter(&fscp->fs_fslock);
	ASSERT((fscp->fs_flags & (CFS_FS_WRITE)) == 0);
	fscp->fs_flags &= ~(CFS_FS_READ | CFS_FS_DIRTYINFO);

	if (fscp->fs_fscdirvp) {
		VN_RELE(fscp->fs_fscdirvp);
		fscp->fs_fscdirvp = NULL;
	}
	if (fscp->fs_fsattrdir) {
		VN_RELE(fscp->fs_fsattrdir);
		fscp->fs_fsattrdir = NULL;
	}
	if (fscp->fs_infovp) {
		VN_RELE(fscp->fs_infovp);
		fscp->fs_infovp = NULL;
	}
	/* XXX dlog stuff? */

	mutex_exit(&fscp->fs_fslock);

	/*
	 * release resources grabbed in cachefs_cache_activate_ro
	 */

	mutex_enter(&cachep->c_contentslock);

	/* kill off the cachep worker thread */
	while (cachep->c_flags & CACHE_CACHEW_THREADRUN) {
		cachep->c_flags |= CACHE_CACHEW_THREADEXIT;
		cv_signal(&cachep->c_cwcv);
		tend = lbolt + (60 * hz);
		(void) cv_timedwait(&cachep->c_cwhaltcv,
			&cachep->c_contentslock, tend);
	}

	if (cachep->c_resfilevp) {
		VN_RELE(cachep->c_resfilevp);
		cachep->c_resfilevp = NULL;
	}
	if (cachep->c_dirvp) {
		VN_RELE(cachep->c_dirvp);
		cachep->c_dirvp = NULL;
	}
	if (cachep->c_lockvp) {
		VN_RELE(cachep->c_lockvp);
		cachep->c_lockvp = NULL;
	}
	if (cachep->c_lostfoundvp) {
		VN_RELE(cachep->c_lostfoundvp);
		cachep->c_lostfoundvp = NULL;
	}

	mutex_enter(&cachep->c_log_mutex);
	if (cachep->c_log_ctl) {
		cachefs_kmem_free(cachep->c_log_ctl,
		    sizeof (cachefs_log_control_t));
		cachep->c_log_ctl = NULL;
	}
	if (cachep->c_log) {
		cachefs_log_destroy_cookie(cachep->c_log);
		cachep->c_log = NULL;
	}
	mutex_exit(&cachep->c_log_mutex);

	/* XXX do what mountroot_init does when ! foundcache */

	cachep->c_flags |= CACHE_NOCACHE;
	mutex_exit(&cachep->c_contentslock);

	/* XXX should i release this here? */
	cachefs_cd_release(fscp);

out:

	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		cachefs_cache_active_rw
 *
 * Description:
 *	Activates the cachefscache_t object for a read-write file system.
 * Arguments:
 *	cachep	the cachefscache_t object to activate
 * Returns:
 * Preconditions:
 *	precond(cachep)
 *	precond((cachep->c_flags & CACHE_NOCACHE) == 0)
 *	precond(cachep->c_flags & CACHE_NOFILL)
 */

void
cachefs_cache_activate_rw(cachefscache_t *cachep)
{
	cachefs_rl_listhead_t *lhp;

	ASSERT((cachep->c_flags & CACHE_NOCACHE) == 0);
	ASSERT(cachep->c_flags & CACHE_NOFILL);

	mutex_enter(&cachep->c_contentslock);
	cachep->c_flags &= ~CACHE_NOFILL;

	/* move the active list to the rl list */
	cachefs_rl_cleanup(cachep);

	lhp = &cachep->c_rlinfo.rl_items[
	    CACHEFS_RL_INDEX(CACHEFS_RL_PACKED_PENDING)];
	if (lhp->rli_itemcnt != 0)
		cachep->c_flags |= CACHE_PACKED_PENDING;
	cachefs_cache_dirty(cachep, 0);
	mutex_exit(&cachep->c_contentslock);
}

/*
 * ------------------------------------------------------------------
 *
 *		cachefs_cache_dirty
 *
 * Description:
 *	Marks the cache as dirty (active).
 * Arguments:
 *	cachep	the cachefscache_t to mark as dirty
 *	lockit	1 means grab contents lock, 0 means caller grabbed it
 * Returns:
 * Preconditions:
 *	precond(cachep)
 *	precond(cache is in rw mode)
 */

void
cachefs_cache_dirty(struct cachefscache *cachep, int lockit)
{
	int error;

	ASSERT((cachep->c_flags & (CACHE_NOCACHE | CACHE_NOFILL)) == 0);

	if (lockit) {
		mutex_enter(&cachep->c_contentslock);
	} else {
		ASSERT(MUTEX_HELD(&cachep->c_contentslock));
	}
	if (cachep->c_flags & CACHE_DIRTY) {
		ASSERT(cachep->c_usage.cu_flags & CUSAGE_ACTIVE);
	} else {
		/*
		 * turn on the "cache active" (dirty) flag and write it
		 * synchronously to disk
		 */
		cachep->c_flags |= CACHE_DIRTY;
		cachep->c_usage.cu_flags |= CUSAGE_ACTIVE;
		if (error = vn_rdwr(UIO_WRITE, cachep->c_resfilevp,
		    (caddr_t)&cachep->c_usage, sizeof (struct cache_usage),
		    0LL, UIO_SYSSPACE, FSYNC, (rlim64_t)RLIM_INFINITY,
				kcred, NULL)) {
			cmn_err(CE_WARN,
			    "cachefs: clean flag write error: %d\n", error);
		}
	}

	if (lockit)
		mutex_exit(&cachep->c_contentslock);
}

/*
 * ------------------------------------------------------------------
 *
 *		cachefs_cache_rssync
 *
 * Description:
 *	Syncs out the resource file for the cachefscache_t object.
 * Arguments:
 *	cachep	the cachefscache_t object to operate on
 * Returns:
 *	Returns 0 for success, !0 on an error writing data.
 * Preconditions:
 *	precond(cachep)
 *	precond(cache is in rw mode)
 */

int
cachefs_cache_rssync(struct cachefscache *cachep)
{
	int error;

	ASSERT((cachep->c_flags & (CACHE_NOCACHE | CACHE_NOFILL |
	    CACHE_ALLOC_PENDING)) == 0);

	if (cachep->c_rl_entries != NULL) {
		error = vn_rdwr(UIO_WRITE, cachep->c_resfilevp,
		    (caddr_t)cachep->c_rl_entries, MAXBSIZE,
		    (offset_t)((cachep->c_rl_window + 1) * MAXBSIZE),
		    UIO_SYSSPACE, FSYNC, RLIM_INFINITY, kcred, NULL);
		if (error)
		    cmn_err(CE_WARN, "cachefs: Can't Write rl entries Info\n");
		cachefs_kmem_free(cachep->c_rl_entries, MAXBSIZE);
		cachep->c_rl_entries = NULL;
	}

	/* write the usage struct for this cache */
	error = vn_rdwr(UIO_WRITE, cachep->c_resfilevp,
		(caddr_t)&cachep->c_usage, sizeof (struct cache_usage),
		0LL, UIO_SYSSPACE, 0, (rlim64_t)RLIM_INFINITY, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: Can't Write Cache Usage Info\n");
	}

	/* write the rlinfo for this cache */
	error = vn_rdwr(UIO_WRITE, cachep->c_resfilevp,
			(caddr_t)&cachep->c_rlinfo, sizeof (cachefs_rl_info_t),
			(offset_t)sizeof (struct cache_usage), UIO_SYSSPACE,
			0, (rlim64_t)RLIM_INFINITY, kcred, NULL);
	if (error) {
		cmn_err(CE_WARN, "cachefs: Can't Write Cache RL Info\n");
	}
	error = VOP_FSYNC(cachep->c_resfilevp, FSYNC, kcred, NULL);
	return (error);
}

/*
 * ------------------------------------------------------------------
 *
 *		cachefs_cache_sync
 *
 * Description:
 *	Sync a cache which includes all of its fscaches.
 * Arguments:
 *	cachep	the cachefscache_t object to sync
 * Returns:
 * Preconditions:
 *	precond(cachep)
 *	precond(cache is in rw mode)
 */

void
cachefs_cache_sync(struct cachefscache *cachep)
{
	struct fscache *fscp;
	struct fscache **syncfsc;
	int nfscs, fscidx;
	int try;
	int done;

	if (cachep->c_flags & (CACHE_NOCACHE | CACHE_NOFILL))
		return;

	done = 0;
	for (try = 0; (try < 2) && !done; try++) {

		nfscs = 0;

		/*
		 * here we turn off the cache-wide DIRTY flag.  If it's still
		 * off when the sync completes we can write the clean flag to
		 * disk telling fsck it has no work to do.
		 */
#ifdef CFSCLEANFLAG
		mutex_enter(&cachep->c_contentslock);
		cachep->c_flags &= ~CACHE_DIRTY;
		mutex_exit(&cachep->c_contentslock);
#endif /* CFSCLEANFLAG */

		cachefs_log_process_queue(cachep, 1);

		mutex_enter(&cachep->c_fslistlock);
		syncfsc = cachefs_kmem_alloc(
		    cachep->c_refcnt * sizeof (struct fscache *), KM_SLEEP);
		for (fscp = cachep->c_fslist; fscp; fscp = fscp->fs_next) {
			fscache_hold(fscp);
			ASSERT(nfscs < cachep->c_refcnt);
			syncfsc[nfscs++] = fscp;
		}
		ASSERT(nfscs == cachep->c_refcnt);
		mutex_exit(&cachep->c_fslistlock);
		for (fscidx = 0; fscidx < nfscs; fscidx++) {
			fscp = syncfsc[fscidx];
			fscache_sync(fscp);
			fscache_rele(fscp);
		}

		/* get rid of any unused fscache objects */
		mutex_enter(&cachep->c_fslistlock);
		fscache_list_gc(cachep);
		mutex_exit(&cachep->c_fslistlock);

		/*
		 * here we check the cache-wide DIRTY flag.
		 * If it's off,
		 * we can write the clean flag to disk.
		 */
#ifdef CFSCLEANFLAG
		mutex_enter(&cachep->c_contentslock);
		if ((cachep->c_flags & CACHE_DIRTY) == 0) {
			if (cachep->c_usage.cu_flags & CUSAGE_ACTIVE) {
				cachep->c_usage.cu_flags &= ~CUSAGE_ACTIVE;
				if (cachefs_cache_rssync(cachep) == 0) {
					done = 1;
				} else {
					cachep->c_usage.cu_flags |=
						CUSAGE_ACTIVE;
				}
			} else {
				done = 1;
			}
		}
		mutex_exit(&cachep->c_contentslock);
#else /* CFSCLEANFLAG */
		mutex_enter(&cachep->c_contentslock);
		(void) cachefs_cache_rssync(cachep);
		mutex_exit(&cachep->c_contentslock);
		done = 1;
#endif /* CFSCLEANFLAG */
		cachefs_kmem_free(syncfsc, nfscs * sizeof (struct fscache *));
	}
}

/*
 * ------------------------------------------------------------------
 *
 *		cachefs_cache_unique
 *
 * Description:
 * Arguments:
 * Returns:
 *	Returns a unique number.
 * Preconditions:
 *	precond(cachep)
 */

uint_t
cachefs_cache_unique(cachefscache_t *cachep)
{
	uint_t unique = 0;
	int error = 0;

	mutex_enter(&cachep->c_contentslock);
	if (cachep->c_usage.cu_flags & CUSAGE_NEED_ADJUST ||
		++(cachep->c_unique) == 0) {
		cachep->c_usage.cu_unique++;

		if (cachep->c_unique == 0)
			cachep->c_unique = 1;
		cachep->c_flags &= ~CUSAGE_NEED_ADJUST;
		error = cachefs_cache_rssync(cachep);
	}
	if (error == 0)
		unique = (cachep->c_usage.cu_unique << 16) + cachep->c_unique;
	mutex_exit(&cachep->c_contentslock);
	return (unique);
}

/*
 * Called from c_getfrontfile. Shouldn't be called from anywhere else !
 */
static int
cachefs_createfrontfile(cnode_t *cp, struct filegrp *fgp)
{
	char name[CFS_FRONTFILE_NAME_SIZE];
	struct vattr *attrp = NULL;
	int error = 0;
	int mode;
	int alloc = 0;
	int freefile = 0;
	int ffrele = 0;
	int rlfree = 0;
	rl_entry_t rl_ent;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_FRONT)
		printf("c_createfrontfile: ENTER cp %p fgp %p\n",
			(void *)cp, (void *)fgp);
#endif

	ASSERT(cp->c_frontvp == NULL);
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp) == 0);

	/* quit if we cannot write to the filegrp */
	if ((fgp->fg_flags & CFS_FG_WRITE) == 0) {
		error = ENOENT;
		goto out;
	}

	/* find or create the filegrp attrcache file if necessary */
	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
		error = filegrp_allocattr(fgp);
		if (error)
			goto out;
	}

	make_ascii_name(&cp->c_id, name);

	/* set up attributes for the front file we want to create */
	attrp = cachefs_kmem_zalloc(sizeof (struct vattr), KM_SLEEP);
	alloc++;
	attrp->va_mode = S_IFREG | 0666;
	mode = 0666;
	attrp->va_uid = 0;
	attrp->va_gid = 0;
	attrp->va_type = VREG;
	attrp->va_size = 0;
	attrp->va_mask = AT_SIZE | AT_TYPE | AT_MODE | AT_UID | AT_GID;

	/* get a file from the resource counts */
	error = cachefs_allocfile(fgp->fg_fscp->fs_cache);
	if (error) {
		error = EINVAL;
		goto out;
	}
	freefile++;

	/* create the metadata slot if necessary */
	if (cp->c_flags & CN_ALLOC_PENDING) {
		error = filegrp_create_metadata(fgp, &cp->c_metadata,
		    &cp->c_id);
		if (error) {
			error = EINVAL;
			goto out;
		}
		cp->c_flags &= ~CN_ALLOC_PENDING;
		cp->c_flags |= CN_UPDATED;
	}

	/* get an rl entry if necessary */
	if (cp->c_metadata.md_rlno == 0) {
		rl_ent.rl_fileno = cp->c_id.cid_fileno;
		rl_ent.rl_local = (cp->c_id.cid_flags & CFS_CID_LOCAL) ? 1 : 0;
		rl_ent.rl_fsid = fgp->fg_fscp->fs_cfsid;
		rl_ent.rl_attrc = 0;
		error = cachefs_rl_alloc(fgp->fg_fscp->fs_cache, &rl_ent,
		    &cp->c_metadata.md_rlno);
		if (error)
			goto out;
		cachefs_rlent_moveto(fgp->fg_fscp->fs_cache,
		    CACHEFS_RL_ACTIVE, cp->c_metadata.md_rlno,
		    cp->c_metadata.md_frontblks);
		cp->c_metadata.md_rltype = CACHEFS_RL_ACTIVE;
		rlfree++;
		cp->c_flags |= CN_UPDATED; /* XXX sam: do we need this? */

		/* increment number of front files */
		error = filegrp_ffhold(fgp);
		if (error) {
			error = EINVAL;
			goto out;
		}
		ffrele++;
	}

	if (cp->c_flags & CN_ASYNC_POP_WORKING) {
		/* lookup the already created front file */
		error = VOP_LOOKUP(fgp->fg_dirvp, name, &cp->c_frontvp,
		    NULL, 0, NULL, kcred, NULL, NULL, NULL);
	} else {
		/* create the front file */
		error = VOP_CREATE(fgp->fg_dirvp, name, attrp, EXCL, mode,
		    &cp->c_frontvp, kcred, 0, NULL, NULL);
	}
	if (error) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_FRONT)
			printf("c_createfrontfile: Can't create cached object"
			    " error %u, fileno %llx\n", error,
			    (u_longlong_t)cp->c_id.cid_fileno);
#endif
		goto out;
	}

	/* get a copy of the fid of the front file */
	cp->c_metadata.md_fid.fid_len = MAXFIDSZ;
	error = VOP_FID(cp->c_frontvp, &cp->c_metadata.md_fid, NULL);
	if (error) {
		/*
		 * If we get back ENOSPC then the fid we passed in was too
		 * small.  For now we don't do anything and map to EINVAL.
		 */
		if (error == ENOSPC) {
			error = EINVAL;
		}
		goto out;
	}

	dnlc_purge_vp(cp->c_frontvp);

	cp->c_metadata.md_flags |= MD_FILE;
	cp->c_flags |= CN_UPDATED | CN_NEED_FRONT_SYNC;

out:
	if (error) {
		if (cp->c_frontvp) {
			VN_RELE(cp->c_frontvp);
			(void) VOP_REMOVE(fgp->fg_dirvp, name, kcred, NULL, 0);
			cp->c_frontvp = NULL;
		}
		if (ffrele)
			filegrp_ffrele(fgp);
		if (freefile)
			cachefs_freefile(fgp->fg_fscp->fs_cache);
		if (rlfree) {
#ifdef CFSDEBUG
			cachefs_rlent_verify(fgp->fg_fscp->fs_cache,
			    CACHEFS_RL_ACTIVE, cp->c_metadata.md_rlno);
#endif /* CFSDEBUG */
			cachefs_rlent_moveto(fgp->fg_fscp->fs_cache,
			    CACHEFS_RL_FREE, cp->c_metadata.md_rlno, 0);
			cp->c_metadata.md_rlno = 0;
			cp->c_metadata.md_rltype = CACHEFS_RL_NONE;
		}
		cachefs_nocache(cp);
	}
	if (alloc)
		cachefs_kmem_free(attrp, sizeof (struct vattr));
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_FRONT)
		printf("c_createfrontfile: EXIT error = %d name %s\n", error,
			name);
#endif
	return (error);
}

/*
 * Releases resources associated with the front file.
 * Only call this routine if a ffhold has been done.
 * Its okay to call this routine if the front file does not exist.
 * Note: this routine is used even if there is no front file.
 */
void
cachefs_removefrontfile(cachefs_metadata_t *mdp, cfs_cid_t *cidp,
    filegrp_t *fgp)
{
	int error, enoent;
	char name[CFS_FRONTFILE_NAME_SIZE + 2];

	ASSERT(CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp) == 0);

	enoent = 0;
	if (mdp->md_flags & MD_FILE) {
		if (fgp->fg_dirvp == NULL) {
			cmn_err(CE_WARN, "cachefs: remove error, run fsck\n");
			return;
		}
		make_ascii_name(cidp, name);
		error = VOP_REMOVE(fgp->fg_dirvp, name, kcred, NULL, 0);
		if (error == ENOENT)
			enoent = 1;
		if ((error) && (error != ENOENT)) {
			cmn_err(CE_WARN, "UFS remove error %s %d, run fsck\n",
			    name, error);
		}
		if (mdp->md_flags & MD_ACLDIR) {
			(void) strcat(name, ".d");
			error = VOP_RMDIR(fgp->fg_dirvp, name, fgp->fg_dirvp,
			    kcred, NULL, 0);
			if ((error) && (error != ENOENT)) {
				cmn_err(CE_WARN, "frontfs rmdir error %s %d"
				    "; run fsck\n", name, error);
			}
		}
		mdp->md_flags &= ~(MD_FILE | MD_POPULATED | MD_ACL | MD_ACLDIR);
		bzero(&mdp->md_allocinfo, mdp->md_allocents *
			sizeof (struct cachefs_allocmap));
		cachefs_freefile(fgp->fg_fscp->fs_cache);
	}

	/*
	 * Clear packed bit, fastsymlinks and special files
	 * do not have a front file.
	 */
	mdp->md_flags &= ~MD_PACKED;

	/* XXX either rename routine or move this to caller */
	if (enoent == 0)
		filegrp_ffrele(fgp);

	if (mdp->md_frontblks) {
		cachefs_freeblocks(fgp->fg_fscp->fs_cache, mdp->md_frontblks,
		    mdp->md_rltype);
		mdp->md_frontblks = 0;
	}
}

/*
 * This is the interface to the rest of CFS. This takes a cnode, and returns
 * the frontvp (stuffs it in the cnode). This creates an attrcache slot and
 * and frontfile if necessary.
 */

int
cachefs_getfrontfile(cnode_t *cp)
{
	struct filegrp *fgp = cp->c_filegrp;
	int error;
	struct vattr va;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_SUBR)
		printf("c_getfrontfile: ENTER cp %p\n", (void *)cp);
#endif

	ASSERT(CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp) == 0);
	ASSERT(MUTEX_HELD(&cp->c_statelock));

	/*
	 * Now we check to see if there is a front file for this entry.
	 * If there is, we get the vnode for it and stick it in the cnode.
	 * Otherwise, we create a front file, get the vnode for it and stick
	 * it in the cnode.
	 */
	if (cp->c_flags & CN_STALE) {
		cp->c_flags |= CN_NOCACHE;
		error = ESTALE;
		goto out;
	}

	/*
	 * If the cnode is being populated, and we're not the populating
	 * thread, then block until the pop thread completes.  If we are the
	 * pop thread, then we may come in here, but not to nuke the directory
	 * cnode at a critical juncture.  If we return from a cv_wait and the
	 * cnode is now stale, don't bother trying to get the front file.
	 */
	while ((cp->c_flags & CN_ASYNC_POP_WORKING) &&
	    (cp->c_popthrp != curthread)) {
		cv_wait(&cp->c_popcv, &cp->c_statelock);
		if (cp->c_flags & CN_STALE) {
			cp->c_flags |= CN_NOCACHE;
			error = ESTALE;
			goto out;
		}
	}

	if ((cp->c_metadata.md_flags & MD_FILE) == 0) {
#ifdef CFSDEBUG
		if (cp->c_frontvp != NULL)
			CFS_DEBUG(CFSDEBUG_FRONT)
				printf(
		"c_getfrontfile: !MD_FILE and frontvp not null cp %p\n",
				    (void *)cp);
#endif
		if (CTOV(cp)->v_type == VDIR)
			ASSERT((cp->c_metadata.md_flags & MD_POPULATED) == 0);
		error = cachefs_createfrontfile(cp, fgp);
		if (error)
			goto out;
	} else {
		/*
		 * A front file exists, all we need to do is to grab the fid,
		 * do a VFS_VGET() on the fid, stuff the vnode in the cnode,
		 * and return.
		 */
		if (fgp->fg_dirvp == NULL) {
			cmn_err(CE_WARN, "cachefs: gff0: corrupted file system"
				" run fsck\n");
			cachefs_inval_object(cp);
			cp->c_flags |= CN_NOCACHE;
			error = ESTALE;
			goto out;
		}
		error = VFS_VGET(fgp->fg_dirvp->v_vfsp, &cp->c_frontvp,
				&cp->c_metadata.md_fid);
		if (error || (cp->c_frontvp == NULL)) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_FRONT)
				printf("cachefs: "
				    "gff1: front file system error %d\n",
				    error);
#endif /* CFSDEBUG */
			cachefs_inval_object(cp);
			cp->c_flags |= CN_NOCACHE;
			error = ESTALE;
			goto out;
		}

		/* don't need to check timestamps if need_front_sync is set */
		if (cp->c_flags & CN_NEED_FRONT_SYNC) {
			error = 0;
			goto out;
		}

		/* don't need to check empty directories */
		if (CTOV(cp)->v_type == VDIR &&
		    ((cp->c_metadata.md_flags & MD_POPULATED) == 0)) {
			error = 0;
			goto out;
		}

		/* get modify time of the front file */
		va.va_mask = AT_MTIME;
		error = VOP_GETATTR(cp->c_frontvp, &va, 0, kcred, NULL);
		if (error) {
			cmn_err(CE_WARN, "cachefs: gff2: front file"
				" system error %d", error);
			cachefs_inval_object(cp);
			error = (cp->c_flags & CN_NOCACHE) ? ESTALE : 0;
			goto out;
		}

		/* compare with modify time stored in metadata */
		if (bcmp(&va.va_mtime, &cp->c_metadata.md_timestamp,
		    sizeof (timestruc_t)) != 0) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_GENERAL | CFSDEBUG_INVALIDATE) {
				long sec, nsec;
				sec = cp->c_metadata.md_timestamp.tv_sec;
				nsec = cp->c_metadata.md_timestamp.tv_nsec;
				printf("c_getfrontfile: timestamps don't"
					" match fileno %lld va %lx %lx"
					" meta %lx %lx\n",
					(u_longlong_t)cp->c_id.cid_fileno,
					va.va_mtime.tv_sec,
					va.va_mtime.tv_nsec, sec, nsec);
			}
#endif
			cachefs_inval_object(cp);
			error = (cp->c_flags & CN_NOCACHE) ? ESTALE : 0;
		}
	}
out:

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_FRONT)
		printf("c_getfrontfile: EXIT error = %d\n", error);
#endif
	return (error);
}

void
cachefs_inval_object(cnode_t *cp)
{
	cachefscache_t *cachep = C_TO_FSCACHE(cp)->fs_cache;
	struct filegrp *fgp = cp->c_filegrp;
	int error;

	ASSERT(CFS_ISFS_BACKFS_NFSV4(C_TO_FSCACHE(cp)) == 0);
	ASSERT(MUTEX_HELD(&cp->c_statelock));
	ASSERT((cp->c_flags & CN_ASYNC_POP_WORKING) == 0 ||
		cp->c_popthrp == curthread);
#if 0
	CFS_DEBUG(CFSDEBUG_SUBR)
		printf("c_inval_object: ENTER cp %p\n", (void *)cp);
	if (cp->c_flags & (CN_ASYNC_POPULATE | CN_ASYNC_POP_WORKING))
		debug_enter("inval object during async pop");
#endif
	cp->c_flags |= CN_NOCACHE;

	/* if we cannot modify the cache */
	if (C_TO_FSCACHE(cp)->fs_cache->c_flags &
	    (CACHE_NOFILL | CACHE_NOCACHE)) {
		goto out;
	}

	/* if there is a front file */
	if (cp->c_metadata.md_flags & MD_FILE) {
		if (fgp->fg_dirvp == NULL)
			goto out;

		/* get the front file vp if necessary */
		if (cp->c_frontvp == NULL) {

			error = VFS_VGET(fgp->fg_dirvp->v_vfsp, &cp->c_frontvp,
				&cp->c_metadata.md_fid);
			if (error || (cp->c_frontvp == NULL)) {
#ifdef CFSDEBUG
				CFS_DEBUG(CFSDEBUG_FRONT)
					printf("cachefs: "
					    "io: front file error %d\n", error);
#endif /* CFSDEBUG */
				goto out;
			}
		}

		/* truncate the file to zero size */
		error = cachefs_frontfile_size(cp, 0);
		if (error)
			goto out;
		cp->c_flags &= ~CN_NOCACHE;

		/* if a directory, v_type is zero if called from initcnode */
		if (cp->c_attr.va_type == VDIR) {
			if (cp->c_usage < CFS_DIRCACHE_COST) {
				cp->c_invals++;
				if (cp->c_invals > CFS_DIRCACHE_INVAL) {
					cp->c_invals = 0;
				}
			} else
				cp->c_invals = 0;
			cp->c_usage = 0;
		}
	} else {
		cp->c_flags &= ~CN_NOCACHE;
	}

out:
	if ((cp->c_metadata.md_flags & MD_PACKED) &&
	    (cp->c_metadata.md_rltype != CACHEFS_RL_MODIFIED) &&
	    ((cachep->c_flags & CACHE_NOFILL) == 0)) {
		ASSERT(cp->c_metadata.md_rlno != 0);
		if (cp->c_metadata.md_rltype != CACHEFS_RL_PACKED_PENDING) {
			cachefs_rlent_moveto(cachep,
			    CACHEFS_RL_PACKED_PENDING,
			    cp->c_metadata.md_rlno,
			    cp->c_metadata.md_frontblks);
			cp->c_metadata.md_rltype = CACHEFS_RL_PACKED_PENDING;
			/* unconditionally set CN_UPDATED below */
		}
	}

	cachefs_purgeacl(cp);

	if (cp->c_flags & CN_ASYNC_POP_WORKING)
		cp->c_flags |= CN_NOCACHE;
	cp->c_metadata.md_flags &= ~(MD_POPULATED | MD_INVALREADDIR |
	    MD_FASTSYMLNK);
	cp->c_flags &= ~CN_NEED_FRONT_SYNC;
	cp->c_flags |= CN_UPDATED;

	/*
	 * If the object invalidated is a directory, the dnlc should be purged
	 * to elide all references to this (directory) vnode.
	 */
	if (CTOV(cp)->v_type == VDIR)
		dnlc_purge_vp(CTOV(cp));

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_SUBR)
		printf("c_inval_object: EXIT\n");
#endif
}

void
make_ascii_name(cfs_cid_t *cidp, char *strp)
{
	int i = sizeof (uint_t) * 4;
	u_longlong_t index;
	ino64_t name;

	if (cidp->cid_flags & CFS_CID_LOCAL)
		*strp++ = 'L';
	name = (ino64_t)cidp->cid_fileno;
	do {
		index = (((u_longlong_t)name) & 0xf000000000000000) >> 60;
		index &= (u_longlong_t)0xf;
		ASSERT(index < (u_longlong_t)16);
		*strp++ = "0123456789abcdef"[index];
		name <<= 4;
	} while (--i);
	*strp = '\0';
}

void
cachefs_nocache(cnode_t *cp)
{
	fscache_t *fscp = C_TO_FSCACHE(cp);
	cachefscache_t *cachep = fscp->fs_cache;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_SUBR)
		printf("c_nocache: ENTER cp %p\n", (void *)cp);
#endif

	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);
	ASSERT(MUTEX_HELD(&cp->c_statelock));
	if ((cp->c_flags & CN_NOCACHE) == 0) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_INVALIDATE)
			printf("cachefs_nocache: invalidating %llu\n",
			    (u_longlong_t)cp->c_id.cid_fileno);
#endif
		/*
		 * Here we are waiting until inactive time to do
		 * the inval_object.  In case we don't get to inactive
		 * (because of a crash, say) we set up a timestamp mismatch
		 * such that getfrontfile will blow the front file away
		 * next time we try to use it.
		 */
		cp->c_metadata.md_timestamp.tv_sec = 0;
		cp->c_metadata.md_timestamp.tv_nsec = 0;
		cp->c_metadata.md_flags &= ~(MD_POPULATED | MD_INVALREADDIR |
		    MD_FASTSYMLNK);
		cp->c_flags &= ~CN_NEED_FRONT_SYNC;

		cachefs_purgeacl(cp);

		/*
		 * It is possible we can nocache while disconnected.
		 * A directory could be nocached by running out of space.
		 * A regular file should only be nocached if an I/O error
		 * occurs to the front fs.
		 * We count on the item staying on the modified list
		 * so we do not loose the cid to fid mapping for directories.
		 */

		if ((cp->c_metadata.md_flags & MD_PACKED) &&
		    (cp->c_metadata.md_rltype != CACHEFS_RL_MODIFIED) &&
		    ((cachep->c_flags & CACHE_NOFILL) == 0)) {
			ASSERT(cp->c_metadata.md_rlno != 0);
			if (cp->c_metadata.md_rltype !=
			    CACHEFS_RL_PACKED_PENDING) {
				cachefs_rlent_moveto(cachep,
				    CACHEFS_RL_PACKED_PENDING,
				    cp->c_metadata.md_rlno,
				    cp->c_metadata.md_frontblks);
				cp->c_metadata.md_rltype =
				    CACHEFS_RL_PACKED_PENDING;
				/* unconditionally set CN_UPDATED below */
			}
		}

		if (CTOV(cp)->v_type == VDIR)
			dnlc_purge_vp(CTOV(cp));
		cp->c_flags |= (CN_NOCACHE | CN_UPDATED);
	}

	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_NOCACHE))
		cachefs_log_nocache(cachep, 0, fscp->fs_cfsvfsp,
		    &cp->c_metadata.md_cookie, cp->c_id.cid_fileno);

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_SUBR)
		printf("c_nocache: EXIT cp %p\n", (void *)cp);
#endif
}

/*
 * Checks to see if the page is in the disk cache, by checking the allocmap.
 */
int
cachefs_check_allocmap(cnode_t *cp, u_offset_t off)
{
	int i;
	size_t dbl_size_to_look = cp->c_attr.va_size - off;
	uint_t	size_to_look;

	if (dbl_size_to_look > (u_offset_t)PAGESIZE)
		size_to_look = (uint_t)PAGESIZE;
	else
		/*LINTED alignment okay*/
		size_to_look = (uint_t)dbl_size_to_look;

	for (i = 0; i < cp->c_metadata.md_allocents; i++) {
		struct cachefs_allocmap *allocp =
				cp->c_metadata.md_allocinfo + i;

		if (off >= allocp->am_start_off) {
			if ((off + size_to_look) <=
			    (allocp->am_start_off + allocp->am_size)) {
				struct fscache *fscp = C_TO_FSCACHE(cp);
				cachefscache_t *cachep = fscp->fs_cache;

				if (CACHEFS_LOG_LOGGING(cachep,
				    CACHEFS_LOG_CALLOC))
					cachefs_log_calloc(cachep, 0,
					    fscp->fs_cfsvfsp,
					    &cp->c_metadata.md_cookie,
					    cp->c_id.cid_fileno,
					    off, size_to_look);
			/*
			 * Found the page in the CFS disk cache.
			 */
				return (1);
			}
		} else {
			return (0);
		}
	}
	return (0);
}

/*
 * Merges adjacent allocmap entries together where possible, e.g.
 *   offset=0x0,     size=0x40000
 *   offset=0x40000, size=0x20000	becomes just offset=0x0, size-0x90000
 *   offset=0x60000, size=0x30000
 */


void
cachefs_coalesce_allocmap(struct cachefs_metadata *cmd)
{
	int i, reduced = 0;
	struct cachefs_allocmap *allocp, *nallocp;

	nallocp = allocp = cmd->md_allocinfo;
	allocp++;
	for (i = 1; i < cmd->md_allocents; i++, allocp++) {
		if (nallocp->am_start_off + nallocp->am_size ==
						allocp->am_start_off) {
			nallocp->am_size += allocp->am_size;
			reduced++;
		} else {
			nallocp++;
			nallocp->am_start_off = allocp->am_start_off;
			nallocp->am_size = allocp->am_size;
		}
	}
	cmd->md_allocents -= reduced;
}

/*
 * Updates the allocmap to reflect a new chunk of data that has been
 * populated.
 */
void
cachefs_update_allocmap(cnode_t *cp, u_offset_t off, size_t size)
{
	int i;
	struct cachefs_allocmap *allocp;
	struct fscache *fscp =  C_TO_FSCACHE(cp);
	cachefscache_t *cachep = fscp->fs_cache;
	u_offset_t saveoff;
	u_offset_t savesize;
	u_offset_t logoff = off;
	size_t logsize = size;
	u_offset_t endoff;
	u_offset_t tmpendoff;

	/*
	 * We try to see if we can coalesce the current block into an existing
	 * allocation and mark it as such.
	 * If we can't do that then we make a new entry in the allocmap.
	 * when we run out of allocmaps, put the cnode in NOCACHE mode.
	 */
again:
	allocp = cp->c_metadata.md_allocinfo;
	for (i = 0; i < cp->c_metadata.md_allocents; i++, allocp++) {

		if (off <= (allocp->am_start_off)) {
			endoff = off + size;
			if (endoff >= allocp->am_start_off) {
				tmpendoff = allocp->am_start_off +
						allocp->am_size;
				if (endoff < tmpendoff)
					endoff = tmpendoff;
				allocp->am_size = endoff - off;
				allocp->am_start_off = off;
				cachefs_coalesce_allocmap(&cp->c_metadata);
				allocp = cp->c_metadata.md_allocinfo;
				if (allocp->am_size >= cp->c_size)
					cp->c_metadata.md_flags |= MD_POPULATED;
				return;
			} else {
				saveoff = off;
				savesize = size;
				off = allocp->am_start_off;
				size = allocp->am_size;
				allocp->am_size = savesize;
				allocp->am_start_off = saveoff;
				goto again;
			}
		} else {
			endoff = allocp->am_start_off + allocp->am_size;
			if (off < endoff) {
				tmpendoff = off + size;
				if (endoff < tmpendoff)
					endoff = tmpendoff;
				allocp->am_size = endoff - allocp->am_start_off;
				cachefs_coalesce_allocmap(&cp->c_metadata);
				allocp = cp->c_metadata.md_allocinfo;
				if (allocp->am_size >= cp->c_size)
					cp->c_metadata.md_flags |= MD_POPULATED;
				return;
			}
			if (off == (allocp->am_start_off + allocp->am_size)) {
				allocp->am_size += size;
				cachefs_coalesce_allocmap(&cp->c_metadata);
				allocp = cp->c_metadata.md_allocinfo;
				if (allocp->am_size >= cp->c_size)
					cp->c_metadata.md_flags |= MD_POPULATED;
				return;
			}
		}
	}
	if (i == C_MAX_ALLOCINFO_SLOTS) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_ALLOCMAP)
			printf("c_update_alloc_map: "
			    "Too many allinfo entries cp %p fileno %llu %p\n",
			    (void *)cp, (u_longlong_t)cp->c_id.cid_fileno,
			    (void *)cp->c_metadata.md_allocinfo);
#endif
		cachefs_nocache(cp);
		return;
	}
	allocp->am_start_off = off;
	allocp->am_size = (u_offset_t)size;
	if (allocp->am_size >= cp->c_size)
		cp->c_metadata.md_flags |= MD_POPULATED;
	cp->c_metadata.md_allocents++;

	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_UALLOC))
		cachefs_log_ualloc(cachep, 0, fscp->fs_cfsvfsp,
		    &cp->c_metadata.md_cookie, cp->c_id.cid_fileno,
		    logoff, logsize);
}

/*
 * CFS population function
 *
 * before async population, this function used to turn on the cnode
 * flags CN_UPDATED, CN_NEED_FRONT_SYNC, and CN_POPULATION_PENDING.
 * now, however, it's the responsibility of the caller to do this if
 * this function returns 0 (no error).
 */

int
cachefs_populate(cnode_t *cp, u_offset_t off, size_t popsize, vnode_t *frontvp,
    vnode_t *backvp, u_offset_t cpsize, cred_t *cr)
{
	int error = 0;
	caddr_t addr;
	u_offset_t upto;
	uint_t size;
	u_offset_t from = off;
	cachefscache_t *cachep = C_TO_FSCACHE(cp)->fs_cache;
	ssize_t resid;
	struct fbuf *fbp;
	caddr_t buf = kmem_alloc(MAXBSIZE, KM_SLEEP);

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_VOPS)
		printf("cachefs_populate: ENTER cp %p off %lld\n",
		    (void *)cp, off);
#endif

	upto = MIN((off + popsize), cpsize);

	while (from < upto) {
		u_offset_t blkoff = (from & (offset_t)MAXBMASK);
		uint_t n = from - blkoff;

		size = upto - from;
		if (upto > (blkoff + MAXBSIZE))
			size = MAXBSIZE - n;

		error = fbread(backvp, (offset_t)blkoff, n + size,
			S_OTHER, &fbp);
		if (CFS_TIMEOUT(C_TO_FSCACHE(cp), error))
			goto out;
		else if (error) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_BACK)
				printf("cachefs_populate: fbread error %d\n",
				    error);
#endif
			goto out;
		}

		addr = fbp->fb_addr;
		ASSERT(addr != NULL);
		ASSERT(n + size <= MAXBSIZE);
		bcopy(addr, buf, n + size);
		fbrelse(fbp, S_OTHER);

		if (n == 0 || cachefs_check_allocmap(cp, blkoff) == 0) {
			if (error = cachefs_allocblocks(cachep, 1,
			    cp->c_metadata.md_rltype))
				goto out;
			cp->c_metadata.md_frontblks++;
		}
		resid = 0;
		error = vn_rdwr(UIO_WRITE, frontvp, buf + n, size,
				(offset_t)from, UIO_SYSSPACE, 0,
				(rlim64_t)RLIM64_INFINITY, cr, &resid);
		if (error) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_FRONT)
				printf("cachefs_populate: "
				    "Got error = %d from vn_rdwr\n", error);
#endif
			goto out;
		}
#ifdef CFSDEBUG
		if (resid)
			CFS_DEBUG(CFSDEBUG_FRONT)
				printf("cachefs_populate: non-zero resid %ld\n",
				    resid);
#endif
		from += size;
	}
	(void) cachefs_update_allocmap(cp, off, upto - off);
out:
	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_POPULATE))
		cachefs_log_populate(cachep, error,
		    C_TO_FSCACHE(cp)->fs_cfsvfsp,
		    &cp->c_metadata.md_cookie, cp->c_id.cid_fileno, off,
		    popsize);

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_VOPS)
		printf("cachefs_populate: EXIT cp %p error %d\n",
		    (void *)cp, error);
#endif
	kmem_free(buf, MAXBSIZE);

	return (error);
}

/*
 * due to compiler error we shifted cnode to the last argument slot.
 * occurred during large files project - XXX.
 */
void
cachefs_cluster_allocmap(u_offset_t off, u_offset_t *popoffp,
    size_t *popsizep, size_t size, struct cnode *cp)
{
	int i;
	u_offset_t lastoff = 0;
	u_offset_t forward_diff = 0;
	u_offset_t backward_diff = 0;

	ASSERT(size <= C_TO_FSCACHE(cp)->fs_info.fi_popsize);

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_SUBR)
		printf("cachefs_cluster_allocmap: off %llx, size %llx, "
			"c_size %llx\n", off, size, (longlong_t)cp->c_size);
#endif /* CFSDEBUG */
	for (i = 0; i < cp->c_metadata.md_allocents; i++) {
		struct cachefs_allocmap *allocp =
			cp->c_metadata.md_allocinfo + i;

		if (allocp->am_start_off > off) {
			if ((off + size) > allocp->am_start_off) {
				forward_diff = allocp->am_start_off - off;
				backward_diff = size - forward_diff;
				if (backward_diff > off)
					backward_diff = off;
				if (lastoff > (off - backward_diff))
					backward_diff = off - lastoff;
			} else {
				forward_diff = size;
			}
			*popoffp = (off - backward_diff) & (offset_t)PAGEMASK;
			*popsizep = ((off + forward_diff) - *popoffp) &
				(offset_t)PAGEMASK;
			return;
		} else {
			lastoff = allocp->am_start_off + allocp->am_size;
		}
	}
	if ((lastoff + size) > off) {
		*popoffp = (lastoff & (offset_t)PAGEMASK);
	} else {
		 *popoffp = off & (offset_t)PAGEMASK;
	}

	/*
	 * 64bit project: popsize is the chunk size used to populate the
	 * cache (default 64K). As such, 32 bit should suffice.
	 */
	if ((*popoffp + size) > cp->c_size)
		*popsizep = (cp->c_size - *popoffp + PAGEOFFSET) &
			(offset_t)PAGEMASK;
	else if (size < PAGESIZE)
		*popsizep = (size + PAGEOFFSET) &
			(offset_t)PAGEMASK;
	else
		*popsizep = size & (offset_t)PAGEMASK;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_SUBR)
		printf("cachefs_cluster_allocmap: popoff %llx, popsize %llx\n",
			(u_longlong_t)(*popoffp), (u_longlong_t)(*popsizep));
#endif /* CFSDEBUG */
}

/*
 * "populate" a symlink in the cache
 */
int
cachefs_stuffsymlink(cnode_t *cp, caddr_t buf, int buflen)
{
	int error = 0;
	struct fscache *fscp = C_TO_FSCACHE(cp);
	cachefscache_t *cachep = fscp->fs_cache;
	struct cachefs_metadata *mdp = &cp->c_metadata;

	ASSERT(RW_WRITE_HELD(&cp->c_rwlock));
	ASSERT(MUTEX_HELD(&cp->c_statelock));

	if (CFS_ISFS_BACKFS_NFSV4(fscp))
		goto out;

	if (cp->c_flags & CN_NOCACHE)
		return (ENOENT);

	cp->c_size = (u_offset_t)buflen;

	/* if can create a fast sym link */
	if (buflen <= C_FSL_SIZE) {
		/* give up the front file resources */
		if (mdp->md_rlno) {
			cachefs_removefrontfile(mdp, &cp->c_id, cp->c_filegrp);
			cachefs_rlent_moveto(cachep, CACHEFS_RL_FREE,
			    mdp->md_rlno, 0);
			mdp->md_rlno = 0;
			mdp->md_rltype = CACHEFS_RL_NONE;
		}
		/* put sym link contents in allocinfo in metadata */
		bzero(mdp->md_allocinfo, C_FSL_SIZE);
		bcopy(buf, mdp->md_allocinfo, buflen);

		mdp->md_flags |= MD_FASTSYMLNK;
		cp->c_flags &= ~CN_NEED_FRONT_SYNC;
		cp->c_flags |= CN_UPDATED;
		goto out;
	}

	/* else create a sym link in a front file */
	if (cp->c_frontvp == NULL)
		error = cachefs_getfrontfile(cp);
	if (error)
		goto out;

	/* truncate front file */
	error = cachefs_frontfile_size(cp, 0);
	mdp->md_flags &= ~(MD_FASTSYMLNK | MD_POPULATED);
	if (error)
		goto out;

	/* get space for the sym link */
	error = cachefs_allocblocks(cachep, 1, cp->c_metadata.md_rltype);
	if (error)
		goto out;

	/* write the sym link to the front file */
	error = vn_rdwr(UIO_WRITE, cp->c_frontvp, buf, buflen, 0,
	    UIO_SYSSPACE, 0, RLIM_INFINITY, kcred, NULL);
	if (error) {
		cachefs_freeblocks(cachep, 1, cp->c_metadata.md_rltype);
		goto out;
	}

	cp->c_metadata.md_flags |= MD_POPULATED;
	cp->c_flags |= CN_NEED_FRONT_SYNC;
	cp->c_flags |= CN_UPDATED;

out:
	if (CACHEFS_LOG_LOGGING(cachep, CACHEFS_LOG_CSYMLINK))
		cachefs_log_csymlink(cachep, error, fscp->fs_cfsvfsp,
		    &cp->c_metadata.md_cookie, cp->c_id.cid_fileno, buflen);

	return (error);
}

/*
 * Reads the full contents of the symbolic link from the back file system.
 * *bufp is set to a MAXPATHLEN buffer that must be freed when done
 * *buflenp is the length of the link
 */
int
cachefs_readlink_back(cnode_t *cp, cred_t *cr, caddr_t *bufp, int *buflenp)
{
	int error;
	struct uio uio;
	struct iovec iov;
	caddr_t buf;
	fscache_t *fscp = C_TO_FSCACHE(cp);

	ASSERT(MUTEX_HELD(&cp->c_statelock));

	*bufp = NULL;

	/* get back vnode */
	if (cp->c_backvp == NULL) {
		error = cachefs_getbackvp(fscp, cp);
		if (error)
			return (error);
	}

	/* set up for the readlink */
	bzero(&uio, sizeof (struct uio));
	bzero(&iov, sizeof (struct iovec));
	buf = cachefs_kmem_alloc(MAXPATHLEN, KM_SLEEP);
	iov.iov_base = buf;
	iov.iov_len = MAXPATHLEN;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = MAXPATHLEN;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_loffset = 0;
	uio.uio_fmode = 0;
	uio.uio_extflg = UIO_COPY_CACHED;
	uio.uio_llimit = MAXOFFSET_T;

	/* get the link data */
	CFS_DPRINT_BACKFS_NFSV4(fscp,
		("cachefs_readlink (nfsv4): cnode %p, backvp %p\n",
		cp, cp->c_backvp));
	error = VOP_READLINK(cp->c_backvp, &uio, cr, NULL);
	if (error) {
		cachefs_kmem_free(buf, MAXPATHLEN);
	} else {
		*bufp = buf;
		/*LINTED alignment okay*/
		*buflenp = MAXPATHLEN - (int)uio.uio_resid;
	}

	return (error);
}

int
cachefs_getbackvp(struct fscache *fscp, struct cnode *cp)
{
	int error = 0;
	int flag;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_CHEAT | CFSDEBUG_BACK)
		printf("cachefs_getbackvp: ENTER fscp %p cp %p\n",
		    (void *)fscp, (void *)cp);
#endif
	ASSERT(cp != NULL);
	ASSERT(MUTEX_HELD(&cp->c_statelock));
	ASSERT(cp->c_backvp == NULL);
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	/*
	 * If destroy is set then the last link to a file has been
	 * removed.  Oddly enough NFS will still return a vnode
	 * for the file if the timeout has not expired.
	 * This causes headaches for cachefs_push because the
	 * vnode is really stale.
	 * So we just short circuit the problem here.
	 */
	if (cp->c_flags & CN_DESTROY)
		return (ESTALE);

	ASSERT(fscp->fs_backvfsp);
	if (fscp->fs_backvfsp == NULL)
		return (ETIMEDOUT);
	error = VFS_VGET(fscp->fs_backvfsp, &cp->c_backvp,
	    (struct fid *)&cp->c_cookie);
	if (cp->c_backvp && cp->c_cred &&
	    ((cp->c_flags & CN_NEEDOPEN) || (cp->c_attr.va_type == VREG))) {
		/*
		 * XXX bob: really should pass in the correct flag,
		 * fortunately nobody pays attention to it
		 */
		flag = 0;
		/*
		 * If NEEDOOPEN is set, then this file was opened VOP_OPEN'd
		 * but the backvp was not.  So, for the sake of the vnode
		 * open counts used by delegation, we need to OPEN the backvp
		 * with the same flags that were used for this cnode.  That way
		 * when the file is VOP_CLOSE'd the counts won't go negative.
		 */
		if (cp->c_flags & CN_NEEDOPEN) {
			cp->c_flags &= ~CN_NEEDOPEN;
			if (cp->c_rdcnt > 0) {
				cp->c_rdcnt--;
				flag |= FREAD;
			}
			if (cp->c_wrcnt > 0) {
				cp->c_wrcnt--;
				flag |= FWRITE;
			}
		}
		error = VOP_OPEN(&cp->c_backvp, flag, cp->c_cred, NULL);
		if (error) {
			VN_RELE(cp->c_backvp);
			cp->c_backvp = NULL;
		}
	}

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_GENERAL | CFSDEBUG_BACK) {
		if (error || cp->c_backvp == NULL) {
			printf("Stale cookie cp %p fileno %llu type %d \n",
			    (void *)cp, (u_longlong_t)cp->c_id.cid_fileno,
			    CTOV(cp)->v_type);
		}
	}
#endif

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_CHEAT | CFSDEBUG_BACK)
		printf("cachefs_getbackvp: EXIT error = %d\n", error);
#endif
	return (error);
}

int
cachefs_getcookie(
	vnode_t *vp,
	struct fid *cookiep,
	struct vattr *attrp,
	cred_t *cr,
	uint32_t valid_fid)
{
	int error = 0;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_CHEAT)
		printf("cachefs_getcookie: ENTER vp %p\n", (void *)vp);
#endif
	/*
	 * Get the FID only if the caller has indicated it is valid,
	 * otherwise, zero the cookie.
	 */
	if (valid_fid) {
		/*
		 * This assumes that the cookie is a full size fid, if we go to
		 * variable length fids we will need to change this.
		 */
		cookiep->fid_len = MAXFIDSZ;
		error = VOP_FID(vp, cookiep, NULL);
	} else {
		bzero(cookiep, sizeof (*cookiep));
	}

	if (!error) {
		if (attrp) {
			ASSERT(attrp != NULL);
			attrp->va_mask = AT_ALL;
			error = VOP_GETATTR(vp, attrp, 0, cr, NULL);
		}
	} else {
		if (error == ENOSPC) {
			/*
			 * This is an indication that the underlying filesystem
			 * needs a bigger fid.  For now just map to EINVAL.
			 */
			error = EINVAL;
		}
	}
#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_CHEAT)
		printf("cachefs_getcookie: EXIT error = %d\n", error);
#endif
	return (error);
}

void
cachefs_workq_init(struct cachefs_workq *qp)
{
	qp->wq_head = qp->wq_tail = NULL;
	qp->wq_length =
	    qp->wq_thread_count =
	    qp->wq_max_len =
	    qp->wq_halt_request = 0;
	qp->wq_keepone = 0;
	cv_init(&qp->wq_req_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&qp->wq_halt_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&qp->wq_queue_lock, NULL, MUTEX_DEFAULT, NULL);
}

/*
 * return non-zero if it's `okay' to queue more requests (policy)
 */

static int cachefs_async_max = 512;
static int cachefs_async_count = 0;
kmutex_t cachefs_async_lock;

int
cachefs_async_okay(void)
{
	/*
	 * a value of -1 for max means to ignore freemem
	 */

	if (cachefs_async_max == -1)
		return (1);

	if (freemem < minfree)
		return (0);

	/*
	 * a value of 0 for max means no arbitrary limit (only `freemen')
	 */

	if (cachefs_async_max == 0)
		return (1);

	ASSERT(cachefs_async_max > 0);

	/*
	 * check the global count against the max.
	 *
	 * we don't need to grab cachefs_async_lock -- we're just
	 * looking, and a little bit of `fuzz' is okay.
	 */

	if (cachefs_async_count >= cachefs_async_max)
		return (0);

	return (1);
}

void
cachefs_async_start(struct cachefs_workq *qp)
{
	struct cachefs_req *rp;
	int left;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &qp->wq_queue_lock, callb_generic_cpr, "cas");
	mutex_enter(&qp->wq_queue_lock);
	left = 1;
	for (;;) {
		/* if there are no pending requests */
		if ((qp->wq_head == NULL) && (qp->wq_logwork == 0)) {
			/* see if thread should exit */
			if (qp->wq_halt_request || (left == -1)) {
				if ((qp->wq_thread_count > 1) ||
				    (qp->wq_keepone == 0))
					break;
			}

			/* wake up thread in async_halt if necessary */
			if (qp->wq_halt_request)
				cv_broadcast(&qp->wq_halt_cv);

			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			/* sleep until there is something to do */
			left = cv_timedwait(&qp->wq_req_cv,
				&qp->wq_queue_lock, CFS_ASYNC_TIMEOUT + lbolt);
			CALLB_CPR_SAFE_END(&cprinfo,
				&qp->wq_queue_lock);
			if ((qp->wq_head == NULL) && (qp->wq_logwork == 0))
				continue;
		}
		left = 1;

		if (qp->wq_logwork) {
			qp->wq_logwork = 0;
			mutex_exit(&qp->wq_queue_lock);
			cachefs_log_process_queue(qp->wq_cachep, 1);
			mutex_enter(&qp->wq_queue_lock);
			continue;
		}

		/* remove request from the list */
		rp = qp->wq_head;
		qp->wq_head = rp->cfs_next;
		if (rp->cfs_next == NULL)
			qp->wq_tail = NULL;

		/* do the request */
		mutex_exit(&qp->wq_queue_lock);
		cachefs_do_req(rp);
		mutex_enter(&qp->wq_queue_lock);

		/* decrement count of requests */
		qp->wq_length--;
		mutex_enter(&cachefs_async_lock);
		--cachefs_async_count;
		mutex_exit(&cachefs_async_lock);
	}
	ASSERT(qp->wq_head == NULL);
	qp->wq_thread_count--;
	if (qp->wq_halt_request && qp->wq_thread_count == 0)
		cv_broadcast(&qp->wq_halt_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
	/*NOTREACHED*/
}

/*
 * attempt to halt all the async threads associated with a given workq
 */
int
cachefs_async_halt(struct cachefs_workq *qp, int force)
{
	int error = 0;
	clock_t tend;

	mutex_enter(&qp->wq_queue_lock);
	if (force)
		qp->wq_keepone = 0;

	if (qp->wq_thread_count > 0) {
		qp->wq_halt_request++;
		cv_broadcast(&qp->wq_req_cv);
		tend = lbolt + (60 * hz);
		(void) cv_timedwait(&qp->wq_halt_cv,
			&qp->wq_queue_lock, tend);
		qp->wq_halt_request--;
		if (qp->wq_thread_count > 0) {
			if ((qp->wq_thread_count == 1) &&
			    (qp->wq_length == 0) && qp->wq_keepone)
				error = EAGAIN;
			else
				error = EBUSY;
		} else {
			ASSERT(qp->wq_length == 0 && qp->wq_head == NULL);
		}
	}
	mutex_exit(&qp->wq_queue_lock);
	return (error);
}

void
cachefs_addqueue(struct cachefs_req *rp, struct cachefs_workq *qp)
{
	mutex_enter(&qp->wq_queue_lock);
	if (qp->wq_thread_count < cachefs_max_threads) {
		if (qp->wq_thread_count == 0 ||
		    (qp->wq_length >= (qp->wq_thread_count * 2))) {
			(void) thread_create(NULL, 0, cachefs_async_start,
			    qp, 0, &p0, TS_RUN, minclsyspri);
			qp->wq_thread_count++;
		}
	}
	mutex_enter(&rp->cfs_req_lock);
	if (qp->wq_tail)
		qp->wq_tail->cfs_next = rp;
	else
		qp->wq_head = rp;
	qp->wq_tail = rp;
	rp->cfs_next = NULL;
	qp->wq_length++;
	if (qp->wq_length > qp->wq_max_len)
		qp->wq_max_len = qp->wq_length;
	mutex_enter(&cachefs_async_lock);
	++cachefs_async_count;
	mutex_exit(&cachefs_async_lock);

	cv_signal(&qp->wq_req_cv);
	mutex_exit(&rp->cfs_req_lock);
	mutex_exit(&qp->wq_queue_lock);
}

void
cachefs_async_putpage(struct cachefs_putpage_req *prp, cred_t *cr)
{
	struct cnode *cp = VTOC(prp->cp_vp);

	ASSERT(CFS_ISFS_BACKFS_NFSV4(C_TO_FSCACHE(cp)) == 0);

	(void) VOP_PUTPAGE(prp->cp_vp, prp->cp_off, prp->cp_len,
		prp->cp_flags, cr, NULL);

	mutex_enter(&cp->c_iomutex);
	if (--cp->c_nio == 0)
		cv_broadcast(&cp->c_iocv);
	if (prp->cp_off == 0 && prp->cp_len == 0 &&
	    (cp->c_ioflags & CIO_PUTPAGES)) {
		cp->c_ioflags &= ~CIO_PUTPAGES;
	}
	mutex_exit(&cp->c_iomutex);
}

void
cachefs_async_populate(struct cachefs_populate_req *pop, cred_t *cr)
{
	struct cnode *cp = VTOC(pop->cpop_vp);
	struct fscache *fscp = C_TO_FSCACHE(cp);
	struct filegrp *fgp = cp->c_filegrp;
	int error = 0; /* not returned -- used as a place-holder */
	vnode_t *frontvp = NULL, *backvp = NULL;
	int havelock = 0;
	vattr_t va;

	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	if (((cp->c_filegrp->fg_flags & CFS_FG_WRITE) == 0) ||
	    (fscp->fs_cdconnected != CFS_CD_CONNECTED)) {
		mutex_enter(&cp->c_statelock);
		cp->c_flags &= ~CN_ASYNC_POPULATE;
		mutex_exit(&cp->c_statelock);
		return; /* goto out */
	}

	error = cachefs_cd_access(fscp, 0, 0);
	if (error) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_ASYNCPOP)
			printf("async_pop: cd_access: err %d con %d\n",
			    error, fscp->fs_cdconnected);
#endif /* CFSDEBUG */
		mutex_enter(&cp->c_statelock);
		cp->c_flags &= ~CN_ASYNC_POPULATE;
		mutex_exit(&cp->c_statelock);
		return; /* goto out */
	}

	/*
	 * grab the statelock for some minimal things
	 */

	rw_enter(&cp->c_rwlock, RW_WRITER);
	mutex_enter(&cp->c_statelock);
	havelock = 1;

	if ((cp->c_flags & CN_ASYNC_POPULATE) == 0)
		goto out;

	/* there can be only one */
	ASSERT((cp->c_flags & CN_ASYNC_POP_WORKING) == 0);
	cp->c_flags |= CN_ASYNC_POP_WORKING;
	cp->c_popthrp = curthread;

	if (cp->c_metadata.md_flags & MD_POPULATED)
		goto out;

	if (cp->c_flags & CN_NOCACHE) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_ASYNCPOP)
			printf("cachefs_async_populate: nocache bit on\n");
#endif /* CFSDEBUG */
		error = EINVAL;
		goto out;
	}

	if (cp->c_frontvp == NULL) {
		if ((cp->c_metadata.md_flags & MD_FILE) == 0) {
			struct cfs_cid cid = cp->c_id;

			mutex_exit(&cp->c_statelock);
			havelock = 0;

			/*
			 * if frontfile doesn't exist, drop the lock
			 * to do some of the file creation stuff.
			 */

			if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
				error = filegrp_allocattr(fgp);
				if (error != 0)
					goto out;
			}
			if (fgp->fg_flags & CFS_FG_ALLOC_FILE) {
				mutex_enter(&fgp->fg_mutex);
				if (fgp->fg_flags & CFS_FG_ALLOC_FILE) {
					if (fgp->fg_header->ach_nffs == 0)
						error = filegrpdir_create(fgp);
					else
						error = filegrpdir_find(fgp);
					if (error != 0) {
						mutex_exit(&fgp->fg_mutex);
						goto out;
					}
				}
				mutex_exit(&fgp->fg_mutex);
			}

			if (fgp->fg_dirvp != NULL) {
				char name[CFS_FRONTFILE_NAME_SIZE];
				struct vattr *attrp;

				attrp = cachefs_kmem_zalloc(
				    sizeof (struct vattr), KM_SLEEP);
				attrp->va_mode = S_IFREG | 0666;
				attrp->va_uid = 0;
				attrp->va_gid = 0;
				attrp->va_type = VREG;
				attrp->va_size = 0;
				attrp->va_mask =
				    AT_SIZE | AT_TYPE | AT_MODE |
				    AT_UID | AT_GID;

				make_ascii_name(&cid, name);

				(void) VOP_CREATE(fgp->fg_dirvp, name, attrp,
				    EXCL, 0666, &frontvp, kcred, 0, NULL, NULL);

				cachefs_kmem_free(attrp,
				    sizeof (struct vattr));
			}

			mutex_enter(&cp->c_statelock);
			havelock = 1;
		}
		error = cachefs_getfrontfile(cp);
		ASSERT((error != 0) ||
		    (frontvp == NULL) ||
		    (frontvp == cp->c_frontvp));
	}
	if ((error != 0) || (cp->c_frontvp == NULL))
		goto out;

	if (frontvp != NULL)
		VN_RELE(frontvp);

	frontvp = cp->c_frontvp;
	VN_HOLD(frontvp);

	if (cp->c_backvp == NULL) {
		error = cachefs_getbackvp(fscp, cp);
		if ((error != 0) || (cp->c_backvp == NULL))
			goto out;
	}
	backvp = cp->c_backvp;
	VN_HOLD(backvp);

	switch (pop->cpop_vp->v_type) {
	case VREG:
		mutex_exit(&cp->c_statelock);
		havelock = 0;
		error = cachefs_async_populate_reg(pop, cr, backvp, frontvp);
		break;
	case VDIR:
		error = cachefs_async_populate_dir(pop, cr, backvp, frontvp);
		mutex_exit(&cp->c_statelock);
		havelock = 0;
		break;
	default:
#ifdef CFSDEBUG
		printf("cachefs_async_populate: warning: vnode type = %d\n",
		    pop->cpop_vp->v_type);
		ASSERT(0);
#endif /* CFSDEBUG */
		error = EINVAL;
		break;
	}

	if (error != 0)
		goto out;

	error = VOP_FSYNC(frontvp, FSYNC, cr, NULL);
	if (error != 0) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_ASYNCPOP)
			printf("cachefs_async_populate: fsync\n");
#endif /* CFSDEBUG */
		goto out;
	}

	/* grab the lock and finish up */
	mutex_enter(&cp->c_statelock);
	havelock = 1;

	/* if went nocache while lock was dropped, get out */
	if ((cp->c_flags & CN_NOCACHE) || (cp->c_frontvp == NULL)) {
		error = EINVAL;
		goto out;
	}

	va.va_mask = AT_MTIME;
	error = VOP_GETATTR(cp->c_frontvp, &va, 0, cr, NULL);
	if (error) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_ASYNCPOP)
			printf("cachefs_async_populate: getattr\n");
#endif /* CFSDEBUG */
		goto out;
	}
	cp->c_metadata.md_timestamp = va.va_mtime;
	cp->c_metadata.md_flags |= MD_POPULATED;
	cp->c_metadata.md_flags &= ~MD_INVALREADDIR;
	cp->c_flags |= CN_UPDATED;

out:
	if (! havelock)
		mutex_enter(&cp->c_statelock);

	/* see if an error happened behind our backs */
	if ((error == 0) && (cp->c_flags & CN_NOCACHE)) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_ASYNCPOP)
			printf("cachefs_async_populate: "
			    "nocache behind our backs\n");
#endif /* CFSDEBUG */
		error = EINVAL;
	}

	cp->c_flags &= ~(CN_NEED_FRONT_SYNC | CN_POPULATION_PENDING |
	    CN_ASYNC_POPULATE | CN_ASYNC_POP_WORKING);
	cp->c_popthrp = NULL;

	if (error != 0)
		cachefs_nocache(cp);

	/* unblock any threads waiting for populate to finish */
	cv_broadcast(&cp->c_popcv);
	mutex_exit(&cp->c_statelock);
	rw_exit(&cp->c_rwlock);
	cachefs_cd_release(fscp);

	if (backvp != NULL) {
		VN_RELE(backvp);
	}
	if (frontvp != NULL) {
		VN_RELE(frontvp);
	}
}

/*
 * only to be called from cachefs_async_populate
 */

static int
cachefs_async_populate_reg(struct cachefs_populate_req *pop, cred_t *cr,
    vnode_t *backvp, vnode_t *frontvp)
{
	struct cnode *cp = VTOC(pop->cpop_vp);
	int error = 0;
	u_offset_t popoff;
	size_t popsize;

	cachefs_cluster_allocmap(pop->cpop_off, &popoff,
	    &popsize, pop->cpop_size, cp);
	if (popsize == 0) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_ASYNCPOP)
			printf("cachefs_async_populate: popsize == 0\n");
#endif /* CFSDEBUG */
		goto out;
	}

	error = cachefs_populate(cp, popoff, popsize, frontvp, backvp,
	    cp->c_size, cr);
	if (error != 0) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_ASYNCPOP)
			printf("cachefs_async_populate: cachefs_populate\n");
#endif /* CFSDEBUG */
		goto out;
	}

out:
	return (error);
}

void
cachefs_do_req(struct cachefs_req *rp)
{
	struct cachefscache *cachep;

	mutex_enter(&rp->cfs_req_lock);
	switch (rp->cfs_cmd) {
	case CFS_INVALID:
		panic("cachefs_do_req: CFS_INVALID operation on queue");
		/*NOTREACHED*/
	case CFS_CACHE_SYNC:
		cachep = rp->cfs_req_u.cu_fs_sync.cf_cachep;
		cachefs_cache_sync(cachep);
		break;
	case CFS_IDLE:
		cachefs_cnode_idle(rp->cfs_req_u.cu_idle.ci_vp, rp->cfs_cr);
		break;
	case CFS_PUTPAGE:
		cachefs_async_putpage(&rp->cfs_req_u.cu_putpage, rp->cfs_cr);
		VN_RELE(rp->cfs_req_u.cu_putpage.cp_vp);
		break;
	case CFS_POPULATE:
		cachefs_async_populate(&rp->cfs_req_u.cu_populate, rp->cfs_cr);
		VN_RELE(rp->cfs_req_u.cu_populate.cpop_vp);
		break;
	case CFS_NOOP:
		break;
	default:
		panic("c_do_req: Invalid CFS async operation");
	}
	crfree(rp->cfs_cr);
	rp->cfs_cmd = CFS_INVALID;
	mutex_exit(&rp->cfs_req_lock);
	kmem_cache_free(cachefs_req_cache, rp);
}




ssize_t cachefs_mem_usage = 0;

struct km_wrap {
	size_t kw_size;
	struct km_wrap *kw_other;
};

kmutex_t cachefs_kmem_lock;

void *
cachefs_kmem_alloc(size_t size, int flag)
{
#ifdef DEBUG
	caddr_t mp = NULL;
	struct km_wrap *kwp;
	size_t n = (size + (2 * sizeof (struct km_wrap)) + 7) & ~7;

	ASSERT(n >= (size + 8));
	mp = kmem_alloc(n, flag);
	if (mp == NULL) {
		return (NULL);
	}
	/*LINTED alignment okay*/
	kwp = (struct km_wrap *)mp;
	kwp->kw_size = n;
	/*LINTED alignment okay*/
	kwp->kw_other = (struct km_wrap *)(mp + n - sizeof (struct km_wrap));
	kwp = (struct km_wrap *)kwp->kw_other;
	kwp->kw_size = n;
	/*LINTED alignment okay*/
	kwp->kw_other = (struct km_wrap *)mp;

	mutex_enter(&cachefs_kmem_lock);
	ASSERT(cachefs_mem_usage >= 0);
	cachefs_mem_usage += n;
	mutex_exit(&cachefs_kmem_lock);

	return (mp + sizeof (struct km_wrap));
#else /* DEBUG */
	return (kmem_alloc(size, flag));
#endif /* DEBUG */
}

void *
cachefs_kmem_zalloc(size_t size, int flag)
{
#ifdef DEBUG
	caddr_t mp = NULL;
	struct km_wrap *kwp;
	size_t n = (size + (2 * sizeof (struct km_wrap)) + 7) & ~7;

	ASSERT(n >= (size + 8));
	mp = kmem_zalloc(n, flag);
	if (mp == NULL) {
		return (NULL);
	}
	/*LINTED alignment okay*/
	kwp = (struct km_wrap *)mp;
	kwp->kw_size = n;
	/*LINTED alignment okay*/
	kwp->kw_other = (struct km_wrap *)(mp + n - sizeof (struct km_wrap));
	kwp = (struct km_wrap *)kwp->kw_other;
	kwp->kw_size = n;
	/*LINTED alignment okay*/
	kwp->kw_other = (struct km_wrap *)mp;

	mutex_enter(&cachefs_kmem_lock);
	ASSERT(cachefs_mem_usage >= 0);
	cachefs_mem_usage += n;
	mutex_exit(&cachefs_kmem_lock);

	return (mp + sizeof (struct km_wrap));
#else /* DEBUG */
	return (kmem_zalloc(size, flag));
#endif /* DEBUG */
}

void
cachefs_kmem_free(void *mp, size_t size)
{
#ifdef DEBUG
	struct km_wrap *front_kwp;
	struct km_wrap *back_kwp;
	size_t n = (size + (2 * sizeof (struct km_wrap)) + 7) & ~7;
	void *p;

	ASSERT(n >= (size + 8));
	front_kwp = (struct km_wrap *)((uintptr_t)mp - sizeof (struct km_wrap));
	back_kwp = (struct km_wrap *)
		((uintptr_t)front_kwp + n - sizeof (struct km_wrap));

	ASSERT(front_kwp->kw_other == back_kwp);
	ASSERT(front_kwp->kw_size == n);
	ASSERT(back_kwp->kw_other == front_kwp);
	ASSERT(back_kwp->kw_size == n);

	mutex_enter(&cachefs_kmem_lock);
	cachefs_mem_usage -= n;
	ASSERT(cachefs_mem_usage >= 0);
	mutex_exit(&cachefs_kmem_lock);

	p = front_kwp;
	front_kwp->kw_size = back_kwp->kw_size = 0;
	front_kwp->kw_other = back_kwp->kw_other = NULL;
	kmem_free(p, n);
#else /* DEBUG */
	kmem_free(mp, size);
#endif /* DEBUG */
}

char *
cachefs_strdup(char *s)
{
	char *rc;

	ASSERT(s != NULL);

	rc = cachefs_kmem_alloc(strlen(s) + 1, KM_SLEEP);
	(void) strcpy(rc, s);

	return (rc);
}

int
cachefs_stats_kstat_snapshot(kstat_t *ksp, void *buf, int rw)
{
	struct fscache *fscp = (struct fscache *)ksp->ks_data;
	cachefscache_t *cachep = fscp->fs_cache;
	int	error = 0;

	if (rw == KSTAT_WRITE) {
		bcopy(buf, &fscp->fs_stats, sizeof (fscp->fs_stats));
		cachep->c_gc_count = fscp->fs_stats.st_gc_count;
		CACHEFS_CFS_TIME_TO_TIME_COPY(fscp->fs_stats.st_gc_time,
			cachep->c_gc_time);
		CACHEFS_CFS_TIME_TO_TIME_COPY(fscp->fs_stats.st_gc_before_atime,
			cachep->c_gc_before);
		CACHEFS_CFS_TIME_TO_TIME_COPY(fscp->fs_stats.st_gc_after_atime,
			cachep->c_gc_after);
		return (error);
	}

	fscp->fs_stats.st_gc_count = cachep->c_gc_count;
	CACHEFS_TIME_TO_CFS_TIME_COPY(cachep->c_gc_time,
			fscp->fs_stats.st_gc_time, error);
	CACHEFS_TIME_TO_CFS_TIME_COPY(cachep->c_gc_before,
			fscp->fs_stats.st_gc_before_atime, error);
	CACHEFS_TIME_TO_CFS_TIME_COPY(cachep->c_gc_after,
			fscp->fs_stats.st_gc_after_atime, error);
	bcopy(&fscp->fs_stats, buf, sizeof (fscp->fs_stats));

	return (error);
}

#ifdef DEBUG
cachefs_debug_info_t *
cachefs_debug_save(cachefs_debug_info_t *oldcdb, int chain,
    char *message, uint_t flags, int number, void *pointer,
    cachefscache_t *cachep, struct fscache *fscp, struct cnode *cp)
{
	cachefs_debug_info_t *cdb;

	if ((chain) || (oldcdb == NULL))
		cdb = cachefs_kmem_zalloc(sizeof (*cdb), KM_SLEEP);
	else
		cdb = oldcdb;
	if (chain)
		cdb->cdb_next = oldcdb;

	if (message != NULL) {
		if (cdb->cdb_message != NULL)
			cachefs_kmem_free(cdb->cdb_message,
			    strlen(cdb->cdb_message) + 1);
		cdb->cdb_message = cachefs_kmem_alloc(strlen(message) + 1,
		    KM_SLEEP);
		(void) strcpy(cdb->cdb_message, message);
	}
	cdb->cdb_flags = flags;
	cdb->cdb_int = number;
	cdb->cdb_pointer = pointer;

	cdb->cdb_count++;

	cdb->cdb_cnode = cp;
	if (cp != NULL) {
		cdb->cdb_frontvp = cp->c_frontvp;
		cdb->cdb_backvp = cp->c_backvp;
	}
	if (fscp != NULL)
		cdb->cdb_fscp = fscp;
	else if (cp != NULL)
		cdb->cdb_fscp = C_TO_FSCACHE(cp);
	if (cachep != NULL)
		cdb->cdb_cachep = cachep;
	else if (cdb->cdb_fscp != NULL)
		cdb->cdb_cachep = cdb->cdb_fscp->fs_cache;

	cdb->cdb_thread = curthread;
	cdb->cdb_timestamp = gethrtime();
	cdb->cdb_depth = getpcstack(cdb->cdb_stack, CACHEFS_DEBUG_DEPTH);

	return (cdb);
}

void
cachefs_debug_show(cachefs_debug_info_t *cdb)
{
	hrtime_t now = gethrtime();
	timestruc_t ts;
	int i;

	while (cdb != NULL) {
		hrt2ts(now - cdb->cdb_timestamp, &ts);
		printf("cdb: %p count: %d timelapse: %ld.%9ld\n",
		    (void *)cdb, cdb->cdb_count, ts.tv_sec, ts.tv_nsec);
		if (cdb->cdb_message != NULL)
			printf("message: %s", cdb->cdb_message);
		printf("flags: %x int: %d pointer: %p\n",
		    cdb->cdb_flags, cdb->cdb_int, (void *)cdb->cdb_pointer);

		printf("cnode: %p fscp: %p cachep: %p\n",
		    (void *)cdb->cdb_cnode,
		    (void *)cdb->cdb_fscp, (void *)cdb->cdb_cachep);
		printf("frontvp: %p backvp: %p\n",
		    (void *)cdb->cdb_frontvp, (void *)cdb->cdb_backvp);

		printf("thread: %p stack...\n", (void *)cdb->cdb_thread);
		for (i = 0; i < cdb->cdb_depth; i++) {
			ulong_t off;
			char *sym;

			sym = kobj_getsymname(cdb->cdb_stack[i], &off);
			printf("%s+%lx\n", sym ? sym : "?", off);
		}
		delay(2*hz);
		cdb = cdb->cdb_next;
	}
	debug_enter(NULL);
}
#endif /* DEBUG */

/*
 * Changes the size of the front file.
 * Returns 0 for success or error if cannot set file size.
 * NOCACHE bit is ignored.
 * c_size is ignored.
 * statelock must be held, frontvp must be set.
 * File must be populated if setting to a size other than zero.
 */
int
cachefs_frontfile_size(cnode_t *cp, u_offset_t length)
{
	cachefscache_t *cachep = C_TO_FSCACHE(cp)->fs_cache;
	vattr_t va;
	size_t nblks, blkdelta;
	int error = 0;
	int alloc = 0;
	struct cachefs_allocmap *allocp;

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	ASSERT(cp->c_frontvp);

	/* if growing the file, allocate space first, we charge for holes */
	if (length) {
		ASSERT(cp->c_metadata.md_flags & MD_POPULATED);

		nblks = (length + MAXBSIZE - 1) / MAXBSIZE;
		if (nblks > cp->c_metadata.md_frontblks) {
			blkdelta = nblks - cp->c_metadata.md_frontblks;
			error = cachefs_allocblocks(cachep, blkdelta,
			    cp->c_metadata.md_rltype);
			if (error)
				goto out;
			alloc = 1;
		}
	}

	/* change the size of the front file */
	va.va_mask = AT_SIZE;
	va.va_size = length;
	error = VOP_SETATTR(cp->c_frontvp, &va, 0, kcred, NULL);
	if (error)
		goto out;

	/* zero out the alloc map */
	bzero(&cp->c_metadata.md_allocinfo,
	    cp->c_metadata.md_allocents * sizeof (struct cachefs_allocmap));
	cp->c_metadata.md_allocents = 0;

	if (length == 0) {
		/* free up blocks */
		if (cp->c_metadata.md_frontblks) {
			cachefs_freeblocks(cachep, cp->c_metadata.md_frontblks,
			    cp->c_metadata.md_rltype);
			cp->c_metadata.md_frontblks = 0;
		}
	} else {
		/* update number of blocks if shrinking file */
		nblks = (length + MAXBSIZE - 1) / MAXBSIZE;
		if (nblks < cp->c_metadata.md_frontblks) {
			blkdelta = cp->c_metadata.md_frontblks - nblks;
			cachefs_freeblocks(cachep, blkdelta,
			    cp->c_metadata.md_rltype);
			cp->c_metadata.md_frontblks = (uint_t)nblks;
		}

		/* fix up alloc map to reflect new size */
		allocp = cp->c_metadata.md_allocinfo;
		allocp->am_start_off = 0;
		allocp->am_size = length;
		cp->c_metadata.md_allocents = 1;
	}
	cp->c_flags |= CN_UPDATED | CN_NEED_FRONT_SYNC;

out:
	if (error && alloc)
		cachefs_freeblocks(cachep, blkdelta, cp->c_metadata.md_rltype);
	return (error);
}

/*ARGSUSED*/
int
cachefs_req_create(void *voidp, void *cdrarg, int kmflags)
{
	struct cachefs_req *rp = (struct cachefs_req *)voidp;

	/*
	 * XXX don't do this!  if you need this, you can't use this
	 * constructor.
	 */

	bzero(rp, sizeof (struct cachefs_req));

	mutex_init(&rp->cfs_req_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
void
cachefs_req_destroy(void *voidp, void *cdrarg)
{
	struct cachefs_req *rp = (struct cachefs_req *)voidp;

	mutex_destroy(&rp->cfs_req_lock);
}
