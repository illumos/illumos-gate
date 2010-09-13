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
#include <sys/buf.h>
#include <netinet/in.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/modctl.h>
#include <vm/pvn.h>

#include <sys/fs/cachefs_fs.h>

/*
 * cachefs_max_idle is a global that is tunable.
 * This value decides how frequently or when the
 * cachefs_cnode_idleclean is run.
 * The default value is set to CFS_FS_MAXIDLE.
 * The tunable if set to X triggers a cleanup when
 * the number of idle cnodes reach X, and cleans up
 * (.25 * X) idle cnodes.
 */
int cachefs_max_idle = CFS_FS_MAXIDLE;


struct kmem_cache *cachefs_cnode_cache = NULL;

/*
 * Functions for cnode management.
 */

/*
 * Puts cnode on idle list.  Only call from an async thread or no
 * locks held.
 */
/*ARGSUSED1*/
void
cachefs_cnode_idle(struct vnode *vp, cred_t *cr)
{
	cnode_t *cp = VTOC(vp);
	fscache_t *fscp = C_TO_FSCACHE(cp);
	int cleanidle;
	vnode_t *unldvp;
	cred_t *unlcred;
	char *unlname;
	int error;

	/*
	 * The key to this routine is not to drop the vnode count
	 * while on the idle list.  This prevents this routine from
	 * being called again by vn_rele on an inactive cnode.
	 * Nothing bad happens if an "active" cnode is put on the idle
	 * list.  It eventually gets pulled off.
	 * Also this routine is only called from a thread message sent
	 * by cachefs_inactive().  It is not safe for this routine
	 * to be the "inactive" entry point because of the dnlc.
	 */

	for (;;) {
		/* get access to the file system */
		error = cachefs_cd_access(fscp, 0, 1);
		ASSERT(error == 0);

		/* get exclusive access to this cnode */
		mutex_enter(&cp->c_statelock);

		/* done with this loop if not unlinking a file */
		if (cp->c_unldvp == NULL)
			break;

		/* get unlink info out of the cnode */
		unldvp = cp->c_unldvp;
		unlcred = cp->c_unlcred;
		unlname = cp->c_unlname;
		cp->c_unldvp = NULL;
		cp->c_unlcred = NULL;
		cp->c_unlname = NULL;
		mutex_exit(&cp->c_statelock);

		/* finish the remove operation */
		if (fscp->fs_cdconnected == CFS_CD_CONNECTED) {
			error = cachefs_remove_connected(unldvp,
			    unlname, unlcred, vp);
		} else {
			error = cachefs_remove_disconnected(unldvp,
			    unlname, unlcred, vp);
		}

		/* reacquire cnode lock */
		mutex_enter(&cp->c_statelock);

		/* if a timeout occurred */
		if (CFS_TIMEOUT(fscp, error)) {
			/* restore cnode state */
			if (cp->c_unldvp == NULL) {
				cp->c_unldvp = unldvp;
				cp->c_unlcred = unlcred;
				cp->c_unlname = unlname;
				if (fscp->fs_cdconnected == CFS_CD_CONNECTED) {
					mutex_exit(&cp->c_statelock);
					cachefs_cd_release(fscp);
					cachefs_cd_timedout(fscp);
					continue;
				} else {
					cp->c_flags |= CN_PENDRM;
					mutex_exit(&cp->c_statelock);
					goto out;
				}
			}
		}
		/* free up resources */
		VN_RELE(unldvp);
		cachefs_kmem_free(unlname, MAXNAMELEN);
		crfree(unlcred);
		break;
	}

	ASSERT((cp->c_flags & CN_IDLE) == 0);
	/*
	 * If we are going to destroy this cnode,
	 * do it now instead of later.
	 */
	if (cp->c_flags & (CN_DESTROY | CN_STALE)) {
		mutex_exit(&cp->c_statelock);
		(void) cachefs_cnode_inactive(vp, cr);
		goto out;
	}

	/*
	 * mark cnode as idle, put it on the idle list, and increment the
	 * number of idle cnodes
	 */
	cp->c_flags |= CN_IDLE;
	mutex_enter(&fscp->fs_idlelock);
	cachefs_cnode_idleadd(cp);
	if ((fscp->fs_idlecnt > cachefs_max_idle) &&
	    (fscp->fs_idleclean == 0) &&
	    (fscp->fs_cdtransition == 0)) {
		fscp->fs_idleclean = 1;
		cleanidle = 1;
	} else {
		cleanidle = 0;
	}
	mutex_exit(&fscp->fs_idlelock);

	/* release cnode */
	mutex_exit(&cp->c_statelock);

	/* if should reduce the number of idle cnodes */
	if (cleanidle) {
		ASSERT(fscp->fs_idlecnt > 1);
		fscache_hold(fscp);
		cachefs_cnode_idleclean(fscp, 0);
		/* XXX race with cachefs_unmount() calling destroy */
		fscache_rele(fscp);
	}

out:
	/* release hold on the file system */
	/* XXX unmount() could have called destroy after fscache_rele() */
	cachefs_cd_release(fscp);
}

/*
 * Removes cnodes from the idle list and destroys them.
 */
void
cachefs_cnode_idleclean(fscache_t *fscp, int unmount)
{
	int remcnt;
	cnode_t *cp;

	mutex_enter(&fscp->fs_idlelock);

	/* determine number of cnodes to destroy */
	if (unmount) {
		/* destroy all plus any that go idle while in this routine */
		remcnt = fscp->fs_idlecnt * 2;
	} else {
		/* reduce to 75% of max allowed idle cnodes */
		remcnt = (fscp->fs_idlecnt - cachefs_max_idle) +
		    (cachefs_max_idle >> 2);
	}

	for (; remcnt > 0; remcnt--) {
		/* get cnode on back of idle list and hold it */
		cp = fscp->fs_idleback;
		if (cp == NULL)
			break;
		VN_HOLD(CTOV(cp));
		mutex_exit(&fscp->fs_idlelock);

		/* if the cnode is still on the idle list */
		mutex_enter(&cp->c_statelock);
		if (cp->c_flags & CN_IDLE) {
			cp->c_flags &= ~CN_IDLE;

			/* remove cnode from the idle list */
			mutex_enter(&fscp->fs_idlelock);
			cachefs_cnode_idlerem(cp);
			mutex_exit(&fscp->fs_idlelock);
			mutex_exit(&cp->c_statelock);

			/* destroy the cnode */
			VN_RELE(CTOV(cp));
			(void) cachefs_cnode_inactive(CTOV(cp), kcred);
		} else {
			/* cnode went active, just skip it */
			mutex_exit(&cp->c_statelock);
			VN_RELE(CTOV(cp));
		}
		mutex_enter(&fscp->fs_idlelock);
	}

	fscp->fs_idleclean = 0;
	mutex_exit(&fscp->fs_idlelock);
}

/*
 * This routine does the real work of inactivating a cachefs vnode.
 */
int
cachefs_cnode_inactive(register struct vnode *vp, cred_t *cr)
{
	cnode_t *cp;
	struct fscache *fscp;
	struct filegrp *fgp;
	cachefscache_t *cachep;
	struct cachefs_metadata *mdp;
	int meta_destroyed = 0;

	cp = VTOC(vp);

	fscp = C_TO_FSCACHE(cp);
	cachep = fscp->fs_cache;
	ASSERT(cachep != NULL);
	fgp = cp->c_filegrp;

	ASSERT((cp->c_flags & CN_IDLE) == 0);

	/* truncate the front file if necessary */
	mutex_enter(&cp->c_statelock);
	if ((cp->c_flags & CN_NOCACHE) && (cp->c_metadata.md_flags & MD_FILE) &&
	    cp->c_metadata.md_frontblks) {

		ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_INVALIDATE)
			printf("c_cnode_inactive: invalidating %llu\n",
			    (u_longlong_t)cp->c_id.cid_fileno);
#endif
		/*
		 * If the cnode is being populated, and we're not the
		 * populating thread, then block until the pop thread
		 * completes.  If we are the pop thread, then we may come in
		 * here, but not to nuke the directory cnode at a critical
		 * juncture.
		 */
		while ((cp->c_flags & CN_ASYNC_POP_WORKING) &&
		    (cp->c_popthrp != curthread))
			cv_wait(&cp->c_popcv, &cp->c_statelock);

		cachefs_inval_object(cp);
	}
	mutex_exit(&cp->c_statelock);

	for (;;) {
		/* see if vnode is really inactive */
		mutex_enter(&vp->v_lock);
		ASSERT(vp->v_count > 0);
		if (vp->v_count > 1) {
			/*
			 * It's impossible for us to be cnode_inactive for
			 * the root cnode _unless_ we are being called from
			 * cachefs_unmount (where inactive is called
			 * explictly).  If the count is not 1, there is
			 * still an outstanding reference to the root cnode,
			 * and we return EBUSY; this allows cachefs_unmount
			 * to fail.
			 */
			if (cp->c_flags & CN_ROOT) {
				mutex_exit(&vp->v_lock);
				return (EBUSY);
			}
			cp->c_ipending = 0;
			vp->v_count--;	/* release our hold from vn_rele */
			mutex_exit(&vp->v_lock);
			return (0);
		}
		mutex_exit(&vp->v_lock);

		/* get rid of any pages, do not care if cannot be pushed */
		if (vn_has_cached_data(vp)) {
			ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);
			(void) cachefs_putpage_common(vp, (offset_t)0, 0,
			    B_INVAL | B_FORCE, cr);
		}

		/* if need to sync metadata, the call is a no op for NFSv4 */
		if ((cp->c_flags & (CN_UPDATED | CN_DESTROY)) == CN_UPDATED) {
			(void) cachefs_sync_metadata(cp);
			continue;
		}
		break;
	}

	/*
	 * Lock out possible race with makecachefsnode.
	 * Makecachefsnode will fix up the rl/active list stuff to
	 * be correct when it gets to run.
	 * We have to do the rl/active stuff while the cnode is on the hash
	 * list to sync actions on the rl/active list.
	 */
	mutex_enter(&fgp->fg_cnodelock);
	mutex_enter(&cp->c_statelock);

	/* see if vnode is still inactive */
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count > 0);
	if (vp->v_count > 1) {
		cp->c_ipending = 0;
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		mutex_exit(&cp->c_statelock);
		mutex_exit(&fgp->fg_cnodelock);
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_INVALIDATE)
			printf("cachefs_cnode_inactive: %u vp %p\n",
			    vp->v_count, vp);
#endif
		return (0);
	}
	mutex_exit(&vp->v_lock);

	/* check for race with remove */
	if (cp->c_unldvp) {
		mutex_exit(&cp->c_statelock);
		mutex_exit(&fgp->fg_cnodelock);

		/* this causes cachefs_inactive to be called again */
		VN_RELE(vp);
		return (0);
	}

	/* if any pages left, really get rid of them */
	if (vn_has_cached_data(vp)) {
		ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);
		(void) pvn_vplist_dirty(vp, 0, NULL, B_INVAL | B_TRUNC, cr);
	}
	ASSERT(vp->v_count == 1);

	mdp = &cp->c_metadata;

	/* if we can (and should) destroy the front file and metadata */
	if ((cp->c_flags & (CN_DESTROY | CN_STALE)) &&
	    (fgp->fg_flags & CFS_FG_WRITE) && !CFS_ISFS_BACKFS_NFSV4(fscp)) {
		if (mdp->md_rlno) {
			cachefs_removefrontfile(mdp, &cp->c_id, fgp);
			cachefs_rlent_moveto(cachep, CACHEFS_RL_FREE,
			    mdp->md_rlno, 0);
			mdp->md_rlno = 0;
			mdp->md_rltype = CACHEFS_RL_NONE;
		}
		if ((cp->c_flags & CN_ALLOC_PENDING) == 0) {
			(void) filegrp_destroy_metadata(fgp, &cp->c_id);
			meta_destroyed = 1;
		}
	}

	/* else put the front file on the gc list */
	else if (mdp->md_rlno &&
	    (fgp->fg_flags & CFS_FG_WRITE) &&
	    (cp->c_metadata.md_rltype == CACHEFS_RL_ACTIVE)) {
#ifdef CFSDEBUG
		cachefs_rlent_verify(cachep, CACHEFS_RL_ACTIVE,
		    mdp->md_rlno);
#endif /* CFSDEBUG */

		ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);
		cachefs_rlent_moveto(cachep, CACHEFS_RL_GC, mdp->md_rlno,
		    mdp->md_frontblks);
		mdp->md_rltype = CACHEFS_RL_GC;
		cp->c_flags |= CN_UPDATED;
	}

	/* if idlelist pointer(s) not null, remove from idle list */
	if ((cp->c_idlefront != NULL) || (cp->c_idleback != NULL)) {
		mutex_enter(&fscp->fs_idlelock);
		cachefs_cnode_idlerem(cp);
		mutex_exit(&fscp->fs_idlelock);
	}

	/* remove from the filegrp list prior to releasing the cnode lock */
	cachefs_cnode_listrem(cp);

	mutex_exit(&cp->c_statelock);
	if (! meta_destroyed)
		(void) cachefs_sync_metadata(cp);

	mutex_exit(&fgp->fg_cnodelock);

	if (cp->c_cred != NULL) {
		crfree(cp->c_cred);
		cp->c_cred = NULL;
	}

	if (cp->c_frontvp)
		VN_RELE(cp->c_frontvp);

	if (cp->c_backvp)
		VN_RELE(cp->c_backvp);

	if (cp->c_acldirvp)
		VN_RELE(cp->c_acldirvp);

	rw_destroy(&cp->c_rwlock);
	mutex_destroy(&cp->c_statelock);
	cv_destroy(&cp->c_popcv);
	mutex_destroy(&cp->c_iomutex);
	cv_destroy(&cp->c_iocv);

	/* free up cnode memory */
	vn_invalid(cp->c_vnode);
	vn_free(cp->c_vnode);
	kmem_cache_free(cachefs_cnode_cache, cp);

	filegrp_rele(fgp);
	(void) fscache_cnodecnt(fscp, -1);
	return (0);
}

/*
 * Add a cnode to the filegrp list.
 */
void
cachefs_cnode_listadd(struct cnode *cp)
{
	filegrp_t *fgp = cp->c_filegrp;

	ASSERT(MUTEX_HELD(&fgp->fg_cnodelock));
	ASSERT(cp->c_next == NULL);

	cp->c_next = fgp->fg_cnodelist;
	fgp->fg_cnodelist = cp;
}

/*
 * Remove a cnode from the filegrp list.
 */
void
cachefs_cnode_listrem(struct cnode *cp)
{
	filegrp_t *fgp = cp->c_filegrp;
	struct cnode **headpp;

#ifdef CFSDEBUG
	int found = 0;
#endif

	ASSERT(MUTEX_HELD(&fgp->fg_cnodelock));
	ASSERT(cp->c_idleback == NULL);
	ASSERT(cp->c_idlefront == NULL);

	for (headpp = &fgp->fg_cnodelist;
		*headpp != NULL; headpp = &(*headpp)->c_next) {
		if (*headpp == cp) {
			*headpp = cp->c_next;
			cp->c_next = NULL;
#ifdef CFSDEBUG
			found++;
#endif
			break;
		}
	}
#ifdef CFSDEBUG
	ASSERT(found);
#endif
}

/*
 * Add a cnode to the front of the fscache idle list.
 */
void
cachefs_cnode_idleadd(struct cnode *cp)
{
	fscache_t *fscp = C_TO_FSCACHE(cp);

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	ASSERT(MUTEX_HELD(&fscp->fs_idlelock));

	/* put cnode on the front of the idle list */
	cp->c_idlefront = fscp->fs_idlefront;
	cp->c_idleback =  NULL;

	if (fscp->fs_idlefront)
		fscp->fs_idlefront->c_idleback = cp;
	else {
		ASSERT(fscp->fs_idleback == NULL);
		fscp->fs_idleback = cp;
	}
	fscp->fs_idlefront = cp;
	fscp->fs_idlecnt++;
}

/*
 * Remove a cnode from the fscache idle list.
 */
void
cachefs_cnode_idlerem(struct cnode *cp)
{
	fscache_t *fscp = C_TO_FSCACHE(cp);

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	ASSERT(MUTEX_HELD(&fscp->fs_idlelock));

	if (cp->c_idlefront == NULL) {
		ASSERT(fscp->fs_idleback == cp);
		fscp->fs_idleback = cp->c_idleback;
		if (fscp->fs_idleback != NULL)
			fscp->fs_idleback->c_idlefront = NULL;
	} else {
		cp->c_idlefront->c_idleback = cp->c_idleback;
	}

	if (cp->c_idleback == NULL) {
		ASSERT(fscp->fs_idlefront == cp);
		fscp->fs_idlefront = cp->c_idlefront;
		if (fscp->fs_idlefront != NULL)
			fscp->fs_idlefront->c_idleback = NULL;
	} else {
		cp->c_idleback->c_idlefront = cp->c_idlefront;
		cp->c_idleback = NULL;
	}
	cp->c_idlefront = NULL;
	fscp->fs_idlecnt--;
	ASSERT(fscp->fs_idlecnt >= 0);
}

/*
 * Search the cnode list of the input file group, looking for a cnode which
 * matches the supplied file ident fileno.
 *
 * Returns:
 *	*cpp = NULL, if no valid matching cnode is found
 *	*cpp = address of cnode with matching fileno, with c_statelock held
 *	return status is 0 if no cnode found, or if found & cookies match
 *	return status is 1 if a cnode was found, but the cookies don't match
 *
 * Note:  must grab the c_statelock for each cnode, or its state could
 * change while we're processing it.  Also, if a cnode is found, must return
 * with c_statelock still held, so that the cnode state cannot change until
 * the calling routine releases the lock.
 */
int
cachefs_cnode_find(filegrp_t *fgp, cfs_cid_t *cidp, fid_t *cookiep,
    struct cnode **cpp, struct vnode *backvp, vattr_t *vap)
{
	struct cnode *cp;
	int badcookie = 0;
	uint32_t is_nfsv4;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_CNODE)
		cmn_err(CE_NOTE, "cachefs_cnode_find: fileno %llu fgp %p\n",
		    (u_longlong_t)cidp->cid_fileno, (void *)fgp);
#endif
	ASSERT(MUTEX_HELD(&fgp->fg_cnodelock));

	*cpp = NULL;
	is_nfsv4 = CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp);

	/*
	 * Cookie should be filled unless disconnected operation or
	 * backfilesystem is NFSv4
	 */
	if (cookiep == NULL && !CFS_ISFS_SNR(fgp->fg_fscp) &&
	    !CFS_ISFS_BACKFS_NFSV4(fgp->fg_fscp)) {
		goto out;
	}

	for (cp = fgp->fg_cnodelist; cp != NULL; cp = cp->c_next) {
		mutex_enter(&cp->c_statelock);

		if ((cidp->cid_fileno != cp->c_id.cid_fileno &&
			(is_nfsv4 == FALSE || cp->c_backvp != backvp)) ||
		    (cp->c_flags & (CN_STALE | CN_DESTROY))) {
			mutex_exit(&cp->c_statelock);
			continue;
		}

		/*
		 * Having found a non stale, non destroy pending cnode with
		 * matching fileno, will be exiting the for loop, after
		 * determining return status
		 */
		*cpp = cp;

		if ((cookiep != NULL) &&
		    ((cookiep->fid_len != cp->c_cookie.fid_len) ||
		    (bcmp((caddr_t)cookiep->fid_data,
		    (caddr_t)&cp->c_cookie.fid_data, cookiep->fid_len)) != 0)) {
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_GENERAL) {
				cmn_err(CE_NOTE,
				    "cachefs: dup fileno %llu, cp %p\n",
				    (u_longlong_t)cidp->cid_fileno, (void *)cp);
			}
#endif
			badcookie = 1;
		}

		/*
		 * For NFSv4 since there is no fid, add a check to
		 * ensure the backvp and vap matches that in the cnode.
		 * If it doesn't then someone tried to use a stale cnode.
		 */
		if (is_nfsv4) {
			if (backvp && backvp != cp->c_backvp ||
			    vap && vap->va_type != cp->c_attr.va_type ||
			    cidp->cid_fileno != cp->c_id.cid_fileno) {
				CFS_DPRINT_BACKFS_NFSV4(C_TO_FSCACHE(cp),
				("cachefs_cnode_find (nfsv4): stale cnode "
				"cnode %p, backvp %p, new-backvp %p, vap %p "
				"fileno=%llx cp-fileno=%llx\n",
				cp, cp->c_backvp, backvp, vap,
				cidp->cid_fileno, cp->c_id.cid_fileno));
				badcookie = 1;
			}
		}
		break;
	}
out:

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_CNODE)
		cmn_err(CE_NOTE, "cachefs_cnode_find: cp %p\n", (void *)*cpp);
#endif
	return (badcookie);
}

/*
 * We have to initialize the cnode contents. Fill in the contents from the
 * cache (attrcache file), from the info passed in, whatever it takes.
 */
static int
cachefs_cnode_init(cfs_cid_t *cidp, cnode_t *cp, fscache_t *fscp,
    filegrp_t *fgp, fid_t *cookiep, vattr_t *vap, vnode_t *backvp,
    int flag, cred_t *cr)
{
	int error = 0;
	int slotfound;
	vnode_t *vp;
	int null_cookie;
	cachefscache_t *cachep = fscp->fs_cache;

	bzero(cp, sizeof (cnode_t));
	cp->c_vnode = vn_alloc(KM_SLEEP);

	vp = CTOV(cp);

	vp->v_data = (caddr_t)cp;

	rw_init(&cp->c_rwlock, NULL, RW_DEFAULT, NULL);
	mutex_init(&cp->c_statelock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cp->c_popcv, NULL, CV_DEFAULT, NULL);
	mutex_init(&cp->c_iomutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cp->c_iocv, NULL, CV_DEFAULT, NULL);

	vn_setops(vp, cachefs_getvnodeops());
	cp->c_id = *cidp;
	if (backvp != NULL) {
		cp->c_backvp = backvp;
		VN_HOLD(backvp);
	}
	cp->c_flags |= flag;
	filegrp_hold(fgp);
	cp->c_filegrp = fgp;
	if (cookiep)
		cp->c_cookie = *cookiep;
	mutex_enter(&cp->c_statelock);

	/*
	 * if nocache is set then ignore anything cached for this file,
	 * if nfsv4 flag is set, then create the cnode but don't do
	 * any caching.
	 */
	if (cp->c_flags & CN_NOCACHE || CFS_ISFS_BACKFS_NFSV4(fscp)) {
		/*
		 * this case only happens while booting without a cache
		 * or if NFSv4 is the backfilesystem
		 */
		ASSERT(!CFS_ISFS_SNR(fscp));
		ASSERT(fscp->fs_cdconnected == CFS_CD_CONNECTED);
		if (cookiep || CFS_ISFS_BACKFS_NFSV4(fscp)) {
			error = CFSOP_INIT_COBJECT(fscp, cp, vap, cr);
			if (error)
				goto out;
			cp->c_flags |= CN_UPDATED | CN_ALLOC_PENDING;
			ASSERT(cp->c_attr.va_type != 0);
			VN_SET_VFS_TYPE_DEV(vp, fscp->fs_cfsvfsp,
			    cp->c_attr.va_type, cp->c_attr.va_rdev);
			cachefs_cnode_setlocalstats(cp);
		} else
			error = ESTALE;
		goto out;
	}

	/*
	 * see if there's a slot for this filegrp/cid fileno
	 * if not, and there's no cookie info, nothing can be done, but if
	 * there's cookie data indicate we need to create a metadata slot.
	 */
	slotfound = cachefs_cid_inuse(cp->c_filegrp, cidp);
	if (slotfound == 0) {
		if (cookiep == NULL) {
			error = ENOENT;
			goto out;
		}
		cp->c_flags |= CN_ALLOC_PENDING;
	} else {
		/*
		 * if a slot was found, then increment the slot in use count
		 * and try to read the metadata.
		 */
		cp->c_filegrp->fg_header->ach_count++;
		error = filegrp_read_metadata(cp->c_filegrp, cidp,
		    &cp->c_metadata);
	}
	/*
	 * if there wasn't a slot, or an attempt to read it results in ENOENT,
	 * then init the cache object, create the vnode, etc...
	 */
	if ((slotfound == 0) || (error == ENOENT)) {
		error = CFSOP_INIT_COBJECT(fscp, cp, vap, cr);
		if (error)
			goto out;
		ASSERT(cp->c_attr.va_type != 0);
		VN_SET_VFS_TYPE_DEV(vp, fscp->fs_cfsvfsp,
		    cp->c_attr.va_type, cp->c_attr.va_rdev);
		cp->c_metadata.md_rltype = CACHEFS_RL_NONE;
	} else if (error == 0) {
		/* slot found, no error occurred on the metadata read */
		cp->c_size = cp->c_attr.va_size;

		if ((cachep->c_flags & CACHE_CHECK_RLTYPE) &&
		    (cp->c_metadata.md_rlno != 0) &&
		    (cp->c_metadata.md_rltype == CACHEFS_RL_ACTIVE)) {
			rl_entry_t rl, *rlp;

			mutex_enter(&cachep->c_contentslock);
			error = cachefs_rl_entry_get(cachep,
			    cp->c_metadata.md_rlno, &rlp);
			if (error) {
				mutex_exit(&cachep->c_contentslock);
				goto out;
			}
			rl = *rlp;
			mutex_exit(&cachep->c_contentslock);
			if (cp->c_metadata.md_rltype != rl.rl_current) {
				cp->c_flags |= CN_UPDATED;
				cp->c_metadata.md_rltype = rl.rl_current;
			}
		}

		/*
		 * If no cookie is specified, or if this is a local file,
		 * accept the one in the metadata.
		 */
		null_cookie = 0;
		if ((cookiep == NULL) || (cp->c_id.cid_flags & CFS_CID_LOCAL)) {
			cookiep = &cp->c_metadata.md_cookie;
			null_cookie = 1;
		}

		/* if cookies do not match, reset the metadata */
		if ((cookiep->fid_len != cp->c_cookie.fid_len) ||
		    (bcmp(&cookiep->fid_data, &cp->c_cookie.fid_data,
			(size_t)cookiep->fid_len) != 0)) {
			cp->c_cookie = *cookiep;
			cp->c_flags |= CN_UPDATED;
			cp->c_metadata.md_timestamp.tv_sec = 0;
			/* clear all but the front file bit */
			cp->c_metadata.md_flags &= MD_FILE;
			error = CFSOP_INIT_COBJECT(fscp, cp, vap, cr);
			ASSERT(cp->c_attr.va_type != 0);
			VN_SET_VFS_TYPE_DEV(vp, fscp->fs_cfsvfsp,
			    cp->c_attr.va_type, cp->c_attr.va_rdev);
		}

		/* else if the consistency type changed, fix it up */
		else if (cp->c_metadata.md_consttype != fscp->fs_consttype) {
			ASSERT(cp->c_attr.va_type != 0);
			VN_SET_VFS_TYPE_DEV(vp, fscp->fs_cfsvfsp,
			    cp->c_attr.va_type, cp->c_attr.va_rdev);
			CFSOP_CONVERT_COBJECT(fscp, cp, cr);
			if (!null_cookie) {
				error = CFSOP_CHECK_COBJECT(fscp, cp,
				    C_BACK_CHECK, cr);
			}
		}

		/* else check the consistency of the data */
		else {
			ASSERT(cp->c_attr.va_type != 0);
			VN_SET_VFS_TYPE_DEV(vp, fscp->fs_cfsvfsp,
			    cp->c_attr.va_type, cp->c_attr.va_rdev);
			if (!null_cookie) {
				error = CFSOP_CHECK_COBJECT(fscp, cp, 0, cr);
			}
		}
	} else {
		goto out;
	}
	cachefs_cnode_setlocalstats(cp);

out:
	mutex_exit(&cp->c_statelock);
	if (error) {
		if (cp->c_frontvp)
			VN_RELE(cp->c_frontvp);
		if (cp->c_backvp)
			VN_RELE(cp->c_backvp);
		if (cp->c_acldirvp)
			VN_RELE(cp->c_acldirvp);
		filegrp_rele(fgp);
		rw_destroy(&cp->c_rwlock);
		mutex_destroy(&cp->c_statelock);
		cv_destroy(&cp->c_popcv);
		mutex_destroy(&cp->c_iomutex);
		cv_destroy(&cp->c_iocv);
	}
	return (error);
}

/*
 * Finds the cnode for the specified fileno and fid.
 * Creates the cnode if it does not exist.
 * The cnode is returned held.
 */
int
cachefs_cnode_make(cfs_cid_t *cidp, fscache_t *fscp, fid_t *cookiep,
	vattr_t *vap, vnode_t *backvp, cred_t *cr, int flag, cnode_t **cpp)
{
	struct cnode *cp;
	int error;
	struct filegrp *fgp;
	struct cachefs_metadata *mdp;
	fid_t cookie;

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_CNODE)
		printf("cachefs_cnode_make: ENTER fileno %llu\n",
		    (u_longlong_t)cidp->cid_fileno);
#endif

	/* get the file group that owns this file */
	mutex_enter(&fscp->fs_fslock);
	fgp = filegrp_list_find(fscp, cidp);
	if (fgp == NULL) {
		fgp = filegrp_create(fscp, cidp);
		filegrp_list_add(fscp, fgp);
	}
	filegrp_hold(fgp);
	mutex_exit(&fscp->fs_fslock);

	/* grab the cnode list lock */
	mutex_enter(&fgp->fg_cnodelock);

	if ((fgp->fg_flags & CFS_FG_READ) == 0)
		flag |= CN_NOCACHE;

	error = 0;
	cp = NULL;

	/* look for the cnode on the cnode list */
	error = cachefs_cnode_find(fgp, cidp, cookiep, &cp, backvp, vap);

	/*
	 * If there already is a cnode with this cid but a different cookie,
	 * (or backvp) we're not going to be using the one we found.
	 */
	if (error && CFS_ISFS_BACKFS_NFSV4(fscp)) {
		ASSERT(MUTEX_HELD(&cp->c_statelock));
		cachefs_cnode_stale(cp);
		mutex_exit(&cp->c_statelock);
		cp = NULL;
		error = 0;
	} else if (error) {
		ASSERT(cp);
		ASSERT(cookiep);

		mutex_exit(&cp->c_statelock);

		/*
		 * If backvp is NULL then someone tried to use
		 * a stale cookie.
		 */
		if (backvp == NULL) {
			mutex_exit(&fgp->fg_cnodelock);
			error = ESTALE;
			goto out;
		}

		/* verify the backvp */
		error = cachefs_getcookie(backvp, &cookie, NULL, cr, TRUE);
		if (error ||
		    ((cookiep->fid_len != cookie.fid_len) ||
		    (bcmp(&cookiep->fid_data, cookie.fid_data,
			(size_t)cookiep->fid_len) != 0))) {
			mutex_exit(&fgp->fg_cnodelock);
			error = ESTALE;
			goto out;
		}

		/* make the old cnode give up its front file resources */
		VN_HOLD(CTOV(cp));
		(void) cachefs_sync_metadata(cp);
		mutex_enter(&cp->c_statelock);
		mdp = &cp->c_metadata;
		if (mdp->md_rlno) {
			/* XXX sam: should this assert be NOCACHE? */
			/* XXX sam: maybe we should handle NOFILL as no-op */
			ASSERT((fscp->fs_cache->c_flags & CACHE_NOFILL) == 0);

			/* if modified in the cache, move to lost+found */
			if ((cp->c_attr.va_type == VREG) &&
			    (cp->c_metadata.md_rltype == CACHEFS_RL_MODIFIED)) {
				error = cachefs_cnode_lostfound(cp, NULL);
				if (error) {
					mutex_exit(&cp->c_statelock);
					VN_RELE(CTOV(cp));
					mutex_exit(&fgp->fg_cnodelock);
					error = ESTALE;
					goto out;
				}
			}

			/* else nuke the front file */
			else {
				cachefs_cnode_stale(cp);
			}
		} else {
			cachefs_cnode_stale(cp);
		}
		mutex_exit(&cp->c_statelock);
		VN_RELE(CTOV(cp));
		cp = NULL;
		error = 0;
	}


	/* if the cnode does not exist */
	if (cp == NULL) {
		/* XXX should we drop all locks for this? */
		cp = kmem_cache_alloc(cachefs_cnode_cache, KM_SLEEP);

		error = cachefs_cnode_init(cidp, cp, fscp, fgp,
		    cookiep, vap, backvp, flag, cr);
		if (error) {
			mutex_exit(&fgp->fg_cnodelock);
			vn_free(cp->c_vnode);
			kmem_cache_free(cachefs_cnode_cache, cp);
			goto out;
		}

		if (cp->c_metadata.md_rlno &&
		    (cp->c_metadata.md_rltype == CACHEFS_RL_GC) &&
		    ((fscp->fs_cache->c_flags & CACHE_NOFILL) == 0)) {
#ifdef CFSDEBUG
			cachefs_rlent_verify(fscp->fs_cache,
			    CACHEFS_RL_GC, cp->c_metadata.md_rlno);
#endif /* CFSDEBUG */
			cachefs_rlent_moveto(fscp->fs_cache,
			    CACHEFS_RL_ACTIVE, cp->c_metadata.md_rlno,
			    cp->c_metadata.md_frontblks);
			cp->c_metadata.md_rltype = CACHEFS_RL_ACTIVE;
			cp->c_flags |= CN_UPDATED;
		}

		cachefs_cnode_listadd(cp);
		vn_exists(cp->c_vnode);
		mutex_exit(&fgp->fg_cnodelock);
		(void) fscache_cnodecnt(fscp, 1);
	}

	/* else if the cnode exists */
	else {
		VN_HOLD(CTOV(cp));

		/* remove from idle list if on it */
		if (cp->c_flags & CN_IDLE) {
			cp->c_flags &= ~CN_IDLE;

			mutex_enter(&fscp->fs_idlelock);
			cachefs_cnode_idlerem(cp);
			mutex_exit(&fscp->fs_idlelock);
			VN_RELE(CTOV(cp));
			cp->c_ipending = 0;
		}
		mutex_exit(&cp->c_statelock);
		mutex_exit(&fgp->fg_cnodelock);
	}

	/*
	 * Assertion to ensure the cnode matches
	 * the backvp and attribute type information.
	 */
	ASSERT((CFS_ISFS_BACKFS_NFSV4(fscp) == 0) ||
		((cp->c_backvp == backvp) &&
		(cp->c_attr.va_type == vap->va_type)));
out:
	*cpp = ((error == 0) ? cp : NULL);
	filegrp_rele(fgp);

#ifdef CFSDEBUG
	CFS_DEBUG(CFSDEBUG_CNODE)
		printf("cachefs_cnode_make: EXIT cp %p, error %d\n",
		    (void *)*cpp, error);
#endif
	return (error);
}

/*
 * cachefs_cid_inuse()
 *
 * returns nonzero if a cid has any data in the cache; either a cnode
 * or metadata.
 */

int
cachefs_cid_inuse(filegrp_t *fgp, cfs_cid_t *cidp)
{
	cnode_t *cp;
	int status = 0;

	ASSERT(MUTEX_HELD(&fgp->fg_cnodelock));

	/*
	 * Since we don't care about the cookie data, we don't care about any
	 * status that find might return.
	 */

	cp = NULL;
	(void) cachefs_cnode_find(fgp, cidp, NULL, &cp, NULL, NULL);
	if (cp != NULL) {
		mutex_exit(&cp->c_statelock);
		status = 1;
		return (status);
	}

	/*
	 * Don't want to use filegrp_read_metadata, since it will return
	 * ENOENT if the metadata slot exists but hasn't been written to yet.
	 * That condition still counts as the slot (metadata) being in use.
	 * Instead, as long as the filegrp attrcache has been created and
	 * there's a slot assigned for this cid, then the metadata is in use.
	 */
	if (((fgp->fg_flags & CFS_FG_ALLOC_ATTR) == 0) &&
	    (filegrp_cid_to_slot(fgp, cidp) != 0))
		status = 1;

	return (status);
}

/*
 * cachefs_fileno_inuse()
 *
 * returns nonzero if a fileno is known to the cache, as either a
 * local or a normal file.
 */

int
cachefs_fileno_inuse(fscache_t *fscp, ino64_t fileno)
{
	cfs_cid_t cid;
	filegrp_t *fgp;
	int known = 0;

	ASSERT(MUTEX_HELD(&fscp->fs_fslock));
	cid.cid_fileno = fileno;

	/* if there's no filegrp for this cid range, then there's no data */
	fgp = filegrp_list_find(fscp, &cid);
	if (fgp == NULL)
		return (known);

	filegrp_hold(fgp);
	mutex_enter(&fgp->fg_cnodelock);

	cid.cid_flags = CFS_CID_LOCAL;
	if (cachefs_cid_inuse(fgp, &cid)) {
		known = 1;
		goto out;
	}
	cid.cid_flags = 0;
	if (cachefs_cid_inuse(fgp, &cid))
		known = 1;
out:
	mutex_exit(&fgp->fg_cnodelock);
	filegrp_rele(fgp);
	return (known);
}

/*
 * Creates a cnode from an unused inode in the cache.
 * The cnode is returned held.
 */
int
cachefs_cnode_create(fscache_t *fscp, vattr_t *vap, int flag, cnode_t **cpp)
{
	struct cnode *cp;
	int error, found;
	struct filegrp *fgp;
	cfs_cid_t cid, cid2;

	ASSERT(CFS_ISFS_SNR(fscp));
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	cid.cid_flags = CFS_CID_LOCAL;
	cid2.cid_flags = 0;

	/* find an unused local file in the cache */
	for (;;) {
		mutex_enter(&fscp->fs_fslock);

		/* make sure we did not wrap */
		fscp->fs_info.fi_localfileno++;
		if (fscp->fs_info.fi_localfileno == 0)
			fscp->fs_info.fi_localfileno = 3;
		cid.cid_fileno = fscp->fs_info.fi_localfileno;
		fscp->fs_flags |= CFS_FS_DIRTYINFO;

		/* avoid fileno conflict in non-local space */
		cid2.cid_fileno = cid.cid_fileno;
		fgp = filegrp_list_find(fscp, &cid2);
		if (fgp != NULL) {
			filegrp_hold(fgp);
			mutex_enter(&fgp->fg_cnodelock);
			found = cachefs_cid_inuse(fgp, &cid2);
			mutex_exit(&fgp->fg_cnodelock);
			filegrp_rele(fgp);
			if (found) {
				mutex_exit(&fscp->fs_fslock);
				continue;
			}
		}

		/* get the file group that owns this fileno */
		fgp = filegrp_list_find(fscp, &cid);
		if (fgp == NULL) {
			fgp = filegrp_create(fscp, &cid);
			filegrp_list_add(fscp, fgp);
		}

		/* see if there is any room left in this file group */
		mutex_enter(&fgp->fg_mutex);
		if (fgp->fg_header &&
		    (fgp->fg_header->ach_count ==
		    fscp->fs_info.fi_fgsize)) {
			/* no more room, set up for the next file group */
			fscp->fs_info.fi_localfileno = fgp->fg_id.cid_fileno +
			    fscp->fs_info.fi_fgsize;
			mutex_exit(&fgp->fg_mutex);
			mutex_exit(&fscp->fs_fslock);
			continue;
		}
		mutex_exit(&fgp->fg_mutex);

		filegrp_hold(fgp);
		mutex_exit(&fscp->fs_fslock);

		ASSERT((fgp->fg_flags &
		    (CFS_FG_READ | CFS_FG_WRITE)) ==
		    (CFS_FG_READ | CFS_FG_WRITE));

		/* grab the cnode list lock */
		mutex_enter(&fgp->fg_cnodelock);

		if ((fgp->fg_flags & CFS_FG_READ) == 0)
			flag |= CN_NOCACHE;

		/* keep looking if a cnode or metadata exist for this fileno */
		if (cachefs_cid_inuse(fgp, &cid)) {
			mutex_exit(&fgp->fg_cnodelock);
			filegrp_rele(fgp);
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_CNODE)
				cmn_err(CE_NOTE, "cachefs_cnode_create: "
				    "fileno %llu exists.\n",
				    (u_longlong_t)cid.cid_fileno);
#endif
			continue;
		}
		break;
	}

	vap->va_nodeid = cid.cid_fileno;

	/* create space for the cnode */
	cp = kmem_cache_alloc(cachefs_cnode_cache, KM_SLEEP);

	/* set up the cnode */
	error = cachefs_cnode_init(&cid, cp, fscp, fgp,
	    &cp->c_cookie, vap, NULL, flag, kcred);
	if (error) {
		mutex_exit(&fgp->fg_cnodelock);
		vn_free(cp->c_vnode);
		kmem_cache_free(cachefs_cnode_cache, cp);
		goto out;
	}

	/* save copy of fileno that is returned to the user */
	cp->c_metadata.md_flags |= MD_LOCALFILENO;
	cp->c_metadata.md_localfileno = cid.cid_fileno;
	cp->c_flags |= CN_UPDATED;

	cachefs_cnode_listadd(cp);
	mutex_exit(&fgp->fg_cnodelock);
	(void) fscache_cnodecnt(fscp, 1);

out:
	*cpp = ((error == 0) ? cp : NULL);
	filegrp_rele(fgp);
	return (error);
}

/*
 * Moves the cnode to its new location in the cache.
 * Before calling this routine other steps must be taken
 * to ensure that other file system routines that operate
 * on cnodes do not run.
 */
void
cachefs_cnode_move(cnode_t *cp)
{
	fscache_t *fscp = C_TO_FSCACHE(cp);
	cfs_cid_t cid;
	filegrp_t *fgp;
	filegrp_t *ofgp = cp->c_filegrp;
	struct cachefs_metadata *mdp;
	cnode_t *xcp;
	char oname[CFS_FRONTFILE_NAME_SIZE];
	char nname[CFS_FRONTFILE_NAME_SIZE];
	int ffnuke = 0;
	int error;

	ASSERT(CFS_ISFS_SNR(fscp));
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);
	ASSERT(cp->c_id.cid_flags & CFS_CID_LOCAL);
	ASSERT(cp->c_attr.va_nodeid != 0);

	/* construct the cid of the new file location */
	cid.cid_fileno = cp->c_attr.va_nodeid;
	cid.cid_flags = 0;

	/* see if there already is a file occupying our slot */
	error = cachefs_cnode_make(&cid, fscp, NULL, NULL, NULL, kcred,
	    0, &xcp);
	if (error == 0) {
		mutex_enter(&xcp->c_statelock);
		cachefs_cnode_stale(xcp);
		mutex_exit(&xcp->c_statelock);
		VN_RELE(CTOV(xcp));
		xcp = NULL;
		error = 0;
	}

	/* get the file group that this file is moving to */
	mutex_enter(&fscp->fs_fslock);
	fgp = filegrp_list_find(fscp, &cid);
	if (fgp == NULL) {
		fgp = filegrp_create(fscp, &cid);
		filegrp_list_add(fscp, fgp);
	}
	filegrp_hold(fgp);
	mutex_exit(&fscp->fs_fslock);

	/* XXX fix to not have to create metadata to hold rl slot */
	/* get a metadata slot in the new file group */
	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
		(void) filegrp_allocattr(fgp);
	}
	/* XXX can fix create_metadata to call allocattr if necessary? */
	error = filegrp_create_metadata(fgp, &cp->c_metadata, &cid);
	if (error)
		ffnuke = 1;
	if ((ffnuke == 0) && filegrp_ffhold(fgp))
		ffnuke = 1;

	/* move the front file to the new file group */
	if ((ffnuke == 0) && (cp->c_metadata.md_flags & MD_FILE)) {
		make_ascii_name(&cp->c_id, oname);
		make_ascii_name(&cid, nname);
		error = VOP_RENAME(ofgp->fg_dirvp, oname, fgp->fg_dirvp,
			nname, kcred, NULL, 0);
		if (error) {
			ffnuke = 1;
#ifdef CFSDEBUG
			if (error != ENOSPC) {
				CFS_DEBUG(CFSDEBUG_CNODE)
					printf("cachefs: cnode_move "
					    "1: error %d\n", error);
			}
#endif
		}
	}

	/* remove the file from the old file group */
	mutex_enter(&ofgp->fg_cnodelock);
	mutex_enter(&cp->c_statelock);
	if (cp->c_frontvp) {
		VN_RELE(cp->c_frontvp);
		cp->c_frontvp = NULL;
	}
	if (cp->c_acldirvp) {
		VN_RELE(cp->c_acldirvp);
		cp->c_acldirvp = NULL;
	}
	mdp = &cp->c_metadata;
	if (mdp->md_rlno) {
		if (ffnuke) {
			cachefs_removefrontfile(mdp, &cp->c_id, ofgp);
			cachefs_rlent_moveto(fscp->fs_cache,
			    CACHEFS_RL_FREE, mdp->md_rlno, 0);
			mdp->md_rlno = 0;
			mdp->md_rltype = CACHEFS_RL_NONE;
		} else {
			filegrp_ffrele(ofgp);
		}
	}
	if (ffnuke)
		mdp->md_flags &= ~MD_PACKED;
	if ((cp->c_flags & CN_ALLOC_PENDING) == 0) {
		(void) filegrp_destroy_metadata(ofgp, &cp->c_id);
		cp->c_flags |= CN_ALLOC_PENDING;
	}
	cachefs_cnode_listrem(cp);
	cp->c_filegrp = NULL;
	mutex_exit(&cp->c_statelock);
	mutex_exit(&ofgp->fg_cnodelock);

	/* add the cnode to the new file group */
	mutex_enter(&fgp->fg_cnodelock);
	mutex_enter(&cp->c_statelock);
	cp->c_id = cid;
	cp->c_filegrp = fgp;
	cp->c_flags |= CN_UPDATED;
	mutex_exit(&cp->c_statelock);
	cachefs_cnode_listadd(cp);
	if (mdp->md_rlno)
		cachefs_rl_changefileno(fscp->fs_cache, mdp->md_rlno,
		    cp->c_id.cid_fileno);
	mutex_exit(&fgp->fg_cnodelock);

	filegrp_rele(ofgp);
}

/*
 * Syncs out the specified cnode.
 * Only called via cnode_traverse from fscache_sync
 */
void
cachefs_cnode_sync(cnode_t *cp)
{
	vnode_t *vp = CTOV(cp);
	int error = 0;
	fscache_t *fscp = C_TO_FSCACHE(cp);
	int held = 0;

	if (cp->c_flags & (CN_STALE | CN_DESTROY))
		return;

	if (fscp->fs_backvfsp && fscp->fs_backvfsp->vfs_flag & VFS_RDONLY)
		return;

	for (;;) {
		/* get (or renew) access to the file system */
		if (held) {
			cachefs_cd_release(fscp);
			held = 0;
		}
		/*
		 * Getting file system access for reading is really cheating.
		 * However we are getting called from sync so we do not
		 * want to hang up if the cachefsd is not running.
		 */
		error = cachefs_cd_access(fscp, 0, 0);
		if (error)
			break;
		held = 1;

		/* if a regular file, write out the pages */
		if ((vp->v_type == VREG) && vn_has_cached_data(vp)) {
			ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);
			error = cachefs_putpage_common(vp, (offset_t)0,
			    0, 0, kcred);
			if (CFS_TIMEOUT(fscp, error)) {
				if (fscp->fs_cdconnected == CFS_CD_CONNECTED) {
					cachefs_cd_release(fscp);
					held = 0;
					cachefs_cd_timedout(fscp);
					continue;
				} else {
					/* cannot push, give up */
					break;
				}
			}

			/* clear the cnode error if putpage worked */
			if ((error == 0) && cp->c_error) {
				mutex_enter(&cp->c_statelock);
				cp->c_error = 0;
				mutex_exit(&cp->c_statelock);
			}

			if (error)
				break;
		}

		/* if connected, sync the backvp */
		if ((fscp->fs_cdconnected == CFS_CD_CONNECTED) &&
		    cp->c_backvp) {
			mutex_enter(&cp->c_statelock);
			if (cp->c_backvp) {
				error = VOP_FSYNC(cp->c_backvp, FSYNC, kcred,
				    NULL);
				if (CFS_TIMEOUT(fscp, error)) {
					mutex_exit(&cp->c_statelock);
					cachefs_cd_release(fscp);
					held = 0;
					cachefs_cd_timedout(fscp);
					continue;
				} else if (error && (error != EINTR))
					cp->c_error = error;
			}
			mutex_exit(&cp->c_statelock);
		}

		/* sync the metadata and the front file to the front fs */
		(void) cachefs_sync_metadata(cp);
		break;
	}

	if (held)
		cachefs_cd_release(fscp);
}

/*
 * Moves the specified file to the lost+found directory for the
 * cached file system.
 * Invalidates cached data and attributes.
 * Returns 0 or an error if could not perform operation.
 */
int
cachefs_cnode_lostfound(cnode_t *cp, char *rname)
{
	int error = 0;
	fscache_t *fscp;
	cachefscache_t *cachep;
	char oname[CFS_FRONTFILE_NAME_SIZE];
	filegrp_t *fgp;
	char *namep, *strp;
	char *namebuf = NULL;
	vnode_t *nvp;
	int index;
	int len;

	fscp = C_TO_FSCACHE(cp);
	cachep = fscp->fs_cache;

	ASSERT(MUTEX_HELD(&cp->c_statelock));
	ASSERT((cachep->c_flags & (CACHE_NOCACHE|CACHE_NOFILL)) == 0);
	ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

	fgp = cp->c_filegrp;

	/* set up the file group if necessary */
	if (fgp->fg_flags & CFS_FG_ALLOC_ATTR) {
		error = filegrp_allocattr(fgp);
		if (error)
			goto out;
	}
	ASSERT(fgp->fg_dirvp);

	namebuf = cachefs_kmem_alloc(MAXNAMELEN * 2, KM_SLEEP);

	if ((cp->c_attr.va_type != VREG) ||
	    (cp->c_metadata.md_rltype != CACHEFS_RL_MODIFIED) ||
	    ((cp->c_metadata.md_flags & MD_POPULATED) == 0) ||
	    ((cp->c_metadata.md_flags & MD_FILE) == 0) ||
	    (cp->c_metadata.md_rlno == 0)) {
#ifdef CFSDEBUG
		CFS_DEBUG(CFSDEBUG_CNODE)
			printf("cachefs_cnode_lostfound cp %p cannot save\n",
			    (void *)cp);
#endif
		error = EINVAL;
		goto out;
	}

	/* lock out other users of the lost+found directory */
	mutex_enter(&cachep->c_contentslock);

	/* find a name we can use in lost+found */
	if (rname)
		namep = rname;
	else
		namep = "lostfile";
	error = VOP_LOOKUP(cachep->c_lostfoundvp, namep, &nvp,
	    NULL, 0, NULL, kcred, NULL, NULL, NULL);
	if (error == 0)
		VN_RELE(nvp);
	if (error != ENOENT) {
#define		MAXTRIES 1000
		strp = namep;
		for (index = 0; index < MAXTRIES; index++) {
			(void) sprintf(namebuf, "%s.%" PRIx64, strp,
			    gethrestime_sec() * cp->c_id.cid_fileno * index);
			len = (int)strlen(namebuf) + 1;
			if (len > MAXNAMELEN)
				namep = &namebuf[len - MAXNAMELEN];
			else
				namep = namebuf;
			error = VOP_LOOKUP(cachep->c_lostfoundvp, namep, &nvp,
			    NULL, 0, NULL, kcred, NULL, NULL, NULL);
			if (error == 0)
				VN_RELE(nvp);
			if (error == ENOENT)
				break;
		}
		if (index == MAXTRIES) {
			error = EIO;
			mutex_exit(&cachep->c_contentslock);
			goto out;
		}
	}

	/* get the name of the front file */
	make_ascii_name(&cp->c_id, oname);

	/* rename the file into the lost+found directory */
	error = VOP_RENAME(fgp->fg_dirvp, oname, cachep->c_lostfoundvp,
	    namep, kcred, NULL, 0);
	if (error) {
		mutex_exit(&cachep->c_contentslock);
		goto out;
	}
	mutex_exit(&cachep->c_contentslock);

	/* copy out the new name */
	if (rname)
		(void) strcpy(rname, namep);

out:
	/* clean up */
	cachefs_cnode_stale(cp);

	if (namebuf)
		cachefs_kmem_free(namebuf, MAXNAMELEN * 2);

#if 0 /* XXX until we can put filesystem in read-only mode */
	if (error) {
		/* XXX put file system in read-only mode */
	}
#endif

	return (error);
}

/*
 * Traverses the list of cnodes on the fscache and calls the
 * specified routine with the held cnode.
 */
void
cachefs_cnode_traverse(fscache_t *fscp, void (*routinep)(cnode_t *))
{
	filegrp_t *fgp, *ofgp;
	cnode_t *cp, *ocp;
	int index;

	/* lock the fscache while we traverse the file groups */
	mutex_enter(&fscp->fs_fslock);

	/* for each bucket of file groups */
	for (index = 0; index < CFS_FS_FGP_BUCKET_SIZE; index++) {
		ofgp = NULL;

		/* for each file group in a bucket */
		for (fgp = fscp->fs_filegrp[index];
		    fgp != NULL;
		    fgp = fgp->fg_next) {

			/* hold the file group */
			filegrp_hold(fgp);

			/* drop fscache lock so others can use it */
			mutex_exit(&fscp->fs_fslock);

			/* drop hold on previous file group */
			if (ofgp)
				filegrp_rele(ofgp);
			ofgp = fgp;

			/* lock the cnode list while we traverse it */
			mutex_enter(&fgp->fg_cnodelock);
			ocp = NULL;

			/* for each cnode in this file group */
			for (cp = fgp->fg_cnodelist;
			    cp != NULL;
			    cp = cp->c_next) {

				/* hold the cnode */
				VN_HOLD(CTOV(cp));

				/* drop cnode list lock so others can use it */
				mutex_exit(&fgp->fg_cnodelock);

				/* drop hold on previous cnode */
				if (ocp) {
					VN_RELE(CTOV(ocp));
				}
				ocp = cp;

				/*
				 * Execute routine for this cnode.
				 * At this point no locks are held.
				 */
				(routinep)(cp);

				/* reacquire the cnode list lock */
				mutex_enter(&fgp->fg_cnodelock);
			}

			/* drop cnode list lock */
			mutex_exit(&fgp->fg_cnodelock);

			/* drop hold on last cnode */
			if (ocp) {
				VN_RELE(CTOV(ocp));
			}

			/* reacquire the fscache lock */
			mutex_enter(&fscp->fs_fslock);
		}

		/* drop hold on last file group */
		if (ofgp)
			filegrp_rele(ofgp);
	}
	mutex_exit(&fscp->fs_fslock);
}

void
cachefs_cnode_disable_caching(struct cnode *cp)
{
	mutex_enter(&cp->c_statelock);
	cp->c_flags |= CN_NOCACHE;
	if (cp->c_frontvp != NULL) {
		VN_RELE(cp->c_frontvp);
		cp->c_frontvp = NULL;
	}
	mutex_exit(&cp->c_statelock);
}

#define	TIMEMATCH(a, b)	((a)->tv_sec == (b)->tv_sec && \
	(a)->tv_nsec == (b)->tv_nsec)

static void
cnode_enable_caching(struct cnode *cp)
{
	struct vnode *iovp;
	struct filegrp *fgp;
	struct cachefs_metadata md;
	cachefscache_t *cachep = C_TO_FSCACHE(cp)->fs_cache;
	int error;

	ASSERT((cachep->c_flags & (CACHE_NOFILL | CACHE_NOCACHE)) == 0);
	ASSERT(CFS_ISFS_BACKFS_NFSV4(C_TO_FSCACHE(cp)) == 0);

	iovp = NULL;
	if (CTOV(cp)->v_type == VREG)
		iovp = cp->c_backvp;
	if (iovp) {
		(void) VOP_PUTPAGE(iovp, (offset_t)0,
		    (uint_t)0, B_INVAL, kcred, NULL);
	}
	mutex_enter(&cp->c_statelock);
	if (cp->c_backvp) {
		VN_RELE(cp->c_backvp);
		cp->c_backvp = NULL;
	}
	fgp = cp->c_filegrp;
	ASSERT(fgp);
	error = filegrp_read_metadata(fgp, &cp->c_id, &md);
	if (error == 0) {
		if ((cachep->c_flags & CACHE_CHECK_RLTYPE) &&
		    (md.md_rlno != 0) &&
		    (md.md_rltype == CACHEFS_RL_ACTIVE)) {
			rl_entry_t *rlp, rl;

			mutex_enter(&cachep->c_contentslock);
			error = cachefs_rl_entry_get(cachep, md.md_rlno, &rlp);
			if (error) {
				mutex_exit(&cachep->c_contentslock);
				goto out;
			}

			rl = *rlp;
			mutex_exit(&cachep->c_contentslock);

			if (rl.rl_current != md.md_rltype) {
				md.md_rltype = rl.rl_current;
				cp->c_flags |= CN_UPDATED;
			}
		}

		/*
		 * A rudimentary consistency check
		 * here.  If the cookie and mtime
		 * from the cnode match those from the
		 * cache metadata, we assume for now that
		 * the cached data is OK.
		 */
		if (bcmp(&md.md_cookie.fid_data, &cp->c_cookie.fid_data,
			(size_t)cp->c_cookie.fid_len) == 0 &&
		    TIMEMATCH(&cp->c_attr.va_mtime, &md.md_vattr.va_mtime)) {
			cp->c_metadata = md;
		} else {
			/*
			 * Here we're skeptical about the validity of
			 * the front file.
			 * We'll keep the attributes already present in
			 * the cnode, and bring along the parts of the
			 * metadata that we need to eventually nuke this
			 * bogus front file -- in inactive or getfrontfile,
			 * whichever comes first...
			 */
			if (cp->c_frontvp != NULL) {
				VN_RELE(cp->c_frontvp);
				cp->c_frontvp = NULL;
			}
			cp->c_metadata.md_flags = md.md_flags;
			cp->c_metadata.md_flags |= MD_NEEDATTRS;
			cp->c_metadata.md_rlno = md.md_rlno;
			cp->c_metadata.md_rltype = md.md_rltype;
			cp->c_metadata.md_consttype = md.md_consttype;
			cp->c_metadata.md_fid = md.md_fid;
			cp->c_metadata.md_frontblks = md.md_frontblks;
			cp->c_metadata.md_timestamp.tv_sec = 0;
			cp->c_metadata.md_timestamp.tv_nsec = 0;
			bzero(&cp->c_metadata.md_allocinfo,
			    cp->c_metadata.md_allocents *
			    sizeof (struct cachefs_allocmap));
			cp->c_metadata.md_allocents = 0;
			cp->c_metadata.md_flags &= ~MD_POPULATED;
			if ((cp->c_metadata.md_rlno != 0) &&
			    (cp->c_metadata.md_rltype == CACHEFS_RL_PACKED)) {
				cachefs_rlent_moveto(cachep,
				    CACHEFS_RL_PACKED_PENDING,
				    cp->c_metadata.md_rlno,
				    cp->c_metadata.md_frontblks);
				cp->c_metadata.md_rltype =
				    CACHEFS_RL_PACKED_PENDING;
			}

			cp->c_flags |= CN_UPDATED;
#ifdef CFSDEBUG
			CFS_DEBUG(CFSDEBUG_GENERAL) {
				printf(
				    "fileno %lld ignores cached data due "
				    "to cookie and/or mtime mismatch\n",
				    (longlong_t)cp->c_id.cid_fileno);
			}
#endif
		}
		if (cp->c_metadata.md_rltype == CACHEFS_RL_GC) {
			cachefs_rlent_moveto(cachep, CACHEFS_RL_ACTIVE,
			    cp->c_metadata.md_rlno,
			    cp->c_metadata.md_frontblks);
			cp->c_metadata.md_rltype = CACHEFS_RL_ACTIVE;
			cp->c_flags |= CN_UPDATED;
		}
	}

out:
	cp->c_flags &= ~CN_NOCACHE;
	mutex_exit(&cp->c_statelock);

	(void) cachefs_pack_common(CTOV(cp), kcred);
}

void
cachefs_enable_caching(struct fscache *fscp)
{

	/*
	 * This function is only called when a remount occurs,
	 * with "nocache" and "nofill" options configured
	 * (currently these aren't supported). Since this
	 * function can write into the cache, make sure that
	 * its not in use with NFSv4.
	 */
	if (CFS_ISFS_BACKFS_NFSV4(fscp))
		return;

	/*
	 * set up file groups so we can read them.  Note that general
	 * users (makecfsnode) will *not* start using them (i.e., all
	 * newly created cnodes will be NOCACHE)
	 * until we "enable_caching_rw" below.
	 */
	mutex_enter(&fscp->fs_fslock);
	filegrp_list_enable_caching_ro(fscp);
	mutex_exit(&fscp->fs_fslock);

	cachefs_cnode_traverse(fscp, cnode_enable_caching);

	/* enable general use of the filegrps */
	mutex_enter(&fscp->fs_fslock);
	filegrp_list_enable_caching_rw(fscp);
	mutex_exit(&fscp->fs_fslock);
}

/*
 * This function makes a cnode stale by performing the following tasks:
 *	1) remove the front file
 *	2) Remove any resource file entries
 *	3) Remove any metadata entry from the attrcache file
 * 	4) Set the stale bit in the cnode flags field
 */
void
cachefs_cnode_stale(cnode_t *cp)
{
	fscache_t *fscp = C_TO_FSCACHE(cp);
	struct cachefs_metadata *mdp;

	ASSERT(MUTEX_HELD(&cp->c_statelock));

	/*
	 * Remove a metadata entry if the file exists
	 */
	mdp = &cp->c_metadata;
	if (mdp->md_rlno) {

		ASSERT(CFS_ISFS_BACKFS_NFSV4(fscp) == 0);

		/*
		 * destroy the frontfile
		 */
		cachefs_removefrontfile(mdp, &cp->c_id, cp->c_filegrp);
		/*
		 * Remove resource file entry
		 */
		cachefs_rlent_moveto(fscp->fs_cache, CACHEFS_RL_FREE,
		    mdp->md_rlno, 0);
		mdp->md_rlno = 0;
		mdp->md_rltype = CACHEFS_RL_NONE;
	}

	/*
	 * Remove attrcache metadata
	 */
	if (CFS_ISFS_BACKFS_NFSV4(fscp) == 0)
		(void) filegrp_destroy_metadata(cp->c_filegrp, &cp->c_id);
	mdp->md_flags = 0;

	if (cp->c_frontvp) {
		VN_RELE(cp->c_frontvp);
		cp->c_frontvp = NULL;
	}

	/*
	 * For NFSv4 need to hang on to the backvp until vn_rele()
	 * frees this cnode.
	 */
	if (cp->c_backvp && !CFS_ISFS_BACKFS_NFSV4(fscp)) {
		VN_RELE(cp->c_backvp);
		cp->c_backvp = NULL;
	}
	if (cp->c_acldirvp) {
		VN_RELE(cp->c_acldirvp);
		cp->c_acldirvp = NULL;
	}

	cp->c_flags |= CN_STALE | CN_ALLOC_PENDING | CN_NOCACHE;
}

/*
 * Sets up the local attributes in the metadata from the attributes.
 */
void
cachefs_cnode_setlocalstats(cnode_t *cp)
{
	fscache_t *fscp = C_TO_FSCACHE(cp);
	cachefs_metadata_t *mdp = &cp->c_metadata;

	ASSERT(MUTEX_HELD(&cp->c_statelock));

	/* allow over writing of local attributes if a remount occurred */
	if (fscp->fs_info.fi_resettimes != mdp->md_resettimes) {
		mdp->md_flags &= ~(MD_LOCALCTIME | MD_LOCALMTIME);
		mdp->md_resettimes = fscp->fs_info.fi_resettimes;
	}
	if (fscp->fs_info.fi_resetfileno != mdp->md_resetfileno) {
		mdp->md_flags &= ~MD_LOCALFILENO;
		mdp->md_resetfileno = fscp->fs_info.fi_resetfileno;
	}

	/* overwrite old fileno and timestamps if not local versions */
	if ((mdp->md_flags & MD_LOCALFILENO) == 0)
		mdp->md_localfileno = mdp->md_vattr.va_nodeid;
	if ((mdp->md_flags & MD_LOCALCTIME) == 0)
		mdp->md_localctime = mdp->md_vattr.va_ctime;
	if ((mdp->md_flags & MD_LOCALMTIME) == 0)
		mdp->md_localmtime = mdp->md_vattr.va_mtime;
	cp->c_flags |= CN_UPDATED;
}
