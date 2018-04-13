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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 *	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All rights reserved.
 */

#include <sys/param.h>
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

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>

#define	ATTRCACHE_VALID(vp)	(gethrtime() < VTOSMB(vp)->r_attrtime)

static int smbfs_getattr_cache(vnode_t *, smbfattr_t *);
static void smbfattr_to_vattr(vnode_t *, smbfattr_t *, vattr_t *);
static void smbfattr_to_xvattr(smbfattr_t *, vattr_t *);
static int smbfs_getattr_otw(vnode_t *, struct smbfattr *, cred_t *);


/*
 * The following code provide zone support in order to perform an action
 * for each smbfs mount in a zone.  This is also where we would add
 * per-zone globals and kernel threads for the smbfs module (since
 * they must be terminated by the shutdown callback).
 */

struct smi_globals {
	kmutex_t	smg_lock;  /* lock protecting smg_list */
	list_t		smg_list;  /* list of SMBFS mounts in zone */
	boolean_t	smg_destructor_called;
};
typedef struct smi_globals smi_globals_t;

static zone_key_t smi_list_key;

/*
 * Attributes caching:
 *
 * Attributes are cached in the smbnode in struct vattr form.
 * There is a time associated with the cached attributes (r_attrtime)
 * which tells whether the attributes are valid. The time is initialized
 * to the difference between current time and the modify time of the vnode
 * when new attributes are cached. This allows the attributes for
 * files that have changed recently to be timed out sooner than for files
 * that have not changed for a long time. There are minimum and maximum
 * timeout values that can be set per mount point.
 */

/*
 * Helper for _validate_caches
 */
int
smbfs_waitfor_purge_complete(vnode_t *vp)
{
	smbnode_t *np;
	k_sigset_t smask;

	np = VTOSMB(vp);
	if (np->r_serial != NULL && np->r_serial != curthread) {
		mutex_enter(&np->r_statelock);
		sigintr(&smask, VTOSMI(vp)->smi_flags & SMI_INT);
		while (np->r_serial != NULL) {
			if (!cv_wait_sig(&np->r_cv, &np->r_statelock)) {
				sigunintr(&smask);
				mutex_exit(&np->r_statelock);
				return (EINTR);
			}
		}
		sigunintr(&smask);
		mutex_exit(&np->r_statelock);
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
smbfs_validate_caches(
	struct vnode *vp,
	cred_t *cr)
{
	struct smbfattr fa;
	int error;

	if (ATTRCACHE_VALID(vp)) {
		error = smbfs_waitfor_purge_complete(vp);
		if (error)
			return (error);
		return (0);
	}

	return (smbfs_getattr_otw(vp, &fa, cr));
}

/*
 * Purge all of the various data caches.
 *
 * Here NFS also had a flags arg to control what gets flushed.
 * We only have the page cache, so no flags arg.
 */
/* ARGSUSED */
void
smbfs_purge_caches(struct vnode *vp, cred_t *cr)
{

	/*
	 * Here NFS has: Purge the DNLC for this vp,
	 * Clear any readdir state bits,
	 * the readlink response cache, ...
	 */

	/*
	 * Flush the page cache.
	 */
	if (vn_has_cached_data(vp)) {
		(void) VOP_PUTPAGE(vp, (u_offset_t)0, 0, B_INVAL, cr, NULL);
	}

	/*
	 * Here NFS has: Flush the readdir response cache.
	 * No readdir cache in smbfs.
	 */
}

/*
 * Here NFS has:
 * nfs_purge_rddir_cache()
 * nfs3_cache_post_op_attr()
 * nfs3_cache_post_op_vattr()
 * nfs3_cache_wcc_data()
 */

/*
 * Check the attribute cache to see if the new attributes match
 * those cached.  If they do, the various `data' caches are
 * considered to be good.  Otherwise, purge the cached data.
 */
static void
smbfs_cache_check(
	struct vnode *vp,
	struct smbfattr *fap,
	cred_t *cr)
{
	smbnode_t *np;
	int purge_data = 0;
	int purge_acl = 0;

	np = VTOSMB(vp);
	mutex_enter(&np->r_statelock);

	/*
	 * Compare with NFS macro: CACHE_VALID
	 * If the mtime or size has changed,
	 * purge cached data.
	 */
	if (np->r_attr.fa_mtime.tv_sec != fap->fa_mtime.tv_sec ||
	    np->r_attr.fa_mtime.tv_nsec != fap->fa_mtime.tv_nsec)
		purge_data = 1;
	if (np->r_attr.fa_size != fap->fa_size)
		purge_data = 1;

	if (np->r_attr.fa_ctime.tv_sec != fap->fa_ctime.tv_sec ||
	    np->r_attr.fa_ctime.tv_nsec != fap->fa_ctime.tv_nsec)
		purge_acl = 1;

	if (purge_acl) {
		np->r_sectime = gethrtime();
	}

	mutex_exit(&np->r_statelock);

	if (purge_data)
		smbfs_purge_caches(vp, cr);
}

/*
 * Set attributes cache for given vnode using SMB fattr
 * and update the attribute cache timeout.
 *
 * Based on NFS: nfs_attrcache, nfs_attrcache_va
 */
void
smbfs_attrcache_fa(vnode_t *vp, struct smbfattr *fap)
{
	smbnode_t *np;
	smbmntinfo_t *smi;
	hrtime_t delta, now;
	u_offset_t newsize;
	vtype_t	 vtype, oldvt;
	mode_t mode;

	np = VTOSMB(vp);
	smi = VTOSMI(vp);

	/*
	 * We allow v_type to change, so set that here
	 * (and the mode, which depends on the type).
	 */
	if (fap->fa_attr & SMB_FA_DIR) {
		vtype = VDIR;
		mode = smi->smi_dmode;
	} else {
		vtype = VREG;
		mode = smi->smi_fmode;
	}

	mutex_enter(&np->r_statelock);
	now = gethrtime();

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
	 * using mixed client and server times.  SMBFS
	 * does not make any assumptions regarding the
	 * client and server clocks being synchronized.
	 */
	if (fap->fa_mtime.tv_sec  != np->r_attr.fa_mtime.tv_sec ||
	    fap->fa_mtime.tv_nsec != np->r_attr.fa_mtime.tv_nsec ||
	    fap->fa_size	  != np->r_attr.fa_size)
		np->r_mtime = now;

	if ((smi->smi_flags & SMI_NOAC) || (vp->v_flag & VNOCACHE))
		delta = 0;
	else {
		delta = now - np->r_mtime;
		if (vtype == VDIR) {
			if (delta < smi->smi_acdirmin)
				delta = smi->smi_acdirmin;
			else if (delta > smi->smi_acdirmax)
				delta = smi->smi_acdirmax;
		} else {
			if (delta < smi->smi_acregmin)
				delta = smi->smi_acregmin;
			else if (delta > smi->smi_acregmax)
				delta = smi->smi_acregmax;
		}
	}

	np->r_attrtime = now + delta;
	np->r_attr = *fap;
	np->n_mode = mode;
	oldvt = vp->v_type;
	vp->v_type = vtype;

	/*
	 * Shall we update r_size? (local notion of size)
	 *
	 * The real criteria for updating r_size should be:
	 * if the file has grown on the server, or if
	 * the client has not modified the file.
	 *
	 * Also deal with the fact that SMB presents
	 * directories as having size=0.  Doing that
	 * here and leaving fa_size as returned OtW
	 * avoids fixing the size lots of places.
	 */
	newsize = fap->fa_size;
	if (vtype == VDIR && newsize < DEV_BSIZE)
		newsize = DEV_BSIZE;

	if (np->r_size != newsize &&
	    (!vn_has_cached_data(vp) ||
	    (!(np->r_flags & RDIRTY) && np->r_count == 0))) {
		/* OK to set the size. */
		np->r_size = newsize;
	}

	/*
	 * Here NFS has:
	 * nfs_setswaplike(vp, va);
	 * np->r_flags &= ~RWRITEATTR;
	 * (not needed here)
	 */

	np->n_flag &= ~NATTRCHANGED;
	mutex_exit(&np->r_statelock);

	if (oldvt != vtype) {
		SMBVDEBUG("vtype change %d to %d\n", oldvt, vtype);
	}
}

/*
 * Fill in attribute from the cache.
 *
 * If valid, copy to *fap and return zero,
 * otherwise return an error.
 *
 * From NFS: nfs_getattr_cache()
 */
int
smbfs_getattr_cache(vnode_t *vp, struct smbfattr *fap)
{
	smbnode_t *np;
	int error;

	np = VTOSMB(vp);

	mutex_enter(&np->r_statelock);
	if (gethrtime() >= np->r_attrtime) {
		/* cache expired */
		error = ENOENT;
	} else {
		/* cache is valid */
		*fap = np->r_attr;
		error = 0;
	}
	mutex_exit(&np->r_statelock);

	return (error);
}

/*
 * Get attributes over-the-wire and update attributes cache
 * if no error occurred in the over-the-wire operation.
 * Return 0 if successful, otherwise error.
 * From NFS: nfs_getattr_otw
 */
static int
smbfs_getattr_otw(vnode_t *vp, struct smbfattr *fap, cred_t *cr)
{
	struct smbnode *np;
	struct smb_cred scred;
	int error;

	np = VTOSMB(vp);

	/*
	 * Here NFS uses the ACL RPC (if smi_flags & SMI_ACL)
	 * With SMB, getting the ACL is a significantly more
	 * expensive operation, so we do that only when asked
	 * for the uid/gid.  See smbfsgetattr().
	 */

	/* Shared lock for (possible) n_fid use. */
	if (smbfs_rw_enter_sig(&np->r_lkserlock, RW_READER, SMBINTR(vp)))
		return (EINTR);
	smb_credinit(&scred, cr);

	bzero(fap, sizeof (*fap));
	error = smbfs_smb_getfattr(np, fap, &scred);

	smb_credrele(&scred);
	smbfs_rw_exit(&np->r_lkserlock);

	if (error) {
		/* Here NFS has: PURGE_STALE_FH(error, vp, cr) */
		smbfs_attrcache_remove(np);
		if (error == ENOENT || error == ENOTDIR) {
			/*
			 * Getattr failed because the object was
			 * removed or renamed by another client.
			 * Remove any cached attributes under it.
			 */
			smbfs_attrcache_prune(np);
		}
		return (error);
	}

	/*
	 * Here NFS has: nfs_cache_fattr(vap, fa, vap, t, cr);
	 * which did: fattr_to_vattr, nfs_attr_cache.
	 * We cache the fattr form, so just do the
	 * cache check and store the attributes.
	 */
	smbfs_cache_check(vp, fap, cr);
	smbfs_attrcache_fa(vp, fap);

	return (0);
}

/*
 * Return either cached or remote attributes. If we get remote attrs,
 * use them to check and invalidate caches, then cache the new attributes.
 *
 * From NFS: nfsgetattr()
 */
int
smbfsgetattr(vnode_t *vp, struct vattr *vap, cred_t *cr)
{
	struct smbfattr fa;
	smbmntinfo_t *smi;
	uint_t mask;
	int error;

	smi = VTOSMI(vp);

	ASSERT(curproc->p_zone == smi->smi_zone_ref.zref_zone);

	/*
	 * If asked for UID or GID, update n_uid, n_gid.
	 */
	mask = AT_ALL;
	if (vap->va_mask & (AT_UID | AT_GID)) {
		if (smi->smi_flags & SMI_ACL)
			(void) smbfs_acl_getids(vp, cr);
		/* else leave as set in make_smbnode */
	} else {
		mask &= ~(AT_UID | AT_GID);
	}

	/*
	 * If we've got cached attributes, just use them;
	 * otherwise go to the server to get attributes,
	 * which will update the cache in the process.
	 */
	error = smbfs_getattr_cache(vp, &fa);
	if (error)
		error = smbfs_getattr_otw(vp, &fa, cr);
	if (error)
		return (error);
	vap->va_mask |= mask;

	/*
	 * Re. client's view of the file size, see:
	 * smbfs_attrcache_fa, smbfs_getattr_otw
	 */
	smbfattr_to_vattr(vp, &fa, vap);
	if (vap->va_mask & AT_XVATTR)
		smbfattr_to_xvattr(&fa, vap);

	return (0);
}


/*
 * Convert SMB over the wire attributes to vnode form.
 * Returns 0 for success, error if failed (overflow, etc).
 * From NFS: nattr_to_vattr()
 */
void
smbfattr_to_vattr(vnode_t *vp, struct smbfattr *fa, struct vattr *vap)
{
	struct smbnode *np = VTOSMB(vp);

	/*
	 * Take type, mode, uid, gid from the smbfs node,
	 * which has have been updated by _getattr_otw.
	 */
	vap->va_type = vp->v_type;
	vap->va_mode = np->n_mode;

	vap->va_uid = np->n_uid;
	vap->va_gid = np->n_gid;

	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_nodeid = np->n_ino;
	vap->va_nlink = 1;

	/*
	 * Difference from NFS here:  We cache attributes as
	 * reported by the server, so r_attr.fa_size is the
	 * server's idea of the file size.  This is called
	 * for getattr, so we want to return the client's
	 * idea of the file size.  NFS deals with that in
	 * nfsgetattr(), the equivalent of our caller.
	 */
	vap->va_size = np->r_size;

	/*
	 * Times.  Note, already converted from NT to
	 * Unix form (in the unmarshalling code).
	 */
	vap->va_atime = fa->fa_atime;
	vap->va_mtime = fa->fa_mtime;
	vap->va_ctime = fa->fa_ctime;

	/*
	 * rdev, blksize, seq are made up.
	 * va_nblocks is 512 byte blocks.
	 */
	vap->va_rdev = vp->v_rdev;
	vap->va_blksize = MAXBSIZE;
	vap->va_nblocks = (fsblkcnt64_t)btod(np->r_attr.fa_allocsz);
	vap->va_seq = 0;
}

/*
 * smbfattr_to_xvattr: like smbfattr_to_vattr but for
 * Extensible system attributes (PSARC 2007/315)
 */
static void
smbfattr_to_xvattr(struct smbfattr *fa, struct vattr *vap)
{
	xvattr_t *xvap = (xvattr_t *)vap;	/* *vap may be xvattr_t */
	xoptattr_t *xoap = NULL;

	if ((xoap = xva_getxoptattr(xvap)) == NULL)
		return;

	if (XVA_ISSET_REQ(xvap, XAT_CREATETIME)) {
		xoap->xoa_createtime = fa->fa_createtime;
		XVA_SET_RTN(xvap, XAT_CREATETIME);
	}

	if (XVA_ISSET_REQ(xvap, XAT_ARCHIVE)) {
		xoap->xoa_archive =
		    ((fa->fa_attr & SMB_FA_ARCHIVE) != 0);
		XVA_SET_RTN(xvap, XAT_ARCHIVE);
	}

	if (XVA_ISSET_REQ(xvap, XAT_SYSTEM)) {
		xoap->xoa_system =
		    ((fa->fa_attr & SMB_FA_SYSTEM) != 0);
		XVA_SET_RTN(xvap, XAT_SYSTEM);
	}

	if (XVA_ISSET_REQ(xvap, XAT_READONLY)) {
		xoap->xoa_readonly =
		    ((fa->fa_attr & SMB_FA_RDONLY) != 0);
		XVA_SET_RTN(xvap, XAT_READONLY);
	}

	if (XVA_ISSET_REQ(xvap, XAT_HIDDEN)) {
		xoap->xoa_hidden =
		    ((fa->fa_attr & SMB_FA_HIDDEN) != 0);
		XVA_SET_RTN(xvap, XAT_HIDDEN);
	}
}

/*
 * Here NFS has:
 *	nfs_async_... stuff
 * which we're not using (no async I/O), and:
 *	writerp(),
 *	nfs_putpages()
 *	nfs_invalidate_pages()
 * which we have in smbfs_vnops.c, and
 *	nfs_printfhandle()
 *	nfs_write_error()
 * not needed here.
 */

/*
 * Helper function for smbfs_sync
 *
 * Walk the per-zone list of smbfs mounts, calling smbfs_rflush
 * on each one.  This is a little tricky because we need to exit
 * the list mutex before each _rflush call and then try to resume
 * where we were in the list after re-entering the mutex.
 */
void
smbfs_flushall(cred_t *cr)
{
	smi_globals_t *smg;
	smbmntinfo_t *tmp_smi, *cur_smi, *next_smi;

	smg = zone_getspecific(smi_list_key, crgetzone(cr));
	ASSERT(smg != NULL);

	mutex_enter(&smg->smg_lock);
	cur_smi = list_head(&smg->smg_list);
	if (cur_smi == NULL) {
		mutex_exit(&smg->smg_lock);
		return;
	}
	VFS_HOLD(cur_smi->smi_vfsp);
	mutex_exit(&smg->smg_lock);

flush:
	smbfs_rflush(cur_smi->smi_vfsp, cr);

	mutex_enter(&smg->smg_lock);
	/*
	 * Resume after cur_smi if that's still on the list,
	 * otherwise restart at the head.
	 */
	for (tmp_smi = list_head(&smg->smg_list);
	    tmp_smi != NULL;
	    tmp_smi = list_next(&smg->smg_list, tmp_smi))
		if (tmp_smi == cur_smi)
			break;
	if (tmp_smi != NULL)
		next_smi = list_next(&smg->smg_list, tmp_smi);
	else
		next_smi = list_head(&smg->smg_list);

	if (next_smi != NULL)
		VFS_HOLD(next_smi->smi_vfsp);
	VFS_RELE(cur_smi->smi_vfsp);

	mutex_exit(&smg->smg_lock);

	if (next_smi != NULL) {
		cur_smi = next_smi;
		goto flush;
	}
}

/*
 * SMB Client initialization and cleanup.
 * Much of it is per-zone now.
 */


/* ARGSUSED */
static void *
smbfs_zone_init(zoneid_t zoneid)
{
	smi_globals_t *smg;

	smg = kmem_alloc(sizeof (*smg), KM_SLEEP);
	mutex_init(&smg->smg_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&smg->smg_list, sizeof (smbmntinfo_t),
	    offsetof(smbmntinfo_t, smi_zone_node));
	smg->smg_destructor_called = B_FALSE;
	return (smg);
}

/*
 * Callback routine to tell all SMBFS mounts in the zone to stop creating new
 * threads.  Existing threads should exit.
 */
/* ARGSUSED */
static void
smbfs_zone_shutdown(zoneid_t zoneid, void *data)
{
	smi_globals_t *smg = data;
	smbmntinfo_t *smi;

	ASSERT(smg != NULL);
again:
	mutex_enter(&smg->smg_lock);
	for (smi = list_head(&smg->smg_list); smi != NULL;
	    smi = list_next(&smg->smg_list, smi)) {

		/*
		 * If we've done the shutdown work for this FS, skip.
		 * Once we go off the end of the list, we're done.
		 */
		if (smi->smi_flags & SMI_DEAD)
			continue;

		/*
		 * We will do work, so not done.  Get a hold on the FS.
		 */
		VFS_HOLD(smi->smi_vfsp);

		mutex_enter(&smi->smi_lock);
		smi->smi_flags |= SMI_DEAD;
		mutex_exit(&smi->smi_lock);

		/*
		 * Drop lock and release FS, which may change list, then repeat.
		 * We're done when every mi has been done or the list is empty.
		 */
		mutex_exit(&smg->smg_lock);
		VFS_RELE(smi->smi_vfsp);
		goto again;
	}
	mutex_exit(&smg->smg_lock);
}

static void
smbfs_zone_free_globals(smi_globals_t *smg)
{
	list_destroy(&smg->smg_list);	/* makes sure the list is empty */
	mutex_destroy(&smg->smg_lock);
	kmem_free(smg, sizeof (*smg));

}

/* ARGSUSED */
static void
smbfs_zone_destroy(zoneid_t zoneid, void *data)
{
	smi_globals_t *smg = data;

	ASSERT(smg != NULL);
	mutex_enter(&smg->smg_lock);
	if (list_head(&smg->smg_list) != NULL) {
		/* Still waiting for VFS_FREEVFS() */
		smg->smg_destructor_called = B_TRUE;
		mutex_exit(&smg->smg_lock);
		return;
	}
	smbfs_zone_free_globals(smg);
}

/*
 * Add an SMBFS mount to the per-zone list of SMBFS mounts.
 */
void
smbfs_zonelist_add(smbmntinfo_t *smi)
{
	smi_globals_t *smg;

	smg = zone_getspecific(smi_list_key, smi->smi_zone_ref.zref_zone);
	mutex_enter(&smg->smg_lock);
	list_insert_head(&smg->smg_list, smi);
	mutex_exit(&smg->smg_lock);
}

/*
 * Remove an SMBFS mount from the per-zone list of SMBFS mounts.
 */
void
smbfs_zonelist_remove(smbmntinfo_t *smi)
{
	smi_globals_t *smg;

	smg = zone_getspecific(smi_list_key, smi->smi_zone_ref.zref_zone);
	mutex_enter(&smg->smg_lock);
	list_remove(&smg->smg_list, smi);
	/*
	 * We can be called asynchronously by VFS_FREEVFS() after the zone
	 * shutdown/destroy callbacks have executed; if so, clean up the zone's
	 * smi_globals.
	 */
	if (list_head(&smg->smg_list) == NULL &&
	    smg->smg_destructor_called == B_TRUE) {
		smbfs_zone_free_globals(smg);
		return;
	}
	mutex_exit(&smg->smg_lock);
}

#ifdef	lint
#define	NEED_SMBFS_CALLBACKS	1
#endif

#ifdef NEED_SMBFS_CALLBACKS
/*
 * Call-back hooks for netsmb, in case we want them.
 * Apple's VFS wants them.  We may not need them.
 */
/*ARGSUSED*/
static void smbfs_dead(smb_share_t *ssp)
{
	/*
	 * Walk the mount list, finding all mounts
	 * using this share...
	 */
}

/*ARGSUSED*/
static void smbfs_cb_nop(smb_share_t *ss)
{
	/* no-op */
}

smb_fscb_t smbfs_cb = {
	.fscb_disconn	= smbfs_dead,
	.fscb_connect	= smbfs_cb_nop,
	.fscb_down	= smbfs_cb_nop,
	.fscb_up	= smbfs_cb_nop };

#endif /* NEED_SMBFS_CALLBACKS */

/*
 * SMBFS Client initialization routine.  This routine should only be called
 * once.  It performs the following tasks:
 *      - Initalize all global locks
 *      - Call sub-initialization routines (localize access to variables)
 */
int
smbfs_clntinit(void)
{

	zone_key_create(&smi_list_key, smbfs_zone_init, smbfs_zone_shutdown,
	    smbfs_zone_destroy);
#ifdef NEED_SMBFS_CALLBACKS
	(void) smb_fscb_set(&smbfs_cb);
#endif /* NEED_SMBFS_CALLBACKS */
	return (0);
}

/*
 * This routine is called when the modunload is called. This will cleanup
 * the previously allocated/initialized nodes.
 */
void
smbfs_clntfini(void)
{
#ifdef NEED_SMBFS_CALLBACKS
	(void) smb_fscb_set(NULL);
#endif /* NEED_SMBFS_CALLBACKS */
	(void) zone_key_delete(smi_list_key);
}
