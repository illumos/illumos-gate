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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *  	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All Rights Reserved
 */

/*
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/tiuser.h>
#include <sys/swap.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/session.h>
#include <sys/dnlc.h>
#include <sys/bitmap.h>
#include <sys/acl.h>
#include <sys/ddi.h>
#include <sys/pathname.h>
#include <sys/flock.h>
#include <sys/dirent.h>
#include <sys/flock.h>
#include <sys/callb.h>
#include <sys/sdt.h>

#include <vm/pvn.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/rpcsec_gss.h>
#include <rpc/clnt.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs_acl.h>

#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>

/*
 * The hash queues for the access to active and cached rnodes
 * are organized as doubly linked lists.  A reader/writer lock
 * for each hash bucket is used to control access and to synchronize
 * lookups, additions, and deletions from the hash queue.
 *
 * The rnode freelist is organized as a doubly linked list with
 * a head pointer.  Additions and deletions are synchronized via
 * a single mutex.
 *
 * In order to add an rnode to the free list, it must be hashed into
 * a hash queue and the exclusive lock to the hash queue be held.
 * If an rnode is not hashed into a hash queue, then it is destroyed
 * because it represents no valuable information that can be reused
 * about the file.  The exclusive lock to the hash queue must be
 * held in order to prevent a lookup in the hash queue from finding
 * the rnode and using it and assuming that the rnode is not on the
 * freelist.  The lookup in the hash queue will have the hash queue
 * locked, either exclusive or shared.
 *
 * The vnode reference count for each rnode is not allowed to drop
 * below 1.  This prevents external entities, such as the VM
 * subsystem, from acquiring references to vnodes already on the
 * freelist and then trying to place them back on the freelist
 * when their reference is released.  This means that the when an
 * rnode is looked up in the hash queues, then either the rnode
 * is removed from the freelist and that reference is transferred to
 * the new reference or the vnode reference count must be incremented
 * accordingly.  The mutex for the freelist must be held in order to
 * accurately test to see if the rnode is on the freelist or not.
 * The hash queue lock might be held shared and it is possible that
 * two different threads may race to remove the rnode from the
 * freelist.  This race can be resolved by holding the mutex for the
 * freelist.  Please note that the mutex for the freelist does not
 * need to be held if the rnode is not on the freelist.  It can not be
 * placed on the freelist due to the requirement that the thread
 * putting the rnode on the freelist must hold the exclusive lock
 * to the hash queue and the thread doing the lookup in the hash
 * queue is holding either a shared or exclusive lock to the hash
 * queue.
 *
 * The lock ordering is:
 *
 *	hash bucket lock -> vnode lock
 *	hash bucket lock -> freelist lock -> r_statelock
 */
r4hashq_t *rtable4;

static kmutex_t rp4freelist_lock;
static rnode4_t *rp4freelist = NULL;
static long rnode4_new = 0;
int rtable4size;
static int rtable4mask;
static struct kmem_cache *rnode4_cache;
static int rnode4_hashlen = 4;

static void	r4inactive(rnode4_t *, cred_t *);
static vnode_t	*make_rnode4(nfs4_sharedfh_t *, r4hashq_t *, struct vfs *,
		    struct vnodeops *,
		    int (*)(vnode_t *, page_t *, u_offset_t *, size_t *, int,
		    cred_t *),
		    int *, cred_t *);
static void	rp4_rmfree(rnode4_t *);
int		nfs4_free_data_reclaim(rnode4_t *);
static int	nfs4_active_data_reclaim(rnode4_t *);
static int	nfs4_free_reclaim(void);
static int	nfs4_active_reclaim(void);
static int	nfs4_rnode_reclaim(void);
static void	nfs4_reclaim(void *);
static int	isrootfh(nfs4_sharedfh_t *, rnode4_t *);
static void	uninit_rnode4(rnode4_t *);
static void	destroy_rnode4(rnode4_t *);
static void	r4_stub_set(rnode4_t *, nfs4_stub_type_t);

#ifdef DEBUG
static int r4_check_for_dups = 0; /* Flag to enable dup rnode detection. */
static int nfs4_rnode_debug = 0;
/* if nonzero, kmem_cache_free() rnodes rather than place on freelist */
static int nfs4_rnode_nofreelist = 0;
/* give messages on colliding shared filehandles */
static void	r4_dup_check(rnode4_t *, vfs_t *);
#endif

/*
 * If the vnode has pages, run the list and check for any that are
 * still dangling.  We call this routine before putting an rnode on
 * the free list.
 */
static int
nfs4_dross_pages(vnode_t *vp)
{
	page_t *pp;
	kmutex_t *vphm;

	vphm = page_vnode_mutex(vp);
	mutex_enter(vphm);
	if ((pp = vp->v_pages) != NULL) {
		do {
			if (pp->p_hash != PVN_VPLIST_HASH_TAG &&
			    pp->p_fsdata != C_NOCOMMIT) {
				mutex_exit(vphm);
				return (1);
			}
		} while ((pp = pp->p_vpnext) != vp->v_pages);
	}
	mutex_exit(vphm);

	return (0);
}

/*
 * Flush any pages left on this rnode.
 */
static void
r4flushpages(rnode4_t *rp, cred_t *cr)
{
	vnode_t *vp;
	int error;

	/*
	 * Before freeing anything, wait until all asynchronous
	 * activity is done on this rnode.  This will allow all
	 * asynchronous read ahead and write behind i/o's to
	 * finish.
	 */
	mutex_enter(&rp->r_statelock);
	while (rp->r_count > 0)
		cv_wait(&rp->r_cv, &rp->r_statelock);
	mutex_exit(&rp->r_statelock);

	/*
	 * Flush and invalidate all pages associated with the vnode.
	 */
	vp = RTOV4(rp);
	if (nfs4_has_pages(vp)) {
		ASSERT(vp->v_type != VCHR);
		if ((rp->r_flags & R4DIRTY) && !rp->r_error) {
			error = VOP_PUTPAGE(vp, (u_offset_t)0, 0, 0, cr, NULL);
			if (error && (error == ENOSPC || error == EDQUOT)) {
				mutex_enter(&rp->r_statelock);
				if (!rp->r_error)
					rp->r_error = error;
				mutex_exit(&rp->r_statelock);
			}
		}
		nfs4_invalidate_pages(vp, (u_offset_t)0, cr);
	}
}

/*
 * Free the resources associated with an rnode.
 */
static void
r4inactive(rnode4_t *rp, cred_t *cr)
{
	vnode_t *vp;
	char *contents;
	int size;
	vsecattr_t *vsp;
	vnode_t *xattr;

	r4flushpages(rp, cr);

	vp = RTOV4(rp);

	/*
	 * Free any held caches which may be
	 * associated with this rnode.
	 */
	mutex_enter(&rp->r_statelock);
	contents = rp->r_symlink.contents;
	size = rp->r_symlink.size;
	rp->r_symlink.contents = NULL;
	vsp = rp->r_secattr;
	rp->r_secattr = NULL;
	xattr = rp->r_xattr_dir;
	rp->r_xattr_dir = NULL;
	mutex_exit(&rp->r_statelock);

	/*
	 * Free the access cache entries.
	 */
	(void) nfs4_access_purge_rp(rp);

	/*
	 * Free the readdir cache entries.
	 */
	nfs4_purge_rddir_cache(vp);

	/*
	 * Free the symbolic link cache.
	 */
	if (contents != NULL) {

		kmem_free((void *)contents, size);
	}

	/*
	 * Free any cached ACL.
	 */
	if (vsp != NULL)
		nfs4_acl_free_cache(vsp);

	/*
	 * Release the cached xattr_dir
	 */
	if (xattr != NULL)
		VN_RELE(xattr);
}

/*
 * We have seen a case that the fh passed in is for "." which
 * should be a VROOT node, however, the fh is different from the
 * root fh stored in the mntinfo4_t. The invalid fh might be
 * from a misbehaved server and will panic the client system at
 * a later time. To avoid the panic, we drop the bad fh, use
 * the root fh from mntinfo4_t, and print an error message
 * for attention.
 */
nfs4_sharedfh_t *
badrootfh_check(nfs4_sharedfh_t *fh, nfs4_fname_t *nm, mntinfo4_t *mi,
    int *wasbad)
{
	char *s;

	*wasbad = 0;
	s = fn_name(nm);
	ASSERT(strcmp(s, "..") != 0);

	if ((s[0] == '.' && s[1] == '\0') && fh &&
	    !SFH4_SAME(mi->mi_rootfh, fh)) {
#ifdef DEBUG
		nfs4_fhandle_t fhandle;

		zcmn_err(mi->mi_zone->zone_id, CE_WARN,
		    "Server %s returns a different "
		    "root filehandle for the path %s:",
		    mi->mi_curr_serv->sv_hostname,
		    mi->mi_curr_serv->sv_path);

		/* print the bad fh */
		fhandle.fh_len = fh->sfh_fh.nfs_fh4_len;
		bcopy(fh->sfh_fh.nfs_fh4_val, fhandle.fh_buf,
		    fhandle.fh_len);
		nfs4_printfhandle(&fhandle);

		/* print mi_rootfh */
		fhandle.fh_len = mi->mi_rootfh->sfh_fh.nfs_fh4_len;
		bcopy(mi->mi_rootfh->sfh_fh.nfs_fh4_val, fhandle.fh_buf,
		    fhandle.fh_len);
		nfs4_printfhandle(&fhandle);
#endif
		/* use mi_rootfh instead; fh will be rele by the caller */
		fh = mi->mi_rootfh;
		*wasbad = 1;
	}

	kmem_free(s, MAXNAMELEN);
	return (fh);
}

void
r4_do_attrcache(vnode_t *vp, nfs4_ga_res_t *garp, int newnode,
    hrtime_t t, cred_t *cr, int index)
{
	int is_stub;
	vattr_t *attr;
	/*
	 * Don't add to attrcache if time overflow, but
	 * no need to check because either attr is null or the time
	 * values in it were processed by nfs4_time_ntov(), which checks
	 * for time overflows.
	 */
	attr = garp ? &garp->n4g_va : NULL;

	if (attr) {
		if (!newnode) {
			rw_exit(&rtable4[index].r_lock);
#ifdef DEBUG
			if (vp->v_type != attr->va_type &&
			    vp->v_type != VNON && attr->va_type != VNON) {
				zcmn_err(VTOMI4(vp)->mi_zone->zone_id, CE_WARN,
				    "makenfs4node: type (%d) doesn't "
				    "match type of found node at %p (%d)",
				    attr->va_type, (void *)vp, vp->v_type);
			}
#endif
			nfs4_attr_cache(vp, garp, t, cr, TRUE, NULL);
		} else {
			rnode4_t *rp = VTOR4(vp);

			vp->v_type = attr->va_type;
			vp->v_rdev = attr->va_rdev;

			/*
			 * Turn this object into a "stub" object if we
			 * crossed an underlying server fs boundary.
			 * To make this check, during mount we save the
			 * fsid of the server object being mounted.
			 * Here we compare this object's server fsid
			 * with the fsid we saved at mount.  If they
			 * are different, we crossed server fs boundary.
			 *
			 * The stub type is set (or not) at rnode
			 * creation time and it never changes for life
			 * of the rnode.
			 *
			 * This stub will be for a mirror-mount, rather than
			 * a referral (the latter also sets R4SRVSTUB).
			 *
			 * The stub type is also set during RO failover,
			 * nfs4_remap_file().
			 *
			 * We don't bother with taking r_state_lock to
			 * set the stub type because this is a new rnode
			 * and we're holding the hash bucket r_lock RW_WRITER.
			 * No other thread could have obtained access
			 * to this rnode.
			 */
			is_stub = 0;
			if (garp->n4g_fsid_valid) {
				fattr4_fsid ga_fsid = garp->n4g_fsid;
				servinfo4_t *svp = rp->r_server;

				rp->r_srv_fsid = ga_fsid;

				(void) nfs_rw_enter_sig(&svp->sv_lock,
				    RW_READER, 0);
				if (!FATTR4_FSID_EQ(&ga_fsid, &svp->sv_fsid))
					is_stub = 1;
				nfs_rw_exit(&svp->sv_lock);
			}

			if (is_stub)
				r4_stub_mirrormount(rp);
			else
				r4_stub_none(rp);

			/* Can not cache partial attr */
			if (attr->va_mask == AT_ALL)
				nfs4_attrcache_noinval(vp, garp, t);
			else
				PURGE_ATTRCACHE4(vp);

			rw_exit(&rtable4[index].r_lock);
		}
	} else {
		if (newnode) {
			PURGE_ATTRCACHE4(vp);
		}
		rw_exit(&rtable4[index].r_lock);
	}
}

/*
 * Find or create an rnode based primarily on filehandle.  To be
 * used when dvp (vnode for parent directory) is not available;
 * otherwise, makenfs4node() should be used.
 *
 * The nfs4_fname_t argument *npp is consumed and nulled out.
 */

vnode_t *
makenfs4node_by_fh(nfs4_sharedfh_t *sfh, nfs4_sharedfh_t *psfh,
    nfs4_fname_t **npp, nfs4_ga_res_t *garp,
    mntinfo4_t *mi, cred_t *cr, hrtime_t t)
{
	vfs_t *vfsp = mi->mi_vfsp;
	int newnode = 0;
	vnode_t *vp;
	rnode4_t *rp;
	svnode_t *svp;
	nfs4_fname_t *name, *svpname;
	int index;

	ASSERT(npp && *npp);
	name = *npp;
	*npp = NULL;

	index = rtable4hash(sfh);
	rw_enter(&rtable4[index].r_lock, RW_READER);

	vp = make_rnode4(sfh, &rtable4[index], vfsp,
	    nfs4_vnodeops, nfs4_putapage, &newnode, cr);

	svp = VTOSV(vp);
	rp = VTOR4(vp);
	if (newnode) {
		svp->sv_forw = svp->sv_back = svp;
		svp->sv_name = name;
		if (psfh != NULL)
			sfh4_hold(psfh);
		svp->sv_dfh = psfh;
	} else {
		/*
		 * It is possible that due to a server
		 * side rename fnames have changed.
		 * update the fname here.
		 */
		mutex_enter(&rp->r_svlock);
		svpname = svp->sv_name;
		if (svp->sv_name != name) {
			svp->sv_name = name;
			mutex_exit(&rp->r_svlock);
			fn_rele(&svpname);
		} else {
			mutex_exit(&rp->r_svlock);
			fn_rele(&name);
		}
	}

	ASSERT(RW_LOCK_HELD(&rtable4[index].r_lock));
	r4_do_attrcache(vp, garp, newnode, t, cr, index);
	ASSERT(rw_owner(&rtable4[index].r_lock) != curthread);

	return (vp);
}

/*
 * Find or create a vnode for the given filehandle, filesystem, parent, and
 * name.  The reference to nm is consumed, so the caller must first do an
 * fn_hold() if it wants to continue using nm after this call.
 */
vnode_t *
makenfs4node(nfs4_sharedfh_t *fh, nfs4_ga_res_t *garp, struct vfs *vfsp,
    hrtime_t t, cred_t *cr, vnode_t *dvp, nfs4_fname_t *nm)
{
	vnode_t *vp;
	int newnode;
	int index;
	mntinfo4_t *mi = VFTOMI4(vfsp);
	int had_badfh = 0;
	rnode4_t *rp;

	ASSERT(dvp != NULL);

	fh = badrootfh_check(fh, nm, mi, &had_badfh);

	index = rtable4hash(fh);
	rw_enter(&rtable4[index].r_lock, RW_READER);

	/*
	 * Note: make_rnode4() may upgrade the hash bucket lock to exclusive.
	 */
	vp = make_rnode4(fh, &rtable4[index], vfsp, nfs4_vnodeops,
	    nfs4_putapage, &newnode, cr);

	rp = VTOR4(vp);
	sv_activate(&vp, dvp, &nm, newnode);
	if (dvp->v_flag & V_XATTRDIR) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags |= R4ISXATTR;
		mutex_exit(&rp->r_statelock);
	}

	/* if getting a bad file handle, do not cache the attributes. */
	if (had_badfh) {
		rw_exit(&rtable4[index].r_lock);
		return (vp);
	}

	ASSERT(RW_LOCK_HELD(&rtable4[index].r_lock));
	r4_do_attrcache(vp, garp, newnode, t, cr, index);
	ASSERT(rw_owner(&rtable4[index].r_lock) != curthread);

	return (vp);
}

/*
 * Hash on address of filehandle object.
 * XXX totally untuned.
 */

int
rtable4hash(nfs4_sharedfh_t *fh)
{
	return (((uintptr_t)fh / sizeof (*fh)) & rtable4mask);
}

/*
 * Find or create the vnode for the given filehandle and filesystem.
 * *newnode is set to zero if the vnode already existed; non-zero if it had
 * to be created.
 *
 * Note: make_rnode4() may upgrade the hash bucket lock to exclusive.
 */

static vnode_t *
make_rnode4(nfs4_sharedfh_t *fh, r4hashq_t *rhtp, struct vfs *vfsp,
    struct vnodeops *vops,
    int (*putapage)(vnode_t *, page_t *, u_offset_t *, size_t *, int, cred_t *),
    int *newnode, cred_t *cr)
{
	rnode4_t *rp;
	rnode4_t *trp;
	vnode_t *vp;
	mntinfo4_t *mi;

	ASSERT(RW_READ_HELD(&rhtp->r_lock));

	mi = VFTOMI4(vfsp);

start:
	if ((rp = r4find(rhtp, fh, vfsp)) != NULL) {
		vp = RTOV4(rp);
		*newnode = 0;
		return (vp);
	}
	rw_exit(&rhtp->r_lock);

	mutex_enter(&rp4freelist_lock);

	if (rp4freelist != NULL && rnode4_new >= nrnode) {
		rp = rp4freelist;
		rp4_rmfree(rp);
		mutex_exit(&rp4freelist_lock);

		vp = RTOV4(rp);

		if (rp->r_flags & R4HASHED) {
			rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				VN_RELE_LOCKED(vp);
				mutex_exit(&vp->v_lock);
				rw_exit(&rp->r_hashq->r_lock);
				rw_enter(&rhtp->r_lock, RW_READER);
				goto start;
			}
			mutex_exit(&vp->v_lock);
			rp4_rmhash_locked(rp);
			rw_exit(&rp->r_hashq->r_lock);
		}

		r4inactive(rp, cr);

		mutex_enter(&vp->v_lock);
		if (vp->v_count > 1) {
			VN_RELE_LOCKED(vp);
			mutex_exit(&vp->v_lock);
			rw_enter(&rhtp->r_lock, RW_READER);
			goto start;
		}
		mutex_exit(&vp->v_lock);
		vn_invalid(vp);

		/*
		 * destroy old locks before bzero'ing and
		 * recreating the locks below.
		 */
		uninit_rnode4(rp);

		/*
		 * Make sure that if rnode is recycled then
		 * VFS count is decremented properly before
		 * reuse.
		 */
		VFS_RELE(vp->v_vfsp);
		vn_reinit(vp);
	} else {
		vnode_t *new_vp;

		mutex_exit(&rp4freelist_lock);

		rp = kmem_cache_alloc(rnode4_cache, KM_SLEEP);
		new_vp = vn_alloc(KM_SLEEP);

		atomic_inc_ulong((ulong_t *)&rnode4_new);
#ifdef DEBUG
		clstat4_debug.nrnode.value.ui64++;
#endif
		vp = new_vp;
	}

	bzero(rp, sizeof (*rp));
	rp->r_vnode = vp;
	nfs_rw_init(&rp->r_rwlock, NULL, RW_DEFAULT, NULL);
	nfs_rw_init(&rp->r_lkserlock, NULL, RW_DEFAULT, NULL);
	mutex_init(&rp->r_svlock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&rp->r_statelock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&rp->r_statev4_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&rp->r_os_lock, NULL, MUTEX_DEFAULT, NULL);
	rp->created_v4 = 0;
	list_create(&rp->r_open_streams, sizeof (nfs4_open_stream_t),
	    offsetof(nfs4_open_stream_t, os_node));
	rp->r_lo_head.lo_prev_rnode = &rp->r_lo_head;
	rp->r_lo_head.lo_next_rnode = &rp->r_lo_head;
	cv_init(&rp->r_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&rp->r_commit.c_cv, NULL, CV_DEFAULT, NULL);
	rp->r_flags = R4READDIRWATTR;
	rp->r_fh = fh;
	rp->r_hashq = rhtp;
	sfh4_hold(rp->r_fh);
	rp->r_server = mi->mi_curr_serv;
	rp->r_deleg_type = OPEN_DELEGATE_NONE;
	rp->r_deleg_needs_recovery = OPEN_DELEGATE_NONE;
	nfs_rw_init(&rp->r_deleg_recall_lock, NULL, RW_DEFAULT, NULL);

	rddir4_cache_create(rp);
	rp->r_putapage = putapage;
	vn_setops(vp, vops);
	vp->v_data = (caddr_t)rp;
	vp->v_vfsp = vfsp;
	VFS_HOLD(vfsp);
	vp->v_type = VNON;
	vp->v_flag |= VMODSORT;
	if (isrootfh(fh, rp))
		vp->v_flag = VROOT;
	vn_exists(vp);

	/*
	 * There is a race condition if someone else
	 * alloc's the rnode while no locks are held, so we
	 * check again and recover if found.
	 */
	rw_enter(&rhtp->r_lock, RW_WRITER);
	if ((trp = r4find(rhtp, fh, vfsp)) != NULL) {
		vp = RTOV4(trp);
		*newnode = 0;
		rw_exit(&rhtp->r_lock);
		rp4_addfree(rp, cr);
		rw_enter(&rhtp->r_lock, RW_READER);
		return (vp);
	}
	rp4_addhash(rp);
	*newnode = 1;
	return (vp);
}

static void
uninit_rnode4(rnode4_t *rp)
{
	vnode_t *vp = RTOV4(rp);

	ASSERT(rp != NULL);
	ASSERT(vp != NULL);
	ASSERT(vp->v_count == 1);
	ASSERT(rp->r_count == 0);
	ASSERT(rp->r_mapcnt == 0);
	if (rp->r_flags & R4LODANGLERS) {
		nfs4_flush_lock_owners(rp);
	}
	ASSERT(rp->r_lo_head.lo_next_rnode == &rp->r_lo_head);
	ASSERT(rp->r_lo_head.lo_prev_rnode == &rp->r_lo_head);
	ASSERT(!(rp->r_flags & R4HASHED));
	ASSERT(rp->r_freef == NULL && rp->r_freeb == NULL);
	nfs4_clear_open_streams(rp);
	list_destroy(&rp->r_open_streams);

	/*
	 * Destroy the rddir cache first since we need to grab the r_statelock.
	 */
	mutex_enter(&rp->r_statelock);
	rddir4_cache_destroy(rp);
	mutex_exit(&rp->r_statelock);
	sv_uninit(&rp->r_svnode);
	sfh4_rele(&rp->r_fh);
	nfs_rw_destroy(&rp->r_rwlock);
	nfs_rw_destroy(&rp->r_lkserlock);
	mutex_destroy(&rp->r_statelock);
	mutex_destroy(&rp->r_statev4_lock);
	mutex_destroy(&rp->r_os_lock);
	cv_destroy(&rp->r_cv);
	cv_destroy(&rp->r_commit.c_cv);
	nfs_rw_destroy(&rp->r_deleg_recall_lock);
	if (rp->r_flags & R4DELMAPLIST)
		list_destroy(&rp->r_indelmap);
}

/*
 * Put an rnode on the free list.
 *
 * Rnodes which were allocated above and beyond the normal limit
 * are immediately freed.
 */
void
rp4_addfree(rnode4_t *rp, cred_t *cr)
{
	vnode_t *vp;
	vnode_t *xattr;
	struct vfs *vfsp;

	vp = RTOV4(rp);
	ASSERT(vp->v_count >= 1);
	ASSERT(rp->r_freef == NULL && rp->r_freeb == NULL);

	/*
	 * If we have too many rnodes allocated and there are no
	 * references to this rnode, or if the rnode is no longer
	 * accessible by it does not reside in the hash queues,
	 * or if an i/o error occurred while writing to the file,
	 * then just free it instead of putting it on the rnode
	 * freelist.
	 */
	vfsp = vp->v_vfsp;
	if (((rnode4_new > nrnode || !(rp->r_flags & R4HASHED) ||
#ifdef DEBUG
	    (nfs4_rnode_nofreelist != 0) ||
#endif
	    rp->r_error || (rp->r_flags & R4RECOVERR) ||
	    (vfsp->vfs_flag & VFS_UNMOUNTED)) && rp->r_count == 0)) {
		if (rp->r_flags & R4HASHED) {
			rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				VN_RELE_LOCKED(vp);
				mutex_exit(&vp->v_lock);
				rw_exit(&rp->r_hashq->r_lock);
				return;
			}
			mutex_exit(&vp->v_lock);
			rp4_rmhash_locked(rp);
			rw_exit(&rp->r_hashq->r_lock);
		}

		/*
		 * Make sure we don't have a delegation on this rnode
		 * before destroying it.
		 */
		if (rp->r_deleg_type != OPEN_DELEGATE_NONE) {
			(void) nfs4delegreturn(rp,
			    NFS4_DR_FORCE|NFS4_DR_PUSH|NFS4_DR_REOPEN);
		}

		r4inactive(rp, cr);

		/*
		 * Recheck the vnode reference count.  We need to
		 * make sure that another reference has not been
		 * acquired while we were not holding v_lock.  The
		 * rnode is not in the rnode hash queues; one
		 * way for a reference to have been acquired
		 * is for a VOP_PUTPAGE because the rnode was marked
		 * with R4DIRTY or for a modified page.  This
		 * reference may have been acquired before our call
		 * to r4inactive.  The i/o may have been completed,
		 * thus allowing r4inactive to complete, but the
		 * reference to the vnode may not have been released
		 * yet.  In any case, the rnode can not be destroyed
		 * until the other references to this vnode have been
		 * released.  The other references will take care of
		 * either destroying the rnode or placing it on the
		 * rnode freelist.  If there are no other references,
		 * then the rnode may be safely destroyed.
		 */
		mutex_enter(&vp->v_lock);
		if (vp->v_count > 1) {
			VN_RELE_LOCKED(vp);
			mutex_exit(&vp->v_lock);
			return;
		}
		mutex_exit(&vp->v_lock);

		destroy_rnode4(rp);
		return;
	}

	/*
	 * Lock the hash queue and then recheck the reference count
	 * to ensure that no other threads have acquired a reference
	 * to indicate that the rnode should not be placed on the
	 * freelist.  If another reference has been acquired, then
	 * just release this one and let the other thread complete
	 * the processing of adding this rnode to the freelist.
	 */
again:
	rw_enter(&rp->r_hashq->r_lock, RW_WRITER);

	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1) {
		VN_RELE_LOCKED(vp);
		mutex_exit(&vp->v_lock);
		rw_exit(&rp->r_hashq->r_lock);
		return;
	}
	mutex_exit(&vp->v_lock);

	/*
	 * Make sure we don't put an rnode with a delegation
	 * on the free list.
	 */
	if (rp->r_deleg_type != OPEN_DELEGATE_NONE) {
		rw_exit(&rp->r_hashq->r_lock);
		(void) nfs4delegreturn(rp,
		    NFS4_DR_FORCE|NFS4_DR_PUSH|NFS4_DR_REOPEN);
		goto again;
	}

	/*
	 * Now that we have the hash queue lock, and we know there
	 * are not anymore references on the vnode, check to make
	 * sure there aren't any open streams still on the rnode.
	 * If so, drop the hash queue lock, remove the open streams,
	 * and recheck the v_count.
	 */
	mutex_enter(&rp->r_os_lock);
	if (list_head(&rp->r_open_streams) != NULL) {
		mutex_exit(&rp->r_os_lock);
		rw_exit(&rp->r_hashq->r_lock);
		if (nfs_zone() != VTOMI4(vp)->mi_zone)
			nfs4_clear_open_streams(rp);
		else
			(void) nfs4close_all(vp, cr);
		goto again;
	}
	mutex_exit(&rp->r_os_lock);

	/*
	 * Before we put it on the freelist, make sure there are no pages.
	 * If there are, flush and commit of all of the dirty and
	 * uncommitted pages, assuming the file system isn't read only.
	 */
	if (!(vp->v_vfsp->vfs_flag & VFS_RDONLY) && nfs4_dross_pages(vp)) {
		rw_exit(&rp->r_hashq->r_lock);
		r4flushpages(rp, cr);
		goto again;
	}

	/*
	 * Before we put it on the freelist, make sure there is no
	 * active xattr directory cached, the freelist will not
	 * have its entries r4inactive'd if there is still an active
	 * rnode, thus nothing in the freelist can hold another
	 * rnode active.
	 */
	xattr = rp->r_xattr_dir;
	rp->r_xattr_dir = NULL;

	/*
	 * If there is no cached data or metadata for this file, then
	 * put the rnode on the front of the freelist so that it will
	 * be reused before other rnodes which may have cached data or
	 * metadata associated with them.
	 */
	mutex_enter(&rp4freelist_lock);
	if (rp4freelist == NULL) {
		rp->r_freef = rp;
		rp->r_freeb = rp;
		rp4freelist = rp;
	} else {
		rp->r_freef = rp4freelist;
		rp->r_freeb = rp4freelist->r_freeb;
		rp4freelist->r_freeb->r_freef = rp;
		rp4freelist->r_freeb = rp;
		if (!nfs4_has_pages(vp) && rp->r_dir == NULL &&
		    rp->r_symlink.contents == NULL && rp->r_secattr == NULL)
			rp4freelist = rp;
	}
	mutex_exit(&rp4freelist_lock);

	rw_exit(&rp->r_hashq->r_lock);

	if (xattr)
		VN_RELE(xattr);
}

/*
 * Remove an rnode from the free list.
 *
 * The caller must be holding rp4freelist_lock and the rnode
 * must be on the freelist.
 */
static void
rp4_rmfree(rnode4_t *rp)
{

	ASSERT(MUTEX_HELD(&rp4freelist_lock));
	ASSERT(rp->r_freef != NULL && rp->r_freeb != NULL);

	if (rp == rp4freelist) {
		rp4freelist = rp->r_freef;
		if (rp == rp4freelist)
			rp4freelist = NULL;
	}
	rp->r_freeb->r_freef = rp->r_freef;
	rp->r_freef->r_freeb = rp->r_freeb;

	rp->r_freef = rp->r_freeb = NULL;
}

/*
 * Put a rnode in the hash table.
 *
 * The caller must be holding the exclusive hash queue lock
 */
void
rp4_addhash(rnode4_t *rp)
{
	mntinfo4_t *mi;

	ASSERT(RW_WRITE_HELD(&rp->r_hashq->r_lock));
	ASSERT(!(rp->r_flags & R4HASHED));

#ifdef DEBUG
	r4_dup_check(rp, RTOV4(rp)->v_vfsp);
#endif

	rp->r_hashf = rp->r_hashq->r_hashf;
	rp->r_hashq->r_hashf = rp;
	rp->r_hashb = (rnode4_t *)rp->r_hashq;
	rp->r_hashf->r_hashb = rp;

	mutex_enter(&rp->r_statelock);
	rp->r_flags |= R4HASHED;
	mutex_exit(&rp->r_statelock);

	mi = VTOMI4(RTOV4(rp));
	mutex_enter(&mi->mi_rnodes_lock);
	list_insert_tail(&mi->mi_rnodes, rp);
	mutex_exit(&mi->mi_rnodes_lock);
}

/*
 * Remove a rnode from the hash table.
 *
 * The caller must be holding the hash queue lock.
 */
void
rp4_rmhash_locked(rnode4_t *rp)
{
	mntinfo4_t *mi;

	ASSERT(RW_WRITE_HELD(&rp->r_hashq->r_lock));
	ASSERT(rp->r_flags & R4HASHED);

	rp->r_hashb->r_hashf = rp->r_hashf;
	rp->r_hashf->r_hashb = rp->r_hashb;

	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~R4HASHED;
	mutex_exit(&rp->r_statelock);

	mi = VTOMI4(RTOV4(rp));
	mutex_enter(&mi->mi_rnodes_lock);
	if (list_link_active(&rp->r_mi_link))
		list_remove(&mi->mi_rnodes, rp);
	mutex_exit(&mi->mi_rnodes_lock);
}

/*
 * Remove a rnode from the hash table.
 *
 * The caller must not be holding the hash queue lock.
 */
void
rp4_rmhash(rnode4_t *rp)
{
	rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
	rp4_rmhash_locked(rp);
	rw_exit(&rp->r_hashq->r_lock);
}

/*
 * Lookup a rnode by fhandle.  Ignores rnodes that had failed recovery.
 * Returns NULL if no match.  If an rnode is returned, the reference count
 * on the master vnode is incremented.
 *
 * The caller must be holding the hash queue lock, either shared or exclusive.
 */
rnode4_t *
r4find(r4hashq_t *rhtp, nfs4_sharedfh_t *fh, struct vfs *vfsp)
{
	rnode4_t *rp;
	vnode_t *vp;

	ASSERT(RW_LOCK_HELD(&rhtp->r_lock));

	for (rp = rhtp->r_hashf; rp != (rnode4_t *)rhtp; rp = rp->r_hashf) {
		vp = RTOV4(rp);
		if (vp->v_vfsp == vfsp && SFH4_SAME(rp->r_fh, fh)) {

			mutex_enter(&rp->r_statelock);
			if (rp->r_flags & R4RECOVERR) {
				mutex_exit(&rp->r_statelock);
				continue;
			}
			mutex_exit(&rp->r_statelock);
#ifdef DEBUG
			r4_dup_check(rp, vfsp);
#endif
			if (rp->r_freef != NULL) {
				mutex_enter(&rp4freelist_lock);
				/*
				 * If the rnode is on the freelist,
				 * then remove it and use that reference
				 * as the new reference.  Otherwise,
				 * need to increment the reference count.
				 */
				if (rp->r_freef != NULL) {
					rp4_rmfree(rp);
					mutex_exit(&rp4freelist_lock);
				} else {
					mutex_exit(&rp4freelist_lock);
					VN_HOLD(vp);
				}
			} else
				VN_HOLD(vp);

			/*
			 * if root vnode, set v_flag to indicate that
			 */
			if (isrootfh(fh, rp)) {
				if (!(vp->v_flag & VROOT)) {
					mutex_enter(&vp->v_lock);
					vp->v_flag |= VROOT;
					mutex_exit(&vp->v_lock);
				}
			}
			return (rp);
		}
	}
	return (NULL);
}

/*
 * Lookup an rnode by fhandle. Just a wrapper for r4find()
 * that assumes the caller hasn't already got the lock
 * on the hash bucket.
 */
rnode4_t *
r4find_unlocked(nfs4_sharedfh_t *fh, struct vfs *vfsp)
{
	rnode4_t *rp;
	int index;

	index = rtable4hash(fh);
	rw_enter(&rtable4[index].r_lock, RW_READER);
	rp = r4find(&rtable4[index], fh, vfsp);
	rw_exit(&rtable4[index].r_lock);

	return (rp);
}

/*
 * Return 1 if there is an active vnode belonging to this vfs in the
 * rtable4 cache.
 *
 * Several of these checks are done without holding the usual
 * locks.  This is safe because destroy_rtable4(), rp4_addfree(),
 * etc. will redo the necessary checks before actually destroying
 * any rnodes.
 */
int
check_rtable4(struct vfs *vfsp)
{
	rnode4_t *rp;
	vnode_t *vp;
	mntinfo4_t *mi;

	ASSERT(vfsp != NULL);
	mi = VFTOMI4(vfsp);

	mutex_enter(&mi->mi_rnodes_lock);
	for (rp = list_head(&mi->mi_rnodes); rp != NULL;
	    rp = list_next(&mi->mi_rnodes, rp)) {
		vp = RTOV4(rp);

		if (rp->r_freef == NULL ||
		    (nfs4_has_pages(vp) && (rp->r_flags & R4DIRTY)) ||
		    rp->r_count > 0) {
			mutex_exit(&mi->mi_rnodes_lock);
			return (1);
		}
	}
	mutex_exit(&mi->mi_rnodes_lock);

	return (0);
}

/*
 * Destroy inactive vnodes from the hash queues which
 * belong to this vfs. All of the vnodes should be inactive.
 * It is essential that we destroy all rnodes in case of
 * forced unmount as well as in normal unmount case.
 */

void
destroy_rtable4(struct vfs *vfsp, cred_t *cr)
{
	rnode4_t *rp;
	mntinfo4_t *mi;

	ASSERT(vfsp != NULL);

	mi = VFTOMI4(vfsp);

	mutex_enter(&rp4freelist_lock);
	mutex_enter(&mi->mi_rnodes_lock);
	while ((rp = list_remove_head(&mi->mi_rnodes)) != NULL) {
		/*
		 * If the rnode is no longer on the freelist it is not
		 * ours and it will be handled by some other thread, so
		 * skip it.
		 */
		if (rp->r_freef == NULL)
			continue;
		mutex_exit(&mi->mi_rnodes_lock);

		rp4_rmfree(rp);
		mutex_exit(&rp4freelist_lock);

		rp4_rmhash(rp);

		/*
		 * This call to rp4_addfree will end up destroying the
		 * rnode, but in a safe way with the appropriate set
		 * of checks done.
		 */
		rp4_addfree(rp, cr);

		mutex_enter(&rp4freelist_lock);
		mutex_enter(&mi->mi_rnodes_lock);
	}
	mutex_exit(&mi->mi_rnodes_lock);
	mutex_exit(&rp4freelist_lock);
}

/*
 * This routine destroys all the resources of an rnode
 * and finally the rnode itself.
 */
static void
destroy_rnode4(rnode4_t *rp)
{
	vnode_t *vp;
	vfs_t *vfsp;

	ASSERT(rp->r_deleg_type == OPEN_DELEGATE_NONE);

	vp = RTOV4(rp);
	vfsp = vp->v_vfsp;

	uninit_rnode4(rp);
	atomic_dec_ulong((ulong_t *)&rnode4_new);
#ifdef DEBUG
	clstat4_debug.nrnode.value.ui64--;
#endif
	kmem_cache_free(rnode4_cache, rp);
	vn_invalid(vp);
	vn_free(vp);
	VFS_RELE(vfsp);
}

/*
 * Invalidate the attributes on all rnodes forcing the next getattr
 * to go over the wire.  Used to flush stale uid and gid mappings.
 * Maybe done on a per vfsp, or all rnodes (vfsp == NULL)
 */
void
nfs4_rnode_invalidate(struct vfs *vfsp)
{
	int index;
	rnode4_t *rp;
	vnode_t *vp;

	/*
	 * Walk the hash queues looking for rnodes.
	 */
	for (index = 0; index < rtable4size; index++) {
		rw_enter(&rtable4[index].r_lock, RW_READER);
		for (rp = rtable4[index].r_hashf;
		    rp != (rnode4_t *)(&rtable4[index]);
		    rp = rp->r_hashf) {
			vp = RTOV4(rp);
			if (vfsp != NULL && vp->v_vfsp != vfsp)
				continue;

			if (!mutex_tryenter(&rp->r_statelock))
				continue;

			/*
			 * Expire the attributes by resetting the change
			 * and attr timeout.
			 */
			rp->r_change = 0;
			PURGE_ATTRCACHE4_LOCKED(rp);
			mutex_exit(&rp->r_statelock);
		}
		rw_exit(&rtable4[index].r_lock);
	}
}

/*
 * Flush all vnodes in this (or every) vfs.
 * Used by nfs_sync and by nfs_unmount.
 */
void
r4flush(struct vfs *vfsp, cred_t *cr)
{
	int index;
	rnode4_t *rp;
	vnode_t *vp, **vplist;
	long num, cnt;

	/*
	 * Check to see whether there is anything to do.
	 */
	num = rnode4_new;
	if (num == 0)
		return;

	/*
	 * Allocate a slot for all currently active rnodes on the
	 * supposition that they all may need flushing.
	 */
	vplist = kmem_alloc(num * sizeof (*vplist), KM_SLEEP);
	cnt = 0;

	/*
	 * If the vfs is known we can do fast path by iterating all rnodes that
	 * belongs to this vfs.  This is much faster than the traditional way
	 * of iterating rtable4 (below) in a case there is a lot of rnodes that
	 * does not belong to our vfs.
	 */
	if (vfsp != NULL) {
		mntinfo4_t *mi = VFTOMI4(vfsp);

		mutex_enter(&mi->mi_rnodes_lock);
		for (rp = list_head(&mi->mi_rnodes); rp != NULL;
		    rp = list_next(&mi->mi_rnodes, rp)) {
			vp = RTOV4(rp);
			/*
			 * Don't bother sync'ing a vp if it
			 * is part of virtual swap device or
			 * if VFS is read-only
			 */
			if (IS_SWAPVP(vp) || vn_is_readonly(vp))
				continue;
			/*
			 * If the vnode has pages and is marked as either dirty
			 * or mmap'd, hold and add this vnode to the list of
			 * vnodes to flush.
			 */
			ASSERT(vp->v_vfsp == vfsp);
			if (nfs4_has_pages(vp) &&
			    ((rp->r_flags & R4DIRTY) || rp->r_mapcnt > 0)) {
				VN_HOLD(vp);
				vplist[cnt++] = vp;
				if (cnt == num) {
					/*
					 * The vplist is full because there is
					 * too many rnodes.  We are done for
					 * now.
					 */
					break;
				}
			}
		}
		mutex_exit(&mi->mi_rnodes_lock);

		goto done;
	}

	ASSERT(vfsp == NULL);

	/*
	 * Walk the hash queues looking for rnodes with page
	 * lists associated with them.  Make a list of these
	 * files.
	 */
	for (index = 0; index < rtable4size; index++) {
		rw_enter(&rtable4[index].r_lock, RW_READER);
		for (rp = rtable4[index].r_hashf;
		    rp != (rnode4_t *)(&rtable4[index]);
		    rp = rp->r_hashf) {
			vp = RTOV4(rp);
			/*
			 * Don't bother sync'ing a vp if it
			 * is part of virtual swap device or
			 * if VFS is read-only
			 */
			if (IS_SWAPVP(vp) || vn_is_readonly(vp))
				continue;
			/*
			 * If the vnode has pages and is marked as either dirty
			 * or mmap'd, hold and add this vnode to the list of
			 * vnodes to flush.
			 */
			if (nfs4_has_pages(vp) &&
			    ((rp->r_flags & R4DIRTY) || rp->r_mapcnt > 0)) {
				VN_HOLD(vp);
				vplist[cnt++] = vp;
				if (cnt == num) {
					rw_exit(&rtable4[index].r_lock);
					/*
					 * The vplist is full because there is
					 * too many rnodes.  We are done for
					 * now.
					 */
					goto done;
				}
			}
		}
		rw_exit(&rtable4[index].r_lock);
	}

done:

	/*
	 * Flush and release all of the files on the list.
	 */
	while (cnt-- > 0) {
		vp = vplist[cnt];
		(void) VOP_PUTPAGE(vp, (u_offset_t)0, 0, B_ASYNC, cr, NULL);
		VN_RELE(vp);
	}

	/*
	 * Free the space allocated to hold the list.
	 */
	kmem_free(vplist, num * sizeof (*vplist));
}

int
nfs4_free_data_reclaim(rnode4_t *rp)
{
	char *contents;
	vnode_t *xattr;
	int size;
	vsecattr_t *vsp;
	int freed;
	bool_t rdc = FALSE;

	/*
	 * Free any held caches which may
	 * be associated with this rnode.
	 */
	mutex_enter(&rp->r_statelock);
	if (rp->r_dir != NULL)
		rdc = TRUE;
	contents = rp->r_symlink.contents;
	size = rp->r_symlink.size;
	rp->r_symlink.contents = NULL;
	vsp = rp->r_secattr;
	rp->r_secattr = NULL;
	xattr = rp->r_xattr_dir;
	rp->r_xattr_dir = NULL;
	mutex_exit(&rp->r_statelock);

	/*
	 * Free the access cache entries.
	 */
	freed = nfs4_access_purge_rp(rp);

	if (rdc == FALSE && contents == NULL && vsp == NULL && xattr == NULL)
		return (freed);

	/*
	 * Free the readdir cache entries, incompletely if we can't block.
	 */
	nfs4_purge_rddir_cache(RTOV4(rp));

	/*
	 * Free the symbolic link cache.
	 */
	if (contents != NULL) {

		kmem_free((void *)contents, size);
	}

	/*
	 * Free any cached ACL.
	 */
	if (vsp != NULL)
		nfs4_acl_free_cache(vsp);

	/*
	 * Release the xattr directory vnode
	 */
	if (xattr != NULL)
		VN_RELE(xattr);

	return (1);
}

static int
nfs4_active_data_reclaim(rnode4_t *rp)
{
	char *contents;
	vnode_t *xattr = NULL;
	int size;
	vsecattr_t *vsp;
	int freed;
	bool_t rdc = FALSE;

	/*
	 * Free any held credentials and caches which
	 * may be associated with this rnode.
	 */
	if (!mutex_tryenter(&rp->r_statelock))
		return (0);
	contents = rp->r_symlink.contents;
	size = rp->r_symlink.size;
	rp->r_symlink.contents = NULL;
	vsp = rp->r_secattr;
	rp->r_secattr = NULL;
	if (rp->r_dir != NULL)
		rdc = TRUE;
	/*
	 * To avoid a deadlock, do not free r_xattr_dir cache if it is hashed
	 * on the same r_hashq queue. We are not mandated to free all caches.
	 * VN_RELE(rp->r_xattr_dir) will be done sometime later - e.g. when the
	 * rnode 'rp' is freed or put on the free list.
	 *
	 * We will retain NFS4_XATTR_DIR_NOTSUPP because:
	 * - it has no associated rnode4_t (its v_data is NULL),
	 * - it is preallocated statically and will never go away,
	 * so we cannot save anything by releasing it.
	 */
	if (rp->r_xattr_dir && rp->r_xattr_dir != NFS4_XATTR_DIR_NOTSUPP &&
	    VTOR4(rp->r_xattr_dir)->r_hashq != rp->r_hashq) {
		xattr = rp->r_xattr_dir;
		rp->r_xattr_dir = NULL;
	}
	mutex_exit(&rp->r_statelock);

	/*
	 * Free the access cache entries.
	 */
	freed = nfs4_access_purge_rp(rp);

	if (contents == NULL && vsp == NULL && rdc == FALSE && xattr == NULL)
		return (freed);

	/*
	 * Free the symbolic link cache.
	 */
	if (contents != NULL) {

		kmem_free((void *)contents, size);
	}

	/*
	 * Free any cached ACL.
	 */
	if (vsp != NULL)
		nfs4_acl_free_cache(vsp);

	nfs4_purge_rddir_cache(RTOV4(rp));

	/*
	 * Release the xattr directory vnode
	 */
	if (xattr != NULL)
		VN_RELE(xattr);

	return (1);
}

static int
nfs4_free_reclaim(void)
{
	int freed;
	rnode4_t *rp;

#ifdef DEBUG
	clstat4_debug.f_reclaim.value.ui64++;
#endif
	freed = 0;
	mutex_enter(&rp4freelist_lock);
	rp = rp4freelist;
	if (rp != NULL) {
		do {
			if (nfs4_free_data_reclaim(rp))
				freed = 1;
		} while ((rp = rp->r_freef) != rp4freelist);
	}
	mutex_exit(&rp4freelist_lock);
	return (freed);
}

static int
nfs4_active_reclaim(void)
{
	int freed;
	int index;
	rnode4_t *rp;

#ifdef DEBUG
	clstat4_debug.a_reclaim.value.ui64++;
#endif
	freed = 0;
	for (index = 0; index < rtable4size; index++) {
		rw_enter(&rtable4[index].r_lock, RW_READER);
		for (rp = rtable4[index].r_hashf;
		    rp != (rnode4_t *)(&rtable4[index]);
		    rp = rp->r_hashf) {
			if (nfs4_active_data_reclaim(rp))
				freed = 1;
		}
		rw_exit(&rtable4[index].r_lock);
	}
	return (freed);
}

static int
nfs4_rnode_reclaim(void)
{
	int freed;
	rnode4_t *rp;
	vnode_t *vp;

#ifdef DEBUG
	clstat4_debug.r_reclaim.value.ui64++;
#endif
	freed = 0;
	mutex_enter(&rp4freelist_lock);
	while ((rp = rp4freelist) != NULL) {
		rp4_rmfree(rp);
		mutex_exit(&rp4freelist_lock);
		if (rp->r_flags & R4HASHED) {
			vp = RTOV4(rp);
			rw_enter(&rp->r_hashq->r_lock, RW_WRITER);
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				VN_RELE_LOCKED(vp);
				mutex_exit(&vp->v_lock);
				rw_exit(&rp->r_hashq->r_lock);
				mutex_enter(&rp4freelist_lock);
				continue;
			}
			mutex_exit(&vp->v_lock);
			rp4_rmhash_locked(rp);
			rw_exit(&rp->r_hashq->r_lock);
		}
		/*
		 * This call to rp_addfree will end up destroying the
		 * rnode, but in a safe way with the appropriate set
		 * of checks done.
		 */
		rp4_addfree(rp, CRED());
		mutex_enter(&rp4freelist_lock);
	}
	mutex_exit(&rp4freelist_lock);
	return (freed);
}

/*ARGSUSED*/
static void
nfs4_reclaim(void *cdrarg)
{
#ifdef DEBUG
	clstat4_debug.reclaim.value.ui64++;
#endif
	if (nfs4_free_reclaim())
		return;

	if (nfs4_active_reclaim())
		return;

	(void) nfs4_rnode_reclaim();
}

/*
 * Returns the clientid4 to use for the given mntinfo4.  Note that the
 * clientid can change if the caller drops mi_recovlock.
 */

clientid4
mi2clientid(mntinfo4_t *mi)
{
	nfs4_server_t	*sp;
	clientid4	clientid = 0;

	/* this locks down sp if it is found */
	sp = find_nfs4_server(mi);
	if (sp != NULL) {
		clientid = sp->clientid;
		mutex_exit(&sp->s_lock);
		nfs4_server_rele(sp);
	}
	return (clientid);
}

/*
 * Return the current lease time for the server associated with the given
 * file.  Note that the lease time could change immediately after this
 * call.
 */

time_t
r2lease_time(rnode4_t *rp)
{
	nfs4_server_t	*sp;
	time_t		lease_time;
	mntinfo4_t	*mi = VTOMI4(RTOV4(rp));

	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER, 0);

	/* this locks down sp if it is found */
	sp = find_nfs4_server(VTOMI4(RTOV4(rp)));

	if (VTOMI4(RTOV4(rp))->mi_vfsp->vfs_flag & VFS_UNMOUNTED) {
		if (sp != NULL) {
			mutex_exit(&sp->s_lock);
			nfs4_server_rele(sp);
		}
		nfs_rw_exit(&mi->mi_recovlock);
		return (1);		/* 1 second */
	}

	ASSERT(sp != NULL);

	lease_time = sp->s_lease_time;

	mutex_exit(&sp->s_lock);
	nfs4_server_rele(sp);
	nfs_rw_exit(&mi->mi_recovlock);

	return (lease_time);
}

/*
 * Return a list with information about all the known open instances for
 * a filesystem. The caller must call r4releopenlist() when done with the
 * list.
 *
 * We are safe at looking at os_valid and os_pending_close across dropping
 * the 'os_sync_lock' to count up the number of open streams and then
 * allocate memory for the osp list due to:
 *	-Looking at os_pending_close is safe since this routine is
 *	only called via recovery, and os_pending_close can only be set via
 *	a non-recovery operation (which are all blocked when recovery
 *	is active).
 *
 *	-Examining os_valid is safe since non-recovery operations, which
 *	could potentially switch os_valid to 0, are blocked (via
 *	nfs4_start_fop) and recovery is single-threaded per mntinfo4_t
 *	(which means we are the only recovery thread potentially acting
 *	on this open stream).
 */

nfs4_opinst_t *
r4mkopenlist(mntinfo4_t *mi)
{
	nfs4_opinst_t *reopenlist, *rep;
	rnode4_t *rp;
	vnode_t *vp;
	vfs_t *vfsp = mi->mi_vfsp;
	int numosp;
	nfs4_open_stream_t *osp;
	int index;
	open_delegation_type4 dtype;
	int hold_vnode;

	reopenlist = NULL;

	for (index = 0; index < rtable4size; index++) {
		rw_enter(&rtable4[index].r_lock, RW_READER);
		for (rp = rtable4[index].r_hashf;
		    rp != (rnode4_t *)(&rtable4[index]);
		    rp = rp->r_hashf) {

			vp = RTOV4(rp);
			if (vp->v_vfsp != vfsp)
				continue;
			hold_vnode = 0;

			mutex_enter(&rp->r_os_lock);

			/* Count the number of valid open_streams of the file */
			numosp = 0;
			for (osp = list_head(&rp->r_open_streams); osp != NULL;
			    osp = list_next(&rp->r_open_streams, osp)) {
				mutex_enter(&osp->os_sync_lock);
				if (osp->os_valid && !osp->os_pending_close)
					numosp++;
				mutex_exit(&osp->os_sync_lock);
			}

			/* Fill in the valid open streams per vp */
			if (numosp > 0) {
				int j;

				hold_vnode = 1;

				/*
				 * Add a new open instance to the list
				 */
				rep = kmem_zalloc(sizeof (*reopenlist),
				    KM_SLEEP);
				rep->re_next = reopenlist;
				reopenlist = rep;

				rep->re_vp = vp;
				rep->re_osp = kmem_zalloc(
				    numosp * sizeof (*(rep->re_osp)),
				    KM_SLEEP);
				rep->re_numosp = numosp;

				j = 0;
				for (osp = list_head(&rp->r_open_streams);
				    osp != NULL;
				    osp = list_next(&rp->r_open_streams, osp)) {

					mutex_enter(&osp->os_sync_lock);
					if (osp->os_valid &&
					    !osp->os_pending_close) {
						osp->os_ref_count++;
						rep->re_osp[j] = osp;
						j++;
					}
					mutex_exit(&osp->os_sync_lock);
				}
				/*
				 * Assuming valid osp(s) stays valid between
				 * the time obtaining j and numosp.
				 */
				ASSERT(j == numosp);
			}

			mutex_exit(&rp->r_os_lock);
			/* do this here to keep v_lock > r_os_lock */
			if (hold_vnode)
				VN_HOLD(vp);
			mutex_enter(&rp->r_statev4_lock);
			if (rp->r_deleg_type != OPEN_DELEGATE_NONE) {
				/*
				 * If this rnode holds a delegation,
				 * but if there are no valid open streams,
				 * then just discard the delegation
				 * without doing delegreturn.
				 */
				if (numosp > 0)
					rp->r_deleg_needs_recovery =
					    rp->r_deleg_type;
			}
			/* Save the delegation type for use outside the lock */
			dtype = rp->r_deleg_type;
			mutex_exit(&rp->r_statev4_lock);

			/*
			 * If we have a delegation then get rid of it.
			 * We've set rp->r_deleg_needs_recovery so we have
			 * enough information to recover.
			 */
			if (dtype != OPEN_DELEGATE_NONE) {
				(void) nfs4delegreturn(rp, NFS4_DR_DISCARD);
			}
		}
		rw_exit(&rtable4[index].r_lock);
	}
	return (reopenlist);
}

/*
 * Given a filesystem id, check to see if any rnodes
 * within this fsid reside in the rnode cache, other
 * than one we know about.
 *
 * Return 1 if an rnode is found, 0 otherwise
 */
int
r4find_by_fsid(mntinfo4_t *mi, fattr4_fsid *moved_fsid)
{
	rnode4_t *rp;
	vnode_t *vp;
	vfs_t *vfsp = mi->mi_vfsp;
	fattr4_fsid *fsid;
	int index, found = 0;

	for (index = 0; index < rtable4size; index++) {
		rw_enter(&rtable4[index].r_lock, RW_READER);
		for (rp = rtable4[index].r_hashf;
		    rp != (rnode4_t *)(&rtable4[index]);
		    rp = rp->r_hashf) {

			vp = RTOV4(rp);
			if (vp->v_vfsp != vfsp)
				continue;

			/*
			 * XXX there might be a case where a
			 * replicated fs may have the same fsid
			 * across two different servers. This
			 * check isn't good enough in that case
			 */
			fsid = &rp->r_srv_fsid;
			if (FATTR4_FSID_EQ(moved_fsid, fsid)) {
				found = 1;
				break;
			}
		}
		rw_exit(&rtable4[index].r_lock);

		if (found)
			break;
	}
	return (found);
}

/*
 * Release the list of open instance references.
 */

void
r4releopenlist(nfs4_opinst_t *reopenp)
{
	nfs4_opinst_t *rep, *next;
	int i;

	for (rep = reopenp; rep; rep = next) {
		next = rep->re_next;

		for (i = 0; i < rep->re_numosp; i++)
			open_stream_rele(rep->re_osp[i], VTOR4(rep->re_vp));

		VN_RELE(rep->re_vp);
		kmem_free(rep->re_osp,
		    rep->re_numosp * sizeof (*(rep->re_osp)));

		kmem_free(rep, sizeof (*rep));
	}
}

int
nfs4_rnode_init(void)
{
	ulong_t nrnode4_max;
	int i;

	/*
	 * Compute the size of the rnode4 hash table
	 */
	if (nrnode <= 0)
		nrnode = ncsize;
	nrnode4_max =
	    (ulong_t)((kmem_maxavail() >> 2) / sizeof (struct rnode4));
	if (nrnode > nrnode4_max || (nrnode == 0 && ncsize == 0)) {
		zcmn_err(GLOBAL_ZONEID, CE_NOTE,
		    "!setting nrnode to max value of %ld", nrnode4_max);
		nrnode = nrnode4_max;
	}
	rtable4size = 1 << highbit(nrnode / rnode4_hashlen);
	rtable4mask = rtable4size - 1;

	/*
	 * Allocate and initialize the hash buckets
	 */
	rtable4 = kmem_alloc(rtable4size * sizeof (*rtable4), KM_SLEEP);
	for (i = 0; i < rtable4size; i++) {
		rtable4[i].r_hashf = (rnode4_t *)(&rtable4[i]);
		rtable4[i].r_hashb = (rnode4_t *)(&rtable4[i]);
		rw_init(&rtable4[i].r_lock, NULL, RW_DEFAULT, NULL);
	}

	rnode4_cache = kmem_cache_create("rnode4_cache", sizeof (rnode4_t),
	    0, NULL, NULL, nfs4_reclaim, NULL, NULL, 0);

	return (0);
}

int
nfs4_rnode_fini(void)
{
	int i;

	/*
	 * Deallocate the rnode hash queues
	 */
	kmem_cache_destroy(rnode4_cache);

	for (i = 0; i < rtable4size; i++)
		rw_destroy(&rtable4[i].r_lock);

	kmem_free(rtable4, rtable4size * sizeof (*rtable4));

	return (0);
}

/*
 * Return non-zero if the given filehandle refers to the root filehandle
 * for the given rnode.
 */

static int
isrootfh(nfs4_sharedfh_t *fh, rnode4_t *rp)
{
	int isroot;

	isroot = 0;
	if (SFH4_SAME(VTOMI4(RTOV4(rp))->mi_rootfh, fh))
		isroot = 1;

	return (isroot);
}

/*
 * The r4_stub_* routines assume that the rnode is newly activated, and
 * that the caller either holds the hash bucket r_lock for this rnode as
 * RW_WRITER, or holds r_statelock.
 */
static void
r4_stub_set(rnode4_t *rp, nfs4_stub_type_t type)
{
	vnode_t *vp = RTOV4(rp);
	krwlock_t *hash_lock = &rp->r_hashq->r_lock;

	ASSERT(RW_WRITE_HELD(hash_lock) || MUTEX_HELD(&rp->r_statelock));

	rp->r_stub_type = type;

	/*
	 * Safely switch this vnode to the trigger vnodeops.
	 *
	 * Currently, we don't ever switch a trigger vnode back to using
	 * "regular" v4 vnodeops. NFS4_STUB_NONE is only used to note that
	 * a new v4 object is not a trigger, and it will already have the
	 * correct v4 vnodeops by default. So, no "else" case required here.
	 */
	if (type != NFS4_STUB_NONE)
		vn_setops(vp, nfs4_trigger_vnodeops);
}

void
r4_stub_mirrormount(rnode4_t *rp)
{
	r4_stub_set(rp, NFS4_STUB_MIRRORMOUNT);
}

void
r4_stub_referral(rnode4_t *rp)
{
	DTRACE_PROBE1(nfs4clnt__func__referral__moved,
	    vnode_t *, RTOV4(rp));
	r4_stub_set(rp, NFS4_STUB_REFERRAL);
}

void
r4_stub_none(rnode4_t *rp)
{
	r4_stub_set(rp, NFS4_STUB_NONE);
}

#ifdef DEBUG

/*
 * Look in the rnode table for other rnodes that have the same filehandle.
 * Assume the lock is held for the hash chain of checkrp
 */

static void
r4_dup_check(rnode4_t *checkrp, vfs_t *vfsp)
{
	rnode4_t *rp;
	vnode_t *tvp;
	nfs4_fhandle_t fh, fh2;
	int index;

	if (!r4_check_for_dups)
		return;

	ASSERT(RW_LOCK_HELD(&checkrp->r_hashq->r_lock));

	sfh4_copyval(checkrp->r_fh, &fh);

	for (index = 0; index < rtable4size; index++) {

		if (&rtable4[index] != checkrp->r_hashq)
			rw_enter(&rtable4[index].r_lock, RW_READER);

		for (rp = rtable4[index].r_hashf;
		    rp != (rnode4_t *)(&rtable4[index]);
		    rp = rp->r_hashf) {

			if (rp == checkrp)
				continue;

			tvp = RTOV4(rp);
			if (tvp->v_vfsp != vfsp)
				continue;

			sfh4_copyval(rp->r_fh, &fh2);
			if (nfs4cmpfhandle(&fh, &fh2) == 0) {
				cmn_err(CE_PANIC, "rnodes with same fs, fh "
				    "(%p, %p)", (void *)checkrp, (void *)rp);
			}
		}

		if (&rtable4[index] != checkrp->r_hashq)
			rw_exit(&rtable4[index].r_lock);
	}
}

#endif /* DEBUG */
