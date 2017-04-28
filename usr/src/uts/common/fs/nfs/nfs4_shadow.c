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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */


#include <sys/systm.h>
#include <sys/cmn_err.h>

#include <nfs/nfs.h>

#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>

static struct kmem_cache *svnode_cache;

struct sv_stats
{
	int	sv_activate;
	int	sv_find;
	int	sv_match;
	int	sv_inactive;
	int	sv_exchange;
} sv_stats;

static int	sv_match(nfs4_fname_t *, nfs4_sharedfh_t *, svnode_t *);

/*
 * Map a vnode back to the shadow which points to it.  This is
 * hard now that the vnode is not embedded in the shadow vnode.
 */


svnode_t *
vtosv(vnode_t *vp)
{
	rnode4_t *rp = VTOR4(vp);
	svnode_t *svp, *svp_found = NULL;

	/* Check to see if it's the master shadow vnode first. */

	if (RTOV4(rp) == vp)
		return (&rp->r_svnode);

	mutex_enter(&rp->r_svlock);

	for (svp = rp->r_svnode.sv_forw; svp != &rp->r_svnode;
	    svp = svp->sv_forw)
		if (svp->sv_r_vnode == vp) {
			svp_found = svp;
			break;
		}

	mutex_exit(&rp->r_svlock);
	ASSERT(svp_found != NULL);

	return (svp_found);
}

/*
 * sv_activate - find and activate the shadow vnode for the given
 * directory file handle and name.  May replace *vpp with a held reference
 * to a different vnode, in which case the reference to the previous one is
 * released.
 */

void
sv_activate(vnode_t **vpp, vnode_t *dvp, nfs4_fname_t **namepp, int newnode)
{
	svnode_t *svp;
	vnode_t *resvp;
	nfs4_fname_t *svpname;
	rnode4_t *rp = VTOR4(*vpp);
	svp = VTOSV(*vpp);

	ASSERT(namepp != NULL);
	ASSERT(*namepp != NULL);
	ASSERT(dvp != NULL);

	sv_stats.sv_activate++;

	ASSERT(RW_LOCK_HELD(&rp->r_hashq->r_lock));

	/*
	 * If make_rnode made a new rnode (ie. newnode != 0), then
	 * the master vnode was (partially) initialized there.  If
	 * it was not a new rnode, then it returns the master vnode.
	 * Call sv_find to find and/or initialize the shadow
	 * vnode.
	 */

	if (newnode) {
		/*
		 * Initialize the shadow vnode.
		 */
		svp->sv_forw = svp->sv_back = svp;
		ASSERT(svp->sv_dfh == NULL);
		svp->sv_dfh = VTOR4(dvp)->r_fh;
		sfh4_hold(svp->sv_dfh);
		ASSERT(svp->sv_name == NULL);
		svp->sv_name = *namepp;
	} else if ((*vpp)->v_type == VREG && !((*vpp)->v_flag & VROOT)) {
		resvp = sv_find(*vpp, dvp, namepp);
		ASSERT(resvp->v_type == VREG);
		VN_RELE(*vpp);
		*vpp = resvp;
	} else {
		/*
		 * No shadow vnodes (i.e. hard links) in this branch.
		 * If sv_activate() is called for an existing rnode
		 * (newnode isn't set) but with a new name, the sv_name
		 * needs to be updated and the old sv_name released.
		 *
		 * fname mismatches can occur due to server side renames,
		 * here is a chance to update the fname in case there is
		 * a mismatch. Since this is not a newnode we hold r_svlock
		 * to protect sv_name.
		 */
		mutex_enter(&rp->r_svlock);
		svpname = svp->sv_name;
		if (svpname != *namepp) {
			/*
			 * Call fn_rele() to release the hold for the
			 * previous shadow vnode reference. Don't
			 * release the hold on the fname pointed to by
			 * namepp as we have new reference to it from
			 * this shadow vnode.
			 */
			svp->sv_name = *namepp;
			mutex_exit(&rp->r_svlock);
			fn_rele(&svpname);
		} else {
			mutex_exit(&rp->r_svlock);
			fn_rele(namepp);
		}
	}
}

/*
 * sv_find - find the shadow vnode for the desired name and directory
 * file handle.  If one does not exist, then create it.  Returns the shadow
 * vnode.  The caller is responsible for freeing the reference.
 * Consumes the name reference and nulls it out.
 *
 * Side effects: increments the reference count on the master vnode if the
 * shadow vnode had to be created.
 */

vnode_t *
sv_find(vnode_t *mvp, vnode_t *dvp, nfs4_fname_t **namepp)
{
	vnode_t *vp;
	rnode4_t *rp = VTOR4(mvp);
	svnode_t *svp;
	svnode_t *master_svp = VTOSV(mvp);
	rnode4_t *drp = VTOR4(dvp);
	nfs4_fname_t *nm;

	ASSERT(dvp != NULL);

	sv_stats.sv_find++;

	ASSERT(namepp != NULL);
	ASSERT(*namepp != NULL);
	nm = *namepp;
	*namepp = NULL;

	/*
	 * At this point, all we know is that we have an rnode whose
	 * file handle matches the file handle of the object we want.
	 * We have to verify that component name and the directory
	 * match.  If so, then we are done.
	 *
	 * Note: mvp is always the master vnode.
	 */

	ASSERT(!IS_SHADOW(mvp, rp));

	if (sv_match(nm, drp->r_fh, master_svp)) {
		VN_HOLD(mvp);
		fn_rele(&nm);
		return (mvp);
	}

	/*
	 * No match, search through the shadow vnode list.
	 * Hold the r_svlock to prevent changes.
	 */

	mutex_enter(&rp->r_svlock);

	for (svp = master_svp->sv_forw; svp != master_svp; svp = svp->sv_forw)
		if (sv_match(nm, drp->r_fh, svp)) {

			/*
			 * A matching shadow vnode is found, bump the
			 * reference count on it and return it.
			 */

			vp = SVTOV(svp);
			VN_HOLD(vp);
			fn_rele(&nm);
			mutex_exit(&rp->r_svlock);
			return (vp);
		}

	/*
	 * No match searching the list, go allocate a new shadow
	 */
	svp = kmem_cache_alloc(svnode_cache, KM_SLEEP);
	svp->sv_r_vnode = vn_alloc(KM_SLEEP);
	vp = SVTOV(svp);

	/* Initialize the vnode */

	vn_setops(vp, nfs4_vnodeops);
	vp->v_data = (caddr_t)rp;
	vp->v_vfsp = mvp->v_vfsp;
	ASSERT(nfs4_consistent_type(mvp));
	vp->v_type = mvp->v_type;
	vp->v_pages = (page_t *)-1;	/* No pages, please */
	vn_exists(vp);

	/* Initialize the shadow vnode */

	svp->sv_dfh = VTOR4(dvp)->r_fh;
	sfh4_hold(svp->sv_dfh);

	svp->sv_name = nm;
	VN_HOLD(mvp);
	insque(svp, master_svp);
	mutex_exit(&rp->r_svlock);

	return (vp);
}

/*
 * sv_match - check to see if the shadow vnode matches the desired
 * name and directory file handle.  Returns non-zero if there's a match,
 * zero if it's not a match.
 */

static int
sv_match(nfs4_fname_t *nm, nfs4_sharedfh_t *fhp, svnode_t *svp)
{
	sv_stats.sv_match++;

	return (svp->sv_name != NULL && svp->sv_name == nm &&
	    SFH4_SAME(svp->sv_dfh, fhp));
}

/*
 * sv_inactive - deactivate a shadow vnode. sv_inactive is called
 * from nfs4_inactive.  Whenever a shadow vnode is de-activated,
 * sv_inactive cleans up the mess and releases the reference on the
 * master vnode.
 */

void
sv_inactive(vnode_t *vp)
{
	svnode_t *svp;
	rnode4_t *rp;
	vnode_t *mvp;

	sv_stats.sv_inactive++;

	svp = VTOSV(vp);
	rp = VTOR4(vp);
	mvp = rp->r_vnode;

	ASSERT(mvp != vp);

	/*
	 * Remove the shadow vnode from the list.  The serialization
	 * is provided by the svnode list lock.  This could be done
	 * with the r_statelock, but that would require more locking
	 * in the activation path.
	 */

	mutex_enter(&rp->r_svlock);
	mutex_enter(&vp->v_lock);
	/* check if someone slipped in while locks were dropped */
	if (vp->v_count > 1) {
		VN_RELE_LOCKED(vp);
		mutex_exit(&vp->v_lock);
		mutex_exit(&rp->r_svlock);
		return;
	}
	remque(svp);
	mutex_exit(&vp->v_lock);
	mutex_exit(&rp->r_svlock);

	sv_uninit(svp);
	svp->sv_forw = svp->sv_back = NULL;
	kmem_cache_free(svnode_cache, svp);
	vn_invalid(vp);
	vn_free(vp);

	/* release the reference held by this shadow on the master */

	VN_RELE(mvp);
}

/*
 * sv_uninit - free any data structures allocated by the shadow vnode.
 */

void
sv_uninit(svnode_t *svp)
{
	if (svp->sv_name != NULL)
		fn_rele(&svp->sv_name);
	if (svp->sv_dfh != NULL)
		sfh4_rele(&svp->sv_dfh);
}

/*
 * sv_exchange -  exchange a shadow vnode for the master vnode.  This
 * occurs during nfs4_open, since only the master vnode owns the files
 * resources (eg. pages).
 */

void
sv_exchange(vnode_t **vpp)
{
	vnode_t *mvp;

	sv_stats.sv_exchange++;

	/* RTOV always returns the master vnode */
	mvp = RTOV4(VTOR4(*vpp));
	VN_HOLD(mvp)
	VN_RELE(*vpp);
	*vpp = mvp;
}

int
nfs4_shadow_init(void)
{
	/*
	 * Allocate shadow vnode cache
	 */
	svnode_cache = kmem_cache_create("svnode_cache",
	    sizeof (svnode_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	return (0);
}

int
nfs4_shadow_fini(void)
{
	kmem_cache_destroy(svnode_cache);

	return (0);
}
