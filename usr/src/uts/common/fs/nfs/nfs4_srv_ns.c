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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <sys/cmn_err.h>

#define	PSEUDOFS_SUFFIX		" (pseudo)"

/*
 * A version of VOP_FID that deals with a remote VOP_FID for nfs.
 * If vp is an nfs node, nfs4_fid() returns EREMOTE, nfs3_fid() and nfs_fid()
 * returns the filehandle of vp as its fid. When nfs uses fid to set the
 * exportinfo filehandle template, a remote nfs filehandle would be too big for
 * the fid of the exported directory. This routine remaps the value of the
 * attribute va_nodeid of vp to be the fid of vp, so that the fid can fit.
 *
 * We need this fid mainly for setting up NFSv4 server namespace where an
 * nfs filesystem is also part of it. Thus, need to be able to setup a pseudo
 * exportinfo for an nfs node.
 *
 * e.g. mount a filesystem on top of a nfs dir, and then share the new mount
 *      (like exporting a local disk from a "diskless" client)
 */
int
vop_fid_pseudo(vnode_t *vp, fid_t *fidp)
{
	struct vattr va;
	int error;

	error = VOP_FID(vp, fidp, NULL);

	/*
	 * XXX nfs4_fid() does nothing and returns EREMOTE.
	 * XXX nfs3_fid()/nfs_fid() returns nfs filehandle as its fid
	 * which has a bigger length than local fid.
	 * NFS_FH4MAXDATA is the size of
	 * fhandle4_t.fh_xdata[NFS_FH4MAXDATA].
	 *
	 * Note: nfs[2,3,4]_fid() only gets called for diskless clients.
	 */
	if (error == EREMOTE ||
	    (error == 0 && fidp->fid_len > NFS_FH4MAXDATA)) {

		va.va_mask = AT_NODEID;
		error = VOP_GETATTR(vp, &va, 0, CRED(), NULL);
		if (error)
			return (error);

		fidp->fid_len = sizeof (va.va_nodeid);
		bcopy(&va.va_nodeid, fidp->fid_data, fidp->fid_len);
		return (0);
	}

	return (error);
}

/*
 * Get an nfsv4 vnode of the given fid from the visible list of an
 * nfs filesystem or get the exi_vp if it is the root node.
 */
int
nfs4_vget_pseudo(struct exportinfo *exi, vnode_t **vpp, fid_t *fidp)
{
	fid_t exp_fid;
	struct exp_visible *visp;
	int error;

	/* check if the given fid is in the visible list */

	for (visp = exi->exi_visible; visp; visp = visp->vis_next) {
		if (EQFID(fidp, &visp->vis_fid)) {
			VN_HOLD(visp->vis_vp);
			*vpp = visp->vis_vp;
			return (0);
		}
	}

	/* check if the given fid is the same as the exported node */

	bzero(&exp_fid, sizeof (exp_fid));
	exp_fid.fid_len = MAXFIDSZ;
	error = vop_fid_pseudo(exi->exi_vp, &exp_fid);
	if (error)
		return (error);

	if (EQFID(fidp, &exp_fid)) {
		VN_HOLD(exi->exi_vp);
		*vpp = exi->exi_vp;
		return (0);
	}

	return (ENOENT);
}

/*
 * Create a pseudo export entry
 *
 * This is an export entry that's created as the
 * side-effect of a "real" export.  As a part of
 * a real export, the pathname to the export is
 * checked to see if all the directory components
 * are accessible via an NFSv4 client, i.e. are
 * exported.  If treeclimb_export() finds an unexported
 * mountpoint along the path, then it calls this
 * function to export it.
 *
 * This pseudo export differs from a real export in that
 * it only allows read-only access.  A "visible" list of
 * directories is added to filter lookup and readdir results
 * to only contain dirnames which lead to descendant shares.
 *
 * A visible list has a per-file-system scope.  Any exportinfo
 * struct (real or pseudo) can have a visible list as long as
 * a) its export root is VROOT
 * b) a descendant of the export root is shared
 */
int
pseudo_exportfs(vnode_t *vp, struct exp_visible *vis_head,
					struct exportdata *exdata)
{
	struct exportinfo *exi;
	struct exportdata *kex;
	fid_t fid;
	fsid_t fsid;
	int error, vpathlen;

	ASSERT(RW_WRITE_HELD(&exported_lock));

	/*
	 * Get the vfs id
	 */
	bzero(&fid, sizeof (fid));
	fid.fid_len = MAXFIDSZ;
	error = vop_fid_pseudo(vp, &fid);
	if (error) {
		/*
		 * If VOP_FID returns ENOSPC then the fid supplied
		 * is too small.  For now we simply return EREMOTE.
		 */
		if (error == ENOSPC)
			error = EREMOTE;
		return (error);
	}

	fsid = vp->v_vfsp->vfs_fsid;
	exi = kmem_zalloc(sizeof (*exi), KM_SLEEP);
	exi->exi_fsid = fsid;
	exi->exi_fid = fid;
	exi->exi_vp = vp;
	VN_HOLD(exi->exi_vp);
	exi->exi_visible = vis_head;
	exi->exi_count = 1;
	exi->exi_volatile_dev = (vfssw[vp->v_vfsp->vfs_fstype].vsw_flag &
	    VSW_VOLATILEDEV) ? 1 : 0;
	mutex_init(&exi->exi_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Build up the template fhandle
	 */
	exi->exi_fh.fh_fsid = fsid;
	ASSERT(exi->exi_fid.fid_len <= sizeof (exi->exi_fh.fh_xdata));
	exi->exi_fh.fh_xlen = exi->exi_fid.fid_len;
	bcopy(exi->exi_fid.fid_data, exi->exi_fh.fh_xdata,
	    exi->exi_fid.fid_len);
	exi->exi_fh.fh_len = sizeof (exi->exi_fh.fh_data);

	kex = &exi->exi_export;
	kex->ex_flags = EX_PSEUDO;

	vpathlen = vp->v_path ? strlen(vp->v_path) : 0;
	kex->ex_pathlen = vpathlen + strlen(PSEUDOFS_SUFFIX);
	kex->ex_path = kmem_alloc(kex->ex_pathlen + 1, KM_SLEEP);

	if (vpathlen)
		(void) strcpy(kex->ex_path, vp->v_path);
	(void) strcpy(kex->ex_path + vpathlen, PSEUDOFS_SUFFIX);

	/* Transfer the secinfo data from exdata to this new pseudo node */
	if (exdata)
		srv_secinfo_exp2pseu(&exi->exi_export, exdata);

	/*
	 * Initialize auth cache lock
	 */
	rw_init(&exi->exi_cache_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Insert the new entry at the front of the export list
	 */
	export_link(exi);

	return (0);
}

/*
 * Free a list of visible directories
 */
void
free_visible(struct exp_visible *head)
{
	struct exp_visible *visp, *next;

	for (visp = head; visp; visp = next) {
		if (visp->vis_vp != NULL)
			VN_RELE(visp->vis_vp);

		next = visp->vis_next;
		srv_secinfo_list_free(visp->vis_secinfo, visp->vis_seccnt);
		kmem_free(visp, sizeof (*visp));
	}
}

/*
 * Add a list of visible directories to a pseudo exportfs.
 *
 * When we export a new directory we need to add a new
 * path segment through the pseudofs to reach the new
 * directory. This new path is reflected in a list of
 * directories added to the "visible" list.
 *
 * Here there are two lists of visible fids: one hanging off the
 * pseudo exportinfo, and the one we want to add.  It's possible
 * that the two lists share a common path segment
 * and have some common directories.  We need to combine
 * the lists so there's no duplicate entries. Where a common
 * path component is found, the vis_count field is bumped.
 *
 * When the addition is complete, the supplied list is freed.
 */

static void
more_visible(struct exportinfo *exi, struct exp_visible *vis_head)
{
	struct exp_visible *vp1, *vp2;
	struct exp_visible *tail, *new;
	int found;

	/*
	 * If exportinfo doesn't already have a visible
	 * list just assign the entire supplied list.
	 */
	if (exi->exi_visible == NULL) {
		exi->exi_visible = vis_head;
		return;
	}

	/*
	 * The outer loop traverses the supplied list.
	 */
	for (vp1 = vis_head; vp1; vp1 = vp1->vis_next) {

		/*
		 * Given an element from the list to be added,
		 * search the exportinfo visible list looking for a match.
		 * If a match is found, increment the reference count.
		 */
		found = 0;

		for (vp2 = exi->exi_visible; vp2; vp2 = vp2->vis_next) {

			tail = vp2;

			if (EQFID(&vp1->vis_fid, &vp2->vis_fid)) {
				found = 1;
				vp2->vis_count++;
				VN_RELE(vp1->vis_vp);
				vp1->vis_vp = NULL;

				/*
				 * If the visible struct we want to add
				 * (vp1) has vis_exported set to 1, then
				 * the matching visible struct we just found
				 * must also have it's vis_exported field
				 * set to 1.
				 *
				 * For example, if /export/home was shared
				 * (and a mountpoint), then "export" and
				 * "home" would each have visible structs in
				 * the root pseudo exportinfo. The vis_exported
				 * for home would be 1, and vis_exported for
				 * export would be 0.  Now, if /export was
				 * also shared, more_visible would find the
				 * existing visible struct for export, and
				 * see that vis_exported was 0.  The code
				 * below will set it to 1.
				 *
				 * vp1 is from vis list passed in (vis_head)
				 * vp2 is from vis list on pseudo exportinfo
				 */
				if (vp1->vis_exported && !vp2->vis_exported)
					vp2->vis_exported = 1;
				break;
			}
		}

		/* If not found - add to the end of the list */
		if (! found) {
			new = kmem_zalloc(sizeof (*new), KM_SLEEP);
			*new = *vp1;
			tail->vis_next = new;
			new->vis_next = NULL;
			vp1->vis_vp = NULL;
		}
	}

	/*
	 * Throw away the path list. vis_vp pointers in vis_head list
	 * are either VN_RELEed or reassigned, and are set to NULL.
	 * There is no need to VN_RELE in free_visible for this vis_head.
	 */
	free_visible(vis_head);
}

/*
 * Remove a list of visible directories from the pseudo exportfs.
 *
 * When we unexport a directory, we have to remove path
 * components from the visible list in the pseudo exportfs
 * entry.  The supplied visible list contains the fids of the path
 * to the unexported directory.  The visible list of the export
 * is checked against this list any matching fids have their
 * reference count decremented.  If a reference count drops to
 * zero, then it means no paths now use this directory, so its
 * fid can be removed from the visible list.
 *
 * When the last path is removed, the visible list will be null.
 */
static void
less_visible(struct exportinfo *exi, struct exp_visible *vis_head)
{
	struct exp_visible *vp1, *vp2;
	struct exp_visible *prev, *next;

	/*
	 * The outer loop traverses the supplied list.
	 */
	for (vp1 = vis_head; vp1; vp1 = vp1->vis_next) {

		/*
		 * Given an element from the list to be removed,
		 * search the exportinfo list looking for a match.
		 * If a match is found, decrement the reference
		 * count and drop the element if the count drops
		 * to zero.
		 */
		for (vp2 = exi->exi_visible, prev = NULL; vp2; vp2 = next) {

			next = vp2->vis_next;

			if (EQFID(&vp1->vis_fid, &vp2->vis_fid)) {

				/*
				 * Decrement the ref count.
				 * Remove the entry if it's zero.
				 */
				if (--vp2->vis_count <= 0) {
					if (prev == NULL)
						exi->exi_visible = next;
					else
						prev->vis_next = next;

					VN_RELE(vp2->vis_vp);
					srv_secinfo_list_free(vp2->vis_secinfo,
					    vp2->vis_seccnt);
					kmem_free(vp2, sizeof (*vp1));
				} else {
					/*
					 * If we're here, then the vp2 will
					 * remain in the vis list.  If the
					 * vis entry corresponds to the object
					 * being unshared, then vis_exported
					 * needs to be set to 0.
					 *
					 * vp1 is a node from caller's list
					 * vp2 is node from exportinfo's list
					 *
					 * Only 1 node in the caller's list
					 * will have vis_exported set to 1,
					 * and it corresponds to the obj being
					 * unshared.  It should always be the
					 * last element of the caller's list.
					 */
					if (vp1->vis_exported &&
					    vp2->vis_exported) {
						vp2->vis_exported = 0;
					}
				}

				break;
			}

			prev = vp2;
		}
	}

	free_visible(vis_head);
}

/*
 * This function checks the path to a new export to
 * check whether all the pathname components are
 * exported. It works by climbing the file tree one
 * component at a time via "..", crossing mountpoints
 * if necessary until an export entry is found, or the
 * system root is reached.
 *
 * If an unexported mountpoint is found, then
 * a new pseudo export is added and the pathname from
 * the mountpoint down to the export is added to the
 * visible list for the new pseudo export.  If an existing
 * pseudo export is found, then the pathname is added
 * to its visible list.
 *
 * Note that there's some tests for exportdir.
 * The exportinfo entry that's passed as a parameter
 * is that of the real export and exportdir is set
 * for this case.
 *
 * Here is an example of a possible setup:
 *
 * () - a new fs; fs mount point
 * EXPORT - a real exported node
 * PSEUDO - a pseudo node
 * vis - visible list
 * f# - security flavor#
 * (f#) - security flavor# propagated from its descendents
 * "" - covered vnode
 *
 *
 *                 /
 *                 |
 *                 (a) PSEUDO (f1,f2)
 *                 |   vis: b,b,"c","n"
 *                 |
 *                 b
 *        ---------|------------------
 *        |                          |
 *        (c) EXPORT,f1(f2)          (n) PSEUDO (f1,f2)
 *        |   vis: "e","d"           |   vis: m,m,,p,q,"o"
 *        |                          |
 *  ------------------          -------------------
 *  |        |        |         |                  |
 *  (d)      (e)      f         m EXPORT,f1(f2)    p
 *  EXPORT   EXPORT             |                  |
 *  f1       f2                 |                  |
 *           |                  |                  |
 *           j                 (o) EXPORT,f2       q EXPORT f2
 *
 */
int
treeclimb_export(struct exportinfo *exip)
{
	vnode_t *dvp, *vp;
	fid_t fid;
	int error;
	int exportdir;
	struct exportinfo *exi = NULL;
	struct exp_visible *visp;
	struct exp_visible *vis_head = NULL;
	struct vattr va;

	ASSERT(RW_WRITE_HELD(&exported_lock));

	vp = exip->exi_vp;
	VN_HOLD(vp);
	exportdir = 1;

	for (;;) {

		bzero(&fid, sizeof (fid));
		fid.fid_len = MAXFIDSZ;
		error = vop_fid_pseudo(vp, &fid);
		if (error)
			break;

		if (! exportdir) {
			/*
			 * Check if this exportroot is a VROOT dir.  If so,
			 * then attach the pseudonodes.  If not, then
			 * continue .. traversal until we hit a VROOT
			 * export (pseudo or real).
			 */
			exi = checkexport4(&vp->v_vfsp->vfs_fsid, &fid, vp);
			if (exi != NULL && vp->v_flag & VROOT) {
				/*
				 * Found an export info
				 *
				 * Extend the list of visible
				 * directories whether it's a pseudo
				 * or a real export.
				 */
				more_visible(exi, vis_head);
				vis_head = NULL;
				break;	/* and climb no further */
			}
		}

		/*
		 * If at the root of the filesystem, need
		 * to traverse across the mountpoint
		 * and continue the climb on the mounted-on
		 * filesystem.
		 */
		if (vp->v_flag & VROOT) {

			if (! exportdir) {
				/*
				 * Found the root directory of a filesystem
				 * that isn't exported.  Need to export
				 * this as a pseudo export so that an NFS v4
				 * client can do lookups in it.
				 */
				error = pseudo_exportfs(vp, vis_head, NULL);
				if (error)
					break;
				vis_head = NULL;
			}

			if (VN_CMP(vp, rootdir)) {
				/* at system root */
				break;
			}

			vp = untraverse(vp);
			exportdir = 0;
			continue;
		}

		/*
		 * Do a getattr to obtain the nodeid (inode num)
		 * for this vnode.
		 */
		va.va_mask = AT_NODEID;
		error = VOP_GETATTR(vp, &va, 0, CRED(), NULL);
		if (error)
			break;

		/*
		 *  Add this directory fid to visible list
		 */
		visp = kmem_alloc(sizeof (*visp), KM_SLEEP);
		VN_HOLD(vp);
		visp->vis_vp = vp;
		visp->vis_fid = fid;		/* structure copy */
		visp->vis_ino = va.va_nodeid;
		visp->vis_count = 1;
		visp->vis_exported = exportdir;
		visp->vis_secinfo = NULL;
		visp->vis_seccnt = 0;
		visp->vis_next = vis_head;
		vis_head = visp;

		/*
		 * Now, do a ".." to find parent dir of vp.
		 */
		error = VOP_LOOKUP(vp, "..", &dvp, NULL, 0, NULL, CRED(),
		    NULL, NULL, NULL);

		if (error == ENOTDIR && exportdir) {
			dvp = exip->exi_dvp;
			ASSERT(dvp != NULL);
			VN_HOLD(dvp);
			error = 0;
		}

		if (error)
			break;

		exportdir = 0;
		VN_RELE(vp);
		vp = dvp;
	}

	VN_RELE(vp);
	return (error);
}

/*
 * Walk up the tree looking for pseudo export entries.
 *
 * If a pseudo export is found, remove the path we've
 * climbed from its visible list. If the visible list
 * still has entries after the removal, then we can stop.
 * If it becomes null, then remove the pseudo export entry
 * and carry on up the tree to see if there's any more.
 */
int
treeclimb_unexport(struct exportinfo *exip)
{
	vnode_t *dvp, *vp;
	fid_t fid;
	int error = 0;
	int exportdir;
	struct exportinfo *exi = NULL;
	struct exp_visible *vis_head = NULL, *visp;

	ASSERT(RW_WRITE_HELD(&exported_lock));

	exportdir = 1;
	vp = exip->exi_vp;
	VN_HOLD(vp);

	for (;;) {

		bzero(&fid, sizeof (fid));
		fid.fid_len = MAXFIDSZ;
		error = vop_fid_pseudo(vp, &fid);
		if (error)
			break;

		if (! exportdir) {

			/*
			 * We need to use checkexport4() here because it
			 * doesn't acquire exported_lock and it doesn't
			 * manipulate exi_count.
			 *
			 * Remove directories from the visible
			 * list that are unique to the path
			 * for this export.  (Only VROOT exportinfos
			 * have can have visible entries).
			 */
			exi = checkexport4(&vp->v_vfsp->vfs_fsid, &fid, vp);
			if (exi != NULL && (vp->v_flag & VROOT)) {

				less_visible(exi, vis_head);
				vis_head = NULL;

				/*
				 * If the visible list has entries
				 * or if it's a real export, then
				 * there's no need to keep climbing.
				 */
				if (exi->exi_visible || ! PSEUDO(exi))
					break;

				/*
				 * Otherwise, we have a pseudo export
				 * with an empty list (no exports below
				 * it) so we must remove and continue
				 * the climb to remove its name from
				 * the parent export.
				 */
				error = export_unlink(&vp->v_vfsp->vfs_fsid,
				    &fid, vp, NULL);
				if (error)
					break;

				exi_rele(exi);
			}
		}

		/*
		 * If at the root of the filesystem, need
		 * to traverse across the mountpoint
		 * and continue the climb on the mounted-on
		 * filesystem.
		 */
		if (vp->v_flag & VROOT) {
			if (VN_CMP(vp, rootdir)) {
				/* at system root */
				break;
			}
			vp = untraverse(vp);
			exportdir = 0;
			continue;
		}

		/*
		 *  Add this directory fid to path list
		 */
		visp = kmem_alloc(sizeof (*visp), KM_SLEEP);
		VN_HOLD(vp);
		visp->vis_vp = vp;
		visp->vis_fid = fid;		/* structure copy */
		visp->vis_ino = 0;
		visp->vis_count = 1;
		visp->vis_exported = exportdir;
		visp->vis_secinfo = NULL;
		visp->vis_seccnt = 0;
		visp->vis_next = vis_head;
		vis_head = visp;

		/*
		 * Do a ".." to find parent dir of vp.
		 */
		error = VOP_LOOKUP(vp, "..", &dvp, NULL, 0, NULL, CRED(),
		    NULL, NULL, NULL);

		if (error == ENOTDIR && exportdir) {
			dvp = exip->exi_dvp;
			ASSERT(dvp != NULL);
			VN_HOLD(dvp);
			error = 0;
		}
		if (error)
			break;

		exportdir = 0;
		VN_RELE(vp);
		vp = dvp;
	}

	VN_RELE(vp);
	return (error);
}


/*
 * Traverse backward across mountpoint from the
 * root vnode of a filesystem to its mounted-on
 * vnode.
 */
vnode_t *
untraverse(vnode_t *vp)
{
	vnode_t *tvp, *nextvp;

	tvp = vp;
	for (;;) {
		if (! (tvp->v_flag & VROOT))
			break;

		/* lock vfs to prevent unmount of this vfs */
		vfs_lock_wait(tvp->v_vfsp);

		if ((nextvp = tvp->v_vfsp->vfs_vnodecovered) == NULL) {
			vfs_unlock(tvp->v_vfsp);
			break;
		}

		/*
		 * Hold nextvp to prevent unmount.  After unlock vfs and
		 * rele tvp, any number of overlays could be unmounted.
		 * Putting a hold on vfs_vnodecovered will only allow
		 * tvp's vfs to be unmounted. Of course if caller placed
		 * extra hold on vp before calling untraverse, the following
		 * hold would not be needed.  Since prev actions of caller
		 * are unknown, we need to hold here just to be safe.
		 */
		VN_HOLD(nextvp);
		vfs_unlock(tvp->v_vfsp);
		VN_RELE(tvp);
		tvp = nextvp;
	}

	return (tvp);
}

/*
 * Given an exportinfo, climb up to find the exportinfo for the VROOT
 * of the filesystem.
 *
 * e.g.         /
 *              |
 *              a (VROOT) pseudo-exportinfo
 *		|
 *		b
 *		|
 *		c  #share /a/b/c
 *		|
 *		d
 *
 * where c is in the same filesystem as a.
 * So, get_root_export(*exportinfo_for_c) returns exportinfo_for_a
 *
 * If d is shared, then c will be put into a's visible list.
 * Note: visible list is per filesystem and is attached to the
 * VROOT exportinfo.
 */
struct exportinfo *
get_root_export(struct exportinfo *exip)
{
	vnode_t *dvp, *vp;
	fid_t fid;
	struct exportinfo *exi = exip;
	int error;

	vp = exi->exi_vp;
	VN_HOLD(vp);

	for (;;) {

		if (vp->v_flag & VROOT) {
			ASSERT(exi != NULL);
			break;
		}

		/*
		 * Now, do a ".." to find parent dir of vp.
		 */
		error = VOP_LOOKUP(vp, "..", &dvp, NULL, 0, NULL, CRED(),
		    NULL, NULL, NULL);

		if (error) {
			exi = NULL;
			break;
		}

		VN_RELE(vp);
		vp = dvp;

		bzero(&fid, sizeof (fid));
		fid.fid_len = MAXFIDSZ;
		error = vop_fid_pseudo(vp, &fid);
		if (error) {
			exi = NULL;
			break;
		}

		exi = checkexport4(&vp->v_vfsp->vfs_fsid, &fid, vp);
	}

	VN_RELE(vp);
	return (exi);
}

/*
 * Return true if the supplied vnode has a sub-directory exported.
 */
int
has_visible(struct exportinfo *exi, vnode_t *vp)
{
	struct exp_visible *visp;
	fid_t fid;
	bool_t vp_is_exported;

	vp_is_exported = VN_CMP(vp,  exi->exi_vp);

	/*
	 * An exported root vnode has a sub-dir shared if it has a visible list.
	 * i.e. if it does not have a visible list, then there is no node in
	 * this filesystem leads to any other shared node.
	 */
	if (vp_is_exported && (vp->v_flag & VROOT))
		return (exi->exi_visible ? 1 : 0);

	/*
	 * Only the exportinfo of a fs root node may have a visible list.
	 * Either it is a pseudo root node, or a real exported root node.
	 */
	if ((exi = get_root_export(exi)) == NULL) {
		return (0);
	}

	if (!exi->exi_visible)
		return (0);

	/* Get the fid of the vnode */
	bzero(&fid, sizeof (fid));
	fid.fid_len = MAXFIDSZ;
	if (vop_fid_pseudo(vp, &fid) != 0) {
		return (0);
	}

	/*
	 * See if vp is in the visible list of the root node exportinfo.
	 */
	for (visp = exi->exi_visible; visp; visp = visp->vis_next) {
		if (EQFID(&fid, &visp->vis_fid)) {
			/*
			 * If vp is an exported non-root node with only 1 path
			 * count (for itself), it indicates no sub-dir shared
			 * using this vp as a path.
			 */
			if (vp_is_exported && visp->vis_count < 2)
				break;

			return (1);
		}
	}

	return (0);
}

/*
 * Returns true if the supplied vnode is visible
 * in this export.  If vnode is visible, return
 * vis_exported in expseudo.
 */
int
nfs_visible(struct exportinfo *exi, vnode_t *vp, int *expseudo)
{
	struct exp_visible *visp;
	fid_t fid;

	/*
	 * First check to see if vp is export root.
	 *
	 * A pseudo export root can never be exported
	 * (it would be a real export then); however,
	 * it is always visible.  If a pseudo root object
	 * was exported by server admin, then the entire
	 * pseudo exportinfo (and all visible entries) would
	 * be destroyed.  A pseudo exportinfo only exists
	 * to provide access to real (descendant) export(s).
	 *
	 * Previously, rootdir was special cased here; however,
	 * the export root special case handles the rootdir
	 * case also.
	 */
	if (VN_CMP(vp, exi->exi_vp)) {
		*expseudo = 0;
		return (1);
	}

	/*
	 * Only a PSEUDO node has a visible list or an exported VROOT
	 * node may have a visible list.
	 */
	if (! PSEUDO(exi) && (exi = get_root_export(exi)) == NULL) {
		*expseudo = 0;
		return (0);
	}

	/* Get the fid of the vnode */

	bzero(&fid, sizeof (fid));
	fid.fid_len = MAXFIDSZ;
	if (vop_fid_pseudo(vp, &fid) != 0) {
		*expseudo = 0;
		return (0);
	}

	/*
	 * We can't trust VN_CMP() above because of LOFS.
	 * Even though VOP_CMP will do the right thing for LOFS
	 * objects, VN_CMP will short circuit out early when the
	 * vnode ops ptrs are different.  Just in case we're dealing
	 * with LOFS, compare exi_fid/fsid here.
	 *
	 * expseudo is not set because this is not an export
	 */
	if (EQFID(&exi->exi_fid, &fid) &&
	    EQFSID(&exi->exi_fsid, &vp->v_vfsp->vfs_fsid)) {
		*expseudo = 0;
		return (1);
	}


	/* See if it matches any fid in the visible list */

	for (visp = exi->exi_visible; visp; visp = visp->vis_next) {
		if (EQFID(&fid, &visp->vis_fid)) {
			*expseudo = visp->vis_exported;
			return (1);
		}
	}

	*expseudo = 0;

	return (0);
}

/*
 * Returns true if the supplied vnode is the
 * directory of an export point.
 */
int
nfs_exported(struct exportinfo *exi, vnode_t *vp)
{
	struct exp_visible *visp;
	fid_t fid;

	/*
	 * First check to see if vp is the export root
	 * This check required for the case of lookup ..
	 * where .. is a V_ROOT vnode and a pseudo exportroot.
	 * Pseudo export root objects do not have an entry
	 * in the visible list even though every V_ROOT
	 * pseudonode is visible.  It is safe to compare
	 * vp here because pseudo_exportfs put a hold on
	 * it when exi_vp was initialized.
	 *
	 * Note: VN_CMP() won't match for LOFS shares, but they're
	 * handled below w/EQFID/EQFSID.
	 */
	if (VN_CMP(vp, exi->exi_vp))
		return (1);

	/* Get the fid of the vnode */

	bzero(&fid, sizeof (fid));
	fid.fid_len = MAXFIDSZ;
	if (vop_fid_pseudo(vp, &fid) != 0)
		return (0);

	if (EQFID(&fid, &exi->exi_fid) &&
	    EQFSID(&vp->v_vfsp->vfs_fsid, &exi->exi_fsid)) {
		return (1);
	}

	/* See if it matches any fid in the visible list */

	for (visp = exi->exi_visible; visp; visp = visp->vis_next) {
		if (EQFID(&fid, &visp->vis_fid))
			return (visp->vis_exported);
	}

	return (0);
}

/*
 * Returns true if the supplied inode is visible
 * in this export.  This function is used by
 * readdir which uses inode numbers from the
 * directory.
 *
 * NOTE: this code does not match inode number for ".",
 * but it isn't required because NFS4 server rddir
 * skips . and .. entries.
 */
int
nfs_visible_inode(struct exportinfo *exi, ino64_t ino, int *expseudo)
{
	struct exp_visible *visp;

	/*
	 * Only a PSEUDO node has a visible list or an exported VROOT
	 * node may have a visible list.
	 */
	if (! PSEUDO(exi) && (exi = get_root_export(exi)) == NULL) {
		*expseudo = 0;
		return (0);
	}

	for (visp = exi->exi_visible; visp; visp = visp->vis_next)
		if ((u_longlong_t)ino == visp->vis_ino) {
			*expseudo = visp->vis_exported;
			return (1);
		}

	*expseudo = 0;
	return (0);
}
