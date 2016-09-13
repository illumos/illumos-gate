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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/systm.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <sys/cmn_err.h>
#include <sys/avl.h>

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
struct exportinfo *
pseudo_exportfs(vnode_t *vp, fid_t *fid, struct exp_visible *vis_head,
	    struct exportdata *exdata)
{
	struct exportinfo *exi;
	struct exportdata *kex;
	fsid_t fsid;
	int vpathlen;
	int i;

	ASSERT(RW_WRITE_HELD(&exported_lock));

	fsid = vp->v_vfsp->vfs_fsid;
	exi = kmem_zalloc(sizeof (*exi), KM_SLEEP);
	exi->exi_fsid = fsid;
	exi->exi_fid = *fid;
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
	 * Initialize auth cache and auth cache lock
	 */
	for (i = 0; i < AUTH_TABLESIZE; i++) {
		exi->exi_cache[i] = kmem_alloc(sizeof (avl_tree_t), KM_SLEEP);
		avl_create(exi->exi_cache[i], nfsauth_cache_clnt_compar,
		    sizeof (struct auth_cache_clnt),
		    offsetof(struct auth_cache_clnt, authc_link));
	}
	rw_init(&exi->exi_cache_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Insert the new entry at the front of the export list
	 */
	export_link(exi);

	return (exi);
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
 * Connects newchild (or subtree with newchild in head)
 * to the parent node. We always add it to the beginning
 * of sibling list.
 */
static void
tree_add_child(treenode_t *parent, treenode_t *newchild)
{
	newchild->tree_parent = parent;
	newchild->tree_sibling = parent->tree_child_first;
	parent->tree_child_first = newchild;
}

/* Look up among direct children a node with the exact tree_vis pointer */
static treenode_t *
tree_find_child_by_vis(treenode_t *t, exp_visible_t *vis)
{
	for (t = t->tree_child_first; t; t = t->tree_sibling)
		if (t->tree_vis == vis)
			return (t);
	return (NULL);
}

/*
 * Add new node to the head of subtree pointed by 'n'. n can be NULL.
 * Interconnects the new treenode with exp_visible and exportinfo
 * if needed.
 */
static treenode_t *
tree_prepend_node(treenode_t *n, exp_visible_t *v, exportinfo_t *e)
{
	treenode_t *tnode = kmem_zalloc(sizeof (*tnode), KM_SLEEP);

	if (n) {
		tnode->tree_child_first = n;
		n->tree_parent = tnode;
	}
	if (v) {
		tnode->tree_vis = v;
	}
	if (e) {
		tnode->tree_exi = e;
		e->exi_tree = tnode;
	}
	return (tnode);
}

/*
 * Removes node from the tree and frees the treenode struct.
 * Does not free structures pointed by tree_exi and tree_vis,
 * they should be already freed.
 */
static void
tree_remove_node(treenode_t *node)
{
	treenode_t *parent = node->tree_parent;
	treenode_t *s; /* s for sibling */

	if (parent == NULL) {
		kmem_free(node, sizeof (*node));
		ns_root = NULL;
		return;
	}
	/* This node is first child */
	if (parent->tree_child_first == node) {
		parent->tree_child_first = node->tree_sibling;
	/* This node is not first child */
	} else {
		s = parent->tree_child_first;
		while (s->tree_sibling != node)
			s = s->tree_sibling;
		s->tree_sibling = s->tree_sibling->tree_sibling;
	}
	kmem_free(node, sizeof (*node));
}

/*
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
 * This example shows that the treenode chain (tree_head) and
 * exp_visible chain (vis_head) can differ in length. The latter
 * can be shorter. The outer loop must loop over the vis_head chain.
 *
 * share /x/a
 * mount -F ufs /dev/dsk/... /x/y
 * mkdir -p /x/y/a/b
 * share  /x/y/a/b
 *
 * When more_visible() is called during the second share,
 * the existing namespace is following:
 *                                   exp_visible_t
 *   treenode_t       exportinfo_t      v0     v1
 * ns_root+---+        +------------+  +---+  +---+
 *      t0| / |........| E0 pseudo  |->| x |->| a |
 *        +---+        +------------+  +---+  +---+
 *          |                           /    /
 *        +---+                        /    /
 *      t1| x |------------------------    /
 *        +---+                           /
 *          |                            /
 *        +---+                         /
 *      t2| a |-------------------------
 *        +---+........+------------+
 *                     | E1 real    |
 *                     +------------+
 *
 * This is being added:
 *
 *    tree_head  vis_head
 *        +---+  +---+
 *      t3| x |->| x |v2
 *        +---+  +---+
 *          |      |
 *        +---+  +---+                     v4     v5
 *      t4| y |->| y |v3  +------------+  +---+  +---+
 *        +---+\ +---+    | E2 pseudo  |->| a |->| b |
 *          |   \....... >+------------+  +---+  +---+
 *        +---+                           /      /
 *      t5| a |---------------------------      /
 *        +---+                                /
 *          |                                 /
 *        +---+-------------------------------
 *      t6| b |           +------------+
 *        +---+..........>| E3 real    |
 *                        +------------+
 *
 * more_visible() will:
 * - kmem_free() t3 and v2
 * - add t4, t5, t6 as a child of t1 (t4 will become sibling of t2)
 * - add v3 to the end of E0->exi_visible
 *
 * Note that v4 and v5 were already processed in pseudo_exportfs() and
 * added to E2. The outer loop of more_visible() will loop only over v2
 * and v3. The inner loop of more_visible() always loops over v0 and v1.
 *
 * Illustration for this scenario:
 *
 * mkdir -p /v/a/b/c
 * share /v/a/b/c
 * mkdir /v/a/b/c1
 * mkdir -p /v/a1
 * mv /v/a/b /v/a1
 * share /v/a1/b/c1
 *
 *           EXISTING
 *           treenode
 *           namespace:    +-----------+   visibles
 *                         |exportinfo |-->v->a->b->c
 * connect_point->+---+--->+-----------+
 *                | / |T0
 *                +---+
 *                  |                            NEW treenode chain:
 *         child->+---+
 *                | v |T1                          +---+<-curr
 *                +---+                          N1| v |
 *                  |                              +---+
 *                +---+                              |
 *                | a |T2                          +---+<-tree_head
 *                +---+                          N2| a1|
 *                  |                              +---+
 *                +---+                              |
 *                | b |T3                          +---+
 *                +---+                          N3| b |
 *                  |                              +---+
 *                +---+                              |
 *                | c |T4                          +---+
 *                +---+                          N4| c1|
 *                                                 +---+
 *
 * The picture above illustrates the position of following pointers after line
 * 'child = tree_find_child_by_vis(connect_point, curr->tree_vis);'
 * was executed for the first time in the outer 'for' loop:
 *
 * connect_point..parent treenode in the EXISTING namespace to which the 'curr'
 *                should be connected. If 'connect_point' already has a child
 *                with the same value of tree_vis as the curr->tree_vis is,
 *                the 'curr' will not be added, but kmem_free()d.
 * child..........the result of tree_find_child_by_vis()
 * curr...........currently processed treenode from the NEW treenode chain
 * tree_head......current head of the NEW treenode chain, in this case it was
 *                already moved down to its child - preparation for another loop
 *
 * What will happen to NEW treenodes N1, N2, N3, N4 in more_visible() later:
 *
 * N1: is merged - i.e. N1 is kmem_free()d. T0 has a child T1 with the same
 *     tree_vis as N1
 * N2: is added as a new child of T1
 *     Note: not just N2, but the whole chain N2->N3->N4 is added
 * N3: not processed separately (it was added together with N2)
 *     Even that N3 and T3 have same tree_vis, they are NOT merged, but will
 *     become duplicates.
 * N4: not processed separately
 */
static void
more_visible(struct exportinfo *exi, treenode_t *tree_head)
{
	struct exp_visible *vp1, *vp2, *vis_head, *tail, *next;
	int found;
	treenode_t *child, *curr, *connect_point;

	vis_head = tree_head->tree_vis;
	connect_point = exi->exi_tree;

	/*
	 * If exportinfo doesn't already have a visible
	 * list just assign the entire supplied list.
	 */
	if (exi->exi_visible == NULL) {
		tree_add_child(exi->exi_tree, tree_head);
		exi->exi_visible = vis_head;
		return;
	}

	/* The outer loop traverses the supplied list. */
	for (vp1 = vis_head; vp1; vp1 = next) {
		found = 0;
		next = vp1->vis_next;

		/* The inner loop searches the exportinfo visible list. */
		for (vp2 = exi->exi_visible; vp2; vp2 = vp2->vis_next) {
			tail = vp2;
			if (EQFID(&vp1->vis_fid, &vp2->vis_fid)) {
				found = 1;
				vp2->vis_count++;
				VN_RELE(vp1->vis_vp);
				/* Transfer vis_exported from vp1 to vp2. */
				if (vp1->vis_exported && !vp2->vis_exported)
					vp2->vis_exported = 1;
				kmem_free(vp1, sizeof (*vp1));
				tree_head->tree_vis = vp2;
				break;
			}
		}

		/* If not found - add to the end of the list */
		if (! found) {
			tail->vis_next = vp1;
			vp1->vis_next = NULL;
		}

		curr = tree_head;
		tree_head = tree_head->tree_child_first;

		if (! connect_point) /* No longer merging */
			continue;
		/*
		 * The inner loop could set curr->tree_vis to the EXISTING
		 * exp_visible vp2, so we can search among the children of
		 * connect_point for the curr->tree_vis. No need for EQFID.
		 */
		child = tree_find_child_by_vis(connect_point, curr->tree_vis);

		/*
		 * Merging cannot be done if a valid child->tree_exi would
		 * be overwritten by a new curr->tree_exi.
		 */
		if (child &&
		    (child->tree_exi == NULL || curr->tree_exi == NULL)) {
			if (curr->tree_exi) { /* Transfer the exportinfo */
				child->tree_exi = curr->tree_exi;
				child->tree_exi->exi_tree = child;
			}
			kmem_free(curr, sizeof (treenode_t));
			connect_point = child;
		} else { /* Branching */
			tree_add_child(connect_point, curr);
			connect_point = NULL;
		}
	}
}

/*
 * Remove one visible entry from the pseudo exportfs.
 *
 * When we unexport a directory, we have to remove path
 * components from the visible list in the pseudo exportfs
 * entry. The supplied visible contains one fid of one path
 * component. The visible list of the export
 * is checked against provided visible, matching fid has its
 * reference count decremented.  If a reference count drops to
 * zero, then it means no paths now use this directory, so its
 * fid can be removed from the visible list.
 *
 * When the last path is removed, the visible list will be null.
 */
static void
less_visible(struct exportinfo *exi, struct exp_visible *vp1)
{
	struct exp_visible *vp2;
	struct exp_visible *prev, *next;

	for (vp2 = exi->exi_visible, prev = NULL; vp2; vp2 = next) {

		next = vp2->vis_next;

		if (vp1 == vp2) {
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
			}
			break;
		}
		prev = vp2;
	}
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
	struct exportinfo *new_exi = exip;
	struct exp_visible *visp;
	struct exp_visible *vis_head = NULL;
	struct vattr va;
	treenode_t *tree_head = NULL;

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
				more_visible(exi, tree_head);
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
				new_exi = pseudo_exportfs(vp, &fid, vis_head,
				    NULL);
				vis_head = NULL;
			}

			if (VN_CMP(vp, rootdir)) {
				/* at system root */
				/*
				 * If sharing "/", new_exi is shared exportinfo
				 * (exip). Otherwise, new_exi is exportinfo
				 * created in pseudo_exportfs() above.
				 */
				ns_root = tree_prepend_node(tree_head, 0,
				    new_exi);
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
		 * Will set treenode's pointer to exportinfo to
		 * 1. shared exportinfo (exip) - if first visit here
		 * 2. freshly allocated pseudo export (if any)
		 * 3. null otherwise
		 */
		tree_head = tree_prepend_node(tree_head, visp, new_exi);
		new_exi = NULL;

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

	/*
	 * We can have set error due to error in:
	 * 1. vop_fid_pseudo()
	 * 2. VOP_GETATTR()
	 * 3. VOP_LOOKUP()
	 * We must free pseudo exportinfos, visibles and treenodes.
	 * Visibles are referenced from treenode_t::tree_vis and
	 * exportinfo_t::exi_visible. To avoid double freeing, only
	 * exi_visible pointer is used, via exi_rele(), for the clean-up.
	 */
	if (error) {
		/* Free unconnected visibles, if there are any. */
		if (vis_head)
			free_visible(vis_head);

		/* Connect unconnected exportinfo, if there is any. */
		if (new_exi && new_exi != exip)
			tree_head = tree_prepend_node(tree_head, 0, new_exi);

		while (tree_head) {
			treenode_t *t2 = tree_head;
			exportinfo_t *e  = tree_head->tree_exi;
			/* exip will be freed in exportfs() */
			if (e && e != exip) {
				export_unlink(e);
				exi_rele(e);
			}
			tree_head = tree_head->tree_child_first;
			kmem_free(t2, sizeof (*t2));
		}
	}

	return (error);
}

/*
 * Walk up the tree and:
 * 1. release pseudo exportinfo if it has no child
 * 2. release visible in parent's exportinfo
 * 3. delete non-exported leaf nodes from tree
 *
 * Deleting of nodes will start only if the unshared
 * node was a leaf node.
 * Deleting of nodes will finish when we reach a node which
 * has children or is a real export, then we might still need
 * to continue releasing visibles, until we reach VROOT node.
 */
void
treeclimb_unexport(struct exportinfo *exip)
{
	treenode_t *tnode, *old_nd;

	ASSERT(RW_WRITE_HELD(&exported_lock));

	tnode = exip->exi_tree;
	/*
	 * The unshared exportinfo was unlinked in unexport().
	 * Zeroing tree_exi ensures that we will skip it.
	 */
	tnode->tree_exi = NULL;

	if (tnode->tree_vis) /* system root has tree_vis == NULL */
		tnode->tree_vis->vis_exported = 0;

	while (tnode) {

		/* Stop at VROOT node which is exported or has child */
		if (TREE_ROOT(tnode) &&
		    (TREE_EXPORTED(tnode) || tnode->tree_child_first))
			break;

		/* Release pseudo export if it has no child */
		if (TREE_ROOT(tnode) && !TREE_EXPORTED(tnode) &&
		    tnode->tree_child_first == 0) {
			export_unlink(tnode->tree_exi);
			exi_rele(tnode->tree_exi);
		}

		/* Release visible in parent's exportinfo */
		if (tnode->tree_vis)
			less_visible(vis2exi(tnode), tnode->tree_vis);

		/* Continue with parent */
		old_nd = tnode;
		tnode = tnode->tree_parent;

		/* Remove itself, if this is a leaf and non-exported node */
		if (old_nd->tree_child_first == NULL && !TREE_EXPORTED(old_nd))
			tree_remove_node(old_nd);
	}
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
	treenode_t *tnode = exip->exi_tree;
	exportinfo_t *exi = NULL;

	while (tnode) {
		if (TREE_ROOT(tnode)) {
			exi = tnode->tree_exi;
			break;
		}
		tnode = tnode->tree_parent;
	}
	ASSERT(exi);
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
	exi = get_root_export(exi);

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
	if (! PSEUDO(exi))
		exi = get_root_export(exi);

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
	if (! PSEUDO(exi))
		exi = get_root_export(exi);

	for (visp = exi->exi_visible; visp; visp = visp->vis_next)
		if ((u_longlong_t)ino == visp->vis_ino) {
			*expseudo = visp->vis_exported;
			return (1);
		}

	*expseudo = 0;
	return (0);
}
