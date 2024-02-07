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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2022-2023 RackTop Systems, Inc.
 */
/*
 * SMB Node State Machine
 * ----------------------
 *
 *
 *		    +----------- Creation/Allocation
 *		    |
 *		    | T0
 *		    |
 *		    v
 *    +----------------------------+
 *    |  SMB_NODE_STATE_AVAILABLE  |
 *    +----------------------------+
 *		    |
 *		    | T1
 *		    |
 *		    v
 *    +-----------------------------+
 *    |  SMB_NODE_STATE_DESTROYING  |
 *    +-----------------------------+
 *		    |
 *		    |
 *		    | T2
 *		    |
 *		    +----------> Deletion/Free
 *
 * Transition T0
 *
 *    This transition occurs in smb_node_lookup(). If the node looked for is
 *    not found in the has table a new node is created. The reference count is
 *    initialized to 1 and the state initialized to SMB_NODE_STATE_AVAILABLE.
 *
 * Transition T1
 *
 *    This transition occurs in smb_node_release(). If the reference count
 *    drops to zero the state is moved to SMB_NODE_STATE_DESTROYING and no more
 *    reference count will be given out for that node.
 *
 * Transition T2
 *
 *    This transition occurs in smb_node_release(). The structure is deleted.
 *
 * Comments
 * --------
 *
 *    The reason the smb node has 2 states is the following synchronization
 *    rule:
 *
 *    There's a mutex embedded in the node used to protect its fields and
 *    there's a lock embedded in the bucket of the hash table the node belongs
 *    to. To increment or to decrement the reference count the mutex must be
 *    entered. To insert the node into the bucket and to remove it from the
 *    bucket the lock must be entered in RW_WRITER mode. When both (mutex and
 *    lock) have to be entered, the lock has always to be entered first then
 *    the mutex. This prevents a deadlock between smb_node_lookup() and
 *    smb_node_release() from occurring. However, in smb_node_release() when the
 *    reference count drops to zero and triggers the deletion of the node, the
 *    mutex has to be released before entering the lock of the bucket (to
 *    remove the node). This creates a window during which the node that is
 *    about to be freed could be given out by smb_node_lookup(). To close that
 *    window the node is moved to the state SMB_NODE_STATE_DESTROYING before
 *    releasing the mutex. That way, even if smb_node_lookup() finds it, the
 *    state will indicate that the node should be treated as non existent (of
 *    course the state of the node should be tested/updated under the
 *    protection of the mutex).
 */
#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_kstat.h>
#include <sys/ddi.h>
#include <sys/extdirent.h>
#include <sys/pathname.h>
#include <sys/sdt.h>
#include <sys/nbmlock.h>
#include <fs/fs_reparse.h>

/* Todo: move this to sys/time.h */
#ifndef	timespeccmp
#define	timespeccmp(tvp, uvp, cmp)				\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?			\
	((tvp)->tv_nsec cmp (uvp)->tv_nsec) :			\
	((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

uint32_t smb_is_executable(char *);
static void smb_node_create_audit_buf(smb_node_t *, int);
static void smb_node_destroy_audit_buf(smb_node_t *);
static void smb_node_audit(smb_node_t *);
static smb_node_t *smb_node_alloc(char *, vnode_t *, smb_llist_t *, uint32_t);
static void smb_node_free(smb_node_t *);
static int smb_node_constructor(void *, void *, int);
static void smb_node_destructor(void *, void *);
static smb_llist_t *smb_node_get_hash(fsid_t *, smb_attr_t *, uint32_t *);

static void smb_node_init_reparse(smb_node_t *, smb_attr_t *);
static void smb_node_init_system(smb_node_t *);

#define	VALIDATE_DIR_NODE(_dir_, _node_) \
    ASSERT((_dir_)->n_magic == SMB_NODE_MAGIC); \
    ASSERT(((_dir_)->vp->v_xattrdir) || ((_dir_)->vp->v_type == VDIR)); \
    ASSERT((_dir_)->n_dnode != (_node_));

/* round sz to DEV_BSIZE block */
#define	SMB_ALLOCSZ(sz)	(((sz) + DEV_BSIZE-1) & ~(DEV_BSIZE-1))

static kmem_cache_t	*smb_node_cache = NULL;
static smb_llist_t	smb_node_hash_table[SMBND_HASH_MASK+1];
static smb_node_t	*smb_root_node;

/*
 * smb_node_init
 *
 * Initialization of the SMB node layer.
 *
 * This function is not multi-thread safe. The caller must make sure only one
 * thread makes the call.
 */
void
smb_node_init(void)
{
	smb_attr_t	attr;
	smb_llist_t	*node_hdr;
	smb_node_t	*node;
	uint32_t	hashkey;
	int		i;

	if (smb_node_cache != NULL)
		return;

	smb_node_cache = kmem_cache_create(SMBSRV_KSTAT_NODE_CACHE,
	    sizeof (smb_node_t), 8, smb_node_constructor, smb_node_destructor,
	    NULL, NULL, NULL, 0);

	for (i = 0; i <= SMBND_HASH_MASK; i++) {
		smb_llist_constructor(&smb_node_hash_table[i],
		    sizeof (smb_node_t), offsetof(smb_node_t, n_lnd));
	}

	/*
	 * The node cache is shared by all zones, so the smb_root_node
	 * must represent the real (global zone) rootdir.
	 * Note intentional use of kcred here.
	 */
	attr.sa_mask = SMB_AT_ALL;
	VERIFY0(smb_vop_getattr(rootdir, NULL, &attr, 0, kcred));
	node_hdr = smb_node_get_hash(&rootdir->v_vfsp->vfs_fsid, &attr,
	    &hashkey);
	node = smb_node_alloc("/", rootdir, node_hdr, hashkey);
	smb_llist_enter(node_hdr, RW_WRITER);
	smb_llist_insert_head(node_hdr, node);
	smb_llist_exit(node_hdr);
	smb_root_node = node;	/* smb_node_release in smb_node_fini */
}

/*
 * smb_node_fini
 *
 * This function is not multi-thread safe. The caller must make sure only one
 * thread makes the call.
 */
void
smb_node_fini(void)
{
	int	i;

	if (smb_root_node != NULL) {
		smb_node_release(smb_root_node);
		smb_root_node = NULL;
	}

	if (smb_node_cache == NULL)
		return;

	for (i = 0; i <= SMBND_HASH_MASK; i++) {
		smb_llist_t	*bucket;
		smb_node_t	*node;

		/*
		 * The SMB node hash table should be empty at this point.
		 * If the hash table is not empty, clean it up.
		 *
		 * The reason why SMB nodes might remain in this table is
		 * generally forgotten references somewhere, perhaps on
		 * open files, etc.  Those are defects.
		 */
		bucket = &smb_node_hash_table[i];
		node = smb_llist_head(bucket);
		while (node != NULL) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "leaked node: 0x%p %s",
			    (void *)node, node->od_name);
			cmn_err(CE_NOTE, "...bucket: 0x%p", bucket);
			debug_enter("leaked_node");
#endif
			smb_llist_remove(bucket, node);
			node = smb_llist_head(bucket);
		}
	}

	for (i = 0; i <= SMBND_HASH_MASK; i++) {
		smb_llist_destructor(&smb_node_hash_table[i]);
	}
	kmem_cache_destroy(smb_node_cache);
	smb_node_cache = NULL;
}

/*
 * smb_node_lookup()
 *
 * NOTE: This routine should only be called by the file system interface layer,
 * and not by SMB.
 *
 * smb_node_lookup() is called upon successful lookup, mkdir, and create
 * (for both non-streams and streams).  In each of these cases, a held vnode is
 * passed into this routine.  If a new smb_node is created it will take its
 * own hold on the vnode.  The caller's hold therefore still belongs to, and
 * should be released by, the caller.
 *
 * A reference is taken on the smb_node whether found in the hash table
 * or newly created.
 *
 * If an smb_node needs to be created, a reference is also taken on the
 * dnode (if passed in).
 *
 * See smb_node_release() for details on the release of these references.
 */

/*ARGSUSED*/
smb_node_t *
smb_node_lookup(
    struct smb_request	*sr,
    struct open_param	*op,
    cred_t		*cred,
    vnode_t		*vp,
    char		*od_name,
    smb_node_t		*dnode,
    smb_node_t		*unode)
{
	smb_llist_t		*node_hdr;
	smb_node_t		*node;
	smb_attr_t		attr;
	uint32_t		hashkey = 0;
	fsid_t			fsid;
	int			error;
	krw_t			lock_mode;
	vnode_t			*unnamed_vp = NULL;

	/*
	 * smb_vop_getattr() is called here instead of smb_fsop_getattr(),
	 * because the node may not yet exist.  We also do not want to call
	 * it with the list lock held.
	 */

	if (unode)
		unnamed_vp = unode->vp;

	/*
	 * This getattr is performed on behalf of the server
	 * that's why kcred is used not the user's cred
	 */
	attr.sa_mask = SMB_AT_ALL;
	error = smb_vop_getattr(vp, unnamed_vp, &attr, 0, zone_kcred());
	if (error)
		return (NULL);

	if (sr && sr->tid_tree) {
		/*
		 * The fsid for a file is that of the tree, even
		 * if the file resides in a different mountpoint
		 * under the share.
		 */
		fsid = SMB_TREE_FSID(sr->tid_tree);
	} else {
		/*
		 * This should be getting executed only for the
		 * tree root smb_node.
		 */
		fsid = vp->v_vfsp->vfs_fsid;
	}

	node_hdr = smb_node_get_hash(&fsid, &attr, &hashkey);
	lock_mode = RW_READER;

	smb_llist_enter(node_hdr, lock_mode);
	for (;;) {
		node = list_head(&node_hdr->ll_list);
		while (node) {
			ASSERT(node->n_magic == SMB_NODE_MAGIC);
			ASSERT(node->n_hash_bucket == node_hdr);
			if ((node->n_hashkey == hashkey) && (node->vp == vp)) {
				mutex_enter(&node->n_mutex);
				DTRACE_PROBE1(smb_node_lookup_hit,
				    smb_node_t *, node);
				switch (node->n_state) {
				case SMB_NODE_STATE_AVAILABLE:
					/* The node was found. */
					node->n_refcnt++;
					if ((node->n_dnode == NULL) &&
					    (dnode != NULL) &&
					    (node != dnode) &&
					    (strcmp(od_name, "..") != 0) &&
					    (strcmp(od_name, ".") != 0)) {
						VALIDATE_DIR_NODE(dnode, node);
						node->n_dnode = dnode;
						smb_node_ref(dnode);
					}

					smb_node_audit(node);
					mutex_exit(&node->n_mutex);
					smb_llist_exit(node_hdr);
					return (node);

				case SMB_NODE_STATE_DESTROYING:
					/*
					 * Although the node exists it is about
					 * to be destroyed. We act as it hasn't
					 * been found.
					 */
					mutex_exit(&node->n_mutex);
					break;
				default:
					/*
					 * Although the node exists it is in an
					 * unknown state. We act as it hasn't
					 * been found.
					 */
					ASSERT(0);
					mutex_exit(&node->n_mutex);
					break;
				}
			}
			node = smb_llist_next(node_hdr, node);
		}
		if ((lock_mode == RW_READER) && smb_llist_upgrade(node_hdr)) {
			lock_mode = RW_WRITER;
			continue;
		}
		break;
	}
	node = smb_node_alloc(od_name, vp, node_hdr, hashkey);
	smb_node_init_reparse(node, &attr);

	if (op)
		node->flags |= smb_is_executable(op->fqi.fq_last_comp);

	if (dnode) {
		smb_node_ref(dnode);
		node->n_dnode = dnode;
		ASSERT(dnode->n_dnode != node);
		ASSERT((dnode->vp->v_xattrdir) ||
		    (dnode->vp->v_type == VDIR));
	}

	if (unode) {
		smb_node_ref(unode);
		node->n_unode = unode;
	}

	smb_node_init_system(node);

	DTRACE_PROBE1(smb_node_lookup_miss, smb_node_t *, node);
	smb_node_audit(node);
	smb_llist_insert_head(node_hdr, node);
	smb_llist_exit(node_hdr);
	return (node);
}

/*
 * smb_stream_node_lookup()
 *
 * Note: stream_name (the name that will be stored in the "od_name" field
 * of a stream's smb_node) is the same as the on-disk name for the stream
 * except that it does not have SMB_STREAM_PREFIX prepended.
 */

smb_node_t *
smb_stream_node_lookup(smb_request_t *sr, cred_t *cr, smb_node_t *fnode,
    vnode_t *xattrdirvp, vnode_t *vp, char *stream_name)
{
	smb_node_t	*xattrdir_node;
	smb_node_t	*snode;

	xattrdir_node = smb_node_lookup(sr, NULL, cr, xattrdirvp, XATTR_DIR,
	    fnode, NULL);

	if (xattrdir_node == NULL)
		return (NULL);

	snode = smb_node_lookup(sr, NULL, cr, vp, stream_name, xattrdir_node,
	    fnode);

	(void) smb_node_release(xattrdir_node);
	return (snode);
}


/*
 * This function should be called whenever a reference is needed on an
 * smb_node pointer.  The copy of an smb_node pointer from one non-local
 * data structure to another requires a reference to be taken on the smb_node
 * (unless the usage is localized).  Each data structure deallocation routine
 * will call smb_node_release() on its smb_node pointers.
 *
 * In general, an smb_node pointer residing in a structure should never be
 * stale.  A node pointer may be NULL, however, and care should be taken
 * prior to calling smb_node_ref(), which ASSERTs that the pointer is valid.
 * Care also needs to be taken with respect to racing deallocations of a
 * structure.
 */
void
smb_node_ref(smb_node_t *node)
{
	SMB_NODE_VALID(node);

	mutex_enter(&node->n_mutex);
	switch (node->n_state) {
	case SMB_NODE_STATE_AVAILABLE:
		node->n_refcnt++;
		ASSERT(node->n_refcnt);
		DTRACE_PROBE1(smb_node_ref_exit, smb_node_t *, node);
		smb_node_audit(node);
		break;
	default:
		SMB_PANIC();
	}
	mutex_exit(&node->n_mutex);
}

/*
 * smb_node_lookup() takes a hold on an smb_node, whether found in the
 * hash table or newly created.  This hold is expected to be released
 * in the following manner.
 *
 * smb_node_lookup() takes an address of an smb_node pointer.  This should
 * be getting passed down via a lookup (whether path name or component), mkdir,
 * create.  If the original smb_node pointer resides in a data structure, then
 * the deallocation routine for the data structure is responsible for calling
 * smb_node_release() on the smb_node pointer.  Alternatively,
 * smb_node_release() can be called as soon as the smb_node pointer is no longer
 * needed.  In this case, callers are responsible for setting an embedded
 * pointer to NULL if it is known that the last reference is being released.
 *
 * If the passed-in address of the smb_node pointer belongs to a local variable,
 * then the caller with the local variable should call smb_node_release()
 * directly.
 *
 * smb_node_release() itself will call smb_node_release() on a node's n_dnode,
 * as smb_node_lookup() takes a hold on dnode.
 */
void
smb_node_release(smb_node_t *node)
{
	SMB_NODE_VALID(node);

	mutex_enter(&node->n_mutex);
	ASSERT(node->n_refcnt);
	DTRACE_PROBE1(smb_node_release, smb_node_t *, node);
	if (--node->n_refcnt == 0) {
		switch (node->n_state) {

		case SMB_NODE_STATE_AVAILABLE:
			node->n_state = SMB_NODE_STATE_DESTROYING;

			/*
			 * While we still hold n_mutex,
			 * make sure FEM hooks are gone.
			 */
			if (node->n_fcn_count > 0) {
				DTRACE_PROBE1(fem__fcn__dangles,
				    smb_node_t *, node);
				node->n_fcn_count = 0;
				(void) smb_fem_fcn_uninstall(node);
			}

			mutex_exit(&node->n_mutex);

			/*
			 * Out of caution, make sure FEM hooks
			 * used by oplocks are also gone.
			 */
			mutex_enter(&node->n_oplock.ol_mutex);
			ASSERT(node->n_oplock.ol_fem == B_FALSE);
			if (node->n_oplock.ol_fem == B_TRUE) {
				smb_fem_oplock_uninstall(node);
				node->n_oplock.ol_fem = B_FALSE;
			}
			mutex_exit(&node->n_oplock.ol_mutex);

			smb_llist_enter(node->n_hash_bucket, RW_WRITER);
			smb_llist_remove(node->n_hash_bucket, node);
			smb_llist_exit(node->n_hash_bucket);

			/*
			 * Check if the file was deleted
			 */
			if (node->flags & NODE_FLAGS_DELETE_ON_CLOSE) {
				smb_node_delete_on_close(node);
			}

			if (node->n_dnode) {
				ASSERT(node->n_dnode->n_magic ==
				    SMB_NODE_MAGIC);
				smb_node_release(node->n_dnode);
			}

			if (node->n_unode) {
				ASSERT(node->n_unode->n_magic ==
				    SMB_NODE_MAGIC);
				smb_node_release(node->n_unode);
			}

			smb_node_free(node);
			return;

		default:
			SMB_PANIC();
		}
	}
	smb_node_audit(node);
	mutex_exit(&node->n_mutex);
}

void
smb_node_delete_on_close(smb_node_t *node)
{
	smb_node_t	*d_snode;
	int		rc = 0;
	uint32_t	flags = 0;

	d_snode = node->n_dnode;

	ASSERT((node->flags & NODE_FLAGS_DELETE_ON_CLOSE) != 0);

	node->flags &= ~NODE_FLAGS_DELETE_ON_CLOSE;
	node->flags |= NODE_FLAGS_DELETE_COMMITTED;
	flags = node->n_delete_on_close_flags;
	ASSERT(node->od_name != NULL);

	if (smb_node_is_dir(node))
		rc = smb_fsop_rmdir(0, node->delete_on_close_cred,
		    d_snode, node->od_name, flags);
	else
		rc = smb_fsop_remove(0, node->delete_on_close_cred,
		    d_snode, node->od_name, flags);
	crfree(node->delete_on_close_cred);
	node->delete_on_close_cred = NULL;

	if (rc != 0)
		cmn_err(CE_WARN, "File %s could not be removed, rc=%d\n",
		    node->od_name, rc);
	DTRACE_PROBE2(smb_node_delete_on_close, int, rc, smb_node_t *, node);
}

/*
 * smb_node_rename()
 *
 */
void
smb_node_rename(
    smb_node_t	*from_dnode,
    smb_node_t	*ret_node,
    smb_node_t	*to_dnode,
    char	*to_name)
{
	SMB_NODE_VALID(from_dnode);
	SMB_NODE_VALID(to_dnode);
	SMB_NODE_VALID(ret_node);

	smb_node_ref(to_dnode);
	mutex_enter(&ret_node->n_mutex);
	switch (ret_node->n_state) {
	case SMB_NODE_STATE_AVAILABLE:
		ret_node->n_dnode = to_dnode;
		mutex_exit(&ret_node->n_mutex);
		ASSERT(to_dnode->n_dnode != ret_node);
		ASSERT((to_dnode->vp->v_xattrdir) ||
		    (to_dnode->vp->v_type == VDIR));
		smb_node_release(from_dnode);
		(void) strcpy(ret_node->od_name, to_name);
		/*
		 * XXX Need to update attributes?
		 */
		break;
	default:
		SMB_PANIC();
	}
}

/*
 * Find/create an SMB node for the root of this zone and store it
 * in *svrootp.  Also create nodes leading to this directory.
 */
int
smb_node_root_init(smb_server_t *sv, smb_node_t **svrootp)
{
	zone_t		*zone = curzone;
	int		error;

	ASSERT(zone->zone_id == sv->sv_zid);
	if (smb_root_node == NULL)
		return (ENOENT);

	/*
	 * We're getting smb nodes below the zone root here,
	 * so need to use kcred, not zone_kcred().
	 */
	error = smb_pathname(NULL, zone->zone_rootpath, 0,
	    smb_root_node, smb_root_node, NULL, svrootp, kcred, NULL);

	return (error);
}

/*
 * Helper function for smb_node_set_delete_on_close(). Assumes node is a dir.
 * Return 0 if this is an empty dir. Otherwise return a NT_STATUS code.
 * Unfortunately, to find out if a directory is empty, we have to read it
 * and check for anything other than "." or ".." in the readdir buf.
 */
static uint32_t
smb_rmdir_possible(smb_node_t *n)
{
	ASSERT(n->vp->v_type == VDIR);
	char *buf;
	char *bufptr;
	struct dirent64	*dp;
	uint32_t status = NT_STATUS_SUCCESS;
	int bsize = SMB_ODIR_BUFSIZE;
	int eof = 0;

	buf = kmem_alloc(SMB_ODIR_BUFSIZE, KM_SLEEP);

	/* Flags zero: no edirent, no ABE wanted here */
	if (smb_vop_readdir(n->vp, 0, buf, &bsize, &eof, 0, zone_kcred())) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	bufptr = buf;
	while (bsize > 0) {
		/* LINTED pointer alignment */
		dp = (struct dirent64 *)bufptr;

		bufptr += dp->d_reclen;
		bsize  -= dp->d_reclen;
		if (bsize < 0) {
			/* partial record */
			status = NT_STATUS_DIRECTORY_NOT_EMPTY;
			break;
		}

		if (strcmp(dp->d_name, ".") != 0 &&
		    strcmp(dp->d_name, "..") != 0) {
			status = NT_STATUS_DIRECTORY_NOT_EMPTY;
			break;
		}
	}

out:
	kmem_free(buf, SMB_ODIR_BUFSIZE);
	return (status);
}

/*
 * When DeleteOnClose is set on an smb_node, the common open code will
 * reject subsequent open requests for the file. Observation of Windows
 * 2000 indicates that subsequent opens should be allowed (assuming
 * there would be no sharing violation) until the file is closed using
 * the fid on which the DeleteOnClose was requested.
 *
 * If there are multiple opens with delete-on-close create options,
 * whichever the first file handle is closed will trigger the node to be
 * marked as delete-on-close. The credentials of that ofile will be used
 * as the delete-on-close credentials of the node.
 *
 * Note that "read-only" tests have already happened before this call.
 */
uint32_t
smb_node_set_delete_on_close(smb_node_t *node, cred_t *cr, uint32_t flags)
{
	uint32_t status;

	/*
	 * If the directory is not empty we should fail setting del-on-close
	 * with STATUS_DIRECTORY_NOT_EMPTY. see MS's
	 * "File System Behavior Overview" doc section 4.3.2
	 */
	if (smb_node_is_dir(node)) {
		status = smb_rmdir_possible(node);
		if (status != 0) {
			return (status);
		}
	}

	/* Dataset roots can't be deleted, so don't set DOC */
	if ((node->flags & NODE_FLAGS_VFSROOT) != 0) {
		return (NT_STATUS_CANNOT_DELETE);
	}

	mutex_enter(&node->n_mutex);
	if (node->flags & NODE_FLAGS_DELETE_ON_CLOSE) {
		/* It was already marked.  We're done. */
		mutex_exit(&node->n_mutex);
		return (NT_STATUS_SUCCESS);
	}

	crhold(cr);
	node->delete_on_close_cred = cr;
	node->n_delete_on_close_flags = flags;
	node->flags |= NODE_FLAGS_DELETE_ON_CLOSE;
	mutex_exit(&node->n_mutex);

	/*
	 * Tell any change notify calls to close their handles
	 * and get out of the way.  FILE_ACTION_DELETE_PENDING
	 * is a special, internal-only action for this purpose.
	 */
	smb_node_notify_change(node, FILE_ACTION_DELETE_PENDING, NULL);

	return (NT_STATUS_SUCCESS);
}

void
smb_node_reset_delete_on_close(smb_node_t *node)
{
	mutex_enter(&node->n_mutex);
	if (node->flags & NODE_FLAGS_DELETE_ON_CLOSE) {
		node->flags &= ~NODE_FLAGS_DELETE_ON_CLOSE;
		crfree(node->delete_on_close_cred);
		node->delete_on_close_cred = NULL;
		node->n_delete_on_close_flags = 0;
	}
	mutex_exit(&node->n_mutex);
}

/*
 * smb_node_open_check
 *
 * check file sharing rules for current open request
 * against all existing opens for a file.
 *
 * Returns NT_STATUS_SHARING_VIOLATION if there is any
 * sharing conflict, otherwise returns NT_STATUS_SUCCESS.
 */
uint32_t
smb_node_open_check(smb_node_t *node, uint32_t desired_access,
    uint32_t share_access)
{
	smb_ofile_t *of;
	uint32_t status;

	SMB_NODE_VALID(node);

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	of = smb_llist_head(&node->n_ofile_list);
	while (of) {
		status = smb_ofile_open_check(of, desired_access, share_access);

		switch (status) {
		case NT_STATUS_INVALID_HANDLE:
		case NT_STATUS_SUCCESS:
			of = smb_llist_next(&node->n_ofile_list, of);
			break;
		default:
			ASSERT(status == NT_STATUS_SHARING_VIOLATION);
			DTRACE_PROBE3(conflict3,
			    smb_ofile_t *, of,
			    uint32_t, desired_access,
			    uint32_t, share_access);
			smb_llist_exit(&node->n_ofile_list);
			return (status);
		}
	}

	smb_llist_exit(&node->n_ofile_list);
	return (NT_STATUS_SUCCESS);
}

uint32_t
smb_node_rename_check(smb_node_t *node)
{
	smb_ofile_t	*of;
	uint32_t	status;

	SMB_NODE_VALID(node);

	/*
	 * Intra-CIFS check
	 */
	smb_llist_enter(&node->n_ofile_list, RW_READER);
	of = smb_llist_head(&node->n_ofile_list);
	while (of) {
		status = smb_ofile_rename_check(of);

		switch (status) {
		case NT_STATUS_INVALID_HANDLE:
		case NT_STATUS_SUCCESS:
			of = smb_llist_next(&node->n_ofile_list, of);
			break;
		default:
			ASSERT(status == NT_STATUS_SHARING_VIOLATION);
			DTRACE_PROBE1(conflict1, smb_ofile_t *, of);
			smb_llist_exit(&node->n_ofile_list);
			return (status);
		}
	}
	smb_llist_exit(&node->n_ofile_list);
	return (NT_STATUS_SUCCESS);
}

uint32_t
smb_node_delete_check(smb_node_t *node)
{
	smb_ofile_t	*of;
	uint32_t	status;

	SMB_NODE_VALID(node);

	if (smb_node_is_dir(node))
		return (NT_STATUS_SUCCESS);

	if (smb_node_is_reparse(node))
		return (NT_STATUS_ACCESS_DENIED);

	/*
	 * intra-CIFS check
	 */
	smb_llist_enter(&node->n_ofile_list, RW_READER);
	of = smb_llist_head(&node->n_ofile_list);
	while (of) {
		status = smb_ofile_delete_check(of);

		switch (status) {
		case NT_STATUS_INVALID_HANDLE:
		case NT_STATUS_SUCCESS:
			of = smb_llist_next(&node->n_ofile_list, of);
			break;
		default:
			ASSERT(status == NT_STATUS_SHARING_VIOLATION);
			DTRACE_PROBE1(conflict1, smb_ofile_t *, of);
			smb_llist_exit(&node->n_ofile_list);
			return (status);
		}
	}
	smb_llist_exit(&node->n_ofile_list);
	return (NT_STATUS_SUCCESS);
}

/*
 * smb_node_share_check
 *
 * Returns: TRUE    - ofiles have non-zero share access
 *          B_FALSE - ofile with share access NONE.
 */
boolean_t
smb_node_share_check(smb_node_t *node)
{
	smb_ofile_t	*of;
	boolean_t	status = B_TRUE;

	SMB_NODE_VALID(node);

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	of = smb_llist_head(&node->n_ofile_list);
	if (of)
		status = smb_ofile_share_check(of);
	smb_llist_exit(&node->n_ofile_list);

	return (status);
}

/*
 * SMB Change Notification
 */

void
smb_node_fcn_subscribe(smb_node_t *node)
{

	mutex_enter(&node->n_mutex);
	if (node->n_fcn_count == 0)
		(void) smb_fem_fcn_install(node);
	node->n_fcn_count++;
	mutex_exit(&node->n_mutex);
}

void
smb_node_fcn_unsubscribe(smb_node_t *node)
{

	mutex_enter(&node->n_mutex);
	node->n_fcn_count--;
	if (node->n_fcn_count == 0) {
		VERIFY0(smb_fem_fcn_uninstall(node));
	}
	mutex_exit(&node->n_mutex);
}

void
smb_node_notify_change(smb_node_t *node, uint_t action, const char *name)
{
	smb_ofile_t	*of;

	SMB_NODE_VALID(node);

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	of = smb_llist_head(&node->n_ofile_list);
	while (of) {
		/*
		 * We'd rather deliver events only to ofiles that have
		 * subscribed.  There's no explicit synchronization with
		 * where this flag is set, but other actions cause this
		 * value to reach visibility soon enough for events to
		 * start arriving by the time we need them to start.
		 * Once nc_subscribed is set, it stays set for the
		 * life of the ofile.
		 */
		if (of->f_notify.nc_subscribed)
			smb_notify_ofile(of, action, name);
		of = smb_llist_next(&node->n_ofile_list, of);
	}
	smb_llist_exit(&node->n_ofile_list);

	/*
	 * After changes that add or remove a name,
	 * we know the directory attributes changed,
	 * and we can tell the immediate parent.
	 */
	switch (action) {
	case FILE_ACTION_ADDED:
	case FILE_ACTION_REMOVED:
	case FILE_ACTION_RENAMED_NEW_NAME:
		/*
		 * Note: FILE_ACTION_RENAMED_OLD_NAME is intentionally
		 * omitted, because it's always followed by another
		 * event with FILE_ACTION_RENAMED_NEW_NAME posted to
		 * the same directory, and we only need/want one.
		 */
		if (node->n_dnode != NULL) {
			smb_node_notify_change(node->n_dnode,
			    FILE_ACTION_MODIFIED, node->od_name);
		}
		break;
	}

	/*
	 * If we wanted to support recursive notify events
	 * (where a notify call on some directory receives
	 * events from all objects below that directory),
	 * we might deliver _SUBDIR_CHANGED to all our
	 * parents, grandparents etc, here.  However, we
	 * don't currently subscribe to changes on all the
	 * child (and grandchild) objects that would be
	 * needed to make that work. It's prohibitively
	 * expensive to do that, and support for recursive
	 * notify is optional anyway, so don't bother.
	 */
}

/*
 * Change notify modified differs for stream vs regular file.
 * Changes to a stream give a notification on the "unnamed" node,
 * which is the parent object of the stream.
 */
void
smb_node_notify_modified(smb_node_t *node)
{
	smb_node_t *u_node;

	u_node = SMB_IS_STREAM(node);
	if (u_node != NULL) {
		/* This is a named stream */
		if (u_node->n_dnode != NULL) {
			smb_node_notify_change(u_node->n_dnode,
			    FILE_ACTION_MODIFIED_STREAM, u_node->od_name);
		}
	} else {
		/* regular file or directory */
		if (node->n_dnode != NULL) {
			smb_node_notify_change(node->n_dnode,
			    FILE_ACTION_MODIFIED, node->od_name);
		}
	}
}

/*
 * smb_node_start_crit()
 *
 * Enter critical region for share reservations.
 * See comments above smb_fsop_shrlock().
 */
void
smb_node_start_crit(smb_node_t *node, krw_t mode)
{
	rw_enter(&node->n_lock, mode);
	nbl_start_crit(node->vp, mode);
}

/*
 * smb_node_end_crit()
 *
 * Exit critical region for share reservations.
 */
void
smb_node_end_crit(smb_node_t *node)
{
	nbl_end_crit(node->vp);
	rw_exit(&node->n_lock);
}

int
smb_node_in_crit(smb_node_t *node)
{
	return (nbl_in_crit(node->vp) && RW_LOCK_HELD(&node->n_lock));
}

void
smb_node_rdlock(smb_node_t *node)
{
	rw_enter(&node->n_lock, RW_READER);
}

void
smb_node_wrlock(smb_node_t *node)
{
	rw_enter(&node->n_lock, RW_WRITER);
}

void
smb_node_unlock(smb_node_t *node)
{
	rw_exit(&node->n_lock);
}

void
smb_node_add_ofile(smb_node_t *node, smb_ofile_t *of)
{
	SMB_NODE_VALID(node);

	smb_llist_enter(&node->n_ofile_list, RW_WRITER);
	smb_llist_insert_tail(&node->n_ofile_list, of);
	smb_llist_exit(&node->n_ofile_list);
}

void
smb_node_rem_ofile(smb_node_t *node, smb_ofile_t *of)
{
	SMB_NODE_VALID(node);

	smb_llist_enter(&node->n_ofile_list, RW_WRITER);
	smb_llist_remove(&node->n_ofile_list, of);
	smb_llist_exit(&node->n_ofile_list);
}

/*
 * smb_node_inc_open_ofiles
 */
void
smb_node_inc_open_ofiles(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	atomic_inc_32(&node->n_open_count);
}

/*
 * smb_node_dec_open_ofiles
 * returns new value
 */
uint32_t
smb_node_dec_open_ofiles(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	return (atomic_dec_32_nv(&node->n_open_count));
}

/*
 * smb_node_inc_opening_count
 */
void
smb_node_inc_opening_count(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	atomic_inc_32(&node->n_opening_count);
}

/*
 * smb_node_dec_opening_count
 */
void
smb_node_dec_opening_count(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	atomic_dec_32(&node->n_opening_count);
}

/*
 * smb_node_getmntpath
 */
int
smb_node_getmntpath(smb_node_t *node, char *buf, uint32_t buflen)
{
	vnode_t *vp, *root_vp;
	vfs_t *vfsp;
	int err;

	ASSERT(node);
	ASSERT(node->vp);
	ASSERT(node->vp->v_vfsp);

	vp = node->vp;
	vfsp = vp->v_vfsp;

	if (VFS_ROOT(vfsp, &root_vp))
		return (ENOENT);

	VN_HOLD(vp);

	/* NULL is passed in as we want to start at "/" */
	err = vnodetopath(NULL, root_vp, buf, buflen, zone_kcred());

	VN_RELE(vp);
	VN_RELE(root_vp);
	return (err);
}

/*
 * smb_node_getshrpath
 *
 * Determine the absolute pathname of 'node' within the share (tree).
 * For example if the node represents file "test1.txt" in directory
 * "dir1" the pathname would be: \dir1\test1.txt
 */
int
smb_node_getshrpath(smb_node_t *node, smb_tree_t *tree,
    char *buf, uint32_t buflen)
{
	int rc;

	ASSERT(node);
	ASSERT(tree);
	ASSERT(tree->t_snode);

	rc = smb_node_getpath(node, tree->t_snode->vp, buf, buflen);
	(void) strsubst(buf, '/', '\\');
	return (rc);
}

/*
 * smb_node_getpath
 *
 * Determine the absolute pathname of 'node' from 'rootvp'.
 *
 * Using vnodetopath is only reliable for directory nodes (due to
 * its reliance on the DNLC for non-directory nodes). Thus, if node
 * represents a file, construct the pathname for the parent dnode
 * and append filename.
 * If node represents a named stream, construct the pathname for the
 * associated unnamed stream and append the stream name.
 *
 * The pathname returned in buf will be '/' separated.
 */
int
smb_node_getpath(smb_node_t *node, vnode_t *rootvp, char *buf, uint32_t buflen)
{
	int rc;
	vnode_t *vp;
	smb_node_t *unode, *dnode;
	cred_t *kcr = zone_kcred();

	unode = (SMB_IS_STREAM(node)) ? node->n_unode : node;
	dnode = (smb_node_is_dir(unode)) ? unode : unode->n_dnode;

	/* find path to directory node */
	vp = dnode->vp;
	VN_HOLD(vp);
	if (rootvp) {
		VN_HOLD(rootvp);
		rc = vnodetopath(rootvp, vp, buf, buflen, kcr);
		VN_RELE(rootvp);
	} else {
		rc = vnodetopath(NULL, vp, buf, buflen, kcr);
	}
	VN_RELE(vp);

	if (rc != 0)
		return (rc);

	/* append filename if necessary */
	if (!smb_node_is_dir(unode)) {
		if (buf[strlen(buf) - 1] != '/')
			(void) strlcat(buf, "/", buflen);
		(void) strlcat(buf, unode->od_name, buflen);
	}

	/* append named stream name if necessary */
	if (SMB_IS_STREAM(node))
		(void) strlcat(buf, node->od_name, buflen);

	return (rc);
}

/*
 * smb_node_alloc
 */
static smb_node_t *
smb_node_alloc(
    char	*od_name,
    vnode_t	*vp,
    smb_llist_t	*bucket,
    uint32_t	hashkey)
{
	smb_node_t	*node;

	node = kmem_cache_alloc(smb_node_cache, KM_SLEEP);

	if (node->n_audit_buf != NULL)
		node->n_audit_buf->anb_index = 0;

	node->flags = 0;
	VN_HOLD(vp);
	node->vp = vp;
	node->n_refcnt = 1;
	node->n_hash_bucket = bucket;
	node->n_hashkey = hashkey;
	node->n_open_count = 0;
	node->n_allocsz = 0;
	node->n_dnode = NULL;
	node->n_unode = NULL;
	node->delete_on_close_cred = NULL;
	node->n_delete_on_close_flags = 0;
	node->n_oplock.ol_fem = B_FALSE;

	(void) strlcpy(node->od_name, od_name, sizeof (node->od_name));
	if (strcmp(od_name, XATTR_DIR) == 0)
		node->flags |= NODE_XATTR_DIR;

	if ((vp->v_flag & VROOT) != 0)
		node->flags |= NODE_FLAGS_VFSROOT;

	node->n_state = SMB_NODE_STATE_AVAILABLE;
	node->n_magic = SMB_NODE_MAGIC;

	return (node);
}

/*
 * smb_node_free
 */
static void
smb_node_free(smb_node_t *node)
{
	SMB_NODE_VALID(node);

	node->n_magic = 0;
	VERIFY(!list_link_active(&node->n_lnd));
	VERIFY(node->n_lock_list.ll_count == 0);
	VERIFY(node->n_wlock_list.ll_count == 0);
	VERIFY(node->n_ofile_list.ll_count == 0);
	VERIFY(node->n_oplock.ol_fem == B_FALSE);
	VERIFY(MUTEX_NOT_HELD(&node->n_mutex));
	VERIFY(!RW_LOCK_HELD(&node->n_lock));
	VN_RELE(node->vp);
	kmem_cache_free(smb_node_cache, node);
}

/*
 * smb_node_constructor
 */
static int
smb_node_constructor(void *buf, void *un, int kmflags)
{
	_NOTE(ARGUNUSED(kmflags, un))

	smb_node_t	*node = (smb_node_t *)buf;

	bzero(node, sizeof (smb_node_t));

	smb_llist_constructor(&node->n_ofile_list, sizeof (smb_ofile_t),
	    offsetof(smb_ofile_t, f_node_lnd));
	smb_llist_constructor(&node->n_lock_list, sizeof (smb_lock_t),
	    offsetof(smb_lock_t, l_lnd));
	smb_llist_constructor(&node->n_wlock_list, sizeof (smb_lock_t),
	    offsetof(smb_lock_t, l_lnd));
	mutex_init(&node->n_oplock.ol_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&node->n_oplock.WaitingOpenCV, NULL, CV_DEFAULT, NULL);
	rw_init(&node->n_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&node->n_mutex, NULL, MUTEX_DEFAULT, NULL);
	smb_node_create_audit_buf(node, kmflags);
	return (0);
}

/*
 * smb_node_destructor
 */
static void
smb_node_destructor(void *buf, void *un)
{
	_NOTE(ARGUNUSED(un))

	smb_node_t	*node = (smb_node_t *)buf;

	smb_node_destroy_audit_buf(node);
	mutex_destroy(&node->n_mutex);
	rw_destroy(&node->n_lock);
	cv_destroy(&node->n_oplock.WaitingOpenCV);
	mutex_destroy(&node->n_oplock.ol_mutex);
	smb_llist_destructor(&node->n_lock_list);
	smb_llist_destructor(&node->n_wlock_list);
	smb_llist_destructor(&node->n_ofile_list);
}

/*
 * smb_node_create_audit_buf
 */
static void
smb_node_create_audit_buf(smb_node_t *node, int kmflags)
{
	smb_audit_buf_node_t	*abn;

	if (smb_audit_flags & SMB_AUDIT_NODE) {
		abn = kmem_zalloc(sizeof (smb_audit_buf_node_t), kmflags);
		abn->anb_max_index = SMB_AUDIT_BUF_MAX_REC - 1;
		node->n_audit_buf = abn;
	}
}

/*
 * smb_node_destroy_audit_buf
 */
static void
smb_node_destroy_audit_buf(smb_node_t *node)
{
	if (node->n_audit_buf != NULL) {
		kmem_free(node->n_audit_buf, sizeof (smb_audit_buf_node_t));
		node->n_audit_buf = NULL;
	}
}

/*
 * smb_node_audit
 *
 * This function saves the calling stack in the audit buffer of the node passed
 * in.
 */
static void
smb_node_audit(smb_node_t *node)
{
#ifdef	_KERNEL
	smb_audit_buf_node_t	*abn;
	smb_audit_record_node_t	*anr;

	if (node->n_audit_buf) {
		abn = node->n_audit_buf;
		anr = abn->anb_records;
		anr += abn->anb_index;
		abn->anb_index++;
		abn->anb_index &= abn->anb_max_index;
		anr->anr_refcnt = node->n_refcnt;
		anr->anr_depth = getpcstack(anr->anr_stack,
		    SMB_AUDIT_STACK_DEPTH);
	}
#else	/* _KERNEL */
	_NOTE(ARGUNUSED(node))
#endif	/* _KERNEL */
}

static smb_llist_t *
smb_node_get_hash(fsid_t *fsid, smb_attr_t *attr, uint32_t *phashkey)
{
	uint32_t	hashkey;

	hashkey = fsid->val[0] + attr->sa_vattr.va_nodeid;
	hashkey += (hashkey >> 24) + (hashkey >> 16) + (hashkey >> 8);
	*phashkey = hashkey;
	return (&smb_node_hash_table[(hashkey & SMBND_HASH_MASK)]);
}

boolean_t
smb_node_is_file(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	return (node->vp->v_type == VREG);
}

boolean_t
smb_node_is_dir(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	return ((node->vp->v_type == VDIR) ||
	    (node->flags & NODE_FLAGS_DFSLINK));
}

boolean_t
smb_node_is_symlink(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	return ((node->vp->v_type == VLNK) &&
	    ((node->flags & NODE_FLAGS_REPARSE) == 0));
}

boolean_t
smb_node_is_dfslink(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	return ((node->vp->v_type == VLNK) &&
	    (node->flags & NODE_FLAGS_DFSLINK));
}

boolean_t
smb_node_is_reparse(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	return ((node->vp->v_type == VLNK) &&
	    (node->flags & NODE_FLAGS_REPARSE));
}

boolean_t
smb_node_is_vfsroot(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	return ((node->flags & NODE_FLAGS_VFSROOT) == NODE_FLAGS_VFSROOT);
}

boolean_t
smb_node_is_system(smb_node_t *node)
{
	SMB_NODE_VALID(node);
	return ((node->flags & NODE_FLAGS_SYSTEM) == NODE_FLAGS_SYSTEM);
}

/*
 * smb_node_file_is_readonly
 *
 * Checks if the file (which node represents) is marked readonly
 * in the filesystem.  Note that there may be handles open with
 * modify rights, and those continue to allow access even after
 * the DOS read-only flag has been set in the file system.
 */
boolean_t
smb_node_file_is_readonly(smb_node_t *node)
{
	smb_attr_t attr;

	if (node == NULL)
		return (B_FALSE);	/* pipes */

	bzero(&attr, sizeof (smb_attr_t));
	attr.sa_mask = SMB_AT_DOSATTR;
	(void) smb_fsop_getattr(NULL, zone_kcred(), node, &attr);
	return ((attr.sa_dosattr & FILE_ATTRIBUTE_READONLY) != 0);
}

/*
 * smb_node_setattr
 *
 * The sr may be NULL, for example when closing an ofile.
 * The ofile may be NULL, for example when a client request
 * specifies the file by pathname.
 *
 * Returns: errno
 *
 * Timestamps
 *
 * Windows and Unix have different models for timestamp updates.
 * [MS-FSA 2.1.5.14 Server Requests Setting of File Information]
 *
 * An open "handle" in Windows can control whether and when
 * any timestamp updates happen for that handle.  For example,
 * timestamps set via some handle are no longer updated by I/O
 * operations on that handle.  In Unix we don't really have any
 * way to avoid the timestamp updates that the file system does.
 * Therefore, we need to make some compromises, and simulate the
 * more important parts of the Windows file system semantics.
 *
 * For example, when an SMB client sets file times, set those
 * times in the file system (so the change will be visible to
 * other clients, at least until they change again) but we also
 * make those times "sticky" in our open handle, and reapply
 * those times when the handle is closed.  That reapply on close
 * simulates the Windows behavior where the timestamp updates
 * would be discontinued after they were set.  These "sticky"
 * attributes are returned in any query on the handle where
 * they are stored.
 *
 * The client can also turn on or off these "sticky" times using
 * the special NT time values -1 or -2, as described in:
 *	[MS-FSCC] Section 2.4.7, the paragraphs describing:
 *	CreationTime, LastAccessTime, LastWriteTime, ChangeTime
 * and the Windows behavior notes in those descriptions.
 * To summarize all the "special" NT time values:
 *	 0: no change (caller handles this case)
 *	-1: pause time updates (current value becomes "sticky")
 *	-2: resume time updates (discontiue "sticky" behavior)
 *
 * Other than the above, the file system layer takes care of the
 * normal time stamp updates, such as updating the mtime after a
 * write, and ctime after an attribute change.
 *
 * File allocation size is also simulated, and not persistent.
 * When the file allocation size is set it is first rounded up
 * to block size. If the file size is smaller than the allocation
 * size the file is truncated by setting the filesize to allocsz.
 */
int
smb_node_setattr(smb_request_t *sr, smb_node_t *node,
    cred_t *cr, smb_ofile_t *of, smb_attr_t *attr)
{
	smb_attr_t cur_attr;
	uint_t times_set = 0;
	uint_t times_clr = 0;
	int rc;

	SMB_NODE_VALID(node);

	/* set attributes specified in attr */
	if (attr->sa_mask == 0)
		return (0);  /* nothing to do (caller bug?) */

	/*
	 * Allocation size and EOF position interact.
	 * We don't persistently store the allocation size
	 * but make it look like we do while there are opens.
	 * Note: We update the caller's attr in the cases
	 * where they're setting only one of allocsz|size.
	 */
	switch (attr->sa_mask & (SMB_AT_ALLOCSZ | SMB_AT_SIZE)) {

	case SMB_AT_ALLOCSZ:
		/*
		 * Setting the allocation size but not EOF position.
		 * Get the current EOF in cur_attr and (if necessary)
		 * truncate to the (rounded up) allocation size.
		 * Using kcred here because if we don't have access,
		 * we want to fail at setattr below and not here.
		 */
		bzero(&cur_attr, sizeof (smb_attr_t));
		cur_attr.sa_mask = SMB_AT_SIZE;
		rc = smb_fsop_getattr(NULL, zone_kcred(), node, &cur_attr);
		if (rc != 0)
			return (rc);
		attr->sa_allocsz = SMB_ALLOCSZ(attr->sa_allocsz);
		if (cur_attr.sa_vattr.va_size > attr->sa_allocsz) {
			/* truncate the file to allocsz */
			attr->sa_vattr.va_size = attr->sa_allocsz;
			attr->sa_mask |= SMB_AT_SIZE;
		}
		break;

	case SMB_AT_SIZE:
		/*
		 * Setting the EOF position but not allocation size.
		 * If the new EOF position would be greater than
		 * the allocation size, increase the latter.
		 */
		if (node->n_allocsz < attr->sa_vattr.va_size) {
			attr->sa_mask |= SMB_AT_ALLOCSZ;
			attr->sa_allocsz =
			    SMB_ALLOCSZ(attr->sa_vattr.va_size);
		}
		break;

	case SMB_AT_ALLOCSZ | SMB_AT_SIZE:
		/*
		 * Setting both.  Increase alloc size if needed.
		 */
		if (attr->sa_allocsz < attr->sa_vattr.va_size)
			attr->sa_allocsz =
			    SMB_ALLOCSZ(attr->sa_vattr.va_size);
		break;

	default:
		break;
	}

	/*
	 * When setting times, -1 and -2 are "special" (see above).
	 * Keep track of -2 values and just clear mask.
	 * Replace -1 values with current time.
	 *
	 * Note that NT times -1, -2 have been converted to
	 * smb_nttime_m1, smb_nttime_m2, respectively.
	 */
	times_set = attr->sa_mask & SMB_AT_TIMES;
	if (times_set != 0) {
		bzero(&cur_attr, sizeof (smb_attr_t));
		cur_attr.sa_mask = SMB_AT_TIMES;
		rc = smb_fsop_getattr(NULL, zone_kcred(), node, &cur_attr);
		if (rc != 0)
			return (rc);

		/* Easiest to get these right with a macro. */
#define	FIX_TIME(FIELD, MASK)				\
		if (timespeccmp(&attr->FIELD, &smb_nttime_m2, ==)) { \
			times_clr |= MASK;		\
			times_set &= ~MASK;		\
		}					\
		if (timespeccmp(&attr->FIELD, &smb_nttime_m1, ==)) \
			attr->FIELD = cur_attr.FIELD	/* no ; */

		if (times_set & SMB_AT_ATIME) {
			FIX_TIME(sa_vattr.va_atime, SMB_AT_ATIME);
		}
		if (times_set & SMB_AT_MTIME) {
			FIX_TIME(sa_vattr.va_mtime, SMB_AT_MTIME);
		}
		if (times_set & SMB_AT_CTIME) {
			FIX_TIME(sa_vattr.va_ctime, SMB_AT_CTIME);
		}
		if (times_set & SMB_AT_CRTIME) {
			FIX_TIME(sa_crtime, SMB_AT_CRTIME);
		}
#undef	FIX_TIME

		/* Clear mask for -2 fields. */
		attr->sa_mask &= ~times_clr;
	}

	/*
	 * When operating on an open file, some settable attributes
	 * become "sticky" in the open file object until close, or until
	 * a set-time with value -2 (see above re. timestamps)
	 *
	 * Save the pending attributes.  We've handled -2 and -1 above,
	 * and cleared the -2 cases from the times_set mask.
	 */
	if (of != NULL && (times_set != 0 || times_clr != 0)) {
		smb_attr_t *pa;

		SMB_OFILE_VALID(of);
		mutex_enter(&of->f_mutex);
		pa = &of->f_pending_attr;

		pa->sa_mask |= times_set;
		pa->sa_mask &= ~times_clr;

		if (times_set & SMB_AT_ATIME)
			pa->sa_vattr.va_atime = attr->sa_vattr.va_atime;
		if (times_set & SMB_AT_MTIME)
			pa->sa_vattr.va_mtime = attr->sa_vattr.va_mtime;
		if (times_set & SMB_AT_CTIME)
			pa->sa_vattr.va_ctime = attr->sa_vattr.va_ctime;
		if (times_set & SMB_AT_CRTIME)
			pa->sa_crtime = attr->sa_crtime;

		mutex_exit(&of->f_mutex);

		/*
		 * The f_pending_attr times are reapplied in
		 * smb_ofile_close().
		 */

		/*
		 * If this change is coming directly from a client
		 * (sr != NULL) and it's a persistent handle, save
		 * the "sticky times" in the handle.
		 */
		if (sr != NULL && of->dh_persist) {
			smb2_dh_update_times(sr, of, attr);
		}
	}

	if ((attr->sa_mask & SMB_AT_ALLOCSZ) != 0) {
		mutex_enter(&node->n_mutex);
		/*
		 * Simulate n_allocsz persistence only while
		 * there are opens.  See smb_node_getattr
		 */
		if (node->n_open_count != 0)
			node->n_allocsz = attr->sa_allocsz;
		mutex_exit(&node->n_mutex);
	}

	rc = smb_fsop_setattr(sr, cr, node, attr);

	/*
	 * Only generate change notify events for client requests.
	 * Internal operations use sr=NULL
	 */
	if (rc == 0 && sr != NULL)
		smb_node_notify_modified(node);

	return (rc);
}

/*
 * smb_node_getattr
 *
 * Get attributes from the file system and apply any smb-specific
 * overrides for size, dos attributes and timestamps
 *
 * Returns: errno
 */
int
smb_node_getattr(smb_request_t *sr, smb_node_t *node, cred_t *cr,
    smb_ofile_t *of, smb_attr_t *attr)
{
	int rc;
	uint_t want_mask, pend_mask;
	boolean_t isdir;

	SMB_NODE_VALID(node);

	rc = smb_fsop_getattr(sr, cr, node, attr);
	if (rc != 0)
		return (rc);

	isdir = smb_node_is_dir(node);

	mutex_enter(&node->n_mutex);

	/*
	 * Fix-up sa_allocsz, for which we simulate persistence
	 * while there are open files. (See smb_node_setattr)
	 *
	 * The value in node->n_allocsz is the value last set via
	 * smb_node_setattr.  It's possible that writes may have
	 * increased the file size beyond n_allocsz, in which case
	 * the sa_vattr.va_size, sa_allocsz from smb_fsop_getattr
	 * will be greater than n_allocsz, so this returns the
	 * greater of n_allocsz and sa_allocsz.
	 */
	if ((attr->sa_mask & SMB_AT_ALLOCSZ) != 0 &&
	    node->n_open_count > 0 && !isdir &&
	    attr->sa_allocsz < node->n_allocsz) {
		attr->sa_allocsz = node->n_allocsz;
	}

	mutex_exit(&node->n_mutex);

	/*
	 * getattr with an ofile gets any "pending" times that
	 * might have been previously set via this ofile.
	 * This is what makes these times "sticky".
	 */
	want_mask = attr->sa_mask & SMB_AT_TIMES;
	if (of != NULL && want_mask != 0) {
		smb_attr_t *pa;

		SMB_OFILE_VALID(of);
		mutex_enter(&of->f_mutex);
		pa = &of->f_pending_attr;

		pend_mask = pa->sa_mask;

		if (want_mask & pend_mask & SMB_AT_ATIME)
			attr->sa_vattr.va_atime =
			    pa->sa_vattr.va_atime;
		if (want_mask & pend_mask & SMB_AT_MTIME)
			attr->sa_vattr.va_mtime =
			    pa->sa_vattr.va_mtime;
		if (want_mask & pend_mask & SMB_AT_CTIME)
			attr->sa_vattr.va_ctime =
			    pa->sa_vattr.va_ctime;
		if (want_mask & pend_mask & SMB_AT_CRTIME)
			attr->sa_crtime =
			    pa->sa_crtime;

		mutex_exit(&of->f_mutex);
	}


	return (0);
}


#ifndef	_KERNEL
extern int reparse_vnode_parse(vnode_t *vp, nvlist_t *nvl);
#endif	/* _KERNEL */

/*
 * Check to see if the node represents a reparse point.
 * If yes, whether the reparse point contains a DFS link.
 */
static void
smb_node_init_reparse(smb_node_t *node, smb_attr_t *attr)
{
	nvlist_t *nvl;
	nvpair_t *rec;
	char *rec_type;

	if ((attr->sa_dosattr & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
		return;

	if ((nvl = reparse_init()) == NULL)
		return;

	if (reparse_vnode_parse(node->vp, nvl) != 0) {
		reparse_free(nvl);
		return;
	}

	node->flags |= NODE_FLAGS_REPARSE;

	rec = nvlist_next_nvpair(nvl, NULL);
	while (rec != NULL) {
		rec_type = nvpair_name(rec);
		if ((rec_type != NULL) &&
		    (strcasecmp(rec_type, DFS_REPARSE_SVCTYPE) == 0)) {
			node->flags |= NODE_FLAGS_DFSLINK;
			break;
		}
		rec = nvlist_next_nvpair(nvl, rec);
	}

	reparse_free(nvl);
}

/*
 * smb_node_init_system
 *
 * If the node represents a special system file set NODE_FLAG_SYSTEM.
 * System files:
 * - any node whose parent dnode has NODE_FLAG_SYSTEM set
 * - any node whose associated unnamed stream node (unode) has
 *   NODE_FLAG_SYSTEM set
 * - .$EXTEND at root of share (quota management)
 */
static void
smb_node_init_system(smb_node_t *node)
{
	smb_node_t *dnode = node->n_dnode;
	smb_node_t *unode = node->n_unode;

	if ((dnode) && (dnode->flags & NODE_FLAGS_SYSTEM)) {
		node->flags |= NODE_FLAGS_SYSTEM;
		return;
	}

	if ((unode) && (unode->flags & NODE_FLAGS_SYSTEM)) {
		node->flags |= NODE_FLAGS_SYSTEM;
		return;
	}

	if ((dnode) && (smb_node_is_vfsroot(node->n_dnode) &&
	    (strcasecmp(node->od_name, ".$EXTEND") == 0))) {
		node->flags |= NODE_FLAGS_SYSTEM;
	}
}
