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

/*
 * General Structures Layout
 * -------------------------
 *
 * This is a simplified diagram showing the relationship between most of the
 * main structures.
 *
 * +-------------------+
 * |     SMB_INFO      |
 * +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |     SESSION       |<----->|     SESSION       |......|      SESSION      |
 * +-------------------+       +-------------------+      +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |       USER        |<----->|       USER        |......|       USER        |
 * +-------------------+       +-------------------+      +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |       TREE        |<----->|       TREE        |......|       TREE        |
 * +-------------------+       +-------------------+      +-------------------+
 *      |         |
 *      |         |
 *      |         v
 *      |     +-------+       +-------+      +-------+
 *      |     | OFILE |<----->| OFILE |......| OFILE |
 *      |     +-------+       +-------+      +-------+
 *      |
 *      |
 *      v
 *  +-------+       +------+      +------+
 *  | ODIR  |<----->| ODIR |......| ODIR |
 *  +-------+       +------+      +------+
 *
 *
 * Tree State Machine
 * ------------------
 *
 *    +-----------------------------+	 T0
 *    |  SMB_TREE_STATE_CONNECTED   |<----------- Creation/Allocation
 *    +-----------------------------+
 *		    |
 *		    | T1
 *		    |
 *		    v
 *    +------------------------------+
 *    | SMB_TREE_STATE_DISCONNECTING |
 *    +------------------------------+
 *		    |
 *		    | T2
 *		    |
 *		    v
 *    +-----------------------------+    T3
 *    | SMB_TREE_STATE_DISCONNECTED |----------> Deletion/Free
 *    +-----------------------------+
 *
 * SMB_TREE_STATE_CONNECTED
 *
 *    While in this state:
 *      - The tree is queued in the list of trees of its user.
 *      - References will be given out if the tree is looked up.
 *      - Files under that tree can be accessed.
 *
 * SMB_TREE_STATE_DISCONNECTING
 *
 *    While in this state:
 *      - The tree is queued in the list of trees of its user.
 *      - References will not be given out if the tree is looked up.
 *      - The files and directories open under the tree are being closed.
 *      - The resources associated with the tree remain.
 *
 * SMB_TREE_STATE_DISCONNECTED
 *
 *    While in this state:
 *      - The tree is queued in the list of trees of its user.
 *      - References will not be given out if the tree is looked up.
 *      - The tree has no more files and directories opened.
 *      - The resources associated with the tree remain.
 *
 * Transition T0
 *
 *    This transition occurs in smb_tree_connect(). A new tree is created and
 *    added to the list of trees of a user.
 *
 * Transition T1
 *
 *    This transition occurs in smb_tree_disconnect().
 *
 * Transition T2
 *
 *    This transition occurs in smb_tree_release(). The resources associated
 *    with the tree are freed as well as the tree structure. For the transition
 *    to occur, the tree must be in the SMB_TREE_STATE_DISCONNECTED state and
 *    the reference count be zero.
 *
 * Comments
 * --------
 *
 *    The state machine of the tree structures is controlled by 3 elements:
 *      - The list of trees of the user it belongs to.
 *      - The mutex embedded in the structure itself.
 *      - The reference count.
 *
 *    There's a mutex embedded in the tree structure used to protect its fields
 *    and there's a lock embedded in the list of trees of a user. To
 *    increment or to decrement the reference count the mutex must be entered.
 *    To insert the tree into the list of trees of the user and to remove
 *    the tree from it, the lock must be entered in RW_WRITER mode.
 *
 *    Rules of access to a tree structure:
 *
 *    1) In order to avoid deadlocks, when both (mutex and lock of the user
 *       list) have to be entered, the lock must be entered first.
 *
 *    2) All actions applied to a tree require a reference count.
 *
 *    3) There are 2 ways of getting a reference count. One is when the tree
 *       is connected. The other when the user is looked up. This translates
 *       into 2 functions: smb_tree_connect() and smb_tree_lookup_by_tid().
 *
 *    It should be noted that the reference count of a tree registers the
 *    number of references to the tree in other structures (such as an smb
 *    request). The reference count is not incremented in these 2 instances:
 *
 *    1) The tree is connected. An tree is anchored by his state. If there's
 *       no activity involving a tree currently connected, the reference
 *       count of that tree is zero.
 *
 *    2) The tree is queued in the list of trees of the user. The fact of
 *       being queued in that list is NOT registered by incrementing the
 *       reference count.
 */
#include <sys/fsid.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

/* Static functions defined further down this file. */
static void smb_tree_delete(smb_tree_t *);
static smb_tree_t *smb_tree_lookup_head(smb_llist_t *);
static smb_tree_t *smb_tree_lookup_next(smb_llist_t *, smb_tree_t *);

/*
 * smb_tree_connect
 */
smb_tree_t *
smb_tree_connect(
    smb_user_t		*user,
    uint16_t		access_flags,
    char		*sharename,
    char		*resource,
    int32_t		stype,
    smb_node_t		*snode,
    fsvol_attr_t	*vol_attr)
{
	smb_tree_t	*tree;
	uint16_t	tid;

	if (smb_idpool_alloc(&user->u_tid_pool, &tid)) {
		return (NULL);
	}

	tree = kmem_cache_alloc(smb_info.si_cache_tree, KM_SLEEP);
	bzero(tree, sizeof (smb_tree_t));

	if (smb_idpool_constructor(&tree->t_fid_pool)) {
		smb_idpool_free(&user->u_tid_pool, tid);
		kmem_cache_free(smb_info.si_cache_tree, tree);
		return (NULL);
	}

	if (smb_idpool_constructor(&tree->t_sid_pool)) {
		smb_idpool_destructor(&tree->t_fid_pool);
		smb_idpool_free(&user->u_tid_pool, tid);
		kmem_cache_free(smb_info.si_cache_tree, tree);
		return (NULL);
	}

	smb_llist_constructor(&tree->t_ofile_list, sizeof (smb_ofile_t),
	    offsetof(smb_ofile_t, f_lnd));

	smb_llist_constructor(&tree->t_odir_list, sizeof (smb_odir_t),
	    offsetof(smb_odir_t, d_lnd));

	(void) strlcpy(tree->t_sharename, sharename,
	    sizeof (tree->t_sharename));
	(void) strlcpy(tree->t_resource, resource, sizeof (tree->t_resource));

	mutex_init(&tree->t_mutex, NULL, MUTEX_DEFAULT, NULL);

	tree->t_user = user;
	tree->t_session = user->u_session;
	tree->t_refcnt = 1;
	tree->t_tid = tid;
	tree->t_access = access_flags;
	tree->t_res_type = stype;
	tree->t_snode = snode;
	tree->t_state = SMB_TREE_STATE_CONNECTED;
	tree->t_magic = SMB_TREE_MAGIC;

	switch (stype & STYPE_MASK) {
	case STYPE_DISKTREE:
		tree->t_fsd = snode->tree_fsd;

		(void) strlcpy(tree->t_typename, vol_attr->fs_typename,
		    SMB_TREE_TYPENAME_SZ);
		(void) utf8_strupr((char *)tree->t_typename);

		if (vol_attr->flags & FSOLF_READONLY)
			tree->t_access = SMB_TREE_READ_ONLY;

		tree->t_acltype = smb_fsop_acltype(snode);

		if (strncasecmp(tree->t_typename, NFS, sizeof (NFS)) == 0)
			tree->t_flags |= SMB_TREE_FLAG_NFS_MOUNTED;

		if (strncasecmp(tree->t_typename, "UFS", sizeof ("UFS")) == 0)
			tree->t_flags |= SMB_TREE_FLAG_UFS;

		if (vfs_has_feature(snode->vp->v_vfsp, VFSFT_ACLONCREATE))
			tree->t_flags |= SMB_TREE_FLAG_ACLONCREATE;

		if (vfs_has_feature(snode->vp->v_vfsp, VFSFT_ACEMASKONACCESS))
			tree->t_flags |= SMB_TREE_FLAG_ACEMASKONACCESS;

		if (vfs_has_feature(snode->vp->v_vfsp, VFSFT_CASEINSENSITIVE))
			tree->t_flags |= SMB_TREE_FLAG_IGNORE_CASE;

		break;

	case STYPE_IPC:
	default:
		tree->t_typename[0] = '\0';
		break;
	}

	smb_llist_enter(&user->u_tree_list, RW_WRITER);
	smb_llist_insert_head(&user->u_tree_list, tree);
	smb_llist_exit(&user->u_tree_list);
	atomic_inc_32(&user->u_session->s_tree_cnt);
	atomic_inc_32(&smb_info.open_trees);

	return (tree);
}

/*
 * smb_tree_disconnect
 *
 *
 */
void
smb_tree_disconnect(
    smb_tree_t	*tree)
{
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	mutex_enter(&tree->t_mutex);
	ASSERT(tree->t_refcnt);
	switch (tree->t_state) {
	case SMB_TREE_STATE_CONNECTED: {
		/*
		 * The tree is moved into a state indicating that the disconnect
		 * process has started.
		 */
		tree->t_state = SMB_TREE_STATE_DISCONNECTING;
		mutex_exit(&tree->t_mutex);
		atomic_dec_32(&smb_info.open_trees);
		/*
		 * The files opened under this tree are closed.
		 */
		smb_ofile_close_all(tree);
		/*
		 * The directories opened under this tree are closed.
		 */
		smb_odir_close_all(tree);
		mutex_enter(&tree->t_mutex);
		tree->t_state = SMB_TREE_STATE_DISCONNECTED;
		/*FALLTHRU*/
	}
	case SMB_TREE_STATE_DISCONNECTED:
	case SMB_TREE_STATE_DISCONNECTING:
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&tree->t_mutex);
}

/*
 * smb_tree_disconnect_all
 *
 *
 */
void
smb_tree_disconnect_all(
    smb_user_t		*user)
{
	smb_tree_t	*tree;

	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	tree = smb_tree_lookup_head(&user->u_tree_list);
	while (tree) {
		ASSERT(tree->t_user == user);
		smb_tree_disconnect(tree);
		smb_tree_release(tree);
		tree = smb_tree_lookup_head(&user->u_tree_list);
	}
}

/*
 * smb_tree_close_all_by_pid
 *
 *
 */
void
smb_tree_close_all_by_pid(
    smb_user_t		*user,
    uint16_t		pid)
{
	smb_tree_t	*tree;

	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	tree = smb_tree_lookup_head(&user->u_tree_list);
	while (tree) {
		smb_tree_t	*next;
		ASSERT(tree->t_user == user);
		smb_ofile_close_all_by_pid(tree, pid);
		smb_odir_close_all_by_pid(tree, pid);
		next = smb_tree_lookup_next(&user->u_tree_list, tree);
		smb_tree_release(tree);
		tree = next;
	}
}

/*
 * smb_tree_release
 *
 *
 */
void
smb_tree_release(
    smb_tree_t		*tree)
{
	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	mutex_enter(&tree->t_mutex);
	ASSERT(tree->t_refcnt);
	tree->t_refcnt--;
	switch (tree->t_state) {
	case SMB_TREE_STATE_DISCONNECTED:
		if (tree->t_refcnt == 0) {
			mutex_exit(&tree->t_mutex);
			smb_tree_delete(tree);
			return;
		}
		break;

	case SMB_TREE_STATE_CONNECTED:
	case SMB_TREE_STATE_DISCONNECTING:
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&tree->t_mutex);
}

/*
 * Find the appropriate tree for this request. The request credentials
 * set here override those set during uid lookup. In domain mode, the
 * user and tree credentials should be the same. In share mode, the
 * tree credentials (defined in the share definition) should override
 * the user credentials.
 */
smb_tree_t *
smb_tree_lookup_by_tid(
    smb_user_t		*user,
    uint16_t		tid)
{
	smb_tree_t	*tree;

	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	smb_llist_enter(&user->u_tree_list, RW_READER);
	tree = smb_llist_head(&user->u_tree_list);
	while (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);
		if (tree->t_tid == tid) {
			mutex_enter(&tree->t_mutex);
			switch (tree->t_state) {
			case SMB_TREE_STATE_CONNECTED:
				/* The tree exists and is still connected. */
				tree->t_refcnt++;
				mutex_exit(&tree->t_mutex);
				smb_llist_exit(&user->u_tree_list);
				return (tree);
			case SMB_TREE_STATE_DISCONNECTING:
			case SMB_TREE_STATE_DISCONNECTED:
				/*
				 * The tree exists but is diconnected or is in
				 * the process of being destroyed.
				 */
				mutex_exit(&tree->t_mutex);
				smb_llist_exit(&user->u_tree_list);
				return (NULL);
			default:
				ASSERT(0);
				mutex_exit(&tree->t_mutex);
				smb_llist_exit(&user->u_tree_list);
				return (NULL);
			}
		}
		tree = smb_llist_next(&user->u_tree_list, tree);
	}
	smb_llist_exit(&user->u_tree_list);
	return (NULL);
}

/*
 * smb_tree_lookup_first_by_name
 *
 * This function returns the first tree in the connected state that matches the
 * sharename passed in. If the tree provided is NULL the search starts from
 * the beginning of the list of trees of the user. It a tree is provided the
 * search starts just after that tree.
 */
smb_tree_t *
smb_tree_lookup_by_name(
    smb_user_t		*user,
    char		*sharename,
    smb_tree_t		*tree)
{
	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);
	ASSERT(sharename);

	smb_llist_enter(&user->u_tree_list, RW_READER);

	if (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);
		tree = smb_llist_next(&user->u_tree_list, tree);
	} else {
		tree = smb_llist_head(&user->u_tree_list);
	}

	while (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);
		if (strcmp(tree->t_sharename, sharename) == 0) {
			mutex_enter(&tree->t_mutex);
			switch (tree->t_state) {
			case SMB_TREE_STATE_CONNECTED:
				/* The tree exists and is still connected. */
				tree->t_refcnt++;
				mutex_exit(&tree->t_mutex);
				smb_llist_exit(&user->u_tree_list);
				return (tree);
			case SMB_TREE_STATE_DISCONNECTING:
			case SMB_TREE_STATE_DISCONNECTED:
				/*
				 * The tree exists but is diconnected or is in
				 * the process of being destroyed.
				 */
				mutex_exit(&tree->t_mutex);
				break;
			default:
				ASSERT(0);
				mutex_exit(&tree->t_mutex);
				break;
			}
		}
		tree = smb_llist_next(&user->u_tree_list, tree);
	}
	smb_llist_exit(&user->u_tree_list);
	return (NULL);
}

/*
 * smb_tree_lookup_first_by_fsd
 *
 * This function returns the first tree in the connected state that matches the
 * fsd passed in. If the tree provided is NULL the search starts from
 * the beginning of the list of trees of the user. It a tree is provided the
 * search starts just after that tree.
 */
smb_tree_t *
smb_tree_lookup_by_fsd(
    smb_user_t		*user,
    fs_desc_t		*fsd,
    smb_tree_t		*tree)
{
	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);
	ASSERT(fsd);

	smb_llist_enter(&user->u_tree_list, RW_READER);

	if (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);
		tree = smb_llist_next(&user->u_tree_list, tree);
	} else {
		tree = smb_llist_head(&user->u_tree_list);
	}

	while (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);
		if (fsd_cmp(&tree->t_fsd, fsd) == 0) {
			mutex_enter(&tree->t_mutex);
			switch (tree->t_state) {
			case SMB_TREE_STATE_CONNECTED:
				/* The tree exists and is still connected. */
				tree->t_refcnt++;
				mutex_exit(&tree->t_mutex);
				smb_llist_exit(&user->u_tree_list);
				return (tree);
			case SMB_TREE_STATE_DISCONNECTING:
			case SMB_TREE_STATE_DISCONNECTED:
				/*
				 * The tree exists but is diconnected or is in
				 * the process of being destroyed.
				 */
				mutex_exit(&tree->t_mutex);
				break;
			default:
				ASSERT(0);
				mutex_exit(&tree->t_mutex);
				break;
			}
		}
		tree = smb_llist_next(&user->u_tree_list, tree);
	}
	smb_llist_exit(&user->u_tree_list);
	return (NULL);
}

/* *************************** Static Functions ***************************** */

/*
 * smb_tree_delete
 *
 * This function releases all the resources associated with a tree. It also
 * removes the tree the caller passes from the list of trees of the user.
 *
 * The tree to destroy must be in the "destroying state" and the reference count
 * must be zero. This function assumes it's single threaded i.e. only one
 * thread will attempt to destroy a specific tree (this condition should be met
 * if the tree is is the "destroying state" and has a reference count of zero).
 *
 * Entry:
 *	tree	Tree to destroy
 *
 * Exit:
 *	Nothing
 *
 * Return:
 *	Nothing
 */
static void
smb_tree_delete(smb_tree_t *tree)
{
	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);
	ASSERT(tree->t_state == SMB_TREE_STATE_DISCONNECTED);
	ASSERT(tree->t_refcnt == 0);

	/*
	 * Let's remove the tree from the list of trees of the
	 * user. This has to be done before any resources
	 * associated with the tree are released.
	 */
	smb_llist_enter(&tree->t_user->u_tree_list, RW_WRITER);
	smb_llist_remove(&tree->t_user->u_tree_list, tree);
	smb_llist_exit(&tree->t_user->u_tree_list);

	tree->t_magic = (uint32_t)~SMB_TREE_MAGIC;
	smb_idpool_free(&tree->t_user->u_tid_pool, tree->t_tid);
	atomic_dec_32(&tree->t_session->s_tree_cnt);

	if (tree->t_snode) {
		smb_node_release(tree->t_snode);
	}
	mutex_destroy(&tree->t_mutex);
	/*
	 * The list of open files and open directories should be empty.
	 */
	smb_llist_destructor(&tree->t_ofile_list);
	smb_llist_destructor(&tree->t_odir_list);
	smb_idpool_destructor(&tree->t_fid_pool);
	smb_idpool_destructor(&tree->t_sid_pool);
	kmem_cache_free(smb_info.si_cache_tree, tree);
}

/*
 * smb_tree_lookup_head
 *
 * This function returns the first tree in the list that is in the
 * SMB_TREE_STATE_CONNECTED. A reference is taken on the tree and
 * smb_tree_release() will have to be called for the tree returned.
 *
 * Entry:
 *	lst	List of trees (usually the list of trees of a user)
 *
 * Exit:
 *	Nothing
 *
 * Return:
 *	NULL	No tree in the SMB_TREE_STATE_CONNECTED state was found.
 *	!NULL	First tree in the list in the SMB_TREE_STATE_CONNECTED state.
 */
static smb_tree_t *
smb_tree_lookup_head(
    smb_llist_t		*lst)
{
	smb_tree_t	*tree;

	smb_llist_enter(lst, RW_READER);
	tree = smb_llist_head(lst);
	while (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		mutex_enter(&tree->t_mutex);
		if (tree->t_state == SMB_TREE_STATE_CONNECTED) {
			tree->t_refcnt++;
			mutex_exit(&tree->t_mutex);
			break;
		} else if ((tree->t_state == SMB_TREE_STATE_DISCONNECTING) ||
		    (tree->t_state == SMB_TREE_STATE_DISCONNECTED)) {
			mutex_exit(&tree->t_mutex);
			tree = smb_llist_next(lst, tree);
		} else {
			ASSERT(0);
			mutex_exit(&tree->t_mutex);
			tree = smb_llist_next(lst, tree);
		}
	}
	smb_llist_exit(lst);

	return (tree);
}

/*
 * smb_tree_lookup_next
 *
 * This function returns the next tree in the list that is in the
 * SMB_TREE_STATE_CONNECTED. A reference is taken on the tree and
 * smb_tree_release() will have to be called for the tree returned.
 *
 * Entry:
 *	lst	List of trees (usually the list of trees of a user).
 *	tree	Starting tree.
 *
 * Exit:
 *	Nothing
 *
 * Return:
 *	NULL	No tree in the SMB_TREE_STATE_CONNECTED state was found.
 *	!NULL	Next tree in the list in the SMB_TREE_STATE_CONNECTED state.
 */
static smb_tree_t *
smb_tree_lookup_next(
    smb_llist_t		*lst,
    smb_tree_t		*tree)
{
	smb_tree_t	*next;

	ASSERT(lst);
	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);
	ASSERT(tree->t_refcnt);

	smb_llist_enter(lst, RW_READER);
	next = smb_llist_next(lst, tree);
	while (next) {
		ASSERT(next->t_magic == SMB_TREE_MAGIC);
		mutex_enter(&next->t_mutex);
		if (next->t_state == SMB_TREE_STATE_CONNECTED) {
			next->t_refcnt++;
			mutex_exit(&next->t_mutex);
			break;
		} else if ((next->t_state == SMB_TREE_STATE_DISCONNECTING) ||
		    (next->t_state == SMB_TREE_STATE_DISCONNECTED)) {
			mutex_exit(&next->t_mutex);
			next = smb_llist_next(lst, next);
		} else {
			ASSERT(0);
			mutex_exit(&next->t_mutex);
			next = smb_llist_next(lst, next);
		}
	}
	smb_llist_exit(lst);

	return (next);
}
