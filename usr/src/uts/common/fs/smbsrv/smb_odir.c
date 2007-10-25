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
 * Odir State Machine
 * ------------------
 *
 *    +-------------------------+	 T0
 *    |  SMB_ODIR_STATE_OPEN   |<----------- Creation/Allocation
 *    +-------------------------+
 *		    |
 *		    | T1
 *		    |
 *		    v
 *    +-------------------------+
 *    | SMB_ODIR_STATE_CLOSING |
 *    +-------------------------+
 *		    |
 *		    | T2
 *		    |
 *		    v
 *    +-------------------------+    T3
 *    | SMB_ODIR_STATE_CLOSED  |----------> Deletion/Free
 *    +-------------------------+
 *
 * SMB_ODIR_STATE_OPEN
 *
 *    While in this state:
 *      - The odir is queued in the list of odirs of its tree.
 *      - References will be given out if the odir is looked up.
 *
 * SMB_ODIR_STATE_CLOSING
 *
 *    While in this state:
 *      - The odir is queued in the list of odirs of its tree.
 *      - References will not be given out if the odir is looked up.
 *      - The odir is closed.
 *      - The resources associated with the odir remain.
 *
 * SMB_ODIR_STATE_CLOSED
 *
 *    While in this state:
 *      - The odir is queued in the list of odirs of its tree.
 *      - References will not be given out if the odir is looked up.
 *      - The resources associated with the odir remain.
 *
 * Transition T0
 *
 *    This transition occurs in smb_odir_open(). A new odir is created and
 *    added to the list of odirs of a tree.
 *
 * Transition T1
 *
 *    This transition occurs in smb_odir_close().
 *
 * Transition T2
 *
 *    This transition occurs in smb_odir_release(). The resources associated
 *    with the odir are freed as well as the odir structure. For the
 *    transition to occur, the odir must be in the SMB_ODIR_STATE_CLOSED
 *    state and the reference count be zero.
 *
 * Comments
 * --------
 *
 *    The state machine of the odir structures is controlled by 3 elements:
 *      - The list of odirs of the tree it belongs to.
 *      - The mutex embedded in the structure itself.
 *      - The reference count.
 *
 *    There's a mutex embedded in the odir structure used to protect its fields
 *    and there's a lock embedded in the list of odirs of a tree. To
 *    increment or to decrement the reference count the mutex must be entered.
 *    To insert the odir into the list of odirs of the tree and to remove
 *    the odir from it, the lock must be entered in RW_WRITER mode.
 *
 *    Rules of access to a odir structure:
 *
 *    1) In order to avoid deadlocks, when both (mutex and lock of the odir
 *       list) have to be entered, the lock must be entered first.
 *
 *    2) All actions applied to an odir require a reference count.
 *
 *    3) There are 2 ways of getting a reference count. One is when the odir
 *       is opened. The other when the odir is looked up. This translates
 *       into 2 functions: smb_odir_open() and smb_odir_lookup_by_fid().
 *
 *    It should be noted that the reference count of an odir registers the
 *    number of references to the odir in other structures (such as an smb
 *    request). The reference count is not incremented in these 2 instances:
 *
 *    1) The odir is open. An odir is anchored by his state. If there's
 *       no activity involving an odir currently open, the reference count
 *       of that odir is zero.
 *
 *    2) The odir is queued in the list of odirs of its tree. The fact of
 *       being queued in that list is NOT registered by incrementing the
 *       reference count.
 */
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>

/* Static functions defined further down this file. */
static void		smb_odir_delete(smb_odir_t *of);
static smb_odir_t	*smb_odir_close_and_next(smb_odir_t *od);

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

/*
 * smb_odir_open
 */
smb_odir_t *
smb_odir_open(
    smb_tree_t		*tree,
    smb_node_t		*node,
    char		*pattern,
    uint16_t		pid,
    unsigned short	sattr)
{
	smb_odir_t	*dir;

	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);
	ASSERT(node);
	ASSERT(node->n_magic == SMB_NODE_MAGIC);
	ASSERT(pattern);

	if (strlen(pattern) >= sizeof (dir->d_pattern)) {
		return (NULL);
	}

	dir = kmem_cache_alloc(smb_info.si_cache_odir, KM_SLEEP);
	bzero(dir, sizeof (smb_odir_t));
	dir->d_refcnt = 1;
	dir->d_session = tree->t_session;
	dir->d_user = tree->t_user;
	dir->d_tree = tree;
	(void) strlcpy(dir->d_pattern, pattern, sizeof (dir->d_pattern));
	dir->d_wildcards = smb_convert_unicode_wildcards(pattern);
	dir->d_state = SMB_ODIR_STATE_OPEN;

	if (smb_idpool_alloc(&dir->d_tree->t_sid_pool, &dir->d_sid)) {
		kmem_cache_free(smb_info.si_cache_odir, dir);
		return (NULL);
	}
	mutex_init(&dir->d_mutex, NULL, MUTEX_DEFAULT, NULL);
	dir->d_sattr = sattr;
	dir->d_opened_by_pid = pid;
	dir->d_dir_snode = node;
	dir->d_state = SMB_ODIR_STATE_OPEN;
	dir->d_magic = SMB_ODIR_MAGIC;

	smb_llist_enter(&tree->t_odir_list, RW_WRITER);
	smb_llist_insert_tail(&tree->t_odir_list, dir);
	smb_llist_exit(&tree->t_odir_list);

	atomic_inc_32(&tree->t_session->s_dir_cnt);
	return (dir);
}

/*
 * smb_odir_close
 */
void
smb_odir_close(
    smb_odir_t		*od)
{
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);

	mutex_enter(&od->d_mutex);
	ASSERT(od->d_refcnt);
	switch (od->d_state) {
	case SMB_ODIR_STATE_OPEN:
		od->d_state = SMB_ODIR_STATE_CLOSED;
		break;
	case SMB_ODIR_STATE_CLOSING:
	case SMB_ODIR_STATE_CLOSED:
		break;
	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&od->d_mutex);
}

/*
 * smb_odir_close_all
 *
 *
 */
void
smb_odir_close_all(
    smb_tree_t		*tree)
{
	smb_odir_t	*od;

	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	smb_llist_enter(&tree->t_odir_list, RW_READER);
	od = smb_llist_head(&tree->t_odir_list);
	while (od) {
		ASSERT(od->d_magic == SMB_ODIR_MAGIC);
		ASSERT(od->d_tree == tree);
		od = smb_odir_close_and_next(od);
	}
	smb_llist_exit(&tree->t_odir_list);
}

/*
 * smb_odir_close_all_by_pid
 *
 *
 */
void
smb_odir_close_all_by_pid(
    smb_tree_t		*tree,
    uint16_t		pid)
{
	smb_odir_t	*od;

	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	smb_llist_enter(&tree->t_odir_list, RW_READER);
	od = smb_llist_head(&tree->t_odir_list);
	while (od) {
		ASSERT(od->d_magic == SMB_ODIR_MAGIC);
		ASSERT(od->d_tree == tree);
		if (od->d_opened_by_pid == pid) {
			od = smb_odir_close_and_next(od);
		} else {
			od = smb_llist_next(&tree->t_odir_list, od);
		}
	}
	smb_llist_exit(&tree->t_odir_list);
}

/*
 * smb_odir_release
 */
void
smb_odir_release(
    smb_odir_t	*od)
{
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);

	mutex_enter(&od->d_mutex);
	ASSERT(od->d_refcnt);
	od->d_refcnt--;
	switch (od->d_state) {
	case SMB_ODIR_STATE_CLOSING:
	case SMB_ODIR_STATE_OPEN:
		break;

	case SMB_ODIR_STATE_CLOSED:
		if (od->d_refcnt == 0) {
			mutex_exit(&od->d_mutex);
			smb_odir_delete(od);
			return;
		}
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&od->d_mutex);
}

/*
 * smb_odir_lookup_by_sid
 */
smb_odir_t *
smb_odir_lookup_by_sid(
	smb_tree_t	*tree,
	uint16_t	sid)
{
	smb_llist_t	*od_list;
	smb_odir_t	*od;

	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	od_list = &tree->t_odir_list;

	smb_llist_enter(od_list, RW_READER);
	od = smb_llist_head(od_list);
	while (od) {
		ASSERT(od->d_magic == SMB_ODIR_MAGIC);
		ASSERT(od->d_tree == tree);
		if (od->d_sid == sid) {
			mutex_enter(&od->d_mutex);
			if (od->d_state != SMB_ODIR_STATE_OPEN) {
				mutex_exit(&od->d_mutex);
				smb_llist_exit(od_list);
				return (NULL);
			}
			od->d_refcnt++;
			mutex_exit(&od->d_mutex);
			break;
		}
		od = smb_llist_next(od_list, od);
	}
	smb_llist_exit(od_list);
	return (od);
}

/* *************************** Static Functions ***************************** */

/*
 * smb_odir_close_and_next
 *
 * This function closes the directory passed in (if appropriate) and returns the
 * next directory in the list of directories of the tree of the directory passed
 * in. It requires that the list of directories of the tree be entered in
 * RW_READER mode before being called.
 */
static smb_odir_t *
smb_odir_close_and_next(
    smb_odir_t		*od)
{
	smb_odir_t	*next_od;
	smb_tree_t	*tree;

	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);

	mutex_enter(&od->d_mutex);
	switch (od->d_state) {
	case SMB_ODIR_STATE_OPEN:
		/* The directory is still opened. */
		od->d_refcnt++;
		ASSERT(od->d_refcnt);
		tree = od->d_tree;
		mutex_exit(&od->d_mutex);
		smb_llist_exit(&od->d_tree->t_odir_list);
		smb_odir_close(od);
		smb_odir_release(od);
		smb_llist_enter(&tree->t_odir_list, RW_READER);
		next_od = smb_llist_head(&tree->t_odir_list);
		break;
	case SMB_ODIR_STATE_CLOSING:
	case SMB_ODIR_STATE_CLOSED:
		/*
		 * The odir exists but is closed or is in the process
		 * of being closed.
		 */
		mutex_exit(&od->d_mutex);
		next_od = smb_llist_next(&od->d_tree->t_odir_list, od);
		break;
	default:
		ASSERT(0);
		mutex_exit(&od->d_mutex);
		next_od = smb_llist_next(&od->d_tree->t_odir_list, od);
		break;
	}
	return (next_od);
}

/*
 * smb_odir_delete
 */
static void
smb_odir_delete(
    smb_odir_t		*od)
{
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);
	ASSERT(od->d_state == SMB_ODIR_STATE_CLOSED);
	ASSERT(od->d_refcnt == 0);

	/*
	 * Let's remove the odir from the list of odirs of the tree. This has
	 * to be done before any resources associated with the odir are
	 * released.
	 */
	smb_llist_enter(&od->d_tree->t_odir_list, RW_WRITER);
	smb_llist_remove(&od->d_tree->t_odir_list, od);
	smb_llist_exit(&od->d_tree->t_odir_list);

	smb_node_release(od->d_dir_snode);
	atomic_dec_32(&od->d_tree->t_session->s_dir_cnt);
	smb_idpool_free(&od->d_tree->t_sid_pool, od->d_sid);
	mutex_destroy(&od->d_mutex);
	kmem_cache_free(smb_info.si_cache_odir, od);
}
