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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"@(#)smb_ofile.c	1.12	08/08/08 SMI"

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
 * Ofile State Machine
 * ------------------
 *
 *    +-------------------------+	 T0
 *    |  SMB_OFILE_STATE_OPEN   |<----------- Creation/Allocation
 *    +-------------------------+
 *		    |
 *		    | T1
 *		    |
 *		    v
 *    +-------------------------+
 *    | SMB_OFILE_STATE_CLOSING |
 *    +-------------------------+
 *		    |
 *		    | T2
 *		    |
 *		    v
 *    +-------------------------+    T3
 *    | SMB_OFILE_STATE_CLOSED  |----------> Deletion/Free
 *    +-------------------------+
 *
 * SMB_OFILE_STATE_OPEN
 *
 *    While in this state:
 *      - The ofile is queued in the list of ofiles of its tree.
 *      - References will be given out if the ofile is looked up.
 *
 * SMB_OFILE_STATE_CLOSING
 *
 *    While in this state:
 *      - The ofile is queued in the list of ofiles of its tree.
 *      - References will not be given out if the ofile is looked up.
 *      - The file is closed and the locks held are being released.
 *      - The resources associated with the ofile remain.
 *
 * SMB_OFILE_STATE_CLOSED
 *
 *    While in this state:
 *      - The ofile is queued in the list of ofiles of its tree.
 *      - References will not be given out if the ofile is looked up.
 *      - The resources associated with the ofile remain.
 *
 * Transition T0
 *
 *    This transition occurs in smb_ofile_open(). A new ofile is created and
 *    added to the list of ofiles of a tree.
 *
 * Transition T1
 *
 *    This transition occurs in smb_ofile_close().
 *
 * Transition T2
 *
 *    This transition occurs in smb_ofile_release(). The resources associated
 *    with the ofile are freed as well as the ofile structure. For the
 *    transition to occur, the ofile must be in the SMB_OFILE_STATE_CLOSED
 *    state and the reference count be zero.
 *
 * Comments
 * --------
 *
 *    The state machine of the ofile structures is controlled by 3 elements:
 *      - The list of ofiles of the tree it belongs to.
 *      - The mutex embedded in the structure itself.
 *      - The reference count.
 *
 *    There's a mutex embedded in the ofile structure used to protect its fields
 *    and there's a lock embedded in the list of ofiles of a tree. To
 *    increment or to decrement the reference count the mutex must be entered.
 *    To insert the ofile into the list of ofiles of the tree and to remove
 *    the ofile from it, the lock must be entered in RW_WRITER mode.
 *
 *    Rules of access to a ofile structure:
 *
 *    1) In order to avoid deadlocks, when both (mutex and lock of the ofile
 *       list) have to be entered, the lock must be entered first.
 *
 *    2) All actions applied to an ofile require a reference count.
 *
 *    3) There are 2 ways of getting a reference count. One is when the ofile
 *       is opened. The other one when the ofile is looked up. This translates
 *       into 2 functions: smb_ofile_open() and smb_ofile_lookup_by_fid().
 *
 *    It should be noted that the reference count of an ofile registers the
 *    number of references to the ofile in other structures (such as an smb
 *    request). The reference count is not incremented in these 2 instances:
 *
 *    1) The ofile is open. An ofile is anchored by his state. If there's
 *       no activity involving an ofile currently open, the reference count
 *       of that ofile is zero.
 *
 *    2) The ofile is queued in the list of ofiles of its tree. The fact of
 *       being queued in that list is NOT registered by incrementing the
 *       reference count.
 */
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>

/* Static functions defined further down this file. */
static void		smb_ofile_delete(smb_ofile_t *of);
static smb_ofile_t	*smb_ofile_close_and_next(smb_ofile_t *of);

/*
 * smb_ofile_open
 *
 *
 */
smb_ofile_t *
smb_ofile_open(
    smb_tree_t		*tree,
    smb_node_t		*node,
    uint16_t		pid,
    struct open_param	*op,
    uint16_t		ftype,
    uint32_t		uniqid,
    smb_error_t		*err)
{
	smb_ofile_t	*of;
	uint16_t	fid;

	if (smb_idpool_alloc(&tree->t_fid_pool, &fid)) {
		err->status = NT_STATUS_TOO_MANY_OPENED_FILES;
		err->errcls = ERRDOS;
		err->errcode = ERROR_TOO_MANY_OPEN_FILES;
		return (NULL);
	}

	of = kmem_cache_alloc(tree->t_server->si_cache_ofile, KM_SLEEP);
	bzero(of, sizeof (smb_ofile_t));
	of->f_magic = SMB_OFILE_MAGIC;
	of->f_refcnt = 1;
	of->f_fid = fid;
	of->f_uniqid = uniqid;
	of->f_opened_by_pid = pid;
	of->f_granted_access = op->desired_access;
	of->f_share_access = op->share_access;
	of->f_create_options = op->create_options;
	of->f_cr = tree->t_user->u_cred;
	crhold(of->f_cr);
	of->f_ftype = ftype;
	of->f_server = tree->t_server;
	of->f_session = tree->t_user->u_session;
	of->f_user = tree->t_user;
	of->f_tree = tree;
	of->f_node = node;
	mutex_init(&of->f_mutex, NULL, MUTEX_DEFAULT, NULL);
	of->f_state = SMB_OFILE_STATE_OPEN;

	if (ftype == SMB_FTYPE_MESG_PIPE) {
		of->f_pipe = kmem_zalloc(sizeof (smb_opipe_t), KM_SLEEP);
	} else {
		ASSERT(ftype == SMB_FTYPE_DISK); /* Regular file, not a pipe */
		ASSERT(node);
		if (crgetuid(of->f_cr) == node->attr.sa_vattr.va_uid) {
			/*
			 * Add this bit for the file's owner even if it's not
			 * specified in the request (Windows behavior).
			 */
			of->f_granted_access |= FILE_READ_ATTRIBUTES;
		}

		if (node->vp->v_type == VREG) {
			of->f_mode =
			    smb_fsop_amask_to_omode(of->f_granted_access);
			if (smb_fsop_open(node, of->f_mode, of->f_cr) != 0) {
				of->f_magic = 0;
				mutex_destroy(&of->f_mutex);
				crfree(of->f_cr);
				smb_idpool_free(&tree->t_fid_pool, of->f_fid);
				kmem_cache_free(tree->t_server->si_cache_ofile,
				    of);
				err->status = NT_STATUS_ACCESS_DENIED;
				err->errcls = ERRDOS;
				err->errcode = ERROR_ACCESS_DENIED;
				return (NULL);
			}
		}

		if (tree->t_flags & SMB_TREE_READONLY)
			of->f_flags |= SMB_OFLAGS_READONLY;

		if (op->created_readonly)
			node->readonly_creator = of;

		smb_llist_enter(&node->n_ofile_list, RW_WRITER);
		smb_llist_insert_tail(&node->n_ofile_list, of);
		smb_llist_exit(&node->n_ofile_list);
	}
	smb_llist_enter(&tree->t_ofile_list, RW_WRITER);
	smb_llist_insert_tail(&tree->t_ofile_list, of);
	smb_llist_exit(&tree->t_ofile_list);
	atomic_inc_32(&tree->t_server->sv_open_files);
	atomic_inc_32(&of->f_session->s_file_cnt);

	return (of);
}

/*
 * smb_ofile_close
 *
 *
 */
void
smb_ofile_close(
    smb_ofile_t		*of,
    uint32_t		last_wtime)
{
	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);
	ASSERT(of->f_refcnt);
	switch (of->f_state) {
	case SMB_OFILE_STATE_OPEN: {

		of->f_state = SMB_OFILE_STATE_CLOSING;
		mutex_exit(&of->f_mutex);

		if (of->f_ftype == SMB_FTYPE_MESG_PIPE) {
			smb_opipe_close(of);
		} else {
			/*
			 * For files created readonly, propagate the readonly
			 * bit to the ofile now
			 */

			if (of->f_node->readonly_creator == of) {
				of->f_node->attr.sa_dosattr |=
				    FILE_ATTRIBUTE_READONLY;
				of->f_node->what |= SMB_AT_DOSATTR;
				of->f_node->readonly_creator = NULL;
			}

			smb_ofile_close_timestamp_update(of, last_wtime);
			smb_commit_delete_on_close(of);
			smb_oplock_release(of->f_node, B_FALSE);
			smb_fsop_unshrlock(of->f_cr, of->f_node, of->f_uniqid);
			smb_node_destroy_lock_by_ofile(of->f_node, of);

			if (of->f_node->vp->v_type == VREG)
				(void) smb_fsop_close(of->f_node, of->f_mode,
				    of->f_cr);

			/*
			 * Cancel any notify change requests related
			 * to this open instance.
			 */
			if (of->f_node->flags & NODE_FLAGS_NOTIFY_CHANGE)
				smb_process_file_notify_change_queue(of);
		}
		atomic_dec_32(&of->f_tree->t_server->sv_open_files);

		mutex_enter(&of->f_mutex);
		ASSERT(of->f_refcnt);
		ASSERT(of->f_state == SMB_OFILE_STATE_CLOSING);
		of->f_state = SMB_OFILE_STATE_CLOSED;
		mutex_exit(&of->f_mutex);
		return;
	}
	case SMB_OFILE_STATE_CLOSED:
	case SMB_OFILE_STATE_CLOSING:
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&of->f_mutex);
}

/*
 * smb_ofile_close_all
 *
 *
 */
void
smb_ofile_close_all(
    smb_tree_t		*tree)
{
	smb_ofile_t	*of;

	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	smb_llist_enter(&tree->t_ofile_list, RW_READER);
	of = smb_llist_head(&tree->t_ofile_list);
	while (of) {
		ASSERT(of->f_magic == SMB_OFILE_MAGIC);
		ASSERT(of->f_tree == tree);
		of = smb_ofile_close_and_next(of);
	}
	smb_llist_exit(&tree->t_ofile_list);
}

/*
 * smb_ofiles_close_by_pid
 *
 *
 */
void
smb_ofile_close_all_by_pid(
    smb_tree_t		*tree,
    uint16_t		pid)
{
	smb_ofile_t	*of;

	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	smb_llist_enter(&tree->t_ofile_list, RW_READER);
	of = smb_llist_head(&tree->t_ofile_list);
	while (of) {
		ASSERT(of->f_magic == SMB_OFILE_MAGIC);
		ASSERT(of->f_tree == tree);
		if (of->f_opened_by_pid == pid) {
			of = smb_ofile_close_and_next(of);
		} else {
			of = smb_llist_next(&tree->t_ofile_list, of);
		}
	}
	smb_llist_exit(&tree->t_ofile_list);
}

/*
 * smb_ofile_release
 *
 */
void
smb_ofile_release(
    smb_ofile_t		*of)
{
	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);
	ASSERT(of->f_refcnt);
	of->f_refcnt--;
	switch (of->f_state) {
	case SMB_OFILE_STATE_OPEN:
	case SMB_OFILE_STATE_CLOSING:
		break;

	case SMB_OFILE_STATE_CLOSED:
		if (of->f_refcnt == 0) {
			mutex_exit(&of->f_mutex);
			smb_ofile_delete(of);
			return;
		}
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&of->f_mutex);
}

/*
 * smb_ofile_lookup_by_fid
 *
 * Find the open file whose fid matches the one specified in the request.
 * If we can't find the fid or the shares (trees) don't match, we have a
 * bad fid.
 */
smb_ofile_t *
smb_ofile_lookup_by_fid(
    smb_tree_t		*tree,
    uint16_t		fid)
{
	smb_llist_t	*of_list;
	smb_ofile_t	*of;

	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	of_list = &tree->t_ofile_list;

	smb_llist_enter(of_list, RW_READER);
	of = smb_llist_head(of_list);
	while (of) {
		ASSERT(of->f_magic == SMB_OFILE_MAGIC);
		ASSERT(of->f_tree == tree);
		if (of->f_fid == fid) {
			mutex_enter(&of->f_mutex);
			if (of->f_state != SMB_OFILE_STATE_OPEN) {
				mutex_exit(&of->f_mutex);
				smb_llist_exit(of_list);
				return (NULL);
			}
			of->f_refcnt++;
			mutex_exit(&of->f_mutex);
			break;
		}
		of = smb_llist_next(of_list, of);
	}
	smb_llist_exit(of_list);
	return (of);
}

/*
 * smb_ofile_set_flags
 *
 * Return value:
 *
 *	Current flags value
 *
 */
void
smb_ofile_set_flags(
    smb_ofile_t		*of,
    uint32_t		flags)
{
	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);
	ASSERT(of->f_refcnt);

	mutex_enter(&of->f_mutex);
	of->f_flags |= flags;
	mutex_exit(&of->f_mutex);
}
/*
 * smb_ofile_seek
 *
 * Return value:
 *
 *	0		Success
 *	EINVAL		Unknown mode
 *	EOVERFLOW	offset too big
 *
 */
int
smb_ofile_seek(
    smb_ofile_t		*of,
    ushort_t		mode,
    int32_t		off,
    uint32_t		*retoff)
{
	u_offset_t	newoff = 0;
	int		rc = 0;

	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);
	ASSERT(of->f_refcnt);

	mutex_enter(&of->f_mutex);
	switch (mode) {
	case SMB_SEEK_SET:
		if (off < 0)
			newoff = 0;
		else
			newoff = (u_offset_t)off;
		break;

	case SMB_SEEK_CUR:
		if (off < 0 && (-off) > of->f_seek_pos)
			newoff = 0;
		else
			newoff = of->f_seek_pos + (u_offset_t)off;
		break;

	case SMB_SEEK_END:
		if (off < 0 && (-off) > of->f_node->attr.sa_vattr.va_size)
			newoff = 0;
		else
			newoff = of->f_node->attr.sa_vattr.va_size +
			    (u_offset_t)off;
		break;

	default:
		mutex_exit(&of->f_mutex);
		return (EINVAL);
	}

	/*
	 * See comments at the beginning of smb_seek.c.
	 * If the offset is greater than UINT_MAX, we will return an error.
	 */

	if (newoff > UINT_MAX) {
		rc = EOVERFLOW;
	} else {
		of->f_seek_pos = newoff;
		*retoff = (uint32_t)newoff;
	}
	mutex_exit(&of->f_mutex);
	return (rc);
}

/*
 * smb_ofile_close_timestamp_update
 *
 * The last_wtime is specified in the request received
 * from the client. If it is neither 0 nor -1, this time
 * should be used as the file's mtime. It must first be
 * converted from the server's localtime (as received in
 * the client's request) to GMT.
 */
void
smb_ofile_close_timestamp_update(
    smb_ofile_t		*of,
    uint32_t		last_wtime)
{
	smb_node_t	*node;
	timestruc_t	mtime, atime;
	unsigned int	what = 0;

	mtime.tv_sec = 0;
	mtime.tv_nsec = 0;

	if (last_wtime != 0 && last_wtime != 0xFFFFFFFF) {
		mtime.tv_sec = last_wtime + of->f_server->si_gmtoff;
		what |= SMB_AT_MTIME;
	}

	/*
	 * NODE_FLAGS_SYNCATIME is set whenever something is
	 * written to a file.
	 */
	node = of->f_node;
	if (node->flags & NODE_FLAGS_SYNCATIME) {
		what |= SMB_AT_ATIME;
		(void) microtime(&atime);
	}

	smb_node_set_time(node, 0, &mtime, &atime, 0, what);
	(void) smb_sync_fsattr(NULL, of->f_cr, of->f_node);
}

/*
 * smb_ofile_is_open
 *
 */
boolean_t
smb_ofile_is_open(
    smb_ofile_t		*of)
{
	boolean_t	rc = B_FALSE;

	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);
	if (of->f_state == SMB_OFILE_STATE_OPEN) {
		rc = B_TRUE;
	}
	mutex_exit(&of->f_mutex);
	return (rc);
}

/* *************************** Static Functions ***************************** */

/*
 * smb_ofile_close_and_next
 *
 * This function closes the file passed in (if appropriate) and returns the
 * next open file in the list of open files of the tree of the open file passed
 * in. It requires that the list of open files of the tree be entered in
 * RW_READER mode before being called.
 */
static smb_ofile_t *
smb_ofile_close_and_next(
    smb_ofile_t		*of)
{
	smb_ofile_t	*next_of;
	smb_tree_t	*tree;

	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);
	switch (of->f_state) {
	case SMB_OFILE_STATE_OPEN:
		/* The file is still open. */
		of->f_refcnt++;
		ASSERT(of->f_refcnt);
		tree = of->f_tree;
		mutex_exit(&of->f_mutex);
		smb_llist_exit(&of->f_tree->t_ofile_list);
		smb_ofile_close(of, 0);
		smb_ofile_release(of);
		smb_llist_enter(&tree->t_ofile_list, RW_READER);
		next_of = smb_llist_head(&tree->t_ofile_list);
		break;
	case SMB_OFILE_STATE_CLOSING:
	case SMB_OFILE_STATE_CLOSED:
		/*
		 * The ofile exists but is closed or
		 * in the process being closed.
		 */
		mutex_exit(&of->f_mutex);
		next_of = smb_llist_next(&of->f_tree->t_ofile_list, of);
		break;
	default:
		ASSERT(0);
		mutex_exit(&of->f_mutex);
		next_of = smb_llist_next(&of->f_tree->t_ofile_list, of);
		break;
	}
	return (next_of);
}

/*
 * smb_ofile_delete
 *
 *
 */
static void
smb_ofile_delete(
    smb_ofile_t		*of)
{
	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);
	ASSERT(of->f_refcnt == 0);
	ASSERT(of->f_state == SMB_OFILE_STATE_CLOSED);

	/*
	 * Let's remove the ofile from the list of ofiles of the tree. This has
	 * to be done before any resources associated with the ofile are
	 * released.
	 */
	smb_llist_enter(&of->f_tree->t_ofile_list, RW_WRITER);
	smb_llist_remove(&of->f_tree->t_ofile_list, of);
	smb_llist_exit(&of->f_tree->t_ofile_list);
	atomic_dec_32(&of->f_session->s_file_cnt);

	if (of->f_ftype == SMB_FTYPE_MESG_PIPE) {
		kmem_free(of->f_pipe, sizeof (smb_opipe_t));
		of->f_pipe = NULL;
	} else {
		ASSERT(of->f_ftype == SMB_FTYPE_DISK);
		ASSERT(of->f_node != NULL);
		smb_llist_enter(&of->f_node->n_ofile_list, RW_WRITER);
		smb_llist_remove(&of->f_node->n_ofile_list, of);
		smb_llist_exit(&of->f_node->n_ofile_list);
		smb_node_release(of->f_node);
	}

	of->f_magic = (uint32_t)~SMB_OFILE_MAGIC;
	mutex_destroy(&of->f_mutex);
	crfree(of->f_cr);
	smb_idpool_free(&of->f_tree->t_fid_pool, of->f_fid);
	kmem_cache_free(of->f_tree->t_server->si_cache_ofile, of);
}

/*
 * smb_ofile_access
 *
 * This function will check to see if the access requested is granted.
 * Returns NT status codes.
 */
uint32_t
smb_ofile_access(smb_ofile_t *of, cred_t *cr, uint32_t access)
{

	if ((of == NULL) || (cr == kcred))
		return (NT_STATUS_SUCCESS);

	/*
	 * If the request is for something
	 * I don't grant it is an error
	 */
	if (~(of->f_granted_access) & access) {
		if (!(of->f_granted_access & ACCESS_SYSTEM_SECURITY) &&
		    (access & ACCESS_SYSTEM_SECURITY)) {
			return (NT_STATUS_PRIVILEGE_NOT_HELD);
		}
		return (NT_STATUS_ACCESS_DENIED);
	}

	return (NT_STATUS_SUCCESS);
}


/*
 * smb_ofile_open_check
 *
 * check file sharing rules for current open request
 * against existing open instances of the same file
 *
 * Returns NT_STATUS_SHARING_VIOLATION if there is any
 * sharing conflict, otherwise returns NT_STATUS_SUCCESS.
 */
uint32_t
smb_ofile_open_check(
    smb_ofile_t *of,
    cred_t *cr,
    uint32_t desired_access,
    uint32_t share_access)
{
	smb_node_t *node;

	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	node = of->f_node;

	mutex_enter(&of->f_mutex);

	if (of->f_state != SMB_OFILE_STATE_OPEN) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_INVALID_HANDLE);
	}

	/*
	 * It appears that share modes are not relevant to
	 * directories, but this check will remain as it is not
	 * clear whether it was originally put here for a reason.
	 */
	if (node->attr.sa_vattr.va_type == VDIR) {
		if (SMB_DENY_RW(of->f_share_access) &&
		    (node->n_orig_uid != crgetuid(cr))) {
			mutex_exit(&of->f_mutex);
			return (NT_STATUS_SHARING_VIOLATION);
		}

		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SUCCESS);
	}

	/* if it's just meta data */
	if ((of->f_granted_access & FILE_DATA_ALL) == 0) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SUCCESS);
	}

	/*
	 * Check requested share access against the
	 * open granted (desired) access
	 */
	if (SMB_DENY_DELETE(share_access) && (of->f_granted_access & DELETE)) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SHARING_VIOLATION);
	}

	if (SMB_DENY_READ(share_access) &&
	    (of->f_granted_access & (FILE_READ_DATA | FILE_EXECUTE))) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SHARING_VIOLATION);
	}

	if (SMB_DENY_WRITE(share_access) &&
	    (of->f_granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA))) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SHARING_VIOLATION);
	}

	/* check requested desired access against the open share access */
	if (SMB_DENY_DELETE(of->f_share_access) && (desired_access & DELETE)) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SHARING_VIOLATION);
	}

	if (SMB_DENY_READ(of->f_share_access) &&
	    (desired_access & (FILE_READ_DATA | FILE_EXECUTE))) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SHARING_VIOLATION);
	}

	if (SMB_DENY_WRITE(of->f_share_access) &&
	    (desired_access & (FILE_WRITE_DATA | FILE_APPEND_DATA))) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SHARING_VIOLATION);
	}

	mutex_exit(&of->f_mutex);
	return (NT_STATUS_SUCCESS);
}

/*
 * smb_ofile_rename_check
 *
 * An open file can be renamed if
 *
 *  1. isn't opened for data writing or deleting
 *
 *  2. Opened with "Deny Delete" share mode
 *         But not opened for data reading or executing
 *         (opened for accessing meta data)
 */

uint32_t
smb_ofile_rename_check(smb_ofile_t *of)
{
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);

	if (of->f_state != SMB_OFILE_STATE_OPEN) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_INVALID_HANDLE);
	}

	if (of->f_granted_access &
	    (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE)) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SHARING_VIOLATION);
	}

	if ((of->f_share_access & FILE_SHARE_DELETE) == 0) {
		if (of->f_granted_access &
		    (FILE_READ_DATA | FILE_EXECUTE)) {
			mutex_exit(&of->f_mutex);
			return (NT_STATUS_SHARING_VIOLATION);
		}
	}

	mutex_exit(&of->f_mutex);
	return (NT_STATUS_SUCCESS);
}

/*
 * smb_ofile_delete_check
 *
 * An open file can be deleted only if opened for
 * accessing meta data. Share modes aren't important
 * in this case.
 *
 * NOTE: there is another mechanism for deleting an
 * open file that NT clients usually use.
 * That's setting "Delete on close" flag for an open
 * file.  In this way the file will be deleted after
 * last close. This flag can be set by SmbTrans2SetFileInfo
 * with FILE_DISPOSITION_INFO information level.
 * For setting this flag, the file should be opened by
 * DELETE access in the FID that is passed in the Trans2
 * request.
 */

uint32_t
smb_ofile_delete_check(smb_ofile_t *of)
{
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);

	if (of->f_state != SMB_OFILE_STATE_OPEN) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_INVALID_HANDLE);
	}

	if (of->f_granted_access &
	    (FILE_READ_DATA | FILE_WRITE_DATA |
	    FILE_APPEND_DATA | FILE_EXECUTE | DELETE)) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_SHARING_VIOLATION);
	}

	mutex_exit(&of->f_mutex);
	return (NT_STATUS_SUCCESS);
}
