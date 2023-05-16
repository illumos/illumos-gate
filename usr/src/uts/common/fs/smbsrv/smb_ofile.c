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
 * Copyright 2011-2020 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2016 Syneto S.R.L. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 */

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
 *   |          |
 *   |          |
 *   |          v
 *   |  +-------------------+     +-------------------+   +-------------------+
 *   |  |       USER        |<--->|       USER        |...|       USER        |
 *   |  +-------------------+     +-------------------+   +-------------------+
 *   |
 *   |
 *   v
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
 *    |  SMB_OFILE_STATE_OPEN   |<--+-------- Creation/Allocation
 *    +-------------------------+   |
 *	    |		|	    | T5
 *	    |		|	+---------------------------+
 *	    |		|	| SMB_OFILE_STATE_RECONNECT |
 *	    |		|	+---------------------------+
 *	    |		|	    ^
 *	    |		v	    |
 *	    |   +---------------+   |
 *	    |   | STATE_SAVE_DH |   |
 *	    |   | STATE_SAVING  |   |
 *	    |   +---------------+   |
 *	    |		|	    | T4
 *	    | T1	| T3	+--------------------------+
 *	    |		+------>| SMB_OFILE_STATE_ORPHANED |
 *	    v			+--------------------------+
 *    +-------------------------+   |		|
 *    | SMB_OFILE_STATE_CLOSING |<--+ T6	| T7
 *    +-------------------------+		|
 *	    |		^			v
 *	    | T2	| T8	+-------------------------+
 *	    |		+-------| SMB_OFILE_STATE_EXPIRED |
 *	    v			+-------------------------+
 *    +-------------------------+
 *    | SMB_OFILE_STATE_CLOSED  |----------> Deletion/Free
 *    +-------------------------+    T9
 *
 * SMB_OFILE_STATE_OPEN
 *
 *    While in this state:
 *      - The ofile is queued in the list of ofiles of its tree.
 *      - References will be given out if the ofile is looked up.
 *
 * SMB_OFILE_STATE_SAVE_DH
 *
 *    Similar to state _CLOSING, but instead of deleting the ofile,
 *    it leaves the ofile in state _ORPHANED (for later reclaim).
 *    Will move to _SAVING after last ref, then _ORPHANED.
 *
 *    While in this state:
 *	- The ofile has been marked for preservation during a
 *	  walk of the tree ofile list to close multiple files.
 *	- References will not be given out if the ofile is looked up,
 *	  except for oplock break processing.
 *	- Still affects Sharing Violation rules
 *
 * SMB_OFILE_STATE_SAVING
 *
 *    Transient state used to keep oplock break processing out
 *    while the ofile moves to state _ORPHANED.
 *
 *    While in this state:
 *	- References will not be given out if the ofile is looked up,
 *	  except for oplock break processing.
 *	- Still affects Sharing Violation rules
 *
 * SMB_OFILE_STATE_CLOSING
 *
 *    Close has been requested.  Stay in this state until the last
 *    ref. is gone, then move to state _CLOSED
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
 * SMB_OFILE_STATE_ORPHANED
 *
 *    While in this state:
 *      - The ofile is queued in the list of ofiles of its tree.
 *      - Can be reclaimed by the original owner
 *      - References will not be given out if the ofile is looked up.
 *      - All the tree, user, and session "up" pointers are NULL!
 *      - Will eventually be "expired" if not reclaimed
 *      - Can be closed if its oplock is broken
 *      - Still affects Sharing Violation rules
 *
 * SMB_OFILE_STATE_EXPIRED
 *
 *    While in this state:
 *      - The ofile is queued in the list of ofiles of its tree.
 *      - References will not be given out if the ofile is looked up.
 *      - The ofile has not been reclaimed and will soon be closed,
 *        due to, for example, the durable handle timer expiring, or its
 *        oplock being broken.
 *      - Cannot be reclaimed at this point
 *
 * SMB_OFILE_STATE_RECONNECT
 *
 *    Transient state used to keep oplock break processing out
 *    while the ofile moves from state _ORPHANED to _OPEN.
 *
 *    While in this state:
 *      - The ofile is being reclaimed; do not touch it.
 *      - References will not be given out if the ofile is looked up.
 *      - Still affects Sharing Violation rules
 *	- see smb2_dh_reconnect() for which members need to be avoided
 *
 * Transition T0
 *
 *    This transition occurs in smb_ofile_open(). A new ofile is created and
 *    added to the list of ofiles of a tree.
 *
 * Transition T1
 *
 *    This transition occurs in smb_ofile_close(). Note that this only happens
 *    when we determine that an ofile should be closed in spite of its durable
 *    handle properties.
 *
 * Transition T2
 *
 *    This transition occurs in smb_ofile_release(). The resources associated
 *    with the ofile are freed as well as the ofile structure. For the
 *    transition to occur, the ofile must be in the SMB_OFILE_STATE_CLOSED
 *    state and the reference count be zero.
 *
 * Transition T3
 *
 *    This transition occurs in smb_ofile_orphan_dh(). It happens during an
 *    smb2 logoff, or during a session disconnect when certain conditions are
 *    met. The ofile and structures above it will be kept around until the ofile
 *    either gets reclaimed, expires after f_timeout_offset nanoseconds, or its
 *    oplock is broken.
 *
 * Transition T4
 *
 *    This transition occurs in smb2_dh_reconnect(). An smb2 create request
 *    with a DURABLE_HANDLE_RECONNECT(_V2) create context has been
 *    recieved from the original owner. If leases are supported or it's
 *    RECONNECT_V2, reconnect is subject to additional conditions. The ofile
 *    will be unwired from the old, disconnected session, tree, and user,
 *    and wired up to its new context.
 *
 * Transition T5
 *
 *    This transition occurs in smb2_dh_reconnect(). The ofile has been
 *    successfully reclaimed.
 *
 * Transition T6
 *
 *    This transition occurs in smb_ofile_close(). The ofile has been orphaned
 *    while some thread was blocked, and that thread closes the ofile. Can only
 *    happen when the ofile is orphaned due to an SMB2 LOGOFF request.
 *
 * Transition T7
 *
 *    This transition occurs in smb_session_durable_timers() and
 *    smb_oplock_send_break(). The ofile will soon be closed.
 *    In the former case, f_timeout_offset nanoseconds have passed since
 *    the ofile was orphaned. In the latter, an oplock break occured
 *    on the ofile while it was orphaned.
 *
 * Transition T8
 *
 *    This transition occurs in smb_ofile_close().
 *
 * Transition T9
 *
 *    This transition occurs in smb_ofile_delete().
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
 *       list) have to be entered, the lock must be entered first. Additionally,
 *       f_mutex must not be held when removing the ofile from sv_persistid_ht.
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
 *    1) The ofile is open. An ofile is anchored by its state. If there's
 *       no activity involving an ofile currently open, the reference count
 *       of that ofile is zero.
 *
 *    2) The ofile is queued in the list of ofiles of its tree. The fact of
 *       being queued in that list is NOT registered by incrementing the
 *       reference count.
 */
#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <sys/time.h>
#include <sys/random.h>

static boolean_t smb_ofile_is_open_locked(smb_ofile_t *);
static void smb_ofile_delete(void *arg);
static void smb_ofile_save_dh(void *arg);

static int smb_ofile_netinfo_encode(smb_ofile_t *, uint8_t *, size_t,
    uint32_t *);
static int smb_ofile_netinfo_init(smb_ofile_t *, smb_netfileinfo_t *);
static void smb_ofile_netinfo_fini(smb_netfileinfo_t *);

/*
 * The uniq_fid is a CIFS-server-wide unique identifier for an ofile
 * which is used to uniquely identify open instances for the
 * VFS share reservation and POSIX locks.
 */
static volatile uint32_t smb_fids = 0;
#define	SMB_UNIQ_FID()	atomic_inc_32_nv(&smb_fids)

/*
 * AVL Comparator for t_ofile_list
 *
 * NB: can only access f_fid because smb_ofile_lookup_by_fid
 * doesn't pass in an entire smb_ofile_t.
 */
int
smb_ofile_avl_compare(const void *v1, const void *v2)
{
	const smb_ofile_t *of1 = v1;
	const smb_ofile_t *of2 = v2;

	return (AVL_CMP(of1->f_fid, of2->f_fid));
}

/*
 * smb_ofile_alloc
 * Allocate an ofile and fill in it's "up" pointers, but
 * do NOT link it into the tree's list of ofiles or the
 * node's list of ofiles.  An ofile in this state is a
 * "proposed" open passed to the oplock break code.
 *
 * If we don't get as far as smb_ofile_open with this OF,
 * call smb_ofile_free() to free this object.
 *
 * Note: The following sr members may be null during
 * persistent handle import: session, uid_usr, tid_tree
 */
smb_ofile_t *
smb_ofile_alloc(
    smb_request_t	*sr,
    smb_arg_open_t	*op,
    smb_node_t		*node, /* optional (may be NULL) */
    uint16_t		ftype,
    uint16_t		tree_fid)
{
	smb_user_t	*user = sr->uid_user;	/* optional */
	smb_tree_t	*tree = sr->tid_tree;	/* optional */
	smb_ofile_t	*of;

	of = kmem_cache_alloc(smb_cache_ofile, KM_SLEEP);
	bzero(of, sizeof (smb_ofile_t));
	of->f_magic = SMB_OFILE_MAGIC;

	mutex_init(&of->f_mutex, NULL, MUTEX_DEFAULT, NULL);
	list_create(&of->f_notify.nc_waiters, sizeof (smb_request_t),
	    offsetof(smb_request_t, sr_waiters));
	mutex_init(&of->dh_nvlock, NULL, MUTEX_DEFAULT, NULL);

	of->f_state = SMB_OFILE_STATE_ALLOC;
	of->f_refcnt = 1;
	of->f_ftype = ftype;
	of->f_fid = tree_fid;
	/* of->f_persistid see smb2_create */
	of->f_uniqid = SMB_UNIQ_FID();
	of->f_opened_by_pid = sr->smb_pid;
	of->f_granted_access = op->desired_access;
	of->f_share_access = op->share_access;
	of->f_create_options = op->create_options;
	if (user != NULL) {
		if ((op->create_options & FILE_OPEN_FOR_BACKUP_INTENT) != 0)
			of->f_cr = smb_user_getprivcred(user);
		else
			of->f_cr = user->u_cred;
		crhold(of->f_cr);
	}
	of->f_server = sr->sr_server;
	of->f_session = sr->session;	/* may be NULL */

	(void) memset(of->f_lock_seq, -1, SMB_OFILE_LSEQ_MAX);

	of->f_mode = smb_fsop_amask_to_omode(of->f_granted_access);
	if ((of->f_granted_access & FILE_DATA_ALL) == FILE_EXECUTE)
		of->f_flags |= SMB_OFLAGS_EXECONLY;

	/*
	 * In case a lease is requested, copy the lease keys now so
	 * any oplock breaks during open don't break those on our
	 * other handles that might have the same lease.
	 */
	bcopy(op->lease_key, of->TargetOplockKey, SMB_LEASE_KEY_SZ);
	bcopy(op->parent_lease_key, of->ParentOplockKey, SMB_LEASE_KEY_SZ);

	/*
	 * grab a ref for of->f_user and of->f_tree
	 * We know the user and tree must be "live" because
	 * this SR holds references to them.  The node ref. is
	 * held by our caller, until smb_ofile_open puts this
	 * ofile on the node ofile list with smb_node_add_ofile.
	 */
	if (user != NULL) {
		smb_user_hold_internal(user);
		of->f_user = user;
	}
	if (tree != NULL) {
		smb_tree_hold_internal(tree);
		of->f_tree = tree;
	}
	of->f_node = node;	/* may be NULL */

	return (of);
}

/*
 * smb_ofile_open
 *
 * Complete an open on an ofile that was previously allocated by
 * smb_ofile_alloc, by putting it on the tree ofile list and
 * (if it's a file) the node ofile list.
 */
void
smb_ofile_open(
    smb_request_t	*sr,
    smb_arg_open_t	*op,
    smb_ofile_t		*of)
{
	smb_tree_t	*tree = sr->tid_tree;
	smb_node_t	*node = of->f_node;

	ASSERT(of->f_state == SMB_OFILE_STATE_ALLOC);
	ASSERT(of->f_fid != 0);

	of->f_state = SMB_OFILE_STATE_OPEN;

	switch (of->f_ftype) {
	case SMB_FTYPE_BYTE_PIPE:
	case SMB_FTYPE_MESG_PIPE:
		/* See smb_opipe_open. */
		of->f_pipe = op->pipe;
		smb_server_inc_pipes(of->f_server);
		break;
	case SMB_FTYPE_DISK:
	case SMB_FTYPE_PRINTER:
		/* Regular file, not a pipe */
		ASSERT(node != NULL);

		smb_node_inc_open_ofiles(node);
		smb_node_add_ofile(node, of);
		smb_node_ref(node);
		smb_server_inc_files(of->f_server);
		break;
	default:
		ASSERT(0);
	}
	ASSERT(of->f_fid != 0);
	smb_lavl_enter(&tree->t_ofile_list, RW_WRITER);
	smb_lavl_insert(&tree->t_ofile_list, of);
	smb_lavl_exit(&tree->t_ofile_list);
	atomic_inc_32(&tree->t_open_files);
	atomic_inc_32(&of->f_session->s_file_cnt);

}

/*
 * smb_ofile_close
 *
 * Incoming states: (where from)
 *   SMB_OFILE_STATE_OPEN  protocol close, smb_ofile_drop
 *   SMB_OFILE_STATE_EXPIRED  called via smb2_dh_expire
 *   SMB_OFILE_STATE_ORPHANED  smb2_dh_shutdown
 *
 * Not that this enters the of->node->n_ofile_list rwlock as reader,
 * (via smb_oplock_close) so this must not be called while holding
 * that rwlock.
 */
void
smb_ofile_close(smb_ofile_t *of, int32_t mtime_sec)
{
	smb_attr_t *pa;

	SMB_OFILE_VALID(of);

	if (of->f_ftype == SMB_FTYPE_DISK) {
		smb_oplock_close(of);
	}

	mutex_enter(&of->f_mutex);
	ASSERT(of->f_refcnt);

	switch (of->f_state) {
	case SMB_OFILE_STATE_OPEN:
	case SMB_OFILE_STATE_ORPHANED:
	case SMB_OFILE_STATE_EXPIRED:
		of->f_state = SMB_OFILE_STATE_CLOSING;
		mutex_exit(&of->f_mutex);
		break;
	default:
		mutex_exit(&of->f_mutex);
		return;
	}

	/*
	 * Only one thread here (the one that that set f_state closing)
	 */
	switch (of->f_ftype) {
	case SMB_FTYPE_BYTE_PIPE:
	case SMB_FTYPE_MESG_PIPE:
		smb_opipe_close(of);
		smb_server_dec_pipes(of->f_server);
		break;

	case SMB_FTYPE_DISK:
		if (of->dh_persist)
			smb2_dh_close_persistent(of);
		if (of->f_persistid != 0)
			smb_ofile_del_persistid(of);
		/* FALLTHROUGH */

	case SMB_FTYPE_PRINTER: /* or FTYPE_DISK */
		/*
		 * In here we make changes to of->f_pending_attr
		 * while not holding of->f_mutex.  This is OK
		 * because we've changed f_state to CLOSING,
		 * so no more threads will take this path.
		 */
		pa = &of->f_pending_attr;
		if (mtime_sec != 0) {
			pa->sa_vattr.va_mtime.tv_sec = mtime_sec;
			pa->sa_mask |= SMB_AT_MTIME;
		}

		if (of->f_flags & SMB_OFLAGS_SET_DELETE_ON_CLOSE) {
			/* We delete using the on-disk name. */
			uint32_t flags = SMB_CASE_SENSITIVE;
			(void) smb_node_set_delete_on_close(of->f_node,
			    of->f_cr, flags);
		}
		smb_fsop_unshrlock(of->f_cr, of->f_node, of->f_uniqid);
		smb_node_destroy_lock_by_ofile(of->f_node, of);

		if (smb_node_is_file(of->f_node)) {
			(void) smb_fsop_close(of->f_node, of->f_mode,
			    of->f_cr);
		} else {
			/*
			 * If there was an odir, close it.
			 */
			if (of->f_odir != NULL)
				smb_odir_close(of->f_odir);
			/*
			 * Cancel any notify change requests that
			 * might be watching this open file (dir),
			 * and unsubscribe it from node events.
			 *
			 * Can't hold f_mutex when calling smb_notify_ofile.
			 * Don't really need it when unsubscribing, but
			 * harmless, and consistent with subscribing.
			 */
			if (of->f_notify.nc_subscribed)
				smb_notify_ofile(of,
				    FILE_ACTION_HANDLE_CLOSED, NULL);
			mutex_enter(&of->f_mutex);
			if (of->f_notify.nc_subscribed) {
				of->f_notify.nc_subscribed = B_FALSE;
				smb_node_fcn_unsubscribe(of->f_node);
				of->f_notify.nc_filter = 0;
			}
			mutex_exit(&of->f_mutex);
		}
		if (smb_node_dec_open_ofiles(of->f_node) == 0) {
			/*
			 * Last close.  If we're not deleting
			 * the file, apply any pending attrs.
			 * Leave allocsz zero when no open files,
			 * just to avoid confusion, because it's
			 * only updated when there are opens.
			 * XXX: Just do this on _every_ close.
			 */
			mutex_enter(&of->f_node->n_mutex);
			if (of->f_node->flags & NODE_FLAGS_DELETE_ON_CLOSE) {
				smb_node_delete_on_close(of->f_node);
				pa->sa_mask = 0;
			}
			of->f_node->n_allocsz = 0;
			mutex_exit(&of->f_node->n_mutex);
		}
		if (pa->sa_mask != 0) {
			/*
			 * Commit any pending attributes from
			 * the ofile we're closing.  Note that
			 * we pass NULL as the ofile to setattr
			 * so it will write to the file system
			 * and not keep anything on the ofile.
			 */
			(void) smb_node_setattr(NULL, of->f_node,
			    of->f_cr, NULL, pa);
		}
		/*
		 * Don't want the performance cost of generating
		 * change notify events on every write.  Instead:
		 * Keep track of the fact that we have written
		 * data via this handle, and do change notify
		 * work on the first write, and during close.
		 */
		if (of->f_written) {
			smb_node_notify_modified(of->f_node);
		}

		smb_server_dec_files(of->f_server);
		break;
	}

	/*
	 * Keep f_state == SMB_OFILE_STATE_CLOSING
	 * until the last ref. is dropped, in
	 * smb_ofile_release()
	 */
}

/*
 * "Destructor" function for smb_ofile_close_all, and
 * smb_ofile_close_all_by_pid, called after the llist lock
 * for tree list has been exited.  Our job is to either
 * close this ofile, or (if durable) set state _SAVE_DH.
 *
 * The next interesting thing happens when the last ref.
 * on this ofile calls smb_ofile_release(), where we
 * eihter delete the ofile, or (if durable) leave it
 * in the persistid hash table for possible reclaim.
 *
 * This is run via smb_llist_post (after smb_llist_exit)
 * because smb_ofile_close can block, and we'd rather not
 * block while holding the ofile list as reader.
 */
static void
smb_ofile_drop(void *arg)
{
	smb_ofile_t	*of = arg;

	SMB_OFILE_VALID(of);

	mutex_enter(&of->f_mutex);
	switch (of->f_state) {
	case SMB_OFILE_STATE_OPEN:
		/* DH checks under mutex. */
		if (of->f_ftype == SMB_FTYPE_DISK &&
		    of->dh_vers != SMB2_NOT_DURABLE &&
		    smb_dh_should_save(of)) {
			/*
			 * Tell smb_ofile_release() to
			 * make this an _ORPHANED DH.
			 */
			of->f_state = SMB_OFILE_STATE_SAVE_DH;
			mutex_exit(&of->f_mutex);
			break;
		}
		/* OK close it. */
		mutex_exit(&of->f_mutex);
		smb_ofile_close(of, 0);
		break;

	default:
		/* Something else closed it already. */
		mutex_exit(&of->f_mutex);
		break;
	}

	/*
	 * Release the ref acquired during the traversal loop.
	 * Note that on the last ref, this ofile will be
	 * removed from the tree list etc.
	 * See: smb_llist_post, smb_ofile_delete
	 */
	smb_ofile_release(of);
}

/*
 * smb_ofile_close_all
 *
 *
 */
void
smb_ofile_close_all(
    smb_tree_t		*tree,
    uint32_t		pid)
{
	smb_ofile_t	*of;
	smb_lavl_t	*la;

	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	la = &tree->t_ofile_list;

	smb_lavl_enter(la, RW_READER);
	for (of = smb_lavl_first(la);
	    of != NULL;
	    of = smb_lavl_next(la, of)) {
		ASSERT(of->f_magic == SMB_OFILE_MAGIC);
		ASSERT(of->f_tree == tree);
		if (pid != 0 && of->f_opened_by_pid != pid)
			continue;
		if (smb_ofile_hold(of)) {
			smb_lavl_post(la, of, smb_ofile_drop);
		}
	}

	/*
	 * Drop the lock and process the llist dtor queue.
	 * Calls smb_ofile_drop on ofiles that were open.
	 */
	smb_lavl_exit(la);
}

/*
 * If the enumeration request is for ofile data, handle it here.
 * Otherwise, return.
 *
 * This function should be called with a hold on the ofile.
 */
int
smb_ofile_enum(smb_ofile_t *of, smb_svcenum_t *svcenum)
{
	uint8_t *pb;
	uint_t nbytes;
	int rc;

	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);
	ASSERT(of->f_refcnt);

	if (svcenum->se_type != SMB_SVCENUM_TYPE_FILE)
		return (0);

	if (svcenum->se_nskip > 0) {
		svcenum->se_nskip--;
		return (0);
	}

	if (svcenum->se_nitems >= svcenum->se_nlimit) {
		svcenum->se_nitems = svcenum->se_nlimit;
		return (0);
	}

	pb = &svcenum->se_buf[svcenum->se_bused];

	rc = smb_ofile_netinfo_encode(of, pb, svcenum->se_bavail,
	    &nbytes);
	if (rc == 0) {
		svcenum->se_bavail -= nbytes;
		svcenum->se_bused += nbytes;
		svcenum->se_nitems++;
	}

	return (rc);
}

/*
 * Take a reference on an open file, in any of the states:
 *   RECONNECT, SAVE_DH, OPEN, ORPHANED, EXPIRED.
 * Return TRUE if ref taken.  Used for oplock breaks.
 *
 * Note: When the oplock break code calls this, it holds the
 * node ofile list lock and node oplock mutex.  When we see
 * an ofile in states RECONNECT or SAVING, we know the ofile
 * is gaining or losing it's tree, and that happens quickly,
 * so we just wait for that work to finish.  However, the
 * waiting for state transitions here means we have to be
 * careful not to re-enter the node list lock or otherwise
 * block on things that could cause a deadlock.  Waiting
 * just on of->f_mutex here is OK.
 */
boolean_t
smb_ofile_hold_olbrk(smb_ofile_t *of)
{
	boolean_t ret = B_FALSE;

	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);

again:
	switch (of->f_state) {
	case SMB_OFILE_STATE_RECONNECT:
	case SMB_OFILE_STATE_SAVING:
		cv_wait(&of->f_cv, &of->f_mutex);
		goto again;

	case SMB_OFILE_STATE_OPEN:
	case SMB_OFILE_STATE_SAVE_DH:
	case SMB_OFILE_STATE_ORPHANED:
	case SMB_OFILE_STATE_EXPIRED:
		of->f_refcnt++;
		ret = B_TRUE;
		break;

	/*
	 * This is called only when an ofile has an oplock,
	 * so if we come across states that should not have
	 * an oplock, let's debug how that happened.
	 */
	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&of->f_mutex);

	return (ret);
}

/*
 * Take a reference on an open file.
 */
boolean_t
smb_ofile_hold(smb_ofile_t *of)
{
	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);

	if (of->f_state != SMB_OFILE_STATE_OPEN) {
		mutex_exit(&of->f_mutex);
		return (B_FALSE);
	}
	of->f_refcnt++;

	mutex_exit(&of->f_mutex);
	return (B_TRUE);
}

/*
 * Void arg variant of smb_ofile_release for use with smb_llist_post.
 * This is needed because smb_ofile_release may need to enter the
 * smb_llist as writer when it drops the last reference, so when
 * we're in the llist as reader, use smb_llist_post with this
 * function to arrange for the release call at llist_exit.
 */
void
smb_ofile_release_LL(void *arg)
{
	smb_ofile_t	*of = arg;

	SMB_OFILE_VALID(of);
	smb_ofile_release(of);
}

/*
 * Release a reference on a file.  If the reference count falls to
 * zero and the file has been closed, post the object for deletion.
 * Object deletion is deferred to avoid modifying a list while an
 * iteration may be in progress.
 *
 * We're careful to avoid dropping f_session etc. until the last
 * reference goes away.  The oplock break code depends on that
 * not changing while it holds a ref. on an ofile.
 */
void
smb_ofile_release(smb_ofile_t *of)
{
	smb_tree_t *tree = of->f_tree;
	boolean_t delete = B_FALSE;

	SMB_OFILE_VALID(of);

	mutex_enter(&of->f_mutex);
	ASSERT(of->f_refcnt > 0);
	of->f_refcnt--;

	switch (of->f_state) {
	case SMB_OFILE_STATE_OPEN:
	case SMB_OFILE_STATE_ORPHANED:
	case SMB_OFILE_STATE_EXPIRED:
		break;

	case SMB_OFILE_STATE_SAVE_DH:
		ASSERT(tree != NULL);
		if (of->f_refcnt == 0) {
			of->f_state = SMB_OFILE_STATE_SAVING;
			smb_lavl_post(&tree->t_ofile_list, of,
			    smb_ofile_save_dh);
		}
		break;

	case SMB_OFILE_STATE_CLOSING:
		/* Note, tree == NULL on _ORPHANED */
		if (of->f_refcnt == 0) {
			of->f_state = SMB_OFILE_STATE_CLOSED;
			if (tree == NULL) {
				/* Skip smb_llist_post */
				delete = B_TRUE;
				break;
			}
			smb_lavl_post(&tree->t_ofile_list, of,
			    smb_ofile_delete);
		}
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&of->f_mutex);

	/*
	 * When we drop the last ref. on an expired DH, it's no longer
	 * in any tree, so skip the smb_llist_post and just call
	 * smb_ofile_delete directly.
	 */
	if (delete) {
		smb_ofile_delete(of);
	}
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
    smb_request_t	*sr,
    uint16_t		fid)
{
	smb_tree_t	*tree = sr->tid_tree;
	smb_lavl_t	*lavl;
	smb_ofile_t	*of;
	uint16_t	cmp_fid;

	CTASSERT(offsetof(smb_ofile_t, f_fid) == 0);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	cmp_fid = fid;

	lavl = &tree->t_ofile_list;

	smb_lavl_enter(lavl, RW_READER);
	of = avl_find(&lavl->la_tree, &cmp_fid, NULL);
	if (of == NULL)
		goto out;

	/*
	 * Only allow use of a given FID with the same UID that
	 * was used to open it.  MS-CIFS 3.3.5.14
	 */
	if (of->f_user != sr->uid_user) {
		of = NULL;
		goto out;
	}

	/* inline smb_ofile_hold() */
	mutex_enter(&of->f_mutex);
	if (of->f_state != SMB_OFILE_STATE_OPEN) {
		mutex_exit(&of->f_mutex);
		of = NULL;
		goto out;
	}
	of->f_refcnt++;
	mutex_exit(&of->f_mutex);

out:
	smb_lavl_exit(lavl);
	return (of);
}

/*
 * smb_ofile_lookup_by_uniqid
 *
 * Find the open file whose uniqid matches the one specified in the request.
 */
smb_ofile_t *
smb_ofile_lookup_by_uniqid(smb_tree_t *tree, uint32_t uniqid)
{
	smb_lavl_t	*lavl;
	smb_ofile_t	*of;

	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	lavl = &tree->t_ofile_list;
	smb_lavl_enter(lavl, RW_READER);
	of = smb_lavl_first(lavl);

	while (of) {
		ASSERT(of->f_magic == SMB_OFILE_MAGIC);
		ASSERT(of->f_tree == tree);

		if (of->f_uniqid == uniqid) {
			if (smb_ofile_hold(of)) {
				smb_lavl_exit(lavl);
				return (of);
			}
		}

		of = smb_lavl_next(lavl, of);
	}

	smb_lavl_exit(lavl);
	return (NULL);
}

/*
 * Durable ID (or persistent ID)
 */

static smb_ofile_t *
smb_ofile_hold_cb(smb_ofile_t *of)
{
	smb_ofile_t *ret = of;

	mutex_enter(&of->f_mutex);
	if (of->f_state == SMB_OFILE_STATE_ORPHANED)
		/* inline smb_ofile_hold() */
		of->f_refcnt++;
	else
		ret = NULL;

	mutex_exit(&of->f_mutex);
	return (ret);
}

/*
 * Lookup an ofile by persistent ID, and return ONLY if in state ORPHANED
 * This is used by SMB2 create "reclaim".
 */
smb_ofile_t *
smb_ofile_lookup_by_persistid(smb_request_t *sr, uint64_t persistid)
{
	smb_hash_t *hash;
	smb_bucket_t *bucket;
	smb_llist_t *ll;
	smb_ofile_t *of;
	uint_t idx;

	if (persistid == 0)
		return (NULL);

	hash = sr->sr_server->sv_persistid_ht;
	idx = smb_hash_uint64(hash, persistid);
	bucket = &hash->buckets[idx];
	ll = &bucket->b_list;

	smb_llist_enter(ll, RW_READER);
	of = smb_llist_head(ll);
	while (of != NULL) {
		if (of->f_persistid == persistid)
			break;
		of = smb_llist_next(ll, of);
	}
	if (of != NULL)
		of = smb_ofile_hold_cb(of);
	smb_llist_exit(ll);

	return (of);
}

/*
 * Create a (unique) durable/persistent ID for a new ofile,
 * and add this ofile to the persistid hash table.  This ID
 * is referred to as the persistent ID in the protocol spec,
 * so that's what we call it too, though the persistence may
 * vary.  "Durable" handles are persistent across reconnects
 * but not server reboots.  Persistent handles are persistent
 * across server reboots too.
 *
 * Note that persistent IDs need to be unique for the lifetime of
 * any given ofile.  For normal (non-persistent) ofiles we can just
 * use a persistent ID derived from the ofile memory address, as
 * these don't ever live beyond the current OS boot lifetime.
 *
 * Persistent handles are re-imported after server restart, and
 * generally have a different memory address after import than
 * they had in the previous OS boot lifetime, so for these we
 * use a randomly assigned value that won't conflict with any
 * non-persistent (durable) handles.  Ensuring that a randomly
 * generated ID is unique requires a search of the ofiles in one
 * hash bucket, which we'd rather avoid for non-persistent opens.
 *
 * The solution used here is to divide the persistent ID space
 * in half (odd and even values) where durable opens use an ID
 * derived from the ofile address (which is always even), and
 * persistent opens use an ID generated randomly (always odd).
 *
 * smb_ofile_set_persistid_dh() sets a durable handle ID and
 * smb_ofile_set_persistid_ph() sets a persistent handle ID.
 */
void
smb_ofile_set_persistid_dh(smb_ofile_t *of)
{
	smb_hash_t *hash = of->f_server->sv_persistid_ht;
	smb_bucket_t *bucket;
	smb_llist_t *ll;
	uint64_t persistid;
	uint_t idx;

	persistid = (uintptr_t)of;
	/* Avoid showing object addresses */
	persistid ^= ((uintptr_t)&smb_cache_ofile);
	/* make sure it's even */
	persistid &= ~((uint64_t)1);

	idx = smb_hash_uint64(hash, persistid);
	bucket = &hash->buckets[idx];
	ll = &bucket->b_list;
	smb_llist_enter(ll, RW_WRITER);
	if (of->f_persistid == 0) {
		of->f_persistid = persistid;
		smb_llist_insert_tail(ll, of);
	}
	smb_llist_exit(ll);
}

void
smb_ofile_set_persistid_ph(smb_ofile_t *of)
{
	uint64_t persistid;
	int rc;

top:
	(void) random_get_pseudo_bytes((uint8_t *)&persistid,
	    sizeof (persistid));
	if (persistid == 0) {
		cmn_err(CE_NOTE, "random gave all zeros!");
		goto top;
	}
	/* make sure it's odd */
	persistid |= (uint64_t)1;

	/*
	 * Try inserting with this persistent ID.
	 */
	rc = smb_ofile_insert_persistid(of, persistid);
	if (rc == EEXIST)
		goto top;
	if (rc != 0) {
		cmn_err(CE_NOTE, "set persistid rc=%d", rc);
	}
}

/*
 * Insert an ofile into the persistid hash table.
 * If the persistent ID is in use, error.
 */
int
smb_ofile_insert_persistid(smb_ofile_t *new_of, uint64_t persistid)
{
	smb_hash_t *hash = new_of->f_server->sv_persistid_ht;
	smb_bucket_t *bucket;
	smb_llist_t *ll;
	smb_ofile_t *of;
	uint_t idx;

	ASSERT(persistid != 0);

	/*
	 * Look to see if this key alreay exists.
	 */
	idx = smb_hash_uint64(hash, persistid);
	bucket = &hash->buckets[idx];
	ll = &bucket->b_list;

	smb_llist_enter(ll, RW_WRITER);
	of = smb_llist_head(ll);
	while (of != NULL) {
		if (of->f_persistid == persistid) {
			/* already in use */
			smb_llist_exit(ll);
			return (EEXIST);
		}
		of = smb_llist_next(ll, of);
	}

	/* Not found, so OK to insert. */
	if (new_of->f_persistid == 0) {
		new_of->f_persistid = persistid;
		smb_llist_insert_tail(ll, new_of);
	}
	smb_llist_exit(ll);

	return (0);
}

void
smb_ofile_del_persistid(smb_ofile_t *of)
{
	smb_hash_t *hash = of->f_server->sv_persistid_ht;
	smb_bucket_t *bucket;
	smb_llist_t *ll;
	uint_t idx;

	idx = smb_hash_uint64(hash, of->f_persistid);
	bucket = &hash->buckets[idx];
	ll = &bucket->b_list;
	smb_llist_enter(ll, RW_WRITER);
	if (of->f_persistid != 0) {
		smb_llist_remove(ll, of);
		of->f_persistid = 0;
	}
	smb_llist_exit(ll);
}

/*
 * Disallow NetFileClose on certain ofiles to avoid side-effects.
 * Closing a tree root is not allowed: use NetSessionDel or NetShareDel.
 * Closing SRVSVC connections is not allowed because this NetFileClose
 * request may depend on this ofile.
 */
boolean_t
smb_ofile_disallow_fclose(smb_ofile_t *of)
{
	ASSERT(of);
	ASSERT(of->f_magic == SMB_OFILE_MAGIC);
	ASSERT(of->f_refcnt);

	switch (of->f_ftype) {
	case SMB_FTYPE_DISK:
		ASSERT(of->f_tree);
		return (of->f_node == of->f_tree->t_snode);

	case SMB_FTYPE_MESG_PIPE:
		ASSERT(of->f_pipe);
		if (smb_strcasecmp(of->f_pipe->p_name, "SRVSVC", 0) == 0)
			return (B_TRUE);
		break;
	default:
		break;
	}

	return (B_FALSE);
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
	smb_attr_t	attr;

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
		bzero(&attr, sizeof (smb_attr_t));
		attr.sa_mask |= SMB_AT_SIZE;
		rc = smb_fsop_getattr(NULL, zone_kcred(), of->f_node, &attr);
		if (rc != 0) {
			mutex_exit(&of->f_mutex);
			return (rc);
		}
		if (off < 0 && (-off) > attr.sa_vattr.va_size)
			newoff = 0;
		else
			newoff = attr.sa_vattr.va_size + (u_offset_t)off;
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
 * smb_ofile_flush
 *
 * If writes on this file are not synchronous, flush it using the NFSv3
 * commit interface.
 *
 * XXX - todo: Flush named pipe should drain writes.
 */
void
smb_ofile_flush(struct smb_request *sr, struct smb_ofile *of)
{
	switch (of->f_ftype) {
	case SMB_FTYPE_DISK:
		if ((of->f_node->flags & NODE_FLAGS_WRITE_THROUGH) == 0)
			(void) smb_fsop_commit(sr, of->f_cr, of->f_node);
		break;
	default:
		break;
	}
}

/*
 * smb_ofile_is_open
 */
boolean_t
smb_ofile_is_open(smb_ofile_t *of)
{
	boolean_t	rc;

	SMB_OFILE_VALID(of);

	mutex_enter(&of->f_mutex);
	rc = smb_ofile_is_open_locked(of);
	mutex_exit(&of->f_mutex);
	return (rc);
}

/* *************************** Static Functions ***************************** */

/*
 * Determine whether or not an ofile is open.
 * This function must be called with the mutex held.
 */
static boolean_t
smb_ofile_is_open_locked(smb_ofile_t *of)
{
	ASSERT(MUTEX_HELD(&of->f_mutex));

	switch (of->f_state) {
	case SMB_OFILE_STATE_OPEN:
	case SMB_OFILE_STATE_SAVE_DH:
	case SMB_OFILE_STATE_SAVING:
	case SMB_OFILE_STATE_ORPHANED:
	case SMB_OFILE_STATE_RECONNECT:
		return (B_TRUE);

	case SMB_OFILE_STATE_CLOSING:
	case SMB_OFILE_STATE_CLOSED:
	case SMB_OFILE_STATE_EXPIRED:
		return (B_FALSE);

	default:
		ASSERT(0);
		return (B_FALSE);
	}
}

/*
 * smb_ofile_save_dh
 *
 * Called via smb_llist_post (after smb_llist_exit) when the last ref.
 * on this ofile has gone, and this ofile is a "durable handle" (DH)
 * that has state we've decided to save.
 *
 * This does parts of what smb_ofile_delete would do, including:
 * remove the ofile from the tree ofile list and related.
 *
 * We leave the ofile in state ORPHANED, ready for reconnect
 * or expiration via smb2_dh_expire (see smb_ofile_delete).
 */
static void
smb_ofile_save_dh(void *arg)
{
	smb_ofile_t	*of = (smb_ofile_t *)arg;
	smb_tree_t	*tree = of->f_tree;

	SMB_OFILE_VALID(of);
	ASSERT(of->f_refcnt == 0);
	ASSERT(of->f_ftype == SMB_FTYPE_DISK);
	ASSERT(of->f_state == SMB_OFILE_STATE_SAVING);

	atomic_dec_32(&of->f_session->s_file_cnt);
	atomic_dec_32(&of->f_tree->t_open_files);
	smb_lavl_enter(&tree->t_ofile_list, RW_WRITER);
	smb_lavl_remove(&tree->t_ofile_list, of);
	smb_lavl_exit(&tree->t_ofile_list);

	/*
	 * This ofile is no longer on t_ofile_list, however...
	 *
	 * This is called via smb_llist_post, which means it may run
	 * BEFORE smb_ofile_release drops f_mutex (if another thread
	 * flushes the delete queue before we do).  Synchronize.
	 */
	mutex_enter(&of->f_mutex);
	DTRACE_PROBE1(ofile__exit, smb_ofile_t *, of);
	mutex_exit(&of->f_mutex);

	/*
	 * Keep f_notify state, lease, and
	 * keep on node ofile list.
	 * Keep of->f_cr until reclaim.
	 */

	ASSERT(of->f_fid != 0);
	smb_idpool_free(&tree->t_fid_pool, of->f_fid);
	of->f_fid = 0;
	smb_tree_release(of->f_tree);
	of->f_tree = NULL;
	smb_user_release(of->f_user);
	of->f_user = NULL;
	of->f_session = NULL;

	/*
	 * Make it "orphaned" so it can now be reclaimed.
	 * Note that smb_ofile_hold_olbrk() may have blocked
	 * for state SMB_OFILE_STATE_SAVING, so wake it.
	 */
	mutex_enter(&of->f_mutex);
	of->dh_expire_time = gethrtime() + of->dh_timeout_offset;
	of->f_state = SMB_OFILE_STATE_ORPHANED;
	cv_broadcast(&of->f_cv);
	mutex_exit(&of->f_mutex);
}

/*
 * Delete an ofile.
 *
 * Approximately the inverse of smb_ofile_alloc()
 * Called via smb_llist_post (after smb_llist_exit)
 * when the last ref. on this ofile has gone.
 *
 * Normally,this removes the ofile from the tree list and
 * then frees resources held on the ofile.  However, when
 * we're expiring an orphaned durable handle, the linkage
 * into the tree lists etc. have already been destroyed.
 * This case is distinguished by of->f_tree == NULL.
 */
static void
smb_ofile_delete(void *arg)
{
	smb_ofile_t	*of = (smb_ofile_t *)arg;
	smb_tree_t	*tree = of->f_tree;

	SMB_OFILE_VALID(of);
	ASSERT(of->f_refcnt == 0);
	ASSERT(of->f_state == SMB_OFILE_STATE_CLOSED);

	if (tree != NULL) {
		ASSERT(of->f_user != NULL);
		ASSERT(of->f_session != NULL);
		atomic_dec_32(&of->f_session->s_file_cnt);
		atomic_dec_32(&of->f_tree->t_open_files);
		smb_lavl_enter(&tree->t_ofile_list, RW_WRITER);
		smb_lavl_remove(&tree->t_ofile_list, of);
		smb_lavl_exit(&tree->t_ofile_list);
	}

	/*
	 * Remove this ofile from the node's n_ofile_list so it
	 * can't be found by list walkers like notify or oplock.
	 * Keep the node ref. until later in this function so
	 * of->f_node remains valid while we destroy the ofile.
	 */
	if (of->f_ftype == SMB_FTYPE_DISK ||
	    of->f_ftype == SMB_FTYPE_PRINTER) {
		smb_node_t *node = of->f_node;

		/*
		 * Oplock cleanup should have made sure that
		 * excl_open does not point to this ofile.
		 */
		VERIFY(node->n_oplock.excl_open != of);

		/*
		 * Note smb_ofile_close did smb_node_dec_open_ofiles()
		 */
		smb_node_rem_ofile(node, of);
	}

	/*
	 * This ofile is no longer on any lists, however...
	 *
	 * This is called via smb_llist_post, which means it may run
	 * BEFORE smb_ofile_release drops f_mutex (if another thread
	 * flushes the delete queue before we do).  Synchronize.
	 */
	mutex_enter(&of->f_mutex);
	of->f_state = SMB_OFILE_STATE_ALLOC;
	DTRACE_PROBE1(ofile__exit, smb_ofile_t *, of);
	mutex_exit(&of->f_mutex);

	switch (of->f_ftype) {
	case SMB_FTYPE_BYTE_PIPE:
	case SMB_FTYPE_MESG_PIPE:
		smb_opipe_dealloc(of->f_pipe);
		of->f_pipe = NULL;
		break;
	case SMB_FTYPE_DISK:
		ASSERT(of->f_notify.nc_subscribed == B_FALSE);
		MBC_FLUSH(&of->f_notify.nc_buffer);
		if (of->f_odir != NULL)
			smb_odir_release(of->f_odir);
		if (of->f_lease != NULL) {
			smb2_lease_rele(of->f_lease);
			of->f_lease = NULL;
		}
		/* FALLTHROUGH */
	case SMB_FTYPE_PRINTER:
		/*
		 * Did smb_node_rem_ofile above.
		 */
		ASSERT(of->f_node != NULL);
		smb_node_release(of->f_node);
		break;
	default:
		ASSERT(!"f_ftype");
		break;
	}

	smb_ofile_free(of);
}

void
smb_ofile_free(smb_ofile_t *of)
{
	smb_tree_t	*tree = of->f_tree;

	ASSERT(of->f_state == SMB_OFILE_STATE_ALLOC);

	/* Make sure it's not in the persistid hash. */
	ASSERT(of->f_persistid == 0);

	if (tree != NULL) {
		if (of->f_fid != 0)
			smb_idpool_free(&tree->t_fid_pool, of->f_fid);
		smb_tree_release(of->f_tree);
		smb_user_release(of->f_user);
	}

	if (of->f_cr != NULL)
		crfree(of->f_cr);

	of->f_magic = (uint32_t)~SMB_OFILE_MAGIC;
	list_destroy(&of->f_notify.nc_waiters);
	mutex_destroy(&of->dh_nvlock);
	mutex_destroy(&of->f_mutex);
	kmem_cache_free(smb_cache_ofile, of);
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

	if ((of == NULL) || (cr == zone_kcred()))
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
 * smb_ofile_share_check
 *
 * Check if ofile was opened with share access NONE (0).
 * Returns: B_TRUE  - share access non-zero
 *          B_FALSE - share access NONE
 */
boolean_t
smb_ofile_share_check(smb_ofile_t *of)
{
	return (!SMB_DENY_ALL(of->f_share_access));
}

/*
 * check file sharing rules for current open request
 * against existing open instances of the same file
 *
 * Returns NT_STATUS_SHARING_VIOLATION if there is any
 * sharing conflict, otherwise returns NT_STATUS_SUCCESS.
 */
uint32_t
smb_ofile_open_check(smb_ofile_t *of, uint32_t desired_access,
    uint32_t share_access)
{
	uint32_t ret;

	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);

	if (!smb_ofile_is_open_locked(of)) {
		ret = NT_STATUS_INVALID_HANDLE;
		goto out;
	}

	/* if it's just meta data */
	if ((of->f_granted_access & FILE_DATA_ALL) == 0) {
		ret = NT_STATUS_SUCCESS;
		goto out;
	}

	/*
	 * Check requested share access against the
	 * open granted (desired) access
	 */
	if (SMB_DENY_DELETE(share_access) && (of->f_granted_access & DELETE)) {
		ret = NT_STATUS_SHARING_VIOLATION;
		goto out;
	}

	if (SMB_DENY_READ(share_access) &&
	    (of->f_granted_access & (FILE_READ_DATA | FILE_EXECUTE))) {
		ret = NT_STATUS_SHARING_VIOLATION;
		goto out;
	}

	if (SMB_DENY_WRITE(share_access) &&
	    (of->f_granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA))) {
		ret = NT_STATUS_SHARING_VIOLATION;
		goto out;
	}

	/* check requested desired access against the open share access */
	if (SMB_DENY_DELETE(of->f_share_access) && (desired_access & DELETE)) {
		ret = NT_STATUS_SHARING_VIOLATION;
		goto out;
	}

	if (SMB_DENY_READ(of->f_share_access) &&
	    (desired_access & (FILE_READ_DATA | FILE_EXECUTE))) {
		ret = NT_STATUS_SHARING_VIOLATION;
		goto out;
	}

	if (SMB_DENY_WRITE(of->f_share_access) &&
	    (desired_access & (FILE_WRITE_DATA | FILE_APPEND_DATA))) {
		ret = NT_STATUS_SHARING_VIOLATION;
		goto out;
	}

	ret = NT_STATUS_SUCCESS;
out:
	mutex_exit(&of->f_mutex);
	return (ret);
}

/*
 * smb_ofile_rename_check
 *
 * This does the work described in MS-FSA 2.1.5.1.2.2 (Algorithm
 * to Check Sharing Access to an Existing Stream or Directory),
 * where the "open in-progress" has DesiredAccess = DELETE and
 * SharingMode = SHARE_READ | SHARE_WRITE | SHARE_DELETE.
 */

uint32_t
smb_ofile_rename_check(smb_ofile_t *of)
{
	uint32_t ret;

	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);

	if (!smb_ofile_is_open_locked(of)) {
		ret = NT_STATUS_INVALID_HANDLE;
		goto out;
	}

	if ((of->f_granted_access & FILE_DATA_ALL) == 0) {
		ret = NT_STATUS_SUCCESS;
		goto out;
	}

	if ((of->f_share_access & FILE_SHARE_DELETE) == 0) {
		ret = NT_STATUS_SHARING_VIOLATION;
		goto out;
	}

	ret = NT_STATUS_SUCCESS;
out:
	mutex_exit(&of->f_mutex);
	return (ret);
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
	uint32_t ret;

	ASSERT(of->f_magic == SMB_OFILE_MAGIC);

	mutex_enter(&of->f_mutex);

	if (!smb_ofile_is_open_locked(of)) {
		ret = NT_STATUS_INVALID_HANDLE;
		goto out;
	}

	if (of->f_granted_access &
	    (FILE_READ_DATA | FILE_WRITE_DATA |
	    FILE_APPEND_DATA | FILE_EXECUTE | DELETE)) {
		ret = NT_STATUS_SHARING_VIOLATION;
		goto out;
	}

	ret = NT_STATUS_SUCCESS;
out:
	mutex_exit(&of->f_mutex);
	return (ret);
}

cred_t *
smb_ofile_getcred(smb_ofile_t *of)
{
	return (of->f_cr);
}

/*
 * smb_ofile_set_delete_on_close
 *
 * Set the DeleteOnClose flag on the smb file. When the file is closed,
 * the flag will be transferred to the smb node, which will commit the
 * delete operation and inhibit subsequent open requests.
 *
 * When DeleteOnClose is set on an smb_node, the common open code will
 * reject subsequent open requests for the file. Observation of Windows
 * 2000 indicates that subsequent opens should be allowed (assuming
 * there would be no sharing violation) until the file is closed using
 * the fid on which the DeleteOnClose was requested.
 */
void
smb_ofile_set_delete_on_close(smb_request_t *sr, smb_ofile_t *of)
{
	uint32_t	status;

	/*
	 * Break any oplock handle caching.
	 */
	status = smb_oplock_break_SETINFO(of->f_node, of,
	    FileDispositionInformation);
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		if (sr->session->dialect >= SMB_VERS_2_BASE)
			(void) smb2sr_go_async(sr);
		(void) smb_oplock_wait_break(sr, of->f_node, 0);
	}

	mutex_enter(&of->f_mutex);
	of->f_flags |= SMB_OFLAGS_SET_DELETE_ON_CLOSE;
	mutex_exit(&of->f_mutex);
}

/*
 * Encode open file information into a buffer; needed in user space to
 * support RPC requests.
 */
static int
smb_ofile_netinfo_encode(smb_ofile_t *of, uint8_t *buf, size_t buflen,
    uint32_t *nbytes)
{
	smb_netfileinfo_t	fi;
	int			rc;

	rc = smb_ofile_netinfo_init(of, &fi);
	if (rc == 0) {
		rc = smb_netfileinfo_encode(&fi, buf, buflen, nbytes);
		smb_ofile_netinfo_fini(&fi);
	}

	return (rc);
}

static int
smb_ofile_netinfo_init(smb_ofile_t *of, smb_netfileinfo_t *fi)
{
	smb_user_t	*user;
	smb_tree_t	*tree;
	smb_node_t	*node;
	char		*path;
	char		*buf;
	int		rc;

	ASSERT(of);
	user = of->f_user;
	tree = of->f_tree;
	ASSERT(user);
	ASSERT(tree);

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	switch (of->f_ftype) {
	case SMB_FTYPE_DISK:
		node = of->f_node;
		ASSERT(node);

		fi->fi_permissions = of->f_granted_access;
		fi->fi_numlocks = smb_lock_get_lock_count(node, of);

		path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

		if (node != tree->t_snode) {
			rc = smb_node_getshrpath(node, tree, path, MAXPATHLEN);
			if (rc != 0)
				(void) strlcpy(path, node->od_name, MAXPATHLEN);
		}

		(void) snprintf(buf, MAXPATHLEN, "%s:%s", tree->t_sharename,
		    path);
		kmem_free(path, MAXPATHLEN);
		break;

	case SMB_FTYPE_MESG_PIPE:
		ASSERT(of->f_pipe);

		fi->fi_permissions = FILE_READ_DATA | FILE_WRITE_DATA |
		    FILE_EXECUTE;
		fi->fi_numlocks = 0;
		(void) snprintf(buf, MAXPATHLEN, "\\PIPE\\%s",
		    of->f_pipe->p_name);
		break;

	default:
		kmem_free(buf, MAXPATHLEN);
		return (-1);
	}

	fi->fi_fid = of->f_fid;
	fi->fi_uniqid = of->f_uniqid;
	fi->fi_pathlen = strlen(buf) + 1;
	fi->fi_path = smb_mem_strdup(buf);
	kmem_free(buf, MAXPATHLEN);

	fi->fi_namelen = user->u_domain_len + user->u_name_len + 2;
	fi->fi_username = kmem_alloc(fi->fi_namelen, KM_SLEEP);
	(void) snprintf(fi->fi_username, fi->fi_namelen, "%s\\%s",
	    user->u_domain, user->u_name);
	return (0);
}

static void
smb_ofile_netinfo_fini(smb_netfileinfo_t *fi)
{
	if (fi == NULL)
		return;

	if (fi->fi_path)
		smb_mem_free(fi->fi_path);
	if (fi->fi_username)
		kmem_free(fi->fi_username, fi->fi_namelen);

	bzero(fi, sizeof (smb_netfileinfo_t));
}

/*
 * A query of user and group quotas may span multiple requests.
 * f_quota_resume is used to determine where the query should
 * be resumed, in a subsequent request. f_quota_resume contains
 * the SID of the last quota entry returned to the client.
 */
void
smb_ofile_set_quota_resume(smb_ofile_t *ofile, char *resume)
{
	ASSERT(ofile);
	mutex_enter(&ofile->f_mutex);
	if (resume == NULL)
		bzero(ofile->f_quota_resume, SMB_SID_STRSZ);
	else
		(void) strlcpy(ofile->f_quota_resume, resume, SMB_SID_STRSZ);
	mutex_exit(&ofile->f_mutex);
}

void
smb_ofile_get_quota_resume(smb_ofile_t *ofile, char *buf, int bufsize)
{
	ASSERT(ofile);
	mutex_enter(&ofile->f_mutex);
	(void) strlcpy(buf, ofile->f_quota_resume, bufsize);
	mutex_exit(&ofile->f_mutex);
}
