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
 */

/*
 * smb_oplock_wait / smb_oplock_broadcast
 * When an oplock is being acquired, we must ensure that the acquisition
 * response is submitted to the network stack before any other operation
 * is permitted on the oplock.
 * In smb_oplock_acquire, oplock.ol_xthread is set to point to the worker
 * thread processing the command that is granting the oplock.
 * Other threads accessing the oplock will be suspended in smb_oplock_wait().
 * They will be awakened when the worker thread referenced in 'ol_xthread'
 * calls smb_oplock_broadcast().
 *
 * The purpose of this mechanism is to prevent another thread from
 * triggering an oplock break before the response conveying the grant
 * has been sent.
 */

#include <smbsrv/smb_kproto.h>
#include <sys/nbmlock.h>
#include <inet/tcp.h>

#define	SMB_OPLOCK_IS_EXCLUSIVE(level)		\
	(((level) == SMB_OPLOCK_EXCLUSIVE) ||	\
	((level) == SMB_OPLOCK_BATCH))

extern int smb_fem_oplock_install(smb_node_t *);
extern int smb_fem_oplock_uninstall(smb_node_t *);

static int smb_oplock_install_fem(smb_node_t *);
static void smb_oplock_uninstall_fem(smb_node_t *);

static void smb_oplock_wait(smb_node_t *);
static void smb_oplock_wait_ack(smb_node_t *, uint32_t);
static void smb_oplock_timedout(smb_node_t *);

static smb_oplock_grant_t *smb_oplock_set_grant(smb_ofile_t *, uint8_t);
void smb_oplock_clear_grant(smb_oplock_grant_t *);
static int smb_oplock_insert_grant(smb_node_t *, smb_oplock_grant_t *);
static void smb_oplock_remove_grant(smb_node_t *, smb_oplock_grant_t *);
static smb_oplock_grant_t *smb_oplock_exclusive_grant(list_t *);
static smb_oplock_grant_t *smb_oplock_get_grant(smb_oplock_t *, smb_ofile_t *);

static smb_oplock_break_t *smb_oplock_create_break(smb_node_t *);
static smb_oplock_break_t *smb_oplock_get_break(void);
static void smb_oplock_delete_break(smb_oplock_break_t *);
static void smb_oplock_process_levelII_break(smb_node_t *);

static void smb_oplock_break_thread();

/* levelII oplock break requests (smb_oplock_break_t) */
static boolean_t	smb_oplock_initialized = B_FALSE;
static kmem_cache_t	*smb_oplock_break_cache = NULL;
static smb_llist_t	smb_oplock_breaks;
static smb_thread_t	smb_oplock_thread;


/*
 * smb_oplock_init
 *
 * This function is not multi-thread safe. The caller must make sure only one
 * thread makes the call.
 */
int
smb_oplock_init(void)
{
	int rc;

	if (smb_oplock_initialized)
		return (0);

	smb_oplock_break_cache = kmem_cache_create("smb_oplock_break_cache",
	    sizeof (smb_oplock_break_t), 8, NULL, NULL, NULL, NULL, NULL, 0);

	smb_llist_constructor(&smb_oplock_breaks, sizeof (smb_oplock_break_t),
	    offsetof(smb_oplock_break_t, ob_lnd));

	smb_thread_init(&smb_oplock_thread, "smb_thread_oplock_break",
	    smb_oplock_break_thread, NULL);

	rc = smb_thread_start(&smb_oplock_thread);
	if (rc != 0) {
		smb_thread_destroy(&smb_oplock_thread);
		smb_llist_destructor(&smb_oplock_breaks);
		kmem_cache_destroy(smb_oplock_break_cache);
		return (rc);
	}

	smb_oplock_initialized = B_TRUE;
	return (0);
}

/*
 * smb_oplock_fini
 * This function is not multi-thread safe. The caller must make sure only one
 * thread makes the call.
 */
void
smb_oplock_fini(void)
{
	smb_oplock_break_t	*ob;

	if (!smb_oplock_initialized)
		return;

	smb_thread_stop(&smb_oplock_thread);
	smb_thread_destroy(&smb_oplock_thread);

	while ((ob = smb_llist_head(&smb_oplock_breaks)) != NULL) {
		SMB_OPLOCK_BREAK_VALID(ob);
		smb_llist_remove(&smb_oplock_breaks, ob);
		smb_oplock_delete_break(ob);
	}
	smb_llist_destructor(&smb_oplock_breaks);

	kmem_cache_destroy(smb_oplock_break_cache);
}

/*
 * smb_oplock_install_fem
 * Install fem monitor for cross protocol oplock breaking.
 */
static int
smb_oplock_install_fem(smb_node_t *node)
{
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));

	if (node->n_oplock.ol_fem == B_FALSE) {
		if (smb_fem_oplock_install(node) != 0) {
			cmn_err(CE_NOTE, "No oplock granted: "
			    "failed to install fem monitor %s",
			    node->vp->v_path);
			return (-1);
		}
		node->n_oplock.ol_fem = B_TRUE;
	}
	return (0);
}

/*
 * smb_oplock_uninstall_fem
 * Uninstall fem monitor for cross protocol oplock breaking.
 */
static void
smb_oplock_uninstall_fem(smb_node_t *node)
{
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));

	if (node->n_oplock.ol_fem) {
		if (smb_fem_oplock_uninstall(node) == 0) {
			node->n_oplock.ol_fem = B_FALSE;
		} else {
			cmn_err(CE_NOTE,
			    "failed to uninstall fem monitor %s",
			    node->vp->v_path);
		}
	}
}

/*
 * smb_oplock_acquire
 *
 * Attempt to acquire an oplock. Clients will request EXCLUSIVE or BATCH,
 * but might only be granted LEVEL_II or NONE.
 *
 * If oplocks are not supported on the tree, or node, grant NONE.
 * If nobody else has the file open, grant the requested level.
 * If any of the following are true, grant NONE:
 * - there is an exclusive oplock on the node
 * - op->op_oplock_levelII is B_FALSE (LEVEL_II not supported by open cmd.
 * - LEVEL_II oplocks are not supported for the session
 * - a BATCH oplock is requested on a named stream
 * - there are any range locks on the node (SMB writers)
 * Otherwise, grant LEVEL_II.
 *
 * ol->ol_xthread is set to the current thread to lock the oplock against
 * other operations until the acquire response is on the wire. When the
 * acquire response is on the wire, smb_oplock_broadcast() is called to
 * reset ol->ol_xthread and wake any waiting threads.
 */
void
smb_oplock_acquire(smb_request_t *sr, smb_node_t *node, smb_ofile_t *ofile)
{
	smb_oplock_t		*ol;
	smb_oplock_grant_t	*og;
	list_t			*grants;
	smb_arg_open_t		*op;
	smb_tree_t		*tree;
	smb_session_t		*session;

	SMB_NODE_VALID(node);
	SMB_OFILE_VALID(ofile);

	ASSERT(node == SMB_OFILE_GET_NODE(ofile));
	ASSERT(RW_LOCK_HELD(&node->n_lock));

	op = &sr->sr_open;
	tree = SMB_OFILE_GET_TREE(ofile);
	session = SMB_OFILE_GET_SESSION(ofile);

	if (!smb_tree_has_feature(tree, SMB_TREE_OPLOCKS) ||
	    (op->op_oplock_level == SMB_OPLOCK_NONE) ||
	    ((op->op_oplock_level == SMB_OPLOCK_BATCH) &&
	    SMB_IS_STREAM(node))) {
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	ol = &node->n_oplock;
	grants = &ol->ol_grants;

	mutex_enter(&ol->ol_mutex);
	smb_oplock_wait(node);

	if ((node->n_open_count > 1) ||
	    (node->n_opening_count > 1) ||
	    smb_vop_other_opens(node->vp, ofile->f_mode)) {
		/*
		 * There are other opens.
		 */
		if ((!op->op_oplock_levelII) ||
		    (!smb_session_levelII_oplocks(session)) ||
		    (smb_oplock_exclusive_grant(grants) != NULL) ||
		    (smb_lock_range_access(sr, node, 0, 0, B_FALSE))) {
			/*
			 * LevelII (shared) oplock not allowed,
			 * so reply with "none".
			 */
			op->op_oplock_level = SMB_OPLOCK_NONE;
			mutex_exit(&ol->ol_mutex);
			return;
		}

		op->op_oplock_level = SMB_OPLOCK_LEVEL_II;
	}

	og = smb_oplock_set_grant(ofile, op->op_oplock_level);
	if (smb_oplock_insert_grant(node, og) != 0) {
		smb_oplock_clear_grant(og);
		op->op_oplock_level = SMB_OPLOCK_NONE;
		mutex_exit(&ol->ol_mutex);
		return;
	}

	ol->ol_xthread = curthread;
	mutex_exit(&ol->ol_mutex);
}

/*
 * smb_oplock_break
 *
 * Break granted oplocks according to the following rules:
 *
 * If there's an exclusive oplock granted on the node
 *  - if the BREAK_BATCH flags is specified and the oplock is not
 *    a batch oplock, no break is required.
 *  - if the session doesn't support LEVEL II oplocks, and 'brk' is
 *    BREAK_TO_LEVEL_II, do a BREAK_TO_NONE.
 *  - if the oplock is already breaking update the break level (if
 *    the requested break is to a lesser level), otherwise send an
 *    oplock break.
 *    Wait for acknowledgement of the break (unless NOWAIT flag is set)
 *
 * Otherwise:
 * If there are level II oplocks granted on the node, and the flags
 * indicate that they should be broken (BREAK_TO_NONE specified,
 * BREAK_EXCLUSIVE, BREAK_BATCH not specified) queue the levelII
 * break request for asynchronous processing.
 *
 * Returns:
 *       0 - oplock broken (or no break required)
 *  EAGAIN - oplock break request sent and would block
 *           awaiting the reponse but NOWAIT was specified
 */
int
smb_oplock_break(smb_request_t *sr, smb_node_t *node, uint32_t flags)
{
	smb_oplock_t		*ol;
	smb_oplock_grant_t	*og;
	list_t			*grants;
	uint32_t		timeout;
	uint8_t			brk;

	SMB_NODE_VALID(node);
	ol = &node->n_oplock;
	grants = &ol->ol_grants;

	mutex_enter(&ol->ol_mutex);
	smb_oplock_wait(node);

	og = list_head(grants);
	if (og == NULL) {
		mutex_exit(&ol->ol_mutex);
		return (0);
	}

	SMB_OPLOCK_GRANT_VALID(og);

	/* break levelII oplocks */
	if (og->og_level == SMB_OPLOCK_LEVEL_II) {
		mutex_exit(&ol->ol_mutex);

		if ((flags & SMB_OPLOCK_BREAK_TO_NONE) &&
		    !(flags & SMB_OPLOCK_BREAK_EXCLUSIVE) &&
		    !(flags & SMB_OPLOCK_BREAK_BATCH))  {
			smb_oplock_break_levelII(node);
		}
		return (0);
	}

	/* break exclusive oplock */
	if ((flags & SMB_OPLOCK_BREAK_BATCH) &&
	    (og->og_level != SMB_OPLOCK_BATCH)) {
		mutex_exit(&ol->ol_mutex);
		return (0);
	}

	if ((flags & SMB_OPLOCK_BREAK_TO_LEVEL_II) &&
	    smb_session_levelII_oplocks(og->og_session)) {
		brk = SMB_OPLOCK_BREAK_TO_LEVEL_II;
	} else {
		brk = SMB_OPLOCK_BREAK_TO_NONE;
	}

	switch (ol->ol_break) {
	case SMB_OPLOCK_NO_BREAK:
		ol->ol_break = brk;
		smb_session_oplock_break(og->og_session,
		    og->og_tid, og->og_fid, brk);
		break;
	case SMB_OPLOCK_BREAK_TO_LEVEL_II:
		if (brk == SMB_OPLOCK_BREAK_TO_NONE)
			ol->ol_break = SMB_OPLOCK_BREAK_TO_NONE;
		break;
	case SMB_OPLOCK_BREAK_TO_NONE:
	default:
		break;
	}

	if (flags & SMB_OPLOCK_BREAK_NOWAIT) {
		mutex_exit(&ol->ol_mutex);
		return (EAGAIN);
	}

	if (sr && (sr->session == og->og_session) &&
	    (sr->smb_uid == og->og_uid)) {
		timeout = smb_oplock_min_timeout;
	} else {
		timeout = smb_oplock_timeout;
	}

	mutex_exit(&ol->ol_mutex);
	smb_oplock_wait_ack(node, timeout);
	return (0);
}

/*
 * smb_oplock_break_levelII
 *
 * LevelII (shared) oplock breaks are processed asynchronously.
 * Unlike exclusive oplock breaks, the thread initiating the break
 * is NOT blocked while the request is processed.
 *
 * Create an oplock_break_request and add it to the list for async
 * processing.
 */
void
smb_oplock_break_levelII(smb_node_t *node)
{
	smb_oplock_break_t	*ob;

	ob = smb_oplock_create_break(node);

	smb_llist_enter(&smb_oplock_breaks, RW_WRITER);
	smb_llist_insert_tail(&smb_oplock_breaks, ob);
	smb_llist_exit(&smb_oplock_breaks);

	smb_thread_signal(&smb_oplock_thread);
}

/*
 * smb_oplock_break_thread
 *
 * The smb_oplock_thread is woken when an oplock break request is
 * added to the list of pending levelII oplock break requests.
 * Gets the oplock break request from the list, processes it and
 * deletes it.
 */
/*ARGSUSED*/
static void
smb_oplock_break_thread(smb_thread_t *thread, void *arg)
{
	smb_oplock_break_t	*ob;

	while (smb_thread_continue(thread)) {
		while ((ob = smb_oplock_get_break()) != NULL) {
			smb_oplock_process_levelII_break(ob->ob_node);
			smb_oplock_delete_break(ob);
		}
	}
}

/*
 * smb_oplock_get_break
 *
 * Remove and return the next oplock break request from the list
 */
static smb_oplock_break_t *
smb_oplock_get_break(void)
{
	smb_oplock_break_t	*ob;

	smb_llist_enter(&smb_oplock_breaks, RW_WRITER);
	if ((ob = smb_llist_head(&smb_oplock_breaks)) != NULL) {
		SMB_OPLOCK_BREAK_VALID(ob);
		smb_llist_remove(&smb_oplock_breaks, ob);
	}
	smb_llist_exit(&smb_oplock_breaks);
	return (ob);
}

/*
 * smb_oplock_process_levelII_break
 */
void
smb_oplock_process_levelII_break(smb_node_t *node)
{
	smb_oplock_t		*ol;
	smb_oplock_grant_t	*og;
	list_t			*grants;

	if (!smb_oplock_levelII)
		return;

	ol = &node->n_oplock;
	mutex_enter(&ol->ol_mutex);
	smb_oplock_wait(node);
	grants = &node->n_oplock.ol_grants;

	while ((og = list_head(grants)) != NULL) {
		SMB_OPLOCK_GRANT_VALID(og);

		if (SMB_OPLOCK_IS_EXCLUSIVE(og->og_level))
			break;

		smb_session_oplock_break(og->og_session,
		    og->og_tid, og->og_fid, SMB_OPLOCK_BREAK_TO_NONE);
		smb_oplock_remove_grant(node, og);
		smb_oplock_clear_grant(og);
	}

	mutex_exit(&ol->ol_mutex);
}

/*
 * smb_oplock_wait_ack
 *
 * Timed wait for an oplock break acknowledgement (or oplock release).
 */
static void
smb_oplock_wait_ack(smb_node_t *node, uint32_t timeout)
{
	smb_oplock_t	*ol;
	clock_t		time;

	ol = &node->n_oplock;
	mutex_enter(&ol->ol_mutex);
	time = MSEC_TO_TICK(timeout) + ddi_get_lbolt();

	while (ol->ol_break != SMB_OPLOCK_NO_BREAK) {
		if (cv_timedwait(&ol->ol_cv, &ol->ol_mutex, time) < 0) {
			smb_oplock_timedout(node);
			cv_broadcast(&ol->ol_cv);
			break;
		}
	}
	mutex_exit(&ol->ol_mutex);
}

/*
 * smb_oplock_timedout
 *
 * An oplock break has not been acknowledged within timeout
 * 'smb_oplock_timeout'.
 * Set oplock grant to the desired break level.
 */
static void
smb_oplock_timedout(smb_node_t *node)
{
	smb_oplock_t		*ol;
	smb_oplock_grant_t	*og;
	list_t			*grants;

	ol = &node->n_oplock;
	grants = &ol->ol_grants;

	ASSERT(MUTEX_HELD(&ol->ol_mutex));

	og = smb_oplock_exclusive_grant(grants);
	if (og) {
		switch (ol->ol_break) {
		case SMB_OPLOCK_BREAK_TO_NONE:
			og->og_level = SMB_OPLOCK_NONE;
			smb_oplock_remove_grant(node, og);
			smb_oplock_clear_grant(og);
			break;
		case SMB_OPLOCK_BREAK_TO_LEVEL_II:
			og->og_level = SMB_OPLOCK_LEVEL_II;
			break;
		default:
			SMB_PANIC();
		}
	}
	ol->ol_break = SMB_OPLOCK_NO_BREAK;
}

/*
 * smb_oplock_release
 *
 * Release the oplock granted on ofile 'of'.
 * Wake any threads waiting for an oplock break acknowledgement for
 * this oplock.
 * This is called when the ofile is being closed.
 */
void
smb_oplock_release(smb_node_t *node, smb_ofile_t *of)
{
	smb_oplock_t		*ol;
	smb_oplock_grant_t	*og;

	ol = &node->n_oplock;
	mutex_enter(&ol->ol_mutex);
	smb_oplock_wait(node);

	og = smb_oplock_get_grant(ol, of);
	if (og) {
		smb_oplock_remove_grant(node, og);
		smb_oplock_clear_grant(og);

		if (ol->ol_break != SMB_OPLOCK_NO_BREAK) {
			ol->ol_break = SMB_OPLOCK_NO_BREAK;
			cv_broadcast(&ol->ol_cv);
		}
	}

	mutex_exit(&ol->ol_mutex);
}

/*
 * smb_oplock_ack
 *
 * Process oplock acknowledgement received for ofile 'of'.
 * - oplock.ol_break is the break level that was requested.
 * - brk is the break level being acknowledged by the client.
 *
 * Update the oplock grant level to the lesser of ol_break and brk.
 * If the grant is now SMB_OPLOCK_NONE, remove the grant from the
 * oplock's grant list and delete it.
 * If the requested break level (ol_break) was NONE and the brk is
 * LEVEL_II, send another oplock break (NONE). Do not wait for an
 * acknowledgement.
 * Wake any threads waiting for the oplock break acknowledgement.
 */
void
smb_oplock_ack(smb_node_t *node, smb_ofile_t *of, uint8_t brk)
{
	smb_oplock_t		*ol;
	smb_oplock_grant_t	*og;
	boolean_t		brk_to_none = B_FALSE;

	ol = &node->n_oplock;
	mutex_enter(&ol->ol_mutex);
	smb_oplock_wait(node);

	if ((ol->ol_break == SMB_OPLOCK_NO_BREAK) ||
	    ((og = smb_oplock_get_grant(ol, of)) == NULL)) {
		mutex_exit(&ol->ol_mutex);
		return;
	}

	switch (brk) {
	case SMB_OPLOCK_BREAK_TO_NONE:
		og->og_level = SMB_OPLOCK_NONE;
		break;
	case SMB_OPLOCK_BREAK_TO_LEVEL_II:
		if (ol->ol_break == SMB_OPLOCK_BREAK_TO_LEVEL_II) {
			og->og_level = SMB_OPLOCK_LEVEL_II;
		} else {
			/* SMB_OPLOCK_BREAK_TO_NONE */
			og->og_level = SMB_OPLOCK_NONE;
			brk_to_none = B_TRUE;
		}
		break;
	default:
		SMB_PANIC();
	}

	if (og->og_level == SMB_OPLOCK_NONE) {
		smb_oplock_remove_grant(node, og);
		smb_oplock_clear_grant(og);
	}

	ol->ol_break = SMB_OPLOCK_NO_BREAK;
	cv_broadcast(&ol->ol_cv);

	if (brk_to_none) {
		smb_session_oplock_break(of->f_session,
		    of->f_tree->t_tid, of->f_fid,
		    SMB_OPLOCK_BREAK_TO_NONE);
	}

	mutex_exit(&ol->ol_mutex);
}

/*
 * smb_oplock_broadcast
 *
 * ol->ol_xthread identifies the thread that was performing an oplock
 * acquire. Other threads may be blocked awaiting completion of the
 * acquire.
 * If the calling thread is ol_ol_xthread, wake any waiting threads.
 */
void
smb_oplock_broadcast(smb_node_t *node)
{
	smb_oplock_t	*ol;

	SMB_NODE_VALID(node);
	ol = &node->n_oplock;

	mutex_enter(&ol->ol_mutex);
	if ((ol->ol_xthread != NULL) && (ol->ol_xthread == curthread)) {
		ol->ol_xthread = NULL;
		cv_broadcast(&ol->ol_cv);
	}
	mutex_exit(&ol->ol_mutex);
}

/*
 * smb_oplock_wait
 *
 * Wait for the completion of an oplock acquire.
 * If ol_xthread is not NULL and doesn't contain the pointer to the
 * context of the calling thread, the caller will sleep until the
 * ol_xthread is reset to NULL (via smb_oplock_broadcast()).
 */
static void
smb_oplock_wait(smb_node_t *node)
{
	smb_oplock_t	*ol;

	ol = &node->n_oplock;
	ASSERT(MUTEX_HELD(&ol->ol_mutex));

	if ((ol->ol_xthread != NULL) && (ol->ol_xthread != curthread)) {
		while (ol->ol_xthread != NULL)
			cv_wait(&ol->ol_cv, &ol->ol_mutex);
	}
}

/*
 * smb_oplock_set_grant
 */
static smb_oplock_grant_t *
smb_oplock_set_grant(smb_ofile_t *of, uint8_t level)
{
	smb_oplock_grant_t	*og;

	og = &of->f_oplock_grant;

	og->og_magic = SMB_OPLOCK_GRANT_MAGIC;
	og->og_level = level;
	og->og_ofile = of;
	og->og_fid = of->f_fid;
	og->og_tid = of->f_tree->t_tid;
	og->og_uid = of->f_user->u_uid;
	og->og_session = of->f_session;
	return (og);
}

/*
 * smb_oplock_clear_grant
 */
void
smb_oplock_clear_grant(smb_oplock_grant_t *og)
{
	bzero(og, sizeof (smb_oplock_grant_t));
}

/*
 * smb_oplock_insert_grant
 *
 * If there are no grants in the oplock's list install the fem
 * monitor.
 * Insert the grant into the list and increment the grant count.
 */
static int
smb_oplock_insert_grant(smb_node_t *node, smb_oplock_grant_t *og)
{
	smb_oplock_t *ol = &node->n_oplock;

	ASSERT(MUTEX_HELD(&ol->ol_mutex));

	if (ol->ol_count == 0) {
		if (smb_oplock_install_fem(node) != 0)
			return (-1);
	}

	list_insert_tail(&ol->ol_grants, og);
	++ol->ol_count;
	return (0);
}

/*
 * smb_oplock_remove_grant
 *
 * Remove the oplock grant from the list, decrement the grant count
 * and, if there are no other grants in the list, uninstall the fem
 * monitor.
 */
static void
smb_oplock_remove_grant(smb_node_t *node, smb_oplock_grant_t *og)
{
	smb_oplock_t *ol = &node->n_oplock;

	ASSERT(MUTEX_HELD(&ol->ol_mutex));
	ASSERT(ol->ol_count > 0);

	list_remove(&ol->ol_grants, og);
	if (--ol->ol_count == 0)
		smb_oplock_uninstall_fem(node);
}

/*
 * smb_oplock_exclusive_grant
 *
 * If an exclusive (EXCLUSIVE or BATCH) oplock grant exists,
 * return it. Otherwise return NULL.
 */
static smb_oplock_grant_t *
smb_oplock_exclusive_grant(list_t *grants)
{
	smb_oplock_grant_t	*og;

	og = list_head(grants);
	if (og) {
		SMB_OPLOCK_GRANT_VALID(og);
		if (SMB_OPLOCK_IS_EXCLUSIVE(og->og_level))
			return (og);
	}
	return (NULL);
}

/*
 * smb_oplock_get_grant
 *
 * Find oplock grant corresponding to the specified ofile.
 */
static smb_oplock_grant_t *
smb_oplock_get_grant(smb_oplock_t *ol, smb_ofile_t *ofile)
{
	ASSERT(MUTEX_HELD(&ol->ol_mutex));

	if (SMB_OFILE_OPLOCK_GRANTED(ofile))
		return (&ofile->f_oplock_grant);
	else
		return (NULL);
}

/*
 * smb_oplock_create_break
 */
static smb_oplock_break_t *
smb_oplock_create_break(smb_node_t *node)
{
	smb_oplock_break_t	*ob;

	ob = kmem_cache_alloc(smb_oplock_break_cache, KM_SLEEP);

	smb_node_ref(node);
	ob->ob_magic = SMB_OPLOCK_BREAK_MAGIC;
	ob->ob_node = node;

	return (ob);
}

/*
 * smb_oplock_delete_break
 */
static void
smb_oplock_delete_break(smb_oplock_break_t *ob)
{
	smb_node_release(ob->ob_node);
	kmem_cache_free(smb_oplock_break_cache, ob);
}
