/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2021-2023 RackTop Systems, Inc.
 */

/*
 * (SMB1/SMB2) Server-level Oplock support.
 *
 * Conceptually, this is a separate layer on top of the
 * file system (FS) layer oplock code in smb_cmn_oplock.c.
 * If these layers were more distinct, the FS layer would
 * need to use call-back functions (installed from here)
 * to "indicate an oplock break to the server" (see below).
 * As these layers are all in the same kernel module, the
 * delivery of these break indications just uses a direct
 * function call to smb_oplock_ind_break() below.
 *
 * This layer is responsible for handling the break indication,
 * which often requires scheduling a taskq job in the server,
 * and sending an oplock break mesage to the client using
 * the appropriate protocol for the open handle affected.
 *
 * The details of composing an oplock break message, the
 * protocol-specific details of requesting an oplock, and
 * returning that oplock to the client are in the files:
 *  smb_oplock.c, smb2_oplock.c, smb2_lease.c
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_oplock.h>

/*
 * Verify relationship between BREAK_TO_... and CACHE bits,
 * used when setting the BREAK_TO_... below.
 */
#if BREAK_TO_READ_CACHING != (READ_CACHING << BREAK_SHIFT)
#error "BREAK_TO_READ_CACHING"
#endif
#if BREAK_TO_HANDLE_CACHING != (HANDLE_CACHING << BREAK_SHIFT)
#error "BREAK_TO_HANDLE_CACHING"
#endif
#if BREAK_TO_WRITE_CACHING != (WRITE_CACHING << BREAK_SHIFT)
#error "BREAK_TO_WRITE_CACHING"
#endif
#define	CACHE_RWH (READ_CACHING | WRITE_CACHING | HANDLE_CACHING)

/*
 * This is the timeout used in the thread that sends an
 * oplock break and waits for the client to respond
 * before it breaks the oplock locally.
 */
int smb_oplock_timeout_ack = 30000; /* mSec. */

/*
 * This is the timeout used in threads that have just
 * finished some sort of oplock request and now must
 * wait for (possibly multiple) breaks to complete.
 * This value must be at least a couple seconds LONGER
 * than the ack timeout above so that I/O callers won't
 * give up waiting before the local ack timeout.
 */
int smb_oplock_timeout_def = 45000; /* mSec. */

static void smb_oplock_async_break(void *);
static void smb_oplock_hdl_update(smb_request_t *sr);
static void smb_oplock_hdl_moved(smb_ofile_t *);
static void smb_oplock_hdl_closed(smb_ofile_t *);
static void smb_oplock_wait_break_cancel(smb_request_t *sr);


/*
 * 2.1.5.17.3 Indicating an Oplock Break to the Server
 *
 * The inputs for indicating an oplock break to the server are:
 *
 *	BreakingOplockOpen: The Open used to request the oplock
 *	  that is now breaking.
 *	 NewOplockLevel: The type of oplock the requested oplock
 *	  has been broken to.  Valid values are as follows:
 *		LEVEL_NONE (that is, no oplock)
 *		LEVEL_TWO
 *		A combination of one or more of the following flags:
 *			READ_CACHING
 *			HANDLE_CACHING
 *			WRITE_CACHING
 *	AcknowledgeRequired: A Boolean value; TRUE if the server
 *	  MUST acknowledge the oplock break, FALSE if not,
 *	  as specified in section 2.1.5.18.
 *	OplockCompletionStatus: The NTSTATUS code to return to the server.
 *
 * This algorithm simply represents the completion of an oplock request,
 * as specified in section 2.1.5.17.1 or section 2.1.5.17.2. The server
 * is expected to associate the return status from this algorithm with
 * BreakingOplockOpen, which is the Open passed in when it requested
 * the oplock that is now breaking.
 *
 * It is important to note that because several oplocks can be outstanding
 * in parallel, although this algorithm represents the completion of an
 * oplock request, it might not result in the completion of the algorithm
 * that called it. In particular, calling this algorithm will result in
 * completion of the caller only if BreakingOplockOpen is the same as the
 * Open with which the calling algorithm was itself called. To mitigate
 * confusion, each algorithm that refers to this section will specify
 * whether that algorithm's operation terminates at that point or not.
 *
 * The object store MUST return OplockCompletionStatus,
 * AcknowledgeRequired, and NewOplockLevel to the server (the algorithm is
 * as specified in section 2.1.5.17.1 and section 2.1.5.17.2).
 *
 * Implementation:
 *
 * We use two versions of this function:
 *	smb_oplock_ind_break_in_ack
 *	smb_oplock_ind_break
 *
 * The first is used when we're handling an Oplock Break Ack.
 * The second is used when other operations cause a break,
 * generally in one of the smb_oplock_break_... functions.
 *
 * Note that these are call-back functions that may be called with the
 * node ofile list rwlock held and the node oplock mutex entered, so
 * these should ONLY schedule oplock break work, and MUST NOT attempt
 * any actions that might require either of those locks.
 */

/*
 * smb_oplock_ind_break_in_ack
 *
 * Variant of smb_oplock_ind_break() for the oplock Ack handler.
 * When we need to indicate another oplock break from within the
 * Ack handler (during the Ack. of some previous oplock break)
 * we need to make sure this new break indication goes out only
 * AFTER the reply to the current break ack. is sent out.
 *
 * In this case, we always have an SR (the break ack) so we can
 * append the "ind break" work to the current SR and let the
 * request hander thread do this work after the reply is sent.
 * Note: this is always an SMB2 or later request, because this
 * only happens for "granular" oplocks, which are SMB2-only.
 *
 * This is mostly the same as smb_oplock_ind_break() except:
 * - The only CompletionStatus possible is STATUS_CANT_GRANT.
 * - Instead of taskq_dispatch this appends the new SR to
 *   the "post work" queue on the current SR (if possible).
 *
 * Note called with the node ofile list rwlock held and
 * the oplock mutex entered.
 */
void
smb_oplock_ind_break_in_ack(smb_request_t *ack_sr, smb_ofile_t *ofile,
    uint32_t NewLevel, boolean_t AckRequired)
{
	smb_server_t *sv = ofile->f_server;
	smb_node_t *node = ofile->f_node;
	smb_request_t *sr = NULL;
	taskqid_t tqid;
	boolean_t use_postwork = B_TRUE;

	ASSERT(RW_READ_HELD(&node->n_ofile_list.ll_lock));
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));

	/*
	 * This should happen only with SMB2 or later,
	 * but in case that ever changes...
	 */
	if (ack_sr->session->dialect < SMB_VERS_2_BASE) {
		smb_oplock_ind_break(ofile, NewLevel,
		    AckRequired, STATUS_CANT_GRANT);
		return;
	}

	/*
	 * We're going to schedule a request that will have a
	 * reference to this ofile. Get the hold first.
	 */
	if (!smb_ofile_hold_olbrk(ofile)) {
		/* It's closing (or whatever).  Nothing to do. */
		return;
	}

	/*
	 * When called from Ack processing, we want to use a
	 * request on the session doing the ack, so we can
	 * append "post work" to that session.  If we can't
	 * allocate a request on that session (because it's
	 * now disconnecting) use a request from the server
	 * session like smb_oplock_ind_break does, and then
	 * use taskq_dispatch instead of postwork.
	 */
	sr = smb_request_alloc(ack_sr->session, 0);
	if (sr == NULL) {
		use_postwork = B_FALSE;
		sr = smb_request_alloc(sv->sv_session, 0);
	}
	if (sr == NULL) {
		/*
		 * Server must be shutting down.  We took a
		 * hold on the ofile that must be released,
		 * but we can't release here because we're
		 * called with the node ofile list entered.
		 * See smb_ofile_release_LL.
		 */
		smb_llist_post(&node->n_ofile_list, ofile,
		    smb_ofile_release_LL);
		return;
	}

	sr->sr_state = SMB_REQ_STATE_SUBMITTED;
	sr->smb2_async = B_TRUE;
	sr->user_cr = zone_kcred();
	sr->fid_ofile = ofile;
	if (ofile->f_tree != NULL) {
		sr->tid_tree = ofile->f_tree;
		smb_tree_hold_internal(sr->tid_tree);
	}
	if (ofile->f_user != NULL) {
		sr->uid_user = ofile->f_user;
		smb_user_hold_internal(sr->uid_user);
	}
	if (ofile->f_lease != NULL)
		NewLevel |= OPLOCK_LEVEL_GRANULAR;

	sr->arg.olbrk.NewLevel = NewLevel;
	sr->arg.olbrk.AckRequired = AckRequired;

	/*
	 * Could do this in _hdl_update but this way it's
	 * visible in the dtrace fbt entry probe.
	 */
	sr->arg.olbrk.OldLevel = ofile->f_oplock.og_breakto;

	smb_oplock_hdl_update(sr);

	if (use_postwork) {
		/*
		 * Using smb2_cmd_code to indicate what to call.
		 * work func. will call smb_oplock_send_brk
		 */
		sr->smb2_cmd_code = SMB2_OPLOCK_BREAK;
		smb2sr_append_postwork(ack_sr, sr);
		return;
	}

	/* Will call smb_oplock_send_break */
	sr->smb2_status = STATUS_CANT_GRANT;
	tqid = taskq_dispatch(sv->sv_notify_pool,
	    smb_oplock_async_break, sr, TQ_SLEEP);
	VERIFY(tqid != TASKQID_INVALID);
}

/*
 * smb_oplock_ind_break
 *
 * This is the function described in [MS-FSA] 2.1.5.17.3
 * which is called many places in the oplock break code.
 *
 * Schedule a request & taskq job to do oplock break work
 * as requested by the FS-level code (smb_cmn_oplock.c).
 *
 * See also: smb_oplock_ind_break_in_ack
 *
 * Note called with the node ofile list rwlock held and
 * the oplock mutex entered.
 */
void
smb_oplock_ind_break(smb_ofile_t *ofile, uint32_t NewLevel,
    boolean_t AckRequired, uint32_t CompletionStatus)
{
	smb_server_t *sv = ofile->f_server;
	smb_node_t *node = ofile->f_node;
	smb_request_t *sr = NULL;
	taskqid_t tqid;

	ASSERT(RW_READ_HELD(&node->n_ofile_list.ll_lock));
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));

	/*
	 * See notes at smb_oplock_async_break re. CompletionStatus
	 * Check for any invalid codes here, so assert happens in
	 * the thread passing an unexpected value.
	 * The real work happens in a taskq job.
	 */
	switch (CompletionStatus) {

	case NT_STATUS_SUCCESS:
	case STATUS_CANT_GRANT:
		/* Send break via taskq job. */
		break;

	case STATUS_NEW_HANDLE:
		smb_oplock_hdl_moved(ofile);
		return;

	case NT_STATUS_OPLOCK_HANDLE_CLOSED:
		smb_oplock_hdl_closed(ofile);
		return;

	default:
		ASSERT(0);
		return;
	}

	/*
	 * We're going to schedule a request that will have a
	 * reference to this ofile. Get the hold first.
	 */
	if (!smb_ofile_hold_olbrk(ofile)) {
		/* It's closing (or whatever).  Nothing to do. */
		return;
	}

	/*
	 * We need a request allocated on the session that owns
	 * this ofile in order to safely send on that session.
	 *
	 * Note that while we hold a ref. on the ofile, it's
	 * f_session will not change.  An ofile in state
	 * _ORPHANED will have f_session == NULL, but the
	 * f_session won't _change_ while we have a ref,
	 * and won't be torn down under our feet.
	 * Same for f_tree and f_user
	 *
	 * If f_session is NULL, or it's in a state that doesn't
	 * allow new requests, use the special "server" session.
	 */
	if (ofile->f_session != NULL)
		sr = smb_request_alloc(ofile->f_session, 0);
	if (sr == NULL)
		sr = smb_request_alloc(sv->sv_session, 0);
	if (sr == NULL) {
		/*
		 * Server must be shutting down.  We took a
		 * hold on the ofile that must be released,
		 * but we can't release here because we're
		 * called with the node ofile list entered.
		 * See smb_ofile_release_LL.
		 */
		smb_llist_post(&node->n_ofile_list, ofile,
		    smb_ofile_release_LL);
		return;
	}

	sr->sr_state = SMB_REQ_STATE_SUBMITTED;
	sr->smb2_async = B_TRUE;
	sr->user_cr = zone_kcred();
	sr->fid_ofile = ofile;
	if (ofile->f_tree != NULL) {
		sr->tid_tree = ofile->f_tree;
		smb_tree_hold_internal(sr->tid_tree);
	}
	if (ofile->f_user != NULL) {
		sr->uid_user = ofile->f_user;
		smb_user_hold_internal(sr->uid_user);
	}
	if (ofile->f_lease != NULL)
		NewLevel |= OPLOCK_LEVEL_GRANULAR;

	sr->arg.olbrk.NewLevel = NewLevel;
	sr->arg.olbrk.AckRequired = AckRequired;
	sr->smb2_status = CompletionStatus;

	/*
	 * Could do this in _hdl_update but this way it's
	 * visible in the dtrace fbt entry probe.
	 */
	sr->arg.olbrk.OldLevel = ofile->f_oplock.og_breakto;

	smb_oplock_hdl_update(sr);

	/* Will call smb_oplock_send_break */
	tqid = taskq_dispatch(sv->sv_notify_pool,
	    smb_oplock_async_break, sr, TQ_SLEEP);
	VERIFY(tqid != TASKQID_INVALID);
}

/*
 * smb_oplock_async_break
 *
 * Called via the taskq to handle an asynchronous oplock break.
 * We have a hold on the ofile, which will be released in
 * smb_request_free (via sr->fid_ofile)
 *
 * Note we may have: sr->uid_user == NULL, sr->tid_tree == NULL.
 */
static void
smb_oplock_async_break(void *arg)
{
	smb_request_t	*sr = arg;
	uint32_t	CompletionStatus;

	SMB_REQ_VALID(sr);

	CompletionStatus = sr->smb2_status;
	sr->smb2_status = NT_STATUS_SUCCESS;

	mutex_enter(&sr->sr_mutex);
	sr->sr_worker = curthread;
	sr->sr_state = SMB_REQ_STATE_ACTIVE;
	mutex_exit(&sr->sr_mutex);

	/*
	 * Note that the CompletionStatus from the FS level
	 * (smb_cmn_oplock.c) encodes what kind of action we
	 * need to take at the SMB level.
	 */
	switch (CompletionStatus) {

	case STATUS_CANT_GRANT:
	case NT_STATUS_SUCCESS:
		smb_oplock_send_break(sr);
		break;

	default:
		/* Checked by caller. */
		ASSERT(0);
		break;
	}

	if (sr->dh_nvl_dirty) {
		sr->dh_nvl_dirty = B_FALSE;
		smb2_dh_update_nvfile(sr);
	}

	sr->sr_state = SMB_REQ_STATE_COMPLETED;
	smb_request_free(sr);
}

/*
 * Send an oplock (or lease) break to the client.
 * If we can't, then do a local break.
 *
 * This is called either from smb_oplock_async_break via a
 * taskq job scheduled in smb_oplock_ind_break, or from the
 * smb2sr_append_postwork() mechanism when we're doing a
 * "break in ack", via smb_oplock_ind_break_in_ack.
 *
 * We don't always have an sr->session here, so
 * determine the oplock type (lease etc) from
 * f_lease and f_oplock.og_dialect etc.
 */
void
smb_oplock_send_break(smb_request_t *sr)
{
	smb_ofile_t	*ofile = sr->fid_ofile;

	if (ofile->f_lease != NULL)
		smb2_lease_send_break(sr);
	else if (ofile->f_oplock.og_dialect >= SMB_VERS_2_BASE)
		smb2_oplock_send_break(sr);
	else
		smb1_oplock_send_break(sr);
}

/*
 * Called by smb_oplock_ind_break for the case STATUS_NEW_HANDLE,
 * which is an alias for NT_STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE.
 *
 * The FS-level oplock layer calls this to update the SMB-level state
 * when the oplock for some lease is about to move to a different
 * ofile on the lease.
 *
 * To avoid later confusion, clear og_state on this ofile now.
 * Without this, smb_oplock_move() may issue debug complaints
 * about moving oplock state onto a non-empty oplock.
 */
static const smb_ofile_t invalid_ofile;
static void
smb_oplock_hdl_moved(smb_ofile_t *ofile)
{
	smb_lease_t *ls = ofile->f_lease;

	ASSERT(ls != NULL);
	if (ls != NULL && ls->ls_oplock_ofile == ofile)
		ls->ls_oplock_ofile = (smb_ofile_t *)&invalid_ofile;

	ofile->f_oplock.og_state = 0;
	ofile->f_oplock.og_breakto = 0;
	ofile->f_oplock.og_breaking = B_FALSE;
}

/*
 * See: NT_STATUS_OPLOCK_HANDLE_CLOSED above and
 * smb_ofile_close, smb_oplock_break_CLOSE.
 *
 * The FS-level oplock layer calls this to update the
 * SMB-level state when a handle loses its oplock.
 */
static void
smb_oplock_hdl_closed(smb_ofile_t *ofile)
{
	smb_lease_t *lease = ofile->f_lease;

	if (lease != NULL) {
		if (lease->ls_oplock_ofile == ofile) {
			/*
			 * smb2_lease_ofile_close should have
			 * moved the oplock to another ofile.
			 */
			ASSERT(0);
			lease->ls_oplock_ofile = NULL;
		}
	}
	ofile->f_oplock.og_state = 0;
	ofile->f_oplock.og_breakto = 0;
	ofile->f_oplock.og_breaking = B_FALSE;
}

/*
 * smb_oplock_hdl_update
 *
 * Called by smb_oplock_ind_break (and ...in_ack) just before we
 * schedule smb_oplock_async_break / mb_oplock_send_break taskq job,
 * so we can make any state changes that should happen immediately.
 *
 * Here, keep track of what we will send to the client.
 * Saves old state in arg.olbck.OldLevel
 *
 * Note that because we may be in the midst of processing an
 * smb_oplock_ack_break call here, the _breaking flag will be
 * temporarily false, and is set true again if this ack causes
 * another break.  This makes it tricky to know when to update
 * the epoch, which is not supposed to increment when there's
 * already an unacknowledged break out to the client.
 * We can recognize that by comparing ls_state vs ls_breakto.
 * If no unacknowledged break, ls_state == ls_breakto.
 */
static void
smb_oplock_hdl_update(smb_request_t *sr)
{
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_lease_t	*lease = ofile->f_lease;
	uint32_t	NewLevel = sr->arg.olbrk.NewLevel;
	boolean_t	AckReq = sr->arg.olbrk.AckRequired;

#ifdef	DEBUG
	smb_node_t *node = ofile->f_node;
	ASSERT(RW_READ_HELD(&node->n_ofile_list.ll_lock));
	ASSERT(MUTEX_HELD(&node->n_oplock.ol_mutex));
#endif

	/* Caller sets arg.olbrk.OldLevel */
	ofile->f_oplock.og_breakto = NewLevel;
	ofile->f_oplock.og_breaking = B_TRUE;
	if (lease != NULL) {
		// If no unacknowledged break, update epoch.
		if (lease->ls_breakto == lease->ls_state)
			lease->ls_epoch++;

		lease->ls_breakto = NewLevel;
		lease->ls_breaking = B_TRUE;
	}

	if (!AckReq) {
		/*
		 * Not expecting an Ack from the client.
		 * Update state immediately.
		 */
		ofile->f_oplock.og_state = NewLevel;
		ofile->f_oplock.og_breaking = B_FALSE;
		if (lease != NULL) {
			lease->ls_state = NewLevel;
			lease->ls_breaking = B_FALSE;
		}
		if (ofile->dh_persist) {
			smb2_dh_update_oplock(sr, ofile);
		}
	}
}

/*
 * Helper for smb_ofile_close
 *
 * Note that a client may close an ofile in response to an
 * oplock break or lease break intead of doing an Ack break,
 * so this must wake anything that might be waiting on an ack.
 */
void
smb_oplock_close(smb_ofile_t *ofile)
{
	smb_node_t *node = ofile->f_node;

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	if (ofile->f_oplock_closing == B_FALSE) {
		ofile->f_oplock_closing = B_TRUE;

		if (ofile->f_lease != NULL)
			smb2_lease_ofile_close(ofile);

		smb_oplock_break_CLOSE(node, ofile);

		ofile->f_oplock.og_state = 0;
		ofile->f_oplock.og_breakto = 0;
		ofile->f_oplock.og_breaking = B_FALSE;
		cv_broadcast(&ofile->f_oplock.og_ack_cv);
	}

	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);
}

/*
 * Called by smb_request_cancel() via sr->cancel_method
 * Arg is the smb_node_t with the breaking oplock.
 */
static void
smb_oplock_wait_ack_cancel(smb_request_t *sr)
{
	kcondvar_t	*cvp = sr->cancel_arg2;
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_node_t	*node = ofile->f_node;

	mutex_enter(&node->n_oplock.ol_mutex);
	cv_broadcast(cvp);
	mutex_exit(&node->n_oplock.ol_mutex);
}

/*
 * Wait for an oplock break ACK to arrive.  This is called after
 * we've sent an oplock break or lease break to the client where
 * an "Ack break" is expected back.  If we get an Ack, that will
 * wake us up via smb2_oplock_break_ack or smb2_lease_break_ack.
 *
 * Wait until state reduced to NewLevel (or less).
 * Note that in multi-break cases, we might wait here for just
 * one ack when another has become pending, in which case the
 * og_breakto might be a subset of NewLevel.  Wait until the
 * state field is no longer a superset of NewLevel.
 */
uint32_t
smb_oplock_wait_ack(smb_request_t *sr, uint32_t NewLevel)
{
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_lease_t	*lease = ofile->f_lease;
	smb_node_t	*node = ofile->f_node;
	smb_oplock_t	*ol = &node->n_oplock;
	uint32_t	*state_p;
	kcondvar_t	*cv_p;
	clock_t		time, rv;
	uint32_t	status = 0;
	smb_req_state_t  srstate;
	uint32_t	wait_mask;

	time = ddi_get_lbolt() +
	    MSEC_TO_TICK(smb_oplock_timeout_ack);

	/*
	 * Wait on either lease state or oplock state
	 */
	if (lease != NULL) {
		state_p = &lease->ls_state;
		cv_p = &lease->ls_ack_cv;
	} else {
		state_p = &ofile->f_oplock.og_state;
		cv_p = &ofile->f_oplock.og_ack_cv;
	}

	/*
	 * These are all the bits that we wait to be cleared.
	 */
	wait_mask = ~NewLevel & (CACHE_RWH |
	    LEVEL_TWO | LEVEL_ONE | LEVEL_BATCH);

	/*
	 * Setup cancellation callback
	 */
	mutex_enter(&sr->sr_mutex);
	if (sr->sr_state != SMB_REQ_STATE_ACTIVE) {
		mutex_exit(&sr->sr_mutex);
		return (NT_STATUS_CANCELLED);
	}
	sr->sr_state = SMB_REQ_STATE_WAITING_OLBRK;
	sr->cancel_method = smb_oplock_wait_ack_cancel;
	sr->cancel_arg2 = cv_p;
	mutex_exit(&sr->sr_mutex);

	/*
	 * Enter the wait loop
	 */
	mutex_enter(&ol->ol_mutex);

	while ((*state_p & wait_mask) != 0) {
		rv = cv_timedwait(cv_p, &ol->ol_mutex, time);
		if (rv < 0) {
			/* cv_timewait timeout */
			char *fname;
			char *opname;
			int rc;

			/*
			 * Get the path name of the open file
			 */
			fname = smb_srm_zalloc(sr, MAXPATHLEN);
			rc = smb_node_getpath(node, NULL, fname, MAXPATHLEN);
			if (rc != 0) {
				/* Not expected. Just show last part. */
				(void) snprintf(fname, MAXPATHLEN, "(?)/%s",
				    node->od_name);
			}

			/*
			 * Get an operation name reflecting which kind of
			 * lease or oplock break got us here, so the log
			 * message will say "lease break" or whatever.
			 */
			if (lease != NULL) {
				opname = "lease";
			} else if (ofile->f_oplock.og_dialect >=
			    SMB_VERS_2_BASE) {
				opname = "oplock2";
			} else {
				opname = "oplock1";
			}

			cmn_err(CE_NOTE, "!client %s %s break timeout for %s",
			    sr->session->ip_addr_str, opname, fname);

			status = NT_STATUS_CANNOT_BREAK_OPLOCK;
			break;
		}

		/*
		 * Check if we were woken by smb_request_cancel,
		 * which sets state SMB_REQ_STATE_CANCEL_PENDING
		 * and signals the CV.  The mutex enter/exit is
		 * just to ensure cache visibility of sr_state
		 * that was updated in smb_request_cancel.
		 */
		mutex_enter(&sr->sr_mutex);
		srstate = sr->sr_state;
		mutex_exit(&sr->sr_mutex);
		if (srstate != SMB_REQ_STATE_WAITING_OLBRK) {
			break;
		}
	}
	mutex_exit(&ol->ol_mutex);

	/*
	 * Clear cancellation callback and see if it fired.
	 */
	mutex_enter(&sr->sr_mutex);
	sr->cancel_method = NULL;
	sr->cancel_arg2 = NULL;
	switch (sr->sr_state) {
	case SMB_REQ_STATE_WAITING_OLBRK:
		sr->sr_state = SMB_REQ_STATE_ACTIVE;
		/* status from above */
		break;
	case SMB_REQ_STATE_CANCEL_PENDING:
		sr->sr_state = SMB_REQ_STATE_CANCELLED;
		status = NT_STATUS_CANCELLED;
		break;
	default:
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}
	mutex_exit(&sr->sr_mutex);

	return (status);
}

/*
 * Called by smb_request_cancel() via sr->cancel_method
 * Arg is the smb_node_t with the breaking oplock.
 */
static void
smb_oplock_wait_break_cancel(smb_request_t *sr)
{
	smb_node_t   *node = sr->cancel_arg2;
	smb_oplock_t *ol;

	SMB_NODE_VALID(node);
	ol = &node->n_oplock;

	mutex_enter(&ol->ol_mutex);
	cv_broadcast(&ol->WaitingOpenCV);
	mutex_exit(&ol->ol_mutex);
}

/*
 * Wait up to "timeout" mSec. for the current oplock "breaking" flags
 * to be cleared (by smb_oplock_ack_break or smb_oplock_break_CLOSE).
 *
 * Callers of the above public oplock functions:
 *	smb_oplock_request()
 *	smb_oplock_ack_break()
 *	smb_oplock_break_OPEN() ...
 * check for return status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS
 * and call this function to wait for the break to complete.
 *
 * Most callers should use this default timeout, which they get
 * by passing zero as the timeout arg.  This include places where
 * we're about to do something that invalidates some cache.
 */
uint32_t
smb_oplock_wait_break(smb_request_t *sr, smb_node_t *node, int timeout)
{
	smb_oplock_t	*ol;
	clock_t		time, rv;
	uint32_t	status = 0;
	smb_req_state_t  srstate;

	SMB_NODE_VALID(node);
	ol = &node->n_oplock;

	if (timeout == 0)
		timeout = smb_oplock_timeout_def;
	time = MSEC_TO_TICK(timeout) + ddi_get_lbolt();

	mutex_enter(&sr->sr_mutex);
	if (sr->sr_state != SMB_REQ_STATE_ACTIVE) {
		mutex_exit(&sr->sr_mutex);
		return (NT_STATUS_CANCELLED);
	}
	sr->sr_state = SMB_REQ_STATE_WAITING_OLBRK;
	sr->cancel_method = smb_oplock_wait_break_cancel;
	sr->cancel_arg2 = node;
	mutex_exit(&sr->sr_mutex);

	mutex_enter(&ol->ol_mutex);
	while ((ol->ol_state & BREAK_ANY) != 0) {
		ol->waiters++;
		rv = cv_timedwait(&ol->WaitingOpenCV,
		    &ol->ol_mutex, time);
		ol->waiters--;
		if (rv < 0) {
			/* cv_timewait timeout */
			status = NT_STATUS_CANNOT_BREAK_OPLOCK;
			break;
		}

		/*
		 * Check if we were woken by smb_request_cancel,
		 * which sets state SMB_REQ_STATE_CANCEL_PENDING
		 * and signals the CV.  The mutex enter/exit is
		 * just to ensure cache visibility of sr_state
		 * that was updated in smb_request_cancel.
		 */
		mutex_enter(&sr->sr_mutex);
		srstate = sr->sr_state;
		mutex_exit(&sr->sr_mutex);
		if (srstate != SMB_REQ_STATE_WAITING_OLBRK) {
			break;
		}
	}

	mutex_exit(&ol->ol_mutex);

	mutex_enter(&sr->sr_mutex);
	sr->cancel_method = NULL;
	sr->cancel_arg2 = NULL;
	switch (sr->sr_state) {
	case SMB_REQ_STATE_WAITING_OLBRK:
		sr->sr_state = SMB_REQ_STATE_ACTIVE;
		/* status from above */
		break;
	case SMB_REQ_STATE_CANCEL_PENDING:
		sr->sr_state = SMB_REQ_STATE_CANCELLED;
		status = NT_STATUS_CANCELLED;
		break;
	default:
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}
	mutex_exit(&sr->sr_mutex);

	return (status);
}

/*
 * Simplified version used in smb_fem.c, like above,
 * but no smb_request_cancel stuff.
 */
uint32_t
smb_oplock_wait_break_fem(smb_node_t *node, int timeout)  /* mSec. */
{
	smb_oplock_t	*ol;
	clock_t		time, rv;
	uint32_t	status = 0;

	if (timeout == 0)
		timeout = smb_oplock_timeout_def;

	SMB_NODE_VALID(node);
	ol = &node->n_oplock;

	mutex_enter(&ol->ol_mutex);
	time = MSEC_TO_TICK(timeout) + ddi_get_lbolt();

	while ((ol->ol_state & BREAK_ANY) != 0) {
		ol->waiters++;
		rv = cv_timedwait(&ol->WaitingOpenCV,
		    &ol->ol_mutex, time);
		ol->waiters--;
		if (rv < 0) {
			status = NT_STATUS_CANNOT_BREAK_OPLOCK;
			break;
		}
	}

	mutex_exit(&ol->ol_mutex);

	return (status);
}
