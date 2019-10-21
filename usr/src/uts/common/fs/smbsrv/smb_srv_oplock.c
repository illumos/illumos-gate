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
 * Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
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
static void smb_oplock_hdl_clear(smb_ofile_t *);


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
 *   the "post work" queue on the current SR.
 *
 * Note called with the node ofile list rwlock held and
 * the oplock mutex entered.
 */
void
smb_oplock_ind_break_in_ack(smb_request_t *ack_sr, smb_ofile_t *ofile,
    uint32_t NewLevel, boolean_t AckRequired)
{
	smb_request_t *new_sr;

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
	 * request on the session doing the ack.  If we can't
	 * allocate a request on that session (because it's
	 * now disconnecting) just fall-back to the normal
	 * oplock break code path which deals with that.
	 * Once we have a request on the ack session, that
	 * session won't go away until the request is done.
	 */
	new_sr = smb_request_alloc(ack_sr->session, 0);
	if (new_sr == NULL) {
		smb_oplock_ind_break(ofile, NewLevel,
		    AckRequired, STATUS_CANT_GRANT);
		smb_ofile_release(ofile);
		return;
	}

	new_sr->sr_state = SMB_REQ_STATE_SUBMITTED;
	new_sr->smb2_async = B_TRUE;
	new_sr->user_cr = zone_kcred();
	new_sr->fid_ofile = ofile;
	if (ofile->f_tree != NULL) {
		new_sr->tid_tree = ofile->f_tree;
		smb_tree_hold_internal(ofile->f_tree);
	}
	if (ofile->f_user != NULL) {
		new_sr->uid_user = ofile->f_user;
		smb_user_hold_internal(ofile->f_user);
	}
	new_sr->arg.olbrk.NewLevel = NewLevel;
	new_sr->arg.olbrk.AckRequired = AckRequired;

	/*
	 * Using smb2_cmd_code to indicate what to call.
	 * work func. will call smb_oplock_send_brk
	 */
	new_sr->smb2_cmd_code = SMB2_OPLOCK_BREAK;
	smb2sr_append_postwork(ack_sr, new_sr);
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
 * Note called with the node ofile list rwlock held and
 * the oplock mutex entered.
 */
void
smb_oplock_ind_break(smb_ofile_t *ofile, uint32_t NewLevel,
    boolean_t AckRequired, uint32_t CompletionStatus)
{
	smb_server_t *sv = ofile->f_server;
	smb_request_t *sr = NULL;

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
	case NT_STATUS_OPLOCK_HANDLE_CLOSED:
		smb_oplock_hdl_clear(ofile);
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
	sr->arg.olbrk.NewLevel = NewLevel;
	sr->arg.olbrk.AckRequired = AckRequired;
	sr->smb2_status = CompletionStatus;

	(void) taskq_dispatch(
	    sv->sv_worker_pool,
	    smb_oplock_async_break, sr, TQ_SLEEP);
}

/*
 * smb_oplock_async_break
 *
 * Called via the taskq to handle an asynchronous oplock break.
 * We have a hold on the ofile, which will be released in
 * smb_request_free (via sr->fid_ofile)
 *
 * Note we have: sr->uid_user == NULL, sr->tid_tree == NULL.
 * Nothing called here needs those.
 *
 * Note that NewLevel as provided by the FS up-call does NOT
 * include the GRANULAR flag.  The SMB level is expected to
 * keep track of how each oplock was acquired (by lease or
 * traditional oplock request) and put the GRANULAR flag
 * back into the oplock state when calling down to the
 * FS-level code.  Also note that the lease break message
 * carries only the cache flags, not the GRANULAR flag.
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
		smb_oplock_send_brk(sr);
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

#ifdef DEBUG
int smb_oplock_debug_wait = 0;
#endif

/*
 * Send an oplock break over the wire, or if we can't,
 * then process the oplock break locally.
 *
 * Note that we have sr->fid_ofile here but all the other
 * normal sr members may be NULL:  uid_user, tid_tree.
 * Also sr->session may or may not be the same session as
 * the ofile came from (ofile->f_session) depending on
 * whether this is a "live" open or an orphaned DH,
 * where ofile->f_session will be NULL.
 *
 * Given that we don't always have a session, we determine
 * the oplock type (lease etc) from f_oplock.og_dialect.
 */
void
smb_oplock_send_brk(smb_request_t *sr)
{
	smb_ofile_t	*ofile;
	smb_lease_t	*lease;
	uint32_t	NewLevel;
	boolean_t	AckReq;
	uint32_t	status;
	int		rc;

	ofile = sr->fid_ofile;
	NewLevel = sr->arg.olbrk.NewLevel;
	AckReq = sr->arg.olbrk.AckRequired;
	lease = ofile->f_lease;

	/*
	 * Build the break message in sr->reply.
	 * It's free'd in smb_request_free().
	 * Also updates the lease and NewLevel.
	 */
	sr->reply.max_bytes = MLEN;
	if (ofile->f_oplock.og_dialect >= SMB_VERS_2_BASE) {
		if (lease != NULL) {
			/*
			 * Oplock state has changed, so
			 * update the epoch.
			 */
			mutex_enter(&lease->ls_mutex);
			lease->ls_epoch++;
			mutex_exit(&lease->ls_mutex);

			/* Note, needs "old" state in og_state */
			smb2_lease_break_notification(sr,
			    (NewLevel & CACHE_RWH), AckReq);
			NewLevel |= OPLOCK_LEVEL_GRANULAR;
		} else {
			smb2_oplock_break_notification(sr, NewLevel);
		}
	} else {
		/*
		 * SMB1 clients should only get Level II oplocks if they
		 * set the capability indicating they know about them.
		 */
		if (NewLevel == OPLOCK_LEVEL_TWO &&
		    ofile->f_oplock.og_dialect < NT_LM_0_12)
			NewLevel = OPLOCK_LEVEL_NONE;
		smb1_oplock_break_notification(sr, NewLevel);
	}

	/*
	 * Keep track of what we last sent to the client,
	 * preserving the GRANULAR flag (if a lease).
	 * If we're expecting an ACK, set og_breaking
	 * (and maybe lease->ls_breaking) so we can
	 * later find the ofile with breaks pending.
	 */
	if (AckReq) {
		uint32_t BreakTo;

		if (lease != NULL) {
			BreakTo = (NewLevel & CACHE_RWH) << BREAK_SHIFT;
			if (BreakTo == 0)
				BreakTo = BREAK_TO_NO_CACHING;
			lease->ls_breaking = BreakTo;
		} else {
			if ((NewLevel & LEVEL_TWO_OPLOCK) != 0)
				BreakTo = BREAK_TO_TWO;
			else
				BreakTo = BREAK_TO_NONE;
		}
		/* Will update og_state in ack. */
		ofile->f_oplock.og_breaking = BreakTo;
	} else {
		if (lease != NULL)
			lease->ls_state = NewLevel & CACHE_RWH;
		ofile->f_oplock.og_state = NewLevel;

		if (ofile->dh_persist) {
			smb2_dh_update_oplock(sr, ofile);
		}
	}

	/*
	 * Try to send the break message to the client.
	 * When we get to multi-channel, this is supposed to
	 * try to send on every channel before giving up.
	 */
	if (sr->session == ofile->f_session)
		rc = smb_session_send(sr->session, 0, &sr->reply);
	else
		rc = ENOTCONN;

	if (rc == 0) {
		/*
		 * OK, we were able to send the break message.
		 * If no ack. required, we're done.
		 */
		if (!AckReq)
			return;

		/*
		 * We're expecting an ACK.  Wait in this thread
		 * so we can log clients that don't respond.
		 *
		 * If debugging, may want to break after a
		 * short wait to look into why we might be
		 * holding up progress.  (i.e. locks?)
		 */
#ifdef DEBUG
		if (smb_oplock_debug_wait > 0) {
			status = smb_oplock_wait_break(ofile->f_node,
			    smb_oplock_debug_wait);
			if (status == 0)
				return;
			cmn_err(CE_NOTE, "clnt %s oplock break wait debug",
			    sr->session->ip_addr_str);
			debug_enter("oplock_wait");
		}
#endif
		status = smb_oplock_wait_break(ofile->f_node,
		    smb_oplock_timeout_ack);
		if (status == 0)
			return;

		cmn_err(CE_NOTE, "clnt %s oplock break timeout",
		    sr->session->ip_addr_str);
		DTRACE_PROBE1(break_timeout, smb_ofile_t, ofile);

		/*
		 * Will do local ack below.  Note, after timeout,
		 * do a break to none or "no caching" regardless
		 * of what the passed in cache level was.
		 * That means: clear all except GRANULAR.
		 */
		NewLevel &= OPLOCK_LEVEL_GRANULAR;
	} else {
		/*
		 * We were unable to send the oplock break request.
		 * Generally, that means we have no connection to this
		 * client right now, and this ofile will have state
		 * SMB_OFILE_STATE_ORPHANED.  We either close the handle
		 * or break the oplock locally, in which case the client
		 * gets the updated oplock state when they reconnect.
		 * Decide whether to keep or close.
		 *
		 * Relevant [MS-SMB2] sections:
		 *
		 * 3.3.4.6 Object Store Indicates an Oplock Break
		 * If Open.Connection is NULL, Open.IsResilient is FALSE,
		 * Open.IsDurable is FALSE and Open.IsPersistent is FALSE,
		 * the server SHOULD close the Open as specified in...
		 *
		 * 3.3.4.7 Object Store Indicates a Lease Break
		 * If Open.Connection is NULL, the server MUST close the
		 * Open as specified in ... for the following cases:
		 * - Open.IsResilient is FALSE, Open.IsDurable is FALSE,
		 *   and Open.IsPersistent is FALSE.
		 * - Lease.BreakToLeaseState does not contain
		 *   ...HANDLE_CACHING and Open.IsDurable is TRUE.
		 * If Lease.LeaseOpens is empty, (... local ack to "none").
		 */

		/*
		 * See similar logic in smb_dh_should_save
		 */
		switch (ofile->dh_vers) {
		case SMB2_RESILIENT:
			break;			/* keep DH */

		case SMB2_DURABLE_V2:
			if (ofile->dh_persist)
				break;		/* keep DH */
			/* FALLTHROUGH */
		case SMB2_DURABLE_V1:
			/* IS durable (v1 or v2) */
			if ((NewLevel & (OPLOCK_LEVEL_BATCH |
			    OPLOCK_LEVEL_CACHE_HANDLE)) != 0)
				break;		/* keep DH */
			/* FALLTHROUGH */
		case SMB2_NOT_DURABLE:
		default:
			smb_ofile_close(ofile, 0);
			return;
		}
		/* Keep this ofile (durable handle). */

		if (!AckReq) {
			/* Nothing more to do. */
			return;
		}
	}

	/*
	 * We get here after either an oplock break ack timeout,
	 * or a send failure for a durable handle type that we
	 * preserve rather than just close.  Do local ack.
	 */
	ofile->f_oplock.og_breaking = 0;
	if (lease != NULL)
		lease->ls_breaking = 0;

	status = smb_oplock_ack_break(sr, ofile, &NewLevel);
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		/* Not expecting this status return. */
		cmn_err(CE_NOTE, "clnt local oplock ack wait?");
		(void) smb_oplock_wait_break(ofile->f_node,
		    smb_oplock_timeout_ack);
		status = 0;
	}
	if (status != 0) {
		cmn_err(CE_NOTE, "clnt local oplock ack, "
		    "status=0x%x", status);
	}

	/* Update og_state as if we heard from the client. */
	ofile->f_oplock.og_state = NewLevel;
	if (lease != NULL) {
		lease->ls_state = NewLevel & CACHE_RWH;
	}

	if (ofile->dh_persist) {
		smb2_dh_update_oplock(sr, ofile);
	}
}

/*
 * See: NT_STATUS_OPLOCK_HANDLE_CLOSED above,
 * and: STATUS_NEW_HANDLE
 *
 * The FS-level oplock layer calls this to update the
 * SMB-level state when a handle loses its oplock.
 */
static void
smb_oplock_hdl_clear(smb_ofile_t *ofile)
{
	smb_lease_t *lease = ofile->f_lease;

	if (lease != NULL) {
		if (lease->ls_oplock_ofile == ofile) {
			/* Last close on the lease. */
			lease->ls_oplock_ofile = NULL;
		}
	}
	ofile->f_oplock.og_state = 0;
	ofile->f_oplock.og_breaking = 0;
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
smb_oplock_wait_break(smb_node_t *node, int timeout)  /* mSec. */
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
