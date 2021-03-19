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
 * Copyright 2015-2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 */


#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_kstat.h>
#include <smbsrv/smb2.h>

#define	SMB2_ASYNCID(sr) (sr->smb2_messageid ^ (1ULL << 62))

smb_sdrc_t smb2_invalid_cmd(smb_request_t *);
static void smb2_tq_work(void *);
static void smb2sr_run_postwork(smb_request_t *);
static int smb3_decrypt_msg(smb_request_t *);

static const smb_disp_entry_t
smb2_disp_table[SMB2__NCMDS] = {

	/* text-name, pre, func, post, cmd-code, dialect, flags */

	{  "smb2_negotiate", NULL,
	    smb2_negotiate, NULL, 0, 0,
	    SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID },

	{  "smb2_session_setup", NULL,
	    smb2_session_setup, NULL, 0, 0,
	    SDDF_SUPPRESS_TID | SDDF_SUPPRESS_UID },

	{  "smb2_logoff", NULL,
	    smb2_logoff, NULL, 0, 0,
	    SDDF_SUPPRESS_TID },

	{  "smb2_tree_connect", NULL,
	    smb2_tree_connect, NULL, 0, 0,
	    SDDF_SUPPRESS_TID },

	{  "smb2_tree_disconn", NULL,
	    smb2_tree_disconn, NULL, 0, 0 },

	{  "smb2_create", NULL,
	    smb2_create, NULL, 0, 0 },

	{  "smb2_close", NULL,
	    smb2_close, NULL, 0, 0 },

	{  "smb2_flush", NULL,
	    smb2_flush, NULL, 0, 0 },

	{  "smb2_read", NULL,
	    smb2_read, NULL, 0, 0 },

	{  "smb2_write", NULL,
	    smb2_write, NULL, 0, 0 },

	{  "smb2_lock", NULL,
	    smb2_lock, NULL, 0, 0 },

	{  "smb2_ioctl", NULL,
	    smb2_ioctl, NULL, 0, 0 },

	{  "smb2_cancel", NULL,
	    smb2_cancel, NULL, 0, 0,
	    SDDF_SUPPRESS_UID | SDDF_SUPPRESS_TID },

	{  "smb2_echo", NULL,
	    smb2_echo, NULL, 0, 0,
	    SDDF_SUPPRESS_UID | SDDF_SUPPRESS_TID },

	{  "smb2_query_dir", NULL,
	    smb2_query_dir, NULL, 0, 0 },

	{  "smb2_change_notify", NULL,
	    smb2_change_notify, NULL, 0, 0 },

	{  "smb2_query_info", NULL,
	    smb2_query_info, NULL, 0, 0 },

	{  "smb2_set_info", NULL,
	    smb2_set_info, NULL, 0, 0 },

	{  "smb2_oplock_break_ack", NULL,
	    smb2_oplock_break_ack, NULL, 0, 0 },

	{  "smb2_invalid_cmd", NULL,
	    smb2_invalid_cmd, NULL, 0, 0,
	    SDDF_SUPPRESS_UID | SDDF_SUPPRESS_TID },
};

smb_sdrc_t
smb2_invalid_cmd(smb_request_t *sr)
{
#ifdef	DEBUG
	cmn_err(CE_NOTE, "clnt %s bad SMB2 cmd code",
	    sr->session->ip_addr_str);
#endif
	sr->smb2_status = NT_STATUS_INVALID_PARAMETER;
	return (SDRC_DROP_VC);
}

/*
 * This is the SMB2 handler for new smb requests, called from
 * smb_session_reader after SMB negotiate is done.  For most SMB2
 * requests, we just enqueue them for the smb_session_worker to
 * execute via the task queue, so they can block for resources
 * without stopping the reader thread.  A few protocol messages
 * are special cases and are handled directly here in the reader
 * thread so they don't wait for taskq scheduling.
 *
 * This function must either enqueue the new request for
 * execution via the task queue, or execute it directly
 * and then free it.  If this returns non-zero, the caller
 * will drop the session.
 */
int
smb2sr_newrq(smb_request_t *sr)
{
	struct mbuf_chain *mbc = &sr->command;
	taskqid_t tqid;
	uint32_t magic;
	int rc, skip;

	if (smb_mbc_peek(mbc, 0, "l", &magic) != 0)
		goto drop;

	/* 0xFD S M B */
	if (magic == SMB3_ENCRYPTED_MAGIC) {
		if (smb3_decrypt_msg(sr) != 0)
			goto drop;
		/*
		 * Should now be looking at an un-encrypted
		 * SMB2 message header.
		 */
		if (smb_mbc_peek(mbc, 0, "l", &magic) != 0)
			goto drop;
	}

	if (magic != SMB2_PROTOCOL_MAGIC)
		goto drop;

	/*
	 * Walk the SMB2 commands in this compound message and
	 * keep track of the range of message IDs it uses.
	 */
	for (;;) {
		if (smb2_decode_header(sr) != 0)
			goto drop;

		/*
		 * Cancel requests are special:  They refer to
		 * an earlier message ID (or an async. ID),
		 * never a new ID, and are never compounded.
		 * This is intentionally not "goto drop"
		 * because rc may be zero (success).
		 */
		if (sr->smb2_cmd_code == SMB2_CANCEL) {
			rc = smb2_newrq_cancel(sr);
			smb_request_free(sr);
			return (rc);
		}

		/*
		 * Keep track of the total credits in this compound
		 * and the first (real) message ID (not: 0, -1)
		 * While we're looking, verify that all (real) IDs
		 * are (first <= ID < (first + msg_credits))
		 */
		if (sr->smb2_credit_charge == 0)
			sr->smb2_credit_charge = 1;
		sr->smb2_total_credits += sr->smb2_credit_charge;

		if (sr->smb2_messageid != 0 &&
		    sr->smb2_messageid != UINT64_MAX) {

			if (sr->smb2_first_msgid == 0)
				sr->smb2_first_msgid = sr->smb2_messageid;

			if (sr->smb2_messageid < sr->smb2_first_msgid ||
			    sr->smb2_messageid >= (sr->smb2_first_msgid +
			    sr->smb2_total_credits)) {
				long long id = (long long) sr->smb2_messageid;
				cmn_err(CE_WARN, "clnt %s msg ID 0x%llx "
				    "out of sequence in compound",
				    sr->session->ip_addr_str, id);
			}
		}

		/* Normal loop exit on next == zero */
		if (sr->smb2_next_command == 0)
			break;

		/* Abundance of caution... */
		if (sr->smb2_next_command < SMB2_HDR_SIZE)
			goto drop;

		/* Advance to the next header. */
		skip = sr->smb2_next_command - SMB2_HDR_SIZE;
		if (MBC_ROOM_FOR(mbc, skip) == 0)
			goto drop;
		mbc->chain_offset += skip;
	}
	/* Rewind back to the top. */
	mbc->chain_offset = 0;

	/*
	 * Submit the request to the task queue, which calls
	 * smb2_tq_work when the workload permits.
	 */
	sr->sr_time_submitted = gethrtime();
	sr->sr_state = SMB_REQ_STATE_SUBMITTED;
	smb_srqueue_waitq_enter(sr->session->s_srqueue);
	tqid = taskq_dispatch(sr->sr_server->sv_worker_pool,
	    smb2_tq_work, sr, TQ_SLEEP);
	VERIFY(tqid != TASKQID_INVALID);

	return (0);

drop:
	smb_request_free(sr);
	return (-1);
}

static void
smb2_tq_work(void *arg)
{
	smb_request_t	*sr;
	smb_srqueue_t	*srq;

	sr = (smb_request_t *)arg;
	SMB_REQ_VALID(sr);

	srq = sr->session->s_srqueue;
	smb_srqueue_waitq_to_runq(srq);
	sr->sr_worker = curthread;
	sr->sr_time_active = gethrtime();

	/*
	 * Always dispatch to the work function, because cancelled
	 * requests need an error reply (NT_STATUS_CANCELLED).
	 */
	mutex_enter(&sr->sr_mutex);
	if (sr->sr_state == SMB_REQ_STATE_SUBMITTED)
		sr->sr_state = SMB_REQ_STATE_ACTIVE;
	mutex_exit(&sr->sr_mutex);

	smb2sr_work(sr);

	smb_srqueue_runq_exit(srq);
}

/*
 * Wrapper to setup a new mchain for the plaintext request that will
 * replace the encrypted one.  Returns non-zero to drop the connection.
 * Error return values here are just for visibility in dtrace.
 */
static int
smb3_decrypt_msg(smb_request_t *sr)
{
	struct mbuf_chain clear_mbc = {0};
	struct mbuf_chain tmp_mbc;
	mbuf_t *m;
	int clearsize;
	int rc;

	if (sr->session->dialect < SMB_VERS_3_0) {
		/* Encrypted message in SMB 2.x */
		return (-1);
	}
	if ((sr->session->srv_cap & SMB2_CAP_ENCRYPTION) == 0) {
		/* Should have srv_cap SMB2_CAP_ENCRYPTION flag set! */
		return (-2);
	}

	sr->encrypted = B_TRUE;
	if (sr->command.max_bytes <
	    (SMB3_TFORM_HDR_SIZE + SMB2_HDR_SIZE)) {
		/* Short transform header */
		return (-3);
	}
	clearsize = sr->command.max_bytes - SMB3_TFORM_HDR_SIZE;

	clear_mbc.max_bytes = clearsize;
	m = smb_mbuf_alloc_chain(clearsize);
	MBC_ATTACH_MBUF(&clear_mbc, m);

	rc = smb3_decrypt_sr(sr, &sr->command, &clear_mbc);
	if (rc != 0) {
		MBC_FLUSH(&clear_mbc);
		return (rc);
	}

	/* Swap clear_mbc in place of command */
	tmp_mbc = sr->command;
	sr->command = clear_mbc;
	MBC_FLUSH(&tmp_mbc);	// free old sr->command

	return (0);
}

/*
 * SMB2 credits determine how many simultaneous commands the
 * client may issue, and bounds the range of message IDs those
 * commands may use.  With multi-credit support, commands may
 * use ranges of message IDs, where the credits used by each
 * command are proportional to their data transfer size.
 *
 * Every command may request an increase or decrease of
 * the currently granted credits, based on the difference
 * between the credit request and the credit charge.
 * [MS-SMB2] 3.3.1.2 Algorithm for the Granting of Credits
 *
 * Most commands have credit_request=1, credit_charge=1,
 * which keeps the credit grant unchanged.
 *
 * All we're really doing here (for now) is reducing the
 * credit_response if the client requests a credit increase
 * that would take their credit over the maximum, and
 * limiting the decrease so they don't run out of credits.
 *
 * Later, this could do something dynamic based on load.
 *
 * One other non-obvious bit about credits: We keep the
 * session s_max_credits low until the 1st authentication,
 * at which point we'll set the normal maximum_credits.
 * Some clients ask for more credits with session setup,
 * and we need to handle that requested increase _after_
 * the command-specific handler returns so it won't be
 * restricted to the lower (pre-auth) limit.
 */
static inline void
smb2_credit_decrease(smb_request_t *sr)
{
	smb_session_t *session = sr->session;
	uint16_t cur, d;

	ASSERT3U(sr->smb2_credit_request, <, sr->smb2_credit_charge);

	mutex_enter(&session->s_credits_mutex);
	cur = session->s_cur_credits;
	ASSERT(cur > 0);

	/* Handle credit decrease. */
	d = sr->smb2_credit_charge - sr->smb2_credit_request;

	/*
	 * Prevent underflow of current credits, and
	 * enforce a minimum of one credit, per:
	 * [MS-SMB2] 3.3.1.2
	 */
	if (d >= cur) {
		/*
		 * Tried to give up more credits than we should.
		 * Reduce the decrement.
		 */
		d = cur - 1;
		cur = 1;
		DTRACE_PROBE1(smb2__credit__neg, smb_request_t *, sr);
	} else {
		cur -= d;
	}

	ASSERT3U(d, <=, sr->smb2_credit_charge);
	sr->smb2_credit_response = sr->smb2_credit_charge - d;

	DTRACE_PROBE3(smb2__credit__decrease,
	    smb_request_t *, sr, int, (int)cur,
	    int, (int)session->s_cur_credits);

	session->s_cur_credits = cur;
	mutex_exit(&session->s_credits_mutex);
}

/*
 * Second half of SMB2 credit handling (increases)
 */
static inline void
smb2_credit_increase(smb_request_t *sr)
{
	smb_session_t *session = sr->session;
	uint16_t cur, d;

	ASSERT3U(sr->smb2_credit_request, >, sr->smb2_credit_charge);

	mutex_enter(&session->s_credits_mutex);
	cur = session->s_cur_credits;

	/* Handle credit increase. */
	d = sr->smb2_credit_request - sr->smb2_credit_charge;

	/*
	 * If new credits would be above max,
	 * reduce the credit grant.
	 */
	if (d > (session->s_max_credits - cur)) {
		d = session->s_max_credits - cur;
		cur = session->s_max_credits;
		DTRACE_PROBE1(smb2__credit__max, smb_request_t *, sr);
	} else {
		cur += d;
	}
	sr->smb2_credit_response = sr->smb2_credit_charge + d;

	DTRACE_PROBE3(smb2__credit__increase,
	    smb_request_t *, sr, int, (int)cur,
	    int, (int)session->s_cur_credits);

	session->s_cur_credits = cur;
	mutex_exit(&session->s_credits_mutex);
}

/*
 * Record some statistics:  latency, rx bytes, tx bytes
 * per:  server, session & kshare.
 */
static inline void
smb2_record_stats(smb_request_t *sr, smb_disp_stats_t *sds, boolean_t tx_only)
{
	hrtime_t	dt;
	int64_t		rxb;
	int64_t		txb;

	dt = gethrtime() - sr->sr_time_start;
	rxb = (int64_t)(sr->command.chain_offset - sr->smb2_cmd_hdr);
	txb = (int64_t)(sr->reply.chain_offset - sr->smb2_reply_hdr);

	if (!tx_only) {
		smb_server_inc_req(sr->sr_server);
		smb_latency_add_sample(&sds->sdt_lat, dt);
		atomic_add_64(&sds->sdt_rxb, rxb);
	}
	atomic_add_64(&sds->sdt_txb, txb);
}

/*
 * smb2sr_work
 *
 * This function processes each SMB command in the current request
 * (which may be a compound request) building a reply containing
 * SMB reply messages, one-to-one with the SMB commands.  Some SMB
 * commands (change notify, blocking locks) may require both an
 * "interim response" and a later "async response" at completion.
 * In such cases, we'll encode the interim response in the reply
 * compound we're building, and put the (now async) command on a
 * list of commands that need further processing.  After we've
 * finished processing the commands in this compound and building
 * the compound reply, we'll send the compound reply, and finally
 * process the list of async commands.
 *
 * As we work our way through the compound request and reply,
 * we need to keep track of the bounds of the current request
 * and reply.  For the request, this uses an MBC_SHADOW_CHAIN
 * that begins at smb2_cmd_hdr.  The reply is appended to the
 * sr->reply chain starting at smb2_reply_hdr.
 *
 * This function must always free the smb request, or arrange
 * for it to be completed and free'd later (if SDRC_SR_KEPT).
 */
void
smb2sr_work(struct smb_request *sr)
{
	const smb_disp_entry_t	*sdd;
	smb_disp_stats_t	*sds;
	smb_session_t		*session;
	uint32_t		msg_len;
	uint16_t		cmd_idx;
	int			rc = 0;
	boolean_t		disconnect = B_FALSE;
	boolean_t		related;

	session = sr->session;

	ASSERT(sr->smb2_async == B_FALSE);
	ASSERT(sr->tid_tree == 0);
	ASSERT(sr->uid_user == 0);
	ASSERT(sr->fid_ofile == 0);
	sr->smb_fid = (uint16_t)-1;
	sr->smb2_status = 0;

	/* temporary until we identify a user */
	sr->user_cr = zone_kcred();

cmd_start:
	/*
	 * Note that we don't check sr_state here and abort the
	 * compound if cancelled (etc.) because some SMB2 command
	 * handlers need to do work even when cancelled.
	 *
	 * We treat some status codes as if "sticky", meaning
	 * once they're set after some command handler returns,
	 * all remaining commands get this status without even
	 * calling the command-specific handler.
	 */
	if (sr->smb2_status != NT_STATUS_CANCELLED &&
	    sr->smb2_status != NT_STATUS_INSUFFICIENT_RESOURCES)
		sr->smb2_status = 0;

	/*
	 * Decode the request header
	 *
	 * Most problems with decoding will result in the error
	 * STATUS_INVALID_PARAMETER.  If the decoding problem
	 * prevents continuing, we'll close the connection.
	 * [MS-SMB2] 3.3.5.2.6 Handling Incorrectly Formatted...
	 */
	sr->smb2_cmd_hdr = sr->command.chain_offset;
	if ((rc = smb2_decode_header(sr)) != 0) {
		cmn_err(CE_WARN, "clnt %s bad SMB2 header",
		    session->ip_addr_str);
		disconnect = B_TRUE;
		goto cleanup;
	}

	/*
	 * The SMB2_FLAGS_SERVER_TO_REDIR should only appear
	 * in messages from the server back to the client.
	 */
	if ((sr->smb2_hdr_flags & SMB2_FLAGS_SERVER_TO_REDIR) != 0) {
		cmn_err(CE_WARN, "clnt %s bad SMB2 flags",
		    session->ip_addr_str);
		disconnect = B_TRUE;
		goto cleanup;
	}
	related = (sr->smb2_hdr_flags & SMB2_FLAGS_RELATED_OPERATIONS);
	sr->smb2_hdr_flags |= SMB2_FLAGS_SERVER_TO_REDIR;
	if (sr->smb2_hdr_flags & SMB2_FLAGS_ASYNC_COMMAND) {
		/* Probably an async cancel. */
		DTRACE_PROBE1(smb2__dispatch__async, smb_request_t *, sr);
	} else if (sr->smb2_async) {
		/* Previous command in compound went async. */
		sr->smb2_hdr_flags |= SMB2_FLAGS_ASYNC_COMMAND;
		sr->smb2_async_id = SMB2_ASYNCID(sr);
	}

	/*
	 * In case we bail out with an error before we get to the
	 * section that computes the credit grant, initialize the
	 * response header fields so that credits won't change.
	 * Note: SMB 2.02 clients may send credit charge zero.
	 */
	if (sr->smb2_credit_charge == 0)
		sr->smb2_credit_charge = 1;
	sr->smb2_credit_response = sr->smb2_credit_charge;

	/*
	 * Write a tentative reply header.
	 *
	 * We could just leave this blank, but if we're using the
	 * mdb module feature that extracts packets, it's useful
	 * to have the header mostly correct here.
	 *
	 * If we have already exhausted the output space, then the
	 * client is trying something funny.  Log it and kill 'em.
	 */
	sr->smb2_next_reply = 0;
	ASSERT((sr->reply.chain_offset & 7) == 0);
	sr->smb2_reply_hdr = sr->reply.chain_offset;
	if ((rc = smb2_encode_header(sr, B_FALSE)) != 0) {
		cmn_err(CE_WARN, "clnt %s excessive reply",
		    session->ip_addr_str);
		disconnect = B_TRUE;
		goto cleanup;
	}

	/*
	 * Figure out the length of data following the SMB2 header.
	 * It ends at either the next SMB2 header if there is one
	 * (smb2_next_command != 0) or at the end of the message.
	 */
	if (sr->smb2_next_command != 0) {
		/* [MS-SMB2] says this is 8-byte aligned */
		msg_len = sr->smb2_next_command;
		if ((msg_len & 7) != 0 || (msg_len < SMB2_HDR_SIZE) ||
		    ((sr->smb2_cmd_hdr + msg_len) > sr->command.max_bytes)) {
			cmn_err(CE_WARN, "clnt %s bad SMB2 next cmd",
			    session->ip_addr_str);
			disconnect = B_TRUE;
			goto cleanup;
		}
	} else {
		msg_len = sr->command.max_bytes - sr->smb2_cmd_hdr;
	}

	/*
	 * Setup a shadow chain for this SMB2 command, starting
	 * with the header and ending at either the next command
	 * or the end of the message.  The signing check below
	 * needs the entire SMB2 command.  After that's done, we
	 * advance chain_offset to the end of the header where
	 * the command specific handlers continue decoding.
	 */
	(void) MBC_SHADOW_CHAIN(&sr->smb_data, &sr->command,
	    sr->smb2_cmd_hdr, msg_len);

	/*
	 * We will consume the data for this request from smb_data.
	 * That effectively consumes msg_len bytes from sr->command
	 * but doesn't update its chain_offset, so we need to update
	 * that here to make later received bytes accounting work.
	 */
	sr->command.chain_offset = sr->smb2_cmd_hdr + msg_len;
	ASSERT(sr->command.chain_offset <= sr->command.max_bytes);

	/*
	 * Validate the commmand code, get dispatch table entries.
	 * [MS-SMB2] 3.3.5.2.6 Handling Incorrectly Formatted...
	 *
	 * The last slot in the dispatch table is used to handle
	 * invalid commands.  Same for statistics.
	 */
	if (sr->smb2_cmd_code < SMB2_INVALID_CMD)
		cmd_idx = sr->smb2_cmd_code;
	else
		cmd_idx = SMB2_INVALID_CMD;
	sdd = &smb2_disp_table[cmd_idx];
	sds = &session->s_server->sv_disp_stats2[cmd_idx];

	/*
	 * If this command is NOT "related" to the previous,
	 * clear out the UID, TID, FID state that might be
	 * left over from the previous command.
	 *
	 * If the command IS related, any new IDs are ignored,
	 * and we simply continue with the previous user, tree,
	 * and open file.
	 */
	if (!related) {
		/*
		 * Drop user, tree, file; carefully ordered to
		 * avoid dangling references: file, tree, user
		 */
		if (sr->fid_ofile != NULL) {
			smb_ofile_release(sr->fid_ofile);
			sr->fid_ofile = NULL;
		}
		if (sr->tid_tree != NULL) {
			smb_tree_release(sr->tid_tree);
			sr->tid_tree = NULL;
		}
		if (sr->uid_user != NULL) {
			smb_user_release(sr->uid_user);
			sr->uid_user = NULL;
			sr->user_cr = zone_kcred();
		}
	}

	/*
	 * Make sure we have a user and tree as needed
	 * according to the flags for the this command.
	 * Note that we may have inherited these.
	 */
	if ((sdd->sdt_flags & SDDF_SUPPRESS_UID) == 0) {
		/*
		 * This command requires a user session.
		 */
		if (related) {
			/*
			 * Previous command should have given us a user.
			 * [MS-SMB2] 3.3.5.2 Handling Related Requests
			 */
			if (sr->uid_user == NULL) {
				smb2sr_put_error(sr,
				    NT_STATUS_INVALID_PARAMETER);
				goto cmd_done;
			}
			sr->smb2_ssnid = sr->uid_user->u_ssnid;
		} else {
			/*
			 * Lookup the UID
			 * [MS-SMB2] 3.3.5.2 Verifying the Session
			 */
			ASSERT(sr->uid_user == NULL);
			/*
			 * [MS-SMB2] 3.3.5.2.7 Handling Compounded Requests
			 *
			 * If this is an encrypted compound request,
			 * ensure that the ssnid in the request
			 * is the same as the tform ssnid if this
			 * message is not related.
			 *
			 * The reasons this is done seem to apply equally
			 * to uncompounded requests, so we apply it to all.
			 */

			if (sr->encrypted &&
			    sr->smb2_ssnid != sr->th_ssnid) {
				disconnect = B_TRUE;
				goto cleanup; /* just do this for now */
			}

			sr->uid_user = smb_session_lookup_ssnid(session,
			    sr->smb2_ssnid);
			if (sr->uid_user == NULL) {
				smb2sr_put_error(sr,
				    NT_STATUS_USER_SESSION_DELETED);
				goto cmd_done;
			}

			/*
			 * [MS-SMB2] 3.3.5.2.9 Verifying the Session
			 *
			 * If we're talking 3.x,
			 * RejectUnencryptedAccess is TRUE,
			 * Session.EncryptData is TRUE,
			 * and the message wasn't encrypted,
			 * return ACCESS_DENIED.
			 *
			 * Note that Session.EncryptData can only be TRUE when
			 * we're talking 3.x.
			 */
			if (sr->uid_user->u_encrypt == SMB_CONFIG_REQUIRED &&
			    !sr->encrypted) {
				smb2sr_put_error(sr,
				    NT_STATUS_ACCESS_DENIED);
				goto cmd_done;
			}

			sr->user_cr = smb_user_getcred(sr->uid_user);
		}
		ASSERT(sr->uid_user != NULL);

		/*
		 * Encrypt if:
		 * - The cmd is not SESSION_SETUP or NEGOTIATE; AND
		 * - Session.EncryptData is TRUE
		 *
		 * Those commands suppress UID, so they can't be the cmd here.
		 */
		if (sr->uid_user->u_encrypt != SMB_CONFIG_DISABLED &&
		    sr->th_sid_user == NULL) {
			smb_user_hold_internal(sr->uid_user);
			sr->th_sid_user = sr->uid_user;
			sr->th_ssnid = sr->smb2_ssnid;
		}
	}

	if ((sdd->sdt_flags & SDDF_SUPPRESS_TID) == 0) {
		/*
		 * This command requires a tree connection.
		 */
		if (related) {
			/*
			 * Previous command should have given us a tree.
			 * [MS-SMB2] 3.3.5.2 Handling Related Requests
			 */
			if (sr->tid_tree == NULL) {
				smb2sr_put_error(sr,
				    NT_STATUS_INVALID_PARAMETER);
				goto cmd_done;
			}
			sr->smb_tid = sr->tid_tree->t_tid;
		} else {
			/*
			 * Lookup the TID
			 * [MS-SMB2] 3.3.5.2 Verifying the Tree Connect
			 */
			ASSERT(sr->tid_tree == NULL);
			sr->tid_tree = smb_session_lookup_tree(session,
			    sr->smb_tid);
			if (sr->tid_tree == NULL) {
				smb2sr_put_error(sr,
				    NT_STATUS_NETWORK_NAME_DELETED);
				goto cmd_done;
			}

			/*
			 * [MS-SMB2] 3.3.5.2.11 Verifying the Tree Connect
			 *
			 * If we support 3.x, RejectUnencryptedAccess is TRUE,
			 * if Tcon.EncryptData is TRUE or
			 * global EncryptData is TRUE and
			 * the message wasn't encrypted, or
			 * if Tcon.EncryptData is TRUE or
			 * global EncryptData is TRUE or
			 * the request was encrypted and
			 * the connection doesn't support encryption,
			 * return ACCESS_DENIED.
			 *
			 * If RejectUnencryptedAccess is TRUE, we force
			 * max_protocol to at least 3.0. Additionally,
			 * if the tree requires encryption, we don't care
			 * what we support, we still enforce encryption.
			 * Since smb3_decrypt_msg() does check session->srv_cap,
			 * we only need to check sr->encrypted here.
			 */
			if (sr->tid_tree->t_encrypt == SMB_CONFIG_REQUIRED &&
			    !sr->encrypted) {
				smb2sr_put_error(sr,
				    NT_STATUS_ACCESS_DENIED);
				goto cmd_done;
			}
		}
		ASSERT(sr->tid_tree != NULL);

		/*
		 * Encrypt if:
		 * - The cmd is not TREE_CONNECT; AND
		 * - Tree.EncryptData is TRUE
		 *
		 * TREE_CONNECT suppresses TID, so that can't be the cmd here.
		 * NOTE: assumes we can't have a tree without a user
		 */
		if (sr->tid_tree->t_encrypt != SMB_CONFIG_DISABLED &&
		    sr->th_sid_user == NULL) {
			smb_user_hold_internal(sr->uid_user);
			sr->th_sid_user = sr->uid_user;
			sr->th_ssnid = sr->smb2_ssnid;
		}
	}

	/*
	 * SMB2 signature verification, two parts:
	 * (a) Require SMB2_FLAGS_SIGNED (for most request types)
	 * (b) If SMB2_FLAGS_SIGNED is set, check the signature.
	 * [MS-SMB2] 3.3.5.2.4 Verifying the Signature
	 */

	/*
	 * No user session means no signature check.  That's OK,
	 * i.e. for commands marked SDDF_SUPPRESS_UID above.
	 * Note, this also means we won't sign the reply.
	 */
	if (sr->uid_user == NULL)
		sr->smb2_hdr_flags &= ~SMB2_FLAGS_SIGNED;

	/*
	 * The SDDF_SUPPRESS_UID dispatch is set for requests that
	 * don't need a UID (user).  These also don't require a
	 * signature check here.
	 *
	 * [MS-SMB2] 3.3.5.2.4 Verifying the Signature
	 *
	 * If the packet was successfully decrypted, the message
	 * signature has already been verified, so we can skip this.
	 */
	if ((sdd->sdt_flags & SDDF_SUPPRESS_UID) == 0 &&
	    !sr->encrypted && sr->uid_user != NULL &&
	    (sr->uid_user->u_sign_flags & SMB_SIGNING_ENABLED) != 0) {
		/*
		 * If the request is signed, check the signature.
		 * Otherwise, if signing is required, deny access.
		 */
		if ((sr->smb2_hdr_flags & SMB2_FLAGS_SIGNED) != 0) {
			if (smb2_sign_check_request(sr) != 0) {
				smb2sr_put_error(sr, NT_STATUS_ACCESS_DENIED);
				DTRACE_PROBE1(smb2__sign__check,
				    smb_request_t *, sr);
				goto cmd_done;
			}
		} else if (
		    (sr->uid_user->u_sign_flags & SMB_SIGNING_CHECK) != 0) {
			smb2sr_put_error(sr, NT_STATUS_ACCESS_DENIED);
			goto cmd_done;
		}
	}

	/*
	 * Now that the signing check is done with smb_data,
	 * advance past the SMB2 header we decoded earlier.
	 * This leaves sr->smb_data correctly positioned
	 * for command-specific decoding in the dispatch
	 * function called next.
	 */
	sr->smb_data.chain_offset = sr->smb2_cmd_hdr + SMB2_HDR_SIZE;

	/*
	 * Credit adjustments (decrease)
	 *
	 * If we've gone async, credit adjustments were done
	 * when we sent the interim reply.
	 */
	if (!sr->smb2_async) {
		if (sr->smb2_credit_request < sr->smb2_credit_charge) {
			smb2_credit_decrease(sr);
		}
	}

	/*
	 * The real work: call the SMB2 command handler
	 * (except for "sticky" smb2_status - see above)
	 */
	sr->sr_time_start = gethrtime();
	rc = SDRC_SUCCESS;
	if (sr->smb2_status == 0) {
		/* NB: not using pre_op */
		rc = (*sdd->sdt_function)(sr);
		/* NB: not using post_op */
	} else {
		smb2sr_put_error(sr, sr->smb2_status);
	}

	/*
	 * When the sdt_function returns SDRC_SR_KEPT, it means
	 * this SR may have been passed to another thread so we
	 * MUST NOT touch it anymore.
	 */
	if (rc == SDRC_SR_KEPT)
		return;

	MBC_FLUSH(&sr->raw_data);

	/*
	 * Credit adjustments (increase)
	 */
	if (!sr->smb2_async) {
		if (sr->smb2_credit_request > sr->smb2_credit_charge) {
			smb2_credit_increase(sr);
		}
	}

cmd_done:
	switch (rc) {
	case SDRC_SUCCESS:
		break;
	default:
		/*
		 * SMB2 does not use the other dispatch return codes.
		 * If we see something else, log an event so we'll
		 * know something is returning bogus status codes.
		 * If you see these in the log, use dtrace to find
		 * the code returning something else.
		 */
#ifdef	DEBUG
		cmn_err(CE_NOTE, "handler for %u returned 0x%x",
		    sr->smb2_cmd_code, rc);
#endif
		smb2sr_put_error(sr, NT_STATUS_INTERNAL_ERROR);
		break;
	case SDRC_ERROR:
		/*
		 * Many command handlers return SDRC_ERROR for any
		 * problems decoding the request, and don't bother
		 * setting smb2_status.  For those cases, the best
		 * status return would be "invalid parameter".
		 */
		if (sr->smb2_status == 0)
			sr->smb2_status = NT_STATUS_INVALID_PARAMETER;
		smb2sr_put_error(sr, sr->smb2_status);
		break;
	case SDRC_DROP_VC:
		disconnect = B_TRUE;
		goto cleanup;

	case SDRC_NO_REPLY:
		/* will free sr */
		goto cleanup;
	}

	/*
	 * Pad the reply to align(8) if there will be another.
	 * (We don't compound async replies.)
	 */
	if (!sr->smb2_async && sr->smb2_next_command != 0)
		(void) smb_mbc_put_align(&sr->reply, 8);

	/*
	 * Record some statistics.  Uses:
	 *   rxb = command.chain_offset - smb2_cmd_hdr;
	 *   txb = reply.chain_offset - smb2_reply_hdr;
	 * which at this point represent the current cmd/reply.
	 *
	 * Note: If async, this does txb only, and
	 * skips the smb_latency_add_sample() calls.
	 */
	smb2_record_stats(sr, sds, sr->smb2_async);

	/*
	 * If there's a next command, figure out where it starts,
	 * and fill in the next header offset for the reply.
	 * Note: We sanity checked smb2_next_command above.
	 */
	if (sr->smb2_next_command != 0) {
		sr->command.chain_offset =
		    sr->smb2_cmd_hdr + sr->smb2_next_command;
		sr->smb2_next_reply =
		    sr->reply.chain_offset - sr->smb2_reply_hdr;
	} else {
		ASSERT(sr->smb2_next_reply == 0);
	}

	/*
	 * Overwrite the (now final) SMB2 header for this response.
	 */
	(void) smb2_encode_header(sr, B_TRUE);

	/*
	 * Cannot move this into smb2_session_setup() - encoded header required.
	 */
	if (session->dialect >= SMB_VERS_3_11 &&
	    sr->smb2_cmd_code == SMB2_SESSION_SETUP &&
	    sr->smb2_status == NT_STATUS_MORE_PROCESSING_REQUIRED) {
		if (smb31_preauth_sha512_calc(sr, &sr->reply,
		    sr->uid_user->u_preauth_hashval,
		    sr->uid_user->u_preauth_hashval) != 0)
			cmn_err(CE_WARN, "(3) Preauth hash calculation "
			    "failed");
	}

	/* Don't sign if we're going to encrypt */
	if (sr->th_sid_user == NULL &&
	    (sr->smb2_hdr_flags & SMB2_FLAGS_SIGNED) != 0)
		smb2_sign_reply(sr);

	/*
	 * Non-async runs the whole compound before send.
	 * When we've gone async, send each individually.
	 */
	if (!sr->smb2_async && sr->smb2_next_command != 0)
		goto cmd_start;

	/*
	 * If we have a durable handle, and this operation updated
	 * the nvlist, write it out (before smb2_send_reply).
	 */
	if (sr->dh_nvl_dirty) {
		sr->dh_nvl_dirty = B_FALSE;
		smb2_dh_update_nvfile(sr);
	}

	smb2_send_reply(sr);
	if (sr->smb2_async && sr->smb2_next_command != 0) {
		MBC_FLUSH(&sr->reply);	/* New reply buffer. */
		ASSERT(sr->reply.max_bytes == sr->session->reply_max_bytes);
		goto cmd_start;
	}

cleanup:
	if (disconnect)
		smb_session_disconnect(session);

	/*
	 * Do "postwork" for oplock (and maybe other things)
	 */
	if (sr->sr_postwork != NULL)
		smb2sr_run_postwork(sr);

	mutex_enter(&sr->sr_mutex);
	sr->sr_state = SMB_REQ_STATE_COMPLETED;
	mutex_exit(&sr->sr_mutex);

	smb_request_free(sr);
}

/*
 * Build interim responses for the current and all following
 * requests in this compound, then send the compound response,
 * leaving the SR state so that smb2sr_work() can continue its
 * processing of this compound in "async mode".
 *
 * If we agree to "go async", this should return STATUS_SUCCESS.
 * Otherwise return STATUS_INSUFFICIENT_RESOURCES for this and
 * all requests following this request.  (See the comments re.
 * "sticky" smb2_status values in smb2sr_work).
 *
 * Note: the Async ID we assign here is arbitrary, and need only
 * be unique among pending async responses on this connection, so
 * this just uses a modified messageID, which is already unique.
 *
 * Credits:  All credit changes should happen via the interim
 * responses, so we have to manage credits here.  After this
 * returns to smb2sr_work, the final replies for all these
 * commands will have smb2_credit_response = smb2_credit_charge
 * (meaning no further changes to the clients' credits).
 */
uint32_t
smb2sr_go_async(smb_request_t *sr)
{
	smb_session_t *session;
	smb_disp_stats_t *sds;
	uint16_t cmd_idx;
	int32_t saved_com_offset;
	uint32_t saved_cmd_hdr;
	uint16_t saved_cred_resp;
	uint32_t saved_hdr_flags;
	uint32_t saved_reply_hdr;
	uint32_t msg_len;
	boolean_t disconnect = B_FALSE;

	if (sr->smb2_async) {
		/* already went async in some previous cmd. */
		return (NT_STATUS_SUCCESS);
	}
	sr->smb2_async = B_TRUE;

	/* The "server" session always runs async. */
	session = sr->session;
	if (session->sock == NULL)
		return (NT_STATUS_SUCCESS);

	sds = NULL;
	saved_com_offset = sr->command.chain_offset;
	saved_cmd_hdr = sr->smb2_cmd_hdr;
	saved_cred_resp = sr->smb2_credit_response;
	saved_hdr_flags = sr->smb2_hdr_flags;
	saved_reply_hdr = sr->smb2_reply_hdr;

	/*
	 * The command-specific handler should not yet have put any
	 * data in the reply except for the (place holder) header.
	 */
	if (sr->reply.chain_offset != sr->smb2_reply_hdr + SMB2_HDR_SIZE) {
		ASSERT3U(sr->reply.chain_offset, ==,
		    sr->smb2_reply_hdr + SMB2_HDR_SIZE);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	/*
	 * Rewind to the start of the current header in both the
	 * command and reply bufers, so the loop below can just
	 * decode/encode just in every pass.  This means the
	 * current command header is decoded again, but that
	 * avoids having to special-case the first loop pass.
	 */
	sr->command.chain_offset = sr->smb2_cmd_hdr;
	sr->reply.chain_offset = sr->smb2_reply_hdr;

	/*
	 * This command processing loop is a simplified version of
	 * smb2sr_work() that just puts an "interim response" for
	 * every command in the compound (NT_STATUS_PENDING).
	 */
cmd_start:
	sr->smb2_status = NT_STATUS_PENDING;

	/*
	 * Decode the request header
	 */
	sr->smb2_cmd_hdr = sr->command.chain_offset;
	if ((smb2_decode_header(sr)) != 0) {
		cmn_err(CE_WARN, "clnt %s bad SMB2 header",
		    session->ip_addr_str);
		disconnect = B_TRUE;
		goto cleanup;
	}
	sr->smb2_hdr_flags |= (SMB2_FLAGS_SERVER_TO_REDIR |
	    SMB2_FLAGS_ASYNC_COMMAND);
	sr->smb2_async_id = SMB2_ASYNCID(sr);

	/*
	 * In case we bail out...
	 */
	if (sr->smb2_credit_charge == 0)
		sr->smb2_credit_charge = 1;
	sr->smb2_credit_response = sr->smb2_credit_charge;

	/*
	 * Write a tentative reply header.
	 */
	sr->smb2_next_reply = 0;
	ASSERT((sr->reply.chain_offset & 7) == 0);
	sr->smb2_reply_hdr = sr->reply.chain_offset;
	if ((smb2_encode_header(sr, B_FALSE)) != 0) {
		cmn_err(CE_WARN, "clnt %s excessive reply",
		    session->ip_addr_str);
		disconnect = B_TRUE;
		goto cleanup;
	}

	/*
	 * Figure out the length of data...
	 */
	if (sr->smb2_next_command != 0) {
		/* [MS-SMB2] says this is 8-byte aligned */
		msg_len = sr->smb2_next_command;
		if ((msg_len & 7) != 0 || (msg_len < SMB2_HDR_SIZE) ||
		    ((sr->smb2_cmd_hdr + msg_len) > sr->command.max_bytes)) {
			cmn_err(CE_WARN, "clnt %s bad SMB2 next cmd",
			    session->ip_addr_str);
			disconnect = B_TRUE;
			goto cleanup;
		}
	} else {
		msg_len = sr->command.max_bytes - sr->smb2_cmd_hdr;
	}

	/*
	 * We just skip any data, so no shadow chain etc.
	 */
	sr->command.chain_offset = sr->smb2_cmd_hdr + msg_len;
	ASSERT(sr->command.chain_offset <= sr->command.max_bytes);

	/*
	 * Validate the commmand code...
	 */
	if (sr->smb2_cmd_code < SMB2_INVALID_CMD)
		cmd_idx = sr->smb2_cmd_code;
	else
		cmd_idx = SMB2_INVALID_CMD;
	sds = &session->s_server->sv_disp_stats2[cmd_idx];

	/*
	 * Don't change (user, tree, file) because we want them
	 * exactly as they were when we entered.  That also means
	 * we may not have the right user in sr->uid_user for
	 * signature checks, so leave that until smb2sr_work
	 * runs these commands "for real".  Therefore, here
	 * we behave as if: (sr->uid_user == NULL)
	 */
	sr->smb2_hdr_flags &= ~SMB2_FLAGS_SIGNED;

	/*
	 * Credit adjustments (decrease)
	 *
	 * NOTE: interim responses are not signed.
	 * Any attacker can modify the credit grant
	 * in the response. Because of this property,
	 * it is no worse to assume the credit charge and grant
	 * are sane without verifying the signature,
	 * and that saves us a whole lot of work.
	 * If the credits WERE modified, we'll find out
	 * when we verify the signature later,
	 * which nullifies any changes caused here.
	 *
	 * Skip this on the first command, because the
	 * credit decrease was done by the caller.
	 */
	if (sr->smb2_cmd_hdr != saved_cmd_hdr) {
		if (sr->smb2_credit_request < sr->smb2_credit_charge) {
			smb2_credit_decrease(sr);
		}
	}

	/*
	 * The real work: ... (would be here)
	 */
	smb2sr_put_error(sr, sr->smb2_status);

	/*
	 * Credit adjustments (increase)
	 */
	if (sr->smb2_credit_request > sr->smb2_credit_charge) {
		smb2_credit_increase(sr);
	}

	/* cmd_done: label */

	/*
	 * Pad the reply to align(8) if there will be another.
	 * This (interim) reply uses compounding.
	 */
	if (sr->smb2_next_command != 0)
		(void) smb_mbc_put_align(&sr->reply, 8);

	/*
	 * Record some statistics.  Uses:
	 *   rxb = command.chain_offset - smb2_cmd_hdr;
	 *   txb = reply.chain_offset - smb2_reply_hdr;
	 * which at this point represent the current cmd/reply.
	 *
	 * Note: We're doing smb_latency_add_sample() for all
	 * remaining commands NOW, which means we won't include
	 * the async part of their work in latency statistics.
	 * That's intentional, as the async part of a command
	 * would otherwise skew our latency statistics.
	 */
	smb2_record_stats(sr, sds, B_FALSE);

	/*
	 * If there's a next command, figure out where it starts,
	 * and fill in the next header offset for the reply.
	 * Note: We sanity checked smb2_next_command above.
	 */
	if (sr->smb2_next_command != 0) {
		sr->command.chain_offset =
		    sr->smb2_cmd_hdr + sr->smb2_next_command;
		sr->smb2_next_reply =
		    sr->reply.chain_offset - sr->smb2_reply_hdr;
	} else {
		ASSERT(sr->smb2_next_reply == 0);
	}

	/*
	 * Overwrite the (now final) SMB2 header for this response.
	 */
	(void) smb2_encode_header(sr, B_TRUE);

	/*
	 * Process whole compound before sending.
	 */
	if (sr->smb2_next_command != 0)
		goto cmd_start;
	smb2_send_reply(sr);

	ASSERT(!disconnect);

cleanup:
	/*
	 * Restore caller's command processing state.
	 */
	sr->smb2_cmd_hdr = saved_cmd_hdr;
	sr->command.chain_offset = saved_cmd_hdr;
	(void) smb2_decode_header(sr);
	sr->command.chain_offset = saved_com_offset;

	sr->smb2_credit_response = saved_cred_resp;
	sr->smb2_hdr_flags = saved_hdr_flags;
	sr->smb2_status = NT_STATUS_SUCCESS;

	/*
	 * In here, the "disconnect" flag just means we had an
	 * error decoding or encoding something.  Rather than
	 * actually disconnect here, let's assume whatever
	 * problem we encountered will be seen by the caller
	 * as they continue processing the compound, and just
	 * restore everything and return an error.
	 */
	if (disconnect) {
		sr->smb2_async = B_FALSE;
		sr->smb2_reply_hdr = saved_reply_hdr;
		sr->reply.chain_offset = sr->smb2_reply_hdr;
		(void) smb2_encode_header(sr, B_FALSE);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	/*
	 * The compound reply buffer we sent is now gone.
	 * Setup a new reply buffer for the caller.
	 */
	sr->smb2_hdr_flags |= SMB2_FLAGS_ASYNC_COMMAND;
	sr->smb2_async_id = SMB2_ASYNCID(sr);
	sr->smb2_next_reply = 0;
	MBC_FLUSH(&sr->reply);
	ASSERT(sr->reply.max_bytes == sr->session->reply_max_bytes);
	ASSERT(sr->reply.chain_offset == 0);
	sr->smb2_reply_hdr = 0;
	(void) smb2_encode_header(sr, B_FALSE);

	return (NT_STATUS_SUCCESS);
}

int
smb2_decode_header(smb_request_t *sr)
{
	uint32_t pid, tid;
	uint16_t hdr_len;
	int rc;

	rc = smb_mbc_decodef(
	    &sr->command, "Nwww..wwllqllq16c",
	    &hdr_len,			/* w */
	    &sr->smb2_credit_charge,	/* w */
	    &sr->smb2_chan_seq,		/* w */
	    /* reserved			  .. */
	    &sr->smb2_cmd_code,		/* w */
	    &sr->smb2_credit_request,	/* w */
	    &sr->smb2_hdr_flags,	/* l */
	    &sr->smb2_next_command,	/* l */
	    &sr->smb2_messageid,	/* q */
	    &pid,			/* l */
	    &tid,			/* l */
	    &sr->smb2_ssnid,		/* q */
	    sr->smb2_sig);		/* 16c */
	if (rc)
		return (rc);

	if (hdr_len != SMB2_HDR_SIZE)
		return (-1);

	if (sr->smb2_hdr_flags & SMB2_FLAGS_ASYNC_COMMAND) {
		sr->smb2_async_id = pid |
		    ((uint64_t)tid) << 32;
		sr->smb_pid = 0;
		sr->smb_tid = 0;
	} else {
		sr->smb2_async_id = 0;
		sr->smb_pid = pid;
		sr->smb_tid = (uint16_t)tid; /* XXX wide TIDs */
	}

	return (rc);
}

int
smb2_encode_header(smb_request_t *sr, boolean_t overwrite)
{
	uint64_t pid_tid_aid; /* pid+tid, or async id */
	int rc;

	if (sr->smb2_hdr_flags & SMB2_FLAGS_ASYNC_COMMAND) {
		pid_tid_aid = sr->smb2_async_id;
	} else {
		pid_tid_aid = sr->smb_pid |
		    ((uint64_t)sr->smb_tid) << 32;
	}

	if (overwrite) {
		rc = smb_mbc_poke(&sr->reply,
		    sr->smb2_reply_hdr,
		    "Nwwlwwllqqq16c",
		    SMB2_HDR_SIZE,		/* w */
		    sr->smb2_credit_charge,	/* w */
		    sr->smb2_status,		/* l */
		    sr->smb2_cmd_code,		/* w */
		    sr->smb2_credit_response,	/* w */
		    sr->smb2_hdr_flags,		/* l */
		    sr->smb2_next_reply,	/* l */
		    sr->smb2_messageid,		/* q */
		    pid_tid_aid,		/* q */
		    sr->smb2_ssnid,		/* q */
		    sr->smb2_sig);		/* 16c */
	} else {
		rc = smb_mbc_encodef(&sr->reply,
		    "Nwwlwwllqqq16c",
		    SMB2_HDR_SIZE,		/* w */
		    sr->smb2_credit_charge,	/* w */
		    sr->smb2_status,		/* l */
		    sr->smb2_cmd_code,		/* w */
		    sr->smb2_credit_response,	/* w */
		    sr->smb2_hdr_flags,		/* l */
		    sr->smb2_next_reply,	/* l */
		    sr->smb2_messageid,		/* q */
		    pid_tid_aid,		/* q */
		    sr->smb2_ssnid,		/* q */
		    sr->smb2_sig);		/* 16c */
	}

	return (rc);
}

void
smb2_send_reply(smb_request_t *sr)
{
	struct mbuf_chain enc_reply;
	smb_session_t *session = sr->session;
	mbuf_t *m;

	/*
	 * [MS-SMB2] 3.3.4.1.4 Encrypting the Message
	 *
	 * When the connection supports encryption and the dialect
	 * is 3.x, encrypt if:
	 * - The request was encrypted OR
	 * - The cmd is not SESSION_SETUP or NEGOTIATE AND
	 * -- Session.EncryptData is TRUE OR
	 * -- The cmd is not TREE_CONNECT AND
	 * --- Tree.EncryptData is TRUE
	 *
	 * This boils down to sr->th_sid_user != NULL, and the rest
	 * is enforced when th_sid_user is set.
	 */

	if ((session->capabilities & SMB2_CAP_ENCRYPTION) == 0 ||
	    sr->th_sid_user == NULL) {
		(void) smb_session_send(sr->session, 0, &sr->reply);
		return;
	}

	/*
	 * Encrypted send
	 *
	 * Not doing in-place encryption because we may have
	 * loaned buffers (eg. from ZFS) that are read-only.
	 *
	 * Setup the transform header in its own mblk,
	 * with leading space for the netbios header.
	 */
	MBC_INIT(&enc_reply, SMB3_TFORM_HDR_SIZE);
	m = enc_reply.chain;
	m->m_len = SMB3_TFORM_HDR_SIZE;

	sr->th_msglen = sr->reply.chain_offset;
	m->m_next = smb_mbuf_alloc_chain(sr->th_msglen);
	enc_reply.max_bytes += sr->th_msglen;

	if (smb3_encrypt_sr(sr, &sr->reply, &enc_reply) != 0) {
		cmn_err(CE_WARN, "smb3 encryption failed");
		smb_session_disconnect(sr->session);
	} else {
		(void) smb_session_send(sr->session, 0, &enc_reply);
	}
	MBC_FLUSH(&enc_reply);
}

/*
 * This wrapper function exists to help catch calls to smbsr_status()
 * (which is SMB1-specific) in common code.  See smbsr_status().
 * If the log message below is seen, put a dtrace probe on this
 * function with a stack() action to see who is calling the SMB1
 * "put error" from common code, and fix it.
 */
void
smbsr_status_smb2(smb_request_t *sr, DWORD status)
{
	const char *name;

	if (sr->smb2_cmd_code < SMB2__NCMDS)
		name = smb2_disp_table[sr->smb2_cmd_code].sdt_name;
	else
		name = "<unknown>";
#ifdef	DEBUG
	cmn_err(CE_NOTE, "smbsr_status called for %s", name);
#endif

	smb2sr_put_error_data(sr, status, NULL);
}

void
smb2sr_put_errno(struct smb_request *sr, int errnum)
{
	uint32_t status = smb_errno2status(errnum);
	smb2sr_put_error_data(sr, status, NULL);
}

void
smb2sr_put_error(smb_request_t *sr, uint32_t status)
{
	smb2sr_put_error_data(sr, status, NULL);
}

/*
 * Build an SMB2 error response.  [MS-SMB2] 2.2.2
 */
void
smb2sr_put_error_data(smb_request_t *sr, uint32_t status, mbuf_chain_t *mbc)
{
	DWORD len;

	/*
	 * The common dispatch code writes this when it
	 * updates the SMB2 header before sending.
	 */
	sr->smb2_status = status;

	/* Rewind to the end of the SMB header. */
	sr->reply.chain_offset = sr->smb2_reply_hdr + SMB2_HDR_SIZE;

	/*
	 * NB: Must provide at least one byte of error data,
	 * per [MS-SMB2] 2.2.2
	 */
	if (mbc != NULL && (len = MBC_LENGTH(mbc)) != 0) {
		(void) smb_mbc_encodef(
		    &sr->reply,
		    "wwlC",
		    9,	/* StructSize */	/* w */
		    0,	/* reserved */		/* w */
		    len,			/* l */
		    mbc);			/* C */
	} else {
		(void) smb_mbc_encodef(
		    &sr->reply,
		    "wwl.",
		    9,	/* StructSize */	/* w */
		    0,	/* reserved */		/* w */
		    0);				/* l. */
	}
}

/*
 * Build an SMB2 error context response (dialect 3.1.1).
 */
void
smb2sr_put_error_ctx(smb_request_t *sr, uint32_t status, uint32_t errid,
    mbuf_chain_t *mbc)
{
	DWORD len;

	/*
	 * The common dispatch code writes this when it
	 * updates the SMB2 header before sending.
	 */
	sr->smb2_status = status;

	/* Rewind to the end of the SMB header. */
	sr->reply.chain_offset = sr->smb2_reply_hdr + SMB2_HDR_SIZE;

	/*
	 *  Error Context is 8-byte header plus encaps. data (ErrorContextData),
	 *  which can be zero-length.
	 */
	if (mbc != NULL && (len = MBC_LENGTH(mbc)) != 0) {
		(void) smb_mbc_encodef(
		    &sr->reply,
		    "wbblllC",
		    9,		/* StructSize */	/* w */
		    1,		/* ErrorContextCount */	/* b */
		    0,		/* reserved */		/* b */
		    8+len,	/* ByteCount */		/* l */
		    len,	/* ErrorDataLength */	/* l */
		    errid,	/* ErrorId */		/* l */
		    mbc);				/* C */
	} else {
		(void) smb_mbc_encodef(
		    &sr->reply,
		    "wbblll",
		    9,		/* StructSize */	/* w */
		    1,		/* ErrorContextCount */	/* b */
		    0,		/* reserved */		/* b */
		    8,		/* ByteCount */		/* l */
		    0,		/* ErrorDataLength */	/* l */
		    errid);	/* ErrorId */		/* l */
	}
}

/*
 * Build an SMB2 error context response with SMB2_ERROR_ID_DEFAULT ErrorId.
 *
 * This only handles the case we currently need, encapsulating a
 * single error data section inside an SMB2_ERROR_ID_DEFAULT
 * error context type (which is type zero, and that's what
 * the zero on the end of this function name refers to).
 */
void
smb2sr_put_error_ctx0(smb_request_t *sr, uint32_t status, mbuf_chain_t *mbc)
{
	return (smb2sr_put_error_ctx(sr, status, SMB2_ERROR_ID_DEFAULT, mbc));
}

/*
 * smb2sr_lookup_fid
 *
 * Setup sr->fid_ofile, either inherited from a related command,
 * or obtained via FID lookup.  Similar inheritance logic as in
 * smb2sr_work.
 */
uint32_t
smb2sr_lookup_fid(smb_request_t *sr, smb2fid_t *fid)
{
	boolean_t related = sr->smb2_hdr_flags &
	    SMB2_FLAGS_RELATED_OPERATIONS;

	if (related) {
		if (sr->fid_ofile == NULL)
			return (NT_STATUS_INVALID_PARAMETER);
		sr->smb_fid = sr->fid_ofile->f_fid;
		return (0);
	}

	/*
	 * If we could be sure this is called only once per cmd,
	 * we could simply ASSERT(sr->fid_ofile == NULL) here.
	 * However, there are cases where it can be called again
	 * handling the same command, so let's tolerate that.
	 */
	if (sr->fid_ofile == NULL) {
		sr->smb_fid = (uint16_t)fid->temporal;
		sr->fid_ofile = smb_ofile_lookup_by_fid(sr, sr->smb_fid);
	}
	if (sr->fid_ofile == NULL ||
	    sr->fid_ofile->f_persistid != fid->persistent)
		return (NT_STATUS_FILE_CLOSED);

	return (0);
}

/*
 * smb2_dispatch_stats_init
 *
 * Initializes dispatch statistics for SMB2.
 * See also smb_dispatch_stats_init(), which fills in
 * the lower part of the statistics array, from zero
 * through SMB_COM_NUM;
 */
void
smb2_dispatch_stats_init(smb_server_t *sv)
{
	smb_disp_stats_t *sds = sv->sv_disp_stats2;
	smb_kstat_req_t *ksr;
	int		i;

	ksr = ((smbsrv_kstats_t *)sv->sv_ksp->ks_data)->ks_reqs2;

	for (i = 0; i < SMB2__NCMDS; i++, ksr++) {
		smb_latency_init(&sds[i].sdt_lat);
		(void) strlcpy(ksr->kr_name, smb2_disp_table[i].sdt_name,
		    sizeof (ksr->kr_name));
	}
}

/*
 * smb2_dispatch_stats_fini
 *
 * Frees and destroyes the resources used for statistics.
 */
void
smb2_dispatch_stats_fini(smb_server_t *sv)
{
	smb_disp_stats_t *sds = sv->sv_disp_stats2;
	int	i;

	for (i = 0; i < SMB2__NCMDS; i++)
		smb_latency_destroy(&sds[i].sdt_lat);
}

void
smb2_dispatch_stats_update(smb_server_t *sv,
    smb_kstat_req_t *ksr, int first, int nreq)
{
	smb_disp_stats_t *sds = sv->sv_disp_stats2;
	int	i;
	int	last;

	last = first + nreq - 1;

	if ((first < SMB2__NCMDS) && (last < SMB2__NCMDS))  {
		for (i = first; i <= last; i++, ksr++) {
			ksr->kr_rxb = sds[i].sdt_rxb;
			ksr->kr_txb = sds[i].sdt_txb;
			mutex_enter(&sds[i].sdt_lat.ly_mutex);
			ksr->kr_nreq = sds[i].sdt_lat.ly_a_nreq;
			ksr->kr_sum = sds[i].sdt_lat.ly_a_sum;
			ksr->kr_a_mean = sds[i].sdt_lat.ly_a_mean;
			ksr->kr_a_stddev =
			    sds[i].sdt_lat.ly_a_stddev;
			ksr->kr_d_mean = sds[i].sdt_lat.ly_d_mean;
			ksr->kr_d_stddev =
			    sds[i].sdt_lat.ly_d_stddev;
			sds[i].sdt_lat.ly_d_mean = 0;
			sds[i].sdt_lat.ly_d_nreq = 0;
			sds[i].sdt_lat.ly_d_stddev = 0;
			sds[i].sdt_lat.ly_d_sum = 0;
			mutex_exit(&sds[i].sdt_lat.ly_mutex);
		}
	}
}

/*
 * Append new_sr to the postwork queue.  sr->smb2_cmd_code encodes
 * the action that should be run by this sr.
 *
 * This queue is rarely used (and normally empty) so we're OK
 * using a simple "walk to tail and insert" here.
 */
void
smb2sr_append_postwork(smb_request_t *top_sr, smb_request_t *new_sr)
{
	smb_request_t *last_sr;

	ASSERT(top_sr->session->dialect >= SMB_VERS_2_BASE);

	last_sr = top_sr;
	while (last_sr->sr_postwork != NULL)
		last_sr = last_sr->sr_postwork;

	last_sr->sr_postwork = new_sr;
}

/*
 * Run any "post work" that was appended to the main SR while it
 * was running.  This is called after the request has been sent
 * for the main SR, and used in cases i.e. the oplock code, where
 * we need to send something to the client only _after_ the main
 * sr request has gone out.
 */
static void
smb2sr_run_postwork(smb_request_t *top_sr)
{
	smb_request_t *post_sr;	/* the one we're running */
	smb_request_t *next_sr;

	while ((post_sr = top_sr->sr_postwork) != NULL) {
		next_sr = post_sr->sr_postwork;
		top_sr->sr_postwork = next_sr;
		post_sr->sr_postwork = NULL;

		post_sr->sr_worker = top_sr->sr_worker;
		post_sr->sr_state = SMB_REQ_STATE_ACTIVE;

		switch (post_sr->smb2_cmd_code) {
		case SMB2_OPLOCK_BREAK:
			smb_oplock_send_break(post_sr);
			break;
		default:
			ASSERT(0);
		}

		/*
		 * If we have a durable handle, and this operation
		 * updated the nvlist, write it out.
		 */
		if (post_sr->dh_nvl_dirty) {
			post_sr->dh_nvl_dirty = B_FALSE;
			smb2_dh_update_nvfile(post_sr);
		}

		post_sr->sr_state = SMB_REQ_STATE_COMPLETED;
		smb_request_free(post_sr);
	}
}
