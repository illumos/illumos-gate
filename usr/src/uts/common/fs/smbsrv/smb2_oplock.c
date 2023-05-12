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
 * Copyright 2020 Tintri by DDN, Inc.  All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 */

/*
 * Dispatch function for SMB2_OPLOCK_BREAK
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_oplock.h>

#define	BATCH_OR_EXCL	(OPLOCK_LEVEL_BATCH | OPLOCK_LEVEL_ONE)

/* StructSize for the two "break" message formats. */
#define	SSZ_OPLOCK	24
#define	SSZ_LEASE	36

/*
 * SMB2 Oplock Break Acknowledgement
 * [MS-SMB2] 3.3.5.22.1 Processing an Oplock Acknowledgment
 * Called via smb2_disp_table[]
 * This is an "Ack" from the client.
 */
smb_sdrc_t
smb2_oplock_break_ack(smb_request_t *sr)
{
	smb_arg_olbrk_t	*olbrk = &sr->arg.olbrk;
	smb_node_t  *node;
	smb_ofile_t *ofile;
	smb_oplock_grant_t *og;
	smb2fid_t smb2fid;
	uint32_t status;
	uint32_t NewLevel;
	uint8_t smbOplockLevel;
	int rc = 0;
	uint16_t StructSize;

	/*
	 * Decode the SMB2 Oplock Break Ack (24 bytes) or
	 * Lease Break Ack (36 bytes), starting with just
	 * the StructSize, which tells us what this is.
	 */
	rc = smb_mbc_decodef(&sr->smb_data, "w", &StructSize);
	if (rc != 0)
		return (SDRC_ERROR);

	if (StructSize == SSZ_LEASE) {
		/* See smb2_lease.c */
		return (smb2_lease_break_ack(sr));
	}
	if (StructSize != SSZ_OPLOCK)
		return (SDRC_ERROR);

	/*
	 * Decode an SMB2 Oplock Break Ack.
	 * [MS-SMB2] 2.2.24.1
	 * Note: Struct size decoded above.
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "b5.qq",
	    &smbOplockLevel,		/* b */
	    /* reserved			  5. */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal);		/* q */
	if (rc != 0)
		return (SDRC_ERROR);

	/*
	 * Convert SMB oplock level to internal form.
	 */
	switch (smbOplockLevel) {
	case SMB2_OPLOCK_LEVEL_NONE:	/* 0x00 */
		NewLevel = OPLOCK_LEVEL_NONE;
		break;
	case SMB2_OPLOCK_LEVEL_II:	/* 0x01 */
		NewLevel = OPLOCK_LEVEL_TWO;
		break;
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE: /* 0x08 */
		NewLevel = OPLOCK_LEVEL_ONE;
		break;
	case SMB2_OPLOCK_LEVEL_BATCH:	/* 0x09 */
		NewLevel = OPLOCK_LEVEL_BATCH;
		break;

	/* Note: _LEVEL_LEASE is not valid here. */
	case SMB2_OPLOCK_LEVEL_LEASE:	/* 0xFF */
	default:
		/*
		 * Impossible NewLevel here, will cause
		 * NT_STATUS_INVALID_PARAMETER below.
		 */
		NewLevel = OPLOCK_LEVEL_GRANULAR;
		break;
	}

	/* for dtrace */
	olbrk->NewLevel = NewLevel;

	/* Find the ofile */
	status = smb2sr_lookup_fid(sr, &smb2fid);
	/* Success or NT_STATUS_FILE_CLOSED */

	DTRACE_SMB2_START(op__OplockBreak, smb_request_t *, sr);

	if (status != 0) {
		/* lookup fid failed */
		goto errout;
	}

	if (NewLevel == OPLOCK_LEVEL_GRANULAR) {
		/* Switch above got invalid smbOplockLevel */
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	/* Success, so have sr->fid_ofile */
	ofile = sr->fid_ofile;
	og = &ofile->f_oplock;
	node = ofile->f_node;

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	if (og->og_breaking == B_FALSE) {
		/*
		 * This is an unsolicited Ack. (There is no
		 * outstanding oplock break in progress now.)
		 * There are WPTS tests that care which error
		 * is returned.  See [MS-SMB2] 3.3.5.22.1
		 */
		if (NewLevel >= (og->og_state & OPLOCK_LEVEL_TYPE_MASK)) {
			status = NT_STATUS_INVALID_OPLOCK_PROTOCOL;
			goto unlock_out;
		}
		status = NT_STATUS_INVALID_DEVICE_STATE;
		goto unlock_out;
	}

	/*
	 * Process the oplock break ack.
	 *
	 * Clear breaking flags before we ack,
	 * because ack might set those.
	 */
	ofile->f_oplock.og_breaking = B_FALSE;
	cv_broadcast(&ofile->f_oplock.og_ack_cv);

	status = smb_oplock_ack_break(sr, ofile, &NewLevel);

	ofile->f_oplock.og_state = NewLevel;
	if (ofile->dh_persist)
		smb2_dh_update_oplock(sr, ofile);

unlock_out:
	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__OplockBreak, smb_request_t *, sr);
	if (status) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	/*
	 * Convert internal oplock state back to SMB form.
	 */
	switch (NewLevel & OPLOCK_LEVEL_TYPE_MASK) {
	case OPLOCK_LEVEL_NONE:
		smbOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
		break;
	case OPLOCK_LEVEL_TWO:
		smbOplockLevel = SMB2_OPLOCK_LEVEL_II;
		break;
	case OPLOCK_LEVEL_ONE:
		smbOplockLevel = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
		break;
	case OPLOCK_LEVEL_BATCH:
		smbOplockLevel = SMB2_OPLOCK_LEVEL_BATCH;
		break;
	case OPLOCK_LEVEL_GRANULAR:
	default:
		smbOplockLevel = SMB2_OPLOCK_LEVEL_NONE;
		break;
	}

	/*
	 * Encode an SMB2 Oplock Break Ack response
	 * [MS-SMB2] 2.2.25.1
	 */
	(void) smb_mbc_encodef(
	    &sr->reply, "wb5.qq",
	    SSZ_OPLOCK,			/* w */
	    smbOplockLevel,		/* b */
	    /* reserved			  5. */
	    smb2fid.persistent,		/* q */
	    smb2fid.temporal);		/* q */

	return (SDRC_SUCCESS);
}

/*
 * Compose an SMB2 Oplock Break Notification packet, including
 * the SMB2 header and everything, in sr->reply.
 * The caller will send it and free the request.
 */
static void
smb2_oplock_break_notification(smb_request_t *sr, uint32_t NewLevel)
{
	smb_ofile_t *ofile = sr->fid_ofile;
	smb2fid_t smb2fid;
	uint16_t StructSize;
	uint8_t OplockLevel;

	/*
	 * Convert internal level to SMB2
	 */
	switch (NewLevel) {
	default:
		ASSERT(0);
		/* FALLTHROUGH */
	case OPLOCK_LEVEL_NONE:
		OplockLevel = SMB2_OPLOCK_LEVEL_NONE;
		break;
	case OPLOCK_LEVEL_TWO:
		OplockLevel = SMB2_OPLOCK_LEVEL_II;
		break;
	}

	/*
	 * SMB2 Header
	 */
	sr->smb2_cmd_code = SMB2_OPLOCK_BREAK;
	sr->smb2_hdr_flags = SMB2_FLAGS_SERVER_TO_REDIR;
	sr->smb_tid = 0;
	sr->smb_pid = 0;
	sr->smb2_ssnid = 0;
	sr->smb2_messageid = UINT64_MAX;
	(void) smb2_encode_header(sr, B_FALSE);

	/*
	 * SMB2 Oplock Break, variable part
	 */
	StructSize = 24;
	smb2fid.persistent = ofile->f_persistid;
	smb2fid.temporal = ofile->f_fid;
	(void) smb_mbc_encodef(
	    &sr->reply, "wb5.qq",
	    StructSize,		/* w */
	    OplockLevel,	/* b */
	    /* reserved		  5. */
	    smb2fid.persistent,	/* q */
	    smb2fid.temporal);	/* q */
}

/*
 * Send an oplock break over the wire, or if we can't,
 * then process the oplock break locally.
 *
 * [MS-SMB2] 3.3.4.6 Object Store Indicates an Oplock Break
 *
 * Note: When "AckRequired" is set, and we're for any reason
 * unable to communicate with the client so that they do an
 * "oplock break ACK", then we absolutely MUST do a local ACK
 * for this break indication (or close the ofile).
 *
 * The file-system level oplock code (smb_cmn_oplock.c)
 * requires these ACK calls to clear "breaking" flags.
 *
 * This is called either from smb_oplock_async_break via a
 * taskq job scheduled in smb_oplock_ind_break, or from the
 * smb2sr_append_postwork() mechanism when we're doing a
 * "break in ack", via smb_oplock_ind_break_in_ack.
 *
 * This runs much like other smb_request_t handlers, in the
 * context of a worker task that calls with no locks held.
 *
 * Note that we have sr->fid_ofile here but all the other
 * normal sr members may be NULL:  uid_user, tid_tree.
 * Also sr->session may or may not be the same session as
 * the ofile came from (ofile->f_session) depending on
 * whether this is a "live" open or an orphaned DH,
 * where ofile->f_session will be NULL.
 */
void
smb2_oplock_send_break(smb_request_t *sr)
{
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_node_t	*node = ofile->f_node;
	uint32_t	NewLevel = sr->arg.olbrk.NewLevel;
	boolean_t	AckReq = sr->arg.olbrk.AckRequired;
	uint32_t	status;
	int		rc;

	/*
	 * Build the break message in sr->reply.
	 * It's free'd in smb_request_free().
	 * Always SMB2 oplock here (no lease)
	 */
	sr->reply.max_bytes = MLEN;
	smb2_oplock_break_notification(sr, NewLevel);

	/*
	 * Try to send the break message to the client.
	 * If connected, this IF body will be true.
	 */
	if (sr->session == ofile->f_session)
		rc = smb_session_send(sr->session, 0, &sr->reply);
	else
		rc = ENOTCONN;

	if (rc != 0) {
		/*
		 * We were unable to send the oplock break request,
		 * presumably because the connection is gone.
		 *
		 * [MS-SMB2] 3.3.4.6 Object Store Indicates an Oplock Break
		 * If no connection is available, Open.IsResilient is FALSE,
		 * Open.IsDurable is FALSE, and Open.IsPersistent is FALSE,
		 * the server SHOULD close the Open as specified in...
		 */
		if (ofile->dh_persist == B_FALSE &&
		    ofile->dh_vers != SMB2_RESILIENT &&
		    (ofile->dh_vers == SMB2_NOT_DURABLE ||
		    (NewLevel & OPLOCK_LEVEL_BATCH) == 0)) {
			smb_ofile_close(ofile, 0);
			return;
		}
		/* Keep this (durable) open. */
		if (!AckReq)
			return;
		/* Do local Ack below. */
	} else {
		/*
		 * OK, we were able to send the break message.
		 * If no ack. required, we're done.
		 */
		if (!AckReq)
			return;

		/*
		 * We're expecting an ACK.  Wait in this thread
		 * so we can log clients that don't respond.
		 * Note: this can also fail for other reasons
		 * such as client disconnect or server shutdown.
		 */
		status = smb_oplock_wait_ack(sr, NewLevel);
		if (status == 0)
			return;

		DTRACE_PROBE2(wait__ack__failed, smb_request_t *, sr,
		    uint32_t, status);

		/*
		 * Will do local ack below.  Note, after timeout,
		 * do a break to none or "no caching" regardless
		 * of what the passed in cache level was.
		 */
		NewLevel = OPLOCK_LEVEL_NONE;
	}

	/*
	 * Do the ack locally.
	 */
	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	ofile->f_oplock.og_breaking = B_FALSE;
	cv_broadcast(&ofile->f_oplock.og_ack_cv);

	status = smb_oplock_ack_break(sr, ofile, &NewLevel);

	ofile->f_oplock.og_state = NewLevel;
	if (ofile->dh_persist)
		smb2_dh_update_oplock(sr, ofile);

	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);

#ifdef	DEBUG
	if (status != 0) {
		cmn_err(CE_NOTE, "clnt %s local oplock ack, status=0x%x",
		    sr->session->ip_addr_str, status);
	}
#endif
}

/*
 * Client has an open handle and requests an oplock.
 * Convert SMB2 oplock request info in to internal form,
 * call common oplock code, convert result to SMB2.
 *
 * If necessary, "go async" here.
 */
void
smb2_oplock_acquire(smb_request_t *sr)
{
	smb_arg_open_t *op = &sr->arg.open;
	smb_ofile_t *ofile = sr->fid_ofile;
	uint32_t status;

	/* Only disk trees get oplocks. */
	ASSERT((sr->tid_tree->t_res_type & STYPE_MASK) == STYPE_DISKTREE);

	/* Only plain files... */
	if (!smb_node_is_file(ofile->f_node)) {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	}

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_OPLOCKS)) {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	}

	/*
	 * SMB2: Convert to internal form.
	 */
	switch (op->op_oplock_level) {
	case SMB2_OPLOCK_LEVEL_BATCH:
		op->op_oplock_state = OPLOCK_LEVEL_BATCH;
		break;
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
		op->op_oplock_state = OPLOCK_LEVEL_ONE;
		break;
	case SMB2_OPLOCK_LEVEL_II:
		op->op_oplock_state = OPLOCK_LEVEL_TWO;
		break;
	case SMB2_OPLOCK_LEVEL_LEASE:
		ASSERT(0); /* Handled elsewhere */
		/* FALLTHROUGH */
	case SMB2_OPLOCK_LEVEL_NONE:
	default:
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	}

	/*
	 * Tree options may force shared oplocks,
	 * in which case we reduce the request.
	 * Can't get here with LEVEL_NONE, so
	 * this can only decrease the level.
	 */
	if (smb_tree_has_feature(sr->tid_tree, SMB_TREE_FORCE_L2_OPLOCK)) {
		op->op_oplock_state = OPLOCK_LEVEL_TWO;
	}

	/*
	 * Try exclusive first, if requested
	 */
	if ((op->op_oplock_state & BATCH_OR_EXCL) != 0) {
		status = smb_oplock_request(sr, ofile,
		    &op->op_oplock_state);
	} else {
		status = NT_STATUS_OPLOCK_NOT_GRANTED;
	}

	/*
	 * If exclusive failed (or the tree forced shared oplocks)
	 * try for a shared oplock (Level II)
	 */
	if (status == NT_STATUS_OPLOCK_NOT_GRANTED) {
		op->op_oplock_state = OPLOCK_LEVEL_TWO;
		status = smb_oplock_request(sr, ofile,
		    &op->op_oplock_state);
	}

	/*
	 * Keep track of what we got (ofile->f_oplock.og_state etc)
	 * so we'll know what we had when sending a break later.
	 * The og_dialect here is the oplock dialect, not the
	 * SMB dialect.  No lease here, so SMB 2.0.
	 */
	switch (status) {
	case NT_STATUS_SUCCESS:
	case NT_STATUS_OPLOCK_BREAK_IN_PROGRESS:
		ofile->f_oplock.og_dialect = SMB_VERS_2_002;
		ofile->f_oplock.og_state   = op->op_oplock_state;
		ofile->f_oplock.og_breakto = op->op_oplock_state;
		ofile->f_oplock.og_breaking = B_FALSE;
		if (ofile->dh_persist) {
			smb2_dh_update_oplock(sr, ofile);
		}
		break;

	case NT_STATUS_OPLOCK_NOT_GRANTED:
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;

	default:
		/* Caller did not check args sufficiently? */
		cmn_err(CE_NOTE, "clnt %s oplock req. err 0x%x",
		    sr->session->ip_addr_str, status);
		DTRACE_PROBE2(other__error, smb_request_t *, sr,
		    uint32_t, status);
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	}

	/*
	 * Only success cases get here
	 * Convert internal oplock state to SMB2
	 */
	if (op->op_oplock_state & OPLOCK_LEVEL_GRANULAR) {
		ASSERT(0);
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
	} else if (op->op_oplock_state & OPLOCK_LEVEL_BATCH) {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	} else if (op->op_oplock_state & OPLOCK_LEVEL_ONE) {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	} else if (op->op_oplock_state & OPLOCK_LEVEL_TWO) {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_II;
	} else {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
	}

	/*
	 * An smb_oplock_reqest call may have returned the
	 * status code that says we should wait.
	 */
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		(void) smb2sr_go_async(sr);
		(void) smb_oplock_wait_break(sr, ofile->f_node, 0);
	}
}

/*
 * smb2_oplock_reconnect()  Helper for smb2_dh_reconnect
 * Get oplock state into op->op_oplock_level etc.
 *
 * Similar to the end of smb2_lease_acquire (for leases) or
 * the end of smb2_oplock_acquire (for old-style oplocks).
 */
void
smb2_oplock_reconnect(smb_request_t *sr)
{
	smb_arg_open_t *op = &sr->arg.open;
	smb_ofile_t *ofile = sr->fid_ofile;

	op->op_oplock_state = ofile->f_oplock.og_state;
	if (ofile->f_lease != NULL) {
		smb_lease_t *ls = ofile->f_lease;

		op->op_oplock_level = SMB2_OPLOCK_LEVEL_LEASE;
		op->lease_state = ls->ls_state &
		    OPLOCK_LEVEL_CACHE_MASK;
		op->lease_flags = (ls->ls_breaking != 0) ?
		    SMB2_LEASE_FLAG_BREAK_IN_PROGRESS : 0;
		op->lease_epoch = ls->ls_epoch;
		op->lease_version = ls->ls_version;
	} else {
		switch (op->op_oplock_state & OPLOCK_LEVEL_TYPE_MASK) {
		default:
		case OPLOCK_LEVEL_NONE:
			op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
			break;
		case OPLOCK_LEVEL_TWO:
			op->op_oplock_level = SMB2_OPLOCK_LEVEL_II;
			break;
		case OPLOCK_LEVEL_ONE:
			op->op_oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
			break;
		case OPLOCK_LEVEL_BATCH:
			op->op_oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
			break;
		}
	}
}
