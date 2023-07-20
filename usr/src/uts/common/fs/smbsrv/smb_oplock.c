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
 * Copyright 2020 Tintri by DDN, Inc.  All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 */

/*
 * smb1 oplock support
 */

#include <smbsrv/smb_kproto.h>

#define	BATCH_OR_EXCL	(OPLOCK_LEVEL_BATCH | OPLOCK_LEVEL_ONE)

/*
 * This is called by the SMB1 "Locking_andX" handler,
 * for SMB1 oplock break acknowledgement.
 * This is an "Ack" from the client.
 */
void
smb1_oplock_ack_break(smb_request_t *sr, uchar_t oplock_level)
{
	smb_ofile_t	*ofile;
	smb_node_t	*node;
	uint32_t	NewLevel;

	ofile = sr->fid_ofile;
	node = ofile->f_node;

	if (oplock_level == 0)
		NewLevel = OPLOCK_LEVEL_NONE;
	else
		NewLevel = OPLOCK_LEVEL_TWO;

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	ofile->f_oplock.og_breaking = B_FALSE;
	cv_broadcast(&ofile->f_oplock.og_ack_cv);

	(void) smb_oplock_ack_break(sr, ofile, &NewLevel);

	ofile->f_oplock.og_state = NewLevel;

	mutex_exit(&node->n_oplock.ol_mutex);
	smb_llist_exit(&node->n_ofile_list);
}

/*
 * Compose an SMB1 Oplock Break Notification packet, including
 * the SMB1 header and everything, in sr->reply.
 * The caller will send it and free the request.
 */
static void
smb1_oplock_break_notification(smb_request_t *sr, uint32_t NewLevel)
{
	smb_ofile_t *ofile = sr->fid_ofile;
	uint16_t fid;
	uint8_t lock_type;
	uint8_t oplock_level;

	/*
	 * Convert internal level to SMB1
	 */
	switch (NewLevel) {
	default:
		ASSERT(0);
		/* FALLTHROUGH */
	case OPLOCK_LEVEL_NONE:
		oplock_level = 0;
		break;

	case OPLOCK_LEVEL_TWO:
		oplock_level = 1;
		break;
	}

	sr->smb_com = SMB_COM_LOCKING_ANDX;
	sr->smb_tid = ofile->f_tree->t_tid;
	sr->smb_pid = 0xFFFF;
	sr->smb_uid = 0;
	sr->smb_mid = 0xFFFF;
	fid = ofile->f_fid;
	lock_type = LOCKING_ANDX_OPLOCK_RELEASE;

	(void) smb_mbc_encodef(
	    &sr->reply, "Mb19.wwwwbb3.wbb10.",
	    /*  "\xffSMB"		   M */
	    sr->smb_com,		/* b */
	    /* status, flags, signature	 19. */
	    sr->smb_tid,		/* w */
	    sr->smb_pid,		/* w */
	    sr->smb_uid,		/* w */
	    sr->smb_mid,		/* w */
	    8,		/* word count	   b */
	    0xFF,	/* AndX cmd	   b */
	    /*  AndX reserved, offset	  3. */
	    fid,
	    lock_type,
	    oplock_level);
}

/*
 * Send an oplock break over the wire, or if we can't,
 * then process the oplock break locally.
 *
 * [MS-CIFS] 3.3.4.2 Object Store Indicates an OpLock Break
 *
 * This is mostly similar to smb2_oplock_send_break()
 * See top comment there about the design.
 * Called from smb_oplock_async_break.
 *
 * This handles only SMB1, which has no durable handles,
 * and never has GRANULAR oplocks.
 */
void
smb1_oplock_send_break(smb_request_t *sr)
{
	smb_ofile_t	*ofile = sr->fid_ofile;
	smb_node_t	*node = ofile->f_node;
	uint32_t	NewLevel = sr->arg.olbrk.NewLevel;
	boolean_t	AckReq = sr->arg.olbrk.AckRequired;
	uint32_t	status;
	int		rc;

	/*
	 * SMB1 clients should only get Level II oplocks if they
	 * set the capability indicating they know about them.
	 */
	if (NewLevel == OPLOCK_LEVEL_TWO &&
	    ofile->f_oplock.og_dialect < NT_LM_0_12)
		NewLevel = OPLOCK_LEVEL_NONE;

	/*
	 * Build the break message in sr->reply.
	 * It's free'd in smb_request_free().
	 * Always SMB1 here.
	 */
	sr->reply.max_bytes = MLEN;
	smb1_oplock_break_notification(sr, NewLevel);

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
		 * Just close the handle.
		 */
		smb_ofile_close(ofile, 0);
		return;
	}

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
	 * Did not get an ACK, so do the ACK locally.
	 * Note: always break to none here, regardless
	 * of what the passed in cache level was.
	 */
	NewLevel = OPLOCK_LEVEL_NONE;

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	mutex_enter(&node->n_oplock.ol_mutex);

	ofile->f_oplock.og_breaking = B_FALSE;
	cv_broadcast(&ofile->f_oplock.og_ack_cv);

	status = smb_oplock_ack_break(sr, ofile, &NewLevel);

	ofile->f_oplock.og_state = NewLevel;

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
 * Convert SMB1 oplock request info in to internal form,
 * call common oplock code, convert result to SMB1.
 */
void
smb1_oplock_acquire(smb_request_t *sr, boolean_t level2ok)
{
	smb_arg_open_t *op = &sr->arg.open;
	smb_ofile_t *ofile = sr->fid_ofile;
	uint32_t status;

	/* Only disk trees get oplocks. */
	if ((sr->tid_tree->t_res_type & STYPE_MASK) != STYPE_DISKTREE) {
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_OPLOCKS)) {
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	if (!smb_session_levelII_oplocks(sr->session))
		level2ok = B_FALSE;

	/* Common code checks file type. */

	/*
	 * SMB1: Convert to internal form.
	 */
	switch (op->op_oplock_level) {
	case SMB_OPLOCK_BATCH:
		op->op_oplock_state = OPLOCK_LEVEL_BATCH;
		break;
	case SMB_OPLOCK_EXCLUSIVE:
		op->op_oplock_state = OPLOCK_LEVEL_ONE;
		break;
	case SMB_OPLOCK_LEVEL_II:
		op->op_oplock_state = OPLOCK_LEVEL_TWO;
		break;
	case SMB_OPLOCK_NONE:
	default:
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	/*
	 * Tree options may force shared oplocks
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
	 * and if the caller supports Level II, try shared.
	 */
	if (status == NT_STATUS_OPLOCK_NOT_GRANTED && level2ok) {
		op->op_oplock_state = OPLOCK_LEVEL_TWO;
		status = smb_oplock_request(sr, ofile,
		    &op->op_oplock_state);
	}

	/*
	 * Keep track of what we got (ofile->f_oplock.og_state etc)
	 * so we'll know what we had when sending a break later.
	 * The og_dialect here is the oplock dialect, which may be
	 * different than SMB dialect.  Pre-NT clients did not
	 * support "Level II" oplocks.  If we're talking to a
	 * client that didn't set the CAP_LEVEL_II_OPLOCKS in
	 * its capabilities, let og_dialect = LANMAN2_1.
	 */
	switch (status) {
	case NT_STATUS_SUCCESS:
	case NT_STATUS_OPLOCK_BREAK_IN_PROGRESS:
		ofile->f_oplock.og_dialect = (level2ok) ?
		    NT_LM_0_12 : LANMAN2_1;
		ofile->f_oplock.og_state   = op->op_oplock_state;
		ofile->f_oplock.og_breakto = op->op_oplock_state;
		ofile->f_oplock.og_breaking = B_FALSE;
		break;
	case NT_STATUS_OPLOCK_NOT_GRANTED:
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	default:
		/* Caller did not check args sufficiently? */
		cmn_err(CE_NOTE, "clnt %s oplock req. err 0x%x",
		    sr->session->ip_addr_str, status);
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	/*
	 * Only succes cases get here.
	 * Convert internal oplock state to SMB1
	 */
	if (op->op_oplock_state & OPLOCK_LEVEL_BATCH) {
		op->op_oplock_level = SMB_OPLOCK_BATCH;
	} else if (op->op_oplock_state & OPLOCK_LEVEL_ONE) {
		op->op_oplock_level = SMB_OPLOCK_EXCLUSIVE;
	} else if (op->op_oplock_state & OPLOCK_LEVEL_TWO) {
		op->op_oplock_level = SMB_OPLOCK_LEVEL_II;
	} else {
		op->op_oplock_level = SMB_OPLOCK_NONE;
	}

	/*
	 * An smb_oplock_reqest call may have returned the
	 * status code that says we should wait.
	 */
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		(void) smb_oplock_wait_break(sr, ofile->f_node, 0);
	}
}
