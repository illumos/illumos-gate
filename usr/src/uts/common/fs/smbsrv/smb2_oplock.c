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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_OPLOCK_BREAK
 */

#include <smbsrv/smb2_kproto.h>

#define	BATCH_OR_EXCL	(OPLOCK_LEVEL_BATCH | OPLOCK_LEVEL_ONE)

/* StructSize for the two "break" message formats. */
#define	SSZ_OPLOCK	24
#define	SSZ_LEASE	36

/*
 * SMB2 Oplock Break Acknowledgement
 * [MS-SMB2] 3.3.5.22.1 Processing an Oplock Acknowledgment
 * Called via smb2_disp_table[]
 */
smb_sdrc_t
smb2_oplock_break_ack(smb_request_t *sr)
{
	smb_ofile_t *ofile;
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

	/* Find the ofile */
	status = smb2sr_lookup_fid(sr, &smb2fid);
	/* Success or NT_STATUS_FILE_CLOSED */

	DTRACE_SMB2_START(op__OplockBreak, smb_request_t *, sr);
	if (status != 0)
		goto errout;

	/*
	 * Process an (old-style) oplock break ack.
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
	case SMB2_OPLOCK_LEVEL_LEASE:	/* 0xFF */
	default:
		NewLevel = OPLOCK_LEVEL_NONE;
		break;
	}

	ofile = sr->fid_ofile;
	ofile->f_oplock.og_breaking = 0;
	status = smb_oplock_ack_break(sr, ofile, &NewLevel);
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		status = smb2sr_go_async(sr);
		if (status != 0)
			goto errout;
		(void) smb_oplock_wait_break(ofile->f_node, 0);
		status = 0;
	}
	if (status != 0) {
		NewLevel = OPLOCK_LEVEL_NONE;
		goto errout;
	}

	ofile->f_oplock.og_state = NewLevel;
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

errout:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__OplockBreak, smb_request_t *, sr);
	if (status) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
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
void
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
	 * Either of the above may have returned the
	 * status code that says we should wait.
	 */
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		(void) smb2sr_go_async(sr);
		(void) smb_oplock_wait_break(ofile->f_node, 0);
		status = 0;
	}

	/*
	 * Keep track of what we got (in ofile->f_oplock.og_state)
	 * so we'll know what we had when sending a break later.
	 * The og_dialect here is the oplock dialect, not the
	 * SMB dialect.  No lease here, so SMB 2.0.
	 */
	ofile->f_oplock.og_dialect = SMB_VERS_2_002;
	switch (status) {
	case NT_STATUS_SUCCESS:
		ofile->f_oplock.og_state = op->op_oplock_state;
		break;
	case NT_STATUS_OPLOCK_NOT_GRANTED:
		ofile->f_oplock.og_state = 0;
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	default:
		/* Caller did not check args sufficiently? */
		cmn_err(CE_NOTE, "clnt %s oplock req. err 0x%x",
		    sr->session->ip_addr_str, status);
		ofile->f_oplock.og_state = 0;
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	}

	/*
	 * Have STATUS_SUCCESS
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
