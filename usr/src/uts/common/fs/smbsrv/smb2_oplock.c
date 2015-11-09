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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_OPLOCK_BREAK
 */

#include <smbsrv/smb2_kproto.h>

/*
 * SMB2 Oplock Break Acknowledgement
 * [MS-SMB2 2.2.24]
 */
smb_sdrc_t
smb2_oplock_break_ack(smb_request_t *sr)
{
	smb_node_t *node;
	smb2fid_t smb2fid;
	uint32_t status;
	uint16_t StructSize;
	uint8_t OplockLevel;
	uint8_t brk;
	int rc = 0;

	/*
	 * Decode the SMB2 Oplock Break Ack.
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wb5.qq",
	    &StructSize,		/* w */
	    &OplockLevel,		/* b */
	    /* reserved			  5. */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal);		/* q */
	if (rc || StructSize != 24)
		return (SDRC_ERROR);

	status = smb2sr_lookup_fid(sr, &smb2fid);
	if (status)
		goto errout;
	if ((node = sr->fid_ofile->f_node) == NULL) {
		/* Not a regular file */
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	/*
	 * Process the oplock break ack.  We only expect levels
	 * at or below the hightest break levels we send, which is
	 * currently SMB2_OPLOCK_LEVEL_II.
	 */
	switch (OplockLevel) {
	case SMB2_OPLOCK_LEVEL_NONE:	/* 0x00 */
		brk = SMB_OPLOCK_BREAK_TO_NONE;
		break;

	case SMB2_OPLOCK_LEVEL_II:	/* 0x01 */
		brk = SMB_OPLOCK_BREAK_TO_LEVEL_II;
		break;

	/* We don't break to these levels (yet). */
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE: /* 0x08 */
	case SMB2_OPLOCK_LEVEL_BATCH:	/* 0x09 */
	case SMB2_OPLOCK_LEVEL_LEASE:	/* 0xFF */
	default: /* gcc -Wuninitialized */
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	smb_oplock_ack(node, sr->fid_ofile, brk);

	/*
	 * Generate SMB2 Oplock Break response
	 * [MS-SMB2] 2.2.25
	 */
	StructSize = 24;
	(void) smb_mbc_encodef(
	    &sr->reply, "wb5.qq",
	    StructSize,			/* w */
	    OplockLevel,		/* b */
	    /* reserved			  5. */
	    smb2fid.persistent,		/* q */
	    smb2fid.temporal);		/* q */
	return (SDRC_SUCCESS);

errout:
	smb2sr_put_error(sr, status);
	return (SDRC_SUCCESS);
}

/*
 * Compose an SMB2 Oplock Break Notification packet, including
 * the SMB2 header and everything, in sr->reply.
 * The caller will send it and free the request.
 */
void
smb2_oplock_break_notification(smb_request_t *sr, uint8_t brk)
{
	smb_ofile_t *ofile = sr->fid_ofile;
	smb2fid_t smb2fid;
	uint16_t StructSize;
	uint8_t OplockLevel;

	switch (brk) {
	default:
		ASSERT(0);
		/* FALLTHROUGH */
	case SMB_OPLOCK_BREAK_TO_NONE:
		OplockLevel = SMB2_OPLOCK_LEVEL_NONE;
		break;
	case SMB_OPLOCK_BREAK_TO_LEVEL_II:
		OplockLevel = SMB2_OPLOCK_LEVEL_II;
		break;
	}

	/*
	 * SMB2 Header
	 */
	sr->smb2_cmd_code = SMB2_OPLOCK_BREAK;
	sr->smb2_hdr_flags = SMB2_FLAGS_SERVER_TO_REDIR;
	sr->smb_tid = ofile->f_tree->t_tid;
	sr->smb_pid = 0;
	sr->smb_uid = 0;
	sr->smb2_messageid = UINT64_MAX;
	(void) smb2_encode_header(sr, B_FALSE);

	/*
	 * SMB2 Oplock Break, variable part
	 */
	StructSize = 24;
	smb2fid.persistent = 0;
	smb2fid.temporal = ofile->f_fid;
	(void) smb_mbc_encodef(
	    &sr->reply, "wb5.qq",
	    StructSize,		/* w */
	    OplockLevel,	/* b */
	    /* reserved		  5. */
	    smb2fid.persistent,	/* q */
	    smb2fid.temporal);	/* q */
}
