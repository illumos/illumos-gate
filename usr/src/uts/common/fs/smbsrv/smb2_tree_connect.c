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
 * Dispatch function for SMB2_TREE_CONNECT
 */

#include <smbsrv/smb2_kproto.h>

smb_sdrc_t
smb2_tree_connect(smb_request_t *sr)
{
	smb_arg_tcon_t	*tcon = &sr->sr_tcon;
	smb_tree_t	*tree = NULL;
	uint16_t StructureSize;
	uint16_t PathOffset;
	uint16_t PathLength;
	uint8_t ShareType;
	uint32_t ShareFlags;
	uint32_t Capabilities;
	uint32_t status;
	int skip;
	int rc = 0;

	/*
	 * SMB2 Tree Connect request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "w..ww",
	    &StructureSize,
	    /* reserved */
	    &PathOffset,
	    &PathLength);
	if (rc)
		return (SDRC_ERROR);

	/*
	 * We're normally positioned at the path name now,
	 * but there could be some padding before it.
	 */
	skip = (PathOffset + sr->smb2_cmd_hdr) -
	    sr->smb_data.chain_offset;
	if (skip < 0)
		return (SDRC_ERROR);
	if (skip > 0)
		(void) smb_mbc_decodef(&sr->smb_data, "#.", skip);

	/*
	 * Get the path name
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "%#U",
	    sr, (uint_t)PathLength, &tcon->path);
	if (rc)
		return (SDRC_ERROR);

	DTRACE_SMB2_START(op__TreeConnect, smb_request_t *, sr);

	/*
	 * [MS-SMB2] 3.3.5.7 Receiving an SMB2 TREE_CONNECT Request
	 *
	 * If RejectUnencryptedAccess is TRUE,
	 * global EncryptData or Share.EncryptData is TRUE,
	 * we support 3.x, and srv_cap doesn't indicate encryption support,
	 * return ACCESS_DENIED.
	 *
	 * This also applies to SMB1, so do it in smb_tree_connect_core.
	 */
	status = smb_tree_connect(sr);

	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__TreeConnect, smb_request_t *, sr);

	if (status) {
		(void) smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}
	tree = sr->tid_tree;

	/*
	 * Report the share type.
	 */
	switch (tree->t_res_type & STYPE_MASK) {
	case STYPE_IPC:
		ShareType = SMB2_SHARE_TYPE_PIPE;
		break;
	case STYPE_PRINTQ:
		ShareType = SMB2_SHARE_TYPE_PRINT;
		break;
	case STYPE_DISKTREE:
	default:
		ShareType = SMB2_SHARE_TYPE_DISK;
		break;
	}

	/*
	 * XXX These need work..
	 */
	if (tree->t_encrypt != SMB_CONFIG_DISABLED)
		ShareFlags = SMB2_SHAREFLAG_ENCRYPT_DATA;
	else
		ShareFlags = 0;

	Capabilities = 0;

	/*
	 * SMB2 Tree Connect reply
	 */
	(void) smb_mbc_encodef(
	    &sr->reply,
	    "wb.lll",
	    16,	/* StructSize */	/* w */
	    ShareType,			/* b */
	    ShareFlags,			/* l */
	    Capabilities,		/* l */
	    tree->t_access);		/* l */

	return (SDRC_SUCCESS);
}
