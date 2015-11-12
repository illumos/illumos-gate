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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_TREE_DISCONNECT
 */

#include <smbsrv/smb2_kproto.h>

smb_sdrc_t
smb2_tree_disconn(smb_request_t *sr)
{
	uint16_t StructSize;
	uint16_t reserved;
	int rc;

	/*
	 * SMB2 Tree Disconnect request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "ww",
	    &StructSize,		/* w */
	    &reserved);			/* w */
	if (rc)
		return (SDRC_ERROR);
	if (StructSize != 4)
		return (SDRC_ERROR);

	if (sr->uid_user == NULL || sr->tid_tree == NULL)
		return (SDRC_ERROR);

	smb_session_cancel_requests(sr->session, sr->tid_tree, sr);
	smb_tree_disconnect(sr->tid_tree, B_TRUE);

	/*
	 * SMB2 Tree Disconnect reply
	 */
	(void) smb_mbc_encodef(
	    &sr->reply, "wwl",
	    4,	/* StructSize */	/* w */
	    0); /* reserved */		/* w */

	return (SDRC_SUCCESS);
}
