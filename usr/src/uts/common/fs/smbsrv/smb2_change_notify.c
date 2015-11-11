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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_CHANGE_NOTIFY
 */

#include <smbsrv/smb2_kproto.h>

static smb_sdrc_t smb2_change_notify_async(smb_request_t *);

smb_sdrc_t
smb2_change_notify(smb_request_t *sr)
{
	smb_node_t *node = NULL;
	uint16_t StructSize;
	uint16_t iFlags;
	uint32_t oBufLength;
	smb2fid_t smb2fid;
	uint32_t CompletionFilter;
	uint32_t reserved;
	uint32_t status;
	int rc = 0;

	/*
	 * SMB2 Change Notify request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data,		"wwlqqll",
	    &StructSize,		/* w */
	    &iFlags,			/* w */
	    &oBufLength,		/* l */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal,		/* q */
	    &CompletionFilter,		/* l */
	    &reserved);			/* l */
	if (rc || StructSize != 32)
		return (SDRC_ERROR);

	status = smb2sr_lookup_fid(sr, &smb2fid);
	if (status)
		goto puterror;

	node = sr->fid_ofile->f_node;
	if (node == NULL || !smb_node_is_dir(node)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto puterror;
	}

	/*
	 * Let Change Notify "go async", because it
	 * may block indefinitely.
	 */
	status = smb2sr_go_async(sr, smb2_change_notify_async);
puterror:
	ASSERT(status != 0);
	smb2sr_put_error(sr, status);
	return (SDRC_SUCCESS);
}

static smb_sdrc_t
smb2_change_notify_async(smb_request_t *sr)
{
	uint16_t StructSize;
	uint16_t iFlags;
	uint32_t oBufLength;
	smb2fid_t smb2fid;
	uint32_t CompletionFilter;
	uint32_t reserved;
	uint32_t status;
	uint16_t DataOff;
	int rc = 0;

	/*
	 * SMB2 Change Notify request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data,		"wwlqqll",
	    &StructSize,		/* w */
	    &iFlags,			/* w */
	    &oBufLength,		/* l */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal,		/* q */
	    &CompletionFilter,		/* l */
	    &reserved);			/* l */
	if (rc || StructSize != 32)
		return (SDRC_ERROR);

	status = smb2sr_lookup_fid(sr, &smb2fid);
	if (status != 0) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	CompletionFilter &= FILE_NOTIFY_VALID_MASK;
	if (iFlags & SMB2_WATCH_TREE)
		CompletionFilter |= NODE_FLAGS_WATCH_TREE;

	if (oBufLength > smb2_max_trans)
		oBufLength = smb2_max_trans;
	sr->raw_data.max_bytes = oBufLength;

	status = smb_notify_common(sr, &sr->raw_data, CompletionFilter);
	if (status != 0) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	/*
	 * SMB2 Change Notify reply
	 */
	DataOff = SMB2_HDR_SIZE + 8;
	oBufLength = MBC_LENGTH(&sr->raw_data);
	rc = smb_mbc_encodef(
	    &sr->reply, "wwlC",
	    9,	/* StructSize */	/* w */
	    DataOff,			/* w */
	    oBufLength,			/* l */
	    &sr->raw_data);		/* C */
	if (rc)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}
