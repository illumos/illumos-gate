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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_CHANGE_NOTIFY
 */

#include <smbsrv/smb2_kproto.h>

/* For the output DataOffset fields in here. */
#define	DATA_OFF	(SMB2_HDR_SIZE + 8)

static smb_sdrc_t smb2_change_notify_async(smb_request_t *);

smb_sdrc_t
smb2_change_notify(smb_request_t *sr)
{
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
	DTRACE_SMB2_START(op__ChangeNotify, smb_request_t *, sr);

	if (status != 0)
		goto errout; /* Bad FID */

	CompletionFilter &= FILE_NOTIFY_VALID_MASK;
	if (iFlags & SMB2_WATCH_TREE)
		CompletionFilter |= FILE_NOTIFY_CHANGE_EV_SUBDIR;

	if (oBufLength > smb2_max_trans)
		oBufLength = smb2_max_trans;

	/*
	 * Check for events and consume, non-blocking.
	 * Special return STATUS_PENDING means:
	 *   No events; caller must call "act2" next.
	 * SMB2 does that in the "async" handler.
	 */
	status = smb_notify_act1(sr, oBufLength, CompletionFilter);
	if (status == NT_STATUS_PENDING) {
		status = smb2sr_go_async(sr, smb2_change_notify_async);
	}

errout:
	sr->smb2_status = status;
	if (status != NT_STATUS_PENDING) {
		DTRACE_SMB2_DONE(op__ChangeNotify, smb_request_t *, sr);
	}

	if (NT_SC_SEVERITY(status) == NT_STATUS_SEVERITY_SUCCESS) {
		oBufLength = sr->raw_data.chain_offset;
		(void) smb_mbc_encodef(
		    &sr->reply, "wwlC",
		    9,	/* StructSize */	/* w */
		    DATA_OFF,			/* w */
		    oBufLength,			/* l */
		    &sr->raw_data);		/* C */
	} else {
		smb2sr_put_error(sr, status);
	}

	return (SDRC_SUCCESS);
}

/*
 * This is called when the dispatch loop has made it to the end of a
 * compound request, and we had a notify that will require blocking.
 */
static smb_sdrc_t
smb2_change_notify_async(smb_request_t *sr)
{
	uint32_t status;

	status = smb_notify_act2(sr);
	if (status == NT_STATUS_PENDING) {
		/* See next: smb2_change_notify_finish */
		return (SDRC_SR_KEPT);
	}

	/* Note: Never NT_STATUS_NOTIFY_ENUM_DIR here. */
	ASSERT(status != NT_STATUS_NOTIFY_ENUM_DIR);

	if (status != 0)
		smb2sr_put_error(sr, status);

	return (SDRC_SUCCESS);
}

/*
 * This is called via taskq_dispatch in smb_notify.c
 * to finish up an NT transact notify change request.
 * Build an SMB2 Change Notify reply and send it.
 */
void
smb2_change_notify_finish(void *arg)
{
	smb_request_t	*sr = arg;
	uint32_t status;
	uint32_t oBufLength;

	SMB_REQ_VALID(sr);

	/*
	 * Common part of notify, puts data in sr->raw_data
	 */
	status = smb_notify_act3(sr);

	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__ChangeNotify, smb_request_t *, sr);

	if (NT_SC_SEVERITY(status) == NT_STATUS_SEVERITY_SUCCESS) {
		oBufLength = sr->raw_data.chain_offset;
		(void) smb_mbc_encodef(
		    &sr->reply, "wwlC",
		    9,	/* StructSize */	/* w */
		    DATA_OFF,			/* w */
		    oBufLength,			/* l */
		    &sr->raw_data);		/* C */
	} else {
		smb2sr_put_error(sr, status);
	}

	smb2sr_finish_async(sr);
}
