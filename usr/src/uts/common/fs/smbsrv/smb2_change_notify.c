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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2022-2025 RackTop Systems, Inc.
 */

/*
 * Dispatch function for SMB2_CHANGE_NOTIFY
 */

#include <smbsrv/smb2_kproto.h>

/* For the output DataOffset fields in here. */
#define	DATA_OFF	(SMB2_HDR_SIZE + 8)

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

	/*
	 * Only deal with change notify last in a compound,
	 * because it blocks indefinitely.  This status gets
	 * "sticky" handling in smb2sr_work().
	 */
	if (sr->smb2_next_command != 0) {
		status = NT_STATUS_INSUFFICIENT_RESOURCES;
		goto errout;
	}

	CompletionFilter &= FILE_NOTIFY_VALID_MASK;
	if (iFlags & SMB2_WATCH_TREE)
		CompletionFilter |= FILE_NOTIFY_CHANGE_EV_SUBDIR;

	if (oBufLength > smb2_max_trans) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	/*
	 * Check for events and consume, non-blocking.
	 * Special return STATUS_PENDING means:
	 *   No events; caller must call "act2" next.
	 * SMB2 does that in "async mode".
	 */
	status = smb_notify_act1(sr, oBufLength, CompletionFilter);
	if (status == NT_STATUS_PENDING) {
		smb_disp_stats_t *sds;
		hrtime_t start_time = sr->sr_time_start;

		ASSERT(sr->smb2_cmd_code == SMB2_CHANGE_NOTIFY);
		sds = &sr->sr_server->sv_disp_stats2[SMB2_CHANGE_NOTIFY];

		status = smb2sr_go_async_indefinite(sr);
		if (status != 0)
			goto errout;
		status = smb_notify_act2(sr);
		if (status == NT_STATUS_PENDING) {
			/*
			 * NOTE: at this point, the sr can no longer be
			 * referenced, as smb2_change_notify_finish() may have
			 * freed the sr.
			 *
			 * Change Notify is expected to block for a long time.
			 * Record a latency sample before we go async
			 * so as not to mislead users of SMB statistics.
			 */
			smb_latency_add_sample(&sds->sdt_lat,
			    gethrtime() - start_time);

			/* See next: smb2_change_notify_finish */
			return (SDRC_SR_KEPT);
		}
	}

errout:
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
	smb_request_t *sr = arg;
	smb_disp_stats_t *sds;
	uint32_t status;
	uint32_t oBufLength;

	SMB_REQ_VALID(sr);

	/*
	 * Common part of notify, puts data in sr->raw_data
	 */
	status = smb_notify_act3(sr);

	/*
	 * The prior thread returned SDRC_SR_KEPT and skiped
	 * the dtrace DONE probe, so fire that here.
	 */
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

	/*
	 * Record some statistics.
	 * We already took a latency sample before we went async.
	 */
	sds = &sr->session->s_server->sv_disp_stats2[SMB2_CHANGE_NOTIFY];
	smb2_record_stats(sr, sds, B_FALSE);

	/*
	 * Put (overwrite) the final SMB2 header,
	 * sign, send.
	 */
	(void) smb2_encode_header(sr, B_TRUE);
	if (sr->smb2_hdr_flags & SMB2_FLAGS_SIGNED)
		smb2_sign_reply(sr);
	smb2_send_reply(sr);

	mutex_enter(&sr->sr_mutex);
	sr->sr_state = SMB_REQ_STATE_COMPLETED;
	mutex_exit(&sr->sr_mutex);

	smb_request_free(sr);
}
