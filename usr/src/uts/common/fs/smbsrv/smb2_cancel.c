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
 * Dispatch function for SMB2_CANCEL
 */

#include <smbsrv/smb2_kproto.h>

static void smb2sr_cancel_async(smb_request_t *);
static void smb2sr_cancel_sync(smb_request_t *);

/*
 * This handles an SMB2_CANCEL request when seen in the reader.
 * (See smb2sr_newrq)  Handle this immediately, rather than
 * going through the normal taskq dispatch mechanism.
 * Note that Cancel does NOT get a response.
 */
int
smb2sr_newrq_cancel(smb_request_t *sr)
{
	int rc;

	/*
	 * Decode the header
	 */
	if ((rc = smb2_decode_header(sr)) != 0)
		return (rc);

	if (sr->smb2_hdr_flags & SMB2_FLAGS_ASYNC_COMMAND)
		smb2sr_cancel_async(sr);
	else
		smb2sr_cancel_sync(sr);

	return (0);
}

static void
smb2sr_cancel_sync(smb_request_t *sr)
{
	struct smb_request *req;
	struct smb_session *session = sr->session;
	int cnt = 0;

	smb_slist_enter(&session->s_req_list);
	req = smb_slist_head(&session->s_req_list);
	while (req) {
		ASSERT(req->sr_magic == SMB_REQ_MAGIC);
		if ((req != sr) &&
		    (req->smb2_messageid == sr->smb2_messageid)) {
			smb_request_cancel(req);
			cnt++;
		}
		req = smb_slist_next(&session->s_req_list, req);
	}
	if (cnt != 1) {
		DTRACE_PROBE2(smb2__cancel__error,
		    uint64_t, sr->smb2_messageid, int, cnt);
	}
	smb_slist_exit(&session->s_req_list);
}

static void
smb2sr_cancel_async(smb_request_t *sr)
{
	struct smb_request *req;
	struct smb_session *session = sr->session;
	int cnt = 0;

	smb_slist_enter(&session->s_req_list);
	req = smb_slist_head(&session->s_req_list);
	while (req) {
		ASSERT(req->sr_magic == SMB_REQ_MAGIC);
		if ((req != sr) &&
		    (req->smb2_async_id == sr->smb2_async_id)) {
			smb_request_cancel(req);
			cnt++;
		}
		req = smb_slist_next(&session->s_req_list, req);
	}
	if (cnt != 1) {
		DTRACE_PROBE2(smb2__cancel__error,
		    uint64_t, sr->smb2_async_id, int, cnt);
	}
	smb_slist_exit(&session->s_req_list);
}
