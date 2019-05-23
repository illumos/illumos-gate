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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_CANCEL
 */

#include <smbsrv/smb2_kproto.h>

static void smb2_cancel_async(smb_request_t *);
static void smb2_cancel_sync(smb_request_t *);

/*
 * This handles an SMB2_CANCEL request when seen in the reader.
 * (See smb2sr_newrq)  Handle this immediately, rather than
 * going through the normal taskq dispatch mechanism.
 * Note that Cancel does NOT get a response.
 *
 * Any non-zero return causes disconnect.
 * SMB2 header is already decoded.
 */
int
smb2_newrq_cancel(smb_request_t *sr)
{

	/*
	 * If we get SMB2 cancel as part of a compound,
	 * that's a protocol violation.  Drop 'em!
	 */
	if (sr->smb2_next_command != 0)
		return (EINVAL);

	if (sr->smb2_hdr_flags & SMB2_FLAGS_ASYNC_COMMAND)
		smb2_cancel_async(sr);
	else
		smb2_cancel_sync(sr);

	return (0);
}

/*
 * Dispatch handler for SMB2_CANCEL.
 * Note that Cancel does NOT get a response.
 */
smb_sdrc_t
smb2_cancel(smb_request_t *sr)
{

	/*
	 * If we get SMB2 cancel as part of a compound,
	 * that's a protocol violation.  Drop 'em!
	 */
	if (sr->smb2_cmd_hdr != 0 || sr->smb2_next_command != 0)
		return (SDRC_DROP_VC);

	if (sr->smb2_hdr_flags & SMB2_FLAGS_ASYNC_COMMAND) {
		smb2_cancel_async(sr);
	} else {
		smb2_cancel_sync(sr);
	}

	return (SDRC_NO_REPLY);
}

/*
 * SMB2 Cancel (sync) has an inherent race with the request being
 * cancelled.  The request may have been received but not yet
 * executed by a worker thread, in which case we'll mark the
 * request state as cancelled, and when a worker thread starts
 * on this request we'll cancel everything in the compound.
 */
static void
smb2_cancel_sync(smb_request_t *sr)
{
	struct smb_request *req;
	struct smb_session *session = sr->session;
	int cnt = 0;

	if (sr->smb2_messageid == 0)
		goto failure;

	smb_slist_enter(&session->s_req_list);
	for (req = smb_slist_head(&session->s_req_list); req != NULL;
	    req = smb_slist_next(&session->s_req_list, req)) {

		/* never cancel self */
		if (req == sr)
			continue;

		if (sr->smb2_messageid >= req->smb2_first_msgid &&
		    sr->smb2_messageid < (req->smb2_first_msgid +
		    req->smb2_total_credits)) {
			smb_request_cancel(req);
			cnt++;
		}
	}
	smb_slist_exit(&session->s_req_list);

	if (cnt != 1) {
	failure:
		DTRACE_PROBE2(smb2__cancel__error,
		    uint64_t, sr->smb2_messageid, int, cnt);
#ifdef	DEBUG
		/*
		 * It's somewhat common that we may see a cancel for a
		 * request that has already completed, so report that
		 * only in debug builds.
		 */
		cmn_err(CE_WARN, "SMB2 cancel failed, "
		    "client=%s, MID=0x%llx",
		    sr->session->ip_addr_str,
		    (u_longlong_t)sr->smb2_messageid);
#endif
	}
}

/*
 * Note that cancelling an async request doesn't have a race
 * because the client doesn't learn about the async ID until we
 * send it to them in an interim reply, and by that point the
 * request has progressed to the point where smb_cancel can find
 * the request and cancel it.
 */
static void
smb2_cancel_async(smb_request_t *sr)
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
		/*
		 * Not logging here, as this is normal, i.e.
		 * when both a cancel and a handle close
		 * terminates an SMB2_notify request.
		 */
	}
	smb_slist_exit(&session->s_req_list);
}
