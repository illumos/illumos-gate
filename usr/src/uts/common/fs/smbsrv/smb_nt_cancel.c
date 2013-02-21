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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SMB: nt_cancel
 *
 * This SMB allows a client to cancel a request currently pending at the
 * server.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   No words are sent (== 0)
 * USHORT ByteCount;                  No bytes (==0)
 *
 * The Sid, Uid, Pid, Tid, and Mid fields of the SMB are used to locate an
 * pending server request from this session.  If a pending request is
 * found, it is "hurried along" which may result in success or failure of
 * the original request.  No other response is generated for this SMB.
 */

#include <smbsrv/smb_kproto.h>

smb_sdrc_t
smb_pre_nt_cancel(smb_request_t *sr)
{
	DTRACE_SMB_1(op__NtCancel__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_nt_cancel(smb_request_t *sr)
{
	DTRACE_SMB_1(op__NtCancel__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_nt_cancel(smb_request_t *sr)
{
	struct smb_request *req;
	struct smb_session *session;

	session = sr->session;

	smb_slist_enter(&session->s_req_list);
	req = smb_slist_head(&session->s_req_list);
	while (req) {
		ASSERT(req->sr_magic == SMB_REQ_MAGIC);
		if ((req != sr) &&
		    (req->smb_uid == sr->smb_uid) &&
		    (req->smb_pid == sr->smb_pid) &&
		    (req->smb_tid == sr->smb_tid) &&
		    (req->smb_mid == sr->smb_mid)) {
			smb_request_cancel(req);
		}
		req = smb_slist_next(&session->s_req_list, req);
	}
	smb_slist_exit(&session->s_req_list);

	return (SDRC_NO_REPLY);
}
