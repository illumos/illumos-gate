/*
 * Copyright (c) 2011  Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2024 RackTop Systems, Inc.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>
#include <sys/sdt.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb2.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb2_rq.h>

static const uint8_t SMB2_SIGNATURE[4] = SMB2_PROTOCOL_ID;

static int  smb2_rq_enqueue(struct smb_rq *rqp);
static int  smb2_rq_reply(struct smb_rq *rqp);

/*
 * Given a request with it's body already composed,
 * rewind to the start and fill in the SMB2 header.
 * This is called when the request is enqueued,
 * so we have the final message ID etc.
 */
void
smb2_rq_fillhdr(struct smb_rq *rqp)
{
	struct mbchain mbtmp, *mbp = &mbtmp;
	uint16_t creditcharge, creditrequest;
	size_t len;
	mblk_t *m;

	ASSERT((rqp->sr2_nextcmd & 7) == 0);
	if (rqp->sr2_nextcmd != 0) {
		len = msgdsize(rqp->sr_rq.mb_top);
		ASSERT((len & 7) == 0);
	}

	/*
	 * When sending negotiate, we don't technically know yet
	 * if the server handles SMB 2.1 or later and credits.
	 * Negotiate is supposed to set these to zero.
	 */
	if (rqp->sr2_command == SMB2_NEGOTIATE) {
		creditcharge = creditrequest = 0;
	} else {
		creditcharge = rqp->sr2_creditcharge;
		creditrequest = rqp->sr2_creditsrequested;
	}

	/*
	 * Fill in the SMB2 header using a dup of the first mblk,
	 * which points at the same data but has its own wptr,
	 * so we can rewind without trashing the message.
	 */
	m = dupb(rqp->sr_rq.mb_top);
	m->b_wptr = m->b_rptr;	/* rewind */
	mb_initm(mbp, m);

	mb_put_mem(mbp, SMB2_SIGNATURE, 4, MB_MSYSTEM);
	mb_put_uint16le(mbp, SMB2_HDR_SIZE);		/* Struct Size */
	mb_put_uint16le(mbp, creditcharge);
	mb_put_uint32le(mbp, 0);	/* Status */
	mb_put_uint16le(mbp, rqp->sr2_command);
	mb_put_uint16le(mbp, creditrequest);
	mb_put_uint32le(mbp, rqp->sr2_rqflags);
	mb_put_uint32le(mbp, rqp->sr2_nextcmd);
	mb_put_uint64le(mbp, rqp->sr2_messageid);

	mb_put_uint32le(mbp, rqp->sr_pid);		/* Process ID */
	mb_put_uint32le(mbp, rqp->sr2_rqtreeid);	/* Tree ID */
	mb_put_uint64le(mbp, rqp->sr2_rqsessionid);	/* Session ID */
	/* The MAC signature is filled in by smb2_vc_sign() */

	/* This will free the mblk from dupb. */
	mb_done(mbp);
}

int
smb2_rq_simple(struct smb_rq *rqp)
{
	return (smb2_rq_simple_timed(rqp, smb2_timo_default));
}

/*
 * Simple request-reply exchange
 */
int
smb2_rq_simple_timed(struct smb_rq *rqp, int timeout)
{
	int error;

	rqp->sr_flags &= ~SMBR_RESTART;
	rqp->sr_timo = timeout;	/* in seconds */
	rqp->sr_state = SMBRQ_NOTSENT;

	error = smb2_rq_enqueue(rqp);
	if (error == 0)
		error = smb2_rq_reply(rqp);

	return (error);
}


static int
smb2_rq_enqueue(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	struct smb_share *ssp = rqp->sr_share;
	int error = 0;

	ASSERT((vcp->vc_flags & SMBV_SMB2) != 0);

	/*
	 * Normal requests may initiate a reconnect,
	 * and/or wait for state changes to finish.
	 * Some requests set the NORECONNECT flag
	 * to avoid all that (i.e. tree discon)
	 */
	if (rqp->sr_flags & SMBR_NORECONNECT) {
		if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
			SMBSDEBUG("bad vc_state=%d\n", vcp->vc_state);
			return (ENOTCONN);
		}
		if (ssp != NULL &&
		    ((ssp->ss_flags & SMBS_CONNECTED) == 0))
			return (ENOTCONN);
		goto ok_out;
	}

	/*
	 * If we're not connected, initiate a reconnect
	 * and/or wait for an existing one to finish.
	 */
	if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		error = smb_iod_reconnect(vcp);
		if (error != 0)
			return (error);
	}

	/*
	 * If this request has a "share" object
	 * that needs a tree connect, do it now.
	 */
	if (ssp != NULL && (ssp->ss_flags & SMBS_CONNECTED) == 0) {
		error = smb_share_tcon(ssp, rqp->sr_cred);
		if (error)
			return (error);
	}

	/*
	 * We now know what UID + TID to use.
	 * Store them in the request.
	 */
ok_out:
	rqp->sr2_rqsessionid = vcp->vc2_session_id;
	rqp->sr2_rqtreeid = ssp ? ssp->ss2_tree_id : SMB2_TID_UNKNOWN;
	error = smb2_iod_addrq(rqp);

	return (error);
}

/*
 * Used by the IOD thread during connection setup,
 * and for smb2_echo after network timeouts.  Note that
 * unlike smb2_rq_simple, callers must check sr_error.
 */
int
smb2_rq_internal(struct smb_rq *rqp, int timeout)
{
	struct smb_vc *vcp = rqp->sr_vc;
	int error;

	ASSERT((vcp->vc_flags & SMBV_SMB2) != 0);

	rqp->sr_flags &= ~SMBR_RESTART;
	rqp->sr_timo = timeout;	/* in seconds */
	rqp->sr_state = SMBRQ_NOTSENT;

	/*
	 * In-line smb2_rq_enqueue(rqp) here, as we don't want it
	 * trying to reconnect etc. for an internal request.
	 */
	rqp->sr2_rqsessionid = vcp->vc2_session_id;
	rqp->sr2_rqtreeid = SMB2_TID_UNKNOWN;
	rqp->sr_flags |= SMBR_INTERNAL;
	error = smb2_iod_addrq(rqp);
	if (error != 0)
		return (error);

	/*
	 * In-line a variant of smb2_rq_reply(rqp) here as we may
	 * need to do custom parsing for SMB1-to-SMB2 negotiate.
	 */
	if (rqp->sr_timo == SMBNOREPLYWAIT) {
		smb_iod_removerq(rqp);
		return (0);
	}

	error = smb_iod_waitrq_int(rqp);
	if (error)
		return (error);

	/*
	 * If the request was signed (and reply not encrypted)
	 * validate the signature on the response.
	 */
	if ((rqp->sr2_rqflags & SMB2_FLAGS_SIGNED) != 0 &&
	    (rqp->sr_flags & SMBR_ENCRYPTED) == 0) {
		error = smb2_rq_verify(rqp);
		if (error)
			return (error);
	}

	/*
	 * Parse the SMB2 header.
	 */
	error = smb2_rq_parsehdr(rqp);

	/*
	 * Skip the error translation smb2_rq_reply does.
	 * Callers of this expect "raw" NT status.
	 */

	return (error);
}

/*
 * Wait for a reply to this request, then parse it.
 */
static int
smb2_rq_reply(struct smb_rq *rqp)
{
	int error;

	if (rqp->sr_timo == SMBNOREPLYWAIT) {
		smb_iod_removerq(rqp);
		return (0);
	}

	error = smb_iod_waitrq(rqp);
	if (error)
		return (error);

	/*
	 * If the request was signed (and reply not encrypted)
	 * validate the signature on the response.
	 */
	if ((rqp->sr2_rqflags & SMB2_FLAGS_SIGNED) != 0 &&
	    (rqp->sr_flags & SMBR_ENCRYPTED) == 0) {
		error = smb2_rq_verify(rqp);
		if (error)
			return (error);
	}

	/*
	 * Parse the SMB2 header
	 */
	error = smb2_rq_parsehdr(rqp);
	if (error != 0)
		return (error);

	if (rqp->sr_error != 0) {
		error = smb_maperr32(rqp->sr_error);
	}

	if (error != 0) {
		/*
		 * Do a special check for STATUS_BUFFER_OVERFLOW;
		 * it's not an error.
		 */
		if (rqp->sr_error == NT_STATUS_BUFFER_OVERFLOW) {
			/*
			 * Don't report it as an error to our caller;
			 * they can look at rqp->sr_error if they
			 * need to know whether we got a
			 * STATUS_BUFFER_OVERFLOW.
			 */
			rqp->sr_flags |= SMBR_MOREDATA;
			error = 0;
		}
	} else {
		rqp->sr_flags &= ~SMBR_MOREDATA;
	}

	return (error);
}

/*
 * Parse the SMB 2+ Header
 */
int
smb2_rq_parsehdr(struct smb_rq *rqp)
{
	struct mdchain *mdp = &rqp->sr_rp;
	uint32_t protocol_id;
	uint16_t length = 0;
	uint16_t credit_charge;
	uint16_t command;
	uint64_t message_id = 0;
	int error = 0;

	/* Get Protocol ID */
	md_get_uint32le(mdp, &protocol_id);

	/* Get/Check structure size is 64 */
	md_get_uint16le(mdp, &length);
	if (length != 64)
		return (EBADRPC);

	md_get_uint16le(mdp, &credit_charge);
	md_get_uint32le(mdp, &rqp->sr_error);
	md_get_uint16le(mdp, &command);
	md_get_uint16le(mdp, &rqp->sr2_rspcreditsgranted);
	md_get_uint32le(mdp, &rqp->sr2_rspflags);
	md_get_uint32le(mdp, &rqp->sr2_rspnextcmd);
	md_get_uint64le(mdp, &message_id);

	if ((rqp->sr2_rspflags & SMB2_FLAGS_ASYNC_COMMAND) == 0) {
		/*
		 * Sync Header
		 */

		/* Get Process ID */
		md_get_uint32le(mdp, &rqp->sr2_rsppid);

		/* Get Tree ID */
		md_get_uint32le(mdp, &rqp->sr2_rsptreeid);
	} else {
		/*
		 * Async Header
		 */

		/* Get Async ID */
		md_get_uint64le(mdp, &rqp->sr2_rspasyncid);
	}

	/* Get Session ID */
	error = md_get_uint64le(mdp, &rqp->sr2_rspsessionid);
	if (error)
		return (error);

	/* Skip MAC Signature */
	error = md_get_mem(mdp, NULL, 16, MB_MSYSTEM);

	return (error);
}
