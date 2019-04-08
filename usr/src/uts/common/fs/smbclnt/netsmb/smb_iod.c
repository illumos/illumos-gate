/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_iod.c,v 1.32 2005/02/12 00:17:09 lindak Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright (C) 2001 - 2013 Apple Inc. All rights reserved.
 * Copyright 2019 Nexenta Systems, Inc.  All rights reserved.
 */

#ifdef DEBUG
/* See sys/queue.h */
#define	QUEUEDEBUG 1
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/unistd.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/time.h>
#include <sys/class.h>
#include <sys/disp.h>
#include <sys/cmn_err.h>
#include <sys/zone.h>
#include <sys/sdt.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb2.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb2_rq.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>
#include <netsmb/smb_trantcp.h>

/*
 * SMB messages are up to 64K.  Let's leave room for two.
 * If we negotiate up to SMB2, increase these. XXX todo
 */
static int smb_tcpsndbuf = 0x20000;
static int smb_tcprcvbuf = 0x20000;
static int smb_connect_timeout = 10; /* seconds */

static int smb1_iod_process(smb_vc_t *, mblk_t *);
static int smb2_iod_process(smb_vc_t *, mblk_t *);
static int smb_iod_send_echo(smb_vc_t *, cred_t *cr);
static int smb_iod_logoff(struct smb_vc *vcp, cred_t *cr);

/*
 * This is set/cleared when smbfs loads/unloads
 * No locks should be necessary, because smbfs
 * can't unload until all the mounts are gone.
 */
static smb_fscb_t *fscb;
void
smb_fscb_set(smb_fscb_t *cb)
{
	fscb = cb;
}

static void
smb_iod_share_disconnected(smb_share_t *ssp)
{

	smb_share_invalidate(ssp);

	/*
	 * This is the only fscb hook smbfs currently uses.
	 * Replaces smbfs_dead() from Darwin.
	 */
	if (fscb && fscb->fscb_disconn) {
		fscb->fscb_disconn(ssp);
	}
}

/*
 * State changes are important and infrequent.
 * Make them easily observable via dtrace.
 */
void
smb_iod_newstate(struct smb_vc *vcp, int state)
{
	vcp->vc_state = state;
}

/* Lock Held version of the next function. */
static inline void
smb_iod_rqprocessed_LH(
	struct smb_rq *rqp,
	int error,
	int flags)
{
	rqp->sr_flags |= flags;
	rqp->sr_lerror = error;
	rqp->sr_rpgen++;
	rqp->sr_state = SMBRQ_NOTIFIED;
	cv_broadcast(&rqp->sr_cond);
}

static void
smb_iod_rqprocessed(
	struct smb_rq *rqp,
	int error,
	int flags)
{

	SMBRQ_LOCK(rqp);
	smb_iod_rqprocessed_LH(rqp, error, flags);
	SMBRQ_UNLOCK(rqp);
}

static void
smb_iod_invrq(struct smb_vc *vcp)
{
	struct smb_rq *rqp;

	/*
	 * Invalidate all outstanding requests for this connection
	 * Also wakeup iod_muxwant waiters.
	 */
	rw_enter(&vcp->iod_rqlock, RW_READER);
	TAILQ_FOREACH(rqp, &vcp->iod_rqlist, sr_link) {
		smb_iod_rqprocessed(rqp, ENOTCONN, SMBR_RESTART);
	}
	rw_exit(&vcp->iod_rqlock);
	cv_broadcast(&vcp->iod_muxwait);
}

/*
 * Called by smb_vc_rele/smb_vc_kill on last ref, and by
 * the driver close function if the IOD closes its minor.
 * In those cases, the caller should be the IOD thread.
 *
 * Forcibly kill the connection.
 */
void
smb_iod_disconnect(struct smb_vc *vcp)
{

	/*
	 * Inform everyone of the state change.
	 */
	SMB_VC_LOCK(vcp);
	if (vcp->vc_state != SMBIOD_ST_DEAD) {
		smb_iod_newstate(vcp, SMBIOD_ST_DEAD);
		cv_broadcast(&vcp->vc_statechg);
	}
	SMB_VC_UNLOCK(vcp);

	SMB_TRAN_DISCONNECT(vcp);
}

/*
 * Send one request.
 *
 * SMB1 only
 *
 * Called by _addrq (for internal requests)
 * and _sendall (via _addrq, _multirq, _waitrq)
 * Errors are reported via the smb_rq, using:
 *   smb_iod_rqprocessed(rqp, ...)
 */
static void
smb1_iod_sendrq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *m;
	int error;

	ASSERT(vcp);
	ASSERT(RW_WRITE_HELD(&vcp->iod_rqlock));
	ASSERT((vcp->vc_flags & SMBV_SMB2) == 0);

	/*
	 * Internal requests are allowed in any state;
	 * otherwise should be active.
	 */
	if ((rqp->sr_flags & SMBR_INTERNAL) == 0 &&
	    vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
		smb_iod_rqprocessed(rqp, ENOTCONN, SMBR_RESTART);
		return;
	}

	/*
	 * Overwrite the SMB header with the assigned MID and
	 * (if we're signing) sign it.
	 */
	smb_rq_fillhdr(rqp);
	if (rqp->sr_rqflags2 & SMB_FLAGS2_SECURITY_SIGNATURE) {
		smb_rq_sign(rqp);
	}

	/*
	 * The transport send consumes the message and we'd
	 * prefer to keep a copy, so dupmsg() before sending.
	 */
	m = dupmsg(rqp->sr_rq.mb_top);
	if (m == NULL) {
		error = ENOBUFS;
		goto fatal;
	}

#ifdef DTRACE_PROBE2
	DTRACE_PROBE2(iod_sendrq,
	    (smb_rq_t *), rqp, (mblk_t *), m);
#endif

	error = SMB_TRAN_SEND(vcp, m);
	m = 0; /* consumed by SEND */

	rqp->sr_lerror = error;
	if (error == 0) {
		SMBRQ_LOCK(rqp);
		rqp->sr_flags |= SMBR_SENT;
		rqp->sr_state = SMBRQ_SENT;
		SMBRQ_UNLOCK(rqp);
		return;
	}
	/*
	 * Transport send returned an error.
	 * Was it a fatal one?
	 */
	if (SMB_TRAN_FATAL(vcp, error)) {
		/*
		 * No further attempts should be made
		 */
	fatal:
		SMBSDEBUG("TRAN_SEND returned fatal error %d\n", error);
		smb_iod_rqprocessed(rqp, error, SMBR_RESTART);
		return;
	}
}

/*
 * Send one request.
 *
 * SMB2 only
 *
 * Called by _addrq (for internal requests)
 * and _sendall (via _addrq, _multirq, _waitrq)
 * Errors are reported via the smb_rq, using:
 *   smb_iod_rqprocessed(rqp, ...)
 */
static void
smb2_iod_sendrq(struct smb_rq *rqp)
{
	struct smb_rq *c_rqp;	/* compound */
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *top_m;
	mblk_t *cur_m;
	int error;

	ASSERT(vcp);
	ASSERT(RW_WRITE_HELD(&vcp->iod_rqlock));
	ASSERT((vcp->vc_flags & SMBV_SMB2) != 0);

	/*
	 * Internal requests are allowed in any state;
	 * otherwise should be active.
	 */
	if ((rqp->sr_flags & SMBR_INTERNAL) == 0 &&
	    vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
		smb_iod_rqprocessed(rqp, ENOTCONN, SMBR_RESTART);
		return;
	}

	/*
	 * Overwrite the SMB header with the assigned MID and
	 * (if we're signing) sign it.  If there are compounded
	 * requests after the top one, do those too.
	 */
	smb2_rq_fillhdr(rqp);
	if (rqp->sr2_rqflags & SMB2_FLAGS_SIGNED) {
		smb2_rq_sign(rqp);
	}
	c_rqp = rqp->sr2_compound_next;
	while (c_rqp != NULL) {
		smb2_rq_fillhdr(c_rqp);
		if (c_rqp->sr2_rqflags & SMB2_FLAGS_SIGNED) {
			smb2_rq_sign(c_rqp);
		}
		c_rqp = c_rqp->sr2_compound_next;
	}

	/*
	 * The transport send consumes the message and we'd
	 * prefer to keep a copy, so dupmsg() before sending.
	 * We also need this to build the compound message
	 * that we'll actually send.  The message offset at
	 * the start of each compounded message should be
	 * eight-byte aligned.  The caller preparing the
	 * compounded request has to take care of that
	 * before we get here and sign messages etc.
	 */
	top_m = dupmsg(rqp->sr_rq.mb_top);
	if (top_m == NULL) {
		error = ENOBUFS;
		goto fatal;
	}
	c_rqp = rqp->sr2_compound_next;
	while (c_rqp != NULL) {
		size_t len = msgdsize(top_m);
		ASSERT((len & 7) == 0);
		cur_m = dupmsg(c_rqp->sr_rq.mb_top);
		if (cur_m == NULL) {
			freemsg(top_m);
			error = ENOBUFS;
			goto fatal;
		}
		linkb(top_m, cur_m);
	}

	DTRACE_PROBE2(iod_sendrq,
	    (smb_rq_t *), rqp, (mblk_t *), top_m);

	error = SMB_TRAN_SEND(vcp, top_m);
	top_m = 0; /* consumed by SEND */

	rqp->sr_lerror = error;
	if (error == 0) {
		SMBRQ_LOCK(rqp);
		rqp->sr_flags |= SMBR_SENT;
		rqp->sr_state = SMBRQ_SENT;
		SMBRQ_UNLOCK(rqp);
		return;
	}
	/*
	 * Transport send returned an error.
	 * Was it a fatal one?
	 */
	if (SMB_TRAN_FATAL(vcp, error)) {
		/*
		 * No further attempts should be made
		 */
	fatal:
		SMBSDEBUG("TRAN_SEND returned fatal error %d\n", error);
		smb_iod_rqprocessed(rqp, error, SMBR_RESTART);
		return;
	}
}

/*
 * Receive one NetBIOS (or NBT over TCP) message.  If none have arrived,
 * wait up to SMB_NBTIMO (15 sec.) for one to arrive, and then if still
 * none have arrived, return ETIME.
 */
static int
smb_iod_recvmsg(struct smb_vc *vcp, mblk_t **mpp)
{
	mblk_t *m;
	int error;

top:
	m = NULL;
	error = SMB_TRAN_RECV(vcp, &m);
	if (error == EAGAIN)
		goto top;
	if (error)
		return (error);
	ASSERT(m != NULL);

	m = m_pullup(m, 4);
	if (m == NULL) {
		return (ENOSR);
	}

	*mpp = m;
	return (0);
}

/*
 * How long should we keep around an unused VC (connection)?
 * There's usually a good chance connections will be reused,
 * so the default is to keep such connections for 5 min.
 */
#ifdef	DEBUG
int smb_iod_idle_keep_time = 60;	/* seconds */
#else
int smb_iod_idle_keep_time = 300;	/* seconds */
#endif

/*
 * Process incoming packets
 *
 * This is the "reader" loop, run by the IOD thread.  Normally we're in
 * state SMBIOD_ST_VCACTIVE here, but during reconnect we're called in
 * other states with poll==TRUE
 *
 * A non-zero error return here causes the IOD work loop to terminate.
 */
int
smb_iod_recvall(struct smb_vc *vcp, boolean_t poll)
{
	mblk_t *m;
	int error = 0;
	int etime_idle = 0;	/* How many 15 sec. "ticks" idle. */
	int etime_count = 0;	/* ... and when we have requests. */

	for (;;) {
		/*
		 * Check whether someone "killed" this VC,
		 * or is asking the IOD to terminate.
		 */
		if (vcp->iod_flags & SMBIOD_SHUTDOWN) {
			SMBIODEBUG("SHUTDOWN set\n");
			/* This IOD thread will terminate. */
			SMB_VC_LOCK(vcp);
			smb_iod_newstate(vcp, SMBIOD_ST_DEAD);
			cv_broadcast(&vcp->vc_statechg);
			SMB_VC_UNLOCK(vcp);
			error = EINTR;
			break;
		}

		m = NULL;
		error = smb_iod_recvmsg(vcp, &m);

		/*
		 * Internal requests (reconnecting) call this in a loop
		 * (with poll==TRUE) until the request completes.
		 */
		if (error == ETIME && poll)
			break;

		if (error == ETIME &&
		    vcp->iod_rqlist.tqh_first != NULL) {

			/*
			 * Nothing received and requests waiting.
			 * Increment etime_count.  If we were idle,
			 * skip the 1st tick, because we started
			 * waiting before there were any requests.
			 */
			if (etime_idle != 0) {
				etime_idle = 0;
			} else if (etime_count < INT16_MAX) {
				etime_count++;
			}

			/*
			 * ETIME and requests in the queue.
			 * The first time (at 15 sec.)
			 * Log an error (just once).
			 */
			if (etime_count > 0 &&
			    vcp->iod_noresp == B_FALSE) {
				vcp->iod_noresp = B_TRUE;
				zprintf(vcp->vc_zoneid,
				    "SMB server %s not responding\n",
				    vcp->vc_srvname);
			}
			/*
			 * At 30 sec. try sending an echo, which
			 * should cause some response.
			 */
			if (etime_count == 2) {
				SMBIODEBUG("send echo\n");
				(void) smb_iod_send_echo(vcp, CRED());
			}
			/*
			 * At 45 sec. give up on the connection
			 * and try to reconnect.
			 */
			if (etime_count == 3) {
				SMB_VC_LOCK(vcp);
				smb_iod_newstate(vcp, SMBIOD_ST_RECONNECT);
				SMB_VC_UNLOCK(vcp);
				SMB_TRAN_DISCONNECT(vcp);
				break;
			}
			continue;
		} /* ETIME and requests in the queue */

		if (error == ETIME) {
			/*
			 * Nothing received and no active requests.
			 *
			 * If we've received nothing from the server for
			 * smb_iod_idle_keep_time seconds, and the IOD
			 * thread holds the last reference to this VC,
			 * move to state IDLE and drop the TCP session.
			 * The IDLE handler will destroy the VC unless
			 * vc_state goes to RECONNECT before then.
			 */
			etime_count = 0;
			if (etime_idle < INT16_MAX)
				etime_idle++;
			if ((etime_idle * SMB_NBTIMO) <
			    smb_iod_idle_keep_time)
				continue;
			SMB_VC_LOCK(vcp);
			if (vcp->vc_co.co_usecount == 1) {
				smb_iod_newstate(vcp, SMBIOD_ST_IDLE);
				SMB_VC_UNLOCK(vcp);
				SMBIODEBUG("logoff & disconnect\n");
				(void) smb_iod_logoff(vcp, CRED());
				SMB_TRAN_DISCONNECT(vcp);
				error = 0;
				break;
			}
			SMB_VC_UNLOCK(vcp);
			continue;
		} /* error == ETIME */

		if (error) {
			/*
			 * The recv above returned an error indicating
			 * that our TCP session is no longer usable.
			 * Disconnect the session and get ready to
			 * reconnect.  If we have pending requests,
			 * move to state reconnect immediately;
			 * otherwise move to state IDLE until a
			 * request is issued on this VC.
			 */
			SMB_VC_LOCK(vcp);
			if (vcp->iod_rqlist.tqh_first != NULL)
				smb_iod_newstate(vcp, SMBIOD_ST_RECONNECT);
			else
				smb_iod_newstate(vcp, SMBIOD_ST_IDLE);
			cv_broadcast(&vcp->vc_statechg);
			SMB_VC_UNLOCK(vcp);
			SMB_TRAN_DISCONNECT(vcp);
			break;
		}

		/*
		 * Received something.  Yea!
		 */
		etime_count = 0;
		etime_idle = 0;

		/*
		 * If we just completed a reconnect after logging
		 * "SMB server %s not responding" then log OK now.
		 */
		if (vcp->iod_noresp) {
			vcp->iod_noresp = B_FALSE;
			zprintf(vcp->vc_zoneid, "SMB server %s OK\n",
			    vcp->vc_srvname);
		}

		if ((vcp->vc_flags & SMBV_SMB2) != 0) {
			error = smb2_iod_process(vcp, m);
		} else {
			error = smb1_iod_process(vcp, m);
		}

		/*
		 * Reconnect calls this in a loop with poll=TRUE
		 * We've received a response, so break now.
		 */
		if (poll) {
			error = 0;
			break;
		}
	}

	return (error);
}

/*
 * Have what should be an SMB1 reply.  Check and parse the header,
 * then use the message ID to find the request this belongs to and
 * post it on that request.
 *
 * Returns an error if the reader should give up.
 * To be safe, error if we read garbage.
 */
static int
smb1_iod_process(smb_vc_t *vcp, mblk_t *m)
{
	struct mdchain md;
	struct smb_rq *rqp;
	uint8_t cmd, sig[4];
	uint16_t mid;
	int err, skip;

	m = m_pullup(m, SMB_HDRLEN);
	if (m == NULL)
		return (ENOMEM);

	/*
	 * Note: Intentionally do NOT md_done(&md)
	 * because that would free the message and
	 * we just want to peek here.
	 */
	md_initm(&md, m);

	/*
	 * Check the SMB header version and get the MID.
	 *
	 * The header version should be SMB1 except when we're
	 * doing SMB1-to-SMB2 negotiation, in which case we may
	 * see an SMB2 header with message ID=0 (only allowed in
	 * vc_state == SMBIOD_ST_CONNECTED -- negotiationg).
	 */
	err = md_get_mem(&md, sig, 4, MB_MSYSTEM);
	if (err)
		return (err);
	if (sig[1] != 'S' || sig[2] != 'M' || sig[3] != 'B') {
		goto bad_hdr;
	}
	switch (sig[0]) {
	case SMB_HDR_V1:	/* SMB1 */
		md_get_uint8(&md, &cmd);
		/* Skip to and get the MID. At offset 5 now. */
		skip = SMB_HDR_OFF_MID - 5;
		md_get_mem(&md, NULL, skip, MB_MSYSTEM);
		err = md_get_uint16le(&md, &mid);
		if (err)
			return (err);
		break;
	case SMB_HDR_V2:	/* SMB2+ */
		if (vcp->vc_state == SMBIOD_ST_CONNECTED) {
			/*
			 * No need to look, can only be
			 * MID=0, cmd=negotiate
			 */
			cmd = SMB_COM_NEGOTIATE;
			mid = 0;
			break;
		}
		/* FALLTHROUGH */
	bad_hdr:
	default:
		SMBIODEBUG("Bad SMB hdr\n");
		m_freem(m);
		return (EPROTO);
	}

	/*
	 * Find the reqeuest and post the reply
	 */
	rw_enter(&vcp->iod_rqlock, RW_READER);
	TAILQ_FOREACH(rqp, &vcp->iod_rqlist, sr_link) {

		if (rqp->sr_mid != mid)
			continue;

		DTRACE_PROBE2(iod_post_reply,
		    (smb_rq_t *), rqp, (mblk_t *), m);
		m_dumpm(m);

		SMBRQ_LOCK(rqp);
		if (rqp->sr_rp.md_top == NULL) {
			md_initm(&rqp->sr_rp, m);
		} else {
			if (rqp->sr_flags & SMBR_MULTIPACKET) {
				md_append_record(&rqp->sr_rp, m);
			} else {
				SMBRQ_UNLOCK(rqp);
				rqp = NULL;
				break;
			}
		}
		smb_iod_rqprocessed_LH(rqp, 0, 0);
		SMBRQ_UNLOCK(rqp);
		break;
	}
	rw_exit(&vcp->iod_rqlock);

	if (rqp == NULL) {
		if (cmd != SMB_COM_ECHO) {
			SMBSDEBUG("drop resp: MID 0x%04x\n", (uint_t)mid);
		}
		m_freem(m);
		/*
		 * Keep going.  It's possible this reply came
		 * after the request timed out and went away.
		 */
	}
	return (0);
}

/*
 * Have what should be an SMB2 reply.  Check and parse the header,
 * then use the message ID to find the request this belongs to and
 * post it on that request.
 *
 * We also want to apply any credit grant in this reply now,
 * rather than waiting for the owner to wake up.
 */
static int
smb2_iod_process(smb_vc_t *vcp, mblk_t *m)
{
	struct mdchain md;
	struct smb_rq *rqp;
	uint8_t sig[4];
	mblk_t *next_m = NULL;
	uint64_t message_id, async_id;
	uint32_t flags, next_cmd_off, status;
	uint16_t command, credits_granted;
	int err;

top:
	m = m_pullup(m, SMB2_HDRLEN);
	if (m == NULL)
		return (ENOMEM);

	/*
	 * Note: Intentionally do NOT md_done(&md)
	 * because that would free the message and
	 * we just want to peek here.
	 */
	md_initm(&md, m);

	/*
	 * Check the SMB header.  Must be SMB2
	 * (and later, could be SMB3 encrypted)
	 */
	err = md_get_mem(&md, sig, 4, MB_MSYSTEM);
	if (err)
		return (err);
	if (sig[1] != 'S' || sig[2] != 'M' || sig[3] != 'B') {
		goto bad_hdr;
	}
	switch (sig[0]) {
	case SMB_HDR_V2:
		break;
	case SMB_HDR_V3E:
		/*
		 * Todo: If encryption enabled, decrypt the message
		 * and restart processing on the cleartext.
		 */
		/* FALLTHROUGH */
	bad_hdr:
	default:
		SMBIODEBUG("Bad SMB2 hdr\n");
		m_freem(m);
		return (EPROTO);
	}

	/*
	 * Parse the rest of the SMB2 header,
	 * skipping what we don't need.
	 */
	md_get_uint32le(&md, NULL);	/* length, credit_charge */
	md_get_uint32le(&md, &status);
	md_get_uint16le(&md, &command);
	md_get_uint16le(&md, &credits_granted);
	md_get_uint32le(&md, &flags);
	md_get_uint32le(&md, &next_cmd_off);
	md_get_uint64le(&md, &message_id);
	if (flags & SMB2_FLAGS_ASYNC_COMMAND) {
		md_get_uint64le(&md, &async_id);
	} else {
		/* PID, TID (not needed) */
		async_id = 0;
	}

	/*
	 * If this is a compound reply, split it.
	 * Next must be 8-byte aligned.
	 */
	if (next_cmd_off != 0) {
		if ((next_cmd_off & 7) != 0)
			SMBIODEBUG("Misaligned next cmd\n");
		else
			next_m = m_split(m, next_cmd_off, 1);
	}

	/*
	 * SMB2 Negotiate may return zero credits_granted,
	 * in which case we should assume it granted one.
	 */
	if (command == SMB2_NEGOTIATE && credits_granted == 0)
		credits_granted = 1;

	/*
	 * Apply the credit grant
	 */
	rw_enter(&vcp->iod_rqlock, RW_WRITER);
	vcp->vc2_limit_message_id += credits_granted;

	/*
	 * Find the reqeuest and post the reply
	 */
	rw_downgrade(&vcp->iod_rqlock);
	TAILQ_FOREACH(rqp, &vcp->iod_rqlist, sr_link) {

		if (rqp->sr2_messageid != message_id)
			continue;

		DTRACE_PROBE2(iod_post_reply,
		    (smb_rq_t *), rqp, (mblk_t *), m);
		m_dumpm(m);

		/*
		 * If this is an interim response, just save the
		 * async ID but don't wakup the request.
		 * Don't need SMBRQ_LOCK for this.
		 */
		if (status == NT_STATUS_PENDING && async_id != 0) {
			rqp->sr2_rspasyncid = async_id;
			m_freem(m);
			break;
		}

		SMBRQ_LOCK(rqp);
		if (rqp->sr_rp.md_top == NULL) {
			md_initm(&rqp->sr_rp, m);
		} else {
			SMBRQ_UNLOCK(rqp);
			rqp = NULL;
			break;
		}
		smb_iod_rqprocessed_LH(rqp, 0, 0);
		SMBRQ_UNLOCK(rqp);
		break;
	}
	rw_exit(&vcp->iod_rqlock);

	if (rqp == NULL) {
		if (command != SMB2_ECHO) {
			SMBSDEBUG("drop resp: MID %lld\n",
			    (long long)message_id);
		}
		m_freem(m);
		/*
		 * Keep going.  It's possible this reply came
		 * after the request timed out and went away.
		 */
	}

	/*
	 * If we split a compound reply, continue with the
	 * next part of the compound.
	 */
	if (next_m != NULL) {
		m = next_m;
		goto top;
	}

	return (0);
}

/*
 * The IOD receiver thread has requests pending and
 * has not received anything in a while.  Try to
 * send an SMB echo request.  It's tricky to do a
 * send from the IOD thread because we can't block.
 *
 * Using tmo=SMBNOREPLYWAIT in the request
 * so smb_rq_reply will skip smb_iod_waitrq.
 * The smb_smb_echo call uses SMBR_INTERNAL
 * to avoid calling smb_iod_sendall().
 */
static int
smb_iod_send_echo(smb_vc_t *vcp, cred_t *cr)
{
	smb_cred_t scred;
	int err, tmo = SMBNOREPLYWAIT;

	ASSERT(vcp->iod_thr == curthread);

	smb_credinit(&scred, cr);
	if ((vcp->vc_flags & SMBV_SMB2) != 0) {
		err = smb2_smb_echo(vcp, &scred, tmo);
	} else {
		err = smb_smb_echo(vcp, &scred, tmo);
	}
	smb_credrele(&scred);
	return (err);
}

/*
 * Helper for smb1_iod_addrq, smb2_iod_addrq
 * Returns zero if interrupted, else 1.
 */
static int
smb_iod_muxwait(smb_vc_t *vcp, boolean_t sig_ok)
{
	int rc;

	SMB_VC_LOCK(vcp);
	vcp->iod_muxwant++;
	if (sig_ok) {
		rc = cv_wait_sig(&vcp->iod_muxwait, &vcp->vc_lock);
	} else {
		cv_wait(&vcp->iod_muxwait, &vcp->vc_lock);
		rc = 1;
	}
	vcp->iod_muxwant--;
	SMB_VC_UNLOCK(vcp);

	return (rc);
}

/*
 * Place request in the queue, and send it.
 * Called with no locks held.
 *
 * Called for SMB1 only
 *
 * The logic for how we limit active requests differs between
 * SMB1 and SMB2.  With SMB1 it's a simple counter ioc_muxcnt.
 */
int
smb1_iod_addrq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	uint16_t need;
	boolean_t sig_ok =
	    (rqp->sr_flags & SMBR_NOINTR_SEND) == 0;

	ASSERT(rqp->sr_cred);
	ASSERT((vcp->vc_flags & SMBV_SMB2) == 0);

	rqp->sr_owner = curthread;

	rw_enter(&vcp->iod_rqlock, RW_WRITER);

recheck:
	/*
	 * Internal requests can be added in any state,
	 * but normal requests only in state active.
	 */
	if ((rqp->sr_flags & SMBR_INTERNAL) == 0 &&
	    vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
		rw_exit(&vcp->iod_rqlock);
		return (ENOTCONN);
	}

	/*
	 * If we're at the limit of active requests, block until
	 * enough requests complete so we can make ours active.
	 * Wakeup in smb_iod_removerq().
	 *
	 * Normal callers leave one slot free, so internal
	 * callers can have the last slot if needed.
	 */
	need = 1;
	if ((rqp->sr_flags & SMBR_INTERNAL) == 0)
		need++;
	if ((vcp->iod_muxcnt + need) > vcp->vc_maxmux) {
		rw_exit(&vcp->iod_rqlock);
		if (rqp->sr_flags & SMBR_INTERNAL)
			return (EBUSY);
		if (smb_iod_muxwait(vcp, sig_ok) == 0)
			return (EINTR);
		rw_enter(&vcp->iod_rqlock, RW_WRITER);
		goto recheck;
	}

	/*
	 * Add this request to the active list and send it.
	 * For SMB2 we may have a sequence of compounded
	 * requests, in which case we must add them all.
	 * They're sent as a compound in smb2_iod_sendrq.
	 */
	rqp->sr_mid = vcp->vc_next_mid++;
	/* If signing, set the signing sequence numbers. */
	if (vcp->vc_mackey != NULL && (rqp->sr_rqflags2 &
	    SMB_FLAGS2_SECURITY_SIGNATURE) != 0) {
		rqp->sr_seqno = vcp->vc_next_seq++;
		rqp->sr_rseqno = vcp->vc_next_seq++;
	}
	vcp->iod_muxcnt++;
	TAILQ_INSERT_TAIL(&vcp->iod_rqlist, rqp, sr_link);
	smb1_iod_sendrq(rqp);

	rw_exit(&vcp->iod_rqlock);
	return (0);
}

/*
 * Place request in the queue, and send it.
 * Called with no locks held.
 *
 * Called for SMB2 only.
 *
 * With SMB2 we have a range of valid message IDs, and we may
 * only send requests when we can assign a message ID within
 * the valid range.  We may need to wait here for some active
 * request to finish (and update vc2_limit_message_id) before
 * we can get message IDs for our new request(s).  Another
 * difference is that the request sequence we're waiting to
 * add here may require multipe message IDs, either due to
 * either compounding or multi-credit requests.  Therefore
 * we need to wait for the availibility of how ever many
 * message IDs are required by our request sequence.
 */
int
smb2_iod_addrq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	struct smb_rq *c_rqp;	/* compound req */
	uint16_t charge;
	boolean_t sig_ok =
	    (rqp->sr_flags & SMBR_NOINTR_SEND) == 0;

	ASSERT(rqp->sr_cred != NULL);
	ASSERT((vcp->vc_flags & SMBV_SMB2) != 0);

	/*
	 * Figure out the credit charges
	 * No multi-credit messages yet.
	 */
	rqp->sr2_totalcreditcharge = rqp->sr2_creditcharge;
	c_rqp = rqp->sr2_compound_next;
	while (c_rqp != NULL) {
		rqp->sr2_totalcreditcharge += c_rqp->sr2_creditcharge;
		c_rqp = c_rqp->sr2_compound_next;
	}

	/*
	 * Internal request must not be compounded
	 * and should use exactly one credit.
	 */
	if (rqp->sr_flags & SMBR_INTERNAL) {
		if (rqp->sr2_compound_next != NULL) {
			ASSERT(0);
			return (EINVAL);
		}
	}

	rqp->sr_owner = curthread;

	rw_enter(&vcp->iod_rqlock, RW_WRITER);

recheck:
	/*
	 * Internal requests can be added in any state,
	 * but normal requests only in state active.
	 */
	if ((rqp->sr_flags & SMBR_INTERNAL) == 0 &&
	    vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
		rw_exit(&vcp->iod_rqlock);
		return (ENOTCONN);
	}

	/*
	 * If we're at the limit of active requests, block until
	 * enough requests complete so we can make ours active.
	 * Wakeup in smb_iod_removerq().
	 *
	 * Normal callers leave one slot free, so internal
	 * callers can have the last slot if needed.
	 */
	charge = rqp->sr2_totalcreditcharge;
	if ((rqp->sr_flags & SMBR_INTERNAL) == 0)
		charge++;
	if ((vcp->vc2_next_message_id + charge) >
	    vcp->vc2_limit_message_id) {
		rw_exit(&vcp->iod_rqlock);
		if (rqp->sr_flags & SMBR_INTERNAL)
			return (EBUSY);
		if (smb_iod_muxwait(vcp, sig_ok) == 0)
			return (EINTR);
		rw_enter(&vcp->iod_rqlock, RW_WRITER);
		goto recheck;
	}

	/*
	 * Add this request to the active list and send it.
	 * For SMB2 we may have a sequence of compounded
	 * requests, in which case we must add them all.
	 * They're sent as a compound in smb2_iod_sendrq.
	 */

	rqp->sr2_messageid = vcp->vc2_next_message_id;
	vcp->vc2_next_message_id += rqp->sr2_creditcharge;
	TAILQ_INSERT_TAIL(&vcp->iod_rqlist, rqp, sr_link);

	c_rqp = rqp->sr2_compound_next;
	while (c_rqp != NULL) {
		c_rqp->sr2_messageid = vcp->vc2_next_message_id;
		vcp->vc2_next_message_id += c_rqp->sr2_creditcharge;
		TAILQ_INSERT_TAIL(&vcp->iod_rqlist, c_rqp, sr_link);
		c_rqp = c_rqp->sr2_compound_next;
	}
	smb2_iod_sendrq(rqp);

	rw_exit(&vcp->iod_rqlock);
	return (0);
}

/*
 * Mark an SMBR_MULTIPACKET request as
 * needing another send.  Similar to the
 * "normal" part of smb1_iod_addrq.
 * Only used by SMB1
 */
int
smb1_iod_multirq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;

	ASSERT(rqp->sr_flags & SMBR_MULTIPACKET);

	if (vcp->vc_flags & SMBV_SMB2) {
		ASSERT("!SMB2?");
		return (EINVAL);
	}

	if (rqp->sr_flags & SMBR_INTERNAL)
		return (EINVAL);

	if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
		return (ENOTCONN);
	}

	rw_enter(&vcp->iod_rqlock, RW_WRITER);

	/* Already on iod_rqlist, just reset state. */
	rqp->sr_state = SMBRQ_NOTSENT;
	smb1_iod_sendrq(rqp);

	rw_exit(&vcp->iod_rqlock);

	return (0);
}

/*
 * Remove a request from the active list, and
 * wake up requests waiting to go active.
 *
 * Shared by SMB1 + SMB2
 *
 * The logic for how we limit active requests differs between
 * SMB1 and SMB2.  With SMB1 it's a simple counter ioc_muxcnt.
 * With SMB2 we have a range of valid message IDs, and when we
 * retire the oldest request we need to keep track of what is
 * now the oldest message ID.  In both cases, after we take a
 * request out of the list here, we should be able to wake up
 * a request waiting to get in the active list.
 */
void
smb_iod_removerq(struct smb_rq *rqp)
{
	struct smb_rq *rqp2;
	struct smb_vc *vcp = rqp->sr_vc;
	boolean_t was_head = B_FALSE;

	rw_enter(&vcp->iod_rqlock, RW_WRITER);

#ifdef QUEUEDEBUG
	/*
	 * Make sure we have not already removed it.
	 * See sys/queue.h QUEUEDEBUG_TAILQ_POSTREMOVE
	 * XXX: Don't like the constant 1 here...
	 */
	ASSERT(rqp->sr_link.tqe_next != (void *)1L);
#endif

	if (TAILQ_FIRST(&vcp->iod_rqlist) == rqp)
		was_head = B_TRUE;
	TAILQ_REMOVE(&vcp->iod_rqlist, rqp, sr_link);
	if (vcp->vc_flags & SMBV_SMB2) {
		rqp2 = TAILQ_FIRST(&vcp->iod_rqlist);
		if (was_head && rqp2 != NULL) {
			/* Do we still need this? */
			vcp->vc2_oldest_message_id =
			    rqp2->sr2_messageid;
		}
	} else {
		ASSERT(vcp->iod_muxcnt > 0);
		vcp->iod_muxcnt--;
	}

	rw_exit(&vcp->iod_rqlock);

	/*
	 * If there are requests waiting for "mux" slots,
	 * wake one.
	 */
	SMB_VC_LOCK(vcp);
	if (vcp->iod_muxwant != 0)
		cv_signal(&vcp->iod_muxwait);
	SMB_VC_UNLOCK(vcp);
}

/*
 * Wait for a request to complete.
 */
int
smb_iod_waitrq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	clock_t tr, tmo1, tmo2;
	int error;

	if (rqp->sr_flags & SMBR_INTERNAL) {
		/* XXX - Do we ever take this path now? */
		return (smb_iod_waitrq_int(rqp));
	}

	/*
	 * Make sure this is NOT the IOD thread,
	 * or the wait below will stop the reader.
	 */
	ASSERT(curthread != vcp->iod_thr);

	SMBRQ_LOCK(rqp);

	/*
	 * The request has been sent.  Now wait for the response,
	 * with the timeout specified for this request.
	 * Compute all the deadlines now, so we effectively
	 * start the timer(s) after the request is sent.
	 */
	if (smb_timo_notice && (smb_timo_notice < rqp->sr_timo))
		tmo1 = SEC_TO_TICK(smb_timo_notice);
	else
		tmo1 = 0;
	tmo2 = ddi_get_lbolt() + SEC_TO_TICK(rqp->sr_timo);

	/*
	 * As above, we don't want to allow interrupt for some
	 * requests like open, because we could miss a succesful
	 * response and therefore "leak" a FID.  Such requests
	 * are marked SMBR_NOINTR_RECV to prevent that.
	 *
	 * If "slow server" warnings are enabled, wait first
	 * for the "notice" timeout, and warn if expired.
	 */
	if (tmo1 && rqp->sr_rpgen == rqp->sr_rplast) {
		if (rqp->sr_flags & SMBR_NOINTR_RECV)
			tr = cv_reltimedwait(&rqp->sr_cond,
			    &rqp->sr_lock, tmo1, TR_CLOCK_TICK);
		else
			tr = cv_reltimedwait_sig(&rqp->sr_cond,
			    &rqp->sr_lock, tmo1, TR_CLOCK_TICK);
		if (tr == 0) {
			error = EINTR;
			goto out;
		}
		if (tr < 0) {
			DTRACE_PROBE1(smb_iod_waitrq1,
			    (smb_rq_t *), rqp);
		}
	}

	/*
	 * Keep waiting until tmo2 is expired.
	 */
	while (rqp->sr_rpgen == rqp->sr_rplast) {
		if (rqp->sr_flags & SMBR_NOINTR_RECV)
			tr = cv_timedwait(&rqp->sr_cond,
			    &rqp->sr_lock, tmo2);
		else
			tr = cv_timedwait_sig(&rqp->sr_cond,
			    &rqp->sr_lock, tmo2);
		if (tr == 0) {
			error = EINTR;
			goto out;
		}
		if (tr < 0) {
			DTRACE_PROBE1(smb_iod_waitrq2,
			    (smb_rq_t *), rqp);
			error = ETIME;
			goto out;
		}
		/* got wakeup */
	}
	error = rqp->sr_lerror;
	rqp->sr_rplast++;

out:
	SMBRQ_UNLOCK(rqp);

	/*
	 * MULTIPACKET request must stay in the list.
	 * They may need additional responses.
	 */
	if ((rqp->sr_flags & SMBR_MULTIPACKET) == 0)
		smb_iod_removerq(rqp);

	return (error);
}

/*
 * Internal variant of smb_iod_waitrq(), for use in
 * requests run by the IOD (reader) thread itself.
 * Block only long enough to receive one reply.
 */
int
smb_iod_waitrq_int(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	int timeleft = rqp->sr_timo;
	int error;

	ASSERT((rqp->sr_flags & SMBR_MULTIPACKET) == 0);
again:
	error = smb_iod_recvall(vcp, B_TRUE);
	if (error == ETIME) {
		/* We waited SMB_NBTIMO sec. */
		timeleft -= SMB_NBTIMO;
		if (timeleft > 0)
			goto again;
	}

	smb_iod_removerq(rqp);
	if (rqp->sr_state != SMBRQ_NOTIFIED)
		error = ETIME;

	return (error);
}

/*
 * Shutdown all outstanding I/O requests on the specified share with
 * ENXIO; used when unmounting a share.  (There shouldn't be any for a
 * non-forced unmount; if this is a forced unmount, we have to shutdown
 * the requests as part of the unmount process.)
 */
void
smb_iod_shutdown_share(struct smb_share *ssp)
{
	struct smb_vc *vcp = SSTOVC(ssp);
	struct smb_rq *rqp;

	/*
	 * Loop through the list of requests and shutdown the ones
	 * that are for the specified share.
	 */
	rw_enter(&vcp->iod_rqlock, RW_READER);
	TAILQ_FOREACH(rqp, &vcp->iod_rqlist, sr_link) {
		if (rqp->sr_state != SMBRQ_NOTIFIED && rqp->sr_share == ssp)
			smb_iod_rqprocessed(rqp, EIO, 0);
	}
	rw_exit(&vcp->iod_rqlock);
}

/*
 * Ioctl functions called by the user-level I/O Deamon (IOD)
 * to bring up and service a connection to some SMB server.
 */

/*
 * Handle ioctl SMBIOC_IOD_CONNECT
 */
int
nsmb_iod_connect(struct smb_vc *vcp, cred_t *cr)
{
	int err, val;

	ASSERT(vcp->iod_thr == curthread);

	if (vcp->vc_state != SMBIOD_ST_RECONNECT) {
		cmn_err(CE_NOTE, "iod_connect: bad state %d", vcp->vc_state);
		return (EINVAL);
	}

	/*
	 * Putting a TLI endpoint back in the right state for a new
	 * connection is a bit tricky.  In theory, this could be:
	 *	SMB_TRAN_DISCONNECT(vcp);
	 *	SMB_TRAN_UNBIND(vcp);
	 * but that method often results in TOUTSTATE errors.
	 * It's easier to just close it and open a new endpoint.
	 */
	SMB_VC_LOCK(vcp);
	if (vcp->vc_tdata)
		SMB_TRAN_DONE(vcp);
	err = SMB_TRAN_CREATE(vcp, cr);
	SMB_VC_UNLOCK(vcp);
	if (err != 0)
		return (err);

	/*
	 * Set various options on this endpoint.
	 * Keep going in spite of errors.
	 */
	val = smb_tcpsndbuf;
	err = SMB_TRAN_SETPARAM(vcp, SMBTP_SNDBUF, &val);
	if (err != 0) {
		cmn_err(CE_NOTE, "iod_connect: setopt SNDBUF, err=%d", err);
	}
	val = smb_tcprcvbuf;
	err = SMB_TRAN_SETPARAM(vcp, SMBTP_RCVBUF, &val);
	if (err != 0) {
		cmn_err(CE_NOTE, "iod_connect: setopt RCVBUF, err=%d", err);
	}
	val = 1;
	err = SMB_TRAN_SETPARAM(vcp, SMBTP_KEEPALIVE, &val);
	if (err != 0) {
		cmn_err(CE_NOTE, "iod_connect: setopt KEEPALIVE, err=%d", err);
	}
	val = 1;
	err = SMB_TRAN_SETPARAM(vcp, SMBTP_TCP_NODELAY, &val);
	if (err != 0) {
		cmn_err(CE_NOTE, "iod_connect: setopt TCP_NODELAY err=%d", err);
	}
	val = smb_connect_timeout * 1000;
	err = SMB_TRAN_SETPARAM(vcp, SMBTP_TCP_CON_TMO, &val);
	if (err != 0) {
		cmn_err(CE_NOTE, "iod_connect: setopt TCP con tmo err=%d", err);
	}

	/*
	 * Bind and connect
	 */
	err = SMB_TRAN_BIND(vcp, NULL);
	if (err != 0) {
		cmn_err(CE_NOTE, "iod_connect: t_kbind: err=%d", err);
		/* Continue on and try connect. */
	}
	err = SMB_TRAN_CONNECT(vcp, &vcp->vc_srvaddr.sa);
	/*
	 * No cmn_err here, as connect failures are normal, i.e.
	 * when a server has multiple addresses and only some are
	 * routed for us. (libsmbfs tries them all)
	 */
	if (err == 0) {
		SMB_VC_LOCK(vcp);
		smb_iod_newstate(vcp, SMBIOD_ST_CONNECTED);
		SMB_VC_UNLOCK(vcp);
	} /* else stay in state reconnect */

	return (err);
}

/*
 * Handle ioctl SMBIOC_IOD_NEGOTIATE
 * Do the whole SMB1/SMB2 negotiate
 *
 * This is where we send our first request to the server.
 * If this is the first time we're talking to this server,
 * (meaning not a reconnect) then we don't know whether
 * the server supports SMB2, so we need to use the weird
 * SMB1-to-SMB2 negotiation. That's where we send an SMB1
 * negotiate including dialect "SMB 2.???" and if the
 * server supports SMB2 we get an SMB2 reply -- Yes, an
 * SMB2 reply to an SMB1 request.  A strange protocol...
 *
 * If on the other hand we already know the server supports
 * SMB2 (because this is a reconnect) or if the client side
 * has disabled SMB1 entirely, we'll skip the SMB1 part.
 */
int
nsmb_iod_negotiate(struct smb_vc *vcp, cred_t *cr)
{
	struct smb_sopt *sv = &vcp->vc_sopt;
	smb_cred_t scred;
	int err = 0;

	ASSERT(vcp->iod_thr == curthread);

	smb_credinit(&scred, cr);

	if (vcp->vc_state != SMBIOD_ST_CONNECTED) {
		cmn_err(CE_NOTE, "iod_negotiate: bad state %d", vcp->vc_state);
		err = EINVAL;
		goto out;
	}

	if (vcp->vc_maxver == 0 || vcp->vc_minver > vcp->vc_maxver) {
		err = EINVAL;
		goto out;
	}

	/*
	 * (Re)init negotiated values
	 */
	bzero(sv, sizeof (*sv));
	vcp->vc2_next_message_id = 0;
	vcp->vc2_limit_message_id = 1;
	vcp->vc2_session_id = 0;
	vcp->vc_next_seq = 0;

	/*
	 * If this was reconnect, get rid of the old MAC key
	 * and session key.
	 */
	SMB_VC_LOCK(vcp);
	if (vcp->vc_mackey != NULL) {
		kmem_free(vcp->vc_mackey, vcp->vc_mackeylen);
		vcp->vc_mackey = NULL;
		vcp->vc_mackeylen = 0;
	}
	if (vcp->vc_ssnkey != NULL) {
		kmem_free(vcp->vc_ssnkey, vcp->vc_ssnkeylen);
		vcp->vc_ssnkey = NULL;
		vcp->vc_ssnkeylen = 0;
	}
	SMB_VC_UNLOCK(vcp);

	/*
	 * If this is not an SMB2 reconect (SMBV_SMB2 not set),
	 * and if SMB1 is enabled, do SMB1 neogotiate.  Then
	 * if either SMB1-to-SMB2 negotiate tells us we should
	 * switch to SMB2, or the local configuration has
	 * disabled SMB1, set the SMBV_SMB2 flag.
	 *
	 * Note that vc_maxver is handled in smb_smb_negotiate
	 * so we never get sv_proto == SMB_DIALECT_SMB2_FF when
	 * the local configuration disables SMB2, and therefore
	 * we won't set the SMBV_SMB2 flag.
	 */
	if ((vcp->vc_flags & SMBV_SMB2) == 0) {
		if (vcp->vc_minver < SMB2_DIALECT_BASE) {
			/*
			 * SMB1 is enabled
			 */
			err = smb_smb_negotiate(vcp, &scred);
			if (err != 0)
				goto out;
		}
		/*
		 * If SMB1-to-SMB2 negotiate told us we should
		 * switch to SMB2, or if the local configuration
		 * disables SMB1, set the SMB2 flag.
		 */
		if (sv->sv_proto == SMB_DIALECT_SMB2_FF ||
		    vcp->vc_minver >= SMB2_DIALECT_BASE) {
			/*
			 * Switch this VC to SMB2.
			 */
			SMB_VC_LOCK(vcp);
			vcp->vc_flags |= SMBV_SMB2;
			SMB_VC_UNLOCK(vcp);
		}
	}

	/*
	 * If this is an SMB2 reconnect (SMBV_SMB2 was set before this
	 * function was called), or SMB1-to-SMB2 negotiate indicated
	 * we should switch to SMB2, or we have SMB1 disabled (both
	 * cases set SMBV_SMB2 above), then do SMB2 negotiate.
	 */
	if ((vcp->vc_flags & SMBV_SMB2) != 0) {
		err = smb2_smb_negotiate(vcp, &scred);
	}

out:
	if (err == 0) {
		SMB_VC_LOCK(vcp);
		smb_iod_newstate(vcp, SMBIOD_ST_NEGOTIATED);
		SMB_VC_UNLOCK(vcp);
	}
	/*
	 * (else) leave state as it was.
	 * User-level will either close this handle (if connecting
	 * for the first time) or call rcfail and then try again.
	 */

	smb_credrele(&scred);

	return (err);
}

/*
 * Handle ioctl SMBIOC_IOD_SSNSETUP
 * Do either SMB1 or SMB2 session setup (one call/reply)
 */
int
nsmb_iod_ssnsetup(struct smb_vc *vcp, cred_t *cr)
{
	smb_cred_t scred;
	int err;

	ASSERT(vcp->iod_thr == curthread);

	switch (vcp->vc_state) {
	case SMBIOD_ST_NEGOTIATED:
	case SMBIOD_ST_AUTHCONT:
		break;
	default:
		return (EINVAL);
	}

	smb_credinit(&scred, cr);
	if (vcp->vc_flags & SMBV_SMB2)
		err = smb2_smb_ssnsetup(vcp, &scred);
	else
		err = smb_smb_ssnsetup(vcp, &scred);
	smb_credrele(&scred);

	SMB_VC_LOCK(vcp);
	switch (err) {
	case 0:
		smb_iod_newstate(vcp, SMBIOD_ST_AUTHOK);
		break;
	case EINPROGRESS:	/* MORE_PROCESSING_REQUIRED */
		smb_iod_newstate(vcp, SMBIOD_ST_AUTHCONT);
		break;
	default:
		smb_iod_newstate(vcp, SMBIOD_ST_AUTHFAIL);
		break;
	}
	SMB_VC_UNLOCK(vcp);

	return (err);
}

static int
smb_iod_logoff(struct smb_vc *vcp, cred_t *cr)
{
	smb_cred_t scred;
	int err;

	ASSERT(vcp->iod_thr == curthread);

	smb_credinit(&scred, cr);
	if (vcp->vc_flags & SMBV_SMB2)
		err = smb2_smb_logoff(vcp, &scred);
	else
		err = smb_smb_logoff(vcp, &scred);
	smb_credrele(&scred);

	return (err);
}

/*
 * Handle ioctl SMBIOC_IOD_WORK
 *
 * The smbiod agent calls this after authentication to become
 * the reader for this session, so long as that's possible.
 * This should only return non-zero if we want that agent to
 * give up on this VC permanently.
 */
/* ARGSUSED */
int
smb_iod_vc_work(struct smb_vc *vcp, int flags, cred_t *cr)
{
	smbioc_ssn_work_t *wk = &vcp->vc_work;
	int err = 0;

	/*
	 * This is called by the one-and-only
	 * IOD thread for this VC.
	 */
	ASSERT(vcp->iod_thr == curthread);

	/*
	 * Should be in state...
	 */
	if (vcp->vc_state != SMBIOD_ST_AUTHOK) {
		cmn_err(CE_NOTE, "iod_vc_work: bad state %d", vcp->vc_state);
		return (EINVAL);
	}

	/*
	 * Update the session key and initialize SMB signing.
	 *
	 * This implementation does not use multiple SMB sessions per
	 * TCP connection (where only the first session key is used)
	 * so we always have a new session key here.  Sanity check the
	 * length from user space.  Normally 16 or 32.
	 */
	if (wk->wk_u_ssnkey_len > 1024) {
		cmn_err(CE_NOTE, "iod_vc_work: ssn key too long");
		return (EINVAL);
	}

	ASSERT(vcp->vc_ssnkey == NULL);
	SMB_VC_LOCK(vcp);
	if (wk->wk_u_ssnkey_len != 0 &&
	    wk->wk_u_ssnkey_buf.lp_ptr != NULL) {
		vcp->vc_ssnkeylen = wk->wk_u_ssnkey_len;
		vcp->vc_ssnkey = kmem_alloc(vcp->vc_ssnkeylen, KM_SLEEP);
		if (ddi_copyin(wk->wk_u_ssnkey_buf.lp_ptr,
		    vcp->vc_ssnkey, vcp->vc_ssnkeylen, flags) != 0) {
			err = EFAULT;
		}
	}
	SMB_VC_UNLOCK(vcp);
	if (err)
		return (err);

	/*
	 * If we have a session key, derive the MAC key for SMB signing.
	 * If this was a NULL session, we might have no session key.
	 */
	ASSERT(vcp->vc_mackey == NULL);
	if (vcp->vc_ssnkey != NULL) {
		if (vcp->vc_flags & SMBV_SMB2)
			err = smb2_sign_init(vcp);
		else
			err = smb_sign_init(vcp);
		if (err != 0)
			return (err);
	}

	/*
	 * Tell any enqueued requests they can start.
	 */
	SMB_VC_LOCK(vcp);
	vcp->vc_genid++;	/* possibly new connection */
	smb_iod_newstate(vcp, SMBIOD_ST_VCACTIVE);
	cv_broadcast(&vcp->vc_statechg);
	SMB_VC_UNLOCK(vcp);

	/*
	 * The above cv_broadcast should be sufficient to
	 * get requests going again.
	 *
	 * If we have a callback function, run it.
	 * Was: smb_iod_notify_connected()
	 */
	if (fscb && fscb->fscb_connect)
		smb_vc_walkshares(vcp, fscb->fscb_connect);

	/*
	 * Run the "reader" loop.  An error return here is normal
	 * (i.e. when we need to reconnect) so ignore errors.
	 * Note: This call updates the vc_state.
	 */
	(void) smb_iod_recvall(vcp, B_FALSE);

	/*
	 * The reader loop returned, so we must have a
	 * new state.  (disconnected or reconnecting)
	 *
	 * Notify shares of the disconnect.
	 * Was: smb_iod_notify_disconnect()
	 */
	smb_vc_walkshares(vcp, smb_iod_share_disconnected);

	/*
	 * The reader loop function returns only when
	 * there's been an error on the connection, or
	 * this VC has no more references.  It also
	 * updates the state before it returns.
	 *
	 * Tell any requests to give up or restart.
	 */
	smb_iod_invrq(vcp);

	return (err);
}

/*
 * Handle ioctl SMBIOC_IOD_IDLE
 *
 * Wait around for someone to ask to use this VC again after the
 * TCP session has closed.  When one of the connected trees adds a
 * request, smb_iod_reconnect will set vc_state to RECONNECT and
 * wake this cv_wait.  When a VC ref. goes away in smb_vc_rele,
 * that also signals this wait so we can re-check whether we
 * now hold the last ref. on this VC (and can destroy it).
 */
int
smb_iod_vc_idle(struct smb_vc *vcp)
{
	int err = 0;
	boolean_t destroy = B_FALSE;

	/*
	 * This is called by the one-and-only
	 * IOD thread for this VC.
	 */
	ASSERT(vcp->iod_thr == curthread);

	/*
	 * Should be in state...
	 */
	if (vcp->vc_state != SMBIOD_ST_IDLE &&
	    vcp->vc_state != SMBIOD_ST_RECONNECT) {
		cmn_err(CE_NOTE, "iod_vc_idle: bad state %d", vcp->vc_state);
		return (EINVAL);
	}

	SMB_VC_LOCK(vcp);

	while (vcp->vc_state == SMBIOD_ST_IDLE &&
	    vcp->vc_co.co_usecount > 1) {
		if (cv_wait_sig(&vcp->iod_idle, &vcp->vc_lock) == 0) {
			err = EINTR;
			break;
		}
	}
	if (vcp->vc_state == SMBIOD_ST_IDLE &&
	    vcp->vc_co.co_usecount == 1) {
		/*
		 * We were woken because we now have the last ref.
		 * Arrange for this VC to be destroyed now.
		 * Set the "GONE" flag while holding the lock,
		 * to prevent a race with new references.
		 * The destroy happens after unlock.
		 */
		vcp->vc_flags |= SMBV_GONE;
		destroy = B_TRUE;
	}

	SMB_VC_UNLOCK(vcp);

	if (destroy) {
		/* This sets vc_state = DEAD */
		smb_iod_disconnect(vcp);
	}

	return (err);
}

/*
 * Handle ioctl SMBIOC_IOD_RCFAIL
 *
 * After a failed reconnect attempt, smbiod will
 * call this to make current requests error out.
 */
int
smb_iod_vc_rcfail(struct smb_vc *vcp)
{
	clock_t tr;
	int err = 0;

	/*
	 * This is called by the one-and-only
	 * IOD thread for this VC.
	 */
	ASSERT(vcp->iod_thr == curthread);
	SMB_VC_LOCK(vcp);

	smb_iod_newstate(vcp, SMBIOD_ST_RCFAILED);
	cv_broadcast(&vcp->vc_statechg);

	/*
	 * Short wait here for two reasons:
	 * (1) Give requests a chance to error out.
	 * (2) Prevent immediate retry.
	 */
	tr = cv_reltimedwait_sig(&vcp->iod_idle, &vcp->vc_lock,
	    SEC_TO_TICK(5), TR_CLOCK_TICK);
	if (tr == 0)
		err = EINTR;

	/*
	 * Normally we'll switch to state IDLE here.  However,
	 * if something called smb_iod_reconnect() while we were
	 * waiting above, we'll be in in state reconnect already.
	 * In that case, keep state RECONNECT, so we essentially
	 * skip transition through state IDLE that would normally
	 * happen next.
	 */
	if (vcp->vc_state != SMBIOD_ST_RECONNECT) {
		smb_iod_newstate(vcp, SMBIOD_ST_IDLE);
		cv_broadcast(&vcp->vc_statechg);
	}

	SMB_VC_UNLOCK(vcp);

	return (err);
}

/*
 * Ask the IOD to reconnect (if not already underway)
 * then wait for the reconnect to finish.
 */
int
smb_iod_reconnect(struct smb_vc *vcp)
{
	int err = 0, rv;

	SMB_VC_LOCK(vcp);
again:
	switch (vcp->vc_state) {

	case SMBIOD_ST_IDLE:
		/* Tell the IOD thread it's no longer IDLE. */
		smb_iod_newstate(vcp, SMBIOD_ST_RECONNECT);
		cv_signal(&vcp->iod_idle);
		/* FALLTHROUGH */

	case SMBIOD_ST_RECONNECT:
	case SMBIOD_ST_CONNECTED:
	case SMBIOD_ST_NEGOTIATED:
	case SMBIOD_ST_AUTHCONT:
	case SMBIOD_ST_AUTHOK:
		/* Wait for the VC state to become ACTIVE. */
		rv = cv_wait_sig(&vcp->vc_statechg, &vcp->vc_lock);
		if (rv == 0) {
			err = EINTR;
			break;
		}
		goto again;

	case SMBIOD_ST_VCACTIVE:
		err = 0; /* success! */
		break;

	case SMBIOD_ST_AUTHFAIL:
	case SMBIOD_ST_RCFAILED:
	case SMBIOD_ST_DEAD:
	default:
		err = ENOTCONN;
		break;
	}

	SMB_VC_UNLOCK(vcp);
	return (err);
}
