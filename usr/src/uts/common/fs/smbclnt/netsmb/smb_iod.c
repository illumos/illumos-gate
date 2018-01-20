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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
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
#include <netsmb/smb_conn.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>
#include <netsmb/smb_trantcp.h>

/*
 * SMB messages are up to 64K.
 * Let's leave room for two.
 */
static int smb_tcpsndbuf = 0x20000;
static int smb_tcprcvbuf = 0x20000;
static int smb_connect_timeout = 10; /* seconds */

int smb_iod_send_echo(smb_vc_t *);

#ifdef	_FAKE_KERNEL
extern void tsignal(kthread_t *, int);
#endif

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

	/* smbfs_dead() */
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
	 */
	rw_enter(&vcp->iod_rqlock, RW_READER);
	TAILQ_FOREACH(rqp, &vcp->iod_rqlist, sr_link) {
		smb_iod_rqprocessed(rqp, ENOTCONN, SMBR_RESTART);
	}
	rw_exit(&vcp->iod_rqlock);
}

/*
 * Called by smb_vc_rele, smb_vc_kill, and by the driver
 * close entry point if the IOD closes its dev handle.
 *
 * Forcibly kill the connection and IOD.
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

	/*
	 * Let's be safe here and avoid doing any
	 * call across the network while trying to
	 * shut things down.  If we just disconnect,
	 * the server will take care of the logoff.
	 */
	SMB_TRAN_DISCONNECT(vcp);
}

/*
 * Send one request.
 *
 * Called by _addrq (for internal requests)
 * and _sendall (via _addrq, _multirq, _waitrq)
 */
static int
smb_iod_sendrq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *m;
	int error;

	ASSERT(vcp);
	ASSERT(SEMA_HELD(&vcp->vc_sendlock));
	ASSERT(RW_READ_HELD(&vcp->iod_rqlock));

	/*
	 * Internal requests are allowed in any state;
	 * otherwise should be active.
	 */
	if ((rqp->sr_flags & SMBR_INTERNAL) == 0 &&
	    vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
		return (ENOTCONN);
	}

	/*
	 * On the first send, set the MID and (maybe)
	 * the signing sequence numbers.  The increments
	 * here are serialized by vc_sendlock
	 */
	if (rqp->sr_sendcnt == 0) {

		rqp->sr_mid = vcp->vc_next_mid++;

		if (vcp->vc_mackey != NULL && (rqp->sr_rqflags2 &
		    SMB_FLAGS2_SECURITY_SIGNATURE) != 0) {
			/*
			 * We're signing requests and verifying
			 * signatures on responses.  Set the
			 * sequence numbers of the request and
			 * response here, used in smb_rq_verify.
			 * Note we have the signing flag during
			 * session setup but no key yet, and
			 * don't want sequence numbers there.
			 */
			rqp->sr_seqno = vcp->vc_next_seq++;
			rqp->sr_rseqno = vcp->vc_next_seq++;
		}

		/* Fill in UID, TID, MID, etc. */
		smb_rq_fillhdr(rqp);

		/*
		 * Sign the message now that we're finally done
		 * filling in the SMB header fields, etc.
		 */
		if (rqp->sr_rqflags2 & SMB_FLAGS2_SECURITY_SIGNATURE) {
			smb_rq_sign(rqp);
		}
	}
	if (rqp->sr_sendcnt++ >= 60/SMBSBTIMO) { /* one minute */
		smb_iod_rqprocessed(rqp, rqp->sr_lerror, SMBR_RESTART);
		/*
		 * If all attempts to send a request failed, then
		 * something is seriously hosed.
		 */
		return (ENOTCONN);
	}

	/*
	 * Replaced m_copym() with Solaris copymsg() which does the same
	 * work when we want to do a M_COPYALL.
	 * m = m_copym(rqp->sr_rq.mb_top, 0, M_COPYALL, 0);
	 */
	m = copymsg(rqp->sr_rq.mb_top);

	DTRACE_PROBE2(smb_iod_sendrq,
	    (smb_rq_t *), rqp, (mblk_t *), m);
	m_dumpm(m);

	if (m != NULL) {
		error = SMB_TRAN_SEND(vcp, m);
		m = 0; /* consumed by SEND */
	} else
		error = ENOBUFS;

	rqp->sr_lerror = error;
	if (error == 0) {
		SMBRQ_LOCK(rqp);
		rqp->sr_flags |= SMBR_SENT;
		rqp->sr_state = SMBRQ_SENT;
		if (rqp->sr_flags & SMBR_SENDWAIT)
			cv_broadcast(&rqp->sr_cond);
		SMBRQ_UNLOCK(rqp);
		return (0);
	}
	/*
	 * Check for fatal errors
	 */
	if (SMB_TRAN_FATAL(vcp, error)) {
		/*
		 * No further attempts should be made
		 */
		SMBSDEBUG("TRAN_SEND returned fatal error %d\n", error);
		return (ENOTCONN);
	}
	if (error)
		SMBSDEBUG("TRAN_SEND returned non-fatal error %d\n", error);

	return (0);
}

static int
smb_iod_recv1(struct smb_vc *vcp, mblk_t **mpp)
{
	mblk_t *m;
	uchar_t *hp;
	int error;

top:
	m = NULL;
	error = SMB_TRAN_RECV(vcp, &m);
	if (error == EAGAIN)
		goto top;
	if (error)
		return (error);
	ASSERT(m);

	m = m_pullup(m, SMB_HDRLEN);
	if (m == NULL) {
		return (ENOSR);
	}

	/*
	 * Check the SMB header
	 */
	hp = mtod(m, uchar_t *);
	if (bcmp(hp, SMB_SIGNATURE, SMB_SIGLEN) != 0) {
		m_freem(m);
		return (EPROTO);
	}

	*mpp = m;
	return (0);
}

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
	struct smb_rq *rqp;
	mblk_t *m;
	uchar_t *hp;
	ushort_t mid;
	int error = 0;
	int etime_count = 0; /* for "server not responding", etc. */

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
		error = smb_iod_recv1(vcp, &m);

		/*
		 * Internal requests (reconnecting) call this in a loop
		 * (with poll==TRUE) until the request completes.
		 */
		if (error == ETIME && poll)
			break;

		if (error == ETIME &&
		    vcp->iod_rqlist.tqh_first != NULL) {
			/*
			 * Nothing received for 15 seconds and
			 * we have requests in the queue.
			 */
			etime_count++;

			/*
			 * Once, at 15 sec. notify callbacks
			 * and print the warning message.
			 */
			if (etime_count == 1) {
				/* Was: smb_iod_notify_down(vcp); */
				if (fscb && fscb->fscb_down)
					smb_vc_walkshares(vcp,
					    fscb->fscb_down);
				zprintf(vcp->vc_zoneid,
				    "SMB server %s not responding\n",
				    vcp->vc_srvname);
			}

			/*
			 * At 30 sec. try sending an echo, and then
			 * once a minute thereafter.
			 */
			if ((etime_count & 3) == 2) {
				(void) smb_iod_send_echo(vcp);
			}

			continue;
		} /* ETIME && requests in queue */

		if (error == ETIME) {	/* and req list empty */
			/*
			 * If the IOD thread holds the last reference
			 * to this VC, let it become IDLE, and then
			 * let it be destroyed if not used.
			 */
			if (vcp->vc_co.co_usecount > 1)
				continue;
			SMB_VC_LOCK(vcp);
			if (vcp->vc_co.co_usecount == 1) {
				smb_iod_newstate(vcp, SMBIOD_ST_IDLE);
				SMB_VC_UNLOCK(vcp);
				error = 0;
				break;
			}
			SMB_VC_UNLOCK(vcp);
			continue;
		} /* error == ETIME */

		if (error) {
			/*
			 * The recv. above returned some error
			 * we can't continue from i.e. ENOTCONN.
			 * It's dangerous to continue here.
			 * (possible infinite loop!)
			 *
			 * If this VC has shares, try reconnect;
			 * otherwise let this VC die now.
			 */
			SMB_VC_LOCK(vcp);
			if (vcp->vc_co.co_usecount > 1)
				smb_iod_newstate(vcp, SMBIOD_ST_RECONNECT);
			else
				smb_iod_newstate(vcp, SMBIOD_ST_DEAD);
			cv_broadcast(&vcp->vc_statechg);
			SMB_VC_UNLOCK(vcp);
			break;
		}

		/*
		 * Received something.  Yea!
		 */
		if (etime_count) {
			etime_count = 0;

			zprintf(vcp->vc_zoneid, "SMB server %s OK\n",
			    vcp->vc_srvname);

			/* Was: smb_iod_notify_up(vcp); */
			if (fscb && fscb->fscb_up)
				smb_vc_walkshares(vcp, fscb->fscb_up);
		}

		/*
		 * Have an SMB packet.  The SMB header was
		 * checked in smb_iod_recv1().
		 * Find the request...
		 */
		hp = mtod(m, uchar_t *);
		/*LINTED*/
		mid = letohs(SMB_HDRMID(hp));
		SMBIODEBUG("mid %04x\n", (uint_t)mid);

		rw_enter(&vcp->iod_rqlock, RW_READER);
		TAILQ_FOREACH(rqp, &vcp->iod_rqlist, sr_link) {

			if (rqp->sr_mid != mid)
				continue;

			DTRACE_PROBE2(smb_iod_recvrq,
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
					SMBSDEBUG("duplicate response %d "
					    "(ignored)\n", mid);
					break;
				}
			}
			smb_iod_rqprocessed_LH(rqp, 0, 0);
			SMBRQ_UNLOCK(rqp);
			break;
		}

		if (rqp == NULL) {
			int cmd = SMB_HDRCMD(hp);

			if (cmd != SMB_COM_ECHO)
				SMBSDEBUG("drop resp: mid %d, cmd %d\n",
				    (uint_t)mid, cmd);
			m_freem(m);
		}
		rw_exit(&vcp->iod_rqlock);

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
int
smb_iod_send_echo(smb_vc_t *vcp)
{
	smb_cred_t scred;
	int err;

	smb_credinit(&scred, NULL);
	err = smb_smb_echo(vcp, &scred, SMBNOREPLYWAIT);
	smb_credrele(&scred);
	return (err);
}

/*
 * The IOD thread is now just a "reader",
 * so no more smb_iod_request().  Yea!
 */

/*
 * Place request in the queue, and send it now if possible.
 * Called with no locks held.
 */
int
smb_iod_addrq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	int error, save_newrq;

	ASSERT(rqp->sr_cred);

	/*
	 * Requests from the IOD itself are marked _INTERNAL,
	 * and get some special treatment to avoid blocking
	 * the reader thread (so we don't deadlock).
	 * The request is not yet on the queue, so we can
	 * modify it's state here without locks.
	 */
	rqp->sr_owner = curthread;
	if (rqp->sr_owner == vcp->iod_thr) {
		rqp->sr_flags |= SMBR_INTERNAL;

		/*
		 * This is a request from the IOD thread.
		 * Always send directly from this thread.
		 * Note lock order: iod_rqlist, vc_sendlock
		 */
		rw_enter(&vcp->iod_rqlock, RW_WRITER);
		TAILQ_INSERT_HEAD(&vcp->iod_rqlist, rqp, sr_link);
		rw_downgrade(&vcp->iod_rqlock);

		/*
		 * Note: iod_sendrq expects vc_sendlock,
		 * so take that here, but carefully:
		 * Never block the IOD thread here.
		 */
		if (sema_tryp(&vcp->vc_sendlock) == 0) {
			SMBIODEBUG("sendlock busy\n");
			error = EAGAIN;
		} else {
			/* Have vc_sendlock */
			error = smb_iod_sendrq(rqp);
			sema_v(&vcp->vc_sendlock);
		}

		rw_exit(&vcp->iod_rqlock);

		/*
		 * In the non-error case, _removerq
		 * is done by either smb_rq_reply
		 * or smb_iod_waitrq.
		 */
		if (error)
			smb_iod_removerq(rqp);

		return (error);
	} else {
		/*
		 * State should be correct after the check in
		 * smb_rq_enqueue(), but we dropped locks...
		 */
		if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
			SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
			return (ENOTCONN);
		}
	}

	rw_enter(&vcp->iod_rqlock, RW_WRITER);

	TAILQ_INSERT_TAIL(&vcp->iod_rqlist, rqp, sr_link);
	/* iod_rqlock/WRITER protects iod_newrq */
	save_newrq = vcp->iod_newrq;
	vcp->iod_newrq++;

	rw_exit(&vcp->iod_rqlock);

	/*
	 * Now send any requests that need to be sent,
	 * including the one we just put on the list.
	 * Only the thread that found iod_newrq==0
	 * needs to run the send loop.
	 */
	if (save_newrq == 0)
		smb_iod_sendall(vcp);

	return (0);
}

/*
 * Mark an SMBR_MULTIPACKET request as
 * needing another send.  Similar to the
 * "normal" part of smb_iod_addrq.
 */
int
smb_iod_multirq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	int save_newrq;

	ASSERT(rqp->sr_flags & SMBR_MULTIPACKET);

	if (rqp->sr_flags & SMBR_INTERNAL)
		return (EINVAL);

	if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
		return (ENOTCONN);
	}

	rw_enter(&vcp->iod_rqlock, RW_WRITER);

	/* Already on iod_rqlist, just reset state. */
	rqp->sr_state = SMBRQ_NOTSENT;

	/* iod_rqlock/WRITER protects iod_newrq */
	save_newrq = vcp->iod_newrq;
	vcp->iod_newrq++;

	rw_exit(&vcp->iod_rqlock);

	/*
	 * Now send any requests that need to be sent,
	 * including the one we just marked NOTSENT.
	 * Only the thread that found iod_newrq==0
	 * needs to run the send loop.
	 */
	if (save_newrq == 0)
		smb_iod_sendall(vcp);

	return (0);
}


void
smb_iod_removerq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;

	rw_enter(&vcp->iod_rqlock, RW_WRITER);
#ifdef QUEUEDEBUG
	/*
	 * Make sure we have not already removed it.
	 * See sys/queue.h QUEUEDEBUG_TAILQ_POSTREMOVE
	 * XXX: Don't like the constant 1 here...
	 */
	ASSERT(rqp->sr_link.tqe_next != (void *)1L);
#endif
	TAILQ_REMOVE(&vcp->iod_rqlist, rqp, sr_link);
	rw_exit(&vcp->iod_rqlock);
}



/*
 * Wait for a request to complete.
 *
 * For normal requests, we need to deal with
 * ioc_muxcnt dropping below vc_maxmux by
 * making arrangements to send more...
 */
int
smb_iod_waitrq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	clock_t tr, tmo1, tmo2;
	int error, rc;

	if (rqp->sr_flags & SMBR_INTERNAL) {
		int timeleft = rqp->sr_timo;

		ASSERT((rqp->sr_flags & SMBR_MULTIPACKET) == 0);
	again:
		smb_iod_sendall(vcp);
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
	 * Make sure this is NOT the IOD thread,
	 * or the wait below will stop the reader.
	 */
	ASSERT(curthread != vcp->iod_thr);

	SMBRQ_LOCK(rqp);

	/*
	 * First, wait for the request to be sent.  Normally the send
	 * has already happened by the time we get here.  However, if
	 * we have more than maxmux entries in the request list, our
	 * request may not be sent until other requests complete.
	 * The wait in this case is due to local I/O demands, so
	 * we don't want the server response timeout to apply.
	 *
	 * If a request is allowed to interrupt this wait, then the
	 * request is cancelled and never sent OTW.  Some kinds of
	 * requests should never be cancelled (i.e. close) and those
	 * are marked SMBR_NOINTR_SEND so they either go eventually,
	 * or a connection close will terminate them with ENOTCONN.
	 */
	while (rqp->sr_state == SMBRQ_NOTSENT) {
		rqp->sr_flags |= SMBR_SENDWAIT;
		if (rqp->sr_flags & SMBR_NOINTR_SEND) {
			cv_wait(&rqp->sr_cond, &rqp->sr_lock);
			rc = 1;
		} else
			rc = cv_wait_sig(&rqp->sr_cond, &rqp->sr_lock);
		rqp->sr_flags &= ~SMBR_SENDWAIT;
		if (rc == 0) {
			SMBIODEBUG("EINTR in sendwait, rq=%p\n", (void *)rqp);
			error = EINTR;
			goto out;
		}
	}

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

	/*
	 * Some request has been completed.
	 * If we reached the mux limit,
	 * re-run the send loop...
	 */
	if (vcp->iod_muxfull)
		smb_iod_sendall(vcp);

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
 * Send all requests that need sending.
 * Called from _addrq, _multirq, _waitrq
 */
void
smb_iod_sendall(smb_vc_t *vcp)
{
	struct smb_rq *rqp;
	int error, muxcnt;

	/*
	 * Clear "newrq" to make sure threads adding
	 * new requests will run this function again.
	 */
	rw_enter(&vcp->iod_rqlock, RW_WRITER);
	vcp->iod_newrq = 0;

	/*
	 * We only read iod_rqlist, so downgrade rwlock.
	 * This allows the IOD to handle responses while
	 * some requesting thread may be blocked in send.
	 */
	rw_downgrade(&vcp->iod_rqlock);

	/*
	 * Serialize to prevent multiple senders.
	 * Note lock order: iod_rqlock, vc_sendlock
	 */
	sema_p(&vcp->vc_sendlock);

	/*
	 * Walk the list of requests and send when possible.
	 * We avoid having more than vc_maxmux requests
	 * outstanding to the server by traversing only
	 * vc_maxmux entries into this list.  Simple!
	 */
	ASSERT(vcp->vc_maxmux > 0);
	error = muxcnt = 0;
	TAILQ_FOREACH(rqp, &vcp->iod_rqlist, sr_link) {

		if (rqp->sr_state == SMBRQ_NOTSENT) {
			error = smb_iod_sendrq(rqp);
			if (error)
				break;
		}

		if (++muxcnt == vcp->vc_maxmux) {
			SMBIODEBUG("muxcnt == vc_maxmux\n");
			break;
		}

	}

	/*
	 * If we have vc_maxmux requests outstanding,
	 * arrange for _waitrq to call _sendall as
	 * requests are completed.
	 */
	vcp->iod_muxfull =
	    (muxcnt < vcp->vc_maxmux) ? 0 : 1;

	sema_v(&vcp->vc_sendlock);
	rw_exit(&vcp->iod_rqlock);
}

/*
 * Ioctl functions called by the user-level I/O Deamon (IOD)
 * to bring up and service a connection to some SMB server.
 */

int
nsmb_iod_connect(struct smb_vc *vcp)
{
	int err, val;

	ASSERT(vcp->iod_thr == curthread);

	if (vcp->vc_state != SMBIOD_ST_RECONNECT) {
		cmn_err(CE_NOTE, "iod_connect: bad state %d", vcp->vc_state);
		return (EINVAL);
	}

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
		cmn_err(CE_NOTE, "iod_connect: setopt TCP_NODELAY, err=%d", err);
	}
	val = smb_connect_timeout * 1000;
	err = SMB_TRAN_SETPARAM(vcp, SMBTP_TCP_CON_TMO, &val);
	if (err != 0) {
		cmn_err(CE_NOTE, "iod_connect: setopt TCP con tmo, err=%d", err);
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
 * Do the whole SMB1/SMB2 negotiate
 */
int
nsmb_iod_negotiate(struct smb_vc *vcp, cred_t *cr)
{
	struct smb_sopt *sv = &vcp->vc_sopt;
	smb_cred_t scred;
	int err = 0;

	ASSERT(vcp->iod_thr == curthread);

	if (vcp->vc_state != SMBIOD_ST_CONNECTED) {
		cmn_err(CE_NOTE, "iod_negotiate: bad state %d", vcp->vc_state);
		return (EINVAL);
	}

	/*
	 * (Re)init negotiated values
	 */
	bzero(sv, sizeof (*sv));
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

	smb_credinit(&scred, cr);
	err = smb_smb_negotiate(vcp, &scred);
	smb_credrele(&scred);

	if (err == 0) {
		SMB_VC_LOCK(vcp);
		smb_iod_newstate(vcp, SMBIOD_ST_NEGOTIATED);
		SMB_VC_UNLOCK(vcp);
	}
	/*
	 * (else) leave state as it was.
	 * User-level will report this error
	 * and close this device handle.
	 */

	return (err);
}

/*
 * Do either SMB1 or SMB2 session setup.
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
	// XXX if SMB1 else ...
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
	 * Run the "reader" loop.
	 */
	err = smb_iod_recvall(vcp, B_FALSE);

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
 * Wait around for someone to ask to use this VC.
 * If the VC has only the IOD reference, then
 * wait only a minute or so, then drop it.
 */
int
smb_iod_vc_idle(struct smb_vc *vcp)
{
	clock_t tr, delta = SEC_TO_TICK(15);
	int err = 0;

	/*
	 * This is called by the one-and-only
	 * IOD thread for this VC.
	 */
	ASSERT(vcp->iod_thr == curthread);

	SMB_VC_LOCK(vcp);
	while (vcp->vc_state == SMBIOD_ST_IDLE) {
		tr = cv_reltimedwait_sig(&vcp->iod_idle, &vcp->vc_lock,
		    delta, TR_CLOCK_TICK);
		if (tr == 0) {
			err = EINTR;
			break;
		}
		if (tr < 0) {
			/* timeout */
			if (vcp->vc_co.co_usecount == 1) {
				/* Let this IOD terminate. */
				smb_iod_newstate(vcp, SMBIOD_ST_DEAD);
				/* nobody to cv_broadcast */
				break;
			}
		}
	}
	SMB_VC_UNLOCK(vcp);

	return (err);
}

/*
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
	 * While we were waiting on the CV, the state might have
	 * changed to reconnect.  If so, leave that; otherwise
	 * go to state idle until the next request.
	 */
	if (vcp->vc_state == SMBIOD_ST_RCFAILED)
		smb_iod_newstate(vcp, SMBIOD_ST_IDLE);
	cv_broadcast(&vcp->vc_statechg);

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
		smb_iod_newstate(vcp, SMBIOD_ST_RECONNECT);
		cv_signal(&vcp->iod_idle);
		/* FALLTHROUGH */

	case SMBIOD_ST_RECONNECT:
	case SMBIOD_ST_CONNECTED:
	case SMBIOD_ST_NEGOTIATED:
	case SMBIOD_ST_AUTHCONT:
	case SMBIOD_ST_AUTHOK:
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
