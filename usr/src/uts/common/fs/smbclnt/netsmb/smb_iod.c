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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#ifdef APPLE
#include <sys/smb_apple.h>
#else
#include <netsmb/smb_osdep.h>
#endif

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_rq.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>
#include <netsmb/smb_trantcp.h>

#ifdef NEED_SMBFS_CALLBACKS
/*
 * This is set/cleared when smbfs loads/unloads
 * No locks should be necessary, because smbfs
 * can't unload until all the mounts are gone.
 */
static smb_fscb_t *fscb;
int
smb_fscb_set(smb_fscb_t *cb)
{
	fscb = cb;
	return (0);
}
#endif /* NEED_SMBFS_CALLBACKS */

static void smb_iod_sendall(struct smb_vc *);
static void smb_iod_recvall(struct smb_vc *);
static void smb_iod_main(struct smb_vc *);


#define	SMBIOD_SLEEP_TIMO	2
#define	SMBIOD_PING_TIMO	60	/* seconds */

/*
 * After this many seconds we want an unresponded-to request to trigger
 * some sort of UE (dialogue).  If the connection hasn't responded at all
 * in this many seconds then the dialogue is of the "connection isn't
 * responding would you like to force unmount" variety.  If the connection
 * has been responding (to other requests that is) then we need a dialogue
 * of the "operation is still pending do you want to cancel it" variety.
 * At present this latter dialogue does not exist so we have no UE and
 * just keep waiting for the slow operation.
 */
#define	SMBUETIMEOUT 8 /* seconds */


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

#ifdef SMBTP_UPCALL
static void
smb_iod_sockwakeup(struct smb_vc *vcp)
{
	/* note: called from socket upcall... */
}
#endif

/*
 * Called after we fail to send or recv.
 * Called with no locks held.
 */
static void
smb_iod_dead(struct smb_vc *vcp)
{

	SMB_VC_LOCK(vcp);
	vcp->vc_state = SMBIOD_ST_DEAD;
	cv_broadcast(&vcp->vc_statechg);

#ifdef NEED_SMBFS_CALLBACKS
	if (fscb != NULL) {
		struct smb_connobj *co;
		/*
		 * Walk the share list, notify...
		 * Was: smbfs_dead(...share->ss_mount);
		 * XXX: Ok to hold vc_lock here?
		 * XXX: More to do here?
		 */
		SLIST_FOREACH(co, &(VCTOCP(vcp)->co_children), co_next) {
			/* smbfs_dead() */
			fscb->fscb_dead(CPTOSS(co));
		}
	}
#endif /* NEED_SMBFS_CALLBACKS */

	SMB_VC_UNLOCK(vcp);

	smb_iod_invrq(vcp);
}

int
smb_iod_connect(struct smb_vc *vcp)
{
	struct proc *p = curproc;
	int error;

	if (vcp->vc_state != SMBIOD_ST_RECONNECT)
		return (EINVAL);

	if (vcp->vc_laddr) {
		error = SMB_TRAN_BIND(vcp, vcp->vc_laddr, p);
		if (error)
			goto errout;
	}

#ifdef SMBTP_SELECTID
	SMB_TRAN_SETPARAM(vcp, SMBTP_SELECTID, vcp);
#endif
#ifdef SMBTP_UPCALL
	SMB_TRAN_SETPARAM(vcp, SMBTP_UPCALL, (void *)smb_iod_sockwakeup);
#endif

	error = SMB_TRAN_CONNECT(vcp, vcp->vc_paddr, p);
	if (error) {
		SMBIODEBUG("connection to %s error %d\n",
		    vcp->vc_srvname, error);
		goto errout;
	}

	/* Success! */
	return (0);

errout:

	return (error);
}

/*
 * Called by smb_vc_rele, smb_vc_kill
 * Make the connection go away, and
 * the IOD (reader) thread too!
 */
int
smb_iod_disconnect(struct smb_vc *vcp)
{

	/*
	 * Let's be safe here and avoid doing any
	 * call across the network while trying to
	 * shut things down.  If we just disconnect,
	 * the server will take care of the logoff.
	 */
#if 0
	if (vcp->vc_state == SMBIOD_ST_VCACTIVE) {
		smb_smb_ssnclose(vcp, &vcp->vc_scred);
		vcp->vc_state = SMBIOD_ST_TRANACTIVE;
	}
	vcp->vc_smbuid = SMB_UID_UNKNOWN;
#endif

	/*
	 * Used to call smb_iod_closetran here,
	 * which did both disconnect and close.
	 * We now do the close in smb_vc_free,
	 * so we always have a valid vc_tdata.
	 * Now just send the disconnect here.
	 * Extra disconnect calls are ignored.
	 */
	SMB_TRAN_DISCONNECT(vcp, curproc);

	/*
	 * If we have an IOD, let it handle the
	 * state change when it receives the ACK
	 * from the disconnect we just sent.
	 * Otherwise set the state here, i.e.
	 * after failing session setup.
	 */
	SMB_VC_LOCK(vcp);
	if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		vcp->vc_state = SMBIOD_ST_DEAD;
		cv_broadcast(&vcp->vc_statechg);
	}
	SMB_VC_UNLOCK(vcp);

	return (0);
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
	struct proc *p = curproc;
	struct smb_vc *vcp = rqp->sr_vc;
	struct smb_share *ssp = rqp->sr_share;
	mblk_t *m;
	int error;

	ASSERT(vcp);
	ASSERT(SEMA_HELD(&vcp->vc_sendlock));
	ASSERT(RW_READ_HELD(&vcp->iod_rqlock));

	/*
	 * Note: requests with sr_flags & SMBR_INTERNAL
	 * need to pass here with these states:
	 *   SMBIOD_ST_TRANACTIVE: smb_negotiate
	 *   SMBIOD_ST_NEGOACTIVE: smb_ssnsetup
	 */
	SMBIODEBUG("vc_state = %d\n", vcp->vc_state);
	switch (vcp->vc_state) {
	case SMBIOD_ST_NOTCONN:
		smb_iod_rqprocessed(rqp, ENOTCONN, 0);
		return (0);
	case SMBIOD_ST_DEAD:
		/* This is what keeps the iod itself from sending more */
		smb_iod_rqprocessed(rqp, ENOTCONN, 0);
		return (0);
	case SMBIOD_ST_RECONNECT:
		return (0);
	default:
		break;
	}

	if (rqp->sr_sendcnt == 0) {
		*rqp->sr_rquid = htoles(vcp->vc_smbuid);

		/*
		 * XXX: Odd place for all this...
		 * Would expect these values in vc_smbuid
		 * and/or the request before we get here.
		 * I think most of this mess is due to having
		 * the initial UID set to SMB_UID_UKNOWN when
		 * it should have been initialized to zero!
		 * REVIST this later. XXX -gwr
		 *
		 * This is checking for the case where
		 * "vc_smbuid" was set to 0 in "smb_smb_ssnsetup()";
		 * that happens for requests that occur
		 * after that's done but before we get back the final
		 * session setup reply, where the latter is what
		 * gives us the UID.  (There can be an arbitrary # of
		 * session setup packet exchanges to complete
		 * "extended security" authentication.)
		 *
		 * However, if the server gave us a UID of 0 in a
		 * Session Setup andX reply, and we then do a
		 * Tree Connect andX and get back a TID, we should
		 * use that TID, not 0, in subsequent references to
		 * that tree (e.g., in NetShareEnum RAP requests).
		 *
		 * So, for now, we forcibly zero out the TID only if we're
		 * doing extended security, as that's the only time
		 * that "vc_smbuid" should be explicitly zeroed.
		 *
		 * note we must and do use SMB_TID_UNKNOWN for SMB_COM_ECHO
		 */
		if (!vcp->vc_smbuid &&
		    (vcp->vc_hflags2 & SMB_FLAGS2_EXT_SEC))
			*rqp->sr_rqtid = htoles(0);
		else
			*rqp->sr_rqtid =
			    htoles(ssp ? ssp->ss_tid : SMB_TID_UNKNOWN);
		mb_fixhdr(&rqp->sr_rq);

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

#ifdef DTRACE_PROBE
	DTRACE_PROBE2(smb_iod_sendrq,
	    (smb_rq_t *), rqp, (mblk_t *), m);
#else
	SMBIODEBUG("M:%04x, P:%04x, U:%04x, T:%04x\n", rqp->sr_mid, 0, 0, 0);
#endif
	m_dumpm(m);

	error = rqp->sr_lerror = m ? SMB_TRAN_SEND(vcp, m, p) : ENOBUFS;
	m = 0; /* consumed by SEND */
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

#ifdef APPLE
	/* If proc waiting on rqp was signaled... */
	if (smb_rq_intr(rqp))
		smb_iod_rqprocessed(rqp, EINTR, 0);
#endif

	return (0);
}

static int
smb_iod_recv1(struct smb_vc *vcp, mblk_t **mpp)
{
	struct proc *p = curproc;
	mblk_t *m;
	uchar_t *hp;
	int error;

top:
	m = NULL;
	error = SMB_TRAN_RECV(vcp, &m, p);
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
 * This is the "reader" loop, run by the IOD thread
 * while in state SMBIOD_ST_VCACTIVE.  The loop now
 * simply blocks in the socket recv until either a
 * message arrives, or a disconnect.
 */
static void
smb_iod_recvall(struct smb_vc *vcp)
{
	struct smb_rq *rqp;
	mblk_t *m;
	uchar_t *hp;
	ushort_t mid;
	int error;
	int etime_count = 0; /* for "server not responding", etc. */

	for (;;) {

		if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
			SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
			error = EIO;
			break;
		}

		if (vcp->iod_flags & SMBIOD_SHUTDOWN) {
			SMBIODEBUG("SHUTDOWN set\n");
			error = EIO;
			break;
		}

		m = NULL;
		error = smb_iod_recv1(vcp, &m);

		if ((error == ETIME) && vcp->iod_rqwaiting) {
			/*
			 * Nothing received for 15 seconds,
			 * and we have requests waiting.
			 */
			etime_count++;

			/*
			 * Once, at 15 sec. notify callbacks
			 * and print the warning message.
			 */
			if (etime_count == 1) {
				smb_iod_notify_down(vcp);
				zprintf(vcp->vc_zoneid,
				    "SMB server %s not responding\n",
				    vcp->vc_srvname);
			}

			/*
			 * At 30 sec. try sending an echo, and then
			 * once a minute thereafter. It's tricky to
			 * do a send from the IOD thread because
			 * we don't want to block here.
			 *
			 * Using tmo=SMBNOREPLYWAIT in the request
			 * so smb_rq_reply will skip smb_iod_waitrq.
			 * The smb_smb_echo call uses SMBR_INTERNAL
			 * to avoid calling smb_iod_sendall().
			 */
			if ((etime_count & 3) == 2) {
				smb_smb_echo(vcp, &vcp->vc_scred,
				    SMBNOREPLYWAIT);
			}

			continue;
		} /* ETIME && iod_rqwaiting */

		if (error == ETIME) {
			/*
			 * If the IOD thread holds the last reference
			 * to this VC, disconnect, release, terminate.
			 * Usually can avoid the lock/unlock here.
			 * Note, in-line: _vc_kill ... _vc_gone
			 */
			if (vcp->vc_co.co_usecount > 1)
				continue;
			SMB_VC_LOCK(vcp);
			if (vcp->vc_co.co_usecount == 1 &&
			    (vcp->vc_flags & SMBV_GONE) == 0) {
				vcp->vc_flags |= SMBV_GONE;
				SMB_VC_UNLOCK(vcp);
				smb_iod_disconnect(vcp);
				break;
			}
			SMB_VC_UNLOCK(vcp);
			continue;
		} /* error == ETIME */

		if (error) {
			/*
			 * It's dangerous to continue here.
			 * (possible infinite loop!)
			 */
			break;
		}

		/*
		 * Received something.  Yea!
		 */
		if (etime_count) {
			etime_count = 0;

			zprintf(vcp->vc_zoneid, "SMB server %s OK\n",
			    vcp->vc_srvname);

			smb_iod_notify_up(vcp);
		}

		/*
		 * Have an SMB packet.  The SMB header was
		 * checked in smb_iod_recv1().
		 * Find the request...
		 */
		hp = mtod(m, uchar_t *);
		/*LINTED*/
		mid = SMB_HDRMID(hp);
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
/*			smb_printrqlist(vcp); */
			m_freem(m);
		}
		rw_exit(&vcp->iod_rqlock);

	}
#ifdef APPLE
	/*
	 * check for interrupts
	 * On Solaris, handle in smb_iod_waitrq
	 */
	rw_enter(&vcp->iod_rqlock, RW_READER);
	TAILQ_FOREACH(rqp, &vcp->iod_rqlist, sr_link) {
		if (smb_sigintr(rqp->sr_cred->scr_vfsctx))
			smb_iod_rqprocessed(rqp, EINTR, 0);
	}
	rw_exit(&vcp->iod_rqlock);
#endif
}

/*
 * Looks like we don't need these callbacks,
 * but keep the code for now (for Apple).
 */
/*ARGSUSED*/
void
smb_iod_notify_down(struct smb_vc *vcp)
{
#ifdef NEED_SMBFS_CALLBACKS
	struct smb_connobj *co;

	if (fscb == NULL)
		return;

	/*
	 * Walk the share list, notify...
	 * Was: smbfs_down(...share->ss_mount);
	 * XXX: Ok to hold vc_lock here?
	 */
	SMB_VC_LOCK(vcp);
	SLIST_FOREACH(co, &(VCTOCP(vcp)->co_children), co_next) {
		/* smbfs_down() */
		fscb->fscb_down(CPTOSS(co));
	}
	SMB_VC_UNLOCK(vcp);
#endif /* NEED_SMBFS_CALLBACKS */
}

/*ARGSUSED*/
void
smb_iod_notify_up(struct smb_vc *vcp)
{
#ifdef NEED_SMBFS_CALLBACKS
	struct smb_connobj *co;

	if (fscb == NULL)
		return;

	/*
	 * Walk the share list, notify...
	 * Was: smbfs_up(...share->ss_mount);
	 * XXX: Ok to hold vc_lock here?
	 */
	SMB_VC_LOCK(vcp);
	SLIST_FOREACH(co, &(VCTOCP(vcp)->co_children), co_next) {
		/* smbfs_up() */
		fscb->fscb_up(CPTOSS(co));
	}
	SMB_VC_UNLOCK(vcp);
#endif /* NEED_SMBFS_CALLBACKS */
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

	SMBIODEBUG("entry, mid=%d\n", rqp->sr_mid);

	ASSERT(rqp->sr_cred);

	/* This helps a little with debugging. */
	rqp->sr_owner = curthread;

	if (rqp->sr_flags & SMBR_INTERNAL) {
		/*
		 * This is some kind of internal request,
		 * i.e. negotiate, session setup, echo...
		 * Allow vc_state < SMBIOD_ST_VCACTIVE, and
		 * always send directly from this thread.
		 * May be called by the IOD thread (echo).
		 * Note lock order: iod_rqlist, vc_sendlock
		 */
		rw_enter(&vcp->iod_rqlock, RW_WRITER);
		if (rqp->sr_rqflags2 & SMB_FLAGS2_SECURITY_SIGNATURE) {
			/*
			 * We're signing requests and verifying
			 * signatures on responses.  Set the
			 * sequence numbers of the request and
			 * response here, used in smb_rq_verify.
			 */
			rqp->sr_seqno = vcp->vc_seqno++;
			rqp->sr_rseqno = vcp->vc_seqno++;
		}
		TAILQ_INSERT_HEAD(&vcp->iod_rqlist, rqp, sr_link);
		rw_downgrade(&vcp->iod_rqlock);

		/*
		 * Note: iod_sendrq expects vc_sendlock,
		 * so take that here, but carefully:
		 * Never block the IOD thread here.
		 */
		if (curthread == vcp->iod_thr) {
			if (sema_tryp(&vcp->vc_sendlock) == 0) {
				SMBIODEBUG("sendlock busy\n");
				error = EAGAIN;
			} else {
				/* Have vc_sendlock */
				error = smb_iod_sendrq(rqp);
				sema_v(&vcp->vc_sendlock);
			}
		} else {
			sema_p(&vcp->vc_sendlock);
			error = smb_iod_sendrq(rqp);
			sema_v(&vcp->vc_sendlock);
		}

		rw_exit(&vcp->iod_rqlock);
		if (error)
			smb_iod_removerq(rqp);

		return (error);
	}

	/*
	 * Normal request from the driver or smbfs.
	 * State should be correct after the check in
	 * smb_rq_enqueue(), but we dropped locks...
	 */
	if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
		return (ENOTCONN);
	}

	rw_enter(&vcp->iod_rqlock, RW_WRITER);

	if (rqp->sr_rqflags2 & SMB_FLAGS2_SECURITY_SIGNATURE) {
		/*
		 * We're signing requests and verifying
		 * signatures on responses.  Set the
		 * sequence numbers of the request and
		 * response here, used in smb_rq_verify.
		 */
		rqp->sr_seqno = vcp->vc_seqno++;
		rqp->sr_rseqno = vcp->vc_seqno++;
	}
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


int
smb_iod_removerq(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;

	SMBIODEBUG("entry, mid=%d\n", rqp->sr_mid);

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

	return (0);
}


/*
 * Internal version of smb_iod_waitrq.
 *
 * This is used when there is no reader thread,
 * so we have to do the recv here.  The request
 * must have the SMBR_INTERNAL flag set.
 */
static int
smb_iod_waitrq_internal(struct smb_rq *rqp)
{
	struct smb_vc *vcp = rqp->sr_vc;
	mblk_t *m;
	uchar_t *hp;
	int error;
	uint16_t mid;
	uint8_t cmd;

	/* Make sure it's an internal request. */
	if ((rqp->sr_flags & SMBR_INTERNAL) == 0) {
		SMBIODEBUG("not internal\n");
		return (EINVAL);
	}

	/* Only simple requests allowed. */
	if (rqp->sr_flags & SMBR_MULTIPACKET) {
		SMBIODEBUG("multipacket\n");
		return (EINVAL);
	}

	/* Should not already have a response. */
	if (rqp->sr_rp.md_top) {
		DEBUG_ENTER("smb_iod_waitrq again?\n");
		return (0);
	}

	/*
	 * The message recv loop.  Terminates when we
	 * receive the message we're looking for.
	 * Drop others, with complaints.
	 * Scaled-down version of smb_iod_recvall
	 */
	for (;;) {
		m = NULL;
		error = smb_iod_recv1(vcp, &m);
		if (error) {
			/*
			 * It's dangerous to continue here.
			 * (possible infinite loop!)
			 */
#if 0
			if (SMB_TRAN_FATAL(vcp, error)) {
				return (error);
			}
			continue;
#endif
			return (error);
		}

		hp = mtod(m, uchar_t *);
		cmd = SMB_HDRCMD(hp);
		/*LINTED*/
		mid = SMB_HDRMID(hp);

		SMBIODEBUG("cmd 0x%02x mid %04x\n",
		    (uint_t)cmd, (uint_t)mid);
		m_dumpm(m);

		/*
		 * Normally, the MID will match.
		 * For internal requests, also
		 * match on the cmd to be safe.
		 */
		if (mid == rqp->sr_mid)
			break;
		if (cmd == rqp->sr_cmd) {
			SMBIODEBUG("cmd match but not mid!\n");
			break;
		}

		SMBIODEBUG("drop nomatch\n");
		m_freem(m);
	}

	/*
	 * Have the response we were waiting for.
	 * Simplified version of the code from
	 * smb_iod_recvall
	 */
	SMBRQ_LOCK(rqp);
	if (rqp->sr_rp.md_top == NULL) {
		md_initm(&rqp->sr_rp, m);
	} else {
		SMBIODEBUG("drop duplicate\n");
		m_freem(m);
	}
	SMBRQ_UNLOCK(rqp);

	return (0);
}


/*
 * Wait for a request to complete.
 *
 * For internal requests, see smb_iod_waitrq_internal.
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

	SMBIODEBUG("entry, cmd=0x%02x mid=0x%04x\n",
	    (uint_t)rqp->sr_cmd, (uint_t)rqp->sr_mid);

	if (rqp->sr_flags & SMBR_INTERNAL) {
		ASSERT((rqp->sr_flags & SMBR_MULTIPACKET) == 0);
		error = smb_iod_waitrq_internal(rqp);
		smb_iod_removerq(rqp);
		return (error);
	}

	/*
	 * Make sure this is NOT the IOD thread,
	 * or the wait below will always timeout.
	 */
	ASSERT(curthread != vcp->iod_thr);

	atomic_inc_uint(&vcp->iod_rqwaiting);
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
			SMBIODEBUG("EINTR in sendwait, mid=%u\n", rqp->sr_mid);
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
		tmo1 = lbolt + SEC_TO_TICK(smb_timo_notice);
	else
		tmo1 = 0;
	tmo2 = lbolt + SEC_TO_TICK(rqp->sr_timo);

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
			tr = cv_timedwait(&rqp->sr_cond,
			    &rqp->sr_lock, tmo1);
		else
			tr = cv_timedwait_sig(&rqp->sr_cond,
			    &rqp->sr_lock, tmo1);
		if (tr == 0) {
			error = EINTR;
			goto out;
		}
		if (tr < 0) {
#ifdef DTRACE_PROBE
			DTRACE_PROBE1(smb_iod_waitrq1,
			    (smb_rq_t *), rqp);
#endif
#ifdef NOT_YET
			/* Want this to go ONLY to the user. */
			uprintf("SMB server %s has not responded"
			    " to request %d after %d seconds..."
			    " (still waiting).\n", vcp->vc_srvname,
			    rqp->sr_mid, smb_timo_notice);
#endif
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
#ifdef DTRACE_PROBE
			DTRACE_PROBE1(smb_iod_waitrq2,
			    (smb_rq_t *), rqp);
#endif
#ifdef NOT_YET
			/* Want this to go ONLY to the user. */
			uprintf("SMB server %s has not responded"
			    " to request %d after %d seconds..."
			    " (giving up).\n", vcp->vc_srvname,
			    rqp->sr_mid, rqp->sr_timo);
#endif
			error = ETIME;
			goto out;
		}
		/* got wakeup */
	}
	error = rqp->sr_lerror;
	rqp->sr_rplast++;

out:
	SMBRQ_UNLOCK(rqp);
	atomic_dec_uint(&vcp->iod_rqwaiting);

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
static void
smb_iod_sendall(struct smb_vc *vcp)
{
	struct smb_rq *rqp;
	int error, save_newrq, muxcnt;

	/*
	 * Clear "newrq" to make sure threads adding
	 * new requests will run this function again.
	 */
	rw_enter(&vcp->iod_rqlock, RW_WRITER);
	save_newrq = vcp->iod_newrq;
	vcp->iod_newrq = 0;

	/*
	 * We only read iod_rqlist, so downgrade rwlock.
	 * This allows the IOD to handle responses while
	 * some requesting thread may be blocked in send.
	 */
	rw_downgrade(&vcp->iod_rqlock);

	/* Expect to find about this many requests. */
	SMBIODEBUG("top, save_newrq=%d\n", save_newrq);

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

		if (vcp->vc_state == SMBIOD_ST_DEAD) {
			error = ENOTCONN; /* stop everything! */
			break;
		}

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

	if (error == ENOTCONN)
		smb_iod_dead(vcp);

}


/*
 * "main" function for smbiod daemon thread
 */
void
smb_iod_main(struct smb_vc *vcp)
{
	kthread_t *thr = curthread;

	SMBIODEBUG("entry\n");

	SMBIODEBUG("Running, thr=0x%p\n", thr);

	/*
	 * Prevent race with thread that created us.
	 * After we get this lock iod_thr is set.
	 */
	SMB_VC_LOCK(vcp);
	ASSERT(thr == vcp->iod_thr);

	/* Redundant with iod_thr, but may help debugging. */
	vcp->iod_flags |= SMBIOD_RUNNING;
	SMB_VC_UNLOCK(vcp);

	/*
	 * OK, this is a new reader thread.
	 * In case of reconnect, tell any
	 * old requests they can restart.
	 */
	smb_iod_invrq(vcp);

	/*
	 * Run the "reader" loop.
	 */
	smb_iod_recvall(vcp);

	/*
	 * The reader loop function returns only when
	 * there's been a fatal error on the connection.
	 */
	smb_iod_dead(vcp);

	/*
	 * The reader thread is going away.  Clear iod_thr,
	 * and wake up anybody waiting for us to quit.
	 */
	SMB_VC_LOCK(vcp);
	vcp->iod_flags &= ~SMBIOD_RUNNING;
	vcp->iod_thr = NULL;
	cv_broadcast(&vcp->iod_exit);
	SMB_VC_UNLOCK(vcp);

	/*
	 * This hold was taken in smb_iod_create()
	 * when this thread was created.
	 */
	smb_vc_rele(vcp);

	SMBIODEBUG("Exiting, p=0x%p\n", curproc);
	zthread_exit();
}

/*
 * Create the reader thread.
 *
 * This happens when we are just about to
 * enter vc_state = SMBIOD_ST_VCACTIVE;
 * See smb_sm_ssnsetup()
 */
int
smb_iod_create(struct smb_vc *vcp)
{
	kthread_t *thr = NULL;
	int error;

	/*
	 * Take a hold on the VC for the IOD thread.
	 * This hold will be released when the IOD
	 * thread terminates. (or on error below)
	 */
	smb_vc_hold(vcp);

	SMB_VC_LOCK(vcp);

	if (vcp->iod_thr != NULL) {
		SMBIODEBUG("aready have an IOD?");
		error = EIO;
		goto out;
	}

	/*
	 * Darwin code used: IOCreateThread(...)
	 * In Solaris, we use...
	 */
	thr = zthread_create(
	    NULL,	/* stack */
	    0, /* stack size (default) */
	    smb_iod_main, /* entry func... */
	    vcp, /* ... and arg */
	    0, /* len (of what?) */
	    minclsyspri); /* priority */
	if (thr == NULL) {
		SMBERROR("can't start smbiod\n");
		error = ENOMEM;
		goto out;
	}

	/* Success! */
	error = 0;
	vcp->iod_thr = thr;

out:
	SMB_VC_UNLOCK(vcp);

	if (error)
		smb_vc_rele(vcp);

	return (error);
}

/*
 * Called from smb_vc_free to do any
 * cleanup of our IOD (reader) thread.
 */
int
smb_iod_destroy(struct smb_vc *vcp)
{
	clock_t tmo;

	/*
	 * Let's try to make sure the IOD thread
	 * goes away, by waiting for it to exit.
	 * Normally, it's gone by now.
	 *
	 * Only wait for a second, because we're in the
	 * teardown path and don't want to get stuck here.
	 * Should not take long, or things are hosed...
	 */
	SMB_VC_LOCK(vcp);
	if (vcp->iod_thr) {
		vcp->iod_flags |= SMBIOD_SHUTDOWN;
		tmo = lbolt + hz;
		tmo = cv_timedwait(&vcp->iod_exit, &vcp->vc_lock, tmo);
		if (tmo == -1) {
			SMBERROR("IOD thread for %s did not exit?\n",
			    vcp->vc_srvname);
		}
	}
	if (vcp->iod_thr) {
		/* This should not happen. */
		SMBIODEBUG("IOD thread did not exit!\n");
		/* Try harder? */
		tsignal(vcp->iod_thr, SIGKILL);
	}
	SMB_VC_UNLOCK(vcp);

	return (0);
}
