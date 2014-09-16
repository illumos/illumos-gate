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
 * $Id: smb_trantcp.c,v 1.39 2005/03/02 01:27:44 lindak Exp $
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/autoconf.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/tihdr.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <sys/priv.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/mchain.h>
#include <netsmb/netbios.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>
#include <netsmb/smb_trantcp.h>

/*
 * SMB messages are up to 64K.
 * Let's leave room for two.
 */
static int smb_tcpsndbuf = 0x20000;
static int smb_tcprcvbuf = 0x20000;

static int  nb_disconnect(struct nbpcb *nbp);


/*
 * Get mblks into *mpp until the data length is at least mlen.
 * Note that *mpp may already contain a fragment.
 *
 * If we ever have to wait more than 15 sec. to read a message,
 * return ETIME.  (Caller will declare the VD dead.)
 */
static int
nb_getmsg_mlen(struct nbpcb *nbp, mblk_t **mpp, size_t mlen)
{
	mblk_t *im, *tm;
	union T_primitives	*pptr;
	size_t dlen;
	int events, fmode, timo, waitflg;
	int error = 0;

	/* We should be the only reader. */
	ASSERT(nbp->nbp_flags & NBF_RECVLOCK);
	/* nbp->nbp_tiptr checked by caller */

	/*
	 * Get the first message (fragment) if
	 * we don't already have a left-over.
	 */
	dlen = msgdsize(*mpp); /* *mpp==null is OK */
	while (dlen < mlen) {

		/*
		 * I think we still want this to return ETIME
		 * if nothing arrives for SMB_NBTIMO (15) sec.
		 * so we can report "server not responding".
		 * We _could_ just block here now that our
		 * IOD is just a reader.
		 */
#if 1
		/* Wait with timeout... */
		events = 0;
		waitflg = READWAIT;
		timo = SEC_TO_TICK(SMB_NBTIMO);
		error = t_kspoll(nbp->nbp_tiptr, timo, waitflg, &events);
		if (!error && !events)
			error = ETIME;
		if (error)
			break;
		/* file mode for recv is: */
		fmode = FNDELAY; /* non-blocking */
#else
		fmode = 0; /* normal (blocking) */
#endif

		/* Get some more... */
		tm = NULL;
		error = tli_recv(nbp->nbp_tiptr, &tm, fmode);
		if (error == EAGAIN)
			continue;
		if (error)
			break;

		/*
		 * Normally get M_DATA messages here,
		 * but have to check for other types.
		 */
		switch (tm->b_datap->db_type) {
		case M_DATA:
			break;
		case M_PROTO:
		case M_PCPROTO:
			/*LINTED*/
			pptr = (union T_primitives *)tm->b_rptr;
			switch (pptr->type) {
			case T_DATA_IND:
				/* remove 1st mblk, keep the rest. */
				im = tm->b_cont;
				tm->b_cont = NULL;
				freeb(tm);
				tm = im;
				break;
			case T_DISCON_IND:
				/* Peer disconnected. */
				NBDEBUG("T_DISCON_IND: reason=%d",
				    pptr->discon_ind.DISCON_reason);
				goto discon;
			case T_ORDREL_IND:
				/* Peer disconnecting. */
				NBDEBUG("T_ORDREL_IND");
				goto discon;
			case T_OK_ACK:
				switch (pptr->ok_ack.CORRECT_prim) {
				case T_DISCON_REQ:
					NBDEBUG("T_OK_ACK/T_DISCON_REQ");
					goto discon;
				default:
					NBDEBUG("T_OK_ACK/prim=%d",
					    pptr->ok_ack.CORRECT_prim);
					goto discon;
				}
			default:
				NBDEBUG("M_PROTO/type=%d", pptr->type);
				goto discon;
			}
			break; /* M_PROTO, M_PCPROTO */

		default:
			NBDEBUG("unexpected msg type=%d",
			    tm->b_datap->db_type);
			/*FALLTHROUGH*/
discon:
			/*
			 * The connection is no longer usable.
			 * Drop this message and disconnect.
			 *
			 * Note: nb_disconnect only does t_snddis
			 * on the first call, but does important
			 * cleanup and state change on any call.
			 */
			freemsg(tm);
			(void) nb_disconnect(nbp);
			return (ENOTCONN);
		}

		/*
		 * If we have a data message, append it to
		 * the previous chunk(s) and update dlen
		 */
		if (!tm)
			continue;
		if (*mpp == NULL) {
			*mpp = tm;
		} else {
			/* Append */
			for (im = *mpp; im->b_cont; im = im->b_cont)
				;
			im->b_cont = tm;
		}
		dlen += msgdsize(tm);
	}

	return (error);
}

/*
 * Send a T_DISCON_REQ (disconnect)
 */
static int
nb_snddis(struct nbpcb *nbp)
{
	TIUSER *tiptr = nbp->nbp_tiptr;
	cred_t *cr = nbp->nbp_cred;
	mblk_t *mp;
	struct T_discon_req *dreq;
	int error, mlen;

	ASSERT(MUTEX_HELD(&nbp->nbp_lock));

	if (tiptr == NULL)
		return (EBADF);

	mlen = sizeof (struct T_discon_req);
	if (!(mp = allocb_cred_wait(mlen, STR_NOSIG, &error, cr, NOPID)))
		return (error);

	mp->b_datap->db_type = M_PROTO;
	/*LINTED*/
	dreq = (struct T_discon_req *)mp->b_wptr;
	dreq->PRIM_type = T_DISCON_REQ;
	dreq->SEQ_number = -1;
	mp->b_wptr += sizeof (struct T_discon_req);

	error = tli_send(tiptr, mp, tiptr->fp->f_flag);
	/*
	 * There is an OK/ACK response expected, which is
	 * either handled by our receiver thread, or just
	 * discarded if we're closing this endpoint.
	 */

	return (error);
}

/*
 * Stuff the NetBIOS header into space already prepended.
 */
static void
nb_sethdr(mblk_t *m, uint8_t type, uint32_t len)
{
	uint32_t *p;

	len &= 0x1FFFF;
	len |= (type << 24);

	/*LINTED*/
	p = (uint32_t *)m->b_rptr;
	*p = htonl(len);
}

/*
 * Wait for up to 15 sec. for the next packet.
 * Often return ETIME and do nothing else.
 * When a packet header is available, check
 * the header and get the length, but don't
 * consume it.  No side effects here except
 * for the pullupmsg call.
 */
static int
nbssn_peekhdr(struct nbpcb *nbp, size_t *lenp,	uint8_t *rpcodep)
{
	uint32_t len, *hdr;
	int error;

	/*
	 * Get the first message (fragment) if
	 * we don't already have a left-over.
	 */
	error = nb_getmsg_mlen(nbp, &nbp->nbp_frag, sizeof (len));
	if (error)
		return (error);

	if (!pullupmsg(nbp->nbp_frag, sizeof (len)))
		return (ENOSR);

	/*
	 * Check the NetBIOS header.
	 * (NOT consumed here)
	 */
	/*LINTED*/
	hdr = (uint32_t *)nbp->nbp_frag->b_rptr;

	len = ntohl(*hdr);
	if ((len >> 16) & 0xFE) {
		NBDEBUG("bad nb header received 0x%x (MBZ flag set)\n", len);
		return (EPIPE);
	}
	*rpcodep = (len >> 24) & 0xFF;
	switch (*rpcodep) {
	case NB_SSN_MESSAGE:
	case NB_SSN_REQUEST:
	case NB_SSN_POSRESP:
	case NB_SSN_NEGRESP:
	case NB_SSN_RTGRESP:
	case NB_SSN_KEEPALIVE:
		break;
	default:
		NBDEBUG("bad nb header received 0x%x (bogus type)\n", len);
		return (EPIPE);
	}
	len &= 0x1ffff;
	if (len > NB_MAXPKTLEN) {
		NBDEBUG("packet too long (%d)\n", len);
		return (EFBIG);
	}
	*lenp = len;
	return (0);
}

/*
 * Receive a NetBIOS message.  This may block to wait for the entire
 * message to arrive.  The caller knows there is (or should be) a
 * message to be read.  When we receive and drop a keepalive or
 * zero-length message, return EAGAIN so the caller knows that
 * something was received.  This avoids false triggering of the
 * "server not responding" state machine.
 *
 * Calls to this are serialized at a higher level.
 */
static int
nbssn_recv(struct nbpcb *nbp, mblk_t **mpp, int *lenp,
    uint8_t *rpcodep)
{
	mblk_t *m0;
	uint8_t rpcode;
	int error;
	size_t rlen, len;

	/* We should be the only reader. */
	ASSERT(nbp->nbp_flags & NBF_RECVLOCK);

	if (nbp->nbp_tiptr == NULL)
		return (EBADF);
	if (mpp) {
		if (*mpp) {
			NBDEBUG("*mpp not 0 - leak?");
		}
		*mpp = NULL;
	}
	m0 = NULL;

	/*
	 * Get the NetBIOS header (not consumed yet)
	 */
	error = nbssn_peekhdr(nbp, &len, &rpcode);
	if (error) {
		if (error != ETIME)
			NBDEBUG("peekhdr, error=%d\n", error);
		return (error);
	}
	NBDEBUG("Have pkt, type=0x%x len=0x%x\n",
	    (int)rpcode, (int)len);

	/*
	 * Block here waiting for the whole packet to arrive.
	 * If we get a timeout, return without side effects.
	 * The data length we wait for here includes both the
	 * NetBIOS header and the payload.
	 */
	error = nb_getmsg_mlen(nbp, &nbp->nbp_frag, len + 4);
	if (error) {
		NBDEBUG("getmsg(body), error=%d\n", error);
		return (error);
	}

	/*
	 * We now have an entire NetBIOS message.
	 * Trim off the NetBIOS header and consume it.
	 * Note: _peekhdr has done pullupmsg for us,
	 * so we know it's safe to advance b_rptr.
	 */
	m0 = nbp->nbp_frag;
	m0->b_rptr += 4;

	/*
	 * There may be more data after the message
	 * we're about to return, in which case we
	 * split it and leave the remainder.
	 */
	rlen = msgdsize(m0);
	ASSERT(rlen >= len);
	nbp->nbp_frag = NULL;
	if (rlen > len)
		nbp->nbp_frag = m_split(m0, len, 1);

	if (nbp->nbp_state != NBST_SESSION) {
		/*
		 * No session is established.
		 * Return whatever packet we got.
		 */
		goto out;
	}

	/*
	 * A session is established; the only packets
	 * we should see are session message and
	 * keep-alive packets.  Drop anything else.
	 */
	switch (rpcode) {

	case NB_SSN_KEEPALIVE:
		/*
		 * It's a keepalive.  Discard any data in it
		 * (there's not supposed to be any, but that
		 * doesn't mean some server won't send some)
		 */
		if (len)
			NBDEBUG("Keepalive with data %d\n", (int)len);
		error = EAGAIN;
		break;

	case NB_SSN_MESSAGE:
		/*
		 * Session message.  Does it have any data?
		 */
		if (len == 0) {
			/*
			 * No data - treat as keepalive (drop).
			 */
			error = EAGAIN;
			break;
		}
		/*
		 * Yes, has data.  Return it.
		 */
		error = 0;
		break;

	default:
		/*
		 * Drop anything else.
		 */
		NBDEBUG("non-session packet %x\n", rpcode);
		error = EAGAIN;
		break;
	}

out:
	if (error) {
		if (m0)
			m_freem(m0);
		return (error);
	}
	if (mpp)
		*mpp = m0;
	else
		m_freem(m0);
	*lenp = (int)len;
	*rpcodep = rpcode;
	return (0);
}

/*
 * SMB transport interface
 *
 * This is called only by the thread creating this endpoint,
 * so we're single-threaded here.
 */
/*ARGSUSED*/
static int
smb_nbst_create(struct smb_vc *vcp, cred_t *cr)
{
	struct nbpcb *nbp;

	nbp = kmem_zalloc(sizeof (struct nbpcb), KM_SLEEP);

	nbp->nbp_timo.tv_sec = SMB_NBTIMO;
	nbp->nbp_state = NBST_CLOSED; /* really IDLE */
	nbp->nbp_vc = vcp;
	nbp->nbp_sndbuf = smb_tcpsndbuf;
	nbp->nbp_rcvbuf = smb_tcprcvbuf;
	nbp->nbp_cred = cr;
	crhold(cr);
	mutex_init(&nbp->nbp_lock, NULL, MUTEX_DRIVER, NULL);
	vcp->vc_tdata = nbp;

	return (0);
}

/*
 * destroy a transport endpoint
 *
 * This is called only by the thread with the last reference
 * to this endpoint, so we're single-threaded here.
 */
static int
smb_nbst_done(struct smb_vc *vcp)
{
	struct nbpcb *nbp = vcp->vc_tdata;

	if (nbp == NULL)
		return (ENOTCONN);
	vcp->vc_tdata = NULL;

	/*
	 * Don't really need to disconnect here,
	 * because the close following will do it.
	 * But it's harmless.
	 */
	if (nbp->nbp_flags & NBF_CONNECTED)
		(void) nb_disconnect(nbp);
	if (nbp->nbp_tiptr)
		(void) t_kclose(nbp->nbp_tiptr, 0);
	if (nbp->nbp_laddr)
		smb_free_sockaddr((struct sockaddr *)nbp->nbp_laddr);
	if (nbp->nbp_paddr)
		smb_free_sockaddr((struct sockaddr *)nbp->nbp_paddr);
	if (nbp->nbp_cred)
		crfree(nbp->nbp_cred);
	mutex_destroy(&nbp->nbp_lock);
	kmem_free(nbp, sizeof (*nbp));
	return (0);
}

/*
 * Loan a transport file pointer (from user space) to this
 * IOD endpoint.  There should be no other thread using this
 * endpoint when we do this, but lock for consistency.
 */
static int
nb_loan_fp(struct nbpcb *nbp, struct file *fp, cred_t *cr)
{
	TIUSER *tiptr;
	int err;

	err = t_kopen(fp, 0, 0, &tiptr, cr);
	if (err != 0)
		return (err);

	mutex_enter(&nbp->nbp_lock);

	nbp->nbp_tiptr = tiptr;
	nbp->nbp_fmode = tiptr->fp->f_flag;
	nbp->nbp_flags |= NBF_CONNECTED;
	nbp->nbp_state = NBST_SESSION;

	mutex_exit(&nbp->nbp_lock);

	return (0);
}

/*
 * Take back the transport file pointer we previously loaned.
 * It's possible there may be another thread in here, so let
 * others get out of the way before we pull the rug out.
 *
 * Some notes about the locking here:  The higher-level IOD code
 * serializes activity such that at most one reader and writer
 * thread can be active in this code (and possibly both).
 * Keeping nbp_lock held during the activities of these two
 * threads would lead to the possibility of nbp_lock being
 * held by a blocked thread, so this instead sets one of the
 * flags (NBF_SENDLOCK | NBF_RECVLOCK) when a sender or a
 * receiver is active (respectively).  Lastly, tear-down is
 * the only tricky bit (here) where we must wait for any of
 * these activities to get out of current calls so they will
 * notice that we've turned off the NBF_CONNECTED flag.
 */
static void
nb_unloan_fp(struct nbpcb *nbp)
{

	mutex_enter(&nbp->nbp_lock);

	nbp->nbp_flags &= ~NBF_CONNECTED;
	while (nbp->nbp_flags & (NBF_SENDLOCK | NBF_RECVLOCK)) {
		nbp->nbp_flags |= NBF_LOCKWAIT;
		cv_wait(&nbp->nbp_cv, &nbp->nbp_lock);
	}
	if (nbp->nbp_frag != NULL) {
		freemsg(nbp->nbp_frag);
		nbp->nbp_frag = NULL;
	}
	if (nbp->nbp_tiptr != NULL) {
		(void) t_kclose(nbp->nbp_tiptr, 0);
		nbp->nbp_tiptr = NULL;
	}
	nbp->nbp_state = NBST_CLOSED;

	mutex_exit(&nbp->nbp_lock);
}

static int
smb_nbst_loan_fp(struct smb_vc *vcp, struct file *fp, cred_t *cr)
{
	struct nbpcb *nbp = vcp->vc_tdata;
	int error = 0;

	/*
	 * Un-loan the existing one, if any.
	 */
	(void) nb_disconnect(nbp);
	nb_unloan_fp(nbp);

	/*
	 * Loan the new one passed in.
	 */
	if (fp != NULL) {
		error = nb_loan_fp(nbp, fp, cr);
	}

	return (error);
}

/*ARGSUSED*/
static int
smb_nbst_bind(struct smb_vc *vcp, struct sockaddr *sap)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
smb_nbst_connect(struct smb_vc *vcp, struct sockaddr *sap)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
smb_nbst_disconnect(struct smb_vc *vcp)
{
	struct nbpcb *nbp = vcp->vc_tdata;

	if (nbp == NULL)
		return (ENOTCONN);

	return (nb_disconnect(nbp));
}

static int
nb_disconnect(struct nbpcb *nbp)
{
	int err = 0;

	mutex_enter(&nbp->nbp_lock);

	if ((nbp->nbp_flags & NBF_CONNECTED) != 0) {
		nbp->nbp_flags &= ~NBF_CONNECTED;
		err = nb_snddis(nbp);
	}

	mutex_exit(&nbp->nbp_lock);
	return (err);
}

/*
 * Add the NetBIOS session header and send.
 *
 * Calls to this are serialized at a higher level.
 */
static int
nbssn_send(struct nbpcb *nbp, mblk_t *m)
{
	ptrdiff_t diff;
	uint32_t mlen;
	int error;

	/* We should be the only sender. */
	ASSERT(nbp->nbp_flags & NBF_SENDLOCK);

	if (nbp->nbp_tiptr == NULL) {
		error = EBADF;
		goto errout;
	}

	/*
	 * Get the message length, which
	 * does NOT include the NetBIOS header
	 */
	mlen = msgdsize(m);

	/*
	 * Normally, mb_init() will have left space
	 * for us to prepend the NetBIOS header in
	 * the data block of the first mblk.
	 * However, we have to check in case other
	 * code did not leave this space, or if the
	 * message is from dupmsg (db_ref > 1)
	 *
	 * If don't find room in the first data block,
	 * we have to allocb a new message and link it
	 * on the front of the chain.  We try not to
	 * do this becuase it's less efficient.  Also,
	 * some network drivers will apparently send
	 * each mblk in the chain as separate frames.
	 * (That's arguably a driver bug.)
	 *
	 * Not bothering with allocb_cred_wait below
	 * because the message we're prepending to
	 * should already have a db_credp.
	 */

	diff = MBLKHEAD(m);
	if (diff == 4 && DB_REF(m) == 1) {
		/* We can use the first dblk. */
		m->b_rptr -= 4;
	} else {
		/* Link a new mblk on the head. */
		mblk_t *m0;

		/* M_PREPEND */
		m0 = allocb_wait(4, BPRI_LO, STR_NOSIG, &error);
		if (m0 == NULL)
			goto errout;

		m0->b_wptr += 4;
		m0->b_cont = m;
		m = m0;
	}

	nb_sethdr(m, NB_SSN_MESSAGE, mlen);
	error = tli_send(nbp->nbp_tiptr, m, 0);
	return (error);

errout:
	if (m != NULL)
		m_freem(m);
	return (error);
}

/*
 * Always consume the message.
 * (On error too!)
 */
static int
smb_nbst_send(struct smb_vc *vcp, mblk_t *m)
{
	struct nbpcb *nbp = vcp->vc_tdata;
	int err;

	mutex_enter(&nbp->nbp_lock);
	if ((nbp->nbp_flags & NBF_CONNECTED) == 0) {
		err = ENOTCONN;
		goto out;
	}
	if (nbp->nbp_flags & NBF_SENDLOCK) {
		NBDEBUG("multiple smb_nbst_send!\n");
		err = EWOULDBLOCK;
		goto out;
	}
	nbp->nbp_flags |= NBF_SENDLOCK;
	mutex_exit(&nbp->nbp_lock);

	err = nbssn_send(nbp, m);
	m = NULL; /* nbssn_send always consumes this */

	mutex_enter(&nbp->nbp_lock);
	nbp->nbp_flags &= ~NBF_SENDLOCK;
	if (nbp->nbp_flags & NBF_LOCKWAIT) {
		nbp->nbp_flags &= ~NBF_LOCKWAIT;
		cv_broadcast(&nbp->nbp_cv);
	}
out:
	mutex_exit(&nbp->nbp_lock);
	if (m != NULL)
		m_freem(m);
	return (err);
}

static int
smb_nbst_recv(struct smb_vc *vcp, mblk_t **mpp)
{
	struct nbpcb *nbp = vcp->vc_tdata;
	uint8_t rpcode;
	int err, rplen;

	mutex_enter(&nbp->nbp_lock);
	if ((nbp->nbp_flags & NBF_CONNECTED) == 0) {
		err = ENOTCONN;
		goto out;
	}
	if (nbp->nbp_flags & NBF_RECVLOCK) {
		NBDEBUG("multiple smb_nbst_recv!\n");
		err = EWOULDBLOCK;
		goto out;
	}
	nbp->nbp_flags |= NBF_RECVLOCK;
	mutex_exit(&nbp->nbp_lock);

	err = nbssn_recv(nbp, mpp, &rplen, &rpcode);

	mutex_enter(&nbp->nbp_lock);
	nbp->nbp_flags &= ~NBF_RECVLOCK;
	if (nbp->nbp_flags & NBF_LOCKWAIT) {
		nbp->nbp_flags &= ~NBF_LOCKWAIT;
		cv_broadcast(&nbp->nbp_cv);
	}
out:
	mutex_exit(&nbp->nbp_lock);
	return (err);
}

/*
 * Wait for up to "ticks" clock ticks for input on vcp.
 * Returns zero if input is available, otherwise ETIME
 * indicating time expired, or other error codes.
 */
/*ARGSUSED*/
static int
smb_nbst_poll(struct smb_vc *vcp, int ticks)
{
	return (ENOTSUP);
}

static int
smb_nbst_getparam(struct smb_vc *vcp, int param, void *data)
{
	struct nbpcb *nbp = vcp->vc_tdata;

	switch (param) {
	case SMBTP_SNDSZ:
		*(int *)data = nbp->nbp_sndbuf;
		break;
	case SMBTP_RCVSZ:
		*(int *)data = nbp->nbp_rcvbuf;
		break;
	case SMBTP_TIMEOUT:
		*(struct timespec *)data = nbp->nbp_timo;
		break;
#ifdef SMBTP_SELECTID
	case SMBTP_SELECTID:
		*(void **)data = nbp->nbp_selectid;
		break;
#endif
#ifdef SMBTP_UPCALL
	case SMBTP_UPCALL:
		*(void **)data = nbp->nbp_upcall;
		break;
#endif
	default:
		return (EINVAL);
	}
	return (0);
}

/*ARGSUSED*/
static int
smb_nbst_setparam(struct smb_vc *vcp, int param, void *data)
{
	return (EINVAL);
}

/*
 * Check for fatal errors
 */
/*ARGSUSED*/
static int
smb_nbst_fatal(struct smb_vc *vcp, int error)
{
	switch (error) {
	case ENOTCONN:
	case ENETRESET:
	case ECONNABORTED:
	case EPIPE:
		return (1);
	}
	return (0);
}


struct smb_tran_desc smb_tran_nbtcp_desc = {
	SMBT_NBTCP,
	smb_nbst_create,
	smb_nbst_done,
	smb_nbst_bind,
	smb_nbst_connect,
	smb_nbst_disconnect,
	smb_nbst_send,
	smb_nbst_recv,
	smb_nbst_poll,
	smb_nbst_loan_fp,
	smb_nbst_getparam,
	smb_nbst_setparam,
	smb_nbst_fatal,
	{NULL, NULL}
};
