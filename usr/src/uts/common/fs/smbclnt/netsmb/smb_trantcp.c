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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#ifdef APPLE
#include <sys/smb_apple.h>
#else
#include <netsmb/smb_osdep.h>
#endif

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

static dev_t smb_tcp_dev;

static int  nbssn_recv(struct nbpcb *nbp, mblk_t **mpp, int *lenp,
	uint8_t *rpcodep, struct proc *p);
static int  nb_disconnect(struct nbpcb *nbp);

static int
nb_wait_ack(TIUSER *tiptr, t_scalar_t ack_prim, int fmode)
{
	int			msgsz;
	union T_primitives	*pptr;
	mblk_t			*bp;
	ptrdiff_t	diff;
	int			error;

	/*
	 * wait for ack
	 */
	bp = NULL;
	if ((error = tli_recv(tiptr, &bp, fmode)) != 0)
		return (error);

	/*LINTED*/
	diff = MBLKL(bp);
	ASSERT(diff == (ptrdiff_t)((int)diff));
	msgsz = (int)diff;

	if (msgsz < sizeof (int)) {
		freemsg(bp);
		return (EPROTO);
	}

	/*LINTED*/
	pptr = (union T_primitives *)bp->b_rptr;
	if (pptr->type == ack_prim)
		error = 0; /* Success */
	else if (pptr->type == T_ERROR_ACK) {
		if (pptr->error_ack.TLI_error == TSYSERR)
			error = pptr->error_ack.UNIX_error;
		else
			error = t_tlitosyserr(pptr->error_ack.TLI_error);
	} else
		error = EPROTO;

	freemsg(bp);
	return (error);
}

/*
 * Internal set sockopt for int-sized options.
 * Is there a common Solaris function for this?
 * Code from uts/common/rpc/clnt_cots.c
 */
static int
nb_setsockopt_int(TIUSER *tiptr, int level, int name, int val)
{
	int fmode;
	mblk_t *mp;
	struct opthdr *opt;
	struct T_optmgmt_req *tor;
	int *valp;
	int error, mlen;

	mlen = (sizeof (struct T_optmgmt_req) +
	    sizeof (struct opthdr) + sizeof (int));
	if (!(mp = allocb_wait(mlen, BPRI_LO, STR_NOSIG, &error)))
		return (error);

	mp->b_datap->db_type = M_PROTO;
	/*LINTED*/
	tor = (struct T_optmgmt_req *)mp->b_wptr;
	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->MGMT_flags = T_NEGOTIATE;
	tor->OPT_length = sizeof (struct opthdr) + sizeof (int);
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	mp->b_wptr += sizeof (struct T_optmgmt_req);

	/*LINTED*/
	opt = (struct opthdr *)mp->b_wptr;
	opt->level = level;
	opt->name = name;
	opt->len = sizeof (int);
	mp->b_wptr += sizeof (struct opthdr);

	/* LINTED */
	valp = (int *)mp->b_wptr;
	*valp = val;
	mp->b_wptr += sizeof (int);

	fmode = tiptr->fp->f_flag;
	if ((error = tli_send(tiptr, mp, fmode)) != 0)
		return (error);

	fmode = 0; /* need to block */
	error = nb_wait_ack(tiptr, T_OPTMGMT_ACK, fmode);
	return (error);
}

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
			nb_disconnect(nbp);
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
nb_snddis(TIUSER *tiptr)
{
	mblk_t *mp;
	struct T_discon_req *dreq;
	int error, fmode, mlen;

	mlen = sizeof (struct T_discon_req);
	if (!(mp = allocb_wait(mlen, BPRI_LO, STR_NOSIG, &error)))
		return (error);

	mp->b_datap->db_type = M_PROTO;
	/*LINTED*/
	dreq = (struct T_discon_req *)mp->b_wptr;
	dreq->PRIM_type = T_DISCON_REQ;
	dreq->SEQ_number = -1;
	mp->b_wptr += sizeof (struct T_discon_req);

	fmode = tiptr->fp->f_flag;
	if ((error = tli_send(tiptr, mp, fmode)) != 0)
		return (error);

#if 0 /* Now letting the IOD recv this. */
	fmode = 0; /* need to block */
	error = nb_wait_ack(tiptr, T_OK_ACK, fmode);
#endif
	return (error);
}

#ifdef APPLE
static int
nb_intr(struct nbpcb *nbp, struct proc *p)
{
	return (0);
}
#endif

/*
 * Stuff the NetBIOS header into space already prepended.
 */
static int
nb_sethdr(mblk_t *m, uint8_t type, uint32_t len)
{
	uint32_t *p;

	len &= 0x1FFFF;
	len |= (type << 24);

	/*LINTED*/
	p = (uint32_t *)m->b_rptr;
	*p = htonl(len);
	return (0);
}

/*
 * Note: Moved name encoding into here.
 */
static int
nb_put_name(struct mbchain *mbp, struct sockaddr_nb *snb)
{
	int i, len;
	uchar_t ch, *p;

	/*
	 * Do the NetBIOS "first-level encoding" here.
	 * (RFC1002 explains this wierdness...)
	 * See similar code in smbfs library:
	 *   lib/libsmbfs/smb/nb_name.c
	 *
	 * Here is what we marshall:
	 *   uint8_t NAME_LENGTH (always 32)
	 *   uint8_t ENCODED_NAME[32]
	 *   uint8_t SCOPE_LENGTH
	 *   XXX Scope should follow here, then another null,
	 *   if and when we support NetBIOS scopes.
	 */
	len = 1 + (2 * NB_NAMELEN) + 1;

	p = mb_reserve(mbp, len);
	if (!p)
		return (ENOSR);

	/* NAME_LENGTH */
	*p++ = (2 * NB_NAMELEN);

	/* ENCODED_NAME */
	for (i = 0; i < NB_NAMELEN; i++) {
		ch = (uchar_t)snb->snb_name[i];
		*p++ = 'A' + ((ch >> 4) & 0xF);
		*p++ = 'A' + ((ch) & 0xF);
	}

	/* SCOPE_LENGTH */
	*p++ = 0;

	return (0);
}

static int
nb_tcpopen(struct nbpcb *nbp, struct proc *p)
{
	TIUSER *tiptr;
	int err, oflags = FREAD|FWRITE;
	cred_t *cr = p->p_cred;

	if (!smb_tcp_dev) {
		smb_tcp_dev = makedevice(
		    clone_major, ddi_name_to_major("tcp"));
	}

	/*
	 * This magic arranges for our network endpoint
	 * to have the right "label" for operation in a
	 * "trusted extensions" environment.
	 */
	if (is_system_labeled()) {
		cr = crdup(cr);
		(void) setpflags(NET_MAC_AWARE, 1, cr);
	} else {
		crhold(cr);
	}
	err = t_kopen(NULL, smb_tcp_dev, oflags, &tiptr, cr);
	crfree(cr);
	if (err)
		return (err);

	/* Note: I_PUSH "timod" is done by t_kopen */

	/* Save the TPI handle we use everywhere. */
	nbp->nbp_tiptr = tiptr;

	/*
	 * Internal ktli calls need the "fmode" flags
	 * from the t_kopen call.  XXX: Not sure if the
	 * flags have the right bits set, or if we
	 * always want the same block/non-block flags.
	 * XXX: Look into this...
	 */
	nbp->nbp_fmode = tiptr->fp->f_flag;
	return (0);
}

/*ARGSUSED*/
static int
nb_connect_in(struct nbpcb *nbp, struct sockaddr_in *to, struct proc *p)
{
	int error;
	TIUSER *tiptr = NULL;
	struct t_call call;

	tiptr = nbp->nbp_tiptr;
	if (tiptr == NULL)
		return (EBADF);
	if (nbp->nbp_flags & NBF_CONNECTED)
		return (EISCONN);

	/*
	 * Set various socket/TCP options.
	 * Failures here are not fatal -
	 * just log a complaint.
	 *
	 * We don't need these two:
	 *   SO_RCVTIMEO, SO_SNDTIMEO
	 */

	error = nb_setsockopt_int(tiptr, SOL_SOCKET, SO_SNDBUF,
	    nbp->nbp_sndbuf);
	if (error)
		NBDEBUG("nb_connect_in: set SO_SNDBUF");

	error = nb_setsockopt_int(tiptr, SOL_SOCKET, SO_RCVBUF,
	    nbp->nbp_rcvbuf);
	if (error)
		NBDEBUG("nb_connect_in: set SO_RCVBUF");

	error = nb_setsockopt_int(tiptr, SOL_SOCKET, SO_KEEPALIVE, 1);
	if (error)
		NBDEBUG("nb_connect_in: set SO_KEEPALIVE");

	error = nb_setsockopt_int(tiptr, IPPROTO_TCP, TCP_NODELAY, 1);
	if (error)
		NBDEBUG("nb_connect_in: set TCP_NODELAY");

	/* Do local bind (any address) */
	if ((error = t_kbind(tiptr, NULL, NULL)) != 0) {
		NBDEBUG("nb_connect_in: bind local");
		return (error);
	}

	/*
	 * Setup (snd)call address (connect to).
	 * Just pass NULL for the (rcv)call.
	 */
	bzero(&call, sizeof (call));
	call.addr.len = sizeof (*to);
	call.addr.buf = (char *)to;
	/* call.opt - none */
	/* call.udata -- XXX: Should put NB session req here! */

	/* Send the connect, wait... */
	error = t_kconnect(tiptr, &call, NULL);
	if (error) {
		NBDEBUG("nb_connect_in: connect %d error", error);
		/*
		 * XXX: t_kconnect returning EPROTO here instead of ETIMEDOUT
		 * here. Temporarily return ETIMEDOUT error if we get EPROTO.
		 */
		if (error == EPROTO)
			error = ETIMEDOUT;
	} else {
		mutex_enter(&nbp->nbp_lock);
		nbp->nbp_flags |= NBF_CONNECTED;
		mutex_exit(&nbp->nbp_lock);
	}

	return (error);
}

static int
nbssn_rq_request(struct nbpcb *nbp, struct proc *p)
{
	struct mbchain mb, *mbp = &mb;
	struct mdchain md, *mdp = &md;
	mblk_t *m0;
	struct sockaddr_in sin;
	ushort_t port;
	uint8_t rpcode;
	int error, rplen;

	error = mb_init(mbp);
	if (error)
		return (error);

	/*
	 * Put a zero for the 4-byte NetBIOS header,
	 * then let nb_sethdr() overwrite it.
	 */
	mb_put_uint32le(mbp, 0);
	nb_put_name(mbp, nbp->nbp_paddr);
	nb_put_name(mbp, nbp->nbp_laddr);
	nb_sethdr(mbp->mb_top, NB_SSN_REQUEST, mb_fixhdr(mbp) - 4);

	m0 = mb_detach(mbp);
	error = tli_send(nbp->nbp_tiptr, m0, nbp->nbp_fmode);
	m0 = NULL; /* Note: _always_ consumed by tli_send */
	mb_done(mbp);
	if (error)
		return (error);

	nbp->nbp_state = NBST_RQSENT;
	error = nbssn_recv(nbp, &m0, &rplen, &rpcode, p);
	if (error == EWOULDBLOCK) {	/* Timeout */
		NBDEBUG("initial request timeout\n");
		return (ETIMEDOUT);
	}
	if (error) {
		NBDEBUG("recv() error %d\n", error);
		return (error);
	}
	/*
	 * Process NETBIOS reply
	 */
	if (m0)
		md_initm(mdp, m0);

	error = 0;
	if (rpcode == NB_SSN_POSRESP) {
		mutex_enter(&nbp->nbp_lock);
		nbp->nbp_state = NBST_SESSION;
		mutex_exit(&nbp->nbp_lock);
		goto out;
	}
	if (rpcode != NB_SSN_RTGRESP) {
		error = ECONNABORTED;
		goto out;
	}
	if (rplen != 6) {
		error = ECONNABORTED;
		goto out;
	}
	md_get_mem(mdp, (caddr_t)&sin.sin_addr, 4, MB_MSYSTEM);
	md_get_uint16(mdp, &port);
	sin.sin_port = port;
	nbp->nbp_state = NBST_RETARGET;
	nb_disconnect(nbp);
	error = nb_connect_in(nbp, &sin, p);
	if (!error)
		error = nbssn_rq_request(nbp, p);
	if (error) {
		nb_disconnect(nbp);
	}

out:
	if (m0)
		md_done(mdp);
	return (error);
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
	if (len > SMB_MAXPKTLEN) {
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
 */
/*ARGSUSED*/
static int
nbssn_recv(struct nbpcb *nbp, mblk_t **mpp, int *lenp,
    uint8_t *rpcodep, struct proc *p)
{
	TIUSER *tiptr = nbp->nbp_tiptr;
	mblk_t *m0;
	uint8_t rpcode;
	int error;
	size_t rlen, len;

	/* We should be the only reader. */
	ASSERT(nbp->nbp_flags & NBF_RECVLOCK);

	if (tiptr == NULL)
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
 */
static int
smb_nbst_create(struct smb_vc *vcp, struct proc *p)
{
	struct nbpcb *nbp;
	int error;

	nbp = kmem_zalloc(sizeof (struct nbpcb), KM_SLEEP);

	/*
	 * We don't keep reference counts or otherwise
	 * prevent nbp->nbp_tiptr from going away, so
	 * do the TLI open here and keep it until the
	 * last ref calls smb_nbst_done.
	 * This does t_kopen (open endpoint)
	 */
	error = nb_tcpopen(nbp, p);
	if (error) {
		kmem_free(nbp, sizeof (*nbp));
		return (error);
	}

	nbp->nbp_timo.tv_sec = SMB_NBTIMO;
	nbp->nbp_state = NBST_CLOSED; /* really IDLE */
	nbp->nbp_vc = vcp;
	nbp->nbp_sndbuf = smb_tcpsndbuf;
	nbp->nbp_rcvbuf = smb_tcprcvbuf;
	mutex_init(&nbp->nbp_lock, NULL, MUTEX_DRIVER, NULL);
	vcp->vc_tdata = nbp;
	return (0);
}

/*ARGSUSED*/
static int
smb_nbst_done(struct smb_vc *vcp, struct proc *p)
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
		nb_disconnect(nbp);
	if (nbp->nbp_tiptr)
		t_kclose(nbp->nbp_tiptr, 1);
	if (nbp->nbp_laddr)
		smb_free_sockaddr((struct sockaddr *)nbp->nbp_laddr);
	if (nbp->nbp_paddr)
		smb_free_sockaddr((struct sockaddr *)nbp->nbp_paddr);
	mutex_destroy(&nbp->nbp_lock);
	kmem_free(nbp, sizeof (*nbp));
	return (0);
}

/*ARGSUSED*/
static int
smb_nbst_bind(struct smb_vc *vcp, struct sockaddr *sap, struct proc *p)
{
	struct nbpcb *nbp = vcp->vc_tdata;
	struct sockaddr_nb *snb;
	int error;

	NBDEBUG("\n");
	error = EINVAL;

	if (nbp->nbp_flags & NBF_LOCADDR)
		goto out;

	/*
	 * Null name is an "anonymous" (NULL) bind request.
	 * (Let the transport pick a local name.)
	 * This transport does not support NULL bind.
	 */
	if (sap == NULL)
		goto out;

	/*LINTED*/
	snb = (struct sockaddr_nb *)smb_dup_sockaddr(sap);
	if (snb == NULL) {
		error = ENOMEM;
		goto out;
	}
	mutex_enter(&nbp->nbp_lock);
	nbp->nbp_laddr = snb;
	nbp->nbp_flags |= NBF_LOCADDR;
	mutex_exit(&nbp->nbp_lock);
	error = 0;

out:
	return (error);
}

static int
smb_nbst_connect(struct smb_vc *vcp, struct sockaddr *sap, struct proc *p)
{
	struct nbpcb *nbp = vcp->vc_tdata;
	struct sockaddr_in sin;
	struct sockaddr_nb *snb;
	struct timespec ts1, ts2;
	int error;

	NBDEBUG("\n");
	if (nbp->nbp_tiptr == NULL)
		return (EBADF);
	if (nbp->nbp_laddr == NULL)
		return (EINVAL);

	/*
	 * Note: nbssn_rq_request() will call nbssn_recv(),
	 * so set the RECVLOCK flag here.  Otherwise we'll
	 * hit an ASSERT for this flag in nbssn_recv().
	 */
	mutex_enter(&nbp->nbp_lock);
	if (nbp->nbp_flags & NBF_RECVLOCK) {
		NBDEBUG("attempt to reenter session layer!\n");
		mutex_exit(&nbp->nbp_lock);
		return (EWOULDBLOCK);
	}
	nbp->nbp_flags |= NBF_RECVLOCK;
	mutex_exit(&nbp->nbp_lock);

	/*LINTED*/
	snb = (struct sockaddr_nb *)smb_dup_sockaddr(sap);
	if (snb == NULL) {
		error = ENOMEM;
		goto out;
	}
	if (nbp->nbp_paddr)
		smb_free_sockaddr((struct sockaddr *)nbp->nbp_paddr);
	nbp->nbp_paddr = snb;

	/* Setup the remote IP address. */
	bzero(&sin, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(SMB_TCP_PORT);
	sin.sin_addr.s_addr = snb->snb_ipaddr;

	/*
	 * For our general timeout we use the greater of
	 * the default (15 sec) and 4 times the time it
	 * took for the first round trip.  We used to use
	 * just the latter, but sometimes if the first
	 * round trip is very fast the subsequent 4 sec
	 * timeouts are simply too short.
	 */
	gethrestime(&ts1);
	error = nb_connect_in(nbp, &sin, p);
	if (error)
		goto out;
	gethrestime(&ts2);
	timespecsub(&ts2, &ts1);
	timespecadd(&ts2, &ts2);
	timespecadd(&ts2, &ts2);	/*  * 4 */
	/*CSTYLED*/
	if (timespeccmp(&ts2, (&(nbp->nbp_timo)), >))
		nbp->nbp_timo = ts2;
	error = nbssn_rq_request(nbp, p);
	if (error)
		nb_disconnect(nbp);
out:
	mutex_enter(&nbp->nbp_lock);
	nbp->nbp_flags &= ~NBF_RECVLOCK;
	mutex_exit(&nbp->nbp_lock);

	return (error);
}

/*ARGSUSED*/
static int
smb_nbst_disconnect(struct smb_vc *vcp, struct proc *p)
{
	struct nbpcb *nbp = vcp->vc_tdata;

	if (nbp == NULL)
		return (ENOTCONN);

	return (nb_disconnect(nbp));
}

static int
nb_disconnect(struct nbpcb *nbp)
{
	TIUSER *tiptr;
	int save_flags;

	tiptr = nbp->nbp_tiptr;
	if (tiptr == NULL)
		return (EBADF);

	mutex_enter(&nbp->nbp_lock);
	save_flags = nbp->nbp_flags;
	nbp->nbp_flags &= ~NBF_CONNECTED;
	if (nbp->nbp_frag) {
		freemsg(nbp->nbp_frag);
		nbp->nbp_frag = NULL;
	}
	mutex_exit(&nbp->nbp_lock);

	if (save_flags & NBF_CONNECTED)
		nb_snddis(tiptr);

	if (nbp->nbp_state != NBST_RETARGET) {
		nbp->nbp_state = NBST_CLOSED; /* really IDLE */
	}
	return (0);
}

/*
 * Always consume the message.
 * (On error too!)
 */
/*ARGSUSED*/
static int
smb_nbst_send(struct smb_vc *vcp, mblk_t *m, struct proc *p)
{
	struct nbpcb *nbp = vcp->vc_tdata;
	ptrdiff_t diff;
	uint32_t mlen;
	int error;

	if (nbp == NULL || nbp->nbp_tiptr == NULL) {
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
	 */

	/* LINTED */
	diff = MBLKHEAD(m);
	if (diff == 4 && DB_REF(m) == 1) {
		/* We can use the first dblk. */
		m->b_rptr -= 4;
	} else {
		/* Link a new mblk on the head. */
		mblk_t *m0;

		/* M_PREPEND */
		m0 = allocb_wait(4, BPRI_LO, STR_NOSIG, &error);
		if (!m0)
			goto errout;

		m0->b_wptr += 4;
		m0->b_cont = m;
		m = m0;
	}

	nb_sethdr(m, NB_SSN_MESSAGE, mlen);
	error = tli_send(nbp->nbp_tiptr, m, 0);
	return (error);

errout:
	if (m)
		m_freem(m);
	return (error);
}


static int
smb_nbst_recv(struct smb_vc *vcp, mblk_t **mpp, struct proc *p)
{
	struct nbpcb *nbp = vcp->vc_tdata;
	uint8_t rpcode;
	int error, rplen;

	mutex_enter(&nbp->nbp_lock);
	if (nbp->nbp_flags & NBF_RECVLOCK) {
		NBDEBUG("attempt to reenter session layer!\n");
		mutex_exit(&nbp->nbp_lock);
		return (EWOULDBLOCK);
	}
	nbp->nbp_flags |= NBF_RECVLOCK;
	mutex_exit(&nbp->nbp_lock);
	error = nbssn_recv(nbp, mpp, &rplen, &rpcode, p);
	mutex_enter(&nbp->nbp_lock);
	nbp->nbp_flags &= ~NBF_RECVLOCK;
	mutex_exit(&nbp->nbp_lock);
	return (error);
}

/*
 * Wait for up to "ticks" clock ticks for input on vcp.
 * Returns zero if input is available, otherwise ETIME
 * indicating time expired, or other error codes.
 */
/*ARGSUSED*/
static int
smb_nbst_poll(struct smb_vc *vcp, int ticks, struct proc *p)
{
	int error;
	int events = 0;
	int waitflg = READWAIT;
	struct nbpcb *nbp = vcp->vc_tdata;

	error = t_kspoll(nbp->nbp_tiptr, ticks, waitflg, &events);
	if (!error && !events)
		error = ETIME;

	return (error);
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
	smb_nbst_getparam,
	smb_nbst_setparam,
	smb_nbst_fatal,
	{NULL, NULL}
};
