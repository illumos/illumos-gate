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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/socketvar.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ip6.h>
#include <inet/sctp_ip.h>
#include <inet/ipclassifier.h>

/*
 * PR-SCTP comments.
 *
 * A message can expire before it gets to the transmit list (i.e. it is still
 * in the unsent list - unchunked), after it gets to the transmit list, but
 * before transmission has actually started, or after transmission has begun.
 * Accordingly, we check for the status of a message in sctp_chunkify() when
 * the message is being transferred from the unsent list to the transmit list;
 * in sctp_get_msg_to_send(), when we get the next chunk from the transmit
 * list and in sctp_rexmit() when we get the next chunk to be (re)transmitted.
 * When we nuke a message in sctp_chunkify(), all we need to do is take it
 * out of the unsent list and update sctp_unsent; when a message is deemed
 * timed-out in sctp_get_msg_to_send() we can just take it out of the transmit
 * list, update sctp_unsent IFF transmission for the message has not yet begun
 * (i.e. !SCTP_CHUNK_ISSENT(meta->b_cont)). However, if transmission for the
 * message has started, then we cannot just take it out of the list, we need
 * to send Forward TSN chunk to the peer so that the peer can clear its
 * fragment list for this message. However, we cannot just send the Forward
 * TSN in sctp_get_msg_to_send() because there might be unacked chunks for
 * messages preceeding this abandoned message. So, we send a Forward TSN
 * IFF all messages prior to this abandoned message has been SACKd, if not
 * we defer sending the Forward TSN to sctp_cumack(), which will check for
 * this condition and send the Forward TSN via sctp_check_abandoned_msg(). In
 * sctp_rexmit() when we check for retransmissions, we need to determine if
 * the advanced peer ack point can be moved ahead, and if so, send a Forward
 * TSN to the peer instead of retransmitting the chunk. Note that when
 * we send a Forward TSN for a message, there may be yet unsent chunks for
 * this message; we need to mark all such chunks as abandoned, so that
 * sctp_cumack() can take the message out of the transmit list, additionally
 * sctp_unsent need to be adjusted. Whenever sctp_unsent is updated (i.e.
 * decremented when a message/chunk is deemed abandoned), sockfs needs to
 * be notified so that it can adjust its idea of the queued message.
 */

#include "sctp_impl.h"

static struct kmem_cache	*sctp_kmem_ftsn_set_cache;
static mblk_t			*sctp_chunkify(sctp_t *, int, int, int);

#ifdef	DEBUG
static boolean_t	sctp_verify_chain(mblk_t *, mblk_t *);
#endif

/*
 * Called to allocate a header mblk when sending data to SCTP.
 * Data will follow in b_cont of this mblk.
 */
mblk_t *
sctp_alloc_hdr(const char *name, int nlen, const char *control, int clen,
    int flags)
{
	mblk_t *mp;
	struct T_unitdata_req *tudr;
	size_t size;
	int error;

	size = sizeof (*tudr) + _TPI_ALIGN_TOPT(nlen) + clen;
	size = MAX(size, sizeof (sctp_msg_hdr_t));
	if (flags & SCTP_CAN_BLOCK) {
		mp = allocb_wait(size, BPRI_MED, 0, &error);
	} else {
		mp = allocb(size, BPRI_MED);
	}
	if (mp) {
		tudr = (struct T_unitdata_req *)mp->b_rptr;
		tudr->PRIM_type = T_UNITDATA_REQ;
		tudr->DEST_length = nlen;
		tudr->DEST_offset = sizeof (*tudr);
		tudr->OPT_length = clen;
		tudr->OPT_offset = (t_scalar_t)(sizeof (*tudr) +
		    _TPI_ALIGN_TOPT(nlen));
		if (nlen > 0)
			bcopy(name, tudr + 1, nlen);
		if (clen > 0)
			bcopy(control, (char *)tudr + tudr->OPT_offset, clen);
		mp->b_wptr += (tudr ->OPT_offset + clen);
		mp->b_datap->db_type = M_PROTO;
	}
	return (mp);
}

/*ARGSUSED2*/
int
sctp_sendmsg(sctp_t *sctp, mblk_t *mp, int flags)
{
	sctp_faddr_t	*fp = NULL;
	struct T_unitdata_req	*tudr;
	int		error = 0;
	mblk_t		*mproto = mp;
	in6_addr_t	*addr;
	in6_addr_t	tmpaddr;
	uint16_t	sid = sctp->sctp_def_stream;
	uint32_t	ppid = sctp->sctp_def_ppid;
	uint32_t	context = sctp->sctp_def_context;
	uint16_t	msg_flags = sctp->sctp_def_flags;
	sctp_msg_hdr_t	*sctp_msg_hdr;
	uint32_t	msg_len = 0;
	uint32_t	timetolive = sctp->sctp_def_timetolive;
	conn_t		*connp = sctp->sctp_connp;

	ASSERT(DB_TYPE(mproto) == M_PROTO);

	mp = mp->b_cont;
	ASSERT(mp == NULL || DB_TYPE(mp) == M_DATA);

	tudr = (struct T_unitdata_req *)mproto->b_rptr;
	ASSERT(tudr->PRIM_type == T_UNITDATA_REQ);

	/* Get destination address, if specified */
	if (tudr->DEST_length > 0) {
		sin_t *sin;
		sin6_t *sin6;

		sin = (struct sockaddr_in *)
		    (mproto->b_rptr + tudr->DEST_offset);
		switch (sin->sin_family) {
		case AF_INET:
			if (tudr->DEST_length < sizeof (*sin)) {
				return (EINVAL);
			}
			IN6_IPADDR_TO_V4MAPPED(sin->sin_addr.s_addr, &tmpaddr);
			addr = &tmpaddr;
			break;
		case AF_INET6:
			if (tudr->DEST_length < sizeof (*sin6)) {
				return (EINVAL);
			}
			sin6 = (struct sockaddr_in6 *)
			    (mproto->b_rptr + tudr->DEST_offset);
			addr = &sin6->sin6_addr;
			break;
		default:
			return (EAFNOSUPPORT);
		}
		fp = sctp_lookup_faddr(sctp, addr);
		if (fp == NULL) {
			return (EINVAL);
		}
	}
	/* Ancillary Data? */
	if (tudr->OPT_length > 0) {
		struct cmsghdr		*cmsg;
		char			*cend;
		struct sctp_sndrcvinfo	*sndrcv;

		cmsg = (struct cmsghdr *)(mproto->b_rptr + tudr->OPT_offset);
		cend = ((char *)cmsg + tudr->OPT_length);
		ASSERT(cend <= (char *)mproto->b_wptr);

		for (;;) {
			if ((char *)(cmsg + 1) > cend ||
			    ((char *)cmsg + cmsg->cmsg_len) > cend) {
				break;
			}
			if ((cmsg->cmsg_level == IPPROTO_SCTP) &&
			    (cmsg->cmsg_type == SCTP_SNDRCV)) {
				if (cmsg->cmsg_len <
				    (sizeof (*sndrcv) + sizeof (*cmsg))) {
					return (EINVAL);
				}
				sndrcv = (struct sctp_sndrcvinfo *)(cmsg + 1);
				sid = sndrcv->sinfo_stream;
				msg_flags = sndrcv->sinfo_flags;
				ppid = sndrcv->sinfo_ppid;
				context = sndrcv->sinfo_context;
				timetolive = sndrcv->sinfo_timetolive;
				break;
			}
			if (cmsg->cmsg_len > 0)
				cmsg = CMSG_NEXT(cmsg);
			else
				break;
		}
	}
	if (msg_flags & MSG_ABORT) {
		if (mp && mp->b_cont) {
			mblk_t *pump = msgpullup(mp, -1);
			if (!pump) {
				return (ENOMEM);
			}
			freemsg(mp);
			mp = pump;
			mproto->b_cont = mp;
		}
		RUN_SCTP(sctp);
		sctp_user_abort(sctp, mp);
		freemsg(mproto);
		goto done2;
	}
	if (mp == NULL)
		goto done;

	RUN_SCTP(sctp);

	/* Reject any new data requests if we are shutting down */
	if (sctp->sctp_state > SCTPS_ESTABLISHED ||
	    (sctp->sctp_connp->conn_state_flags & CONN_CLOSING)) {
		error = EPIPE;
		goto unlock_done;
	}

	/* Re-use the mproto to store relevant info. */
	ASSERT(MBLKSIZE(mproto) >= sizeof (*sctp_msg_hdr));

	mproto->b_rptr = mproto->b_datap->db_base;
	mproto->b_wptr = mproto->b_rptr + sizeof (*sctp_msg_hdr);

	sctp_msg_hdr = (sctp_msg_hdr_t *)mproto->b_rptr;
	bzero(sctp_msg_hdr, sizeof (*sctp_msg_hdr));
	sctp_msg_hdr->smh_context = context;
	sctp_msg_hdr->smh_sid = sid;
	sctp_msg_hdr->smh_ppid = ppid;
	sctp_msg_hdr->smh_flags = msg_flags;
	sctp_msg_hdr->smh_ttl = MSEC_TO_TICK(timetolive);
	sctp_msg_hdr->smh_tob = ddi_get_lbolt64();
	for (; mp != NULL; mp = mp->b_cont)
		msg_len += MBLKL(mp);
	sctp_msg_hdr->smh_msglen = msg_len;

	/* User requested specific destination */
	SCTP_SET_CHUNK_DEST(mproto, fp);

	if (sctp->sctp_state >= SCTPS_COOKIE_ECHOED &&
	    sid >= sctp->sctp_num_ostr) {
		/* Send sendfail event */
		sctp_sendfail_event(sctp, dupmsg(mproto), SCTP_ERR_BAD_SID,
		    B_FALSE);
		error = EINVAL;
		goto unlock_done;
	}

	/* no data */
	if (msg_len == 0) {
		sctp_sendfail_event(sctp, dupmsg(mproto),
		    SCTP_ERR_NO_USR_DATA, B_FALSE);
		error = EINVAL;
		goto unlock_done;
	}

	/* Add it to the unsent list */
	if (sctp->sctp_xmit_unsent == NULL) {
		sctp->sctp_xmit_unsent = sctp->sctp_xmit_unsent_tail = mproto;
	} else {
		sctp->sctp_xmit_unsent_tail->b_next = mproto;
		sctp->sctp_xmit_unsent_tail = mproto;
	}
	sctp->sctp_unsent += msg_len;
	BUMP_LOCAL(sctp->sctp_msgcount);
	/*
	 * Notify sockfs if the tx queue is full.
	 */
	if (SCTP_TXQ_LEN(sctp) >= connp->conn_sndbuf) {
		sctp->sctp_txq_full = 1;
		sctp->sctp_ulp_txq_full(sctp->sctp_ulpd, B_TRUE);
	}
	if (sctp->sctp_state == SCTPS_ESTABLISHED)
		sctp_output(sctp, UINT_MAX);
done2:
	WAKE_SCTP(sctp);
	return (0);
unlock_done:
	WAKE_SCTP(sctp);
done:
	return (error);
}

/*
 * While there are messages on sctp_xmit_unsent, detach each one. For each:
 * allocate space for the chunk header, fill in the data chunk, and fill in
 * the chunk header. Then append it to sctp_xmit_tail.
 * Return after appending as many bytes as required (bytes_to_send).
 * We also return if we've appended one or more chunks, and find a subsequent
 * unsent message is too big to fit in the segment.
 */
mblk_t *
sctp_chunkify(sctp_t *sctp, int mss, int firstseg_len, int bytes_to_send)
{
	mblk_t			*mp;
	mblk_t			*chunk_mp;
	mblk_t			*chunk_head;
	mblk_t			*chunk_hdr;
	mblk_t			*chunk_tail = NULL;
	int			count;
	int			chunksize;
	sctp_data_hdr_t		*sdc;
	mblk_t			*mdblk = sctp->sctp_xmit_unsent;
	sctp_faddr_t		*fp;
	sctp_faddr_t		*fp1;
	size_t			xtralen;
	sctp_msg_hdr_t		*msg_hdr;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	sctp_msg_hdr_t		*next_msg_hdr;
	size_t			nextlen;
	int			remaining_len = mss - firstseg_len;

	ASSERT(remaining_len >= 0);

	fp = SCTP_CHUNK_DEST(mdblk);
	if (fp == NULL)
		fp = sctp->sctp_current;
	if (fp->sf_isv4)
		xtralen = sctp->sctp_hdr_len + sctps->sctps_wroff_xtra +
		    sizeof (*sdc);
	else
		xtralen = sctp->sctp_hdr6_len + sctps->sctps_wroff_xtra +
		    sizeof (*sdc);
	count = chunksize = remaining_len - sizeof (*sdc);
nextmsg:
	next_msg_hdr = (sctp_msg_hdr_t *)sctp->sctp_xmit_unsent->b_rptr;
	nextlen = next_msg_hdr->smh_msglen;
	/*
	 * Will the entire next message fit in the current packet ?
	 * if not, leave it on the unsent list.
	 */
	if ((firstseg_len != 0) && (nextlen > remaining_len))
		return (NULL);

	chunk_mp = mdblk->b_cont;

	/*
	 * If this partially chunked, we ignore the next one for now and
	 * use the one already present. For the unchunked bits, we use the
	 * length of the last chunk.
	 */
	if (SCTP_IS_MSG_CHUNKED(mdblk)) {
		int	chunk_len;

		ASSERT(chunk_mp->b_next != NULL);
		mdblk->b_cont = chunk_mp->b_next;
		chunk_mp->b_next = NULL;
		SCTP_MSG_CLEAR_CHUNKED(mdblk);
		mp = mdblk->b_cont;
		while (mp->b_next != NULL)
			mp = mp->b_next;
		chunk_len = ntohs(((sctp_data_hdr_t *)mp->b_rptr)->sdh_len);
		if (fp->sf_pmss - chunk_len > sizeof (*sdc))
			count = chunksize = fp->sf_pmss - chunk_len;
		else
			count = chunksize = fp->sf_pmss;
		count = chunksize = count - sizeof (*sdc);
	} else {
		msg_hdr = (sctp_msg_hdr_t *)mdblk->b_rptr;
		if (SCTP_MSG_TO_BE_ABANDONED(mdblk, msg_hdr, sctp)) {
			sctp->sctp_xmit_unsent = mdblk->b_next;
			if (sctp->sctp_xmit_unsent == NULL)
				sctp->sctp_xmit_unsent_tail = NULL;
			ASSERT(sctp->sctp_unsent >= msg_hdr->smh_msglen);
			sctp->sctp_unsent -= msg_hdr->smh_msglen;
			mdblk->b_next = NULL;
			BUMP_LOCAL(sctp->sctp_prsctpdrop);
			/*
			 * Update ULP the amount of queued data, which is
			 * sent-unack'ed + unsent.
			 */
			if (!SCTP_IS_DETACHED(sctp))
				SCTP_TXQ_UPDATE(sctp);
			sctp_sendfail_event(sctp, mdblk, 0, B_FALSE);
			goto try_next;
		}
		mdblk->b_cont = NULL;
	}
	msg_hdr = (sctp_msg_hdr_t *)mdblk->b_rptr;
nextchunk:
	chunk_head = chunk_mp;
	chunk_tail = NULL;

	/* Skip as many mblk's as we need */
	while (chunk_mp != NULL && ((count - MBLKL(chunk_mp)) >= 0)) {
		count -= MBLKL(chunk_mp);
		chunk_tail = chunk_mp;
		chunk_mp = chunk_mp->b_cont;
	}
	/* Split the chain, if needed */
	if (chunk_mp != NULL) {
		if (count > 0) {
			mblk_t	*split_mp = dupb(chunk_mp);

			if (split_mp == NULL) {
				if (mdblk->b_cont == NULL) {
					mdblk->b_cont = chunk_head;
				} else  {
					SCTP_MSG_SET_CHUNKED(mdblk);
					ASSERT(chunk_head->b_next == NULL);
					chunk_head->b_next = mdblk->b_cont;
					mdblk->b_cont = chunk_head;
				}
				return (sctp->sctp_xmit_tail);
			}
			if (chunk_tail != NULL) {
				chunk_tail->b_cont = split_mp;
				chunk_tail = chunk_tail->b_cont;
			} else {
				chunk_head = chunk_tail = split_mp;
			}
			chunk_tail->b_wptr = chunk_tail->b_rptr + count;
			chunk_mp->b_rptr = chunk_tail->b_wptr;
			count = 0;
		} else if (chunk_tail == NULL) {
			goto next;
		} else {
			chunk_tail->b_cont = NULL;
		}
	}
	/* Alloc chunk hdr, if needed */
	if (DB_REF(chunk_head) > 1 ||
	    ((intptr_t)chunk_head->b_rptr) & (SCTP_ALIGN - 1) ||
	    MBLKHEAD(chunk_head) < sizeof (*sdc)) {
		if ((chunk_hdr = allocb(xtralen, BPRI_MED)) == NULL) {
			if (mdblk->b_cont == NULL) {
				if (chunk_mp != NULL)
					linkb(chunk_head, chunk_mp);
				mdblk->b_cont = chunk_head;
			} else {
				SCTP_MSG_SET_CHUNKED(mdblk);
				if (chunk_mp != NULL)
					linkb(chunk_head, chunk_mp);
				ASSERT(chunk_head->b_next == NULL);
				chunk_head->b_next = mdblk->b_cont;
				mdblk->b_cont = chunk_head;
			}
			return (sctp->sctp_xmit_tail);
		}
		chunk_hdr->b_rptr += xtralen - sizeof (*sdc);
		chunk_hdr->b_wptr = chunk_hdr->b_rptr + sizeof (*sdc);
		chunk_hdr->b_cont = chunk_head;
	} else {
		chunk_hdr = chunk_head;
		chunk_hdr->b_rptr -= sizeof (*sdc);
	}
	ASSERT(chunk_hdr->b_datap->db_ref == 1);
	sdc = (sctp_data_hdr_t *)chunk_hdr->b_rptr;
	sdc->sdh_id = CHUNK_DATA;
	sdc->sdh_flags = 0;
	sdc->sdh_len = htons(sizeof (*sdc) + chunksize - count);
	ASSERT(sdc->sdh_len);
	sdc->sdh_sid = htons(msg_hdr->smh_sid);
	/*
	 * We defer assigning the SSN just before sending the chunk, else
	 * if we drop the chunk in sctp_get_msg_to_send(), we would need
	 * to send a Forward TSN to let the peer know. Some more comments
	 * about this in sctp_impl.h for SCTP_CHUNK_SENT.
	 */
	sdc->sdh_payload_id = msg_hdr->smh_ppid;

	if (mdblk->b_cont == NULL) {
		mdblk->b_cont = chunk_hdr;
		SCTP_DATA_SET_BBIT(sdc);
	} else {
		mp = mdblk->b_cont;
		while (mp->b_next != NULL)
			mp = mp->b_next;
		mp->b_next = chunk_hdr;
	}

	bytes_to_send -= (chunksize - count);
	if (chunk_mp != NULL) {
next:
		count = chunksize = fp->sf_pmss - sizeof (*sdc);
		goto nextchunk;
	}
	SCTP_DATA_SET_EBIT(sdc);
	sctp->sctp_xmit_unsent = mdblk->b_next;
	if (mdblk->b_next == NULL) {
		sctp->sctp_xmit_unsent_tail = NULL;
	}
	mdblk->b_next = NULL;

	if (sctp->sctp_xmit_tail == NULL) {
		sctp->sctp_xmit_head = sctp->sctp_xmit_tail = mdblk;
	} else {
		mp = sctp->sctp_xmit_tail;
		while (mp->b_next != NULL)
			mp = mp->b_next;
		mp->b_next = mdblk;
		mdblk->b_prev = mp;
	}
try_next:
	if (bytes_to_send > 0 && sctp->sctp_xmit_unsent != NULL) {
		mdblk = sctp->sctp_xmit_unsent;
		fp1 = SCTP_CHUNK_DEST(mdblk);
		if (fp1 == NULL)
			fp1 = sctp->sctp_current;
		if (fp == fp1) {
			size_t len = MBLKL(mdblk->b_cont);
			if ((count > 0) &&
			    ((len > fp->sf_pmss - sizeof (*sdc)) ||
			    (len <= count))) {
				count -= sizeof (*sdc);
				count = chunksize = count - (count & 0x3);
			} else {
				count = chunksize = fp->sf_pmss -
				    sizeof (*sdc);
			}
		} else {
			if (fp1->sf_isv4)
				xtralen = sctp->sctp_hdr_len;
			else
				xtralen = sctp->sctp_hdr6_len;
			xtralen += sctps->sctps_wroff_xtra + sizeof (*sdc);
			count = chunksize = fp1->sf_pmss - sizeof (*sdc);
			fp = fp1;
		}
		goto nextmsg;
	}
	return (sctp->sctp_xmit_tail);
}

void
sctp_free_msg(mblk_t *ump)
{
	mblk_t *mp, *nmp;

	for (mp = ump->b_cont; mp; mp = nmp) {
		nmp = mp->b_next;
		mp->b_next = mp->b_prev = NULL;
		freemsg(mp);
	}
	ASSERT(!ump->b_prev);
	ump->b_next = NULL;
	freeb(ump);
}

mblk_t *
sctp_add_proto_hdr(sctp_t *sctp, sctp_faddr_t *fp, mblk_t *mp, int sacklen,
    int *error)
{
	int hdrlen;
	uchar_t *hdr;
	int isv4 = fp->sf_isv4;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (error != NULL)
		*error = 0;

	if (isv4) {
		hdrlen = sctp->sctp_hdr_len;
		hdr = sctp->sctp_iphc;
	} else {
		hdrlen = sctp->sctp_hdr6_len;
		hdr = sctp->sctp_iphc6;
	}
	/*
	 * A reject|blackhole could mean that the address is 'down'. Similarly,
	 * it is possible that the address went down, we tried to send an
	 * heartbeat and ended up setting fp->sf_saddr as unspec because we
	 * didn't have any usable source address.  In either case
	 * sctp_get_dest() will try find an IRE, if available, and set
	 * the source address, if needed.  If we still don't have any
	 * usable source address, fp->sf_state will be SCTP_FADDRS_UNREACH and
	 * we return EHOSTUNREACH.
	 */
	ASSERT(fp->sf_ixa->ixa_ire != NULL);
	if ((fp->sf_ixa->ixa_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    SCTP_IS_ADDR_UNSPEC(fp->sf_isv4, fp->sf_saddr)) {
		sctp_get_dest(sctp, fp);
		if (fp->sf_state == SCTP_FADDRS_UNREACH) {
			if (error != NULL)
				*error = EHOSTUNREACH;
			return (NULL);
		}
	}
	/* Copy in IP header. */
	if ((mp->b_rptr - mp->b_datap->db_base) <
	    (sctps->sctps_wroff_xtra + hdrlen + sacklen) || DB_REF(mp) > 2) {
		mblk_t *nmp;

		/*
		 * This can happen if IP headers are adjusted after
		 * data was moved into chunks, or during retransmission,
		 * or things like snoop is running.
		 */
		nmp = allocb(sctps->sctps_wroff_xtra + hdrlen + sacklen,
		    BPRI_MED);
		if (nmp == NULL) {
			if (error !=  NULL)
				*error = ENOMEM;
			return (NULL);
		}
		nmp->b_rptr += sctps->sctps_wroff_xtra;
		nmp->b_wptr = nmp->b_rptr + hdrlen + sacklen;
		nmp->b_cont = mp;
		mp = nmp;
	} else {
		mp->b_rptr -= (hdrlen + sacklen);
	}
	bcopy(hdr, mp->b_rptr, hdrlen);
	if (sacklen) {
		sctp_fill_sack(sctp, mp->b_rptr + hdrlen, sacklen);
	}
	if (fp != sctp->sctp_current) {
		/* change addresses in header */
		if (isv4) {
			ipha_t *iph = (ipha_t *)mp->b_rptr;

			IN6_V4MAPPED_TO_IPADDR(&fp->sf_faddr, iph->ipha_dst);
			if (!IN6_IS_ADDR_V4MAPPED_ANY(&fp->sf_saddr)) {
				IN6_V4MAPPED_TO_IPADDR(&fp->sf_saddr,
				    iph->ipha_src);
			} else if (sctp->sctp_bound_to_all) {
				iph->ipha_src = INADDR_ANY;
			}
		} else {
			ip6_t *ip6h = (ip6_t *)mp->b_rptr;

			ip6h->ip6_dst = fp->sf_faddr;
			if (!IN6_IS_ADDR_UNSPECIFIED(&fp->sf_saddr)) {
				ip6h->ip6_src = fp->sf_saddr;
			} else if (sctp->sctp_bound_to_all) {
				ip6h->ip6_src = ipv6_all_zeros;
			}
		}
	}
	return (mp);
}

/*
 * SCTP requires every chunk to be padded so that the total length
 * is a multiple of SCTP_ALIGN.  This function returns a mblk with
 * the specified pad length.
 */
static mblk_t *
sctp_get_padding(sctp_t *sctp, int pad)
{
	mblk_t *fill;

	ASSERT(pad < SCTP_ALIGN);
	ASSERT(sctp->sctp_pad_mp != NULL);
	if ((fill = dupb(sctp->sctp_pad_mp)) != NULL) {
		fill->b_wptr += pad;
		return (fill);
	}

	/*
	 * The memory saving path of reusing the sctp_pad_mp
	 * fails may be because it has been dupb() too
	 * many times (DBLK_REFMAX).  Use the memory consuming
	 * path of allocating the pad mblk.
	 */
	if ((fill = allocb(SCTP_ALIGN, BPRI_MED)) != NULL) {
		/* Zero it out.  SCTP_ALIGN is sizeof (int32_t) */
		*(int32_t *)fill->b_rptr = 0;
		fill->b_wptr += pad;
	}
	return (fill);
}

static mblk_t *
sctp_find_fast_rexmit_mblks(sctp_t *sctp, int *total, sctp_faddr_t **fp)
{
	mblk_t		*meta;
	mblk_t		*start_mp = NULL;
	mblk_t		*end_mp = NULL;
	mblk_t		*mp, *nmp;
	mblk_t		*fill;
	sctp_data_hdr_t	*sdh;
	int		msglen;
	int		extra;
	sctp_msg_hdr_t	*msg_hdr;
	sctp_faddr_t	*old_fp = NULL;
	sctp_faddr_t	*chunk_fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	for (meta = sctp->sctp_xmit_head; meta != NULL; meta = meta->b_next) {
		msg_hdr = (sctp_msg_hdr_t *)meta->b_rptr;
		if (SCTP_IS_MSG_ABANDONED(meta) ||
		    SCTP_MSG_TO_BE_ABANDONED(meta, msg_hdr, sctp)) {
			continue;
		}
		for (mp = meta->b_cont; mp != NULL; mp = mp->b_next) {
			if (SCTP_CHUNK_WANT_REXMIT(mp)) {
				/*
				 * Use the same peer address to do fast
				 * retransmission.  If the original peer
				 * address is dead, switch to the current
				 * one.  Record the old one so that we
				 * will pick the chunks sent to the old
				 * one for fast retransmission.
				 */
				chunk_fp = SCTP_CHUNK_DEST(mp);
				if (*fp == NULL) {
					*fp = chunk_fp;
					if ((*fp)->sf_state !=
					    SCTP_FADDRS_ALIVE) {
						old_fp = *fp;
						*fp = sctp->sctp_current;
					}
				} else if (old_fp == NULL && *fp != chunk_fp) {
					continue;
				} else if (old_fp != NULL &&
				    old_fp != chunk_fp) {
					continue;
				}

				sdh = (sctp_data_hdr_t *)mp->b_rptr;
				msglen = ntohs(sdh->sdh_len);
				if ((extra = msglen & (SCTP_ALIGN - 1)) != 0) {
					extra = SCTP_ALIGN - extra;
				}

				/*
				 * We still return at least the first message
				 * even if that message cannot fit in as
				 * PMTU may have changed.
				 */
				if (*total + msglen + extra >
				    (*fp)->sf_pmss && start_mp != NULL) {
					return (start_mp);
				}
				if ((nmp = dupmsg(mp)) == NULL)
					return (start_mp);
				if (extra > 0) {
					fill = sctp_get_padding(sctp, extra);
					if (fill != NULL) {
						linkb(nmp, fill);
					} else {
						return (start_mp);
					}
				}
				SCTPS_BUMP_MIB(sctps, sctpOutFastRetrans);
				BUMP_LOCAL(sctp->sctp_rxtchunks);
				SCTP_CHUNK_CLEAR_REXMIT(mp);
				if (start_mp == NULL) {
					start_mp = nmp;
				} else {
					linkb(end_mp, nmp);
				}
				end_mp = nmp;
				*total += msglen + extra;
				dprint(2, ("sctp_find_fast_rexmit_mblks: "
				    "tsn %x\n", sdh->sdh_tsn));
			}
		}
	}
	/* Clear the flag as there is no more message to be fast rexmitted. */
	sctp->sctp_chk_fast_rexmit = B_FALSE;
	return (start_mp);
}

/* A debug function just to make sure that a mblk chain is not broken */
#ifdef	DEBUG
static boolean_t
sctp_verify_chain(mblk_t *head, mblk_t *tail)
{
	mblk_t	*mp = head;

	if (head == NULL || tail == NULL)
		return (B_TRUE);
	while (mp != NULL) {
		if (mp == tail)
			return (B_TRUE);
		mp = mp->b_next;
	}
	return (B_FALSE);
}
#endif

/*
 * Gets the next unsent chunk to transmit. Messages that are abandoned are
 * skipped. A message can be abandoned if it has a non-zero timetolive and
 * transmission has not yet started or if it is a partially reliable
 * message and its time is up (assuming we are PR-SCTP aware).
 * We only return a chunk if it will fit entirely in the current packet.
 * 'cansend' is used to determine if need to try and chunkify messages from
 * the unsent list, if any, and also as an input to sctp_chunkify() if so.
 *
 * firstseg_len indicates the space already used, cansend represents remaining
 * space in the window, ((sf_pmss - firstseg_len) can therefore reasonably
 * be used to compute the cansend arg).
 */
mblk_t *
sctp_get_msg_to_send(sctp_t *sctp, mblk_t **mp, mblk_t *meta, int  *error,
    int32_t firstseg_len, uint32_t cansend, sctp_faddr_t *fp)
{
	mblk_t		*mp1;
	sctp_msg_hdr_t	*msg_hdr;
	mblk_t		*tmp_meta;
	sctp_faddr_t	*fp1;

	ASSERT(error != NULL && mp != NULL);
	*error = 0;

	ASSERT(sctp->sctp_current != NULL);

chunkified:
	while (meta != NULL) {
		tmp_meta = meta->b_next;
		msg_hdr = (sctp_msg_hdr_t *)meta->b_rptr;
		mp1 = meta->b_cont;
		if (SCTP_IS_MSG_ABANDONED(meta))
			goto next_msg;
		if (!SCTP_MSG_TO_BE_ABANDONED(meta, msg_hdr, sctp)) {
			while (mp1 != NULL) {
				if (SCTP_CHUNK_CANSEND(mp1)) {
					*mp = mp1;
#ifdef	DEBUG
					ASSERT(sctp_verify_chain(
					    sctp->sctp_xmit_head, meta));
#endif
					return (meta);
				}
				mp1 = mp1->b_next;
			}
			goto next_msg;
		}
		/*
		 * If we come here and the first chunk is sent, then we
		 * we are PR-SCTP aware, in which case if the cumulative
		 * TSN has moved upto or beyond the first chunk (which
		 * means all the previous messages have been cumulative
		 * SACK'd), then we send a Forward TSN with the last
		 * chunk that was sent in this message. If we can't send
		 * a Forward TSN because previous non-abandoned messages
		 * have not been acked then we will defer the Forward TSN
		 * to sctp_rexmit() or sctp_cumack().
		 */
		if (SCTP_CHUNK_ISSENT(mp1)) {
			*error = sctp_check_abandoned_msg(sctp, meta);
			if (*error != 0) {
#ifdef	DEBUG
				ASSERT(sctp_verify_chain(sctp->sctp_xmit_head,
				    sctp->sctp_xmit_tail));
#endif
				return (NULL);
			}
			goto next_msg;
		}
		BUMP_LOCAL(sctp->sctp_prsctpdrop);
		ASSERT(sctp->sctp_unsent >= msg_hdr->smh_msglen);
		if (meta->b_prev == NULL) {
			ASSERT(sctp->sctp_xmit_head == meta);
			sctp->sctp_xmit_head = tmp_meta;
			if (sctp->sctp_xmit_tail == meta)
				sctp->sctp_xmit_tail = tmp_meta;
			meta->b_next = NULL;
			if (tmp_meta != NULL)
				tmp_meta->b_prev = NULL;
		} else if (meta->b_next == NULL) {
			if (sctp->sctp_xmit_tail == meta)
				sctp->sctp_xmit_tail = meta->b_prev;
			meta->b_prev->b_next = NULL;
			meta->b_prev = NULL;
		} else {
			meta->b_prev->b_next = tmp_meta;
			tmp_meta->b_prev = meta->b_prev;
			if (sctp->sctp_xmit_tail == meta)
				sctp->sctp_xmit_tail = tmp_meta;
			meta->b_prev = NULL;
			meta->b_next = NULL;
		}
		sctp->sctp_unsent -= msg_hdr->smh_msglen;
		/*
		 * Update ULP the amount of queued data, which is
		 * sent-unack'ed + unsent.
		 */
		if (!SCTP_IS_DETACHED(sctp))
			SCTP_TXQ_UPDATE(sctp);
		sctp_sendfail_event(sctp, meta, 0, B_TRUE);
next_msg:
		meta = tmp_meta;
	}
	/* chunkify, if needed */
	if (cansend > 0 && sctp->sctp_xmit_unsent != NULL) {
		ASSERT(sctp->sctp_unsent > 0);
		if (fp == NULL) {
			fp = SCTP_CHUNK_DEST(sctp->sctp_xmit_unsent);
			if (fp == NULL || fp->sf_state != SCTP_FADDRS_ALIVE)
				fp = sctp->sctp_current;
		} else {
			/*
			 * If user specified destination, try to honor that.
			 */
			fp1 = SCTP_CHUNK_DEST(sctp->sctp_xmit_unsent);
			if (fp1 != NULL && fp1->sf_state == SCTP_FADDRS_ALIVE &&
			    fp1 != fp) {
				goto chunk_done;
			}
		}
		meta = sctp_chunkify(sctp, fp->sf_pmss, firstseg_len, cansend);
		if (meta == NULL)
			goto chunk_done;
		/*
		 * sctp_chunkify() won't advance sctp_xmit_tail if it adds
		 * new chunk(s) to the tail, so we need to skip the
		 * sctp_xmit_tail, which would have already been processed.
		 * This could happen when there is unacked chunks, but
		 * nothing new to send.
		 * When sctp_chunkify() is called when the transmit queue
		 * is empty then we need to start from sctp_xmit_tail.
		 */
		if (SCTP_CHUNK_ISSENT(sctp->sctp_xmit_tail->b_cont)) {
#ifdef	DEBUG
			mp1 = sctp->sctp_xmit_tail->b_cont;
			while (mp1 != NULL) {
				ASSERT(!SCTP_CHUNK_CANSEND(mp1));
				mp1 = mp1->b_next;
			}
#endif
			if ((meta = sctp->sctp_xmit_tail->b_next) == NULL)
				goto chunk_done;
		}
		goto chunkified;
	}
chunk_done:
#ifdef	DEBUG
	ASSERT(sctp_verify_chain(sctp->sctp_xmit_head, sctp->sctp_xmit_tail));
#endif
	return (NULL);
}

void
sctp_fast_rexmit(sctp_t *sctp)
{
	mblk_t		*mp, *head;
	int		pktlen = 0;
	sctp_faddr_t	*fp = NULL;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	ASSERT(sctp->sctp_xmit_head != NULL);
	mp = sctp_find_fast_rexmit_mblks(sctp, &pktlen, &fp);
	if (mp == NULL) {
		SCTP_KSTAT(sctps, sctp_fr_not_found);
		return;
	}
	if ((head = sctp_add_proto_hdr(sctp, fp, mp, 0, NULL)) == NULL) {
		freemsg(mp);
		SCTP_KSTAT(sctps, sctp_fr_add_hdr);
		return;
	}
	if ((pktlen > fp->sf_pmss) && fp->sf_isv4) {
		ipha_t *iph = (ipha_t *)head->b_rptr;

		iph->ipha_fragment_offset_and_flags = 0;
	}

	sctp_set_iplen(sctp, head, fp->sf_ixa);
	(void) conn_ip_output(head, fp->sf_ixa);
	BUMP_LOCAL(sctp->sctp_opkts);
	sctp->sctp_active = fp->sf_lastactive = ddi_get_lbolt64();
}

void
sctp_output(sctp_t *sctp, uint_t num_pkt)
{
	mblk_t			*mp = NULL;
	mblk_t			*nmp;
	mblk_t			*head;
	mblk_t			*meta = sctp->sctp_xmit_tail;
	mblk_t			*fill = NULL;
	uint16_t		chunklen;
	uint32_t		cansend;
	int32_t			seglen;
	int32_t			xtralen;
	int32_t			sacklen;
	int32_t			pad = 0;
	int32_t			pathmax;
	int			extra;
	int64_t			now = LBOLT_FASTPATH64;
	sctp_faddr_t		*fp;
	sctp_faddr_t		*lfp;
	sctp_data_hdr_t		*sdc;
	int			error;
	boolean_t		notsent = B_TRUE;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	uint32_t		tsn;

	lfp = NULL;

	if (sctp->sctp_ftsn == sctp->sctp_lastacked + 1) {
		sacklen = 0;
	} else {
		/* send a SACK chunk */
		sacklen = sizeof (sctp_chunk_hdr_t) +
		    sizeof (sctp_sack_chunk_t) +
		    (sizeof (sctp_sack_frag_t) * sctp->sctp_sack_gaps);
		lfp = sctp->sctp_lastdata;
		ASSERT(lfp != NULL);
		if (lfp->sf_state != SCTP_FADDRS_ALIVE)
			lfp = sctp->sctp_current;
	}

	cansend = sctp->sctp_frwnd;
	if (sctp->sctp_unsent < cansend)
		cansend = sctp->sctp_unsent;

	/*
	 * Start persist timer if unable to send or when
	 * trying to send into a zero window. This timer
	 * ensures the blocked send attempt is retried.
	 */
	if ((cansend < sctp->sctp_current->sf_pmss / 2) &&
	    (sctp->sctp_unacked != 0) &&
	    (sctp->sctp_unacked < sctp->sctp_current->sf_pmss) &&
	    !sctp->sctp_ndelay ||
	    (cansend == 0 && sctp->sctp_unacked == 0 &&
	    sctp->sctp_unsent != 0)) {
		head = NULL;
		fp = sctp->sctp_current;
		goto unsent_data;
	}
	if (meta != NULL)
		mp = meta->b_cont;
	while (cansend > 0 && num_pkt-- != 0) {
		pad = 0;

		/*
		 * Find first segment eligible for transmit.
		 */
		while (mp != NULL) {
			if (SCTP_CHUNK_CANSEND(mp))
				break;
			mp = mp->b_next;
		}
		if (mp == NULL) {
			meta = sctp_get_msg_to_send(sctp, &mp,
			    meta == NULL ? NULL : meta->b_next, &error, sacklen,
			    cansend, NULL);
			if (error != 0 || meta == NULL) {
				head = NULL;
				fp = sctp->sctp_current;
				goto unsent_data;
			}
			sctp->sctp_xmit_tail =  meta;
		}

		sdc = (sctp_data_hdr_t *)mp->b_rptr;
		seglen = ntohs(sdc->sdh_len);
		xtralen = sizeof (*sdc);
		chunklen = seglen - xtralen;

		/*
		 * Check rwnd.
		 */
		if (chunklen > cansend) {
			head = NULL;
			fp = SCTP_CHUNK_DEST(meta);
			if (fp == NULL || fp->sf_state != SCTP_FADDRS_ALIVE)
				fp = sctp->sctp_current;
			goto unsent_data;
		}
		if ((extra = seglen & (SCTP_ALIGN - 1)) != 0)
			extra = SCTP_ALIGN - extra;

		/*
		 * Pick destination address, and check cwnd.
		 */
		if (sacklen > 0 && (seglen + extra <= lfp->sf_cwnd -
		    lfp->sf_suna) &&
		    (seglen + sacklen + extra <= lfp->sf_pmss)) {
			/*
			 * Only include SACK chunk if it can be bundled
			 * with a data chunk, and sent to sctp_lastdata.
			 */
			pathmax = lfp->sf_cwnd - lfp->sf_suna;

			fp = lfp;
			if ((nmp = dupmsg(mp)) == NULL) {
				head = NULL;
				goto unsent_data;
			}
			SCTP_CHUNK_CLEAR_FLAGS(nmp);
			head = sctp_add_proto_hdr(sctp, fp, nmp, sacklen,
			    &error);
			if (head == NULL) {
				/*
				 * If none of the source addresses are
				 * available (i.e error == EHOSTUNREACH),
				 * pretend we have sent the data. We will
				 * eventually time out trying to retramsmit
				 * the data if the interface never comes up.
				 * If we have already sent some stuff (i.e.,
				 * notsent is B_FALSE) then we are fine, else
				 * just mark this packet as sent.
				 */
				if (notsent && error == EHOSTUNREACH) {
					SCTP_CHUNK_SENT(sctp, mp, sdc,
					    fp, chunklen, meta);
				}
				freemsg(nmp);
				SCTP_KSTAT(sctps, sctp_output_failed);
				goto unsent_data;
			}
			seglen += sacklen;
			xtralen += sacklen;
			sacklen = 0;
		} else {
			fp = SCTP_CHUNK_DEST(meta);
			if (fp == NULL || fp->sf_state != SCTP_FADDRS_ALIVE)
				fp = sctp->sctp_current;
			/*
			 * If we haven't sent data to this destination for
			 * a while, do slow start again.
			 */
			if (now - fp->sf_lastactive > fp->sf_rto) {
				SET_CWND(fp, fp->sf_pmss,
				    sctps->sctps_slow_start_after_idle);
			}

			pathmax = fp->sf_cwnd - fp->sf_suna;
			if (seglen + extra > pathmax) {
				head = NULL;
				goto unsent_data;
			}
			if ((nmp = dupmsg(mp)) == NULL) {
				head = NULL;
				goto unsent_data;
			}
			SCTP_CHUNK_CLEAR_FLAGS(nmp);
			head = sctp_add_proto_hdr(sctp, fp, nmp, 0, &error);
			if (head == NULL) {
				/*
				 * If none of the source addresses are
				 * available (i.e error == EHOSTUNREACH),
				 * pretend we have sent the data. We will
				 * eventually time out trying to retramsmit
				 * the data if the interface never comes up.
				 * If we have already sent some stuff (i.e.,
				 * notsent is B_FALSE) then we are fine, else
				 * just mark this packet as sent.
				 */
				if (notsent && error == EHOSTUNREACH) {
					SCTP_CHUNK_SENT(sctp, mp, sdc,
					    fp, chunklen, meta);
				}
				freemsg(nmp);
				SCTP_KSTAT(sctps, sctp_output_failed);
				goto unsent_data;
			}
		}
		fp->sf_lastactive = now;
		if (pathmax > fp->sf_pmss)
			pathmax = fp->sf_pmss;
		SCTP_CHUNK_SENT(sctp, mp, sdc, fp, chunklen, meta);
		mp = mp->b_next;

		/*
		 * Use this chunk to measure RTT?
		 * Must not be a retransmision of an earlier chunk,
		 * ensure the tsn is current.
		 */
		tsn = ntohl(sdc->sdh_tsn);
		if (sctp->sctp_out_time == 0 && tsn == (sctp->sctp_ltsn - 1)) {
			sctp->sctp_out_time = now;
			sctp->sctp_rtt_tsn = tsn;
		}
		if (extra > 0) {
			fill = sctp_get_padding(sctp, extra);
			if (fill != NULL) {
				linkb(head, fill);
				pad = extra;
				seglen += extra;
			} else {
				goto unsent_data;
			}
		}
		/*
		 * Bundle chunks. We linkb() the chunks together to send
		 * downstream in a single packet.
		 * Partial chunks MUST NOT be bundled with full chunks, so we
		 * rely on sctp_get_msg_to_send() to only return messages that
		 * will fit entirely in the current packet.
		 */
		while (seglen < pathmax) {
			int32_t		new_len;
			int32_t		new_xtralen;

			while (mp != NULL) {
				if (SCTP_CHUNK_CANSEND(mp))
					break;
				mp = mp->b_next;
			}
			if (mp == NULL) {
				meta = sctp_get_msg_to_send(sctp, &mp,
				    meta->b_next, &error, seglen,
				    (seglen - xtralen) >= cansend ? 0 :
				    cansend - seglen, fp);
				if (error != 0)
					break;
				/* If no more eligible chunks, cease bundling */
				if (meta == NULL)
					break;
				sctp->sctp_xmit_tail =  meta;
			}
			ASSERT(mp != NULL);
			if (!SCTP_CHUNK_ISSENT(mp) && SCTP_CHUNK_DEST(meta) &&
			    fp != SCTP_CHUNK_DEST(meta)) {
				break;
			}
			sdc = (sctp_data_hdr_t *)mp->b_rptr;
			chunklen = ntohs(sdc->sdh_len);
			if ((extra = chunklen  & (SCTP_ALIGN - 1)) != 0)
				extra = SCTP_ALIGN - extra;

			new_len = seglen + chunklen;
			new_xtralen = xtralen + sizeof (*sdc);
			chunklen -= sizeof (*sdc);

			if (new_len - new_xtralen > cansend ||
			    new_len + extra > pathmax) {
				break;
			}
			if ((nmp = dupmsg(mp)) == NULL)
				break;
			if (extra > 0) {
				fill = sctp_get_padding(sctp, extra);
				if (fill != NULL) {
					pad += extra;
					new_len += extra;
					linkb(nmp, fill);
				} else {
					freemsg(nmp);
					break;
				}
			}
			seglen = new_len;
			xtralen = new_xtralen;
			SCTP_CHUNK_CLEAR_FLAGS(nmp);
			SCTP_CHUNK_SENT(sctp, mp, sdc, fp, chunklen, meta);
			linkb(head, nmp);
			mp = mp->b_next;
		}
		if ((seglen > fp->sf_pmss) && fp->sf_isv4) {
			ipha_t *iph = (ipha_t *)head->b_rptr;

			/*
			 * Path MTU is different from what we thought it would
			 * be when we created chunks, or IP headers have grown.
			 * Need to clear the DF bit.
			 */
			iph->ipha_fragment_offset_and_flags = 0;
		}
		/* xmit segment */
		ASSERT(cansend >= seglen - pad - xtralen);
		cansend -= (seglen - pad - xtralen);
		dprint(2, ("sctp_output: Sending packet %d bytes, tsn %x "
		    "ssn %d to %p (rwnd %d, cansend %d, lastack_rxd %x)\n",
		    seglen - xtralen, ntohl(sdc->sdh_tsn),
		    ntohs(sdc->sdh_ssn), (void *)fp, sctp->sctp_frwnd,
		    cansend, sctp->sctp_lastack_rxd));
		sctp_set_iplen(sctp, head, fp->sf_ixa);
		(void) conn_ip_output(head, fp->sf_ixa);
		BUMP_LOCAL(sctp->sctp_opkts);
		/* arm rto timer (if not set) */
		if (!fp->sf_timer_running)
			SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
		notsent = B_FALSE;
	}
	sctp->sctp_active = now;
	return;
unsent_data:
	/* arm persist timer (if rto timer not set) */
	if (!fp->sf_timer_running)
		SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
	if (head != NULL)
		freemsg(head);
}

/*
 * The following two functions initialize and destroy the cache
 * associated with the sets used for PR-SCTP.
 */
void
sctp_ftsn_sets_init(void)
{
	sctp_kmem_ftsn_set_cache = kmem_cache_create("sctp_ftsn_set_cache",
	    sizeof (sctp_ftsn_set_t), 0, NULL, NULL, NULL, NULL,
	    NULL, 0);
}

void
sctp_ftsn_sets_fini(void)
{
	kmem_cache_destroy(sctp_kmem_ftsn_set_cache);
}


/* Free PR-SCTP sets */
void
sctp_free_ftsn_set(sctp_ftsn_set_t *s)
{
	sctp_ftsn_set_t *p;

	while (s != NULL) {
		p = s->next;
		s->next = NULL;
		kmem_cache_free(sctp_kmem_ftsn_set_cache, s);
		s = p;
	}
}

/*
 * Given a message meta block, meta, this routine creates or modifies
 * the set that will be used to generate a Forward TSN chunk. If the
 * entry for stream id, sid, for this message already exists, the
 * sequence number, ssn, is updated if it is greater than the existing
 * one. If an entry for this sid does not exist, one is created if
 * the size does not exceed fp->sf_pmss. We return false in case
 * or an error.
 */
boolean_t
sctp_add_ftsn_set(sctp_ftsn_set_t **s, sctp_faddr_t *fp, mblk_t *meta,
    uint_t *nsets, uint32_t *slen)
{
	sctp_ftsn_set_t		*p;
	sctp_msg_hdr_t		*msg_hdr = (sctp_msg_hdr_t *)meta->b_rptr;
	uint16_t		sid = htons(msg_hdr->smh_sid);
	/* msg_hdr->smh_ssn is already in NBO */
	uint16_t		ssn = msg_hdr->smh_ssn;

	ASSERT(s != NULL && nsets != NULL);
	ASSERT((*nsets == 0 && *s == NULL) || (*nsets > 0 && *s != NULL));

	if (*s == NULL) {
		ASSERT((*slen + sizeof (uint32_t)) <= fp->sf_pmss);
		*s = kmem_cache_alloc(sctp_kmem_ftsn_set_cache, KM_NOSLEEP);
		if (*s == NULL)
			return (B_FALSE);
		(*s)->ftsn_entries.ftsn_sid = sid;
		(*s)->ftsn_entries.ftsn_ssn = ssn;
		(*s)->next = NULL;
		*nsets = 1;
		*slen += sizeof (uint32_t);
		return (B_TRUE);
	}
	for (p = *s; p->next != NULL; p = p->next) {
		if (p->ftsn_entries.ftsn_sid == sid) {
			if (SSN_GT(ssn, p->ftsn_entries.ftsn_ssn))
				p->ftsn_entries.ftsn_ssn = ssn;
			return (B_TRUE);
		}
	}
	/* the last one */
	if (p->ftsn_entries.ftsn_sid == sid) {
		if (SSN_GT(ssn, p->ftsn_entries.ftsn_ssn))
			p->ftsn_entries.ftsn_ssn = ssn;
	} else {
		if ((*slen + sizeof (uint32_t)) > fp->sf_pmss)
			return (B_FALSE);
		p->next = kmem_cache_alloc(sctp_kmem_ftsn_set_cache,
		    KM_NOSLEEP);
		if (p->next == NULL)
			return (B_FALSE);
		p = p->next;
		p->ftsn_entries.ftsn_sid = sid;
		p->ftsn_entries.ftsn_ssn = ssn;
		p->next = NULL;
		(*nsets)++;
		*slen += sizeof (uint32_t);
	}
	return (B_TRUE);
}

/*
 * Given a set of stream id - sequence number pairs, this routing creates
 * a Forward TSN chunk. The cumulative TSN (advanced peer ack point)
 * for the chunk is obtained from sctp->sctp_adv_pap. The caller
 * will add the IP/SCTP header.
 */
mblk_t *
sctp_make_ftsn_chunk(sctp_t *sctp, sctp_faddr_t *fp, sctp_ftsn_set_t *sets,
    uint_t nsets, uint32_t seglen)
{
	mblk_t			*ftsn_mp;
	sctp_chunk_hdr_t	*ch_hdr;
	uint32_t		*advtsn;
	uint16_t		schlen;
	size_t			xtralen;
	ftsn_entry_t		*ftsn_entry;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	seglen += sizeof (sctp_chunk_hdr_t);
	if (fp->sf_isv4)
		xtralen = sctp->sctp_hdr_len + sctps->sctps_wroff_xtra;
	else
		xtralen = sctp->sctp_hdr6_len + sctps->sctps_wroff_xtra;
	ftsn_mp = allocb(xtralen + seglen, BPRI_MED);
	if (ftsn_mp == NULL)
		return (NULL);
	ftsn_mp->b_rptr += xtralen;
	ftsn_mp->b_wptr = ftsn_mp->b_rptr + seglen;

	ch_hdr = (sctp_chunk_hdr_t *)ftsn_mp->b_rptr;
	ch_hdr->sch_id = CHUNK_FORWARD_TSN;
	ch_hdr->sch_flags = 0;
	/*
	 * The cast here should not be an issue since seglen is
	 * the length of the Forward TSN chunk.
	 */
	schlen = (uint16_t)seglen;
	U16_TO_ABE16(schlen, &(ch_hdr->sch_len));

	advtsn = (uint32_t *)(ch_hdr + 1);
	U32_TO_ABE32(sctp->sctp_adv_pap, advtsn);
	ftsn_entry = (ftsn_entry_t *)(advtsn + 1);
	while (nsets > 0) {
		ASSERT((uchar_t *)&ftsn_entry[1] <= ftsn_mp->b_wptr);
		ftsn_entry->ftsn_sid = sets->ftsn_entries.ftsn_sid;
		ftsn_entry->ftsn_ssn = sets->ftsn_entries.ftsn_ssn;
		ftsn_entry++;
		sets = sets->next;
		nsets--;
	}
	return (ftsn_mp);
}

/*
 * Given a starting message, the routine steps through all the
 * messages whose TSN is less than sctp->sctp_adv_pap and creates
 * ftsn sets. The ftsn sets is then used to create an Forward TSN
 * chunk. All the messages, that have chunks that are included in the
 * ftsn sets, are flagged abandonded. If a message is partially sent
 * and is deemed abandoned, all remaining unsent chunks are marked
 * abandoned and are deducted from sctp_unsent.
 */
void
sctp_make_ftsns(sctp_t *sctp, mblk_t *meta, mblk_t *mp, mblk_t **nmp,
    sctp_faddr_t *fp, uint32_t *seglen)
{
	mblk_t		*mp1 = mp;
	mblk_t		*mp_head = mp;
	mblk_t		*meta_head = meta;
	mblk_t		*head;
	sctp_ftsn_set_t	*sets = NULL;
	uint_t		nsets = 0;
	uint16_t	clen;
	sctp_data_hdr_t	*sdc;
	uint32_t	sacklen;
	uint32_t	adv_pap = sctp->sctp_adv_pap;
	uint32_t	unsent = 0;
	boolean_t	ubit;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	*seglen = sizeof (uint32_t);

	sdc  = (sctp_data_hdr_t *)mp1->b_rptr;
	while (meta != NULL &&
	    SEQ_GEQ(sctp->sctp_adv_pap, ntohl(sdc->sdh_tsn))) {
		/*
		 * Skip adding FTSN sets for un-ordered messages as they do
		 * not have SSNs.
		 */
		ubit = SCTP_DATA_GET_UBIT(sdc);
		if (!ubit &&
		    !sctp_add_ftsn_set(&sets, fp, meta, &nsets, seglen)) {
			meta = NULL;
			sctp->sctp_adv_pap = adv_pap;
			goto ftsn_done;
		}
		while (mp1 != NULL && SCTP_CHUNK_ISSENT(mp1)) {
			sdc = (sctp_data_hdr_t *)mp1->b_rptr;
			adv_pap = ntohl(sdc->sdh_tsn);
			mp1 = mp1->b_next;
		}
		meta = meta->b_next;
		if (meta != NULL) {
			mp1 = meta->b_cont;
			if (!SCTP_CHUNK_ISSENT(mp1))
				break;
			sdc  = (sctp_data_hdr_t *)mp1->b_rptr;
		}
	}
ftsn_done:
	/*
	 * Can't compare with sets == NULL, since we don't add any
	 * sets for un-ordered messages.
	 */
	if (meta == meta_head)
		return;
	*nmp = sctp_make_ftsn_chunk(sctp, fp, sets, nsets, *seglen);
	sctp_free_ftsn_set(sets);
	if (*nmp == NULL)
		return;
	if (sctp->sctp_ftsn == sctp->sctp_lastacked + 1) {
		sacklen = 0;
	} else {
		sacklen = sizeof (sctp_chunk_hdr_t) +
		    sizeof (sctp_sack_chunk_t) +
		    (sizeof (sctp_sack_frag_t) * sctp->sctp_sack_gaps);
		if (*seglen + sacklen > sctp->sctp_lastdata->sf_pmss) {
			/* piggybacked SACK doesn't fit */
			sacklen = 0;
		} else {
			fp = sctp->sctp_lastdata;
		}
	}
	head = sctp_add_proto_hdr(sctp, fp, *nmp, sacklen, NULL);
	if (head == NULL) {
		freemsg(*nmp);
		*nmp = NULL;
		SCTP_KSTAT(sctps, sctp_send_ftsn_failed);
		return;
	}
	*seglen += sacklen;
	*nmp = head;

	/*
	 * XXXNeed to optimise this, the reason it is done here is so
	 * that we don't have to undo in case of failure.
	 */
	mp1 = mp_head;
	sdc  = (sctp_data_hdr_t *)mp1->b_rptr;
	while (meta_head != NULL &&
	    SEQ_GEQ(sctp->sctp_adv_pap, ntohl(sdc->sdh_tsn))) {
		if (!SCTP_IS_MSG_ABANDONED(meta_head))
			SCTP_MSG_SET_ABANDONED(meta_head);
		while (mp1 != NULL && SCTP_CHUNK_ISSENT(mp1)) {
			sdc = (sctp_data_hdr_t *)mp1->b_rptr;
			if (!SCTP_CHUNK_ISACKED(mp1)) {
				clen = ntohs(sdc->sdh_len) - sizeof (*sdc);
				SCTP_CHUNK_SENT(sctp, mp1, sdc, fp, clen,
				    meta_head);
			}
			mp1 = mp1->b_next;
		}
		while (mp1 != NULL) {
			sdc = (sctp_data_hdr_t *)mp1->b_rptr;
			if (!SCTP_CHUNK_ABANDONED(mp1)) {
				ASSERT(!SCTP_CHUNK_ISSENT(mp1));
				unsent += ntohs(sdc->sdh_len) - sizeof (*sdc);
				SCTP_ABANDON_CHUNK(mp1);
			}
			mp1 = mp1->b_next;
		}
		meta_head = meta_head->b_next;
		if (meta_head != NULL) {
			mp1 = meta_head->b_cont;
			if (!SCTP_CHUNK_ISSENT(mp1))
				break;
			sdc  = (sctp_data_hdr_t *)mp1->b_rptr;
		}
	}
	if (unsent > 0) {
		ASSERT(sctp->sctp_unsent >= unsent);
		sctp->sctp_unsent -= unsent;
		/*
		 * Update ULP the amount of queued data, which is
		 * sent-unack'ed + unsent.
		 */
		if (!SCTP_IS_DETACHED(sctp))
			SCTP_TXQ_UPDATE(sctp);
	}
}

/*
 * This function steps through messages starting at meta and checks if
 * the message is abandoned. It stops when it hits an unsent chunk or
 * a message that has all its chunk acked. This is the only place
 * where the sctp_adv_pap is moved forward to indicated abandoned
 * messages.
 */
void
sctp_check_adv_ack_pt(sctp_t *sctp, mblk_t *meta, mblk_t *mp)
{
	uint32_t	tsn = sctp->sctp_adv_pap;
	sctp_data_hdr_t	*sdc;
	sctp_msg_hdr_t	*msg_hdr;

	ASSERT(mp != NULL);
	sdc = (sctp_data_hdr_t *)mp->b_rptr;
	ASSERT(SEQ_GT(ntohl(sdc->sdh_tsn), sctp->sctp_lastack_rxd));
	msg_hdr = (sctp_msg_hdr_t *)meta->b_rptr;
	if (!SCTP_IS_MSG_ABANDONED(meta) &&
	    !SCTP_MSG_TO_BE_ABANDONED(meta, msg_hdr, sctp)) {
		return;
	}
	while (meta != NULL) {
		while (mp != NULL && SCTP_CHUNK_ISSENT(mp)) {
			sdc = (sctp_data_hdr_t *)mp->b_rptr;
			tsn = ntohl(sdc->sdh_tsn);
			mp = mp->b_next;
		}
		if (mp != NULL)
			break;
		/*
		 * We continue checking for successive messages only if there
		 * is a chunk marked for retransmission. Else, we might
		 * end up sending FTSN prematurely for chunks that have been
		 * sent, but not yet acked.
		 */
		if ((meta = meta->b_next) != NULL) {
			msg_hdr = (sctp_msg_hdr_t *)meta->b_rptr;
			if (!SCTP_IS_MSG_ABANDONED(meta) &&
			    !SCTP_MSG_TO_BE_ABANDONED(meta, msg_hdr, sctp)) {
				break;
			}
			for (mp = meta->b_cont; mp != NULL; mp = mp->b_next) {
				if (!SCTP_CHUNK_ISSENT(mp)) {
					sctp->sctp_adv_pap = tsn;
					return;
				}
				if (SCTP_CHUNK_WANT_REXMIT(mp))
					break;
			}
			if (mp == NULL)
				break;
		}
	}
	sctp->sctp_adv_pap = tsn;
}


/*
 * Determine if we should bundle a data chunk with the chunk being
 * retransmitted.  We bundle if
 *
 * - the chunk is sent to the same destination and unack'ed.
 *
 * OR
 *
 * - the chunk is unsent, i.e. new data.
 */
#define	SCTP_CHUNK_RX_CANBUNDLE(mp, fp)					\
	(!SCTP_CHUNK_ABANDONED((mp)) &&					\
	((SCTP_CHUNK_ISSENT((mp)) && (SCTP_CHUNK_DEST(mp) == (fp) &&	\
	!SCTP_CHUNK_ISACKED(mp))) ||					\
	(((mp)->b_flag & (SCTP_CHUNK_FLAG_REXMIT|SCTP_CHUNK_FLAG_SENT)) != \
	SCTP_CHUNK_FLAG_SENT)))

/*
 * Retransmit first segment which hasn't been acked with cumtsn or send
 * a Forward TSN chunk, if appropriate.
 */
void
sctp_rexmit(sctp_t *sctp, sctp_faddr_t *oldfp)
{
	mblk_t		*mp;
	mblk_t		*nmp = NULL;
	mblk_t		*head;
	mblk_t		*meta = sctp->sctp_xmit_head;
	mblk_t		*fill;
	uint32_t	seglen = 0;
	uint32_t	sacklen;
	uint16_t	chunklen;
	int		extra;
	sctp_data_hdr_t	*sdc;
	sctp_faddr_t	*fp;
	uint32_t	adv_pap = sctp->sctp_adv_pap;
	boolean_t	do_ftsn = B_FALSE;
	boolean_t	ftsn_check = B_TRUE;
	uint32_t	first_ua_tsn;
	sctp_msg_hdr_t	*mhdr;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	int		error;

	while (meta != NULL) {
		for (mp = meta->b_cont; mp != NULL; mp = mp->b_next) {
			uint32_t	tsn;

			if (!SCTP_CHUNK_ISSENT(mp))
				goto window_probe;
			/*
			 * We break in the following cases -
			 *
			 *	if the advanced peer ack point includes the next
			 *	chunk to be retransmited - possibly the Forward
			 *	TSN was lost.
			 *
			 *	if we are PRSCTP aware and the next chunk to be
			 *	retransmitted is now abandoned
			 *
			 *	if the next chunk to be retransmitted is for
			 *	the dest on which the timer went off. (this
			 *	message is not abandoned).
			 *
			 * We check for Forward TSN only for the first
			 * eligible chunk to be retransmitted. The reason
			 * being if the first eligible chunk is skipped (say
			 * it was sent to a destination other than oldfp)
			 * then we cannot advance the cum TSN via Forward
			 * TSN chunk.
			 *
			 * Also, ftsn_check is B_TRUE only for the first
			 * eligible chunk, it  will be B_FALSE for all
			 * subsequent candidate messages for retransmission.
			 */
			sdc = (sctp_data_hdr_t *)mp->b_rptr;
			tsn = ntohl(sdc->sdh_tsn);
			if (SEQ_GT(tsn, sctp->sctp_lastack_rxd)) {
				if (sctp->sctp_prsctp_aware && ftsn_check) {
					if (SEQ_GEQ(sctp->sctp_adv_pap, tsn)) {
						ASSERT(sctp->sctp_prsctp_aware);
						do_ftsn = B_TRUE;
						goto out;
					} else {
						sctp_check_adv_ack_pt(sctp,
						    meta, mp);
						if (SEQ_GT(sctp->sctp_adv_pap,
						    adv_pap)) {
							do_ftsn = B_TRUE;
							goto out;
						}
					}
					ftsn_check = B_FALSE;
				}
				if (SCTP_CHUNK_DEST(mp) == oldfp)
					goto out;
			}
		}
		meta = meta->b_next;
		if (meta != NULL && sctp->sctp_prsctp_aware) {
			mhdr = (sctp_msg_hdr_t *)meta->b_rptr;

			while (meta != NULL && (SCTP_IS_MSG_ABANDONED(meta) ||
			    SCTP_MSG_TO_BE_ABANDONED(meta, mhdr, sctp))) {
				meta = meta->b_next;
			}
		}
	}
window_probe:
	/*
	 * Retransmit fired for a destination which didn't have
	 * any unacked data pending.
	 */
	if (sctp->sctp_unacked == 0 && sctp->sctp_unsent != 0) {
		/*
		 * Send a window probe. Inflate frwnd to allow
		 * sending one segment.
		 */
		if (sctp->sctp_frwnd < (oldfp->sf_pmss - sizeof (*sdc)))
			sctp->sctp_frwnd = oldfp->sf_pmss - sizeof (*sdc);

		/* next TSN to send */
		sctp->sctp_rxt_nxttsn = sctp->sctp_ltsn;

		/*
		 * The above sctp_frwnd adjustment is coarse.  The "changed"
		 * sctp_frwnd may allow us to send more than 1 packet.  So
		 * tell sctp_output() to send only 1 packet.
		 */
		sctp_output(sctp, 1);

		/* Last sent TSN */
		sctp->sctp_rxt_maxtsn = sctp->sctp_ltsn - 1;
		ASSERT(sctp->sctp_rxt_maxtsn >= sctp->sctp_rxt_nxttsn);
		sctp->sctp_zero_win_probe = B_TRUE;
		SCTPS_BUMP_MIB(sctps, sctpOutWinProbe);
	}
	return;
out:
	/*
	 * After a time out, assume that everything has left the network.  So
	 * we can clear rxt_unacked for the original peer address.
	 */
	oldfp->sf_rxt_unacked = 0;

	/*
	 * If we were probing for zero window, don't adjust retransmission
	 * variables, but the timer is still backed off.
	 */
	if (sctp->sctp_zero_win_probe) {
		mblk_t	*pkt;
		uint_t	pkt_len;

		/*
		 * Get the Zero Win Probe for retrasmission, sctp_rxt_nxttsn
		 * and sctp_rxt_maxtsn will specify the ZWP packet.
		 */
		fp = oldfp;
		if (oldfp->sf_state != SCTP_FADDRS_ALIVE)
			fp = sctp_rotate_faddr(sctp, oldfp);
		pkt = sctp_rexmit_packet(sctp, &meta, &mp, fp, &pkt_len);
		if (pkt != NULL) {
			ASSERT(pkt_len <= fp->sf_pmss);
			sctp_set_iplen(sctp, pkt, fp->sf_ixa);
			(void) conn_ip_output(pkt, fp->sf_ixa);
			BUMP_LOCAL(sctp->sctp_opkts);
		} else {
			SCTP_KSTAT(sctps, sctp_ss_rexmit_failed);
		}

		/*
		 * The strikes will be clear by sctp_faddr_alive() when the
		 * other side sends us an ack.
		 */
		oldfp->sf_strikes++;
		sctp->sctp_strikes++;

		SCTP_CALC_RXT(sctp, oldfp, sctp->sctp_rto_max);
		if (oldfp != fp && oldfp->sf_suna != 0)
			SCTP_FADDR_TIMER_RESTART(sctp, oldfp, fp->sf_rto);
		SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
		SCTPS_BUMP_MIB(sctps, sctpOutWinProbe);
		return;
	}

	/*
	 * Enter slowstart for this destination
	 */
	oldfp->sf_ssthresh = oldfp->sf_cwnd / 2;
	if (oldfp->sf_ssthresh < 2 * oldfp->sf_pmss)
		oldfp->sf_ssthresh = 2 * oldfp->sf_pmss;
	oldfp->sf_cwnd = oldfp->sf_pmss;
	oldfp->sf_pba = 0;
	fp = sctp_rotate_faddr(sctp, oldfp);
	ASSERT(fp != NULL);
	sdc = (sctp_data_hdr_t *)mp->b_rptr;

	first_ua_tsn = ntohl(sdc->sdh_tsn);
	if (do_ftsn) {
		sctp_make_ftsns(sctp, meta, mp, &nmp, fp, &seglen);
		if (nmp == NULL) {
			sctp->sctp_adv_pap = adv_pap;
			goto restart_timer;
		}
		head = nmp;
		/*
		 * Move to the next unabandoned chunk. XXXCheck if meta will
		 * always be marked abandoned.
		 */
		while (meta != NULL && SCTP_IS_MSG_ABANDONED(meta))
			meta = meta->b_next;
		if (meta != NULL)
			mp = mp->b_cont;
		else
			mp = NULL;
		goto try_bundle;
	}
	seglen = ntohs(sdc->sdh_len);
	chunklen = seglen - sizeof (*sdc);
	if ((extra = seglen & (SCTP_ALIGN - 1)) != 0)
		extra = SCTP_ALIGN - extra;

	/* Find out if we need to piggyback SACK. */
	if (sctp->sctp_ftsn == sctp->sctp_lastacked + 1) {
		sacklen = 0;
	} else {
		sacklen = sizeof (sctp_chunk_hdr_t) +
		    sizeof (sctp_sack_chunk_t) +
		    (sizeof (sctp_sack_frag_t) * sctp->sctp_sack_gaps);
		if (seglen + sacklen > sctp->sctp_lastdata->sf_pmss) {
			/* piggybacked SACK doesn't fit */
			sacklen = 0;
		} else {
			/*
			 * OK, we have room to send SACK back.  But we
			 * should send it back to the last fp where we
			 * receive data from, unless sctp_lastdata equals
			 * oldfp, then we should probably not send it
			 * back to that fp.  Also we should check that
			 * the fp is alive.
			 */
			if (sctp->sctp_lastdata != oldfp &&
			    sctp->sctp_lastdata->sf_state ==
			    SCTP_FADDRS_ALIVE) {
				fp = sctp->sctp_lastdata;
			}
		}
	}

	/*
	 * Cancel RTT measurement if the retransmitted TSN is before the
	 * TSN used for timimg.
	 */
	if (sctp->sctp_out_time != 0 &&
	    SEQ_GEQ(sctp->sctp_rtt_tsn, sdc->sdh_tsn)) {
		sctp->sctp_out_time = 0;
	}
	/* Clear the counter as the RTT calculation may be off. */
	fp->sf_rtt_updates = 0;
	oldfp->sf_rtt_updates = 0;

	/*
	 * After a timeout, we should change the current faddr so that
	 * new chunks will be sent to the alternate address.
	 */
	sctp_set_faddr_current(sctp, fp);

	nmp = dupmsg(mp);
	if (nmp == NULL)
		goto restart_timer;
	if (extra > 0) {
		fill = sctp_get_padding(sctp, extra);
		if (fill != NULL) {
			linkb(nmp, fill);
			seglen += extra;
		} else {
			freemsg(nmp);
			goto restart_timer;
		}
	}
	SCTP_CHUNK_CLEAR_FLAGS(nmp);
	head = sctp_add_proto_hdr(sctp, fp, nmp, sacklen, NULL);
	if (head == NULL) {
		freemsg(nmp);
		SCTP_KSTAT(sctps, sctp_rexmit_failed);
		goto restart_timer;
	}
	seglen += sacklen;

	SCTP_CHUNK_SENT(sctp, mp, sdc, fp, chunklen, meta);

	mp = mp->b_next;

try_bundle:
	/* We can at least and at most send 1 packet at timeout. */
	while (seglen < fp->sf_pmss) {
		int32_t new_len;

		/* Go through the list to find more chunks to be bundled. */
		while (mp != NULL) {
			/* Check if the chunk can be bundled. */
			if (SCTP_CHUNK_RX_CANBUNDLE(mp, oldfp))
				break;
			mp = mp->b_next;
		}
		/* Go to the next message. */
		if (mp == NULL) {
			for (meta = meta->b_next; meta != NULL;
			    meta = meta->b_next) {
				mhdr = (sctp_msg_hdr_t *)meta->b_rptr;

				if (SCTP_IS_MSG_ABANDONED(meta) ||
				    SCTP_MSG_TO_BE_ABANDONED(meta, mhdr,
				    sctp)) {
					continue;
				}

				mp = meta->b_cont;
				goto try_bundle;
			}
			/*
			 * Check if there is a new message which potentially
			 * could be bundled with this retransmission.
			 */
			meta = sctp_get_msg_to_send(sctp, &mp, NULL, &error,
			    seglen, fp->sf_pmss - seglen, NULL);
			if (error != 0 || meta == NULL) {
				/* No more chunk to be bundled. */
				break;
			} else {
				goto try_bundle;
			}
		}

		sdc = (sctp_data_hdr_t *)mp->b_rptr;
		new_len = ntohs(sdc->sdh_len);
		chunklen = new_len - sizeof (*sdc);

		if ((extra = new_len & (SCTP_ALIGN - 1)) != 0)
			extra = SCTP_ALIGN - extra;
		if ((new_len = seglen + new_len + extra) > fp->sf_pmss)
			break;
		if ((nmp = dupmsg(mp)) == NULL)
			break;

		if (extra > 0) {
			fill = sctp_get_padding(sctp, extra);
			if (fill != NULL) {
				linkb(nmp, fill);
			} else {
				freemsg(nmp);
				break;
			}
		}
		linkb(head, nmp);

		SCTP_CHUNK_CLEAR_FLAGS(nmp);
		SCTP_CHUNK_SENT(sctp, mp, sdc, fp, chunklen, meta);

		seglen = new_len;
		mp = mp->b_next;
	}

	if ((seglen > fp->sf_pmss) && fp->sf_isv4) {
		ipha_t *iph = (ipha_t *)head->b_rptr;

		/*
		 * Path MTU is different from path we thought it would
		 * be when we created chunks, or IP headers have grown.
		 * Need to clear the DF bit.
		 */
		iph->ipha_fragment_offset_and_flags = 0;
	}
	fp->sf_rxt_unacked += seglen;

	dprint(2, ("sctp_rexmit: Sending packet %d bytes, tsn %x "
	    "ssn %d to %p (rwnd %d, lastack_rxd %x)\n",
	    seglen, ntohl(sdc->sdh_tsn), ntohs(sdc->sdh_ssn),
	    (void *)fp, sctp->sctp_frwnd, sctp->sctp_lastack_rxd));

	sctp->sctp_rexmitting = B_TRUE;
	sctp->sctp_rxt_nxttsn = first_ua_tsn;
	sctp->sctp_rxt_maxtsn = sctp->sctp_ltsn - 1;
	sctp_set_iplen(sctp, head, fp->sf_ixa);
	(void) conn_ip_output(head, fp->sf_ixa);
	BUMP_LOCAL(sctp->sctp_opkts);

	/*
	 * Restart the oldfp timer with exponential backoff and
	 * the new fp timer for the retransmitted chunks.
	 */
restart_timer:
	oldfp->sf_strikes++;
	sctp->sctp_strikes++;
	SCTP_CALC_RXT(sctp, oldfp, sctp->sctp_rto_max);
	/*
	 * If there is still some data in the oldfp, restart the
	 * retransmission timer.  If there is no data, the heartbeat will
	 * continue to run so it will do its job in checking the reachability
	 * of the oldfp.
	 */
	if (oldfp != fp && oldfp->sf_suna != 0)
		SCTP_FADDR_TIMER_RESTART(sctp, oldfp, oldfp->sf_rto);

	/*
	 * Should we restart the timer of the new fp?  If there is
	 * outstanding data to the new fp, the timer should be
	 * running already.  So restarting it means that the timer
	 * will fire later for those outstanding data.  But if
	 * we don't restart it, the timer will fire too early for the
	 * just retransmitted chunks to the new fp.  The reason is that we
	 * don't keep a timestamp on when a chunk is retransmitted.
	 * So when the timer fires, it will just search for the
	 * chunk with the earliest TSN sent to new fp.  This probably
	 * is the chunk we just retransmitted.  So for now, let's
	 * be conservative and restart the timer of the new fp.
	 */
	SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);

	sctp->sctp_active = ddi_get_lbolt64();
}

/*
 * This function is called by sctp_ss_rexmit() to create a packet
 * to be retransmitted to the given fp.  The given meta and mp
 * parameters are respectively the sctp_msg_hdr_t and the mblk of the
 * first chunk to be retransmitted.  This is also called when we want
 * to retransmit a zero window probe from sctp_rexmit() or when we
 * want to retransmit the zero window probe after the window has
 * opened from sctp_got_sack().
 */
mblk_t *
sctp_rexmit_packet(sctp_t *sctp, mblk_t **meta, mblk_t **mp, sctp_faddr_t *fp,
    uint_t *packet_len)
{
	uint32_t	seglen = 0;
	uint16_t	chunklen;
	int		extra;
	mblk_t		*nmp;
	mblk_t		*head;
	mblk_t		*fill;
	sctp_data_hdr_t	*sdc;
	sctp_msg_hdr_t	*mhdr;

	sdc = (sctp_data_hdr_t *)(*mp)->b_rptr;
	seglen = ntohs(sdc->sdh_len);
	chunklen = seglen - sizeof (*sdc);
	if ((extra = seglen & (SCTP_ALIGN - 1)) != 0)
		extra = SCTP_ALIGN - extra;

	nmp = dupmsg(*mp);
	if (nmp == NULL)
		return (NULL);
	if (extra > 0) {
		fill = sctp_get_padding(sctp, extra);
		if (fill != NULL) {
			linkb(nmp, fill);
			seglen += extra;
		} else {
			freemsg(nmp);
			return (NULL);
		}
	}
	SCTP_CHUNK_CLEAR_FLAGS(nmp);
	head = sctp_add_proto_hdr(sctp, fp, nmp, 0, NULL);
	if (head == NULL) {
		freemsg(nmp);
		return (NULL);
	}
	SCTP_CHUNK_SENT(sctp, *mp, sdc, fp, chunklen, *meta);
	/*
	 * Don't update the TSN if we are doing a Zero Win Probe.
	 */
	if (!sctp->sctp_zero_win_probe)
		sctp->sctp_rxt_nxttsn = ntohl(sdc->sdh_tsn);
	*mp = (*mp)->b_next;

try_bundle:
	while (seglen < fp->sf_pmss) {
		int32_t new_len;

		/*
		 * Go through the list to find more chunks to be bundled.
		 * We should only retransmit sent by unack'ed chunks.  Since
		 * they were sent before, the peer's receive window should
		 * be able to receive them.
		 */
		while (*mp != NULL) {
			/* Check if the chunk can be bundled. */
			if (SCTP_CHUNK_ISSENT(*mp) && !SCTP_CHUNK_ISACKED(*mp))
				break;
			*mp = (*mp)->b_next;
		}
		/* Go to the next message. */
		if (*mp == NULL) {
			for (*meta = (*meta)->b_next; *meta != NULL;
			    *meta = (*meta)->b_next) {
				mhdr = (sctp_msg_hdr_t *)(*meta)->b_rptr;

				if (SCTP_IS_MSG_ABANDONED(*meta) ||
				    SCTP_MSG_TO_BE_ABANDONED(*meta, mhdr,
				    sctp)) {
					continue;
				}

				*mp = (*meta)->b_cont;
				goto try_bundle;
			}
			/* No more chunk to be bundled. */
			break;
		}

		sdc = (sctp_data_hdr_t *)(*mp)->b_rptr;
		/* Don't bundle chunks beyond sctp_rxt_maxtsn. */
		if (SEQ_GT(ntohl(sdc->sdh_tsn), sctp->sctp_rxt_maxtsn))
			break;
		new_len = ntohs(sdc->sdh_len);
		chunklen = new_len - sizeof (*sdc);

		if ((extra = new_len & (SCTP_ALIGN - 1)) != 0)
			extra = SCTP_ALIGN - extra;
		if ((new_len = seglen + new_len + extra) > fp->sf_pmss)
			break;
		if ((nmp = dupmsg(*mp)) == NULL)
			break;

		if (extra > 0) {
			fill = sctp_get_padding(sctp, extra);
			if (fill != NULL) {
				linkb(nmp, fill);
			} else {
				freemsg(nmp);
				break;
			}
		}
		linkb(head, nmp);

		SCTP_CHUNK_CLEAR_FLAGS(nmp);
		SCTP_CHUNK_SENT(sctp, *mp, sdc, fp, chunklen, *meta);
		/*
		 * Don't update the TSN if we are doing a Zero Win Probe.
		 */
		if (!sctp->sctp_zero_win_probe)
			sctp->sctp_rxt_nxttsn = ntohl(sdc->sdh_tsn);

		seglen = new_len;
		*mp = (*mp)->b_next;
	}
	*packet_len = seglen;
	fp->sf_rxt_unacked += seglen;
	return (head);
}

/*
 * sctp_ss_rexmit() is called when we get a SACK after a timeout which
 * advances the cum_tsn but the cum_tsn is still less than what we have sent
 * (sctp_rxt_maxtsn) at the time of the timeout.  This SACK is a "partial"
 * SACK.  We retransmit unacked chunks without having to wait for another
 * timeout.  The rationale is that the SACK should not be "partial" if all the
 * lost chunks have been retransmitted.  Since the SACK is "partial,"
 * the chunks between the cum_tsn and the sctp_rxt_maxtsn should still
 * be missing.  It is better for us to retransmit them now instead
 * of waiting for a timeout.
 */
void
sctp_ss_rexmit(sctp_t *sctp)
{
	mblk_t		*meta;
	mblk_t		*mp;
	mblk_t		*pkt;
	sctp_faddr_t	*fp;
	uint_t		pkt_len;
	uint32_t	tot_wnd;
	sctp_data_hdr_t	*sdc;
	int		burst;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	ASSERT(!sctp->sctp_zero_win_probe);

	/*
	 * If the last cum ack is smaller than what we have just
	 * retransmitted, simply return.
	 */
	if (SEQ_GEQ(sctp->sctp_lastack_rxd, sctp->sctp_rxt_nxttsn))
		sctp->sctp_rxt_nxttsn = sctp->sctp_lastack_rxd + 1;
	else
		return;
	ASSERT(SEQ_LEQ(sctp->sctp_rxt_nxttsn, sctp->sctp_rxt_maxtsn));

	/*
	 * After a timer fires, sctp_current should be set to the new
	 * fp where the retransmitted chunks are sent.
	 */
	fp = sctp->sctp_current;

	/*
	 * Since we are retransmitting, we only need to use cwnd to determine
	 * how much we can send as we were allowed (by peer's receive window)
	 * to send those retransmitted chunks previously when they are first
	 * sent.  If we record how much we have retransmitted but
	 * unacknowledged using rxt_unacked, then the amount we can now send
	 * is equal to cwnd minus rxt_unacked.
	 *
	 * The field rxt_unacked is incremented when we retransmit a packet
	 * and decremented when we got a SACK acknowledging something.  And
	 * it is reset when the retransmission timer fires as we assume that
	 * all packets have left the network after a timeout.  If this
	 * assumption is not true, it means that after a timeout, we can
	 * get a SACK acknowledging more than rxt_unacked (its value only
	 * contains what is retransmitted when the timer fires).  So
	 * rxt_unacked will become very big (it is an unsiged int so going
	 * negative means that the value is huge).  This is the reason we
	 * always send at least 1 MSS bytes.
	 *
	 * The reason why we do not have an accurate count is that we
	 * only know how many packets are outstanding (using the TSN numbers).
	 * But we do not know how many bytes those packets contain.  To
	 * have an accurate count, we need to walk through the send list.
	 * As it is not really important to have an accurate count during
	 * retransmission, we skip this walk to save some time.  This should
	 * not make the retransmission too aggressive to cause congestion.
	 */
	if (fp->sf_cwnd <= fp->sf_rxt_unacked)
		tot_wnd = fp->sf_pmss;
	else
		tot_wnd = fp->sf_cwnd - fp->sf_rxt_unacked;

	/* Find the first unack'ed chunk */
	for (meta = sctp->sctp_xmit_head; meta != NULL; meta = meta->b_next) {
		sctp_msg_hdr_t	*mhdr = (sctp_msg_hdr_t *)meta->b_rptr;

		if (SCTP_IS_MSG_ABANDONED(meta) ||
		    SCTP_MSG_TO_BE_ABANDONED(meta, mhdr, sctp)) {
			continue;
		}

		for (mp = meta->b_cont; mp != NULL; mp = mp->b_next) {
			/* Again, this may not be possible */
			if (!SCTP_CHUNK_ISSENT(mp))
				return;
			sdc = (sctp_data_hdr_t *)mp->b_rptr;
			if (ntohl(sdc->sdh_tsn) == sctp->sctp_rxt_nxttsn)
				goto found_msg;
		}
	}

	/* Everything is abandoned... */
	return;

found_msg:
	if (!fp->sf_timer_running)
		SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
	pkt = sctp_rexmit_packet(sctp, &meta, &mp, fp, &pkt_len);
	if (pkt == NULL) {
		SCTP_KSTAT(sctps, sctp_ss_rexmit_failed);
		return;
	}
	if ((pkt_len > fp->sf_pmss) && fp->sf_isv4) {
		ipha_t	*iph = (ipha_t *)pkt->b_rptr;

		/*
		 * Path MTU is different from path we thought it would
		 * be when we created chunks, or IP headers have grown.
		 *  Need to clear the DF bit.
		 */
		iph->ipha_fragment_offset_and_flags = 0;
	}
	sctp_set_iplen(sctp, pkt, fp->sf_ixa);
	(void) conn_ip_output(pkt, fp->sf_ixa);
	BUMP_LOCAL(sctp->sctp_opkts);

	/* Check and see if there is more chunk to be retransmitted. */
	if (tot_wnd <= pkt_len || tot_wnd - pkt_len < fp->sf_pmss ||
	    meta == NULL)
		return;
	if (mp == NULL)
		meta = meta->b_next;
	if (meta == NULL)
		return;

	/* Retransmit another packet if the window allows. */
	for (tot_wnd -= pkt_len, burst = sctps->sctps_maxburst - 1;
	    meta != NULL && burst > 0; meta = meta->b_next, burst--) {
		if (mp == NULL)
			mp = meta->b_cont;
		for (; mp != NULL; mp = mp->b_next) {
			/* Again, this may not be possible */
			if (!SCTP_CHUNK_ISSENT(mp))
				return;
			if (!SCTP_CHUNK_ISACKED(mp))
				goto found_msg;
		}
	}
}
