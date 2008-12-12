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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/tihdr.h>
#include <sys/kmem.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/sctp.h>

#include <inet/common.h>
#include <inet/ipclassifier.h>
#include <inet/ip.h>

#include "sctp_impl.h"

/* ARGSUSED */
static void
sctp_notify(sctp_t *sctp, mblk_t *emp, size_t len)
{
	struct T_unitdata_ind *tudi;
	mblk_t *mp;
	sctp_faddr_t *fp;
	int32_t rwnd = 0;
	int error;

	if ((mp = allocb(sizeof (*tudi) + sizeof (void *) +
		sizeof (struct sockaddr_in6), BPRI_HI)) == NULL) {
		/* XXX trouble: don't want to drop events. should queue it. */
		freemsg(emp);
		return;
	}
	dprint(3, ("sctp_notify: event %d\n", (*(uint16_t *)emp->b_rptr)));

	mp->b_datap->db_type = M_PROTO;
	mp->b_flag |= MSGMARK;
	mp->b_rptr += sizeof (void *); /* pointer worth of padding */

	tudi = (struct T_unitdata_ind *)mp->b_rptr;
	tudi->PRIM_type = T_UNITDATA_IND;
	tudi->SRC_offset = sizeof (*tudi);
	tudi->OPT_length = 0;
	tudi->OPT_offset = 0;

	fp = sctp->sctp_primary;
	ASSERT(fp);

	/*
	 * Fill in primary remote address.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&fp->faddr)) {
		struct sockaddr_in *sin4;

		tudi->SRC_length = sizeof (*sin4);
		sin4 = (struct sockaddr_in *)(tudi + 1);
		sin4->sin_family = AF_INET;
		sin4->sin_port = sctp->sctp_fport;
		IN6_V4MAPPED_TO_IPADDR(&fp->faddr, sin4->sin_addr.s_addr);
		mp->b_wptr = (uchar_t *)(sin4 + 1);
	} else {
		struct sockaddr_in6 *sin6;

		tudi->SRC_length = sizeof (*sin6);
		sin6 = (struct sockaddr_in6 *)(tudi + 1);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = sctp->sctp_fport;
		sin6->sin6_addr = fp->faddr;
		mp->b_wptr = (uchar_t *)(sin6 + 1);
	}

	mp->b_cont = emp;

	/*
	 * Notifications are queued regardless of socket rx space.  So
	 * we do not decrement sctp_rwnd here as this will confuse the
	 * other side.
	 */
#ifdef DEBUG
	for (emp = mp->b_cont; emp; emp = emp->b_cont) {
		rwnd += emp->b_wptr - emp->b_rptr;
	}
	ASSERT(len == rwnd);
#endif

	/*
	 * Override b_flag for SCTP sockfs internal use
	 */
	mp->b_flag = (short)SCTP_NOTIFICATION;

	rwnd = sctp->sctp_ulp_recv(sctp->sctp_ulpd, mp, msgdsize(mp), 0,
	    &error, NULL);
	if (rwnd > sctp->sctp_rwnd) {
		sctp->sctp_rwnd = rwnd;
	}
}

void
sctp_assoc_event(sctp_t *sctp, uint16_t state, uint16_t error,
    sctp_chunk_hdr_t *ch)
{
	struct sctp_assoc_change *sacp;
	mblk_t *mp;
	uint16_t ch_len;

	if (!sctp->sctp_recvassocevnt) {
		return;
	}

	ch_len = (ch != NULL) ? ntohs(ch->sch_len) : 0;

	if ((mp = allocb(sizeof (*sacp) + ch_len, BPRI_MED)) == NULL) {
		return;
	}

	sacp = (struct sctp_assoc_change *)mp->b_rptr;
	sacp->sac_type = SCTP_ASSOC_CHANGE;
	sacp->sac_flags = sctp->sctp_prsctp_aware ? SCTP_PRSCTP_CAPABLE : 0;
	sacp->sac_length = sizeof (*sacp) + ch_len;
	sacp->sac_state = state;
	sacp->sac_error = error;
	sacp->sac_outbound_streams = sctp->sctp_num_ostr;
	sacp->sac_inbound_streams = sctp->sctp_num_istr;
	sacp->sac_assoc_id = 0;

	if (ch != NULL)
		bcopy(ch, sacp + 1, ch_len);
	mp->b_wptr += sacp->sac_length;
	sctp_notify(sctp, mp, sacp->sac_length);
}

/*
 * Send failure event. Message is expected to have message header still
 * in place, data follows in subsequent mblk's.
 */
static void
sctp_sendfail(sctp_t *sctp, mblk_t *msghdr, uint16_t flags, int error)
{
	struct sctp_send_failed *sfp;
	mblk_t *mp;
	sctp_msg_hdr_t *smh;

	/* Allocate a mblk for the notification header */
	if ((mp = allocb(sizeof (*sfp), BPRI_MED)) == NULL) {
		/* give up */
		freemsg(msghdr);
		return;
	}

	smh = (sctp_msg_hdr_t *)msghdr->b_rptr;
	sfp = (struct sctp_send_failed *)mp->b_rptr;
	sfp->ssf_type = SCTP_SEND_FAILED;
	sfp->ssf_flags = flags;
	sfp->ssf_length = smh->smh_msglen + sizeof (*sfp);
	sfp->ssf_error = error;
	sfp->ssf_assoc_id = 0;

	bzero(&sfp->ssf_info, sizeof (sfp->ssf_info));
	sfp->ssf_info.sinfo_stream = smh->smh_sid;
	sfp->ssf_info.sinfo_flags = smh->smh_flags;
	sfp->ssf_info.sinfo_ppid = smh->smh_ppid;
	sfp->ssf_info.sinfo_context = smh->smh_context;
	sfp->ssf_info.sinfo_timetolive = TICK_TO_MSEC(smh->smh_ttl);

	mp->b_wptr = (uchar_t *)(sfp + 1);
	mp->b_cont = msghdr->b_cont;

	freeb(msghdr);

	sctp_notify(sctp, mp, sfp->ssf_length);

}

/*
 * Send failure when the message has been fully chunkified.
 */
static void
sctp_sendfail_sent(sctp_t *sctp, mblk_t *meta, int error)
{
	mblk_t		*mp;
	mblk_t		*nmp;
	mblk_t		*tail;
	uint16_t	flags = SCTP_DATA_SENT;

	if (!sctp->sctp_recvsendfailevnt) {
		sctp_free_msg(meta);
		return;
	}

	/*
	 * We need to remove all data_hdr's.
	 */
	nmp = meta->b_cont;
	tail = meta;
	do {
		mp = nmp->b_next;
		nmp->b_next = NULL;

		/*
		 * If one of the chunks hasn't been sent yet, say that
		 * the message hasn't been sent.
		 */
		if (!SCTP_CHUNK_ISSENT(nmp)) {
			flags = SCTP_DATA_UNSENT;
		}
		nmp->b_rptr += sizeof (sctp_data_hdr_t);
		if (nmp->b_rptr == nmp->b_wptr) {
			tail->b_cont = nmp->b_cont;
			freeb(nmp);
		} else {
			tail->b_cont = nmp;
		}
		while (tail->b_cont) {
			tail = tail->b_cont;
		}
	} while ((nmp = mp) != NULL);

	sctp_sendfail(sctp, meta, flags, error);
}

/*
 * Send failure when the message hasn't been fully chunkified.
 */
void
sctp_sendfail_event(sctp_t *sctp, mblk_t *meta, int error, boolean_t chunkified)
{
	mblk_t	*mp;
	mblk_t	*nmp;
	mblk_t	*tail;

	if (meta == NULL)
		return;

	if (!sctp->sctp_recvsendfailevnt) {
		sctp_free_msg(meta);
		return;
	}

	/* If the message is fully chunkified */
	if (chunkified) {
		sctp_sendfail_sent(sctp, meta, error);
		return;
	}
	/*
	 * Message might be partially chunkified, we need to remove
	 * all data_hdr's.
	 */
	mp = meta->b_cont;
	tail = meta;
	while ((nmp = mp->b_next) != NULL) {
		mp->b_next = nmp->b_next;
		nmp->b_next = NULL;
		nmp->b_rptr += sizeof (sctp_data_hdr_t);
		if (nmp->b_rptr == nmp->b_wptr) {
			tail->b_cont = nmp->b_cont;
			freeb(nmp);
		} else {
			tail->b_cont = nmp;
		}
		while (tail->b_cont) {
			tail = tail->b_cont;
		}
	}
	tail->b_cont = mp;

	sctp_sendfail(sctp, meta, SCTP_DATA_UNSENT, error);
}

void
sctp_regift_xmitlist(sctp_t *sctp)
{
	mblk_t *mp;

	if (!sctp->sctp_recvsendfailevnt) {
		return;
	}

	while ((mp = sctp->sctp_xmit_head) != NULL) {
		sctp->sctp_xmit_head = mp->b_next;
		mp->b_next = NULL;
		if (sctp->sctp_xmit_head != NULL)
			sctp->sctp_xmit_head->b_prev = NULL;
		sctp_sendfail_event(sctp, mp, 0, B_TRUE);
	}
	while ((mp = sctp->sctp_xmit_unsent) != NULL) {
		sctp->sctp_xmit_unsent = mp->b_next;
		mp->b_next = NULL;
		sctp_sendfail_event(sctp, mp, 0, B_FALSE);
	}
	sctp->sctp_xmit_tail = sctp->sctp_xmit_unsent_tail = NULL;
	sctp->sctp_unacked = sctp->sctp_unsent = 0;
}

void
sctp_intf_event(sctp_t *sctp, in6_addr_t addr, int state, int error)
{
	struct sctp_paddr_change *spc;
	ipaddr_t addr4;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	mblk_t *mp;

	if (!sctp->sctp_recvpathevnt) {
		return;
	}

	if ((mp = allocb(sizeof (*spc), BPRI_MED)) == NULL) {
		return;
	}

	spc = (struct sctp_paddr_change *)mp->b_rptr;
	spc->spc_type = SCTP_PEER_ADDR_CHANGE;
	spc->spc_flags = 0;
	spc->spc_length = sizeof (*spc);
	if (IN6_IS_ADDR_V4MAPPED(&addr)) {
		IN6_V4MAPPED_TO_IPADDR(&addr, addr4);
		sin = (struct sockaddr_in *)&spc->spc_aaddr;
		sin->sin_family = AF_INET;
		sin->sin_port = 0;
		sin->sin_addr.s_addr = addr4;
	} else {
		sin6 = (struct sockaddr_in6 *)&spc->spc_aaddr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = 0;
		sin6->sin6_addr = addr;
	}
	spc->spc_state = state;
	spc->spc_error = error;
	spc->spc_assoc_id = 0;

	mp->b_wptr = (uchar_t *)(spc + 1);
	sctp_notify(sctp, mp, spc->spc_length);
}

void
sctp_error_event(sctp_t *sctp, sctp_chunk_hdr_t *ch)
{
	struct sctp_remote_error *sre;
	mblk_t *mp;
	size_t len;
	sctp_parm_hdr_t *errh;
	uint16_t dlen = 0;
	uint16_t error = 0;
	void *dtail = NULL;

	if (!sctp->sctp_recvpeererr) {
		return;
	}

	if (ntohs(ch->sch_len) > sizeof (*ch)) {
		errh = (sctp_parm_hdr_t *)(ch + 1);
		error = ntohs(errh->sph_type);
		dlen = ntohs(errh->sph_len) - sizeof (*errh);
		if (dlen > 0) {
			dtail = errh + 1;
		}
	}

	len = sizeof (*sre) + dlen;
	if ((mp = allocb(len, BPRI_MED)) == NULL) {
		return;
	}

	sre = (struct sctp_remote_error *)mp->b_rptr;
	sre->sre_type = SCTP_REMOTE_ERROR;
	sre->sre_flags = 0;
	sre->sre_length = len;
	sre->sre_assoc_id = 0;
	sre->sre_error = error;
	if (dtail) {
		bcopy(dtail, sre + 1, dlen);
	}

	mp->b_wptr = mp->b_rptr + len;
	sctp_notify(sctp, mp, len);
}

void
sctp_shutdown_event(sctp_t *sctp)
{
	struct sctp_shutdown_event *sse;
	mblk_t *mp;

	if (!sctp->sctp_recvshutdownevnt) {
		return;
	}

	if ((mp = allocb(sizeof (*sse), BPRI_MED)) == NULL) {
		return;
	}

	sse = (struct sctp_shutdown_event *)mp->b_rptr;
	sse->sse_type = SCTP_SHUTDOWN_EVENT;
	sse->sse_flags = 0;
	sse->sse_length = sizeof (*sse);
	sse->sse_assoc_id = 0;

	mp->b_wptr = (uchar_t *)(sse + 1);
	sctp_notify(sctp, mp, sse->sse_length);
}

void
sctp_adaptation_event(sctp_t *sctp)
{
	struct sctp_adaptation_event *sai;
	mblk_t *mp;

	if (!sctp->sctp_recvalevnt || !sctp->sctp_recv_adaptation) {
		return;
	}
	if ((mp = allocb(sizeof (*sai), BPRI_MED)) == NULL) {
		return;
	}

	sai = (struct sctp_adaptation_event *)mp->b_rptr;
	sai->sai_type = SCTP_ADAPTATION_INDICATION;
	sai->sai_flags = 0;
	sai->sai_length = sizeof (*sai);
	sai->sai_assoc_id = 0;
	/*
	 * Adaptation code delivered in network byte order.
	 */
	sai->sai_adaptation_ind = sctp->sctp_rx_adaptation_code;

	mp->b_wptr = (uchar_t *)(sai + 1);
	sctp_notify(sctp, mp, sai->sai_length);

	sctp->sctp_recv_adaptation = 0; /* in case there's a restart later */
}

/* Send partial deliver event */
void
sctp_partial_delivery_event(sctp_t *sctp)
{
	struct sctp_pdapi_event	*pdapi;
	mblk_t			*mp;

	if (!sctp->sctp_recvpdevnt)
		return;

	if ((mp = allocb(sizeof (*pdapi), BPRI_MED)) == NULL)
		return;

	pdapi = (struct sctp_pdapi_event *)mp->b_rptr;
	pdapi->pdapi_type = SCTP_PARTIAL_DELIVERY_EVENT;
	pdapi->pdapi_flags = 0;
	pdapi->pdapi_length = sizeof (*pdapi);
	pdapi->pdapi_indication = SCTP_PARTIAL_DELIVERY_ABORTED;
	pdapi->pdapi_assoc_id = 0;
	mp->b_wptr = (uchar_t *)(pdapi + 1);
	sctp_notify(sctp, mp, pdapi->pdapi_length);
}
