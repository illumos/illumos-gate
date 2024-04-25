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
 * Copyright 2024 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp_seq.h>
#include <netinet/sctp.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_if.h>
#include <inet/ip6.h>
#include <inet/mib2.h>
#include <inet/ipclassifier.h>
#include <inet/ipp_common.h>
#include <inet/ipsec_impl.h>
#include <inet/sctp_ip.h>

#include "sctp_impl.h"
#include "sctp_asconf.h"
#include "sctp_addr.h"

static struct kmem_cache *sctp_kmem_set_cache;

/*
 * PR-SCTP comments.
 *
 * When we get a valid Forward TSN chunk, we check the fragment list for this
 * SSN and preceeding SSNs free all them. Further, if this Forward TSN causes
 * the next expected SSN to be present in the stream queue, we deliver any
 * such stranded messages upstream. We also update the SACK info. appropriately.
 * When checking for advancing the cumulative ack (in sctp_cumack()) we must
 * check for abandoned chunks and messages. While traversing the tramsmit
 * list if we come across an abandoned chunk, we can skip the message (i.e.
 * take it out of the (re)transmit list) since this message, and hence this
 * chunk, has been marked abandoned by sctp_rexmit(). If we come across an
 * unsent chunk for a message this now abandoned we need to check if a
 * Forward TSN needs to be sent, this could be a case where we deferred sending
 * a Forward TSN in sctp_get_msg_to_send(). Further, after processing a
 * SACK we check if the Advanced peer ack point can be moved ahead, i.e.
 * if we can send a Forward TSN via sctp_check_abandoned_data().
 */
void
sctp_free_set(sctp_set_t *s)
{
	sctp_set_t *p;

	while (s) {
		p = s->next;
		kmem_cache_free(sctp_kmem_set_cache, s);
		s = p;
	}
}

static void
sctp_ack_add(sctp_set_t **head, uint32_t tsn, int *num)
{
	sctp_set_t *p, *t;

	if (head == NULL || num == NULL)
		return;

	ASSERT(*num >= 0);
	ASSERT((*num == 0 && *head == NULL) || (*num > 0 && *head != NULL));

	if (*head == NULL) {
		*head = kmem_cache_alloc(sctp_kmem_set_cache, KM_NOSLEEP);
		if (*head == NULL)
			return;
		(*head)->prev = (*head)->next = NULL;
		(*head)->begin = tsn;
		(*head)->end = tsn;
		*num = 1;
		return;
	}

	ASSERT((*head)->prev == NULL);

	/*
	 * Handle this special case here so we don't have to check
	 * for it each time in the loop.
	 */
	if (SEQ_LT(tsn + 1, (*head)->begin)) {
		/* add a new set, and move the head pointer */
		t = kmem_cache_alloc(sctp_kmem_set_cache, KM_NOSLEEP);
		if (t == NULL)
			return;
		t->next = *head;
		t->prev = NULL;
		(*head)->prev = t;
		t->begin = tsn;
		t->end = tsn;
		(*num)++;
		*head = t;
		return;
	}

	/*
	 * We need to handle the following cases, where p points to
	 * the current set (as we walk through the loop):
	 *
	 * 1. tsn is entirely less than p; create a new set before p.
	 * 2. tsn borders p from less; coalesce p with tsn.
	 * 3. tsn is withing p; do nothing.
	 * 4. tsn borders p from greater; coalesce p with tsn.
	 * 4a. p may now border p->next from less; if so, coalesce those
	 *    two sets.
	 * 5. tsn is entirely greater then all sets; add a new set at
	 *    the end.
	 */
	for (p = *head; ; p = p->next) {
		if (SEQ_LT(tsn + 1, p->begin)) {
			/* 1: add a new set before p. */
			t = kmem_cache_alloc(sctp_kmem_set_cache, KM_NOSLEEP);
			if (t == NULL)
				return;
			t->next = p;
			t->prev = NULL;
			t->begin = tsn;
			t->end = tsn;
			if (p->prev) {
				t->prev = p->prev;
				p->prev->next = t;
			}
			p->prev = t;
			(*num)++;
			return;
		}

		if ((tsn + 1) == p->begin) {
			/* 2: adjust p->begin */
			p->begin = tsn;
			return;
		}

		if (SEQ_GEQ(tsn, p->begin) && SEQ_LEQ(tsn, p->end)) {
			/* 3; do nothing */
			return;
		}

		if ((p->end + 1) == tsn) {
			/* 4; adjust p->end */
			p->end = tsn;

			if (p->next != NULL && (tsn + 1) == p->next->begin) {
				/* 4a: coalesce p and p->next */
				t = p->next;
				p->end = t->end;
				p->next = t->next;
				if (t->next != NULL)
					t->next->prev = p;
				kmem_cache_free(sctp_kmem_set_cache, t);
				(*num)--;
			}
			return;
		}

		if (p->next == NULL) {
			/* 5: add new set at the end */
			t = kmem_cache_alloc(sctp_kmem_set_cache, KM_NOSLEEP);
			if (t == NULL)
				return;
			t->next = NULL;
			t->prev = p;
			t->begin = tsn;
			t->end = tsn;
			p->next = t;
			(*num)++;
			return;
		}

		if (SEQ_GT(tsn, p->end + 1))
			continue;
	}
}

static void
sctp_ack_rem(sctp_set_t **head, uint32_t end, int *num)
{
	sctp_set_t *p, *t;

	if (head == NULL || *head == NULL || num == NULL)
		return;

	/* Nothing to remove */
	if (SEQ_LT(end, (*head)->begin))
		return;

	/* Find out where to start removing sets */
	for (p = *head; p->next; p = p->next) {
		if (SEQ_LEQ(end, p->end))
			break;
	}

	if (SEQ_LT(end, p->end) && SEQ_GEQ(end, p->begin)) {
		/* adjust p */
		p->begin = end + 1;
		/* all done */
		if (p == *head)
			return;
	} else if (SEQ_GEQ(end, p->end)) {
		/* remove this set too */
		p = p->next;
	}

	/* unlink everything before this set */
	t = *head;
	*head = p;
	if (p != NULL && p->prev != NULL) {
		p->prev->next = NULL;
		p->prev = NULL;
	}

	sctp_free_set(t);

	/* recount the number of sets */
	*num = 0;

	for (p = *head; p != NULL; p = p->next)
		(*num)++;
}

void
sctp_sets_init()
{
	sctp_kmem_set_cache = kmem_cache_create("sctp_set_cache",
	    sizeof (sctp_set_t), 0, NULL, NULL, NULL, NULL,
	    NULL, 0);
}

void
sctp_sets_fini()
{
	kmem_cache_destroy(sctp_kmem_set_cache);
}

sctp_chunk_hdr_t *
sctp_first_chunk(uchar_t *rptr, ssize_t remaining)
{
	sctp_chunk_hdr_t *ch;
	uint16_t ch_len;

	if (remaining < sizeof (*ch)) {
		return (NULL);
	}

	ch = (sctp_chunk_hdr_t *)rptr;
	ch_len = ntohs(ch->sch_len);

	if (ch_len < sizeof (*ch) || remaining < ch_len) {
		return (NULL);
	}

	return (ch);
}

sctp_chunk_hdr_t *
sctp_next_chunk(sctp_chunk_hdr_t *ch, ssize_t *remaining)
{
	int pad;
	uint16_t ch_len;

	if (!ch) {
		return (NULL);
	}

	ch_len = ntohs(ch->sch_len);

	if ((pad = ch_len & (SCTP_ALIGN - 1)) != 0) {
		pad = SCTP_ALIGN - pad;
	}

	*remaining -= (ch_len + pad);
	ch = (sctp_chunk_hdr_t *)((char *)ch + ch_len + pad);

	return (sctp_first_chunk((uchar_t *)ch, *remaining));
}

/*
 * Attach ancillary data to a received SCTP segments.
 * If the source address (fp) is not the primary, send up a
 * unitdata_ind so recvfrom() can populate the msg_name field.
 * If ancillary data is also requested, we append it to the
 * unitdata_req. Otherwise, we just send up an optdata_ind.
 */
static int
sctp_input_add_ancillary(sctp_t *sctp, mblk_t **mp, sctp_data_hdr_t *dcp,
    sctp_faddr_t *fp, ip_pkt_t *ipp, ip_recv_attr_t *ira)
{
	struct T_unitdata_ind	*tudi;
	int			optlen;
	int			hdrlen;
	uchar_t			*optptr;
	struct cmsghdr		*cmsg;
	mblk_t			*mp1;
	struct sockaddr_in6	sin_buf[1];
	struct sockaddr_in6	*sin6;
	struct sockaddr_in	*sin4;
	crb_t			 addflag;	/* Which pieces to add */
	conn_t			*connp = sctp->sctp_connp;

	sin4 = NULL;
	sin6 = NULL;

	optlen = hdrlen = 0;
	addflag.crb_all = 0;

	/* Figure out address size */
	if (connp->conn_family == AF_INET) {
		sin4 = (struct sockaddr_in *)sin_buf;
		sin4->sin_family = AF_INET;
		sin4->sin_port = connp->conn_fport;
		IN6_V4MAPPED_TO_IPADDR(&fp->sf_faddr, sin4->sin_addr.s_addr);
		hdrlen = sizeof (*tudi) + sizeof (*sin4);
	} else {
		sin6 = sin_buf;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = connp->conn_fport;
		sin6->sin6_addr = fp->sf_faddr;
		hdrlen = sizeof (*tudi) + sizeof (*sin6);
	}
	/* If app asked to receive send / recv info */
	if (sctp->sctp_recvsndrcvinfo)
		optlen += sizeof (*cmsg) + sizeof (struct sctp_sndrcvinfo);

	if (connp->conn_recv_ancillary.crb_all == 0)
		goto noancillary;

	if (connp->conn_recv_ancillary.crb_ip_recvpktinfo &&
	    ira->ira_ruifindex != sctp->sctp_recvifindex) {
		optlen += sizeof (*cmsg) + sizeof (struct in6_pktinfo);
		if (hdrlen == 0)
			hdrlen = sizeof (struct T_unitdata_ind);
		addflag.crb_ip_recvpktinfo = 1;
	}
	/* If app asked for hoplimit and it has changed ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvhoplimit &&
	    ipp->ipp_hoplimit != sctp->sctp_recvhops) {
		optlen += sizeof (*cmsg) + sizeof (uint_t);
		if (hdrlen == 0)
			hdrlen = sizeof (struct T_unitdata_ind);
		addflag.crb_ipv6_recvhoplimit = 1;
	}
	/* If app asked for tclass and it has changed ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvtclass &&
	    ipp->ipp_tclass != sctp->sctp_recvtclass) {
		optlen += sizeof (struct T_opthdr) + sizeof (uint_t);
		if (hdrlen == 0)
			hdrlen = sizeof (struct T_unitdata_ind);
		addflag.crb_ipv6_recvtclass = 1;
	}
	/* If app asked for hopbyhop headers and it has changed ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvhopopts &&
	    ip_cmpbuf(sctp->sctp_hopopts, sctp->sctp_hopoptslen,
	    (ipp->ipp_fields & IPPF_HOPOPTS),
	    ipp->ipp_hopopts, ipp->ipp_hopoptslen)) {
		optlen += sizeof (*cmsg) + ipp->ipp_hopoptslen -
		    sctp->sctp_v6label_len;
		if (hdrlen == 0)
			hdrlen = sizeof (struct T_unitdata_ind);
		addflag.crb_ipv6_recvhopopts = 1;
		if (!ip_allocbuf((void **)&sctp->sctp_hopopts,
		    &sctp->sctp_hopoptslen,
		    (ipp->ipp_fields & IPPF_HOPOPTS),
		    ipp->ipp_hopopts, ipp->ipp_hopoptslen))
			return (-1);
	}
	/* If app asked for dst headers before routing headers ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvrthdrdstopts &&
	    ip_cmpbuf(sctp->sctp_rthdrdstopts, sctp->sctp_rthdrdstoptslen,
	    (ipp->ipp_fields & IPPF_RTHDRDSTOPTS),
	    ipp->ipp_rthdrdstopts, ipp->ipp_rthdrdstoptslen)) {
		optlen += sizeof (*cmsg) + ipp->ipp_rthdrdstoptslen;
		if (hdrlen == 0)
			hdrlen = sizeof (struct T_unitdata_ind);
		addflag.crb_ipv6_recvrthdrdstopts = 1;
		if (!ip_allocbuf((void **)&sctp->sctp_rthdrdstopts,
		    &sctp->sctp_rthdrdstoptslen,
		    (ipp->ipp_fields & IPPF_RTHDRDSTOPTS),
		    ipp->ipp_rthdrdstopts, ipp->ipp_rthdrdstoptslen))
			return (-1);
	}
	/* If app asked for routing headers and it has changed ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvrthdr &&
	    ip_cmpbuf(sctp->sctp_rthdr, sctp->sctp_rthdrlen,
	    (ipp->ipp_fields & IPPF_RTHDR),
	    ipp->ipp_rthdr, ipp->ipp_rthdrlen)) {
		optlen += sizeof (*cmsg) + ipp->ipp_rthdrlen;
		if (hdrlen == 0)
			hdrlen = sizeof (struct T_unitdata_ind);
		addflag.crb_ipv6_recvrthdr = 1;
		if (!ip_allocbuf((void **)&sctp->sctp_rthdr,
		    &sctp->sctp_rthdrlen,
		    (ipp->ipp_fields & IPPF_RTHDR),
		    ipp->ipp_rthdr, ipp->ipp_rthdrlen))
			return (-1);
	}
	/* If app asked for dest headers and it has changed ... */
	if (connp->conn_recv_ancillary.crb_ipv6_recvdstopts &&
	    ip_cmpbuf(sctp->sctp_dstopts, sctp->sctp_dstoptslen,
	    (ipp->ipp_fields & IPPF_DSTOPTS),
	    ipp->ipp_dstopts, ipp->ipp_dstoptslen)) {
		optlen += sizeof (*cmsg) + ipp->ipp_dstoptslen;
		if (hdrlen == 0)
			hdrlen = sizeof (struct T_unitdata_ind);
		addflag.crb_ipv6_recvdstopts = 1;
		if (!ip_allocbuf((void **)&sctp->sctp_dstopts,
		    &sctp->sctp_dstoptslen,
		    (ipp->ipp_fields & IPPF_DSTOPTS),
		    ipp->ipp_dstopts, ipp->ipp_dstoptslen))
			return (-1);
	}
noancillary:
	/* Nothing to add */
	if (hdrlen == 0)
		return (-1);

	mp1 = allocb(hdrlen + optlen + sizeof (void *), BPRI_MED);
	if (mp1 == NULL)
		return (-1);
	mp1->b_cont = *mp;
	*mp = mp1;
	mp1->b_rptr += sizeof (void *);  /* pointer worth of padding */
	mp1->b_wptr = mp1->b_rptr + hdrlen + optlen;
	DB_TYPE(mp1) = M_PROTO;
	tudi = (struct T_unitdata_ind *)mp1->b_rptr;
	tudi->PRIM_type = T_UNITDATA_IND;
	tudi->SRC_length = sin4 ? sizeof (*sin4) : sizeof (*sin6);
	tudi->SRC_offset = sizeof (*tudi);
	tudi->OPT_offset = sizeof (*tudi) + tudi->SRC_length;
	tudi->OPT_length = optlen;
	if (sin4) {
		bcopy(sin4, tudi + 1, sizeof (*sin4));
	} else {
		bcopy(sin6, tudi + 1, sizeof (*sin6));
	}
	optptr = (uchar_t *)tudi + tudi->OPT_offset;

	if (sctp->sctp_recvsndrcvinfo) {
		/* XXX need backout method if memory allocation fails. */
		struct sctp_sndrcvinfo *sri;

		cmsg = (struct cmsghdr *)optptr;
		cmsg->cmsg_level = IPPROTO_SCTP;
		cmsg->cmsg_type = SCTP_SNDRCV;
		cmsg->cmsg_len = sizeof (*cmsg) + sizeof (*sri);
		optptr += sizeof (*cmsg);

		sri = (struct sctp_sndrcvinfo *)(cmsg + 1);
		ASSERT(OK_32PTR(sri));
		sri->sinfo_stream = ntohs(dcp->sdh_sid);
		sri->sinfo_ssn = ntohs(dcp->sdh_ssn);
		if (SCTP_DATA_GET_UBIT(dcp)) {
			sri->sinfo_flags = MSG_UNORDERED;
		} else {
			sri->sinfo_flags = 0;
		}
		sri->sinfo_ppid = dcp->sdh_payload_id;
		sri->sinfo_context = 0;
		sri->sinfo_timetolive = 0;
		sri->sinfo_tsn = ntohl(dcp->sdh_tsn);
		sri->sinfo_cumtsn = sctp->sctp_ftsn;
		sri->sinfo_assoc_id = 0;

		optptr += sizeof (*sri);
	}

	/*
	 * If app asked for pktinfo and the index has changed ...
	 * Note that the local address never changes for the connection.
	 */
	if (addflag.crb_ip_recvpktinfo) {
		struct in6_pktinfo *pkti;
		uint_t ifindex;

		ifindex = ira->ira_ruifindex;
		cmsg = (struct cmsghdr *)optptr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = sizeof (*cmsg) + sizeof (*pkti);
		optptr += sizeof (*cmsg);

		pkti = (struct in6_pktinfo *)optptr;
		if (connp->conn_family == AF_INET6)
			pkti->ipi6_addr = sctp->sctp_ip6h->ip6_src;
		else
			IN6_IPADDR_TO_V4MAPPED(sctp->sctp_ipha->ipha_src,
			    &pkti->ipi6_addr);

		pkti->ipi6_ifindex = ifindex;
		optptr += sizeof (*pkti);
		ASSERT(OK_32PTR(optptr));
		/* Save as "last" value */
		sctp->sctp_recvifindex = ifindex;
	}
	/* If app asked for hoplimit and it has changed ... */
	if (addflag.crb_ipv6_recvhoplimit) {
		cmsg = (struct cmsghdr *)optptr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_HOPLIMIT;
		cmsg->cmsg_len = sizeof (*cmsg) + sizeof (uint_t);
		optptr += sizeof (*cmsg);

		*(uint_t *)optptr = ipp->ipp_hoplimit;
		optptr += sizeof (uint_t);
		ASSERT(OK_32PTR(optptr));
		/* Save as "last" value */
		sctp->sctp_recvhops = ipp->ipp_hoplimit;
	}
	/* If app asked for tclass and it has changed ... */
	if (addflag.crb_ipv6_recvtclass) {
		cmsg = (struct cmsghdr *)optptr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_TCLASS;
		cmsg->cmsg_len = sizeof (*cmsg) + sizeof (uint_t);
		optptr += sizeof (*cmsg);

		*(uint_t *)optptr = ipp->ipp_tclass;
		optptr += sizeof (uint_t);
		ASSERT(OK_32PTR(optptr));
		/* Save as "last" value */
		sctp->sctp_recvtclass = ipp->ipp_tclass;
	}
	if (addflag.crb_ipv6_recvhopopts) {
		cmsg = (struct cmsghdr *)optptr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_HOPOPTS;
		cmsg->cmsg_len = sizeof (*cmsg) + ipp->ipp_hopoptslen;
		optptr += sizeof (*cmsg);

		bcopy(ipp->ipp_hopopts, optptr, ipp->ipp_hopoptslen);
		optptr += ipp->ipp_hopoptslen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&sctp->sctp_hopopts,
		    &sctp->sctp_hopoptslen,
		    (ipp->ipp_fields & IPPF_HOPOPTS),
		    ipp->ipp_hopopts, ipp->ipp_hopoptslen);
	}
	if (addflag.crb_ipv6_recvrthdrdstopts) {
		cmsg = (struct cmsghdr *)optptr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_RTHDRDSTOPTS;
		cmsg->cmsg_len = sizeof (*cmsg) + ipp->ipp_rthdrdstoptslen;
		optptr += sizeof (*cmsg);

		bcopy(ipp->ipp_rthdrdstopts, optptr, ipp->ipp_rthdrdstoptslen);
		optptr += ipp->ipp_rthdrdstoptslen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&sctp->sctp_rthdrdstopts,
		    &sctp->sctp_rthdrdstoptslen,
		    (ipp->ipp_fields & IPPF_RTHDRDSTOPTS),
		    ipp->ipp_rthdrdstopts, ipp->ipp_rthdrdstoptslen);
	}
	if (addflag.crb_ipv6_recvrthdr) {
		cmsg = (struct cmsghdr *)optptr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_RTHDR;
		cmsg->cmsg_len = sizeof (*cmsg) + ipp->ipp_rthdrlen;
		optptr += sizeof (*cmsg);

		bcopy(ipp->ipp_rthdr, optptr, ipp->ipp_rthdrlen);
		optptr += ipp->ipp_rthdrlen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&sctp->sctp_rthdr,
		    &sctp->sctp_rthdrlen,
		    (ipp->ipp_fields & IPPF_RTHDR),
		    ipp->ipp_rthdr, ipp->ipp_rthdrlen);
	}
	if (addflag.crb_ipv6_recvdstopts) {
		cmsg = (struct cmsghdr *)optptr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_DSTOPTS;
		cmsg->cmsg_len = sizeof (*cmsg) + ipp->ipp_dstoptslen;
		optptr += sizeof (*cmsg);

		bcopy(ipp->ipp_dstopts, optptr, ipp->ipp_dstoptslen);
		optptr += ipp->ipp_dstoptslen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&sctp->sctp_dstopts,
		    &sctp->sctp_dstoptslen,
		    (ipp->ipp_fields & IPPF_DSTOPTS),
		    ipp->ipp_dstopts, ipp->ipp_dstoptslen);
	}

	ASSERT(optptr == mp1->b_wptr);

	return (0);
}

void
sctp_free_reass(sctp_instr_t *sip)
{
	mblk_t *mp, *mpnext, *mctl;
#ifdef	DEBUG
	sctp_reass_t	*srp;
#endif

	for (mp = sip->istr_reass; mp != NULL; mp = mpnext) {
		mpnext = mp->b_next;
		mp->b_next = NULL;
		mp->b_prev = NULL;
		if (DB_TYPE(mp) == M_CTL) {
			mctl = mp;
#ifdef	DEBUG
			srp = (sctp_reass_t *)DB_BASE(mctl);
			/* Partial delivery can leave empty srp */
			ASSERT(mp->b_cont != NULL || srp->sr_got == 0);
#endif
			mp = mp->b_cont;
			mctl->b_cont = NULL;
			freeb(mctl);
		}
		freemsg(mp);
	}
	sip->istr_reass = NULL;
}

/*
 * If the series of data fragments of which dmp is a part is successfully
 * reassembled, the first mblk in the series is returned. dc is adjusted
 * to point at the data chunk in the lead mblk, and b_rptr also points to
 * the data chunk; the following mblk's b_rptr's point at the actual payload.
 *
 * If the series is not yet reassembled, NULL is returned. dc is not changed.
 * XXX should probably move this up into the state machine.
 */

/* Fragment list for un-ordered messages. Partial delivery is not supported */
static mblk_t *
sctp_uodata_frag(sctp_t *sctp, mblk_t *dmp, sctp_data_hdr_t **dc)
{
	mblk_t		*hmp;
	mblk_t		*begin = NULL;
	mblk_t		*end = NULL;
	sctp_data_hdr_t	*qdc;
	uint32_t	ntsn;
	uint32_t	tsn = ntohl((*dc)->sdh_tsn);
#ifdef	DEBUG
	mblk_t		*mp1;
#endif

	/* First frag. */
	if (sctp->sctp_uo_frags == NULL) {
		sctp->sctp_uo_frags = dmp;
		return (NULL);
	}
	hmp = sctp->sctp_uo_frags;
	/*
	 * Insert the segment according to the TSN, fragmented unordered
	 * chunks are sequenced by TSN.
	 */
	while (hmp != NULL) {
		qdc = (sctp_data_hdr_t *)hmp->b_rptr;
		ntsn = ntohl(qdc->sdh_tsn);
		if (SEQ_GT(ntsn, tsn)) {
			if (hmp->b_prev == NULL) {
				dmp->b_next = hmp;
				hmp->b_prev = dmp;
				sctp->sctp_uo_frags = dmp;
			} else {
				dmp->b_next = hmp;
				dmp->b_prev = hmp->b_prev;
				hmp->b_prev->b_next = dmp;
				hmp->b_prev = dmp;
			}
			break;
		}
		if (hmp->b_next == NULL) {
			hmp->b_next = dmp;
			dmp->b_prev = hmp;
			break;
		}
		hmp = hmp->b_next;
	}
	/* check if we completed a msg */
	if (SCTP_DATA_GET_BBIT(*dc)) {
		begin = dmp;
	} else if (SCTP_DATA_GET_EBIT(*dc)) {
		end = dmp;
	}
	/*
	 * We walk consecutive TSNs backwards till we get a seg. with
	 * the B bit
	 */
	if (begin == NULL) {
		for (hmp = dmp->b_prev; hmp != NULL; hmp = hmp->b_prev) {
			qdc = (sctp_data_hdr_t *)hmp->b_rptr;
			ntsn = ntohl(qdc->sdh_tsn);
			if ((int32_t)(tsn - ntsn) > 1) {
				return (NULL);
			}
			if (SCTP_DATA_GET_BBIT(qdc)) {
				begin = hmp;
				break;
			}
			tsn = ntsn;
		}
	}
	tsn = ntohl((*dc)->sdh_tsn);
	/*
	 * We walk consecutive TSNs till we get a seg. with the E bit
	 */
	if (end == NULL) {
		for (hmp = dmp->b_next; hmp != NULL; hmp = hmp->b_next) {
			qdc = (sctp_data_hdr_t *)hmp->b_rptr;
			ntsn = ntohl(qdc->sdh_tsn);
			if ((int32_t)(ntsn - tsn) > 1) {
				return (NULL);
			}
			if (SCTP_DATA_GET_EBIT(qdc)) {
				end = hmp;
				break;
			}
			tsn = ntsn;
		}
	}
	if (begin == NULL || end == NULL) {
		return (NULL);
	}
	/* Got one!, Remove the msg from the list */
	if (sctp->sctp_uo_frags == begin) {
		ASSERT(begin->b_prev == NULL);
		sctp->sctp_uo_frags = end->b_next;
		if (end->b_next != NULL)
			end->b_next->b_prev = NULL;
	} else {
		begin->b_prev->b_next = end->b_next;
		if (end->b_next != NULL)
			end->b_next->b_prev = begin->b_prev;
	}
	begin->b_prev = NULL;
	end->b_next = NULL;

	/*
	 * Null out b_next and b_prev and chain using b_cont.
	 */
	dmp = end = begin;
	hmp = begin->b_next;
	*dc = (sctp_data_hdr_t *)begin->b_rptr;
	begin->b_next = NULL;
	while (hmp != NULL) {
		qdc = (sctp_data_hdr_t *)hmp->b_rptr;
		hmp->b_rptr = (uchar_t *)(qdc + 1);
		end = hmp->b_next;
		dmp->b_cont = hmp;
		dmp = hmp;

		if (end != NULL)
			hmp->b_next = NULL;
		hmp->b_prev = NULL;
		hmp = end;
	}
	BUMP_LOCAL(sctp->sctp_reassmsgs);
#ifdef	DEBUG
	mp1 = begin;
	while (mp1 != NULL) {
		ASSERT(mp1->b_next == NULL);
		ASSERT(mp1->b_prev == NULL);
		mp1 = mp1->b_cont;
	}
#endif
	return (begin);
}

/*
 * Try partial delivery.
 */
static mblk_t *
sctp_try_partial_delivery(sctp_t *sctp, mblk_t *hmp, sctp_reass_t *srp,
    sctp_data_hdr_t **dc)
{
	mblk_t		*mp;
	mblk_t		*dmp;
	mblk_t		*qmp;
	mblk_t		*prev;
	sctp_data_hdr_t	*qdc;
	uint32_t	tsn;

	ASSERT(DB_TYPE(hmp) == M_CTL);

	dprint(4, ("trypartial: got=%d, needed=%d\n",
	    (int)(srp->sr_got), (int)(srp->sr_needed)));

	mp = hmp->b_cont;
	qdc = (sctp_data_hdr_t *)mp->b_rptr;

	ASSERT(SCTP_DATA_GET_BBIT(qdc) && srp->sr_hasBchunk);

	tsn = ntohl(qdc->sdh_tsn) + 1;

	/*
	 * This loop has two exit conditions: the
	 * end of received chunks has been reached, or
	 * there is a break in the sequence. We want
	 * to chop the reassembly list as follows (the
	 * numbers are TSNs):
	 *   10 -> 11 ->	(end of chunks)
	 *   10 -> 11 -> | 13   (break in sequence)
	 */
	prev = mp;
	mp = mp->b_cont;
	while (mp != NULL) {
		qdc = (sctp_data_hdr_t *)mp->b_rptr;
		if (ntohl(qdc->sdh_tsn) != tsn)
			break;
		prev = mp;
		mp = mp->b_cont;
		tsn++;
	}
	/*
	 * We are sending all the fragments upstream, we have to retain
	 * the srp info for further fragments.
	 */
	if (mp == NULL) {
		dmp = hmp->b_cont;
		hmp->b_cont = NULL;
		srp->sr_nexttsn = tsn;
		srp->sr_msglen = 0;
		srp->sr_needed = 0;
		srp->sr_got = 0;
		srp->sr_tail = NULL;
	} else {
		/*
		 * There is a gap then some ordered frags which are not
		 * the next deliverable tsn. When the next deliverable
		 * frag arrives it will be set as the new list head in
		 * sctp_data_frag() by setting the B bit.
		 */
		dmp = hmp->b_cont;
		hmp->b_cont = mp;
	}
	srp->sr_hasBchunk = B_FALSE;
	/*
	 * mp now points at the last chunk in the sequence,
	 * and prev points to mp's previous in the list.
	 * We chop the list at prev. Subsequent fragment
	 * deliveries will follow the normal reassembly
	 * path unless they too exceed the sctp_pd_point.
	 */
	prev->b_cont = NULL;
	srp->sr_partial_delivered = B_TRUE;

	dprint(4, ("trypartial: got some, got=%d, needed=%d\n",
	    (int)(srp->sr_got), (int)(srp->sr_needed)));

	/*
	 * Adjust all mblk's except the lead so their rptr's point to the
	 * payload. sctp_data_chunk() will need to process the lead's
	 * data chunk section, so leave it's rptr pointing at the data chunk.
	 */
	*dc = (sctp_data_hdr_t *)dmp->b_rptr;
	if (srp->sr_tail != NULL) {
		srp->sr_got--;
		ASSERT(srp->sr_got != 0);
		if (srp->sr_needed != 0) {
			srp->sr_needed--;
			ASSERT(srp->sr_needed != 0);
		}
		srp->sr_msglen -= ntohs((*dc)->sdh_len);
	}
	for (qmp = dmp->b_cont; qmp != NULL; qmp = qmp->b_cont) {
		qdc = (sctp_data_hdr_t *)qmp->b_rptr;
		qmp->b_rptr = (uchar_t *)(qdc + 1);

		/*
		 * Deduct the balance from got and needed here, now that
		 * we know we are actually delivering these data.
		 */
		if (srp->sr_tail != NULL) {
			srp->sr_got--;
			ASSERT(srp->sr_got != 0);
			if (srp->sr_needed != 0) {
				srp->sr_needed--;
				ASSERT(srp->sr_needed != 0);
			}
			srp->sr_msglen -= ntohs(qdc->sdh_len);
		}
	}
	ASSERT(srp->sr_msglen == 0);
	BUMP_LOCAL(sctp->sctp_reassmsgs);

	return (dmp);
}

/*
 * Handle received fragments for ordered delivery to upper layer protocol.
 * Manage the per message reassembly queue and if this fragment completes
 * reassembly of the message, or qualifies the already reassembled data
 * for partial delivery, prepare the message for delivery upstream.
 *
 * tpfinished in the caller remains set only when the incoming fragment
 * has completed the reassembly of the message associated with its ssn.
 */
static mblk_t *
sctp_data_frag(sctp_t *sctp, mblk_t *dmp, sctp_data_hdr_t **dc, int *error,
    sctp_instr_t *sip, boolean_t *tpfinished)
{
	mblk_t		*reassq_curr, *reassq_next, *reassq_prev;
	mblk_t		*new_reassq;
	mblk_t		*qmp;
	mblk_t		*first_mp;
	sctp_reass_t	*srp;
	sctp_data_hdr_t	*qdc;
	sctp_data_hdr_t	*bdc;
	sctp_data_hdr_t	*edc;
	uint32_t	tsn;
	uint16_t	fraglen = 0;

	reassq_curr = NULL;
	*error = 0;

	/*
	 * Find the reassembly queue for this data chunk, if none
	 * yet exists, a new per message queue will be created and
	 * appended to the end of the list of per message queues.
	 *
	 * sip points on sctp_instr_t representing instream messages
	 * as yet undelivered for this stream (sid) of the association.
	 */
	reassq_next = reassq_prev = sip->istr_reass;
	for (; reassq_next != NULL; reassq_next = reassq_next->b_next) {
		srp = (sctp_reass_t *)DB_BASE(reassq_next);
		if (ntohs((*dc)->sdh_ssn) == srp->sr_ssn) {
			reassq_curr = reassq_next;
			goto foundit;
		} else if (SSN_GT(srp->sr_ssn, ntohs((*dc)->sdh_ssn)))
			break;
		reassq_prev = reassq_next;
	}

	/*
	 * First fragment of this message received, allocate a M_CTL that
	 * will head the reassembly queue for this message. The message
	 * and all its fragments are identified by having the same ssn.
	 *
	 * Arriving fragments will be inserted in tsn order on the
	 * reassembly queue for this message (ssn), linked by b_cont.
	 */
	if ((new_reassq = allocb(sizeof (*srp), BPRI_MED)) == NULL) {
		*error = ENOMEM;
		return (NULL);
	}
	DB_TYPE(new_reassq) = M_CTL;
	srp = (sctp_reass_t *)DB_BASE(new_reassq);
	new_reassq->b_cont = dmp;

	/*
	 * All per ssn reassembly queues, (one for each message) on
	 * this stream are doubly linked by b_next/b_prev back to the
	 * instr_reass of the instream structure associated with this
	 * stream id, (sip is initialized as sctp->sctp_instr[sid]).
	 * Insert the new reassembly queue in the correct (ssn) order.
	 */
	if (reassq_next != NULL) {
		if (sip->istr_reass == reassq_next) {
			/* head insertion */
			sip->istr_reass = new_reassq;
			new_reassq->b_next = reassq_next;
			new_reassq->b_prev = NULL;
			reassq_next->b_prev = new_reassq;
		} else {
			/* mid queue insertion */
			reassq_prev->b_next = new_reassq;
			new_reassq->b_prev = reassq_prev;
			new_reassq->b_next = reassq_next;
			reassq_next->b_prev = new_reassq;
		}
	} else {
		/* place new reassembly queue at the end */
		if (sip->istr_reass == NULL) {
			sip->istr_reass = new_reassq;
			new_reassq->b_prev = NULL;
		} else {
			reassq_prev->b_next = new_reassq;
			new_reassq->b_prev = reassq_prev;
		}
		new_reassq->b_next = NULL;
	}
	srp->sr_partial_delivered = B_FALSE;
	srp->sr_ssn = ntohs((*dc)->sdh_ssn);
	srp->sr_hasBchunk = B_FALSE;
empty_srp:
	srp->sr_needed = 0;
	srp->sr_got = 1;
	/* tail always the highest tsn on the reassembly queue for this ssn */
	srp->sr_tail = dmp;
	if (SCTP_DATA_GET_BBIT(*dc)) {
		/* Incoming frag is flagged as the beginning of message */
		srp->sr_msglen = ntohs((*dc)->sdh_len);
		srp->sr_nexttsn = ntohl((*dc)->sdh_tsn) + 1;
		srp->sr_hasBchunk = B_TRUE;
	} else if (srp->sr_partial_delivered &&
	    srp->sr_nexttsn == ntohl((*dc)->sdh_tsn)) {
		/*
		 * The real beginning fragment of the message was already
		 * delivered upward, so this is the earliest frag expected.
		 * Fake the B-bit then see if this frag also completes the
		 * message.
		 */
		SCTP_DATA_SET_BBIT(*dc);
		srp->sr_hasBchunk = B_TRUE;
		srp->sr_msglen = ntohs((*dc)->sdh_len);
		if (SCTP_DATA_GET_EBIT(*dc)) {
			/* This frag is marked as the end of message */
			srp->sr_needed = 1;
			/* Got all fragments of this message now */
			goto frag_done;
		}
		srp->sr_nexttsn++;
	}

	/* The only fragment of this message currently queued */
	*tpfinished = B_FALSE;
	return (NULL);
foundit:
	/*
	 * This message already has a reassembly queue. Insert the new frag
	 * in the reassembly queue. Try the tail first, on the assumption
	 * that the fragments are arriving in order.
	 */
	qmp = srp->sr_tail;

	/*
	 * A NULL tail means all existing fragments of the message have
	 * been entirely consumed during a partially delivery.
	 */
	if (qmp == NULL) {
		ASSERT(srp->sr_got == 0 && srp->sr_needed == 0 &&
		    srp->sr_partial_delivered);
		ASSERT(reassq_curr->b_cont == NULL);
		reassq_curr->b_cont = dmp;
		goto empty_srp;
	} else {
		/*
		 * If partial delivery did take place but the next arriving
		 * fragment was not the next to be delivered, or partial
		 * delivery broke off due to a gap, fragments remain on the
		 * tail. The next fragment due to be delivered still has to
		 * be set as the new head of list upon arrival. Fake B-bit
		 * on that frag then see if it also completes the message.
		 */
		if (srp->sr_partial_delivered &&
		    srp->sr_nexttsn == ntohl((*dc)->sdh_tsn)) {
			SCTP_DATA_SET_BBIT(*dc);
			srp->sr_hasBchunk = B_TRUE;
			if (SCTP_DATA_GET_EBIT(*dc)) {
				/* Got all fragments of this message now */
				goto frag_done;
			}
		}
	}

	/* grab the frag header of already queued tail frag for comparison */
	qdc = (sctp_data_hdr_t *)qmp->b_rptr;
	ASSERT(qmp->b_cont == NULL);

	/* check if the frag goes on the tail in order */
	if (SEQ_GT(ntohl((*dc)->sdh_tsn), ntohl(qdc->sdh_tsn))) {
		qmp->b_cont = dmp;
		srp->sr_tail = dmp;
		dmp->b_cont = NULL;
		if (srp->sr_hasBchunk && srp->sr_nexttsn ==
		    ntohl((*dc)->sdh_tsn)) {
			srp->sr_msglen += ntohs((*dc)->sdh_len);
			srp->sr_nexttsn++;
		}
		goto inserted;
	}

	/* Next check if we should insert this frag at the beginning */
	qmp = reassq_curr->b_cont;
	qdc = (sctp_data_hdr_t *)qmp->b_rptr;
	if (SEQ_LT(ntohl((*dc)->sdh_tsn), ntohl(qdc->sdh_tsn))) {
		dmp->b_cont = qmp;
		reassq_curr->b_cont = dmp;
		if (SCTP_DATA_GET_BBIT(*dc)) {
			srp->sr_hasBchunk = B_TRUE;
			srp->sr_nexttsn = ntohl((*dc)->sdh_tsn);
		}
		goto preinserted;
	}

	/* Insert this frag in it's correct order in the middle */
	for (;;) {
		/* Tail check above should have caught this */
		ASSERT(qmp->b_cont != NULL);

		qdc = (sctp_data_hdr_t *)qmp->b_cont->b_rptr;
		if (SEQ_LT(ntohl((*dc)->sdh_tsn), ntohl(qdc->sdh_tsn))) {
			/* insert here */
			dmp->b_cont = qmp->b_cont;
			qmp->b_cont = dmp;
			break;
		}
		qmp = qmp->b_cont;
	}
preinserted:
	/*
	 * Need head of message and to be due to deliver, otherwise skip
	 * the recalculation of the message length below.
	 */
	if (!srp->sr_hasBchunk || ntohl((*dc)->sdh_tsn) != srp->sr_nexttsn)
		goto inserted;
	/*
	 * fraglen contains the length of consecutive chunks of fragments.
	 * starting from the chunk we just inserted.
	 */
	tsn = srp->sr_nexttsn;
	for (qmp = dmp; qmp != NULL; qmp = qmp->b_cont) {
		qdc = (sctp_data_hdr_t *)qmp->b_rptr;
		if (tsn != ntohl(qdc->sdh_tsn))
			break;
		fraglen += ntohs(qdc->sdh_len);
		tsn++;
	}
	srp->sr_nexttsn = tsn;
	srp->sr_msglen += fraglen;
inserted:
	srp->sr_got++;
	first_mp = reassq_curr->b_cont;
	/* Prior to this frag either the beginning or end frag was missing */
	if (srp->sr_needed == 0) {
		/* used to check if we have the first and last fragments */
		bdc = (sctp_data_hdr_t *)first_mp->b_rptr;
		edc = (sctp_data_hdr_t *)srp->sr_tail->b_rptr;

		/*
		 * If we now have both the beginning and the end of the message,
		 * calculate how many fragments in the complete message.
		 */
		if (SCTP_DATA_GET_BBIT(bdc) && SCTP_DATA_GET_EBIT(edc)) {
			srp->sr_needed = ntohl(edc->sdh_tsn) -
			    ntohl(bdc->sdh_tsn) + 1;
		}
	}

	/*
	 * Try partial delivery if the message length has exceeded the
	 * partial delivery point. Only do this if we can immediately
	 * deliver the partially assembled message, and only partially
	 * deliver one message at a time (i.e. messages cannot be
	 * intermixed arriving at the upper layer).
	 * sctp_try_partial_delivery() will return a message consisting
	 * of only consecutive fragments.
	 */
	if (srp->sr_needed != srp->sr_got) {
		/* we don't have the full message yet */
		dmp = NULL;
		if (ntohl((*dc)->sdh_tsn) <= sctp->sctp_ftsn &&
		    srp->sr_msglen >= sctp->sctp_pd_point &&
		    srp->sr_ssn == sip->nextseq) {
			dmp = sctp_try_partial_delivery(sctp, reassq_curr,
			    srp, dc);
		}
		*tpfinished = B_FALSE;
		/*
		 * NULL unless a segment of the message now qualified for
		 * partial_delivery and has been prepared for delivery by
		 * sctp_try_partial_delivery().
		 */
		return (dmp);
	}
frag_done:
	/*
	 * Reassembly complete for this message, prepare the data for delivery.
	 * First unlink the reassembly queue for this ssn from the list of
	 * messages in reassembly.
	 */
	if (sip->istr_reass == reassq_curr) {
		sip->istr_reass = reassq_curr->b_next;
		if (reassq_curr->b_next)
			reassq_curr->b_next->b_prev = NULL;
	} else {
		ASSERT(reassq_curr->b_prev != NULL);
		reassq_curr->b_prev->b_next = reassq_curr->b_next;
		if (reassq_curr->b_next)
			reassq_curr->b_next->b_prev = reassq_curr->b_prev;
	}

	/*
	 * Need to clean up b_prev and b_next as freeb() will
	 * ASSERT that they are unused.
	 */
	reassq_curr->b_next = NULL;
	reassq_curr->b_prev = NULL;

	dmp = reassq_curr;
	/* point to the head of the reassembled data message */
	dmp = dmp->b_cont;
	reassq_curr->b_cont = NULL;
	freeb(reassq_curr);
	/* Tell our caller that we are returning a complete message. */
	*tpfinished = B_TRUE;

	/*
	 * Adjust all mblk's except the lead so their rptr's point to the
	 * payload. sctp_data_chunk() will need to process the lead's data
	 * data chunk section, so leave its rptr pointing at the data chunk
	 * header.
	 */
	*dc = (sctp_data_hdr_t *)dmp->b_rptr;
	for (qmp = dmp->b_cont; qmp != NULL; qmp = qmp->b_cont) {
		qdc = (sctp_data_hdr_t *)qmp->b_rptr;
		qmp->b_rptr = (uchar_t *)(qdc + 1);
	}
	BUMP_LOCAL(sctp->sctp_reassmsgs);

	return (dmp);
}

static void
sctp_add_dup(uint32_t tsn, mblk_t **dups)
{
	mblk_t *mp;
	size_t bsize = SCTP_DUP_MBLK_SZ * sizeof (tsn);

	if (dups == NULL) {
		return;
	}

	/* first time? */
	if (*dups == NULL) {
		*dups = allocb(bsize, BPRI_MED);
		if (*dups == NULL) {
			return;
		}
	}

	mp = *dups;
	if ((mp->b_wptr - mp->b_rptr) >= bsize) {
		/* maximum reached */
		return;
	}

	/* add the duplicate tsn */
	bcopy(&tsn, mp->b_wptr, sizeof (tsn));
	mp->b_wptr += sizeof (tsn);
	ASSERT((mp->b_wptr - mp->b_rptr) <= bsize);
}

/*
 * All incoming sctp data, complete messages and fragments are handled by
 * this function. Unless the U-bit is set in the data chunk it will be
 * delivered in order or queued until an in-order delivery can be made.
 */
static void
sctp_data_chunk(sctp_t *sctp, sctp_chunk_hdr_t *ch, mblk_t *mp, mblk_t **dups,
    sctp_faddr_t *fp, ip_pkt_t *ipp, ip_recv_attr_t *ira)
{
	sctp_data_hdr_t *dc;
	mblk_t *dmp, *pmp;
	sctp_instr_t *instr;
	int ubit;
	int sid;
	int isfrag;
	uint16_t ssn;
	uint32_t oftsn;
	boolean_t can_deliver = B_TRUE;
	uint32_t tsn;
	int dlen;
	boolean_t tpfinished = B_TRUE;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	int	error;

	/* The following are used multiple times, so we inline them */
#define	SCTP_ACK_IT(sctp, tsn)						\
	if (tsn == sctp->sctp_ftsn) {					\
		dprint(2, ("data_chunk: acking next %x\n", tsn));	\
		(sctp)->sctp_ftsn++;					\
		if ((sctp)->sctp_sack_gaps > 0)				\
			(sctp)->sctp_force_sack = 1;			\
	} else if (SEQ_GT(tsn, sctp->sctp_ftsn)) {			\
		/* Got a gap; record it */				\
		BUMP_LOCAL(sctp->sctp_outseqtsns);			\
		dprint(2, ("data_chunk: acking gap %x\n", tsn));	\
		sctp_ack_add(&sctp->sctp_sack_info, tsn,		\
		    &sctp->sctp_sack_gaps);				\
		sctp->sctp_force_sack = 1;				\
	}

	dmp = NULL;

	dc = (sctp_data_hdr_t *)ch;
	tsn = ntohl(dc->sdh_tsn);

	dprint(3, ("sctp_data_chunk: mp=%p tsn=%x\n", (void *)mp, tsn));

	/* Check for duplicates */
	if (SEQ_LT(tsn, sctp->sctp_ftsn)) {
		dprint(4, ("sctp_data_chunk: dropping duplicate\n"));
		BUMP_LOCAL(sctp->sctp_idupchunks);
		sctp->sctp_force_sack = 1;
		sctp_add_dup(dc->sdh_tsn, dups);
		return;
	}

	/* Check for dups of sack'ed data */
	if (sctp->sctp_sack_info != NULL) {
		sctp_set_t *sp;

		for (sp = sctp->sctp_sack_info; sp; sp = sp->next) {
			if (SEQ_GEQ(tsn, sp->begin) && SEQ_LEQ(tsn, sp->end)) {
				dprint(4,
				    ("sctp_data_chunk: dropping dup > "
				    "cumtsn\n"));
				BUMP_LOCAL(sctp->sctp_idupchunks);
				sctp->sctp_force_sack = 1;
				sctp_add_dup(dc->sdh_tsn, dups);
				return;
			}
		}
	}

	/* We can no longer deliver anything up, but still need to handle it. */
	if (SCTP_IS_DETACHED(sctp)) {
		SCTPS_BUMP_MIB(sctps, sctpInClosed);
		can_deliver = B_FALSE;
	}

	dlen = ntohs(dc->sdh_len) - sizeof (*dc);

	/*
	 * Check for buffer space. Note if this is the next expected TSN
	 * we have to take it to avoid deadlock because we cannot deliver
	 * later queued TSNs and thus clear buffer space without it.
	 * We drop anything that is purely zero window probe data here.
	 */
	if ((sctp->sctp_rwnd - sctp->sctp_rxqueued < dlen) &&
	    (tsn != sctp->sctp_ftsn || sctp->sctp_rwnd == 0)) {
		/* Drop and SACK, but don't advance the cumulative TSN. */
		sctp->sctp_force_sack = 1;
		dprint(0, ("sctp_data_chunk: exceed rwnd %d rxqueued %d "
		    "dlen %d ssn %d tsn %x\n", sctp->sctp_rwnd,
		    sctp->sctp_rxqueued, dlen, ntohs(dc->sdh_ssn),
		    ntohl(dc->sdh_tsn)));
		return;
	}

	sid = ntohs(dc->sdh_sid);

	/* Data received for a stream not negotiated for this association */
	if (sid >= sctp->sctp_num_istr) {
		sctp_bsc_t	inval_parm;

		/* Will populate the CAUSE block in the ERROR chunk. */
		inval_parm.bsc_sid = dc->sdh_sid;
		/* RESERVED, ignored at the receiving end */
		inval_parm.bsc_pad = 0;

		/* ack and drop it */
		sctp_add_err(sctp, SCTP_ERR_BAD_SID, (void *)&inval_parm,
		    sizeof (sctp_bsc_t), fp);
		SCTP_ACK_IT(sctp, tsn);
		return;
	}

	/* unordered delivery OK for this data if ubit set */
	ubit = SCTP_DATA_GET_UBIT(dc);
	ASSERT(sctp->sctp_instr != NULL);

	/* select per stream structure for this stream from the array */
	instr = &sctp->sctp_instr[sid];
	/* Initialize the stream, if not yet used */
	if (instr->sctp == NULL)
		instr->sctp = sctp;

	/* Begin and End bit set would mean a complete message */
	isfrag = !(SCTP_DATA_GET_BBIT(dc) && SCTP_DATA_GET_EBIT(dc));

	/* The ssn of this sctp message and of any fragments in it */
	ssn = ntohs(dc->sdh_ssn);

	dmp = dupb(mp);
	if (dmp == NULL) {
		/* drop it and don't ack, let the peer retransmit */
		return;
	}
	/*
	 * Past header and payload, note: the underlying buffer may
	 * contain further chunks from the same incoming IP packet,
	 * if so db_ref will be greater than one.
	 */
	dmp->b_wptr = (uchar_t *)ch + ntohs(ch->sch_len);

	sctp->sctp_rxqueued += dlen;

	oftsn = sctp->sctp_ftsn;

	if (isfrag) {

		error = 0;
		/* fragmented data chunk */
		dmp->b_rptr = (uchar_t *)dc;
		if (ubit) {
			/* prepare data for unordered delivery */
			dmp = sctp_uodata_frag(sctp, dmp, &dc);
#if	DEBUG
			if (dmp != NULL) {
				ASSERT(instr ==
				    &sctp->sctp_instr[sid]);
			}
#endif
		} else {
			/*
			 * Assemble fragments and queue for ordered delivery,
			 * dmp returned is NULL or the head of a complete or
			 * "partial delivery" message. Any returned message
			 * and all its fragments will have the same ssn as the
			 * input fragment currently being handled.
			 */
			dmp = sctp_data_frag(sctp, dmp, &dc, &error, instr,
			    &tpfinished);
		}
		if (error == ENOMEM) {
			/* back out the adjustment made earlier */
			sctp->sctp_rxqueued -= dlen;
			/*
			 * Don't ack the segment,
			 * the peer will retransmit.
			 */
			return;
		}

		if (dmp == NULL) {
			/*
			 * The frag has been queued for later in-order delivery,
			 * but the cumulative TSN may need to advance, so also
			 * need to perform the gap ack checks at the done label.
			 */
			SCTP_ACK_IT(sctp, tsn);
			DTRACE_PROBE4(sctp_data_frag_queued, sctp_t *, sctp,
			    int, sid, int, tsn, uint16_t, ssn);
			goto done;
		}
	}

	/*
	 * Unless message is the next for delivery to the ulp, queue complete
	 * message in the correct order for ordered delivery.
	 * Note: tpfinished is true when the incoming chunk contains a complete
	 * message or is the final missing fragment which completed a message.
	 */
	if (!ubit && tpfinished && ssn != instr->nextseq) {
		/* Adjust rptr to point at the data chunk for compares */
		dmp->b_rptr = (uchar_t *)dc;

		dprint(2,
		    ("data_chunk: inserted %x in pq (ssn %d expected %d)\n",
		    ntohl(dc->sdh_tsn), (int)(ssn), (int)(instr->nextseq)));

		if (instr->istr_msgs == NULL) {
			instr->istr_msgs = dmp;
			ASSERT(dmp->b_prev == NULL && dmp->b_next == NULL);
		} else {
			mblk_t			*imblk = instr->istr_msgs;
			sctp_data_hdr_t		*idc;

			/*
			 * XXXNeed to take sequence wraps into account,
			 * ... and a more efficient insertion algo.
			 */
			for (;;) {
				idc = (sctp_data_hdr_t *)imblk->b_rptr;
				if (SSN_GT(ntohs(idc->sdh_ssn),
				    ntohs(dc->sdh_ssn))) {
					if (instr->istr_msgs == imblk) {
						instr->istr_msgs = dmp;
						dmp->b_next = imblk;
						imblk->b_prev = dmp;
					} else {
						ASSERT(imblk->b_prev != NULL);
						imblk->b_prev->b_next = dmp;
						dmp->b_prev = imblk->b_prev;
						imblk->b_prev = dmp;
						dmp->b_next = imblk;
					}
					break;
				}
				if (imblk->b_next == NULL) {
					imblk->b_next = dmp;
					dmp->b_prev = imblk;
					break;
				}
				imblk = imblk->b_next;
			}
		}
		(instr->istr_nmsgs)++;
		(sctp->sctp_istr_nmsgs)++;
		SCTP_ACK_IT(sctp, tsn);
		DTRACE_PROBE4(sctp_pqueue_completemsg, sctp_t *, sctp,
		    int, sid, int, tsn, uint16_t, ssn);
		return;
	}

	/*
	 * Deliver the data directly. Recalculate dlen now since
	 * we may have just reassembled this data.
	 */
	dlen = dmp->b_wptr - (uchar_t *)dc - sizeof (*dc);
	for (pmp = dmp->b_cont; pmp != NULL; pmp = pmp->b_cont)
		dlen += MBLKL(pmp);
	ASSERT(sctp->sctp_rxqueued >= dlen);

	/* Deliver the message. */
	sctp->sctp_rxqueued -= dlen;

	if (can_deliver) {
		/* step past header to the payload */
		dmp->b_rptr = (uchar_t *)(dc + 1);
		if (sctp_input_add_ancillary(sctp, &dmp, dc, fp,
		    ipp, ira) == 0) {
			dprint(1, ("sctp_data_chunk: delivering %lu bytes\n",
			    msgdsize(dmp)));
			/*
			 * We overload the meaning of b_flag for SCTP sockfs
			 * internal use, to advise sockfs of partial delivery
			 * semantics.
			 */
			dmp->b_flag = tpfinished ? 0 : SCTP_PARTIAL_DATA;
			if (sctp->sctp_flowctrld) {
				sctp->sctp_rwnd -= dlen;
				if (sctp->sctp_rwnd < 0)
					sctp->sctp_rwnd = 0;
			}
			if (sctp->sctp_ulp_recv(sctp->sctp_ulpd, dmp,
			    msgdsize(dmp), 0, &error, NULL) <= 0) {
				sctp->sctp_flowctrld = B_TRUE;
			}
			SCTP_ACK_IT(sctp, tsn);
		} else {
			/* No memory don't ack, the peer will retransmit. */
			freemsg(dmp);
			return;
		}
	} else {
		/* Closed above, ack to peer and free the data */
		freemsg(dmp);
		SCTP_ACK_IT(sctp, tsn);
	}

	/*
	 * Data now enqueued, may already have been processed and free'd
	 * by the ULP (or we may have just freed it above, if we could not
	 * deliver), so we must not reference it (this is why we saved the
	 * ssn and ubit earlier).
	 */
	if (ubit != 0) {
		BUMP_LOCAL(sctp->sctp_iudchunks);
		goto done;
	}
	BUMP_LOCAL(sctp->sctp_idchunks);

	/*
	 * There was a partial delivery and it has not finished,
	 * don't pull anything from the pqueues or increment the
	 * nextseq. This msg must complete before starting on
	 * the next ssn and the partial message must have the
	 * same ssn as the next expected message..
	 */
	if (!tpfinished) {
		DTRACE_PROBE4(sctp_partial_delivery, sctp_t *, sctp,
		    int, sid, int, tsn, uint16_t, ssn);
		/*
		 * Verify the partial delivery is part of the
		 * message expected for ordered delivery.
		 */
		if (ssn != instr->nextseq) {
			DTRACE_PROBE4(sctp_partial_delivery_error,
			    sctp_t *, sctp, int, sid, int, tsn,
			    uint16_t, ssn);
			cmn_err(CE_WARN, "sctp partial"
			    " delivery error, sctp 0x%p"
			    " sid = 0x%x ssn != nextseq"
			    " tsn 0x%x ftsn 0x%x"
			    " ssn 0x%x nextseq 0x%x",
			    (void *)sctp, sid,
			    tsn, sctp->sctp_ftsn, ssn,
			    instr->nextseq);
		}

		ASSERT(ssn == instr->nextseq);
		goto done;
	}

	if (ssn != instr->nextseq) {
		DTRACE_PROBE4(sctp_inorder_delivery_error,
		    sctp_t *, sctp, int, sid, int, tsn,
		    uint16_t, ssn);
		cmn_err(CE_WARN, "sctp in-order delivery error, sctp 0x%p "
		    "sid = 0x%x ssn != nextseq ssn 0x%x nextseq 0x%x",
		    (void *)sctp, sid, ssn, instr->nextseq);
	}

	ASSERT(ssn == instr->nextseq);

	DTRACE_PROBE4(sctp_deliver_completemsg, sctp_t *, sctp, int, sid,
	    int, tsn, uint16_t, ssn);

	instr->nextseq = ssn + 1;

	/*
	 * Deliver any successive data chunks waiting in the instr pqueue
	 * for the data just sent up.
	 */
	while (instr->istr_nmsgs > 0) {
		dmp = (mblk_t *)instr->istr_msgs;
		dc = (sctp_data_hdr_t *)dmp->b_rptr;
		ssn = ntohs(dc->sdh_ssn);
		tsn = ntohl(dc->sdh_tsn);
		/* Stop at the first gap in the sequence */
		if (ssn != instr->nextseq)
			break;

		DTRACE_PROBE4(sctp_deliver_pqueuedmsg, sctp_t *, sctp,
		    int, sid, int, tsn, uint16_t, ssn);
		/*
		 * Ready to deliver all data before the gap
		 * to the upper layer.
		 */
		(instr->istr_nmsgs)--;
		(instr->nextseq)++;
		(sctp->sctp_istr_nmsgs)--;

		instr->istr_msgs = instr->istr_msgs->b_next;
		if (instr->istr_msgs != NULL)
			instr->istr_msgs->b_prev = NULL;
		dmp->b_next = dmp->b_prev = NULL;

		dprint(2, ("data_chunk: pulling %x from pq (ssn %d)\n",
		    ntohl(dc->sdh_tsn), (int)ssn));

		/*
		 * Composite messages indicate this chunk was reassembled,
		 * each b_cont represents another TSN; Follow the chain to
		 * reach the frag with the last tsn in order to advance ftsn
		 * shortly by calling SCTP_ACK_IT().
		 */
		dlen = dmp->b_wptr - dmp->b_rptr - sizeof (*dc);
		for (pmp = dmp->b_cont; pmp; pmp = pmp->b_cont)
			dlen += MBLKL(pmp);

		ASSERT(sctp->sctp_rxqueued >= dlen);

		sctp->sctp_rxqueued -= dlen;
		if (can_deliver) {
			dmp->b_rptr = (uchar_t *)(dc + 1);
			if (sctp_input_add_ancillary(sctp, &dmp, dc, fp,
			    ipp, ira) == 0) {
				dprint(1, ("sctp_data_chunk: delivering %lu "
				    "bytes\n", msgdsize(dmp)));
				/*
				 * Meaning of b_flag overloaded for SCTP sockfs
				 * internal use, advise sockfs of partial
				 * delivery semantics.
				 */
				dmp->b_flag = tpfinished ?
				    0 : SCTP_PARTIAL_DATA;
				if (sctp->sctp_flowctrld) {
					sctp->sctp_rwnd -= dlen;
					if (sctp->sctp_rwnd < 0)
						sctp->sctp_rwnd = 0;
				}
				if (sctp->sctp_ulp_recv(sctp->sctp_ulpd, dmp,
				    msgdsize(dmp), 0, &error, NULL) <= 0) {
					sctp->sctp_flowctrld = B_TRUE;
				}
				SCTP_ACK_IT(sctp, tsn);
			} else {
				/* don't ack, the peer will retransmit */
				freemsg(dmp);
				return;
			}
		} else {
			/* Closed above, ack and free the data */
			freemsg(dmp);
			SCTP_ACK_IT(sctp, tsn);
		}
	}

done:

	/*
	 * If there are gap reports pending, check if advancing
	 * the ftsn here closes a gap. If so, we can advance
	 * ftsn to the end of the set.
	 */
	if (sctp->sctp_sack_info != NULL &&
	    sctp->sctp_ftsn == sctp->sctp_sack_info->begin) {
		sctp->sctp_ftsn = sctp->sctp_sack_info->end + 1;
	}
	/*
	 * If ftsn has moved forward, maybe we can remove gap reports.
	 * NB: dmp may now be NULL, so don't dereference it here.
	 */
	if (oftsn != sctp->sctp_ftsn && sctp->sctp_sack_info != NULL) {
		sctp_ack_rem(&sctp->sctp_sack_info, sctp->sctp_ftsn - 1,
		    &sctp->sctp_sack_gaps);
		dprint(2, ("data_chunk: removed acks before %x (num=%d)\n",
		    sctp->sctp_ftsn - 1, sctp->sctp_sack_gaps));
	}

#ifdef	DEBUG
	if (sctp->sctp_sack_info != NULL) {
		ASSERT(sctp->sctp_ftsn != sctp->sctp_sack_info->begin);
	}
#endif

#undef	SCTP_ACK_IT
}

void
sctp_fill_sack(sctp_t *sctp, unsigned char *dst, int sacklen)
{
	sctp_chunk_hdr_t *sch;
	sctp_sack_chunk_t *sc;
	sctp_sack_frag_t *sf;
	uint16_t num_gaps = sctp->sctp_sack_gaps;
	sctp_set_t *sp;

	/* Chunk hdr */
	sch = (sctp_chunk_hdr_t *)dst;
	sch->sch_id = CHUNK_SACK;
	sch->sch_flags = 0;
	sch->sch_len = htons(sacklen);

	/* SACK chunk */
	sctp->sctp_lastacked = sctp->sctp_ftsn - 1;

	sc = (sctp_sack_chunk_t *)(sch + 1);
	sc->ssc_cumtsn = htonl(sctp->sctp_lastacked);
	if (sctp->sctp_rxqueued < sctp->sctp_rwnd) {
		sc->ssc_a_rwnd = htonl(sctp->sctp_rwnd - sctp->sctp_rxqueued);
	} else {
		sc->ssc_a_rwnd = 0;
	}
	/* Remember the last window sent to peer. */
	sctp->sctp_arwnd = sc->ssc_a_rwnd;
	sc->ssc_numfrags = htons(num_gaps);
	sc->ssc_numdups = 0;

	/* lay in gap reports */
	sf = (sctp_sack_frag_t *)(sc + 1);
	for (sp = sctp->sctp_sack_info; sp; sp = sp->next) {
		uint16_t offset;

		/* start */
		if (sp->begin > sctp->sctp_lastacked) {
			offset = (uint16_t)(sp->begin - sctp->sctp_lastacked);
		} else {
			/* sequence number wrap */
			offset = (uint16_t)(UINT32_MAX - sctp->sctp_lastacked +
			    sp->begin);
		}
		sf->ssf_start = htons(offset);

		/* end */
		if (sp->end >= sp->begin) {
			offset += (uint16_t)(sp->end - sp->begin);
		} else {
			/* sequence number wrap */
			offset += (uint16_t)(UINT32_MAX - sp->begin + sp->end);
		}
		sf->ssf_end = htons(offset);

		sf++;
		/* This is just for debugging (a la the following assertion) */
		num_gaps--;
	}

	ASSERT(num_gaps == 0);

	/* If the SACK timer is running, stop it */
	if (sctp->sctp_ack_timer_running) {
		sctp_timer_stop(sctp->sctp_ack_mp);
		sctp->sctp_ack_timer_running = B_FALSE;
	}

	BUMP_LOCAL(sctp->sctp_obchunks);
	BUMP_LOCAL(sctp->sctp_osacks);
}

mblk_t *
sctp_make_sack(sctp_t *sctp, sctp_faddr_t *sendto, mblk_t *dups)
{
	mblk_t *smp;
	size_t slen;
	sctp_chunk_hdr_t *sch;
	sctp_sack_chunk_t *sc;
	int32_t acks_max;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	uint32_t	dups_len;
	sctp_faddr_t	*fp;

	ASSERT(sendto != NULL);

	if (sctp->sctp_force_sack) {
		sctp->sctp_force_sack = 0;
		goto checks_done;
	}

	acks_max = sctps->sctps_deferred_acks_max;
	if (sctp->sctp_state == SCTPS_ESTABLISHED) {
		if (sctp->sctp_sack_toggle < acks_max) {
			/* no need to SACK right now */
			dprint(2, ("sctp_make_sack: %p no sack (toggle)\n",
			    (void *)sctp));
			return (NULL);
		} else if (sctp->sctp_sack_toggle >= acks_max) {
			sctp->sctp_sack_toggle = 0;
		}
	}

	if (sctp->sctp_ftsn == sctp->sctp_lastacked + 1) {
		dprint(2, ("sctp_make_sack: %p no sack (already)\n",
		    (void *)sctp));
		return (NULL);
	}

checks_done:
	dprint(2, ("sctp_make_sack: acking %x\n", sctp->sctp_ftsn - 1));

	if (dups != NULL)
		dups_len = MBLKL(dups);
	else
		dups_len = 0;
	slen = sizeof (*sch) + sizeof (*sc) +
	    (sizeof (sctp_sack_frag_t) * sctp->sctp_sack_gaps);

	/*
	 * If there are error chunks, check and see if we can send the
	 * SACK chunk and error chunks together in one packet.  If not,
	 * send the error chunks out now.
	 */
	if (sctp->sctp_err_chunks != NULL) {
		fp = SCTP_CHUNK_DEST(sctp->sctp_err_chunks);
		if (sctp->sctp_err_len + slen + dups_len > fp->sf_pmss) {
			if ((smp = sctp_make_mp(sctp, fp, 0)) == NULL) {
				SCTP_KSTAT(sctps, sctp_send_err_failed);
				SCTP_KSTAT(sctps, sctp_send_sack_failed);
				freemsg(sctp->sctp_err_chunks);
				sctp->sctp_err_chunks = NULL;
				sctp->sctp_err_len = 0;
				return (NULL);
			}
			smp->b_cont = sctp->sctp_err_chunks;
			sctp_set_iplen(sctp, smp, fp->sf_ixa);
			(void) conn_ip_output(smp, fp->sf_ixa);
			BUMP_LOCAL(sctp->sctp_opkts);
			sctp->sctp_err_chunks = NULL;
			sctp->sctp_err_len = 0;
		}
	}
	smp = sctp_make_mp(sctp, sendto, slen);
	if (smp == NULL) {
		SCTP_KSTAT(sctps, sctp_send_sack_failed);
		return (NULL);
	}
	sch = (sctp_chunk_hdr_t *)smp->b_wptr;

	sctp_fill_sack(sctp, smp->b_wptr, slen);
	smp->b_wptr += slen;
	if (dups != NULL) {
		sc = (sctp_sack_chunk_t *)(sch + 1);
		sc->ssc_numdups = htons(MBLKL(dups) / sizeof (uint32_t));
		sch->sch_len = htons(slen + dups_len);
		smp->b_cont = dups;
	}

	if (sctp->sctp_err_chunks != NULL) {
		linkb(smp, sctp->sctp_err_chunks);
		sctp->sctp_err_chunks = NULL;
		sctp->sctp_err_len = 0;
	}
	return (smp);
}

/*
 * Check and see if we need to send a SACK chunk.  If it is needed,
 * send it out.  Return true if a SACK chunk is sent, false otherwise.
 */
boolean_t
sctp_sack(sctp_t *sctp, mblk_t *dups)
{
	mblk_t *smp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	/* If we are shutting down, let send_shutdown() bundle the SACK */
	if (sctp->sctp_state == SCTPS_SHUTDOWN_SENT) {
		sctp_send_shutdown(sctp, 0);
	}

	ASSERT(sctp->sctp_lastdata != NULL);

	if ((smp = sctp_make_sack(sctp, sctp->sctp_lastdata, dups)) == NULL) {
		/* The caller of sctp_sack() will not free the dups mblk. */
		if (dups != NULL)
			freeb(dups);
		return (B_FALSE);
	}
	dprint(2, ("sctp_sack: sending to %p %x:%x:%x:%x\n",
	    (void *)sctp->sctp_lastdata,
	    SCTP_PRINTADDR(sctp->sctp_lastdata->sf_faddr)));

	sctp->sctp_active = LBOLT_FASTPATH64;

	SCTPS_BUMP_MIB(sctps, sctpOutAck);

	sctp_set_iplen(sctp, smp, sctp->sctp_lastdata->sf_ixa);
	(void) conn_ip_output(smp, sctp->sctp_lastdata->sf_ixa);
	BUMP_LOCAL(sctp->sctp_opkts);
	return (B_TRUE);
}

/*
 * This is called if we have a message that was partially sent and is
 * abandoned. The cum TSN will be the last chunk sent for this message,
 * subsequent chunks will be marked ABANDONED. We send a Forward TSN
 * chunk in this case with the TSN of the last sent chunk so that the
 * peer can clean up its fragment list for this message. This message
 * will be removed from the transmit list when the peer sends a SACK
 * back.
 */
int
sctp_check_abandoned_msg(sctp_t *sctp, mblk_t *meta)
{
	sctp_data_hdr_t	*dh;
	mblk_t		*nmp;
	mblk_t		*head;
	int32_t		unsent = 0;
	mblk_t		*mp1 = meta->b_cont;
	uint32_t	adv_pap = sctp->sctp_adv_pap;
	sctp_faddr_t	*fp = sctp->sctp_current;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	dh = (sctp_data_hdr_t *)mp1->b_rptr;
	if (SEQ_GEQ(sctp->sctp_lastack_rxd, ntohl(dh->sdh_tsn))) {
		sctp_ftsn_set_t	*sets = NULL;
		uint_t		nsets = 0;
		uint32_t	seglen = sizeof (uint32_t);
		boolean_t	ubit = SCTP_DATA_GET_UBIT(dh);

		while (mp1->b_next != NULL && SCTP_CHUNK_ISSENT(mp1->b_next))
			mp1 = mp1->b_next;
		dh = (sctp_data_hdr_t *)mp1->b_rptr;
		sctp->sctp_adv_pap = ntohl(dh->sdh_tsn);
		if (!ubit &&
		    !sctp_add_ftsn_set(&sets, fp, meta, &nsets, &seglen)) {
			sctp->sctp_adv_pap = adv_pap;
			return (ENOMEM);
		}
		nmp = sctp_make_ftsn_chunk(sctp, fp, sets, nsets, seglen);
		sctp_free_ftsn_set(sets);
		if (nmp == NULL) {
			sctp->sctp_adv_pap = adv_pap;
			return (ENOMEM);
		}
		head = sctp_add_proto_hdr(sctp, fp, nmp, 0, NULL);
		if (head == NULL) {
			sctp->sctp_adv_pap = adv_pap;
			freemsg(nmp);
			SCTP_KSTAT(sctps, sctp_send_ftsn_failed);
			return (ENOMEM);
		}
		SCTP_MSG_SET_ABANDONED(meta);
		sctp_set_iplen(sctp, head, fp->sf_ixa);
		(void) conn_ip_output(head, fp->sf_ixa);
		BUMP_LOCAL(sctp->sctp_opkts);
		if (!fp->sf_timer_running)
			SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
		mp1 = mp1->b_next;
		while (mp1 != NULL) {
			ASSERT(!SCTP_CHUNK_ISSENT(mp1));
			ASSERT(!SCTP_CHUNK_ABANDONED(mp1));
			SCTP_ABANDON_CHUNK(mp1);
			dh = (sctp_data_hdr_t *)mp1->b_rptr;
			unsent += ntohs(dh->sdh_len) - sizeof (*dh);
			mp1 = mp1->b_next;
		}
		ASSERT(sctp->sctp_unsent >= unsent);
		sctp->sctp_unsent -= unsent;
		/*
		 * Update ULP the amount of queued data, which is
		 * sent-unack'ed + unsent.
		 */
		if (!SCTP_IS_DETACHED(sctp))
			SCTP_TXQ_UPDATE(sctp);
		return (0);
	}
	return (-1);
}

uint32_t
sctp_cumack(sctp_t *sctp, uint32_t tsn, mblk_t **first_unacked)
{
	mblk_t *ump, *nump, *mp = NULL;
	uint16_t chunklen;
	uint32_t xtsn;
	sctp_faddr_t *fp;
	sctp_data_hdr_t *sdc;
	uint32_t cumack_forward = 0;
	sctp_msg_hdr_t	*mhdr;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	ump = sctp->sctp_xmit_head;

	/*
	 * Free messages only when they're completely acked.
	 */
	while (ump != NULL) {
		mhdr = (sctp_msg_hdr_t *)ump->b_rptr;
		for (mp = ump->b_cont; mp != NULL; mp = mp->b_next) {
			if (SCTP_CHUNK_ABANDONED(mp)) {
				ASSERT(SCTP_IS_MSG_ABANDONED(ump));
				mp = NULL;
				break;
			}
			/*
			 * We check for abandoned message if we are PR-SCTP
			 * aware, if this is not the first chunk in the
			 * message (b_cont) and if the message is marked
			 * abandoned.
			 */
			if (!SCTP_CHUNK_ISSENT(mp)) {
				if (sctp->sctp_prsctp_aware &&
				    mp != ump->b_cont &&
				    (SCTP_IS_MSG_ABANDONED(ump) ||
				    SCTP_MSG_TO_BE_ABANDONED(ump, mhdr,
				    sctp))) {
					(void) sctp_check_abandoned_msg(sctp,
					    ump);
				}
				goto cum_ack_done;
			}
			sdc = (sctp_data_hdr_t *)mp->b_rptr;
			xtsn = ntohl(sdc->sdh_tsn);
			if (SEQ_GEQ(sctp->sctp_lastack_rxd, xtsn))
				continue;
			if (SEQ_GEQ(tsn, xtsn)) {
				fp = SCTP_CHUNK_DEST(mp);
				chunklen = ntohs(sdc->sdh_len);

				if (sctp->sctp_out_time != 0 &&
				    xtsn == sctp->sctp_rtt_tsn) {
					/* Got a new RTT measurement */
					sctp_update_rtt(sctp, fp,
					    ddi_get_lbolt64() -
					    sctp->sctp_out_time);
					sctp->sctp_out_time = 0;
				}
				if (SCTP_CHUNK_ISACKED(mp))
					continue;
				SCTP_CHUNK_SET_SACKCNT(mp, 0);
				SCTP_CHUNK_ACKED(mp);
				ASSERT(fp->sf_suna >= chunklen);
				fp->sf_suna -= chunklen;
				fp->sf_acked += chunklen;
				cumack_forward += chunklen;
				ASSERT(sctp->sctp_unacked >=
				    (chunklen - sizeof (*sdc)));
				sctp->sctp_unacked -=
				    (chunklen - sizeof (*sdc));
				if (fp->sf_suna == 0) {
					/* all outstanding data acked */
					fp->sf_pba = 0;
					SCTP_FADDR_TIMER_STOP(fp);
				} else {
					SCTP_FADDR_TIMER_RESTART(sctp, fp,
					    fp->sf_rto);
				}
			} else {
				goto cum_ack_done;
			}
		}
		nump = ump->b_next;
		if (nump != NULL)
			nump->b_prev = NULL;
		if (ump == sctp->sctp_xmit_tail)
			sctp->sctp_xmit_tail = nump;
		if (SCTP_IS_MSG_ABANDONED(ump)) {
			BUMP_LOCAL(sctp->sctp_prsctpdrop);
			ump->b_next = NULL;
			sctp_sendfail_event(sctp, ump, 0, B_TRUE);
		} else {
			sctp_free_msg(ump);
		}
		sctp->sctp_xmit_head = ump = nump;
	}
cum_ack_done:
	*first_unacked = mp;
	if (cumack_forward > 0) {
		SCTPS_BUMP_MIB(sctps, sctpInAck);
		if (SEQ_GT(sctp->sctp_lastack_rxd, sctp->sctp_recovery_tsn)) {
			sctp->sctp_recovery_tsn = sctp->sctp_lastack_rxd;
		}

		/*
		 * Update ULP the amount of queued data, which is
		 * sent-unack'ed + unsent.
		 */
		if (!SCTP_IS_DETACHED(sctp))
			SCTP_TXQ_UPDATE(sctp);

		/* Time to send a shutdown? */
		if (sctp->sctp_state == SCTPS_SHUTDOWN_PENDING) {
			sctp_send_shutdown(sctp, 0);
		}
		sctp->sctp_xmit_unacked = mp;
	} else {
		/* dup ack */
		SCTPS_BUMP_MIB(sctps, sctpInDupAck);
	}
	sctp->sctp_lastack_rxd = tsn;
	if (SEQ_LT(sctp->sctp_adv_pap, sctp->sctp_lastack_rxd))
		sctp->sctp_adv_pap = sctp->sctp_lastack_rxd;
	ASSERT(sctp->sctp_xmit_head || sctp->sctp_unacked == 0);

	return (cumack_forward);
}

static int
sctp_set_frwnd(sctp_t *sctp, uint32_t frwnd)
{
	uint32_t orwnd;

	if (sctp->sctp_unacked > frwnd) {
		sctp->sctp_frwnd = 0;
		return (0);
	}
	orwnd = sctp->sctp_frwnd;
	sctp->sctp_frwnd = frwnd - sctp->sctp_unacked;
	if (orwnd < sctp->sctp_frwnd) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * For un-ordered messages.
 * Walk the sctp->sctp_uo_frag list and remove any fragments with TSN
 * less than/equal to ftsn. Fragments for un-ordered messages are
 * strictly in sequence (w.r.t TSN).
 */
static int
sctp_ftsn_check_uo_frag(sctp_t *sctp, uint32_t ftsn)
{
	mblk_t		*hmp;
	mblk_t		*hmp_next;
	sctp_data_hdr_t	*dc;
	int		dlen = 0;

	hmp = sctp->sctp_uo_frags;
	while (hmp != NULL) {
		hmp_next = hmp->b_next;
		dc = (sctp_data_hdr_t *)hmp->b_rptr;
		if (SEQ_GT(ntohl(dc->sdh_tsn), ftsn))
			return (dlen);
		sctp->sctp_uo_frags = hmp_next;
		if (hmp_next != NULL)
			hmp_next->b_prev = NULL;
		hmp->b_next = NULL;
		dlen += ntohs(dc->sdh_len) - sizeof (*dc);
		freeb(hmp);
		hmp = hmp_next;
	}
	return (dlen);
}

/*
 * For ordered messages.
 * Check for existing fragments for an sid-ssn pair reported as abandoned,
 * hence will not receive, in the Forward TSN. If there are fragments, then
 * we just nuke them. If and when Partial Delivery API is supported, we
 * would need to send a notification to the upper layer about this.
 */
static int
sctp_ftsn_check_frag(sctp_t *sctp, uint16_t ssn, sctp_instr_t *sip)
{
	sctp_reass_t	*srp;
	mblk_t		*hmp;
	mblk_t		*dmp;
	mblk_t		*hmp_next;
	sctp_data_hdr_t	*dc;
	int		dlen = 0;

	hmp = sip->istr_reass;
	while (hmp != NULL) {
		hmp_next = hmp->b_next;
		srp = (sctp_reass_t *)DB_BASE(hmp);
		if (SSN_GT(srp->sr_ssn, ssn))
			return (dlen);
		/*
		 * If we had sent part of this message up, send a partial
		 * delivery event. Since this is ordered delivery, we should
		 * have sent partial message only for the next in sequence,
		 * hence the ASSERT. See comments in sctp_data_chunk() for
		 * trypartial.
		 */
		if (srp->sr_partial_delivered) {
			if (srp->sr_ssn != sip->nextseq)
				cmn_err(CE_WARN, "sctp partial"
				    " delivery notify, sctp 0x%p"
				    " sip = 0x%p ssn != nextseq"
				    " ssn 0x%x nextseq 0x%x",
				    (void *)sctp, (void *)sip,
				    srp->sr_ssn, sip->nextseq);
			ASSERT(sip->nextseq == srp->sr_ssn);
			sctp_partial_delivery_event(sctp);
		}
		/* Take it out of the reass queue */
		sip->istr_reass = hmp_next;
		if (hmp_next != NULL)
			hmp_next->b_prev = NULL;
		hmp->b_next = NULL;
		ASSERT(hmp->b_prev == NULL);
		dmp = hmp;
		ASSERT(DB_TYPE(hmp) == M_CTL);
		dmp = hmp->b_cont;
		hmp->b_cont = NULL;
		freeb(hmp);
		hmp = dmp;
		while (dmp != NULL) {
			dc = (sctp_data_hdr_t *)dmp->b_rptr;
			dlen += ntohs(dc->sdh_len) - sizeof (*dc);
			dmp = dmp->b_cont;
		}
		freemsg(hmp);
		hmp = hmp_next;
	}
	return (dlen);
}

/*
 * Update sctp_ftsn to the cumulative TSN from the Forward TSN chunk. Remove
 * any SACK gaps less than the newly updated sctp_ftsn. Walk through the
 * sid-ssn pair in the Forward TSN and for each, clean the fragment list
 * for this pair, if needed, and check if we can deliver subsequent
 * messages, if any, from the instream queue (that were waiting for this
 * sid-ssn message to show up). Once we are done try to update the SACK
 * info. We could get a duplicate Forward TSN, in which case just send
 * a SACK. If any of the sid values in the Forward TSN is invalid,
 * send back an "Invalid Stream Identifier" error and continue processing
 * the rest.
 */
static void
sctp_process_forward_tsn(sctp_t *sctp, sctp_chunk_hdr_t *ch, sctp_faddr_t *fp,
    ip_pkt_t *ipp, ip_recv_attr_t *ira)
{
	uint32_t	*ftsn = (uint32_t *)(ch + 1);
	ftsn_entry_t	*ftsn_entry;
	sctp_instr_t	*instr;
	boolean_t	can_deliver = B_TRUE;
	size_t		dlen;
	int		flen;
	mblk_t		*dmp;
	mblk_t		*pmp;
	sctp_data_hdr_t	*dc;
	ssize_t		remaining;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	*ftsn = ntohl(*ftsn);
	remaining =  ntohs(ch->sch_len) - sizeof (*ch) - sizeof (*ftsn);

	if (SCTP_IS_DETACHED(sctp)) {
		SCTPS_BUMP_MIB(sctps, sctpInClosed);
		can_deliver = B_FALSE;
	}
	/*
	 * un-ordered messages don't have SID-SSN pair entries, we check
	 * for any fragments (for un-ordered message) to be discarded using
	 * the cumulative FTSN.
	 */
	flen = sctp_ftsn_check_uo_frag(sctp, *ftsn);
	if (flen > 0) {
		ASSERT(sctp->sctp_rxqueued >= flen);
		sctp->sctp_rxqueued -= flen;
	}
	ftsn_entry = (ftsn_entry_t *)(ftsn + 1);
	while (remaining >= sizeof (*ftsn_entry)) {
		ftsn_entry->ftsn_sid = ntohs(ftsn_entry->ftsn_sid);
		ftsn_entry->ftsn_ssn = ntohs(ftsn_entry->ftsn_ssn);
		if (ftsn_entry->ftsn_sid >= sctp->sctp_num_istr) {
			sctp_bsc_t	inval_parm;

			/* Will populate the CAUSE block in the ERROR chunk. */
			inval_parm.bsc_sid = htons(ftsn_entry->ftsn_sid);
			/* RESERVED, ignored at the receiving end */
			inval_parm.bsc_pad = 0;

			sctp_add_err(sctp, SCTP_ERR_BAD_SID,
			    (void *)&inval_parm, sizeof (sctp_bsc_t), fp);
			ftsn_entry++;
			remaining -= sizeof (*ftsn_entry);
			continue;
		}
		instr = &sctp->sctp_instr[ftsn_entry->ftsn_sid];
		flen = sctp_ftsn_check_frag(sctp, ftsn_entry->ftsn_ssn, instr);
		/* Indicates frags were nuked, update rxqueued */
		if (flen > 0) {
			ASSERT(sctp->sctp_rxqueued >= flen);
			sctp->sctp_rxqueued -= flen;
		}
		/*
		 * It is possible to receive an FTSN chunk with SSN smaller
		 * than then nextseq if this chunk is a retransmission because
		 * of incomplete processing when it was first processed.
		 */
		if (SSN_GE(ftsn_entry->ftsn_ssn, instr->nextseq))
			instr->nextseq = ftsn_entry->ftsn_ssn + 1;
		while (instr->istr_nmsgs > 0) {
			mblk_t	*next;

			dmp = (mblk_t *)instr->istr_msgs;
			dc = (sctp_data_hdr_t *)dmp->b_rptr;
			if (ntohs(dc->sdh_ssn) != instr->nextseq)
				break;

			next = dmp->b_next;
			dlen = dmp->b_wptr - dmp->b_rptr - sizeof (*dc);
			for (pmp = dmp->b_cont; pmp != NULL;
			    pmp = pmp->b_cont) {
				dlen += MBLKL(pmp);
			}
			if (can_deliver) {
				int error;

				dmp->b_rptr = (uchar_t *)(dc + 1);
				dmp->b_next = NULL;
				ASSERT(dmp->b_prev == NULL);
				if (sctp_input_add_ancillary(sctp,
				    &dmp, dc, fp, ipp, ira) == 0) {
					sctp->sctp_rxqueued -= dlen;
					/*
					 * Override b_flag for SCTP sockfs
					 * internal use
					 */

					dmp->b_flag = 0;
					if (sctp->sctp_flowctrld) {
						sctp->sctp_rwnd -= dlen;
						if (sctp->sctp_rwnd < 0)
							sctp->sctp_rwnd = 0;
					}
					if (sctp->sctp_ulp_recv(
					    sctp->sctp_ulpd, dmp, msgdsize(dmp),
					    0, &error, NULL) <= 0) {
						sctp->sctp_flowctrld = B_TRUE;
					}
				} else {
					/*
					 * We will resume processing when
					 * the FTSN chunk is re-xmitted.
					 */
					dmp->b_rptr = (uchar_t *)dc;
					dmp->b_next = next;
					dprint(0,
					    ("FTSN dequeuing %u failed\n",
					    ntohs(dc->sdh_ssn)));
					return;
				}
			} else {
				sctp->sctp_rxqueued -= dlen;
				ASSERT(dmp->b_prev == NULL);
				dmp->b_next = NULL;
				freemsg(dmp);
			}
			instr->istr_nmsgs--;
			instr->nextseq++;
			sctp->sctp_istr_nmsgs--;
			if (next != NULL)
				next->b_prev = NULL;
			instr->istr_msgs = next;
		}
		ftsn_entry++;
		remaining -= sizeof (*ftsn_entry);
	}
	/* Duplicate FTSN */
	if (*ftsn <= (sctp->sctp_ftsn - 1)) {
		sctp->sctp_force_sack = 1;
		return;
	}
	/* Advance cum TSN to that reported in the Forward TSN chunk */
	sctp->sctp_ftsn = *ftsn + 1;

	/* Remove all the SACK gaps before the new cum TSN */
	if (sctp->sctp_sack_info != NULL) {
		sctp_ack_rem(&sctp->sctp_sack_info, sctp->sctp_ftsn - 1,
		    &sctp->sctp_sack_gaps);
	}
	/*
	 * If there are gap reports pending, check if advancing
	 * the ftsn here closes a gap. If so, we can advance
	 * ftsn to the end of the set.
	 * If ftsn has moved forward, maybe we can remove gap reports.
	 */
	if (sctp->sctp_sack_info != NULL &&
	    sctp->sctp_ftsn == sctp->sctp_sack_info->begin) {
		sctp->sctp_ftsn = sctp->sctp_sack_info->end + 1;
		sctp_ack_rem(&sctp->sctp_sack_info, sctp->sctp_ftsn - 1,
		    &sctp->sctp_sack_gaps);
	}
}

/*
 * When we have processed a SACK we check to see if we can advance the
 * cumulative TSN if there are abandoned chunks immediately following
 * the updated cumulative TSN. If there are, we attempt to send a
 * Forward TSN chunk.
 */
static void
sctp_check_abandoned_data(sctp_t *sctp, sctp_faddr_t *fp)
{
	mblk_t		*meta = sctp->sctp_xmit_head;
	mblk_t		*mp;
	mblk_t		*nmp;
	uint32_t	seglen;
	uint32_t	adv_pap = sctp->sctp_adv_pap;

	/*
	 * We only check in the first meta since otherwise we can't
	 * advance the cumulative ack point. We just look for chunks
	 * marked for retransmission, else we might prematurely
	 * send an FTSN for a sent, but unacked, chunk.
	 */
	for (mp = meta->b_cont; mp != NULL; mp = mp->b_next) {
		if (!SCTP_CHUNK_ISSENT(mp))
			return;
		if (SCTP_CHUNK_WANT_REXMIT(mp))
			break;
	}
	if (mp == NULL)
		return;
	sctp_check_adv_ack_pt(sctp, meta, mp);
	if (SEQ_GT(sctp->sctp_adv_pap, adv_pap)) {
		sctp_make_ftsns(sctp, meta, mp, &nmp, fp, &seglen);
		if (nmp == NULL) {
			sctp->sctp_adv_pap = adv_pap;
			if (!fp->sf_timer_running)
				SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
			return;
		}
		sctp_set_iplen(sctp, nmp, fp->sf_ixa);
		(void) conn_ip_output(nmp, fp->sf_ixa);
		BUMP_LOCAL(sctp->sctp_opkts);
		if (!fp->sf_timer_running)
			SCTP_FADDR_TIMER_RESTART(sctp, fp, fp->sf_rto);
	}
}

/*
 * The processing here follows the same logic in sctp_got_sack(), the reason
 * we do this separately is because, usually, gap blocks are ordered and
 * we can process it in sctp_got_sack(). However if they aren't we would
 * need to do some additional non-optimal stuff when we start processing the
 * unordered gaps. To that effect sctp_got_sack() does the processing in the
 * simple case and this does the same in the more involved case.
 */
static uint32_t
sctp_process_uo_gaps(sctp_t *sctp, uint32_t ctsn, sctp_sack_frag_t *ssf,
    int num_gaps, mblk_t *umphead, mblk_t *mphead, int *trysend,
    boolean_t *fast_recovery, uint32_t fr_xtsn)
{
	uint32_t		xtsn;
	uint32_t		gapstart = 0;
	uint32_t		gapend = 0;
	int			gapcnt;
	uint16_t		chunklen;
	sctp_data_hdr_t		*sdc;
	int			gstart;
	mblk_t			*ump = umphead;
	mblk_t			*mp = mphead;
	sctp_faddr_t		*fp;
	uint32_t		acked = 0;
	sctp_stack_t		*sctps = sctp->sctp_sctps;

	/*
	 * gstart tracks the last (in the order of TSN) gapstart that
	 * we process in this SACK gaps walk.
	 */
	gstart = ctsn;

	sdc = (sctp_data_hdr_t *)mp->b_rptr;
	xtsn = ntohl(sdc->sdh_tsn);
	for (gapcnt = 0; gapcnt < num_gaps; gapcnt++, ssf++) {
		if (gapstart != 0) {
			/*
			 * If we have reached the end of the transmit list or
			 * hit an unsent chunk or encountered an unordered gap
			 * block start from the ctsn again.
			 */
			if (ump == NULL || !SCTP_CHUNK_ISSENT(mp) ||
			    SEQ_LT(ctsn + ntohs(ssf->ssf_start), xtsn)) {
				ump = umphead;
				mp = mphead;
				sdc = (sctp_data_hdr_t *)mp->b_rptr;
				xtsn = ntohl(sdc->sdh_tsn);
			}
		}

		gapstart = ctsn + ntohs(ssf->ssf_start);
		gapend = ctsn + ntohs(ssf->ssf_end);

		/*
		 * Sanity checks:
		 *
		 * 1. SACK for TSN we have not sent - ABORT
		 * 2. Invalid or spurious gaps, ignore all gaps
		 */
		if (SEQ_GT(gapstart, sctp->sctp_ltsn - 1) ||
		    SEQ_GT(gapend, sctp->sctp_ltsn - 1)) {
			SCTPS_BUMP_MIB(sctps, sctpInAckUnsent);
			*trysend = -1;
			return (acked);
		} else if (SEQ_LT(gapend, gapstart) ||
		    SEQ_LEQ(gapstart, ctsn)) {
			break;
		}
		/*
		 * The xtsn can be the TSN processed for the last gap
		 * (gapend) or it could be the cumulative TSN. We continue
		 * with the last xtsn as long as the gaps are ordered, when
		 * we hit an unordered gap, we re-start from the cumulative
		 * TSN. For the first gap it is always the cumulative TSN.
		 */
		while (xtsn != gapstart) {
			/*
			 * We can't reliably check for reneged chunks
			 * when walking the unordered list, so we don't.
			 * In case the peer reneges then we will end up
			 * sending the reneged chunk via timeout.
			 */
			mp = mp->b_next;
			if (mp == NULL) {
				ump = ump->b_next;
				/*
				 * ump can't be NULL because of the sanity
				 * check above.
				 */
				ASSERT(ump != NULL);
				mp = ump->b_cont;
			}
			/*
			 * mp can't be unsent because of the sanity check
			 * above.
			 */
			ASSERT(SCTP_CHUNK_ISSENT(mp));
			sdc = (sctp_data_hdr_t *)mp->b_rptr;
			xtsn = ntohl(sdc->sdh_tsn);
		}
		/*
		 * Now that we have found the chunk with TSN == 'gapstart',
		 * let's walk till we hit the chunk with TSN == 'gapend'.
		 * All intermediate chunks will be marked ACKED, if they
		 * haven't already been.
		 */
		while (SEQ_LEQ(xtsn, gapend)) {
			/*
			 * SACKed
			 */
			SCTP_CHUNK_SET_SACKCNT(mp, 0);
			if (!SCTP_CHUNK_ISACKED(mp)) {
				SCTP_CHUNK_ACKED(mp);

				fp = SCTP_CHUNK_DEST(mp);
				chunklen = ntohs(sdc->sdh_len);
				ASSERT(fp->sf_suna >= chunklen);
				fp->sf_suna -= chunklen;
				if (fp->sf_suna == 0) {
					/* All outstanding data acked. */
					fp->sf_pba = 0;
					SCTP_FADDR_TIMER_STOP(fp);
				}
				fp->sf_acked += chunklen;
				acked += chunklen;
				sctp->sctp_unacked -= chunklen - sizeof (*sdc);
				ASSERT(sctp->sctp_unacked >= 0);
			}
			/*
			 * Move to the next message in the transmit list
			 * if we are done with all the chunks from the current
			 * message. Note, it is possible to hit the end of the
			 * transmit list here, i.e. if we have already completed
			 * processing the gap block.
			 */
			mp = mp->b_next;
			if (mp == NULL) {
				ump = ump->b_next;
				if (ump == NULL) {
					ASSERT(xtsn == gapend);
					break;
				}
				mp = ump->b_cont;
			}
			/*
			 * Likewise, we can hit an unsent chunk once we have
			 * completed processing the gap block.
			 */
			if (!SCTP_CHUNK_ISSENT(mp)) {
				ASSERT(xtsn == gapend);
				break;
			}
			sdc = (sctp_data_hdr_t *)mp->b_rptr;
			xtsn = ntohl(sdc->sdh_tsn);
		}
		/*
		 * We keep track of the last gap we successfully processed
		 * so that we can terminate the walk below for incrementing
		 * the SACK count.
		 */
		if (SEQ_LT(gstart, gapstart))
			gstart = gapstart;
	}
	/*
	 * Check if have incremented the SACK count for all unacked TSNs in
	 * sctp_got_sack(), if so we are done.
	 */
	if (SEQ_LEQ(gstart, fr_xtsn))
		return (acked);

	ump = umphead;
	mp = mphead;
	sdc = (sctp_data_hdr_t *)mp->b_rptr;
	xtsn = ntohl(sdc->sdh_tsn);
	while (SEQ_LT(xtsn, gstart)) {
		/*
		 * We have incremented SACK count for TSNs less than fr_tsn
		 * in sctp_got_sack(), so don't increment them again here.
		 */
		if (SEQ_GT(xtsn, fr_xtsn) && !SCTP_CHUNK_ISACKED(mp)) {
			SCTP_CHUNK_SET_SACKCNT(mp, SCTP_CHUNK_SACKCNT(mp) + 1);
			if (SCTP_CHUNK_SACKCNT(mp) ==
			    sctps->sctps_fast_rxt_thresh) {
				SCTP_CHUNK_REXMIT(sctp, mp);
				sctp->sctp_chk_fast_rexmit = B_TRUE;
				*trysend = 1;
				if (!*fast_recovery) {
					/*
					 * Entering fast recovery.
					 */
					fp = SCTP_CHUNK_DEST(mp);
					fp->sf_ssthresh = fp->sf_cwnd / 2;
					if (fp->sf_ssthresh < 2 * fp->sf_pmss) {
						fp->sf_ssthresh =
						    2 * fp->sf_pmss;
					}
					fp->sf_cwnd = fp->sf_ssthresh;
					fp->sf_pba = 0;
					sctp->sctp_recovery_tsn =
					    sctp->sctp_ltsn - 1;
					*fast_recovery = B_TRUE;
				}
			}
		}
		mp = mp->b_next;
		if (mp == NULL) {
			ump = ump->b_next;
			/* We can't get to the end of the transmit list here */
			ASSERT(ump != NULL);
			mp = ump->b_cont;
		}
		/* We can't hit an unsent chunk here */
		ASSERT(SCTP_CHUNK_ISSENT(mp));
		sdc = (sctp_data_hdr_t *)mp->b_rptr;
		xtsn = ntohl(sdc->sdh_tsn);
	}
	return (acked);
}

static int
sctp_got_sack(sctp_t *sctp, sctp_chunk_hdr_t *sch)
{
	sctp_sack_chunk_t	*sc;
	sctp_data_hdr_t		*sdc;
	sctp_sack_frag_t	*ssf;
	mblk_t			*ump;
	mblk_t			*mp;
	mblk_t			*mp1;
	uint32_t		cumtsn;
	uint32_t		xtsn;
	uint32_t		gapstart = 0;
	uint32_t		gapend = 0;
	uint32_t		acked = 0;
	uint16_t		chunklen;
	sctp_faddr_t		*fp;
	int			num_gaps;
	int			trysend = 0;
	int			i;
	boolean_t		fast_recovery = B_FALSE;
	boolean_t		cumack_forward = B_FALSE;
	boolean_t		fwd_tsn = B_FALSE;
	sctp_stack_t		*sctps = sctp->sctp_sctps;

	BUMP_LOCAL(sctp->sctp_ibchunks);
	BUMP_LOCAL(sctp->sctp_isacks);
	chunklen = ntohs(sch->sch_len);
	if (chunklen < (sizeof (*sch) + sizeof (*sc)))
		return (0);

	sc = (sctp_sack_chunk_t *)(sch + 1);
	cumtsn = ntohl(sc->ssc_cumtsn);

	dprint(2, ("got sack cumtsn %x -> %x\n", sctp->sctp_lastack_rxd,
	    cumtsn));

	/* out of order */
	if (SEQ_LT(cumtsn, sctp->sctp_lastack_rxd))
		return (0);

	if (SEQ_GT(cumtsn, sctp->sctp_ltsn - 1)) {
		SCTPS_BUMP_MIB(sctps, sctpInAckUnsent);
		/* Send an ABORT */
		return (-1);
	}

	/*
	 * Cwnd only done when not in fast recovery mode.
	 */
	if (SEQ_LT(sctp->sctp_lastack_rxd, sctp->sctp_recovery_tsn))
		fast_recovery = B_TRUE;

	/*
	 * .. and if the cum TSN is not moving ahead on account Forward TSN
	 */
	if (SEQ_LT(sctp->sctp_lastack_rxd, sctp->sctp_adv_pap))
		fwd_tsn = B_TRUE;

	if (cumtsn == sctp->sctp_lastack_rxd &&
	    (sctp->sctp_xmit_unacked == NULL ||
	    !SCTP_CHUNK_ABANDONED(sctp->sctp_xmit_unacked))) {
		if (sctp->sctp_xmit_unacked != NULL)
			mp = sctp->sctp_xmit_unacked;
		else if (sctp->sctp_xmit_head != NULL)
			mp = sctp->sctp_xmit_head->b_cont;
		else
			mp = NULL;
		SCTPS_BUMP_MIB(sctps, sctpInDupAck);
		/*
		 * If we were doing a zero win probe and the win
		 * has now opened to at least MSS, re-transmit the
		 * zero win probe via sctp_rexmit_packet().
		 */
		if (mp != NULL && sctp->sctp_zero_win_probe &&
		    ntohl(sc->ssc_a_rwnd) >= sctp->sctp_current->sf_pmss) {
			mblk_t	*pkt;
			uint_t	pkt_len;
			mblk_t	*mp1 = mp;
			mblk_t	*meta = sctp->sctp_xmit_head;

			/*
			 * Reset the RTO since we have been backing-off
			 * to send the ZWP.
			 */
			fp = sctp->sctp_current;
			fp->sf_rto = fp->sf_srtt + 4 * fp->sf_rttvar;
			SCTP_MAX_RTO(sctp, fp);
			/* Resend the ZWP */
			pkt = sctp_rexmit_packet(sctp, &meta, &mp1, fp,
			    &pkt_len);
			if (pkt == NULL) {
				SCTP_KSTAT(sctps, sctp_ss_rexmit_failed);
				return (0);
			}
			ASSERT(pkt_len <= fp->sf_pmss);
			sctp->sctp_zero_win_probe = B_FALSE;
			sctp->sctp_rxt_nxttsn = sctp->sctp_ltsn;
			sctp->sctp_rxt_maxtsn = sctp->sctp_ltsn;
			sctp_set_iplen(sctp, pkt, fp->sf_ixa);
			(void) conn_ip_output(pkt, fp->sf_ixa);
			BUMP_LOCAL(sctp->sctp_opkts);
		}
	} else {
		if (sctp->sctp_zero_win_probe) {
			/*
			 * Reset the RTO since we have been backing-off
			 * to send the ZWP.
			 */
			fp = sctp->sctp_current;
			fp->sf_rto = fp->sf_srtt + 4 * fp->sf_rttvar;
			SCTP_MAX_RTO(sctp, fp);
			sctp->sctp_zero_win_probe = B_FALSE;
			/* This is probably not required */
			if (!sctp->sctp_rexmitting) {
				sctp->sctp_rxt_nxttsn = sctp->sctp_ltsn;
				sctp->sctp_rxt_maxtsn = sctp->sctp_ltsn;
			}
		}
		acked = sctp_cumack(sctp, cumtsn, &mp);
		sctp->sctp_xmit_unacked = mp;
		if (acked > 0) {
			trysend = 1;
			cumack_forward = B_TRUE;
			if (fwd_tsn && SEQ_GEQ(sctp->sctp_lastack_rxd,
			    sctp->sctp_adv_pap)) {
				cumack_forward = B_FALSE;
			}
		}
	}
	num_gaps = ntohs(sc->ssc_numfrags);
	UPDATE_LOCAL(sctp->sctp_gapcnt, num_gaps);
	if (num_gaps == 0 || mp == NULL || !SCTP_CHUNK_ISSENT(mp) ||
	    chunklen < (sizeof (*sch) + sizeof (*sc) +
	    num_gaps * sizeof (*ssf))) {
		goto ret;
	}
#ifdef	DEBUG
	/*
	 * Since we delete any message that has been acked completely,
	 * the unacked chunk must belong to sctp_xmit_head (as
	 * we don't have a back pointer from the mp to the meta data
	 * we do this).
	 */
	{
		mblk_t	*mp2 = sctp->sctp_xmit_head->b_cont;

		while (mp2 != NULL) {
			if (mp2 == mp)
				break;
			mp2 = mp2->b_next;
		}
		ASSERT(mp2 != NULL);
	}
#endif
	ump = sctp->sctp_xmit_head;

	/*
	 * Just remember where we started from, in case we need to call
	 * sctp_process_uo_gaps() if the gap blocks are unordered.
	 */
	mp1 = mp;

	sdc = (sctp_data_hdr_t *)mp->b_rptr;
	xtsn = ntohl(sdc->sdh_tsn);
	ASSERT(xtsn == cumtsn + 1);

	/*
	 * Go through SACK gaps. They are ordered based on start TSN.
	 */
	ssf = (sctp_sack_frag_t *)(sc + 1);
	for (i = 0; i < num_gaps; i++, ssf++) {
		if (gapstart != 0) {
			/* check for unordered gap */
			if (SEQ_LEQ(cumtsn + ntohs(ssf->ssf_start), gapstart)) {
				acked += sctp_process_uo_gaps(sctp,
				    cumtsn, ssf, num_gaps - i,
				    sctp->sctp_xmit_head, mp1,
				    &trysend, &fast_recovery, gapstart);
				if (trysend < 0) {
					SCTPS_BUMP_MIB(sctps, sctpInAckUnsent);
					return (-1);
				}
				break;
			}
		}
		gapstart = cumtsn + ntohs(ssf->ssf_start);
		gapend = cumtsn + ntohs(ssf->ssf_end);

		/*
		 * Sanity checks:
		 *
		 * 1. SACK for TSN we have not sent - ABORT
		 * 2. Invalid or spurious gaps, ignore all gaps
		 */
		if (SEQ_GT(gapstart, sctp->sctp_ltsn - 1) ||
		    SEQ_GT(gapend, sctp->sctp_ltsn - 1)) {
			SCTPS_BUMP_MIB(sctps, sctpInAckUnsent);
			return (-1);
		} else if (SEQ_LT(gapend, gapstart) ||
		    SEQ_LEQ(gapstart, cumtsn)) {
			break;
		}
		/*
		 * Let's start at the current TSN (for the 1st gap we start
		 * from the cumulative TSN, for subsequent ones we start from
		 * where the previous gapend was found - second while loop
		 * below) and walk the transmit list till we find the TSN
		 * corresponding to gapstart. All the unacked chunks till we
		 * get to the chunk with TSN == gapstart will have their
		 * SACKCNT incremented by 1. Note since the gap blocks are
		 * ordered, we won't be incrementing the SACKCNT for an
		 * unacked chunk by more than one while processing the gap
		 * blocks. If the SACKCNT for any unacked chunk exceeds
		 * the fast retransmit threshold, we will fast retransmit
		 * after processing all the gap blocks.
		 */
		ASSERT(SEQ_LEQ(xtsn, gapstart));
		while (xtsn != gapstart) {
			SCTP_CHUNK_SET_SACKCNT(mp, SCTP_CHUNK_SACKCNT(mp) + 1);
			if (SCTP_CHUNK_SACKCNT(mp) ==
			    sctps->sctps_fast_rxt_thresh) {
				SCTP_CHUNK_REXMIT(sctp, mp);
				sctp->sctp_chk_fast_rexmit = B_TRUE;
				trysend = 1;
				if (!fast_recovery) {
					/*
					 * Entering fast recovery.
					 */
					fp = SCTP_CHUNK_DEST(mp);
					fp->sf_ssthresh = fp->sf_cwnd / 2;
					if (fp->sf_ssthresh < 2 * fp->sf_pmss) {
						fp->sf_ssthresh =
						    2 * fp->sf_pmss;
					}
					fp->sf_cwnd = fp->sf_ssthresh;
					fp->sf_pba = 0;
					sctp->sctp_recovery_tsn =
					    sctp->sctp_ltsn - 1;
					fast_recovery = B_TRUE;
				}
			}

			/*
			 * Peer may have reneged on this chunk, so un-sack
			 * it now. If the peer did renege, we need to
			 * readjust unacked.
			 */
			if (SCTP_CHUNK_ISACKED(mp)) {
				chunklen = ntohs(sdc->sdh_len);
				fp = SCTP_CHUNK_DEST(mp);
				fp->sf_suna += chunklen;
				sctp->sctp_unacked += chunklen - sizeof (*sdc);
				SCTP_CHUNK_CLEAR_ACKED(sctp, mp);
				if (!fp->sf_timer_running) {
					SCTP_FADDR_TIMER_RESTART(sctp, fp,
					    fp->sf_rto);
				}
			}

			mp = mp->b_next;
			if (mp == NULL) {
				ump = ump->b_next;
				/*
				 * ump can't be NULL given the sanity check
				 * above.  But if it is NULL, it means that
				 * there is a data corruption.  We'd better
				 * panic.
				 */
				if (ump == NULL) {
					panic("Memory corruption detected: gap "
					    "start TSN 0x%x missing from the "
					    "xmit list: %p", gapstart,
					    (void *)sctp);
				}
				mp = ump->b_cont;
			}
			/*
			 * mp can't be unsent given the sanity check above.
			 */
			ASSERT(SCTP_CHUNK_ISSENT(mp));
			sdc = (sctp_data_hdr_t *)mp->b_rptr;
			xtsn = ntohl(sdc->sdh_tsn);
		}
		/*
		 * Now that we have found the chunk with TSN == 'gapstart',
		 * let's walk till we hit the chunk with TSN == 'gapend'.
		 * All intermediate chunks will be marked ACKED, if they
		 * haven't already been.
		 */
		while (SEQ_LEQ(xtsn, gapend)) {
			/*
			 * SACKed
			 */
			SCTP_CHUNK_SET_SACKCNT(mp, 0);
			if (!SCTP_CHUNK_ISACKED(mp)) {
				SCTP_CHUNK_ACKED(mp);

				fp = SCTP_CHUNK_DEST(mp);
				chunklen = ntohs(sdc->sdh_len);
				ASSERT(fp->sf_suna >= chunklen);
				fp->sf_suna -= chunklen;
				if (fp->sf_suna == 0) {
					/* All outstanding data acked. */
					fp->sf_pba = 0;
					SCTP_FADDR_TIMER_STOP(fp);
				}
				fp->sf_acked += chunklen;
				acked += chunklen;
				sctp->sctp_unacked -= chunklen - sizeof (*sdc);
				ASSERT(sctp->sctp_unacked >= 0);
			}
			/* Go to the next chunk of the current message */
			mp = mp->b_next;
			/*
			 * Move to the next message in the transmit list
			 * if we are done with all the chunks from the current
			 * message. Note, it is possible to hit the end of the
			 * transmit list here, i.e. if we have already completed
			 * processing the gap block.  But the TSN must be equal
			 * to the gapend because of the above sanity check.
			 * If it is not equal, it means that some data is
			 * missing.
			 * Also, note that we break here, which means we
			 * continue processing gap blocks, if any. In case of
			 * ordered gap blocks there can't be any following
			 * this (if there is it will fail the sanity check
			 * above). In case of un-ordered gap blocks we will
			 * switch to sctp_process_uo_gaps().  In either case
			 * it should be fine to continue with NULL ump/mp,
			 * but we just reset it to xmit_head.
			 */
			if (mp == NULL) {
				ump = ump->b_next;
				if (ump == NULL) {
					if (xtsn != gapend) {
						panic("Memory corruption "
						    "detected: gap end TSN "
						    "0x%x missing from the "
						    "xmit list: %p", gapend,
						    (void *)sctp);
					}
					ump = sctp->sctp_xmit_head;
					mp = mp1;
					sdc = (sctp_data_hdr_t *)mp->b_rptr;
					xtsn = ntohl(sdc->sdh_tsn);
					break;
				}
				mp = ump->b_cont;
			}
			/*
			 * Likewise, we could hit an unsent chunk once we have
			 * completed processing the gap block. Again, it is
			 * fine to continue processing gap blocks with mp
			 * pointing to the unsent chunk, because if there
			 * are more ordered gap blocks, they will fail the
			 * sanity check, and if there are un-ordered gap blocks,
			 * we will continue processing in sctp_process_uo_gaps()
			 * We just reset the mp to the one we started with.
			 */
			if (!SCTP_CHUNK_ISSENT(mp)) {
				ASSERT(xtsn == gapend);
				ump = sctp->sctp_xmit_head;
				mp = mp1;
				sdc = (sctp_data_hdr_t *)mp->b_rptr;
				xtsn = ntohl(sdc->sdh_tsn);
				break;
			}
			sdc = (sctp_data_hdr_t *)mp->b_rptr;
			xtsn = ntohl(sdc->sdh_tsn);
		}
	}
	if (sctp->sctp_prsctp_aware)
		sctp_check_abandoned_data(sctp, sctp->sctp_current);
	if (sctp->sctp_chk_fast_rexmit)
		sctp_fast_rexmit(sctp);
ret:
	trysend += sctp_set_frwnd(sctp, ntohl(sc->ssc_a_rwnd));

	/*
	 * If receive window is closed while there is unsent data,
	 * set a timer for doing zero window probes.
	 */
	if (sctp->sctp_frwnd == 0 && sctp->sctp_unacked == 0 &&
	    sctp->sctp_unsent != 0) {
		SCTP_FADDR_TIMER_RESTART(sctp, sctp->sctp_current,
		    sctp->sctp_current->sf_rto);
	}

	/*
	 * Set cwnd for all destinations.
	 * Congestion window gets increased only when cumulative
	 * TSN moves forward, we're not in fast recovery, and
	 * cwnd has been fully utilized (almost fully, need to allow
	 * some leeway due to non-MSS sized messages).
	 */
	if (sctp->sctp_current->sf_acked == acked) {
		/*
		 * Fast-path, only data sent to sctp_current got acked.
		 */
		fp = sctp->sctp_current;
		if (cumack_forward && !fast_recovery &&
		    (fp->sf_acked + fp->sf_suna > fp->sf_cwnd - fp->sf_pmss)) {
			if (fp->sf_cwnd < fp->sf_ssthresh) {
				/*
				 * Slow start
				 */
				if (fp->sf_acked > fp->sf_pmss) {
					fp->sf_cwnd += fp->sf_pmss;
				} else {
					fp->sf_cwnd += fp->sf_acked;
				}
				fp->sf_cwnd = MIN(fp->sf_cwnd,
				    sctp->sctp_cwnd_max);
			} else {
				/*
				 * Congestion avoidance
				 */
				fp->sf_pba += fp->sf_acked;
				if (fp->sf_pba >= fp->sf_cwnd) {
					fp->sf_pba -= fp->sf_cwnd;
					fp->sf_cwnd += fp->sf_pmss;
					fp->sf_cwnd = MIN(fp->sf_cwnd,
					    sctp->sctp_cwnd_max);
				}
			}
		}
		/*
		 * Limit the burst of transmitted data segments.
		 */
		if (fp->sf_suna + sctps->sctps_maxburst * fp->sf_pmss <
		    fp->sf_cwnd) {
			fp->sf_cwnd = fp->sf_suna + sctps->sctps_maxburst *
			    fp->sf_pmss;
		}
		fp->sf_acked = 0;
		goto check_ss_rxmit;
	}
	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next) {
		if (cumack_forward && fp->sf_acked && !fast_recovery &&
		    (fp->sf_acked + fp->sf_suna > fp->sf_cwnd - fp->sf_pmss)) {
			if (fp->sf_cwnd < fp->sf_ssthresh) {
				if (fp->sf_acked > fp->sf_pmss) {
					fp->sf_cwnd += fp->sf_pmss;
				} else {
					fp->sf_cwnd += fp->sf_acked;
				}
				fp->sf_cwnd = MIN(fp->sf_cwnd,
				    sctp->sctp_cwnd_max);
			} else {
				fp->sf_pba += fp->sf_acked;
				if (fp->sf_pba >= fp->sf_cwnd) {
					fp->sf_pba -= fp->sf_cwnd;
					fp->sf_cwnd += fp->sf_pmss;
					fp->sf_cwnd = MIN(fp->sf_cwnd,
					    sctp->sctp_cwnd_max);
				}
			}
		}
		if (fp->sf_suna + sctps->sctps_maxburst * fp->sf_pmss <
		    fp->sf_cwnd) {
			fp->sf_cwnd = fp->sf_suna + sctps->sctps_maxburst *
			    fp->sf_pmss;
		}
		fp->sf_acked = 0;
	}
	fp = sctp->sctp_current;
check_ss_rxmit:
	/*
	 * If this is a SACK following a timeout, check if there are
	 * still unacked chunks (sent before the timeout) that we can
	 * send.
	 */
	if (sctp->sctp_rexmitting) {
		if (SEQ_LT(sctp->sctp_lastack_rxd, sctp->sctp_rxt_maxtsn)) {
			/*
			 * As we are in retransmission phase, we may get a
			 * SACK which indicates some new chunks are received
			 * but cum_tsn does not advance.  During this
			 * phase, the other side advances cum_tsn only because
			 * it receives our retransmitted chunks.  Only
			 * this signals that some chunks are still
			 * missing.
			 */
			if (cumack_forward) {
				fp->sf_rxt_unacked -= acked;
				sctp_ss_rexmit(sctp);
			}
		} else {
			sctp->sctp_rexmitting = B_FALSE;
			sctp->sctp_rxt_nxttsn = sctp->sctp_ltsn;
			sctp->sctp_rxt_maxtsn = sctp->sctp_ltsn;
			fp->sf_rxt_unacked = 0;
		}
	}
	return (trysend);
}

/*
 * Returns 0 if the caller should stop processing any more chunks,
 * 1 if the caller should skip this chunk and continue processing.
 */
static int
sctp_strange_chunk(sctp_t *sctp, sctp_chunk_hdr_t *ch, sctp_faddr_t *fp)
{
	size_t len;

	BUMP_LOCAL(sctp->sctp_ibchunks);
	/* check top two bits for action required */
	if (ch->sch_id & 0x40) {	/* also matches 0xc0 */
		len = ntohs(ch->sch_len);
		sctp_add_err(sctp, SCTP_ERR_UNREC_CHUNK, ch, len, fp);

		if ((ch->sch_id & 0xc0) == 0xc0) {
			/* skip and continue */
			return (1);
		} else {
			/* stop processing */
			return (0);
		}
	}
	if (ch->sch_id & 0x80) {
		/* skip and continue, no error */
		return (1);
	}
	/* top two bits are clear; stop processing and no error */
	return (0);
}

/*
 * Basic sanity checks on all input chunks and parameters: they must
 * be of legitimate size for their purported type, and must follow
 * ordering conventions as defined in rfc2960.
 *
 * Returns 1 if the chunk and all encloded params are legitimate,
 * 0 otherwise.
 */
/*ARGSUSED*/
static int
sctp_check_input(sctp_t *sctp, sctp_chunk_hdr_t *ch, ssize_t len, int first)
{
	sctp_parm_hdr_t	*ph;
	void		*p = NULL;
	ssize_t		clen;
	uint16_t	ch_len;

	ch_len = ntohs(ch->sch_len);
	if (ch_len > len) {
		return (0);
	}

	switch (ch->sch_id) {
	case CHUNK_DATA:
		if (ch_len < sizeof (sctp_data_hdr_t)) {
			return (0);
		}
		return (1);
	case CHUNK_INIT:
	case CHUNK_INIT_ACK:
		{
			ssize_t	remlen = len;

			/*
			 * INIT and INIT-ACK chunks must not be bundled with
			 * any other.
			 */
			if (!first || sctp_next_chunk(ch, &remlen) != NULL ||
			    (ch_len < (sizeof (*ch) +
			    sizeof (sctp_init_chunk_t)))) {
				return (0);
			}
			/* may have params that need checking */
			p = (char *)(ch + 1) + sizeof (sctp_init_chunk_t);
			clen = ch_len - (sizeof (*ch) +
			    sizeof (sctp_init_chunk_t));
		}
		break;
	case CHUNK_SACK:
		if (ch_len < (sizeof (*ch) + sizeof (sctp_sack_chunk_t))) {
			return (0);
		}
		/* dup and gap reports checked by got_sack() */
		return (1);
	case CHUNK_SHUTDOWN:
		if (ch_len < (sizeof (*ch) + sizeof (uint32_t))) {
			return (0);
		}
		return (1);
	case CHUNK_ABORT:
	case CHUNK_ERROR:
		if (ch_len < sizeof (*ch)) {
			return (0);
		}
		/* may have params that need checking */
		p = ch + 1;
		clen = ch_len - sizeof (*ch);
		break;
	case CHUNK_ECNE:
	case CHUNK_CWR:
	case CHUNK_HEARTBEAT:
	case CHUNK_HEARTBEAT_ACK:
	/* Full ASCONF chunk and parameter checks are in asconf.c */
	case CHUNK_ASCONF:
	case CHUNK_ASCONF_ACK:
		if (ch_len < sizeof (*ch)) {
			return (0);
		}
		/* heartbeat data checked by process_heartbeat() */
		return (1);
	case CHUNK_SHUTDOWN_COMPLETE:
		{
			ssize_t remlen = len;

			/*
			 * SHUTDOWN-COMPLETE chunk must not be bundled with any
			 * other
			 */
			if (!first || sctp_next_chunk(ch, &remlen) != NULL ||
			    ch_len < sizeof (*ch)) {
				return (0);
			}
		}
		return (1);
	case CHUNK_COOKIE:
	case CHUNK_COOKIE_ACK:
	case CHUNK_SHUTDOWN_ACK:
		if (ch_len < sizeof (*ch) || !first) {
			return (0);
		}
		return (1);
	case CHUNK_FORWARD_TSN:
		if (ch_len < (sizeof (*ch) + sizeof (uint32_t)))
			return (0);
		return (1);
	default:
		return (1);	/* handled by strange_chunk() */
	}

	/* check and byteorder parameters */
	if (clen <= 0) {
		return (1);
	}
	ASSERT(p != NULL);

	ph = p;
	while (ph != NULL && clen > 0) {
		ch_len = ntohs(ph->sph_len);
		if (ch_len > len || ch_len < sizeof (*ph)) {
			return (0);
		}
		ph = sctp_next_parm(ph, &clen);
	}

	/* All OK */
	return (1);
}

static mblk_t *
sctp_check_in_policy(mblk_t *mp, ip_recv_attr_t *ira, ip_stack_t *ipst)
{
	boolean_t policy_present;
	ipha_t *ipha;
	ip6_t *ip6h;
	netstack_t	*ns = ipst->ips_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION) {
		policy_present = ipss->ipsec_inbound_v4_policy_present;
		ipha = (ipha_t *)mp->b_rptr;
		ip6h = NULL;
	} else {
		policy_present = ipss->ipsec_inbound_v6_policy_present;
		ipha = NULL;
		ip6h = (ip6_t *)mp->b_rptr;
	}

	if (policy_present) {
		/*
		 * The conn_t parameter is NULL because we already know
		 * nobody's home.
		 */
		mp = ipsec_check_global_policy(mp, (conn_t *)NULL,
		    ipha, ip6h, ira, ns);
		if (mp == NULL)
			return (NULL);
	}
	return (mp);
}

/* Handle out-of-the-blue packets */
void
sctp_ootb_input(mblk_t *mp, ip_recv_attr_t *ira, ip_stack_t *ipst)
{
	sctp_t			*sctp;
	sctp_chunk_hdr_t	*ch;
	sctp_hdr_t		*sctph;
	in6_addr_t		src, dst;
	uint_t			ip_hdr_len = ira->ira_ip_hdr_length;
	ssize_t			mlen;
	sctp_stack_t		*sctps;
	boolean_t		secure;
	zoneid_t		zoneid = ira->ira_zoneid;
	uchar_t			*rptr;

	ASSERT(ira->ira_ill == NULL);

	secure = ira->ira_flags & IRAF_IPSEC_SECURE;

	sctps = ipst->ips_netstack->netstack_sctp;

	SCTPS_BUMP_MIB(sctps, sctpOutOfBlue);
	SCTPS_BUMP_MIB(sctps, sctpInSCTPPkts);

	if (mp->b_cont != NULL) {
		/*
		 * All subsequent code is vastly simplified if it can
		 * assume a single contiguous chunk of data.
		 */
		if (pullupmsg(mp, -1) == 0) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, NULL);
			freemsg(mp);
			return;
		}
	}

	rptr = mp->b_rptr;
	sctph = ((sctp_hdr_t *)&rptr[ip_hdr_len]);
	if (ira->ira_flags & IRAF_IS_IPV4) {
		ipha_t *ipha;

		ipha = (ipha_t *)rptr;
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &src);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &dst);
	} else {
		ip6_t *ip6h;

		ip6h = (ip6_t *)rptr;
		src = ip6h->ip6_src;
		dst = ip6h->ip6_dst;
	}

	mlen = mp->b_wptr - (uchar_t *)(sctph + 1);
	if ((ch = sctp_first_chunk((uchar_t *)(sctph + 1), mlen)) == NULL) {
		dprint(3, ("sctp_ootb_input: invalid packet\n"));
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", mp, NULL);
		freemsg(mp);
		return;
	}

	switch (ch->sch_id) {
	case CHUNK_INIT:
		/* no listener; send abort  */
		if (secure && sctp_check_in_policy(mp, ira, ipst) == NULL)
			return;
		sctp_ootb_send_abort(sctp_init2vtag(ch), 0,
		    NULL, 0, mp, 0, B_TRUE, ira, ipst);
		break;
	case CHUNK_INIT_ACK:
		/* check for changed src addr */
		sctp = sctp_addrlist2sctp(mp, sctph, ch, zoneid, sctps);
		if (sctp != NULL) {
			/* success; proceed to normal path */
			mutex_enter(&sctp->sctp_lock);
			if (sctp->sctp_running) {
				sctp_add_recvq(sctp, mp, B_FALSE, ira);
				mutex_exit(&sctp->sctp_lock);
			} else {
				/*
				 * If the source address is changed, we
				 * don't need to worry too much about
				 * out of order processing.  So we don't
				 * check if the recvq is empty or not here.
				 */
				sctp->sctp_running = B_TRUE;
				mutex_exit(&sctp->sctp_lock);
				sctp_input_data(sctp, mp, ira);
				WAKE_SCTP(sctp);
			}
			SCTP_REFRELE(sctp);
			return;
		}
		/* else bogus init ack; drop it */
		break;
	case CHUNK_SHUTDOWN_ACK:
		if (secure && sctp_check_in_policy(mp, ira, ipst) == NULL)
			return;
		sctp_ootb_shutdown_ack(mp, ip_hdr_len, ira, ipst);
		return;
	case CHUNK_ERROR:
	case CHUNK_ABORT:
	case CHUNK_COOKIE_ACK:
	case CHUNK_SHUTDOWN_COMPLETE:
		break;
	default:
		if (secure && sctp_check_in_policy(mp, ira, ipst) == NULL)
			return;
		sctp_ootb_send_abort(sctph->sh_verf, 0,
		    NULL, 0, mp, 0, B_TRUE, ira, ipst);
		break;
	}
	freemsg(mp);
}

/*
 * Handle sctp packets.
 * Note that we rele the sctp_t (the caller got a reference on it).
 */
void
sctp_input(conn_t *connp, ipha_t *ipha, ip6_t *ip6h, mblk_t *mp,
    ip_recv_attr_t *ira)
{
	sctp_t		*sctp = CONN2SCTP(connp);
	boolean_t	secure;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;
	iaflags_t	iraflags = ira->ira_flags;
	ill_t		*rill = ira->ira_rill;

	secure = iraflags & IRAF_IPSEC_SECURE;

	if (connp->conn_min_ttl != 0 && connp->conn_min_ttl > ira->ira_ttl) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", mp, ill);
		SCTP_REFRELE(sctp);
		freemsg(mp);
		return;
	}

	/*
	 * We check some fields in conn_t without holding a lock.
	 * This should be fine.
	 */
	if (((iraflags & IRAF_IS_IPV4) ?
	    CONN_INBOUND_POLICY_PRESENT(connp, ipss) :
	    CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss)) ||
	    secure) {
		mp = ipsec_check_inbound_policy(mp, connp, ipha,
		    ip6h, ira);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			/* Note that mp is NULL */
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			SCTP_REFRELE(sctp);
			return;
		}
	}

	ira->ira_ill = ira->ira_rill = NULL;

	mutex_enter(&sctp->sctp_lock);
	if (sctp->sctp_running) {
		sctp_add_recvq(sctp, mp, B_FALSE, ira);
		mutex_exit(&sctp->sctp_lock);
		goto done;
	} else {
		sctp->sctp_running = B_TRUE;
		mutex_exit(&sctp->sctp_lock);

		mutex_enter(&sctp->sctp_recvq_lock);
		if (sctp->sctp_recvq != NULL) {
			sctp_add_recvq(sctp, mp, B_TRUE, ira);
			mutex_exit(&sctp->sctp_recvq_lock);
			WAKE_SCTP(sctp);
			goto done;
		}
	}
	mutex_exit(&sctp->sctp_recvq_lock);
	if (ira->ira_flags & IRAF_ICMP_ERROR)
		sctp_icmp_error(sctp, mp);
	else
		sctp_input_data(sctp, mp, ira);
	WAKE_SCTP(sctp);

done:
	SCTP_REFRELE(sctp);
	ira->ira_ill = ill;
	ira->ira_rill = rill;
}

static void
sctp_process_abort(sctp_t *sctp, sctp_chunk_hdr_t *ch, int err)
{
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	SCTPS_BUMP_MIB(sctps, sctpAborted);
	BUMP_LOCAL(sctp->sctp_ibchunks);

	/*
	 * SCTP_COMM_LOST is only sent up if the association is
	 * established (sctp_state >= SCTPS_ESTABLISHED).
	 */
	if (sctp->sctp_state >= SCTPS_ESTABLISHED) {
		sctp_assoc_event(sctp, SCTP_COMM_LOST,
		    ntohs(((sctp_parm_hdr_t *)(ch + 1))->sph_type), ch);
	}

	sctp_clean_death(sctp, err);
}

void
sctp_input_data(sctp_t *sctp, mblk_t *mp, ip_recv_attr_t *ira)
{
	sctp_chunk_hdr_t	*ch;
	ssize_t			mlen;
	int			gotdata;
	int			trysend;
	sctp_faddr_t		*fp;
	sctp_init_chunk_t	*iack;
	uint32_t		tsn;
	sctp_data_hdr_t		*sdc;
	ip_pkt_t		ipp;
	in6_addr_t		src;
	in6_addr_t		dst;
	uint_t			ifindex;
	sctp_hdr_t		*sctph;
	uint_t			ip_hdr_len = ira->ira_ip_hdr_length;
	mblk_t			*dups = NULL;
	int			recv_adaptation;
	boolean_t		wake_eager = B_FALSE;
	in6_addr_t		peer_src;
	int64_t			now;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	ip_stack_t		*ipst = sctps->sctps_netstack->netstack_ip;
	boolean_t		hb_already = B_FALSE;
	cred_t			*cr;
	pid_t			cpid;
	uchar_t			*rptr;
	conn_t			*connp = sctp->sctp_connp;
	boolean_t		shutdown_ack_needed = B_FALSE;

	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(ira->ira_ill == NULL);

	if (mp->b_cont != NULL) {
		/*
		 * All subsequent code is vastly simplified if it can
		 * assume a single contiguous chunk of data.
		 */
		if (pullupmsg(mp, -1) == 0) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, NULL);
			freemsg(mp);
			return;
		}
	}

	BUMP_LOCAL(sctp->sctp_ipkts);
	ifindex = ira->ira_ruifindex;

	rptr = mp->b_rptr;

	ipp.ipp_fields = 0;
	if (connp->conn_recv_ancillary.crb_all != 0) {
		/*
		 * Record packet information in the ip_pkt_t
		 */
		if (ira->ira_flags & IRAF_IS_IPV4) {
			(void) ip_find_hdr_v4((ipha_t *)rptr, &ipp,
			    B_FALSE);
		} else {
			uint8_t nexthdrp;

			/*
			 * IPv6 packets can only be received by applications
			 * that are prepared to receive IPv6 addresses.
			 * The IP fanout must ensure this.
			 */
			ASSERT(connp->conn_family == AF_INET6);

			(void) ip_find_hdr_v6(mp, (ip6_t *)rptr, B_TRUE, &ipp,
			    &nexthdrp);
			ASSERT(nexthdrp == IPPROTO_SCTP);

			/* Could have caused a pullup? */
			rptr = mp->b_rptr;
		}
	}

	sctph = ((sctp_hdr_t *)&rptr[ip_hdr_len]);

	if (ira->ira_flags & IRAF_IS_IPV4) {
		ipha_t *ipha;

		ipha = (ipha_t *)rptr;
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &src);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &dst);
	} else {
		ip6_t *ip6h;

		ip6h = (ip6_t *)rptr;
		src = ip6h->ip6_src;
		dst = ip6h->ip6_dst;
	}

	mlen = mp->b_wptr - (uchar_t *)(sctph + 1);
	ch = sctp_first_chunk((uchar_t *)(sctph + 1), mlen);
	if (ch == NULL) {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", mp, NULL);
		freemsg(mp);
		return;
	}

	if (!sctp_check_input(sctp, ch, mlen, 1)) {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", mp, NULL);
		goto done;
	}
	/*
	 * Check verfication tag (special handling for INIT,
	 * COOKIE, SHUTDOWN_COMPLETE and SHUTDOWN_ACK chunks).
	 * ABORTs are handled in the chunk processing loop, since
	 * may not appear first. All other checked chunks must
	 * appear first, or will have been dropped by check_input().
	 */
	switch (ch->sch_id) {
	case CHUNK_INIT:
		if (sctph->sh_verf != 0) {
			/* drop it */
			goto done;
		}
		break;
	case CHUNK_SHUTDOWN_COMPLETE:
		if (sctph->sh_verf == sctp->sctp_lvtag)
			break;
		if (sctph->sh_verf == sctp->sctp_fvtag &&
		    SCTP_GET_TBIT(ch)) {
			break;
		}
		/* else drop it */
		goto done;
	case CHUNK_ABORT:
	case CHUNK_COOKIE:
		/* handled below */
		break;
	case CHUNK_SHUTDOWN_ACK:
		if (sctp->sctp_state > SCTPS_BOUND &&
		    sctp->sctp_state < SCTPS_ESTABLISHED) {
			/* treat as OOTB */
			sctp_ootb_shutdown_ack(mp, ip_hdr_len, ira, ipst);
			return;
		}
		/* else fallthru */
	default:
		/*
		 * All other packets must have a valid
		 * verification tag, however if this is a
		 * listener, we use a refined version of
		 * out-of-the-blue logic.
		 */
		if (sctph->sh_verf != sctp->sctp_lvtag &&
		    sctp->sctp_state != SCTPS_LISTEN) {
			/* drop it */
			goto done;
		}
		break;
	}

	/* Have a valid sctp for this packet */
	fp = sctp_lookup_faddr(sctp, &src);
	dprint(2, ("sctp_dispatch_rput: mp=%p fp=%p sctp=%p\n", (void *)mp,
	    (void *)fp, (void *)sctp));

	gotdata = 0;
	trysend = 0;

	now = LBOLT_FASTPATH64;
	/* Process the chunks */
	do {
		dprint(3, ("sctp_dispatch_rput: state=%d, chunk id=%d\n",
		    sctp->sctp_state, (int)(ch->sch_id)));

		if (ch->sch_id == CHUNK_ABORT) {
			if (sctph->sh_verf != sctp->sctp_lvtag &&
			    sctph->sh_verf != sctp->sctp_fvtag) {
				/* drop it */
				goto done;
			}
		}

		switch (sctp->sctp_state) {

		case SCTPS_ESTABLISHED:
		case SCTPS_SHUTDOWN_PENDING:
		case SCTPS_SHUTDOWN_SENT:
			switch (ch->sch_id) {
			case CHUNK_DATA:
				/* 0-length data chunks are not allowed */
				if (ntohs(ch->sch_len) == sizeof (*sdc)) {
					sdc = (sctp_data_hdr_t *)ch;
					tsn = sdc->sdh_tsn;
					sctp_send_abort(sctp, sctp->sctp_fvtag,
					    SCTP_ERR_NO_USR_DATA, (char *)&tsn,
					    sizeof (tsn), mp, 0, B_FALSE, ira);
					sctp_assoc_event(sctp, SCTP_COMM_LOST,
					    0, NULL);
					sctp_clean_death(sctp, ECONNABORTED);
					goto done;
				}

				ASSERT(fp != NULL);
				sctp->sctp_lastdata = fp;
				sctp_data_chunk(sctp, ch, mp, &dups, fp,
				    &ipp, ira);
				gotdata = 1;
				/* Restart shutdown timer if shutting down */
				if (sctp->sctp_state == SCTPS_SHUTDOWN_SENT) {
					/*
					 * If we have exceeded our max
					 * wait bound for waiting for a
					 * shutdown ack from the peer,
					 * abort the association.
					 */
					if (sctps->sctps_shutack_wait_bound !=
					    0 &&
					    TICK_TO_MSEC(now -
					    sctp->sctp_out_time) >
					    sctps->sctps_shutack_wait_bound) {
						sctp_send_abort(sctp,
						    sctp->sctp_fvtag, 0, NULL,
						    0, mp, 0, B_FALSE, ira);
						sctp_assoc_event(sctp,
						    SCTP_COMM_LOST, 0, NULL);
						sctp_clean_death(sctp,
						    ECONNABORTED);
						goto done;
					}
					SCTP_FADDR_TIMER_RESTART(sctp, fp,
					    fp->sf_rto);
				}
				break;
			case CHUNK_SACK:
				ASSERT(fp != NULL);
				/*
				 * Peer is real and alive if it can ack our
				 * data.
				 */
				sctp_faddr_alive(sctp, fp);
				trysend = sctp_got_sack(sctp, ch);
				if (trysend < 0) {
					sctp_send_abort(sctp, sctph->sh_verf,
					    0, NULL, 0, mp, 0, B_FALSE, ira);
					sctp_assoc_event(sctp,
					    SCTP_COMM_LOST, 0, NULL);
					sctp_clean_death(sctp,
					    ECONNABORTED);
					goto done;
				}
				break;
			case CHUNK_HEARTBEAT:
				if (!hb_already) {
					/*
					 * In any one packet, there should
					 * only be one heartbeat chunk.  So
					 * we should not process more than
					 * once.
					 */
					sctp_return_heartbeat(sctp, ch, mp);
					hb_already = B_TRUE;
				}
				break;
			case CHUNK_HEARTBEAT_ACK:
				sctp_process_heartbeat(sctp, ch);
				break;
			case CHUNK_SHUTDOWN:
				sctp_shutdown_event(sctp);
				trysend = sctp_shutdown_received(sctp, ch,
				    B_FALSE, B_FALSE, fp);
				BUMP_LOCAL(sctp->sctp_ibchunks);
				break;
			case CHUNK_SHUTDOWN_ACK:
				BUMP_LOCAL(sctp->sctp_ibchunks);
				if (sctp->sctp_state == SCTPS_SHUTDOWN_SENT) {
					sctp_shutdown_complete(sctp);
					SCTPS_BUMP_MIB(sctps, sctpShutdowns);
					sctp_assoc_event(sctp,
					    SCTP_SHUTDOWN_COMP, 0, NULL);
					sctp_clean_death(sctp, 0);
					goto done;
				}
				break;
			case CHUNK_ABORT: {
				sctp_saddr_ipif_t *sp;

				/* Ignore if delete pending */
				sp = sctp_saddr_lookup(sctp, &dst, 0);
				ASSERT(sp != NULL);
				if (sp->saddr_ipif_delete_pending) {
					BUMP_LOCAL(sctp->sctp_ibchunks);
					break;
				}

				sctp_process_abort(sctp, ch, ECONNRESET);
				goto done;
			}
			case CHUNK_INIT:
				sctp_send_initack(sctp, sctph, ch, mp, ira);
				break;
			case CHUNK_COOKIE:
				if (sctp_process_cookie(sctp, ch, mp, &iack,
				    sctph, &recv_adaptation, NULL, ira) != -1) {
					sctp_send_cookie_ack(sctp);
					sctp_assoc_event(sctp, SCTP_RESTART,
					    0, NULL);
					if (recv_adaptation) {
						sctp->sctp_recv_adaptation = 1;
						sctp_adaptation_event(sctp);
					}
				} else {
					SCTPS_BUMP_MIB(sctps,
					    sctpInInvalidCookie);
				}
				break;
			case CHUNK_ERROR: {
				int error;

				BUMP_LOCAL(sctp->sctp_ibchunks);
				error = sctp_handle_error(sctp, sctph, ch, mp,
				    ira);
				if (error != 0) {
					sctp_assoc_event(sctp, SCTP_COMM_LOST,
					    0, NULL);
					sctp_clean_death(sctp, error);
					goto done;
				}
				break;
			}
			case CHUNK_ASCONF:
				ASSERT(fp != NULL);
				sctp_input_asconf(sctp, ch, fp);
				BUMP_LOCAL(sctp->sctp_ibchunks);
				break;
			case CHUNK_ASCONF_ACK:
				ASSERT(fp != NULL);
				sctp_faddr_alive(sctp, fp);
				sctp_input_asconf_ack(sctp, ch, fp);
				BUMP_LOCAL(sctp->sctp_ibchunks);
				break;
			case CHUNK_FORWARD_TSN:
				ASSERT(fp != NULL);
				sctp->sctp_lastdata = fp;
				sctp_process_forward_tsn(sctp, ch, fp,
				    &ipp, ira);
				gotdata = 1;
				BUMP_LOCAL(sctp->sctp_ibchunks);
				break;
			default:
				if (sctp_strange_chunk(sctp, ch, fp) == 0) {
					goto nomorechunks;
				} /* else skip and continue processing */
				break;
			}
			break;

		case SCTPS_LISTEN:
			switch (ch->sch_id) {
			case CHUNK_INIT:
				sctp_send_initack(sctp, sctph, ch, mp, ira);
				break;
			case CHUNK_COOKIE: {
				sctp_t *eager;

				if (sctp_process_cookie(sctp, ch, mp, &iack,
				    sctph, &recv_adaptation, &peer_src,
				    ira) == -1) {
					SCTPS_BUMP_MIB(sctps,
					    sctpInInvalidCookie);
					goto done;
				}

				/*
				 * The cookie is good; ensure that
				 * the peer used the verification
				 * tag from the init ack in the header.
				 */
				if (iack->sic_inittag != sctph->sh_verf)
					goto done;

				eager = sctp_conn_request(sctp, mp, ifindex,
				    ip_hdr_len, iack, ira);
				if (eager == NULL) {
					sctp_send_abort(sctp, sctph->sh_verf,
					    SCTP_ERR_NO_RESOURCES, NULL, 0, mp,
					    0, B_FALSE, ira);
					goto done;
				}

				/*
				 * If there were extra chunks
				 * bundled with the cookie,
				 * they must be processed
				 * on the eager's queue. We
				 * accomplish this by refeeding
				 * the whole packet into the
				 * state machine on the right
				 * q. The packet (mp) gets
				 * there via the eager's
				 * cookie_mp field (overloaded
				 * with the active open role).
				 * This is picked up when
				 * processing the null bind
				 * request put on the eager's
				 * q by sctp_accept(). We must
				 * first revert the cookie
				 * chunk's length field to network
				 * byteorder so it can be
				 * properly reprocessed on the
				 * eager's queue.
				 */
				SCTPS_BUMP_MIB(sctps, sctpPassiveEstab);
				if (mlen > ntohs(ch->sch_len)) {
					eager->sctp_cookie_mp = dupb(mp);
					/*
					 * If no mem, just let
					 * the peer retransmit.
					 */
				}
				sctp_assoc_event(eager, SCTP_COMM_UP, 0, NULL);
				if (recv_adaptation) {
					eager->sctp_recv_adaptation = 1;
					eager->sctp_rx_adaptation_code =
					    sctp->sctp_rx_adaptation_code;
					sctp_adaptation_event(eager);
				}

				eager->sctp_active = now;
				sctp_send_cookie_ack(eager);

				wake_eager = B_TRUE;

				/*
				 * Process rest of the chunks with eager.
				 */
				sctp = eager;
				fp = sctp_lookup_faddr(sctp, &peer_src);
				/*
				 * Confirm peer's original source.  fp can
				 * only be NULL if peer does not use the
				 * original source as one of its addresses...
				 */
				if (fp == NULL)
					fp = sctp_lookup_faddr(sctp, &src);
				else
					sctp_faddr_alive(sctp, fp);

				/*
				 * Validate the peer addresses.  It also starts
				 * the heartbeat timer.
				 */
				sctp_validate_peer(sctp);
				break;
			}
			/* Anything else is considered out-of-the-blue */
			case CHUNK_ERROR:
			case CHUNK_ABORT:
			case CHUNK_COOKIE_ACK:
			case CHUNK_SHUTDOWN_COMPLETE:
				BUMP_LOCAL(sctp->sctp_ibchunks);
				goto done;
			default:
				BUMP_LOCAL(sctp->sctp_ibchunks);
				sctp_send_abort(sctp, sctph->sh_verf, 0, NULL,
				    0, mp, 0, B_TRUE, ira);
				goto done;
			}
			break;

		case SCTPS_COOKIE_WAIT:
			switch (ch->sch_id) {
			case CHUNK_INIT_ACK:
				sctp_stop_faddr_timers(sctp);
				sctp_faddr_alive(sctp, sctp->sctp_current);
				sctp_send_cookie_echo(sctp, ch, mp, ira);
				BUMP_LOCAL(sctp->sctp_ibchunks);
				break;
			case CHUNK_ABORT:
				sctp_process_abort(sctp, ch, ECONNREFUSED);
				goto done;
			case CHUNK_INIT:
				sctp_send_initack(sctp, sctph, ch, mp, ira);
				break;
			case CHUNK_COOKIE:
				cr = ira->ira_cred;
				cpid = ira->ira_cpid;

				if (sctp_process_cookie(sctp, ch, mp, &iack,
				    sctph, &recv_adaptation, NULL, ira) == -1) {
					SCTPS_BUMP_MIB(sctps,
					    sctpInInvalidCookie);
					break;
				}
				sctp_send_cookie_ack(sctp);
				sctp_stop_faddr_timers(sctp);
				if (!SCTP_IS_DETACHED(sctp)) {
					sctp->sctp_ulp_connected(
					    sctp->sctp_ulpd, 0, cr, cpid);
					sctp_set_ulp_prop(sctp);

				}
				SCTP_ASSOC_EST(sctps, sctp);
				SCTPS_BUMP_MIB(sctps, sctpActiveEstab);
				if (sctp->sctp_cookie_mp) {
					freemsg(sctp->sctp_cookie_mp);
					sctp->sctp_cookie_mp = NULL;
				}

				/* Validate the peer addresses. */
				sctp->sctp_active = now;
				sctp_validate_peer(sctp);

				sctp_assoc_event(sctp, SCTP_COMM_UP, 0, NULL);
				if (recv_adaptation) {
					sctp->sctp_recv_adaptation = 1;
					sctp_adaptation_event(sctp);
				}
				/* Try sending queued data, or ASCONFs */
				trysend = 1;
				break;
			default:
				if (sctp_strange_chunk(sctp, ch, fp) == 0) {
					goto nomorechunks;
				} /* else skip and continue processing */
				break;
			}
			break;

		case SCTPS_COOKIE_ECHOED:
			switch (ch->sch_id) {
			case CHUNK_COOKIE_ACK:
				cr = ira->ira_cred;
				cpid = ira->ira_cpid;

				if (!SCTP_IS_DETACHED(sctp)) {
					sctp->sctp_ulp_connected(
					    sctp->sctp_ulpd, 0, cr, cpid);
					sctp_set_ulp_prop(sctp);
				}
				if (sctp->sctp_unacked == 0)
					sctp_stop_faddr_timers(sctp);
				SCTP_ASSOC_EST(sctps, sctp);
				SCTPS_BUMP_MIB(sctps, sctpActiveEstab);
				BUMP_LOCAL(sctp->sctp_ibchunks);
				if (sctp->sctp_cookie_mp) {
					freemsg(sctp->sctp_cookie_mp);
					sctp->sctp_cookie_mp = NULL;
				}
				sctp_faddr_alive(sctp, fp);
				/* Validate the peer addresses. */
				sctp->sctp_active = now;
				sctp_validate_peer(sctp);

				/* Try sending queued data, or ASCONFs */
				trysend = 1;
				sctp_assoc_event(sctp, SCTP_COMM_UP, 0, NULL);
				sctp_adaptation_event(sctp);
				break;
			case CHUNK_ABORT:
				sctp_process_abort(sctp, ch, ECONNREFUSED);
				goto done;
			case CHUNK_COOKIE:
				cr = ira->ira_cred;
				cpid = ira->ira_cpid;

				if (sctp_process_cookie(sctp, ch, mp, &iack,
				    sctph, &recv_adaptation, NULL, ira) == -1) {
					SCTPS_BUMP_MIB(sctps,
					    sctpInInvalidCookie);
					break;
				}
				sctp_send_cookie_ack(sctp);

				if (!SCTP_IS_DETACHED(sctp)) {
					sctp->sctp_ulp_connected(
					    sctp->sctp_ulpd, 0, cr, cpid);
					sctp_set_ulp_prop(sctp);

				}
				if (sctp->sctp_unacked == 0)
					sctp_stop_faddr_timers(sctp);
				SCTP_ASSOC_EST(sctps, sctp);
				SCTPS_BUMP_MIB(sctps, sctpActiveEstab);
				if (sctp->sctp_cookie_mp) {
					freemsg(sctp->sctp_cookie_mp);
					sctp->sctp_cookie_mp = NULL;
				}
				/* Validate the peer addresses. */
				sctp->sctp_active = now;
				sctp_validate_peer(sctp);

				sctp_assoc_event(sctp, SCTP_COMM_UP, 0, NULL);
				if (recv_adaptation) {
					sctp->sctp_recv_adaptation = 1;
					sctp_adaptation_event(sctp);
				}
				/* Try sending queued data, or ASCONFs */
				trysend = 1;
				break;
			case CHUNK_INIT:
				sctp_send_initack(sctp, sctph, ch, mp, ira);
				break;
			case CHUNK_ERROR: {
				sctp_parm_hdr_t *p;

				BUMP_LOCAL(sctp->sctp_ibchunks);
				/* check for a stale cookie */
				if (ntohs(ch->sch_len) >=
				    (sizeof (*p) + sizeof (*ch)) +
				    sizeof (uint32_t)) {

					p = (sctp_parm_hdr_t *)(ch + 1);
					if (p->sph_type ==
					    htons(SCTP_ERR_STALE_COOKIE)) {
						SCTPS_BUMP_MIB(sctps,
						    sctpAborted);
						sctp_error_event(sctp,
						    ch, B_FALSE);
						sctp_assoc_event(sctp,
						    SCTP_COMM_LOST, 0, NULL);
						sctp_clean_death(sctp,
						    ECONNREFUSED);
						goto done;
					}
				}
				break;
			}
			case CHUNK_HEARTBEAT:
				if (!hb_already) {
					sctp_return_heartbeat(sctp, ch, mp);
					hb_already = B_TRUE;
				}
				break;
			default:
				if (sctp_strange_chunk(sctp, ch, fp) == 0) {
					goto nomorechunks;
				} /* else skip and continue processing */
			} /* switch (ch->sch_id) */
			break;

		case SCTPS_SHUTDOWN_ACK_SENT:
			switch (ch->sch_id) {
			case CHUNK_ABORT:
				/* Pass gathered wisdom to IP for keeping */
				sctp_update_dce(sctp);
				sctp_process_abort(sctp, ch, 0);
				goto done;
			case CHUNK_SHUTDOWN_COMPLETE:
				BUMP_LOCAL(sctp->sctp_ibchunks);
				SCTPS_BUMP_MIB(sctps, sctpShutdowns);
				sctp_assoc_event(sctp, SCTP_SHUTDOWN_COMP, 0,
				    NULL);

				/* Pass gathered wisdom to IP for keeping */
				sctp_update_dce(sctp);
				sctp_clean_death(sctp, 0);
				goto done;
			case CHUNK_SHUTDOWN_ACK:
				sctp_shutdown_complete(sctp);
				BUMP_LOCAL(sctp->sctp_ibchunks);
				SCTPS_BUMP_MIB(sctps, sctpShutdowns);
				sctp_assoc_event(sctp, SCTP_SHUTDOWN_COMP, 0,
				    NULL);
				sctp_clean_death(sctp, 0);
				goto done;
			case CHUNK_COOKIE:
				(void) sctp_shutdown_received(sctp, NULL,
				    B_TRUE, B_FALSE, fp);
				BUMP_LOCAL(sctp->sctp_ibchunks);
				break;
			case CHUNK_HEARTBEAT:
				if (!hb_already) {
					sctp_return_heartbeat(sctp, ch, mp);
					hb_already = B_TRUE;
				}
				break;
			default:
				if (sctp_strange_chunk(sctp, ch, fp) == 0) {
					goto nomorechunks;
				} /* else skip and continue processing */
				break;
			}
			break;

		case SCTPS_SHUTDOWN_RECEIVED:
			switch (ch->sch_id) {
			case CHUNK_SHUTDOWN:
				trysend = sctp_shutdown_received(sctp, ch,
				    B_FALSE, B_FALSE, fp);
				/*
				 * shutdown_ack_needed may have been set as
				 * mentioned in the case CHUNK_SACK below.
				 * If sctp_shutdown_received() above found
				 * the xmit queue empty the SHUTDOWN ACK chunk
				 * has already been sent (or scheduled to be
				 * sent on the timer) and the SCTP state
				 * changed, so reset shutdown_ack_needed.
				 */
				if (shutdown_ack_needed && (sctp->sctp_state ==
				    SCTPS_SHUTDOWN_ACK_SENT))
					shutdown_ack_needed = B_FALSE;
				break;
			case CHUNK_SACK:
				trysend = sctp_got_sack(sctp, ch);
				if (trysend < 0) {
					sctp_send_abort(sctp, sctph->sh_verf,
					    0, NULL, 0, mp, 0, B_FALSE, ira);
					sctp_assoc_event(sctp,
					    SCTP_COMM_LOST, 0, NULL);
					sctp_clean_death(sctp,
					    ECONNABORTED);
					goto done;
				}

				/*
				 * All data acknowledgement after a shutdown
				 * should be done with SHUTDOWN chunk.
				 * However some peer SCTP do not conform with
				 * this and can unexpectedly send a SACK chunk.
				 * If all data are acknowledged, set
				 * shutdown_ack_needed here indicating that
				 * SHUTDOWN ACK needs to be sent later by
				 * sctp_send_shutdown_ack().
				 */
				if ((sctp->sctp_xmit_head == NULL) &&
				    (sctp->sctp_xmit_unsent == NULL))
					shutdown_ack_needed = B_TRUE;
				break;
			case CHUNK_ABORT:
				sctp_process_abort(sctp, ch, ECONNRESET);
				goto done;
			case CHUNK_HEARTBEAT:
				if (!hb_already) {
					sctp_return_heartbeat(sctp, ch, mp);
					hb_already = B_TRUE;
				}
				break;
			default:
				if (sctp_strange_chunk(sctp, ch, fp) == 0) {
					goto nomorechunks;
				} /* else skip and continue processing */
				break;
			}
			break;

		default:
			/*
			 * The only remaining states are SCTPS_IDLE and
			 * SCTPS_BOUND, and we should not be getting here
			 * for these.
			 */
			ASSERT(0);
		} /* switch (sctp->sctp_state) */

		ch = sctp_next_chunk(ch, &mlen);
		if (ch != NULL && !sctp_check_input(sctp, ch, mlen, 0))
			goto done;
	} while (ch != NULL);

	/* Finished processing all chunks in packet */

nomorechunks:

	if (shutdown_ack_needed)
		sctp_send_shutdown_ack(sctp, fp, B_FALSE);

	/* SACK if necessary */
	if (gotdata) {
		boolean_t sack_sent;

		(sctp->sctp_sack_toggle)++;
		sack_sent = sctp_sack(sctp, dups);
		dups = NULL;

		/* If a SACK is sent, no need to restart the timer. */
		if (!sack_sent && !sctp->sctp_ack_timer_running) {
			sctp->sctp_ack_timer_running = B_TRUE;
			sctp_timer(sctp, sctp->sctp_ack_mp,
			    MSEC_TO_TICK(sctps->sctps_deferred_ack_interval));
		}
	}

	if (trysend) {
		sctp_output(sctp, UINT_MAX);
		if (sctp->sctp_cxmit_list != NULL)
			sctp_wput_asconf(sctp, NULL);
	}
	/*
	 * If there is unsent data, make sure a timer is running, check
	 * timer_mp, if sctp_closei_local() ran the timers may be free.
	 */
	if (sctp->sctp_unsent > 0 && !sctp->sctp_current->sf_timer_running &&
	    sctp->sctp_current->sf_timer_mp != NULL) {
		SCTP_FADDR_TIMER_RESTART(sctp, sctp->sctp_current,
		    sctp->sctp_current->sf_rto);
	}

done:
	if (dups != NULL)
		freeb(dups);
	freemsg(mp);

	if (sctp->sctp_err_chunks != NULL)
		sctp_process_err(sctp);

	if (wake_eager) {
		/*
		 * sctp points to newly created control block, need to
		 * release it before exiting.
		 */
		WAKE_SCTP(sctp);
	}
}

/*
 * Some amount of data got removed from ULP's receive queue and we can
 * push messages up if we are flow controlled before.  Reset the receive
 * window to full capacity (conn_rcvbuf) and check if we should send a
 * window update.
 */
void
sctp_recvd(sctp_t *sctp, int len)
{
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	conn_t		*connp = sctp->sctp_connp;
	boolean_t	send_sack = B_FALSE;

	ASSERT(sctp != NULL);
	RUN_SCTP(sctp);

	sctp->sctp_flowctrld = B_FALSE;
	/* This is the amount of data queued in ULP. */
	sctp->sctp_ulp_rxqueued = connp->conn_rcvbuf - len;

	if (connp->conn_rcvbuf - sctp->sctp_arwnd >= sctp->sctp_mss)
		send_sack = B_TRUE;
	sctp->sctp_rwnd = connp->conn_rcvbuf;

	if (sctp->sctp_state >= SCTPS_ESTABLISHED && send_sack) {
		sctp->sctp_force_sack = 1;
		SCTPS_BUMP_MIB(sctps, sctpOutWinUpdate);
		(void) sctp_sack(sctp, NULL);
	}
	WAKE_SCTP(sctp);
}
