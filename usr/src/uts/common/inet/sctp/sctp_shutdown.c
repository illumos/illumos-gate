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
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/sctp_ip.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"

void
sctp_send_shutdown(sctp_t *sctp, int rexmit)
{
	mblk_t *smp;
	mblk_t *sendmp;
	sctp_chunk_hdr_t *sch;
	uint32_t *ctsn;
	sctp_faddr_t *fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (sctp->sctp_state != SCTPS_ESTABLISHED &&
	    sctp->sctp_state != SCTPS_SHUTDOWN_PENDING &&
	    sctp->sctp_state != SCTPS_SHUTDOWN_SENT) {
		return;
	}

	if (sctp->sctp_state == SCTPS_ESTABLISHED) {
		sctp->sctp_state = SCTPS_SHUTDOWN_PENDING;
		/*
		 * We set an upper bound on how long we will
		 * wait for a shutdown-ack from the peer. This
		 * is to prevent the receiver from attempting
		 * to create a half-closed state indefinately.
		 * See archive from IETF TSVWG mailing list
		 * for June 2001 for more information.
		 * Since we will not be calculating RTTs after
		 * sending the shutdown, we can overload out_time
		 * to track how long we have waited.
		 */
		sctp->sctp_out_time = lbolt64;
	}

	/*
	 * If there is unsent (or unacked) data, wait for it to get ack'd
	 */
	if (sctp->sctp_xmit_head != NULL || sctp->sctp_xmit_unsent != NULL) {
		return;
	}

	/* rotate faddrs if we are retransmitting */
	if (!rexmit) {
		fp = sctp->sctp_current;
	} else {
		fp = sctp_rotate_faddr(sctp, sctp->sctp_shutdown_faddr);
	}

	sctp->sctp_shutdown_faddr = fp;

	/* Link in a SACK if resending the shutdown */
	if (sctp->sctp_state > SCTPS_SHUTDOWN_PENDING &&
	    (sendmp = sctp_make_sack(sctp, fp, NULL)) != NULL) {

		smp = allocb(sizeof (*sch) + sizeof (*ctsn), BPRI_MED);
		if (smp == NULL) {
			freemsg(sendmp);
			goto done;
		}
		linkb(sendmp, smp);

		sch = (sctp_chunk_hdr_t *)smp->b_rptr;
		smp->b_wptr = smp->b_rptr + sizeof (*sch) + sizeof (*ctsn);
	} else {
		sendmp = sctp_make_mp(sctp, fp,
		    sizeof (*sch) + sizeof (*ctsn));
		if (sendmp == NULL) {
			SCTP_KSTAT(sctps, sctp_send_shutdown_failed);
			goto done;
		}
		sch = (sctp_chunk_hdr_t *)sendmp->b_wptr;
		sendmp->b_wptr += sizeof (*sch) + sizeof (*ctsn);

		/* shutdown w/o sack, update lastacked */
		sctp->sctp_lastacked = sctp->sctp_ftsn - 1;
	}

	sch->sch_id = CHUNK_SHUTDOWN;
	sch->sch_flags = 0;
	sch->sch_len = htons(sizeof (*sch) + sizeof (*ctsn));

	ctsn = (uint32_t *)(sch + 1);
	*ctsn = htonl(sctp->sctp_lastacked);

	/* Link the shutdown chunk in after the IP/SCTP header */

	sctp_set_iplen(sctp, sendmp);

	BUMP_LOCAL(sctp->sctp_obchunks);

	/* Send the shutdown and restart the timer */
	sctp_add_sendq(sctp, sendmp);

done:
	sctp->sctp_state = SCTPS_SHUTDOWN_SENT;
	SCTP_FADDR_TIMER_RESTART(sctp, sctp->sctp_current,
	    sctp->sctp_current->rto);
}

int
sctp_shutdown_received(sctp_t *sctp, sctp_chunk_hdr_t *sch, boolean_t crwsd,
    boolean_t rexmit, sctp_faddr_t *fp)
{
	mblk_t *samp;
	sctp_chunk_hdr_t *sach;
	uint32_t *tsn;
	int trysend = 0;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	if (sctp->sctp_state != SCTPS_SHUTDOWN_ACK_SENT)
		sctp->sctp_state = SCTPS_SHUTDOWN_RECEIVED;

	/* Extract and process the TSN in the shutdown chunk */
	if (sch != NULL) {
		tsn = (uint32_t *)(sch + 1);
		trysend = sctp_cumack(sctp, ntohl(*tsn), &samp);
	}

	/* Don't allow sending new data */
	if (!SCTP_IS_DETACHED(sctp) && !sctp->sctp_ulp_discon_done) {
		sctp->sctp_ulp_opctl(sctp->sctp_ulpd, SOCK_OPCTL_SHUT_SEND, 0);
		sctp->sctp_ulp_discon_done = B_TRUE;
	}

	/*
	 * If there is unsent or unacked data, try sending them out now.
	 * The other side should acknowledge them.  After we have flushed
	 * the transmit queue, we can complete the shutdown sequence.
	 */
	if (sctp->sctp_xmit_head != NULL || sctp->sctp_xmit_unsent != NULL)
		return (1);

	if (fp == NULL) {
		/* rotate faddrs if we are retransmitting */
		if (!rexmit)
			fp = sctp->sctp_current;
		else
			fp = sctp_rotate_faddr(sctp, sctp->sctp_shutdown_faddr);
	}
	sctp->sctp_shutdown_faddr = fp;

	samp = sctp_make_mp(sctp, fp, sizeof (*sach));
	if (samp == NULL) {
		SCTP_KSTAT(sctps, sctp_send_shutdown_ack_failed);
		goto dotimer;
	}

	sach = (sctp_chunk_hdr_t *)samp->b_wptr;
	sach->sch_id = CHUNK_SHUTDOWN_ACK;
	sach->sch_flags = 0;
	sach->sch_len = htons(sizeof (*sach));

	samp->b_wptr += sizeof (*sach);

	/*
	 * bundle a "cookie received while shutting down" error if
	 * the caller asks for it.
	 */
	if (crwsd) {
		mblk_t *errmp;

		errmp = sctp_make_err(sctp, SCTP_ERR_COOKIE_SHUT, NULL, 0);
		if (errmp != NULL) {
			linkb(samp, errmp);
			BUMP_LOCAL(sctp->sctp_obchunks);
		}
	}

	sctp_set_iplen(sctp, samp);

	BUMP_LOCAL(sctp->sctp_obchunks);

	sctp_add_sendq(sctp, samp);

dotimer:
	sctp->sctp_state = SCTPS_SHUTDOWN_ACK_SENT;
	SCTP_FADDR_TIMER_RESTART(sctp, sctp->sctp_current,
	    sctp->sctp_current->rto);

	return (trysend);
}

void
sctp_shutdown_complete(sctp_t *sctp)
{
	mblk_t *scmp;
	sctp_chunk_hdr_t *scch;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	scmp = sctp_make_mp(sctp, NULL, sizeof (*scch));
	if (scmp == NULL) {
		/* XXX use timer approach */
		SCTP_KSTAT(sctps, sctp_send_shutdown_comp_failed);
		return;
	}

	scch = (sctp_chunk_hdr_t *)scmp->b_wptr;
	scch->sch_id = CHUNK_SHUTDOWN_COMPLETE;
	scch->sch_flags = 0;
	scch->sch_len = htons(sizeof (*scch));

	scmp->b_wptr += sizeof (*scch);

	sctp_set_iplen(sctp, scmp);

	BUMP_LOCAL(sctp->sctp_obchunks);

	sctp_add_sendq(sctp, scmp);
}

/*
 * Similar to sctp_shutdown_complete(), except that since this
 * is out-of-the-blue, we can't use an sctp's association information,
 * and instead must draw all necessary info from the incoming packet.
 */
void
sctp_ootb_shutdown_ack(sctp_t *gsctp, mblk_t *inmp, uint_t ip_hdr_len)
{
	boolean_t		isv4;
	ipha_t			*inip4h;
	ip6_t			*inip6h;
	sctp_hdr_t		*insctph;
	sctp_chunk_hdr_t	*scch;
	int			i;
	uint16_t		port;
	mblk_t			*mp1;
	sctp_stack_t	*sctps = gsctp->sctp_sctps;

	isv4 = (IPH_HDR_VERSION(inmp->b_rptr) == IPV4_VERSION);

	/*
	 * The gsctp should contain the minimal IP header.  So the
	 * incoming mblk should be able to hold the new SCTP packet.
	 */
	ASSERT(MBLKL(inmp) >= sizeof (*insctph) + sizeof (*scch) +
	    (isv4 ? gsctp->sctp_ip_hdr_len : gsctp->sctp_ip_hdr6_len));

	/*
	 * Check to see if we can reuse the incoming mblk.  There should
	 * not be other reference and the db_base of the mblk should be
	 * properly aligned.  Since this packet comes from below,
	 * there should be enough header space to fill in what the lower
	 * layers want to add.  And we will not stash anything there.
	 */
	if (!IS_P2ALIGNED(DB_BASE(inmp), sizeof (ire_t *)) ||
	    DB_REF(inmp) != 1) {
		mp1 = allocb(MBLKL(inmp) + sctps->sctps_wroff_xtra, BPRI_MED);
		if (mp1 == NULL) {
			freeb(inmp);
			return;
		}
		mp1->b_rptr += sctps->sctps_wroff_xtra;
		mp1->b_wptr = mp1->b_rptr + MBLKL(inmp);
		bcopy(inmp->b_rptr, mp1->b_rptr, MBLKL(inmp));
		freeb(inmp);
		inmp = mp1;
	} else {
		ASSERT(DB_CKSUMFLAGS(inmp) == 0);
	}

	/*
	 * We follow the logic in tcp_xmit_early_reset() in that we skip
	 * reversing source route (i.e. relpace all IP options with EOL).
	 */
	if (isv4) {
		ipaddr_t	v4addr;

		inip4h = (ipha_t *)inmp->b_rptr;
		for (i = IP_SIMPLE_HDR_LENGTH; i < (int)ip_hdr_len; i++)
			inmp->b_rptr[i] = IPOPT_EOL;
		/* Swap addresses */
		inip4h->ipha_length = htons(ip_hdr_len + sizeof (*insctph) +
		    sizeof (*scch));
		v4addr = inip4h->ipha_src;
		inip4h->ipha_src = inip4h->ipha_dst;
		inip4h->ipha_dst = v4addr;
		inip4h->ipha_ident = 0;
		inip4h->ipha_ttl = (uchar_t)sctps->sctps_ipv4_ttl;
	} else {
		in6_addr_t	v6addr;

		inip6h = (ip6_t *)inmp->b_rptr;
		/* Remove any extension headers assuming partial overlay */
		if (ip_hdr_len > IPV6_HDR_LEN) {
			uint8_t	*to;

			to = inmp->b_rptr + ip_hdr_len - IPV6_HDR_LEN;
			ovbcopy(inip6h, to, IPV6_HDR_LEN);
			inmp->b_rptr += ip_hdr_len - IPV6_HDR_LEN;
			ip_hdr_len = IPV6_HDR_LEN;
			inip6h = (ip6_t *)inmp->b_rptr;
			inip6h->ip6_nxt = IPPROTO_SCTP;
		}
		inip6h->ip6_plen = htons(ip_hdr_len + sizeof (*insctph) +
		    sizeof (*scch) - IPV6_HDR_LEN);
		v6addr = inip6h->ip6_src;
		inip6h->ip6_src = inip6h->ip6_dst;
		inip6h->ip6_dst = v6addr;
		inip6h->ip6_hops = (uchar_t)sctps->sctps_ipv6_hoplimit;
	}
	insctph = (sctp_hdr_t *)(inmp->b_rptr + ip_hdr_len);

	/* Swap ports.  Verification tag is reused. */
	port = insctph->sh_sport;
	insctph->sh_sport = insctph->sh_dport;
	insctph->sh_dport = port;

	/* Lay in the shutdown complete chunk */
	scch = (sctp_chunk_hdr_t *)(insctph + 1);
	scch->sch_id = CHUNK_SHUTDOWN_COMPLETE;
	scch->sch_len = htons(sizeof (*scch));
	scch->sch_flags = 0;

	/* Set the T-bit */
	SCTP_SET_TBIT(scch);

	BUMP_LOCAL(gsctp->sctp_obchunks);
	/* Nothing to stash... */
	SCTP_STASH_IPINFO(inmp, (ire_t *)NULL);

	sctp_add_sendq(gsctp, inmp);
}
