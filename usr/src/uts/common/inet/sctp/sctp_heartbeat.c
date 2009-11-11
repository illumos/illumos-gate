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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#include <sys/strsubr.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mib2.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"

void
sctp_return_heartbeat(sctp_t *sctp, sctp_chunk_hdr_t *hbcp, mblk_t *mp)
{
	mblk_t *smp;
	sctp_chunk_hdr_t *cp;
	ipha_t *iniph;
	ip6_t *inip6h;
	int isv4;
	in6_addr_t addr;
	sctp_faddr_t *fp;
	uint16_t len;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	BUMP_LOCAL(sctp->sctp_ibchunks);

	/* Update the faddr for the src addr */
	isv4 = (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION);
	if (isv4) {
		iniph = (ipha_t *)mp->b_rptr;
		IN6_IPADDR_TO_V4MAPPED(iniph->ipha_src, &addr);
	} else {
		inip6h = (ip6_t *)mp->b_rptr;
		addr = inip6h->ip6_src;
	}
	fp = sctp_lookup_faddr(sctp, &addr);
	/* If the source address is bogus we silently drop the packet */
	if (fp == NULL) {
		dprint(1,
		    ("sctp_return_heartbeat: %p bogus hb from %x:%x:%x:%x\n",
		    (void *)sctp, SCTP_PRINTADDR(addr)));
		SCTP_KSTAT(sctps, sctp_return_hb_failed);
		return;
	}
	dprint(3, ("sctp_return_heartbeat: %p got hb from %x:%x:%x:%x\n",
	    (void *)sctp, SCTP_PRINTADDR(addr)));

	/*
	 * XXX It's really tempting to reuse the heartbeat mblk. But
	 * this complicates processing in sctp_dispatch (i.e. it will
	 * screw up sctp_next_chunk since we will set the chunk
	 * header's length into network byte-order), and if we ever
	 * encounter a heartbeat bundled with other chunks...
	 * So we take the slower-but-safe route.
	 */
	len = ntohs(hbcp->sch_len);

	/* Create an IP header, returning to the src addr from the heartbt */
	smp = sctp_make_mp(sctp, fp, len);
	if (smp == NULL) {
		SCTP_KSTAT(sctps, sctp_return_hb_failed);
		return;
	}

	cp = (sctp_chunk_hdr_t *)smp->b_wptr;
	cp->sch_id = CHUNK_HEARTBEAT_ACK;
	cp->sch_flags = 0;
	cp->sch_len = htons(len);

	/* Copy the information field from the heartbeat */
	bcopy((void *)(hbcp + 1), (void *)(cp + 1), len - sizeof (*cp));

	smp->b_wptr += len;

	BUMP_LOCAL(sctp->sctp_obchunks);

	sctp_set_iplen(sctp, smp, fp->ixa);
	(void) conn_ip_output(smp, fp->ixa);
	BUMP_LOCAL(sctp->sctp_opkts);
}

/*
 * The data section of the heartbeat contains a time field (lbolt64),
 * a 64 bit secret, followed by the v6 (possible a v4mapped) address this
 * heartbeat was sent to.  No byte-ordering is done, since the heartbeat
 * is not interpreted by the peer.
 */
void
sctp_send_heartbeat(sctp_t *sctp, sctp_faddr_t *fp)
{
	sctp_chunk_hdr_t *cp;
	sctp_parm_hdr_t *hpp;
	int64_t *t;
	int64_t now;
	in6_addr_t *a;
	mblk_t *hbmp;
	size_t hblen;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	dprint(3, ("sctp_send_heartbeat: to %x:%x:%x:%x from %x:%x:%x:%x\n",
	    SCTP_PRINTADDR(fp->faddr), SCTP_PRINTADDR(fp->saddr)));

	hblen = sizeof (*cp) +
	    sizeof (*hpp) +
	    sizeof (*t) +
	    sizeof (fp->hb_secret) +
	    sizeof (fp->faddr);
	hbmp = sctp_make_mp(sctp, fp, hblen);
	if (hbmp == NULL) {
		SCTP_KSTAT(sctps, sctp_send_hb_failed);
		return;
	}

	cp = (sctp_chunk_hdr_t *)hbmp->b_wptr;
	cp->sch_id = CHUNK_HEARTBEAT;
	cp->sch_flags = 0;
	cp->sch_len = hblen;
	cp->sch_len = htons(cp->sch_len);

	hpp = (sctp_parm_hdr_t *)(cp + 1);
	hpp->sph_type = htons(PARM_HBINFO);
	hpp->sph_len = hblen - sizeof (*cp);
	hpp->sph_len = htons(hpp->sph_len);

	/*
	 * Timestamp
	 *
	 * Copy the current time to the heartbeat and we can use it to
	 * calculate the RTT when we get it back in the heartbeat ACK.
	 */
	now = lbolt64;
	t = (int64_t *)(hpp + 1);
	bcopy(&now, t, sizeof (now));

	/*
	 * Secret
	 *
	 * The per peer address secret is used to make sure that the heartbeat
	 * ack is really in response to our heartbeat.  This prevents blind
	 * spoofing of heartbeat ack to fake the validity of an address.
	 */
	t++;
	bcopy(&fp->hb_secret, t, sizeof (uint64_t));

	/*
	 * Peer address
	 *
	 * The peer address is used to associate the heartbeat ack with
	 * the correct peer address.  The reason is that the peer is
	 * multihomed so that it may not use the same address as source
	 * in response to our heartbeat.
	 */
	a = (in6_addr_t *)(t + 1);
	bcopy(&fp->faddr, a, sizeof (*a));

	hbmp->b_wptr += hblen;

	/* Update the faddr's info */
	fp->lastactive = now;
	fp->hb_pending = B_TRUE;

	BUMP_LOCAL(sctp->sctp_obchunks);
	BUMP_MIB(&sctps->sctps_mib, sctpTimHeartBeatProbe);

	sctp_set_iplen(sctp, hbmp, fp->ixa);
	(void) conn_ip_output(hbmp, fp->ixa);
	BUMP_LOCAL(sctp->sctp_opkts);
}

/*
 * Call right after any address change to validate peer addresses.
 */
void
sctp_validate_peer(sctp_t *sctp)
{
	sctp_faddr_t	*fp;
	int		cnt;
	int64_t		now;
	int64_t		earliest_expiry;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	now = lbolt64;
	earliest_expiry = 0;
	cnt = sctps->sctps_maxburst;

	/*
	 * Loop thru the list looking for unconfirmed addresses and
	 * send a heartbeat.  But we should only send at most sctp_maxburst
	 * heartbeats.
	 */
	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->next) {
		/* No need to validate unreachable address. */
		if (fp->state == SCTP_FADDRS_UNREACH)
			continue;
		if (fp->state == SCTP_FADDRS_UNCONFIRMED) {
			if (cnt-- > 0) {
				fp->hb_expiry = now + fp->rto;
				sctp_send_heartbeat(sctp, fp);
			} else {
				/*
				 * If we cannot send now, be more aggressive
				 * and try again about half of RTO.  Note that
				 * all the unsent probes are set to expire at
				 * the same time.
				 */
				fp->hb_expiry = now +
				    (sctp->sctp_rto_initial >> 1);
			}
		}
		/* Find the earliest heartbeat expiry time for ALL fps. */
		if (fp->hb_interval != 0 && (earliest_expiry == 0 ||
		    fp->hb_expiry < earliest_expiry)) {
			earliest_expiry = fp->hb_expiry;
		}
	}
	/* We use heartbeat timer for autoclose. */
	if (sctp->sctp_autoclose != 0) {
		int64_t expire;

		expire = sctp->sctp_active + sctp->sctp_autoclose;
		if (earliest_expiry == 0 || expire < earliest_expiry)
			earliest_expiry = expire;
	}

	/*
	 * Set the timer to fire for the earliest heartbeat unless
	 * heartbeat is disabled for all addresses.
	 */
	if (earliest_expiry != 0) {
		earliest_expiry -= now;
		if (earliest_expiry < 0)
			earliest_expiry = 1;
		sctp_timer(sctp, sctp->sctp_heartbeat_mp, earliest_expiry);
	}
}

/*
 * Process an incoming heartbeat ack.  When sending a heartbeat, we
 * put the timestamp, a secret and the peer address the heartbeat is
 * sent in the data part of the heartbeat.  We will extract this info
 * and verify that this heartbeat ack is valid.
 */
void
sctp_process_heartbeat(sctp_t *sctp, sctp_chunk_hdr_t *cp)
{
	int64_t *sentp, sent;
	uint64_t secret;
	in6_addr_t addr;
	sctp_faddr_t *fp;
	sctp_parm_hdr_t *hpp;
	int64_t now;

	BUMP_LOCAL(sctp->sctp_ibchunks);

	/* Sanity checks */
	ASSERT(OK_32PTR(cp));
	if (ntohs(cp->sch_len) < (sizeof (*cp) + sizeof (*hpp) +
	    sizeof (sent) + sizeof (secret) + sizeof (addr))) {
		/* drop it */
		dprint(2, ("sctp_process_heartbeat: malformed ack %p\n",
		    (void *)sctp));
		return;
	}

	hpp = (sctp_parm_hdr_t *)(cp + 1);
	if (ntohs(hpp->sph_type) != PARM_HBINFO ||
	    ntohs(hpp->sph_len) != (ntohs(cp->sch_len) - sizeof (*cp))) {
		dprint(2,
		    ("sctp_process_heartbeat: malformed param in ack %p\n",
		    (void *)sctp));
		return;
	}

	/*
	 * Pull out the time sent from the ack.
	 * SCTP is 32-bit aligned, so copy 64 bit quantity.  Since we
	 * put it in, it should be in our byte order.
	 */
	sentp = (int64_t *)(hpp + 1);
	bcopy(sentp, &sent, sizeof (sent));

	/* Grab the secret to make sure that this heartbeat is valid */
	bcopy(++sentp, &secret, sizeof (secret));

	/* Next, verify the address to make sure that it is the right one. */
	bcopy(++sentp, &addr, sizeof (addr));
	fp = sctp_lookup_faddr(sctp, &addr);
	if (fp == NULL) {
		dprint(2, ("sctp_process_heartbeat: invalid faddr (sctp=%p)\n",
		    (void *)sctp));
		return;
	}
	if (secret != fp->hb_secret) {
		dprint(2,
		    ("sctp_process_heartbeat: invalid secret in ack %p\n",
		    (void *)sctp));
		return;
	}

	/* This address is now confirmed and alive. */
	sctp_faddr_alive(sctp, fp);
	now = lbolt64;
	sctp_update_rtt(sctp, fp, now - sent);

	/*
	 * Note that the heartbeat timer should still be running, we don't
	 * reset it to avoid going through the whole list of peer addresses
	 * for each heartbeat ack as we probably are in interrupt context.
	 */
	fp->hb_expiry = now + SET_HB_INTVL(fp);
}
