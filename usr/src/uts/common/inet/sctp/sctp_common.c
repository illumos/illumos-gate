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
#include <sys/strsubr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/sctp.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_ire.h>
#include <inet/ip_if.h>
#include <inet/ip_ndp.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/sctp_ip.h>
#include <inet/ipclassifier.h>

#include "sctp_impl.h"
#include "sctp_addr.h"
#include "sctp_asconf.h"

static struct kmem_cache *sctp_kmem_faddr_cache;
static void sctp_init_faddr(sctp_t *, sctp_faddr_t *, in6_addr_t *, mblk_t *);

/* Set the source address.  Refer to comments in sctp_get_dest(). */
void
sctp_set_saddr(sctp_t *sctp, sctp_faddr_t *fp)
{
	boolean_t v6 = !fp->sf_isv4;
	boolean_t addr_set;

	fp->sf_saddr = sctp_get_valid_addr(sctp, v6, &addr_set);
	/*
	 * If there is no source address avaialble, mark this peer address
	 * as unreachable for now.  When the heartbeat timer fires, it will
	 * call sctp_get_dest() to re-check if there is any source address
	 * available.
	 */
	if (!addr_set)
		fp->sf_state = SCTP_FADDRS_UNREACH;
}

/*
 * Call this function to get information about a peer addr fp.
 *
 * Uses ip_attr_connect to avoid explicit use of ire and source address
 * selection.
 */
void
sctp_get_dest(sctp_t *sctp, sctp_faddr_t *fp)
{
	in6_addr_t	laddr;
	in6_addr_t	nexthop;
	sctp_saddr_ipif_t *sp;
	int		hdrlen;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	conn_t		*connp = sctp->sctp_connp;
	iulp_t		uinfo;
	uint_t		pmtu;
	int		error;
	uint32_t	flags = IPDF_VERIFY_DST | IPDF_IPSEC |
	    IPDF_SELECT_SRC | IPDF_UNIQUE_DCE;

	/*
	 * Tell sctp_make_mp it needs to call us again should we not
	 * complete and set the saddr.
	 */
	fp->sf_saddr = ipv6_all_zeros;

	/*
	 * If this addr is not reachable, mark it as unconfirmed for now, the
	 * state will be changed back to unreachable later in this function
	 * if it is still the case.
	 */
	if (fp->sf_state == SCTP_FADDRS_UNREACH) {
		fp->sf_state = SCTP_FADDRS_UNCONFIRMED;
	}

	/*
	 * Socket is connected - enable PMTU discovery.
	 */
	if (!sctps->sctps_ignore_path_mtu)
		fp->sf_ixa->ixa_flags |= IXAF_PMTU_DISCOVERY;

	ip_attr_nexthop(&connp->conn_xmit_ipp, fp->sf_ixa, &fp->sf_faddr,
	    &nexthop);

	laddr = fp->sf_saddr;
	error = ip_attr_connect(connp, fp->sf_ixa, &laddr, &fp->sf_faddr,
	    &nexthop, connp->conn_fport, &laddr, &uinfo, flags);

	if (error != 0) {
		dprint(3, ("sctp_get_dest: no ire for %x:%x:%x:%x\n",
		    SCTP_PRINTADDR(fp->sf_faddr)));
		/*
		 * It is tempting to just leave the src addr
		 * unspecified and let IP figure it out, but we
		 * *cannot* do this, since IP may choose a src addr
		 * that is not part of this association... unless
		 * this sctp has bound to all addrs.  So if the dest
		 * lookup fails, try to find one in our src addr
		 * list, unless the sctp has bound to all addrs, in
		 * which case we change the src addr to unspec.
		 *
		 * Note that if this is a v6 endpoint but it does
		 * not have any v4 address at this point (e.g. may
		 * have been  deleted), sctp_get_valid_addr() will
		 * return mapped INADDR_ANY.  In this case, this
		 * address should be marked not reachable so that
		 * it won't be used to send data.
		 */
		sctp_set_saddr(sctp, fp);
		if (fp->sf_state == SCTP_FADDRS_UNREACH)
			return;
		goto check_current;
	}
	ASSERT(fp->sf_ixa->ixa_ire != NULL);
	ASSERT(!(fp->sf_ixa->ixa_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)));

	if (!sctp->sctp_loopback)
		sctp->sctp_loopback = uinfo.iulp_loopback;

	/* Make sure the laddr is part of this association */
	if ((sp = sctp_saddr_lookup(sctp, &laddr, 0)) != NULL &&
	    !sp->saddr_ipif_dontsrc) {
		if (sp->saddr_ipif_unconfirmed == 1)
			sp->saddr_ipif_unconfirmed = 0;
		/* We did IPsec policy lookup for laddr already */
		fp->sf_saddr = laddr;
	} else {
		dprint(2, ("sctp_get_dest: src addr is not part of assoc "
		    "%x:%x:%x:%x\n", SCTP_PRINTADDR(laddr)));

		/*
		 * Set the src to the first saddr and hope for the best.
		 * Note that this case should very seldomly
		 * happen.  One scenario this can happen is an app
		 * explicitly bind() to an address.  But that address is
		 * not the preferred source address to send to the peer.
		 */
		sctp_set_saddr(sctp, fp);
		if (fp->sf_state == SCTP_FADDRS_UNREACH) {
			return;
		}
	}

	/*
	 * Pull out RTO information for this faddr and use it if we don't
	 * have any yet.
	 */
	if (fp->sf_srtt == -1 && uinfo.iulp_rtt != 0) {
		/* The cached value is in ms. */
		fp->sf_srtt = MSEC_TO_TICK(uinfo.iulp_rtt);
		fp->sf_rttvar = MSEC_TO_TICK(uinfo.iulp_rtt_sd);
		fp->sf_rto = 3 * fp->sf_srtt;

		/* Bound the RTO by configured min and max values */
		if (fp->sf_rto < sctp->sctp_rto_min) {
			fp->sf_rto = sctp->sctp_rto_min;
		}
		if (fp->sf_rto > sctp->sctp_rto_max) {
			fp->sf_rto = sctp->sctp_rto_max;
		}
		SCTP_MAX_RTO(sctp, fp);
	}
	pmtu = uinfo.iulp_mtu;

	/*
	 * Record the MTU for this faddr. If the MTU for this faddr has
	 * changed, check if the assc MTU will also change.
	 */
	if (fp->sf_isv4) {
		hdrlen = sctp->sctp_hdr_len;
	} else {
		hdrlen = sctp->sctp_hdr6_len;
	}
	if ((fp->sf_pmss + hdrlen) != pmtu) {
		/* Make sure that sf_pmss is a multiple of SCTP_ALIGN. */
		fp->sf_pmss = (pmtu - hdrlen) & ~(SCTP_ALIGN - 1);
		if (fp->sf_cwnd < (fp->sf_pmss * 2)) {
			SET_CWND(fp, fp->sf_pmss,
			    sctps->sctps_slow_start_initial);
		}
	}

check_current:
	if (fp == sctp->sctp_current)
		sctp_set_faddr_current(sctp, fp);
}

void
sctp_update_dce(sctp_t *sctp)
{
	sctp_faddr_t	*fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	iulp_t		uinfo;
	ip_stack_t	*ipst = sctps->sctps_netstack->netstack_ip;
	uint_t		ifindex;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next) {
		bzero(&uinfo, sizeof (uinfo));
		/*
		 * Only record the PMTU for this faddr if we actually have
		 * done discovery. This prevents initialized default from
		 * clobbering any real info that IP may have.
		 */
		if (fp->sf_pmtu_discovered) {
			if (fp->sf_isv4) {
				uinfo.iulp_mtu = fp->sf_pmss +
				    sctp->sctp_hdr_len;
			} else {
				uinfo.iulp_mtu = fp->sf_pmss +
				    sctp->sctp_hdr6_len;
			}
		}
		if (sctps->sctps_rtt_updates != 0 &&
		    fp->sf_rtt_updates >= sctps->sctps_rtt_updates) {
			/*
			 * dce_update_uinfo() merges these values with the
			 * old values.
			 */
			uinfo.iulp_rtt = TICK_TO_MSEC(fp->sf_srtt);
			uinfo.iulp_rtt_sd = TICK_TO_MSEC(fp->sf_rttvar);
			fp->sf_rtt_updates = 0;
		}
		ifindex = 0;
		if (IN6_IS_ADDR_LINKSCOPE(&fp->sf_faddr)) {
			/*
			 * If we are going to create a DCE we'd better have
			 * an ifindex
			 */
			if (fp->sf_ixa->ixa_nce != NULL) {
				ifindex = fp->sf_ixa->ixa_nce->nce_common->
				    ncec_ill->ill_phyint->phyint_ifindex;
			} else {
				continue;
			}
		}

		(void) dce_update_uinfo(&fp->sf_faddr, ifindex, &uinfo, ipst);
	}
}

/*
 * The sender must later set the total length in the IP header.
 */
mblk_t *
sctp_make_mp(sctp_t *sctp, sctp_faddr_t *fp, int trailer)
{
	mblk_t *mp;
	size_t ipsctplen;
	int isv4;
	sctp_stack_t *sctps = sctp->sctp_sctps;
	boolean_t src_changed = B_FALSE;

	ASSERT(fp != NULL);
	isv4 = fp->sf_isv4;

	if (SCTP_IS_ADDR_UNSPEC(isv4, fp->sf_saddr) ||
	    (fp->sf_ixa->ixa_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))) {
		/* Need to pick a source */
		sctp_get_dest(sctp, fp);
		/*
		 * Although we still may not get an IRE, the source address
		 * may be changed in sctp_get_ire().  Set src_changed to
		 * true so that the source address is copied again.
		 */
		src_changed = B_TRUE;
	}

	/* There is no suitable source address to use, return. */
	if (fp->sf_state == SCTP_FADDRS_UNREACH)
		return (NULL);

	ASSERT(fp->sf_ixa->ixa_ire != NULL);
	ASSERT(!SCTP_IS_ADDR_UNSPEC(isv4, fp->sf_saddr));

	if (isv4) {
		ipsctplen = sctp->sctp_hdr_len;
	} else {
		ipsctplen = sctp->sctp_hdr6_len;
	}

	mp = allocb(ipsctplen + sctps->sctps_wroff_xtra + trailer, BPRI_MED);
	if (mp == NULL) {
		ip1dbg(("sctp_make_mp: error making mp..\n"));
		return (NULL);
	}
	mp->b_rptr += sctps->sctps_wroff_xtra;
	mp->b_wptr = mp->b_rptr + ipsctplen;

	ASSERT(OK_32PTR(mp->b_wptr));

	if (isv4) {
		ipha_t *iph = (ipha_t *)mp->b_rptr;

		bcopy(sctp->sctp_iphc, mp->b_rptr, ipsctplen);
		if (fp != sctp->sctp_current || src_changed) {
			/* Fix the source and destination addresses. */
			IN6_V4MAPPED_TO_IPADDR(&fp->sf_faddr, iph->ipha_dst);
			IN6_V4MAPPED_TO_IPADDR(&fp->sf_saddr, iph->ipha_src);
		}
		/* set or clear the don't fragment bit */
		if (fp->sf_df) {
			iph->ipha_fragment_offset_and_flags = htons(IPH_DF);
		} else {
			iph->ipha_fragment_offset_and_flags = 0;
		}
	} else {
		bcopy(sctp->sctp_iphc6, mp->b_rptr, ipsctplen);
		if (fp != sctp->sctp_current || src_changed) {
			/* Fix the source and destination addresses. */
			((ip6_t *)(mp->b_rptr))->ip6_dst = fp->sf_faddr;
			((ip6_t *)(mp->b_rptr))->ip6_src = fp->sf_saddr;
		}
	}
	ASSERT(sctp->sctp_connp != NULL);
	return (mp);
}

/*
 * Notify upper layers about preferred write offset, write size.
 */
void
sctp_set_ulp_prop(sctp_t *sctp)
{
	int hdrlen;
	struct sock_proto_props sopp;

	sctp_stack_t *sctps = sctp->sctp_sctps;

	if (sctp->sctp_current->sf_isv4) {
		hdrlen = sctp->sctp_hdr_len;
	} else {
		hdrlen = sctp->sctp_hdr6_len;
	}
	ASSERT(sctp->sctp_ulpd);

	sctp->sctp_connp->conn_wroff = sctps->sctps_wroff_xtra + hdrlen +
	    sizeof (sctp_data_hdr_t);

	ASSERT(sctp->sctp_current->sf_pmss == sctp->sctp_mss);
	bzero(&sopp, sizeof (sopp));
	sopp.sopp_flags = SOCKOPT_MAXBLK|SOCKOPT_WROFF;
	sopp.sopp_wroff = sctp->sctp_connp->conn_wroff;
	sopp.sopp_maxblk = sctp->sctp_mss - sizeof (sctp_data_hdr_t);
	sctp->sctp_ulp_prop(sctp->sctp_ulpd, &sopp);
}

/*
 * Set the lengths in the packet and the transmit attributes.
 */
void
sctp_set_iplen(sctp_t *sctp, mblk_t *mp, ip_xmit_attr_t *ixa)
{
	uint16_t	sum = 0;
	ipha_t		*iph;
	ip6_t		*ip6h;
	mblk_t		*pmp = mp;
	boolean_t	isv4;

	isv4 = (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION);
	for (; pmp; pmp = pmp->b_cont)
		sum += pmp->b_wptr - pmp->b_rptr;

	ixa->ixa_pktlen = sum;
	if (isv4) {
		iph = (ipha_t *)mp->b_rptr;
		iph->ipha_length = htons(sum);
		ixa->ixa_ip_hdr_length = sctp->sctp_ip_hdr_len;
	} else {
		ip6h = (ip6_t *)mp->b_rptr;
		ip6h->ip6_plen = htons(sum - IPV6_HDR_LEN);
		ixa->ixa_ip_hdr_length = sctp->sctp_ip_hdr6_len;
	}
}

int
sctp_compare_faddrsets(sctp_faddr_t *a1, sctp_faddr_t *a2)
{
	int na1 = 0;
	int overlap = 0;
	int equal = 1;
	int onematch;
	sctp_faddr_t *fp1, *fp2;

	for (fp1 = a1; fp1; fp1 = fp1->sf_next) {
		onematch = 0;
		for (fp2 = a2; fp2; fp2 = fp2->sf_next) {
			if (IN6_ARE_ADDR_EQUAL(&fp1->sf_faddr,
			    &fp2->sf_faddr)) {
				overlap++;
				onematch = 1;
				break;
			}
			if (!onematch) {
				equal = 0;
			}
		}
		na1++;
	}

	if (equal) {
		return (SCTP_ADDR_EQUAL);
	}
	if (overlap == na1) {
		return (SCTP_ADDR_SUBSET);
	}
	if (overlap) {
		return (SCTP_ADDR_OVERLAP);
	}
	return (SCTP_ADDR_DISJOINT);
}

/*
 * Returns 0 on success, ENOMEM on memory allocation failure, EHOSTUNREACH
 * if the connection credentials fail remote host accreditation or
 * if the new destination does not support the previously established
 * connection security label. If sleep is true, this function should
 * never fail for a memory allocation failure. The boolean parameter
 * "first" decides whether the newly created faddr structure should be
 * added at the beginning of the list or at the end.
 *
 * Note: caller must hold conn fanout lock.
 */
int
sctp_add_faddr(sctp_t *sctp, in6_addr_t *addr, int sleep, boolean_t first)
{
	sctp_faddr_t	*faddr;
	mblk_t		*timer_mp;
	int		err;
	conn_t		*connp = sctp->sctp_connp;

	if (is_system_labeled()) {
		ip_xmit_attr_t	*ixa = connp->conn_ixa;
		ts_label_t	*effective_tsl = NULL;

		ASSERT(ixa->ixa_tsl != NULL);

		/*
		 * Verify the destination is allowed to receive packets
		 * at the security label of the connection we are initiating.
		 *
		 * tsol_check_dest() will create a new effective label for
		 * this connection with a modified label or label flags only
		 * if there are changes from the original label.
		 *
		 * Accept whatever label we get if this is the first
		 * destination address for this connection. The security
		 * label and label flags must match any previuous settings
		 * for all subsequent destination addresses.
		 */
		if (IN6_IS_ADDR_V4MAPPED(addr)) {
			uint32_t dst;
			IN6_V4MAPPED_TO_IPADDR(addr, dst);
			err = tsol_check_dest(ixa->ixa_tsl,
			    &dst, IPV4_VERSION, connp->conn_mac_mode,
			    connp->conn_zone_is_global, &effective_tsl);
		} else {
			err = tsol_check_dest(ixa->ixa_tsl,
			    addr, IPV6_VERSION, connp->conn_mac_mode,
			    connp->conn_zone_is_global, &effective_tsl);
		}
		if (err != 0)
			return (err);

		if (sctp->sctp_faddrs == NULL && effective_tsl != NULL) {
			ip_xmit_attr_replace_tsl(ixa, effective_tsl);
		} else if (effective_tsl != NULL) {
			label_rele(effective_tsl);
			return (EHOSTUNREACH);
		}
	}

	if ((faddr = kmem_cache_alloc(sctp_kmem_faddr_cache, sleep)) == NULL)
		return (ENOMEM);
	bzero(faddr, sizeof (*faddr));
	timer_mp = sctp_timer_alloc((sctp), sctp_rexmit_timer, sleep);
	if (timer_mp == NULL) {
		kmem_cache_free(sctp_kmem_faddr_cache, faddr);
		return (ENOMEM);
	}
	((sctpt_t *)(timer_mp->b_rptr))->sctpt_faddr = faddr;

	/* Start with any options set on the conn */
	faddr->sf_ixa = conn_get_ixa_exclusive(connp);
	if (faddr->sf_ixa == NULL) {
		freemsg(timer_mp);
		kmem_cache_free(sctp_kmem_faddr_cache, faddr);
		return (ENOMEM);
	}
	faddr->sf_ixa->ixa_notify_cookie = connp->conn_sctp;

	sctp_init_faddr(sctp, faddr, addr, timer_mp);
	ASSERT(faddr->sf_ixa->ixa_cred != NULL);

	/* ip_attr_connect didn't allow broadcats/multicast dest */
	ASSERT(faddr->sf_next == NULL);

	if (sctp->sctp_faddrs == NULL) {
		ASSERT(sctp->sctp_lastfaddr == NULL);
		/* only element on list; first and last are same */
		sctp->sctp_faddrs = sctp->sctp_lastfaddr = faddr;
	} else if (first) {
		ASSERT(sctp->sctp_lastfaddr != NULL);
		faddr->sf_next = sctp->sctp_faddrs;
		sctp->sctp_faddrs = faddr;
	} else {
		sctp->sctp_lastfaddr->sf_next = faddr;
		sctp->sctp_lastfaddr = faddr;
	}
	sctp->sctp_nfaddrs++;

	return (0);
}

sctp_faddr_t *
sctp_lookup_faddr(sctp_t *sctp, in6_addr_t *addr)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next) {
		if (IN6_ARE_ADDR_EQUAL(&fp->sf_faddr, addr))
			break;
	}

	return (fp);
}

sctp_faddr_t *
sctp_lookup_faddr_nosctp(sctp_faddr_t *fp, in6_addr_t *addr)
{
	for (; fp; fp = fp->sf_next) {
		if (IN6_ARE_ADDR_EQUAL(&fp->sf_faddr, addr)) {
			break;
		}
	}

	return (fp);
}

/*
 * To change the currently used peer address to the specified one.
 */
void
sctp_set_faddr_current(sctp_t *sctp, sctp_faddr_t *fp)
{
	/* Now setup the composite header. */
	if (fp->sf_isv4) {
		IN6_V4MAPPED_TO_IPADDR(&fp->sf_faddr,
		    sctp->sctp_ipha->ipha_dst);
		IN6_V4MAPPED_TO_IPADDR(&fp->sf_saddr,
		    sctp->sctp_ipha->ipha_src);
		/* update don't fragment bit */
		if (fp->sf_df) {
			sctp->sctp_ipha->ipha_fragment_offset_and_flags =
			    htons(IPH_DF);
		} else {
			sctp->sctp_ipha->ipha_fragment_offset_and_flags = 0;
		}
	} else {
		sctp->sctp_ip6h->ip6_dst = fp->sf_faddr;
		sctp->sctp_ip6h->ip6_src = fp->sf_saddr;
	}

	sctp->sctp_current = fp;
	sctp->sctp_mss = fp->sf_pmss;

	/* Update the uppper layer for the change. */
	if (!SCTP_IS_DETACHED(sctp))
		sctp_set_ulp_prop(sctp);
}

void
sctp_redo_faddr_srcs(sctp_t *sctp)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next) {
		sctp_get_dest(sctp, fp);
	}
}

void
sctp_faddr_alive(sctp_t *sctp, sctp_faddr_t *fp)
{
	int64_t now = LBOLT_FASTPATH64;

	/*
	 * If we are under memory pressure, we abort association waiting
	 * in zero window probing state for too long.  We do this by not
	 * resetting sctp_strikes.  So if sctp_zero_win_probe continues
	 * while under memory pressure, this association will eventually
	 * time out.
	 */
	if (!sctp->sctp_zero_win_probe || !sctp->sctp_sctps->sctps_reclaim) {
		sctp->sctp_strikes = 0;
	}
	fp->sf_strikes = 0;
	fp->sf_lastactive = now;
	fp->sf_hb_expiry = now + SET_HB_INTVL(fp);
	fp->sf_hb_pending = B_FALSE;
	if (fp->sf_state != SCTP_FADDRS_ALIVE) {
		fp->sf_state = SCTP_FADDRS_ALIVE;
		sctp_intf_event(sctp, fp->sf_faddr, SCTP_ADDR_AVAILABLE, 0);
		/* Should have a full IRE now */
		sctp_get_dest(sctp, fp);

		/*
		 * If this is the primary, switch back to it now.  And
		 * we probably want to reset the source addr used to reach
		 * it.
		 * Note that if we didn't find a source in sctp_get_dest
		 * then we'd be unreachable at this point in time.
		 */
		if (fp == sctp->sctp_primary &&
		    fp->sf_state != SCTP_FADDRS_UNREACH) {
			sctp_set_faddr_current(sctp, fp);
			return;
		}
	}
}

/*
 * Return B_TRUE if there is still an active peer address with zero strikes;
 * otherwise rturn B_FALSE.
 */
boolean_t
sctp_is_a_faddr_clean(sctp_t *sctp)
{
	sctp_faddr_t *fp;

	for (fp = sctp->sctp_faddrs; fp; fp = fp->sf_next) {
		if (fp->sf_state == SCTP_FADDRS_ALIVE && fp->sf_strikes == 0) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Returns 0 if there is at leave one other active faddr, -1 if there
 * are none. If there are none left, faddr_dead() will start killing the
 * association.
 * If the downed faddr was the current faddr, a new current faddr
 * will be chosen.
 */
int
sctp_faddr_dead(sctp_t *sctp, sctp_faddr_t *fp, int newstate)
{
	sctp_faddr_t *ofp;
	sctp_stack_t *sctps = sctp->sctp_sctps;

	if (fp->sf_state == SCTP_FADDRS_ALIVE) {
		sctp_intf_event(sctp, fp->sf_faddr, SCTP_ADDR_UNREACHABLE, 0);
	}
	fp->sf_state = newstate;

	dprint(1, ("sctp_faddr_dead: %x:%x:%x:%x down (state=%d)\n",
	    SCTP_PRINTADDR(fp->sf_faddr), newstate));

	if (fp == sctp->sctp_current) {
		/* Current faddr down; need to switch it */
		sctp->sctp_current = NULL;
	}

	/* Find next alive faddr */
	ofp = fp;
	for (fp = fp->sf_next; fp != NULL; fp = fp->sf_next) {
		if (fp->sf_state == SCTP_FADDRS_ALIVE) {
			break;
		}
	}

	if (fp == NULL) {
		/* Continue from beginning of list */
		for (fp = sctp->sctp_faddrs; fp != ofp; fp = fp->sf_next) {
			if (fp->sf_state == SCTP_FADDRS_ALIVE) {
				break;
			}
		}
	}

	/*
	 * Find a new fp, so if the current faddr is dead, use the new fp
	 * as the current one.
	 */
	if (fp != ofp) {
		if (sctp->sctp_current == NULL) {
			dprint(1, ("sctp_faddr_dead: failover->%x:%x:%x:%x\n",
			    SCTP_PRINTADDR(fp->sf_faddr)));
			/*
			 * Note that we don't need to reset the source addr
			 * of the new fp.
			 */
			sctp_set_faddr_current(sctp, fp);
		}
		return (0);
	}


	/* All faddrs are down; kill the association */
	dprint(1, ("sctp_faddr_dead: all faddrs down, killing assoc\n"));
	SCTPS_BUMP_MIB(sctps, sctpAborted);
	sctp_assoc_event(sctp, sctp->sctp_state < SCTPS_ESTABLISHED ?
	    SCTP_CANT_STR_ASSOC : SCTP_COMM_LOST, 0, NULL);
	sctp_clean_death(sctp, sctp->sctp_client_errno ?
	    sctp->sctp_client_errno : ETIMEDOUT);

	return (-1);
}

sctp_faddr_t *
sctp_rotate_faddr(sctp_t *sctp, sctp_faddr_t *ofp)
{
	sctp_faddr_t *nfp = NULL;
	sctp_faddr_t *saved_fp = NULL;
	int min_strikes;

	if (ofp == NULL) {
		ofp = sctp->sctp_current;
	}
	/* Nothing to do */
	if (sctp->sctp_nfaddrs < 2)
		return (ofp);

	/*
	 * Find the next live peer address with zero strikes. In case
	 * there is none, find the one with the lowest number of strikes.
	 */
	min_strikes = ofp->sf_strikes;
	nfp = ofp->sf_next;
	while (nfp != ofp) {
		/* If reached end of list, continue scan from the head */
		if (nfp == NULL) {
			nfp = sctp->sctp_faddrs;
			continue;
		}
		if (nfp->sf_state == SCTP_FADDRS_ALIVE) {
			if (nfp->sf_strikes == 0)
				break;
			if (nfp->sf_strikes < min_strikes) {
				min_strikes = nfp->sf_strikes;
				saved_fp = nfp;
			}
		}
		nfp = nfp->sf_next;
	}
	/* If reached the old address, there is no zero strike path */
	if (nfp == ofp)
		nfp = NULL;

	/*
	 * If there is a peer address with zero strikes  we use that, if not
	 * return a peer address with fewer strikes than the one last used,
	 * if neither exist we may as well stay with the old one.
	 */
	if (nfp != NULL)
		return (nfp);
	if (saved_fp != NULL)
		return (saved_fp);
	return (ofp);
}

void
sctp_unlink_faddr(sctp_t *sctp, sctp_faddr_t *fp)
{
	sctp_faddr_t *fpp;

	fpp = NULL;

	if (!sctp->sctp_faddrs) {
		return;
	}

	if (fp->sf_timer_mp != NULL) {
		sctp_timer_free(fp->sf_timer_mp);
		fp->sf_timer_mp = NULL;
		fp->sf_timer_running = 0;
	}
	if (fp->sf_rc_timer_mp != NULL) {
		sctp_timer_free(fp->sf_rc_timer_mp);
		fp->sf_rc_timer_mp = NULL;
		fp->sf_rc_timer_running = 0;
	}
	if (fp->sf_ixa != NULL) {
		ixa_refrele(fp->sf_ixa);
		fp->sf_ixa = NULL;
	}

	if (fp == sctp->sctp_faddrs) {
		goto gotit;
	}

	for (fpp = sctp->sctp_faddrs; fpp->sf_next != fp; fpp = fpp->sf_next)
		;

gotit:
	ASSERT(sctp->sctp_conn_tfp != NULL);
	mutex_enter(&sctp->sctp_conn_tfp->tf_lock);
	if (fp == sctp->sctp_faddrs) {
		sctp->sctp_faddrs = fp->sf_next;
	} else {
		fpp->sf_next = fp->sf_next;
	}
	mutex_exit(&sctp->sctp_conn_tfp->tf_lock);
	kmem_cache_free(sctp_kmem_faddr_cache, fp);
	sctp->sctp_nfaddrs--;
}

void
sctp_zap_faddrs(sctp_t *sctp, int caller_holds_lock)
{
	sctp_faddr_t *fp, *fpn;

	if (sctp->sctp_faddrs == NULL) {
		ASSERT(sctp->sctp_lastfaddr == NULL);
		return;
	}

	ASSERT(sctp->sctp_lastfaddr != NULL);
	sctp->sctp_lastfaddr = NULL;
	sctp->sctp_current = NULL;
	sctp->sctp_primary = NULL;

	sctp_free_faddr_timers(sctp);

	if (sctp->sctp_conn_tfp != NULL && !caller_holds_lock) {
		/* in conn fanout; need to hold lock */
		mutex_enter(&sctp->sctp_conn_tfp->tf_lock);
	}

	for (fp = sctp->sctp_faddrs; fp; fp = fpn) {
		fpn = fp->sf_next;
		if (fp->sf_ixa != NULL) {
			ixa_refrele(fp->sf_ixa);
			fp->sf_ixa = NULL;
		}
		kmem_cache_free(sctp_kmem_faddr_cache, fp);
		sctp->sctp_nfaddrs--;
	}

	sctp->sctp_faddrs = NULL;
	ASSERT(sctp->sctp_nfaddrs == 0);
	if (sctp->sctp_conn_tfp != NULL && !caller_holds_lock) {
		mutex_exit(&sctp->sctp_conn_tfp->tf_lock);
	}

}

void
sctp_zap_addrs(sctp_t *sctp)
{
	sctp_zap_faddrs(sctp, 0);
	sctp_free_saddrs(sctp);
}

/*
 * Build two SCTP header templates; one for IPv4 and one for IPv6.
 * Store them in sctp_iphc and sctp_iphc6 respectively (and related fields).
 * There are no IP addresses in the templates, but the port numbers and
 * verifier are field in from the conn_t and sctp_t.
 *
 * Returns failure if can't allocate memory, or if there is a problem
 * with a routing header/option.
 *
 * We allocate space for the minimum sctp header (sctp_hdr_t).
 *
 * We massage an routing option/header. There is no checksum implication
 * for a routing header for sctp.
 *
 * Caller needs to update conn_wroff if desired.
 *
 * TSol notes: This assumes that a SCTP association has a single peer label
 * since we only track a single pair of ipp_label_v4/v6 and not a separate one
 * for each faddr.
 */
int
sctp_build_hdrs(sctp_t *sctp, int sleep)
{
	conn_t		*connp = sctp->sctp_connp;
	ip_pkt_t	*ipp = &connp->conn_xmit_ipp;
	uint_t		ip_hdr_length;
	uchar_t		*hdrs;
	uint_t		hdrs_len;
	uint_t		ulp_hdr_length = sizeof (sctp_hdr_t);
	ipha_t		*ipha;
	ip6_t		*ip6h;
	sctp_hdr_t	*sctph;
	in6_addr_t	v6src, v6dst;
	ipaddr_t	v4src, v4dst;

	v4src = connp->conn_saddr_v4;
	v4dst = connp->conn_faddr_v4;
	v6src = connp->conn_saddr_v6;
	v6dst = connp->conn_faddr_v6;

	/* First do IPv4 header */
	ip_hdr_length = ip_total_hdrs_len_v4(ipp);

	/* In case of TX label and IP options it can be too much */
	if (ip_hdr_length > IP_MAX_HDR_LENGTH) {
		/* Preserves existing TX errno for this */
		return (EHOSTUNREACH);
	}
	hdrs_len = ip_hdr_length + ulp_hdr_length;
	ASSERT(hdrs_len != 0);

	if (hdrs_len != sctp->sctp_iphc_len) {
		/* Allocate new before we free any old */
		hdrs = kmem_alloc(hdrs_len, sleep);
		if (hdrs == NULL)
			return (ENOMEM);

		if (sctp->sctp_iphc != NULL)
			kmem_free(sctp->sctp_iphc, sctp->sctp_iphc_len);
		sctp->sctp_iphc = hdrs;
		sctp->sctp_iphc_len = hdrs_len;
	} else {
		hdrs = sctp->sctp_iphc;
	}
	sctp->sctp_hdr_len = sctp->sctp_iphc_len;
	sctp->sctp_ip_hdr_len = ip_hdr_length;

	sctph = (sctp_hdr_t *)(hdrs + ip_hdr_length);
	sctp->sctp_sctph = sctph;
	sctph->sh_sport = connp->conn_lport;
	sctph->sh_dport = connp->conn_fport;
	sctph->sh_verf = sctp->sctp_fvtag;
	sctph->sh_chksum = 0;

	ipha = (ipha_t *)hdrs;
	sctp->sctp_ipha = ipha;

	ipha->ipha_src = v4src;
	ipha->ipha_dst = v4dst;
	ip_build_hdrs_v4(hdrs, ip_hdr_length, ipp, connp->conn_proto);
	ipha->ipha_length = htons(hdrs_len);
	ipha->ipha_fragment_offset_and_flags = 0;

	if (ipp->ipp_fields & IPPF_IPV4_OPTIONS)
		(void) ip_massage_options(ipha, connp->conn_netstack);

	/* Now IPv6 */
	ip_hdr_length = ip_total_hdrs_len_v6(ipp);
	hdrs_len = ip_hdr_length + ulp_hdr_length;
	ASSERT(hdrs_len != 0);

	if (hdrs_len != sctp->sctp_iphc6_len) {
		/* Allocate new before we free any old */
		hdrs = kmem_alloc(hdrs_len, sleep);
		if (hdrs == NULL)
			return (ENOMEM);

		if (sctp->sctp_iphc6 != NULL)
			kmem_free(sctp->sctp_iphc6, sctp->sctp_iphc6_len);
		sctp->sctp_iphc6 = hdrs;
		sctp->sctp_iphc6_len = hdrs_len;
	} else {
		hdrs = sctp->sctp_iphc6;
	}
	sctp->sctp_hdr6_len = sctp->sctp_iphc6_len;
	sctp->sctp_ip_hdr6_len = ip_hdr_length;

	sctph = (sctp_hdr_t *)(hdrs + ip_hdr_length);
	sctp->sctp_sctph6 = sctph;
	sctph->sh_sport = connp->conn_lport;
	sctph->sh_dport = connp->conn_fport;
	sctph->sh_verf = sctp->sctp_fvtag;
	sctph->sh_chksum = 0;

	ip6h = (ip6_t *)hdrs;
	sctp->sctp_ip6h = ip6h;

	ip6h->ip6_src = v6src;
	ip6h->ip6_dst = v6dst;
	ip_build_hdrs_v6(hdrs, ip_hdr_length, ipp, connp->conn_proto,
	    connp->conn_flowinfo);
	ip6h->ip6_plen = htons(hdrs_len - IPV6_HDR_LEN);

	if (ipp->ipp_fields & IPPF_RTHDR) {
		uint8_t		*end;
		ip6_rthdr_t	*rth;

		end = (uint8_t *)ip6h + ip_hdr_length;
		rth = ip_find_rthdr_v6(ip6h, end);
		if (rth != NULL) {
			(void) ip_massage_options_v6(ip6h, rth,
			    connp->conn_netstack);
		}

		/*
		 * Verify that the first hop isn't a mapped address.
		 * Routers along the path need to do this verification
		 * for subsequent hops.
		 */
		if (IN6_IS_ADDR_V4MAPPED(&ip6h->ip6_dst))
			return (EADDRNOTAVAIL);
	}
	return (0);
}

static int
sctp_v4_label(sctp_t *sctp, sctp_faddr_t *fp)
{
	conn_t *connp = sctp->sctp_connp;

	ASSERT(fp->sf_ixa->ixa_flags & IXAF_IS_IPV4);
	return (conn_update_label(connp, fp->sf_ixa, &fp->sf_faddr,
	    &connp->conn_xmit_ipp));
}

static int
sctp_v6_label(sctp_t *sctp, sctp_faddr_t *fp)
{
	conn_t *connp = sctp->sctp_connp;

	ASSERT(!(fp->sf_ixa->ixa_flags & IXAF_IS_IPV4));
	return (conn_update_label(connp, fp->sf_ixa, &fp->sf_faddr,
	    &connp->conn_xmit_ipp));
}

/*
 * XXX implement more sophisticated logic
 *
 * Tsol note: We have already verified the addresses using tsol_check_dest
 * in sctp_add_faddr, thus no need to redo that here.
 * We do setup ipp_label_v4 and ipp_label_v6 based on which addresses
 * we have.
 */
int
sctp_set_hdraddrs(sctp_t *sctp)
{
	sctp_faddr_t *fp;
	int gotv4 = 0;
	int gotv6 = 0;
	conn_t *connp = sctp->sctp_connp;

	ASSERT(sctp->sctp_faddrs != NULL);
	ASSERT(sctp->sctp_nsaddrs > 0);

	/* Set up using the primary first */
	connp->conn_faddr_v6 = sctp->sctp_primary->sf_faddr;
	/* saddr may be unspec; make_mp() will handle this */
	connp->conn_saddr_v6 = sctp->sctp_primary->sf_saddr;
	connp->conn_laddr_v6 = connp->conn_saddr_v6;
	if (IN6_IS_ADDR_V4MAPPED(&sctp->sctp_primary->sf_faddr)) {
		if (!is_system_labeled() ||
		    sctp_v4_label(sctp, sctp->sctp_primary) == 0) {
			gotv4 = 1;
			if (connp->conn_family == AF_INET) {
				goto done;
			}
		}
	} else {
		if (!is_system_labeled() ||
		    sctp_v6_label(sctp, sctp->sctp_primary) == 0) {
			gotv6 = 1;
		}
	}

	for (fp = sctp->sctp_faddrs; fp; fp = fp->sf_next) {
		if (!gotv4 && IN6_IS_ADDR_V4MAPPED(&fp->sf_faddr)) {
			if (!is_system_labeled() ||
			    sctp_v4_label(sctp, fp) == 0) {
				gotv4 = 1;
				if (connp->conn_family == AF_INET || gotv6) {
					break;
				}
			}
		} else if (!gotv6 && !IN6_IS_ADDR_V4MAPPED(&fp->sf_faddr)) {
			if (!is_system_labeled() ||
			    sctp_v6_label(sctp, fp) == 0) {
				gotv6 = 1;
				if (gotv4)
					break;
			}
		}
	}

done:
	if (!gotv4 && !gotv6)
		return (EACCES);

	return (0);
}

/*
 * got_errchunk is set B_TRUE only if called from validate_init_params(), when
 * an ERROR chunk is already prepended the size of which needs updating for
 * additional unrecognized parameters. Other callers either prepend the ERROR
 * chunk with the correct size after calling this function, or they are calling
 * to add an invalid parameter to an INIT_ACK chunk, in that case no ERROR chunk
 * exists, the CAUSE blocks go into the INIT_ACK directly.
 *
 * *errmp will be non-NULL both when adding an additional CAUSE block to an
 * existing prepended COOKIE ERROR chunk (processing params of an INIT_ACK),
 * and when adding unrecognized parameters after the first, to an INIT_ACK
 * (processing params of an INIT chunk).
 */
void
sctp_add_unrec_parm(sctp_parm_hdr_t *uph, mblk_t **errmp,
    boolean_t got_errchunk)
{
	mblk_t *mp;
	sctp_parm_hdr_t *ph;
	size_t len;
	int pad;
	sctp_chunk_hdr_t *ecp;

	len = sizeof (*ph) + ntohs(uph->sph_len);
	if ((pad = len % SCTP_ALIGN) != 0) {
		pad = SCTP_ALIGN - pad;
		len += pad;
	}
	mp = allocb(len, BPRI_MED);
	if (mp == NULL) {
		return;
	}

	ph = (sctp_parm_hdr_t *)(mp->b_rptr);
	ph->sph_type = htons(PARM_UNRECOGNIZED);
	ph->sph_len = htons(len - pad);

	/* copy in the unrecognized parameter */
	bcopy(uph, ph + 1, ntohs(uph->sph_len));

	if (pad != 0)
		bzero((mp->b_rptr + len - pad), pad);

	mp->b_wptr = mp->b_rptr + len;
	if (*errmp != NULL) {
		/*
		 * Update total length if an ERROR chunk, then link
		 * this CAUSE block to the possible chain of CAUSE
		 * blocks attached to the ERROR chunk or INIT_ACK
		 * being created.
		 */
		if (got_errchunk) {
			/* ERROR chunk already prepended */
			ecp = (sctp_chunk_hdr_t *)((*errmp)->b_rptr);
			ecp->sch_len = htons(ntohs(ecp->sch_len) + len);
		}
		linkb(*errmp, mp);
	} else {
		*errmp = mp;
	}
}

/*
 * o Bounds checking
 * o Updates remaining
 * o Checks alignment
 */
sctp_parm_hdr_t *
sctp_next_parm(sctp_parm_hdr_t *current, ssize_t *remaining)
{
	int pad;
	uint16_t len;

	len = ntohs(current->sph_len);
	*remaining -= len;
	if (*remaining < sizeof (*current) || len < sizeof (*current)) {
		return (NULL);
	}
	if ((pad = len & (SCTP_ALIGN - 1)) != 0) {
		pad = SCTP_ALIGN - pad;
		*remaining -= pad;
	}
	/*LINTED pointer cast may result in improper alignment*/
	current = (sctp_parm_hdr_t *)((char *)current + len + pad);
	return (current);
}

/*
 * Sets the address parameters given in the INIT chunk into sctp's
 * faddrs; if psctp is non-NULL, copies psctp's saddrs. If there are
 * no address parameters in the INIT chunk, a single faddr is created
 * from the ip hdr at the beginning of pkt.
 * If there already are existing addresses hanging from sctp, merge
 * them in, if the old info contains addresses which are not present
 * in this new info, get rid of them, and clean the pointers if there's
 * messages which have this as their target address.
 *
 * We also re-adjust the source address list here since the list may
 * contain more than what is actually part of the association. If
 * we get here from sctp_send_cookie_echo(), we are on the active
 * side and psctp will be NULL and ich will be the INIT-ACK chunk.
 * If we get here from sctp_accept_comm(), ich will be the INIT chunk
 * and psctp will the listening endpoint.
 *
 * INIT processing: When processing the INIT we inherit the src address
 * list from the listener. For a loopback or linklocal association, we
 * delete the list and just take the address from the IP header (since
 * that's how we created the INIT-ACK). Additionally, for loopback we
 * ignore the address params in the INIT. For determining which address
 * types were sent in the INIT-ACK we follow the same logic as in
 * creating the INIT-ACK. We delete addresses of the type that are not
 * supported by the peer.
 *
 * INIT-ACK processing: When processing the INIT-ACK since we had not
 * included addr params for loopback or linklocal addresses when creating
 * the INIT, we just use the address from the IP header. Further, for
 * loopback we ignore the addr param list. We mark addresses of the
 * type not supported by the peer as unconfirmed.
 *
 * In case of INIT processing we look for supported address types in the
 * supported address param, if present. In both cases the address type in
 * the IP header is supported as well as types for addresses in the param
 * list, if any.
 *
 * Once we have the supported address types sctp_check_saddr() runs through
 * the source address list and deletes or marks as unconfirmed address of
 * types not supported by the peer.
 *
 * Returns 0 on success, sys errno on failure
 */
int
sctp_get_addrparams(sctp_t *sctp, sctp_t *psctp, mblk_t *pkt,
    sctp_chunk_hdr_t *ich, uint_t *sctp_options)
{
	sctp_init_chunk_t	*init;
	ipha_t			*iph;
	ip6_t			*ip6h;
	in6_addr_t		hdrsaddr[1];
	in6_addr_t		hdrdaddr[1];
	sctp_parm_hdr_t		*ph;
	ssize_t			remaining;
	int			isv4;
	int			err;
	sctp_faddr_t		*fp;
	int			supp_af = 0;
	boolean_t		check_saddr = B_TRUE;
	in6_addr_t		curaddr;
	sctp_stack_t		*sctps = sctp->sctp_sctps;
	conn_t			*connp = sctp->sctp_connp;

	if (sctp_options != NULL)
		*sctp_options = 0;

	/* extract the address from the IP header */
	isv4 = (IPH_HDR_VERSION(pkt->b_rptr) == IPV4_VERSION);
	if (isv4) {
		iph = (ipha_t *)pkt->b_rptr;
		IN6_IPADDR_TO_V4MAPPED(iph->ipha_src, hdrsaddr);
		IN6_IPADDR_TO_V4MAPPED(iph->ipha_dst, hdrdaddr);
		supp_af |= PARM_SUPP_V4;
	} else {
		ip6h = (ip6_t *)pkt->b_rptr;
		hdrsaddr[0] = ip6h->ip6_src;
		hdrdaddr[0] = ip6h->ip6_dst;
		supp_af |= PARM_SUPP_V6;
	}

	/*
	 * Unfortunately, we can't delay this because adding an faddr
	 * looks for the presence of the source address (from the ire
	 * for the faddr) in the source address list. We could have
	 * delayed this if, say, this was a loopback/linklocal connection.
	 * Now, we just end up nuking this list and taking the addr from
	 * the IP header for loopback/linklocal.
	 */
	if (psctp != NULL && psctp->sctp_nsaddrs > 0) {
		ASSERT(sctp->sctp_nsaddrs == 0);

		err = sctp_dup_saddrs(psctp, sctp, KM_NOSLEEP);
		if (err != 0)
			return (err);
	}
	/*
	 * We will add the faddr before parsing the address list as this
	 * might be a loopback connection and we would not have to
	 * go through the list.
	 *
	 * Make sure the header's addr is in the list
	 */
	fp = sctp_lookup_faddr(sctp, hdrsaddr);
	if (fp == NULL) {
		/* not included; add it now */
		err = sctp_add_faddr(sctp, hdrsaddr, KM_NOSLEEP, B_TRUE);
		if (err != 0)
			return (err);

		/* sctp_faddrs will be the hdr addr */
		fp = sctp->sctp_faddrs;
	}
	/* make the header addr the primary */

	if (cl_sctp_assoc_change != NULL && psctp == NULL)
		curaddr = sctp->sctp_current->sf_faddr;

	sctp->sctp_primary = fp;
	sctp->sctp_current = fp;
	sctp->sctp_mss = fp->sf_pmss;

	/* For loopback connections & linklocal get address from the header */
	if (sctp->sctp_loopback || sctp->sctp_linklocal) {
		if (sctp->sctp_nsaddrs != 0)
			sctp_free_saddrs(sctp);
		if ((err = sctp_saddr_add_addr(sctp, hdrdaddr, 0)) != 0)
			return (err);
		/* For loopback ignore address list */
		if (sctp->sctp_loopback)
			return (0);
		check_saddr = B_FALSE;
	}

	/* Walk the params in the INIT [ACK], pulling out addr params */
	remaining = ntohs(ich->sch_len) - sizeof (*ich) -
	    sizeof (sctp_init_chunk_t);
	if (remaining < sizeof (*ph)) {
		if (check_saddr) {
			sctp_check_saddr(sctp, supp_af, psctp == NULL ?
			    B_FALSE : B_TRUE, hdrdaddr);
		}
		ASSERT(sctp_saddr_lookup(sctp, hdrdaddr, 0) != NULL);
		return (0);
	}

	init = (sctp_init_chunk_t *)(ich + 1);
	ph = (sctp_parm_hdr_t *)(init + 1);

	/* params will have already been byteordered when validating */
	while (ph != NULL) {
		if (ph->sph_type == htons(PARM_SUPP_ADDRS)) {
			int		plen;
			uint16_t	*p;
			uint16_t	addrtype;

			ASSERT(psctp != NULL);
			plen = ntohs(ph->sph_len);
			p = (uint16_t *)(ph + 1);
			while (plen > 0) {
				addrtype = ntohs(*p);
				switch (addrtype) {
					case PARM_ADDR6:
						supp_af |= PARM_SUPP_V6;
						break;
					case PARM_ADDR4:
						supp_af |= PARM_SUPP_V4;
						break;
					default:
						break;
				}
				p++;
				plen -= sizeof (*p);
			}
		} else if (ph->sph_type == htons(PARM_ADDR4)) {
			if (remaining >= PARM_ADDR4_LEN) {
				in6_addr_t addr;
				ipaddr_t ta;

				supp_af |= PARM_SUPP_V4;
				/*
				 * Screen out broad/multicasts & loopback.
				 * If the endpoint only accepts v6 address,
				 * go to the next one.
				 *
				 * Subnet broadcast check is done in
				 * sctp_add_faddr().  If the address is
				 * a broadcast address, it won't be added.
				 */
				bcopy(ph + 1, &ta, sizeof (ta));
				if (ta == 0 ||
				    ta == INADDR_BROADCAST ||
				    ta == htonl(INADDR_LOOPBACK) ||
				    CLASSD(ta) || connp->conn_ipv6_v6only) {
					goto next;
				}
				IN6_INADDR_TO_V4MAPPED((struct in_addr *)
				    (ph + 1), &addr);

				/* Check for duplicate. */
				if (sctp_lookup_faddr(sctp, &addr) != NULL)
					goto next;

				/* OK, add it to the faddr set */
				err = sctp_add_faddr(sctp, &addr, KM_NOSLEEP,
				    B_FALSE);
				/* Something is wrong...  Try the next one. */
				if (err != 0)
					goto next;
			}
		} else if (ph->sph_type == htons(PARM_ADDR6) &&
		    connp->conn_family == AF_INET6) {
			/* An v4 socket should not take v6 addresses. */
			if (remaining >= PARM_ADDR6_LEN) {
				in6_addr_t *addr6;

				supp_af |= PARM_SUPP_V6;
				addr6 = (in6_addr_t *)(ph + 1);
				/*
				 * Screen out link locals, mcast, loopback
				 * and bogus v6 address.
				 */
				if (IN6_IS_ADDR_LINKLOCAL(addr6) ||
				    IN6_IS_ADDR_MULTICAST(addr6) ||
				    IN6_IS_ADDR_LOOPBACK(addr6) ||
				    IN6_IS_ADDR_V4MAPPED(addr6)) {
					goto next;
				}
				/* Check for duplicate. */
				if (sctp_lookup_faddr(sctp, addr6) != NULL)
					goto next;

				err = sctp_add_faddr(sctp,
				    (in6_addr_t *)(ph + 1), KM_NOSLEEP,
				    B_FALSE);
				/* Something is wrong...  Try the next one. */
				if (err != 0)
					goto next;
			}
		} else if (ph->sph_type == htons(PARM_FORWARD_TSN)) {
			if (sctp_options != NULL)
				*sctp_options |= SCTP_PRSCTP_OPTION;
		} /* else; skip */

next:
		ph = sctp_next_parm(ph, &remaining);
	}
	if (check_saddr) {
		sctp_check_saddr(sctp, supp_af, psctp == NULL ? B_FALSE :
		    B_TRUE, hdrdaddr);
	}
	ASSERT(sctp_saddr_lookup(sctp, hdrdaddr, 0) != NULL);
	/*
	 * We have the right address list now, update clustering's
	 * knowledge because when we sent the INIT we had just added
	 * the address the INIT was sent to.
	 */
	if (psctp == NULL && cl_sctp_assoc_change != NULL) {
		uchar_t	*alist;
		size_t	asize;
		uchar_t	*dlist;
		size_t	dsize;

		asize = sizeof (in6_addr_t) * sctp->sctp_nfaddrs;
		alist = kmem_alloc(asize, KM_NOSLEEP);
		if (alist == NULL) {
			SCTP_KSTAT(sctps, sctp_cl_assoc_change);
			return (ENOMEM);
		}
		/*
		 * Just include the address the INIT was sent to in the
		 * delete list and send the entire faddr list. We could
		 * do it differently (i.e include all the addresses in the
		 * add list even if it contains the original address OR
		 * remove the original address from the add list etc.), but
		 * this seems reasonable enough.
		 */
		dsize = sizeof (in6_addr_t);
		dlist = kmem_alloc(dsize, KM_NOSLEEP);
		if (dlist == NULL) {
			kmem_free(alist, asize);
			SCTP_KSTAT(sctps, sctp_cl_assoc_change);
			return (ENOMEM);
		}
		bcopy(&curaddr, dlist, sizeof (curaddr));
		sctp_get_faddr_list(sctp, alist, asize);
		(*cl_sctp_assoc_change)(connp->conn_family, alist, asize,
		    sctp->sctp_nfaddrs, dlist, dsize, 1, SCTP_CL_PADDR,
		    (cl_sctp_handle_t)sctp);
		/* alist and dlist will be freed by the clustering module */
	}
	return (0);
}

/*
 * Returns 0 if the check failed and the restart should be refused,
 * 1 if the check succeeded.
 */
int
sctp_secure_restart_check(mblk_t *pkt, sctp_chunk_hdr_t *ich, uint32_t ports,
    int sleep, sctp_stack_t *sctps, ip_recv_attr_t *ira)
{
	sctp_faddr_t *fp, *fphead = NULL;
	sctp_parm_hdr_t *ph;
	ssize_t remaining;
	int isv4;
	ipha_t *iph;
	ip6_t *ip6h;
	in6_addr_t hdraddr[1];
	int retval = 0;
	sctp_tf_t *tf;
	sctp_t *sctp;
	int compres;
	sctp_init_chunk_t *init;
	int nadded = 0;

	/* extract the address from the IP header */
	isv4 = (IPH_HDR_VERSION(pkt->b_rptr) == IPV4_VERSION);
	if (isv4) {
		iph = (ipha_t *)pkt->b_rptr;
		IN6_IPADDR_TO_V4MAPPED(iph->ipha_src, hdraddr);
	} else {
		ip6h = (ip6_t *)pkt->b_rptr;
		hdraddr[0] = ip6h->ip6_src;
	}

	/* Walk the params in the INIT [ACK], pulling out addr params */
	remaining = ntohs(ich->sch_len) - sizeof (*ich) -
	    sizeof (sctp_init_chunk_t);
	if (remaining < sizeof (*ph)) {
		/* no parameters; restart OK */
		return (1);
	}
	init = (sctp_init_chunk_t *)(ich + 1);
	ph = (sctp_parm_hdr_t *)(init + 1);

	while (ph != NULL) {
		sctp_faddr_t *fpa = NULL;

		/* params will have already been byteordered when validating */
		if (ph->sph_type == htons(PARM_ADDR4)) {
			if (remaining >= PARM_ADDR4_LEN) {
				in6_addr_t addr;
				IN6_INADDR_TO_V4MAPPED((struct in_addr *)
				    (ph + 1), &addr);
				fpa = kmem_cache_alloc(sctp_kmem_faddr_cache,
				    sleep);
				if (fpa == NULL) {
					goto done;
				}
				bzero(fpa, sizeof (*fpa));
				fpa->sf_faddr = addr;
				fpa->sf_next = NULL;
			}
		} else if (ph->sph_type == htons(PARM_ADDR6)) {
			if (remaining >= PARM_ADDR6_LEN) {
				fpa = kmem_cache_alloc(sctp_kmem_faddr_cache,
				    sleep);
				if (fpa == NULL) {
					goto done;
				}
				bzero(fpa, sizeof (*fpa));
				bcopy(ph + 1, &fpa->sf_faddr,
				    sizeof (fpa->sf_faddr));
				fpa->sf_next = NULL;
			}
		}
		/* link in the new addr, if it was an addr param */
		if (fpa != NULL) {
			if (fphead == NULL) {
				fphead = fpa;
			} else {
				fpa->sf_next = fphead;
				fphead = fpa;
			}
		}

		ph = sctp_next_parm(ph, &remaining);
	}

	if (fphead == NULL) {
		/* no addr parameters; restart OK */
		return (1);
	}

	/*
	 * got at least one; make sure the header's addr is
	 * in the list
	 */
	fp = sctp_lookup_faddr_nosctp(fphead, hdraddr);
	if (fp == NULL) {
		/* not included; add it now */
		fp = kmem_cache_alloc(sctp_kmem_faddr_cache, sleep);
		if (fp == NULL) {
			goto done;
		}
		bzero(fp, sizeof (*fp));
		fp->sf_faddr = *hdraddr;
		fp->sf_next = fphead;
		fphead = fp;
	}

	/*
	 * Now, we can finally do the check: For each sctp instance
	 * on the hash line for ports, compare its faddr set against
	 * the new one. If the new one is a strict subset of any
	 * existing sctp's faddrs, the restart is OK. However, if there
	 * is an overlap, this could be an attack, so return failure.
	 * If all sctp's faddrs are disjoint, this is a legitimate new
	 * association.
	 */
	tf = &(sctps->sctps_conn_fanout[SCTP_CONN_HASH(sctps, ports)]);
	mutex_enter(&tf->tf_lock);

	for (sctp = tf->tf_sctp; sctp; sctp = sctp->sctp_conn_hash_next) {
		if (ports != sctp->sctp_connp->conn_ports) {
			continue;
		}
		compres = sctp_compare_faddrsets(fphead, sctp->sctp_faddrs);
		if (compres <= SCTP_ADDR_SUBSET) {
			retval = 1;
			mutex_exit(&tf->tf_lock);
			goto done;
		}
		if (compres == SCTP_ADDR_OVERLAP) {
			dprint(1,
			    ("new assoc from %x:%x:%x:%x overlaps with %p\n",
			    SCTP_PRINTADDR(*hdraddr), (void *)sctp));
			/*
			 * While we still hold the lock, we need to
			 * figure out which addresses have been
			 * added so we can include them in the abort
			 * we will send back. Since these faddrs will
			 * never be used, we overload the rto field
			 * here, setting it to 0 if the address was
			 * not added, 1 if it was added.
			 */
			for (fp = fphead; fp; fp = fp->sf_next) {
				if (sctp_lookup_faddr(sctp, &fp->sf_faddr)) {
					fp->sf_rto = 0;
				} else {
					fp->sf_rto = 1;
					nadded++;
				}
			}
			mutex_exit(&tf->tf_lock);
			goto done;
		}
	}
	mutex_exit(&tf->tf_lock);

	/* All faddrs are disjoint; legit new association */
	retval = 1;

done:
	/* If are attempted adds, send back an abort listing the addrs */
	if (nadded > 0) {
		void *dtail;
		size_t dlen;

		dtail = kmem_alloc(PARM_ADDR6_LEN * nadded, KM_NOSLEEP);
		if (dtail == NULL) {
			goto cleanup;
		}

		ph = dtail;
		dlen = 0;
		for (fp = fphead; fp; fp = fp->sf_next) {
			if (fp->sf_rto == 0) {
				continue;
			}
			if (IN6_IS_ADDR_V4MAPPED(&fp->sf_faddr)) {
				ipaddr_t addr4;

				ph->sph_type = htons(PARM_ADDR4);
				ph->sph_len = htons(PARM_ADDR4_LEN);
				IN6_V4MAPPED_TO_IPADDR(&fp->sf_faddr, addr4);
				ph++;
				bcopy(&addr4, ph, sizeof (addr4));
				ph = (sctp_parm_hdr_t *)
				    ((char *)ph + sizeof (addr4));
				dlen += PARM_ADDR4_LEN;
			} else {
				ph->sph_type = htons(PARM_ADDR6);
				ph->sph_len = htons(PARM_ADDR6_LEN);
				ph++;
				bcopy(&fp->sf_faddr, ph, sizeof (fp->sf_faddr));
				ph = (sctp_parm_hdr_t *)
				    ((char *)ph + sizeof (fp->sf_faddr));
				dlen += PARM_ADDR6_LEN;
			}
		}

		/* Send off the abort */
		sctp_send_abort(sctp, sctp_init2vtag(ich),
		    SCTP_ERR_RESTART_NEW_ADDRS, dtail, dlen, pkt, 0, B_TRUE,
		    ira);

		kmem_free(dtail, PARM_ADDR6_LEN * nadded);
	}

cleanup:
	/* Clean up */
	if (fphead) {
		sctp_faddr_t *fpn;
		for (fp = fphead; fp; fp = fpn) {
			fpn = fp->sf_next;
			if (fp->sf_ixa != NULL) {
				ixa_refrele(fp->sf_ixa);
				fp->sf_ixa = NULL;
			}
			kmem_cache_free(sctp_kmem_faddr_cache, fp);
		}
	}

	return (retval);
}

/*
 * Reset any state related to transmitted chunks.
 */
void
sctp_congest_reset(sctp_t *sctp)
{
	sctp_faddr_t	*fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	mblk_t		*mp;

	for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next) {
		fp->sf_ssthresh = sctps->sctps_initial_mtu;
		SET_CWND(fp, fp->sf_pmss, sctps->sctps_slow_start_initial);
		fp->sf_suna = 0;
		fp->sf_pba = 0;
	}
	/*
	 * Clean up the transmit list as well since we have reset accounting
	 * on all the fps. Send event upstream, if required.
	 */
	while ((mp = sctp->sctp_xmit_head) != NULL) {
		sctp->sctp_xmit_head = mp->b_next;
		mp->b_next = NULL;
		if (sctp->sctp_xmit_head != NULL)
			sctp->sctp_xmit_head->b_prev = NULL;
		sctp_sendfail_event(sctp, mp, 0, B_TRUE);
	}
	sctp->sctp_xmit_head = NULL;
	sctp->sctp_xmit_tail = NULL;
	sctp->sctp_xmit_unacked = NULL;

	sctp->sctp_unacked = 0;
	/*
	 * Any control message as well. We will clean-up this list as well.
	 * This contains any pending ASCONF request that we have queued/sent.
	 * If we do get an ACK we will just drop it. However, given that
	 * we are restarting chances are we aren't going to get any.
	 */
	if (sctp->sctp_cxmit_list != NULL)
		sctp_asconf_free_cxmit(sctp, NULL);
	sctp->sctp_cxmit_list = NULL;
	sctp->sctp_cchunk_pend = 0;

	sctp->sctp_rexmitting = B_FALSE;
	sctp->sctp_rxt_nxttsn = 0;
	sctp->sctp_rxt_maxtsn = 0;

	sctp->sctp_zero_win_probe = B_FALSE;
}

static void
sctp_init_faddr(sctp_t *sctp, sctp_faddr_t *fp, in6_addr_t *addr,
    mblk_t *timer_mp)
{
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	ASSERT(fp->sf_ixa != NULL);

	bcopy(addr, &fp->sf_faddr, sizeof (*addr));
	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		fp->sf_isv4 = 1;
		/* Make sure that sf_pmss is a multiple of SCTP_ALIGN. */
		fp->sf_pmss =
		    (sctps->sctps_initial_mtu - sctp->sctp_hdr_len) &
		    ~(SCTP_ALIGN - 1);
		fp->sf_ixa->ixa_flags |= IXAF_IS_IPV4;
	} else {
		fp->sf_isv4 = 0;
		fp->sf_pmss =
		    (sctps->sctps_initial_mtu - sctp->sctp_hdr6_len) &
		    ~(SCTP_ALIGN - 1);
		fp->sf_ixa->ixa_flags &= ~IXAF_IS_IPV4;
	}
	fp->sf_cwnd = sctps->sctps_slow_start_initial * fp->sf_pmss;
	fp->sf_rto = MIN(sctp->sctp_rto_initial, sctp->sctp_rto_max_init);
	SCTP_MAX_RTO(sctp, fp);
	fp->sf_srtt = -1;
	fp->sf_rtt_updates = 0;
	fp->sf_strikes = 0;
	fp->sf_max_retr = sctp->sctp_pp_max_rxt;
	/* Mark it as not confirmed. */
	fp->sf_state = SCTP_FADDRS_UNCONFIRMED;
	fp->sf_hb_interval = sctp->sctp_hb_interval;
	fp->sf_ssthresh = sctps->sctps_initial_ssthresh;
	fp->sf_suna = 0;
	fp->sf_pba = 0;
	fp->sf_acked = 0;
	fp->sf_lastactive = fp->sf_hb_expiry = ddi_get_lbolt64();
	fp->sf_timer_mp = timer_mp;
	fp->sf_hb_pending = B_FALSE;
	fp->sf_hb_enabled = B_TRUE;
	fp->sf_df = 1;
	fp->sf_pmtu_discovered = 0;
	fp->sf_next = NULL;
	fp->sf_T3expire = 0;
	(void) random_get_pseudo_bytes((uint8_t *)&fp->sf_hb_secret,
	    sizeof (fp->sf_hb_secret));
	fp->sf_rxt_unacked = 0;

	sctp_get_dest(sctp, fp);
}

/*ARGSUSED*/
static int
faddr_constructor(void *buf, void *arg, int flags)
{
	sctp_faddr_t *fp = buf;

	fp->sf_timer_mp = NULL;
	fp->sf_timer_running = 0;

	fp->sf_rc_timer_mp = NULL;
	fp->sf_rc_timer_running = 0;

	return (0);
}

/*ARGSUSED*/
static void
faddr_destructor(void *buf, void *arg)
{
	sctp_faddr_t *fp = buf;

	ASSERT(fp->sf_timer_mp == NULL);
	ASSERT(fp->sf_timer_running == 0);

	ASSERT(fp->sf_rc_timer_mp == NULL);
	ASSERT(fp->sf_rc_timer_running == 0);
}

void
sctp_faddr_init(void)
{
	sctp_kmem_faddr_cache = kmem_cache_create("sctp_faddr_cache",
	    sizeof (sctp_faddr_t), 0, faddr_constructor, faddr_destructor,
	    NULL, NULL, NULL, 0);
}

void
sctp_faddr_fini(void)
{
	kmem_cache_destroy(sctp_kmem_faddr_cache);
}
