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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved
 *
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strlog.h>
#include <sys/strsun.h>
#include <sys/zone.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/xti_inet.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kobj.h>
#include <sys/modctl.h>
#include <sys/atomic.h>
#include <sys/policy.h>
#include <sys/priv.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/sdt.h>
#include <sys/socket.h>
#include <sys/vtrace.h>
#include <sys/isa_defs.h>
#include <sys/mac.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <net/if_dl.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/arp.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>

#include <netinet/igmp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/sctp.h>

#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip6_asp.h>
#include <inet/optcom.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/ip_multi.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/ip_ndp.h>
#include <inet/ip_listutils.h>
#include <netinet/igmp.h>
#include <netinet/ip_mroute.h>
#include <inet/ipp_common.h>

#include <net/pfkeyv2.h>
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <inet/ipdrop.h>
#include <inet/ip_netinfo.h>
#include <inet/ilb_ip.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>

#include <sys/ethernet.h>
#include <net/if_types.h>
#include <sys/cpuvar.h>

#include <ipp/ipp.h>
#include <ipp/ipp_impl.h>
#include <ipp/ipgpc/ipgpc.h>

#include <sys/pattr.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include <inet/sctp/sctp_impl.h>
#include <inet/udp_impl.h>
#include <sys/sunddi.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#include <sys/clock_impl.h>	/* For LBOLT_FASTPATH{,64} */

#ifdef	DEBUG
extern boolean_t skip_sctp_cksum;
#endif

static void	ip_input_local_v6(ire_t *, mblk_t *, ip6_t *, ip_recv_attr_t *);

static void	ip_input_multicast_v6(ire_t *, mblk_t *, ip6_t *,
    ip_recv_attr_t *);

#pragma inline(ip_input_common_v6, ip_input_local_v6, ip_forward_xmit_v6)

/*
 * Direct read side procedure capable of dealing with chains. GLDv3 based
 * drivers call this function directly with mblk chains while STREAMS
 * read side procedure ip_rput() calls this for single packet with ip_ring
 * set to NULL to process one packet at a time.
 *
 * The ill will always be valid if this function is called directly from
 * the driver.
 *
 * If ip_input_v6() is called from GLDv3:
 *
 *   - This must be a non-VLAN IP stream.
 *   - 'mp' is either an untagged or a special priority-tagged packet.
 *   - Any VLAN tag that was in the MAC header has been stripped.
 *
 * If the IP header in packet is not 32-bit aligned, every message in the
 * chain will be aligned before further operations. This is required on SPARC
 * platform.
 */
void
ip_input_v6(ill_t *ill, ill_rx_ring_t *ip_ring, mblk_t *mp_chain,
    struct mac_header_info_s *mhip)
{
	(void) ip_input_common_v6(ill, ip_ring, mp_chain, mhip, NULL, NULL,
	    NULL);
}

/*
 * ip_accept_tcp_v6() - This function is called by the squeue when it retrieves
 * a chain of packets in the poll mode. The packets have gone through the
 * data link processing but not IP processing. For performance and latency
 * reasons, the squeue wants to process the chain in line instead of feeding
 * it back via ip_input path.
 *
 * We set up the ip_recv_attr_t with IRAF_TARGET_SQP to that ip_fanout_v6
 * will pass back any TCP packets matching the target sqp to
 * ip_input_common_v6 using ira_target_sqp_mp. Other packets are handled by
 * ip_input_v6 and ip_fanout_v6 as normal.
 * The TCP packets that match the target squeue are returned to the caller
 * as a b_next chain after each packet has been prepend with an mblk
 * from ip_recv_attr_to_mblk.
 */
mblk_t *
ip_accept_tcp_v6(ill_t *ill, ill_rx_ring_t *ip_ring, squeue_t *target_sqp,
    mblk_t *mp_chain, mblk_t **last, uint_t *cnt)
{
	return (ip_input_common_v6(ill, ip_ring, mp_chain, NULL, target_sqp,
	    last, cnt));
}

/*
 * Used by ip_input_v6 and ip_accept_tcp_v6
 * The last three arguments are only used by ip_accept_tcp_v6, and mhip is
 * only used by ip_input_v6.
 */
mblk_t *
ip_input_common_v6(ill_t *ill, ill_rx_ring_t *ip_ring, mblk_t *mp_chain,
    struct mac_header_info_s *mhip, squeue_t *target_sqp,
    mblk_t **last, uint_t *cnt)
{
	mblk_t		*mp;
	ip6_t		*ip6h;
	ip_recv_attr_t	iras;	/* Receive attributes */
	rtc_t		rtc;
	iaflags_t	chain_flags = 0;	/* Fixed for chain */
	mblk_t 		*ahead = NULL;	/* Accepted head */
	mblk_t		*atail = NULL;	/* Accepted tail */
	uint_t		acnt = 0;	/* Accepted count */

	ASSERT(mp_chain != NULL);
	ASSERT(ill != NULL);

	/* These ones do not change as we loop over packets */
	iras.ira_ill = iras.ira_rill = ill;
	iras.ira_ruifindex = ill->ill_phyint->phyint_ifindex;
	iras.ira_rifindex = iras.ira_ruifindex;
	iras.ira_sqp = NULL;
	iras.ira_ring = ip_ring;
	/* For ECMP and outbound transmit ring selection */
	iras.ira_xmit_hint = ILL_RING_TO_XMIT_HINT(ip_ring);

	iras.ira_target_sqp = target_sqp;
	iras.ira_target_sqp_mp = NULL;
	if (target_sqp != NULL)
		chain_flags |= IRAF_TARGET_SQP;

	/*
	 * We try to have a mhip pointer when possible, but
	 * it might be NULL in some cases. In those cases we
	 * have to assume unicast.
	 */
	iras.ira_mhip = mhip;
	iras.ira_flags = 0;
	if (mhip != NULL) {
		switch (mhip->mhi_dsttype) {
		case MAC_ADDRTYPE_MULTICAST :
			chain_flags |= IRAF_L2DST_MULTICAST;
			break;
		case MAC_ADDRTYPE_BROADCAST :
			chain_flags |= IRAF_L2DST_BROADCAST;
			break;
		}
	}

	/*
	 * Initialize the one-element route cache.
	 *
	 * We do ire caching from one iteration to
	 * another. In the event the packet chain contains
	 * all packets from the same dst, this caching saves
	 * an ire_route_recursive for each of the succeeding
	 * packets in a packet chain.
	 */
	rtc.rtc_ire = NULL;
	rtc.rtc_ip6addr = ipv6_all_zeros;

	/* Loop over b_next */
	for (mp = mp_chain; mp != NULL; mp = mp_chain) {
		mp_chain = mp->b_next;
		mp->b_next = NULL;

		/*
		 * if db_ref > 1 then copymsg and free original. Packet
		 * may be changed and we do not want the other entity
		 * who has a reference to this message to trip over the
		 * changes. This is a blind change because trying to
		 * catch all places that might change the packet is too
		 * difficult.
		 *
		 * This corresponds to the fast path case, where we have
		 * a chain of M_DATA mblks.  We check the db_ref count
		 * of only the 1st data block in the mblk chain. There
		 * doesn't seem to be a reason why a device driver would
		 * send up data with varying db_ref counts in the mblk
		 * chain. In any case the Fast path is a private
		 * interface, and our drivers don't do such a thing.
		 * Given the above assumption, there is no need to walk
		 * down the entire mblk chain (which could have a
		 * potential performance problem)
		 *
		 * The "(DB_REF(mp) > 1)" check was moved from ip_rput()
		 * to here because of exclusive ip stacks and vnics.
		 * Packets transmitted from exclusive stack over vnic
		 * can have db_ref > 1 and when it gets looped back to
		 * another vnic in a different zone, you have ip_input()
		 * getting dblks with db_ref > 1. So if someone
		 * complains of TCP performance under this scenario,
		 * take a serious look here on the impact of copymsg().
		 */
		if (DB_REF(mp) > 1) {
			if ((mp = ip_fix_dbref(mp, &iras)) == NULL)
				continue;
		}

		/*
		 * IP header ptr not aligned?
		 * OR IP header not complete in first mblk
		 */
		ip6h = (ip6_t *)mp->b_rptr;
		if (!OK_32PTR(ip6h) || MBLKL(mp) < IPV6_HDR_LEN) {
			mp = ip_check_and_align_header(mp, IPV6_HDR_LEN, &iras);
			if (mp == NULL)
				continue;
			ip6h = (ip6_t *)mp->b_rptr;
		}

		/* Protect against a mix of Ethertypes and IP versions */
		if (IPH_HDR_VERSION(ip6h) != IPV6_VERSION) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
			ip_drop_input("ipIfStatsInHdrErrors", mp, ill);
			freemsg(mp);
			/* mhip might point into 1st packet in the chain. */
			iras.ira_mhip = NULL;
			continue;
		}

		/*
		 * Check for Martian addrs; we have to explicitly
		 * test for for zero dst since this is also used as
		 * an indication that the rtc is not used.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_dst)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
			ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
			freemsg(mp);
			/* mhip might point into 1st packet in the chain. */
			iras.ira_mhip = NULL;
			continue;
		}
		/*
		 * Keep L2SRC from a previous packet in chain since mhip
		 * might point into an earlier packet in the chain.
		 */
		chain_flags |= (iras.ira_flags & IRAF_L2SRC_SET);

		iras.ira_flags = IRAF_VERIFY_ULP_CKSUM | chain_flags;
		iras.ira_free_flags = 0;
		iras.ira_cred = NULL;
		iras.ira_cpid = NOPID;
		iras.ira_tsl = NULL;
		iras.ira_zoneid = ALL_ZONES;	/* Default for forwarding */

		/*
		 * We must count all incoming packets, even if they end
		 * up being dropped later on. Defer counting bytes until
		 * we have the whole IP header in first mblk.
		 */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInReceives);

		iras.ira_pktlen = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
		UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInOctets,
		    iras.ira_pktlen);

		/*
		 * Call one of:
		 * 	ill_input_full_v6
		 *	ill_input_short_v6
		 * The former is used in the case of TX. See ill_set_inputfn().
		 */
		(*ill->ill_inputfn)(mp, ip6h, &ip6h->ip6_dst, &iras, &rtc);

		/* Any references to clean up? No hold on ira_ill */
		if (iras.ira_flags & (IRAF_IPSEC_SECURE|IRAF_SYSTEM_LABELED))
			ira_cleanup(&iras, B_FALSE);

		if (iras.ira_target_sqp_mp != NULL) {
			/* Better be called from ip_accept_tcp */
			ASSERT(target_sqp != NULL);

			/* Found one packet to accept */
			mp = iras.ira_target_sqp_mp;
			iras.ira_target_sqp_mp = NULL;
			ASSERT(ip_recv_attr_is_mblk(mp));

			if (atail != NULL)
				atail->b_next = mp;
			else
				ahead = mp;
			atail = mp;
			acnt++;
			mp = NULL;
		}
		/* mhip might point into 1st packet in the chain. */
		iras.ira_mhip = NULL;
	}
	/* Any remaining references to the route cache? */
	if (rtc.rtc_ire != NULL) {
		ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&rtc.rtc_ip6addr));
		ire_refrele(rtc.rtc_ire);
	}

	if (ahead != NULL) {
		/* Better be called from ip_accept_tcp */
		ASSERT(target_sqp != NULL);
		*last = atail;
		*cnt = acnt;
		return (ahead);
	}

	return (NULL);
}

/*
 * This input function is used when
 *  - is_system_labeled()
 *
 * Note that for IPv6 CGTP filtering is handled only when receiving fragment
 * headers, and RSVP uses router alert options, thus we don't need anything
 * extra for them.
 */
void
ill_input_full_v6(mblk_t *mp, void *iph_arg, void *nexthop_arg,
    ip_recv_attr_t *ira, rtc_t *rtc)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	in6_addr_t	*nexthop = (in6_addr_t *)nexthop_arg;
	ill_t		*ill = ira->ira_ill;

	ASSERT(ira->ira_tsl == NULL);

	/*
	 * Attach any necessary label information to
	 * this packet
	 */
	if (is_system_labeled()) {
		ira->ira_flags |= IRAF_SYSTEM_LABELED;

		/*
		 * This updates ira_cred, ira_tsl and ira_free_flags based
		 * on the label.
		 */
		if (!tsol_get_pkt_label(mp, IPV6_VERSION, ira)) {
			if (ip6opt_ls != 0)
				ip0dbg(("tsol_get_pkt_label v6 failed\n"));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return;
		}
		/* Note that ira_tsl can be NULL here. */

		/* tsol_get_pkt_label sometimes does pullupmsg */
		ip6h = (ip6_t *)mp->b_rptr;
	}
	ill_input_short_v6(mp, ip6h, nexthop, ira, rtc);
}

/*
 * Check for IPv6 addresses that should not appear on the wire
 * as either source or destination.
 * If we ever implement Stateless IPv6 Translators (SIIT) we'd have
 * to revisit the IPv4-mapped part.
 */
static boolean_t
ip6_bad_address(in6_addr_t *addr, boolean_t is_src)
{
	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		ip1dbg(("ip_input_v6: pkt with IPv4-mapped addr"));
		return (B_TRUE);
	}
	if (IN6_IS_ADDR_LOOPBACK(addr)) {
		ip1dbg(("ip_input_v6: pkt with loopback addr"));
		return (B_TRUE);
	}
	if (!is_src && IN6_IS_ADDR_UNSPECIFIED(addr)) {
		/*
		 * having :: in the src is ok: it's used for DAD.
		 */
		ip1dbg(("ip_input_v6: pkt with unspecified addr"));
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Routing lookup for IPv6 link-locals.
 * First we look on the inbound interface, then we check for IPMP and
 * look on the upper interface.
 * We update ira_ruifindex if we find the IRE on the upper interface.
 */
static ire_t *
ire_linklocal(const in6_addr_t *nexthop, ill_t *ill, ip_recv_attr_t *ira,
    uint_t irr_flags, ip_stack_t *ipst)
{
	int match_flags = MATCH_IRE_SECATTR | MATCH_IRE_ILL;
	ire_t *ire;

	ASSERT(IN6_IS_ADDR_LINKLOCAL(nexthop));
	ire = ire_route_recursive_v6(nexthop, 0, ill, ALL_ZONES, ira->ira_tsl,
	    match_flags, irr_flags, ira->ira_xmit_hint, ipst, NULL, NULL, NULL);
	if (!(ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    !IS_UNDER_IPMP(ill))
		return (ire);

	/*
	 * When we are using IMP we need to look for an IRE on both the
	 * under and upper interfaces since there are different
	 * link-local addresses for the under and upper.
	 */
	ill = ipmp_ill_hold_ipmp_ill(ill);
	if (ill == NULL)
		return (ire);

	ira->ira_ruifindex = ill->ill_phyint->phyint_ifindex;

	ire_refrele(ire);
	ire = ire_route_recursive_v6(nexthop, 0, ill, ALL_ZONES, ira->ira_tsl,
	    match_flags, irr_flags, ira->ira_xmit_hint, ipst, NULL, NULL, NULL);
	ill_refrele(ill);
	return (ire);
}

/*
 * This is the tail-end of the full receive side packet handling.
 * It can be used directly when the configuration is simple.
 */
void
ill_input_short_v6(mblk_t *mp, void *iph_arg, void *nexthop_arg,
    ip_recv_attr_t *ira, rtc_t *rtc)
{
	ire_t		*ire;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint_t		pkt_len;
	ssize_t 	len;
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	in6_addr_t	nexthop = *(in6_addr_t *)nexthop_arg;
	ilb_stack_t	*ilbs = ipst->ips_netstack->netstack_ilb;
	uint_t		irr_flags;
#define	rptr	((uchar_t *)ip6h)

	ASSERT(DB_TYPE(mp) == M_DATA);

	/*
	 * Check for source/dest being a bad address: loopback, any, or
	 * v4mapped. All of them start with a 64 bits of zero.
	 */
	if (ip6h->ip6_src.s6_addr32[0] == 0 &&
	    ip6h->ip6_src.s6_addr32[1] == 0) {
		if (ip6_bad_address(&ip6h->ip6_src, B_TRUE)) {
			ip1dbg(("ip_input_v6: pkt with bad src addr\n"));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
			ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
			freemsg(mp);
			return;
		}
	}
	if (ip6h->ip6_dst.s6_addr32[0] == 0 &&
	    ip6h->ip6_dst.s6_addr32[1] == 0) {
		if (ip6_bad_address(&ip6h->ip6_dst, B_FALSE)) {
			ip1dbg(("ip_input_v6: pkt with bad dst addr\n"));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
			ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
			freemsg(mp);
			return;
		}
	}

	len = mp->b_wptr - rptr;
	pkt_len = ira->ira_pktlen;

	/* multiple mblk or too short */
	len -= pkt_len;
	if (len != 0) {
		mp = ip_check_length(mp, rptr, len, pkt_len, IPV6_HDR_LEN, ira);
		if (mp == NULL)
			return;
		ip6h = (ip6_t *)mp->b_rptr;
	}

	DTRACE_IP7(receive, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
	    ip6h, __dtrace_ipsr_ill_t *, ill, ipha_t *, NULL, ip6_t *, ip6h,
	    int, 0);
	/*
	 * The event for packets being received from a 'physical'
	 * interface is placed after validation of the source and/or
	 * destination address as being local so that packets can be
	 * redirected to loopback addresses using ipnat.
	 */
	DTRACE_PROBE4(ip6__physical__in__start,
	    ill_t *, ill, ill_t *, NULL,
	    ip6_t *, ip6h, mblk_t *, mp);

	if (HOOKS6_INTERESTED_PHYSICAL_IN(ipst)) {
		int	ll_multicast = 0;
		int	error;
		in6_addr_t orig_dst = ip6h->ip6_dst;

		if (ira->ira_flags & IRAF_L2DST_MULTICAST)
			ll_multicast = HPE_MULTICAST;
		else if (ira->ira_flags & IRAF_L2DST_BROADCAST)
			ll_multicast = HPE_BROADCAST;

		FW_HOOKS6(ipst->ips_ip6_physical_in_event,
		    ipst->ips_ipv6firewall_physical_in,
		    ill, NULL, ip6h, mp, mp, ll_multicast, ipst, error);

		DTRACE_PROBE1(ip6__physical__in__end, mblk_t *, mp);

		if (mp == NULL)
			return;

		/* The length could have changed */
		ip6h = (ip6_t *)mp->b_rptr;
		ira->ira_pktlen = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
		pkt_len = ira->ira_pktlen;

		/*
		 * In case the destination changed we override any previous
		 * change to nexthop.
		 */
		if (!IN6_ARE_ADDR_EQUAL(&orig_dst, &ip6h->ip6_dst))
			nexthop = ip6h->ip6_dst;

		if (IN6_IS_ADDR_UNSPECIFIED(&nexthop)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
			ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
			freemsg(mp);
			return;
		}

	}

	if (ipst->ips_ip6_observe.he_interested) {
		zoneid_t dzone;

		/*
		 * On the inbound path the src zone will be unknown as
		 * this packet has come from the wire.
		 */
		dzone = ip_get_zoneid_v6(&nexthop, mp, ill, ira, ALL_ZONES);
		ipobs_hook(mp, IPOBS_HOOK_INBOUND, ALL_ZONES, dzone, ill, ipst);
	}

	if ((ip6h->ip6_vcf & IPV6_VERS_AND_FLOW_MASK) !=
	    IPV6_DEFAULT_VERS_AND_FLOW) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInWrongIPVersion);
		ip_drop_input("ipIfStatsInWrongIPVersion", mp, ill);
		freemsg(mp);
		return;
	}

	/*
	 * For IPv6 we update ira_ip_hdr_length and ira_protocol as
	 * we parse the headers, starting with the hop-by-hop options header.
	 */
	ira->ira_ip_hdr_length = IPV6_HDR_LEN;
	if ((ira->ira_protocol = ip6h->ip6_nxt) == IPPROTO_HOPOPTS) {
		ip6_hbh_t	*hbhhdr;
		uint_t		ehdrlen;
		uint8_t		*optptr;

		if (pkt_len < IPV6_HDR_LEN + MIN_EHDR_LEN) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
			ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
			freemsg(mp);
			return;
		}
		if (mp->b_cont != NULL &&
		    rptr + IPV6_HDR_LEN + MIN_EHDR_LEN > mp->b_wptr) {
			ip6h = ip_pullup(mp, IPV6_HDR_LEN + MIN_EHDR_LEN, ira);
			if (ip6h == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				freemsg(mp);
				return;
			}
		}
		hbhhdr = (ip6_hbh_t *)&ip6h[1];
		ehdrlen = 8 * (hbhhdr->ip6h_len + 1);

		if (pkt_len < IPV6_HDR_LEN + ehdrlen) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
			ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
			freemsg(mp);
			return;
		}
		if (mp->b_cont != NULL &&
		    rptr + IPV6_HDR_LEN + ehdrlen > mp->b_wptr) {
			ip6h = ip_pullup(mp, IPV6_HDR_LEN + ehdrlen, ira);
			if (ip6h == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				freemsg(mp);
				return;
			}
			hbhhdr = (ip6_hbh_t *)&ip6h[1];
		}

		/*
		 * Update ira_ip_hdr_length to skip the hop-by-hop header
		 * once we get to ip_fanout_v6
		 */
		ira->ira_ip_hdr_length += ehdrlen;
		ira->ira_protocol = hbhhdr->ip6h_nxt;

		optptr = (uint8_t *)&hbhhdr[1];
		switch (ip_process_options_v6(mp, ip6h, optptr,
		    ehdrlen - 2, IPPROTO_HOPOPTS, ira)) {
		case -1:
			/*
			 * Packet has been consumed and any
			 * needed ICMP messages sent.
			 */
			return;
		case 0:
			/* no action needed */
			break;
		case 1:
			/*
			 * Known router alert. Make use handle it as local
			 * by setting the nexthop to be the all-host multicast
			 * address, and skip multicast membership filter by
			 * marking as a router alert.
			 */
			ira->ira_flags |= IRAF_ROUTER_ALERT;
			nexthop = ipv6_all_hosts_mcast;
			break;
		}
	}

	/*
	 * Here we check to see if we machine is setup as
	 * L3 loadbalancer and if the incoming packet is for a VIP
	 *
	 * Check the following:
	 * - there is at least a rule
	 * - protocol of the packet is supported
	 *
	 * We don't load balance IPv6 link-locals.
	 */
	if (ilb_has_rules(ilbs) && ILB_SUPP_L4(ira->ira_protocol) &&
	    !IN6_IS_ADDR_LINKLOCAL(&nexthop)) {
		in6_addr_t	lb_dst;
		int		lb_ret;

		/* For convenience, we just pull up the mblk. */
		if (mp->b_cont != NULL) {
			if (pullupmsg(mp, -1) == 0) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards - pullupmsg",
				    mp, ill);
				freemsg(mp);
				return;
			}
			ip6h = (ip6_t *)mp->b_rptr;
		}
		lb_ret = ilb_check_v6(ilbs, ill, mp, ip6h, ira->ira_protocol,
		    (uint8_t *)ip6h + ira->ira_ip_hdr_length, &lb_dst);
		if (lb_ret == ILB_DROPPED) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ILB_DROPPED", mp, ill);
			freemsg(mp);
			return;
		}
		if (lb_ret == ILB_BALANCED) {
			/* Set the dst to that of the chosen server */
			nexthop = lb_dst;
			DB_CKSUMFLAGS(mp) = 0;
		}
	}

	if (ill->ill_flags & ILLF_ROUTER)
		irr_flags = IRR_ALLOCATE;
	else
		irr_flags = IRR_NONE;

	/* Can not use route cache with TX since the labels can differ */
	if (ira->ira_flags & IRAF_SYSTEM_LABELED) {
		if (IN6_IS_ADDR_MULTICAST(&nexthop)) {
			ire = ire_multicast(ill);
		} else if (IN6_IS_ADDR_LINKLOCAL(&nexthop)) {
			ire = ire_linklocal(&nexthop, ill, ira, irr_flags,
			    ipst);
		} else {
			/* Match destination and label */
			ire = ire_route_recursive_v6(&nexthop, 0, NULL,
			    ALL_ZONES, ira->ira_tsl, MATCH_IRE_SECATTR,
			    irr_flags, ira->ira_xmit_hint, ipst, NULL, NULL,
			    NULL);
		}
		/* Update the route cache so we do the ire_refrele */
		ASSERT(ire != NULL);
		if (rtc->rtc_ire != NULL)
			ire_refrele(rtc->rtc_ire);
		rtc->rtc_ire = ire;
		rtc->rtc_ip6addr = nexthop;
	} else if (IN6_ARE_ADDR_EQUAL(&nexthop, &rtc->rtc_ip6addr) &&
	    rtc->rtc_ire != NULL) {
		/* Use the route cache */
		ire = rtc->rtc_ire;
	} else {
		/* Update the route cache */
		if (IN6_IS_ADDR_MULTICAST(&nexthop)) {
			ire = ire_multicast(ill);
		} else if (IN6_IS_ADDR_LINKLOCAL(&nexthop)) {
			ire = ire_linklocal(&nexthop, ill, ira, irr_flags,
			    ipst);
		} else {
			ire = ire_route_recursive_dstonly_v6(&nexthop,
			    irr_flags, ira->ira_xmit_hint, ipst);
		}
		ASSERT(ire != NULL);
		if (rtc->rtc_ire != NULL)
			ire_refrele(rtc->rtc_ire);
		rtc->rtc_ire = ire;
		rtc->rtc_ip6addr = nexthop;
	}

	ire->ire_ib_pkt_count++;

	/*
	 * Based on ire_type and ire_flags call one of:
	 *	ire_recv_local_v6 - for IRE_LOCAL
	 *	ire_recv_loopback_v6 - for IRE_LOOPBACK
	 *	ire_recv_multirt_v6 - if RTF_MULTIRT
	 *	ire_recv_noroute_v6 - if RTF_REJECT or RTF_BLACHOLE
	 *	ire_recv_multicast_v6 - for IRE_MULTICAST
	 *	ire_recv_noaccept_v6 - for ire_noaccept ones
	 *	ire_recv_forward_v6 - for the rest.
	 */

	(*ire->ire_recvfn)(ire, mp, ip6h, ira);
}
#undef rptr

/*
 * ire_recvfn for IREs that need forwarding
 */
void
ire_recv_forward_v6(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	iaflags_t	iraflags = ira->ira_flags;
	ill_t		*dst_ill;
	nce_t		*nce;
	uint32_t	added_tx_len;
	uint32_t	mtu, iremtu;

	if (iraflags & (IRAF_L2DST_MULTICAST|IRAF_L2DST_BROADCAST)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		ip_drop_input("l2 multicast not forwarded", mp, ill);
		freemsg(mp);
		return;
	}

	if (!(ill->ill_flags & ILLF_ROUTER)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		ip_drop_input("ipIfStatsForwProhibits", mp, ill);
		freemsg(mp);
		return;
	}

	/*
	 * Either ire_nce_capable or ire_dep_parent would be set for the IRE
	 * when it is found by ire_route_recursive, but that some other thread
	 * could have changed the routes with the effect of clearing
	 * ire_dep_parent. In that case we'd end up dropping the packet, or
	 * finding a new nce below.
	 * Get, allocate, or update the nce.
	 * We get a refhold on ire_nce_cache as a result of this to avoid races
	 * where ire_nce_cache is deleted.
	 *
	 * This ensures that we don't forward if the interface is down since
	 * ipif_down removes all the nces.
	 */
	mutex_enter(&ire->ire_lock);
	nce = ire->ire_nce_cache;
	if (nce == NULL) {
		/* Not yet set up - try to set one up */
		mutex_exit(&ire->ire_lock);
		(void) ire_revalidate_nce(ire);
		mutex_enter(&ire->ire_lock);
		nce = ire->ire_nce_cache;
		if (nce == NULL) {
			mutex_exit(&ire->ire_lock);
			/* The ire_dep_parent chain went bad, or no memory */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("No ire_dep_parent", mp, ill);
			freemsg(mp);
			return;
		}
	}
	nce_refhold(nce);
	mutex_exit(&ire->ire_lock);

	if (nce->nce_is_condemned) {
		nce_t *nce1;

		nce1 = ire_handle_condemned_nce(nce, ire, NULL, ip6h, B_FALSE);
		nce_refrele(nce);
		if (nce1 == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("No nce", mp, ill);
			freemsg(mp);
			return;
		}
		nce = nce1;
	}
	dst_ill = nce->nce_ill;

	/*
	 * Unless we are forwarding, drop the packet.
	 * Unlike IPv4 we don't allow source routed packets out the same
	 * interface when we are not a router.
	 * Note that ill_forward_set() will set the ILLF_ROUTER on
	 * all the group members when it gets an ipmp-ill or under-ill.
	 */
	if (!(dst_ill->ill_flags & ILLF_ROUTER)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		ip_drop_input("ipIfStatsForwProhibits", mp, ill);
		freemsg(mp);
		nce_refrele(nce);
		return;
	}

	if (ire->ire_zoneid != GLOBAL_ZONEID && ire->ire_zoneid != ALL_ZONES) {
		ire->ire_ib_pkt_count--;
		/*
		 * Should only use IREs that are visible from the
		 * global zone for forwarding.
		 * For IPv6 any source route would have already been
		 * advanced in ip_fanout_v6
		 */
		ire = ire_route_recursive_v6(&ip6h->ip6_dst, 0, NULL,
		    GLOBAL_ZONEID, ira->ira_tsl, MATCH_IRE_SECATTR,
		    (ill->ill_flags & ILLF_ROUTER) ? IRR_ALLOCATE : IRR_NONE,
		    ira->ira_xmit_hint, ipst, NULL, NULL, NULL);
		ire->ire_ib_pkt_count++;
		(*ire->ire_recvfn)(ire, mp, ip6h, ira);
		ire_refrele(ire);
		nce_refrele(nce);
		return;
	}
	/*
	 * ipIfStatsHCInForwDatagrams should only be increment if there
	 * will be an attempt to forward the packet, which is why we
	 * increment after the above condition has been checked.
	 */
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInForwDatagrams);

	/* Initiate Read side IPPF processing */
	if (IPP_ENABLED(IPP_FWD_IN, ipst)) {
		/* ip_process translates an IS_UNDER_IPMP */
		mp = ip_process(IPP_FWD_IN, mp, ill, ill);
		if (mp == NULL) {
			/* ip_drop_packet and MIB done */
			ip2dbg(("ire_recv_forward_v6: pkt dropped/deferred "
			    "during IPPF processing\n"));
			nce_refrele(nce);
			return;
		}
	}

	DTRACE_PROBE4(ip6__forwarding__start,
	    ill_t *, ill, ill_t *, dst_ill, ip6_t *, ip6h, mblk_t *, mp);

	if (HOOKS6_INTERESTED_FORWARDING(ipst)) {
		int	error;

		FW_HOOKS(ipst->ips_ip6_forwarding_event,
		    ipst->ips_ipv6firewall_forwarding,
		    ill, dst_ill, ip6h, mp, mp, 0, ipst, error);

		DTRACE_PROBE1(ip6__forwarding__end, mblk_t *, mp);

		if (mp == NULL) {
			nce_refrele(nce);
			return;
		}
		/*
		 * Even if the destination was changed by the filter we use the
		 * forwarding decision that was made based on the address
		 * in ip_input.
		 */

		/* Might have changed */
		ip6h = (ip6_t *)mp->b_rptr;
		ira->ira_pktlen = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
	}

	/* Packet is being forwarded. Turning off hwcksum flag. */
	DB_CKSUMFLAGS(mp) = 0;

	/*
	 * Per RFC 3513 section 2.5.2, we must not forward packets with
	 * an unspecified source address.
	 * The loopback address check for both src and dst has already
	 * been checked in ip_input_v6
	 * In the future one can envision adding RPF checks using number 3.
	 */
	switch (ipst->ips_src_check) {
	case 0:
		break;
	case 1:
	case 2:
		if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src) ||
		    IN6_IS_ADDR_MULTICAST(&ip6h->ip6_src)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
			ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
			nce_refrele(nce);
			freemsg(mp);
			return;
		}
		break;
	}

	/*
	 * Check to see if we're forwarding the packet to a
	 * different link from which it came.  If so, check the
	 * source and destination addresses since routers must not
	 * forward any packets with link-local source or
	 * destination addresses to other links.  Otherwise (if
	 * we're forwarding onto the same link), conditionally send
	 * a redirect message.
	 */
	if (!IS_ON_SAME_LAN(dst_ill, ill)) {
		if (IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_dst) ||
		    IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
			ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
			freemsg(mp);
			nce_refrele(nce);
			return;
		}
		/* TBD add site-local check at site boundary? */
	} else if (ipst->ips_ipv6_send_redirects) {
		ip_send_potential_redirect_v6(mp, ip6h, ire, ira);
	}

	added_tx_len = 0;
	if (iraflags & IRAF_SYSTEM_LABELED) {
		mblk_t		*mp1;
		uint32_t	old_pkt_len = ira->ira_pktlen;

		/*
		 * Check if it can be forwarded and add/remove
		 * CIPSO options as needed.
		 */
		if ((mp1 = tsol_ip_forward(ire, mp, ira)) == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
			ip_drop_input("tsol_ip_forward", mp, ill);
			freemsg(mp);
			nce_refrele(nce);
			return;
		}
		/*
		 * Size may have changed. Remember amount added in case
		 * ip_fragment needs to send an ICMP too big.
		 */
		mp = mp1;
		ip6h = (ip6_t *)mp->b_rptr;
		ira->ira_pktlen = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
		ira->ira_ip_hdr_length = IPV6_HDR_LEN;
		if (ira->ira_pktlen > old_pkt_len)
			added_tx_len = ira->ira_pktlen - old_pkt_len;
	}

	mtu = dst_ill->ill_mtu;
	if ((iremtu = ire->ire_metrics.iulp_mtu) != 0 && iremtu < mtu)
		mtu = iremtu;
	ip_forward_xmit_v6(nce, mp, ip6h, ira, mtu, added_tx_len);
	nce_refrele(nce);
	return;

}

/*
 * Used for sending out unicast and multicast packets that are
 * forwarded.
 */
void
ip_forward_xmit_v6(nce_t *nce, mblk_t *mp, ip6_t *ip6h, ip_recv_attr_t *ira,
    uint32_t mtu, uint32_t added_tx_len)
{
	ill_t		*dst_ill = nce->nce_ill;
	uint32_t	pkt_len;
	iaflags_t	iraflags = ira->ira_flags;
	ip_stack_t	*ipst = dst_ill->ill_ipst;

	if (ip6h->ip6_hops-- <= 1) {
		BUMP_MIB(ira->ira_ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ICMP6_TIME_EXCEED_TRANSIT", mp, ira->ira_ill);
		icmp_time_exceeded_v6(mp, ICMP6_TIME_EXCEED_TRANSIT, B_FALSE,
		    ira);
		return;
	}

	/* Initiate Write side IPPF processing before any fragmentation */
	if (IPP_ENABLED(IPP_FWD_OUT, ipst)) {
		/* ip_process translates an IS_UNDER_IPMP */
		mp = ip_process(IPP_FWD_OUT, mp, dst_ill, dst_ill);
		if (mp == NULL) {
			/* ip_drop_packet and MIB done */
			ip2dbg(("ire_recv_forward_v6: pkt dropped/deferred" \
			    " during IPPF processing\n"));
			return;
		}
	}

	pkt_len = ira->ira_pktlen;

	BUMP_MIB(dst_ill->ill_ip_mib, ipIfStatsHCOutForwDatagrams);

	if (pkt_len > mtu) {
		BUMP_MIB(dst_ill->ill_ip_mib, ipIfStatsOutFragFails);
		ip_drop_output("ipIfStatsOutFragFails", mp, dst_ill);
		if (iraflags & IRAF_SYSTEM_LABELED) {
			/*
			 * Remove any CIPSO option added by
			 * tsol_ip_forward, and make sure we report
			 * a path MTU so that there
			 * is room to add such a CIPSO option for future
			 * packets.
			 */
			mtu = tsol_pmtu_adjust(mp, mtu, added_tx_len, AF_INET6);
		}
		icmp_pkt2big_v6(mp, mtu, B_TRUE, ira);
		return;
	}

	ASSERT(pkt_len ==
	    ntohs(((ip6_t *)mp->b_rptr)->ip6_plen) + IPV6_HDR_LEN);

	if (iraflags & IRAF_LOOPBACK_COPY) {
		/*
		 * IXAF_NO_LOOP_ZONEID is not set hence 6th arg
		 * is don't care
		 */
		(void) ip_postfrag_loopcheck(mp, nce,
		    (IXAF_LOOPBACK_COPY | IXAF_NO_DEV_FLOW_CTL),
		    pkt_len, ira->ira_xmit_hint, GLOBAL_ZONEID, 0, NULL);
	} else {
		(void) ip_xmit(mp, nce, IXAF_NO_DEV_FLOW_CTL,
		    pkt_len, ira->ira_xmit_hint, GLOBAL_ZONEID, 0, NULL);
	}
}

/*
 * ire_recvfn for RTF_REJECT and RTF_BLACKHOLE routes, including IRE_NOROUTE,
 * which is what ire_route_recursive returns when there is no matching ire.
 * Send ICMP unreachable unless blackhole.
 */
void
ire_recv_noroute_v6(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	/* Would we have forwarded this packet if we had a route? */
	if (ira->ira_flags & (IRAF_L2DST_MULTICAST|IRAF_L2DST_BROADCAST)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		ip_drop_input("l2 multicast not forwarded", mp, ill);
		freemsg(mp);
		return;
	}

	if (!(ill->ill_flags & ILLF_ROUTER)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		ip_drop_input("ipIfStatsForwProhibits", mp, ill);
		freemsg(mp);
		return;
	}
	/*
	 * If we had a route this could have been forwarded. Count as such.
	 *
	 * ipIfStatsHCInForwDatagrams should only be increment if there
	 * will be an attempt to forward the packet, which is why we
	 * increment after the above condition has been checked.
	 */
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInForwDatagrams);

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInNoRoutes);

	ip_rts_change_v6(RTM_MISS, &ip6h->ip6_dst, 0, 0, 0, 0, 0, 0, RTA_DST,
	    ipst);

	if (ire->ire_flags & RTF_BLACKHOLE) {
		ip_drop_input("ipIfStatsInNoRoutes RTF_BLACKHOLE", mp, ill);
		freemsg(mp);
	} else {
		ip_drop_input("ipIfStatsInNoRoutes RTF_REJECT", mp, ill);

		icmp_unreachable_v6(mp, ICMP6_DST_UNREACH_NOROUTE, B_FALSE,
		    ira);
	}
}

/*
 * ire_recvfn for IRE_LOCALs marked with ire_noaccept. Such IREs are used for
 * VRRP when in noaccept mode.
 * We silently drop packets except for Neighbor Solicitations and
 * Neighbor Advertisements.
 */
void
ire_recv_noaccept_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	ill_t		*ill = ira->ira_ill;
	icmp6_t		*icmp6;
	int		ip_hdr_length;

	if (ip6h->ip6_nxt != IPPROTO_ICMPV6) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards - noaccept", mp, ill);
		freemsg(mp);
		return;
	}
	ip_hdr_length = ira->ira_ip_hdr_length;
	if ((mp->b_wptr - mp->b_rptr) < (ip_hdr_length + ICMP6_MINLEN)) {
		if (ira->ira_pktlen < (ip_hdr_length + ICMP6_MINLEN)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
			ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
			freemsg(mp);
			return;
		}
		ip6h = ip_pullup(mp, ip_hdr_length + ICMP6_MINLEN, ira);
		if (ip6h == NULL) {
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInErrors);
			freemsg(mp);
			return;
		}
	}
	icmp6 = (icmp6_t *)(&mp->b_rptr[ip_hdr_length]);

	if (icmp6->icmp6_type != ND_NEIGHBOR_SOLICIT &&
	    icmp6->icmp6_type != ND_NEIGHBOR_ADVERT) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards - noaccept", mp, ill);
		freemsg(mp);
		return;
	}
	ire_recv_local_v6(ire, mp, ip6h, ira);
}

/*
 * ire_recvfn for IRE_MULTICAST.
 */
void
ire_recv_multicast_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	ill_t		*ill = ira->ira_ill;

	ASSERT(ire->ire_ill == ira->ira_ill);

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInMcastPkts);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInMcastOctets, ira->ira_pktlen);

	/* Tag for higher-level protocols */
	ira->ira_flags |= IRAF_MULTICAST;

	/*
	 * So that we don't end up with dups, only one ill an IPMP group is
	 * nominated to receive multicast traffic.
	 * If we have no cast_ill we are liberal and accept everything.
	 */
	if (IS_UNDER_IPMP(ill)) {
		ip_stack_t	*ipst = ill->ill_ipst;

		/* For an under ill_grp can change under lock */
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
		if (!ill->ill_nom_cast && ill->ill_grp != NULL &&
		    ill->ill_grp->ig_cast_ill != NULL) {
			rw_exit(&ipst->ips_ill_g_lock);
			ip_drop_input("not on cast ill", mp, ill);
			freemsg(mp);
			return;
		}
		rw_exit(&ipst->ips_ill_g_lock);
		/*
		 * We switch to the upper ill so that mrouter and hasmembers
		 * can operate on upper here and in ip_input_multicast.
		 */
		ill = ipmp_ill_hold_ipmp_ill(ill);
		if (ill != NULL) {
			ASSERT(ill != ira->ira_ill);
			ASSERT(ire->ire_ill == ira->ira_ill);
			ira->ira_ill = ill;
			ira->ira_ruifindex = ill->ill_phyint->phyint_ifindex;
		} else {
			ill = ira->ira_ill;
		}
	}

#ifdef notdef
	/*
	 * Check if we are a multicast router - send ip_mforward a copy of
	 * the packet.
	 * Due to mroute_decap tunnels we consider forwarding packets even if
	 * mrouted has not joined the allmulti group on this interface.
	 */
	if (ipst->ips_ip_g_mrouter) {
		int retval;

		/*
		 * Clear the indication that this may have hardware
		 * checksum as we are not using it for forwarding.
		 */
		DB_CKSUMFLAGS(mp) = 0;

		/*
		 * ip_mforward helps us make these distinctions: If received
		 * on tunnel and not IGMP, then drop.
		 * If IGMP packet, then don't check membership
		 * If received on a phyint and IGMP or PIM, then
		 * don't check membership
		 */
		retval = ip_mforward_v6(mp, ira);
		/* ip_mforward updates mib variables if needed */

		switch (retval) {
		case 0:
			/*
			 * pkt is okay and arrived on phyint.
			 */
			break;
		case -1:
			/* pkt is mal-formed, toss it */
			freemsg(mp);
			goto done;
		case 1:
			/*
			 * pkt is okay and arrived on a tunnel
			 *
			 * If we are running a multicast router
			 * we need to see all mld packets, which
			 * are marked with router alerts.
			 */
			if (ira->ira_flags & IRAF_ROUTER_ALERT)
				goto forus;
			ip_drop_input("Multicast on tunnel ignored", mp, ill);
			freemsg(mp);
			goto done;
		}
	}
#endif /* notdef */

	/*
	 * If this was a router alert we skip the group membership check.
	 */
	if (ira->ira_flags & IRAF_ROUTER_ALERT)
		goto forus;

	/*
	 * Check if we have members on this ill. This is not necessary for
	 * correctness because even if the NIC/GLD had a leaky filter, we
	 * filter before passing to each conn_t.
	 */
	if (!ill_hasmembers_v6(ill, &ip6h->ip6_dst)) {
		/*
		 * Nobody interested
		 *
		 * This might just be caused by the fact that
		 * multiple IP Multicast addresses map to the same
		 * link layer multicast - no need to increment counter!
		 */
		ip_drop_input("Multicast with no members", mp, ill);
		freemsg(mp);
		goto done;
	}
forus:
	ip2dbg(("ire_recv_multicast_v6: multicast for us\n"));

	/*
	 * After reassembly and IPsec we will need to duplicate the
	 * multicast packet for all matching zones on the ill.
	 */
	ira->ira_zoneid = ALL_ZONES;

	/* Reassemble on the ill on which the packet arrived */
	ip_input_local_v6(ire, mp, ip6h, ira);
done:
	if (ill != ire->ire_ill) {
		ill_refrele(ill);
		ira->ira_ill = ire->ire_ill;
		ira->ira_ruifindex = ira->ira_ill->ill_phyint->phyint_ifindex;
	}
}

/*
 * ire_recvfn for IRE_OFFLINK with RTF_MULTIRT.
 * Drop packets since we don't forward out multirt routes.
 */
/* ARGSUSED */
void
ire_recv_multirt_v6(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInNoRoutes);
	ip_drop_input("Not forwarding out MULTIRT", mp, ill);
	freemsg(mp);
}

/*
 * ire_recvfn for IRE_LOOPBACK. This is only used when a FW_HOOK
 * has rewritten the packet to have a loopback destination address (We
 * filter out packet with a loopback destination from arriving over the wire).
 * We don't know what zone to use, thus we always use the GLOBAL_ZONEID.
 */
void
ire_recv_loopback_v6(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	ill_t		*ill = ira->ira_ill;
	ill_t		*ire_ill = ire->ire_ill;

	ira->ira_zoneid = GLOBAL_ZONEID;

	/* Switch to the lo0 ill for further processing  */
	if (ire_ill != ill) {
		/*
		 * Update ira_ill to be the ILL on which the IP address
		 * is hosted.
		 * No need to hold the ill since we have a hold on the ire
		 */
		ASSERT(ira->ira_ill == ira->ira_rill);
		ira->ira_ill = ire_ill;

		ip_input_local_v6(ire, mp, ip6h, ira);

		/* Restore */
		ASSERT(ira->ira_ill == ire_ill);
		ira->ira_ill = ill;
		return;

	}
	ip_input_local_v6(ire, mp, ip6h, ira);
}

/*
 * ire_recvfn for IRE_LOCAL.
 */
void
ire_recv_local_v6(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	ill_t		*ill = ira->ira_ill;
	ill_t		*ire_ill = ire->ire_ill;

	/* Make a note for DAD that this address is in use */
	ire->ire_last_used_time = LBOLT_FASTPATH;

	/* Only target the IRE_LOCAL with the right zoneid. */
	ira->ira_zoneid = ire->ire_zoneid;

	/*
	 * If the packet arrived on the wrong ill, we check that
	 * this is ok.
	 * If it is, then we ensure that we do the reassembly on
	 * the ill on which the address is hosted. We keep ira_rill as
	 * the one on which the packet arrived, so that IP_PKTINFO and
	 * friends can report this.
	 */
	if (ire_ill != ill) {
		ire_t *new_ire;

		new_ire = ip_check_multihome(&ip6h->ip6_dst, ire, ill);
		if (new_ire == NULL) {
			/* Drop packet */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
			ip_drop_input("ipIfStatsInForwProhibits", mp, ill);
			freemsg(mp);
			return;
		}
		/*
		 * Update ira_ill to be the ILL on which the IP address
		 * is hosted. No need to hold the ill since we have a
		 * hold on the ire. Note that we do the switch even if
		 * new_ire == ire (for IPMP, ire would be the one corresponding
		 * to the IPMP ill).
		 */
		ASSERT(ira->ira_ill == ira->ira_rill);
		ira->ira_ill = new_ire->ire_ill;

		/* ira_ruifindex tracks the upper for ira_rill */
		if (IS_UNDER_IPMP(ill))
			ira->ira_ruifindex = ill_get_upper_ifindex(ill);

		ip_input_local_v6(new_ire, mp, ip6h, ira);

		/* Restore */
		ASSERT(ira->ira_ill == new_ire->ire_ill);
		ira->ira_ill = ill;
		ira->ira_ruifindex = ill->ill_phyint->phyint_ifindex;

		if (new_ire != ire)
			ire_refrele(new_ire);
		return;
	}

	ip_input_local_v6(ire, mp, ip6h, ira);
}

/*
 * Common function for packets arriving for the host. Handles
 * checksum verification, reassembly checks, etc.
 */
static void
ip_input_local_v6(ire_t *ire, mblk_t *mp, ip6_t *ip6h, ip_recv_attr_t *ira)
{
	iaflags_t	iraflags = ira->ira_flags;

	/*
	 * For multicast we need some extra work before
	 * we call ip_fanout_v6(), since in the case of shared-IP zones
	 * we need to pretend that a packet arrived for each zoneid.
	 */
	if (iraflags & IRAF_MULTICAST) {
		ip_input_multicast_v6(ire, mp, ip6h, ira);
		return;
	}
	ip_fanout_v6(mp, ip6h, ira);
}

/*
 * Handle multiple zones which want to receive the same multicast packets
 * on this ill by delivering a packet to each of them.
 *
 * Note that for packets delivered to transports we could instead do this
 * as part of the fanout code, but since we need to handle icmp_inbound
 * it is simpler to have multicast work the same as IPv4 broadcast.
 *
 * The ip_fanout matching for multicast matches based on ilm independent of
 * zoneid since the zoneid restriction is applied when joining a multicast
 * group.
 */
/* ARGSUSED */
static void
ip_input_multicast_v6(ire_t *ire, mblk_t *mp, ip6_t *ip6h, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	iaflags_t	iraflags = ira->ira_flags;
	ip_stack_t	*ipst = ill->ill_ipst;
	netstack_t	*ns = ipst->ips_netstack;
	zoneid_t	zoneid;
	mblk_t		*mp1;
	ip6_t		*ip6h1;
	uint_t		ira_pktlen = ira->ira_pktlen;
	uint16_t	ira_ip_hdr_length = ira->ira_ip_hdr_length;

	/* ire_recv_multicast has switched to the upper ill for IPMP */
	ASSERT(!IS_UNDER_IPMP(ill));

	/*
	 * If we don't have more than one shared-IP zone, or if
	 * there are no members in anything but the global zone,
	 * then just set the zoneid and proceed.
	 */
	if (ns->netstack_numzones == 1 ||
	    !ill_hasmembers_otherzones_v6(ill, &ip6h->ip6_dst,
	    GLOBAL_ZONEID)) {
		ira->ira_zoneid = GLOBAL_ZONEID;

		/* If sender didn't want this zone to receive it, drop */
		if ((iraflags & IRAF_NO_LOOP_ZONEID_SET) &&
		    ira->ira_no_loop_zoneid == ira->ira_zoneid) {
			ip_drop_input("Multicast but wrong zoneid", mp, ill);
			freemsg(mp);
			return;
		}
		ip_fanout_v6(mp, ip6h, ira);
		return;
	}

	/*
	 * Here we loop over all zoneids that have members in the group
	 * and deliver a packet to ip_fanout for each zoneid.
	 *
	 * First find any members in the lowest numeric zoneid by looking for
	 * first zoneid larger than -1 (ALL_ZONES).
	 * We terminate the loop when we receive -1 (ALL_ZONES).
	 */
	zoneid = ill_hasmembers_nextzone_v6(ill, &ip6h->ip6_dst, ALL_ZONES);
	for (; zoneid != ALL_ZONES;
	    zoneid = ill_hasmembers_nextzone_v6(ill, &ip6h->ip6_dst, zoneid)) {
		/*
		 * Avoid an extra copymsg/freemsg by skipping global zone here
		 * and doing that at the end.
		 */
		if (zoneid == GLOBAL_ZONEID)
			continue;

		ira->ira_zoneid = zoneid;

		/* If sender didn't want this zone to receive it, skip */
		if ((iraflags & IRAF_NO_LOOP_ZONEID_SET) &&
		    ira->ira_no_loop_zoneid == ira->ira_zoneid)
			continue;

		mp1 = copymsg(mp);
		if (mp1 == NULL) {
			/* Failed to deliver to one zone */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			continue;
		}
		ip6h1 = (ip6_t *)mp1->b_rptr;
		ip_fanout_v6(mp1, ip6h1, ira);
		/*
		 * IPsec might have modified ira_pktlen and ira_ip_hdr_length
		 * so we restore them for a potential next iteration
		 */
		ira->ira_pktlen = ira_pktlen;
		ira->ira_ip_hdr_length = ira_ip_hdr_length;
	}

	/* Do the main ire */
	ira->ira_zoneid = GLOBAL_ZONEID;
	/* If sender didn't want this zone to receive it, drop */
	if ((iraflags & IRAF_NO_LOOP_ZONEID_SET) &&
	    ira->ira_no_loop_zoneid == ira->ira_zoneid) {
		ip_drop_input("Multicast but wrong zoneid", mp, ill);
		freemsg(mp);
	} else {
		ip_fanout_v6(mp, ip6h, ira);
	}
}


/*
 * Determine the zoneid and IRAF_TX_MAC_EXEMPTABLE if trusted extensions
 * is in use. Updates ira_zoneid and ira_flags as a result.
 */
static void
ip_fanout_tx_v6(mblk_t *mp, ip6_t *ip6h, uint8_t protocol, uint_t ip_hdr_length,
    ip_recv_attr_t *ira)
{
	uint16_t	*up;
	uint16_t	lport;
	zoneid_t	zoneid;

	ASSERT(ira->ira_flags & IRAF_SYSTEM_LABELED);

	/*
	 * If the packet is unlabeled we might allow read-down
	 * for MAC_EXEMPT. Below we clear this if it is a multi-level
	 * port (MLP).
	 * Note that ira_tsl can be NULL here.
	 */
	if (ira->ira_tsl != NULL && ira->ira_tsl->tsl_flags & TSLF_UNLABELED)
		ira->ira_flags |= IRAF_TX_MAC_EXEMPTABLE;

	if (ira->ira_zoneid != ALL_ZONES)
		return;

	ira->ira_flags |= IRAF_TX_SHARED_ADDR;

	up = (uint16_t *)((uchar_t *)ip6h + ip_hdr_length);
	switch (protocol) {
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
	case IPPROTO_UDP:
		/* Caller ensures this */
		ASSERT(((uchar_t *)ip6h) + ip_hdr_length +4 <= mp->b_wptr);

		/*
		 * Only these transports support MLP.
		 * We know their destination port numbers is in
		 * the same place in the header.
		 */
		lport = up[1];

		/*
		 * No need to handle exclusive-stack zones
		 * since ALL_ZONES only applies to the shared IP instance.
		 */
		zoneid = tsol_mlp_findzone(protocol, lport);
		/*
		 * If no shared MLP is found, tsol_mlp_findzone returns
		 * ALL_ZONES.  In that case, we assume it's SLP, and
		 * search for the zone based on the packet label.
		 *
		 * If there is such a zone, we prefer to find a
		 * connection in it.  Otherwise, we look for a
		 * MAC-exempt connection in any zone whose label
		 * dominates the default label on the packet.
		 */
		if (zoneid == ALL_ZONES)
			zoneid = tsol_attr_to_zoneid(ira);
		else
			ira->ira_flags &= ~IRAF_TX_MAC_EXEMPTABLE;
		break;
	default:
		/* Handle shared address for other protocols */
		zoneid = tsol_attr_to_zoneid(ira);
		break;
	}
	ira->ira_zoneid = zoneid;
}

/*
 * Increment checksum failure statistics
 */
static void
ip_input_cksum_err_v6(uint8_t protocol, uint16_t hck_flags, ill_t *ill)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	switch (protocol) {
	case IPPROTO_TCP:
		BUMP_MIB(ill->ill_ip_mib, tcpIfStatsInErrs);

		if (hck_flags & HCK_FULLCKSUM)
			IP6_STAT(ipst, ip6_tcp_in_full_hw_cksum_err);
		else if (hck_flags & HCK_PARTIALCKSUM)
			IP6_STAT(ipst, ip6_tcp_in_part_hw_cksum_err);
		else
			IP6_STAT(ipst, ip6_tcp_in_sw_cksum_err);
		break;
	case IPPROTO_UDP:
		BUMP_MIB(ill->ill_ip_mib, udpIfStatsInCksumErrs);
		if (hck_flags & HCK_FULLCKSUM)
			IP6_STAT(ipst, ip6_udp_in_full_hw_cksum_err);
		else if (hck_flags & HCK_PARTIALCKSUM)
			IP6_STAT(ipst, ip6_udp_in_part_hw_cksum_err);
		else
			IP6_STAT(ipst, ip6_udp_in_sw_cksum_err);
		break;
	case IPPROTO_ICMPV6:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInMsgs);
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInErrors);
		break;
	default:
		ASSERT(0);
		break;
	}
}

/* Calculate the IPv6 pseudo-header checksum for TCP, UDP, and ICMPV6 */
uint32_t
ip_input_cksum_pseudo_v6(ip6_t *ip6h, ip_recv_attr_t *ira)
{
	uint_t		ulp_len;
	uint32_t	cksum;
	uint8_t		protocol = ira->ira_protocol;
	uint16_t	ip_hdr_length = ira->ira_ip_hdr_length;

#define	iphs    ((uint16_t *)ip6h)

	switch (protocol) {
	case IPPROTO_TCP:
		ulp_len = ira->ira_pktlen - ip_hdr_length;

		/* Protocol and length */
		cksum = htons(ulp_len) + IP_TCP_CSUM_COMP;
		/* IP addresses */
		cksum += iphs[4] + iphs[5] + iphs[6] + iphs[7] +
		    iphs[8] + iphs[9] + iphs[10] + iphs[11] +
		    iphs[12] + iphs[13] + iphs[14] + iphs[15] +
		    iphs[16] + iphs[17] + iphs[18] + iphs[19];
		break;

	case IPPROTO_UDP: {
		udpha_t		*udpha;

		udpha = (udpha_t  *)((uchar_t *)ip6h + ip_hdr_length);

		/* Protocol and length */
		cksum = udpha->uha_length + IP_UDP_CSUM_COMP;
		/* IP addresses */
		cksum += iphs[4] + iphs[5] + iphs[6] + iphs[7] +
		    iphs[8] + iphs[9] + iphs[10] + iphs[11] +
		    iphs[12] + iphs[13] + iphs[14] + iphs[15] +
		    iphs[16] + iphs[17] + iphs[18] + iphs[19];
		break;
	}
	case IPPROTO_ICMPV6:
		ulp_len = ira->ira_pktlen - ip_hdr_length;

		/* Protocol and length */
		cksum = htons(ulp_len) + IP_ICMPV6_CSUM_COMP;
		/* IP addresses */
		cksum += iphs[4] + iphs[5] + iphs[6] + iphs[7] +
		    iphs[8] + iphs[9] + iphs[10] + iphs[11] +
		    iphs[12] + iphs[13] + iphs[14] + iphs[15] +
		    iphs[16] + iphs[17] + iphs[18] + iphs[19];
		break;
	default:
		cksum = 0;
		break;
	}
#undef	iphs
	return (cksum);
}


/*
 * Software verification of the ULP checksums.
 * Returns B_TRUE if ok.
 * Increments statistics of failed.
 */
static boolean_t
ip_input_sw_cksum_v6(mblk_t *mp, ip6_t *ip6h, ip_recv_attr_t *ira)
{
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	uint32_t	cksum;
	uint8_t		protocol = ira->ira_protocol;
	uint16_t	ip_hdr_length = ira->ira_ip_hdr_length;

	IP6_STAT(ipst, ip6_in_sw_cksum);

	ASSERT(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP ||
	    protocol == IPPROTO_ICMPV6);

	cksum = ip_input_cksum_pseudo_v6(ip6h, ira);
	cksum = IP_CSUM(mp, ip_hdr_length, cksum);
	if (cksum == 0)
		return (B_TRUE);

	ip_input_cksum_err_v6(protocol, 0, ira->ira_ill);
	return (B_FALSE);
}

/*
 * Verify the ULP checksums.
 * Returns B_TRUE if ok, or if the ULP doesn't have a well-defined checksum
 * algorithm.
 * Increments statistics if failed.
 */
static boolean_t
ip_input_cksum_v6(iaflags_t iraflags, mblk_t *mp, ip6_t *ip6h,
    ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_rill;
	uint16_t	hck_flags;
	uint32_t	cksum;
	mblk_t		*mp1;
	uint_t		len;
	uint8_t		protocol = ira->ira_protocol;
	uint16_t	ip_hdr_length = ira->ira_ip_hdr_length;


	switch (protocol) {
	case IPPROTO_TCP:
	case IPPROTO_ICMPV6:
		break;

	case IPPROTO_UDP: {
		udpha_t		*udpha;

		udpha = (udpha_t  *)((uchar_t *)ip6h + ip_hdr_length);
		/*
		 *  Before going through the regular checksum
		 *  calculation, make sure the received checksum
		 *  is non-zero. RFC 2460 says, a 0x0000 checksum
		 *  in a UDP packet (within IPv6 packet) is invalid
		 *  and should be replaced by 0xffff. This makes
		 *  sense as regular checksum calculation will
		 *  pass for both the cases i.e. 0x0000 and 0xffff.
		 *  Removing one of the case makes error detection
		 *  stronger.
		 */
		if (udpha->uha_checksum == 0) {
			/* 0x0000 checksum is invalid */
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsInCksumErrs);
			return (B_FALSE);
		}
		break;
	}
	case IPPROTO_SCTP: {
		sctp_hdr_t	*sctph;
		uint32_t	pktsum;

		sctph = (sctp_hdr_t *)((uchar_t *)ip6h + ip_hdr_length);
#ifdef	DEBUG
		if (skip_sctp_cksum)
			return (B_TRUE);
#endif
		pktsum = sctph->sh_chksum;
		sctph->sh_chksum = 0;
		cksum = sctp_cksum(mp, ip_hdr_length);
		sctph->sh_chksum = pktsum;
		if (cksum == pktsum)
			return (B_TRUE);

		/*
		 * Defer until later whether a bad checksum is ok
		 * in order to allow RAW sockets to use Adler checksum
		 * with SCTP.
		 */
		ira->ira_flags |= IRAF_SCTP_CSUM_ERR;
		return (B_TRUE);
	}

	default:
		/* No ULP checksum to verify. */
		return (B_TRUE);
	}

	/*
	 * Revert to software checksum calculation if the interface
	 * isn't capable of checksum offload.
	 * We clear DB_CKSUMFLAGS when going through IPsec in ip_fanout.
	 * Note: IRAF_NO_HW_CKSUM is not currently used.
	 */
	ASSERT(!IS_IPMP(ill));
	if ((iraflags & IRAF_NO_HW_CKSUM) || !ILL_HCKSUM_CAPABLE(ill) ||
	    !dohwcksum) {
		return (ip_input_sw_cksum_v6(mp, ip6h, ira));
	}

	/*
	 * We apply this for all ULP protocols. Does the HW know to
	 * not set the flags for SCTP and other protocols.
	 */

	hck_flags = DB_CKSUMFLAGS(mp);

	if (hck_flags & HCK_FULLCKSUM_OK) {
		/*
		 * Hardware has already verified the checksum.
		 */
		return (B_TRUE);
	}

	if (hck_flags & HCK_FULLCKSUM) {
		/*
		 * Full checksum has been computed by the hardware
		 * and has been attached.  If the driver wants us to
		 * verify the correctness of the attached value, in
		 * order to protect against faulty hardware, compare
		 * it against -0 (0xFFFF) to see if it's valid.
		 */
		cksum = DB_CKSUM16(mp);
		if (cksum == 0xFFFF)
			return (B_TRUE);
		ip_input_cksum_err_v6(protocol, hck_flags, ira->ira_ill);
		return (B_FALSE);
	}

	mp1 = mp->b_cont;
	if ((hck_flags & HCK_PARTIALCKSUM) &&
	    (mp1 == NULL || mp1->b_cont == NULL) &&
	    ip_hdr_length >= DB_CKSUMSTART(mp) &&
	    ((len = ip_hdr_length - DB_CKSUMSTART(mp)) & 1) == 0) {
		uint32_t	adj;
		uchar_t		*cksum_start;

		cksum = ip_input_cksum_pseudo_v6(ip6h, ira);

		cksum_start = ((uchar_t *)ip6h + DB_CKSUMSTART(mp));

		/*
		 * Partial checksum has been calculated by hardware
		 * and attached to the packet; in addition, any
		 * prepended extraneous data is even byte aligned,
		 * and there are at most two mblks associated with
		 * the packet.  If any such data exists, we adjust
		 * the checksum; also take care any postpended data.
		 */
		IP_ADJCKSUM_PARTIAL(cksum_start, mp, mp1, len, adj);
		/*
		 * One's complement subtract extraneous checksum
		 */
		cksum += DB_CKSUM16(mp);
		if (adj >= cksum)
			cksum = ~(adj - cksum) & 0xFFFF;
		else
			cksum -= adj;
		cksum = (cksum & 0xFFFF) + ((int)cksum >> 16);
		cksum = (cksum & 0xFFFF) + ((int)cksum >> 16);
		if (!(~cksum & 0xFFFF))
			return (B_TRUE);

		ip_input_cksum_err_v6(protocol, hck_flags, ira->ira_ill);
		return (B_FALSE);
	}
	return (ip_input_sw_cksum_v6(mp, ip6h, ira));
}


/*
 * Handle fanout of received packets.
 * Unicast packets that are looped back (from ire_send_local_v6) and packets
 * from the wire are differentiated by checking IRAF_VERIFY_ULP_CKSUM.
 *
 * IPQoS Notes
 * Before sending it to the client, invoke IPPF processing. Policy processing
 * takes place only if the callout_position, IPP_LOCAL_IN, is enabled.
 */
void
ip_fanout_v6(mblk_t *mp, ip6_t *ip6h, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	iaflags_t	iraflags = ira->ira_flags;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint8_t		protocol;
	conn_t		*connp;
#define	rptr	((uchar_t *)ip6h)
	uint_t		ip_hdr_length;
	uint_t		min_ulp_header_length;
	int		offset;
	ssize_t		len;
	netstack_t	*ns = ipst->ips_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ill_t		*rill = ira->ira_rill;

	ASSERT(ira->ira_pktlen == ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN);

	/*
	 * We repeat this as we parse over destination options header and
	 * fragment headers (earlier we've handled any hop-by-hop options
	 * header.)
	 * We update ira_protocol and ira_ip_hdr_length as we skip past
	 * the intermediate headers; they already point past any
	 * hop-by-hop header.
	 */
repeat:
	protocol = ira->ira_protocol;
	ip_hdr_length = ira->ira_ip_hdr_length;

	/*
	 * Time for IPP once we've done reassembly and IPsec.
	 * We skip this for loopback packets since we don't do IPQoS
	 * on loopback.
	 */
	if (IPP_ENABLED(IPP_LOCAL_IN, ipst) &&
	    !(iraflags & IRAF_LOOPBACK) &&
	    (protocol != IPPROTO_ESP || protocol != IPPROTO_AH ||
	    protocol != IPPROTO_DSTOPTS || protocol != IPPROTO_ROUTING ||
	    protocol != IPPROTO_FRAGMENT)) {
		/*
		 * Use the interface on which the packet arrived - not where
		 * the IP address is hosted.
		 */
		/* ip_process translates an IS_UNDER_IPMP */
		mp = ip_process(IPP_LOCAL_IN, mp, rill, ill);
		if (mp == NULL) {
			/* ip_drop_packet and MIB done */
			return;
		}
	}

	/* Determine the minimum required size of the upper-layer header */
	/* Need to do this for at least the set of ULPs that TX handles. */
	switch (protocol) {
	case IPPROTO_TCP:
		min_ulp_header_length = TCP_MIN_HEADER_LENGTH;
		break;
	case IPPROTO_SCTP:
		min_ulp_header_length = SCTP_COMMON_HDR_LENGTH;
		break;
	case IPPROTO_UDP:
		min_ulp_header_length = UDPH_SIZE;
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		min_ulp_header_length = ICMPH_SIZE;
		break;
	case IPPROTO_FRAGMENT:
	case IPPROTO_DSTOPTS:
	case IPPROTO_ROUTING:
		min_ulp_header_length = MIN_EHDR_LEN;
		break;
	default:
		min_ulp_header_length = 0;
		break;
	}
	/* Make sure we have the min ULP header length */
	len = mp->b_wptr - rptr;
	if (len < ip_hdr_length + min_ulp_header_length) {
		if (ira->ira_pktlen < ip_hdr_length + min_ulp_header_length)
			goto pkt_too_short;

		IP6_STAT(ipst, ip6_recv_pullup);
		ip6h = ip_pullup(mp, ip_hdr_length + min_ulp_header_length,
		    ira);
		if (ip6h == NULL)
			goto discard;
		len = mp->b_wptr - rptr;
	}

	/*
	 * If trusted extensions then determine the zoneid and TX specific
	 * ira_flags.
	 */
	if (iraflags & IRAF_SYSTEM_LABELED) {
		/* This can update ira->ira_flags and ira->ira_zoneid */
		ip_fanout_tx_v6(mp, ip6h, protocol, ip_hdr_length, ira);
		iraflags = ira->ira_flags;
	}


	/* Verify ULP checksum. Handles TCP, UDP, and SCTP */
	if (iraflags & IRAF_VERIFY_ULP_CKSUM) {
		if (!ip_input_cksum_v6(iraflags, mp, ip6h, ira)) {
			/* Bad checksum. Stats are already incremented */
			ip_drop_input("Bad ULP checksum", mp, ill);
			freemsg(mp);
			return;
		}
		/* IRAF_SCTP_CSUM_ERR could have been set */
		iraflags = ira->ira_flags;
	}
	switch (protocol) {
	case IPPROTO_TCP:
		/* For TCP, discard multicast packets. */
		if (iraflags & IRAF_MULTIBROADCAST)
			goto discard;

		/* First mblk contains IP+TCP headers per above check */
		ASSERT(len >= ip_hdr_length + TCP_MIN_HEADER_LENGTH);

		/* TCP options present? */
		offset = ((uchar_t *)ip6h)[ip_hdr_length + 12] >> 4;
		if (offset != 5) {
			if (offset < 5)
				goto discard;

			/*
			 * There must be TCP options.
			 * Make sure we can grab them.
			 */
			offset <<= 2;
			offset += ip_hdr_length;
			if (len < offset) {
				if (ira->ira_pktlen < offset)
					goto pkt_too_short;

				IP6_STAT(ipst, ip6_recv_pullup);
				ip6h = ip_pullup(mp, offset, ira);
				if (ip6h == NULL)
					goto discard;
				len = mp->b_wptr - rptr;
			}
		}

		/*
		 * Pass up a squeue hint to tcp.
		 * If ira_sqp is already set (this is loopback) we leave it
		 * alone.
		 */
		if (ira->ira_sqp == NULL) {
			ira->ira_sqp = ip_squeue_get(ira->ira_ring);
		}

		/* Look for AF_INET or AF_INET6 that matches */
		connp = ipcl_classify_v6(mp, IPPROTO_TCP, ip_hdr_length,
		    ira, ipst);
		if (connp == NULL) {
			/* Send the TH_RST */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
			tcp_xmit_listeners_reset(mp, ira, ipst, NULL);
			return;
		}
		if (connp->conn_incoming_ifindex != 0 &&
		    connp->conn_incoming_ifindex != ira->ira_ruifindex) {
			CONN_DEC_REF(connp);

			/* Send the TH_RST */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
			tcp_xmit_listeners_reset(mp, ira, ipst, NULL);
			return;
		}
		if (CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) ||
		    (iraflags & IRAF_IPSEC_SECURE)) {
			mp = ipsec_check_inbound_policy(mp, connp,
			    NULL, ip6h, ira);
			if (mp == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				/* Note that mp is NULL */
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				CONN_DEC_REF(connp);
				return;
			}
		}
		/* Found a client; up it goes */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		ira->ira_ill = ira->ira_rill = NULL;
		if (!IPCL_IS_TCP(connp)) {
			/* Not TCP; must be SOCK_RAW, IPPROTO_TCP */
			(connp->conn_recv)(connp, mp, NULL, ira);
			CONN_DEC_REF(connp);
			ira->ira_ill = ill;
			ira->ira_rill = rill;
			return;
		}

		/*
		 * We do different processing whether called from
		 * ip_accept_tcp and we match the target, don't match
		 * the target, and when we are called by ip_input.
		 */
		if (iraflags & IRAF_TARGET_SQP) {
			if (ira->ira_target_sqp == connp->conn_sqp) {
				mblk_t	*attrmp;

				attrmp = ip_recv_attr_to_mblk(ira);
				if (attrmp == NULL) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInDiscards);
					ip_drop_input("ipIfStatsInDiscards",
					    mp, ill);
					freemsg(mp);
					CONN_DEC_REF(connp);
				} else {
					SET_SQUEUE(attrmp, connp->conn_recv,
					    connp);
					attrmp->b_cont = mp;
					ASSERT(ira->ira_target_sqp_mp == NULL);
					ira->ira_target_sqp_mp = attrmp;
					/*
					 * Conn ref release when drained from
					 * the squeue.
					 */
				}
			} else {
				SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
				    connp->conn_recv, connp, ira, SQ_FILL,
				    SQTAG_IP6_TCP_INPUT);
			}
		} else {
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp, connp->conn_recv,
			    connp, ira, ip_squeue_flag, SQTAG_IP6_TCP_INPUT);
		}
		ira->ira_ill = ill;
		ira->ira_rill = rill;
		return;

	case IPPROTO_SCTP: {
		sctp_hdr_t	*sctph;
		uint32_t	ports;	/* Source and destination ports */
		sctp_stack_t	*sctps = ipst->ips_netstack->netstack_sctp;

		/* For SCTP, discard multicast packets. */
		if (iraflags & IRAF_MULTIBROADCAST)
			goto discard;

		/*
		 * Since there is no SCTP h/w cksum support yet, just
		 * clear the flag.
		 */
		DB_CKSUMFLAGS(mp) = 0;

		/* Length ensured above */
		ASSERT(MBLKL(mp) >= ip_hdr_length + SCTP_COMMON_HDR_LENGTH);
		sctph = (sctp_hdr_t *)(rptr + ip_hdr_length);

		/* get the ports */
		ports = *(uint32_t *)&sctph->sh_sport;

		if (iraflags & IRAF_SCTP_CSUM_ERR) {
			/*
			 * No potential sctp checksum errors go to the Sun
			 * sctp stack however they might be Adler-32 summed
			 * packets a userland stack bound to a raw IP socket
			 * could reasonably use. Note though that Adler-32 is
			 * a long deprecated algorithm and customer sctp
			 * networks should eventually migrate to CRC-32 at
			 * which time this facility should be removed.
			 */
			ip_fanout_sctp_raw(mp, NULL, ip6h, ports, ira);
			return;
		}
		connp = sctp_fanout(&ip6h->ip6_src, &ip6h->ip6_dst, ports,
		    ira, mp, sctps, sctph);
		if (connp == NULL) {
			/* Check for raw socket or OOTB handling */
			ip_fanout_sctp_raw(mp, NULL, ip6h, ports, ira);
			return;
		}
		if (connp->conn_incoming_ifindex != 0 &&
		    connp->conn_incoming_ifindex != ira->ira_ruifindex) {
			CONN_DEC_REF(connp);

			/* Check for raw socket or OOTB handling */
			ip_fanout_sctp_raw(mp, NULL, ip6h, ports, ira);
			return;
		}

		/* Found a client; up it goes */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		sctp_input(connp, NULL, ip6h, mp, ira);
		/* sctp_input does a rele of the sctp_t */
		return;
	}

	case IPPROTO_UDP:
		/* First mblk contains IP+UDP headers as checked above */
		ASSERT(MBLKL(mp) >= ip_hdr_length + UDPH_SIZE);

		if (iraflags & IRAF_MULTIBROADCAST) {
			uint16_t *up;	/* Pointer to ports in ULP header */

			up = (uint16_t *)((uchar_t *)ip6h + ip_hdr_length);

			ip_fanout_udp_multi_v6(mp, ip6h, up[1], up[0], ira);
			return;
		}

		/* Look for AF_INET or AF_INET6 that matches */
		connp = ipcl_classify_v6(mp, IPPROTO_UDP, ip_hdr_length,
		    ira, ipst);
		if (connp == NULL) {
	no_udp_match:
			if (ipst->ips_ipcl_proto_fanout_v6[IPPROTO_UDP].
			    connf_head != NULL) {
				ASSERT(ira->ira_protocol == IPPROTO_UDP);
				ip_fanout_proto_v6(mp, ip6h, ira);
			} else {
				ip_fanout_send_icmp_v6(mp, ICMP6_DST_UNREACH,
				    ICMP6_DST_UNREACH_NOPORT, ira);
			}
			return;

		}
		if (connp->conn_incoming_ifindex != 0 &&
		    connp->conn_incoming_ifindex != ira->ira_ruifindex) {
			CONN_DEC_REF(connp);
			goto no_udp_match;
		}
		if (IPCL_IS_NONSTR(connp) ? connp->conn_flow_cntrld :
		    !canputnext(connp->conn_rq)) {
			CONN_DEC_REF(connp);
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsInOverflows);
			ip_drop_input("udpIfStatsInOverflows", mp, ill);
			freemsg(mp);
			return;
		}
		if (CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) ||
		    (iraflags & IRAF_IPSEC_SECURE)) {
			mp = ipsec_check_inbound_policy(mp, connp,
			    NULL, ip6h, ira);
			if (mp == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				/* Note that mp is NULL */
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				CONN_DEC_REF(connp);
				return;
			}
		}

		/* Found a client; up it goes */
		IP6_STAT(ipst, ip6_udp_fannorm);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		ira->ira_ill = ira->ira_rill = NULL;
		(connp->conn_recv)(connp, mp, NULL, ira);
		CONN_DEC_REF(connp);
		ira->ira_ill = ill;
		ira->ira_rill = rill;
		return;
	default:
		break;
	}

	/*
	 * Clear hardware checksumming flag as it is currently only
	 * used by TCP and UDP.
	 */
	DB_CKSUMFLAGS(mp) = 0;

	switch (protocol) {
	case IPPROTO_ICMPV6:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInMsgs);

		/* Check variable for testing applications */
		if (ipst->ips_ipv6_drop_inbound_icmpv6) {
			ip_drop_input("ipv6_drop_inbound_icmpv6", mp, ill);
			freemsg(mp);
			return;
		}
		/*
		 * We need to accomodate icmp messages coming in clear
		 * until we get everything secure from the wire. If
		 * icmp_accept_clear_messages is zero we check with
		 * the global policy and act accordingly. If it is
		 * non-zero, we accept the message without any checks.
		 * But *this does not mean* that this will be delivered
		 * to RAW socket clients. By accepting we might send
		 * replies back, change our MTU value etc.,
		 * but delivery to the ULP/clients depends on their
		 * policy dispositions.
		 */
		if (ipst->ips_icmp_accept_clear_messages == 0) {
			mp = ipsec_check_global_policy(mp, NULL,
			    NULL, ip6h, ira, ns);
			if (mp == NULL)
				return;
		}

		/*
		 * On a labeled system, we have to check whether the zone
		 * itself is permitted to receive raw traffic.
		 */
		if (ira->ira_flags & IRAF_SYSTEM_LABELED) {
			if (!tsol_can_accept_raw(mp, ira, B_FALSE)) {
				BUMP_MIB(ill->ill_icmp6_mib,
				    ipv6IfIcmpInErrors);
				ip_drop_input("tsol_can_accept_raw", mp, ill);
				freemsg(mp);
				return;
			}
		}

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		mp = icmp_inbound_v6(mp, ira);
		if (mp == NULL) {
			/* No need to pass to RAW sockets */
			return;
		}
		break;

	case IPPROTO_DSTOPTS: {
		ip6_dest_t	*desthdr;
		uint_t		ehdrlen;
		uint8_t		*optptr;

		/* We already check for MIN_EHDR_LEN above */

		/* Check if AH is present and needs to be processed. */
		mp = ipsec_early_ah_v6(mp, ira);
		if (mp == NULL)
			return;

		/*
		 * Reinitialize pointers, as ipsec_early_ah_v6() does
		 * complete pullups.  We don't have to do more pullups
		 * as a result.
		 */
		ip6h = (ip6_t *)mp->b_rptr;

		if (ira->ira_pktlen - ip_hdr_length < MIN_EHDR_LEN)
			goto pkt_too_short;

		if (mp->b_cont != NULL &&
		    rptr + ip_hdr_length + MIN_EHDR_LEN > mp->b_wptr) {
			ip6h = ip_pullup(mp, ip_hdr_length + MIN_EHDR_LEN, ira);
			if (ip6h == NULL)
				goto discard;
		}
		desthdr = (ip6_dest_t *)(rptr + ip_hdr_length);
		ehdrlen = 8 * (desthdr->ip6d_len + 1);
		if (ira->ira_pktlen - ip_hdr_length < ehdrlen)
			goto pkt_too_short;
		if (mp->b_cont != NULL &&
		    rptr + IPV6_HDR_LEN + ehdrlen > mp->b_wptr) {
			ip6h = ip_pullup(mp, IPV6_HDR_LEN + ehdrlen, ira);
			if (ip6h == NULL)
				goto discard;

			desthdr = (ip6_dest_t *)(rptr + ip_hdr_length);
		}
		optptr = (uint8_t *)&desthdr[1];

		/*
		 * Update ira_ip_hdr_length to skip the destination header
		 * when we repeat.
		 */
		ira->ira_ip_hdr_length += ehdrlen;

		ira->ira_protocol = desthdr->ip6d_nxt;

		/*
		 * Note: XXX This code does not seem to make
		 * distinction between Destination Options Header
		 * being before/after Routing Header which can
		 * happen if we are at the end of source route.
		 * This may become significant in future.
		 * (No real significant Destination Options are
		 * defined/implemented yet ).
		 */
		switch (ip_process_options_v6(mp, ip6h, optptr,
		    ehdrlen - 2, IPPROTO_DSTOPTS, ira)) {
		case -1:
			/*
			 * Packet has been consumed and any needed
			 * ICMP errors sent.
			 */
			return;
		case 0:
			/* No action needed  continue */
			break;
		case 1:
			/*
			 * Unnexpected return value
			 * (Router alert is a Hop-by-Hop option)
			 */
#ifdef DEBUG
			panic("ip_fanout_v6: router "
			    "alert hbh opt indication in dest opt");
			/*NOTREACHED*/
#else
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return;
#endif
		}
		goto repeat;
	}
	case IPPROTO_FRAGMENT: {
		ip6_frag_t *fraghdr;

		if (ira->ira_pktlen - ip_hdr_length < sizeof (ip6_frag_t))
			goto pkt_too_short;

		if (mp->b_cont != NULL &&
		    rptr + ip_hdr_length + sizeof (ip6_frag_t) > mp->b_wptr) {
			ip6h = ip_pullup(mp,
			    ip_hdr_length + sizeof (ip6_frag_t), ira);
			if (ip6h == NULL)
				goto discard;
		}

		fraghdr = (ip6_frag_t *)(rptr + ip_hdr_length);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsReasmReqds);

		/*
		 * Invoke the CGTP (multirouting) filtering module to
		 * process the incoming packet. Packets identified as
		 * duplicates must be discarded. Filtering is active
		 * only if the ip_cgtp_filter ndd variable is
		 * non-zero.
		 */
		if (ipst->ips_ip_cgtp_filter &&
		    ipst->ips_ip_cgtp_filter_ops != NULL) {
			int cgtp_flt_pkt;
			netstackid_t stackid;

			stackid = ipst->ips_netstack->netstack_stackid;

			/*
			 * CGTP and IPMP are mutually exclusive so
			 * phyint_ifindex is fine here.
			 */
			cgtp_flt_pkt =
			    ipst->ips_ip_cgtp_filter_ops->cfo_filter_v6(
			    stackid, ill->ill_phyint->phyint_ifindex,
			    ip6h, fraghdr);
			if (cgtp_flt_pkt == CGTP_IP_PKT_DUPLICATE) {
				ip_drop_input("CGTP_IP_PKT_DUPLICATE", mp, ill);
				freemsg(mp);
				return;
			}
		}

		/*
		 * Update ip_hdr_length to skip the frag header
		 * ip_input_fragment_v6 will determine the extension header
		 * prior to the fragment header and update its nexthdr value,
		 * and also set ira_protocol to the nexthdr that follows the
		 * completed fragment.
		 */
		ip_hdr_length += sizeof (ip6_frag_t);

		/*
		 * Make sure we have ira_l2src before we loose the original
		 * mblk
		 */
		if (!(ira->ira_flags & IRAF_L2SRC_SET))
			ip_setl2src(mp, ira, ira->ira_rill);

		mp = ip_input_fragment_v6(mp, ip6h, fraghdr,
		    ira->ira_pktlen - ip_hdr_length, ira);
		if (mp == NULL) {
			/* Reassembly is still pending */
			return;
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsReasmOKs);

		/*
		 * The mblk chain has the frag header removed and
		 * ira_protocol, ira_pktlen, ira_ip_hdr_length as well as the
		 * IP header has been updated to refleact the result.
		 */
		ip6h = (ip6_t *)mp->b_rptr;
		ip_hdr_length = ira->ira_ip_hdr_length;
		goto repeat;
	}
	case IPPROTO_HOPOPTS:
		/*
		 * Illegal header sequence.
		 * (Hop-by-hop headers are processed above
		 *  and required to immediately follow IPv6 header)
		 */
		ip_drop_input("ICMP_PARAM_PROBLEM", mp, ill);
		icmp_param_problem_nexthdr_v6(mp, B_FALSE, ira);
		return;

	case IPPROTO_ROUTING: {
		uint_t ehdrlen;
		ip6_rthdr_t *rthdr;

		/* Check if AH is present and needs to be processed. */
		mp = ipsec_early_ah_v6(mp, ira);
		if (mp == NULL)
			return;

		/*
		 * Reinitialize pointers, as ipsec_early_ah_v6() does
		 * complete pullups.  We don't have to do more pullups
		 * as a result.
		 */
		ip6h = (ip6_t *)mp->b_rptr;

		if (ira->ira_pktlen - ip_hdr_length < MIN_EHDR_LEN)
			goto pkt_too_short;

		if (mp->b_cont != NULL &&
		    rptr + ip_hdr_length + MIN_EHDR_LEN > mp->b_wptr) {
			ip6h = ip_pullup(mp, ip_hdr_length + MIN_EHDR_LEN, ira);
			if (ip6h == NULL)
				goto discard;
		}
		rthdr = (ip6_rthdr_t *)(rptr + ip_hdr_length);
		protocol = ira->ira_protocol = rthdr->ip6r_nxt;
		ehdrlen = 8 * (rthdr->ip6r_len + 1);
		if (ira->ira_pktlen - ip_hdr_length < ehdrlen)
			goto pkt_too_short;
		if (mp->b_cont != NULL &&
		    rptr + IPV6_HDR_LEN + ehdrlen > mp->b_wptr) {
			ip6h = ip_pullup(mp, IPV6_HDR_LEN + ehdrlen, ira);
			if (ip6h == NULL)
				goto discard;
			rthdr = (ip6_rthdr_t *)(rptr + ip_hdr_length);
		}
		if (rthdr->ip6r_segleft != 0) {
			/* Not end of source route */
			if (ira->ira_flags &
			    (IRAF_L2DST_MULTICAST|IRAF_L2DST_BROADCAST)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsForwProhibits);
				ip_drop_input("ipIfStatsInForwProhibits",
				    mp, ill);
				freemsg(mp);
				return;
			}
			ip_process_rthdr(mp, ip6h, rthdr, ira);
			return;
		}
		ira->ira_ip_hdr_length += ehdrlen;
		goto repeat;
	}

	case IPPROTO_AH:
	case IPPROTO_ESP: {
		/*
		 * Fast path for AH/ESP.
		 */
		netstack_t *ns = ipst->ips_netstack;
		ipsec_stack_t *ipss = ns->netstack_ipsec;

		IP_STAT(ipst, ipsec_proto_ahesp);

		if (!ipsec_loaded(ipss)) {
			ip_proto_not_sup(mp, ira);
			return;
		}

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		/* select inbound SA and have IPsec process the pkt */
		if (protocol == IPPROTO_ESP) {
			esph_t *esph;

			mp = ipsec_inbound_esp_sa(mp, ira, &esph);
			if (mp == NULL)
				return;

			ASSERT(esph != NULL);
			ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
			ASSERT(ira->ira_ipsec_esp_sa != NULL);
			ASSERT(ira->ira_ipsec_esp_sa->ipsa_input_func != NULL);

			mp = ira->ira_ipsec_esp_sa->ipsa_input_func(mp, esph,
			    ira);
		} else {
			ah_t *ah;

			mp = ipsec_inbound_ah_sa(mp, ira, &ah);
			if (mp == NULL)
				return;

			ASSERT(ah != NULL);
			ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
			ASSERT(ira->ira_ipsec_ah_sa != NULL);
			ASSERT(ira->ira_ipsec_ah_sa->ipsa_input_func != NULL);
			mp = ira->ira_ipsec_ah_sa->ipsa_input_func(mp, ah,
			    ira);
		}

		if (mp == NULL) {
			/*
			 * Either it failed or is pending. In the former case
			 * ipIfStatsInDiscards was increased.
			 */
			return;
		}
		/* we're done with IPsec processing, send it up */
		ip_input_post_ipsec(mp, ira);
		return;
	}
	case IPPROTO_NONE:
		/* All processing is done. Count as "delivered". */
		freemsg(mp);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		return;

	case IPPROTO_ENCAP:
	case IPPROTO_IPV6:
		/* iptun will verify trusted label */
		connp = ipcl_classify_v6(mp, protocol, ip_hdr_length,
		    ira, ipst);
		if (connp != NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
			ira->ira_ill = ira->ira_rill = NULL;
			connp->conn_recv(connp, mp, NULL, ira);
			CONN_DEC_REF(connp);
			ira->ira_ill = ill;
			ira->ira_rill = rill;
			return;
		}
		/* FALLTHRU */
	default:
		/*
		 * On a labeled system, we have to check whether the zone
		 * itself is permitted to receive raw traffic.
		 */
		if (ira->ira_flags & IRAF_SYSTEM_LABELED) {
			if (!tsol_can_accept_raw(mp, ira, B_FALSE)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				freemsg(mp);
				return;
			}
		}
		break;
	}

	/*
	 * The above input functions may have returned the pulled up message.
	 * So ip6h need to be reinitialized.
	 */
	ip6h = (ip6_t *)mp->b_rptr;
	ira->ira_protocol = protocol;
	if (ipst->ips_ipcl_proto_fanout_v6[protocol].connf_head == NULL) {
		/* No user-level listener for these packets packets */
		ip_proto_not_sup(mp, ira);
		return;
	}

	/*
	 * Handle fanout to raw sockets.  There
	 * can be more than one stream bound to a particular
	 * protocol.  When this is the case, each one gets a copy
	 * of any incoming packets.
	 */
	ASSERT(ira->ira_protocol == protocol);
	ip_fanout_proto_v6(mp, ip6h, ira);
	return;

pkt_too_short:
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
	ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
	freemsg(mp);
	return;

discard:
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
	ip_drop_input("ipIfStatsInDiscards", mp, ill);
	freemsg(mp);
#undef rptr
}
