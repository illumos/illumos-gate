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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <sys/zone.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/atomic.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/sdt.h>
#include <sys/socket.h>
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
#include <inet/tcp.h>
#include <inet/ip_multi.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/optcom.h>
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

#include <sys/pattr.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>
#include <inet/sctp/sctp_impl.h>
#include <inet/udp_impl.h>
#include <sys/sunddi.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#ifdef	DEBUG
extern boolean_t skip_sctp_cksum;
#endif

int
ip_output_simple_v6(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	ip6_t		*ip6h;
	in6_addr_t	firsthop; /* In IP header */
	in6_addr_t	dst;	/* End of source route, or ip6_dst if none */
	ire_t		*ire;
	in6_addr_t	setsrc;
	int		error;
	ill_t		*ill = NULL;
	dce_t		*dce = NULL;
	nce_t		*nce;
	iaflags_t	ixaflags = ixa->ixa_flags;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	uint8_t		*nexthdrp;
	boolean_t	repeat = B_FALSE;
	boolean_t	multirt = B_FALSE;
	uint_t		ifindex;
	int64_t		now;

	ip6h = (ip6_t *)mp->b_rptr;
	ASSERT(IPH_HDR_VERSION(ip6h) == IPV6_VERSION);

	ASSERT(ixa->ixa_nce == NULL);

	ixa->ixa_pktlen = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
	ASSERT(ixa->ixa_pktlen == msgdsize(mp));
	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &ixa->ixa_ip_hdr_length,
	    &nexthdrp)) {
		/* Malformed packet */
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsHCOutRequests);
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards", mp, NULL);
		freemsg(mp);
		return (EINVAL);
	}
	ixa->ixa_protocol = *nexthdrp;

	/*
	 * Assumes that source routed packets have already been massaged by
	 * the ULP (ip_massage_options_v6) and as a result ip6_dst is the next
	 * hop in the source route. The final destination is used for IPsec
	 * policy and DCE lookup.
	 */
	firsthop = ip6h->ip6_dst;
	dst = ip_get_dst_v6(ip6h, mp, NULL);

repeat_ire:
	error = 0;
	setsrc = ipv6_all_zeros;
	ire = ip_select_route_v6(&firsthop, ip6h->ip6_src, ixa, NULL, &setsrc,
	    &error, &multirt);
	ASSERT(ire != NULL);	/* IRE_NOROUTE if none found */
	if (error != 0) {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsHCOutRequests);
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards", mp, NULL);
		freemsg(mp);
		goto done;
	}

	if (ire->ire_flags & (RTF_BLACKHOLE|RTF_REJECT)) {
		/* ire_ill might be NULL hence need to skip some code */
		if (ixaflags & IXAF_SET_SOURCE)
			ip6h->ip6_src = ipv6_loopback;
		ixa->ixa_fragsize = IP_MAXPACKET;
		ire->ire_ob_pkt_count++;
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsHCOutRequests);
		/* No dce yet; use default one */
		error = (ire->ire_sendfn)(ire, mp, ip6h, ixa,
		    &ipst->ips_dce_default->dce_ident);
		goto done;
	}

	/* Note that ip6_dst is only used for IRE_MULTICAST */
	nce = ire_to_nce(ire, INADDR_ANY, &ip6h->ip6_dst);
	if (nce == NULL) {
		/* Allocation failure? */
		ip_drop_output("ire_to_nce", mp, ill);
		freemsg(mp);
		error = ENOBUFS;
		goto done;
	}
	if (nce->nce_is_condemned) {
		nce_t *nce1;

		nce1 = ire_handle_condemned_nce(nce, ire, NULL, ip6h, B_TRUE);
		nce_refrele(nce);
		if (nce1 == NULL) {
			if (!repeat) {
				/* Try finding a better IRE */
				repeat = B_TRUE;
				ire_refrele(ire);
				goto repeat_ire;
			}
			/* Tried twice - drop packet */
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("No nce", mp, ill);
			freemsg(mp);
			error = ENOBUFS;
			goto done;
		}
		nce = nce1;
	}
	/*
	 * For multicast with multirt we have a flag passed back from
	 * ire_lookup_multi_ill_v6 since we don't have an IRE for each
	 * possible multicast address.
	 * We also need a flag for multicast since we can't check
	 * whether RTF_MULTIRT is set in ixa_ire for multicast.
	 */
	if (multirt) {
		ixa->ixa_postfragfn = ip_postfrag_multirt_v6;
		ixa->ixa_flags |= IXAF_MULTIRT_MULTICAST;
	} else {
		ixa->ixa_postfragfn = ire->ire_postfragfn;
		ixa->ixa_flags &= ~IXAF_MULTIRT_MULTICAST;
	}
	ASSERT(ixa->ixa_nce == NULL);
	ixa->ixa_nce = nce;

	/*
	 * Check for a dce_t with a path mtu.
	 */
	ifindex = 0;
	if (IN6_IS_ADDR_LINKSCOPE(&dst))
		ifindex = nce->nce_common->ncec_ill->ill_phyint->phyint_ifindex;

	dce = dce_lookup_v6(&dst, ifindex, ipst, NULL);
	ASSERT(dce != NULL);

	if (!(ixaflags & IXAF_PMTU_DISCOVERY)) {
		ixa->ixa_fragsize = IPV6_MIN_MTU;
	} else if (dce->dce_flags & DCEF_PMTU) {
		/*
		 * To avoid a periodic timer to increase the path MTU we
		 * look at dce_last_change_time each time we send a packet.
		 */
		now = ddi_get_lbolt64();
		if (TICK_TO_SEC(now) - dce->dce_last_change_time >
		    ipst->ips_ip_pathmtu_interval) {
			/*
			 * Older than 20 minutes. Drop the path MTU information.
			 */
			mutex_enter(&dce->dce_lock);
			dce->dce_flags &= ~(DCEF_PMTU|DCEF_TOO_SMALL_PMTU);
			dce->dce_last_change_time = TICK_TO_SEC(now);
			mutex_exit(&dce->dce_lock);
			dce_increment_generation(dce);
			ixa->ixa_fragsize = ip_get_base_mtu(nce->nce_ill, ire);
		} else {
			uint_t fragsize;

			fragsize = ip_get_base_mtu(nce->nce_ill, ire);
			if (fragsize > dce->dce_pmtu)
				fragsize = dce->dce_pmtu;
			ixa->ixa_fragsize = fragsize;
		}
	} else {
		ixa->ixa_fragsize = ip_get_base_mtu(nce->nce_ill, ire);
	}

	/*
	 * We use use ire_nexthop_ill (and not ncec_ill) to avoid the under ipmp
	 * interface for source address selection.
	 */
	ill = ire_nexthop_ill(ire);

	if (ixaflags & IXAF_SET_SOURCE) {
		in6_addr_t	src;

		/*
		 * We use the final destination to get
		 * correct selection for source routed packets
		 */

		/* If unreachable we have no ill but need some source */
		if (ill == NULL) {
			src = ipv6_loopback;
			error = 0;
		} else {
			error = ip_select_source_v6(ill, &setsrc, &dst,
			    ixa->ixa_zoneid, ipst, B_FALSE,
			    ixa->ixa_src_preferences, &src, NULL, NULL);
		}
		if (error != 0) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutRequests);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards - no source",
			    mp, ill);
			freemsg(mp);
			goto done;
		}
		ip6h->ip6_src = src;
	} else if (ixaflags & IXAF_VERIFY_SOURCE) {
		/* Check if the IP source is assigned to the host. */
		if (!ip_verify_src(mp, ixa, NULL)) {
			/* Don't send a packet with a source that isn't ours */
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsHCOutRequests);
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards - invalid source",
			    mp, ill);
			freemsg(mp);
			error = EADDRNOTAVAIL;
			goto done;
		}
	}

	/*
	 * Check against global IPsec policy to set the AH/ESP attributes.
	 * IPsec will set IXAF_IPSEC_* and ixa_ipsec_* as appropriate.
	 */
	if (!(ixaflags & (IXAF_NO_IPSEC|IXAF_IPSEC_SECURE))) {
		ASSERT(ixa->ixa_ipsec_policy == NULL);
		mp = ip_output_attach_policy(mp, NULL, ip6h, NULL, ixa);
		if (mp == NULL) {
			/* MIB and ip_drop_packet already done */
			return (EHOSTUNREACH);	/* IPsec policy failure */
		}
	}

	if (ill != NULL) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutRequests);
	} else {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsHCOutRequests);
	}

	/*
	 * We update the statistics on the most specific IRE i.e., the first
	 * one we found.
	 * We don't have an IRE when we fragment, hence ire_ob_pkt_count
	 * can only count the use prior to fragmentation. However the MIB
	 * counters on the ill will be incremented in post fragmentation.
	 */
	ire->ire_ob_pkt_count++;

	/*
	 * Based on ire_type and ire_flags call one of:
	 *	ire_send_local_v6 - for IRE_LOCAL and IRE_LOOPBACK
	 *	ire_send_multirt_v6 - if RTF_MULTIRT
	 *	ire_send_noroute_v6 - if RTF_REJECT or RTF_BLACHOLE
	 *	ire_send_multicast_v6 - for IRE_MULTICAST
	 *	ire_send_wire_v6 - for the rest.
	 */
	error = (ire->ire_sendfn)(ire, mp, ip6h, ixa, &dce->dce_ident);
done:
	ire_refrele(ire);
	if (dce != NULL)
		dce_refrele(dce);
	if (ill != NULL)
		ill_refrele(ill);
	if (ixa->ixa_nce != NULL)
		nce_refrele(ixa->ixa_nce);
	ixa->ixa_nce = NULL;
	return (error);
}

/*
 * ire_sendfn() functions.
 * These functions use the following xmit_attr:
 *  - ixa_fragsize - read to determine whether or not to fragment
 *  - IXAF_IPSEC_SECURE - to determine whether or not to invoke IPsec
 *  - ixa_ipsec_*  are used inside IPsec
 *  - IXAF_LOOPBACK_COPY - for multicast
 */


/*
 * ire_sendfn for IRE_LOCAL and IRE_LOOPBACK
 *
 * The checks for restrict_interzone_loopback are done in ire_route_recursive.
 */
/* ARGSUSED4 */
int
ire_send_local_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ill_t		*ill = ire->ire_ill;
	ip_recv_attr_t	iras;	/* NOTE: No bzero for performance */
	uint_t		pktlen = ixa->ixa_pktlen;

	/*
	 * No fragmentation, no nce, and no application of IPsec.
	 *
	 *
	 * Note different order between IP provider and FW_HOOKS than in
	 * send_wire case.
	 */

	/*
	 * DTrace this as ip:::send.  A packet blocked by FW_HOOKS will fire the
	 * send probe, but not the receive probe.
	 */
	DTRACE_IP7(send, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
	    ip6h, __dtrace_ipsr_ill_t *, ill, ipha_t *, NULL, ip6_t *, ip6h,
	    int, 1);

	DTRACE_PROBE4(ip6__loopback__out__start,
	    ill_t *, NULL, ill_t *, ill,
	    ip6_t *, ip6h, mblk_t *, mp);

	if (HOOKS6_INTERESTED_LOOPBACK_OUT(ipst)) {
		int	error;

		FW_HOOKS(ipst->ips_ip6_loopback_out_event,
		    ipst->ips_ipv6firewall_loopback_out,
		    NULL, ill, ip6h, mp, mp, 0, ipst, error);

		DTRACE_PROBE1(ip6__loopback__out__end, mblk_t *, mp);
		if (mp == NULL)
			return (error);

		/*
		 * Even if the destination was changed by the filter we use the
		 * forwarding decision that was made based on the address
		 * in ip_output/ip_set_destination.
		 */
		/* Length could be different */
		ip6h = (ip6_t *)mp->b_rptr;
		pktlen = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
	}

	/*
	 * If a callback is enabled then we need to know the
	 * source and destination zoneids for the packet. We already
	 * have those handy.
	 */
	if (ipst->ips_ip6_observe.he_interested) {
		zoneid_t szone, dzone;
		zoneid_t stackzoneid;

		stackzoneid = netstackid_to_zoneid(
		    ipst->ips_netstack->netstack_stackid);

		if (stackzoneid == GLOBAL_ZONEID) {
			/* Shared-IP zone */
			dzone = ire->ire_zoneid;
			szone = ixa->ixa_zoneid;
		} else {
			szone = dzone = stackzoneid;
		}
		ipobs_hook(mp, IPOBS_HOOK_LOCAL, szone, dzone, ill, ipst);
	}

	/* Handle lo0 stats */
	ipst->ips_loopback_packets++;

	/*
	 * Update output mib stats. Note that we can't move into the icmp
	 * sender (icmp_output etc) since they don't know the ill and the
	 * stats are per ill.
	 */
	if (ixa->ixa_protocol == IPPROTO_ICMPV6) {
		icmp6_t		*icmp6;

		icmp6 = (icmp6_t *)((uchar_t *)ip6h + ixa->ixa_ip_hdr_length);
		icmp_update_out_mib_v6(ill, icmp6);
	}

	DTRACE_PROBE4(ip6__loopback__in__start,
	    ill_t *, ill, ill_t *, NULL,
	    ip6_t *, ip6h, mblk_t *, mp);

	if (HOOKS6_INTERESTED_LOOPBACK_IN(ipst)) {
		int	error;

		FW_HOOKS(ipst->ips_ip6_loopback_in_event,
		    ipst->ips_ipv6firewall_loopback_in,
		    ill, NULL, ip6h, mp, mp, 0, ipst, error);

		DTRACE_PROBE1(ip6__loopback__in__end, mblk_t *, mp);
		if (mp == NULL)
			return (error);

		/*
		 * Even if the destination was changed by the filter we use the
		 * forwarding decision that was made based on the address
		 * in ip_output/ip_set_destination.
		 */
		/* Length could be different */
		ip6h = (ip6_t *)mp->b_rptr;
		pktlen = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
	}

	DTRACE_IP7(receive, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
	    ip6h, __dtrace_ipsr_ill_t *, ill, ipha_t *, NULL, ip6_t *, ip6h,
	    int, 1);

	/* Map ixa to ira including IPsec policies */
	ipsec_out_to_in(ixa, ill, &iras);
	iras.ira_pktlen = pktlen;

	ire->ire_ib_pkt_count++;
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInReceives);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInOctets, pktlen);

	/* Destined to ire_zoneid - use that for fanout */
	iras.ira_zoneid = ire->ire_zoneid;

	if (is_system_labeled()) {
		iras.ira_flags |= IRAF_SYSTEM_LABELED;

		/*
		 * This updates ira_cred, ira_tsl and ira_free_flags based
		 * on the label. We don't expect this to ever fail for
		 * loopback packets, so we silently drop the packet should it
		 * fail.
		 */
		if (!tsol_get_pkt_label(mp, IPV6_VERSION, &iras)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("tsol_get_pkt_label", mp, ill);
			freemsg(mp);
			return (0);
		}
		ASSERT(iras.ira_tsl != NULL);

		/* tsol_get_pkt_label sometimes does pullupmsg */
		ip6h = (ip6_t *)mp->b_rptr;
	}

	ip_fanout_v6(mp, ip6h, &iras);

	/* We moved any IPsec refs from ixa to iras */
	ira_cleanup(&iras, B_FALSE);
	return (0);
}

static void
multirt_check_v6(ire_t *ire, ip6_t *ip6h, ip_xmit_attr_t *ixa)
{
	ip_stack_t *ipst = ixa->ixa_ipst;

	/* Limit the TTL on multirt packets. Do this even if IPV6_HOPLIMIT */
	if (ire->ire_type & IRE_MULTICAST) {
		if (ip6h->ip6_hops > 1) {
			ip2dbg(("ire_send_multirt_v6: forcing multicast "
			    "multirt TTL to 1 (was %d)\n", ip6h->ip6_hops));
			ip6h->ip6_hops = 1;
		}
		ixa->ixa_flags |= IXAF_NO_TTL_CHANGE;
	} else if ((ipst->ips_ip_multirt_ttl > 0) &&
	    (ip6h->ip6_hops > ipst->ips_ip_multirt_ttl)) {
		ip6h->ip6_hops = ipst->ips_ip_multirt_ttl;
		/*
		 * Need to ensure we don't increase the ttl should we go through
		 * ire_send_multicast.
		 */
		ixa->ixa_flags |= IXAF_NO_TTL_CHANGE;
	}

	/* For IPv6 this also needs to insert a fragment header */
	ixa->ixa_flags |= IXAF_IPV6_ADD_FRAGHDR;
}

/*
 * ire_sendfn for IRE_MULTICAST
 *
 * Note that we do path MTU discovery by default for IPv6 multicast. But
 * since unconnected UDP and RAW sockets don't set IXAF_PMTU_DISCOVERY
 * only connected sockets get this by default.
 */
int
ire_send_multicast_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ill_t		*ill = ire->ire_ill;
	iaflags_t	ixaflags = ixa->ixa_flags;

	/*
	 * The IRE_MULTICAST is the same whether or not multirt is in use.
	 * Hence we need special-case code.
	 */
	if (ixaflags & IXAF_MULTIRT_MULTICAST)
		multirt_check_v6(ire, ip6h, ixa);

	/*
	 * Check if anything in ip_input_v6 wants a copy of the transmitted
	 * packet (after IPsec and fragmentation)
	 *
	 * 1. Multicast routers always need a copy unless SO_DONTROUTE is set
	 *    RSVP and the rsvp daemon is an example of a
	 *    protocol and user level process that
	 *    handles it's own routing. Hence, it uses the
	 *    SO_DONTROUTE option to accomplish this.
	 * 2. If the sender has set IP_MULTICAST_LOOP, then we just
	 *    check whether there are any receivers for the group on the ill
	 *    (ignoring the zoneid).
	 * 3. If IP_MULTICAST_LOOP is not set, then we check if there are
	 *    any members in other shared-IP zones.
	 *    If such members exist, then we indicate that the sending zone
	 *    shouldn't get a loopback copy to preserve the IP_MULTICAST_LOOP
	 *    behavior.
	 *
	 * When we loopback we skip hardware checksum to make sure loopback
	 * copy is checksumed.
	 *
	 * Note that ire_ill is the upper in the case of IPMP.
	 */
	ixa->ixa_flags &= ~(IXAF_LOOPBACK_COPY | IXAF_NO_HW_CKSUM);
	if (ipst->ips_ip_g_mrouter && ill->ill_mrouter_cnt > 0 &&
	    !(ixaflags & IXAF_DONTROUTE)) {
		ixa->ixa_flags |= IXAF_LOOPBACK_COPY | IXAF_NO_HW_CKSUM;
	} else if (ixaflags & IXAF_MULTICAST_LOOP) {
		/*
		 * If this zone or any other zone has members then loopback
		 * a copy.
		 */
		if (ill_hasmembers_v6(ill, &ip6h->ip6_dst))
			ixa->ixa_flags |= IXAF_LOOPBACK_COPY | IXAF_NO_HW_CKSUM;
	} else if (ipst->ips_netstack->netstack_numzones > 1) {
		/*
		 * This zone should not have a copy. But there are some other
		 * zones which might have members.
		 */
		if (ill_hasmembers_otherzones_v6(ill, &ip6h->ip6_dst,
		    ixa->ixa_zoneid)) {
			ixa->ixa_flags |= IXAF_NO_LOOP_ZONEID_SET;
			ixa->ixa_no_loop_zoneid = ixa->ixa_zoneid;
			ixa->ixa_flags |= IXAF_LOOPBACK_COPY | IXAF_NO_HW_CKSUM;
		}
	}

	/*
	 * Unless IPV6_HOPLIMIT or ire_send_multirt_v6 already set a ttl,
	 * force the ttl to the IP_MULTICAST_TTL value
	 */
	if (!(ixaflags & IXAF_NO_TTL_CHANGE)) {
		ip6h->ip6_hops = ixa->ixa_multicast_ttl;
	}

	return (ire_send_wire_v6(ire, mp, ip6h, ixa, identp));
}

/*
 * ire_sendfn for IREs with RTF_MULTIRT
 */
int
ire_send_multirt_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;

	multirt_check_v6(ire, ip6h, ixa);

	if (ire->ire_type & IRE_MULTICAST)
		return (ire_send_multicast_v6(ire, mp, ip6h, ixa, identp));
	else
		return (ire_send_wire_v6(ire, mp, ip6h, ixa, identp));
}

/*
 * ire_sendfn for IREs with RTF_REJECT/RTF_BLACKHOLE, including IRE_NOROUTE
 */
/* ARGSUSED4 */
int
ire_send_noroute_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ill_t		*ill;
	ip_recv_attr_t	iras;
	boolean_t	dummy;

	BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutNoRoutes);

	if (ire->ire_type & IRE_NOROUTE) {
		/* A lack of a route as opposed to RTF_REJECT|BLACKHOLE */
		ip_rts_change_v6(RTM_MISS, &ip6h->ip6_dst, 0, 0, 0, 0, 0, 0,
		    RTA_DST, ipst);
	}

	if (ire->ire_flags & RTF_BLACKHOLE) {
		ip_drop_output("ipIfStatsOutNoRoutes RTF_BLACKHOLE", mp, NULL);
		freemsg(mp);
		/* No error even for local senders - silent blackhole */
		return (0);
	}
	ip_drop_output("ipIfStatsOutNoRoutes RTF_REJECT", mp, NULL);

	/*
	 * We need an ill_t for the ip_recv_attr_t even though this packet
	 * was never received and icmp_unreachable doesn't currently use
	 * ira_ill.
	 */
	ill = ill_lookup_on_name("lo0", B_FALSE,
	    !(ixa->ixa_flags & IRAF_IS_IPV4), &dummy, ipst);
	if (ill == NULL) {
		freemsg(mp);
		return (EHOSTUNREACH);
	}

	bzero(&iras, sizeof (iras));
	/* Map ixa to ira including IPsec policies */
	ipsec_out_to_in(ixa, ill, &iras);

	icmp_unreachable_v6(mp, ICMP6_DST_UNREACH_NOROUTE, B_FALSE, &iras);
	/* We moved any IPsec refs from ixa to iras */
	ira_cleanup(&iras, B_FALSE);

	ill_refrele(ill);
	return (EHOSTUNREACH);
}

/*
 * Calculate a checksum ignoring any hardware capabilities
 *
 * Returns B_FALSE if the packet was too short for the checksum. Caller
 * should free and do stats.
 */
static boolean_t
ip_output_sw_cksum_v6(mblk_t *mp, ip6_t *ip6h, ip_xmit_attr_t *ixa)
{
	ip_stack_t	*ipst = ixa->ixa_ipst;
	uint_t		pktlen = ixa->ixa_pktlen;
	uint16_t	*cksump;
	uint32_t	cksum;
	uint8_t		protocol = ixa->ixa_protocol;
	uint16_t	ip_hdr_length = ixa->ixa_ip_hdr_length;

#define	iphs    ((uint16_t *)ip6h)

	/* Just in case it contained garbage */
	DB_CKSUMFLAGS(mp) &= ~HCK_FLAGS;

	/*
	 * Calculate ULP checksum
	 */
	if (protocol == IPPROTO_TCP) {
		cksump = IPH_TCPH_CHECKSUMP(ip6h, ip_hdr_length);
		cksum = IP_TCP_CSUM_COMP;
	} else if (protocol == IPPROTO_UDP) {
		cksump = IPH_UDPH_CHECKSUMP(ip6h, ip_hdr_length);
		cksum = IP_UDP_CSUM_COMP;
	} else if (protocol == IPPROTO_SCTP) {
		sctp_hdr_t	*sctph;

		ASSERT(MBLKL(mp) >= (ip_hdr_length + sizeof (*sctph)));
		sctph = (sctp_hdr_t *)(mp->b_rptr + ip_hdr_length);
		/*
		 * Zero out the checksum field to ensure proper
		 * checksum calculation.
		 */
		sctph->sh_chksum = 0;
#ifdef	DEBUG
		if (!skip_sctp_cksum)
#endif
			sctph->sh_chksum = sctp_cksum(mp, ip_hdr_length);
		return (B_TRUE);
	} else if (ixa->ixa_flags & IXAF_SET_RAW_CKSUM) {
		/*
		 * icmp has placed length and routing
		 * header adjustment in the checksum field.
		 */
		cksump = (uint16_t *)(((uint8_t *)ip6h) + ip_hdr_length +
		    ixa->ixa_raw_cksum_offset);
		cksum = htons(protocol);
	} else if (protocol == IPPROTO_ICMPV6) {
		cksump = IPH_ICMPV6_CHECKSUMP(ip6h, ip_hdr_length);
		cksum = IP_ICMPV6_CSUM_COMP;	/* Pseudo-header cksum */
	} else {
		return (B_TRUE);
	}

	/* ULP puts the checksum field is in the first mblk */
	ASSERT(((uchar_t *)cksump) + sizeof (uint16_t) <= mp->b_wptr);

	/*
	 * We accumulate the pseudo header checksum in cksum.
	 * This is pretty hairy code, so watch close.  One
	 * thing to keep in mind is that UDP and TCP have
	 * stored their respective datagram lengths in their
	 * checksum fields.  This lines things up real nice.
	 */
	cksum += iphs[4] + iphs[5] + iphs[6] + iphs[7] +
	    iphs[8] + iphs[9] + iphs[10] + iphs[11] +
	    iphs[12] + iphs[13] + iphs[14] + iphs[15] +
	    iphs[16] + iphs[17] + iphs[18] + iphs[19];
	cksum = IP_CSUM(mp, ip_hdr_length, cksum);

	/*
	 * For UDP/IPv6 a zero UDP checksum is not allowed.
	 * Change to 0xffff
	 */
	if (protocol == IPPROTO_UDP && cksum == 0)
		*cksump = ~cksum;
	else
		*cksump = cksum;

	IP6_STAT(ipst, ip6_out_sw_cksum);
	IP6_STAT_UPDATE(ipst, ip6_out_sw_cksum_bytes, pktlen);

	/* No IP header checksum for IPv6 */

	return (B_TRUE);
#undef	iphs
}

/* There are drivers that can't do partial checksum for ICMPv6 */
int nxge_cksum_workaround = 1;

/*
 * Calculate the ULP checksum - try to use hardware.
 * In the case of MULTIRT or multicast the
 * IXAF_NO_HW_CKSUM is set in which case we use software.
 *
 * Returns B_FALSE if the packet was too short for the checksum. Caller
 * should free and do stats.
 */
static boolean_t
ip_output_cksum_v6(iaflags_t ixaflags, mblk_t *mp, ip6_t *ip6h,
    ip_xmit_attr_t *ixa, ill_t *ill)
{
	uint_t		pktlen = ixa->ixa_pktlen;
	uint16_t	*cksump;
	uint16_t	hck_flags;
	uint32_t	cksum;
	uint8_t		protocol = ixa->ixa_protocol;
	uint16_t	ip_hdr_length = ixa->ixa_ip_hdr_length;

#define	iphs    ((uint16_t *)ip6h)

	if ((ixaflags & IXAF_NO_HW_CKSUM) || !ILL_HCKSUM_CAPABLE(ill) ||
	    !dohwcksum) {
		return (ip_output_sw_cksum_v6(mp, ip6h, ixa));
	}

	/*
	 * Calculate ULP checksum. Note that we don't use cksump and cksum
	 * if the ill has FULL support.
	 */
	if (protocol == IPPROTO_TCP) {
		cksump = IPH_TCPH_CHECKSUMP(ip6h, ip_hdr_length);
		cksum = IP_TCP_CSUM_COMP;	/* Pseudo-header cksum */
	} else if (protocol == IPPROTO_UDP) {
		cksump = IPH_UDPH_CHECKSUMP(ip6h, ip_hdr_length);
		cksum = IP_UDP_CSUM_COMP;	/* Pseudo-header cksum */
	} else if (protocol == IPPROTO_SCTP) {
		sctp_hdr_t	*sctph;

		ASSERT(MBLKL(mp) >= (ip_hdr_length + sizeof (*sctph)));
		sctph = (sctp_hdr_t *)(mp->b_rptr + ip_hdr_length);
		/*
		 * Zero out the checksum field to ensure proper
		 * checksum calculation.
		 */
		sctph->sh_chksum = 0;
#ifdef	DEBUG
		if (!skip_sctp_cksum)
#endif
			sctph->sh_chksum = sctp_cksum(mp, ip_hdr_length);
		goto ip_hdr_cksum;
	} else if (ixa->ixa_flags & IXAF_SET_RAW_CKSUM) {
		/*
		 * icmp has placed length and routing
		 * header adjustment in the checksum field.
		 */
		cksump = (uint16_t *)(((uint8_t *)ip6h) + ip_hdr_length +
		    ixa->ixa_raw_cksum_offset);
		cksum = htons(protocol);
	} else if (protocol == IPPROTO_ICMPV6) {
		cksump = IPH_ICMPV6_CHECKSUMP(ip6h, ip_hdr_length);
		cksum = IP_ICMPV6_CSUM_COMP;	/* Pseudo-header cksum */
	} else {
	ip_hdr_cksum:
		/* No IP header checksum for IPv6 */
		return (B_TRUE);
	}

	/* ULP puts the checksum field is in the first mblk */
	ASSERT(((uchar_t *)cksump) + sizeof (uint16_t) <= mp->b_wptr);

	/*
	 * Underlying interface supports hardware checksum offload for
	 * the payload; leave the payload checksum for the hardware to
	 * calculate.  N.B: We only need to set up checksum info on the
	 * first mblk.
	 */
	hck_flags = ill->ill_hcksum_capab->ill_hcksum_txflags;

	DB_CKSUMFLAGS(mp) &= ~HCK_FLAGS;
	if (hck_flags & HCKSUM_INET_FULL_V6) {
		/*
		 * Hardware calculates pseudo-header, header and the
		 * payload checksums, so clear the checksum field in
		 * the protocol header.
		 */
		*cksump = 0;
		DB_CKSUMFLAGS(mp) |= HCK_FULLCKSUM;
		return (B_TRUE);
	}
	if (((hck_flags) & HCKSUM_INET_PARTIAL) &&
	    (protocol != IPPROTO_ICMPV6 || !nxge_cksum_workaround)) {
		/*
		 * Partial checksum offload has been enabled.  Fill
		 * the checksum field in the protocol header with the
		 * pseudo-header checksum value.
		 *
		 * We accumulate the pseudo header checksum in cksum.
		 * This is pretty hairy code, so watch close.  One
		 * thing to keep in mind is that UDP and TCP have
		 * stored their respective datagram lengths in their
		 * checksum fields.  This lines things up real nice.
		 */
		cksum += iphs[4] + iphs[5] + iphs[6] + iphs[7] +
		    iphs[8] + iphs[9] + iphs[10] + iphs[11] +
		    iphs[12] + iphs[13] + iphs[14] + iphs[15] +
		    iphs[16] + iphs[17] + iphs[18] + iphs[19];
		cksum += *(cksump);
		cksum = (cksum & 0xFFFF) + (cksum >> 16);
		*(cksump) = (cksum & 0xFFFF) + (cksum >> 16);

		/*
		 * Offsets are relative to beginning of IP header.
		 */
		DB_CKSUMSTART(mp) = ip_hdr_length;
		DB_CKSUMSTUFF(mp) = (uint8_t *)cksump - (uint8_t *)ip6h;
		DB_CKSUMEND(mp) = pktlen;
		DB_CKSUMFLAGS(mp) |= HCK_PARTIALCKSUM;
		return (B_TRUE);
	}
	/* Hardware capabilities include neither full nor partial IPv6 */
	return (ip_output_sw_cksum_v6(mp, ip6h, ixa));
#undef	iphs
}

/*
 * ire_sendfn for offlink and onlink destinations.
 * Also called from the multicast, and multirt send functions.
 *
 * Assumes that the caller has a hold on the ire.
 *
 * This function doesn't care if the IRE just became condemned since that
 * can happen at any time.
 */
/* ARGSUSED */
int
ire_send_wire_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ip6_t		*ip6h = (ip6_t *)iph_arg;
	iaflags_t	ixaflags = ixa->ixa_flags;
	ill_t		*ill;
	uint32_t	pktlen = ixa->ixa_pktlen;

	ASSERT(ixa->ixa_nce != NULL);
	ill = ixa->ixa_nce->nce_ill;

	/*
	 * Update output mib stats. Note that we can't move into the icmp
	 * sender (icmp_output etc) since they don't know the ill and the
	 * stats are per ill.
	 *
	 * With IPMP we record the stats on the upper ill.
	 */
	if (ixa->ixa_protocol == IPPROTO_ICMPV6) {
		icmp6_t		*icmp6;

		icmp6 = (icmp6_t *)((uchar_t *)ip6h + ixa->ixa_ip_hdr_length);
		icmp_update_out_mib_v6(ixa->ixa_nce->nce_common->ncec_ill,
		    icmp6);
	}

	if (ixaflags & IXAF_DONTROUTE)
		ip6h->ip6_hops = 1;

	/*
	 * This might set b_band, thus the IPsec and fragmentation
	 * code in IP ensures that b_band is updated in the first mblk.
	 */
	if (IPP_ENABLED(IPP_LOCAL_OUT, ipst)) {
		/* ip_process translates an IS_UNDER_IPMP */
		mp = ip_process(IPP_LOCAL_OUT, mp, ill, ill);
		if (mp == NULL) {
			/* ip_drop_packet and MIB done */
			return (0);	/* Might just be delayed */
		}
	}

	/*
	 * To handle IPsec/iptun's labeling needs we need to tag packets
	 * while we still have ixa_tsl
	 */
	if (is_system_labeled() && ixa->ixa_tsl != NULL &&
	    (ill->ill_mactype == DL_6TO4 || ill->ill_mactype == DL_IPV4 ||
	    ill->ill_mactype == DL_IPV6)) {
		cred_t *newcr;

		newcr = copycred_from_tslabel(ixa->ixa_cred, ixa->ixa_tsl,
		    KM_NOSLEEP);
		if (newcr == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards - newcr",
			    mp, ill);
			freemsg(mp);
			return (ENOBUFS);
		}
		mblk_setcred(mp, newcr, NOPID);
		crfree(newcr);	/* mblk_setcred did its own crhold */
	}

	/*
	 * IXAF_IPV6_ADD_FRAGHDR is set for CGTP so that we will add a
	 * fragment header without fragmenting. CGTP on the receiver will
	 * filter duplicates on the ident field.
	 */
	if (pktlen > ixa->ixa_fragsize ||
	    (ixaflags & (IXAF_IPSEC_SECURE|IXAF_IPV6_ADD_FRAGHDR))) {
		uint32_t ident;

		if (ixaflags & IXAF_IPSEC_SECURE)
			pktlen += ipsec_out_extra_length(ixa);

		if (pktlen > IP_MAXPACKET)
			return (EMSGSIZE);

		if (ixaflags & IXAF_SET_ULP_CKSUM) {
			/*
			 * Compute ULP checksum using software
			 */
			if (!ip_output_sw_cksum_v6(mp, ip6h, ixa)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
				ip_drop_output("ipIfStatsOutDiscards", mp, ill);
				freemsg(mp);
				return (EINVAL);
			}
			/* Avoid checksum again below if we only add fraghdr */
			ixaflags &= ~IXAF_SET_ULP_CKSUM;
		}

		/*
		 * If we need a fragment header, pick the ident and insert
		 * the header before IPsec to we have a place to store
		 * the ident value.
		 */
		if ((ixaflags & IXAF_IPV6_ADD_FRAGHDR) ||
		    pktlen > ixa->ixa_fragsize) {
			/*
			 * If this packet would generate a icmp_frag_needed
			 * message, we need to handle it before we do the IPsec
			 * processing. Otherwise, we need to strip the IPsec
			 * headers before we send up the message to the ULPs
			 * which becomes messy and difficult.
			 */
			if ((pktlen > ixa->ixa_fragsize) &&
			    (ixaflags & IXAF_DONTFRAG)) {
				/* Generate ICMP and return error */
				ip_recv_attr_t	iras;

				DTRACE_PROBE4(ip6__fragsize__fail,
				    uint_t, pktlen, uint_t, ixa->ixa_fragsize,
				    uint_t, ixa->ixa_pktlen,
				    uint_t, ixa->ixa_pmtu);

				bzero(&iras, sizeof (iras));
				/* Map ixa to ira including IPsec policies */
				ipsec_out_to_in(ixa, ill, &iras);

				ip_drop_output("ICMP6_PKT_TOO_BIG", mp, ill);
				icmp_pkt2big_v6(mp, ixa->ixa_fragsize, B_TRUE,
				    &iras);
				/* We moved any IPsec refs from ixa to iras */
				ira_cleanup(&iras, B_FALSE);
				return (EMSGSIZE);
			}
			DTRACE_PROBE4(ip6__fragsize__ok, uint_t, pktlen,
			    uint_t, ixa->ixa_fragsize, uint_t, ixa->ixa_pktlen,
			    uint_t, ixa->ixa_pmtu);
			/*
			 * Assign an ident value for this packet. There could
			 * be other threads targeting the same destination, so
			 * we have to arrange for a atomic increment.
			 * Normally ixa_extra_ident is 0, but in the case of
			 * LSO it will be the number of TCP segments  that the
			 * driver/hardware will extraly construct.
			 *
			 * Note that cl_inet_ipident has only been used for
			 * IPv4. We don't use it here.
			 */
			ident = atomic_add_32_nv(identp, ixa->ixa_extra_ident +
			    1);
			ixa->ixa_ident = ident;	/* In case we do IPsec */
		}
		if (ixaflags & IXAF_IPSEC_SECURE) {
			/*
			 * Pass in sufficient information so that
			 * IPsec can determine whether to fragment, and
			 * which function to call after fragmentation.
			 */
			return (ipsec_out_process(mp, ixa));
		}

		mp = ip_fraghdr_add_v6(mp, ident, ixa);
		if (mp == NULL) {
			/* MIB and ip_drop_output already done */
			return (ENOMEM);
		}
		ASSERT(pktlen == ixa->ixa_pktlen);
		pktlen += sizeof (ip6_frag_t);

		if (pktlen > ixa->ixa_fragsize) {
			return (ip_fragment_v6(mp, ixa->ixa_nce, ixaflags,
			    pktlen, ixa->ixa_fragsize,
			    ixa->ixa_xmit_hint, ixa->ixa_zoneid,
			    ixa->ixa_no_loop_zoneid, ixa->ixa_postfragfn,
			    &ixa->ixa_cookie));
		}
	}
	if (ixaflags & IXAF_SET_ULP_CKSUM) {
		/* Compute ULP checksum and IP header checksum */
		/* An IS_UNDER_IPMP ill is ok here */
		if (!ip_output_cksum_v6(ixaflags, mp, ip6h, ixa, ill)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", mp, ill);
			freemsg(mp);
			return (EINVAL);
		}
	}
	return ((ixa->ixa_postfragfn)(mp, ixa->ixa_nce, ixaflags,
	    pktlen, ixa->ixa_xmit_hint, ixa->ixa_zoneid,
	    ixa->ixa_no_loop_zoneid, &ixa->ixa_cookie));
}

/*
 * Post fragmentation function for RTF_MULTIRT routes.
 * Since IRE_MULTICASTs might have RTF_MULTIRT, this function
 * checks IXAF_LOOPBACK_COPY.
 *
 * If no packet is sent due to failures then we return an errno, but if at
 * least one succeeded we return zero.
 */
int
ip_postfrag_multirt_v6(mblk_t *mp, nce_t *nce, iaflags_t ixaflags,
    uint_t pkt_len, uint32_t xmit_hint, zoneid_t szone, zoneid_t nolzid,
    uintptr_t *ixacookie)
{
	irb_t		*irb;
	ip6_t		*ip6h = (ip6_t *)mp->b_rptr;
	ire_t		*ire;
	ire_t		*ire1;
	mblk_t		*mp1;
	nce_t		*nce1;
	ill_t		*ill = nce->nce_ill;
	ill_t		*ill1;
	ip_stack_t	*ipst = ill->ill_ipst;
	int		error = 0;
	int		num_sent = 0;
	int		err;
	uint_t		ire_type;
	in6_addr_t	nexthop;

	ASSERT(!(ixaflags & IXAF_IS_IPV4));

	/* Check for IXAF_LOOPBACK_COPY */
	if (ixaflags & IXAF_LOOPBACK_COPY) {
		mblk_t *mp1;

		mp1 = copymsg(mp);
		if (mp1 == NULL) {
			/* Failed to deliver the loopback copy. */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", mp, ill);
			error = ENOBUFS;
		} else {
			ip_postfrag_loopback(mp1, nce, ixaflags, pkt_len,
			    nolzid);
		}
	}

	/*
	 * Loop over RTF_MULTIRT for ip6_dst in the same bucket. Send
	 * a copy to each one.
	 * Use the nce (nexthop) and ip6_dst to find the ire.
	 *
	 * MULTIRT is not designed to work with shared-IP zones thus we don't
	 * need to pass a zoneid or a label to the IRE lookup.
	 */
	if (IN6_ARE_ADDR_EQUAL(&nce->nce_addr, &ip6h->ip6_dst)) {
		/* Broadcast and multicast case */
		ire = ire_ftable_lookup_v6(&ip6h->ip6_dst, 0, 0, 0, NULL,
		    ALL_ZONES, NULL, MATCH_IRE_DSTONLY, 0, ipst, NULL);
	} else {
		/* Unicast case */
		ire = ire_ftable_lookup_v6(&ip6h->ip6_dst, 0, &nce->nce_addr,
		    0, NULL, ALL_ZONES, NULL, MATCH_IRE_GW, 0, ipst, NULL);
	}

	if (ire == NULL ||
	    (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    !(ire->ire_flags & RTF_MULTIRT)) {
		/* Drop */
		ip_drop_output("ip_postfrag_multirt didn't find route",
		    mp, nce->nce_ill);
		if (ire != NULL)
			ire_refrele(ire);
		return (ENETUNREACH);
	}

	irb = ire->ire_bucket;
	irb_refhold(irb);
	for (ire1 = irb->irb_ire; ire1 != NULL; ire1 = ire1->ire_next) {
		if (IRE_IS_CONDEMNED(ire1) ||
		    !(ire1->ire_flags & RTF_MULTIRT))
			continue;

		/* Note: When IPv6 uses radix tree we don't need this check */
		if (!IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6, &ire1->ire_addr_v6))
			continue;

		/* Do the ire argument one after the loop */
		if (ire1 == ire)
			continue;

		ill1 = ire_nexthop_ill(ire1);
		if (ill1 == NULL) {
			/*
			 * This ire might not have been picked by
			 * ire_route_recursive, in which case ire_dep might
			 * not have been setup yet.
			 * We kick ire_route_recursive to try to resolve
			 * starting at ire1.
			 */
			ire_t *ire2;
			uint_t match_flags = MATCH_IRE_DSTONLY;

			if (ire1->ire_ill != NULL)
				match_flags |= MATCH_IRE_ILL;
			ire2 = ire_route_recursive_impl_v6(ire1,
			    &ire1->ire_addr_v6, ire1->ire_type, ire1->ire_ill,
			    ire1->ire_zoneid, NULL, match_flags,
			    IRR_ALLOCATE, 0, ipst, NULL, NULL, NULL);
			if (ire2 != NULL)
				ire_refrele(ire2);
			ill1 = ire_nexthop_ill(ire1);
		}
		if (ill1 == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards - no ill",
			    mp, ill);
			error = ENETUNREACH;
			continue;
		}
		/* Pick the addr and type to use for ndp_nce_init */
		if (nce->nce_common->ncec_flags & NCE_F_MCAST) {
			ire_type = IRE_MULTICAST;
			nexthop = ip6h->ip6_dst;
		} else {
			ire_type = ire1->ire_type;	/* Doesn't matter */
			nexthop = ire1->ire_gateway_addr_v6;
		}

		/* If IPMP meta or under, then we just drop */
		if (ill1->ill_grp != NULL) {
			BUMP_MIB(ill1->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards - IPMP",
			    mp, ill1);
			ill_refrele(ill1);
			error = ENETUNREACH;
			continue;
		}

		nce1 = ndp_nce_init(ill1, &nexthop, ire_type);
		if (nce1 == NULL) {
			BUMP_MIB(ill1->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards - no nce",
			    mp, ill1);
			ill_refrele(ill1);
			error = ENOBUFS;
			continue;
		}
		mp1 = copymsg(mp);
		if (mp1 == NULL) {
			BUMP_MIB(ill1->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", mp, ill1);
			nce_refrele(nce1);
			ill_refrele(ill1);
			error = ENOBUFS;
			continue;
		}
		/* Preserve HW checksum for this copy */
		DB_CKSUMSTART(mp1) = DB_CKSUMSTART(mp);
		DB_CKSUMSTUFF(mp1) = DB_CKSUMSTUFF(mp);
		DB_CKSUMEND(mp1) = DB_CKSUMEND(mp);
		DB_CKSUMFLAGS(mp1) = DB_CKSUMFLAGS(mp);
		DB_LSOMSS(mp1) = DB_LSOMSS(mp);

		ire1->ire_ob_pkt_count++;
		err = ip_xmit(mp1, nce1, ixaflags, pkt_len, xmit_hint, szone,
		    0, ixacookie);
		if (err == 0)
			num_sent++;
		else
			error = err;
		nce_refrele(nce1);
		ill_refrele(ill1);
	}
	irb_refrele(irb);
	ire_refrele(ire);
	/* Finally, the main one */
	err = ip_xmit(mp, nce, ixaflags, pkt_len, xmit_hint, szone, 0,
	    ixacookie);
	if (err == 0)
		num_sent++;
	else
		error = err;
	if (num_sent > 0)
		return (0);
	else
		return (error);
}
