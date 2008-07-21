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
/*
 * Copyright (c) 1990 Mentat Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <sys/strlog.h>
#include <sys/strsubr.h>
#define	_SUN_TPI_VERSION	2
#include <sys/tihdr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/sdt.h>
#include <sys/kobj.h>
#include <sys/zone.h>
#include <sys/neti.h>
#include <sys/hook.h>

#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/vtrace.h>
#include <sys/isa_defs.h>
#include <sys/atomic.h>
#include <sys/iphada.h>
#include <sys/policy.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/sctp.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/optcom.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/arp.h>

#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip6_asp.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/udp_impl.h>
#include <inet/ipp_common.h>

#include <inet/ip_multi.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <inet/ip_ndp.h>
#include <net/pfkeyv2.h>
#include <inet/ipsec_info.h>
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <inet/tun.h>
#include <inet/sctp_ip.h>
#include <sys/pattr.h>
#include <inet/ipclassifier.h>
#include <inet/ipsecah.h>
#include <inet/udp_impl.h>
#include <inet/rawip_impl.h>
#include <inet/rts_impl.h>
#include <sys/squeue.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#include <rpc/pmap_prot.h>

/* Temporary; for CR 6451644 work-around */
#include <sys/ethernet.h>

extern squeue_func_t ip_input_proc;

/*
 * Naming conventions:
 *      These rules should be judiciously applied
 *	if there is a need to identify something as IPv6 versus IPv4
 *	IPv6 funcions will end with _v6 in the ip module.
 *	IPv6 funcions will end with _ipv6 in the transport modules.
 *	IPv6 macros:
 *		Some macros end with _V6; e.g. ILL_FRAG_HASH_V6
 *		Some macros start with V6_; e.g. V6_OR_V4_INADDR_ANY
 *		And then there are ..V4_PART_OF_V6.
 *		The intent is that macros in the ip module end with _V6.
 *	IPv6 global variables will start with ipv6_
 *	IPv6 structures will start with ipv6
 *	IPv6 defined constants should start with IPV6_
 *		(but then there are NDP_DEFAULT_VERS_PRI_AND_FLOW, etc)
 */

/*
 * ip6opt_ls is used to enable IPv6 (via /etc/system on TX systems).
 * We need to do this because we didn't obtain the IP6OPT_LS (0x0a)
 * from IANA. This mechanism will remain in effect until an official
 * number is obtained.
 */
uchar_t ip6opt_ls;

const in6_addr_t ipv6_all_ones =
	{ 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU };
const in6_addr_t ipv6_all_zeros = { 0, 0, 0, 0 };

#ifdef	_BIG_ENDIAN
const in6_addr_t ipv6_unspecified_group = { 0xff000000U, 0, 0, 0 };
#else	/* _BIG_ENDIAN */
const in6_addr_t ipv6_unspecified_group = { 0x000000ffU, 0, 0, 0 };
#endif	/* _BIG_ENDIAN */

#ifdef	_BIG_ENDIAN
const in6_addr_t ipv6_loopback = { 0, 0, 0, 0x00000001U };
#else  /* _BIG_ENDIAN */
const in6_addr_t ipv6_loopback = { 0, 0, 0, 0x01000000U };
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
const in6_addr_t ipv6_all_hosts_mcast = { 0xff020000U, 0, 0, 0x00000001U };
#else  /* _BIG_ENDIAN */
const in6_addr_t ipv6_all_hosts_mcast = { 0x000002ffU, 0, 0, 0x01000000U };
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
const in6_addr_t ipv6_all_rtrs_mcast = { 0xff020000U, 0, 0, 0x00000002U };
#else  /* _BIG_ENDIAN */
const in6_addr_t ipv6_all_rtrs_mcast = { 0x000002ffU, 0, 0, 0x02000000U };
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
const in6_addr_t ipv6_all_v2rtrs_mcast = { 0xff020000U, 0, 0, 0x00000016U };
#else  /* _BIG_ENDIAN */
const in6_addr_t ipv6_all_v2rtrs_mcast = { 0x000002ffU, 0, 0, 0x16000000U };
#endif /* _BIG_ENDIAN */

#ifdef _BIG_ENDIAN
const in6_addr_t ipv6_solicited_node_mcast =
			{ 0xff020000U, 0, 0x00000001U, 0xff000000U };
#else  /* _BIG_ENDIAN */
const in6_addr_t ipv6_solicited_node_mcast =
			{ 0x000002ffU, 0, 0x01000000U, 0x000000ffU };
#endif /* _BIG_ENDIAN */

/* Leave room for ip_newroute to tack on the src and target addresses */
#define	OK_RESOLVER_MP_V6(mp)						\
		((mp) && ((mp)->b_wptr - (mp)->b_rptr) >= (2 * IPV6_ADDR_LEN))

#define	IP6_MBLK_OK		0
#define	IP6_MBLK_HDR_ERR	1
#define	IP6_MBLK_LEN_ERR	2

static void	icmp_inbound_too_big_v6(queue_t *, mblk_t *, ill_t *ill,
    boolean_t, zoneid_t);
static void	icmp_pkt_v6(queue_t *, mblk_t *, void *, size_t,
    const in6_addr_t *, boolean_t, zoneid_t, ip_stack_t *);
static void	icmp_redirect_v6(queue_t *, mblk_t *, ill_t *ill);
static int	ip_bind_connected_v6(conn_t *, mblk_t *, in6_addr_t *,
    uint16_t, const in6_addr_t *, ip6_pkt_t *, uint16_t,
    boolean_t, boolean_t, boolean_t, boolean_t);
static boolean_t ip_bind_insert_ire_v6(mblk_t *, ire_t *, const in6_addr_t *,
    iulp_t *, ip_stack_t *);
static int	ip_bind_laddr_v6(conn_t *, mblk_t *, const in6_addr_t *,
    uint16_t, boolean_t, boolean_t, boolean_t);
static void	ip_fanout_proto_v6(queue_t *, mblk_t *, ip6_t *, ill_t *,
    ill_t *, uint8_t, uint_t, uint_t, boolean_t, zoneid_t);
static void	ip_fanout_tcp_v6(queue_t *, mblk_t *, ip6_t *, ill_t *,
    ill_t *, uint_t, uint_t, boolean_t, zoneid_t);
static void	ip_fanout_udp_v6(queue_t *, mblk_t *, ip6_t *, uint32_t,
    ill_t *, ill_t *, uint_t, boolean_t, zoneid_t);
static int	ip_process_options_v6(queue_t *, mblk_t *, ip6_t *,
    uint8_t *, uint_t, uint8_t, ip_stack_t *);
static mblk_t	*ip_rput_frag_v6(queue_t *, mblk_t *, ip6_t *,
    ip6_frag_t *, uint_t, uint_t *, uint32_t *, uint16_t *);
static boolean_t	ip_source_routed_v6(ip6_t *, mblk_t *, ip_stack_t *);
static void	ip_wput_ire_v6(queue_t *, mblk_t *, ire_t *, int, int,
    conn_t *, int, int, int, zoneid_t);

/*
 * A template for an IPv6 AR_ENTRY_QUERY
 */
static areq_t	ipv6_areq_template = {
	AR_ENTRY_QUERY,				/* cmd */
	sizeof (areq_t)+(2*IPV6_ADDR_LEN),	/* name offset */
	sizeof (areq_t),	/* name len (filled by ill_arp_alloc) */
	IP6_DL_SAP,		/* protocol, from arps perspective */
	sizeof (areq_t),	/* target addr offset */
	IPV6_ADDR_LEN,		/* target addr_length */
	0,			/* flags */
	sizeof (areq_t) + IPV6_ADDR_LEN,	/* sender addr offset */
	IPV6_ADDR_LEN,		/* sender addr length */
	6,			/* xmit_count */
	1000,			/* (re)xmit_interval in milliseconds */
	4			/* max # of requests to buffer */
	/* anything else filled in by the code */
};

/*
 * Handle IPv6 ICMP packets sent to us.  Consume the mblk passed in.
 * The message has already been checksummed and if needed,
 * a copy has been made to be sent any interested ICMP client (conn)
 * Note that this is different than icmp_inbound() which does the fanout
 * to conn's as well as local processing of the ICMP packets.
 *
 * All error messages are passed to the matching transport stream.
 *
 * Zones notes:
 * The packet is only processed in the context of the specified zone: typically
 * only this zone will reply to an echo request. This means that the caller must
 * call icmp_inbound_v6() for each relevant zone.
 */
static void
icmp_inbound_v6(queue_t *q, mblk_t *mp, ill_t *ill, uint_t hdr_length,
    boolean_t mctl_present, uint_t flags, zoneid_t zoneid, mblk_t *dl_mp)
{
	icmp6_t		*icmp6;
	ip6_t		*ip6h;
	boolean_t	interested;
	ip6i_t		*ip6i;
	in6_addr_t	origsrc;
	ire_t		*ire;
	mblk_t		*first_mp;
	ipsec_in_t	*ii;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ill != NULL);
	first_mp = mp;
	if (mctl_present) {
		mp = first_mp->b_cont;
		ASSERT(mp != NULL);

		ii = (ipsec_in_t *)first_mp->b_rptr;
		ASSERT(ii->ipsec_in_type == IPSEC_IN);
	}

	ip6h = (ip6_t *)mp->b_rptr;

	BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInMsgs);

	if ((mp->b_wptr - mp->b_rptr) < (hdr_length + ICMP6_MINLEN)) {
		if (!pullupmsg(mp, hdr_length + ICMP6_MINLEN)) {
			ip1dbg(("icmp_inbound_v6: pullupmsg failed\n"));
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInErrors);
			freemsg(first_mp);
			return;
		}
		ip6h = (ip6_t *)mp->b_rptr;
	}
	if (ipst->ips_icmp_accept_clear_messages == 0) {
		first_mp = ipsec_check_global_policy(first_mp, NULL,
		    NULL, ip6h, mctl_present, ipst->ips_netstack);
		if (first_mp == NULL)
			return;
	}

	/*
	 * On a labeled system, we have to check whether the zone itself is
	 * permitted to receive raw traffic.
	 */
	if (is_system_labeled()) {
		if (zoneid == ALL_ZONES)
			zoneid = tsol_packet_to_zoneid(mp);
		if (!tsol_can_accept_raw(mp, B_FALSE)) {
			ip1dbg(("icmp_inbound_v6: zone %d can't receive raw",
			    zoneid));
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInErrors);
			freemsg(first_mp);
			return;
		}
	}

	icmp6 = (icmp6_t *)(&mp->b_rptr[hdr_length]);
	ip2dbg(("icmp_inbound_v6: type %d code %d\n", icmp6->icmp6_type,
	    icmp6->icmp6_code));
	interested = !(icmp6->icmp6_type & ICMP6_INFOMSG_MASK);

	/* Initiate IPPF processing here */
	if (IP6_IN_IPP(flags, ipst)) {

		/*
		 * If the ifindex changes due to SIOCSLIFINDEX
		 * packet may return to IP on the wrong ill.
		 */
		ip_process(IPP_LOCAL_IN, &mp, ill->ill_phyint->phyint_ifindex);
		if (mp == NULL) {
			if (mctl_present) {
				freeb(first_mp);
			}
			return;
		}
	}

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInDestUnreachs);
		if (icmp6->icmp6_code == ICMP6_DST_UNREACH_ADMIN)
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInAdminProhibs);
		break;

	case ICMP6_TIME_EXCEEDED:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInTimeExcds);
		break;

	case ICMP6_PARAM_PROB:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInParmProblems);
		break;

	case ICMP6_PACKET_TOO_BIG:
		icmp_inbound_too_big_v6(q, first_mp, ill, mctl_present,
		    zoneid);
		return;
	case ICMP6_ECHO_REQUEST:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInEchos);
		if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst) &&
		    !ipst->ips_ipv6_resp_echo_mcast)
			break;

		/*
		 * We must have exclusive use of the mblk to convert it to
		 * a response.
		 * If not, we copy it.
		 */
		if (mp->b_datap->db_ref > 1) {
			mblk_t	*mp1;

			mp1 = copymsg(mp);
			freemsg(mp);
			if (mp1 == NULL) {
				BUMP_MIB(ill->ill_icmp6_mib,
				    ipv6IfIcmpInErrors);
				if (mctl_present)
					freeb(first_mp);
				return;
			}
			mp = mp1;
			ip6h = (ip6_t *)mp->b_rptr;
			icmp6 = (icmp6_t *)(&mp->b_rptr[hdr_length]);
			if (mctl_present)
				first_mp->b_cont = mp;
			else
				first_mp = mp;
		}

		/*
		 * Turn the echo into an echo reply.
		 * Remove any extension headers (do not reverse a source route)
		 * and clear the flow id (keep traffic class for now).
		 */
		if (hdr_length != IPV6_HDR_LEN) {
			int	i;

			for (i = 0; i < IPV6_HDR_LEN; i++)
				mp->b_rptr[hdr_length - i - 1] =
				    mp->b_rptr[IPV6_HDR_LEN - i - 1];
			mp->b_rptr += (hdr_length - IPV6_HDR_LEN);
			ip6h = (ip6_t *)mp->b_rptr;
			ip6h->ip6_nxt = IPPROTO_ICMPV6;
			hdr_length = IPV6_HDR_LEN;
		}
		ip6h->ip6_vcf &= ~IPV6_FLOWINFO_FLOWLABEL;
		icmp6->icmp6_type = ICMP6_ECHO_REPLY;

		ip6h->ip6_plen =
		    htons((uint16_t)(msgdsize(mp) - IPV6_HDR_LEN));
		origsrc = ip6h->ip6_src;
		/*
		 * Reverse the source and destination addresses.
		 * If the return address is a multicast, zero out the source
		 * (ip_wput_v6 will set an address).
		 */
		if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
			ip6h->ip6_src = ipv6_all_zeros;
			ip6h->ip6_dst = origsrc;
		} else {
			ip6h->ip6_src = ip6h->ip6_dst;
			ip6h->ip6_dst = origsrc;
		}

		/* set the hop limit */
		ip6h->ip6_hops = ipst->ips_ipv6_def_hops;

		/*
		 * Prepare for checksum by putting icmp length in the icmp
		 * checksum field. The checksum is calculated in ip_wput_v6.
		 */
		icmp6->icmp6_cksum = ip6h->ip6_plen;
		/*
		 * ICMP echo replies should go out on the same interface
		 * the request came on as probes used by in.mpathd for
		 * detecting NIC failures are ECHO packets. We turn-off load
		 * spreading by allocating a ip6i and setting ip6i_attach_if
		 * to B_TRUE which is handled both by ip_wput_v6 and
		 * ip_newroute_v6. If we don't turnoff load spreading,
		 * the packets might get dropped if there are no
		 * non-FAILED/INACTIVE interfaces for it to go out on and
		 * in.mpathd would wrongly detect a failure or mis-detect
		 * a NIC failure as a link failure. As load spreading can
		 * happen only if ill_group is not NULL, we do only for
		 * that case and this does not affect the normal case.
		 *
		 * We force this only on echo packets that came from on-link
		 * hosts. We restrict this to link-local addresses which
		 * is used by in.mpathd for probing. In the IPv6 case,
		 * default routes typically have an ire_ipif pointer and
		 * hence a MATCH_IRE_ILL later in ip_newroute_v6/ip_wput_v6
		 * might work. As a default route out of this interface
		 * may not be present, enforcing this packet to go out in
		 * this case may not work.
		 */
		if (ill->ill_group != NULL &&
		    IN6_IS_ADDR_LINKLOCAL(&origsrc)) {
			/*
			 * If we are sending replies to ourselves, don't
			 * set ATTACH_IF as we may not be able to find
			 * the IRE_LOCAL on this ill i.e setting ATTACH_IF
			 * causes ip_wput_v6 to look for an IRE_LOCAL on
			 * "ill" which it may not find and will try to
			 * create an IRE_CACHE for our local address. Once
			 * we do this, we will try to forward all packets
			 * meant to our LOCAL address.
			 */
			ire = ire_cache_lookup_v6(&ip6h->ip6_dst, ALL_ZONES,
			    NULL, ipst);
			if (ire == NULL || ire->ire_type != IRE_LOCAL) {
				mp = ip_add_info_v6(mp, NULL, &ip6h->ip6_dst);
				if (mp == NULL) {
					BUMP_MIB(ill->ill_icmp6_mib,
					    ipv6IfIcmpInErrors);
					if (ire != NULL)
						ire_refrele(ire);
					if (mctl_present)
						freeb(first_mp);
					return;
				} else if (mctl_present) {
					first_mp->b_cont = mp;
				} else {
					first_mp = mp;
				}
				ip6i = (ip6i_t *)mp->b_rptr;
				ip6i->ip6i_flags = IP6I_ATTACH_IF;
				ip6i->ip6i_ifindex =
				    ill->ill_phyint->phyint_ifindex;
			}
			if (ire != NULL)
				ire_refrele(ire);
		}

		if (!mctl_present) {
			/*
			 * This packet should go out the same way as it
			 * came in i.e in clear. To make sure that global
			 * policy will not be applied to this in ip_wput,
			 * we attach a IPSEC_IN mp and clear ipsec_in_secure.
			 */
			ASSERT(first_mp == mp);
			first_mp = ipsec_in_alloc(B_FALSE, ipst->ips_netstack);
			if (first_mp == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				freemsg(mp);
				return;
			}
			ii = (ipsec_in_t *)first_mp->b_rptr;

			/* This is not a secure packet */
			ii->ipsec_in_secure = B_FALSE;
			first_mp->b_cont = mp;
		}
		ii->ipsec_in_zoneid = zoneid;
		ASSERT(zoneid != ALL_ZONES);
		if (!ipsec_in_to_out(first_mp, NULL, ip6h)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			return;
		}
		put(WR(q), first_mp);
		return;

	case ICMP6_ECHO_REPLY:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInEchoReplies);
		break;

	case ND_ROUTER_SOLICIT:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInRouterSolicits);
		break;

	case ND_ROUTER_ADVERT:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInRouterAdvertisements);
		break;

	case ND_NEIGHBOR_SOLICIT:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInNeighborSolicits);
		if (mctl_present)
			freeb(first_mp);
		/* XXX may wish to pass first_mp up to ndp_input someday. */
		ndp_input(ill, mp, dl_mp);
		return;

	case ND_NEIGHBOR_ADVERT:
		BUMP_MIB(ill->ill_icmp6_mib,
		    ipv6IfIcmpInNeighborAdvertisements);
		if (mctl_present)
			freeb(first_mp);
		/* XXX may wish to pass first_mp up to ndp_input someday. */
		ndp_input(ill, mp, dl_mp);
		return;

	case ND_REDIRECT: {
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInRedirects);

		if (ipst->ips_ipv6_ignore_redirect)
			break;

		/*
		 * As there is no upper client to deliver, we don't
		 * need the first_mp any more.
		 */
		if (mctl_present)
			freeb(first_mp);
		if (!pullupmsg(mp, -1)) {
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
			break;
		}
		icmp_redirect_v6(q, mp, ill);
		return;
	}

	/*
	 * The next three icmp messages will be handled by MLD.
	 * Pass all valid MLD packets up to any process(es)
	 * listening on a raw ICMP socket. MLD messages are
	 * freed by mld_input function.
	 */
	case MLD_LISTENER_QUERY:
	case MLD_LISTENER_REPORT:
	case MLD_LISTENER_REDUCTION:
		if (mctl_present)
			freeb(first_mp);
		mld_input(q, mp, ill);
		return;
	default:
		break;
	}
	if (interested) {
		icmp_inbound_error_fanout_v6(q, first_mp, ip6h, icmp6, ill,
		    mctl_present, zoneid);
	} else {
		freemsg(first_mp);
	}
}

/*
 * Process received IPv6 ICMP Packet too big.
 * After updating any IRE it does the fanout to any matching transport streams.
 * Assumes the IPv6 plus ICMPv6 headers have been pulled up but nothing else.
 */
/* ARGSUSED */
static void
icmp_inbound_too_big_v6(queue_t *q, mblk_t *mp, ill_t *ill,
    boolean_t mctl_present, zoneid_t zoneid)
{
	ip6_t		*ip6h;
	ip6_t		*inner_ip6h;
	icmp6_t		*icmp6;
	uint16_t	hdr_length;
	uint32_t	mtu;
	ire_t		*ire, *first_ire;
	mblk_t		*first_mp;
	ip_stack_t	*ipst = ill->ill_ipst;

	first_mp = mp;
	if (mctl_present)
		mp = first_mp->b_cont;
	/*
	 * We must have exclusive use of the mblk to update the MTU
	 * in the packet.
	 * If not, we copy it.
	 *
	 * If there's an M_CTL present, we know that allocated first_mp
	 * earlier in this function, so we know first_mp has refcnt of one.
	 */
	ASSERT(!mctl_present || first_mp->b_datap->db_ref == 1);
	if (mp->b_datap->db_ref > 1) {
		mblk_t	*mp1;

		mp1 = copymsg(mp);
		freemsg(mp);
		if (mp1 == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			if (mctl_present)
				freeb(first_mp);
			return;
		}
		mp = mp1;
		if (mctl_present)
			first_mp->b_cont = mp;
		else
			first_mp = mp;
	}
	ip6h = (ip6_t *)mp->b_rptr;
	if (ip6h->ip6_nxt != IPPROTO_ICMPV6)
		hdr_length = ip_hdr_length_v6(mp, ip6h);
	else
		hdr_length = IPV6_HDR_LEN;

	icmp6 = (icmp6_t *)(&mp->b_rptr[hdr_length]);
	ASSERT((size_t)(mp->b_wptr - mp->b_rptr) >= hdr_length + ICMP6_MINLEN);
	inner_ip6h = (ip6_t *)&icmp6[1];	/* Packet in error */
	if ((uchar_t *)&inner_ip6h[1] > mp->b_wptr) {
		if (!pullupmsg(mp, (uchar_t *)&inner_ip6h[1] - mp->b_rptr)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(first_mp);
			return;
		}
		ip6h = (ip6_t *)mp->b_rptr;
		icmp6 = (icmp6_t *)&mp->b_rptr[hdr_length];
		inner_ip6h = (ip6_t *)&icmp6[1];
	}

	/*
	 * For link local destinations matching simply on IRE type is not
	 * sufficient. Same link local addresses for different ILL's is
	 * possible.
	 */

	if (IN6_IS_ADDR_LINKLOCAL(&inner_ip6h->ip6_dst)) {
		first_ire = ire_ctable_lookup_v6(&inner_ip6h->ip6_dst, NULL,
		    IRE_CACHE, ill->ill_ipif, ALL_ZONES, NULL,
		    MATCH_IRE_TYPE | MATCH_IRE_ILL_GROUP, ipst);

		if (first_ire == NULL) {
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("icmp_inbound_too_big_v6:"
				    "no ire for dst %s\n", AF_INET6,
				    &inner_ip6h->ip6_dst);
			}
			freemsg(first_mp);
			return;
		}

		mtu = ntohl(icmp6->icmp6_mtu);
		rw_enter(&first_ire->ire_bucket->irb_lock, RW_READER);
		for (ire = first_ire; ire != NULL &&
		    IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6, &inner_ip6h->ip6_dst);
		    ire = ire->ire_next) {
			mutex_enter(&ire->ire_lock);
			if (mtu < IPV6_MIN_MTU) {
				ip1dbg(("Received mtu less than IPv6 "
				    "min mtu %d: %d\n", IPV6_MIN_MTU, mtu));
				mtu = IPV6_MIN_MTU;
				/*
				 * If an mtu less than IPv6 min mtu is received,
				 * we must include a fragment header in
				 * subsequent packets.
				 */
				ire->ire_frag_flag |= IPH_FRAG_HDR;
			}
			ip1dbg(("Received mtu from router: %d\n", mtu));
			ire->ire_max_frag = MIN(ire->ire_max_frag, mtu);
			/* Record the new max frag size for the ULP. */
			if (ire->ire_frag_flag & IPH_FRAG_HDR) {
				/*
				 * If we need a fragment header in every packet
				 * (above case or multirouting), make sure the
				 * ULP takes it into account when computing the
				 * payload size.
				 */
				icmp6->icmp6_mtu = htonl(ire->ire_max_frag -
				    sizeof (ip6_frag_t));
			} else {
				icmp6->icmp6_mtu = htonl(ire->ire_max_frag);
			}
			mutex_exit(&ire->ire_lock);
		}
		rw_exit(&first_ire->ire_bucket->irb_lock);
		ire_refrele(first_ire);
	} else {
		irb_t	*irb = NULL;
		/*
		 * for non-link local destinations we match only on the IRE type
		 */
		ire = ire_ctable_lookup_v6(&inner_ip6h->ip6_dst, NULL,
		    IRE_CACHE, ill->ill_ipif, ALL_ZONES, NULL, MATCH_IRE_TYPE,
		    ipst);
		if (ire == NULL) {
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("icmp_inbound_too_big_v6:"
				    "no ire for dst %s\n",
				    AF_INET6, &inner_ip6h->ip6_dst);
			}
			freemsg(first_mp);
			return;
		}
		irb = ire->ire_bucket;
		ire_refrele(ire);
		rw_enter(&irb->irb_lock, RW_READER);
		for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
			if (IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6,
			    &inner_ip6h->ip6_dst)) {
				mtu = ntohl(icmp6->icmp6_mtu);
				mutex_enter(&ire->ire_lock);
				if (mtu < IPV6_MIN_MTU) {
					ip1dbg(("Received mtu less than IPv6"
					    "min mtu %d: %d\n",
					    IPV6_MIN_MTU, mtu));
					mtu = IPV6_MIN_MTU;
					/*
					 * If an mtu less than IPv6 min mtu is
					 * received, we must include a fragment
					 * header in subsequent packets.
					 */
					ire->ire_frag_flag |= IPH_FRAG_HDR;
				}

				ip1dbg(("Received mtu from router: %d\n", mtu));
				ire->ire_max_frag = MIN(ire->ire_max_frag, mtu);
				/* Record the new max frag size for the ULP. */
				if (ire->ire_frag_flag & IPH_FRAG_HDR) {
					/*
					 * If we need a fragment header in
					 * every packet (above case or
					 * multirouting), make sure the ULP
					 * takes it into account when computing
					 * the payload size.
					 */
					icmp6->icmp6_mtu =
					    htonl(ire->ire_max_frag -
					    sizeof (ip6_frag_t));
				} else {
					icmp6->icmp6_mtu =
					    htonl(ire->ire_max_frag);
				}
				mutex_exit(&ire->ire_lock);
			}
		}
		rw_exit(&irb->irb_lock);
	}
	icmp_inbound_error_fanout_v6(q, first_mp, ip6h, icmp6, ill,
	    mctl_present, zoneid);
}

/*
 * Fanout received ICMPv6 error packets to the transports.
 * Assumes the IPv6 plus ICMPv6 headers have been pulled up but nothing else.
 */
void
icmp_inbound_error_fanout_v6(queue_t *q, mblk_t *mp, ip6_t *ip6h,
    icmp6_t *icmp6, ill_t *ill, boolean_t mctl_present, zoneid_t zoneid)
{
	uint16_t *up;	/* Pointer to ports in ULP header */
	uint32_t ports;	/* reversed ports for fanout */
	ip6_t rip6h;	/* With reversed addresses */
	uint16_t	hdr_length;
	uint8_t		*nexthdrp;
	uint8_t		nexthdr;
	mblk_t *first_mp;
	ipsec_in_t *ii;
	tcpha_t	*tcpha;
	conn_t	*connp;
	ip_stack_t	*ipst = ill->ill_ipst;

	first_mp = mp;
	if (mctl_present) {
		mp = first_mp->b_cont;
		ASSERT(mp != NULL);

		ii = (ipsec_in_t *)first_mp->b_rptr;
		ASSERT(ii->ipsec_in_type == IPSEC_IN);
	} else {
		ii = NULL;
	}

	hdr_length = (uint16_t)((uchar_t *)icmp6 - (uchar_t *)ip6h);
	ASSERT((size_t)(mp->b_wptr - (uchar_t *)icmp6) >= ICMP6_MINLEN);

	/*
	 * Need to pullup everything in order to use
	 * ip_hdr_length_nexthdr_v6()
	 */
	if (mp->b_cont != NULL) {
		if (!pullupmsg(mp, -1)) {
			ip1dbg(("icmp_inbound_error_fanout_v6: "
			    "pullupmsg failed\n"));
			goto drop_pkt;
		}
		ip6h = (ip6_t *)mp->b_rptr;
		icmp6 = (icmp6_t *)(&mp->b_rptr[hdr_length]);
	}

	ip6h = (ip6_t *)&icmp6[1];	/* Packet in error */
	if ((uchar_t *)&ip6h[1] > mp->b_wptr)
		goto drop_pkt;

	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &hdr_length, &nexthdrp))
		goto drop_pkt;
	nexthdr = *nexthdrp;

	/* Set message type, must be done after pullups */
	mp->b_datap->db_type = M_CTL;

	/* Try to pass the ICMP message to clients who need it */
	switch (nexthdr) {
	case IPPROTO_UDP: {
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * UDP header to get the port information.
		 */
		if ((uchar_t *)ip6h + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr) {
			break;
		}
		/*
		 * Attempt to find a client stream based on port.
		 * Note that we do a reverse lookup since the header is
		 * in the form we sent it out.
		 * The rip6h header is only used for the IPCL_UDP_MATCH_V6
		 * and we only set the src and dst addresses and nexthdr.
		 */
		up = (uint16_t *)((uchar_t *)ip6h + hdr_length);
		rip6h.ip6_src = ip6h->ip6_dst;
		rip6h.ip6_dst = ip6h->ip6_src;
		rip6h.ip6_nxt = nexthdr;
		((uint16_t *)&ports)[0] = up[1];
		((uint16_t *)&ports)[1] = up[0];

		ip_fanout_udp_v6(q, first_mp, &rip6h, ports, ill, ill,
		    IP6_NO_IPPOLICY, mctl_present, zoneid);
		return;
	}
	case IPPROTO_TCP: {
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * the TCP header to get the port information.
		 */
		if ((uchar_t *)ip6h + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr) {
			break;
		}

		/*
		 * Attempt to find a client stream based on port.
		 * Note that we do a reverse lookup since the header is
		 * in the form we sent it out.
		 * The rip6h header is only used for the IP_TCP_*MATCH_V6 and
		 * we only set the src and dst addresses and nexthdr.
		 */

		tcpha = (tcpha_t *)((char *)ip6h + hdr_length);
		connp = ipcl_tcp_lookup_reversed_ipv6(ip6h, tcpha,
		    TCPS_LISTEN, ill->ill_phyint->phyint_ifindex, ipst);
		if (connp == NULL) {
			goto drop_pkt;
		}

		squeue_fill(connp->conn_sqp, first_mp, tcp_input,
		    connp, SQTAG_TCP6_INPUT_ICMP_ERR);
		return;

	}
	case IPPROTO_SCTP:
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * the SCTP header to get the port information.
		 */
		if ((uchar_t *)ip6h + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr) {
			break;
		}

		up = (uint16_t *)((uchar_t *)ip6h + hdr_length);
		((uint16_t *)&ports)[0] = up[1];
		((uint16_t *)&ports)[1] = up[0];
		ip_fanout_sctp(first_mp, ill, (ipha_t *)ip6h, ports, 0,
		    mctl_present, IP6_NO_IPPOLICY, zoneid);
		return;
	case IPPROTO_ESP:
	case IPPROTO_AH: {
		int ipsec_rc;
		ipsec_stack_t *ipss = ipst->ips_netstack->netstack_ipsec;

		/*
		 * We need a IPSEC_IN in the front to fanout to AH/ESP.
		 * We will re-use the IPSEC_IN if it is already present as
		 * AH/ESP will not affect any fields in the IPSEC_IN for
		 * ICMP errors. If there is no IPSEC_IN, allocate a new
		 * one and attach it in the front.
		 */
		if (ii != NULL) {
			/*
			 * ip_fanout_proto_again converts the ICMP errors
			 * that come back from AH/ESP to M_DATA so that
			 * if it is non-AH/ESP and we do a pullupmsg in
			 * this function, it would work. Convert it back
			 * to M_CTL before we send up as this is a ICMP
			 * error. This could have been generated locally or
			 * by some router. Validate the inner IPSEC
			 * headers.
			 *
			 * NOTE : ill_index is used by ip_fanout_proto_again
			 * to locate the ill.
			 */
			ASSERT(ill != NULL);
			ii->ipsec_in_ill_index =
			    ill->ill_phyint->phyint_ifindex;
			ii->ipsec_in_rill_index = ii->ipsec_in_ill_index;
			first_mp->b_cont->b_datap->db_type = M_CTL;
		} else {
			/*
			 * IPSEC_IN is not present. We attach a ipsec_in
			 * message and send up to IPSEC for validating
			 * and removing the IPSEC headers. Clear
			 * ipsec_in_secure so that when we return
			 * from IPSEC, we don't mistakenly think that this
			 * is a secure packet came from the network.
			 *
			 * NOTE : ill_index is used by ip_fanout_proto_again
			 * to locate the ill.
			 */
			ASSERT(first_mp == mp);
			first_mp = ipsec_in_alloc(B_FALSE, ipst->ips_netstack);
			ASSERT(ill != NULL);
			if (first_mp == NULL) {
				freemsg(mp);
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				return;
			}
			ii = (ipsec_in_t *)first_mp->b_rptr;

			/* This is not a secure packet */
			ii->ipsec_in_secure = B_FALSE;
			first_mp->b_cont = mp;
			mp->b_datap->db_type = M_CTL;
			ii->ipsec_in_ill_index =
			    ill->ill_phyint->phyint_ifindex;
			ii->ipsec_in_rill_index = ii->ipsec_in_ill_index;
		}

		if (!ipsec_loaded(ipss)) {
			ip_proto_not_sup(q, first_mp, 0, zoneid, ipst);
			return;
		}

		if (nexthdr == IPPROTO_ESP)
			ipsec_rc = ipsecesp_icmp_error(first_mp);
		else
			ipsec_rc = ipsecah_icmp_error(first_mp);
		if (ipsec_rc == IPSEC_STATUS_FAILED)
			return;

		ip_fanout_proto_again(first_mp, ill, ill, NULL);
		return;
	}
	case IPPROTO_ENCAP:
	case IPPROTO_IPV6:
		if ((uint8_t *)ip6h + hdr_length +
		    (nexthdr == IPPROTO_ENCAP ? sizeof (ipha_t) :
		    sizeof (ip6_t)) > mp->b_wptr) {
			goto drop_pkt;
		}

		if (nexthdr == IPPROTO_ENCAP ||
		    !IN6_ARE_ADDR_EQUAL(
		    &((ip6_t *)(((uint8_t *)ip6h) + hdr_length))->ip6_src,
		    &ip6h->ip6_src) ||
		    !IN6_ARE_ADDR_EQUAL(
		    &((ip6_t *)(((uint8_t *)ip6h) + hdr_length))->ip6_dst,
		    &ip6h->ip6_dst)) {
			/*
			 * For tunnels that have used IPsec protection,
			 * we need to adjust the MTU to take into account
			 * the IPsec overhead.
			 */
			if (ii != NULL)
				icmp6->icmp6_mtu = htonl(
				    ntohl(icmp6->icmp6_mtu) -
				    ipsec_in_extra_length(first_mp));
		} else {
			/*
			 * Self-encapsulated case. As in the ipv4 case,
			 * we need to strip the 2nd IP header. Since mp
			 * is already pulled-up, we can simply bcopy
			 * the 3rd header + data over the 2nd header.
			 */
			uint16_t unused_len;
			ip6_t *inner_ip6h = (ip6_t *)
			    ((uchar_t *)ip6h + hdr_length);

			/*
			 * Make sure we don't do recursion more than once.
			 */
			if (!ip_hdr_length_nexthdr_v6(mp, inner_ip6h,
			    &unused_len, &nexthdrp) ||
			    *nexthdrp == IPPROTO_IPV6) {
				goto drop_pkt;
			}

			/*
			 * We are about to modify the packet. Make a copy if
			 * someone else has a reference to it.
			 */
			if (DB_REF(mp) > 1) {
				mblk_t	*mp1;
				uint16_t icmp6_offset;

				mp1 = copymsg(mp);
				if (mp1 == NULL) {
					goto drop_pkt;
				}
				icmp6_offset = (uint16_t)
				    ((uchar_t *)icmp6 - mp->b_rptr);
				freemsg(mp);
				mp = mp1;

				icmp6 = (icmp6_t *)(mp->b_rptr + icmp6_offset);
				ip6h = (ip6_t *)&icmp6[1];
				inner_ip6h = (ip6_t *)
				    ((uchar_t *)ip6h + hdr_length);

				if (mctl_present)
					first_mp->b_cont = mp;
				else
					first_mp = mp;
			}

			/*
			 * Need to set db_type back to M_DATA before
			 * refeeding mp into this function.
			 */
			DB_TYPE(mp) = M_DATA;

			/*
			 * Copy the 3rd header + remaining data on top
			 * of the 2nd header.
			 */
			bcopy(inner_ip6h, ip6h,
			    mp->b_wptr - (uchar_t *)inner_ip6h);

			/*
			 * Subtract length of the 2nd header.
			 */
			mp->b_wptr -= hdr_length;

			/*
			 * Now recurse, and see what I _really_ should be
			 * doing here.
			 */
			icmp_inbound_error_fanout_v6(q, first_mp,
			    (ip6_t *)mp->b_rptr, icmp6, ill, mctl_present,
			    zoneid);
			return;
		}
		/* FALLTHRU */
	default:
		/*
		 * The rip6h header is only used for the lookup and we
		 * only set the src and dst addresses and nexthdr.
		 */
		rip6h.ip6_src = ip6h->ip6_dst;
		rip6h.ip6_dst = ip6h->ip6_src;
		rip6h.ip6_nxt = nexthdr;
		ip_fanout_proto_v6(q, first_mp, &rip6h, ill, ill, nexthdr, 0,
		    IP6_NO_IPPOLICY, mctl_present, zoneid);
		return;
	}
	/* NOTREACHED */
drop_pkt:
	BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInErrors);
	ip1dbg(("icmp_inbound_error_fanout_v6: drop pkt\n"));
	freemsg(first_mp);
}

/*
 * Process received IPv6 ICMP Redirect messages.
 */
/* ARGSUSED */
static void
icmp_redirect_v6(queue_t *q, mblk_t *mp, ill_t *ill)
{
	ip6_t		*ip6h;
	uint16_t	hdr_length;
	nd_redirect_t	*rd;
	ire_t		*ire;
	ire_t		*prev_ire;
	ire_t		*redir_ire;
	in6_addr_t	*src, *dst, *gateway;
	nd_opt_hdr_t	*opt;
	nce_t		*nce;
	int		nce_flags = 0;
	int		err = 0;
	boolean_t	redirect_to_router = B_FALSE;
	int		len;
	int		optlen;
	iulp_t		ulp_info = { 0 };
	ill_t		*prev_ire_ill;
	ipif_t		*ipif;
	ip_stack_t	*ipst = ill->ill_ipst;

	ip6h = (ip6_t *)mp->b_rptr;
	if (ip6h->ip6_nxt != IPPROTO_ICMPV6)
		hdr_length = ip_hdr_length_v6(mp, ip6h);
	else
		hdr_length = IPV6_HDR_LEN;

	rd = (nd_redirect_t *)&mp->b_rptr[hdr_length];
	len = mp->b_wptr - mp->b_rptr -  hdr_length;
	src = &ip6h->ip6_src;
	dst = &rd->nd_rd_dst;
	gateway = &rd->nd_rd_target;

	/* Verify if it is a valid redirect */
	if (!IN6_IS_ADDR_LINKLOCAL(src) ||
	    (ip6h->ip6_hops != IPV6_MAX_HOPS) ||
	    (rd->nd_rd_code != 0) ||
	    (len < sizeof (nd_redirect_t)) ||
	    (IN6_IS_ADDR_V4MAPPED(dst)) ||
	    (IN6_IS_ADDR_MULTICAST(dst))) {
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
		freemsg(mp);
		return;
	}

	if (!(IN6_IS_ADDR_LINKLOCAL(gateway) ||
	    IN6_ARE_ADDR_EQUAL(gateway, dst))) {
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
		freemsg(mp);
		return;
	}

	if (len > sizeof (nd_redirect_t)) {
		if (!ndp_verify_optlen((nd_opt_hdr_t *)&rd[1],
		    len - sizeof (nd_redirect_t))) {
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
			freemsg(mp);
			return;
		}
	}

	if (!IN6_ARE_ADDR_EQUAL(gateway, dst)) {
		redirect_to_router = B_TRUE;
		nce_flags |= NCE_F_ISROUTER;
	}

	/* ipif will be refreleased afterwards */
	ipif = ipif_get_next_ipif(NULL, ill);
	if (ipif == NULL) {
		freemsg(mp);
		return;
	}

	/*
	 * Verify that the IP source address of the redirect is
	 * the same as the current first-hop router for the specified
	 * ICMP destination address.
	 * Also, Make sure we had a route for the dest in question and
	 * that route was pointing to the old gateway (the source of the
	 * redirect packet.)
	 */

	prev_ire = ire_route_lookup_v6(dst, 0, src, 0, ipif, NULL,
	    ALL_ZONES, NULL, MATCH_IRE_GW | MATCH_IRE_ILL_GROUP |
	    MATCH_IRE_DEFAULT, ipst);

	/*
	 * Check that
	 *	the redirect was not from ourselves
	 *	old gateway is still directly reachable
	 */
	if (prev_ire == NULL ||
	    prev_ire->ire_type == IRE_LOCAL) {
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
		ipif_refrele(ipif);
		goto fail_redirect;
	}
	prev_ire_ill = ire_to_ill(prev_ire);
	ASSERT(prev_ire_ill != NULL);
	if (prev_ire_ill->ill_flags & ILLF_NONUD)
		nce_flags |= NCE_F_NONUD;

	/*
	 * Should we use the old ULP info to create the new gateway?  From
	 * a user's perspective, we should inherit the info so that it
	 * is a "smooth" transition.  If we do not do that, then new
	 * connections going thru the new gateway will have no route metrics,
	 * which is counter-intuitive to user.  From a network point of
	 * view, this may or may not make sense even though the new gateway
	 * is still directly connected to us so the route metrics should not
	 * change much.
	 *
	 * But if the old ire_uinfo is not initialized, we do another
	 * recursive lookup on the dest using the new gateway.  There may
	 * be a route to that.  If so, use it to initialize the redirect
	 * route.
	 */
	if (prev_ire->ire_uinfo.iulp_set) {
		bcopy(&prev_ire->ire_uinfo, &ulp_info, sizeof (iulp_t));
	} else if (redirect_to_router) {
		/*
		 * Only do the following if the redirection is really to
		 * a router.
		 */
		ire_t *tmp_ire;
		ire_t *sire;

		tmp_ire = ire_ftable_lookup_v6(dst, 0, gateway, 0, NULL, &sire,
		    ALL_ZONES, 0, NULL,
		    (MATCH_IRE_RECURSIVE | MATCH_IRE_GW | MATCH_IRE_DEFAULT),
		    ipst);
		if (sire != NULL) {
			bcopy(&sire->ire_uinfo, &ulp_info, sizeof (iulp_t));
			ASSERT(tmp_ire != NULL);
			ire_refrele(tmp_ire);
			ire_refrele(sire);
		} else if (tmp_ire != NULL) {
			bcopy(&tmp_ire->ire_uinfo, &ulp_info,
			    sizeof (iulp_t));
			ire_refrele(tmp_ire);
		}
	}

	optlen = mp->b_wptr - mp->b_rptr -  hdr_length - sizeof (nd_redirect_t);
	opt = (nd_opt_hdr_t *)&rd[1];
	opt = ndp_get_option(opt, optlen, ND_OPT_TARGET_LINKADDR);
	if (opt != NULL) {
		err = ndp_lookup_then_add_v6(ill,
		    (uchar_t *)&opt[1],		/* Link layer address */
		    gateway,
		    &ipv6_all_ones,		/* prefix mask */
		    &ipv6_all_zeros,		/* Mapping mask */
		    0,
		    nce_flags,
		    ND_STALE,
		    &nce);
		switch (err) {
		case 0:
			NCE_REFRELE(nce);
			break;
		case EEXIST:
			/*
			 * Check to see if link layer address has changed and
			 * process the nce_state accordingly.
			 */
			ndp_process(nce, (uchar_t *)&opt[1], 0, B_FALSE);
			NCE_REFRELE(nce);
			break;
		default:
			ip1dbg(("icmp_redirect_v6: NCE create failed %d\n",
			    err));
			ipif_refrele(ipif);
			goto fail_redirect;
		}
	}
	if (redirect_to_router) {
		/* icmp_redirect_ok_v6() must  have already verified this  */
		ASSERT(IN6_IS_ADDR_LINKLOCAL(gateway));

		/*
		 * Create a Route Association.  This will allow us to remember
		 * a router told us to use the particular gateway.
		 */
		ire = ire_create_v6(
		    dst,
		    &ipv6_all_ones,		/* mask */
		    &prev_ire->ire_src_addr_v6,	/* source addr */
		    gateway,			/* gateway addr */
		    &prev_ire->ire_max_frag,	/* max frag */
		    NULL,			/* no src nce */
		    NULL, 			/* no rfq */
		    NULL,			/* no stq */
		    IRE_HOST,
		    prev_ire->ire_ipif,
		    NULL,
		    0,
		    0,
		    (RTF_DYNAMIC | RTF_GATEWAY | RTF_HOST),
		    &ulp_info,
		    NULL,
		    NULL,
		    ipst);
	} else {
		queue_t *stq;

		stq = (ipif->ipif_net_type == IRE_IF_RESOLVER)
		    ? ipif->ipif_rq : ipif->ipif_wq;

		/*
		 * Just create an on link entry, i.e. interface route.
		 */
		ire = ire_create_v6(
		    dst,				/* gateway == dst */
		    &ipv6_all_ones,			/* mask */
		    &prev_ire->ire_src_addr_v6,		/* source addr */
		    &ipv6_all_zeros,			/* gateway addr */
		    &prev_ire->ire_max_frag,		/* max frag */
		    NULL,				/* no src nce */
		    NULL,				/* ire rfq */
		    stq,				/* ire stq */
		    ipif->ipif_net_type,		/* IF_[NO]RESOLVER */
		    prev_ire->ire_ipif,
		    &ipv6_all_ones,
		    0,
		    0,
		    (RTF_DYNAMIC | RTF_HOST),
		    &ulp_info,
		    NULL,
		    NULL,
		    ipst);
	}

	/* Release reference from earlier ipif_get_next_ipif() */
	ipif_refrele(ipif);

	if (ire == NULL)
		goto fail_redirect;

	if (ire_add(&ire, NULL, NULL, NULL, B_FALSE) == 0) {

		/* tell routing sockets that we received a redirect */
		ip_rts_change_v6(RTM_REDIRECT,
		    &rd->nd_rd_dst,
		    &rd->nd_rd_target,
		    &ipv6_all_ones, 0, &ire->ire_src_addr_v6,
		    (RTF_DYNAMIC | RTF_GATEWAY | RTF_HOST), 0,
		    (RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_AUTHOR), ipst);

		/*
		 * Delete any existing IRE_HOST type ires for this destination.
		 * This together with the added IRE has the effect of
		 * modifying an existing redirect.
		 */
		redir_ire = ire_ftable_lookup_v6(dst, 0, src, IRE_HOST,
		    ire->ire_ipif, NULL, ALL_ZONES, 0, NULL,
		    (MATCH_IRE_GW | MATCH_IRE_TYPE | MATCH_IRE_ILL_GROUP),
		    ipst);

		ire_refrele(ire);		/* Held in ire_add_v6 */

		if (redir_ire != NULL) {
			if (redir_ire->ire_flags & RTF_DYNAMIC)
				ire_delete(redir_ire);
			ire_refrele(redir_ire);
		}
	}

	if (prev_ire->ire_type == IRE_CACHE)
		ire_delete(prev_ire);
	ire_refrele(prev_ire);
	prev_ire = NULL;

fail_redirect:
	if (prev_ire != NULL)
		ire_refrele(prev_ire);
	freemsg(mp);
}

static ill_t *
ip_queue_to_ill_v6(queue_t *q, ip_stack_t *ipst)
{
	ill_t *ill;

	ASSERT(WR(q) == q);

	if (q->q_next != NULL) {
		ill = (ill_t *)q->q_ptr;
		if (ILL_CAN_LOOKUP(ill))
			ill_refhold(ill);
		else
			ill = NULL;
	} else {
		ill = ill_lookup_on_name(ipif_loopback_name, B_FALSE, B_TRUE,
		    NULL, NULL, NULL, NULL, NULL, ipst);
	}
	if (ill == NULL)
		ip0dbg(("ip_queue_to_ill_v6: no ill\n"));
	return (ill);
}

/*
 * Assigns an appropriate source address to the packet.
 * If origdst is one of our IP addresses that use it as the source.
 * If the queue is an ill queue then select a source from that ill.
 * Otherwise pick a source based on a route lookup back to the origsrc.
 *
 * src is the return parameter. Returns a pointer to src or NULL if failure.
 */
static in6_addr_t *
icmp_pick_source_v6(queue_t *wq, in6_addr_t *origsrc, in6_addr_t *origdst,
    in6_addr_t *src, zoneid_t zoneid, ip_stack_t *ipst)
{
	ill_t	*ill;
	ire_t	*ire;
	ipif_t	*ipif;

	ASSERT(!(wq->q_flag & QREADR));
	if (wq->q_next != NULL) {
		ill = (ill_t *)wq->q_ptr;
	} else {
		ill = NULL;
	}

	ire = ire_route_lookup_v6(origdst, 0, 0, (IRE_LOCAL|IRE_LOOPBACK),
	    NULL, NULL, zoneid, NULL, (MATCH_IRE_TYPE|MATCH_IRE_ZONEONLY),
	    ipst);
	if (ire != NULL) {
		/* Destined to one of our addresses */
		*src = *origdst;
		ire_refrele(ire);
		return (src);
	}
	if (ire != NULL) {
		ire_refrele(ire);
		ire = NULL;
	}
	if (ill == NULL) {
		/* What is the route back to the original source? */
		ire = ire_route_lookup_v6(origsrc, 0, 0, 0,
		    NULL, NULL, zoneid, NULL,
		    (MATCH_IRE_DEFAULT|MATCH_IRE_RECURSIVE), ipst);
		if (ire == NULL) {
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutNoRoutes);
			return (NULL);
		}
		/*
		 * Does not matter whether we use ire_stq or ire_ipif here.
		 * Just pick an ill for ICMP replies.
		 */
		ASSERT(ire->ire_ipif != NULL);
		ill = ire->ire_ipif->ipif_ill;
		ire_refrele(ire);
	}
	ipif = ipif_select_source_v6(ill, origsrc, RESTRICT_TO_NONE,
	    IPV6_PREFER_SRC_DEFAULT, zoneid);
	if (ipif != NULL) {
		*src = ipif->ipif_v6src_addr;
		ipif_refrele(ipif);
		return (src);
	}
	/*
	 * Unusual case - can't find a usable source address to reach the
	 * original source. Use what in the route to the source.
	 */
	ire = ire_route_lookup_v6(origsrc, 0, 0, 0,
	    NULL, NULL, zoneid, NULL,
	    (MATCH_IRE_DEFAULT|MATCH_IRE_RECURSIVE), ipst);
	if (ire == NULL) {
		BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutNoRoutes);
		return (NULL);
	}
	ASSERT(ire != NULL);
	*src = ire->ire_src_addr_v6;
	ire_refrele(ire);
	return (src);
}

/*
 * Build and ship an IPv6 ICMP message using the packet data in mp,
 * and the ICMP header pointed to by "stuff".  (May be called as
 * writer.)
 * Note: assumes that icmp_pkt_err_ok_v6 has been called to
 * verify that an icmp error packet can be sent.
 *
 * If q is an ill write side queue (which is the case when packets
 * arrive from ip_rput) then ip_wput code will ensure that packets to
 * link-local destinations are sent out that ill.
 *
 * If v6src_ptr is set use it as a source. Otherwise select a reasonable
 * source address (see above function).
 */
static void
icmp_pkt_v6(queue_t *q, mblk_t *mp, void *stuff, size_t len,
    const in6_addr_t *v6src_ptr, boolean_t mctl_present, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	ip6_t		*ip6h;
	in6_addr_t	v6dst;
	size_t		len_needed;
	size_t		msg_len;
	mblk_t		*mp1;
	icmp6_t		*icmp6;
	ill_t		*ill;
	in6_addr_t	v6src;
	mblk_t *ipsec_mp;
	ipsec_out_t *io;

	ill = ip_queue_to_ill_v6(q, ipst);
	if (ill == NULL) {
		freemsg(mp);
		return;
	}

	if (mctl_present) {
		/*
		 * If it is :
		 *
		 * 1) a IPSEC_OUT, then this is caused by outbound
		 *    datagram originating on this host. IPSEC processing
		 *    may or may not have been done. Refer to comments above
		 *    icmp_inbound_error_fanout for details.
		 *
		 * 2) a IPSEC_IN if we are generating a icmp_message
		 *    for an incoming datagram destined for us i.e called
		 *    from ip_fanout_send_icmp.
		 */
		ipsec_info_t *in;

		ipsec_mp = mp;
		mp = ipsec_mp->b_cont;

		in = (ipsec_info_t *)ipsec_mp->b_rptr;
		ip6h = (ip6_t *)mp->b_rptr;

		ASSERT(in->ipsec_info_type == IPSEC_OUT ||
		    in->ipsec_info_type == IPSEC_IN);

		if (in->ipsec_info_type == IPSEC_IN) {
			/*
			 * Convert the IPSEC_IN to IPSEC_OUT.
			 */
			if (!ipsec_in_to_out(ipsec_mp, NULL, ip6h)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ill_refrele(ill);
				return;
			}
		} else {
			ASSERT(in->ipsec_info_type == IPSEC_OUT);
			io = (ipsec_out_t *)in;
			/*
			 * Clear out ipsec_out_proc_begin, so we do a fresh
			 * ire lookup.
			 */
			io->ipsec_out_proc_begin = B_FALSE;
		}
	} else {
		/*
		 * This is in clear. The icmp message we are building
		 * here should go out in clear.
		 */
		ipsec_in_t *ii;
		ASSERT(mp->b_datap->db_type == M_DATA);
		ipsec_mp = ipsec_in_alloc(B_FALSE, ipst->ips_netstack);
		if (ipsec_mp == NULL) {
			freemsg(mp);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ill_refrele(ill);
			return;
		}
		ii = (ipsec_in_t *)ipsec_mp->b_rptr;

		/* This is not a secure packet */
		ii->ipsec_in_secure = B_FALSE;
		/*
		 * For trusted extensions using a shared IP address we can
		 * send using any zoneid.
		 */
		if (zoneid == ALL_ZONES)
			ii->ipsec_in_zoneid = GLOBAL_ZONEID;
		else
			ii->ipsec_in_zoneid = zoneid;
		ipsec_mp->b_cont = mp;
		ip6h = (ip6_t *)mp->b_rptr;
		/*
		 * Convert the IPSEC_IN to IPSEC_OUT.
		 */
		if (!ipsec_in_to_out(ipsec_mp, NULL, ip6h)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ill_refrele(ill);
			return;
		}
	}
	io = (ipsec_out_t *)ipsec_mp->b_rptr;

	if (v6src_ptr != NULL) {
		v6src = *v6src_ptr;
	} else {
		if (icmp_pick_source_v6(q, &ip6h->ip6_src, &ip6h->ip6_dst,
		    &v6src, zoneid, ipst) == NULL) {
			freemsg(ipsec_mp);
			ill_refrele(ill);
			return;
		}
	}
	v6dst = ip6h->ip6_src;
	len_needed = ipst->ips_ipv6_icmp_return - IPV6_HDR_LEN - len;
	msg_len = msgdsize(mp);
	if (msg_len > len_needed) {
		if (!adjmsg(mp, len_needed - msg_len)) {
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutErrors);
			freemsg(ipsec_mp);
			ill_refrele(ill);
			return;
		}
		msg_len = len_needed;
	}
	mp1 = allocb_cred(IPV6_HDR_LEN + len, DB_CRED(mp));
	if (mp1 == NULL) {
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutErrors);
		freemsg(ipsec_mp);
		ill_refrele(ill);
		return;
	}
	ill_refrele(ill);
	mp1->b_cont = mp;
	mp = mp1;
	ASSERT(ipsec_mp->b_datap->db_type == M_CTL &&
	    io->ipsec_out_type == IPSEC_OUT);
	ipsec_mp->b_cont = mp;

	/*
	 * Set ipsec_out_icmp_loopback so we can let the ICMP messages this
	 * node generates be accepted in peace by all on-host destinations.
	 * If we do NOT assume that all on-host destinations trust
	 * self-generated ICMP messages, then rework here, ip.c, and spd.c.
	 * (Look for ipsec_out_icmp_loopback).
	 */
	io->ipsec_out_icmp_loopback = B_TRUE;

	ip6h = (ip6_t *)mp->b_rptr;
	mp1->b_wptr = (uchar_t *)ip6h + (IPV6_HDR_LEN + len);

	ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	ip6h->ip6_nxt = IPPROTO_ICMPV6;
	ip6h->ip6_hops = ipst->ips_ipv6_def_hops;
	ip6h->ip6_dst = v6dst;
	ip6h->ip6_src = v6src;
	msg_len += IPV6_HDR_LEN + len;
	if (msg_len > IP_MAXPACKET + IPV6_HDR_LEN) {
		(void) adjmsg(mp, IP_MAXPACKET + IPV6_HDR_LEN - msg_len);
		msg_len = IP_MAXPACKET + IPV6_HDR_LEN;
	}
	ip6h->ip6_plen = htons((uint16_t)(msgdsize(mp) - IPV6_HDR_LEN));
	icmp6 = (icmp6_t *)&ip6h[1];
	bcopy(stuff, (char *)icmp6, len);
	/*
	 * Prepare for checksum by putting icmp length in the icmp
	 * checksum field. The checksum is calculated in ip_wput_v6.
	 */
	icmp6->icmp6_cksum = ip6h->ip6_plen;
	if (icmp6->icmp6_type == ND_REDIRECT) {
		ip6h->ip6_hops = IPV6_MAX_HOPS;
	}
	/* Send to V6 writeside put routine */
	put(q, ipsec_mp);
}

/*
 * Update the output mib when ICMPv6 packets are sent.
 */
static void
icmp_update_out_mib_v6(ill_t *ill, icmp6_t *icmp6)
{
	BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutMsgs);

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutDestUnreachs);
		if (icmp6->icmp6_code == ICMP6_DST_UNREACH_ADMIN)
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutAdminProhibs);
		break;

	case ICMP6_TIME_EXCEEDED:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutTimeExcds);
		break;

	case ICMP6_PARAM_PROB:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutParmProblems);
		break;

	case ICMP6_PACKET_TOO_BIG:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutPktTooBigs);
		break;

	case ICMP6_ECHO_REQUEST:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutEchos);
		break;

	case ICMP6_ECHO_REPLY:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutEchoReplies);
		break;

	case ND_ROUTER_SOLICIT:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutRouterSolicits);
		break;

	case ND_ROUTER_ADVERT:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutRouterAdvertisements);
		break;

	case ND_NEIGHBOR_SOLICIT:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutNeighborSolicits);
		break;

	case ND_NEIGHBOR_ADVERT:
		BUMP_MIB(ill->ill_icmp6_mib,
		    ipv6IfIcmpOutNeighborAdvertisements);
		break;

	case ND_REDIRECT:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutRedirects);
		break;

	case MLD_LISTENER_QUERY:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutGroupMembQueries);
		break;

	case MLD_LISTENER_REPORT:
	case MLD_V2_LISTENER_REPORT:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutGroupMembResponses);
		break;

	case MLD_LISTENER_REDUCTION:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutGroupMembReductions);
		break;
	}
}

/*
 * Check if it is ok to send an ICMPv6 error packet in
 * response to the IP packet in mp.
 * Free the message and return null if no
 * ICMP error packet should be sent.
 */
static mblk_t *
icmp_pkt_err_ok_v6(queue_t *q, mblk_t *mp,
    boolean_t llbcast, boolean_t mcast_ok, ip_stack_t *ipst)
{
	ip6_t	*ip6h;

	if (!mp)
		return (NULL);

	ip6h = (ip6_t *)mp->b_rptr;

	/* Check if source address uniquely identifies the host */

	if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_src) ||
	    IN6_IS_ADDR_V4MAPPED(&ip6h->ip6_src) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src)) {
		freemsg(mp);
		return (NULL);
	}

	if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
		size_t	len_needed = IPV6_HDR_LEN + ICMP6_MINLEN;
		icmp6_t		*icmp6;

		if (mp->b_wptr - mp->b_rptr < len_needed) {
			if (!pullupmsg(mp, len_needed)) {
				ill_t	*ill;

				ill = ip_queue_to_ill_v6(q, ipst);
				if (ill == NULL) {
					BUMP_MIB(&ipst->ips_icmp6_mib,
					    ipv6IfIcmpInErrors);
				} else {
					BUMP_MIB(ill->ill_icmp6_mib,
					    ipv6IfIcmpInErrors);
					ill_refrele(ill);
				}
				freemsg(mp);
				return (NULL);
			}
			ip6h = (ip6_t *)mp->b_rptr;
		}
		icmp6 = (icmp6_t *)&ip6h[1];
		/* Explicitly do not generate errors in response to redirects */
		if (ICMP6_IS_ERROR(icmp6->icmp6_type) ||
		    icmp6->icmp6_type == ND_REDIRECT) {
			freemsg(mp);
			return (NULL);
		}
	}
	/*
	 * Check that the destination is not multicast and that the packet
	 * was not sent on link layer broadcast or multicast.  (Exception
	 * is Packet too big message as per the draft - when mcast_ok is set.)
	 */
	if (!mcast_ok &&
	    (llbcast || IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst))) {
		freemsg(mp);
		return (NULL);
	}
	if (icmp_err_rate_limit(ipst)) {
		/*
		 * Only send ICMP error packets every so often.
		 * This should be done on a per port/source basis,
		 * but for now this will suffice.
		 */
		freemsg(mp);
		return (NULL);
	}
	return (mp);
}

/*
 * Generate an ICMPv6 redirect message.
 * Include target link layer address option if it exits.
 * Always include redirect header.
 */
static void
icmp_send_redirect_v6(queue_t *q, mblk_t *mp, in6_addr_t *targetp,
    in6_addr_t *dest, ill_t *ill, boolean_t llbcast)
{
	nd_redirect_t	*rd;
	nd_opt_rd_hdr_t	*rdh;
	uchar_t		*buf;
	nce_t		*nce = NULL;
	nd_opt_hdr_t	*opt;
	int		len;
	int		ll_opt_len = 0;
	int		max_redir_hdr_data_len;
	int		pkt_len;
	in6_addr_t	*srcp;
	ip_stack_t	*ipst = ill->ill_ipst;

	/*
	 * We are called from ip_rput where we could
	 * not have attached an IPSEC_IN.
	 */
	ASSERT(mp->b_datap->db_type == M_DATA);

	mp = icmp_pkt_err_ok_v6(q, mp, llbcast, B_FALSE, ipst);
	if (mp == NULL)
		return;
	nce = ndp_lookup_v6(ill, targetp, B_FALSE);
	if (nce != NULL && nce->nce_state != ND_INCOMPLETE) {
		ll_opt_len = (sizeof (nd_opt_hdr_t) +
		    ill->ill_phys_addr_length + 7)/8 * 8;
	}
	len = sizeof (nd_redirect_t) + sizeof (nd_opt_rd_hdr_t) + ll_opt_len;
	ASSERT(len % 4 == 0);
	buf = kmem_alloc(len, KM_NOSLEEP);
	if (buf == NULL) {
		if (nce != NULL)
			NCE_REFRELE(nce);
		freemsg(mp);
		return;
	}

	rd = (nd_redirect_t *)buf;
	rd->nd_rd_type = (uint8_t)ND_REDIRECT;
	rd->nd_rd_code = 0;
	rd->nd_rd_reserved = 0;
	rd->nd_rd_target = *targetp;
	rd->nd_rd_dst = *dest;

	opt = (nd_opt_hdr_t *)(buf + sizeof (nd_redirect_t));
	if (nce != NULL && ll_opt_len != 0) {
		opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		opt->nd_opt_len = ll_opt_len/8;
		bcopy((char *)nce->nce_res_mp->b_rptr +
		    NCE_LL_ADDR_OFFSET(ill), &opt[1],
		    ill->ill_phys_addr_length);
	}
	if (nce != NULL)
		NCE_REFRELE(nce);
	rdh = (nd_opt_rd_hdr_t *)(buf + sizeof (nd_redirect_t) + ll_opt_len);
	rdh->nd_opt_rh_type = (uint8_t)ND_OPT_REDIRECTED_HEADER;
	/* max_redir_hdr_data_len and nd_opt_rh_len must be multiple of 8 */
	max_redir_hdr_data_len =
	    (ipst->ips_ipv6_icmp_return - IPV6_HDR_LEN - len)/8*8;
	pkt_len = msgdsize(mp);
	/* Make sure mp is 8 byte aligned */
	if (pkt_len > max_redir_hdr_data_len) {
		rdh->nd_opt_rh_len = (max_redir_hdr_data_len +
		    sizeof (nd_opt_rd_hdr_t))/8;
		(void) adjmsg(mp, max_redir_hdr_data_len - pkt_len);
	} else {
		rdh->nd_opt_rh_len = (pkt_len + sizeof (nd_opt_rd_hdr_t))/8;
		(void) adjmsg(mp, -(pkt_len % 8));
	}
	rdh->nd_opt_rh_reserved1 = 0;
	rdh->nd_opt_rh_reserved2 = 0;
	/* ipif_v6src_addr contains the link-local source address */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	if (ill->ill_group != NULL) {
		/*
		 * The receiver of the redirect will verify whether it
		 * had a route through us (srcp that we will use in
		 * the redirect) or not. As we load spread even link-locals,
		 * we don't know which source address the receiver of
		 * redirect has in its route for communicating with us.
		 * Thus we randomly choose a source here and finally we
		 * should get to the right one and it will eventually
		 * accept the redirect from us. We can't call
		 * ip_lookup_scope_v6 because we don't have the right
		 * link-local address here. Thus we randomly choose one.
		 */
		int cnt = ill->ill_group->illgrp_ill_count;

		ill = ill->ill_group->illgrp_ill;
		cnt = ++ipst->ips_icmp_redirect_v6_src_index % cnt;
		while (cnt--)
			ill = ill->ill_group_next;
		srcp = &ill->ill_ipif->ipif_v6src_addr;
	} else {
		srcp = &ill->ill_ipif->ipif_v6src_addr;
	}
	rw_exit(&ipst->ips_ill_g_lock);
	/* Redirects sent by router, and router is global zone */
	icmp_pkt_v6(q, mp, buf, len, srcp, B_FALSE, GLOBAL_ZONEID, ipst);
	kmem_free(buf, len);
}


/* Generate an ICMP time exceeded message.  (May be called as writer.) */
void
icmp_time_exceeded_v6(queue_t *q, mblk_t *mp, uint8_t code,
    boolean_t llbcast, boolean_t mcast_ok, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	icmp6_t	icmp6;
	boolean_t mctl_present;
	mblk_t *first_mp;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);

	mp = icmp_pkt_err_ok_v6(q, mp, llbcast, mcast_ok, ipst);
	if (mp == NULL) {
		if (mctl_present)
			freeb(first_mp);
		return;
	}
	bzero(&icmp6, sizeof (icmp6_t));
	icmp6.icmp6_type = ICMP6_TIME_EXCEEDED;
	icmp6.icmp6_code = code;
	icmp_pkt_v6(q, first_mp, &icmp6, sizeof (icmp6_t), NULL, mctl_present,
	    zoneid, ipst);
}

/*
 * Generate an ICMP unreachable message.
 */
void
icmp_unreachable_v6(queue_t *q, mblk_t *mp, uint8_t code,
    boolean_t llbcast, boolean_t mcast_ok, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	icmp6_t	icmp6;
	boolean_t mctl_present;
	mblk_t *first_mp;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);

	mp = icmp_pkt_err_ok_v6(q, mp, llbcast, mcast_ok, ipst);
	if (mp == NULL) {
		if (mctl_present)
			freeb(first_mp);
		return;
	}
	bzero(&icmp6, sizeof (icmp6_t));
	icmp6.icmp6_type = ICMP6_DST_UNREACH;
	icmp6.icmp6_code = code;
	icmp_pkt_v6(q, first_mp, &icmp6, sizeof (icmp6_t), NULL, mctl_present,
	    zoneid, ipst);
}

/*
 * Generate an ICMP pkt too big message.
 */
static void
icmp_pkt2big_v6(queue_t *q, mblk_t *mp, uint32_t mtu,
    boolean_t llbcast, boolean_t mcast_ok, zoneid_t zoneid, ip_stack_t *ipst)
{
	icmp6_t	icmp6;
	mblk_t *first_mp;
	boolean_t mctl_present;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);

	mp = icmp_pkt_err_ok_v6(q, mp, llbcast, mcast_ok,  ipst);
	if (mp == NULL) {
		if (mctl_present)
			freeb(first_mp);
		return;
	}
	bzero(&icmp6, sizeof (icmp6_t));
	icmp6.icmp6_type = ICMP6_PACKET_TOO_BIG;
	icmp6.icmp6_code = 0;
	icmp6.icmp6_mtu = htonl(mtu);

	icmp_pkt_v6(q, first_mp, &icmp6, sizeof (icmp6_t), NULL, mctl_present,
	    zoneid, ipst);
}

/*
 * Generate an ICMP parameter problem message. (May be called as writer.)
 * 'offset' is the offset from the beginning of the packet in error.
 */
static void
icmp_param_problem_v6(queue_t *q, mblk_t *mp, uint8_t code,
    uint32_t offset, boolean_t llbcast, boolean_t mcast_ok, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	icmp6_t	icmp6;
	boolean_t mctl_present;
	mblk_t *first_mp;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);

	mp = icmp_pkt_err_ok_v6(q, mp, llbcast, mcast_ok, ipst);
	if (mp == NULL) {
		if (mctl_present)
			freeb(first_mp);
		return;
	}
	bzero((char *)&icmp6, sizeof (icmp6_t));
	icmp6.icmp6_type = ICMP6_PARAM_PROB;
	icmp6.icmp6_code = code;
	icmp6.icmp6_pptr = htonl(offset);
	icmp_pkt_v6(q, first_mp, &icmp6, sizeof (icmp6_t), NULL, mctl_present,
	    zoneid, ipst);
}

/*
 * This code will need to take into account the possibility of binding
 * to a link local address on a multi-homed host, in which case the
 * outgoing interface (from the conn) will need to be used when getting
 * an ire for the dst. Going through proper outgoing interface and
 * choosing the source address corresponding to the outgoing interface
 * is necessary when the destination address is a link-local address and
 * IPV6_BOUND_IF or IPV6_PKTINFO or scope_id has been set.
 * This can happen when active connection is setup; thus ipp pointer
 * is passed here from tcp_connect_*() routines, in non-TCP cases NULL
 * pointer is passed as ipp pointer.
 */
mblk_t *
ip_bind_v6(queue_t *q, mblk_t *mp, conn_t *connp, ip6_pkt_t *ipp)
{
	ssize_t			len;
	int			protocol;
	struct T_bind_req	*tbr;
	sin6_t			*sin6;
	ipa6_conn_t		*ac6;
	in6_addr_t		*v6srcp;
	in6_addr_t		*v6dstp;
	uint16_t		lport;
	uint16_t		fport;
	uchar_t			*ucp;
	mblk_t			*mp1;
	boolean_t		ire_requested;
	boolean_t		ipsec_policy_set;
	int			error = 0;
	boolean_t		local_bind;
	boolean_t		orig_pkt_isv6 = connp->conn_pkt_isv6;
	ipa6_conn_x_t		*acx6;
	boolean_t		verify_dst;
	ip_stack_t		*ipst = connp->conn_netstack->netstack_ip;

	ASSERT(connp->conn_af_isv6);
	len = mp->b_wptr - mp->b_rptr;
	if (len < (sizeof (*tbr) + 1)) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "ip_bind_v6: bogus msg, len %ld", len);
		goto bad_addr;
	}
	/* Back up and extract the protocol identifier. */
	mp->b_wptr--;
	tbr = (struct T_bind_req *)mp->b_rptr;
	/* Reset the message type in preparation for shipping it back. */
	mp->b_datap->db_type = M_PCPROTO;

	protocol = *mp->b_wptr & 0xFF;
	connp->conn_ulp = (uint8_t)protocol;

	/*
	 * Check for a zero length address.  This is from a protocol that
	 * wants to register to receive all packets of its type.
	 */
	if (tbr->ADDR_length == 0) {
		if ((protocol == IPPROTO_TCP || protocol == IPPROTO_SCTP ||
		    protocol == IPPROTO_ESP || protocol == IPPROTO_AH) &&
		    ipst->ips_ipcl_proto_fanout_v6[protocol].connf_head !=
		    NULL) {
			/*
			 * TCP, SCTP, AH, and ESP have single protocol fanouts.
			 * Do not allow others to bind to these.
			 */
			goto bad_addr;
		}

		/*
		 *
		 * The udp module never sends down a zero-length address,
		 * and allowing this on a labeled system will break MLP
		 * functionality.
		 */
		if (is_system_labeled() && protocol == IPPROTO_UDP)
			goto bad_addr;

		/* Allow ipsec plumbing */
		if (connp->conn_mac_exempt && protocol != IPPROTO_AH &&
		    protocol != IPPROTO_ESP)
			goto bad_addr;

		connp->conn_srcv6 = ipv6_all_zeros;
		ipcl_proto_insert_v6(connp, protocol);

		tbr->PRIM_type = T_BIND_ACK;
		return (mp);
	}

	/* Extract the address pointer from the message. */
	ucp = (uchar_t *)mi_offset_param(mp, tbr->ADDR_offset,
	    tbr->ADDR_length);
	if (ucp == NULL) {
		ip1dbg(("ip_bind_v6: no address\n"));
		goto bad_addr;
	}
	if (!OK_32PTR(ucp)) {
		ip1dbg(("ip_bind_v6: unaligned address\n"));
		goto bad_addr;
	}
	mp1 = mp->b_cont;	/* trailing mp if any */
	ire_requested = (mp1 && mp1->b_datap->db_type == IRE_DB_REQ_TYPE);
	ipsec_policy_set = (mp1 && mp1->b_datap->db_type == IPSEC_POLICY_SET);

	switch (tbr->ADDR_length) {
	default:
		ip1dbg(("ip_bind_v6: bad address length %d\n",
		    (int)tbr->ADDR_length));
		goto bad_addr;

	case IPV6_ADDR_LEN:
		/* Verification of local address only */
		v6srcp = (in6_addr_t *)ucp;
		lport = 0;
		local_bind = B_TRUE;
		break;

	case sizeof (sin6_t):
		sin6 = (sin6_t *)ucp;
		v6srcp = &sin6->sin6_addr;
		lport = sin6->sin6_port;
		local_bind = B_TRUE;
		break;

	case sizeof (ipa6_conn_t):
		/*
		 * Verify that both the source and destination addresses
		 * are valid.
		 * Note that we allow connect to broadcast and multicast
		 * addresses when ire_requested is set. Thus the ULP
		 * has to check for IRE_BROADCAST and multicast.
		 */
		ac6 = (ipa6_conn_t *)ucp;
		v6srcp = &ac6->ac6_laddr;
		v6dstp = &ac6->ac6_faddr;
		fport = ac6->ac6_fport;
		/* For raw socket, the local port is not set. */
		lport = ac6->ac6_lport != 0 ? ac6->ac6_lport :
		    connp->conn_lport;
		local_bind = B_FALSE;
		/* Always verify destination reachability. */
		verify_dst = B_TRUE;
		break;

	case sizeof (ipa6_conn_x_t):
		/*
		 * Verify that the source address is valid.
		 * Note that we allow connect to broadcast and multicast
		 * addresses when ire_requested is set. Thus the ULP
		 * has to check for IRE_BROADCAST and multicast.
		 */
		acx6 = (ipa6_conn_x_t *)ucp;
		ac6 = &acx6->ac6x_conn;
		v6srcp = &ac6->ac6_laddr;
		v6dstp = &ac6->ac6_faddr;
		fport = ac6->ac6_fport;
		lport = ac6->ac6_lport;
		local_bind = B_FALSE;
		/*
		 * Client that passed ipa6_conn_x_t to us specifies whether to
		 * verify destination reachability.
		 */
		verify_dst = (acx6->ac6x_flags & ACX_VERIFY_DST) != 0;
		break;
	}
	if (local_bind) {
		if (IN6_IS_ADDR_V4MAPPED(v6srcp) && !connp->conn_ipv6_v6only) {
			/* Bind to IPv4 address */
			ipaddr_t v4src;

			IN6_V4MAPPED_TO_IPADDR(v6srcp, v4src);

			error = ip_bind_laddr(connp, mp, v4src, lport,
			    ire_requested, ipsec_policy_set,
			    tbr->ADDR_length != IPV6_ADDR_LEN);
			if (error != 0)
				goto bad_addr;
			connp->conn_pkt_isv6 = B_FALSE;
		} else {
			if (IN6_IS_ADDR_V4MAPPED(v6srcp)) {
				error = 0;
				goto bad_addr;
			}
			error = ip_bind_laddr_v6(connp, mp, v6srcp, lport,
			    ire_requested, ipsec_policy_set,
			    (tbr->ADDR_length != IPV6_ADDR_LEN));
			if (error != 0)
				goto bad_addr;
			connp->conn_pkt_isv6 = B_TRUE;
		}
	} else {
		/*
		 * Bind to local and remote address. Local might be
		 * unspecified in which case it will be extracted from
		 * ire_src_addr_v6
		 */
		if (IN6_IS_ADDR_V4MAPPED(v6dstp) && !connp->conn_ipv6_v6only) {
			/* Connect to IPv4 address */
			ipaddr_t v4src;
			ipaddr_t v4dst;

			/* Is the source unspecified or mapped? */
			if (!IN6_IS_ADDR_V4MAPPED(v6srcp) &&
			    !IN6_IS_ADDR_UNSPECIFIED(v6srcp)) {
				ip1dbg(("ip_bind_v6: "
				    "dst is mapped, but not the src\n"));
				goto bad_addr;
			}
			IN6_V4MAPPED_TO_IPADDR(v6srcp, v4src);
			IN6_V4MAPPED_TO_IPADDR(v6dstp, v4dst);

			/*
			 * XXX Fix needed. Need to pass ipsec_policy_set
			 * instead of B_FALSE.
			 */

			/* Always verify destination reachability. */
			error = ip_bind_connected(connp, mp, &v4src, lport,
			    v4dst, fport, ire_requested, ipsec_policy_set,
			    B_TRUE, B_TRUE);
			if (error != 0)
				goto bad_addr;
			IN6_IPADDR_TO_V4MAPPED(v4src, v6srcp);
			connp->conn_pkt_isv6 = B_FALSE;
		} else if (IN6_IS_ADDR_V4MAPPED(v6srcp)) {
			ip1dbg(("ip_bind_v6: "
			    "src is mapped, but not the dst\n"));
			goto bad_addr;
		} else {
			error = ip_bind_connected_v6(connp, mp, v6srcp,
			    lport, v6dstp, ipp, fport, ire_requested,
			    ipsec_policy_set, B_TRUE, verify_dst);
			if (error != 0)
				goto bad_addr;
			connp->conn_pkt_isv6 = B_TRUE;
		}
	}

	/* Update conn_send and pktversion if v4/v6 changed */
	if (orig_pkt_isv6 != connp->conn_pkt_isv6) {
		ip_setpktversion(connp, connp->conn_pkt_isv6, B_TRUE, ipst);
	}
	/*
	 * Pass the IPSEC headers size in ire_ipsec_overhead.
	 * We can't do this in ip_bind_insert_ire because the policy
	 * may not have been inherited at that point in time and hence
	 * conn_out_enforce_policy may not be set.
	 */
	mp1 = mp->b_cont;
	if (ire_requested && connp->conn_out_enforce_policy &&
	    mp1 != NULL && DB_TYPE(mp1) == IRE_DB_REQ_TYPE) {
		ire_t *ire = (ire_t *)mp1->b_rptr;
		ASSERT(MBLKL(mp1) >= sizeof (ire_t));
		ire->ire_ipsec_overhead = (conn_ipsec_length(connp));
	}

	/* Send it home. */
	mp->b_datap->db_type = M_PCPROTO;
	tbr->PRIM_type = T_BIND_ACK;
	return (mp);

bad_addr:
	if (error == EINPROGRESS)
		return (NULL);
	if (error > 0)
		mp = mi_tpi_err_ack_alloc(mp, TSYSERR, error);
	else
		mp = mi_tpi_err_ack_alloc(mp, TBADADDR, 0);
	return (mp);
}

/*
 * Here address is verified to be a valid local address.
 * If the IRE_DB_REQ_TYPE mp is present, a multicast
 * address is also considered a valid local address.
 * In the case of a multicast address, however, the
 * upper protocol is expected to reset the src address
 * to 0 if it sees an ire with IN6_IS_ADDR_MULTICAST returned so that
 * no packets are emitted with multicast address as
 * source address.
 * The addresses valid for bind are:
 *	(1) - in6addr_any
 *	(2) - IP address of an UP interface
 *	(3) - IP address of a DOWN interface
 *	(4) - a multicast address. In this case
 *	the conn will only receive packets destined to
 *	the specified multicast address. Note: the
 *	application still has to issue an
 *	IPV6_JOIN_GROUP socket option.
 *
 * In all the above cases, the bound address must be valid in the current zone.
 * When the address is loopback or multicast, there might be many matching IREs
 * so bind has to look up based on the zone.
 */
static int
ip_bind_laddr_v6(conn_t *connp, mblk_t *mp, const in6_addr_t *v6src,
    uint16_t lport, boolean_t ire_requested, boolean_t ipsec_policy_set,
    boolean_t fanout_insert)
{
	int		error = 0;
	ire_t		*src_ire = NULL;
	ipif_t		*ipif = NULL;
	mblk_t		*policy_mp;
	zoneid_t	zoneid;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	if (ipsec_policy_set)
		policy_mp = mp->b_cont;

	/*
	 * If it was previously connected, conn_fully_bound would have
	 * been set.
	 */
	connp->conn_fully_bound = B_FALSE;

	zoneid = connp->conn_zoneid;

	if (!IN6_IS_ADDR_UNSPECIFIED(v6src)) {
		src_ire = ire_route_lookup_v6(v6src, 0, 0,
		    0, NULL, NULL, zoneid, NULL, MATCH_IRE_ZONEONLY, ipst);
		/*
		 * If an address other than in6addr_any is requested,
		 * we verify that it is a valid address for bind
		 * Note: Following code is in if-else-if form for
		 * readability compared to a condition check.
		 */
		ASSERT(src_ire == NULL || !(src_ire->ire_type & IRE_BROADCAST));
		if (IRE_IS_LOCAL(src_ire)) {
			/*
			 * (2) Bind to address of local UP interface
			 */
			ipif = src_ire->ire_ipif;
		} else if (IN6_IS_ADDR_MULTICAST(v6src)) {
			ipif_t	*multi_ipif = NULL;
			ire_t	*save_ire;
			/*
			 * (4) bind to multicast address.
			 * Fake out the IRE returned to upper
			 * layer to be a broadcast IRE in
			 * ip_bind_insert_ire_v6().
			 * Pass other information that matches
			 * the ipif (e.g. the source address).
			 * conn_multicast_ill is only used for
			 * IPv6 packets
			 */
			mutex_enter(&connp->conn_lock);
			if (connp->conn_multicast_ill != NULL) {
				(void) ipif_lookup_zoneid(
				    connp->conn_multicast_ill, zoneid, 0,
				    &multi_ipif);
			} else {
				/*
				 * Look for default like
				 * ip_wput_v6
				 */
				multi_ipif = ipif_lookup_group_v6(
				    &ipv6_unspecified_group, zoneid, ipst);
			}
			mutex_exit(&connp->conn_lock);
			save_ire = src_ire;
			src_ire = NULL;
			if (multi_ipif == NULL || !ire_requested ||
			    (src_ire = ipif_to_ire_v6(multi_ipif)) == NULL) {
				src_ire = save_ire;
				error = EADDRNOTAVAIL;
			} else {
				ASSERT(src_ire != NULL);
				if (save_ire != NULL)
					ire_refrele(save_ire);
			}
			if (multi_ipif != NULL)
				ipif_refrele(multi_ipif);
		} else {
			*mp->b_wptr++ = (char)connp->conn_ulp;
			ipif = ipif_lookup_addr_v6(v6src, NULL, zoneid,
			    CONNP_TO_WQ(connp), mp, ip_wput_nondata, &error,
			    ipst);
			if (ipif == NULL) {
				if (error == EINPROGRESS) {
					if (src_ire != NULL)
						ire_refrele(src_ire);
					return (error);
				}
				/*
				 * Not a valid address for bind
				 */
				error = EADDRNOTAVAIL;
			} else {
				ipif_refrele(ipif);
			}
			/*
			 * Just to keep it consistent with the processing in
			 * ip_bind_v6().
			 */
			mp->b_wptr--;
		}

		if (error != 0) {
			/* Red Alert!  Attempting to be a bogon! */
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("ip_bind_laddr_v6: bad src"
				    " address %s\n", AF_INET6, v6src);
			}
			goto bad_addr;
		}
	}

	/*
	 * Allow setting new policies. For example, disconnects come
	 * down as ipa_t bind. As we would have set conn_policy_cached
	 * to B_TRUE before, we should set it to B_FALSE, so that policy
	 * can change after the disconnect.
	 */
	connp->conn_policy_cached = B_FALSE;

	/* If not fanout_insert this was just an address verification */
	if (fanout_insert) {
		/*
		 * The addresses have been verified. Time to insert in
		 * the correct fanout list.
		 */
		connp->conn_srcv6 = *v6src;
		connp->conn_remv6 = ipv6_all_zeros;
		connp->conn_lport = lport;
		connp->conn_fport = 0;
		error = ipcl_bind_insert_v6(connp, *mp->b_wptr, v6src, lport);
	}
	if (error == 0) {
		if (ire_requested) {
			if (!ip_bind_insert_ire_v6(mp, src_ire, v6src, NULL,
			    ipst)) {
				error = -1;
				goto bad_addr;
			}
		} else if (ipsec_policy_set) {
			if (!ip_bind_ipsec_policy_set(connp, policy_mp)) {
				error = -1;
				goto bad_addr;
			}
		}
	}
bad_addr:
	if (error != 0) {
		if (connp->conn_anon_port) {
			(void) tsol_mlp_anon(crgetzone(connp->conn_cred),
			    connp->conn_mlp_type, connp->conn_ulp, ntohs(lport),
			    B_FALSE);
		}
		connp->conn_mlp_type = mlptSingle;
	}

	if (src_ire != NULL)
		ire_refrele(src_ire);

	if (ipsec_policy_set) {
		ASSERT(policy_mp != NULL);
		freeb(policy_mp);
		/*
		 * As of now assume that nothing else accompanies
		 * IPSEC_POLICY_SET.
		 */
		mp->b_cont = NULL;
	}
	return (error);
}

/* ARGSUSED */
static void
ip_bind_connected_resume_v6(ipsq_t *ipsq, queue_t *q, mblk_t *mp,
    void *dummy_arg)
{
	conn_t	*connp = NULL;
	t_scalar_t prim;

	ASSERT(DB_TYPE(mp) == M_PROTO || DB_TYPE(mp) == M_PCPROTO);

	if (CONN_Q(q))
		connp = Q_TO_CONN(q);
	ASSERT(connp != NULL);

	prim = ((union T_primitives *)mp->b_rptr)->type;
	ASSERT(prim == O_T_BIND_REQ || prim == T_BIND_REQ);

	if (IPCL_IS_TCP(connp)) {
		/* Pass sticky_ipp for scope_id and pktinfo */
		mp = ip_bind_v6(q, mp, connp, &connp->conn_tcp->tcp_sticky_ipp);
	} else {
		/* For UDP and ICMP */
		mp = ip_bind_v6(q, mp, connp, NULL);
	}
	if (mp != NULL) {
		if (IPCL_IS_TCP(connp)) {
			CONN_INC_REF(connp);
			squeue_fill(connp->conn_sqp, mp, ip_resume_tcp_bind,
			    connp, SQTAG_TCP_RPUTOTHER);
		} else if (IPCL_IS_UDP(connp)) {
			udp_resume_bind(connp, mp);
		} else {
			ASSERT(IPCL_IS_RAWIP(connp));
			rawip_resume_bind(connp, mp);
		}
	}
}

/*
 * Verify that both the source and destination addresses
 * are valid.  If verify_dst, then destination address must also be reachable,
 * i.e. have a route.  Protocols like TCP want this.  Tunnels do not.
 * It takes ip6_pkt_t * as one of the arguments to determine correct
 * source address when IPV6_PKTINFO or scope_id is set along with a link-local
 * destination address. Note that parameter ipp is only useful for TCP connect
 * when scope_id is set or IPV6_PKTINFO option is set with an ifindex. For all
 * non-TCP cases, it is NULL and for all other tcp cases it is not useful.
 *
 */
static int
ip_bind_connected_v6(conn_t *connp, mblk_t *mp, in6_addr_t *v6src,
    uint16_t lport, const in6_addr_t *v6dst, ip6_pkt_t *ipp, uint16_t fport,
    boolean_t ire_requested, boolean_t ipsec_policy_set,
    boolean_t fanout_insert, boolean_t verify_dst)
{
	ire_t		*src_ire;
	ire_t		*dst_ire;
	int		error = 0;
	int 		protocol;
	mblk_t		*policy_mp;
	ire_t		*sire = NULL;
	ire_t		*md_dst_ire = NULL;
	ill_t		*md_ill = NULL;
	ill_t 		*dst_ill = NULL;
	ipif_t		*src_ipif = NULL;
	zoneid_t	zoneid;
	boolean_t ill_held = B_FALSE;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	src_ire = dst_ire = NULL;
	/*
	 * NOTE:  The protocol is beyond the wptr because that's how
	 * the undocumented transport<-->IP T_BIND_REQ behavior works.
	 */
	protocol = *mp->b_wptr & 0xFF;

	/*
	 * If we never got a disconnect before, clear it now.
	 */
	connp->conn_fully_bound = B_FALSE;

	if (ipsec_policy_set) {
		policy_mp = mp->b_cont;
	}

	zoneid = connp->conn_zoneid;

	if (IN6_IS_ADDR_MULTICAST(v6dst)) {
		ipif_t *ipif;

		/*
		 * Use an "emulated" IRE_BROADCAST to tell the transport it
		 * is a multicast.
		 * Pass other information that matches
		 * the ipif (e.g. the source address).
		 *
		 * conn_multicast_ill is only used for IPv6 packets
		 */
		mutex_enter(&connp->conn_lock);
		if (connp->conn_multicast_ill != NULL) {
			(void) ipif_lookup_zoneid(connp->conn_multicast_ill,
			    zoneid, 0, &ipif);
		} else {
			/* Look for default like ip_wput_v6 */
			ipif = ipif_lookup_group_v6(v6dst, zoneid, ipst);
		}
		mutex_exit(&connp->conn_lock);
		if (ipif == NULL || !ire_requested ||
		    (dst_ire = ipif_to_ire_v6(ipif)) == NULL) {
			if (ipif != NULL)
				ipif_refrele(ipif);
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("ip_bind_connected_v6: bad "
				    "connected multicast %s\n", AF_INET6,
				    v6dst);
			}
			error = ENETUNREACH;
			goto bad_addr;
		}
		if (ipif != NULL)
			ipif_refrele(ipif);
	} else {
		dst_ire = ire_route_lookup_v6(v6dst, NULL, NULL, 0,
		    NULL, &sire, zoneid, MBLK_GETLABEL(mp),
		    MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
		    MATCH_IRE_PARENT | MATCH_IRE_RJ_BHOLE | MATCH_IRE_SECATTR,
		    ipst);
		/*
		 * We also prevent ire's with src address INADDR_ANY to
		 * be used, which are created temporarily for
		 * sending out packets from endpoints that have
		 * conn_unspec_src set.
		 */
		if (dst_ire == NULL ||
		    (dst_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
		    IN6_IS_ADDR_UNSPECIFIED(&dst_ire->ire_src_addr_v6)) {
			/*
			 * When verifying destination reachability, we always
			 * complain.
			 *
			 * When not verifying destination reachability but we
			 * found an IRE, i.e. the destination is reachable,
			 * then the other tests still apply and we complain.
			 */
			if (verify_dst || (dst_ire != NULL)) {
				if (ip_debug > 2) {
					/* ip1dbg */
					pr_addr_dbg("ip_bind_connected_v6: bad"
					    " connected dst %s\n", AF_INET6,
					    v6dst);
				}
				if (dst_ire == NULL ||
				    !(dst_ire->ire_type & IRE_HOST)) {
					error = ENETUNREACH;
				} else {
					error = EHOSTUNREACH;
				}
				goto bad_addr;
			}
		}
	}

	/*
	 * We now know that routing will allow us to reach the destination.
	 * Check whether Trusted Solaris policy allows communication with this
	 * host, and pretend that the destination is unreachable if not.
	 *
	 * This is never a problem for TCP, since that transport is known to
	 * compute the label properly as part of the tcp_rput_other T_BIND_ACK
	 * handling.  If the remote is unreachable, it will be detected at that
	 * point, so there's no reason to check it here.
	 *
	 * Note that for sendto (and other datagram-oriented friends), this
	 * check is done as part of the data path label computation instead.
	 * The check here is just to make non-TCP connect() report the right
	 * error.
	 */
	if (dst_ire != NULL && is_system_labeled() &&
	    !IPCL_IS_TCP(connp) &&
	    tsol_compute_label_v6(DB_CREDDEF(mp, connp->conn_cred), v6dst, NULL,
	    connp->conn_mac_exempt, ipst) != 0) {
		error = EHOSTUNREACH;
		if (ip_debug > 2) {
			pr_addr_dbg("ip_bind_connected: no label for dst %s\n",
			    AF_INET6, v6dst);
		}
		goto bad_addr;
	}

	/*
	 * If the app does a connect(), it means that it will most likely
	 * send more than 1 packet to the destination.  It makes sense
	 * to clear the temporary flag.
	 */
	if (dst_ire != NULL && dst_ire->ire_type == IRE_CACHE &&
	    (dst_ire->ire_marks & IRE_MARK_TEMPORARY)) {
		irb_t *irb = dst_ire->ire_bucket;

		rw_enter(&irb->irb_lock, RW_WRITER);
		/*
		 * We need to recheck for IRE_MARK_TEMPORARY after acquiring
		 * the lock in order to guarantee irb_tmp_ire_cnt.
		 */
		if (dst_ire->ire_marks & IRE_MARK_TEMPORARY) {
			dst_ire->ire_marks &= ~IRE_MARK_TEMPORARY;
			irb->irb_tmp_ire_cnt--;
		}
		rw_exit(&irb->irb_lock);
	}

	ASSERT(dst_ire == NULL || dst_ire->ire_ipversion == IPV6_VERSION);

	/*
	 * See if we should notify ULP about MDT; we do this whether or not
	 * ire_requested is TRUE, in order to handle active connects; MDT
	 * eligibility tests for passive connects are handled separately
	 * through tcp_adapt_ire().  We do this before the source address
	 * selection, because dst_ire may change after a call to
	 * ipif_select_source_v6().  This is a best-effort check, as the
	 * packet for this connection may not actually go through
	 * dst_ire->ire_stq, and the exact IRE can only be known after
	 * calling ip_newroute_v6().  This is why we further check on the
	 * IRE during Multidata packet transmission in tcp_multisend().
	 */
	if (ipst->ips_ip_multidata_outbound && !ipsec_policy_set &&
	    dst_ire != NULL &&
	    !(dst_ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK | IRE_BROADCAST)) &&
	    (md_ill = ire_to_ill(dst_ire), md_ill != NULL) &&
	    ILL_MDT_CAPABLE(md_ill)) {
		md_dst_ire = dst_ire;
		IRE_REFHOLD(md_dst_ire);
	}

	if (dst_ire != NULL &&
	    dst_ire->ire_type == IRE_LOCAL &&
	    dst_ire->ire_zoneid != zoneid &&
	    dst_ire->ire_zoneid != ALL_ZONES) {
		src_ire = ire_ftable_lookup_v6(v6dst, 0, 0, 0, NULL, NULL,
		    zoneid, 0, NULL,
		    MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
		    MATCH_IRE_RJ_BHOLE, ipst);
		if (src_ire == NULL) {
			error = EHOSTUNREACH;
			goto bad_addr;
		} else if (src_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
			if (!(src_ire->ire_type & IRE_HOST))
				error = ENETUNREACH;
			else
				error = EHOSTUNREACH;
			goto bad_addr;
		}
		if (IN6_IS_ADDR_UNSPECIFIED(v6src)) {
			src_ipif = src_ire->ire_ipif;
			ipif_refhold(src_ipif);
			*v6src = src_ipif->ipif_v6lcl_addr;
		}
		ire_refrele(src_ire);
		src_ire = NULL;
	} else if (IN6_IS_ADDR_UNSPECIFIED(v6src) && dst_ire != NULL) {
		if ((sire != NULL) && (sire->ire_flags & RTF_SETSRC)) {
			*v6src = sire->ire_src_addr_v6;
			ire_refrele(dst_ire);
			dst_ire = sire;
			sire = NULL;
		} else if (dst_ire->ire_type == IRE_CACHE &&
		    (dst_ire->ire_flags & RTF_SETSRC)) {
			ASSERT(dst_ire->ire_zoneid == zoneid ||
			    dst_ire->ire_zoneid == ALL_ZONES);
			*v6src = dst_ire->ire_src_addr_v6;
		} else {
			/*
			 * Pick a source address so that a proper inbound load
			 * spreading would happen. Use dst_ill specified by the
			 * app. when socket option or scopeid is set.
			 */
			int  err;

			if (ipp != NULL && ipp->ipp_ifindex != 0) {
				uint_t	if_index;

				/*
				 * Scope id or IPV6_PKTINFO
				 */

				if_index = ipp->ipp_ifindex;
				dst_ill = ill_lookup_on_ifindex(
				    if_index, B_TRUE, NULL, NULL, NULL, NULL,
				    ipst);
				if (dst_ill == NULL) {
					ip1dbg(("ip_bind_connected_v6:"
					    " bad ifindex %d\n", if_index));
					error = EADDRNOTAVAIL;
					goto bad_addr;
				}
				ill_held = B_TRUE;
			} else if (connp->conn_outgoing_ill != NULL) {
				/*
				 * For IPV6_BOUND_IF socket option,
				 * conn_outgoing_ill should be set
				 * already in TCP or UDP/ICMP.
				 */
				dst_ill = conn_get_held_ill(connp,
				    &connp->conn_outgoing_ill, &err);
				if (err == ILL_LOOKUP_FAILED) {
					ip1dbg(("ip_bind_connected_v6:"
					    "no ill for bound_if\n"));
					error = EADDRNOTAVAIL;
					goto bad_addr;
				}
				ill_held = B_TRUE;
			} else if (dst_ire->ire_stq != NULL) {
				/* No need to hold ill here */
				dst_ill = (ill_t *)dst_ire->ire_stq->q_ptr;
			} else {
				/* No need to hold ill here */
				dst_ill = dst_ire->ire_ipif->ipif_ill;
			}
			if (!ip6_asp_can_lookup(ipst)) {
				*mp->b_wptr++ = (char)protocol;
				ip6_asp_pending_op(CONNP_TO_WQ(connp), mp,
				    ip_bind_connected_resume_v6);
				error = EINPROGRESS;
				goto refrele_and_quit;
			}
			src_ipif = ipif_select_source_v6(dst_ill, v6dst,
			    RESTRICT_TO_NONE, connp->conn_src_preferences,
			    zoneid);
			ip6_asp_table_refrele(ipst);
			if (src_ipif == NULL) {
				pr_addr_dbg("ip_bind_connected_v6: "
				    "no usable source address for "
				    "connection to %s\n", AF_INET6, v6dst);
				error = EADDRNOTAVAIL;
				goto bad_addr;
			}
			*v6src = src_ipif->ipif_v6lcl_addr;
		}
	}

	/*
	 * We do ire_route_lookup_v6() here (and not an interface lookup)
	 * as we assert that v6src should only come from an
	 * UP interface for hard binding.
	 */
	src_ire = ire_route_lookup_v6(v6src, 0, 0, 0, NULL,
	    NULL, zoneid, NULL, MATCH_IRE_ZONEONLY, ipst);

	/* src_ire must be a local|loopback */
	if (!IRE_IS_LOCAL(src_ire)) {
		if (ip_debug > 2) {
			/* ip1dbg */
			pr_addr_dbg("ip_bind_connected_v6: bad "
			    "connected src %s\n", AF_INET6, v6src);
		}
		error = EADDRNOTAVAIL;
		goto bad_addr;
	}

	/*
	 * If the source address is a loopback address, the
	 * destination had best be local or multicast.
	 * The transports that can't handle multicast will reject
	 * those addresses.
	 */
	if (src_ire->ire_type == IRE_LOOPBACK &&
	    !(IRE_IS_LOCAL(dst_ire) || IN6_IS_ADDR_MULTICAST(v6dst) ||
	    IN6_IS_ADDR_V4MAPPED_CLASSD(v6dst))) {
		ip1dbg(("ip_bind_connected_v6: bad connected loopback\n"));
		error = -1;
		goto bad_addr;
	}
	/*
	 * Allow setting new policies. For example, disconnects come
	 * down as ipa_t bind. As we would have set conn_policy_cached
	 * to B_TRUE before, we should set it to B_FALSE, so that policy
	 * can change after the disconnect.
	 */
	connp->conn_policy_cached = B_FALSE;

	/*
	 * The addresses have been verified. Initialize the conn
	 * before calling the policy as they expect the conns
	 * initialized.
	 */
	connp->conn_srcv6 = *v6src;
	connp->conn_remv6 = *v6dst;
	connp->conn_lport = lport;
	connp->conn_fport = fport;

	ASSERT(!(ipsec_policy_set && ire_requested));
	if (ire_requested) {
		iulp_t *ulp_info = NULL;

		/*
		 * Note that sire will not be NULL if this is an off-link
		 * connection and there is not cache for that dest yet.
		 *
		 * XXX Because of an existing bug, if there are multiple
		 * default routes, the IRE returned now may not be the actual
		 * default route used (default routes are chosen in a
		 * round robin fashion).  So if the metrics for different
		 * default routes are different, we may return the wrong
		 * metrics.  This will not be a problem if the existing
		 * bug is fixed.
		 */
		if (sire != NULL)
			ulp_info = &(sire->ire_uinfo);

		if (!ip_bind_insert_ire_v6(mp, dst_ire, v6dst, ulp_info,
		    ipst)) {
			error = -1;
			goto bad_addr;
		}
	} else if (ipsec_policy_set) {
		if (!ip_bind_ipsec_policy_set(connp, policy_mp)) {
			error = -1;
			goto bad_addr;
		}
	}

	/*
	 * Cache IPsec policy in this conn.  If we have per-socket policy,
	 * we'll cache that.  If we don't, we'll inherit global policy.
	 *
	 * We can't insert until the conn reflects the policy. Note that
	 * conn_policy_cached is set by ipsec_conn_cache_policy() even for
	 * connections where we don't have a policy. This is to prevent
	 * global policy lookups in the inbound path.
	 *
	 * If we insert before we set conn_policy_cached,
	 * CONN_INBOUND_POLICY_PRESENT_V6() check can still evaluate true
	 * because global policy cound be non-empty. We normally call
	 * ipsec_check_policy() for conn_policy_cached connections only if
	 * conn_in_enforce_policy is set. But in this case,
	 * conn_policy_cached can get set anytime since we made the
	 * CONN_INBOUND_POLICY_PRESENT_V6() check and ipsec_check_policy()
	 * is called, which will make the above assumption false.  Thus, we
	 * need to insert after we set conn_policy_cached.
	 */
	if ((error = ipsec_conn_cache_policy(connp, B_FALSE)) != 0)
		goto bad_addr;

	/* If not fanout_insert this was just an address verification */
	if (fanout_insert) {
		/*
		 * The addresses have been verified. Time to insert in
		 * the correct fanout list.
		 */
		error = ipcl_conn_insert_v6(connp, protocol, v6src, v6dst,
		    connp->conn_ports,
		    IPCL_IS_TCP(connp) ? connp->conn_tcp->tcp_bound_if : 0);
	}
	if (error == 0) {
		connp->conn_fully_bound = B_TRUE;
		/*
		 * Our initial checks for MDT have passed; the IRE is not
		 * LOCAL/LOOPBACK/BROADCAST, and the link layer seems to
		 * be supporting MDT.  Pass the IRE, IPC and ILL into
		 * ip_mdinfo_return(), which performs further checks
		 * against them and upon success, returns the MDT info
		 * mblk which we will attach to the bind acknowledgment.
		 */
		if (md_dst_ire != NULL) {
			mblk_t *mdinfo_mp;

			ASSERT(md_ill != NULL);
			ASSERT(md_ill->ill_mdt_capab != NULL);
			if ((mdinfo_mp = ip_mdinfo_return(md_dst_ire, connp,
			    md_ill->ill_name, md_ill->ill_mdt_capab)) != NULL)
				linkb(mp, mdinfo_mp);
		}
	}
bad_addr:
	if (ipsec_policy_set) {
		ASSERT(policy_mp != NULL);
		freeb(policy_mp);
		/*
		 * As of now assume that nothing else accompanies
		 * IPSEC_POLICY_SET.
		 */
		mp->b_cont = NULL;
	}
refrele_and_quit:
	if (src_ire != NULL)
		IRE_REFRELE(src_ire);
	if (dst_ire != NULL)
		IRE_REFRELE(dst_ire);
	if (sire != NULL)
		IRE_REFRELE(sire);
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	if (md_dst_ire != NULL)
		IRE_REFRELE(md_dst_ire);
	if (ill_held && dst_ill != NULL)
		ill_refrele(dst_ill);
	return (error);
}

/*
 * Insert the ire in b_cont. Returns false if it fails (due to lack of space).
 * Makes the IRE be IRE_BROADCAST if dst is a multicast address.
 */
/* ARGSUSED4 */
static boolean_t
ip_bind_insert_ire_v6(mblk_t *mp, ire_t *ire, const in6_addr_t *dst,
    iulp_t *ulp_info, ip_stack_t *ipst)
{
	mblk_t	*mp1;
	ire_t	*ret_ire;

	mp1 = mp->b_cont;
	ASSERT(mp1 != NULL);

	if (ire != NULL) {
		/*
		 * mp1 initialized above to IRE_DB_REQ_TYPE
		 * appended mblk. Its <upper protocol>'s
		 * job to make sure there is room.
		 */
		if ((mp1->b_datap->db_lim - mp1->b_rptr) < sizeof (ire_t))
			return (B_FALSE);

		mp1->b_datap->db_type = IRE_DB_TYPE;
		mp1->b_wptr = mp1->b_rptr + sizeof (ire_t);
		bcopy(ire, mp1->b_rptr, sizeof (ire_t));
		ret_ire = (ire_t *)mp1->b_rptr;
		if (IN6_IS_ADDR_MULTICAST(dst) ||
		    IN6_IS_ADDR_V4MAPPED_CLASSD(dst)) {
			ret_ire->ire_type = IRE_BROADCAST;
			ret_ire->ire_addr_v6 = *dst;
		}
		if (ulp_info != NULL) {
			bcopy(ulp_info, &(ret_ire->ire_uinfo),
			    sizeof (iulp_t));
		}
		ret_ire->ire_mp = mp1;
	} else {
		/*
		 * No IRE was found. Remove IRE mblk.
		 */
		mp->b_cont = mp1->b_cont;
		freeb(mp1);
	}
	return (B_TRUE);
}

/*
 * Add an ip6i_t header to the front of the mblk.
 * Inline if possible else allocate a separate mblk containing only the ip6i_t.
 * Returns NULL if allocation fails (and frees original message).
 * Used in outgoing path when going through ip_newroute_*v6().
 * Used in incoming path to pass ifindex to transports.
 */
mblk_t *
ip_add_info_v6(mblk_t *mp, ill_t *ill, const in6_addr_t *dst)
{
	mblk_t *mp1;
	ip6i_t *ip6i;
	ip6_t *ip6h;

	ip6h = (ip6_t *)mp->b_rptr;
	ip6i = (ip6i_t *)(mp->b_rptr - sizeof (ip6i_t));
	if ((uchar_t *)ip6i < mp->b_datap->db_base ||
	    mp->b_datap->db_ref > 1) {
		mp1 = allocb(sizeof (ip6i_t), BPRI_MED);
		if (mp1 == NULL) {
			freemsg(mp);
			return (NULL);
		}
		mp1->b_wptr = mp1->b_rptr = mp1->b_datap->db_lim;
		mp1->b_cont = mp;
		mp = mp1;
		ip6i = (ip6i_t *)(mp->b_rptr - sizeof (ip6i_t));
	}
	mp->b_rptr = (uchar_t *)ip6i;
	ip6i->ip6i_vcf = ip6h->ip6_vcf;
	ip6i->ip6i_nxt = IPPROTO_RAW;
	if (ill != NULL) {
		ip6i->ip6i_flags = IP6I_IFINDEX;
		ip6i->ip6i_ifindex = ill->ill_phyint->phyint_ifindex;
	} else {
		ip6i->ip6i_flags = 0;
	}
	ip6i->ip6i_nexthop = *dst;
	return (mp);
}

/*
 * Handle protocols with which IP is less intimate.  There
 * can be more than one stream bound to a particular
 * protocol.  When this is the case, normally each one gets a copy
 * of any incoming packets.
 * However, if the packet was tunneled and not multicast we only send to it
 * the first match.
 *
 * Zones notes:
 * Packets will be distributed to streams in all zones. This is really only
 * useful for ICMPv6 as only applications in the global zone can create raw
 * sockets for other protocols.
 */
static void
ip_fanout_proto_v6(queue_t *q, mblk_t *mp, ip6_t *ip6h, ill_t *ill,
    ill_t *inill, uint8_t nexthdr, uint_t nexthdr_offset, uint_t flags,
    boolean_t mctl_present, zoneid_t zoneid)
{
	queue_t	*rq;
	mblk_t	*mp1, *first_mp1;
	in6_addr_t dst = ip6h->ip6_dst;
	in6_addr_t src = ip6h->ip6_src;
	boolean_t one_only;
	mblk_t *first_mp = mp;
	boolean_t secure, shared_addr;
	conn_t	*connp, *first_connp, *next_connp;
	connf_t *connfp;
	ip_stack_t	*ipst = inill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	if (mctl_present) {
		mp = first_mp->b_cont;
		secure = ipsec_in_is_secure(first_mp);
		ASSERT(mp != NULL);
	} else {
		secure = B_FALSE;
	}

	/*
	 * If the packet was tunneled and not multicast we only send to it
	 * the first match.
	 */
	one_only = ((nexthdr == IPPROTO_ENCAP || nexthdr == IPPROTO_IPV6) &&
	    !IN6_IS_ADDR_MULTICAST(&dst));

	shared_addr = (zoneid == ALL_ZONES);
	if (shared_addr) {
		/*
		 * We don't allow multilevel ports for raw IP, so no need to
		 * check for that here.
		 */
		zoneid = tsol_packet_to_zoneid(mp);
	}

	connfp = &ipst->ips_ipcl_proto_fanout_v6[nexthdr];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		if (IPCL_PROTO_MATCH_V6(connp, nexthdr, ip6h, ill, flags,
		    zoneid) &&
		    (!is_system_labeled() ||
		    tsol_receive_local(mp, &dst, IPV6_VERSION, shared_addr,
		    connp)))
			break;
	}

	if (connp == NULL || connp->conn_upq == NULL) {
		/*
		 * No one bound to this port.  Is
		 * there a client that wants all
		 * unclaimed datagrams?
		 */
		mutex_exit(&connfp->connf_lock);
		if (ip_fanout_send_icmp_v6(q, first_mp, flags,
		    ICMP6_PARAM_PROB, ICMP6_PARAMPROB_NEXTHEADER,
		    nexthdr_offset, mctl_present, zoneid, ipst)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInUnknownProtos);
		}

		return;
	}

	CONN_INC_REF(connp);
	first_connp = connp;

	/*
	 * XXX: Fix the multiple protocol listeners case. We should not
	 * be walking the conn->next list here.
	 */
	if (one_only) {
		/*
		 * Only send message to one tunnel driver by immediately
		 * terminating the loop.
		 */
		connp = NULL;
	} else {
		connp = connp->conn_next;

	}
	for (;;) {
		while (connp != NULL) {
			if (IPCL_PROTO_MATCH_V6(connp, nexthdr, ip6h, ill,
			    flags, zoneid) &&
			    (!is_system_labeled() ||
			    tsol_receive_local(mp, &dst, IPV6_VERSION,
			    shared_addr, connp)))
				break;
			connp = connp->conn_next;
		}

		/*
		 * Just copy the data part alone. The mctl part is
		 * needed just for verifying policy and it is never
		 * sent up.
		 */
		if (connp == NULL || connp->conn_upq == NULL ||
		    (((first_mp1 = dupmsg(first_mp)) == NULL) &&
		    ((first_mp1 = ip_copymsg(first_mp)) == NULL))) {
			/*
			 * No more intested clients or memory
			 * allocation failed
			 */
			connp = first_connp;
			break;
		}
		mp1 = mctl_present ? first_mp1->b_cont : first_mp1;
		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);
		rq = connp->conn_rq;
		/*
		 * For link-local always add ifindex so that transport can set
		 * sin6_scope_id. Avoid it for ICMP error fanout.
		 */
		if ((connp->conn_ip_recvpktinfo ||
		    IN6_IS_ADDR_LINKLOCAL(&src)) &&
		    (flags & IP_FF_IPINFO)) {
			/* Add header */
			mp1 = ip_add_info_v6(mp1, inill, &dst);
		}
		if (mp1 == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		} else if (!canputnext(rq)) {
			if (flags & IP_FF_RAWIP) {
				BUMP_MIB(ill->ill_ip_mib,
				    rawipIfStatsInOverflows);
			} else {
				BUMP_MIB(ill->ill_icmp6_mib,
				    ipv6IfIcmpInOverflows);
			}

			freemsg(mp1);
		} else {
			/*
			 * Don't enforce here if we're a tunnel - let "tun" do
			 * it instead.
			 */
			if (!IPCL_IS_IPTUN(connp) &&
			    (CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) ||
			    secure)) {
				first_mp1 = ipsec_check_inbound_policy
				    (first_mp1, connp, NULL, ip6h,
				    mctl_present);
			}
			if (first_mp1 != NULL) {
				if (mctl_present)
					freeb(first_mp1);
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsHCInDelivers);
				(connp->conn_recv)(connp, mp1, NULL);
			}
		}
		mutex_enter(&connfp->connf_lock);
		/* Follow the next pointer before releasing the conn. */
		next_connp = connp->conn_next;
		CONN_DEC_REF(connp);
		connp = next_connp;
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);

	/* Initiate IPPF processing */
	if (IP6_IN_IPP(flags, ipst)) {
		uint_t ifindex;

		mutex_enter(&ill->ill_lock);
		ifindex = ill->ill_phyint->phyint_ifindex;
		mutex_exit(&ill->ill_lock);
		ip_process(IPP_LOCAL_IN, &mp, ifindex);
		if (mp == NULL) {
			CONN_DEC_REF(connp);
			if (mctl_present)
				freeb(first_mp);
			return;
		}
	}

	/*
	 * For link-local always add ifindex so that transport can set
	 * sin6_scope_id. Avoid it for ICMP error fanout.
	 */
	if ((connp->conn_ip_recvpktinfo || IN6_IS_ADDR_LINKLOCAL(&src)) &&
	    (flags & IP_FF_IPINFO)) {
		/* Add header */
		mp = ip_add_info_v6(mp, inill, &dst);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			if (mctl_present)
				freeb(first_mp);
			return;
		} else if (mctl_present) {
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}
	}

	rq = connp->conn_rq;
	if (!canputnext(rq)) {
		if (flags & IP_FF_RAWIP) {
			BUMP_MIB(ill->ill_ip_mib, rawipIfStatsInOverflows);
		} else {
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInOverflows);
		}

		freemsg(first_mp);
	} else {
		if (IPCL_IS_IPTUN(connp)) {
			/*
			 * Tunneled packet.  We enforce policy in the tunnel
			 * module itself.
			 *
			 * Send the WHOLE packet up (incl. IPSEC_IN) without
			 * a policy check.
			 */
			putnext(rq, first_mp);
			CONN_DEC_REF(connp);
			return;
		}
		/*
		 * Don't enforce here if we're a tunnel - let "tun" do
		 * it instead.
		 */
		if (nexthdr != IPPROTO_ENCAP && nexthdr != IPPROTO_IPV6 &&
		    (CONN_INBOUND_POLICY_PRESENT(connp, ipss) || secure)) {
			first_mp = ipsec_check_inbound_policy(first_mp, connp,
			    NULL, ip6h, mctl_present);
			if (first_mp == NULL) {
				CONN_DEC_REF(connp);
				return;
			}
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		(connp->conn_recv)(connp, mp, NULL);
		if (mctl_present)
			freeb(first_mp);
	}
	CONN_DEC_REF(connp);
}

/*
 * Send an ICMP error after patching up the packet appropriately.  Returns
 * non-zero if the appropriate MIB should be bumped; zero otherwise.
 */
int
ip_fanout_send_icmp_v6(queue_t *q, mblk_t *mp, uint_t flags,
    uint_t icmp_type, uint8_t icmp_code, uint_t nexthdr_offset,
    boolean_t mctl_present, zoneid_t zoneid, ip_stack_t *ipst)
{
	ip6_t *ip6h;
	mblk_t *first_mp;
	boolean_t secure;
	unsigned char db_type;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	first_mp = mp;
	if (mctl_present) {
		mp = mp->b_cont;
		secure = ipsec_in_is_secure(first_mp);
		ASSERT(mp != NULL);
	} else {
		/*
		 * If this is an ICMP error being reported - which goes
		 * up as M_CTLs, we need to convert them to M_DATA till
		 * we finish checking with global policy because
		 * ipsec_check_global_policy() assumes M_DATA as clear
		 * and M_CTL as secure.
		 */
		db_type = mp->b_datap->db_type;
		mp->b_datap->db_type = M_DATA;
		secure = B_FALSE;
	}
	/*
	 * We are generating an icmp error for some inbound packet.
	 * Called from all ip_fanout_(udp, tcp, proto) functions.
	 * Before we generate an error, check with global policy
	 * to see whether this is allowed to enter the system. As
	 * there is no "conn", we are checking with global policy.
	 */
	ip6h = (ip6_t *)mp->b_rptr;
	if (secure || ipss->ipsec_inbound_v6_policy_present) {
		first_mp = ipsec_check_global_policy(first_mp, NULL,
		    NULL, ip6h, mctl_present, ipst->ips_netstack);
		if (first_mp == NULL)
			return (0);
	}

	if (!mctl_present)
		mp->b_datap->db_type = db_type;

	if (flags & IP_FF_SEND_ICMP) {
		if (flags & IP_FF_HDR_COMPLETE) {
			if (ip_hdr_complete_v6(ip6h, zoneid, ipst)) {
				freemsg(first_mp);
				return (1);
			}
		}
		switch (icmp_type) {
		case ICMP6_DST_UNREACH:
			icmp_unreachable_v6(WR(q), first_mp, icmp_code,
			    B_FALSE, B_FALSE, zoneid, ipst);
			break;
		case ICMP6_PARAM_PROB:
			icmp_param_problem_v6(WR(q), first_mp, icmp_code,
			    nexthdr_offset, B_FALSE, B_FALSE, zoneid, ipst);
			break;
		default:
#ifdef DEBUG
			panic("ip_fanout_send_icmp_v6: wrong type");
			/*NOTREACHED*/
#else
			freemsg(first_mp);
			break;
#endif
		}
	} else {
		freemsg(first_mp);
		return (0);
	}

	return (1);
}


/*
 * Fanout for TCP packets
 * The caller puts <fport, lport> in the ports parameter.
 */
static void
ip_fanout_tcp_v6(queue_t *q, mblk_t *mp, ip6_t *ip6h, ill_t *ill, ill_t *inill,
    uint_t flags, uint_t hdr_len, boolean_t mctl_present, zoneid_t zoneid)
{
	mblk_t  	*first_mp;
	boolean_t 	secure;
	conn_t		*connp;
	tcph_t		*tcph;
	boolean_t	syn_present = B_FALSE;
	ip_stack_t	*ipst = inill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	first_mp = mp;
	if (mctl_present) {
		mp = first_mp->b_cont;
		secure = ipsec_in_is_secure(first_mp);
		ASSERT(mp != NULL);
	} else {
		secure = B_FALSE;
	}

	connp = ipcl_classify_v6(mp, IPPROTO_TCP, hdr_len, zoneid, ipst);

	if (connp == NULL ||
	    !conn_wantpacket_v6(connp, ill, ip6h, flags, zoneid)) {
		/*
		 * No hard-bound match. Send Reset.
		 */
		dblk_t *dp = mp->b_datap;
		uint32_t ill_index;

		ASSERT((dp->db_struioflag & STRUIO_IP) == 0);

		/* Initiate IPPf processing, if needed. */
		if (IPP_ENABLED(IPP_LOCAL_IN, ipst) &&
		    (flags & IP6_NO_IPPOLICY)) {
			ill_index = ill->ill_phyint->phyint_ifindex;
			ip_process(IPP_LOCAL_IN, &first_mp, ill_index);
			if (first_mp == NULL) {
				if (connp != NULL)
					CONN_DEC_REF(connp);
				return;
			}
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		tcp_xmit_listeners_reset(first_mp, hdr_len, zoneid,
		    ipst->ips_netstack->netstack_tcp, connp);
		if (connp != NULL)
			CONN_DEC_REF(connp);
		return;
	}

	tcph = (tcph_t *)&mp->b_rptr[hdr_len];
	if ((tcph->th_flags[0] & (TH_SYN|TH_ACK|TH_RST|TH_URG)) == TH_SYN) {
		if (connp->conn_flags & IPCL_TCP) {
			squeue_t *sqp;

			/*
			 * For fused tcp loopback, assign the eager's
			 * squeue to be that of the active connect's.
			 */
			if ((flags & IP_FF_LOOPBACK) && do_tcp_fusion &&
			    !CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) &&
			    !secure &&
			    !IP6_IN_IPP(flags, ipst)) {
				ASSERT(Q_TO_CONN(q) != NULL);
				sqp = Q_TO_CONN(q)->conn_sqp;
			} else {
				sqp = IP_SQUEUE_GET(lbolt);
			}

			mp->b_datap->db_struioflag |= STRUIO_EAGER;
			DB_CKSUMSTART(mp) = (intptr_t)sqp;

			/*
			 * db_cksumstuff is unused in the incoming
			 * path; Thus store the ifindex here. It will
			 * be cleared in tcp_conn_create_v6().
			 */
			DB_CKSUMSTUFF(mp) =
			    (intptr_t)ill->ill_phyint->phyint_ifindex;
			syn_present = B_TRUE;
		}
	}

	if (IPCL_IS_TCP(connp) && IPCL_IS_BOUND(connp) && !syn_present) {
		uint_t	flags = (unsigned int)tcph->th_flags[0] & 0xFF;
		if ((flags & TH_RST) || (flags & TH_URG)) {
			CONN_DEC_REF(connp);
			freemsg(first_mp);
			return;
		}
		if (flags & TH_ACK) {
			tcp_xmit_listeners_reset(first_mp, hdr_len, zoneid,
			    ipst->ips_netstack->netstack_tcp, connp);
			CONN_DEC_REF(connp);
			return;
		}

		CONN_DEC_REF(connp);
		freemsg(first_mp);
		return;
	}

	if (CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) || secure) {
		first_mp = ipsec_check_inbound_policy(first_mp, connp,
		    NULL, ip6h, mctl_present);
		if (first_mp == NULL) {
			CONN_DEC_REF(connp);
			return;
		}
		if (IPCL_IS_TCP(connp) && IPCL_IS_BOUND(connp)) {
			ASSERT(syn_present);
			if (mctl_present) {
				ASSERT(first_mp != mp);
				first_mp->b_datap->db_struioflag |=
				    STRUIO_POLICY;
			} else {
				ASSERT(first_mp == mp);
				mp->b_datap->db_struioflag &=
				    ~STRUIO_EAGER;
				mp->b_datap->db_struioflag |=
				    STRUIO_POLICY;
			}
		} else {
			/*
			 * Discard first_mp early since we're dealing with a
			 * fully-connected conn_t and tcp doesn't do policy in
			 * this case. Also, if someone is bound to IPPROTO_TCP
			 * over raw IP, they don't expect to see a M_CTL.
			 */
			if (mctl_present) {
				freeb(first_mp);
				mctl_present = B_FALSE;
			}
			first_mp = mp;
		}
	}

	/* Initiate IPPF processing */
	if (IP6_IN_IPP(flags, ipst)) {
		uint_t	ifindex;

		mutex_enter(&ill->ill_lock);
		ifindex = ill->ill_phyint->phyint_ifindex;
		mutex_exit(&ill->ill_lock);
		ip_process(IPP_LOCAL_IN, &mp, ifindex);
		if (mp == NULL) {
			CONN_DEC_REF(connp);
			if (mctl_present) {
				freeb(first_mp);
			}
			return;
		} else if (mctl_present) {
			/*
			 * ip_add_info_v6 might return a new mp.
			 */
			ASSERT(first_mp != mp);
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}
	}

	/*
	 * For link-local always add ifindex so that TCP can bind to that
	 * interface. Avoid it for ICMP error fanout.
	 */
	if (!syn_present && ((connp->conn_ip_recvpktinfo ||
	    IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src)) &&
	    (flags & IP_FF_IPINFO))) {
		/* Add header */
		mp = ip_add_info_v6(mp, inill, &ip6h->ip6_dst);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			if (mctl_present)
				freeb(first_mp);
			return;
		} else if (mctl_present) {
			ASSERT(first_mp != mp);
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}
	}

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
	if (IPCL_IS_TCP(connp)) {
		(*ip_input_proc)(connp->conn_sqp, first_mp,
		    connp->conn_recv, connp, SQTAG_IP6_TCP_INPUT);
	} else {
		/* SOCK_RAW, IPPROTO_TCP case */
		(connp->conn_recv)(connp, first_mp, NULL);
		CONN_DEC_REF(connp);
	}
}

/*
 * Fanout for UDP packets.
 * The caller puts <fport, lport> in the ports parameter.
 * ire_type must be IRE_BROADCAST for multicast and broadcast packets.
 *
 * If SO_REUSEADDR is set all multicast and broadcast packets
 * will be delivered to all streams bound to the same port.
 *
 * Zones notes:
 * Multicast packets will be distributed to streams in all zones.
 */
static void
ip_fanout_udp_v6(queue_t *q, mblk_t *mp, ip6_t *ip6h, uint32_t ports,
    ill_t *ill, ill_t *inill, uint_t flags, boolean_t mctl_present,
    zoneid_t zoneid)
{
	uint32_t	dstport, srcport;
	in6_addr_t	dst;
	mblk_t		*first_mp;
	boolean_t	secure;
	conn_t		*connp;
	connf_t		*connfp;
	conn_t		*first_conn;
	conn_t 		*next_conn;
	mblk_t		*mp1, *first_mp1;
	in6_addr_t	src;
	boolean_t	shared_addr;
	ip_stack_t	*ipst = inill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	first_mp = mp;
	if (mctl_present) {
		mp = first_mp->b_cont;
		secure = ipsec_in_is_secure(first_mp);
		ASSERT(mp != NULL);
	} else {
		secure = B_FALSE;
	}

	/* Extract ports in net byte order */
	dstport = htons(ntohl(ports) & 0xFFFF);
	srcport = htons(ntohl(ports) >> 16);
	dst = ip6h->ip6_dst;
	src = ip6h->ip6_src;

	shared_addr = (zoneid == ALL_ZONES);
	if (shared_addr) {
		/*
		 * No need to handle exclusive-stack zones since ALL_ZONES
		 * only applies to the shared stack.
		 */
		zoneid = tsol_mlp_findzone(IPPROTO_UDP, dstport);
		/*
		 * If no shared MLP is found, tsol_mlp_findzone returns
		 * ALL_ZONES.  In that case, we assume it's SLP, and
		 * search for the zone based on the packet label.
		 * That will also return ALL_ZONES on failure, but
		 * we never allow conn_zoneid to be set to ALL_ZONES.
		 */
		if (zoneid == ALL_ZONES)
			zoneid = tsol_packet_to_zoneid(mp);
	}

	/* Attempt to find a client stream based on destination port. */
	connfp = &ipst->ips_ipcl_udp_fanout[IPCL_UDP_HASH(dstport, ipst)];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;
	if (!IN6_IS_ADDR_MULTICAST(&dst)) {
		/*
		 * Not multicast. Send to the one (first) client we find.
		 */
		while (connp != NULL) {
			if (IPCL_UDP_MATCH_V6(connp, dstport, dst, srcport,
			    src) && IPCL_ZONE_MATCH(connp, zoneid) &&
			    conn_wantpacket_v6(connp, ill, ip6h,
			    flags, zoneid)) {
				break;
			}
			connp = connp->conn_next;
		}
		if (connp == NULL || connp->conn_upq == NULL)
			goto notfound;

		if (is_system_labeled() &&
		    !tsol_receive_local(mp, &dst, IPV6_VERSION, shared_addr,
		    connp))
			goto notfound;

		/* Found a client */
		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);

		if (CONN_UDP_FLOWCTLD(connp)) {
			freemsg(first_mp);
			CONN_DEC_REF(connp);
			return;
		}
		if (CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) || secure) {
			first_mp = ipsec_check_inbound_policy(first_mp,
			    connp, NULL, ip6h, mctl_present);
			if (first_mp == NULL) {
				CONN_DEC_REF(connp);
				return;
			}
		}
		/* Initiate IPPF processing */
		if (IP6_IN_IPP(flags, ipst)) {
			uint_t	ifindex;

			mutex_enter(&ill->ill_lock);
			ifindex = ill->ill_phyint->phyint_ifindex;
			mutex_exit(&ill->ill_lock);
			ip_process(IPP_LOCAL_IN, &mp, ifindex);
			if (mp == NULL) {
				CONN_DEC_REF(connp);
				if (mctl_present)
					freeb(first_mp);
				return;
			}
		}
		/*
		 * For link-local always add ifindex so that
		 * transport can set sin6_scope_id. Avoid it for
		 * ICMP error fanout.
		 */
		if ((connp->conn_ip_recvpktinfo ||
		    IN6_IS_ADDR_LINKLOCAL(&src)) &&
		    (flags & IP_FF_IPINFO)) {
				/* Add header */
			mp = ip_add_info_v6(mp, inill, &dst);
			if (mp == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				CONN_DEC_REF(connp);
				if (mctl_present)
					freeb(first_mp);
				return;
			} else if (mctl_present) {
				first_mp->b_cont = mp;
			} else {
				first_mp = mp;
			}
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);

		/* Send it upstream */
		(connp->conn_recv)(connp, mp, NULL);

		IP6_STAT(ipst, ip6_udp_fannorm);
		CONN_DEC_REF(connp);
		if (mctl_present)
			freeb(first_mp);
		return;
	}

	while (connp != NULL) {
		if ((IPCL_UDP_MATCH_V6(connp, dstport, dst, srcport, src)) &&
		    conn_wantpacket_v6(connp, ill, ip6h, flags, zoneid) &&
		    (!is_system_labeled() ||
		    tsol_receive_local(mp, &dst, IPV6_VERSION, shared_addr,
		    connp)))
			break;
		connp = connp->conn_next;
	}

	if (connp == NULL || connp->conn_upq == NULL)
		goto notfound;

	first_conn = connp;

	CONN_INC_REF(connp);
	connp = connp->conn_next;
	for (;;) {
		while (connp != NULL) {
			if (IPCL_UDP_MATCH_V6(connp, dstport, dst, srcport,
			    src) && conn_wantpacket_v6(connp, ill, ip6h,
			    flags, zoneid) &&
			    (!is_system_labeled() ||
			    tsol_receive_local(mp, &dst, IPV6_VERSION,
			    shared_addr, connp)))
				break;
			connp = connp->conn_next;
		}
		/*
		 * Just copy the data part alone. The mctl part is
		 * needed just for verifying policy and it is never
		 * sent up.
		 */
		if (connp == NULL ||
		    (((first_mp1 = dupmsg(first_mp)) == NULL) &&
		    ((first_mp1 = ip_copymsg(first_mp)) == NULL))) {
			/*
			 * No more interested clients or memory
			 * allocation failed
			 */
			connp = first_conn;
			break;
		}
		mp1 = mctl_present ? first_mp1->b_cont : first_mp1;
		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);
		/*
		 * For link-local always add ifindex so that transport
		 * can set sin6_scope_id. Avoid it for ICMP error
		 * fanout.
		 */
		if ((connp->conn_ip_recvpktinfo ||
		    IN6_IS_ADDR_LINKLOCAL(&src)) &&
		    (flags & IP_FF_IPINFO)) {
			/* Add header */
			mp1 = ip_add_info_v6(mp1, inill, &dst);
		}
		/* mp1 could have changed */
		if (mctl_present)
			first_mp1->b_cont = mp1;
		else
			first_mp1 = mp1;
		if (mp1 == NULL) {
			if (mctl_present)
				freeb(first_mp1);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			goto next_one;
		}
		if (CONN_UDP_FLOWCTLD(connp)) {
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsInOverflows);
			freemsg(first_mp1);
			goto next_one;
		}

		if (CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) || secure) {
			first_mp1 = ipsec_check_inbound_policy
			    (first_mp1, connp, NULL, ip6h,
			    mctl_present);
		}
		if (first_mp1 != NULL) {
			if (mctl_present)
				freeb(first_mp1);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);

			/* Send it upstream */
			(connp->conn_recv)(connp, mp1, NULL);
		}
next_one:
		mutex_enter(&connfp->connf_lock);
		/* Follow the next pointer before releasing the conn. */
		next_conn = connp->conn_next;
		IP6_STAT(ipst, ip6_udp_fanmb);
		CONN_DEC_REF(connp);
		connp = next_conn;
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);

	/* Initiate IPPF processing */
	if (IP6_IN_IPP(flags, ipst)) {
		uint_t	ifindex;

		mutex_enter(&ill->ill_lock);
		ifindex = ill->ill_phyint->phyint_ifindex;
		mutex_exit(&ill->ill_lock);
		ip_process(IPP_LOCAL_IN, &mp, ifindex);
		if (mp == NULL) {
			CONN_DEC_REF(connp);
			if (mctl_present) {
				freeb(first_mp);
			}
			return;
		}
	}

	/*
	 * For link-local always add ifindex so that transport can set
	 * sin6_scope_id. Avoid it for ICMP error fanout.
	 */
	if ((connp->conn_ip_recvpktinfo ||
	    IN6_IS_ADDR_LINKLOCAL(&src)) && (flags & IP_FF_IPINFO)) {
		/* Add header */
		mp = ip_add_info_v6(mp, inill, &dst);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			if (mctl_present)
				freeb(first_mp);
			return;
		} else if (mctl_present) {
			first_mp->b_cont = mp;
		} else {
			first_mp = mp;
		}
	}
	if (CONN_UDP_FLOWCTLD(connp)) {
		BUMP_MIB(ill->ill_ip_mib, udpIfStatsInOverflows);
		freemsg(mp);
	} else {
		if (CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) || secure) {
			first_mp = ipsec_check_inbound_policy(first_mp,
			    connp, NULL, ip6h, mctl_present);
			if (first_mp == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				CONN_DEC_REF(connp);
				return;
			}
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);

		/* Send it upstream */
		(connp->conn_recv)(connp, mp, NULL);
	}
	IP6_STAT(ipst, ip6_udp_fanmb);
	CONN_DEC_REF(connp);
	if (mctl_present)
		freeb(first_mp);
	return;

notfound:
	mutex_exit(&connfp->connf_lock);
	/*
	 * No one bound to this port.  Is
	 * there a client that wants all
	 * unclaimed datagrams?
	 */
	if (ipst->ips_ipcl_proto_fanout_v6[IPPROTO_UDP].connf_head != NULL) {
		ip_fanout_proto_v6(q, first_mp, ip6h, ill, inill, IPPROTO_UDP,
		    0, flags | IP_FF_RAWIP | IP_FF_IPINFO, mctl_present,
		    zoneid);
	} else {
		if (ip_fanout_send_icmp_v6(q, first_mp, flags,
		    ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT, 0,
		    mctl_present, zoneid, ipst)) {
			BUMP_MIB(ill->ill_ip_mib, udpIfStatsNoPorts);
		}
	}
}

/*
 * int ip_find_hdr_v6()
 *
 * This routine is used by the upper layer protocols and the IP tunnel
 * module to:
 * - Set extension header pointers to appropriate locations
 * - Determine IPv6 header length and return it
 * - Return a pointer to the last nexthdr value
 *
 * The caller must initialize ipp_fields.
 *
 * NOTE: If multiple extension headers of the same type are present,
 * ip_find_hdr_v6() will set the respective extension header pointers
 * to the first one that it encounters in the IPv6 header.  It also
 * skips fragment headers.  This routine deals with malformed packets
 * of various sorts in which case the returned length is up to the
 * malformed part.
 */
int
ip_find_hdr_v6(mblk_t *mp, ip6_t *ip6h, ip6_pkt_t *ipp, uint8_t *nexthdrp)
{
	uint_t	length, ehdrlen;
	uint8_t nexthdr;
	uint8_t *whereptr, *endptr;
	ip6_dest_t *tmpdstopts;
	ip6_rthdr_t *tmprthdr;
	ip6_hbh_t *tmphopopts;
	ip6_frag_t *tmpfraghdr;

	length = IPV6_HDR_LEN;
	whereptr = ((uint8_t *)&ip6h[1]); /* point to next hdr */
	endptr = mp->b_wptr;

	nexthdr = ip6h->ip6_nxt;
	while (whereptr < endptr) {
		/* Is there enough left for len + nexthdr? */
		if (whereptr + MIN_EHDR_LEN > endptr)
			goto done;

		switch (nexthdr) {
		case IPPROTO_HOPOPTS:
			tmphopopts = (ip6_hbh_t *)whereptr;
			ehdrlen = 8 * (tmphopopts->ip6h_len + 1);
			if ((uchar_t *)tmphopopts +  ehdrlen > endptr)
				goto done;
			nexthdr = tmphopopts->ip6h_nxt;
			/* return only 1st hbh */
			if (!(ipp->ipp_fields & IPPF_HOPOPTS)) {
				ipp->ipp_fields |= IPPF_HOPOPTS;
				ipp->ipp_hopopts = tmphopopts;
				ipp->ipp_hopoptslen = ehdrlen;
			}
			break;
		case IPPROTO_DSTOPTS:
			tmpdstopts = (ip6_dest_t *)whereptr;
			ehdrlen = 8 * (tmpdstopts->ip6d_len + 1);
			if ((uchar_t *)tmpdstopts +  ehdrlen > endptr)
				goto done;
			nexthdr = tmpdstopts->ip6d_nxt;
			/*
			 * ipp_dstopts is set to the destination header after a
			 * routing header.
			 * Assume it is a post-rthdr destination header
			 * and adjust when we find an rthdr.
			 */
			if (!(ipp->ipp_fields & IPPF_DSTOPTS)) {
				ipp->ipp_fields |= IPPF_DSTOPTS;
				ipp->ipp_dstopts = tmpdstopts;
				ipp->ipp_dstoptslen = ehdrlen;
			}
			break;
		case IPPROTO_ROUTING:
			tmprthdr = (ip6_rthdr_t *)whereptr;
			ehdrlen = 8 * (tmprthdr->ip6r_len + 1);
			if ((uchar_t *)tmprthdr +  ehdrlen > endptr)
				goto done;
			nexthdr = tmprthdr->ip6r_nxt;
			/* return only 1st rthdr */
			if (!(ipp->ipp_fields & IPPF_RTHDR)) {
				ipp->ipp_fields |= IPPF_RTHDR;
				ipp->ipp_rthdr = tmprthdr;
				ipp->ipp_rthdrlen = ehdrlen;
			}
			/*
			 * Make any destination header we've seen be a
			 * pre-rthdr destination header.
			 */
			if (ipp->ipp_fields & IPPF_DSTOPTS) {
				ipp->ipp_fields &= ~IPPF_DSTOPTS;
				ipp->ipp_fields |= IPPF_RTDSTOPTS;
				ipp->ipp_rtdstopts = ipp->ipp_dstopts;
				ipp->ipp_dstopts = NULL;
				ipp->ipp_rtdstoptslen = ipp->ipp_dstoptslen;
				ipp->ipp_dstoptslen = 0;
			}
			break;
		case IPPROTO_FRAGMENT:
			tmpfraghdr = (ip6_frag_t *)whereptr;
			ehdrlen = sizeof (ip6_frag_t);
			if ((uchar_t *)tmpfraghdr + ehdrlen > endptr)
				goto done;
			nexthdr = tmpfraghdr->ip6f_nxt;
			if (!(ipp->ipp_fields & IPPF_FRAGHDR)) {
				ipp->ipp_fields |= IPPF_FRAGHDR;
				ipp->ipp_fraghdr = tmpfraghdr;
				ipp->ipp_fraghdrlen = ehdrlen;
			}
			break;
		case IPPROTO_NONE:
		default:
			goto done;
		}
		length += ehdrlen;
		whereptr += ehdrlen;
	}
done:
	if (nexthdrp != NULL)
		*nexthdrp = nexthdr;
	return (length);
}

int
ip_hdr_complete_v6(ip6_t *ip6h, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t *ire;

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src)) {
		ire = ire_lookup_local_v6(zoneid, ipst);
		if (ire == NULL) {
			ip1dbg(("ip_hdr_complete_v6: no source IRE\n"));
			return (1);
		}
		ip6h->ip6_src = ire->ire_addr_v6;
		ire_refrele(ire);
	}
	ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	ip6h->ip6_hops = ipst->ips_ipv6_def_hops;
	return (0);
}

/*
 * Try to determine where and what are the IPv6 header length and
 * pointer to nexthdr value for the upper layer protocol (or an
 * unknown next hdr).
 *
 * Parameters returns a pointer to the nexthdr value;
 * Must handle malformed packets of various sorts.
 * Function returns failure for malformed cases.
 */
boolean_t
ip_hdr_length_nexthdr_v6(mblk_t *mp, ip6_t *ip6h, uint16_t *hdr_length_ptr,
    uint8_t **nexthdrpp)
{
	uint16_t length;
	uint_t	ehdrlen;
	uint8_t	*nexthdrp;
	uint8_t *whereptr;
	uint8_t *endptr;
	ip6_dest_t *desthdr;
	ip6_rthdr_t *rthdr;
	ip6_frag_t *fraghdr;

	ASSERT((IPH_HDR_VERSION(ip6h) & ~IP_FORWARD_PROG_BIT) == IPV6_VERSION);
	length = IPV6_HDR_LEN;
	whereptr = ((uint8_t *)&ip6h[1]); /* point to next hdr */
	endptr = mp->b_wptr;

	nexthdrp = &ip6h->ip6_nxt;
	while (whereptr < endptr) {
		/* Is there enough left for len + nexthdr? */
		if (whereptr + MIN_EHDR_LEN > endptr)
			break;

		switch (*nexthdrp) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
			/* Assumes the headers are identical for hbh and dst */
			desthdr = (ip6_dest_t *)whereptr;
			ehdrlen = 8 * (desthdr->ip6d_len + 1);
			if ((uchar_t *)desthdr +  ehdrlen > endptr)
				return (B_FALSE);
			nexthdrp = &desthdr->ip6d_nxt;
			break;
		case IPPROTO_ROUTING:
			rthdr = (ip6_rthdr_t *)whereptr;
			ehdrlen =  8 * (rthdr->ip6r_len + 1);
			if ((uchar_t *)rthdr +  ehdrlen > endptr)
				return (B_FALSE);
			nexthdrp = &rthdr->ip6r_nxt;
			break;
		case IPPROTO_FRAGMENT:
			fraghdr = (ip6_frag_t *)whereptr;
			ehdrlen = sizeof (ip6_frag_t);
			if ((uchar_t *)&fraghdr[1] > endptr)
				return (B_FALSE);
			nexthdrp = &fraghdr->ip6f_nxt;
			break;
		case IPPROTO_NONE:
			/* No next header means we're finished */
		default:
			*hdr_length_ptr = length;
			*nexthdrpp = nexthdrp;
			return (B_TRUE);
		}
		length += ehdrlen;
		whereptr += ehdrlen;
		*hdr_length_ptr = length;
		*nexthdrpp = nexthdrp;
	}
	switch (*nexthdrp) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_DSTOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
		/*
		 * If any know extension headers are still to be processed,
		 * the packet's malformed (or at least all the IP header(s) are
		 * not in the same mblk - and that should never happen.
		 */
		return (B_FALSE);

	default:
		/*
		 * If we get here, we know that all of the IP headers were in
		 * the same mblk, even if the ULP header is in the next mblk.
		 */
		*hdr_length_ptr = length;
		*nexthdrpp = nexthdrp;
		return (B_TRUE);
	}
}

/*
 * Return the length of the IPv6 related headers (including extension headers)
 * Returns a length even if the packet is malformed.
 */
int
ip_hdr_length_v6(mblk_t *mp, ip6_t *ip6h)
{
	uint16_t hdr_len;
	uint8_t	*nexthdrp;

	(void) ip_hdr_length_nexthdr_v6(mp, ip6h, &hdr_len, &nexthdrp);
	return (hdr_len);
}

/*
 * Select an ill for the packet by considering load spreading across
 * a different ill in the group if dst_ill is part of some group.
 */
static ill_t *
ip_newroute_get_dst_ill_v6(ill_t *dst_ill)
{
	ill_t *ill;

	/*
	 * We schedule irrespective of whether the source address is
	 * INADDR_UNSPECIED or not.
	 */
	ill = illgrp_scheduler(dst_ill);
	if (ill == NULL)
		return (NULL);

	/*
	 * For groups with names ip_sioctl_groupname ensures that all
	 * ills are of same type. For groups without names, ifgrp_insert
	 * ensures this.
	 */
	ASSERT(dst_ill->ill_type == ill->ill_type);

	return (ill);
}

/*
 * IPv6 -
 * ip_newroute_v6 is called by ip_rput_data_v6 or ip_wput_v6 whenever we need
 * to send out a packet to a destination address for which we do not have
 * specific routing information.
 *
 * Handle non-multicast packets. If ill is non-NULL the match is done
 * for that ill.
 *
 * When a specific ill is specified (using IPV6_PKTINFO,
 * IPV6_MULTICAST_IF, or IPV6_BOUND_IF) we will only match
 * on routing entries (ftable and ctable) that have a matching
 * ire->ire_ipif->ipif_ill. Thus this can only be used
 * for destinations that are on-link for the specific ill
 * and that can appear on multiple links. Thus it is useful
 * for multicast destinations, link-local destinations, and
 * at some point perhaps for site-local destinations (if the
 * node sits at a site boundary).
 * We create the cache entries in the regular ctable since
 * it can not "confuse" things for other destinations.
 * table.
 *
 * When ill is part of a ill group, we subject the packets
 * to load spreading even if the ill is specified by the
 * means described above. We disable only for IPV6_BOUND_PIF
 * and for the cases where IP6I_ATTACH_IF is set i.e NS/NA/
 * Echo replies to link-local destinations have IP6I_ATTACH_IF
 * set.
 *
 * NOTE : These are the scopes of some of the variables that point at IRE,
 *	  which needs to be followed while making any future modifications
 *	  to avoid memory leaks.
 *
 *	- ire and sire are the entries looked up initially by
 *	  ire_ftable_lookup_v6.
 *	- ipif_ire is used to hold the interface ire associated with
 *	  the new cache ire. But it's scope is limited, so we always REFRELE
 *	  it before branching out to error paths.
 *	- save_ire is initialized before ire_create, so that ire returned
 *	  by ire_create will not over-write the ire. We REFRELE save_ire
 *	  before breaking out of the switch.
 *
 *	Thus on failures, we have to REFRELE only ire and sire, if they
 *	are not NULL.
 *
 *	v6srcp may be used in the future. Currently unused.
 */
/* ARGSUSED */
void
ip_newroute_v6(queue_t *q, mblk_t *mp, const in6_addr_t *v6dstp,
    const in6_addr_t *v6srcp, ill_t *ill, zoneid_t zoneid, ip_stack_t *ipst)
{
	in6_addr_t	v6gw;
	in6_addr_t	dst;
	ire_t		*ire = NULL;
	ipif_t		*src_ipif = NULL;
	ill_t		*dst_ill = NULL;
	ire_t		*sire = NULL;
	ire_t		*save_ire;
	ip6_t		*ip6h;
	int		err = 0;
	mblk_t		*first_mp;
	ipsec_out_t	*io;
	ill_t		*attach_ill = NULL;
	ushort_t	ire_marks = 0;
	int		match_flags;
	boolean_t	ip6i_present;
	ire_t		*first_sire = NULL;
	mblk_t		*copy_mp = NULL;
	mblk_t		*xmit_mp = NULL;
	in6_addr_t	save_dst;
	uint32_t	multirt_flags =
	    MULTIRT_CACHEGW | MULTIRT_USESTAMP | MULTIRT_SETSTAMP;
	boolean_t	multirt_is_resolvable;
	boolean_t	multirt_resolve_next;
	boolean_t	need_rele = B_FALSE;
	boolean_t	do_attach_ill = B_FALSE;
	boolean_t	ip6_asp_table_held = B_FALSE;
	tsol_ire_gw_secattr_t *attrp = NULL;
	tsol_gcgrp_t	*gcgrp = NULL;
	tsol_gcgrp_addr_t ga;

	ASSERT(!IN6_IS_ADDR_MULTICAST(v6dstp));

	first_mp = mp;
	if (mp->b_datap->db_type == M_CTL) {
		mp = mp->b_cont;
		io = (ipsec_out_t *)first_mp->b_rptr;
		ASSERT(io->ipsec_out_type == IPSEC_OUT);
	} else {
		io = NULL;
	}

	/*
	 * If this end point is bound to IPIF_NOFAILOVER, set bnf_ill and
	 * bind_to_nofailover B_TRUE. We can't use conn to determine as it
	 * could be NULL.
	 *
	 * This information can appear either in an ip6i_t or an IPSEC_OUT
	 * message.
	 */
	ip6h = (ip6_t *)mp->b_rptr;
	ip6i_present = (ip6h->ip6_nxt == IPPROTO_RAW);
	if (ip6i_present || (io != NULL && io->ipsec_out_attach_if)) {
		if (!ip6i_present ||
		    ((ip6i_t *)ip6h)->ip6i_flags & IP6I_ATTACH_IF) {
			attach_ill = ip_grab_attach_ill(ill, first_mp,
			    (ip6i_present ? ((ip6i_t *)ip6h)->ip6i_ifindex :
			    io->ipsec_out_ill_index), B_TRUE, ipst);
			/* Failure case frees things for us. */
			if (attach_ill == NULL)
				return;

			/*
			 * Check if we need an ire that will not be
			 * looked up by anybody else i.e. HIDDEN.
			 */
			if (ill_is_probeonly(attach_ill))
				ire_marks = IRE_MARK_HIDDEN;
		}
	}

	if (IN6_IS_ADDR_LOOPBACK(v6dstp)) {
		ip1dbg(("ip_newroute_v6: dst with loopback addr\n"));
		goto icmp_err_ret;
	} else if ((v6srcp != NULL) && IN6_IS_ADDR_LOOPBACK(v6srcp)) {
		ip1dbg(("ip_newroute_v6: src with loopback addr\n"));
		goto icmp_err_ret;
	}

	/*
	 * If this IRE is created for forwarding or it is not for
	 * TCP traffic, mark it as temporary.
	 *
	 * Is it sufficient just to check the next header??
	 */
	if (mp->b_prev != NULL || !IP_FLOW_CONTROLLED_ULP(ip6h->ip6_nxt))
		ire_marks |= IRE_MARK_TEMPORARY;

	/*
	 * Get what we can from ire_ftable_lookup_v6 which will follow an IRE
	 * chain until it gets the most specific information available.
	 * For example, we know that there is no IRE_CACHE for this dest,
	 * but there may be an IRE_OFFSUBNET which specifies a gateway.
	 * ire_ftable_lookup_v6 will look up the gateway, etc.
	 */

	if (ill == NULL) {
		match_flags = MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
		    MATCH_IRE_PARENT | MATCH_IRE_RJ_BHOLE | MATCH_IRE_SECATTR;
		ire = ire_ftable_lookup_v6(v6dstp, 0, 0, 0,
		    NULL, &sire, zoneid, 0, MBLK_GETLABEL(mp),
		    match_flags, ipst);
		/*
		 * ire_add_then_send -> ip_newroute_v6 in the CGTP case passes
		 * in a NULL ill, but the packet could be a neighbor
		 * solicitation/advertisment and could have a valid attach_ill.
		 */
		if (attach_ill != NULL)
			ill_refrele(attach_ill);
	} else {
		if (attach_ill != NULL) {
			/*
			 * attach_ill is set only for communicating with
			 * on-link hosts. So, don't look for DEFAULT.
			 * ip_wput_v6 passes the right ill in this case and
			 * hence we can assert.
			 */
			ASSERT(ill == attach_ill);
			ill_refrele(attach_ill);
			do_attach_ill = B_TRUE;
			match_flags = MATCH_IRE_RJ_BHOLE | MATCH_IRE_ILL;
		} else {
			match_flags = MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
			    MATCH_IRE_RJ_BHOLE | MATCH_IRE_ILL_GROUP;
		}
		match_flags |= MATCH_IRE_PARENT | MATCH_IRE_SECATTR;
		ire = ire_ftable_lookup_v6(v6dstp, NULL, NULL, 0, ill->ill_ipif,
		    &sire, zoneid, 0, MBLK_GETLABEL(mp), match_flags, ipst);
	}

	ip3dbg(("ip_newroute_v6: ire_ftable_lookup_v6() "
	    "returned ire %p, sire %p\n", (void *)ire, (void *)sire));

	/*
	 * We enter a loop that will be run only once in most cases.
	 * The loop is re-entered in the case where the destination
	 * can be reached through multiple RTF_MULTIRT-flagged routes.
	 * The intention is to compute multiple routes to a single
	 * destination in a single ip_newroute_v6 call.
	 * The information is contained in sire->ire_flags.
	 */
	do {
		multirt_resolve_next = B_FALSE;

		if (dst_ill != NULL) {
			ill_refrele(dst_ill);
			dst_ill = NULL;
		}
		if (src_ipif != NULL) {
			ipif_refrele(src_ipif);
			src_ipif = NULL;
		}
		if ((sire != NULL) && sire->ire_flags & RTF_MULTIRT) {
			ip3dbg(("ip_newroute_v6: starting new resolution "
			    "with first_mp %p, tag %d\n",
			    (void *)first_mp, MULTIRT_DEBUG_TAGGED(first_mp)));

			/*
			 * We check if there are trailing unresolved routes for
			 * the destination contained in sire.
			 */
			multirt_is_resolvable = ire_multirt_lookup_v6(&ire,
			    &sire, multirt_flags, MBLK_GETLABEL(mp), ipst);

			ip3dbg(("ip_newroute_v6: multirt_is_resolvable %d, "
			    "ire %p, sire %p\n",
			    multirt_is_resolvable, (void *)ire, (void *)sire));

			if (!multirt_is_resolvable) {
				/*
				 * No more multirt routes to resolve; give up
				 * (all routes resolved or no more resolvable
				 * routes).
				 */
				if (ire != NULL) {
					ire_refrele(ire);
					ire = NULL;
				}
			} else {
				ASSERT(sire != NULL);
				ASSERT(ire != NULL);
				/*
				 * We simply use first_sire as a flag that
				 * indicates if a resolvable multirt route has
				 * already been found during the preceding
				 * loops. If it is not the case, we may have
				 * to send an ICMP error to report that the
				 * destination is unreachable. We do not
				 * IRE_REFHOLD first_sire.
				 */
				if (first_sire == NULL) {
					first_sire = sire;
				}
			}
		}
		if ((ire == NULL) || (ire == sire)) {
			/*
			 * either ire == NULL (the destination cannot be
			 * resolved) or ire == sire (the gateway cannot be
			 * resolved). At this point, there are no more routes
			 * to resolve for the destination, thus we exit.
			 */
			if (ip_debug > 3) {
				/* ip2dbg */
				pr_addr_dbg("ip_newroute_v6: "
				    "can't resolve %s\n", AF_INET6, v6dstp);
			}
			ip3dbg(("ip_newroute_v6: "
			    "ire %p, sire %p, first_sire %p\n",
			    (void *)ire, (void *)sire, (void *)first_sire));

			if (sire != NULL) {
				ire_refrele(sire);
				sire = NULL;
			}

			if (first_sire != NULL) {
				/*
				 * At least one multirt route has been found
				 * in the same ip_newroute() call; there is no
				 * need to report an ICMP error.
				 * first_sire was not IRE_REFHOLDed.
				 */
				MULTIRT_DEBUG_UNTAG(first_mp);
				freemsg(first_mp);
				return;
			}
			ip_rts_change_v6(RTM_MISS, v6dstp, 0, 0, 0, 0, 0, 0,
			    RTA_DST, ipst);
			goto icmp_err_ret;
		}

		ASSERT(ire->ire_ipversion == IPV6_VERSION);

		/*
		 * Verify that the returned IRE does not have either the
		 * RTF_REJECT or RTF_BLACKHOLE flags set and that the IRE is
		 * either an IRE_CACHE, IRE_IF_NORESOLVER or IRE_IF_RESOLVER.
		 */
		if ((ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE)) ||
		    (ire->ire_type & (IRE_CACHE | IRE_INTERFACE)) == 0)
			goto icmp_err_ret;

		/*
		 * Increment the ire_ob_pkt_count field for ire if it is an
		 * INTERFACE (IF_RESOLVER or IF_NORESOLVER) IRE type, and
		 * increment the same for the parent IRE, sire, if it is some
		 * sort of prefix IRE (which includes DEFAULT, PREFIX, and HOST)
		 */
		if ((ire->ire_type & IRE_INTERFACE) != 0) {
			UPDATE_OB_PKT_COUNT(ire);
			ire->ire_last_used_time = lbolt;
		}

		if (sire != NULL) {
			mutex_enter(&sire->ire_lock);
			v6gw = sire->ire_gateway_addr_v6;
			mutex_exit(&sire->ire_lock);
			ASSERT((sire->ire_type & (IRE_CACHETABLE |
			    IRE_INTERFACE)) == 0);
			UPDATE_OB_PKT_COUNT(sire);
			sire->ire_last_used_time = lbolt;
		} else {
			v6gw = ipv6_all_zeros;
		}

		/*
		 * We have a route to reach the destination.
		 *
		 * 1) If the interface is part of ill group, try to get a new
		 *    ill taking load spreading into account.
		 *
		 * 2) After selecting the ill, get a source address that might
		 *    create good inbound load spreading and that matches the
		 *    right scope. ipif_select_source_v6 does this for us.
		 *
		 * If the application specified the ill (ifindex), we still
		 * load spread. Only if the packets needs to go out specifically
		 * on a given ill e.g. bind to IPIF_NOFAILOVER address,
		 * IPV6_BOUND_PIF we don't try to use a different ill for load
		 * spreading.
		 */
		if (!do_attach_ill) {
			/*
			 * If the interface belongs to an interface group,
			 * make sure the next possible interface in the group
			 * is used.  This encourages load spreading among
			 * peers in an interface group. However, in the case
			 * of multirouting, load spreading is not used, as we
			 * actually want to replicate outgoing packets through
			 * particular interfaces.
			 *
			 * Note: While we pick a dst_ill we are really only
			 * interested in the ill for load spreading.
			 * The source ipif is determined by source address
			 * selection below.
			 */
			if ((sire != NULL) && (sire->ire_flags & RTF_MULTIRT)) {
				dst_ill = ire->ire_ipif->ipif_ill;
				/* For uniformity do a refhold */
				ill_refhold(dst_ill);
			} else {
				/*
				 * If we are here trying to create an IRE_CACHE
				 * for an offlink destination and have the
				 * IRE_CACHE for the next hop and the latter is
				 * using virtual IP source address selection i.e
				 * it's ire->ire_ipif is pointing to a virtual
				 * network interface (vni) then
				 * ip_newroute_get_dst_ll() will return the vni
				 * interface as the dst_ill. Since the vni is
				 * virtual i.e not associated with any physical
				 * interface, it cannot be the dst_ill, hence
				 * in such a case call ip_newroute_get_dst_ll()
				 * with the stq_ill instead of the ire_ipif ILL.
				 * The function returns a refheld ill.
				 */
				if ((ire->ire_type == IRE_CACHE) &&
				    IS_VNI(ire->ire_ipif->ipif_ill))
					dst_ill = ip_newroute_get_dst_ill_v6(
					    ire->ire_stq->q_ptr);
				else
					dst_ill = ip_newroute_get_dst_ill_v6(
					    ire->ire_ipif->ipif_ill);
			}
			if (dst_ill == NULL) {
				if (ip_debug > 2) {
					pr_addr_dbg("ip_newroute_v6 : no dst "
					    "ill for dst %s\n",
					    AF_INET6, v6dstp);
				}
				goto icmp_err_ret;
			} else if (dst_ill->ill_group == NULL && ill != NULL &&
			    dst_ill != ill) {
				/*
				 * If "ill" is not part of any group, we should
				 * have found a route matching "ill" as we
				 * called ire_ftable_lookup_v6 with
				 * MATCH_IRE_ILL_GROUP.
				 * Rather than asserting when there is a
				 * mismatch, we just drop the packet.
				 */
				ip0dbg(("ip_newroute_v6: BOUND_IF failed : "
				    "dst_ill %s ill %s\n",
				    dst_ill->ill_name,
				    ill->ill_name));
				goto icmp_err_ret;
			}
		} else {
			dst_ill = ire->ire_ipif->ipif_ill;
			/* For uniformity do refhold */
			ill_refhold(dst_ill);
			/*
			 * We should have found a route matching ill as we
			 * called ire_ftable_lookup_v6 with MATCH_IRE_ILL.
			 * Rather than asserting, while there is a mismatch,
			 * we just drop the packet.
			 */
			if (dst_ill != ill) {
				ip0dbg(("ip_newroute_v6: Packet dropped as "
				    "IP6I_ATTACH_IF ill is %s, "
				    "ire->ire_ipif->ipif_ill is %s\n",
				    ill->ill_name,
				    dst_ill->ill_name));
				goto icmp_err_ret;
			}
		}
		/*
		 * Pick a source address which matches the scope of the
		 * destination address.
		 * For RTF_SETSRC routes, the source address is imposed by the
		 * parent ire (sire).
		 */
		ASSERT(src_ipif == NULL);
		if (ire->ire_type == IRE_IF_RESOLVER &&
		    !IN6_IS_ADDR_UNSPECIFIED(&v6gw) &&
		    ip6_asp_can_lookup(ipst)) {
			/*
			 * The ire cache entry we're adding is for the
			 * gateway itself.  The source address in this case
			 * is relative to the gateway's address.
			 */
			ip6_asp_table_held = B_TRUE;
			src_ipif = ipif_select_source_v6(dst_ill, &v6gw,
			    RESTRICT_TO_GROUP, IPV6_PREFER_SRC_DEFAULT, zoneid);
			if (src_ipif != NULL)
				ire_marks |= IRE_MARK_USESRC_CHECK;
		} else {
			if ((sire != NULL) && (sire->ire_flags & RTF_SETSRC)) {
				/*
				 * Check that the ipif matching the requested
				 * source address still exists.
				 */
				src_ipif = ipif_lookup_addr_v6(
				    &sire->ire_src_addr_v6, NULL, zoneid,
				    NULL, NULL, NULL, NULL, ipst);
			}
			if (src_ipif == NULL && ip6_asp_can_lookup(ipst)) {
				uint_t restrict_ill = RESTRICT_TO_NONE;

				if (ip6i_present && ((ip6i_t *)ip6h)->ip6i_flags
				    & IP6I_ATTACH_IF)
					restrict_ill = RESTRICT_TO_ILL;
				ip6_asp_table_held = B_TRUE;
				src_ipif = ipif_select_source_v6(dst_ill,
				    v6dstp, restrict_ill,
				    IPV6_PREFER_SRC_DEFAULT, zoneid);
				if (src_ipif != NULL)
					ire_marks |= IRE_MARK_USESRC_CHECK;
			}
		}

		if (src_ipif == NULL) {
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("ip_newroute_v6: no src for "
				    "dst %s\n, ", AF_INET6, v6dstp);
				printf("ip_newroute_v6: interface name %s\n",
				    dst_ill->ill_name);
			}
			goto icmp_err_ret;
		}

		if (ip_debug > 3) {
			/* ip2dbg */
			pr_addr_dbg("ip_newroute_v6: first hop %s\n",
			    AF_INET6, &v6gw);
		}
		ip2dbg(("\tire type %s (%d)\n",
		    ip_nv_lookup(ire_nv_tbl, ire->ire_type), ire->ire_type));

		/*
		 * At this point in ip_newroute_v6(), ire is either the
		 * IRE_CACHE of the next-hop gateway for an off-subnet
		 * destination or an IRE_INTERFACE type that should be used
		 * to resolve an on-subnet destination or an on-subnet
		 * next-hop gateway.
		 *
		 * In the IRE_CACHE case, we have the following :
		 *
		 * 1) src_ipif - used for getting a source address.
		 *
		 * 2) dst_ill - from which we derive ire_stq/ire_rfq. This
		 *    means packets using this IRE_CACHE will go out on dst_ill.
		 *
		 * 3) The IRE sire will point to the prefix that is the longest
		 *    matching route for the destination. These prefix types
		 *    include IRE_DEFAULT, IRE_PREFIX, IRE_HOST.
		 *
		 *    The newly created IRE_CACHE entry for the off-subnet
		 *    destination is tied to both the prefix route and the
		 *    interface route used to resolve the next-hop gateway
		 *    via the ire_phandle and ire_ihandle fields, respectively.
		 *
		 * In the IRE_INTERFACE case, we have the following :
		 *
		 * 1) src_ipif - used for getting a source address.
		 *
		 * 2) dst_ill - from which we derive ire_stq/ire_rfq. This
		 *    means packets using the IRE_CACHE that we will build
		 *    here will go out on dst_ill.
		 *
		 * 3) sire may or may not be NULL. But, the IRE_CACHE that is
		 *    to be created will only be tied to the IRE_INTERFACE that
		 *    was derived from the ire_ihandle field.
		 *
		 *    If sire is non-NULL, it means the destination is off-link
		 *    and we will first create the IRE_CACHE for the gateway.
		 *    Next time through ip_newroute_v6, we will create the
		 *    IRE_CACHE for the final destination as described above.
		 */
		save_ire = ire;
		switch (ire->ire_type) {
		case IRE_CACHE: {
			ire_t	*ipif_ire;

			ASSERT(sire != NULL);
			if (IN6_IS_ADDR_UNSPECIFIED(&v6gw)) {
				mutex_enter(&ire->ire_lock);
				v6gw = ire->ire_gateway_addr_v6;
				mutex_exit(&ire->ire_lock);
			}
			/*
			 * We need 3 ire's to create a new cache ire for an
			 * off-link destination from the cache ire of the
			 * gateway.
			 *
			 *	1. The prefix ire 'sire'
			 *	2. The cache ire of the gateway 'ire'
			 *	3. The interface ire 'ipif_ire'
			 *
			 * We have (1) and (2). We lookup (3) below.
			 *
			 * If there is no interface route to the gateway,
			 * it is a race condition, where we found the cache
			 * but the inteface route has been deleted.
			 */
			ipif_ire = ire_ihandle_lookup_offlink_v6(ire, sire);
			if (ipif_ire == NULL) {
				ip1dbg(("ip_newroute_v6:"
				    "ire_ihandle_lookup_offlink_v6 failed\n"));
				goto icmp_err_ret;
			}
			/*
			 * Assume DL_UNITDATA_REQ is same for all physical
			 * interfaces in the ifgrp.  If it isn't, this code will
			 * have to be seriously rewhacked to allow the
			 * fastpath probing (such that I cache the link
			 * header in the IRE_CACHE) to work over ifgrps.
			 * We have what we need to build an IRE_CACHE.
			 */
			/*
			 * Note: the new ire inherits RTF_SETSRC
			 * and RTF_MULTIRT to propagate these flags from prefix
			 * to cache.
			 */

			/*
			 * Check cached gateway IRE for any security
			 * attributes; if found, associate the gateway
			 * credentials group to the destination IRE.
			 */
			if ((attrp = save_ire->ire_gw_secattr) != NULL) {
				mutex_enter(&attrp->igsa_lock);
				if ((gcgrp = attrp->igsa_gcgrp) != NULL)
					GCGRP_REFHOLD(gcgrp);
				mutex_exit(&attrp->igsa_lock);
			}

			ire = ire_create_v6(
			    v6dstp,			/* dest address */
			    &ipv6_all_ones,		/* mask */
			    &src_ipif->ipif_v6src_addr, /* source address */
			    &v6gw,			/* gateway address */
			    &save_ire->ire_max_frag,
			    NULL,			/* src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,
			    src_ipif,
			    &sire->ire_mask_v6,		/* Parent mask */
			    sire->ire_phandle,		/* Parent handle */
			    ipif_ire->ire_ihandle,	/* Interface handle */
			    sire->ire_flags &		/* flags if any */
			    (RTF_SETSRC | RTF_MULTIRT),
			    &(sire->ire_uinfo),
			    NULL,
			    gcgrp,
			    ipst);

			if (ire == NULL) {
				if (gcgrp != NULL) {
					GCGRP_REFRELE(gcgrp);
					gcgrp = NULL;
				}
				ire_refrele(save_ire);
				ire_refrele(ipif_ire);
				break;
			}

			/* reference now held by IRE */
			gcgrp = NULL;

			ire->ire_marks |= ire_marks;

			/*
			 * Prevent sire and ipif_ire from getting deleted. The
			 * newly created ire is tied to both of them via the
			 * phandle and ihandle respectively.
			 */
			IRB_REFHOLD(sire->ire_bucket);
			/* Has it been removed already ? */
			if (sire->ire_marks & IRE_MARK_CONDEMNED) {
				IRB_REFRELE(sire->ire_bucket);
				ire_refrele(ipif_ire);
				ire_refrele(save_ire);
				break;
			}

			IRB_REFHOLD(ipif_ire->ire_bucket);
			/* Has it been removed already ? */
			if (ipif_ire->ire_marks & IRE_MARK_CONDEMNED) {
				IRB_REFRELE(ipif_ire->ire_bucket);
				IRB_REFRELE(sire->ire_bucket);
				ire_refrele(ipif_ire);
				ire_refrele(save_ire);
				break;
			}

			xmit_mp = first_mp;
			if (ire->ire_flags & RTF_MULTIRT) {
				copy_mp = copymsg(first_mp);
				if (copy_mp != NULL) {
					xmit_mp = copy_mp;
					MULTIRT_DEBUG_TAG(first_mp);
				}
			}
			ire_add_then_send(q, ire, xmit_mp);
			if (ip6_asp_table_held) {
				ip6_asp_table_refrele(ipst);
				ip6_asp_table_held = B_FALSE;
			}
			ire_refrele(save_ire);

			/* Assert that sire is not deleted yet. */
			ASSERT(sire->ire_ptpn != NULL);
			IRB_REFRELE(sire->ire_bucket);

			/* Assert that ipif_ire is not deleted yet. */
			ASSERT(ipif_ire->ire_ptpn != NULL);
			IRB_REFRELE(ipif_ire->ire_bucket);
			ire_refrele(ipif_ire);

			if (copy_mp != NULL) {
				/*
				 * Search for the next unresolved
				 * multirt route.
				 */
				copy_mp = NULL;
				ipif_ire = NULL;
				ire = NULL;
				/* re-enter the loop */
				multirt_resolve_next = B_TRUE;
				continue;
			}
			ire_refrele(sire);
			ill_refrele(dst_ill);
			ipif_refrele(src_ipif);
			return;
		}
		case IRE_IF_NORESOLVER:
			/*
			 * We have what we need to build an IRE_CACHE.
			 *
			 * handle the Gated case, where we create
			 * a NORESOLVER route for loopback.
			 */
			if (dst_ill->ill_net_type != IRE_IF_NORESOLVER)
				break;
			/*
			 * TSol note: We are creating the ire cache for the
			 * destination 'dst'. If 'dst' is offlink, going
			 * through the first hop 'gw', the security attributes
			 * of 'dst' must be set to point to the gateway
			 * credentials of gateway 'gw'. If 'dst' is onlink, it
			 * is possible that 'dst' is a potential gateway that is
			 * referenced by some route that has some security
			 * attributes. Thus in the former case, we need to do a
			 * gcgrp_lookup of 'gw' while in the latter case we
			 * need to do gcgrp_lookup of 'dst' itself.
			 */
			ga.ga_af = AF_INET6;
			if (!IN6_IS_ADDR_UNSPECIFIED(&v6gw))
				ga.ga_addr = v6gw;
			else
				ga.ga_addr = *v6dstp;
			gcgrp = gcgrp_lookup(&ga, B_FALSE);

			/*
			 * Note: the new ire inherits sire flags RTF_SETSRC
			 * and RTF_MULTIRT to propagate those rules from prefix
			 * to cache.
			 */
			ire = ire_create_v6(
			    v6dstp,			/* dest address */
			    &ipv6_all_ones,		/* mask */
			    &src_ipif->ipif_v6src_addr, /* source address */
			    &v6gw,			/* gateway address */
			    &save_ire->ire_max_frag,
			    NULL,			/* no src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,
			    src_ipif,
			    &save_ire->ire_mask_v6,	/* Parent mask */
			    (sire != NULL) ?		/* Parent handle */
			    sire->ire_phandle : 0,
			    save_ire->ire_ihandle,	/* Interface handle */
			    (sire != NULL) ?		/* flags if any */
			    sire->ire_flags &
			    (RTF_SETSRC | RTF_MULTIRT) : 0,
			    &(save_ire->ire_uinfo),
			    NULL,
			    gcgrp,
			    ipst);

			if (ire == NULL) {
				if (gcgrp != NULL) {
					GCGRP_REFRELE(gcgrp);
					gcgrp = NULL;
				}
				ire_refrele(save_ire);
				break;
			}

			/* reference now held by IRE */
			gcgrp = NULL;

			ire->ire_marks |= ire_marks;

			if (!IN6_IS_ADDR_UNSPECIFIED(&v6gw))
				dst = v6gw;
			else
				dst = *v6dstp;
			err = ndp_noresolver(dst_ill, &dst);
			if (err != 0) {
				ire_refrele(save_ire);
				break;
			}

			/* Prevent save_ire from getting deleted */
			IRB_REFHOLD(save_ire->ire_bucket);
			/* Has it been removed already ? */
			if (save_ire->ire_marks & IRE_MARK_CONDEMNED) {
				IRB_REFRELE(save_ire->ire_bucket);
				ire_refrele(save_ire);
				break;
			}

			xmit_mp = first_mp;
			/*
			 * In case of MULTIRT, a copy of the current packet
			 * to send is made to further re-enter the
			 * loop and attempt another route resolution
			 */
			if ((sire != NULL) && sire->ire_flags & RTF_MULTIRT) {
				copy_mp = copymsg(first_mp);
				if (copy_mp != NULL) {
					xmit_mp = copy_mp;
					MULTIRT_DEBUG_TAG(first_mp);
				}
			}
			ire_add_then_send(q, ire, xmit_mp);
			if (ip6_asp_table_held) {
				ip6_asp_table_refrele(ipst);
				ip6_asp_table_held = B_FALSE;
			}

			/* Assert that it is not deleted yet. */
			ASSERT(save_ire->ire_ptpn != NULL);
			IRB_REFRELE(save_ire->ire_bucket);
			ire_refrele(save_ire);

			if (copy_mp != NULL) {
				/*
				 * If we found a (no)resolver, we ignore any
				 * trailing top priority IRE_CACHE in
				 * further loops. This ensures that we do not
				 * omit any (no)resolver despite the priority
				 * in this call.
				 * IRE_CACHE, if any, will be processed
				 * by another thread entering ip_newroute(),
				 * (on resolver response, for example).
				 * We use this to force multiple parallel
				 * resolution as soon as a packet needs to be
				 * sent. The result is, after one packet
				 * emission all reachable routes are generally
				 * resolved.
				 * Otherwise, complete resolution of MULTIRT
				 * routes would require several emissions as
				 * side effect.
				 */
				multirt_flags &= ~MULTIRT_CACHEGW;

				/*
				 * Search for the next unresolved multirt
				 * route.
				 */
				copy_mp = NULL;
				save_ire = NULL;
				ire = NULL;
				/* re-enter the loop */
				multirt_resolve_next = B_TRUE;
				continue;
			}

			/* Don't need sire anymore */
			if (sire != NULL)
				ire_refrele(sire);
			ill_refrele(dst_ill);
			ipif_refrele(src_ipif);
			return;

		case IRE_IF_RESOLVER:
			/*
			 * We can't build an IRE_CACHE yet, but at least we
			 * found a resolver that can help.
			 */
			dst = *v6dstp;

			/*
			 * To be at this point in the code with a non-zero gw
			 * means that dst is reachable through a gateway that
			 * we have never resolved.  By changing dst to the gw
			 * addr we resolve the gateway first.  When
			 * ire_add_then_send() tries to put the IP dg to dst,
			 * it will reenter ip_newroute() at which time we will
			 * find the IRE_CACHE for the gw and create another
			 * IRE_CACHE above (for dst itself).
			 */
			if (!IN6_IS_ADDR_UNSPECIFIED(&v6gw)) {
				save_dst = dst;
				dst = v6gw;
				v6gw = ipv6_all_zeros;
			}
			if (dst_ill->ill_flags & ILLF_XRESOLV) {
				/*
				 * Ask the external resolver to do its thing.
				 * Make an mblk chain in the following form:
				 * ARQ_REQ_MBLK-->IRE_MBLK-->packet
				 */
				mblk_t		*ire_mp;
				mblk_t		*areq_mp;
				areq_t		*areq;
				in6_addr_t	*addrp;

				ip1dbg(("ip_newroute_v6:ILLF_XRESOLV\n"));
				if (ip6_asp_table_held) {
					ip6_asp_table_refrele(ipst);
					ip6_asp_table_held = B_FALSE;
				}
				ire = ire_create_mp_v6(
				    &dst,		/* dest address */
				    &ipv6_all_ones,	/* mask */
				    &src_ipif->ipif_v6src_addr,
				    /* source address */
				    &v6gw,		/* gateway address */
				    NULL,		/* no src nce */
				    dst_ill->ill_rq,	/* recv-from queue */
				    dst_ill->ill_wq, 	/* send-to queue */
				    IRE_CACHE,
				    src_ipif,
				    &save_ire->ire_mask_v6, /* Parent mask */
				    0,
				    save_ire->ire_ihandle,
				    /* Interface handle */
				    0,		/* flags if any */
				    &(save_ire->ire_uinfo),
				    NULL,
				    NULL,
				    ipst);

				ire_refrele(save_ire);
				if (ire == NULL) {
					ip1dbg(("ip_newroute_v6:"
					    "ire is NULL\n"));
					break;
				}

				if ((sire != NULL) &&
				    (sire->ire_flags & RTF_MULTIRT)) {
					/*
					 * processing a copy of the packet to
					 * send for further resolution loops
					 */
					copy_mp = copymsg(first_mp);
					if (copy_mp != NULL)
						MULTIRT_DEBUG_TAG(copy_mp);
				}
				ire->ire_marks |= ire_marks;
				ire_mp = ire->ire_mp;
				/*
				 * Now create or find an nce for this interface.
				 * The hw addr will need to to be set from
				 * the reply to the AR_ENTRY_QUERY that
				 * we're about to send. This will be done in
				 * ire_add_v6().
				 */
				err = ndp_resolver(dst_ill, &dst, mp, zoneid);
				switch (err) {
				case 0:
					/*
					 * New cache entry created.
					 * Break, then ask the external
					 * resolver.
					 */
					break;
				case EINPROGRESS:
					/*
					 * Resolution in progress;
					 * packet has been queued by
					 * ndp_resolver().
					 */
					ire_delete(ire);
					ire = NULL;
					/*
					 * Check if another multirt
					 * route must be resolved.
					 */
					if (copy_mp != NULL) {
						/*
						 * If we found a resolver, we
						 * ignore any trailing top
						 * priority IRE_CACHE in
						 * further loops. The reason is
						 * the same as for noresolver.
						 */
						multirt_flags &=
						    ~MULTIRT_CACHEGW;
						/*
						 * Search for the next
						 * unresolved multirt route.
						 */
						first_mp = copy_mp;
						copy_mp = NULL;
						mp = first_mp;
						if (mp->b_datap->db_type ==
						    M_CTL) {
							mp = mp->b_cont;
						}
						ASSERT(sire != NULL);
						dst = save_dst;
						/*
						 * re-enter the loop
						 */
						multirt_resolve_next =
						    B_TRUE;
						continue;
					}

					if (sire != NULL)
						ire_refrele(sire);
					ill_refrele(dst_ill);
					ipif_refrele(src_ipif);
					return;
				default:
					/*
					 * Transient error; packet will be
					 * freed.
					 */
					ire_delete(ire);
					ire = NULL;
					break;
				}
				if (err != 0)
					break;
				/*
				 * Now set up the AR_ENTRY_QUERY and send it.
				 */
				areq_mp = ill_arp_alloc(dst_ill,
				    (uchar_t *)&ipv6_areq_template,
				    (caddr_t)&dst);
				if (areq_mp == NULL) {
					ip1dbg(("ip_newroute_v6:"
					    "areq_mp is NULL\n"));
					freemsg(ire_mp);
					break;
				}
				areq = (areq_t *)areq_mp->b_rptr;
				addrp = (in6_addr_t *)((char *)areq +
				    areq->areq_target_addr_offset);
				*addrp = dst;
				addrp = (in6_addr_t *)((char *)areq +
				    areq->areq_sender_addr_offset);
				*addrp = src_ipif->ipif_v6src_addr;
				/*
				 * link the chain, then send up to the resolver.
				 */
				linkb(areq_mp, ire_mp);
				linkb(areq_mp, mp);
				ip1dbg(("ip_newroute_v6:"
				    "putnext to resolver\n"));
				putnext(dst_ill->ill_rq, areq_mp);
				/*
				 * Check if another multirt route
				 * must be resolved.
				 */
				ire = NULL;
				if (copy_mp != NULL) {
					/*
					 * If we find a resolver, we ignore any
					 * trailing top priority IRE_CACHE in
					 * further loops. The reason is the
					 * same as for noresolver.
					 */
					multirt_flags &= ~MULTIRT_CACHEGW;
					/*
					 * Search for the next unresolved
					 * multirt route.
					 */
					first_mp = copy_mp;
					copy_mp = NULL;
					mp = first_mp;
					if (mp->b_datap->db_type == M_CTL) {
						mp = mp->b_cont;
					}
					ASSERT(sire != NULL);
					dst = save_dst;
					/*
					 * re-enter the loop
					 */
					multirt_resolve_next = B_TRUE;
					continue;
				}

				if (sire != NULL)
					ire_refrele(sire);
				ill_refrele(dst_ill);
				ipif_refrele(src_ipif);
				return;
			}
			/*
			 * Non-external resolver case.
			 *
			 * TSol note: Please see the note above the
			 * IRE_IF_NORESOLVER case.
			 */
			ga.ga_af = AF_INET6;
			ga.ga_addr = dst;
			gcgrp = gcgrp_lookup(&ga, B_FALSE);

			ire = ire_create_v6(
			    &dst,			/* dest address */
			    &ipv6_all_ones,		/* mask */
			    &src_ipif->ipif_v6src_addr, /* source address */
			    &v6gw,			/* gateway address */
			    &save_ire->ire_max_frag,
			    NULL,			/* no src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,
			    src_ipif,
			    &save_ire->ire_mask_v6,	/* Parent mask */
			    0,
			    save_ire->ire_ihandle,	/* Interface handle */
			    0,				/* flags if any */
			    &(save_ire->ire_uinfo),
			    NULL,
			    gcgrp,
			    ipst);

			if (ire == NULL) {
				if (gcgrp != NULL) {
					GCGRP_REFRELE(gcgrp);
					gcgrp = NULL;
				}
				ire_refrele(save_ire);
				break;
			}

			/* reference now held by IRE */
			gcgrp = NULL;

			if ((sire != NULL) &&
			    (sire->ire_flags & RTF_MULTIRT)) {
				copy_mp = copymsg(first_mp);
				if (copy_mp != NULL)
					MULTIRT_DEBUG_TAG(copy_mp);
			}

			ire->ire_marks |= ire_marks;
			err = ndp_resolver(dst_ill, &dst, first_mp, zoneid);
			switch (err) {
			case 0:
				/* Prevent save_ire from getting deleted */
				IRB_REFHOLD(save_ire->ire_bucket);
				/* Has it been removed already ? */
				if (save_ire->ire_marks & IRE_MARK_CONDEMNED) {
					IRB_REFRELE(save_ire->ire_bucket);
					ire_refrele(save_ire);
					break;
				}

				/*
				 * We have a resolved cache entry,
				 * add in the IRE.
				 */
				ire_add_then_send(q, ire, first_mp);
				if (ip6_asp_table_held) {
					ip6_asp_table_refrele(ipst);
					ip6_asp_table_held = B_FALSE;
				}

				/* Assert that it is not deleted yet. */
				ASSERT(save_ire->ire_ptpn != NULL);
				IRB_REFRELE(save_ire->ire_bucket);
				ire_refrele(save_ire);
				/*
				 * Check if another multirt route
				 * must be resolved.
				 */
				ire = NULL;
				if (copy_mp != NULL) {
					/*
					 * If we find a resolver, we ignore any
					 * trailing top priority IRE_CACHE in
					 * further loops. The reason is the
					 * same as for noresolver.
					 */
					multirt_flags &= ~MULTIRT_CACHEGW;
					/*
					 * Search for the next unresolved
					 * multirt route.
					 */
					first_mp = copy_mp;
					copy_mp = NULL;
					mp = first_mp;
					if (mp->b_datap->db_type == M_CTL) {
						mp = mp->b_cont;
					}
					ASSERT(sire != NULL);
					dst = save_dst;
					/*
					 * re-enter the loop
					 */
					multirt_resolve_next = B_TRUE;
					continue;
				}

				if (sire != NULL)
					ire_refrele(sire);
				ill_refrele(dst_ill);
				ipif_refrele(src_ipif);
				return;

			case EINPROGRESS:
				/*
				 * mp was consumed - presumably queued.
				 * No need for ire, presumably resolution is
				 * in progress, and ire will be added when the
				 * address is resolved.
				 */
				if (ip6_asp_table_held) {
					ip6_asp_table_refrele(ipst);
					ip6_asp_table_held = B_FALSE;
				}
				ASSERT(ire->ire_nce == NULL);
				ire_delete(ire);
				ire_refrele(save_ire);
				/*
				 * Check if another multirt route
				 * must be resolved.
				 */
				ire = NULL;
				if (copy_mp != NULL) {
					/*
					 * If we find a resolver, we ignore any
					 * trailing top priority IRE_CACHE in
					 * further loops. The reason is the
					 * same as for noresolver.
					 */
					multirt_flags &= ~MULTIRT_CACHEGW;
					/*
					 * Search for the next unresolved
					 * multirt route.
					 */
					first_mp = copy_mp;
					copy_mp = NULL;
					mp = first_mp;
					if (mp->b_datap->db_type == M_CTL) {
						mp = mp->b_cont;
					}
					ASSERT(sire != NULL);
					dst = save_dst;
					/*
					 * re-enter the loop
					 */
					multirt_resolve_next = B_TRUE;
					continue;
				}
				if (sire != NULL)
					ire_refrele(sire);
				ill_refrele(dst_ill);
				ipif_refrele(src_ipif);
				return;
			default:
				/* Some transient error */
				ASSERT(ire->ire_nce == NULL);
				ire_refrele(save_ire);
				break;
			}
			break;
		default:
			break;
		}
		if (ip6_asp_table_held) {
			ip6_asp_table_refrele(ipst);
			ip6_asp_table_held = B_FALSE;
		}
	} while (multirt_resolve_next);

err_ret:
	ip1dbg(("ip_newroute_v6: dropped\n"));
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	if (dst_ill != NULL) {
		need_rele = B_TRUE;
		ill = dst_ill;
	}
	if (ill != NULL) {
		if (mp->b_prev != NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		} else {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		}

		if (need_rele)
			ill_refrele(ill);
	} else {
		if (mp->b_prev != NULL) {
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsInDiscards);
		} else {
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutDiscards);
		}
	}
	/* Did this packet originate externally? */
	if (mp->b_prev) {
		mp->b_next = NULL;
		mp->b_prev = NULL;
	}
	if (copy_mp != NULL) {
		MULTIRT_DEBUG_UNTAG(copy_mp);
		freemsg(copy_mp);
	}
	MULTIRT_DEBUG_UNTAG(first_mp);
	freemsg(first_mp);
	if (ire != NULL)
		ire_refrele(ire);
	if (sire != NULL)
		ire_refrele(sire);
	return;

icmp_err_ret:
	if (ip6_asp_table_held)
		ip6_asp_table_refrele(ipst);
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	if (dst_ill != NULL) {
		need_rele = B_TRUE;
		ill = dst_ill;
	}
	ip1dbg(("ip_newroute_v6: no route\n"));
	if (sire != NULL)
		ire_refrele(sire);
	/*
	 * We need to set sire to NULL to avoid double freeing if we
	 * ever goto err_ret from below.
	 */
	sire = NULL;
	ip6h = (ip6_t *)mp->b_rptr;
	/* Skip ip6i_t header if present */
	if (ip6h->ip6_nxt == IPPROTO_RAW) {
		/* Make sure the IPv6 header is present */
		if ((mp->b_wptr - (uchar_t *)ip6h) <
		    sizeof (ip6i_t) + IPV6_HDR_LEN) {
			if (!pullupmsg(mp, sizeof (ip6i_t) + IPV6_HDR_LEN)) {
				ip1dbg(("ip_newroute_v6: pullupmsg failed\n"));
				goto err_ret;
			}
		}
		mp->b_rptr += sizeof (ip6i_t);
		ip6h = (ip6_t *)mp->b_rptr;
	}
	/* Did this packet originate externally? */
	if (mp->b_prev) {
		if (ill != NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInNoRoutes);
		} else {
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsInNoRoutes);
		}
		mp->b_next = NULL;
		mp->b_prev = NULL;
		q = WR(q);
	} else {
		if (ill != NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutNoRoutes);
		} else {
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutNoRoutes);
		}
		if (ip_hdr_complete_v6(ip6h, zoneid, ipst)) {
			/* Failed */
			if (copy_mp != NULL) {
				MULTIRT_DEBUG_UNTAG(copy_mp);
				freemsg(copy_mp);
			}
			MULTIRT_DEBUG_UNTAG(first_mp);
			freemsg(first_mp);
			if (ire != NULL)
				ire_refrele(ire);
			if (need_rele)
				ill_refrele(ill);
			return;
		}
	}

	if (need_rele)
		ill_refrele(ill);

	/*
	 * At this point we will have ire only if RTF_BLACKHOLE
	 * or RTF_REJECT flags are set on the IRE. It will not
	 * generate ICMP6_DST_UNREACH_NOROUTE if RTF_BLACKHOLE is set.
	 */
	if (ire != NULL) {
		if (ire->ire_flags & RTF_BLACKHOLE) {
			ire_refrele(ire);
			if (copy_mp != NULL) {
				MULTIRT_DEBUG_UNTAG(copy_mp);
				freemsg(copy_mp);
			}
			MULTIRT_DEBUG_UNTAG(first_mp);
			freemsg(first_mp);
			return;
		}
		ire_refrele(ire);
	}
	if (ip_debug > 3) {
		/* ip2dbg */
		pr_addr_dbg("ip_newroute_v6: no route to %s\n",
		    AF_INET6, v6dstp);
	}
	icmp_unreachable_v6(WR(q), first_mp, ICMP6_DST_UNREACH_NOROUTE,
	    B_FALSE, B_FALSE, zoneid, ipst);
}

/*
 * ip_newroute_ipif_v6 is called by ip_wput_v6 and ip_wput_ipsec_out_v6 whenever
 * we need to send out a packet to a destination address for which we do not
 * have specific routing information. It is only used for multicast packets.
 *
 * If unspec_src we allow creating an IRE with source address zero.
 * ire_send_v6() will delete it after the packet is sent.
 */
void
ip_newroute_ipif_v6(queue_t *q, mblk_t *mp, ipif_t *ipif,
    in6_addr_t v6dst, int unspec_src, zoneid_t zoneid)
{
	ire_t	*ire = NULL;
	ipif_t	*src_ipif = NULL;
	int	err = 0;
	ill_t	*dst_ill = NULL;
	ire_t	*save_ire;
	ushort_t ire_marks = 0;
	ipsec_out_t *io;
	ill_t *attach_ill = NULL;
	ill_t *ill;
	ip6_t *ip6h;
	mblk_t *first_mp;
	boolean_t ip6i_present;
	ire_t *fire = NULL;
	mblk_t  *copy_mp = NULL;
	boolean_t multirt_resolve_next;
	in6_addr_t *v6dstp = &v6dst;
	boolean_t ipif_held = B_FALSE;
	boolean_t ill_held = B_FALSE;
	boolean_t ip6_asp_table_held = B_FALSE;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	/*
	 * This loop is run only once in most cases.
	 * We loop to resolve further routes only when the destination
	 * can be reached through multiple RTF_MULTIRT-flagged ires.
	 */
	do {
		multirt_resolve_next = B_FALSE;
		if (dst_ill != NULL) {
			ill_refrele(dst_ill);
			dst_ill = NULL;
		}

		if (src_ipif != NULL) {
			ipif_refrele(src_ipif);
			src_ipif = NULL;
		}
		ASSERT(ipif != NULL);
		ill = ipif->ipif_ill;

		ASSERT(!IN6_IS_ADDR_V4MAPPED(v6dstp));
		if (ip_debug > 2) {
			/* ip1dbg */
			pr_addr_dbg("ip_newroute_ipif_v6: v6dst %s\n",
			    AF_INET6, v6dstp);
			printf("ip_newroute_ipif_v6: if %s, v6 %d\n",
			    ill->ill_name, ipif->ipif_isv6);
		}

		first_mp = mp;
		if (mp->b_datap->db_type == M_CTL) {
			mp = mp->b_cont;
			io = (ipsec_out_t *)first_mp->b_rptr;
			ASSERT(io->ipsec_out_type == IPSEC_OUT);
		} else {
			io = NULL;
		}

		/*
		 * If the interface is a pt-pt interface we look for an
		 * IRE_IF_RESOLVER or IRE_IF_NORESOLVER that matches both the
		 * local_address and the pt-pt destination address.
		 * Otherwise we just match the local address.
		 */
		if (!(ill->ill_flags & ILLF_MULTICAST)) {
			goto err_ret;
		}
		/*
		 * If this end point is bound to IPIF_NOFAILOVER, set bnf_ill
		 * and bind_to_nofailover B_TRUE. We can't use conn to determine
		 * as it could be NULL.
		 *
		 * This information can appear either in an ip6i_t or an
		 * IPSEC_OUT message.
		 */
		ip6h = (ip6_t *)mp->b_rptr;
		ip6i_present = (ip6h->ip6_nxt == IPPROTO_RAW);
		if (ip6i_present || (io != NULL && io->ipsec_out_attach_if)) {
			if (!ip6i_present ||
			    ((ip6i_t *)ip6h)->ip6i_flags & IP6I_ATTACH_IF) {
				attach_ill = ip_grab_attach_ill(ill, first_mp,
				    (ip6i_present ?
				    ((ip6i_t *)ip6h)->ip6i_ifindex :
				    io->ipsec_out_ill_index), B_TRUE, ipst);
				/* Failure case frees things for us. */
				if (attach_ill == NULL)
					return;

				/*
				 * Check if we need an ire that will not be
				 * looked up by anybody else i.e. HIDDEN.
				 */
				if (ill_is_probeonly(attach_ill))
					ire_marks = IRE_MARK_HIDDEN;
			}
		}

		/*
		 * We check if an IRE_OFFSUBNET for the addr that goes through
		 * ipif exists. We need it to determine if the RTF_SETSRC and/or
		 * RTF_MULTIRT flags must be honored.
		 */
		fire = ipif_lookup_multi_ire_v6(ipif, v6dstp);
		ip2dbg(("ip_newroute_ipif_v6: "
		    "ipif_lookup_multi_ire_v6("
		    "ipif %p, dst %08x) = fire %p\n",
		    (void *)ipif, ntohl(V4_PART_OF_V6((*v6dstp))),
		    (void *)fire));

		/*
		 * If the application specified the ill (ifindex), we still
		 * load spread. Only if the packets needs to go out specifically
		 * on a given ill e.g. binding to IPIF_NOFAILOVER address or
		 * IPV6_BOUND_PIF, or there is a parent ire entry that specified
		 * multirouting, then we don't try to use a different ill for
		 * load spreading.
		 */
		if (attach_ill == NULL) {
			/*
			 * If the interface belongs to an interface group,
			 * make sure the next possible interface in the group
			 * is used.  This encourages load spreading among peers
			 * in an interface group.
			 *
			 * Note: While we pick a dst_ill we are really only
			 * interested in the ill for load spreading. The source
			 * ipif is determined by source address selection below.
			 */
			if ((fire != NULL) && (fire->ire_flags & RTF_MULTIRT)) {
				dst_ill = ipif->ipif_ill;
				/* For uniformity do a refhold */
				ill_refhold(dst_ill);
			} else {
				/* refheld by ip_newroute_get_dst_ill_v6 */
				dst_ill =
				    ip_newroute_get_dst_ill_v6(ipif->ipif_ill);
			}
			if (dst_ill == NULL) {
				if (ip_debug > 2) {
					pr_addr_dbg("ip_newroute_ipif_v6: "
					    "no dst ill for dst %s\n",
					    AF_INET6, v6dstp);
				}
				goto err_ret;
			}
		} else {
			dst_ill = ipif->ipif_ill;
			/*
			 * ip_wput_v6 passes the right ipif for IPIF_NOFAILOVER
			 * and IPV6_BOUND_PIF case.
			 */
			ASSERT(dst_ill == attach_ill);
			/* attach_ill is already refheld */
		}
		/*
		 * Pick a source address which matches the scope of the
		 * destination address.
		 * For RTF_SETSRC routes, the source address is imposed by the
		 * parent ire (fire).
		 */
		ASSERT(src_ipif == NULL);
		if ((fire != NULL) && (fire->ire_flags & RTF_SETSRC)) {
			/*
			 * Check that the ipif matching the requested source
			 * address still exists.
			 */
			src_ipif =
			    ipif_lookup_addr_v6(&fire->ire_src_addr_v6,
			    NULL, zoneid, NULL, NULL, NULL, NULL, ipst);
		}
		if (src_ipif == NULL && ip6_asp_can_lookup(ipst)) {
			ip6_asp_table_held = B_TRUE;
			src_ipif = ipif_select_source_v6(dst_ill, v6dstp,
			    RESTRICT_TO_NONE, IPV6_PREFER_SRC_DEFAULT, zoneid);
		}

		if (src_ipif == NULL) {
			if (!unspec_src) {
				if (ip_debug > 2) {
					/* ip1dbg */
					pr_addr_dbg("ip_newroute_ipif_v6: "
					    "no src for dst %s\n,",
					    AF_INET6, v6dstp);
					printf(" through interface %s\n",
					    dst_ill->ill_name);
				}
				goto err_ret;
			}
			src_ipif = ipif;
			ipif_refhold(src_ipif);
		}
		ire = ipif_to_ire_v6(ipif);
		if (ire == NULL) {
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("ip_newroute_ipif_v6: v6src %s\n",
				    AF_INET6, &ipif->ipif_v6lcl_addr);
				printf("ip_newroute_ipif_v6: "
				    "if %s\n", dst_ill->ill_name);
			}
			goto err_ret;
		}
		if (ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE))
			goto err_ret;

		ASSERT(ire->ire_ipversion == IPV6_VERSION);

		ip1dbg(("ip_newroute_ipif_v6: interface type %s (%d),",
		    ip_nv_lookup(ire_nv_tbl, ire->ire_type), ire->ire_type));
		if (ip_debug > 2) {
			/* ip1dbg */
			pr_addr_dbg(" address %s\n",
			    AF_INET6, &ire->ire_src_addr_v6);
		}
		save_ire = ire;
		ip2dbg(("ip_newroute_ipif: ire %p, ipif %p\n",
		    (void *)ire, (void *)ipif));

		if ((fire != NULL) && (fire->ire_flags & RTF_MULTIRT)) {
			/*
			 * an IRE_OFFSUBET was looked up
			 * on that interface.
			 * this ire has RTF_MULTIRT flag,
			 * so the resolution loop
			 * will be re-entered to resolve
			 * additional routes on other
			 * interfaces. For that purpose,
			 * a copy of the packet is
			 * made at this point.
			 */
			fire->ire_last_used_time = lbolt;
			copy_mp = copymsg(first_mp);
			if (copy_mp) {
				MULTIRT_DEBUG_TAG(copy_mp);
			}
		}

		ASSERT((attach_ill == NULL) || (dst_ill == attach_ill));
		switch (ire->ire_type) {
		case IRE_IF_NORESOLVER: {
			/*
			 * We have what we need to build an IRE_CACHE.
			 *
			 * handle the Gated case, where we create
			 * a NORESOLVER route for loopback.
			 */
			if (dst_ill->ill_net_type != IRE_IF_NORESOLVER)
				break;
			/*
			 * The newly created ire will inherit the flags of the
			 * parent ire, if any.
			 */
			ire = ire_create_v6(
			    v6dstp,			/* dest address */
			    &ipv6_all_ones,		/* mask */
			    &src_ipif->ipif_v6src_addr, /* source address */
			    NULL,			/* gateway address */
			    &save_ire->ire_max_frag,
			    NULL,			/* no src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,
			    src_ipif,
			    NULL,
			    (fire != NULL) ?		/* Parent handle */
			    fire->ire_phandle : 0,
			    save_ire->ire_ihandle,	/* Interface handle */
			    (fire != NULL) ?
			    (fire->ire_flags & (RTF_SETSRC | RTF_MULTIRT)) :
			    0,
			    &ire_uinfo_null,
			    NULL,
			    NULL,
			    ipst);

			if (ire == NULL) {
				ire_refrele(save_ire);
				break;
			}

			ire->ire_marks |= ire_marks;

			err = ndp_noresolver(dst_ill, v6dstp);
			if (err != 0) {
				ire_refrele(save_ire);
				break;
			}

			/* Prevent save_ire from getting deleted */
			IRB_REFHOLD(save_ire->ire_bucket);
			/* Has it been removed already ? */
			if (save_ire->ire_marks & IRE_MARK_CONDEMNED) {
				IRB_REFRELE(save_ire->ire_bucket);
				ire_refrele(save_ire);
				break;
			}

			ire_add_then_send(q, ire, first_mp);
			if (ip6_asp_table_held) {
				ip6_asp_table_refrele(ipst);
				ip6_asp_table_held = B_FALSE;
			}

			/* Assert that it is not deleted yet. */
			ASSERT(save_ire->ire_ptpn != NULL);
			IRB_REFRELE(save_ire->ire_bucket);
			ire_refrele(save_ire);
			if (fire != NULL) {
				ire_refrele(fire);
				fire = NULL;
			}

			/*
			 * The resolution loop is re-entered if we
			 * actually are in a multirouting case.
			 */
			if (copy_mp != NULL) {
				boolean_t need_resolve =
				    ire_multirt_need_resolve_v6(v6dstp,
				    MBLK_GETLABEL(copy_mp), ipst);
				if (!need_resolve) {
					MULTIRT_DEBUG_UNTAG(copy_mp);
					freemsg(copy_mp);
					copy_mp = NULL;
				} else {
					/*
					 * ipif_lookup_group_v6() calls
					 * ire_lookup_multi_v6() that uses
					 * ire_ftable_lookup_v6() to find
					 * an IRE_INTERFACE for the group.
					 * In the multirt case,
					 * ire_lookup_multi_v6() then invokes
					 * ire_multirt_lookup_v6() to find
					 * the next resolvable ire.
					 * As a result, we obtain a new
					 * interface, derived from the
					 * next ire.
					 */
					if (ipif_held) {
						ipif_refrele(ipif);
						ipif_held = B_FALSE;
					}
					ipif = ipif_lookup_group_v6(v6dstp,
					    zoneid, ipst);
					ip2dbg(("ip_newroute_ipif: "
					    "multirt dst %08x, ipif %p\n",
					    ntohl(V4_PART_OF_V6((*v6dstp))),
					    (void *)ipif));
					if (ipif != NULL) {
						ipif_held = B_TRUE;
						mp = copy_mp;
						copy_mp = NULL;
						multirt_resolve_next =
						    B_TRUE;
						continue;
					} else {
						freemsg(copy_mp);
					}
				}
			}
			ill_refrele(dst_ill);
			if (ipif_held) {
				ipif_refrele(ipif);
				ipif_held = B_FALSE;
			}
			if (src_ipif != NULL)
				ipif_refrele(src_ipif);
			return;
		}
		case IRE_IF_RESOLVER: {

			ASSERT(dst_ill->ill_isv6);

			/*
			 * We obtain a partial IRE_CACHE which we will pass
			 * along with the resolver query.  When the response
			 * comes back it will be there ready for us to add.
			 */
			/*
			 * the newly created ire will inherit the flags of the
			 * parent ire, if any.
			 */
			ire = ire_create_v6(
			    v6dstp,			/* dest address */
			    &ipv6_all_ones,		/* mask */
			    &src_ipif->ipif_v6src_addr, /* source address */
			    NULL,			/* gateway address */
			    &save_ire->ire_max_frag,
			    NULL,			/* src nce */
			    dst_ill->ill_rq,		/* recv-from queue */
			    dst_ill->ill_wq,		/* send-to queue */
			    IRE_CACHE,
			    src_ipif,
			    NULL,
			    (fire != NULL) ?		/* Parent handle */
			    fire->ire_phandle : 0,
			    save_ire->ire_ihandle,	/* Interface handle */
			    (fire != NULL) ?
			    (fire->ire_flags & (RTF_SETSRC | RTF_MULTIRT)) :
			    0,
			    &ire_uinfo_null,
			    NULL,
			    NULL,
			    ipst);

			if (ire == NULL) {
				ire_refrele(save_ire);
				break;
			}

			ire->ire_marks |= ire_marks;

			/* Resolve and add ire to the ctable */
			err = ndp_resolver(dst_ill, v6dstp, first_mp, zoneid);
			switch (err) {
			case 0:
				/* Prevent save_ire from getting deleted */
				IRB_REFHOLD(save_ire->ire_bucket);
				/* Has it been removed already ? */
				if (save_ire->ire_marks & IRE_MARK_CONDEMNED) {
					IRB_REFRELE(save_ire->ire_bucket);
					ire_refrele(save_ire);
					break;
				}
				/*
				 * We have a resolved cache entry,
				 * add in the IRE.
				 */
				ire_add_then_send(q, ire, first_mp);
				if (ip6_asp_table_held) {
					ip6_asp_table_refrele(ipst);
					ip6_asp_table_held = B_FALSE;
				}

				/* Assert that it is not deleted yet. */
				ASSERT(save_ire->ire_ptpn != NULL);
				IRB_REFRELE(save_ire->ire_bucket);
				ire_refrele(save_ire);
				if (fire != NULL) {
					ire_refrele(fire);
					fire = NULL;
				}

				/*
				 * The resolution loop is re-entered if we
				 * actually are in a multirouting case.
				 */
				if (copy_mp != NULL) {
					boolean_t need_resolve =
					    ire_multirt_need_resolve_v6(v6dstp,
					    MBLK_GETLABEL(copy_mp), ipst);
					if (!need_resolve) {
						MULTIRT_DEBUG_UNTAG(copy_mp);
						freemsg(copy_mp);
						copy_mp = NULL;
					} else {
						/*
						 * ipif_lookup_group_v6() calls
						 * ire_lookup_multi_v6() that
						 * uses ire_ftable_lookup_v6()
						 * to find an IRE_INTERFACE for
						 * the group. In the multirt
						 * case, ire_lookup_multi_v6()
						 * then invokes
						 * ire_multirt_lookup_v6() to
						 * find the next resolvable ire.
						 * As a result, we obtain a new
						 * interface, derived from the
						 * next ire.
						 */
						if (ipif_held) {
							ipif_refrele(ipif);
							ipif_held = B_FALSE;
						}
						ipif = ipif_lookup_group_v6(
						    v6dstp, zoneid, ipst);
						ip2dbg(("ip_newroute_ipif: "
						    "multirt dst %08x, "
						    "ipif %p\n",
						    ntohl(V4_PART_OF_V6(
						    (*v6dstp))),
						    (void *)ipif));
						if (ipif != NULL) {
							ipif_held = B_TRUE;
							mp = copy_mp;
							copy_mp = NULL;
							multirt_resolve_next =
							    B_TRUE;
							continue;
						} else {
							freemsg(copy_mp);
						}
					}
				}
				ill_refrele(dst_ill);
				if (ipif_held) {
					ipif_refrele(ipif);
					ipif_held = B_FALSE;
				}
				if (src_ipif != NULL)
					ipif_refrele(src_ipif);
				return;

			case EINPROGRESS:
				/*
				 * mp was consumed - presumably queued.
				 * No need for ire, presumably resolution is
				 * in progress, and ire will be added when the
				 * address is resolved.
				 */
				if (ip6_asp_table_held) {
					ip6_asp_table_refrele(ipst);
					ip6_asp_table_held = B_FALSE;
				}
				ire_delete(ire);
				ire_refrele(save_ire);
				if (fire != NULL) {
					ire_refrele(fire);
					fire = NULL;
				}

				/*
				 * The resolution loop is re-entered if we
				 * actually are in a multirouting case.
				 */
				if (copy_mp != NULL) {
					boolean_t need_resolve =
					    ire_multirt_need_resolve_v6(v6dstp,
					    MBLK_GETLABEL(copy_mp), ipst);
					if (!need_resolve) {
						MULTIRT_DEBUG_UNTAG(copy_mp);
						freemsg(copy_mp);
						copy_mp = NULL;
					} else {
						/*
						 * ipif_lookup_group_v6() calls
						 * ire_lookup_multi_v6() that
						 * uses ire_ftable_lookup_v6()
						 * to find an IRE_INTERFACE for
						 * the group. In the multirt
						 * case, ire_lookup_multi_v6()
						 * then invokes
						 * ire_multirt_lookup_v6() to
						 * find the next resolvable ire.
						 * As a result, we obtain a new
						 * interface, derived from the
						 * next ire.
						 */
						if (ipif_held) {
							ipif_refrele(ipif);
							ipif_held = B_FALSE;
						}
						ipif = ipif_lookup_group_v6(
						    v6dstp, zoneid, ipst);
						ip2dbg(("ip_newroute_ipif: "
						    "multirt dst %08x, "
						    "ipif %p\n",
						    ntohl(V4_PART_OF_V6(
						    (*v6dstp))),
						    (void *)ipif));
						if (ipif != NULL) {
							ipif_held = B_TRUE;
							mp = copy_mp;
							copy_mp = NULL;
							multirt_resolve_next =
							    B_TRUE;
							continue;
						} else {
							freemsg(copy_mp);
						}
					}
				}
				ill_refrele(dst_ill);
				if (ipif_held) {
					ipif_refrele(ipif);
					ipif_held = B_FALSE;
				}
				if (src_ipif != NULL)
					ipif_refrele(src_ipif);
				return;
			default:
				/* Some transient error */
				ire_refrele(save_ire);
				break;
			}
			break;
		}
		default:
			break;
		}
		if (ip6_asp_table_held) {
			ip6_asp_table_refrele(ipst);
			ip6_asp_table_held = B_FALSE;
		}
	} while (multirt_resolve_next);

err_ret:
	if (ip6_asp_table_held)
		ip6_asp_table_refrele(ipst);
	if (ire != NULL)
		ire_refrele(ire);
	if (fire != NULL)
		ire_refrele(fire);
	if (ipif != NULL && ipif_held)
		ipif_refrele(ipif);
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	/* Multicast - no point in trying to generate ICMP error */
	ASSERT((attach_ill == NULL) || (dst_ill == attach_ill));
	if (dst_ill != NULL) {
		ill = dst_ill;
		ill_held = B_TRUE;
	}
	if (mp->b_prev || mp->b_next) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
	} else {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
	}
	ip1dbg(("ip_newroute_ipif_v6: dropped\n"));
	mp->b_next = NULL;
	mp->b_prev = NULL;
	freemsg(first_mp);
	if (ill_held)
		ill_refrele(ill);
}

/*
 * Parse and process any hop-by-hop or destination options.
 *
 * Assumes that q is an ill read queue so that ICMP errors for link-local
 * destinations are sent out the correct interface.
 *
 * Returns -1 if there was an error and mp has been consumed.
 * Returns 0 if no special action is needed.
 * Returns 1 if the packet contained a router alert option for this node
 * which is verified to be "interesting/known" for our implementation.
 *
 * XXX Note: In future as more hbh or dest options are defined,
 * it may be better to have different routines for hbh and dest
 * options as opt_type fields other than IP6OPT_PAD1 and IP6OPT_PADN
 * may have same value in different namespaces. Or is it same namespace ??
 * Current code checks for each opt_type (other than pads) if it is in
 * the expected  nexthdr (hbh or dest)
 */
static int
ip_process_options_v6(queue_t *q, mblk_t *mp, ip6_t *ip6h,
    uint8_t *optptr, uint_t optlen, uint8_t hdr_type, ip_stack_t *ipst)
{
	uint8_t opt_type;
	uint_t optused;
	int ret = 0;
	mblk_t *first_mp;
	const char *errtype;
	zoneid_t zoneid;
	ill_t *ill = q->q_ptr;
	ipif_t *ipif;

	first_mp = mp;
	if (mp->b_datap->db_type == M_CTL) {
		mp = mp->b_cont;
	}

	while (optlen != 0) {
		opt_type = *optptr;
		if (opt_type == IP6OPT_PAD1) {
			optused = 1;
		} else {
			if (optlen < 2)
				goto bad_opt;
			errtype = "malformed";
			if (opt_type == ip6opt_ls) {
				optused = 2 + optptr[1];
				if (optused > optlen)
					goto bad_opt;
			} else switch (opt_type) {
			case IP6OPT_PADN:
				/*
				 * Note:We don't verify that (N-2) pad octets
				 * are zero as required by spec. Adhere to
				 * "be liberal in what you accept..." part of
				 * implementation philosophy (RFC791,RFC1122)
				 */
				optused = 2 + optptr[1];
				if (optused > optlen)
					goto bad_opt;
				break;

			case IP6OPT_JUMBO:
				if (hdr_type != IPPROTO_HOPOPTS)
					goto opt_error;
				goto opt_error; /* XXX Not implemented! */

			case IP6OPT_ROUTER_ALERT: {
				struct ip6_opt_router *or;

				if (hdr_type != IPPROTO_HOPOPTS)
					goto opt_error;
				optused = 2 + optptr[1];
				if (optused > optlen)
					goto bad_opt;
				or = (struct ip6_opt_router *)optptr;
				/* Check total length and alignment */
				if (optused != sizeof (*or) ||
				    ((uintptr_t)or->ip6or_value & 0x1) != 0)
					goto opt_error;
				/* Check value */
				switch (*((uint16_t *)or->ip6or_value)) {
				case IP6_ALERT_MLD:
				case IP6_ALERT_RSVP:
					ret = 1;
				}
				break;
			}
			case IP6OPT_HOME_ADDRESS: {
				/*
				 * Minimal support for the home address option
				 * (which is required by all IPv6 nodes).
				 * Implement by just swapping the home address
				 * and source address.
				 * XXX Note: this has IPsec implications since
				 * AH needs to take this into account.
				 * Also, when IPsec is used we need to ensure
				 * that this is only processed once
				 * in the received packet (to avoid swapping
				 * back and forth).
				 * NOTE:This option processing is considered
				 * to be unsafe and prone to a denial of
				 * service attack.
				 * The current processing is not safe even with
				 * IPsec secured IP packets. Since the home
				 * address option processing requirement still
				 * is in the IETF draft and in the process of
				 * being redefined for its usage, it has been
				 * decided to turn off the option by default.
				 * If this section of code needs to be executed,
				 * ndd variable ip6_ignore_home_address_opt
				 * should be set to 0 at the user's own risk.
				 */
				struct ip6_opt_home_address *oh;
				in6_addr_t tmp;

				if (ipst->ips_ipv6_ignore_home_address_opt)
					goto opt_error;

				if (hdr_type != IPPROTO_DSTOPTS)
					goto opt_error;
				optused = 2 + optptr[1];
				if (optused > optlen)
					goto bad_opt;

				/*
				 * We did this dest. opt the first time
				 * around (i.e. before AH processing).
				 * If we've done AH... stop now.
				 */
				if (first_mp != mp) {
					ipsec_in_t *ii;

					ii = (ipsec_in_t *)first_mp->b_rptr;
					if (ii->ipsec_in_ah_sa != NULL)
						break;
				}

				oh = (struct ip6_opt_home_address *)optptr;
				/* Check total length and alignment */
				if (optused < sizeof (*oh) ||
				    ((uintptr_t)oh->ip6oh_addr & 0x7) != 0)
					goto opt_error;
				/* Swap ip6_src and the home address */
				tmp = ip6h->ip6_src;
				/* XXX Note: only 8 byte alignment option */
				ip6h->ip6_src = *(in6_addr_t *)oh->ip6oh_addr;
				*(in6_addr_t *)oh->ip6oh_addr = tmp;
				break;
			}

			case IP6OPT_TUNNEL_LIMIT:
				if (hdr_type != IPPROTO_DSTOPTS) {
					goto opt_error;
				}
				optused = 2 + optptr[1];
				if (optused > optlen) {
					goto bad_opt;
				}
				if (optused != 3) {
					goto opt_error;
				}
				break;

			default:
				errtype = "unknown";
				/* FALLTHROUGH */
			opt_error:
				/* Determine which zone should send error */
				zoneid = ipif_lookup_addr_zoneid_v6(
				    &ip6h->ip6_dst, ill, ipst);
				switch (IP6OPT_TYPE(opt_type)) {
				case IP6OPT_TYPE_SKIP:
					optused = 2 + optptr[1];
					if (optused > optlen)
						goto bad_opt;
					ip1dbg(("ip_process_options_v6: %s "
					    "opt 0x%x skipped\n",
					    errtype, opt_type));
					break;
				case IP6OPT_TYPE_DISCARD:
					ip1dbg(("ip_process_options_v6: %s "
					    "opt 0x%x; packet dropped\n",
					    errtype, opt_type));
					freemsg(first_mp);
					return (-1);
				case IP6OPT_TYPE_ICMP:
					if (zoneid == ALL_ZONES) {
						freemsg(first_mp);
						return (-1);
					}
					icmp_param_problem_v6(WR(q), first_mp,
					    ICMP6_PARAMPROB_OPTION,
					    (uint32_t)(optptr -
					    (uint8_t *)ip6h),
					    B_FALSE, B_FALSE, zoneid, ipst);
					return (-1);
				case IP6OPT_TYPE_FORCEICMP:
					/*
					 * If we don't have a zone and the dst
					 * addr is multicast, then pick a zone
					 * based on the inbound interface.
					 */
					if (zoneid == ALL_ZONES &&
					    IN6_IS_ADDR_MULTICAST(
					    &ip6h->ip6_dst)) {
						ipif = ipif_select_source_v6(
						    ill, &ip6h->ip6_src,
						    RESTRICT_TO_GROUP,
						    IPV6_PREFER_SRC_DEFAULT,
						    ALL_ZONES);
						if (ipif != NULL) {
							zoneid =
							    ipif->ipif_zoneid;
							ipif_refrele(ipif);
						}
					}
					if (zoneid == ALL_ZONES) {
						freemsg(first_mp);
						return (-1);
					}
					icmp_param_problem_v6(WR(q), first_mp,
					    ICMP6_PARAMPROB_OPTION,
					    (uint32_t)(optptr -
					    (uint8_t *)ip6h),
					    B_FALSE, B_TRUE, zoneid, ipst);
					return (-1);
				default:
					ASSERT(0);
				}
			}
		}
		optlen -= optused;
		optptr += optused;
	}
	return (ret);

bad_opt:
	/* Determine which zone should send error */
	zoneid = ipif_lookup_addr_zoneid_v6(&ip6h->ip6_dst, ill, ipst);
	if (zoneid == ALL_ZONES) {
		freemsg(first_mp);
	} else {
		icmp_param_problem_v6(WR(q), first_mp, ICMP6_PARAMPROB_OPTION,
		    (uint32_t)(optptr - (uint8_t *)ip6h),
		    B_FALSE, B_FALSE, zoneid, ipst);
	}
	return (-1);
}

/*
 * Process a routing header that is not yet empty.
 * Only handles type 0 routing headers.
 */
static void
ip_process_rthdr(queue_t *q, mblk_t *mp, ip6_t *ip6h, ip6_rthdr_t *rth,
    ill_t *ill, uint_t flags, mblk_t *hada_mp, mblk_t *dl_mp)
{
	ip6_rthdr0_t *rthdr;
	uint_t ehdrlen;
	uint_t numaddr;
	in6_addr_t *addrptr;
	in6_addr_t tmp;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(rth->ip6r_segleft != 0);

	if (!ipst->ips_ipv6_forward_src_routed) {
		/* XXX Check for source routed out same interface? */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
		freemsg(hada_mp);
		freemsg(mp);
		return;
	}

	if (rth->ip6r_type != 0) {
		if (hada_mp != NULL)
			goto hada_drop;
		/* Sent by forwarding path, and router is global zone */
		icmp_param_problem_v6(WR(q), mp,
		    ICMP6_PARAMPROB_HEADER,
		    (uint32_t)((uchar_t *)&rth->ip6r_type - (uchar_t *)ip6h),
		    B_FALSE, B_FALSE, GLOBAL_ZONEID, ipst);
		return;
	}
	rthdr = (ip6_rthdr0_t *)rth;
	ehdrlen = 8 * (rthdr->ip6r0_len + 1);
	ASSERT(mp->b_rptr + ehdrlen <= mp->b_wptr);
	addrptr = (in6_addr_t *)((char *)rthdr + sizeof (*rthdr));
	/* rthdr->ip6r0_len is twice the number of addresses in the header */
	if (rthdr->ip6r0_len & 0x1) {
		/* An odd length is impossible */
		if (hada_mp != NULL)
			goto hada_drop;
		/* Sent by forwarding path, and router is global zone */
		icmp_param_problem_v6(WR(q), mp,
		    ICMP6_PARAMPROB_HEADER,
		    (uint32_t)((uchar_t *)&rthdr->ip6r0_len - (uchar_t *)ip6h),
		    B_FALSE, B_FALSE, GLOBAL_ZONEID, ipst);
		return;
	}
	numaddr = rthdr->ip6r0_len / 2;
	if (rthdr->ip6r0_segleft > numaddr) {
		/* segleft exceeds number of addresses in routing header */
		if (hada_mp != NULL)
			goto hada_drop;
		/* Sent by forwarding path, and router is global zone */
		icmp_param_problem_v6(WR(q), mp,
		    ICMP6_PARAMPROB_HEADER,
		    (uint32_t)((uchar_t *)&rthdr->ip6r0_segleft -
		    (uchar_t *)ip6h),
		    B_FALSE, B_FALSE, GLOBAL_ZONEID, ipst);
		return;
	}
	addrptr += (numaddr - rthdr->ip6r0_segleft);
	if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst) ||
	    IN6_IS_ADDR_MULTICAST(addrptr)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		freemsg(hada_mp);
		freemsg(mp);
		return;
	}
	/* Swap */
	tmp = *addrptr;
	*addrptr = ip6h->ip6_dst;
	ip6h->ip6_dst = tmp;
	rthdr->ip6r0_segleft--;
	/* Don't allow any mapped addresses - ip_wput_v6 can't handle them */
	if (IN6_IS_ADDR_V4MAPPED(&ip6h->ip6_dst)) {
		if (hada_mp != NULL)
			goto hada_drop;
		/* Sent by forwarding path, and router is global zone */
		icmp_unreachable_v6(WR(q), mp, ICMP6_DST_UNREACH_NOROUTE,
		    B_FALSE, B_FALSE, GLOBAL_ZONEID, ipst);
		return;
	}
	if (ip_check_v6_mblk(mp, ill) == IP6_MBLK_OK) {
		ip6h = (ip6_t *)mp->b_rptr;
		ip_rput_data_v6(q, ill, mp, ip6h, flags, hada_mp, dl_mp);
	} else {
		freemsg(mp);
	}
	return;
hada_drop:
	/* IPsec kstats: bean counter? */
	freemsg(hada_mp);
	freemsg(mp);
}

/*
 * Read side put procedure for IPv6 module.
 */
void
ip_rput_v6(queue_t *q, mblk_t *mp)
{
	mblk_t		*first_mp;
	mblk_t		*hada_mp = NULL;
	ip6_t		*ip6h;
	boolean_t	ll_multicast = B_FALSE;
	boolean_t	mctl_present = B_FALSE;
	ill_t		*ill;
	struct iocblk	*iocp;
	uint_t 		flags = 0;
	mblk_t		*dl_mp;
	ip_stack_t	*ipst;
	int		check;

	ill = (ill_t *)q->q_ptr;
	ipst = ill->ill_ipst;
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		union DL_primitives *dl;

		dl = (union DL_primitives *)mp->b_rptr;
		/*
		 * Things are opening or closing - only accept DLPI
		 * ack messages. If the stream is closing and ip_wsrv
		 * has completed, ip_close is out of the qwait, but has
		 * not yet completed qprocsoff. Don't proceed any further
		 * because the ill has been cleaned up and things hanging
		 * off the ill have been freed.
		 */
		if ((mp->b_datap->db_type != M_PCPROTO) ||
		    (dl->dl_primitive == DL_UNITDATA_IND)) {
			inet_freemsg(mp);
			return;
		}
	}

	dl_mp = NULL;
	switch (mp->b_datap->db_type) {
	case M_DATA: {
		int hlen;
		uchar_t *ucp;
		struct ether_header *eh;
		dl_unitdata_ind_t *dui;

		/*
		 * This is a work-around for CR 6451644, a bug in Nemo.  It
		 * should be removed when that problem is fixed.
		 */
		if (ill->ill_mactype == DL_ETHER &&
		    (hlen = MBLKHEAD(mp)) >= sizeof (struct ether_header) &&
		    (ucp = mp->b_rptr)[-1] == (IP6_DL_SAP & 0xFF) &&
		    ucp[-2] == (IP6_DL_SAP >> 8)) {
			if (hlen >= sizeof (struct ether_vlan_header) &&
			    ucp[-5] == 0 && ucp[-6] == 0x81)
				ucp -= sizeof (struct ether_vlan_header);
			else
				ucp -= sizeof (struct ether_header);
			/*
			 * If it's a group address, then fabricate a
			 * DL_UNITDATA_IND message.
			 */
			if ((ll_multicast = (ucp[0] & 1)) != 0 &&
			    (dl_mp = allocb(DL_UNITDATA_IND_SIZE + 16,
			    BPRI_HI)) != NULL) {
				eh = (struct ether_header *)ucp;
				dui = (dl_unitdata_ind_t *)dl_mp->b_rptr;
				DB_TYPE(dl_mp) = M_PROTO;
				dl_mp->b_wptr = (uchar_t *)(dui + 1) + 16;
				dui->dl_primitive = DL_UNITDATA_IND;
				dui->dl_dest_addr_length = 8;
				dui->dl_dest_addr_offset = DL_UNITDATA_IND_SIZE;
				dui->dl_src_addr_length = 8;
				dui->dl_src_addr_offset = DL_UNITDATA_IND_SIZE +
				    8;
				dui->dl_group_address = 1;
				ucp = (uchar_t *)(dui + 1);
				if (ill->ill_sap_length > 0)
					ucp += ill->ill_sap_length;
				bcopy(&eh->ether_dhost, ucp, 6);
				bcopy(&eh->ether_shost, ucp + 8, 6);
				ucp = (uchar_t *)(dui + 1);
				if (ill->ill_sap_length < 0)
					ucp += 8 + ill->ill_sap_length;
				bcopy(&eh->ether_type, ucp, 2);
				bcopy(&eh->ether_type, ucp + 8, 2);
			}
		}
		break;
	}

	case M_PROTO:
	case M_PCPROTO:
		if (((dl_unitdata_ind_t *)mp->b_rptr)->dl_primitive !=
		    DL_UNITDATA_IND) {
			/* Go handle anything other than data elsewhere. */
			ip_rput_dlpi(q, mp);
			return;
		}
		ll_multicast = ip_get_dlpi_mbcast(ill, mp);

		/* Save the DLPI header. */
		dl_mp = mp;
		mp = mp->b_cont;
		dl_mp->b_cont = NULL;
		break;
	case M_BREAK:
		panic("ip_rput_v6: got an M_BREAK");
		/*NOTREACHED*/
	case M_IOCACK:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case DL_IOC_HDR_INFO:
			ill = (ill_t *)q->q_ptr;
			ill_fastpath_ack(ill, mp);
			return;

		case SIOCGTUNPARAM:
		case OSIOCGTUNPARAM:
			ip_rput_other(NULL, q, mp, NULL);
			return;

		case SIOCSTUNPARAM:
		case OSIOCSTUNPARAM:
			/* Go through qwriter */
			break;
		default:
			putnext(q, mp);
			return;
		}
		/* FALLTHRU */
	case M_ERROR:
	case M_HANGUP:
		mutex_enter(&ill->ill_lock);
		if (ill->ill_state_flags & ILL_CONDEMNED) {
			mutex_exit(&ill->ill_lock);
			freemsg(mp);
			return;
		}
		ill_refhold_locked(ill);
		mutex_exit(&ill->ill_lock);
		qwriter_ip(ill, q, mp, ip_rput_other, CUR_OP, B_FALSE);
		return;
	case M_CTL:
		if ((MBLKL(mp) > sizeof (int)) &&
		    ((da_ipsec_t *)mp->b_rptr)->da_type == IPHADA_M_CTL) {
			ASSERT(MBLKL(mp) >= sizeof (da_ipsec_t));
			mctl_present = B_TRUE;
			break;
		}
		putnext(q, mp);
		return;
	case M_IOCNAK:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case DL_IOC_HDR_INFO:
		case SIOCGTUNPARAM:
		case OSIOCGTUNPARAM:
			ip_rput_other(NULL, q, mp, NULL);
			return;

		case SIOCSTUNPARAM:
		case OSIOCSTUNPARAM:
			mutex_enter(&ill->ill_lock);
			if (ill->ill_state_flags & ILL_CONDEMNED) {
				mutex_exit(&ill->ill_lock);
				freemsg(mp);
				return;
			}
			ill_refhold_locked(ill);
			mutex_exit(&ill->ill_lock);
			qwriter_ip(ill, q, mp, ip_rput_other, CUR_OP, B_FALSE);
			return;
		default:
			break;
		}
		/* FALLTHRU */
	default:
		putnext(q, mp);
		return;
	}
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInReceives);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInOctets,
	    (mp->b_cont == NULL) ? MBLKL(mp) : msgdsize(mp));
	/*
	 * if db_ref > 1 then copymsg and free original. Packet may be
	 * changed and do not want other entity who has a reference to this
	 * message to trip over the changes. This is a blind change because
	 * trying to catch all places that might change packet is too
	 * difficult (since it may be a module above this one).
	 */
	if (mp->b_datap->db_ref > 1) {
		mblk_t  *mp1;

		mp1 = copymsg(mp);
		freemsg(mp);
		if (mp1 == NULL) {
			first_mp = NULL;
			goto discard;
		}
		mp = mp1;
	}
	first_mp = mp;
	if (mctl_present) {
		hada_mp = first_mp;
		mp = first_mp->b_cont;
	}

	if ((check = ip_check_v6_mblk(mp, ill)) == IP6_MBLK_HDR_ERR) {
		freemsg(mp);
		return;
	}

	ip6h = (ip6_t *)mp->b_rptr;

	/*
	 * ip:::receive must see ipv6 packets with a full header,
	 * and so is placed after the IP6_MBLK_HDR_ERR check.
	 */
	DTRACE_IP7(receive, mblk_t *, first_mp, conn_t *, NULL, void_ip_t *,
	    ip6h, __dtrace_ipsr_ill_t *, ill, ipha_t *, NULL, ip6_t *, ip6h,
	    int, 0);

	if (check != IP6_MBLK_OK) {
		freemsg(mp);
		return;
	}

	DTRACE_PROBE4(ip6__physical__in__start,
	    ill_t *, ill, ill_t *, NULL,
	    ip6_t *, ip6h, mblk_t *, first_mp);

	FW_HOOKS6(ipst->ips_ip6_physical_in_event,
	    ipst->ips_ipv6firewall_physical_in,
	    ill, NULL, ip6h, first_mp, mp, ll_multicast, ipst);

	DTRACE_PROBE1(ip6__physical__in__end, mblk_t *, first_mp);

	if (first_mp == NULL)
		return;

	if ((ip6h->ip6_vcf & IPV6_VERS_AND_FLOW_MASK) ==
	    IPV6_DEFAULT_VERS_AND_FLOW) {
		/*
		 * It may be a bit too expensive to do this mapped address
		 * check here, but in the interest of robustness, it seems
		 * like the correct place.
		 * TODO: Avoid this check for e.g. connected TCP sockets
		 */
		if (IN6_IS_ADDR_V4MAPPED(&ip6h->ip6_src)) {
			ip1dbg(("ip_rput_v6: pkt with mapped src addr\n"));
			goto discard;
		}

		if (IN6_IS_ADDR_LOOPBACK(&ip6h->ip6_src)) {
			ip1dbg(("ip_rput_v6: pkt with loopback src"));
			goto discard;
		} else if (IN6_IS_ADDR_LOOPBACK(&ip6h->ip6_dst)) {
			ip1dbg(("ip_rput_v6: pkt with loopback dst"));
			goto discard;
		}

		flags |= (ll_multicast ? IP6_IN_LLMCAST : 0);
		ip_rput_data_v6(q, ill, mp, ip6h, flags, hada_mp, dl_mp);
	} else {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInWrongIPVersion);
		goto discard;
	}
	freemsg(dl_mp);
	return;

discard:
	if (dl_mp != NULL)
		freeb(dl_mp);
	freemsg(first_mp);
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
}

/*
 * Walk through the IPv6 packet in mp and see if there's an AH header
 * in it.  See if the AH header needs to get done before other headers in
 * the packet.  (Worker function for ipsec_early_ah_v6().)
 */
#define	IPSEC_HDR_DONT_PROCESS	0
#define	IPSEC_HDR_PROCESS	1
#define	IPSEC_MEMORY_ERROR	2
static int
ipsec_needs_processing_v6(mblk_t *mp, uint8_t *nexthdr)
{
	uint_t	length;
	uint_t	ehdrlen;
	uint8_t *whereptr;
	uint8_t *endptr;
	uint8_t *nexthdrp;
	ip6_dest_t *desthdr;
	ip6_rthdr_t *rthdr;
	ip6_t	*ip6h;

	/*
	 * For now just pullup everything.  In general, the less pullups,
	 * the better, but there's so much squirrelling through anyway,
	 * it's just easier this way.
	 */
	if (!pullupmsg(mp, -1)) {
		return (IPSEC_MEMORY_ERROR);
	}

	ip6h = (ip6_t *)mp->b_rptr;
	length = IPV6_HDR_LEN;
	whereptr = ((uint8_t *)&ip6h[1]); /* point to next hdr */
	endptr = mp->b_wptr;

	/*
	 * We can't just use the argument nexthdr in the place
	 * of nexthdrp becaue we don't dereference nexthdrp
	 * till we confirm whether it is a valid address.
	 */
	nexthdrp = &ip6h->ip6_nxt;
	while (whereptr < endptr) {
		/* Is there enough left for len + nexthdr? */
		if (whereptr + MIN_EHDR_LEN > endptr)
			return (IPSEC_MEMORY_ERROR);

		switch (*nexthdrp) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
			/* Assumes the headers are identical for hbh and dst */
			desthdr = (ip6_dest_t *)whereptr;
			ehdrlen = 8 * (desthdr->ip6d_len + 1);
			if ((uchar_t *)desthdr +  ehdrlen > endptr)
				return (IPSEC_MEMORY_ERROR);
			/*
			 * Return DONT_PROCESS because the destination
			 * options header may be for each hop in a
			 * routing-header, and we only want AH if we're
			 * finished with routing headers.
			 */
			if (*nexthdrp == IPPROTO_DSTOPTS)
				return (IPSEC_HDR_DONT_PROCESS);
			nexthdrp = &desthdr->ip6d_nxt;
			break;
		case IPPROTO_ROUTING:
			rthdr = (ip6_rthdr_t *)whereptr;

			/*
			 * If there's more hops left on the routing header,
			 * return now with DON'T PROCESS.
			 */
			if (rthdr->ip6r_segleft > 0)
				return (IPSEC_HDR_DONT_PROCESS);

			ehdrlen =  8 * (rthdr->ip6r_len + 1);
			if ((uchar_t *)rthdr +  ehdrlen > endptr)
				return (IPSEC_MEMORY_ERROR);
			nexthdrp = &rthdr->ip6r_nxt;
			break;
		case IPPROTO_FRAGMENT:
			/* Wait for reassembly */
			return (IPSEC_HDR_DONT_PROCESS);
		case IPPROTO_AH:
			*nexthdr = IPPROTO_AH;
			return (IPSEC_HDR_PROCESS);
		case IPPROTO_NONE:
			/* No next header means we're finished */
		default:
			return (IPSEC_HDR_DONT_PROCESS);
		}
		length += ehdrlen;
		whereptr += ehdrlen;
	}
	panic("ipsec_needs_processing_v6");
	/*NOTREACHED*/
}

/*
 * Path for AH if options are present. If this is the first time we are
 * sending a datagram to AH, allocate a IPSEC_IN message and prepend it.
 * Otherwise, just fanout.  Return value answers the boolean question:
 * "Did I consume the mblk you sent me?"
 *
 * Sometimes AH needs to be done before other IPv6 headers for security
 * reasons.  This function (and its ipsec_needs_processing_v6() above)
 * indicates if that is so, and fans out to the appropriate IPsec protocol
 * for the datagram passed in.
 */
static boolean_t
ipsec_early_ah_v6(queue_t *q, mblk_t *first_mp, boolean_t mctl_present,
    ill_t *ill, mblk_t *hada_mp, zoneid_t zoneid)
{
	mblk_t *mp;
	uint8_t nexthdr;
	ipsec_in_t *ii = NULL;
	ah_t *ah;
	ipsec_status_t ipsec_rc;
	ip_stack_t	*ipst = ill->ill_ipst;
	netstack_t	*ns = ipst->ips_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	ASSERT((hada_mp == NULL) || (!mctl_present));

	switch (ipsec_needs_processing_v6(
	    (mctl_present ? first_mp->b_cont : first_mp), &nexthdr)) {
	case IPSEC_MEMORY_ERROR:
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		freemsg(hada_mp);
		freemsg(first_mp);
		return (B_TRUE);
	case IPSEC_HDR_DONT_PROCESS:
		return (B_FALSE);
	}

	/* Default means send it to AH! */
	ASSERT(nexthdr == IPPROTO_AH);
	if (!mctl_present) {
		mp = first_mp;
		first_mp = ipsec_in_alloc(B_FALSE, ipst->ips_netstack);
		if (first_mp == NULL) {
			ip1dbg(("ipsec_early_ah_v6: IPSEC_IN "
			    "allocation failure.\n"));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(hada_mp);
			freemsg(mp);
			return (B_TRUE);
		}
		/*
		 * Store the ill_index so that when we come back
		 * from IPSEC we ride on the same queue.
		 */
		ii = (ipsec_in_t *)first_mp->b_rptr;
		ii->ipsec_in_ill_index = ill->ill_phyint->phyint_ifindex;
		ii->ipsec_in_rill_index = ii->ipsec_in_ill_index;
		first_mp->b_cont = mp;
	}
	/*
	 * Cache hardware acceleration info.
	 */
	if (hada_mp != NULL) {
		ASSERT(ii != NULL);
		IPSECHW_DEBUG(IPSECHW_PKT, ("ipsec_early_ah_v6: "
		    "caching data attr.\n"));
		ii->ipsec_in_accelerated = B_TRUE;
		ii->ipsec_in_da = hada_mp;
	}

	if (!ipsec_loaded(ipss)) {
		ip_proto_not_sup(q, first_mp, IP_FF_SEND_ICMP, zoneid, ipst);
		return (B_TRUE);
	}

	ah = ipsec_inbound_ah_sa(first_mp, ns);
	if (ah == NULL)
		return (B_TRUE);
	ASSERT(ii->ipsec_in_ah_sa != NULL);
	ASSERT(ii->ipsec_in_ah_sa->ipsa_input_func != NULL);
	ipsec_rc = ii->ipsec_in_ah_sa->ipsa_input_func(first_mp, ah);

	switch (ipsec_rc) {
	case IPSEC_STATUS_SUCCESS:
		/* we're done with IPsec processing, send it up */
		ip_fanout_proto_again(first_mp, ill, ill, NULL);
		break;
	case IPSEC_STATUS_FAILED:
		BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsInDiscards);
		break;
	case IPSEC_STATUS_PENDING:
		/* no action needed */
		break;
	}
	return (B_TRUE);
}

/*
 * Validate the IPv6 mblk for alignment.
 */
int
ip_check_v6_mblk(mblk_t *mp, ill_t *ill)
{
	int pkt_len, ip6_len;
	ip6_t *ip6h = (ip6_t *)mp->b_rptr;

	/* check for alignment and full IPv6 header */
	if (!OK_32PTR((uchar_t *)ip6h) ||
	    (mp->b_wptr - (uchar_t *)ip6h) < IPV6_HDR_LEN) {
		if (!pullupmsg(mp, IPV6_HDR_LEN)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip1dbg(("ip_rput_v6: pullupmsg failed\n"));
			return (IP6_MBLK_HDR_ERR);
		}
		ip6h = (ip6_t *)mp->b_rptr;
	}

	ASSERT(OK_32PTR((uchar_t *)ip6h) &&
	    (mp->b_wptr - (uchar_t *)ip6h) >= IPV6_HDR_LEN);

	if (mp->b_cont == NULL)
		pkt_len = mp->b_wptr - mp->b_rptr;
	else
		pkt_len = msgdsize(mp);
	ip6_len = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;

	/*
	 * Check for bogus (too short packet) and packet which
	 * was padded by the link layer.
	 */
	if (ip6_len != pkt_len) {
		ssize_t diff;

		if (ip6_len > pkt_len) {
			ip1dbg(("ip_rput_data_v6: packet too short %d %d\n",
			    ip6_len, pkt_len));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
			return (IP6_MBLK_LEN_ERR);
		}
		diff = (ssize_t)(pkt_len - ip6_len);

		if (!adjmsg(mp, -diff)) {
			ip1dbg(("ip_rput_data_v6: adjmsg failed\n"));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			return (IP6_MBLK_LEN_ERR);
		}
	}
	return (IP6_MBLK_OK);
}

/*
 * ip_rput_data_v6 -- received IPv6 packets in M_DATA messages show up here.
 * ip_rput_v6 has already verified alignment, the min length, the version,
 * and db_ref = 1.
 *
 * The ill passed in (the arg named inill) is the ill that the packet
 * actually arrived on.  We need to remember this when saving the
 * input interface index into potential IPV6_PKTINFO data in
 * ip_add_info_v6().
 *
 * This routine doesn't free dl_mp; that's the caller's responsibility on
 * return.  (Note that the callers are complex enough that there's no tail
 * recursion here anyway.)
 */
void
ip_rput_data_v6(queue_t *q, ill_t *inill, mblk_t *mp, ip6_t *ip6h,
    uint_t flags, mblk_t *hada_mp, mblk_t *dl_mp)
{
	ire_t		*ire = NULL;
	ill_t		*ill = inill;
	ill_t		*outill;
	ipif_t		*ipif;
	uint8_t		*whereptr;
	uint8_t		nexthdr;
	uint16_t	remlen;
	uint_t		prev_nexthdr_offset;
	uint_t		used;
	size_t		old_pkt_len;
	size_t		pkt_len;
	uint16_t	ip6_len;
	uint_t		hdr_len;
	boolean_t	mctl_present;
	mblk_t		*first_mp;
	mblk_t		*first_mp1;
	boolean_t	no_forward;
	ip6_hbh_t	*hbhhdr;
	boolean_t	ll_multicast = (flags & IP6_IN_LLMCAST);
	conn_t		*connp;
	ilm_t		*ilm;
	uint32_t	ports;
	zoneid_t	zoneid = GLOBAL_ZONEID;
	uint16_t	hck_flags, reass_hck_flags;
	uint32_t	reass_sum;
	boolean_t	cksum_err;
	mblk_t		*mp1;
	ip_stack_t	*ipst = inill->ill_ipst;

	EXTRACT_PKT_MP(mp, first_mp, mctl_present);

	if (hada_mp != NULL) {
		/*
		 * It's an IPsec accelerated packet.
		 * Keep a pointer to the data attributes around until
		 * we allocate the ipsecinfo structure.
		 */
		IPSECHW_DEBUG(IPSECHW_PKT,
		    ("ip_rput_data_v6: inbound HW accelerated IPsec pkt\n"));
		hada_mp->b_cont = NULL;
		/*
		 * Since it is accelerated, it came directly from
		 * the ill.
		 */
		ASSERT(mctl_present == B_FALSE);
		ASSERT(mp->b_datap->db_type != M_CTL);
	}

	ip6h = (ip6_t *)mp->b_rptr;
	ip6_len = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
	old_pkt_len = pkt_len = ip6_len;

	if (ILL_HCKSUM_CAPABLE(ill) && !mctl_present && dohwcksum)
		hck_flags = DB_CKSUMFLAGS(mp);
	else
		hck_flags = 0;

	/* Clear checksum flags in case we need to forward */
	DB_CKSUMFLAGS(mp) = 0;
	reass_sum = reass_hck_flags = 0;

	nexthdr = ip6h->ip6_nxt;

	prev_nexthdr_offset = (uint_t)((uchar_t *)&ip6h->ip6_nxt -
	    (uchar_t *)ip6h);
	whereptr = (uint8_t *)&ip6h[1];
	remlen = pkt_len - IPV6_HDR_LEN;	/* Track how much is left */

	/* Process hop by hop header options */
	if (nexthdr == IPPROTO_HOPOPTS) {
		uint_t ehdrlen;
		uint8_t *optptr;

		if (remlen < MIN_EHDR_LEN)
			goto pkt_too_short;
		if (mp->b_cont != NULL &&
		    whereptr + MIN_EHDR_LEN > mp->b_wptr) {
			if (!pullupmsg(mp, IPV6_HDR_LEN + MIN_EHDR_LEN)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				freemsg(hada_mp);
				freemsg(first_mp);
				return;
			}
			ip6h = (ip6_t *)mp->b_rptr;
			whereptr = (uint8_t *)ip6h + pkt_len - remlen;
		}
		hbhhdr = (ip6_hbh_t *)whereptr;
		nexthdr = hbhhdr->ip6h_nxt;
		prev_nexthdr_offset = (uint_t)(whereptr - (uint8_t *)ip6h);
		ehdrlen = 8 * (hbhhdr->ip6h_len + 1);

		if (remlen < ehdrlen)
			goto pkt_too_short;
		if (mp->b_cont != NULL &&
		    whereptr + ehdrlen > mp->b_wptr) {
			if (!pullupmsg(mp, IPV6_HDR_LEN + ehdrlen)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				freemsg(hada_mp);
				freemsg(first_mp);
				return;
			}
			ip6h = (ip6_t *)mp->b_rptr;
			whereptr = (uint8_t *)ip6h + pkt_len - remlen;
			hbhhdr = (ip6_hbh_t *)whereptr;
		}

		optptr = whereptr + 2;
		whereptr += ehdrlen;
		remlen -= ehdrlen;
		switch (ip_process_options_v6(q, first_mp, ip6h, optptr,
		    ehdrlen - 2, IPPROTO_HOPOPTS, ipst)) {
		case -1:
			/*
			 * Packet has been consumed and any
			 * needed ICMP messages sent.
			 */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
			freemsg(hada_mp);
			return;
		case 0:
			/* no action needed */
			break;
		case 1:
			/* Known router alert */
			goto ipv6forus;
		}
	}

	/*
	 * Attach any necessary label information to this packet.
	 */
	if (is_system_labeled() && !tsol_get_pkt_label(mp, IPV6_VERSION)) {
		if (ip6opt_ls != 0)
			ip0dbg(("tsol_get_pkt_label v6 failed\n"));
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		freemsg(hada_mp);
		freemsg(first_mp);
		return;
	}

	/*
	 * On incoming v6 multicast packets we will bypass the ire table,
	 * and assume that the read queue corresponds to the targetted
	 * interface.
	 *
	 * The effect of this is the same as the IPv4 original code, but is
	 * much cleaner I think.  See ip_rput for how that was done.
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInMcastPkts);
		UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInMcastOctets, pkt_len);
		/*
		 * XXX TODO Give to mrouted to for multicast forwarding.
		 */
		ILM_WALKER_HOLD(ill);
		ilm = ilm_lookup_ill_v6(ill, &ip6h->ip6_dst, ALL_ZONES);
		ILM_WALKER_RELE(ill);
		if (ilm == NULL) {
			if (ip_debug > 3) {
				/* ip2dbg */
				pr_addr_dbg("ip_rput_data_v6: got mcast packet"
				    "  which is not for us: %s\n", AF_INET6,
				    &ip6h->ip6_dst);
			}
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(hada_mp);
			freemsg(first_mp);
			return;
		}
		if (ip_debug > 3) {
			/* ip2dbg */
			pr_addr_dbg("ip_rput_data_v6: multicast for us: %s\n",
			    AF_INET6, &ip6h->ip6_dst);
		}
		zoneid = GLOBAL_ZONEID;
		goto ipv6forus;
	}

	ipif = ill->ill_ipif;

	/*
	 * If a packet was received on an interface that is a 6to4 tunnel,
	 * incoming IPv6 packets, with a 6to4 addressed IPv6 destination, must
	 * be checked to have a 6to4 prefix (2002:V4ADDR::/48) that is equal to
	 * the 6to4 prefix of the address configured on the receiving interface.
	 * Otherwise, the packet was delivered to this interface in error and
	 * the packet must be dropped.
	 */
	if ((ill->ill_is_6to4tun) && IN6_IS_ADDR_6TO4(&ip6h->ip6_dst)) {

		if (!IN6_ARE_6TO4_PREFIX_EQUAL(&ipif->ipif_v6lcl_addr,
		    &ip6h->ip6_dst)) {
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("ip_rput_data_v6: received 6to4 "
				    "addressed packet which is not for us: "
				    "%s\n", AF_INET6, &ip6h->ip6_dst);
			}
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(first_mp);
			return;
		}
	}

	/*
	 * Find an ire that matches destination. For link-local addresses
	 * we have to match the ill.
	 * TBD for site local addresses.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_dst)) {
		ire = ire_ctable_lookup_v6(&ip6h->ip6_dst, NULL,
		    IRE_CACHE|IRE_LOCAL, ill->ill_ipif, ALL_ZONES, NULL,
		    MATCH_IRE_TYPE | MATCH_IRE_ILL_GROUP, ipst);
	} else {
		ire = ire_cache_lookup_v6(&ip6h->ip6_dst, ALL_ZONES,
		    MBLK_GETLABEL(mp), ipst);

		if (ire != NULL && ire->ire_stq != NULL &&
		    ire->ire_zoneid != GLOBAL_ZONEID &&
		    ire->ire_zoneid != ALL_ZONES) {
			/*
			 * Should only use IREs that are visible from the
			 * global zone for forwarding.
			 */
			ire_refrele(ire);
			ire = ire_cache_lookup_v6(&ip6h->ip6_dst,
			    GLOBAL_ZONEID, MBLK_GETLABEL(mp), ipst);
		}
	}

	if (ire == NULL) {
		/*
		 * No matching IRE found.  Mark this packet as having
		 * originated externally.
		 */
		if (!(ill->ill_flags & ILLF_ROUTER) || ll_multicast) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
			if (!(ill->ill_flags & ILLF_ROUTER)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInAddrErrors);
			}
			freemsg(hada_mp);
			freemsg(first_mp);
			return;
		}
		if (ip6h->ip6_hops <= 1) {
			if (hada_mp != NULL)
				goto hada_drop;
			/* Sent by forwarding path, and router is global zone */
			icmp_time_exceeded_v6(WR(q), first_mp,
			    ICMP6_TIME_EXCEED_TRANSIT, ll_multicast, B_FALSE,
			    GLOBAL_ZONEID, ipst);
			return;
		}
		/*
		 * Per RFC 3513 section 2.5.2, we must not forward packets with
		 * an unspecified source address.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
			freemsg(hada_mp);
			freemsg(first_mp);
			return;
		}
		mp->b_prev = (mblk_t *)(uintptr_t)
		    ill->ill_phyint->phyint_ifindex;
		ip_newroute_v6(q, mp, &ip6h->ip6_dst, &ip6h->ip6_src,
		    IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_dst) ? ill : NULL,
		    GLOBAL_ZONEID, ipst);
		return;
	}
	/* we have a matching IRE */
	if (ire->ire_stq != NULL) {
		ill_group_t *ill_group;
		ill_group_t *ire_group;

		/*
		 * To be quicker, we may wish not to chase pointers
		 * (ire->ire_ipif->ipif_ill...) and instead store the
		 * forwarding policy in the ire.  An unfortunate side-
		 * effect of this would be requiring an ire flush whenever
		 * the ILLF_ROUTER flag changes.  For now, chase pointers
		 * once and store in the boolean no_forward.
		 *
		 * This appears twice to keep it out of the non-forwarding,
		 * yes-it's-for-us-on-the-right-interface case.
		 */
		no_forward = ((ill->ill_flags &
		    ire->ire_ipif->ipif_ill->ill_flags & ILLF_ROUTER) == 0);


		ASSERT(first_mp == mp);
		/*
		 * This ire has a send-to queue - forward the packet.
		 */
		if (no_forward || ll_multicast || (hada_mp != NULL)) {
			freemsg(hada_mp);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
			if (no_forward) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInAddrErrors);
			}
			freemsg(mp);
			ire_refrele(ire);
			return;
		}
		/*
		 * ipIfStatsHCInForwDatagrams should only be increment if there
		 * will be an attempt to forward the packet, which is why we
		 * increment after the above condition has been checked.
		 */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInForwDatagrams);
		if (ip6h->ip6_hops <= 1) {
			ip1dbg(("ip_rput_data_v6: hop limit expired.\n"));
			/* Sent by forwarding path, and router is global zone */
			icmp_time_exceeded_v6(WR(q), mp,
			    ICMP6_TIME_EXCEED_TRANSIT, ll_multicast, B_FALSE,
			    GLOBAL_ZONEID, ipst);
			ire_refrele(ire);
			return;
		}
		/*
		 * Per RFC 3513 section 2.5.2, we must not forward packets with
		 * an unspecified source address.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
			freemsg(mp);
			ire_refrele(ire);
			return;
		}

		if (is_system_labeled()) {
			mblk_t *mp1;

			if ((mp1 = tsol_ip_forward(ire, mp)) == NULL) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsForwProhibits);
				freemsg(mp);
				ire_refrele(ire);
				return;
			}
			/* Size may have changed */
			mp = mp1;
			ip6h = (ip6_t *)mp->b_rptr;
			pkt_len = msgdsize(mp);
		}

		if (pkt_len > ire->ire_max_frag) {
			int max_frag = ire->ire_max_frag;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTooBigErrors);
			/*
			 * Handle labeled packet resizing.
			 */
			if (is_system_labeled()) {
				max_frag = tsol_pmtu_adjust(mp, max_frag,
				    pkt_len - old_pkt_len, AF_INET6);
			}

			/* Sent by forwarding path, and router is global zone */
			icmp_pkt2big_v6(WR(q), mp, max_frag,
			    ll_multicast, B_TRUE, GLOBAL_ZONEID, ipst);
			ire_refrele(ire);
			return;
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
		ill_group = ill->ill_group;
		ire_group = ((ill_t *)(ire->ire_rfq)->q_ptr)->ill_group;
		if (ire->ire_rfq != q && (ill_group == NULL ||
		    ill_group != ire_group)) {
			if (IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_dst) ||
			    IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInAddrErrors);
				freemsg(mp);
				ire_refrele(ire);
				return;
			}
			/* TBD add site-local check at site boundary? */
		} else if (ipst->ips_ipv6_send_redirects) {
			in6_addr_t	*v6targ;
			in6_addr_t	gw_addr_v6;
			ire_t		*src_ire_v6 = NULL;

			/*
			 * Don't send a redirect when forwarding a source
			 * routed packet.
			 */
			if (ip_source_routed_v6(ip6h, mp, ipst))
				goto forward;

			mutex_enter(&ire->ire_lock);
			gw_addr_v6 = ire->ire_gateway_addr_v6;
			mutex_exit(&ire->ire_lock);
			if (!IN6_IS_ADDR_UNSPECIFIED(&gw_addr_v6)) {
				v6targ = &gw_addr_v6;
				/*
				 * We won't send redirects to a router
				 * that doesn't have a link local
				 * address, but will forward.
				 */
				if (!IN6_IS_ADDR_LINKLOCAL(v6targ)) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInAddrErrors);
					goto forward;
				}
			} else {
				v6targ = &ip6h->ip6_dst;
			}

			src_ire_v6 = ire_ftable_lookup_v6(&ip6h->ip6_src,
			    NULL, NULL, IRE_INTERFACE, ire->ire_ipif, NULL,
			    GLOBAL_ZONEID, 0, NULL,
			    MATCH_IRE_IPIF | MATCH_IRE_TYPE,
			    ipst);

			if (src_ire_v6 != NULL) {
				/*
				 * The source is directly connected.
				 */
				mp1 = copymsg(mp);
				if (mp1 != NULL) {
					icmp_send_redirect_v6(WR(q),
					    mp1, v6targ, &ip6h->ip6_dst,
					    ill, B_FALSE);
				}
				ire_refrele(src_ire_v6);
			}
		}

forward:
		/* Hoplimit verified above */
		ip6h->ip6_hops--;

		outill = ire->ire_ipif->ipif_ill;

		DTRACE_PROBE4(ip6__forwarding__start,
		    ill_t *, inill, ill_t *, outill,
		    ip6_t *, ip6h, mblk_t *, mp);

		FW_HOOKS6(ipst->ips_ip6_forwarding_event,
		    ipst->ips_ipv6firewall_forwarding,
		    inill, outill, ip6h, mp, mp, 0, ipst);

		DTRACE_PROBE1(ip6__forwarding__end, mblk_t *, mp);

		if (mp != NULL) {
			UPDATE_IB_PKT_COUNT(ire);
			ire->ire_last_used_time = lbolt;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutForwDatagrams);
			ip_xmit_v6(mp, ire, 0, NULL, B_FALSE, NULL);
		}
		IRE_REFRELE(ire);
		return;
	}

	/*
	 * Need to put on correct queue for reassembly to find it.
	 * No need to use put() since reassembly has its own locks.
	 * Note: multicast packets and packets destined to addresses
	 * assigned to loopback (ire_rfq is NULL) will be reassembled on
	 * the arriving ill. Unlike the IPv4 case, enabling strict
	 * destination multihoming will prevent accepting packets
	 * addressed to an IRE_LOCAL on lo0.
	 */
	if (ire->ire_rfq != q) {
		if ((ire = ip_check_multihome(&ip6h->ip6_dst, ire, ill))
		    == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
			freemsg(hada_mp);
			freemsg(first_mp);
			return;
		}
		if (ire->ire_rfq != NULL) {
			q = ire->ire_rfq;
			ill = (ill_t *)q->q_ptr;
			ASSERT(ill != NULL);
		}
	}

	zoneid = ire->ire_zoneid;
	UPDATE_IB_PKT_COUNT(ire);
	ire->ire_last_used_time = lbolt;
	/* Don't use the ire after this point, we'll NULL it out to be sure. */
	ire_refrele(ire);
	ire = NULL;
ipv6forus:
	/*
	 * Looks like this packet is for us one way or another.
	 * This is where we'll process destination headers etc.
	 */
	for (; ; ) {
		switch (nexthdr) {
		case IPPROTO_TCP: {
			uint16_t	*up;
			uint32_t	sum;
			int		offset;

			hdr_len = pkt_len - remlen;

			if (hada_mp != NULL) {
				ip0dbg(("tcp hada drop\n"));
				goto hada_drop;
			}


			/* TCP needs all of the TCP header */
			if (remlen < TCP_MIN_HEADER_LENGTH)
				goto pkt_too_short;
			if (mp->b_cont != NULL &&
			    whereptr + TCP_MIN_HEADER_LENGTH > mp->b_wptr) {
				if (!pullupmsg(mp,
				    hdr_len + TCP_MIN_HEADER_LENGTH)) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInDiscards);
					freemsg(first_mp);
					return;
				}
				hck_flags = 0;
				ip6h = (ip6_t *)mp->b_rptr;
				whereptr = (uint8_t *)ip6h + hdr_len;
			}
			/*
			 * Extract the offset field from the TCP header.
			 */
			offset = ((uchar_t *)ip6h)[hdr_len + 12] >> 4;
			if (offset != 5) {
				if (offset < 5) {
					ip1dbg(("ip_rput_data_v6: short "
					    "TCP data offset"));
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInDiscards);
					freemsg(first_mp);
					return;
				}
				/*
				 * There must be TCP options.
				 * Make sure we can grab them.
				 */
				offset <<= 2;
				if (remlen < offset)
					goto pkt_too_short;
				if (mp->b_cont != NULL &&
				    whereptr + offset > mp->b_wptr) {
					if (!pullupmsg(mp,
					    hdr_len + offset)) {
						BUMP_MIB(ill->ill_ip_mib,
						    ipIfStatsInDiscards);
						freemsg(first_mp);
						return;
					}
					hck_flags = 0;
					ip6h = (ip6_t *)mp->b_rptr;
					whereptr = (uint8_t *)ip6h + hdr_len;
				}
			}

			up = (uint16_t *)&ip6h->ip6_src;
			/*
			 * TCP checksum calculation.  First sum up the
			 * pseudo-header fields:
			 *  -	Source IPv6 address
			 *  -	Destination IPv6 address
			 *  -	TCP payload length
			 *  -	TCP protocol ID
			 */
			sum = htons(IPPROTO_TCP + remlen) +
			    up[0] + up[1] + up[2] + up[3] +
			    up[4] + up[5] + up[6] + up[7] +
			    up[8] + up[9] + up[10] + up[11] +
			    up[12] + up[13] + up[14] + up[15];

			/* Fold initial sum */
			sum = (sum & 0xffff) + (sum >> 16);

			mp1 = mp->b_cont;

			if ((hck_flags & (HCK_FULLCKSUM|HCK_PARTIALCKSUM)) == 0)
				IP6_STAT(ipst, ip6_in_sw_cksum);

			IP_CKSUM_RECV(hck_flags, sum, (uchar_t *)
			    ((uchar_t *)mp->b_rptr + DB_CKSUMSTART(mp)),
			    (int32_t)(whereptr - (uchar_t *)mp->b_rptr),
			    mp, mp1, cksum_err);

			if (cksum_err) {
				BUMP_MIB(ill->ill_ip_mib, tcpIfStatsInErrs);

				if (hck_flags & HCK_FULLCKSUM) {
					IP6_STAT(ipst,
					    ip6_tcp_in_full_hw_cksum_err);
				} else if (hck_flags & HCK_PARTIALCKSUM) {
					IP6_STAT(ipst,
					    ip6_tcp_in_part_hw_cksum_err);
				} else {
					IP6_STAT(ipst, ip6_tcp_in_sw_cksum_err);
				}
				freemsg(first_mp);
				return;
			}
tcp_fanout:
			ip_fanout_tcp_v6(q, first_mp, ip6h, ill, inill,
			    (flags|IP_FF_SEND_ICMP|IP_FF_SYN_ADDIRE|
			    IP_FF_IPINFO), hdr_len, mctl_present, zoneid);
			return;
		}
		case IPPROTO_SCTP:
		{
			sctp_hdr_t *sctph;
			uint32_t calcsum, pktsum;
			uint_t hdr_len = pkt_len - remlen;
			sctp_stack_t *sctps;

			sctps = inill->ill_ipst->ips_netstack->netstack_sctp;

			/* SCTP needs all of the SCTP header */
			if (remlen < sizeof (*sctph)) {
				goto pkt_too_short;
			}
			if (whereptr + sizeof (*sctph) > mp->b_wptr) {
				ASSERT(mp->b_cont != NULL);
				if (!pullupmsg(mp, hdr_len + sizeof (*sctph))) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInDiscards);
					freemsg(mp);
					return;
				}
				ip6h = (ip6_t *)mp->b_rptr;
				whereptr = (uint8_t *)ip6h + hdr_len;
			}

			sctph = (sctp_hdr_t *)(mp->b_rptr + hdr_len);
			/* checksum */
			pktsum = sctph->sh_chksum;
			sctph->sh_chksum = 0;
			calcsum = sctp_cksum(mp, hdr_len);
			if (calcsum != pktsum) {
				BUMP_MIB(&sctps->sctps_mib, sctpChecksumError);
				freemsg(mp);
				return;
			}
			sctph->sh_chksum = pktsum;
			ports = *(uint32_t *)(mp->b_rptr + hdr_len);
			if ((connp = sctp_fanout(&ip6h->ip6_src, &ip6h->ip6_dst,
			    ports, zoneid, mp, sctps)) == NULL) {
				ip_fanout_sctp_raw(first_mp, ill,
				    (ipha_t *)ip6h, B_FALSE, ports,
				    mctl_present,
				    (flags|IP_FF_SEND_ICMP|IP_FF_IPINFO),
				    B_TRUE, zoneid);
				return;
			}
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
			sctp_input(connp, (ipha_t *)ip6h, mp, first_mp, ill,
			    B_FALSE, mctl_present);
			return;
		}
		case IPPROTO_UDP: {
			uint16_t	*up;
			uint32_t	sum;

			hdr_len = pkt_len - remlen;

			if (hada_mp != NULL) {
				ip0dbg(("udp hada drop\n"));
				goto hada_drop;
			}

			/* Verify that at least the ports are present */
			if (remlen < UDPH_SIZE)
				goto pkt_too_short;
			if (mp->b_cont != NULL &&
			    whereptr + UDPH_SIZE > mp->b_wptr) {
				if (!pullupmsg(mp, hdr_len + UDPH_SIZE)) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInDiscards);
					freemsg(first_mp);
					return;
				}
				hck_flags = 0;
				ip6h = (ip6_t *)mp->b_rptr;
				whereptr = (uint8_t *)ip6h + hdr_len;
			}

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

			if (((udpha_t *)whereptr)->uha_checksum == 0) {
				/* 0x0000 checksum is invalid */
				ip1dbg(("ip_rput_data_v6: Invalid UDP "
				    "checksum value 0x0000\n"));
				BUMP_MIB(ill->ill_ip_mib,
				    udpIfStatsInCksumErrs);
				freemsg(first_mp);
				return;
			}

			up = (uint16_t *)&ip6h->ip6_src;

			/*
			 * UDP checksum calculation.  First sum up the
			 * pseudo-header fields:
			 *  -	Source IPv6 address
			 *  -	Destination IPv6 address
			 *  -	UDP payload length
			 *  -	UDP protocol ID
			 */

			sum = htons(IPPROTO_UDP + remlen) +
			    up[0] + up[1] + up[2] + up[3] +
			    up[4] + up[5] + up[6] + up[7] +
			    up[8] + up[9] + up[10] + up[11] +
			    up[12] + up[13] + up[14] + up[15];

			/* Fold initial sum */
			sum = (sum & 0xffff) + (sum >> 16);

			if (reass_hck_flags != 0) {
				hck_flags = reass_hck_flags;

				IP_CKSUM_RECV_REASS(hck_flags,
				    (int32_t)(whereptr - (uchar_t *)mp->b_rptr),
				    sum, reass_sum, cksum_err);
			} else {
				mp1 = mp->b_cont;

				IP_CKSUM_RECV(hck_flags, sum, (uchar_t *)
				    ((uchar_t *)mp->b_rptr + DB_CKSUMSTART(mp)),
				    (int32_t)(whereptr - (uchar_t *)mp->b_rptr),
				    mp, mp1, cksum_err);
			}

			if ((hck_flags & (HCK_FULLCKSUM|HCK_PARTIALCKSUM)) == 0)
				IP6_STAT(ipst, ip6_in_sw_cksum);

			if (cksum_err) {
				BUMP_MIB(ill->ill_ip_mib,
				    udpIfStatsInCksumErrs);

				if (hck_flags & HCK_FULLCKSUM)
					IP6_STAT(ipst,
					    ip6_udp_in_full_hw_cksum_err);
				else if (hck_flags & HCK_PARTIALCKSUM)
					IP6_STAT(ipst,
					    ip6_udp_in_part_hw_cksum_err);
				else
					IP6_STAT(ipst, ip6_udp_in_sw_cksum_err);

				freemsg(first_mp);
				return;
			}
			goto udp_fanout;
		}
		case IPPROTO_ICMPV6: {
			uint16_t	*up;
			uint32_t	sum;
			uint_t		hdr_len = pkt_len - remlen;

			if (hada_mp != NULL) {
				ip0dbg(("icmp hada drop\n"));
				goto hada_drop;
			}

			up = (uint16_t *)&ip6h->ip6_src;
			sum = htons(IPPROTO_ICMPV6 + remlen) +
			    up[0] + up[1] + up[2] + up[3] +
			    up[4] + up[5] + up[6] + up[7] +
			    up[8] + up[9] + up[10] + up[11] +
			    up[12] + up[13] + up[14] + up[15];
			sum = (sum & 0xffff) + (sum >> 16);
			sum = IP_CSUM(mp, hdr_len, sum);
			if (sum != 0) {
				/* IPv6 ICMP checksum failed */
				ip1dbg(("ip_rput_data_v6: ICMPv6 checksum "
				    "failed %x\n",
				    sum));
				BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInMsgs);
				BUMP_MIB(ill->ill_icmp6_mib,
				    ipv6IfIcmpInErrors);
				freemsg(first_mp);
				return;
			}

		icmp_fanout:
			/* Check variable for testing applications */
			if (ipst->ips_ipv6_drop_inbound_icmpv6) {
				freemsg(first_mp);
				return;
			}
			/*
			 * Assume that there is always at least one conn for
			 * ICMPv6 (in.ndpd) i.e. don't optimize the case
			 * where there is no conn.
			 */
			if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
				ASSERT(!IS_LOOPBACK((ill)));
				/*
				 * In the multicast case, applications may have
				 * joined the group from different zones, so we
				 * need to deliver the packet to each of them.
				 * Loop through the multicast memberships
				 * structures (ilm) on the receive ill and send
				 * a copy of the packet up each matching one.
				 */
				ILM_WALKER_HOLD(ill);
				for (ilm = ill->ill_ilm; ilm != NULL;
				    ilm = ilm->ilm_next) {
					if (ilm->ilm_flags & ILM_DELETED)
						continue;
					if (!IN6_ARE_ADDR_EQUAL(
					    &ilm->ilm_v6addr, &ip6h->ip6_dst))
						continue;
					if (!ipif_lookup_zoneid(ill,
					    ilm->ilm_zoneid, IPIF_UP, NULL))
						continue;

					first_mp1 = ip_copymsg(first_mp);
					if (first_mp1 == NULL)
						continue;
					icmp_inbound_v6(q, first_mp1, ill,
					    hdr_len, mctl_present, 0,
					    ilm->ilm_zoneid, dl_mp);
				}
				ILM_WALKER_RELE(ill);
			} else {
				first_mp1 = ip_copymsg(first_mp);
				if (first_mp1 != NULL)
					icmp_inbound_v6(q, first_mp1, ill,
					    hdr_len, mctl_present, 0, zoneid,
					    dl_mp);
			}
		}
			/* FALLTHRU */
		default: {
			/*
			 * Handle protocols with which IPv6 is less intimate.
			 */
			uint_t proto_flags = IP_FF_RAWIP|IP_FF_IPINFO;

			if (hada_mp != NULL) {
				ip0dbg(("default hada drop\n"));
				goto hada_drop;
			}

			/*
			 * Enable sending ICMP for "Unknown" nexthdr
			 * case. i.e. where we did not FALLTHRU from
			 * IPPROTO_ICMPV6 processing case above.
			 * If we did FALLTHRU, then the packet has already been
			 * processed for IPPF, don't process it again in
			 * ip_fanout_proto_v6; set IP6_NO_IPPOLICY in the
			 * flags
			 */
			if (nexthdr != IPPROTO_ICMPV6)
				proto_flags |= IP_FF_SEND_ICMP;
			else
				proto_flags |= IP6_NO_IPPOLICY;

			ip_fanout_proto_v6(q, first_mp, ip6h, ill, inill,
			    nexthdr, prev_nexthdr_offset, (flags|proto_flags),
			    mctl_present, zoneid);
			return;
		}

		case IPPROTO_DSTOPTS: {
			uint_t ehdrlen;
			uint8_t *optptr;
			ip6_dest_t *desthdr;

			/* Check if AH is present. */
			if (ipsec_early_ah_v6(q, first_mp, mctl_present, ill,
			    hada_mp, zoneid)) {
				ip0dbg(("dst early hada drop\n"));
				return;
			}

			/*
			 * Reinitialize pointers, as ipsec_early_ah_v6() does
			 * complete pullups.  We don't have to do more pullups
			 * as a result.
			 */
			whereptr = (uint8_t *)((uintptr_t)mp->b_rptr +
			    (uintptr_t)(whereptr - ((uint8_t *)ip6h)));
			ip6h = (ip6_t *)mp->b_rptr;

			if (remlen < MIN_EHDR_LEN)
				goto pkt_too_short;

			desthdr = (ip6_dest_t *)whereptr;
			nexthdr = desthdr->ip6d_nxt;
			prev_nexthdr_offset = (uint_t)(whereptr -
			    (uint8_t *)ip6h);
			ehdrlen = 8 * (desthdr->ip6d_len + 1);
			if (remlen < ehdrlen)
				goto pkt_too_short;
			optptr = whereptr + 2;
			/*
			 * Note: XXX This code does not seem to make
			 * distinction between Destination Options Header
			 * being before/after Routing Header which can
			 * happen if we are at the end of source route.
			 * This may become significant in future.
			 * (No real significant Destination Options are
			 * defined/implemented yet ).
			 */
			switch (ip_process_options_v6(q, first_mp, ip6h, optptr,
			    ehdrlen - 2, IPPROTO_DSTOPTS, ipst)) {
			case -1:
				/*
				 * Packet has been consumed and any needed
				 * ICMP errors sent.
				 */
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
				freemsg(hada_mp);
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
				panic("ip_rput_data_v6: router "
				    "alert hbh opt indication in dest opt");
				/*NOTREACHED*/
#else
				freemsg(hada_mp);
				freemsg(first_mp);
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				return;
#endif
			}
			used = ehdrlen;
			break;
		}
		case IPPROTO_FRAGMENT: {
			ip6_frag_t *fraghdr;
			size_t no_frag_hdr_len;

			if (hada_mp != NULL) {
				ip0dbg(("frag hada drop\n"));
				goto hada_drop;
			}

			ASSERT(first_mp == mp);
			if (remlen < sizeof (ip6_frag_t))
				goto pkt_too_short;

			if (mp->b_cont != NULL &&
			    whereptr + sizeof (ip6_frag_t) > mp->b_wptr) {
				if (!pullupmsg(mp,
				    pkt_len - remlen + sizeof (ip6_frag_t))) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInDiscards);
					freemsg(mp);
					return;
				}
				hck_flags = 0;
				ip6h = (ip6_t *)mp->b_rptr;
				whereptr = (uint8_t *)ip6h + pkt_len - remlen;
			}

			fraghdr = (ip6_frag_t *)whereptr;
			used = (uint_t)sizeof (ip6_frag_t);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsReasmReqds);

			/*
			 * Invoke the CGTP (multirouting) filtering module to
			 * process the incoming packet. Packets identified as
			 * duplicates must be discarded. Filtering is active
			 * only if the the ip_cgtp_filter ndd variable is
			 * non-zero.
			 */
			if (ipst->ips_ip_cgtp_filter &&
			    ipst->ips_ip_cgtp_filter_ops != NULL) {
				int cgtp_flt_pkt;
				netstackid_t stackid;

				stackid = ipst->ips_netstack->netstack_stackid;

				cgtp_flt_pkt =
				    ipst->ips_ip_cgtp_filter_ops->cfo_filter_v6(
				    stackid, inill->ill_phyint->phyint_ifindex,
				    ip6h, fraghdr);
				if (cgtp_flt_pkt == CGTP_IP_PKT_DUPLICATE) {
					freemsg(mp);
					return;
				}
			}

			/* Restore the flags */
			DB_CKSUMFLAGS(mp) = hck_flags;

			mp = ip_rput_frag_v6(q, mp, ip6h, fraghdr,
			    remlen - used, &prev_nexthdr_offset,
			    &reass_sum, &reass_hck_flags);
			if (mp == NULL) {
				/* Reassembly is still pending */
				return;
			}
			/* The first mblk are the headers before the frag hdr */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsReasmOKs);

			first_mp = mp;	/* mp has most likely changed! */
			no_frag_hdr_len = mp->b_wptr - mp->b_rptr;
			ip6h = (ip6_t *)mp->b_rptr;
			nexthdr = ((char *)ip6h)[prev_nexthdr_offset];
			whereptr = mp->b_rptr + no_frag_hdr_len;
			remlen = ntohs(ip6h->ip6_plen)  +
			    (uint16_t)(IPV6_HDR_LEN - no_frag_hdr_len);
			pkt_len = msgdsize(mp);
			used = 0;
			break;
		}
		case IPPROTO_HOPOPTS: {
			if (hada_mp != NULL) {
				ip0dbg(("hop hada drop\n"));
				goto hada_drop;
			}
			/*
			 * Illegal header sequence.
			 * (Hop-by-hop headers are processed above
			 *  and required to immediately follow IPv6 header)
			 */
			icmp_param_problem_v6(WR(q), first_mp,
			    ICMP6_PARAMPROB_NEXTHEADER,
			    prev_nexthdr_offset,
			    B_FALSE, B_FALSE, zoneid, ipst);
			return;
		}
		case IPPROTO_ROUTING: {
			uint_t ehdrlen;
			ip6_rthdr_t *rthdr;

			/* Check if AH is present. */
			if (ipsec_early_ah_v6(q, first_mp, mctl_present, ill,
			    hada_mp, zoneid)) {
				ip0dbg(("routing hada drop\n"));
				return;
			}

			/*
			 * Reinitialize pointers, as ipsec_early_ah_v6() does
			 * complete pullups.  We don't have to do more pullups
			 * as a result.
			 */
			whereptr = (uint8_t *)((uintptr_t)mp->b_rptr +
			    (uintptr_t)(whereptr - ((uint8_t *)ip6h)));
			ip6h = (ip6_t *)mp->b_rptr;

			if (remlen < MIN_EHDR_LEN)
				goto pkt_too_short;
			rthdr = (ip6_rthdr_t *)whereptr;
			nexthdr = rthdr->ip6r_nxt;
			prev_nexthdr_offset = (uint_t)(whereptr -
			    (uint8_t *)ip6h);
			ehdrlen = 8 * (rthdr->ip6r_len + 1);
			if (remlen < ehdrlen)
				goto pkt_too_short;
			if (rthdr->ip6r_segleft != 0) {
				/* Not end of source route */
				if (ll_multicast) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsForwProhibits);
					freemsg(hada_mp);
					freemsg(mp);
					return;
				}
				ip_process_rthdr(q, mp, ip6h, rthdr, ill,
				    flags, hada_mp, dl_mp);
				return;
			}
			used = ehdrlen;
			break;
		}
		case IPPROTO_AH:
		case IPPROTO_ESP: {
			/*
			 * Fast path for AH/ESP. If this is the first time
			 * we are sending a datagram to AH/ESP, allocate
			 * a IPSEC_IN message and prepend it. Otherwise,
			 * just fanout.
			 */

			ipsec_in_t *ii;
			int ipsec_rc;
			ipsec_stack_t *ipss;

			ipss = ipst->ips_netstack->netstack_ipsec;
			if (!mctl_present) {
				ASSERT(first_mp == mp);
				first_mp = ipsec_in_alloc(B_FALSE,
				    ipst->ips_netstack);
				if (first_mp == NULL) {
					ip1dbg(("ip_rput_data_v6: IPSEC_IN "
					    "allocation failure.\n"));
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInDiscards);
					freemsg(mp);
					return;
				}
				/*
				 * Store the ill_index so that when we come back
				 * from IPSEC we ride on the same queue.
				 */
				ii = (ipsec_in_t *)first_mp->b_rptr;
				ii->ipsec_in_ill_index =
				    ill->ill_phyint->phyint_ifindex;
				ii->ipsec_in_rill_index =
				    ii->ipsec_in_ill_index;
				first_mp->b_cont = mp;
				/*
				 * Cache hardware acceleration info.
				 */
				if (hada_mp != NULL) {
					IPSECHW_DEBUG(IPSECHW_PKT,
					    ("ip_rput_data_v6: "
					    "caching data attr.\n"));
					ii->ipsec_in_accelerated = B_TRUE;
					ii->ipsec_in_da = hada_mp;
					hada_mp = NULL;
				}
			} else {
				ii = (ipsec_in_t *)first_mp->b_rptr;
			}

			if (!ipsec_loaded(ipss)) {
				ip_proto_not_sup(q, first_mp, IP_FF_SEND_ICMP,
				    zoneid, ipst);
				return;
			}

			/* select inbound SA and have IPsec process the pkt */
			if (nexthdr == IPPROTO_ESP) {
				esph_t *esph = ipsec_inbound_esp_sa(first_mp,
				    ipst->ips_netstack);
				if (esph == NULL)
					return;
				ASSERT(ii->ipsec_in_esp_sa != NULL);
				ASSERT(ii->ipsec_in_esp_sa->ipsa_input_func !=
				    NULL);
				ipsec_rc = ii->ipsec_in_esp_sa->ipsa_input_func(
				    first_mp, esph);
			} else {
				ah_t *ah = ipsec_inbound_ah_sa(first_mp,
				    ipst->ips_netstack);
				if (ah == NULL)
					return;
				ASSERT(ii->ipsec_in_ah_sa != NULL);
				ASSERT(ii->ipsec_in_ah_sa->ipsa_input_func !=
				    NULL);
				ipsec_rc = ii->ipsec_in_ah_sa->ipsa_input_func(
				    first_mp, ah);
			}

			switch (ipsec_rc) {
			case IPSEC_STATUS_SUCCESS:
				break;
			case IPSEC_STATUS_FAILED:
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				/* FALLTHRU */
			case IPSEC_STATUS_PENDING:
				return;
			}
			/* we're done with IPsec processing, send it up */
			ip_fanout_proto_again(first_mp, ill, inill, NULL);
			return;
		}
		case IPPROTO_NONE:
			/* All processing is done. Count as "delivered". */
			freemsg(hada_mp);
			freemsg(first_mp);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
			return;
		}
		whereptr += used;
		ASSERT(remlen >= used);
		remlen -= used;
	}
	/* NOTREACHED */

pkt_too_short:
	ip1dbg(("ip_rput_data_v6: packet too short %d %lu %d\n",
	    ip6_len, pkt_len, remlen));
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
	freemsg(hada_mp);
	freemsg(first_mp);
	return;
udp_fanout:
	if (mctl_present || IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
		connp = NULL;
	} else {
		connp = ipcl_classify_v6(mp, IPPROTO_UDP, hdr_len, zoneid,
		    ipst);
		if ((connp != NULL) && (connp->conn_upq == NULL)) {
			CONN_DEC_REF(connp);
			connp = NULL;
		}
	}

	if (connp == NULL) {
		uint32_t	ports;

		ports = *(uint32_t *)(mp->b_rptr + hdr_len +
		    UDP_PORTS_OFFSET);
		IP6_STAT(ipst, ip6_udp_slow_path);
		ip_fanout_udp_v6(q, first_mp, ip6h, ports, ill, inill,
		    (flags|IP_FF_SEND_ICMP|IP_FF_IPINFO), mctl_present,
		    zoneid);
		return;
	}

	if (CONN_UDP_FLOWCTLD(connp)) {
		freemsg(first_mp);
		BUMP_MIB(ill->ill_ip_mib, udpIfStatsInOverflows);
		CONN_DEC_REF(connp);
		return;
	}

	/* Initiate IPPF processing */
	if (IP6_IN_IPP(flags, ipst)) {
		ip_process(IPP_LOCAL_IN, &mp, ill->ill_phyint->phyint_ifindex);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			return;
		}
	}

	if (connp->conn_ip_recvpktinfo ||
	    IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src)) {
		mp = ip_add_info_v6(mp, inill, &ip6h->ip6_dst);
		if (mp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			CONN_DEC_REF(connp);
			return;
		}
	}

	IP6_STAT(ipst, ip6_udp_fast_path);
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);

	/* Send it upstream */
	(connp->conn_recv)(connp, mp, NULL);

	CONN_DEC_REF(connp);
	freemsg(hada_mp);
	return;

hada_drop:
	ip1dbg(("ip_rput_data_v6: malformed accelerated packet\n"));
	/* IPsec kstats: bump counter here */
	freemsg(hada_mp);
	freemsg(first_mp);
}

/*
 * Reassemble fragment.
 * When it returns a completed message the first mblk will only contain
 * the headers prior to the fragment header.
 *
 * prev_nexthdr_offset is an offset indication of where the nexthdr field is
 * of the preceding header.  This is needed to patch the previous header's
 * nexthdr field when reassembly completes.
 */
static mblk_t *
ip_rput_frag_v6(queue_t *q, mblk_t *mp, ip6_t *ip6h,
    ip6_frag_t *fraghdr, uint_t remlen, uint_t *prev_nexthdr_offset,
    uint32_t *cksum_val, uint16_t *cksum_flags)
{
	ill_t		*ill = (ill_t *)q->q_ptr;
	uint32_t	ident = ntohl(fraghdr->ip6f_ident);
	uint16_t	offset;
	boolean_t	more_frags;
	uint8_t		nexthdr = fraghdr->ip6f_nxt;
	in6_addr_t	*v6dst_ptr;
	in6_addr_t	*v6src_ptr;
	uint_t		end;
	uint_t		hdr_length;
	size_t		count;
	ipf_t		*ipf;
	ipf_t		**ipfp;
	ipfb_t		*ipfb;
	mblk_t		*mp1;
	uint8_t		ecn_info = 0;
	size_t		msg_len;
	mblk_t		*tail_mp;
	mblk_t		*t_mp;
	boolean_t	pruned = B_FALSE;
	uint32_t	sum_val;
	uint16_t	sum_flags;
	ip_stack_t	*ipst = ill->ill_ipst;

	if (cksum_val != NULL)
		*cksum_val = 0;
	if (cksum_flags != NULL)
		*cksum_flags = 0;

	/*
	 * We utilize hardware computed checksum info only for UDP since
	 * IP fragmentation is a normal occurence for the protocol.  In
	 * addition, checksum offload support for IP fragments carrying
	 * UDP payload is commonly implemented across network adapters.
	 */
	ASSERT(ill != NULL);
	if (nexthdr == IPPROTO_UDP && dohwcksum && ILL_HCKSUM_CAPABLE(ill) &&
	    (DB_CKSUMFLAGS(mp) & (HCK_FULLCKSUM | HCK_PARTIALCKSUM))) {
		mblk_t *mp1 = mp->b_cont;
		int32_t len;

		/* Record checksum information from the packet */
		sum_val = (uint32_t)DB_CKSUM16(mp);
		sum_flags = DB_CKSUMFLAGS(mp);

		/* fragmented payload offset from beginning of mblk */
		offset = (uint16_t)((uchar_t *)&fraghdr[1] - mp->b_rptr);

		if ((sum_flags & HCK_PARTIALCKSUM) &&
		    (mp1 == NULL || mp1->b_cont == NULL) &&
		    offset >= (uint16_t)DB_CKSUMSTART(mp) &&
		    ((len = offset - (uint16_t)DB_CKSUMSTART(mp)) & 1) == 0) {
			uint32_t adj;
			/*
			 * Partial checksum has been calculated by hardware
			 * and attached to the packet; in addition, any
			 * prepended extraneous data is even byte aligned.
			 * If any such data exists, we adjust the checksum;
			 * this would also handle any postpended data.
			 */
			IP_ADJCKSUM_PARTIAL(mp->b_rptr + DB_CKSUMSTART(mp),
			    mp, mp1, len, adj);

			/* One's complement subtract extraneous checksum */
			if (adj >= sum_val)
				sum_val = ~(adj - sum_val) & 0xFFFF;
			else
				sum_val -= adj;
		}
	} else {
		sum_val = 0;
		sum_flags = 0;
	}

	/* Clear hardware checksumming flag */
	DB_CKSUMFLAGS(mp) = 0;

	/*
	 * Note: Fragment offset in header is in 8-octet units.
	 * Clearing least significant 3 bits not only extracts
	 * it but also gets it in units of octets.
	 */
	offset = ntohs(fraghdr->ip6f_offlg) & ~7;
	more_frags = (fraghdr->ip6f_offlg & IP6F_MORE_FRAG);

	/*
	 * Is the more frags flag on and the payload length not a multiple
	 * of eight?
	 */
	if (more_frags && (ntohs(ip6h->ip6_plen) & 7)) {
		zoneid_t zoneid;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		zoneid = ipif_lookup_addr_zoneid_v6(&ip6h->ip6_dst, ill, ipst);
		if (zoneid == ALL_ZONES) {
			freemsg(mp);
			return (NULL);
		}
		icmp_param_problem_v6(WR(q), mp, ICMP6_PARAMPROB_HEADER,
		    (uint32_t)((char *)&ip6h->ip6_plen -
		    (char *)ip6h), B_FALSE, B_FALSE, zoneid, ipst);
		return (NULL);
	}

	v6src_ptr = &ip6h->ip6_src;
	v6dst_ptr = &ip6h->ip6_dst;
	end = remlen;

	hdr_length = (uint_t)((char *)&fraghdr[1] - (char *)ip6h);
	end += offset;

	/*
	 * Would fragment cause reassembled packet to have a payload length
	 * greater than IP_MAXPACKET - the max payload size?
	 */
	if (end > IP_MAXPACKET) {
		zoneid_t	zoneid;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		zoneid = ipif_lookup_addr_zoneid_v6(&ip6h->ip6_dst, ill, ipst);
		if (zoneid == ALL_ZONES) {
			freemsg(mp);
			return (NULL);
		}
		icmp_param_problem_v6(WR(q), mp, ICMP6_PARAMPROB_HEADER,
		    (uint32_t)((char *)&fraghdr->ip6f_offlg -
		    (char *)ip6h), B_FALSE, B_FALSE, zoneid, ipst);
		return (NULL);
	}

	/*
	 * This packet just has one fragment. Reassembly not
	 * needed.
	 */
	if (!more_frags && offset == 0) {
		goto reass_done;
	}

	/*
	 * Drop the fragmented as early as possible, if
	 * we don't have resource(s) to re-assemble.
	 */
	if (ipst->ips_ip_reass_queue_bytes == 0) {
		freemsg(mp);
		return (NULL);
	}

	/* Record the ECN field info. */
	ecn_info = (uint8_t)(ntohl(ip6h->ip6_vcf & htonl(~0xFFCFFFFF)) >> 20);
	/*
	 * If this is not the first fragment, dump the unfragmentable
	 * portion of the packet.
	 */
	if (offset)
		mp->b_rptr = (uchar_t *)&fraghdr[1];

	/*
	 * Fragmentation reassembly.  Each ILL has a hash table for
	 * queueing packets undergoing reassembly for all IPIFs
	 * associated with the ILL.  The hash is based on the packet
	 * IP ident field.  The ILL frag hash table was allocated
	 * as a timer block at the time the ILL was created.  Whenever
	 * there is anything on the reassembly queue, the timer will
	 * be running.
	 */
	msg_len = MBLKSIZE(mp);
	tail_mp = mp;
	while (tail_mp->b_cont != NULL) {
		tail_mp = tail_mp->b_cont;
		msg_len += MBLKSIZE(tail_mp);
	}
	/*
	 * If the reassembly list for this ILL will get too big
	 * prune it.
	 */

	if ((msg_len + sizeof (*ipf) + ill->ill_frag_count) >=
	    ipst->ips_ip_reass_queue_bytes) {
		ill_frag_prune(ill,
		    (ipst->ips_ip_reass_queue_bytes < msg_len) ? 0 :
		    (ipst->ips_ip_reass_queue_bytes - msg_len));
		pruned = B_TRUE;
	}

	ipfb = &ill->ill_frag_hash_tbl[ILL_FRAG_HASH_V6(*v6src_ptr, ident)];
	mutex_enter(&ipfb->ipfb_lock);

	ipfp = &ipfb->ipfb_ipf;
	/* Try to find an existing fragment queue for this packet. */
	for (;;) {
		ipf = ipfp[0];
		if (ipf) {
			/*
			 * It has to match on ident, source address, and
			 * dest address.
			 */
			if (ipf->ipf_ident == ident &&
			    IN6_ARE_ADDR_EQUAL(&ipf->ipf_v6src, v6src_ptr) &&
			    IN6_ARE_ADDR_EQUAL(&ipf->ipf_v6dst, v6dst_ptr)) {

				/*
				 * If we have received too many
				 * duplicate fragments for this packet
				 * free it.
				 */
				if (ipf->ipf_num_dups > ip_max_frag_dups) {
					ill_frag_free_pkts(ill, ipfb, ipf, 1);
					freemsg(mp);
					mutex_exit(&ipfb->ipfb_lock);
					return (NULL);
				}

				break;
			}
			ipfp = &ipf->ipf_hash_next;
			continue;
		}


		/*
		 * If we pruned the list, do we want to store this new
		 * fragment?. We apply an optimization here based on the
		 * fact that most fragments will be received in order.
		 * So if the offset of this incoming fragment is zero,
		 * it is the first fragment of a new packet. We will
		 * keep it.  Otherwise drop the fragment, as we have
		 * probably pruned the packet already (since the
		 * packet cannot be found).
		 */

		if (pruned && offset != 0) {
			mutex_exit(&ipfb->ipfb_lock);
			freemsg(mp);
			return (NULL);
		}

		/* New guy.  Allocate a frag message. */
		mp1 = allocb(sizeof (*ipf), BPRI_MED);
		if (!mp1) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			freemsg(mp);
	partial_reass_done:
			mutex_exit(&ipfb->ipfb_lock);
			return (NULL);
		}

		if (ipfb->ipfb_frag_pkts >= MAX_FRAG_PKTS(ipst))  {
			/*
			 * Too many fragmented packets in this hash bucket.
			 * Free the oldest.
			 */
			ill_frag_free_pkts(ill, ipfb, ipfb->ipfb_ipf, 1);
		}

		mp1->b_cont = mp;

		/* Initialize the fragment header. */
		ipf = (ipf_t *)mp1->b_rptr;
		ipf->ipf_mp = mp1;
		ipf->ipf_ptphn = ipfp;
		ipfp[0] = ipf;
		ipf->ipf_hash_next = NULL;
		ipf->ipf_ident = ident;
		ipf->ipf_v6src = *v6src_ptr;
		ipf->ipf_v6dst = *v6dst_ptr;
		/* Record reassembly start time. */
		ipf->ipf_timestamp = gethrestime_sec();
		/* Record ipf generation and account for frag header */
		ipf->ipf_gen = ill->ill_ipf_gen++;
		ipf->ipf_count = MBLKSIZE(mp1);
		ipf->ipf_protocol = nexthdr;
		ipf->ipf_nf_hdr_len = 0;
		ipf->ipf_prev_nexthdr_offset = 0;
		ipf->ipf_last_frag_seen = B_FALSE;
		ipf->ipf_ecn = ecn_info;
		ipf->ipf_num_dups = 0;
		ipfb->ipfb_frag_pkts++;
		ipf->ipf_checksum = 0;
		ipf->ipf_checksum_flags = 0;

		/* Store checksum value in fragment header */
		if (sum_flags != 0) {
			sum_val = (sum_val & 0xFFFF) + (sum_val >> 16);
			sum_val = (sum_val & 0xFFFF) + (sum_val >> 16);
			ipf->ipf_checksum = sum_val;
			ipf->ipf_checksum_flags = sum_flags;
		}

		/*
		 * We handle reassembly two ways.  In the easy case,
		 * where all the fragments show up in order, we do
		 * minimal bookkeeping, and just clip new pieces on
		 * the end.  If we ever see a hole, then we go off
		 * to ip_reassemble which has to mark the pieces and
		 * keep track of the number of holes, etc.  Obviously,
		 * the point of having both mechanisms is so we can
		 * handle the easy case as efficiently as possible.
		 */
		if (offset == 0) {
			/* Easy case, in-order reassembly so far. */
			/* Update the byte count */
			ipf->ipf_count += msg_len;
			ipf->ipf_tail_mp = tail_mp;
			/*
			 * Keep track of next expected offset in
			 * ipf_end.
			 */
			ipf->ipf_end = end;
			ipf->ipf_nf_hdr_len = hdr_length;
			ipf->ipf_prev_nexthdr_offset = *prev_nexthdr_offset;
		} else {
			/* Hard case, hole at the beginning. */
			ipf->ipf_tail_mp = NULL;
			/*
			 * ipf_end == 0 means that we have given up
			 * on easy reassembly.
			 */
			ipf->ipf_end = 0;

			/* Forget checksum offload from now on */
			ipf->ipf_checksum_flags = 0;

			/*
			 * ipf_hole_cnt is set by ip_reassemble.
			 * ipf_count is updated by ip_reassemble.
			 * No need to check for return value here
			 * as we don't expect reassembly to complete or
			 * fail for the first fragment itself.
			 */
			(void) ip_reassemble(mp, ipf, offset, more_frags, ill,
			    msg_len);
		}
		/* Update per ipfb and ill byte counts */
		ipfb->ipfb_count += ipf->ipf_count;
		ASSERT(ipfb->ipfb_count > 0);	/* Wraparound */
		atomic_add_32(&ill->ill_frag_count, ipf->ipf_count);
		/* If the frag timer wasn't already going, start it. */
		mutex_enter(&ill->ill_lock);
		ill_frag_timer_start(ill);
		mutex_exit(&ill->ill_lock);
		goto partial_reass_done;
	}

	/*
	 * If the packet's flag has changed (it could be coming up
	 * from an interface different than the previous, therefore
	 * possibly different checksum capability), then forget about
	 * any stored checksum states.  Otherwise add the value to
	 * the existing one stored in the fragment header.
	 */
	if (sum_flags != 0 && sum_flags == ipf->ipf_checksum_flags) {
		sum_val += ipf->ipf_checksum;
		sum_val = (sum_val & 0xFFFF) + (sum_val >> 16);
		sum_val = (sum_val & 0xFFFF) + (sum_val >> 16);
		ipf->ipf_checksum = sum_val;
	} else if (ipf->ipf_checksum_flags != 0) {
		/* Forget checksum offload from now on */
		ipf->ipf_checksum_flags = 0;
	}

	/*
	 * We have a new piece of a datagram which is already being
	 * reassembled.  Update the ECN info if all IP fragments
	 * are ECN capable.  If there is one which is not, clear
	 * all the info.  If there is at least one which has CE
	 * code point, IP needs to report that up to transport.
	 */
	if (ecn_info != IPH_ECN_NECT && ipf->ipf_ecn != IPH_ECN_NECT) {
		if (ecn_info == IPH_ECN_CE)
			ipf->ipf_ecn = IPH_ECN_CE;
	} else {
		ipf->ipf_ecn = IPH_ECN_NECT;
	}

	if (offset && ipf->ipf_end == offset) {
		/* The new fragment fits at the end */
		ipf->ipf_tail_mp->b_cont = mp;
		/* Update the byte count */
		ipf->ipf_count += msg_len;
		/* Update per ipfb and ill byte counts */
		ipfb->ipfb_count += msg_len;
		ASSERT(ipfb->ipfb_count > 0);	/* Wraparound */
		atomic_add_32(&ill->ill_frag_count, msg_len);
		if (more_frags) {
			/* More to come. */
			ipf->ipf_end = end;
			ipf->ipf_tail_mp = tail_mp;
			goto partial_reass_done;
		}
	} else {
		/*
		 * Go do the hard cases.
		 * Call ip_reassemble().
		 */
		int ret;

		if (offset == 0) {
			if (ipf->ipf_prev_nexthdr_offset == 0) {
				ipf->ipf_nf_hdr_len = hdr_length;
				ipf->ipf_prev_nexthdr_offset =
				    *prev_nexthdr_offset;
			}
		}
		/* Save current byte count */
		count = ipf->ipf_count;
		ret = ip_reassemble(mp, ipf, offset, more_frags, ill, msg_len);

		/* Count of bytes added and subtracted (freeb()ed) */
		count = ipf->ipf_count - count;
		if (count) {
			/* Update per ipfb and ill byte counts */
			ipfb->ipfb_count += count;
			ASSERT(ipfb->ipfb_count > 0);	/* Wraparound */
			atomic_add_32(&ill->ill_frag_count, count);
		}
		if (ret == IP_REASS_PARTIAL) {
			goto partial_reass_done;
		} else if (ret == IP_REASS_FAILED) {
			/* Reassembly failed. Free up all resources */
			ill_frag_free_pkts(ill, ipfb, ipf, 1);
			for (t_mp = mp; t_mp != NULL; t_mp = t_mp->b_cont) {
				IP_REASS_SET_START(t_mp, 0);
				IP_REASS_SET_END(t_mp, 0);
			}
			freemsg(mp);
			goto partial_reass_done;
		}

		/* We will reach here iff 'ret' is IP_REASS_COMPLETE */
	}
	/*
	 * We have completed reassembly.  Unhook the frag header from
	 * the reassembly list.
	 *
	 * Grab the unfragmentable header length next header value out
	 * of the first fragment
	 */
	ASSERT(ipf->ipf_nf_hdr_len != 0);
	hdr_length = ipf->ipf_nf_hdr_len;

	/*
	 * Before we free the frag header, record the ECN info
	 * to report back to the transport.
	 */
	ecn_info = ipf->ipf_ecn;

	/*
	 * Store the nextheader field in the header preceding the fragment
	 * header
	 */
	nexthdr = ipf->ipf_protocol;
	*prev_nexthdr_offset = ipf->ipf_prev_nexthdr_offset;
	ipfp = ipf->ipf_ptphn;

	/* We need to supply these to caller */
	if ((sum_flags = ipf->ipf_checksum_flags) != 0)
		sum_val = ipf->ipf_checksum;
	else
		sum_val = 0;

	mp1 = ipf->ipf_mp;
	count = ipf->ipf_count;
	ipf = ipf->ipf_hash_next;
	if (ipf)
		ipf->ipf_ptphn = ipfp;
	ipfp[0] = ipf;
	atomic_add_32(&ill->ill_frag_count, -count);
	ASSERT(ipfb->ipfb_count >= count);
	ipfb->ipfb_count -= count;
	ipfb->ipfb_frag_pkts--;
	mutex_exit(&ipfb->ipfb_lock);
	/* Ditch the frag header. */
	mp = mp1->b_cont;
	freeb(mp1);

	/*
	 * Make sure the packet is good by doing some sanity
	 * check. If bad we can silentely drop the packet.
	 */
reass_done:
	if (hdr_length < sizeof (ip6_frag_t)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		ip1dbg(("ip_rput_frag_v6: bad packet\n"));
		freemsg(mp);
		return (NULL);
	}

	/*
	 * Remove the fragment header from the initial header by
	 * splitting the mblk into the non-fragmentable header and
	 * everthing after the fragment extension header.  This has the
	 * side effect of putting all the headers that need destination
	 * processing into the b_cont block-- on return this fact is
	 * used in order to avoid having to look at the extensions
	 * already processed.
	 *
	 * Note that this code assumes that the unfragmentable portion
	 * of the header is in the first mblk and increments
	 * the read pointer past it.  If this assumption is broken
	 * this code fails badly.
	 */
	if (mp->b_rptr + hdr_length != mp->b_wptr) {
		mblk_t *nmp;

		if (!(nmp = dupb(mp))) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip1dbg(("ip_rput_frag_v6: dupb failed\n"));
			freemsg(mp);
			return (NULL);
		}
		nmp->b_cont = mp->b_cont;
		mp->b_cont = nmp;
		nmp->b_rptr += hdr_length;
	}
	mp->b_wptr = mp->b_rptr + hdr_length - sizeof (ip6_frag_t);

	ip6h = (ip6_t *)mp->b_rptr;
	((char *)ip6h)[*prev_nexthdr_offset] = nexthdr;

	/* Restore original IP length in header. */
	ip6h->ip6_plen = htons((uint16_t)(msgdsize(mp) - IPV6_HDR_LEN));
	/* Record the ECN info. */
	ip6h->ip6_vcf &= htonl(0xFFCFFFFF);
	ip6h->ip6_vcf |= htonl(ecn_info << 20);

	/* Reassembly is successful; return checksum information if needed */
	if (cksum_val != NULL)
		*cksum_val = sum_val;
	if (cksum_flags != NULL)
		*cksum_flags = sum_flags;

	return (mp);
}

/*
 * Walk through the options to see if there is a routing header.
 * If present get the destination which is the last address of
 * the option.
 */
in6_addr_t
ip_get_dst_v6(ip6_t *ip6h, boolean_t *is_fragment)
{
	uint8_t nexthdr;
	uint8_t *whereptr;
	ip6_hbh_t *hbhhdr;
	ip6_dest_t *dsthdr;
	ip6_rthdr0_t *rthdr;
	ip6_frag_t *fraghdr;
	int ehdrlen;
	int left;
	in6_addr_t *ap, rv;

	if (is_fragment != NULL)
		*is_fragment = B_FALSE;

	rv = ip6h->ip6_dst;

	nexthdr = ip6h->ip6_nxt;
	whereptr = (uint8_t *)&ip6h[1];
	for (;;) {

		ASSERT(nexthdr != IPPROTO_RAW);
		switch (nexthdr) {
		case IPPROTO_HOPOPTS:
			hbhhdr = (ip6_hbh_t *)whereptr;
			nexthdr = hbhhdr->ip6h_nxt;
			ehdrlen = 8 * (hbhhdr->ip6h_len + 1);
			break;
		case IPPROTO_DSTOPTS:
			dsthdr = (ip6_dest_t *)whereptr;
			nexthdr = dsthdr->ip6d_nxt;
			ehdrlen = 8 * (dsthdr->ip6d_len + 1);
			break;
		case IPPROTO_ROUTING:
			rthdr = (ip6_rthdr0_t *)whereptr;
			nexthdr = rthdr->ip6r0_nxt;
			ehdrlen = 8 * (rthdr->ip6r0_len + 1);

			left = rthdr->ip6r0_segleft;
			ap = (in6_addr_t *)((char *)rthdr + sizeof (*rthdr));
			rv = *(ap + left - 1);
			/*
			 * If the caller doesn't care whether the packet
			 * is a fragment or not, we can stop here since
			 * we have our destination.
			 */
			if (is_fragment == NULL)
				goto done;
			break;
		case IPPROTO_FRAGMENT:
			fraghdr = (ip6_frag_t *)whereptr;
			nexthdr = fraghdr->ip6f_nxt;
			ehdrlen = sizeof (ip6_frag_t);
			if (is_fragment != NULL)
				*is_fragment = B_TRUE;
			goto done;
		default :
			goto done;
		}
		whereptr += ehdrlen;
	}

done:
	return (rv);
}

/*
 * ip_source_routed_v6:
 * This function is called by redirect code in ip_rput_data_v6 to
 * know whether this packet is source routed through this node i.e
 * whether this node (router) is part of the journey. This
 * function is called under two cases :
 *
 * case 1 : Routing header was processed by this node and
 *	    ip_process_rthdr replaced ip6_dst with the next hop
 *          and we are forwarding the packet to the next hop.
 *
 * case 2 : Routing header was not processed by this node and we
 *	    are just forwarding the packet.
 *
 * For case (1) we don't want to send redirects. For case(2) we
 * want to send redirects.
 */
static boolean_t
ip_source_routed_v6(ip6_t *ip6h, mblk_t *mp, ip_stack_t *ipst)
{
	uint8_t		nexthdr;
	in6_addr_t	*addrptr;
	ip6_rthdr0_t	*rthdr;
	uint8_t		numaddr;
	ip6_hbh_t	*hbhhdr;
	uint_t		ehdrlen;
	uint8_t		*byteptr;

	ip2dbg(("ip_source_routed_v6\n"));
	nexthdr = ip6h->ip6_nxt;
	ehdrlen = IPV6_HDR_LEN;

	/* if a routing hdr is preceeded by HOPOPT or DSTOPT */
	while (nexthdr == IPPROTO_HOPOPTS ||
	    nexthdr == IPPROTO_DSTOPTS) {
		byteptr = (uint8_t *)ip6h + ehdrlen;
		/*
		 * Check if we have already processed
		 * packets or we are just a forwarding
		 * router which only pulled up msgs up
		 * to IPV6HDR and  one HBH ext header
		 */
		if (byteptr + MIN_EHDR_LEN > mp->b_wptr) {
			ip2dbg(("ip_source_routed_v6: Extension"
			    " headers not processed\n"));
			return (B_FALSE);
		}
		hbhhdr = (ip6_hbh_t *)byteptr;
		nexthdr = hbhhdr->ip6h_nxt;
		ehdrlen = ehdrlen + 8 * (hbhhdr->ip6h_len + 1);
	}
	switch (nexthdr) {
	case IPPROTO_ROUTING:
		byteptr = (uint8_t *)ip6h + ehdrlen;
		/*
		 * If for some reason, we haven't pulled up
		 * the routing hdr data mblk, then we must
		 * not have processed it at all. So for sure
		 * we are not part of the source routed journey.
		 */
		if (byteptr + MIN_EHDR_LEN > mp->b_wptr) {
			ip2dbg(("ip_source_routed_v6: Routing"
			    " header not processed\n"));
			return (B_FALSE);
		}
		rthdr = (ip6_rthdr0_t *)byteptr;
		/*
		 * Either we are an intermediate router or the
		 * last hop before destination and we have
		 * already processed the routing header.
		 * If segment_left is greater than or equal to zero,
		 * then we must be the (numaddr - segleft) entry
		 * of the routing header. Although ip6r0_segleft
		 * is a unit8_t variable, we still check for zero
		 * or greater value, if in case the data type
		 * is changed someday in future.
		 */
		if (rthdr->ip6r0_segleft > 0 ||
		    rthdr->ip6r0_segleft == 0) {
			ire_t 	*ire = NULL;

			numaddr = rthdr->ip6r0_len / 2;
			addrptr = (in6_addr_t *)((char *)rthdr +
			    sizeof (*rthdr));
			addrptr += (numaddr - (rthdr->ip6r0_segleft + 1));
			if (addrptr != NULL) {
				ire = ire_ctable_lookup_v6(addrptr, NULL,
				    IRE_LOCAL, NULL, ALL_ZONES, NULL,
				    MATCH_IRE_TYPE,
				    ipst);
				if (ire != NULL) {
					ire_refrele(ire);
					return (B_TRUE);
				}
				ip1dbg(("ip_source_routed_v6: No ire found\n"));
			}
		}
	/* FALLTHRU */
	default:
		ip2dbg(("ip_source_routed_v6: Not source routed here\n"));
		return (B_FALSE);
	}
}

/*
 * ip_wput_v6 -- Packets sent down from transport modules show up here.
 * Assumes that the following set of headers appear in the first
 * mblk:
 *	ip6i_t (if present) CAN also appear as a separate mblk.
 *	ip6_t
 *	Any extension headers
 *	TCP/UDP/SCTP header (if present)
 * The routine can handle an ICMPv6 header that is not in the first mblk.
 *
 * The order to determine the outgoing interface is as follows:
 * 1. IPV6_BOUND_PIF is set, use that ill (conn_outgoing_pill)
 * 2. If conn_nofailover_ill is set then use that ill.
 * 3. If an ip6i_t with IP6I_IFINDEX set then use that ill.
 * 4. If q is an ill queue and (link local or multicast destination) then
 *    use that ill.
 * 5. If IPV6_BOUND_IF has been set use that ill.
 * 6. For multicast: if IPV6_MULTICAST_IF has been set use it. Otherwise
 *    look for the best IRE match for the unspecified group to determine
 *    the ill.
 * 7. For unicast: Just do an IRE lookup for the best match.
 *
 * arg2 is always a queue_t *.
 * When that queue is an ill_t (i.e. q_next != NULL), then arg must be
 * the zoneid.
 * When that queue is not an ill_t, then arg must be a conn_t pointer.
 */
void
ip_output_v6(void *arg, mblk_t *mp, void *arg2, int caller)
{
	conn_t		*connp = NULL;
	queue_t		*q = (queue_t *)arg2;
	ire_t		*ire = NULL;
	ire_t		*sctp_ire = NULL;
	ip6_t		*ip6h;
	in6_addr_t	*v6dstp;
	ill_t		*ill = NULL;
	ipif_t		*ipif;
	ip6i_t		*ip6i;
	int		cksum_request;	/* -1 => normal. */
			/* 1 => Skip TCP/UDP/SCTP checksum */
			/* Otherwise contains insert offset for checksum */
	int		unspec_src;
	boolean_t	do_outrequests;	/* Increment OutRequests? */
	mib2_ipIfStatsEntry_t	*mibptr;
	int 		match_flags = MATCH_IRE_ILL_GROUP;
	boolean_t	attach_if = B_FALSE;
	mblk_t		*first_mp;
	boolean_t	mctl_present;
	ipsec_out_t	*io;
	boolean_t	drop_if_delayed = B_FALSE;
	boolean_t	multirt_need_resolve = B_FALSE;
	mblk_t		*copy_mp = NULL;
	int		err = 0;
	int		ip6i_flags = 0;
	zoneid_t	zoneid;
	ill_t		*saved_ill = NULL;
	boolean_t	conn_lock_held;
	boolean_t	need_decref = B_FALSE;
	ip_stack_t	*ipst;

	if (q->q_next != NULL) {
		ill = (ill_t *)q->q_ptr;
		ipst = ill->ill_ipst;
	} else {
		connp = (conn_t *)arg;
		ASSERT(connp != NULL);
		ipst = connp->conn_netstack->netstack_ip;
	}

	/*
	 * Highest bit in version field is Reachability Confirmation bit
	 * used by NUD in ip_xmit_v6().
	 */
#ifdef	_BIG_ENDIAN
#define	IPVER(ip6h)	((((uint32_t *)ip6h)[0] >> 28) & 0x7)
#else
#define	IPVER(ip6h)	((((uint32_t *)ip6h)[0] >> 4) & 0x7)
#endif

	/*
	 * M_CTL comes from 6 places
	 *
	 * 1) TCP sends down IPSEC_OUT(M_CTL) for detached connections
	 *    both V4 and V6 datagrams.
	 *
	 * 2) AH/ESP sends down M_CTL after doing their job with both
	 *    V4 and V6 datagrams.
	 *
	 * 3) NDP callbacks when nce is resolved and IPSEC_OUT has been
	 *    attached.
	 *
	 * 4) Notifications from an external resolver (for XRESOLV ifs)
	 *
	 * 5) AH/ESP send down IPSEC_CTL(M_CTL) to be relayed to hardware for
	 *    IPsec hardware acceleration support.
	 *
	 * 6) TUN_HELLO.
	 *
	 * We need to handle (1)'s IPv6 case and (3) here.  For the
	 * IPv4 case in (1), and (2), IPSEC processing has already
	 * started. The code in ip_wput() already knows how to handle
	 * continuing IPSEC processing (for IPv4 and IPv6).  All other
	 * M_CTLs (including case (4)) are passed on to ip_wput_nondata()
	 * for handling.
	 */
	first_mp = mp;
	mctl_present = B_FALSE;
	io = NULL;

	/* Multidata transmit? */
	if (DB_TYPE(mp) == M_MULTIDATA) {
		/*
		 * We should never get here, since all Multidata messages
		 * originating from tcp should have been directed over to
		 * tcp_multisend() in the first place.
		 */
		BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutDiscards);
		freemsg(mp);
		return;
	} else if (DB_TYPE(mp) == M_CTL) {
		uint32_t mctltype = 0;
		uint32_t mlen = MBLKL(first_mp);

		mp = mp->b_cont;
		mctl_present = B_TRUE;
		io = (ipsec_out_t *)first_mp->b_rptr;

		/*
		 * Validate this M_CTL message.  The only three types of
		 * M_CTL messages we expect to see in this code path are
		 * ipsec_out_t or ipsec_in_t structures (allocated as
		 * ipsec_info_t unions), or ipsec_ctl_t structures.
		 * The ipsec_out_type and ipsec_in_type overlap in the two
		 * data structures, and they are either set to IPSEC_OUT
		 * or IPSEC_IN depending on which data structure it is.
		 * ipsec_ctl_t is an IPSEC_CTL.
		 *
		 * All other M_CTL messages are sent to ip_wput_nondata()
		 * for handling.
		 */
		if (mlen >= sizeof (io->ipsec_out_type))
			mctltype = io->ipsec_out_type;

		if ((mlen == sizeof (ipsec_ctl_t)) &&
		    (mctltype == IPSEC_CTL)) {
			ip_output(arg, first_mp, arg2, caller);
			return;
		}

		if ((mlen < sizeof (ipsec_info_t)) ||
		    (mctltype != IPSEC_OUT && mctltype != IPSEC_IN) ||
		    mp == NULL) {
			ip_wput_nondata(NULL, q, first_mp, NULL);
			return;
		}
		/* NDP callbacks have q_next non-NULL.  That's case #3. */
		if (q->q_next == NULL) {
			ip6h = (ip6_t *)mp->b_rptr;
			/*
			 * For a freshly-generated TCP dgram that needs IPV6
			 * processing, don't call ip_wput immediately. We can
			 * tell this by the ipsec_out_proc_begin. In-progress
			 * IPSEC_OUT messages have proc_begin set to TRUE,
			 * and we want to send all IPSEC_IN messages to
			 * ip_wput() for IPsec processing or finishing.
			 */
			if (mctltype == IPSEC_IN ||
			    IPVER(ip6h) != IPV6_VERSION ||
			    io->ipsec_out_proc_begin) {
				mibptr = &ipst->ips_ip6_mib;
				goto notv6;
			}
		}
	} else if (DB_TYPE(mp) != M_DATA) {
		ip_wput_nondata(NULL, q, mp, NULL);
		return;
	}

	ip6h = (ip6_t *)mp->b_rptr;

	if (IPVER(ip6h) != IPV6_VERSION) {
		mibptr = &ipst->ips_ip6_mib;
		goto notv6;
	}

	if (is_system_labeled() && DB_TYPE(mp) == M_DATA &&
	    (connp == NULL || !connp->conn_ulp_labeled)) {
		if (connp != NULL) {
			ASSERT(CONN_CRED(connp) != NULL);
			err = tsol_check_label_v6(BEST_CRED(mp, connp),
			    &mp, connp->conn_mac_exempt, ipst);
		} else if (DB_CRED(mp) != NULL) {
			err = tsol_check_label_v6(DB_CRED(mp),
			    &mp, B_FALSE, ipst);
		}
		if (mctl_present)
			first_mp->b_cont = mp;
		else
			first_mp = mp;
		if (err != 0) {
			DTRACE_PROBE3(
			    tsol_ip_log_drop_checklabel_ip6, char *,
			    "conn(1), failed to check/update mp(2)",
			    conn_t, connp, mblk_t, mp);
			freemsg(first_mp);
			return;
		}
		ip6h = (ip6_t *)mp->b_rptr;
	}
	if (q->q_next != NULL) {
		/*
		 * We don't know if this ill will be used for IPv6
		 * until the ILLF_IPV6 flag is set via SIOCSLIFNAME.
		 * ipif_set_values() sets the ill_isv6 flag to true if
		 * ILLF_IPV6 is set.  If the ill_isv6 flag isn't true,
		 * just drop the packet.
		 */
		if (!ill->ill_isv6) {
			ip1dbg(("ip_wput_v6: Received an IPv6 packet before "
			    "ILLF_IPV6 was set\n"));
			freemsg(first_mp);
			return;
		}
		/* For uniformity do a refhold */
		mutex_enter(&ill->ill_lock);
		if (!ILL_CAN_LOOKUP(ill)) {
			mutex_exit(&ill->ill_lock);
			freemsg(first_mp);
			return;
		}
		ill_refhold_locked(ill);
		mutex_exit(&ill->ill_lock);
		mibptr = ill->ill_ip_mib;

		ASSERT(mibptr != NULL);
		unspec_src = 0;
		BUMP_MIB(mibptr, ipIfStatsHCOutRequests);
		do_outrequests = B_FALSE;
		zoneid = (zoneid_t)(uintptr_t)arg;
	} else {
		ASSERT(connp != NULL);
		zoneid = connp->conn_zoneid;

		/* is queue flow controlled? */
		if ((q->q_first || connp->conn_draining) &&
		    (caller == IP_WPUT)) {
			/*
			 * 1) TCP sends down M_CTL for detached connections.
			 * 2) AH/ESP sends down M_CTL.
			 *
			 * We don't flow control either of the above. Only
			 * UDP and others are flow controlled for which we
			 * can't have a M_CTL.
			 */
			ASSERT(first_mp == mp);
			(void) putq(q, mp);
			return;
		}
		mibptr = &ipst->ips_ip6_mib;
		unspec_src = connp->conn_unspec_src;
		do_outrequests = B_TRUE;
		if (mp->b_flag & MSGHASREF) {
			mp->b_flag &= ~MSGHASREF;
			ASSERT(connp->conn_ulp == IPPROTO_SCTP);
			SCTP_EXTRACT_IPINFO(mp, sctp_ire);
			need_decref = B_TRUE;
		}

		/*
		 * If there is a policy, try to attach an ipsec_out in
		 * the front. At the end, first_mp either points to a
		 * M_DATA message or IPSEC_OUT message linked to a
		 * M_DATA message. We have to do it now as we might
		 * lose the "conn" if we go through ip_newroute.
		 */
		if (!mctl_present &&
		    (connp->conn_out_enforce_policy ||
		    connp->conn_latch != NULL)) {
			ASSERT(first_mp == mp);
			/* XXX Any better way to get the protocol fast ? */
			if (((mp = ipsec_attach_ipsec_out(&mp, connp, NULL,
			    connp->conn_ulp, ipst->ips_netstack)) == NULL)) {
				BUMP_MIB(mibptr, ipIfStatsOutDiscards);
				if (need_decref)
					CONN_DEC_REF(connp);
				return;
			} else {
				ASSERT(mp->b_datap->db_type == M_CTL);
				first_mp = mp;
				mp = mp->b_cont;
				mctl_present = B_TRUE;
				io = (ipsec_out_t *)first_mp->b_rptr;
			}
		}
	}

	/* check for alignment and full IPv6 header */
	if (!OK_32PTR((uchar_t *)ip6h) ||
	    (mp->b_wptr - (uchar_t *)ip6h) < IPV6_HDR_LEN) {
		ip0dbg(("ip_wput_v6: bad alignment or length\n"));
		if (do_outrequests)
			BUMP_MIB(mibptr, ipIfStatsHCOutRequests);
		BUMP_MIB(mibptr, ipIfStatsOutDiscards);
		freemsg(first_mp);
		if (ill != NULL)
			ill_refrele(ill);
		if (need_decref)
			CONN_DEC_REF(connp);
		return;
	}
	v6dstp = &ip6h->ip6_dst;
	cksum_request = -1;
	ip6i = NULL;

	/*
	 * Once neighbor discovery has completed, ndp_process() will provide
	 * locally generated packets for which processing can be reattempted.
	 * In these cases, connp is NULL and the original zone is part of a
	 * prepended ipsec_out_t.
	 */
	if (io != NULL) {
		/*
		 * When coming from icmp_input_v6, the zoneid might not match
		 * for the loopback case, because inside icmp_input_v6 the
		 * queue_t is a conn queue from the sending side.
		 */
		zoneid = io->ipsec_out_zoneid;
		ASSERT(zoneid != ALL_ZONES);
	}

	if (ip6h->ip6_nxt == IPPROTO_RAW) {
		/*
		 * This is an ip6i_t header followed by an ip6_hdr.
		 * Check which fields are set.
		 *
		 * When the packet comes from a transport we should have
		 * all needed headers in the first mblk. However, when
		 * going through ip_newroute*_v6 the ip6i might be in
		 * a separate mblk when we return here. In that case
		 * we pullup everything to ensure that extension and transport
		 * headers "stay" in the first mblk.
		 */
		ip6i = (ip6i_t *)ip6h;
		ip6i_flags = ip6i->ip6i_flags;

		ASSERT((mp->b_wptr - (uchar_t *)ip6i) == sizeof (ip6i_t) ||
		    ((mp->b_wptr - (uchar_t *)ip6i) >=
		    sizeof (ip6i_t) + IPV6_HDR_LEN));

		if ((mp->b_wptr - (uchar_t *)ip6i) == sizeof (ip6i_t)) {
			if (!pullupmsg(mp, -1)) {
				ip1dbg(("ip_wput_v6: pullupmsg failed\n"));
				if (do_outrequests) {
					BUMP_MIB(mibptr,
					    ipIfStatsHCOutRequests);
				}
				BUMP_MIB(mibptr, ipIfStatsOutDiscards);
				freemsg(first_mp);
				if (ill != NULL)
					ill_refrele(ill);
				if (need_decref)
					CONN_DEC_REF(connp);
				return;
			}
			ip6h = (ip6_t *)mp->b_rptr;
			v6dstp = &ip6h->ip6_dst;
			ip6i = (ip6i_t *)ip6h;
		}
		ip6h = (ip6_t *)&ip6i[1];

		/*
		 * Advance rptr past the ip6i_t to get ready for
		 * transmitting the packet. However, if the packet gets
		 * passed to ip_newroute*_v6 then rptr is moved back so
		 * that the ip6i_t header can be inspected when the
		 * packet comes back here after passing through
		 * ire_add_then_send.
		 */
		mp->b_rptr = (uchar_t *)ip6h;

		/*
		 * IP6I_ATTACH_IF is set in this function when we had a
		 * conn and it was either bound to the IPFF_NOFAILOVER address
		 * or IPV6_BOUND_PIF was set. These options override other
		 * options that set the ifindex. We come here with
		 * IP6I_ATTACH_IF set when we can't find the ire and
		 * ip_newroute_v6 is feeding the packet for second time.
		 */
		if ((ip6i->ip6i_flags & IP6I_IFINDEX) ||
		    (ip6i->ip6i_flags & IP6I_ATTACH_IF)) {
			ASSERT(ip6i->ip6i_ifindex != 0);
			if (ill != NULL)
				ill_refrele(ill);
			ill = ill_lookup_on_ifindex(ip6i->ip6i_ifindex, 1,
			    NULL, NULL, NULL, NULL, ipst);
			if (ill == NULL) {
				if (do_outrequests) {
					BUMP_MIB(mibptr,
					    ipIfStatsHCOutRequests);
				}
				BUMP_MIB(mibptr, ipIfStatsOutDiscards);
				ip1dbg(("ip_wput_v6: bad ifindex %d\n",
				    ip6i->ip6i_ifindex));
				if (need_decref)
					CONN_DEC_REF(connp);
				freemsg(first_mp);
				return;
			}
			mibptr = ill->ill_ip_mib;
			if (ip6i->ip6i_flags & IP6I_IFINDEX) {
				/*
				 * Preserve the index so that when we return
				 * from IPSEC processing, we know where to
				 * send the packet.
				 */
				if (mctl_present) {
					ASSERT(io != NULL);
					io->ipsec_out_ill_index =
					    ip6i->ip6i_ifindex;
				}
			}
			if (ip6i->ip6i_flags & IP6I_ATTACH_IF) {
				/*
				 * This is a multipathing probe packet that has
				 * been delayed in ND resolution. Drop the
				 * packet for the reasons mentioned in
				 * nce_queue_mp()
				 */
				if ((ip6i->ip6i_flags & IP6I_DROP_IFDELAYED) &&
				    (ip6i->ip6i_flags & IP6I_ND_DELAYED)) {
					freemsg(first_mp);
					ill_refrele(ill);
					if (need_decref)
						CONN_DEC_REF(connp);
					return;
				}
			}
		}
		if (ip6i->ip6i_flags & IP6I_VERIFY_SRC) {
			cred_t *cr = DB_CREDDEF(mp, GET_QUEUE_CRED(q));

			ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src));
			if (secpolicy_net_rawaccess(cr) != 0) {
				/*
				 * Use IPCL_ZONEID to honor SO_ALLZONES.
				 */
				ire = ire_route_lookup_v6(&ip6h->ip6_src,
				    0, 0, (IRE_LOCAL|IRE_LOOPBACK), NULL,
				    NULL, connp != NULL ?
				    IPCL_ZONEID(connp) : zoneid, NULL,
				    MATCH_IRE_TYPE | MATCH_IRE_ZONEONLY, ipst);
				if (ire == NULL) {
					if (do_outrequests)
						BUMP_MIB(mibptr,
						    ipIfStatsHCOutRequests);
					BUMP_MIB(mibptr, ipIfStatsOutDiscards);
					ip1dbg(("ip_wput_v6: bad source "
					    "addr\n"));
					freemsg(first_mp);
					if (ill != NULL)
						ill_refrele(ill);
					if (need_decref)
						CONN_DEC_REF(connp);
					return;
				}
				ire_refrele(ire);
			}
			/* No need to verify again when using ip_newroute */
			ip6i->ip6i_flags &= ~IP6I_VERIFY_SRC;
		}
		if (!(ip6i->ip6i_flags & IP6I_NEXTHOP)) {
			/*
			 * Make sure they match since ip_newroute*_v6 etc might
			 * (unknown to them) inspect ip6i_nexthop when
			 * they think they access ip6_dst.
			 */
			ip6i->ip6i_nexthop = ip6h->ip6_dst;
		}
		if (ip6i->ip6i_flags & IP6I_NO_ULP_CKSUM)
			cksum_request = 1;
		if (ip6i->ip6i_flags & IP6I_RAW_CHECKSUM)
			cksum_request = ip6i->ip6i_checksum_off;
		if (ip6i->ip6i_flags & IP6I_UNSPEC_SRC)
			unspec_src = 1;

		if (do_outrequests && ill != NULL) {
			BUMP_MIB(mibptr, ipIfStatsHCOutRequests);
			do_outrequests = B_FALSE;
		}
		/*
		 * Store ip6i_t info that we need after we come back
		 * from IPSEC processing.
		 */
		if (mctl_present) {
			ASSERT(io != NULL);
			io->ipsec_out_unspec_src = unspec_src;
		}
	}
	if (connp != NULL && connp->conn_dontroute)
		ip6h->ip6_hops = 1;

	if (IN6_IS_ADDR_MULTICAST(v6dstp))
		goto ipv6multicast;

	/* 1. IPV6_BOUND_PIF takes precedence over all the ifindex settings. */
	if (connp != NULL && connp->conn_outgoing_pill != NULL) {
		ill_t	*conn_outgoing_pill;

		conn_outgoing_pill = conn_get_held_ill(connp,
		    &connp->conn_outgoing_pill, &err);
		if (err == ILL_LOOKUP_FAILED) {
			if (ill != NULL)
				ill_refrele(ill);
			if (need_decref)
				CONN_DEC_REF(connp);
			freemsg(first_mp);
			return;
		}
		if (conn_outgoing_pill != NULL) {
			if (ill != NULL)
				ill_refrele(ill);
			ill = conn_outgoing_pill;
			attach_if = B_TRUE;
			match_flags = MATCH_IRE_ILL;
			mibptr = ill->ill_ip_mib;

			/*
			 * Check if we need an ire that will not be
			 * looked up by anybody else i.e. HIDDEN.
			 */
			if (ill_is_probeonly(ill))
				match_flags |= MATCH_IRE_MARK_HIDDEN;
			goto send_from_ill;
		}
	}

	/* 2. If ipc_nofailover_ill is set then use that ill. */
	if (connp != NULL && connp->conn_nofailover_ill != NULL) {
		ill_t	*conn_nofailover_ill;

		conn_nofailover_ill = conn_get_held_ill(connp,
		    &connp->conn_nofailover_ill, &err);
		if (err == ILL_LOOKUP_FAILED) {
			if (ill != NULL)
				ill_refrele(ill);
			if (need_decref)
				CONN_DEC_REF(connp);
			freemsg(first_mp);
			return;
		}
		if (conn_nofailover_ill != NULL) {
			if (ill != NULL)
				ill_refrele(ill);
			ill = conn_nofailover_ill;
			attach_if = B_TRUE;
			/*
			 * Assumes that ipc_nofailover_ill is used only for
			 * multipathing probe packets. These packets are better
			 * dropped, if they are delayed in ND resolution, for
			 * the reasons described in nce_queue_mp().
			 * IP6I_DROP_IFDELAYED will be set later on in this
			 * function for this packet.
			 */
			drop_if_delayed = B_TRUE;
			match_flags = MATCH_IRE_ILL;
			mibptr = ill->ill_ip_mib;

			/*
			 * Check if we need an ire that will not be
			 * looked up by anybody else i.e. HIDDEN.
			 */
			if (ill_is_probeonly(ill))
				match_flags |= MATCH_IRE_MARK_HIDDEN;
			goto send_from_ill;
		}
	}

	/*
	 * Redo 1. If we did not find an IRE_CACHE the first time, we should
	 * have an ip6i_t with IP6I_ATTACH_IF if IPV6_BOUND_PIF or
	 * bind to the IPIF_NOFAILOVER address was used on this endpoint.
	 */
	if (ip6i != NULL && (ip6i->ip6i_flags & IP6I_ATTACH_IF)) {
		ASSERT(ip6i->ip6i_ifindex != 0);
		attach_if = B_TRUE;
		ASSERT(ill != NULL);
		match_flags = MATCH_IRE_ILL;

		/*
		 * Check if we need an ire that will not be
		 * looked up by anybody else i.e. HIDDEN.
		 */
		if (ill_is_probeonly(ill))
			match_flags |= MATCH_IRE_MARK_HIDDEN;
		goto send_from_ill;
	}

	/* 3. If an ip6i_t with IP6I_IFINDEX set then use that ill. */
	if (ip6i != NULL && (ip6i->ip6i_flags & IP6I_IFINDEX)) {
		ASSERT(ill != NULL);
		goto send_from_ill;
	}

	/*
	 * 4. If q is an ill queue and (link local or multicast destination)
	 *    then use that ill.
	 */
	if (ill != NULL && IN6_IS_ADDR_LINKLOCAL(v6dstp)) {
		goto send_from_ill;
	}

	/* 5. If IPV6_BOUND_IF has been set use that ill. */
	if (connp != NULL && connp->conn_outgoing_ill != NULL) {
		ill_t	*conn_outgoing_ill;

		conn_outgoing_ill = conn_get_held_ill(connp,
		    &connp->conn_outgoing_ill, &err);
		if (err == ILL_LOOKUP_FAILED) {
			if (ill != NULL)
				ill_refrele(ill);
			if (need_decref)
				CONN_DEC_REF(connp);
			freemsg(first_mp);
			return;
		}
		if (ill != NULL)
			ill_refrele(ill);
		ill = conn_outgoing_ill;
		mibptr = ill->ill_ip_mib;
		goto send_from_ill;
	}

	/*
	 * 6. For unicast: Just do an IRE lookup for the best match.
	 * If we get here for a link-local address it is rather random
	 * what interface we pick on a multihomed host.
	 * *If* there is an IRE_CACHE (and the link-local address
	 * isn't duplicated on multi links) this will find the IRE_CACHE.
	 * Otherwise it will use one of the matching IRE_INTERFACE routes
	 * for the link-local prefix. Hence, applications
	 * *should* be encouraged to specify an outgoing interface when sending
	 * to a link local address.
	 */
	if (connp == NULL || (IP_FLOW_CONTROLLED_ULP(connp->conn_ulp) &&
	    !connp->conn_fully_bound)) {
		/*
		 * We cache IRE_CACHEs to avoid lookups. We don't do
		 * this for the tcp global queue and listen end point
		 * as it does not really have a real destination to
		 * talk to.
		 */
		ire = ire_cache_lookup_v6(v6dstp, zoneid, MBLK_GETLABEL(mp),
		    ipst);
	} else {
		/*
		 * IRE_MARK_CONDEMNED is marked in ire_delete. We don't
		 * grab a lock here to check for CONDEMNED as it is okay
		 * to send a packet or two with the IRE_CACHE that is going
		 * away.
		 */
		mutex_enter(&connp->conn_lock);
		ire = sctp_ire != NULL ? sctp_ire : connp->conn_ire_cache;
		if (ire != NULL &&
		    IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6, v6dstp) &&
		    !(ire->ire_marks & IRE_MARK_CONDEMNED)) {

			IRE_REFHOLD(ire);
			mutex_exit(&connp->conn_lock);

		} else {
			boolean_t cached = B_FALSE;

			connp->conn_ire_cache = NULL;
			mutex_exit(&connp->conn_lock);
			/* Release the old ire */
			if (ire != NULL && sctp_ire == NULL)
				IRE_REFRELE_NOTR(ire);

			ire = ire_cache_lookup_v6(v6dstp, zoneid,
			    MBLK_GETLABEL(mp), ipst);
			if (ire != NULL) {
				IRE_REFHOLD_NOTR(ire);

				mutex_enter(&connp->conn_lock);
				if (CONN_CACHE_IRE(connp) &&
				    (connp->conn_ire_cache == NULL)) {
					rw_enter(&ire->ire_bucket->irb_lock,
					    RW_READER);
					if (!(ire->ire_marks &
					    IRE_MARK_CONDEMNED)) {
						connp->conn_ire_cache = ire;
						cached = B_TRUE;
					}
					rw_exit(&ire->ire_bucket->irb_lock);
				}
				mutex_exit(&connp->conn_lock);

				/*
				 * We can continue to use the ire but since it
				 * was not cached, we should drop the extra
				 * reference.
				 */
				if (!cached)
					IRE_REFRELE_NOTR(ire);
			}
		}
	}

	if (ire != NULL) {
		if (do_outrequests) {
			/* Handle IRE_LOCAL's that might appear here */
			if (ire->ire_type == IRE_CACHE) {
				mibptr = ((ill_t *)ire->ire_stq->q_ptr)->
				    ill_ip_mib;
			} else {
				mibptr = ire->ire_ipif->ipif_ill->ill_ip_mib;
			}
			BUMP_MIB(mibptr, ipIfStatsHCOutRequests);
		}
		ASSERT(!attach_if);

		/*
		 * Check if the ire has the RTF_MULTIRT flag, inherited
		 * from an IRE_OFFSUBNET ire entry in ip_newroute().
		 */
		if (ire->ire_flags & RTF_MULTIRT) {
			/*
			 * Force hop limit of multirouted packets if required.
			 * The hop limit of such packets is bounded by the
			 * ip_multirt_ttl ndd variable.
			 * NDP packets must have a hop limit of 255; don't
			 * change the hop limit in that case.
			 */
			if ((ipst->ips_ip_multirt_ttl > 0) &&
			    (ip6h->ip6_hops > ipst->ips_ip_multirt_ttl) &&
			    (ip6h->ip6_hops != IPV6_MAX_HOPS)) {
				if (ip_debug > 3) {
					ip2dbg(("ip_wput_v6: forcing multirt "
					    "hop limit to %d (was %d) ",
					    ipst->ips_ip_multirt_ttl,
					    ip6h->ip6_hops));
					pr_addr_dbg("v6dst %s\n", AF_INET6,
					    &ire->ire_addr_v6);
				}
				ip6h->ip6_hops = ipst->ips_ip_multirt_ttl;
			}

			/*
			 * We look at this point if there are pending
			 * unresolved routes. ire_multirt_need_resolve_v6()
			 * checks in O(n) that all IRE_OFFSUBNET ire
			 * entries for the packet's destination and
			 * flagged RTF_MULTIRT are currently resolved.
			 * If some remain unresolved, we do a copy
			 * of the current message. It will be used
			 * to initiate additional route resolutions.
			 */
			multirt_need_resolve =
			    ire_multirt_need_resolve_v6(&ire->ire_addr_v6,
			    MBLK_GETLABEL(first_mp), ipst);
			ip2dbg(("ip_wput_v6: ire %p, "
			    "multirt_need_resolve %d, first_mp %p\n",
			    (void *)ire, multirt_need_resolve,
			    (void *)first_mp));
			if (multirt_need_resolve) {
				copy_mp = copymsg(first_mp);
				if (copy_mp != NULL) {
					MULTIRT_DEBUG_TAG(copy_mp);
				}
			}
		}
		ip_wput_ire_v6(q, first_mp, ire, unspec_src, cksum_request,
		    connp, caller, 0, ip6i_flags, zoneid);
		if (need_decref) {
			CONN_DEC_REF(connp);
			connp = NULL;
		}
		IRE_REFRELE(ire);

		/*
		 * Try to resolve another multiroute if
		 * ire_multirt_need_resolve_v6() deemed it necessary.
		 * copy_mp will be consumed (sent or freed) by
		 * ip_newroute_v6().
		 */
		if (copy_mp != NULL) {
			if (mctl_present) {
				ip6h = (ip6_t *)copy_mp->b_cont->b_rptr;
			} else {
				ip6h = (ip6_t *)copy_mp->b_rptr;
			}
			ip_newroute_v6(q, copy_mp, &ip6h->ip6_dst,
			    &ip6h->ip6_src, NULL, zoneid, ipst);
		}
		if (ill != NULL)
			ill_refrele(ill);
		return;
	}

	/*
	 * No full IRE for this destination.  Send it to
	 * ip_newroute_v6 to see if anything else matches.
	 * Mark this packet as having originated on this
	 * machine.
	 * Update rptr if there was an ip6i_t header.
	 */
	mp->b_prev = NULL;
	mp->b_next = NULL;
	if (ip6i != NULL)
		mp->b_rptr -= sizeof (ip6i_t);

	if (unspec_src) {
		if (ip6i == NULL) {
			/*
			 * Add ip6i_t header to carry unspec_src
			 * until the packet comes back in ip_wput_v6.
			 */
			mp = ip_add_info_v6(mp, NULL, v6dstp);
			if (mp == NULL) {
				if (do_outrequests)
					BUMP_MIB(mibptr,
					    ipIfStatsHCOutRequests);
				BUMP_MIB(mibptr, ipIfStatsOutDiscards);
				if (mctl_present)
					freeb(first_mp);
				if (ill != NULL)
					ill_refrele(ill);
				if (need_decref)
					CONN_DEC_REF(connp);
				return;
			}
			ip6i = (ip6i_t *)mp->b_rptr;

			if (mctl_present) {
				ASSERT(first_mp != mp);
				first_mp->b_cont = mp;
			} else {
				first_mp = mp;
			}

			if ((mp->b_wptr - (uchar_t *)ip6i) ==
			    sizeof (ip6i_t)) {
				/*
				 * ndp_resolver called from ip_newroute_v6
				 * expects pulled up message.
				 */
				if (!pullupmsg(mp, -1)) {
					ip1dbg(("ip_wput_v6: pullupmsg"
					    " failed\n"));
					if (do_outrequests) {
						BUMP_MIB(mibptr,
						    ipIfStatsHCOutRequests);
					}
					BUMP_MIB(mibptr, ipIfStatsOutDiscards);
					freemsg(first_mp);
					if (ill != NULL)
						ill_refrele(ill);
					if (need_decref)
						CONN_DEC_REF(connp);
					return;
				}
				ip6i = (ip6i_t *)mp->b_rptr;
			}
			ip6h = (ip6_t *)&ip6i[1];
			v6dstp = &ip6h->ip6_dst;
		}
		ip6i->ip6i_flags |= IP6I_UNSPEC_SRC;
		if (mctl_present) {
			ASSERT(io != NULL);
			io->ipsec_out_unspec_src = unspec_src;
		}
	}
	if (do_outrequests)
		BUMP_MIB(mibptr, ipIfStatsHCOutRequests);
	if (need_decref)
		CONN_DEC_REF(connp);
	ip_newroute_v6(q, first_mp, v6dstp, &ip6h->ip6_src, NULL, zoneid, ipst);
	if (ill != NULL)
		ill_refrele(ill);
	return;


	/*
	 * Handle multicast packets with or without an conn.
	 * Assumes that the transports set ip6_hops taking
	 * IPV6_MULTICAST_HOPS (and the other ways to set the hoplimit)
	 * into account.
	 */
ipv6multicast:
	ip2dbg(("ip_wput_v6: multicast\n"));

	/*
	 * 1. IPV6_BOUND_PIF takes precedence over all the ifindex settings
	 * 2. If conn_nofailover_ill is set then use that ill.
	 *
	 * Hold the conn_lock till we refhold the ill of interest that is
	 * pointed to from the conn. Since we cannot do an ill/ipif_refrele
	 * while holding any locks, postpone the refrele until after the
	 * conn_lock is dropped.
	 */
	if (connp != NULL) {
		mutex_enter(&connp->conn_lock);
		conn_lock_held = B_TRUE;
	} else {
		conn_lock_held = B_FALSE;
	}
	if (connp != NULL && connp->conn_outgoing_pill != NULL) {
		err = ill_check_and_refhold(connp->conn_outgoing_pill);
		if (err == ILL_LOOKUP_FAILED) {
			ip1dbg(("ip_output_v6: multicast"
			    " conn_outgoing_pill no ipif\n"));
multicast_discard:
			ASSERT(saved_ill == NULL);
			if (conn_lock_held)
				mutex_exit(&connp->conn_lock);
			if (ill != NULL)
				ill_refrele(ill);
			freemsg(first_mp);
			if (do_outrequests)
				BUMP_MIB(mibptr, ipIfStatsOutDiscards);
			if (need_decref)
				CONN_DEC_REF(connp);
			return;
		}
		saved_ill = ill;
		ill = connp->conn_outgoing_pill;
		attach_if = B_TRUE;
		match_flags = MATCH_IRE_ILL;
		mibptr = ill->ill_ip_mib;

		/*
		 * Check if we need an ire that will not be
		 * looked up by anybody else i.e. HIDDEN.
		 */
		if (ill_is_probeonly(ill))
			match_flags |= MATCH_IRE_MARK_HIDDEN;
	} else if (connp != NULL && connp->conn_nofailover_ill != NULL) {
		err = ill_check_and_refhold(connp->conn_nofailover_ill);
		if (err == ILL_LOOKUP_FAILED) {
			ip1dbg(("ip_output_v6: multicast"
			    " conn_nofailover_ill no ipif\n"));
			goto multicast_discard;
		}
		saved_ill = ill;
		ill = connp->conn_nofailover_ill;
		attach_if = B_TRUE;
		match_flags = MATCH_IRE_ILL;

		/*
		 * Check if we need an ire that will not be
		 * looked up by anybody else i.e. HIDDEN.
		 */
		if (ill_is_probeonly(ill))
			match_flags |= MATCH_IRE_MARK_HIDDEN;
	} else if (ip6i != NULL && (ip6i->ip6i_flags & IP6I_ATTACH_IF)) {
		/*
		 * Redo 1. If we did not find an IRE_CACHE the first time,
		 * we should have an ip6i_t with IP6I_ATTACH_IF if
		 * IPV6_BOUND_PIF or bind to the IPIF_NOFAILOVER address was
		 * used on this endpoint.
		 */
		ASSERT(ip6i->ip6i_ifindex != 0);
		attach_if = B_TRUE;
		ASSERT(ill != NULL);
		match_flags = MATCH_IRE_ILL;

		/*
		 * Check if we need an ire that will not be
		 * looked up by anybody else i.e. HIDDEN.
		 */
		if (ill_is_probeonly(ill))
			match_flags |= MATCH_IRE_MARK_HIDDEN;
	} else if (ip6i != NULL && (ip6i->ip6i_flags & IP6I_IFINDEX)) {
		/* 3. If an ip6i_t with IP6I_IFINDEX set then use that ill. */

		ASSERT(ill != NULL);
	} else if (ill != NULL) {
		/*
		 * 4. If q is an ill queue and (link local or multicast
		 * destination) then use that ill.
		 * We don't need the ipif initialization here.
		 * This useless assert below is just to prevent lint from
		 * reporting a null body if statement.
		 */
		ASSERT(ill != NULL);
	} else if (connp != NULL) {
		/*
		 * 5. If IPV6_BOUND_IF has been set use that ill.
		 *
		 * 6. For multicast: if IPV6_MULTICAST_IF has been set use it.
		 * Otherwise look for the best IRE match for the unspecified
		 * group to determine the ill.
		 *
		 * conn_multicast_ill is used for only IPv6 packets.
		 * conn_multicast_ipif is used for only IPv4 packets.
		 * Thus a PF_INET6 socket send both IPv4 and IPv6
		 * multicast packets using different IP*_MULTICAST_IF
		 * interfaces.
		 */
		if (connp->conn_outgoing_ill != NULL) {
			err = ill_check_and_refhold(connp->conn_outgoing_ill);
			if (err == ILL_LOOKUP_FAILED) {
				ip1dbg(("ip_output_v6: multicast"
				    " conn_outgoing_ill no ipif\n"));
				goto multicast_discard;
			}
			ill = connp->conn_outgoing_ill;
		} else if (connp->conn_multicast_ill != NULL) {
			err = ill_check_and_refhold(connp->conn_multicast_ill);
			if (err == ILL_LOOKUP_FAILED) {
				ip1dbg(("ip_output_v6: multicast"
				    " conn_multicast_ill no ipif\n"));
				goto multicast_discard;
			}
			ill = connp->conn_multicast_ill;
		} else {
			mutex_exit(&connp->conn_lock);
			conn_lock_held = B_FALSE;
			ipif = ipif_lookup_group_v6(v6dstp, zoneid, ipst);
			if (ipif == NULL) {
				ip1dbg(("ip_output_v6: multicast no ipif\n"));
				goto multicast_discard;
			}
			/*
			 * We have a ref to this ipif, so we can safely
			 * access ipif_ill.
			 */
			ill = ipif->ipif_ill;
			mutex_enter(&ill->ill_lock);
			if (!ILL_CAN_LOOKUP(ill)) {
				mutex_exit(&ill->ill_lock);
				ipif_refrele(ipif);
				ill = NULL;
				ip1dbg(("ip_output_v6: multicast no ipif\n"));
				goto multicast_discard;
			}
			ill_refhold_locked(ill);
			mutex_exit(&ill->ill_lock);
			ipif_refrele(ipif);
			/*
			 * Save binding until IPV6_MULTICAST_IF
			 * changes it
			 */
			mutex_enter(&connp->conn_lock);
			connp->conn_multicast_ill = ill;
			connp->conn_orig_multicast_ifindex =
			    ill->ill_phyint->phyint_ifindex;
			mutex_exit(&connp->conn_lock);
		}
	}
	if (conn_lock_held)
		mutex_exit(&connp->conn_lock);

	if (saved_ill != NULL)
		ill_refrele(saved_ill);

	ASSERT(ill != NULL);
	/*
	 * For multicast loopback interfaces replace the multicast address
	 * with a unicast address for the ire lookup.
	 */
	if (IS_LOOPBACK(ill))
		v6dstp = &ill->ill_ipif->ipif_v6lcl_addr;

	mibptr = ill->ill_ip_mib;
	if (do_outrequests) {
		BUMP_MIB(mibptr, ipIfStatsHCOutRequests);
		do_outrequests = B_FALSE;
	}
	BUMP_MIB(mibptr, ipIfStatsHCOutMcastPkts);
	UPDATE_MIB(mibptr, ipIfStatsHCOutMcastOctets,
	    ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN);

	/*
	 * As we may lose the conn by the time we reach ip_wput_ire_v6
	 * we copy conn_multicast_loop and conn_dontroute on to an
	 * ipsec_out. In case if this datagram goes out secure,
	 * we need the ill_index also. Copy that also into the
	 * ipsec_out.
	 */
	if (mctl_present) {
		io = (ipsec_out_t *)first_mp->b_rptr;
		ASSERT(first_mp->b_datap->db_type == M_CTL);
		ASSERT(io->ipsec_out_type == IPSEC_OUT);
	} else {
		ASSERT(mp == first_mp);
		if ((first_mp = ipsec_alloc_ipsec_out(ipst->ips_netstack)) ==
		    NULL) {
			BUMP_MIB(mibptr, ipIfStatsOutDiscards);
			freemsg(mp);
			if (ill != NULL)
				ill_refrele(ill);
			if (need_decref)
				CONN_DEC_REF(connp);
			return;
		}
		io = (ipsec_out_t *)first_mp->b_rptr;
		/* This is not a secure packet */
		io->ipsec_out_secure = B_FALSE;
		io->ipsec_out_use_global_policy = B_TRUE;
		io->ipsec_out_zoneid =
		    (zoneid != ALL_ZONES ? zoneid : GLOBAL_ZONEID);
		first_mp->b_cont = mp;
		mctl_present = B_TRUE;
	}
	io->ipsec_out_ill_index = ill->ill_phyint->phyint_ifindex;
	io->ipsec_out_unspec_src = unspec_src;
	if (connp != NULL)
		io->ipsec_out_dontroute = connp->conn_dontroute;

send_from_ill:
	ASSERT(ill != NULL);
	ASSERT(mibptr == ill->ill_ip_mib);
	if (do_outrequests) {
		BUMP_MIB(mibptr, ipIfStatsHCOutRequests);
		do_outrequests = B_FALSE;
	}

	if (io != NULL)
		io->ipsec_out_ill_index = ill->ill_phyint->phyint_ifindex;

	/*
	 * When a specific ill is specified (using IPV6_PKTINFO,
	 * IPV6_MULTICAST_IF, or IPV6_BOUND_IF) we will only match
	 * on routing entries (ftable and ctable) that have a matching
	 * ire->ire_ipif->ipif_ill. Thus this can only be used
	 * for destinations that are on-link for the specific ill
	 * and that can appear on multiple links. Thus it is useful
	 * for multicast destinations, link-local destinations, and
	 * at some point perhaps for site-local destinations (if the
	 * node sits at a site boundary).
	 * We create the cache entries in the regular ctable since
	 * it can not "confuse" things for other destinations.
	 * table.
	 *
	 * NOTE : conn_ire_cache is not used for caching ire_ctable_lookups.
	 *	  It is used only when ire_cache_lookup is used above.
	 */
	ire = ire_ctable_lookup_v6(v6dstp, 0, 0, ill->ill_ipif,
	    zoneid, MBLK_GETLABEL(mp), match_flags, ipst);
	if (ire != NULL) {
		/*
		 * Check if the ire has the RTF_MULTIRT flag, inherited
		 * from an IRE_OFFSUBNET ire entry in ip_newroute().
		 */
		if (ire->ire_flags & RTF_MULTIRT) {
			/*
			 * Force hop limit of multirouted packets if required.
			 * The hop limit of such packets is bounded by the
			 * ip_multirt_ttl ndd variable.
			 * NDP packets must have a hop limit of 255; don't
			 * change the hop limit in that case.
			 */
			if ((ipst->ips_ip_multirt_ttl > 0) &&
			    (ip6h->ip6_hops > ipst->ips_ip_multirt_ttl) &&
			    (ip6h->ip6_hops != IPV6_MAX_HOPS)) {
				if (ip_debug > 3) {
					ip2dbg(("ip_wput_v6: forcing multirt "
					    "hop limit to %d (was %d) ",
					    ipst->ips_ip_multirt_ttl,
					    ip6h->ip6_hops));
					pr_addr_dbg("v6dst %s\n", AF_INET6,
					    &ire->ire_addr_v6);
				}
				ip6h->ip6_hops = ipst->ips_ip_multirt_ttl;
			}

			/*
			 * We look at this point if there are pending
			 * unresolved routes. ire_multirt_need_resolve_v6()
			 * checks in O(n) that all IRE_OFFSUBNET ire
			 * entries for the packet's destination and
			 * flagged RTF_MULTIRT are currently resolved.
			 * If some remain unresolved, we make a copy
			 * of the current message. It will be used
			 * to initiate additional route resolutions.
			 */
			multirt_need_resolve =
			    ire_multirt_need_resolve_v6(&ire->ire_addr_v6,
			    MBLK_GETLABEL(first_mp), ipst);
			ip2dbg(("ip_wput_v6[send_from_ill]: ire %p, "
			    "multirt_need_resolve %d, first_mp %p\n",
			    (void *)ire, multirt_need_resolve,
			    (void *)first_mp));
			if (multirt_need_resolve) {
				copy_mp = copymsg(first_mp);
				if (copy_mp != NULL) {
					MULTIRT_DEBUG_TAG(copy_mp);
				}
			}
		}

		ip1dbg(("ip_wput_v6: send on %s, ire = %p, ill index = %d\n",
		    ill->ill_name, (void *)ire,
		    ill->ill_phyint->phyint_ifindex));
		ip_wput_ire_v6(q, first_mp, ire, unspec_src, cksum_request,
		    connp, caller,
		    (attach_if ? ill->ill_phyint->phyint_ifindex : 0),
		    ip6i_flags, zoneid);
		ire_refrele(ire);
		if (need_decref) {
			CONN_DEC_REF(connp);
			connp = NULL;
		}

		/*
		 * Try to resolve another multiroute if
		 * ire_multirt_need_resolve_v6() deemed it necessary.
		 * copy_mp will be consumed (sent or freed) by
		 * ip_newroute_[ipif_]v6().
		 */
		if (copy_mp != NULL) {
			if (mctl_present) {
				ip6h = (ip6_t *)copy_mp->b_cont->b_rptr;
			} else {
				ip6h = (ip6_t *)copy_mp->b_rptr;
			}
			if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
				ipif = ipif_lookup_group_v6(&ip6h->ip6_dst,
				    zoneid, ipst);
				if (ipif == NULL) {
					ip1dbg(("ip_wput_v6: No ipif for "
					    "multicast\n"));
					MULTIRT_DEBUG_UNTAG(copy_mp);
					freemsg(copy_mp);
					return;
				}
				ip_newroute_ipif_v6(q, copy_mp, ipif,
				    ip6h->ip6_dst, unspec_src, zoneid);
				ipif_refrele(ipif);
			} else {
				ip_newroute_v6(q, copy_mp, &ip6h->ip6_dst,
				    &ip6h->ip6_src, ill, zoneid, ipst);
			}
		}
		ill_refrele(ill);
		return;
	}
	if (need_decref) {
		CONN_DEC_REF(connp);
		connp = NULL;
	}

	/* Update rptr if there was an ip6i_t header. */
	if (ip6i != NULL)
		mp->b_rptr -= sizeof (ip6i_t);
	if (unspec_src || attach_if) {
		if (ip6i == NULL) {
			/*
			 * Add ip6i_t header to carry unspec_src
			 * or attach_if until the packet comes back in
			 * ip_wput_v6.
			 */
			if (mctl_present) {
				first_mp->b_cont =
				    ip_add_info_v6(mp, NULL, v6dstp);
				mp = first_mp->b_cont;
				if (mp == NULL)
					freeb(first_mp);
			} else {
				first_mp = mp = ip_add_info_v6(mp, NULL,
				    v6dstp);
			}
			if (mp == NULL) {
				BUMP_MIB(mibptr, ipIfStatsOutDiscards);
				ill_refrele(ill);
				return;
			}
			ip6i = (ip6i_t *)mp->b_rptr;
			if ((mp->b_wptr - (uchar_t *)ip6i) ==
			    sizeof (ip6i_t)) {
				/*
				 * ndp_resolver called from ip_newroute_v6
				 * expects a pulled up message.
				 */
				if (!pullupmsg(mp, -1)) {
					ip1dbg(("ip_wput_v6: pullupmsg"
					    " failed\n"));
					BUMP_MIB(mibptr, ipIfStatsOutDiscards);
					freemsg(first_mp);
					return;
				}
				ip6i = (ip6i_t *)mp->b_rptr;
			}
			ip6h = (ip6_t *)&ip6i[1];
			v6dstp = &ip6h->ip6_dst;
		}
		if (unspec_src)
			ip6i->ip6i_flags |= IP6I_UNSPEC_SRC;
		if (attach_if) {
			/*
			 * Bind to nofailover/BOUND_PIF overrides ifindex.
			 */
			ip6i->ip6i_flags |= IP6I_ATTACH_IF;
			ip6i->ip6i_flags &= ~IP6I_IFINDEX;
			ip6i->ip6i_ifindex = ill->ill_phyint->phyint_ifindex;
			if (drop_if_delayed) {
				/* This is a multipathing probe packet */
				ip6i->ip6i_flags |= IP6I_DROP_IFDELAYED;
			}
		}
		if (mctl_present) {
			ASSERT(io != NULL);
			io->ipsec_out_unspec_src = unspec_src;
		}
	}
	if (IN6_IS_ADDR_MULTICAST(v6dstp)) {
		ip_newroute_ipif_v6(q, first_mp, ill->ill_ipif, *v6dstp,
		    unspec_src, zoneid);
	} else {
		ip_newroute_v6(q, first_mp, v6dstp, &ip6h->ip6_src, ill,
		    zoneid, ipst);
	}
	ill_refrele(ill);
	return;

notv6:
	/* FIXME?: assume the caller calls the right version of ip_output? */
	if (q->q_next == NULL) {
		connp = Q_TO_CONN(q);

		/*
		 * We can change conn_send for all types of conn, even
		 * though only TCP uses it right now.
		 * FIXME: sctp could use conn_send but doesn't currently.
		 */
		ip_setpktversion(connp, B_FALSE, B_TRUE, ipst);
	}
	BUMP_MIB(mibptr, ipIfStatsOutWrongIPVersion);
	(void) ip_output(arg, first_mp, arg2, caller);
	if (ill != NULL)
		ill_refrele(ill);
}

/*
 * If this is a conn_t queue, then we pass in the conn. This includes the
 * zoneid.
 * Otherwise, this is a message for an ill_t queue,
 * in which case we use the global zoneid since those are all part of
 * the global zone.
 */
void
ip_wput_v6(queue_t *q, mblk_t *mp)
{
	if (CONN_Q(q))
		ip_output_v6(Q_TO_CONN(q), mp, q, IP_WPUT);
	else
		ip_output_v6(GLOBAL_ZONEID, mp, q, IP_WPUT);
}

static void
ipsec_out_attach_if(ipsec_out_t *io, int attach_index)
{
	ASSERT(io->ipsec_out_type == IPSEC_OUT);
	io->ipsec_out_attach_if = B_TRUE;
	io->ipsec_out_ill_index = attach_index;
}

/*
 * NULL send-to queue - packet is to be delivered locally.
 */
void
ip_wput_local_v6(queue_t *q, ill_t *ill, ip6_t *ip6h, mblk_t *first_mp,
    ire_t *ire, int fanout_flags)
{
	uint32_t	ports;
	mblk_t		*mp = first_mp, *first_mp1;
	boolean_t	mctl_present;
	uint8_t		nexthdr;
	uint16_t	hdr_length;
	ipsec_out_t	*io;
	mib2_ipIfStatsEntry_t	*mibptr;
	ilm_t		*ilm;
	uint_t	nexthdr_offset;
	ip_stack_t	*ipst = ill->ill_ipst;

	if (DB_TYPE(mp) == M_CTL) {
		io = (ipsec_out_t *)mp->b_rptr;
		if (!io->ipsec_out_secure) {
			mp = mp->b_cont;
			freeb(first_mp);
			first_mp = mp;
			mctl_present = B_FALSE;
		} else {
			mctl_present = B_TRUE;
			mp = first_mp->b_cont;
			ipsec_out_to_in(first_mp);
		}
	} else {
		mctl_present = B_FALSE;
	}

	/*
	 * Remove reachability confirmation bit from version field
	 * before passing the packet on to any firewall hooks or
	 * looping back the packet.
	 */
	if (ip6h->ip6_vcf & IP_FORWARD_PROG)
		ip6h->ip6_vcf &= ~IP_FORWARD_PROG;

	DTRACE_PROBE4(ip6__loopback__in__start,
	    ill_t *, ill, ill_t *, NULL,
	    ip6_t *, ip6h, mblk_t *, first_mp);

	FW_HOOKS6(ipst->ips_ip6_loopback_in_event,
	    ipst->ips_ipv6firewall_loopback_in,
	    ill, NULL, ip6h, first_mp, mp, 0, ipst);

	DTRACE_PROBE1(ip6__loopback__in__end, mblk_t *, first_mp);

	if (first_mp == NULL)
		return;

	DTRACE_IP7(receive, mblk_t *, first_mp, conn_t *, NULL, void_ip_t *,
	    ip6h, __dtrace_ipsr_ill_t *, ill, ipha_t *, NULL, ip6_t *, ip6h,
	    int, 1);

	nexthdr = ip6h->ip6_nxt;
	mibptr = ill->ill_ip_mib;

	/* Fastpath */
	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMPV6:
	case IPPROTO_SCTP:
		hdr_length = IPV6_HDR_LEN;
		nexthdr_offset = (uint_t)((uchar_t *)&ip6h->ip6_nxt -
		    (uchar_t *)ip6h);
		break;
	default: {
		uint8_t	*nexthdrp;

		if (!ip_hdr_length_nexthdr_v6(mp, ip6h,
		    &hdr_length, &nexthdrp)) {
			/* Malformed packet */
			BUMP_MIB(mibptr, ipIfStatsOutDiscards);
			freemsg(first_mp);
			return;
		}
		nexthdr = *nexthdrp;
		nexthdr_offset = nexthdrp - (uint8_t *)ip6h;
		break;
	}
	}

	UPDATE_OB_PKT_COUNT(ire);
	ire->ire_last_used_time = lbolt;

	switch (nexthdr) {
		case IPPROTO_TCP:
			if (DB_TYPE(mp) == M_DATA) {
				/*
				 * M_DATA mblk, so init mblk (chain) for
				 * no struio().
				 */
				mblk_t  *mp1 = mp;

				do {
					mp1->b_datap->db_struioflag = 0;
				} while ((mp1 = mp1->b_cont) != NULL);
			}
			ports = *(uint32_t *)(mp->b_rptr + hdr_length +
			    TCP_PORTS_OFFSET);
			ip_fanout_tcp_v6(q, first_mp, ip6h, ill, ill,
			    fanout_flags|IP_FF_SEND_ICMP|IP_FF_SYN_ADDIRE|
			    IP_FF_IPINFO|IP6_NO_IPPOLICY|IP_FF_LOOPBACK,
			    hdr_length, mctl_present, ire->ire_zoneid);
			return;

		case IPPROTO_UDP:
			ports = *(uint32_t *)(mp->b_rptr + hdr_length +
			    UDP_PORTS_OFFSET);
			ip_fanout_udp_v6(q, first_mp, ip6h, ports, ill, ill,
			    fanout_flags|IP_FF_SEND_ICMP|IP_FF_IPINFO|
			    IP6_NO_IPPOLICY, mctl_present, ire->ire_zoneid);
			return;

		case IPPROTO_SCTP:
		{
			ports = *(uint32_t *)(mp->b_rptr + hdr_length);
			ip_fanout_sctp(first_mp, ill, (ipha_t *)ip6h, ports,
			    fanout_flags|IP_FF_SEND_ICMP|IP_FF_IPINFO,
			    mctl_present, IP6_NO_IPPOLICY, ire->ire_zoneid);
			return;
		}
		case IPPROTO_ICMPV6: {
			icmp6_t *icmp6;

			/* check for full IPv6+ICMPv6 header */
			if ((mp->b_wptr - mp->b_rptr) <
			    (hdr_length + ICMP6_MINLEN)) {
				if (!pullupmsg(mp, hdr_length + ICMP6_MINLEN)) {
					ip1dbg(("ip_wput_v6: ICMP hdr pullupmsg"
					    " failed\n"));
					BUMP_MIB(mibptr, ipIfStatsOutDiscards);
					freemsg(first_mp);
					return;
				}
				ip6h = (ip6_t *)mp->b_rptr;
			}
			icmp6 = (icmp6_t *)((uchar_t *)ip6h + hdr_length);

			/* Update output mib stats */
			icmp_update_out_mib_v6(ill, icmp6);

			/* Check variable for testing applications */
			if (ipst->ips_ipv6_drop_inbound_icmpv6) {
				freemsg(first_mp);
				return;
			}
			/*
			 * Assume that there is always at least one conn for
			 * ICMPv6 (in.ndpd) i.e. don't optimize the case
			 * where there is no conn.
			 */
			if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst) &&
			    !IS_LOOPBACK(ill)) {
				/*
				 * In the multicast case, applications may have
				 * joined the group from different zones, so we
				 * need to deliver the packet to each of them.
				 * Loop through the multicast memberships
				 * structures (ilm) on the receive ill and send
				 * a copy of the packet up each matching one.
				 * However, we don't do this for multicasts sent
				 * on the loopback interface (PHYI_LOOPBACK flag
				 * set) as they must stay in the sender's zone.
				 */
				ILM_WALKER_HOLD(ill);
				for (ilm = ill->ill_ilm; ilm != NULL;
				    ilm = ilm->ilm_next) {
					if (ilm->ilm_flags & ILM_DELETED)
						continue;
					if (!IN6_ARE_ADDR_EQUAL(
					    &ilm->ilm_v6addr, &ip6h->ip6_dst))
						continue;
					if ((fanout_flags &
					    IP_FF_NO_MCAST_LOOP) &&
					    ilm->ilm_zoneid == ire->ire_zoneid)
						continue;
					if (!ipif_lookup_zoneid(ill,
					    ilm->ilm_zoneid, IPIF_UP, NULL))
						continue;

					first_mp1 = ip_copymsg(first_mp);
					if (first_mp1 == NULL)
						continue;
					icmp_inbound_v6(q, first_mp1, ill,
					    hdr_length, mctl_present,
					    IP6_NO_IPPOLICY, ilm->ilm_zoneid,
					    NULL);
				}
				ILM_WALKER_RELE(ill);
			} else {
				first_mp1 = ip_copymsg(first_mp);
				if (first_mp1 != NULL)
					icmp_inbound_v6(q, first_mp1, ill,
					    hdr_length, mctl_present,
					    IP6_NO_IPPOLICY, ire->ire_zoneid,
					    NULL);
			}
		}
		/* FALLTHRU */
		default: {
			/*
			 * Handle protocols with which IPv6 is less intimate.
			 */
			fanout_flags |= IP_FF_RAWIP|IP_FF_IPINFO;

			/*
			 * Enable sending ICMP for "Unknown" nexthdr
			 * case. i.e. where we did not FALLTHRU from
			 * IPPROTO_ICMPV6 processing case above.
			 */
			if (nexthdr != IPPROTO_ICMPV6)
				fanout_flags |= IP_FF_SEND_ICMP;
			/*
			 * Note: There can be more than one stream bound
			 * to a particular protocol. When this is the case,
			 * each one gets a copy of any incoming packets.
			 */
			ip_fanout_proto_v6(q, first_mp, ip6h, ill, ill, nexthdr,
			    nexthdr_offset, fanout_flags|IP6_NO_IPPOLICY,
			    mctl_present, ire->ire_zoneid);
			return;
		}
	}
}

/*
 * Send packet using IRE.
 * Checksumming is controlled by cksum_request:
 *	-1 => normal i.e. TCP/UDP/SCTP/ICMPv6 are checksummed and nothing else.
 *	1 => Skip TCP/UDP/SCTP checksum
 * 	Otherwise => checksum_request contains insert offset for checksum
 *
 * Assumes that the following set of headers appear in the first
 * mblk:
 *	ip6_t
 *	Any extension headers
 *	TCP/UDP/SCTP header (if present)
 * The routine can handle an ICMPv6 header that is not in the first mblk.
 *
 * NOTE : This function does not ire_refrele the ire passed in as the
 *	  argument unlike ip_wput_ire where the REFRELE is done.
 *	  Refer to ip_wput_ire for more on this.
 */
static void
ip_wput_ire_v6(queue_t *q, mblk_t *mp, ire_t *ire, int unspec_src,
    int cksum_request, conn_t *connp, int caller, int attach_index, int flags,
    zoneid_t zoneid)
{
	ip6_t		*ip6h;
	uint8_t		nexthdr;
	uint16_t	hdr_length;
	uint_t		reachable = 0x0;
	ill_t		*ill;
	mib2_ipIfStatsEntry_t	*mibptr;
	mblk_t		*first_mp;
	boolean_t	mctl_present;
	ipsec_out_t	*io;
	boolean_t	conn_dontroute;	/* conn value for multicast */
	boolean_t	conn_multicast_loop;	/* conn value for multicast */
	boolean_t 	multicast_forward;	/* Should we forward ? */
	int		max_frag;
	ip_stack_t	*ipst = ire->ire_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	ill = ire_to_ill(ire);
	first_mp = mp;
	multicast_forward = B_FALSE;

	if (mp->b_datap->db_type != M_CTL) {
		ip6h = (ip6_t *)first_mp->b_rptr;
	} else {
		io = (ipsec_out_t *)first_mp->b_rptr;
		ASSERT(io->ipsec_out_type == IPSEC_OUT);
		/*
		 * Grab the zone id now because the M_CTL can be discarded by
		 * ip_wput_ire_parse_ipsec_out() below.
		 */
		ASSERT(zoneid == io->ipsec_out_zoneid);
		ASSERT(zoneid != ALL_ZONES);
		ip6h = (ip6_t *)first_mp->b_cont->b_rptr;
		/*
		 * For the multicast case, ipsec_out carries conn_dontroute and
		 * conn_multicast_loop as conn may not be available here. We
		 * need this for multicast loopback and forwarding which is done
		 * later in the code.
		 */
		if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
			conn_dontroute = io->ipsec_out_dontroute;
			conn_multicast_loop = io->ipsec_out_multicast_loop;
			/*
			 * If conn_dontroute is not set or conn_multicast_loop
			 * is set, we need to do forwarding/loopback. For
			 * datagrams from ip_wput_multicast, conn_dontroute is
			 * set to B_TRUE and conn_multicast_loop is set to
			 * B_FALSE so that we neither do forwarding nor
			 * loopback.
			 */
			if (!conn_dontroute || conn_multicast_loop)
				multicast_forward = B_TRUE;
		}
	}

	/*
	 * If the sender didn't supply the hop limit and there is a default
	 * unicast hop limit associated with the output interface, we use
	 * that if the packet is unicast.  Interface specific unicast hop
	 * limits as set via the SIOCSLIFLNKINFO ioctl.
	 */
	if (ill->ill_max_hops != 0 && !(flags & IP6I_HOPLIMIT) &&
	    !(IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst))) {
		ip6h->ip6_hops = ill->ill_max_hops;
	}

	if (ire->ire_type == IRE_LOCAL && ire->ire_zoneid != zoneid &&
	    ire->ire_zoneid != ALL_ZONES) {
		/*
		 * When a zone sends a packet to another zone, we try to deliver
		 * the packet under the same conditions as if the destination
		 * was a real node on the network. To do so, we look for a
		 * matching route in the forwarding table.
		 * RTF_REJECT and RTF_BLACKHOLE are handled just like
		 * ip_newroute_v6() does.
		 * Note that IRE_LOCAL are special, since they are used
		 * when the zoneid doesn't match in some cases. This means that
		 * we need to handle ipha_src differently since ire_src_addr
		 * belongs to the receiving zone instead of the sending zone.
		 * When ip_restrict_interzone_loopback is set, then
		 * ire_cache_lookup_v6() ensures that IRE_LOCAL are only used
		 * for loopback between zones when the logical "Ethernet" would
		 * have looped them back.
		 */
		ire_t *src_ire;

		src_ire = ire_ftable_lookup_v6(&ip6h->ip6_dst, 0, 0, 0,
		    NULL, NULL, zoneid, 0, NULL, (MATCH_IRE_RECURSIVE |
		    MATCH_IRE_DEFAULT | MATCH_IRE_RJ_BHOLE), ipst);
		if (src_ire != NULL &&
		    !(src_ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE)) &&
		    (!ipst->ips_ip_restrict_interzone_loopback ||
		    ire_local_same_ill_group(ire, src_ire))) {
			if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src) &&
			    !unspec_src) {
				ip6h->ip6_src = src_ire->ire_src_addr_v6;
			}
			ire_refrele(src_ire);
		} else {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutNoRoutes);
			if (src_ire != NULL) {
				if (src_ire->ire_flags & RTF_BLACKHOLE) {
					ire_refrele(src_ire);
					freemsg(first_mp);
					return;
				}
				ire_refrele(src_ire);
			}
			if (ip_hdr_complete_v6(ip6h, zoneid, ipst)) {
				/* Failed */
				freemsg(first_mp);
				return;
			}
			icmp_unreachable_v6(q, first_mp,
			    ICMP6_DST_UNREACH_NOROUTE, B_FALSE, B_FALSE,
			    zoneid, ipst);
			return;
		}
	}

	if (mp->b_datap->db_type == M_CTL ||
	    ipss->ipsec_outbound_v6_policy_present) {
		mp = ip_wput_ire_parse_ipsec_out(first_mp, NULL, ip6h, ire,
		    connp, unspec_src, zoneid);
		if (mp == NULL) {
			return;
		}
	}

	first_mp = mp;
	if (mp->b_datap->db_type == M_CTL) {
		io = (ipsec_out_t *)mp->b_rptr;
		ASSERT(io->ipsec_out_type == IPSEC_OUT);
		mp = mp->b_cont;
		mctl_present = B_TRUE;
	} else {
		mctl_present = B_FALSE;
	}

	ip6h = (ip6_t *)mp->b_rptr;
	nexthdr = ip6h->ip6_nxt;
	mibptr = ill->ill_ip_mib;

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src) && !unspec_src) {
		ipif_t *ipif;

		/*
		 * Select the source address using ipif_select_source_v6.
		 */
		if (attach_index != 0) {
			ipif = ipif_select_source_v6(ill, &ip6h->ip6_dst,
			    RESTRICT_TO_ILL, IPV6_PREFER_SRC_DEFAULT, zoneid);
		} else {
			ipif = ipif_select_source_v6(ill, &ip6h->ip6_dst,
			    RESTRICT_TO_NONE, IPV6_PREFER_SRC_DEFAULT, zoneid);
		}
		if (ipif == NULL) {
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("ip_wput_ire_v6: no src for "
				    "dst %s\n, ", AF_INET6, &ip6h->ip6_dst);
				printf("ip_wput_ire_v6: interface name %s\n",
				    ill->ill_name);
			}
			freemsg(first_mp);
			return;
		}
		ip6h->ip6_src = ipif->ipif_v6src_addr;
		ipif_refrele(ipif);
	}
	if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
		if ((connp != NULL && connp->conn_multicast_loop) ||
		    !IS_LOOPBACK(ill)) {
			ilm_t	*ilm;

			ILM_WALKER_HOLD(ill);
			ilm = ilm_lookup_ill_v6(ill, &ip6h->ip6_dst, ALL_ZONES);
			ILM_WALKER_RELE(ill);
			if (ilm != NULL) {
				mblk_t *nmp;
				int fanout_flags = 0;

				if (connp != NULL &&
				    !connp->conn_multicast_loop) {
					fanout_flags |= IP_FF_NO_MCAST_LOOP;
				}
				ip1dbg(("ip_wput_ire_v6: "
				    "Loopback multicast\n"));
				nmp = ip_copymsg(first_mp);
				if (nmp != NULL) {
					ip6_t	*nip6h;
					mblk_t	*mp_ip6h;

					if (mctl_present) {
						nip6h = (ip6_t *)
						    nmp->b_cont->b_rptr;
						mp_ip6h = nmp->b_cont;
					} else {
						nip6h = (ip6_t *)nmp->b_rptr;
						mp_ip6h = nmp;
					}

					DTRACE_PROBE4(
					    ip6__loopback__out__start,
					    ill_t *, NULL,
					    ill_t *, ill,
					    ip6_t *, nip6h,
					    mblk_t *, nmp);

					FW_HOOKS6(
					    ipst->ips_ip6_loopback_out_event,
					    ipst->ips_ipv6firewall_loopback_out,
					    NULL, ill, nip6h, nmp, mp_ip6h,
					    0, ipst);

					DTRACE_PROBE1(
					    ip6__loopback__out__end,
					    mblk_t *, nmp);

					/*
					 * DTrace this as ip:::send.  A blocked
					 * packet will fire the send probe, but
					 * not the receive probe.
					 */
					DTRACE_IP7(send, mblk_t *, nmp,
					    conn_t *, NULL, void_ip_t *, nip6h,
					    __dtrace_ipsr_ill_t *, ill,
					    ipha_t *, NULL, ip6_t *, nip6h,
					    int, 1);

					if (nmp != NULL) {
						/*
						 * Deliver locally and to
						 * every local zone, except
						 * the sending zone when
						 * IPV6_MULTICAST_LOOP is
						 * disabled.
						 */
						ip_wput_local_v6(RD(q), ill,
						    nip6h, nmp,
						    ire, fanout_flags);
					}
				} else {
					BUMP_MIB(mibptr, ipIfStatsOutDiscards);
					ip1dbg(("ip_wput_ire_v6: "
					    "copymsg failed\n"));
				}
			}
		}
		if (ip6h->ip6_hops == 0 ||
		    IN6_IS_ADDR_MC_NODELOCAL(&ip6h->ip6_dst) ||
		    IS_LOOPBACK(ill)) {
			/*
			 * Local multicast or just loopback on loopback
			 * interface.
			 */
			BUMP_MIB(mibptr, ipIfStatsHCOutMcastPkts);
			UPDATE_MIB(mibptr, ipIfStatsHCOutMcastOctets,
			    ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN);
			ip1dbg(("ip_wput_ire_v6: local multicast only\n"));
			freemsg(first_mp);
			return;
		}
	}

	if (ire->ire_stq != NULL) {
		uint32_t	sum;
		uint_t		ill_index =  ((ill_t *)ire->ire_stq->q_ptr)->
		    ill_phyint->phyint_ifindex;
		queue_t		*dev_q = ire->ire_stq->q_next;

		/*
		 * non-NULL send-to queue - packet is to be sent
		 * out an interface.
		 */

		/* Driver is flow-controlling? */
		if (!IP_FLOW_CONTROLLED_ULP(nexthdr) &&
		    ((dev_q->q_next || dev_q->q_first) && !canput(dev_q))) {
			/*
			 * Queue packet if we have an conn to give back
			 * pressure.  We can't queue packets intended for
			 * hardware acceleration since we've tossed that
			 * state already.  If the packet is being fed back
			 * from ire_send_v6, we don't know the position in
			 * the queue to enqueue the packet and we discard
			 * the packet.
			 */
			if (ipst->ips_ip_output_queue && connp != NULL &&
			    !mctl_present && caller != IRE_SEND) {
				if (caller == IP_WSRV) {
					connp->conn_did_putbq = 1;
					(void) putbq(connp->conn_wq, mp);
					conn_drain_insert(connp);
					/*
					 * caller == IP_WSRV implies we are
					 * the service thread, and the
					 * queue is already noenabled.
					 * The check for canput and
					 * the putbq is not atomic.
					 * So we need to check again.
					 */
					if (canput(dev_q))
						connp->conn_did_putbq = 0;
				} else {
					(void) putq(connp->conn_wq, mp);
				}
				return;
			}
			BUMP_MIB(mibptr, ipIfStatsOutDiscards);
			freemsg(first_mp);
			return;
		}

		/*
		 * Look for reachability confirmations from the transport.
		 */
		if (ip6h->ip6_vcf & IP_FORWARD_PROG) {
			reachable |= IPV6_REACHABILITY_CONFIRMATION;
			ip6h->ip6_vcf &= ~IP_FORWARD_PROG;
			if (mctl_present)
				io->ipsec_out_reachable = B_TRUE;
		}
		/* Fastpath */
		switch (nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMPV6:
		case IPPROTO_SCTP:
			hdr_length = IPV6_HDR_LEN;
			break;
		default: {
			uint8_t	*nexthdrp;

			if (!ip_hdr_length_nexthdr_v6(mp, ip6h,
			    &hdr_length, &nexthdrp)) {
				/* Malformed packet */
				BUMP_MIB(mibptr, ipIfStatsOutDiscards);
				freemsg(first_mp);
				return;
			}
			nexthdr = *nexthdrp;
			break;
		}
		}

		if (cksum_request != -1 && nexthdr != IPPROTO_ICMPV6) {
			uint16_t	*up;
			uint16_t	*insp;

			/*
			 * The packet header is processed once for all, even
			 * in the multirouting case. We disable hardware
			 * checksum if the packet is multirouted, as it will be
			 * replicated via several interfaces, and not all of
			 * them may have this capability.
			 */
			if (cksum_request == 1 &&
			    !(ire->ire_flags & RTF_MULTIRT)) {
				/* Skip the transport checksum */
				goto cksum_done;
			}
			/*
			 * Do user-configured raw checksum.
			 * Compute checksum and insert at offset "cksum_request"
			 */

			/* check for enough headers for checksum */
			cksum_request += hdr_length;	/* offset from rptr */
			if ((mp->b_wptr - mp->b_rptr) <
			    (cksum_request + sizeof (int16_t))) {
				if (!pullupmsg(mp,
				    cksum_request + sizeof (int16_t))) {
					ip1dbg(("ip_wput_v6: ICMP hdr pullupmsg"
					    " failed\n"));
					BUMP_MIB(mibptr, ipIfStatsOutDiscards);
					freemsg(first_mp);
					return;
				}
				ip6h = (ip6_t *)mp->b_rptr;
			}
			insp = (uint16_t *)((uchar_t *)ip6h + cksum_request);
			ASSERT(((uintptr_t)insp & 0x1) == 0);
			up = (uint16_t *)&ip6h->ip6_src;
			/*
			 * icmp has placed length and routing
			 * header adjustment in *insp.
			 */
			sum = htons(nexthdr) +
			    up[0] + up[1] + up[2] + up[3] +
			    up[4] + up[5] + up[6] + up[7] +
			    up[8] + up[9] + up[10] + up[11] +
			    up[12] + up[13] + up[14] + up[15];
			sum = (sum & 0xffff) + (sum >> 16);
			*insp = IP_CSUM(mp, hdr_length, sum);
		} else if (nexthdr == IPPROTO_TCP) {
			uint16_t	*up;

			/*
			 * Check for full IPv6 header + enough TCP header
			 * to get at the checksum field.
			 */
			if ((mp->b_wptr - mp->b_rptr) <
			    (hdr_length + TCP_CHECKSUM_OFFSET +
			    TCP_CHECKSUM_SIZE)) {
				if (!pullupmsg(mp, hdr_length +
				    TCP_CHECKSUM_OFFSET + TCP_CHECKSUM_SIZE)) {
					ip1dbg(("ip_wput_v6: TCP hdr pullupmsg"
					    " failed\n"));
					BUMP_MIB(mibptr, ipIfStatsOutDiscards);
					freemsg(first_mp);
					return;
				}
				ip6h = (ip6_t *)mp->b_rptr;
			}

			up = (uint16_t *)&ip6h->ip6_src;
			/*
			 * Note: The TCP module has stored the length value
			 * into the tcp checksum field, so we don't
			 * need to explicitly sum it in here.
			 */
			sum = up[0] + up[1] + up[2] + up[3] +
			    up[4] + up[5] + up[6] + up[7] +
			    up[8] + up[9] + up[10] + up[11] +
			    up[12] + up[13] + up[14] + up[15];

			/* Fold the initial sum */
			sum = (sum & 0xffff) + (sum >> 16);

			up = (uint16_t *)(((uchar_t *)ip6h) +
			    hdr_length + TCP_CHECKSUM_OFFSET);

			IP_CKSUM_XMIT(ill, ire, mp, ip6h, up, IPPROTO_TCP,
			    hdr_length, ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN,
			    ire->ire_max_frag, mctl_present, sum);

			/* Software checksum? */
			if (DB_CKSUMFLAGS(mp) == 0) {
				IP6_STAT(ipst, ip6_out_sw_cksum);
				IP6_STAT_UPDATE(ipst,
				    ip6_tcp_out_sw_cksum_bytes,
				    (ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN) -
				    hdr_length);
			}
		} else if (nexthdr == IPPROTO_UDP) {
			uint16_t	*up;

			/*
			 * check for full IPv6 header + enough UDP header
			 * to get at the UDP checksum field
			 */
			if ((mp->b_wptr - mp->b_rptr) < (hdr_length +
			    UDP_CHECKSUM_OFFSET + UDP_CHECKSUM_SIZE)) {
				if (!pullupmsg(mp, hdr_length +
				    UDP_CHECKSUM_OFFSET + UDP_CHECKSUM_SIZE)) {
					ip1dbg(("ip_wput_v6: UDP hdr pullupmsg"
					    " failed\n"));
					BUMP_MIB(mibptr, ipIfStatsOutDiscards);
					freemsg(first_mp);
					return;
				}
				ip6h = (ip6_t *)mp->b_rptr;
			}
			up = (uint16_t *)&ip6h->ip6_src;
			/*
			 * Note: The UDP module has stored the length value
			 * into the udp checksum field, so we don't
			 * need to explicitly sum it in here.
			 */
			sum = up[0] + up[1] + up[2] + up[3] +
			    up[4] + up[5] + up[6] + up[7] +
			    up[8] + up[9] + up[10] + up[11] +
			    up[12] + up[13] + up[14] + up[15];

			/* Fold the initial sum */
			sum = (sum & 0xffff) + (sum >> 16);

			up = (uint16_t *)(((uchar_t *)ip6h) +
			    hdr_length + UDP_CHECKSUM_OFFSET);

			IP_CKSUM_XMIT(ill, ire, mp, ip6h, up, IPPROTO_UDP,
			    hdr_length, ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN,
			    ire->ire_max_frag, mctl_present, sum);

			/* Software checksum? */
			if (DB_CKSUMFLAGS(mp) == 0) {
				IP6_STAT(ipst, ip6_out_sw_cksum);
				IP6_STAT_UPDATE(ipst,
				    ip6_udp_out_sw_cksum_bytes,
				    (ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN) -
				    hdr_length);
			}
		} else if (nexthdr == IPPROTO_ICMPV6) {
			uint16_t	*up;
			icmp6_t *icmp6;

			/* check for full IPv6+ICMPv6 header */
			if ((mp->b_wptr - mp->b_rptr) <
			    (hdr_length + ICMP6_MINLEN)) {
				if (!pullupmsg(mp, hdr_length + ICMP6_MINLEN)) {
					ip1dbg(("ip_wput_v6: ICMP hdr pullupmsg"
					    " failed\n"));
					BUMP_MIB(mibptr, ipIfStatsOutDiscards);
					freemsg(first_mp);
					return;
				}
				ip6h = (ip6_t *)mp->b_rptr;
			}
			icmp6 = (icmp6_t *)((uchar_t *)ip6h + hdr_length);
			up = (uint16_t *)&ip6h->ip6_src;
			/*
			 * icmp has placed length and routing
			 * header adjustment in icmp6_cksum.
			 */
			sum = htons(IPPROTO_ICMPV6) +
			    up[0] + up[1] + up[2] + up[3] +
			    up[4] + up[5] + up[6] + up[7] +
			    up[8] + up[9] + up[10] + up[11] +
			    up[12] + up[13] + up[14] + up[15];
			sum = (sum & 0xffff) + (sum >> 16);
			icmp6->icmp6_cksum = IP_CSUM(mp, hdr_length, sum);

			/* Update output mib stats */
			icmp_update_out_mib_v6(ill, icmp6);
		} else if (nexthdr == IPPROTO_SCTP) {
			sctp_hdr_t *sctph;

			if (MBLKL(mp) < (hdr_length + sizeof (*sctph))) {
				if (!pullupmsg(mp, hdr_length +
				    sizeof (*sctph))) {
					ip1dbg(("ip_wput_v6: SCTP hdr pullupmsg"
					    " failed\n"));
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsOutDiscards);
					freemsg(mp);
					return;
				}
				ip6h = (ip6_t *)mp->b_rptr;
			}
			sctph = (sctp_hdr_t *)(mp->b_rptr + hdr_length);
			sctph->sh_chksum = 0;
			sctph->sh_chksum = sctp_cksum(mp, hdr_length);
		}

	cksum_done:
		/*
		 * We force the insertion of a fragment header using the
		 * IPH_FRAG_HDR flag in two cases:
		 * - after reception of an ICMPv6 "packet too big" message
		 *   with a MTU < 1280 (cf. RFC 2460 section 5)
		 * - for multirouted IPv6 packets, so that the receiver can
		 *   discard duplicates according to their fragment identifier
		 *
		 * Two flags modifed from the API can modify this behavior.
		 * The first is IPV6_USE_MIN_MTU.  With this API the user
		 * can specify how to manage PMTUD for unicast and multicast.
		 *
		 * IPV6_DONTFRAG disallows fragmentation.
		 */
		max_frag = ire->ire_max_frag;
		switch (IP6I_USE_MIN_MTU_API(flags)) {
		case IPV6_USE_MIN_MTU_DEFAULT:
		case IPV6_USE_MIN_MTU_UNICAST:
			if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
				max_frag = IPV6_MIN_MTU;
			}
			break;

		case IPV6_USE_MIN_MTU_NEVER:
			max_frag = IPV6_MIN_MTU;
			break;
		}
		if (ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN > max_frag ||
		    (ire->ire_frag_flag & IPH_FRAG_HDR)) {
			if (connp != NULL && (flags & IP6I_DONTFRAG)) {
				icmp_pkt2big_v6(ire->ire_stq, first_mp,
				    max_frag, B_FALSE, B_TRUE, zoneid, ipst);
				return;
			}

			if (ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN !=
			    (mp->b_cont ? msgdsize(mp) :
			    mp->b_wptr - (uchar_t *)ip6h)) {
				ip0dbg(("Packet length mismatch: %d, %ld\n",
				    ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN,
				    msgdsize(mp)));
				freemsg(first_mp);
				return;
			}
			/* Do IPSEC processing first */
			if (mctl_present) {
				if (attach_index != 0)
					ipsec_out_attach_if(io, attach_index);
				ipsec_out_process(q, first_mp, ire, ill_index);
				return;
			}
			ASSERT(mp->b_prev == NULL);
			ip2dbg(("Fragmenting Size = %d, mtu = %d\n",
			    ntohs(ip6h->ip6_plen) +
			    IPV6_HDR_LEN, max_frag));
			ASSERT(mp == first_mp);
			/* Initiate IPPF processing */
			if (IPP_ENABLED(IPP_LOCAL_OUT, ipst)) {
				ip_process(IPP_LOCAL_OUT, &mp, ill_index);
				if (mp == NULL) {
					return;
				}
			}
			ip_wput_frag_v6(mp, ire, reachable, connp,
			    caller, max_frag);
			return;
		}
		/* Do IPSEC processing first */
		if (mctl_present) {
			int extra_len = ipsec_out_extra_length(first_mp);

			if (ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN + extra_len >
			    max_frag) {
				/*
				 * IPsec headers will push the packet over the
				 * MTU limit.  Issue an ICMPv6 Packet Too Big
				 * message for this packet if the upper-layer
				 * that issued this packet will be able to
				 * react to the icmp_pkt2big_v6() that we'll
				 * generate.
				 */
				icmp_pkt2big_v6(ire->ire_stq, first_mp,
				    max_frag, B_FALSE, B_TRUE, zoneid, ipst);
				return;
			}
			if (attach_index != 0)
				ipsec_out_attach_if(io, attach_index);
			ipsec_out_process(q, first_mp, ire, ill_index);
			return;
		}
		/*
		 * XXX multicast: add ip_mforward_v6() here.
		 * Check conn_dontroute
		 */
#ifdef lint
		/*
		 * XXX The only purpose of this statement is to avoid lint
		 * errors.  See the above "XXX multicast".  When that gets
		 * fixed, remove this whole #ifdef lint section.
		 */
		ip3dbg(("multicast forward is %s.\n",
		    (multicast_forward ? "TRUE" : "FALSE")));
#endif

		UPDATE_OB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
		ASSERT(mp == first_mp);
		ip_xmit_v6(mp, ire, reachable, connp, caller, NULL);
	} else {
		/*
		 * DTrace this as ip:::send.  A blocked packet will fire the
		 * send probe, but not the receive probe.
		 */
		DTRACE_IP7(send, mblk_t *, first_mp, conn_t *, NULL,
		    void_ip_t *, ip6h, __dtrace_ipsr_ill_t *, ill, ipha_t *,
		    NULL, ip6_t *, ip6h, int, 1);
		DTRACE_PROBE4(ip6__loopback__out__start,
		    ill_t *, NULL, ill_t *, ill,
		    ip6_t *, ip6h, mblk_t *, first_mp);
		FW_HOOKS6(ipst->ips_ip6_loopback_out_event,
		    ipst->ips_ipv6firewall_loopback_out,
		    NULL, ill, ip6h, first_mp, mp, 0, ipst);
		DTRACE_PROBE1(ip6__loopback__out__end, mblk_t *, first_mp);
		if (first_mp != NULL)
			ip_wput_local_v6(RD(q), ill, ip6h, first_mp, ire, 0);
	}
}

/*
 * Outbound IPv6 fragmentation routine using MDT.
 */
static void
ip_wput_frag_mdt_v6(mblk_t *mp, ire_t *ire, size_t max_chunk,
    size_t unfragmentable_len, uint8_t nexthdr, uint_t prev_nexthdr_offset)
{
	ip6_t		*ip6h = (ip6_t *)mp->b_rptr;
	uint_t		pkts, wroff, hdr_chunk_len, pbuf_idx;
	mblk_t		*hdr_mp, *md_mp = NULL;
	int		i1;
	multidata_t	*mmd;
	unsigned char	*hdr_ptr, *pld_ptr;
	ip_pdescinfo_t	pdi;
	uint32_t	ident;
	size_t		len;
	uint16_t	offset;
	queue_t		*stq = ire->ire_stq;
	ill_t		*ill = (ill_t *)stq->q_ptr;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(MBLKL(mp) > unfragmentable_len);

	/*
	 * Move read ptr past unfragmentable portion, we don't want this part
	 * of the data in our fragments.
	 */
	mp->b_rptr += unfragmentable_len;

	/* Calculate how many packets we will send out  */
	i1 = (mp->b_cont == NULL) ? MBLKL(mp) : msgsize(mp);
	pkts = (i1 + max_chunk - 1) / max_chunk;
	ASSERT(pkts > 1);

	/* Allocate a message block which will hold all the IP Headers. */
	wroff = ipst->ips_ip_wroff_extra;
	hdr_chunk_len = wroff + unfragmentable_len + sizeof (ip6_frag_t);

	i1 = pkts * hdr_chunk_len;
	/*
	 * Create the header buffer, Multidata and destination address
	 * and SAP attribute that should be associated with it.
	 */
	if ((hdr_mp = allocb(i1, BPRI_HI)) == NULL ||
	    ((hdr_mp->b_wptr += i1),
	    (mmd = mmd_alloc(hdr_mp, &md_mp, KM_NOSLEEP)) == NULL) ||
	    !ip_md_addr_attr(mmd, NULL, ire->ire_nce->nce_res_mp)) {
		freemsg(mp);
		if (md_mp == NULL) {
			freemsg(hdr_mp);
		} else {
free_mmd:		IP6_STAT(ipst, ip6_frag_mdt_discarded);
			freemsg(md_mp);
		}
		IP6_STAT(ipst, ip6_frag_mdt_allocfail);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		return;
	}
	IP6_STAT(ipst, ip6_frag_mdt_allocd);

	/*
	 * Add a payload buffer to the Multidata; this operation must not
	 * fail, or otherwise our logic in this routine is broken.  There
	 * is no memory allocation done by the routine, so any returned
	 * failure simply tells us that we've done something wrong.
	 *
	 * A failure tells us that either we're adding the same payload
	 * buffer more than once, or we're trying to add more buffers than
	 * allowed.  None of the above cases should happen, and we panic
	 * because either there's horrible heap corruption, and/or
	 * programming mistake.
	 */
	if ((pbuf_idx = mmd_addpldbuf(mmd, mp)) < 0) {
		goto pbuf_panic;
	}

	hdr_ptr = hdr_mp->b_rptr;
	pld_ptr = mp->b_rptr;

	pdi.flags = PDESC_HBUF_REF | PDESC_PBUF_REF;

	ident = htonl(atomic_add_32_nv(&ire->ire_ident, 1));

	/*
	 * len is the total length of the fragmentable data in this
	 * datagram.  For each fragment sent, we will decrement len
	 * by the amount of fragmentable data sent in that fragment
	 * until len reaches zero.
	 */
	len = ntohs(ip6h->ip6_plen) - (unfragmentable_len - IPV6_HDR_LEN);

	offset = 0;
	prev_nexthdr_offset += wroff;

	while (len != 0) {
		size_t		mlen;
		ip6_t		*fip6h;
		ip6_frag_t	*fraghdr;
		int		error;

		ASSERT((hdr_ptr + hdr_chunk_len) <= hdr_mp->b_wptr);
		mlen = MIN(len, max_chunk);
		len -= mlen;

		fip6h = (ip6_t *)(hdr_ptr + wroff);
		ASSERT(OK_32PTR(fip6h));
		bcopy(ip6h, fip6h, unfragmentable_len);
		hdr_ptr[prev_nexthdr_offset] = IPPROTO_FRAGMENT;

		fip6h->ip6_plen = htons((uint16_t)(mlen +
		    unfragmentable_len - IPV6_HDR_LEN + sizeof (ip6_frag_t)));

		fraghdr = (ip6_frag_t *)((unsigned char *)fip6h +
		    unfragmentable_len);
		fraghdr->ip6f_nxt = nexthdr;
		fraghdr->ip6f_reserved = 0;
		fraghdr->ip6f_offlg = htons(offset) |
		    ((len != 0) ? IP6F_MORE_FRAG : 0);
		fraghdr->ip6f_ident = ident;

		/*
		 * Record offset and size of header and data of the next packet
		 * in the multidata message.
		 */
		PDESC_HDR_ADD(&pdi, hdr_ptr, wroff,
		    unfragmentable_len + sizeof (ip6_frag_t), 0);
		PDESC_PLD_INIT(&pdi);
		i1 = MIN(mp->b_wptr - pld_ptr, mlen);
		ASSERT(i1 > 0);
		PDESC_PLD_SPAN_ADD(&pdi, pbuf_idx, pld_ptr, i1);
		if (i1 == mlen) {
			pld_ptr += mlen;
		} else {
			i1 = mlen - i1;
			mp = mp->b_cont;
			ASSERT(mp != NULL);
			ASSERT(MBLKL(mp) >= i1);
			/*
			 * Attach the next payload message block to the
			 * multidata message.
			 */
			if ((pbuf_idx = mmd_addpldbuf(mmd, mp)) < 0)
				goto pbuf_panic;
			PDESC_PLD_SPAN_ADD(&pdi, pbuf_idx, mp->b_rptr, i1);
			pld_ptr = mp->b_rptr + i1;
		}

		if ((mmd_addpdesc(mmd, (pdescinfo_t *)&pdi, &error,
		    KM_NOSLEEP)) == NULL) {
			/*
			 * Any failure other than ENOMEM indicates that we
			 * have passed in invalid pdesc info or parameters
			 * to mmd_addpdesc, which must not happen.
			 *
			 * EINVAL is a result of failure on boundary checks
			 * against the pdesc info contents.  It should not
			 * happen, and we panic because either there's
			 * horrible heap corruption, and/or programming
			 * mistake.
			 */
			if (error != ENOMEM) {
				cmn_err(CE_PANIC, "ip_wput_frag_mdt_v6: "
				    "pdesc logic error detected for "
				    "mmd %p pinfo %p (%d)\n",
				    (void *)mmd, (void *)&pdi, error);
				/* NOTREACHED */
			}
			IP6_STAT(ipst, ip6_frag_mdt_addpdescfail);
			/* Free unattached payload message blocks as well */
			md_mp->b_cont = mp->b_cont;
			goto free_mmd;
		}

		/* Advance fragment offset. */
		offset += mlen;

		/* Advance to location for next header in the buffer. */
		hdr_ptr += hdr_chunk_len;

		/* Did we reach the next payload message block? */
		if (pld_ptr == mp->b_wptr && mp->b_cont != NULL) {
			mp = mp->b_cont;
			/*
			 * Attach the next message block with payload
			 * data to the multidata message.
			 */
			if ((pbuf_idx = mmd_addpldbuf(mmd, mp)) < 0)
				goto pbuf_panic;
			pld_ptr = mp->b_rptr;
		}
	}

	ASSERT(hdr_mp->b_wptr == hdr_ptr);
	ASSERT(mp->b_wptr == pld_ptr);

	/* Update IP statistics */
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsOutFragCreates, pkts);
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragOKs);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutTransmits, pkts);
	/*
	 * The ipv6 header len is accounted for in unfragmentable_len so
	 * when calculating the fragmentation overhead just add the frag
	 * header len.
	 */
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutOctets,
	    (ntohs(ip6h->ip6_plen) - (unfragmentable_len - IPV6_HDR_LEN)) +
	    pkts * (unfragmentable_len + sizeof (ip6_frag_t)));
	IP6_STAT_UPDATE(ipst, ip6_frag_mdt_pkt_out, pkts);

	ire->ire_ob_pkt_count += pkts;
	if (ire->ire_ipif != NULL)
		atomic_add_32(&ire->ire_ipif->ipif_ob_pkt_count, pkts);

	ire->ire_last_used_time = lbolt;
	/* Send it down */
	putnext(stq, md_mp);
	return;

pbuf_panic:
	cmn_err(CE_PANIC, "ip_wput_frag_mdt_v6: payload buffer logic "
	    "error for mmd %p pbuf %p (%d)", (void *)mmd, (void *)mp,
	    pbuf_idx);
	/* NOTREACHED */
}

/*
 * IPv6 fragmentation.  Essentially the same as IPv4 fragmentation.
 * We have not optimized this in terms of number of mblks
 * allocated. For instance, for each fragment sent we always allocate a
 * mblk to hold the IPv6 header and fragment header.
 *
 * Assumes that all the extension headers are contained in the first mblk.
 *
 * The fragment header is inserted after an hop-by-hop options header
 * and after [an optional destinations header followed by] a routing header.
 *
 * NOTE : This function does not ire_refrele the ire passed in as
 * the argument.
 */
void
ip_wput_frag_v6(mblk_t *mp, ire_t *ire, uint_t reachable, conn_t *connp,
    int caller, int max_frag)
{
	ip6_t		*ip6h = (ip6_t *)mp->b_rptr;
	ip6_t		*fip6h;
	mblk_t		*hmp;
	mblk_t		*hmp0;
	mblk_t		*dmp;
	ip6_frag_t	*fraghdr;
	size_t		unfragmentable_len;
	size_t		len;
	size_t		mlen;
	size_t		max_chunk;
	uint32_t	ident;
	uint16_t	off_flags;
	uint16_t	offset = 0;
	ill_t		*ill;
	uint8_t		nexthdr;
	uint_t		prev_nexthdr_offset;
	uint8_t		*ptr;
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(ire->ire_type == IRE_CACHE);
	ill = (ill_t *)ire->ire_stq->q_ptr;

	if (max_frag <= 0) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		freemsg(mp);
		return;
	}
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragReqds);

	/*
	 * Determine the length of the unfragmentable portion of this
	 * datagram.  This consists of the IPv6 header, a potential
	 * hop-by-hop options header, a potential pre-routing-header
	 * destination options header, and a potential routing header.
	 */
	nexthdr = ip6h->ip6_nxt;
	prev_nexthdr_offset = (uint8_t *)&ip6h->ip6_nxt - (uint8_t *)ip6h;
	ptr = (uint8_t *)&ip6h[1];

	if (nexthdr == IPPROTO_HOPOPTS) {
		ip6_hbh_t	*hbh_hdr;
		uint_t		hdr_len;

		hbh_hdr = (ip6_hbh_t *)ptr;
		hdr_len = 8 * (hbh_hdr->ip6h_len + 1);
		nexthdr = hbh_hdr->ip6h_nxt;
		prev_nexthdr_offset = (uint8_t *)&hbh_hdr->ip6h_nxt
		    - (uint8_t *)ip6h;
		ptr += hdr_len;
	}
	if (nexthdr == IPPROTO_DSTOPTS) {
		ip6_dest_t	*dest_hdr;
		uint_t		hdr_len;

		dest_hdr = (ip6_dest_t *)ptr;
		if (dest_hdr->ip6d_nxt == IPPROTO_ROUTING) {
			hdr_len = 8 * (dest_hdr->ip6d_len + 1);
			nexthdr = dest_hdr->ip6d_nxt;
			prev_nexthdr_offset = (uint8_t *)&dest_hdr->ip6d_nxt
			    - (uint8_t *)ip6h;
			ptr += hdr_len;
		}
	}
	if (nexthdr == IPPROTO_ROUTING) {
		ip6_rthdr_t	*rthdr;
		uint_t		hdr_len;

		rthdr = (ip6_rthdr_t *)ptr;
		nexthdr = rthdr->ip6r_nxt;
		prev_nexthdr_offset = (uint8_t *)&rthdr->ip6r_nxt
		    - (uint8_t *)ip6h;
		hdr_len = 8 * (rthdr->ip6r_len + 1);
		ptr += hdr_len;
	}
	unfragmentable_len = (uint_t)(ptr - (uint8_t *)ip6h);

	max_chunk = (min(max_frag, ire->ire_max_frag) - unfragmentable_len -
	    sizeof (ip6_frag_t)) & ~7;

	/* Check if we can use MDT to send out the frags. */
	ASSERT(!IRE_IS_LOCAL(ire));
	if (ipst->ips_ip_multidata_outbound && reachable == 0 &&
	    !(ire->ire_flags & RTF_MULTIRT) && ILL_MDT_CAPABLE(ill) &&
	    IP_CAN_FRAG_MDT(mp, unfragmentable_len, max_chunk)) {
		ip_wput_frag_mdt_v6(mp, ire, max_chunk, unfragmentable_len,
		    nexthdr, prev_nexthdr_offset);
		return;
	}

	/*
	 * Allocate an mblk with enough room for the link-layer
	 * header, the unfragmentable part of the datagram, and the
	 * fragment header.  This (or a copy) will be used as the
	 * first mblk for each fragment we send.
	 */
	hmp = allocb(unfragmentable_len + sizeof (ip6_frag_t) +
	    ipst->ips_ip_wroff_extra, BPRI_HI);
	if (hmp == NULL) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		freemsg(mp);
		return;
	}
	hmp->b_rptr += ipst->ips_ip_wroff_extra;
	hmp->b_wptr = hmp->b_rptr + unfragmentable_len + sizeof (ip6_frag_t);

	fip6h = (ip6_t *)hmp->b_rptr;
	fraghdr = (ip6_frag_t *)(hmp->b_rptr + unfragmentable_len);

	bcopy(ip6h, fip6h, unfragmentable_len);
	hmp->b_rptr[prev_nexthdr_offset] = IPPROTO_FRAGMENT;

	ident = atomic_add_32_nv(&ire->ire_ident, 1);

	fraghdr->ip6f_nxt = nexthdr;
	fraghdr->ip6f_reserved = 0;
	fraghdr->ip6f_offlg = 0;
	fraghdr->ip6f_ident = htonl(ident);

	/*
	 * len is the total length of the fragmentable data in this
	 * datagram.  For each fragment sent, we will decrement len
	 * by the amount of fragmentable data sent in that fragment
	 * until len reaches zero.
	 */
	len = ntohs(ip6h->ip6_plen) - (unfragmentable_len - IPV6_HDR_LEN);

	/*
	 * Move read ptr past unfragmentable portion, we don't want this part
	 * of the data in our fragments.
	 */
	mp->b_rptr += unfragmentable_len;

	while (len != 0) {
		mlen = MIN(len, max_chunk);
		len -= mlen;
		if (len != 0) {
			/* Not last */
			hmp0 = copyb(hmp);
			if (hmp0 == NULL) {
				freeb(hmp);
				freemsg(mp);
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsOutFragFails);
				ip1dbg(("ip_wput_frag_v6: copyb failed\n"));
				return;
			}
			off_flags = IP6F_MORE_FRAG;
		} else {
			/* Last fragment */
			hmp0 = hmp;
			hmp = NULL;
			off_flags = 0;
		}
		fip6h = (ip6_t *)(hmp0->b_rptr);
		fraghdr = (ip6_frag_t *)(hmp0->b_rptr + unfragmentable_len);

		fip6h->ip6_plen = htons((uint16_t)(mlen +
		    unfragmentable_len - IPV6_HDR_LEN + sizeof (ip6_frag_t)));
		/*
		 * Note: Optimization alert.
		 * In IPv6 (and IPv4) protocol header, Fragment Offset
		 * ("offset") is 13 bits wide and in 8-octet units.
		 * In IPv6 protocol header (unlike IPv4) in a 16 bit field,
		 * it occupies the most significant 13 bits.
		 * (least significant 13 bits in IPv4).
		 * We do not do any shifts here. Not shifting is same effect
		 * as taking offset value in octet units, dividing by 8 and
		 * then shifting 3 bits left to line it up in place in proper
		 * place protocol header.
		 */
		fraghdr->ip6f_offlg = htons(offset) | off_flags;

		if (!(dmp = ip_carve_mp(&mp, mlen))) {
			/* mp has already been freed by ip_carve_mp() */
			if (hmp != NULL)
				freeb(hmp);
			freeb(hmp0);
			ip1dbg(("ip_carve_mp: failed\n"));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
			return;
		}
		hmp0->b_cont = dmp;
		/* Get the priority marking, if any */
		hmp0->b_band = dmp->b_band;
		UPDATE_OB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
		ip_xmit_v6(hmp0, ire, reachable | IP6_NO_IPPOLICY, connp,
		    caller, NULL);
		reachable = 0;	/* No need to redo state machine in loop */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragCreates);
		offset += mlen;
	}
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragOKs);
}

/*
 * Determine if the ill and multicast aspects of that packets
 * "matches" the conn.
 */
boolean_t
conn_wantpacket_v6(conn_t *connp, ill_t *ill, ip6_t *ip6h, int fanout_flags,
    zoneid_t zoneid)
{
	ill_t *in_ill;
	boolean_t wantpacket = B_TRUE;
	in6_addr_t *v6dst_ptr = &ip6h->ip6_dst;
	in6_addr_t *v6src_ptr = &ip6h->ip6_src;

	/*
	 * conn_incoming_ill is set by IPV6_BOUND_IF which limits
	 * unicast and multicast reception to conn_incoming_ill.
	 * conn_wantpacket_v6 is called both for unicast and
	 * multicast.
	 *
	 * 1) The unicast copy of the packet can come anywhere in
	 *    the ill group if it is part of the group. Thus, we
	 *    need to check to see whether the ill group matches
	 *    if in_ill is part of a group.
	 *
	 * 2) ip_rput does not suppress duplicate multicast packets.
	 *    If there are two interfaces in a ill group and we have
	 *    2 applications (conns) joined a multicast group G on
	 *    both the interfaces, ilm_lookup_ill filter in ip_rput
	 *    will give us two packets because we join G on both the
	 *    interfaces rather than nominating just one interface
	 *    for receiving multicast like broadcast above. So,
	 *    we have to call ilg_lookup_ill to filter out duplicate
	 *    copies, if ill is part of a group, to supress duplicates.
	 */
	in_ill = connp->conn_incoming_ill;
	if (in_ill != NULL) {
		mutex_enter(&connp->conn_lock);
		in_ill = connp->conn_incoming_ill;
		mutex_enter(&ill->ill_lock);
		/*
		 * No IPMP, and the packet did not arrive on conn_incoming_ill
		 * OR, IPMP in use and the packet arrived on an IPMP group
		 * different from the conn_incoming_ill's IPMP group.
		 * Reject the packet.
		 */
		if ((in_ill->ill_group == NULL && in_ill != ill) ||
		    (in_ill->ill_group != NULL &&
		    in_ill->ill_group !=  ill->ill_group)) {
			wantpacket = B_FALSE;
		}
		mutex_exit(&ill->ill_lock);
		mutex_exit(&connp->conn_lock);
		if (!wantpacket)
			return (B_FALSE);
	}

	if (connp->conn_multi_router)
		return (B_TRUE);

	if (!IN6_IS_ADDR_MULTICAST(v6dst_ptr) &&
	    !IN6_IS_ADDR_V4MAPPED_CLASSD(v6dst_ptr)) {
		/*
		 * Unicast case: we match the conn only if it's in the specified
		 * zone.
		 */
		return (IPCL_ZONE_MATCH(connp, zoneid));
	}

	if ((fanout_flags & IP_FF_NO_MCAST_LOOP) &&
	    (connp->conn_zoneid == zoneid || zoneid == ALL_ZONES)) {
		/*
		 * Loopback case: the sending endpoint has IP_MULTICAST_LOOP
		 * disabled, therefore we don't dispatch the multicast packet to
		 * the sending zone.
		 */
		return (B_FALSE);
	}

	if (IS_LOOPBACK(ill) && connp->conn_zoneid != zoneid &&
	    zoneid != ALL_ZONES) {
		/*
		 * Multicast packet on the loopback interface: we only match
		 * conns who joined the group in the specified zone.
		 */
		return (B_FALSE);
	}

	mutex_enter(&connp->conn_lock);
	wantpacket =
	    ilg_lookup_ill_withsrc_v6(connp, v6dst_ptr, v6src_ptr, ill) != NULL;
	mutex_exit(&connp->conn_lock);

	return (wantpacket);
}


/*
 * Transmit a packet and update any NUD state based on the flags
 * XXX need to "recover" any ip6i_t when doing putq!
 *
 * NOTE : This function does not ire_refrele the ire passed in as the
 * argument.
 */
void
ip_xmit_v6(mblk_t *mp, ire_t *ire, uint_t flags, conn_t *connp,
    int caller, ipsec_out_t *io)
{
	mblk_t		*mp1;
	nce_t		*nce = ire->ire_nce;
	ill_t		*ill;
	ill_t		*out_ill;
	uint64_t	delta;
	ip6_t		*ip6h;
	queue_t		*stq = ire->ire_stq;
	ire_t		*ire1 = NULL;
	ire_t		*save_ire = ire;
	boolean_t	multirt_send = B_FALSE;
	mblk_t		*next_mp = NULL;
	ip_stack_t	*ipst = ire->ire_ipst;

	ip6h = (ip6_t *)mp->b_rptr;
	ASSERT(!IN6_IS_ADDR_V4MAPPED(&ire->ire_addr_v6));
	ASSERT(ire->ire_ipversion == IPV6_VERSION);
	ASSERT(nce != NULL);
	ASSERT(mp->b_datap->db_type == M_DATA);
	ASSERT(stq != NULL);

	ill = ire_to_ill(ire);
	if (!ill) {
		ip0dbg(("ip_xmit_v6: ire_to_ill failed\n"));
		freemsg(mp);
		return;
	}

	/*
	 * If a packet is to be sent out an interface that is a 6to4
	 * tunnel, outgoing IPv6 packets, with a 6to4 addressed IPv6
	 * destination, must be checked to have a 6to4 prefix
	 * (2002:V4ADDR::/48) that is NOT equal to the 6to4 prefix of
	 * address configured on the sending interface.  Otherwise,
	 * the packet was delivered to this interface in error and the
	 * packet must be dropped.
	 */
	if ((ill->ill_is_6to4tun) && IN6_IS_ADDR_6TO4(&ip6h->ip6_dst)) {
		ipif_t *ipif = ill->ill_ipif;

		if (IN6_ARE_6TO4_PREFIX_EQUAL(&ipif->ipif_v6lcl_addr,
		    &ip6h->ip6_dst)) {
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("ip_xmit_v6: attempting to "
				    "send 6to4 addressed IPv6 "
				    "destination (%s) out the wrong "
				    "interface.\n", AF_INET6,
				    &ip6h->ip6_dst);
			}
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			freemsg(mp);
			return;
		}
	}

	/* Flow-control check has been done in ip_wput_ire_v6 */
	if (IP_FLOW_CONTROLLED_ULP(ip6h->ip6_nxt) || caller == IP_WPUT ||
	    caller == IP_WSRV || canput(stq->q_next)) {
		uint32_t ill_index;

		/*
		 * In most cases, the emission loop below is entered only
		 * once. Only in the case where the ire holds the
		 * RTF_MULTIRT flag, do we loop to process all RTF_MULTIRT
		 * flagged ires in the bucket, and send the packet
		 * through all crossed RTF_MULTIRT routes.
		 */
		if (ire->ire_flags & RTF_MULTIRT) {
			/*
			 * Multirouting case. The bucket where ire is stored
			 * probably holds other RTF_MULTIRT flagged ires
			 * to the destination. In this call to ip_xmit_v6,
			 * we attempt to send the packet through all
			 * those ires. Thus, we first ensure that ire is the
			 * first RTF_MULTIRT ire in the bucket,
			 * before walking the ire list.
			 */
			ire_t *first_ire;
			irb_t *irb = ire->ire_bucket;
			ASSERT(irb != NULL);
			multirt_send = B_TRUE;

			/* Make sure we do not omit any multiroute ire. */
			IRB_REFHOLD(irb);
			for (first_ire = irb->irb_ire;
			    first_ire != NULL;
			    first_ire = first_ire->ire_next) {
				if ((first_ire->ire_flags & RTF_MULTIRT) &&
				    (IN6_ARE_ADDR_EQUAL(&first_ire->ire_addr_v6,
				    &ire->ire_addr_v6)) &&
				    !(first_ire->ire_marks &
				    (IRE_MARK_CONDEMNED | IRE_MARK_HIDDEN)))
					break;
			}

			if ((first_ire != NULL) && (first_ire != ire)) {
				IRE_REFHOLD(first_ire);
				/* ire will be released by the caller */
				ire = first_ire;
				nce = ire->ire_nce;
				stq = ire->ire_stq;
				ill = ire_to_ill(ire);
			}
			IRB_REFRELE(irb);
		} else if (connp != NULL && IPCL_IS_TCP(connp) &&
		    connp->conn_mdt_ok && !connp->conn_tcp->tcp_mdt &&
		    ILL_MDT_USABLE(ill)) {
			/*
			 * This tcp connection was marked as MDT-capable, but
			 * it has been turned off due changes in the interface.
			 * Now that the interface support is back, turn it on
			 * by notifying tcp.  We don't directly modify tcp_mdt,
			 * since we leave all the details to the tcp code that
			 * knows better.
			 */
			mblk_t *mdimp = ip_mdinfo_alloc(ill->ill_mdt_capab);

			if (mdimp == NULL) {
				ip0dbg(("ip_xmit_v6: can't re-enable MDT for "
				    "connp %p (ENOMEM)\n", (void *)connp));
			} else {
				CONN_INC_REF(connp);
				squeue_fill(connp->conn_sqp, mdimp, tcp_input,
				    connp, SQTAG_TCP_INPUT_MCTL);
			}
		}

		do {
			mblk_t *mp_ip6h;

			if (multirt_send) {
				irb_t *irb;
				/*
				 * We are in a multiple send case, need to get
				 * the next ire and make a duplicate of the
				 * packet. ire1 holds here the next ire to
				 * process in the bucket. If multirouting is
				 * expected, any non-RTF_MULTIRT ire that has
				 * the right destination address is ignored.
				 */
				irb = ire->ire_bucket;
				ASSERT(irb != NULL);

				IRB_REFHOLD(irb);
				for (ire1 = ire->ire_next;
				    ire1 != NULL;
				    ire1 = ire1->ire_next) {
					if (!(ire1->ire_flags & RTF_MULTIRT))
						continue;
					if (!IN6_ARE_ADDR_EQUAL(
					    &ire1->ire_addr_v6,
					    &ire->ire_addr_v6))
						continue;
					if (ire1->ire_marks &
					    (IRE_MARK_CONDEMNED|
					    IRE_MARK_HIDDEN))
						continue;

					/* Got one */
					if (ire1 != save_ire) {
						IRE_REFHOLD(ire1);
					}
					break;
				}
				IRB_REFRELE(irb);

				if (ire1 != NULL) {
					next_mp = copyb(mp);
					if ((next_mp == NULL) ||
					    ((mp->b_cont != NULL) &&
					    ((next_mp->b_cont =
					    dupmsg(mp->b_cont)) == NULL))) {
						freemsg(next_mp);
						next_mp = NULL;
						ire_refrele(ire1);
						ire1 = NULL;
					}
				}

				/* Last multiroute ire; don't loop anymore. */
				if (ire1 == NULL) {
					multirt_send = B_FALSE;
				}
			}

			ill_index =
			    ((ill_t *)stq->q_ptr)->ill_phyint->phyint_ifindex;

			/* Initiate IPPF processing */
			if (IP6_OUT_IPP(flags, ipst)) {
				ip_process(IPP_LOCAL_OUT, &mp, ill_index);
				if (mp == NULL) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsOutDiscards);
					if (next_mp != NULL)
						freemsg(next_mp);
					if (ire != save_ire) {
						ire_refrele(ire);
					}
					return;
				}
				ip6h = (ip6_t *)mp->b_rptr;
			}
			mp_ip6h = mp;

			/*
			 * Check for fastpath, we need to hold nce_lock to
			 * prevent fastpath update from chaining nce_fp_mp.
			 */

			ASSERT(nce->nce_ipversion != IPV4_VERSION);
			mutex_enter(&nce->nce_lock);
			if ((mp1 = nce->nce_fp_mp) != NULL) {
				uint32_t hlen;
				uchar_t	*rptr;

				hlen = MBLKL(mp1);
				rptr = mp->b_rptr - hlen;
				/*
				 * make sure there is room for the fastpath
				 * datalink header
				 */
				if (rptr < mp->b_datap->db_base) {
					mp1 = copyb(mp1);
					mutex_exit(&nce->nce_lock);
					if (mp1 == NULL) {
						BUMP_MIB(ill->ill_ip_mib,
						    ipIfStatsOutDiscards);
						freemsg(mp);
						if (next_mp != NULL)
							freemsg(next_mp);
						if (ire != save_ire) {
							ire_refrele(ire);
						}
						return;
					}
					mp1->b_cont = mp;

					/* Get the priority marking, if any */
					mp1->b_band = mp->b_band;
					mp = mp1;
				} else {
					mp->b_rptr = rptr;
					/*
					 * fastpath -  pre-pend datalink
					 * header
					 */
					bcopy(mp1->b_rptr, rptr, hlen);
					mutex_exit(&nce->nce_lock);
				}
			} else {
				/*
				 * Get the DL_UNITDATA_REQ.
				 */
				mp1 = nce->nce_res_mp;
				if (mp1 == NULL) {
					mutex_exit(&nce->nce_lock);
					ip1dbg(("ip_xmit_v6: No resolution "
					    "block ire = %p\n", (void *)ire));
					freemsg(mp);
					if (next_mp != NULL)
						freemsg(next_mp);
					if (ire != save_ire) {
						ire_refrele(ire);
					}
					return;
				}
				/*
				 * Prepend the DL_UNITDATA_REQ.
				 */
				mp1 = copyb(mp1);
				mutex_exit(&nce->nce_lock);
				if (mp1 == NULL) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsOutDiscards);
					freemsg(mp);
					if (next_mp != NULL)
						freemsg(next_mp);
					if (ire != save_ire) {
						ire_refrele(ire);
					}
					return;
				}
				mp1->b_cont = mp;

				/* Get the priority marking, if any */
				mp1->b_band = mp->b_band;
				mp = mp1;
			}

			out_ill = (ill_t *)stq->q_ptr;

			DTRACE_PROBE4(ip6__physical__out__start,
			    ill_t *, NULL, ill_t *, out_ill,
			    ip6_t *, ip6h, mblk_t *, mp);

			FW_HOOKS6(ipst->ips_ip6_physical_out_event,
			    ipst->ips_ipv6firewall_physical_out,
			    NULL, out_ill, ip6h, mp, mp_ip6h, 0, ipst);

			DTRACE_PROBE1(ip6__physical__out__end, mblk_t *, mp);

			if (mp == NULL) {
				if (multirt_send) {
					ASSERT(ire1 != NULL);
					if (ire != save_ire) {
						ire_refrele(ire);
					}
					/*
					 * Proceed with the next RTF_MULTIRT
					 * ire, also set up the send-to queue
					 * accordingly.
					 */
					ire = ire1;
					ire1 = NULL;
					stq = ire->ire_stq;
					nce = ire->ire_nce;
					ill = ire_to_ill(ire);
					mp = next_mp;
					next_mp = NULL;
					continue;
				} else {
					ASSERT(next_mp == NULL);
					ASSERT(ire1 == NULL);
					break;
				}
			}

			/*
			 * Update ire and MIB counters; for save_ire, this has
			 * been done by the caller.
			 */
			if (ire != save_ire) {
				UPDATE_OB_PKT_COUNT(ire);
				ire->ire_last_used_time = lbolt;

				if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsHCOutMcastPkts);
					UPDATE_MIB(ill->ill_ip_mib,
					    ipIfStatsHCOutMcastOctets,
					    ntohs(ip6h->ip6_plen) +
					    IPV6_HDR_LEN);
				}
			}

			/*
			 * Send it down.  XXX Do we want to flow control AH/ESP
			 * packets that carry TCP payloads?  We don't flow
			 * control TCP packets, but we should also not
			 * flow-control TCP packets that have been protected.
			 * We don't have an easy way to find out if an AH/ESP
			 * packet was originally TCP or not currently.
			 */
			if (io == NULL) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsHCOutTransmits);
				UPDATE_MIB(ill->ill_ip_mib,
				    ipIfStatsHCOutOctets,
				    ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN);
				DTRACE_IP7(send, mblk_t *, mp, conn_t *, NULL,
				    void_ip_t *, ip6h, __dtrace_ipsr_ill_t *,
				    out_ill, ipha_t *, NULL, ip6_t *, ip6h,
				    int, 0);

				putnext(stq, mp);
			} else {
				/*
				 * Safety Pup says: make sure this is
				 * going to the right interface!
				 */
				if (io->ipsec_out_capab_ill_index !=
				    ill_index) {
					/* IPsec kstats: bump lose counter */
					freemsg(mp1);
				} else {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsHCOutTransmits);
					UPDATE_MIB(ill->ill_ip_mib,
					    ipIfStatsHCOutOctets,
					    ntohs(ip6h->ip6_plen) +
					    IPV6_HDR_LEN);
					DTRACE_IP7(send, mblk_t *, mp,
					    conn_t *, NULL, void_ip_t *, ip6h,
					    __dtrace_ipsr_ill_t *, out_ill,
					    ipha_t *, NULL, ip6_t *, ip6h, int,
					    0);
					ipsec_hw_putnext(stq, mp);
				}
			}

			if (nce->nce_flags & (NCE_F_NONUD|NCE_F_PERMANENT)) {
				if (ire != save_ire) {
					ire_refrele(ire);
				}
				if (multirt_send) {
					ASSERT(ire1 != NULL);
					/*
					 * Proceed with the next RTF_MULTIRT
					 * ire, also set up the send-to queue
					 * accordingly.
					 */
					ire = ire1;
					ire1 = NULL;
					stq = ire->ire_stq;
					nce = ire->ire_nce;
					ill = ire_to_ill(ire);
					mp = next_mp;
					next_mp = NULL;
					continue;
				}
				ASSERT(next_mp == NULL);
				ASSERT(ire1 == NULL);
				return;
			}

			ASSERT(nce->nce_state != ND_INCOMPLETE);

			/*
			 * Check for upper layer advice
			 */
			if (flags & IPV6_REACHABILITY_CONFIRMATION) {
				/*
				 * It should be o.k. to check the state without
				 * a lock here, at most we lose an advice.
				 */
				nce->nce_last = TICK_TO_MSEC(lbolt64);
				if (nce->nce_state != ND_REACHABLE) {

					mutex_enter(&nce->nce_lock);
					nce->nce_state = ND_REACHABLE;
					nce->nce_pcnt = ND_MAX_UNICAST_SOLICIT;
					mutex_exit(&nce->nce_lock);
					(void) untimeout(nce->nce_timeout_id);
					if (ip_debug > 2) {
						/* ip1dbg */
						pr_addr_dbg("ip_xmit_v6: state"
						    " for %s changed to"
						    " REACHABLE\n", AF_INET6,
						    &ire->ire_addr_v6);
					}
				}
				if (ire != save_ire) {
					ire_refrele(ire);
				}
				if (multirt_send) {
					ASSERT(ire1 != NULL);
					/*
					 * Proceed with the next RTF_MULTIRT
					 * ire, also set up the send-to queue
					 * accordingly.
					 */
					ire = ire1;
					ire1 = NULL;
					stq = ire->ire_stq;
					nce = ire->ire_nce;
					ill = ire_to_ill(ire);
					mp = next_mp;
					next_mp = NULL;
					continue;
				}
				ASSERT(next_mp == NULL);
				ASSERT(ire1 == NULL);
				return;
			}

			delta =  TICK_TO_MSEC(lbolt64) - nce->nce_last;
			ip1dbg(("ip_xmit_v6: delta = %" PRId64
			    " ill_reachable_time = %d \n", delta,
			    ill->ill_reachable_time));
			if (delta > (uint64_t)ill->ill_reachable_time) {
				nce = ire->ire_nce;
				mutex_enter(&nce->nce_lock);
				switch (nce->nce_state) {
				case ND_REACHABLE:
				case ND_STALE:
					/*
					 * ND_REACHABLE is identical to
					 * ND_STALE in this specific case. If
					 * reachable time has expired for this
					 * neighbor (delta is greater than
					 * reachable time), conceptually, the
					 * neighbor cache is no longer in
					 * REACHABLE state, but already in
					 * STALE state.  So the correct
					 * transition here is to ND_DELAY.
					 */
					nce->nce_state = ND_DELAY;
					mutex_exit(&nce->nce_lock);
					NDP_RESTART_TIMER(nce,
					    ipst->ips_delay_first_probe_time);
					if (ip_debug > 3) {
						/* ip2dbg */
						pr_addr_dbg("ip_xmit_v6: state"
						    " for %s changed to"
						    " DELAY\n", AF_INET6,
						    &ire->ire_addr_v6);
					}
					break;
				case ND_DELAY:
				case ND_PROBE:
					mutex_exit(&nce->nce_lock);
					/* Timers have already started */
					break;
				case ND_UNREACHABLE:
					/*
					 * ndp timer has detected that this nce
					 * is unreachable and initiated deleting
					 * this nce and all its associated IREs.
					 * This is a race where we found the
					 * ire before it was deleted and have
					 * just sent out a packet using this
					 * unreachable nce.
					 */
					mutex_exit(&nce->nce_lock);
					break;
				default:
					ASSERT(0);
				}
			}

			if (multirt_send) {
				ASSERT(ire1 != NULL);
				/*
				 * Proceed with the next RTF_MULTIRT ire,
				 * Also set up the send-to queue accordingly.
				 */
				if (ire != save_ire) {
					ire_refrele(ire);
				}
				ire = ire1;
				ire1 = NULL;
				stq = ire->ire_stq;
				nce = ire->ire_nce;
				ill = ire_to_ill(ire);
				mp = next_mp;
				next_mp = NULL;
			}
		} while (multirt_send);
		/*
		 * In the multirouting case, release the last ire used for
		 * emission. save_ire will be released by the caller.
		 */
		if (ire != save_ire) {
			ire_refrele(ire);
		}
	} else {
		/*
		 * Queue packet if we have an conn to give back pressure.
		 * We can't queue packets intended for hardware acceleration
		 * since we've tossed that state already. If the packet is
		 * being fed back from ire_send_v6, we don't know the
		 * position in the queue to enqueue the packet and we discard
		 * the packet.
		 */
		if (ipst->ips_ip_output_queue && (connp != NULL) &&
		    (io == NULL) && (caller != IRE_SEND)) {
			if (caller == IP_WSRV) {
				connp->conn_did_putbq = 1;
				(void) putbq(connp->conn_wq, mp);
				conn_drain_insert(connp);
				/*
				 * caller == IP_WSRV implies we are
				 * the service thread, and the
				 * queue is already noenabled.
				 * The check for canput and
				 * the putbq is not atomic.
				 * So we need to check again.
				 */
				if (canput(stq->q_next))
					connp->conn_did_putbq = 0;
			} else {
				(void) putq(connp->conn_wq, mp);
			}
			return;
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		freemsg(mp);
		return;
	}
}

/*
 * pr_addr_dbg function provides the needed buffer space to call
 * inet_ntop() function's 3rd argument. This function should be
 * used by any kernel routine which wants to save INET6_ADDRSTRLEN
 * stack buffer space in it's own stack frame. This function uses
 * a buffer from it's own stack and prints the information.
 * Example: pr_addr_dbg("func: no route for %s\n ", AF_INET, addr)
 *
 * Note:    This function can call inet_ntop() once.
 */
void
pr_addr_dbg(char *fmt1, int af, const void *addr)
{
	char	buf[INET6_ADDRSTRLEN];

	if (fmt1 == NULL) {
		ip0dbg(("pr_addr_dbg: Wrong arguments\n"));
		return;
	}

	/*
	 * This does not compare debug level and just prints
	 * out. Thus it is the responsibility of the caller
	 * to check the appropriate debug-level before calling
	 * this function.
	 */
	if (ip_debug > 0) {
		printf(fmt1, inet_ntop(af, addr, buf, sizeof (buf)));
	}


}


/*
 * Return the length in bytes of the IPv6 headers (base header, ip6i_t
 * if needed and extension headers) that will be needed based on the
 * ip6_pkt_t structure passed by the caller.
 *
 * The returned length does not include the length of the upper level
 * protocol (ULP) header.
 */
int
ip_total_hdrs_len_v6(ip6_pkt_t *ipp)
{
	int len;

	len = IPV6_HDR_LEN;
	if (ipp->ipp_fields & IPPF_HAS_IP6I)
		len += sizeof (ip6i_t);
	if (ipp->ipp_fields & IPPF_HOPOPTS) {
		ASSERT(ipp->ipp_hopoptslen != 0);
		len += ipp->ipp_hopoptslen;
	}
	if (ipp->ipp_fields & IPPF_RTHDR) {
		ASSERT(ipp->ipp_rthdrlen != 0);
		len += ipp->ipp_rthdrlen;
	}
	/*
	 * En-route destination options
	 * Only do them if there's a routing header as well
	 */
	if ((ipp->ipp_fields & (IPPF_RTDSTOPTS|IPPF_RTHDR)) ==
	    (IPPF_RTDSTOPTS|IPPF_RTHDR)) {
		ASSERT(ipp->ipp_rtdstoptslen != 0);
		len += ipp->ipp_rtdstoptslen;
	}
	if (ipp->ipp_fields & IPPF_DSTOPTS) {
		ASSERT(ipp->ipp_dstoptslen != 0);
		len += ipp->ipp_dstoptslen;
	}
	return (len);
}

/*
 * All-purpose routine to build a header chain of an IPv6 header
 * followed by any required extension headers and a proto header,
 * preceeded (where necessary) by an ip6i_t private header.
 *
 * The fields of the IPv6 header that are derived from the ip6_pkt_t
 * will be filled in appropriately.
 * Thus the caller must fill in the rest of the IPv6 header, such as
 * traffic class/flowid, source address (if not set here), hoplimit (if not
 * set here) and destination address.
 *
 * The extension headers and ip6i_t header will all be fully filled in.
 */
void
ip_build_hdrs_v6(uchar_t *ext_hdrs, uint_t ext_hdrs_len,
    ip6_pkt_t *ipp, uint8_t protocol)
{
	uint8_t *nxthdr_ptr;
	uint8_t *cp;
	ip6i_t	*ip6i;
	ip6_t	*ip6h = (ip6_t *)ext_hdrs;

	/*
	 * If sending private ip6i_t header down (checksum info, nexthop,
	 * or ifindex), adjust ip header pointer and set ip6i_t header pointer,
	 * then fill it in. (The checksum info will be filled in by icmp).
	 */
	if (ipp->ipp_fields & IPPF_HAS_IP6I) {
		ip6i = (ip6i_t *)ip6h;
		ip6h = (ip6_t *)&ip6i[1];

		ip6i->ip6i_flags = 0;
		ip6i->ip6i_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
		if (ipp->ipp_fields & IPPF_IFINDEX ||
		    ipp->ipp_fields & IPPF_SCOPE_ID) {
			ASSERT(ipp->ipp_ifindex != 0);
			ip6i->ip6i_flags |= IP6I_IFINDEX;
			ip6i->ip6i_ifindex = ipp->ipp_ifindex;
		}
		if (ipp->ipp_fields & IPPF_ADDR) {
			/*
			 * Enable per-packet source address verification if
			 * IPV6_PKTINFO specified the source address.
			 * ip6_src is set in the transport's _wput function.
			 */
			ASSERT(!IN6_IS_ADDR_UNSPECIFIED(
			    &ipp->ipp_addr));
			ip6i->ip6i_flags |= IP6I_VERIFY_SRC;
		}
		if (ipp->ipp_fields & IPPF_UNICAST_HOPS) {
			ip6h->ip6_hops = ipp->ipp_unicast_hops;
			/*
			 * We need to set this flag so that IP doesn't
			 * rewrite the IPv6 header's hoplimit with the
			 * current default value.
			 */
			ip6i->ip6i_flags |= IP6I_HOPLIMIT;
		}
		if (ipp->ipp_fields & IPPF_NEXTHOP) {
			ASSERT(!IN6_IS_ADDR_UNSPECIFIED(
			    &ipp->ipp_nexthop));
			ip6i->ip6i_flags |= IP6I_NEXTHOP;
			ip6i->ip6i_nexthop = ipp->ipp_nexthop;
		}
		/*
		 * tell IP this is an ip6i_t private header
		 */
		ip6i->ip6i_nxt = IPPROTO_RAW;
	}
	/* Initialize IPv6 header */
	ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	if (ipp->ipp_fields & IPPF_TCLASS) {
		ip6h->ip6_vcf = (ip6h->ip6_vcf & ~IPV6_FLOWINFO_TCLASS) |
		    (ipp->ipp_tclass << 20);
	}
	if (ipp->ipp_fields & IPPF_ADDR)
		ip6h->ip6_src = ipp->ipp_addr;

	nxthdr_ptr = (uint8_t *)&ip6h->ip6_nxt;
	cp = (uint8_t *)&ip6h[1];
	/*
	 * Here's where we have to start stringing together
	 * any extension headers in the right order:
	 * Hop-by-hop, destination, routing, and final destination opts.
	 */
	if (ipp->ipp_fields & IPPF_HOPOPTS) {
		/* Hop-by-hop options */
		ip6_hbh_t *hbh = (ip6_hbh_t *)cp;

		*nxthdr_ptr = IPPROTO_HOPOPTS;
		nxthdr_ptr = &hbh->ip6h_nxt;

		bcopy(ipp->ipp_hopopts, cp, ipp->ipp_hopoptslen);
		cp += ipp->ipp_hopoptslen;
	}
	/*
	 * En-route destination options
	 * Only do them if there's a routing header as well
	 */
	if ((ipp->ipp_fields & (IPPF_RTDSTOPTS|IPPF_RTHDR)) ==
	    (IPPF_RTDSTOPTS|IPPF_RTHDR)) {
		ip6_dest_t *dst = (ip6_dest_t *)cp;

		*nxthdr_ptr = IPPROTO_DSTOPTS;
		nxthdr_ptr = &dst->ip6d_nxt;

		bcopy(ipp->ipp_rtdstopts, cp, ipp->ipp_rtdstoptslen);
		cp += ipp->ipp_rtdstoptslen;
	}
	/*
	 * Routing header next
	 */
	if (ipp->ipp_fields & IPPF_RTHDR) {
		ip6_rthdr_t *rt = (ip6_rthdr_t *)cp;

		*nxthdr_ptr = IPPROTO_ROUTING;
		nxthdr_ptr = &rt->ip6r_nxt;

		bcopy(ipp->ipp_rthdr, cp, ipp->ipp_rthdrlen);
		cp += ipp->ipp_rthdrlen;
	}
	/*
	 * Do ultimate destination options
	 */
	if (ipp->ipp_fields & IPPF_DSTOPTS) {
		ip6_dest_t *dest = (ip6_dest_t *)cp;

		*nxthdr_ptr = IPPROTO_DSTOPTS;
		nxthdr_ptr = &dest->ip6d_nxt;

		bcopy(ipp->ipp_dstopts, cp, ipp->ipp_dstoptslen);
		cp += ipp->ipp_dstoptslen;
	}
	/*
	 * Now set the last header pointer to the proto passed in
	 */
	*nxthdr_ptr = protocol;
	ASSERT((int)(cp - ext_hdrs) == ext_hdrs_len);
}

/*
 * Return a pointer to the routing header extension header
 * in the IPv6 header(s) chain passed in.
 * If none found, return NULL
 * Assumes that all extension headers are in same mblk as the v6 header
 */
ip6_rthdr_t *
ip_find_rthdr_v6(ip6_t *ip6h, uint8_t *endptr)
{
	ip6_dest_t	*desthdr;
	ip6_frag_t	*fraghdr;
	uint_t		hdrlen;
	uint8_t		nexthdr;
	uint8_t		*ptr = (uint8_t *)&ip6h[1];

	if (ip6h->ip6_nxt == IPPROTO_ROUTING)
		return ((ip6_rthdr_t *)ptr);

	/*
	 * The routing header will precede all extension headers
	 * other than the hop-by-hop and destination options
	 * extension headers, so if we see anything other than those,
	 * we're done and didn't find it.
	 * We could see a destination options header alone but no
	 * routing header, in which case we'll return NULL as soon as
	 * we see anything after that.
	 * Hop-by-hop and destination option headers are identical,
	 * so we can use either one we want as a template.
	 */
	nexthdr = ip6h->ip6_nxt;
	while (ptr < endptr) {
		/* Is there enough left for len + nexthdr? */
		if (ptr + MIN_EHDR_LEN > endptr)
			return (NULL);

		switch (nexthdr) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
			/* Assumes the headers are identical for hbh and dst */
			desthdr = (ip6_dest_t *)ptr;
			hdrlen = 8 * (desthdr->ip6d_len + 1);
			nexthdr = desthdr->ip6d_nxt;
			break;

		case IPPROTO_ROUTING:
			return ((ip6_rthdr_t *)ptr);

		case IPPROTO_FRAGMENT:
			fraghdr = (ip6_frag_t *)ptr;
			hdrlen = sizeof (ip6_frag_t);
			nexthdr = fraghdr->ip6f_nxt;
			break;

		default:
			return (NULL);
		}
		ptr += hdrlen;
	}
	return (NULL);
}

/*
 * Called for source-routed packets originating on this node.
 * Manipulates the original routing header by moving every entry up
 * one slot, placing the first entry in the v6 header's v6_dst field,
 * and placing the ultimate destination in the routing header's last
 * slot.
 *
 * Returns the checksum diference between the ultimate destination
 * (last hop in the routing header when the packet is sent) and
 * the first hop (ip6_dst when the packet is sent)
 */
/* ARGSUSED2 */
uint32_t
ip_massage_options_v6(ip6_t *ip6h, ip6_rthdr_t *rth, netstack_t *ns)
{
	uint_t		numaddr;
	uint_t		i;
	in6_addr_t	*addrptr;
	in6_addr_t	tmp;
	ip6_rthdr0_t	*rthdr = (ip6_rthdr0_t *)rth;
	uint32_t	cksm;
	uint32_t	addrsum = 0;
	uint16_t	*ptr;

	/*
	 * Perform any processing needed for source routing.
	 * We know that all extension headers will be in the same mblk
	 * as the IPv6 header.
	 */

	/*
	 * If no segments left in header, or the header length field is zero,
	 * don't move hop addresses around;
	 * Checksum difference is zero.
	 */
	if ((rthdr->ip6r0_segleft == 0) || (rthdr->ip6r0_len == 0))
		return (0);

	ptr = (uint16_t *)&ip6h->ip6_dst;
	cksm = 0;
	for (i = 0; i < (sizeof (in6_addr_t) / sizeof (uint16_t)); i++) {
		cksm += ptr[i];
	}
	cksm = (cksm & 0xFFFF) + (cksm >> 16);

	/*
	 * Here's where the fun begins - we have to
	 * move all addresses up one spot, take the
	 * first hop and make it our first ip6_dst,
	 * and place the ultimate destination in the
	 * newly-opened last slot.
	 */
	addrptr = (in6_addr_t *)((char *)rthdr + sizeof (*rthdr));
	numaddr = rthdr->ip6r0_len / 2;
	tmp = *addrptr;
	for (i = 0; i < (numaddr - 1); addrptr++, i++) {
		*addrptr = addrptr[1];
	}
	*addrptr = ip6h->ip6_dst;
	ip6h->ip6_dst = tmp;

	/*
	 * From the checksummed ultimate destination subtract the checksummed
	 * current ip6_dst (the first hop address). Return that number.
	 * (In the v4 case, the second part of this is done in each routine
	 *  that calls ip_massage_options(). We do it all in this one place
	 *  for v6).
	 */
	ptr = (uint16_t *)&ip6h->ip6_dst;
	for (i = 0; i < (sizeof (in6_addr_t) / sizeof (uint16_t)); i++) {
		addrsum += ptr[i];
	}
	cksm -= ((addrsum >> 16) + (addrsum & 0xFFFF));
	if ((int)cksm < 0)
		cksm--;
	cksm = (cksm & 0xFFFF) + (cksm >> 16);

	return (cksm);
}

/*
 * Propagate a multicast group membership operation (join/leave) (*fn) on
 * all interfaces crossed by the related multirt routes.
 * The call is considered successful if the operation succeeds
 * on at least one interface.
 * The function is called if the destination address in the packet to send
 * is multirouted.
 */
int
ip_multirt_apply_membership_v6(int (*fn)(conn_t *, boolean_t,
    const in6_addr_t *, int, mcast_record_t, const in6_addr_t *, mblk_t *),
    ire_t *ire, conn_t *connp, boolean_t checkonly, const in6_addr_t *v6grp,
    mcast_record_t fmode, const in6_addr_t *v6src, mblk_t *first_mp)
{
	ire_t		*ire_gw;
	irb_t		*irb;
	int		index, error = 0;
	opt_restart_t	*or;
	ip_stack_t	*ipst = ire->ire_ipst;

	irb = ire->ire_bucket;
	ASSERT(irb != NULL);

	ASSERT(DB_TYPE(first_mp) == M_CTL);
	or = (opt_restart_t *)first_mp->b_rptr;

	IRB_REFHOLD(irb);
	for (; ire != NULL; ire = ire->ire_next) {
		if ((ire->ire_flags & RTF_MULTIRT) == 0)
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6, v6grp))
			continue;

		ire_gw = ire_ftable_lookup_v6(&ire->ire_gateway_addr_v6, 0, 0,
		    IRE_INTERFACE, NULL, NULL, ALL_ZONES, 0, NULL,
		    MATCH_IRE_RECURSIVE | MATCH_IRE_TYPE, ipst);
		/* No resolver exists for the gateway; skip this ire. */
		if (ire_gw == NULL)
			continue;
		index = ire_gw->ire_ipif->ipif_ill->ill_phyint->phyint_ifindex;
		/*
		 * A resolver exists: we can get the interface on which we have
		 * to apply the operation.
		 */
		error = fn(connp, checkonly, v6grp, index, fmode, v6src,
		    first_mp);
		if (error == 0)
			or->or_private = CGTP_MCAST_SUCCESS;

		if (ip_debug > 0) {
			ulong_t	off;
			char	*ksym;

			ksym = kobj_getsymname((uintptr_t)fn, &off);
			ip2dbg(("ip_multirt_apply_membership_v6: "
			    "called %s, multirt group 0x%08x via itf 0x%08x, "
			    "error %d [success %u]\n",
			    ksym ? ksym : "?",
			    ntohl(V4_PART_OF_V6((*v6grp))),
			    ntohl(V4_PART_OF_V6(ire_gw->ire_src_addr_v6)),
			    error, or->or_private));
		}

		ire_refrele(ire_gw);
		if (error == EINPROGRESS) {
			IRB_REFRELE(irb);
			return (error);
		}
	}
	IRB_REFRELE(irb);
	/*
	 * Consider the call as successful if we succeeded on at least
	 * one interface. Otherwise, return the last encountered error.
	 */
	return (or->or_private == CGTP_MCAST_SUCCESS ? 0 : error);
}

void
*ip6_kstat_init(netstackid_t stackid, ip6_stat_t *ip6_statisticsp)
{
	kstat_t *ksp;

	ip6_stat_t template = {
		{ "ip6_udp_fast_path", 	KSTAT_DATA_UINT64 },
		{ "ip6_udp_slow_path", 	KSTAT_DATA_UINT64 },
		{ "ip6_udp_fannorm", 	KSTAT_DATA_UINT64 },
		{ "ip6_udp_fanmb", 	KSTAT_DATA_UINT64 },
		{ "ip6_out_sw_cksum",			KSTAT_DATA_UINT64 },
		{ "ip6_in_sw_cksum",			KSTAT_DATA_UINT64 },
		{ "ip6_tcp_in_full_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip6_tcp_in_part_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip6_tcp_in_sw_cksum_err",		KSTAT_DATA_UINT64 },
		{ "ip6_tcp_out_sw_cksum_bytes",		KSTAT_DATA_UINT64 },
		{ "ip6_udp_in_full_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip6_udp_in_part_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip6_udp_in_sw_cksum_err",		KSTAT_DATA_UINT64 },
		{ "ip6_udp_out_sw_cksum_bytes",		KSTAT_DATA_UINT64 },
		{ "ip6_frag_mdt_pkt_out",		KSTAT_DATA_UINT64 },
		{ "ip6_frag_mdt_discarded",		KSTAT_DATA_UINT64 },
		{ "ip6_frag_mdt_allocfail",		KSTAT_DATA_UINT64 },
		{ "ip6_frag_mdt_addpdescfail",		KSTAT_DATA_UINT64 },
		{ "ip6_frag_mdt_allocd",		KSTAT_DATA_UINT64 },
	};
	ksp = kstat_create_netstack("ip", 0, "ip6stat", "net",
	    KSTAT_TYPE_NAMED, sizeof (template) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, stackid);

	if (ksp == NULL)
		return (NULL);

	bcopy(&template, ip6_statisticsp, sizeof (template));
	ksp->ks_data = (void *)ip6_statisticsp;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

void
ip6_kstat_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

/*
 * The following two functions set and get the value for the
 * IPV6_SRC_PREFERENCES socket option.
 */
int
ip6_set_src_preferences(conn_t *connp, uint32_t prefs)
{
	/*
	 * We only support preferences that are covered by
	 * IPV6_PREFER_SRC_MASK.
	 */
	if (prefs & ~IPV6_PREFER_SRC_MASK)
		return (EINVAL);

	/*
	 * Look for conflicting preferences or default preferences.  If
	 * both bits of a related pair are clear, the application wants the
	 * system's default value for that pair.  Both bits in a pair can't
	 * be set.
	 */
	if ((prefs & IPV6_PREFER_SRC_MIPMASK) == 0) {
		prefs |= IPV6_PREFER_SRC_MIPDEFAULT;
	} else if ((prefs & IPV6_PREFER_SRC_MIPMASK) ==
	    IPV6_PREFER_SRC_MIPMASK) {
		return (EINVAL);
	}
	if ((prefs & IPV6_PREFER_SRC_TMPMASK) == 0) {
		prefs |= IPV6_PREFER_SRC_TMPDEFAULT;
	} else if ((prefs & IPV6_PREFER_SRC_TMPMASK) ==
	    IPV6_PREFER_SRC_TMPMASK) {
		return (EINVAL);
	}
	if ((prefs & IPV6_PREFER_SRC_CGAMASK) == 0) {
		prefs |= IPV6_PREFER_SRC_CGADEFAULT;
	} else if ((prefs & IPV6_PREFER_SRC_CGAMASK) ==
	    IPV6_PREFER_SRC_CGAMASK) {
		return (EINVAL);
	}

	connp->conn_src_preferences = prefs;
	return (0);
}

size_t
ip6_get_src_preferences(conn_t *connp, uint32_t *val)
{
	*val = connp->conn_src_preferences;
	return (sizeof (connp->conn_src_preferences));
}

int
ip6_set_pktinfo(cred_t *cr, conn_t *connp, struct in6_pktinfo *pkti, mblk_t *mp)
{
	ill_t	*ill;
	ire_t	*ire;
	int	error;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	/*
	 * Verify the source address and ifindex. Privileged users can use
	 * any source address.  For ancillary data the source address is
	 * checked in ip_wput_v6.
	 */
	if (pkti->ipi6_ifindex != 0) {
		ASSERT(connp != NULL);
		ill = ill_lookup_on_ifindex(pkti->ipi6_ifindex, B_TRUE,
		    CONNP_TO_WQ(connp), mp, ip_restart_optmgmt, &error, ipst);
		if (ill == NULL) {
			/*
			 * We just want to know if the interface exists, we
			 * don't really care about the ill pointer itself.
			 */
			if (error != EINPROGRESS)
				return (error);
			error = 0;	/* Ensure we don't use it below */
		} else {
			ill_refrele(ill);
		}
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&pkti->ipi6_addr) &&
	    secpolicy_net_rawaccess(cr) != 0) {
		ire = ire_route_lookup_v6(&pkti->ipi6_addr, 0, 0,
		    (IRE_LOCAL|IRE_LOOPBACK), NULL, NULL,
		    connp->conn_zoneid, NULL, MATCH_IRE_TYPE, ipst);
		if (ire != NULL)
			ire_refrele(ire);
		else
			return (ENXIO);
	}
	return (0);
}

/*
 * Get the size of the IP options (including the IP headers size)
 * without including the AH header's size. If till_ah is B_FALSE,
 * and if AH header is present, dest options beyond AH header will
 * also be included in the returned size.
 */
int
ipsec_ah_get_hdr_size_v6(mblk_t *mp, boolean_t till_ah)
{
	ip6_t *ip6h;
	uint8_t nexthdr;
	uint8_t *whereptr;
	ip6_hbh_t *hbhhdr;
	ip6_dest_t *dsthdr;
	ip6_rthdr_t *rthdr;
	int ehdrlen;
	int size;
	ah_t *ah;

	ip6h = (ip6_t *)mp->b_rptr;
	size = IPV6_HDR_LEN;
	nexthdr = ip6h->ip6_nxt;
	whereptr = (uint8_t *)&ip6h[1];
	for (;;) {
		/* Assume IP has already stripped it */
		ASSERT(nexthdr != IPPROTO_FRAGMENT && nexthdr != IPPROTO_RAW);
		switch (nexthdr) {
		case IPPROTO_HOPOPTS:
			hbhhdr = (ip6_hbh_t *)whereptr;
			nexthdr = hbhhdr->ip6h_nxt;
			ehdrlen = 8 * (hbhhdr->ip6h_len + 1);
			break;
		case IPPROTO_DSTOPTS:
			dsthdr = (ip6_dest_t *)whereptr;
			nexthdr = dsthdr->ip6d_nxt;
			ehdrlen = 8 * (dsthdr->ip6d_len + 1);
			break;
		case IPPROTO_ROUTING:
			rthdr = (ip6_rthdr_t *)whereptr;
			nexthdr = rthdr->ip6r_nxt;
			ehdrlen = 8 * (rthdr->ip6r_len + 1);
			break;
		default :
			if (till_ah) {
				ASSERT(nexthdr == IPPROTO_AH);
				return (size);
			}
			/*
			 * If we don't have a AH header to traverse,
			 * return now. This happens normally for
			 * outbound datagrams where we have not inserted
			 * the AH header.
			 */
			if (nexthdr != IPPROTO_AH) {
				return (size);
			}

			/*
			 * We don't include the AH header's size
			 * to be symmetrical with other cases where
			 * we either don't have a AH header (outbound)
			 * or peek into the AH header yet (inbound and
			 * not pulled up yet).
			 */
			ah = (ah_t *)whereptr;
			nexthdr = ah->ah_nexthdr;
			ehdrlen = (ah->ah_length << 2) + 8;

			if (nexthdr == IPPROTO_DSTOPTS) {
				if (whereptr + ehdrlen >= mp->b_wptr) {
					/*
					 * The destination options header
					 * is not part of the first mblk.
					 */
					whereptr = mp->b_cont->b_rptr;
				} else {
					whereptr += ehdrlen;
				}

				dsthdr = (ip6_dest_t *)whereptr;
				ehdrlen = 8 * (dsthdr->ip6d_len + 1);
				size += ehdrlen;
			}
			return (size);
		}
		whereptr += ehdrlen;
		size += ehdrlen;
	}
}
