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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 1990 Mentat Inc.
 * Copyright 2017 OmniTI Computer Consulting, Inc. All rights reserved.
 */

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
#include <sys/policy.h>
#include <sys/mac.h>
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
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <inet/iptun/iptun_impl.h>
#include <inet/sctp_ip.h>
#include <sys/pattr.h>
#include <inet/ipclassifier.h>
#include <inet/ipsecah.h>
#include <inet/rawip_impl.h>
#include <inet/rts_impl.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

/* Temporary; for CR 6451644 work-around */
#include <sys/ethernet.h>

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

static boolean_t icmp_inbound_verify_v6(mblk_t *, icmp6_t *, ip_recv_attr_t *);
static void	icmp_inbound_too_big_v6(icmp6_t *, ip_recv_attr_t *);
static void	icmp_pkt_v6(mblk_t *, void *, size_t, const in6_addr_t *,
    ip_recv_attr_t *);
static void	icmp_redirect_v6(mblk_t *, ip6_t *, nd_redirect_t *,
    ip_recv_attr_t *);
static void	icmp_send_redirect_v6(mblk_t *, in6_addr_t *,
    in6_addr_t *, ip_recv_attr_t *);
static void	icmp_send_reply_v6(mblk_t *, ip6_t *, icmp6_t *,
    ip_recv_attr_t *);
static boolean_t	ip_source_routed_v6(ip6_t *, mblk_t *, ip_stack_t *);

/*
 * icmp_inbound_v6 deals with ICMP messages that are handled by IP.
 * If the ICMP message is consumed by IP, i.e., it should not be delivered
 * to any IPPROTO_ICMP raw sockets, then it returns NULL.
 * Likewise, if the ICMP error is misformed (too short, etc), then it
 * returns NULL. The caller uses this to determine whether or not to send
 * to raw sockets.
 *
 * All error messages are passed to the matching transport stream.
 *
 * See comment for icmp_inbound_v4() on how IPsec is handled.
 */
mblk_t *
icmp_inbound_v6(mblk_t *mp, ip_recv_attr_t *ira)
{
	icmp6_t		*icmp6;
	ip6_t		*ip6h;		/* Outer header */
	int		ip_hdr_length;	/* Outer header length */
	boolean_t	interested;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	mblk_t		*mp_ret = NULL;

	ip6h = (ip6_t *)mp->b_rptr;

	BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInMsgs);

	/* Check for Martian packets  */
	if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_src)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
		ip_drop_input("ipIfStatsInAddrErrors: mcast src", mp, ill);
		freemsg(mp);
		return (NULL);
	}

	/* Make sure ira_l2src is set for ndp_input */
	if (!(ira->ira_flags & IRAF_L2SRC_SET))
		ip_setl2src(mp, ira, ira->ira_rill);

	ip_hdr_length = ira->ira_ip_hdr_length;
	if ((mp->b_wptr - mp->b_rptr) < (ip_hdr_length + ICMP6_MINLEN)) {
		if (ira->ira_pktlen < (ip_hdr_length + ICMP6_MINLEN)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
			ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		ip6h = ip_pullup(mp, ip_hdr_length + ICMP6_MINLEN, ira);
		if (ip6h == NULL) {
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInErrors);
			freemsg(mp);
			return (NULL);
		}
	}

	icmp6 = (icmp6_t *)(&mp->b_rptr[ip_hdr_length]);
	DTRACE_PROBE2(icmp__inbound__v6, ip6_t *, ip6h, icmp6_t *, icmp6);
	ip2dbg(("icmp_inbound_v6: type %d code %d\n", icmp6->icmp6_type,
	    icmp6->icmp6_code));

	/*
	 * We will set "interested" to "true" if we should pass a copy to
	 * the transport i.e., if it is an error message.
	 */
	interested = !(icmp6->icmp6_type & ICMP6_INFOMSG_MASK);

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
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInPktTooBigs);
		break;

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
			if (mp1 == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards - copymsg",
				    mp, ill);
				freemsg(mp);
				return (NULL);
			}
			freemsg(mp);
			mp = mp1;
			ip6h = (ip6_t *)mp->b_rptr;
			icmp6 = (icmp6_t *)(&mp->b_rptr[ip_hdr_length]);
		}

		icmp6->icmp6_type = ICMP6_ECHO_REPLY;
		icmp_send_reply_v6(mp, ip6h, icmp6, ira);
		return (NULL);

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
		ndp_input(mp, ira);
		return (NULL);

	case ND_NEIGHBOR_ADVERT:
		BUMP_MIB(ill->ill_icmp6_mib,
		    ipv6IfIcmpInNeighborAdvertisements);
		ndp_input(mp, ira);
		return (NULL);

	case ND_REDIRECT:
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInRedirects);

		if (ipst->ips_ipv6_ignore_redirect)
			break;

		/* We now allow a RAW socket to receive this. */
		interested = B_TRUE;
		break;

	/*
	 * The next three icmp messages will be handled by MLD.
	 * Pass all valid MLD packets up to any process(es)
	 * listening on a raw ICMP socket.
	 */
	case MLD_LISTENER_QUERY:
	case MLD_LISTENER_REPORT:
	case MLD_LISTENER_REDUCTION:
		mp = mld_input(mp, ira);
		return (mp);
	default:
		break;
	}
	/*
	 * See if there is an ICMP client to avoid an extra copymsg/freemsg
	 * if there isn't one.
	 */
	if (ipst->ips_ipcl_proto_fanout_v6[IPPROTO_ICMPV6].connf_head != NULL) {
		/* If there is an ICMP client and we want one too, copy it. */

		if (!interested) {
			/* Caller will deliver to RAW sockets */
			return (mp);
		}
		mp_ret = copymsg(mp);
		if (mp_ret == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards - copymsg", mp, ill);
		}
	} else if (!interested) {
		/* Neither we nor raw sockets are interested. Drop packet now */
		freemsg(mp);
		return (NULL);
	}

	/*
	 * ICMP error or redirect packet. Make sure we have enough of
	 * the header and that db_ref == 1 since we might end up modifying
	 * the packet.
	 */
	if (mp->b_cont != NULL) {
		if (ip_pullup(mp, -1, ira) == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards - ip_pullup",
			    mp, ill);
			freemsg(mp);
			return (mp_ret);
		}
	}

	if (mp->b_datap->db_ref > 1) {
		mblk_t	*mp1;

		mp1 = copymsg(mp);
		if (mp1 == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards - copymsg", mp, ill);
			freemsg(mp);
			return (mp_ret);
		}
		freemsg(mp);
		mp = mp1;
	}

	/*
	 * In case mp has changed, verify the message before any further
	 * processes.
	 */
	ip6h = (ip6_t *)mp->b_rptr;
	icmp6 = (icmp6_t *)(&mp->b_rptr[ip_hdr_length]);
	if (!icmp_inbound_verify_v6(mp, icmp6, ira)) {
		freemsg(mp);
		return (mp_ret);
	}

	switch (icmp6->icmp6_type) {
	case ND_REDIRECT:
		icmp_redirect_v6(mp, ip6h, (nd_redirect_t *)icmp6, ira);
		break;
	case ICMP6_PACKET_TOO_BIG:
		/* Update DCE and adjust MTU is icmp header if needed */
		icmp_inbound_too_big_v6(icmp6, ira);
		/* FALLTHRU */
	default:
		icmp_inbound_error_fanout_v6(mp, icmp6, ira);
		break;
	}

	return (mp_ret);
}

/*
 * Send an ICMP echo reply.
 * The caller has already updated the payload part of the packet.
 * We handle the ICMP checksum, IP source address selection and feed
 * the packet into ip_output_simple.
 */
static void
icmp_send_reply_v6(mblk_t *mp, ip6_t *ip6h, icmp6_t *icmp6,
    ip_recv_attr_t *ira)
{
	uint_t		ip_hdr_length = ira->ira_ip_hdr_length;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ip_xmit_attr_t	ixas;
	in6_addr_t	origsrc;

	/*
	 * Remove any extension headers (do not reverse a source route)
	 * and clear the flow id (keep traffic class for now).
	 */
	if (ip_hdr_length != IPV6_HDR_LEN) {
		int	i;

		for (i = 0; i < IPV6_HDR_LEN; i++) {
			mp->b_rptr[ip_hdr_length - i - 1] =
			    mp->b_rptr[IPV6_HDR_LEN - i - 1];
		}
		mp->b_rptr += (ip_hdr_length - IPV6_HDR_LEN);
		ip6h = (ip6_t *)mp->b_rptr;
		ip6h->ip6_nxt = IPPROTO_ICMPV6;
		i = ntohs(ip6h->ip6_plen);
		i -= (ip_hdr_length - IPV6_HDR_LEN);
		ip6h->ip6_plen = htons(i);
		ip_hdr_length = IPV6_HDR_LEN;
		ASSERT(ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN == msgdsize(mp));
	}
	ip6h->ip6_vcf &= ~IPV6_FLOWINFO_FLOWLABEL;

	/* Reverse the source and destination addresses. */
	origsrc = ip6h->ip6_src;
	ip6h->ip6_src = ip6h->ip6_dst;
	ip6h->ip6_dst = origsrc;

	/* set the hop limit */
	ip6h->ip6_hops = ipst->ips_ipv6_def_hops;

	/*
	 * Prepare for checksum by putting icmp length in the icmp
	 * checksum field. The checksum is calculated in ip_output
	 */
	icmp6->icmp6_cksum = ip6h->ip6_plen;

	bzero(&ixas, sizeof (ixas));
	ixas.ixa_flags = IXAF_BASIC_SIMPLE_V6;
	ixas.ixa_zoneid = ira->ira_zoneid;
	ixas.ixa_cred = kcred;
	ixas.ixa_cpid = NOPID;
	ixas.ixa_tsl = ira->ira_tsl;	/* Behave as a multi-level responder */
	ixas.ixa_ifindex = 0;
	ixas.ixa_ipst = ipst;
	ixas.ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;

	if (!(ira->ira_flags & IRAF_IPSEC_SECURE)) {
		/*
		 * This packet should go out the same way as it
		 * came in i.e in clear, independent of the IPsec
		 * policy for transmitting packets.
		 */
		ixas.ixa_flags |= IXAF_NO_IPSEC;
	} else {
		if (!ipsec_in_to_out(ira, &ixas, mp, NULL, ip6h)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			/* Note: mp already consumed and ip_drop_packet done */
			return;
		}
	}

	/* Was the destination (now source) link-local? Send out same group */
	if (IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_src)) {
		ixas.ixa_flags |= IXAF_SCOPEID_SET;
		if (IS_UNDER_IPMP(ill))
			ixas.ixa_scopeid = ill_get_upper_ifindex(ill);
		else
			ixas.ixa_scopeid = ill->ill_phyint->phyint_ifindex;
	}

	if (ira->ira_flags & IRAF_MULTIBROADCAST) {
		/*
		 * Not one or our addresses (IRE_LOCALs), thus we let
		 * ip_output_simple pick the source.
		 */
		ip6h->ip6_src = ipv6_all_zeros;
		ixas.ixa_flags |= IXAF_SET_SOURCE;
	}

	/* Should we send using dce_pmtu? */
	if (ipst->ips_ipv6_icmp_return_pmtu)
		ixas.ixa_flags |= IXAF_PMTU_DISCOVERY;

	(void) ip_output_simple(mp, &ixas);
	ixa_cleanup(&ixas);

}

/*
 * Verify the ICMP messages for either for ICMP error or redirect packet.
 * The caller should have fully pulled up the message. If it's a redirect
 * packet, only basic checks on IP header will be done; otherwise, verify
 * the packet by looking at the included ULP header.
 *
 * Called before icmp_inbound_error_fanout_v6 is called.
 */
static boolean_t
icmp_inbound_verify_v6(mblk_t *mp, icmp6_t *icmp6, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	uint16_t	hdr_length;
	uint8_t		*nexthdrp;
	uint8_t		nexthdr;
	ip_stack_t	*ipst = ill->ill_ipst;
	conn_t		*connp;
	ip6_t		*ip6h;	/* Inner header */

	ip6h = (ip6_t *)&icmp6[1];
	if ((uchar_t *)ip6h + IPV6_HDR_LEN > mp->b_wptr)
		goto truncated;

	if (icmp6->icmp6_type == ND_REDIRECT) {
		hdr_length = sizeof (nd_redirect_t);
	} else {
		if ((IPH_HDR_VERSION(ip6h) != IPV6_VERSION))
			goto discard_pkt;
		hdr_length = IPV6_HDR_LEN;
	}

	if ((uchar_t *)ip6h + hdr_length > mp->b_wptr)
		goto truncated;

	/*
	 * Stop here for ICMP_REDIRECT.
	 */
	if (icmp6->icmp6_type == ND_REDIRECT)
		return (B_TRUE);

	/*
	 * ICMP errors only.
	 */
	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &hdr_length, &nexthdrp))
		goto discard_pkt;
	nexthdr = *nexthdrp;

	/* Try to pass the ICMP message to clients who need it */
	switch (nexthdr) {
	case IPPROTO_UDP:
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * transport header.
		 */
		if ((uchar_t *)ip6h + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr)
			goto truncated;
		break;
	case IPPROTO_TCP: {
		tcpha_t		*tcpha;

		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * transport header.
		 */
		if ((uchar_t *)ip6h + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr)
			goto truncated;

		tcpha = (tcpha_t *)((uchar_t *)ip6h + hdr_length);
		/*
		 * With IPMP we need to match across group, which we do
		 * since we have the upper ill from ira_ill.
		 */
		connp = ipcl_tcp_lookup_reversed_ipv6(ip6h, tcpha, TCPS_LISTEN,
		    ill->ill_phyint->phyint_ifindex, ipst);
		if (connp == NULL)
			goto discard_pkt;

		if ((connp->conn_verifyicmp != NULL) &&
		    !connp->conn_verifyicmp(connp, tcpha, NULL, icmp6, ira)) {
			CONN_DEC_REF(connp);
			goto discard_pkt;
		}
		CONN_DEC_REF(connp);
		break;
	}
	case IPPROTO_SCTP:
		/*
		 * Verify we have at least ICMP_MIN_TP_HDR_LEN bytes of
		 * transport header.
		 */
		if ((uchar_t *)ip6h + hdr_length + ICMP_MIN_TP_HDR_LEN >
		    mp->b_wptr)
			goto truncated;
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		break;
	case IPPROTO_ENCAP:
	case IPPROTO_IPV6: {
		/* Look for self-encapsulated packets that caused an error */
		ip6_t *in_ip6h;

		in_ip6h = (ip6_t *)((uint8_t *)ip6h + hdr_length);
		if ((uint8_t *)in_ip6h + (nexthdr == IPPROTO_ENCAP ?
		    sizeof (ipha_t) : sizeof (ip6_t)) > mp->b_wptr)
			goto truncated;
		break;
	}
	default:
		break;
	}

	return (B_TRUE);

discard_pkt:
	/* Bogus ICMP error. */
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
	return (B_FALSE);

truncated:
	/* We pulled up everthing already. Must be truncated */
	BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInErrors);
	return (B_FALSE);
}

/*
 * Process received IPv6 ICMP Packet too big.
 * The caller is responsible for validating the packet before passing it in
 * and also to fanout the ICMP error to any matching transport conns. Assumes
 * the message has been fully pulled up.
 *
 * Before getting here, the caller has called icmp_inbound_verify_v6()
 * that should have verified with ULP to prevent undoing the changes we're
 * going to make to DCE. For example, TCP might have verified that the packet
 * which generated error is in the send window.
 *
 * In some cases modified this MTU in the ICMP header packet; the caller
 * should pass to the matching ULP after this returns.
 */
static void
icmp_inbound_too_big_v6(icmp6_t *icmp6, ip_recv_attr_t *ira)
{
	uint32_t	mtu;
	dce_t		*dce;
	ill_t		*ill = ira->ira_ill;	/* Upper ill if IPMP */
	ip_stack_t	*ipst = ill->ill_ipst;
	int		old_max_frag;
	in6_addr_t	final_dst;
	ip6_t		*ip6h;	/* Inner IP header */

	/* Caller has already pulled up everything. */
	ip6h = (ip6_t *)&icmp6[1];
	final_dst = ip_get_dst_v6(ip6h, NULL, NULL);

	mtu = ntohl(icmp6->icmp6_mtu);
	if (mtu < IPV6_MIN_MTU) {
		/*
		 * RFC 8021 suggests to ignore messages where mtu is
		 * less than the IPv6 minimum.
		 */
		ip1dbg(("Received mtu less than IPv6 "
		    "min mtu %d: %d\n", IPV6_MIN_MTU, mtu));
		DTRACE_PROBE1(icmp6__too__small__mtu, uint32_t, mtu);
		return;
	}

	/*
	 * For link local destinations matching simply on address is not
	 * sufficient. Same link local addresses for different ILL's is
	 * possible.
	 */
	if (IN6_IS_ADDR_LINKSCOPE(&final_dst)) {
		dce = dce_lookup_and_add_v6(&final_dst,
		    ill->ill_phyint->phyint_ifindex, ipst);
	} else {
		dce = dce_lookup_and_add_v6(&final_dst, 0, ipst);
	}
	if (dce == NULL) {
		/* Couldn't add a unique one - ENOMEM */
		if (ip_debug > 2) {
			/* ip1dbg */
			pr_addr_dbg("icmp_inbound_too_big_v6:"
			    "no dce for dst %s\n", AF_INET6,
			    &final_dst);
		}
		return;
	}

	mutex_enter(&dce->dce_lock);
	if (dce->dce_flags & DCEF_PMTU)
		old_max_frag = dce->dce_pmtu;
	else if (IN6_IS_ADDR_MULTICAST(&final_dst))
		old_max_frag = ill->ill_mc_mtu;
	else
		old_max_frag = ill->ill_mtu;

	ip1dbg(("Received mtu from router: %d\n", mtu));
	DTRACE_PROBE1(icmp6__received__mtu, uint32_t, mtu);
	dce->dce_pmtu = MIN(old_max_frag, mtu);
	icmp6->icmp6_mtu = htonl(dce->dce_pmtu);

	/* We now have a PMTU for sure */
	dce->dce_flags |= DCEF_PMTU;
	dce->dce_last_change_time = TICK_TO_SEC(ddi_get_lbolt64());

	mutex_exit(&dce->dce_lock);
	/*
	 * After dropping the lock the new value is visible to everyone.
	 * Then we bump the generation number so any cached values reinspect
	 * the dce_t.
	 */
	dce_increment_generation(dce);
	dce_refrele(dce);
}

/*
 * Fanout received ICMPv6 error packets to the transports.
 * Assumes the IPv6 plus ICMPv6 headers have been pulled up but nothing else.
 *
 * The caller must have called icmp_inbound_verify_v6.
 */
void
icmp_inbound_error_fanout_v6(mblk_t *mp, icmp6_t *icmp6, ip_recv_attr_t *ira)
{
	uint16_t	*up;	/* Pointer to ports in ULP header */
	uint32_t	ports;	/* reversed ports for fanout */
	ip6_t		rip6h;	/* With reversed addresses */
	ip6_t		*ip6h;	/* Inner IP header */
	uint16_t	hdr_length; /* Inner IP header length */
	uint8_t		*nexthdrp;
	uint8_t		nexthdr;
	tcpha_t		*tcpha;
	conn_t		*connp;
	ill_t		*ill = ira->ira_ill;	/* Upper in the case of IPMP */
	ip_stack_t	*ipst = ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	/* Caller has already pulled up everything. */
	ip6h = (ip6_t *)&icmp6[1];
	ASSERT(mp->b_cont == NULL);
	ASSERT((uchar_t *)&ip6h[1] <= mp->b_wptr);

	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &hdr_length, &nexthdrp))
		goto drop_pkt;
	nexthdr = *nexthdrp;
	ira->ira_protocol = nexthdr;

	/*
	 * We need a separate IP header with the source and destination
	 * addresses reversed to do fanout/classification because the ip6h in
	 * the ICMPv6 error is in the form we sent it out.
	 */
	rip6h.ip6_src = ip6h->ip6_dst;
	rip6h.ip6_dst = ip6h->ip6_src;
	rip6h.ip6_nxt = nexthdr;

	/* Try to pass the ICMP message to clients who need it */
	switch (nexthdr) {
	case IPPROTO_UDP: {
		/* Attempt to find a client stream based on port. */
		up = (uint16_t *)((uchar_t *)ip6h + hdr_length);

		/* Note that we send error to all matches. */
		ira->ira_flags |= IRAF_ICMP_ERROR;
		ip_fanout_udp_multi_v6(mp, &rip6h, up[0], up[1], ira);
		ira->ira_flags &= ~IRAF_ICMP_ERROR;
		return;
	}
	case IPPROTO_TCP: {
		/*
		 * Attempt to find a client stream based on port.
		 * Note that we do a reverse lookup since the header is
		 * in the form we sent it out.
		 */
		tcpha = (tcpha_t *)((uchar_t *)ip6h + hdr_length);
		/*
		 * With IPMP we need to match across group, which we do
		 * since we have the upper ill from ira_ill.
		 */
		connp = ipcl_tcp_lookup_reversed_ipv6(ip6h, tcpha,
		    TCPS_LISTEN, ill->ill_phyint->phyint_ifindex, ipst);
		if (connp == NULL) {
			goto drop_pkt;
		}

		if (CONN_INBOUND_POLICY_PRESENT_V6(connp, ipss) ||
		    (ira->ira_flags & IRAF_IPSEC_SECURE)) {
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

		ira->ira_flags |= IRAF_ICMP_ERROR;
		if (IPCL_IS_TCP(connp)) {
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
			    connp->conn_recvicmp, connp, ira, SQ_FILL,
			    SQTAG_TCP6_INPUT_ICMP_ERR);
		} else {
			/* Not TCP; must be SOCK_RAW, IPPROTO_TCP */
			ill_t *rill = ira->ira_rill;

			ira->ira_ill = ira->ira_rill = NULL;
			(connp->conn_recv)(connp, mp, NULL, ira);
			CONN_DEC_REF(connp);
			ira->ira_ill = ill;
			ira->ira_rill = rill;
		}
		ira->ira_flags &= ~IRAF_ICMP_ERROR;
		return;

	}
	case IPPROTO_SCTP:
		up = (uint16_t *)((uchar_t *)ip6h + hdr_length);
		/* Find a SCTP client stream for this packet. */
		((uint16_t *)&ports)[0] = up[1];
		((uint16_t *)&ports)[1] = up[0];

		ira->ira_flags |= IRAF_ICMP_ERROR;
		ip_fanout_sctp(mp, NULL, &rip6h, ports, ira);
		ira->ira_flags &= ~IRAF_ICMP_ERROR;
		return;

	case IPPROTO_ESP:
	case IPPROTO_AH:
		if (!ipsec_loaded(ipss)) {
			ip_proto_not_sup(mp, ira);
			return;
		}

		if (nexthdr == IPPROTO_ESP)
			mp = ipsecesp_icmp_error(mp, ira);
		else
			mp = ipsecah_icmp_error(mp, ira);
		if (mp == NULL)
			return;

		/* Just in case ipsec didn't preserve the NULL b_cont */
		if (mp->b_cont != NULL) {
			if (!pullupmsg(mp, -1))
				goto drop_pkt;
		}

		/*
		 * If succesful, the mp has been modified to not include
		 * the ESP/AH header so we can fanout to the ULP's icmp
		 * error handler.
		 */
		if (mp->b_wptr - mp->b_rptr < IPV6_HDR_LEN)
			goto drop_pkt;

		ip6h = (ip6_t *)mp->b_rptr;
		/* Don't call hdr_length_v6() unless you have to. */
		if (ip6h->ip6_nxt != IPPROTO_ICMPV6)
			hdr_length = ip_hdr_length_v6(mp, ip6h);
		else
			hdr_length = IPV6_HDR_LEN;

		/* Verify the modified message before any further processes. */
		icmp6 = (icmp6_t *)(&mp->b_rptr[hdr_length]);
		if (!icmp_inbound_verify_v6(mp, icmp6, ira)) {
			freemsg(mp);
			return;
		}

		icmp_inbound_error_fanout_v6(mp, icmp6, ira);
		return;

	case IPPROTO_IPV6: {
		/* Look for self-encapsulated packets that caused an error */
		ip6_t *in_ip6h;

		in_ip6h = (ip6_t *)((uint8_t *)ip6h + hdr_length);

		if (IN6_ARE_ADDR_EQUAL(&in_ip6h->ip6_src, &ip6h->ip6_src) &&
		    IN6_ARE_ADDR_EQUAL(&in_ip6h->ip6_dst, &ip6h->ip6_dst)) {
			/*
			 * Self-encapsulated case. As in the ipv4 case,
			 * we need to strip the 2nd IP header. Since mp
			 * is already pulled-up, we can simply bcopy
			 * the 3rd header + data over the 2nd header.
			 */
			uint16_t unused_len;

			/*
			 * Make sure we don't do recursion more than once.
			 */
			if (!ip_hdr_length_nexthdr_v6(mp, in_ip6h,
			    &unused_len, &nexthdrp) ||
			    *nexthdrp == IPPROTO_IPV6) {
				goto drop_pkt;
			}

			/*
			 * Copy the 3rd header + remaining data on top
			 * of the 2nd header.
			 */
			bcopy(in_ip6h, ip6h, mp->b_wptr - (uchar_t *)in_ip6h);

			/*
			 * Subtract length of the 2nd header.
			 */
			mp->b_wptr -= hdr_length;

			ip6h = (ip6_t *)mp->b_rptr;
			/* Don't call hdr_length_v6() unless you have to. */
			if (ip6h->ip6_nxt != IPPROTO_ICMPV6)
				hdr_length = ip_hdr_length_v6(mp, ip6h);
			else
				hdr_length = IPV6_HDR_LEN;

			/*
			 * Verify the modified message before any further
			 * processes.
			 */
			icmp6 = (icmp6_t *)(&mp->b_rptr[hdr_length]);
			if (!icmp_inbound_verify_v6(mp, icmp6, ira)) {
				freemsg(mp);
				return;
			}

			/*
			 * Now recurse, and see what I _really_ should be
			 * doing here.
			 */
			icmp_inbound_error_fanout_v6(mp, icmp6, ira);
			return;
		}
		/* FALLTHRU */
	}
	case IPPROTO_ENCAP:
		if ((connp = ipcl_iptun_classify_v6(&rip6h.ip6_src,
		    &rip6h.ip6_dst, ipst)) != NULL) {
			ira->ira_flags |= IRAF_ICMP_ERROR;
			connp->conn_recvicmp(connp, mp, NULL, ira);
			CONN_DEC_REF(connp);
			ira->ira_flags &= ~IRAF_ICMP_ERROR;
			return;
		}
		/*
		 * No IP tunnel is interested, fallthrough and see
		 * if a raw socket will want it.
		 */
		/* FALLTHRU */
	default:
		ira->ira_flags |= IRAF_ICMP_ERROR;
		ASSERT(ira->ira_protocol == nexthdr);
		ip_fanout_proto_v6(mp, &rip6h, ira);
		ira->ira_flags &= ~IRAF_ICMP_ERROR;
		return;
	}
	/* NOTREACHED */
drop_pkt:
	BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInErrors);
	ip1dbg(("icmp_inbound_error_fanout_v6: drop pkt\n"));
	freemsg(mp);
}

/*
 * Process received IPv6 ICMP Redirect messages.
 * Assumes the caller has verified that the headers are in the pulled up mblk.
 * Consumes mp.
 */
/* ARGSUSED */
static void
icmp_redirect_v6(mblk_t *mp, ip6_t *ip6h, nd_redirect_t *rd,
    ip_recv_attr_t *ira)
{
	ire_t		*ire, *nire;
	ire_t		*prev_ire = NULL;
	ire_t		*redir_ire;
	in6_addr_t	*src, *dst, *gateway;
	nd_opt_hdr_t	*opt;
	nce_t		*nce;
	int		ncec_flags = 0;
	int		err = 0;
	boolean_t	redirect_to_router = B_FALSE;
	int		len;
	int		optlen;
	ill_t		*ill = ira->ira_rill;
	ill_t		*rill = ira->ira_rill;
	ip_stack_t	*ipst = ill->ill_ipst;

	/*
	 * Since ira_ill is where the IRE_LOCAL was hosted we use ira_rill
	 * and make it be the IPMP upper so avoid being confused by a packet
	 * addressed to a unicast address on a different ill.
	 */
	if (IS_UNDER_IPMP(rill)) {
		rill = ipmp_ill_hold_ipmp_ill(rill);
		if (rill == NULL) {
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
			ip_drop_input("ipv6IfIcmpInBadRedirects - IPMP ill",
			    mp, ill);
			freemsg(mp);
			return;
		}
		ASSERT(rill != ira->ira_rill);
	}

	len = mp->b_wptr - (uchar_t *)rd;
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
		ip_drop_input("ipv6IfIcmpInBadRedirects - addr/len", mp, ill);
		goto fail_redirect;
	}

	if (!(IN6_IS_ADDR_LINKLOCAL(gateway) ||
	    IN6_ARE_ADDR_EQUAL(gateway, dst))) {
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
		ip_drop_input("ipv6IfIcmpInBadRedirects - bad gateway",
		    mp, ill);
		goto fail_redirect;
	}

	optlen = len - sizeof (nd_redirect_t);
	if (optlen != 0) {
		if (!ndp_verify_optlen((nd_opt_hdr_t *)&rd[1], optlen)) {
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
			ip_drop_input("ipv6IfIcmpInBadRedirects - options",
			    mp, ill);
			goto fail_redirect;
		}
	}

	if (!IN6_ARE_ADDR_EQUAL(gateway, dst)) {
		redirect_to_router = B_TRUE;
		ncec_flags |= NCE_F_ISROUTER;
	} else {
		gateway = dst;	/* Add nce for dst */
	}


	/*
	 * Verify that the IP source address of the redirect is
	 * the same as the current first-hop router for the specified
	 * ICMP destination address.
	 * Also, Make sure we had a route for the dest in question and
	 * that route was pointing to the old gateway (the source of the
	 * redirect packet.)
	 * We do longest match and then compare ire_gateway_addr_v6 below.
	 */
	prev_ire = ire_ftable_lookup_v6(dst, 0, 0, 0, rill,
	    ALL_ZONES, NULL, MATCH_IRE_ILL, 0, ipst, NULL);

	/*
	 * Check that
	 *	the redirect was not from ourselves
	 *	old gateway is still directly reachable
	 */
	if (prev_ire == NULL ||
	    (prev_ire->ire_type & (IRE_LOCAL|IRE_LOOPBACK)) ||
	    (prev_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    !IN6_ARE_ADDR_EQUAL(src, &prev_ire->ire_gateway_addr_v6)) {
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
		ip_drop_input("ipv6IfIcmpInBadRedirects - ire", mp, ill);
		goto fail_redirect;
	}

	ASSERT(prev_ire->ire_ill != NULL);
	if (prev_ire->ire_ill->ill_flags & ILLF_NONUD)
		ncec_flags |= NCE_F_NONUD;

	opt = (nd_opt_hdr_t *)&rd[1];
	opt = ndp_get_option(opt, optlen, ND_OPT_TARGET_LINKADDR);
	if (opt != NULL) {
		err = nce_lookup_then_add_v6(rill,
		    (uchar_t *)&opt[1],		/* Link layer address */
		    rill->ill_phys_addr_length,
		    gateway, ncec_flags, ND_STALE, &nce);
		switch (err) {
		case 0:
			nce_refrele(nce);
			break;
		case EEXIST:
			/*
			 * Check to see if link layer address has changed and
			 * process the ncec_state accordingly.
			 */
			nce_process(nce->nce_common,
			    (uchar_t *)&opt[1], 0, B_FALSE);
			nce_refrele(nce);
			break;
		default:
			ip1dbg(("icmp_redirect_v6: NCE create failed %d\n",
			    err));
			goto fail_redirect;
		}
	}
	if (redirect_to_router) {
		ASSERT(IN6_IS_ADDR_LINKLOCAL(gateway));

		/*
		 * Create a Route Association.  This will allow us to remember
		 * a router told us to use the particular gateway.
		 */
		ire = ire_create_v6(
		    dst,
		    &ipv6_all_ones,		/* mask */
		    gateway,			/* gateway addr */
		    IRE_HOST,
		    prev_ire->ire_ill,
		    ALL_ZONES,
		    (RTF_DYNAMIC | RTF_GATEWAY | RTF_HOST),
		    NULL,
		    ipst);
	} else {
		ipif_t *ipif;
		in6_addr_t gw;

		/*
		 * Just create an on link entry, i.e. interface route.
		 * The gateway field is our link-local on the ill.
		 */
		mutex_enter(&rill->ill_lock);
		for (ipif = rill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (!(ipif->ipif_state_flags & IPIF_CONDEMNED) &&
			    IN6_IS_ADDR_LINKLOCAL(&ipif->ipif_v6lcl_addr))
				break;
		}
		if (ipif == NULL) {
			/* We have no link-local address! */
			mutex_exit(&rill->ill_lock);
			goto fail_redirect;
		}
		gw = ipif->ipif_v6lcl_addr;
		mutex_exit(&rill->ill_lock);

		ire = ire_create_v6(
		    dst,				/* gateway == dst */
		    &ipv6_all_ones,			/* mask */
		    &gw,				/* gateway addr */
		    rill->ill_net_type,			/* IF_[NO]RESOLVER */
		    prev_ire->ire_ill,
		    ALL_ZONES,
		    (RTF_DYNAMIC | RTF_HOST),
		    NULL,
		    ipst);
	}

	if (ire == NULL)
		goto fail_redirect;

	nire = ire_add(ire);
	/* Check if it was a duplicate entry */
	if (nire != NULL && nire != ire) {
		ASSERT(nire->ire_identical_ref > 1);
		ire_delete(nire);
		ire_refrele(nire);
		nire = NULL;
	}
	ire = nire;
	if (ire != NULL) {
		ire_refrele(ire);		/* Held in ire_add */

		/* tell routing sockets that we received a redirect */
		ip_rts_change_v6(RTM_REDIRECT,
		    &rd->nd_rd_dst,
		    &rd->nd_rd_target,
		    &ipv6_all_ones, 0, src,
		    (RTF_DYNAMIC | RTF_GATEWAY | RTF_HOST), 0,
		    (RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_AUTHOR), ipst);

		/*
		 * Delete any existing IRE_HOST type ires for this destination.
		 * This together with the added IRE has the effect of
		 * modifying an existing redirect.
		 */
		redir_ire = ire_ftable_lookup_v6(dst, 0, src, IRE_HOST,
		    prev_ire->ire_ill, ALL_ZONES, NULL,
		    (MATCH_IRE_GW | MATCH_IRE_TYPE | MATCH_IRE_ILL), 0, ipst,
		    NULL);

		if (redir_ire != NULL) {
			if (redir_ire->ire_flags & RTF_DYNAMIC)
				ire_delete(redir_ire);
			ire_refrele(redir_ire);
		}
	}

	ire_refrele(prev_ire);
	prev_ire = NULL;

fail_redirect:
	if (prev_ire != NULL)
		ire_refrele(prev_ire);
	freemsg(mp);
	if (rill != ira->ira_rill)
		ill_refrele(rill);
}

/*
 * Build and ship an IPv6 ICMP message using the packet data in mp,
 * and the ICMP header pointed to by "stuff".  (May be called as
 * writer.)
 * Note: assumes that icmp_pkt_err_ok_v6 has been called to
 * verify that an icmp error packet can be sent.
 *
 * If v6src_ptr is set use it as a source. Otherwise select a reasonable
 * source address (see above function).
 */
static void
icmp_pkt_v6(mblk_t *mp, void *stuff, size_t len,
    const in6_addr_t *v6src_ptr, ip_recv_attr_t *ira)
{
	ip6_t		*ip6h;
	in6_addr_t	v6dst;
	size_t		len_needed;
	size_t		msg_len;
	mblk_t		*mp1;
	icmp6_t		*icmp6;
	in6_addr_t	v6src;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ip_xmit_attr_t	ixas;

	ip6h = (ip6_t *)mp->b_rptr;

	bzero(&ixas, sizeof (ixas));
	ixas.ixa_flags = IXAF_BASIC_SIMPLE_V6;
	ixas.ixa_zoneid = ira->ira_zoneid;
	ixas.ixa_ifindex = 0;
	ixas.ixa_ipst = ipst;
	ixas.ixa_cred = kcred;
	ixas.ixa_cpid = NOPID;
	ixas.ixa_tsl = ira->ira_tsl;	/* Behave as a multi-level responder */
	ixas.ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;

	/*
	 * If the source of the original packet was link-local, then
	 * make sure we send on the same ill (group) as we received it on.
	 */
	if (IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_src)) {
		ixas.ixa_flags |= IXAF_SCOPEID_SET;
		if (IS_UNDER_IPMP(ill))
			ixas.ixa_scopeid = ill_get_upper_ifindex(ill);
		else
			ixas.ixa_scopeid = ill->ill_phyint->phyint_ifindex;
	}

	if (ira->ira_flags & IRAF_IPSEC_SECURE) {
		/*
		 * Apply IPsec based on how IPsec was applied to
		 * the packet that had the error.
		 *
		 * If it was an outbound packet that caused the ICMP
		 * error, then the caller will have setup the IRA
		 * appropriately.
		 */
		if (!ipsec_in_to_out(ira, &ixas, mp, NULL, ip6h)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			/* Note: mp already consumed and ip_drop_packet done */
			return;
		}
	} else {
		/*
		 * This is in clear. The icmp message we are building
		 * here should go out in clear, independent of our policy.
		 */
		ixas.ixa_flags |= IXAF_NO_IPSEC;
	}

	/*
	 * If the caller specified the source we use that.
	 * Otherwise, if the packet was for one of our unicast addresses, make
	 * sure we respond with that as the source. Otherwise
	 * have ip_output_simple pick the source address.
	 */
	if (v6src_ptr != NULL) {
		v6src = *v6src_ptr;
	} else {
		ire_t *ire;
		uint_t match_flags = MATCH_IRE_TYPE | MATCH_IRE_ZONEONLY;

		if (IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_src) ||
		    IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_dst))
			match_flags |= MATCH_IRE_ILL;

		ire = ire_ftable_lookup_v6(&ip6h->ip6_dst, 0, 0,
		    (IRE_LOCAL|IRE_LOOPBACK), ill, ira->ira_zoneid, NULL,
		    match_flags, 0, ipst, NULL);
		if (ire != NULL) {
			v6src = ip6h->ip6_dst;
			ire_refrele(ire);
		} else {
			v6src = ipv6_all_zeros;
			ixas.ixa_flags |= IXAF_SET_SOURCE;
		}
	}
	v6dst = ip6h->ip6_src;
	len_needed = ipst->ips_ipv6_icmp_return - IPV6_HDR_LEN - len;
	msg_len = msgdsize(mp);
	if (msg_len > len_needed) {
		if (!adjmsg(mp, len_needed - msg_len)) {
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutErrors);
			freemsg(mp);
			return;
		}
		msg_len = len_needed;
	}
	mp1 = allocb(IPV6_HDR_LEN + len, BPRI_MED);
	if (mp1 == NULL) {
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutErrors);
		freemsg(mp);
		return;
	}
	mp1->b_cont = mp;
	mp = mp1;

	/*
	 * Set IXAF_TRUSTED_ICMP so we can let the ICMP messages this
	 * node generates be accepted in peace by all on-host destinations.
	 * If we do NOT assume that all on-host destinations trust
	 * self-generated ICMP messages, then rework here, ip6.c, and spd.c.
	 * (Look for IXAF_TRUSTED_ICMP).
	 */
	ixas.ixa_flags |= IXAF_TRUSTED_ICMP;

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
	 * checksum field. The checksum is calculated in ip_output_wire_v6.
	 */
	icmp6->icmp6_cksum = ip6h->ip6_plen;
	if (icmp6->icmp6_type == ND_REDIRECT) {
		ip6h->ip6_hops = IPV6_MAX_HOPS;
	}

	(void) ip_output_simple(mp, &ixas);
	ixa_cleanup(&ixas);
}

/*
 * Update the output mib when ICMPv6 packets are sent.
 */
void
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
icmp_pkt_err_ok_v6(mblk_t *mp, boolean_t mcast_ok, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	boolean_t	llbcast;
	ip6_t		*ip6h;

	if (!mp)
		return (NULL);

	/* We view multicast and broadcast as the same.. */
	llbcast = (ira->ira_flags &
	    (IRAF_L2DST_MULTICAST|IRAF_L2DST_BROADCAST)) != 0;
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
				BUMP_MIB(ill->ill_icmp6_mib,
				    ipv6IfIcmpInErrors);
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
	/*
	 * If this is a labeled system, then check to see if we're allowed to
	 * send a response to this particular sender.  If not, then just drop.
	 */
	if (is_system_labeled() && !tsol_can_reply_error(mp, ira)) {
		BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpOutErrors);
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
 * Called when a packet was sent out the same link that it arrived on.
 * Check if it is ok to send a redirect and then send it.
 */
void
ip_send_potential_redirect_v6(mblk_t *mp, ip6_t *ip6h, ire_t *ire,
    ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	in6_addr_t	*v6targ;
	ire_t		*src_ire_v6 = NULL;
	mblk_t		*mp1;
	ire_t		*nhop_ire = NULL;

	/*
	 * Don't send a redirect when forwarding a source
	 * routed packet.
	 */
	if (ip_source_routed_v6(ip6h, mp, ipst))
		return;

	if (ire->ire_type & IRE_ONLINK) {
		/* Target is directly connected */
		v6targ = &ip6h->ip6_dst;
	} else {
		/* Determine the most specific IRE used to send the packets */
		nhop_ire = ire_nexthop(ire);
		if (nhop_ire == NULL)
			return;

		/*
		 * We won't send redirects to a router
		 * that doesn't have a link local
		 * address, but will forward.
		 */
		if (!IN6_IS_ADDR_LINKLOCAL(&nhop_ire->ire_addr_v6)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
			ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
			ire_refrele(nhop_ire);
			return;
		}
		v6targ = &nhop_ire->ire_addr_v6;
	}
	src_ire_v6 = ire_ftable_lookup_v6(&ip6h->ip6_src,
	    NULL, NULL, IRE_INTERFACE, ire->ire_ill, ALL_ZONES, NULL,
	    MATCH_IRE_ILL | MATCH_IRE_TYPE, 0, ipst, NULL);

	if (src_ire_v6 == NULL) {
		if (nhop_ire != NULL)
			ire_refrele(nhop_ire);
		return;
	}

	/*
	 * The source is directly connected.
	 */
	mp1 = copymsg(mp);
	if (mp1 != NULL)
		icmp_send_redirect_v6(mp1, v6targ, &ip6h->ip6_dst, ira);

	if (nhop_ire != NULL)
		ire_refrele(nhop_ire);
	ire_refrele(src_ire_v6);
}

/*
 * Generate an ICMPv6 redirect message.
 * Include target link layer address option if it exits.
 * Always include redirect header.
 */
static void
icmp_send_redirect_v6(mblk_t *mp, in6_addr_t *targetp, in6_addr_t *dest,
    ip_recv_attr_t *ira)
{
	nd_redirect_t	*rd;
	nd_opt_rd_hdr_t	*rdh;
	uchar_t		*buf;
	ncec_t		*ncec = NULL;
	nd_opt_hdr_t	*opt;
	int		len;
	int		ll_opt_len = 0;
	int		max_redir_hdr_data_len;
	int		pkt_len;
	in6_addr_t	*srcp;
	ill_t		*ill;
	boolean_t	need_refrele;
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;

	mp = icmp_pkt_err_ok_v6(mp, B_FALSE, ira);
	if (mp == NULL)
		return;

	if (IS_UNDER_IPMP(ira->ira_ill)) {
		ill = ipmp_ill_hold_ipmp_ill(ira->ira_ill);
		if (ill == NULL) {
			ill = ira->ira_ill;
			BUMP_MIB(ill->ill_icmp6_mib, ipv6IfIcmpInBadRedirects);
			ip_drop_output("no IPMP ill for sending redirect",
			    mp, ill);
			freemsg(mp);
			return;
		}
		need_refrele = B_TRUE;
	} else {
		ill = ira->ira_ill;
		need_refrele = B_FALSE;
	}

	ncec = ncec_lookup_illgrp_v6(ill, targetp);
	if (ncec != NULL && ncec->ncec_state != ND_INCOMPLETE &&
	    ncec->ncec_lladdr != NULL) {
		ll_opt_len = (sizeof (nd_opt_hdr_t) +
		    ill->ill_phys_addr_length + 7)/8 * 8;
	}
	len = sizeof (nd_redirect_t) + sizeof (nd_opt_rd_hdr_t) + ll_opt_len;
	ASSERT(len % 4 == 0);
	buf = kmem_alloc(len, KM_NOSLEEP);
	if (buf == NULL) {
		if (ncec != NULL)
			ncec_refrele(ncec);
		if (need_refrele)
			ill_refrele(ill);
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
	if (ncec != NULL && ll_opt_len != 0) {
		opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		opt->nd_opt_len = ll_opt_len/8;
		bcopy((char *)ncec->ncec_lladdr, &opt[1],
		    ill->ill_phys_addr_length);
	}
	if (ncec != NULL)
		ncec_refrele(ncec);
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
	/* ipif_v6lcl_addr contains the link-local source address */
	srcp = &ill->ill_ipif->ipif_v6lcl_addr;

	/* Redirects sent by router, and router is global zone */
	ASSERT(ira->ira_zoneid == ALL_ZONES);
	ira->ira_zoneid = GLOBAL_ZONEID;
	icmp_pkt_v6(mp, buf, len, srcp, ira);
	kmem_free(buf, len);
	if (need_refrele)
		ill_refrele(ill);
}


/* Generate an ICMP time exceeded message.  (May be called as writer.) */
void
icmp_time_exceeded_v6(mblk_t *mp, uint8_t code, boolean_t mcast_ok,
    ip_recv_attr_t *ira)
{
	icmp6_t	icmp6;

	mp = icmp_pkt_err_ok_v6(mp, mcast_ok, ira);
	if (mp == NULL)
		return;

	bzero(&icmp6, sizeof (icmp6_t));
	icmp6.icmp6_type = ICMP6_TIME_EXCEEDED;
	icmp6.icmp6_code = code;
	icmp_pkt_v6(mp, &icmp6, sizeof (icmp6_t), NULL, ira);
}

/*
 * Generate an ICMP unreachable message.
 * When called from ip_output side a minimal ip_recv_attr_t needs to be
 * constructed by the caller.
 */
void
icmp_unreachable_v6(mblk_t *mp, uint8_t code, boolean_t mcast_ok,
    ip_recv_attr_t *ira)
{
	icmp6_t	icmp6;

	mp = icmp_pkt_err_ok_v6(mp, mcast_ok, ira);
	if (mp == NULL)
		return;

	bzero(&icmp6, sizeof (icmp6_t));
	icmp6.icmp6_type = ICMP6_DST_UNREACH;
	icmp6.icmp6_code = code;
	icmp_pkt_v6(mp, &icmp6, sizeof (icmp6_t), NULL, ira);
}

/*
 * Generate an ICMP pkt too big message.
 * When called from ip_output side a minimal ip_recv_attr_t needs to be
 * constructed by the caller.
 */
void
icmp_pkt2big_v6(mblk_t *mp, uint32_t mtu, boolean_t mcast_ok,
    ip_recv_attr_t *ira)
{
	icmp6_t	icmp6;

	mp = icmp_pkt_err_ok_v6(mp, mcast_ok, ira);
	if (mp == NULL)
		return;

	bzero(&icmp6, sizeof (icmp6_t));
	icmp6.icmp6_type = ICMP6_PACKET_TOO_BIG;
	icmp6.icmp6_code = 0;
	icmp6.icmp6_mtu = htonl(mtu);

	icmp_pkt_v6(mp, &icmp6, sizeof (icmp6_t), NULL, ira);
}

/*
 * Generate an ICMP parameter problem message. (May be called as writer.)
 * 'offset' is the offset from the beginning of the packet in error.
 * When called from ip_output side a minimal ip_recv_attr_t needs to be
 * constructed by the caller.
 */
static void
icmp_param_problem_v6(mblk_t *mp, uint8_t code, uint32_t offset,
    boolean_t mcast_ok, ip_recv_attr_t *ira)
{
	icmp6_t	icmp6;

	mp = icmp_pkt_err_ok_v6(mp, mcast_ok, ira);
	if (mp == NULL)
		return;

	bzero((char *)&icmp6, sizeof (icmp6_t));
	icmp6.icmp6_type = ICMP6_PARAM_PROB;
	icmp6.icmp6_code = code;
	icmp6.icmp6_pptr = htonl(offset);
	icmp_pkt_v6(mp, &icmp6, sizeof (icmp6_t), NULL, ira);
}

void
icmp_param_problem_nexthdr_v6(mblk_t *mp, boolean_t mcast_ok,
    ip_recv_attr_t *ira)
{
	ip6_t		*ip6h = (ip6_t *)mp->b_rptr;
	uint16_t	hdr_length;
	uint8_t		*nexthdrp;
	uint32_t	offset;
	ill_t		*ill = ira->ira_ill;

	/* Determine the offset of the bad nexthdr value */
	if (!ip_hdr_length_nexthdr_v6(mp, ip6h,	&hdr_length, &nexthdrp)) {
		/* Malformed packet */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", mp, ill);
		freemsg(mp);
		return;
	}

	offset = nexthdrp - mp->b_rptr;
	icmp_param_problem_v6(mp, ICMP6_PARAMPROB_NEXTHEADER, offset,
	    mcast_ok, ira);
}

/*
 * Verify whether or not the IP address is a valid local address.
 * Could be a unicast, including one for a down interface.
 * If allow_mcbc then a multicast or broadcast address is also
 * acceptable.
 *
 * In the case of a multicast address, however, the
 * upper protocol is expected to reset the src address
 * to zero when we return IPVL_MCAST so that
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
ip_laddr_t
ip_laddr_verify_v6(const in6_addr_t *v6src, zoneid_t zoneid,
    ip_stack_t *ipst, boolean_t allow_mcbc, uint_t scopeid)
{
	ire_t		*src_ire;
	uint_t		match_flags;
	ill_t		*ill = NULL;

	ASSERT(!IN6_IS_ADDR_V4MAPPED(v6src));
	ASSERT(!IN6_IS_ADDR_UNSPECIFIED(v6src));

	match_flags = MATCH_IRE_ZONEONLY;
	if (scopeid != 0) {
		ill = ill_lookup_on_ifindex(scopeid, B_TRUE, ipst);
		if (ill == NULL)
			return (IPVL_BAD);
		match_flags |= MATCH_IRE_ILL;
	}

	src_ire = ire_ftable_lookup_v6(v6src, NULL, NULL, 0,
	    ill, zoneid, NULL, match_flags, 0, ipst, NULL);
	if (ill != NULL)
		ill_refrele(ill);

	/*
	 * If an address other than in6addr_any is requested,
	 * we verify that it is a valid address for bind
	 * Note: Following code is in if-else-if form for
	 * readability compared to a condition check.
	 */
	if (src_ire != NULL && (src_ire->ire_type & (IRE_LOCAL|IRE_LOOPBACK))) {
		/*
		 * (2) Bind to address of local UP interface
		 */
		ire_refrele(src_ire);
		return (IPVL_UNICAST_UP);
	} else if (IN6_IS_ADDR_MULTICAST(v6src)) {
		/* (4) bind to multicast address. */
		if (src_ire != NULL)
			ire_refrele(src_ire);

		/*
		 * Note: caller should take IPV6_MULTICAST_IF
		 * into account when selecting a real source address.
		 */
		if (allow_mcbc)
			return (IPVL_MCAST);
		else
			return (IPVL_BAD);
	} else {
		ipif_t *ipif;

		/*
		 * (3) Bind to address of local DOWN interface?
		 * (ipif_lookup_addr() looks up all interfaces
		 * but we do not get here for UP interfaces
		 * - case (2) above)
		 */
		if (src_ire != NULL)
			ire_refrele(src_ire);

		ipif = ipif_lookup_addr_v6(v6src, NULL, zoneid, ipst);
		if (ipif == NULL)
			return (IPVL_BAD);

		/* Not a useful source? */
		if (ipif->ipif_flags & (IPIF_NOLOCAL | IPIF_ANYCAST)) {
			ipif_refrele(ipif);
			return (IPVL_BAD);
		}
		ipif_refrele(ipif);
		return (IPVL_UNICAST_DOWN);
	}
}

/*
 * Verify that both the source and destination addresses are valid.  If
 * IPDF_VERIFY_DST is not set, then the destination address may be unreachable,
 * i.e. have no route to it.  Protocols like TCP want to verify destination
 * reachability, while tunnels do not.
 *
 * Determine the route, the interface, and (optionally) the source address
 * to use to reach a given destination.
 * Note that we allow connect to broadcast and multicast addresses when
 * IPDF_ALLOW_MCBC is set.
 * first_hop and dst_addr are normally the same, but if source routing
 * they will differ; in that case the first_hop is what we'll use for the
 * routing lookup but the dce and label checks will be done on dst_addr,
 *
 * If uinfo is set, then we fill in the best available information
 * we have for the destination. This is based on (in priority order) any
 * metrics and path MTU stored in a dce_t, route metrics, and finally the
 * ill_mtu/ill_mc_mtu.
 *
 * Tsol note: If we have a source route then dst_addr != firsthop. But we
 * always do the label check on dst_addr.
 *
 * Assumes that the caller has set ixa_scopeid for link-local communication.
 */
int
ip_set_destination_v6(in6_addr_t *src_addrp, const in6_addr_t *dst_addr,
    const in6_addr_t *firsthop, ip_xmit_attr_t *ixa, iulp_t *uinfo,
    uint32_t flags, uint_t mac_mode)
{
	ire_t		*ire;
	int		error = 0;
	in6_addr_t	setsrc;				/* RTF_SETSRC */
	zoneid_t	zoneid = ixa->ixa_zoneid;	/* Honors SO_ALLZONES */
	ip_stack_t	*ipst = ixa->ixa_ipst;
	dce_t		*dce;
	uint_t		pmtu;
	uint_t		ifindex;
	uint_t		generation;
	nce_t		*nce;
	ill_t		*ill = NULL;
	boolean_t	multirt = B_FALSE;

	ASSERT(!IN6_IS_ADDR_V4MAPPED(dst_addr));

	ASSERT(!(ixa->ixa_flags & IXAF_IS_IPV4));

	/*
	 * We never send to zero; the ULPs map it to the loopback address.
	 * We can't allow it since we use zero to mean unitialized in some
	 * places.
	 */
	ASSERT(!IN6_IS_ADDR_UNSPECIFIED(dst_addr));

	if (is_system_labeled()) {
		ts_label_t *tsl = NULL;

		error = tsol_check_dest(ixa->ixa_tsl, dst_addr, IPV6_VERSION,
		    mac_mode, (flags & IPDF_ZONE_IS_GLOBAL) != 0, &tsl);
		if (error != 0)
			return (error);
		if (tsl != NULL) {
			/* Update the label */
			ip_xmit_attr_replace_tsl(ixa, tsl);
		}
	}

	setsrc = ipv6_all_zeros;
	/*
	 * Select a route; For IPMP interfaces, we would only select
	 * a "hidden" route (i.e., going through a specific under_ill)
	 * if ixa_ifindex has been specified.
	 */
	ire = ip_select_route_v6(firsthop, *src_addrp, ixa, &generation,
	    &setsrc, &error, &multirt);
	ASSERT(ire != NULL);	/* IRE_NOROUTE if none found */
	if (error != 0)
		goto bad_addr;

	/*
	 * ire can't be a broadcast or multicast unless IPDF_ALLOW_MCBC is set.
	 * If IPDF_VERIFY_DST is set, the destination must be reachable.
	 * Otherwise the destination needn't be reachable.
	 *
	 * If we match on a reject or black hole, then we've got a
	 * local failure.  May as well fail out the connect() attempt,
	 * since it's never going to succeed.
	 */
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		/*
		 * If we're verifying destination reachability, we always want
		 * to complain here.
		 *
		 * If we're not verifying destination reachability but the
		 * destination has a route, we still want to fail on the
		 * temporary address and broadcast address tests.
		 *
		 * In both cases do we let the code continue so some reasonable
		 * information is returned to the caller. That enables the
		 * caller to use (and even cache) the IRE. conn_ip_ouput will
		 * use the generation mismatch path to check for the unreachable
		 * case thereby avoiding any specific check in the main path.
		 */
		ASSERT(generation == IRE_GENERATION_VERIFY);
		if (flags & IPDF_VERIFY_DST) {
			/*
			 * Set errno but continue to set up ixa_ire to be
			 * the RTF_REJECT|RTF_BLACKHOLE IRE.
			 * That allows callers to use ip_output to get an
			 * ICMP error back.
			 */
			if (!(ire->ire_type & IRE_HOST))
				error = ENETUNREACH;
			else
				error = EHOSTUNREACH;
		}
	}

	if ((ire->ire_type & (IRE_BROADCAST|IRE_MULTICAST)) &&
	    !(flags & IPDF_ALLOW_MCBC)) {
		ire_refrele(ire);
		ire = ire_reject(ipst, B_FALSE);
		generation = IRE_GENERATION_VERIFY;
		error = ENETUNREACH;
	}

	/* Cache things */
	if (ixa->ixa_ire != NULL)
		ire_refrele_notr(ixa->ixa_ire);
#ifdef DEBUG
	ire_refhold_notr(ire);
	ire_refrele(ire);
#endif
	ixa->ixa_ire = ire;
	ixa->ixa_ire_generation = generation;

	/*
	 * Ensure that ixa_dce is always set any time that ixa_ire is set,
	 * since some callers will send a packet to conn_ip_output() even if
	 * there's an error.
	 */
	ifindex = 0;
	if (IN6_IS_ADDR_LINKSCOPE(dst_addr)) {
		/* If we are creating a DCE we'd better have an ifindex */
		if (ill != NULL)
			ifindex = ill->ill_phyint->phyint_ifindex;
		else
			flags &= ~IPDF_UNIQUE_DCE;
	}

	if (flags & IPDF_UNIQUE_DCE) {
		/* Fallback to the default dce if allocation fails */
		dce = dce_lookup_and_add_v6(dst_addr, ifindex, ipst);
		if (dce != NULL) {
			generation = dce->dce_generation;
		} else {
			dce = dce_lookup_v6(dst_addr, ifindex, ipst,
			    &generation);
		}
	} else {
		dce = dce_lookup_v6(dst_addr, ifindex, ipst, &generation);
	}
	ASSERT(dce != NULL);
	if (ixa->ixa_dce != NULL)
		dce_refrele_notr(ixa->ixa_dce);
#ifdef DEBUG
	dce_refhold_notr(dce);
	dce_refrele(dce);
#endif
	ixa->ixa_dce = dce;
	ixa->ixa_dce_generation = generation;


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
	if (!(ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))) {
		/* Get an nce to cache. */
		nce = ire_to_nce(ire, NULL, firsthop);
		if (nce == NULL) {
			/* Allocation failure? */
			ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
		} else {
			if (ixa->ixa_nce != NULL)
				nce_refrele(ixa->ixa_nce);
			ixa->ixa_nce = nce;
		}
	}

	/*
	 * If the source address is a loopback address, the
	 * destination had best be local or multicast.
	 * If we are sending to an IRE_LOCAL using a loopback source then
	 * it had better be the same zoneid.
	 */
	if (IN6_IS_ADDR_LOOPBACK(src_addrp)) {
		if ((ire->ire_type & IRE_LOCAL) && ire->ire_zoneid != zoneid) {
			ire = NULL;	/* Stored in ixa_ire */
			error = EADDRNOTAVAIL;
			goto bad_addr;
		}
		if (!(ire->ire_type & (IRE_LOOPBACK|IRE_LOCAL|IRE_MULTICAST))) {
			ire = NULL;	/* Stored in ixa_ire */
			error = EADDRNOTAVAIL;
			goto bad_addr;
		}
	}

	/*
	 * Does the caller want us to pick a source address?
	 */
	if (flags & IPDF_SELECT_SRC) {
		in6_addr_t	src_addr;

		/*
		 * We use use ire_nexthop_ill to avoid the under ipmp
		 * interface for source address selection. Note that for ipmp
		 * probe packets, ixa_ifindex would have been specified, and
		 * the ip_select_route() invocation would have picked an ire
		 * will ire_ill pointing at an under interface.
		 */
		ill = ire_nexthop_ill(ire);

		/* If unreachable we have no ill but need some source */
		if (ill == NULL) {
			src_addr = ipv6_loopback;
			/* Make sure we look for a better source address */
			generation = SRC_GENERATION_VERIFY;
		} else {
			error = ip_select_source_v6(ill, &setsrc, dst_addr,
			    zoneid, ipst, B_FALSE, ixa->ixa_src_preferences,
			    &src_addr, &generation, NULL);
			if (error != 0) {
				ire = NULL;	/* Stored in ixa_ire */
				goto bad_addr;
			}
		}

		/*
		 * We allow the source address to to down.
		 * However, we check that we don't use the loopback address
		 * as a source when sending out on the wire.
		 */
		if (IN6_IS_ADDR_LOOPBACK(&src_addr) &&
		    !(ire->ire_type & (IRE_LOCAL|IRE_LOOPBACK|IRE_MULTICAST)) &&
		    !(ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))) {
			ire = NULL;	/* Stored in ixa_ire */
			error = EADDRNOTAVAIL;
			goto bad_addr;
		}

		*src_addrp = src_addr;
		ixa->ixa_src_generation = generation;
	}

	/*
	 * Make sure we don't leave an unreachable ixa_nce in place
	 * since ip_select_route is used when we unplumb i.e., remove
	 * references on ixa_ire, ixa_nce, and ixa_dce.
	 */
	nce = ixa->ixa_nce;
	if (nce != NULL && nce->nce_is_condemned) {
		nce_refrele(nce);
		ixa->ixa_nce = NULL;
		ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
	}

	/*
	 * Note that IPv6 multicast supports PMTU discovery unlike IPv4
	 * multicast. But pmtu discovery is only enabled for connected
	 * sockets in general.
	 */

	/*
	 * Set initial value for fragmentation limit.  Either conn_ip_output
	 * or ULP might updates it when there are routing changes.
	 * Handles a NULL ixa_ire->ire_ill or a NULL ixa_nce for RTF_REJECT.
	 */
	pmtu = ip_get_pmtu(ixa);
	ixa->ixa_fragsize = pmtu;
	/* Make sure ixa_fragsize and ixa_pmtu remain identical */
	if (ixa->ixa_flags & IXAF_VERIFY_PMTU)
		ixa->ixa_pmtu = pmtu;

	/*
	 * Extract information useful for some transports.
	 * First we look for DCE metrics. Then we take what we have in
	 * the metrics in the route, where the offlink is used if we have
	 * one.
	 */
	if (uinfo != NULL) {
		bzero(uinfo, sizeof (*uinfo));

		if (dce->dce_flags & DCEF_UINFO)
			*uinfo = dce->dce_uinfo;

		rts_merge_metrics(uinfo, &ire->ire_metrics);

		/* Allow ire_metrics to decrease the path MTU from above */
		if (uinfo->iulp_mtu == 0 || uinfo->iulp_mtu > pmtu)
			uinfo->iulp_mtu = pmtu;

		uinfo->iulp_localnet = (ire->ire_type & IRE_ONLINK) != 0;
		uinfo->iulp_loopback = (ire->ire_type & IRE_LOOPBACK) != 0;
		uinfo->iulp_local = (ire->ire_type & IRE_LOCAL) != 0;
	}

	if (ill != NULL)
		ill_refrele(ill);

	return (error);

bad_addr:
	if (ire != NULL)
		ire_refrele(ire);

	if (ill != NULL)
		ill_refrele(ill);

	/*
	 * Make sure we don't leave an unreachable ixa_nce in place
	 * since ip_select_route is used when we unplumb i.e., remove
	 * references on ixa_ire, ixa_nce, and ixa_dce.
	 */
	nce = ixa->ixa_nce;
	if (nce != NULL && nce->nce_is_condemned) {
		nce_refrele(nce);
		ixa->ixa_nce = NULL;
		ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
	}

	return (error);
}

/*
 * Handle protocols with which IP is less intimate.  There
 * can be more than one stream bound to a particular
 * protocol.  When this is the case, normally each one gets a copy
 * of any incoming packets.
 *
 * Zones notes:
 * Packets will be distributed to conns in all zones. This is really only
 * useful for ICMPv6 as only applications in the global zone can create raw
 * sockets for other protocols.
 */
void
ip_fanout_proto_v6(mblk_t *mp, ip6_t *ip6h, ip_recv_attr_t *ira)
{
	mblk_t		*mp1;
	in6_addr_t	laddr = ip6h->ip6_dst;
	conn_t		*connp, *first_connp, *next_connp;
	connf_t		*connfp;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	connfp = &ipst->ips_ipcl_proto_fanout_v6[ira->ira_protocol];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		/* Note: IPCL_PROTO_MATCH_V6 includes conn_wantpacket */
		if (IPCL_PROTO_MATCH_V6(connp, ira, ip6h) &&
		    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
		    tsol_receive_local(mp, &laddr, IPV6_VERSION, ira, connp)))
			break;
	}

	if (connp == NULL) {
		/*
		 * No one bound to this port.  Is
		 * there a client that wants all
		 * unclaimed datagrams?
		 */
		mutex_exit(&connfp->connf_lock);
		ip_fanout_send_icmp_v6(mp, ICMP6_PARAM_PROB,
		    ICMP6_PARAMPROB_NEXTHEADER, ira);
		return;
	}

	ASSERT(IPCL_IS_NONSTR(connp) || connp->conn_rq != NULL);

	CONN_INC_REF(connp);
	first_connp = connp;

	/*
	 * XXX: Fix the multiple protocol listeners case. We should not
	 * be walking the conn->conn_next list here.
	 */
	connp = connp->conn_next;
	for (;;) {
		while (connp != NULL) {
			/* Note: IPCL_PROTO_MATCH_V6 includes conn_wantpacket */
			if (IPCL_PROTO_MATCH_V6(connp, ira, ip6h) &&
			    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
			    tsol_receive_local(mp, &laddr, IPV6_VERSION,
			    ira, connp)))
				break;
			connp = connp->conn_next;
		}

		if (connp == NULL) {
			/* No more interested clients */
			connp = first_connp;
			break;
		}
		if (((mp1 = dupmsg(mp)) == NULL) &&
		    ((mp1 = copymsg(mp)) == NULL)) {
			/* Memory allocation failed */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			connp = first_connp;
			break;
		}

		CONN_INC_REF(connp);
		mutex_exit(&connfp->connf_lock);

		ip_fanout_proto_conn(connp, mp1, NULL, (ip6_t *)mp1->b_rptr,
		    ira);

		mutex_enter(&connfp->connf_lock);
		/* Follow the next pointer before releasing the conn. */
		next_connp = connp->conn_next;
		CONN_DEC_REF(connp);
		connp = next_connp;
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);

	ip_fanout_proto_conn(connp, mp, NULL, ip6h, ira);

	CONN_DEC_REF(connp);
}

/*
 * Called when it is conceptually a ULP that would sent the packet
 * e.g., port unreachable and nexthdr unknown. Check that the packet
 * would have passed the IPsec global policy before sending the error.
 *
 * Send an ICMP error after patching up the packet appropriately.
 * Uses ip_drop_input and bumps the appropriate MIB.
 * For ICMP6_PARAMPROB_NEXTHEADER we determine the offset to use.
 */
void
ip_fanout_send_icmp_v6(mblk_t *mp, uint_t icmp_type, uint8_t icmp_code,
    ip_recv_attr_t *ira)
{
	ip6_t		*ip6h;
	boolean_t	secure;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	netstack_t	*ns = ipst->ips_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;

	secure = ira->ira_flags & IRAF_IPSEC_SECURE;

	/*
	 * We are generating an icmp error for some inbound packet.
	 * Called from all ip_fanout_(udp, tcp, proto) functions.
	 * Before we generate an error, check with global policy
	 * to see whether this is allowed to enter the system. As
	 * there is no "conn", we are checking with global policy.
	 */
	ip6h = (ip6_t *)mp->b_rptr;
	if (secure || ipss->ipsec_inbound_v6_policy_present) {
		mp = ipsec_check_global_policy(mp, NULL, NULL, ip6h, ira, ns);
		if (mp == NULL)
			return;
	}

	/* We never send errors for protocols that we do implement */
	if (ira->ira_protocol == IPPROTO_ICMPV6) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ip_fanout_send_icmp_v6", mp, ill);
		freemsg(mp);
		return;
	}

	switch (icmp_type) {
	case ICMP6_DST_UNREACH:
		ASSERT(icmp_code == ICMP6_DST_UNREACH_NOPORT);

		BUMP_MIB(ill->ill_ip_mib, udpIfStatsNoPorts);
		ip_drop_input("ipIfStatsNoPorts", mp, ill);

		icmp_unreachable_v6(mp, icmp_code, B_FALSE, ira);
		break;
	case ICMP6_PARAM_PROB:
		ASSERT(icmp_code == ICMP6_PARAMPROB_NEXTHEADER);

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInUnknownProtos);
		ip_drop_input("ipIfStatsInUnknownProtos", mp, ill);

		/* Let the system determine the offset for this one */
		icmp_param_problem_nexthdr_v6(mp, B_FALSE, ira);
		break;
	default:
#ifdef DEBUG
		panic("ip_fanout_send_icmp_v6: wrong type");
		/*NOTREACHED*/
#else
		freemsg(mp);
		break;
#endif
	}
}

/*
 * Fanout for UDP packets that are multicast or ICMP errors.
 * (Unicast fanout is handled in ip_input_v6.)
 *
 * If SO_REUSEADDR is set all multicast packets
 * will be delivered to all conns bound to the same port.
 *
 * Fanout for UDP packets.
 * The caller puts <fport, lport> in the ports parameter.
 * ire_type must be IRE_BROADCAST for multicast and broadcast packets.
 *
 * If SO_REUSEADDR is set all multicast and broadcast packets
 * will be delivered to all conns bound to the same port.
 *
 * Zones notes:
 * Earlier in ip_input on a system with multiple shared-IP zones we
 * duplicate the multicast and broadcast packets and send them up
 * with each explicit zoneid that exists on that ill.
 * This means that here we can match the zoneid with SO_ALLZONES being special.
 */
void
ip_fanout_udp_multi_v6(mblk_t *mp, ip6_t *ip6h, uint16_t lport, uint16_t fport,
    ip_recv_attr_t *ira)
{
	in6_addr_t	laddr;
	conn_t		*connp;
	connf_t		*connfp;
	in6_addr_t	faddr;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ira->ira_flags & (IRAF_MULTIBROADCAST|IRAF_ICMP_ERROR));

	laddr = ip6h->ip6_dst;
	faddr = ip6h->ip6_src;

	/* Attempt to find a client stream based on destination port. */
	connfp = &ipst->ips_ipcl_udp_fanout[IPCL_UDP_HASH(lport, ipst)];
	mutex_enter(&connfp->connf_lock);
	connp = connfp->connf_head;
	while (connp != NULL) {
		if ((IPCL_UDP_MATCH_V6(connp, lport, laddr, fport, faddr)) &&
		    conn_wantpacket_v6(connp, ira, ip6h) &&
		    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
		    tsol_receive_local(mp, &laddr, IPV6_VERSION, ira, connp)))
			break;
		connp = connp->conn_next;
	}

	if (connp == NULL)
		goto notfound;

	CONN_INC_REF(connp);

	if (connp->conn_reuseaddr) {
		conn_t		*first_connp = connp;
		conn_t		*next_connp;
		mblk_t		*mp1;

		connp = connp->conn_next;
		for (;;) {
			while (connp != NULL) {
				if (IPCL_UDP_MATCH_V6(connp, lport, laddr,
				    fport, faddr) &&
				    conn_wantpacket_v6(connp, ira, ip6h) &&
				    (!(ira->ira_flags & IRAF_SYSTEM_LABELED) ||
				    tsol_receive_local(mp, &laddr, IPV6_VERSION,
				    ira, connp)))
					break;
				connp = connp->conn_next;
			}
			if (connp == NULL) {
				/* No more interested clients */
				connp = first_connp;
				break;
			}
			if (((mp1 = dupmsg(mp)) == NULL) &&
			    ((mp1 = copymsg(mp)) == NULL)) {
				/* Memory allocation failed */
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				connp = first_connp;
				break;
			}

			CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);

			IP6_STAT(ipst, ip6_udp_fanmb);
			ip_fanout_udp_conn(connp, mp1, NULL,
			    (ip6_t *)mp1->b_rptr, ira);

			mutex_enter(&connfp->connf_lock);
			/* Follow the next pointer before releasing the conn. */
			next_connp = connp->conn_next;
			IP6_STAT(ipst, ip6_udp_fanmb);
			CONN_DEC_REF(connp);
			connp = next_connp;
		}
	}

	/* Last one.  Send it upstream. */
	mutex_exit(&connfp->connf_lock);

	IP6_STAT(ipst, ip6_udp_fanmb);
	ip_fanout_udp_conn(connp, mp, NULL, ip6h, ira);
	CONN_DEC_REF(connp);
	return;

notfound:
	mutex_exit(&connfp->connf_lock);
	/*
	 * No one bound to this port.  Is
	 * there a client that wants all
	 * unclaimed datagrams?
	 */
	if (ipst->ips_ipcl_proto_fanout_v6[IPPROTO_UDP].connf_head != NULL) {
		ASSERT(ira->ira_protocol == IPPROTO_UDP);
		ip_fanout_proto_v6(mp, ip6h, ira);
	} else {
		ip_fanout_send_icmp_v6(mp, ICMP6_DST_UNREACH,
		    ICMP6_DST_UNREACH_NOPORT, ira);
	}
}

/*
 * int ip_find_hdr_v6()
 *
 * This routine is used by the upper layer protocols, iptun, and IPsec:
 * - Set extension header pointers to appropriate locations
 * - Determine IPv6 header length and return it
 * - Return a pointer to the last nexthdr value
 *
 * The caller must initialize ipp_fields.
 * The upper layer protocols normally set label_separate which makes the
 * routine put the TX label in ipp_label_v6. If this is not set then
 * the hop-by-hop options including the label are placed in ipp_hopopts.
 *
 * NOTE: If multiple extension headers of the same type are present,
 * ip_find_hdr_v6() will set the respective extension header pointers
 * to the first one that it encounters in the IPv6 header.  It also
 * skips fragment headers.  This routine deals with malformed packets
 * of various sorts in which case the returned length is up to the
 * malformed part.
 */
int
ip_find_hdr_v6(mblk_t *mp, ip6_t *ip6h, boolean_t label_separate, ip_pkt_t *ipp,
    uint8_t *nexthdrp)
{
	uint_t	length, ehdrlen;
	uint8_t nexthdr;
	uint8_t *whereptr, *endptr;
	ip6_dest_t *tmpdstopts;
	ip6_rthdr_t *tmprthdr;
	ip6_hbh_t *tmphopopts;
	ip6_frag_t *tmpfraghdr;

	ipp->ipp_fields |= IPPF_HOPLIMIT | IPPF_TCLASS | IPPF_ADDR;
	ipp->ipp_hoplimit = ip6h->ip6_hops;
	ipp->ipp_tclass = IPV6_FLOW_TCLASS(ip6h->ip6_flow);
	ipp->ipp_addr = ip6h->ip6_dst;

	length = IPV6_HDR_LEN;
	whereptr = ((uint8_t *)&ip6h[1]); /* point to next hdr */
	endptr = mp->b_wptr;

	nexthdr = ip6h->ip6_nxt;
	while (whereptr < endptr) {
		/* Is there enough left for len + nexthdr? */
		if (whereptr + MIN_EHDR_LEN > endptr)
			goto done;

		switch (nexthdr) {
		case IPPROTO_HOPOPTS: {
			/* We check for any CIPSO */
			uchar_t *secopt;
			boolean_t hbh_needed;
			uchar_t *after_secopt;

			tmphopopts = (ip6_hbh_t *)whereptr;
			ehdrlen = 8 * (tmphopopts->ip6h_len + 1);
			if ((uchar_t *)tmphopopts +  ehdrlen > endptr)
				goto done;
			nexthdr = tmphopopts->ip6h_nxt;

			if (!label_separate) {
				secopt = NULL;
				after_secopt = whereptr;
			} else {
				/*
				 * We have dropped packets with bad options in
				 * ip6_input. No need to check return value
				 * here.
				 */
				(void) tsol_find_secopt_v6(whereptr, ehdrlen,
				    &secopt, &after_secopt, &hbh_needed);
			}
			if (secopt != NULL && after_secopt - whereptr > 0) {
				ipp->ipp_fields |= IPPF_LABEL_V6;
				ipp->ipp_label_v6 = secopt;
				ipp->ipp_label_len_v6 = after_secopt - whereptr;
			} else {
				ipp->ipp_label_len_v6 = 0;
				after_secopt = whereptr;
				hbh_needed = B_TRUE;
			}
			/* return only 1st hbh */
			if (hbh_needed && !(ipp->ipp_fields & IPPF_HOPOPTS)) {
				ipp->ipp_fields |= IPPF_HOPOPTS;
				ipp->ipp_hopopts = (ip6_hbh_t *)after_secopt;
				ipp->ipp_hopoptslen = ehdrlen -
				    ipp->ipp_label_len_v6;
			}
			break;
		}
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
				ipp->ipp_fields |= IPPF_RTHDRDSTOPTS;
				ipp->ipp_rthdrdstopts = ipp->ipp_dstopts;
				ipp->ipp_dstopts = NULL;
				ipp->ipp_rthdrdstoptslen = ipp->ipp_dstoptslen;
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

	ASSERT(IPH_HDR_VERSION(ip6h) == IPV6_VERSION);
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
int
ip_process_options_v6(mblk_t *mp, ip6_t *ip6h,
    uint8_t *optptr, uint_t optlen, uint8_t hdr_type, ip_recv_attr_t *ira)
{
	uint8_t opt_type;
	uint_t optused;
	int ret = 0;
	const char *errtype;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

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
				if ((ira->ira_flags & IRAF_IPSEC_SECURE) &&
				    ira->ira_ipsec_ah_sa != NULL)
					break;

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
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInHdrErrors);
					ip_drop_input("ipIfStatsInHdrErrors",
					    mp, ill);
					freemsg(mp);
					return (-1);
				case IP6OPT_TYPE_ICMP:
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInHdrErrors);
					ip_drop_input("ipIfStatsInHdrErrors",
					    mp, ill);
					icmp_param_problem_v6(mp,
					    ICMP6_PARAMPROB_OPTION,
					    (uint32_t)(optptr -
					    (uint8_t *)ip6h),
					    B_FALSE, ira);
					return (-1);
				case IP6OPT_TYPE_FORCEICMP:
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInHdrErrors);
					ip_drop_input("ipIfStatsInHdrErrors",
					    mp, ill);
					icmp_param_problem_v6(mp,
					    ICMP6_PARAMPROB_OPTION,
					    (uint32_t)(optptr -
					    (uint8_t *)ip6h),
					    B_TRUE, ira);
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
	ip_drop_input("ICMP_PARAM_PROBLEM", mp, ill);
	icmp_param_problem_v6(mp, ICMP6_PARAMPROB_OPTION,
	    (uint32_t)(optptr - (uint8_t *)ip6h),
	    B_FALSE, ira);
	return (-1);
}

/*
 * Process a routing header that is not yet empty.
 * Because of RFC 5095, we now reject all route headers.
 */
void
ip_process_rthdr(mblk_t *mp, ip6_t *ip6h, ip6_rthdr_t *rth,
    ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(rth->ip6r_segleft != 0);

	if (!ipst->ips_ipv6_forward_src_routed) {
		/* XXX Check for source routed out same interface? */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
		ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
		freemsg(mp);
		return;
	}

	ip_drop_input("ICMP_PARAM_PROBLEM", mp, ill);
	icmp_param_problem_v6(mp, ICMP6_PARAMPROB_HEADER,
	    (uint32_t)((uchar_t *)&rth->ip6r_type - (uchar_t *)ip6h),
	    B_FALSE, ira);
}

/*
 * Read side put procedure for IPv6 module.
 */
void
ip_rput_v6(queue_t *q, mblk_t *mp)
{
	ill_t		*ill;

	ill = (ill_t *)q->q_ptr;
	if (ill->ill_state_flags & (ILL_CONDEMNED | ILL_LL_SUBNET_PENDING)) {
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
	if (DB_TYPE(mp) == M_DATA) {
		struct mac_header_info_s mhi;

		ip_mdata_to_mhi(ill, mp, &mhi);
		ip_input_v6(ill, NULL, mp, &mhi);
	} else {
		ip_rput_notdata(ill, mp);
	}
}

/*
 * Walk through the IPv6 packet in mp and see if there's an AH header
 * in it.  See if the AH header needs to get done before other headers in
 * the packet.  (Worker function for ipsec_early_ah_v6().)
 */
#define	IPSEC_HDR_DONT_PROCESS	0
#define	IPSEC_HDR_PROCESS	1
#define	IPSEC_MEMORY_ERROR	2 /* or malformed packet */
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
	/*
	 * Malformed/truncated packet.
	 */
	return (IPSEC_MEMORY_ERROR);
}

/*
 * Path for AH if options are present.
 * Returns NULL if the mblk was consumed.
 *
 * Sometimes AH needs to be done before other IPv6 headers for security
 * reasons.  This function (and its ipsec_needs_processing_v6() above)
 * indicates if that is so, and fans out to the appropriate IPsec protocol
 * for the datagram passed in.
 */
mblk_t *
ipsec_early_ah_v6(mblk_t *mp, ip_recv_attr_t *ira)
{
	uint8_t nexthdr;
	ah_t *ah;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ipsec_stack_t	*ipss = ipst->ips_netstack->netstack_ipsec;

	switch (ipsec_needs_processing_v6(mp, &nexthdr)) {
	case IPSEC_MEMORY_ERROR:
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", mp, ill);
		freemsg(mp);
		return (NULL);
	case IPSEC_HDR_DONT_PROCESS:
		return (mp);
	}

	/* Default means send it to AH! */
	ASSERT(nexthdr == IPPROTO_AH);

	if (!ipsec_loaded(ipss)) {
		ip_proto_not_sup(mp, ira);
		return (NULL);
	}

	mp = ipsec_inbound_ah_sa(mp, ira, &ah);
	if (mp == NULL)
		return (NULL);
	ASSERT(ah != NULL);
	ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
	ASSERT(ira->ira_ipsec_ah_sa != NULL);
	ASSERT(ira->ira_ipsec_ah_sa->ipsa_input_func != NULL);
	mp = ira->ira_ipsec_ah_sa->ipsa_input_func(mp, ah, ira);

	if (mp == NULL) {
		/*
		 * Either it failed or is pending. In the former case
		 * ipIfStatsInDiscards was increased.
		 */
		return (NULL);
	}

	/* we're done with IPsec processing, send it up */
	ip_input_post_ipsec(mp, ira);
	return (NULL);
}

/*
 * Reassemble fragment.
 * When it returns a completed message the first mblk will only contain
 * the headers prior to the fragment header, with the nexthdr value updated
 * to be the header after the fragment header.
 */
mblk_t *
ip_input_fragment_v6(mblk_t *mp, ip6_t *ip6h,
    ip6_frag_t *fraghdr, uint_t remlen, ip_recv_attr_t *ira)
{
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
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint_t		prev_nexthdr_offset;
	uint8_t		prev_nexthdr;
	uint8_t		*ptr;
	uint32_t	packet_size;

	/*
	 * We utilize hardware computed checksum info only for UDP since
	 * IP fragmentation is a normal occurence for the protocol.  In
	 * addition, checksum offload support for IP fragments carrying
	 * UDP payload is commonly implemented across network adapters.
	 */
	ASSERT(ira->ira_rill != NULL);
	if (nexthdr == IPPROTO_UDP && dohwcksum &&
	    ILL_HCKSUM_CAPABLE(ira->ira_rill) &&
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
		    offset >= DB_CKSUMSTART(mp) &&
		    ((len = offset - DB_CKSUMSTART(mp)) & 1) == 0) {
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
	 * Determine the offset (from the begining of the IP header)
	 * of the nexthdr value which has IPPROTO_FRAGMENT. We use
	 * this when removing the fragment header from the packet.
	 * This packet consists of the IPv6 header, a potential
	 * hop-by-hop options header, a potential pre-routing-header
	 * destination options header, and a potential routing header.
	 */
	prev_nexthdr_offset = (uint8_t *)&ip6h->ip6_nxt - (uint8_t *)ip6h;
	prev_nexthdr = ip6h->ip6_nxt;
	ptr = (uint8_t *)&ip6h[1];

	if (prev_nexthdr == IPPROTO_HOPOPTS) {
		ip6_hbh_t	*hbh_hdr;
		uint_t		hdr_len;

		hbh_hdr = (ip6_hbh_t *)ptr;
		hdr_len = 8 * (hbh_hdr->ip6h_len + 1);
		prev_nexthdr = hbh_hdr->ip6h_nxt;
		prev_nexthdr_offset = (uint8_t *)&hbh_hdr->ip6h_nxt
		    - (uint8_t *)ip6h;
		ptr += hdr_len;
	}
	if (prev_nexthdr == IPPROTO_DSTOPTS) {
		ip6_dest_t	*dest_hdr;
		uint_t		hdr_len;

		dest_hdr = (ip6_dest_t *)ptr;
		hdr_len = 8 * (dest_hdr->ip6d_len + 1);
		prev_nexthdr = dest_hdr->ip6d_nxt;
		prev_nexthdr_offset = (uint8_t *)&dest_hdr->ip6d_nxt
		    - (uint8_t *)ip6h;
		ptr += hdr_len;
	}
	if (prev_nexthdr == IPPROTO_ROUTING) {
		ip6_rthdr_t	*rthdr;
		uint_t		hdr_len;

		rthdr = (ip6_rthdr_t *)ptr;
		prev_nexthdr = rthdr->ip6r_nxt;
		prev_nexthdr_offset = (uint8_t *)&rthdr->ip6r_nxt
		    - (uint8_t *)ip6h;
		hdr_len = 8 * (rthdr->ip6r_len + 1);
		ptr += hdr_len;
	}
	if (prev_nexthdr != IPPROTO_FRAGMENT) {
		/* Can't handle other headers before the fragment header */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		ip_drop_input("ipIfStatsInHdrErrors", mp, ill);
		freemsg(mp);
		return (NULL);
	}

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
		ip_drop_input("ICMP_PARAM_PROBLEM", mp, ill);
		icmp_param_problem_v6(mp, ICMP6_PARAMPROB_HEADER,
		    (uint32_t)((char *)&ip6h->ip6_plen -
		    (char *)ip6h), B_FALSE, ira);
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
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInHdrErrors);
		ip_drop_input("Reassembled packet too large", mp, ill);
		icmp_param_problem_v6(mp, ICMP6_PARAMPROB_HEADER,
		    (uint32_t)((char *)&fraghdr->ip6f_offlg -
		    (char *)ip6h), B_FALSE, ira);
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
	/* Handle vnic loopback of fragments */
	if (mp->b_datap->db_ref > 2)
		msg_len = 0;
	else
		msg_len = MBLKSIZE(mp);

	tail_mp = mp;
	while (tail_mp->b_cont != NULL) {
		tail_mp = tail_mp->b_cont;
		if (tail_mp->b_datap->db_ref <= 2)
			msg_len += MBLKSIZE(tail_mp);
	}
	/*
	 * If the reassembly list for this ILL will get too big
	 * prune it.
	 */

	if ((msg_len + sizeof (*ipf) + ill->ill_frag_count) >=
	    ipst->ips_ip_reass_queue_bytes) {
		DTRACE_PROBE3(ip_reass_queue_bytes, uint_t, msg_len,
		    uint_t, ill->ill_frag_count,
		    uint_t, ipst->ips_ip_reass_queue_bytes);
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
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
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
			ipf->ipf_prev_nexthdr_offset = prev_nexthdr_offset;
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
				    prev_nexthdr_offset;
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
	prev_nexthdr_offset = ipf->ipf_prev_nexthdr_offset;
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
		ip_drop_input("ipIfStatsInHdrErrors", mp, ill);
		ip1dbg(("ip_input_fragment_v6: bad packet\n"));
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
			ip1dbg(("ip_input_fragment_v6: dupb failed\n"));
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return (NULL);
		}
		nmp->b_cont = mp->b_cont;
		mp->b_cont = nmp;
		nmp->b_rptr += hdr_length;
	}
	mp->b_wptr = mp->b_rptr + hdr_length - sizeof (ip6_frag_t);

	ip6h = (ip6_t *)mp->b_rptr;
	((char *)ip6h)[prev_nexthdr_offset] = nexthdr;

	/* Restore original IP length in header. */
	packet_size = msgdsize(mp);
	ip6h->ip6_plen = htons((uint16_t)(packet_size - IPV6_HDR_LEN));
	/* Record the ECN info. */
	ip6h->ip6_vcf &= htonl(0xFFCFFFFF);
	ip6h->ip6_vcf |= htonl(ecn_info << 20);

	/* Update the receive attributes */
	ira->ira_pktlen = packet_size;
	ira->ira_ip_hdr_length = hdr_length - sizeof (ip6_frag_t);
	ira->ira_protocol = nexthdr;

	/* Reassembly is successful; set checksum information in packet */
	DB_CKSUM16(mp) = (uint16_t)sum_val;
	DB_CKSUMFLAGS(mp) = sum_flags;
	DB_CKSUMSTART(mp) = ira->ira_ip_hdr_length;

	return (mp);
}

/*
 * Given an mblk and a ptr, find the destination address in an IPv6 routing
 * header.
 */
static in6_addr_t
pluck_out_dst(const mblk_t *mp, uint8_t *whereptr, in6_addr_t oldrv)
{
	ip6_rthdr0_t *rt0;
	int segleft, numaddr;
	in6_addr_t *ap, rv = oldrv;

	rt0 = (ip6_rthdr0_t *)whereptr;
	if (rt0->ip6r0_type != 0 && rt0->ip6r0_type != 2) {
		DTRACE_PROBE2(pluck_out_dst_unknown_type, mblk_t *, mp,
		    uint8_t *, whereptr);
		return (rv);
	}
	segleft = rt0->ip6r0_segleft;
	numaddr = rt0->ip6r0_len / 2;

	if ((rt0->ip6r0_len & 0x1) ||
	    (mp != NULL && whereptr + (rt0->ip6r0_len + 1) * 8 > mp->b_wptr) ||
	    (segleft > rt0->ip6r0_len / 2)) {
		/*
		 * Corrupt packet.  Either the routing header length is odd
		 * (can't happen) or mismatched compared to the packet, or the
		 * number of addresses is.  Return what we can.  This will
		 * only be a problem on forwarded packets that get squeezed
		 * through an outbound tunnel enforcing IPsec Tunnel Mode.
		 */
		DTRACE_PROBE2(pluck_out_dst_badpkt, mblk_t *, mp, uint8_t *,
		    whereptr);
		return (rv);
	}

	if (segleft != 0) {
		ap = (in6_addr_t *)((char *)rt0 + sizeof (*rt0));
		rv = ap[numaddr - 1];
	}

	return (rv);
}

/*
 * Walk through the options to see if there is a routing header.
 * If present get the destination which is the last address of
 * the option.
 * mp needs to be provided in cases when the extension headers might span
 * b_cont; mp is never modified by this function.
 */
in6_addr_t
ip_get_dst_v6(ip6_t *ip6h, const mblk_t *mp, boolean_t *is_fragment)
{
	const mblk_t *current_mp = mp;
	uint8_t nexthdr;
	uint8_t *whereptr;
	int ehdrlen;
	in6_addr_t rv;

	whereptr = (uint8_t *)ip6h;
	ehdrlen = sizeof (ip6_t);

	/* We assume at least the IPv6 base header is within one mblk. */
	ASSERT(mp == NULL ||
	    (mp->b_rptr <= whereptr && mp->b_wptr >= whereptr + ehdrlen));

	rv = ip6h->ip6_dst;
	nexthdr = ip6h->ip6_nxt;
	if (is_fragment != NULL)
		*is_fragment = B_FALSE;

	/*
	 * We also assume (thanks to ipsec_tun_outbound()'s pullup) that
	 * no extension headers will be split across mblks.
	 */

	while (nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_DSTOPTS ||
	    nexthdr == IPPROTO_ROUTING) {
		if (nexthdr == IPPROTO_ROUTING)
			rv = pluck_out_dst(current_mp, whereptr, rv);

		/*
		 * All IPv6 extension headers have the next-header in byte
		 * 0, and the (length - 8) in 8-byte-words.
		 */
		while (current_mp != NULL &&
		    whereptr + ehdrlen >= current_mp->b_wptr) {
			ehdrlen -= (current_mp->b_wptr - whereptr);
			current_mp = current_mp->b_cont;
			if (current_mp == NULL) {
				/* Bad packet.  Return what we can. */
				DTRACE_PROBE3(ip_get_dst_v6_badpkt, mblk_t *,
				    mp, mblk_t *, current_mp, ip6_t *, ip6h);
				goto done;
			}
			whereptr = current_mp->b_rptr;
		}
		whereptr += ehdrlen;

		nexthdr = *whereptr;
		ASSERT(current_mp == NULL || whereptr + 1 < current_mp->b_wptr);
		ehdrlen = (*(whereptr + 1) + 1) * 8;
	}

done:
	if (nexthdr == IPPROTO_FRAGMENT && is_fragment != NULL)
		*is_fragment = B_TRUE;
	return (rv);
}

/*
 * ip_source_routed_v6:
 * This function is called by redirect code (called from ip_input_v6) to
 * know whether this packet is source routed through this node i.e
 * whether this node (router) is part of the journey. This
 * function is called under two cases :
 *
 * case 1 : Routing header was processed by this node and
 *	    ip_process_rthdr replaced ip6_dst with the next hop
 *	    and we are forwarding the packet to the next hop.
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
			numaddr = rthdr->ip6r0_len / 2;
			addrptr = (in6_addr_t *)((char *)rthdr +
			    sizeof (*rthdr));
			addrptr += (numaddr - (rthdr->ip6r0_segleft + 1));
			if (addrptr != NULL) {
				if (ip_type_v6(addrptr, ipst) == IRE_LOCAL)
					return (B_TRUE);
				ip1dbg(("ip_source_routed_v6: Not local\n"));
			}
		}
	/* FALLTHRU */
	default:
		ip2dbg(("ip_source_routed_v6: Not source routed here\n"));
		return (B_FALSE);
	}
}

/*
 * IPv6 fragmentation.  Essentially the same as IPv4 fragmentation.
 * We have not optimized this in terms of number of mblks
 * allocated. For instance, for each fragment sent we always allocate a
 * mblk to hold the IPv6 header and fragment header.
 *
 * Assumes that all the extension headers are contained in the first mblk
 * and that the fragment header has has already been added by calling
 * ip_fraghdr_add_v6.
 */
int
ip_fragment_v6(mblk_t *mp, nce_t *nce, iaflags_t ixaflags, uint_t pkt_len,
    uint32_t max_frag, uint32_t xmit_hint, zoneid_t szone, zoneid_t nolzid,
    pfirepostfrag_t postfragfn, uintptr_t *ixa_cookie)
{
	ip6_t		*ip6h = (ip6_t *)mp->b_rptr;
	ip6_t		*fip6h;
	mblk_t		*hmp;
	mblk_t		*hmp0;
	mblk_t		*dmp;
	ip6_frag_t	*fraghdr;
	size_t		unfragmentable_len;
	size_t		mlen;
	size_t		max_chunk;
	uint16_t	off_flags;
	uint16_t	offset = 0;
	ill_t		*ill = nce->nce_ill;
	uint8_t		nexthdr;
	uint8_t		*ptr;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint_t		priority = mp->b_band;
	int		error = 0;

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragReqds);
	if (max_frag == 0) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		ip_drop_output("FragFails: zero max_frag", mp, ill);
		freemsg(mp);
		return (EINVAL);
	}

	/*
	 * Caller should have added fraghdr_t to pkt_len, and also
	 * updated ip6_plen.
	 */
	ASSERT(ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN == pkt_len);
	ASSERT(msgdsize(mp) == pkt_len);

	/*
	 * Determine the length of the unfragmentable portion of this
	 * datagram.  This consists of the IPv6 header, a potential
	 * hop-by-hop options header, a potential pre-routing-header
	 * destination options header, and a potential routing header.
	 */
	nexthdr = ip6h->ip6_nxt;
	ptr = (uint8_t *)&ip6h[1];

	if (nexthdr == IPPROTO_HOPOPTS) {
		ip6_hbh_t	*hbh_hdr;
		uint_t		hdr_len;

		hbh_hdr = (ip6_hbh_t *)ptr;
		hdr_len = 8 * (hbh_hdr->ip6h_len + 1);
		nexthdr = hbh_hdr->ip6h_nxt;
		ptr += hdr_len;
	}
	if (nexthdr == IPPROTO_DSTOPTS) {
		ip6_dest_t	*dest_hdr;
		uint_t		hdr_len;

		dest_hdr = (ip6_dest_t *)ptr;
		if (dest_hdr->ip6d_nxt == IPPROTO_ROUTING) {
			hdr_len = 8 * (dest_hdr->ip6d_len + 1);
			nexthdr = dest_hdr->ip6d_nxt;
			ptr += hdr_len;
		}
	}
	if (nexthdr == IPPROTO_ROUTING) {
		ip6_rthdr_t	*rthdr;
		uint_t		hdr_len;

		rthdr = (ip6_rthdr_t *)ptr;
		nexthdr = rthdr->ip6r_nxt;
		hdr_len = 8 * (rthdr->ip6r_len + 1);
		ptr += hdr_len;
	}
	if (nexthdr != IPPROTO_FRAGMENT) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		ip_drop_output("FragFails: bad nexthdr", mp, ill);
		freemsg(mp);
		return (EINVAL);
	}
	unfragmentable_len = (uint_t)(ptr - (uint8_t *)ip6h);
	unfragmentable_len += sizeof (ip6_frag_t);

	max_chunk = (max_frag - unfragmentable_len) & ~7;

	/*
	 * Allocate an mblk with enough room for the link-layer
	 * header and the unfragmentable part of the datagram, which includes
	 * the fragment header.  This (or a copy) will be used as the
	 * first mblk for each fragment we send.
	 */
	hmp = allocb_tmpl(unfragmentable_len + ipst->ips_ip_wroff_extra, mp);
	if (hmp == NULL) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
		ip_drop_output("FragFails: no hmp", mp, ill);
		freemsg(mp);
		return (ENOBUFS);
	}
	hmp->b_rptr += ipst->ips_ip_wroff_extra;
	hmp->b_wptr = hmp->b_rptr + unfragmentable_len;

	fip6h = (ip6_t *)hmp->b_rptr;
	bcopy(ip6h, fip6h, unfragmentable_len);

	/*
	 * pkt_len is set to the total length of the fragmentable data in this
	 * datagram.  For each fragment sent, we will decrement pkt_len
	 * by the amount of fragmentable data sent in that fragment
	 * until len reaches zero.
	 */
	pkt_len -= unfragmentable_len;

	/*
	 * Move read ptr past unfragmentable portion, we don't want this part
	 * of the data in our fragments.
	 */
	mp->b_rptr += unfragmentable_len;
	if (mp->b_rptr == mp->b_wptr) {
		mblk_t *mp1 = mp->b_cont;
		freeb(mp);
		mp = mp1;
	}

	while (pkt_len != 0) {
		mlen = MIN(pkt_len, max_chunk);
		pkt_len -= mlen;
		if (pkt_len != 0) {
			/* Not last */
			hmp0 = copyb(hmp);
			if (hmp0 == NULL) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsOutFragFails);
				ip_drop_output("FragFails: copyb failed",
				    mp, ill);
				freeb(hmp);
				freemsg(mp);
				ip1dbg(("ip_fragment_v6: copyb failed\n"));
				return (ENOBUFS);
			}
			off_flags = IP6F_MORE_FRAG;
		} else {
			/* Last fragment */
			hmp0 = hmp;
			hmp = NULL;
			off_flags = 0;
		}
		fip6h = (ip6_t *)(hmp0->b_rptr);
		fraghdr = (ip6_frag_t *)(hmp0->b_rptr + unfragmentable_len -
		    sizeof (ip6_frag_t));

		fip6h->ip6_plen = htons((uint16_t)(mlen +
		    unfragmentable_len - IPV6_HDR_LEN));
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
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
			ip_drop_output("FragFails: could not carve mp",
			    hmp0, ill);
			if (hmp != NULL)
				freeb(hmp);
			freeb(hmp0);
			ip1dbg(("ip_carve_mp: failed\n"));
			return (ENOBUFS);
		}
		hmp0->b_cont = dmp;
		/* Get the priority marking, if any */
		hmp0->b_band = priority;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragCreates);

		error = postfragfn(hmp0, nce, ixaflags,
		    mlen + unfragmentable_len, xmit_hint, szone, nolzid,
		    ixa_cookie);
		if (error != 0 && error != EWOULDBLOCK && hmp != NULL) {
			/* No point in sending the other fragments */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragFails);
			ip_drop_output("FragFails: postfragfn failed",
			    hmp, ill);
			freeb(hmp);
			freemsg(mp);
			return (error);
		}
		/* No need to redo state machine in loop */
		ixaflags &= ~IXAF_REACH_CONF;

		offset += mlen;
	}
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutFragOKs);
	return (error);
}

/*
 * Add a fragment header to an IPv6 packet.
 * Assumes that all the extension headers are contained in the first mblk.
 *
 * The fragment header is inserted after an hop-by-hop options header
 * and after [an optional destinations header followed by] a routing header.
 */
mblk_t *
ip_fraghdr_add_v6(mblk_t *mp, uint32_t ident, ip_xmit_attr_t *ixa)
{
	ip6_t		*ip6h = (ip6_t *)mp->b_rptr;
	ip6_t		*fip6h;
	mblk_t		*hmp;
	ip6_frag_t	*fraghdr;
	size_t		unfragmentable_len;
	uint8_t		nexthdr;
	uint_t		prev_nexthdr_offset;
	uint8_t		*ptr;
	uint_t		priority = mp->b_band;
	ip_stack_t	*ipst = ixa->ixa_ipst;

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

	/*
	 * Allocate an mblk with enough room for the link-layer
	 * header, the unfragmentable part of the datagram, and the
	 * fragment header.
	 */
	hmp = allocb_tmpl(unfragmentable_len + sizeof (ip6_frag_t) +
	    ipst->ips_ip_wroff_extra, mp);
	if (hmp == NULL) {
		ill_t *ill = ixa->ixa_nce->nce_ill;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards: allocb failure", mp, ill);
		freemsg(mp);
		return (NULL);
	}
	hmp->b_rptr += ipst->ips_ip_wroff_extra;
	hmp->b_wptr = hmp->b_rptr + unfragmentable_len + sizeof (ip6_frag_t);

	fip6h = (ip6_t *)hmp->b_rptr;
	fraghdr = (ip6_frag_t *)(hmp->b_rptr + unfragmentable_len);

	bcopy(ip6h, fip6h, unfragmentable_len);
	fip6h->ip6_plen = htons(ntohs(fip6h->ip6_plen) + sizeof (ip6_frag_t));
	hmp->b_rptr[prev_nexthdr_offset] = IPPROTO_FRAGMENT;

	fraghdr->ip6f_nxt = nexthdr;
	fraghdr->ip6f_reserved = 0;
	fraghdr->ip6f_offlg = 0;
	fraghdr->ip6f_ident = htonl(ident);

	/* Get the priority marking, if any */
	hmp->b_band = priority;

	/*
	 * Move read ptr past unfragmentable portion, we don't want this part
	 * of the data in our fragments.
	 */
	mp->b_rptr += unfragmentable_len;
	hmp->b_cont = mp;
	return (hmp);
}

/*
 * Determine if the ill and multicast aspects of that packets
 * "matches" the conn.
 */
boolean_t
conn_wantpacket_v6(conn_t *connp, ip_recv_attr_t *ira, ip6_t *ip6h)
{
	ill_t		*ill = ira->ira_rill;
	zoneid_t	zoneid = ira->ira_zoneid;
	uint_t		in_ifindex;
	in6_addr_t	*v6dst_ptr = &ip6h->ip6_dst;
	in6_addr_t	*v6src_ptr = &ip6h->ip6_src;

	/*
	 * conn_incoming_ifindex is set by IPV6_BOUND_IF and as link-local
	 * scopeid. This is used to limit
	 * unicast and multicast reception to conn_incoming_ifindex.
	 * conn_wantpacket_v6 is called both for unicast and
	 * multicast packets.
	 */
	in_ifindex = connp->conn_incoming_ifindex;

	/* mpathd can bind to the under IPMP interface, which we allow */
	if (in_ifindex != 0 && in_ifindex != ill->ill_phyint->phyint_ifindex) {
		if (!IS_UNDER_IPMP(ill))
			return (B_FALSE);

		if (in_ifindex != ipmp_ill_get_ipmp_ifindex(ill))
			return (B_FALSE);
	}

	if (!IPCL_ZONE_MATCH(connp, zoneid))
		return (B_FALSE);

	if (!(ira->ira_flags & IRAF_MULTICAST))
		return (B_TRUE);

	if (connp->conn_multi_router)
		return (B_TRUE);

	if (ira->ira_protocol == IPPROTO_RSVP)
		return (B_TRUE);

	return (conn_hasmembers_ill_withsrc_v6(connp, v6dst_ptr, v6src_ptr,
	    ira->ira_ill));
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
 * Return the length in bytes of the IPv6 headers (base header
 * extension headers) that will be needed based on the
 * ip_pkt_t structure passed by the caller.
 *
 * The returned length does not include the length of the upper level
 * protocol (ULP) header.
 */
int
ip_total_hdrs_len_v6(const ip_pkt_t *ipp)
{
	int len;

	len = IPV6_HDR_LEN;

	/*
	 * If there's a security label here, then we ignore any hop-by-hop
	 * options the user may try to set.
	 */
	if (ipp->ipp_fields & IPPF_LABEL_V6) {
		uint_t hopoptslen;
		/*
		 * Note that ipp_label_len_v6 is just the option - not
		 * the hopopts extension header. It also needs to be padded
		 * to a multiple of 8 bytes.
		 */
		ASSERT(ipp->ipp_label_len_v6 != 0);
		hopoptslen = ipp->ipp_label_len_v6 + sizeof (ip6_hbh_t);
		hopoptslen = (hopoptslen + 7)/8 * 8;
		len += hopoptslen;
	} else if (ipp->ipp_fields & IPPF_HOPOPTS) {
		ASSERT(ipp->ipp_hopoptslen != 0);
		len += ipp->ipp_hopoptslen;
	}

	/*
	 * En-route destination options
	 * Only do them if there's a routing header as well
	 */
	if ((ipp->ipp_fields & (IPPF_RTHDRDSTOPTS|IPPF_RTHDR)) ==
	    (IPPF_RTHDRDSTOPTS|IPPF_RTHDR)) {
		ASSERT(ipp->ipp_rthdrdstoptslen != 0);
		len += ipp->ipp_rthdrdstoptslen;
	}
	if (ipp->ipp_fields & IPPF_RTHDR) {
		ASSERT(ipp->ipp_rthdrlen != 0);
		len += ipp->ipp_rthdrlen;
	}
	if (ipp->ipp_fields & IPPF_DSTOPTS) {
		ASSERT(ipp->ipp_dstoptslen != 0);
		len += ipp->ipp_dstoptslen;
	}
	return (len);
}

/*
 * All-purpose routine to build a header chain of an IPv6 header
 * followed by any required extension headers and a proto header.
 *
 * The caller has to set the source and destination address as well as
 * ip6_plen. The caller has to massage any routing header and compensate
 * for the ULP pseudo-header checksum due to the source route.
 *
 * The extension headers will all be fully filled in.
 */
void
ip_build_hdrs_v6(uchar_t *buf, uint_t buf_len, const ip_pkt_t *ipp,
    uint8_t protocol, uint32_t flowinfo)
{
	uint8_t *nxthdr_ptr;
	uint8_t *cp;
	ip6_t	*ip6h = (ip6_t *)buf;

	/* Initialize IPv6 header */
	ip6h->ip6_vcf =
	    (IPV6_DEFAULT_VERS_AND_FLOW & IPV6_VERS_AND_FLOW_MASK) |
	    (flowinfo & ~IPV6_VERS_AND_FLOW_MASK);

	if (ipp->ipp_fields & IPPF_TCLASS) {
		/* Overrides the class part of flowinfo */
		ip6h->ip6_vcf = IPV6_TCLASS_FLOW(ip6h->ip6_vcf,
		    ipp->ipp_tclass);
	}

	if (ipp->ipp_fields & IPPF_HOPLIMIT)
		ip6h->ip6_hops = ipp->ipp_hoplimit;
	else
		ip6h->ip6_hops = ipp->ipp_unicast_hops;

	if ((ipp->ipp_fields & IPPF_ADDR) &&
	    !IN6_IS_ADDR_V4MAPPED(&ipp->ipp_addr))
		ip6h->ip6_src = ipp->ipp_addr;

	nxthdr_ptr = (uint8_t *)&ip6h->ip6_nxt;
	cp = (uint8_t *)&ip6h[1];
	/*
	 * Here's where we have to start stringing together
	 * any extension headers in the right order:
	 * Hop-by-hop, destination, routing, and final destination opts.
	 */
	/*
	 * If there's a security label here, then we ignore any hop-by-hop
	 * options the user may try to set.
	 */
	if (ipp->ipp_fields & IPPF_LABEL_V6) {
		/*
		 * Hop-by-hop options with the label.
		 * Note that ipp_label_v6 is just the option - not
		 * the hopopts extension header. It also needs to be padded
		 * to a multiple of 8 bytes.
		 */
		ip6_hbh_t *hbh = (ip6_hbh_t *)cp;
		uint_t hopoptslen;
		uint_t padlen;

		padlen = ipp->ipp_label_len_v6 + sizeof (ip6_hbh_t);
		hopoptslen = (padlen + 7)/8 * 8;
		padlen = hopoptslen - padlen;

		*nxthdr_ptr = IPPROTO_HOPOPTS;
		nxthdr_ptr = &hbh->ip6h_nxt;
		hbh->ip6h_len = hopoptslen/8 - 1;
		cp += sizeof (ip6_hbh_t);
		bcopy(ipp->ipp_label_v6, cp, ipp->ipp_label_len_v6);
		cp += ipp->ipp_label_len_v6;

		ASSERT(padlen <= 7);
		switch (padlen) {
		case 0:
			break;
		case 1:
			cp[0] = IP6OPT_PAD1;
			break;
		default:
			cp[0] = IP6OPT_PADN;
			cp[1] = padlen - 2;
			bzero(&cp[2], padlen - 2);
			break;
		}
		cp += padlen;
	} else if (ipp->ipp_fields & IPPF_HOPOPTS) {
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
	if ((ipp->ipp_fields & (IPPF_RTHDRDSTOPTS|IPPF_RTHDR)) ==
	    (IPPF_RTHDRDSTOPTS|IPPF_RTHDR)) {
		ip6_dest_t *dst = (ip6_dest_t *)cp;

		*nxthdr_ptr = IPPROTO_DSTOPTS;
		nxthdr_ptr = &dst->ip6d_nxt;

		bcopy(ipp->ipp_rthdrdstopts, cp, ipp->ipp_rthdrdstoptslen);
		cp += ipp->ipp_rthdrdstoptslen;
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
	ASSERT((int)(cp - buf) == buf_len);
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

void
*ip6_kstat_init(netstackid_t stackid, ip6_stat_t *ip6_statisticsp)
{
	kstat_t *ksp;

	ip6_stat_t template = {
		{ "ip6_udp_fannorm", 	KSTAT_DATA_UINT64 },
		{ "ip6_udp_fanmb", 	KSTAT_DATA_UINT64 },
		{ "ip6_recv_pullup", 		KSTAT_DATA_UINT64 },
		{ "ip6_db_ref",			KSTAT_DATA_UINT64 },
		{ "ip6_notaligned",		KSTAT_DATA_UINT64 },
		{ "ip6_multimblk",		KSTAT_DATA_UINT64 },
		{ "ipsec_proto_ahesp",		KSTAT_DATA_UINT64 },
		{ "ip6_out_sw_cksum",			KSTAT_DATA_UINT64 },
		{ "ip6_out_sw_cksum_bytes",		KSTAT_DATA_UINT64 },
		{ "ip6_in_sw_cksum",			KSTAT_DATA_UINT64 },
		{ "ip6_tcp_in_full_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip6_tcp_in_part_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip6_tcp_in_sw_cksum_err",		KSTAT_DATA_UINT64 },
		{ "ip6_udp_in_full_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip6_udp_in_part_hw_cksum_err",	KSTAT_DATA_UINT64 },
		{ "ip6_udp_in_sw_cksum_err",		KSTAT_DATA_UINT64 },
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
ip6_set_src_preferences(ip_xmit_attr_t *ixa, uint32_t prefs)
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

	ixa->ixa_src_preferences = prefs;
	return (0);
}

size_t
ip6_get_src_preferences(ip_xmit_attr_t *ixa, uint32_t *val)
{
	*val = ixa->ixa_src_preferences;
	return (sizeof (ixa->ixa_src_preferences));
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
		ASSERT(nexthdr != IPPROTO_FRAGMENT);
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

/*
 * Utility routine that checks if `v6srcp' is a valid address on underlying
 * interface `ill'.  If `ipifp' is non-NULL, it's set to a held ipif
 * associated with `v6srcp' on success.  NOTE: if this is not called from
 * inside the IPSQ (ill_g_lock is not held), `ill' may be removed from the
 * group during or after this lookup.
 */
boolean_t
ipif_lookup_testaddr_v6(ill_t *ill, const in6_addr_t *v6srcp, ipif_t **ipifp)
{
	ipif_t *ipif;


	ipif = ipif_lookup_addr_exact_v6(v6srcp, ill, ill->ill_ipst);
	if (ipif != NULL) {
		if (ipifp != NULL)
			*ipifp = ipif;
		else
			ipif_refrele(ipif);
		return (B_TRUE);
	}

	if (ip_debug > 2) {
		pr_addr_dbg("ipif_lookup_testaddr_v6: cannot find ipif for "
		    "src %s\n", AF_INET6, v6srcp);
	}
	return (B_FALSE);
}
