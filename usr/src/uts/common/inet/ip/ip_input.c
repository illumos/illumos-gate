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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
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

static void	ip_input_local_v4(ire_t *, mblk_t *, ipha_t *,
    ip_recv_attr_t *);

static void	ip_input_broadcast_v4(ire_t *, mblk_t *, ipha_t *,
    ip_recv_attr_t *);
static void	ip_input_multicast_v4(ire_t *, mblk_t *, ipha_t *,
    ip_recv_attr_t *);

#pragma inline(ip_input_common_v4, ip_input_local_v4, ip_forward_xmit_v4)

/*
 * Direct read side procedure capable of dealing with chains. GLDv3 based
 * drivers call this function directly with mblk chains while STREAMS
 * read side procedure ip_rput() calls this for single packet with ip_ring
 * set to NULL to process one packet at a time.
 *
 * The ill will always be valid if this function is called directly from
 * the driver.
 *
 * If ip_input() is called from GLDv3:
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
ip_input(ill_t *ill, ill_rx_ring_t *ip_ring, mblk_t *mp_chain,
    struct mac_header_info_s *mhip)
{
	(void) ip_input_common_v4(ill, ip_ring, mp_chain, mhip, NULL, NULL,
	    NULL);
}

/*
 * ip_accept_tcp() - This function is called by the squeue when it retrieves
 * a chain of packets in the poll mode. The packets have gone through the
 * data link processing but not IP processing. For performance and latency
 * reasons, the squeue wants to process the chain in line instead of feeding
 * it back via ip_input path.
 *
 * We set up the ip_recv_attr_t with IRAF_TARGET_SQP to that ip_fanout_v4
 * will pass back any TCP packets matching the target sqp to
 * ip_input_common_v4 using ira_target_sqp_mp. Other packets are handled by
 * ip_input_v4 and ip_fanout_v4 as normal.
 * The TCP packets that match the target squeue are returned to the caller
 * as a b_next chain after each packet has been prepend with an mblk
 * from ip_recv_attr_to_mblk.
 */
mblk_t *
ip_accept_tcp(ill_t *ill, ill_rx_ring_t *ip_ring, squeue_t *target_sqp,
    mblk_t *mp_chain, mblk_t **last, uint_t *cnt)
{
	return (ip_input_common_v4(ill, ip_ring, mp_chain, NULL, target_sqp,
	    last, cnt));
}

/*
 * Used by ip_input and ip_accept_tcp
 * The last three arguments are only used by ip_accept_tcp, and mhip is
 * only used by ip_input.
 */
mblk_t *
ip_input_common_v4(ill_t *ill, ill_rx_ring_t *ip_ring, mblk_t *mp_chain,
    struct mac_header_info_s *mhip, squeue_t *target_sqp,
    mblk_t **last, uint_t *cnt)
{
	mblk_t		*mp;
	ipha_t		*ipha;
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
	rtc.rtc_ipaddr = INADDR_ANY;

	/* Loop over b_next */
	for (mp = mp_chain; mp != NULL; mp = mp_chain) {
		mp_chain = mp->b_next;
		mp->b_next = NULL;

		ASSERT(DB_TYPE(mp) == M_DATA);


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
			if ((mp = ip_fix_dbref(mp, &iras)) == NULL) {
				/* mhip might point into 1st packet in chain */
				iras.ira_mhip = NULL;
				continue;
			}
		}

		/*
		 * IP header ptr not aligned?
		 * OR IP header not complete in first mblk
		 */
		ipha = (ipha_t *)mp->b_rptr;
		if (!OK_32PTR(ipha) || MBLKL(mp) < IP_SIMPLE_HDR_LENGTH) {
			mp = ip_check_and_align_header(mp, IP_SIMPLE_HDR_LENGTH,
			    &iras);
			if (mp == NULL) {
				/* mhip might point into 1st packet in chain */
				iras.ira_mhip = NULL;
				continue;
			}
			ipha = (ipha_t *)mp->b_rptr;
		}

		/* Protect against a mix of Ethertypes and IP versions */
		if (IPH_HDR_VERSION(ipha) != IPV4_VERSION) {
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
		if (ipha->ipha_dst == INADDR_ANY) {
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
		 * Keep IRAF_VERIFIED_SRC to avoid redoing broadcast
		 * source check in forwarding path.
		 */
		chain_flags |= (iras.ira_flags &
		    (IRAF_L2SRC_SET|IRAF_VERIFIED_SRC));

		iras.ira_flags = IRAF_IS_IPV4 | IRAF_VERIFY_IP_CKSUM |
		    IRAF_VERIFY_ULP_CKSUM | chain_flags;
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

		iras.ira_pktlen = ntohs(ipha->ipha_length);
		UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInOctets,
		    iras.ira_pktlen);

		/*
		 * Call one of:
		 * 	ill_input_full_v4
		 *	ill_input_short_v4
		 * The former is used in unusual cases. See ill_set_inputfn().
		 */
		(*ill->ill_inputfn)(mp, ipha, &ipha->ipha_dst, &iras, &rtc);

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
		ASSERT(rtc.rtc_ipaddr != INADDR_ANY);
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
 *  - CGTP filtering
 *  - DHCP unicast before we have an IP address configured
 *  - there is an listener for IPPROTO_RSVP
 */
void
ill_input_full_v4(mblk_t *mp, void *iph_arg, void *nexthop_arg,
    ip_recv_attr_t *ira, rtc_t *rtc)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
	ipaddr_t	nexthop = *(ipaddr_t *)nexthop_arg;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	int		cgtp_flt_pkt;

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
		if (!tsol_get_pkt_label(mp, IPV4_VERSION, ira)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return;
		}
		/* Note that ira_tsl can be NULL here. */

		/* tsol_get_pkt_label sometimes does pullupmsg */
		ipha = (ipha_t *)mp->b_rptr;
	}

	/*
	 * Invoke the CGTP (multirouting) filtering module to process
	 * the incoming packet. Packets identified as duplicates
	 * must be discarded. Filtering is active only if the
	 * the ip_cgtp_filter ndd variable is non-zero.
	 */
	cgtp_flt_pkt = CGTP_IP_PKT_NOT_CGTP;
	if (ipst->ips_ip_cgtp_filter &&
	    ipst->ips_ip_cgtp_filter_ops != NULL) {
		netstackid_t stackid;

		stackid = ipst->ips_netstack->netstack_stackid;
		/*
		 * CGTP and IPMP are mutually exclusive so
		 * phyint_ifindex is fine here.
		 */
		cgtp_flt_pkt =
		    ipst->ips_ip_cgtp_filter_ops->cfo_filter(stackid,
		    ill->ill_phyint->phyint_ifindex, mp);
		if (cgtp_flt_pkt == CGTP_IP_PKT_DUPLICATE) {
			ip_drop_input("CGTP_IP_PKT_DUPLICATE", mp, ill);
			freemsg(mp);
			return;
		}
	}

	/*
	 * Brutal hack for DHCPv4 unicast: RFC2131 allows a DHCP
	 * server to unicast DHCP packets to a DHCP client using the
	 * IP address it is offering to the client.  This can be
	 * disabled through the "broadcast bit", but not all DHCP
	 * servers honor that bit.  Therefore, to interoperate with as
	 * many DHCP servers as possible, the DHCP client allows the
	 * server to unicast, but we treat those packets as broadcast
	 * here.  Note that we don't rewrite the packet itself since
	 * (a) that would mess up the checksums and (b) the DHCP
	 * client conn is bound to INADDR_ANY so ip_fanout_udp() will
	 * hand it the packet regardless.
	 */
	if (ill->ill_dhcpinit != 0 &&
	    ipha->ipha_version_and_hdr_length == IP_SIMPLE_HDR_VERSION &&
	    ipha->ipha_protocol == IPPROTO_UDP) {
		udpha_t *udpha;

		ipha = ip_pullup(mp, sizeof (ipha_t) + sizeof (udpha_t), ira);
		if (ipha == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards - dhcp", mp, ill);
			freemsg(mp);
			return;
		}
		/* Reload since pullupmsg() can change b_rptr. */
		udpha = (udpha_t *)&ipha[1];

		if (ntohs(udpha->uha_dst_port) == IPPORT_BOOTPC) {
			DTRACE_PROBE2(ip4__dhcpinit__pkt, ill_t *, ill,
			    mblk_t *, mp);
			/*
			 * This assumes that we deliver to all conns for
			 * multicast and broadcast packets.
			 */
			nexthop = INADDR_BROADCAST;
			ira->ira_flags |= IRAF_DHCP_UNICAST;
		}
	}

	/*
	 * If rsvpd is running, let RSVP daemon handle its processing
	 * and forwarding of RSVP multicast/unicast packets.
	 * If rsvpd is not running but mrouted is running, RSVP
	 * multicast packets are forwarded as multicast traffic
	 * and RSVP unicast packets are forwarded by unicast router.
	 * If neither rsvpd nor mrouted is running, RSVP multicast
	 * packets are not forwarded, but the unicast packets are
	 * forwarded like unicast traffic.
	 */
	if (ipha->ipha_protocol == IPPROTO_RSVP &&
	    ipst->ips_ipcl_proto_fanout_v4[IPPROTO_RSVP].connf_head != NULL) {
		/* RSVP packet and rsvpd running. Treat as ours */
		ip2dbg(("ip_input: RSVP for us: 0x%x\n", ntohl(nexthop)));
		/*
		 * We use a multicast address to get the packet to
		 * ire_recv_multicast_v4. There will not be a membership
		 * check since we set IRAF_RSVP
		 */
		nexthop = htonl(INADDR_UNSPEC_GROUP);
		ira->ira_flags |= IRAF_RSVP;
	}

	ill_input_short_v4(mp, ipha, &nexthop, ira, rtc);
}

/*
 * This is the tail-end of the full receive side packet handling.
 * It can be used directly when the configuration is simple.
 */
void
ill_input_short_v4(mblk_t *mp, void *iph_arg, void *nexthop_arg,
    ip_recv_attr_t *ira, rtc_t *rtc)
{
	ire_t		*ire;
	uint_t		opt_len;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint_t		pkt_len;
	ssize_t 	len;
	ipha_t		*ipha = (ipha_t *)iph_arg;
	ipaddr_t	nexthop = *(ipaddr_t *)nexthop_arg;
	ilb_stack_t	*ilbs = ipst->ips_netstack->netstack_ilb;
	uint_t		irr_flags;
#define	rptr	((uchar_t *)ipha)

	ASSERT(DB_TYPE(mp) == M_DATA);

	/*
	 * The following test for loopback is faster than
	 * IP_LOOPBACK_ADDR(), because it avoids any bitwise
	 * operations.
	 * Note that these addresses are always in network byte order
	 */
	if (((*(uchar_t *)&ipha->ipha_dst) == IN_LOOPBACKNET) ||
	    ((*(uchar_t *)&ipha->ipha_src) == IN_LOOPBACKNET)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
		ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
		freemsg(mp);
		return;
	}

	len = mp->b_wptr - rptr;
	pkt_len = ira->ira_pktlen;

	/* multiple mblk or too short */
	len -= pkt_len;
	if (len != 0) {
		mp = ip_check_length(mp, rptr, len, pkt_len,
		    IP_SIMPLE_HDR_LENGTH, ira);
		if (mp == NULL)
			return;
		ipha = (ipha_t *)mp->b_rptr;
	}

	DTRACE_IP7(receive, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
	    ipha, __dtrace_ipsr_ill_t *, ill, ipha_t *, ipha, ip6_t *, NULL,
	    int, 0);

	/*
	 * The event for packets being received from a 'physical'
	 * interface is placed after validation of the source and/or
	 * destination address as being local so that packets can be
	 * redirected to loopback addresses using ipnat.
	 */
	DTRACE_PROBE4(ip4__physical__in__start,
	    ill_t *, ill, ill_t *, NULL,
	    ipha_t *, ipha, mblk_t *, mp);

	if (HOOKS4_INTERESTED_PHYSICAL_IN(ipst)) {
		int	ll_multicast = 0;
		int	error;
		ipaddr_t orig_dst = ipha->ipha_dst;

		if (ira->ira_flags & IRAF_L2DST_MULTICAST)
			ll_multicast = HPE_MULTICAST;
		else if (ira->ira_flags & IRAF_L2DST_BROADCAST)
			ll_multicast = HPE_BROADCAST;

		FW_HOOKS(ipst->ips_ip4_physical_in_event,
		    ipst->ips_ipv4firewall_physical_in,
		    ill, NULL, ipha, mp, mp, ll_multicast, ipst, error);

		DTRACE_PROBE1(ip4__physical__in__end, mblk_t *, mp);

		if (mp == NULL)
			return;
		/* The length could have changed */
		ipha = (ipha_t *)mp->b_rptr;
		ira->ira_pktlen = ntohs(ipha->ipha_length);
		pkt_len = ira->ira_pktlen;

		/*
		 * In case the destination changed we override any previous
		 * change to nexthop.
		 */
		if (orig_dst != ipha->ipha_dst)
			nexthop = ipha->ipha_dst;
		if (nexthop == INADDR_ANY) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInAddrErrors);
			ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
			freemsg(mp);
			return;
		}
	}

	if (ipst->ips_ip4_observe.he_interested) {
		zoneid_t dzone;

		/*
		 * On the inbound path the src zone will be unknown as
		 * this packet has come from the wire.
		 */
		dzone = ip_get_zoneid_v4(nexthop, mp, ira, ALL_ZONES);
		ipobs_hook(mp, IPOBS_HOOK_INBOUND, ALL_ZONES, dzone, ill, ipst);
	}

	/*
	 * If there is a good HW IP header checksum we clear the need
	 * look at the IP header checksum.
	 */
	if ((DB_CKSUMFLAGS(mp) & HCK_IPV4_HDRCKSUM) &&
	    ILL_HCKSUM_CAPABLE(ill) && dohwcksum) {
		/* Header checksum was ok. Clear the flag */
		DB_CKSUMFLAGS(mp) &= ~HCK_IPV4_HDRCKSUM;
		ira->ira_flags &= ~IRAF_VERIFY_IP_CKSUM;
	}

	/*
	 * Here we check to see if we machine is setup as
	 * L3 loadbalancer and if the incoming packet is for a VIP
	 *
	 * Check the following:
	 * - there is at least a rule
	 * - protocol of the packet is supported
	 */
	if (ilb_has_rules(ilbs) && ILB_SUPP_L4(ipha->ipha_protocol)) {
		ipaddr_t	lb_dst;
		int		lb_ret;

		/* For convenience, we pull up the mblk. */
		if (mp->b_cont != NULL) {
			if (pullupmsg(mp, -1) == 0) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards - pullupmsg",
				    mp, ill);
				freemsg(mp);
				return;
			}
			ipha = (ipha_t *)mp->b_rptr;
		}

		/*
		 * We just drop all fragments going to any VIP, at
		 * least for now....
		 */
		if (ntohs(ipha->ipha_fragment_offset_and_flags) &
		    (IPH_MF | IPH_OFFSET)) {
			if (!ilb_rule_match_vip_v4(ilbs, nexthop, NULL)) {
				goto after_ilb;
			}

			ILB_KSTAT_UPDATE(ilbs, ip_frag_in, 1);
			ILB_KSTAT_UPDATE(ilbs, ip_frag_dropped, 1);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ILB fragment", mp, ill);
			freemsg(mp);
			return;
		}
		lb_ret = ilb_check_v4(ilbs, ill, mp, ipha, ipha->ipha_protocol,
		    (uint8_t *)ipha + IPH_HDR_LENGTH(ipha), &lb_dst);

		if (lb_ret == ILB_DROPPED) {
			/* Is this the right counter to increase? */
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

after_ilb:
	opt_len = ipha->ipha_version_and_hdr_length - IP_SIMPLE_HDR_VERSION;
	ira->ira_ip_hdr_length = IP_SIMPLE_HDR_LENGTH;
	if (opt_len != 0) {
		int error = 0;

		ira->ira_ip_hdr_length += (opt_len << 2);
		ira->ira_flags |= IRAF_IPV4_OPTIONS;

		/* IP Options present!  Validate the length. */
		mp = ip_check_optlen(mp, ipha, opt_len, pkt_len, ira);
		if (mp == NULL)
			return;

		/* Might have changed */
		ipha = (ipha_t *)mp->b_rptr;

		/* Verify IP header checksum before parsing the options */
		if ((ira->ira_flags & IRAF_VERIFY_IP_CKSUM) &&
		    ip_csum_hdr(ipha)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
			ip_drop_input("ipIfStatsInCksumErrs", mp, ill);
			freemsg(mp);
			return;
		}
		ira->ira_flags &= ~IRAF_VERIFY_IP_CKSUM;

		/*
		 * Go off to ip_input_options which returns the next hop
		 * destination address, which may have been affected
		 * by source routing.
		 */
		IP_STAT(ipst, ip_opt);

		nexthop = ip_input_options(ipha, nexthop, mp, ira, &error);
		if (error != 0) {
			/*
			 * An ICMP error has been sent and the packet has
			 * been dropped.
			 */
			return;
		}
	}

	if (ill->ill_flags & ILLF_ROUTER)
		irr_flags = IRR_ALLOCATE;
	else
		irr_flags = IRR_NONE;

	/* Can not use route cache with TX since the labels can differ */
	if (ira->ira_flags & IRAF_SYSTEM_LABELED) {
		if (CLASSD(nexthop)) {
			ire = ire_multicast(ill);
		} else {
			/* Match destination and label */
			ire = ire_route_recursive_v4(nexthop, 0, NULL,
			    ALL_ZONES, ira->ira_tsl, MATCH_IRE_SECATTR,
			    irr_flags, ira->ira_xmit_hint, ipst, NULL, NULL,
			    NULL);
		}
		/* Update the route cache so we do the ire_refrele */
		ASSERT(ire != NULL);
		if (rtc->rtc_ire != NULL)
			ire_refrele(rtc->rtc_ire);
		rtc->rtc_ire = ire;
		rtc->rtc_ipaddr = nexthop;
	} else if (nexthop == rtc->rtc_ipaddr && rtc->rtc_ire != NULL) {
		/* Use the route cache */
		ire = rtc->rtc_ire;
	} else {
		/* Update the route cache */
		if (CLASSD(nexthop)) {
			ire = ire_multicast(ill);
		} else {
			/* Just match the destination */
			ire = ire_route_recursive_dstonly_v4(nexthop, irr_flags,
			    ira->ira_xmit_hint, ipst);
		}
		ASSERT(ire != NULL);
		if (rtc->rtc_ire != NULL)
			ire_refrele(rtc->rtc_ire);
		rtc->rtc_ire = ire;
		rtc->rtc_ipaddr = nexthop;
	}

	ire->ire_ib_pkt_count++;

	/*
	 * Based on ire_type and ire_flags call one of:
	 *	ire_recv_local_v4 - for IRE_LOCAL
	 *	ire_recv_loopback_v4 - for IRE_LOOPBACK
	 *	ire_recv_multirt_v4 - if RTF_MULTIRT
	 *	ire_recv_noroute_v4 - if RTF_REJECT or RTF_BLACHOLE
	 *	ire_recv_multicast_v4 - for IRE_MULTICAST
	 *	ire_recv_broadcast_v4 - for IRE_BROADCAST
	 *	ire_recv_noaccept_v4 - for ire_noaccept ones
	 *	ire_recv_forward_v4 - for the rest.
	 */
	(*ire->ire_recvfn)(ire, mp, ipha, ira);
}
#undef rptr

/*
 * ire_recvfn for IREs that need forwarding
 */
void
ire_recv_forward_v4(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ill_t		*dst_ill;
	nce_t		*nce;
	ipaddr_t	src = ipha->ipha_src;
	uint32_t	added_tx_len;
	uint32_t	mtu, iremtu;

	if (ira->ira_flags & (IRAF_L2DST_MULTICAST|IRAF_L2DST_BROADCAST)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		ip_drop_input("l2 multicast not forwarded", mp, ill);
		freemsg(mp);
		return;
	}

	if (!(ill->ill_flags & ILLF_ROUTER) && !ip_source_routed(ipha, ipst)) {
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

		nce1 = ire_handle_condemned_nce(nce, ire, ipha, NULL, B_FALSE);
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
	 * We have to let source routed packets through if they go out
	 * the same interface i.e., they are 'ping -l' packets.
	 */
	if (!(dst_ill->ill_flags & ILLF_ROUTER) &&
	    !(ip_source_routed(ipha, ipst) && dst_ill == ill)) {
		if (ip_source_routed(ipha, ipst)) {
			ip_drop_input("ICMP_SOURCE_ROUTE_FAILED", mp, ill);
			icmp_unreachable(mp, ICMP_SOURCE_ROUTE_FAILED, ira);
			nce_refrele(nce);
			return;
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsForwProhibits);
		ip_drop_input("ipIfStatsForwProhibits", mp, ill);
		freemsg(mp);
		nce_refrele(nce);
		return;
	}

	if (ire->ire_zoneid != GLOBAL_ZONEID && ire->ire_zoneid != ALL_ZONES) {
		ipaddr_t	dst = ipha->ipha_dst;

		ire->ire_ib_pkt_count--;
		/*
		 * Should only use IREs that are visible from the
		 * global zone for forwarding.
		 * Take a source route into account the same way as ip_input
		 * did.
		 */
		if (ira->ira_flags & IRAF_IPV4_OPTIONS) {
			int		error = 0;

			dst = ip_input_options(ipha, dst, mp, ira, &error);
			ASSERT(error == 0);	/* ip_input checked */
		}
		ire = ire_route_recursive_v4(dst, 0, NULL, GLOBAL_ZONEID,
		    ira->ira_tsl, MATCH_IRE_SECATTR,
		    (ill->ill_flags & ILLF_ROUTER) ? IRR_ALLOCATE : IRR_NONE,
		    ira->ira_xmit_hint, ipst, NULL, NULL, NULL);
		ire->ire_ib_pkt_count++;
		(*ire->ire_recvfn)(ire, mp, ipha, ira);
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
			ip2dbg(("ire_recv_forward_v4: pkt dropped/deferred "
			    "during IPPF processing\n"));
			nce_refrele(nce);
			return;
		}
	}

	DTRACE_PROBE4(ip4__forwarding__start,
	    ill_t *, ill, ill_t *, dst_ill, ipha_t *, ipha, mblk_t *, mp);

	if (HOOKS4_INTERESTED_FORWARDING(ipst)) {
		int error;

		FW_HOOKS(ipst->ips_ip4_forwarding_event,
		    ipst->ips_ipv4firewall_forwarding,
		    ill, dst_ill, ipha, mp, mp, 0, ipst, error);

		DTRACE_PROBE1(ip4__forwarding__end, mblk_t *, mp);

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
		ipha = (ipha_t *)mp->b_rptr;
		ira->ira_pktlen = ntohs(ipha->ipha_length);
	}

	/* Packet is being forwarded. Turning off hwcksum flag. */
	DB_CKSUMFLAGS(mp) = 0;

	/*
	 * Martian Address Filtering [RFC 1812, Section 5.3.7]
	 * The loopback address check for both src and dst has already
	 * been checked in ip_input
	 * In the future one can envision adding RPF checks using number 3.
	 * If we already checked the same source address we can skip this.
	 */
	if (!(ira->ira_flags & IRAF_VERIFIED_SRC) ||
	    src != ira->ira_verified_src) {
		switch (ipst->ips_src_check) {
		case 0:
			break;
		case 2:
			if (ip_type_v4(src, ipst) == IRE_BROADCAST) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsForwProhibits);
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInAddrErrors);
				ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
				freemsg(mp);
				nce_refrele(nce);
				return;
			}
			/* FALLTHRU */

		case 1:
			if (CLASSD(src)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsForwProhibits);
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInAddrErrors);
				ip_drop_input("ipIfStatsInAddrErrors", mp, ill);
				freemsg(mp);
				nce_refrele(nce);
				return;
			}
			break;
		}
		/* Remember for next packet */
		ira->ira_flags |= IRAF_VERIFIED_SRC;
		ira->ira_verified_src = src;
	}

	/*
	 * Check if packet is going out the same link on which it arrived.
	 * Means we might need to send a redirect.
	 */
	if (IS_ON_SAME_LAN(dst_ill, ill) && ipst->ips_ip_g_send_redirects) {
		ip_send_potential_redirect_v4(mp, ipha, ire, ira);
	}

	added_tx_len = 0;
	if (ira->ira_flags & IRAF_SYSTEM_LABELED) {
		mblk_t		*mp1;
		uint32_t	old_pkt_len = ira->ira_pktlen;

		/* Verify IP header checksum before adding/removing options */
		if ((ira->ira_flags & IRAF_VERIFY_IP_CKSUM) &&
		    ip_csum_hdr(ipha)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
			ip_drop_input("ipIfStatsInCksumErrs", mp, ill);
			freemsg(mp);
			nce_refrele(nce);
			return;
		}
		ira->ira_flags &= ~IRAF_VERIFY_IP_CKSUM;

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
		 * IP needs to send an ICMP too big.
		 */
		mp = mp1;
		ipha = (ipha_t *)mp->b_rptr;
		ira->ira_pktlen = ntohs(ipha->ipha_length);
		ira->ira_ip_hdr_length = IPH_HDR_LENGTH(ipha);
		if (ira->ira_pktlen > old_pkt_len)
			added_tx_len = ira->ira_pktlen - old_pkt_len;

		/* Options can have been added or removed */
		if (ira->ira_ip_hdr_length != IP_SIMPLE_HDR_LENGTH)
			ira->ira_flags |= IRAF_IPV4_OPTIONS;
		else
			ira->ira_flags &= ~IRAF_IPV4_OPTIONS;
	}

	mtu = dst_ill->ill_mtu;
	if ((iremtu = ire->ire_metrics.iulp_mtu) != 0 && iremtu < mtu)
		mtu = iremtu;
	ip_forward_xmit_v4(nce, ill, mp, ipha, ira, mtu, added_tx_len);
	nce_refrele(nce);
}

/*
 * Used for sending out unicast and multicast packets that are
 * forwarded.
 */
void
ip_forward_xmit_v4(nce_t *nce, ill_t *ill, mblk_t *mp, ipha_t *ipha,
    ip_recv_attr_t *ira, uint32_t mtu, uint32_t added_tx_len)
{
	ill_t		*dst_ill = nce->nce_ill;
	uint32_t	pkt_len;
	uint32_t	sum;
	iaflags_t	iraflags = ira->ira_flags;
	ip_stack_t	*ipst = ill->ill_ipst;
	iaflags_t	ixaflags;

	if (ipha->ipha_ttl <= 1) {
		/* Perhaps the checksum was bad */
		if ((iraflags & IRAF_VERIFY_IP_CKSUM) && ip_csum_hdr(ipha)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
			ip_drop_input("ipIfStatsInCksumErrs", mp, ill);
			freemsg(mp);
			return;
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ICMP_TTL_EXCEEDED", mp, ill);
		icmp_time_exceeded(mp, ICMP_TTL_EXCEEDED, ira);
		return;
	}
	ipha->ipha_ttl--;
	/* Adjust the checksum to reflect the ttl decrement. */
	sum = (int)ipha->ipha_hdr_checksum + IP_HDR_CSUM_TTL_ADJUST;
	ipha->ipha_hdr_checksum = (uint16_t)(sum + (sum >> 16));

	/* Check if there are options to update */
	if (iraflags & IRAF_IPV4_OPTIONS) {
		ASSERT(ipha->ipha_version_and_hdr_length !=
		    IP_SIMPLE_HDR_VERSION);
		ASSERT(!(iraflags & IRAF_VERIFY_IP_CKSUM));

		if (!ip_forward_options(mp, ipha, dst_ill, ira)) {
			/* ipIfStatsForwProhibits and ip_drop_input done */
			return;
		}

		ipha->ipha_hdr_checksum = 0;
		ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
	}

	/* Initiate Write side IPPF processing before any fragmentation */
	if (IPP_ENABLED(IPP_FWD_OUT, ipst)) {
		/* ip_process translates an IS_UNDER_IPMP */
		mp = ip_process(IPP_FWD_OUT, mp, dst_ill, dst_ill);
		if (mp == NULL) {
			/* ip_drop_packet and MIB done */
			ip2dbg(("ire_recv_forward_v4: pkt dropped/deferred" \
			    " during IPPF processing\n"));
			return;
		}
	}

	pkt_len = ira->ira_pktlen;

	BUMP_MIB(dst_ill->ill_ip_mib, ipIfStatsHCOutForwDatagrams);

	ixaflags = IXAF_IS_IPV4 | IXAF_NO_DEV_FLOW_CTL;

	if (pkt_len > mtu) {
		/*
		 * It needs fragging on its way out.  If we haven't
		 * verified the header checksum yet we do it now since
		 * are going to put a surely good checksum in the
		 * outgoing header, we have to make sure that it
		 * was good coming in.
		 */
		if ((iraflags & IRAF_VERIFY_IP_CKSUM) && ip_csum_hdr(ipha)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
			ip_drop_input("ipIfStatsInCksumErrs", mp, ill);
			freemsg(mp);
			return;
		}
		if (ipha->ipha_fragment_offset_and_flags & IPH_DF_HTONS) {
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
				mtu = tsol_pmtu_adjust(mp, mtu, added_tx_len,
				    AF_INET);
			}

			icmp_frag_needed(mp, mtu, ira);
			return;
		}

		(void) ip_fragment_v4(mp, nce, ixaflags, pkt_len, mtu,
		    ira->ira_xmit_hint, GLOBAL_ZONEID, 0, ip_xmit, NULL);
		return;
	}

	ASSERT(pkt_len == ntohs(((ipha_t *)mp->b_rptr)->ipha_length));
	if (iraflags & IRAF_LOOPBACK_COPY) {
		/*
		 * IXAF_NO_LOOP_ZONEID is not set hence 7th arg
		 * is don't care
		 */
		(void) ip_postfrag_loopcheck(mp, nce,
		    ixaflags | IXAF_LOOPBACK_COPY,
		    pkt_len, ira->ira_xmit_hint, GLOBAL_ZONEID, 0, NULL);
	} else {
		(void) ip_xmit(mp, nce, ixaflags, pkt_len, ira->ira_xmit_hint,
		    GLOBAL_ZONEID, 0, NULL);
	}
}

/*
 * ire_recvfn for RTF_REJECT and RTF_BLACKHOLE routes, including IRE_NOROUTE,
 * which is what ire_route_recursive returns when there is no matching ire.
 * Send ICMP unreachable unless blackhole.
 */
void
ire_recv_noroute_v4(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
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

	ip_rts_change(RTM_MISS, ipha->ipha_dst, 0, 0, 0, 0, 0, 0, RTA_DST,
	    ipst);

	if (ire->ire_flags & RTF_BLACKHOLE) {
		ip_drop_input("ipIfStatsInNoRoutes RTF_BLACKHOLE", mp, ill);
		freemsg(mp);
	} else {
		ip_drop_input("ipIfStatsInNoRoutes RTF_REJECT", mp, ill);

		if (ip_source_routed(ipha, ipst)) {
			icmp_unreachable(mp, ICMP_SOURCE_ROUTE_FAILED, ira);
		} else {
			icmp_unreachable(mp, ICMP_HOST_UNREACHABLE, ira);
		}
	}
}

/*
 * ire_recvfn for IRE_LOCALs marked with ire_noaccept. Such IREs are used for
 * VRRP when in noaccept mode.
 * We silently drop the packet. ARP handles packets even if noaccept is set.
 */
/* ARGSUSED */
void
ire_recv_noaccept_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
	ip_drop_input("ipIfStatsInDiscards - noaccept", mp, ill);
	freemsg(mp);
}

/*
 * ire_recvfn for IRE_BROADCAST.
 */
void
ire_recv_broadcast_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
	ill_t		*ill = ira->ira_ill;
	ill_t		*dst_ill = ire->ire_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ire_t		*alt_ire;
	nce_t		*nce;
	ipaddr_t	ipha_dst;

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInBcastPkts);

	/* Tag for higher-level protocols */
	ira->ira_flags |= IRAF_BROADCAST;

	/*
	 * Whether local or directed broadcast forwarding: don't allow
	 * for TCP.
	 */
	if (ipha->ipha_protocol == IPPROTO_TCP) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", mp, ill);
		freemsg(mp);
		return;
	}

	/*
	 * So that we don't end up with dups, only one ill an IPMP group is
	 * nominated to receive broadcast traffic.
	 * If we have no cast_ill we are liberal and accept everything.
	 */
	if (IS_UNDER_IPMP(ill)) {
		/* For an under ill_grp can change under lock */
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
		if (!ill->ill_nom_cast && ill->ill_grp != NULL &&
		    ill->ill_grp->ig_cast_ill != NULL) {
			rw_exit(&ipst->ips_ill_g_lock);
			/* No MIB since this is normal operation */
			ip_drop_input("not nom_cast", mp, ill);
			freemsg(mp);
			return;
		}
		rw_exit(&ipst->ips_ill_g_lock);

		ira->ira_ruifindex = ill_get_upper_ifindex(ill);
	}

	/*
	 * After reassembly and IPsec we will need to duplicate the
	 * broadcast packet for all matching zones on the ill.
	 */
	ira->ira_zoneid = ALL_ZONES;

	/*
	 * Check for directed broadcast i.e. ire->ire_ill is different than
	 * the incoming ill.
	 * The same broadcast address can be assigned to multiple interfaces
	 * so have to check explicitly for that case by looking up the alt_ire
	 */
	if (dst_ill == ill && !(ire->ire_flags & RTF_MULTIRT)) {
		/* Reassemble on the ill on which the packet arrived */
		ip_input_local_v4(ire, mp, ipha, ira);
		/* Restore */
		ira->ira_ruifindex = ill->ill_phyint->phyint_ifindex;
		return;
	}

	/* Is there an IRE_BROADCAST on the incoming ill? */
	ipha_dst = ((ira->ira_flags & IRAF_DHCP_UNICAST) ? INADDR_BROADCAST :
	    ipha->ipha_dst);
	alt_ire = ire_ftable_lookup_v4(ipha_dst, 0, 0, IRE_BROADCAST, ill,
	    ALL_ZONES, ira->ira_tsl,
	    MATCH_IRE_TYPE|MATCH_IRE_ILL|MATCH_IRE_SECATTR, 0, ipst, NULL);
	if (alt_ire != NULL) {
		/* Not a directed broadcast */
		/*
		 * In the special case of multirouted broadcast
		 * packets, we unconditionally need to "gateway"
		 * them to the appropriate interface here so that reassembly
		 * works. We know that the IRE_BROADCAST on cgtp0 doesn't
		 * have RTF_MULTIRT set so we look for such an IRE in the
		 * bucket.
		 */
		if (alt_ire->ire_flags & RTF_MULTIRT) {
			irb_t		*irb;
			ire_t		*ire1;

			irb = ire->ire_bucket;
			irb_refhold(irb);
			for (ire1 = irb->irb_ire; ire1 != NULL;
			    ire1 = ire1->ire_next) {
				if (IRE_IS_CONDEMNED(ire1))
					continue;
				if (!(ire1->ire_type & IRE_BROADCAST) ||
				    (ire1->ire_flags & RTF_MULTIRT))
					continue;
				ill = ire1->ire_ill;
				ill_refhold(ill);
				break;
			}
			irb_refrele(irb);
			if (ire1 != NULL) {
				ill_t *orig_ill = ira->ira_ill;

				ire_refrele(alt_ire);
				/* Reassemble on the new ill */
				ira->ira_ill = ill;
				ip_input_local_v4(ire, mp, ipha, ira);
				ill_refrele(ill);
				/* Restore */
				ira->ira_ill = orig_ill;
				ira->ira_ruifindex =
				    orig_ill->ill_phyint->phyint_ifindex;
				return;
			}
		}
		ire_refrele(alt_ire);
		/* Reassemble on the ill on which the packet arrived */
		ip_input_local_v4(ire, mp, ipha, ira);
		goto done;
	}

	/*
	 * This is a directed broadcast
	 *
	 * If directed broadcast is allowed, then forward the packet out
	 * the destination interface with IXAF_LOOPBACK_COPY set. That will
	 * result in ip_input() receiving a copy of the packet on the
	 * appropriate ill. (We could optimize this to avoid the extra trip
	 * via ip_input(), but since directed broadcasts are normally disabled
	 * it doesn't make sense to optimize it.)
	 */
	if (!ipst->ips_ip_g_forward_directed_bcast ||
	    (ira->ira_flags & (IRAF_L2DST_MULTICAST|IRAF_L2DST_BROADCAST))) {
		ip_drop_input("directed broadcast not allowed", mp, ill);
		freemsg(mp);
		goto done;
	}
	if ((ira->ira_flags & IRAF_VERIFY_IP_CKSUM) && ip_csum_hdr(ipha)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
		ip_drop_input("ipIfStatsInCksumErrs", mp, ill);
		freemsg(mp);
		goto done;
	}

	/*
	 * Clear the indication that this may have hardware
	 * checksum as we are not using it for forwarding.
	 */
	DB_CKSUMFLAGS(mp) = 0;

	/*
	 * Adjust ttl to 2 (1+1 - the forward engine will decrement it by one.
	 */
	ipha->ipha_ttl = ipst->ips_ip_broadcast_ttl + 1;
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);

	/*
	 * We use ip_forward_xmit to do any fragmentation.
	 * and loopback copy on the outbound interface.
	 *
	 * Make it so that IXAF_LOOPBACK_COPY to be set on transmit side.
	 */
	ira->ira_flags |= IRAF_LOOPBACK_COPY;

	nce = arp_nce_init(dst_ill, ipha->ipha_dst, IRE_BROADCAST);
	if (nce == NULL) {
		BUMP_MIB(dst_ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("No nce", mp, dst_ill);
		freemsg(mp);
		goto done;
	}

	ip_forward_xmit_v4(nce, ill, mp, ipha, ira, dst_ill->ill_mc_mtu, 0);
	nce_refrele(nce);
done:
	/* Restore */
	ira->ira_ruifindex = ill->ill_phyint->phyint_ifindex;
}

/*
 * ire_recvfn for IRE_MULTICAST.
 */
void
ire_recv_multicast_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ire->ire_ill == ira->ira_ill);

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInMcastPkts);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInMcastOctets, ira->ira_pktlen);

	/* RSVP hook */
	if (ira->ira_flags & IRAF_RSVP)
		goto forus;

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
		retval = ip_mforward(mp, ira);
		/* ip_mforward updates mib variables if needed */

		switch (retval) {
		case 0:
			/*
			 * pkt is okay and arrived on phyint.
			 *
			 * If we are running as a multicast router
			 * we need to see all IGMP and/or PIM packets.
			 */
			if ((ipha->ipha_protocol == IPPROTO_IGMP) ||
			    (ipha->ipha_protocol == IPPROTO_PIM)) {
				goto forus;
			}
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
			 * we need to see all igmp packets.
			 */
			if (ipha->ipha_protocol == IPPROTO_IGMP) {
				goto forus;
			}
			ip_drop_input("Multicast on tunnel ignored", mp, ill);
			freemsg(mp);
			goto done;
		}
	}

	/*
	 * Check if we have members on this ill. This is not necessary for
	 * correctness because even if the NIC/GLD had a leaky filter, we
	 * filter before passing to each conn_t.
	 */
	if (!ill_hasmembers_v4(ill, ipha->ipha_dst)) {
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
	ip2dbg(("ire_recv_multicast_v4: multicast for us: 0x%x\n",
	    ntohl(ipha->ipha_dst)));

	/*
	 * After reassembly and IPsec we will need to duplicate the
	 * multicast packet for all matching zones on the ill.
	 */
	ira->ira_zoneid = ALL_ZONES;

	/* Reassemble on the ill on which the packet arrived */
	ip_input_local_v4(ire, mp, ipha, ira);
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
ire_recv_multirt_v4(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
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
ire_recv_loopback_v4(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
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

		ip_input_local_v4(ire, mp, ipha, ira);

		/* Restore */
		ASSERT(ira->ira_ill == ire_ill);
		ira->ira_ill = ill;
		return;

	}
	ip_input_local_v4(ire, mp, ipha, ira);
}

/*
 * ire_recvfn for IRE_LOCAL.
 */
void
ire_recv_local_v4(ire_t *ire, mblk_t *mp, void *iph_arg, ip_recv_attr_t *ira)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
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

		new_ire = ip_check_multihome(&ipha->ipha_dst, ire, ill);
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

		ip_input_local_v4(new_ire, mp, ipha, ira);

		/* Restore */
		ASSERT(ira->ira_ill == new_ire->ire_ill);
		ira->ira_ill = ill;
		ira->ira_ruifindex = ill->ill_phyint->phyint_ifindex;

		if (new_ire != ire)
			ire_refrele(new_ire);
		return;
	}

	ip_input_local_v4(ire, mp, ipha, ira);
}

/*
 * Common function for packets arriving for the host. Handles
 * checksum verification, reassembly checks, etc.
 */
static void
ip_input_local_v4(ire_t *ire, mblk_t *mp, ipha_t *ipha, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	iaflags_t	iraflags = ira->ira_flags;

	/*
	 * Verify IP header checksum. If the packet was AH or ESP then
	 * this flag has already been cleared. Likewise if the packet
	 * had a hardware checksum.
	 */
	if ((iraflags & IRAF_VERIFY_IP_CKSUM) && ip_csum_hdr(ipha)) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInCksumErrs);
		ip_drop_input("ipIfStatsInCksumErrs", mp, ill);
		freemsg(mp);
		return;
	}

	if (iraflags & IRAF_IPV4_OPTIONS) {
		if (!ip_input_local_options(mp, ipha, ira)) {
			/* Error has been sent and mp consumed */
			return;
		}
		/*
		 * Some old hardware does partial checksum by including the
		 * whole IP header, so the partial checksum value might have
		 * become invalid if any option in the packet have been
		 * updated. Always clear partial checksum flag here.
		 */
		DB_CKSUMFLAGS(mp) &= ~HCK_PARTIALCKSUM;
	}

	/*
	 * Is packet part of fragmented IP packet?
	 * We compare against defined values in network byte order
	 */
	if (ipha->ipha_fragment_offset_and_flags &
	    (IPH_MF_HTONS | IPH_OFFSET_HTONS)) {
		/*
		 * Make sure we have ira_l2src before we loose the original
		 * mblk
		 */
		if (!(ira->ira_flags & IRAF_L2SRC_SET))
			ip_setl2src(mp, ira, ira->ira_rill);

		mp = ip_input_fragment(mp, ipha, ira);
		if (mp == NULL)
			return;
		/* Completed reassembly */
		ipha = (ipha_t *)mp->b_rptr;
	}

	/*
	 * For broadcast and multicast we need some extra work before
	 * we call ip_fanout_v4(), since in the case of shared-IP zones
	 * we need to pretend that a packet arrived for each zoneid.
	 */
	if (iraflags & IRAF_MULTIBROADCAST) {
		if (iraflags & IRAF_BROADCAST)
			ip_input_broadcast_v4(ire, mp, ipha, ira);
		else
			ip_input_multicast_v4(ire, mp, ipha, ira);
		return;
	}
	ip_fanout_v4(mp, ipha, ira);
}


/*
 * Handle multiple zones which match the same broadcast address
 * and ill by delivering a packet to each of them.
 * Walk the bucket and look for different ire_zoneid but otherwise
 * the same IRE (same ill/addr/mask/type).
 * Note that ire_add() tracks IREs that are identical in all
 * fields (addr/mask/type/gw/ill/zoneid) within a single IRE by
 * increasing ire_identical_cnt. Thus we don't need to be concerned
 * about those.
 */
static void
ip_input_broadcast_v4(ire_t *ire, mblk_t *mp, ipha_t *ipha, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	netstack_t	*ns = ipst->ips_netstack;
	irb_t		*irb;
	ire_t		*ire1;
	mblk_t		*mp1;
	ipha_t		*ipha1;
	uint_t		ira_pktlen = ira->ira_pktlen;
	uint16_t	ira_ip_hdr_length = ira->ira_ip_hdr_length;

	irb = ire->ire_bucket;

	/*
	 * If we don't have more than one shared-IP zone, or if
	 * there can't be more than one IRE_BROADCAST for this
	 * IP address, then just set the zoneid and proceed.
	 */
	if (ns->netstack_numzones == 1 || irb->irb_ire_cnt == 1) {
		ira->ira_zoneid = ire->ire_zoneid;

		ip_fanout_v4(mp, ipha, ira);
		return;
	}
	irb_refhold(irb);
	for (ire1 = irb->irb_ire; ire1 != NULL; ire1 = ire1->ire_next) {
		/* We do the main IRE after the end of the loop */
		if (ire1 == ire)
			continue;

		/*
		 * Only IREs for the same IP address should be in the same
		 * bucket.
		 * But could have IRE_HOSTs in the case of CGTP.
		 */
		ASSERT(ire1->ire_addr == ire->ire_addr);
		if (!(ire1->ire_type & IRE_BROADCAST))
			continue;

		if (IRE_IS_CONDEMNED(ire1))
			continue;

		mp1 = copymsg(mp);
		if (mp1 == NULL) {
			/* Failed to deliver to one zone */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			continue;
		}
		ira->ira_zoneid = ire1->ire_zoneid;
		ipha1 = (ipha_t *)mp1->b_rptr;
		ip_fanout_v4(mp1, ipha1, ira);
		/*
		 * IPsec might have modified ira_pktlen and ira_ip_hdr_length
		 * so we restore them for a potential next iteration
		 */
		ira->ira_pktlen = ira_pktlen;
		ira->ira_ip_hdr_length = ira_ip_hdr_length;
	}
	irb_refrele(irb);
	/* Do the main ire */
	ira->ira_zoneid = ire->ire_zoneid;
	ip_fanout_v4(mp, ipha, ira);
}

/*
 * Handle multiple zones which want to receive the same multicast packets
 * on this ill by delivering a packet to each of them.
 *
 * Note that for packets delivered to transports we could instead do this
 * as part of the fanout code, but since we need to handle icmp_inbound
 * it is simpler to have multicast work the same as broadcast.
 *
 * The ip_fanout matching for multicast matches based on ilm independent of
 * zoneid since the zoneid restriction is applied when joining a multicast
 * group.
 */
/* ARGSUSED */
static void
ip_input_multicast_v4(ire_t *ire, mblk_t *mp, ipha_t *ipha, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	iaflags_t	iraflags = ira->ira_flags;
	ip_stack_t	*ipst = ill->ill_ipst;
	netstack_t	*ns = ipst->ips_netstack;
	zoneid_t	zoneid;
	mblk_t		*mp1;
	ipha_t		*ipha1;
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
	    !ill_hasmembers_otherzones_v4(ill, ipha->ipha_dst,
	    GLOBAL_ZONEID)) {
		ira->ira_zoneid = GLOBAL_ZONEID;

		/* If sender didn't want this zone to receive it, drop */
		if ((iraflags & IRAF_NO_LOOP_ZONEID_SET) &&
		    ira->ira_no_loop_zoneid == ira->ira_zoneid) {
			ip_drop_input("Multicast but wrong zoneid", mp, ill);
			freemsg(mp);
			return;
		}
		ip_fanout_v4(mp, ipha, ira);
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
	zoneid = ill_hasmembers_nextzone_v4(ill, ipha->ipha_dst, ALL_ZONES);
	for (; zoneid != ALL_ZONES;
	    zoneid = ill_hasmembers_nextzone_v4(ill, ipha->ipha_dst, zoneid)) {
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
		ipha1 = (ipha_t *)mp1->b_rptr;
		ip_fanout_v4(mp1, ipha1, ira);
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
		ip_fanout_v4(mp, ipha, ira);
	}
}


/*
 * Determine the zoneid and IRAF_TX_* flags if trusted extensions
 * is in use. Updates ira_zoneid and ira_flags as a result.
 */
static void
ip_fanout_tx_v4(mblk_t *mp, ipha_t *ipha, uint8_t protocol,
    uint_t ip_hdr_length, ip_recv_attr_t *ira)
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

	up = (uint16_t *)((uchar_t *)ipha + ip_hdr_length);
	switch (protocol) {
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
	case IPPROTO_UDP:
		/* Caller ensures this */
		ASSERT(((uchar_t *)ipha) + ip_hdr_length +4 <= mp->b_wptr);

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
ip_input_cksum_err_v4(uint8_t protocol, uint16_t hck_flags, ill_t *ill)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	switch (protocol) {
	case IPPROTO_TCP:
		BUMP_MIB(ill->ill_ip_mib, tcpIfStatsInErrs);

		if (hck_flags & HCK_FULLCKSUM)
			IP_STAT(ipst, ip_tcp_in_full_hw_cksum_err);
		else if (hck_flags & HCK_PARTIALCKSUM)
			IP_STAT(ipst, ip_tcp_in_part_hw_cksum_err);
		else
			IP_STAT(ipst, ip_tcp_in_sw_cksum_err);
		break;
	case IPPROTO_UDP:
		BUMP_MIB(ill->ill_ip_mib, udpIfStatsInCksumErrs);
		if (hck_flags & HCK_FULLCKSUM)
			IP_STAT(ipst, ip_udp_in_full_hw_cksum_err);
		else if (hck_flags & HCK_PARTIALCKSUM)
			IP_STAT(ipst, ip_udp_in_part_hw_cksum_err);
		else
			IP_STAT(ipst, ip_udp_in_sw_cksum_err);
		break;
	case IPPROTO_ICMP:
		BUMP_MIB(&ipst->ips_icmp_mib, icmpInCksumErrs);
		break;
	default:
		ASSERT(0);
		break;
	}
}

/* Calculate the IPv4 pseudo-header checksum */
uint32_t
ip_input_cksum_pseudo_v4(ipha_t *ipha, ip_recv_attr_t *ira)
{
	uint_t		ulp_len;
	uint32_t	cksum;
	uint8_t		protocol = ira->ira_protocol;
	uint16_t	ip_hdr_length = ira->ira_ip_hdr_length;

#define	iphs    ((uint16_t *)ipha)

	switch (protocol) {
	case IPPROTO_TCP:
		ulp_len = ira->ira_pktlen - ip_hdr_length;

		/* Protocol and length */
		cksum = htons(ulp_len) + IP_TCP_CSUM_COMP;
		/* IP addresses */
		cksum += iphs[6] + iphs[7] + iphs[8] + iphs[9];
		break;

	case IPPROTO_UDP: {
		udpha_t		*udpha;

		udpha = (udpha_t  *)((uchar_t *)ipha + ip_hdr_length);

		/* Protocol and length */
		cksum = udpha->uha_length + IP_UDP_CSUM_COMP;
		/* IP addresses */
		cksum += iphs[6] + iphs[7] + iphs[8] + iphs[9];
		break;
	}

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
ip_input_sw_cksum_v4(mblk_t *mp, ipha_t *ipha, ip_recv_attr_t *ira)
{
	ip_stack_t	*ipst = ira->ira_ill->ill_ipst;
	uint32_t	cksum;
	uint8_t		protocol = ira->ira_protocol;
	uint16_t	ip_hdr_length = ira->ira_ip_hdr_length;

	IP_STAT(ipst, ip_in_sw_cksum);

	ASSERT(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);

	cksum = ip_input_cksum_pseudo_v4(ipha, ira);
	cksum = IP_CSUM(mp, ip_hdr_length, cksum);
	if (cksum == 0)
		return (B_TRUE);

	ip_input_cksum_err_v4(protocol, 0, ira->ira_ill);
	return (B_FALSE);
}

/*
 * Verify the ULP checksums.
 * Returns B_TRUE if ok, or if the ULP doesn't have a well-defined checksum
 * algorithm.
 * Increments statistics if failed.
 */
static boolean_t
ip_input_cksum_v4(iaflags_t iraflags, mblk_t *mp, ipha_t *ipha,
    ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_rill;
	uint16_t	hck_flags;
	uint32_t	cksum;
	mblk_t		*mp1;
	int32_t		len;
	uint8_t		protocol = ira->ira_protocol;
	uint16_t	ip_hdr_length = ira->ira_ip_hdr_length;


	switch (protocol) {
	case IPPROTO_TCP:
		break;

	case IPPROTO_UDP: {
		udpha_t		*udpha;

		udpha = (udpha_t  *)((uchar_t *)ipha + ip_hdr_length);
		if (udpha->uha_checksum == 0) {
			/* Packet doesn't have a UDP checksum */
			return (B_TRUE);
		}
		break;
	}
	case IPPROTO_SCTP: {
		sctp_hdr_t	*sctph;
		uint32_t	pktsum;

		sctph = (sctp_hdr_t *)((uchar_t *)ipha + ip_hdr_length);
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
		return (ip_input_sw_cksum_v4(mp, ipha, ira));
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
		ip_input_cksum_err_v4(protocol, hck_flags, ira->ira_ill);
		return (B_FALSE);
	}

	mp1 = mp->b_cont;
	if ((hck_flags & HCK_PARTIALCKSUM) &&
	    (mp1 == NULL || mp1->b_cont == NULL) &&
	    ip_hdr_length >= DB_CKSUMSTART(mp) &&
	    ((len = ip_hdr_length - DB_CKSUMSTART(mp)) & 1) == 0) {
		uint32_t	adj;
		uchar_t		*cksum_start;

		cksum = ip_input_cksum_pseudo_v4(ipha, ira);

		cksum_start = ((uchar_t *)ipha + DB_CKSUMSTART(mp));

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

		ip_input_cksum_err_v4(protocol, hck_flags, ira->ira_ill);
		return (B_FALSE);
	}
	return (ip_input_sw_cksum_v4(mp, ipha, ira));
}


/*
 * Handle fanout of received packets.
 * Unicast packets that are looped back (from ire_send_local_v4) and packets
 * from the wire are differentiated by checking IRAF_VERIFY_ULP_CKSUM.
 *
 * IPQoS Notes
 * Before sending it to the client, invoke IPPF processing. Policy processing
 * takes place only if the callout_position, IPP_LOCAL_IN, is enabled.
 */
void
ip_fanout_v4(mblk_t *mp, ipha_t *ipha, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	iaflags_t	iraflags = ira->ira_flags;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint8_t		protocol = ipha->ipha_protocol;
	conn_t		*connp;
#define	rptr	((uchar_t *)ipha)
	uint_t		ip_hdr_length;
	uint_t		min_ulp_header_length;
	int		offset;
	ssize_t		len;
	netstack_t	*ns = ipst->ips_netstack;
	ipsec_stack_t	*ipss = ns->netstack_ipsec;
	ill_t		*rill = ira->ira_rill;

	ASSERT(ira->ira_pktlen == ntohs(ipha->ipha_length));

	ip_hdr_length = ira->ira_ip_hdr_length;
	ira->ira_protocol = protocol;

	/*
	 * Time for IPP once we've done reassembly and IPsec.
	 * We skip this for loopback packets since we don't do IPQoS
	 * on loopback.
	 */
	if (IPP_ENABLED(IPP_LOCAL_IN, ipst) &&
	    !(iraflags & IRAF_LOOPBACK) &&
	    (protocol != IPPROTO_ESP || protocol != IPPROTO_AH)) {
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
		min_ulp_header_length = ICMPH_SIZE;
		break;
	default:
		min_ulp_header_length = 0;
		break;
	}
	/* Make sure we have the min ULP header length */
	len = mp->b_wptr - rptr;
	if (len < ip_hdr_length + min_ulp_header_length) {
		if (ira->ira_pktlen < ip_hdr_length + min_ulp_header_length) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInTruncatedPkts);
			ip_drop_input("ipIfStatsInTruncatedPkts", mp, ill);
			freemsg(mp);
			return;
		}
		IP_STAT(ipst, ip_recv_pullup);
		ipha = ip_pullup(mp, ip_hdr_length + min_ulp_header_length,
		    ira);
		if (ipha == NULL)
			goto discard;
		len = mp->b_wptr - rptr;
	}

	/*
	 * If trusted extensions then determine the zoneid and TX specific
	 * ira_flags.
	 */
	if (iraflags & IRAF_SYSTEM_LABELED) {
		/* This can update ira->ira_flags and ira->ira_zoneid */
		ip_fanout_tx_v4(mp, ipha, protocol, ip_hdr_length, ira);
		iraflags = ira->ira_flags;
	}


	/* Verify ULP checksum. Handles TCP, UDP, and SCTP */
	if (iraflags & IRAF_VERIFY_ULP_CKSUM) {
		if (!ip_input_cksum_v4(iraflags, mp, ipha, ira)) {
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
		/* For TCP, discard broadcast and multicast packets. */
		if (iraflags & IRAF_MULTIBROADCAST)
			goto discard;

		/* First mblk contains IP+TCP headers per above check */
		ASSERT(len >= ip_hdr_length + TCP_MIN_HEADER_LENGTH);

		/* TCP options present? */
		offset = ((uchar_t *)ipha)[ip_hdr_length + 12] >> 4;
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
				if (ira->ira_pktlen < offset) {
					BUMP_MIB(ill->ill_ip_mib,
					    ipIfStatsInTruncatedPkts);
					ip_drop_input(
					    "ipIfStatsInTruncatedPkts",
					    mp, ill);
					freemsg(mp);
					return;
				}
				IP_STAT(ipst, ip_recv_pullup);
				ipha = ip_pullup(mp, offset, ira);
				if (ipha == NULL)
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
		connp = ipcl_classify_v4(mp, IPPROTO_TCP, ip_hdr_length,
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
		if (CONN_INBOUND_POLICY_PRESENT(connp, ipss) ||
		    (iraflags & IRAF_IPSEC_SECURE)) {
			mp = ipsec_check_inbound_policy(mp, connp,
			    ipha, NULL, ira);
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
				    SQTAG_IP_TCP_INPUT);
			}
		} else {
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp, connp->conn_recv,
			    connp, ira, ip_squeue_flag, SQTAG_IP_TCP_INPUT);
		}
		ira->ira_ill = ill;
		ira->ira_rill = rill;
		return;

	case IPPROTO_SCTP: {
		sctp_hdr_t	*sctph;
		in6_addr_t	map_src, map_dst;
		uint32_t	ports;	/* Source and destination ports */
		sctp_stack_t	*sctps = ipst->ips_netstack->netstack_sctp;

		/* For SCTP, discard broadcast and multicast packets. */
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

		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &map_dst);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &map_src);
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
			ip_fanout_sctp_raw(mp, ipha, NULL, ports, ira);
			return;
		}
		connp = sctp_fanout(&map_src, &map_dst, ports, ira, mp,
		    sctps, sctph);
		if (connp == NULL) {
			/* Check for raw socket or OOTB handling */
			ip_fanout_sctp_raw(mp, ipha, NULL, ports, ira);
			return;
		}
		if (connp->conn_incoming_ifindex != 0 &&
		    connp->conn_incoming_ifindex != ira->ira_ruifindex) {
			CONN_DEC_REF(connp);
			/* Check for raw socket or OOTB handling */
			ip_fanout_sctp_raw(mp, ipha, NULL, ports, ira);
			return;
		}

		/* Found a client; up it goes */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		sctp_input(connp, ipha, NULL, mp, ira);
		/* sctp_input does a rele of the sctp_t */
		return;
	}

	case IPPROTO_UDP:
		/* First mblk contains IP+UDP headers as checked above */
		ASSERT(MBLKL(mp) >= ip_hdr_length + UDPH_SIZE);

		if (iraflags & IRAF_MULTIBROADCAST) {
			uint16_t *up;	/* Pointer to ports in ULP header */

			up = (uint16_t *)((uchar_t *)ipha + ip_hdr_length);
			ip_fanout_udp_multi_v4(mp, ipha, up[1], up[0], ira);
			return;
		}

		/* Look for AF_INET or AF_INET6 that matches */
		connp = ipcl_classify_v4(mp, IPPROTO_UDP, ip_hdr_length,
		    ira, ipst);
		if (connp == NULL) {
	no_udp_match:
			if (ipst->ips_ipcl_proto_fanout_v4[IPPROTO_UDP].
			    connf_head != NULL) {
				ASSERT(ira->ira_protocol == IPPROTO_UDP);
				ip_fanout_proto_v4(mp, ipha, ira);
			} else {
				ip_fanout_send_icmp_v4(mp,
				    ICMP_DEST_UNREACHABLE,
				    ICMP_PORT_UNREACHABLE, ira);
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
		if (CONN_INBOUND_POLICY_PRESENT(connp, ipss) ||
		    (iraflags & IRAF_IPSEC_SECURE)) {
			mp = ipsec_check_inbound_policy(mp, connp,
			    ipha, NULL, ira);
			if (mp == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				/* Note that mp is NULL */
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				CONN_DEC_REF(connp);
				return;
			}
		}
		/*
		 * Remove 0-spi if it's 0, or move everything behind
		 * the UDP header over it and forward to ESP via
		 * ip_fanout_v4().
		 */
		if (connp->conn_udp->udp_nat_t_endpoint) {
			if (iraflags & IRAF_IPSEC_SECURE) {
				ip_drop_packet(mp, B_TRUE, ira->ira_ill,
				    DROPPER(ipss, ipds_esp_nat_t_ipsec),
				    &ipss->ipsec_dropper);
				CONN_DEC_REF(connp);
				return;
			}

			mp = zero_spi_check(mp, ira);
			if (mp == NULL) {
				/*
				 * Packet was consumed - probably sent to
				 * ip_fanout_v4.
				 */
				CONN_DEC_REF(connp);
				return;
			}
			/* Else continue like a normal UDP packet. */
			ipha = (ipha_t *)mp->b_rptr;
			protocol = ipha->ipha_protocol;
			ira->ira_protocol = protocol;
		}
		/* Found a client; up it goes */
		IP_STAT(ipst, ip_udp_fannorm);
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
	case IPPROTO_ICMP:
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
			    ipha, NULL, ira, ns);
			if (mp == NULL)
				return;
		}

		/*
		 * On a labeled system, we have to check whether the zone
		 * itself is permitted to receive raw traffic.
		 */
		if (ira->ira_flags & IRAF_SYSTEM_LABELED) {
			if (!tsol_can_accept_raw(mp, ira, B_FALSE)) {
				BUMP_MIB(&ipst->ips_icmp_mib, icmpInErrors);
				ip_drop_input("tsol_can_accept_raw", mp, ill);
				freemsg(mp);
				return;
			}
		}

		/*
		 * ICMP header checksum, including checksum field,
		 * should be zero.
		 */
		if (IP_CSUM(mp, ip_hdr_length, 0)) {
			BUMP_MIB(&ipst->ips_icmp_mib, icmpInCksumErrs);
			ip_drop_input("icmpInCksumErrs", mp, ill);
			freemsg(mp);
			return;
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		mp = icmp_inbound_v4(mp, ira);
		if (mp == NULL) {
			/* No need to pass to RAW sockets */
			return;
		}
		break;

	case IPPROTO_IGMP:
		/*
		 * If we are not willing to accept IGMP packets in clear,
		 * then check with global policy.
		 */
		if (ipst->ips_igmp_accept_clear_messages == 0) {
			mp = ipsec_check_global_policy(mp, NULL,
			    ipha, NULL, ira, ns);
			if (mp == NULL)
				return;
		}
		if ((ira->ira_flags & IRAF_SYSTEM_LABELED) &&
		    !tsol_can_accept_raw(mp, ira, B_TRUE)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return;
		}
		/*
		 * Validate checksum
		 */
		if (IP_CSUM(mp, ip_hdr_length, 0)) {
			++ipst->ips_igmpstat.igps_rcv_badsum;
			ip_drop_input("igps_rcv_badsum", mp, ill);
			freemsg(mp);
			return;
		}

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
		mp = igmp_input(mp, ira);
		if (mp == NULL) {
			/* Bad packet - discarded by igmp_input */
			return;
		}
		break;
	case IPPROTO_PIM:
		/*
		 * If we are not willing to accept PIM packets in clear,
		 * then check with global policy.
		 */
		if (ipst->ips_pim_accept_clear_messages == 0) {
			mp = ipsec_check_global_policy(mp, NULL,
			    ipha, NULL, ira, ns);
			if (mp == NULL)
				return;
		}
		if ((ira->ira_flags & IRAF_SYSTEM_LABELED) &&
		    !tsol_can_accept_raw(mp, ira, B_TRUE)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return;
		}
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);

		/* Checksum is verified in pim_input */
		mp = pim_input(mp, ira);
		if (mp == NULL) {
			/* Bad packet - discarded by pim_input */
			return;
		}
		break;
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
			boolean_t esp_in_udp_sa;
			boolean_t esp_in_udp_packet;

			mp = ipsec_inbound_esp_sa(mp, ira, &esph);
			if (mp == NULL)
				return;

			ASSERT(esph != NULL);
			ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
			ASSERT(ira->ira_ipsec_esp_sa != NULL);
			ASSERT(ira->ira_ipsec_esp_sa->ipsa_input_func != NULL);

			esp_in_udp_sa = ((ira->ira_ipsec_esp_sa->ipsa_flags &
			    IPSA_F_NATT) != 0);
			esp_in_udp_packet =
			    (ira->ira_flags & IRAF_ESP_UDP_PORTS) != 0;

			/*
			 * The following is a fancy, but quick, way of saying:
			 * ESP-in-UDP SA and Raw ESP packet --> drop
			 *    OR
			 * ESP SA and ESP-in-UDP packet --> drop
			 */
			if (esp_in_udp_sa != esp_in_udp_packet) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_packet(mp, B_TRUE, ira->ira_ill,
				    DROPPER(ipss, ipds_esp_no_sa),
				    &ipss->ipsec_dropper);
				return;
			}
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
	case IPPROTO_ENCAP: {
		ipha_t		*inner_ipha;

		/*
		 * Handle self-encapsulated packets (IP-in-IP where
		 * the inner addresses == the outer addresses).
		 */
		if ((uchar_t *)ipha + ip_hdr_length + sizeof (ipha_t) >
		    mp->b_wptr) {
			if (ira->ira_pktlen <
			    ip_hdr_length + sizeof (ipha_t)) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInTruncatedPkts);
				ip_drop_input("ipIfStatsInTruncatedPkts",
				    mp, ill);
				freemsg(mp);
				return;
			}
			ipha = ip_pullup(mp, (uchar_t *)ipha + ip_hdr_length +
			    sizeof (ipha_t) - mp->b_rptr, ira);
			if (ipha == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				freemsg(mp);
				return;
			}
		}
		inner_ipha = (ipha_t *)((uchar_t *)ipha + ip_hdr_length);
		/*
		 * Check the sanity of the inner IP header.
		 */
		if ((IPH_HDR_VERSION(inner_ipha) != IPV4_VERSION)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return;
		}
		if (IPH_HDR_LENGTH(inner_ipha) < sizeof (ipha_t)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return;
		}
		if (inner_ipha->ipha_src != ipha->ipha_src ||
		    inner_ipha->ipha_dst != ipha->ipha_dst) {
			/* We fallthru to iptun fanout below */
			goto iptun;
		}

		/*
		 * Self-encapsulated tunnel packet. Remove
		 * the outer IP header and fanout again.
		 * We also need to make sure that the inner
		 * header is pulled up until options.
		 */
		mp->b_rptr = (uchar_t *)inner_ipha;
		ipha = inner_ipha;
		ip_hdr_length = IPH_HDR_LENGTH(ipha);
		if ((uchar_t *)ipha + ip_hdr_length > mp->b_wptr) {
			if (ira->ira_pktlen <
			    (uchar_t *)ipha + ip_hdr_length - mp->b_rptr) {
				BUMP_MIB(ill->ill_ip_mib,
				    ipIfStatsInTruncatedPkts);
				ip_drop_input("ipIfStatsInTruncatedPkts",
				    mp, ill);
				freemsg(mp);
				return;
			}
			ipha = ip_pullup(mp,
			    (uchar_t *)ipha + ip_hdr_length - mp->b_rptr, ira);
			if (ipha == NULL) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
				ip_drop_input("ipIfStatsInDiscards", mp, ill);
				freemsg(mp);
				return;
			}
		}
		if (ip_hdr_length > sizeof (ipha_t)) {
			/* We got options on the inner packet. */
			ipaddr_t	dst = ipha->ipha_dst;
			int		error = 0;

			dst = ip_input_options(ipha, dst, mp, ira, &error);
			if (error != 0) {
				/*
				 * An ICMP error has been sent and the packet
				 * has been dropped.
				 */
				return;
			}
			if (dst != ipha->ipha_dst) {
				/*
				 * Someone put a source-route in
				 * the inside header of a self-
				 * encapsulated packet.  Drop it
				 * with extreme prejudice and let
				 * the sender know.
				 */
				ip_drop_input("ICMP_SOURCE_ROUTE_FAILED",
				    mp, ill);
				icmp_unreachable(mp, ICMP_SOURCE_ROUTE_FAILED,
				    ira);
				return;
			}
		}
		if (!(ira->ira_flags & IRAF_IPSEC_SECURE)) {
			/*
			 * This means that somebody is sending
			 * Self-encapsualted packets without AH/ESP.
			 *
			 * Send this packet to find a tunnel endpoint.
			 * if I can't find one, an ICMP
			 * PROTOCOL_UNREACHABLE will get sent.
			 */
			protocol = ipha->ipha_protocol;
			ira->ira_protocol = protocol;
			goto iptun;
		}

		/* Update based on removed IP header */
		ira->ira_ip_hdr_length = ip_hdr_length;
		ira->ira_pktlen = ntohs(ipha->ipha_length);

		if (ira->ira_flags & IRAF_IPSEC_DECAPS) {
			/*
			 * This packet is self-encapsulated multiple
			 * times. We don't want to recurse infinitely.
			 * To keep it simple, drop the packet.
			 */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
			return;
		}
		ASSERT(ira->ira_flags & IRAF_IPSEC_SECURE);
		ira->ira_flags |= IRAF_IPSEC_DECAPS;

		ip_input_post_ipsec(mp, ira);
		return;
	}

	iptun:	/* IPPROTO_ENCAPS that is not self-encapsulated */
	case IPPROTO_IPV6:
		/* iptun will verify trusted label */
		connp = ipcl_classify_v4(mp, protocol, ip_hdr_length,
		    ira, ipst);
		if (connp != NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInDelivers);
			ira->ira_ill = ira->ira_rill = NULL;
			(connp->conn_recv)(connp, mp, NULL, ira);
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
	 * So ipha need to be reinitialized.
	 */
	ipha = (ipha_t *)mp->b_rptr;
	ira->ira_protocol = protocol = ipha->ipha_protocol;
	if (ipst->ips_ipcl_proto_fanout_v4[protocol].connf_head == NULL) {
		/*
		 * No user-level listener for these packets packets.
		 * Check for IPPROTO_ENCAP...
		 */
		if (protocol == IPPROTO_ENCAP && ipst->ips_ip_g_mrouter) {
			/*
			 * Check policy here,
			 * THEN ship off to ip_mroute_decap().
			 *
			 * BTW,  If I match a configured IP-in-IP
			 * tunnel above, this path will not be reached, and
			 * ip_mroute_decap will never be called.
			 */
			mp = ipsec_check_global_policy(mp, connp,
			    ipha, NULL, ira, ns);
			if (mp != NULL) {
				ip_mroute_decap(mp, ira);
			} /* Else we already freed everything! */
		} else {
			ip_proto_not_sup(mp, ira);
		}
		return;
	}

	/*
	 * Handle fanout to raw sockets.  There
	 * can be more than one stream bound to a particular
	 * protocol.  When this is the case, each one gets a copy
	 * of any incoming packets.
	 */
	ASSERT(ira->ira_protocol == ipha->ipha_protocol);
	ip_fanout_proto_v4(mp, ipha, ira);
	return;

discard:
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
	ip_drop_input("ipIfStatsInDiscards", mp, ill);
	freemsg(mp);
#undef rptr
}
