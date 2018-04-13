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

#include <sys/clock_impl.h>	/* For LBOLT_FASTPATH{,64} */

#ifdef	DEBUG
extern boolean_t skip_sctp_cksum;
#endif

static int	ip_verify_nce(mblk_t *, ip_xmit_attr_t *);
static int	ip_verify_dce(mblk_t *, ip_xmit_attr_t *);
static boolean_t ip_verify_lso(ill_t *, ip_xmit_attr_t *);
static boolean_t ip_verify_zcopy(ill_t *, ip_xmit_attr_t *);
static void	ip_output_simple_broadcast(ip_xmit_attr_t *, mblk_t *);

/*
 * There are two types of output functions for IP used for different
 * purposes:
 *  - ip_output_simple() is when sending ICMP errors, TCP resets, etc when there
 *     is no context in the form of a conn_t. However, there is a
 *     ip_xmit_attr_t that the callers use to influence interface selection
 *     (needed for ICMP echo as well as IPv6 link-locals) and IPsec.
 *
 *  - conn_ip_output() is used when sending packets with a conn_t and
 *    ip_set_destination has been called to cache information. In that case
 *    various socket options are recorded in the ip_xmit_attr_t and should
 *    be taken into account.
 */

/*
 * The caller *must* have called conn_connect() or ip_attr_connect()
 * before calling conn_ip_output(). The caller needs to redo that each time
 * the destination IP address or port changes, as well as each time there is
 * a change to any socket option that would modify how packets are routed out
 * of the box (e.g., SO_DONTROUTE, IP_NEXTHOP, IP_BOUND_IF).
 *
 * The ULP caller has to serialize the use of a single ip_xmit_attr_t.
 * We assert for that here.
 */
int
conn_ip_output(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	iaflags_t	ixaflags = ixa->ixa_flags;
	ire_t		*ire;
	nce_t		*nce;
	dce_t		*dce;
	ill_t		*ill;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	int		error;

	/* We defer ipIfStatsHCOutRequests until an error or we have an ill */

	ASSERT(ixa->ixa_ire != NULL);
	/* Note there is no ixa_nce when reject and blackhole routes */
	ASSERT(ixa->ixa_dce != NULL);	/* Could be default dce */

#ifdef DEBUG
	ASSERT(ixa->ixa_curthread == NULL);
	ixa->ixa_curthread = curthread;
#endif

	/*
	 * Even on labeled systems we can have a NULL ixa_tsl e.g.,
	 * for IGMP/MLD traffic.
	 */

	ire = ixa->ixa_ire;

	/*
	 * If the ULP says the (old) IRE resulted in reachability we
	 * record this before determine whether to use a new IRE.
	 * No locking for performance reasons.
	 */
	if (ixaflags & IXAF_REACH_CONF)
		ire->ire_badcnt = 0;

	/*
	 * Has routing changed since we cached the results of the lookup?
	 *
	 * This check captures all of:
	 *  - the cached ire being deleted (by means of the special
	 *    IRE_GENERATION_CONDEMNED)
	 *  - A potentially better ire being added (ire_generation being
	 *    increased)
	 *  - A deletion of the nexthop ire that was used when we did the
	 *    lookup.
	 *  - An addition of a potentially better nexthop ire.
	 * The last two are handled by walking and increasing the generation
	 * number on all dependant IREs in ire_flush_cache().
	 *
	 * The check also handles all cases of RTF_REJECT and RTF_BLACKHOLE
	 * since we ensure that each time we set ixa_ire to such an IRE we
	 * make sure the ixa_ire_generation does not match (by using
	 * IRE_GENERATION_VERIFY).
	 */
	if (ire->ire_generation != ixa->ixa_ire_generation) {
		error = ip_verify_ire(mp, ixa);
		if (error != 0) {
			ip_drop_output("ipIfStatsOutDiscards - verify ire",
			    mp, NULL);
			goto drop;
		}
		ire = ixa->ixa_ire;
		ASSERT(ire != NULL);
		if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
#ifdef DEBUG
			ASSERT(ixa->ixa_curthread == curthread);
			ixa->ixa_curthread = NULL;
#endif
			ire->ire_ob_pkt_count++;
			/* ixa_dce might be condemned; use default one */
			return ((ire->ire_sendfn)(ire, mp, mp->b_rptr, ixa,
			    &ipst->ips_dce_default->dce_ident));
		}
		/*
		 * If the ncec changed then ip_verify_ire already set
		 * ixa->ixa_dce_generation = DCE_GENERATION_VERIFY;
		 * so we can recheck the interface mtu.
		 */

		/*
		 * Note that ire->ire_generation could already have changed.
		 * We catch that next time we send a packet.
		 */
	}

	/*
	 * No need to lock access to ixa_nce since the ip_xmit_attr usage
	 * is single threaded.
	 */
	ASSERT(ixa->ixa_nce != NULL);
	nce = ixa->ixa_nce;
	if (nce->nce_is_condemned) {
		error = ip_verify_nce(mp, ixa);
		/*
		 * In case ZEROCOPY capability become not available, we
		 * copy the message and free the original one. We might
		 * be copying more data than needed but it doesn't hurt
		 * since such change rarely happens.
		 */
		switch (error) {
		case 0:
			break;
		case ENOTSUP: { /* ZEROCOPY */
			mblk_t *nmp;

			if ((nmp = copymsg(mp)) != NULL) {
				freemsg(mp);
				mp = nmp;

				break;
			}
		}
		/* FALLTHROUGH */
		default:
			ip_drop_output("ipIfStatsOutDiscards - verify nce",
			    mp, NULL);
			goto drop;
		}
		ire = ixa->ixa_ire;
		ASSERT(ire != NULL);
		if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
#ifdef DEBUG
			ASSERT(ixa->ixa_curthread == curthread);
			ixa->ixa_curthread = NULL;
#endif
			ire->ire_ob_pkt_count++;
			/* ixa_dce might be condemned; use default one */
			return ((ire->ire_sendfn)(ire, mp, mp->b_rptr,
			    ixa, &ipst->ips_dce_default->dce_ident));
		}
		ASSERT(ixa->ixa_nce != NULL);
		nce = ixa->ixa_nce;

		/*
		 * Note that some other event could already have made
		 * the new nce condemned. We catch that next time we
		 * try to send a packet.
		 */
	}
	/*
	 * If there is no per-destination dce_t then we have a reference to
	 * the default dce_t (which merely contains the dce_ipid).
	 * The generation check captures both the introduction of a
	 * per-destination dce_t (e.g., due to ICMP packet too big) and
	 * any change to the per-destination dce (including it becoming
	 * condemned by use of the special DCE_GENERATION_CONDEMNED).
	 */
	dce = ixa->ixa_dce;

	/*
	 * To avoid a periodic timer to increase the path MTU we
	 * look at dce_last_change_time each time we send a packet.
	 */
	if (dce->dce_flags & DCEF_PMTU) {
		int64_t		now = LBOLT_FASTPATH64;

		if ((TICK_TO_SEC(now) - dce->dce_last_change_time >
		    ipst->ips_ip_pathmtu_interval)) {
			/*
			 * Older than 20 minutes. Drop the path MTU information.
			 * Since the path MTU changes as a result of this,
			 * twiddle ixa_dce_generation to make us go through the
			 * dce verification code in conn_ip_output.
			 */
			mutex_enter(&dce->dce_lock);
			dce->dce_flags &= ~(DCEF_PMTU|DCEF_TOO_SMALL_PMTU);
			dce->dce_last_change_time = TICK_TO_SEC(now);
			mutex_exit(&dce->dce_lock);
			dce_increment_generation(dce);
		}
	}

	if (dce->dce_generation != ixa->ixa_dce_generation) {
		error = ip_verify_dce(mp, ixa);
		if (error != 0) {
			ip_drop_output("ipIfStatsOutDiscards - verify dce",
			    mp, NULL);
			goto drop;
		}
		dce = ixa->ixa_dce;

		/*
		 * Note that some other event could already have made the
		 * new dce's generation number change.
		 * We catch that next time we try to send a packet.
		 */
	}

	ill = nce->nce_ill;

	/*
	 * An initial ixa_fragsize was set in ip_set_destination
	 * and we update it if any routing changes above.
	 * A change to ill_mtu with ifconfig will increase all dce_generation
	 * so that we will detect that with the generation check. Ditto for
	 * ill_mc_mtu.
	 */

	/*
	 * Caller needs to make sure IXAF_VERIFY_SRC is not set if
	 * conn_unspec_src.
	 */
	if ((ixaflags & IXAF_VERIFY_SOURCE) &&
	    ixa->ixa_src_generation != ipst->ips_src_generation) {
		/* Check if the IP source is still assigned to the host. */
		uint_t gen;

		if (!ip_verify_src(mp, ixa, &gen)) {
			/* Don't send a packet with a source that isn't ours */
			error = EADDRNOTAVAIL;
			ip_drop_output("ipIfStatsOutDiscards - invalid src",
			    mp, NULL);
			goto drop;
		}
		/* The source is still valid - update the generation number */
		ixa->ixa_src_generation = gen;
	}

	/*
	 * We don't have an IRE when we fragment, hence ire_ob_pkt_count
	 * can only count the use prior to fragmentation. However the MIB
	 * counters on the ill will be incremented in post fragmentation.
	 */
	ire->ire_ob_pkt_count++;
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutRequests);

	/*
	 * Based on ire_type and ire_flags call one of:
	 *	ire_send_local_v* - for IRE_LOCAL and IRE_LOOPBACK
	 *	ire_send_multirt_v* - if RTF_MULTIRT
	 *	ire_send_noroute_v* - if RTF_REJECT or RTF_BLACHOLE
	 *	ire_send_multicast_v* - for IRE_MULTICAST
	 *	ire_send_broadcast_v4 - for IRE_BROADCAST
	 *	ire_send_wire_v* - for the rest.
	 */
#ifdef DEBUG
	ASSERT(ixa->ixa_curthread == curthread);
	ixa->ixa_curthread = NULL;
#endif
	return ((ire->ire_sendfn)(ire, mp, mp->b_rptr, ixa, &dce->dce_ident));

drop:
	if (ixaflags & IXAF_IS_IPV4) {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsHCOutRequests);
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
	} else {
		BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsHCOutRequests);
		BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutDiscards);
	}
	freemsg(mp);
#ifdef DEBUG
	ASSERT(ixa->ixa_curthread == curthread);
	ixa->ixa_curthread = NULL;
#endif
	return (error);
}

/*
 * Handle both IPv4 and IPv6. Sets the generation number
 * to allow the caller to know when to call us again.
 * Returns true if the source address in the packet is a valid source.
 * We handle callers which try to send with a zero address (since we only
 * get here if UNSPEC_SRC is not set).
 */
boolean_t
ip_verify_src(mblk_t *mp, ip_xmit_attr_t *ixa, uint_t *generationp)
{
	ip_stack_t	*ipst = ixa->ixa_ipst;

	/*
	 * Need to grab the generation number before we check to
	 * avoid a race with a change to the set of local addresses.
	 * No lock needed since the thread which updates the set of local
	 * addresses use ipif/ill locks and exit those (hence a store memory
	 * barrier) before doing the atomic increase of ips_src_generation.
	 */
	if (generationp != NULL)
		*generationp = ipst->ips_src_generation;

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t	*ipha = (ipha_t *)mp->b_rptr;

		if (ipha->ipha_src == INADDR_ANY)
			return (B_FALSE);

		return (ip_laddr_verify_v4(ipha->ipha_src, ixa->ixa_zoneid,
		    ipst, B_FALSE) != IPVL_BAD);
	} else {
		ip6_t	*ip6h = (ip6_t *)mp->b_rptr;
		uint_t	scopeid;

		if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src))
			return (B_FALSE);

		if (ixa->ixa_flags & IXAF_SCOPEID_SET)
			scopeid = ixa->ixa_scopeid;
		else
			scopeid = 0;

		return (ip_laddr_verify_v6(&ip6h->ip6_src, ixa->ixa_zoneid,
		    ipst, B_FALSE, scopeid) != IPVL_BAD);
	}
}

/*
 * Handle both IPv4 and IPv6. Reverify/recalculate the IRE to use.
 */
int
ip_verify_ire(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	uint_t		gen;
	ire_t		*ire;
	nce_t		*nce;
	int		error;
	boolean_t	multirt = B_FALSE;

	/*
	 * Redo ip_select_route.
	 * Need to grab generation number as part of the lookup to
	 * avoid race.
	 */
	error = 0;
	ire = ip_select_route_pkt(mp, ixa, &gen, &error, &multirt);
	ASSERT(ire != NULL); /* IRE_NOROUTE if none found */
	if (error != 0) {
		ire_refrele(ire);
		return (error);
	}

	if (ixa->ixa_ire != NULL)
		ire_refrele_notr(ixa->ixa_ire);
#ifdef DEBUG
	ire_refhold_notr(ire);
	ire_refrele(ire);
#endif
	ixa->ixa_ire = ire;
	ixa->ixa_ire_generation = gen;
	if (multirt) {
		if (ixa->ixa_flags & IXAF_IS_IPV4)
			ixa->ixa_postfragfn = ip_postfrag_multirt_v4;
		else
			ixa->ixa_postfragfn = ip_postfrag_multirt_v6;
		ixa->ixa_flags |= IXAF_MULTIRT_MULTICAST;
	} else {
		ixa->ixa_postfragfn = ire->ire_postfragfn;
		ixa->ixa_flags &= ~IXAF_MULTIRT_MULTICAST;
	}

	/*
	 * Don't look for an nce for reject or blackhole.
	 * They have ire_generation set to IRE_GENERATION_VERIFY which
	 * makes conn_ip_output avoid references to ixa_nce.
	 */
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		ASSERT(ixa->ixa_ire_generation == IRE_GENERATION_VERIFY);
		ixa->ixa_dce_generation = DCE_GENERATION_VERIFY;
		return (0);
	}

	/* The NCE could now be different */
	nce = ire_to_nce_pkt(ire, mp);
	if (nce == NULL) {
		/*
		 * Allocation failure. Make sure we redo ire/nce selection
		 * next time we send.
		 */
		ixa->ixa_ire_generation = IRE_GENERATION_VERIFY;
		ixa->ixa_dce_generation = DCE_GENERATION_VERIFY;
		return (ENOBUFS);
	}
	if (nce == ixa->ixa_nce) {
		/* No change */
		nce_refrele(nce);
		return (0);
	}

	/*
	 * Since the path MTU might change as a result of this
	 * route change, we twiddle ixa_dce_generation to
	 * make conn_ip_output go through the ip_verify_dce code.
	 */
	ixa->ixa_dce_generation = DCE_GENERATION_VERIFY;

	if (ixa->ixa_nce != NULL)
		nce_refrele(ixa->ixa_nce);
	ixa->ixa_nce = nce;
	return (0);
}

/*
 * Handle both IPv4 and IPv6. Reverify/recalculate the NCE to use.
 */
static int
ip_verify_nce(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	ire_t		*ire = ixa->ixa_ire;
	nce_t		*nce;
	int		error = 0;
	ipha_t		*ipha = NULL;
	ip6_t		*ip6h = NULL;

	if (ire->ire_ipversion == IPV4_VERSION)
		ipha = (ipha_t *)mp->b_rptr;
	else
		ip6h = (ip6_t *)mp->b_rptr;

	nce = ire_handle_condemned_nce(ixa->ixa_nce, ire, ipha, ip6h, B_TRUE);
	if (nce == NULL) {
		/* Try to find a better ire */
		return (ip_verify_ire(mp, ixa));
	}

	/*
	 * The hardware offloading capabilities, for example LSO, of the
	 * interface might have changed, so do sanity verification here.
	 */
	if (ixa->ixa_flags & IXAF_VERIFY_LSO) {
		if (!ip_verify_lso(nce->nce_ill, ixa)) {
			ASSERT(ixa->ixa_notify != NULL);
			ixa->ixa_notify(ixa->ixa_notify_cookie, ixa,
			    IXAN_LSO, 0);
			error = ENOTSUP;
		}
	}

	/*
	 * Verify ZEROCOPY capability of underlying ill. Notify the ULP with
	 * any ZEROCOPY changes. In case ZEROCOPY capability is not available
	 * any more, return error so that conn_ip_output() can take care of
	 * the ZEROCOPY message properly. It's safe to continue send the
	 * message when ZEROCOPY newly become available.
	 */
	if (ixa->ixa_flags & IXAF_VERIFY_ZCOPY) {
		if (!ip_verify_zcopy(nce->nce_ill, ixa)) {
			ASSERT(ixa->ixa_notify != NULL);
			ixa->ixa_notify(ixa->ixa_notify_cookie, ixa,
			    IXAN_ZCOPY, 0);
			if ((ixa->ixa_flags & IXAF_ZCOPY_CAPAB) == 0)
				error = ENOTSUP;
		}
	}

	/*
	 * Since the path MTU might change as a result of this
	 * change, we twiddle ixa_dce_generation to
	 * make conn_ip_output go through the ip_verify_dce code.
	 */
	ixa->ixa_dce_generation = DCE_GENERATION_VERIFY;

	nce_refrele(ixa->ixa_nce);
	ixa->ixa_nce = nce;
	return (error);
}

/*
 * Handle both IPv4 and IPv6. Reverify/recalculate the DCE to use.
 */
static int
ip_verify_dce(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	dce_t		*dce;
	uint_t		gen;
	uint_t		pmtu;

	dce = dce_lookup_pkt(mp, ixa, &gen);
	ASSERT(dce != NULL);

	dce_refrele_notr(ixa->ixa_dce);
#ifdef DEBUG
	dce_refhold_notr(dce);
	dce_refrele(dce);
#endif
	ixa->ixa_dce = dce;
	ixa->ixa_dce_generation = gen;

	/* Extract the (path) mtu from the dce, ncec_ill etc */
	pmtu = ip_get_pmtu(ixa);

	/*
	 * Tell ULP about PMTU changes - increase or decrease - by returning
	 * an error if IXAF_VERIFY_PMTU is set. In such case, ULP should update
	 * both ixa_pmtu and ixa_fragsize appropriately.
	 *
	 * If ULP doesn't set that flag then we need to update ixa_fragsize
	 * since routing could have changed the ill after after ixa_fragsize
	 * was set previously in the conn_ip_output path or in
	 * ip_set_destination.
	 *
	 * In case of LSO, ixa_fragsize might be greater than ixa_pmtu.
	 *
	 * In the case of a path MTU increase we send the packet after the
	 * notify to the ULP.
	 */
	if (ixa->ixa_flags & IXAF_VERIFY_PMTU) {
		if (ixa->ixa_pmtu != pmtu) {
			uint_t oldmtu = ixa->ixa_pmtu;

			DTRACE_PROBE2(verify_pmtu, uint32_t, pmtu,
			    uint32_t, ixa->ixa_pmtu);
			ASSERT(ixa->ixa_notify != NULL);
			ixa->ixa_notify(ixa->ixa_notify_cookie, ixa,
			    IXAN_PMTU, pmtu);
			if (pmtu < oldmtu)
				return (EMSGSIZE);
		}
	} else {
		ixa->ixa_fragsize = pmtu;
	}
	return (0);
}

/*
 * Verify LSO usability. Keep the return value simple to indicate whether
 * the LSO capability has changed. Handle both IPv4 and IPv6.
 */
static boolean_t
ip_verify_lso(ill_t *ill, ip_xmit_attr_t *ixa)
{
	ill_lso_capab_t	*lsoc = &ixa->ixa_lso_capab;
	ill_lso_capab_t	*new_lsoc = ill->ill_lso_capab;

	if (ixa->ixa_flags & IXAF_LSO_CAPAB) {
		/*
		 * Not unsable any more.
		 */
		if ((ixa->ixa_flags & IXAF_IPSEC_SECURE) ||
		    (ixa->ixa_ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK)) ||
		    (ixa->ixa_ire->ire_flags & RTF_MULTIRT) ||
		    ((ixa->ixa_flags & IXAF_IS_IPV4) ?
		    !ILL_LSO_TCP_IPV4_USABLE(ill) :
		    !ILL_LSO_TCP_IPV6_USABLE(ill))) {
			ixa->ixa_flags &= ~IXAF_LSO_CAPAB;

			return (B_FALSE);
		}

		/*
		 * Capability has changed, refresh the copy in ixa.
		 */
		if (lsoc->ill_lso_max != new_lsoc->ill_lso_max) {
			*lsoc = *new_lsoc;

			return (B_FALSE);
		}
	} else { /* Was not usable */
		if (!(ixa->ixa_flags & IXAF_IPSEC_SECURE) &&
		    !(ixa->ixa_ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK)) &&
		    !(ixa->ixa_ire->ire_flags & RTF_MULTIRT) &&
		    ((ixa->ixa_flags & IXAF_IS_IPV4) ?
		    ILL_LSO_TCP_IPV4_USABLE(ill) :
		    ILL_LSO_TCP_IPV6_USABLE(ill))) {
			*lsoc = *new_lsoc;
			ixa->ixa_flags |= IXAF_LSO_CAPAB;

			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * Verify ZEROCOPY usability. Keep the return value simple to indicate whether
 * the ZEROCOPY capability has changed. Handle both IPv4 and IPv6.
 */
static boolean_t
ip_verify_zcopy(ill_t *ill, ip_xmit_attr_t *ixa)
{
	if (ixa->ixa_flags & IXAF_ZCOPY_CAPAB) {
		/*
		 * Not unsable any more.
		 */
		if ((ixa->ixa_flags & IXAF_IPSEC_SECURE) ||
		    (ixa->ixa_ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK)) ||
		    (ixa->ixa_ire->ire_flags & RTF_MULTIRT) ||
		    !ILL_ZCOPY_USABLE(ill)) {
			ixa->ixa_flags &= ~IXAF_ZCOPY_CAPAB;

			return (B_FALSE);
		}
	} else { /* Was not usable */
		if (!(ixa->ixa_flags & IXAF_IPSEC_SECURE) &&
		    !(ixa->ixa_ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK)) &&
		    !(ixa->ixa_ire->ire_flags & RTF_MULTIRT) &&
		    ILL_ZCOPY_USABLE(ill)) {
			ixa->ixa_flags |= IXAF_ZCOPY_CAPAB;

			return (B_FALSE);
		}
	}

	return (B_TRUE);
}


/*
 * When there is no conn_t context, this will send a packet.
 * The caller must *not* have called conn_connect() or ip_attr_connect()
 * before calling ip_output_simple().
 * Handles IPv4 and IPv6. Returns zero or an errno such as ENETUNREACH.
 * Honors IXAF_SET_SOURCE.
 *
 * We acquire the ire and after calling ire_sendfn we release
 * the hold on the ire. Ditto for the nce and dce.
 *
 * This assumes that the caller has set the following in ip_xmit_attr_t:
 *	ixa_tsl, ixa_zoneid, and ixa_ipst must always be set.
 *	If ixa_ifindex is non-zero it means send out that ill. (If it is
 *	an upper IPMP ill we load balance across the group; if a lower we send
 *	on that lower ill without load balancing.)
 *	IXAF_IS_IPV4 must be set correctly.
 *	If IXAF_IPSEC_SECURE is set then the ixa_ipsec_* fields must be set.
 *	If IXAF_NO_IPSEC is set we'd skip IPsec policy lookup.
 *	If neither of those two are set we do an IPsec policy lookup.
 *
 * We handle setting things like
 *	ixa_pktlen
 *	ixa_ip_hdr_length
 *	ixa->ixa_protocol
 *
 * The caller may set ixa_xmit_hint, which is used for ECMP selection and
 * transmit ring selecting in GLD.
 *
 * The caller must do an ixa_cleanup() to release any IPsec references
 * after we return.
 */
int
ip_output_simple(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	ts_label_t	*effective_tsl = NULL;
	int		err;

	ASSERT(ixa->ixa_ipst != NULL);

	if (is_system_labeled()) {
		ip_stack_t *ipst = ixa->ixa_ipst;

		if (ixa->ixa_flags & IXAF_IS_IPV4) {
			err = tsol_check_label_v4(ixa->ixa_tsl, ixa->ixa_zoneid,
			    &mp, CONN_MAC_DEFAULT, B_FALSE, ixa->ixa_ipst,
			    &effective_tsl);
		} else {
			err = tsol_check_label_v6(ixa->ixa_tsl, ixa->ixa_zoneid,
			    &mp, CONN_MAC_DEFAULT, B_FALSE, ixa->ixa_ipst,
			    &effective_tsl);
		}
		if (err != 0) {
			ip2dbg(("tsol_check: label check failed (%d)\n", err));
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsHCOutRequests);
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("tsol_check_label", mp, NULL);
			freemsg(mp);
			return (err);
		}
		if (effective_tsl != NULL) {
			/* Update the label */
			ip_xmit_attr_replace_tsl(ixa, effective_tsl);
		}
	}

	if (ixa->ixa_flags & IXAF_IS_IPV4)
		return (ip_output_simple_v4(mp, ixa));
	else
		return (ip_output_simple_v6(mp, ixa));
}

int
ip_output_simple_v4(mblk_t *mp, ip_xmit_attr_t *ixa)
{
	ipha_t		*ipha;
	ipaddr_t	firsthop; /* In IP header */
	ipaddr_t	dst;	/* End of source route, or ipha_dst if none */
	ire_t		*ire;
	ipaddr_t	setsrc;	/* RTF_SETSRC */
	int		error;
	ill_t		*ill = NULL;
	dce_t		*dce = NULL;
	nce_t		*nce;
	iaflags_t	ixaflags = ixa->ixa_flags;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	boolean_t	repeat = B_FALSE;
	boolean_t	multirt = B_FALSE;
	int64_t		now;

	ipha = (ipha_t *)mp->b_rptr;
	ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);

	/*
	 * Even on labeled systems we can have a NULL ixa_tsl e.g.,
	 * for IGMP/MLD traffic.
	 */

	/* Caller already set flags */
	ASSERT(ixa->ixa_flags & IXAF_IS_IPV4);

	ASSERT(ixa->ixa_nce == NULL);

	ixa->ixa_pktlen = ntohs(ipha->ipha_length);
	ASSERT(ixa->ixa_pktlen == msgdsize(mp));
	ixa->ixa_ip_hdr_length = IPH_HDR_LENGTH(ipha);
	ixa->ixa_protocol = ipha->ipha_protocol;

	/*
	 * Assumes that source routed packets have already been massaged by
	 * the ULP (ip_massage_options) and as a result ipha_dst is the next
	 * hop in the source route. The final destination is used for IPsec
	 * policy and DCE lookup.
	 */
	firsthop = ipha->ipha_dst;
	dst = ip_get_dst(ipha);

repeat_ire:
	error = 0;
	setsrc = INADDR_ANY;
	ire = ip_select_route_v4(firsthop, ipha->ipha_src, ixa, NULL,
	    &setsrc, &error, &multirt);
	ASSERT(ire != NULL);	/* IRE_NOROUTE if none found */
	if (error != 0) {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsHCOutRequests);
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards - select route", mp, NULL);
		freemsg(mp);
		goto done;
	}

	if (ire->ire_flags & (RTF_BLACKHOLE|RTF_REJECT)) {
		/* ire_ill might be NULL hence need to skip some code */
		if (ixaflags & IXAF_SET_SOURCE)
			ipha->ipha_src = htonl(INADDR_LOOPBACK);
		ixa->ixa_fragsize = IP_MAXPACKET;
		ill = NULL;
		nce = NULL;
		ire->ire_ob_pkt_count++;
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsHCOutRequests);
		/* No dce yet; use default one */
		error = (ire->ire_sendfn)(ire, mp, ipha, ixa,
		    &ipst->ips_dce_default->dce_ident);
		goto done;
	}

	/* Note that ipha_dst is only used for IRE_MULTICAST */
	nce = ire_to_nce(ire, ipha->ipha_dst, NULL);
	if (nce == NULL) {
		/* Allocation failure? */
		ip_drop_output("ire_to_nce", mp, ill);
		freemsg(mp);
		error = ENOBUFS;
		goto done;
	}
	if (nce->nce_is_condemned) {
		nce_t *nce1;

		nce1 = ire_handle_condemned_nce(nce, ire, ipha, NULL, B_TRUE);
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
	 * ire_lookup_multi_ill_v4 since we don't have an IRE for each
	 * possible multicast address.
	 * We also need a flag for multicast since we can't check
	 * whether RTF_MULTIRT is set in ixa_ire for multicast.
	 */
	if (multirt) {
		ixa->ixa_postfragfn = ip_postfrag_multirt_v4;
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
	dce = dce_lookup_v4(dst, ipst, NULL);
	ASSERT(dce != NULL);

	if (!(ixaflags & IXAF_PMTU_DISCOVERY)) {
		ixa->ixa_fragsize = ip_get_base_mtu(nce->nce_ill, ire);
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
		ipaddr_t	src;

		/*
		 * We use the final destination to get
		 * correct selection for source routed packets
		 */

		/* If unreachable we have no ill but need some source */
		if (ill == NULL) {
			src = htonl(INADDR_LOOPBACK);
			error = 0;
		} else {
			error = ip_select_source_v4(ill, setsrc, dst,
			    ixa->ixa_multicast_ifaddr, ixa->ixa_zoneid, ipst,
			    &src, NULL, NULL);
		}
		if (error != 0) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutRequests);
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards - no source",
			    mp, ill);
			freemsg(mp);
			goto done;
		}
		ipha->ipha_src = src;
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
		mp = ip_output_attach_policy(mp, ipha, NULL, NULL, ixa);
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
	 *	ire_send_local_v4 - for IRE_LOCAL and IRE_LOOPBACK
	 *	ire_send_multirt_v4 - if RTF_MULTIRT
	 *	ire_send_noroute_v4 - if RTF_REJECT or RTF_BLACHOLE
	 *	ire_send_multicast_v4 - for IRE_MULTICAST
	 *	ire_send_broadcast_v4 - for IRE_BROADCAST
	 *	ire_send_wire_v4 - for the rest.
	 */
	error = (ire->ire_sendfn)(ire, mp, ipha, ixa, &dce->dce_ident);
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
 *  - IXAF_SET_SOURCE - replace IP source in broadcast case.
 *  - IXAF_LOOPBACK_COPY - for multicast and broadcast
 */


/*
 * ire_sendfn for IRE_LOCAL and IRE_LOOPBACK
 *
 * The checks for restrict_interzone_loopback are done in ire_route_recursive.
 */
/* ARGSUSED4 */
int
ire_send_local_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ill_t		*ill = ire->ire_ill;
	ip_recv_attr_t	iras;	/* NOTE: No bzero for performance */
	uint_t		pktlen = ixa->ixa_pktlen;

	/*
	 * No fragmentation, no nce, no application of IPsec,
	 * and no ipha_ident assignment.
	 *
	 * Note different order between IP provider and FW_HOOKS than in
	 * send_wire case.
	 */

	/*
	 * DTrace this as ip:::send.  A packet blocked by FW_HOOKS will fire the
	 * send probe, but not the receive probe.
	 */
	DTRACE_IP7(send, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
	    ipha, __dtrace_ipsr_ill_t *, ill, ipha_t *, ipha, ip6_t *, NULL,
	    int, 1);

	if (HOOKS4_INTERESTED_LOOPBACK_OUT(ipst)) {
		int error;

		DTRACE_PROBE4(ip4__loopback__out__start, ill_t *, NULL,
		    ill_t *, ill, ipha_t *, ipha, mblk_t *, mp);
		FW_HOOKS(ipst->ips_ip4_loopback_out_event,
		    ipst->ips_ipv4firewall_loopback_out,
		    NULL, ill, ipha, mp, mp, 0, ipst, error);
		DTRACE_PROBE1(ip4__loopback__out__end, mblk_t *, mp);
		if (mp == NULL)
			return (error);

		/*
		 * Even if the destination was changed by the filter we use the
		 * forwarding decision that was made based on the address
		 * in ip_output/ip_set_destination.
		 */
		/* Length could be different */
		ipha = (ipha_t *)mp->b_rptr;
		pktlen = ntohs(ipha->ipha_length);
	}

	/*
	 * If a callback is enabled then we need to know the
	 * source and destination zoneids for the packet. We already
	 * have those handy.
	 */
	if (ipst->ips_ip4_observe.he_interested) {
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

	/* Map ixa to ira including IPsec policies */
	ipsec_out_to_in(ixa, ill, &iras);
	iras.ira_pktlen = pktlen;

	if (!IS_SIMPLE_IPH(ipha)) {
		ip_output_local_options(ipha, ipst);
		iras.ira_flags |= IRAF_IPV4_OPTIONS;
	}

	if (HOOKS4_INTERESTED_LOOPBACK_IN(ipst)) {
		int error;

		DTRACE_PROBE4(ip4__loopback__in__start, ill_t *, ill,
		    ill_t *, NULL, ipha_t *, ipha, mblk_t *, mp);
		FW_HOOKS(ipst->ips_ip4_loopback_in_event,
		    ipst->ips_ipv4firewall_loopback_in,
		    ill, NULL, ipha, mp, mp, 0, ipst, error);

		DTRACE_PROBE1(ip4__loopback__in__end, mblk_t *, mp);
		if (mp == NULL) {
			ira_cleanup(&iras, B_FALSE);
			return (error);
		}
		/*
		 * Even if the destination was changed by the filter we use the
		 * forwarding decision that was made based on the address
		 * in ip_output/ip_set_destination.
		 */
		/* Length could be different */
		ipha = (ipha_t *)mp->b_rptr;
		pktlen = iras.ira_pktlen = ntohs(ipha->ipha_length);
	}

	DTRACE_IP7(receive, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
	    ipha, __dtrace_ipsr_ill_t *, ill, ipha_t *, ipha, ip6_t *, NULL,
	    int, 1);

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
		if (!tsol_get_pkt_label(mp, IPV4_VERSION, &iras)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("tsol_get_pkt_label", mp, ill);
			freemsg(mp);
			return (0);
		}
		ASSERT(iras.ira_tsl != NULL);

		/* tsol_get_pkt_label sometimes does pullupmsg */
		ipha = (ipha_t *)mp->b_rptr;
	}

	ip_fanout_v4(mp, ipha, &iras);

	/* We moved any IPsec refs from ixa to iras */
	ira_cleanup(&iras, B_FALSE);
	return (0);
}

/*
 * ire_sendfn for IRE_BROADCAST
 * If the broadcast address is present on multiple ills and ixa_ifindex
 * isn't set, then we generate
 * a separate datagram (potentially with different source address) for
 * those ills. In any case, only one copy is looped back to ip_input_v4.
 */
int
ire_send_broadcast_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	irb_t		*irb = ire->ire_bucket;
	ire_t		*ire1;
	mblk_t		*mp1;
	ipha_t		*ipha1;
	iaflags_t	ixaflags = ixa->ixa_flags;
	nce_t		*nce1, *nce_orig;

	/*
	 * Unless ire_send_multirt_v4 already set a ttl, force the
	 * ttl to a smallish value.
	 */
	if (!(ixa->ixa_flags & IXAF_NO_TTL_CHANGE)) {
		/*
		 * To avoid broadcast storms, we usually set the TTL to 1 for
		 * broadcasts.  This can
		 * be overridden stack-wide through the ip_broadcast_ttl
		 * ndd tunable, or on a per-connection basis through the
		 * IP_BROADCAST_TTL socket option.
		 *
		 * If SO_DONTROUTE/IXAF_DONTROUTE is set, then ire_send_wire_v4
		 * will force ttl to one after we've set this.
		 */
		if (ixaflags & IXAF_BROADCAST_TTL_SET)
			ipha->ipha_ttl = ixa->ixa_broadcast_ttl;
		else
			ipha->ipha_ttl = ipst->ips_ip_broadcast_ttl;
	}
	/*
	 * Make sure we get a loopback copy (after IPsec and frag)
	 * Skip hardware checksum so that loopback copy is checksumed.
	 */
	ixa->ixa_flags |= IXAF_LOOPBACK_COPY | IXAF_NO_HW_CKSUM;

	/* Do we need to potentially generate multiple copies? */
	if (irb->irb_ire_cnt == 1 || ixa->ixa_ifindex != 0)
		return (ire_send_wire_v4(ire, mp, ipha, ixa, identp));

	/*
	 * Loop over all IRE_BROADCAST in the bucket (might only be one).
	 * Note that everything in the bucket has the same destination address.
	 */
	irb_refhold(irb);
	for (ire1 = irb->irb_ire; ire1 != NULL; ire1 = ire1->ire_next) {
		/* We do the main IRE after the end of the loop */
		if (ire1 == ire)
			continue;

		/*
		 * Only IREs for the same IP address should be in the same
		 * bucket.
		 * But could have IRE_HOSTs in the case of CGTP.
		 * If we find any multirt routes we bail out of the loop
		 * and just do the single packet at the end; ip_postfrag_multirt
		 * will duplicate the packet.
		 */
		ASSERT(ire1->ire_addr == ire->ire_addr);
		if (!(ire1->ire_type & IRE_BROADCAST))
			continue;

		if (IRE_IS_CONDEMNED(ire1))
			continue;

		if (ixa->ixa_zoneid != ALL_ZONES &&
		    ire->ire_zoneid != ire1->ire_zoneid)
			continue;

		ASSERT(ire->ire_ill != ire1->ire_ill && ire1->ire_ill != NULL);

		if (ire1->ire_flags & RTF_MULTIRT)
			break;

		/*
		 * For IPMP we only send for the ipmp_ill. arp_nce_init() will
		 * ensure that this goes out on the cast_ill.
		 */
		if (IS_UNDER_IPMP(ire1->ire_ill))
			continue;

		mp1 = copymsg(mp);
		if (mp1 == NULL) {
			BUMP_MIB(ire1->ire_ill->ill_ip_mib,
			    ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards",
			    mp, ire1->ire_ill);
			continue;
		}

		ipha1 = (ipha_t *)mp1->b_rptr;
		if (ixa->ixa_flags & IXAF_SET_SOURCE) {
			/*
			 * Need to pick a different source address for each
			 * interface. If we have a global IPsec policy and
			 * no per-socket policy then we punt to
			 * ip_output_simple_v4 using a separate ip_xmit_attr_t.
			 */
			if (ixaflags & IXAF_IPSEC_GLOBAL_POLICY) {
				ip_output_simple_broadcast(ixa, mp1);
				continue;
			}
			/* Pick a new source address for each interface */
			if (ip_select_source_v4(ire1->ire_ill, INADDR_ANY,
			    ipha1->ipha_dst, INADDR_ANY, ixa->ixa_zoneid, ipst,
			    &ipha1->ipha_src, NULL, NULL) != 0) {
				BUMP_MIB(ire1->ire_ill->ill_ip_mib,
				    ipIfStatsOutDiscards);
				ip_drop_output("ipIfStatsOutDiscards - select "
				    "broadcast source", mp1, ire1->ire_ill);
				freemsg(mp1);
				continue;
			}
			/*
			 * Check against global IPsec policy to set the AH/ESP
			 * attributes. IPsec will set IXAF_IPSEC_* and
			 * ixa_ipsec_* as appropriate.
			 */
			if (!(ixaflags & (IXAF_NO_IPSEC|IXAF_IPSEC_SECURE))) {
				ASSERT(ixa->ixa_ipsec_policy == NULL);
				mp1 = ip_output_attach_policy(mp1, ipha, NULL,
				    NULL, ixa);
				if (mp1 == NULL) {
					/*
					 * MIB and ip_drop_packet already
					 * done
					 */
					continue;
				}
			}
		}
		/* Make sure we have an NCE on this ill */
		nce1 = arp_nce_init(ire1->ire_ill, ire1->ire_addr,
		    ire1->ire_type);
		if (nce1 == NULL) {
			BUMP_MIB(ire1->ire_ill->ill_ip_mib,
			    ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards - broadcast nce",
			    mp1, ire1->ire_ill);
			freemsg(mp1);
			continue;
		}
		nce_orig = ixa->ixa_nce;
		ixa->ixa_nce = nce1;

		ire_refhold(ire1);
		/*
		 * Ignore any errors here. We just collect the errno for
		 * the main ire below
		 */
		(void) ire_send_wire_v4(ire1, mp1, ipha1, ixa, identp);
		ire_refrele(ire1);

		ixa->ixa_nce = nce_orig;
		nce_refrele(nce1);

		ixa->ixa_flags &= ~IXAF_LOOPBACK_COPY;
	}
	irb_refrele(irb);
	/* Finally, the main one */

	/*
	 * For IPMP we only send broadcasts on the ipmp_ill.
	 */
	if (IS_UNDER_IPMP(ire->ire_ill)) {
		freemsg(mp);
		return (0);
	}

	return (ire_send_wire_v4(ire, mp, ipha, ixa, identp));
}

/*
 * Send a packet using a different source address and different
 * IPsec policy.
 */
static void
ip_output_simple_broadcast(ip_xmit_attr_t *ixa, mblk_t *mp)
{
	ip_xmit_attr_t ixas;

	bzero(&ixas, sizeof (ixas));
	ixas.ixa_flags = IXAF_BASIC_SIMPLE_V4;
	ixas.ixa_zoneid = ixa->ixa_zoneid;
	ixas.ixa_ifindex = 0;
	ixas.ixa_ipst = ixa->ixa_ipst;
	ixas.ixa_cred = ixa->ixa_cred;
	ixas.ixa_cpid = ixa->ixa_cpid;
	ixas.ixa_tsl = ixa->ixa_tsl;
	ixas.ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;

	(void) ip_output_simple(mp, &ixas);
	ixa_cleanup(&ixas);
}


static void
multirt_check_v4(ire_t *ire, ipha_t *ipha, ip_xmit_attr_t *ixa)
{
	ip_stack_t	*ipst = ixa->ixa_ipst;

	/* Limit the TTL on multirt packets */
	if (ire->ire_type & IRE_MULTICAST) {
		if (ipha->ipha_ttl > 1) {
			ip2dbg(("ire_send_multirt_v4: forcing multicast "
			    "multirt TTL to 1 (was %d), dst 0x%08x\n",
			    ipha->ipha_ttl, ntohl(ire->ire_addr)));
			ipha->ipha_ttl = 1;
		}
		ixa->ixa_flags |= IXAF_NO_TTL_CHANGE;
	} else if ((ipst->ips_ip_multirt_ttl > 0) &&
	    (ipha->ipha_ttl > ipst->ips_ip_multirt_ttl)) {
		ipha->ipha_ttl = ipst->ips_ip_multirt_ttl;
		/*
		 * Need to ensure we don't increase the ttl should we go through
		 * ire_send_broadcast or multicast.
		 */
		ixa->ixa_flags |= IXAF_NO_TTL_CHANGE;
	}
}

/*
 * ire_sendfn for IRE_MULTICAST
 */
int
ire_send_multicast_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ill_t		*ill = ire->ire_ill;
	iaflags_t	ixaflags = ixa->ixa_flags;

	/*
	 * The IRE_MULTICAST is the same whether or not multirt is in use.
	 * Hence we need special-case code.
	 */
	if (ixaflags & IXAF_MULTIRT_MULTICAST)
		multirt_check_v4(ire, ipha, ixa);

	/*
	 * Check if anything in ip_input_v4 wants a copy of the transmitted
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
		if (ill_hasmembers_v4(ill, ipha->ipha_dst))
			ixa->ixa_flags |= IXAF_LOOPBACK_COPY | IXAF_NO_HW_CKSUM;
	} else if (ipst->ips_netstack->netstack_numzones > 1) {
		/*
		 * This zone should not have a copy. But there are some other
		 * zones which might have members.
		 */
		if (ill_hasmembers_otherzones_v4(ill, ipha->ipha_dst,
		    ixa->ixa_zoneid)) {
			ixa->ixa_flags |= IXAF_NO_LOOP_ZONEID_SET;
			ixa->ixa_no_loop_zoneid = ixa->ixa_zoneid;
			ixa->ixa_flags |= IXAF_LOOPBACK_COPY | IXAF_NO_HW_CKSUM;
		}
	}

	/*
	 * Unless ire_send_multirt_v4 or icmp_output_hdrincl already set a ttl,
	 * force the ttl to the IP_MULTICAST_TTL value
	 */
	if (!(ixaflags & IXAF_NO_TTL_CHANGE)) {
		ipha->ipha_ttl = ixa->ixa_multicast_ttl;
	}

	return (ire_send_wire_v4(ire, mp, ipha, ixa, identp));
}

/*
 * ire_sendfn for IREs with RTF_MULTIRT
 */
int
ire_send_multirt_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ipha_t		*ipha = (ipha_t *)iph_arg;

	multirt_check_v4(ire, ipha, ixa);

	if (ire->ire_type & IRE_MULTICAST)
		return (ire_send_multicast_v4(ire, mp, ipha, ixa, identp));
	else if (ire->ire_type & IRE_BROADCAST)
		return (ire_send_broadcast_v4(ire, mp, ipha, ixa, identp));
	else
		return (ire_send_wire_v4(ire, mp, ipha, ixa, identp));
}

/*
 * ire_sendfn for IREs with RTF_REJECT/RTF_BLACKHOLE, including IRE_NOROUTE
 */
int
ire_send_noroute_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ipha_t		*ipha = (ipha_t *)iph_arg;
	ill_t		*ill;
	ip_recv_attr_t	iras;
	boolean_t	dummy;

	/* We assign an IP ident for nice errors */
	ipha->ipha_ident = atomic_inc_32_nv(identp);

	BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutNoRoutes);

	if (ire->ire_type & IRE_NOROUTE) {
		/* A lack of a route as opposed to RTF_REJECT|BLACKHOLE */
		ip_rts_change(RTM_MISS, ipha->ipha_dst, 0, 0, 0, 0, 0, 0,
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

	if (ip_source_routed(ipha, ipst)) {
		icmp_unreachable(mp, ICMP_SOURCE_ROUTE_FAILED, &iras);
	} else {
		icmp_unreachable(mp, ICMP_HOST_UNREACHABLE, &iras);
	}
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
ip_output_sw_cksum_v4(mblk_t *mp, ipha_t *ipha, ip_xmit_attr_t *ixa)
{
	ip_stack_t	*ipst = ixa->ixa_ipst;
	uint_t		pktlen = ixa->ixa_pktlen;
	uint16_t	*cksump;
	uint32_t	cksum;
	uint8_t		protocol = ixa->ixa_protocol;
	uint16_t	ip_hdr_length = ixa->ixa_ip_hdr_length;
	ipaddr_t	dst = ipha->ipha_dst;
	ipaddr_t	src = ipha->ipha_src;

	/* Just in case it contained garbage */
	DB_CKSUMFLAGS(mp) &= ~HCK_FLAGS;

	/*
	 * Calculate ULP checksum
	 */
	if (protocol == IPPROTO_TCP) {
		cksump = IPH_TCPH_CHECKSUMP(ipha, ip_hdr_length);
		cksum = IP_TCP_CSUM_COMP;
	} else if (protocol == IPPROTO_UDP) {
		cksump = IPH_UDPH_CHECKSUMP(ipha, ip_hdr_length);
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
		goto ip_hdr_cksum;
	} else {
		goto ip_hdr_cksum;
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
	cksum += (dst >> 16) + (dst & 0xFFFF) + (src >> 16) + (src & 0xFFFF);

	cksum = IP_CSUM(mp, ip_hdr_length, cksum);
	/*
	 * For UDP/IPv4 a zero means that the packets wasn't checksummed.
	 * Change to 0xffff
	 */
	if (protocol == IPPROTO_UDP && cksum == 0)
		*cksump = ~cksum;
	else
		*cksump = cksum;

	IP_STAT(ipst, ip_out_sw_cksum);
	IP_STAT_UPDATE(ipst, ip_out_sw_cksum_bytes, pktlen);

ip_hdr_cksum:
	/* Calculate IPv4 header checksum */
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
	return (B_TRUE);
}

/*
 * Calculate the ULP checksum - try to use hardware.
 * In the case of MULTIRT, broadcast or multicast the
 * IXAF_NO_HW_CKSUM is set in which case we use software.
 *
 * If the hardware supports IP header checksum offload; then clear the
 * contents of IP header checksum field as expected by NIC.
 * Do this only if we offloaded either full or partial sum.
 *
 * Returns B_FALSE if the packet was too short for the checksum. Caller
 * should free and do stats.
 */
static boolean_t
ip_output_cksum_v4(iaflags_t ixaflags, mblk_t *mp, ipha_t *ipha,
    ip_xmit_attr_t *ixa, ill_t *ill)
{
	uint_t		pktlen = ixa->ixa_pktlen;
	uint16_t	*cksump;
	uint16_t	hck_flags;
	uint32_t	cksum;
	uint8_t		protocol = ixa->ixa_protocol;
	uint16_t	ip_hdr_length = ixa->ixa_ip_hdr_length;

	if ((ixaflags & IXAF_NO_HW_CKSUM) || !ILL_HCKSUM_CAPABLE(ill) ||
	    !dohwcksum) {
		return (ip_output_sw_cksum_v4(mp, ipha, ixa));
	}

	/*
	 * Calculate ULP checksum. Note that we don't use cksump and cksum
	 * if the ill has FULL support.
	 */
	if (protocol == IPPROTO_TCP) {
		cksump = IPH_TCPH_CHECKSUMP(ipha, ip_hdr_length);
		cksum = IP_TCP_CSUM_COMP;	/* Pseudo-header cksum */
	} else if (protocol == IPPROTO_UDP) {
		cksump = IPH_UDPH_CHECKSUMP(ipha, ip_hdr_length);
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
	} else {
	ip_hdr_cksum:
		/* Calculate IPv4 header checksum */
		ipha->ipha_hdr_checksum = 0;
		ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
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
	if (hck_flags & HCKSUM_INET_FULL_V4) {
		/*
		 * Hardware calculates pseudo-header, header and the
		 * payload checksums, so clear the checksum field in
		 * the protocol header.
		 */
		*cksump = 0;
		DB_CKSUMFLAGS(mp) |= HCK_FULLCKSUM;

		ipha->ipha_hdr_checksum = 0;
		if (hck_flags & HCKSUM_IPHDRCKSUM) {
			DB_CKSUMFLAGS(mp) |= HCK_IPV4_HDRCKSUM;
		} else {
			ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
		}
		return (B_TRUE);
	}
	if ((hck_flags) & HCKSUM_INET_PARTIAL)  {
		ipaddr_t	dst = ipha->ipha_dst;
		ipaddr_t	src = ipha->ipha_src;
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
		cksum += (dst >> 16) + (dst & 0xFFFF) +
		    (src >> 16) + (src & 0xFFFF);
		cksum += *(cksump);
		cksum = (cksum & 0xFFFF) + (cksum >> 16);
		*(cksump) = (cksum & 0xFFFF) + (cksum >> 16);

		/*
		 * Offsets are relative to beginning of IP header.
		 */
		DB_CKSUMSTART(mp) = ip_hdr_length;
		DB_CKSUMSTUFF(mp) = (uint8_t *)cksump - (uint8_t *)ipha;
		DB_CKSUMEND(mp) = pktlen;
		DB_CKSUMFLAGS(mp) |= HCK_PARTIALCKSUM;

		ipha->ipha_hdr_checksum = 0;
		if (hck_flags & HCKSUM_IPHDRCKSUM) {
			DB_CKSUMFLAGS(mp) |= HCK_IPV4_HDRCKSUM;
		} else {
			ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
		}
		return (B_TRUE);
	}
	/* Hardware capabilities include neither full nor partial IPv4 */
	return (ip_output_sw_cksum_v4(mp, ipha, ixa));
}

/*
 * ire_sendfn for offlink and onlink destinations.
 * Also called from the multicast, broadcast, multirt send functions.
 *
 * Assumes that the caller has a hold on the ire.
 *
 * This function doesn't care if the IRE just became condemned since that
 * can happen at any time.
 */
/* ARGSUSED */
int
ire_send_wire_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ipha_t		*ipha = (ipha_t *)iph_arg;
	iaflags_t	ixaflags = ixa->ixa_flags;
	ill_t		*ill;

	ASSERT(ixa->ixa_nce != NULL);
	ill = ixa->ixa_nce->nce_ill;

	if (ixaflags & IXAF_DONTROUTE)
		ipha->ipha_ttl = 1;

	/*
	 * Assign an ident value for this packet. There could be other
	 * threads targeting the same destination, so we have to arrange
	 * for a atomic increment.  Note that we use a 32-bit atomic add
	 * because it has better performance than its 16-bit sibling.
	 *
	 * Normally ixa_extra_ident is 0, but in the case of LSO it will
	 * be the number of TCP segments  that the driver/hardware will
	 * extraly construct.
	 *
	 * If running in cluster mode and if the source address
	 * belongs to a replicated service then vector through
	 * cl_inet_ipident vector to allocate ip identifier
	 * NOTE: This is a contract private interface with the
	 * clustering group.
	 */
	if (cl_inet_ipident != NULL) {
		ipaddr_t src = ipha->ipha_src;
		ipaddr_t dst = ipha->ipha_dst;
		netstackid_t stack_id = ipst->ips_netstack->netstack_stackid;

		ASSERT(cl_inet_isclusterwide != NULL);
		if ((*cl_inet_isclusterwide)(stack_id, IPPROTO_IP,
		    AF_INET, (uint8_t *)(uintptr_t)src, NULL)) {
			/*
			 * Note: not correct with LSO since we can't allocate
			 * ixa_extra_ident+1 consecutive values.
			 */
			ipha->ipha_ident = (*cl_inet_ipident)(stack_id,
			    IPPROTO_IP, AF_INET, (uint8_t *)(uintptr_t)src,
			    (uint8_t *)(uintptr_t)dst, NULL);
		} else {
			ipha->ipha_ident = atomic_add_32_nv(identp,
			    ixa->ixa_extra_ident + 1);
		}
	} else {
		ipha->ipha_ident = atomic_add_32_nv(identp,
		    ixa->ixa_extra_ident + 1);
	}
#ifndef _BIG_ENDIAN
	ipha->ipha_ident = htons(ipha->ipha_ident);
#endif

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
	 * Verify any IPv4 options.
	 *
	 * The presense of IP options also forces the network stack to
	 * calculate the checksum in software.  This is because:
	 *
	 * Wrap around: certain partial-checksum NICs (eri, ce) limit
	 * the size of "start offset" width to 6-bit.  This effectively
	 * sets the largest value of the offset to 64-bytes, starting
	 * from the MAC header.  When the cumulative MAC and IP headers
	 * exceed such limit, the offset will wrap around.  This causes
	 * the checksum to be calculated at the wrong place.
	 *
	 * IPv4 source routing: none of the full-checksum capable NICs
	 * is capable of correctly handling the	IPv4 source-routing
	 * option for purposes of calculating the pseudo-header; the
	 * actual destination is different from the destination in the
	 * header which is that of the next-hop.  (This case may not be
	 * true for NICs which can parse IPv6 extension headers, but
	 * we choose to simplify the implementation by not offloading
	 * checksum when they are present.)
	 */
	if (!IS_SIMPLE_IPH(ipha)) {
		ixaflags = ixa->ixa_flags |= IXAF_NO_HW_CKSUM;
		/* An IS_UNDER_IPMP ill is ok here */
		if (ip_output_options(mp, ipha, ixa, ill)) {
			/* Packet has been consumed and ICMP error sent */
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			return (EINVAL);
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

	if (ixa->ixa_pktlen > ixa->ixa_fragsize ||
	    (ixaflags & IXAF_IPSEC_SECURE)) {
		uint32_t pktlen;

		pktlen = ixa->ixa_pktlen;
		if (ixaflags & IXAF_IPSEC_SECURE)
			pktlen += ipsec_out_extra_length(ixa);

		if (pktlen > IP_MAXPACKET)
			return (EMSGSIZE);

		if (ixaflags & IXAF_SET_ULP_CKSUM) {
			/*
			 * Compute ULP checksum and IP header checksum
			 * using software
			 */
			if (!ip_output_sw_cksum_v4(mp, ipha, ixa)) {
				BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
				ip_drop_output("ipIfStatsOutDiscards", mp, ill);
				freemsg(mp);
				return (EINVAL);
			}
		} else {
			/* Calculate IPv4 header checksum */
			ipha->ipha_hdr_checksum = 0;
			ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
		}

		/*
		 * If this packet would generate a icmp_frag_needed
		 * message, we need to handle it before we do the IPsec
		 * processing. Otherwise, we need to strip the IPsec
		 * headers before we send up the message to the ULPs
		 * which becomes messy and difficult.
		 *
		 * We check using IXAF_DONTFRAG. The DF bit in the header
		 * is not inspected - it will be copied to any generated
		 * fragments.
		 */
		if ((pktlen > ixa->ixa_fragsize) &&
		    (ixaflags & IXAF_DONTFRAG)) {
			/* Generate ICMP and return error */
			ip_recv_attr_t	iras;

			DTRACE_PROBE4(ip4__fragsize__fail, uint_t, pktlen,
			    uint_t, ixa->ixa_fragsize, uint_t, ixa->ixa_pktlen,
			    uint_t, ixa->ixa_pmtu);

			bzero(&iras, sizeof (iras));
			/* Map ixa to ira including IPsec policies */
			ipsec_out_to_in(ixa, ill, &iras);

			ip_drop_output("ICMP_FRAG_NEEDED", mp, ill);
			icmp_frag_needed(mp, ixa->ixa_fragsize, &iras);
			/* We moved any IPsec refs from ixa to iras */
			ira_cleanup(&iras, B_FALSE);
			return (EMSGSIZE);
		}
		DTRACE_PROBE4(ip4__fragsize__ok, uint_t, pktlen,
		    uint_t, ixa->ixa_fragsize, uint_t, ixa->ixa_pktlen,
		    uint_t, ixa->ixa_pmtu);

		if (ixaflags & IXAF_IPSEC_SECURE) {
			/*
			 * Pass in sufficient information so that
			 * IPsec can determine whether to fragment, and
			 * which function to call after fragmentation.
			 */
			return (ipsec_out_process(mp, ixa));
		}
		return (ip_fragment_v4(mp, ixa->ixa_nce, ixaflags,
		    ixa->ixa_pktlen, ixa->ixa_fragsize, ixa->ixa_xmit_hint,
		    ixa->ixa_zoneid, ixa->ixa_no_loop_zoneid,
		    ixa->ixa_postfragfn, &ixa->ixa_cookie));
	}
	if (ixaflags & IXAF_SET_ULP_CKSUM) {
		/* Compute ULP checksum and IP header checksum */
		/* An IS_UNDER_IPMP ill is ok here */
		if (!ip_output_cksum_v4(ixaflags, mp, ipha, ixa, ill)) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", mp, ill);
			freemsg(mp);
			return (EINVAL);
		}
	} else {
		/* Calculate IPv4 header checksum */
		ipha->ipha_hdr_checksum = 0;
		ipha->ipha_hdr_checksum = ip_csum_hdr(ipha);
	}
	return ((ixa->ixa_postfragfn)(mp, ixa->ixa_nce, ixaflags,
	    ixa->ixa_pktlen, ixa->ixa_xmit_hint, ixa->ixa_zoneid,
	    ixa->ixa_no_loop_zoneid, &ixa->ixa_cookie));
}

/*
 * Send mp into ip_input
 * Common for IPv4 and IPv6
 */
void
ip_postfrag_loopback(mblk_t *mp, nce_t *nce, iaflags_t ixaflags,
    uint_t pkt_len, zoneid_t nolzid)
{
	rtc_t		rtc;
	ill_t		*ill = nce->nce_ill;
	ip_recv_attr_t	iras;	/* NOTE: No bzero for performance */
	ncec_t		*ncec;

	ncec = nce->nce_common;
	iras.ira_flags = IRAF_VERIFY_IP_CKSUM | IRAF_VERIFY_ULP_CKSUM |
	    IRAF_LOOPBACK | IRAF_L2SRC_LOOPBACK;
	if (ncec->ncec_flags & NCE_F_BCAST)
		iras.ira_flags |= IRAF_L2DST_BROADCAST;
	else if (ncec->ncec_flags & NCE_F_MCAST)
		iras.ira_flags |= IRAF_L2DST_MULTICAST;

	iras.ira_free_flags = 0;
	iras.ira_cred = NULL;
	iras.ira_cpid = NOPID;
	iras.ira_tsl = NULL;
	iras.ira_zoneid = ALL_ZONES;
	iras.ira_pktlen = pkt_len;
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCInOctets, iras.ira_pktlen);
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCInReceives);

	if (ixaflags & IXAF_IS_IPV4)
		iras.ira_flags |= IRAF_IS_IPV4;

	iras.ira_ill = iras.ira_rill = ill;
	iras.ira_ruifindex = ill->ill_phyint->phyint_ifindex;
	iras.ira_rifindex = iras.ira_ruifindex;
	iras.ira_mhip = NULL;

	iras.ira_flags |= ixaflags & IAF_MASK;
	iras.ira_no_loop_zoneid = nolzid;

	/* Broadcast and multicast doesn't care about the squeue */
	iras.ira_sqp = NULL;

	rtc.rtc_ire = NULL;
	if (ixaflags & IXAF_IS_IPV4) {
		ipha_t		*ipha = (ipha_t *)mp->b_rptr;

		rtc.rtc_ipaddr = INADDR_ANY;

		(*ill->ill_inputfn)(mp, ipha, &ipha->ipha_dst, &iras, &rtc);
		if (rtc.rtc_ire != NULL) {
			ASSERT(rtc.rtc_ipaddr != INADDR_ANY);
			ire_refrele(rtc.rtc_ire);
		}
	} else {
		ip6_t		*ip6h = (ip6_t *)mp->b_rptr;

		rtc.rtc_ip6addr = ipv6_all_zeros;

		(*ill->ill_inputfn)(mp, ip6h, &ip6h->ip6_dst, &iras, &rtc);
		if (rtc.rtc_ire != NULL) {
			ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&rtc.rtc_ip6addr));
			ire_refrele(rtc.rtc_ire);
		}
	}
	/* Any references to clean up? No hold on ira */
	if (iras.ira_flags & (IRAF_IPSEC_SECURE|IRAF_SYSTEM_LABELED))
		ira_cleanup(&iras, B_FALSE);
}

/*
 * Post fragmentation function for IRE_MULTICAST and IRE_BROADCAST which
 * looks at the IXAF_LOOPBACK_COPY flag.
 * Common for IPv4 and IPv6.
 *
 * If the loopback copy fails (due to no memory) but we send the packet out
 * on the wire we return no failure. Only in the case we supress the wire
 * sending do we take the loopback failure into account.
 *
 * Note that we do not perform DTRACE_IP7 and FW_HOOKS for the looped back copy.
 * Those operations are performed on this packet in ip_xmit() and it would
 * be odd to do it twice for the same packet.
 */
int
ip_postfrag_loopcheck(mblk_t *mp, nce_t *nce, iaflags_t ixaflags,
    uint_t pkt_len, uint32_t xmit_hint, zoneid_t szone, zoneid_t nolzid,
    uintptr_t *ixacookie)
{
	ill_t		*ill = nce->nce_ill;
	int		error = 0;

	/*
	 * Check for IXAF_LOOPBACK_COPY - send a copy to ip as if the driver
	 * had looped it back
	 */
	if (ixaflags & IXAF_LOOPBACK_COPY) {
		mblk_t		*mp1;

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
	 * If TTL = 0 then only do the loopback to this host i.e. we are
	 * done. We are also done if this was the
	 * loopback interface since it is sufficient
	 * to loopback one copy of a multicast packet.
	 */
	if (ixaflags & IXAF_IS_IPV4) {
		ipha_t *ipha = (ipha_t *)mp->b_rptr;

		if (ipha->ipha_ttl == 0) {
			ip_drop_output("multicast ipha_ttl not sent to wire",
			    mp, ill);
			freemsg(mp);
			return (error);
		}
	} else {
		ip6_t	*ip6h = (ip6_t *)mp->b_rptr;

		if (ip6h->ip6_hops == 0) {
			ip_drop_output("multicast ipha_ttl not sent to wire",
			    mp, ill);
			freemsg(mp);
			return (error);
		}
	}
	if (nce->nce_ill->ill_wq == NULL) {
		/* Loopback interface */
		ip_drop_output("multicast on lo0 not sent to wire", mp, ill);
		freemsg(mp);
		return (error);
	}

	return (ip_xmit(mp, nce, ixaflags, pkt_len, xmit_hint, szone, 0,
	    ixacookie));
}

/*
 * Post fragmentation function for RTF_MULTIRT routes.
 * Since IRE_BROADCASTs can have RTF_MULTIRT, this function
 * checks IXAF_LOOPBACK_COPY.
 *
 * If no packet is sent due to failures then we return an errno, but if at
 * least one succeeded we return zero.
 */
int
ip_postfrag_multirt_v4(mblk_t *mp, nce_t *nce, iaflags_t ixaflags,
    uint_t pkt_len, uint32_t xmit_hint, zoneid_t szone, zoneid_t nolzid,
    uintptr_t *ixacookie)
{
	irb_t		*irb;
	ipha_t		*ipha = (ipha_t *)mp->b_rptr;
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
	ipaddr_t	nexthop;

	ASSERT(ixaflags & IXAF_IS_IPV4);

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
	 * Loop over RTF_MULTIRT for ipha_dst in the same bucket. Send
	 * a copy to each one.
	 * Use the nce (nexthop) and ipha_dst to find the ire.
	 *
	 * MULTIRT is not designed to work with shared-IP zones thus we don't
	 * need to pass a zoneid or a label to the IRE lookup.
	 */
	if (V4_PART_OF_V6(nce->nce_addr) == ipha->ipha_dst) {
		/* Broadcast and multicast case */
		ire = ire_ftable_lookup_v4(ipha->ipha_dst, 0, 0, 0,
		    NULL, ALL_ZONES, NULL, MATCH_IRE_DSTONLY, 0, ipst, NULL);
	} else {
		ipaddr_t v4addr = V4_PART_OF_V6(nce->nce_addr);

		/* Unicast case */
		ire = ire_ftable_lookup_v4(ipha->ipha_dst, 0, v4addr, 0,
		    NULL, ALL_ZONES, NULL, MATCH_IRE_GW, 0, ipst, NULL);
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
		/*
		 * For broadcast we can have a mixture of IRE_BROADCAST and
		 * IRE_HOST due to the manually added IRE_HOSTs that are used
		 * to trigger the creation of the special CGTP broadcast routes.
		 * Thus we have to skip if ire_type doesn't match the original.
		 */
		if (IRE_IS_CONDEMNED(ire1) ||
		    !(ire1->ire_flags & RTF_MULTIRT) ||
		    ire1->ire_type != ire->ire_type)
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
			uint_t	match_flags = MATCH_IRE_DSTONLY;

			if (ire1->ire_ill != NULL)
				match_flags |= MATCH_IRE_ILL;
			ire2 = ire_route_recursive_impl_v4(ire1,
			    ire1->ire_addr, ire1->ire_type, ire1->ire_ill,
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

		/* Pick the addr and type to use for arp_nce_init */
		if (nce->nce_common->ncec_flags & NCE_F_BCAST) {
			ire_type = IRE_BROADCAST;
			nexthop = ire1->ire_gateway_addr;
		} else if (nce->nce_common->ncec_flags & NCE_F_MCAST) {
			ire_type = IRE_MULTICAST;
			nexthop = ipha->ipha_dst;
		} else {
			ire_type = ire1->ire_type;	/* Doesn't matter */
			nexthop = ire1->ire_gateway_addr;
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

		nce1 = arp_nce_init(ill1, nexthop, ire_type);
		if (nce1 == NULL) {
			BUMP_MIB(ill1->ill_ip_mib, ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards - no nce",
			    mp, ill1);
			ill_refrele(ill1);
			error = ENETUNREACH;
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

/*
 * Verify local connectivity. This check is called by ULP fusion code.
 * The generation number on an IRE_LOCAL or IRE_LOOPBACK only changes if
 * the interface is brought down and back up. So we simply fail the local
 * process. The caller, TCP Fusion, should unfuse the connection.
 */
boolean_t
ip_output_verify_local(ip_xmit_attr_t *ixa)
{
	ire_t		*ire = ixa->ixa_ire;

	if (!(ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK)))
		return (B_FALSE);

	return (ixa->ixa_ire->ire_generation == ixa->ixa_ire_generation);
}

/*
 * Local process for ULP loopback, TCP Fusion. Handle both IPv4 and IPv6.
 *
 * The caller must call ip_output_verify_local() first. This function handles
 * IPobs, FW_HOOKS, and/or IPsec cases sequentially.
 */
mblk_t *
ip_output_process_local(mblk_t *mp, ip_xmit_attr_t *ixa, boolean_t hooks_out,
    boolean_t hooks_in, conn_t *peer_connp)
{
	ill_t		*ill = ixa->ixa_ire->ire_ill;
	ipha_t		*ipha = NULL;
	ip6_t		*ip6h = NULL;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	iaflags_t	ixaflags = ixa->ixa_flags;
	ip_recv_attr_t	iras;
	int		error;

	ASSERT(mp != NULL);

	if (ixaflags & IXAF_IS_IPV4) {
		ipha = (ipha_t *)mp->b_rptr;

		/*
		 * If a callback is enabled then we need to know the
		 * source and destination zoneids for the packet. We already
		 * have those handy.
		 */
		if (ipst->ips_ip4_observe.he_interested) {
			zoneid_t szone, dzone;
			zoneid_t stackzoneid;

			stackzoneid = netstackid_to_zoneid(
			    ipst->ips_netstack->netstack_stackid);

			if (stackzoneid == GLOBAL_ZONEID) {
				/* Shared-IP zone */
				dzone = ixa->ixa_ire->ire_zoneid;
				szone = ixa->ixa_zoneid;
			} else {
				szone = dzone = stackzoneid;
			}
			ipobs_hook(mp, IPOBS_HOOK_LOCAL, szone, dzone, ill,
			    ipst);
		}
		DTRACE_IP7(send, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
		    ipha, __dtrace_ipsr_ill_t *, ill, ipha_t *, ipha, ip6_t *,
		    NULL, int, 1);

		/* FW_HOOKS: LOOPBACK_OUT */
		if (hooks_out) {
			DTRACE_PROBE4(ip4__loopback__out__start, ill_t *, NULL,
			    ill_t *, ill, ipha_t *, ipha, mblk_t *, mp);
			FW_HOOKS(ipst->ips_ip4_loopback_out_event,
			    ipst->ips_ipv4firewall_loopback_out,
			    NULL, ill, ipha, mp, mp, 0, ipst, error);
			DTRACE_PROBE1(ip4__loopback__out__end, mblk_t *, mp);
		}
		if (mp == NULL)
			return (NULL);

		/* FW_HOOKS: LOOPBACK_IN */
		if (hooks_in) {
			DTRACE_PROBE4(ip4__loopback__in__start, ill_t *, ill,
			    ill_t *, NULL, ipha_t *, ipha, mblk_t *, mp);
			FW_HOOKS(ipst->ips_ip4_loopback_in_event,
			    ipst->ips_ipv4firewall_loopback_in,
			    ill, NULL, ipha, mp, mp, 0, ipst, error);
			DTRACE_PROBE1(ip4__loopback__in__end, mblk_t *, mp);
		}
		if (mp == NULL)
			return (NULL);

		DTRACE_IP7(receive, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
		    ipha, __dtrace_ipsr_ill_t *, ill, ipha_t *, ipha, ip6_t *,
		    NULL, int, 1);

		/* Inbound IPsec polocies */
		if (peer_connp != NULL) {
			/* Map ixa to ira including IPsec policies. */
			ipsec_out_to_in(ixa, ill, &iras);
			mp = ipsec_check_inbound_policy(mp, peer_connp, ipha,
			    NULL, &iras);
		}
	} else {
		ip6h = (ip6_t *)mp->b_rptr;

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
				dzone = ixa->ixa_ire->ire_zoneid;
				szone = ixa->ixa_zoneid;
			} else {
				szone = dzone = stackzoneid;
			}
			ipobs_hook(mp, IPOBS_HOOK_LOCAL, szone, dzone, ill,
			    ipst);
		}
		DTRACE_IP7(send, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
		    ip6h, __dtrace_ipsr_ill_t *, ill, ipha_t *, NULL, ip6_t *,
		    ip6h, int, 1);

		/* FW_HOOKS: LOOPBACK_OUT */
		if (hooks_out) {
			DTRACE_PROBE4(ip6__loopback__out__start, ill_t *, NULL,
			    ill_t *, ill, ip6_t *, ip6h, mblk_t *, mp);
			FW_HOOKS6(ipst->ips_ip6_loopback_out_event,
			    ipst->ips_ipv6firewall_loopback_out,
			    NULL, ill, ip6h, mp, mp, 0, ipst, error);
			DTRACE_PROBE1(ip6__loopback__out__end, mblk_t *, mp);
		}
		if (mp == NULL)
			return (NULL);

		/* FW_HOOKS: LOOPBACK_IN */
		if (hooks_in) {
			DTRACE_PROBE4(ip6__loopback__in__start, ill_t *, ill,
			    ill_t *, NULL, ip6_t *, ip6h, mblk_t *, mp);
			FW_HOOKS6(ipst->ips_ip6_loopback_in_event,
			    ipst->ips_ipv6firewall_loopback_in,
			    ill, NULL, ip6h, mp, mp, 0, ipst, error);
			DTRACE_PROBE1(ip6__loopback__in__end, mblk_t *, mp);
		}
		if (mp == NULL)
			return (NULL);

		DTRACE_IP7(receive, mblk_t *, mp, conn_t *, NULL, void_ip_t *,
		    ip6h, __dtrace_ipsr_ill_t *, ill, ipha_t *, NULL, ip6_t *,
		    ip6h, int, 1);

		/* Inbound IPsec polocies */
		if (peer_connp != NULL) {
			/* Map ixa to ira including IPsec policies. */
			ipsec_out_to_in(ixa, ill, &iras);
			mp = ipsec_check_inbound_policy(mp, peer_connp, NULL,
			    ip6h, &iras);
		}
	}

	if (mp == NULL) {
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", NULL, ill);
	}

	return (mp);
}
