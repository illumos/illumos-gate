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
/*
 * Copyright (c) 1990 Mentat Inc.
 */

/*
 * This file contains the interface control functions for IPv6.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/debug.h>
#include <sys/zone.h>
#include <sys/policy.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/isa_defs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/igmp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_multi.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <inet/ip_ndp.h>
#include <inet/ip_if.h>
#include <inet/ip6_asp.h>
#include <inet/tun.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>

#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>

static in6_addr_t	ipv6_ll_template =
			{(uint32_t)V6_LINKLOCAL, 0x0, 0x0, 0x0};

static ipif_t *
ipif_lookup_interface_v6(const in6_addr_t *if_addr, const in6_addr_t *dst,
    queue_t *q, mblk_t *mp, ipsq_func_t func, int *error, ip_stack_t *ipst);

/*
 * These two functions, ipif_lookup_group_v6() and ill_lookup_group_v6(),
 * are called when an application does not specify an interface to be
 * used for multicast traffic.  It calls ire_lookup_multi_v6() to look
 * for an interface route for the specified multicast group.  Doing
 * this allows the administrator to add prefix routes for multicast to
 * indicate which interface to be used for multicast traffic in the above
 * scenario.  The route could be for all multicast (ff00::/8), for a single
 * multicast group (a /128 route) or anything in between.  If there is no
 * such multicast route, we just find any multicast capable interface and
 * return it.
 */
ipif_t *
ipif_lookup_group_v6(const in6_addr_t *group, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t	*ire;
	ipif_t	*ipif;

	ire = ire_lookup_multi_v6(group, zoneid, ipst);
	if (ire != NULL) {
		ipif = ire->ire_ipif;
		ipif_refhold(ipif);
		ire_refrele(ire);
		return (ipif);
	}

	return (ipif_lookup_multicast(ipst, zoneid, B_TRUE));
}

ill_t *
ill_lookup_group_v6(const in6_addr_t *group, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t	*ire;
	ill_t	*ill;
	ipif_t	*ipif;

	ire = ire_lookup_multi_v6(group, zoneid, ipst);
	if (ire != NULL) {
		ill = ire->ire_ipif->ipif_ill;
		ill_refhold(ill);
		ire_refrele(ire);
		return (ill);
	}

	ipif = ipif_lookup_multicast(ipst, zoneid, B_TRUE);
	if (ipif == NULL)
		return (NULL);

	ill = ipif->ipif_ill;
	ill_refhold(ill);
	ipif_refrele(ipif);
	return (ill);
}

/*
 * Look for an ipif with the specified interface address and destination.
 * The destination address is used only for matching point-to-point interfaces.
 */
static ipif_t *
ipif_lookup_interface_v6(const in6_addr_t *if_addr, const in6_addr_t *dst,
    queue_t *q, mblk_t *mp, ipsq_func_t func, int *error, ip_stack_t *ipst)
{
	ipif_t	*ipif;
	ill_t	*ill;
	ipsq_t	*ipsq;
	ill_walk_context_t ctx;

	if (error != NULL)
		*error = 0;

	/*
	 * First match all the point-to-point interfaces
	 * before looking at non-point-to-point interfaces.
	 * This is done to avoid returning non-point-to-point
	 * ipif instead of unnumbered point-to-point ipif.
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		GRAB_CONN_LOCK(q);
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			/* Allow the ipif to be down */
			if ((ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    (IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6lcl_addr,
			    if_addr)) &&
			    (IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6pp_dst_addr,
			    dst))) {
				if (IPIF_CAN_LOOKUP(ipif)) {
					ipif_refhold_locked(ipif);
					mutex_exit(&ill->ill_lock);
					RELEASE_CONN_LOCK(q);
					rw_exit(&ipst->ips_ill_g_lock);
					return (ipif);
				} else if (IPIF_CAN_WAIT(ipif, q)) {
					ipsq = ill->ill_phyint->phyint_ipsq;
					mutex_enter(&ipsq->ipsq_lock);
					mutex_enter(&ipsq->ipsq_xop->ipx_lock);
					mutex_exit(&ill->ill_lock);
					rw_exit(&ipst->ips_ill_g_lock);
					ipsq_enq(ipsq, q, mp, func, NEW_OP,
					    ill);
					mutex_exit(&ipsq->ipsq_xop->ipx_lock);
					mutex_exit(&ipsq->ipsq_lock);
					RELEASE_CONN_LOCK(q);
					if (error != NULL)
						*error = EINPROGRESS;
					return (NULL);
				}
			}
		}
		mutex_exit(&ill->ill_lock);
		RELEASE_CONN_LOCK(q);
	}
	rw_exit(&ipst->ips_ill_g_lock);
	/* lookup the ipif based on interface address */
	ipif = ipif_lookup_addr_v6(if_addr, NULL, ALL_ZONES, q, mp, func,
	    error, ipst);
	ASSERT(ipif == NULL || ipif->ipif_isv6);
	return (ipif);
}

/*
 * Common function for ipif_lookup_addr_v6() and ipif_lookup_addr_exact_v6().
 */
static ipif_t *
ipif_lookup_addr_common_v6(const in6_addr_t *addr, ill_t *match_ill,
    boolean_t match_illgrp, zoneid_t zoneid, queue_t *q, mblk_t *mp,
    ipsq_func_t func, int *error, ip_stack_t *ipst)
{
	ipif_t	*ipif;
	ill_t	*ill;
	boolean_t  ptp = B_FALSE;
	ipsq_t	*ipsq;
	ill_walk_context_t ctx;

	if (error != NULL)
		*error = 0;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	/*
	 * Repeat twice, first based on local addresses and
	 * next time for pointopoint.
	 */
repeat:
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (match_ill != NULL && ill != match_ill &&
		    (!match_illgrp || !IS_IN_SAME_ILLGRP(ill, match_ill))) {
			continue;
		}
		GRAB_CONN_LOCK(q);
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (zoneid != ALL_ZONES &&
			    ipif->ipif_zoneid != zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;
			/* Allow the ipif to be down */
			if ((!ptp && (IN6_ARE_ADDR_EQUAL(
			    &ipif->ipif_v6lcl_addr, addr) &&
			    (ipif->ipif_flags & IPIF_UNNUMBERED) == 0)) ||
			    (ptp && (ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6pp_dst_addr,
			    addr))) {
				if (IPIF_CAN_LOOKUP(ipif)) {
					ipif_refhold_locked(ipif);
					mutex_exit(&ill->ill_lock);
					RELEASE_CONN_LOCK(q);
					rw_exit(&ipst->ips_ill_g_lock);
					return (ipif);
				} else if (IPIF_CAN_WAIT(ipif, q)) {
					ipsq = ill->ill_phyint->phyint_ipsq;
					mutex_enter(&ipsq->ipsq_lock);
					mutex_enter(&ipsq->ipsq_xop->ipx_lock);
					mutex_exit(&ill->ill_lock);
					rw_exit(&ipst->ips_ill_g_lock);
					ipsq_enq(ipsq, q, mp, func, NEW_OP,
					    ill);
					mutex_exit(&ipsq->ipsq_xop->ipx_lock);
					mutex_exit(&ipsq->ipsq_lock);
					RELEASE_CONN_LOCK(q);
					if (error != NULL)
						*error = EINPROGRESS;
					return (NULL);
				}
			}
		}
		mutex_exit(&ill->ill_lock);
		RELEASE_CONN_LOCK(q);
	}

	/* If we already did the ptp case, then we are done */
	if (ptp) {
		rw_exit(&ipst->ips_ill_g_lock);
		if (error != NULL)
			*error = ENXIO;
		return (NULL);
	}
	ptp = B_TRUE;
	goto repeat;
}

boolean_t
ip_addr_exists_v6(const in6_addr_t *addr, zoneid_t zoneid,
    ip_stack_t *ipst)
{
	ipif_t	*ipif;
	ill_t	*ill;
	ill_walk_context_t ctx;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);

	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (zoneid != ALL_ZONES &&
			    ipif->ipif_zoneid != zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;
			/* Allow the ipif to be down */
			if (((IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6lcl_addr,
			    addr) &&
			    (ipif->ipif_flags & IPIF_UNNUMBERED) == 0)) ||
			    ((ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6pp_dst_addr,
			    addr))) {
				mutex_exit(&ill->ill_lock);
				rw_exit(&ipst->ips_ill_g_lock);
				return (B_TRUE);
			}
		}
		mutex_exit(&ill->ill_lock);
	}

	rw_exit(&ipst->ips_ill_g_lock);
	return (B_FALSE);
}

/*
 * Lookup an ipif with the specified address.  For point-to-point links we
 * look for matches on either the destination address or the local address,
 * but we skip the local address check if IPIF_UNNUMBERED is set.  If the
 * `match_ill' argument is non-NULL, the lookup is restricted to that ill
 * (or illgrp if `match_ill' is in an IPMP group).
 */
ipif_t *
ipif_lookup_addr_v6(const in6_addr_t *addr, ill_t *match_ill, zoneid_t zoneid,
    queue_t *q, mblk_t *mp, ipsq_func_t func, int *error, ip_stack_t *ipst)
{
	return (ipif_lookup_addr_common_v6(addr, match_ill, B_TRUE, zoneid, q,
	    mp, func, error, ipst));
}

/*
 * Special abbreviated version of ipif_lookup_addr_v6() that doesn't match
 * `match_ill' across the IPMP group.  This function is only needed in some
 * corner-cases; almost everything should use ipif_lookup_addr_v6().
 */
ipif_t *
ipif_lookup_addr_exact_v6(const in6_addr_t *addr, ill_t *match_ill,
    ip_stack_t *ipst)
{
	ASSERT(match_ill != NULL);
	return (ipif_lookup_addr_common_v6(addr, match_ill, B_FALSE, ALL_ZONES,
	    NULL, NULL, NULL, NULL, ipst));
}

/*
 * Look for an ipif with the specified address. For point-point links
 * we look for matches on either the destination address and the local
 * address, but we ignore the check on the local address if IPIF_UNNUMBERED
 * is set.
 * If the `match_ill' argument is non-NULL, the lookup is restricted to that
 * ill (or illgrp if `match_ill' is in an IPMP group).
 * Return the zoneid for the ipif. ALL_ZONES if none found.
 */
zoneid_t
ipif_lookup_addr_zoneid_v6(const in6_addr_t *addr, ill_t *match_ill,
    ip_stack_t *ipst)
{
	ipif_t	*ipif;
	ill_t	*ill;
	boolean_t  ptp = B_FALSE;
	ill_walk_context_t ctx;
	zoneid_t	zoneid;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	/*
	 * Repeat twice, first based on local addresses and
	 * next time for pointopoint.
	 */
repeat:
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (match_ill != NULL && ill != match_ill &&
		    !IS_IN_SAME_ILLGRP(ill, match_ill)) {
			continue;
		}
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			/* Allow the ipif to be down */
			if ((!ptp && (IN6_ARE_ADDR_EQUAL(
			    &ipif->ipif_v6lcl_addr, addr) &&
			    (ipif->ipif_flags & IPIF_UNNUMBERED) == 0)) ||
			    (ptp && (ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6pp_dst_addr,
			    addr)) &&
			    !(ipif->ipif_state_flags & IPIF_CONDEMNED)) {
				zoneid = ipif->ipif_zoneid;
				mutex_exit(&ill->ill_lock);
				rw_exit(&ipst->ips_ill_g_lock);
				/*
				 * If ipif_zoneid was ALL_ZONES then we have
				 * a trusted extensions shared IP address.
				 * In that case GLOBAL_ZONEID works to send.
				 */
				if (zoneid == ALL_ZONES)
					zoneid = GLOBAL_ZONEID;
				return (zoneid);
			}
		}
		mutex_exit(&ill->ill_lock);
	}

	/* If we already did the ptp case, then we are done */
	if (ptp) {
		rw_exit(&ipst->ips_ill_g_lock);
		return (ALL_ZONES);
	}
	ptp = B_TRUE;
	goto repeat;
}

/*
 * Perform various checks to verify that an address would make sense as a local
 * interface address.  This is currently only called when an attempt is made
 * to set a local address.
 *
 * Does not allow a v4-mapped address, an address that equals the subnet
 * anycast address, ... a multicast address, ...
 */
boolean_t
ip_local_addr_ok_v6(const in6_addr_t *addr, const in6_addr_t *subnet_mask)
{
	in6_addr_t subnet;

	if (IN6_IS_ADDR_UNSPECIFIED(addr))
		return (B_TRUE);	/* Allow all zeros */

	/*
	 * Don't allow all zeroes or host part, but allow
	 * all ones netmask.
	 */
	V6_MASK_COPY(*addr, *subnet_mask, subnet);
	if (IN6_IS_ADDR_V4MAPPED(addr) ||
	    (IN6_ARE_ADDR_EQUAL(addr, &subnet) &&
	    !IN6_ARE_ADDR_EQUAL(subnet_mask, &ipv6_all_ones)) ||
	    (IN6_IS_ADDR_V4COMPAT(addr) && CLASSD(V4_PART_OF_V6((*addr)))) ||
	    IN6_IS_ADDR_MULTICAST(addr))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Perform various checks to verify that an address would make sense as a
 * remote/subnet interface address.
 */
boolean_t
ip_remote_addr_ok_v6(const in6_addr_t *addr, const in6_addr_t *subnet_mask)
{
	in6_addr_t subnet;

	if (IN6_IS_ADDR_UNSPECIFIED(addr))
		return (B_TRUE);	/* Allow all zeros */

	V6_MASK_COPY(*addr, *subnet_mask, subnet);
	if (IN6_IS_ADDR_V4MAPPED(addr) ||
	    (IN6_ARE_ADDR_EQUAL(addr, &subnet) &&
	    !IN6_ARE_ADDR_EQUAL(subnet_mask, &ipv6_all_ones)) ||
	    IN6_IS_ADDR_MULTICAST(addr) ||
	    (IN6_IS_ADDR_V4COMPAT(addr) && CLASSD(V4_PART_OF_V6((*addr)))))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * ip_rt_add_v6 is called to add an IPv6 route to the forwarding table.
 * ipif_arg is passed in to associate it with the correct interface
 * (for link-local destinations and gateways).
 */
/* ARGSUSED1 */
int
ip_rt_add_v6(const in6_addr_t *dst_addr, const in6_addr_t *mask,
    const in6_addr_t *gw_addr, const in6_addr_t *src_addr, int flags,
    ipif_t *ipif_arg, ire_t **ire_arg, queue_t *q, mblk_t *mp, ipsq_func_t func,
    struct rtsa_s *sp, ip_stack_t *ipst)
{
	ire_t	*ire;
	ire_t	*gw_ire = NULL;
	ipif_t	*ipif;
	boolean_t ipif_refheld = B_FALSE;
	uint_t	type;
	int	match_flags = MATCH_IRE_TYPE;
	int	error;
	tsol_gc_t *gc = NULL;
	tsol_gcgrp_t *gcgrp = NULL;
	boolean_t gcgrp_xtraref = B_FALSE;

	if (ire_arg != NULL)
		*ire_arg = NULL;

	/*
	 * Prevent routes with a zero gateway from being created (since
	 * interfaces can currently be plumbed and brought up with no assigned
	 * address).
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(gw_addr))
		return (ENETUNREACH);

	/*
	 * If this is the case of RTF_HOST being set, then we set the netmask
	 * to all ones (regardless if one was supplied).
	 */
	if (flags & RTF_HOST)
		mask = &ipv6_all_ones;

	/*
	 * Get the ipif, if any, corresponding to the gw_addr
	 */
	ipif = ipif_lookup_interface_v6(gw_addr, dst_addr, q, mp, func,
	    &error, ipst);
	if (ipif != NULL)
		ipif_refheld = B_TRUE;
	else if (error == EINPROGRESS) {
		ip1dbg(("ip_rt_add_v6: null and EINPROGRESS"));
		return (error);
	}

	/*
	 * GateD will attempt to create routes with a loopback interface
	 * address as the gateway and with RTF_GATEWAY set.  We allow
	 * these routes to be added, but create them as interface routes
	 * since the gateway is an interface address.
	 */
	if ((ipif != NULL) && (ipif->ipif_ire_type == IRE_LOOPBACK)) {
		flags &= ~RTF_GATEWAY;
		if (IN6_ARE_ADDR_EQUAL(gw_addr, &ipv6_loopback) &&
		    IN6_ARE_ADDR_EQUAL(dst_addr, &ipv6_loopback) &&
		    IN6_ARE_ADDR_EQUAL(mask, &ipv6_all_ones)) {
			ire = ire_ctable_lookup_v6(dst_addr, 0, IRE_LOOPBACK,
			    ipif, ALL_ZONES, NULL, match_flags, ipst);
			if (ire != NULL) {
				ire_refrele(ire);
				if (ipif_refheld)
					ipif_refrele(ipif);
				return (EEXIST);
			}
			ip1dbg(("ipif_up_done: 0x%p creating IRE 0x%x"
			    "for 0x%x\n", (void *)ipif,
			    ipif->ipif_ire_type,
			    ntohl(ipif->ipif_lcl_addr)));
			ire = ire_create_v6(
			    dst_addr,
			    mask,
			    &ipif->ipif_v6src_addr,
			    NULL,
			    &ipif->ipif_mtu,
			    NULL,
			    NULL,
			    NULL,
			    ipif->ipif_net_type,
			    ipif,
			    NULL,
			    0,
			    0,
			    flags,
			    &ire_uinfo_null,
			    NULL,
			    NULL,
			    ipst);
			if (ire == NULL) {
				if (ipif_refheld)
					ipif_refrele(ipif);
				return (ENOMEM);
			}
			error = ire_add(&ire, q, mp, func, B_FALSE);
			if (error == 0)
				goto save_ire;
			/*
			 * In the result of failure, ire_add() will have already
			 * deleted the ire in question, so there is no need to
			 * do that here.
			 */
			if (ipif_refheld)
				ipif_refrele(ipif);
			return (error);
		}
	}

	/*
	 * Traditionally, interface routes are ones where RTF_GATEWAY isn't set
	 * and the gateway address provided is one of the system's interface
	 * addresses.  By using the routing socket interface and supplying an
	 * RTA_IFP sockaddr with an interface index, an alternate method of
	 * specifying an interface route to be created is available which uses
	 * the interface index that specifies the outgoing interface rather than
	 * the address of an outgoing interface (which may not be able to
	 * uniquely identify an interface).  When coupled with the RTF_GATEWAY
	 * flag, routes can be specified which not only specify the next-hop to
	 * be used when routing to a certain prefix, but also which outgoing
	 * interface should be used.
	 *
	 * Previously, interfaces would have unique addresses assigned to them
	 * and so the address assigned to a particular interface could be used
	 * to identify a particular interface.  One exception to this was the
	 * case of an unnumbered interface (where IPIF_UNNUMBERED was set).
	 *
	 * With the advent of IPv6 and its link-local addresses, this
	 * restriction was relaxed and interfaces could share addresses between
	 * themselves.  In fact, typically all of the link-local interfaces on
	 * an IPv6 node or router will have the same link-local address.  In
	 * order to differentiate between these interfaces, the use of an
	 * interface index is necessary and this index can be carried inside a
	 * RTA_IFP sockaddr (which is actually a sockaddr_dl).  One restriction
	 * of using the interface index, however, is that all of the ipif's that
	 * are part of an ill have the same index and so the RTA_IFP sockaddr
	 * cannot be used to differentiate between ipif's (or logical
	 * interfaces) that belong to the same ill (physical interface).
	 *
	 * For example, in the following case involving IPv4 interfaces and
	 * logical interfaces
	 *
	 *	192.0.2.32	255.255.255.224	192.0.2.33	U	if0
	 *	192.0.2.32	255.255.255.224	192.0.2.34	U	if0:1
	 *	192.0.2.32	255.255.255.224	192.0.2.35	U	if0:2
	 *
	 * the ipif's corresponding to each of these interface routes can be
	 * uniquely identified by the "gateway" (actually interface address).
	 *
	 * In this case involving multiple IPv6 default routes to a particular
	 * link-local gateway, the use of RTA_IFP is necessary to specify which
	 * default route is of interest:
	 *
	 *	default		fe80::123:4567:89ab:cdef	U	if0
	 *	default		fe80::123:4567:89ab:cdef	U	if1
	 */

	/* RTF_GATEWAY not set */
	if (!(flags & RTF_GATEWAY)) {
		queue_t	*stq;

		if (sp != NULL) {
			ip2dbg(("ip_rt_add_v6: gateway security attributes "
			    "cannot be set with interface route\n"));
			if (ipif_refheld)
				ipif_refrele(ipif);
			return (EINVAL);
		}

		/*
		 * As the interface index specified with the RTA_IFP sockaddr is
		 * the same for all ipif's off of an ill, the matching logic
		 * below uses MATCH_IRE_ILL if such an index was specified.
		 * This means that routes sharing the same prefix when added
		 * using a RTA_IFP sockaddr must have distinct interface
		 * indices (namely, they must be on distinct ill's).
		 *
		 * On the other hand, since the gateway address will usually be
		 * different for each ipif on the system, the matching logic
		 * uses MATCH_IRE_IPIF in the case of a traditional interface
		 * route.  This means that interface routes for the same prefix
		 * can be created if they belong to distinct ipif's and if a
		 * RTA_IFP sockaddr is not present.
		 */
		if (ipif_arg != NULL) {
			if (ipif_refheld) {
				ipif_refrele(ipif);
				ipif_refheld = B_FALSE;
			}
			ipif = ipif_arg;
			match_flags |= MATCH_IRE_ILL;
		} else {
			/*
			 * Check the ipif corresponding to the gw_addr
			 */
			if (ipif == NULL)
				return (ENETUNREACH);
			match_flags |= MATCH_IRE_IPIF;
		}

		ASSERT(ipif != NULL);
		/*
		 * We check for an existing entry at this point.
		 */
		match_flags |= MATCH_IRE_MASK;
		ire = ire_ftable_lookup_v6(dst_addr, mask, 0, IRE_INTERFACE,
		    ipif, NULL, ALL_ZONES, 0, NULL, match_flags, ipst);
		if (ire != NULL) {
			ire_refrele(ire);
			if (ipif_refheld)
				ipif_refrele(ipif);
			return (EEXIST);
		}

		stq = (ipif->ipif_net_type == IRE_IF_RESOLVER)
		    ? ipif->ipif_rq : ipif->ipif_wq;

		/*
		 * Create a copy of the IRE_LOOPBACK, IRE_IF_NORESOLVER or
		 * IRE_IF_RESOLVER with the modified address and netmask.
		 */
		ire = ire_create_v6(
		    dst_addr,
		    mask,
		    &ipif->ipif_v6src_addr,
		    NULL,
		    &ipif->ipif_mtu,
		    NULL,
		    NULL,
		    stq,
		    ipif->ipif_net_type,
		    ipif,
		    NULL,
		    0,
		    0,
		    flags,
		    &ire_uinfo_null,
		    NULL,
		    NULL,
		    ipst);
		if (ire == NULL) {
			if (ipif_refheld)
				ipif_refrele(ipif);
			return (ENOMEM);
		}

		/*
		 * Some software (for example, GateD and Sun Cluster) attempts
		 * to create (what amount to) IRE_PREFIX routes with the
		 * loopback address as the gateway.  This is primarily done to
		 * set up prefixes with the RTF_REJECT flag set (for example,
		 * when generating aggregate routes). We also OR in the
		 * RTF_BLACKHOLE flag as these interface routes, by
		 * definition, can only be that.
		 *
		 * If the IRE type (as defined by ipif->ipif_net_type) is
		 * IRE_LOOPBACK, then we map the request into a
		 * IRE_IF_NORESOLVER.
		 *
		 * Needless to say, the real IRE_LOOPBACK is NOT created by this
		 * routine, but rather using ire_create_v6() directly.
		 */
		if (ipif->ipif_net_type == IRE_LOOPBACK) {
			ire->ire_type = IRE_IF_NORESOLVER;
			ire->ire_flags |= RTF_BLACKHOLE;
		}
		error = ire_add(&ire, q, mp, func, B_FALSE);
		if (error == 0)
			goto save_ire;
		/*
		 * In the result of failure, ire_add() will have already
		 * deleted the ire in question, so there is no need to
		 * do that here.
		 */
		if (ipif_refheld)
			ipif_refrele(ipif);
		return (error);
	}
	if (ipif_refheld) {
		ipif_refrele(ipif);
		ipif_refheld = B_FALSE;
	}

	/*
	 * Get an interface IRE for the specified gateway.
	 * If we don't have an IRE_IF_NORESOLVER or IRE_IF_RESOLVER for the
	 * gateway, it is currently unreachable and we fail the request
	 * accordingly.
	 */
	ipif = ipif_arg;
	if (ipif_arg != NULL)
		match_flags |= MATCH_IRE_ILL;
	gw_ire = ire_ftable_lookup_v6(gw_addr, 0, 0, IRE_INTERFACE, ipif_arg,
	    NULL, ALL_ZONES, 0, NULL, match_flags, ipst);
	if (gw_ire == NULL)
		return (ENETUNREACH);

	/*
	 * We create one of three types of IREs as a result of this request
	 * based on the netmask.  A netmask of all ones (which is automatically
	 * assumed when RTF_HOST is set) results in an IRE_HOST being created.
	 * An all zeroes netmask implies a default route so an IRE_DEFAULT is
	 * created.  Otherwise, an IRE_PREFIX route is created for the
	 * destination prefix.
	 */
	if (IN6_ARE_ADDR_EQUAL(mask, &ipv6_all_ones))
		type = IRE_HOST;
	else if (IN6_IS_ADDR_UNSPECIFIED(mask))
		type = IRE_DEFAULT;
	else
		type = IRE_PREFIX;

	/* check for a duplicate entry */
	ire = ire_ftable_lookup_v6(dst_addr, mask, gw_addr, type, ipif_arg,
	    NULL, ALL_ZONES, 0, NULL,
	    match_flags | MATCH_IRE_MASK | MATCH_IRE_GW, ipst);
	if (ire != NULL) {
		ire_refrele(gw_ire);
		ire_refrele(ire);
		return (EEXIST);
	}

	/* Security attribute exists */
	if (sp != NULL) {
		tsol_gcgrp_addr_t ga;

		/* find or create the gateway credentials group */
		ga.ga_af = AF_INET6;
		ga.ga_addr = *gw_addr;

		/* we hold reference to it upon success */
		gcgrp = gcgrp_lookup(&ga, B_TRUE);
		if (gcgrp == NULL) {
			ire_refrele(gw_ire);
			return (ENOMEM);
		}

		/*
		 * Create and add the security attribute to the group; a
		 * reference to the group is made upon allocating a new
		 * entry successfully.  If it finds an already-existing
		 * entry for the security attribute in the group, it simply
		 * returns it and no new reference is made to the group.
		 */
		gc = gc_create(sp, gcgrp, &gcgrp_xtraref);
		if (gc == NULL) {
			/* release reference held by gcgrp_lookup */
			GCGRP_REFRELE(gcgrp);
			ire_refrele(gw_ire);
			return (ENOMEM);
		}
	}

	/* Create the IRE. */
	ire = ire_create_v6(
	    dst_addr,				/* dest address */
	    mask,				/* mask */
	    /* src address assigned by the caller? */
	    (((flags & RTF_SETSRC) && !IN6_IS_ADDR_UNSPECIFIED(src_addr)) ?
	    src_addr : NULL),
	    gw_addr,				/* gateway address */
	    &gw_ire->ire_max_frag,
	    NULL,				/* no src nce */
	    NULL,				/* no recv-from queue */
	    NULL,				/* no send-to queue */
	    (ushort_t)type,			/* IRE type */
	    ipif_arg,
	    NULL,
	    0,
	    0,
	    flags,
	    &gw_ire->ire_uinfo,			/* Inherit ULP info from gw */
	    gc,					/* security attribute */
	    NULL,
	    ipst);

	/*
	 * The ire holds a reference to the 'gc' and the 'gc' holds a
	 * reference to the 'gcgrp'. We can now release the extra reference
	 * the 'gcgrp' acquired in the gcgrp_lookup, if it was not used.
	 */
	if (gcgrp_xtraref)
		GCGRP_REFRELE(gcgrp);
	if (ire == NULL) {
		if (gc != NULL)
			GC_REFRELE(gc);
		ire_refrele(gw_ire);
		return (ENOMEM);
	}

	/*
	 * POLICY: should we allow an RTF_HOST with address INADDR_ANY?
	 * SUN/OS socket stuff does but do we really want to allow ::0 ?
	 */

	/* Add the new IRE. */
	error = ire_add(&ire, q, mp, func, B_FALSE);
	/*
	 * In the result of failure, ire_add() will have already
	 * deleted the ire in question, so there is no need to
	 * do that here.
	 */
	if (error != 0) {
		ire_refrele(gw_ire);
		return (error);
	}

	if (flags & RTF_MULTIRT) {
		/*
		 * Invoke the CGTP (multirouting) filtering module
		 * to add the dst address in the filtering database.
		 * Replicated inbound packets coming from that address
		 * will be filtered to discard the duplicates.
		 * It is not necessary to call the CGTP filter hook
		 * when the dst address is a multicast, because an
		 * IP source address cannot be a multicast.
		 */
		if (ipst->ips_ip_cgtp_filter_ops != NULL &&
		    !IN6_IS_ADDR_MULTICAST(&(ire->ire_addr_v6))) {
			int res;

			res = ipst->ips_ip_cgtp_filter_ops->cfo_add_dest_v6(
			    ipst->ips_netstack->netstack_stackid,
			    &ire->ire_addr_v6,
			    &ire->ire_gateway_addr_v6,
			    &ire->ire_src_addr_v6,
			    &gw_ire->ire_src_addr_v6);
			if (res != 0) {
				ire_refrele(gw_ire);
				ire_delete(ire);
				return (res);
			}
		}
	}

	/*
	 * Now that the prefix IRE entry has been created, delete any
	 * existing gateway IRE cache entries as well as any IRE caches
	 * using the gateway, and force them to be created through
	 * ip_newroute_v6.
	 */
	if (gc != NULL) {
		ASSERT(gcgrp != NULL);
		ire_clookup_delete_cache_gw_v6(gw_addr, ALL_ZONES, ipst);
	}

save_ire:
	if (gw_ire != NULL) {
		ire_refrele(gw_ire);
	}
	if (ipif != NULL) {
		mblk_t	*save_mp;

		/*
		 * Save enough information so that we can recreate the IRE if
		 * the interface goes down and then up.  The metrics associated
		 * with the route will be saved as well when rts_setmetrics() is
		 * called after the IRE has been created.  In the case where
		 * memory cannot be allocated, none of this information will be
		 * saved.
		 */
		save_mp = allocb(sizeof (ifrt_t), BPRI_MED);
		if (save_mp != NULL) {
			ifrt_t	*ifrt;

			save_mp->b_wptr += sizeof (ifrt_t);
			ifrt = (ifrt_t *)save_mp->b_rptr;
			bzero(ifrt, sizeof (ifrt_t));
			ifrt->ifrt_type = ire->ire_type;
			ifrt->ifrt_v6addr = ire->ire_addr_v6;
			mutex_enter(&ire->ire_lock);
			ifrt->ifrt_v6gateway_addr = ire->ire_gateway_addr_v6;
			ifrt->ifrt_v6src_addr = ire->ire_src_addr_v6;
			mutex_exit(&ire->ire_lock);
			ifrt->ifrt_v6mask = ire->ire_mask_v6;
			ifrt->ifrt_flags = ire->ire_flags;
			ifrt->ifrt_max_frag = ire->ire_max_frag;
			mutex_enter(&ipif->ipif_saved_ire_lock);
			save_mp->b_cont = ipif->ipif_saved_ire_mp;
			ipif->ipif_saved_ire_mp = save_mp;
			ipif->ipif_saved_ire_cnt++;
			mutex_exit(&ipif->ipif_saved_ire_lock);
		}
	}
	if (ire_arg != NULL) {
		/*
		 * Store the ire that was successfully added into where ire_arg
		 * points to so that callers don't have to look it up
		 * themselves (but they are responsible for ire_refrele()ing
		 * the ire when they are finished with it).
		 */
		*ire_arg = ire;
	} else {
		ire_refrele(ire);		/* Held in ire_add */
	}
	if (ipif_refheld)
		ipif_refrele(ipif);
	return (0);
}

/*
 * ip_rt_delete_v6 is called to delete an IPv6 route.
 * ipif_arg is passed in to associate it with the correct interface
 * (for link-local destinations and gateways).
 */
/* ARGSUSED4 */
int
ip_rt_delete_v6(const in6_addr_t *dst_addr, const in6_addr_t *mask,
    const in6_addr_t *gw_addr, uint_t rtm_addrs, int flags, ipif_t *ipif_arg,
    queue_t *q, mblk_t *mp, ipsq_func_t func, ip_stack_t *ipst)
{
	ire_t	*ire = NULL;
	ipif_t	*ipif;
	uint_t	type;
	uint_t	match_flags = MATCH_IRE_TYPE;
	int	err = 0;
	boolean_t	ipif_refheld = B_FALSE;

	/*
	 * If this is the case of RTF_HOST being set, then we set the netmask
	 * to all ones.  Otherwise, we use the netmask if one was supplied.
	 */
	if (flags & RTF_HOST) {
		mask = &ipv6_all_ones;
		match_flags |= MATCH_IRE_MASK;
	} else if (rtm_addrs & RTA_NETMASK) {
		match_flags |= MATCH_IRE_MASK;
	}

	/*
	 * Note that RTF_GATEWAY is never set on a delete, therefore
	 * we check if the gateway address is one of our interfaces first,
	 * and fall back on RTF_GATEWAY routes.
	 *
	 * This makes it possible to delete an original
	 * IRE_IF_NORESOLVER/IRE_IF_RESOLVER - consistent with SunOS 4.1.
	 *
	 * As the interface index specified with the RTA_IFP sockaddr is the
	 * same for all ipif's off of an ill, the matching logic below uses
	 * MATCH_IRE_ILL if such an index was specified.  This means a route
	 * sharing the same prefix and interface index as the the route
	 * intended to be deleted might be deleted instead if a RTA_IFP sockaddr
	 * is specified in the request.
	 *
	 * On the other hand, since the gateway address will usually be
	 * different for each ipif on the system, the matching logic
	 * uses MATCH_IRE_IPIF in the case of a traditional interface
	 * route.  This means that interface routes for the same prefix can be
	 * uniquely identified if they belong to distinct ipif's and if a
	 * RTA_IFP sockaddr is not present.
	 *
	 * For more detail on specifying routes by gateway address and by
	 * interface index, see the comments in ip_rt_add_v6().
	 */
	ipif = ipif_lookup_interface_v6(gw_addr, dst_addr, q, mp, func, &err,
	    ipst);
	if (ipif != NULL) {
		ipif_refheld = B_TRUE;
		if (ipif_arg != NULL) {
			ipif_refrele(ipif);
			ipif_refheld = B_FALSE;
			ipif = ipif_arg;
			match_flags |= MATCH_IRE_ILL;
		} else {
			match_flags |= MATCH_IRE_IPIF;
		}

		if (ipif->ipif_ire_type == IRE_LOOPBACK)
			ire = ire_ctable_lookup_v6(dst_addr, 0, IRE_LOOPBACK,
			    ipif, ALL_ZONES, NULL, match_flags, ipst);
		if (ire == NULL)
			ire = ire_ftable_lookup_v6(dst_addr, mask, 0,
			    IRE_INTERFACE, ipif, NULL, ALL_ZONES, 0, NULL,
			    match_flags, ipst);
	} else if (err == EINPROGRESS) {
		return (err);
	} else {
		err = 0;
	}
	if (ire == NULL) {
		/*
		 * At this point, the gateway address is not one of our own
		 * addresses or a matching interface route was not found.  We
		 * set the IRE type to lookup based on whether
		 * this is a host route, a default route or just a prefix.
		 *
		 * If an ipif_arg was passed in, then the lookup is based on an
		 * interface index so MATCH_IRE_ILL is added to match_flags.
		 * In any case, MATCH_IRE_IPIF is cleared and MATCH_IRE_GW is
		 * set as the route being looked up is not a traditional
		 * interface route.
		 */
		match_flags &= ~MATCH_IRE_IPIF;
		match_flags |= MATCH_IRE_GW;
		if (ipif_arg != NULL)
			match_flags |= MATCH_IRE_ILL;
		if (IN6_ARE_ADDR_EQUAL(mask, &ipv6_all_ones))
			type = IRE_HOST;
		else if (IN6_IS_ADDR_UNSPECIFIED(mask))
			type = IRE_DEFAULT;
		else
			type = IRE_PREFIX;
		ire = ire_ftable_lookup_v6(dst_addr, mask, gw_addr, type,
		    ipif_arg, NULL, ALL_ZONES, 0, NULL, match_flags, ipst);
	}

	if (ipif_refheld) {
		ipif_refrele(ipif);
		ipif_refheld = B_FALSE;
	}
	if (ire == NULL)
		return (ESRCH);

	if (ire->ire_flags & RTF_MULTIRT) {
		/*
		 * Invoke the CGTP (multirouting) filtering module
		 * to remove the dst address from the filtering database.
		 * Packets coming from that address will no longer be
		 * filtered to remove duplicates.
		 */
		if (ipst->ips_ip_cgtp_filter_ops != NULL) {
			err = ipst->ips_ip_cgtp_filter_ops->cfo_del_dest_v6(
			    ipst->ips_netstack->netstack_stackid,
			    &ire->ire_addr_v6, &ire->ire_gateway_addr_v6);
		}
	}

	ipif = ire->ire_ipif;
	if (ipif != NULL) {
		mblk_t		**mpp;
		mblk_t		*mp;
		ifrt_t		*ifrt;
		in6_addr_t	gw_addr_v6;

		/* Remove from ipif_saved_ire_mp list if it is there */
		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
		mutex_enter(&ipif->ipif_saved_ire_lock);
		for (mpp = &ipif->ipif_saved_ire_mp; *mpp != NULL;
		    mpp = &(*mpp)->b_cont) {
			/*
			 * On a given ipif, the triple of address, gateway and
			 * mask is unique for each saved IRE (in the case of
			 * ordinary interface routes, the gateway address is
			 * all-zeroes).
			 */
			mp = *mpp;
			ifrt = (ifrt_t *)mp->b_rptr;
			if (IN6_ARE_ADDR_EQUAL(&ifrt->ifrt_v6addr,
			    &ire->ire_addr_v6) &&
			    IN6_ARE_ADDR_EQUAL(&ifrt->ifrt_v6gateway_addr,
			    &gw_addr_v6) &&
			    IN6_ARE_ADDR_EQUAL(&ifrt->ifrt_v6mask,
			    &ire->ire_mask_v6)) {
				*mpp = mp->b_cont;
				ipif->ipif_saved_ire_cnt--;
				freeb(mp);
				break;
			}
		}
		mutex_exit(&ipif->ipif_saved_ire_lock);
	}
	ire_delete(ire);
	ire_refrele(ire);
	return (err);
}

/*
 * Derive a token from the link layer address.
 */
boolean_t
ill_setdefaulttoken(ill_t *ill)
{
	int		i;
	in6_addr_t	v6addr, v6mask;

	if (!MEDIA_V6INTFID(ill->ill_media, ill, &v6addr))
		return (B_FALSE);

	(void) ip_plen_to_mask_v6(IPV6_TOKEN_LEN, &v6mask);

	for (i = 0; i < 4; i++)
		v6mask.s6_addr32[i] = v6mask.s6_addr32[i] ^
		    (uint32_t)0xffffffff;

	V6_MASK_COPY(v6addr, v6mask, ill->ill_token);
	ill->ill_token_length = IPV6_TOKEN_LEN;
	return (B_TRUE);
}

/*
 * Create a link-local address from a token.
 */
static void
ipif_get_linklocal(in6_addr_t *dest, const in6_addr_t *token)
{
	int i;

	for (i = 0; i < 4; i++) {
		dest->s6_addr32[i] =
		    token->s6_addr32[i] | ipv6_ll_template.s6_addr32[i];
	}
}

/*
 * Set a nice default address for either automatic tunnels tsrc/96 or
 * 6to4 tunnels 2002:<tsrc>::1/64
 */
static void
ipif_set_tun_auto_addr(ipif_t *ipif, struct iftun_req *ta)
{
	sin6_t	sin6;
	sin_t	*sin;
	ill_t	*ill = ipif->ipif_ill;
	tun_t *tp = (tun_t *)ill->ill_wq->q_next->q_ptr;

	if (ta->ifta_saddr.ss_family != AF_INET ||
	    (ipif->ipif_flags & IPIF_UP) || !ipif->ipif_isv6 ||
	    (ta->ifta_flags & IFTUN_SRC) == 0)
		return;

	/*
	 * Check the tunnel type by examining q_next->q_ptr
	 */
	if (tp->tun_flags & TUN_AUTOMATIC) {
		/* this is an automatic tunnel */
		(void) ip_plen_to_mask_v6(IPV6_ABITS - IP_ABITS,
		    &ipif->ipif_v6net_mask);
		bzero(&sin6, sizeof (sin6_t));
		sin = (sin_t *)&ta->ifta_saddr;
		V4_PART_OF_V6(sin6.sin6_addr) = sin->sin_addr.s_addr;
		sin6.sin6_family = AF_INET6;
		(void) ip_sioctl_addr(ipif, (sin_t *)&sin6,
		    NULL, NULL, NULL, NULL);
	} else if (tp->tun_flags & TUN_6TO4) {
		/* this is a 6to4 tunnel */
		(void) ip_plen_to_mask_v6(IPV6_PREFIX_LEN,
		    &ipif->ipif_v6net_mask);
		sin = (sin_t *)&ta->ifta_saddr;
		/* create a 6to4 address from the IPv4 tsrc */
		IN6_V4ADDR_TO_6TO4(&sin->sin_addr, &sin6.sin6_addr);
		sin6.sin6_family = AF_INET6;
		(void) ip_sioctl_addr(ipif, (sin_t *)&sin6,
		    NULL, NULL, NULL, NULL);
	} else {
		ip1dbg(("ipif_set_tun_auto_addr: Unknown tunnel type"));
		return;
	}
}

/*
 * Set link local for ipif_id 0 of a configured tunnel based on the
 * tsrc or tdst parameter
 * For tunnels over IPv4 use the IPv4 address prepended with 32 zeros as
 * the token.
 * For tunnels over IPv6 use the low-order 64 bits of the "inner" IPv6 address
 * as the token for the "outer" link.
 */
void
ipif_set_tun_llink(ill_t *ill, struct iftun_req *ta)
{
	ipif_t		*ipif;
	sin_t		*sin;
	in6_addr_t	*s6addr;

	ASSERT(IAM_WRITER_ILL(ill));

	/* The first ipif must be id zero. */
	ipif = ill->ill_ipif;
	ASSERT(ipif->ipif_id == 0);

	/* no link local for automatic tunnels */
	if (!(ipif->ipif_flags & IPIF_POINTOPOINT)) {
		ipif_set_tun_auto_addr(ipif, ta);
		return;
	}

	if ((ta->ifta_flags & IFTUN_DST) &&
	    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6pp_dst_addr)) {
		sin6_t  sin6;

		ASSERT(!(ipif->ipif_flags & IPIF_UP));
		bzero(&sin6, sizeof (sin6_t));
		if ((ta->ifta_saddr.ss_family == AF_INET)) {
			sin = (sin_t *)&ta->ifta_daddr;
			V4_PART_OF_V6(sin6.sin6_addr) =
			    sin->sin_addr.s_addr;
		} else {
			s6addr =
			    &((sin6_t *)&ta->ifta_daddr)->sin6_addr;
			sin6.sin6_addr.s6_addr32[3] = s6addr->s6_addr32[3];
			sin6.sin6_addr.s6_addr32[2] = s6addr->s6_addr32[2];
		}
		ipif_get_linklocal(&ipif->ipif_v6pp_dst_addr,
		    &sin6.sin6_addr);
		ipif->ipif_v6subnet = ipif->ipif_v6pp_dst_addr;
	}
	if ((ta->ifta_flags & IFTUN_SRC)) {
		ASSERT(!(ipif->ipif_flags & IPIF_UP));

		/* Set the token if it isn't already set */
		if (IN6_IS_ADDR_UNSPECIFIED(&ill->ill_token)) {
			if ((ta->ifta_saddr.ss_family == AF_INET)) {
				sin = (sin_t *)&ta->ifta_saddr;
				V4_PART_OF_V6(ill->ill_token) =
				    sin->sin_addr.s_addr;
			} else {
				s6addr =
				    &((sin6_t *)&ta->ifta_saddr)->sin6_addr;
				ill->ill_token.s6_addr32[3] =
				    s6addr->s6_addr32[3];
				ill->ill_token.s6_addr32[2] =
				    s6addr->s6_addr32[2];
			}
			ill->ill_token_length = IPV6_TOKEN_LEN;
		}
		/*
		 * Attempt to set the link local address if it isn't set.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr))
			(void) ipif_setlinklocal(ipif);
	}
}

/*
 * Is it not possible to set the link local address?
 * The address can be set if the token is set, and the token
 * isn't too long.
 * Return B_TRUE if the address can't be set, or B_FALSE if it can.
 */
boolean_t
ipif_cant_setlinklocal(ipif_t *ipif)
{
	ill_t *ill = ipif->ipif_ill;

	if (IN6_IS_ADDR_UNSPECIFIED(&ill->ill_token) ||
	    ill->ill_token_length > IPV6_ABITS - IPV6_LL_PREFIXLEN)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Generate a link-local address from the token.
 * Return zero if the address was set, or non-zero if it couldn't be set.
 */
int
ipif_setlinklocal(ipif_t *ipif)
{
	ill_t		*ill = ipif->ipif_ill;
	in6_addr_t	ov6addr;

	ASSERT(IAM_WRITER_ILL(ill));

	if (ipif_cant_setlinklocal(ipif))
		return (-1);

	ov6addr = ipif->ipif_v6lcl_addr;
	ipif_get_linklocal(&ipif->ipif_v6lcl_addr, &ill->ill_token);
	sctp_update_ipif_addr(ipif, ov6addr);
	(void) ip_plen_to_mask_v6(IPV6_LL_PREFIXLEN, &ipif->ipif_v6net_mask);
	V6_MASK_COPY(ipif->ipif_v6lcl_addr, ipif->ipif_v6net_mask,
	    ipif->ipif_v6subnet);

	if (ipif->ipif_flags & IPIF_NOLOCAL) {
		ipif->ipif_v6src_addr = ipv6_all_zeros;
	} else {
		ipif->ipif_v6src_addr = ipif->ipif_v6lcl_addr;
	}
	return (0);
}

/*
 * This function sets up the multicast mappings in NDP.
 * Unlike ARP, there are no mapping_mps here. We delete the
 * mapping nces and add a new one.
 *
 * Returns non-zero on error and 0 on success.
 */
int
ipif_ndp_setup_multicast(ipif_t *ipif, nce_t **ret_nce)
{
	ill_t		*ill = ipif->ipif_ill;
	in6_addr_t	v6_mcast_addr = {(uint32_t)V6_MCAST, 0, 0, 0};
	in6_addr_t	v6_mcast_mask = {(uint32_t)V6_MCAST, 0, 0, 0};
	in6_addr_t	v6_extract_mask;
	uchar_t		*phys_addr, *bphys_addr, *alloc_phys;
	nce_t		*mnce = NULL;
	int		err = 0;
	phyint_t	*phyi = ill->ill_phyint;
	uint32_t	hw_extract_start;
	dl_unitdata_req_t *dlur;
	ip_stack_t	*ipst = ill->ill_ipst;

	if (ret_nce != NULL)
		*ret_nce = NULL;

	/*
	 * IPMP meta-interfaces don't have any inherent multicast mappings,
	 * and instead use the ones on the underlying interfaces.
	 */
	if (IS_IPMP(ill))
		return (0);

	/*
	 * Delete the mapping nce. Normally these should not exist
	 * as a previous ipif_down -> ipif_ndp_down should have deleted
	 * all the nces. But they can exist if ip_rput_dlpi_writer
	 * calls this when PHYI_MULTI_BCAST is set.  Mappings are always
	 * tied to the underlying ill, so don't match across the illgrp.
	 */
	mnce = ndp_lookup_v6(ill, B_FALSE, &v6_mcast_addr, B_FALSE);
	if (mnce != NULL) {
		ndp_delete(mnce);
		NCE_REFRELE(mnce);
		mnce = NULL;
	}

	/*
	 * Get media specific v6 mapping information. Note that
	 * nd_lla_len can be 0 for tunnels.
	 */
	alloc_phys = kmem_alloc(ill->ill_nd_lla_len, KM_NOSLEEP);
	if ((alloc_phys == NULL) && (ill->ill_nd_lla_len != 0))
		return (ENOMEM);
	/*
	 * Determine the broadcast address.
	 */
	dlur = (dl_unitdata_req_t *)ill->ill_bcast_mp->b_rptr;
	if (ill->ill_sap_length < 0)
		bphys_addr = (uchar_t *)dlur + dlur->dl_dest_addr_offset;
	else
		bphys_addr = (uchar_t *)dlur +
		    dlur->dl_dest_addr_offset + ill->ill_sap_length;

	/*
	 * Check PHYI_MULTI_BCAST and possible length of physical
	 * address to determine if we use the mapping or the
	 * broadcast address.
	 */
	if ((phyi->phyint_flags & PHYI_MULTI_BCAST) ||
	    (!MEDIA_V6MINFO(ill->ill_media, ill->ill_nd_lla_len,
	    bphys_addr, alloc_phys, &hw_extract_start,
	    &v6_extract_mask))) {
		if (ill->ill_phys_addr_length > IP_MAX_HW_LEN) {
			kmem_free(alloc_phys, ill->ill_nd_lla_len);
			return (E2BIG);
		}
		/* Use the link-layer broadcast address for MULTI_BCAST */
		phys_addr = bphys_addr;
		bzero(&v6_extract_mask, sizeof (v6_extract_mask));
		hw_extract_start = ill->ill_nd_lla_len;
	} else {
		phys_addr = alloc_phys;
	}
	if ((ipif->ipif_flags & IPIF_BROADCAST) ||
	    (ill->ill_flags & ILLF_MULTICAST) ||
	    (phyi->phyint_flags & PHYI_MULTI_BCAST)) {
		mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
		err = ndp_add_v6(ill,
		    phys_addr,
		    &v6_mcast_addr,	/* v6 address */
		    &v6_mcast_mask,	/* v6 mask */
		    &v6_extract_mask,
		    hw_extract_start,
		    NCE_F_MAPPING | NCE_F_PERMANENT | NCE_F_NONUD,
		    ND_REACHABLE,
		    &mnce);
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		if (err == 0) {
			if (ret_nce != NULL) {
				*ret_nce = mnce;
			} else {
				NCE_REFRELE(mnce);
			}
		}
	}
	kmem_free(alloc_phys, ill->ill_nd_lla_len);
	return (err);
}

/*
 * Get the resolver set up for a new ipif.  (Always called as writer.)
 */
int
ipif_ndp_up(ipif_t *ipif, boolean_t initial)
{
	ill_t		*ill = ipif->ipif_ill;
	int		err = 0;
	nce_t		*nce = NULL;
	nce_t		*mnce = NULL;
	boolean_t	added_ipif = B_FALSE;

	ASSERT(IAM_WRITER_ILL(ill));
	ip1dbg(("ipif_ndp_up(%s:%u)\n", ill->ill_name, ipif->ipif_id));

	/*
	 * ND not supported on XRESOLV interfaces. If ND support (multicast)
	 * added later, take out this check.
	 */
	if ((ill->ill_flags & ILLF_XRESOLV) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr) ||
	    (!(ill->ill_net_type & IRE_INTERFACE))) {
		ipif->ipif_addr_ready = 1;
		return (0);
	}

	/*
	 * Need to setup multicast mapping only when the first
	 * interface is coming UP.
	 */
	if (ill->ill_ipif_up_count == 0 &&
	    (ill->ill_flags & ILLF_MULTICAST)) {
		/*
		 * We set the multicast before setting up the mapping for
		 * local address because ipif_ndp_setup_multicast does
		 * ndp_walk to delete nces which will delete the mapping
		 * for local address also if we added the mapping for
		 * local address first.
		 */
		err = ipif_ndp_setup_multicast(ipif, &mnce);
		if (err != 0)
			return (err);
	}

	if ((ipif->ipif_flags & (IPIF_UNNUMBERED|IPIF_NOLOCAL)) == 0) {
		uint16_t	flags;
		uint16_t	state;
		uchar_t		*hw_addr = NULL;
		ill_t		*bound_ill;
		ipmp_illgrp_t	*illg = ill->ill_grp;

		/* Permanent entries don't need NUD */
		flags = NCE_F_PERMANENT | NCE_F_NONUD;
		if (ill->ill_flags & ILLF_ROUTER)
			flags |= NCE_F_ISROUTER;

		if (ipif->ipif_flags & IPIF_ANYCAST)
			flags |= NCE_F_ANYCAST;

		if (IS_IPMP(ill)) {
			ASSERT(ill->ill_net_type == IRE_IF_RESOLVER);
			/*
			 * If we're here via ipif_up(), then the ipif won't be
			 * bound yet -- add it to the group, which will bind
			 * it if possible.  (We would add it in ipif_up(), but
			 * deleting on failure there is gruesome.)  If we're
			 * here via ipmp_ill_bind_ipif(), then the ipif has
			 * already been added to the group and we just need to
			 * use the binding.
			 */
			if ((bound_ill = ipmp_ipif_bound_ill(ipif)) == NULL) {
				bound_ill = ipmp_illgrp_add_ipif(illg, ipif);
				if (bound_ill == NULL) {
					/*
					 * We couldn't bind the ipif to an ill
					 * yet, so we have nothing to publish.
					 * Set ipif_addr_ready so that this
					 * address can be used locally for now.
					 * The routing socket message will be
					 * sent from ipif_up_done_v6().
					 */
					ipif->ipif_addr_ready = 1;
					return (0);
				}
				added_ipif = B_TRUE;
			}
			hw_addr = bound_ill->ill_nd_lla;
		} else {
			bound_ill = ill;
			if (ill->ill_net_type == IRE_IF_RESOLVER)
				hw_addr = ill->ill_nd_lla;
		}

		/*
		 * If this is an initial bring-up (or the ipif was never
		 * completely brought up), do DAD.  Otherwise, we're here
		 * because IPMP has rebound an address to this ill: send
		 * unsolicited advertisements to inform others.
		 */
		if (initial || !ipif->ipif_addr_ready) {
			state = ND_PROBE;
		} else {
			state = ND_REACHABLE;
			flags |= NCE_F_UNSOL_ADV;
		}
		/*
		 * NOTE: for IPMP, local addresses are always associated with
		 * the ill they're bound to, so don't match across the illgrp.
		 */
		err = ndp_lookup_then_add_v6(bound_ill,
		    B_FALSE,
		    hw_addr,
		    &ipif->ipif_v6lcl_addr,
		    &ipv6_all_ones,
		    &ipv6_all_zeros,
		    0,
		    flags,
		    state,
		    &nce);
		switch (err) {
		case 0:
			ip1dbg(("ipif_ndp_up: NCE created for %s\n",
			    ill->ill_name));
			ipif->ipif_addr_ready = 1;
			break;
		case EINPROGRESS:
			ip1dbg(("ipif_ndp_up: running DAD now for %s\n",
			    ill->ill_name));
			break;
		case EEXIST:
			NCE_REFRELE(nce);
			ip1dbg(("ipif_ndp_up: NCE already exists for %s\n",
			    ill->ill_name));
			goto fail;
		default:
			ip1dbg(("ipif_ndp_up: NCE creation failed for %s\n",
			    ill->ill_name));
			goto fail;
		}
	} else {
		/* No local NCE for this entry */
		ipif->ipif_addr_ready = 1;
	}
	if (nce != NULL)
		NCE_REFRELE(nce);
	if (mnce != NULL)
		NCE_REFRELE(mnce);
	return (0);
fail:
	if (mnce != NULL) {
		ndp_delete(mnce);
		NCE_REFRELE(mnce);
	}
	if (added_ipif)
		ipmp_illgrp_del_ipif(ill->ill_grp, ipif);

	return (err);
}

/* Remove all cache entries for this logical interface */
void
ipif_ndp_down(ipif_t *ipif)
{
	nce_t	*nce;
	ill_t	*ill = ipif->ipif_ill;

	ASSERT(IAM_WRITER_ILL(ill));

	if (ipif->ipif_isv6) {
		ill_t *bound_ill;

		if (IS_IPMP(ill))
			bound_ill = ipmp_ipif_bound_ill(ipif);
		else
			bound_ill = ill;

		if (bound_ill != NULL) {
			nce = ndp_lookup_v6(bound_ill,
			    B_FALSE,	/* see comment in ipif_ndp_up() */
			    &ipif->ipif_v6lcl_addr,
			    B_FALSE);
			if (nce != NULL) {
				ndp_delete(nce);
				NCE_REFRELE(nce);
			}
		}

		/*
		 * Make IPMP aware of the deleted data address.
		 */
		if (IS_IPMP(ill))
			ipmp_illgrp_del_ipif(ill->ill_grp, ipif);
	}

	/*
	 * Remove mapping and all other nces dependent on this ill
	 * when the last ipif is going away.
	 */
	if (ill->ill_ipif_up_count == 0)
		ndp_walk(ill, (pfi_t)ndp_delete_per_ill, ill, ill->ill_ipst);
}

/*
 * Used when an interface comes up to recreate any extra routes on this
 * interface.
 */
static ire_t **
ipif_recover_ire_v6(ipif_t *ipif)
{
	mblk_t	*mp;
	ire_t   **ipif_saved_irep;
	ire_t   **irep;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ip1dbg(("ipif_recover_ire_v6(%s:%u)", ipif->ipif_ill->ill_name,
	    ipif->ipif_id));

	ASSERT(ipif->ipif_isv6);

	mutex_enter(&ipif->ipif_saved_ire_lock);
	ipif_saved_irep = (ire_t **)kmem_zalloc(sizeof (ire_t *) *
	    ipif->ipif_saved_ire_cnt, KM_NOSLEEP);
	if (ipif_saved_irep == NULL) {
		mutex_exit(&ipif->ipif_saved_ire_lock);
		return (NULL);
	}

	irep = ipif_saved_irep;

	for (mp = ipif->ipif_saved_ire_mp; mp != NULL; mp = mp->b_cont) {
		ire_t		*ire;
		queue_t		*rfq;
		queue_t		*stq;
		ifrt_t		*ifrt;
		in6_addr_t	*src_addr;
		in6_addr_t	*gateway_addr;
		char		buf[INET6_ADDRSTRLEN];
		ushort_t	type;

		/*
		 * When the ire was initially created and then added in
		 * ip_rt_add_v6(), it was created either using
		 * ipif->ipif_net_type in the case of a traditional interface
		 * route, or as one of the IRE_OFFSUBNET types (with the
		 * exception of IRE_HOST type redirect ire which is created by
		 * icmp_redirect_v6() and which we don't need to save or
		 * recover).  In the case where ipif->ipif_net_type was
		 * IRE_LOOPBACK, ip_rt_add_v6() will update the ire_type to
		 * IRE_IF_NORESOLVER before calling ire_add_v6() to satisfy
		 * software like GateD and Sun Cluster which creates routes
		 * using the the loopback interface's address as a gateway.
		 *
		 * As ifrt->ifrt_type reflects the already updated ire_type,
		 * ire_create_v6() will be called in the same way here as in
		 * ip_rt_add_v6(), namely using ipif->ipif_net_type when the
		 * route looks like a traditional interface route (where
		 * ifrt->ifrt_type & IRE_INTERFACE is true) and otherwise
		 * using the saved ifrt->ifrt_type.  This means that in
		 * the case where ipif->ipif_net_type is IRE_LOOPBACK,
		 * the ire created by ire_create_v6() will be an IRE_LOOPBACK,
		 * it will then be turned into an IRE_IF_NORESOLVER and then
		 * added by ire_add_v6().
		 */
		ifrt = (ifrt_t *)mp->b_rptr;
		if (ifrt->ifrt_type & IRE_INTERFACE) {
			rfq = NULL;
			stq = (ipif->ipif_net_type == IRE_IF_RESOLVER)
			    ? ipif->ipif_rq : ipif->ipif_wq;
			src_addr = (ifrt->ifrt_flags & RTF_SETSRC)
			    ? &ifrt->ifrt_v6src_addr
			    : &ipif->ipif_v6src_addr;
			gateway_addr = NULL;
			type = ipif->ipif_net_type;
		} else {
			rfq = NULL;
			stq = NULL;
			src_addr = (ifrt->ifrt_flags & RTF_SETSRC)
			    ? &ifrt->ifrt_v6src_addr : NULL;
			gateway_addr = &ifrt->ifrt_v6gateway_addr;
			type = ifrt->ifrt_type;
		}

		/*
		 * Create a copy of the IRE with the saved address and netmask.
		 */
		ip1dbg(("ipif_recover_ire_v6: creating IRE %s (%d) for %s/%d\n",
		    ip_nv_lookup(ire_nv_tbl, ifrt->ifrt_type), ifrt->ifrt_type,
		    inet_ntop(AF_INET6, &ifrt->ifrt_v6addr, buf, sizeof (buf)),
		    ip_mask_to_plen_v6(&ifrt->ifrt_v6mask)));
		ire = ire_create_v6(
		    &ifrt->ifrt_v6addr,
		    &ifrt->ifrt_v6mask,
		    src_addr,
		    gateway_addr,
		    &ifrt->ifrt_max_frag,
		    NULL,
		    rfq,
		    stq,
		    type,
		    ipif,
		    NULL,
		    0,
		    0,
		    ifrt->ifrt_flags,
		    &ifrt->ifrt_iulp_info,
		    NULL,
		    NULL,
		    ipst);
		if (ire == NULL) {
			mutex_exit(&ipif->ipif_saved_ire_lock);
			kmem_free(ipif_saved_irep,
			    ipif->ipif_saved_ire_cnt * sizeof (ire_t *));
			return (NULL);
		}

		/*
		 * Some software (for example, GateD and Sun Cluster) attempts
		 * to create (what amount to) IRE_PREFIX routes with the
		 * loopback address as the gateway.  This is primarily done to
		 * set up prefixes with the RTF_REJECT flag set (for example,
		 * when generating aggregate routes.)
		 *
		 * If the IRE type (as defined by ipif->ipif_net_type) is
		 * IRE_LOOPBACK, then we map the request into a
		 * IRE_IF_NORESOLVER.
		 */
		if (ipif->ipif_net_type == IRE_LOOPBACK)
			ire->ire_type = IRE_IF_NORESOLVER;
		/*
		 * ire held by ire_add, will be refreled' in ipif_up_done
		 * towards the end
		 */
		(void) ire_add(&ire, NULL, NULL, NULL, B_FALSE);
		*irep = ire;
		irep++;
		ip1dbg(("ipif_recover_ire_v6: added ire %p\n", (void *)ire));
	}
	mutex_exit(&ipif->ipif_saved_ire_lock);
	return (ipif_saved_irep);
}

/*
 * Return the scope of the given IPv6 address.  If the address is an
 * IPv4 mapped IPv6 address, return the scope of the corresponding
 * IPv4 address.
 */
in6addr_scope_t
ip_addr_scope_v6(const in6_addr_t *addr)
{
	static in6_addr_t ipv6loopback = IN6ADDR_LOOPBACK_INIT;

	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		in_addr_t v4addr_h = ntohl(V4_PART_OF_V6((*addr)));
		if ((v4addr_h >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
		    (v4addr_h & IN_AUTOCONF_MASK) == IN_AUTOCONF_NET)
			return (IP6_SCOPE_LINKLOCAL);
		if ((v4addr_h & IN_PRIVATE8_MASK) == IN_PRIVATE8_NET ||
		    (v4addr_h & IN_PRIVATE12_MASK) == IN_PRIVATE12_NET ||
		    (v4addr_h & IN_PRIVATE16_MASK) == IN_PRIVATE16_NET)
			return (IP6_SCOPE_SITELOCAL);
		return (IP6_SCOPE_GLOBAL);
	}

	if (IN6_IS_ADDR_MULTICAST(addr))
		return (IN6_ADDR_MC_SCOPE(addr));

	/* link-local and loopback addresses are of link-local scope */
	if (IN6_IS_ADDR_LINKLOCAL(addr) ||
	    IN6_ARE_ADDR_EQUAL(addr, &ipv6loopback))
		return (IP6_SCOPE_LINKLOCAL);
	if (IN6_IS_ADDR_SITELOCAL(addr))
		return (IP6_SCOPE_SITELOCAL);
	return (IP6_SCOPE_GLOBAL);
}


/*
 * Returns the length of the common prefix of a1 and a2, as per
 * CommonPrefixLen() defined in RFC 3484.
 */
static int
ip_common_prefix_v6(const in6_addr_t *a1, const in6_addr_t *a2)
{
	int i;
	uint32_t a1val, a2val, mask;

	for (i = 0; i < 4; i++) {
		if ((a1val = a1->s6_addr32[i]) != (a2val = a2->s6_addr32[i])) {
			a1val ^= a2val;
			i *= 32;
			mask = 0x80000000u;
			while (!(a1val & mask)) {
				mask >>= 1;
				i++;
			}
			return (i);
		}
	}
	return (IPV6_ABITS);
}

#define	IPIF_VALID_IPV6_SOURCE(ipif) \
	(((ipif)->ipif_flags & IPIF_UP) && \
	!((ipif)->ipif_flags & (IPIF_NOLOCAL|IPIF_ANYCAST)) && \
	(ipif)->ipif_addr_ready)

/* source address candidate */
typedef struct candidate {
	ipif_t		*cand_ipif;
	/* The properties of this candidate */
	boolean_t	cand_isdst;
	boolean_t	cand_isdst_set;
	in6addr_scope_t	cand_scope;
	boolean_t	cand_scope_set;
	boolean_t	cand_isdeprecated;
	boolean_t	cand_isdeprecated_set;
	boolean_t	cand_ispreferred;
	boolean_t	cand_ispreferred_set;
	boolean_t	cand_matchedinterface;
	boolean_t	cand_matchedinterface_set;
	boolean_t	cand_matchedlabel;
	boolean_t	cand_matchedlabel_set;
	boolean_t	cand_istmp;
	boolean_t	cand_istmp_set;
	int		cand_common_pref;
	boolean_t	cand_common_pref_set;
	boolean_t	cand_pref_eq;
	boolean_t	cand_pref_eq_set;
	int		cand_pref_len;
	boolean_t	cand_pref_len_set;
} cand_t;
#define	cand_srcaddr	cand_ipif->ipif_v6lcl_addr
#define	cand_mask	cand_ipif->ipif_v6net_mask
#define	cand_flags	cand_ipif->ipif_flags
#define	cand_ill	cand_ipif->ipif_ill
#define	cand_zoneid	cand_ipif->ipif_zoneid

/* information about the destination for source address selection */
typedef struct dstinfo {
	const in6_addr_t	*dst_addr;
	ill_t			*dst_ill;
	uint_t			dst_restrict_ill;
	boolean_t		dst_prefer_src_tmp;
	in6addr_scope_t		dst_scope;
	char			*dst_label;
} dstinfo_t;

/*
 * The following functions are rules used to select a source address in
 * ipif_select_source_v6().  Each rule compares a current candidate (cc)
 * against the best candidate (bc).  Each rule has three possible outcomes;
 * the candidate is preferred over the best candidate (CAND_PREFER), the
 * candidate is not preferred over the best candidate (CAND_AVOID), or the
 * candidate is of equal value as the best candidate (CAND_TIE).
 *
 * These rules are part of a greater "Default Address Selection for IPv6"
 * sheme, which is standards based work coming out of the IETF ipv6 working
 * group.  The IETF document defines both IPv6 source address selection and
 * destination address ordering.  The rules defined here implement the IPv6
 * source address selection.  Destination address ordering is done by
 * libnsl, and uses a similar set of rules to implement the sorting.
 *
 * Most of the rules are defined by the RFC and are not typically altered.  The
 * last rule, number 8, has language that allows for local preferences.  In the
 * scheme below, this means that new Solaris rules should normally go between
 * rule_ifprefix and rule_prefix.
 */
typedef enum {CAND_AVOID, CAND_TIE, CAND_PREFER} rule_res_t;
typedef	rule_res_t (*rulef_t)(cand_t *, cand_t *, const dstinfo_t *,
    ip_stack_t *);

/* Prefer an address if it is equal to the destination address. */
/* ARGSUSED3 */
static rule_res_t
rule_isdst(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo, ip_stack_t *ipst)
{
	if (!bc->cand_isdst_set) {
		bc->cand_isdst =
		    IN6_ARE_ADDR_EQUAL(&bc->cand_srcaddr, dstinfo->dst_addr);
		bc->cand_isdst_set = B_TRUE;
	}

	cc->cand_isdst =
	    IN6_ARE_ADDR_EQUAL(&cc->cand_srcaddr, dstinfo->dst_addr);
	cc->cand_isdst_set = B_TRUE;

	if (cc->cand_isdst == bc->cand_isdst)
		return (CAND_TIE);
	else if (cc->cand_isdst)
		return (CAND_PREFER);
	else
		return (CAND_AVOID);
}

/*
 * Prefer addresses that are of closest scope to the destination.  Always
 * prefer addresses that are of greater scope than the destination over
 * those that are of lesser scope than the destination.
 */
/* ARGSUSED3 */
static rule_res_t
rule_scope(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo, ip_stack_t *ipst)
{
	if (!bc->cand_scope_set) {
		bc->cand_scope = ip_addr_scope_v6(&bc->cand_srcaddr);
		bc->cand_scope_set = B_TRUE;
	}

	cc->cand_scope = ip_addr_scope_v6(&cc->cand_srcaddr);
	cc->cand_scope_set = B_TRUE;

	if (cc->cand_scope < bc->cand_scope) {
		if (cc->cand_scope < dstinfo->dst_scope)
			return (CAND_AVOID);
		else
			return (CAND_PREFER);
	} else if (bc->cand_scope < cc->cand_scope) {
		if (bc->cand_scope < dstinfo->dst_scope)
			return (CAND_PREFER);
		else
			return (CAND_AVOID);
	} else {
		return (CAND_TIE);
	}
}

/*
 * Prefer non-deprecated source addresses.
 */
/* ARGSUSED2 */
static rule_res_t
rule_deprecated(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo,
    ip_stack_t *ipst)
{
	if (!bc->cand_isdeprecated_set) {
		bc->cand_isdeprecated =
		    ((bc->cand_flags & IPIF_DEPRECATED) != 0);
		bc->cand_isdeprecated_set = B_TRUE;
	}

	cc->cand_isdeprecated = ((cc->cand_flags & IPIF_DEPRECATED) != 0);
	cc->cand_isdeprecated_set = B_TRUE;

	if (bc->cand_isdeprecated == cc->cand_isdeprecated)
		return (CAND_TIE);
	else if (cc->cand_isdeprecated)
		return (CAND_AVOID);
	else
		return (CAND_PREFER);
}

/*
 * Prefer source addresses that have the IPIF_PREFERRED flag set.  This
 * rule must be before rule_interface because the flag could be set on any
 * interface, not just the interface being used for outgoing packets (for
 * example, the IFF_PREFERRED could be set on an address assigned to the
 * loopback interface).
 */
/* ARGSUSED2 */
static rule_res_t
rule_preferred(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo,
    ip_stack_t *ipst)
{
	if (!bc->cand_ispreferred_set) {
		bc->cand_ispreferred = ((bc->cand_flags & IPIF_PREFERRED) != 0);
		bc->cand_ispreferred_set = B_TRUE;
	}

	cc->cand_ispreferred = ((cc->cand_flags & IPIF_PREFERRED) != 0);
	cc->cand_ispreferred_set = B_TRUE;

	if (bc->cand_ispreferred == cc->cand_ispreferred)
		return (CAND_TIE);
	else if (cc->cand_ispreferred)
		return (CAND_PREFER);
	else
		return (CAND_AVOID);
}

/*
 * Prefer source addresses that are assigned to the outgoing interface.
 */
/* ARGSUSED3 */
static rule_res_t
rule_interface(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo,
    ip_stack_t *ipst)
{
	ill_t *dstill = dstinfo->dst_ill;

	/*
	 * If dstinfo->dst_restrict_ill is set, this rule is unnecessary
	 * since we know all candidates will be on the same link.
	 */
	if (dstinfo->dst_restrict_ill)
		return (CAND_TIE);

	if (!bc->cand_matchedinterface_set) {
		bc->cand_matchedinterface = bc->cand_ill == dstill;
		bc->cand_matchedinterface_set = B_TRUE;
	}

	cc->cand_matchedinterface = cc->cand_ill == dstill;
	cc->cand_matchedinterface_set = B_TRUE;

	if (bc->cand_matchedinterface == cc->cand_matchedinterface)
		return (CAND_TIE);
	else if (cc->cand_matchedinterface)
		return (CAND_PREFER);
	else
		return (CAND_AVOID);
}

/*
 * Prefer source addresses whose label matches the destination's label.
 */
static rule_res_t
rule_label(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo, ip_stack_t *ipst)
{
	char *label;

	if (!bc->cand_matchedlabel_set) {
		label = ip6_asp_lookup(&bc->cand_srcaddr, NULL, ipst);
		bc->cand_matchedlabel =
		    ip6_asp_labelcmp(label, dstinfo->dst_label);
		bc->cand_matchedlabel_set = B_TRUE;
	}

	label = ip6_asp_lookup(&cc->cand_srcaddr, NULL, ipst);
	cc->cand_matchedlabel = ip6_asp_labelcmp(label, dstinfo->dst_label);
	cc->cand_matchedlabel_set = B_TRUE;

	if (bc->cand_matchedlabel == cc->cand_matchedlabel)
		return (CAND_TIE);
	else if (cc->cand_matchedlabel)
		return (CAND_PREFER);
	else
		return (CAND_AVOID);
}

/*
 * Prefer public addresses over temporary ones.  An application can reverse
 * the logic of this rule and prefer temporary addresses by using the
 * IPV6_SRC_PREFERENCES socket option.
 */
/* ARGSUSED3 */
static rule_res_t
rule_temporary(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo,
    ip_stack_t *ipst)
{
	if (!bc->cand_istmp_set) {
		bc->cand_istmp = ((bc->cand_flags & IPIF_TEMPORARY) != 0);
		bc->cand_istmp_set = B_TRUE;
	}

	cc->cand_istmp = ((cc->cand_flags & IPIF_TEMPORARY) != 0);
	cc->cand_istmp_set = B_TRUE;

	if (bc->cand_istmp == cc->cand_istmp)
		return (CAND_TIE);

	if (dstinfo->dst_prefer_src_tmp && cc->cand_istmp)
		return (CAND_PREFER);
	else if (!dstinfo->dst_prefer_src_tmp && !cc->cand_istmp)
		return (CAND_PREFER);
	else
		return (CAND_AVOID);
}

/*
 * Prefer source addresses with longer matching prefix with the destination
 * under the interface mask.  This gets us on the same subnet before applying
 * any Solaris-specific rules.
 */
/* ARGSUSED3 */
static rule_res_t
rule_ifprefix(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo,
    ip_stack_t *ipst)
{
	if (!bc->cand_pref_eq_set) {
		bc->cand_pref_eq = V6_MASK_EQ_2(bc->cand_srcaddr,
		    bc->cand_mask, *dstinfo->dst_addr);
		bc->cand_pref_eq_set = B_TRUE;
	}

	cc->cand_pref_eq = V6_MASK_EQ_2(cc->cand_srcaddr, cc->cand_mask,
	    *dstinfo->dst_addr);
	cc->cand_pref_eq_set = B_TRUE;

	if (bc->cand_pref_eq) {
		if (cc->cand_pref_eq) {
			if (!bc->cand_pref_len_set) {
				bc->cand_pref_len =
				    ip_mask_to_plen_v6(&bc->cand_mask);
				bc->cand_pref_len_set = B_TRUE;
			}
			cc->cand_pref_len = ip_mask_to_plen_v6(&cc->cand_mask);
			cc->cand_pref_len_set = B_TRUE;
			if (bc->cand_pref_len == cc->cand_pref_len)
				return (CAND_TIE);
			else if (bc->cand_pref_len > cc->cand_pref_len)
				return (CAND_AVOID);
			else
				return (CAND_PREFER);
		} else {
			return (CAND_AVOID);
		}
	} else {
		if (cc->cand_pref_eq)
			return (CAND_PREFER);
		else
			return (CAND_TIE);
	}
}

/*
 * Prefer to use zone-specific addresses when possible instead of all-zones
 * addresses.
 */
/* ARGSUSED2 */
static rule_res_t
rule_zone_specific(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo,
    ip_stack_t *ipst)
{
	if ((bc->cand_zoneid == ALL_ZONES) ==
	    (cc->cand_zoneid == ALL_ZONES))
		return (CAND_TIE);
	else if (cc->cand_zoneid == ALL_ZONES)
		return (CAND_AVOID);
	else
		return (CAND_PREFER);
}

/*
 * Prefer to use DHCPv6 (first) and static addresses (second) when possible
 * instead of statelessly autoconfigured addresses.
 *
 * This is done after trying all other preferences (and before the final tie
 * breaker) so that, if all else is equal, we select addresses configured by
 * DHCPv6 over other addresses.  We presume that DHCPv6 addresses, unlike
 * stateless autoconfigured addresses, are deliberately configured by an
 * administrator, and thus are correctly set up in DNS and network packet
 * filters.
 */
/* ARGSUSED2 */
static rule_res_t
rule_addr_type(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo,
    ip_stack_t *ipst)
{
#define	ATYPE(x)	\
	((x) & IPIF_DHCPRUNNING) ? 1 : ((x) & IPIF_ADDRCONF) ? 3 : 2
	int bcval = ATYPE(bc->cand_flags);
	int ccval = ATYPE(cc->cand_flags);
#undef ATYPE

	if (bcval == ccval)
		return (CAND_TIE);
	else if (ccval < bcval)
		return (CAND_PREFER);
	else
		return (CAND_AVOID);
}

/*
 * Prefer source addresses with longer matching prefix with the destination.
 * We do the longest matching prefix calculation by doing an xor of both
 * addresses with the destination, and pick the address with the longest string
 * of leading zeros, as per CommonPrefixLen() defined in RFC 3484.
 */
/* ARGSUSED3 */
static rule_res_t
rule_prefix(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo, ip_stack_t *ipst)
{
	/*
	 * For IPMP, we always want to choose a random source address from
	 * among any equally usable addresses, so always report a tie.
	 */
	if (IS_IPMP(dstinfo->dst_ill))
		return (CAND_TIE);

	if (!bc->cand_common_pref_set) {
		bc->cand_common_pref = ip_common_prefix_v6(&bc->cand_srcaddr,
		    dstinfo->dst_addr);
		bc->cand_common_pref_set = B_TRUE;
	}

	cc->cand_common_pref = ip_common_prefix_v6(&cc->cand_srcaddr,
	    dstinfo->dst_addr);
	cc->cand_common_pref_set = B_TRUE;

	if (bc->cand_common_pref == cc->cand_common_pref)
		return (CAND_TIE);
	else if (bc->cand_common_pref > cc->cand_common_pref)
		return (CAND_AVOID);
	else
		return (CAND_PREFER);
}

/*
 * Last rule: we must pick something, so just prefer the current best
 * candidate.
 */
/* ARGSUSED */
static rule_res_t
rule_must_be_last(cand_t *bc, cand_t *cc, const dstinfo_t *dstinfo,
    ip_stack_t *ipst)
{
	return (CAND_AVOID);
}

/*
 * Determine the best source address given a destination address and a
 * destination ill.  If no suitable source address is found, it returns
 * NULL. If there is a usable address pointed to by the usesrc
 * (i.e ill_usesrc_ifindex != 0) then return that first since it is more
 * fine grained (i.e per interface)
 *
 * This implementation is based on the "Default Address Selection for IPv6"
 * specification produced by the IETF IPv6 working group.  It has been
 * implemented so that the list of addresses is only traversed once (the
 * specification's algorithm could traverse the list of addresses once for
 * every rule).
 *
 * The restrict_ill argument restricts the algorithm to choose a source
 * address that is assigned to the destination ill.  This is used when
 * the destination address is a link-local or multicast address, and when
 * ipv6_strict_dst_multihoming is turned on.
 *
 * src_prefs is the caller's set of source address preferences.  If source
 * address selection is being called to determine the source address of a
 * connected socket (from ip_bind_connected_v6()), then the preferences are
 * taken from conn_src_preferences.  These preferences can be set on a
 * per-socket basis using the IPV6_SRC_PREFERENCES socket option.  The only
 * preference currently implemented is for rfc3041 temporary addresses.
 */
ipif_t *
ipif_select_source_v6(ill_t *dstill, const in6_addr_t *dst,
    boolean_t restrict_ill, uint32_t src_prefs, zoneid_t zoneid)
{
	dstinfo_t	dstinfo;
	char		dstr[INET6_ADDRSTRLEN];
	char		sstr[INET6_ADDRSTRLEN];
	ipif_t		*ipif, *start_ipif, *next_ipif;
	ill_t		*ill, *usesrc_ill = NULL, *ipmp_ill = NULL;
	ill_walk_context_t	ctx;
	cand_t		best_c;	/* The best candidate */
	cand_t		curr_c;	/* The current candidate */
	uint_t		index;
	boolean_t	first_candidate = B_TRUE;
	rule_res_t	rule_result;
	tsol_tpc_t	*src_rhtp, *dst_rhtp;
	ip_stack_t	*ipst = dstill->ill_ipst;

	/*
	 * The list of ordering rules.  They are applied in the order they
	 * appear in the list.
	 *
	 * Solaris doesn't currently support Mobile IPv6, so there's no
	 * rule_mipv6 corresponding to rule 4 in the specification.
	 */
	rulef_t	rules[] = {
		rule_isdst,
		rule_scope,
		rule_deprecated,
		rule_preferred,
		rule_interface,
		rule_label,
		rule_temporary,
		rule_ifprefix,			/* local rules after this */
		rule_zone_specific,
		rule_addr_type,
		rule_prefix,			/* local rules before this */
		rule_must_be_last,		/* must always be last */
		NULL
	};

	ASSERT(dstill->ill_isv6);
	ASSERT(!IN6_IS_ADDR_V4MAPPED(dst));

	/*
	 * Check if there is a usable src address pointed to by the
	 * usesrc ifindex. This has higher precedence since it is
	 * finer grained (i.e per interface) v/s being system wide.
	 */
	if (dstill->ill_usesrc_ifindex != 0) {
		if ((usesrc_ill =
		    ill_lookup_on_ifindex(dstill->ill_usesrc_ifindex, B_TRUE,
		    NULL, NULL, NULL, NULL, ipst)) != NULL) {
			dstinfo.dst_ill = usesrc_ill;
		} else {
			return (NULL);
		}
	} else if (IS_UNDER_IPMP(dstill)) {
		/*
		 * Test addresses should never be used for source address
		 * selection, so if we were passed an underlying ill, switch
		 * to the IPMP meta-interface.
		 */
		if ((ipmp_ill = ipmp_ill_hold_ipmp_ill(dstill)) != NULL)
			dstinfo.dst_ill = ipmp_ill;
		else
			return (NULL);
	} else {
		dstinfo.dst_ill = dstill;
	}

	/*
	 * If we're dealing with an unlabeled destination on a labeled system,
	 * make sure that we ignore source addresses that are incompatible with
	 * the destination's default label.  That destination's default label
	 * must dominate the minimum label on the source address.
	 *
	 * (Note that this has to do with Trusted Solaris.  It's not related to
	 * the labels described by ip6_asp_lookup.)
	 */
	dst_rhtp = NULL;
	if (is_system_labeled()) {
		dst_rhtp = find_tpc(dst, IPV6_VERSION, B_FALSE);
		if (dst_rhtp == NULL)
			return (NULL);
		if (dst_rhtp->tpc_tp.host_type != UNLABELED) {
			TPC_RELE(dst_rhtp);
			dst_rhtp = NULL;
		}
	}

	dstinfo.dst_addr = dst;
	dstinfo.dst_scope = ip_addr_scope_v6(dst);
	dstinfo.dst_label = ip6_asp_lookup(dst, NULL, ipst);
	dstinfo.dst_prefer_src_tmp = ((src_prefs & IPV6_PREFER_SRC_TMP) != 0);
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	/*
	 * Section three of the I-D states that for multicast and
	 * link-local destinations, the candidate set must be restricted to
	 * an interface that is on the same link as the outgoing interface.
	 * Also, when ipv6_strict_dst_multihoming is turned on, always
	 * restrict the source address to the destination link as doing
	 * otherwise will almost certainly cause problems.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(dst) || IN6_IS_ADDR_MULTICAST(dst) ||
	    ipst->ips_ipv6_strict_dst_multihoming || usesrc_ill != NULL) {
		dstinfo.dst_restrict_ill = B_TRUE;
	} else {
		dstinfo.dst_restrict_ill = restrict_ill;
	}

	bzero(&best_c, sizeof (cand_t));

	/*
	 * Take a pass through the list of IPv6 interfaces to choose the best
	 * possible source address.  If restrict_ill is set, just use dst_ill.
	 */
	if (dstinfo.dst_restrict_ill)
		ill = dstinfo.dst_ill;
	else
		ill = ILL_START_WALK_V6(&ctx, ipst);

	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		ASSERT(ill->ill_isv6);

		/*
		 * Test addresses should never be used for source address
		 * selection, so ignore underlying ills.
		 */
		if (IS_UNDER_IPMP(ill))
			continue;

		/*
		 * For source address selection, we treat the ipif list as
		 * circular and continue until we get back to where we
		 * started.  This allows IPMP to vary source address selection
		 * (which improves inbound load spreading) by caching its last
		 * ending point and starting from there.  NOTE: we don't have
		 * to worry about ill_src_ipif changing ills since that can't
		 * happen on the IPMP ill.
		 */
		start_ipif = ill->ill_ipif;
		if (IS_IPMP(ill) && ill->ill_src_ipif != NULL)
			start_ipif = ill->ill_src_ipif;

		ipif = start_ipif;
		do {
			if ((next_ipif = ipif->ipif_next) == NULL)
				next_ipif = ill->ill_ipif;

			if (!IPIF_VALID_IPV6_SOURCE(ipif))
				continue;

			if (zoneid != ALL_ZONES &&
			    ipif->ipif_zoneid != zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;

			/*
			 * Check compatibility of local address for
			 * destination's default label if we're on a labeled
			 * system.  Incompatible addresses can't be used at
			 * all and must be skipped over.
			 */
			if (dst_rhtp != NULL) {
				boolean_t incompat;

				src_rhtp = find_tpc(&ipif->ipif_v6lcl_addr,
				    IPV6_VERSION, B_FALSE);
				if (src_rhtp == NULL)
					continue;
				incompat =
				    src_rhtp->tpc_tp.host_type != SUN_CIPSO ||
				    src_rhtp->tpc_tp.tp_doi !=
				    dst_rhtp->tpc_tp.tp_doi ||
				    (!_blinrange(&dst_rhtp->tpc_tp.tp_def_label,
				    &src_rhtp->tpc_tp.tp_sl_range_cipso) &&
				    !blinlset(&dst_rhtp->tpc_tp.tp_def_label,
				    src_rhtp->tpc_tp.tp_sl_set_cipso));
				TPC_RELE(src_rhtp);
				if (incompat)
					continue;
			}

			if (first_candidate) {
				/*
				 * This is first valid address in the list.
				 * It is automatically the best candidate
				 * so far.
				 */
				best_c.cand_ipif = ipif;
				first_candidate = B_FALSE;
				continue;
			}

			bzero(&curr_c, sizeof (cand_t));
			curr_c.cand_ipif = ipif;

			/*
			 * Compare this current candidate (curr_c) with the
			 * best candidate (best_c) by applying the
			 * comparison rules in order until one breaks the
			 * tie.
			 */
			for (index = 0; rules[index] != NULL; index++) {
				/* Apply a comparison rule. */
				rule_result = (rules[index])(&best_c, &curr_c,
				    &dstinfo, ipst);
				if (rule_result == CAND_AVOID) {
					/*
					 * The best candidate is still the
					 * best candidate.  Forget about
					 * this current candidate and go on
					 * to the next one.
					 */
					break;
				} else if (rule_result == CAND_PREFER) {
					/*
					 * This candidate is prefered.  It
					 * becomes the best candidate so
					 * far.  Go on to the next address.
					 */
					best_c = curr_c;
					break;
				}
				/* We have a tie, apply the next rule. */
			}

			/*
			 * The last rule must be a tie breaker rule and
			 * must never produce a tie.  At this point, the
			 * candidate should have either been rejected, or
			 * have been prefered as the best candidate so far.
			 */
			ASSERT(rule_result != CAND_TIE);
		} while ((ipif = next_ipif) != start_ipif);

		/*
		 * For IPMP, update the source ipif rotor to the next ipif,
		 * provided we can look it up.  (We must not use it if it's
		 * IPIF_CONDEMNED since we may have grabbed ill_g_lock after
		 * ipif_free() checked ill_src_ipif.)
		 */
		if (IS_IPMP(ill) && ipif != NULL) {
			mutex_enter(&ipif->ipif_ill->ill_lock);
			next_ipif = ipif->ipif_next;
			if (next_ipif != NULL && IPIF_CAN_LOOKUP(next_ipif))
				ill->ill_src_ipif = next_ipif;
			else
				ill->ill_src_ipif = NULL;
			mutex_exit(&ipif->ipif_ill->ill_lock);
		}

		/*
		 * Only one ill to consider if dst_restrict_ill is set.
		 */
		if (dstinfo.dst_restrict_ill)
			break;
	}

	ipif = best_c.cand_ipif;
	ip1dbg(("ipif_select_source_v6(%s, %s) -> %s\n",
	    dstinfo.dst_ill->ill_name,
	    inet_ntop(AF_INET6, dstinfo.dst_addr, dstr, sizeof (dstr)),
	    (ipif == NULL ? "NULL" :
	    inet_ntop(AF_INET6, &ipif->ipif_v6lcl_addr, sstr, sizeof (sstr)))));

	if (usesrc_ill != NULL)
		ill_refrele(usesrc_ill);

	if (ipmp_ill != NULL)
		ill_refrele(ipmp_ill);

	if (dst_rhtp != NULL)
		TPC_RELE(dst_rhtp);

	if (ipif == NULL) {
		rw_exit(&ipst->ips_ill_g_lock);
		return (NULL);
	}

	mutex_enter(&ipif->ipif_ill->ill_lock);
	if (IPIF_CAN_LOOKUP(ipif)) {
		ipif_refhold_locked(ipif);
		mutex_exit(&ipif->ipif_ill->ill_lock);
		rw_exit(&ipst->ips_ill_g_lock);
		return (ipif);
	}
	mutex_exit(&ipif->ipif_ill->ill_lock);
	rw_exit(&ipst->ips_ill_g_lock);
	ip1dbg(("ipif_select_source_v6 cannot lookup ipif %p"
	    " returning null \n", (void *)ipif));

	return (NULL);
}

/*
 * If old_ipif is not NULL, see if ipif was derived from old
 * ipif and if so, recreate the interface route by re-doing
 * source address selection. This happens when ipif_down ->
 * ipif_update_other_ipifs calls us.
 *
 * If old_ipif is NULL, just redo the source address selection
 * if needed. This happens when ipif_up_done_v6 calls us.
 */
void
ipif_recreate_interface_routes_v6(ipif_t *old_ipif, ipif_t *ipif)
{
	ire_t *ire;
	ire_t *ipif_ire;
	queue_t *stq;
	ill_t *ill;
	ipif_t *nipif = NULL;
	boolean_t nipif_refheld = B_FALSE;
	boolean_t ip6_asp_table_held = B_FALSE;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ill = ipif->ipif_ill;

	if (!(ipif->ipif_flags &
	    (IPIF_NOLOCAL|IPIF_ANYCAST|IPIF_DEPRECATED))) {
		/*
		 * Can't possibly have borrowed the source
		 * from old_ipif.
		 */
		return;
	}

	/*
	 * Is there any work to be done? No work if the address
	 * is INADDR_ANY, loopback or NOLOCAL or ANYCAST (
	 * ipif_select_source_v6() does not borrow addresses from
	 * NOLOCAL and ANYCAST interfaces).
	 */
	if ((old_ipif != NULL) &&
	    ((IN6_IS_ADDR_UNSPECIFIED(&old_ipif->ipif_v6lcl_addr)) ||
	    (old_ipif->ipif_ill->ill_wq == NULL) ||
	    (old_ipif->ipif_flags &
	    (IPIF_NOLOCAL|IPIF_ANYCAST)))) {
		return;
	}

	/*
	 * Perform the same checks as when creating the
	 * IRE_INTERFACE in ipif_up_done_v6.
	 */
	if (!(ipif->ipif_flags & IPIF_UP))
		return;

	if ((ipif->ipif_flags & IPIF_NOXMIT))
		return;

	if (IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6subnet) &&
	    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6net_mask))
		return;

	/*
	 * We know that ipif uses some other source for its
	 * IRE_INTERFACE. Is it using the source of this
	 * old_ipif?
	 */
	ipif_ire = ipif_to_ire_v6(ipif);
	if (ipif_ire == NULL)
		return;

	if (old_ipif != NULL &&
	    !IN6_ARE_ADDR_EQUAL(&old_ipif->ipif_v6lcl_addr,
	    &ipif_ire->ire_src_addr_v6)) {
		ire_refrele(ipif_ire);
		return;
	}

	if (ip_debug > 2) {
		/* ip1dbg */
		pr_addr_dbg("ipif_recreate_interface_routes_v6: deleting IRE"
		    " for src %s\n", AF_INET6, &ipif_ire->ire_src_addr_v6);
	}

	stq = ipif_ire->ire_stq;

	/*
	 * Can't use our source address. Select a different source address
	 * for the IRE_INTERFACE.  We restrict interface route source
	 * address selection to ipif's assigned to the same link as the
	 * interface.
	 */
	if (ip6_asp_can_lookup(ipst)) {
		ip6_asp_table_held = B_TRUE;
		nipif = ipif_select_source_v6(ill, &ipif->ipif_v6subnet,
		    B_TRUE, IPV6_PREFER_SRC_DEFAULT, ipif->ipif_zoneid);
	}
	if (nipif == NULL) {
		/* Last resort - all ipif's have IPIF_NOLOCAL */
		nipif = ipif;
	} else {
		nipif_refheld = B_TRUE;
	}

	ire = ire_create_v6(
	    &ipif->ipif_v6subnet,	/* dest pref */
	    &ipif->ipif_v6net_mask,	/* mask */
	    &nipif->ipif_v6src_addr,	/* src addr */
	    NULL,			/* no gateway */
	    &ipif->ipif_mtu,		/* max frag */
	    NULL,			/* no src nce */
	    NULL,			/* no recv from queue */
	    stq,			/* send-to queue */
	    ill->ill_net_type,		/* IF_[NO]RESOLVER */
	    ipif,
	    NULL,
	    0,
	    0,
	    0,
	    &ire_uinfo_null,
	    NULL,
	    NULL,
	    ipst);

	if (ire != NULL) {
		ire_t *ret_ire;
		int   error;

		/*
		 * We don't need ipif_ire anymore. We need to delete
		 * before we add so that ire_add does not detect
		 * duplicates.
		 */
		ire_delete(ipif_ire);
		ret_ire = ire;
		error = ire_add(&ret_ire, NULL, NULL, NULL, B_FALSE);
		ASSERT(error == 0);
		ASSERT(ret_ire == ire);
		if (ret_ire != NULL) {
			/* Held in ire_add */
			ire_refrele(ret_ire);
		}
	}
	/*
	 * Either we are falling through from above or could not
	 * allocate a replacement.
	 */
	ire_refrele(ipif_ire);
	if (ip6_asp_table_held)
		ip6_asp_table_refrele(ipst);
	if (nipif_refheld)
		ipif_refrele(nipif);
}

/*
 * This old_ipif is going away.
 *
 * Determine if any other ipif's are using our address as
 * ipif_v6lcl_addr (due to those being IPIF_NOLOCAL, IPIF_ANYCAST, or
 * IPIF_DEPRECATED).
 * Find the IRE_INTERFACE for such ipif's and recreate them
 * to use an different source address following the rules in
 * ipif_up_done_v6.
 */
void
ipif_update_other_ipifs_v6(ipif_t *old_ipif)
{
	ipif_t	*ipif;
	ill_t	*ill;
	char	buf[INET6_ADDRSTRLEN];

	ASSERT(IAM_WRITER_IPIF(old_ipif));

	ill = old_ipif->ipif_ill;

	ip1dbg(("ipif_update_other_ipifs_v6(%s, %s)\n",
	    ill->ill_name,
	    inet_ntop(AF_INET6, &old_ipif->ipif_v6lcl_addr,
	    buf, sizeof (buf))));

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (ipif != old_ipif)
			ipif_recreate_interface_routes_v6(old_ipif, ipif);
	}
}

/*
 * Perform an attach and bind to get phys addr plus info_req for
 * the physical device.
 * q and mp represents an ioctl which will be queued waiting for
 * completion of the DLPI message exchange.
 * MUST be called on an ill queue. Can not set conn_pending_ill for that
 * reason thus the DL_PHYS_ADDR_ACK code does not assume ill_pending_q.
 *
 * Returns EINPROGRESS when mp has been consumed by queueing it on
 * ill_pending_mp and the ioctl will complete in ip_rput.
 */
int
ill_dl_phys(ill_t *ill, ipif_t *ipif, mblk_t *mp, queue_t *q)
{
	mblk_t	*v6token_mp = NULL;
	mblk_t	*v6lla_mp = NULL;
	mblk_t	*phys_mp = NULL;
	mblk_t	*info_mp = NULL;
	mblk_t	*attach_mp = NULL;
	mblk_t	*bind_mp = NULL;
	mblk_t	*unbind_mp = NULL;
	mblk_t	*notify_mp = NULL;

	ip1dbg(("ill_dl_phys(%s:%u)\n", ill->ill_name, ipif->ipif_id));
	ASSERT(ill->ill_dlpi_style_set);
	ASSERT(WR(q)->q_next != NULL);

	if (ill->ill_isv6) {
		v6token_mp = ip_dlpi_alloc(sizeof (dl_phys_addr_req_t) +
		    sizeof (t_scalar_t), DL_PHYS_ADDR_REQ);
		if (v6token_mp == NULL)
			goto bad;
		((dl_phys_addr_req_t *)v6token_mp->b_rptr)->dl_addr_type =
		    DL_IPV6_TOKEN;

		v6lla_mp = ip_dlpi_alloc(sizeof (dl_phys_addr_req_t) +
		    sizeof (t_scalar_t), DL_PHYS_ADDR_REQ);
		if (v6lla_mp == NULL)
			goto bad;
		((dl_phys_addr_req_t *)v6lla_mp->b_rptr)->dl_addr_type =
		    DL_IPV6_LINK_LAYER_ADDR;
	}

	/*
	 * Allocate a DL_NOTIFY_REQ and set the notifications we want.
	 */
	notify_mp = ip_dlpi_alloc(sizeof (dl_notify_req_t) + sizeof (long),
	    DL_NOTIFY_REQ);
	if (notify_mp == NULL)
		goto bad;
	((dl_notify_req_t *)notify_mp->b_rptr)->dl_notifications =
	    (DL_NOTE_PHYS_ADDR | DL_NOTE_SDU_SIZE | DL_NOTE_FASTPATH_FLUSH |
	    DL_NOTE_LINK_UP | DL_NOTE_LINK_DOWN | DL_NOTE_CAPAB_RENEG);

	phys_mp = ip_dlpi_alloc(sizeof (dl_phys_addr_req_t) +
	    sizeof (t_scalar_t), DL_PHYS_ADDR_REQ);
	if (phys_mp == NULL)
		goto bad;
	((dl_phys_addr_req_t *)phys_mp->b_rptr)->dl_addr_type =
	    DL_CURR_PHYS_ADDR;

	info_mp = ip_dlpi_alloc(
	    sizeof (dl_info_req_t) + sizeof (dl_info_ack_t),
	    DL_INFO_REQ);
	if (info_mp == NULL)
		goto bad;

	bind_mp = ip_dlpi_alloc(sizeof (dl_bind_req_t) + sizeof (long),
	    DL_BIND_REQ);
	if (bind_mp == NULL)
		goto bad;
	((dl_bind_req_t *)bind_mp->b_rptr)->dl_sap = ill->ill_sap;
	((dl_bind_req_t *)bind_mp->b_rptr)->dl_service_mode = DL_CLDLS;

	unbind_mp = ip_dlpi_alloc(sizeof (dl_unbind_req_t), DL_UNBIND_REQ);
	if (unbind_mp == NULL)
		goto bad;

	/* If we need to attach, pre-alloc and initialize the mblk */
	if (ill->ill_needs_attach) {
		attach_mp = ip_dlpi_alloc(sizeof (dl_attach_req_t),
		    DL_ATTACH_REQ);
		if (attach_mp == NULL)
			goto bad;
		((dl_attach_req_t *)attach_mp->b_rptr)->dl_ppa = ill->ill_ppa;
	}

	/*
	 * Here we are going to delay the ioctl ack until after
	 * ACKs from DL_PHYS_ADDR_REQ. So need to save the
	 * original ioctl message before sending the requests
	 */
	mutex_enter(&ill->ill_lock);
	/* ipsq_pending_mp_add won't fail since we pass in a NULL connp */
	(void) ipsq_pending_mp_add(NULL, ipif, ill->ill_wq, mp, 0);
	/*
	 * Set ill_phys_addr_pend to zero. It will be set to the addr_type of
	 * the DL_PHYS_ADDR_REQ in ill_dlpi_send() and ill_dlpi_done(). It will
	 * be used to track which DL_PHYS_ADDR_REQ is being ACK'd/NAK'd.
	 */
	ill->ill_phys_addr_pend = 0;
	mutex_exit(&ill->ill_lock);

	if (attach_mp != NULL) {
		ip1dbg(("ill_dl_phys: attach\n"));
		ill_dlpi_send(ill, attach_mp);
	}
	ill_dlpi_send(ill, bind_mp);
	ill_dlpi_send(ill, info_mp);
	if (ill->ill_isv6) {
		ill_dlpi_send(ill, v6token_mp);
		ill_dlpi_send(ill, v6lla_mp);
	}
	ill_dlpi_send(ill, phys_mp);
	ill_dlpi_send(ill, notify_mp);
	ill_dlpi_send(ill, unbind_mp);

	/*
	 * This operation will complete in ip_rput_dlpi_writer with either
	 * a DL_PHYS_ADDR_ACK or DL_ERROR_ACK.
	 */
	return (EINPROGRESS);
bad:
	freemsg(v6token_mp);
	freemsg(v6lla_mp);
	freemsg(phys_mp);
	freemsg(info_mp);
	freemsg(attach_mp);
	freemsg(bind_mp);
	freemsg(unbind_mp);
	freemsg(notify_mp);
	return (ENOMEM);
}

uint_t ip_loopback_mtu_v6plus = IP_LOOPBACK_MTU + IPV6_HDR_LEN + 20;

/*
 * DLPI is up.
 * Create all the IREs associated with an interface bring up multicast.
 * Set the interface flag and finish other initialization
 * that potentially had to be differed to after DL_BIND_ACK.
 */
int
ipif_up_done_v6(ipif_t *ipif)
{
	ire_t	*ire_array[20];
	ire_t	**irep = ire_array;
	ire_t	**irep1;
	ill_t	*ill = ipif->ipif_ill;
	queue_t	*stq;
	in6_addr_t	v6addr;
	in6_addr_t	route_mask;
	ipif_t	 *src_ipif = NULL;
	ipif_t   *tmp_ipif;
	boolean_t	flush_ire_cache = B_TRUE;
	int	err;
	char	buf[INET6_ADDRSTRLEN];
	ire_t	**ipif_saved_irep = NULL;
	int ipif_saved_ire_cnt;
	int cnt;
	boolean_t src_ipif_held = B_FALSE;
	boolean_t loopback = B_FALSE;
	boolean_t ip6_asp_table_held = B_FALSE;
	ip_stack_t	*ipst = ill->ill_ipst;

	ip1dbg(("ipif_up_done_v6(%s:%u)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id));

	/* Check if this is a loopback interface */
	if (ipif->ipif_ill->ill_wq == NULL)
		loopback = B_TRUE;

	ASSERT(ipif->ipif_isv6);
	ASSERT(!MUTEX_HELD(&ipif->ipif_ill->ill_lock));

	/*
	 * If all other interfaces for this ill are down or DEPRECATED,
	 * or otherwise unsuitable for source address selection, remove
	 * any IRE_CACHE entries for this ill to make sure source
	 * address selection gets to take this new ipif into account.
	 * No need to hold ill_lock while traversing the ipif list since
	 * we are writer
	 */
	for (tmp_ipif = ill->ill_ipif; tmp_ipif;
	    tmp_ipif = tmp_ipif->ipif_next) {
		if (((tmp_ipif->ipif_flags &
		    (IPIF_NOXMIT|IPIF_ANYCAST|IPIF_NOLOCAL|IPIF_DEPRECATED)) ||
		    !(tmp_ipif->ipif_flags & IPIF_UP)) ||
		    (tmp_ipif == ipif))
			continue;
		/* first useable pre-existing interface */
		flush_ire_cache = B_FALSE;
		break;
	}
	if (flush_ire_cache)
		ire_walk_ill_v6(MATCH_IRE_ILL | MATCH_IRE_TYPE,
		    IRE_CACHE, ill_ipif_cache_delete, ill, ill);

	/*
	 * Figure out which way the send-to queue should go.  Only
	 * IRE_IF_RESOLVER or IRE_IF_NORESOLVER should show up here.
	 */
	switch (ill->ill_net_type) {
	case IRE_IF_RESOLVER:
		stq = ill->ill_rq;
		break;
	case IRE_IF_NORESOLVER:
	case IRE_LOOPBACK:
		stq = ill->ill_wq;
		break;
	default:
		return (EINVAL);
	}

	if (IS_LOOPBACK(ill)) {
		/*
		 * lo0:1 and subsequent ipifs were marked IRE_LOCAL in
		 * ipif_lookup_on_name(), but in the case of zones we can have
		 * several loopback addresses on lo0. So all the interfaces with
		 * loopback addresses need to be marked IRE_LOOPBACK.
		 */
		if (IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6lcl_addr, &ipv6_loopback))
			ipif->ipif_ire_type = IRE_LOOPBACK;
		else
			ipif->ipif_ire_type = IRE_LOCAL;
	}

	if (ipif->ipif_flags & (IPIF_NOLOCAL|IPIF_ANYCAST) ||
	    ((ipif->ipif_flags & IPIF_DEPRECATED) &&
	    !(ipif->ipif_flags & IPIF_NOFAILOVER))) {
		/*
		 * Can't use our source address. Select a different
		 * source address for the IRE_INTERFACE and IRE_LOCAL
		 */
		if (ip6_asp_can_lookup(ipst)) {
			ip6_asp_table_held = B_TRUE;
			src_ipif = ipif_select_source_v6(ipif->ipif_ill,
			    &ipif->ipif_v6subnet, B_FALSE,
			    IPV6_PREFER_SRC_DEFAULT, ipif->ipif_zoneid);
		}
		if (src_ipif == NULL)
			src_ipif = ipif;	/* Last resort */
		else
			src_ipif_held = B_TRUE;
	} else {
		src_ipif = ipif;
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr) &&
	    !(ipif->ipif_flags & IPIF_NOLOCAL)) {

		/*
		 * If we're on a labeled system then make sure that zone-
		 * private addresses have proper remote host database entries.
		 */
		if (is_system_labeled() &&
		    ipif->ipif_ire_type != IRE_LOOPBACK) {
			if (ip6opt_ls == 0) {
				cmn_err(CE_WARN, "IPv6 not enabled "
				    "via /etc/system");
				return (EINVAL);
			}
			if (!tsol_check_interface_address(ipif))
				return (EINVAL);
		}

		/* Register the source address for __sin6_src_id */
		err = ip_srcid_insert(&ipif->ipif_v6lcl_addr,
		    ipif->ipif_zoneid, ipst);
		if (err != 0) {
			ip0dbg(("ipif_up_done_v6: srcid_insert %d\n", err));
			if (src_ipif_held)
				ipif_refrele(src_ipif);
			if (ip6_asp_table_held)
				ip6_asp_table_refrele(ipst);
			return (err);
		}
		/*
		 * If the interface address is set, create the LOCAL
		 * or LOOPBACK IRE.
		 */
		ip1dbg(("ipif_up_done_v6: creating IRE %d for %s\n",
		    ipif->ipif_ire_type,
		    inet_ntop(AF_INET6, &ipif->ipif_v6lcl_addr,
		    buf, sizeof (buf))));

		*irep++ = ire_create_v6(
		    &ipif->ipif_v6lcl_addr,		/* dest address */
		    &ipv6_all_ones,			/* mask */
		    &src_ipif->ipif_v6src_addr,		/* source address */
		    NULL,				/* no gateway */
		    &ip_loopback_mtu_v6plus,		/* max frag size */
		    NULL,
		    ipif->ipif_rq,			/* recv-from queue */
		    NULL,				/* no send-to queue */
		    ipif->ipif_ire_type,		/* LOCAL or LOOPBACK */
		    ipif,				/* interface */
		    NULL,
		    0,
		    0,
		    (ipif->ipif_flags & IPIF_PRIVATE) ? RTF_PRIVATE : 0,
		    &ire_uinfo_null,
		    NULL,
		    NULL,
		    ipst);
	}

	/*
	 * Set up the IRE_IF_RESOLVER or IRE_IF_NORESOLVER, as appropriate.
	 * Note that atun interfaces have an all-zero ipif_v6subnet.
	 * Thus we allow a zero subnet as long as the mask is non-zero.
	 */
	if (stq != NULL && !(ipif->ipif_flags & IPIF_NOXMIT) &&
	    !(IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6subnet) &&
	    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6net_mask))) {
		/* ipif_v6subnet is ipif_v6pp_dst_addr for pt-pt */
		v6addr = ipif->ipif_v6subnet;

		if (ipif->ipif_flags & IPIF_POINTOPOINT) {
			route_mask = ipv6_all_ones;
		} else {
			route_mask = ipif->ipif_v6net_mask;
		}

		ip1dbg(("ipif_up_done_v6: creating if IRE %d for %s\n",
		    ill->ill_net_type,
		    inet_ntop(AF_INET6, &v6addr, buf, sizeof (buf))));

		*irep++ = ire_create_v6(
		    &v6addr,			/* dest pref */
		    &route_mask,		/* mask */
		    &src_ipif->ipif_v6src_addr,	/* src addr */
		    NULL,			/* no gateway */
		    &ipif->ipif_mtu,		/* max frag */
		    NULL,			/* no src nce */
		    NULL,			/* no recv from queue */
		    stq,			/* send-to queue */
		    ill->ill_net_type,		/* IF_[NO]RESOLVER */
		    ipif,
		    NULL,
		    0,
		    0,
		    (ipif->ipif_flags & IPIF_PRIVATE) ? RTF_PRIVATE : 0,
		    &ire_uinfo_null,
		    NULL,
		    NULL,
		    ipst);
	}

	/*
	 * Setup 2002::/16 route, if this interface is a 6to4 tunnel
	 */
	if (IN6_IS_ADDR_6TO4(&ipif->ipif_v6lcl_addr) &&
	    (ill->ill_is_6to4tun)) {
		/*
		 * Destination address is 2002::/16
		 */
#ifdef	_BIG_ENDIAN
		const in6_addr_t prefix_addr = { 0x20020000U, 0, 0, 0 };
		const in6_addr_t prefix_mask = { 0xffff0000U, 0, 0, 0 };
#else
		const in6_addr_t prefix_addr = { 0x00000220U, 0, 0, 0 };
		const in6_addr_t prefix_mask = { 0x0000ffffU, 0, 0, 0 };
#endif /* _BIG_ENDIAN */
		char	buf2[INET6_ADDRSTRLEN];
		ire_t *isdup;
		in6_addr_t *first_addr = &ill->ill_ipif->ipif_v6lcl_addr;

		/*
		 * check to see if this route has already been added for
		 * this tunnel interface.
		 */
		isdup = ire_ftable_lookup_v6(first_addr, &prefix_mask, 0,
		    IRE_IF_NORESOLVER, ill->ill_ipif, NULL, ALL_ZONES, 0, NULL,
		    (MATCH_IRE_SRC | MATCH_IRE_MASK), ipst);

		if (isdup == NULL) {
			ip1dbg(("ipif_up_done_v6: creating if IRE %d for %s",
			    IRE_IF_NORESOLVER, inet_ntop(AF_INET6, &v6addr,
			    buf2, sizeof (buf2))));

			*irep++ = ire_create_v6(
			    &prefix_addr,		/* 2002:: */
			    &prefix_mask,		/* ffff:: */
			    &ipif->ipif_v6lcl_addr, 	/* src addr */
			    NULL, 			/* gateway */
			    &ipif->ipif_mtu, 		/* max_frag */
			    NULL, 			/* no src nce */
			    NULL, 			/* no rfq */
			    ill->ill_wq, 		/* stq */
			    IRE_IF_NORESOLVER,		/* type */
			    ipif,			/* interface */
			    NULL,			/* v6cmask */
			    0,
			    0,
			    RTF_UP,
			    &ire_uinfo_null,
			    NULL,
			    NULL,
			    ipst);
		} else {
			ire_refrele(isdup);
		}
	}

	/* If an earlier ire_create failed, get out now */
	for (irep1 = irep; irep1 > ire_array; ) {
		irep1--;
		if (*irep1 == NULL) {
			ip1dbg(("ipif_up_done_v6: NULL ire found in"
			    " ire_array\n"));
			err = ENOMEM;
			goto bad;
		}
	}

	ASSERT(!MUTEX_HELD(&ipif->ipif_ill->ill_lock));

	/*
	 * Need to atomically check for IP address availability under
	 * ip_addr_avail_lock.  ill_g_lock is held as reader to ensure no new
	 * ills or new ipifs can be added while we are checking availability.
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	mutex_enter(&ipst->ips_ip_addr_avail_lock);
	ill->ill_ipif_up_count++;
	ipif->ipif_flags |= IPIF_UP;
	err = ip_addr_availability_check(ipif);
	mutex_exit(&ipst->ips_ip_addr_avail_lock);
	rw_exit(&ipst->ips_ill_g_lock);

	if (err != 0) {
		/*
		 * Our address may already be up on the same ill. In this case,
		 * the external resolver entry for our ipif replaced the one for
		 * the other ipif. So we don't want to delete it (otherwise the
		 * other ipif would be unable to send packets).
		 * ip_addr_availability_check() identifies this case for us and
		 * returns EADDRINUSE; we need to turn it into EADDRNOTAVAIL
		 * which is the expected error code.
		 */
		if (err == EADDRINUSE) {
			if (ipif->ipif_ill->ill_flags & ILLF_XRESOLV) {
				freemsg(ipif->ipif_arp_del_mp);
				ipif->ipif_arp_del_mp = NULL;
			}
			err = EADDRNOTAVAIL;
		}
		ill->ill_ipif_up_count--;
		ipif->ipif_flags &= ~IPIF_UP;
		goto bad;
	}

	/*
	 * Add in all newly created IREs.
	 *
	 * NOTE : We refrele the ire though we may branch to "bad"
	 *	  later on where we do ire_delete. This is okay
	 *	  because nobody can delete it as we are running
	 *	  exclusively.
	 */
	for (irep1 = irep; irep1 > ire_array; ) {
		irep1--;
		/* Shouldn't be adding any bcast ire's */
		ASSERT((*irep1)->ire_type != IRE_BROADCAST);
		ASSERT(!MUTEX_HELD(&ipif->ipif_ill->ill_lock));
		/*
		 * refheld by ire_add. refele towards the end of the func
		 */
		(void) ire_add(irep1, NULL, NULL, NULL, B_FALSE);
	}
	if (ip6_asp_table_held) {
		ip6_asp_table_refrele(ipst);
		ip6_asp_table_held = B_FALSE;
	}

	/* Recover any additional IRE_IF_[NO]RESOLVER entries for this ipif */
	ipif_saved_ire_cnt = ipif->ipif_saved_ire_cnt;
	ipif_saved_irep = ipif_recover_ire_v6(ipif);

	if (ill->ill_need_recover_multicast) {
		/*
		 * Need to recover all multicast memberships in the driver.
		 * This had to be deferred until we had attached.
		 */
		ill_recover_multicast(ill);
	}

	if (ill->ill_ipif_up_count == 1) {
		/*
		 * Since the interface is now up, it may now be active.
		 */
		if (IS_UNDER_IPMP(ill))
			ipmp_ill_refresh_active(ill);
	}

	/* Join the allhosts multicast address and the solicited node MC */
	ipif_multicast_up(ipif);

	/*
	 * See if anybody else would benefit from our new ipif.
	 */
	if (!loopback &&
	    !(ipif->ipif_flags & (IPIF_NOLOCAL|IPIF_ANYCAST|IPIF_DEPRECATED))) {
		ill_update_source_selection(ill);
	}

	for (irep1 = irep; irep1 > ire_array; ) {
		irep1--;
		if (*irep1 != NULL) {
			/* was held in ire_add */
			ire_refrele(*irep1);
		}
	}

	cnt = ipif_saved_ire_cnt;
	for (irep1 = ipif_saved_irep; cnt > 0; irep1++, cnt--) {
		if (*irep1 != NULL) {
			/* was held in ire_add */
			ire_refrele(*irep1);
		}
	}

	if (ipif->ipif_addr_ready)
		ipif_up_notify(ipif);

	if (ipif_saved_irep != NULL) {
		kmem_free(ipif_saved_irep,
		    ipif_saved_ire_cnt * sizeof (ire_t *));
	}

	if (src_ipif_held)
		ipif_refrele(src_ipif);

	return (0);

bad:
	if (ip6_asp_table_held)
		ip6_asp_table_refrele(ipst);

	while (irep > ire_array) {
		irep--;
		if (*irep != NULL)
			ire_delete(*irep);
	}
	(void) ip_srcid_remove(&ipif->ipif_v6lcl_addr, ipif->ipif_zoneid, ipst);

	if (ipif_saved_irep != NULL) {
		kmem_free(ipif_saved_irep,
		    ipif_saved_ire_cnt * sizeof (ire_t *));
	}
	if (src_ipif_held)
		ipif_refrele(src_ipif);

	ipif_ndp_down(ipif);
	ipif_resolver_down(ipif);

	return (err);
}

/*
 * Delete an ND entry and the corresponding IRE_CACHE entry if it exists.
 */
/* ARGSUSED */
int
ip_siocdelndp_v6(ipif_t *ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	sin6_t		*sin6;
	nce_t		*nce;
	struct lifreq	*lifr;
	lif_nd_req_t	*lnr;
	ill_t		*ill = ipif->ipif_ill;
	ire_t		*ire;

	lifr = (struct lifreq *)mp->b_cont->b_cont->b_rptr;
	lnr = &lifr->lifr_nd;
	/* Only allow for logical unit zero i.e. not on "le0:17" */
	if (ipif->ipif_id != 0)
		return (EINVAL);

	if (!ipif->ipif_isv6)
		return (EINVAL);

	if (lnr->lnr_addr.ss_family != AF_INET6)
		return (EAFNOSUPPORT);

	sin6 = (sin6_t *)&lnr->lnr_addr;

	/*
	 * Since ND mappings must be consistent across an IPMP group, prohibit
	 * deleting ND mappings on underlying interfaces.  Also, since ND
	 * mappings for IPMP data addresses are owned by IP itself, prohibit
	 * deleting them.
	 */
	if (IS_UNDER_IPMP(ill))
		return (EPERM);

	if (IS_IPMP(ill)) {
		ire = ire_ctable_lookup_v6(&sin6->sin6_addr, NULL, IRE_LOCAL,
		    ipif, ALL_ZONES, NULL, MATCH_IRE_TYPE | MATCH_IRE_ILL,
		    ill->ill_ipst);
		if (ire != NULL) {
			ire_refrele(ire);
			return (EPERM);
		}
	}

	/* See comment in ndp_query() regarding IS_IPMP(ill) usage */
	nce = ndp_lookup_v6(ill, IS_IPMP(ill), &sin6->sin6_addr, B_FALSE);
	if (nce == NULL)
		return (ESRCH);
	ndp_delete(nce);
	NCE_REFRELE(nce);
	return (0);
}

/*
 * Return nbr cache info.
 */
/* ARGSUSED */
int
ip_siocqueryndp_v6(ipif_t *ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	ill_t		*ill = ipif->ipif_ill;
	struct lifreq	*lifr;
	lif_nd_req_t	*lnr;

	lifr = (struct lifreq *)mp->b_cont->b_cont->b_rptr;
	lnr = &lifr->lifr_nd;
	/* Only allow for logical unit zero i.e. not on "le0:17" */
	if (ipif->ipif_id != 0)
		return (EINVAL);

	if (!ipif->ipif_isv6)
		return (EINVAL);

	if (lnr->lnr_addr.ss_family != AF_INET6)
		return (EAFNOSUPPORT);

	if (ill->ill_phys_addr_length > sizeof (lnr->lnr_hdw_addr))
		return (EINVAL);

	return (ndp_query(ill, lnr));
}

/*
 * Perform an update of the nd entry for the specified address.
 */
/* ARGSUSED */
int
ip_siocsetndp_v6(ipif_t *ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	sin6_t		*sin6;
	ill_t		*ill = ipif->ipif_ill;
	struct	lifreq	*lifr;
	lif_nd_req_t	*lnr;
	ire_t		*ire;

	lifr = (struct lifreq *)mp->b_cont->b_cont->b_rptr;
	lnr = &lifr->lifr_nd;
	/* Only allow for logical unit zero i.e. not on "le0:17" */
	if (ipif->ipif_id != 0)
		return (EINVAL);

	if (!ipif->ipif_isv6)
		return (EINVAL);

	if (lnr->lnr_addr.ss_family != AF_INET6)
		return (EAFNOSUPPORT);

	sin6 = (sin6_t *)&lnr->lnr_addr;

	/*
	 * Since ND mappings must be consistent across an IPMP group, prohibit
	 * updating ND mappings on underlying interfaces.  Also, since ND
	 * mappings for IPMP data addresses are owned by IP itself, prohibit
	 * updating them.
	 */
	if (IS_UNDER_IPMP(ill))
		return (EPERM);

	if (IS_IPMP(ill)) {
		ire = ire_ctable_lookup_v6(&sin6->sin6_addr, NULL, IRE_LOCAL,
		    ipif, ALL_ZONES, NULL, MATCH_IRE_TYPE | MATCH_IRE_ILL,
		    ill->ill_ipst);
		if (ire != NULL) {
			ire_refrele(ire);
			return (EPERM);
		}
	}

	return (ndp_sioc_update(ill, lnr));
}
