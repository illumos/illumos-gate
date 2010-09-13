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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <inet/tunables.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_multi.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <inet/ip_ndp.h>
#include <inet/ip_if.h>
#include <inet/ip6_asp.h>
#include <inet/ipclassifier.h>
#include <inet/sctp_ip.h>

#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>

static in6_addr_t	ipv6_ll_template =
			{(uint32_t)V6_LINKLOCAL, 0x0, 0x0, 0x0};

static ipif_t *
ipif_lookup_interface_v6(const in6_addr_t *if_addr, const in6_addr_t *dst,
    ip_stack_t *ipst);

static int	ipif_add_ires_v6(ipif_t *, boolean_t);

/*
 * This function is called when an application does not specify an interface
 * to be used for multicast traffic.  It calls ire_lookup_multi_v6() to look
 * for an interface route for the specified multicast group.  Doing
 * this allows the administrator to add prefix routes for multicast to
 * indicate which interface to be used for multicast traffic in the above
 * scenario.  The route could be for all multicast (ff00::/8), for a single
 * multicast group (a /128 route) or anything in between.  If there is no
 * such multicast route, we just find any multicast capable interface and
 * return it.
 *
 * We support MULTIRT and RTF_SETSRC on the multicast routes added to the
 * unicast table. This is used by CGTP.
 */
ill_t *
ill_lookup_group_v6(const in6_addr_t *group, zoneid_t zoneid, ip_stack_t *ipst,
    boolean_t *multirtp, in6_addr_t *setsrcp)
{
	ill_t	*ill;

	ill = ire_lookup_multi_ill_v6(group, zoneid, ipst, multirtp, setsrcp);
	if (ill != NULL)
		return (ill);

	return (ill_lookup_multicast(ipst, zoneid, B_TRUE));
}

/*
 * Look for an ipif with the specified interface address and destination.
 * The destination address is used only for matching point-to-point interfaces.
 */
static ipif_t *
ipif_lookup_interface_v6(const in6_addr_t *if_addr, const in6_addr_t *dst,
    ip_stack_t *ipst)
{
	ipif_t	*ipif;
	ill_t	*ill;
	ill_walk_context_t ctx;

	/*
	 * First match all the point-to-point interfaces
	 * before looking at non-point-to-point interfaces.
	 * This is done to avoid returning non-point-to-point
	 * ipif instead of unnumbered point-to-point ipif.
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V6(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			/* Allow the ipif to be down */
			if ((ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    (IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6lcl_addr,
			    if_addr)) &&
			    (IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6pp_dst_addr,
			    dst))) {
				if (!IPIF_IS_CONDEMNED(ipif)) {
					ipif_refhold_locked(ipif);
					mutex_exit(&ill->ill_lock);
					rw_exit(&ipst->ips_ill_g_lock);
					return (ipif);
				}
			}
		}
		mutex_exit(&ill->ill_lock);
	}
	rw_exit(&ipst->ips_ill_g_lock);
	/* lookup the ipif based on interface address */
	ipif = ipif_lookup_addr_v6(if_addr, NULL, ALL_ZONES, ipst);
	ASSERT(ipif == NULL || ipif->ipif_isv6);
	return (ipif);
}

/*
 * Common function for ipif_lookup_addr_v6() and ipif_lookup_addr_exact_v6().
 */
static ipif_t *
ipif_lookup_addr_common_v6(const in6_addr_t *addr, ill_t *match_ill,
    uint32_t match_flags, zoneid_t zoneid, ip_stack_t *ipst)
{
	ipif_t	*ipif;
	ill_t	*ill;
	boolean_t  ptp = B_FALSE;
	ill_walk_context_t ctx;
	boolean_t match_illgrp = (match_flags & IPIF_MATCH_ILLGRP);
	boolean_t no_duplicate = (match_flags & IPIF_MATCH_NONDUP);

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
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (zoneid != ALL_ZONES &&
			    ipif->ipif_zoneid != zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;

			if (no_duplicate &&
			    !(ipif->ipif_flags & IPIF_UP)) {
				continue;
			}

			/* Allow the ipif to be down */
			if ((!ptp && (IN6_ARE_ADDR_EQUAL(
			    &ipif->ipif_v6lcl_addr, addr) &&
			    (ipif->ipif_flags & IPIF_UNNUMBERED) == 0)) ||
			    (ptp && (ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6pp_dst_addr,
			    addr))) {
				if (!IPIF_IS_CONDEMNED(ipif)) {
					ipif_refhold_locked(ipif);
					mutex_exit(&ill->ill_lock);
					rw_exit(&ipst->ips_ill_g_lock);
					return (ipif);
				}
			}
		}
		mutex_exit(&ill->ill_lock);
	}

	/* If we already did the ptp case, then we are done */
	if (ptp) {
		rw_exit(&ipst->ips_ill_g_lock);
		return (NULL);
	}
	ptp = B_TRUE;
	goto repeat;
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
    ip_stack_t *ipst)
{
	return (ipif_lookup_addr_common_v6(addr, match_ill, IPIF_MATCH_ILLGRP,
	    zoneid, ipst));
}

/*
 * Lookup an ipif with the specified address. Similar to ipif_lookup_addr,
 * except that we will only return an address if it is not marked as
 * IPIF_DUPLICATE
 */
ipif_t *
ipif_lookup_addr_nondup_v6(const in6_addr_t *addr, ill_t *match_ill,
    zoneid_t zoneid, ip_stack_t *ipst)
{
	return (ipif_lookup_addr_common_v6(addr, match_ill,
	    (IPIF_MATCH_ILLGRP | IPIF_MATCH_NONDUP), zoneid,
	    ipst));
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
	return (ipif_lookup_addr_common_v6(addr, match_ill, 0, ALL_ZONES,
	    ipst));
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
 * ill is passed in to associate it with the correct interface
 * (for link-local destinations and gateways).
 * If ire_arg is set, then we return the held IRE in that location.
 */
/* ARGSUSED1 */
int
ip_rt_add_v6(const in6_addr_t *dst_addr, const in6_addr_t *mask,
    const in6_addr_t *gw_addr, const in6_addr_t *src_addr, int flags,
    ill_t *ill, ire_t **ire_arg, struct rtsa_s *sp, ip_stack_t *ipst,
    zoneid_t zoneid)
{
	ire_t	*ire, *nire;
	ire_t	*gw_ire = NULL;
	ipif_t	*ipif;
	uint_t	type;
	int	match_flags = MATCH_IRE_TYPE;
	tsol_gc_t *gc = NULL;
	tsol_gcgrp_t *gcgrp = NULL;
	boolean_t gcgrp_xtraref = B_FALSE;
	boolean_t unbound = B_FALSE;

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
	 * If -ifp was specified we restrict ourselves to the ill, otherwise
	 * we match on the gatway and destination to handle unnumbered pt-pt
	 * interfaces.
	 */
	if (ill != NULL)
		ipif = ipif_lookup_addr_v6(gw_addr, ill, ALL_ZONES, ipst);
	else
		ipif = ipif_lookup_interface_v6(gw_addr, dst_addr, ipst);
	if (ipif != NULL) {
		if (IS_VNI(ipif->ipif_ill)) {
			ipif_refrele(ipif);
			return (EINVAL);
		}
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
			ire = ire_ftable_lookup_v6(dst_addr, 0, 0, IRE_LOOPBACK,
			    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, 0, ipst,
			    NULL);
			if (ire != NULL) {
				ire_refrele(ire);
				ipif_refrele(ipif);
				return (EEXIST);
			}
			ip1dbg(("ip_rt_add_v6: 0x%p creating IRE 0x%x"
			    "for 0x%x\n", (void *)ipif,
			    ipif->ipif_ire_type,
			    ntohl(ipif->ipif_lcl_addr)));
			ire = ire_create_v6(
			    dst_addr,
			    mask,
			    NULL,
			    ipif->ipif_ire_type,	/* LOOPBACK */
			    ipif->ipif_ill,
			    zoneid,
			    (ipif->ipif_flags & IPIF_PRIVATE) ? RTF_PRIVATE : 0,
			    NULL,
			    ipst);

			if (ire == NULL) {
				ipif_refrele(ipif);
				return (ENOMEM);
			}
			/* src address assigned by the caller? */
			if ((flags & RTF_SETSRC) &&
			    !IN6_IS_ADDR_UNSPECIFIED(src_addr))
				ire->ire_setsrc_addr_v6 = *src_addr;

			nire = ire_add(ire);
			if (nire == NULL) {
				/*
				 * In the result of failure, ire_add() will have
				 * already deleted the ire in question, so there
				 * is no need to do that here.
				 */
				ipif_refrele(ipif);
				return (ENOMEM);
			}
			/*
			 * Check if it was a duplicate entry. This handles
			 * the case of two racing route adds for the same route
			 */
			if (nire != ire) {
				ASSERT(nire->ire_identical_ref > 1);
				ire_delete(nire);
				ire_refrele(nire);
				ipif_refrele(ipif);
				return (EEXIST);
			}
			ire = nire;
			goto save_ire;
		}
	}

	/*
	 * The routes for multicast with CGTP are quite special in that
	 * the gateway is the local interface address, yet RTF_GATEWAY
	 * is set. We turn off RTF_GATEWAY to provide compatibility with
	 * this undocumented and unusual use of multicast routes.
	 */
	if ((flags & RTF_MULTIRT) && ipif != NULL)
		flags &= ~RTF_GATEWAY;

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
	 *	192.0.2.32	255.255.255.224	192.0.2.34	U	if0
	 *	192.0.2.32	255.255.255.224	192.0.2.35	U	if0
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
		if (sp != NULL) {
			ip2dbg(("ip_rt_add_v6: gateway security attributes "
			    "cannot be set with interface route\n"));
			if (ipif != NULL)
				ipif_refrele(ipif);
			return (EINVAL);
		}

		/*
		 * Whether or not ill (RTA_IFP) is set, we require that
		 * the gateway is one of our local addresses.
		 */
		if (ipif == NULL)
			return (ENETUNREACH);

		/*
		 * We use MATCH_IRE_ILL here. If the caller specified an
		 * interface (from the RTA_IFP sockaddr) we use it, otherwise
		 * we use the ill derived from the gateway address.
		 * We can always match the gateway address since we record it
		 * in ire_gateway_addr.
		 * We don't allow RTA_IFP to specify a different ill than the
		 * one matching the ipif to make sure we can delete the route.
		 */
		match_flags |= MATCH_IRE_GW | MATCH_IRE_ILL;
		if (ill == NULL) {
			ill = ipif->ipif_ill;
		} else if (ill != ipif->ipif_ill) {
			ipif_refrele(ipif);
			return (EINVAL);
		}

		/*
		 * We check for an existing entry at this point.
		 */
		match_flags |= MATCH_IRE_MASK;
		ire = ire_ftable_lookup_v6(dst_addr, mask, gw_addr,
		    IRE_INTERFACE, ill, ALL_ZONES, NULL, match_flags, 0, ipst,
		    NULL);
		if (ire != NULL) {
			ire_refrele(ire);
			ipif_refrele(ipif);
			return (EEXIST);
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
		 * If the IRE type (as defined by ill->ill_net_type) would be
		 * IRE_LOOPBACK, then we map the request into a
		 * IRE_IF_NORESOLVER.
		 *
		 * Needless to say, the real IRE_LOOPBACK is NOT created by this
		 * routine, but rather using ire_create_v6() directly.
		 */
		type = ill->ill_net_type;
		if (type == IRE_LOOPBACK) {
			type = IRE_IF_NORESOLVER;
			flags |= RTF_BLACKHOLE;
		}

		/*
		 * Create a copy of the IRE_IF_NORESOLVER or
		 * IRE_IF_RESOLVER with the modified address, netmask, and
		 * gateway.
		 */
		ire = ire_create_v6(
		    dst_addr,
		    mask,
		    gw_addr,
		    type,
		    ill,
		    zoneid,
		    flags,
		    NULL,
		    ipst);
		if (ire == NULL) {
			ipif_refrele(ipif);
			return (ENOMEM);
		}

		/* src address assigned by the caller? */
		if ((flags & RTF_SETSRC) && !IN6_IS_ADDR_UNSPECIFIED(src_addr))
			ire->ire_setsrc_addr_v6 = *src_addr;

		nire = ire_add(ire);
		if (nire == NULL) {
			/*
			 * In the result of failure, ire_add() will have
			 * already deleted the ire in question, so there
			 * is no need to do that here.
			 */
			ipif_refrele(ipif);
			return (ENOMEM);
		}
		/*
		 * Check if it was a duplicate entry. This handles
		 * the case of two racing route adds for the same route
		 */
		if (nire != ire) {
			ASSERT(nire->ire_identical_ref > 1);
			ire_delete(nire);
			ire_refrele(nire);
			ipif_refrele(ipif);
			return (EEXIST);
		}
		ire = nire;
		goto save_ire;
	}

	/*
	 * Get an interface IRE for the specified gateway.
	 * If we don't have an IRE_IF_NORESOLVER or IRE_IF_RESOLVER for the
	 * gateway, it is currently unreachable and we fail the request
	 * accordingly. We reject any RTF_GATEWAY routes where the gateway
	 * is an IRE_LOCAL or IRE_LOOPBACK.
	 * If RTA_IFP was specified we look on that particular ill.
	 */
	if (ill != NULL)
		match_flags |= MATCH_IRE_ILL;

	/* Check whether the gateway is reachable. */
again:
	type = IRE_INTERFACE | IRE_LOCAL | IRE_LOOPBACK;
	if (flags & RTF_INDIRECT)
		type |= IRE_OFFLINK;

	gw_ire = ire_ftable_lookup_v6(gw_addr, 0, 0, type, ill,
	    ALL_ZONES, NULL, match_flags, 0, ipst, NULL);
	if (gw_ire == NULL) {
		/*
		 * With IPMP, we allow host routes to influence in.mpathd's
		 * target selection.  However, if the test addresses are on
		 * their own network, the above lookup will fail since the
		 * underlying IRE_INTERFACEs are marked hidden.  So allow
		 * hidden test IREs to be found and try again.
		 */
		if (!(match_flags & MATCH_IRE_TESTHIDDEN))  {
			match_flags |= MATCH_IRE_TESTHIDDEN;
			goto again;
		}
		if (ipif != NULL)
			ipif_refrele(ipif);
		return (ENETUNREACH);
	}
	if (gw_ire->ire_type & (IRE_LOCAL|IRE_LOOPBACK)) {
		ire_refrele(gw_ire);
		if (ipif != NULL)
			ipif_refrele(ipif);
		return (ENETUNREACH);
	}
	if (ill == NULL && !(flags & RTF_INDIRECT)) {
		unbound = B_TRUE;
		if (ipst->ips_ipv6_strict_src_multihoming > 0)
			ill = gw_ire->ire_ill;
	}

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
	ire = ire_ftable_lookup_v6(dst_addr, mask, gw_addr, type, ill,
	    ALL_ZONES, NULL,
	    match_flags | MATCH_IRE_MASK | MATCH_IRE_GW, 0, ipst, NULL);
	if (ire != NULL) {
		if (ipif != NULL)
			ipif_refrele(ipif);
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
			if (ipif != NULL)
				ipif_refrele(ipif);
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
			if (ipif != NULL)
				ipif_refrele(ipif);
			ire_refrele(gw_ire);
			return (ENOMEM);
		}
	}

	/* Create the IRE. */
	ire = ire_create_v6(
	    dst_addr,				/* dest address */
	    mask,				/* mask */
	    gw_addr,				/* gateway address */
	    (ushort_t)type,			/* IRE type */
	    ill,
	    zoneid,
	    flags,
	    gc,					/* security attribute */
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
		if (ipif != NULL)
			ipif_refrele(ipif);
		ire_refrele(gw_ire);
		return (ENOMEM);
	}

	/* src address assigned by the caller? */
	if ((flags & RTF_SETSRC) && !IN6_IS_ADDR_UNSPECIFIED(src_addr))
		ire->ire_setsrc_addr_v6 = *src_addr;

	ire->ire_unbound = unbound;

	/*
	 * POLICY: should we allow an RTF_HOST with address INADDR_ANY?
	 * SUN/OS socket stuff does but do we really want to allow ::0 ?
	 */

	/* Add the new IRE. */
	nire = ire_add(ire);
	if (nire == NULL) {
		/*
		 * In the result of failure, ire_add() will have
		 * already deleted the ire in question, so there
		 * is no need to do that here.
		 */
		if (ipif != NULL)
			ipif_refrele(ipif);
		ire_refrele(gw_ire);
		return (ENOMEM);
	}
	/*
	 * Check if it was a duplicate entry. This handles
	 * the case of two racing route adds for the same route
	 */
	if (nire != ire) {
		ASSERT(nire->ire_identical_ref > 1);
		ire_delete(nire);
		ire_refrele(nire);
		if (ipif != NULL)
			ipif_refrele(ipif);
		ire_refrele(gw_ire);
		return (EEXIST);
	}
	ire = nire;

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
			ipif_t *src_ipif;

			/* Find the source address corresponding to gw_ire */
			src_ipif = ipif_lookup_addr_v6(
			    &gw_ire->ire_gateway_addr_v6, NULL, zoneid, ipst);
			if (src_ipif != NULL) {
				res = ipst->ips_ip_cgtp_filter_ops->
				    cfo_add_dest_v6(
				    ipst->ips_netstack->netstack_stackid,
				    &ire->ire_addr_v6,
				    &ire->ire_gateway_addr_v6,
				    &ire->ire_setsrc_addr_v6,
				    &src_ipif->ipif_v6lcl_addr);
				ipif_refrele(src_ipif);
			} else {
				res = EADDRNOTAVAIL;
			}
			if (res != 0) {
				if (ipif != NULL)
					ipif_refrele(ipif);
				ire_refrele(gw_ire);
				ire_delete(ire);
				ire_refrele(ire);	/* Held in ire_add */
				return (res);
			}
		}
	}

save_ire:
	if (gw_ire != NULL) {
		ire_refrele(gw_ire);
		gw_ire = NULL;
	}
	if (ire->ire_ill != NULL) {
		/*
		 * Save enough information so that we can recreate the IRE if
		 * the ILL goes down and then up.  The metrics associated
		 * with the route will be saved as well when rts_setmetrics() is
		 * called after the IRE has been created.  In the case where
		 * memory cannot be allocated, none of this information will be
		 * saved.
		 */
		ill_save_ire(ire->ire_ill, ire);
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
	if (ipif != NULL)
		ipif_refrele(ipif);
	return (0);
}

/*
 * ip_rt_delete_v6 is called to delete an IPv6 route.
 * ill is passed in to associate it with the correct interface.
 * (for link-local destinations and gateways).
 */
/* ARGSUSED4 */
int
ip_rt_delete_v6(const in6_addr_t *dst_addr, const in6_addr_t *mask,
    const in6_addr_t *gw_addr, uint_t rtm_addrs, int flags, ill_t *ill,
    ip_stack_t *ipst, zoneid_t zoneid)
{
	ire_t	*ire = NULL;
	ipif_t	*ipif;
	uint_t	type;
	uint_t	match_flags = MATCH_IRE_TYPE;
	int	err = 0;

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
	 * However, we have RTF_KERNEL set on the ones created by ipif_up
	 * and those can not be deleted here.
	 *
	 * We use MATCH_IRE_ILL if we know the interface. If the caller
	 * specified an interface (from the RTA_IFP sockaddr) we use it,
	 * otherwise we use the ill derived from the gateway address.
	 * We can always match the gateway address since we record it
	 * in ire_gateway_addr.
	 *
	 * For more detail on specifying routes by gateway address and by
	 * interface index, see the comments in ip_rt_add_v6().
	 */
	ipif = ipif_lookup_interface_v6(gw_addr, dst_addr, ipst);
	if (ipif != NULL) {
		ill_t	*ill_match;

		if (ill != NULL)
			ill_match = ill;
		else
			ill_match = ipif->ipif_ill;

		match_flags |= MATCH_IRE_ILL;
		if (ipif->ipif_ire_type == IRE_LOOPBACK) {
			ire = ire_ftable_lookup_v6(dst_addr, mask, 0,
			    IRE_LOOPBACK, ill_match, ALL_ZONES, NULL,
			    match_flags, 0, ipst, NULL);
		}
		if (ire == NULL) {
			match_flags |= MATCH_IRE_GW;
			ire = ire_ftable_lookup_v6(dst_addr, mask, gw_addr,
			    IRE_INTERFACE, ill_match, ALL_ZONES, NULL,
			    match_flags, 0, ipst, NULL);
		}
		/* Avoid deleting routes created by kernel from an ipif */
		if (ire != NULL && (ire->ire_flags & RTF_KERNEL)) {
			ire_refrele(ire);
			ire = NULL;
		}

		/* Restore in case we didn't find a match */
		match_flags &= ~(MATCH_IRE_GW|MATCH_IRE_ILL);
	}

	if (ire == NULL) {
		/*
		 * At this point, the gateway address is not one of our own
		 * addresses or a matching interface route was not found.  We
		 * set the IRE type to lookup based on whether
		 * this is a host route, a default route or just a prefix.
		 *
		 * If an ill was passed in, then the lookup is based on an
		 * interface index so MATCH_IRE_ILL is added to match_flags.
		 */
		match_flags |= MATCH_IRE_GW;
		if (ill != NULL)
			match_flags |= MATCH_IRE_ILL;
		if (IN6_ARE_ADDR_EQUAL(mask, &ipv6_all_ones))
			type = IRE_HOST;
		else if (IN6_IS_ADDR_UNSPECIFIED(mask))
			type = IRE_DEFAULT;
		else
			type = IRE_PREFIX;
		ire = ire_ftable_lookup_v6(dst_addr, mask, gw_addr, type,
		    ill, ALL_ZONES, NULL, match_flags, 0, ipst, NULL);
	}

	if (ipif != NULL) {
		ipif_refrele(ipif);
		ipif = NULL;
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

	ill = ire->ire_ill;
	if (ill != NULL)
		ill_remove_saved_ire(ill, ire);
	ire_delete(ire);
	ire_refrele(ire);
	return (err);
}

/*
 * Derive an interface id from the link layer address.
 */
void
ill_setdefaulttoken(ill_t *ill)
{
	if (!ill->ill_manual_token) {
		bzero(&ill->ill_token, sizeof (ill->ill_token));
		MEDIA_V6INTFID(ill->ill_media, ill, &ill->ill_token);
		ill->ill_token_length = IPV6_TOKEN_LEN;
	}
}

void
ill_setdesttoken(ill_t *ill)
{
	bzero(&ill->ill_dest_token, sizeof (ill->ill_dest_token));
	MEDIA_V6DESTINTFID(ill->ill_media, ill, &ill->ill_dest_token);
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
 * Set a default IPv6 address for a 6to4 tunnel interface 2002:<tsrc>::1/16
 */
static void
ipif_set6to4addr(ipif_t *ipif)
{
	ill_t		*ill = ipif->ipif_ill;
	struct in_addr	v4phys;

	ASSERT(ill->ill_mactype == DL_6TO4);
	ASSERT(ill->ill_phys_addr_length == sizeof (struct in_addr));
	ASSERT(ipif->ipif_isv6);

	if (ipif->ipif_flags & IPIF_UP)
		return;

	(void) ip_plen_to_mask_v6(16, &ipif->ipif_v6net_mask);
	bcopy(ill->ill_phys_addr, &v4phys, sizeof (struct in_addr));
	IN6_V4ADDR_TO_6TO4(&v4phys, &ipif->ipif_v6lcl_addr);
	V6_MASK_COPY(ipif->ipif_v6lcl_addr, ipif->ipif_v6net_mask,
	    ipif->ipif_v6subnet);
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
 */
void
ipif_setlinklocal(ipif_t *ipif)
{
	ill_t		*ill = ipif->ipif_ill;
	in6_addr_t	ov6addr;

	ASSERT(IAM_WRITER_ILL(ill));

	/*
	 * If the interface was created with no link-local address
	 * on it and the flag ILLF_NOLINKLOCAL was set, then we
	 * dont want to update the link-local.
	 */
	if ((ill->ill_flags & ILLF_NOLINKLOCAL) &&
	    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr))
		return;
	/*
	 * ill_manual_linklocal is set when the link-local address was
	 * manually configured.
	 */
	if (ill->ill_manual_linklocal)
		return;

	/*
	 * IPv6 interfaces over 6to4 tunnels are special.  They do not have
	 * link-local addresses, but instead have a single automatically
	 * generated global address.
	 */
	if (ill->ill_mactype == DL_6TO4) {
		ipif_set6to4addr(ipif);
		return;
	}

	if (ipif_cant_setlinklocal(ipif))
		return;

	ov6addr = ipif->ipif_v6lcl_addr;
	ipif_get_linklocal(&ipif->ipif_v6lcl_addr, &ill->ill_token);
	sctp_update_ipif_addr(ipif, ov6addr);
	(void) ip_plen_to_mask_v6(IPV6_LL_PREFIXLEN, &ipif->ipif_v6net_mask);
	if (IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6pp_dst_addr)) {
		V6_MASK_COPY(ipif->ipif_v6lcl_addr, ipif->ipif_v6net_mask,
		    ipif->ipif_v6subnet);
	}

	ip_rts_newaddrmsg(RTM_CHGADDR, 0, ipif, RTSQ_DEFAULT);
}

/*
 * Generate a destination link-local address for a point-to-point IPv6
 * interface with a destination interface id (IP tunnels are such interfaces)
 * based on the destination token.
 */
void
ipif_setdestlinklocal(ipif_t *ipif)
{
	ill_t	*ill = ipif->ipif_ill;

	ASSERT(IAM_WRITER_ILL(ill));

	if (ill->ill_manual_dst_linklocal)
		return;

	if (IN6_IS_ADDR_UNSPECIFIED(&ill->ill_dest_token))
		return;

	ipif_get_linklocal(&ipif->ipif_v6pp_dst_addr, &ill->ill_dest_token);
	ipif->ipif_v6subnet = ipif->ipif_v6pp_dst_addr;
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
	boolean_t	added_ipif = B_FALSE;

	DTRACE_PROBE3(ipif__downup, char *, "ipif_ndp_up",
	    ill_t *, ill, ipif_t *, ipif);
	ip1dbg(("ipif_ndp_up(%s:%u)\n", ill->ill_name, ipif->ipif_id));

	if (IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr) ||
	    (!(ill->ill_net_type & IRE_INTERFACE))) {
		ipif->ipif_addr_ready = 1;
		return (0);
	}

	if ((ipif->ipif_flags & (IPIF_UNNUMBERED|IPIF_NOLOCAL)) == 0) {
		uint16_t	flags;
		uint16_t	state;
		uchar_t		*hw_addr;
		ill_t		*bound_ill;
		ipmp_illgrp_t	*illg = ill->ill_grp;
		uint_t		hw_addr_len;

		flags = NCE_F_MYADDR | NCE_F_NONUD | NCE_F_PUBLISH |
		    NCE_F_AUTHORITY;
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
			hw_addr_len = bound_ill->ill_phys_addr_length;
		} else {
			bound_ill = ill;
			hw_addr = ill->ill_nd_lla;
			hw_addr_len = ill->ill_phys_addr_length;
		}

		/*
		 * If this is an initial bring-up (or the ipif was never
		 * completely brought up), do DAD.  Otherwise, we're here
		 * because IPMP has rebound an address to this ill: send
		 * unsolicited advertisements to inform others.
		 */
		if (initial || !ipif->ipif_addr_ready) {
			/* Causes Duplicate Address Detection to run */
			state = ND_PROBE;
		} else {
			state = ND_REACHABLE;
			flags |= NCE_F_UNSOL_ADV;
		}

retry:
		err = nce_lookup_then_add_v6(ill, hw_addr, hw_addr_len,
		    &ipif->ipif_v6lcl_addr, flags, state, &nce);
		switch (err) {
		case 0:
			ip1dbg(("ipif_ndp_up: NCE created for %s\n",
			    ill->ill_name));
			ipif->ipif_addr_ready = 1;
			ipif->ipif_added_nce = 1;
			nce->nce_ipif_cnt++;
			break;
		case EINPROGRESS:
			ip1dbg(("ipif_ndp_up: running DAD now for %s\n",
			    ill->ill_name));
			ipif->ipif_added_nce = 1;
			nce->nce_ipif_cnt++;
			break;
		case EEXIST:
			ip1dbg(("ipif_ndp_up: NCE already exists for %s\n",
			    ill->ill_name));
			if (!NCE_MYADDR(nce->nce_common)) {
				/*
				 * A leftover nce from before this address
				 * existed
				 */
				ncec_delete(nce->nce_common);
				nce_refrele(nce);
				nce = NULL;
				goto retry;
			}
			if ((ipif->ipif_flags & IPIF_POINTOPOINT) == 0) {
				nce_refrele(nce);
				nce = NULL;
				ip1dbg(("ipif_ndp_up: NCE already exists "
				    "for %s\n", ill->ill_name));
				goto fail;
			}
			/*
			 * Duplicate local addresses are permissible for
			 * IPIF_POINTOPOINT interfaces which will get marked
			 * IPIF_UNNUMBERED later in
			 * ip_addr_availability_check().
			 *
			 * The nce_ipif_cnt field tracks the number of
			 * ipifs that have nce_addr as their local address.
			 */
			ipif->ipif_addr_ready = 1;
			ipif->ipif_added_nce = 1;
			nce->nce_ipif_cnt++;
			err = 0;
			break;
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
		nce_refrele(nce);
	return (0);
fail:
	if (added_ipif)
		ipmp_illgrp_del_ipif(ill->ill_grp, ipif);

	return (err);
}

/* Remove all cache entries for this logical interface */
void
ipif_ndp_down(ipif_t *ipif)
{
	ipif_nce_down(ipif);
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
	!((ipif)->ipif_ill->ill_flags & ILLF_NOACCEPT))

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
 * connected socket (from ip_set_destination_v6()), then the preferences are
 * taken from conn_ixa->ixa_src_preferences.  These preferences can be set on a
 * per-socket basis using the IPV6_SRC_PREFERENCES socket option.  The only
 * preference currently implemented is for rfc3041 temporary addresses.
 */
ipif_t *
ipif_select_source_v6(ill_t *dstill, const in6_addr_t *dst,
    boolean_t restrict_ill, uint32_t src_prefs, zoneid_t zoneid,
    boolean_t allow_usesrc, boolean_t *notreadyp)
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
	if (dstill->ill_usesrc_ifindex != 0 && allow_usesrc) {
		if ((usesrc_ill =
		    ill_lookup_on_ifindex(dstill->ill_usesrc_ifindex, B_TRUE,
		    ipst)) != NULL) {
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

		if (ill->ill_ipif == NULL)
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

			if (!ipif->ipif_addr_ready) {
				if (notreadyp != NULL)
					*notreadyp = B_TRUE;
				continue;
			}

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
			if (next_ipif != NULL && !IPIF_IS_CONDEMNED(next_ipif))
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
	if (!IPIF_IS_CONDEMNED(ipif)) {
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
 * Pick a source address based on the destination ill and an optional setsrc
 * address.
 * The result is stored in srcp. If generation is set, then put the source
 * generation number there before we look for the source address (to avoid
 * missing changes in the set of source addresses.
 * If flagsp is set, then us it to pass back ipif_flags.
 *
 * If the caller wants to cache the returned source address and detect when
 * that might be stale, the caller should pass in a generation argument,
 * which the caller can later compare against ips_src_generation
 *
 * The precedence order for selecting an IPv6 source address is:
 *  - RTF_SETSRC on the first ire in the recursive lookup always wins.
 *  - If usrsrc is set, swap the ill to be the usesrc one.
 *  - If IPMP is used on the ill, select a random address from the most
 *    preferred ones below:
 * That is followed by the long list of IPv6 source address selection rules
 * starting with rule_isdst(), rule_scope(), etc.
 *
 * We have lower preference for ALL_ZONES IP addresses,
 * as they pose problems with unlabeled destinations.
 *
 * Note that when multiple IP addresses match e.g., with rule_scope() we pick
 * the first one if IPMP is not in use. With IPMP we randomize.
 */
int
ip_select_source_v6(ill_t *ill, const in6_addr_t *setsrc, const in6_addr_t *dst,
    zoneid_t zoneid, ip_stack_t *ipst, uint_t restrict_ill, uint32_t src_prefs,
    in6_addr_t *srcp, uint32_t *generation, uint64_t *flagsp)
{
	ipif_t *ipif;
	boolean_t notready = B_FALSE;	/* Set if !ipif_addr_ready found */

	if (flagsp != NULL)
		*flagsp = 0;

	/*
	 * Need to grab the generation number before we check to
	 * avoid a race with a change to the set of local addresses.
	 * No lock needed since the thread which updates the set of local
	 * addresses use ipif/ill locks and exit those (hence a store memory
	 * barrier) before doing the atomic increase of ips_src_generation.
	 */
	if (generation != NULL) {
		*generation = ipst->ips_src_generation;
	}

	/* Was RTF_SETSRC set on the first IRE in the recursive lookup? */
	if (setsrc != NULL && !IN6_IS_ADDR_UNSPECIFIED(setsrc)) {
		*srcp = *setsrc;
		return (0);
	}

	ipif = ipif_select_source_v6(ill, dst, restrict_ill, src_prefs, zoneid,
	    B_TRUE, &notready);
	if (ipif == NULL) {
		if (notready)
			return (ENETDOWN);
		else
			return (EADDRNOTAVAIL);
	}
	*srcp = ipif->ipif_v6lcl_addr;
	if (flagsp != NULL)
		*flagsp = ipif->ipif_flags;
	ipif_refrele(ipif);
	return (0);
}

/*
 * Perform an attach and bind to get phys addr plus info_req for
 * the physical device.
 * q and mp represents an ioctl which will be queued waiting for
 * completion of the DLPI message exchange.
 * MUST be called on an ill queue.
 *
 * Returns EINPROGRESS when mp has been consumed by queueing it.
 * The ioctl will complete in ip_rput.
 */
int
ill_dl_phys(ill_t *ill, ipif_t *ipif, mblk_t *mp, queue_t *q)
{
	mblk_t	*v6token_mp = NULL;
	mblk_t	*v6lla_mp = NULL;
	mblk_t	*dest_mp = NULL;
	mblk_t	*phys_mp = NULL;
	mblk_t	*info_mp = NULL;
	mblk_t	*attach_mp = NULL;
	mblk_t	*bind_mp = NULL;
	mblk_t	*unbind_mp = NULL;
	mblk_t	*notify_mp = NULL;
	mblk_t  *capab_mp = NULL;

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

	if (ill->ill_mactype == DL_IPV4 || ill->ill_mactype == DL_IPV6) {
		dest_mp = ip_dlpi_alloc(sizeof (dl_phys_addr_req_t) +
		    sizeof (t_scalar_t), DL_PHYS_ADDR_REQ);
		if (dest_mp == NULL)
			goto bad;
		((dl_phys_addr_req_t *)dest_mp->b_rptr)->dl_addr_type =
		    DL_CURR_DEST_ADDR;
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
	    DL_NOTE_LINK_UP | DL_NOTE_LINK_DOWN | DL_NOTE_CAPAB_RENEG |
	    DL_NOTE_PROMISC_ON_PHYS | DL_NOTE_PROMISC_OFF_PHYS |
	    DL_NOTE_REPLUMB | DL_NOTE_ALLOWED_IPS | DL_NOTE_SDU_SIZE2);

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

	ASSERT(ill->ill_dlpi_capab_state == IDCS_UNKNOWN);
	capab_mp = ip_dlpi_alloc(sizeof (dl_capability_req_t),
	    DL_CAPABILITY_REQ);
	if (capab_mp == NULL)
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

	/*
	 * Send the capability request to get the VRRP capability information.
	 */
	ill_capability_send(ill, capab_mp);

	if (v6token_mp != NULL)
		ill_dlpi_send(ill, v6token_mp);
	if (v6lla_mp != NULL)
		ill_dlpi_send(ill, v6lla_mp);
	if (dest_mp != NULL)
		ill_dlpi_send(ill, dest_mp);
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
	freemsg(dest_mp);
	freemsg(phys_mp);
	freemsg(info_mp);
	freemsg(attach_mp);
	freemsg(bind_mp);
	freemsg(capab_mp);
	freemsg(unbind_mp);
	freemsg(notify_mp);
	return (ENOMEM);
}

/* Add room for tcp+ip headers */
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
	ill_t	*ill = ipif->ipif_ill;
	int	err;
	boolean_t loopback = B_FALSE;

	ip1dbg(("ipif_up_done_v6(%s:%u)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id));
	DTRACE_PROBE3(ipif__downup, char *, "ipif_up_done_v6",
	    ill_t *, ill, ipif_t *, ipif);

	/* Check if this is a loopback interface */
	if (ipif->ipif_ill->ill_wq == NULL)
		loopback = B_TRUE;

	ASSERT(ipif->ipif_isv6);
	ASSERT(!MUTEX_HELD(&ipif->ipif_ill->ill_lock));

	if (IS_LOOPBACK(ill) || ill->ill_net_type == IRE_IF_NORESOLVER) {
		nce_t *loop_nce = NULL;
		uint16_t flags = (NCE_F_MYADDR | NCE_F_NONUD | NCE_F_AUTHORITY);

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
		if (ill->ill_net_type != IRE_LOOPBACK)
			flags |= NCE_F_PUBLISH;
		err = nce_lookup_then_add_v6(ill, NULL,
		    ill->ill_phys_addr_length,
		    &ipif->ipif_v6lcl_addr, flags, ND_REACHABLE, &loop_nce);

		/* A shared-IP zone sees EEXIST for lo0:N */
		if (err == 0 || err == EEXIST) {
			ipif->ipif_added_nce = 1;
			loop_nce->nce_ipif_cnt++;
			nce_refrele(loop_nce);
			err = 0;
		} else {
			ASSERT(loop_nce == NULL);
			return (err);
		}
	}

	err = ipif_add_ires_v6(ipif, loopback);
	if (err != 0) {
		/*
		 * See comments about return value from
		 * ipif_addr_availability_check() in ipif_add_ires_v6().
		 */
		if (err != EADDRINUSE) {
			ipif_ndp_down(ipif);
		} else {
			/*
			 * Make IPMP aware of the deleted ipif so that
			 * the needed ipmp cleanup (e.g., of ipif_bound_ill)
			 * can be completed. Note that we do not want to
			 * destroy the nce that was created on the ipmp_ill
			 * for the active copy of the duplicate address in
			 * use.
			 */
			if (IS_IPMP(ill))
				ipmp_illgrp_del_ipif(ill->ill_grp, ipif);
			err = EADDRNOTAVAIL;
		}
		return (err);
	}

	if (ill->ill_ipif_up_count == 1 && !loopback) {
		/* Recover any additional IREs entries for this ill */
		(void) ill_recover_saved_ire(ill);
	}

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

	/* Perhaps ilgs should use this ill */
	update_conn_ill(NULL, ill->ill_ipst);

	if (ipif->ipif_addr_ready)
		ipif_up_notify(ipif);

	return (0);
}

/*
 * Add the IREs associated with the ipif.
 * Those MUST be explicitly removed in ipif_delete_ires_v6.
 */
static int
ipif_add_ires_v6(ipif_t *ipif, boolean_t loopback)
{
	ill_t		*ill = ipif->ipif_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	in6_addr_t	v6addr;
	in6_addr_t	route_mask;
	int		err;
	char		buf[INET6_ADDRSTRLEN];
	ire_t		*ire_local = NULL;	/* LOCAL or LOOPBACK */
	ire_t		*ire_if = NULL;
	in6_addr_t	*gw;

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

		if (loopback)
			gw = &ipif->ipif_v6lcl_addr;
		else
			gw = NULL;

		/* Register the source address for __sin6_src_id */
		err = ip_srcid_insert(&ipif->ipif_v6lcl_addr,
		    ipif->ipif_zoneid, ipst);
		if (err != 0) {
			ip0dbg(("ipif_add_ires_v6: srcid_insert %d\n", err));
			return (err);
		}
		/*
		 * If the interface address is set, create the LOCAL
		 * or LOOPBACK IRE.
		 */
		ip1dbg(("ipif_add_ires_v6: creating IRE %d for %s\n",
		    ipif->ipif_ire_type,
		    inet_ntop(AF_INET6, &ipif->ipif_v6lcl_addr,
		    buf, sizeof (buf))));

		ire_local = ire_create_v6(
		    &ipif->ipif_v6lcl_addr,		/* dest address */
		    &ipv6_all_ones,			/* mask */
		    gw,					/* gateway */
		    ipif->ipif_ire_type,		/* LOCAL or LOOPBACK */
		    ipif->ipif_ill,			/* interface */
		    ipif->ipif_zoneid,
		    ((ipif->ipif_flags & IPIF_PRIVATE) ?
		    RTF_PRIVATE : 0) | RTF_KERNEL,
		    NULL,
		    ipst);
		if (ire_local == NULL) {
			ip1dbg(("ipif_up_done_v6: NULL ire_local\n"));
			err = ENOMEM;
			goto bad;
		}
	}

	/* Set up the IRE_IF_RESOLVER or IRE_IF_NORESOLVER, as appropriate. */
	if (!loopback && !(ipif->ipif_flags & IPIF_NOXMIT) &&
	    !(IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6subnet) &&
	    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6net_mask))) {
		/* ipif_v6subnet is ipif_v6pp_dst_addr for pt-pt */
		v6addr = ipif->ipif_v6subnet;

		if (ipif->ipif_flags & IPIF_POINTOPOINT) {
			route_mask = ipv6_all_ones;
		} else {
			route_mask = ipif->ipif_v6net_mask;
		}

		ip1dbg(("ipif_add_ires_v6: creating if IRE %d for %s\n",
		    ill->ill_net_type,
		    inet_ntop(AF_INET6, &v6addr, buf, sizeof (buf))));

		ire_if = ire_create_v6(
		    &v6addr,			/* dest pref */
		    &route_mask,		/* mask */
		    &ipif->ipif_v6lcl_addr,	/* gateway */
		    ill->ill_net_type,		/* IF_[NO]RESOLVER */
		    ipif->ipif_ill,
		    ipif->ipif_zoneid,
		    ((ipif->ipif_flags & IPIF_PRIVATE) ?
		    RTF_PRIVATE : 0) | RTF_KERNEL,
		    NULL,
		    ipst);
		if (ire_if == NULL) {
			ip1dbg(("ipif_up_done: NULL ire_if\n"));
			err = ENOMEM;
			goto bad;
		}
	}

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
		 * returns EADDRINUSE; Caller must  turn it into EADDRNOTAVAIL
		 * which is the expected error code.
		 *
		 * Note that ipif_ndp_down() will only delete the nce in the
		 * case when the nce_ipif_cnt drops to 0.
		 */
		ill->ill_ipif_up_count--;
		ipif->ipif_flags &= ~IPIF_UP;
		goto bad;
	}

	/*
	 * Add in all newly created IREs.
	 * We add the IRE_INTERFACE before the IRE_LOCAL to ensure
	 * that lookups find the IRE_LOCAL even if the IRE_INTERFACE is
	 * a /128 route.
	 */
	if (ire_if != NULL) {
		ire_if = ire_add(ire_if);
		if (ire_if == NULL) {
			err = ENOMEM;
			goto bad2;
		}
#ifdef DEBUG
		ire_refhold_notr(ire_if);
		ire_refrele(ire_if);
#endif
	}
	if (ire_local != NULL) {
		ire_local = ire_add(ire_local);
		if (ire_local == NULL) {
			err = ENOMEM;
			goto bad2;
		}
#ifdef DEBUG
		ire_refhold_notr(ire_local);
		ire_refrele(ire_local);
#endif
	}
	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
	if (ire_local != NULL)
		ipif->ipif_ire_local = ire_local;
	if (ire_if != NULL)
		ipif->ipif_ire_if = ire_if;
	rw_exit(&ipst->ips_ill_g_lock);
	ire_local = NULL;
	ire_if = NULL;

	if (ipif->ipif_addr_ready)
		ipif_up_notify(ipif);
	return (0);

bad2:
	ill->ill_ipif_up_count--;
	ipif->ipif_flags &= ~IPIF_UP;

bad:
	if (ire_local != NULL)
		ire_delete(ire_local);
	if (ire_if != NULL)
		ire_delete(ire_if);

	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
	ire_local = ipif->ipif_ire_local;
	ipif->ipif_ire_local = NULL;
	ire_if = ipif->ipif_ire_if;
	ipif->ipif_ire_if = NULL;
	rw_exit(&ipst->ips_ill_g_lock);
	if (ire_local != NULL) {
		ire_delete(ire_local);
		ire_refrele_notr(ire_local);
	}
	if (ire_if != NULL) {
		ire_delete(ire_if);
		ire_refrele_notr(ire_if);
	}
	(void) ip_srcid_remove(&ipif->ipif_v6lcl_addr, ipif->ipif_zoneid, ipst);

	return (err);
}

/* Remove all the IREs created by ipif_add_ires_v6 */
void
ipif_delete_ires_v6(ipif_t *ipif)
{
	ill_t		*ill = ipif->ipif_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	ire_t		*ire;

	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
	ire = ipif->ipif_ire_local;
	ipif->ipif_ire_local = NULL;
	rw_exit(&ipst->ips_ill_g_lock);
	if (ire != NULL) {
		/*
		 * Move count to ipif so we don't loose the count due to
		 * a down/up dance.
		 */
		atomic_add_32(&ipif->ipif_ib_pkt_count, ire->ire_ib_pkt_count);

		ire_delete(ire);
		ire_refrele_notr(ire);
	}
	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
	ire = ipif->ipif_ire_if;
	ipif->ipif_ire_if = NULL;
	rw_exit(&ipst->ips_ill_g_lock);
	if (ire != NULL) {
		ire_delete(ire);
		ire_refrele_notr(ire);
	}
}

/*
 * Delete an ND entry if it exists.
 */
/* ARGSUSED */
int
ip_siocdelndp_v6(ipif_t *ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	sin6_t		*sin6;
	struct lifreq	*lifr;
	lif_nd_req_t	*lnr;
	ill_t		*ill = ipif->ipif_ill;
	nce_t		*nce;

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
	 * deleting ND mappings on underlying interfaces.
	 * Don't allow deletion of mappings for local addresses.
	 */
	if (IS_UNDER_IPMP(ill))
		return (EPERM);

	nce = nce_lookup_v6(ill, &sin6->sin6_addr);
	if (nce == NULL)
		return (ESRCH);

	if (NCE_MYADDR(nce->nce_common)) {
		nce_refrele(nce);
		return (EPERM);
	}

	/*
	 * delete the nce_common which will also delete the nces on any
	 * under_ill in the case of ipmp.
	 */
	ncec_delete(nce->nce_common);
	nce_refrele(nce);
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
		ire = ire_ftable_lookup_v6(&sin6->sin6_addr, NULL, NULL,
		    IRE_LOCAL, ill, ALL_ZONES, NULL,
		    MATCH_IRE_TYPE | MATCH_IRE_ILL, 0, ill->ill_ipst, NULL);
		if (ire != NULL) {
			ire_refrele(ire);
			return (EPERM);
		}
	}

	return (ndp_sioc_update(ill, lnr));
}
