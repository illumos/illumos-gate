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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains consumer routines of the IPv4 forwarding engine
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <sys/dlpi.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>

#include <sys/systm.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/ipsec_impl.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip_ndp.h>
#include <inet/arp.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/nd.h>

#include <net/pfkeyv2.h>
#include <inet/sadb.h>
#include <inet/tcp.h>
#include <inet/ipclassifier.h>
#include <sys/zone.h>
#include <net/radix.h>
#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#define	IS_DEFAULT_ROUTE(ire)	\
	(((ire)->ire_type & IRE_DEFAULT) || \
	    (((ire)->ire_type & IRE_INTERFACE) && ((ire)->ire_addr == 0)))

#define	IP_SRC_MULTIHOMING(isv6, ipst) 			\
	(isv6 ? ipst->ips_ipv6_strict_src_multihoming :	\
	ipst->ips_ip_strict_src_multihoming)

static ire_t	*route_to_dst(const struct sockaddr *, zoneid_t, ip_stack_t *);
static void	ire_del_host_redir(ire_t *, char *);
static boolean_t ire_find_best_route(struct radix_node *, void *);

/*
 * Lookup a route in forwarding table. A specific lookup is indicated by
 * passing the required parameters and indicating the match required in the
 * flag field.
 *
 * Supports IP_BOUND_IF by following the ipif/ill when recursing.
 */
ire_t *
ire_ftable_lookup_v4(ipaddr_t addr, ipaddr_t mask, ipaddr_t gateway,
    int type, const ill_t *ill, zoneid_t zoneid, const ts_label_t *tsl,
    int flags, uint32_t xmit_hint, ip_stack_t *ipst, uint_t *generationp)
{
	ire_t *ire;
	struct rt_sockaddr rdst, rmask;
	struct rt_entry *rt;
	ire_ftable_args_t margs;

	ASSERT(ill == NULL || !ill->ill_isv6);

	/*
	 * ire_match_args() will dereference ill if MATCH_IRE_ILL
	 * is set.
	 */
	if ((flags & (MATCH_IRE_ILL|MATCH_IRE_SRC_ILL)) && (ill == NULL))
		return (NULL);

	bzero(&rdst, sizeof (rdst));
	rdst.rt_sin_len = sizeof (rdst);
	rdst.rt_sin_family = AF_INET;
	rdst.rt_sin_addr.s_addr = addr;

	bzero(&rmask, sizeof (rmask));
	rmask.rt_sin_len = sizeof (rmask);
	rmask.rt_sin_family = AF_INET;
	rmask.rt_sin_addr.s_addr = mask;

	bzero(&margs, sizeof (margs));
	margs.ift_addr = addr;
	margs.ift_mask = mask;
	margs.ift_gateway = gateway;
	margs.ift_type = type;
	margs.ift_ill = ill;
	margs.ift_zoneid = zoneid;
	margs.ift_tsl = tsl;
	margs.ift_flags = flags;

	/*
	 * The flags argument passed to ire_ftable_lookup may cause the
	 * search to return, not the longest matching prefix, but the
	 * "best matching prefix", i.e., the longest prefix that also
	 * satisfies constraints imposed via the permutation of flags
	 * passed in. To achieve this, we invoke ire_match_args() on
	 * each matching leaf in the  radix tree. ire_match_args is
	 * invoked by the callback function ire_find_best_route()
	 * We hold the global tree lock in read mode when calling
	 * rn_match_args. Before dropping the global tree lock, ensure
	 * that the radix node can't be deleted by incrementing ire_refcnt.
	 */
	RADIX_NODE_HEAD_RLOCK(ipst->ips_ip_ftable);
	rt = (struct rt_entry *)ipst->ips_ip_ftable->rnh_matchaddr_args(&rdst,
	    ipst->ips_ip_ftable, ire_find_best_route, &margs);
	ire = margs.ift_best_ire;
	if (rt == NULL) {
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
		return (NULL);
	}
	ASSERT(ire != NULL);

	DTRACE_PROBE2(ire__found, ire_ftable_args_t *, &margs, ire_t *, ire);

	/*
	 * round-robin only if we have more than one route in the bucket.
	 * ips_ip_ecmp_behavior controls when we do ECMP
	 *	2:	always
	 *	1:	for IRE_DEFAULT and /0 IRE_INTERFACE
	 *	0:	never
	 */
	if (ire->ire_bucket->irb_ire_cnt > 1 && !(flags & MATCH_IRE_GW)) {
		if (ipst->ips_ip_ecmp_behavior == 2 ||
		    (ipst->ips_ip_ecmp_behavior == 1 &&
		    IS_DEFAULT_ROUTE(ire))) {
			ire_t	*next_ire;

			margs.ift_best_ire = NULL;
			next_ire = ire_round_robin(ire->ire_bucket, &margs,
			    xmit_hint, ire, ipst);
			if (next_ire == NULL) {
				/* keep ire if next_ire is null */
				goto done;
			}
			ire_refrele(ire);
			ire = next_ire;
		}
	}

done:
	/* Return generation before dropping lock */
	if (generationp != NULL)
		*generationp = ire->ire_generation;

	RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);

	/*
	 * For shared-IP zones we need additional checks to what was
	 * done in ire_match_args to make sure IRE_LOCALs are handled.
	 *
	 * When ip_restrict_interzone_loopback is set, then
	 * we ensure that IRE_LOCAL are only used for loopback
	 * between zones when the logical "Ethernet" would
	 * have looped them back. That is, if in the absense of
	 * the IRE_LOCAL we would have sent to packet out the
	 * same ill.
	 */
	if ((ire->ire_type & IRE_LOCAL) && zoneid != ALL_ZONES &&
	    ire->ire_zoneid != zoneid && ire->ire_zoneid != ALL_ZONES &&
	    ipst->ips_ip_restrict_interzone_loopback) {
		ire = ire_alt_local(ire, zoneid, tsl, ill, generationp);
		ASSERT(ire != NULL);
	}
	return (ire);
}

/*
 * This function is called by
 * ip_input/ire_route_recursive when doing a route lookup on only the
 * destination address.
 *
 * The optimizations of this function over ire_ftable_lookup are:
 *	o removing unnecessary flag matching
 *	o doing longest prefix match instead of overloading it further
 *	  with the unnecessary "best_prefix_match"
 *
 * If no route is found we return IRE_NOROUTE.
 */
ire_t *
ire_ftable_lookup_simple_v4(ipaddr_t addr, uint32_t xmit_hint, ip_stack_t *ipst,
    uint_t *generationp)
{
	ire_t *ire;
	struct rt_sockaddr rdst;
	struct rt_entry *rt;
	irb_t *irb;

	rdst.rt_sin_len = sizeof (rdst);
	rdst.rt_sin_family = AF_INET;
	rdst.rt_sin_addr.s_addr = addr;

	/*
	 * This is basically inlining  a simpler version of ire_match_args
	 */
	RADIX_NODE_HEAD_RLOCK(ipst->ips_ip_ftable);

	rt = (struct rt_entry *)ipst->ips_ip_ftable->rnh_matchaddr_args(&rdst,
	    ipst->ips_ip_ftable, NULL, NULL);

	if (rt == NULL)
		goto bad;

	irb = &rt->rt_irb;
	if (irb->irb_ire_cnt == 0)
		goto bad;

	rw_enter(&irb->irb_lock, RW_READER);
	ire = irb->irb_ire;
	if (ire == NULL) {
		rw_exit(&irb->irb_lock);
		goto bad;
	}
	while (IRE_IS_CONDEMNED(ire)) {
		ire = ire->ire_next;
		if (ire == NULL) {
			rw_exit(&irb->irb_lock);
			goto bad;
		}
	}

	/* we have a ire that matches */
	ire_refhold(ire);
	rw_exit(&irb->irb_lock);

	/*
	 * round-robin only if we have more than one route in the bucket.
	 * ips_ip_ecmp_behavior controls when we do ECMP
	 *	2:	always
	 *	1:	for IRE_DEFAULT and /0 IRE_INTERFACE
	 *	0:	never
	 *
	 * Note: if we found an IRE_IF_CLONE we won't look at the bucket with
	 * other ECMP IRE_INTERFACEs since the IRE_IF_CLONE is a /128 match
	 * and the IRE_INTERFACESs are likely to be shorter matches.
	 */
	if (ire->ire_bucket->irb_ire_cnt > 1) {
		if (ipst->ips_ip_ecmp_behavior == 2 ||
		    (ipst->ips_ip_ecmp_behavior == 1 &&
		    IS_DEFAULT_ROUTE(ire))) {
			ire_t	*next_ire;
			ire_ftable_args_t margs;

			bzero(&margs, sizeof (margs));
			margs.ift_addr = addr;
			margs.ift_zoneid = ALL_ZONES;

			next_ire = ire_round_robin(ire->ire_bucket, &margs,
			    xmit_hint, ire, ipst);
			if (next_ire == NULL) {
				/* keep ire if next_ire is null */
				if (generationp != NULL)
					*generationp = ire->ire_generation;
				RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
				return (ire);
			}
			ire_refrele(ire);
			ire = next_ire;
		}
	}
	/* Return generation before dropping lock */
	if (generationp != NULL)
		*generationp = ire->ire_generation;

	RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);

	/*
	 * Since we only did ALL_ZONES matches there is no special handling
	 * of IRE_LOCALs needed here. ire_ftable_lookup_v4 has to handle that.
	 */
	return (ire);

bad:
	if (generationp != NULL)
		*generationp = IRE_GENERATION_VERIFY;

	RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
	return (ire_reject(ipst, B_FALSE));
}

/*
 * Find the ill matching a multicast group.
 * Allows different routes for multicast addresses
 * in the unicast routing table (akin to 224.0.0.0 but could be more specific)
 * which point at different interfaces. This is used when IP_MULTICAST_IF
 * isn't specified (when sending) and when IP_ADD_MEMBERSHIP doesn't
 * specify the interface to join on.
 *
 * Supports link-local addresses by using ire_route_recursive which follows
 * the ill when recursing.
 *
 * To handle CGTP, since we don't have a separate IRE_MULTICAST for each group
 * and the MULTIRT property can be different for different groups, we
 * extract RTF_MULTIRT from the special unicast route added for a group
 * with CGTP and pass that back in the multirtp argument.
 * This is used in ip_set_destination etc to set ixa_postfragfn for multicast.
 * We have a setsrcp argument for the same reason.
 */
ill_t *
ire_lookup_multi_ill_v4(ipaddr_t group, zoneid_t zoneid, ip_stack_t *ipst,
    boolean_t *multirtp, ipaddr_t *setsrcp)
{
	ire_t	*ire;
	ill_t	*ill;

	ire = ire_route_recursive_v4(group, 0, NULL, zoneid, NULL,
	    MATCH_IRE_DSTONLY, IRR_NONE, 0, ipst, setsrcp, NULL, NULL);
	ASSERT(ire != NULL);
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		ire_refrele(ire);
		return (NULL);
	}

	if (multirtp != NULL)
		*multirtp = (ire->ire_flags & RTF_MULTIRT) != 0;

	ill = ire_nexthop_ill(ire);
	ire_refrele(ire);
	return (ill);
}

/*
 * Delete the passed in ire if the gateway addr matches
 */
void
ire_del_host_redir(ire_t *ire, char *gateway)
{
	if ((ire->ire_flags & RTF_DYNAMIC) &&
	    (ire->ire_gateway_addr == *(ipaddr_t *)gateway))
		ire_delete(ire);
}

/*
 * Search for all IRE_HOST RTF_DYNAMIC (aka redirect) routes that are
 * pointing at the specified gateway and
 * delete them. This routine is called only
 * when a default gateway is going away.
 */
void
ire_delete_host_redirects(ipaddr_t gateway, ip_stack_t *ipst)
{
	struct rtfuncarg rtfarg;

	bzero(&rtfarg, sizeof (rtfarg));
	rtfarg.rt_func = ire_del_host_redir;
	rtfarg.rt_arg = (void *)&gateway;
	rtfarg.rt_zoneid = ALL_ZONES;
	rtfarg.rt_ipst = ipst;
	(void) ipst->ips_ip_ftable->rnh_walktree_mt(ipst->ips_ip_ftable,
	    rtfunc, &rtfarg, irb_refhold_rn, irb_refrele_rn);
}

/*
 * Obtain the rt_entry and rt_irb for the route to be added to
 * the ips_ip_ftable.
 * First attempt to add a node to the radix tree via rn_addroute. If the
 * route already exists, return the bucket for the existing route.
 *
 * Locking notes: Need to hold the global radix tree lock in write mode to
 * add a radix node. To prevent the node from being deleted, ire_get_bucket()
 * returns with a ref'ed irb_t. The ire itself is added in ire_add_v4()
 * while holding the irb_lock, but not the radix tree lock.
 */
irb_t *
ire_get_bucket(ire_t *ire)
{
	struct radix_node *rn;
	struct rt_entry *rt;
	struct rt_sockaddr rmask, rdst;
	irb_t *irb = NULL;
	ip_stack_t *ipst = ire->ire_ipst;

	ASSERT(ipst->ips_ip_ftable != NULL);

	/* first try to see if route exists (based on rtalloc1) */
	bzero(&rdst, sizeof (rdst));
	rdst.rt_sin_len = sizeof (rdst);
	rdst.rt_sin_family = AF_INET;
	rdst.rt_sin_addr.s_addr = ire->ire_addr;

	bzero(&rmask, sizeof (rmask));
	rmask.rt_sin_len = sizeof (rmask);
	rmask.rt_sin_family = AF_INET;
	rmask.rt_sin_addr.s_addr = ire->ire_mask;

	/*
	 * add the route. based on BSD's rtrequest1(RTM_ADD)
	 */
	R_Malloc(rt, rt_entry_cache,  sizeof (*rt));
	/* kmem_alloc failed */
	if (rt == NULL)
		return (NULL);

	bzero(rt, sizeof (*rt));
	rt->rt_nodes->rn_key = (char *)&rt->rt_dst;
	rt->rt_dst = rdst;
	irb = &rt->rt_irb;
	irb->irb_marks |= IRB_MARK_DYNAMIC; /* dynamically allocated/freed */
	irb->irb_ipst = ipst;
	rw_init(&irb->irb_lock, NULL, RW_DEFAULT, NULL);
	RADIX_NODE_HEAD_WLOCK(ipst->ips_ip_ftable);
	rn = ipst->ips_ip_ftable->rnh_addaddr(&rt->rt_dst, &rmask,
	    ipst->ips_ip_ftable, (struct radix_node *)rt);
	if (rn == NULL) {
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
		Free(rt, rt_entry_cache);
		rt = NULL;
		irb = NULL;
		RADIX_NODE_HEAD_RLOCK(ipst->ips_ip_ftable);
		rn = ipst->ips_ip_ftable->rnh_lookup(&rdst, &rmask,
		    ipst->ips_ip_ftable);
		if (rn != NULL && ((rn->rn_flags & RNF_ROOT) == 0)) {
			/* found a non-root match */
			rt = (struct rt_entry *)rn;
		}
	}
	if (rt != NULL) {
		irb = &rt->rt_irb;
		irb_refhold(irb);
	}
	RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
	return (irb);
}

/*
 * This function is used when the caller wants to know the outbound
 * interface for a packet given only the address.
 * If this is a offlink IP address and there are multiple
 * routes to this destination, this routine will utilise the
 * first route it finds to IP address
 * Return values:
 * 	0	- FAILURE
 *	nonzero	- ifindex
 */
uint_t
ifindex_lookup(const struct sockaddr *ipaddr, zoneid_t zoneid)
{
	uint_t ifindex = 0;
	ire_t *ire;
	ill_t *ill;
	netstack_t *ns;
	ip_stack_t *ipst;

	if (zoneid == ALL_ZONES)
		ns = netstack_find_by_zoneid(GLOBAL_ZONEID);
	else
		ns = netstack_find_by_zoneid(zoneid);
	ASSERT(ns != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * since IP uses the global zoneid in the exclusive stacks.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	ipst = ns->netstack_ip;

	ASSERT(ipaddr->sa_family == AF_INET || ipaddr->sa_family == AF_INET6);

	if ((ire = route_to_dst(ipaddr, zoneid, ipst)) != NULL) {
		ill = ire_nexthop_ill(ire);
		if (ill != NULL) {
			ifindex = ill->ill_phyint->phyint_ifindex;
			ill_refrele(ill);
		}
		ire_refrele(ire);
	}
	netstack_rele(ns);
	return (ifindex);
}

/*
 * Routine to find the route to a destination. If a ifindex is supplied
 * it tries to match the route to the corresponding ipif for the ifindex
 */
static	ire_t *
route_to_dst(const struct sockaddr *dst_addr, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t *ire = NULL;
	int match_flags;

	match_flags = MATCH_IRE_DSTONLY;

	/* XXX pass NULL tsl for now */

	if (dst_addr->sa_family == AF_INET) {
		ire = ire_route_recursive_v4(
		    ((struct sockaddr_in *)dst_addr)->sin_addr.s_addr, 0, NULL,
		    zoneid, NULL, match_flags, IRR_ALLOCATE, 0, ipst, NULL,
		    NULL, NULL);
	} else {
		ire = ire_route_recursive_v6(
		    &((struct sockaddr_in6 *)dst_addr)->sin6_addr, 0, NULL,
		    zoneid, NULL, match_flags, IRR_ALLOCATE, 0, ipst, NULL,
		    NULL, NULL);
	}
	ASSERT(ire != NULL);
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		ire_refrele(ire);
		return (NULL);
	}
	return (ire);
}

/*
 * This routine is called by IP Filter to send a packet out on the wire
 * to a specified dstination (which may be onlink or offlink). The ifindex may
 * or may not be 0. A non-null ifindex indicates IP Filter has stipulated
 * an outgoing interface and requires the nexthop to be on that interface.
 * IP WILL NOT DO the following to the data packet before sending it out:
 *	a. manipulate ttl
 *	b. ipsec work
 *	c. fragmentation
 *
 * If the packet has been prepared for hardware checksum then it will be
 * passed off to ip_send_align_cksum() to check that the flags set on the
 * packet are in alignment with the capabilities of the new outgoing NIC.
 *
 * Return values:
 *	0:		IP was able to send of the data pkt
 *	ECOMM:		Could not send packet
 *	ENONET		No route to dst. It is up to the caller
 *			to send icmp unreachable error message,
 *	EINPROGRESS	The macaddr of the onlink dst or that
 *			of the offlink dst's nexthop needs to get
 *			resolved before packet can be sent to dst.
 *			Thus transmission is not guaranteed.
 *			Note: No longer have visibility to the ARP queue
 *			hence no EINPROGRESS.
 */
int
ipfil_sendpkt(const struct sockaddr *dst_addr, mblk_t *mp, uint_t ifindex,
    zoneid_t zoneid)
{
	ipaddr_t nexthop;
	netstack_t *ns;
	ip_stack_t *ipst;
	ip_xmit_attr_t ixas;
	int error;

	ASSERT(mp != NULL);

	if (zoneid == ALL_ZONES)
		ns = netstack_find_by_zoneid(GLOBAL_ZONEID);
	else
		ns = netstack_find_by_zoneid(zoneid);
	ASSERT(ns != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * since IP uses the global zoneid in the exclusive stacks.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	ipst = ns->netstack_ip;

	ASSERT(dst_addr->sa_family == AF_INET ||
	    dst_addr->sa_family == AF_INET6);

	bzero(&ixas, sizeof (ixas));
	/*
	 * No IPsec, no fragmentation, and don't let any hooks see
	 * the packet.
	 */
	ixas.ixa_flags = IXAF_NO_IPSEC | IXAF_DONTFRAG | IXAF_NO_PFHOOK;
	ixas.ixa_cred = kcred;
	ixas.ixa_cpid = NOPID;
	ixas.ixa_tsl = NULL;
	ixas.ixa_ipst = ipst;
	ixas.ixa_ifindex = ifindex;

	if (dst_addr->sa_family == AF_INET) {
		ipha_t *ipha = (ipha_t *)mp->b_rptr;

		ixas.ixa_flags |= IXAF_IS_IPV4;
		nexthop = ((struct sockaddr_in *)dst_addr)->sin_addr.s_addr;
		if (nexthop != ipha->ipha_dst) {
			ixas.ixa_flags |= IXAF_NEXTHOP_SET;
			ixas.ixa_nexthop_v4 = nexthop;
		}
		ixas.ixa_multicast_ttl = ipha->ipha_ttl;
	} else {
		ip6_t *ip6h = (ip6_t *)mp->b_rptr;
		in6_addr_t *nexthop6;

		nexthop6 = &((struct sockaddr_in6 *)dst_addr)->sin6_addr;
		if (!IN6_ARE_ADDR_EQUAL(nexthop6, &ip6h->ip6_dst)) {
			ixas.ixa_flags |= IXAF_NEXTHOP_SET;
			ixas.ixa_nexthop_v6 = *nexthop6;
		}
		ixas.ixa_multicast_ttl = ip6h->ip6_hops;
	}
	error = ip_output_simple(mp, &ixas);
	ixa_cleanup(&ixas);

	netstack_rele(ns);
	switch (error) {
	case 0:
		break;

	case EHOSTUNREACH:
	case ENETUNREACH:
		error = ENONET;
		break;

	default:
		error = ECOMM;
		break;
	}
	return (error);
}

/*
 * callback function provided by ire_ftable_lookup when calling
 * rn_match_args(). Invoke ire_match_args on each matching leaf node in
 * the radix tree.
 */
boolean_t
ire_find_best_route(struct radix_node *rn, void *arg)
{
	struct rt_entry *rt = (struct rt_entry *)rn;
	irb_t *irb_ptr;
	ire_t *ire;
	ire_ftable_args_t *margs = arg;
	ipaddr_t match_mask;

	ASSERT(rt != NULL);

	irb_ptr = &rt->rt_irb;

	if (irb_ptr->irb_ire_cnt == 0)
		return (B_FALSE);

	rw_enter(&irb_ptr->irb_lock, RW_READER);
	for (ire = irb_ptr->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (IRE_IS_CONDEMNED(ire))
			continue;
		ASSERT((margs->ift_flags & MATCH_IRE_SHORTERMASK) == 0);
		if (margs->ift_flags & MATCH_IRE_MASK)
			match_mask = margs->ift_mask;
		else
			match_mask = ire->ire_mask;

		if (ire_match_args(ire, margs->ift_addr, match_mask,
		    margs->ift_gateway, margs->ift_type, margs->ift_ill,
		    margs->ift_zoneid, margs->ift_tsl,
		    margs->ift_flags)) {
			ire_refhold(ire);
			rw_exit(&irb_ptr->irb_lock);
			margs->ift_best_ire = ire;
			return (B_TRUE);
		}
	}
	rw_exit(&irb_ptr->irb_lock);
	return (B_FALSE);
}

/*
 * ftable irb_t structures are dynamically allocated, and we need to
 * check if the irb_t (and associated ftable tree attachment) needs to
 * be cleaned up when the irb_refcnt goes to 0. The conditions that need
 * be verified are:
 * - no other walkers of the irebucket, i.e., quiescent irb_refcnt,
 * - no other threads holding references to ire's in the bucket,
 *   i.e., irb_nire == 0
 * - no active ire's in the bucket, i.e., irb_ire_cnt == 0
 * - need to hold the global tree lock and irb_lock in write mode.
 */
void
irb_refrele_ftable(irb_t *irb)
{
	for (;;) {
		rw_enter(&irb->irb_lock, RW_WRITER);
		ASSERT(irb->irb_refcnt != 0);
		if (irb->irb_refcnt != 1) {
			/*
			 * Someone has a reference to this radix node
			 * or there is some bucket walker.
			 */
			irb->irb_refcnt--;
			rw_exit(&irb->irb_lock);
			return;
		} else {
			/*
			 * There is no other walker, nor is there any
			 * other thread that holds a direct ref to this
			 * radix node. Do the clean up if needed. Call
			 * to ire_unlink will clear the IRB_MARK_CONDEMNED flag
			 */
			if (irb->irb_marks & IRB_MARK_CONDEMNED)  {
				ire_t *ire_list;

				ire_list = ire_unlink(irb);
				rw_exit(&irb->irb_lock);

				if (ire_list != NULL)
					ire_cleanup(ire_list);
				/*
				 * more CONDEMNED entries could have
				 * been added while we dropped the lock,
				 * so we have to re-check.
				 */
				continue;
			}

			/*
			 * Now check if there are still any ires
			 * associated with this radix node.
			 */
			if (irb->irb_nire != 0) {
				/*
				 * someone is still holding on
				 * to ires in this bucket
				 */
				irb->irb_refcnt--;
				rw_exit(&irb->irb_lock);
				return;
			} else {
				/*
				 * Everything is clear. Zero walkers,
				 * Zero threads with a ref to this
				 * radix node, Zero ires associated with
				 * this radix node. Due to lock order,
				 * check the above conditions again
				 * after grabbing all locks in the right order
				 */
				rw_exit(&irb->irb_lock);
				if (irb_inactive(irb))
					return;
				/*
				 * irb_inactive could not free the irb.
				 * See if there are any walkers, if not
				 * try to clean up again.
				 */
			}
		}
	}
}

/*
 * IRE iterator used by ire_ftable_lookup to process multiple equal
 * routes. Given a starting point in the hash list (hash), walk the IREs
 * in the bucket skipping deleted entries. We treat the bucket as a circular
 * list for the purposes of walking it.
 * Returns the IRE (held) that corresponds to the hash value. If that IRE is
 * not applicable (ire_match_args failed) then it returns a subsequent one.
 * If we fail to find an IRE we return NULL.
 *
 * Assumes that the caller holds a reference on the IRE bucket and a read lock
 * on the radix_node_head (for IPv4) or the ip6_ire_head (for IPv6).
 *
 * Applies to IPv4 and IPv6.
 *
 * For CGTP, where an IRE_BROADCAST and IRE_HOST can exist for the same
 * address and bucket, we compare against ire_type for the orig_ire. We also
 * have IRE_BROADCASTs with and without RTF_MULTIRT, with the former being
 * first in the bucket. Thus we compare that RTF_MULTIRT match the orig_ire.
 *
 * Due to shared-IP zones we check that an IRE_OFFLINK has a gateway that is
 * reachable from the zone i.e., that the ire_gateway_addr is in a subnet
 * in which the zone has an IP address. We check this for the global zone
 * even if no shared-IP zones are configured.
 */
ire_t *
ire_round_robin(irb_t *irb_ptr, ire_ftable_args_t *margs, uint_t hash,
    ire_t *orig_ire, ip_stack_t *ipst)
{
	ire_t		*ire, *maybe_ire = NULL;
	uint_t		maybe_badcnt;
	uint_t		maxwalk;

	/* Fold in more bits from the hint/hash */
	hash = hash ^ (hash >> 8) ^ (hash >> 16);

	rw_enter(&irb_ptr->irb_lock, RW_WRITER);
	maxwalk = irb_ptr->irb_ire_cnt;	/* Excludes condemned */
	if (maxwalk == 0) {
		rw_exit(&irb_ptr->irb_lock);
		return (NULL);
	}

	hash %= maxwalk;
	irb_refhold_locked(irb_ptr);
	rw_exit(&irb_ptr->irb_lock);

	/*
	 * Round-robin the routers list looking for a route that
	 * matches the passed in parameters.
	 * First we skip "hash" number of non-condemned IREs.
	 * Then we match the IRE.
	 * If we find an ire which has a non-zero ire_badcnt then we remember
	 * it and keep on looking for a lower ire_badcnt.
	 * If we come to the end of the list we continue (treat the
	 * bucket list as a circular list) but we match less than "max"
	 * entries.
	 */
	ire = irb_ptr->irb_ire;
	while (maxwalk > 0) {
		if (IRE_IS_CONDEMNED(ire))
			goto next_ire_skip;

		/* Skip the first "hash" entries to do ECMP */
		if (hash != 0) {
			hash--;
			goto next_ire_skip;
		}

		/* See CGTP comment above */
		if (ire->ire_type != orig_ire->ire_type ||
		    ((ire->ire_flags ^ orig_ire->ire_flags) & RTF_MULTIRT) != 0)
			goto next_ire;

		/*
		 * Note: Since IPv6 has hash buckets instead of radix
		 * buckers we need to explicitly compare the addresses.
		 * That makes this less efficient since we will be called
		 * even if there is no alternatives just because the
		 * bucket has multiple IREs for different addresses.
		 */
		if (ire->ire_ipversion == IPV6_VERSION) {
			if (!IN6_ARE_ADDR_EQUAL(&orig_ire->ire_addr_v6,
			    &ire->ire_addr_v6))
				goto next_ire;
		}

		/*
		 * For some reason find_best_route uses ire_mask. We do
		 * the same.
		 */
		if (ire->ire_ipversion == IPV4_VERSION ?
		    !ire_match_args(ire, margs->ift_addr,
		    ire->ire_mask, margs->ift_gateway,
		    margs->ift_type, margs->ift_ill, margs->ift_zoneid,
		    margs->ift_tsl, margs->ift_flags) :
		    !ire_match_args_v6(ire, &margs->ift_addr_v6,
		    &ire->ire_mask_v6, &margs->ift_gateway_v6,
		    margs->ift_type, margs->ift_ill, margs->ift_zoneid,
		    margs->ift_tsl, margs->ift_flags))
			goto next_ire;

		if (margs->ift_zoneid != ALL_ZONES &&
		    (ire->ire_type & IRE_OFFLINK)) {
			/*
			 * When we're in a zone, we're only
			 * interested in routers that are
			 * reachable through ipifs within our zone.
			 */
			if (ire->ire_ipversion == IPV4_VERSION) {
				if (!ire_gateway_ok_zone_v4(
				    ire->ire_gateway_addr, margs->ift_zoneid,
				    ire->ire_ill, margs->ift_tsl, ipst,
				    B_TRUE))
					goto next_ire;
			} else {
				if (!ire_gateway_ok_zone_v6(
				    &ire->ire_gateway_addr_v6,
				    margs->ift_zoneid, ire->ire_ill,
				    margs->ift_tsl, ipst, B_TRUE))
					goto next_ire;
			}
		}
		mutex_enter(&ire->ire_lock);
		/* Look for stale ire_badcnt and clear */
		if (ire->ire_badcnt != 0 &&
		    (TICK_TO_SEC(ddi_get_lbolt64()) - ire->ire_last_badcnt >
		    ipst->ips_ip_ire_badcnt_lifetime))
			ire->ire_badcnt = 0;
		mutex_exit(&ire->ire_lock);

		if (ire->ire_badcnt == 0) {
			/* We found one with a zero badcnt; done */
			ire_refhold(ire);
			/*
			 * Care needed since irb_refrele grabs WLOCK to free
			 * the irb_t.
			 */
			if (ire->ire_ipversion == IPV4_VERSION) {
				RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
				irb_refrele(irb_ptr);
				RADIX_NODE_HEAD_RLOCK(ipst->ips_ip_ftable);
			} else {
				rw_exit(&ipst->ips_ip6_ire_head_lock);
				irb_refrele(irb_ptr);
				rw_enter(&ipst->ips_ip6_ire_head_lock,
				    RW_READER);
			}
			return (ire);
		}
		/*
		 * keep looking to see if there is a better (lower
		 * badcnt) matching IRE, but save this one as a last resort.
		 * If we find a lower badcnt pick that one as the last* resort.
		 */
		if (maybe_ire == NULL) {
			maybe_ire = ire;
			maybe_badcnt = ire->ire_badcnt;
		} else if (ire->ire_badcnt < maybe_badcnt) {
			maybe_ire = ire;
			maybe_badcnt = ire->ire_badcnt;
		}

next_ire:
		maxwalk--;
next_ire_skip:
		ire = ire->ire_next;
		if (ire == NULL)
			ire = irb_ptr->irb_ire;
	}
	if (maybe_ire != NULL)
		ire_refhold(maybe_ire);

	/* Care needed since irb_refrele grabs WLOCK to free the irb_t. */
	if (ire->ire_ipversion == IPV4_VERSION) {
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
		irb_refrele(irb_ptr);
		RADIX_NODE_HEAD_RLOCK(ipst->ips_ip_ftable);
	} else {
		rw_exit(&ipst->ips_ip6_ire_head_lock);
		irb_refrele(irb_ptr);
		rw_enter(&ipst->ips_ip6_ire_head_lock, RW_READER);
	}
	return (maybe_ire);
}

void
irb_refhold_rn(struct radix_node *rn)
{
	if ((rn->rn_flags & RNF_ROOT) == 0)
		irb_refhold(&((rt_t *)(rn))->rt_irb);
}

void
irb_refrele_rn(struct radix_node *rn)
{
	if ((rn->rn_flags & RNF_ROOT) == 0)
		irb_refrele_ftable(&((rt_t *)(rn))->rt_irb);
}


/*
 * ip_select_src_ill() is used by ip_select_route() to find the src_ill
 * to be used for source-aware routing table lookup. This function will
 * ignore IPIF_UNNUMBERED interface addresses, and will only return a
 * numbered interface (ipif_lookup_addr_nondup() will ignore UNNUMBERED
 * interfaces).
 */
static ill_t *
ip_select_src_ill(const in6_addr_t *v6src, zoneid_t zoneid, ip_stack_t *ipst)
{
	ipif_t *ipif;
	ill_t *ill;
	boolean_t isv6 = !IN6_IS_ADDR_V4MAPPED(v6src);
	ipaddr_t v4src;

	if (isv6) {
		ipif = ipif_lookup_addr_nondup_v6(v6src, NULL, zoneid, ipst);
	} else {
		IN6_V4MAPPED_TO_IPADDR(v6src, v4src);
		ipif = ipif_lookup_addr_nondup(v4src, NULL, zoneid, ipst);
	}
	if (ipif == NULL)
		return (NULL);
	ill = ipif->ipif_ill;
	ill_refhold(ill);
	ipif_refrele(ipif);
	return (ill);
}

/*
 * verify that v6src is configured on ill
 */
static boolean_t
ip_verify_src_on_ill(const in6_addr_t v6src, ill_t *ill, zoneid_t zoneid)
{
	ipif_t *ipif;
	ip_stack_t *ipst;
	ipaddr_t v4src;

	if (ill == NULL)
		return (B_FALSE);
	ipst = ill->ill_ipst;

	if (ill->ill_isv6) {
		ipif = ipif_lookup_addr_nondup_v6(&v6src, ill, zoneid, ipst);
	} else {
		IN6_V4MAPPED_TO_IPADDR(&v6src, v4src);
		ipif = ipif_lookup_addr_nondup(v4src, ill, zoneid, ipst);
	}

	if (ipif != NULL) {
		ipif_refrele(ipif);
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

/*
 * Select a route for IPv4 and IPv6. Except for multicast, loopback and reject
 * routes this routine sets up a ire_nce_cache as well. The caller needs to
 * lookup an nce for the multicast case.
 *
 * When src_multihoming is set to 2 (strict src multihoming) we use the source
 * address to select the interface and route. If IP_BOUND_IF etc are
 * specified, we require that they specify an interface on which the
 * source address is assigned.
 *
 * When src_multihoming is set to 1 (preferred src aware route
 * selection)  the unicast lookup prefers a matching source
 * (i.e., that the route points out an ill on which the source is assigned), but
 * if no such route is found we fallback to not considering the source in the
 * route lookup.
 *
 * We skip the src_multihoming check when the source isn't (yet) set, and
 * when IXAF_VERIFY_SOURCE is not set. The latter allows RAW sockets to send
 * with bogus source addresses as allowed by IP_HDRINCL and IPV6_PKTINFO
 * when secpolicy_net_rawaccess().
 */
ire_t *
ip_select_route(const in6_addr_t *v6dst, const in6_addr_t v6src,
    ip_xmit_attr_t *ixa, uint_t *generationp, in6_addr_t *setsrcp,
    int *errorp, boolean_t *multirtp)
{
	uint_t		match_args;
	uint_t		ire_type;
	ill_t		*ill = NULL;
	ire_t		*ire;
	ip_stack_t	*ipst = ixa->ixa_ipst;
	ipaddr_t	v4dst;
	in6_addr_t	v6nexthop;
	iaflags_t	ixaflags = ixa->ixa_flags;
	nce_t		*nce;
	boolean_t	preferred_src_aware = B_FALSE;
	boolean_t	verify_src;
	boolean_t	isv6 = !(ixa->ixa_flags & IXAF_IS_IPV4);
	int		src_multihoming = IP_SRC_MULTIHOMING(isv6, ipst);

	/*
	 * We only verify that the src has been configured on a selected
	 * interface if the src is not :: or INADDR_ANY, and if the
	 * IXAF_VERIFY_SOURCE flag is set.
	 */
	verify_src = (!V6_OR_V4_INADDR_ANY(v6src) &&
	    (ixa->ixa_flags & IXAF_VERIFY_SOURCE));

	match_args = MATCH_IRE_SECATTR;
	IN6_V4MAPPED_TO_IPADDR(v6dst, v4dst);
	if (setsrcp != NULL)
		ASSERT(IN6_IS_ADDR_UNSPECIFIED(setsrcp));
	if (errorp != NULL)
		ASSERT(*errorp == 0);

	/*
	 * The content of the ixa will be different if IP_NEXTHOP,
	 * SO_DONTROUTE, IP_BOUND_IF, IP_PKTINFO etc are set
	 */

	if (isv6 ? IN6_IS_ADDR_MULTICAST(v6dst) : CLASSD(v4dst)) {
		/* Pick up the IRE_MULTICAST for the ill */
		if (ixa->ixa_multicast_ifindex != 0) {
			ill = ill_lookup_on_ifindex(ixa->ixa_multicast_ifindex,
			    isv6, ipst);
		} else if (ixaflags & IXAF_SCOPEID_SET) {
			/* sin6_scope_id takes precedence over ixa_ifindex */
			ASSERT(ixa->ixa_scopeid != 0);
			ill = ill_lookup_on_ifindex(ixa->ixa_scopeid,
			    isv6, ipst);
		} else if (ixa->ixa_ifindex != 0) {
			/*
			 * In the ipmp case, the ixa_ifindex is set to
			 * point at an under_ill and we would return the
			 * ire_multicast() corresponding to that under_ill.
			 */
			ill = ill_lookup_on_ifindex(ixa->ixa_ifindex,
			    isv6, ipst);
		} else if (src_multihoming != 0 && verify_src) {
			/* Look up the ill based on the source address */
			ill = ip_select_src_ill(&v6src, ixa->ixa_zoneid, ipst);
			/*
			 * Since we looked up the ill from the source there
			 * is no need to verify that the source is on the ill
			 * below.
			 */
			verify_src = B_FALSE;
			if (ill != NULL && IS_VNI(ill)) {
				ill_t *usesrc = ill;

				ill = ill_lookup_usesrc(usesrc);
				ill_refrele(usesrc);
			}
		} else if (!isv6) {
			ipaddr_t	v4setsrc = INADDR_ANY;

			ill = ill_lookup_group_v4(v4dst, ixa->ixa_zoneid,
			    ipst, multirtp, &v4setsrc);
			if (setsrcp != NULL)
				IN6_IPADDR_TO_V4MAPPED(v4setsrc, setsrcp);
		} else {
			ill = ill_lookup_group_v6(v6dst, ixa->ixa_zoneid,
			    ipst, multirtp, setsrcp);
		}
		if (ill != NULL && IS_VNI(ill)) {
			ill_refrele(ill);
			ill = NULL;
		}
		if (ill == NULL) {
			if (errorp != NULL)
				*errorp = ENXIO;
			/* Get a hold on the IRE_NOROUTE */
			ire = ire_reject(ipst, isv6);
			return (ire);
		}
		if (!(ill->ill_flags & ILLF_MULTICAST)) {
			ill_refrele(ill);
			if (errorp != NULL)
				*errorp = EHOSTUNREACH;
			/* Get a hold on the IRE_NOROUTE */
			ire = ire_reject(ipst, isv6);
			return (ire);
		}
		/*
		 * If we are doing the strictest src_multihoming, then
		 * we check that IP_MULTICAST_IF, IP_BOUND_IF, etc specify
		 * an interface that is consistent with the source address.
		 */
		if (verify_src && src_multihoming == 2 &&
		    !ip_verify_src_on_ill(v6src, ill, ixa->ixa_zoneid)) {
			if (errorp != NULL)
				*errorp = EADDRNOTAVAIL;
			ill_refrele(ill);
			/* Get a hold on the IRE_NOROUTE */
			ire = ire_reject(ipst, isv6);
			return (ire);
		}
		/* Get a refcnt on the single IRE_MULTICAST per ill */
		ire = ire_multicast(ill);
		ill_refrele(ill);
		if (generationp != NULL)
			*generationp = ire->ire_generation;
		if (errorp != NULL &&
		    (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))) {
			*errorp = EHOSTUNREACH;
		}
		return (ire);
	}

	/* Now for unicast */
	if (ixa->ixa_ifindex != 0 || (ixaflags & IXAF_SCOPEID_SET)) {
		if (ixaflags & IXAF_SCOPEID_SET) {
			/* sin6_scope_id takes precedence over ixa_ifindex */
			ASSERT(ixa->ixa_scopeid != 0);
			ill = ill_lookup_on_ifindex(ixa->ixa_scopeid,
			    isv6, ipst);
		} else {
			ASSERT(ixa->ixa_ifindex != 0);
			ill = ill_lookup_on_ifindex(ixa->ixa_ifindex,
			    isv6, ipst);
		}
		if (ill != NULL && IS_VNI(ill)) {
			ill_refrele(ill);
			ill = NULL;
		}
		if (ill == NULL) {
			if (errorp != NULL)
				*errorp = ENXIO;
			/* Get a hold on the IRE_NOROUTE */
			ire = ire_reject(ipst, isv6);
			return (ire);
		}

		match_args |= MATCH_IRE_ILL;

		/*
		 * icmp_send_reply_v6 uses scopeid, and mpathd sets IP*_BOUND_IF
		 * so for both of them we need to be able look for an under
		 * interface.
		 */
		if (IS_UNDER_IPMP(ill))
			match_args |= MATCH_IRE_TESTHIDDEN;

		/*
		 * If we are doing the strictest src_multihoming, then
		 * we check that IP_BOUND_IF, IP_PKTINFO, etc specify
		 * an interface that is consistent with the source address.
		 */
		if (src_multihoming == 2 &&
		    !ip_verify_src_on_ill(v6src, ill, ixa->ixa_zoneid)) {
			if (errorp != NULL)
				*errorp = EADDRNOTAVAIL;
			ill_refrele(ill);
			/* Get a hold on the IRE_NOROUTE */
			ire = ire_reject(ipst, isv6);
			return (ire);
		}
	} else if (src_multihoming != 0 && verify_src) {
		/* Look up the ill based on the source address */
		ill = ip_select_src_ill(&v6src, ixa->ixa_zoneid, ipst);
		if (ill == NULL) {
			char addrbuf[INET6_ADDRSTRLEN];

			ip3dbg(("%s not a valid src for unicast",
			    inet_ntop(AF_INET6, &v6src, addrbuf,
			    sizeof (addrbuf))));
			if (errorp != NULL)
				*errorp = EADDRNOTAVAIL;
			/* Get a hold on the IRE_NOROUTE */
			ire = ire_reject(ipst, isv6);
			return (ire);
		}
		match_args |= MATCH_IRE_SRC_ILL;
		preferred_src_aware = (src_multihoming == 1);
	}

	if (ixaflags & IXAF_NEXTHOP_SET) {
		/* IP_NEXTHOP was set */
		v6nexthop = ixa->ixa_nexthop_v6;
	} else {
		v6nexthop = *v6dst;
	}

	ire_type = 0;

	/*
	 * If SO_DONTROUTE is set or if IP_NEXTHOP is set, then
	 * we only look for an onlink IRE.
	 */
	if (ixaflags & (IXAF_DONTROUTE|IXAF_NEXTHOP_SET)) {
		match_args |= MATCH_IRE_TYPE;
		ire_type = IRE_ONLINK;
	}

retry:
	if (!isv6) {
		ipaddr_t	v4nexthop;
		ipaddr_t	v4setsrc = INADDR_ANY;

		IN6_V4MAPPED_TO_IPADDR(&v6nexthop, v4nexthop);
		ire = ire_route_recursive_v4(v4nexthop, ire_type, ill,
		    ixa->ixa_zoneid, ixa->ixa_tsl, match_args, IRR_ALLOCATE,
		    ixa->ixa_xmit_hint, ipst, &v4setsrc, NULL, generationp);
		if (setsrcp != NULL)
			IN6_IPADDR_TO_V4MAPPED(v4setsrc, setsrcp);
	} else {
		ire = ire_route_recursive_v6(&v6nexthop, ire_type, ill,
		    ixa->ixa_zoneid, ixa->ixa_tsl, match_args, IRR_ALLOCATE,
		    ixa->ixa_xmit_hint, ipst, setsrcp, NULL, generationp);
	}

#ifdef DEBUG
	if (match_args & MATCH_IRE_TESTHIDDEN) {
		ip3dbg(("looking for hidden; dst %x ire %p\n",
		    v4dst, (void *)ire));
	}
#endif
	if (ill != NULL) {
		ill_refrele(ill);
		ill = NULL;
	}
	if ((ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    (ire->ire_type & IRE_MULTICAST)) {
		if (preferred_src_aware) {
			/*
			 * "Preferred Source Aware" send mode. If we cannot
			 * find an ire whose ire_ill had the desired source
			 * address retry after relaxing the ill matching
			 * constraint.
			 */
			ire_refrele(ire);
			preferred_src_aware = B_FALSE;
			match_args &= ~MATCH_IRE_SRC_ILL;
			goto retry;
		}
		/* No ire_nce_cache */
		return (ire);
	}

	/* Setup ire_nce_cache if it doesn't exist or is condemned. */
	mutex_enter(&ire->ire_lock);
	nce = ire->ire_nce_cache;
	if (nce == NULL || nce->nce_is_condemned) {
		mutex_exit(&ire->ire_lock);
		(void) ire_revalidate_nce(ire);
	} else {
		mutex_exit(&ire->ire_lock);
	}
	return (ire);
}

/*
 * Find a route given some xmit attributes and a packet.
 * Generic for IPv4 and IPv6
 *
 * This never returns NULL. But when it returns the IRE_NOROUTE
 * it might set errorp.
 */
ire_t *
ip_select_route_pkt(mblk_t *mp, ip_xmit_attr_t *ixa, uint_t *generationp,
    int *errorp, boolean_t *multirtp)
{
	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t		*ipha = (ipha_t *)mp->b_rptr;
		in6_addr_t	v6dst, v6src;

		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &v6dst);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &v6src);

		return (ip_select_route(&v6dst, v6src, ixa, generationp,
		    NULL, errorp, multirtp));
	} else {
		ip6_t	*ip6h = (ip6_t *)mp->b_rptr;

		return (ip_select_route(&ip6h->ip6_dst, ip6h->ip6_src,
		    ixa, generationp, NULL, errorp, multirtp));
	}
}

ire_t *
ip_select_route_v4(ipaddr_t dst, ipaddr_t src, ip_xmit_attr_t *ixa,
    uint_t *generationp, ipaddr_t *v4setsrcp, int *errorp, boolean_t *multirtp)
{
	in6_addr_t	v6dst, v6src;
	ire_t		*ire;
	in6_addr_t	setsrc;

	ASSERT(ixa->ixa_flags & IXAF_IS_IPV4);

	IN6_IPADDR_TO_V4MAPPED(dst, &v6dst);
	IN6_IPADDR_TO_V4MAPPED(src, &v6src);

	setsrc = ipv6_all_zeros;
	ire = ip_select_route(&v6dst, v6src, ixa, generationp, &setsrc, errorp,
	    multirtp);
	if (v4setsrcp != NULL)
		IN6_V4MAPPED_TO_IPADDR(&setsrc, *v4setsrcp);
	return (ire);
}

/*
 * Recursively look for a route to the destination. Can also match on
 * the zoneid, ill, and label. Used for the data paths. See also
 * ire_route_recursive.
 *
 * If IRR_ALLOCATE is not set then we will only inspect the existing IREs; never
 * create an IRE_IF_CLONE. This is used on the receive side when we are not
 * forwarding.
 * If IRR_INCOMPLETE is set then we return the IRE even if we can't correctly
 * resolve the gateway.
 *
 * Note that this function never returns NULL. It returns an IRE_NOROUTE
 * instead.
 *
 * If we find any IRE_LOCAL|BROADCAST etc past the first iteration it
 * is an error.
 * Allow at most one RTF_INDIRECT.
 */
ire_t *
ire_route_recursive_impl_v4(ire_t *ire,
    ipaddr_t nexthop, uint_t ire_type, const ill_t *ill_arg,
    zoneid_t zoneid, const ts_label_t *tsl, uint_t match_args,
    uint_t irr_flags, uint32_t xmit_hint, ip_stack_t *ipst, ipaddr_t *setsrcp,
    tsol_ire_gw_secattr_t **gwattrp, uint_t *generationp)
{
	int		i, j;
	ire_t		*ires[MAX_IRE_RECURSION];
	uint_t		generation;
	uint_t		generations[MAX_IRE_RECURSION];
	boolean_t	need_refrele = B_FALSE;
	boolean_t	invalidate = B_FALSE;
	ill_t		*ill = NULL;
	uint_t		maskoff = (IRE_LOCAL|IRE_LOOPBACK|IRE_BROADCAST);

	if (setsrcp != NULL)
		ASSERT(*setsrcp == INADDR_ANY);
	if (gwattrp != NULL)
		ASSERT(*gwattrp == NULL);

	/*
	 * We iterate up to three times to resolve a route, even though
	 * we have four slots in the array. The extra slot is for an
	 * IRE_IF_CLONE we might need to create.
	 */
	i = 0;
	while (i < MAX_IRE_RECURSION - 1) {
		/* ire_ftable_lookup handles round-robin/ECMP */
		if (ire == NULL) {
			ire = ire_ftable_lookup_v4(nexthop, 0, 0, ire_type,
			    (ill != NULL? ill : ill_arg), zoneid, tsl,
			    match_args, xmit_hint, ipst, &generation);
		} else {
			/* Caller passed it; extra hold since we will rele */
			ire_refhold(ire);
			if (generationp != NULL)
				generation = *generationp;
			else
				generation = IRE_GENERATION_VERIFY;
		}
		if (ire == NULL) {
			if (i > 0 && (irr_flags & IRR_INCOMPLETE)) {
				ire = ires[0];
				ire_refhold(ire);
			} else {
				ire = ire_reject(ipst, B_FALSE);
			}
			goto error;
		}

		/* Need to return the ire with RTF_REJECT|BLACKHOLE */
		if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))
			goto error;

		ASSERT(!(ire->ire_type & IRE_MULTICAST)); /* Not in ftable */
		/*
		 * Verify that the IRE_IF_CLONE has a consistent generation
		 * number.
		 */
		if ((ire->ire_type & IRE_IF_CLONE) && !ire_clone_verify(ire)) {
			ire_refrele(ire);
			ire = NULL;
			continue;
		}

		/*
		 * Don't allow anything unusual past the first iteration.
		 * After the first lookup, we should no longer look for
		 * (IRE_LOCAL|IRE_LOOPBACK|IRE_BROADCAST) or RTF_INDIRECT
		 * routes.
		 *
		 * In addition, after we have found a direct IRE_OFFLINK,
		 * we should only look for interface or clone routes.
		 */
		match_args |= MATCH_IRE_DIRECT; /* no more RTF_INDIRECTs */

		if ((ire->ire_type & IRE_OFFLINK) &&
		    !(ire->ire_flags & RTF_INDIRECT)) {
			ire_type = IRE_IF_ALL;
		} else {
			/*
			 * no more local, loopback, broadcast routes
			 */
			if (!(match_args & MATCH_IRE_TYPE))
				ire_type = (IRE_OFFLINK|IRE_ONLINK);
			ire_type &= ~maskoff;
		}
		match_args |= MATCH_IRE_TYPE;

		/* We have a usable IRE */
		ires[i] = ire;
		generations[i] = generation;
		i++;

		/* The first RTF_SETSRC address is passed back if setsrcp */
		if ((ire->ire_flags & RTF_SETSRC) &&
		    setsrcp != NULL && *setsrcp == INADDR_ANY) {
			ASSERT(ire->ire_setsrc_addr != INADDR_ANY);
			*setsrcp = ire->ire_setsrc_addr;
		}

		/* The first ire_gw_secattr is passed back if gwattrp */
		if (ire->ire_gw_secattr != NULL &&
		    gwattrp != NULL && *gwattrp == NULL)
			*gwattrp = ire->ire_gw_secattr;

		/*
		 * Check if we have a short-cut pointer to an IRE for this
		 * destination, and that the cached dependency isn't stale.
		 * In that case we've rejoined an existing tree towards a
		 * parent, thus we don't need to continue the loop to
		 * discover the rest of the tree.
		 */
		mutex_enter(&ire->ire_lock);
		if (ire->ire_dep_parent != NULL &&
		    ire->ire_dep_parent->ire_generation ==
		    ire->ire_dep_parent_generation) {
			mutex_exit(&ire->ire_lock);
			ire = NULL;
			goto done;
		}
		mutex_exit(&ire->ire_lock);

		/*
		 * If this type should have an ire_nce_cache (even if it
		 * doesn't yet have one) then we are done. Includes
		 * IRE_INTERFACE with a full 32 bit mask.
		 */
		if (ire->ire_nce_capable) {
			ire = NULL;
			goto done;
		}
		ASSERT(!(ire->ire_type & IRE_IF_CLONE));
		/*
		 * For an IRE_INTERFACE we create an IRE_IF_CLONE for this
		 * particular destination
		 */
		if (ire->ire_type & IRE_INTERFACE) {
			in6_addr_t	v6nexthop;
			ire_t		*clone;

			ASSERT(ire->ire_masklen != IPV4_ABITS);

			/*
			 * In the case of ip_input and ILLF_FORWARDING not
			 * being set, and in the case of RTM_GET, there is
			 * no point in allocating an IRE_IF_CLONE. We return
			 * the IRE_INTERFACE. Note that !IRR_ALLOCATE can
			 * result in a ire_dep_parent which is IRE_IF_*
			 * without an IRE_IF_CLONE.
			 * We recover from that when we need to send packets
			 * by ensuring that the generations become
			 * IRE_GENERATION_VERIFY in this case.
			 */
			if (!(irr_flags & IRR_ALLOCATE)) {
				invalidate = B_TRUE;
				ire = NULL;
				goto done;
			}

			IN6_IPADDR_TO_V4MAPPED(nexthop, &v6nexthop);

			clone = ire_create_if_clone(ire, &v6nexthop,
			    &generation);
			if (clone == NULL) {
				/*
				 * Temporary failure - no memory.
				 * Don't want caller to cache IRE_NOROUTE.
				 */
				invalidate = B_TRUE;
				ire = ire_blackhole(ipst, B_FALSE);
				goto error;
			}
			/*
			 * Make clone next to last entry and the
			 * IRE_INTERFACE the last in the dependency
			 * chain since the clone depends on the
			 * IRE_INTERFACE.
			 */
			ASSERT(i >= 1);
			ASSERT(i < MAX_IRE_RECURSION);

			ires[i] = ires[i-1];
			generations[i] = generations[i-1];
			ires[i-1] = clone;
			generations[i-1] = generation;
			i++;

			ire = NULL;
			goto done;
		}

		/*
		 * We only match on the type and optionally ILL when
		 * recursing. The type match is used by some callers
		 * to exclude certain types (such as IRE_IF_CLONE or
		 * IRE_LOCAL|IRE_LOOPBACK).
		 *
		 * In the MATCH_IRE_SRC_ILL case, ill_arg may be the 'srcof'
		 * ire->ire_ill, and we want to find the IRE_INTERFACE for
		 * ire_ill, so we set ill to the ire_ill;
		 */
		match_args &= (MATCH_IRE_TYPE | MATCH_IRE_DIRECT);
		nexthop = ire->ire_gateway_addr;
		if (ill == NULL && ire->ire_ill != NULL) {
			ill = ire->ire_ill;
			need_refrele = B_TRUE;
			ill_refhold(ill);
			match_args |= MATCH_IRE_ILL;
		}
		ire = NULL;
	}
	ASSERT(ire == NULL);
	ire = ire_reject(ipst, B_FALSE);

error:
	ASSERT(ire != NULL);
	if (need_refrele)
		ill_refrele(ill);

	/*
	 * In the case of MULTIRT we want to try a different IRE the next
	 * time. We let the next packet retry in that case.
	 */
	if (i > 0 && (ires[0]->ire_flags & RTF_MULTIRT))
		(void) ire_no_good(ires[0]);

cleanup:
	/* cleanup ires[i] */
	ire_dep_unbuild(ires, i);
	for (j = 0; j < i; j++)
		ire_refrele(ires[j]);

	ASSERT((ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    (irr_flags & IRR_INCOMPLETE));
	/*
	 * Use IRE_GENERATION_VERIFY to ensure that ip_output will redo the
	 * ip_select_route since the reject or lack of memory might be gone.
	 */
	if (generationp != NULL)
		*generationp = IRE_GENERATION_VERIFY;
	return (ire);

done:
	ASSERT(ire == NULL);
	if (need_refrele) {
		ill_refrele(ill);
		ill = NULL;
	}

	/* Build dependencies */
	if (i > 1 && !ire_dep_build(ires, generations, i)) {
		/* Something in chain was condemned; tear it apart */
		ire = ire_reject(ipst, B_FALSE);
		goto cleanup;
	}

	/*
	 * Release all refholds except the one for ires[0] that we
	 * will return to the caller.
	 */
	for (j = 1; j < i; j++)
		ire_refrele(ires[j]);

	if (invalidate) {
		/*
		 * Since we needed to allocate but couldn't we need to make
		 * sure that the dependency chain is rebuilt the next time.
		 */
		ire_dep_invalidate_generations(ires[0]);
		generation = IRE_GENERATION_VERIFY;
	} else {
		/*
		 * IREs can have been added or deleted while we did the
		 * recursive lookup and we can't catch those until we've built
		 * the dependencies. We verify the stored
		 * ire_dep_parent_generation to catch any such changes and
		 * return IRE_GENERATION_VERIFY (which will cause
		 * ip_select_route to be called again so we can redo the
		 * recursive lookup next time we send a packet.
		 */
		if (ires[0]->ire_dep_parent == NULL)
			generation = ires[0]->ire_generation;
		else
			generation = ire_dep_validate_generations(ires[0]);
		if (generations[0] != ires[0]->ire_generation) {
			/* Something changed at the top */
			generation = IRE_GENERATION_VERIFY;
		}
	}
	if (generationp != NULL)
		*generationp = generation;

	return (ires[0]);
}

ire_t *
ire_route_recursive_v4(ipaddr_t nexthop, uint_t ire_type, const ill_t *ill,
    zoneid_t zoneid, const ts_label_t *tsl, uint_t match_args,
    uint_t irr_flags, uint32_t xmit_hint, ip_stack_t *ipst, ipaddr_t *setsrcp,
    tsol_ire_gw_secattr_t **gwattrp, uint_t *generationp)
{
	return (ire_route_recursive_impl_v4(NULL, nexthop, ire_type, ill,
	    zoneid, tsl, match_args, irr_flags, xmit_hint, ipst, setsrcp,
	    gwattrp, generationp));
}

/*
 * Recursively look for a route to the destination.
 * We only handle a destination match here, yet we have the same arguments
 * as the full match to allow function pointers to select between the two.
 *
 * Note that this function never returns NULL. It returns an IRE_NOROUTE
 * instead.
 *
 * If we find any IRE_LOCAL|BROADCAST etc past the first iteration it
 * is an error.
 * Allow at most one RTF_INDIRECT.
 */
ire_t *
ire_route_recursive_dstonly_v4(ipaddr_t nexthop, uint_t irr_flags,
    uint32_t xmit_hint, ip_stack_t *ipst)
{
	ire_t	*ire;
	ire_t	*ire1;
	uint_t	generation;

	/* ire_ftable_lookup handles round-robin/ECMP */
	ire = ire_ftable_lookup_simple_v4(nexthop, xmit_hint, ipst,
	    &generation);
	ASSERT(ire != NULL);
	/*
	 * If the IRE has a current cached parent we know that the whole
	 * parent chain is current, hence we don't need to discover and
	 * build any dependencies by doing a recursive lookup.
	 */
	mutex_enter(&ire->ire_lock);
	if (ire->ire_dep_parent != NULL) {
		if (ire->ire_dep_parent->ire_generation ==
		    ire->ire_dep_parent_generation) {
			mutex_exit(&ire->ire_lock);
			return (ire);
		}
		mutex_exit(&ire->ire_lock);
	} else {
		mutex_exit(&ire->ire_lock);
		/*
		 * If this type should have an ire_nce_cache (even if it
		 * doesn't yet have one) then we are done. Includes
		 * IRE_INTERFACE with a full 32 bit mask.
		 */
		if (ire->ire_nce_capable)
			return (ire);
	}

	/*
	 * Fallback to loop in the normal code starting with the ire
	 * we found. Normally this would return the same ire.
	 */
	ire1 = ire_route_recursive_impl_v4(ire, nexthop, 0, NULL, ALL_ZONES,
	    NULL, MATCH_IRE_DSTONLY, irr_flags, xmit_hint, ipst, NULL, NULL,
	    &generation);
	ire_refrele(ire);
	return (ire1);
}

/*
 * Verify that the generation numbers in the chain leading to an IRE_IF_CLONE
 * are consistent. Return FALSE (and delete the IRE_IF_CLONE) if they
 * are not consistent, and TRUE otherwise.
 */
boolean_t
ire_clone_verify(ire_t *ire)
{
	ASSERT((ire->ire_type & IRE_IF_CLONE) != 0);
	mutex_enter(&ire->ire_lock);
	if (ire->ire_dep_parent != NULL &&
	    ire->ire_dep_parent->ire_generation !=
	    ire->ire_dep_parent_generation) {
		mutex_exit(&ire->ire_lock);
		ire_delete(ire);
		return (B_FALSE);
	}
	mutex_exit(&ire->ire_lock);
	return (B_TRUE);
}
