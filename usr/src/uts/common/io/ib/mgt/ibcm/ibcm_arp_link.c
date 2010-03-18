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

#include <sys/types.h>
#include <net/if.h>
#include <net/if_types.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ip_if.h>
#include <sys/ethernet.h>
#include <sys/ib/mgt/ibcm/ibcm_arp.h>

extern char cmlog[];

_NOTE(SCHEME_PROTECTS_DATA("Unshared data", ibcm_arp_streams_t))

static void ibcm_resolver_ack(ip2mac_t *, void *);
static int ibcm_nce_lookup(ibcm_arp_prwqn_t *wqnp, ill_t *ill, zoneid_t zid);

/*
 * delete a wait queue node from the list.
 * assumes mutex is acquired
 */
void
ibcm_arp_delete_prwqn(ibcm_arp_prwqn_t *wqnp)
{
	ibcm_arp_streams_t *ib_s;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_delete_prwqn(%p)", wqnp);

	ib_s = wqnp->ib_str;
	ib_s->wqnp = NULL;
	kmem_free(wqnp, sizeof (ibcm_arp_prwqn_t));
}

/*
 * allocate a wait queue node, and insert it in the list
 */
static ibcm_arp_prwqn_t *
ibcm_arp_create_prwqn(ibcm_arp_streams_t *ib_s, ibt_ip_addr_t *dst_addr,
    ibt_ip_addr_t *src_addr)
{
	ibcm_arp_prwqn_t *wqnp;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_create_prwqn(ib_s: 0x%p)", ib_s);

	if (dst_addr == NULL) {
		return (NULL);
	}
	if ((wqnp = kmem_zalloc(sizeof (ibcm_arp_prwqn_t), KM_NOSLEEP)) ==
	    NULL) {
		return (NULL);
	}
	wqnp->dst_addr = *dst_addr;

	if (src_addr) {
		wqnp->usrc_addr = *src_addr;
	}
	wqnp->ib_str = ib_s;
	wqnp->ifproto = (dst_addr->family == AF_INET) ?
	    ETHERTYPE_IP : ETHERTYPE_IPV6;

	ib_s->wqnp = wqnp;

	IBTF_DPRINTF_L4(cmlog, "ibcm_arp_create_prwqn: Return wqnp: %p", wqnp);

	return (wqnp);
}


/*
 * Check if the interface is loopback or IB.
 */
static int
ibcm_arp_check_interface(ill_t *ill)
{
	if (IS_LOOPBACK(ill) || ill->ill_type == IFT_IB)
		return (0);

	return (ETIMEDOUT);
}

int
ibcm_resolver_pr_lookup(ibcm_arp_streams_t *ib_s, ibt_ip_addr_t *dst_addr,
    ibt_ip_addr_t *src_addr, zoneid_t myzoneid)
{
	ibcm_arp_prwqn_t *wqnp;
	ire_t	*ire = NULL;
	ipif_t	*ipif = NULL;
	ill_t	*ill = NULL;
	ill_t	*hwaddr_ill = NULL;
	ip_stack_t *ipst;
	ipaddr_t	setsrcv4;
	in6_addr_t	setsrcv6;

	IBCM_PRINT_IP("ibcm_arp_pr_lookup: SRC", src_addr);
	IBCM_PRINT_IP("ibcm_arp_pr_lookup: DST", dst_addr);

	if ((wqnp = ibcm_arp_create_prwqn(ib_s, dst_addr, src_addr)) == NULL) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_resolver_pr_lookup: "
		    "ibcm_arp_create_prwqn failed");
		ib_s->status = ENOMEM;
		return (1);
	}

	ipst = netstack_find_by_zoneid(myzoneid)->netstack_ip;
	if (dst_addr->family == AF_INET) {
		/*
		 * get an ire for the destination adress.
		 * Note that we can't use MATCH_IRE_ILL since that would
		 * require that the first ill we find have ire_ill set.
		 */
		setsrcv4 = INADDR_ANY;
		ire = ire_route_recursive_v4(dst_addr->un.ip4addr, 0, NULL,
		    myzoneid, NULL, MATCH_IRE_DSTONLY, B_TRUE, 0, ipst,
		    &setsrcv4, NULL, NULL);

		ASSERT(ire != NULL);
		if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_resolver_pr_lookup: "
			    "ire_route_recursive_v4 failed");
			ib_s->status = EFAULT;
			goto fail;
		}
		ill = ire_nexthop_ill(ire);
		if (ill == NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_resolver_pr_lookup: "
			    "ire_nexthop_ill failed");
			ib_s->status = EFAULT;
			goto fail;
		}

		/* Pick a source address */
		if (ip_select_source_v4(ill, setsrcv4, dst_addr->un.ip4addr,
		    INADDR_ANY, myzoneid, ipst, &wqnp->src_addr.un.ip4addr,
		    NULL, NULL) != 0) {
			ib_s->status = EADDRNOTAVAIL;
			goto fail;
		}

		wqnp->gateway.un.ip4addr = ire->ire_gateway_addr;
		wqnp->netmask.un.ip4addr = ire->ire_mask;
		wqnp->src_addr.family = wqnp->gateway.family =
		    wqnp->netmask.family = AF_INET;

	} else if (dst_addr->family == AF_INET6) {
		/*
		 * get an ire for the destination adress.
		 * Note that we can't use MATCH_IRE_ILL since that would
		 * require that the first ill we find have ire_ill set. Thus
		 * we compare ire_ill against ipif_ill after the lookup.
		 */
		setsrcv6 = ipv6_all_zeros;
		ire = ire_route_recursive_v6(&dst_addr->un.ip6addr, 0, NULL,
		    myzoneid, NULL, MATCH_IRE_DSTONLY, B_TRUE, 0, ipst,
		    &setsrcv6, NULL, NULL);

		ASSERT(ire != NULL);
		if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_resolver_pr_lookup: "
			    "ire_route_recursive_v6 failed");
			ib_s->status = EFAULT;
			goto fail;
		}
		ill = ire_nexthop_ill(ire);
		if (ill == NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_resolver_pr_lookup: "
			    "ire_nexthop_ill failed");
			ib_s->status = EFAULT;
			goto fail;
		}

		/* Pick a source address */
		if (ip_select_source_v6(ill, &setsrcv6, &dst_addr->un.ip6addr,
		    myzoneid, ipst, B_FALSE, IPV6_PREFER_SRC_DEFAULT,
		    &wqnp->src_addr.un.ip6addr, NULL, NULL) != 0) {
			ib_s->status = EADDRNOTAVAIL;
			goto fail;
		}

		wqnp->gateway.un.ip6addr = ire->ire_gateway_addr_v6;
		wqnp->netmask.un.ip6addr = ire->ire_mask_v6;
		wqnp->src_addr.family = wqnp->gateway.family =
		    wqnp->netmask.family = AF_INET6;
	}

	(void) strlcpy(wqnp->ifname, ill->ill_name, sizeof (wqnp->ifname));

	/*
	 * For IPMP data addresses, we need to use the hardware address of the
	 * interface bound to the given address.
	 */
	if (IS_IPMP(ill)) {
		if (wqnp->src_addr.family == AF_INET) {
			ipif = ipif_lookup_addr(wqnp->src_addr.un.ip4addr, ill,
			    myzoneid, ipst);
		} else {
			ipif = ipif_lookup_addr_v6(&wqnp->src_addr.un.ip6addr,
			    ill, myzoneid, ipst);
		}
		if (ipif == NULL) {
			ib_s->status = ENETUNREACH;
			goto fail;
		}

		if ((hwaddr_ill = ipmp_ipif_hold_bound_ill(ipif)) == NULL) {
			IBTF_DPRINTF_L2(cmlog, "ibcm_resolver_pr_lookup: "
			    "no bound ill for IPMP interface %s",
			    ill->ill_name);
			ib_s->status = EFAULT;
			goto fail;
		}
	} else {
		hwaddr_ill = ill;
		ill_refhold(hwaddr_ill);	/* for symmetry */
	}

	if ((ib_s->status = ibcm_arp_check_interface(hwaddr_ill)) != 0) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_resolver_pr_lookup: "
		    "ibcm_arp_check_interface failed");
		goto fail;
	}

	bcopy(hwaddr_ill->ill_phys_addr, &wqnp->src_mac,
	    hwaddr_ill->ill_phys_addr_length);

	IBTF_DPRINTF_L4(cmlog, "ibcm_resolver_pr_lookup: outgoing if:%s",
	    wqnp->ifname);

	/*
	 * at this stage, we have the source address and the IB
	 * interface, now get the destination mac address from
	 * arp or ipv6 drivers
	 */
	ib_s->status = ibcm_nce_lookup(wqnp, ill, myzoneid);
	if (ib_s->status != 0) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_resolver_pr_lookup: "
		    "ibcm_nce_lookup failed: %d", ib_s->status);
		goto fail;
	}

	ill_refrele(hwaddr_ill);
	ill_refrele(ill);
	ire_refrele(ire);
	if (ipif != NULL)
		ipif_refrele(ipif);
	netstack_rele(ipst->ips_netstack);

	IBTF_DPRINTF_L4(cmlog, "ibcm_resolver_pr_lookup: Return: 0x%p", wqnp);
	return (0);
fail:
	if (hwaddr_ill != NULL)
		ill_refrele(hwaddr_ill);
	if (ill != NULL)
		ill_refrele(ill);
	if (ire != NULL)
		ire_refrele(ire);
	if (ipif != NULL)
		ipif_refrele(ipif);
	ibcm_arp_delete_prwqn(wqnp);
	netstack_rele(ipst->ips_netstack);
	return (1);
}

/*
 * Query the neighbor cache for IPv4/IPv6 to mac address mapping.
 */
static int
ibcm_nce_lookup(ibcm_arp_prwqn_t *wqnp, ill_t *ill, zoneid_t zoneid)
{
	ip2mac_t	ip2m;
	sin_t		*sin;
	sin6_t		*sin6;
	ip2mac_id_t	ip2mid;
	int		err;

	if (wqnp->src_addr.family != wqnp->dst_addr.family) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_nce_lookup: Mis-match SRC_ADDR "
		    "Family: %d, DST_ADDR Family %d", wqnp->src_addr.family,
		    wqnp->dst_addr.family);
		return (1);
	}
	bzero(&ip2m, sizeof (ip2m));

	if (wqnp->dst_addr.family == AF_INET) {
		sin = (sin_t *)&ip2m.ip2mac_pa;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = wqnp->dst_addr.un.ip4addr;
	} else if (wqnp->dst_addr.family == AF_INET6) {
		sin6 = (sin6_t *)&ip2m.ip2mac_pa;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = wqnp->dst_addr.un.ip6addr;
	} else {
		IBTF_DPRINTF_L2(cmlog, "ibcm_nce_lookup: Invalid DST_ADDR "
		    "Family: %d", wqnp->dst_addr.family);
		return (1);
	}

	ip2m.ip2mac_ifindex = ill->ill_phyint->phyint_ifindex;

	wqnp->flags |= IBCM_ARP_PR_RESOLVE_PENDING;

	/*
	 * issue the request to IP for Neighbor Discovery
	 */
	ip2mid = ip2mac(IP2MAC_RESOLVE, &ip2m, ibcm_resolver_ack, wqnp,
	    zoneid);
	err = ip2m.ip2mac_err;
	if (err == EINPROGRESS) {
		wqnp->ip2mac_id = ip2mid;
		wqnp->flags |= IBCM_ARP_PR_RESOLVE_PENDING;
		err = 0;
	} else if (err == 0) {
		ibcm_resolver_ack(&ip2m, wqnp);
	}
	return (err);
}

/*
 * do sanity checks on the link-level sockaddr
 */
static boolean_t
ibcm_check_sockdl(struct sockaddr_dl *sdl)
{

	if (sdl->sdl_type != IFT_IB || sdl->sdl_alen != IPOIB_ADDRL)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * callback for resolver lookups, both for success and failure.
 * If Address resolution was succesful: return GID info.
 */
static void
ibcm_resolver_ack(ip2mac_t *ip2macp, void *arg)
{
	ibcm_arp_prwqn_t *wqnp = (ibcm_arp_prwqn_t *)arg;
	ibcm_arp_streams_t *ib_s;
	uchar_t *cp;
	int err = 0;

	IBTF_DPRINTF_L4(cmlog, "ibcm_resolver_ack(%p, %p)", ip2macp, wqnp);

	ib_s = wqnp->ib_str;
	mutex_enter(&ib_s->lock);

	if (ip2macp->ip2mac_err != 0) {
		wqnp->flags &= ~IBCM_ARP_PR_RESOLVE_PENDING;
		cv_broadcast(&ib_s->cv);
		err = EHOSTUNREACH;
		goto user_callback;
	}

	if (!ibcm_check_sockdl(&ip2macp->ip2mac_ha)) {
		IBTF_DPRINTF_L2(cmlog, "ibcm_resolver_ack: Error: "
		    "interface %s is not IB\n", wqnp->ifname);
		err = EHOSTUNREACH;
		goto user_callback;
	}

	cp = (uchar_t *)LLADDR(&ip2macp->ip2mac_ha);
	bcopy(cp, &wqnp->dst_mac, IPOIB_ADDRL);

	/*
	 * at this point we have src/dst gid's derived from the mac addresses
	 * now get the hca, port
	 */
	bcopy(&wqnp->src_mac.ipoib_gidpref, &wqnp->sgid, sizeof (ib_gid_t));
	bcopy(&wqnp->dst_mac.ipoib_gidpref, &wqnp->dgid, sizeof (ib_gid_t));

	IBCM_H2N_GID(wqnp->sgid);
	IBCM_H2N_GID(wqnp->dgid);

user_callback:

	ib_s->status = err;
	ib_s->done = B_TRUE;

	/* lock is held by the caller. */
	cv_signal(&ib_s->cv);
	mutex_exit(&ib_s->lock);
}
