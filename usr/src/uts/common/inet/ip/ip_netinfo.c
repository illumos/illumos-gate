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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/pattr.h>
#include <sys/dlpi.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/socket.h>
#include <sys/neti.h>

#include <netinet/in.h>
#include <inet/common.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_impl.h>
#include <inet/ip_ndp.h>
#include <inet/ipclassifier.h>
#include <inet/ipp_common.h>
#include <inet/ip_ftable.h>

/*
 * IPv4 netinfo entry point declarations.
 */
static int 		ip_getifname(phy_if_t, char *, const size_t);
static int 		ip_getmtu(phy_if_t, lif_if_t);
static int 		ip_getpmtuenabled(void);
static int 		ip_getlifaddr(phy_if_t, lif_if_t, size_t,
			    net_ifaddr_t [], void *);
static phy_if_t		ip_phygetnext(phy_if_t);
static phy_if_t 	ip_phylookup(const char *);
static lif_if_t 	ip_lifgetnext(phy_if_t, lif_if_t);
static int 		ip_inject(inject_t, net_inject_t *);
static phy_if_t 	ip_routeto(struct sockaddr *);
static int 		ip_ispartialchecksum(mblk_t *);
static int 		ip_isvalidchecksum(mblk_t *);

static int 		ipv6_getifname(phy_if_t, char *, const size_t);
static int 		ipv6_getmtu(phy_if_t, lif_if_t);
static int 		ipv6_getlifaddr(phy_if_t, lif_if_t, size_t,
			    net_ifaddr_t [], void *);
static phy_if_t 	ipv6_phygetnext(phy_if_t);
static phy_if_t 	ipv6_phylookup(const char *);
static lif_if_t 	ipv6_lifgetnext(phy_if_t, lif_if_t);
static int 		ipv6_inject(inject_t, net_inject_t *);
static phy_if_t 	ipv6_routeto(struct sockaddr *);
static int 		ipv6_isvalidchecksum(mblk_t *);

/* Netinfo private functions */
static	int		ip_getifname_impl(phy_if_t, char *,
			    const size_t, boolean_t);
static	int		ip_getmtu_impl(phy_if_t, lif_if_t, boolean_t);
static	phy_if_t	ip_phylookup_impl(const char *, boolean_t);
static	lif_if_t	ip_lifgetnext_impl(phy_if_t, lif_if_t, boolean_t);
static	int		ip_inject_impl(inject_t, net_inject_t *, boolean_t);
static	int		ip_getifaddr_type(sa_family_t, ipif_t *, lif_if_t,
			    void *);
static	phy_if_t	ip_routeto_impl(struct sockaddr *);
static	int		ip_getlifaddr_impl(sa_family_t, phy_if_t, lif_if_t,
			    size_t, net_ifaddr_t [], struct sockaddr *);
static	void		ip_ni_queue_in_func(void *);
static	void		ip_ni_queue_out_func(void *);
static	void		ip_ni_queue_func_impl(injection_t *,  boolean_t);


static net_info_t ipv4info = {
	NETINFO_VERSION,
	NHF_INET,
	ip_getifname,
	ip_getmtu,
	ip_getpmtuenabled,
	ip_getlifaddr,
	ip_phygetnext,
	ip_phylookup,
	ip_lifgetnext,
	ip_inject,
	ip_routeto,
	ip_ispartialchecksum,
	ip_isvalidchecksum
};


static net_info_t ipv6info = {
	NETINFO_VERSION,
	NHF_INET6,
	ipv6_getifname,
	ipv6_getmtu,
	ip_getpmtuenabled,
	ipv6_getlifaddr,
	ipv6_phygetnext,
	ipv6_phylookup,
	ipv6_lifgetnext,
	ipv6_inject,
	ipv6_routeto,
	ip_ispartialchecksum,
	ipv6_isvalidchecksum
};

/*
 * The taskq eventq_queue_in is used to process the upside inject messages.
 * The taskq eventq_queue_out is used to process the downside inject messages.
 * The taskq eventq_queue_nic is used to process the nic event messages.
 */
static ddi_taskq_t 	*eventq_queue_in = NULL;
static ddi_taskq_t 	*eventq_queue_out = NULL;
ddi_taskq_t 	*eventq_queue_nic = NULL;

static hook_family_t	ipv4root;
static hook_family_t	ipv6root;

/*
 * Hooks for firewalling
 */
hook_event_t		ip4_physical_in_event;
hook_event_t		ip4_physical_out_event;
hook_event_t		ip4_forwarding_event;
hook_event_t		ip4_loopback_in_event;
hook_event_t		ip4_loopback_out_event;
hook_event_t		ip4_nic_events;
hook_event_t		ip6_physical_in_event;
hook_event_t		ip6_physical_out_event;
hook_event_t		ip6_forwarding_event;
hook_event_t		ip6_loopback_in_event;
hook_event_t		ip6_loopback_out_event;
hook_event_t		ip6_nic_events;

hook_event_token_t	ipv4firewall_physical_in;
hook_event_token_t	ipv4firewall_physical_out;
hook_event_token_t	ipv4firewall_forwarding;
hook_event_token_t	ipv4firewall_loopback_in;
hook_event_token_t	ipv4firewall_loopback_out;
hook_event_token_t	ipv4nicevents;
hook_event_token_t	ipv6firewall_physical_in;
hook_event_token_t	ipv6firewall_physical_out;
hook_event_token_t	ipv6firewall_forwarding;
hook_event_token_t	ipv6firewall_loopback_in;
hook_event_token_t	ipv6firewall_loopback_out;
hook_event_token_t	ipv6nicevents;

net_data_t		ipv4 = NULL;
net_data_t		ipv6 = NULL;


/*
 * Register IPv4 and IPv6 netinfo functions and initialize queues for inject.
 */
void
ip_net_init()
{

	ipv4 = net_register(&ipv4info);
	ASSERT(ipv4 != NULL);

	ipv6 = net_register(&ipv6info);
	ASSERT(ipv6 != NULL);

	if (eventq_queue_out == NULL) {
		eventq_queue_out = ddi_taskq_create(NULL,
		    "IP_INJECT_QUEUE_OUT", 1, TASKQ_DEFAULTPRI, 0);

		if (eventq_queue_out == NULL)
			cmn_err(CE_NOTE, "ipv4_net_init: "
			    "ddi_taskq_create failed for IP_INJECT_QUEUE_OUT");
	}

	if (eventq_queue_in == NULL) {
		eventq_queue_in = ddi_taskq_create(NULL,
		    "IP_INJECT_QUEUE_IN", 1, TASKQ_DEFAULTPRI, 0);

		if (eventq_queue_in == NULL)
			cmn_err(CE_NOTE, "ipv4_net_init: "
			    "ddi_taskq_create failed for IP_INJECT_QUEUE_IN");
	}

	if (eventq_queue_nic == NULL) {
		eventq_queue_nic = ddi_taskq_create(NULL,
		    "IP_NIC_EVENT_QUEUE", 1, TASKQ_DEFAULTPRI, 0);

		if (eventq_queue_nic == NULL)
			cmn_err(CE_NOTE, "ipv4_net_init: "
			    "ddi_taskq_create failed for IP_NIC_EVENT_QUEUE");
	}
}


/*
 * Unregister IPv4 and IPv6 functions and inject queues
 */
void
ip_net_destroy()
{

	if (eventq_queue_nic != NULL) {
		ddi_taskq_destroy(eventq_queue_nic);
		eventq_queue_nic = NULL;
	}

	if (eventq_queue_in != NULL) {
		ddi_taskq_destroy(eventq_queue_in);
		eventq_queue_in = NULL;
	}

	if (eventq_queue_out != NULL) {
		ddi_taskq_destroy(eventq_queue_out);
		eventq_queue_out = NULL;
	}

	if (ipv4 != NULL) {
		if (net_unregister(ipv4) == 0)
			ipv4 = NULL;
	}

	if (ipv6 != NULL) {
		if (net_unregister(ipv6) == 0)
			ipv6 = NULL;
	}
}


/*
 * Initialize IPv4 hooks family the event
 */
void
ipv4_hook_init()
{

	HOOK_FAMILY_INIT(&ipv4root, Hn_IPV4);
	if (net_register_family(ipv4, &ipv4root) != 0) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_register_family failed for ipv4");
	}

	HOOK_EVENT_INIT(&ip4_physical_in_event, NH_PHYSICAL_IN);
	ipv4firewall_physical_in = net_register_event(ipv4,
	    &ip4_physical_in_event);
	if (ipv4firewall_physical_in == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_register_event failed for ipv4/physical_in");
	}

	HOOK_EVENT_INIT(&ip4_physical_out_event, NH_PHYSICAL_OUT);
	ipv4firewall_physical_out = net_register_event(ipv4,
	    &ip4_physical_out_event);
	if (ipv4firewall_physical_out == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_register_event failed for ipv4/physical_out");
	}

	HOOK_EVENT_INIT(&ip4_forwarding_event, NH_FORWARDING);
	ipv4firewall_forwarding = net_register_event(ipv4,
	    &ip4_forwarding_event);
	if (ipv4firewall_forwarding == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_register_event failed for ipv4/forwarding");
	}

	HOOK_EVENT_INIT(&ip4_loopback_in_event, NH_LOOPBACK_IN);
	ipv4firewall_loopback_in = net_register_event(ipv4,
	    &ip4_loopback_in_event);
	if (ipv4firewall_loopback_in == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_register_event failed for ipv4/loopback_in");
	}

	HOOK_EVENT_INIT(&ip4_loopback_out_event, NH_LOOPBACK_OUT);
	ipv4firewall_loopback_out = net_register_event(ipv4,
	    &ip4_loopback_out_event);
	if (ipv4firewall_loopback_out == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_register_event failed for ipv4/loopback_out");
	}

	HOOK_EVENT_INIT(&ip4_nic_events, NH_NIC_EVENTS);
	ip4_nic_events.he_flags = HOOK_RDONLY;
	ipv4nicevents = net_register_event(ipv4, &ip4_nic_events);
	if (ipv4nicevents == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_register_event failed for ipv4/nic_events");
	}
}


void
ipv4_hook_destroy()
{
	if (ipv4firewall_forwarding != NULL) {
		if (net_unregister_event(ipv4, &ip4_forwarding_event) == 0)
			ipv4firewall_forwarding = NULL;
	}

	if (ipv4firewall_physical_in != NULL) {
		if (net_unregister_event(ipv4, &ip4_physical_in_event) == 0)
			ipv4firewall_physical_in = NULL;
	}

	if (ipv4firewall_physical_out != NULL) {
		if (net_unregister_event(ipv4, &ip4_physical_out_event) == 0)
			ipv4firewall_physical_out = NULL;
	}

	if (ipv4firewall_loopback_in != NULL) {
		if (net_unregister_event(ipv4, &ip4_loopback_in_event) == 0)
			ipv4firewall_loopback_in = NULL;
	}

	if (ipv4firewall_loopback_out != NULL) {
		if (net_unregister_event(ipv4, &ip4_loopback_out_event) == 0)
			ipv4firewall_loopback_out = NULL;
	}

	if (ipv4nicevents != NULL) {
		if (net_unregister_event(ipv4, &ip4_nic_events) == 0)
			ipv4nicevents = NULL;
	}

	(void) net_unregister_family(ipv4, &ipv4root);
}


/*
 * Initialize IPv6 hooks family and event
 */
void
ipv6_hook_init()
{

	HOOK_FAMILY_INIT(&ipv6root, Hn_IPV6);
	if (net_register_family(ipv6, &ipv6root) != 0) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_register_family failed for ipv6");
	}

	HOOK_EVENT_INIT(&ip6_physical_in_event, NH_PHYSICAL_IN);
	ipv6firewall_physical_in = net_register_event(ipv6,
	    &ip6_physical_in_event);
	if (ipv6firewall_physical_in == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_register_event failed for ipv6/physical_in");
	}

	HOOK_EVENT_INIT(&ip6_physical_out_event, NH_PHYSICAL_OUT);
	ipv6firewall_physical_out = net_register_event(ipv6,
	    &ip6_physical_out_event);
	if (ipv6firewall_physical_out == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_register_event failed for ipv6/physical_out");
	}

	HOOK_EVENT_INIT(&ip6_forwarding_event, NH_FORWARDING);
	ipv6firewall_forwarding = net_register_event(ipv6,
	    &ip6_forwarding_event);
	if (ipv6firewall_forwarding == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_register_event failed for ipv6/forwarding");
	}

	HOOK_EVENT_INIT(&ip6_loopback_in_event, NH_LOOPBACK_IN);
	ipv6firewall_loopback_in = net_register_event(ipv6,
	    &ip6_loopback_in_event);
	if (ipv6firewall_loopback_in == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_register_event failed for ipv6/loopback_in");
	}

	HOOK_EVENT_INIT(&ip6_loopback_out_event, NH_LOOPBACK_OUT);
	ipv6firewall_loopback_out = net_register_event(ipv6,
	    &ip6_loopback_out_event);
	if (ipv6firewall_loopback_out == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_register_event failed for ipv6/loopback_out");
	}

	HOOK_EVENT_INIT(&ip6_nic_events, NH_NIC_EVENTS);
	ip6_nic_events.he_flags = HOOK_RDONLY;
	ipv6nicevents = net_register_event(ipv6, &ip6_nic_events);
	if (ipv6nicevents == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_register_event failed for ipv6/nic_events");
	}
}


void
ipv6_hook_destroy()
{
	if (ipv6firewall_forwarding != NULL) {
		if (net_unregister_event(ipv6, &ip6_forwarding_event) == 0)
			ipv6firewall_forwarding = NULL;
	}

	if (ipv6firewall_physical_in != NULL) {
		if (net_unregister_event(ipv6, &ip6_physical_in_event) == 0)
			ipv6firewall_physical_in = NULL;
	}

	if (ipv6firewall_physical_out != NULL) {
		if (net_unregister_event(ipv6, &ip6_physical_out_event) == 0)
			ipv6firewall_physical_out = NULL;
	}

	if (ipv6firewall_loopback_in != NULL) {
		if (net_unregister_event(ipv6, &ip6_loopback_in_event) == 0)
			ipv6firewall_loopback_in = NULL;
	}

	if (ipv6firewall_loopback_out != NULL) {
		if (net_unregister_event(ipv6, &ip6_loopback_out_event) == 0)
			ipv6firewall_loopback_out = NULL;
	}

	if (ipv6nicevents != NULL) {
		if (net_unregister_event(ipv6, &ip6_nic_events) == 0)
			ipv6nicevents = NULL;
	}

	(void) net_unregister_family(ipv6, &ipv6root);
}


/*
 * Determine the name of an IPv4 interface
 */
static int
ip_getifname(phy_if_t phy_ifdata, char *buffer, const size_t buflen)
{

	return (ip_getifname_impl(phy_ifdata, buffer, buflen, B_FALSE));
}


/*
 * Determine the name of an IPv6 interface
 */
static int
ipv6_getifname(phy_if_t phy_ifdata, char *buffer, const size_t buflen)
{

	return (ip_getifname_impl(phy_ifdata, buffer, buflen, B_TRUE));
}


/*
 * Shared implementation to determine the name of a given network interface
 */
/* ARGSUSED */
static int
ip_getifname_impl(phy_if_t phy_ifdata,
    char *buffer, const size_t buflen, boolean_t isv6)
{
	ill_t *ill;

	ASSERT(buffer != NULL);

	ill = ill_lookup_on_ifindex((uint_t)phy_ifdata, isv6, NULL, NULL,
	    NULL, NULL);
	if (ill == NULL)
		return (1);

	if (ill->ill_name != NULL) {
		(void) strlcpy(buffer, ill->ill_name, buflen);
		ill_refrele(ill);
		return (0);
	} else {
		ill_refrele(ill);
		return (1);
	}

}


/*
 * Determine the MTU of an IPv4 network interface
 */
static int
ip_getmtu(phy_if_t phy_ifdata, lif_if_t ifdata)
{

	return (ip_getmtu_impl(phy_ifdata, ifdata, B_FALSE));
}


/*
 * Determine the MTU of an IPv6 network interface
 */
static int
ipv6_getmtu(phy_if_t phy_ifdata, lif_if_t ifdata)
{

	return (ip_getmtu_impl(phy_ifdata, ifdata, B_TRUE));
}


/*
 * Shared implementation to determine the MTU of a network interface
 */
/* ARGSUSED */
static int
ip_getmtu_impl(phy_if_t phy_ifdata, lif_if_t ifdata, boolean_t isv6)
{
	lif_if_t ipifid;
	ipif_t *ipif;
	int mtu;

	ipifid = UNMAP_IPIF_ID(ifdata);

	ipif = ipif_getby_indexes((uint_t)phy_ifdata, (uint_t)ipifid, isv6);
	if (ipif == NULL)
		return (0);

	mtu = ipif->ipif_mtu;
	ipif_refrele(ipif);

	if (mtu == 0) {
		ill_t *ill;

		if ((ill = ill_lookup_on_ifindex((uint_t)phy_ifdata, isv6,
		    NULL, NULL, NULL, NULL)) == NULL) {
			return (0);
		}
		mtu = ill->ill_max_frag;
		ill_refrele(ill);
	}

	return (mtu);
}


/*
 * Determine if path MTU discovery is enabled for IP
 */
static int
ip_getpmtuenabled(void)
{

	return (ip_path_mtu_discovery);
}


/*
 * Get next interface from the current list of IPv4 physical network interfaces
 */
static phy_if_t
ip_phygetnext(phy_if_t phy_ifdata)
{

	return (ill_get_next_ifindex(phy_ifdata, B_FALSE));
}


/*
 * Get next interface from the current list of IPv6 physical network interfaces
 */
static phy_if_t
ipv6_phygetnext(phy_if_t phy_ifdata)
{

	return (ill_get_next_ifindex(phy_ifdata, B_TRUE));
}


/*
 * Determine if a network interface name exists for IPv4
 */
static phy_if_t
ip_phylookup(const char *name)
{

	return (ip_phylookup_impl(name, B_FALSE));

}


/*
 * Determine if a network interface name exists for IPv6
 */
static phy_if_t
ipv6_phylookup(const char *name)
{

	return (ip_phylookup_impl(name, B_TRUE));
}


/*
 * Implement looking up an ill_t based on the name supplied and matching
 * it up with either IPv4 or IPv6.  ill_get_ifindex_by_name() is not used
 * because it does not match on the address family in addition to the name.
 */
static phy_if_t
ip_phylookup_impl(const char *name, boolean_t isv6)
{
	phy_if_t phy;
	ill_t *ill;

	ill = ill_lookup_on_name((char *)name, B_FALSE, isv6, NULL, NULL,
	    NULL, NULL, NULL);

	if (ill == NULL)
		return (0);

	phy = ill->ill_phyint->phyint_ifindex;

	ill_refrele(ill);

	return (phy);
}


/*
 * Get next interface from the current list of IPv4 logical network interfaces
 */
static lif_if_t
ip_lifgetnext(phy_if_t phy_ifdata, lif_if_t ifdata)
{

	return (ip_lifgetnext_impl(phy_ifdata, ifdata, B_FALSE));
}


/*
 * Get next interface from the current list of IPv6 logical network interfaces
 */
static lif_if_t
ipv6_lifgetnext(phy_if_t phy_ifdata, lif_if_t ifdata)
{

	return (ip_lifgetnext_impl(phy_ifdata, ifdata, B_TRUE));
}


/*
 * Shared implementation to get next interface from the current list of
 * logical network interfaces
 */
static lif_if_t
ip_lifgetnext_impl(phy_if_t phy_ifdata, lif_if_t ifdata, boolean_t isv6)
{
	lif_if_t newidx, oldidx;
	boolean_t nextok;
	ipif_t *ipif;
	ill_t *ill;

	ill = ill_lookup_on_ifindex(phy_ifdata, isv6, NULL, NULL, NULL, NULL);
	if (ill == NULL)
		return (0);

	if (ifdata != 0) {
		oldidx = UNMAP_IPIF_ID(ifdata);
		nextok = B_FALSE;
	} else {
		oldidx = 0;
		nextok = B_TRUE;
	}

	mutex_enter(&ill->ill_lock);
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		mutex_exit(&ill->ill_lock);
		ill_refrele(ill);
		return (0);
	}

	/*
	 * It's safe to iterate the ill_ipif list when holding an ill_lock.
	 * And it's also safe to access ipif_id without ipif refhold.
	 * See ipif_get_id().
	 */
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (!IPIF_CAN_LOOKUP(ipif))
			continue;
		if (nextok) {
			ipif_refhold_locked(ipif);
			break;
		} else if (oldidx == ipif->ipif_id) {
			nextok = B_TRUE;
		}
	}

	mutex_exit(&ill->ill_lock);
	ill_refrele(ill);

	if (ipif == NULL)
		return (0);

	newidx = ipif->ipif_id;
	ipif_refrele(ipif);

	return (MAP_IPIF_ID(newidx));
}


/*
 * Inject an IPv4 packet to or from an interface
 */
static int
ip_inject(inject_t style, net_inject_t *packet)
{

	return (ip_inject_impl(style, packet, B_FALSE));
}


/*
 * Inject an IPv6 packet to or from an interface
 */
static int
ipv6_inject(inject_t style, net_inject_t *packet)
{

	return (ip_inject_impl(style, packet, B_TRUE));
}


/*
 * Shared implementation to inject a packet to or from an interface
 * Return value:
 *   0: successful
 *  -1: memory allocation failed
 *   1: other errors
 */
static int
ip_inject_impl(inject_t style, net_inject_t *packet, boolean_t isv6)
{
	struct sockaddr_in6 *sin6;
	ddi_taskq_t *tq = NULL;
	void (* func)(void*);
	injection_t *inject;
	ip6_t *ip6h;
	ire_t *ire;
	mblk_t *mp;

	ASSERT(packet != NULL);
	ASSERT(packet->ni_packet != NULL);
	ASSERT(packet->ni_packet->b_datap->db_type == M_DATA);

	switch (style) {
	case NI_QUEUE_IN:
		inject = kmem_alloc(sizeof (*inject), KM_NOSLEEP);
		if (inject == NULL)
			return (-1);
		inject->inj_data = *packet;
		inject->inj_isv6 = isv6;
		/*
		 * deliver up into the kernel, immitating its reception by a
		 * network interface, add to list and schedule timeout
		 */
		func = ip_ni_queue_in_func;
		tq = eventq_queue_in;
		break;

	case NI_QUEUE_OUT:
		inject = kmem_alloc(sizeof (*inject), KM_NOSLEEP);
		if (inject == NULL)
			return (-1);
		inject->inj_data = *packet;
		inject->inj_isv6 = isv6;
		/*
		 * deliver out of the kernel, as if it were being sent via a
		 * raw socket so that IPFilter will see it again, add to list
		 * and schedule timeout
		 */
		func = ip_ni_queue_out_func;
		tq = eventq_queue_out;
		break;

	case NI_DIRECT_OUT:
		/*
		 * Note:
		 * For IPv4, the code path below will be greatly simplified
		 * with the delivery of surya - it will become a single
		 * function call to X.  A follow on project is aimed to
		 * provide similar functionality for IPv6.
		 */
		mp = packet->ni_packet;

		if (!isv6) {
			struct sockaddr *sock;

			sock = (struct sockaddr *)&packet->ni_addr;
			/*
			 * ipfil_sendpkt was provided by surya to ease the
			 * problems associated with sending out a packet.
			 * Currently this function only supports IPv4.
			 */
			switch (ipfil_sendpkt(sock, mp, packet->ni_physical,
			    ALL_ZONES)) {
			case 0 :
			case EINPROGRESS:
				return (0);
			case ECOMM :
			case ENONET :
				return (1);
			default :
				return (1);
			}
			/* NOTREACHED */

		}

		ip6h = (ip6_t *)mp->b_rptr;
		sin6 = (struct sockaddr_in6 *)&packet->ni_addr;
		ASSERT(sin6->sin6_family == AF_INET6);

		ire = ire_route_lookup_v6(&sin6->sin6_addr, 0, 0, 0,
		    NULL, NULL, ALL_ZONES, NULL,
		    MATCH_IRE_DSTONLY|MATCH_IRE_DEFAULT|MATCH_IRE_RECURSIVE);

		if (ire == NULL) {
			ip2dbg(("ip_inject: ire_cache_lookup failed\n"));
			freemsg(mp);
			return (1);
		}

		if (ire->ire_stq == NULL) {
			/* Send to loopback destination. */
			if (ire->ire_rfq == NULL) {
				ip2dbg(("ip_inject: bad nexthop\n"));
				ire_refrele(ire);
				freemsg(mp);
				return (1);
			}
			ip_wput_local_v6(ire->ire_rfq,
			    ire->ire_ipif->ipif_ill, ip6h, mp, ire, 0);
			ire_refrele(ire);
			return (0);
		}

		mp->b_queue = ire->ire_stq;

		if (ire->ire_nce == NULL ||
		    ire->ire_nce->nce_fp_mp == NULL &&
		    ire->ire_nce->nce_res_mp == NULL) {
			ip_newroute_v6(ire->ire_stq, mp,
			    &sin6->sin6_addr, NULL, NULL, ALL_ZONES);

			ire_refrele(ire);
			return (0);
		} else {
			/* prepend L2 header for IPv6 packets. */
			mblk_t *llmp;

			/*
			 * Lock IREs, see 6420438
			 */
			mutex_enter(&ire->ire_lock);
			llmp = ire->ire_nce->nce_fp_mp ?
			    ire->ire_nce->nce_fp_mp :
			    ire->ire_nce->nce_res_mp;

			if ((mp = dupb(llmp)) == NULL &&
			    (mp = copyb(llmp)) == NULL) {
				ip2dbg(("ip_inject: llhdr failed\n"));
				mutex_exit(&ire->ire_lock);
				ire_refrele(ire);
				freemsg(mp);
				return (1);
			}
			mutex_exit(&ire->ire_lock);
			linkb(mp, packet->ni_packet);
		}

		mp->b_queue = ire->ire_stq;

		break;
	default:
		freemsg(packet->ni_packet);
		return (1);
	}

	if (tq) {
		if (ddi_taskq_dispatch(tq, func, (void *)inject,
		    DDI_SLEEP) == DDI_FAILURE) {
			ip2dbg(("ip_inject:  ddi_taskq_dispatch failed\n"));
			freemsg(packet->ni_packet);
			return (1);
		}
	} else {
		putnext(ire->ire_stq, mp);
		ire_refrele(ire);
	}

	return (0);
}


/*
 * Find the interface used for traffic to a given IPv4 address
 */
static phy_if_t
ip_routeto(struct sockaddr *address)
{

	ASSERT(address != NULL);

	if (address->sa_family != AF_INET)
		return (0);
	return (ip_routeto_impl(address));
}


/*
 * Find the interface used for traffic to a given IPv6 address
 */
static phy_if_t
ipv6_routeto(struct sockaddr *address)
{

	ASSERT(address != NULL);

	if (address->sa_family != AF_INET6)
		return (0);
	return (ip_routeto_impl(address));
}


/*
 * Find the interface used for traffic to an address
 */
static phy_if_t
ip_routeto_impl(struct sockaddr *address)
{
	ire_t *ire;
	ill_t *ill;
	phy_if_t phy_if;

	if (address->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
		ire = ire_route_lookup_v6(&sin6->sin6_addr, NULL,
		    0, 0, NULL, NULL, ALL_ZONES, NULL,
		    MATCH_IRE_DSTONLY|MATCH_IRE_DEFAULT|MATCH_IRE_RECURSIVE);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)address;
		ire = ire_route_lookup(sin->sin_addr.s_addr, 0,
		    0, 0, NULL, NULL, ALL_ZONES, NULL,
		    MATCH_IRE_DSTONLY|MATCH_IRE_DEFAULT|MATCH_IRE_RECURSIVE);
	}

	if (ire == NULL)
		return (0);

	ill = ire_to_ill(ire);
	if (ill == NULL)
		return (0);

	ASSERT(ill != NULL);
	phy_if = (phy_if_t)ill->ill_phyint->phyint_ifindex;
	ire_refrele(ire);

	return (phy_if);
}


/*
 * Determine if checksumming is being used for the given packet.
 *
 * Return value:
 *   NET_HCK_NONE: full checksum recalculation is required
 *   NET_HCK_L3_FULL: full layer 3 checksum
 *   NET_HCK_L4_FULL: full layer 4 checksum
 *   NET_HCK_L4_PART: partial layer 4 checksum
 */
static int
ip_ispartialchecksum(mblk_t *mp)
{
	int ret = 0;

	ASSERT(mp != NULL);

	if ((DB_CKSUMFLAGS(mp) & HCK_FULLCKSUM) != 0) {
		ret |= (int)NET_HCK_L4_FULL;
		if ((DB_CKSUMFLAGS(mp) & HCK_IPV4_HDRCKSUM) != 0)
			ret |= (int)NET_HCK_L3_FULL;
	}
	if ((DB_CKSUMFLAGS(mp) & HCK_PARTIALCKSUM) != 0) {
		ret |= (int)NET_HCK_L4_PART;
		if ((DB_CKSUMFLAGS(mp) & HCK_IPV4_HDRCKSUM) != 0)
			ret |= (int)NET_HCK_L3_FULL;
	}

	return (ret);
}


/*
 * Return true or false, indicating whether the network and transport
 * headers are correct.  Use the capabilities flags and flags set in the
 * dblk_t to determine whether or not the checksum is valid.
 *
 * Return:
 *   0: the checksum was incorrect
 *   1: the original checksum was correct
 */
static int
ip_isvalidchecksum(mblk_t *mp)
{
	unsigned char *wptr;
	ipha_t *ipha = (ipha_t *)mp->b_rptr;
	int hlen;
	int ret;

	ASSERT(mp != NULL);

	if (dohwcksum &&
	    DB_CKSUM16(mp) != 0xFFFF &&
	    (DB_CKSUMFLAGS(mp) & HCK_FULLCKSUM) &&
	    (DB_CKSUMFLAGS(mp) & HCK_FULLCKSUM_OK) &&
	    (DB_CKSUMFLAGS(mp) & HCK_IPV4_HDRCKSUM))
		return (1);

	hlen = (ipha->ipha_version_and_hdr_length & 0x0F) << 2;

	/*
	 * Check that the mblk being passed in has enough data in it
	 * before blindly checking ip_cksum.
	 */
	if (msgdsize(mp) < hlen)
		return (0);

	if (mp->b_wptr < mp->b_rptr + hlen) {
		if (pullupmsg(mp, hlen) == 0)
			return (0);
		wptr = mp->b_wptr;
	} else {
		wptr = mp->b_wptr;
		mp->b_wptr = mp->b_rptr + hlen;
	}

	if (ipha->ipha_hdr_checksum == ip_cksum(mp, 0, ipha->ipha_hdr_checksum))
		ret = 1;
	else
		ret = 0;
	mp->b_wptr = wptr;

	return (ret);
}


/*
 * Unsupported with IPv6
 */
/*ARGSUSED*/
static int
ipv6_isvalidchecksum(mblk_t *mp)
{

	return (-1);
}

/*
 * Determine the network addresses for an IPv4 interface
 */
static int
ip_getlifaddr(phy_if_t phy_ifdata, lif_if_t ifdata, size_t nelem,
	net_ifaddr_t type[], void *storage)
{

	return (ip_getlifaddr_impl(AF_INET, phy_ifdata, ifdata,
	    nelem, type, storage));
}


/*
 * Determine the network addresses for an IPv6 interface
 */
static int
ipv6_getlifaddr(phy_if_t phy_ifdata, lif_if_t ifdata, size_t nelem,
		net_ifaddr_t type[], void *storage)
{

	return (ip_getlifaddr_impl(AF_INET6, phy_ifdata, ifdata,
	    nelem, type, storage));
}


/*
 * Shared implementation to determine the network addresses for an interface
 */
/* ARGSUSED */
static int
ip_getlifaddr_impl(sa_family_t family, phy_if_t phy_ifdata,
    lif_if_t ifdata, size_t nelem, net_ifaddr_t type[],
    struct sockaddr *storage)
{
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	lif_if_t ipifid;
	ipif_t *ipif;
	int i;

	ASSERT(type != NULL);
	ASSERT(storage != NULL);

	ipifid = UNMAP_IPIF_ID(ifdata);

	if (family == AF_INET) {
		if ((ipif = ipif_getby_indexes((uint_t)phy_ifdata,
		    (uint_t)ipifid, B_FALSE)) == NULL)
			return (1);

		sin = (struct sockaddr_in *)storage;
		for (i = 0; i < nelem; i++, sin++) {
			if (ip_getifaddr_type(AF_INET, ipif, type[i],
			    &sin->sin_addr) < 0) {
				ip2dbg(("ip_getlifaddr_impl failed type %d\n",
				    type[i]));
				ipif_refrele(ipif);
				return (1);
			}
		}
	} else {
		if ((ipif = ipif_getby_indexes((uint_t)phy_ifdata,
		    (uint_t)ipifid, B_TRUE)) == NULL)
			return (1);

		sin6 = (struct sockaddr_in6 *)storage;
		for (i = 0; i < nelem; i++, sin6++) {
			if (ip_getifaddr_type(AF_INET6, ipif, type[i],
			    &sin6->sin6_addr) < 0) {
				ip2dbg(("ip_getlifaddr_impl failed type %d\n",
				    type[i]));
				ipif_refrele(ipif);
				return (1);
			}
		}
	}
	ipif_refrele(ipif);
	return (0);
}

/*
 * ip_getlifaddr private function
 */
static int
ip_getifaddr_type(sa_family_t family, ipif_t *ill_ipif,
    lif_if_t type, void *storage)
{
	void *src_addr;
	int mem_size;

	ASSERT(ill_ipif != NULL);
	ASSERT(storage != NULL);

	if (family == AF_INET) {
		mem_size = sizeof (struct in_addr);

		switch (type) {
		case NA_ADDRESS:
			src_addr = &(ill_ipif->ipif_lcl_addr);
			break;
		case NA_PEER:
			src_addr = &(ill_ipif->ipif_pp_dst_addr);
			break;
		case NA_BROADCAST:
			src_addr = &(ill_ipif->ipif_brd_addr);
			break;
		case NA_NETMASK:
			src_addr = &(ill_ipif->ipif_net_mask);
			break;
		default:
			return (-1);
			/*NOTREACHED*/
		}
	} else {
		mem_size = sizeof (struct in6_addr);

		switch (type) {
		case NA_ADDRESS:
			src_addr = &(ill_ipif->ipif_v6lcl_addr);
			break;
		case NA_PEER:
			src_addr = &(ill_ipif->ipif_v6pp_dst_addr);
			break;
		case NA_BROADCAST:
			src_addr = &(ill_ipif->ipif_v6brd_addr);
			break;
		case NA_NETMASK:
			src_addr = &(ill_ipif->ipif_v6net_mask);
			break;
		default:
			return (-1);
			/*NOTREACHED*/
		}
	}

	(void) memcpy(storage, src_addr, mem_size);
	return (1);
}


/*
 * Deliver packet up into the kernel, immitating its reception by a
 * network interface.
 */
static void
ip_ni_queue_in_func(void *inject)
{

	ip_ni_queue_func_impl(inject, B_FALSE);
}


/*
 * Deliver out of the kernel, as if it were being sent via a
 * raw socket so that IPFilter will see it again.
 */
static void
ip_ni_queue_out_func(void *inject)
{

	ip_ni_queue_func_impl(inject, B_TRUE);
}


/*
 * Shared implementation for inject via ip_output and ip_input
 */
static void
ip_ni_queue_func_impl(injection_t *inject,  boolean_t out)
{
	net_inject_t *packet;
	conn_t *conn;
	ill_t *ill;

	ASSERT(inject != NULL);
	packet = &inject->inj_data;
	ASSERT(packet->ni_packet != NULL);

	if ((ill = ill_lookup_on_ifindex((uint_t)packet->ni_physical,
	    B_FALSE, NULL, NULL, NULL, NULL)) == NULL) {
		kmem_free(inject, sizeof (*inject));
		return;
	}

	if (out == 0) {
		if (inject->inj_isv6) {
			ip_rput_v6(ill->ill_rq, packet->ni_packet);
		} else {
			ip_input(ill, NULL, packet->ni_packet, 0);
		}
		kmem_free(inject, sizeof (*inject));
		ill_refrele(ill);
		return;
	}

	/*
	 * Even though ipcl_conn_create requests that it be passed
	 * a different value for "TCP", in this case there may not
	 * be a TCP connection backing the packet and more than
	 * likely, non-TCP packets will go here too.
	 */
	conn = ipcl_conn_create(IPCL_IPCCONN, KM_NOSLEEP);
	if (conn != NULL) {
		if (inject->inj_isv6) {
			conn->conn_flags |= IPCL_ISV6;
			conn->conn_af_isv6 = B_TRUE;
			conn->conn_src_preferences = IPV6_PREFER_SRC_DEFAULT;
			conn->conn_multicast_loop = IP_DEFAULT_MULTICAST_LOOP;
			ip_output_v6(conn, packet->ni_packet, ill->ill_wq,
				IP_WPUT);
		} else {
			conn->conn_af_isv6 = B_FALSE;
			conn->conn_pkt_isv6 = B_FALSE;
			conn->conn_multicast_loop = IP_DEFAULT_MULTICAST_LOOP;
			ip_output(conn, packet->ni_packet, ill->ill_wq,
				IP_WPUT);
		}

		CONN_DEC_REF(conn);
	}

	kmem_free(inject, sizeof (*inject));
	ill_refrele(ill);
}

/*
 * taskq function for nic events.
 */
void
ip_ne_queue_func(void *arg)
{

	hook_event_int_t *hr;
	hook_nic_event_t *info = (hook_nic_event_t *)arg;

	hr = (info->hne_family == ipv6) ? ipv6nicevents : ipv4nicevents;
	(void) hook_run(hr, (hook_data_t)info);

	if (info->hne_data != NULL)
		kmem_free(info->hne_data, info->hne_datalen);
	kmem_free(arg, sizeof (hook_nic_event_t));
}
