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
#include <sys/sdt.h>
#include <sys/cmn_err.h>

#include <netinet/in.h>
#include <inet/ipsec_impl.h>
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
static int 		ip_getifname(net_handle_t, phy_if_t, char *,
			    const size_t);
static int 		ip_getmtu(net_handle_t, phy_if_t, lif_if_t);
static int 		ip_getpmtuenabled(net_handle_t);
static int 		ip_getlifaddr(net_handle_t, phy_if_t, lif_if_t,
			    size_t, net_ifaddr_t [], void *);
static int		ip_getlifzone(net_handle_t, phy_if_t, lif_if_t,
			    zoneid_t *);
static int		ip_getlifflags(net_handle_t, phy_if_t, lif_if_t,
			    uint64_t *);
static phy_if_t		ip_phygetnext(net_handle_t, phy_if_t);
static phy_if_t 	ip_phylookup(net_handle_t, const char *);
static lif_if_t 	ip_lifgetnext(net_handle_t, phy_if_t, lif_if_t);
static int 		ip_inject(net_handle_t, inject_t, net_inject_t *);
static phy_if_t 	ip_routeto(net_handle_t, struct sockaddr *,
			    struct sockaddr *);
static int 		ip_ispartialchecksum(net_handle_t, mblk_t *);
static int 		ip_isvalidchecksum(net_handle_t, mblk_t *);

static int 		ipv6_getifname(net_handle_t, phy_if_t, char *,
			    const size_t);
static int 		ipv6_getmtu(net_handle_t, phy_if_t, lif_if_t);
static int 		ipv6_getlifaddr(net_handle_t, phy_if_t, lif_if_t,
			    size_t, net_ifaddr_t [], void *);
static int		ipv6_getlifzone(net_handle_t, phy_if_t, lif_if_t,
			    zoneid_t *);
static int		ipv6_getlifflags(net_handle_t, phy_if_t, lif_if_t,
			    uint64_t *);
static phy_if_t 	ipv6_phygetnext(net_handle_t, phy_if_t);
static phy_if_t 	ipv6_phylookup(net_handle_t, const char *);
static lif_if_t 	ipv6_lifgetnext(net_handle_t, phy_if_t, lif_if_t);
static int 		ipv6_inject(net_handle_t, inject_t, net_inject_t *);
static phy_if_t 	ipv6_routeto(net_handle_t, struct sockaddr *,
			    struct sockaddr *);
static int 		ipv6_isvalidchecksum(net_handle_t, mblk_t *);

static int 		net_no_getmtu(net_handle_t, phy_if_t, lif_if_t);
static int 		net_no_getpmtuenabled(net_handle_t);
static lif_if_t 	net_no_lifgetnext(net_handle_t, phy_if_t, lif_if_t);
static int 		net_no_inject(net_handle_t, inject_t, net_inject_t *);
static phy_if_t 	net_no_routeto(net_handle_t, struct sockaddr *,
			    struct sockaddr *);
static int 		net_no_ispartialchecksum(net_handle_t, mblk_t *);
static int 		net_no_getlifaddr(net_handle_t, phy_if_t, lif_if_t,
			    size_t, net_ifaddr_t [], void *);
static int		net_no_getlifzone(net_handle_t, phy_if_t, lif_if_t,
			    zoneid_t *);
static int		net_no_getlifflags(net_handle_t, phy_if_t, lif_if_t,
			    uint64_t *);

/* Netinfo private functions */
static	int		ip_getifname_impl(phy_if_t, char *,
			    const size_t, boolean_t, ip_stack_t *);
static	int		ip_getmtu_impl(phy_if_t, lif_if_t, boolean_t,
			    ip_stack_t *);
static	phy_if_t	ip_phylookup_impl(const char *, boolean_t,
			    ip_stack_t *);
static	lif_if_t	ip_lifgetnext_impl(phy_if_t, lif_if_t, boolean_t,
			    ip_stack_t *);
static	int		ip_inject_impl(inject_t, net_inject_t *, boolean_t,
			    ip_stack_t *);
static	int		ip_getifaddr_type(sa_family_t, ipif_t *, lif_if_t,
			    void *);
static	phy_if_t	ip_routeto_impl(struct sockaddr *, struct sockaddr *,
			    ip_stack_t *);
static	int		ip_getlifaddr_impl(sa_family_t, phy_if_t, lif_if_t,
			    size_t, net_ifaddr_t [], struct sockaddr *,
			    ip_stack_t *);
static	void		ip_ni_queue_in_func(void *);
static	void		ip_ni_queue_out_func(void *);
static	void		ip_ni_queue_func_impl(injection_t *,  boolean_t);

static net_protocol_t ipv4info = {
	NETINFO_VERSION,
	NHF_INET,
	ip_getifname,
	ip_getmtu,
	ip_getpmtuenabled,
	ip_getlifaddr,
	ip_getlifzone,
	ip_getlifflags,
	ip_phygetnext,
	ip_phylookup,
	ip_lifgetnext,
	ip_inject,
	ip_routeto,
	ip_ispartialchecksum,
	ip_isvalidchecksum
};


static net_protocol_t ipv6info = {
	NETINFO_VERSION,
	NHF_INET6,
	ipv6_getifname,
	ipv6_getmtu,
	ip_getpmtuenabled,
	ipv6_getlifaddr,
	ipv6_getlifzone,
	ipv6_getlifflags,
	ipv6_phygetnext,
	ipv6_phylookup,
	ipv6_lifgetnext,
	ipv6_inject,
	ipv6_routeto,
	ip_ispartialchecksum,
	ipv6_isvalidchecksum
};

static net_protocol_t arp_netinfo = {
	NETINFO_VERSION,
	NHF_ARP,
	ip_getifname,
	net_no_getmtu,
	net_no_getpmtuenabled,
	net_no_getlifaddr,
	net_no_getlifzone,
	net_no_getlifflags,
	ip_phygetnext,
	ip_phylookup,
	net_no_lifgetnext,
	net_no_inject,
	net_no_routeto,
	net_no_ispartialchecksum,
	ip_isvalidchecksum
};

/*
 * The taskq eventq_queue_in is used to process the upside inject messages.
 * The taskq eventq_queue_out is used to process the downside inject messages.
 * The taskq eventq_queue_nic is used to process the nic event messages.
 */
static ddi_taskq_t 	*eventq_queue_in = NULL;
static ddi_taskq_t 	*eventq_queue_out = NULL;
ddi_taskq_t 	*eventq_queue_nic = NULL;

/*
 * Initialize queues for inject.
 */
void
ip_net_g_init()
{
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
 * Destroy inject queues
 */
void
ip_net_g_destroy()
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
}

/*
 * Register IPv4 and IPv6 netinfo functions and initialize queues for inject.
 */
void
ip_net_init(ip_stack_t *ipst, netstack_t *ns)
{
	netid_t id;

	id = net_getnetidbynetstackid(ns->netstack_stackid);
	ASSERT(id != -1);

	ipst->ips_ipv4_net_data = net_protocol_register(id, &ipv4info);
	ASSERT(ipst->ips_ipv4_net_data != NULL);

	ipst->ips_ipv6_net_data = net_protocol_register(id, &ipv6info);
	ASSERT(ipst->ips_ipv6_net_data != NULL);

	ipst->ips_arp_net_data = net_protocol_register(id, &arp_netinfo);
	ASSERT(ipst->ips_ipv6_net_data != NULL);
}


/*
 * Unregister IPv4 and IPv6 functions.
 */
void
ip_net_destroy(ip_stack_t *ipst)
{
	if (ipst->ips_ipv4_net_data != NULL) {
		if (net_protocol_unregister(ipst->ips_ipv4_net_data) == 0)
			ipst->ips_ipv4_net_data = NULL;
	}

	if (ipst->ips_ipv6_net_data != NULL) {
		if (net_protocol_unregister(ipst->ips_ipv6_net_data) == 0)
			ipst->ips_ipv6_net_data = NULL;
	}

	if (ipst->ips_arp_net_data != NULL) {
		if (net_protocol_unregister(ipst->ips_arp_net_data) == 0)
			ipst->ips_arp_net_data = NULL;
	}
}

/*
 * Initialize IPv4 hooks family the event
 */
void
ipv4_hook_init(ip_stack_t *ipst)
{
	HOOK_FAMILY_INIT(&ipst->ips_ipv4root, Hn_IPV4);
	if (net_family_register(ipst->ips_ipv4_net_data, &ipst->ips_ipv4root)
	    != 0) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_family_register failed for ipv4");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip4_physical_in_event, NH_PHYSICAL_IN);
	ipst->ips_ipv4firewall_physical_in = net_event_register(
	    ipst->ips_ipv4_net_data, &ipst->ips_ip4_physical_in_event);
	if (ipst->ips_ipv4firewall_physical_in == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_event_register failed for ipv4/physical_in");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip4_physical_out_event, NH_PHYSICAL_OUT);
	ipst->ips_ipv4firewall_physical_out = net_event_register(
	    ipst->ips_ipv4_net_data, &ipst->ips_ip4_physical_out_event);
	if (ipst->ips_ipv4firewall_physical_out == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_event_register failed for ipv4/physical_out");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip4_forwarding_event, NH_FORWARDING);
	ipst->ips_ipv4firewall_forwarding = net_event_register(
	    ipst->ips_ipv4_net_data, &ipst->ips_ip4_forwarding_event);
	if (ipst->ips_ipv4firewall_forwarding == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_event_register failed for ipv4/forwarding");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip4_loopback_in_event, NH_LOOPBACK_IN);
	ipst->ips_ipv4firewall_loopback_in = net_event_register(
	    ipst->ips_ipv4_net_data, &ipst->ips_ip4_loopback_in_event);
	if (ipst->ips_ipv4firewall_loopback_in == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_event_register failed for ipv4/loopback_in");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip4_loopback_out_event, NH_LOOPBACK_OUT);
	ipst->ips_ipv4firewall_loopback_out = net_event_register(
	    ipst->ips_ipv4_net_data, &ipst->ips_ip4_loopback_out_event);
	if (ipst->ips_ipv4firewall_loopback_out == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_event_register failed for ipv4/loopback_out");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip4_nic_events, NH_NIC_EVENTS);
	ipst->ips_ip4_nic_events.he_flags = HOOK_RDONLY;
	ipst->ips_ipv4nicevents = net_event_register(
	    ipst->ips_ipv4_net_data, &ipst->ips_ip4_nic_events);
	if (ipst->ips_ipv4nicevents == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_event_register failed for ipv4/nic_events");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip4_observe, NH_OBSERVE);
	ipst->ips_ip4_observe.he_flags = HOOK_RDONLY;
	ipst->ips_ipv4observing = net_event_register(
	    ipst->ips_ipv4_net_data, &ipst->ips_ip4_observe);
	if (ipst->ips_ipv4observing == NULL) {
		cmn_err(CE_NOTE, "ipv4_hook_init: "
		    "net_event_register failed for ipv4/observe");
	}

}

void
ipv4_hook_shutdown(ip_stack_t *ipst)
{
	if (ipst->ips_ipv4firewall_forwarding != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_forwarding_event);
	}

	if (ipst->ips_ipv4firewall_physical_in != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_physical_in_event);
	}

	if (ipst->ips_ipv4firewall_physical_out != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_physical_out_event);
	}

	if (ipst->ips_ipv4firewall_loopback_in != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_loopback_in_event);
	}

	if (ipst->ips_ipv4firewall_loopback_out != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_loopback_out_event);
	}

	if (ipst->ips_ipv4nicevents != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_nic_events);
	}

	if (ipst->ips_ipv4observing != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_observe);
	}

	(void) net_family_shutdown(ipst->ips_ipv4_net_data,
	    &ipst->ips_ipv4root);
}

void
ipv4_hook_destroy(ip_stack_t *ipst)
{
	if (ipst->ips_ipv4firewall_forwarding != NULL) {
		if (net_event_unregister(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_forwarding_event) == 0)
			ipst->ips_ipv4firewall_forwarding = NULL;
	}

	if (ipst->ips_ipv4firewall_physical_in != NULL) {
		if (net_event_unregister(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_physical_in_event) == 0)
			ipst->ips_ipv4firewall_physical_in = NULL;
	}

	if (ipst->ips_ipv4firewall_physical_out != NULL) {
		if (net_event_unregister(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_physical_out_event) == 0)
			ipst->ips_ipv4firewall_physical_out = NULL;
	}

	if (ipst->ips_ipv4firewall_loopback_in != NULL) {
		if (net_event_unregister(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_loopback_in_event) == 0)
			ipst->ips_ipv4firewall_loopback_in = NULL;
	}

	if (ipst->ips_ipv4firewall_loopback_out != NULL) {
		if (net_event_unregister(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_loopback_out_event) == 0)
			ipst->ips_ipv4firewall_loopback_out = NULL;
	}

	if (ipst->ips_ipv4nicevents != NULL) {
		if (net_event_unregister(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_nic_events) == 0)
			ipst->ips_ipv4nicevents = NULL;
	}

	if (ipst->ips_ipv4observing != NULL) {
		if (net_event_unregister(ipst->ips_ipv4_net_data,
		    &ipst->ips_ip4_observe) == 0)
			ipst->ips_ipv4observing = NULL;
	}

	(void) net_family_unregister(ipst->ips_ipv4_net_data,
	    &ipst->ips_ipv4root);
}

/*
 * Initialize IPv6 hooks family and event
 */
void
ipv6_hook_init(ip_stack_t *ipst)
{

	HOOK_FAMILY_INIT(&ipst->ips_ipv6root, Hn_IPV6);
	if (net_family_register(ipst->ips_ipv6_net_data, &ipst->ips_ipv6root)
	    != 0) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_family_register failed for ipv6");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip6_physical_in_event, NH_PHYSICAL_IN);
	ipst->ips_ipv6firewall_physical_in = net_event_register(
	    ipst->ips_ipv6_net_data, &ipst->ips_ip6_physical_in_event);
	if (ipst->ips_ipv6firewall_physical_in == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_event_register failed for ipv6/physical_in");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip6_physical_out_event, NH_PHYSICAL_OUT);
	ipst->ips_ipv6firewall_physical_out = net_event_register(
	    ipst->ips_ipv6_net_data, &ipst->ips_ip6_physical_out_event);
	if (ipst->ips_ipv6firewall_physical_out == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_event_register failed for ipv6/physical_out");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip6_forwarding_event, NH_FORWARDING);
	ipst->ips_ipv6firewall_forwarding = net_event_register(
	    ipst->ips_ipv6_net_data, &ipst->ips_ip6_forwarding_event);
	if (ipst->ips_ipv6firewall_forwarding == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_event_register failed for ipv6/forwarding");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip6_loopback_in_event, NH_LOOPBACK_IN);
	ipst->ips_ipv6firewall_loopback_in = net_event_register(
	    ipst->ips_ipv6_net_data, &ipst->ips_ip6_loopback_in_event);
	if (ipst->ips_ipv6firewall_loopback_in == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_event_register failed for ipv6/loopback_in");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip6_loopback_out_event, NH_LOOPBACK_OUT);
	ipst->ips_ipv6firewall_loopback_out = net_event_register(
	    ipst->ips_ipv6_net_data, &ipst->ips_ip6_loopback_out_event);
	if (ipst->ips_ipv6firewall_loopback_out == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_event_register failed for ipv6/loopback_out");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip6_nic_events, NH_NIC_EVENTS);
	ipst->ips_ip6_nic_events.he_flags = HOOK_RDONLY;
	ipst->ips_ipv6nicevents = net_event_register(
	    ipst->ips_ipv6_net_data, &ipst->ips_ip6_nic_events);
	if (ipst->ips_ipv6nicevents == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_event_register failed for ipv6/nic_events");
	}

	HOOK_EVENT_INIT(&ipst->ips_ip6_observe, NH_OBSERVE);
	ipst->ips_ip6_observe.he_flags = HOOK_RDONLY;
	ipst->ips_ipv6observing = net_event_register(
	    ipst->ips_ipv6_net_data, &ipst->ips_ip6_observe);
	if (ipst->ips_ipv6observing == NULL) {
		cmn_err(CE_NOTE, "ipv6_hook_init: "
		    "net_event_register failed for ipv6/observe");
	}
}

void
ipv6_hook_shutdown(ip_stack_t *ipst)
{
	if (ipst->ips_ipv6firewall_forwarding != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_forwarding_event);
	}

	if (ipst->ips_ipv6firewall_physical_in != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_physical_in_event);
	}

	if (ipst->ips_ipv6firewall_physical_out != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_physical_out_event);
	}

	if (ipst->ips_ipv6firewall_loopback_in != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_loopback_in_event);
	}

	if (ipst->ips_ipv6firewall_loopback_out != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_loopback_out_event);
	}

	if (ipst->ips_ipv6nicevents != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_nic_events);
	}

	if (ipst->ips_ipv6observing != NULL) {
		(void) net_event_shutdown(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_observe);
	}

	(void) net_family_shutdown(ipst->ips_ipv6_net_data,
	    &ipst->ips_ipv6root);
}

void
ipv6_hook_destroy(ip_stack_t *ipst)
{
	if (ipst->ips_ipv6firewall_forwarding != NULL) {
		if (net_event_unregister(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_forwarding_event) == 0)
			ipst->ips_ipv6firewall_forwarding = NULL;
	}

	if (ipst->ips_ipv6firewall_physical_in != NULL) {
		if (net_event_unregister(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_physical_in_event) == 0)
			ipst->ips_ipv6firewall_physical_in = NULL;
	}

	if (ipst->ips_ipv6firewall_physical_out != NULL) {
		if (net_event_unregister(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_physical_out_event) == 0)
			ipst->ips_ipv6firewall_physical_out = NULL;
	}

	if (ipst->ips_ipv6firewall_loopback_in != NULL) {
		if (net_event_unregister(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_loopback_in_event) == 0)
			ipst->ips_ipv6firewall_loopback_in = NULL;
	}

	if (ipst->ips_ipv6firewall_loopback_out != NULL) {
		if (net_event_unregister(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_loopback_out_event) == 0)
			ipst->ips_ipv6firewall_loopback_out = NULL;
	}

	if (ipst->ips_ipv6nicevents != NULL) {
		if (net_event_unregister(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_nic_events) == 0)
			ipst->ips_ipv6nicevents = NULL;
	}

	if (ipst->ips_ipv6observing != NULL) {
		if (net_event_unregister(ipst->ips_ipv6_net_data,
		    &ipst->ips_ip6_observe) == 0)
			ipst->ips_ipv6observing = NULL;
	}

	(void) net_family_unregister(ipst->ips_ipv6_net_data,
	    &ipst->ips_ipv6root);
}

/*
 * Determine the name of an IPv4 interface
 */
static int
ip_getifname(net_handle_t neti, phy_if_t phy_ifdata, char *buffer,
    const size_t buflen)
{
	return (ip_getifname_impl(phy_ifdata, buffer, buflen, B_FALSE,
	    neti->netd_stack->nts_netstack->netstack_ip));
}

/*
 * Determine the name of an IPv6 interface
 */
static int
ipv6_getifname(net_handle_t neti, phy_if_t phy_ifdata, char *buffer,
    const size_t buflen)
{
	return (ip_getifname_impl(phy_ifdata, buffer, buflen, B_TRUE,
	    neti->netd_stack->nts_netstack->netstack_ip));
}

/*
 * Shared implementation to determine the name of a given network interface
 */
/* ARGSUSED */
static int
ip_getifname_impl(phy_if_t phy_ifdata,
    char *buffer, const size_t buflen, boolean_t isv6, ip_stack_t *ipst)
{
	ill_t *ill;

	ASSERT(buffer != NULL);

	ill = ill_lookup_on_ifindex((uint_t)phy_ifdata, isv6, ipst);
	if (ill == NULL)
		return (1);

	(void) strlcpy(buffer, ill->ill_name, buflen);
	ill_refrele(ill);
	return (0);
}

/*
 * Determine the MTU of an IPv4 network interface
 */
static int
ip_getmtu(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ip_getmtu_impl(phy_ifdata, ifdata, B_FALSE, ns->netstack_ip));
}

/*
 * Determine the MTU of an IPv6 network interface
 */
static int
ipv6_getmtu(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ip_getmtu_impl(phy_ifdata, ifdata, B_TRUE, ns->netstack_ip));
}

/*
 * Shared implementation to determine the MTU of a network interface
 */
/* ARGSUSED */
static int
ip_getmtu_impl(phy_if_t phy_ifdata, lif_if_t ifdata, boolean_t isv6,
    ip_stack_t *ipst)
{
	lif_if_t ipifid;
	ipif_t *ipif;
	int mtu;

	ipifid = UNMAP_IPIF_ID(ifdata);

	ipif = ipif_getby_indexes((uint_t)phy_ifdata, (uint_t)ipifid,
	    isv6, ipst);
	if (ipif == NULL)
		return (0);

	mtu = ipif->ipif_ill->ill_mtu;
	ipif_refrele(ipif);

	if (mtu == 0) {
		ill_t *ill;

		if ((ill = ill_lookup_on_ifindex((uint_t)phy_ifdata, isv6,
		    ipst)) == NULL) {
			return (0);
		}
		mtu = ill->ill_mtu;
		ill_refrele(ill);
	}

	return (mtu);
}

/*
 * Determine if path MTU discovery is enabled for IP
 */
static int
ip_getpmtuenabled(net_handle_t neti)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ns->netstack_ip->ips_ip_path_mtu_discovery);
}

/*
 * Get next interface from the current list of IPv4 physical network interfaces
 */
static phy_if_t
ip_phygetnext(net_handle_t neti, phy_if_t phy_ifdata)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ill_get_next_ifindex(phy_ifdata, B_FALSE, ns->netstack_ip));
}

/*
 * Get next interface from the current list of IPv6 physical network interfaces
 */
static phy_if_t
ipv6_phygetnext(net_handle_t neti, phy_if_t phy_ifdata)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ill_get_next_ifindex(phy_ifdata, B_TRUE, ns->netstack_ip));
}

/*
 * Determine if a network interface name exists for IPv4
 */
static phy_if_t
ip_phylookup(net_handle_t neti, const char *name)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ip_phylookup_impl(name, B_FALSE, ns->netstack_ip));
}

/*
 * Determine if a network interface name exists for IPv6
 */
static phy_if_t
ipv6_phylookup(net_handle_t neti, const char *name)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ip_phylookup_impl(name, B_TRUE, ns->netstack_ip));
}

/*
 * Implement looking up an ill_t based on the name supplied and matching
 * it up with either IPv4 or IPv6.  ill_get_ifindex_by_name() is not used
 * because it does not match on the address family in addition to the name.
 */
static phy_if_t
ip_phylookup_impl(const char *name, boolean_t isv6, ip_stack_t *ipst)
{
	phy_if_t phy;
	ill_t *ill;

	ill = ill_lookup_on_name((char *)name, B_FALSE, isv6, NULL, ipst);
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
ip_lifgetnext(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ip_lifgetnext_impl(phy_ifdata, ifdata, B_FALSE,
	    ns->netstack_ip));
}

/*
 * Get next interface from the current list of IPv6 logical network interfaces
 */
static lif_if_t
ipv6_lifgetnext(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ip_lifgetnext_impl(phy_ifdata, ifdata, B_TRUE,
	    ns->netstack_ip));
}

/*
 * Shared implementation to get next interface from the current list of
 * logical network interfaces
 */
static lif_if_t
ip_lifgetnext_impl(phy_if_t phy_ifdata, lif_if_t ifdata, boolean_t isv6,
    ip_stack_t *ipst)
{
	lif_if_t newidx, oldidx;
	boolean_t nextok;
	ipif_t *ipif;
	ill_t *ill;

	ill = ill_lookup_on_ifindex(phy_ifdata, isv6, ipst);
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
	 * See the field access rules in ip.h.
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
ip_inject(net_handle_t neti, inject_t style, net_inject_t *packet)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ip_inject_impl(style, packet, B_FALSE, ns->netstack_ip));
}


/*
 * Inject an IPv6 packet to or from an interface
 */
static int
ipv6_inject(net_handle_t neti, inject_t style, net_inject_t *packet)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	return (ip_inject_impl(style, packet, B_TRUE, ns->netstack_ip));
}

/*
 * Shared implementation to inject a packet to or from an interface
 * Return value:
 *   0: successful
 *  -1: memory allocation failed
 *   1: other errors
 */
static int
ip_inject_impl(inject_t style, net_inject_t *packet, boolean_t isv6,
    ip_stack_t *ipst)
{
	ddi_taskq_t *tq = NULL;
	void (* func)(void *);
	injection_t *inject;
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

	case NI_DIRECT_OUT: {
		struct sockaddr *sock;

		mp = packet->ni_packet;

		sock = (struct sockaddr *)&packet->ni_addr;
		/*
		 * ipfil_sendpkt was provided by surya to ease the
		 * problems associated with sending out a packet.
		 */
		switch (ipfil_sendpkt(sock, mp, packet->ni_physical,
		    netstackid_to_zoneid(
		    ipst->ips_netstack->netstack_stackid))) {
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
	default:
		freemsg(packet->ni_packet);
		return (1);
	}

	ASSERT(tq != NULL);

	inject->inj_ptr = ipst;
	if (ddi_taskq_dispatch(tq, func, (void *)inject,
	    DDI_SLEEP) == DDI_FAILURE) {
		ip2dbg(("ip_inject:  ddi_taskq_dispatch failed\n"));
		freemsg(packet->ni_packet);
		return (1);
	}
	return (0);
}

/*
 * Find the interface used for traffic to a given IPv4 address
 */
static phy_if_t
ip_routeto(net_handle_t neti, struct sockaddr *address, struct sockaddr *next)
{
	netstack_t *ns;

	ASSERT(address != NULL);

	if (address->sa_family != AF_INET)
		return (0);

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);

	return (ip_routeto_impl(address, next, ns->netstack_ip));
}

/*
 * Find the interface used for traffic to a given IPv6 address
 */
static phy_if_t
ipv6_routeto(net_handle_t neti, struct sockaddr *address, struct sockaddr *next)
{
	netstack_t *ns;

	ASSERT(address != NULL);

	if (address->sa_family != AF_INET6)
		return (0);

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);

	return (ip_routeto_impl(address, next, ns->netstack_ip));
}


/*
 * Find the interface used for traffic to an address.
 * For lint reasons, next/next6/sin/sin6 are all declared and assigned
 * a value at the top.  The alternative would end up with two bunches
 * of assignments, with each bunch setting half to NULL.
 */
static phy_if_t
ip_routeto_impl(struct sockaddr *address, struct sockaddr *nexthop,
    ip_stack_t *ipst)
{
	struct sockaddr_in6 *next6 = (struct sockaddr_in6 *)nexthop;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
	struct sockaddr_in *next = (struct sockaddr_in *)nexthop;
	struct sockaddr_in *sin = (struct sockaddr_in *)address;
	ire_t *ire;
	ire_t *nexthop_ire;
	phy_if_t phy_if;
	zoneid_t zoneid;

	zoneid = netstackid_to_zoneid(ipst->ips_netstack->netstack_stackid);

	if (address->sa_family == AF_INET6) {
		ire = ire_route_recursive_v6(&sin6->sin6_addr, 0, NULL,
		    zoneid, NULL, MATCH_IRE_DSTONLY, IRR_ALLOCATE, 0, ipst,
		    NULL, NULL, NULL);
	} else {
		ire = ire_route_recursive_v4(sin->sin_addr.s_addr, 0, NULL,
		    zoneid, NULL, MATCH_IRE_DSTONLY, IRR_ALLOCATE, 0, ipst,
		    NULL, NULL, NULL);
	}
	ASSERT(ire != NULL);
	/*
	 * For some destinations, we have routes that are dead ends, so
	 * return to indicate that no physical interface can be used to
	 * reach the destination.
	 */
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		ire_refrele(ire);
		return (NULL);
	}

	nexthop_ire = ire_nexthop(ire);
	if (nexthop_ire == NULL) {
		ire_refrele(ire);
		return (0);
	}
	if (nexthop_ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		ire_refrele(nexthop_ire);
		ire_refrele(ire);
		return (0);
	}

	ASSERT(nexthop_ire->ire_ill != NULL);

	if (nexthop != NULL) {
		if (address->sa_family == AF_INET6) {
			next6->sin6_addr = nexthop_ire->ire_addr_v6;
		} else {
			next->sin_addr.s_addr = nexthop_ire->ire_addr;
		}
	}

	phy_if = (phy_if_t)nexthop_ire->ire_ill->ill_phyint->phyint_ifindex;
	ire_refrele(ire);
	ire_refrele(nexthop_ire);

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
/*ARGSUSED*/
static int
ip_ispartialchecksum(net_handle_t neti, mblk_t *mp)
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
/*ARGSUSED*/
static int
ip_isvalidchecksum(net_handle_t neti, mblk_t *mp)
{
	unsigned char *wptr;
	ipha_t *ipha = (ipha_t *)mp->b_rptr;
	int hlen;
	int ret;

	ASSERT(mp != NULL);

	if (dohwcksum &&
	    ((DB_CKSUM16(mp) != 0xFFFF &&
	    (DB_CKSUMFLAGS(mp) & HCK_FULLCKSUM)) ||
	    (DB_CKSUMFLAGS(mp) & HCK_FULLCKSUM_OK)) &&
	    (DB_CKSUMFLAGS(mp) & HCK_IPV4_HDRCKSUM_OK))
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
ipv6_isvalidchecksum(net_handle_t neti, mblk_t *mp)
{
	return (-1);
}

/*
 * Determine the network addresses for an IPv4 interface
 */
static int
ip_getlifaddr(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata,
    size_t nelem, net_ifaddr_t type[], void *storage)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ip_getlifaddr_impl(AF_INET, phy_ifdata, ifdata,
	    nelem, type, storage, ns->netstack_ip));
}

/*
 * Determine the network addresses for an IPv6 interface
 */
static int
ipv6_getlifaddr(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata,
    size_t nelem, net_ifaddr_t type[], void *storage)
{
	netstack_t *ns;

	ns = neti->netd_stack->nts_netstack;
	ASSERT(ns != NULL);
	return (ip_getlifaddr_impl(AF_INET6, phy_ifdata, ifdata,
	    nelem, type, storage, ns->netstack_ip));
}

/*
 * Shared implementation to determine the network addresses for an interface
 */
/* ARGSUSED */
static int
ip_getlifaddr_impl(sa_family_t family, phy_if_t phy_ifdata,
    lif_if_t ifdata, size_t nelem, net_ifaddr_t type[],
    struct sockaddr *storage, ip_stack_t *ipst)
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
		    (uint_t)ipifid, B_FALSE, ipst)) == NULL)
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
			sin->sin_family = AF_INET;
		}
	} else {
		if ((ipif = ipif_getby_indexes((uint_t)phy_ifdata,
		    (uint_t)ipifid, B_TRUE, ipst)) == NULL)
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
			sin6->sin6_family = AF_INET6;
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
 * Shared implementation to determine the zoneid associated with an IPv4/IPv6
 * address
 */
static int
ip_getlifzone_impl(sa_family_t family, phy_if_t phy_ifdata, lif_if_t ifdata,
    ip_stack_t *ipst, zoneid_t *zoneid)
{
	ipif_t  *ipif;

	ipif = ipif_getby_indexes((uint_t)phy_ifdata,
	    UNMAP_IPIF_ID((uint_t)ifdata), (family == AF_INET6), ipst);
	if (ipif == NULL)
		return (-1);
	*zoneid = IP_REAL_ZONEID(ipif->ipif_zoneid, ipst);
	ipif_refrele(ipif);
	return (0);
}

/*
 * Determine the zoneid associated with an IPv4 address
 */
static int
ip_getlifzone(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata,
    zoneid_t *zoneid)
{
	return (ip_getlifzone_impl(AF_INET, phy_ifdata, ifdata,
	    neti->netd_stack->nts_netstack->netstack_ip, zoneid));
}

/*
 * Determine the zoneid associated with an IPv6 address
 */
static int
ipv6_getlifzone(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata,
    zoneid_t *zoneid)
{
	return (ip_getlifzone_impl(AF_INET6, phy_ifdata, ifdata,
	    neti->netd_stack->nts_netstack->netstack_ip, zoneid));
}

/*
 * The behaviour here mirrors that for the SIOCFLIFFLAGS ioctl where the
 * union of all of the relevant flags is returned.
 */
static int
ip_getlifflags_impl(sa_family_t family, phy_if_t phy_ifdata, lif_if_t ifdata,
    ip_stack_t *ipst, uint64_t *flags)
{
	phyint_t *phyi;
	ipif_t *ipif;
	ill_t *ill;

	ill = ill_lookup_on_ifindex(phy_ifdata, (family == AF_INET6), ipst);
	if (ill == NULL)
		return (-1);
	phyi = ill->ill_phyint;

	ipif = ipif_getby_indexes((uint_t)phy_ifdata,
	    UNMAP_IPIF_ID((uint_t)ifdata), (family == AF_INET6), ipst);
	if (ipif == NULL) {
		ill_refrele(ill);
		return (-1);
	}
	*flags = ipif->ipif_flags | ill->ill_flags | phyi->phyint_flags;
	ipif_refrele(ipif);
	ill_refrele(ill);
	return (0);
}

static int
ip_getlifflags(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata,
    uint64_t *flags)
{
	return (ip_getlifflags_impl(AF_INET, phy_ifdata, ifdata,
	    neti->netd_stack->nts_netstack->netstack_ip, flags));
}

static int
ipv6_getlifflags(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata,
    uint64_t *flags)
{
	return (ip_getlifflags_impl(AF_INET6, phy_ifdata, ifdata,
	    neti->netd_stack->nts_netstack->netstack_ip, flags));
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
	ill_t *ill;
	ip_stack_t *ipst = (ip_stack_t *)inject->inj_ptr;
	ip_xmit_attr_t	ixas;

	ASSERT(inject != NULL);
	packet = &inject->inj_data;
	ASSERT(packet->ni_packet != NULL);

	if (out == 0) {
		ill = ill_lookup_on_ifindex((uint_t)packet->ni_physical,
		    inject->inj_isv6, ipst);

		if (ill == NULL) {
			kmem_free(inject, sizeof (*inject));
			return;
		}

		if (inject->inj_isv6) {
			ip_input_v6(ill, NULL, packet->ni_packet, NULL);
		} else {
			ip_input(ill, NULL, packet->ni_packet, NULL);
		}
		ill_refrele(ill);
	} else {
		bzero(&ixas, sizeof (ixas));
		ixas.ixa_ifindex = packet->ni_physical;
		ixas.ixa_ipst = ipst;
		if (inject->inj_isv6) {
			ixas.ixa_flags = IXAF_BASIC_SIMPLE_V6;
		} else {
			ixas.ixa_flags = IXAF_BASIC_SIMPLE_V4;
		}
		ixas.ixa_flags &= ~IXAF_VERIFY_SOURCE;
		(void) ip_output_simple(packet->ni_packet, &ixas);
		ixa_cleanup(&ixas);
	}

	kmem_free(inject, sizeof (*inject));
}

/*
 * taskq function for nic events.
 */
void
ip_ne_queue_func(void *arg)
{
	hook_event_token_t hr;
	hook_nic_event_int_t *info = (hook_nic_event_int_t *)arg;
	ip_stack_t *ipst;
	netstack_t *ns;

	ns = netstack_find_by_stackid(info->hnei_stackid);
	if (ns == NULL)
		goto done;

	ipst = ns->netstack_ip;
	if (ipst == NULL)
		goto done;

	hr = (info->hnei_event.hne_protocol == ipst->ips_ipv6_net_data) ?
	    ipst->ips_ipv6nicevents : ipst->ips_ipv4nicevents;
	(void) hook_run(info->hnei_event.hne_protocol->netd_hooks, hr,
	    (hook_data_t)&info->hnei_event);

done:
	if (ns != NULL)
		netstack_rele(ns);
	kmem_free(info->hnei_event.hne_data, info->hnei_event.hne_datalen);
	kmem_free(arg, sizeof (hook_nic_event_int_t));
}

/*
 * Initialize ARP hook family and events
 */
void
arp_hook_init(ip_stack_t *ipst)
{
	HOOK_FAMILY_INIT(&ipst->ips_arproot, Hn_ARP);
	if (net_family_register(ipst->ips_arp_net_data, &ipst->ips_arproot)
	    != 0) {
		cmn_err(CE_NOTE, "arp_hook_init"
		    "net_family_register failed for arp");
	}

	HOOK_EVENT_INIT(&ipst->ips_arp_physical_in_event, NH_PHYSICAL_IN);
	ipst->ips_arp_physical_in = net_event_register(ipst->ips_arp_net_data,
	    &ipst->ips_arp_physical_in_event);
	if (ipst->ips_arp_physical_in == NULL) {
		cmn_err(CE_NOTE, "arp_hook_init: "
		    "net_event_register failed for arp/physical_in");
	}

	HOOK_EVENT_INIT(&ipst->ips_arp_physical_out_event, NH_PHYSICAL_OUT);
	ipst->ips_arp_physical_out = net_event_register(ipst->ips_arp_net_data,
	    &ipst->ips_arp_physical_out_event);
	if (ipst->ips_arp_physical_out == NULL) {
		cmn_err(CE_NOTE, "arp_hook_init: "
		    "net_event_register failed for arp/physical_out");
	}

	HOOK_EVENT_INIT(&ipst->ips_arp_nic_events, NH_NIC_EVENTS);
	ipst->ips_arpnicevents = net_event_register(ipst->ips_arp_net_data,
	    &ipst->ips_arp_nic_events);
	if (ipst->ips_arpnicevents == NULL) {
		cmn_err(CE_NOTE, "arp_hook_init: "
		    "net_event_register failed for arp/nic_events");
	}
}

void
arp_hook_destroy(ip_stack_t *ipst)
{
	if (ipst->ips_arpnicevents != NULL) {
		if (net_event_unregister(ipst->ips_arp_net_data,
		    &ipst->ips_arp_nic_events) == 0)
			ipst->ips_arpnicevents = NULL;
	}

	if (ipst->ips_arp_physical_out != NULL) {
		if (net_event_unregister(ipst->ips_arp_net_data,
		    &ipst->ips_arp_physical_out_event) == 0)
			ipst->ips_arp_physical_out = NULL;
	}

	if (ipst->ips_arp_physical_in != NULL) {
		if (net_event_unregister(ipst->ips_arp_net_data,
		    &ipst->ips_arp_physical_in_event) == 0)
			ipst->ips_arp_physical_in = NULL;
	}

	(void) net_family_unregister(ipst->ips_arp_net_data,
	    &ipst->ips_arproot);
}

void
arp_hook_shutdown(ip_stack_t *ipst)
{
	if (ipst->ips_arp_physical_in != NULL) {
		(void) net_event_shutdown(ipst->ips_arp_net_data,
		    &ipst->ips_arp_physical_in_event);
	}
	if (ipst->ips_arp_physical_out != NULL) {
		(void) net_event_shutdown(ipst->ips_arp_net_data,
		    &ipst->ips_arp_physical_out_event);
	}
	if (ipst->ips_arpnicevents != NULL) {
		(void) net_event_shutdown(ipst->ips_arp_net_data,
		    &ipst->ips_arp_nic_events);
	}
}

/* netinfo routines for the unsupported cases */

/* ARGSUSED */
int
net_no_getmtu(net_handle_t handle, phy_if_t phy_ifdata, lif_if_t ifdata)
{
	return (-1);
}

/* ARGSUSED */
static int
net_no_getpmtuenabled(net_handle_t neti)
{
	return (-1);
}

/* ARGSUSED */
static lif_if_t
net_no_lifgetnext(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata)
{
	return (-1);
}

/* ARGSUSED */
static int
net_no_inject(net_handle_t neti, inject_t style, net_inject_t *packet)
{
	return (-1);
}

/* ARGSUSED */
static phy_if_t
net_no_routeto(net_handle_t neti, struct sockaddr *address,
    struct sockaddr *next)
{
	return ((phy_if_t)-1);
}

/* ARGSUSED */
static int
net_no_ispartialchecksum(net_handle_t neti, mblk_t *mp)
{
	return (-1);
}

/* ARGSUSED */
static int
net_no_getlifaddr(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata,
    size_t nelem, net_ifaddr_t type[], void *storage)
{
	return (-1);
}

/* ARGSUSED */
static int
net_no_getlifzone(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata,
    zoneid_t *zoneid)
{
	return (-1);
}

/* ARGSUSED */
static int
net_no_getlifflags(net_handle_t neti, phy_if_t phy_ifdata, lif_if_t ifdata,
    uint64_t *flags)
{
	return (-1);
}
