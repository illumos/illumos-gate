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

#ifndef _INET_IPNET_H
#define	_INET_IPNET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/netstack.h>
#include <sys/list.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/avl.h>
#include <sys/neti.h>

/*
 * Structure used to hold information for both IPv4 and IPv6 addresses.
 */
typedef struct ipnetif_addr {
	union {
		ipaddr_t	ifau_ip4addr;
		in6_addr_t	ifau_ip6addr;
	} ifa_addr;
	ipaddr_t	ifa_brdaddr;
	zoneid_t	ifa_zone;
	uint64_t	ifa_id;
	list_node_t	ifa_link;
} ipnetif_addr_t;
#define	ifa_ip4addr	ifa_addr.ifau_ip4addr
#define	ifa_ip6addr	ifa_addr.ifau_ip6addr

/*
 * Structure describes the ipnet module representation of an ip interface.
 * The structure holds both IPv4 and IPv6 addresses, the address lists are
 * protected by a mutex. The ipnetif structures are held per stack instance
 * within avl trees indexed on name and ip index.
 */
typedef struct ipnetif {
	char		if_name[LIFNAMSIZ];
	uint_t		if_flags;
	uint64_t	if_index;
	kmutex_t	if_addr_lock;	/* protects both addr lists */
	list_t		if_ip4addr_list;
	list_t		if_ip6addr_list;
	avl_node_t	if_avl_by_index;
	avl_node_t	if_avl_by_name;
	dev_t		if_dev;
	uint_t		if_multicnt;	/* protected by ips_event_lock */
	kmutex_t	if_reflock;	/* protects if_refcnt */
	uint_t		if_refcnt;
} ipnetif_t;

/* if_flags */
#define	IPNETIF_IPV4PLUMBED	0x01
#define	IPNETIF_IPV6PLUMBED	0x02
#define	IPNETIF_IPV4ALLMULTI	0x04
#define	IPNETIF_IPV6ALLMULTI	0x08

/*
 * Structure used by the accept callback function.  This is simply an address
 * pointer into a packet (either IPv4 or IPv6), along with an address family
 * that denotes which pointer is valid.
 */
typedef struct ipnet_addrp {
	sa_family_t	iap_family;
	union {
		ipaddr_t	*iapu_addr4;
		in6_addr_t	*iapu_addr6;
	} iap_addrp;
} ipnet_addrp_t;
#define	iap_addr4	iap_addrp.iapu_addr4
#define	iap_addr6	iap_addrp.iapu_addr6

struct ipnet;
struct ipobs_hook_data;
typedef boolean_t ipnet_acceptfn_t(struct ipnet *, struct ipobs_hook_data *,
    ipnet_addrp_t *, ipnet_addrp_t *);

/*
 * Per instance data for all open streams. Instance data is held on a
 * per netstack list see struct ipnet_stack below.
 */
typedef struct ipnet {
	queue_t		*ipnet_rq;	/* read queue pointer */
	minor_t		ipnet_minor;	/* minor number for this instance */
	ipnetif_t	*ipnet_if;	/* ipnetif for this open instance */
	zoneid_t	ipnet_zoneid;	/* zoneid the device was opened in */
	uint16_t	ipnet_flags;	/* see below */
	t_scalar_t	ipnet_sap;	/* sap this instance is bound to */
	t_uscalar_t	ipnet_dlstate;	/* dlpi state */
	list_node_t	ipnet_next;	/* list next member */
	netstack_t	*ipnet_ns;	/* netstack of zone we were opened in */
	ipnet_acceptfn_t *ipnet_acceptfn; /* accept callback function pointer */
} ipnet_t;

/* ipnet_flags */
#define	IPNET_PROMISC_PHYS	0x01
#define	IPNET_PROMISC_MULTI	0x02
#define	IPNET_PROMISC_SAP	0x04
#define	IPNET_INFO		0x08
#define	IPNET_LOMODE		0x10

/*
 * Per-netstack data holding:
 * - net_handle_t references for IPv4 and IPv6 for this netstack.
 * - avl trees by name and index for ip interfaces associated with this
 *   netstack. The trees are protected by ips_avl_lock.
 * - ips_str_list is a list of open client streams.  ips_walkers_lock in
 *   conjunction with ips_walkers_cv and ips_walkers_cnt synchronize access to
 *   the list.  The count is incremented in ipnet_dispatch() at the start of a
 *   walk and decremented when the walk is finished. If the walkers count is 0
 *   then we cv_broadcast() waiting any threads waiting on the walkers count.
 * - ips_event_lock synchronizes ipnet_if_init() and incoming NIC info events.
 *   We cannot be processing any NIC info events while initializing interfaces
 *   in ipnet_if_init().
 *
 * Note on lock ordering: If a thread needs to both hold the ips_event_lock
 * and any other lock such as ips_walkers_lock, ips_avl_lock, or if_addr_lock,
 * the ips_event_lock must be held first.  This lock ordering is mandated by
 * ipnet_nicevent_cb() which must always grab ips_event_lock before continuing
 * with processing NIC events.
 */
typedef struct ipnet_stack {
	net_handle_t	ips_ndv4;
	net_handle_t	ips_ndv6;
	netstack_t	*ips_netstack;
	hook_t		*ips_nicevents;
	kmutex_t	ips_event_lock;
	kmutex_t	ips_avl_lock;
	avl_tree_t	ips_avl_by_index;
	avl_tree_t	ips_avl_by_name;
	kmutex_t	ips_walkers_lock;
	kcondvar_t	ips_walkers_cv;
	uint_t		ips_walkers_cnt;
	list_t		ips_str_list;
	uint64_t	ips_drops;
} ipnet_stack_t;

/*
 * Template for dl_info_ack_t initialization.  We don't have an address, so we
 * set the address length to just the SAP length (16 bits).  We don't really
 * have a maximum SDU, but setting it to UINT_MAX proved problematic with
 * applications that performed arithmetic on dl_max_sdu and wrapped around, so
 * we sleaze out and use INT_MAX.
 */
#define	IPNET_INFO_ACK_INIT {						\
	DL_INFO_ACK,			/* dl_primitive */		\
	INT_MAX,			/* dl_max_sdu */		\
	0,				/* dl_min_sdu */		\
	sizeof (uint16_t),		/* dl_addr_length */ 		\
	DL_IPNET,			/* dl_mac_type */		\
	0,				/* dl_reserved */		\
	0,				/* dl_current_state */		\
	sizeof (uint16_t),		/* dl_sap_length */ 		\
	DL_CLDLS,			/* dl_service_mode */		\
	0,				/* dl_qos_length */		\
	0,				/* dl_qos_offset */		\
	0,				/* dl_range_length */		\
	0,				/* dl_range_offset */		\
	DL_STYLE1,			/* dl_provider_style */		\
	0,				/* dl_addr_offset */		\
	DL_VERSION_2,			/* dl_version */		\
	0,				/* dl_brdcst_addr_length */	\
	0				/* dl_brdcst_addr_offset */	\
}

typedef void ipnet_walkfunc_t(const char *, void *, dev_t);
extern void ipnet_walk_if(ipnet_walkfunc_t *, void *, zoneid_t);
extern dev_t ipnet_if_getdev(char *, zoneid_t);

#ifdef __cplusplus
}
#endif

#endif /* _INET_IPNET_H */
