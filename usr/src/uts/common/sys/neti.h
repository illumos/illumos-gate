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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_NETI_H
#define	_SYS_NETI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netinet/in.h>
#include <sys/int_types.h>
#include <sys/queue.h>
#include <sys/hook_impl.h>
#include <sys/netstack.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NETINFO_VERSION 1

/*
 * Network hooks framework stack protocol name
 */
#define	NHF_INET	"NHF_INET"
#define	NHF_INET6	"NHF_INET6"
#define	NHF_ARP		"NHF_ARP"

/*
 * Event identification
 */
#define	NH_PHYSICAL_IN	"PHYSICAL_IN"
#define	NH_PHYSICAL_OUT	"PHYSICAL_OUT"
#define	NH_FORWARDING	"FORWARDING"
#define	NH_LOOPBACK_IN	"LOOPBACK_IN"
#define	NH_LOOPBACK_OUT	"LOOPBACK_OUT"
#define	NH_NIC_EVENTS	"NIC_EVENTS"

/*
 * Network NIC hardware checksum capability
 */
#define	NET_HCK_NONE   	0x00
#define	NET_HCK_L3_FULL	0x01
#define	NET_HCK_L3_PART	0x02
#define	NET_HCK_L4_FULL	0x10
#define	NET_HCK_L4_PART	0x20

#define	NET_IS_HCK_L3_FULL(n, x)                                             \
	((net_ispartialchecksum(n, x) & NET_HCK_L3_FULL) == NET_HCK_L3_FULL)
#define	NET_IS_HCK_L3_PART(n, x)                                             \
	((net_ispartialchecksum(n, x) & NET_HCK_L3_PART) == NET_HCK_L3_PART)
#define	NET_IS_HCK_L4_FULL(n, x)                                             \
	((net_ispartialchecksum(n, x) & NET_HCK_L4_FULL) == NET_HCK_L4_FULL)
#define	NET_IS_HCK_L4_PART(n, x)                                             \
	((net_ispartialchecksum(n, x) & NET_HCK_L4_PART) == NET_HCK_L4_PART)
#define	NET_IS_HCK_L34_FULL(n, x)                                            \
	((net_ispartialchecksum(n, x) & (NET_HCK_L3_FULL|NET_HCK_L4_FULL))   \
	    == (NET_HCK_L3_FULL | NET_HCK_L4_FULL))

typedef uintptr_t	phy_if_t;
typedef intptr_t	lif_if_t;
typedef uintptr_t	net_ifdata_t;

struct net_data;
typedef struct net_data *net_data_t;

/*
 * Netinfo interface specification
 *
 * Netinfo provides an extensible and easy to use interface for
 * accessing data and functionality already embedded within network
 * code that exists within the kernel.
 */
typedef enum net_ifaddr {
	NA_ADDRESS = 1,
	NA_PEER,
	NA_BROADCAST,
	NA_NETMASK
} net_ifaddr_t;


typedef enum inject {
	NI_QUEUE_IN = 1,
	NI_QUEUE_OUT,
	NI_DIRECT_OUT
} inject_t;

typedef struct net_inject {
	mblk_t			*ni_packet;
	struct sockaddr_storage	ni_addr;
	phy_if_t		ni_physical;
} net_inject_t;


/*
 * net_info_t public interface
 */
typedef struct net_info {
	int		neti_version;
	char		*neti_protocol;
	int		(*neti_getifname)(phy_if_t, char *, const size_t,
			    netstack_t *);
	int		(*neti_getmtu)(phy_if_t, lif_if_t, netstack_t *);
	int		(*neti_getpmtuenabled)(netstack_t *);
	int		(*neti_getlifaddr)(phy_if_t, lif_if_t, size_t,
			    net_ifaddr_t [], void *, netstack_t *);
	phy_if_t	(*neti_phygetnext)(phy_if_t, netstack_t *);
	phy_if_t	(*neti_phylookup)(const char *, netstack_t *);
	lif_if_t	(*neti_lifgetnext)(phy_if_t, lif_if_t, netstack_t *);
	int		(*neti_inject)(inject_t, net_inject_t *, netstack_t *);
	phy_if_t	(*neti_routeto)(struct sockaddr *, netstack_t *);
	int		(*neti_ispartialchecksum)(mblk_t *);
	int		(*neti_isvalidchecksum)(mblk_t *);
} net_info_t;


/*
 * Private data structures
 */
struct net_data {
	LIST_ENTRY(net_data)		netd_list;
	net_info_t			netd_info;
	int				netd_refcnt;
	hook_family_int_t		*netd_hooks;
	netstack_t 			*netd_netstack;
};


typedef struct injection_s {
	net_inject_t	inj_data;
	boolean_t	inj_isv6;
	void *		inj_ptr;
} injection_t;

/*
 * The ipif_id space is [0,MAX) but this interface wants to return [1,MAX] as
 * a valid range of logical interface numbers so that it can return 0 to mean
 * "end of list" with net_lifgetnext.  Changing ipif_id's to use the [1,MAX]
 * space is something to be considered for the future, if it is worthwhile.
 */
#define	MAP_IPIF_ID(x)		((x) + 1)
#define	UNMAP_IPIF_ID(x)	(((x) > 0) ? (x) - 1 : (x))


/*
 * neti stack instances
 */
struct neti_stack {
	krwlock_t nts_netlock;

	/* list of net_data_t */
	LIST_HEAD(netd_listhead, net_data) nts_netd_head;
	netstack_t *nts_netstack;
};
typedef struct neti_stack neti_stack_t;


/*
 * Data management functions
 */
extern net_data_t net_register(const net_info_t *, netstackid_t);
extern net_data_t net_register_impl(const net_info_t *, netstack_t *);
extern int net_unregister(net_data_t);
extern net_data_t net_lookup(const char *, netstackid_t);
extern net_data_t net_lookup_impl(const char *, netstack_t *);
extern int net_release(net_data_t);
extern net_data_t net_walk(net_data_t, netstackid_t);
extern net_data_t net_walk_impl(net_data_t, netstack_t *);

/*
 * Accessor functions
 */
extern int net_register_family(net_data_t, hook_family_t *);
extern int net_unregister_family(net_data_t, hook_family_t *);
extern hook_event_token_t net_register_event(net_data_t, hook_event_t *);
extern int net_unregister_event(net_data_t, hook_event_t *);
extern int net_register_hook(net_data_t, char *, hook_t *);
extern int net_unregister_hook(net_data_t, char *, hook_t *);
extern int net_getifname(net_data_t, phy_if_t, char *, const size_t);
extern int net_getmtu(net_data_t, phy_if_t, lif_if_t);
extern int net_getpmtuenabled(net_data_t);
extern int net_getlifaddr(net_data_t, phy_if_t, lif_if_t,
    int, net_ifaddr_t [], void *);
extern phy_if_t net_phygetnext(net_data_t, phy_if_t);
extern phy_if_t net_phylookup(net_data_t, const char *);
extern lif_if_t net_lifgetnext(net_data_t, phy_if_t, lif_if_t);
extern int net_inject(net_data_t, inject_t, net_inject_t *);
extern phy_if_t net_routeto(net_data_t, struct sockaddr *);
extern int net_ispartialchecksum(net_data_t, mblk_t *);
extern int net_isvalidchecksum(net_data_t, mblk_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_NETI_H */
