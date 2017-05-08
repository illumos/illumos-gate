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

#ifndef _SYS_NETI_H
#define	_SYS_NETI_H

#include <netinet/in.h>
#include <sys/int_types.h>
#include <sys/queue.h>
#include <sys/hook_impl.h>
#include <sys/netstack.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct msgb;	/* avoiding sys/stream.h here */

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
#define	NH_OBSERVE	"OBSERVING"

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
typedef id_t		netid_t;

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

/*
 * net_inject - public interface
 */
typedef struct net_inject {
	int			ni_version;
	netid_t			ni_netid;
	struct msgb		*ni_packet;
	struct sockaddr_storage	ni_addr;
	phy_if_t		ni_physical;
} net_inject_t;

typedef struct net_data *net_handle_t;

/*
 * net_protocol_t private interface
 */
struct net_protocol_s {
	int		netp_version;
	char		*netp_name;
	int		(*netp_getifname)(net_handle_t, phy_if_t, char *,
			    const size_t);
	int		(*netp_getmtu)(net_handle_t, phy_if_t, lif_if_t);
	int		(*netp_getpmtuenabled)(net_handle_t);
	int		(*netp_getlifaddr)(net_handle_t, phy_if_t, lif_if_t,
			    size_t, net_ifaddr_t [], void *);
	int		(*neti_getlifzone)(net_handle_t, phy_if_t, lif_if_t,
			    zoneid_t *);
	int		(*neti_getlifflags)(net_handle_t, phy_if_t, lif_if_t,
			    uint64_t *);
	phy_if_t	(*netp_phygetnext)(net_handle_t, phy_if_t);
	phy_if_t	(*netp_phylookup)(net_handle_t, const char *);
	lif_if_t	(*netp_lifgetnext)(net_handle_t, phy_if_t, lif_if_t);
	int		(*netp_inject)(net_handle_t, inject_t, net_inject_t *);
	phy_if_t	(*netp_routeto)(net_handle_t, struct sockaddr *,
			    struct sockaddr *);
	int		(*netp_ispartialchecksum)(net_handle_t, struct msgb *);
	int		(*netp_isvalidchecksum)(net_handle_t, struct msgb *);
};
typedef struct net_protocol_s net_protocol_t;


/*
 * Private data structures
 */
struct net_data {
	LIST_ENTRY(net_data)		netd_list;
	net_protocol_t			netd_info;
	int				netd_refcnt;
	hook_family_int_t		*netd_hooks;
	struct neti_stack_s		*netd_stack;
	int				netd_condemned;
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

struct net_instance_s {
	int				nin_version;
	char				*nin_name;
	void				*(*nin_create)(const netid_t);
	void				(*nin_destroy)(const netid_t, void *);
	void				(*nin_shutdown)(const netid_t, void *);
};
typedef struct net_instance_s net_instance_t;

struct net_instance_int_s {
	LIST_ENTRY(net_instance_int_s)	nini_next;
	uint_t				nini_ref;
	void				*nini_created;
	struct net_instance_int_s	*nini_parent;
	net_instance_t			*nini_instance;
	hook_notify_t			nini_notify;
	uint32_t			nini_flags;
	kcondvar_t			nini_cv;
	boolean_t			nini_condemned;
};
typedef struct net_instance_int_s net_instance_int_t;
LIST_HEAD(nini_head_s, net_instance_int_s);
typedef struct nini_head_s nini_head_t;

#define	nini_version	nini_instance->nin_version
#define	nini_name	nini_instance->nin_name
#define	nini_create	nini_instance->nin_create
#define	nini_destroy	nini_instance->nin_destroy
#define	nini_shutdown	nini_instance->nin_shutdown

/*
 * netinfo stack instances
 */
struct neti_stack_s {
	kmutex_t			nts_lock;
	LIST_ENTRY(neti_stack_s)	nts_next;
	netid_t				nts_id;
	zoneid_t			nts_zoneid;
	netstackid_t			nts_stackid;
	netstack_t			*nts_netstack;
	nini_head_t			nts_instances;
	uint32_t			nts_flags;
	kcondvar_t			nts_cv;
	/* list of net_handle_t */
	LIST_HEAD(netd_listhead, net_data) nts_netd_head;
};
typedef struct neti_stack_s neti_stack_t;
LIST_HEAD(neti_stack_head_s, neti_stack_s);
typedef struct neti_stack_head_s neti_stack_head_t;

/*
 * Internal functions that need to be exported within the module.
 */
extern void neti_init(void);
extern void neti_fini(void);
extern neti_stack_t *net_getnetistackbyid(netid_t);
extern netstackid_t net_getnetstackidbynetid(netid_t);
extern netid_t net_getnetidbynetstackid(netstackid_t);
extern netid_t net_zoneidtonetid(zoneid_t);
extern zoneid_t net_getzoneidbynetid(netid_t);

/*
 * Functions available for public use.
 */
extern hook_event_token_t net_event_register(net_handle_t, hook_event_t *);
extern int net_event_shutdown(net_handle_t, hook_event_t *);
extern int net_event_unregister(net_handle_t, hook_event_t *);
extern int net_event_notify_register(net_handle_t, char *,
    hook_notify_fn_t, void *);
extern int net_event_notify_unregister(net_handle_t, char *, hook_notify_fn_t);

extern int net_family_register(net_handle_t, hook_family_t *);
extern int net_family_shutdown(net_handle_t, hook_family_t *);
extern int net_family_unregister(net_handle_t, hook_family_t *);

extern int net_hook_register(net_handle_t, char *, hook_t *);
extern int net_hook_unregister(net_handle_t, char *, hook_t *);

extern int net_inject(net_handle_t, inject_t, net_inject_t *);
extern net_inject_t *net_inject_alloc(const int);
extern void net_inject_free(net_inject_t *);

extern net_instance_t *net_instance_alloc(const int version);
extern void net_instance_free(net_instance_t *);
extern int net_instance_register(net_instance_t *);
extern int net_instance_unregister(net_instance_t *);
extern int net_instance_notify_register(netid_t, hook_notify_fn_t, void *);
extern int net_instance_notify_unregister(netid_t netid, hook_notify_fn_t);

extern kstat_t *net_kstat_create(netid_t, char *, int, char *, char *,
    uchar_t, ulong_t, uchar_t);
extern void net_kstat_delete(netid_t, kstat_t *);

extern net_handle_t net_protocol_lookup(netid_t, const char *);
extern net_handle_t net_protocol_register(netid_t, const net_protocol_t *);
extern int net_protocol_release(net_handle_t);
extern int net_protocol_unregister(net_handle_t);
extern net_handle_t net_protocol_walk(netid_t, net_handle_t);
extern int net_protocol_notify_register(net_handle_t, hook_notify_fn_t, void *);
extern int net_protocol_notify_unregister(net_handle_t, hook_notify_fn_t);


extern int net_getifname(net_handle_t, phy_if_t, char *, const size_t);
extern int net_getmtu(net_handle_t, phy_if_t, lif_if_t);
extern int net_getpmtuenabled(net_handle_t);
extern int net_getlifaddr(net_handle_t, phy_if_t, lif_if_t,
    int, net_ifaddr_t [], void *);
extern zoneid_t net_getlifzone(net_handle_t, phy_if_t, lif_if_t, zoneid_t *);
extern int net_getlifflags(net_handle_t, phy_if_t, lif_if_t, uint64_t *);
extern phy_if_t net_phygetnext(net_handle_t, phy_if_t);
extern phy_if_t net_phylookup(net_handle_t, const char *);
extern lif_if_t net_lifgetnext(net_handle_t, phy_if_t, lif_if_t);
extern phy_if_t net_routeto(net_handle_t, struct sockaddr *,
    struct sockaddr *);
extern int net_ispartialchecksum(net_handle_t, struct msgb *);
extern int net_isvalidchecksum(net_handle_t, struct msgb *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_NETI_H */
