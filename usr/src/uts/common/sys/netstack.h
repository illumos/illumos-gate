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
 * Copyright (c) 2016, Joyent, Inc. All rights reserved.
 */

#ifndef _SYS_NETSTACK_H
#define	_SYS_NETSTACK_H

#include <sys/kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This allows various pieces in and around IP to have a separate instance
 * for each instance of IP. This is used to support zones that have an
 * exclusive stack.
 * Pieces of software far removed from IP (e.g., kernel software
 * sitting on top of TCP or UDP) probably should not use the netstack
 * support; if such software wants to support separate zones it
 * can do that using the zones framework (zone_key_create() etc)
 * whether there is a shared IP stack or and exclusive IP stack underneath.
 */

/*
 * Each netstack has an identifier. We reuse the zoneid allocation for
 * this but have a separate typedef. Thus the shared stack (used by
 * the global zone and other shared stack zones) have a zero ID, and
 * the exclusive stacks have a netstackid that is the same as their zoneid.
 */
typedef id_t	netstackid_t;

#define	GLOBAL_NETSTACKID	0

/*
 * One for each module which uses netstack support.
 * Used in netstack_register().
 *
 * The order of these is important for some modules both for
 * the creation (which done in ascending order) and destruction (which is
 * done in in decending order).
 */
#define	NS_ALL		-1	/* Match all */
#define	NS_DLS		0
#define	NS_IPTUN	1
#define	NS_STR		2	/* autopush list etc */
#define	NS_HOOK		3
#define	NS_NETI		4
#define	NS_ARP		5
#define	NS_IP		6
#define	NS_ICMP		7
#define	NS_UDP		8
#define	NS_TCP		9
#define	NS_SCTP		10
#define	NS_RTS		11
#define	NS_IPSEC	12
#define	NS_KEYSOCK	13
#define	NS_SPDSOCK	14
#define	NS_IPSECAH	15
#define	NS_IPSECESP	16
#define	NS_IPNET	17
#define	NS_ILB		18
#define	NS_MAX		(NS_ILB+1)

/*
 * State maintained for each module which tracks the state of
 * the create, shutdown and destroy callbacks.
 *
 * Keeps track of pending actions to avoid holding locks when
 * calling into the create/shutdown/destroy functions in the module.
 */
#ifdef _KERNEL
typedef struct {
	uint16_t 	nms_flags;
	kcondvar_t	nms_cv;
} nm_state_t;

/*
 * nms_flags
 */
#define	NSS_CREATE_NEEDED	0x0001
#define	NSS_CREATE_INPROGRESS	0x0002
#define	NSS_CREATE_COMPLETED	0x0004
#define	NSS_SHUTDOWN_NEEDED	0x0010
#define	NSS_SHUTDOWN_INPROGRESS	0x0020
#define	NSS_SHUTDOWN_COMPLETED	0x0040
#define	NSS_DESTROY_NEEDED	0x0100
#define	NSS_DESTROY_INPROGRESS	0x0200
#define	NSS_DESTROY_COMPLETED	0x0400

#define	NSS_CREATE_ALL	\
	(NSS_CREATE_NEEDED|NSS_CREATE_INPROGRESS|NSS_CREATE_COMPLETED)
#define	NSS_SHUTDOWN_ALL	\
	(NSS_SHUTDOWN_NEEDED|NSS_SHUTDOWN_INPROGRESS|NSS_SHUTDOWN_COMPLETED)
#define	NSS_DESTROY_ALL	\
	(NSS_DESTROY_NEEDED|NSS_DESTROY_INPROGRESS|NSS_DESTROY_COMPLETED)

#define	NSS_ALL_INPROGRESS	\
	(NSS_CREATE_INPROGRESS|NSS_SHUTDOWN_INPROGRESS|NSS_DESTROY_INPROGRESS)
#else
/* User-level compile like IP Filter needs a netstack_t. Dummy */
typedef uint_t nm_state_t;
#endif /* _KERNEL */

/*
 * One for every netstack in the system.
 * We use a union so that the compilar and lint can provide type checking -
 * in principle we could have
 * #define	netstack_arp		netstack_modules[NS_ARP]
 * etc, but that would imply void * types hence no type checking by the
 * compiler.
 *
 * All the fields in netstack_t except netstack_next are protected by
 * netstack_lock. netstack_next is protected by netstack_g_lock.
 */
struct netstack {
	union {
		void	*nu_modules[NS_MAX];
		struct {
			struct dls_stack	*nu_dls;
			struct iptun_stack	*nu_iptun;
			struct str_stack	*nu_str;
			struct hook_stack	*nu_hook;
			struct neti_stack	*nu_neti;
			struct arp_stack	*nu_arp;
			struct ip_stack		*nu_ip;
			struct icmp_stack	*nu_icmp;
			struct udp_stack	*nu_udp;
			struct tcp_stack	*nu_tcp;
			struct sctp_stack	*nu_sctp;
			struct rts_stack	*nu_rts;
			struct ipsec_stack	*nu_ipsec;
			struct keysock_stack	*nu_keysock;
			struct spd_stack	*nu_spdsock;
			struct ipsecah_stack	*nu_ipsecah;
			struct ipsecesp_stack	*nu_ipsecesp;
			struct ipnet_stack	*nu_ipnet;
			struct ilb_stack	*nu_ilb;
		} nu_s;
	} netstack_u;
#define	netstack_modules	netstack_u.nu_modules
#define	netstack_dls		netstack_u.nu_s.nu_dls
#define	netstack_iptun		netstack_u.nu_s.nu_iptun
#define	netstack_str		netstack_u.nu_s.nu_str
#define	netstack_hook		netstack_u.nu_s.nu_hook
#define	netstack_neti		netstack_u.nu_s.nu_neti
#define	netstack_arp		netstack_u.nu_s.nu_arp
#define	netstack_ip		netstack_u.nu_s.nu_ip
#define	netstack_icmp		netstack_u.nu_s.nu_icmp
#define	netstack_udp		netstack_u.nu_s.nu_udp
#define	netstack_tcp		netstack_u.nu_s.nu_tcp
#define	netstack_sctp		netstack_u.nu_s.nu_sctp
#define	netstack_rts		netstack_u.nu_s.nu_rts
#define	netstack_ipsec		netstack_u.nu_s.nu_ipsec
#define	netstack_keysock	netstack_u.nu_s.nu_keysock
#define	netstack_spdsock	netstack_u.nu_s.nu_spdsock
#define	netstack_ipsecah	netstack_u.nu_s.nu_ipsecah
#define	netstack_ipsecesp	netstack_u.nu_s.nu_ipsecesp
#define	netstack_ipnet		netstack_u.nu_s.nu_ipnet
#define	netstack_ilb		netstack_u.nu_s.nu_ilb

	nm_state_t	netstack_m_state[NS_MAX]; /* module state */

	kmutex_t	netstack_lock;
	struct netstack *netstack_next;
	netstackid_t	netstack_stackid;
	int		netstack_numzones;	/* Number of zones using this */
	int		netstack_refcnt;	/* Number of hold-rele */
	int		netstack_flags;	/* See below */

#ifdef _KERNEL
	/* Needed to ensure that we run the callback functions in order */
	kcondvar_t	netstack_cv;
#endif
};
typedef struct netstack netstack_t;

/* netstack_flags values */
#define	NSF_UNINIT		0x01		/* Not initialized */
#define	NSF_CLOSING		0x02		/* Going away */
#define	NSF_ZONE_CREATE		0x04		/* create callbacks inprog */
#define	NSF_ZONE_SHUTDOWN	0x08		/* shutdown callbacks */
#define	NSF_ZONE_DESTROY	0x10		/* destroy callbacks */

#define	NSF_ZONE_INPROGRESS	\
	(NSF_ZONE_CREATE|NSF_ZONE_SHUTDOWN|NSF_ZONE_DESTROY)

/*
 * One for each of the NS_* values.
 */
struct netstack_registry {
	int		nr_flags;	/* 0 if nothing registered */
	void		*(*nr_create)(netstackid_t, netstack_t *);
	void		(*nr_shutdown)(netstackid_t, void *);
	void		(*nr_destroy)(netstackid_t, void *);
};

/* nr_flags values */
#define	NRF_REGISTERED	0x01
#define	NRF_DYING	0x02	/* No new creates */

/*
 * To support kstat_create_netstack() using kstat_add_zone we need
 * to track both
 *  - all zoneids that use the global/shared stack
 *  - all kstats that have been added for the shared stack
 */

extern void netstack_init(void);
extern void netstack_hold(netstack_t *);
extern void netstack_rele(netstack_t *);
extern netstack_t *netstack_find_by_cred(const cred_t *);
extern netstack_t *netstack_find_by_stackid(netstackid_t);
extern netstack_t *netstack_find_by_zoneid(zoneid_t);
extern boolean_t netstack_inuse_by_stackid(netstackid_t stackid);

extern zoneid_t netstackid_to_zoneid(netstackid_t);
extern zoneid_t netstack_get_zoneid(netstack_t *);
extern netstackid_t zoneid_to_netstackid(zoneid_t);

extern netstack_t *netstack_get_current(void);

/*
 * Register interest in changes to the set of netstacks.
 * The createfn and destroyfn are required, but the shutdownfn can be
 * NULL.
 * Note that due to the current zsd implementation, when the create
 * function is called the zone isn't fully present, thus functions
 * like zone_find_by_* will fail, hence the create function can not
 * use many zones kernel functions including zcmn_err().
 */
extern void	netstack_register(int,
    void *(*)(netstackid_t, netstack_t *),
    void (*)(netstackid_t, void *),
    void (*)(netstackid_t, void *));
extern void	netstack_unregister(int);
extern kstat_t	*kstat_create_netstack(char *, int, char *, char *, uchar_t,
    uint_t, uchar_t, netstackid_t);
extern void	kstat_delete_netstack(kstat_t *, netstackid_t);

/*
 * Simple support for walking all the netstacks.
 * The caller of netstack_next() needs to call netstack_rele() when
 * done with a netstack.
 */
typedef	int	netstack_handle_t;

extern void	netstack_next_init(netstack_handle_t *);
extern void	netstack_next_fini(netstack_handle_t *);
extern netstack_t	*netstack_next(netstack_handle_t *);

#ifdef	__cplusplus
}
#endif


#endif	/* _SYS_NETSTACK_H */
