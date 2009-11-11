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

#ifndef	_INET_IPTUN_IMPL_H
#define	_INET_IPTUN_IMPL_H

#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/stream.h>
#include <sys/modhash.h>
#include <sys/list.h>
#include <sys/dls.h>
#include <sys/mac.h>
#include <sys/dld_impl.h>
#include <sys/netstack.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/socket.h>
#include <inet/iptun.h>
#include <inet/ipclassifier.h>
#include <inet/ipsec_impl.h>
#include <netinet/in.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	IPTUN_MODID		5134
#define	IPTUN_DRIVER_NAME	"iptun"

typedef struct iptun_encaplim_s {
	ip6_dest_t		iel_destopt;
	struct ip6_opt_tunnel	iel_telopt;
	uint8_t			iel_padn[3];
} iptun_encaplim_t;

typedef struct iptun_ipv6hdrs_s {
	ip6_t			it6h_ip6h;
	iptun_encaplim_t	it6h_encaplim;
} iptun_ipv6hdrs_t;

typedef union iptun_header_u {
	ipha_t			ihu_hdr4;
	iptun_ipv6hdrs_t	ihu_hdr6;
} iptun_header_t;

typedef struct iptun_addr_s {
	sa_family_t	ia_family;
	union {
		ipaddr_t	iau_addr4;
		in6_addr_t	iau_addr6;
	} ia_addr;
} iptun_addr_t;

typedef struct iptun_typeinfo {
	iptun_type_t	iti_type;
	const char	*iti_ident;	/* MAC-Type plugin identifier */
	uint_t		iti_ipvers;	/* outer header IP version */
	uint32_t	iti_minmtu;	/* minimum possible tunnel MTU */
	uint32_t	iti_maxmtu;	/* maximum possible tunnel MTU */
	boolean_t	iti_hasraddr;	/* has a remote adress */
} iptun_typeinfo_t;

/*
 * An iptun_t represents an IP tunnel link.  The iptun_lock protects the
 * integrity of all fields except statistics which are updated atomically, and
 * is also used by iptun_upcall_cv and iptun_enter_cv.  Access to all fields
 * must be done under the protection of iptun_lock with the following
 * exceptions:
 *
 * The datapath reads certain fields without locks for performance reasons.
 *
 * - IPTUN_IS_RUNNING() is used (read access to iptun_flags IPTUN_BOUND and
 *   IPTUN_MAC_STARTED) to drop packets if they're sent while the tunnel is
 *   not running.  This is harmless as the worst case scenario is that a
 *   packet will be needlessly sent down to ip and be dropped due to an
 *   unspecified source or destination.
 */
typedef struct iptun_s {
	datalink_id_t	iptun_linkid;
	kmutex_t	iptun_lock;
	kcondvar_t	iptun_upcall_cv;
	kcondvar_t	iptun_enter_cv;
	uint32_t	iptun_flags;
	list_node_t	iptun_link;
	mac_handle_t	iptun_mh;
	conn_t		*iptun_connp;
	zoneid_t	iptun_zoneid;
	netstack_t	*iptun_ns;
	struct ipsec_tun_pol_s	*iptun_itp;
	iptun_typeinfo_t	*iptun_typeinfo;
	uint32_t	iptun_mtu;
	uint32_t	iptun_dpmtu;	/* destination path MTU */
	uint8_t		iptun_hoplimit;
	uint8_t		iptun_encaplimit;
	iptun_addr_t	iptun_laddr;	/* local address */
	iptun_addr_t	iptun_raddr;	/* remote address */
	iptun_header_t	iptun_header;
	size_t		iptun_header_size;
	ipsec_req_t	iptun_simple_policy;

	/* statistics */
	uint64_t	iptun_ierrors;
	uint64_t	iptun_oerrors;
	uint64_t	iptun_rbytes;
	uint64_t	iptun_obytes;
	uint64_t	iptun_ipackets;
	uint64_t	iptun_opackets;
	uint64_t	iptun_norcvbuf;
	uint64_t	iptun_noxmtbuf;
	uint64_t	iptun_taskq_fail;
} iptun_t;

#define	iptun_iptuns	iptun_ns->netstack_iptun
#define	iptun_laddr4	iptun_laddr.ia_addr.iau_addr4
#define	iptun_laddr6	iptun_laddr.ia_addr.iau_addr6
#define	iptun_raddr4	iptun_raddr.ia_addr.iau_addr4
#define	iptun_raddr6	iptun_raddr.ia_addr.iau_addr6
#define	iptun_header4	iptun_header.ihu_hdr4
#define	iptun_header6	iptun_header.ihu_hdr6

/* iptun_flags */
#define	IPTUN_BOUND		0x0001	/* tunnel address(es) bound with ip */
#define	IPTUN_LADDR		0x0002	/* local address is set */
#define	IPTUN_RADDR		0x0004	/* remote address is set */
#define	IPTUN_MAC_REGISTERED	0x0008	/* registered with the mac module */
#define	IPTUN_MAC_STARTED	0x0010	/* iptun_m_start() has been called */
#define	IPTUN_HASH_INSERTED	0x0020	/* iptun_t in iptun_hash */
#define	IPTUN_FIXED_MTU		0x0040	/* MTU was set using mtu link prop */
#define	IPTUN_IMPLICIT		0x0080	/* implicitly created IP tunnel */
#define	IPTUN_SIMPLE_POLICY	0x0100	/* cached iptun_simple_policy */
#define	IPTUN_UPCALL_PENDING	0x0200	/* upcall to mac module in progress */
#define	IPTUN_DELETE_PENDING	0x0400	/* iptun_delete() is issuing upcalls */
#define	IPTUN_CONDEMNED		0x0800	/* iptun_t is to be freed */

#define	IS_IPTUN_RUNNING(iptun)						\
	((iptun->iptun_flags & (IPTUN_BOUND | IPTUN_MAC_STARTED)) ==	\
	    (IPTUN_BOUND | IPTUN_MAC_STARTED))

/*
 * iptuns_lock protects iptuns_iptunlist.
 */
typedef struct iptun_stack {
	netstack_t	*iptuns_netstack; /* Common netstack */
	kmutex_t	iptuns_lock;
	list_t		iptuns_iptunlist; /* list of tunnels in this stack. */
	ipaddr_t	iptuns_relay_rtr_addr;
} iptun_stack_t;

extern dev_info_t	*iptun_dip;
extern mod_hash_t	*iptun_hash;
extern kmem_cache_t	*iptun_cache;
extern ddi_taskq_t	*iptun_taskq;
extern ldi_ident_t	iptun_ldi_ident;

extern int	iptun_ioc_init(void);
extern void	iptun_ioc_fini(void);
extern uint_t	iptun_count(void);
extern int	iptun_create(iptun_kparams_t *, cred_t *);
extern int	iptun_delete(datalink_id_t, cred_t *);
extern int	iptun_modify(const iptun_kparams_t *, cred_t *);
extern int	iptun_info(iptun_kparams_t *, cred_t *);
extern int	iptun_set_6to4relay(netstack_t *, ipaddr_t);
extern void	iptun_get_6to4relay(netstack_t *, ipaddr_t *);
extern void	iptun_set_policy(datalink_id_t, ipsec_tun_pol_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IPTUN_IMPL_H */
