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

#ifndef	_INET_IP_NDP_H
#define	_INET_IP_NDP_H

#include <sys/mutex.h>
#include <sys/stream.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <inet/ip.h>
#include <inet/ip2mac.h>

/*
 * Internal definitions for the kernel implementation of the IPv6
 * Neighbor Discovery Protocol (NDP) and Address Resolution Protocol (ARP).
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#define	NCE_TABLE_SIZE	256
/*
 * callbacks set up with ip2mac interface, waiting for result
 * of neighbor resolution.
 */
typedef struct ncec_cb_s {
	list_node_t		ncec_cb_node;	/* next entry in list */
	void			*ncec_cb_id;
	uint32_t		ncec_cb_flags;
	ip2mac_callback_t	*ncec_cb_func;
	void			*ncec_cb_arg;
} ncec_cb_t;

#define	NCE_CB_DISPATCHED	0x00000001

/*
 * Core information tracking Neighbor Reachability is tracked in the
 * ncec_s/ncec_t. The information contained in the ncec_t does not contain
 * any link-specific details other than the pointer to the ill_t itself.
 * The link-specific information is tracked in the nce_t structure.
 */
struct ncec_s {
	struct	ncec_s	*ncec_next;	/* Hash chain next pointer */
	struct	ncec_s	**ncec_ptpn;	/* Pointer to previous next */
	struct 	ill_s	*ncec_ill;	/* Associated ill */
	uint16_t	ncec_flags;	/* See below */
	uint16_t	ncec_state;	/* See reachability states in if.h */
	int16_t		ncec_pcnt;	/* Probe counter */
	uint16_t	ncec_rcnt;	/* Retransmit counter */
	in6_addr_t	ncec_addr;	/* address of the nighbor */
	uchar_t		*ncec_lladdr;
	mblk_t		*ncec_qd_mp;	/* Head outgoing queued packets */
	uint64_t	ncec_last;	/* Time last reachable in msec */
	uint32_t	ncec_refcnt;	/* ncec active usage count */
	kmutex_t	ncec_lock;	/* See comments on top for what */
					/* this field protects */
	int		ncec_unsolicit_count; /* Unsolicited Adv count */
	timeout_id_t	ncec_timeout_id;
	uchar_t		ncec_ipversion;	/* IPv4(ARP)/IPv6(NDP) version */
	uint_t		ncec_defense_count;	/* number of NDP conflicts */
	uint_t		ncec_last_time_defended; /* last time defended (secs) */
	uint64_t	ncec_init_time; /* time when it was set to ND_INITIAL */
	boolean_t	ncec_trace_disable;	/* True when alloc fails */
	/*
	 * interval to keep track of DAD probes.
	 */
	clock_t		ncec_xmit_interval;
	ip_stack_t	*ncec_ipst;	/* Does not have a netstack_hold */
	list_t		ncec_cb;	/* callbacks waiting for resolution */
	uint_t		ncec_cb_walker_cnt;
	uint_t		ncec_nprobes;
	uint_t		ncec_lladdr_length;
};

/*
 * The nce_t list hangs off the ill_s and tracks information that depends
 * on the underlying physical link. Thus when the ill goes down,
 * the nce_t list has to be flushed. This is  done as part of ill_delete()
 *
 * When the fastpath ack comes back in ill_fastpath_ack we call
 * nce_fastpath_update to update the nce_t. We never actually
 * flush the fastpath list, which is kept as an index into the
 * ncec_t structures.
 *
 * when we ndp_delete, we remove the nce entries pointing
 * at the dying ncec from the ill_fastpath_list chain.
 *
 */
struct nce_s	{
	list_node_t	nce_node;
	ill_t		*nce_ill;
	boolean_t	nce_is_condemned;
	in6_addr_t	nce_addr;
	/*
	 * link-layer specific fields below
	 */
	mblk_t		*nce_dlur_mp;	/* DL_UNITDATA_REQ mp */
	mblk_t		*nce_fp_mp;	/* fast path mp */
	struct ncec_s	*nce_common;
	kmutex_t	nce_lock;
	uint32_t	nce_refcnt;
	uint_t		nce_ipif_cnt;	/* number of ipifs with the nce_addr */
					/* as their local address */
};

/*
 * The ndp_g_t structure contains protocol specific information needed
 * to synchronize and manage neighbor cache entries for IPv4 and IPv6.
 * There are 2 such structures, ips_ndp4 and ips_ndp6.
 * ips_ndp6 contains the data structures needed for IPv6 Neighbor Discovery.
 * ips_ndp4 contains the data structures for IPv4 ARP.
 *
 * Locking notes:
 * ndp_g_lock protects neighbor cache tables access and
 * insertion/removal of cache entries into/from these tables. The ncec_lock
 * and nce_lock protect fields in the ncec_t and nce_t structures.
 * Should there be a need to obtain nce[c]_lock and ndp_g_lock, ndp_g_lock is
 * acquired first.
 */
typedef	struct ndp_g_s {
	kmutex_t	ndp_g_lock;	/* Lock protecting  cache hash table */
	ncec_t		*nce_hash_tbl[NCE_TABLE_SIZE];
	int		ndp_g_walker; /* # of active thread walking hash list */
	boolean_t	ndp_g_walker_cleanup; /* true implies defer deletion. */
} ndp_g_t;

/* ncec_flags  */
#define	NCE_F_MYADDR		0x1	/* ipif exists for the ncec_addr */
#define	NCE_F_UNVERIFIED	0x2	/* DAD in progress. */
#define	NCE_F_ISROUTER		0x4
#define	NCE_F_FAST		0x8

/*
 * NCE_F_NONUD is used to disable IPv6 Neighbor Unreachability Detection or
 * IPv4 aging and maps to the ATF_PERM flag for arp(1m)
 */
#define	NCE_F_NONUD		0x10

#define	NCE_F_ANYCAST		0x20
#define	NCE_F_CONDEMNED		0x40
#define	NCE_F_UNSOL_ADV		0x80
#define	NCE_F_BCAST		0x100
#define	NCE_F_MCAST		0x200

/*
 * NCE_F_PUBLISH is set for all ARP/ND entries that we announce. This
 * includes locally configured addresses as well as those that we proxy for.
 */
#define	NCE_F_PUBLISH		0x400

/*
 * NCE_F_AUTHORITY is set for any address that we have authoritatitve
 * information for. This includes locally configured addresses as well
 * as statically configured arp entries that are set up using the "permanent"
 * option described in arp(1m). The NCE_F_AUTHORITY asserts that we would
 * reject any updates for that nce's (host, link-layer-address) information
 */
#define	NCE_F_AUTHORITY		0x800

#define	NCE_F_DELAYED		0x1000 /* rescheduled on dad_defend_rate */
#define	NCE_F_STATIC		0x2000

/* State REACHABLE, STALE, DELAY or PROBE */
#define	NCE_ISREACHABLE(ncec)			\
	(((((ncec)->ncec_state) >= ND_REACHABLE) &&	\
	((ncec)->ncec_state) <= ND_PROBE))

#define	NCE_ISCONDEMNED(ncec)	((ncec)->ncec_flags & NCE_F_CONDEMNED)

/* NDP flags set in SOL/ADV requests */
#define	NDP_UNICAST		0x1
#define	NDP_ISROUTER		0x2
#define	NDP_SOLICITED		0x4
#define	NDP_ORIDE		0x8
#define	NDP_PROBE		0x10

/* Number of packets queued in NDP for a neighbor */
#define	ND_MAX_Q		4

/*
 * Structure for nce_update_hw_changed;
 */
typedef struct {
	ipaddr_t hwm_addr;	/* IPv4 address */
	uint_t	hwm_hwlen;	/* Length of hardware address (may be 0) */
	uchar_t *hwm_hwaddr;	/* Pointer to new hardware address, if any */
	int	hwm_flags;
} nce_hw_map_t;

/* When SAP is greater than zero address appears before SAP */
#define	NCE_LL_ADDR_OFFSET(ill)	(((ill)->ill_sap_length) < 0 ? \
	(sizeof (dl_unitdata_req_t)) : \
	((sizeof (dl_unitdata_req_t)) + (ABS((ill)->ill_sap_length))))

#define	NCE_LL_SAP_OFFSET(ill) (((ill)->ill_sap_length) < 0 ? \
	((sizeof (dl_unitdata_req_t)) + ((ill)->ill_phys_addr_length)) : \
	(sizeof (dl_unitdata_req_t)))

#define	NCE_MYADDR(ncec)	(((ncec)->ncec_flags & NCE_F_MYADDR) != 0)

/*
 * NCE_PUBLISH() identifies the addresses that we are publishing. This
 * includes locally configured address (NCE_MYADDR()) as well as those that
 * we are proxying.
 */
#define	NCE_PUBLISH(ncec) ((ncec->ncec_flags & NCE_F_PUBLISH) != 0)

#ifdef _BIG_ENDIAN
#define	NCE_LL_SAP_COPY(ill, mp) \
	{ \
	size_t abs_sap_len = ABS((ill)->ill_sap_length); \
	if (abs_sap_len > 0) { \
		ASSERT(abs_sap_len <= sizeof (uint32_t)); \
		ASSERT((mp)->b_rptr + NCE_LL_SAP_OFFSET(ill) + \
		    abs_sap_len <= ((mp)->b_wptr)); \
		bcopy((uint8_t *)&(ill)->ill_sap + sizeof (ill->ill_sap) - \
		    abs_sap_len, \
		    ((mp)->b_rptr + NCE_LL_SAP_OFFSET(ill)), \
		    abs_sap_len); \
	} \
	}
#else
#define	NCE_LL_SAP_COPY(ill, mp) \
	{ \
	size_t abs_sap_len = ABS((ill)->ill_sap_length); \
	if (abs_sap_len > 0) { \
		uint32_t abs_sap_len = ABS((ill)->ill_sap_length); \
		ASSERT(abs_sap_len <= sizeof (uint32_t)); \
		ASSERT((mp)->b_rptr + NCE_LL_SAP_OFFSET(ill) + \
		    abs_sap_len <= ((mp)->b_wptr)); \
		bcopy(&((ill)->ill_sap), \
		((mp)->b_rptr + NCE_LL_SAP_OFFSET(ill)), \
		abs_sap_len); \
	} \
	}
#endif

/*
 * Exclusive-or the 6 bytes that are likely to contain the MAC
 * address. Assumes table_size does not exceed 256.
 * Assumes EUI-64 format for good hashing.
 */
#define	NCE_ADDR_HASH_V6(addr, table_size)				\
	(((addr).s6_addr8[8] ^ (addr).s6_addr8[9] ^			\
	(addr).s6_addr8[10] ^ (addr).s6_addr8[13] ^			\
	(addr).s6_addr8[14] ^ (addr).s6_addr8[15]) % (table_size))

/* NDP Cache Entry Hash Table */
#define	NCE_TABLE_SIZE	256

extern	void	ip_nce_reclaim(void *);
extern	void	ncec_delete(ncec_t *);
extern	void	ncec_delete_per_ill(ncec_t *, uchar_t *);
extern	void	nce_fastpath_update(ill_t *, mblk_t  *);
extern	nd_opt_hdr_t *ndp_get_option(nd_opt_hdr_t *, int, int);
extern	void	ncec_inactive(ncec_t *);
extern	void	ndp_input(mblk_t *, ip_recv_attr_t *);
extern	ncec_t	*ncec_lookup_illgrp_v6(ill_t *, const in6_addr_t *);
extern	ncec_t	*ncec_lookup_illgrp_v4(ill_t *, const in_addr_t *);
extern	nce_t	*nce_lookup_v4(ill_t *, const in_addr_t *);
extern	nce_t	*nce_lookup_v6(ill_t *, const in6_addr_t *);
extern	void	nce_make_unreachable(ncec_t *);
extern	mblk_t	*ndp_mcastreq(ill_t *, const in6_addr_t *, uint32_t, uint32_t,
    mblk_t *);
extern  nce_t	*ndp_nce_init(ill_t *, const in6_addr_t *, int);
extern  void	nce_process(ncec_t *, uchar_t *, uint32_t, boolean_t);
extern	int	ndp_query(ill_t *, lif_nd_req_t *);
extern	int	ndp_sioc_update(ill_t *, lif_nd_req_t *);
extern	boolean_t	ndp_verify_optlen(nd_opt_hdr_t *, int);
extern	void	nce_timer(void *);
extern	void	ncec_walk(ill_t *, pfi_t, void *, ip_stack_t *);
extern	void	ncec_walk_common(ndp_g_t *, ill_t *, pfi_t,
    void *, boolean_t);
extern	boolean_t	nce_restart_dad(ncec_t *);
extern	void	ndp_resolv_failed(ncec_t *);
extern	void	arp_resolv_failed(ncec_t *);
extern	void	nce_fastpath_list_delete(ill_t *, ncec_t *, list_t *);
extern	void	nce_queue_mp(ncec_t *, mblk_t *, boolean_t);
extern	void	nce_update_hw_changed(ncec_t *, void *);
extern	int	nce_lookup_then_add_v6(ill_t *, uchar_t *, uint_t,
    const in6_addr_t *, uint16_t, uint16_t, nce_t **);
extern	int	nce_lookup_then_add_v4(ill_t *, uchar_t *, uint_t,
    const in_addr_t *, uint16_t, uint16_t, nce_t **);
extern boolean_t nce_cmp_ll_addr(const ncec_t *, const uchar_t *, uint32_t);
extern void	nce_update(ncec_t *, uint16_t, uchar_t *);
extern nce_t   *nce_lookup_mapping(ill_t *, const in6_addr_t *);

extern void	nce_restart_timer(ncec_t *, uint_t);
extern void	ncec_refrele(ncec_t *);
extern void	ncec_refhold(ncec_t *);
extern void	ncec_refrele_notr(ncec_t *);
extern void	ncec_refhold_notr(ncec_t *);
extern void	nce_resolv_ok(ncec_t *);
extern uint32_t	ndp_solicit(ncec_t *, in6_addr_t, ill_t *);
extern boolean_t ip_nce_conflict(mblk_t *, ip_recv_attr_t *, ncec_t *);
extern boolean_t ndp_announce(ncec_t *);
extern void	ip_nce_lookup_and_update(ipaddr_t *, ipif_t *, ip_stack_t *,
    uchar_t *, int, int);
extern void	nce_refrele(nce_t *);
extern void	nce_refhold(nce_t *);
extern void	nce_delete(nce_t *);
extern void	nce_flush(ill_t *, boolean_t);
extern void	nce_walk(ill_t *, pfi_t, void *);
extern void	ip_ndp_resolve(struct ncec_s *);
extern void	ip_addr_recover(ipsq_t *, queue_t *, mblk_t *, void *);

#ifdef DEBUG
extern	void	nce_trace_ref(ncec_t *);
extern	void	nce_untrace_ref(ncec_t *);
#endif

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_NDP_H */
