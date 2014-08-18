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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_INET_IP_IRE_H
#define	_INET_IP_IRE_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	IPV6_LL_PREFIXLEN	10	/* Number of bits in link-local pref */

#define	IP_CACHE_TABLE_SIZE	256
#define	IP_MASK_TABLE_SIZE	(IP_ABITS + 1)		/* 33 ptrs */

#define	IP6_FTABLE_HASH_SIZE	32	/* size of each hash table in ptrs */
#define	IP6_CACHE_TABLE_SIZE	256
#define	IP6_MASK_TABLE_SIZE	(IPV6_ABITS + 1)	/* 129 ptrs */

/*
 * We use the common modulo hash function.  In ip_ire_init(), we make
 * sure that the cache table size is always a power of 2.  That's why
 * we can use & instead of %.  Also note that we try hard to make sure
 * the lower bits of an address capture most info from the whole address.
 * The reason being that since our hash table is probably a lot smaller
 * than 2^32 buckets so the lower bits are the most important.
 */
#define	IRE_ADDR_HASH(addr, table_size) \
	(((addr) ^ ((addr) >> 8) ^ ((addr) >> 16) ^ ((addr) >> 24)) &	\
	((table_size) - 1))

/*
 * To make a byte-order neutral hash for IPv6, just take all the
 * bytes in the bottom 32 bits into account.
 */
#define	IRE_ADDR_HASH_V6(addr, table_size) 				\
	IRE_ADDR_HASH((addr).s6_addr32[3], table_size)

/*
 * This assumes that the ftable size is a power of 2.
 * We include some high-order bytes to avoid all IRE_LOCALs in the same
 * bucket for performance reasons.
 */
#define	IRE_ADDR_MASK_HASH_V6(addr, mask, table_size) 			\
	((((addr).s6_addr8[0] & (mask).s6_addr8[0]) ^ 			\
	((addr).s6_addr8[1] & (mask).s6_addr8[1]) ^ 			\
	((addr).s6_addr8[6] & (mask).s6_addr8[6]) ^ 			\
	((addr).s6_addr8[7] & (mask).s6_addr8[7]) ^ 			\
	((addr).s6_addr8[8] & (mask).s6_addr8[8]) ^ 			\
	((addr).s6_addr8[9] & (mask).s6_addr8[9]) ^			\
	((addr).s6_addr8[10] & (mask).s6_addr8[10]) ^ 			\
	((addr).s6_addr8[13] & (mask).s6_addr8[13]) ^ 			\
	((addr).s6_addr8[14] & (mask).s6_addr8[14]) ^ 			\
	((addr).s6_addr8[15] & (mask).s6_addr8[15])) & ((table_size) - 1))

#define	IRE_HIDDEN_TYPE(ire_type) ((ire_type) &			\
	(IRE_HOST | IRE_PREFIX | IRE_DEFAULT | IRE_IF_ALL | IRE_BROADCAST))

/*
 * match parameter definitions for IRE lookup routines.
 */
#define	MATCH_IRE_DSTONLY	0x0000	/* Match just the address */
#define	MATCH_IRE_TYPE		0x0001	/* Match IRE type */
#define	MATCH_IRE_MASK		0x0002	/* Match IRE mask */
#define	MATCH_IRE_SHORTERMASK	0x0004	/* A mask shorter than the argument */
#define	MATCH_IRE_GW		0x0008	/* Match IRE gateway */
#define	MATCH_IRE_ILL		0x0010	/* Match IRE on the ill */
#define	MATCH_IRE_ZONEONLY	0x0020	/* Match IREs in specified zone, ie */
					/* don't match IRE_LOCALs from other */
					/* zones or shared IREs */
#define	MATCH_IRE_SECATTR	0x0040	/* Match gateway security attributes */
#define	MATCH_IRE_TESTHIDDEN 	0x0080	/* Match ire_testhidden IREs */
#define	MATCH_IRE_SRC_ILL	0x0100	/* ire_ill uses a src address on ill */
#define	MATCH_IRE_DIRECT	0x0200	/* Don't match indirect routes */

#define	MAX_IRE_RECURSION	4	/* Max IREs in ire_route_recursive */


/*
 * We use atomics so that we get an accurate accounting on the ires.
 * Otherwise we can't determine leaks correctly.
 */
#define	BUMP_IRE_STATS(ire_stats, x) atomic_inc_64(&(ire_stats).x)

#ifdef _KERNEL
struct ts_label_s;
struct nce_s;
/*
 * structure for passing args between ire_ftable_lookup and ire_find_best_route
 */
typedef struct ire_ftable_args_s {
	in6_addr_t		ift_addr_v6;
	in6_addr_t		ift_mask_v6;
	in6_addr_t		ift_gateway_v6;
#define	ift_addr		V4_PART_OF_V6(ift_addr_v6)
#define	ift_mask		V4_PART_OF_V6(ift_mask_v6)
#define	ift_gateway		V4_PART_OF_V6(ift_gateway_v6)
	int			ift_type;
	const ill_t		*ift_ill;
	zoneid_t		ift_zoneid;
	const ts_label_t	*ift_tsl;
	int			ift_flags;
	ire_t			*ift_best_ire;
} ire_ftable_args_t;

extern	ipaddr_t	ip_plen_to_mask(uint_t);
extern	in6_addr_t	*ip_plen_to_mask_v6(uint_t, in6_addr_t *);

extern	int	ip_ire_advise(queue_t *, mblk_t *, cred_t *);
extern	int	ip_ire_delete(queue_t *, mblk_t *, cred_t *);
extern	void	ip_ire_reclaim(void *);

extern	int	ip_mask_to_plen(ipaddr_t);
extern	int	ip_mask_to_plen_v6(const in6_addr_t *);

extern	ire_t	*ire_add(ire_t *);
extern	ire_t	*ire_add_v6(ire_t *);
extern	int	ire_atomic_start(irb_t *irb_ptr, ire_t *ire);
extern	void	ire_atomic_end(irb_t *irb_ptr, ire_t *ire);

extern	ire_t	*ire_create(uchar_t *, uchar_t *, uchar_t *,
    ushort_t, ill_t *, zoneid_t, uint_t, tsol_gc_t *, ip_stack_t *);

extern	ire_t	**ire_create_bcast(ill_t *, ipaddr_t, zoneid_t, ire_t **);
extern	ire_t	*ire_create_if_clone(ire_t *, const in6_addr_t *, uint_t *);
extern	ire_t	*ire_lookup_bcast(ill_t *, ipaddr_t, zoneid_t);
extern	int	ire_init_v4(ire_t *, uchar_t *, uchar_t *, uchar_t *,
    ushort_t, ill_t *, zoneid_t, uint_t, tsol_gc_t *, ip_stack_t *);
extern	int	ire_init_v6(ire_t *, const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, ushort_t, ill_t *, zoneid_t, uint_t, tsol_gc_t *,
    ip_stack_t *);

extern	int	ire_init_common(ire_t *, ushort_t, ill_t *, zoneid_t, uint_t,
    uchar_t, tsol_gc_t *, ip_stack_t *);

extern	ire_t	*ire_create_v6(const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, ushort_t, ill_t *, zoneid_t, uint_t,
    tsol_gc_t *, ip_stack_t *);

extern	void	ire_delete(ire_t *);
extern	void	ire_delete_v6(ire_t *);

extern	boolean_t ire_dep_build(ire_t *[], uint_t [], uint_t);
extern	void	ire_dep_delete_if_clone(ire_t *);
extern	void	ire_dep_incr_generation(ire_t *);
extern	void	ire_dep_remove(ire_t *);
extern	void	ire_dep_unbuild(ire_t *[], uint_t);
extern	uint_t	ire_dep_validate_generations(ire_t *);
extern	void	ire_dep_invalidate_generations(ire_t *);
extern	boolean_t ire_determine_nce_capable(ire_t *);

extern	void	ire_flush_cache_v4(ire_t *, int);
extern	void	ire_flush_cache_v6(ire_t *, int);

extern	ire_t	*ire_ftable_lookup_v4(ipaddr_t, ipaddr_t, ipaddr_t, int,
    const ill_t *, zoneid_t, const struct ts_label_s *, int, uint32_t,
    ip_stack_t *, uint_t *);
extern	ire_t	*ire_ftable_lookup_v6(const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, int, const ill_t *, zoneid_t,
    const struct ts_label_s *, int, uint32_t, ip_stack_t *, uint_t *);

extern	ire_t	*ire_ftable_lookup_simple_v4(ipaddr_t, uint32_t, ip_stack_t *,
    uint_t *);
extern	ire_t	*ire_ftable_lookup_simple_v6(const in6_addr_t *, uint32_t,
    ip_stack_t *, uint_t *);

extern boolean_t ire_gateway_ok_zone_v4(ipaddr_t, zoneid_t, ill_t *,
    const ts_label_t *, ip_stack_t *, boolean_t);
extern boolean_t ire_gateway_ok_zone_v6(const in6_addr_t *, zoneid_t, ill_t *,
    const ts_label_t *, ip_stack_t *, boolean_t);

extern ire_t	*ire_alt_local(ire_t *, zoneid_t, const ts_label_t *,
    const ill_t *, uint_t *);

extern  ill_t	*ire_lookup_multi_ill_v4(ipaddr_t, zoneid_t, ip_stack_t *,
    boolean_t *, ipaddr_t *);
extern  ill_t	*ire_lookup_multi_ill_v6(const in6_addr_t *, zoneid_t,
    ip_stack_t *, boolean_t *, in6_addr_t *);

extern	ire_t	*ire_nexthop(ire_t *);
extern	ill_t	*ire_nexthop_ill(ire_t *);
extern	ill_t	*ire_nce_ill(ire_t *);

extern	ire_t	*ire_reject(ip_stack_t *, boolean_t);
extern	ire_t	*ire_blackhole(ip_stack_t *, boolean_t);
extern	ire_t	*ire_multicast(ill_t *);

/* The different ire_recvfn functions */
extern void	ire_recv_forward_v4(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_noroute_v4(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_broadcast_v4(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_multicast_v4(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_multirt_v4(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_loopback_v4(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_local_v4(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_noaccept_v4(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);

extern void	ire_recv_forward_v6(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_noroute_v6(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_multicast_v6(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_multirt_v6(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_loopback_v6(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);
extern void	ire_recv_local_v6(ire_t *, mblk_t *, void *, ip_recv_attr_t *);
extern void	ire_recv_noaccept_v6(ire_t *, mblk_t *, void *,
    ip_recv_attr_t *);

extern	void	irb_refhold(irb_t *);
extern	void	irb_refhold_locked(irb_t *);
extern	void	irb_refrele(irb_t *);
extern  void	irb_increment_generation(irb_t *);

extern	void	ire_refhold(ire_t *);
extern	void	ire_refhold_notr(ire_t *);
extern	void	ire_refhold_locked(ire_t *);
extern	void	ire_refrele(ire_t *);
extern	void	ire_refrele_notr(ire_t *);
extern	void	ire_make_condemned(ire_t *);
extern	boolean_t ire_no_good(ire_t *);
extern	nce_t	*ire_handle_condemned_nce(nce_t *, ire_t *, ipha_t *, ip6_t *,
    boolean_t);

extern ire_t   	*ire_round_robin(irb_t *, ire_ftable_args_t *, uint_t,
    ire_t *, ip_stack_t *);

extern ire_t	*ire_route_recursive_v4(ipaddr_t, uint_t, const ill_t *,
    zoneid_t, const ts_label_t *, uint_t, uint_t, uint32_t, ip_stack_t *,
    ipaddr_t *, tsol_ire_gw_secattr_t **, uint_t *);
extern ire_t	*ire_route_recursive_v6(const in6_addr_t *, uint_t,
    const ill_t *, zoneid_t, const ts_label_t *, uint_t, uint_t, uint32_t,
    ip_stack_t *, in6_addr_t *, tsol_ire_gw_secattr_t **, uint_t *);
extern ire_t	*ire_route_recursive_dstonly_v4(ipaddr_t, uint_t,
    uint32_t, ip_stack_t *);
extern ire_t	*ire_route_recursive_dstonly_v6(const in6_addr_t *, uint_t,
    uint32_t, ip_stack_t *);
extern ire_t	*ire_route_recursive_impl_v4(ire_t *ire, ipaddr_t, uint_t,
    const ill_t *, zoneid_t, const ts_label_t *, uint_t, uint_t, uint32_t,
    ip_stack_t *, ipaddr_t *, tsol_ire_gw_secattr_t **, uint_t *);
extern ire_t	*ire_route_recursive_impl_v6(ire_t *ire, const in6_addr_t *,
    uint_t, const ill_t *, zoneid_t, const ts_label_t *, uint_t, uint_t,
    uint32_t, ip_stack_t *, in6_addr_t *, tsol_ire_gw_secattr_t **, uint_t *);

/* The different ire_sendfn functions */
extern int	ire_send_local_v4(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_multirt_v4(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_noroute_v4(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_multicast_v4(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_broadcast_v4(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_wire_v4(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_local_v6(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_multirt_v6(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_noroute_v6(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_multicast_v6(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);
extern int	ire_send_wire_v6(ire_t *, mblk_t *, void *,
    ip_xmit_attr_t *, uint32_t *);

extern nce_t	*ire_to_nce_pkt(ire_t *, mblk_t *);
extern nce_t	*ire_to_nce(ire_t *, ipaddr_t, const in6_addr_t *);

/* Different ire_postfragfn functions */
extern int	ip_xmit(mblk_t *, struct nce_s *,
    iaflags_t, uint_t, uint32_t, zoneid_t, zoneid_t, uintptr_t *);
extern int	ip_postfrag_loopcheck(mblk_t *, struct nce_s *,
    iaflags_t, uint_t, uint32_t, zoneid_t, zoneid_t, uintptr_t *);
extern int	ip_postfrag_multirt_v4(mblk_t *, struct nce_s *,
    iaflags_t, uint_t, uint32_t, zoneid_t, zoneid_t, uintptr_t *);
extern int	ip_postfrag_multirt_v6(mblk_t *, struct nce_s *,
    iaflags_t, uint_t, uint32_t, zoneid_t, zoneid_t, uintptr_t *);

extern void	ip_postfrag_loopback(mblk_t *, struct nce_s *,
    iaflags_t, uint_t, zoneid_t);
extern int	ire_revalidate_nce(ire_t *);

extern ire_t	*ip_select_route_pkt(mblk_t *, ip_xmit_attr_t *,
    uint_t *, int *, boolean_t *);
extern ire_t	*ip_select_route(const in6_addr_t *, const in6_addr_t,
    ip_xmit_attr_t *, uint_t *, in6_addr_t *, int *, boolean_t *);
extern ire_t	*ip_select_route_v4(ipaddr_t, ipaddr_t, ip_xmit_attr_t *,
    uint_t *, ipaddr_t *, int *, boolean_t *);
extern ire_t	*ip_select_route_v6(const in6_addr_t *, const in6_addr_t,
    ip_xmit_attr_t *, uint_t *, in6_addr_t *, int *, boolean_t *);

extern	void	ire_walk(pfv_t, void *, ip_stack_t *);
extern	void	ire_walk_ill(uint_t, uint_t, pfv_t, void *, ill_t *);
extern	void	ire_walk_v4(pfv_t, void *, zoneid_t, ip_stack_t *);
extern  void	ire_walk_ill_tables(uint_t match_flags, uint_t ire_type,
    pfv_t func, void *arg, size_t ftbl_sz, size_t htbl_sz,
    irb_t **ipftbl, ill_t *ill,
    zoneid_t zoneid, ip_stack_t *);
extern	void	ire_walk_v6(pfv_t, void *, zoneid_t, ip_stack_t *);

extern boolean_t	ire_match_args(ire_t *, ipaddr_t, ipaddr_t, ipaddr_t,
    int, const ill_t *, zoneid_t, const struct ts_label_s *, int);
extern boolean_t	ire_match_args_v6(ire_t *, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, int, const ill_t *, zoneid_t,
    const ts_label_t *, int);

extern  struct nce_s	*arp_nce_init(ill_t *, in_addr_t, int);
extern  boolean_t	ire_walk_ill_match(uint_t, uint_t, ire_t *, ill_t *,
    zoneid_t, ip_stack_t *);
extern  void ire_increment_generation(ire_t *);
extern  void ire_increment_multicast_generation(ip_stack_t *, boolean_t);
extern	void ire_rebind(ire_t *);
extern	boolean_t ire_clone_verify(ire_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_IRE_H */
