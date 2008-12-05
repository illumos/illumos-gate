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

/* This assumes that the ftable size is a power of 2. */
#define	IRE_ADDR_MASK_HASH_V6(addr, mask, table_size) 			\
	((((addr).s6_addr8[8] & (mask).s6_addr8[8]) ^ 			\
	((addr).s6_addr8[9] & (mask).s6_addr8[9]) ^			\
	((addr).s6_addr8[10] & (mask).s6_addr8[10]) ^ 			\
	((addr).s6_addr8[13] & (mask).s6_addr8[13]) ^ 			\
	((addr).s6_addr8[14] & (mask).s6_addr8[14]) ^ 			\
	((addr).s6_addr8[15] & (mask).s6_addr8[15])) & ((table_size) - 1))

/*
 * match parameter definitions for IRE lookup routines.
 */
#define	MATCH_IRE_DSTONLY	0x0000	/* Match just the address */
#define	MATCH_IRE_TYPE		0x0001	/* Match IRE type */
#define	MATCH_IRE_SRC		0x0002	/* Match IRE source address */
#define	MATCH_IRE_MASK		0x0004	/* Match IRE mask */
#define	MATCH_IRE_WQ		0x0008	/* Match IRE ire_stq to write queue */
#define	MATCH_IRE_GW		0x0010	/* Match IRE gateway */
#define	MATCH_IRE_IPIF		0x0020	/* Match IRE ipif */
#define	MATCH_IRE_RECURSIVE	0x0040	/* Do recursive lookup if necessary */
#define	MATCH_IRE_DEFAULT	0x0080	/* Return default route if no route */
					/* found. */
#define	MATCH_IRE_RJ_BHOLE	0x0100	/* During lookup if we hit an ire */
					/* with RTF_REJECT or RTF_BLACKHOLE, */
					/* return the ire. No recursive */
					/* lookup should be done. */
#define	MATCH_IRE_IHANDLE	0x0200	/* Match IRE on ihandle */
#define	MATCH_IRE_MARK_HIDDEN	0x0400	/* Match IRE ire_marks with */
					/* IRE_MARK_HIDDEN. */
/*
 * MATCH_IRE_ILL is used whenever we want to specifically match an IRE
 * whose ire_ipif->ipif_ill or (ill_t *)ire_stq->q_ptr matches a given
 * ill. When MATCH_IRE_ILL is used to locate an IRE_CACHE, it implies
 * that the packet will not be load balanced. This is normally used
 * by in.mpathd to send out failure detection probes.
 *
 * MATCH_IRE_ILL_GROUP is used whenever we are not specific about which
 * interface (ill) the packet should be sent out. This implies that the
 * packets will be subjected to load balancing and it might go out on
 * any interface in the group. When there is only interface in the group,
 * MATCH_IRE_ILL_GROUP becomes MATCH_IRE_ILL. Most of the code uses
 * MATCH_IRE_ILL_GROUP and MATCH_IRE_ILL is used in very few cases where
 * we want to disable load balancing.
 *
 * MATCH_IRE_PARENT is used whenever we unconditionally want to get the
 * parent IRE (sire) while recursively searching IREs for an offsubnet
 * destination. With this flag, even if no IRE_CACHETABLE or IRE_INTERFACE
 * is found to help resolving IRE_OFFSUBNET in lookup routines, the
 * IRE_OFFSUBNET sire, if any, is returned to the caller.
 */
#define	MATCH_IRE_ILL_GROUP	0x0800	/* Match IRE on ill or the ill_group. */
#define	MATCH_IRE_ILL		0x1000	/* Match IRE on the ill only */

#define	MATCH_IRE_PARENT	0x2000	/* Match parent ire, if any, */
					/* even if ire is not matched. */
#define	MATCH_IRE_ZONEONLY	0x4000	/* Match IREs in specified zone, ie */
					/* don't match IRE_LOCALs from other */
					/* zones or shared IREs */
#define	MATCH_IRE_MARK_PRIVATE_ADDR	0x8000	/* Match IRE ire_marks with */
						/* IRE_MARK_PRIVATE_ADDR. */
#define	MATCH_IRE_SECATTR	0x10000	/* Match gateway security attributes */
#define	MATCH_IRE_COMPLETE	0x20000	/* ire_ftable_lookup() can return */
					/* IRE_CACHE entry only if it is  */
					/* ND_REACHABLE			  */

/*
 * Any ire to nce association is long term, and
 * the refhold and refrele may be done by different
 * threads. So all cases of making or breaking ire to
 * nce association should all effectively use the NOTR variants.
 * To understand the *effectively* part read on.
 *
 * ndp_lookup() and ndp_add_v4()/ndp_add_v6() implicitly do
 * NCE_REFHOLD. So wherever we make ire to nce association after
 * calling these functions, we effectively want to end up with
 * NCE_REFHOLD_NOTR. We call this macro to achieve this effect. This
 * macro changes a NCE_REFHOLD to a NCE_REFHOLD_NOTR. The macro's
 * NCE_REFRELE cancels off ndp_lookup[ndp_add]'s implicit NCE_REFHOLD,
 * and what you are left with is a NCE_REFHOLD_NOTR
 */
#define	NCE_REFHOLD_TO_REFHOLD_NOTR(nce) {	\
	NCE_REFHOLD_NOTR(nce);			\
	NCE_REFRELE(nce);			\
}

/*
 * find the next ire_t entry in the ire_next chain starting at ire
 * that is not CONDEMNED.  ire is set to NULL if we reach the end of the list.
 * Caller must hold the ire_bucket lock.
 */

#define	IRE_FIND_NEXT_ORIGIN(ire) {					\
	while ((ire) != NULL && ((ire)->ire_marks & IRE_MARK_CONDEMNED))\
		(ire) = (ire)->ire_next;				\
}


/* Structure for ire_cache_count() */
typedef struct {
	int	icc_total;	/* Total number of IRE_CACHE */
	int	icc_unused;	/* # off/no PMTU unused since last reclaim */
	int	icc_offlink;	/* # offlink without PMTU information */
	int	icc_pmtu;	/* # offlink with PMTU information */
	int	icc_onlink;	/* # onlink */
} ire_cache_count_t;

/*
 * Structure for ire_cache_reclaim(). Each field is a fraction i.e. 1 meaning
 * reclaim all, N meaning reclaim 1/Nth of all entries, 0 meaning reclaim none.
 *
 * The comment below (and for other netstack_t references) refers
 * to the fact that we only do netstack_hold in particular cases,
 * such as the references from open streams (ill_t and conn_t's
 * pointers). Internally within IP we rely on IP's ability to cleanup e.g.
 * ire_t's when an ill goes away.
 */
typedef struct {
	int	icr_unused;	/* Fraction for unused since last reclaim */
	int	icr_offlink;	/* Fraction for offlink without PMTU info */
	int	icr_pmtu;	/* Fraction for offlink with PMTU info */
	int	icr_onlink;	/* Fraction for onlink */
	ip_stack_t *icr_ipst;	/* Does not have a netstack_hold */
} ire_cache_reclaim_t;

/*
 * We use atomics so that we get an accurate accounting on the ires.
 * Otherwise we can't determine leaks correctly.
 */
#define	BUMP_IRE_STATS(ire_stats, x) atomic_add_64(&(ire_stats).x, 1)

#ifdef _KERNEL
/*
 * Structure for passing args for the IRE cache lookup functions.
 */
typedef struct ire_ctable_args_s {
	void			*ict_addr;
	void			*ict_gateway;
	int			ict_type;
	const ipif_t		*ict_ipif;
	zoneid_t		ict_zoneid;
	const ts_label_t	*ict_tsl;
	int			ict_flags;
	ip_stack_t		*ict_ipst;
	queue_t			*ict_wq;
} ire_ctable_args_t;

struct ts_label_s;
struct nce_s;

extern	ipaddr_t	ip_plen_to_mask(uint_t);
extern	in6_addr_t	*ip_plen_to_mask_v6(uint_t, in6_addr_t *);

extern	int	ip_ire_advise(queue_t *, mblk_t *, cred_t *);
extern	int	ip_ire_delete(queue_t *, mblk_t *, cred_t *);
extern	boolean_t ip_ire_clookup_and_delete(ipaddr_t, ipif_t *, ip_stack_t *);
extern	void	ip_ire_clookup_and_delete_v6(const in6_addr_t *,
    ip_stack_t *);

extern	void	ip_ire_req(queue_t *, mblk_t *);

extern	int	ip_mask_to_plen(ipaddr_t);
extern	int	ip_mask_to_plen_v6(const in6_addr_t *);

extern	ire_t	*ipif_to_ire(const ipif_t *);
extern	ire_t	*ipif_to_ire_v6(const ipif_t *);

extern	int	ire_add(ire_t **, queue_t *, mblk_t *, ipsq_func_t, boolean_t);
extern	void	ire_add_then_send(queue_t *, ire_t *, mblk_t *);
extern	int	ire_add_v6(ire_t **, queue_t *, mblk_t *, ipsq_func_t);
extern	int	ire_atomic_start(irb_t *irb_ptr, ire_t *ire, queue_t *q,
    mblk_t *mp, ipsq_func_t func);
extern	void	ire_atomic_end(irb_t *irb_ptr, ire_t *ire);

extern	void	ire_cache_count(ire_t *, char *);
extern	ire_t	*ire_cache_lookup(ipaddr_t, zoneid_t,
    const struct ts_label_s *, ip_stack_t *);
extern	ire_t	*ire_cache_lookup_simple(ipaddr_t, ip_stack_t *);
extern	ire_t	*ire_cache_lookup_v6(const in6_addr_t *, zoneid_t,
    const struct ts_label_s *, ip_stack_t *);
extern	void	ire_cache_reclaim(ire_t *, char *);

extern	ire_t	*ire_create_mp(uchar_t *, uchar_t *, uchar_t *, uchar_t *,
    uint_t, struct nce_s *, queue_t *, queue_t *, ushort_t, ipif_t *, ipaddr_t,
    uint32_t, uint32_t, uint32_t, const iulp_t *, tsol_gc_t *, tsol_gcgrp_t *,
    ip_stack_t *);
extern	ire_t	*ire_create(uchar_t *, uchar_t *, uchar_t *, uchar_t *,
    uint_t *, struct nce_s *, queue_t *, queue_t *, ushort_t, ipif_t *,
    ipaddr_t, uint32_t, uint32_t, uint32_t, const iulp_t *, tsol_gc_t *,
    tsol_gcgrp_t *, ip_stack_t *);

extern	ire_t	**ire_check_and_create_bcast(ipif_t *, ipaddr_t,
    ire_t **, int);
extern	ire_t	**ire_create_bcast(ipif_t *, ipaddr_t, ire_t **);
extern	ire_t	*ire_init(ire_t *, uchar_t *, uchar_t *, uchar_t *, uchar_t *,
    uint_t *, struct nce_s *, queue_t *, queue_t *, ushort_t, ipif_t *,
    ipaddr_t, uint32_t, uint32_t, uint32_t, const iulp_t *, tsol_gc_t *,
    tsol_gcgrp_t *, ip_stack_t *);

extern	boolean_t ire_init_common(ire_t *, uint_t *, struct nce_s *, queue_t *,
    queue_t *, ushort_t, ipif_t *, uint32_t, uint32_t, uint32_t, uchar_t,
    const iulp_t *, tsol_gc_t *, tsol_gcgrp_t *, ip_stack_t *);

extern	ire_t	*ire_create_v6(const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, uint_t *, struct nce_s *, queue_t *,
    queue_t *, ushort_t, ipif_t *,
    const in6_addr_t *, uint32_t, uint32_t, uint_t, const iulp_t *,
    tsol_gc_t *, tsol_gcgrp_t *, ip_stack_t *);

extern	ire_t	*ire_create_mp_v6(const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, struct nce_s *, queue_t *,
    queue_t *, ushort_t, ipif_t *,
    const in6_addr_t *, uint32_t, uint32_t, uint_t, const iulp_t *,
    tsol_gc_t *, tsol_gcgrp_t *, ip_stack_t *);


extern	void	ire_clookup_delete_cache_gw(ipaddr_t, zoneid_t,
    ip_stack_t *);
extern	void	ire_clookup_delete_cache_gw_v6(const in6_addr_t *, zoneid_t,
    ip_stack_t *);

extern	ire_t	*ire_ctable_lookup(ipaddr_t, ipaddr_t, int, const ipif_t *,
    zoneid_t, const struct ts_label_s *, int, ip_stack_t *);

extern	ire_t	*ire_ctable_lookup_v6(const in6_addr_t *, const in6_addr_t *,
    int, const ipif_t *, zoneid_t, const struct ts_label_s *, int,
    ip_stack_t *);

extern	void	ire_delete(ire_t *);
extern	void	ire_delete_cache_gw(ire_t *, char *);
extern	void	ire_delete_cache_gw_v6(ire_t *, char *);
extern	void	ire_delete_cache_v6(ire_t *, char *);
extern	void	ire_delete_v6(ire_t *);

extern	void	ire_expire(ire_t *, char *);

extern	void	ire_flush_cache_v4(ire_t *, int);
extern	void	ire_flush_cache_v6(ire_t *, int);

extern	ire_t	*ire_ftable_lookup_v6(const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, int, const ipif_t *, ire_t **, zoneid_t,
    uint32_t, const struct ts_label_s *, int, ip_stack_t *);

extern	ire_t	*ire_ihandle_lookup_onlink(ire_t *);
extern	ire_t	*ire_ihandle_lookup_offlink(ire_t *, ire_t *);
extern	ire_t	*ire_ihandle_lookup_offlink_v6(ire_t *, ire_t *);

extern	boolean_t	ire_local_same_ill_group(ire_t *, ire_t *);
extern	boolean_t	ire_local_ok_across_zones(ire_t *, zoneid_t, void *,
    const struct ts_label_s *, ip_stack_t *);

extern	ire_t 	*ire_lookup_local(zoneid_t, ip_stack_t *);
extern	ire_t 	*ire_lookup_local_v6(zoneid_t, ip_stack_t *);

extern  ire_t	*ire_lookup_multi(ipaddr_t, zoneid_t, ip_stack_t *);
extern  ire_t	*ire_lookup_multi_v6(const in6_addr_t *, zoneid_t,
    ip_stack_t *);

extern	void	ire_refrele(ire_t *);
extern	void	ire_refrele_notr(ire_t *);
extern	ire_t	*ire_route_lookup(ipaddr_t, ipaddr_t, ipaddr_t, int,
    const ipif_t *, ire_t **, zoneid_t, const struct ts_label_s *, int,
    ip_stack_t *);

extern	ire_t	*ire_route_lookup_v6(const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, int, const ipif_t *, ire_t **, zoneid_t,
    const struct ts_label_s *, int, ip_stack_t *);

extern ill_t	*ire_to_ill(const ire_t *);

extern	void	ire_walk(pfv_t, void *, ip_stack_t *);
extern	void	ire_walk_ill(uint_t, uint_t, pfv_t, void *, ill_t *);
extern	void	ire_walk_ill_v4(uint_t, uint_t, pfv_t, void *, ill_t *);
extern	void	ire_walk_ill_v6(uint_t, uint_t, pfv_t, void *, ill_t *);
extern	void	ire_walk_v4(pfv_t, void *, zoneid_t, ip_stack_t *);
extern  void	ire_walk_ill_tables(uint_t match_flags, uint_t ire_type,
    pfv_t func, void *arg, size_t ftbl_sz, size_t htbl_sz,
    irb_t **ipftbl, size_t ctbl_sz, irb_t *ipctbl, ill_t *ill,
    zoneid_t zoneid, ip_stack_t *);
extern	void	ire_walk_v6(pfv_t, void *, zoneid_t, ip_stack_t *);

extern boolean_t	ire_multirt_lookup(ire_t **, ire_t **, uint32_t,
    const struct ts_label_s *, ip_stack_t *);
extern boolean_t	ire_multirt_need_resolve(ipaddr_t,
    const struct ts_label_s *, ip_stack_t *);
extern boolean_t	ire_multirt_lookup_v6(ire_t **, ire_t **, uint32_t,
    const struct ts_label_s *, ip_stack_t *);
extern boolean_t	ire_multirt_need_resolve_v6(const in6_addr_t *,
    const struct ts_label_s *, ip_stack_t *);

extern ire_t	*ipif_lookup_multi_ire(ipif_t *, ipaddr_t);
extern ire_t	*ipif_lookup_multi_ire_v6(ipif_t *, const in6_addr_t *);

extern ire_t	*ire_get_next_bcast_ire(ire_t *, ire_t *);
extern ire_t	*ire_get_next_default_ire(ire_t *, ire_t *);

extern  void	ire_arpresolve(ire_t *,  ill_t *);
extern  void	ire_freemblk(ire_t *);
extern boolean_t	ire_match_args(ire_t *, ipaddr_t, ipaddr_t, ipaddr_t,
    int, const ipif_t *, zoneid_t, uint32_t, const struct ts_label_s *, int,
    queue_t *);
extern  int	ire_nce_init(ire_t *, struct nce_s *);
extern  boolean_t	ire_walk_ill_match(uint_t, uint_t, ire_t *, ill_t *,
    zoneid_t, ip_stack_t *);
extern	ire_t	*ire_arpresolve_lookup(ipaddr_t, ipaddr_t, ipif_t *, zoneid_t,
    ip_stack_t *, queue_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_IRE_H */
