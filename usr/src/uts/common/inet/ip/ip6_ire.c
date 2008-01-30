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
/*
 * Copyright (c) 1990 Mentat Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains routines that manipulate Internet Routing Entries (IREs).
 */
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_ndp.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ipclassifier.h>
#include <inet/nd.h>
#include <sys/kmem.h>
#include <sys/zone.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

static	ire_t	ire_null;

static ire_t	*ire_ihandle_lookup_onlink_v6(ire_t *cire);
static boolean_t ire_match_args_v6(ire_t *ire, const in6_addr_t *addr,
    const in6_addr_t *mask, const in6_addr_t *gateway, int type,
    const ipif_t *ipif, zoneid_t zoneid, uint32_t ihandle,
    const ts_label_t *tsl, int match_flags);
static	ire_t	*ire_init_v6(ire_t *, const in6_addr_t *, const in6_addr_t *,
    const in6_addr_t *, const in6_addr_t *, uint_t *, queue_t *, queue_t *,
    ushort_t, ipif_t *, const in6_addr_t *, uint32_t, uint32_t, uint_t,
    const iulp_t *, tsol_gc_t *, tsol_gcgrp_t *, ip_stack_t *);


/*
 * Initialize the ire that is specific to IPv6 part and call
 * ire_init_common to finish it.
 */
static ire_t *
ire_init_v6(ire_t *ire, const in6_addr_t *v6addr, const in6_addr_t *v6mask,
    const in6_addr_t *v6src_addr, const in6_addr_t *v6gateway,
    uint_t *max_fragp, queue_t *rfq, queue_t *stq, ushort_t type,
    ipif_t *ipif, const in6_addr_t *v6cmask, uint32_t phandle,
    uint32_t ihandle, uint_t flags, const iulp_t *ulp_info, tsol_gc_t *gc,
    tsol_gcgrp_t *gcgrp, ip_stack_t *ipst)
{

	/*
	 * Reject IRE security attribute creation/initialization
	 * if system is not running in Trusted mode.
	 */
	if ((gc != NULL || gcgrp != NULL) && !is_system_labeled())
		return (NULL);


	BUMP_IRE_STATS(ipst->ips_ire_stats_v6, ire_stats_alloced);
	ire->ire_addr_v6 = *v6addr;

	if (v6src_addr != NULL)
		ire->ire_src_addr_v6 = *v6src_addr;
	if (v6mask != NULL) {
		ire->ire_mask_v6 = *v6mask;
		ire->ire_masklen = ip_mask_to_plen_v6(&ire->ire_mask_v6);
	}
	if (v6gateway != NULL)
		ire->ire_gateway_addr_v6 = *v6gateway;

	if (type == IRE_CACHE && v6cmask != NULL)
		ire->ire_cmask_v6 = *v6cmask;

	/*
	 * Multirouted packets need to have a fragment header added so that
	 * the receiver is able to discard duplicates according to their
	 * fragment identifier.
	 */
	if (type == IRE_CACHE && (flags & RTF_MULTIRT)) {
		ire->ire_frag_flag = IPH_FRAG_HDR;
	}

	/* ire_init_common will free the mblks upon encountering any failure */
	if (!ire_init_common(ire, max_fragp, NULL, rfq, stq, type, ipif,
	    phandle, ihandle, flags, IPV6_VERSION, ulp_info, gc, gcgrp, ipst))
		return (NULL);

	return (ire);
}

/*
 * Similar to ire_create_v6 except that it is called only when
 * we want to allocate ire as an mblk e.g. we have a external
 * resolver. Do we need this in IPv6 ?
 *
 * IPv6 initializes the ire_nce in ire_add_v6, which expects to
 * find the ire_nce to be null when it is called. So, although
 * we have a src_nce parameter (in the interest of matching up with
 * the argument list of the v4 version), we ignore the src_nce
 * argument here.
 */
/* ARGSUSED */
ire_t *
ire_create_mp_v6(const in6_addr_t *v6addr, const in6_addr_t *v6mask,
    const in6_addr_t *v6src_addr, const in6_addr_t *v6gateway,
    nce_t *src_nce, queue_t *rfq, queue_t *stq, ushort_t type,
    ipif_t *ipif, const in6_addr_t *v6cmask,
    uint32_t phandle, uint32_t ihandle, uint_t flags, const iulp_t *ulp_info,
    tsol_gc_t *gc, tsol_gcgrp_t *gcgrp, ip_stack_t *ipst)
{
	ire_t	*ire;
	ire_t	*ret_ire;
	mblk_t	*mp;

	ASSERT(!IN6_IS_ADDR_V4MAPPED(v6addr));

	/* Allocate the new IRE. */
	mp = allocb(sizeof (ire_t), BPRI_MED);
	if (mp == NULL) {
		ip1dbg(("ire_create_mp_v6: alloc failed\n"));
		return (NULL);
	}

	ire = (ire_t *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)&ire[1];

	/* Start clean. */
	*ire = ire_null;
	ire->ire_mp = mp;
	mp->b_datap->db_type = IRE_DB_TYPE;

	ret_ire = ire_init_v6(ire, v6addr, v6mask, v6src_addr, v6gateway,
	    NULL, rfq, stq, type, ipif, v6cmask, phandle,
	    ihandle, flags, ulp_info, gc, gcgrp, ipst);

	if (ret_ire == NULL) {
		freeb(ire->ire_mp);
		return (NULL);
	}
	return (ire);
}

/*
 * ire_create_v6 is called to allocate and initialize a new IRE.
 *
 * NOTE : This is called as writer sometimes though not required
 * by this function.
 *
 * See comments above ire_create_mp_v6() for the rationale behind the
 * unused src_nce argument.
 */
/* ARGSUSED */
ire_t *
ire_create_v6(const in6_addr_t *v6addr, const in6_addr_t *v6mask,
    const in6_addr_t *v6src_addr, const in6_addr_t *v6gateway,
    uint_t *max_fragp, nce_t *src_nce, queue_t *rfq, queue_t *stq,
    ushort_t type, ipif_t *ipif, const in6_addr_t *v6cmask,
    uint32_t phandle, uint32_t ihandle, uint_t flags, const iulp_t *ulp_info,
    tsol_gc_t *gc, tsol_gcgrp_t *gcgrp, ip_stack_t *ipst)
{
	ire_t	*ire;
	ire_t	*ret_ire;

	ASSERT(!IN6_IS_ADDR_V4MAPPED(v6addr));

	ire = kmem_cache_alloc(ire_cache, KM_NOSLEEP);
	if (ire == NULL) {
		ip1dbg(("ire_create_v6: alloc failed\n"));
		return (NULL);
	}
	*ire = ire_null;

	ret_ire = ire_init_v6(ire, v6addr, v6mask, v6src_addr, v6gateway,
	    max_fragp, rfq, stq, type, ipif, v6cmask, phandle,
	    ihandle, flags, ulp_info, gc, gcgrp, ipst);

	if (ret_ire == NULL) {
		kmem_cache_free(ire_cache, ire);
		return (NULL);
	}
	ASSERT(ret_ire == ire);
	return (ire);
}

/*
 * Find an IRE_INTERFACE for the multicast group.
 * Allows different routes for multicast addresses
 * in the unicast routing table (akin to FF::0/8 but could be more specific)
 * which point at different interfaces. This is used when IPV6_MULTICAST_IF
 * isn't specified (when sending) and when IPV6_JOIN_GROUP doesn't
 * specify the interface to join on.
 *
 * Supports link-local addresses by following the ipif/ill when recursing.
 */
ire_t *
ire_lookup_multi_v6(const in6_addr_t *group, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t	*ire;
	ipif_t	*ipif = NULL;
	int	match_flags = MATCH_IRE_TYPE;
	in6_addr_t gw_addr_v6;

	ire = ire_ftable_lookup_v6(group, 0, 0, 0, NULL, NULL,
	    zoneid, 0, NULL, MATCH_IRE_DEFAULT, ipst);

	/* We search a resolvable ire in case of multirouting. */
	if ((ire != NULL) && (ire->ire_flags & RTF_MULTIRT)) {
		ire_t *cire = NULL;
		/*
		 * If the route is not resolvable, the looked up ire
		 * may be changed here. In that case, ire_multirt_lookup()
		 * IRE_REFRELE the original ire and change it.
		 */
		(void) ire_multirt_lookup_v6(&cire, &ire, MULTIRT_CACHEGW,
		    NULL, ipst);
		if (cire != NULL)
			ire_refrele(cire);
	}
	if (ire == NULL)
		return (NULL);
	/*
	 * Make sure we follow ire_ipif.
	 *
	 * We need to determine the interface route through
	 * which the gateway will be reached. We don't really
	 * care which interface is picked if the interface is
	 * part of a group.
	 */
	if (ire->ire_ipif != NULL) {
		ipif = ire->ire_ipif;
		match_flags |= MATCH_IRE_ILL_GROUP;
	}

	switch (ire->ire_type) {
	case IRE_DEFAULT:
	case IRE_PREFIX:
	case IRE_HOST:
		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
		ire_refrele(ire);
		ire = ire_ftable_lookup_v6(&gw_addr_v6, 0, 0,
		    IRE_INTERFACE, ipif, NULL, zoneid, 0,
		    NULL, match_flags, ipst);
		return (ire);
	case IRE_IF_NORESOLVER:
	case IRE_IF_RESOLVER:
		return (ire);
	default:
		ire_refrele(ire);
		return (NULL);
	}
}

/*
 * Return any local address.  We use this to target ourselves
 * when the src address was specified as 'default'.
 * Preference for IRE_LOCAL entries.
 */
ire_t *
ire_lookup_local_v6(zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t	*ire;
	irb_t	*irb;
	ire_t	*maybe = NULL;
	int i;

	for (i = 0; i < ipst->ips_ip6_cache_table_size;  i++) {
		irb = &ipst->ips_ip_cache_table_v6[i];
		if (irb->irb_ire == NULL)
			continue;
		rw_enter(&irb->irb_lock, RW_READER);
		for (ire = irb->irb_ire; ire; ire = ire->ire_next) {
			if ((ire->ire_marks & IRE_MARK_CONDEMNED) ||
			    ire->ire_zoneid != zoneid &&
			    ire->ire_zoneid != ALL_ZONES)
				continue;
			switch (ire->ire_type) {
			case IRE_LOOPBACK:
				if (maybe == NULL) {
					IRE_REFHOLD(ire);
					maybe = ire;
				}
				break;
			case IRE_LOCAL:
				if (maybe != NULL) {
					ire_refrele(maybe);
				}
				IRE_REFHOLD(ire);
				rw_exit(&irb->irb_lock);
				return (ire);
			}
		}
		rw_exit(&irb->irb_lock);
	}
	return (maybe);
}

/*
 * This function takes a mask and returns number of bits set in the
 * mask (the represented prefix length).  Assumes a contiguous mask.
 */
int
ip_mask_to_plen_v6(const in6_addr_t *v6mask)
{
	int		bits;
	int		plen = IPV6_ABITS;
	int		i;

	for (i = 3; i >= 0; i--) {
		if (v6mask->s6_addr32[i] == 0) {
			plen -= 32;
			continue;
		}
		bits = ffs(ntohl(v6mask->s6_addr32[i])) - 1;
		if (bits == 0)
			break;
		plen -= bits;
	}

	return (plen);
}

/*
 * Convert a prefix length to the mask for that prefix.
 * Returns the argument bitmask.
 */
in6_addr_t *
ip_plen_to_mask_v6(uint_t plen, in6_addr_t *bitmask)
{
	uint32_t *ptr;

	if (plen < 0 || plen > IPV6_ABITS)
		return (NULL);
	*bitmask = ipv6_all_zeros;

	ptr = (uint32_t *)bitmask;
	while (plen > 32) {
		*ptr++ = 0xffffffffU;
		plen -= 32;
	}
	*ptr = htonl(0xffffffffU << (32 - plen));
	return (bitmask);
}

/*
 * Add a fully initialized IRE to an appropriate
 * table based on ire_type.
 *
 * The forward table contains IRE_PREFIX/IRE_HOST/IRE_HOST and
 * IRE_IF_RESOLVER/IRE_IF_NORESOLVER and IRE_DEFAULT.
 *
 * The cache table contains IRE_BROADCAST/IRE_LOCAL/IRE_LOOPBACK
 * and IRE_CACHE.
 *
 * NOTE : This function is called as writer though not required
 * by this function.
 */
int
ire_add_v6(ire_t **ire_p, queue_t *q, mblk_t *mp, ipsq_func_t func)
{
	ire_t	*ire1;
	int	mask_table_index;
	irb_t	*irb_ptr;
	ire_t	**irep;
	int	flags;
	ire_t	*pire = NULL;
	ill_t	*stq_ill;
	boolean_t	ndp_g_lock_held = B_FALSE;
	ire_t	*ire = *ire_p;
	int	error;
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(ire->ire_ipversion == IPV6_VERSION);
	ASSERT(ire->ire_mp == NULL); /* Calls should go through ire_add */
	ASSERT(ire->ire_nce == NULL);

	/* Find the appropriate list head. */
	switch (ire->ire_type) {
	case IRE_HOST:
		ire->ire_mask_v6 = ipv6_all_ones;
		ire->ire_masklen = IPV6_ABITS;
		if ((ire->ire_flags & RTF_SETSRC) == 0)
			ire->ire_src_addr_v6 = ipv6_all_zeros;
		break;
	case IRE_CACHE:
	case IRE_LOCAL:
	case IRE_LOOPBACK:
		ire->ire_mask_v6 = ipv6_all_ones;
		ire->ire_masklen = IPV6_ABITS;
		break;
	case IRE_PREFIX:
		if ((ire->ire_flags & RTF_SETSRC) == 0)
			ire->ire_src_addr_v6 = ipv6_all_zeros;
		break;
	case IRE_DEFAULT:
		if ((ire->ire_flags & RTF_SETSRC) == 0)
			ire->ire_src_addr_v6 = ipv6_all_zeros;
		break;
	case IRE_IF_RESOLVER:
	case IRE_IF_NORESOLVER:
		break;
	default:
		printf("ire_add_v6: ire %p has unrecognized IRE type (%d)\n",
		    (void *)ire, ire->ire_type);
		ire_delete(ire);
		*ire_p = NULL;
		return (EINVAL);
	}

	/* Make sure the address is properly masked. */
	V6_MASK_COPY(ire->ire_addr_v6, ire->ire_mask_v6, ire->ire_addr_v6);

	if ((ire->ire_type & IRE_CACHETABLE) == 0) {
		/* IRE goes into Forward Table */
		mask_table_index = ip_mask_to_plen_v6(&ire->ire_mask_v6);
		if ((ipst->ips_ip_forwarding_table_v6[mask_table_index]) ==
		    NULL) {
			irb_t *ptr;
			int i;

			ptr = (irb_t *)mi_zalloc((
			    ipst->ips_ip6_ftable_hash_size * sizeof (irb_t)));
			if (ptr == NULL) {
				ire_delete(ire);
				*ire_p = NULL;
				return (ENOMEM);
			}
			for (i = 0; i < ipst->ips_ip6_ftable_hash_size; i++) {
				rw_init(&ptr[i].irb_lock, NULL,
				    RW_DEFAULT, NULL);
			}
			mutex_enter(&ipst->ips_ire_ft_init_lock);
			if (ipst->ips_ip_forwarding_table_v6[
			    mask_table_index] == NULL) {
				ipst->ips_ip_forwarding_table_v6[
				    mask_table_index] = ptr;
				mutex_exit(&ipst->ips_ire_ft_init_lock);
			} else {
				/*
				 * Some other thread won the race in
				 * initializing the forwarding table at the
				 * same index.
				 */
				mutex_exit(&ipst->ips_ire_ft_init_lock);
				for (i = 0; i < ipst->ips_ip6_ftable_hash_size;
				    i++) {
					rw_destroy(&ptr[i].irb_lock);
				}
				mi_free(ptr);
			}
		}
		irb_ptr = &(ipst->ips_ip_forwarding_table_v6[mask_table_index][
		    IRE_ADDR_MASK_HASH_V6(ire->ire_addr_v6, ire->ire_mask_v6,
		    ipst->ips_ip6_ftable_hash_size)]);
	} else {
		irb_ptr = &(ipst->ips_ip_cache_table_v6[IRE_ADDR_HASH_V6(
		    ire->ire_addr_v6, ipst->ips_ip6_cache_table_size)]);
	}
	/*
	 * For xresolv interfaces (v6 interfaces with an external
	 * address resolver), ip_newroute_v6/ip_newroute_ipif_v6
	 * are unable to prevent the deletion of the interface route
	 * while adding an IRE_CACHE for an on-link destination
	 * in the IRE_IF_RESOLVER case, since the ire has to go to
	 * the external resolver and return. We can't do a REFHOLD on the
	 * associated interface ire for fear of the message being freed
	 * if the external resolver can't resolve the address.
	 * Here we look up the interface ire in the forwarding table
	 * and make sure that the interface route has not been deleted.
	 */
	if (ire->ire_type == IRE_CACHE &&
	    IN6_IS_ADDR_UNSPECIFIED(&ire->ire_gateway_addr_v6) &&
	    (((ill_t *)ire->ire_stq->q_ptr)->ill_net_type == IRE_IF_RESOLVER) &&
	    (((ill_t *)ire->ire_stq->q_ptr)->ill_flags & ILLF_XRESOLV)) {

		pire = ire_ihandle_lookup_onlink_v6(ire);
		if (pire == NULL) {
			ire_delete(ire);
			*ire_p = NULL;
			return (EINVAL);
		}
		/* Prevent pire from getting deleted */
		IRB_REFHOLD(pire->ire_bucket);
		/* Has it been removed already? */
		if (pire->ire_marks & IRE_MARK_CONDEMNED) {
			IRB_REFRELE(pire->ire_bucket);
			ire_refrele(pire);
			ire_delete(ire);
			*ire_p = NULL;
			return (EINVAL);
		}
	}

	flags = (MATCH_IRE_MASK | MATCH_IRE_TYPE | MATCH_IRE_GW);
	/*
	 * For IRE_CACHES, MATCH_IRE_IPIF is not enough to check
	 * for duplicates because :
	 *
	 * 1) ire_ipif->ipif_ill and ire_stq->q_ptr could be
	 *    pointing at different ills. A real duplicate is
	 *    a match on both ire_ipif and ire_stq.
	 *
	 * 2) We could have multiple packets trying to create
	 *    an IRE_CACHE for the same ill.
	 *
	 * Moreover, IPIF_NOFAILOVER and IPV6_BOUND_PIF endpoints wants
	 * to go out on a particular ill. Rather than looking at the
	 * packet, we depend on the above for MATCH_IRE_ILL here.
	 *
	 * Unlike IPv4, MATCH_IRE_IPIF is needed here as we could have
	 * multiple IRE_CACHES for an ill for the same destination
	 * with various scoped addresses i.e represented by ipifs.
	 *
	 * MATCH_IRE_ILL is done implicitly below for IRE_CACHES.
	 */
	if (ire->ire_ipif != NULL)
		flags |= MATCH_IRE_IPIF;
	/*
	 * If we are creating hidden ires, make sure we search on
	 * this ill (MATCH_IRE_ILL) and a hidden ire, while we are
	 * searching for duplicates below. Otherwise we could
	 * potentially find an IRE on some other interface
	 * and it may not be a IRE marked with IRE_MARK_HIDDEN. We
	 * shouldn't do this as this will lead to an infinite loop as
	 * eventually we need an hidden ire for this packet to go
	 * out. MATCH_IRE_ILL is already marked above.
	 */
	if (ire->ire_marks & IRE_MARK_HIDDEN) {
		ASSERT(ire->ire_type == IRE_CACHE);
		flags |= MATCH_IRE_MARK_HIDDEN;
	}

	/*
	 * Start the atomic add of the ire. Grab the ill locks,
	 * ill_g_usesrc_lock and the bucket lock. Check for condemned.
	 * To avoid lock order problems, get the ndp6.ndp_g_lock now itself.
	 */
	if (ire->ire_type == IRE_CACHE) {
		mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
		ndp_g_lock_held = B_TRUE;
	}

	/*
	 * If ipif or ill is changing ire_atomic_start() may queue the
	 * request and return EINPROGRESS.
	 */

	error = ire_atomic_start(irb_ptr, ire, q, mp, func);
	if (error != 0) {
		if (ndp_g_lock_held)
			mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		/*
		 * We don't know whether it is a valid ipif or not.
		 * So, set it to NULL. This assumes that the ire has not added
		 * a reference to the ipif.
		 */
		ire->ire_ipif = NULL;
		ire_delete(ire);
		if (pire != NULL) {
			IRB_REFRELE(pire->ire_bucket);
			ire_refrele(pire);
		}
		*ire_p = NULL;
		return (error);
	}
	/*
	 * To avoid creating ires having stale values for the ire_max_frag
	 * we get the latest value atomically here. For more details
	 * see the block comment in ip_sioctl_mtu and in DL_NOTE_SDU_CHANGE
	 * in ip_rput_dlpi_writer
	 */
	if (ire->ire_max_fragp == NULL) {
		if (IN6_IS_ADDR_MULTICAST(&ire->ire_addr_v6))
			ire->ire_max_frag = ire->ire_ipif->ipif_mtu;
		else
			ire->ire_max_frag = pire->ire_max_frag;
	} else {
		uint_t  max_frag;

		max_frag = *ire->ire_max_fragp;
		ire->ire_max_fragp = NULL;
		ire->ire_max_frag = max_frag;
	}

	/*
	 * Atomically check for duplicate and insert in the table.
	 */
	for (ire1 = irb_ptr->irb_ire; ire1 != NULL; ire1 = ire1->ire_next) {
		if (ire1->ire_marks & IRE_MARK_CONDEMNED)
			continue;

		if (ire->ire_type == IRE_CACHE) {
			/*
			 * We do MATCH_IRE_ILL implicitly here for IRE_CACHES.
			 * As ire_ipif and ire_stq could point to two
			 * different ills, we can't pass just ire_ipif to
			 * ire_match_args and get a match on both ills.
			 * This is just needed for duplicate checks here and
			 * so we don't add an extra argument to
			 * ire_match_args for this. Do it locally.
			 *
			 * NOTE : Currently there is no part of the code
			 * that asks for both MATH_IRE_IPIF and MATCH_IRE_ILL
			 * match for IRE_CACHEs. Thus we don't want to
			 * extend the arguments to ire_match_args_v6.
			 */
			if (ire1->ire_stq != ire->ire_stq)
				continue;
			/*
			 * Multiroute IRE_CACHEs for a given destination can
			 * have the same ire_ipif, typically if their source
			 * address is forced using RTF_SETSRC, and the same
			 * send-to queue. We differentiate them using the parent
			 * handle.
			 */
			if ((ire1->ire_flags & RTF_MULTIRT) &&
			    (ire->ire_flags & RTF_MULTIRT) &&
			    (ire1->ire_phandle != ire->ire_phandle))
				continue;
		}
		if (ire1->ire_zoneid != ire->ire_zoneid)
			continue;
		if (ire_match_args_v6(ire1, &ire->ire_addr_v6,
		    &ire->ire_mask_v6, &ire->ire_gateway_addr_v6,
		    ire->ire_type, ire->ire_ipif, ire->ire_zoneid, 0, NULL,
		    flags)) {
			/*
			 * Return the old ire after doing a REFHOLD.
			 * As most of the callers continue to use the IRE
			 * after adding, we return a held ire. This will
			 * avoid a lookup in the caller again. If the callers
			 * don't want to use it, they need to do a REFRELE.
			 */
			ip1dbg(("found dup ire existing %p new %p",
			    (void *)ire1, (void *)ire));
			IRE_REFHOLD(ire1);
			if (ndp_g_lock_held)
				mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
			ire_atomic_end(irb_ptr, ire);
			ire_delete(ire);
			if (pire != NULL) {
				/*
				 * Assert that it is
				 * not yet removed from the list.
				 */
				ASSERT(pire->ire_ptpn != NULL);
				IRB_REFRELE(pire->ire_bucket);
				ire_refrele(pire);
			}
			*ire_p = ire1;
			return (0);
		}
	}
	if (ire->ire_type == IRE_CACHE) {
		in6_addr_t gw_addr_v6;
		ill_t	*ill = ire_to_ill(ire);
		char	buf[INET6_ADDRSTRLEN];
		nce_t	*nce;

		/*
		 * All IRE_CACHE types must have a nce.  If this is
		 * not the case the entry will not be added. We need
		 * to make sure that if somebody deletes the nce
		 * after we looked up, they will find this ire and
		 * delete the ire. To delete this ire one needs the
		 * bucket lock which we are still holding here. So,
		 * even if the nce gets deleted after we looked up,
		 * this ire  will get deleted.
		 *
		 * NOTE : Don't need the ire_lock for accessing
		 * ire_gateway_addr_v6 as it is appearing first
		 * time on the list and rts_setgwr_v6 could not
		 * be changing this.
		 */
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		if (IN6_IS_ADDR_UNSPECIFIED(&gw_addr_v6)) {
			nce = ndp_lookup_v6(ill, &ire->ire_addr_v6, B_TRUE);
		} else {
			nce = ndp_lookup_v6(ill, &gw_addr_v6, B_TRUE);
		}
		if (nce == NULL)
			goto failed;

		/* Pair of refhold, refrele just to get the tracing right */
		NCE_REFHOLD_TO_REFHOLD_NOTR(nce);
		/*
		 * Atomically make sure that new IREs don't point
		 * to an NCE that is logically deleted (CONDEMNED).
		 * ndp_delete() first marks the NCE CONDEMNED.
		 * This ensures that the nce_refcnt won't increase
		 * due to new nce_lookups or due to addition of new IREs
		 * pointing to this NCE. Then ndp_delete() cleans up
		 * existing references. If we don't do it atomically here,
		 * ndp_delete() -> nce_ire_delete() will not be able to
		 * clean up the IRE list completely, and the nce_refcnt
		 * won't go down to zero.
		 */
		mutex_enter(&nce->nce_lock);
		if (ill->ill_flags & ILLF_XRESOLV) {
			/*
			 * If we used an external resolver, we may not
			 * have gone through neighbor discovery to get here.
			 * Must update the nce_state before the next check.
			 */
			if (nce->nce_state == ND_INCOMPLETE)
				nce->nce_state = ND_REACHABLE;
		}
		if (nce->nce_state == ND_INCOMPLETE ||
		    (nce->nce_flags & NCE_F_CONDEMNED) ||
		    (nce->nce_state == ND_UNREACHABLE)) {
failed:
			if (ndp_g_lock_held)
				mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
			if (nce != NULL)
				mutex_exit(&nce->nce_lock);
			ire_atomic_end(irb_ptr, ire);
			ip1dbg(("ire_add_v6: No nce for dst %s \n",
			    inet_ntop(AF_INET6, &ire->ire_addr_v6,
			    buf, sizeof (buf))));
			ire_delete(ire);
			if (pire != NULL) {
				/*
				 * Assert that it is
				 * not yet removed from the list.
				 */
				ASSERT(pire->ire_ptpn != NULL);
				IRB_REFRELE(pire->ire_bucket);
				ire_refrele(pire);
			}
			if (nce != NULL)
				NCE_REFRELE_NOTR(nce);
			*ire_p = NULL;
			return (EINVAL);
		} else {
			ire->ire_nce = nce;
		}
		mutex_exit(&nce->nce_lock);
	}
	/*
	 * Find the first entry that matches ire_addr - provides
	 * tail insertion. *irep will be null if no match.
	 */
	irep = (ire_t **)irb_ptr;
	while ((ire1 = *irep) != NULL &&
	    !IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6, &ire1->ire_addr_v6))
		irep = &ire1->ire_next;
	ASSERT(!(ire->ire_type & IRE_BROADCAST));

	if (*irep != NULL) {
		/*
		 * Find the last ire which matches ire_addr_v6.
		 * Needed to do tail insertion among entries with the same
		 * ire_addr_v6.
		 */
		while (IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6,
		    &ire1->ire_addr_v6)) {
			irep = &ire1->ire_next;
			ire1 = *irep;
			if (ire1 == NULL)
				break;
		}
	}

	if (ire->ire_type == IRE_DEFAULT) {
		/*
		 * We keep a count of default gateways which is used when
		 * assigning them as routes.
		 */
		ipst->ips_ipv6_ire_default_count++;
		ASSERT(ipst->ips_ipv6_ire_default_count != 0); /* Wraparound */
	}
	/* Insert at *irep */
	ire1 = *irep;
	if (ire1 != NULL)
		ire1->ire_ptpn = &ire->ire_next;
	ire->ire_next = ire1;
	/* Link the new one in. */
	ire->ire_ptpn = irep;
	/*
	 * ire_walk routines de-reference ire_next without holding
	 * a lock. Before we point to the new ire, we want to make
	 * sure the store that sets the ire_next of the new ire
	 * reaches global visibility, so that ire_walk routines
	 * don't see a truncated list of ires i.e if the ire_next
	 * of the new ire gets set after we do "*irep = ire" due
	 * to re-ordering, the ire_walk thread will see a NULL
	 * once it accesses the ire_next of the new ire.
	 * membar_producer() makes sure that the following store
	 * happens *after* all of the above stores.
	 */
	membar_producer();
	*irep = ire;
	ire->ire_bucket = irb_ptr;
	/*
	 * We return a bumped up IRE above. Keep it symmetrical
	 * so that the callers will always have to release. This
	 * helps the callers of this function because they continue
	 * to use the IRE after adding and hence they don't have to
	 * lookup again after we return the IRE.
	 *
	 * NOTE : We don't have to use atomics as this is appearing
	 * in the list for the first time and no one else can bump
	 * up the reference count on this yet.
	 */
	IRE_REFHOLD_LOCKED(ire);
	BUMP_IRE_STATS(ipst->ips_ire_stats_v6, ire_stats_inserted);
	irb_ptr->irb_ire_cnt++;
	if (ire->ire_marks & IRE_MARK_TEMPORARY)
		irb_ptr->irb_tmp_ire_cnt++;

	if (ire->ire_ipif != NULL) {
		ire->ire_ipif->ipif_ire_cnt++;
		if (ire->ire_stq != NULL) {
			stq_ill = (ill_t *)ire->ire_stq->q_ptr;
			stq_ill->ill_ire_cnt++;
		}
	} else {
		ASSERT(ire->ire_stq == NULL);
	}

	if (ndp_g_lock_held)
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
	ire_atomic_end(irb_ptr, ire);

	if (pire != NULL) {
		/* Assert that it is not removed from the list yet */
		ASSERT(pire->ire_ptpn != NULL);
		IRB_REFRELE(pire->ire_bucket);
		ire_refrele(pire);
	}

	if (ire->ire_type != IRE_CACHE) {
		/*
		 * For ire's with with host mask see if there is an entry
		 * in the cache. If there is one flush the whole cache as
		 * there might be multiple entries due to RTF_MULTIRT (CGTP).
		 * If no entry is found than there is no need to flush the
		 * cache.
		 */

		if (ip_mask_to_plen_v6(&ire->ire_mask_v6) == IPV6_ABITS) {
			ire_t *lire;
			lire = ire_ctable_lookup_v6(&ire->ire_addr_v6, NULL,
			    IRE_CACHE, NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE,
			    ipst);
			if (lire != NULL) {
				ire_refrele(lire);
				ire_flush_cache_v6(ire, IRE_FLUSH_ADD);
			}
		} else {
			ire_flush_cache_v6(ire, IRE_FLUSH_ADD);
		}
	}

	*ire_p = ire;
	return (0);
}

/*
 * Search for all HOST REDIRECT routes that are
 * pointing at the specified gateway and
 * delete them. This routine is called only
 * when a default gateway is going away.
 */
static void
ire_delete_host_redirects_v6(const in6_addr_t *gateway, ip_stack_t *ipst)
{
	irb_t *irb_ptr;
	irb_t *irb;
	ire_t *ire;
	in6_addr_t gw_addr_v6;
	int i;

	/* get the hash table for HOST routes */
	irb_ptr = ipst->ips_ip_forwarding_table_v6[(IP6_MASK_TABLE_SIZE - 1)];
	if (irb_ptr == NULL)
		return;
	for (i = 0; (i < ipst->ips_ip6_ftable_hash_size); i++) {
		irb = &irb_ptr[i];
		IRB_REFHOLD(irb);
		for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
			if (!(ire->ire_flags & RTF_DYNAMIC))
				continue;
			mutex_enter(&ire->ire_lock);
			gw_addr_v6 = ire->ire_gateway_addr_v6;
			mutex_exit(&ire->ire_lock);
			if (IN6_ARE_ADDR_EQUAL(&gw_addr_v6, gateway))
				ire_delete(ire);
		}
		IRB_REFRELE(irb);
	}
}

/*
 * Delete all the cache entries with this 'addr'. This is the IPv6 counterpart
 * of ip_ire_clookup_and_delete. The difference being this function does not
 * return any value. IPv6 processing of a gratuitous ARP, as it stands, is
 * different than IPv4 in that, regardless of the presence of a cache entry
 * for this address, an ire_walk_v6 is done. Another difference is that unlike
 * in the case of IPv4 this does not take an ipif_t argument, since it is only
 * called by ip_arp_news and the match is always only on the address.
 */
void
ip_ire_clookup_and_delete_v6(const in6_addr_t *addr, ip_stack_t *ipst)
{
	irb_t		*irb;
	ire_t		*cire;
	boolean_t	found = B_FALSE;

	irb = &ipst->ips_ip_cache_table_v6[IRE_ADDR_HASH_V6(*addr,
	    ipst->ips_ip6_cache_table_size)];
	IRB_REFHOLD(irb);
	for (cire = irb->irb_ire; cire != NULL; cire = cire->ire_next) {
		if (cire->ire_marks & IRE_MARK_CONDEMNED)
			continue;
		if (IN6_ARE_ADDR_EQUAL(&cire->ire_addr_v6, addr)) {

			/* This signifies start of a match */
			if (!found)
				found = B_TRUE;
			if (cire->ire_type == IRE_CACHE) {
				if (cire->ire_nce != NULL)
					ndp_delete(cire->ire_nce);
				ire_delete_v6(cire);
			}
		/* End of the match */
		} else if (found)
			break;
	}
	IRB_REFRELE(irb);
}

/*
 * Delete the specified IRE.
 * All calls should use ire_delete().
 * Sometimes called as writer though not required by this function.
 *
 * NOTE : This function is called only if the ire was added
 * in the list.
 */
void
ire_delete_v6(ire_t *ire)
{
	in6_addr_t gw_addr_v6;
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(ire->ire_refcnt >= 1);
	ASSERT(ire->ire_ipversion == IPV6_VERSION);

	if (ire->ire_type != IRE_CACHE)
		ire_flush_cache_v6(ire, IRE_FLUSH_DELETE);
	if (ire->ire_type == IRE_DEFAULT) {
		/*
		 * when a default gateway is going away
		 * delete all the host redirects pointing at that
		 * gateway.
		 */
		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
		ire_delete_host_redirects_v6(&gw_addr_v6, ipst);
	}
}

/*
 * ire_walk routine to delete all IRE_CACHE and IRE_HOST type redirect
 * entries.
 */
/*ARGSUSED1*/
void
ire_delete_cache_v6(ire_t *ire, char *arg)
{
	char    addrstr1[INET6_ADDRSTRLEN];
	char    addrstr2[INET6_ADDRSTRLEN];

	if ((ire->ire_type & IRE_CACHE) ||
	    (ire->ire_flags & RTF_DYNAMIC)) {
		ip1dbg(("ire_delete_cache_v6: deleted %s type %d through %s\n",
		    inet_ntop(AF_INET6, &ire->ire_addr_v6,
		    addrstr1, sizeof (addrstr1)),
		    ire->ire_type,
		    inet_ntop(AF_INET6, &ire->ire_gateway_addr_v6,
		    addrstr2, sizeof (addrstr2))));
		ire_delete(ire);
	}

}

/*
 * ire_walk routine to delete all IRE_CACHE/IRE_HOST type redirect entries
 * that have a given gateway address.
 */
void
ire_delete_cache_gw_v6(ire_t *ire, char *addr)
{
	in6_addr_t	*gw_addr = (in6_addr_t *)addr;
	char		buf1[INET6_ADDRSTRLEN];
	char		buf2[INET6_ADDRSTRLEN];
	in6_addr_t	ire_gw_addr_v6;

	if (!(ire->ire_type & IRE_CACHE) &&
	    !(ire->ire_flags & RTF_DYNAMIC))
		return;

	mutex_enter(&ire->ire_lock);
	ire_gw_addr_v6 = ire->ire_gateway_addr_v6;
	mutex_exit(&ire->ire_lock);

	if (IN6_ARE_ADDR_EQUAL(&ire_gw_addr_v6, gw_addr)) {
		ip1dbg(("ire_delete_cache_gw_v6: deleted %s type %d to %s\n",
		    inet_ntop(AF_INET6, &ire->ire_src_addr_v6,
		    buf1, sizeof (buf1)),
		    ire->ire_type,
		    inet_ntop(AF_INET6, &ire_gw_addr_v6,
		    buf2, sizeof (buf2))));
		ire_delete(ire);
	}
}

/*
 * Remove all IRE_CACHE entries that match
 * the ire specified.  (Sometimes called
 * as writer though not required by this function.)
 *
 * The flag argument indicates if the
 * flush request is due to addition
 * of new route (IRE_FLUSH_ADD) or deletion of old
 * route (IRE_FLUSH_DELETE).
 *
 * This routine takes only the IREs from the forwarding
 * table and flushes the corresponding entries from
 * the cache table.
 *
 * When flushing due to the deletion of an old route, it
 * just checks the cache handles (ire_phandle and ire_ihandle) and
 * deletes the ones that match.
 *
 * When flushing due to the creation of a new route, it checks
 * if a cache entry's address matches the one in the IRE and
 * that the cache entry's parent has a less specific mask than the
 * one in IRE. The destination of such a cache entry could be the
 * gateway for other cache entries, so we need to flush those as
 * well by looking for gateway addresses matching the IRE's address.
 */
void
ire_flush_cache_v6(ire_t *ire, int flag)
{
	int i;
	ire_t *cire;
	irb_t *irb;
	ip_stack_t	*ipst = ire->ire_ipst;

	if (ire->ire_type & IRE_CACHE)
		return;

	/*
	 * If a default is just created, there is no point
	 * in going through the cache, as there will not be any
	 * cached ires.
	 */
	if (ire->ire_type == IRE_DEFAULT && flag == IRE_FLUSH_ADD)
		return;
	if (flag == IRE_FLUSH_ADD) {
		/*
		 * This selective flush is
		 * due to the addition of
		 * new IRE.
		 */
		for (i = 0; i < ipst->ips_ip6_cache_table_size; i++) {
			irb = &ipst->ips_ip_cache_table_v6[i];
			if ((cire = irb->irb_ire) == NULL)
				continue;
			IRB_REFHOLD(irb);
			for (cire = irb->irb_ire; cire != NULL;
			    cire = cire->ire_next) {
				if (cire->ire_type != IRE_CACHE)
					continue;
				/*
				 * If 'cire' belongs to the same subnet
				 * as the new ire being added, and 'cire'
				 * is derived from a prefix that is less
				 * specific than the new ire being added,
				 * we need to flush 'cire'; for instance,
				 * when a new interface comes up.
				 */
				if ((V6_MASK_EQ_2(cire->ire_addr_v6,
				    ire->ire_mask_v6, ire->ire_addr_v6) &&
				    (ip_mask_to_plen_v6(&cire->ire_cmask_v6) <=
				    ire->ire_masklen))) {
					ire_delete(cire);
					continue;
				}
				/*
				 * This is the case when the ire_gateway_addr
				 * of 'cire' belongs to the same subnet as
				 * the new ire being added.
				 * Flushing such ires is sometimes required to
				 * avoid misrouting: say we have a machine with
				 * two interfaces (I1 and I2), a default router
				 * R on the I1 subnet, and a host route to an
				 * off-link destination D with a gateway G on
				 * the I2 subnet.
				 * Under normal operation, we will have an
				 * on-link cache entry for G and an off-link
				 * cache entry for D with G as ire_gateway_addr,
				 * traffic to D will reach its destination
				 * through gateway G.
				 * If the administrator does 'ifconfig I2 down',
				 * the cache entries for D and G will be
				 * flushed. However, G will now be resolved as
				 * an off-link destination using R (the default
				 * router) as gateway. Then D will also be
				 * resolved as an off-link destination using G
				 * as gateway - this behavior is due to
				 * compatibility reasons, see comment in
				 * ire_ihandle_lookup_offlink(). Traffic to D
				 * will go to the router R and probably won't
				 * reach the destination.
				 * The administrator then does 'ifconfig I2 up'.
				 * Since G is on the I2 subnet, this routine
				 * will flush its cache entry. It must also
				 * flush the cache entry for D, otherwise
				 * traffic will stay misrouted until the IRE
				 * times out.
				 */
				if (V6_MASK_EQ_2(cire->ire_gateway_addr_v6,
				    ire->ire_mask_v6, ire->ire_addr_v6)) {
					ire_delete(cire);
					continue;
				}
			}
			IRB_REFRELE(irb);
		}
	} else {
		/*
		 * delete the cache entries based on
		 * handle in the IRE as this IRE is
		 * being deleted/changed.
		 */
		for (i = 0; i < ipst->ips_ip6_cache_table_size; i++) {
			irb = &ipst->ips_ip_cache_table_v6[i];
			if ((cire = irb->irb_ire) == NULL)
				continue;
			IRB_REFHOLD(irb);
			for (cire = irb->irb_ire; cire != NULL;
			    cire = cire->ire_next) {
				if (cire->ire_type != IRE_CACHE)
					continue;
				if ((cire->ire_phandle == 0 ||
				    cire->ire_phandle != ire->ire_phandle) &&
				    (cire->ire_ihandle == 0 ||
				    cire->ire_ihandle != ire->ire_ihandle))
					continue;
				ire_delete(cire);
			}
			IRB_REFRELE(irb);
		}
	}
}

/*
 * Matches the arguments passed with the values in the ire.
 *
 * Note: for match types that match using "ipif" passed in, ipif
 * must be checked for non-NULL before calling this routine.
 */
static boolean_t
ire_match_args_v6(ire_t *ire, const in6_addr_t *addr, const in6_addr_t *mask,
    const in6_addr_t *gateway, int type, const ipif_t *ipif, zoneid_t zoneid,
    uint32_t ihandle, const ts_label_t *tsl, int match_flags)
{
	in6_addr_t masked_addr;
	in6_addr_t gw_addr_v6;
	ill_t *ire_ill = NULL, *dst_ill;
	ill_t *ipif_ill = NULL;
	ill_group_t *ire_ill_group = NULL;
	ill_group_t *ipif_ill_group = NULL;
	ipif_t	*src_ipif;

	ASSERT(ire->ire_ipversion == IPV6_VERSION);
	ASSERT(addr != NULL);
	ASSERT(mask != NULL);
	ASSERT((!(match_flags & MATCH_IRE_GW)) || gateway != NULL);
	ASSERT((!(match_flags & (MATCH_IRE_ILL|MATCH_IRE_ILL_GROUP))) ||
	    (ipif != NULL && ipif->ipif_isv6));

	/*
	 * HIDDEN cache entries have to be looked up specifically with
	 * MATCH_IRE_MARK_HIDDEN. MATCH_IRE_MARK_HIDDEN is usually set
	 * when the interface is FAILED or INACTIVE. In that case,
	 * any IRE_CACHES that exists should be marked with
	 * IRE_MARK_HIDDEN. So, we don't really need to match below
	 * for IRE_MARK_HIDDEN. But we do so for consistency.
	 */
	if (!(match_flags & MATCH_IRE_MARK_HIDDEN) &&
	    (ire->ire_marks & IRE_MARK_HIDDEN))
		return (B_FALSE);

	if (zoneid != ALL_ZONES && zoneid != ire->ire_zoneid &&
	    ire->ire_zoneid != ALL_ZONES) {
		/*
		 * If MATCH_IRE_ZONEONLY has been set and the supplied zoneid is
		 * valid and does not match that of ire_zoneid, a failure to
		 * match is reported at this point. Otherwise, since some IREs
		 * that are available in the global zone can be used in local
		 * zones, additional checks need to be performed:
		 *
		 *	IRE_CACHE and IRE_LOOPBACK entries should
		 *	never be matched in this situation.
		 *
		 *	IRE entries that have an interface associated with them
		 *	should in general not match unless they are an IRE_LOCAL
		 *	or in the case when MATCH_IRE_DEFAULT has been set in
		 *	the caller.  In the case of the former, checking of the
		 *	other fields supplied should take place.
		 *
		 *	In the case where MATCH_IRE_DEFAULT has been set,
		 *	all of the ipif's associated with the IRE's ill are
		 *	checked to see if there is a matching zoneid.  If any
		 *	one ipif has a matching zoneid, this IRE is a
		 *	potential candidate so checking of the other fields
		 *	takes place.
		 *
		 *	In the case where the IRE_INTERFACE has a usable source
		 *	address (indicated by ill_usesrc_ifindex) in the
		 *	correct zone then it's permitted to return this IRE
		 */
		if (match_flags & MATCH_IRE_ZONEONLY)
			return (B_FALSE);
		if (ire->ire_type & (IRE_CACHE | IRE_LOOPBACK))
			return (B_FALSE);
		/*
		 * Note, IRE_INTERFACE can have the stq as NULL. For
		 * example, if the default multicast route is tied to
		 * the loopback address.
		 */
		if ((ire->ire_type & IRE_INTERFACE) &&
		    (ire->ire_stq != NULL)) {
			dst_ill = (ill_t *)ire->ire_stq->q_ptr;
			/*
			 * If there is a usable source address in the
			 * zone, then it's ok to return an
			 * IRE_INTERFACE
			 */
			if ((dst_ill->ill_usesrc_ifindex != 0) &&
			    (src_ipif = ipif_select_source_v6(dst_ill, addr,
			    RESTRICT_TO_NONE, IPV6_PREFER_SRC_DEFAULT, zoneid))
			    != NULL) {
				ip3dbg(("ire_match_args: src_ipif %p"
				    " dst_ill %p", (void *)src_ipif,
				    (void *)dst_ill));
				ipif_refrele(src_ipif);
			} else {
				ip3dbg(("ire_match_args: src_ipif NULL"
				    " dst_ill %p\n", (void *)dst_ill));
				return (B_FALSE);
			}
		}
		if (ire->ire_ipif != NULL && ire->ire_type != IRE_LOCAL &&
		    !(ire->ire_type & IRE_INTERFACE)) {
			ipif_t	*tipif;

			if ((match_flags & MATCH_IRE_DEFAULT) == 0)
				return (B_FALSE);
			mutex_enter(&ire->ire_ipif->ipif_ill->ill_lock);
			for (tipif = ire->ire_ipif->ipif_ill->ill_ipif;
			    tipif != NULL; tipif = tipif->ipif_next) {
				if (IPIF_CAN_LOOKUP(tipif) &&
				    (tipif->ipif_flags & IPIF_UP) &&
				    (tipif->ipif_zoneid == zoneid ||
				    tipif->ipif_zoneid == ALL_ZONES))
					break;
			}
			mutex_exit(&ire->ire_ipif->ipif_ill->ill_lock);
			if (tipif == NULL)
				return (B_FALSE);
		}
	}

	if (match_flags & MATCH_IRE_GW) {
		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
	}
	/*
	 * For IRE_CACHES, MATCH_IRE_ILL/ILL_GROUP really means that
	 * somebody wants to send out on a particular interface which
	 * is given by ire_stq and hence use ire_stq to derive the ill
	 * value. ire_ipif for IRE_CACHES is just the
	 * means of getting a source address i.e ire_src_addr_v6 =
	 * ire->ire_ipif->ipif_src_addr_v6.
	 */
	if (match_flags & (MATCH_IRE_ILL|MATCH_IRE_ILL_GROUP)) {
		ire_ill = ire_to_ill(ire);
		if (ire_ill != NULL)
			ire_ill_group = ire_ill->ill_group;
		ipif_ill = ipif->ipif_ill;
		ipif_ill_group = ipif_ill->ill_group;
	}

	/* No ire_addr_v6 bits set past the mask */
	ASSERT(V6_MASK_EQ(ire->ire_addr_v6, ire->ire_mask_v6,
	    ire->ire_addr_v6));
	V6_MASK_COPY(*addr, *mask, masked_addr);

	if (V6_MASK_EQ(*addr, *mask, ire->ire_addr_v6) &&
	    ((!(match_flags & MATCH_IRE_GW)) ||
	    IN6_ARE_ADDR_EQUAL(&gw_addr_v6, gateway)) &&
	    ((!(match_flags & MATCH_IRE_TYPE)) ||
	    (ire->ire_type & type)) &&
	    ((!(match_flags & MATCH_IRE_SRC)) ||
	    IN6_ARE_ADDR_EQUAL(&ire->ire_src_addr_v6,
	    &ipif->ipif_v6src_addr)) &&
	    ((!(match_flags & MATCH_IRE_IPIF)) ||
	    (ire->ire_ipif == ipif)) &&
	    ((!(match_flags & MATCH_IRE_MARK_HIDDEN)) ||
	    (ire->ire_type != IRE_CACHE ||
	    ire->ire_marks & IRE_MARK_HIDDEN)) &&
	    ((!(match_flags & MATCH_IRE_ILL)) ||
	    (ire_ill == ipif_ill)) &&
	    ((!(match_flags & MATCH_IRE_IHANDLE)) ||
	    (ire->ire_ihandle == ihandle)) &&
	    ((!(match_flags & MATCH_IRE_ILL_GROUP)) ||
	    (ire_ill == ipif_ill) ||
	    (ire_ill_group != NULL &&
	    ire_ill_group == ipif_ill_group)) &&
	    ((!(match_flags & MATCH_IRE_SECATTR)) ||
	    (!is_system_labeled()) ||
	    (tsol_ire_match_gwattr(ire, tsl) == 0))) {
		/* We found the matched IRE */
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Lookup for a route in all the tables
 */
ire_t *
ire_route_lookup_v6(const in6_addr_t *addr, const in6_addr_t *mask,
    const in6_addr_t *gateway, int type, const ipif_t *ipif, ire_t **pire,
    zoneid_t zoneid, const ts_label_t *tsl, int flags, ip_stack_t *ipst)
{
	ire_t *ire = NULL;

	/*
	 * ire_match_args_v6() will dereference ipif MATCH_IRE_SRC or
	 * MATCH_IRE_ILL is set.
	 */
	if ((flags & (MATCH_IRE_SRC | MATCH_IRE_ILL | MATCH_IRE_ILL_GROUP)) &&
	    (ipif == NULL))
		return (NULL);

	/*
	 * might be asking for a cache lookup,
	 * This is not best way to lookup cache,
	 * user should call ire_cache_lookup directly.
	 *
	 * If MATCH_IRE_TYPE was set, first lookup in the cache table and then
	 * in the forwarding table, if the applicable type flags were set.
	 */
	if ((flags & MATCH_IRE_TYPE) == 0 || (type & IRE_CACHETABLE) != 0) {
		ire = ire_ctable_lookup_v6(addr, gateway, type, ipif, zoneid,
		    tsl, flags, ipst);
		if (ire != NULL)
			return (ire);
	}
	if ((flags & MATCH_IRE_TYPE) == 0 || (type & IRE_FORWARDTABLE) != 0) {
		ire = ire_ftable_lookup_v6(addr, mask, gateway, type, ipif,
		    pire, zoneid, 0, tsl, flags, ipst);
	}
	return (ire);
}

/*
 * Lookup a route in forwarding table.
 * specific lookup is indicated by passing the
 * required parameters and indicating the
 * match required in flag field.
 *
 * Looking for default route can be done in three ways
 * 1) pass mask as ipv6_all_zeros and set MATCH_IRE_MASK in flags field
 *    along with other matches.
 * 2) pass type as IRE_DEFAULT and set MATCH_IRE_TYPE in flags
 *    field along with other matches.
 * 3) if the destination and mask are passed as zeros.
 *
 * A request to return a default route if no route
 * is found, can be specified by setting MATCH_IRE_DEFAULT
 * in flags.
 *
 * It does not support recursion more than one level. It
 * will do recursive lookup only when the lookup maps to
 * a prefix or default route and MATCH_IRE_RECURSIVE flag is passed.
 *
 * If the routing table is setup to allow more than one level
 * of recursion, the cleaning up cache table will not work resulting
 * in invalid routing.
 *
 * Supports link-local addresses by following the ipif/ill when recursing.
 *
 * NOTE : When this function returns NULL, pire has already been released.
 *	  pire is valid only when this function successfully returns an
 *	  ire.
 */
ire_t *
ire_ftable_lookup_v6(const in6_addr_t *addr, const in6_addr_t *mask,
    const in6_addr_t *gateway, int type, const ipif_t *ipif, ire_t **pire,
    zoneid_t zoneid, uint32_t ihandle, const ts_label_t *tsl, int flags,
    ip_stack_t *ipst)
{
	irb_t *irb_ptr;
	ire_t	*rire;
	ire_t *ire = NULL;
	ire_t	*saved_ire;
	nce_t	*nce;
	int i;
	in6_addr_t gw_addr_v6;

	ASSERT(addr != NULL);
	ASSERT((!(flags & MATCH_IRE_MASK)) || mask != NULL);
	ASSERT((!(flags & MATCH_IRE_GW)) || gateway != NULL);
	ASSERT(ipif == NULL || ipif->ipif_isv6);

	/*
	 * When we return NULL from this function, we should make
	 * sure that *pire is NULL so that the callers will not
	 * wrongly REFRELE the pire.
	 */
	if (pire != NULL)
		*pire = NULL;
	/*
	 * ire_match_args_v6() will dereference ipif MATCH_IRE_SRC or
	 * MATCH_IRE_ILL is set.
	 */
	if ((flags & (MATCH_IRE_SRC | MATCH_IRE_ILL | MATCH_IRE_ILL_GROUP)) &&
	    (ipif == NULL))
		return (NULL);

	/*
	 * If the mask is known, the lookup
	 * is simple, if the mask is not known
	 * we need to search.
	 */
	if (flags & MATCH_IRE_MASK) {
		uint_t masklen;

		masklen = ip_mask_to_plen_v6(mask);
		if (ipst->ips_ip_forwarding_table_v6[masklen] == NULL)
			return (NULL);
		irb_ptr = &(ipst->ips_ip_forwarding_table_v6[masklen][
		    IRE_ADDR_MASK_HASH_V6(*addr, *mask,
		    ipst->ips_ip6_ftable_hash_size)]);
		rw_enter(&irb_ptr->irb_lock, RW_READER);
		for (ire = irb_ptr->irb_ire; ire != NULL;
		    ire = ire->ire_next) {
			if (ire->ire_marks & IRE_MARK_CONDEMNED)
				continue;
			if (ire_match_args_v6(ire, addr, mask, gateway, type,
			    ipif, zoneid, ihandle, tsl, flags))
				goto found_ire;
		}
		rw_exit(&irb_ptr->irb_lock);
	} else {
		/*
		 * In this case we don't know the mask, we need to
		 * search the table assuming different mask sizes.
		 * we start with 128 bit mask, we don't allow default here.
		 */
		for (i = (IP6_MASK_TABLE_SIZE - 1); i > 0; i--) {
			in6_addr_t tmpmask;

			if ((ipst->ips_ip_forwarding_table_v6[i]) == NULL)
				continue;
			(void) ip_plen_to_mask_v6(i, &tmpmask);
			irb_ptr = &ipst->ips_ip_forwarding_table_v6[i][
			    IRE_ADDR_MASK_HASH_V6(*addr, tmpmask,
			    ipst->ips_ip6_ftable_hash_size)];
			rw_enter(&irb_ptr->irb_lock, RW_READER);
			for (ire = irb_ptr->irb_ire; ire != NULL;
			    ire = ire->ire_next) {
				if (ire->ire_marks & IRE_MARK_CONDEMNED)
					continue;
				if (ire_match_args_v6(ire, addr,
				    &ire->ire_mask_v6, gateway, type, ipif,
				    zoneid, ihandle, tsl, flags))
					goto found_ire;
			}
			rw_exit(&irb_ptr->irb_lock);
		}
	}

	/*
	 * We come here if no route has yet been found.
	 *
	 * Handle the case where default route is
	 * requested by specifying type as one of the possible
	 * types for that can have a zero mask (IRE_DEFAULT and IRE_INTERFACE).
	 *
	 * If MATCH_IRE_MASK is specified, then the appropriate default route
	 * would have been found above if it exists so it isn't looked up here.
	 * If MATCH_IRE_DEFAULT was also specified, then a default route will be
	 * searched for later.
	 */
	if ((flags & (MATCH_IRE_TYPE | MATCH_IRE_MASK)) == MATCH_IRE_TYPE &&
	    (type & (IRE_DEFAULT | IRE_INTERFACE))) {
		if (ipst->ips_ip_forwarding_table_v6[0] != NULL) {
			/* addr & mask is zero for defaults */
			irb_ptr = &ipst->ips_ip_forwarding_table_v6[0][
			    IRE_ADDR_HASH_V6(ipv6_all_zeros,
			    ipst->ips_ip6_ftable_hash_size)];
			rw_enter(&irb_ptr->irb_lock, RW_READER);
			for (ire = irb_ptr->irb_ire; ire != NULL;
			    ire = ire->ire_next) {

				if (ire->ire_marks & IRE_MARK_CONDEMNED)
					continue;

				if (ire_match_args_v6(ire, addr,
				    &ipv6_all_zeros, gateway, type, ipif,
				    zoneid, ihandle, tsl, flags))
					goto found_ire;
			}
			rw_exit(&irb_ptr->irb_lock);
		}
	}
	/*
	 * We come here only if no route is found.
	 * see if the default route can be used which is allowed
	 * only if the default matching criteria is specified.
	 * The ipv6_ire_default_count tracks the number of IRE_DEFAULT
	 * entries. However, the ip_forwarding_table_v6[0] also contains
	 * interface routes thus the count can be zero.
	 */
	saved_ire = NULL;
	if ((flags & (MATCH_IRE_DEFAULT | MATCH_IRE_MASK)) ==
	    MATCH_IRE_DEFAULT) {
		ire_t	*ire_origin;
		uint_t	g_index;
		uint_t	index;

		if (ipst->ips_ip_forwarding_table_v6[0] == NULL)
			return (NULL);
		irb_ptr = &(ipst->ips_ip_forwarding_table_v6[0])[0];

		/*
		 * Keep a tab on the bucket while looking the IRE_DEFAULT
		 * entries. We need to keep track of a particular IRE
		 * (ire_origin) so this ensures that it will not be unlinked
		 * from the hash list during the recursive lookup below.
		 */
		IRB_REFHOLD(irb_ptr);
		ire = irb_ptr->irb_ire;
		if (ire == NULL) {
			IRB_REFRELE(irb_ptr);
			return (NULL);
		}

		/*
		 * Get the index first, since it can be changed by other
		 * threads. Then get to the right default route skipping
		 * default interface routes if any. As we hold a reference on
		 * the IRE bucket, ipv6_ire_default_count can only increase so
		 * we can't reach the end of the hash list unexpectedly.
		 */
		if (ipst->ips_ipv6_ire_default_count != 0) {
			g_index = ipst->ips_ipv6_ire_default_index++;
			index = g_index % ipst->ips_ipv6_ire_default_count;
			while (index != 0) {
				if (!(ire->ire_type & IRE_INTERFACE))
					index--;
				ire = ire->ire_next;
			}
			ASSERT(ire != NULL);
		} else {
			/*
			 * No default route, so we only have default interface
			 * routes: don't enter the first loop.
			 */
			ire = NULL;
		}

		/*
		 * Round-robin the default routers list looking for a neighbor
		 * that matches the passed in parameters and is reachable.  If
		 * none found, just return a route from the default router list
		 * if it exists. If we can't find a default route (IRE_DEFAULT),
		 * look for interface default routes.
		 * We start with the ire we found above and we walk the hash
		 * list until we're back where we started, see
		 * ire_get_next_default_ire(). It doesn't matter if default
		 * routes are added or deleted by other threads - we know this
		 * ire will stay in the list because we hold a reference on the
		 * ire bucket.
		 * NB: if we only have interface default routes, ire is NULL so
		 * we don't even enter this loop (see above).
		 */
		ire_origin = ire;
		for (; ire != NULL;
		    ire = ire_get_next_default_ire(ire, ire_origin)) {

			if (ire_match_args_v6(ire, addr,
			    &ipv6_all_zeros, gateway, type, ipif,
			    zoneid, ihandle, tsl, flags)) {
				int match_flags;

				/*
				 * We have something to work with.
				 * If we can find a resolved/reachable
				 * entry, we will use this. Otherwise
				 * we'll try to find an entry that has
				 * a resolved cache entry. We will fallback
				 * on this if we don't find anything else.
				 */
				if (saved_ire == NULL)
					saved_ire = ire;
				mutex_enter(&ire->ire_lock);
				gw_addr_v6 = ire->ire_gateway_addr_v6;
				mutex_exit(&ire->ire_lock);
				match_flags = MATCH_IRE_ILL_GROUP |
				    MATCH_IRE_SECATTR;
				rire = ire_ctable_lookup_v6(&gw_addr_v6, NULL,
				    0, ire->ire_ipif, zoneid, tsl, match_flags,
				    ipst);
				if (rire != NULL) {
					nce = rire->ire_nce;
					if (nce != NULL &&
					    NCE_ISREACHABLE(nce) &&
					    nce->nce_flags & NCE_F_ISROUTER) {
						ire_refrele(rire);
						IRE_REFHOLD(ire);
						IRB_REFRELE(irb_ptr);
						goto found_ire_held;
					} else if (nce != NULL &&
					    !(nce->nce_flags &
					    NCE_F_ISROUTER)) {
						/*
						 * Make sure we don't use
						 * this ire
						 */
						if (saved_ire == ire)
							saved_ire = NULL;
					}
					ire_refrele(rire);
				} else if (ipst->
				    ips_ipv6_ire_default_count > 1 &&
				    zoneid != GLOBAL_ZONEID) {
					/*
					 * When we're in a local zone, we're
					 * only interested in default routers
					 * that are reachable through ipifs
					 * within our zone.
					 * The potentially expensive call to
					 * ire_route_lookup_v6() is avoided when
					 * we have only one default route.
					 */
					int ire_match_flags = MATCH_IRE_TYPE |
					    MATCH_IRE_SECATTR;

					if (ire->ire_ipif != NULL) {
						ire_match_flags |=
						    MATCH_IRE_ILL_GROUP;
					}
					rire = ire_route_lookup_v6(&gw_addr_v6,
					    NULL, NULL, IRE_INTERFACE,
					    ire->ire_ipif, NULL,
					    zoneid, tsl, ire_match_flags, ipst);
					if (rire != NULL) {
						ire_refrele(rire);
						saved_ire = ire;
					} else if (saved_ire == ire) {
						/*
						 * Make sure we don't use
						 * this ire
						 */
						saved_ire = NULL;
					}
				}
			}
		}
		if (saved_ire != NULL) {
			ire = saved_ire;
			IRE_REFHOLD(ire);
			IRB_REFRELE(irb_ptr);
			goto found_ire_held;
		} else {
			/*
			 * Look for a interface default route matching the
			 * args passed in. No round robin here. Just pick
			 * the right one.
			 */
			for (ire = irb_ptr->irb_ire; ire != NULL;
			    ire = ire->ire_next) {

				if (!(ire->ire_type & IRE_INTERFACE))
					continue;

				if (ire->ire_marks & IRE_MARK_CONDEMNED)
					continue;

				if (ire_match_args_v6(ire, addr,
				    &ipv6_all_zeros, gateway, type, ipif,
				    zoneid, ihandle, tsl, flags)) {
					IRE_REFHOLD(ire);
					IRB_REFRELE(irb_ptr);
					goto found_ire_held;
				}
			}
			IRB_REFRELE(irb_ptr);
		}
	}
	ASSERT(ire == NULL);
	ip1dbg(("ire_ftable_lookup_v6: returning NULL ire"));
	return (NULL);
found_ire:
	ASSERT((ire->ire_marks & IRE_MARK_CONDEMNED) == 0);
	IRE_REFHOLD(ire);
	rw_exit(&irb_ptr->irb_lock);

found_ire_held:
	if ((flags & MATCH_IRE_RJ_BHOLE) &&
	    (ire->ire_flags & (RTF_BLACKHOLE | RTF_REJECT))) {
		return (ire);
	}
	/*
	 * At this point, IRE that was found must be an IRE_FORWARDTABLE
	 * or IRE_CACHETABLE type.  If this is a recursive lookup and an
	 * IRE_INTERFACE type was found, return that.  If it was some other
	 * IRE_FORWARDTABLE type of IRE (one of the prefix types), then it
	 * is necessary to fill in the  parent IRE pointed to by pire, and
	 * then lookup the gateway address of  the parent.  For backwards
	 * compatiblity, if this lookup returns an
	 * IRE other than a IRE_CACHETABLE or IRE_INTERFACE, then one more level
	 * of lookup is done.
	 */
	if (flags & MATCH_IRE_RECURSIVE) {
		const ipif_t *gw_ipif;
		int match_flags = MATCH_IRE_DSTONLY;

		if (ire->ire_type & IRE_INTERFACE)
			return (ire);
		if (pire != NULL)
			*pire = ire;
		/*
		 * If we can't find an IRE_INTERFACE or the caller has not
		 * asked for pire, we need to REFRELE the saved_ire.
		 */
		saved_ire = ire;

		/*
		 * Currently MATCH_IRE_ILL is never used with
		 * (MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT) while
		 * sending out packets as MATCH_IRE_ILL is used only
		 * for communicating with on-link hosts. We can't assert
		 * that here as RTM_GET calls this function with
		 * MATCH_IRE_ILL | MATCH_IRE_DEFAULT | MATCH_IRE_RECURSIVE.
		 * We have already used the MATCH_IRE_ILL in determining
		 * the right prefix route at this point. To match the
		 * behavior of how we locate routes while sending out
		 * packets, we don't want to use MATCH_IRE_ILL below
		 * while locating the interface route.
		 */
		if (ire->ire_ipif != NULL)
			match_flags |= MATCH_IRE_ILL_GROUP;

		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);

		ire = ire_route_lookup_v6(&gw_addr_v6, NULL, NULL, 0,
		    ire->ire_ipif, NULL, zoneid, tsl, match_flags, ipst);
		if (ire == NULL) {
			/*
			 * In this case we have to deal with the
			 * MATCH_IRE_PARENT flag, which means the
			 * parent has to be returned if ire is NULL.
			 * The aim of this is to have (at least) a starting
			 * ire when we want to look at all of the ires in a
			 * bucket aimed at a single destination (as is the
			 * case in ip_newroute_v6 for the RTF_MULTIRT
			 * flagged routes).
			 */
			if (flags & MATCH_IRE_PARENT) {
				if (pire != NULL) {
					/*
					 * Need an extra REFHOLD, if the
					 * parent ire is returned via both
					 * ire and pire.
					 */
					IRE_REFHOLD(saved_ire);
				}
				ire = saved_ire;
			} else {
				ire_refrele(saved_ire);
				if (pire != NULL)
					*pire = NULL;
			}
			return (ire);
		}
		if (ire->ire_type & (IRE_CACHETABLE | IRE_INTERFACE)) {
			/*
			 * If the caller did not ask for pire, release
			 * it now.
			 */
			if (pire == NULL) {
				ire_refrele(saved_ire);
			}
			return (ire);
		}
		match_flags |= MATCH_IRE_TYPE;
		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
		gw_ipif = ire->ire_ipif;
		ire_refrele(ire);
		ire = ire_route_lookup_v6(&gw_addr_v6, NULL, NULL,
		    (IRE_CACHETABLE | IRE_INTERFACE), gw_ipif, NULL, zoneid,
		    NULL, match_flags, ipst);
		if (ire == NULL) {
			/*
			 * In this case we have to deal with the
			 * MATCH_IRE_PARENT flag, which means the
			 * parent has to be returned if ire is NULL.
			 * The aim of this is to have (at least) a starting
			 * ire when we want to look at all of the ires in a
			 * bucket aimed at a single destination (as is the
			 * case in ip_newroute_v6 for the RTF_MULTIRT
			 * flagged routes).
			 */
			if (flags & MATCH_IRE_PARENT) {
				if (pire != NULL) {
					/*
					 * Need an extra REFHOLD, if the
					 * parent ire is returned via both
					 * ire and pire.
					 */
					IRE_REFHOLD(saved_ire);
				}
				ire = saved_ire;
			} else {
				ire_refrele(saved_ire);
				if (pire != NULL)
					*pire = NULL;
			}
			return (ire);
		} else if (pire == NULL) {
			/*
			 * If the caller did not ask for pire, release
			 * it now.
			 */
			ire_refrele(saved_ire);
		}
		return (ire);
	}

	ASSERT(pire == NULL || *pire == NULL);
	return (ire);
}

/*
 * Delete the IRE cache for the gateway and all IRE caches whose
 * ire_gateway_addr_v6 points to this gateway, and allow them to
 * be created on demand by ip_newroute_v6.
 */
void
ire_clookup_delete_cache_gw_v6(const in6_addr_t *addr, zoneid_t zoneid,
	ip_stack_t *ipst)
{
	irb_t *irb;
	ire_t *ire;

	irb = &ipst->ips_ip_cache_table_v6[IRE_ADDR_HASH_V6(*addr,
	    ipst->ips_ip6_cache_table_size)];
	IRB_REFHOLD(irb);
	for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (ire->ire_marks & IRE_MARK_CONDEMNED)
			continue;

		ASSERT(IN6_ARE_ADDR_EQUAL(&ire->ire_mask_v6, &ipv6_all_ones));
		if (ire_match_args_v6(ire, addr, &ire->ire_mask_v6, 0,
		    IRE_CACHE, NULL, zoneid, 0, NULL, MATCH_IRE_TYPE)) {
			ire_delete(ire);
		}
	}
	IRB_REFRELE(irb);

	ire_walk_v6(ire_delete_cache_gw_v6, (char *)addr, zoneid, ipst);
}

/*
 * Looks up cache table for a route.
 * specific lookup can be indicated by
 * passing the MATCH_* flags and the
 * necessary parameters.
 */
ire_t *
ire_ctable_lookup_v6(const in6_addr_t *addr, const in6_addr_t *gateway,
    int type, const ipif_t *ipif, zoneid_t zoneid, const ts_label_t *tsl,
    int flags, ip_stack_t *ipst)
{
	ire_t *ire;
	irb_t *irb_ptr;
	ASSERT(addr != NULL);
	ASSERT((!(flags & MATCH_IRE_GW)) || gateway != NULL);

	/*
	 * ire_match_args_v6() will dereference ipif MATCH_IRE_SRC or
	 * MATCH_IRE_ILL is set.
	 */
	if ((flags & (MATCH_IRE_SRC |  MATCH_IRE_ILL | MATCH_IRE_ILL_GROUP)) &&
	    (ipif == NULL))
		return (NULL);

	irb_ptr = &ipst->ips_ip_cache_table_v6[IRE_ADDR_HASH_V6(*addr,
	    ipst->ips_ip6_cache_table_size)];
	rw_enter(&irb_ptr->irb_lock, RW_READER);
	for (ire = irb_ptr->irb_ire; ire; ire = ire->ire_next) {
		if (ire->ire_marks & IRE_MARK_CONDEMNED)
			continue;

		ASSERT(IN6_ARE_ADDR_EQUAL(&ire->ire_mask_v6, &ipv6_all_ones));
		if (ire_match_args_v6(ire, addr, &ire->ire_mask_v6, gateway,
		    type, ipif, zoneid, 0, tsl, flags)) {
			IRE_REFHOLD(ire);
			rw_exit(&irb_ptr->irb_lock);
			return (ire);
		}
	}
	rw_exit(&irb_ptr->irb_lock);
	return (NULL);
}

/*
 * Lookup cache. Don't return IRE_MARK_HIDDEN entries. Callers
 * should use ire_ctable_lookup with MATCH_IRE_MARK_HIDDEN to get
 * to the hidden ones.
 *
 * In general the zoneid has to match (where ALL_ZONES match all of them).
 * But for IRE_LOCAL we also need to handle the case where L2 should
 * conceptually loop back the packet. This is necessary since neither
 * Ethernet drivers nor Ethernet hardware loops back packets sent to their
 * own MAC address. This loopback is needed when the normal
 * routes (ignoring IREs with different zoneids) would send out the packet on
 * the same ill (or ill group) as the ill with which this IRE_LOCAL is
 * associated.
 *
 * Earlier versions of this code always matched an IRE_LOCAL independently of
 * the zoneid. We preserve that earlier behavior when
 * ip_restrict_interzone_loopback is turned off.
 */
ire_t *
ire_cache_lookup_v6(const in6_addr_t *addr, zoneid_t zoneid,
    const ts_label_t *tsl, ip_stack_t *ipst)
{
	irb_t *irb_ptr;
	ire_t *ire;

	irb_ptr = &ipst->ips_ip_cache_table_v6[IRE_ADDR_HASH_V6(*addr,
	    ipst->ips_ip6_cache_table_size)];
	rw_enter(&irb_ptr->irb_lock, RW_READER);
	for (ire = irb_ptr->irb_ire; ire; ire = ire->ire_next) {
		if (ire->ire_marks & (IRE_MARK_CONDEMNED|IRE_MARK_HIDDEN))
			continue;
		if (IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6, addr)) {
			/*
			 * Finally, check if the security policy has any
			 * restriction on using this route for the specified
			 * message.
			 */
			if (tsl != NULL &&
			    ire->ire_gw_secattr != NULL &&
			    tsol_ire_match_gwattr(ire, tsl) != 0) {
				continue;
			}

			if (zoneid == ALL_ZONES || ire->ire_zoneid == zoneid ||
			    ire->ire_zoneid == ALL_ZONES) {
				IRE_REFHOLD(ire);
				rw_exit(&irb_ptr->irb_lock);
				return (ire);
			}

			if (ire->ire_type == IRE_LOCAL) {
				if (ipst->ips_ip_restrict_interzone_loopback &&
				    !ire_local_ok_across_zones(ire, zoneid,
				    (void *)addr, tsl, ipst))
					continue;

				IRE_REFHOLD(ire);
				rw_exit(&irb_ptr->irb_lock);
				return (ire);
			}
		}
	}
	rw_exit(&irb_ptr->irb_lock);
	return (NULL);
}

/*
 * Locate the interface ire that is tied to the cache ire 'cire' via
 * cire->ire_ihandle.
 *
 * We are trying to create the cache ire for an onlink destn. or
 * gateway in 'cire'. We are called from ire_add_v6() in the IRE_IF_RESOLVER
 * case for xresolv interfaces, after the ire has come back from
 * an external resolver.
 */
static ire_t *
ire_ihandle_lookup_onlink_v6(ire_t *cire)
{
	ire_t	*ire;
	int	match_flags;
	int	i;
	int	j;
	irb_t	*irb_ptr;
	ip_stack_t	*ipst = cire->ire_ipst;

	ASSERT(cire != NULL);

	match_flags =  MATCH_IRE_TYPE | MATCH_IRE_IHANDLE | MATCH_IRE_MASK;
	/*
	 * We know that the mask of the interface ire equals cire->ire_cmask.
	 * (When ip_newroute_v6() created 'cire' for an on-link destn.
	 * it set its cmask from the interface ire's mask)
	 */
	ire = ire_ftable_lookup_v6(&cire->ire_addr_v6, &cire->ire_cmask_v6,
	    NULL, IRE_INTERFACE, NULL, NULL, ALL_ZONES, cire->ire_ihandle,
	    NULL, match_flags, ipst);
	if (ire != NULL)
		return (ire);
	/*
	 * If we didn't find an interface ire above, we can't declare failure.
	 * For backwards compatibility, we need to support prefix routes
	 * pointing to next hop gateways that are not on-link.
	 *
	 * In the resolver/noresolver case, ip_newroute_v6() thinks
	 * it is creating the cache ire for an onlink destination in 'cire'.
	 * But 'cire' is not actually onlink, because ire_ftable_lookup_v6()
	 * cheated it, by doing ire_route_lookup_v6() twice and returning an
	 * interface ire.
	 *
	 * Eg. default	-	gw1			(line 1)
	 *	gw1	-	gw2			(line 2)
	 *	gw2	-	hme0			(line 3)
	 *
	 * In the above example, ip_newroute_v6() tried to create the cache ire
	 * 'cire' for gw1, based on the interface route in line 3. The
	 * ire_ftable_lookup_v6() above fails, because there is
	 * no interface route to reach gw1. (it is gw2). We fall thru below.
	 *
	 * Do a brute force search based on the ihandle in a subset of the
	 * forwarding tables, corresponding to cire->ire_cmask_v6. Otherwise
	 * things become very complex, since we don't have 'pire' in this
	 * case. (Also note that this method is not possible in the offlink
	 * case because we don't know the mask)
	 */
	i = ip_mask_to_plen_v6(&cire->ire_cmask_v6);
	if ((ipst->ips_ip_forwarding_table_v6[i]) == NULL)
		return (NULL);
	for (j = 0; j < ipst->ips_ip6_ftable_hash_size; j++) {
		irb_ptr = &ipst->ips_ip_forwarding_table_v6[i][j];
		rw_enter(&irb_ptr->irb_lock, RW_READER);
		for (ire = irb_ptr->irb_ire; ire != NULL;
		    ire = ire->ire_next) {
			if (ire->ire_marks & IRE_MARK_CONDEMNED)
				continue;
			if ((ire->ire_type & IRE_INTERFACE) &&
			    (ire->ire_ihandle == cire->ire_ihandle)) {
				IRE_REFHOLD(ire);
				rw_exit(&irb_ptr->irb_lock);
				return (ire);
			}
		}
		rw_exit(&irb_ptr->irb_lock);
	}
	return (NULL);
}


/*
 * Locate the interface ire that is tied to the cache ire 'cire' via
 * cire->ire_ihandle.
 *
 * We are trying to create the cache ire for an offlink destn based
 * on the cache ire of the gateway in 'cire'. 'pire' is the prefix ire
 * as found by ip_newroute_v6(). We are called from ip_newroute_v6() in
 * the IRE_CACHE case.
 */
ire_t *
ire_ihandle_lookup_offlink_v6(ire_t *cire, ire_t *pire)
{
	ire_t	*ire;
	int	match_flags;
	in6_addr_t	gw_addr;
	ipif_t		*gw_ipif;
	ip_stack_t	*ipst = cire->ire_ipst;

	ASSERT(cire != NULL && pire != NULL);

	match_flags =  MATCH_IRE_TYPE | MATCH_IRE_IHANDLE | MATCH_IRE_MASK;
	/*
	 * ip_newroute_v6 calls ire_ftable_lookup with MATCH_IRE_ILL only
	 * for on-link hosts. We should never be here for onlink.
	 * Thus, use MATCH_IRE_ILL_GROUP.
	 */
	if (pire->ire_ipif != NULL)
		match_flags |= MATCH_IRE_ILL_GROUP;
	/*
	 * We know that the mask of the interface ire equals cire->ire_cmask.
	 * (When ip_newroute_v6() created 'cire' for an on-link destn. it set
	 * its cmask from the interface ire's mask)
	 */
	ire = ire_ftable_lookup_v6(&cire->ire_addr_v6, &cire->ire_cmask_v6, 0,
	    IRE_INTERFACE, pire->ire_ipif, NULL, ALL_ZONES, cire->ire_ihandle,
	    NULL, match_flags, ipst);
	if (ire != NULL)
		return (ire);
	/*
	 * If we didn't find an interface ire above, we can't declare failure.
	 * For backwards compatibility, we need to support prefix routes
	 * pointing to next hop gateways that are not on-link.
	 *
	 * Assume we are trying to ping some offlink destn, and we have the
	 * routing table below.
	 *
	 * Eg.	default	- gw1		<--- pire	(line 1)
	 *	gw1	- gw2				(line 2)
	 *	gw2	- hme0				(line 3)
	 *
	 * If we already have a cache ire for gw1 in 'cire', the
	 * ire_ftable_lookup_v6 above would have failed, since there is no
	 * interface ire to reach gw1. We will fallthru below.
	 *
	 * Here we duplicate the steps that ire_ftable_lookup_v6() did in
	 * getting 'cire' from 'pire', in the MATCH_IRE_RECURSIVE case.
	 * The differences are the following
	 * i.   We want the interface ire only, so we call
	 *	ire_ftable_lookup_v6() instead of ire_route_lookup_v6()
	 * ii.  We look for only prefix routes in the 1st call below.
	 * ii.  We want to match on the ihandle in the 2nd call below.
	 */
	match_flags =  MATCH_IRE_TYPE;
	if (pire->ire_ipif != NULL)
		match_flags |= MATCH_IRE_ILL_GROUP;

	mutex_enter(&pire->ire_lock);
	gw_addr = pire->ire_gateway_addr_v6;
	mutex_exit(&pire->ire_lock);
	ire = ire_ftable_lookup_v6(&gw_addr, 0, 0, IRE_OFFSUBNET,
	    pire->ire_ipif, NULL, ALL_ZONES, 0, NULL, match_flags, ipst);
	if (ire == NULL)
		return (NULL);
	/*
	 * At this point 'ire' corresponds to the entry shown in line 2.
	 * gw_addr is 'gw2' in the example above.
	 */
	mutex_enter(&ire->ire_lock);
	gw_addr = ire->ire_gateway_addr_v6;
	mutex_exit(&ire->ire_lock);
	gw_ipif = ire->ire_ipif;
	ire_refrele(ire);

	match_flags |= MATCH_IRE_IHANDLE;
	ire = ire_ftable_lookup_v6(&gw_addr, 0, 0, IRE_INTERFACE,
	    gw_ipif, NULL, ALL_ZONES, cire->ire_ihandle,
	    NULL, match_flags, ipst);
	return (ire);
}

/*
 * Return the IRE_LOOPBACK, IRE_IF_RESOLVER or IRE_IF_NORESOLVER
 * ire associated with the specified ipif.
 *
 * This might occasionally be called when IPIF_UP is not set since
 * the IPV6_MULTICAST_IF as well as creating interface routes
 * allows specifying a down ipif (ipif_lookup* match ipifs that are down).
 *
 * Note that if IPIF_NOLOCAL, IPIF_NOXMIT, or IPIF_DEPRECATED is set on
 * the ipif this routine might return NULL.
 * (Sometimes called as writer though not required by this function.)
 */
ire_t *
ipif_to_ire_v6(const ipif_t *ipif)
{
	ire_t	*ire;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ASSERT(ipif->ipif_isv6);
	if (ipif->ipif_ire_type == IRE_LOOPBACK) {
		ire = ire_ctable_lookup_v6(&ipif->ipif_v6lcl_addr, NULL,
		    IRE_LOOPBACK, ipif, ALL_ZONES, NULL,
		    (MATCH_IRE_TYPE | MATCH_IRE_IPIF), ipst);
	} else if (ipif->ipif_flags & IPIF_POINTOPOINT) {
		/* In this case we need to lookup destination address. */
		ire = ire_ftable_lookup_v6(&ipif->ipif_v6pp_dst_addr,
		    &ipv6_all_ones, NULL, IRE_INTERFACE, ipif, NULL, ALL_ZONES,
		    0, NULL, (MATCH_IRE_TYPE | MATCH_IRE_IPIF |
		    MATCH_IRE_MASK), ipst);
	} else {
		ire = ire_ftable_lookup_v6(&ipif->ipif_v6subnet,
		    &ipif->ipif_v6net_mask, NULL, IRE_INTERFACE, ipif, NULL,
		    ALL_ZONES, 0, NULL, (MATCH_IRE_TYPE | MATCH_IRE_IPIF |
		    MATCH_IRE_MASK), ipst);
	}
	return (ire);
}

/*
 * Return B_TRUE if a multirt route is resolvable
 * (or if no route is resolved yet), B_FALSE otherwise.
 * This only works in the global zone.
 */
boolean_t
ire_multirt_need_resolve_v6(const in6_addr_t *v6dstp, const ts_label_t *tsl,
    ip_stack_t *ipst)
{
	ire_t	*first_fire;
	ire_t	*first_cire;
	ire_t	*fire;
	ire_t	*cire;
	irb_t	*firb;
	irb_t	*cirb;
	int	unres_cnt = 0;
	boolean_t resolvable = B_FALSE;

	/* Retrieve the first IRE_HOST that matches the destination */
	first_fire = ire_ftable_lookup_v6(v6dstp, &ipv6_all_ones, 0, IRE_HOST,
	    NULL, NULL, ALL_ZONES, 0, tsl, MATCH_IRE_MASK | MATCH_IRE_TYPE |
	    MATCH_IRE_SECATTR, ipst);

	/* No route at all */
	if (first_fire == NULL) {
		return (B_TRUE);
	}

	firb = first_fire->ire_bucket;
	ASSERT(firb);

	/* Retrieve the first IRE_CACHE ire for that destination. */
	first_cire = ire_cache_lookup_v6(v6dstp, GLOBAL_ZONEID, tsl, ipst);

	/* No resolved route. */
	if (first_cire == NULL) {
		ire_refrele(first_fire);
		return (B_TRUE);
	}

	/* At least one route is resolved. */

	cirb = first_cire->ire_bucket;
	ASSERT(cirb);

	/* Count the number of routes to that dest that are declared. */
	IRB_REFHOLD(firb);
	for (fire = first_fire; fire != NULL; fire = fire->ire_next) {
		if (!(fire->ire_flags & RTF_MULTIRT))
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&fire->ire_addr_v6, v6dstp))
			continue;
		unres_cnt++;
	}
	IRB_REFRELE(firb);


	/* Then subtract the number of routes to that dst that are resolved */
	IRB_REFHOLD(cirb);
	for (cire = first_cire; cire != NULL; cire = cire->ire_next) {
		if (!(cire->ire_flags & RTF_MULTIRT))
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&cire->ire_addr_v6, v6dstp))
			continue;
		if (cire->ire_marks & (IRE_MARK_CONDEMNED|IRE_MARK_HIDDEN))
			continue;
		unres_cnt--;
	}
	IRB_REFRELE(cirb);

	/* At least one route is unresolved; search for a resolvable route. */
	if (unres_cnt > 0)
		resolvable = ire_multirt_lookup_v6(&first_cire, &first_fire,
		    MULTIRT_USESTAMP|MULTIRT_CACHEGW, tsl, ipst);

	if (first_fire)
		ire_refrele(first_fire);

	if (first_cire)
		ire_refrele(first_cire);

	return (resolvable);
}


/*
 * Return B_TRUE and update *ire_arg and *fire_arg
 * if at least one resolvable route is found.
 * Return B_FALSE otherwise (all routes are resolved or
 * the remaining unresolved routes are all unresolvable).
 * This only works in the global zone.
 */
boolean_t
ire_multirt_lookup_v6(ire_t **ire_arg, ire_t **fire_arg, uint32_t flags,
    const ts_label_t *tsl, ip_stack_t *ipst)
{
	clock_t	delta;
	ire_t	*best_fire = NULL;
	ire_t	*best_cire = NULL;
	ire_t	*first_fire;
	ire_t	*first_cire;
	ire_t	*fire;
	ire_t	*cire;
	irb_t	*firb = NULL;
	irb_t	*cirb = NULL;
	ire_t	*gw_ire;
	boolean_t	already_resolved;
	boolean_t	res;
	in6_addr_t	v6dst;
	in6_addr_t	v6gw;

	ip2dbg(("ire_multirt_lookup_v6: *ire_arg %p, *fire_arg %p, "
	    "flags %04x\n", (void *)*ire_arg, (void *)*fire_arg, flags));

	ASSERT(ire_arg);
	ASSERT(fire_arg);

	/* Not an IRE_HOST ire; give up. */
	if ((*fire_arg == NULL) ||
	    ((*fire_arg)->ire_type != IRE_HOST)) {
		return (B_FALSE);
	}

	/* This is the first IRE_HOST ire for that destination. */
	first_fire = *fire_arg;
	firb = first_fire->ire_bucket;
	ASSERT(firb);

	mutex_enter(&first_fire->ire_lock);
	v6dst = first_fire->ire_addr_v6;
	mutex_exit(&first_fire->ire_lock);

	ip2dbg(("ire_multirt_lookup_v6: dst %08x\n",
	    ntohl(V4_PART_OF_V6(v6dst))));

	/*
	 * Retrieve the first IRE_CACHE ire for that destination;
	 * if we don't find one, no route for that dest is
	 * resolved yet.
	 */
	first_cire = ire_cache_lookup_v6(&v6dst, GLOBAL_ZONEID, tsl, ipst);
	if (first_cire) {
		cirb = first_cire->ire_bucket;
	}

	ip2dbg(("ire_multirt_lookup_v6: first_cire %p\n", (void *)first_cire));

	/*
	 * Search for a resolvable route, giving the top priority
	 * to routes that can be resolved without any call to the resolver.
	 */
	IRB_REFHOLD(firb);

	if (!IN6_IS_ADDR_MULTICAST(&v6dst)) {
		/*
		 * For all multiroute IRE_HOST ires for that destination,
		 * check if the route via the IRE_HOST's gateway is
		 * resolved yet.
		 */
		for (fire = first_fire; fire != NULL; fire = fire->ire_next) {

			if (!(fire->ire_flags & RTF_MULTIRT))
				continue;
			if (!IN6_ARE_ADDR_EQUAL(&fire->ire_addr_v6, &v6dst))
				continue;

			if (fire->ire_gw_secattr != NULL &&
			    tsol_ire_match_gwattr(fire, tsl) != 0) {
				continue;
			}

			mutex_enter(&fire->ire_lock);
			v6gw = fire->ire_gateway_addr_v6;
			mutex_exit(&fire->ire_lock);

			ip2dbg(("ire_multirt_lookup_v6: fire %p, "
			    "ire_addr %08x, ire_gateway_addr %08x\n",
			    (void *)fire,
			    ntohl(V4_PART_OF_V6(fire->ire_addr_v6)),
			    ntohl(V4_PART_OF_V6(v6gw))));

			already_resolved = B_FALSE;

			if (first_cire) {
				ASSERT(cirb);

				IRB_REFHOLD(cirb);
				/*
				 * For all IRE_CACHE ires for that
				 * destination.
				 */
				for (cire = first_cire;
				    cire != NULL;
				    cire = cire->ire_next) {

					if (!(cire->ire_flags & RTF_MULTIRT))
						continue;
					if (!IN6_ARE_ADDR_EQUAL(
					    &cire->ire_addr_v6, &v6dst))
						continue;
					if (cire->ire_marks &
					    (IRE_MARK_CONDEMNED|
					    IRE_MARK_HIDDEN))
						continue;

					if (cire->ire_gw_secattr != NULL &&
					    tsol_ire_match_gwattr(cire,
					    tsl) != 0) {
						continue;
					}

					/*
					 * Check if the IRE_CACHE's gateway
					 * matches the IRE_HOST's gateway.
					 */
					if (IN6_ARE_ADDR_EQUAL(
					    &cire->ire_gateway_addr_v6,
					    &v6gw)) {
						already_resolved = B_TRUE;
						break;
					}
				}
				IRB_REFRELE(cirb);
			}

			/*
			 * This route is already resolved;
			 * proceed with next one.
			 */
			if (already_resolved) {
				ip2dbg(("ire_multirt_lookup_v6: found cire %p, "
				    "already resolved\n", (void *)cire));
				continue;
			}

			/*
			 * The route is unresolved; is it actually
			 * resolvable, i.e. is there a cache or a resolver
			 * for the gateway?
			 */
			gw_ire = ire_route_lookup_v6(&v6gw, 0, 0, 0, NULL, NULL,
			    ALL_ZONES, tsl, MATCH_IRE_RECURSIVE |
			    MATCH_IRE_SECATTR, ipst);

			ip2dbg(("ire_multirt_lookup_v6: looked up gw_ire %p\n",
			    (void *)gw_ire));

			/*
			 * This route can be resolved without any call to the
			 * resolver; if the MULTIRT_CACHEGW flag is set,
			 * give the top priority to this ire and exit the
			 * loop.
			 * This occurs when an resolver reply is processed
			 * through ip_wput_nondata()
			 */
			if ((flags & MULTIRT_CACHEGW) &&
			    (gw_ire != NULL) &&
			    (gw_ire->ire_type & IRE_CACHETABLE)) {
				/*
				 * Release the resolver associated to the
				 * previous candidate best ire, if any.
				 */
				if (best_cire) {
					ire_refrele(best_cire);
					ASSERT(best_fire);
				}

				best_fire = fire;
				best_cire = gw_ire;

				ip2dbg(("ire_multirt_lookup_v6: found top prio "
				    "best_fire %p, best_cire %p\n",
				    (void *)best_fire, (void *)best_cire));
				break;
			}

			/*
			 * Compute the time elapsed since our preceding
			 * attempt to  resolve that route.
			 * If the MULTIRT_USESTAMP flag is set, we take that
			 * route into account only if this time interval
			 * exceeds ip_multirt_resolution_interval;
			 * this prevents us from attempting to resolve a
			 * broken route upon each sending of a packet.
			 */
			delta = lbolt - fire->ire_last_used_time;
			delta = TICK_TO_MSEC(delta);

			res = (boolean_t)
			    ((delta > ipst->
			    ips_ip_multirt_resolution_interval) ||
			    (!(flags & MULTIRT_USESTAMP)));

			ip2dbg(("ire_multirt_lookup_v6: fire %p, delta %lu, "
			    "res %d\n",
			    (void *)fire, delta, res));

			if (res) {
				/*
				 * A resolver exists for the gateway: save
				 * the current IRE_HOST ire as a candidate
				 * best ire. If we later discover that a
				 * top priority ire exists (i.e. no need to
				 * call the resolver), then this new ire
				 * will be preferred to the current one.
				 */
				if (gw_ire != NULL) {
					if (best_fire == NULL) {
						ASSERT(best_cire == NULL);

						best_fire = fire;
						best_cire = gw_ire;

						ip2dbg(("ire_multirt_lookup_v6:"
						    "found candidate "
						    "best_fire %p, "
						    "best_cire %p\n",
						    (void *)best_fire,
						    (void *)best_cire));

						/*
						 * If MULTIRT_CACHEGW is not
						 * set, we ignore the top
						 * priority ires that can
						 * be resolved without any
						 * call to the resolver;
						 * In that case, there is
						 * actually no need
						 * to continue the loop.
						 */
						if (!(flags &
						    MULTIRT_CACHEGW)) {
							break;
						}
						continue;
					}
				} else {
					/*
					 * No resolver for the gateway: the
					 * route is not resolvable.
					 * If the MULTIRT_SETSTAMP flag is
					 * set, we stamp the IRE_HOST ire,
					 * so we will not select it again
					 * during this resolution interval.
					 */
					if (flags & MULTIRT_SETSTAMP)
						fire->ire_last_used_time =
						    lbolt;
				}
			}

			if (gw_ire != NULL)
				ire_refrele(gw_ire);
		}
	} else { /* IN6_IS_ADDR_MULTICAST(&v6dst) */

		for (fire = first_fire;
		    fire != NULL;
		    fire = fire->ire_next) {

			if (!(fire->ire_flags & RTF_MULTIRT))
				continue;
			if (!IN6_ARE_ADDR_EQUAL(&fire->ire_addr_v6, &v6dst))
				continue;

			if (fire->ire_gw_secattr != NULL &&
			    tsol_ire_match_gwattr(fire, tsl) != 0) {
				continue;
			}

			already_resolved = B_FALSE;

			mutex_enter(&fire->ire_lock);
			v6gw = fire->ire_gateway_addr_v6;
			mutex_exit(&fire->ire_lock);

			gw_ire = ire_ftable_lookup_v6(&v6gw, 0, 0,
			    IRE_INTERFACE, NULL, NULL, ALL_ZONES, 0, tsl,
			    MATCH_IRE_RECURSIVE | MATCH_IRE_TYPE |
			    MATCH_IRE_SECATTR, ipst);

			/* No resolver for the gateway; we skip this ire. */
			if (gw_ire == NULL) {
				continue;
			}

			if (first_cire) {

				IRB_REFHOLD(cirb);
				/*
				 * For all IRE_CACHE ires for that
				 * destination.
				 */
				for (cire = first_cire;
				    cire != NULL;
				    cire = cire->ire_next) {

					if (!(cire->ire_flags & RTF_MULTIRT))
						continue;
					if (!IN6_ARE_ADDR_EQUAL(
					    &cire->ire_addr_v6, &v6dst))
						continue;
					if (cire->ire_marks &
					    (IRE_MARK_CONDEMNED|
					    IRE_MARK_HIDDEN))
						continue;

					if (cire->ire_gw_secattr != NULL &&
					    tsol_ire_match_gwattr(cire,
					    tsl) != 0) {
						continue;
					}

					/*
					 * Cache entries are linked to the
					 * parent routes using the parent handle
					 * (ire_phandle). If no cache entry has
					 * the same handle as fire, fire is
					 * still unresolved.
					 */
					ASSERT(cire->ire_phandle != 0);
					if (cire->ire_phandle ==
					    fire->ire_phandle) {
						already_resolved = B_TRUE;
						break;
					}
				}
				IRB_REFRELE(cirb);
			}

			/*
			 * This route is already resolved; proceed with
			 * next one.
			 */
			if (already_resolved) {
				ire_refrele(gw_ire);
				continue;
			}

			/*
			 * Compute the time elapsed since our preceding
			 * attempt to resolve that route.
			 * If the MULTIRT_USESTAMP flag is set, we take
			 * that route into account only if this time
			 * interval exceeds ip_multirt_resolution_interval;
			 * this prevents us from attempting to resolve a
			 * broken route upon each sending of a packet.
			 */
			delta = lbolt - fire->ire_last_used_time;
			delta = TICK_TO_MSEC(delta);

			res = (boolean_t)
			    ((delta > ipst->
			    ips_ip_multirt_resolution_interval) ||
			    (!(flags & MULTIRT_USESTAMP)));

			ip3dbg(("ire_multirt_lookup_v6: fire %p, delta %lx, "
			    "flags %04x, res %d\n",
			    (void *)fire, delta, flags, res));

			if (res) {
				if (best_cire) {
					/*
					 * Release the resolver associated
					 * to the preceding candidate best
					 * ire, if any.
					 */
					ire_refrele(best_cire);
					ASSERT(best_fire);
				}
				best_fire = fire;
				best_cire = gw_ire;
				continue;
			}

			ire_refrele(gw_ire);
		}
	}

	if (best_fire) {
		IRE_REFHOLD(best_fire);
	}
	IRB_REFRELE(firb);

	/* Release the first IRE_CACHE we initially looked up, if any. */
	if (first_cire)
		ire_refrele(first_cire);

	/* Found a resolvable route. */
	if (best_fire) {
		ASSERT(best_cire);

		if (*fire_arg)
			ire_refrele(*fire_arg);
		if (*ire_arg)
			ire_refrele(*ire_arg);

		/*
		 * Update the passed arguments with the
		 * resolvable multirt route we found
		 */
		*fire_arg = best_fire;
		*ire_arg = best_cire;

		ip2dbg(("ire_multirt_lookup_v6: returning B_TRUE, "
		    "*fire_arg %p, *ire_arg %p\n",
		    (void *)best_fire, (void *)best_cire));

		return (B_TRUE);
	}

	ASSERT(best_cire == NULL);

	ip2dbg(("ire_multirt_lookup_v6: returning B_FALSE, *fire_arg %p, "
	    "*ire_arg %p\n",
	    (void *)*fire_arg, (void *)*ire_arg));

	/* No resolvable route. */
	return (B_FALSE);
}


/*
 * Find an IRE_OFFSUBNET IRE entry for the multicast address 'v6dstp'
 * that goes through 'ipif'. As a fallback, a route that goes through
 * ipif->ipif_ill can be returned.
 */
ire_t *
ipif_lookup_multi_ire_v6(ipif_t *ipif, const in6_addr_t *v6dstp)
{
	ire_t	*ire;
	ire_t	*save_ire = NULL;
	ire_t   *gw_ire;
	irb_t   *irb;
	in6_addr_t v6gw;
	int	match_flags = MATCH_IRE_TYPE | MATCH_IRE_ILL;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ire = ire_ftable_lookup_v6(v6dstp, 0, 0, 0, NULL, NULL, ALL_ZONES, 0,
	    NULL, MATCH_IRE_DEFAULT, ipst);

	if (ire == NULL)
		return (NULL);

	irb = ire->ire_bucket;
	ASSERT(irb);

	IRB_REFHOLD(irb);
	ire_refrele(ire);
	for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (!IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6, v6dstp) ||
		    (ipif->ipif_zoneid != ire->ire_zoneid &&
		    ire->ire_zoneid != ALL_ZONES)) {
			continue;
		}

		switch (ire->ire_type) {
		case IRE_DEFAULT:
		case IRE_PREFIX:
		case IRE_HOST:
			mutex_enter(&ire->ire_lock);
			v6gw = ire->ire_gateway_addr_v6;
			mutex_exit(&ire->ire_lock);
			gw_ire = ire_ftable_lookup_v6(&v6gw, 0, 0,
			    IRE_INTERFACE, ipif, NULL, ALL_ZONES, 0,
			    NULL, match_flags, ipst);

			if (gw_ire != NULL) {
				if (save_ire != NULL) {
					ire_refrele(save_ire);
				}
				IRE_REFHOLD(ire);
				if (gw_ire->ire_ipif == ipif) {
					ire_refrele(gw_ire);

					IRB_REFRELE(irb);
					return (ire);
				}
				ire_refrele(gw_ire);
				save_ire = ire;
			}
			break;
		case IRE_IF_NORESOLVER:
		case IRE_IF_RESOLVER:
			if (ire->ire_ipif == ipif) {
				if (save_ire != NULL) {
					ire_refrele(save_ire);
				}
				IRE_REFHOLD(ire);

				IRB_REFRELE(irb);
				return (ire);
			}
			break;
		}
	}
	IRB_REFRELE(irb);

	return (save_ire);
}
