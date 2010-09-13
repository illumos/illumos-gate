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
 * Copyright (c) 1990 Mentat Inc.
 */

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
#include <inet/tunables.h>
#include <sys/kmem.h>
#include <sys/zone.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#define	IS_DEFAULT_ROUTE_V6(ire)	\
	(((ire)->ire_type & IRE_DEFAULT) || \
	    (((ire)->ire_type & IRE_INTERFACE) && \
	    (IN6_IS_ADDR_UNSPECIFIED(&(ire)->ire_addr_v6))))

static	ire_t	ire_null;

static ire_t *
ire_ftable_lookup_impl_v6(const in6_addr_t *addr, const in6_addr_t *mask,
    const in6_addr_t *gateway, int type, const ill_t *ill,
    zoneid_t zoneid, const ts_label_t *tsl, int flags,
    ip_stack_t *ipst);

/*
 * Initialize the ire that is specific to IPv6 part and call
 * ire_init_common to finish it.
 * Returns zero or errno.
 */
int
ire_init_v6(ire_t *ire, const in6_addr_t *v6addr, const in6_addr_t *v6mask,
    const in6_addr_t *v6gateway, ushort_t type, ill_t *ill,
    zoneid_t zoneid, uint_t flags, tsol_gc_t *gc, ip_stack_t *ipst)
{
	int error;

	/*
	 * Reject IRE security attmakeribute creation/initialization
	 * if system is not running in Trusted mode.
	 */
	if (gc != NULL && !is_system_labeled())
		return (EINVAL);

	BUMP_IRE_STATS(ipst->ips_ire_stats_v6, ire_stats_alloced);
	if (v6addr != NULL)
		ire->ire_addr_v6 = *v6addr;
	if (v6gateway != NULL)
		ire->ire_gateway_addr_v6 = *v6gateway;

	/* Make sure we don't have stray values in some fields */
	switch (type) {
	case IRE_LOOPBACK:
	case IRE_HOST:
	case IRE_LOCAL:
	case IRE_IF_CLONE:
		ire->ire_mask_v6 = ipv6_all_ones;
		ire->ire_masklen = IPV6_ABITS;
		break;
	case IRE_PREFIX:
	case IRE_DEFAULT:
	case IRE_IF_RESOLVER:
	case IRE_IF_NORESOLVER:
		if (v6mask != NULL) {
			ire->ire_mask_v6 = *v6mask;
			ire->ire_masklen =
			    ip_mask_to_plen_v6(&ire->ire_mask_v6);
		}
		break;
	case IRE_MULTICAST:
	case IRE_NOROUTE:
		ASSERT(v6mask == NULL);
		break;
	default:
		ASSERT(0);
		return (EINVAL);
	}

	error = ire_init_common(ire, type, ill, zoneid, flags, IPV6_VERSION,
	    gc, ipst);
	if (error != NULL)
		return (error);

	/* Determine which function pointers to use */
	ire->ire_postfragfn = ip_xmit;		/* Common case */

	switch (ire->ire_type) {
	case IRE_LOCAL:
		ire->ire_sendfn = ire_send_local_v6;
		ire->ire_recvfn = ire_recv_local_v6;
		ASSERT(ire->ire_ill != NULL);
		if (ire->ire_ill->ill_flags & ILLF_NOACCEPT)
			ire->ire_recvfn = ire_recv_noaccept_v6;
		break;
	case IRE_LOOPBACK:
		ire->ire_sendfn = ire_send_local_v6;
		ire->ire_recvfn = ire_recv_loopback_v6;
		break;
	case IRE_MULTICAST:
		ire->ire_postfragfn = ip_postfrag_loopcheck;
		ire->ire_sendfn = ire_send_multicast_v6;
		ire->ire_recvfn = ire_recv_multicast_v6;
		break;
	default:
		/*
		 * For IRE_IF_ALL and IRE_OFFLINK we forward received
		 * packets by default.
		 */
		ire->ire_sendfn = ire_send_wire_v6;
		ire->ire_recvfn = ire_recv_forward_v6;
		break;
	}
	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		ire->ire_sendfn = ire_send_noroute_v6;
		ire->ire_recvfn = ire_recv_noroute_v6;
	} else if (ire->ire_flags & RTF_MULTIRT) {
		ire->ire_postfragfn = ip_postfrag_multirt_v6;
		ire->ire_sendfn = ire_send_multirt_v6;
		ire->ire_recvfn = ire_recv_multirt_v6;
	}
	ire->ire_nce_capable = ire_determine_nce_capable(ire);
	return (0);
}

/*
 * ire_create_v6 is called to allocate and initialize a new IRE.
 *
 * NOTE : This is called as writer sometimes though not required
 * by this function.
 */
/* ARGSUSED */
ire_t *
ire_create_v6(const in6_addr_t *v6addr, const in6_addr_t *v6mask,
    const in6_addr_t *v6gateway, ushort_t type, ill_t *ill, zoneid_t zoneid,
    uint_t flags, tsol_gc_t *gc, ip_stack_t *ipst)
{
	ire_t	*ire;
	int	error;

	ASSERT(!IN6_IS_ADDR_V4MAPPED(v6addr));

	ire = kmem_cache_alloc(ire_cache, KM_NOSLEEP);
	if (ire == NULL) {
		DTRACE_PROBE(kmem__cache__alloc);
		return (NULL);
	}
	*ire = ire_null;

	error = ire_init_v6(ire, v6addr, v6mask, v6gateway,
	    type, ill, zoneid, flags, gc, ipst);

	if (error != 0) {
		DTRACE_PROBE2(ire__init__v6, ire_t *, ire, int, error);
		kmem_cache_free(ire_cache, ire);
		return (NULL);
	}
	return (ire);
}

/*
 * Find the ill matching a multicast group.
 * Allows different routes for multicast addresses
 * in the unicast routing table (akin to FF::0/8 but could be more specific)
 * which point at different interfaces. This is used when IPV6_MULTICAST_IF
 * isn't specified (when sending) and when IPV6_JOIN_GROUP doesn't
 * specify the interface to join on.
 *
 * Supports link-local addresses by using ire_route_recursive which follows
 * the ill when recursing.
 *
 * To handle CGTP, since we don't have a separate IRE_MULTICAST for each group
 * and the MULTIRT property can be different for different groups, we
 * extract RTF_MULTIRT from the special unicast route added for a group
 * with CGTP and pass that back in the multirtp argument.
 * This is used in ip_set_destination etc to set ixa_postfragfn for multicast.
 * We have a setsrcp argument for the same reason.
 */
ill_t *
ire_lookup_multi_ill_v6(const in6_addr_t *group, zoneid_t zoneid,
    ip_stack_t *ipst, boolean_t *multirtp, in6_addr_t *setsrcp)
{
	ire_t	*ire;
	ill_t	*ill;

	ire = ire_route_recursive_v6(group, 0, NULL, zoneid, NULL,
	    MATCH_IRE_DSTONLY, IRR_NONE, 0, ipst, setsrcp, NULL, NULL);
	ASSERT(ire != NULL);

	if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		ire_refrele(ire);
		return (NULL);
	}

	if (multirtp != NULL)
		*multirtp = (ire->ire_flags & RTF_MULTIRT) != 0;

	ill = ire_nexthop_ill(ire);
	ire_refrele(ire);
	return (ill);
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
	if (plen == 0)
		return (bitmask);

	ptr = (uint32_t *)bitmask;
	while (plen > 32) {
		*ptr++ = 0xffffffffU;
		plen -= 32;
	}
	*ptr = htonl(0xffffffffU << (32 - plen));
	return (bitmask);
}

/*
 * Add a fully initialized IPv6 IRE to the forwarding table.
 * This returns NULL on failure, or a held IRE on success.
 * Normally the returned IRE is the same as the argument. But a different
 * IRE will be returned if the added IRE is deemed identical to an existing
 * one. In that case ire_identical_ref will be increased.
 * The caller always needs to do an ire_refrele() on the returned IRE.
 */
ire_t *
ire_add_v6(ire_t *ire)
{
	ire_t	*ire1;
	int	mask_table_index;
	irb_t	*irb_ptr;
	ire_t	**irep;
	int	match_flags;
	int	error;
	ip_stack_t	*ipst = ire->ire_ipst;

	ASSERT(ire->ire_ipversion == IPV6_VERSION);

	/* Make sure the address is properly masked. */
	V6_MASK_COPY(ire->ire_addr_v6, ire->ire_mask_v6, ire->ire_addr_v6);

	mask_table_index = ip_mask_to_plen_v6(&ire->ire_mask_v6);
	if ((ipst->ips_ip_forwarding_table_v6[mask_table_index]) == NULL) {
		irb_t *ptr;
		int i;

		ptr = (irb_t *)mi_zalloc((ipst->ips_ip6_ftable_hash_size *
		    sizeof (irb_t)));
		if (ptr == NULL) {
			ire_delete(ire);
			return (NULL);
		}
		for (i = 0; i < ipst->ips_ip6_ftable_hash_size; i++) {
			rw_init(&ptr[i].irb_lock, NULL, RW_DEFAULT, NULL);
			ptr[i].irb_ipst = ipst;
		}
		mutex_enter(&ipst->ips_ire_ft_init_lock);
		if (ipst->ips_ip_forwarding_table_v6[mask_table_index] ==
		    NULL) {
			ipst->ips_ip_forwarding_table_v6[mask_table_index] =
			    ptr;
			mutex_exit(&ipst->ips_ire_ft_init_lock);
		} else {
			/*
			 * Some other thread won the race in
			 * initializing the forwarding table at the
			 * same index.
			 */
			mutex_exit(&ipst->ips_ire_ft_init_lock);
			for (i = 0; i < ipst->ips_ip6_ftable_hash_size; i++) {
				rw_destroy(&ptr[i].irb_lock);
			}
			mi_free(ptr);
		}
	}
	irb_ptr = &(ipst->ips_ip_forwarding_table_v6[mask_table_index][
	    IRE_ADDR_MASK_HASH_V6(ire->ire_addr_v6, ire->ire_mask_v6,
	    ipst->ips_ip6_ftable_hash_size)]);

	match_flags = (MATCH_IRE_MASK | MATCH_IRE_TYPE | MATCH_IRE_GW);
	if (ire->ire_ill != NULL)
		match_flags |= MATCH_IRE_ILL;
	/*
	 * Start the atomic add of the ire. Grab the bucket lock and the
	 * ill lock. Check for condemned.
	 */
	error = ire_atomic_start(irb_ptr, ire);
	if (error != 0) {
		ire_delete(ire);
		return (NULL);
	}

	/*
	 * If we are creating a hidden IRE, make sure we search for
	 * hidden IREs when searching for duplicates below.
	 * Otherwise, we might find an IRE on some other interface
	 * that's not marked hidden.
	 */
	if (ire->ire_testhidden)
		match_flags |= MATCH_IRE_TESTHIDDEN;

	/*
	 * Atomically check for duplicate and insert in the table.
	 */
	for (ire1 = irb_ptr->irb_ire; ire1 != NULL; ire1 = ire1->ire_next) {
		if (IRE_IS_CONDEMNED(ire1))
			continue;
		/*
		 * Here we need an exact match on zoneid, i.e.,
		 * ire_match_args doesn't fit.
		 */
		if (ire1->ire_zoneid != ire->ire_zoneid)
			continue;

		if (ire1->ire_type != ire->ire_type)
			continue;

		/*
		 * Note: We do not allow multiple routes that differ only
		 * in the gateway security attributes; such routes are
		 * considered duplicates.
		 * To change that we explicitly have to treat them as
		 * different here.
		 */
		if (ire_match_args_v6(ire1, &ire->ire_addr_v6,
		    &ire->ire_mask_v6, &ire->ire_gateway_addr_v6,
		    ire->ire_type, ire->ire_ill, ire->ire_zoneid, NULL,
		    match_flags)) {
			/*
			 * Return the old ire after doing a REFHOLD.
			 * As most of the callers continue to use the IRE
			 * after adding, we return a held ire. This will
			 * avoid a lookup in the caller again. If the callers
			 * don't want to use it, they need to do a REFRELE.
			 *
			 * We only allow exactly one IRE_IF_CLONE for any dst,
			 * so, if the is an IF_CLONE, return the ire without
			 * an identical_ref, but with an ire_ref held.
			 */
			if (ire->ire_type != IRE_IF_CLONE) {
				atomic_add_32(&ire1->ire_identical_ref, 1);
				DTRACE_PROBE2(ire__add__exist, ire_t *, ire1,
				    ire_t *, ire);
			}
			ip1dbg(("found dup ire existing %p new %p",
			    (void *)ire1, (void *)ire));
			ire_refhold(ire1);
			ire_atomic_end(irb_ptr, ire);
			ire_delete(ire);
			return (ire1);
		}
	}

	/*
	 * Normally we do head insertion since most things do not care about
	 * the order of the IREs in the bucket.
	 * However, due to shared-IP zones (and restrict_interzone_loopback)
	 * we can have an IRE_LOCAL as well as IRE_IF_CLONE for the same
	 * address. For that reason we do tail insertion for IRE_IF_CLONE.
	 */
	irep = (ire_t **)irb_ptr;
	if (ire->ire_type & IRE_IF_CLONE) {
		while ((ire1 = *irep) != NULL)
			irep = &ire1->ire_next;
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
	ire_refhold_locked(ire);
	BUMP_IRE_STATS(ipst->ips_ire_stats_v6, ire_stats_inserted);
	irb_ptr->irb_ire_cnt++;

	if (ire->ire_ill != NULL) {
		DTRACE_PROBE3(ill__incr__cnt, (ill_t *), ire->ire_ill,
		    (char *), "ire", (void *), ire);
		ire->ire_ill->ill_ire_cnt++;
		ASSERT(ire->ire_ill->ill_ire_cnt != 0);	/* Wraparound */
	}
	ire_atomic_end(irb_ptr, ire);

	/* Make any caching of the IREs be notified or updated */
	ire_flush_cache_v6(ire, IRE_FLUSH_ADD);

	return (ire);
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
		irb_refhold(irb);
		for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
			if (!(ire->ire_flags & RTF_DYNAMIC))
				continue;
			mutex_enter(&ire->ire_lock);
			gw_addr_v6 = ire->ire_gateway_addr_v6;
			mutex_exit(&ire->ire_lock);
			if (IN6_ARE_ADDR_EQUAL(&gw_addr_v6, gateway))
				ire_delete(ire);
		}
		irb_refrele(irb);
	}
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

	/*
	 * Make sure ire_generation increases from ire_flush_cache happen
	 * after any lookup/reader has read ire_generation.
	 * Since the rw_enter makes us wait until any lookup/reader has
	 * completed we can exit the lock immediately.
	 */
	rw_enter(&ipst->ips_ip6_ire_head_lock, RW_WRITER);
	rw_exit(&ipst->ips_ip6_ire_head_lock);

	ASSERT(ire->ire_refcnt >= 1);
	ASSERT(ire->ire_ipversion == IPV6_VERSION);

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

	/*
	 * If we are deleting an IRE_INTERFACE then we make sure we also
	 * delete any IRE_IF_CLONE that has been created from it.
	 * Those are always in ire_dep_children.
	 */
	if ((ire->ire_type & IRE_INTERFACE) && ire->ire_dep_children != 0)
		ire_dep_delete_if_clone(ire);

	/* Remove from parent dependencies and child */
	rw_enter(&ipst->ips_ire_dep_lock, RW_WRITER);
	if (ire->ire_dep_parent != NULL) {
		ire_dep_remove(ire);
	}
	while (ire->ire_dep_children != NULL)
		ire_dep_remove(ire->ire_dep_children);
	rw_exit(&ipst->ips_ire_dep_lock);
}

/*
 * When an IRE is added or deleted this routine is called to make sure
 * any caching of IRE information is notified or updated.
 *
 * The flag argument indicates if the flush request is due to addition
 * of new route (IRE_FLUSH_ADD), deletion of old route (IRE_FLUSH_DELETE),
 * or a change to ire_gateway_addr (IRE_FLUSH_GWCHANGE).
 */
void
ire_flush_cache_v6(ire_t *ire, int flag)
{
	ip_stack_t *ipst = ire->ire_ipst;

	/*
	 * IRE_IF_CLONE ire's don't provide any new information
	 * than the parent from which they are cloned, so don't
	 * perturb the generation numbers.
	 */
	if (ire->ire_type & IRE_IF_CLONE)
		return;

	/*
	 * Ensure that an ire_add during a lookup serializes the updates of
	 * the generation numbers under ire_head_lock so that the lookup gets
	 * either the old ire and old generation number, or a new ire and new
	 * generation number.
	 */
	rw_enter(&ipst->ips_ip6_ire_head_lock, RW_WRITER);

	/*
	 * If a route was just added, we need to notify everybody that
	 * has cached an IRE_NOROUTE since there might now be a better
	 * route for them.
	 */
	if (flag == IRE_FLUSH_ADD) {
		ire_increment_generation(ipst->ips_ire_reject_v6);
		ire_increment_generation(ipst->ips_ire_blackhole_v6);
	}

	/* Adding a default can't otherwise provide a better route */
	if (ire->ire_type == IRE_DEFAULT && flag == IRE_FLUSH_ADD) {
		rw_exit(&ipst->ips_ip6_ire_head_lock);
		return;
	}

	switch (flag) {
	case IRE_FLUSH_DELETE:
	case IRE_FLUSH_GWCHANGE:
		/*
		 * Update ire_generation for all ire_dep_children chains
		 * starting with this IRE
		 */
		ire_dep_incr_generation(ire);
		break;
	case IRE_FLUSH_ADD: {
		in6_addr_t	addr;
		in6_addr_t	mask;
		ip_stack_t	*ipst = ire->ire_ipst;
		uint_t		masklen;

		/*
		 * Find an IRE which is a shorter match than the ire to be added
		 * For any such IRE (which we repeat) we update the
		 * ire_generation the same way as in the delete case.
		 */
		addr = ire->ire_addr_v6;
		mask = ire->ire_mask_v6;
		masklen = ip_mask_to_plen_v6(&mask);

		ire = ire_ftable_lookup_impl_v6(&addr, &mask, NULL, 0, NULL,
		    ALL_ZONES, NULL, MATCH_IRE_SHORTERMASK, ipst);
		while (ire != NULL) {
			/* We need to handle all in the same bucket */
			irb_increment_generation(ire->ire_bucket);

			mask = ire->ire_mask_v6;
			ASSERT(masklen > ip_mask_to_plen_v6(&mask));
			masklen = ip_mask_to_plen_v6(&mask);
			ire_refrele(ire);
			ire = ire_ftable_lookup_impl_v6(&addr, &mask, NULL, 0,
			    NULL, ALL_ZONES, NULL, MATCH_IRE_SHORTERMASK, ipst);
		}
		}
		break;
	}
	rw_exit(&ipst->ips_ip6_ire_head_lock);
}

/*
 * Matches the arguments passed with the values in the ire.
 *
 * Note: for match types that match using "ill" passed in, ill
 * must be checked for non-NULL before calling this routine.
 */
boolean_t
ire_match_args_v6(ire_t *ire, const in6_addr_t *addr, const in6_addr_t *mask,
    const in6_addr_t *gateway, int type, const ill_t *ill, zoneid_t zoneid,
    const ts_label_t *tsl, int match_flags)
{
	in6_addr_t masked_addr;
	in6_addr_t gw_addr_v6;
	ill_t *ire_ill = NULL, *dst_ill;
	ip_stack_t *ipst = ire->ire_ipst;

	ASSERT(ire->ire_ipversion == IPV6_VERSION);
	ASSERT(addr != NULL);
	ASSERT(mask != NULL);
	ASSERT((!(match_flags & MATCH_IRE_GW)) || gateway != NULL);
	ASSERT((!(match_flags & (MATCH_IRE_ILL|MATCH_IRE_SRC_ILL))) ||
	    (ill != NULL && ill->ill_isv6));

	/*
	 * If MATCH_IRE_TESTHIDDEN is set, then only return the IRE if it
	 * is in fact hidden, to ensure the caller gets the right one.
	 */
	if (ire->ire_testhidden) {
		if (!(match_flags & MATCH_IRE_TESTHIDDEN))
			return (B_FALSE);
	}

	if (zoneid != ALL_ZONES && zoneid != ire->ire_zoneid &&
	    ire->ire_zoneid != ALL_ZONES) {
		/*
		 * If MATCH_IRE_ZONEONLY has been set and the supplied zoneid
		 * does not match that of ire_zoneid, a failure to
		 * match is reported at this point. Otherwise, since some IREs
		 * that are available in the global zone can be used in local
		 * zones, additional checks need to be performed:
		 *
		 * IRE_LOOPBACK
		 *	entries should never be matched in this situation.
		 *	Each zone has its own IRE_LOOPBACK.
		 *
		 * IRE_LOCAL
		 *	We allow them for any zoneid. ire_route_recursive
		 *	does additional checks when
		 *	ip_restrict_interzone_loopback is set.
		 *
		 * If ill_usesrc_ifindex is set
		 *	Then we check if the zone has a valid source address
		 *	on the usesrc ill.
		 *
		 * If ire_ill is set, then check that the zone has an ipif
		 *	on that ill.
		 *
		 * Outside of this function (in ire_round_robin) we check
		 * that any IRE_OFFLINK has a gateway that reachable from the
		 * zone when we have multiple choices (ECMP).
		 */
		if (match_flags & MATCH_IRE_ZONEONLY)
			return (B_FALSE);
		if (ire->ire_type & IRE_LOOPBACK)
			return (B_FALSE);

		if (ire->ire_type & IRE_LOCAL)
			goto matchit;

		/*
		 * The normal case of IRE_ONLINK has a matching zoneid.
		 * Here we handle the case when shared-IP zones have been
		 * configured with IP addresses on vniN. In that case it
		 * is ok for traffic from a zone to use IRE_ONLINK routes
		 * if the ill has a usesrc pointing at vniN
		 * Applies to IRE_INTERFACE.
		 */
		dst_ill = ire->ire_ill;
		if (ire->ire_type & IRE_ONLINK) {
			uint_t	ifindex;

			/*
			 * Note there is no IRE_INTERFACE on vniN thus
			 * can't do an IRE lookup for a matching route.
			 */
			ifindex = dst_ill->ill_usesrc_ifindex;
			if (ifindex == 0)
				return (B_FALSE);

			/*
			 * If there is a usable source address in the
			 * zone, then it's ok to return this IRE_INTERFACE
			 */
			if (!ipif_zone_avail(ifindex, dst_ill->ill_isv6,
			    zoneid, ipst)) {
				ip3dbg(("ire_match_args: no usrsrc for zone"
				    " dst_ill %p\n", (void *)dst_ill));
				return (B_FALSE);
			}
		}
		/*
		 * For example, with
		 * route add 11.0.0.0 gw1 -ifp bge0
		 * route add 11.0.0.0 gw2 -ifp bge1
		 * this code would differentiate based on
		 * where the sending zone has addresses.
		 * Only if the zone has an address on bge0 can it use the first
		 * route. It isn't clear if this behavior is documented
		 * anywhere.
		 */
		if (dst_ill != NULL && (ire->ire_type & IRE_OFFLINK)) {
			ipif_t	*tipif;

			mutex_enter(&dst_ill->ill_lock);
			for (tipif = dst_ill->ill_ipif;
			    tipif != NULL; tipif = tipif->ipif_next) {
				if (!IPIF_IS_CONDEMNED(tipif) &&
				    (tipif->ipif_flags & IPIF_UP) &&
				    (tipif->ipif_zoneid == zoneid ||
				    tipif->ipif_zoneid == ALL_ZONES))
					break;
			}
			mutex_exit(&dst_ill->ill_lock);
			if (tipif == NULL)
				return (B_FALSE);
		}
	}

matchit:
	ire_ill = ire->ire_ill;
	if (match_flags & MATCH_IRE_GW) {
		mutex_enter(&ire->ire_lock);
		gw_addr_v6 = ire->ire_gateway_addr_v6;
		mutex_exit(&ire->ire_lock);
	}
	if (match_flags & MATCH_IRE_ILL) {

		/*
		 * If asked to match an ill, we *must* match
		 * on the ire_ill for ipmp test addresses, or
		 * any of the ill in the group for data addresses.
		 * If we don't, we may as well fail.
		 * However, we need an exception for IRE_LOCALs to ensure
		 * we loopback packets even sent to test addresses on different
		 * interfaces in the group.
		 */
		if ((match_flags & MATCH_IRE_TESTHIDDEN) &&
		    !(ire->ire_type & IRE_LOCAL)) {
			if (ire->ire_ill != ill)
				return (B_FALSE);
		} else  {
			match_flags &= ~MATCH_IRE_TESTHIDDEN;
			/*
			 * We know that ill is not NULL, but ire_ill could be
			 * NULL
			 */
			if (ire_ill == NULL || !IS_ON_SAME_LAN(ill, ire_ill))
				return (B_FALSE);
		}
	}
	if (match_flags & MATCH_IRE_SRC_ILL) {
		if (ire_ill == NULL)
			return (B_FALSE);
		if (!IS_ON_SAME_LAN(ill, ire_ill)) {
			if (ire_ill->ill_usesrc_ifindex == 0 ||
			    (ire_ill->ill_usesrc_ifindex !=
			    ill->ill_phyint->phyint_ifindex))
				return (B_FALSE);
		}
	}

	/* No ire_addr_v6 bits set past the mask */
	ASSERT(V6_MASK_EQ(ire->ire_addr_v6, ire->ire_mask_v6,
	    ire->ire_addr_v6));
	V6_MASK_COPY(*addr, *mask, masked_addr);
	if (V6_MASK_EQ(*addr, *mask, ire->ire_addr_v6) &&
	    ((!(match_flags & MATCH_IRE_GW)) ||
	    ((!(match_flags & MATCH_IRE_DIRECT)) ||
	    !(ire->ire_flags & RTF_INDIRECT)) &&
	    IN6_ARE_ADDR_EQUAL(&gw_addr_v6, gateway)) &&
	    ((!(match_flags & MATCH_IRE_TYPE)) || (ire->ire_type & type)) &&
	    ((!(match_flags & MATCH_IRE_TESTHIDDEN)) || ire->ire_testhidden) &&
	    ((!(match_flags & MATCH_IRE_MASK)) ||
	    (IN6_ARE_ADDR_EQUAL(&ire->ire_mask_v6, mask))) &&
	    ((!(match_flags & MATCH_IRE_SECATTR)) ||
	    (!is_system_labeled()) ||
	    (tsol_ire_match_gwattr(ire, tsl) == 0))) {
		/* We found the matched IRE */
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Check if the zoneid (not ALL_ZONES) has an IRE_INTERFACE for the specified
 * gateway address. If ill is non-NULL we also match on it.
 * The caller must hold a read lock on RADIX_NODE_HEAD if lock_held is set.
 */
boolean_t
ire_gateway_ok_zone_v6(const in6_addr_t *gateway, zoneid_t zoneid, ill_t *ill,
    const ts_label_t *tsl, ip_stack_t *ipst, boolean_t lock_held)
{
	ire_t	*ire;
	uint_t	match_flags;

	if (lock_held)
		ASSERT(RW_READ_HELD(&ipst->ips_ip6_ire_head_lock));
	else
		rw_enter(&ipst->ips_ip6_ire_head_lock, RW_READER);

	match_flags = MATCH_IRE_TYPE | MATCH_IRE_SECATTR;
	if (ill != NULL)
		match_flags |= MATCH_IRE_ILL;

	ire = ire_ftable_lookup_impl_v6(gateway, &ipv6_all_zeros,
	    &ipv6_all_zeros, IRE_INTERFACE, ill, zoneid, tsl, match_flags,
	    ipst);

	if (!lock_held)
		rw_exit(&ipst->ips_ip6_ire_head_lock);
	if (ire != NULL) {
		ire_refrele(ire);
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

/*
 * Lookup a route in forwarding table.
 * specific lookup is indicated by passing the
 * required parameters and indicating the
 * match required in flag field.
 *
 * Supports link-local addresses by following the ipif/ill when recursing.
 */
ire_t *
ire_ftable_lookup_v6(const in6_addr_t *addr, const in6_addr_t *mask,
    const in6_addr_t *gateway, int type, const ill_t *ill,
    zoneid_t zoneid, const ts_label_t *tsl, int flags,
    uint32_t xmit_hint, ip_stack_t *ipst, uint_t *generationp)
{
	ire_t *ire = NULL;

	ASSERT(addr != NULL);
	ASSERT((!(flags & MATCH_IRE_MASK)) || mask != NULL);
	ASSERT((!(flags & MATCH_IRE_GW)) || gateway != NULL);
	ASSERT(ill == NULL || ill->ill_isv6);

	ASSERT(!IN6_IS_ADDR_V4MAPPED(addr));

	/*
	 * ire_match_args_v6() will dereference ill if MATCH_IRE_ILL
	 * or MATCH_IRE_SRC_ILL is set.
	 */
	if ((flags & (MATCH_IRE_ILL|MATCH_IRE_SRC_ILL)) && (ill == NULL))
		return (NULL);

	rw_enter(&ipst->ips_ip6_ire_head_lock, RW_READER);
	ire = ire_ftable_lookup_impl_v6(addr, mask, gateway, type, ill, zoneid,
	    tsl, flags, ipst);
	if (ire == NULL) {
		rw_exit(&ipst->ips_ip6_ire_head_lock);
		return (NULL);
	}

	/*
	 * round-robin only if we have more than one route in the bucket.
	 * ips_ip_ecmp_behavior controls when we do ECMP
	 *	2:	always
	 *	1:	for IRE_DEFAULT and /0 IRE_INTERFACE
	 *	0:	never
	 *
	 * Note: if we found an IRE_IF_CLONE we won't look at the bucket with
	 * other ECMP IRE_INTERFACEs since the IRE_IF_CLONE is a /128 match
	 * and the IRE_INTERFACESs are likely to be shorter matches.
	 */
	if (ire->ire_bucket->irb_ire_cnt > 1 && !(flags & MATCH_IRE_GW)) {
		if (ipst->ips_ip_ecmp_behavior == 2 ||
		    (ipst->ips_ip_ecmp_behavior == 1 &&
		    IS_DEFAULT_ROUTE_V6(ire))) {
			ire_t	*next_ire;
			ire_ftable_args_t margs;

			bzero(&margs, sizeof (margs));
			margs.ift_addr_v6 = *addr;
			if (mask != NULL)
				margs.ift_mask_v6 = *mask;
			if (gateway != NULL)
				margs.ift_gateway_v6 = *gateway;
			margs.ift_type = type;
			margs.ift_ill = ill;
			margs.ift_zoneid = zoneid;
			margs.ift_tsl = tsl;
			margs.ift_flags = flags;

			next_ire = ire_round_robin(ire->ire_bucket, &margs,
			    xmit_hint, ire, ipst);
			if (next_ire == NULL) {
				/* keep ire if next_ire is null */
				goto done;
			}
			ire_refrele(ire);
			ire = next_ire;
		}
	}

done:
	/* Return generation before dropping lock */
	if (generationp != NULL)
		*generationp = ire->ire_generation;

	rw_exit(&ipst->ips_ip6_ire_head_lock);

	/*
	 * For shared-IP zones we need additional checks to what was
	 * done in ire_match_args to make sure IRE_LOCALs are handled.
	 *
	 * When ip_restrict_interzone_loopback is set, then
	 * we ensure that IRE_LOCAL are only used for loopback
	 * between zones when the logical "Ethernet" would
	 * have looped them back. That is, if in the absense of
	 * the IRE_LOCAL we would have sent to packet out the
	 * same ill.
	 */
	if ((ire->ire_type & IRE_LOCAL) && zoneid != ALL_ZONES &&
	    ire->ire_zoneid != zoneid && ire->ire_zoneid != ALL_ZONES &&
	    ipst->ips_ip_restrict_interzone_loopback) {
		ire = ire_alt_local(ire, zoneid, tsl, ill, generationp);
		ASSERT(ire != NULL);
	}

	return (ire);
}

/*
 * Look up a single ire. The caller holds either the read or write lock.
 */
ire_t *
ire_ftable_lookup_impl_v6(const in6_addr_t *addr, const in6_addr_t *mask,
    const in6_addr_t *gateway, int type, const ill_t *ill,
    zoneid_t zoneid, const ts_label_t *tsl, int flags,
    ip_stack_t *ipst)
{
	irb_t *irb_ptr;
	ire_t *ire = NULL;
	int i;

	ASSERT(RW_LOCK_HELD(&ipst->ips_ip6_ire_head_lock));

	/*
	 * If the mask is known, the lookup
	 * is simple, if the mask is not known
	 * we need to search.
	 */
	if (flags & MATCH_IRE_MASK) {
		uint_t masklen;

		masklen = ip_mask_to_plen_v6(mask);
		if (ipst->ips_ip_forwarding_table_v6[masklen] == NULL) {
			return (NULL);
		}
		irb_ptr = &(ipst->ips_ip_forwarding_table_v6[masklen][
		    IRE_ADDR_MASK_HASH_V6(*addr, *mask,
		    ipst->ips_ip6_ftable_hash_size)]);
		rw_enter(&irb_ptr->irb_lock, RW_READER);
		for (ire = irb_ptr->irb_ire; ire != NULL;
		    ire = ire->ire_next) {
			if (IRE_IS_CONDEMNED(ire))
				continue;
			if (ire_match_args_v6(ire, addr, mask, gateway, type,
			    ill, zoneid, tsl, flags))
				goto found_ire;
		}
		rw_exit(&irb_ptr->irb_lock);
	} else {
		uint_t masklen;

		/*
		 * In this case we don't know the mask, we need to
		 * search the table assuming different mask sizes.
		 */
		if (flags & MATCH_IRE_SHORTERMASK) {
			masklen = ip_mask_to_plen_v6(mask);
			if (masklen == 0) {
				/* Nothing shorter than zero */
				return (NULL);
			}
			masklen--;
		} else {
			masklen = IP6_MASK_TABLE_SIZE - 1;
		}

		for (i = masklen; i >= 0; i--) {
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
				if (IRE_IS_CONDEMNED(ire))
					continue;
				if (ire_match_args_v6(ire, addr,
				    &ire->ire_mask_v6, gateway, type, ill,
				    zoneid, tsl, flags))
					goto found_ire;
			}
			rw_exit(&irb_ptr->irb_lock);
		}
	}
	ASSERT(ire == NULL);
	ip1dbg(("ire_ftable_lookup_v6: returning NULL ire"));
	return (NULL);

found_ire:
	ire_refhold(ire);
	rw_exit(&irb_ptr->irb_lock);
	return (ire);
}


/*
 * This function is called by
 * ip_input/ire_route_recursive when doing a route lookup on only the
 * destination address.
 *
 * The optimizations of this function over ire_ftable_lookup are:
 *	o removing unnecessary flag matching
 *	o doing longest prefix match instead of overloading it further
 *	  with the unnecessary "best_prefix_match"
 *
 * If no route is found we return IRE_NOROUTE.
 */
ire_t *
ire_ftable_lookup_simple_v6(const in6_addr_t *addr, uint32_t xmit_hint,
    ip_stack_t *ipst, uint_t *generationp)
{
	ire_t	*ire;

	ire = ire_ftable_lookup_v6(addr, NULL, NULL, 0, NULL, ALL_ZONES, NULL,
	    MATCH_IRE_DSTONLY, xmit_hint, ipst, generationp);
	if (ire == NULL) {
		ire = ire_reject(ipst, B_TRUE);
		if (generationp != NULL)
			*generationp = IRE_GENERATION_VERIFY;
	}
	/* ftable_lookup did round robin */
	return (ire);
}

ire_t *
ip_select_route_v6(const in6_addr_t *dst, const in6_addr_t src,
    ip_xmit_attr_t *ixa, uint_t *generationp, in6_addr_t *setsrcp,
    int *errorp, boolean_t *multirtp)
{
	ASSERT(!(ixa->ixa_flags & IXAF_IS_IPV4));

	return (ip_select_route(dst, src, ixa, generationp, setsrcp, errorp,
	    multirtp));
}

/*
 * Recursively look for a route to the destination. Can also match on
 * the zoneid, ill, and label. Used for the data paths. See also
 * ire_route_recursive_dstonly.
 *
 * If IRR_ALLOCATE is not set then we will only inspect the existing IREs; never
 * create an IRE_IF_CLONE. This is used on the receive side when we are not
 * forwarding.
 * If IRR_INCOMPLETE is set then we return the IRE even if we can't correctly
 * resolve the gateway.
 *
 * Note that this function never returns NULL. It returns an IRE_NOROUTE
 * instead.
 *
 * If we find any IRE_LOCAL|BROADCAST etc past the first iteration it
 * is an error.
 * Allow at most one RTF_INDIRECT.
 */
ire_t *
ire_route_recursive_impl_v6(ire_t *ire,
    const in6_addr_t *nexthop, uint_t ire_type, const ill_t *ill_arg,
    zoneid_t zoneid, const ts_label_t *tsl, uint_t match_args,
    uint_t irr_flags, uint32_t xmit_hint, ip_stack_t *ipst,
    in6_addr_t *setsrcp, tsol_ire_gw_secattr_t **gwattrp, uint_t *generationp)
{
	int		i, j;
	in6_addr_t	v6nexthop = *nexthop;
	ire_t		*ires[MAX_IRE_RECURSION];
	uint_t		generation;
	uint_t		generations[MAX_IRE_RECURSION];
	boolean_t	need_refrele = B_FALSE;
	boolean_t	invalidate = B_FALSE;
	ill_t		*ill = NULL;
	uint_t		maskoff = (IRE_LOCAL|IRE_LOOPBACK);

	if (setsrcp != NULL)
		ASSERT(IN6_IS_ADDR_UNSPECIFIED(setsrcp));
	if (gwattrp != NULL)
		ASSERT(*gwattrp == NULL);

	/*
	 * We iterate up to three times to resolve a route, even though
	 * we have four slots in the array. The extra slot is for an
	 * IRE_IF_CLONE we might need to create.
	 */
	i = 0;
	while (i < MAX_IRE_RECURSION - 1) {
		/* ire_ftable_lookup handles round-robin/ECMP */
		if (ire == NULL) {
			ire = ire_ftable_lookup_v6(&v6nexthop, 0, 0, ire_type,
			    (ill != NULL ? ill : ill_arg), zoneid, tsl,
			    match_args, xmit_hint, ipst, &generation);
		} else {
			/* Caller passed it; extra hold since we will rele */
			ire_refhold(ire);
			if (generationp != NULL)
				generation = *generationp;
			else
				generation = IRE_GENERATION_VERIFY;
		}

		if (ire == NULL) {
			if (i > 0 && (irr_flags & IRR_INCOMPLETE)) {
				ire = ires[0];
				ire_refhold(ire);
			} else {
				ire = ire_reject(ipst, B_TRUE);
			}
			goto error;
		}

		/* Need to return the ire with RTF_REJECT|BLACKHOLE */
		if (ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE))
			goto error;

		ASSERT(!(ire->ire_type & IRE_MULTICAST)); /* Not in ftable */
		/*
		 * Verify that the IRE_IF_CLONE has a consistent generation
		 * number.
		 */
		if ((ire->ire_type & IRE_IF_CLONE) && !ire_clone_verify(ire)) {
			ire_refrele(ire);
			ire = NULL;
			continue;
		}

		/*
		 * Don't allow anything unusual past the first iteration.
		 * After the first lookup, we should no longer look for
		 * (IRE_LOCAL|IRE_LOOPBACK) or RTF_INDIRECT routes.
		 *
		 * In addition, after we have found a direct IRE_OFFLINK,
		 * we should only look for interface or clone routes.
		 */
		match_args |= MATCH_IRE_DIRECT; /* no more RTF_INDIRECTs */
		if ((ire->ire_type & IRE_OFFLINK) &&
		    !(ire->ire_flags & RTF_INDIRECT)) {
			ire_type = IRE_IF_ALL;
		} else {
			if (!(match_args & MATCH_IRE_TYPE))
				ire_type = (IRE_OFFLINK|IRE_ONLINK);
			ire_type &= ~maskoff; /* no more LOCAL, LOOPBACK */
		}
		match_args |= MATCH_IRE_TYPE;
		/* We have a usable IRE */
		ires[i] = ire;
		generations[i] = generation;
		i++;

		/* The first RTF_SETSRC address is passed back if setsrcp */
		if ((ire->ire_flags & RTF_SETSRC) &&
		    setsrcp != NULL && IN6_IS_ADDR_UNSPECIFIED(setsrcp)) {
			ASSERT(!IN6_IS_ADDR_UNSPECIFIED(
			    &ire->ire_setsrc_addr_v6));
			*setsrcp = ire->ire_setsrc_addr_v6;
		}

		/* The first ire_gw_secattr is passed back if gwattrp */
		if (ire->ire_gw_secattr != NULL &&
		    gwattrp != NULL && *gwattrp == NULL)
			*gwattrp = ire->ire_gw_secattr;

		/*
		 * Check if we have a short-cut pointer to an IRE for this
		 * destination, and that the cached dependency isn't stale.
		 * In that case we've rejoined an existing tree towards a
		 * parent, thus we don't need to continue the loop to
		 * discover the rest of the tree.
		 */
		mutex_enter(&ire->ire_lock);
		if (ire->ire_dep_parent != NULL &&
		    ire->ire_dep_parent->ire_generation ==
		    ire->ire_dep_parent_generation) {
			mutex_exit(&ire->ire_lock);
			ire = NULL;
			goto done;
		}
		mutex_exit(&ire->ire_lock);

		/*
		 * If this type should have an ire_nce_cache (even if it
		 * doesn't yet have one) then we are done. Includes
		 * IRE_INTERFACE with a full 128 bit mask.
		 */
		if (ire->ire_nce_capable) {
			ire = NULL;
			goto done;
		}
		ASSERT(!(ire->ire_type & IRE_IF_CLONE));
		/*
		 * For an IRE_INTERFACE we create an IRE_IF_CLONE for this
		 * particular destination
		 */
		if (ire->ire_type & IRE_INTERFACE) {
			ire_t		*clone;

			ASSERT(ire->ire_masklen != IPV6_ABITS);

			/*
			 * In the case of ip_input and ILLF_FORWARDING not
			 * being set, and in the case of RTM_GET, there is
			 * no point in allocating an IRE_IF_CLONE. We return
			 * the IRE_INTERFACE. Note that !IRR_ALLOCATE can
			 * result in a ire_dep_parent which is IRE_IF_*
			 * without an IRE_IF_CLONE.
			 * We recover from that when we need to send packets
			 * by ensuring that the generations become
			 * IRE_GENERATION_VERIFY in this case.
			 */
			if (!(irr_flags & IRR_ALLOCATE)) {
				invalidate = B_TRUE;
				ire = NULL;
				goto done;
			}

			clone = ire_create_if_clone(ire, &v6nexthop,
			    &generation);
			if (clone == NULL) {
				/*
				 * Temporary failure - no memory.
				 * Don't want caller to cache IRE_NOROUTE.
				 */
				invalidate = B_TRUE;
				ire = ire_blackhole(ipst, B_TRUE);
				goto error;
			}
			/*
			 * Make clone next to last entry and the
			 * IRE_INTERFACE the last in the dependency
			 * chain since the clone depends on the
			 * IRE_INTERFACE.
			 */
			ASSERT(i >= 1);
			ASSERT(i < MAX_IRE_RECURSION);

			ires[i] = ires[i-1];
			generations[i] = generations[i-1];
			ires[i-1] = clone;
			generations[i-1] = generation;
			i++;

			ire = NULL;
			goto done;
		}

		/*
		 * We only match on the type and optionally ILL when
		 * recursing. The type match is used by some callers
		 * to exclude certain types (such as IRE_IF_CLONE or
		 * IRE_LOCAL|IRE_LOOPBACK).
		 *
		 * In the MATCH_IRE_SRC_ILL case, ill_arg may be the 'srcof'
		 * ire->ire_ill, and we want to find the IRE_INTERFACE for
		 * ire_ill, so we set ill to the ire_ill
		 */
		match_args &= (MATCH_IRE_TYPE | MATCH_IRE_DIRECT);
		v6nexthop = ire->ire_gateway_addr_v6;
		if (ill == NULL && ire->ire_ill != NULL) {
			ill = ire->ire_ill;
			need_refrele = B_TRUE;
			ill_refhold(ill);
			match_args |= MATCH_IRE_ILL;
		}
		ire = NULL;
	}
	ASSERT(ire == NULL);
	ire = ire_reject(ipst, B_TRUE);

error:
	ASSERT(ire != NULL);
	if (need_refrele)
		ill_refrele(ill);

	/*
	 * In the case of MULTIRT we want to try a different IRE the next
	 * time. We let the next packet retry in that case.
	 */
	if (i > 0 && (ires[0]->ire_flags & RTF_MULTIRT))
		(void) ire_no_good(ires[0]);

cleanup:
	/* cleanup ires[i] */
	ire_dep_unbuild(ires, i);
	for (j = 0; j < i; j++)
		ire_refrele(ires[j]);

	ASSERT((ire->ire_flags & (RTF_REJECT|RTF_BLACKHOLE)) ||
	    (irr_flags & IRR_INCOMPLETE));
	/*
	 * Use IRE_GENERATION_VERIFY to ensure that ip_output will redo the
	 * ip_select_route since the reject or lack of memory might be gone.
	 */
	if (generationp != NULL)
		*generationp = IRE_GENERATION_VERIFY;
	return (ire);

done:
	ASSERT(ire == NULL);
	if (need_refrele)
		ill_refrele(ill);

	/* Build dependencies */
	if (i > 1 && !ire_dep_build(ires, generations, i)) {
		/* Something in chain was condemned; tear it apart */
		ire = ire_blackhole(ipst, B_TRUE);
		goto cleanup;
	}

	/*
	 * Release all refholds except the one for ires[0] that we
	 * will return to the caller.
	 */
	for (j = 1; j < i; j++)
		ire_refrele(ires[j]);

	if (invalidate) {
		/*
		 * Since we needed to allocate but couldn't we need to make
		 * sure that the dependency chain is rebuilt the next time.
		 */
		ire_dep_invalidate_generations(ires[0]);
		generation = IRE_GENERATION_VERIFY;
	} else {
		/*
		 * IREs can have been added or deleted while we did the
		 * recursive lookup and we can't catch those until we've built
		 * the dependencies. We verify the stored
		 * ire_dep_parent_generation to catch any such changes and
		 * return IRE_GENERATION_VERIFY (which will cause
		 * ip_select_route to be called again so we can redo the
		 * recursive lookup next time we send a packet.
		 */
		if (ires[0]->ire_dep_parent == NULL)
			generation = ires[0]->ire_generation;
		else
			generation = ire_dep_validate_generations(ires[0]);
		if (generations[0] != ires[0]->ire_generation) {
			/* Something changed at the top */
			generation = IRE_GENERATION_VERIFY;
		}
	}
	if (generationp != NULL)
		*generationp = generation;

	return (ires[0]);
}

ire_t *
ire_route_recursive_v6(const in6_addr_t *nexthop, uint_t ire_type,
    const ill_t *ill, zoneid_t zoneid, const ts_label_t *tsl, uint_t match_args,
    uint_t irr_flags, uint32_t xmit_hint, ip_stack_t *ipst,
    in6_addr_t *setsrcp, tsol_ire_gw_secattr_t **gwattrp, uint_t *generationp)
{
	return (ire_route_recursive_impl_v6(NULL, nexthop, ire_type, ill,
	    zoneid, tsl, match_args, irr_flags, xmit_hint, ipst, setsrcp,
	    gwattrp, generationp));
}

/*
 * Recursively look for a route to the destination.
 * We only handle a destination match here, yet we have the same arguments
 * as the full match to allow function pointers to select between the two.
 *
 * Note that this function never returns NULL. It returns an IRE_NOROUTE
 * instead.
 *
 * If we find any IRE_LOCAL|BROADCAST etc past the first iteration it
 * is an error.
 * Allow at most one RTF_INDIRECT.
 */
ire_t *
ire_route_recursive_dstonly_v6(const in6_addr_t *nexthop, uint_t irr_flags,
    uint32_t xmit_hint, ip_stack_t *ipst)
{
	ire_t	*ire;
	ire_t	*ire1;
	uint_t	generation;

	/* ire_ftable_lookup handles round-robin/ECMP */
	ire = ire_ftable_lookup_simple_v6(nexthop, xmit_hint, ipst,
	    &generation);
	ASSERT(ire != NULL);

	/*
	 * If the IRE has a current cached parent we know that the whole
	 * parent chain is current, hence we don't need to discover and
	 * build any dependencies by doing a recursive lookup.
	 */
	mutex_enter(&ire->ire_lock);
	if (ire->ire_dep_parent != NULL) {
		if (ire->ire_dep_parent->ire_generation ==
		    ire->ire_dep_parent_generation) {
			mutex_exit(&ire->ire_lock);
			return (ire);
		}
		mutex_exit(&ire->ire_lock);
	} else {
		mutex_exit(&ire->ire_lock);
		/*
		 * If this type should have an ire_nce_cache (even if it
		 * doesn't yet have one) then we are done. Includes
		 * IRE_INTERFACE with a full 128 bit mask.
		 */
		if (ire->ire_nce_capable)
			return (ire);
	}

	/*
	 * Fallback to loop in the normal code starting with the ire
	 * we found. Normally this would return the same ire.
	 */
	ire1 = ire_route_recursive_impl_v6(ire, nexthop, 0, NULL, ALL_ZONES,
	    NULL, MATCH_IRE_DSTONLY, irr_flags, xmit_hint, ipst, NULL, NULL,
	    &generation);
	ire_refrele(ire);
	return (ire1);
}
