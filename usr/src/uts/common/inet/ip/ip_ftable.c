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
 * This file contains consumer routines of the IPv4 forwarding engine
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <sys/dlpi.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>

#include <sys/systm.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/pattr.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip_ndp.h>
#include <inet/arp.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/nd.h>

#include <net/pfkeyv2.h>
#include <inet/ipsec_info.h>
#include <inet/sadb.h>
#include <inet/tcp.h>
#include <inet/ipclassifier.h>
#include <sys/zone.h>
#include <net/radix.h>
#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#define	IS_DEFAULT_ROUTE(ire)	\
	(((ire)->ire_type & IRE_DEFAULT) || \
	    (((ire)->ire_type & IRE_INTERFACE) && ((ire)->ire_addr == 0)))

/*
 * structure for passing args between ire_ftable_lookup and ire_find_best_route
 */
typedef struct ire_ftable_args_s {
	ipaddr_t	ift_addr;
	ipaddr_t	ift_mask;
	ipaddr_t	ift_gateway;
	int		ift_type;
	const ipif_t		*ift_ipif;
	zoneid_t	ift_zoneid;
	uint32_t	ift_ihandle;
	const ts_label_t	*ift_tsl;
	int		ift_flags;
	ire_t		*ift_best_ire;
} ire_ftable_args_t;

static ire_t	*route_to_dst(const struct sockaddr *, zoneid_t, ip_stack_t *);
static ire_t   	*ire_round_robin(irb_t *, zoneid_t, ire_ftable_args_t *,
    ip_stack_t *);
static void		ire_del_host_redir(ire_t *, char *);
static boolean_t	ire_find_best_route(struct radix_node *, void *);
static int	ip_send_align_hcksum_flags(mblk_t *, ill_t *);
static ire_t	*ire_ftable_lookup_simple(ipaddr_t,
	ire_t **, zoneid_t,  int, ip_stack_t *);

/*
 * Lookup a route in forwarding table. A specific lookup is indicated by
 * passing the required parameters and indicating the match required in the
 * flag field.
 *
 * Looking for default route can be done in three ways
 * 1) pass mask as 0 and set MATCH_IRE_MASK in flags field
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
 * Supports IP_BOUND_IF by following the ipif/ill when recursing.
 *
 * NOTE : When this function returns NULL, pire has already been released.
 *	  pire is valid only when this function successfully returns an
 *	  ire.
 */
ire_t *
ire_ftable_lookup(ipaddr_t addr, ipaddr_t mask, ipaddr_t gateway,
    int type, const ipif_t *ipif, ire_t **pire, zoneid_t zoneid,
    uint32_t ihandle, const ts_label_t *tsl, int flags, ip_stack_t *ipst)
{
	ire_t *ire = NULL;
	ipaddr_t gw_addr;
	struct rt_sockaddr rdst, rmask;
	struct rt_entry *rt;
	ire_ftable_args_t margs;
	boolean_t found_incomplete = B_FALSE;

	ASSERT(ipif == NULL || !ipif->ipif_isv6);

	/*
	 * When we return NULL from this function, we should make
	 * sure that *pire is NULL so that the callers will not
	 * wrongly REFRELE the pire.
	 */
	if (pire != NULL)
		*pire = NULL;
	/*
	 * ire_match_args() will dereference ipif MATCH_IRE_SRC or
	 * MATCH_IRE_ILL is set.
	 */
	if ((flags & (MATCH_IRE_SRC | MATCH_IRE_ILL)) && (ipif == NULL))
		return (NULL);

	(void) memset(&rdst, 0, sizeof (rdst));
	rdst.rt_sin_len = sizeof (rdst);
	rdst.rt_sin_family = AF_INET;
	rdst.rt_sin_addr.s_addr = addr;

	(void) memset(&rmask, 0, sizeof (rmask));
	rmask.rt_sin_len = sizeof (rmask);
	rmask.rt_sin_family = AF_INET;
	rmask.rt_sin_addr.s_addr = mask;

	(void) memset(&margs, 0, sizeof (margs));
	margs.ift_addr = addr;
	margs.ift_mask = mask;
	margs.ift_gateway = gateway;
	margs.ift_type = type;
	margs.ift_ipif = ipif;
	margs.ift_zoneid = zoneid;
	margs.ift_ihandle = ihandle;
	margs.ift_tsl = tsl;
	margs.ift_flags = flags;

	/*
	 * The flags argument passed to ire_ftable_lookup may cause the
	 * search to return, not the longest matching prefix, but the
	 * "best matching prefix", i.e., the longest prefix that also
	 * satisfies constraints imposed via the permutation of flags
	 * passed in. To achieve this, we invoke ire_match_args() on
	 * each matching leaf in the  radix tree. ire_match_args is
	 * invoked by the callback function ire_find_best_route()
	 * We hold the global tree lock in read mode when calling
	 * rn_match_args.Before dropping the global tree lock, ensure
	 * that the radix node can't be deleted by incrementing ire_refcnt.
	 */
	RADIX_NODE_HEAD_RLOCK(ipst->ips_ip_ftable);
	rt = (struct rt_entry *)ipst->ips_ip_ftable->rnh_matchaddr_args(&rdst,
	    ipst->ips_ip_ftable, ire_find_best_route, &margs);
	ire = margs.ift_best_ire;
	RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);

	if (rt == NULL) {
		return (NULL);
	} else {
		ASSERT(ire != NULL);
	}

	DTRACE_PROBE2(ire__found, ire_ftable_args_t *, &margs, ire_t *, ire);

	if (!IS_DEFAULT_ROUTE(ire))
		goto found_ire_held;
	/*
	 * If default route is found, see if default matching criteria
	 * are satisfied.
	 */
	if (flags & MATCH_IRE_MASK) {
		/*
		 * we were asked to match a 0 mask, and came back with
		 * a default route. Ok to return it.
		 */
		goto found_default_ire;
	}
	if ((flags & MATCH_IRE_TYPE) &&
	    (type & (IRE_DEFAULT | IRE_INTERFACE))) {
		/*
		 * we were asked to match a default ire type. Ok to return it.
		 */
		goto found_default_ire;
	}
	if (flags & MATCH_IRE_DEFAULT) {
		goto found_default_ire;
	}
	/*
	 * we found a default route, but default matching criteria
	 * are not specified and we are not explicitly looking for
	 * default.
	 */
	IRE_REFRELE(ire);
	return (NULL);
found_default_ire:
	/*
	 * round-robin only if we have more than one route in the bucket.
	 */
	if ((ire->ire_bucket->irb_ire_cnt > 1) &&
	    IS_DEFAULT_ROUTE(ire) &&
	    ((flags & (MATCH_IRE_DEFAULT | MATCH_IRE_MASK)) ==
	    MATCH_IRE_DEFAULT)) {
		ire_t *next_ire;

		next_ire = ire_round_robin(ire->ire_bucket, zoneid, &margs,
		    ipst);
		IRE_REFRELE(ire);
		if (next_ire != NULL) {
			ire = next_ire;
		} else {
			/* no route */
			return (NULL);
		}
	}
found_ire_held:
	if ((flags & MATCH_IRE_RJ_BHOLE) &&
	    (ire->ire_flags & (RTF_BLACKHOLE | RTF_REJECT))) {
		return (ire);
	}
	/*
	 * At this point, IRE that was found must be an IRE_FORWARDTABLE
	 * type.  If this is a recursive lookup and an IRE_INTERFACE type was
	 * found, return that.  If it was some other IRE_FORWARDTABLE type of
	 * IRE (one of the prefix types), then it is necessary to fill in the
	 * parent IRE pointed to by pire, and then lookup the gateway address of
	 * the parent.  For backwards compatiblity, if this lookup returns an
	 * IRE other than a IRE_CACHETABLE or IRE_INTERFACE, then one more level
	 * of lookup is done.
	 */
	if (flags & MATCH_IRE_RECURSIVE) {
		ipif_t	*gw_ipif;
		int match_flags = MATCH_IRE_DSTONLY;
		ire_t *save_ire;

		if (ire->ire_type & IRE_INTERFACE)
			return (ire);
		if (pire != NULL)
			*pire = ire;
		/*
		 * If we can't find an IRE_INTERFACE or the caller has not
		 * asked for pire, we need to REFRELE the save_ire.
		 */
		save_ire = ire;

		if (ire->ire_ipif != NULL)
			match_flags |= MATCH_IRE_ILL;

		/*
		 * ire_ftable_lookup may end up with an incomplete IRE_CACHE
		 * entry for the gateway (i.e., one for which the
		 * ire_nce->nce_state is not yet ND_REACHABLE). If the caller
		 * has specified MATCH_IRE_COMPLETE, such entries will not
		 * be returned; instead, we return the IF_RESOLVER ire.
		 */
		ire = ire_route_lookup(ire->ire_gateway_addr, 0, 0, 0,
		    ire->ire_ipif, NULL, zoneid, tsl, match_flags, ipst);
		DTRACE_PROBE2(ftable__route__lookup1, (ire_t *), ire,
		    (ire_t *), save_ire);
		if (ire == NULL ||
		    ((ire->ire_type & IRE_CACHE) && ire->ire_nce &&
		    ire->ire_nce->nce_state != ND_REACHABLE &&
		    (flags & MATCH_IRE_COMPLETE))) {
			/*
			 * Do not release the parent ire if MATCH_IRE_PARENT
			 * is set. Also return it via ire.
			 */
			if (ire != NULL) {
				ire_refrele(ire);
				ire = NULL;
				found_incomplete = B_TRUE;
			}
			if (flags & MATCH_IRE_PARENT) {
				if (pire != NULL) {
					/*
					 * Need an extra REFHOLD, if the parent
					 * ire is returned via both ire and
					 * pire.
					 */
					IRE_REFHOLD(save_ire);
				}
				ire = save_ire;
			} else {
				ire_refrele(save_ire);
				if (pire != NULL)
					*pire = NULL;
			}
			if (!found_incomplete)
				return (ire);
		}
		if (ire->ire_type & (IRE_CACHETABLE | IRE_INTERFACE)) {
			/*
			 * If the caller did not ask for pire, release
			 * it now.
			 */
			if (pire == NULL) {
				ire_refrele(save_ire);
			}
			return (ire);
		}
		match_flags |= MATCH_IRE_TYPE;
		gw_addr = ire->ire_gateway_addr;
		gw_ipif = ire->ire_ipif;
		ire_refrele(ire);
		ire = ire_route_lookup(gw_addr, 0, 0,
		    (found_incomplete? IRE_INTERFACE :
		    (IRE_CACHETABLE | IRE_INTERFACE)),
		    gw_ipif, NULL, zoneid, tsl, match_flags, ipst);
		DTRACE_PROBE2(ftable__route__lookup2, (ire_t *), ire,
		    (ire_t *), save_ire);
		if (ire == NULL ||
		    ((ire->ire_type & IRE_CACHE) && ire->ire_nce &&
		    ire->ire_nce->nce_state != ND_REACHABLE &&
		    (flags & MATCH_IRE_COMPLETE))) {
			/*
			 * Do not release the parent ire if MATCH_IRE_PARENT
			 * is set. Also return it via ire.
			 */
			if (ire != NULL) {
				ire_refrele(ire);
				ire = NULL;
			}
			if (flags & MATCH_IRE_PARENT) {
				if (pire != NULL) {
					/*
					 * Need an extra REFHOLD, if the
					 * parent ire is returned via both
					 * ire and pire.
					 */
					IRE_REFHOLD(save_ire);
				}
				ire = save_ire;
			} else {
				ire_refrele(save_ire);
				if (pire != NULL)
					*pire = NULL;
			}
			return (ire);
		} else if (pire == NULL) {
			/*
			 * If the caller did not ask for pire, release
			 * it now.
			 */
			ire_refrele(save_ire);
		}
		return (ire);
	}
	ASSERT(pire == NULL || *pire == NULL);
	return (ire);
}

/*
 * This function is called by
 * ip_fast_forward->ire_forward_simple
 * The optimizations of this function over ire_ftable_lookup are:
 *	o removing unnecessary flag matching
 *	o doing longest prefix match instead of overloading it further
 *	  with the unnecessary "best_prefix_match"
 *	o Does not do round robin of default route for every packet
 *	o inlines code of ire_ctable_lookup to look for nexthop cache
 *	  entry before calling ire_route_lookup
 */
static ire_t *
ire_ftable_lookup_simple(ipaddr_t addr,
    ire_t **pire, zoneid_t zoneid, int flags,
    ip_stack_t *ipst)
{
	ire_t *ire = NULL;
	ire_t *tmp_ire = NULL;
	struct rt_sockaddr rdst;
	struct rt_entry *rt;
	irb_t *irb_ptr;
	ire_t *save_ire;
	int match_flags;

	rdst.rt_sin_len = sizeof (rdst);
	rdst.rt_sin_family = AF_INET;
	rdst.rt_sin_addr.s_addr = addr;

	/*
	 * This is basically inlining  a simpler version of ire_match_args
	 */
	RADIX_NODE_HEAD_RLOCK(ipst->ips_ip_ftable);

	rt = (struct rt_entry *)ipst->ips_ip_ftable->rnh_matchaddr_args(&rdst,
	    ipst->ips_ip_ftable, NULL, NULL);

	if (rt == NULL) {
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
		return (NULL);
	}
	irb_ptr = &rt->rt_irb;
	if (irb_ptr == NULL || irb_ptr->irb_ire_cnt == 0) {
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
		return (NULL);
	}

	rw_enter(&irb_ptr->irb_lock, RW_READER);
	for (ire = irb_ptr->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (ire->ire_zoneid == zoneid)
			break;
	}

	if (ire == NULL || (ire->ire_marks & IRE_MARK_CONDEMNED)) {
		rw_exit(&irb_ptr->irb_lock);
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
		return (NULL);
	}
	/* we have a ire that matches */
	if (ire != NULL)
		IRE_REFHOLD(ire);
	rw_exit(&irb_ptr->irb_lock);
	RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);

	if ((flags & MATCH_IRE_RJ_BHOLE) &&
	    (ire->ire_flags & (RTF_BLACKHOLE | RTF_REJECT))) {
		return (ire);
	}
	/*
	 * At this point, IRE that was found must be an IRE_FORWARDTABLE
	 * type.  If this is a recursive lookup and an IRE_INTERFACE type was
	 * found, return that.  If it was some other IRE_FORWARDTABLE type of
	 * IRE (one of the prefix types), then it is necessary to fill in the
	 * parent IRE pointed to by pire, and then lookup the gateway address of
	 * the parent.  For backwards compatiblity, if this lookup returns an
	 * IRE other than a IRE_CACHETABLE or IRE_INTERFACE, then one more level
	 * of lookup is done.
	 */
	match_flags = MATCH_IRE_DSTONLY;

	if (ire->ire_type & IRE_INTERFACE)
		return (ire);
	*pire = ire;
	/*
	 * If we can't find an IRE_INTERFACE or the caller has not
	 * asked for pire, we need to REFRELE the save_ire.
	 */
	save_ire = ire;

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
	 *
	 * ire_ftable_lookup may end up with an incomplete IRE_CACHE
	 * entry for the gateway (i.e., one for which the
	 * ire_nce->nce_state is not yet ND_REACHABLE). If the caller
	 * has specified MATCH_IRE_COMPLETE, such entries will not
	 * be returned; instead, we return the IF_RESOLVER ire.
	 */

	if (ire->ire_ipif == NULL) {
		tmp_ire = ire;
		/*
		 * Look to see if the nexthop entry is in the
		 * cachetable (I am inlining a simpler ire_cache_lookup
		 * here).
		 */
		ire = ire_cache_lookup_simple(ire->ire_gateway_addr, ipst);
		if (ire == NULL) {
			/* Try ire_route_lookup */
			ire = tmp_ire;
		} else {
			goto solved;
		}
	}
	if (ire->ire_ipif != NULL)
		match_flags |= MATCH_IRE_ILL;

	ire = ire_route_lookup(ire->ire_gateway_addr, 0,
	    0, 0, ire->ire_ipif, NULL, zoneid, NULL, match_flags, ipst);
solved:
	DTRACE_PROBE2(ftable__route__lookup1, (ire_t *), ire,
	    (ire_t *), save_ire);
	if (ire == NULL) {
		/*
		 * Do not release the parent ire if MATCH_IRE_PARENT
		 * is set. Also return it via ire.
		 */
		ire_refrele(save_ire);
		*pire = NULL;
		return (ire);
	}
	if (ire->ire_type & (IRE_CACHETABLE | IRE_INTERFACE)) {
		/*
		 * If the caller did not ask for pire, release
		 * it now.
		 */
		if (pire == NULL) {
			ire_refrele(save_ire);
		}
	}
	return (ire);
}

/*
 * Find an IRE_OFFSUBNET IRE entry for the multicast address 'group'
 * that goes through 'ipif'. As a fallback, a route that goes through
 * ipif->ipif_ill can be returned.
 */
ire_t *
ipif_lookup_multi_ire(ipif_t *ipif, ipaddr_t group)
{
	ire_t	*ire;
	ire_t	*save_ire = NULL;
	ire_t   *gw_ire;
	irb_t   *irb;
	ipaddr_t gw_addr;
	int	match_flags = MATCH_IRE_TYPE | MATCH_IRE_ILL;
	ip_stack_t *ipst = ipif->ipif_ill->ill_ipst;

	ASSERT(CLASSD(group));

	ire = ire_ftable_lookup(group, 0, 0, 0, NULL, NULL, ALL_ZONES, 0,
	    NULL, MATCH_IRE_DEFAULT, ipst);

	if (ire == NULL)
		return (NULL);

	irb = ire->ire_bucket;
	ASSERT(irb);

	IRB_REFHOLD(irb);
	ire_refrele(ire);
	for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (ire->ire_addr != group ||
		    ipif->ipif_zoneid != ire->ire_zoneid &&
		    ire->ire_zoneid != ALL_ZONES) {
			continue;
		}

		switch (ire->ire_type) {
		case IRE_DEFAULT:
		case IRE_PREFIX:
		case IRE_HOST:
			gw_addr = ire->ire_gateway_addr;
			gw_ire = ire_ftable_lookup(gw_addr, 0, 0, IRE_INTERFACE,
			    ipif, NULL, ALL_ZONES, 0, NULL, match_flags, ipst);

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

/*
 * Find an IRE_INTERFACE for the multicast group.
 * Allows different routes for multicast addresses
 * in the unicast routing table (akin to 224.0.0.0 but could be more specific)
 * which point at different interfaces. This is used when IP_MULTICAST_IF
 * isn't specified (when sending) and when IP_ADD_MEMBERSHIP doesn't
 * specify the interface to join on.
 *
 * Supports IP_BOUND_IF by following the ipif/ill when recursing.
 */
ire_t *
ire_lookup_multi(ipaddr_t group, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t	*ire;
	ipif_t	*ipif = NULL;
	int	match_flags = MATCH_IRE_TYPE;
	ipaddr_t gw_addr;

	ire = ire_ftable_lookup(group, 0, 0, 0, NULL, NULL, zoneid,
	    0, NULL, MATCH_IRE_DEFAULT, ipst);

	/* We search a resolvable ire in case of multirouting. */
	if ((ire != NULL) && (ire->ire_flags & RTF_MULTIRT)) {
		ire_t *cire = NULL;
		/*
		 * If the route is not resolvable, the looked up ire
		 * may be changed here. In that case, ire_multirt_lookup()
		 * IRE_REFRELE the original ire and change it.
		 */
		(void) ire_multirt_lookup(&cire, &ire, MULTIRT_CACHEGW,
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
	 * which the gateway will be reached.
	 */
	if (ire->ire_ipif != NULL) {
		ipif = ire->ire_ipif;
		match_flags |= MATCH_IRE_ILL;
	}

	switch (ire->ire_type) {
	case IRE_DEFAULT:
	case IRE_PREFIX:
	case IRE_HOST:
		gw_addr = ire->ire_gateway_addr;
		ire_refrele(ire);
		ire = ire_ftable_lookup(gw_addr, 0, 0,
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
 * Delete the passed in ire if the gateway addr matches
 */
void
ire_del_host_redir(ire_t *ire, char *gateway)
{
	if ((ire->ire_flags & RTF_DYNAMIC) &&
	    (ire->ire_gateway_addr == *(ipaddr_t *)gateway))
		ire_delete(ire);
}

/*
 * Search for all HOST REDIRECT routes that are
 * pointing at the specified gateway and
 * delete them. This routine is called only
 * when a default gateway is going away.
 */
void
ire_delete_host_redirects(ipaddr_t gateway, ip_stack_t *ipst)
{
	struct rtfuncarg rtfarg;

	(void) memset(&rtfarg, 0, sizeof (rtfarg));
	rtfarg.rt_func = ire_del_host_redir;
	rtfarg.rt_arg = (void *)&gateway;
	(void) ipst->ips_ip_ftable->rnh_walktree_mt(ipst->ips_ip_ftable,
	    rtfunc, &rtfarg, irb_refhold_rn, irb_refrele_rn);
}

struct ihandle_arg {
	uint32_t ihandle;
	ire_t	 *ire;
};

static int
ire_ihandle_onlink_match(struct radix_node *rn, void *arg)
{
	struct rt_entry *rt;
	irb_t *irb;
	ire_t *ire;
	struct ihandle_arg *ih = arg;

	rt = (struct rt_entry *)rn;
	ASSERT(rt != NULL);
	irb = &rt->rt_irb;
	for (ire = irb->irb_ire; ire != NULL; ire = ire->ire_next) {
		if ((ire->ire_type & IRE_INTERFACE) &&
		    (ire->ire_ihandle == ih->ihandle)) {
			ih->ire = ire;
			IRE_REFHOLD(ire);
			return (1);
		}
	}
	return (0);
}

/*
 * Locate the interface ire that is tied to the cache ire 'cire' via
 * cire->ire_ihandle.
 *
 * We are trying to create the cache ire for an onlink destn. or
 * gateway in 'cire'. We are called from ire_add_v4() in the IRE_IF_RESOLVER
 * case, after the ire has come back from ARP.
 */
ire_t *
ire_ihandle_lookup_onlink(ire_t *cire)
{
	ire_t	*ire;
	int	match_flags;
	struct ihandle_arg ih;
	ip_stack_t *ipst;

	ASSERT(cire != NULL);
	ipst = cire->ire_ipst;

	/*
	 * We don't need to specify the zoneid to ire_ftable_lookup() below
	 * because the ihandle refers to an ipif which can be in only one zone.
	 */
	match_flags =  MATCH_IRE_TYPE | MATCH_IRE_IHANDLE | MATCH_IRE_MASK;
	/*
	 * We know that the mask of the interface ire equals cire->ire_cmask.
	 * (When ip_newroute() created 'cire' for an on-link destn. it set its
	 * cmask from the interface ire's mask)
	 */
	ire = ire_ftable_lookup(cire->ire_addr, cire->ire_cmask, 0,
	    IRE_INTERFACE, NULL, NULL, ALL_ZONES, cire->ire_ihandle,
	    NULL, match_flags, ipst);
	if (ire != NULL)
		return (ire);
	/*
	 * If we didn't find an interface ire above, we can't declare failure.
	 * For backwards compatibility, we need to support prefix routes
	 * pointing to next hop gateways that are not on-link.
	 *
	 * In the resolver/noresolver case, ip_newroute() thinks it is creating
	 * the cache ire for an onlink destination in 'cire'. But 'cire' is
	 * not actually onlink, because ire_ftable_lookup() cheated it, by
	 * doing ire_route_lookup() twice and returning an interface ire.
	 *
	 * Eg. default	-	gw1			(line 1)
	 *	gw1	-	gw2			(line 2)
	 *	gw2	-	hme0			(line 3)
	 *
	 * In the above example, ip_newroute() tried to create the cache ire
	 * 'cire' for gw1, based on the interface route in line 3. The
	 * ire_ftable_lookup() above fails, because there is no interface route
	 * to reach gw1. (it is gw2). We fall thru below.
	 *
	 * Do a brute force search based on the ihandle in a subset of the
	 * forwarding tables, corresponding to cire->ire_cmask. Otherwise
	 * things become very complex, since we don't have 'pire' in this
	 * case. (Also note that this method is not possible in the offlink
	 * case because we don't know the mask)
	 */
	(void) memset(&ih, 0, sizeof (ih));
	ih.ihandle = cire->ire_ihandle;
	(void) ipst->ips_ip_ftable->rnh_walktree_mt(ipst->ips_ip_ftable,
	    ire_ihandle_onlink_match, &ih, irb_refhold_rn, irb_refrele_rn);
	return (ih.ire);
}

/*
 * IRE iterator used by ire_ftable_lookup[_v6]() to process multiple default
 * routes. Given a starting point in the hash list (ire_origin), walk the IREs
 * in the bucket skipping default interface routes and deleted entries.
 * Returns the next IRE (unheld), or NULL when we're back to the starting point.
 * Assumes that the caller holds a reference on the IRE bucket.
 */
ire_t *
ire_get_next_default_ire(ire_t *ire, ire_t *ire_origin)
{
	ASSERT(ire_origin->ire_bucket != NULL);
	ASSERT(ire != NULL);

	do {
		ire = ire->ire_next;
		if (ire == NULL)
			ire = ire_origin->ire_bucket->irb_ire;
		if (ire == ire_origin)
			return (NULL);
	} while ((ire->ire_type & IRE_INTERFACE) ||
	    (ire->ire_marks & IRE_MARK_CONDEMNED));
	ASSERT(ire != NULL);
	return (ire);
}

static ipif_t *
ire_forward_src_ipif(ipaddr_t dst, ire_t *sire, ire_t *ire,
    int zoneid, ushort_t *marks)
{
	ipif_t *src_ipif;
	ill_t *ill = ire->ire_ipif->ipif_ill;
	ip_stack_t *ipst = ill->ill_ipst;

	/*
	 * Pick the best source address from ill.
	 *
	 * 1) Try to pick the source address from the destination
	 *    route. Clustering assumes that when we have multiple
	 *    prefixes hosted on an interface, the prefix of the
	 *    source address matches the prefix of the destination
	 *    route. We do this only if the address is not
	 *    DEPRECATED.
	 *
	 * 2) If the conn is in a different zone than the ire, we
	 *    need to pick a source address from the right zone.
	 */
	if ((sire != NULL) && (sire->ire_flags & RTF_SETSRC)) {
		/*
		 * The RTF_SETSRC flag is set in the parent ire (sire).
		 * Check that the ipif matching the requested source
		 * address still exists.
		 */
		src_ipif = ipif_lookup_addr(sire->ire_src_addr, NULL,
		    zoneid, NULL, NULL, NULL, NULL, ipst);
		return (src_ipif);
	}
	*marks |= IRE_MARK_USESRC_CHECK;
	if (IS_IPMP(ill) ||
	    (ire->ire_ipif->ipif_flags & IPIF_DEPRECATED) ||
	    (ill->ill_usesrc_ifindex != 0)) {
		src_ipif = ipif_select_source(ill, dst, zoneid);
	} else {
		src_ipif = ire->ire_ipif;
		ASSERT(src_ipif != NULL);
		/* hold src_ipif for uniformity */
		ipif_refhold(src_ipif);
	}
	return (src_ipif);
}

/*
 * This function is called by ip_rput_noire() and ip_fast_forward()
 * to resolve the route of incoming packet that needs to be forwarded.
 * If the ire of the nexthop is not already in the cachetable, this
 * routine will insert it to the table, but won't trigger ARP resolution yet.
 * Thus unlike ip_newroute, this function adds incomplete ires to
 * the cachetable. ARP resolution for these ires are  delayed until
 * after all of the packet processing is completed and its ready to
 * be sent out on the wire, Eventually, the packet transmit routine
 * ip_xmit_v4() attempts to send a packet  to the driver. If it finds
 * that there is no link layer information, it will do the arp
 * resolution and queue the packet in ire->ire_nce->nce_qd_mp and
 * then send it out once the arp resolution is over
 * (see ip_xmit_v4()->ire_arpresolve()). This scheme is similar to
 * the model of BSD/SunOS 4
 *
 * In future, the insertion of incomplete ires in the cachetable should
 * be implemented in hostpath as well, as doing so will greatly reduce
 * the existing complexity for code paths that depend on the context of
 * the sender (such as IPsec).
 *
 * Thus this scheme of adding incomplete ires in cachetable in forwarding
 * path can be used as a template for simplifying the hostpath.
 */

ire_t *
ire_forward(ipaddr_t dst, enum ire_forward_action *ret_action,
    ire_t *supplied_ire, ire_t *supplied_sire, const struct ts_label_s *tsl,
    ip_stack_t *ipst)
{
	ipaddr_t gw = 0;
	ire_t	*ire = NULL;
	ire_t   *sire = NULL, *save_ire;
	ill_t *dst_ill = NULL;
	int error;
	zoneid_t zoneid;
	ipif_t *src_ipif = NULL;
	mblk_t *res_mp;
	ushort_t ire_marks = 0;
	tsol_gcgrp_t *gcgrp = NULL;
	tsol_gcgrp_addr_t ga;

	zoneid = GLOBAL_ZONEID;

	if (supplied_ire != NULL) {
		/* We have arrived here from ipfil_sendpkt */
		ire = supplied_ire;
		sire = supplied_sire;
		goto create_irecache;
	}

	ire = ire_ftable_lookup(dst, 0, 0, 0, NULL, &sire, zoneid, 0,
	    tsl, MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
	    MATCH_IRE_RJ_BHOLE | MATCH_IRE_PARENT|MATCH_IRE_SECATTR, ipst);

	if (ire == NULL) {
		ip_rts_change(RTM_MISS, dst, 0, 0, 0, 0, 0, 0, RTA_DST, ipst);
		goto icmp_err_ret;
	}

	/*
	 * If we encounter CGTP, we should  have the caller use
	 * ip_newroute to resolve multirt instead of this function.
	 * CGTP specs explicitly state that it can't be used with routers.
	 * This essentially prevents insertion of incomplete RTF_MULTIRT
	 * ires in cachetable.
	 */
	if (ipst->ips_ip_cgtp_filter &&
	    ((ire->ire_flags & RTF_MULTIRT) ||
	    ((sire != NULL) && (sire->ire_flags & RTF_MULTIRT)))) {
		ip3dbg(("ire_forward: packet is to be multirouted- "
		    "handing it to ip_newroute\n"));
		if (sire != NULL)
			ire_refrele(sire);
		ire_refrele(ire);
		/*
		 * Inform caller about encountering of multirt so that
		 * ip_newroute() can be called.
		 */
		*ret_action = Forward_check_multirt;
		return (NULL);
	}

	/*
	 * Verify that the returned IRE does not have either
	 * the RTF_REJECT or RTF_BLACKHOLE flags set and that the IRE is
	 * either an IRE_CACHE, IRE_IF_NORESOLVER or IRE_IF_RESOLVER.
	 */
	if ((ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE)) ||
	    (ire->ire_type & (IRE_CACHE | IRE_INTERFACE)) == 0) {
		ip3dbg(("ire 0x%p is not cache/resolver/noresolver\n",
		    (void *)ire));
		goto icmp_err_ret;
	}

	/*
	 * If we already have a fully resolved IRE CACHE of the
	 * nexthop router, just hand over the cache entry
	 * and we are done.
	 */

	if (ire->ire_type & IRE_CACHE) {

		/*
		 * If we are using this ire cache entry as a
		 * gateway to forward packets, chances are we
		 * will be using it again. So turn off
		 * the temporary flag, thus reducing its
		 * chances of getting deleted frequently.
		 */
		if (ire->ire_marks & IRE_MARK_TEMPORARY) {
			irb_t *irb = ire->ire_bucket;
			rw_enter(&irb->irb_lock, RW_WRITER);
			/*
			 * We need to recheck for IRE_MARK_TEMPORARY after
			 * acquiring the lock in order to guarantee
			 * irb_tmp_ire_cnt
			 */
			if (ire->ire_marks & IRE_MARK_TEMPORARY) {
				ire->ire_marks &= ~IRE_MARK_TEMPORARY;
				irb->irb_tmp_ire_cnt--;
			}
			rw_exit(&irb->irb_lock);
		}

		if (sire != NULL) {
			UPDATE_OB_PKT_COUNT(sire);
			sire->ire_last_used_time = lbolt;
			ire_refrele(sire);
		}
		*ret_action = Forward_ok;
		return (ire);
	}
create_irecache:
	/*
	 * Increment the ire_ob_pkt_count field for ire if it is an
	 * INTERFACE (IF_RESOLVER or IF_NORESOLVER) IRE type, and
	 * increment the same for the parent IRE, sire, if it is some
	 * sort of prefix IRE (which includes DEFAULT, PREFIX, and HOST).
	 */
	if ((ire->ire_type & IRE_INTERFACE) != 0) {
		UPDATE_OB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
	}

	/*
	 * sire must be either IRE_CACHETABLE OR IRE_INTERFACE type
	 */
	if (sire != NULL) {
		gw = sire->ire_gateway_addr;
		ASSERT((sire->ire_type &
		    (IRE_CACHETABLE | IRE_INTERFACE)) == 0);
		UPDATE_OB_PKT_COUNT(sire);
		sire->ire_last_used_time = lbolt;
	}

	dst_ill = ire->ire_ipif->ipif_ill;
	if (IS_IPMP(dst_ill))
		dst_ill = ipmp_illgrp_hold_next_ill(dst_ill->ill_grp);
	else
		ill_refhold(dst_ill);

	if (dst_ill == NULL) {
		ip2dbg(("ire_forward no dst ill; ire 0x%p\n", (void *)ire));
		goto icmp_err_ret;
	}

	ASSERT(src_ipif == NULL);
	/* Now obtain the src_ipif */
	src_ipif = ire_forward_src_ipif(dst, sire, ire, zoneid, &ire_marks);
	if (src_ipif == NULL)
		goto icmp_err_ret;

	switch (ire->ire_type) {
	case IRE_IF_NORESOLVER:
		/* create ire_cache for ire_addr endpoint */
		if (dst_ill->ill_phys_addr_length != IP_ADDR_LEN &&
		    dst_ill->ill_resolver_mp == NULL) {
			ip1dbg(("ire_forward: dst_ill %p "
			    "for IRE_IF_NORESOLVER ire %p has "
			    "no ill_resolver_mp\n",
			    (void *)dst_ill, (void *)ire));
			goto icmp_err_ret;
		}
		/* FALLTHRU */
	case IRE_IF_RESOLVER:
		/*
		 * We have the IRE_IF_RESOLVER of the nexthop gateway
		 * and now need to build a IRE_CACHE for it.
		 * In this case, we have the following :
		 *
		 * 1) src_ipif - used for getting a source address.
		 *
		 * 2) dst_ill - from which we derive ire_stq/ire_rfq. This
		 *    means packets using the IRE_CACHE that we will build
		 *    here will go out on dst_ill.
		 *
		 * 3) sire may or may not be NULL. But, the IRE_CACHE that is
		 *    to be created will only be tied to the IRE_INTERFACE
		 *    that was derived from the ire_ihandle field.
		 *
		 *    If sire is non-NULL, it means the destination is
		 *    off-link and we will first create the IRE_CACHE for the
		 *    gateway.
		 */
		res_mp = dst_ill->ill_resolver_mp;
		if (ire->ire_type == IRE_IF_RESOLVER &&
		    (!OK_RESOLVER_MP(res_mp))) {
			goto icmp_err_ret;
		}
		/*
		 * To be at this point in the code with a non-zero gw
		 * means that dst is reachable through a gateway that
		 * we have never resolved.  By changing dst to the gw
		 * addr we resolve the gateway first.
		 */
		if (gw != INADDR_ANY) {
			/*
			 * The source ipif that was determined above was
			 * relative to the destination address, not the
			 * gateway's. If src_ipif was not taken out of
			 * the IRE_IF_RESOLVER entry, we'll need to call
			 * ipif_select_source() again.
			 */
			if (src_ipif != ire->ire_ipif) {
				ipif_refrele(src_ipif);
				src_ipif = ipif_select_source(dst_ill,
				    gw, zoneid);
				if (src_ipif == NULL)
					goto icmp_err_ret;
			}
			dst = gw;
			gw = INADDR_ANY;
		}
		/*
		 * dst has been set to the address of the nexthop.
		 *
		 * TSol note: get security attributes of the nexthop;
		 * Note that the nexthop may either be a gateway, or the
		 * packet destination itself; Detailed explanation of
		 * issues involved is  provided in the  IRE_IF_NORESOLVER
		 * logic in ip_newroute().
		 */
		ga.ga_af = AF_INET;
		IN6_IPADDR_TO_V4MAPPED(dst, &ga.ga_addr);
		gcgrp = gcgrp_lookup(&ga, B_FALSE);

		if (ire->ire_type == IRE_IF_NORESOLVER)
			dst = ire->ire_addr; /* ire_cache for tunnel endpoint */

		save_ire = ire;
		/*
		 * create an incomplete IRE_CACHE.
		 * An areq_mp will be generated in ire_arpresolve() for
		 * RESOLVER interfaces.
		 */
		ire = ire_create(
		    (uchar_t *)&dst,		/* dest address */
		    (uchar_t *)&ip_g_all_ones,	/* mask */
		    (uchar_t *)&src_ipif->ipif_src_addr, /* src addr */
		    (uchar_t *)&gw,		/* gateway address */
		    (save_ire->ire_type == IRE_IF_RESOLVER ?  NULL:
		    &save_ire->ire_max_frag),
		    NULL,
		    dst_ill->ill_rq,		/* recv-from queue */
		    dst_ill->ill_wq,		/* send-to queue */
		    IRE_CACHE,			/* IRE type */
		    src_ipif,
		    ire->ire_mask,		/* Parent mask */
		    0,
		    ire->ire_ihandle,	/* Interface handle */
		    0,
		    &(ire->ire_uinfo),
		    NULL,
		    gcgrp,
		    ipst);
		ip1dbg(("incomplete ire_cache 0x%p\n", (void *)ire));
		if (ire != NULL) {
			gcgrp = NULL; /* reference now held by IRE */
			ire->ire_marks |= ire_marks;
			/* add the incomplete ire: */
			error = ire_add(&ire, NULL, NULL, NULL, B_TRUE);
			if (error == 0 && ire != NULL) {
				ire->ire_max_frag = save_ire->ire_max_frag;
				ip1dbg(("setting max_frag to %d in ire 0x%p\n",
				    ire->ire_max_frag, (void *)ire));
			} else {
				ire_refrele(save_ire);
				goto icmp_err_ret;
			}
		} else {
			if (gcgrp != NULL) {
				GCGRP_REFRELE(gcgrp);
				gcgrp = NULL;
			}
		}

		ire_refrele(save_ire);
		break;
	default:
		break;
	}

	*ret_action = Forward_ok;
	if (sire != NULL)
		ire_refrele(sire);
	if (dst_ill != NULL)
		ill_refrele(dst_ill);
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	return (ire);
icmp_err_ret:
	*ret_action = Forward_ret_icmp_err;
	if (sire != NULL)
		ire_refrele(sire);
	if (dst_ill != NULL)
		ill_refrele(dst_ill);
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	if (ire != NULL) {
		if (ire->ire_flags & RTF_BLACKHOLE)
			*ret_action = Forward_blackhole;
		ire_refrele(ire);
	}
	return (NULL);
}

/*
 * Since caller is ip_fast_forward, there is no CGTP or Tsol test
 * Also we dont call ftable lookup with MATCH_IRE_PARENT
 */

ire_t *
ire_forward_simple(ipaddr_t dst, enum ire_forward_action *ret_action,
    ip_stack_t *ipst)
{
	ipaddr_t gw = 0;
	ire_t	*ire = NULL;
	ire_t   *sire = NULL, *save_ire;
	ill_t *dst_ill = NULL;
	int error;
	zoneid_t zoneid = GLOBAL_ZONEID;
	ipif_t *src_ipif = NULL;
	mblk_t *res_mp;
	ushort_t ire_marks = 0;

	ire = ire_ftable_lookup_simple(dst, &sire, zoneid,
	    MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT | MATCH_IRE_RJ_BHOLE, ipst);
	if (ire == NULL) {
		ip_rts_change(RTM_MISS, dst, 0, 0, 0, 0, 0, 0, RTA_DST, ipst);
		goto icmp_err_ret;
	}

	/*
	 * Verify that the returned IRE does not have either
	 * the RTF_REJECT or RTF_BLACKHOLE flags set and that the IRE is
	 * either an IRE_CACHE, IRE_IF_NORESOLVER or IRE_IF_RESOLVER.
	 */
	if ((ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE))) {
		ASSERT(ire->ire_type & (IRE_CACHE | IRE_INTERFACE));
		ip3dbg(("ire 0x%p is not cache/resolver/noresolver\n",
		    (void *)ire));
		goto icmp_err_ret;
	}

	/*
	 * If we already have a fully resolved IRE CACHE of the
	 * nexthop router, just hand over the cache entry
	 * and we are done.
	 */
	if (ire->ire_type & IRE_CACHE) {
		/*
		 * If we are using this ire cache entry as a
		 * gateway to forward packets, chances are we
		 * will be using it again. So turn off
		 * the temporary flag, thus reducing its
		 * chances of getting deleted frequently.
		 */
		if (ire->ire_marks & IRE_MARK_TEMPORARY) {
			irb_t *irb = ire->ire_bucket;
			rw_enter(&irb->irb_lock, RW_WRITER);
			ire->ire_marks &= ~IRE_MARK_TEMPORARY;
			irb->irb_tmp_ire_cnt--;
			rw_exit(&irb->irb_lock);
		}

		if (sire != NULL) {
			UPDATE_OB_PKT_COUNT(sire);
			ire_refrele(sire);
		}
		*ret_action = Forward_ok;
		return (ire);
	}
	/*
	 * Increment the ire_ob_pkt_count field for ire if it is an
	 * INTERFACE (IF_RESOLVER or IF_NORESOLVER) IRE type, and
	 * increment the same for the parent IRE, sire, if it is some
	 * sort of prefix IRE (which includes DEFAULT, PREFIX, and HOST).
	 */
	if ((ire->ire_type & IRE_INTERFACE) != 0) {
		UPDATE_OB_PKT_COUNT(ire);
		ire->ire_last_used_time = lbolt;
	}

	/*
	 * sire must be either IRE_CACHETABLE OR IRE_INTERFACE type
	 */
	if (sire != NULL) {
		gw = sire->ire_gateway_addr;
		ASSERT((sire->ire_type &
		    (IRE_CACHETABLE | IRE_INTERFACE)) == 0);
		UPDATE_OB_PKT_COUNT(sire);
	}

	dst_ill = ire->ire_ipif->ipif_ill;
	if (IS_IPMP(dst_ill))
		dst_ill = ipmp_illgrp_hold_next_ill(dst_ill->ill_grp);
	else
		ill_refhold(dst_ill);	/* for symmetry */

	if (dst_ill == NULL) {
		ip2dbg(("ire_forward_simple: no dst ill; ire 0x%p\n",
		    (void *)ire));
		goto icmp_err_ret;
	}

	ASSERT(src_ipif == NULL);
	/* Now obtain the src_ipif */
	src_ipif = ire_forward_src_ipif(dst, sire, ire, zoneid, &ire_marks);
	if (src_ipif == NULL)
		goto icmp_err_ret;

	switch (ire->ire_type) {
	case IRE_IF_NORESOLVER:
		/* create ire_cache for ire_addr endpoint */
	case IRE_IF_RESOLVER:
		/*
		 * We have the IRE_IF_RESOLVER of the nexthop gateway
		 * and now need to build a IRE_CACHE for it.
		 * In this case, we have the following :
		 *
		 * 1) src_ipif - used for getting a source address.
		 *
		 * 2) dst_ill - from which we derive ire_stq/ire_rfq. This
		 *    means packets using the IRE_CACHE that we will build
		 *    here will go out on dst_ill.
		 *
		 * 3) sire may or may not be NULL. But, the IRE_CACHE that is
		 *    to be created will only be tied to the IRE_INTERFACE
		 *    that was derived from the ire_ihandle field.
		 *
		 *    If sire is non-NULL, it means the destination is
		 *    off-link and we will first create the IRE_CACHE for the
		 *    gateway.
		 */
		res_mp = dst_ill->ill_resolver_mp;
		if (ire->ire_type == IRE_IF_RESOLVER &&
		    (!OK_RESOLVER_MP(res_mp))) {
			ire_refrele(ire);
			ire = NULL;
			goto out;
		}
		/*
		 * To be at this point in the code with a non-zero gw
		 * means that dst is reachable through a gateway that
		 * we have never resolved.  By changing dst to the gw
		 * addr we resolve the gateway first.
		 */
		if (gw != INADDR_ANY) {
			/*
			 * The source ipif that was determined above was
			 * relative to the destination address, not the
			 * gateway's. If src_ipif was not taken out of
			 * the IRE_IF_RESOLVER entry, we'll need to call
			 * ipif_select_source() again.
			 */
			if (src_ipif != ire->ire_ipif) {
				ipif_refrele(src_ipif);
				src_ipif = ipif_select_source(dst_ill,
				    gw, zoneid);
				if (src_ipif == NULL)
					goto icmp_err_ret;
			}
			dst = gw;
			gw = INADDR_ANY;
		}

		if (ire->ire_type == IRE_IF_NORESOLVER)
			dst = ire->ire_addr; /* ire_cache for tunnel endpoint */

		save_ire = ire;
		/*
		 * create an incomplete IRE_CACHE.
		 * An areq_mp will be generated in ire_arpresolve() for
		 * RESOLVER interfaces.
		 */
		ire = ire_create(
		    (uchar_t *)&dst,		/* dest address */
		    (uchar_t *)&ip_g_all_ones,	/* mask */
		    (uchar_t *)&src_ipif->ipif_src_addr, /* src addr */
		    (uchar_t *)&gw,		/* gateway address */
		    (save_ire->ire_type == IRE_IF_RESOLVER ?  NULL:
		    &save_ire->ire_max_frag),
		    NULL,
		    dst_ill->ill_rq,		/* recv-from queue */
		    dst_ill->ill_wq,		/* send-to queue */
		    IRE_CACHE,			/* IRE type */
		    src_ipif,
		    ire->ire_mask,		/* Parent mask */
		    0,
		    ire->ire_ihandle,	/* Interface handle */
		    0,
		    &(ire->ire_uinfo),
		    NULL,
		    NULL,
		    ipst);
		ip1dbg(("incomplete ire_cache 0x%p\n", (void *)ire));
		if (ire != NULL) {
			ire->ire_marks |= ire_marks;
			/* add the incomplete ire: */
			error = ire_add(&ire, NULL, NULL, NULL, B_TRUE);
			if (error == 0 && ire != NULL) {
				ire->ire_max_frag = save_ire->ire_max_frag;
				ip1dbg(("setting max_frag to %d in ire 0x%p\n",
				    ire->ire_max_frag, (void *)ire));
			} else {
				ire_refrele(save_ire);
				goto icmp_err_ret;
			}
		}

		ire_refrele(save_ire);
		break;
	default:
		break;
	}

out:
	*ret_action = Forward_ok;
	if (sire != NULL)
		ire_refrele(sire);
	if (dst_ill != NULL)
		ill_refrele(dst_ill);
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	return (ire);
icmp_err_ret:
	*ret_action = Forward_ret_icmp_err;
	if (src_ipif != NULL)
		ipif_refrele(src_ipif);
	if (dst_ill != NULL)
		ill_refrele(dst_ill);
	if (sire != NULL)
		ire_refrele(sire);
	if (ire != NULL) {
		if (ire->ire_flags & RTF_BLACKHOLE)
			*ret_action = Forward_blackhole;
		ire_refrele(ire);
	}
	/* caller needs to send icmp error message */
	return (NULL);

}

/*
 * Obtain the rt_entry and rt_irb for the route to be added to
 * the ips_ip_ftable.
 * First attempt to add a node to the radix tree via rn_addroute. If the
 * route already exists, return the bucket for the existing route.
 *
 * Locking notes: Need to hold the global radix tree lock in write mode to
 * add a radix node. To prevent the node from being deleted, ire_get_bucket()
 * returns with a ref'ed irb_t. The ire itself is added in ire_add_v4()
 * while holding the irb_lock, but not the radix tree lock.
 */
irb_t *
ire_get_bucket(ire_t *ire)
{
	struct radix_node *rn;
	struct rt_entry *rt;
	struct rt_sockaddr rmask, rdst;
	irb_t *irb = NULL;
	ip_stack_t *ipst = ire->ire_ipst;

	ASSERT(ipst->ips_ip_ftable != NULL);

	/* first try to see if route exists (based on rtalloc1) */
	(void) memset(&rdst, 0, sizeof (rdst));
	rdst.rt_sin_len = sizeof (rdst);
	rdst.rt_sin_family = AF_INET;
	rdst.rt_sin_addr.s_addr = ire->ire_addr;

	(void) memset(&rmask, 0, sizeof (rmask));
	rmask.rt_sin_len = sizeof (rmask);
	rmask.rt_sin_family = AF_INET;
	rmask.rt_sin_addr.s_addr = ire->ire_mask;

	/*
	 * add the route. based on BSD's rtrequest1(RTM_ADD)
	 */
	R_Malloc(rt, rt_entry_cache,  sizeof (*rt));
	/* kmem_alloc failed */
	if (rt == NULL)
		return (NULL);

	(void) memset(rt, 0, sizeof (*rt));
	rt->rt_nodes->rn_key = (char *)&rt->rt_dst;
	rt->rt_dst = rdst;
	irb = &rt->rt_irb;
	irb->irb_marks |= IRB_MARK_FTABLE; /* dynamically allocated/freed */
	irb->irb_ipst = ipst;
	rw_init(&irb->irb_lock, NULL, RW_DEFAULT, NULL);
	RADIX_NODE_HEAD_WLOCK(ipst->ips_ip_ftable);
	rn = ipst->ips_ip_ftable->rnh_addaddr(&rt->rt_dst, &rmask,
	    ipst->ips_ip_ftable, (struct radix_node *)rt);
	if (rn == NULL) {
		RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
		Free(rt, rt_entry_cache);
		rt = NULL;
		irb = NULL;
		RADIX_NODE_HEAD_RLOCK(ipst->ips_ip_ftable);
		rn = ipst->ips_ip_ftable->rnh_lookup(&rdst, &rmask,
		    ipst->ips_ip_ftable);
		if (rn != NULL && ((rn->rn_flags & RNF_ROOT) == 0)) {
			/* found a non-root match */
			rt = (struct rt_entry *)rn;
		}
	}
	if (rt != NULL) {
		irb = &rt->rt_irb;
		IRB_REFHOLD(irb);
	}
	RADIX_NODE_HEAD_UNLOCK(ipst->ips_ip_ftable);
	return (irb);
}

/*
 * This function is used when the caller wants to know the outbound
 * interface for a packet given only the address.
 * If this is a offlink IP address and there are multiple
 * routes to this destination, this routine will utilise the
 * first route it finds to IP address
 * Return values:
 * 	0	- FAILURE
 *	nonzero	- ifindex
 */
uint_t
ifindex_lookup(const struct sockaddr *ipaddr, zoneid_t zoneid)
{
	uint_t ifindex = 0;
	ire_t *ire;
	ill_t *ill;
	netstack_t *ns;
	ip_stack_t *ipst;

	if (zoneid == ALL_ZONES)
		ns = netstack_find_by_zoneid(GLOBAL_ZONEID);
	else
		ns = netstack_find_by_zoneid(zoneid);
	ASSERT(ns != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * since IP uses the global zoneid in the exclusive stacks.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	ipst = ns->netstack_ip;

	ASSERT(ipaddr->sa_family == AF_INET || ipaddr->sa_family == AF_INET6);

	if ((ire =  route_to_dst(ipaddr, zoneid, ipst)) != NULL) {
		ill = ire_to_ill(ire);
		if (ill != NULL)
			ifindex = ill->ill_phyint->phyint_ifindex;
		ire_refrele(ire);
	}
	netstack_rele(ns);
	return (ifindex);
}

/*
 * Routine to find the route to a destination. If a ifindex is supplied
 * it tries to match the the route to the corresponding ipif for the ifindex
 */
static	ire_t *
route_to_dst(const struct sockaddr *dst_addr, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t *ire = NULL;
	int match_flags;

	match_flags = (MATCH_IRE_DSTONLY | MATCH_IRE_DEFAULT |
	    MATCH_IRE_RECURSIVE | MATCH_IRE_RJ_BHOLE);

	/* XXX pass NULL tsl for now */

	if (dst_addr->sa_family == AF_INET) {
		ire = ire_route_lookup(
		    ((struct sockaddr_in *)dst_addr)->sin_addr.s_addr,
		    0, 0, 0, NULL, NULL, zoneid, NULL, match_flags, ipst);
	} else {
		ire = ire_route_lookup_v6(
		    &((struct sockaddr_in6 *)dst_addr)->sin6_addr,
		    0, 0, 0, NULL, NULL, zoneid, NULL, match_flags, ipst);
	}
	return (ire);
}

/*
 * This routine is called by IP Filter to send a packet out on the wire
 * to a specified V4 dst (which may be onlink or offlink). The ifindex may or
 * may not be 0. A non-null ifindex indicates IP Filter has stipulated
 * an outgoing interface and requires the nexthop to be on that interface.
 * IP WILL NOT DO the following to the data packet before sending it out:
 *	a. manipulate ttl
 *	b. ipsec work
 *	c. fragmentation
 *
 * If the packet has been prepared for hardware checksum then it will be
 * passed off to ip_send_align_cksum() to check that the flags set on the
 * packet are in alignment with the capabilities of the new outgoing NIC.
 *
 * Return values:
 *	0:		IP was able to send of the data pkt
 *	ECOMM:		Could not send packet
 *	ENONET		No route to dst. It is up to the caller
 *			to send icmp unreachable error message,
 *	EINPROGRESS	The macaddr of the onlink dst or that
 *			of the offlink dst's nexthop needs to get
 *			resolved before packet can be sent to dst.
 *			Thus transmission is not guaranteed.
 *
 */

int
ipfil_sendpkt(const struct sockaddr *dst_addr, mblk_t *mp, uint_t ifindex,
    zoneid_t zoneid)
{
	ire_t *ire = NULL, *sire = NULL;
	ire_t *ire_cache = NULL;
	int value;
	int match_flags;
	ipaddr_t dst;
	netstack_t *ns;
	ip_stack_t *ipst;
	enum ire_forward_action ret_action;

	ASSERT(mp != NULL);

	if (zoneid == ALL_ZONES)
		ns = netstack_find_by_zoneid(GLOBAL_ZONEID);
	else
		ns = netstack_find_by_zoneid(zoneid);
	ASSERT(ns != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * since IP uses the global zoneid in the exclusive stacks.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	ipst = ns->netstack_ip;

	ASSERT(dst_addr->sa_family == AF_INET ||
	    dst_addr->sa_family == AF_INET6);

	if (dst_addr->sa_family == AF_INET) {
		dst = ((struct sockaddr_in *)dst_addr)->sin_addr.s_addr;
	} else {
		/*
		 * We dont have support for V6 yet. It will be provided
		 * once RFE  6399103  has been delivered.
		 * Until then, for V6 dsts, IP Filter will not call
		 * this function. Instead the netinfo framework provides
		 * its own code path, in ip_inject_impl(), to achieve
		 * what it needs to do, for the time being.
		 */
		ip1dbg(("ipfil_sendpkt: no V6 support \n"));
		value = ECOMM;
		freemsg(mp);
		goto discard;
	}

	/*
	 * Lets get the ire. We might get the ire cache entry,
	 * or the ire,sire pair needed to create the cache entry.
	 * XXX pass NULL tsl for now.
	 */

	if (ifindex == 0) {
		/* There is no supplied index. So use the FIB info */

		match_flags = (MATCH_IRE_DSTONLY | MATCH_IRE_DEFAULT |
		    MATCH_IRE_RECURSIVE | MATCH_IRE_RJ_BHOLE);
		ire = ire_route_lookup(dst,
		    0, 0, 0, NULL, &sire, zoneid, MBLK_GETLABEL(mp),
		    match_flags, ipst);
	} else {
		ipif_t *supplied_ipif;
		ill_t *ill;

		match_flags = (MATCH_IRE_DSTONLY | MATCH_IRE_DEFAULT |
		    MATCH_IRE_RECURSIVE| MATCH_IRE_RJ_BHOLE|
		    MATCH_IRE_SECATTR | MATCH_IRE_ILL);

		/*
		 * If supplied ifindex is non-null, the only valid
		 * nexthop is one off of the interface corresponding
		 * to the specified ifindex.
		 */
		ill = ill_lookup_on_ifindex(ifindex, B_FALSE,
		    NULL, NULL, NULL, NULL, ipst);
		if (ill != NULL) {
			supplied_ipif = ipif_get_next_ipif(NULL, ill);
		} else {
			ip1dbg(("ipfil_sendpkt: Could not find"
			    " route to dst\n"));
			value = ECOMM;
			freemsg(mp);
			goto discard;
		}

		ire = ire_route_lookup(dst, 0, 0, 0, supplied_ipif,
		    &sire, zoneid, MBLK_GETLABEL(mp), match_flags, ipst);
		ipif_refrele(supplied_ipif);
		ill_refrele(ill);
	}

	/*
	 * Verify that the returned IRE is non-null and does
	 * not have either the RTF_REJECT or RTF_BLACKHOLE
	 * flags set and that the IRE is  either an IRE_CACHE,
	 * IRE_IF_NORESOLVER or IRE_IF_RESOLVER.
	 */
	if (ire == NULL ||
	    ((ire->ire_flags & (RTF_REJECT | RTF_BLACKHOLE)) ||
	    (ire->ire_type & (IRE_CACHE | IRE_INTERFACE)) == 0)) {
		/*
		 * Either ire could not be found or we got
		 * an invalid one
		 */
		ip1dbg(("ipfil_sendpkt: Could not find route to dst\n"));
		value = ENONET;
		freemsg(mp);
		goto discard;
	}

	/* IP Filter and CGTP dont mix. So bail out if CGTP is on */
	if (ipst->ips_ip_cgtp_filter &&
	    ((ire->ire_flags & RTF_MULTIRT) ||
	    ((sire != NULL) && (sire->ire_flags & RTF_MULTIRT)))) {
		ip1dbg(("ipfil_sendpkt: IPFilter does not work with CGTP\n"));
		value = ECOMM;
		freemsg(mp);
		goto discard;
	}

	ASSERT(ire->ire_type != IRE_CACHE || ire->ire_nce != NULL);

	/*
	 * If needed, we will create the ire cache entry for the
	 * nexthop, resolve its link-layer address and then send
	 * the packet out without ttl or IPSec processing.
	 */
	switch (ire->ire_type) {
	case IRE_CACHE:
		if (sire != NULL) {
			UPDATE_OB_PKT_COUNT(sire);
			sire->ire_last_used_time = lbolt;
			ire_refrele(sire);
		}
		ire_cache = ire;
		break;
	case IRE_IF_NORESOLVER:
	case IRE_IF_RESOLVER:
		/*
		 * Call ire_forward(). This function
		 * will, create the ire cache entry of the
		 * the nexthop and adds this incomplete ire
		 * to the ire cache table
		 */
		ire_cache = ire_forward(dst, &ret_action, ire, sire,
		    MBLK_GETLABEL(mp), ipst);
		if (ire_cache == NULL) {
			ip1dbg(("ipfil_sendpkt: failed to create the"
			    " ire cache entry \n"));
			value = ENONET;
			freemsg(mp);
			sire = NULL;
			ire = NULL;
			goto discard;
		}
		break;
	}

	if (DB_CKSUMFLAGS(mp)) {
		if (ip_send_align_hcksum_flags(mp, ire_to_ill(ire_cache)))
			goto cleanup;
	}

	/*
	 * Now that we have the ire cache entry of the nexthop, call
	 * ip_xmit_v4() to trigger mac addr resolution
	 * if necessary and send it once ready.
	 */

	value = ip_xmit_v4(mp, ire_cache, NULL, B_FALSE, NULL);
cleanup:
	ire_refrele(ire_cache);
	/*
	 * At this point, the reference for these have already been
	 * released within ire_forward() and/or ip_xmit_v4(). So we set
	 * them to NULL to make sure we dont drop the references
	 * again in case ip_xmit_v4() returns with either SEND_FAILED
	 * or LLHDR_RESLV_FAILED
	 */
	sire = NULL;
	ire = NULL;

	switch (value) {
	case SEND_FAILED:
		ip1dbg(("ipfil_sendpkt: Send failed\n"));
		value = ECOMM;
		break;
	case LLHDR_RESLV_FAILED:
		ip1dbg(("ipfil_sendpkt: Link-layer resolution"
		    "  failed\n"));
		value = ECOMM;
		break;
	case LOOKUP_IN_PROGRESS:
		netstack_rele(ns);
		return (EINPROGRESS);
	case SEND_PASSED:
		netstack_rele(ns);
		return (0);
	}
discard:
	if (dst_addr->sa_family == AF_INET) {
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
	} else {
		BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutDiscards);
	}
	if (ire != NULL)
		ire_refrele(ire);
	if (sire != NULL)
		ire_refrele(sire);
	netstack_rele(ns);
	return (value);
}


/*
 * We don't check for dohwcksum in here because it should be being used
 * elsewhere to control what flags are being set on the mblk.  That is,
 * if DB_CKSUMFLAGS() is non-zero then we assume dohwcksum to be true
 * for this packet.
 *
 * This function assumes that it is *only* being called for TCP or UDP
 * packets and nothing else.
 */
static int
ip_send_align_hcksum_flags(mblk_t *mp, ill_t *ill)
{
	int illhckflags;
	int mbhckflags;
	uint16_t *up;
	uint32_t cksum;
	ipha_t *ipha;
	ip6_t *ip6;
	int proto;
	int ipversion;
	int length;
	int start;
	ip6_pkt_t ipp;

	mbhckflags = DB_CKSUMFLAGS(mp);
	ASSERT(mbhckflags != 0);
	ASSERT(mp->b_datap->db_type == M_DATA);
	/*
	 * Since this function only knows how to manage the hardware checksum
	 * issue, reject and packets that have flags set on the aside from
	 * checksum related attributes as we cannot necessarily safely map
	 * that packet onto the new NIC.  Packets that can be potentially
	 * dropped here include those marked for LSO.
	 */
	if ((mbhckflags &
	    ~(HCK_FULLCKSUM|HCK_PARTIALCKSUM|HCK_IPV4_HDRCKSUM)) != 0) {
		DTRACE_PROBE2(pbr__incapable, (mblk_t *), mp, (ill_t *), ill);
		freemsg(mp);
		return (-1);
	}

	ipha = (ipha_t *)mp->b_rptr;

	/*
	 * Find out what the new NIC is capable of, if anything, and
	 * only allow it to be used with M_DATA mblks being sent out.
	 */
	if (ILL_HCKSUM_CAPABLE(ill)) {
		illhckflags = ill->ill_hcksum_capab->ill_hcksum_txflags;
	} else {
		/*
		 * No capabilities, so turn off everything.
		 */
		illhckflags = 0;
		(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, 0, 0, 0);
		mp->b_datap->db_struioflag &= ~STRUIO_IP;
	}

	DTRACE_PROBE4(pbr__info__a, (mblk_t *), mp, (ill_t *), ill,
	    uint32_t, illhckflags, uint32_t, mbhckflags);
	/*
	 * This block of code that looks for the position of the TCP/UDP
	 * checksum is early in this function because we need to know
	 * what needs to be blanked out for the hardware checksum case.
	 *
	 * That we're in this function implies that the packet is either
	 * TCP or UDP on Solaris, so checks are made for one protocol and
	 * if that fails, the other is therefore implied.
	 */
	ipversion = IPH_HDR_VERSION(ipha);

	if (ipversion == IPV4_VERSION) {
		proto = ipha->ipha_protocol;
		if (proto == IPPROTO_TCP) {
			up = IPH_TCPH_CHECKSUMP(ipha, IP_SIMPLE_HDR_LENGTH);
		} else {
			up = IPH_UDPH_CHECKSUMP(ipha, IP_SIMPLE_HDR_LENGTH);
		}
	} else {
		uint8_t lasthdr;

		/*
		 * Nothing I've seen indicates that IPv6 checksum'ing
		 * precludes the presence of extension headers, so we
		 * can't just look at the next header value in the IPv6
		 * packet header to see if it is TCP/UDP.
		 */
		ip6 = (ip6_t *)ipha;
		(void) memset(&ipp, 0, sizeof (ipp));
		start = ip_find_hdr_v6(mp, ip6, &ipp, &lasthdr);
		proto = lasthdr;

		if (proto == IPPROTO_TCP) {
			up = IPH_TCPH_CHECKSUMP(ipha, start);
		} else {
			up = IPH_UDPH_CHECKSUMP(ipha, start);
		}
	}

	/*
	 * The first case here is easiest:
	 * mblk hasn't asked for full checksum, but the card supports it.
	 *
	 * In addition, check for IPv4 header capability.  Note that only
	 * the mblk flag is checked and not ipversion.
	 */
	if ((((illhckflags & HCKSUM_INET_FULL_V4) && (ipversion == 4)) ||
	    (((illhckflags & HCKSUM_INET_FULL_V6) && (ipversion == 6)))) &&
	    ((mbhckflags & (HCK_FULLCKSUM|HCK_PARTIALCKSUM)) != 0)) {
		int newflags = HCK_FULLCKSUM;

		if ((mbhckflags & HCK_IPV4_HDRCKSUM) != 0) {
			if ((illhckflags & HCKSUM_IPHDRCKSUM) != 0) {
				newflags |= HCK_IPV4_HDRCKSUM;
			} else {
				/*
				 * Rather than call a function, just inline
				 * the computation of the basic IPv4 header.
				 */
				cksum = (ipha->ipha_dst >> 16) +
				    (ipha->ipha_dst & 0xFFFF) +
				    (ipha->ipha_src >> 16) +
				    (ipha->ipha_src & 0xFFFF);
				IP_HDR_CKSUM(ipha, cksum,
				    ((uint32_t *)ipha)[0],
				    ((uint16_t *)ipha)[4]);
			}
		}

		*up = 0;
		(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, 0,
		    newflags, 0);
		return (0);
	}

	DTRACE_PROBE2(pbr__info__b, int, ipversion, int, proto);

	/*
	 * Start calculating the pseudo checksum over the IP packet header.
	 * Although the final pseudo checksum used by TCP/UDP consists of
	 * more than just the address fields, we can use the result of
	 * adding those together a little bit further down for IPv4.
	 */
	if (ipversion == IPV4_VERSION) {
		cksum = (ipha->ipha_dst >> 16) + (ipha->ipha_dst & 0xFFFF) +
		    (ipha->ipha_src >> 16) + (ipha->ipha_src & 0xFFFF);
		start = IP_SIMPLE_HDR_LENGTH;
		length = ntohs(ipha->ipha_length);
		DTRACE_PROBE3(pbr__info__e, uint32_t, ipha->ipha_src,
		    uint32_t, ipha->ipha_dst, int, cksum);
	} else {
		uint16_t *pseudo;

		pseudo = (uint16_t *)&ip6->ip6_src;

		/* calculate pseudo-header checksum */
		cksum = pseudo[0] + pseudo[1] + pseudo[2] + pseudo[3] +
		    pseudo[4] + pseudo[5] + pseudo[6] + pseudo[7] +
		    pseudo[8] + pseudo[9] + pseudo[10] + pseudo[11] +
		    pseudo[12] + pseudo[13] + pseudo[14] + pseudo[15];

		length = ntohs(ip6->ip6_plen) + sizeof (ip6_t);
	}

	/* Fold the initial sum */
	cksum = (cksum & 0xffff) + (cksum >> 16);

	/*
	 * If the packet was asking for an IPv4 header checksum to be
	 * calculated but the interface doesn't support that, fill it in
	 * using our pseudo checksum as a starting point.
	 */
	if (((mbhckflags & HCK_IPV4_HDRCKSUM) != 0) &&
	    ((illhckflags & HCKSUM_IPHDRCKSUM) == 0)) {
		/*
		 * IP_HDR_CKSUM uses the 2rd arg to the macro in a destructive
		 * way so pass in a copy of the checksum calculated thus far.
		 */
		uint32_t ipsum = cksum;

		DB_CKSUMFLAGS(mp) &= ~HCK_IPV4_HDRCKSUM;

		IP_HDR_CKSUM(ipha, ipsum, ((uint32_t *)ipha)[0],
		    ((uint16_t *)ipha)[4]);
	}

	DTRACE_PROBE3(pbr__info__c, int, start, int, length, int, cksum);

	if (proto == IPPROTO_TCP) {
		cksum += IP_TCP_CSUM_COMP;
	} else {
		cksum += IP_UDP_CSUM_COMP;
	}
	cksum += htons(length - start);
	cksum = (cksum & 0xffff) + (cksum >> 16);

	/*
	 * For TCP/UDP, we either want to setup the packet for partial
	 * checksum or we want to do it all ourselves because the NIC
	 * offers no support for either partial or full checksum.
	 */
	if ((illhckflags & HCKSUM_INET_PARTIAL) != 0) {
		/*
		 * The only case we care about here is if the mblk was
		 * previously set for full checksum offload.  If it was
		 * marked for partial (and the NIC does partial), then
		 * we have nothing to do.  Similarly if the packet was
		 * not set for partial or full, we do nothing as this
		 * is cheaper than more work to set something up.
		 */
		if ((mbhckflags & HCK_FULLCKSUM) != 0) {
			uint32_t offset;

			if (proto == IPPROTO_TCP) {
				offset = TCP_CHECKSUM_OFFSET;
			} else {
				offset = UDP_CHECKSUM_OFFSET;
			}
			*up = cksum;

			DTRACE_PROBE3(pbr__info__f, int, length - start, int,
			    cksum, int, offset);

			(void) hcksum_assoc(mp, NULL, NULL, start,
			    start + offset, length, 0,
			    DB_CKSUMFLAGS(mp) | HCK_PARTIALCKSUM, 0);
		}

	} else if (mbhckflags & (HCK_FULLCKSUM|HCK_PARTIALCKSUM)) {
		DB_CKSUMFLAGS(mp) &= ~(HCK_PARTIALCKSUM|HCK_FULLCKSUM);

		*up = 0;
		*up = IP_CSUM(mp, start, cksum);
	}

	DTRACE_PROBE4(pbr__info__d, (mblk_t *), mp, (ipha_t *), ipha,
	    (uint16_t *), up, int, cksum);
	return (0);
}

/*
 * callback function provided by ire_ftable_lookup when calling
 * rn_match_args(). Invoke ire_match_args on each matching leaf node in
 * the radix tree.
 */
boolean_t
ire_find_best_route(struct radix_node *rn, void *arg)
{
	struct rt_entry *rt = (struct rt_entry *)rn;
	irb_t *irb_ptr;
	ire_t *ire;
	ire_ftable_args_t *margs = arg;
	ipaddr_t match_mask;

	ASSERT(rt != NULL);

	irb_ptr = &rt->rt_irb;

	if (irb_ptr->irb_ire_cnt == 0)
		return (B_FALSE);

	rw_enter(&irb_ptr->irb_lock, RW_READER);
	for (ire = irb_ptr->irb_ire; ire != NULL; ire = ire->ire_next) {
		if (ire->ire_marks & IRE_MARK_CONDEMNED)
			continue;
		if (margs->ift_flags & MATCH_IRE_MASK)
			match_mask = margs->ift_mask;
		else
			match_mask = ire->ire_mask;

		if (ire_match_args(ire, margs->ift_addr, match_mask,
		    margs->ift_gateway, margs->ift_type, margs->ift_ipif,
		    margs->ift_zoneid, margs->ift_ihandle, margs->ift_tsl,
		    margs->ift_flags, NULL)) {
			IRE_REFHOLD(ire);
			rw_exit(&irb_ptr->irb_lock);
			margs->ift_best_ire = ire;
			return (B_TRUE);
		}
	}
	rw_exit(&irb_ptr->irb_lock);
	return (B_FALSE);
}

/*
 * ftable irb_t structures are dynamically allocated, and we need to
 * check if the irb_t (and associated ftable tree attachment) needs to
 * be cleaned up when the irb_refcnt goes to 0. The conditions that need
 * be verified are:
 * - no other walkers of the irebucket, i.e., quiescent irb_refcnt,
 * - no other threads holding references to ire's in the bucket,
 *   i.e., irb_nire == 0
 * - no active ire's in the bucket, i.e., irb_ire_cnt == 0
 * - need to hold the global tree lock and irb_lock in write mode.
 */
void
irb_refrele_ftable(irb_t *irb)
{
	for (;;) {
		rw_enter(&irb->irb_lock, RW_WRITER);
		ASSERT(irb->irb_refcnt != 0);
		if (irb->irb_refcnt != 1) {
			/*
			 * Someone has a reference to this radix node
			 * or there is some bucket walker.
			 */
			irb->irb_refcnt--;
			rw_exit(&irb->irb_lock);
			return;
		} else {
			/*
			 * There is no other walker, nor is there any
			 * other thread that holds a direct ref to this
			 * radix node. Do the clean up if needed. Call
			 * to ire_unlink will clear the IRB_MARK_CONDEMNED flag
			 */
			if (irb->irb_marks & IRB_MARK_CONDEMNED)  {
				ire_t *ire_list;

				ire_list = ire_unlink(irb);
				rw_exit(&irb->irb_lock);

				if (ire_list != NULL)
					ire_cleanup(ire_list);
				/*
				 * more CONDEMNED entries could have
				 * been added while we dropped the lock,
				 * so we have to re-check.
				 */
				continue;
			}

			/*
			 * Now check if there are still any ires
			 * associated with this radix node.
			 */
			if (irb->irb_nire != 0) {
				/*
				 * someone is still holding on
				 * to ires in this bucket
				 */
				irb->irb_refcnt--;
				rw_exit(&irb->irb_lock);
				return;
			} else {
				/*
				 * Everything is clear. Zero walkers,
				 * Zero threads with a ref to this
				 * radix node, Zero ires associated with
				 * this radix node. Due to lock order,
				 * check the above conditions again
				 * after grabbing all locks in the right order
				 */
				rw_exit(&irb->irb_lock);
				if (irb_inactive(irb))
					return;
				/*
				 * irb_inactive could not free the irb.
				 * See if there are any walkers, if not
				 * try to clean up again.
				 */
			}
		}
	}
}

/*
 * IRE iterator used by ire_ftable_lookup() to process multiple default
 * routes. Given a starting point in the hash list (ire_origin), walk the IREs
 * in the bucket skipping default interface routes and deleted entries.
 * Returns the next IRE (unheld), or NULL when we're back to the starting point.
 * Assumes that the caller holds a reference on the IRE bucket.
 *
 * In the absence of good IRE_DEFAULT routes, this function will return
 * the first IRE_INTERFACE route found (if any).
 */
ire_t *
ire_round_robin(irb_t *irb_ptr, zoneid_t zoneid, ire_ftable_args_t *margs,
	ip_stack_t *ipst)
{
	ire_t	*ire_origin;
	ire_t	*ire, *maybe_ire = NULL;

	rw_enter(&irb_ptr->irb_lock, RW_WRITER);
	ire_origin = irb_ptr->irb_rr_origin;
	if (ire_origin != NULL) {
		ire_origin = ire_origin->ire_next;
		IRE_FIND_NEXT_ORIGIN(ire_origin);
	}

	if (ire_origin == NULL) {
		/*
		 * first time through routine, or we dropped off the end
		 * of list.
		 */
		ire_origin = irb_ptr->irb_ire;
		IRE_FIND_NEXT_ORIGIN(ire_origin);
	}
	irb_ptr->irb_rr_origin = ire_origin;
	IRB_REFHOLD_LOCKED(irb_ptr);
	rw_exit(&irb_ptr->irb_lock);

	DTRACE_PROBE2(ire__rr__origin, (irb_t *), irb_ptr,
	    (ire_t *), ire_origin);

	/*
	 * Round-robin the routers list looking for a route that
	 * matches the passed in parameters.
	 * We start with the ire we found above and we walk the hash
	 * list until we're back where we started. It doesn't matter if
	 * routes are added or deleted by other threads - we know this
	 * ire will stay in the list because we hold a reference on the
	 * ire bucket.
	 */
	ire = ire_origin;
	while (ire != NULL) {
		int match_flags = MATCH_IRE_TYPE | MATCH_IRE_SECATTR;
		ire_t *rire;

		if (ire->ire_marks & IRE_MARK_CONDEMNED)
			goto next_ire;

		if (!ire_match_args(ire, margs->ift_addr, (ipaddr_t)0,
		    margs->ift_gateway, margs->ift_type, margs->ift_ipif,
		    margs->ift_zoneid, margs->ift_ihandle, margs->ift_tsl,
		    margs->ift_flags, NULL))
			goto next_ire;

		if (ire->ire_type & IRE_INTERFACE) {
			/*
			 * keep looking to see if there is a non-interface
			 * default ire, but save this one as a last resort.
			 */
			if (maybe_ire == NULL)
				maybe_ire = ire;
			goto next_ire;
		}

		if (zoneid == ALL_ZONES) {
			IRE_REFHOLD(ire);
			IRB_REFRELE(irb_ptr);
			return (ire);
		}
		/*
		 * When we're in a non-global zone, we're only
		 * interested in routers that are
		 * reachable through ipifs within our zone.
		 */
		if (ire->ire_ipif != NULL)
			match_flags |= MATCH_IRE_ILL;

		rire = ire_route_lookup(ire->ire_gateway_addr, 0, 0,
		    IRE_INTERFACE, ire->ire_ipif, NULL, zoneid, margs->ift_tsl,
		    match_flags, ipst);
		if (rire != NULL) {
			ire_refrele(rire);
			IRE_REFHOLD(ire);
			IRB_REFRELE(irb_ptr);
			return (ire);
		}
next_ire:
		ire = (ire->ire_next ?  ire->ire_next : irb_ptr->irb_ire);
		if (ire == ire_origin)
			break;
	}
	if (maybe_ire != NULL)
		IRE_REFHOLD(maybe_ire);
	IRB_REFRELE(irb_ptr);
	return (maybe_ire);
}

void
irb_refhold_rn(struct radix_node *rn)
{
	if ((rn->rn_flags & RNF_ROOT) == 0)
		IRB_REFHOLD(&((rt_t *)(rn))->rt_irb);
}

void
irb_refrele_rn(struct radix_node *rn)
{
	if ((rn->rn_flags & RNF_ROOT) == 0)
		irb_refrele_ftable(&((rt_t *)(rn))->rt_irb);
}
