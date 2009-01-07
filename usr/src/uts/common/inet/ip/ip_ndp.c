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

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/dlpi.h>
#include <sys/socket.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/zone.h>
#include <sys/ethernet.h>
#include <sys/sdt.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ipclassifier.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <inet/ip6.h>
#include <inet/ip_ndp.h>
#include <inet/ipsec_impl.h>
#include <inet/ipsec_info.h>
#include <inet/sctp_ip.h>

/*
 * Function names with nce_ prefix are static while function
 * names with ndp_ prefix are used by rest of the IP.
 *
 * Lock ordering:
 *
 *	ndp_g_lock -> ill_lock -> nce_lock
 *
 * The ndp_g_lock protects the NCE hash (nce_hash_tbl, NCE_HASH_PTR) and
 * nce_next.  Nce_lock protects the contents of the NCE (particularly
 * nce_refcnt).
 */

static	boolean_t nce_cmp_ll_addr(const nce_t *nce, const uchar_t *new_ll_addr,
    uint32_t ll_addr_len);
static	void	nce_ire_delete(nce_t *nce);
static	void	nce_ire_delete1(ire_t *ire, char *nce_arg);
static	void 	nce_set_ll(nce_t *nce, uchar_t *ll_addr);
static	nce_t	*nce_lookup_addr(ill_t *, boolean_t, const in6_addr_t *,
    nce_t *);
static	nce_t	*nce_lookup_mapping(ill_t *, const in6_addr_t *);
static	void	nce_make_mapping(nce_t *nce, uchar_t *addrpos,
    uchar_t *addr);
static	int	nce_set_multicast(ill_t *ill, const in6_addr_t *addr);
static	void	nce_queue_mp(nce_t *nce, mblk_t *mp);
static	mblk_t	*nce_udreq_alloc(ill_t *ill);
static	void	nce_update(nce_t *nce, uint16_t new_state,
    uchar_t *new_ll_addr);
static	uint32_t	nce_solicit(nce_t *nce, mblk_t *mp);
static	boolean_t	nce_xmit(ill_t *ill, uint8_t type,
    boolean_t use_lla_addr, const in6_addr_t *sender,
    const in6_addr_t *target, int flag);
static boolean_t	nce_xmit_advert(nce_t *nce, boolean_t use_nd_lla,
    const in6_addr_t *target, uint_t flags);
static boolean_t	nce_xmit_solicit(nce_t *nce, boolean_t use_nd_lla,
    const in6_addr_t *src, uint_t flags);
static int	ndp_add_v4(ill_t *, const in_addr_t *, uint16_t,
    nce_t **, nce_t *);
static ipif_t	*ip_ndp_lookup_addr_v6(const in6_addr_t *v6addrp, ill_t *ill);

#ifdef DEBUG
static void	nce_trace_cleanup(const nce_t *);
#endif

#define	NCE_HASH_PTR_V4(ipst, addr)					\
	(&((ipst)->ips_ndp4->nce_hash_tbl[IRE_ADDR_HASH(addr, NCE_TABLE_SIZE)]))

#define	NCE_HASH_PTR_V6(ipst, addr)				 \
	(&((ipst)->ips_ndp6->nce_hash_tbl[NCE_ADDR_HASH_V6(addr, \
		NCE_TABLE_SIZE)]))

/* Non-tunable probe interval, based on link capabilities */
#define	ILL_PROBE_INTERVAL(ill)	((ill)->ill_note_link ? 150 : 1500)

/*
 * NDP Cache Entry creation routine.
 * Mapped entries will never do NUD .
 * This routine must always be called with ndp6->ndp_g_lock held.
 * Prior to return, nce_refcnt is incremented.
 */
int
ndp_add_v6(ill_t *ill, uchar_t *hw_addr, const in6_addr_t *addr,
    const in6_addr_t *mask, const in6_addr_t *extract_mask,
    uint32_t hw_extract_start, uint16_t flags, uint16_t state,
    nce_t **newnce)
{
	static	nce_t		nce_nil;
	nce_t		*nce;
	mblk_t		*mp;
	mblk_t		*template;
	nce_t		**ncep;
	int		err;
	boolean_t	dropped = B_FALSE;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(MUTEX_HELD(&ipst->ips_ndp6->ndp_g_lock));
	ASSERT(ill != NULL && ill->ill_isv6);
	if (IN6_IS_ADDR_UNSPECIFIED(addr)) {
		ip0dbg(("ndp_add_v6: no addr\n"));
		return (EINVAL);
	}
	if ((flags & ~NCE_EXTERNAL_FLAGS_MASK)) {
		ip0dbg(("ndp_add_v6: flags = %x\n", (int)flags));
		return (EINVAL);
	}
	if (IN6_IS_ADDR_UNSPECIFIED(extract_mask) &&
	    (flags & NCE_F_MAPPING)) {
		ip0dbg(("ndp_add_v6: extract mask zero for mapping"));
		return (EINVAL);
	}
	/*
	 * Allocate the mblk to hold the nce.
	 *
	 * XXX This can come out of a separate cache - nce_cache.
	 * We don't need the mp anymore as there are no more
	 * "qwriter"s
	 */
	mp = allocb(sizeof (nce_t), BPRI_MED);
	if (mp == NULL)
		return (ENOMEM);

	nce = (nce_t *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)&nce[1];
	*nce = nce_nil;

	/*
	 * This one holds link layer address
	 */
	if (ill->ill_net_type == IRE_IF_RESOLVER) {
		template = nce_udreq_alloc(ill);
	} else {
		if (ill->ill_resolver_mp == NULL) {
			freeb(mp);
			return (EINVAL);
		}
		ASSERT((ill->ill_net_type == IRE_IF_NORESOLVER));
		template = copyb(ill->ill_resolver_mp);
	}
	if (template == NULL) {
		freeb(mp);
		return (ENOMEM);
	}
	nce->nce_ill = ill;
	nce->nce_ipversion = IPV6_VERSION;
	nce->nce_flags = flags;
	nce->nce_state = state;
	nce->nce_pcnt = ND_MAX_UNICAST_SOLICIT;
	nce->nce_rcnt = ill->ill_xmit_count;
	nce->nce_addr = *addr;
	nce->nce_mask = *mask;
	nce->nce_extract_mask = *extract_mask;
	nce->nce_ll_extract_start = hw_extract_start;
	nce->nce_fp_mp = NULL;
	nce->nce_res_mp = template;
	if (state == ND_REACHABLE)
		nce->nce_last = TICK_TO_MSEC(lbolt64);
	else
		nce->nce_last = 0;
	nce->nce_qd_mp = NULL;
	nce->nce_mp = mp;
	if (hw_addr != NULL)
		nce_set_ll(nce, hw_addr);
	/* This one is for nce getting created */
	nce->nce_refcnt = 1;
	mutex_init(&nce->nce_lock, NULL, MUTEX_DEFAULT, NULL);
	if (nce->nce_flags & NCE_F_MAPPING) {
		ASSERT(IN6_IS_ADDR_MULTICAST(addr));
		ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&nce->nce_mask));
		ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&nce->nce_extract_mask));
		ncep = &ipst->ips_ndp6->nce_mask_entries;
	} else {
		ncep = ((nce_t **)NCE_HASH_PTR_V6(ipst, *addr));
	}

	nce->nce_trace_disable = B_FALSE;

	/*
	 * Atomically ensure that the ill is not CONDEMNED, before
	 * adding the NCE.
	 */
	mutex_enter(&ill->ill_lock);
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		mutex_exit(&ill->ill_lock);
		freeb(mp);
		freeb(template);
		return (EINVAL);
	}
	if ((nce->nce_next = *ncep) != NULL)
		nce->nce_next->nce_ptpn = &nce->nce_next;
	*ncep = nce;
	nce->nce_ptpn = ncep;
	*newnce = nce;
	/* This one is for nce being used by an active thread */
	NCE_REFHOLD(*newnce);

	/* Bump up the number of nce's referencing this ill */
	DTRACE_PROBE3(ill__incr__cnt, (ill_t *), ill,
	    (char *), "nce", (void *), nce);
	ill->ill_nce_cnt++;
	mutex_exit(&ill->ill_lock);

	err = 0;
	if ((flags & NCE_F_PERMANENT) && state == ND_PROBE) {
		mutex_enter(&nce->nce_lock);
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		nce->nce_pcnt = ND_MAX_UNICAST_SOLICIT;
		mutex_exit(&nce->nce_lock);
		dropped = nce_xmit_solicit(nce, B_FALSE, NULL, NDP_PROBE);
		if (dropped) {
			mutex_enter(&nce->nce_lock);
			nce->nce_pcnt++;
			mutex_exit(&nce->nce_lock);
		}
		NDP_RESTART_TIMER(nce, ILL_PROBE_INTERVAL(ill));
		mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
		err = EINPROGRESS;
	} else if (flags & NCE_F_UNSOL_ADV) {
		/*
		 * We account for the transmit below by assigning one
		 * less than the ndd variable. Subsequent decrements
		 * are done in ndp_timer.
		 */
		mutex_enter(&nce->nce_lock);
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		nce->nce_unsolicit_count = ipst->ips_ip_ndp_unsolicit_count - 1;
		mutex_exit(&nce->nce_lock);
		dropped = nce_xmit_advert(nce, B_TRUE, &ipv6_all_hosts_mcast,
		    0);
		mutex_enter(&nce->nce_lock);
		if (dropped)
			nce->nce_unsolicit_count++;
		if (nce->nce_unsolicit_count != 0) {
			ASSERT(nce->nce_timeout_id == 0);
			nce->nce_timeout_id = timeout(ndp_timer, nce,
			    MSEC_TO_TICK(ipst->ips_ip_ndp_unsolicit_interval));
		}
		mutex_exit(&nce->nce_lock);
		mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
	}

	/*
	 * If the hw_addr is NULL, typically for ND_INCOMPLETE nces, then
	 * we call nce_fastpath as soon as the nce is resolved in ndp_process.
	 * We call nce_fastpath from nce_update if the link layer address of
	 * the peer changes from nce_update
	 */
	if (hw_addr != NULL || ill->ill_net_type == IRE_IF_NORESOLVER)
		nce_fastpath(nce);
	return (err);
}

int
ndp_lookup_then_add_v6(ill_t *ill, boolean_t match_illgrp, uchar_t *hw_addr,
    const in6_addr_t *addr, const in6_addr_t *mask,
    const in6_addr_t *extract_mask, uint32_t hw_extract_start, uint16_t flags,
    uint16_t state, nce_t **newnce)
{
	int	err = 0;
	nce_t	*nce;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ill->ill_isv6);
	mutex_enter(&ipst->ips_ndp6->ndp_g_lock);

	/* Get head of v6 hash table */
	nce = *((nce_t **)NCE_HASH_PTR_V6(ipst, *addr));
	nce = nce_lookup_addr(ill, match_illgrp, addr, nce);
	if (nce == NULL) {
		err = ndp_add_v6(ill,
		    hw_addr,
		    addr,
		    mask,
		    extract_mask,
		    hw_extract_start,
		    flags,
		    state,
		    newnce);
	} else {
		*newnce = nce;
		err = EEXIST;
	}
	mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
	return (err);
}

/*
 * Remove all the CONDEMNED nces from the appropriate hash table.
 * We create a private list of NCEs, these may have ires pointing
 * to them, so the list will be passed through to clean up dependent
 * ires and only then we can do NCE_REFRELE which can make NCE inactive.
 */
static void
nce_remove(ndp_g_t *ndp, nce_t *nce, nce_t **free_nce_list)
{
	nce_t *nce1;
	nce_t **ptpn;

	ASSERT(MUTEX_HELD(&ndp->ndp_g_lock));
	ASSERT(ndp->ndp_g_walker == 0);
	for (; nce; nce = nce1) {
		nce1 = nce->nce_next;
		mutex_enter(&nce->nce_lock);
		if (nce->nce_flags & NCE_F_CONDEMNED) {
			ptpn = nce->nce_ptpn;
			nce1 = nce->nce_next;
			if (nce1 != NULL)
				nce1->nce_ptpn = ptpn;
			*ptpn = nce1;
			nce->nce_ptpn = NULL;
			nce->nce_next = NULL;
			nce->nce_next = *free_nce_list;
			*free_nce_list = nce;
		}
		mutex_exit(&nce->nce_lock);
	}
}

/*
 * 1. Mark the nce CONDEMNED. This ensures that no new nce_lookup()
 *    will return this NCE. Also no new IREs will be created that
 *    point to this NCE (See ire_add_v6).  Also no new timeouts will
 *    be started (See NDP_RESTART_TIMER).
 * 2. Cancel any currently running timeouts.
 * 3. If there is an ndp walker, return. The walker will do the cleanup.
 *    This ensures that walkers see a consistent list of NCEs while walking.
 * 4. Otherwise remove the NCE from the list of NCEs
 * 5. Delete all IREs pointing to this NCE.
 */
void
ndp_delete(nce_t *nce)
{
	nce_t	**ptpn;
	nce_t	*nce1;
	int	ipversion = nce->nce_ipversion;
	ndp_g_t *ndp;
	ip_stack_t	*ipst = nce->nce_ill->ill_ipst;

	if (ipversion == IPV4_VERSION)
		ndp = ipst->ips_ndp4;
	else
		ndp = ipst->ips_ndp6;

	/* Serialize deletes */
	mutex_enter(&nce->nce_lock);
	if (nce->nce_flags & NCE_F_CONDEMNED) {
		/* Some other thread is doing the delete */
		mutex_exit(&nce->nce_lock);
		return;
	}
	/*
	 * Caller has a refhold. Also 1 ref for being in the list. Thus
	 * refcnt has to be >= 2
	 */
	ASSERT(nce->nce_refcnt >= 2);
	nce->nce_flags |= NCE_F_CONDEMNED;
	mutex_exit(&nce->nce_lock);

	nce_fastpath_list_delete(nce);

	/*
	 * Cancel any running timer. Timeout can't be restarted
	 * since CONDEMNED is set. Can't hold nce_lock across untimeout.
	 * Passing invalid timeout id is fine.
	 */
	if (nce->nce_timeout_id != 0) {
		(void) untimeout(nce->nce_timeout_id);
		nce->nce_timeout_id = 0;
	}

	mutex_enter(&ndp->ndp_g_lock);
	if (nce->nce_ptpn == NULL) {
		/*
		 * The last ndp walker has already removed this nce from
		 * the list after we marked the nce CONDEMNED and before
		 * we grabbed the global lock.
		 */
		mutex_exit(&ndp->ndp_g_lock);
		return;
	}
	if (ndp->ndp_g_walker > 0) {
		/*
		 * Can't unlink. The walker will clean up
		 */
		ndp->ndp_g_walker_cleanup = B_TRUE;
		mutex_exit(&ndp->ndp_g_lock);
		return;
	}

	/*
	 * Now remove the nce from the list. NDP_RESTART_TIMER won't restart
	 * the timer since it is marked CONDEMNED.
	 */
	ptpn = nce->nce_ptpn;
	nce1 = nce->nce_next;
	if (nce1 != NULL)
		nce1->nce_ptpn = ptpn;
	*ptpn = nce1;
	nce->nce_ptpn = NULL;
	nce->nce_next = NULL;
	mutex_exit(&ndp->ndp_g_lock);

	nce_ire_delete(nce);
}

void
ndp_inactive(nce_t *nce)
{
	mblk_t		**mpp;
	ill_t		*ill;

	ASSERT(nce->nce_refcnt == 0);
	ASSERT(MUTEX_HELD(&nce->nce_lock));
	ASSERT(nce->nce_fastpath == NULL);

	/* Free all nce allocated messages */
	mpp = &nce->nce_first_mp_to_free;
	do {
		while (*mpp != NULL) {
			mblk_t  *mp;

			mp = *mpp;
			*mpp = mp->b_next;

			inet_freemsg(mp);
		}
	} while (mpp++ != &nce->nce_last_mp_to_free);

#ifdef DEBUG
	nce_trace_cleanup(nce);
#endif

	ill = nce->nce_ill;
	mutex_enter(&ill->ill_lock);
	DTRACE_PROBE3(ill__decr__cnt, (ill_t *), ill,
	    (char *), "nce", (void *), nce);
	ill->ill_nce_cnt--;
	/*
	 * If the number of nce's associated with this ill have dropped
	 * to zero, check whether we need to restart any operation that
	 * is waiting for this to happen.
	 */
	if (ILL_DOWN_OK(ill)) {
		/* ipif_ill_refrele_tail drops the ill_lock */
		ipif_ill_refrele_tail(ill);
	} else {
		mutex_exit(&ill->ill_lock);
	}
	mutex_destroy(&nce->nce_lock);
	if (nce->nce_mp != NULL)
		inet_freemsg(nce->nce_mp);
}

/*
 * ndp_walk routine.  Delete the nce if it is associated with the ill
 * that is going away.  Always called as a writer.
 */
void
ndp_delete_per_ill(nce_t *nce, uchar_t *arg)
{
	if ((nce != NULL) && nce->nce_ill == (ill_t *)arg) {
		ndp_delete(nce);
	}
}

/*
 * Walk a list of to be inactive NCEs and blow away all the ires.
 */
static void
nce_ire_delete_list(nce_t *nce)
{
	nce_t *nce_next;

	ASSERT(nce != NULL);
	while (nce != NULL) {
		nce_next = nce->nce_next;
		nce->nce_next = NULL;

		/*
		 * It is possible for the last ndp walker (this thread)
		 * to come here after ndp_delete has marked the nce CONDEMNED
		 * and before it has removed the nce from the fastpath list
		 * or called untimeout. So we need to do it here. It is safe
		 * for both ndp_delete and this thread to do it twice or
		 * even simultaneously since each of the threads has a
		 * reference on the nce.
		 */
		nce_fastpath_list_delete(nce);
		/*
		 * Cancel any running timer. Timeout can't be restarted
		 * since CONDEMNED is set. Can't hold nce_lock across untimeout.
		 * Passing invalid timeout id is fine.
		 */
		if (nce->nce_timeout_id != 0) {
			(void) untimeout(nce->nce_timeout_id);
			nce->nce_timeout_id = 0;
		}
		/*
		 * We might hit this func thus in the v4 case:
		 * ipif_down->ipif_ndp_down->ndp_walk
		 */

		if (nce->nce_ipversion == IPV4_VERSION) {
			ire_walk_ill_v4(MATCH_IRE_ILL | MATCH_IRE_TYPE,
			    IRE_CACHE, nce_ire_delete1, nce, nce->nce_ill);
		} else {
			ASSERT(nce->nce_ipversion == IPV6_VERSION);
			ire_walk_ill_v6(MATCH_IRE_ILL | MATCH_IRE_TYPE,
			    IRE_CACHE, nce_ire_delete1, nce, nce->nce_ill);
		}
		NCE_REFRELE_NOTR(nce);
		nce = nce_next;
	}
}

/*
 * Delete an ire when the nce goes away.
 */
/* ARGSUSED */
static void
nce_ire_delete(nce_t *nce)
{
	if (nce->nce_ipversion == IPV6_VERSION) {
		ire_walk_ill_v6(MATCH_IRE_ILL | MATCH_IRE_TYPE, IRE_CACHE,
		    nce_ire_delete1, (char *)nce, nce->nce_ill);
		NCE_REFRELE_NOTR(nce);
	} else {
		ire_walk_ill_v4(MATCH_IRE_ILL | MATCH_IRE_TYPE, IRE_CACHE,
		    nce_ire_delete1, (char *)nce, nce->nce_ill);
		NCE_REFRELE_NOTR(nce);
	}
}

/*
 * ire_walk routine used to delete every IRE that shares this nce
 */
static void
nce_ire_delete1(ire_t *ire, char *nce_arg)
{
	nce_t	*nce = (nce_t *)nce_arg;

	ASSERT(ire->ire_type == IRE_CACHE);

	if (ire->ire_nce == nce) {
		ASSERT(ire->ire_ipversion == nce->nce_ipversion);
		ire_delete(ire);
	}
}

/*
 * Restart DAD on given NCE.  Returns B_TRUE if DAD has been restarted.
 */
boolean_t
ndp_restart_dad(nce_t *nce)
{
	boolean_t started;
	boolean_t dropped;

	if (nce == NULL)
		return (B_FALSE);
	mutex_enter(&nce->nce_lock);
	if (nce->nce_state == ND_PROBE) {
		mutex_exit(&nce->nce_lock);
		started = B_TRUE;
	} else if (nce->nce_state == ND_REACHABLE) {
		nce->nce_state = ND_PROBE;
		nce->nce_pcnt = ND_MAX_UNICAST_SOLICIT - 1;
		mutex_exit(&nce->nce_lock);
		dropped = nce_xmit_solicit(nce, B_FALSE, NULL, NDP_PROBE);
		if (dropped) {
			mutex_enter(&nce->nce_lock);
			nce->nce_pcnt++;
			mutex_exit(&nce->nce_lock);
		}
		NDP_RESTART_TIMER(nce, ILL_PROBE_INTERVAL(nce->nce_ill));
		started = B_TRUE;
	} else {
		mutex_exit(&nce->nce_lock);
		started = B_FALSE;
	}
	return (started);
}

/*
 * IPv6 Cache entry lookup.  Try to find an nce matching the parameters passed.
 * If one is found, the refcnt on the nce will be incremented.
 */
nce_t *
ndp_lookup_v6(ill_t *ill, boolean_t match_illgrp, const in6_addr_t *addr,
    boolean_t caller_holds_lock)
{
	nce_t	*nce;
	ip_stack_t *ipst = ill->ill_ipst;

	ASSERT(ill->ill_isv6);
	if (!caller_holds_lock)
		mutex_enter(&ipst->ips_ndp6->ndp_g_lock);

	/* Get head of v6 hash table */
	nce = *((nce_t **)NCE_HASH_PTR_V6(ipst, *addr));
	nce = nce_lookup_addr(ill, match_illgrp, addr, nce);
	if (nce == NULL)
		nce = nce_lookup_mapping(ill, addr);
	if (!caller_holds_lock)
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
	return (nce);
}
/*
 * IPv4 Cache entry lookup.  Try to find an nce matching the parameters passed.
 * If one is found, the refcnt on the nce will be incremented.
 * Since multicast mappings are handled in arp, there are no nce_mcast_entries
 * so we skip the nce_lookup_mapping call.
 * XXX TODO: if the nce is found to be ND_STALE, ndp_delete it and return NULL
 */
nce_t *
ndp_lookup_v4(ill_t *ill, const in_addr_t *addr, boolean_t caller_holds_lock)
{
	nce_t	*nce;
	in6_addr_t addr6;
	ip_stack_t *ipst = ill->ill_ipst;

	if (!caller_holds_lock)
		mutex_enter(&ipst->ips_ndp4->ndp_g_lock);

	/* Get head of v4 hash table */
	nce = *((nce_t **)NCE_HASH_PTR_V4(ipst, *addr));
	IN6_IPADDR_TO_V4MAPPED(*addr, &addr6);
	/*
	 * NOTE: IPv4 never matches across the illgrp since the NCE's we're
	 * looking up have fastpath headers that are inherently per-ill.
	 */
	nce = nce_lookup_addr(ill, B_FALSE, &addr6, nce);
	if (!caller_holds_lock)
		mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
	return (nce);
}

/*
 * Cache entry lookup.  Try to find an nce matching the parameters passed.
 * Look only for exact entries (no mappings).  If an nce is found, increment
 * the hold count on that nce. The caller passes in the start of the
 * appropriate hash table, and must be holding the appropriate global
 * lock (ndp_g_lock).
 */
static nce_t *
nce_lookup_addr(ill_t *ill, boolean_t match_illgrp, const in6_addr_t *addr,
    nce_t *nce)
{
	ndp_g_t		*ndp;
	ip_stack_t	*ipst = ill->ill_ipst;

	if (ill->ill_isv6)
		ndp = ipst->ips_ndp6;
	else
		ndp = ipst->ips_ndp4;

	ASSERT(MUTEX_HELD(&ndp->ndp_g_lock));
	if (IN6_IS_ADDR_UNSPECIFIED(addr))
		return (NULL);
	for (; nce != NULL; nce = nce->nce_next) {
		if (nce->nce_ill == ill ||
		    match_illgrp && IS_IN_SAME_ILLGRP(ill, nce->nce_ill)) {
			if (IN6_ARE_ADDR_EQUAL(&nce->nce_addr, addr) &&
			    IN6_ARE_ADDR_EQUAL(&nce->nce_mask,
			    &ipv6_all_ones)) {
				mutex_enter(&nce->nce_lock);
				if (!(nce->nce_flags & NCE_F_CONDEMNED)) {
					NCE_REFHOLD_LOCKED(nce);
					mutex_exit(&nce->nce_lock);
					break;
				}
				mutex_exit(&nce->nce_lock);
			}
		}
	}
	return (nce);
}

/*
 * Cache entry lookup.  Try to find an nce matching the parameters passed.
 * Look only for mappings.
 */
static nce_t *
nce_lookup_mapping(ill_t *ill, const in6_addr_t *addr)
{
	nce_t	*nce;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ill != NULL && ill->ill_isv6);
	ASSERT(MUTEX_HELD(&ipst->ips_ndp6->ndp_g_lock));
	if (!IN6_IS_ADDR_MULTICAST(addr))
		return (NULL);
	nce = ipst->ips_ndp6->nce_mask_entries;
	for (; nce != NULL; nce = nce->nce_next)
		if (nce->nce_ill == ill &&
		    (V6_MASK_EQ(*addr, nce->nce_mask, nce->nce_addr))) {
			mutex_enter(&nce->nce_lock);
			if (!(nce->nce_flags & NCE_F_CONDEMNED)) {
				NCE_REFHOLD_LOCKED(nce);
				mutex_exit(&nce->nce_lock);
				break;
			}
			mutex_exit(&nce->nce_lock);
		}
	return (nce);
}

/*
 * Process passed in parameters either from an incoming packet or via
 * user ioctl.
 */
static void
nce_process(nce_t *nce, uchar_t *hw_addr, uint32_t flag, boolean_t is_adv)
{
	ill_t	*ill = nce->nce_ill;
	uint32_t hw_addr_len = ill->ill_nd_lla_len;
	mblk_t	*mp;
	boolean_t ll_updated = B_FALSE;
	boolean_t ll_changed;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(nce->nce_ipversion == IPV6_VERSION);
	/*
	 * No updates of link layer address or the neighbor state is
	 * allowed, when the cache is in NONUD state.  This still
	 * allows for responding to reachability solicitation.
	 */
	mutex_enter(&nce->nce_lock);
	if (nce->nce_state == ND_INCOMPLETE) {
		if (hw_addr == NULL) {
			mutex_exit(&nce->nce_lock);
			return;
		}
		nce_set_ll(nce, hw_addr);
		/*
		 * Update nce state and send the queued packets
		 * back to ip this time ire will be added.
		 */
		if (flag & ND_NA_FLAG_SOLICITED) {
			nce_update(nce, ND_REACHABLE, NULL);
		} else {
			nce_update(nce, ND_STALE, NULL);
		}
		mutex_exit(&nce->nce_lock);
		nce_fastpath(nce);
		mutex_enter(&nce->nce_lock);
		mp = nce->nce_qd_mp;
		nce->nce_qd_mp = NULL;
		mutex_exit(&nce->nce_lock);
		while (mp != NULL) {
			mblk_t *nxt_mp, *data_mp;

			nxt_mp = mp->b_next;
			mp->b_next = NULL;

			if (mp->b_datap->db_type == M_CTL)
				data_mp = mp->b_cont;
			else
				data_mp = mp;
			if (data_mp->b_prev != NULL) {
				ill_t   *inbound_ill;
				queue_t *fwdq = NULL;
				uint_t ifindex;

				ifindex = (uint_t)(uintptr_t)data_mp->b_prev;
				inbound_ill = ill_lookup_on_ifindex(ifindex,
				    B_TRUE, NULL, NULL, NULL, NULL, ipst);
				if (inbound_ill == NULL) {
					data_mp->b_prev = NULL;
					freemsg(mp);
					return;
				} else {
					fwdq = inbound_ill->ill_rq;
				}
				data_mp->b_prev = NULL;
				/*
				 * Send a forwarded packet back into ip_rput_v6
				 * just as in ire_send_v6().
				 * Extract the queue from b_prev (set in
				 * ip_rput_data_v6).
				 */
				if (fwdq != NULL) {
					/*
					 * Forwarded packets hop count will
					 * get decremented in ip_rput_data_v6
					 */
					if (data_mp != mp)
						freeb(mp);
					put(fwdq, data_mp);
				} else {
					/*
					 * Send locally originated packets back
					 * into ip_wput_v6.
					 */
					put(ill->ill_wq, mp);
				}
				ill_refrele(inbound_ill);
			} else {
				put(ill->ill_wq, mp);
			}
			mp = nxt_mp;
		}
		return;
	}
	ll_changed = nce_cmp_ll_addr(nce, hw_addr, hw_addr_len);
	if (!is_adv) {
		/* If this is a SOLICITATION request only */
		if (ll_changed)
			nce_update(nce, ND_STALE, hw_addr);
		mutex_exit(&nce->nce_lock);
		return;
	}
	if (!(flag & ND_NA_FLAG_OVERRIDE) && ll_changed) {
		/* If in any other state than REACHABLE, ignore */
		if (nce->nce_state == ND_REACHABLE) {
			nce_update(nce, ND_STALE, NULL);
		}
		mutex_exit(&nce->nce_lock);
		return;
	} else {
		if (ll_changed) {
			nce_update(nce, ND_UNCHANGED, hw_addr);
			ll_updated = B_TRUE;
		}
		if (flag & ND_NA_FLAG_SOLICITED) {
			nce_update(nce, ND_REACHABLE, NULL);
		} else {
			if (ll_updated) {
				nce_update(nce, ND_STALE, NULL);
			}
		}
		mutex_exit(&nce->nce_lock);
		if (!(flag & ND_NA_FLAG_ROUTER) && (nce->nce_flags &
		    NCE_F_ISROUTER)) {
			ire_t *ire;

			/*
			 * Router turned to host.  We need to remove the
			 * entry as well as any default route that may be
			 * using this as a next hop.  This is required by
			 * section 7.2.5 of RFC 2461.
			 */
			ire = ire_ftable_lookup_v6(&ipv6_all_zeros,
			    &ipv6_all_zeros, &nce->nce_addr, IRE_DEFAULT,
			    nce->nce_ill->ill_ipif, NULL, ALL_ZONES, 0, NULL,
			    MATCH_IRE_ILL | MATCH_IRE_TYPE | MATCH_IRE_GW |
			    MATCH_IRE_DEFAULT, ipst);
			if (ire != NULL) {
				ip_rts_rtmsg(RTM_DELETE, ire, 0, ipst);
				ire_delete(ire);
				ire_refrele(ire);
			}
			ndp_delete(nce);
		}
	}
}

/*
 * Walker state structure used by ndp_process() / ndp_process_entry().
 */
typedef struct ndp_process_data {
	ill_t		*np_ill; 	/* ill/illgrp to match against */
	const in6_addr_t *np_addr; 	/* IPv6 address to match */
	uchar_t		*np_hw_addr; 	/* passed to nce_process() */
	uint32_t	np_flag;	/* passed to nce_process() */
	boolean_t	np_is_adv;	/* passed to nce_process() */
} ndp_process_data_t;

/*
 * Walker callback used by ndp_process() for IPMP groups: calls nce_process()
 * for each NCE with a matching address that's in the same IPMP group.
 */
static void
ndp_process_entry(nce_t *nce, void *arg)
{
	ndp_process_data_t *npp = arg;

	if (IS_IN_SAME_ILLGRP(nce->nce_ill, npp->np_ill) &&
	    IN6_ARE_ADDR_EQUAL(&nce->nce_addr, npp->np_addr) &&
	    IN6_ARE_ADDR_EQUAL(&nce->nce_mask, &ipv6_all_ones)) {
		nce_process(nce, npp->np_hw_addr, npp->np_flag, npp->np_is_adv);
	}
}

/*
 * Wrapper around nce_process() that handles IPMP.  In particular, for IPMP,
 * NCEs are per-underlying-ill (because of nce_fp_mp) and thus we may have
 * more than one NCE for a given IPv6 address to tend to.  In that case, we
 * need to walk all NCEs and callback nce_process() for each one.  Since this
 * is expensive, in the non-IPMP case we just directly call nce_process().
 * Ultimately, nce_fp_mp needs to be moved out of the nce_t so that all IP
 * interfaces in an IPMP group share the same NCEs -- at which point this
 * function can be removed entirely.
 */
void
ndp_process(nce_t *nce, uchar_t *hw_addr, uint32_t flag, boolean_t is_adv)
{
	ill_t *ill = nce->nce_ill;
	struct ndp_g_s *ndp = ill->ill_ipst->ips_ndp6;
	ndp_process_data_t np;

	if (ill->ill_grp == NULL) {
		nce_process(nce, hw_addr, flag, is_adv);
		return;
	}

	/* IPMP case: walk all NCEs */
	np.np_ill = ill;
	np.np_addr = &nce->nce_addr;
	np.np_flag = flag;
	np.np_is_adv = is_adv;
	np.np_hw_addr = hw_addr;

	ndp_walk_common(ndp, NULL, (pfi_t)ndp_process_entry, &np, ALL_ZONES);
}

/*
 * Pass arg1 to the pfi supplied, along with each nce in existence.
 * ndp_walk() places a REFHOLD on the nce and drops the lock when
 * walking the hash list.
 */
void
ndp_walk_common(ndp_g_t *ndp, ill_t *ill, pfi_t pfi, void *arg1,
    boolean_t trace)
{
	nce_t	*nce;
	nce_t	*nce1;
	nce_t	**ncep;
	nce_t	*free_nce_list = NULL;

	mutex_enter(&ndp->ndp_g_lock);
	/* Prevent ndp_delete from unlink and free of NCE */
	ndp->ndp_g_walker++;
	mutex_exit(&ndp->ndp_g_lock);
	for (ncep = ndp->nce_hash_tbl;
	    ncep < A_END(ndp->nce_hash_tbl); ncep++) {
		for (nce = *ncep; nce != NULL; nce = nce1) {
			nce1 = nce->nce_next;
			if (ill == NULL || nce->nce_ill == ill) {
				if (trace) {
					NCE_REFHOLD(nce);
					(*pfi)(nce, arg1);
					NCE_REFRELE(nce);
				} else {
					NCE_REFHOLD_NOTR(nce);
					(*pfi)(nce, arg1);
					NCE_REFRELE_NOTR(nce);
				}
			}
		}
	}
	for (nce = ndp->nce_mask_entries; nce != NULL; nce = nce1) {
		nce1 = nce->nce_next;
		if (ill == NULL || nce->nce_ill == ill) {
			if (trace) {
				NCE_REFHOLD(nce);
				(*pfi)(nce, arg1);
				NCE_REFRELE(nce);
			} else {
				NCE_REFHOLD_NOTR(nce);
				(*pfi)(nce, arg1);
				NCE_REFRELE_NOTR(nce);
			}
		}
	}
	mutex_enter(&ndp->ndp_g_lock);
	ndp->ndp_g_walker--;
	/*
	 * While NCE's are removed from global list they are placed
	 * in a private list, to be passed to nce_ire_delete_list().
	 * The reason is, there may be ires pointing to this nce
	 * which needs to cleaned up.
	 */
	if (ndp->ndp_g_walker_cleanup && ndp->ndp_g_walker == 0) {
		/* Time to delete condemned entries */
		for (ncep = ndp->nce_hash_tbl;
		    ncep < A_END(ndp->nce_hash_tbl); ncep++) {
			nce = *ncep;
			if (nce != NULL) {
				nce_remove(ndp, nce, &free_nce_list);
			}
		}
		nce = ndp->nce_mask_entries;
		if (nce != NULL) {
			nce_remove(ndp, nce, &free_nce_list);
		}
		ndp->ndp_g_walker_cleanup = B_FALSE;
	}

	mutex_exit(&ndp->ndp_g_lock);

	if (free_nce_list != NULL) {
		nce_ire_delete_list(free_nce_list);
	}
}

/*
 * Walk everything.
 * Note that ill can be NULL hence can't derive the ipst from it.
 */
void
ndp_walk(ill_t *ill, pfi_t pfi, void *arg1, ip_stack_t *ipst)
{
	ndp_walk_common(ipst->ips_ndp4, ill, pfi, arg1, B_TRUE);
	ndp_walk_common(ipst->ips_ndp6, ill, pfi, arg1, B_TRUE);
}

/*
 * Process resolve requests.  Handles both mapped entries
 * as well as cases that needs to be send out on the wire.
 * Lookup a NCE for a given IRE.  Regardless of whether one exists
 * or one is created, we defer making ire point to nce until the
 * ire is actually added at which point the nce_refcnt on the nce is
 * incremented.  This is done primarily to have symmetry between ire_add()
 * and ire_delete() which decrements the nce_refcnt, when an ire is deleted.
 */
int
ndp_resolver(ill_t *ill, const in6_addr_t *dst, mblk_t *mp, zoneid_t zoneid)
{
	nce_t		*nce, *hw_nce = NULL;
	int		err;
	ill_t		*ipmp_ill;
	uint16_t	nce_flags;
	uint32_t	ms;
	mblk_t		*mp_nce = NULL;
	ip_stack_t	*ipst = ill->ill_ipst;
	uchar_t		*hwaddr = NULL;

	ASSERT(ill->ill_isv6);

	if (IN6_IS_ADDR_MULTICAST(dst))
		return (nce_set_multicast(ill, dst));

	nce_flags = (ill->ill_flags & ILLF_NONUD) ? NCE_F_NONUD : 0;

	/*
	 * If `ill' is under IPMP, then first check to see if there's an NCE
	 * for `dst' on the IPMP meta-interface (e.g., because an application
	 * explicitly did an SIOCLIFSETND to tie a hardware address to `dst').
	 * If so, we use that hardware address when creating the NCE below.
	 * Note that we don't yet have a mechanism to remove these NCEs if the
	 * NCE for `dst' on the IPMP meta-interface is subsequently removed --
	 * but rather than build such a beast, we should fix NCEs so that they
	 * can be properly shared across an IPMP group.
	 */
	if (IS_UNDER_IPMP(ill)) {
		if ((ipmp_ill = ipmp_ill_hold_ipmp_ill(ill)) != NULL) {
			hw_nce = ndp_lookup_v6(ipmp_ill, B_FALSE, dst, B_FALSE);
			if (hw_nce != NULL && hw_nce->nce_res_mp != NULL) {
				hwaddr = hw_nce->nce_res_mp->b_rptr +
				    NCE_LL_ADDR_OFFSET(ipmp_ill);
				nce_flags |= hw_nce->nce_flags;
			}
			ill_refrele(ipmp_ill);
		}
	}

	err = ndp_lookup_then_add_v6(ill,
	    B_FALSE,	/* NCE fastpath is per ill; don't match across group */
	    hwaddr,
	    dst,
	    &ipv6_all_ones,
	    &ipv6_all_zeros,
	    0,
	    nce_flags,
	    hwaddr != NULL ? ND_REACHABLE : ND_INCOMPLETE,
	    &nce);

	if (hw_nce != NULL)
		NCE_REFRELE(hw_nce);

	switch (err) {
	case 0:
		/*
		 * New cache entry was created. Make sure that the state
		 * is not ND_INCOMPLETE. It can be in some other state
		 * even before we send out the solicitation as we could
		 * get un-solicited advertisements.
		 *
		 * If this is an XRESOLV interface, simply return 0,
		 * since we don't want to solicit just yet.
		 */
		if (ill->ill_flags & ILLF_XRESOLV) {
			NCE_REFRELE(nce);
			return (0);
		}

		mutex_enter(&nce->nce_lock);
		if (nce->nce_state != ND_INCOMPLETE) {
			mutex_exit(&nce->nce_lock);
			NCE_REFRELE(nce);
			return (0);
		}
		mp_nce = ip_prepend_zoneid(mp, zoneid, ipst);
		if (mp_nce == NULL) {
			/* The caller will free mp */
			mutex_exit(&nce->nce_lock);
			ndp_delete(nce);
			NCE_REFRELE(nce);
			return (ENOMEM);
		}
		if ((ms = nce_solicit(nce, mp_nce)) == 0) {
			/* The caller will free mp */
			if (mp_nce != mp)
				freeb(mp_nce);
			mutex_exit(&nce->nce_lock);
			ndp_delete(nce);
			NCE_REFRELE(nce);
			return (EBUSY);
		}
		mutex_exit(&nce->nce_lock);
		NDP_RESTART_TIMER(nce, (clock_t)ms);
		NCE_REFRELE(nce);
		return (EINPROGRESS);
	case EEXIST:
		/* Resolution in progress just queue the packet */
		mutex_enter(&nce->nce_lock);
		if (nce->nce_state == ND_INCOMPLETE) {
			mp_nce = ip_prepend_zoneid(mp, zoneid, ipst);
			if (mp_nce == NULL) {
				err = ENOMEM;
			} else {
				nce_queue_mp(nce, mp_nce);
				err = EINPROGRESS;
			}
		} else {
			/*
			 * Any other state implies we have
			 * a nce but IRE needs to be added ...
			 * ire_add_v6() will take care of the
			 * the case when the nce becomes CONDEMNED
			 * before the ire is added to the table.
			 */
			err = 0;
		}
		mutex_exit(&nce->nce_lock);
		NCE_REFRELE(nce);
		break;
	default:
		ip1dbg(("ndp_resolver: Can't create NCE %d\n", err));
		break;
	}
	return (err);
}

/*
 * When there is no resolver, the link layer template is passed in
 * the IRE.
 * Lookup a NCE for a given IRE.  Regardless of whether one exists
 * or one is created, we defer making ire point to nce until the
 * ire is actually added at which point the nce_refcnt on the nce is
 * incremented.  This is done primarily to have symmetry between ire_add()
 * and ire_delete() which decrements the nce_refcnt, when an ire is deleted.
 */
int
ndp_noresolver(ill_t *ill, const in6_addr_t *dst)
{
	nce_t		*nce;
	int		err = 0;

	ASSERT(ill != NULL);
	ASSERT(ill->ill_isv6);
	if (IN6_IS_ADDR_MULTICAST(dst)) {
		err = nce_set_multicast(ill, dst);
		return (err);
	}

	err = ndp_lookup_then_add_v6(ill,
	    B_FALSE,	/* NCE fastpath is per ill; don't match across group */
	    NULL,	/* hardware address */
	    dst,
	    &ipv6_all_ones,
	    &ipv6_all_zeros,
	    0,
	    (ill->ill_flags & ILLF_NONUD) ? NCE_F_NONUD : 0,
	    ND_REACHABLE,
	    &nce);

	switch (err) {
	case 0:
		/*
		 * Cache entry with a proper resolver cookie was
		 * created.
		 */
		NCE_REFRELE(nce);
		break;
	case EEXIST:
		err = 0;
		NCE_REFRELE(nce);
		break;
	default:
		ip1dbg(("ndp_noresolver: Can't create NCE %d\n", err));
		break;
	}
	return (err);
}

/*
 * For each interface an entry is added for the unspecified multicast group.
 * Here that mapping is used to form the multicast cache entry for a particular
 * multicast destination.
 */
static int
nce_set_multicast(ill_t *ill, const in6_addr_t *dst)
{
	nce_t		*mnce;	/* Multicast mapping entry */
	nce_t		*nce;
	uchar_t		*hw_addr = NULL;
	int		err = 0;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ill != NULL);
	ASSERT(ill->ill_isv6);
	ASSERT(!(IN6_IS_ADDR_UNSPECIFIED(dst)));

	mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
	nce = *((nce_t **)NCE_HASH_PTR_V6(ipst, *dst));
	nce = nce_lookup_addr(ill, B_FALSE, dst, nce);
	if (nce != NULL) {
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		NCE_REFRELE(nce);
		return (0);
	}
	/* No entry, now lookup for a mapping this should never fail */
	mnce = nce_lookup_mapping(ill, dst);
	if (mnce == NULL) {
		/* Something broken for the interface. */
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		return (ESRCH);
	}
	ASSERT(mnce->nce_flags & NCE_F_MAPPING);
	if (ill->ill_net_type == IRE_IF_RESOLVER) {
		/*
		 * For IRE_IF_RESOLVER a hardware mapping can be
		 * generated, for IRE_IF_NORESOLVER, resolution cookie
		 * in the ill is copied in ndp_add_v6().
		 */
		hw_addr = kmem_alloc(ill->ill_nd_lla_len, KM_NOSLEEP);
		if (hw_addr == NULL) {
			mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
			NCE_REFRELE(mnce);
			return (ENOMEM);
		}
		nce_make_mapping(mnce, hw_addr, (uchar_t *)dst);
	}
	NCE_REFRELE(mnce);
	/*
	 * IRE_IF_NORESOLVER type simply copies the resolution
	 * cookie passed in.  So no hw_addr is needed.
	 */
	err = ndp_add_v6(ill,
	    hw_addr,
	    dst,
	    &ipv6_all_ones,
	    &ipv6_all_zeros,
	    0,
	    NCE_F_NONUD,
	    ND_REACHABLE,
	    &nce);
	mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
	if (hw_addr != NULL)
		kmem_free(hw_addr, ill->ill_nd_lla_len);
	if (err != 0) {
		ip1dbg(("nce_set_multicast: create failed" "%d\n", err));
		return (err);
	}
	NCE_REFRELE(nce);
	return (0);
}

/*
 * Return the link layer address, and any flags of a nce.
 */
int
ndp_query(ill_t *ill, struct lif_nd_req *lnr)
{
	nce_t		*nce;
	in6_addr_t	*addr;
	sin6_t		*sin6;
	dl_unitdata_req_t	*dl;

	ASSERT(ill != NULL && ill->ill_isv6);
	sin6 = (sin6_t *)&lnr->lnr_addr;
	addr =  &sin6->sin6_addr;

	/*
	 * NOTE: if the ill is an IPMP interface, then match against the whole
	 * illgrp.  This e.g. allows in.ndpd to retrieve the link layer
	 * addresses for the data addresses on an IPMP interface even though
	 * ipif_ndp_up() created them with an nce_ill of ipif_bound_ill.
	 */
	nce = ndp_lookup_v6(ill, IS_IPMP(ill), addr, B_FALSE);
	if (nce == NULL)
		return (ESRCH);
	/* If in INCOMPLETE state, no link layer address is available yet */
	if (nce->nce_state == ND_INCOMPLETE)
		goto done;
	dl = (dl_unitdata_req_t *)nce->nce_res_mp->b_rptr;
	if (ill->ill_flags & ILLF_XRESOLV)
		lnr->lnr_hdw_len = dl->dl_dest_addr_length;
	else
		lnr->lnr_hdw_len = ill->ill_nd_lla_len;
	ASSERT(NCE_LL_ADDR_OFFSET(ill) + lnr->lnr_hdw_len <=
	    sizeof (lnr->lnr_hdw_addr));
	bcopy(nce->nce_res_mp->b_rptr + NCE_LL_ADDR_OFFSET(ill),
	    (uchar_t *)&lnr->lnr_hdw_addr, lnr->lnr_hdw_len);
	if (nce->nce_flags & NCE_F_ISROUTER)
		lnr->lnr_flags = NDF_ISROUTER_ON;
	if (nce->nce_flags & NCE_F_ANYCAST)
		lnr->lnr_flags |= NDF_ANYCAST_ON;
done:
	NCE_REFRELE(nce);
	return (0);
}

/*
 * Send Enable/Disable multicast reqs to driver.
 */
int
ndp_mcastreq(ill_t *ill, const in6_addr_t *addr, uint32_t hw_addr_len,
    uint32_t hw_addr_offset, mblk_t *mp)
{
	nce_t		*nce;
	uchar_t		*hw_addr;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ill != NULL && ill->ill_isv6);
	ASSERT(ill->ill_net_type == IRE_IF_RESOLVER);
	hw_addr = mi_offset_paramc(mp, hw_addr_offset, hw_addr_len);
	if (hw_addr == NULL || !IN6_IS_ADDR_MULTICAST(addr)) {
		freemsg(mp);
		return (EINVAL);
	}
	mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
	nce = nce_lookup_mapping(ill, addr);
	if (nce == NULL) {
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		freemsg(mp);
		return (ESRCH);
	}
	mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
	/*
	 * Update dl_addr_length and dl_addr_offset for primitives that
	 * have physical addresses as opposed to full saps
	 */
	switch (((union DL_primitives *)mp->b_rptr)->dl_primitive) {
	case DL_ENABMULTI_REQ:
		/* Track the state if this is the first enabmulti */
		if (ill->ill_dlpi_multicast_state == IDS_UNKNOWN)
			ill->ill_dlpi_multicast_state = IDS_INPROGRESS;
		ip1dbg(("ndp_mcastreq: ENABMULTI\n"));
		break;
	case DL_DISABMULTI_REQ:
		ip1dbg(("ndp_mcastreq: DISABMULTI\n"));
		break;
	default:
		NCE_REFRELE(nce);
		ip1dbg(("ndp_mcastreq: default\n"));
		return (EINVAL);
	}
	nce_make_mapping(nce, hw_addr, (uchar_t *)addr);
	NCE_REFRELE(nce);
	ill_dlpi_send(ill, mp);
	return (0);
}

/*
 * Send a neighbor solicitation.
 * Returns number of milliseconds after which we should either rexmit or abort.
 * Return of zero means we should abort.
 * The caller holds the nce_lock to protect nce_qd_mp and nce_rcnt.
 *
 * NOTE: This routine drops nce_lock (and later reacquires it) when sending
 * the packet.
 * NOTE: This routine does not consume mp.
 */
uint32_t
nce_solicit(nce_t *nce, mblk_t *mp)
{
	ip6_t		*ip6h;
	in6_addr_t	sender;
	boolean_t	dropped;

	ASSERT(MUTEX_HELD(&nce->nce_lock));

	if (nce->nce_rcnt == 0)
		return (0);

	if (mp == NULL) {
		ASSERT(nce->nce_qd_mp != NULL);
		mp = nce->nce_qd_mp;
	} else {
		nce_queue_mp(nce, mp);
	}

	/* Handle ip_newroute_v6 giving us IPSEC packets */
	if (mp->b_datap->db_type == M_CTL)
		mp = mp->b_cont;

	ip6h = (ip6_t *)mp->b_rptr;
	if (ip6h->ip6_nxt == IPPROTO_RAW) {
		/*
		 * This message should have been pulled up already in
		 * ip_wput_v6. We can't do pullups here because the message
		 * could be from the nce_qd_mp which could have b_next/b_prev
		 * non-NULL.
		 */
		ASSERT(MBLKL(mp) >= sizeof (ip6i_t) + IPV6_HDR_LEN);
		ip6h = (ip6_t *)(mp->b_rptr + sizeof (ip6i_t));
	}

	/*
	 * Need to copy the sender address into a local since `mp' can
	 * go away once we drop nce_lock.
	 */
	sender = ip6h->ip6_src;
	nce->nce_rcnt--;
	mutex_exit(&nce->nce_lock);
	dropped = nce_xmit_solicit(nce, B_TRUE, &sender, 0);
	mutex_enter(&nce->nce_lock);
	if (dropped)
		nce->nce_rcnt++;
	return (nce->nce_ill->ill_reachable_retrans_time);
}

/*
 * Attempt to recover an address on an interface that's been marked as a
 * duplicate.  Because NCEs are destroyed when the interface goes down, there's
 * no easy way to just probe the address and have the right thing happen if
 * it's no longer in use.  Instead, we just bring it up normally and allow the
 * regular interface start-up logic to probe for a remaining duplicate and take
 * us back down if necessary.
 * Neither DHCP nor temporary addresses arrive here; they're excluded by
 * ip_ndp_excl.
 */
/* ARGSUSED */
static void
ip_ndp_recover(ipsq_t *ipsq, queue_t *rq, mblk_t *mp, void *dummy_arg)
{
	ill_t	*ill = rq->q_ptr;
	ipif_t	*ipif;
	in6_addr_t *addr = (in6_addr_t *)mp->b_rptr;

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		/*
		 * We do not support recovery of proxy ARP'd interfaces,
		 * because the system lacks a complete proxy ARP mechanism.
		 */
		if ((ipif->ipif_flags & IPIF_POINTOPOINT) ||
		    !IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6lcl_addr, addr)) {
			continue;
		}

		/*
		 * If we have already recovered or if the interface is going
		 * away, then ignore.
		 */
		mutex_enter(&ill->ill_lock);
		if (!(ipif->ipif_flags & IPIF_DUPLICATE) ||
		    (ipif->ipif_state_flags & IPIF_CONDEMNED)) {
			mutex_exit(&ill->ill_lock);
			continue;
		}

		ipif->ipif_flags &= ~IPIF_DUPLICATE;
		ill->ill_ipif_dup_count--;
		mutex_exit(&ill->ill_lock);
		ipif->ipif_was_dup = B_TRUE;

		VERIFY(ipif_ndp_up(ipif, B_TRUE) != EINPROGRESS);
		(void) ipif_up_done_v6(ipif);
	}
	freeb(mp);
}

/*
 * Attempt to recover an IPv6 interface that's been shut down as a duplicate.
 * As long as someone else holds the address, the interface will stay down.
 * When that conflict goes away, the interface is brought back up.  This is
 * done so that accidental shutdowns of addresses aren't made permanent.  Your
 * server will recover from a failure.
 *
 * For DHCP and temporary addresses, recovery is not done in the kernel.
 * Instead, it's handled by user space processes (dhcpagent and in.ndpd).
 *
 * This function is entered on a timer expiry; the ID is in ipif_recovery_id.
 */
static void
ipif6_dup_recovery(void *arg)
{
	ipif_t *ipif = arg;

	ipif->ipif_recovery_id = 0;
	if (!(ipif->ipif_flags & IPIF_DUPLICATE))
		return;

	/*
	 * No lock, because this is just an optimization.
	 */
	if (ipif->ipif_state_flags & IPIF_CONDEMNED)
		return;

	/* If the link is down, we'll retry this later */
	if (!(ipif->ipif_ill->ill_phyint->phyint_flags & PHYI_RUNNING))
		return;

	ndp_do_recovery(ipif);
}

/*
 * Perform interface recovery by forcing the duplicate interfaces up and
 * allowing the system to determine which ones should stay up.
 *
 * Called both by recovery timer expiry and link-up notification.
 */
void
ndp_do_recovery(ipif_t *ipif)
{
	ill_t *ill = ipif->ipif_ill;
	mblk_t *mp;
	ip_stack_t *ipst = ill->ill_ipst;

	mp = allocb(sizeof (ipif->ipif_v6lcl_addr), BPRI_MED);
	if (mp == NULL) {
		mutex_enter(&ill->ill_lock);
		if (ipif->ipif_recovery_id == 0 &&
		    !(ipif->ipif_state_flags & IPIF_CONDEMNED)) {
			ipif->ipif_recovery_id = timeout(ipif6_dup_recovery,
			    ipif, MSEC_TO_TICK(ipst->ips_ip_dup_recovery));
		}
		mutex_exit(&ill->ill_lock);
	} else {
		/*
		 * A recovery timer may still be running if we got here from
		 * ill_restart_dad(); cancel that timer.
		 */
		if (ipif->ipif_recovery_id != 0)
			(void) untimeout(ipif->ipif_recovery_id);
		ipif->ipif_recovery_id = 0;

		bcopy(&ipif->ipif_v6lcl_addr, mp->b_rptr,
		    sizeof (ipif->ipif_v6lcl_addr));
		ill_refhold(ill);
		qwriter_ip(ill, ill->ill_rq, mp, ip_ndp_recover, NEW_OP,
		    B_FALSE);
	}
}

/*
 * Find the MAC and IP addresses in an NA/NS message.
 */
static void
ip_ndp_find_addresses(mblk_t *mp, mblk_t *dl_mp, ill_t *ill, in6_addr_t *targp,
    uchar_t **haddr, uint_t *haddrlenp)
{
	ip6_t *ip6h = (ip6_t *)mp->b_rptr;
	icmp6_t *icmp6 = (icmp6_t *)(mp->b_rptr + IPV6_HDR_LEN);
	nd_neighbor_advert_t *na = (nd_neighbor_advert_t *)icmp6;
	nd_neighbor_solicit_t *ns = (nd_neighbor_solicit_t *)icmp6;
	uchar_t *addr;
	int alen = 0;

	if (dl_mp == NULL) {
		nd_opt_hdr_t *opt;
		int len;

		/*
		 * If it's from the fast-path, then it can't be a probe
		 * message, and thus must include a linkaddr option.
		 * Extract that here.
		 */
		switch (icmp6->icmp6_type) {
		case ND_NEIGHBOR_SOLICIT:
			len = mp->b_wptr - (uchar_t *)ns;
			if ((len -= sizeof (*ns)) > 0) {
				opt = ndp_get_option((nd_opt_hdr_t *)(ns + 1),
				    len, ND_OPT_SOURCE_LINKADDR);
			}
			break;
		case ND_NEIGHBOR_ADVERT:
			len = mp->b_wptr - (uchar_t *)na;
			if ((len -= sizeof (*na)) > 0) {
				opt = ndp_get_option((nd_opt_hdr_t *)(na + 1),
				    len, ND_OPT_TARGET_LINKADDR);
			}
			break;
		}

		if (opt != NULL && opt->nd_opt_len * 8 - sizeof (*opt) >=
		    ill->ill_nd_lla_len) {
			addr = (uchar_t *)(opt + 1);
			alen = ill->ill_nd_lla_len;
		}

		/*
		 * We cheat a bit here for the sake of printing usable log
		 * messages in the rare case where the reply we got was unicast
		 * without a source linkaddr option, and the interface is in
		 * fastpath mode.  (Sigh.)
		 */
		if (alen == 0 && ill->ill_type == IFT_ETHER &&
		    MBLKHEAD(mp) >= sizeof (struct ether_header)) {
			struct ether_header *pether;

			pether = (struct ether_header *)((char *)ip6h -
			    sizeof (*pether));
			addr = pether->ether_shost.ether_addr_octet;
			alen = ETHERADDRL;
		}
	} else {
		dl_unitdata_ind_t *dlu;

		dlu = (dl_unitdata_ind_t *)dl_mp->b_rptr;
		alen = dlu->dl_src_addr_length;
		if (alen > 0 && dlu->dl_src_addr_offset >= sizeof (*dlu) &&
		    dlu->dl_src_addr_offset + alen <= MBLKL(dl_mp)) {
			addr = dl_mp->b_rptr + dlu->dl_src_addr_offset;
			if (ill->ill_sap_length < 0) {
				alen += ill->ill_sap_length;
			} else {
				addr += ill->ill_sap_length;
				alen -= ill->ill_sap_length;
			}
		}
	}

	if (alen > 0) {
		*haddr = addr;
		*haddrlenp = alen;
	} else {
		*haddr = NULL;
		*haddrlenp = 0;
	}

	/* nd_ns_target and nd_na_target are at the same offset, so we cheat */
	*targp = ns->nd_ns_target;
}

/*
 * This is for exclusive changes due to NDP duplicate address detection
 * failure.
 */
/* ARGSUSED */
static void
ip_ndp_excl(ipsq_t *ipsq, queue_t *rq, mblk_t *mp, void *dummy_arg)
{
	ill_t	*ill = rq->q_ptr;
	ipif_t	*ipif;
	mblk_t	*dl_mp = NULL;
	uchar_t	*haddr;
	uint_t	haddrlen;
	ip_stack_t *ipst = ill->ill_ipst;
	in6_addr_t targ;

	if (DB_TYPE(mp) != M_DATA) {
		dl_mp = mp;
		mp = mp->b_cont;
	}

	ip_ndp_find_addresses(mp, dl_mp, ill, &targ, &haddr, &haddrlen);
	if (haddr != NULL && haddrlen == ill->ill_phys_addr_length) {
		/*
		 * Ignore conflicts generated by misbehaving switches that
		 * just reflect our own messages back to us.  For IPMP, we may
		 * see reflections across any ill in the illgrp.
		 */
		if (bcmp(haddr, ill->ill_phys_addr, haddrlen) == 0 ||
		    IS_UNDER_IPMP(ill) &&
		    ipmp_illgrp_find_ill(ill->ill_grp, haddr, haddrlen) != NULL)
			goto ignore_conflict;
	}

	/*
	 * Look up the appropriate ipif.
	 */
	ipif = ipif_lookup_addr_v6(&targ, ill, ALL_ZONES, NULL, NULL, NULL,
	    NULL, ipst);
	if (ipif == NULL)
		goto ignore_conflict;

	/* Reload the ill to match the ipif */
	ill = ipif->ipif_ill;

	/* If it's already duplicate or ineligible, then don't do anything. */
	if (ipif->ipif_flags & (IPIF_POINTOPOINT|IPIF_DUPLICATE)) {
		ipif_refrele(ipif);
		goto ignore_conflict;
	}

	/*
	 * If this is a failure during duplicate recovery, then don't
	 * complain.  It may take a long time to recover.
	 */
	if (!ipif->ipif_was_dup) {
		char ibuf[LIFNAMSIZ];
		char hbuf[MAC_STR_LEN];
		char sbuf[INET6_ADDRSTRLEN];

		ipif_get_name(ipif, ibuf, sizeof (ibuf));
		cmn_err(CE_WARN, "%s has duplicate address %s (in use by %s);"
		    " disabled", ibuf,
		    inet_ntop(AF_INET6, &targ, sbuf, sizeof (sbuf)),
		    mac_colon_addr(haddr, haddrlen, hbuf, sizeof (hbuf)));
	}
	mutex_enter(&ill->ill_lock);
	ASSERT(!(ipif->ipif_flags & IPIF_DUPLICATE));
	ipif->ipif_flags |= IPIF_DUPLICATE;
	ill->ill_ipif_dup_count++;
	mutex_exit(&ill->ill_lock);
	(void) ipif_down(ipif, NULL, NULL);
	ipif_down_tail(ipif);
	mutex_enter(&ill->ill_lock);
	if (!(ipif->ipif_flags & (IPIF_DHCPRUNNING|IPIF_TEMPORARY)) &&
	    ill->ill_net_type == IRE_IF_RESOLVER &&
	    !(ipif->ipif_state_flags & IPIF_CONDEMNED) &&
	    ipst->ips_ip_dup_recovery > 0) {
		ASSERT(ipif->ipif_recovery_id == 0);
		ipif->ipif_recovery_id = timeout(ipif6_dup_recovery,
		    ipif, MSEC_TO_TICK(ipst->ips_ip_dup_recovery));
	}
	mutex_exit(&ill->ill_lock);
	ipif_refrele(ipif);
ignore_conflict:
	if (dl_mp != NULL)
		freeb(dl_mp);
	freemsg(mp);
}

/*
 * Handle failure by tearing down the ipifs with the specified address.  Note
 * that tearing down the ipif also means deleting the nce through ipif_down, so
 * it's not possible to do recovery by just restarting the nce timer.  Instead,
 * we start a timer on the ipif.
 */
static void
ip_ndp_failure(ill_t *ill, mblk_t *mp, mblk_t *dl_mp)
{
	if ((mp = copymsg(mp)) != NULL) {
		if (dl_mp == NULL)
			dl_mp = mp;
		else if ((dl_mp = copyb(dl_mp)) != NULL)
			dl_mp->b_cont = mp;
		if (dl_mp == NULL) {
			freemsg(mp);
		} else {
			ill_refhold(ill);
			qwriter_ip(ill, ill->ill_rq, dl_mp, ip_ndp_excl, NEW_OP,
			    B_FALSE);
		}
	}
}

/*
 * Handle a discovered conflict: some other system is advertising that it owns
 * one of our IP addresses.  We need to defend ourselves, or just shut down the
 * interface.
 */
static void
ip_ndp_conflict(ill_t *ill, mblk_t *mp, mblk_t *dl_mp, nce_t *nce)
{
	ipif_t *ipif;
	uint32_t now;
	uint_t maxdefense;
	uint_t defs;
	ip_stack_t *ipst = ill->ill_ipst;

	ipif = ipif_lookup_addr_v6(&nce->nce_addr, ill, ALL_ZONES, NULL, NULL,
	    NULL, NULL, ipst);
	if (ipif == NULL)
		return;

	/*
	 * First, figure out if this address is disposable.
	 */
	if (ipif->ipif_flags & (IPIF_DHCPRUNNING | IPIF_TEMPORARY))
		maxdefense = ipst->ips_ip_max_temp_defend;
	else
		maxdefense = ipst->ips_ip_max_defend;

	/*
	 * Now figure out how many times we've defended ourselves.  Ignore
	 * defenses that happened long in the past.
	 */
	now = gethrestime_sec();
	mutex_enter(&nce->nce_lock);
	if ((defs = nce->nce_defense_count) > 0 &&
	    now - nce->nce_defense_time > ipst->ips_ip_defend_interval) {
		nce->nce_defense_count = defs = 0;
	}
	nce->nce_defense_count++;
	nce->nce_defense_time = now;
	mutex_exit(&nce->nce_lock);
	ipif_refrele(ipif);

	/*
	 * If we've defended ourselves too many times already, then give up and
	 * tear down the interface(s) using this address.  Otherwise, defend by
	 * sending out an unsolicited Neighbor Advertisement.
	 */
	if (defs >= maxdefense) {
		ip_ndp_failure(ill, mp, dl_mp);
	} else {
		char hbuf[MAC_STR_LEN];
		char sbuf[INET6_ADDRSTRLEN];
		uchar_t *haddr;
		uint_t haddrlen;
		in6_addr_t targ;

		ip_ndp_find_addresses(mp, dl_mp, ill, &targ, &haddr, &haddrlen);
		cmn_err(CE_WARN, "node %s is using our IP address %s on %s",
		    mac_colon_addr(haddr, haddrlen, hbuf, sizeof (hbuf)),
		    inet_ntop(AF_INET6, &targ, sbuf, sizeof (sbuf)),
		    ill->ill_name);

		(void) nce_xmit_advert(nce, B_FALSE, &ipv6_all_hosts_mcast, 0);
	}
}

static void
ndp_input_solicit(ill_t *ill, mblk_t *mp, mblk_t *dl_mp)
{
	nd_neighbor_solicit_t *ns;
	uint32_t	hlen = ill->ill_nd_lla_len;
	uchar_t		*haddr = NULL;
	icmp6_t		*icmp_nd;
	ip6_t		*ip6h;
	nce_t		*our_nce = NULL;
	in6_addr_t	target;
	in6_addr_t	src;
	int		len;
	int		flag = 0;
	nd_opt_hdr_t	*opt = NULL;
	boolean_t	bad_solicit = B_FALSE;
	mib2_ipv6IfIcmpEntry_t	*mib = ill->ill_icmp6_mib;

	ip6h = (ip6_t *)mp->b_rptr;
	icmp_nd = (icmp6_t *)(mp->b_rptr + IPV6_HDR_LEN);
	len = mp->b_wptr - mp->b_rptr - IPV6_HDR_LEN;
	src = ip6h->ip6_src;
	ns = (nd_neighbor_solicit_t *)icmp_nd;
	target = ns->nd_ns_target;
	if (IN6_IS_ADDR_MULTICAST(&target)) {
		if (ip_debug > 2) {
			/* ip1dbg */
			pr_addr_dbg("ndp_input_solicit: Target is"
			    " multicast! %s\n", AF_INET6, &target);
		}
		bad_solicit = B_TRUE;
		goto done;
	}
	if (len > sizeof (nd_neighbor_solicit_t)) {
		/* Options present */
		opt = (nd_opt_hdr_t *)&ns[1];
		len -= sizeof (nd_neighbor_solicit_t);
		if (!ndp_verify_optlen(opt, len)) {
			ip1dbg(("ndp_input_solicit: Bad opt len\n"));
			bad_solicit = B_TRUE;
			goto done;
		}

	}
	if (IN6_IS_ADDR_UNSPECIFIED(&src)) {
		/* Check to see if this is a valid DAD solicitation */
		if (!IN6_IS_ADDR_MC_SOLICITEDNODE(&ip6h->ip6_dst)) {
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("ndp_input_solicit: IPv6 "
				    "Destination is not solicited node "
				    "multicast %s\n", AF_INET6,
				    &ip6h->ip6_dst);
			}
			bad_solicit = B_TRUE;
			goto done;
		}
	}

	/*
	 * NOTE: with IPMP, it's possible the nominated multicast ill (which
	 * received this packet if it's multicast) is not the ill tied to
	 * e.g. the IPMP ill's data link-local.  So we match across the illgrp
	 * to ensure we find the associated NCE.
	 */
	our_nce = ndp_lookup_v6(ill, B_TRUE, &target, B_FALSE);
	/*
	 * If this is a valid Solicitation, a permanent
	 * entry should exist in the cache
	 */
	if (our_nce == NULL ||
	    !(our_nce->nce_flags & NCE_F_PERMANENT)) {
		ip1dbg(("ndp_input_solicit: Wrong target in NS?!"
		    "ifname=%s ", ill->ill_name));
		if (ip_debug > 2) {
			/* ip1dbg */
			pr_addr_dbg(" dst %s\n", AF_INET6, &target);
		}
		bad_solicit = B_TRUE;
		goto done;
	}

	/* At this point we should have a verified NS per spec */
	if (opt != NULL) {
		opt = ndp_get_option(opt, len, ND_OPT_SOURCE_LINKADDR);
		if (opt != NULL) {
			haddr = (uchar_t *)&opt[1];
			if (hlen > opt->nd_opt_len * 8 - sizeof (*opt) ||
			    hlen == 0) {
				ip1dbg(("ndp_input_solicit: bad SLLA\n"));
				bad_solicit = B_TRUE;
				goto done;
			}
		}
	}

	/* If sending directly to peer, set the unicast flag */
	if (!IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst))
		flag |= NDP_UNICAST;

	/*
	 * Create/update the entry for the soliciting node.
	 * or respond to outstanding queries, don't if
	 * the source is unspecified address.
	 */
	if (!IN6_IS_ADDR_UNSPECIFIED(&src)) {
		int	err;
		nce_t	*nnce;

		ASSERT(ill->ill_isv6);
		/*
		 * Regular solicitations *must* include the Source Link-Layer
		 * Address option.  Ignore messages that do not.
		 */
		if (haddr == NULL && IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst)) {
			ip1dbg(("ndp_input_solicit: source link-layer address "
			    "option missing with a specified source.\n"));
			bad_solicit = B_TRUE;
			goto done;
		}

		/*
		 * This is a regular solicitation.  If we're still in the
		 * process of verifying the address, then don't respond at all
		 * and don't keep track of the sender.
		 */
		if (our_nce->nce_state == ND_PROBE)
			goto done;

		/*
		 * If the solicitation doesn't have sender hardware address
		 * (legal for unicast solicitation), then process without
		 * installing the return NCE.  Either we already know it, or
		 * we'll be forced to look it up when (and if) we reply to the
		 * packet.
		 */
		if (haddr == NULL)
			goto no_source;

		err = ndp_lookup_then_add_v6(ill,
		    B_FALSE,
		    haddr,
		    &src,	/* Soliciting nodes address */
		    &ipv6_all_ones,
		    &ipv6_all_zeros,
		    0,
		    0,
		    ND_STALE,
		    &nnce);
		switch (err) {
		case 0:
			/* done with this entry */
			NCE_REFRELE(nnce);
			break;
		case EEXIST:
			/*
			 * B_FALSE indicates this is not an an advertisement.
			 */
			ndp_process(nnce, haddr, 0, B_FALSE);
			NCE_REFRELE(nnce);
			break;
		default:
			ip1dbg(("ndp_input_solicit: Can't create NCE %d\n",
			    err));
			goto done;
		}
no_source:
		flag |= NDP_SOLICITED;
	} else {
		/*
		 * No source link layer address option should be present in a
		 * valid DAD request.
		 */
		if (haddr != NULL) {
			ip1dbg(("ndp_input_solicit: source link-layer address "
			    "option present with an unspecified source.\n"));
			bad_solicit = B_TRUE;
			goto done;
		}
		if (our_nce->nce_state == ND_PROBE) {
			/*
			 * Internally looped-back probes won't have DLPI
			 * attached to them.  External ones (which are sent by
			 * multicast) always will.  Just ignore our own
			 * transmissions.
			 */
			if (dl_mp != NULL) {
				/*
				 * If someone else is probing our address, then
				 * we've crossed wires.  Declare failure.
				 */
				ip_ndp_failure(ill, mp, dl_mp);
			}
			goto done;
		}
		/*
		 * This is a DAD probe.  Multicast the advertisement to the
		 * all-nodes address.
		 */
		src = ipv6_all_hosts_mcast;
	}
	/* Response to a solicitation */
	(void) nce_xmit_advert(our_nce, B_TRUE, &src, flag);
done:
	if (bad_solicit)
		BUMP_MIB(mib, ipv6IfIcmpInBadNeighborSolicitations);
	if (our_nce != NULL)
		NCE_REFRELE(our_nce);
}

void
ndp_input_advert(ill_t *ill, mblk_t *mp, mblk_t *dl_mp)
{
	nd_neighbor_advert_t *na;
	uint32_t	hlen = ill->ill_nd_lla_len;
	uchar_t		*haddr = NULL;
	icmp6_t		*icmp_nd;
	ip6_t		*ip6h;
	nce_t		*dst_nce = NULL;
	in6_addr_t	target;
	nd_opt_hdr_t	*opt = NULL;
	int		len;
	ip_stack_t	*ipst = ill->ill_ipst;
	mib2_ipv6IfIcmpEntry_t	*mib = ill->ill_icmp6_mib;

	ip6h = (ip6_t *)mp->b_rptr;
	icmp_nd = (icmp6_t *)(mp->b_rptr + IPV6_HDR_LEN);
	len = mp->b_wptr - mp->b_rptr - IPV6_HDR_LEN;
	na = (nd_neighbor_advert_t *)icmp_nd;
	if (IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst) &&
	    (na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED)) {
		ip1dbg(("ndp_input_advert: Target is multicast but the "
		    "solicited flag is not zero\n"));
		BUMP_MIB(mib, ipv6IfIcmpInBadNeighborAdvertisements);
		return;
	}
	target = na->nd_na_target;
	if (IN6_IS_ADDR_MULTICAST(&target)) {
		ip1dbg(("ndp_input_advert: Target is multicast!\n"));
		BUMP_MIB(mib, ipv6IfIcmpInBadNeighborAdvertisements);
		return;
	}
	if (len > sizeof (nd_neighbor_advert_t)) {
		opt = (nd_opt_hdr_t *)&na[1];
		if (!ndp_verify_optlen(opt,
		    len - sizeof (nd_neighbor_advert_t))) {
			ip1dbg(("ndp_input_advert: cannot verify SLLA\n"));
			BUMP_MIB(mib, ipv6IfIcmpInBadNeighborAdvertisements);
			return;
		}
		/* At this point we have a verified NA per spec */
		len -= sizeof (nd_neighbor_advert_t);
		opt = ndp_get_option(opt, len, ND_OPT_TARGET_LINKADDR);
		if (opt != NULL) {
			haddr = (uchar_t *)&opt[1];
			if (hlen > opt->nd_opt_len * 8 - sizeof (*opt) ||
			    hlen == 0) {
				ip1dbg(("ndp_input_advert: bad SLLA\n"));
				BUMP_MIB(mib,
				    ipv6IfIcmpInBadNeighborAdvertisements);
				return;
			}
		}
	}

	/*
	 * NOTE: we match across the illgrp since we need to do DAD for all of
	 * our local addresses, and those are spread across all the active
	 * ills in the group.
	 */
	if ((dst_nce = ndp_lookup_v6(ill, B_TRUE, &target, B_FALSE)) == NULL)
		return;

	if (dst_nce->nce_flags & NCE_F_PERMANENT) {
		/*
		 * Someone just advertised one of our local addresses.	First,
		 * check it it was us -- if so, we can safely ignore it.
		 */
		if (haddr != NULL) {
			if (!nce_cmp_ll_addr(dst_nce, haddr, hlen))
				goto out;   /* from us -- no conflict */

			/*
			 * If we're in an IPMP group, check if this is an echo
			 * from another ill in the group.  Use the double-
			 * checked locking pattern to avoid grabbing
			 * ill_g_lock in the non-IPMP case.
			 */
			if (IS_UNDER_IPMP(ill)) {
				rw_enter(&ipst->ips_ill_g_lock, RW_READER);
				if (IS_UNDER_IPMP(ill) && ipmp_illgrp_find_ill(
				    ill->ill_grp, haddr, hlen) != NULL) {
					rw_exit(&ipst->ips_ill_g_lock);
					goto out;
				}
				rw_exit(&ipst->ips_ill_g_lock);
			}
		}

		/*
		 * This appears to be a real conflict.  If we're trying to
		 * configure this NCE (ND_PROBE), then shut it down.
		 * Otherwise, handle the discovered conflict.
		 *
		 * Note that dl_mp might be NULL if we're getting a unicast
		 * reply.  This isn't typically done (multicast is the norm in
		 * response to a probe), but we can handle the dl_mp == NULL
		 * case as well.
		 */
		if (dst_nce->nce_state == ND_PROBE)
			ip_ndp_failure(ill, mp, dl_mp);
		else
			ip_ndp_conflict(ill, mp, dl_mp, dst_nce);
	} else {
		if (na->nd_na_flags_reserved & ND_NA_FLAG_ROUTER)
			dst_nce->nce_flags |= NCE_F_ISROUTER;

		/* B_TRUE indicates this an advertisement */
		ndp_process(dst_nce, haddr, na->nd_na_flags_reserved, B_TRUE);
	}
out:
	NCE_REFRELE(dst_nce);
}

/*
 * Process NDP neighbor solicitation/advertisement messages.
 * The checksum has already checked o.k before reaching here.
 */
void
ndp_input(ill_t *ill, mblk_t *mp, mblk_t *dl_mp)
{
	icmp6_t		*icmp_nd;
	ip6_t		*ip6h;
	int		len;
	mib2_ipv6IfIcmpEntry_t	*mib = ill->ill_icmp6_mib;


	if (!pullupmsg(mp, -1)) {
		ip1dbg(("ndp_input: pullupmsg failed\n"));
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		goto done;
	}
	ip6h = (ip6_t *)mp->b_rptr;
	if (ip6h->ip6_hops != IPV6_MAX_HOPS) {
		ip1dbg(("ndp_input: hoplimit != IPV6_MAX_HOPS\n"));
		BUMP_MIB(mib, ipv6IfIcmpBadHoplimit);
		goto done;
	}
	/*
	 * NDP does not accept any extension headers between the
	 * IP header and the ICMP header since e.g. a routing
	 * header could be dangerous.
	 * This assumes that any AH or ESP headers are removed
	 * by ip prior to passing the packet to ndp_input.
	 */
	if (ip6h->ip6_nxt != IPPROTO_ICMPV6) {
		ip1dbg(("ndp_input: Wrong next header 0x%x\n",
		    ip6h->ip6_nxt));
		BUMP_MIB(mib, ipv6IfIcmpInErrors);
		goto done;
	}
	icmp_nd = (icmp6_t *)(mp->b_rptr + IPV6_HDR_LEN);
	ASSERT(icmp_nd->icmp6_type == ND_NEIGHBOR_SOLICIT ||
	    icmp_nd->icmp6_type == ND_NEIGHBOR_ADVERT);
	if (icmp_nd->icmp6_code != 0) {
		ip1dbg(("ndp_input: icmp6 code != 0 \n"));
		BUMP_MIB(mib, ipv6IfIcmpInErrors);
		goto done;
	}
	len = mp->b_wptr - mp->b_rptr - IPV6_HDR_LEN;
	/*
	 * Make sure packet length is large enough for either
	 * a NS or a NA icmp packet.
	 */
	if (len <  sizeof (struct icmp6_hdr) + sizeof (struct in6_addr)) {
		ip1dbg(("ndp_input: packet too short\n"));
		BUMP_MIB(mib, ipv6IfIcmpInErrors);
		goto done;
	}
	if (icmp_nd->icmp6_type == ND_NEIGHBOR_SOLICIT) {
		ndp_input_solicit(ill, mp, dl_mp);
	} else {
		ndp_input_advert(ill, mp, dl_mp);
	}
done:
	freemsg(mp);
}

/*
 * Utility routine to send an advertisement.  Assumes that the NCE cannot
 * go away (e.g., because it's refheld).
 */
static boolean_t
nce_xmit_advert(nce_t *nce, boolean_t use_nd_lla, const in6_addr_t *target,
    uint_t flags)
{
	ASSERT((flags & NDP_PROBE) == 0);

	if (nce->nce_flags & NCE_F_ISROUTER)
		flags |= NDP_ISROUTER;
	if (!(nce->nce_flags & NCE_F_ANYCAST))
		flags |= NDP_ORIDE;

	return (nce_xmit(nce->nce_ill, ND_NEIGHBOR_ADVERT, use_nd_lla,
	    &nce->nce_addr, target, flags));
}

/*
 * Utility routine to send a solicitation.  Assumes that the NCE cannot
 * go away (e.g., because it's refheld).
 */
static boolean_t
nce_xmit_solicit(nce_t *nce, boolean_t use_nd_lla, const in6_addr_t *sender,
    uint_t flags)
{
	if (flags & NDP_PROBE)
		sender = &ipv6_all_zeros;

	return (nce_xmit(nce->nce_ill, ND_NEIGHBOR_SOLICIT, use_nd_lla,
	    sender, &nce->nce_addr, flags));
}

/*
 * nce_xmit is called to form and transmit a ND solicitation or
 * advertisement ICMP packet.
 *
 * If the source address is unspecified and this isn't a probe (used for
 * duplicate address detection), an appropriate source address and link layer
 * address will be chosen here.  The link layer address option is included if
 * the source is specified (i.e., all non-probe packets), and omitted (per the
 * specification) otherwise.
 *
 * It returns B_FALSE only if it does a successful put() to the
 * corresponding ill's ill_wq otherwise returns B_TRUE.
 */
static boolean_t
nce_xmit(ill_t *ill, uint8_t type, boolean_t use_nd_lla,
    const in6_addr_t *sender, const in6_addr_t *target, int flag)
{
	ill_t		*hwaddr_ill;
	uint32_t	len;
	icmp6_t 	*icmp6;
	mblk_t		*mp;
	ip6_t		*ip6h;
	nd_opt_hdr_t	*opt;
	uint_t		plen, maxplen;
	ip6i_t		*ip6i;
	ipif_t		*src_ipif = NULL;
	uint8_t		*hw_addr;
	zoneid_t	zoneid = GLOBAL_ZONEID;
	char		buf[INET6_ADDRSTRLEN];

	ASSERT(!IS_IPMP(ill));

	/*
	 * Check that the sender is actually a usable address on `ill', and if
	 * so, track that as the src_ipif.  If not, for solicitations, set the
	 * sender to :: so that a new one will be picked below; for adverts,
	 * drop the packet since we expect nce_xmit_advert() to always provide
	 * a valid sender.
	 */
	if (!IN6_IS_ADDR_UNSPECIFIED(sender)) {
		if ((src_ipif = ip_ndp_lookup_addr_v6(sender, ill)) == NULL ||
		    !src_ipif->ipif_addr_ready) {
			if (src_ipif != NULL) {
				ipif_refrele(src_ipif);
				src_ipif = NULL;
			}
			if (type == ND_NEIGHBOR_ADVERT) {
				ip1dbg(("nce_xmit: No source ipif for src %s\n",
				    inet_ntop(AF_INET6, sender, buf,
				    sizeof (buf))));
				return (B_TRUE);
			}
			sender = &ipv6_all_zeros;
		}
	}

	/*
	 * If we still have an unspecified source (sender) address and this
	 * isn't a probe, select a source address from `ill'.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(sender) && !(flag & NDP_PROBE)) {
		ASSERT(type != ND_NEIGHBOR_ADVERT);
		/*
		 * Pick a source address for this solicitation, but restrict
		 * the selection to addresses assigned to the output
		 * interface.  We do this because the destination will create
		 * a neighbor cache entry for the source address of this
		 * packet, so the source address needs to be a valid neighbor.
		 */
		src_ipif = ipif_select_source_v6(ill, target, B_TRUE,
		    IPV6_PREFER_SRC_DEFAULT, ALL_ZONES);
		if (src_ipif == NULL) {
			ip1dbg(("nce_xmit: No source ipif for dst %s\n",
			    inet_ntop(AF_INET6, target, buf, sizeof (buf))));
			return (B_TRUE);
		}
		sender = &src_ipif->ipif_v6src_addr;
	}

	/*
	 * We're either sending a probe or we have a source address.
	 */
	ASSERT((flag & NDP_PROBE) || src_ipif != NULL);

	maxplen = roundup(sizeof (nd_opt_hdr_t) + ND_MAX_HDW_LEN, 8);
	len = IPV6_HDR_LEN + sizeof (ip6i_t) + sizeof (nd_neighbor_advert_t) +
	    maxplen;
	mp = allocb(len,  BPRI_LO);
	if (mp == NULL) {
		if (src_ipif != NULL)
			ipif_refrele(src_ipif);
		return (B_TRUE);
	}
	bzero((char *)mp->b_rptr, len);
	mp->b_wptr = mp->b_rptr + len;

	ip6i = (ip6i_t *)mp->b_rptr;
	ip6i->ip6i_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	ip6i->ip6i_nxt = IPPROTO_RAW;
	ip6i->ip6i_flags = IP6I_HOPLIMIT;
	if (flag & NDP_PROBE)
		ip6i->ip6i_flags |= IP6I_UNSPEC_SRC;

	ip6h = (ip6_t *)(mp->b_rptr + sizeof (ip6i_t));
	ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	ip6h->ip6_plen = htons(len - IPV6_HDR_LEN - sizeof (ip6i_t));
	ip6h->ip6_nxt = IPPROTO_ICMPV6;
	ip6h->ip6_hops = IPV6_MAX_HOPS;
	ip6h->ip6_src = *sender;
	ip6h->ip6_dst = *target;
	icmp6 = (icmp6_t *)&ip6h[1];

	opt = (nd_opt_hdr_t *)((uint8_t *)ip6h + IPV6_HDR_LEN +
	    sizeof (nd_neighbor_advert_t));

	if (type == ND_NEIGHBOR_SOLICIT) {
		nd_neighbor_solicit_t *ns = (nd_neighbor_solicit_t *)icmp6;

		if (!(flag & NDP_PROBE))
			opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
		ns->nd_ns_target = *target;
		if (!(flag & NDP_UNICAST)) {
			/* Form multicast address of the target */
			ip6h->ip6_dst = ipv6_solicited_node_mcast;
			ip6h->ip6_dst.s6_addr32[3] |=
			    ns->nd_ns_target.s6_addr32[3];
		}
	} else {
		nd_neighbor_advert_t *na = (nd_neighbor_advert_t *)icmp6;

		ASSERT(!(flag & NDP_PROBE));
		opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		na->nd_na_target = *sender;
		if (flag & NDP_ISROUTER)
			na->nd_na_flags_reserved |= ND_NA_FLAG_ROUTER;
		if (flag & NDP_SOLICITED)
			na->nd_na_flags_reserved |= ND_NA_FLAG_SOLICITED;
		if (flag & NDP_ORIDE)
			na->nd_na_flags_reserved |= ND_NA_FLAG_OVERRIDE;
	}

	hw_addr = NULL;
	if (!(flag & NDP_PROBE)) {
		/*
		 * Use our source address to find the hardware address to put
		 * in the packet, so that the hardware address and IP address
		 * will match up -- even if that hardware address doesn't
		 * match the ill we actually transmit the packet through.
		 */
		if (IS_IPMP(src_ipif->ipif_ill)) {
			hwaddr_ill = ipmp_ipif_hold_bound_ill(src_ipif);
			if (hwaddr_ill == NULL) {
				ip1dbg(("nce_xmit: no bound ill!\n"));
				ipif_refrele(src_ipif);
				freemsg(mp);
				return (B_TRUE);
			}
		} else {
			hwaddr_ill = src_ipif->ipif_ill;
			ill_refhold(hwaddr_ill);	/* for symmetry */
		}

		plen = roundup(sizeof (nd_opt_hdr_t) +
		    hwaddr_ill->ill_nd_lla_len, 8);

		hw_addr = use_nd_lla ? hwaddr_ill->ill_nd_lla :
		    hwaddr_ill->ill_phys_addr;
		if (hw_addr != NULL) {
			/* Fill in link layer address and option len */
			opt->nd_opt_len = (uint8_t)(plen / 8);
			bcopy(hw_addr, &opt[1], hwaddr_ill->ill_nd_lla_len);
		}

		ill_refrele(hwaddr_ill);
	}

	if (hw_addr == NULL)
		plen = 0;

	/* Fix up the length of the packet now that plen is known */
	len -= (maxplen - plen);
	mp->b_wptr = mp->b_rptr + len;
	ip6h->ip6_plen = htons(len - IPV6_HDR_LEN - sizeof (ip6i_t));

	icmp6->icmp6_type = type;
	icmp6->icmp6_code = 0;
	/*
	 * Prepare for checksum by putting icmp length in the icmp
	 * checksum field. The checksum is calculated in ip_wput_v6.
	 */
	icmp6->icmp6_cksum = ip6h->ip6_plen;

	/*
	 * Before we toss the src_ipif, look up the zoneid to pass to
	 * ip_output_v6().  This is to ensure unicast ND_NEIGHBOR_ADVERT
	 * packets to be routed correctly by IP (we cannot guarantee that the
	 * global zone has an interface route to the destination).
	 */
	if (src_ipif != NULL) {
		if ((zoneid = src_ipif->ipif_zoneid) == ALL_ZONES)
			zoneid = GLOBAL_ZONEID;
		ipif_refrele(src_ipif);
	}

	ip_output_v6((void *)(uintptr_t)zoneid, mp, ill->ill_wq, IP_WPUT);
	return (B_FALSE);
}

/*
 * Make a link layer address (does not include the SAP) from an nce.
 * To form the link layer address, use the last four bytes of ipv6
 * address passed in and the fixed offset stored in nce.
 */
static void
nce_make_mapping(nce_t *nce, uchar_t *addrpos, uchar_t *addr)
{
	uchar_t *mask, *to;
	ill_t	*ill = nce->nce_ill;
	int 	len;

	if (ill->ill_net_type == IRE_IF_NORESOLVER)
		return;
	ASSERT(nce->nce_res_mp != NULL);
	ASSERT(ill->ill_net_type == IRE_IF_RESOLVER);
	ASSERT(nce->nce_flags & NCE_F_MAPPING);
	ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&nce->nce_extract_mask));
	ASSERT(addr != NULL);
	bcopy(nce->nce_res_mp->b_rptr + NCE_LL_ADDR_OFFSET(ill),
	    addrpos, ill->ill_nd_lla_len);
	len = MIN((int)ill->ill_nd_lla_len - nce->nce_ll_extract_start,
	    IPV6_ADDR_LEN);
	mask = (uchar_t *)&nce->nce_extract_mask;
	mask += (IPV6_ADDR_LEN - len);
	addr += (IPV6_ADDR_LEN - len);
	to = addrpos + nce->nce_ll_extract_start;
	while (len-- > 0)
		*to++ |= *mask++ & *addr++;
}

mblk_t *
nce_udreq_alloc(ill_t *ill)
{
	mblk_t	*template_mp = NULL;
	dl_unitdata_req_t *dlur;
	int	sap_length;

	ASSERT(ill->ill_isv6);

	sap_length = ill->ill_sap_length;
	template_mp = ip_dlpi_alloc(sizeof (dl_unitdata_req_t) +
	    ill->ill_nd_lla_len + ABS(sap_length), DL_UNITDATA_REQ);
	if (template_mp == NULL)
		return (NULL);

	dlur = (dl_unitdata_req_t *)template_mp->b_rptr;
	dlur->dl_priority.dl_min = 0;
	dlur->dl_priority.dl_max = 0;
	dlur->dl_dest_addr_length = ABS(sap_length) + ill->ill_nd_lla_len;
	dlur->dl_dest_addr_offset = sizeof (dl_unitdata_req_t);

	/* Copy in the SAP value. */
	NCE_LL_SAP_COPY(ill, template_mp);

	return (template_mp);
}

/*
 * NDP retransmit timer.
 * This timer goes off when:
 * a. It is time to retransmit NS for resolver.
 * b. It is time to send reachability probes.
 */
void
ndp_timer(void *arg)
{
	nce_t		*nce = arg;
	ill_t		*ill = nce->nce_ill;
	uint32_t	ms;
	char		addrbuf[INET6_ADDRSTRLEN];
	boolean_t	dropped = B_FALSE;
	ip_stack_t	*ipst = ill->ill_ipst;

	/*
	 * The timer has to be cancelled by ndp_delete before doing the final
	 * refrele. So the NCE is guaranteed to exist when the timer runs
	 * until it clears the timeout_id. Before clearing the timeout_id
	 * bump up the refcnt so that we can continue to use the nce
	 */
	ASSERT(nce != NULL);

	mutex_enter(&nce->nce_lock);
	NCE_REFHOLD_LOCKED(nce);
	nce->nce_timeout_id = 0;

	/*
	 * Check the reachability state first.
	 */
	switch (nce->nce_state) {
	case ND_DELAY:
		nce->nce_state = ND_PROBE;
		mutex_exit(&nce->nce_lock);
		(void) nce_xmit_solicit(nce, B_FALSE, &ipv6_all_zeros,
		    NDP_UNICAST);
		if (ip_debug > 3) {
			/* ip2dbg */
			pr_addr_dbg("ndp_timer: state for %s changed "
			    "to PROBE\n", AF_INET6, &nce->nce_addr);
		}
		NDP_RESTART_TIMER(nce, ill->ill_reachable_retrans_time);
		NCE_REFRELE(nce);
		return;
	case ND_PROBE:
		/* must be retransmit timer */
		nce->nce_pcnt--;
		ASSERT(nce->nce_pcnt < ND_MAX_UNICAST_SOLICIT &&
		    nce->nce_pcnt >= -1);
		if (nce->nce_pcnt > 0) {
			/*
			 * As per RFC2461, the nce gets deleted after
			 * MAX_UNICAST_SOLICIT unsuccessful re-transmissions.
			 * Note that the first unicast solicitation is sent
			 * during the DELAY state.
			 */
			ip2dbg(("ndp_timer: pcount=%x dst %s\n",
			    nce->nce_pcnt, inet_ntop(AF_INET6, &nce->nce_addr,
			    addrbuf, sizeof (addrbuf))));
			mutex_exit(&nce->nce_lock);
			dropped = nce_xmit_solicit(nce, B_FALSE,
			    &ipv6_all_zeros,
			    (nce->nce_flags & NCE_F_PERMANENT) ? NDP_PROBE :
			    NDP_UNICAST);
			if (dropped) {
				mutex_enter(&nce->nce_lock);
				nce->nce_pcnt++;
				mutex_exit(&nce->nce_lock);
			}
			NDP_RESTART_TIMER(nce, ILL_PROBE_INTERVAL(ill));
		} else if (nce->nce_pcnt < 0) {
			/* No hope, delete the nce */
			nce->nce_state = ND_UNREACHABLE;
			mutex_exit(&nce->nce_lock);
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("ndp_timer: Delete IRE for"
				    " dst %s\n", AF_INET6, &nce->nce_addr);
			}
			ndp_delete(nce);
		} else if (!(nce->nce_flags & NCE_F_PERMANENT)) {
			/* Wait RetransTimer, before deleting the entry */
			ip2dbg(("ndp_timer: pcount=%x dst %s\n",
			    nce->nce_pcnt, inet_ntop(AF_INET6,
			    &nce->nce_addr, addrbuf, sizeof (addrbuf))));
			mutex_exit(&nce->nce_lock);
			/* Wait one interval before killing */
			NDP_RESTART_TIMER(nce, ill->ill_reachable_retrans_time);
		} else if (ill->ill_phyint->phyint_flags & PHYI_RUNNING) {
			ipif_t *ipif;

			/*
			 * We're done probing, and we can now declare this
			 * address to be usable.  Let IP know that it's ok to
			 * use.
			 */
			nce->nce_state = ND_REACHABLE;
			mutex_exit(&nce->nce_lock);
			ipif = ip_ndp_lookup_addr_v6(&nce->nce_addr,
			    nce->nce_ill);
			if (ipif != NULL) {
				if (ipif->ipif_was_dup) {
					char ibuf[LIFNAMSIZ + 10];
					char sbuf[INET6_ADDRSTRLEN];

					ipif->ipif_was_dup = B_FALSE;
					(void) inet_ntop(AF_INET6,
					    &ipif->ipif_v6lcl_addr,
					    sbuf, sizeof (sbuf));
					ipif_get_name(ipif, ibuf,
					    sizeof (ibuf));
					cmn_err(CE_NOTE, "recovered address "
					    "%s on %s", sbuf, ibuf);
				}
				if ((ipif->ipif_flags & IPIF_UP) &&
				    !ipif->ipif_addr_ready)
					ipif_up_notify(ipif);
				ipif->ipif_addr_ready = 1;
				ipif_refrele(ipif);
			}
			/* Begin defending our new address */
			nce->nce_unsolicit_count = 0;
			dropped = nce_xmit_advert(nce, B_FALSE,
			    &ipv6_all_hosts_mcast, 0);
			if (dropped) {
				nce->nce_unsolicit_count = 1;
				NDP_RESTART_TIMER(nce,
				    ipst->ips_ip_ndp_unsolicit_interval);
			} else if (ipst->ips_ip_ndp_defense_interval != 0) {
				NDP_RESTART_TIMER(nce,
				    ipst->ips_ip_ndp_defense_interval);
			}
		} else {
			/*
			 * This is an address we're probing to be our own, but
			 * the ill is down.  Wait until it comes back before
			 * doing anything, but switch to reachable state so
			 * that the restart will work.
			 */
			nce->nce_state = ND_REACHABLE;
			mutex_exit(&nce->nce_lock);
		}
		NCE_REFRELE(nce);
		return;
	case ND_INCOMPLETE: {
		ip6_t	*ip6h;
		ip6i_t	*ip6i;
		mblk_t	*mp, *datamp, *nextmp, **prevmpp;

		/*
		 * Per case (2) in the nce_queue_mp() comments, scan nce_qd_mp
		 * for any IPMP probe packets, and toss 'em.  IPMP probe
		 * packets will always be at the head of nce_qd_mp and always
		 * have an ip6i_t header, so we can stop at the first queued
		 * ND packet without an ip6i_t.
		 */
		prevmpp = &nce->nce_qd_mp;
		for (mp = nce->nce_qd_mp; mp != NULL; mp = nextmp) {
			nextmp = mp->b_next;
			datamp = (DB_TYPE(mp) == M_CTL) ? mp->b_cont : mp;
			ip6h = (ip6_t *)datamp->b_rptr;
			if (ip6h->ip6_nxt != IPPROTO_RAW)
				break;

			ip6i = (ip6i_t *)ip6h;
			if (ip6i->ip6i_flags & IP6I_IPMP_PROBE) {
				inet_freemsg(mp);
				*prevmpp = nextmp;
			} else {
				prevmpp = &mp->b_next;
			}
		}

		/*
		 * Must be resolver's retransmit timer.
		 */
		if (nce->nce_qd_mp != NULL) {
			if ((ms = nce_solicit(nce, NULL)) == 0) {
				if (nce->nce_state != ND_REACHABLE) {
					mutex_exit(&nce->nce_lock);
					nce_resolv_failed(nce);
					ndp_delete(nce);
				} else {
					mutex_exit(&nce->nce_lock);
				}
			} else {
				mutex_exit(&nce->nce_lock);
				NDP_RESTART_TIMER(nce, (clock_t)ms);
			}
			NCE_REFRELE(nce);
			return;
		}
		mutex_exit(&nce->nce_lock);
		NCE_REFRELE(nce);
		break;
	}
	case ND_REACHABLE:
		if (((nce->nce_flags & NCE_F_UNSOL_ADV) &&
		    nce->nce_unsolicit_count != 0) ||
		    ((nce->nce_flags & NCE_F_PERMANENT) &&
		    ipst->ips_ip_ndp_defense_interval != 0)) {
			if (nce->nce_unsolicit_count > 0)
				nce->nce_unsolicit_count--;
			mutex_exit(&nce->nce_lock);
			dropped = nce_xmit_advert(nce, B_FALSE,
			    &ipv6_all_hosts_mcast, 0);
			if (dropped) {
				mutex_enter(&nce->nce_lock);
				nce->nce_unsolicit_count++;
				mutex_exit(&nce->nce_lock);
			}
			if (nce->nce_unsolicit_count != 0) {
				NDP_RESTART_TIMER(nce,
				    ipst->ips_ip_ndp_unsolicit_interval);
			} else {
				NDP_RESTART_TIMER(nce,
				    ipst->ips_ip_ndp_defense_interval);
			}
		} else {
			mutex_exit(&nce->nce_lock);
		}
		NCE_REFRELE(nce);
		break;
	default:
		mutex_exit(&nce->nce_lock);
		NCE_REFRELE(nce);
		break;
	}
}

/*
 * Set a link layer address from the ll_addr passed in.
 * Copy SAP from ill.
 */
static void
nce_set_ll(nce_t *nce, uchar_t *ll_addr)
{
	ill_t	*ill = nce->nce_ill;
	uchar_t	*woffset;

	ASSERT(ll_addr != NULL);
	/* Always called before fast_path_probe */
	ASSERT(nce->nce_fp_mp == NULL);
	if (ill->ill_sap_length != 0) {
		/*
		 * Copy the SAP type specified in the
		 * request into the xmit template.
		 */
		NCE_LL_SAP_COPY(ill, nce->nce_res_mp);
	}
	if (ill->ill_phys_addr_length > 0) {
		/*
		 * The bcopy() below used to be called for the physical address
		 * length rather than the link layer address length. For
		 * ethernet and many other media, the phys_addr and lla are
		 * identical.
		 * However, with xresolv interfaces being introduced, the
		 * phys_addr and lla are no longer the same, and the physical
		 * address may not have any useful meaning, so we use the lla
		 * for IPv6 address resolution and destination addressing.
		 *
		 * For PPP or other interfaces with a zero length
		 * physical address, don't do anything here.
		 * The bcopy() with a zero phys_addr length was previously
		 * a no-op for interfaces with a zero-length physical address.
		 * Using the lla for them would change the way they operate.
		 * Doing nothing in such cases preserves expected behavior.
		 */
		woffset = nce->nce_res_mp->b_rptr + NCE_LL_ADDR_OFFSET(ill);
		bcopy(ll_addr, woffset, ill->ill_nd_lla_len);
	}
}

static boolean_t
nce_cmp_ll_addr(const nce_t *nce, const uchar_t *ll_addr, uint32_t ll_addr_len)
{
	ill_t	*ill = nce->nce_ill;
	uchar_t	*ll_offset;

	ASSERT(nce->nce_res_mp != NULL);
	if (ll_addr == NULL)
		return (B_FALSE);
	ll_offset = nce->nce_res_mp->b_rptr + NCE_LL_ADDR_OFFSET(ill);
	if (bcmp(ll_addr, ll_offset, ll_addr_len) != 0)
		return (B_TRUE);
	return (B_FALSE);
}

/*
 * Updates the link layer address or the reachability state of
 * a cache entry.  Reset probe counter if needed.
 */
static void
nce_update(nce_t *nce, uint16_t new_state, uchar_t *new_ll_addr)
{
	ill_t	*ill = nce->nce_ill;
	boolean_t need_stop_timer = B_FALSE;
	boolean_t need_fastpath_update = B_FALSE;

	ASSERT(MUTEX_HELD(&nce->nce_lock));
	ASSERT(nce->nce_ipversion == IPV6_VERSION);
	/*
	 * If this interface does not do NUD, there is no point
	 * in allowing an update to the cache entry.  Although
	 * we will respond to NS.
	 * The only time we accept an update for a resolver when
	 * NUD is turned off is when it has just been created.
	 * Non-Resolvers will always be created as REACHABLE.
	 */
	if (new_state != ND_UNCHANGED) {
		if ((nce->nce_flags & NCE_F_NONUD) &&
		    (nce->nce_state != ND_INCOMPLETE))
			return;
		ASSERT((int16_t)new_state >= ND_STATE_VALID_MIN);
		ASSERT((int16_t)new_state <= ND_STATE_VALID_MAX);
		need_stop_timer = B_TRUE;
		if (new_state == ND_REACHABLE)
			nce->nce_last = TICK_TO_MSEC(lbolt64);
		else {
			/* We force NUD in this case */
			nce->nce_last = 0;
		}
		nce->nce_state = new_state;
		nce->nce_pcnt = ND_MAX_UNICAST_SOLICIT;
	}
	/*
	 * In case of fast path we need to free the the fastpath
	 * M_DATA and do another probe.  Otherwise we can just
	 * overwrite the DL_UNITDATA_REQ data, noting we'll lose
	 * whatever packets that happens to be transmitting at the time.
	 */
	if (new_ll_addr != NULL) {
		ASSERT(nce->nce_res_mp->b_rptr + NCE_LL_ADDR_OFFSET(ill) +
		    ill->ill_nd_lla_len <= nce->nce_res_mp->b_wptr);
		bcopy(new_ll_addr, nce->nce_res_mp->b_rptr +
		    NCE_LL_ADDR_OFFSET(ill), ill->ill_nd_lla_len);
		if (nce->nce_fp_mp != NULL) {
			freemsg(nce->nce_fp_mp);
			nce->nce_fp_mp = NULL;
		}
		need_fastpath_update = B_TRUE;
	}
	mutex_exit(&nce->nce_lock);
	if (need_stop_timer) {
		(void) untimeout(nce->nce_timeout_id);
		nce->nce_timeout_id = 0;
	}
	if (need_fastpath_update)
		nce_fastpath(nce);
	mutex_enter(&nce->nce_lock);
}

void
nce_queue_mp_common(nce_t *nce, mblk_t *mp, boolean_t head_insert)
{
	uint_t	count = 0;
	mblk_t  **mpp, *tmp;

	ASSERT(MUTEX_HELD(&nce->nce_lock));

	for (mpp = &nce->nce_qd_mp; *mpp != NULL; mpp = &(*mpp)->b_next) {
		if (++count > nce->nce_ill->ill_max_buf) {
			tmp = nce->nce_qd_mp->b_next;
			nce->nce_qd_mp->b_next = NULL;
			nce->nce_qd_mp->b_prev = NULL;
			freemsg(nce->nce_qd_mp);
			nce->nce_qd_mp = tmp;
		}
	}

	if (head_insert) {
		mp->b_next = nce->nce_qd_mp;
		nce->nce_qd_mp = mp;
	} else {
		*mpp = mp;
	}
}

static void
nce_queue_mp(nce_t *nce, mblk_t *mp)
{
	boolean_t head_insert = B_FALSE;
	ip6_t	*ip6h;
	ip6i_t  *ip6i;
	mblk_t	*data_mp;

	ASSERT(MUTEX_HELD(&nce->nce_lock));

	if (mp->b_datap->db_type == M_CTL)
		data_mp = mp->b_cont;
	else
		data_mp = mp;
	ip6h = (ip6_t *)data_mp->b_rptr;
	if (ip6h->ip6_nxt == IPPROTO_RAW) {
		/*
		 * This message should have been pulled up already in
		 * ip_wput_v6. We can't do pullups here because the message
		 * could be from the nce_qd_mp which could have b_next/b_prev
		 * non-NULL.
		 */
		ip6i = (ip6i_t *)ip6h;
		ASSERT(MBLKL(data_mp) >= sizeof (ip6i_t) + IPV6_HDR_LEN);

		/*
		 * If this packet is marked IP6I_IPMP_PROBE, then we need to:
		 *
		 *   1. Insert it at the head of the nce_qd_mp list.  Consider
		 *	the normal (non-probe) load-speading case where the
		 *	source address of the ND packet is not tied to nce_ill.
		 *	If the ill bound to the source address cannot receive,
		 *	the response to the ND packet will not be received.
		 *	However, if ND packets for nce_ill's probes are queued
		 *	behind that ND packet, those probes will also fail to
		 *	be sent, and thus in.mpathd will erroneously conclude
		 *	that nce_ill has also failed.
		 *
		 *   2. Drop the probe packet in ndp_timer() if the ND did
		 *	not succeed on the first attempt.  This ensures that
		 *	ND problems do not manifest as probe RTT spikes.
		 */
		if (ip6i->ip6i_flags & IP6I_IPMP_PROBE)
			head_insert = B_TRUE;
	}
	nce_queue_mp_common(nce, mp, head_insert);
}

/*
 * Called when address resolution failed due to a timeout.
 * Send an ICMP unreachable in response to all queued packets.
 */
void
nce_resolv_failed(nce_t *nce)
{
	mblk_t	*mp, *nxt_mp, *first_mp;
	char	buf[INET6_ADDRSTRLEN];
	ip6_t *ip6h;
	zoneid_t zoneid = GLOBAL_ZONEID;
	ip_stack_t	*ipst = nce->nce_ill->ill_ipst;

	ip1dbg(("nce_resolv_failed: dst %s\n",
	    inet_ntop(AF_INET6, (char *)&nce->nce_addr, buf, sizeof (buf))));
	mutex_enter(&nce->nce_lock);
	mp = nce->nce_qd_mp;
	nce->nce_qd_mp = NULL;
	mutex_exit(&nce->nce_lock);
	while (mp != NULL) {
		nxt_mp = mp->b_next;
		mp->b_next = NULL;
		mp->b_prev = NULL;

		first_mp = mp;
		if (mp->b_datap->db_type == M_CTL) {
			ipsec_out_t *io = (ipsec_out_t *)mp->b_rptr;
			ASSERT(io->ipsec_out_type == IPSEC_OUT);
			zoneid = io->ipsec_out_zoneid;
			ASSERT(zoneid != ALL_ZONES);
			mp = mp->b_cont;
			mp->b_next = NULL;
			mp->b_prev = NULL;
		}

		ip6h = (ip6_t *)mp->b_rptr;
		if (ip6h->ip6_nxt == IPPROTO_RAW) {
			ip6i_t *ip6i;
			/*
			 * This message should have been pulled up already
			 * in ip_wput_v6. ip_hdr_complete_v6 assumes that
			 * the header is pulled up.
			 */
			ip6i = (ip6i_t *)ip6h;
			ASSERT((mp->b_wptr - (uchar_t *)ip6i) >=
			    sizeof (ip6i_t) + IPV6_HDR_LEN);
			mp->b_rptr += sizeof (ip6i_t);
		}
		/*
		 * Ignore failure since icmp_unreachable_v6 will silently
		 * drop packets with an unspecified source address.
		 */
		(void) ip_hdr_complete_v6((ip6_t *)mp->b_rptr, zoneid, ipst);
		icmp_unreachable_v6(nce->nce_ill->ill_wq, first_mp,
		    ICMP6_DST_UNREACH_ADDR, B_FALSE, B_FALSE, zoneid, ipst);
		mp = nxt_mp;
	}
}

/*
 * Called by SIOCSNDP* ioctl to add/change an nce entry
 * and the corresponding attributes.
 * Disallow states other than ND_REACHABLE or ND_STALE.
 */
int
ndp_sioc_update(ill_t *ill, lif_nd_req_t *lnr)
{
	sin6_t		*sin6;
	in6_addr_t	*addr;
	nce_t		*nce;
	int		err;
	uint16_t	new_flags = 0;
	uint16_t	old_flags = 0;
	int		inflags = lnr->lnr_flags;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ill->ill_isv6);
	if ((lnr->lnr_state_create != ND_REACHABLE) &&
	    (lnr->lnr_state_create != ND_STALE))
		return (EINVAL);

	if (lnr->lnr_hdw_len > ND_MAX_HDW_LEN)
		return (EINVAL);

	sin6 = (sin6_t *)&lnr->lnr_addr;
	addr = &sin6->sin6_addr;

	mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
	/* We know it can not be mapping so just look in the hash table */
	nce = *((nce_t **)NCE_HASH_PTR_V6(ipst, *addr));
	/* See comment in ndp_query() regarding IS_IPMP(ill) usage */
	nce = nce_lookup_addr(ill, IS_IPMP(ill), addr, nce);
	if (nce != NULL)
		new_flags = nce->nce_flags;

	switch (inflags & (NDF_ISROUTER_ON|NDF_ISROUTER_OFF)) {
	case NDF_ISROUTER_ON:
		new_flags |= NCE_F_ISROUTER;
		break;
	case NDF_ISROUTER_OFF:
		new_flags &= ~NCE_F_ISROUTER;
		break;
	case (NDF_ISROUTER_OFF|NDF_ISROUTER_ON):
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		if (nce != NULL)
			NCE_REFRELE(nce);
		return (EINVAL);
	}

	switch (inflags & (NDF_ANYCAST_ON|NDF_ANYCAST_OFF)) {
	case NDF_ANYCAST_ON:
		new_flags |= NCE_F_ANYCAST;
		break;
	case NDF_ANYCAST_OFF:
		new_flags &= ~NCE_F_ANYCAST;
		break;
	case (NDF_ANYCAST_OFF|NDF_ANYCAST_ON):
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		if (nce != NULL)
			NCE_REFRELE(nce);
		return (EINVAL);
	}

	if (nce == NULL) {
		err = ndp_add_v6(ill,
		    (uchar_t *)lnr->lnr_hdw_addr,
		    addr,
		    &ipv6_all_ones,
		    &ipv6_all_zeros,
		    0,
		    new_flags,
		    lnr->lnr_state_create,
		    &nce);
		if (err != 0) {
			mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
			ip1dbg(("ndp_sioc_update: Can't create NCE %d\n", err));
			return (err);
		}
	}
	old_flags = nce->nce_flags;
	if (old_flags & NCE_F_ISROUTER && !(new_flags & NCE_F_ISROUTER)) {
		/*
		 * Router turned to host, delete all ires.
		 * XXX Just delete the entry, but we need to add too.
		 */
		nce->nce_flags &= ~NCE_F_ISROUTER;
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		ndp_delete(nce);
		NCE_REFRELE(nce);
		return (0);
	}
	mutex_exit(&ipst->ips_ndp6->ndp_g_lock);

	mutex_enter(&nce->nce_lock);
	nce->nce_flags = new_flags;
	mutex_exit(&nce->nce_lock);
	/*
	 * Note that we ignore the state at this point, which
	 * should be either STALE or REACHABLE.  Instead we let
	 * the link layer address passed in to determine the state
	 * much like incoming packets.
	 */
	nce_process(nce, (uchar_t *)lnr->lnr_hdw_addr, 0, B_FALSE);
	NCE_REFRELE(nce);
	return (0);
}

/*
 * If the device driver supports it, we make nce_fp_mp to have
 * an M_DATA prepend.  Otherwise nce_fp_mp will be null.
 * The caller ensures there is hold on nce for this function.
 * Note that since ill_fastpath_probe() copies the mblk there is
 * no need for the hold beyond this function.
 */
void
nce_fastpath(nce_t *nce)
{
	ill_t	*ill = nce->nce_ill;
	int res;

	ASSERT(ill != NULL);
	ASSERT(nce->nce_state != ND_INITIAL && nce->nce_state != ND_INCOMPLETE);

	if (nce->nce_fp_mp != NULL) {
		/* Already contains fastpath info */
		return;
	}
	if (nce->nce_res_mp != NULL) {
		nce_fastpath_list_add(nce);
		res = ill_fastpath_probe(ill, nce->nce_res_mp);
		/*
		 * EAGAIN is an indication of a transient error
		 * i.e. allocation failure etc. leave the nce in the list it
		 * will be updated when another probe happens for another ire
		 * if not it will be taken out of the list when the ire is
		 * deleted.
		 */

		if (res != 0 && res != EAGAIN)
			nce_fastpath_list_delete(nce);
	}
}

/*
 * Drain the list of nce's waiting for fastpath response.
 */
void
nce_fastpath_list_dispatch(ill_t *ill, boolean_t (*func)(nce_t *, void  *),
    void *arg)
{

	nce_t *next_nce;
	nce_t *current_nce;
	nce_t *first_nce;
	nce_t *prev_nce = NULL;

	mutex_enter(&ill->ill_lock);
	first_nce = current_nce = (nce_t *)ill->ill_fastpath_list;
	while (current_nce != (nce_t *)&ill->ill_fastpath_list) {
		next_nce = current_nce->nce_fastpath;
		/*
		 * Take it off the list if we're flushing, or if the callback
		 * routine tells us to do so.  Otherwise, leave the nce in the
		 * fastpath list to handle any pending response from the lower
		 * layer.  We can't drain the list when the callback routine
		 * comparison failed, because the response is asynchronous in
		 * nature, and may not arrive in the same order as the list
		 * insertion.
		 */
		if (func == NULL || func(current_nce, arg)) {
			current_nce->nce_fastpath = NULL;
			if (current_nce == first_nce)
				ill->ill_fastpath_list = first_nce = next_nce;
			else
				prev_nce->nce_fastpath = next_nce;
		} else {
			/* previous element that is still in the list */
			prev_nce = current_nce;
		}
		current_nce = next_nce;
	}
	mutex_exit(&ill->ill_lock);
}

/*
 * Add nce to the nce fastpath list.
 */
void
nce_fastpath_list_add(nce_t *nce)
{
	ill_t *ill;

	ill = nce->nce_ill;

	mutex_enter(&ill->ill_lock);
	mutex_enter(&nce->nce_lock);

	/*
	 * if nce has not been deleted and
	 * is not already in the list add it.
	 */
	if (!(nce->nce_flags & NCE_F_CONDEMNED) &&
	    (nce->nce_fastpath == NULL)) {
		nce->nce_fastpath = (nce_t *)ill->ill_fastpath_list;
		ill->ill_fastpath_list = nce;
	}

	mutex_exit(&nce->nce_lock);
	mutex_exit(&ill->ill_lock);
}

/*
 * remove nce from the nce fastpath list.
 */
void
nce_fastpath_list_delete(nce_t *nce)
{
	nce_t *nce_ptr;

	ill_t *ill;

	ill = nce->nce_ill;
	ASSERT(ill != NULL);

	mutex_enter(&ill->ill_lock);
	if (nce->nce_fastpath == NULL)
		goto done;

	ASSERT(ill->ill_fastpath_list != &ill->ill_fastpath_list);

	if (ill->ill_fastpath_list == nce) {
		ill->ill_fastpath_list = nce->nce_fastpath;
	} else {
		nce_ptr = ill->ill_fastpath_list;
		while (nce_ptr != (nce_t *)&ill->ill_fastpath_list) {
			if (nce_ptr->nce_fastpath == nce) {
				nce_ptr->nce_fastpath = nce->nce_fastpath;
				break;
			}
			nce_ptr = nce_ptr->nce_fastpath;
		}
	}

	nce->nce_fastpath = NULL;
done:
	mutex_exit(&ill->ill_lock);
}

/*
 * Update all NCE's that are not in fastpath mode and
 * have an nce_fp_mp that matches mp. mp->b_cont contains
 * the fastpath header.
 *
 * Returns TRUE if entry should be dequeued, or FALSE otherwise.
 */
boolean_t
ndp_fastpath_update(nce_t *nce, void *arg)
{
	mblk_t 	*mp, *fp_mp;
	uchar_t	*mp_rptr, *ud_mp_rptr;
	mblk_t	*ud_mp = nce->nce_res_mp;
	ptrdiff_t	cmplen;

	if (nce->nce_flags & NCE_F_MAPPING)
		return (B_TRUE);
	if ((nce->nce_fp_mp != NULL) || (ud_mp == NULL))
		return (B_TRUE);

	ip2dbg(("ndp_fastpath_update: trying\n"));
	mp = (mblk_t *)arg;
	mp_rptr = mp->b_rptr;
	cmplen = mp->b_wptr - mp_rptr;
	ASSERT(cmplen >= 0);
	ud_mp_rptr = ud_mp->b_rptr;
	/*
	 * The nce is locked here to prevent any other threads
	 * from accessing and changing nce_res_mp when the IPv6 address
	 * becomes resolved to an lla while we're in the middle
	 * of looking at and comparing the hardware address (lla).
	 * It is also locked to prevent multiple threads in nce_fastpath_update
	 * from examining nce_res_mp atthe same time.
	 */
	mutex_enter(&nce->nce_lock);
	if (ud_mp->b_wptr - ud_mp_rptr != cmplen ||
	    bcmp((char *)mp_rptr, (char *)ud_mp_rptr, cmplen) != 0) {
		mutex_exit(&nce->nce_lock);
		/*
		 * Don't take the ire off the fastpath list yet,
		 * since the response may come later.
		 */
		return (B_FALSE);
	}
	/* Matched - install mp as the fastpath mp */
	ip1dbg(("ndp_fastpath_update: match\n"));
	fp_mp = dupb(mp->b_cont);
	if (fp_mp != NULL) {
		nce->nce_fp_mp = fp_mp;
	}
	mutex_exit(&nce->nce_lock);
	return (B_TRUE);
}

/*
 * This function handles the DL_NOTE_FASTPATH_FLUSH notification from
 * driver.  Note that it assumes IP is exclusive...
 */
/* ARGSUSED */
void
ndp_fastpath_flush(nce_t *nce, char *arg)
{
	if (nce->nce_flags & NCE_F_MAPPING)
		return;
	/* No fastpath info? */
	if (nce->nce_fp_mp == NULL || nce->nce_res_mp == NULL)
		return;

	if (nce->nce_ipversion == IPV4_VERSION &&
	    nce->nce_flags & NCE_F_BCAST) {
		/*
		 * IPv4 BROADCAST entries:
		 * We can't delete the nce since it is difficult to
		 * recreate these without going through the
		 * ipif down/up dance.
		 *
		 * All access to nce->nce_fp_mp in the case of these
		 * is protected by nce_lock.
		 */
		mutex_enter(&nce->nce_lock);
		if (nce->nce_fp_mp != NULL) {
			freeb(nce->nce_fp_mp);
			nce->nce_fp_mp = NULL;
			mutex_exit(&nce->nce_lock);
			nce_fastpath(nce);
		} else {
			mutex_exit(&nce->nce_lock);
		}
	} else {
		/* Just delete the NCE... */
		ndp_delete(nce);
	}
}

/*
 * Return a pointer to a given option in the packet.
 * Assumes that option part of the packet have already been validated.
 */
nd_opt_hdr_t *
ndp_get_option(nd_opt_hdr_t *opt, int optlen, int opt_type)
{
	while (optlen > 0) {
		if (opt->nd_opt_type == opt_type)
			return (opt);
		optlen -= 8 * opt->nd_opt_len;
		opt = (struct nd_opt_hdr *)((char *)opt + 8 * opt->nd_opt_len);
	}
	return (NULL);
}

/*
 * Verify all option lengths present are > 0, also check to see
 * if the option lengths and packet length are consistent.
 */
boolean_t
ndp_verify_optlen(nd_opt_hdr_t *opt, int optlen)
{
	ASSERT(opt != NULL);
	while (optlen > 0) {
		if (opt->nd_opt_len == 0)
			return (B_FALSE);
		optlen -= 8 * opt->nd_opt_len;
		if (optlen < 0)
			return (B_FALSE);
		opt = (struct nd_opt_hdr *)((char *)opt + 8 * opt->nd_opt_len);
	}
	return (B_TRUE);
}

/*
 * ndp_walk function.
 * Free a fraction of the NCE cache entries.
 * A fraction of zero means to not free any in that category.
 */
void
ndp_cache_reclaim(nce_t *nce, char *arg)
{
	nce_cache_reclaim_t *ncr = (nce_cache_reclaim_t *)arg;
	uint_t	rand;

	if (nce->nce_flags & NCE_F_PERMANENT)
		return;

	rand = (uint_t)lbolt +
	    NCE_ADDR_HASH_V6(nce->nce_addr, NCE_TABLE_SIZE);
	if (ncr->ncr_host != 0 &&
	    (rand/ncr->ncr_host)*ncr->ncr_host == rand) {
		ndp_delete(nce);
		return;
	}
}

/*
 * ndp_walk function.
 * Count the number of NCEs that can be deleted.
 * These would be hosts but not routers.
 */
void
ndp_cache_count(nce_t *nce, char *arg)
{
	ncc_cache_count_t *ncc = (ncc_cache_count_t *)arg;

	if (nce->nce_flags & NCE_F_PERMANENT)
		return;

	ncc->ncc_total++;
	if (!(nce->nce_flags & NCE_F_ISROUTER))
		ncc->ncc_host++;
}

#ifdef DEBUG
void
nce_trace_ref(nce_t *nce)
{
	ASSERT(MUTEX_HELD(&nce->nce_lock));

	if (nce->nce_trace_disable)
		return;

	if (!th_trace_ref(nce, nce->nce_ill->ill_ipst)) {
		nce->nce_trace_disable = B_TRUE;
		nce_trace_cleanup(nce);
	}
}

void
nce_untrace_ref(nce_t *nce)
{
	ASSERT(MUTEX_HELD(&nce->nce_lock));

	if (!nce->nce_trace_disable)
		th_trace_unref(nce);
}

static void
nce_trace_cleanup(const nce_t *nce)
{
	th_trace_cleanup(nce, nce->nce_trace_disable);
}
#endif

/*
 * Called when address resolution fails due to a timeout.
 * Send an ICMP unreachable in response to all queued packets.
 */
void
arp_resolv_failed(nce_t *nce)
{
	mblk_t	*mp, *nxt_mp, *first_mp;
	char	buf[INET6_ADDRSTRLEN];
	zoneid_t zoneid = GLOBAL_ZONEID;
	struct in_addr ipv4addr;
	ip_stack_t *ipst = nce->nce_ill->ill_ipst;

	IN6_V4MAPPED_TO_INADDR(&nce->nce_addr, &ipv4addr);
	ip3dbg(("arp_resolv_failed: dst %s\n",
	    inet_ntop(AF_INET, &ipv4addr, buf, sizeof (buf))));
	mutex_enter(&nce->nce_lock);
	mp = nce->nce_qd_mp;
	nce->nce_qd_mp = NULL;
	mutex_exit(&nce->nce_lock);

	while (mp != NULL) {
		nxt_mp = mp->b_next;
		mp->b_next = NULL;
		mp->b_prev = NULL;

		first_mp = mp;
		/*
		 * Send icmp unreachable messages
		 * to the hosts.
		 */
		(void) ip_hdr_complete((ipha_t *)mp->b_rptr, zoneid, ipst);
		ip3dbg(("arp_resolv_failed: Calling icmp_unreachable\n"));
		icmp_unreachable(nce->nce_ill->ill_wq, first_mp,
		    ICMP_HOST_UNREACHABLE, zoneid, ipst);
		mp = nxt_mp;
	}
}

int
ndp_lookup_then_add_v4(ill_t *ill, const in_addr_t *addr, uint16_t flags,
    nce_t **newnce, nce_t *src_nce)
{
	int	err;
	nce_t	*nce;
	in6_addr_t addr6;
	ip_stack_t *ipst = ill->ill_ipst;

	mutex_enter(&ipst->ips_ndp4->ndp_g_lock);
	nce = *((nce_t **)NCE_HASH_PTR_V4(ipst, *addr));
	IN6_IPADDR_TO_V4MAPPED(*addr, &addr6);
	/*
	 * NOTE: IPv4 never matches across the illgrp since the NCE's we're
	 * looking up have fastpath headers that are inherently per-ill.
	 */
	nce = nce_lookup_addr(ill, B_FALSE, &addr6, nce);
	if (nce == NULL) {
		err = ndp_add_v4(ill, addr, flags, newnce, src_nce);
	} else {
		*newnce = nce;
		err = EEXIST;
	}
	mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
	return (err);
}

/*
 * NDP Cache Entry creation routine for IPv4.
 * Mapped entries are handled in arp.
 * This routine must always be called with ndp4->ndp_g_lock held.
 * Prior to return, nce_refcnt is incremented.
 */
static int
ndp_add_v4(ill_t *ill, const in_addr_t *addr, uint16_t flags,
    nce_t **newnce, nce_t *src_nce)
{
	static	nce_t		nce_nil;
	nce_t		*nce;
	mblk_t		*mp;
	mblk_t		*template = NULL;
	nce_t		**ncep;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint16_t	state = ND_INITIAL;
	int		err;

	ASSERT(MUTEX_HELD(&ipst->ips_ndp4->ndp_g_lock));
	ASSERT(!ill->ill_isv6);
	ASSERT((flags & NCE_F_MAPPING) == 0);

	if (ill->ill_resolver_mp == NULL)
		return (EINVAL);
	/*
	 * Allocate the mblk to hold the nce.
	 */
	mp = allocb(sizeof (nce_t), BPRI_MED);
	if (mp == NULL)
		return (ENOMEM);

	nce = (nce_t *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)&nce[1];
	*nce = nce_nil;
	nce->nce_ill = ill;
	nce->nce_ipversion = IPV4_VERSION;
	nce->nce_flags = flags;
	nce->nce_pcnt = ND_MAX_UNICAST_SOLICIT;
	nce->nce_rcnt = ill->ill_xmit_count;
	IN6_IPADDR_TO_V4MAPPED(*addr, &nce->nce_addr);
	nce->nce_mask = ipv6_all_ones;
	nce->nce_extract_mask = ipv6_all_zeros;
	nce->nce_ll_extract_start = 0;
	nce->nce_qd_mp = NULL;
	nce->nce_mp = mp;
	/* This one is for nce getting created */
	nce->nce_refcnt = 1;
	mutex_init(&nce->nce_lock, NULL, MUTEX_DEFAULT, NULL);
	ncep = ((nce_t **)NCE_HASH_PTR_V4(ipst, *addr));

	nce->nce_trace_disable = B_FALSE;

	if (src_nce != NULL) {
		/*
		 * src_nce has been provided by the caller. The only
		 * caller who provides a non-null, non-broadcast
		 * src_nce is from ip_newroute() which must pass in
		 * a ND_REACHABLE src_nce (this condition is verified
		 * via an ASSERT for the save_ire->ire_nce in ip_newroute())
		 */
		mutex_enter(&src_nce->nce_lock);
		state = src_nce->nce_state;
		if ((src_nce->nce_flags & NCE_F_CONDEMNED) ||
		    (ipst->ips_ndp4->ndp_g_hw_change > 0)) {
			/*
			 * src_nce has been deleted, or
			 * ip_arp_news is in the middle of
			 * flushing entries in the the nce.
			 * Fail the add, since we don't know
			 * if it is safe to copy the contents of
			 * src_nce
			 */
			DTRACE_PROBE2(nce__bad__src__nce,
			    nce_t *, src_nce, ill_t *, ill);
			mutex_exit(&src_nce->nce_lock);
			err = EINVAL;
			goto err_ret;
		}
		template = copyb(src_nce->nce_res_mp);
		mutex_exit(&src_nce->nce_lock);
		if (template == NULL) {
			err = ENOMEM;
			goto err_ret;
		}
	} else if (flags & NCE_F_BCAST) {
		/*
		 * broadcast nce.
		 */
		template = copyb(ill->ill_bcast_mp);
		if (template == NULL) {
			err = ENOMEM;
			goto err_ret;
		}
		state = ND_REACHABLE;
	} else if (ill->ill_net_type == IRE_IF_NORESOLVER) {
		/*
		 * NORESOLVER entries are always created in the REACHABLE
		 * state. We create a nce_res_mp with the IP nexthop address
		 * in the destination address in the DLPI hdr if the
		 * physical length is exactly 4 bytes.
		 *
		 * XXX not clear which drivers set ill_phys_addr_length to
		 * IP_ADDR_LEN.
		 */
		if (ill->ill_phys_addr_length == IP_ADDR_LEN) {
			template = ill_dlur_gen((uchar_t *)addr,
			    ill->ill_phys_addr_length,
			    ill->ill_sap, ill->ill_sap_length);
		} else {
			template = copyb(ill->ill_resolver_mp);
		}
		if (template == NULL) {
			err = ENOMEM;
			goto err_ret;
		}
		state = ND_REACHABLE;
	}
	nce->nce_fp_mp = NULL;
	nce->nce_res_mp = template;
	nce->nce_state = state;
	if (state == ND_REACHABLE) {
		nce->nce_last = TICK_TO_MSEC(lbolt64);
		nce->nce_init_time = TICK_TO_MSEC(lbolt64);
	} else {
		nce->nce_last = 0;
		if (state == ND_INITIAL)
			nce->nce_init_time = TICK_TO_MSEC(lbolt64);
	}

	ASSERT((nce->nce_res_mp == NULL && nce->nce_state == ND_INITIAL) ||
	    (nce->nce_res_mp != NULL && nce->nce_state == ND_REACHABLE));
	/*
	 * Atomically ensure that the ill is not CONDEMNED, before
	 * adding the NCE.
	 */
	mutex_enter(&ill->ill_lock);
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		mutex_exit(&ill->ill_lock);
		err = EINVAL;
		goto err_ret;
	}
	if ((nce->nce_next = *ncep) != NULL)
		nce->nce_next->nce_ptpn = &nce->nce_next;
	*ncep = nce;
	nce->nce_ptpn = ncep;
	*newnce = nce;
	/* This one is for nce being used by an active thread */
	NCE_REFHOLD(*newnce);

	/* Bump up the number of nce's referencing this ill */
	DTRACE_PROBE3(ill__incr__cnt, (ill_t *), ill,
	    (char *), "nce", (void *), nce);
	ill->ill_nce_cnt++;
	mutex_exit(&ill->ill_lock);
	DTRACE_PROBE1(ndp__add__v4, nce_t *, nce);
	return (0);
err_ret:
	freeb(mp);
	freemsg(template);
	return (err);
}

/*
 * ndp_walk routine to delete all entries that have a given destination or
 * gateway address and cached link layer (MAC) address.  This is used when ARP
 * informs us that a network-to-link-layer mapping may have changed.
 */
void
nce_delete_hw_changed(nce_t *nce, void *arg)
{
	nce_hw_map_t *hwm = arg;
	mblk_t *mp;
	dl_unitdata_req_t *dlu;
	uchar_t *macaddr;
	ill_t *ill;
	int saplen;
	ipaddr_t nce_addr;

	if (nce->nce_state != ND_REACHABLE)
		return;

	IN6_V4MAPPED_TO_IPADDR(&nce->nce_addr, nce_addr);
	if (nce_addr != hwm->hwm_addr)
		return;

	mutex_enter(&nce->nce_lock);
	if ((mp = nce->nce_res_mp) == NULL) {
		mutex_exit(&nce->nce_lock);
		return;
	}
	dlu = (dl_unitdata_req_t *)mp->b_rptr;
	macaddr = (uchar_t *)(dlu + 1);
	ill = nce->nce_ill;
	if ((saplen = ill->ill_sap_length) > 0)
		macaddr += saplen;
	else
		saplen = -saplen;

	/*
	 * If the hardware address is unchanged, then leave this one alone.
	 * Note that saplen == abs(saplen) now.
	 */
	if (hwm->hwm_hwlen == dlu->dl_dest_addr_length - saplen &&
	    bcmp(hwm->hwm_hwaddr, macaddr, hwm->hwm_hwlen) == 0) {
		mutex_exit(&nce->nce_lock);
		return;
	}
	mutex_exit(&nce->nce_lock);

	DTRACE_PROBE1(nce__hw__deleted, nce_t *, nce);
	ndp_delete(nce);
}

/*
 * This function verifies whether a given IPv4 address is potentially known to
 * the NCE subsystem.  If so, then ARP must not delete the corresponding ace_t,
 * so that it can continue to look for hardware changes on that address.
 */
boolean_t
ndp_lookup_ipaddr(in_addr_t addr, netstack_t *ns)
{
	nce_t		*nce;
	struct in_addr	nceaddr;
	ip_stack_t	*ipst = ns->netstack_ip;

	if (addr == INADDR_ANY)
		return (B_FALSE);

	mutex_enter(&ipst->ips_ndp4->ndp_g_lock);
	nce = *(nce_t **)NCE_HASH_PTR_V4(ipst, addr);
	for (; nce != NULL; nce = nce->nce_next) {
		/* Note that only v4 mapped entries are in the table. */
		IN6_V4MAPPED_TO_INADDR(&nce->nce_addr, &nceaddr);
		if (addr == nceaddr.s_addr &&
		    IN6_ARE_ADDR_EQUAL(&nce->nce_mask, &ipv6_all_ones)) {
			/* Single flag check; no lock needed */
			if (!(nce->nce_flags & NCE_F_CONDEMNED))
				break;
		}
	}
	mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
	return (nce != NULL);
}

/*
 * Wrapper around ipif_lookup_addr_exact_v6() that allows ND to work properly
 * with IPMP.  Specifically, since neighbor discovery is always done on
 * underlying interfaces (even for addresses owned by an IPMP interface), we
 * need to check for `v6addrp' on both `ill' and on the IPMP meta-interface
 * associated with `ill' (if it exists).
 */
static ipif_t *
ip_ndp_lookup_addr_v6(const in6_addr_t *v6addrp, ill_t *ill)
{
	ipif_t *ipif;
	ip_stack_t *ipst = ill->ill_ipst;

	ipif = ipif_lookup_addr_exact_v6(v6addrp, ill, ipst);
	if (ipif == NULL && IS_UNDER_IPMP(ill)) {
		if ((ill = ipmp_ill_hold_ipmp_ill(ill)) != NULL) {
			ipif = ipif_lookup_addr_exact_v6(v6addrp, ill, ipst);
			ill_refrele(ill);
		}
	}
	return (ipif);
}
