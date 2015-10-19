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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/mac.h>

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
#include <inet/sctp_ip.h>
#include <inet/ip_arp.h>
#include <inet/ip2mac_impl.h>

#define	ANNOUNCE_INTERVAL(isv6) \
	(isv6 ? ipst->ips_ip_ndp_unsolicit_interval : \
	ipst->ips_ip_arp_publish_interval)

#define	DEFENSE_INTERVAL(isv6) \
	(isv6 ? ipst->ips_ndp_defend_interval : \
	ipst->ips_arp_defend_interval)

/* Non-tunable probe interval, based on link capabilities */
#define	ILL_PROBE_INTERVAL(ill)	((ill)->ill_note_link ? 150 : 1500)

/*
 * The IPv4 Link Local address space is special; we do extra duplicate checking
 * there, as the entire assignment mechanism rests on random numbers.
 */
#define	IS_IPV4_LL_SPACE(ptr)	(((uchar_t *)ptr)[0] == 169 && \
				((uchar_t *)ptr)[1] == 254)

/*
 * NCE_EXTERNAL_FLAGS_MASK defines the set of ncec_flags that may be passed
 * in to the ncec*add* functions.
 *
 * NCE_F_AUTHORITY means that we ignore any incoming adverts for that
 * mapping (though DAD is performed for the mapping). NCE_F_PUBLISH means
 * that we will respond to requests for the protocol address.
 */
#define	NCE_EXTERNAL_FLAGS_MASK \
	(NCE_F_MYADDR | NCE_F_ISROUTER | NCE_F_NONUD | \
	NCE_F_ANYCAST | NCE_F_UNSOL_ADV | NCE_F_BCAST | NCE_F_MCAST | \
	NCE_F_AUTHORITY | NCE_F_PUBLISH | NCE_F_STATIC)

/*
 * Lock ordering:
 *
 *	ndp_g_lock -> ill_lock -> ncec_lock
 *
 * The ndp_g_lock protects the NCE hash (nce_hash_tbl, NCE_HASH_PTR) and
 * ncec_next.  ncec_lock protects the contents of the NCE (particularly
 * ncec_refcnt).
 */

static	void	nce_cleanup_list(ncec_t *ncec);
static	void 	nce_set_ll(ncec_t *ncec, uchar_t *ll_addr);
static	ncec_t	*ncec_lookup_illgrp(ill_t *, const in6_addr_t *,
    ncec_t *);
static	nce_t	*nce_lookup_addr(ill_t *, const in6_addr_t *);
static	int	nce_set_multicast_v6(ill_t *ill, const in6_addr_t *addr,
    uint16_t ncec_flags, nce_t **newnce);
static	int	nce_set_multicast_v4(ill_t *ill, const in_addr_t *dst,
    uint16_t ncec_flags, nce_t **newnce);
static	boolean_t	ndp_xmit(ill_t *ill, uint32_t operation,
    uint8_t *hwaddr, uint_t hwaddr_len, const in6_addr_t *sender,
    const in6_addr_t *target, int flag);
static void	ncec_refhold_locked(ncec_t *);
static boolean_t ill_defend_rate_limit(ill_t *, ncec_t *);
static	void	nce_queue_mp_common(ncec_t *, mblk_t *, boolean_t);
static	int	nce_add_common(ill_t *, uchar_t *, uint_t, const in6_addr_t *,
    uint16_t, uint16_t, nce_t **);
static nce_t *nce_add_impl(ill_t *, ncec_t *, nce_t *, mblk_t *);
static nce_t *nce_add(ill_t *, ncec_t *);
static void nce_inactive(nce_t *);
extern nce_t 	*nce_lookup(ill_t *, const in6_addr_t *);
static nce_t *nce_ill_lookup_then_add(ill_t *, ncec_t *);
static int	nce_add_v6(ill_t *, uchar_t *, uint_t, const in6_addr_t *,
    uint16_t, uint16_t, nce_t **);
static int	nce_add_v4(ill_t *, uchar_t *, uint_t, const in_addr_t *,
    uint16_t, uint16_t, nce_t **);
static int  nce_add_v6_postprocess(nce_t *);
static int  nce_add_v4_postprocess(nce_t *);
static ill_t *nce_resolve_src(ncec_t *, in6_addr_t *);
static clock_t nce_fuzz_interval(clock_t, boolean_t);
static void nce_resolv_ipmp_ok(ncec_t *);
static void nce_walk_common(ill_t *, pfi_t, void *);
static void nce_start_timer(ncec_t *, uint_t);
static nce_t *nce_fastpath_create(ill_t *, ncec_t *);
static void nce_fastpath_trigger(nce_t *);
static nce_t *nce_fastpath(ncec_t *, boolean_t, nce_t *);

#ifdef DEBUG
static void	ncec_trace_cleanup(const ncec_t *);
#endif

#define	NCE_HASH_PTR_V4(ipst, addr)					\
	(&((ipst)->ips_ndp4->nce_hash_tbl[IRE_ADDR_HASH(addr, NCE_TABLE_SIZE)]))

#define	NCE_HASH_PTR_V6(ipst, addr)				 \
	(&((ipst)->ips_ndp6->nce_hash_tbl[NCE_ADDR_HASH_V6(addr, \
		NCE_TABLE_SIZE)]))

extern kmem_cache_t *ncec_cache;
extern kmem_cache_t *nce_cache;

/*
 * Send out a IPv6 (unicast) or IPv4 (broadcast) DAD probe
 * If src_ill is not null, the ncec_addr is bound to src_ill. The
 * src_ill is ignored by nce_dad for IPv4 Neighbor Cache entries where
 * the probe is sent on the ncec_ill (in the non-IPMP case) or the
 * IPMP cast_ill (in the IPMP case).
 *
 * Note that the probe interval is based on the src_ill for IPv6, and
 * the ncec_xmit_interval for IPv4.
 */
static void
nce_dad(ncec_t *ncec, ill_t *src_ill, boolean_t send_probe)
{
	boolean_t dropped;
	uint32_t probe_interval;

	ASSERT(!(ncec->ncec_flags & NCE_F_MCAST));
	ASSERT(!(ncec->ncec_flags & NCE_F_BCAST));
	if (ncec->ncec_ipversion == IPV6_VERSION) {
		dropped = ndp_xmit(src_ill, ND_NEIGHBOR_SOLICIT,
		    ncec->ncec_lladdr, ncec->ncec_lladdr_length,
		    &ipv6_all_zeros, &ncec->ncec_addr, NDP_PROBE);
		probe_interval = ILL_PROBE_INTERVAL(src_ill);
	} else {
		/* IPv4 DAD delay the initial probe. */
		if (send_probe)
			dropped = arp_probe(ncec);
		else
			dropped = B_TRUE;
		probe_interval = nce_fuzz_interval(ncec->ncec_xmit_interval,
		    !send_probe);
	}
	if (!dropped) {
		mutex_enter(&ncec->ncec_lock);
		ncec->ncec_pcnt--;
		mutex_exit(&ncec->ncec_lock);
	}
	nce_restart_timer(ncec, probe_interval);
}

/*
 * Compute default flags to use for an advertisement of this ncec's address.
 */
static int
nce_advert_flags(const ncec_t *ncec)
{
	int flag = 0;

	if (ncec->ncec_flags & NCE_F_ISROUTER)
		flag |= NDP_ISROUTER;
	if (!(ncec->ncec_flags & NCE_F_ANYCAST))
		flag |= NDP_ORIDE;

	return (flag);
}

/*
 * NDP Cache Entry creation routine.
 * This routine must always be called with ndp6->ndp_g_lock held.
 */
int
nce_add_v6(ill_t *ill, uchar_t *hw_addr, uint_t hw_addr_len,
    const in6_addr_t *addr, uint16_t flags, uint16_t state, nce_t **newnce)
{
	int		err;
	nce_t		*nce;

	ASSERT(MUTEX_HELD(&ill->ill_ipst->ips_ndp6->ndp_g_lock));
	ASSERT(ill != NULL && ill->ill_isv6);

	err = nce_add_common(ill, hw_addr, hw_addr_len, addr, flags, state,
	    &nce);
	if (err != 0)
		return (err);
	ASSERT(newnce != NULL);
	*newnce = nce;
	return (err);
}

/*
 * Post-processing routine to be executed after nce_add_v6(). This function
 * triggers fastpath (if appropriate) and DAD on the newly added nce entry
 * and must be called without any locks held.
 */
int
nce_add_v6_postprocess(nce_t *nce)
{
	ncec_t		*ncec = nce->nce_common;
	boolean_t	dropped = B_FALSE;
	uchar_t		*hw_addr = ncec->ncec_lladdr;
	uint_t		hw_addr_len = ncec->ncec_lladdr_length;
	ill_t		*ill = ncec->ncec_ill;
	int		err = 0;
	uint16_t	flags = ncec->ncec_flags;
	ip_stack_t	*ipst = ill->ill_ipst;
	boolean_t	trigger_fastpath = B_TRUE;

	/*
	 * If the hw_addr is NULL, typically for ND_INCOMPLETE nces, then
	 * we call nce_fastpath as soon as the ncec is resolved in nce_process.
	 * We call nce_fastpath from nce_update if the link layer address of
	 * the peer changes from nce_update
	 */
	if (NCE_PUBLISH(ncec) || !NCE_ISREACHABLE(ncec) ||
	    (hw_addr == NULL && ill->ill_net_type != IRE_IF_NORESOLVER))
		trigger_fastpath = B_FALSE;

	if (trigger_fastpath)
		nce_fastpath_trigger(nce);
	if (NCE_PUBLISH(ncec) && ncec->ncec_state == ND_PROBE) {
		ill_t *hwaddr_ill;
		/*
		 * Unicast entry that needs DAD.
		 */
		if (IS_IPMP(ill)) {
			hwaddr_ill = ipmp_illgrp_find_ill(ill->ill_grp,
			    hw_addr, hw_addr_len);
		} else {
			hwaddr_ill = ill;
		}
		nce_dad(ncec, hwaddr_ill, B_TRUE);
		err = EINPROGRESS;
	} else if (flags & NCE_F_UNSOL_ADV) {
		/*
		 * We account for the transmit below by assigning one
		 * less than the ndd variable. Subsequent decrements
		 * are done in nce_timer.
		 */
		mutex_enter(&ncec->ncec_lock);
		ncec->ncec_unsolicit_count =
		    ipst->ips_ip_ndp_unsolicit_count - 1;
		mutex_exit(&ncec->ncec_lock);
		dropped = ndp_xmit(ill,
		    ND_NEIGHBOR_ADVERT,
		    hw_addr,
		    hw_addr_len,
		    &ncec->ncec_addr,	/* Source and target of the adv */
		    &ipv6_all_hosts_mcast, /* Destination of the packet */
		    nce_advert_flags(ncec));
		mutex_enter(&ncec->ncec_lock);
		if (dropped)
			ncec->ncec_unsolicit_count++;
		else
			ncec->ncec_last_time_defended = ddi_get_lbolt();
		if (ncec->ncec_unsolicit_count != 0) {
			nce_start_timer(ncec,
			    ipst->ips_ip_ndp_unsolicit_interval);
		}
		mutex_exit(&ncec->ncec_lock);
	}
	return (err);
}

/*
 * Atomically lookup and add (if needed) Neighbor Cache information for
 * an address.
 *
 * IPMP notes: the ncec for non-local (i.e., !NCE_MYADDR(ncec) addresses
 * are always added pointing at the ipmp_ill. Thus, when the ill passed
 * to nce_add_v6 is an under_ill (i.e., IS_UNDER_IPMP(ill)) two nce_t
 * entries will be created, both pointing at the same ncec_t. The nce_t
 * entries will have their nce_ill set to the ipmp_ill and the under_ill
 * respectively, with the ncec_t having its ncec_ill pointing at the ipmp_ill.
 * Local addresses are always created on the ill passed to nce_add_v6.
 */
int
nce_lookup_then_add_v6(ill_t *ill, uchar_t *hw_addr, uint_t hw_addr_len,
    const in6_addr_t *addr, uint16_t flags, uint16_t state, nce_t **newnce)
{
	int		err = 0;
	ip_stack_t	*ipst = ill->ill_ipst;
	nce_t		*nce, *upper_nce = NULL;
	ill_t		*in_ill = ill;
	boolean_t	need_ill_refrele = B_FALSE;

	if (flags & NCE_F_MCAST) {
		/*
		 * hw_addr will be figured out in nce_set_multicast_v6;
		 * caller has to select the cast_ill
		 */
		ASSERT(hw_addr == NULL);
		ASSERT(!IS_IPMP(ill));
		err = nce_set_multicast_v6(ill, addr, flags, newnce);
		return (err);
	}
	ASSERT(ill->ill_isv6);
	if (IS_UNDER_IPMP(ill) && !(flags & NCE_F_MYADDR)) {
		ill = ipmp_ill_hold_ipmp_ill(ill);
		if (ill == NULL)
			return (ENXIO);
		need_ill_refrele = B_TRUE;
	}

	mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
	nce = nce_lookup_addr(ill, addr);
	if (nce == NULL) {
		err = nce_add_v6(ill, hw_addr, hw_addr_len, addr, flags, state,
		    &nce);
	} else {
		err = EEXIST;
	}
	mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
	if (err == 0)
		err = nce_add_v6_postprocess(nce);
	if (in_ill != ill && nce != NULL) {
		nce_t *under_nce = NULL;

		/*
		 * in_ill was the under_ill. Try to create the under_nce.
		 * Hold the ill_g_lock to prevent changes to group membership
		 * until we are done.
		 */
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
		if (!IS_IN_SAME_ILLGRP(in_ill, ill)) {
			DTRACE_PROBE2(ill__not__in__group, nce_t *, nce,
			    ill_t *, ill);
			rw_exit(&ipst->ips_ill_g_lock);
			err = ENXIO;
			nce_refrele(nce);
			nce = NULL;
			goto bail;
		}
		under_nce = nce_fastpath_create(in_ill, nce->nce_common);
		if (under_nce == NULL) {
			rw_exit(&ipst->ips_ill_g_lock);
			err = EINVAL;
			nce_refrele(nce);
			nce = NULL;
			goto bail;
		}
		rw_exit(&ipst->ips_ill_g_lock);
		upper_nce = nce;
		nce = under_nce; /* will be returned to caller */
		if (NCE_ISREACHABLE(nce->nce_common))
			nce_fastpath_trigger(under_nce);
	}
	/* nce_refrele is deferred until the lock is dropped  */
	if (nce != NULL) {
		if (newnce != NULL)
			*newnce = nce;
		else
			nce_refrele(nce);
	}
bail:
	if (upper_nce != NULL)
		nce_refrele(upper_nce);
	if (need_ill_refrele)
		ill_refrele(ill);
	return (err);
}

/*
 * Remove all the CONDEMNED nces from the appropriate hash table.
 * We create a private list of NCEs, these may have ires pointing
 * to them, so the list will be passed through to clean up dependent
 * ires and only then we can do ncec_refrele() which can make NCE inactive.
 */
static void
nce_remove(ndp_g_t *ndp, ncec_t *ncec, ncec_t **free_nce_list)
{
	ncec_t *ncec1;
	ncec_t **ptpn;

	ASSERT(MUTEX_HELD(&ndp->ndp_g_lock));
	ASSERT(ndp->ndp_g_walker == 0);
	for (; ncec; ncec = ncec1) {
		ncec1 = ncec->ncec_next;
		mutex_enter(&ncec->ncec_lock);
		if (NCE_ISCONDEMNED(ncec)) {
			ptpn = ncec->ncec_ptpn;
			ncec1 = ncec->ncec_next;
			if (ncec1 != NULL)
				ncec1->ncec_ptpn = ptpn;
			*ptpn = ncec1;
			ncec->ncec_ptpn = NULL;
			ncec->ncec_next = NULL;
			ncec->ncec_next = *free_nce_list;
			*free_nce_list = ncec;
		}
		mutex_exit(&ncec->ncec_lock);
	}
}

/*
 * 1. Mark the entry CONDEMNED. This ensures that no new nce_lookup()
 *    will return this NCE. Also no new timeouts will
 *    be started (See nce_restart_timer).
 * 2. Cancel any currently running timeouts.
 * 3. If there is an ndp walker, return. The walker will do the cleanup.
 *    This ensures that walkers see a consistent list of NCEs while walking.
 * 4. Otherwise remove the NCE from the list of NCEs
 */
void
ncec_delete(ncec_t *ncec)
{
	ncec_t	**ptpn;
	ncec_t	*ncec1;
	int	ipversion = ncec->ncec_ipversion;
	ndp_g_t *ndp;
	ip_stack_t	*ipst = ncec->ncec_ipst;

	if (ipversion == IPV4_VERSION)
		ndp = ipst->ips_ndp4;
	else
		ndp = ipst->ips_ndp6;

	/* Serialize deletes */
	mutex_enter(&ncec->ncec_lock);
	if (NCE_ISCONDEMNED(ncec)) {
		/* Some other thread is doing the delete */
		mutex_exit(&ncec->ncec_lock);
		return;
	}
	/*
	 * Caller has a refhold. Also 1 ref for being in the list. Thus
	 * refcnt has to be >= 2
	 */
	ASSERT(ncec->ncec_refcnt >= 2);
	ncec->ncec_flags |= NCE_F_CONDEMNED;
	mutex_exit(&ncec->ncec_lock);

	/* Count how many condemned ires for kmem_cache callback */
	atomic_inc_32(&ipst->ips_num_nce_condemned);
	nce_fastpath_list_delete(ncec->ncec_ill, ncec, NULL);

	/* Complete any waiting callbacks */
	ncec_cb_dispatch(ncec);

	/*
	 * Cancel any running timer. Timeout can't be restarted
	 * since CONDEMNED is set. Can't hold ncec_lock across untimeout.
	 * Passing invalid timeout id is fine.
	 */
	if (ncec->ncec_timeout_id != 0) {
		(void) untimeout(ncec->ncec_timeout_id);
		ncec->ncec_timeout_id = 0;
	}

	mutex_enter(&ndp->ndp_g_lock);
	if (ncec->ncec_ptpn == NULL) {
		/*
		 * The last ndp walker has already removed this ncec from
		 * the list after we marked the ncec CONDEMNED and before
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
	 * Now remove the ncec from the list. nce_restart_timer won't restart
	 * the timer since it is marked CONDEMNED.
	 */
	ptpn = ncec->ncec_ptpn;
	ncec1 = ncec->ncec_next;
	if (ncec1 != NULL)
		ncec1->ncec_ptpn = ptpn;
	*ptpn = ncec1;
	ncec->ncec_ptpn = NULL;
	ncec->ncec_next = NULL;
	mutex_exit(&ndp->ndp_g_lock);

	/* Removed from ncec_ptpn/ncec_next list */
	ncec_refrele_notr(ncec);
}

void
ncec_inactive(ncec_t *ncec)
{
	mblk_t		**mpp;
	ill_t		*ill = ncec->ncec_ill;
	ip_stack_t	*ipst = ncec->ncec_ipst;

	ASSERT(ncec->ncec_refcnt == 0);
	ASSERT(MUTEX_HELD(&ncec->ncec_lock));

	/* Count how many condemned nces for kmem_cache callback */
	if (NCE_ISCONDEMNED(ncec))
		atomic_add_32(&ipst->ips_num_nce_condemned, -1);

	/* Free all allocated messages */
	mpp = &ncec->ncec_qd_mp;
	while (*mpp != NULL) {
		mblk_t  *mp;

		mp = *mpp;
		*mpp = mp->b_next;

		inet_freemsg(mp);
	}
	/*
	 * must have been cleaned up in ncec_delete
	 */
	ASSERT(list_is_empty(&ncec->ncec_cb));
	list_destroy(&ncec->ncec_cb);
	/*
	 * free the ncec_lladdr if one was allocated in nce_add_common()
	 */
	if (ncec->ncec_lladdr_length > 0)
		kmem_free(ncec->ncec_lladdr, ncec->ncec_lladdr_length);

#ifdef DEBUG
	ncec_trace_cleanup(ncec);
#endif

	mutex_enter(&ill->ill_lock);
	DTRACE_PROBE3(ill__decr__cnt, (ill_t *), ill,
	    (char *), "ncec", (void *), ncec);
	ill->ill_ncec_cnt--;
	ncec->ncec_ill = NULL;
	/*
	 * If the number of ncec's associated with this ill have dropped
	 * to zero, check whether we need to restart any operation that
	 * is waiting for this to happen.
	 */
	if (ILL_DOWN_OK(ill)) {
		/* ipif_ill_refrele_tail drops the ill_lock */
		ipif_ill_refrele_tail(ill);
	} else {
		mutex_exit(&ill->ill_lock);
	}

	mutex_destroy(&ncec->ncec_lock);
	kmem_cache_free(ncec_cache, ncec);
}

/*
 * ncec_walk routine.  Delete the ncec if it is associated with the ill
 * that is going away.  Always called as a writer.
 */
void
ncec_delete_per_ill(ncec_t *ncec, uchar_t *arg)
{
	if ((ncec != NULL) && ncec->ncec_ill == (ill_t *)arg) {
		ncec_delete(ncec);
	}
}

/*
 * Neighbor Cache cleanup logic for a list of ncec_t entries.
 */
static void
nce_cleanup_list(ncec_t *ncec)
{
	ncec_t *ncec_next;

	ASSERT(ncec != NULL);
	while (ncec != NULL) {
		ncec_next = ncec->ncec_next;
		ncec->ncec_next = NULL;

		/*
		 * It is possible for the last ndp walker (this thread)
		 * to come here after ncec_delete has marked the ncec CONDEMNED
		 * and before it has removed the ncec from the fastpath list
		 * or called untimeout. So we need to do it here. It is safe
		 * for both ncec_delete and this thread to do it twice or
		 * even simultaneously since each of the threads has a
		 * reference on the ncec.
		 */
		nce_fastpath_list_delete(ncec->ncec_ill, ncec, NULL);
		/*
		 * Cancel any running timer. Timeout can't be restarted
		 * since CONDEMNED is set. The ncec_lock can't be
		 * held across untimeout though passing invalid timeout
		 * id is fine.
		 */
		if (ncec->ncec_timeout_id != 0) {
			(void) untimeout(ncec->ncec_timeout_id);
			ncec->ncec_timeout_id = 0;
		}
		/* Removed from ncec_ptpn/ncec_next list */
		ncec_refrele_notr(ncec);
		ncec = ncec_next;
	}
}

/*
 * Restart DAD on given NCE.  Returns B_TRUE if DAD has been restarted.
 */
boolean_t
nce_restart_dad(ncec_t *ncec)
{
	boolean_t started;
	ill_t *ill, *hwaddr_ill;

	if (ncec == NULL)
		return (B_FALSE);
	ill = ncec->ncec_ill;
	mutex_enter(&ncec->ncec_lock);
	if (ncec->ncec_state == ND_PROBE) {
		mutex_exit(&ncec->ncec_lock);
		started = B_TRUE;
	} else if (ncec->ncec_state == ND_REACHABLE) {
		ASSERT(ncec->ncec_lladdr != NULL);
		ncec->ncec_state = ND_PROBE;
		ncec->ncec_pcnt = ND_MAX_UNICAST_SOLICIT;
		/*
		 * Slight cheat here: we don't use the initial probe delay
		 * for IPv4 in this obscure case.
		 */
		mutex_exit(&ncec->ncec_lock);
		if (IS_IPMP(ill)) {
			hwaddr_ill = ipmp_illgrp_find_ill(ill->ill_grp,
			    ncec->ncec_lladdr, ncec->ncec_lladdr_length);
		} else {
			hwaddr_ill = ill;
		}
		nce_dad(ncec, hwaddr_ill, B_TRUE);
		started = B_TRUE;
	} else {
		mutex_exit(&ncec->ncec_lock);
		started = B_FALSE;
	}
	return (started);
}

/*
 * IPv6 Cache entry lookup.  Try to find an ncec matching the parameters passed.
 * If one is found, the refcnt on the ncec will be incremented.
 */
ncec_t *
ncec_lookup_illgrp_v6(ill_t *ill, const in6_addr_t *addr)
{
	ncec_t		*ncec;
	ip_stack_t	*ipst = ill->ill_ipst;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	mutex_enter(&ipst->ips_ndp6->ndp_g_lock);

	/* Get head of v6 hash table */
	ncec = *((ncec_t **)NCE_HASH_PTR_V6(ipst, *addr));
	ncec = ncec_lookup_illgrp(ill, addr, ncec);
	mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
	rw_exit(&ipst->ips_ill_g_lock);
	return (ncec);
}
/*
 * IPv4 Cache entry lookup.  Try to find an ncec matching the parameters passed.
 * If one is found, the refcnt on the ncec will be incremented.
 */
ncec_t *
ncec_lookup_illgrp_v4(ill_t *ill, const in_addr_t *addr)
{
	ncec_t	*ncec = NULL;
	in6_addr_t addr6;
	ip_stack_t *ipst = ill->ill_ipst;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	mutex_enter(&ipst->ips_ndp4->ndp_g_lock);

	/* Get head of v4 hash table */
	ncec = *((ncec_t **)NCE_HASH_PTR_V4(ipst, *addr));
	IN6_IPADDR_TO_V4MAPPED(*addr, &addr6);
	ncec = ncec_lookup_illgrp(ill, &addr6, ncec);
	mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
	rw_exit(&ipst->ips_ill_g_lock);
	return (ncec);
}

/*
 * Cache entry lookup.  Try to find an ncec matching the parameters passed.
 * If an ncec is found, increment the hold count on that ncec.
 * The caller passes in the start of the appropriate hash table, and must
 * be holding the appropriate global lock (ndp_g_lock). In addition, since
 * this function matches ncec_t entries across the illgrp, the ips_ill_g_lock
 * must be held as reader.
 *
 * This function always matches across the ipmp group.
 */
ncec_t *
ncec_lookup_illgrp(ill_t *ill, const in6_addr_t *addr, ncec_t *ncec)
{
	ndp_g_t		*ndp;
	ip_stack_t	*ipst = ill->ill_ipst;

	if (ill->ill_isv6)
		ndp = ipst->ips_ndp6;
	else
		ndp = ipst->ips_ndp4;

	ASSERT(ill != NULL);
	ASSERT(MUTEX_HELD(&ndp->ndp_g_lock));
	if (IN6_IS_ADDR_UNSPECIFIED(addr))
		return (NULL);
	for (; ncec != NULL; ncec = ncec->ncec_next) {
		if (ncec->ncec_ill == ill ||
		    IS_IN_SAME_ILLGRP(ill, ncec->ncec_ill)) {
			if (IN6_ARE_ADDR_EQUAL(&ncec->ncec_addr, addr)) {
				mutex_enter(&ncec->ncec_lock);
				if (!NCE_ISCONDEMNED(ncec)) {
					ncec_refhold_locked(ncec);
					mutex_exit(&ncec->ncec_lock);
					break;
				}
				mutex_exit(&ncec->ncec_lock);
			}
		}
	}
	return (ncec);
}

/*
 * Find an nce_t on ill with nce_addr == addr. Lookup the nce_t
 * entries for ill only, i.e., when ill is part of an ipmp group,
 * nce_lookup_v4 will never try to match across the group.
 */
nce_t *
nce_lookup_v4(ill_t *ill, const in_addr_t *addr)
{
	nce_t *nce;
	in6_addr_t addr6;
	ip_stack_t *ipst = ill->ill_ipst;

	mutex_enter(&ipst->ips_ndp4->ndp_g_lock);
	IN6_IPADDR_TO_V4MAPPED(*addr, &addr6);
	nce = nce_lookup_addr(ill, &addr6);
	mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
	return (nce);
}

/*
 * Find an nce_t on ill with nce_addr == addr. Lookup the nce_t
 * entries for ill only, i.e., when ill is part of an ipmp group,
 * nce_lookup_v6 will never try to match across the group.
 */
nce_t *
nce_lookup_v6(ill_t *ill, const in6_addr_t *addr6)
{
	nce_t *nce;
	ip_stack_t *ipst = ill->ill_ipst;

	mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
	nce = nce_lookup_addr(ill, addr6);
	mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
	return (nce);
}

static nce_t *
nce_lookup_addr(ill_t *ill, const in6_addr_t *addr)
{
	nce_t *nce;

	ASSERT(ill != NULL);
#ifdef DEBUG
	if (ill->ill_isv6)
		ASSERT(MUTEX_HELD(&ill->ill_ipst->ips_ndp6->ndp_g_lock));
	else
		ASSERT(MUTEX_HELD(&ill->ill_ipst->ips_ndp4->ndp_g_lock));
#endif
	mutex_enter(&ill->ill_lock);
	nce = nce_lookup(ill, addr);
	mutex_exit(&ill->ill_lock);
	return (nce);
}


/*
 * Router turned to host.  We need to make sure that cached copies of the ncec
 * are not used for forwarding packets if they were derived from the default
 * route, and that the default route itself is removed, as  required by
 * section 7.2.5 of RFC 2461.
 *
 * Note that the ncec itself probably has valid link-layer information for the
 * nexthop, so that there is no reason to delete the ncec, as long as the
 * ISROUTER flag is turned off.
 */
static void
ncec_router_to_host(ncec_t *ncec)
{
	ire_t		*ire;
	ip_stack_t	*ipst = ncec->ncec_ipst;

	mutex_enter(&ncec->ncec_lock);
	ncec->ncec_flags &= ~NCE_F_ISROUTER;
	mutex_exit(&ncec->ncec_lock);

	ire = ire_ftable_lookup_v6(&ipv6_all_zeros, &ipv6_all_zeros,
	    &ncec->ncec_addr, IRE_DEFAULT, ncec->ncec_ill, ALL_ZONES, NULL,
	    MATCH_IRE_ILL | MATCH_IRE_TYPE | MATCH_IRE_GW, 0, ipst, NULL);
	if (ire != NULL) {
		ip_rts_rtmsg(RTM_DELETE, ire, 0, ipst);
		ire_delete(ire);
		ire_refrele(ire);
	}
}

/*
 * Process passed in parameters either from an incoming packet or via
 * user ioctl.
 */
void
nce_process(ncec_t *ncec, uchar_t *hw_addr, uint32_t flag, boolean_t is_adv)
{
	ill_t	*ill = ncec->ncec_ill;
	uint32_t hw_addr_len = ill->ill_phys_addr_length;
	boolean_t ll_updated = B_FALSE;
	boolean_t ll_changed;
	nce_t	*nce;

	ASSERT(ncec->ncec_ipversion == IPV6_VERSION);
	/*
	 * No updates of link layer address or the neighbor state is
	 * allowed, when the cache is in NONUD state.  This still
	 * allows for responding to reachability solicitation.
	 */
	mutex_enter(&ncec->ncec_lock);
	if (ncec->ncec_state == ND_INCOMPLETE) {
		if (hw_addr == NULL) {
			mutex_exit(&ncec->ncec_lock);
			return;
		}
		nce_set_ll(ncec, hw_addr);
		/*
		 * Update ncec state and send the queued packets
		 * back to ip this time ire will be added.
		 */
		if (flag & ND_NA_FLAG_SOLICITED) {
			nce_update(ncec, ND_REACHABLE, NULL);
		} else {
			nce_update(ncec, ND_STALE, NULL);
		}
		mutex_exit(&ncec->ncec_lock);
		nce = nce_fastpath(ncec, B_TRUE, NULL);
		nce_resolv_ok(ncec);
		if (nce != NULL)
			nce_refrele(nce);
		return;
	}
	ll_changed = nce_cmp_ll_addr(ncec, hw_addr, hw_addr_len);
	if (!is_adv) {
		/* If this is a SOLICITATION request only */
		if (ll_changed)
			nce_update(ncec, ND_STALE, hw_addr);
		mutex_exit(&ncec->ncec_lock);
		ncec_cb_dispatch(ncec);
		return;
	}
	if (!(flag & ND_NA_FLAG_OVERRIDE) && ll_changed) {
		/* If in any other state than REACHABLE, ignore */
		if (ncec->ncec_state == ND_REACHABLE) {
			nce_update(ncec, ND_STALE, NULL);
		}
		mutex_exit(&ncec->ncec_lock);
		ncec_cb_dispatch(ncec);
		return;
	} else {
		if (ll_changed) {
			nce_update(ncec, ND_UNCHANGED, hw_addr);
			ll_updated = B_TRUE;
		}
		if (flag & ND_NA_FLAG_SOLICITED) {
			nce_update(ncec, ND_REACHABLE, NULL);
		} else {
			if (ll_updated) {
				nce_update(ncec, ND_STALE, NULL);
			}
		}
		mutex_exit(&ncec->ncec_lock);
		if (!(flag & ND_NA_FLAG_ROUTER) && (ncec->ncec_flags &
		    NCE_F_ISROUTER)) {
			ncec_router_to_host(ncec);
		} else {
			ncec_cb_dispatch(ncec);
		}
	}
}

/*
 * Pass arg1 to the pfi supplied, along with each ncec in existence.
 * ncec_walk() places a REFHOLD on the ncec and drops the lock when
 * walking the hash list.
 */
void
ncec_walk_common(ndp_g_t *ndp, ill_t *ill, pfi_t pfi, void *arg1,
    boolean_t trace)
{
	ncec_t	*ncec;
	ncec_t	*ncec1;
	ncec_t	**ncep;
	ncec_t	*free_nce_list = NULL;

	mutex_enter(&ndp->ndp_g_lock);
	/* Prevent ncec_delete from unlink and free of NCE */
	ndp->ndp_g_walker++;
	mutex_exit(&ndp->ndp_g_lock);
	for (ncep = ndp->nce_hash_tbl;
	    ncep < A_END(ndp->nce_hash_tbl); ncep++) {
		for (ncec = *ncep; ncec != NULL; ncec = ncec1) {
			ncec1 = ncec->ncec_next;
			if (ill == NULL || ncec->ncec_ill == ill) {
				if (trace) {
					ncec_refhold(ncec);
					(*pfi)(ncec, arg1);
					ncec_refrele(ncec);
				} else {
					ncec_refhold_notr(ncec);
					(*pfi)(ncec, arg1);
					ncec_refrele_notr(ncec);
				}
			}
		}
	}
	mutex_enter(&ndp->ndp_g_lock);
	ndp->ndp_g_walker--;
	if (ndp->ndp_g_walker_cleanup && ndp->ndp_g_walker == 0) {
		/* Time to delete condemned entries */
		for (ncep = ndp->nce_hash_tbl;
		    ncep < A_END(ndp->nce_hash_tbl); ncep++) {
			ncec = *ncep;
			if (ncec != NULL) {
				nce_remove(ndp, ncec, &free_nce_list);
			}
		}
		ndp->ndp_g_walker_cleanup = B_FALSE;
	}

	mutex_exit(&ndp->ndp_g_lock);

	if (free_nce_list != NULL) {
		nce_cleanup_list(free_nce_list);
	}
}

/*
 * Walk everything.
 * Note that ill can be NULL hence can't derive the ipst from it.
 */
void
ncec_walk(ill_t *ill, pfi_t pfi, void *arg1, ip_stack_t *ipst)
{
	ncec_walk_common(ipst->ips_ndp4, ill, pfi, arg1, B_TRUE);
	ncec_walk_common(ipst->ips_ndp6, ill, pfi, arg1, B_TRUE);
}

/*
 * For each interface an entry is added for the unspecified multicast group.
 * Here that mapping is used to form the multicast cache entry for a particular
 * multicast destination.
 */
static int
nce_set_multicast_v6(ill_t *ill, const in6_addr_t *dst,
    uint16_t flags, nce_t **newnce)
{
	uchar_t		*hw_addr;
	int		err = 0;
	ip_stack_t	*ipst = ill->ill_ipst;
	nce_t		*nce;

	ASSERT(ill != NULL);
	ASSERT(ill->ill_isv6);
	ASSERT(!(IN6_IS_ADDR_UNSPECIFIED(dst)));

	mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
	nce = nce_lookup_addr(ill, dst);
	if (nce != NULL) {
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		goto done;
	}
	if (ill->ill_net_type == IRE_IF_RESOLVER) {
		/*
		 * For IRE_IF_RESOLVER a hardware mapping can be
		 * generated.
		 */
		hw_addr = kmem_alloc(ill->ill_nd_lla_len, KM_NOSLEEP);
		if (hw_addr == NULL) {
			mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
			return (ENOMEM);
		}
		ip_mcast_mapping(ill, (uchar_t *)dst, hw_addr);
	} else {
		/* No hw_addr is needed for IRE_IF_NORESOLVER. */
		hw_addr = NULL;
	}
	ASSERT((flags & NCE_F_MCAST) != 0);
	ASSERT((flags & NCE_F_NONUD) != 0);
	/* nce_state will be computed by nce_add_common() */
	err = nce_add_v6(ill, hw_addr, ill->ill_phys_addr_length, dst, flags,
	    ND_UNCHANGED, &nce);
	mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
	if (err == 0)
		err = nce_add_v6_postprocess(nce);
	if (hw_addr != NULL)
		kmem_free(hw_addr, ill->ill_nd_lla_len);
	if (err != 0) {
		ip1dbg(("nce_set_multicast_v6: create failed" "%d\n", err));
		return (err);
	}
done:
	ASSERT(nce->nce_common->ncec_state == ND_REACHABLE);
	if (newnce != NULL)
		*newnce = nce;
	else
		nce_refrele(nce);
	return (0);
}

/*
 * Return the link layer address, and any flags of a ncec.
 */
int
ndp_query(ill_t *ill, struct lif_nd_req *lnr)
{
	ncec_t		*ncec;
	in6_addr_t	*addr;
	sin6_t		*sin6;

	ASSERT(ill != NULL && ill->ill_isv6);
	sin6 = (sin6_t *)&lnr->lnr_addr;
	addr =  &sin6->sin6_addr;

	/*
	 * NOTE: if the ill is an IPMP interface, then match against the whole
	 * illgrp.  This e.g. allows in.ndpd to retrieve the link layer
	 * addresses for the data addresses on an IPMP interface even though
	 * ipif_ndp_up() created them with an ncec_ill of ipif_bound_ill.
	 */
	ncec = ncec_lookup_illgrp_v6(ill, addr);
	if (ncec == NULL)
		return (ESRCH);
	/* If no link layer address is available yet, return ESRCH */
	if (!NCE_ISREACHABLE(ncec)) {
		ncec_refrele(ncec);
		return (ESRCH);
	}
	lnr->lnr_hdw_len = ill->ill_phys_addr_length;
	bcopy(ncec->ncec_lladdr, (uchar_t *)&lnr->lnr_hdw_addr,
	    lnr->lnr_hdw_len);
	if (ncec->ncec_flags & NCE_F_ISROUTER)
		lnr->lnr_flags = NDF_ISROUTER_ON;
	if (ncec->ncec_flags & NCE_F_ANYCAST)
		lnr->lnr_flags |= NDF_ANYCAST_ON;
	if (ncec->ncec_flags & NCE_F_STATIC)
		lnr->lnr_flags |= NDF_STATIC;
	ncec_refrele(ncec);
	return (0);
}

/*
 * Finish setting up the Enable/Disable multicast for the driver.
 */
mblk_t *
ndp_mcastreq(ill_t *ill, const in6_addr_t *v6group, uint32_t hw_addr_len,
    uint32_t hw_addr_offset, mblk_t *mp)
{
	uchar_t		*hw_addr;
	ipaddr_t	v4group;
	uchar_t		*addr;

	ASSERT(ill->ill_net_type == IRE_IF_RESOLVER);
	if (IN6_IS_ADDR_V4MAPPED(v6group)) {
		IN6_V4MAPPED_TO_IPADDR(v6group, v4group);

		ASSERT(CLASSD(v4group));
		ASSERT(!(ill->ill_isv6));

		addr = (uchar_t *)&v4group;
	} else {
		ASSERT(IN6_IS_ADDR_MULTICAST(v6group));
		ASSERT(ill->ill_isv6);

		addr = (uchar_t *)v6group;
	}
	hw_addr = mi_offset_paramc(mp, hw_addr_offset, hw_addr_len);
	if (hw_addr == NULL) {
		ip0dbg(("ndp_mcastreq NULL hw_addr\n"));
		freemsg(mp);
		return (NULL);
	}

	ip_mcast_mapping(ill, addr, hw_addr);
	return (mp);
}

void
ip_ndp_resolve(ncec_t *ncec)
{
	in_addr_t	sender4 = INADDR_ANY;
	in6_addr_t	sender6 = ipv6_all_zeros;
	ill_t		*src_ill;
	uint32_t	ms;

	src_ill = nce_resolve_src(ncec, &sender6);
	if (src_ill == NULL) {
		/* Make sure we try again later */
		ms = ncec->ncec_ill->ill_reachable_retrans_time;
		nce_restart_timer(ncec, (clock_t)ms);
		return;
	}
	if (ncec->ncec_ipversion == IPV4_VERSION)
		IN6_V4MAPPED_TO_IPADDR(&sender6, sender4);
	mutex_enter(&ncec->ncec_lock);
	if (ncec->ncec_ipversion == IPV6_VERSION)
		ms = ndp_solicit(ncec, sender6, src_ill);
	else
		ms = arp_request(ncec, sender4, src_ill);
	mutex_exit(&ncec->ncec_lock);
	if (ms == 0) {
		if (ncec->ncec_state != ND_REACHABLE) {
			if (ncec->ncec_ipversion == IPV6_VERSION)
				ndp_resolv_failed(ncec);
			else
				arp_resolv_failed(ncec);
			ASSERT((ncec->ncec_flags & NCE_F_STATIC) == 0);
			nce_make_unreachable(ncec);
			ncec_delete(ncec);
		}
	} else {
		nce_restart_timer(ncec, (clock_t)ms);
	}
done:
	ill_refrele(src_ill);
}

/*
 * Send an IPv6 neighbor solicitation.
 * Returns number of milliseconds after which we should either rexmit or abort.
 * Return of zero means we should abort.
 * The caller holds the ncec_lock to protect ncec_qd_mp and ncec_rcnt.
 * The optional source address is used as a hint to ndp_solicit for
 * which source to use in the packet.
 *
 * NOTE: This routine drops ncec_lock (and later reacquires it) when sending
 * the packet.
 */
uint32_t
ndp_solicit(ncec_t *ncec, in6_addr_t src, ill_t *ill)
{
	in6_addr_t	dst;
	boolean_t	dropped = B_FALSE;

	ASSERT(ncec->ncec_ipversion == IPV6_VERSION);
	ASSERT(MUTEX_HELD(&ncec->ncec_lock));

	if (ncec->ncec_rcnt == 0)
		return (0);

	dst = ncec->ncec_addr;
	ncec->ncec_rcnt--;
	mutex_exit(&ncec->ncec_lock);
	dropped = ndp_xmit(ill, ND_NEIGHBOR_SOLICIT, ill->ill_phys_addr,
	    ill->ill_phys_addr_length, &src, &dst, 0);
	mutex_enter(&ncec->ncec_lock);
	if (dropped)
		ncec->ncec_rcnt++;
	return (ncec->ncec_ill->ill_reachable_retrans_time);
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
void
ip_addr_recover(ipsq_t *ipsq, queue_t *rq, mblk_t *mp, void *dummy_arg)
{
	ill_t	*ill = rq->q_ptr;
	ipif_t	*ipif;
	in6_addr_t *addr6 = (in6_addr_t *)mp->b_rptr;
	in_addr_t *addr4 = (in_addr_t *)mp->b_rptr;
	boolean_t addr_equal;

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		/*
		 * We do not support recovery of proxy ARP'd interfaces,
		 * because the system lacks a complete proxy ARP mechanism.
		 */
		if (ill->ill_isv6) {
			addr_equal = IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6lcl_addr,
			    addr6);
		} else {
			addr_equal = (ipif->ipif_lcl_addr == *addr4);
		}

		if ((ipif->ipif_flags & IPIF_POINTOPOINT) || !addr_equal)
			continue;

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

		if (ill->ill_isv6) {
			VERIFY(ipif_ndp_up(ipif, B_TRUE) != EINPROGRESS);
			(void) ipif_up_done_v6(ipif);
		} else {
			VERIFY(ipif_arp_up(ipif, Res_act_initial, B_TRUE) !=
			    EINPROGRESS);
			(void) ipif_up_done(ipif);
		}
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
void
ipif_dup_recovery(void *arg)
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

	ipif_do_recovery(ipif);
}

/*
 * Perform interface recovery by forcing the duplicate interfaces up and
 * allowing the system to determine which ones should stay up.
 *
 * Called both by recovery timer expiry and link-up notification.
 */
void
ipif_do_recovery(ipif_t *ipif)
{
	ill_t *ill = ipif->ipif_ill;
	mblk_t *mp;
	ip_stack_t *ipst = ill->ill_ipst;
	size_t mp_size;

	if (ipif->ipif_isv6)
		mp_size = sizeof (ipif->ipif_v6lcl_addr);
	else
		mp_size = sizeof (ipif->ipif_lcl_addr);
	mp = allocb(mp_size, BPRI_MED);
	if (mp == NULL) {
		mutex_enter(&ill->ill_lock);
		if (ipst->ips_ip_dup_recovery > 0 &&
		    ipif->ipif_recovery_id == 0 &&
		    !(ipif->ipif_state_flags & IPIF_CONDEMNED)) {
			ipif->ipif_recovery_id = timeout(ipif_dup_recovery,
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

		if (ipif->ipif_isv6) {
			bcopy(&ipif->ipif_v6lcl_addr, mp->b_rptr,
			    sizeof (ipif->ipif_v6lcl_addr));
		} else  {
			bcopy(&ipif->ipif_lcl_addr, mp->b_rptr,
			    sizeof (ipif->ipif_lcl_addr));
		}
		ill_refhold(ill);
		qwriter_ip(ill, ill->ill_rq, mp, ip_addr_recover, NEW_OP,
		    B_FALSE);
	}
}

/*
 * Find the MAC and IP addresses in an NA/NS message.
 */
static void
ip_ndp_find_addresses(mblk_t *mp, ip_recv_attr_t *ira, ill_t *ill,
    in6_addr_t *targp, uchar_t **haddr, uint_t *haddrlenp)
{
	icmp6_t *icmp6 = (icmp6_t *)(mp->b_rptr + IPV6_HDR_LEN);
	nd_neighbor_solicit_t *ns = (nd_neighbor_solicit_t *)icmp6;
	uchar_t *addr;
	int alen;

	/* icmp_inbound_v6 ensures this */
	ASSERT(ira->ira_flags & IRAF_L2SRC_SET);

	addr = ira->ira_l2src;
	alen = ill->ill_phys_addr_length;
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
	uchar_t	*haddr;
	uint_t	haddrlen;
	ip_stack_t *ipst = ill->ill_ipst;
	in6_addr_t targ;
	ip_recv_attr_t iras;
	mblk_t	*attrmp;

	attrmp = mp;
	mp = mp->b_cont;
	attrmp->b_cont = NULL;
	if (!ip_recv_attr_from_mblk(attrmp, &iras)) {
		/* The ill or ip_stack_t disappeared on us */
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ip_recv_attr_from_mblk", mp, ill);
		freemsg(mp);
		ira_cleanup(&iras, B_TRUE);
		return;
	}

	ASSERT(ill == iras.ira_rill);

	ip_ndp_find_addresses(mp, &iras, ill, &targ, &haddr, &haddrlen);
	if (haddr != NULL && haddrlen == ill->ill_phys_addr_length) {
		/*
		 * Ignore conflicts generated by misbehaving switches that
		 * just reflect our own messages back to us.  For IPMP, we may
		 * see reflections across any ill in the illgrp.
		 *
		 * RFC2462 and revisions tried to detect both the case
		 * when a statically configured IPv6 address is a duplicate,
		 * and the case when the L2 address itself is a duplicate. The
		 * later is important because, with stateles address autoconf,
		 * if the L2 address is a duplicate, the resulting IPv6
		 * address(es) would also be duplicates. We rely on DAD of the
		 * IPv6 address itself to detect the latter case.
		 */
		/* For an under ill_grp can change under lock */
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
		if (bcmp(haddr, ill->ill_phys_addr, haddrlen) == 0 ||
		    IS_UNDER_IPMP(ill) &&
		    ipmp_illgrp_find_ill(ill->ill_grp, haddr,
		    haddrlen) != NULL) {
			rw_exit(&ipst->ips_ill_g_lock);
			goto ignore_conflict;
		}
		rw_exit(&ipst->ips_ill_g_lock);
	}

	/*
	 * Look up the appropriate ipif.
	 */
	ipif = ipif_lookup_addr_v6(&targ, ill, ALL_ZONES, ipst);
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
	(void) ipif_down_tail(ipif);
	mutex_enter(&ill->ill_lock);
	if (!(ipif->ipif_flags & (IPIF_DHCPRUNNING|IPIF_TEMPORARY)) &&
	    ill->ill_net_type == IRE_IF_RESOLVER &&
	    !(ipif->ipif_state_flags & IPIF_CONDEMNED) &&
	    ipst->ips_ip_dup_recovery > 0) {
		ASSERT(ipif->ipif_recovery_id == 0);
		ipif->ipif_recovery_id = timeout(ipif_dup_recovery,
		    ipif, MSEC_TO_TICK(ipst->ips_ip_dup_recovery));
	}
	mutex_exit(&ill->ill_lock);
	ipif_refrele(ipif);

ignore_conflict:
	freemsg(mp);
	ira_cleanup(&iras, B_TRUE);
}

/*
 * Handle failure by tearing down the ipifs with the specified address.  Note
 * that tearing down the ipif also means deleting the ncec through ipif_down, so
 * it's not possible to do recovery by just restarting the ncec timer.  Instead,
 * we start a timer on the ipif.
 * Caller has to free mp;
 */
static void
ndp_failure(mblk_t *mp, ip_recv_attr_t *ira)
{
	const uchar_t	*haddr;
	ill_t		*ill = ira->ira_rill;

	/*
	 * Ignore conflicts generated by misbehaving switches that just
	 * reflect our own messages back to us.
	 */

	/* icmp_inbound_v6 ensures this */
	ASSERT(ira->ira_flags & IRAF_L2SRC_SET);
	haddr = ira->ira_l2src;
	if (haddr != NULL &&
	    bcmp(haddr, ill->ill_phys_addr, ill->ill_phys_addr_length) == 0) {
		return;
	}

	if ((mp = copymsg(mp)) != NULL) {
		mblk_t	*attrmp;

		attrmp = ip_recv_attr_to_mblk(ira);
		if (attrmp == NULL) {
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, ill);
			freemsg(mp);
		} else {
			ASSERT(attrmp->b_cont == NULL);
			attrmp->b_cont = mp;
			mp = attrmp;
			ill_refhold(ill);
			qwriter_ip(ill, ill->ill_rq, mp, ip_ndp_excl, NEW_OP,
			    B_FALSE);
		}
	}
}

/*
 * Handle a discovered conflict: some other system is advertising that it owns
 * one of our IP addresses.  We need to defend ourselves, or just shut down the
 * interface.
 *
 * Handles both IPv4 and IPv6
 */
boolean_t
ip_nce_conflict(mblk_t *mp, ip_recv_attr_t *ira, ncec_t *ncec)
{
	ipif_t		*ipif;
	clock_t		now;
	uint_t		maxdefense;
	uint_t		defs;
	ill_t		*ill = ira->ira_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint32_t	elapsed;
	boolean_t	isv6 = ill->ill_isv6;
	ipaddr_t	ncec_addr;

	if (isv6) {
		ipif = ipif_lookup_addr_v6(&ncec->ncec_addr, ill, ALL_ZONES,
		    ipst);
	} else {
		if (arp_no_defense) {
			/*
			 * Yes, there is a conflict, but no, we do not
			 * defend ourself.
			 */
			return (B_TRUE);
		}
		IN6_V4MAPPED_TO_IPADDR(&ncec->ncec_addr, ncec_addr);
		ipif = ipif_lookup_addr(ncec_addr, ill, ALL_ZONES,
		    ipst);
	}
	if (ipif == NULL)
		return (B_FALSE);

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
	now = ddi_get_lbolt();
	elapsed = (drv_hztousec(now - ncec->ncec_last_time_defended))/1000000;
	mutex_enter(&ncec->ncec_lock);
	if ((defs = ncec->ncec_defense_count) > 0 &&
	    elapsed > ipst->ips_ip_defend_interval) {
		/*
		 * ip_defend_interval has elapsed.
		 * reset the defense count.
		 */
		ncec->ncec_defense_count = defs = 0;
	}
	ncec->ncec_defense_count++;
	ncec->ncec_last_time_defended = now;
	mutex_exit(&ncec->ncec_lock);
	ipif_refrele(ipif);

	/*
	 * If we've defended ourselves too many times already, then give up and
	 * tear down the interface(s) using this address.
	 * Otherwise, caller has to defend by sending out an announce.
	 */
	if (defs >= maxdefense) {
		if (isv6)
			ndp_failure(mp, ira);
		else
			arp_failure(mp, ira);
	} else {
		return (B_TRUE); /* caller must defend this address */
	}
	return (B_FALSE);
}

/*
 * Handle reception of Neighbor Solicitation messages.
 */
static void
ndp_input_solicit(mblk_t *mp, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill, *under_ill;
	nd_neighbor_solicit_t *ns;
	uint32_t	hlen = ill->ill_phys_addr_length;
	uchar_t		*haddr = NULL;
	icmp6_t		*icmp_nd;
	ip6_t		*ip6h;
	ncec_t		*our_ncec = NULL;
	in6_addr_t	target;
	in6_addr_t	src;
	int		len;
	int		flag = 0;
	nd_opt_hdr_t	*opt = NULL;
	boolean_t	bad_solicit = B_FALSE;
	mib2_ipv6IfIcmpEntry_t	*mib = ill->ill_icmp6_mib;
	boolean_t	need_ill_refrele = B_FALSE;

	ip6h = (ip6_t *)mp->b_rptr;
	icmp_nd = (icmp6_t *)(mp->b_rptr + IPV6_HDR_LEN);
	len = mp->b_wptr - mp->b_rptr - IPV6_HDR_LEN;
	src = ip6h->ip6_src;
	ns = (nd_neighbor_solicit_t *)icmp_nd;
	target = ns->nd_ns_target;
	if (IN6_IS_ADDR_MULTICAST(&target) || IN6_IS_ADDR_V4MAPPED(&target) ||
	    IN6_IS_ADDR_LOOPBACK(&target)) {
		if (ip_debug > 2) {
			/* ip1dbg */
			pr_addr_dbg("ndp_input_solicit: Martian Target %s\n",
			    AF_INET6, &target);
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
	our_ncec = ncec_lookup_illgrp_v6(ill, &target);
	/*
	 * If this is a valid Solicitation for an address we are publishing,
	 * then a PUBLISH entry should exist in the cache
	 */
	if (our_ncec == NULL || !NCE_PUBLISH(our_ncec)) {
		ip1dbg(("ndp_input_solicit: Wrong target in NS?!"
		    "ifname=%s ", ill->ill_name));
		if (ip_debug > 2) {
			/* ip1dbg */
			pr_addr_dbg(" dst %s\n", AF_INET6, &target);
		}
		if (our_ncec == NULL)
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
				ip1dbg(("ndp_input_advert: bad SLLA\n"));
				bad_solicit = B_TRUE;
				goto done;
			}
		}
	}

	/* If sending directly to peer, set the unicast flag */
	if (!IN6_IS_ADDR_MULTICAST(&ip6h->ip6_dst))
		flag |= NDP_UNICAST;

	/*
	 * Create/update the entry for the soliciting node on the ipmp_ill.
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
		if (our_ncec->ncec_state == ND_PROBE)
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

		under_ill = ill;
		if (IS_UNDER_IPMP(under_ill)) {
			ill = ipmp_ill_hold_ipmp_ill(under_ill);
			if (ill == NULL)
				ill = under_ill;
			else
				need_ill_refrele = B_TRUE;
		}
		err = nce_lookup_then_add_v6(ill,
		    haddr, hlen,
		    &src,	/* Soliciting nodes address */
		    0,
		    ND_STALE,
		    &nnce);

		if (need_ill_refrele) {
			ill_refrele(ill);
			ill = under_ill;
			need_ill_refrele =  B_FALSE;
		}
		switch (err) {
		case 0:
			/* done with this entry */
			nce_refrele(nnce);
			break;
		case EEXIST:
			/*
			 * B_FALSE indicates this is not an an advertisement.
			 */
			nce_process(nnce->nce_common, haddr, 0, B_FALSE);
			nce_refrele(nnce);
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
		if (our_ncec->ncec_state == ND_PROBE) {
			/*
			 * Internally looped-back probes will have
			 * IRAF_L2SRC_LOOPBACK set so we can ignore our own
			 * transmissions.
			 */
			if (!(ira->ira_flags & IRAF_L2SRC_LOOPBACK)) {
				/*
				 * If someone else is probing our address, then
				 * we've crossed wires.  Declare failure.
				 */
				ndp_failure(mp, ira);
			}
			goto done;
		}
		/*
		 * This is a DAD probe.  Multicast the advertisement to the
		 * all-nodes address.
		 */
		src = ipv6_all_hosts_mcast;
	}
	flag |= nce_advert_flags(our_ncec);
	(void) ndp_xmit(ill,
	    ND_NEIGHBOR_ADVERT,
	    our_ncec->ncec_lladdr,
	    our_ncec->ncec_lladdr_length,
	    &target,	/* Source and target of the advertisement pkt */
	    &src,	/* IP Destination (source of original pkt) */
	    flag);
done:
	if (bad_solicit)
		BUMP_MIB(mib, ipv6IfIcmpInBadNeighborSolicitations);
	if (our_ncec != NULL)
		ncec_refrele(our_ncec);
}

/*
 * Handle reception of Neighbor Solicitation messages
 */
void
ndp_input_advert(mblk_t *mp, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_ill;
	nd_neighbor_advert_t *na;
	uint32_t	hlen = ill->ill_phys_addr_length;
	uchar_t		*haddr = NULL;
	icmp6_t		*icmp_nd;
	ip6_t		*ip6h;
	ncec_t		*dst_ncec = NULL;
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
	if (IN6_IS_ADDR_MULTICAST(&target) || IN6_IS_ADDR_V4MAPPED(&target) ||
	    IN6_IS_ADDR_LOOPBACK(&target)) {
		if (ip_debug > 2) {
			/* ip1dbg */
			pr_addr_dbg("ndp_input_solicit: Martian Target %s\n",
			    AF_INET6, &target);
		}
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
	if ((dst_ncec = ncec_lookup_illgrp_v6(ill, &target)) == NULL)
		return;

	if (NCE_PUBLISH(dst_ncec)) {
		/*
		 * Someone just advertised an addresses that we publish. First,
		 * check it it was us -- if so, we can safely ignore it.
		 * We don't get the haddr from the ira_l2src because, in the
		 * case that the packet originated from us, on an IPMP group,
		 * the ira_l2src may would be the link-layer address of the
		 * cast_ill used to send the packet, which may not be the same
		 * as the dst_ncec->ncec_lladdr of the address.
		 */
		if (haddr != NULL) {
			if (ira->ira_flags & IRAF_L2SRC_LOOPBACK)
				goto out;

			if (!nce_cmp_ll_addr(dst_ncec, haddr, hlen))
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
		 */
		if (dst_ncec->ncec_state == ND_PROBE) {
			ndp_failure(mp, ira);
		} else {
			if (ip_nce_conflict(mp, ira, dst_ncec)) {
				char hbuf[MAC_STR_LEN];
				char sbuf[INET6_ADDRSTRLEN];

				cmn_err(CE_WARN,
				    "node '%s' is using %s on %s",
				    inet_ntop(AF_INET6, &target, sbuf,
				    sizeof (sbuf)),
				    haddr == NULL ? "<none>" :
				    mac_colon_addr(haddr, hlen, hbuf,
				    sizeof (hbuf)), ill->ill_name);
				/*
				 * RFC 4862, Section 5.4.4 does not mandate
				 * any specific behavior when an NA matches
				 * a non-tentative address assigned to the
				 * receiver. We make the choice of defending
				 * our address, based on the assumption that
				 * the sender has not detected the Duplicate.
				 *
				 * ncec_last_time_defended has been adjusted
				 * in ip_nce_conflict()
				 */
				(void) ndp_announce(dst_ncec);
			}
		}
	} else {
		if (na->nd_na_flags_reserved & ND_NA_FLAG_ROUTER)
			dst_ncec->ncec_flags |= NCE_F_ISROUTER;

		/* B_TRUE indicates this an advertisement */
		nce_process(dst_ncec, haddr, na->nd_na_flags_reserved, B_TRUE);
	}
out:
	ncec_refrele(dst_ncec);
}

/*
 * Process NDP neighbor solicitation/advertisement messages.
 * The checksum has already checked o.k before reaching here.
 * Information about the datalink header is contained in ira_l2src, but
 * that should be ignored for loopback packets.
 */
void
ndp_input(mblk_t *mp, ip_recv_attr_t *ira)
{
	ill_t		*ill = ira->ira_rill;
	icmp6_t		*icmp_nd;
	ip6_t		*ip6h;
	int		len;
	mib2_ipv6IfIcmpEntry_t	*mib = ill->ill_icmp6_mib;
	ill_t		*orig_ill = NULL;

	/*
	 * Since ira_ill is where the IRE_LOCAL was hosted we use ira_rill
	 * and make it be the IPMP upper so avoid being confused by a packet
	 * addressed to a unicast address on a different ill.
	 */
	if (IS_UNDER_IPMP(ill)) {
		orig_ill = ill;
		ill = ipmp_ill_hold_ipmp_ill(orig_ill);
		if (ill == NULL) {
			ill = orig_ill;
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards - IPMP ill",
			    mp, ill);
			freemsg(mp);
			return;
		}
		ASSERT(ill != orig_ill);
		orig_ill = ira->ira_ill;
		ira->ira_ill = ill;
		mib = ill->ill_icmp6_mib;
	}
	if (!pullupmsg(mp, -1)) {
		ip1dbg(("ndp_input: pullupmsg failed\n"));
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards - pullupmsg", mp, ill);
		goto done;
	}
	ip6h = (ip6_t *)mp->b_rptr;
	if (ip6h->ip6_hops != IPV6_MAX_HOPS) {
		ip1dbg(("ndp_input: hoplimit != IPV6_MAX_HOPS\n"));
		ip_drop_input("ipv6IfIcmpBadHoplimit", mp, ill);
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
		ip_drop_input("Wrong next header", mp, ill);
		BUMP_MIB(mib, ipv6IfIcmpInErrors);
		goto done;
	}
	icmp_nd = (icmp6_t *)(mp->b_rptr + IPV6_HDR_LEN);
	ASSERT(icmp_nd->icmp6_type == ND_NEIGHBOR_SOLICIT ||
	    icmp_nd->icmp6_type == ND_NEIGHBOR_ADVERT);
	if (icmp_nd->icmp6_code != 0) {
		ip1dbg(("ndp_input: icmp6 code != 0 \n"));
		ip_drop_input("code non-zero", mp, ill);
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
		ip_drop_input("packet too short", mp, ill);
		BUMP_MIB(mib, ipv6IfIcmpInErrors);
		goto done;
	}
	if (icmp_nd->icmp6_type == ND_NEIGHBOR_SOLICIT) {
		ndp_input_solicit(mp, ira);
	} else {
		ndp_input_advert(mp, ira);
	}
done:
	freemsg(mp);
	if (orig_ill != NULL) {
		ill_refrele(ill);
		ira->ira_ill = orig_ill;
	}
}

/*
 * ndp_xmit is called to form and transmit a ND solicitation or
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
ndp_xmit(ill_t *ill, uint32_t operation, uint8_t *hw_addr, uint_t hw_addr_len,
    const in6_addr_t *sender, const in6_addr_t *target, int flag)
{
	uint32_t	len;
	icmp6_t 	*icmp6;
	mblk_t		*mp;
	ip6_t		*ip6h;
	nd_opt_hdr_t	*opt;
	uint_t		plen;
	zoneid_t	zoneid = GLOBAL_ZONEID;
	ill_t		*hwaddr_ill = ill;
	ip_xmit_attr_t	ixas;
	ip_stack_t	*ipst = ill->ill_ipst;
	boolean_t	need_refrele = B_FALSE;
	boolean_t	probe = B_FALSE;

	if (IS_UNDER_IPMP(ill)) {
		probe = ipif_lookup_testaddr_v6(ill, sender, NULL);
		/*
		 * We send non-probe packets on the upper IPMP interface.
		 * ip_output_simple() will use cast_ill for sending any
		 * multicast packets. Note that we can't follow the same
		 * logic for probe packets because all interfaces in the ipmp
		 * group may have failed, so that we really want to only try
		 * to send the ND packet on the ill corresponding to the src
		 * address.
		 */
		if (!probe) {
			ill = ipmp_ill_hold_ipmp_ill(ill);
			if (ill != NULL)
				need_refrele = B_TRUE;
			else
				ill = hwaddr_ill;
		}
	}

	/*
	 * If we have a unspecified source(sender) address, select a
	 * proper source address for the solicitation here itself so
	 * that we can initialize the h/w address correctly.
	 *
	 * If the sender is specified then we use this address in order
	 * to lookup the zoneid before calling ip_output_v6(). This is to
	 * enable unicast ND_NEIGHBOR_ADVERT packets to be routed correctly
	 * by IP (we cannot guarantee that the global zone has an interface
	 * route to the destination).
	 *
	 * Note that the NA never comes here with the unspecified source
	 * address.
	 */

	/*
	 * Probes will have unspec src at this point.
	 */
	if (!(IN6_IS_ADDR_UNSPECIFIED(sender))) {
		zoneid = ipif_lookup_addr_zoneid_v6(sender, ill, ipst);
		/*
		 * It's possible for ipif_lookup_addr_zoneid_v6() to return
		 * ALL_ZONES if it cannot find a matching ipif for the address
		 * we are trying to use. In this case we err on the side of
		 * trying to send the packet by defaulting to the GLOBAL_ZONEID.
		 */
		if (zoneid == ALL_ZONES)
			zoneid = GLOBAL_ZONEID;
	}

	plen = (sizeof (nd_opt_hdr_t) + hw_addr_len + 7) / 8;
	len = IPV6_HDR_LEN + sizeof (nd_neighbor_advert_t) + plen * 8;
	mp = allocb(len,  BPRI_LO);
	if (mp == NULL) {
		if (need_refrele)
			ill_refrele(ill);
		return (B_TRUE);
	}

	bzero((char *)mp->b_rptr, len);
	mp->b_wptr = mp->b_rptr + len;

	bzero(&ixas, sizeof (ixas));
	ixas.ixa_flags = IXAF_SET_ULP_CKSUM | IXAF_NO_HW_CKSUM;

	ixas.ixa_ifindex = ill->ill_phyint->phyint_ifindex;
	ixas.ixa_ipst = ipst;
	ixas.ixa_cred = kcred;
	ixas.ixa_cpid = NOPID;
	ixas.ixa_tsl = NULL;
	ixas.ixa_zoneid = zoneid;

	ip6h = (ip6_t *)mp->b_rptr;
	ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	ip6h->ip6_plen = htons(len - IPV6_HDR_LEN);
	ip6h->ip6_nxt = IPPROTO_ICMPV6;
	ip6h->ip6_hops = IPV6_MAX_HOPS;
	ixas.ixa_multicast_ttl = ip6h->ip6_hops;
	ip6h->ip6_dst = *target;
	icmp6 = (icmp6_t *)&ip6h[1];

	if (hw_addr_len != 0) {
		opt = (nd_opt_hdr_t *)((uint8_t *)ip6h + IPV6_HDR_LEN +
		    sizeof (nd_neighbor_advert_t));
	} else {
		opt = NULL;
	}
	if (operation == ND_NEIGHBOR_SOLICIT) {
		nd_neighbor_solicit_t *ns = (nd_neighbor_solicit_t *)icmp6;

		if (opt != NULL && !(flag & NDP_PROBE)) {
			/*
			 * Note that we don't send out SLLA for ND probes
			 * per RFC 4862, even though we do send out the src
			 * haddr for IPv4 DAD probes, even though both IPv4
			 * and IPv6 go out with the unspecified/INADDR_ANY
			 * src IP addr.
			 */
			opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
		}
		ip6h->ip6_src = *sender;
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
		if (opt != NULL)
			opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		ip6h->ip6_src = *sender;
		na->nd_na_target = *sender;
		if (flag & NDP_ISROUTER)
			na->nd_na_flags_reserved |= ND_NA_FLAG_ROUTER;
		if (flag & NDP_SOLICITED)
			na->nd_na_flags_reserved |= ND_NA_FLAG_SOLICITED;
		if (flag & NDP_ORIDE)
			na->nd_na_flags_reserved |= ND_NA_FLAG_OVERRIDE;
	}

	if (!(flag & NDP_PROBE)) {
		if (hw_addr != NULL && opt != NULL) {
			/* Fill in link layer address and option len */
			opt->nd_opt_len = (uint8_t)plen;
			bcopy(hw_addr, &opt[1], hw_addr_len);
		}
	}
	if (opt != NULL && opt->nd_opt_type == 0) {
		/* If there's no link layer address option, then strip it. */
		len -= plen * 8;
		mp->b_wptr = mp->b_rptr + len;
		ip6h->ip6_plen = htons(len - IPV6_HDR_LEN);
	}

	icmp6->icmp6_type = (uint8_t)operation;
	icmp6->icmp6_code = 0;
	/*
	 * Prepare for checksum by putting icmp length in the icmp
	 * checksum field. The checksum is calculated in ip_output.c.
	 */
	icmp6->icmp6_cksum = ip6h->ip6_plen;

	(void) ip_output_simple(mp, &ixas);
	ixa_cleanup(&ixas);
	if (need_refrele)
		ill_refrele(ill);
	return (B_FALSE);
}

/*
 * Used to set ND_UNREACHBLE before ncec_delete sets it NCE_F_CONDEMNED.
 * The datapath uses this as an indication that there
 * is a problem (as opposed to a NCE that was just
 * reclaimed due to lack of memory.
 * Note that static ARP entries never become unreachable.
 */
void
nce_make_unreachable(ncec_t *ncec)
{
	mutex_enter(&ncec->ncec_lock);
	ncec->ncec_state = ND_UNREACHABLE;
	mutex_exit(&ncec->ncec_lock);
}

/*
 * NCE retransmit timer. Common to IPv4 and IPv6.
 * This timer goes off when:
 * a. It is time to retransmit a resolution for resolver.
 * b. It is time to send reachability probes.
 */
void
nce_timer(void *arg)
{
	ncec_t		*ncec = arg;
	ill_t		*ill = ncec->ncec_ill, *src_ill;
	char		addrbuf[INET6_ADDRSTRLEN];
	boolean_t	dropped = B_FALSE;
	ip_stack_t	*ipst = ncec->ncec_ipst;
	boolean_t	isv6 = (ncec->ncec_ipversion == IPV6_VERSION);
	in_addr_t	sender4 = INADDR_ANY;
	in6_addr_t	sender6 = ipv6_all_zeros;

	/*
	 * The timer has to be cancelled by ncec_delete before doing the final
	 * refrele. So the NCE is guaranteed to exist when the timer runs
	 * until it clears the timeout_id. Before clearing the timeout_id
	 * bump up the refcnt so that we can continue to use the ncec
	 */
	ASSERT(ncec != NULL);
	mutex_enter(&ncec->ncec_lock);
	ncec_refhold_locked(ncec);
	ncec->ncec_timeout_id = 0;
	mutex_exit(&ncec->ncec_lock);

	src_ill = nce_resolve_src(ncec, &sender6);
	/* if we could not find a sender address, return */
	if (src_ill == NULL) {
		if (!isv6) {
			IN6_V4MAPPED_TO_IPADDR(&ncec->ncec_addr, sender4);
			ip1dbg(("no src ill for %s\n", inet_ntop(AF_INET,
			    &sender4, addrbuf, sizeof (addrbuf))));
		} else {
			ip1dbg(("no src ill for %s\n", inet_ntop(AF_INET6,
			    &ncec->ncec_addr, addrbuf, sizeof (addrbuf))));
		}
		nce_restart_timer(ncec, ill->ill_reachable_retrans_time);
		ncec_refrele(ncec);
		return;
	}
	if (!isv6)
		IN6_V4MAPPED_TO_IPADDR(&sender6, sender4);

	mutex_enter(&ncec->ncec_lock);
	/*
	 * Check the reachability state.
	 */
	switch (ncec->ncec_state) {
	case ND_DELAY:
		ASSERT(ncec->ncec_lladdr != NULL);
		ncec->ncec_state = ND_PROBE;
		ncec->ncec_pcnt = ND_MAX_UNICAST_SOLICIT;
		if (isv6) {
			mutex_exit(&ncec->ncec_lock);
			dropped = ndp_xmit(src_ill, ND_NEIGHBOR_SOLICIT,
			    src_ill->ill_phys_addr,
			    src_ill->ill_phys_addr_length,
			    &sender6, &ncec->ncec_addr,
			    NDP_UNICAST);
		} else {
			dropped = (arp_request(ncec, sender4, src_ill) == 0);
			mutex_exit(&ncec->ncec_lock);
		}
		if (!dropped) {
			mutex_enter(&ncec->ncec_lock);
			ncec->ncec_pcnt--;
			mutex_exit(&ncec->ncec_lock);
		}
		if (ip_debug > 3) {
			/* ip2dbg */
			pr_addr_dbg("nce_timer: state for %s changed "
			    "to PROBE\n", AF_INET6, &ncec->ncec_addr);
		}
		nce_restart_timer(ncec, ill->ill_reachable_retrans_time);
		break;
	case ND_PROBE:
		/* must be retransmit timer */
		ASSERT(ncec->ncec_pcnt >= -1);
		if (ncec->ncec_pcnt > 0) {
			/*
			 * As per RFC2461, the ncec gets deleted after
			 * MAX_UNICAST_SOLICIT unsuccessful re-transmissions.
			 * Note that the first unicast solicitation is sent
			 * during the DELAY state.
			 */
			ip2dbg(("nce_timer: pcount=%x dst %s\n",
			    ncec->ncec_pcnt,
			    inet_ntop((isv6? AF_INET6 : AF_INET),
			    &ncec->ncec_addr, addrbuf, sizeof (addrbuf))));
			if (NCE_PUBLISH(ncec)) {
				mutex_exit(&ncec->ncec_lock);
				/*
				 * send out a probe; note that src_ill
				 * is ignored by nce_dad() for all
				 * DAD message types other than IPv6
				 * unicast probes
				 */
				nce_dad(ncec, src_ill, B_TRUE);
			} else {
				ASSERT(src_ill != NULL);
				if (isv6) {
					mutex_exit(&ncec->ncec_lock);
					dropped = ndp_xmit(src_ill,
					    ND_NEIGHBOR_SOLICIT,
					    src_ill->ill_phys_addr,
					    src_ill->ill_phys_addr_length,
					    &sender6, &ncec->ncec_addr,
					    NDP_UNICAST);
				} else {
					/*
					 * since the nce is REACHABLE,
					 * the ARP request will be sent out
					 * as a link-layer unicast.
					 */
					dropped = (arp_request(ncec, sender4,
					    src_ill) == 0);
					mutex_exit(&ncec->ncec_lock);
				}
				if (!dropped) {
					mutex_enter(&ncec->ncec_lock);
					ncec->ncec_pcnt--;
					mutex_exit(&ncec->ncec_lock);
				}
				nce_restart_timer(ncec,
				    ill->ill_reachable_retrans_time);
			}
		} else if (ncec->ncec_pcnt < 0) {
			/* No hope, delete the ncec */
			/* Tell datapath it went bad */
			ncec->ncec_state = ND_UNREACHABLE;
			mutex_exit(&ncec->ncec_lock);
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("nce_timer: Delete NCE for"
				    " dst %s\n", (isv6? AF_INET6: AF_INET),
				    &ncec->ncec_addr);
			}
			/* if static ARP can't delete. */
			if ((ncec->ncec_flags & NCE_F_STATIC) == 0)
				ncec_delete(ncec);

		} else if (!NCE_PUBLISH(ncec)) {
			/*
			 * Probe count is 0 for a dynamic entry (one that we
			 * ourselves are not publishing). We should never get
			 * here if NONUD was requested, hence the ASSERT below.
			 */
			ASSERT((ncec->ncec_flags & NCE_F_NONUD) == 0);
			ip2dbg(("nce_timer: pcount=%x dst %s\n",
			    ncec->ncec_pcnt, inet_ntop(AF_INET6,
			    &ncec->ncec_addr, addrbuf, sizeof (addrbuf))));
			ncec->ncec_pcnt--;
			mutex_exit(&ncec->ncec_lock);
			/* Wait one interval before killing */
			nce_restart_timer(ncec,
			    ill->ill_reachable_retrans_time);
		} else if (ill->ill_phyint->phyint_flags & PHYI_RUNNING) {
			ipif_t *ipif;
			ipaddr_t ncec_addr;

			/*
			 * We're done probing, and we can now declare this
			 * address to be usable.  Let IP know that it's ok to
			 * use.
			 */
			ncec->ncec_state = ND_REACHABLE;
			ncec->ncec_flags &= ~NCE_F_UNVERIFIED;
			mutex_exit(&ncec->ncec_lock);
			if (isv6) {
				ipif = ipif_lookup_addr_exact_v6(
				    &ncec->ncec_addr, ill, ipst);
			} else {
				IN6_V4MAPPED_TO_IPADDR(&ncec->ncec_addr,
				    ncec_addr);
				ipif = ipif_lookup_addr_exact(ncec_addr, ill,
				    ipst);
			}
			if (ipif != NULL) {
				if (ipif->ipif_was_dup) {
					char ibuf[LIFNAMSIZ];
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
			if (!isv6 && arp_no_defense)
				break;
			/* Begin defending our new address */
			if (ncec->ncec_unsolicit_count > 0) {
				ncec->ncec_unsolicit_count--;
				if (isv6) {
					dropped = ndp_announce(ncec);
				} else {
					dropped = arp_announce(ncec);
				}

				if (dropped)
					ncec->ncec_unsolicit_count++;
				else
					ncec->ncec_last_time_defended =
					    ddi_get_lbolt();
			}
			if (ncec->ncec_unsolicit_count > 0) {
				nce_restart_timer(ncec,
				    ANNOUNCE_INTERVAL(isv6));
			} else if (DEFENSE_INTERVAL(isv6) != 0) {
				nce_restart_timer(ncec, DEFENSE_INTERVAL(isv6));
			}
		} else {
			/*
			 * This is an address we're probing to be our own, but
			 * the ill is down.  Wait until it comes back before
			 * doing anything, but switch to reachable state so
			 * that the restart will work.
			 */
			ncec->ncec_state = ND_REACHABLE;
			mutex_exit(&ncec->ncec_lock);
		}
		break;
	case ND_INCOMPLETE: {
		mblk_t	*mp, *nextmp;
		mblk_t	**prevmpp;

		/*
		 * Per case (2) in the nce_queue_mp() comments, scan ncec_qd_mp
		 * for any IPMP probe packets, and toss them.  IPMP probe
		 * packets will always be at the head of ncec_qd_mp, so that
		 * we can stop at the first queued ND packet that is
		 * not a probe packet.
		 */
		prevmpp = &ncec->ncec_qd_mp;
		for (mp = ncec->ncec_qd_mp; mp != NULL; mp = nextmp) {
			nextmp = mp->b_next;

			if (IS_UNDER_IPMP(ill) && ncec->ncec_nprobes > 0) {
				inet_freemsg(mp);
				ncec->ncec_nprobes--;
				*prevmpp = nextmp;
			} else {
				prevmpp = &mp->b_next;
			}
		}

		/*
		 * Must be resolver's retransmit timer.
		 */
		mutex_exit(&ncec->ncec_lock);
		ip_ndp_resolve(ncec);
		break;
	}
	case ND_REACHABLE:
		if (((ncec->ncec_flags & NCE_F_UNSOL_ADV) &&
		    ncec->ncec_unsolicit_count != 0) ||
		    (NCE_PUBLISH(ncec) && DEFENSE_INTERVAL(isv6) != 0)) {
			if (ncec->ncec_unsolicit_count > 0) {
				ncec->ncec_unsolicit_count--;
				mutex_exit(&ncec->ncec_lock);
				/*
				 * When we get to zero announcements left,
				 * switch to address defense
				 */
			} else {
				boolean_t rate_limit;

				mutex_exit(&ncec->ncec_lock);
				rate_limit = ill_defend_rate_limit(ill, ncec);
				if (rate_limit) {
					nce_restart_timer(ncec,
					    DEFENSE_INTERVAL(isv6));
					break;
				}
			}
			if (isv6) {
				dropped = ndp_announce(ncec);
			} else {
				dropped = arp_announce(ncec);
			}
			mutex_enter(&ncec->ncec_lock);
			if (dropped) {
				ncec->ncec_unsolicit_count++;
			} else {
				ncec->ncec_last_time_defended =
				    ddi_get_lbolt();
			}
			mutex_exit(&ncec->ncec_lock);
			if (ncec->ncec_unsolicit_count != 0) {
				nce_restart_timer(ncec,
				    ANNOUNCE_INTERVAL(isv6));
			} else {
				nce_restart_timer(ncec, DEFENSE_INTERVAL(isv6));
			}
		} else {
			mutex_exit(&ncec->ncec_lock);
		}
		break;
	default:
		mutex_exit(&ncec->ncec_lock);
		break;
	}
done:
	ncec_refrele(ncec);
	ill_refrele(src_ill);
}

/*
 * Set a link layer address from the ll_addr passed in.
 * Copy SAP from ill.
 */
static void
nce_set_ll(ncec_t *ncec, uchar_t *ll_addr)
{
	ill_t	*ill = ncec->ncec_ill;

	ASSERT(ll_addr != NULL);
	if (ill->ill_phys_addr_length > 0) {
		/*
		 * The bcopy() below used to be called for the physical address
		 * length rather than the link layer address length. For
		 * ethernet and many other media, the phys_addr and lla are
		 * identical.
		 *
		 * The phys_addr and lla may not be the same for devices that
		 * support DL_IPV6_LINK_LAYER_ADDR, though there are currently
		 * no known instances of these.
		 *
		 * For PPP or other interfaces with a zero length
		 * physical address, don't do anything here.
		 * The bcopy() with a zero phys_addr length was previously
		 * a no-op for interfaces with a zero-length physical address.
		 * Using the lla for them would change the way they operate.
		 * Doing nothing in such cases preserves expected behavior.
		 */
		bcopy(ll_addr, ncec->ncec_lladdr, ill->ill_nd_lla_len);
	}
}

boolean_t
nce_cmp_ll_addr(const ncec_t *ncec, const uchar_t *ll_addr,
    uint32_t ll_addr_len)
{
	ASSERT(ncec->ncec_lladdr != NULL);
	if (ll_addr == NULL)
		return (B_FALSE);
	if (bcmp(ll_addr, ncec->ncec_lladdr, ll_addr_len) != 0)
		return (B_TRUE);
	return (B_FALSE);
}

/*
 * Updates the link layer address or the reachability state of
 * a cache entry.  Reset probe counter if needed.
 */
void
nce_update(ncec_t *ncec, uint16_t new_state, uchar_t *new_ll_addr)
{
	ill_t	*ill = ncec->ncec_ill;
	boolean_t need_stop_timer = B_FALSE;
	boolean_t need_fastpath_update = B_FALSE;
	nce_t	*nce = NULL;
	timeout_id_t tid;

	ASSERT(MUTEX_HELD(&ncec->ncec_lock));
	/*
	 * If this interface does not do NUD, there is no point
	 * in allowing an update to the cache entry.  Although
	 * we will respond to NS.
	 * The only time we accept an update for a resolver when
	 * NUD is turned off is when it has just been created.
	 * Non-Resolvers will always be created as REACHABLE.
	 */
	if (new_state != ND_UNCHANGED) {
		if ((ncec->ncec_flags & NCE_F_NONUD) &&
		    (ncec->ncec_state != ND_INCOMPLETE))
			return;
		ASSERT((int16_t)new_state >= ND_STATE_VALID_MIN);
		ASSERT((int16_t)new_state <= ND_STATE_VALID_MAX);
		need_stop_timer = B_TRUE;
		if (new_state == ND_REACHABLE)
			ncec->ncec_last = TICK_TO_MSEC(ddi_get_lbolt64());
		else {
			/* We force NUD in this case */
			ncec->ncec_last = 0;
		}
		ncec->ncec_state = new_state;
		ncec->ncec_pcnt = ND_MAX_UNICAST_SOLICIT;
		ASSERT(ncec->ncec_lladdr != NULL || new_state == ND_INITIAL ||
		    new_state == ND_INCOMPLETE);
	}
	if (need_stop_timer || (ncec->ncec_flags & NCE_F_STATIC)) {
		tid = ncec->ncec_timeout_id;
		ncec->ncec_timeout_id = 0;
	}
	/*
	 * Re-trigger fastpath probe and
	 * overwrite the DL_UNITDATA_REQ data, noting we'll lose
	 * whatever packets that happens to be transmitting at the time.
	 */
	if (new_ll_addr != NULL) {
		bcopy(new_ll_addr, ncec->ncec_lladdr,
		    ill->ill_phys_addr_length);
		need_fastpath_update = B_TRUE;
	}
	mutex_exit(&ncec->ncec_lock);
	if (need_stop_timer || (ncec->ncec_flags & NCE_F_STATIC)) {
		if (tid != 0)
			(void) untimeout(tid);
	}
	if (need_fastpath_update) {
		/*
		 * Delete any existing existing dlur_mp and fp_mp information.
		 * For IPMP interfaces, all underlying ill's must be checked
		 * and purged.
		 */
		nce_fastpath_list_delete(ncec->ncec_ill, ncec, NULL);
		/*
		 * add the new dlur_mp and fp_mp
		 */
		nce = nce_fastpath(ncec, B_TRUE, NULL);
		if (nce != NULL)
			nce_refrele(nce);
	}
	mutex_enter(&ncec->ncec_lock);
}

static void
nce_queue_mp_common(ncec_t *ncec, mblk_t *mp, boolean_t head_insert)
{
	uint_t	count = 0;
	mblk_t  **mpp, *tmp;

	ASSERT(MUTEX_HELD(&ncec->ncec_lock));

	for (mpp = &ncec->ncec_qd_mp; *mpp != NULL; mpp = &(*mpp)->b_next) {
		if (++count > ncec->ncec_ill->ill_max_buf) {
			tmp = ncec->ncec_qd_mp->b_next;
			ncec->ncec_qd_mp->b_next = NULL;
			/*
			 * if we never create data addrs on the under_ill
			 * does this matter?
			 */
			BUMP_MIB(ncec->ncec_ill->ill_ip_mib,
			    ipIfStatsOutDiscards);
			ip_drop_output("ipIfStatsOutDiscards", ncec->ncec_qd_mp,
			    ncec->ncec_ill);
			freemsg(ncec->ncec_qd_mp);
			ncec->ncec_qd_mp = tmp;
		}
	}

	if (head_insert) {
		ncec->ncec_nprobes++;
		mp->b_next = ncec->ncec_qd_mp;
		ncec->ncec_qd_mp = mp;
	} else {
		*mpp = mp;
	}
}

/*
 * nce_queue_mp will queue the packet into the ncec_qd_mp. The packet will be
 * queued at the head or tail of the queue based on the input argument
 * 'head_insert'. The caller should specify this argument as B_TRUE if this
 * packet is an IPMP probe packet, in which case the following happens:
 *
 *   1. Insert it at the head of the ncec_qd_mp list.  Consider the normal
 *	(non-ipmp_probe) load-speading case where the source address of the ND
 *	packet is not tied to ncec_ill. If the ill bound to the source address
 *	cannot receive, the response to the ND packet will not be received.
 *	However, if ND packets for ncec_ill's probes are queued	behind that ND
 *	packet, those probes will also fail to be sent, and thus in.mpathd will
 *	 erroneously conclude that ncec_ill has also failed.
 *
 *   2. Drop the ipmp_probe packet in ndp_timer() if the ND did	not succeed on
 *	the first attempt.  This ensures that ND problems do not manifest as
 *	probe RTT spikes.
 *
 * We achieve this by inserting ipmp_probe() packets at the head of the
 * nce_queue.
 *
 * The ncec for the probe target is created with ncec_ill set to the ipmp_ill,
 * but the caller needs to set head_insert to B_TRUE if this is a probe packet.
 */
void
nce_queue_mp(ncec_t *ncec, mblk_t *mp, boolean_t head_insert)
{
	ASSERT(MUTEX_HELD(&ncec->ncec_lock));
	nce_queue_mp_common(ncec, mp, head_insert);
}

/*
 * Called when address resolution failed due to a timeout.
 * Send an ICMP unreachable in response to all queued packets.
 */
void
ndp_resolv_failed(ncec_t *ncec)
{
	mblk_t	*mp, *nxt_mp;
	char	buf[INET6_ADDRSTRLEN];
	ill_t *ill = ncec->ncec_ill;
	ip_recv_attr_t	iras;

	bzero(&iras, sizeof (iras));
	iras.ira_flags = 0;
	/*
	 * we are setting the ira_rill to the ipmp_ill (instead of
	 * the actual ill on which the packet was received), but this
	 * is ok because we don't actually need the real ira_rill.
	 * to send the icmp unreachable to the sender.
	 */
	iras.ira_ill = iras.ira_rill = ill;
	iras.ira_ruifindex = ill->ill_phyint->phyint_ifindex;
	iras.ira_rifindex = iras.ira_ruifindex;

	ip1dbg(("ndp_resolv_failed: dst %s\n",
	    inet_ntop(AF_INET6, (char *)&ncec->ncec_addr, buf, sizeof (buf))));
	mutex_enter(&ncec->ncec_lock);
	mp = ncec->ncec_qd_mp;
	ncec->ncec_qd_mp = NULL;
	ncec->ncec_nprobes = 0;
	mutex_exit(&ncec->ncec_lock);
	while (mp != NULL) {
		nxt_mp = mp->b_next;
		mp->b_next = NULL;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards - address unreachable",
		    mp, ill);
		icmp_unreachable_v6(mp,
		    ICMP6_DST_UNREACH_ADDR, B_FALSE, &iras);
		ASSERT(!(iras.ira_flags & IRAF_IPSEC_SECURE));
		mp = nxt_mp;
	}
	ncec_cb_dispatch(ncec); /* finish off waiting callbacks */
}

/*
 * Handle the completion of NDP and ARP resolution.
 */
void
nce_resolv_ok(ncec_t *ncec)
{
	mblk_t *mp;
	uint_t pkt_len;
	iaflags_t ixaflags = IXAF_NO_TRACE;
	nce_t *nce;
	ill_t	*ill = ncec->ncec_ill;
	boolean_t isv6 = (ncec->ncec_ipversion == IPV6_VERSION);
	ip_stack_t *ipst = ill->ill_ipst;

	if (IS_IPMP(ncec->ncec_ill)) {
		nce_resolv_ipmp_ok(ncec);
		return;
	}
	/* non IPMP case */

	mutex_enter(&ncec->ncec_lock);
	ASSERT(ncec->ncec_nprobes == 0);
	mp = ncec->ncec_qd_mp;
	ncec->ncec_qd_mp = NULL;
	mutex_exit(&ncec->ncec_lock);

	while (mp != NULL) {
		mblk_t *nxt_mp;

		if (ill->ill_isv6) {
			ip6_t *ip6h = (ip6_t *)mp->b_rptr;

			pkt_len = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
		} else {
			ipha_t *ipha = (ipha_t *)mp->b_rptr;

			ixaflags |= IXAF_IS_IPV4;
			pkt_len = ntohs(ipha->ipha_length);
		}
		nxt_mp = mp->b_next;
		mp->b_next = NULL;
		/*
		 * IXAF_NO_DEV_FLOW_CTL information for TCP packets is no
		 * longer available, but it's ok to drop this flag because TCP
		 * has its own flow-control in effect, so TCP packets
		 * are not likely to get here when flow-control is in effect.
		 */
		mutex_enter(&ill->ill_lock);
		nce = nce_lookup(ill, &ncec->ncec_addr);
		mutex_exit(&ill->ill_lock);

		if (nce == NULL) {
			if (isv6) {
				BUMP_MIB(&ipst->ips_ip6_mib,
				    ipIfStatsOutDiscards);
			} else {
				BUMP_MIB(&ipst->ips_ip_mib,
				    ipIfStatsOutDiscards);
			}
			ip_drop_output("ipIfStatsOutDiscards - no nce",
			    mp, NULL);
			freemsg(mp);
		} else {
			/*
			 * We don't know the zoneid, but
			 * ip_xmit does not care since IXAF_NO_TRACE
			 * is set. (We traced the packet the first
			 * time through ip_xmit.)
			 */
			(void) ip_xmit(mp, nce, ixaflags, pkt_len, 0,
			    ALL_ZONES, 0, NULL);
			nce_refrele(nce);
		}
		mp = nxt_mp;
	}

	ncec_cb_dispatch(ncec); /* complete callbacks */
}

/*
 * Called by SIOCSNDP* ioctl to add/change an ncec entry
 * and the corresponding attributes.
 * Disallow states other than ND_REACHABLE or ND_STALE.
 */
int
ndp_sioc_update(ill_t *ill, lif_nd_req_t *lnr)
{
	sin6_t		*sin6;
	in6_addr_t	*addr;
	ncec_t		*ncec;
	nce_t		*nce;
	int		err = 0;
	uint16_t	new_flags = 0;
	uint16_t	old_flags = 0;
	int		inflags = lnr->lnr_flags;
	ip_stack_t	*ipst = ill->ill_ipst;
	boolean_t	do_postprocess = B_FALSE;

	ASSERT(ill->ill_isv6);
	if ((lnr->lnr_state_create != ND_REACHABLE) &&
	    (lnr->lnr_state_create != ND_STALE))
		return (EINVAL);

	sin6 = (sin6_t *)&lnr->lnr_addr;
	addr = &sin6->sin6_addr;

	mutex_enter(&ipst->ips_ndp6->ndp_g_lock);
	ASSERT(!IS_UNDER_IPMP(ill));
	nce = nce_lookup_addr(ill, addr);
	if (nce != NULL)
		new_flags = nce->nce_common->ncec_flags;

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
			nce_refrele(nce);
		return (EINVAL);
	}
	if (inflags & NDF_STATIC)
		new_flags |= NCE_F_STATIC;

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
			nce_refrele(nce);
		return (EINVAL);
	}

	if (nce == NULL) {
		err = nce_add_v6(ill,
		    (uchar_t *)lnr->lnr_hdw_addr,
		    ill->ill_phys_addr_length,
		    addr,
		    new_flags,
		    lnr->lnr_state_create,
		    &nce);
		if (err != 0) {
			mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
			ip1dbg(("ndp_sioc_update: Can't create NCE %d\n", err));
			return (err);
		} else {
			do_postprocess = B_TRUE;
		}
	}
	ncec = nce->nce_common;
	old_flags = ncec->ncec_flags;
	if (old_flags & NCE_F_ISROUTER && !(new_flags & NCE_F_ISROUTER)) {
		ncec_router_to_host(ncec);
		mutex_exit(&ipst->ips_ndp6->ndp_g_lock);
		if (do_postprocess)
			err = nce_add_v6_postprocess(nce);
		nce_refrele(nce);
		return (0);
	}
	mutex_exit(&ipst->ips_ndp6->ndp_g_lock);

	if (do_postprocess)
		err = nce_add_v6_postprocess(nce);
	/*
	 * err cannot be anything other than 0 because we don't support
	 * proxy arp of static addresses.
	 */
	ASSERT(err == 0);

	mutex_enter(&ncec->ncec_lock);
	ncec->ncec_flags = new_flags;
	mutex_exit(&ncec->ncec_lock);
	/*
	 * Note that we ignore the state at this point, which
	 * should be either STALE or REACHABLE.  Instead we let
	 * the link layer address passed in to determine the state
	 * much like incoming packets.
	 */
	nce_process(ncec, (uchar_t *)lnr->lnr_hdw_addr, 0, B_FALSE);
	nce_refrele(nce);
	return (0);
}

/*
 * Create an nce_t structure for ill using the ncec->ncec_lladdr to set up
 * the nce_dlur_mp. If ill != ncec->ncec_ill, then the ips_ill_g_lock must
 * be held to ensure that they are in the same group.
 */
static nce_t *
nce_fastpath_create(ill_t *ill, ncec_t *ncec)
{

	nce_t *nce;

	nce = nce_ill_lookup_then_add(ill, ncec);

	if (nce == NULL || IS_LOOPBACK(nce->nce_ill) || IS_VNI(nce->nce_ill))
		return (nce);

	/*
	 * hold the ncec_lock to synchronize with nce_update() so that,
	 * at the end of this function, the contents of nce_dlur_mp are
	 * consistent with ncec->ncec_lladdr, even though some intermediate
	 * packet may have been sent out with a mangled address, which would
	 * only be a transient condition.
	 */
	mutex_enter(&ncec->ncec_lock);
	if (ncec->ncec_lladdr != NULL) {
		bcopy(ncec->ncec_lladdr, nce->nce_dlur_mp->b_rptr +
		    NCE_LL_ADDR_OFFSET(ill), ill->ill_phys_addr_length);
	} else {
		nce->nce_dlur_mp = ill_dlur_gen(NULL, 0, ill->ill_sap,
		    ill->ill_sap_length);
	}
	mutex_exit(&ncec->ncec_lock);
	return (nce);
}

/*
 * we make nce_fp_mp to have an M_DATA prepend.
 * The caller ensures there is hold on ncec for this function.
 * Note that since ill_fastpath_probe() copies the mblk there is
 * no need to hold the nce or ncec beyond this function.
 *
 * If the caller has passed in a non-null ncec_nce to nce_fastpath() that
 * ncec_nce must correspond to the nce for ncec with nce_ill == ncec->ncec_ill
 * and will be returned back by this function, so that no extra nce_refrele
 * is required for the caller. The calls from nce_add_common() use this
 * method. All other callers (that pass in NULL ncec_nce) will have to do a
 * nce_refrele of the returned nce (when it is non-null).
 */
nce_t *
nce_fastpath(ncec_t *ncec, boolean_t trigger_fp_req, nce_t *ncec_nce)
{
	nce_t *nce;
	ill_t *ill = ncec->ncec_ill;

	ASSERT(ill != NULL);

	if (IS_IPMP(ill) && trigger_fp_req) {
		trigger_fp_req = B_FALSE;
		ipmp_ncec_refresh_nce(ncec);
	}

	/*
	 * If the caller already has the nce corresponding to the ill, use
	 * that one. Otherwise we have to lookup/add the nce. Calls from
	 * nce_add_common() fall in the former category, and have just done
	 * the nce lookup/add that can be reused.
	 */
	if (ncec_nce == NULL)
		nce = nce_fastpath_create(ill, ncec);
	else
		nce = ncec_nce;

	if (nce == NULL || IS_LOOPBACK(nce->nce_ill) || IS_VNI(nce->nce_ill))
		return (nce);

	if (trigger_fp_req)
		nce_fastpath_trigger(nce);
	return (nce);
}

/*
 * Trigger fastpath on nce. No locks may be held.
 */
static void
nce_fastpath_trigger(nce_t *nce)
{
	int res;
	ill_t *ill = nce->nce_ill;
	ncec_t *ncec = nce->nce_common;

	res = ill_fastpath_probe(ill, nce->nce_dlur_mp);
	/*
	 * EAGAIN is an indication of a transient error
	 * i.e. allocation failure etc. leave the ncec in the list it
	 * will be updated when another probe happens for another ire
	 * if not it will be taken out of the list when the ire is
	 * deleted.
	 */
	if (res != 0 && res != EAGAIN && res != ENOTSUP)
		nce_fastpath_list_delete(ill, ncec, NULL);
}

/*
 * Add ncec to the nce fastpath list on ill.
 */
static nce_t *
nce_ill_lookup_then_add_locked(ill_t *ill, ncec_t *ncec)
{
	nce_t *nce = NULL;

	ASSERT(MUTEX_HELD(&ill->ill_lock));
	/*
	 * Atomically ensure that the ill is not CONDEMNED and is not going
	 * down, before adding the NCE.
	 */
	if (ill->ill_state_flags & ILL_CONDEMNED)
		return (NULL);
	mutex_enter(&ncec->ncec_lock);
	/*
	 * if ncec has not been deleted and
	 * is not already in the list add it.
	 */
	if (!NCE_ISCONDEMNED(ncec)) {
		nce = nce_lookup(ill, &ncec->ncec_addr);
		if (nce != NULL)
			goto done;
		nce = nce_add(ill, ncec);
	}
done:
	mutex_exit(&ncec->ncec_lock);
	return (nce);
}

nce_t *
nce_ill_lookup_then_add(ill_t *ill, ncec_t *ncec)
{
	nce_t *nce;

	mutex_enter(&ill->ill_lock);
	nce = nce_ill_lookup_then_add_locked(ill, ncec);
	mutex_exit(&ill->ill_lock);
	return (nce);
}


/*
 * remove ncec from the ill_nce list. If 'dead' is non-null, the deleted
 * nce is added to the 'dead' list, and the caller must nce_refrele() the
 * entry after all locks have been dropped.
 */
void
nce_fastpath_list_delete(ill_t *ill, ncec_t *ncec, list_t *dead)
{
	nce_t *nce;

	ASSERT(ill != NULL);

	/* delete any nces referencing the ncec from underlying ills */
	if (IS_IPMP(ill))
		ipmp_ncec_delete_nce(ncec);

	/* now the ill itself */
	mutex_enter(&ill->ill_lock);
	for (nce = list_head(&ill->ill_nce); nce != NULL;
	    nce = list_next(&ill->ill_nce, nce)) {
		if (nce->nce_common == ncec) {
			nce_refhold(nce);
			nce_delete(nce);
			break;
		}
	}
	mutex_exit(&ill->ill_lock);
	if (nce != NULL) {
		if (dead == NULL)
			nce_refrele(nce);
		else
			list_insert_tail(dead, nce);
	}
}

/*
 * when the fastpath response does not fit in the datab
 * associated with the existing nce_fp_mp, we delete and
 * add the nce to retrigger fastpath based on the information
 * in the ncec_t.
 */
static nce_t *
nce_delete_then_add(nce_t *nce)
{
	ill_t		*ill = nce->nce_ill;
	nce_t		*newnce = NULL;

	ip0dbg(("nce_delete_then_add nce %p ill %s\n",
	    (void *)nce, ill->ill_name));
	mutex_enter(&ill->ill_lock);
	mutex_enter(&nce->nce_common->ncec_lock);
	nce_delete(nce);
	/*
	 * Make sure that ncec is not condemned before adding. We hold the
	 * ill_lock and ncec_lock to synchronize with ncec_delete() and
	 * ipmp_ncec_delete_nce()
	 */
	if (!NCE_ISCONDEMNED(nce->nce_common))
		newnce = nce_add(ill, nce->nce_common);
	mutex_exit(&nce->nce_common->ncec_lock);
	mutex_exit(&ill->ill_lock);
	nce_refrele(nce);
	return (newnce); /* could be null if nomem */
}

typedef struct nce_fp_match_s {
	nce_t	*nce_fp_match_res;
	mblk_t	*nce_fp_match_ack_mp;
} nce_fp_match_t;

/* ARGSUSED */
static int
nce_fastpath_match_dlur(ill_t *ill, nce_t *nce, void *arg)
{
	nce_fp_match_t	*nce_fp_marg = arg;
	ncec_t		*ncec = nce->nce_common;
	mblk_t		*mp = nce_fp_marg->nce_fp_match_ack_mp;
	uchar_t	*mp_rptr, *ud_mp_rptr;
	mblk_t		*ud_mp = nce->nce_dlur_mp;
	ptrdiff_t	cmplen;

	/*
	 * mp is the mp associated with the fastpath ack.
	 * ud_mp is the outstanding DL_UNITDATA_REQ on the nce_t
	 * under consideration. If the contents match, then the
	 * fastpath ack is used to update the nce.
	 */
	if (ud_mp == NULL)
		return (0);
	mp_rptr = mp->b_rptr;
	cmplen = mp->b_wptr - mp_rptr;
	ASSERT(cmplen >= 0);

	ud_mp_rptr = ud_mp->b_rptr;
	/*
	 * The ncec is locked here to prevent any other threads from accessing
	 * and changing nce_dlur_mp when the address becomes resolved to an
	 * lla while we're in the middle of looking at and comparing the
	 * hardware address (lla). It is also locked to prevent multiple
	 * threads in nce_fastpath() from examining nce_dlur_mp at the same
	 * time.
	 */
	mutex_enter(&ncec->ncec_lock);
	if (ud_mp->b_wptr - ud_mp_rptr != cmplen ||
	    bcmp((char *)mp_rptr, (char *)ud_mp_rptr, cmplen) == 0) {
		nce_fp_marg->nce_fp_match_res = nce;
		mutex_exit(&ncec->ncec_lock);
		nce_refhold(nce);
		return (1);
	}
	mutex_exit(&ncec->ncec_lock);
	return (0);
}

/*
 * Update all NCE's that are not in fastpath mode and
 * have an nce_fp_mp that matches mp. mp->b_cont contains
 * the fastpath header.
 *
 * Returns TRUE if entry should be dequeued, or FALSE otherwise.
 */
void
nce_fastpath_update(ill_t *ill,  mblk_t *mp)
{
	nce_fp_match_t nce_fp_marg;
	nce_t *nce;
	mblk_t *nce_fp_mp, *fp_mp;

	nce_fp_marg.nce_fp_match_res = NULL;
	nce_fp_marg.nce_fp_match_ack_mp = mp;

	nce_walk(ill, nce_fastpath_match_dlur, &nce_fp_marg);

	if ((nce = nce_fp_marg.nce_fp_match_res) == NULL)
		return;

	mutex_enter(&nce->nce_lock);
	nce_fp_mp = nce->nce_fp_mp;

	if (nce_fp_mp != NULL) {
		fp_mp = mp->b_cont;
		if (nce_fp_mp->b_rptr + MBLKL(fp_mp) >
		    nce_fp_mp->b_datap->db_lim) {
			mutex_exit(&nce->nce_lock);
			nce = nce_delete_then_add(nce);
			if (nce == NULL) {
				return;
			}
			mutex_enter(&nce->nce_lock);
			nce_fp_mp = nce->nce_fp_mp;
		}
	}

	/* Matched - install mp as the fastpath mp */
	if (nce_fp_mp == NULL) {
		fp_mp = dupb(mp->b_cont);
		nce->nce_fp_mp = fp_mp;
	} else {
		fp_mp = mp->b_cont;
		bcopy(fp_mp->b_rptr, nce_fp_mp->b_rptr, MBLKL(fp_mp));
		nce->nce_fp_mp->b_wptr = nce->nce_fp_mp->b_rptr
		    + MBLKL(fp_mp);
	}
	mutex_exit(&nce->nce_lock);
	nce_refrele(nce);
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
 * ncec_walk function.
 * Free a fraction of the NCE cache entries.
 *
 * A possible optimization here would be to use ncec_last where possible, and
 * delete the least-frequently used entry, which would require more complex
 * computation as we walk through the ncec's (e.g., track ncec entries by
 * order of ncec_last and/or maintain state)
 */
static void
ncec_cache_reclaim(ncec_t *ncec, char *arg)
{
	ip_stack_t	*ipst = ncec->ncec_ipst;
	uint_t		fraction = *(uint_t *)arg;
	uint_t		rand;

	if ((ncec->ncec_flags &
	    (NCE_F_MYADDR | NCE_F_STATIC | NCE_F_BCAST)) != 0) {
		return;
	}

	rand = (uint_t)ddi_get_lbolt() +
	    NCE_ADDR_HASH_V6(ncec->ncec_addr, NCE_TABLE_SIZE);
	if ((rand/fraction)*fraction == rand) {
		IP_STAT(ipst, ip_nce_reclaim_deleted);
		ncec_delete(ncec);
	}
}

/*
 * kmem_cache callback to free up memory.
 *
 * For now we just delete a fixed fraction.
 */
static void
ip_nce_reclaim_stack(ip_stack_t *ipst)
{
	uint_t		fraction = ipst->ips_ip_nce_reclaim_fraction;

	IP_STAT(ipst, ip_nce_reclaim_calls);

	ncec_walk(NULL, (pfi_t)ncec_cache_reclaim, (uchar_t *)&fraction, ipst);

	/*
	 * Walk all CONNs that can have a reference on an ire, ncec or dce.
	 * Get them to update any stale references to drop any refholds they
	 * have.
	 */
	ipcl_walk(conn_ixa_cleanup, (void *)B_FALSE, ipst);
}

/*
 * Called by the memory allocator subsystem directly, when the system
 * is running low on memory.
 */
/* ARGSUSED */
void
ip_nce_reclaim(void *args)
{
	netstack_handle_t nh;
	netstack_t *ns;
	ip_stack_t *ipst;

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		/*
		 * netstack_next() can return a netstack_t with a NULL
		 * netstack_ip at boot time.
		 */
		if ((ipst = ns->netstack_ip) == NULL) {
			netstack_rele(ns);
			continue;
		}
		ip_nce_reclaim_stack(ipst);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
}

#ifdef DEBUG
void
ncec_trace_ref(ncec_t *ncec)
{
	ASSERT(MUTEX_HELD(&ncec->ncec_lock));

	if (ncec->ncec_trace_disable)
		return;

	if (!th_trace_ref(ncec, ncec->ncec_ipst)) {
		ncec->ncec_trace_disable = B_TRUE;
		ncec_trace_cleanup(ncec);
	}
}

void
ncec_untrace_ref(ncec_t *ncec)
{
	ASSERT(MUTEX_HELD(&ncec->ncec_lock));

	if (!ncec->ncec_trace_disable)
		th_trace_unref(ncec);
}

static void
ncec_trace_cleanup(const ncec_t *ncec)
{
	th_trace_cleanup(ncec, ncec->ncec_trace_disable);
}
#endif

/*
 * Called when address resolution fails due to a timeout.
 * Send an ICMP unreachable in response to all queued packets.
 */
void
arp_resolv_failed(ncec_t *ncec)
{
	mblk_t	*mp, *nxt_mp;
	char	buf[INET6_ADDRSTRLEN];
	struct in_addr ipv4addr;
	ill_t *ill = ncec->ncec_ill;
	ip_stack_t *ipst = ncec->ncec_ipst;
	ip_recv_attr_t	iras;

	bzero(&iras, sizeof (iras));
	iras.ira_flags = IRAF_IS_IPV4;
	/*
	 * we are setting the ira_rill to the ipmp_ill (instead of
	 * the actual ill on which the packet was received), but this
	 * is ok because we don't actually need the real ira_rill.
	 * to send the icmp unreachable to the sender.
	 */
	iras.ira_ill = iras.ira_rill = ill;
	iras.ira_ruifindex = ill->ill_phyint->phyint_ifindex;
	iras.ira_rifindex = iras.ira_ruifindex;

	IN6_V4MAPPED_TO_INADDR(&ncec->ncec_addr, &ipv4addr);
	ip3dbg(("arp_resolv_failed: dst %s\n",
	    inet_ntop(AF_INET, &ipv4addr, buf, sizeof (buf))));
	mutex_enter(&ncec->ncec_lock);
	mp = ncec->ncec_qd_mp;
	ncec->ncec_qd_mp = NULL;
	ncec->ncec_nprobes = 0;
	mutex_exit(&ncec->ncec_lock);
	while (mp != NULL) {
		nxt_mp = mp->b_next;
		mp->b_next = NULL;

		BUMP_MIB(ill->ill_ip_mib, ipIfStatsOutDiscards);
		ip_drop_output("ipIfStatsOutDiscards - address unreachable",
		    mp, ill);
		if (ipst->ips_ip_arp_icmp_error) {
			ip3dbg(("arp_resolv_failed: "
			    "Calling icmp_unreachable\n"));
			icmp_unreachable(mp, ICMP_HOST_UNREACHABLE, &iras);
		} else {
			freemsg(mp);
		}
		ASSERT(!(iras.ira_flags & IRAF_IPSEC_SECURE));
		mp = nxt_mp;
	}
	ncec_cb_dispatch(ncec); /* finish off waiting callbacks */
}

/*
 * if ill is an under_ill, translate it to the ipmp_ill and add the
 * nce on the ipmp_ill. Two nce_t entries (one on the ipmp_ill, and
 * one on the underlying in_ill) will be created for the
 * ncec_t in this case. The ncec_t itself will be created on the ipmp_ill.
 */
int
nce_lookup_then_add_v4(ill_t *ill, uchar_t *hw_addr, uint_t hw_addr_len,
    const in_addr_t *addr, uint16_t flags, uint16_t state, nce_t **newnce)
{
	int	err;
	in6_addr_t addr6;
	ip_stack_t *ipst = ill->ill_ipst;
	nce_t	*nce, *upper_nce = NULL;
	ill_t	*in_ill = ill, *under = NULL;
	boolean_t need_ill_refrele = B_FALSE;

	if (flags & NCE_F_MCAST) {
		/*
		 * hw_addr will be figured out in nce_set_multicast_v4;
		 * caller needs to pass in the cast_ill for ipmp
		 */
		ASSERT(hw_addr == NULL);
		ASSERT(!IS_IPMP(ill));
		err = nce_set_multicast_v4(ill, addr, flags, newnce);
		return (err);
	}

	if (IS_UNDER_IPMP(ill) && !(flags & NCE_F_MYADDR)) {
		ill = ipmp_ill_hold_ipmp_ill(ill);
		if (ill == NULL)
			return (ENXIO);
		need_ill_refrele = B_TRUE;
	}
	if ((flags & NCE_F_BCAST) != 0) {
		/*
		 * IPv4 broadcast ncec: compute the hwaddr.
		 */
		if (IS_IPMP(ill)) {
			under = ipmp_ill_hold_xmit_ill(ill, B_FALSE);
			if (under == NULL)  {
				if (need_ill_refrele)
					ill_refrele(ill);
				return (ENETDOWN);
			}
			hw_addr = under->ill_bcast_mp->b_rptr +
			    NCE_LL_ADDR_OFFSET(under);
			hw_addr_len = under->ill_phys_addr_length;
		} else {
			hw_addr = ill->ill_bcast_mp->b_rptr +
			    NCE_LL_ADDR_OFFSET(ill),
			    hw_addr_len = ill->ill_phys_addr_length;
		}
	}

	mutex_enter(&ipst->ips_ndp4->ndp_g_lock);
	IN6_IPADDR_TO_V4MAPPED(*addr, &addr6);
	nce = nce_lookup_addr(ill, &addr6);
	if (nce == NULL) {
		err = nce_add_v4(ill, hw_addr, hw_addr_len, addr, flags,
		    state, &nce);
	} else {
		err = EEXIST;
	}
	mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
	if (err == 0)
		err = nce_add_v4_postprocess(nce);

	if (in_ill != ill && nce != NULL) {
		nce_t *under_nce = NULL;

		/*
		 * in_ill was the under_ill. Try to create the under_nce.
		 * Hold the ill_g_lock to prevent changes to group membership
		 * until we are done.
		 */
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
		if (!IS_IN_SAME_ILLGRP(in_ill, ill)) {
			DTRACE_PROBE2(ill__not__in__group, nce_t *, nce,
			    ill_t *, ill);
			rw_exit(&ipst->ips_ill_g_lock);
			err = ENXIO;
			nce_refrele(nce);
			nce = NULL;
			goto bail;
		}
		under_nce = nce_fastpath_create(in_ill, nce->nce_common);
		if (under_nce == NULL) {
			rw_exit(&ipst->ips_ill_g_lock);
			err = EINVAL;
			nce_refrele(nce);
			nce = NULL;
			goto bail;
		}
		rw_exit(&ipst->ips_ill_g_lock);
		upper_nce = nce;
		nce = under_nce; /* will be returned to caller */
		if (NCE_ISREACHABLE(nce->nce_common))
			nce_fastpath_trigger(under_nce);
	}
	if (nce != NULL) {
		if (newnce != NULL)
			*newnce = nce;
		else
			nce_refrele(nce);
	}
bail:
	if (under != NULL)
		ill_refrele(under);
	if (upper_nce != NULL)
		nce_refrele(upper_nce);
	if (need_ill_refrele)
		ill_refrele(ill);

	return (err);
}

/*
 * NDP Cache Entry creation routine for IPv4.
 * This routine must always be called with ndp4->ndp_g_lock held.
 * Prior to return, ncec_refcnt is incremented.
 *
 * IPMP notes: the ncec for non-local (i.e., !NCE_MYADDR(ncec) addresses
 * are always added pointing at the ipmp_ill. Thus, when the ill passed
 * to nce_add_v4 is an under_ill (i.e., IS_UNDER_IPMP(ill)) two nce_t
 * entries will be created, both pointing at the same ncec_t. The nce_t
 * entries will have their nce_ill set to the ipmp_ill and the under_ill
 * respectively, with the ncec_t having its ncec_ill pointing at the ipmp_ill.
 * Local addresses are always created on the ill passed to nce_add_v4.
 */
int
nce_add_v4(ill_t *ill, uchar_t *hw_addr, uint_t hw_addr_len,
    const in_addr_t *addr, uint16_t flags, uint16_t state, nce_t **newnce)
{
	int		err;
	boolean_t	is_multicast = (flags & NCE_F_MCAST);
	struct in6_addr	addr6;
	nce_t		*nce;

	ASSERT(MUTEX_HELD(&ill->ill_ipst->ips_ndp4->ndp_g_lock));
	ASSERT(!ill->ill_isv6);
	ASSERT(!IN_MULTICAST(htonl(*addr)) || is_multicast);

	IN6_IPADDR_TO_V4MAPPED(*addr, &addr6);
	err = nce_add_common(ill, hw_addr, hw_addr_len, &addr6, flags, state,
	    &nce);
	ASSERT(newnce != NULL);
	*newnce = nce;
	return (err);
}

/*
 * Post-processing routine to be executed after nce_add_v4(). This function
 * triggers fastpath (if appropriate) and DAD on the newly added nce entry
 * and must be called without any locks held.
 *
 * Always returns 0, but we return an int to keep this symmetric with the
 * IPv6 counter-part.
 */
int
nce_add_v4_postprocess(nce_t *nce)
{
	ncec_t		*ncec = nce->nce_common;
	uint16_t	flags = ncec->ncec_flags;
	boolean_t	ndp_need_dad = B_FALSE;
	boolean_t	dropped;
	clock_t		delay;
	ip_stack_t	*ipst = ncec->ncec_ill->ill_ipst;
	uchar_t		*hw_addr = ncec->ncec_lladdr;
	boolean_t	trigger_fastpath = B_TRUE;

	/*
	 * If the hw_addr is NULL, typically for ND_INCOMPLETE nces, then
	 * we call nce_fastpath as soon as the ncec is resolved in nce_process.
	 * We call nce_fastpath from nce_update if the link layer address of
	 * the peer changes from nce_update
	 */
	if (NCE_PUBLISH(ncec) || !NCE_ISREACHABLE(ncec) || (hw_addr == NULL &&
	    ncec->ncec_ill->ill_net_type != IRE_IF_NORESOLVER))
		trigger_fastpath = B_FALSE;

	if (trigger_fastpath)
		nce_fastpath_trigger(nce);

	if (NCE_PUBLISH(ncec) && ncec->ncec_state == ND_PROBE) {
		/*
		 * Either the caller (by passing in ND_PROBE)
		 * or nce_add_common() (by the internally computed state
		 * based on ncec_addr and ill_net_type) has determined
		 * that this unicast entry needs DAD. Trigger DAD.
		 */
		ndp_need_dad = B_TRUE;
	} else if (flags & NCE_F_UNSOL_ADV) {
		/*
		 * We account for the transmit below by assigning one
		 * less than the ndd variable. Subsequent decrements
		 * are done in nce_timer.
		 */
		mutex_enter(&ncec->ncec_lock);
		ncec->ncec_unsolicit_count =
		    ipst->ips_ip_arp_publish_count - 1;
		mutex_exit(&ncec->ncec_lock);
		dropped = arp_announce(ncec);
		mutex_enter(&ncec->ncec_lock);
		if (dropped)
			ncec->ncec_unsolicit_count++;
		else
			ncec->ncec_last_time_defended = ddi_get_lbolt();
		if (ncec->ncec_unsolicit_count != 0) {
			nce_start_timer(ncec,
			    ipst->ips_ip_arp_publish_interval);
		}
		mutex_exit(&ncec->ncec_lock);
	}

	/*
	 * If ncec_xmit_interval is 0, user has configured us to send the first
	 * probe right away.  Do so, and set up for the subsequent probes.
	 */
	if (ndp_need_dad) {
		mutex_enter(&ncec->ncec_lock);
		if (ncec->ncec_pcnt == 0) {
			/*
			 * DAD probes and announce can be
			 * administratively disabled by setting the
			 * probe_count to zero. Restart the timer in
			 * this case to mark the ipif as ready.
			 */
			ncec->ncec_unsolicit_count = 0;
			mutex_exit(&ncec->ncec_lock);
			nce_restart_timer(ncec, 0);
		} else {
			mutex_exit(&ncec->ncec_lock);
			delay = ((ncec->ncec_flags & NCE_F_FAST) ?
			    ipst->ips_arp_probe_delay :
			    ipst->ips_arp_fastprobe_delay);
			nce_dad(ncec, NULL, (delay == 0 ? B_TRUE : B_FALSE));
		}
	}
	return (0);
}

/*
 * ncec_walk routine to update all entries that have a given destination or
 * gateway address and cached link layer (MAC) address.  This is used when ARP
 * informs us that a network-to-link-layer mapping may have changed.
 */
void
nce_update_hw_changed(ncec_t *ncec, void *arg)
{
	nce_hw_map_t *hwm = arg;
	ipaddr_t ncec_addr;

	if (ncec->ncec_state != ND_REACHABLE)
		return;

	IN6_V4MAPPED_TO_IPADDR(&ncec->ncec_addr, ncec_addr);
	if (ncec_addr != hwm->hwm_addr)
		return;

	mutex_enter(&ncec->ncec_lock);
	if (hwm->hwm_flags != 0)
		ncec->ncec_flags = hwm->hwm_flags;
	nce_update(ncec, ND_STALE, hwm->hwm_hwaddr);
	mutex_exit(&ncec->ncec_lock);
}

void
ncec_refhold(ncec_t *ncec)
{
	mutex_enter(&(ncec)->ncec_lock);
	(ncec)->ncec_refcnt++;
	ASSERT((ncec)->ncec_refcnt != 0);
#ifdef DEBUG
	ncec_trace_ref(ncec);
#endif
	mutex_exit(&(ncec)->ncec_lock);
}

void
ncec_refhold_notr(ncec_t *ncec)
{
	mutex_enter(&(ncec)->ncec_lock);
	(ncec)->ncec_refcnt++;
	ASSERT((ncec)->ncec_refcnt != 0);
	mutex_exit(&(ncec)->ncec_lock);
}

static void
ncec_refhold_locked(ncec_t *ncec)
{
	ASSERT(MUTEX_HELD(&(ncec)->ncec_lock));
	(ncec)->ncec_refcnt++;
#ifdef DEBUG
	ncec_trace_ref(ncec);
#endif
}

/* ncec_inactive destroys the mutex thus no mutex_exit is needed */
void
ncec_refrele(ncec_t *ncec)
{
	mutex_enter(&(ncec)->ncec_lock);
#ifdef DEBUG
	ncec_untrace_ref(ncec);
#endif
	ASSERT((ncec)->ncec_refcnt != 0);
	if (--(ncec)->ncec_refcnt == 0) {
		ncec_inactive(ncec);
	} else {
		mutex_exit(&(ncec)->ncec_lock);
	}
}

void
ncec_refrele_notr(ncec_t *ncec)
{
	mutex_enter(&(ncec)->ncec_lock);
	ASSERT((ncec)->ncec_refcnt != 0);
	if (--(ncec)->ncec_refcnt == 0) {
		ncec_inactive(ncec);
	} else {
		mutex_exit(&(ncec)->ncec_lock);
	}
}

/*
 * Common to IPv4 and IPv6.
 */
void
nce_restart_timer(ncec_t *ncec, uint_t ms)
{
	timeout_id_t tid;

	ASSERT(!MUTEX_HELD(&(ncec)->ncec_lock));

	/* First cancel any running timer */
	mutex_enter(&ncec->ncec_lock);
	tid = ncec->ncec_timeout_id;
	ncec->ncec_timeout_id = 0;
	if (tid != 0) {
		mutex_exit(&ncec->ncec_lock);
		(void) untimeout(tid);
		mutex_enter(&ncec->ncec_lock);
	}

	/* Restart timer */
	nce_start_timer(ncec, ms);
	mutex_exit(&ncec->ncec_lock);
}

static void
nce_start_timer(ncec_t *ncec, uint_t ms)
{
	ASSERT(MUTEX_HELD(&ncec->ncec_lock));
	/*
	 * Don't start the timer if the ncec has been deleted, or if the timer
	 * is already running
	 */
	if (!NCE_ISCONDEMNED(ncec) && ncec->ncec_timeout_id == 0) {
		ncec->ncec_timeout_id = timeout(nce_timer, ncec,
		    MSEC_TO_TICK(ms) == 0 ? 1 : MSEC_TO_TICK(ms));
	}
}

int
nce_set_multicast_v4(ill_t *ill, const in_addr_t *dst,
    uint16_t flags, nce_t **newnce)
{
	uchar_t		*hw_addr;
	int		err = 0;
	ip_stack_t	*ipst = ill->ill_ipst;
	in6_addr_t	dst6;
	nce_t		*nce;

	ASSERT(!ill->ill_isv6);

	IN6_IPADDR_TO_V4MAPPED(*dst, &dst6);
	mutex_enter(&ipst->ips_ndp4->ndp_g_lock);
	if ((nce = nce_lookup_addr(ill, &dst6)) != NULL) {
		mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
		goto done;
	}
	if (ill->ill_net_type == IRE_IF_RESOLVER) {
		/*
		 * For IRE_IF_RESOLVER a hardware mapping can be
		 * generated, for IRE_IF_NORESOLVER, resolution cookie
		 * in the ill is copied in nce_add_v4().
		 */
		hw_addr = kmem_alloc(ill->ill_phys_addr_length, KM_NOSLEEP);
		if (hw_addr == NULL) {
			mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
			return (ENOMEM);
		}
		ip_mcast_mapping(ill, (uchar_t *)dst, hw_addr);
	} else {
		/*
		 * IRE_IF_NORESOLVER type simply copies the resolution
		 * cookie passed in.  So no hw_addr is needed.
		 */
		hw_addr = NULL;
	}
	ASSERT(flags & NCE_F_MCAST);
	ASSERT(flags & NCE_F_NONUD);
	/* nce_state will be computed by nce_add_common() */
	err = nce_add_v4(ill, hw_addr, ill->ill_phys_addr_length, dst, flags,
	    ND_UNCHANGED, &nce);
	mutex_exit(&ipst->ips_ndp4->ndp_g_lock);
	if (err == 0)
		err = nce_add_v4_postprocess(nce);
	if (hw_addr != NULL)
		kmem_free(hw_addr, ill->ill_phys_addr_length);
	if (err != 0) {
		ip1dbg(("nce_set_multicast_v4: create failed" "%d\n", err));
		return (err);
	}
done:
	if (newnce != NULL)
		*newnce = nce;
	else
		nce_refrele(nce);
	return (0);
}

/*
 * This is used when scanning for "old" (least recently broadcast) NCEs.  We
 * don't want to have to walk the list for every single one, so we gather up
 * batches at a time.
 */
#define	NCE_RESCHED_LIST_LEN	8

typedef struct {
	ill_t	*ncert_ill;
	uint_t	ncert_num;
	ncec_t	*ncert_nces[NCE_RESCHED_LIST_LEN];
} nce_resched_t;

/*
 * Pick the longest waiting NCEs for defense.
 */
/* ARGSUSED */
static int
ncec_reschedule(ill_t *ill, nce_t *nce, void *arg)
{
	nce_resched_t *ncert = arg;
	ncec_t **ncecs;
	ncec_t **ncec_max;
	ncec_t *ncec_temp;
	ncec_t *ncec = nce->nce_common;

	ASSERT(ncec->ncec_ill == ncert->ncert_ill);
	/*
	 * Only reachable entries that are ready for announcement are eligible.
	 */
	if (!NCE_MYADDR(ncec) || ncec->ncec_state != ND_REACHABLE)
		return (0);
	if (ncert->ncert_num < NCE_RESCHED_LIST_LEN) {
		ncec_refhold(ncec);
		ncert->ncert_nces[ncert->ncert_num++] = ncec;
	} else {
		ncecs = ncert->ncert_nces;
		ncec_max = ncecs + NCE_RESCHED_LIST_LEN;
		ncec_refhold(ncec);
		for (; ncecs < ncec_max; ncecs++) {
			ASSERT(ncec != NULL);
			if ((*ncecs)->ncec_last_time_defended >
			    ncec->ncec_last_time_defended) {
				ncec_temp = *ncecs;
				*ncecs = ncec;
				ncec = ncec_temp;
			}
		}
		ncec_refrele(ncec);
	}
	return (0);
}

/*
 * Reschedule the ARP defense of any long-waiting NCEs.  It's assumed that this
 * doesn't happen very often (if at all), and thus it needn't be highly
 * optimized.  (Note, though, that it's actually O(N) complexity, because the
 * outer loop is bounded by a constant rather than by the length of the list.)
 */
static void
nce_ill_reschedule(ill_t *ill, nce_resched_t *ncert)
{
	ncec_t		*ncec;
	ip_stack_t	*ipst = ill->ill_ipst;
	uint_t		i, defend_rate;

	i = ill->ill_defend_count;
	ill->ill_defend_count = 0;
	if (ill->ill_isv6)
		defend_rate = ipst->ips_ndp_defend_rate;
	else
		defend_rate = ipst->ips_arp_defend_rate;
	/* If none could be sitting around, then don't reschedule */
	if (i < defend_rate) {
		DTRACE_PROBE1(reschedule_none, ill_t *, ill);
		return;
	}
	ncert->ncert_ill = ill;
	while (ill->ill_defend_count < defend_rate) {
		nce_walk_common(ill, ncec_reschedule, ncert);
		for (i = 0; i < ncert->ncert_num; i++) {

			ncec = ncert->ncert_nces[i];
			mutex_enter(&ncec->ncec_lock);
			ncec->ncec_flags |= NCE_F_DELAYED;
			mutex_exit(&ncec->ncec_lock);
			/*
			 * we plan to schedule this ncec, so incr the
			 * defend_count in anticipation.
			 */
			if (++ill->ill_defend_count >= defend_rate)
				break;
		}
		if (ncert->ncert_num < NCE_RESCHED_LIST_LEN)
			break;
	}
}

/*
 * Check if the current rate-limiting parameters permit the sending
 * of another address defense announcement for both IPv4 and IPv6.
 * Returns B_TRUE if rate-limiting is in effect (i.e., send is not
 * permitted), and B_FALSE otherwise. The `defend_rate' parameter
 * determines how many address defense announcements are permitted
 * in any `defense_perio' interval.
 */
static boolean_t
ill_defend_rate_limit(ill_t *ill, ncec_t *ncec)
{
	clock_t		now = ddi_get_lbolt();
	ip_stack_t	*ipst = ill->ill_ipst;
	clock_t		start = ill->ill_defend_start;
	uint32_t	elapsed, defend_period, defend_rate;
	nce_resched_t	ncert;
	boolean_t	ret;
	int		i;

	if (ill->ill_isv6) {
		defend_period = ipst->ips_ndp_defend_period;
		defend_rate = ipst->ips_ndp_defend_rate;
	} else {
		defend_period = ipst->ips_arp_defend_period;
		defend_rate = ipst->ips_arp_defend_rate;
	}
	if (defend_rate == 0)
		return (B_TRUE);
	bzero(&ncert, sizeof (ncert));
	mutex_enter(&ill->ill_lock);
	if (start > 0) {
		elapsed = now - start;
		if (elapsed > SEC_TO_TICK(defend_period)) {
			ill->ill_defend_start = now;
			/*
			 * nce_ill_reschedule will attempt to
			 * prevent starvation by reschduling the
			 * oldest entries, which are marked with
			 * the NCE_F_DELAYED flag.
			 */
			nce_ill_reschedule(ill, &ncert);
		}
	} else {
		ill->ill_defend_start = now;
	}
	ASSERT(ill->ill_defend_count <= defend_rate);
	mutex_enter(&ncec->ncec_lock);
	if (ncec->ncec_flags & NCE_F_DELAYED) {
		/*
		 * This ncec was rescheduled as one of the really old
		 * entries needing on-going defense. The
		 * ill_defend_count was already incremented in
		 * nce_ill_reschedule. Go ahead and send the announce.
		 */
		ncec->ncec_flags &= ~NCE_F_DELAYED;
		mutex_exit(&ncec->ncec_lock);
		ret = B_FALSE;
		goto done;
	}
	mutex_exit(&ncec->ncec_lock);
	if (ill->ill_defend_count < defend_rate)
		ill->ill_defend_count++;
	if (ill->ill_defend_count == defend_rate) {
		/*
		 * we are no longer allowed to send unbidden defense
		 * messages. Wait for rescheduling.
		 */
		ret = B_TRUE;
	} else {
		ret = B_FALSE;
	}
done:
	mutex_exit(&ill->ill_lock);
	/*
	 * After all the locks have been dropped we can restart nce timer,
	 * and refrele the delayed ncecs
	 */
	for (i = 0; i < ncert.ncert_num; i++) {
		clock_t	xmit_interval;
		ncec_t	*tmp;

		tmp = ncert.ncert_nces[i];
		xmit_interval = nce_fuzz_interval(tmp->ncec_xmit_interval,
		    B_FALSE);
		nce_restart_timer(tmp, xmit_interval);
		ncec_refrele(tmp);
	}
	return (ret);
}

boolean_t
ndp_announce(ncec_t *ncec)
{
	return (ndp_xmit(ncec->ncec_ill, ND_NEIGHBOR_ADVERT, ncec->ncec_lladdr,
	    ncec->ncec_lladdr_length, &ncec->ncec_addr, &ipv6_all_hosts_mcast,
	    nce_advert_flags(ncec)));
}

ill_t *
nce_resolve_src(ncec_t *ncec, in6_addr_t *src)
{
	mblk_t		*mp;
	in6_addr_t	src6;
	ipaddr_t	src4;
	ill_t		*ill = ncec->ncec_ill;
	ill_t		*src_ill = NULL;
	ipif_t		*ipif = NULL;
	boolean_t	is_myaddr = NCE_MYADDR(ncec);
	boolean_t	isv6 = (ncec->ncec_ipversion == IPV6_VERSION);

	ASSERT(src != NULL);
	ASSERT(IN6_IS_ADDR_UNSPECIFIED(src));
	src6 = *src;
	if (is_myaddr) {
		src6 = ncec->ncec_addr;
		if (!isv6)
			IN6_V4MAPPED_TO_IPADDR(&ncec->ncec_addr, src4);
	} else {
		/*
		 * try to find one from the outgoing packet.
		 */
		mutex_enter(&ncec->ncec_lock);
		mp = ncec->ncec_qd_mp;
		if (mp != NULL) {
			if (isv6) {
				ip6_t	*ip6h = (ip6_t *)mp->b_rptr;

				src6 = ip6h->ip6_src;
			} else {
				ipha_t  *ipha = (ipha_t *)mp->b_rptr;

				src4 = ipha->ipha_src;
				IN6_IPADDR_TO_V4MAPPED(src4, &src6);
			}
		}
		mutex_exit(&ncec->ncec_lock);
	}

	/*
	 * For outgoing packets, if the src of outgoing packet is one
	 * of the assigned interface addresses use it, otherwise we
	 * will pick the source address below.
	 * For local addresses (is_myaddr) doing DAD, NDP announce
	 * messages are mcast. So we use the (IPMP) cast_ill or the
	 * (non-IPMP) ncec_ill for these message types. The only case
	 * of unicast DAD messages are for IPv6 ND probes, for which
	 * we find the ipif_bound_ill corresponding to the ncec_addr.
	 */
	if (!IN6_IS_ADDR_UNSPECIFIED(&src6) || is_myaddr) {
		if (isv6) {
			ipif = ipif_lookup_addr_nondup_v6(&src6, ill, ALL_ZONES,
			    ill->ill_ipst);
		} else {
			ipif = ipif_lookup_addr_nondup(src4, ill, ALL_ZONES,
			    ill->ill_ipst);
		}

		/*
		 * If no relevant ipif can be found, then it's not one of our
		 * addresses.  Reset to :: and try to find a src for the NS or
		 * ARP request using ipif_select_source_v[4,6]  below.
		 * If an ipif can be found, but it's not yet done with
		 * DAD verification, and we are not being invoked for
		 * DAD (i.e., !is_myaddr), then just postpone this
		 * transmission until later.
		 */
		if (ipif == NULL) {
			src6 = ipv6_all_zeros;
			src4 = INADDR_ANY;
		} else if (!ipif->ipif_addr_ready && !is_myaddr) {
			DTRACE_PROBE2(nce__resolve__ipif__not__ready,
			    ncec_t *, ncec, ipif_t *, ipif);
			ipif_refrele(ipif);
			return (NULL);
		}
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&src6) && !is_myaddr) {
		/*
		 * Pick a source address for this solicitation, but
		 * restrict the selection to addresses assigned to the
		 * output interface.  We do this because the destination will
		 * create a neighbor cache entry for the source address of
		 * this packet, so the source address had better be a valid
		 * neighbor.
		 */
		if (isv6) {
			ipif = ipif_select_source_v6(ill, &ncec->ncec_addr,
			    B_TRUE, IPV6_PREFER_SRC_DEFAULT, ALL_ZONES,
			    B_FALSE, NULL);
		} else {
			ipaddr_t nce_addr;

			IN6_V4MAPPED_TO_IPADDR(&ncec->ncec_addr, nce_addr);
			ipif = ipif_select_source_v4(ill, nce_addr, ALL_ZONES,
			    B_FALSE, NULL);
		}
		if (ipif == NULL && IS_IPMP(ill)) {
			ill_t *send_ill = ipmp_ill_hold_xmit_ill(ill, B_TRUE);

			if (send_ill != NULL) {
				if (isv6) {
					ipif = ipif_select_source_v6(send_ill,
					    &ncec->ncec_addr, B_TRUE,
					    IPV6_PREFER_SRC_DEFAULT, ALL_ZONES,
					    B_FALSE, NULL);
				} else {
					IN6_V4MAPPED_TO_IPADDR(&ncec->ncec_addr,
					    src4);
					ipif = ipif_select_source_v4(send_ill,
					    src4, ALL_ZONES, B_TRUE, NULL);
				}
				ill_refrele(send_ill);
			}
		}

		if (ipif == NULL) {
			char buf[INET6_ADDRSTRLEN];

			ip1dbg(("nce_resolve_src: No source ipif for dst %s\n",
			    inet_ntop((isv6 ? AF_INET6 : AF_INET),
			    (char *)&ncec->ncec_addr, buf, sizeof (buf))));
			DTRACE_PROBE1(nce__resolve__no__ipif, ncec_t *, ncec);
			return (NULL);
		}
		src6 = ipif->ipif_v6lcl_addr;
	}
	*src = src6;
	if (ipif != NULL) {
		src_ill = ipif->ipif_ill;
		if (IS_IPMP(src_ill))
			src_ill = ipmp_ipif_hold_bound_ill(ipif);
		else
			ill_refhold(src_ill);
		ipif_refrele(ipif);
		DTRACE_PROBE2(nce__resolve__src__ill, ncec_t *, ncec,
		    ill_t *, src_ill);
	}
	return (src_ill);
}

void
ip_nce_lookup_and_update(ipaddr_t *addr, ipif_t *ipif, ip_stack_t *ipst,
    uchar_t *hwaddr, int hwaddr_len, int flags)
{
	ill_t	*ill;
	ncec_t	*ncec;
	nce_t	*nce;
	uint16_t new_state;

	ill = (ipif ? ipif->ipif_ill : NULL);
	if (ill != NULL) {
		/*
		 * only one ncec is possible
		 */
		nce = nce_lookup_v4(ill, addr);
		if (nce != NULL) {
			ncec = nce->nce_common;
			mutex_enter(&ncec->ncec_lock);
			if (NCE_ISREACHABLE(ncec))
				new_state = ND_UNCHANGED;
			else
				new_state = ND_STALE;
			ncec->ncec_flags = flags;
			nce_update(ncec, new_state, hwaddr);
			mutex_exit(&ncec->ncec_lock);
			nce_refrele(nce);
			return;
		}
	} else {
		/*
		 * ill is wildcard; clean up all ncec's and ire's
		 * that match on addr.
		 */
		nce_hw_map_t hwm;

		hwm.hwm_addr = *addr;
		hwm.hwm_hwlen = hwaddr_len;
		hwm.hwm_hwaddr = hwaddr;
		hwm.hwm_flags = flags;

		ncec_walk_common(ipst->ips_ndp4, NULL,
		    (pfi_t)nce_update_hw_changed, (uchar_t *)&hwm, B_TRUE);
	}
}

/*
 * Common function to add ncec entries.
 * we always add the ncec with ncec_ill == ill, and always create
 * nce_t on ncec_ill. A dlpi fastpath message may be triggered if the
 * ncec is !reachable.
 *
 * When the caller passes in an nce_state of ND_UNCHANGED,
 * nce_add_common() will determine the state of the created nce based
 * on the ill_net_type and nce_flags used. Otherwise, the nce will
 * be created with state set to the passed in nce_state.
 */
static int
nce_add_common(ill_t *ill, uchar_t *hw_addr, uint_t hw_addr_len,
    const in6_addr_t *addr, uint16_t flags, uint16_t nce_state, nce_t **retnce)
{
	static	ncec_t		nce_nil;
	uchar_t			*template = NULL;
	int			err;
	ncec_t			*ncec;
	ncec_t			**ncep;
	ip_stack_t		*ipst = ill->ill_ipst;
	uint16_t		state;
	boolean_t		fastprobe = B_FALSE;
	struct ndp_g_s		*ndp;
	nce_t			*nce = NULL;
	mblk_t			*dlur_mp = NULL;

	if (ill->ill_isv6)
		ndp = ill->ill_ipst->ips_ndp6;
	else
		ndp = ill->ill_ipst->ips_ndp4;

	*retnce = NULL;

	ASSERT(MUTEX_HELD(&ndp->ndp_g_lock));

	if (IN6_IS_ADDR_UNSPECIFIED(addr)) {
		ip0dbg(("nce_add_common: no addr\n"));
		return (EINVAL);
	}
	if ((flags & ~NCE_EXTERNAL_FLAGS_MASK)) {
		ip0dbg(("nce_add_common: flags = %x\n", (int)flags));
		return (EINVAL);
	}

	if (ill->ill_isv6) {
		ncep = ((ncec_t **)NCE_HASH_PTR_V6(ipst, *addr));
	} else {
		ipaddr_t v4addr;

		IN6_V4MAPPED_TO_IPADDR(addr, v4addr);
		ncep = ((ncec_t **)NCE_HASH_PTR_V4(ipst, v4addr));
	}

	/*
	 * The caller has ensured that there is no nce on ill, but there could
	 * still be an nce_common_t for the address, so that we find exisiting
	 * ncec_t strucutures first, and atomically add a new nce_t if
	 * one is found. The ndp_g_lock ensures that we don't cross threads
	 * with an ncec_delete(). Unlike ncec_lookup_illgrp() we do not
	 * compare for matches across the illgrp because this function is
	 * called via nce_lookup_then_add_v* -> nce_add_v* -> nce_add_common,
	 * with the nce_lookup_then_add_v* passing in the ipmp_ill where
	 * appropriate.
	 */
	ncec = *ncep;
	for (; ncec != NULL; ncec = ncec->ncec_next) {
		if (ncec->ncec_ill == ill) {
			if (IN6_ARE_ADDR_EQUAL(&ncec->ncec_addr, addr)) {
				/*
				 * We should never find *retnce to be
				 * MYADDR, since the caller may then
				 * incorrectly restart a DAD timer that's
				 * already running.  However, if we are in
				 * forwarding mode, and the interface is
				 * moving in/out of groups, the data
				 * path ire lookup (e.g., ire_revalidate_nce)
				 * may  have determined that some destination
				 * is offlink while the control path is adding
				 * that address as a local address.
				 * Recover from  this case by failing the
				 * lookup
				 */
				if (NCE_MYADDR(ncec))
					return (ENXIO);
				*retnce = nce_ill_lookup_then_add(ill, ncec);
				if (*retnce != NULL)
					break;
			}
		}
	}
	if (*retnce != NULL) /* caller must trigger fastpath on nce */
		return (0);

	ncec = kmem_cache_alloc(ncec_cache, KM_NOSLEEP);
	if (ncec == NULL)
		return (ENOMEM);
	*ncec = nce_nil;
	ncec->ncec_ill = ill;
	ncec->ncec_ipversion = (ill->ill_isv6 ? IPV6_VERSION : IPV4_VERSION);
	ncec->ncec_flags = flags;
	ncec->ncec_ipst = ipst;	/* No netstack_hold */

	if (!ill->ill_isv6) {
		ipaddr_t addr4;

		/*
		 * DAD probe interval and probe count are set based on
		 * fast/slow probe settings. If the underlying link doesn't
		 * have reliably up/down notifications or if we're working
		 * with IPv4 169.254.0.0/16 Link Local Address space, then
		 * don't use the fast timers.  Otherwise, use them.
		 */
		ASSERT(IN6_IS_ADDR_V4MAPPED(addr));
		IN6_V4MAPPED_TO_IPADDR(addr, addr4);
		if (ill->ill_note_link && !IS_IPV4_LL_SPACE(&addr4)) {
			fastprobe = B_TRUE;
		} else if (IS_IPMP(ill) && NCE_PUBLISH(ncec) &&
		    !IS_IPV4_LL_SPACE(&addr4)) {
			ill_t *hwaddr_ill;

			hwaddr_ill = ipmp_illgrp_find_ill(ill->ill_grp, hw_addr,
			    hw_addr_len);
			if (hwaddr_ill != NULL && hwaddr_ill->ill_note_link)
				fastprobe = B_TRUE;
		}
		if (fastprobe) {
			ncec->ncec_xmit_interval =
			    ipst->ips_arp_fastprobe_interval;
			ncec->ncec_pcnt =
			    ipst->ips_arp_fastprobe_count;
			ncec->ncec_flags |= NCE_F_FAST;
		} else {
			ncec->ncec_xmit_interval =
			    ipst->ips_arp_probe_interval;
			ncec->ncec_pcnt =
			    ipst->ips_arp_probe_count;
		}
		if (NCE_PUBLISH(ncec)) {
			ncec->ncec_unsolicit_count =
			    ipst->ips_ip_arp_publish_count;
		}
	} else {
		/*
		 * probe interval is constant: ILL_PROBE_INTERVAL
		 * probe count is constant: ND_MAX_UNICAST_SOLICIT
		 */
		ncec->ncec_pcnt = ND_MAX_UNICAST_SOLICIT;
		if (NCE_PUBLISH(ncec)) {
			ncec->ncec_unsolicit_count =
			    ipst->ips_ip_ndp_unsolicit_count;
		}
	}
	ncec->ncec_rcnt = ill->ill_xmit_count;
	ncec->ncec_addr = *addr;
	ncec->ncec_qd_mp = NULL;
	ncec->ncec_refcnt = 1; /* for ncec getting created */
	mutex_init(&ncec->ncec_lock, NULL, MUTEX_DEFAULT, NULL);
	ncec->ncec_trace_disable = B_FALSE;

	/*
	 * ncec_lladdr holds link layer address
	 */
	if (hw_addr_len > 0) {
		template = kmem_alloc(hw_addr_len, KM_NOSLEEP);
		if (template == NULL) {
			err = ENOMEM;
			goto err_ret;
		}
		ncec->ncec_lladdr = template;
		ncec->ncec_lladdr_length = hw_addr_len;
		bzero(ncec->ncec_lladdr, hw_addr_len);
	}
	if ((flags & NCE_F_BCAST) != 0) {
		state = ND_REACHABLE;
		ASSERT(hw_addr_len > 0);
	} else if (ill->ill_net_type == IRE_IF_RESOLVER) {
		state = ND_INITIAL;
	} else if (ill->ill_net_type == IRE_IF_NORESOLVER) {
		/*
		 * NORESOLVER entries are always created in the REACHABLE
		 * state.
		 */
		state = ND_REACHABLE;
		if (ill->ill_phys_addr_length == IP_ADDR_LEN &&
		    ill->ill_mactype != DL_IPV4 &&
		    ill->ill_mactype != DL_6TO4) {
			/*
			 * We create a nce_res_mp with the IP nexthop address
			 * as the destination address if the physical length
			 * is exactly 4 bytes for point-to-multipoint links
			 * that do their own resolution from IP to link-layer
			 * address (e.g. IP over X.25).
			 */
			bcopy((uchar_t *)addr,
			    ncec->ncec_lladdr, ill->ill_phys_addr_length);
		}
		if (ill->ill_phys_addr_length == IPV6_ADDR_LEN &&
		    ill->ill_mactype != DL_IPV6) {
			/*
			 * We create a nce_res_mp with the IP nexthop address
			 * as the destination address if the physical legnth
			 * is exactly 16 bytes for point-to-multipoint links
			 * that do their own resolution from IP to link-layer
			 * address.
			 */
			bcopy((uchar_t *)addr,
			    ncec->ncec_lladdr, ill->ill_phys_addr_length);
		}
		/*
		 * Since NUD is not part of the base IPv4 protocol definition,
		 * IPv4 neighbor entries on NORESOLVER interfaces will never
		 * age, and are marked NCE_F_NONUD.
		 */
		if (!ill->ill_isv6)
			ncec->ncec_flags |= NCE_F_NONUD;
	} else if (ill->ill_net_type == IRE_LOOPBACK) {
		state = ND_REACHABLE;
	}

	if (hw_addr != NULL || ill->ill_net_type == IRE_IF_NORESOLVER) {
		/*
		 * We are adding an ncec with a deterministic hw_addr,
		 * so the state can only be one of {REACHABLE, STALE, PROBE}.
		 *
		 * if we are adding a unicast ncec for the local address
		 * it would be REACHABLE; we would be adding a ND_STALE entry
		 * for the requestor of an ARP_REQUEST/ND_SOLICIT. Our own
		 * addresses are added in PROBE to trigger DAD.
		 */
		if ((flags & (NCE_F_MCAST|NCE_F_BCAST)) ||
		    ill->ill_net_type == IRE_IF_NORESOLVER)
			state = ND_REACHABLE;
		else if (!NCE_PUBLISH(ncec))
			state = ND_STALE;
		else
			state = ND_PROBE;
		if (hw_addr != NULL)
			nce_set_ll(ncec, hw_addr);
	}
	/* caller overrides internally computed state */
	if (nce_state != ND_UNCHANGED)
		state = nce_state;

	if (state == ND_PROBE)
		ncec->ncec_flags |= NCE_F_UNVERIFIED;

	ncec->ncec_state = state;

	if (state == ND_REACHABLE) {
		ncec->ncec_last = ncec->ncec_init_time =
		    TICK_TO_MSEC(ddi_get_lbolt64());
	} else {
		ncec->ncec_last = 0;
		if (state == ND_INITIAL)
			ncec->ncec_init_time = TICK_TO_MSEC(ddi_get_lbolt64());
	}
	list_create(&ncec->ncec_cb, sizeof (ncec_cb_t),
	    offsetof(ncec_cb_t, ncec_cb_node));
	/*
	 * have all the memory allocations out of the way before taking locks
	 * and adding the nce.
	 */
	nce = kmem_cache_alloc(nce_cache, KM_NOSLEEP);
	if (nce == NULL) {
		err = ENOMEM;
		goto err_ret;
	}
	if (ncec->ncec_lladdr != NULL ||
	    ill->ill_net_type == IRE_IF_NORESOLVER) {
		dlur_mp = ill_dlur_gen(ncec->ncec_lladdr,
		    ill->ill_phys_addr_length, ill->ill_sap,
		    ill->ill_sap_length);
		if (dlur_mp == NULL) {
			err = ENOMEM;
			goto err_ret;
		}
	}

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
	if (!NCE_MYADDR(ncec) &&
	    (ill->ill_state_flags & ILL_DOWN_IN_PROGRESS)) {
		mutex_exit(&ill->ill_lock);
		DTRACE_PROBE1(nce__add__on__down__ill, ncec_t *, ncec);
		err = EINVAL;
		goto err_ret;
	}
	/*
	 * Acquire the ncec_lock even before adding the ncec to the list
	 * so that it cannot get deleted after the ncec is added, but
	 * before we add the nce.
	 */
	mutex_enter(&ncec->ncec_lock);
	if ((ncec->ncec_next = *ncep) != NULL)
		ncec->ncec_next->ncec_ptpn = &ncec->ncec_next;
	*ncep = ncec;
	ncec->ncec_ptpn = ncep;

	/* Bump up the number of ncec's referencing this ill */
	DTRACE_PROBE3(ill__incr__cnt, (ill_t *), ill,
	    (char *), "ncec", (void *), ncec);
	ill->ill_ncec_cnt++;
	/*
	 * Since we hold the ncec_lock at this time, the ncec cannot be
	 * condemned, and we can safely add the nce.
	 */
	*retnce = nce_add_impl(ill, ncec, nce, dlur_mp);
	mutex_exit(&ncec->ncec_lock);
	mutex_exit(&ill->ill_lock);

	/* caller must trigger fastpath on *retnce */
	return (0);

err_ret:
	if (ncec != NULL)
		kmem_cache_free(ncec_cache, ncec);
	if (nce != NULL)
		kmem_cache_free(nce_cache, nce);
	freemsg(dlur_mp);
	if (template != NULL)
		kmem_free(template, ill->ill_phys_addr_length);
	return (err);
}

/*
 * take a ref on the nce
 */
void
nce_refhold(nce_t *nce)
{
	mutex_enter(&nce->nce_lock);
	nce->nce_refcnt++;
	ASSERT((nce)->nce_refcnt != 0);
	mutex_exit(&nce->nce_lock);
}

/*
 * release a ref on the nce; In general, this
 * cannot be called with locks held because nce_inactive
 * may result in nce_inactive which will take the ill_lock,
 * do ipif_ill_refrele_tail etc. Thus the one exception
 * where this can be called with locks held is when the caller
 * is certain that the nce_refcnt is sufficient to prevent
 * the invocation of nce_inactive.
 */
void
nce_refrele(nce_t *nce)
{
	ASSERT((nce)->nce_refcnt != 0);
	mutex_enter(&nce->nce_lock);
	if (--nce->nce_refcnt == 0)
		nce_inactive(nce); /* destroys the mutex */
	else
		mutex_exit(&nce->nce_lock);
}

/*
 * free the nce after all refs have gone away.
 */
static void
nce_inactive(nce_t *nce)
{
	ill_t *ill = nce->nce_ill;

	ASSERT(nce->nce_refcnt == 0);

	ncec_refrele_notr(nce->nce_common);
	nce->nce_common = NULL;
	freemsg(nce->nce_fp_mp);
	freemsg(nce->nce_dlur_mp);

	mutex_enter(&ill->ill_lock);
	DTRACE_PROBE3(ill__decr__cnt, (ill_t *), ill,
	    (char *), "nce", (void *), nce);
	ill->ill_nce_cnt--;
	nce->nce_ill = NULL;
	/*
	 * If the number of ncec's associated with this ill have dropped
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
	kmem_cache_free(nce_cache, nce);
}

/*
 * Add an nce to the ill_nce list.
 */
static nce_t *
nce_add_impl(ill_t *ill, ncec_t *ncec, nce_t *nce, mblk_t *dlur_mp)
{
	bzero(nce, sizeof (*nce));
	mutex_init(&nce->nce_lock, NULL, MUTEX_DEFAULT, NULL);
	nce->nce_common = ncec;
	nce->nce_addr = ncec->ncec_addr;
	nce->nce_ill = ill;
	DTRACE_PROBE3(ill__incr__cnt, (ill_t *), ill,
	    (char *), "nce", (void *), nce);
	ill->ill_nce_cnt++;

	nce->nce_refcnt = 1; /* for the thread */
	ncec->ncec_refcnt++; /* want ncec_refhold_locked_notr(ncec) */
	nce->nce_dlur_mp = dlur_mp;

	/* add nce to the ill's fastpath list.  */
	nce->nce_refcnt++; /* for the list */
	list_insert_head(&ill->ill_nce, nce);
	return (nce);
}

static nce_t *
nce_add(ill_t *ill, ncec_t *ncec)
{
	nce_t	*nce;
	mblk_t	*dlur_mp = NULL;

	ASSERT(MUTEX_HELD(&ill->ill_lock));
	ASSERT(MUTEX_HELD(&ncec->ncec_lock));

	nce = kmem_cache_alloc(nce_cache, KM_NOSLEEP);
	if (nce == NULL)
		return (NULL);
	if (ncec->ncec_lladdr != NULL ||
	    ill->ill_net_type == IRE_IF_NORESOLVER) {
		dlur_mp = ill_dlur_gen(ncec->ncec_lladdr,
		    ill->ill_phys_addr_length, ill->ill_sap,
		    ill->ill_sap_length);
		if (dlur_mp == NULL) {
			kmem_cache_free(nce_cache, nce);
			return (NULL);
		}
	}
	return (nce_add_impl(ill, ncec, nce, dlur_mp));
}

/*
 * remove the nce from the ill_faspath list
 */
void
nce_delete(nce_t *nce)
{
	ill_t	*ill = nce->nce_ill;

	ASSERT(MUTEX_HELD(&ill->ill_lock));

	mutex_enter(&nce->nce_lock);
	if (nce->nce_is_condemned) {
		/*
		 * some other thread has removed this nce from the ill_nce list
		 */
		mutex_exit(&nce->nce_lock);
		return;
	}
	nce->nce_is_condemned = B_TRUE;
	mutex_exit(&nce->nce_lock);

	list_remove(&ill->ill_nce, nce);
	/*
	 * even though we are holding the ill_lock, it is ok to
	 * call nce_refrele here because we know that we should have
	 * at least 2 refs on the nce: one for the thread, and one
	 * for the list. The refrele below will release the one for
	 * the list.
	 */
	nce_refrele(nce);
}

nce_t *
nce_lookup(ill_t *ill, const in6_addr_t *addr)
{
	nce_t *nce = NULL;

	ASSERT(ill != NULL);
	ASSERT(MUTEX_HELD(&ill->ill_lock));

	for (nce = list_head(&ill->ill_nce); nce != NULL;
	    nce = list_next(&ill->ill_nce, nce)) {
		if (IN6_ARE_ADDR_EQUAL(&nce->nce_addr, addr))
			break;
	}

	/*
	 * if we found the nce on the ill_nce list while holding
	 * the ill_lock, then it cannot be condemned yet.
	 */
	if (nce != NULL) {
		ASSERT(!nce->nce_is_condemned);
		nce_refhold(nce);
	}
	return (nce);
}

/*
 * Walk the ill_nce list on ill. The callback function func() cannot perform
 * any destructive actions.
 */
static void
nce_walk_common(ill_t *ill, pfi_t func, void *arg)
{
	nce_t *nce = NULL, *nce_next;

	ASSERT(MUTEX_HELD(&ill->ill_lock));
	for (nce = list_head(&ill->ill_nce); nce != NULL; ) {
		nce_next = list_next(&ill->ill_nce, nce);
		if (func(ill, nce, arg) != 0)
			break;
		nce = nce_next;
	}
}

void
nce_walk(ill_t *ill, pfi_t func, void *arg)
{
	mutex_enter(&ill->ill_lock);
	nce_walk_common(ill, func, arg);
	mutex_exit(&ill->ill_lock);
}

void
nce_flush(ill_t *ill, boolean_t flushall)
{
	nce_t *nce, *nce_next;
	list_t dead;

	list_create(&dead, sizeof (nce_t), offsetof(nce_t, nce_node));
	mutex_enter(&ill->ill_lock);
	for (nce = list_head(&ill->ill_nce); nce != NULL; ) {
		nce_next = list_next(&ill->ill_nce, nce);
		if (!flushall && NCE_PUBLISH(nce->nce_common)) {
			nce = nce_next;
			continue;
		}
		/*
		 * nce_delete requires that the caller should either not
		 * be holding locks, or should hold a ref to ensure that
		 * we wont hit ncec_inactive. So take a ref and clean up
		 * after the list is flushed.
		 */
		nce_refhold(nce);
		nce_delete(nce);
		list_insert_tail(&dead, nce);
		nce = nce_next;
	}
	mutex_exit(&ill->ill_lock);
	while ((nce = list_head(&dead)) != NULL) {
		list_remove(&dead, nce);
		nce_refrele(nce);
	}
	ASSERT(list_is_empty(&dead));
	list_destroy(&dead);
}

/* Return an interval that is anywhere in the [1 .. intv] range */
static clock_t
nce_fuzz_interval(clock_t intv, boolean_t initial_time)
{
	clock_t rnd, frac;

	(void) random_get_pseudo_bytes((uint8_t *)&rnd, sizeof (rnd));
	/* Note that clock_t is signed; must chop off bits */
	rnd &= (1ul << (NBBY * sizeof (rnd) - 1)) - 1;
	if (initial_time) {
		if (intv <= 0)
			intv = 1;
		else
			intv = (rnd % intv) + 1;
	} else {
		/* Compute 'frac' as 20% of the configured interval */
		if ((frac = intv / 5) <= 1)
			frac = 2;
		/* Set intv randomly in the range [intv-frac .. intv+frac] */
		if ((intv = intv - frac + rnd % (2 * frac + 1)) <= 0)
		intv = 1;
	}
	return (intv);
}

void
nce_resolv_ipmp_ok(ncec_t *ncec)
{
	mblk_t *mp;
	uint_t pkt_len;
	iaflags_t ixaflags = IXAF_NO_TRACE;
	nce_t *under_nce;
	ill_t	*ill = ncec->ncec_ill;
	boolean_t isv6 = (ncec->ncec_ipversion == IPV6_VERSION);
	ipif_t *src_ipif = NULL;
	ip_stack_t *ipst = ill->ill_ipst;
	ill_t *send_ill;
	uint_t nprobes;

	ASSERT(IS_IPMP(ill));

	mutex_enter(&ncec->ncec_lock);
	nprobes = ncec->ncec_nprobes;
	mp = ncec->ncec_qd_mp;
	ncec->ncec_qd_mp = NULL;
	ncec->ncec_nprobes = 0;
	mutex_exit(&ncec->ncec_lock);

	while (mp != NULL) {
		mblk_t *nxt_mp;

		nxt_mp = mp->b_next;
		mp->b_next = NULL;
		if (isv6) {
			ip6_t *ip6h = (ip6_t *)mp->b_rptr;

			pkt_len = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
			src_ipif = ipif_lookup_addr_nondup_v6(&ip6h->ip6_src,
			    ill, ALL_ZONES, ipst);
		} else {
			ipha_t *ipha = (ipha_t *)mp->b_rptr;

			ixaflags |= IXAF_IS_IPV4;
			pkt_len = ntohs(ipha->ipha_length);
			src_ipif = ipif_lookup_addr_nondup(ipha->ipha_src,
			    ill, ALL_ZONES, ipst);
		}

		/*
		 * find a new nce based on an under_ill. The first IPMP probe
		 * packet gets queued, so we could still find a src_ipif that
		 * matches an IPMP test address.
		 */
		if (src_ipif == NULL || IS_IPMP(src_ipif->ipif_ill)) {
			/*
			 * if src_ipif is null, this could be either a
			 * forwarded packet or a probe whose src got deleted.
			 * We identify the former case by looking for the
			 * ncec_nprobes: the first ncec_nprobes packets are
			 * probes;
			 */
			if (src_ipif == NULL && nprobes > 0)
				goto drop_pkt;

			/*
			 * For forwarded packets, we use the ipmp rotor
			 * to find send_ill.
			 */
			send_ill = ipmp_ill_hold_xmit_ill(ncec->ncec_ill,
			    B_TRUE);
		} else {
			send_ill = src_ipif->ipif_ill;
			ill_refhold(send_ill);
		}

		DTRACE_PROBE4(nce__resolve__ipmp, (mblk_t *), mp,
		    (ncec_t *), ncec, (ipif_t *),
		    src_ipif, (ill_t *), send_ill);

		if (send_ill == NULL) {
			if (src_ipif != NULL)
				ipif_refrele(src_ipif);
			goto drop_pkt;
		}
		/* create an under_nce on send_ill */
		rw_enter(&ipst->ips_ill_g_lock, RW_READER);
		if (IS_IN_SAME_ILLGRP(send_ill, ncec->ncec_ill))
			under_nce = nce_fastpath_create(send_ill, ncec);
		else
			under_nce = NULL;
		rw_exit(&ipst->ips_ill_g_lock);
		if (under_nce != NULL && NCE_ISREACHABLE(ncec))
			nce_fastpath_trigger(under_nce);

		ill_refrele(send_ill);
		if (src_ipif != NULL)
			ipif_refrele(src_ipif);

		if (under_nce != NULL) {
			(void) ip_xmit(mp, under_nce, ixaflags, pkt_len, 0,
			    ALL_ZONES, 0, NULL);
			nce_refrele(under_nce);
			if (nprobes > 0)
				nprobes--;
			mp = nxt_mp;
			continue;
		}
drop_pkt:
		if (isv6) {
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsOutDiscards);
		} else {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsOutDiscards);
		}
		ip_drop_output("ipIfStatsOutDiscards - no under_ill", mp, NULL);
		freemsg(mp);
		if (nprobes > 0)
			nprobes--;
		mp = nxt_mp;
	}
	ncec_cb_dispatch(ncec); /* complete callbacks */
}
