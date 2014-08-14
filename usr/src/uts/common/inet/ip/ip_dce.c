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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/zone.h>
#include <sys/ddi.h>
#include <sys/disp.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/atomic.h>
#include <sys/callb.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/snmpcom.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip6_asp.h>
#include <inet/ip_multi.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/ip_ndp.h>
#include <inet/ipclassifier.h>
#include <inet/ip_listutils.h>

#include <sys/sunddi.h>

/*
 * Routines for handling destination cache entries.
 * There is always one DCEF_DEFAULT for each ip_stack_t created at init time.
 * That entry holds both the IP ident value and the dce generation number.
 *
 * Any time a DCE is changed significantly (different path MTU, but NOT
 * different ULP info!), the dce_generation number is increased.
 * Also, when a new DCE is created, the dce_generation number in the default
 * DCE is bumped. That allows the dce_t information to be cached efficiently
 * as long as the entity caching the dce_t also caches the dce_generation,
 * and compares the cached generation to detect any changes.
 * Furthermore, when a DCE is deleted, if there are any outstanding references
 * to the DCE it will be marked as condemned. The condemned mark is
 * a designated generation number which is never otherwise used, hence
 * the single comparison with the generation number captures that as well.
 *
 * An example of code which caches is as follows:
 *
 *	if (mystruct->my_dce_generation != mystruct->my_dce->dce_generation) {
 *		The DCE has changed
 *		mystruct->my_dce = dce_lookup_pkt(mp, ixa,
 *		    &mystruct->my_dce_generation);
 *		Not needed in practice, since we have the default DCE:
 *		if (DCE_IS_CONDEMNED(mystruct->my_dce))
 *			return failure;
 *	}
 *
 * Note that for IPv6 link-local addresses we record the ifindex since the
 * link-locals are not globally unique.
 */

/*
 * Hash bucket structure for DCEs
 */
typedef struct dcb_s {
	krwlock_t	dcb_lock;
	uint32_t	dcb_cnt;
	dce_t		*dcb_dce;
} dcb_t;

static void	dce_delete_locked(dcb_t *, dce_t *);
static void	dce_make_condemned(dce_t *);

static kmem_cache_t *dce_cache;
static kthread_t *dce_reclaim_thread;
static kmutex_t dce_reclaim_lock;
static kcondvar_t dce_reclaim_cv;
static int dce_reclaim_shutdown;

/* Global so it can be tuned in /etc/system. This must be a power of two. */
uint_t ip_dce_hash_size = 1024;

/* The time in seconds between executions of the IP DCE reclaim worker. */
uint_t ip_dce_reclaim_interval = 60;

/* The factor of the DCE threshold at which to start hard reclaims */
uint_t ip_dce_reclaim_threshold_hard = 2;

/* Operates on a uint64_t */
#define	RANDOM_HASH(p) ((p) ^ ((p)>>16) ^ ((p)>>32) ^ ((p)>>48))

/*
 * Reclaim a fraction of dce's in the dcb.
 * For now we have a higher probability to delete DCEs without DCE_PMTU.
 */
static void
dcb_reclaim(dcb_t *dcb, ip_stack_t *ipst, uint_t fraction)
{
	uint_t	fraction_pmtu = fraction*4;
	uint_t	hash;
	dce_t	*dce, *nextdce;
	hrtime_t seed = gethrtime();
	uint_t	retained = 0;
	uint_t	max = ipst->ips_ip_dce_reclaim_threshold;

	max *= ip_dce_reclaim_threshold_hard;

	rw_enter(&dcb->dcb_lock, RW_WRITER);
	for (dce = dcb->dcb_dce; dce != NULL; dce = nextdce) {
		nextdce = dce->dce_next;
		/* Clear DCEF_PMTU if the pmtu is too old */
		mutex_enter(&dce->dce_lock);
		if ((dce->dce_flags & DCEF_PMTU) &&
		    TICK_TO_SEC(ddi_get_lbolt64()) - dce->dce_last_change_time >
		    ipst->ips_ip_pathmtu_interval) {
			dce->dce_flags &= ~DCEF_PMTU;
			mutex_exit(&dce->dce_lock);
			dce_increment_generation(dce);
		} else {
			mutex_exit(&dce->dce_lock);
		}

		if (max == 0 || retained < max) {
			hash = RANDOM_HASH((uint64_t)((uintptr_t)dce | seed));

			if (dce->dce_flags & DCEF_PMTU) {
				if (hash % fraction_pmtu != 0) {
					retained++;
					continue;
				}
			} else {
				if (hash % fraction != 0) {
					retained++;
					continue;
				}
			}
		}

		IP_STAT(ipst, ip_dce_reclaim_deleted);
		dce_delete_locked(dcb, dce);
		dce_refrele(dce);
	}
	rw_exit(&dcb->dcb_lock);
}

/*
 * kmem_cache callback to free up memory.
 *
 */
static void
ip_dce_reclaim_stack(ip_stack_t *ipst)
{
	int	i;

	IP_STAT(ipst, ip_dce_reclaim_calls);
	for (i = 0; i < ipst->ips_dce_hashsize; i++) {
		dcb_reclaim(&ipst->ips_dce_hash_v4[i], ipst,
		    ipst->ips_ip_dce_reclaim_fraction);

		dcb_reclaim(&ipst->ips_dce_hash_v6[i], ipst,
		    ipst->ips_ip_dce_reclaim_fraction);
	}

	/*
	 * Walk all CONNs that can have a reference on an ire, nce or dce.
	 * Get them to update any stale references to drop any refholds they
	 * have.
	 */
	ipcl_walk(conn_ixa_cleanup, (void *)B_FALSE, ipst);
}

/*
 * Called by dce_reclaim_worker() below, and no one else.  Typically this will
 * mean that the number of entries in the hash buckets has exceeded a tunable
 * threshold.
 */
static void
ip_dce_reclaim(void)
{
	netstack_handle_t nh;
	netstack_t *ns;
	ip_stack_t *ipst;

	ASSERT(curthread == dce_reclaim_thread);

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
		if (atomic_swap_uint(&ipst->ips_dce_reclaim_needed, 0) != 0)
			ip_dce_reclaim_stack(ipst);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
}

/* ARGSUSED */
static void
dce_reclaim_worker(void *arg)
{
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, &dce_reclaim_lock, callb_generic_cpr,
	    "dce_reclaim_worker");

	mutex_enter(&dce_reclaim_lock);
	while (!dce_reclaim_shutdown) {
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		(void) cv_timedwait(&dce_reclaim_cv, &dce_reclaim_lock,
		    ddi_get_lbolt() + ip_dce_reclaim_interval * hz);
		CALLB_CPR_SAFE_END(&cprinfo, &dce_reclaim_lock);

		if (dce_reclaim_shutdown)
			break;

		mutex_exit(&dce_reclaim_lock);
		ip_dce_reclaim();
		mutex_enter(&dce_reclaim_lock);
	}

	ASSERT(MUTEX_HELD(&dce_reclaim_lock));
	dce_reclaim_thread = NULL;
	dce_reclaim_shutdown = 0;
	cv_broadcast(&dce_reclaim_cv);
	CALLB_CPR_EXIT(&cprinfo);	/* drops the lock */

	thread_exit();
}

void
dce_g_init(void)
{
	dce_cache = kmem_cache_create("dce_cache",
	    sizeof (dce_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	mutex_init(&dce_reclaim_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&dce_reclaim_cv, NULL, CV_DEFAULT, NULL);

	dce_reclaim_thread = thread_create(NULL, 0, dce_reclaim_worker,
	    NULL, 0, &p0, TS_RUN, minclsyspri);
}

void
dce_g_destroy(void)
{
	mutex_enter(&dce_reclaim_lock);
	dce_reclaim_shutdown = 1;
	cv_signal(&dce_reclaim_cv);
	while (dce_reclaim_thread != NULL)
		cv_wait(&dce_reclaim_cv, &dce_reclaim_lock);
	mutex_exit(&dce_reclaim_lock);

	cv_destroy(&dce_reclaim_cv);
	mutex_destroy(&dce_reclaim_lock);

	kmem_cache_destroy(dce_cache);
}

/*
 * Allocate a default DCE and a hash table for per-IP address DCEs
 */
void
dce_stack_init(ip_stack_t *ipst)
{
	int	i;

	ipst->ips_dce_default = kmem_cache_alloc(dce_cache, KM_SLEEP);
	bzero(ipst->ips_dce_default, sizeof (dce_t));
	ipst->ips_dce_default->dce_flags = DCEF_DEFAULT;
	ipst->ips_dce_default->dce_generation = DCE_GENERATION_INITIAL;
	ipst->ips_dce_default->dce_last_change_time =
	    TICK_TO_SEC(ddi_get_lbolt64());
	ipst->ips_dce_default->dce_refcnt = 1;	/* Should never go away */
	ipst->ips_dce_default->dce_ipst = ipst;

	/* This must be a power of two since we are using IRE_ADDR_HASH macro */
	ipst->ips_dce_hashsize = ip_dce_hash_size;
	ipst->ips_dce_hash_v4 = kmem_zalloc(ipst->ips_dce_hashsize *
	    sizeof (dcb_t), KM_SLEEP);
	ipst->ips_dce_hash_v6 = kmem_zalloc(ipst->ips_dce_hashsize *
	    sizeof (dcb_t), KM_SLEEP);
	for (i = 0; i < ipst->ips_dce_hashsize; i++) {
		rw_init(&ipst->ips_dce_hash_v4[i].dcb_lock, NULL, RW_DEFAULT,
		    NULL);
		rw_init(&ipst->ips_dce_hash_v6[i].dcb_lock, NULL, RW_DEFAULT,
		    NULL);
	}
}

void
dce_stack_destroy(ip_stack_t *ipst)
{
	int i;
	for (i = 0; i < ipst->ips_dce_hashsize; i++) {
		rw_destroy(&ipst->ips_dce_hash_v4[i].dcb_lock);
		rw_destroy(&ipst->ips_dce_hash_v6[i].dcb_lock);
	}
	kmem_free(ipst->ips_dce_hash_v4,
	    ipst->ips_dce_hashsize * sizeof (dcb_t));
	ipst->ips_dce_hash_v4 = NULL;
	kmem_free(ipst->ips_dce_hash_v6,
	    ipst->ips_dce_hashsize * sizeof (dcb_t));
	ipst->ips_dce_hash_v6 = NULL;
	ipst->ips_dce_hashsize = 0;

	ASSERT(ipst->ips_dce_default->dce_refcnt == 1);
	kmem_cache_free(dce_cache, ipst->ips_dce_default);
	ipst->ips_dce_default = NULL;
}

/* When any DCE is good enough */
dce_t *
dce_get_default(ip_stack_t *ipst)
{
	dce_t		*dce;

	dce = ipst->ips_dce_default;
	dce_refhold(dce);
	return (dce);
}

/*
 * Generic for IPv4 and IPv6.
 *
 * Used by callers that need to cache e.g., the datapath
 * Returns the generation number in the last argument.
 */
dce_t *
dce_lookup_pkt(mblk_t *mp, ip_xmit_attr_t *ixa, uint_t *generationp)
{
	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		/*
		 * If we have a source route we need to look for the final
		 * destination in the source route option.
		 */
		ipaddr_t final_dst;
		ipha_t *ipha = (ipha_t *)mp->b_rptr;

		final_dst = ip_get_dst(ipha);
		return (dce_lookup_v4(final_dst, ixa->ixa_ipst, generationp));
	} else {
		uint_t ifindex;
		/*
		 * If we have a routing header we need to look for the final
		 * destination in the routing extension header.
		 */
		in6_addr_t final_dst;
		ip6_t *ip6h = (ip6_t *)mp->b_rptr;

		final_dst = ip_get_dst_v6(ip6h, mp, NULL);
		ifindex = 0;
		if (IN6_IS_ADDR_LINKSCOPE(&final_dst) && ixa->ixa_nce != NULL) {
			ifindex = ixa->ixa_nce->nce_common->ncec_ill->
			    ill_phyint->phyint_ifindex;
		}
		return (dce_lookup_v6(&final_dst, ifindex, ixa->ixa_ipst,
		    generationp));
	}
}

/*
 * Used by callers that need to cache e.g., the datapath
 * Returns the generation number in the last argument.
 */
dce_t *
dce_lookup_v4(ipaddr_t dst, ip_stack_t *ipst, uint_t *generationp)
{
	uint_t		hash;
	dcb_t		*dcb;
	dce_t		*dce;

	/* Set *generationp before dropping the lock(s) that allow additions */
	if (generationp != NULL)
		*generationp = ipst->ips_dce_default->dce_generation;

	hash = IRE_ADDR_HASH(dst, ipst->ips_dce_hashsize);
	dcb = &ipst->ips_dce_hash_v4[hash];
	rw_enter(&dcb->dcb_lock, RW_READER);
	for (dce = dcb->dcb_dce; dce != NULL; dce = dce->dce_next) {
		if (dce->dce_v4addr == dst) {
			mutex_enter(&dce->dce_lock);
			if (!DCE_IS_CONDEMNED(dce)) {
				dce_refhold(dce);
				if (generationp != NULL)
					*generationp = dce->dce_generation;
				mutex_exit(&dce->dce_lock);
				rw_exit(&dcb->dcb_lock);
				return (dce);
			}
			mutex_exit(&dce->dce_lock);
		}
	}
	rw_exit(&dcb->dcb_lock);
	/* Not found */
	dce = ipst->ips_dce_default;
	dce_refhold(dce);
	return (dce);
}

/*
 * Used by callers that need to cache e.g., the datapath
 * Returns the generation number in the last argument.
 * ifindex should only be set for link-locals
 */
dce_t *
dce_lookup_v6(const in6_addr_t *dst, uint_t ifindex, ip_stack_t *ipst,
    uint_t *generationp)
{
	uint_t		hash;
	dcb_t		*dcb;
	dce_t		*dce;

	/* Set *generationp before dropping the lock(s) that allow additions */
	if (generationp != NULL)
		*generationp = ipst->ips_dce_default->dce_generation;

	hash = IRE_ADDR_HASH_V6(*dst, ipst->ips_dce_hashsize);
	dcb = &ipst->ips_dce_hash_v6[hash];
	rw_enter(&dcb->dcb_lock, RW_READER);
	for (dce = dcb->dcb_dce; dce != NULL; dce = dce->dce_next) {
		if (IN6_ARE_ADDR_EQUAL(&dce->dce_v6addr, dst) &&
		    dce->dce_ifindex == ifindex) {
			mutex_enter(&dce->dce_lock);
			if (!DCE_IS_CONDEMNED(dce)) {
				dce_refhold(dce);
				if (generationp != NULL)
					*generationp = dce->dce_generation;
				mutex_exit(&dce->dce_lock);
				rw_exit(&dcb->dcb_lock);
				return (dce);
			}
			mutex_exit(&dce->dce_lock);
		}
	}
	rw_exit(&dcb->dcb_lock);
	/* Not found */
	dce = ipst->ips_dce_default;
	dce_refhold(dce);
	return (dce);
}

/*
 * Atomically looks for a non-default DCE, and if not found tries to create one.
 * If there is no memory it returns NULL.
 * When an entry is created we increase the generation number on
 * the default DCE so that conn_ip_output will detect there is a new DCE.
 */
dce_t *
dce_lookup_and_add_v4(ipaddr_t dst, ip_stack_t *ipst)
{
	uint_t		hash;
	dcb_t		*dcb;
	dce_t		*dce;

	hash = IRE_ADDR_HASH(dst, ipst->ips_dce_hashsize);
	dcb = &ipst->ips_dce_hash_v4[hash];
	/*
	 * Assuming that we get fairly even distribution across all of the
	 * buckets, once one bucket is overly full, prune the whole cache.
	 */
	if (dcb->dcb_cnt > ipst->ips_ip_dce_reclaim_threshold)
		atomic_or_uint(&ipst->ips_dce_reclaim_needed, 1);
	rw_enter(&dcb->dcb_lock, RW_WRITER);
	for (dce = dcb->dcb_dce; dce != NULL; dce = dce->dce_next) {
		if (dce->dce_v4addr == dst) {
			mutex_enter(&dce->dce_lock);
			if (!DCE_IS_CONDEMNED(dce)) {
				dce_refhold(dce);
				mutex_exit(&dce->dce_lock);
				rw_exit(&dcb->dcb_lock);
				return (dce);
			}
			mutex_exit(&dce->dce_lock);
		}
	}
	dce = kmem_cache_alloc(dce_cache, KM_NOSLEEP);
	if (dce == NULL) {
		rw_exit(&dcb->dcb_lock);
		return (NULL);
	}
	bzero(dce, sizeof (dce_t));
	dce->dce_ipst = ipst;	/* No netstack_hold */
	dce->dce_v4addr = dst;
	dce->dce_generation = DCE_GENERATION_INITIAL;
	dce->dce_ipversion = IPV4_VERSION;
	dce->dce_last_change_time = TICK_TO_SEC(ddi_get_lbolt64());
	dce_refhold(dce);	/* For the hash list */

	/* Link into list */
	if (dcb->dcb_dce != NULL)
		dcb->dcb_dce->dce_ptpn = &dce->dce_next;
	dce->dce_next = dcb->dcb_dce;
	dce->dce_ptpn = &dcb->dcb_dce;
	dcb->dcb_dce = dce;
	dce->dce_bucket = dcb;
	atomic_inc_32(&dcb->dcb_cnt);
	dce_refhold(dce);	/* For the caller */
	rw_exit(&dcb->dcb_lock);

	/* Initialize dce_ident to be different than for the last packet */
	dce->dce_ident = ipst->ips_dce_default->dce_ident + 1;

	dce_increment_generation(ipst->ips_dce_default);
	return (dce);
}

/*
 * Atomically looks for a non-default DCE, and if not found tries to create one.
 * If there is no memory it returns NULL.
 * When an entry is created we increase the generation number on
 * the default DCE so that conn_ip_output will detect there is a new DCE.
 * ifindex should only be used with link-local addresses.
 */
dce_t *
dce_lookup_and_add_v6(const in6_addr_t *dst, uint_t ifindex, ip_stack_t *ipst)
{
	uint_t		hash;
	dcb_t		*dcb;
	dce_t		*dce;

	/* We should not create entries for link-locals w/o an ifindex */
	ASSERT(!(IN6_IS_ADDR_LINKSCOPE(dst)) || ifindex != 0);

	hash = IRE_ADDR_HASH_V6(*dst, ipst->ips_dce_hashsize);
	dcb = &ipst->ips_dce_hash_v6[hash];
	/*
	 * Assuming that we get fairly even distribution across all of the
	 * buckets, once one bucket is overly full, prune the whole cache.
	 */
	if (dcb->dcb_cnt > ipst->ips_ip_dce_reclaim_threshold)
		atomic_or_uint(&ipst->ips_dce_reclaim_needed, 1);
	rw_enter(&dcb->dcb_lock, RW_WRITER);
	for (dce = dcb->dcb_dce; dce != NULL; dce = dce->dce_next) {
		if (IN6_ARE_ADDR_EQUAL(&dce->dce_v6addr, dst) &&
		    dce->dce_ifindex == ifindex) {
			mutex_enter(&dce->dce_lock);
			if (!DCE_IS_CONDEMNED(dce)) {
				dce_refhold(dce);
				mutex_exit(&dce->dce_lock);
				rw_exit(&dcb->dcb_lock);
				return (dce);
			}
			mutex_exit(&dce->dce_lock);
		}
	}

	dce = kmem_cache_alloc(dce_cache, KM_NOSLEEP);
	if (dce == NULL) {
		rw_exit(&dcb->dcb_lock);
		return (NULL);
	}
	bzero(dce, sizeof (dce_t));
	dce->dce_ipst = ipst;	/* No netstack_hold */
	dce->dce_v6addr = *dst;
	dce->dce_ifindex = ifindex;
	dce->dce_generation = DCE_GENERATION_INITIAL;
	dce->dce_ipversion = IPV6_VERSION;
	dce->dce_last_change_time = TICK_TO_SEC(ddi_get_lbolt64());
	dce_refhold(dce);	/* For the hash list */

	/* Link into list */
	if (dcb->dcb_dce != NULL)
		dcb->dcb_dce->dce_ptpn = &dce->dce_next;
	dce->dce_next = dcb->dcb_dce;
	dce->dce_ptpn = &dcb->dcb_dce;
	dcb->dcb_dce = dce;
	dce->dce_bucket = dcb;
	atomic_inc_32(&dcb->dcb_cnt);
	dce_refhold(dce);	/* For the caller */
	rw_exit(&dcb->dcb_lock);

	/* Initialize dce_ident to be different than for the last packet */
	dce->dce_ident = ipst->ips_dce_default->dce_ident + 1;
	dce_increment_generation(ipst->ips_dce_default);
	return (dce);
}

/*
 * Set/update uinfo. Creates a per-destination dce if none exists.
 *
 * Note that we do not bump the generation number here.
 * New connections will find the new uinfo.
 *
 * The only use of this (tcp, sctp using iulp_t) is to set rtt+rtt_sd.
 */
static void
dce_setuinfo(dce_t *dce, iulp_t *uinfo)
{
	/*
	 * Update the round trip time estimate and/or the max frag size
	 * and/or the slow start threshold.
	 *
	 * We serialize multiple advises using dce_lock.
	 */
	mutex_enter(&dce->dce_lock);
	/* Gard against setting to zero */
	if (uinfo->iulp_rtt != 0) {
		/*
		 * If there is no old cached values, initialize them
		 * conservatively.  Set them to be (1.5 * new value).
		 */
		if (dce->dce_uinfo.iulp_rtt != 0) {
			dce->dce_uinfo.iulp_rtt = (dce->dce_uinfo.iulp_rtt +
			    uinfo->iulp_rtt) >> 1;
		} else {
			dce->dce_uinfo.iulp_rtt = uinfo->iulp_rtt +
			    (uinfo->iulp_rtt >> 1);
		}
		if (dce->dce_uinfo.iulp_rtt_sd != 0) {
			dce->dce_uinfo.iulp_rtt_sd =
			    (dce->dce_uinfo.iulp_rtt_sd +
			    uinfo->iulp_rtt_sd) >> 1;
		} else {
			dce->dce_uinfo.iulp_rtt_sd = uinfo->iulp_rtt_sd +
			    (uinfo->iulp_rtt_sd >> 1);
		}
	}
	if (uinfo->iulp_mtu != 0) {
		if (dce->dce_flags & DCEF_PMTU) {
			dce->dce_pmtu = MIN(uinfo->iulp_mtu, dce->dce_pmtu);
		} else {
			dce->dce_pmtu = MIN(uinfo->iulp_mtu, IP_MAXPACKET);
			dce->dce_flags |= DCEF_PMTU;
		}
		dce->dce_last_change_time = TICK_TO_SEC(ddi_get_lbolt64());
	}
	if (uinfo->iulp_ssthresh != 0) {
		if (dce->dce_uinfo.iulp_ssthresh != 0)
			dce->dce_uinfo.iulp_ssthresh =
			    (uinfo->iulp_ssthresh +
			    dce->dce_uinfo.iulp_ssthresh) >> 1;
		else
			dce->dce_uinfo.iulp_ssthresh = uinfo->iulp_ssthresh;
	}
	/* We have uinfo for sure */
	dce->dce_flags |= DCEF_UINFO;
	mutex_exit(&dce->dce_lock);
}


int
dce_update_uinfo_v4(ipaddr_t dst, iulp_t *uinfo, ip_stack_t *ipst)
{
	dce_t *dce;

	dce = dce_lookup_and_add_v4(dst, ipst);
	if (dce == NULL)
		return (ENOMEM);

	dce_setuinfo(dce, uinfo);
	dce_refrele(dce);
	return (0);
}

int
dce_update_uinfo_v6(const in6_addr_t *dst, uint_t ifindex, iulp_t *uinfo,
    ip_stack_t *ipst)
{
	dce_t *dce;

	dce = dce_lookup_and_add_v6(dst, ifindex, ipst);
	if (dce == NULL)
		return (ENOMEM);

	dce_setuinfo(dce, uinfo);
	dce_refrele(dce);
	return (0);
}

/* Common routine for IPv4 and IPv6 */
int
dce_update_uinfo(const in6_addr_t *dst, uint_t ifindex, iulp_t *uinfo,
    ip_stack_t *ipst)
{
	ipaddr_t dst4;

	if (IN6_IS_ADDR_V4MAPPED_ANY(dst)) {
		IN6_V4MAPPED_TO_IPADDR(dst, dst4);
		return (dce_update_uinfo_v4(dst4, uinfo, ipst));
	} else {
		return (dce_update_uinfo_v6(dst, ifindex, uinfo, ipst));
	}
}

static void
dce_make_condemned(dce_t *dce)
{
	ip_stack_t	*ipst = dce->dce_ipst;

	mutex_enter(&dce->dce_lock);
	ASSERT(!DCE_IS_CONDEMNED(dce));
	dce->dce_generation = DCE_GENERATION_CONDEMNED;
	mutex_exit(&dce->dce_lock);
	/* Count how many condemned dces for kmem_cache callback */
	atomic_inc_32(&ipst->ips_num_dce_condemned);
}

/*
 * Increment the generation avoiding the special condemned value
 */
void
dce_increment_generation(dce_t *dce)
{
	uint_t generation;

	mutex_enter(&dce->dce_lock);
	if (!DCE_IS_CONDEMNED(dce)) {
		generation = dce->dce_generation + 1;
		if (generation == DCE_GENERATION_CONDEMNED)
			generation = DCE_GENERATION_INITIAL;
		ASSERT(generation != DCE_GENERATION_VERIFY);
		dce->dce_generation = generation;
	}
	mutex_exit(&dce->dce_lock);
}

/*
 * Increment the generation number on all dces that have a path MTU and
 * the default DCE. Used when ill_mtu or ill_mc_mtu changes.
 */
void
dce_increment_all_generations(boolean_t isv6, ip_stack_t *ipst)
{
	int		i;
	dcb_t		*dcb;
	dce_t		*dce;

	for (i = 0; i < ipst->ips_dce_hashsize; i++) {
		if (isv6)
			dcb = &ipst->ips_dce_hash_v6[i];
		else
			dcb = &ipst->ips_dce_hash_v4[i];
		rw_enter(&dcb->dcb_lock, RW_WRITER);
		for (dce = dcb->dcb_dce; dce != NULL; dce = dce->dce_next) {
			if (DCE_IS_CONDEMNED(dce))
				continue;
			dce_increment_generation(dce);
		}
		rw_exit(&dcb->dcb_lock);
	}
	dce_increment_generation(ipst->ips_dce_default);
}

/*
 * Caller needs to do a dce_refrele since we can't do the
 * dce_refrele under dcb_lock.
 */
static void
dce_delete_locked(dcb_t *dcb, dce_t *dce)
{
	dce->dce_bucket = NULL;
	*dce->dce_ptpn = dce->dce_next;
	if (dce->dce_next != NULL)
		dce->dce_next->dce_ptpn = dce->dce_ptpn;
	dce->dce_ptpn = NULL;
	dce->dce_next = NULL;
	atomic_dec_32(&dcb->dcb_cnt);
	dce_make_condemned(dce);
}

static void
dce_inactive(dce_t *dce)
{
	ip_stack_t	*ipst = dce->dce_ipst;

	ASSERT(!(dce->dce_flags & DCEF_DEFAULT));
	ASSERT(dce->dce_ptpn == NULL);
	ASSERT(dce->dce_bucket == NULL);

	/* Count how many condemned dces for kmem_cache callback */
	if (DCE_IS_CONDEMNED(dce))
		atomic_dec_32(&ipst->ips_num_dce_condemned);

	kmem_cache_free(dce_cache, dce);
}

void
dce_refrele(dce_t *dce)
{
	ASSERT(dce->dce_refcnt != 0);
	if (atomic_dec_32_nv(&dce->dce_refcnt) == 0)
		dce_inactive(dce);
}

void
dce_refhold(dce_t *dce)
{
	atomic_inc_32(&dce->dce_refcnt);
	ASSERT(dce->dce_refcnt != 0);
}

/* No tracing support yet hence the same as the above functions */
void
dce_refrele_notr(dce_t *dce)
{
	ASSERT(dce->dce_refcnt != 0);
	if (atomic_dec_32_nv(&dce->dce_refcnt) == 0)
		dce_inactive(dce);
}

void
dce_refhold_notr(dce_t *dce)
{
	atomic_inc_32(&dce->dce_refcnt);
	ASSERT(dce->dce_refcnt != 0);
}

/* Report both the IPv4 and IPv6 DCEs. */
mblk_t *
ip_snmp_get_mib2_ip_dce(queue_t *q, mblk_t *mpctl, ip_stack_t *ipst)
{
	struct opthdr		*optp;
	mblk_t			*mp2ctl;
	dest_cache_entry_t	dest_cache;
	mblk_t			*mp_tail = NULL;
	dce_t			*dce;
	dcb_t			*dcb;
	int			i;
	uint64_t		current_time;

	current_time = TICK_TO_SEC(ddi_get_lbolt64());

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	/* First we do IPv4 entries */
	optp = (struct opthdr *)&mpctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP;
	optp->name = EXPER_IP_DCE;

	for (i = 0; i < ipst->ips_dce_hashsize; i++) {
		dcb = &ipst->ips_dce_hash_v4[i];
		rw_enter(&dcb->dcb_lock, RW_READER);
		for (dce = dcb->dcb_dce; dce != NULL; dce = dce->dce_next) {
			dest_cache.DestIpv4Address = dce->dce_v4addr;
			dest_cache.DestFlags = dce->dce_flags;
			if (dce->dce_flags & DCEF_PMTU)
				dest_cache.DestPmtu = dce->dce_pmtu;
			else
				dest_cache.DestPmtu = 0;
			dest_cache.DestIdent = dce->dce_ident;
			dest_cache.DestIfindex = 0;
			dest_cache.DestAge = current_time -
			    dce->dce_last_change_time;
			if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
			    (char *)&dest_cache, (int)sizeof (dest_cache))) {
				ip1dbg(("ip_snmp_get_mib2_ip_dce: "
				    "failed to allocate %u bytes\n",
				    (uint_t)sizeof (dest_cache)));
			}
		}
		rw_exit(&dcb->dcb_lock);
	}
	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);

	if (mp2ctl == NULL) {
		/* Copymsg failed above */
		return (NULL);
	}

	/* Now for IPv6 */
	mpctl = mp2ctl;
	mp_tail = NULL;
	mp2ctl = copymsg(mpctl);
	optp = (struct opthdr *)&mpctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_IP6;
	optp->name = EXPER_IP_DCE;

	for (i = 0; i < ipst->ips_dce_hashsize; i++) {
		dcb = &ipst->ips_dce_hash_v6[i];
		rw_enter(&dcb->dcb_lock, RW_READER);
		for (dce = dcb->dcb_dce; dce != NULL; dce = dce->dce_next) {
			dest_cache.DestIpv6Address = dce->dce_v6addr;
			dest_cache.DestFlags = dce->dce_flags;
			if (dce->dce_flags & DCEF_PMTU)
				dest_cache.DestPmtu = dce->dce_pmtu;
			else
				dest_cache.DestPmtu = 0;
			dest_cache.DestIdent = dce->dce_ident;
			if (IN6_IS_ADDR_LINKSCOPE(&dce->dce_v6addr))
				dest_cache.DestIfindex = dce->dce_ifindex;
			else
				dest_cache.DestIfindex = 0;
			dest_cache.DestAge = current_time -
			    dce->dce_last_change_time;
			if (!snmp_append_data2(mpctl->b_cont, &mp_tail,
			    (char *)&dest_cache, (int)sizeof (dest_cache))) {
				ip1dbg(("ip_snmp_get_mib2_ip_dce: "
				    "failed to allocate %u bytes\n",
				    (uint_t)sizeof (dest_cache)));
			}
		}
		rw_exit(&dcb->dcb_lock);
	}
	optp->len = (t_uscalar_t)msgdsize(mpctl->b_cont);
	ip3dbg(("ip_snmp_get: level %d, name %d, len %d\n",
	    (int)optp->level, (int)optp->name, (int)optp->len));
	qreply(q, mpctl);

	return (mp2ctl);
}

/*
 * Remove IPv6 DCEs which refer to an ifindex that is going away.
 * This is not required for correctness, but it avoids netstat -d
 * showing stale stuff that will never be used.
 */
void
dce_cleanup(uint_t ifindex, ip_stack_t *ipst)
{
	uint_t	i;
	dcb_t	*dcb;
	dce_t	*dce, *nextdce;

	for (i = 0; i < ipst->ips_dce_hashsize; i++) {
		dcb = &ipst->ips_dce_hash_v6[i];
		rw_enter(&dcb->dcb_lock, RW_WRITER);

		for (dce = dcb->dcb_dce; dce != NULL; dce = nextdce) {
			nextdce = dce->dce_next;
			if (dce->dce_ifindex == ifindex) {
				dce_delete_locked(dcb, dce);
				dce_refrele(dce);
			}
		}
		rw_exit(&dcb->dcb_lock);
	}
}
