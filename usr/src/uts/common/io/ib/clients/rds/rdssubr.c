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

#include <sys/sysmacros.h>
#include <sys/ib/clients/rds/rds.h>
#include <sys/ib/clients/rds/rds_kstat.h>

#include <inet/ipclassifier.h>

struct rds_kstat_s rds_kstat = {
	{"rds_nports",			KSTAT_DATA_ULONG},
	{"rds_nsessions",		KSTAT_DATA_ULONG},
	{"rds_tx_bytes",		KSTAT_DATA_ULONG},
	{"rds_tx_pkts",			KSTAT_DATA_ULONG},
	{"rds_tx_errors",		KSTAT_DATA_ULONG},
	{"rds_rx_bytes",		KSTAT_DATA_ULONG},
	{"rds_rx_pkts",			KSTAT_DATA_ULONG},
	{"rds_rx_pkts_pending",		KSTAT_DATA_ULONG},
	{"rds_rx_errors",		KSTAT_DATA_ULONG},
	{"rds_tx_acks",			KSTAT_DATA_ULONG},
	{"rds_post_recv_buf_called",	KSTAT_DATA_ULONG},
	{"rds_stalls_triggered",	KSTAT_DATA_ULONG},
	{"rds_stalls_sent",		KSTAT_DATA_ULONG},
	{"rds_unstalls_triggered",	KSTAT_DATA_ULONG},
	{"rds_unstalls_sent",		KSTAT_DATA_ULONG},
	{"rds_stalls_recvd",		KSTAT_DATA_ULONG},
	{"rds_unstalls_recvd",		KSTAT_DATA_ULONG},
	{"rds_stalls_ignored",		KSTAT_DATA_ULONG},
	{"rds_enobufs",			KSTAT_DATA_ULONG},
	{"rds_ewouldblocks",		KSTAT_DATA_ULONG},
	{"rds_failovers",		KSTAT_DATA_ULONG},
	{"rds_port_quota",		KSTAT_DATA_ULONG},
	{"rds_port_quota_adjusted",	KSTAT_DATA_ULONG},
};

kstat_t *rds_kstatsp;
static kmutex_t rds_kstat_mutex;


struct	kmem_cache	*rds_alloc_cache;

uint_t	rds_bind_fanout_size = RDS_BIND_FANOUT_SIZE;
rds_bf_t *rds_bind_fanout;

void
rds_increment_kstat(kstat_named_t *ksnp, boolean_t lock, uint_t num)
{
	if (lock)
		mutex_enter(&rds_kstat_mutex);
	ksnp->value.ul += num;
	if (lock)
		mutex_exit(&rds_kstat_mutex);
}

void
rds_decrement_kstat(kstat_named_t *ksnp, boolean_t lock, uint_t num)
{
	if (lock)
		mutex_enter(&rds_kstat_mutex);
	ksnp->value.ul -= num;
	if (lock)
		mutex_exit(&rds_kstat_mutex);
}

void
rds_set_kstat(kstat_named_t *ksnp, boolean_t lock, ulong_t num)
{
	if (lock)
		mutex_enter(&rds_kstat_mutex);
	ksnp->value.ul = num;
	if (lock)
		mutex_exit(&rds_kstat_mutex);
}

ulong_t
rds_get_kstat(kstat_named_t *ksnp, boolean_t lock)
{
	ulong_t	value;

	if (lock)
		mutex_enter(&rds_kstat_mutex);
	value = ksnp->value.ul;
	if (lock)
		mutex_exit(&rds_kstat_mutex);

	return (value);
}


void
rds_fini()
{
	int	i;

	for (i = 0; i < rds_bind_fanout_size; i++) {
		mutex_destroy(&rds_bind_fanout[i].rds_bf_lock);
	}
	kmem_free(rds_bind_fanout, rds_bind_fanout_size * sizeof (rds_bf_t));

	kmem_cache_destroy(rds_alloc_cache);
	kstat_delete(rds_kstatsp);
}


void
rds_init()
{
	rds_alloc_cache = kmem_cache_create("rds_alloc_cache",
	    sizeof (rds_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	rds_hash_init();
	/*
	 * kstats
	 */
	rds_kstatsp = kstat_create("rds", 0,
	    "rds_kstat", "misc", KSTAT_TYPE_NAMED,
	    sizeof (rds_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);
	if (rds_kstatsp != NULL) {
		rds_kstatsp->ks_lock = &rds_kstat_mutex;
		rds_kstatsp->ks_data = (void *)&rds_kstat;
		kstat_install(rds_kstatsp);
	}
}

#define	UINT_32_BITS 31
void
rds_hash_init()
{
	int i;

	if (!ISP2(rds_bind_fanout_size)) {
		/* Not a power of two. Round up to nearest power of two */
		for (i = 0; i < UINT_32_BITS; i++) {
			if (rds_bind_fanout_size < (1 << i))
				break;
		}
		rds_bind_fanout_size = 1 << i;
	}
	rds_bind_fanout = kmem_zalloc(rds_bind_fanout_size *
	    sizeof (rds_bf_t), KM_SLEEP);
	for (i = 0; i < rds_bind_fanout_size; i++) {
		mutex_init(&rds_bind_fanout[i].rds_bf_lock, NULL, MUTEX_DEFAULT,
		    NULL);
	}
}

void
rds_free(rds_t *rds)
{
	ASSERT(rds->rds_refcnt == 0);
	ASSERT(MUTEX_HELD(&rds->rds_lock));
	crfree(rds->rds_cred);
	kmem_cache_free(rds_alloc_cache, rds);
}

rds_t *
rds_create(void *rds_ulpd, cred_t *credp)
{
	rds_t	*rds;

	/* User must supply a credential. */
	if (credp == NULL)
		return (NULL);
	rds = kmem_cache_alloc(rds_alloc_cache, KM_SLEEP);
	if (rds == NULL) {
		return (NULL);
	}

	bzero(rds, sizeof (rds_t));
	mutex_init(&rds->rds_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rds->rds_refcv, NULL, CV_DEFAULT, NULL);
	rds->rds_cred = credp;
	rds->rds_ulpd = rds_ulpd;
	rds->rds_zoneid = getzoneid();
	crhold(credp);
	rds->rds_refcnt++;
	return (rds);
}


/*
 * Hash list removal routine for rds_t structures.
 */
void
rds_bind_hash_remove(rds_t *rds, boolean_t caller_holds_lock)
{
	rds_t   *rdsnext;
	kmutex_t *lockp;

	if (rds->rds_ptpbhn == NULL)
		return;

	/*
	 * Extract the lock pointer in case there are concurrent
	 * hash_remove's for this instance.
	 */
	ASSERT(rds->rds_port != 0);
	if (!caller_holds_lock) {
		lockp = &rds_bind_fanout[RDS_BIND_HASH(rds->rds_port)].
		    rds_bf_lock;
		ASSERT(lockp != NULL);
		mutex_enter(lockp);
	}

	if (rds->rds_ptpbhn != NULL) {
		rdsnext = rds->rds_bind_hash;
		if (rdsnext != NULL) {
			rdsnext->rds_ptpbhn = rds->rds_ptpbhn;
			rds->rds_bind_hash = NULL;
		}
		*rds->rds_ptpbhn = rdsnext;
		rds->rds_ptpbhn = NULL;
	}

	RDS_DEC_REF_CNT(rds);

	if (!caller_holds_lock) {
		mutex_exit(lockp);
	}
}

void
rds_bind_hash_insert(rds_bf_t *rdsbf, rds_t *rds)
{
	rds_t   **rdsp;
	rds_t   *rdsnext;

	ASSERT(MUTEX_HELD(&rdsbf->rds_bf_lock));
	if (rds->rds_ptpbhn != NULL) {
		rds_bind_hash_remove(rds, B_TRUE);
	}

	rdsp = &rdsbf->rds_bf_rds;
	rdsnext = rdsp[0];

	if (rdsnext != NULL) {
		rdsnext->rds_ptpbhn = &rds->rds_bind_hash;
	}
	rds->rds_bind_hash = rdsnext;
	rds->rds_ptpbhn = rdsp;
	rdsp[0] = rds;
	RDS_INCR_REF_CNT(rds);

}

/*
 * Everything is in network byte order
 */
/* ARGSUSED */
rds_t *
rds_fanout(ipaddr_t local_addr, ipaddr_t rem_addr,
    in_port_t local_port, in_port_t rem_port, zoneid_t zoneid)
{
	rds_t	*rds;
	rds_bf_t *rdsbf;

	rdsbf = &rds_bind_fanout[RDS_BIND_HASH(local_port)];
	mutex_enter(&rdsbf->rds_bf_lock);
	rds = rdsbf->rds_bf_rds;
	while (rds != NULL) {
		if (!(rds->rds_flags & RDS_CLOSING)) {
			if ((RDS_MATCH(rds, local_port, local_addr)) &&
			    ((local_addr != INADDR_LOOPBACK) ||
			    (rds->rds_zoneid == zoneid))) {
				RDS_INCR_REF_CNT(rds);
				break;
			}
		}
		rds = rds->rds_bind_hash;
	}
	mutex_exit(&rdsbf->rds_bf_lock);
	return (rds);
}

boolean_t
rds_islocal(ipaddr_t addr)
{
	ip_stack_t *ipst;

	ipst = netstack_find_by_zoneid(GLOBAL_ZONEID)->netstack_ip;
	ASSERT(ipst != NULL);
	if (ip_laddr_verify_v4(addr, ALL_ZONES, ipst, B_FALSE) == IPVL_BAD) {
		netstack_rele(ipst->ips_netstack);
		return (B_FALSE);
	}
	netstack_rele(ipst->ips_netstack);
	return (B_TRUE);
}
