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

#include <sys/types.h>
#include <sys/callb.h>
#include <sys/sdt.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/vlan.h>
#include <inet/ipsec_impl.h>
#include <inet/ip_impl.h>
#include <inet/sadb.h>
#include <inet/ipsecesp.h>
#include <inet/ipsecah.h>

#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_soft_ring.h>
#include <sys/mac_flow_impl.h>

static void mac_srs_soft_rings_signal(mac_soft_ring_set_t *, uint_t);
static void mac_srs_update_fanout_list(mac_soft_ring_set_t *);
static void mac_srs_poll_unbind(mac_soft_ring_set_t *);
static void mac_srs_worker_unbind(mac_soft_ring_set_t *);
static void mac_srs_soft_rings_quiesce(mac_soft_ring_set_t *, uint_t);

static int mac_srs_cpu_setup(cpu_setup_t, int, void *);
static void mac_srs_worker_bind(mac_soft_ring_set_t *, processorid_t);
static void mac_srs_poll_bind(mac_soft_ring_set_t *, processorid_t);
static void mac_srs_threads_unbind(mac_soft_ring_set_t *);
static void mac_srs_add_glist(mac_soft_ring_set_t *);
static void mac_srs_remove_glist(mac_soft_ring_set_t *);
static void mac_srs_fanout_list_free(mac_soft_ring_set_t *);
static void mac_soft_ring_remove(mac_soft_ring_set_t *, mac_soft_ring_t *);

static int mac_compute_soft_ring_count(flow_entry_t *, int);
static void mac_walk_srs_and_bind(int);
static void mac_walk_srs_and_unbind(int);

extern mac_group_t *mac_reserve_rx_group(mac_client_impl_t *, uint8_t *,
    mac_rx_group_reserve_type_t);
extern void mac_release_rx_group(mac_client_impl_t *, mac_group_t *);

extern boolean_t mac_latency_optimize;

static kmem_cache_t *mac_srs_cache;
kmem_cache_t *mac_soft_ring_cache;

/*
 * The duration in msec we wait before signalling the soft ring
 * worker thread in case packets get queued.
 */
static uint32_t mac_soft_ring_worker_wait = 0;

/*
 * Need to set mac_soft_ring_max_q_cnt based on bandwidth and perhaps latency.
 * Large values could end up in consuming lot of system memory and cause
 * system hang.
 */
static int mac_soft_ring_max_q_cnt = 1024;
static int mac_soft_ring_min_q_cnt = 256;
static int mac_soft_ring_poll_thres = 16;

/*
 * Default value of number of TX rings to be assigned to a MAC client.
 * If less than 'mac_tx_ring_count' worth of Tx rings is available, then
 * as many as is available will be assigned to the newly created MAC client.
 * If no TX rings are available, then MAC client(s) will be assigned the
 * default Tx ring. Default Tx ring can be shared among multiple MAC clients.
 */
static uint32_t mac_tx_ring_count = 8;
static boolean_t mac_tx_serialize = B_FALSE;

/*
 * mac_tx_srs_hiwat is the queue depth threshold at which callers of
 * mac_tx() will be notified of flow control condition.
 *
 * TCP does not honour flow control condition sent up by mac_tx().
 * Thus provision is made for TCP to allow more packets to be queued
 * in SRS upto a maximum of mac_tx_srs_max_q_cnt.
 *
 * Note that mac_tx_srs_hiwat is always be lesser than
 * mac_tx_srs_max_q_cnt.
 */
static uint32_t mac_tx_srs_max_q_cnt = 100000;
static uint32_t mac_tx_srs_hiwat = 1000;

/*
 * mac_rx_soft_ring_count, mac_soft_ring_10gig_count:
 *
 * Global tunables that determines the number of soft rings to be used for
 * fanning out incoming traffic on a link. These count will be used only
 * when no explicit set of CPUs was assigned to the data-links.
 *
 * mac_rx_soft_ring_count tunable will come into effect only if
 * mac_soft_ring_enable is set. mac_soft_ring_enable is turned on by
 * default only for sun4v platforms.
 *
 * mac_rx_soft_ring_10gig_count will come into effect if you are running on a
 * 10Gbps link and is not dependent upon mac_soft_ring_enable.
 *
 * The number of soft rings for fanout for a link or a flow is determined
 * by mac_compute_soft_ring_count() routine. This routine will take into
 * account mac_soft_ring_enable, mac_rx_soft_ring_count and
 * mac_rx_soft_ring_10gig_count to determine the soft ring count for a link.
 *
 * If a bandwidth is specified, the determination of the number of soft
 * rings is based on specified bandwidth, CPU speed and number of CPUs in
 * the system.
 */
static uint_t mac_rx_soft_ring_count = 8;
static uint_t mac_rx_soft_ring_10gig_count = 8;

/*
 * Every Tx and Rx mac_soft_ring_set_t (mac_srs) created gets added
 * to mac_srs_g_list and mac_srs_g_lock protects mac_srs_g_list. The
 * list is used to walk the list of all MAC threads when a CPU is
 * coming online or going offline.
 */
static mac_soft_ring_set_t *mac_srs_g_list = NULL;
static krwlock_t mac_srs_g_lock;

/*
 * Whether the SRS threads should be bound, or not.
 */
static boolean_t mac_srs_thread_bind = B_TRUE;

/*
 * CPU to fallback to, used by mac_next_bind_cpu().
 */
static processorid_t srs_bind_cpu = 0;

/*
 * Possible setting for soft_ring_process_flag is
 * 0 or ST_RING_WORKER_ONLY.
 */
static int soft_ring_process_flag = ST_RING_WORKER_ONLY;

/*
 * If cpu bindings are specified by user, then Tx SRS and its soft
 * rings should also be bound to the CPUs specified by user. The
 * CPUs for Tx bindings are at the end of the cpu list provided by
 * the user. If enough CPUs are not available (for Tx and Rx
 * SRSes), then the CPUs are shared by both Tx and Rx SRSes.
 */
#define	BIND_TX_SRS_AND_SOFT_RINGS(mac_tx_srs, mrp) {			\
	processorid_t cpuid;						\
	int i, j;							\
	mac_soft_ring_t *softring;					\
									\
	cpuid = mrp->mrp_cpu[mrp->mrp_ncpus - 1];			\
	mac_srs_worker_bind(mac_tx_srs, cpuid);			\
	if (TX_MULTI_RING_MODE(mac_tx_srs)) {				\
		j =  mrp->mrp_ncpus - 1;				\
		for (i = 0;						\
		    i < mac_tx_srs->srs_oth_ring_count; i++, j--) {	\
			if (j < 0)					\
				j =  mrp->mrp_ncpus - 1;		\
			cpuid = mrp->mrp_cpu[j];			\
			softring = mac_tx_srs->srs_oth_soft_rings[i];	\
			(void) mac_soft_ring_bind(softring, cpuid);	\
		}							\
	}								\
}

/* INIT and FINI ROUTINES */

void
mac_soft_ring_init(void)
{
	mac_soft_ring_cache = kmem_cache_create("mac_soft_ring_cache",
	    sizeof (mac_soft_ring_t), 64, NULL, NULL, NULL, NULL, NULL, 0);

	mac_srs_cache = kmem_cache_create("mac_srs_cache",
	    sizeof (mac_soft_ring_set_t),
	    64, NULL, NULL, NULL, NULL, NULL, 0);

	rw_init(&mac_srs_g_lock, NULL, RW_DEFAULT, NULL);
	mutex_enter(&cpu_lock);
	register_cpu_setup_func(mac_srs_cpu_setup, NULL);
	mutex_exit(&cpu_lock);
}

void
mac_soft_ring_finish(void)
{
	mutex_enter(&cpu_lock);
	unregister_cpu_setup_func(mac_srs_cpu_setup, NULL);
	mutex_exit(&cpu_lock);
	rw_destroy(&mac_srs_g_lock);
	kmem_cache_destroy(mac_soft_ring_cache);
	kmem_cache_destroy(mac_srs_cache);
}

static void
mac_srs_soft_rings_free(mac_soft_ring_set_t *mac_srs, boolean_t release_tx_ring)
{
	mac_soft_ring_t	*softring, *next, *head;

	/*
	 * Synchronize with mac_walk_srs_bind/unbind which are callbacks from
	 * DR. The callbacks from DR are called with cpu_lock held, and hence
	 * can't wait to grab the mac perimeter. The soft ring list is hence
	 * protected for read access by srs_lock. Changing the soft ring list
	 * needs the mac perimeter and the srs_lock.
	 */
	mutex_enter(&mac_srs->srs_lock);

	head = mac_srs->srs_soft_ring_head;
	mac_srs->srs_soft_ring_head = NULL;
	mac_srs->srs_soft_ring_tail = NULL;
	mac_srs->srs_soft_ring_count = 0;

	mutex_exit(&mac_srs->srs_lock);

	for (softring = head; softring != NULL; softring = next) {
		next = softring->s_ring_next;
		mac_soft_ring_free(softring, release_tx_ring);
	}
}

static void
mac_srs_add_glist(mac_soft_ring_set_t *mac_srs)
{
	ASSERT(mac_srs->srs_next == NULL && mac_srs->srs_prev == NULL);
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mac_srs->srs_mcip->mci_mip));

	rw_enter(&mac_srs_g_lock, RW_WRITER);
	mutex_enter(&mac_srs->srs_lock);

	ASSERT((mac_srs->srs_state & SRS_IN_GLIST) == 0);

	if (mac_srs_g_list == NULL) {
		mac_srs_g_list = mac_srs;
	} else {
		mac_srs->srs_next = mac_srs_g_list;
		mac_srs_g_list->srs_prev = mac_srs;
		mac_srs->srs_prev = NULL;
		mac_srs_g_list = mac_srs;
	}
	mac_srs->srs_state |= SRS_IN_GLIST;

	mutex_exit(&mac_srs->srs_lock);
	rw_exit(&mac_srs_g_lock);
}

static void
mac_srs_remove_glist(mac_soft_ring_set_t *mac_srs)
{
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mac_srs->srs_mcip->mci_mip));

	rw_enter(&mac_srs_g_lock, RW_WRITER);
	mutex_enter(&mac_srs->srs_lock);

	ASSERT((mac_srs->srs_state & SRS_IN_GLIST) != 0);

	if (mac_srs == mac_srs_g_list) {
		mac_srs_g_list = mac_srs->srs_next;
		if (mac_srs_g_list != NULL)
			mac_srs_g_list->srs_prev = NULL;
	} else {
		mac_srs->srs_prev->srs_next = mac_srs->srs_next;
		if (mac_srs->srs_next != NULL)
			mac_srs->srs_next->srs_prev = mac_srs->srs_prev;
	}
	mac_srs->srs_state &= ~SRS_IN_GLIST;

	mutex_exit(&mac_srs->srs_lock);
	rw_exit(&mac_srs_g_lock);
}

/* POLLING SETUP AND TEAR DOWN ROUTINES */

/*
 * mac_srs_client_poll_quiesce and mac_srs_client_poll_restart
 *
 * These routines are used to call back into the upper layer
 * (primarily TCP squeue) to stop polling the soft rings or
 * restart polling.
 */
void
mac_srs_client_poll_quiesce(mac_client_impl_t *mcip,
    mac_soft_ring_set_t *mac_srs)
{
	mac_soft_ring_t	*softring;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	if (!(mac_srs->srs_type & SRST_CLIENT_POLL_ENABLED)) {
		ASSERT(!(mac_srs->srs_type & SRST_DLS_BYPASS));
		return;
	}

	for (softring = mac_srs->srs_soft_ring_head;
	    softring != NULL; softring = softring->s_ring_next) {
		if ((softring->s_ring_type & ST_RING_TCP) &&
		    (softring->s_ring_rx_arg2 != NULL)) {
			mcip->mci_resource_quiesce(mcip->mci_resource_arg,
			    softring->s_ring_rx_arg2);
		}
	}
}

void
mac_srs_client_poll_restart(mac_client_impl_t *mcip,
    mac_soft_ring_set_t *mac_srs)
{
	mac_soft_ring_t	*softring;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	if (!(mac_srs->srs_type & SRST_CLIENT_POLL_ENABLED)) {
		ASSERT(!(mac_srs->srs_type & SRST_DLS_BYPASS));
		return;
	}

	for (softring = mac_srs->srs_soft_ring_head;
	    softring != NULL; softring = softring->s_ring_next) {
		if ((softring->s_ring_type & ST_RING_TCP) &&
		    (softring->s_ring_rx_arg2 != NULL)) {
			mcip->mci_resource_restart(mcip->mci_resource_arg,
			    softring->s_ring_rx_arg2);
		}
	}
}

/*
 * Register the given SRS and associated soft rings with the consumer and
 * enable the polling interface used by the consumer.(i.e IP) over this
 * SRS and associated soft rings.
 */
void
mac_srs_client_poll_enable(mac_client_impl_t *mcip,
    mac_soft_ring_set_t *mac_srs)
{
	mac_rx_fifo_t		mrf;
	mac_soft_ring_t		*softring;

	ASSERT(mac_srs->srs_mcip == mcip);
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	if (!(mcip->mci_state_flags & MCIS_CLIENT_POLL_CAPABLE))
		return;

	bzero(&mrf, sizeof (mac_rx_fifo_t));
	mrf.mrf_type = MAC_RX_FIFO;

	/*
	 * A SRS is capable of acting as a soft ring for cases
	 * where no fanout is needed. This is the case for userland
	 * flows.
	 */
	if (mac_srs->srs_type & SRST_NO_SOFT_RINGS)
		return;

	mrf.mrf_receive = (mac_receive_t)mac_soft_ring_poll;
	mrf.mrf_intr_enable = (mac_intr_enable_t)mac_soft_ring_intr_enable;
	mrf.mrf_intr_disable = (mac_intr_disable_t)mac_soft_ring_intr_disable;
	mac_srs->srs_type |= SRST_CLIENT_POLL_ENABLED;

	softring = mac_srs->srs_soft_ring_head;
	while (softring != NULL) {
		if (softring->s_ring_type & (ST_RING_TCP | ST_RING_UDP)) {
			/*
			 * TCP and UDP support DLS bypass. Squeue polling
			 * support implies DLS bypass since the squeue poll
			 * path does not have DLS processing.
			 */
			mac_soft_ring_dls_bypass(softring,
			    mcip->mci_direct_rx_fn, mcip->mci_direct_rx_arg);
		}
		/*
		 * Non-TCP protocols don't support squeues. Hence we don't
		 * make any ring addition callbacks for non-TCP rings
		 */
		if (!(softring->s_ring_type & ST_RING_TCP)) {
			softring->s_ring_rx_arg2 = NULL;
			softring = softring->s_ring_next;
			continue;
		}
		mrf.mrf_rx_arg = softring;
		mrf.mrf_intr_handle = (mac_intr_handle_t)softring;
		mrf.mrf_cpu_id = softring->s_ring_cpuid;
		mrf.mrf_flow_priority = mac_srs->srs_pri;

		softring->s_ring_rx_arg2 = mcip->mci_resource_add(
		    mcip->mci_resource_arg, (mac_resource_t *)&mrf);

		softring = softring->s_ring_next;
	}
}

/*
 * Unregister the given SRS and associated soft rings with the consumer and
 * disable the polling interface used by the consumer.(i.e IP) over this
 * SRS and associated soft rings.
 */
void
mac_srs_client_poll_disable(mac_client_impl_t *mcip,
    mac_soft_ring_set_t *mac_srs)
{
	mac_soft_ring_t		*softring;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	/*
	 * A SRS is capable of acting as a soft ring for cases
	 * where no protocol fanout is needed. This is the case
	 * for userland flows. Nothing to do here.
	 */
	if (mac_srs->srs_type & SRST_NO_SOFT_RINGS)
		return;

	mutex_enter(&mac_srs->srs_lock);
	if (!(mac_srs->srs_type & SRST_CLIENT_POLL_ENABLED)) {
		ASSERT(!(mac_srs->srs_type & SRST_DLS_BYPASS));
		mutex_exit(&mac_srs->srs_lock);
		return;
	}
	mac_srs->srs_type &= ~(SRST_CLIENT_POLL_ENABLED | SRST_DLS_BYPASS);
	mutex_exit(&mac_srs->srs_lock);

	/*
	 * DLS bypass is now disabled in the case of both TCP and UDP.
	 * Reset the soft ring callbacks to the standard 'mac_rx_deliver'
	 * callback. In addition, in the case of TCP, invoke IP's callback
	 * for ring removal.
	 */
	for (softring = mac_srs->srs_soft_ring_head;
	    softring != NULL; softring = softring->s_ring_next) {
		if (!(softring->s_ring_type & (ST_RING_UDP | ST_RING_TCP)))
			continue;

		if ((softring->s_ring_type & ST_RING_TCP) &&
		    softring->s_ring_rx_arg2 != NULL) {
			mcip->mci_resource_remove(mcip->mci_resource_arg,
			    softring->s_ring_rx_arg2);
		}

		mutex_enter(&softring->s_ring_lock);
		while (softring->s_ring_state & S_RING_PROC) {
			softring->s_ring_state |= S_RING_CLIENT_WAIT;
			cv_wait(&softring->s_ring_client_cv,
			    &softring->s_ring_lock);
		}
		softring->s_ring_state &= ~S_RING_CLIENT_WAIT;
		softring->s_ring_rx_arg2 = NULL;
		softring->s_ring_rx_func = mac_rx_deliver;
		softring->s_ring_rx_arg1 = mcip;
		mutex_exit(&softring->s_ring_lock);
	}
}

/*
 * Enable or disable poll capability of the SRS on the underlying Rx ring.
 *
 * There is a need to enable or disable the poll capability of an SRS over an
 * Rx ring depending on the number of mac clients sharing the ring and also
 * whether user flows are configured on it. However the poll state is actively
 * manipulated by the SRS worker and poll threads and uncoordinated changes by
 * yet another thread to the underlying capability can surprise them leading
 * to assert failures. Instead we quiesce the SRS, make the changes and then
 * restart the SRS.
 */
static void
mac_srs_poll_state_change(mac_soft_ring_set_t *mac_srs,
    boolean_t turn_off_poll_capab, mac_rx_func_t rx_func)
{
	boolean_t	need_restart = B_FALSE;
	mac_srs_rx_t	*srs_rx = &mac_srs->srs_rx;
	mac_ring_t	*ring;

	if (!SRS_QUIESCED(mac_srs)) {
		mac_rx_srs_quiesce(mac_srs, SRS_QUIESCE);
		need_restart = B_TRUE;
	}

	ring = mac_srs->srs_ring;
	if ((ring != NULL) &&
	    (ring->mr_classify_type == MAC_HW_CLASSIFIER)) {
		if (turn_off_poll_capab)
			mac_srs->srs_state &= ~SRS_POLLING_CAPAB;
		else
			mac_srs->srs_state |= SRS_POLLING_CAPAB;
	}
	srs_rx->sr_lower_proc = rx_func;

	if (need_restart)
		mac_rx_srs_restart(mac_srs);
}

/* CPU RECONFIGURATION AND FANOUT COMPUTATION ROUTINES */

/*
 * Return the next CPU to be used to bind a MAC kernel thread.
 */
static processorid_t
mac_next_bind_cpu(void)
{
	static processorid_t srs_curr_cpu = -1;
	cpu_t *cp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	srs_curr_cpu++;
	cp = cpu_get(srs_curr_cpu);
	if (cp == NULL || !cpu_is_online(cp))
		srs_curr_cpu = srs_bind_cpu;

	return (srs_curr_cpu);
}

/* ARGSUSED */
static int
mac_srs_cpu_setup(cpu_setup_t what, int id, void *arg)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	switch (what) {
	case CPU_CONFIG:
	case CPU_ON:
	case CPU_CPUPART_IN:
		mac_walk_srs_and_bind(id);
		break;

	case CPU_UNCONFIG:
	case CPU_OFF:
	case CPU_CPUPART_OUT:
		mac_walk_srs_and_unbind(id);
		break;

	default:
		break;
	}
	return (0);
}

/*
 * mac_compute_soft_ring_count():
 *
 * This routine computes the number of soft rings needed to handle incoming
 * load given a flow_entry.
 *
 * The routine does the following:
 * 1) soft rings will be created if mac_soft_ring_enable is set.
 * 2) If the underlying link is a 10Gbps link, then soft rings will be
 * created even if mac_soft_ring_enable is not set. The number of soft
 * rings, so created,  will equal mac_rx_soft_ring_10gig_count.
 * 3) On a sun4v platform (i.e., mac_soft_ring_enable is set), 2 times the
 * mac_rx_soft_ring_10gig_count number of soft rings will be created for a
 * 10Gbps link.
 *
 * If a bandwidth limit is specified, the number that gets computed is
 * dependent upon CPU speed, the number of Rx rings configured, and
 * the bandwidth limit.
 * If more Rx rings are available, less number of soft rings is needed.
 *
 * mac_use_bw_heuristic is another "hidden" variable that can be used to
 * override the default use of soft ring count computation. Depending upon
 * the usefulness of it, mac_use_bw_heuristic can later be made into a
 * data-link property or removed altogether.
 *
 * TODO: Cleanup and tighten some of the assumptions.
 */
boolean_t mac_use_bw_heuristic = B_TRUE;
static int
mac_compute_soft_ring_count(flow_entry_t *flent, int rx_srs_cnt)
{
	uint64_t cpu_speed, bw = 0;
	int srings = 0;
	boolean_t bw_enabled = B_FALSE;

	ASSERT(!(flent->fe_type & FLOW_USER));
	if (flent->fe_resource_props.mrp_mask & MRP_MAXBW &&
	    mac_use_bw_heuristic) {
		/* bandwidth enabled */
		bw_enabled = B_TRUE;
		bw = flent->fe_resource_props.mrp_maxbw;
	}
	if (!bw_enabled) {
		/* No bandwidth enabled */
		if (mac_soft_ring_enable)
			srings = mac_rx_soft_ring_count;

		/* Is this a 10Gig link? */
		flent->fe_nic_speed = mac_client_stat_get(flent->fe_mcip,
		    MAC_STAT_IFSPEED);
		/* convert to Mbps */
		if (((flent->fe_nic_speed)/1000000) > 1000 &&
		    mac_rx_soft_ring_10gig_count > 0) {
			/* This is a 10Gig link */
			srings = mac_rx_soft_ring_10gig_count;
			/*
			 * Use 2 times mac_rx_soft_ring_10gig_count for
			 * sun4v systems.
			 */
			if (mac_soft_ring_enable)
				srings = srings * 2;
		}
	} else {
		/*
		 * Soft ring computation using CPU speed and specified
		 * bandwidth limit.
		 */
		/* Assumption: all CPUs have the same frequency */
		cpu_speed = (uint64_t)CPU->cpu_type_info.pi_clock;

		/* cpu_speed is in MHz; make bw in units of Mbps.  */
		bw = bw/1000000;

		if (bw >= 1000) {
			/*
			 * bw is greater than or equal to 1Gbps.
			 * The number of soft rings required is a function
			 * of bandwidth and CPU speed. To keep this simple,
			 * let's use this rule: 1GHz CPU can handle 1Gbps.
			 * If bw is less than 1 Gbps, then there is no need
			 * for soft rings. Assumption is that CPU speeds
			 * (on modern systems) are at least 1GHz.
			 */
			srings = bw/cpu_speed;
			if (srings <= 1 && mac_soft_ring_enable) {
				/*
				 * Give at least 2 soft rings
				 * for sun4v systems
				 */
				srings = 2;
			}
		}
	}
	/*
	 * If the flent has multiple Rx SRSs, then each SRS need not
	 * have that many soft rings on top of it. The number of
	 * soft rings for each Rx SRS is found by dividing srings by
	 * rx_srs_cnt.
	 */
	if (rx_srs_cnt > 1) {
		int remainder;

		remainder = srings%rx_srs_cnt;
		srings = srings/rx_srs_cnt;
		if (remainder != 0)
			srings++;
		/*
		 * Fanning out to 1 soft ring is not very useful.
		 * Set it as well to 0 and mac_srs_fanout_init()
		 * will take care of creating a single soft ring
		 * for proto fanout.
		 */
		if (srings == 1)
			srings = 0;
	}
	/* Do some more massaging */
	srings = min(srings, ncpus);
	srings = min(srings, MAX_SR_FANOUT);
	return (srings);
}

/*
 * Assignment of user specified CPUs to a link.
 *
 * Minimum CPUs required to get an optimal assignmet:
 * For each Rx SRS, atleast two CPUs are needed if mac_latency_optimize
 * flag is set -- one for polling, one for fanout soft ring.
 * If mac_latency_optimize is not set, then 3 CPUs are needed -- one
 * for polling, one for SRS worker thread and one for fanout soft ring.
 *
 * The CPUs needed for Tx side is equal to the number of Tx rings
 * the link is using.
 *
 * mac_flow_user_cpu_init() categorizes the CPU assignment depending
 * upon the number of CPUs in 3 different buckets.
 *
 * In the first bucket, the most optimal case is handled. The user has
 * passed enough number of CPUs and every thread gets its own CPU.
 *
 * The second and third are the sub-optimal cases. Enough CPUs are not
 * available.
 *
 * The second bucket handles the case where atleast one distinct CPU is
 * is available for each of the Rx rings (Rx SRSes) and Tx rings (Tx
 * SRS or soft rings).
 *
 * In the third case (worst case scenario), specified CPU count is less
 * than the Rx rings configured for the link. In this case, we round
 * robin the CPUs among the Rx SRSes and Tx SRS/soft rings.
 */
static void
mac_flow_user_cpu_init(flow_entry_t *flent, mac_resource_props_t *mrp)
{
	mac_soft_ring_set_t *rx_srs, *tx_srs;
	int i, srs_cnt;
	mac_cpus_t *srs_cpu;
	int no_of_cpus, cpu_cnt;
	int rx_srs_cnt, reqd_rx_cpu_cnt;
	int fanout_cpu_cnt, reqd_tx_cpu_cnt;
	int reqd_poll_worker_cnt, fanout_cnt_per_srs;

	ASSERT(mrp->mrp_fanout_mode == MCM_CPUS);
	/*
	 * The check for nbc_ncpus to be within limits for
	 * the user specified case was done earlier and if
	 * not within limits, an error would have been
	 * returned to the user.
	 */
	ASSERT(mrp->mrp_ncpus > 0 && mrp->mrp_ncpus <= MAX_SR_FANOUT);

	no_of_cpus = mrp->mrp_ncpus;

	if (mrp->mrp_intr_cpu != -1) {
		/*
		 * interrupt has been re-targetted. Poll
		 * thread needs to be bound to interrupt
		 * CPU. Presently only fixed interrupts
		 * are re-targetted, MSI-x aren't.
		 *
		 * Find where in the list is the intr
		 * CPU and swap it with the first one.
		 * We will be using the first CPU in the
		 * list for poll.
		 */
		for (i = 0; i < no_of_cpus; i++) {
			if (mrp->mrp_cpu[i] == mrp->mrp_intr_cpu)
				break;
		}
		mrp->mrp_cpu[i] = mrp->mrp_cpu[0];
		mrp->mrp_cpu[0] = mrp->mrp_intr_cpu;
	}

	/*
	 * Requirements:
	 * The number of CPUs that each Rx ring needs is dependent
	 * upon mac_latency_optimize flag.
	 * 1) If set, atleast 2 CPUs are needed -- one for
	 * polling, one for fanout soft ring.
	 * 2) If not set, then atleast 3 CPUs are needed -- one
	 * for polling, one for srs worker thread, and one for
	 * fanout soft ring.
	 */
	rx_srs_cnt = (flent->fe_rx_srs_cnt > 1) ?
	    (flent->fe_rx_srs_cnt - 1) : flent->fe_rx_srs_cnt;
	reqd_rx_cpu_cnt = mac_latency_optimize ?
	    (rx_srs_cnt * 2) : (rx_srs_cnt * 3);

	/* How many CPUs are needed for Tx side? */
	tx_srs = flent->fe_tx_srs;
	reqd_tx_cpu_cnt = TX_MULTI_RING_MODE(tx_srs) ?
	    tx_srs->srs_oth_ring_count : 1;

	/* CPUs needed for Rx SRSes poll and worker threads */
	reqd_poll_worker_cnt = mac_latency_optimize ?
	    rx_srs_cnt : rx_srs_cnt * 2;

	/* Has the user provided enough CPUs? */
	if (no_of_cpus >= (reqd_rx_cpu_cnt + reqd_tx_cpu_cnt)) {
		/*
		 * Best case scenario. There is enough CPUs. All
		 * Rx rings will get their own set of CPUs plus
		 * Tx soft rings will get their own.
		 */
		/*
		 * fanout_cpu_cnt is the number of CPUs available
		 * for Rx side fanout soft rings.
		 */
		fanout_cpu_cnt = no_of_cpus -
		    reqd_poll_worker_cnt - reqd_tx_cpu_cnt;

		/*
		 * Divide fanout_cpu_cnt by rx_srs_cnt to find
		 * out how many fanout soft rings each Rx SRS
		 * can have.
		 */
		fanout_cnt_per_srs = fanout_cpu_cnt/rx_srs_cnt;

		/* Do the assignment for the default Rx ring */
		cpu_cnt = 0;
		rx_srs = flent->fe_rx_srs[0];
		ASSERT(rx_srs->srs_ring == NULL);
		if (rx_srs->srs_fanout_state == SRS_FANOUT_INIT)
			rx_srs->srs_fanout_state = SRS_FANOUT_REINIT;
		srs_cpu = &rx_srs->srs_cpu;
		srs_cpu->mc_ncpus = no_of_cpus;
		bcopy(mrp->mrp_cpu,
		    srs_cpu->mc_cpus, sizeof (srs_cpu->mc_cpus));
		srs_cpu->mc_fanout_cnt = fanout_cnt_per_srs;
		srs_cpu->mc_pollid = mrp->mrp_cpu[cpu_cnt++];
		srs_cpu->mc_intr_cpu = mrp->mrp_intr_cpu;
		srs_cpu->mc_workerid = srs_cpu->mc_pollid;
		if (!mac_latency_optimize)
			srs_cpu->mc_workerid = mrp->mrp_cpu[cpu_cnt++];
		for (i = 0; i < fanout_cnt_per_srs; i++)
			srs_cpu->mc_fanout_cpus[i] = mrp->mrp_cpu[cpu_cnt++];

		/* Do the assignment for h/w Rx SRSes */
		if (flent->fe_rx_srs_cnt > 1) {
			cpu_cnt = 0;
			for (srs_cnt = 1;
			    srs_cnt < flent->fe_rx_srs_cnt; srs_cnt++) {
				rx_srs = flent->fe_rx_srs[srs_cnt];
				ASSERT(rx_srs->srs_ring != NULL);
				if (rx_srs->srs_fanout_state ==
				    SRS_FANOUT_INIT) {
					rx_srs->srs_fanout_state =
					    SRS_FANOUT_REINIT;
				}
				srs_cpu = &rx_srs->srs_cpu;
				srs_cpu->mc_ncpus = no_of_cpus;
				bcopy(mrp->mrp_cpu, srs_cpu->mc_cpus,
				    sizeof (srs_cpu->mc_cpus));
				srs_cpu->mc_fanout_cnt = fanout_cnt_per_srs;
				/* The first CPU in the list is the intr CPU */
				srs_cpu->mc_pollid = mrp->mrp_cpu[cpu_cnt++];
				srs_cpu->mc_intr_cpu = mrp->mrp_intr_cpu;
				srs_cpu->mc_workerid = srs_cpu->mc_pollid;
				if (!mac_latency_optimize) {
					srs_cpu->mc_workerid =
					    mrp->mrp_cpu[cpu_cnt++];
				}
				for (i = 0; i < fanout_cnt_per_srs; i++) {
					srs_cpu->mc_fanout_cpus[i] =
					    mrp->mrp_cpu[cpu_cnt++];
				}
				ASSERT(cpu_cnt <= no_of_cpus);
			}
		}
		return;
	}

	/*
	 * Sub-optimal case.
	 * We have the following information:
	 * no_of_cpus - no. of cpus that user passed.
	 * rx_srs_cnt - no. of rx rings.
	 * reqd_rx_cpu_cnt = mac_latency_optimize?rx_srs_cnt*2:rx_srs_cnt*3
	 * reqd_tx_cpu_cnt - no. of cpus reqd. for Tx side.
	 * reqd_poll_worker_cnt = mac_latency_optimize?rx_srs_cnt:rx_srs_cnt*2
	 */
	/*
	 * If we bind the Rx fanout soft rings to the same CPUs
	 * as poll/worker, would that be enough?
	 */
	if (no_of_cpus >= (rx_srs_cnt + reqd_tx_cpu_cnt)) {
		boolean_t worker_assign = B_FALSE;

		/*
		 * If mac_latency_optimize is not set, are there
		 * enough CPUs to assign a CPU for worker also?
		 */
		if (no_of_cpus >= (reqd_poll_worker_cnt + reqd_tx_cpu_cnt))
			worker_assign = B_TRUE;
		/*
		 * Zero'th Rx SRS is the default Rx ring. It is not
		 * associated with h/w Rx ring.
		 */
		rx_srs = flent->fe_rx_srs[0];
		ASSERT(rx_srs->srs_ring == NULL);
		if (rx_srs->srs_fanout_state == SRS_FANOUT_INIT)
			rx_srs->srs_fanout_state = SRS_FANOUT_REINIT;
		cpu_cnt = 0;
		srs_cpu = &rx_srs->srs_cpu;
		srs_cpu->mc_ncpus = no_of_cpus;
		bcopy(mrp->mrp_cpu,
		    srs_cpu->mc_cpus, sizeof (srs_cpu->mc_cpus));
		srs_cpu->mc_fanout_cnt = 1;
		srs_cpu->mc_pollid = mrp->mrp_cpu[cpu_cnt++];
		srs_cpu->mc_intr_cpu = mrp->mrp_intr_cpu;
		srs_cpu->mc_workerid = srs_cpu->mc_pollid;
		if (!mac_latency_optimize && worker_assign)
			srs_cpu->mc_workerid = mrp->mrp_cpu[cpu_cnt++];
		srs_cpu->mc_fanout_cpus[0] = mrp->mrp_cpu[cpu_cnt];

		/* Do CPU bindings for SRSes having h/w Rx rings */
		if (flent->fe_rx_srs_cnt > 1) {
			cpu_cnt = 0;
			for (srs_cnt = 1;
			    srs_cnt < flent->fe_rx_srs_cnt; srs_cnt++) {
				rx_srs = flent->fe_rx_srs[srs_cnt];
				ASSERT(rx_srs->srs_ring != NULL);
				if (rx_srs->srs_fanout_state ==
				    SRS_FANOUT_INIT) {
					rx_srs->srs_fanout_state =
					    SRS_FANOUT_REINIT;
				}
				srs_cpu = &rx_srs->srs_cpu;
				srs_cpu->mc_ncpus = no_of_cpus;
				bcopy(mrp->mrp_cpu, srs_cpu->mc_cpus,
				    sizeof (srs_cpu->mc_cpus));
				srs_cpu->mc_pollid =
				    mrp->mrp_cpu[cpu_cnt];
				srs_cpu->mc_intr_cpu = mrp->mrp_intr_cpu;
				srs_cpu->mc_workerid = srs_cpu->mc_pollid;
				if (!mac_latency_optimize && worker_assign) {
					srs_cpu->mc_workerid =
					    mrp->mrp_cpu[++cpu_cnt];
				}
				srs_cpu->mc_fanout_cnt = 1;
				srs_cpu->mc_fanout_cpus[0] =
				    mrp->mrp_cpu[cpu_cnt];
				cpu_cnt++;
				ASSERT(cpu_cnt <= no_of_cpus);
			}
		}
		return;
	}

	/*
	 * Real sub-optimal case. Not enough CPUs for poll and
	 * Tx soft rings. Do a round robin assignment where
	 * each Rx SRS will get the same CPU for poll, worker
	 * and fanout soft ring.
	 */
	cpu_cnt = 0;
	for (srs_cnt = 0; srs_cnt < flent->fe_rx_srs_cnt; srs_cnt++) {
		rx_srs = flent->fe_rx_srs[srs_cnt];
		srs_cpu = &rx_srs->srs_cpu;
		if (rx_srs->srs_fanout_state == SRS_FANOUT_INIT)
			rx_srs->srs_fanout_state = SRS_FANOUT_REINIT;
		srs_cpu->mc_ncpus = no_of_cpus;
		bcopy(mrp->mrp_cpu,
		    srs_cpu->mc_cpus, sizeof (srs_cpu->mc_cpus));
		srs_cpu->mc_fanout_cnt = 1;
		srs_cpu->mc_pollid = mrp->mrp_cpu[cpu_cnt];
		srs_cpu->mc_intr_cpu = mrp->mrp_intr_cpu;
		srs_cpu->mc_workerid = mrp->mrp_cpu[cpu_cnt];
		srs_cpu->mc_fanout_cpus[0] = mrp->mrp_cpu[cpu_cnt];
		if (++cpu_cnt >= no_of_cpus)
			cpu_cnt = 0;
	}
}

/*
 * mac_flow_cpu_init():
 *
 * Each SRS has a mac_cpu_t structure, srs_cpu. This routine fills in
 * the CPU binding information in srs_cpu for all Rx SRSes associated
 * with a flent.
 */
static void
mac_flow_cpu_init(flow_entry_t *flent, mac_resource_props_t *mrp)
{
	mac_soft_ring_set_t *rx_srs;
	processorid_t cpuid;
	int j, srs_cnt, soft_ring_cnt = 0;
	mac_cpus_t *srs_cpu;

	if (mrp->mrp_mask & MRP_CPUS_USERSPEC) {
		mac_flow_user_cpu_init(flent, mrp);
	} else {
		/*
		 * Compute the number of soft rings needed on top for each Rx
		 * SRS. "rx_srs_cnt-1" indicates the number of Rx SRS
		 * associated with h/w Rx rings. Soft ring count needed for
		 * each h/w Rx SRS is computed and the same is applied to
		 * software classified Rx SRS. The first Rx SRS in fe_rx_srs[]
		 * is the software classified Rx SRS.
		 */
		soft_ring_cnt = mac_compute_soft_ring_count(flent,
		    flent->fe_rx_srs_cnt - 1);
		if (soft_ring_cnt == 0) {
			/*
			 * Even when soft_ring_cnt is 0, we still need
			 * to create a soft ring for TCP, UDP and
			 * OTHER. So set it to 1.
			 */
			soft_ring_cnt = 1;
		}
		for (srs_cnt = 0; srs_cnt < flent->fe_rx_srs_cnt; srs_cnt++) {
			rx_srs = flent->fe_rx_srs[srs_cnt];
			srs_cpu = &rx_srs->srs_cpu;
			if (rx_srs->srs_fanout_state == SRS_FANOUT_INIT) {
				if (soft_ring_cnt == srs_cpu->mc_fanout_cnt)
					continue;
				rx_srs->srs_fanout_state = SRS_FANOUT_REINIT;
			}
			srs_cpu->mc_ncpus = soft_ring_cnt;
			srs_cpu->mc_fanout_cnt = soft_ring_cnt;
			mutex_enter(&cpu_lock);
			for (j = 0; j < soft_ring_cnt; j++) {
				cpuid = mac_next_bind_cpu();
				srs_cpu->mc_cpus[j] = cpuid;
				srs_cpu->mc_fanout_cpus[j] = cpuid;
			}
			cpuid = mac_next_bind_cpu();
			srs_cpu->mc_pollid = cpuid;
			/* increment ncpus to account for polling cpu */
			srs_cpu->mc_ncpus++;
			srs_cpu->mc_cpus[j++] = cpuid;
			if (!mac_latency_optimize) {
				cpuid = mac_next_bind_cpu();
				srs_cpu->mc_ncpus++;
				srs_cpu->mc_cpus[j++] = cpuid;
			}
			srs_cpu->mc_workerid = cpuid;
			mutex_exit(&cpu_lock);
		}
	}
}

/*
 * DATAPATH SETUP ROUTINES
 * (setup SRS and set/update FANOUT, B/W and PRIORITY)
 */

static void
mac_srs_fanout_list_alloc(mac_soft_ring_set_t *mac_srs)
{
	mac_srs->srs_tcp_soft_rings = (mac_soft_ring_t **)
	    kmem_zalloc(sizeof (mac_soft_ring_t *) * MAX_SR_FANOUT, KM_SLEEP);
	mac_srs->srs_udp_soft_rings = (mac_soft_ring_t **)
	    kmem_zalloc(sizeof (mac_soft_ring_t *) * MAX_SR_FANOUT, KM_SLEEP);
	mac_srs->srs_oth_soft_rings = (mac_soft_ring_t **)
	    kmem_zalloc(sizeof (mac_soft_ring_t *) * MAX_SR_FANOUT, KM_SLEEP);
}

static void
mac_srs_worker_bind(mac_soft_ring_set_t *mac_srs, processorid_t cpuid)
{
	cpu_t *cp;
	boolean_t clear = B_FALSE;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (!mac_srs_thread_bind)
		return;

	cp = cpu_get(cpuid);
	if (cp == NULL || !cpu_is_online(cp))
		return;

	mutex_enter(&mac_srs->srs_lock);
	mac_srs->srs_state |= SRS_WORKER_BOUND;
	if (mac_srs->srs_worker_cpuid != -1)
		clear = B_TRUE;
	mac_srs->srs_worker_cpuid = cpuid;
	mutex_exit(&mac_srs->srs_lock);

	if (clear)
		thread_affinity_clear(mac_srs->srs_worker);

	thread_affinity_set(mac_srs->srs_worker, cpuid);
	DTRACE_PROBE1(worker__CPU, processorid_t, cpuid);
}

static void
mac_srs_poll_bind(mac_soft_ring_set_t *mac_srs, processorid_t cpuid)
{
	cpu_t *cp;
	boolean_t clear = B_FALSE;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (!mac_srs_thread_bind || mac_srs->srs_poll_thr == NULL)
		return;

	cp = cpu_get(cpuid);
	if (cp == NULL || !cpu_is_online(cp))
		return;

	mutex_enter(&mac_srs->srs_lock);
	mac_srs->srs_state |= SRS_POLL_BOUND;
	if (mac_srs->srs_poll_cpuid != -1)
		clear = B_TRUE;
	mac_srs->srs_poll_cpuid = cpuid;
	mutex_exit(&mac_srs->srs_lock);

	if (clear)
		thread_affinity_clear(mac_srs->srs_poll_thr);

	thread_affinity_set(mac_srs->srs_poll_thr, cpuid);
	DTRACE_PROBE1(poll__CPU, processorid_t, cpuid);
}

/*
 * When a CPU comes back online, bind the MAC kernel threads which
 * were previously bound to that CPU, and had to be unbound because
 * the CPU was going away.
 *
 * These functions are called with cpu_lock held and hence we can't
 * cv_wait to grab the mac perimeter. Since these functions walk the soft
 * ring list of an SRS without being in the perimeter, the list itself
 * is protected by the SRS lock.
 */
static void
mac_walk_srs_and_bind(int cpuid)
{
	mac_soft_ring_set_t *mac_srs;
	mac_soft_ring_t *soft_ring;

	rw_enter(&mac_srs_g_lock, RW_READER);

	if ((mac_srs = mac_srs_g_list) == NULL)
		goto done;

	for (; mac_srs != NULL; mac_srs = mac_srs->srs_next) {
		if (mac_srs->srs_worker_cpuid == -1 &&
		    mac_srs->srs_worker_cpuid_save == cpuid) {
			mac_srs->srs_worker_cpuid_save = -1;
			mac_srs_worker_bind(mac_srs, cpuid);
		}

		if (!(mac_srs->srs_type & SRST_TX)) {
			if (mac_srs->srs_poll_cpuid == -1 &&
			    mac_srs->srs_poll_cpuid_save == cpuid) {
				mac_srs->srs_poll_cpuid_save = -1;
				mac_srs_poll_bind(mac_srs, cpuid);
			}
		}

		/* Next tackle the soft rings associated with the srs */
		mutex_enter(&mac_srs->srs_lock);
		for (soft_ring = mac_srs->srs_soft_ring_head; soft_ring != NULL;
		    soft_ring = soft_ring->s_ring_next) {
			if (soft_ring->s_ring_cpuid == -1 &&
			    soft_ring->s_ring_cpuid_save == cpuid) {
				soft_ring->s_ring_cpuid_save = -1;
				(void) mac_soft_ring_bind(soft_ring, cpuid);
			}
		}
		mutex_exit(&mac_srs->srs_lock);
	}
done:
	rw_exit(&mac_srs_g_lock);
}

/*
 * Change the priority of the SRS's poll and worker thread. Additionally,
 * update the priority of the worker threads for the SRS's soft rings.
 * Need to modify any associated squeue threads.
 */
void
mac_update_srs_priority(mac_soft_ring_set_t *mac_srs, pri_t prival)
{
	mac_soft_ring_t		*ringp;

	mac_srs->srs_pri = prival;
	thread_lock(mac_srs->srs_worker);
	(void) thread_change_pri(mac_srs->srs_worker, mac_srs->srs_pri, 0);
	thread_unlock(mac_srs->srs_worker);
	if (mac_srs->srs_poll_thr != NULL) {
		thread_lock(mac_srs->srs_poll_thr);
		(void) thread_change_pri(mac_srs->srs_poll_thr,
		    mac_srs->srs_pri, 0);
		thread_unlock(mac_srs->srs_poll_thr);
	}
	if ((ringp = mac_srs->srs_soft_ring_head) == NULL)
		return;
	while (ringp != mac_srs->srs_soft_ring_tail) {
		thread_lock(ringp->s_ring_worker);
		(void) thread_change_pri(ringp->s_ring_worker,
		    mac_srs->srs_pri, 0);
		thread_unlock(ringp->s_ring_worker);
		ringp = ringp->s_ring_next;
	}
	ASSERT(ringp == mac_srs->srs_soft_ring_tail);
	thread_lock(ringp->s_ring_worker);
	(void) thread_change_pri(ringp->s_ring_worker, mac_srs->srs_pri, 0);
	thread_unlock(ringp->s_ring_worker);
}

/*
 * Change the receive bandwidth limit.
 */
static void
mac_rx_srs_update_bwlimit(mac_soft_ring_set_t *srs, mac_resource_props_t *mrp)
{
	mac_soft_ring_t		*softring;

	mutex_enter(&srs->srs_lock);
	mutex_enter(&srs->srs_bw->mac_bw_lock);

	if (mrp->mrp_maxbw == MRP_MAXBW_RESETVAL) {
		/* Reset bandwidth limit */
		if (srs->srs_type & SRST_BW_CONTROL) {
			softring = srs->srs_soft_ring_head;
			while (softring != NULL) {
				softring->s_ring_type &= ~ST_RING_BW_CTL;
				softring = softring->s_ring_next;
			}
			srs->srs_type &= ~SRST_BW_CONTROL;
			srs->srs_drain_func = mac_rx_srs_drain;
		}
	} else {
		/* Set/Modify bandwidth limit */
		srs->srs_bw->mac_bw_limit = FLOW_BYTES_PER_TICK(mrp->mrp_maxbw);
		/*
		 * Give twice the queuing capability before
		 * dropping packets. The unit is bytes/tick.
		 */
		srs->srs_bw->mac_bw_drop_threshold =
		    srs->srs_bw->mac_bw_limit << 1;
		if (!(srs->srs_type & SRST_BW_CONTROL)) {
			softring = srs->srs_soft_ring_head;
			while (softring != NULL) {
				softring->s_ring_type |= ST_RING_BW_CTL;
				softring = softring->s_ring_next;
			}
			srs->srs_type |= SRST_BW_CONTROL;
			srs->srs_drain_func = mac_rx_srs_drain_bw;
		}
	}
done:
	mutex_exit(&srs->srs_bw->mac_bw_lock);
	mutex_exit(&srs->srs_lock);
}

/* Change the transmit bandwidth limit */
static void
mac_tx_srs_update_bwlimit(mac_soft_ring_set_t *srs, mac_resource_props_t *mrp)
{
	mac_srs_tx_t	*srs_tx = &srs->srs_tx;
	uint32_t	tx_mode;
	mac_impl_t *mip = srs->srs_mcip->mci_mip;

	mutex_enter(&srs->srs_lock);
	mutex_enter(&srs->srs_bw->mac_bw_lock);

	tx_mode = srs_tx->st_mode;

	if (mrp->mrp_maxbw == MRP_MAXBW_RESETVAL) {
		/* Reset bandwidth limit */
		if (tx_mode == SRS_TX_BW) {
			if (mac_tx_serialize ||
			    (mip->mi_v12n_level & MAC_VIRT_SERIALIZE)) {
				srs_tx->st_mode = SRS_TX_SERIALIZE;
			} else {
				srs_tx->st_mode = SRS_TX_DEFAULT;
			}
		} else if (tx_mode == SRS_TX_BW_FANOUT) {
			srs_tx->st_mode = SRS_TX_FANOUT;
		}
		srs->srs_type &= ~SRST_BW_CONTROL;
	} else {
		/* Set/Modify bandwidth limit */
		srs->srs_bw->mac_bw_limit = FLOW_BYTES_PER_TICK(mrp->mrp_maxbw);
		/*
		 * Give twice the queuing capability before
		 * dropping packets. The unit is bytes/tick.
		 */
		srs->srs_bw->mac_bw_drop_threshold =
		    srs->srs_bw->mac_bw_limit << 1;
		srs->srs_type |= SRST_BW_CONTROL;
		if (tx_mode != SRS_TX_BW &&
		    tx_mode != SRS_TX_BW_FANOUT) {
			if (tx_mode == SRS_TX_SERIALIZE ||
			    tx_mode == SRS_TX_DEFAULT) {
				srs_tx->st_mode = SRS_TX_BW;
			} else if (tx_mode == SRS_TX_FANOUT) {
				srs_tx->st_mode = SRS_TX_BW_FANOUT;
			} else {
				ASSERT(0);
			}
		}
	}
done:
	srs_tx->st_func = mac_tx_get_func(srs_tx->st_mode);
	mutex_exit(&srs->srs_bw->mac_bw_lock);
	mutex_exit(&srs->srs_lock);
}

/*
 * The uber function that deals with any update to bandwidth limits.
 */
void
mac_srs_update_bwlimit(flow_entry_t *flent, mac_resource_props_t *mrp)
{
	int			count;

	for (count = 0; count < flent->fe_rx_srs_cnt; count++)
		mac_rx_srs_update_bwlimit(flent->fe_rx_srs[count], mrp);
	mac_tx_srs_update_bwlimit(flent->fe_tx_srs, mrp);
}

void
mac_srs_change_upcall(void *arg, mac_direct_rx_t rx_func, void *rx_arg1)
{
	mac_soft_ring_set_t	*mac_srs = arg;
	mac_srs_rx_t		*srs_rx = &mac_srs->srs_rx;
	mac_soft_ring_t		*softring;

	mutex_enter(&mac_srs->srs_lock);
	ASSERT((mac_srs->srs_type & SRST_TX) == 0);
	srs_rx->sr_func = rx_func;
	srs_rx->sr_arg1 = rx_arg1;

	softring = mac_srs->srs_soft_ring_head;
	while (softring != NULL) {
		mutex_enter(&softring->s_ring_lock);
		softring->s_ring_rx_func = rx_func;
		softring->s_ring_rx_arg1 = rx_arg1;
		mutex_exit(&softring->s_ring_lock);
		softring = softring->s_ring_next;
	}

	mutex_exit(&mac_srs->srs_lock);
}

/*
 * When the first sub-flow is added to a link, we disable polling on the
 * link and also modify the entry point to mac_rx_srs_subflow_process.
 * (polling is disabled because with the subflow added, accounting
 * for polling needs additional logic, it is assumed that when a subflow is
 * added, we can take some hit as a result of disabling polling rather than
 * adding more complexity - if this becomes a perf. issue we need to
 * re-rvaluate this logic).  When the last subflow is removed, we turn back
 * polling and also reset the entry point to mac_rx_srs_process.
 *
 * In the future if there are multiple SRS, we can simply
 * take one and give it to the flow rather than disabling polling and
 * resetting the entry point.
 */
void
mac_client_update_classifier(mac_client_impl_t *mcip, boolean_t enable)
{
	flow_entry_t		*flent = mcip->mci_flent;
	int			i;
	mac_impl_t		*mip = mcip->mci_mip;
	mac_rx_func_t		rx_func;
	uint_t			rx_srs_cnt;
	boolean_t		enable_classifier;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	enable_classifier = !FLOW_TAB_EMPTY(mcip->mci_subflow_tab) && enable;

	rx_func = enable_classifier ? mac_rx_srs_subflow_process :
	    mac_rx_srs_process;

	/*
	 * If receive function has already been configured correctly for
	 * current subflow configuration, do nothing.
	 */
	if (flent->fe_cb_fn == (flow_fn_t)rx_func)
		return;

	rx_srs_cnt = flent->fe_rx_srs_cnt;
	for (i = 0; i < rx_srs_cnt; i++) {
		ASSERT(flent->fe_rx_srs[i] != NULL);
		mac_srs_poll_state_change(flent->fe_rx_srs[i],
		    enable_classifier, rx_func);
	}

	/*
	 * Change the S/W classifier so that we can land in the
	 * correct processing function with correct argument.
	 * If all subflows have been removed we can revert to
	 * mac_rx_srsprocess, else we need mac_rx_srs_subflow_process.
	 */
	mutex_enter(&flent->fe_lock);
	flent->fe_cb_fn = (flow_fn_t)rx_func;
	flent->fe_cb_arg1 = (void *)mip;
	flent->fe_cb_arg2 = flent->fe_rx_srs[0];
	mutex_exit(&flent->fe_lock);
}

static void
mac_srs_update_fanout_list(mac_soft_ring_set_t *mac_srs)
{
	int		tcp_count = 0;
	int		udp_count = 0;
	int		oth_count = 0;
	mac_soft_ring_t *softring;

	softring = mac_srs->srs_soft_ring_head;
	if (softring == NULL) {
		ASSERT(mac_srs->srs_soft_ring_count == 0);
		mac_srs->srs_tcp_ring_count = 0;
		mac_srs->srs_udp_ring_count = 0;
		mac_srs->srs_oth_ring_count = 0;
		return;
	}

	softring = mac_srs->srs_soft_ring_head;
	tcp_count = udp_count = oth_count = 0;

	while (softring != NULL) {
		if (softring->s_ring_type & ST_RING_TCP)
			mac_srs->srs_tcp_soft_rings[tcp_count++] = softring;
		else if (softring->s_ring_type & ST_RING_UDP)
			mac_srs->srs_udp_soft_rings[udp_count++] = softring;
		else
			mac_srs->srs_oth_soft_rings[oth_count++] = softring;
		softring = softring->s_ring_next;
	}

	ASSERT(mac_srs->srs_soft_ring_count ==
	    (tcp_count + udp_count + oth_count));

	mac_srs->srs_tcp_ring_count = tcp_count;
	mac_srs->srs_udp_ring_count = udp_count;
	mac_srs->srs_oth_ring_count = oth_count;
}

void
mac_srs_create_proto_softrings(int id, void *flent, uint16_t type,
    pri_t pri, mac_client_impl_t *mcip, mac_soft_ring_set_t *mac_srs,
    processorid_t cpuid, mac_direct_rx_t rx_func, void *x_arg1,
    mac_resource_handle_t x_arg2, boolean_t set_bypass)
{
	mac_soft_ring_t	*softring;
	mac_rx_fifo_t	mrf;

	bzero(&mrf, sizeof (mac_rx_fifo_t));
	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_receive = (mac_receive_t)mac_soft_ring_poll;
	mrf.mrf_intr_enable =
	    (mac_intr_enable_t)mac_soft_ring_intr_enable;
	mrf.mrf_intr_disable =
	    (mac_intr_disable_t)mac_soft_ring_intr_disable;
	mrf.mrf_flow_priority = pri;

	softring = mac_soft_ring_create(id, mac_soft_ring_worker_wait,
	    (void *)flent, (type|ST_RING_TCP), pri, mcip, mac_srs,
	    cpuid, rx_func, x_arg1, x_arg2);
	softring->s_ring_rx_arg2 = NULL;

	/*
	 * TCP and UDP support DLS bypass. In addition TCP
	 * squeue can also poll their corresponding soft rings.
	 */
	if (set_bypass && (mcip->mci_resource_arg != NULL)) {
		mac_soft_ring_dls_bypass(softring,
		    mcip->mci_direct_rx_fn,
		    mcip->mci_direct_rx_arg);

		mrf.mrf_rx_arg = softring;
		mrf.mrf_intr_handle = (mac_intr_handle_t)softring;

		/*
		 * Make a call in IP to get a TCP squeue assigned to
		 * this softring to maintain full CPU locality through
		 * the stack and allow the squeue to be able to poll
		 * the softring so the flow control can be pushed
		 * all the way to H/W.
		 */
		softring->s_ring_rx_arg2 =
		    mcip->mci_resource_add((void *)mcip->mci_resource_arg,
		    (mac_resource_t *)&mrf);
	}

	/*
	 * Non-TCP protocols don't support squeues. Hence we
	 * don't make any ring addition callbacks for non-TCP
	 * rings. Now create the UDP softring and allow it to
	 * bypass the DLS layer.
	 */
	softring = mac_soft_ring_create(id, mac_soft_ring_worker_wait,
	    (void *)flent, (type|ST_RING_UDP), pri, mcip, mac_srs,
	    cpuid, rx_func, x_arg1, x_arg2);
	softring->s_ring_rx_arg2 = NULL;

	if (set_bypass && (mcip->mci_resource_arg != NULL)) {
		mac_soft_ring_dls_bypass(softring,
		    mcip->mci_direct_rx_fn,
		    mcip->mci_direct_rx_arg);
	}

	/* Create the Oth softrings which has to go through the DLS */
	softring = mac_soft_ring_create(id, mac_soft_ring_worker_wait,
	    (void *)flent, (type|ST_RING_OTH), pri, mcip, mac_srs,
	    cpuid, rx_func, x_arg1, x_arg2);
	softring->s_ring_rx_arg2 = NULL;
}

/*
 * This routine associates a CPU or a set of CPU to process incoming
 * traffic from a mac client. If multiple CPUs are specified, then
 * so many soft rings are created with each soft ring worker thread
 * bound to a CPU in the set. Each soft ring in turn will be
 * associated with an squeue and the squeue will be moved to the
 * same CPU as that of the soft ring's.
 */
static void
mac_srs_fanout_modify(mac_client_impl_t *mcip, flow_entry_t *flent,
    mac_resource_props_t *mrp, mac_direct_rx_t rx_func, void *x_arg1,
    mac_resource_handle_t x_arg2, mac_soft_ring_set_t *mac_rx_srs,
    mac_soft_ring_set_t *mac_tx_srs)
{
	mac_soft_ring_t *softring;
	uint32_t soft_ring_flag = soft_ring_process_flag;
	processorid_t cpuid = -1;
	boolean_t user_specified;
	int i, srings_present, new_fanout_cnt;
	mac_cpus_t *srs_cpu;

	user_specified = mrp->mrp_mask & MRP_CPUS_USERSPEC;
	/* fanout state is REINIT. Set it back to INIT */
	ASSERT(mac_rx_srs->srs_fanout_state == SRS_FANOUT_REINIT);
	mac_rx_srs->srs_fanout_state = SRS_FANOUT_INIT;

	/* how many are present right now */
	srings_present = mac_rx_srs->srs_tcp_ring_count;
	/* new request */
	srs_cpu = &mac_rx_srs->srs_cpu;
	new_fanout_cnt = srs_cpu->mc_fanout_cnt;

	mutex_enter(&mac_rx_srs->srs_lock);
	if (mac_rx_srs->srs_type & SRST_BW_CONTROL)
		soft_ring_flag |= ST_RING_BW_CTL;
	mutex_exit(&mac_rx_srs->srs_lock);

	if (new_fanout_cnt > srings_present) {
		/* soft rings increased */
		mutex_enter(&mac_rx_srs->srs_lock);
		mac_rx_srs->srs_type |= SRST_FANOUT_SRC_IP;
		mutex_exit(&mac_rx_srs->srs_lock);

		for (i = mac_rx_srs->srs_tcp_ring_count;
		    i < new_fanout_cnt; i++) {
			/*
			 * Create the protocol softrings and set the
			 * DLS bypass where possible.
			 */
			mac_srs_create_proto_softrings(i,
			    (void *)flent, soft_ring_flag,
			    mac_rx_srs->srs_pri, mcip, mac_rx_srs, cpuid,
			    rx_func, x_arg1, x_arg2, B_TRUE);
		}
		mac_srs_update_fanout_list(mac_rx_srs);
	} else if (new_fanout_cnt < srings_present) {
		/* soft rings decreased */
		if (new_fanout_cnt == 1) {
			mutex_enter(&mac_rx_srs->srs_lock);
			mac_rx_srs->srs_type &= ~SRST_FANOUT_SRC_IP;
			ASSERT(mac_rx_srs->srs_type & SRST_FANOUT_PROTO);
			mutex_exit(&mac_rx_srs->srs_lock);
		}
		/* Get rid of extra soft rings */
		for (i = new_fanout_cnt;
		    i < mac_rx_srs->srs_tcp_ring_count; i++) {
			softring = mac_rx_srs->srs_tcp_soft_rings[i];
			if (softring->s_ring_rx_arg2 != NULL) {
				mcip->mci_resource_remove(
				    (void *)mcip->mci_resource_arg,
				    softring->s_ring_rx_arg2);
			}
			mac_soft_ring_remove(mac_rx_srs,
			    mac_rx_srs->srs_tcp_soft_rings[i]);
			mac_soft_ring_remove(mac_rx_srs,
			    mac_rx_srs->srs_udp_soft_rings[i]);
			mac_soft_ring_remove(mac_rx_srs,
			    mac_rx_srs->srs_oth_soft_rings[i]);
		}
		mac_srs_update_fanout_list(mac_rx_srs);
	}

	ASSERT(new_fanout_cnt == mac_rx_srs->srs_tcp_ring_count);
	mutex_enter(&cpu_lock);
	for (i = 0; i < mac_rx_srs->srs_tcp_ring_count; i++) {
		cpuid = srs_cpu->mc_fanout_cpus[i];
		(void) mac_soft_ring_bind(mac_rx_srs->srs_udp_soft_rings[i],
		    cpuid);
		(void) mac_soft_ring_bind(mac_rx_srs->srs_oth_soft_rings[i],
		    cpuid);
		(void) mac_soft_ring_bind(mac_rx_srs->srs_tcp_soft_rings[i],
		    cpuid);
		softring = mac_rx_srs->srs_tcp_soft_rings[i];
		if (softring->s_ring_rx_arg2 != NULL) {
			mcip->mci_resource_bind((void *)mcip->mci_resource_arg,
			    softring->s_ring_rx_arg2, cpuid);
		}
	}

	mac_srs_worker_bind(mac_rx_srs, srs_cpu->mc_pollid);
	mac_srs_poll_bind(mac_rx_srs, srs_cpu->mc_workerid);

	/*
	 * Bind Tx srs and soft ring threads too. Let's bind tx
	 * srs to the last cpu in mrp list.
	 */
	if (mac_tx_srs != NULL && user_specified) {
		BIND_TX_SRS_AND_SOFT_RINGS(mac_tx_srs, mrp);
	}
	mutex_exit(&cpu_lock);
}

/*
 * Bind SRS threads and soft rings to CPUs/create fanout list.
 */
void
mac_srs_fanout_init(mac_client_impl_t *mcip, flow_entry_t *flent,
    mac_resource_props_t *mrp, mac_direct_rx_t rx_func, void *x_arg1,
    mac_resource_handle_t x_arg2, mac_soft_ring_set_t *mac_rx_srs,
    mac_soft_ring_set_t *mac_tx_srs)
{
	int		i;
	processorid_t	cpuid, worker_cpuid, poll_cpuid;
	uint32_t	soft_ring_flag = soft_ring_process_flag;
	int soft_ring_cnt;
	boolean_t user_specified = B_FALSE;
	mac_cpus_t *srs_cpu = &mac_rx_srs->srs_cpu;

	/*
	 * Remove the no soft ring flag and we will adjust it
	 * appropriately further down.
	 */
	mutex_enter(&mac_rx_srs->srs_lock);
	mac_rx_srs->srs_type &= ~SRST_NO_SOFT_RINGS;
	mutex_exit(&mac_rx_srs->srs_lock);

	ASSERT(mac_rx_srs->srs_soft_ring_head == NULL);

	if (mac_rx_srs->srs_type & SRST_BW_CONTROL)
		soft_ring_flag |= ST_RING_BW_CTL;

	ASSERT(mac_rx_srs->srs_fanout_state == SRS_FANOUT_UNINIT);
	mac_rx_srs->srs_fanout_state = SRS_FANOUT_INIT;
	user_specified = mrp->mrp_mask & MRP_CPUS_USERSPEC;
	/*
	 * Ring count can be 0 if no fanout is required and no cpu
	 * were specified. Leave the SRS worker and poll thread
	 * unbound
	 */
	ASSERT(mrp != NULL);
	soft_ring_cnt = srs_cpu->mc_fanout_cnt;

	/* Step 1: bind cpu contains cpu list where threads need to bind */
	if (soft_ring_cnt > 0) {
		mutex_enter(&cpu_lock);
		for (i = 0; i < soft_ring_cnt; i++) {
			cpuid = srs_cpu->mc_fanout_cpus[i];
			/* Create the protocol softrings */
			mac_srs_create_proto_softrings(i, (void *)flent,
			    soft_ring_flag, mac_rx_srs->srs_pri,
			    mcip, mac_rx_srs, cpuid, rx_func,
			    x_arg1, x_arg2, B_FALSE);
		}
		worker_cpuid = srs_cpu->mc_workerid;
		poll_cpuid = srs_cpu->mc_pollid;
		mac_srs_worker_bind(mac_rx_srs, worker_cpuid);
		mac_srs_poll_bind(mac_rx_srs, poll_cpuid);

		/*
		 * Bind Tx srs and soft ring threads too.
		 * Let's bind tx srs to the last cpu in
		 * mrp list.
		 */
		if (mac_tx_srs == NULL) {
			mutex_exit(&cpu_lock);
			goto alldone;
		}

		if (user_specified) {
			BIND_TX_SRS_AND_SOFT_RINGS(mac_tx_srs, mrp);
		}
		mutex_exit(&cpu_lock);
	} else {
		mutex_enter(&cpu_lock);
		/*
		 * For a subflow, mrp_workerid and mrp_pollid
		 * is not set.
		 */
		mac_srs_worker_bind(mac_rx_srs, mrp->mrp_workerid);
		mac_srs_poll_bind(mac_rx_srs, mrp->mrp_pollid);
		mutex_exit(&cpu_lock);
		goto no_softrings;
	}

alldone:
	if (soft_ring_cnt > 1)
		mac_rx_srs->srs_type |= SRST_FANOUT_SRC_IP;
	mac_srs_update_fanout_list(mac_rx_srs);
	mac_srs_client_poll_enable(mcip, mac_rx_srs);
	return;

no_softrings:
	if (mac_rx_srs->srs_type & SRST_FANOUT_PROTO) {
		mutex_enter(&cpu_lock);
		cpuid = mac_next_bind_cpu();
		/* Create the protocol softrings */
		mac_srs_create_proto_softrings(0, (void *)flent,
		    soft_ring_flag, mac_rx_srs->srs_pri,
		    mcip, mac_rx_srs, cpuid, rx_func,
		    x_arg1, x_arg2, B_FALSE);
		mutex_exit(&cpu_lock);
	} else {
		/*
		 * This is the case when there is no fanout which is
		 * true for subflows.
		 */
		mac_rx_srs->srs_type |= SRST_NO_SOFT_RINGS;
	}
	mac_srs_update_fanout_list(mac_rx_srs);
	mac_srs_client_poll_enable(mcip, mac_rx_srs);
}

/*
 * mac_fanout_setup:
 *
 * Calls mac_srs_fanout_init() or modify() depending upon whether
 * the SRS is getting initialized or re-initialized.
 */
void
mac_fanout_setup(mac_client_impl_t *mcip, flow_entry_t *flent,
    mac_resource_props_t *mrp, mac_direct_rx_t rx_func, void *x_arg1,
    mac_resource_handle_t x_arg2)
{
	mac_soft_ring_set_t *mac_rx_srs, *mac_tx_srs;
	int i, rx_srs_cnt;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));
	/*
	 * This is an aggregation port. Fanout will be setup
	 * over the aggregation itself.
	 */
	if (mcip->mci_state_flags & MCIS_IS_AGGR_PORT)
		return;

	mac_rx_srs = flent->fe_rx_srs[0];
	/*
	 * Set up the fanout on the tx side only once, with the
	 * first rx SRS. The CPU binding, fanout, and bandwidth
	 * criteria are common to both RX and TX, so
	 * initializing them along side avoids redundant code.
	 */
	mac_tx_srs = flent->fe_tx_srs;
	rx_srs_cnt = flent->fe_rx_srs_cnt;

	/* No fanout for subflows */
	if (flent->fe_type & FLOW_USER) {
		mac_srs_fanout_init(mcip, flent, mrp, rx_func,
		    x_arg1, x_arg2, mac_rx_srs, mac_tx_srs);
		return;
	}

	mac_flow_cpu_init(flent, mrp);

	/*
	 * Set up fanout for both SW (0th SRS) and HW classified
	 * SRS (the rest of Rx SRSs in flent).
	 */
	for (i = 0; i < rx_srs_cnt; i++) {
		mac_rx_srs = flent->fe_rx_srs[i];
		if (i != 0)
			mac_tx_srs = NULL;
		switch (mac_rx_srs->srs_fanout_state) {
		case SRS_FANOUT_UNINIT:
			mac_srs_fanout_init(mcip, flent, mrp, rx_func,
			    x_arg1, x_arg2, mac_rx_srs, mac_tx_srs);
			break;
		case SRS_FANOUT_INIT:
			break;
		case SRS_FANOUT_REINIT:
			mac_rx_srs_quiesce(mac_rx_srs, SRS_QUIESCE);
			mac_srs_fanout_modify(mcip, flent, mrp, rx_func,
			    x_arg1, x_arg2, mac_rx_srs, mac_tx_srs);
			mac_rx_srs_restart(mac_rx_srs);
			break;
		default:
			VERIFY(mac_rx_srs->srs_fanout_state <=
			    SRS_FANOUT_REINIT);
			break;
		}
	}
}

/*
 * mac_create_soft_ring_set:
 *
 * Create a mac_soft_ring_set_t (SRS). If soft_ring_fanout_type is
 * SRST_TX, an SRS for Tx side is created. Otherwise an SRS for Rx side
 * processing is created.
 *
 * Details on Rx SRS:
 * Create a SRS and also add the necessary soft rings for TCP and
 * non-TCP based on fanout type and count specified.
 *
 * mac_soft_ring_fanout, mac_srs_fanout_modify (?),
 * mac_soft_ring_stop_workers, mac_soft_ring_set_destroy, etc need
 * to be heavily modified.
 *
 * mi_soft_ring_list_size, mi_soft_ring_size, etc need to disappear.
 */
mac_soft_ring_set_t *
mac_srs_create(mac_client_impl_t *mcip, flow_entry_t *flent, uint32_t srs_type,
    mac_direct_rx_t rx_func, void *x_arg1, mac_resource_handle_t x_arg2,
    mac_ring_t *ring)
{
	mac_soft_ring_set_t 	*mac_srs;
	mac_srs_rx_t		*srs_rx;
	mac_srs_tx_t		*srs_tx;
	mac_bw_ctl_t		*mac_bw;
	mac_resource_props_t	*mrp;
	boolean_t		is_tx_srs = ((srs_type & SRST_TX) != 0);

	mac_srs = kmem_cache_alloc(mac_srs_cache, KM_SLEEP);
	bzero(mac_srs, sizeof (mac_soft_ring_set_t));
	srs_rx = &mac_srs->srs_rx;
	srs_tx = &mac_srs->srs_tx;

	mutex_enter(&flent->fe_lock);

	/*
	 * Get the bandwidth control structure from the flent. Get
	 * rid of any residual values in the control structure for
	 * the tx bw struct and also for the rx, if the rx srs is
	 * the 1st one being brought up (the rx bw ctl struct may
	 * be shared by multiple SRSs)
	 */
	if (is_tx_srs) {
		mac_srs->srs_bw = &flent->fe_tx_bw;
		bzero(mac_srs->srs_bw, sizeof (mac_bw_ctl_t));
		flent->fe_tx_srs = mac_srs;
	} else {
		/*
		 * The bw counter (stored in the flent) is shared
		 * by SRS's within an rx group.
		 */
		mac_srs->srs_bw = &flent->fe_rx_bw;
		/* First rx SRS, clear the bw structure */
		if (flent->fe_rx_srs_cnt == 0)
			bzero(mac_srs->srs_bw, sizeof (mac_bw_ctl_t));
		ASSERT(flent->fe_rx_srs_cnt < MAX_RINGS_PER_GROUP);
		flent->fe_rx_srs[flent->fe_rx_srs_cnt] = mac_srs;
		flent->fe_rx_srs_cnt++;
	}
	mac_srs->srs_flent = flent;
	mutex_exit(&flent->fe_lock);

	mac_srs->srs_state = 0;
	mac_srs->srs_type = (srs_type | SRST_NO_SOFT_RINGS);
	mac_srs->srs_worker_cpuid = mac_srs->srs_worker_cpuid_save = -1;
	mac_srs->srs_poll_cpuid = mac_srs->srs_poll_cpuid_save = -1;
	mac_srs_fanout_list_alloc(mac_srs);

	/*
	 * For a flow we use the underlying MAC client's priority range with
	 * the priority value to find an absolute priority value. For a MAC
	 * client we use the MAC client's maximum priority as the value.
	 */
	mrp = &flent->fe_effective_props;
	if ((mac_srs->srs_type & SRST_FLOW) != 0) {
		mac_srs->srs_pri = FLOW_PRIORITY(mcip->mci_min_pri,
		    mcip->mci_max_pri, mrp->mrp_priority);
	} else {
		mac_srs->srs_pri = mcip->mci_max_pri;
	}
	mac_srs->srs_mcip = mcip;
	/*
	 * We need to insert the SRS in the global list before
	 * binding the SRS and SR threads. Otherwise there is a
	 * is a small window where the cpu reconfig callbacks
	 * may miss the SRS in the list walk and DR could fail
	 * as there are bound threads.
	 */
	mac_srs_add_glist(mac_srs);

	/* Initialize bw limit */
	if ((mrp->mrp_mask & MRP_MAXBW) != 0) {
		mac_srs->srs_drain_func = mac_rx_srs_drain_bw;

		mac_bw = mac_srs->srs_bw;
		mutex_enter(&mac_bw->mac_bw_lock);
		mac_bw->mac_bw_limit = FLOW_BYTES_PER_TICK(mrp->mrp_maxbw);

		/*
		 * Give twice the queuing capability before
		 * dropping packets. The unit is bytes/tick.
		 */
		mac_bw->mac_bw_drop_threshold = mac_bw->mac_bw_limit << 1;
		mutex_exit(&mac_bw->mac_bw_lock);
		mac_srs->srs_type |= SRST_BW_CONTROL;
	} else {
		mac_srs->srs_drain_func = mac_rx_srs_drain;
	}

	/*
	 * We use the following policy to control Receive
	 * Side Dynamic Polling:
	 * 1) We switch to poll mode anytime the processing thread causes
	 *    a backlog to build up in SRS and its associated Soft Rings
	 *    (sr_poll_pkt_cnt > 0).
	 * 2) As long as the backlog stays under the low water mark
	 *    (sr_lowat), we poll the H/W for more packets.
	 * 3) If the backlog (sr_poll_pkt_cnt) exceeds low water mark, we
	 *    stay in poll mode but don't poll the H/W for more packets.
	 * 4) Anytime in polling mode, if we poll the H/W for packets and
	 *    find nothing plus we have an existing backlog
	 *    (sr_poll_pkt_cnt > 0), we stay in polling mode but don't poll
	 *    the H/W for packets anymore (let the polling thread go to sleep).
	 * 5) Once the backlog is relived (packets are processed) we reenable
	 *    polling (by signalling the poll thread) only when the backlog
	 *    dips below sr_poll_thres.
	 * 6) sr_hiwat is used exclusively when we are not polling capable
	 *    and is used to decide when to drop packets so the SRS queue
	 *    length doesn't grow infinitely.
	 */
	if (!is_tx_srs) {
		srs_rx->sr_hiwat = mac_soft_ring_max_q_cnt;
		/* Low water mark needs to be less than high water mark */
		srs_rx->sr_lowat = mac_soft_ring_min_q_cnt <=
		    mac_soft_ring_max_q_cnt ? mac_soft_ring_min_q_cnt :
		    (mac_soft_ring_max_q_cnt >> 2);
		/* Poll threshold need to be half of low water mark or less */
		srs_rx->sr_poll_thres = mac_soft_ring_poll_thres <=
		    (srs_rx->sr_lowat >> 1) ? mac_soft_ring_poll_thres :
		    (srs_rx->sr_lowat >> 1);
		if (mac_latency_optimize)
			mac_srs->srs_state |= SRS_LATENCY_OPT;
	}

	mac_srs->srs_worker = thread_create(NULL, 0,
	    mac_srs_worker, mac_srs, 0, &p0, TS_RUN, mac_srs->srs_pri);

	if (is_tx_srs) {
		/* Handle everything about Tx SRS and return */
		mac_srs->srs_drain_func = mac_tx_srs_drain;
		srs_tx->st_max_q_cnt = mac_tx_srs_max_q_cnt;
		srs_tx->st_hiwat =
		    (mac_tx_srs_hiwat > mac_tx_srs_max_q_cnt) ?
		    mac_tx_srs_max_q_cnt : mac_tx_srs_hiwat;
		srs_tx->st_arg1 = x_arg1;
		srs_tx->st_arg2 = x_arg2;
		return (mac_srs);
	}

	if ((srs_type & SRST_FLOW) != 0 ||
	    FLOW_TAB_EMPTY(mcip->mci_subflow_tab))
		srs_rx->sr_lower_proc = mac_rx_srs_process;
	else
		srs_rx->sr_lower_proc = mac_rx_srs_subflow_process;

	srs_rx->sr_func = rx_func;
	srs_rx->sr_arg1 = x_arg1;
	srs_rx->sr_arg2 = x_arg2;

	if (ring != NULL) {
		/* Is the mac_srs created over the RX default group? */
		if (ring->mr_gh == (mac_group_handle_t)
		    (&mcip->mci_mip->mi_rx_groups[0]))
			mac_srs->srs_type |= SRST_DEFAULT_GRP;

		mac_srs->srs_ring = ring;
		ring->mr_srs = mac_srs;
		ring->mr_classify_type = MAC_HW_CLASSIFIER;
		ring->mr_flag |= MR_INCIPIENT;

		if (FLOW_TAB_EMPTY(mcip->mci_subflow_tab))
			mac_srs->srs_state |= SRS_POLLING_CAPAB;

		mac_srs->srs_poll_thr = thread_create(NULL, 0,
		    mac_rx_srs_poll_ring, mac_srs, 0, &p0, TS_RUN,
		    mac_srs->srs_pri);
	}
	return (mac_srs);
}

/*
 * Figure out the number of soft rings required. Its dependant on
 * if protocol fanout is required (for LINKs), global settings
 * require us to do fanout for performance (based on mac_soft_ring_enable),
 * or user has specifically requested fanout.
 */
static uint32_t
mac_find_fanout(flow_entry_t *flent, uint32_t link_type)
{
	uint32_t			fanout_type;
	mac_resource_props_t		*mrp = &flent->fe_effective_props;

	/* no fanout for subflows */
	switch (link_type) {
	case SRST_FLOW:
		fanout_type = SRST_NO_SOFT_RINGS;
		break;
	case SRST_LINK:
		fanout_type = SRST_FANOUT_PROTO;
		break;
	}

	/* A primary NIC/link is being plumbed */
	if (flent->fe_type & FLOW_PRIMARY_MAC) {
		if (mac_soft_ring_enable && mac_rx_soft_ring_count > 1) {
			fanout_type |= SRST_FANOUT_SRC_IP;
		}
	} else if (flent->fe_type & FLOW_VNIC) {
		/* A VNIC is being created */
		if (mrp != NULL && mrp->mrp_ncpus > 0) {
			fanout_type |= SRST_FANOUT_SRC_IP;
		}
	}

	return (fanout_type);
}

/*
 * Change a group from h/w to s/w classification.
 */
static void
mac_rx_switch_grp_to_sw(mac_group_t *group)
{
	mac_ring_t		*ring;
	mac_soft_ring_set_t	*mac_srs;

	for (ring = group->mrg_rings; ring != NULL; ring = ring->mr_next) {
		if (ring->mr_classify_type == MAC_HW_CLASSIFIER) {
			/*
			 * Remove the SRS associated with the HW ring.
			 * As a result, polling will be disabled.
			 */
			mac_srs = ring->mr_srs;
			ASSERT(mac_srs != NULL);
			mac_rx_srs_remove(mac_srs);
			ring->mr_srs = NULL;
		}

		if (ring->mr_state != MR_INUSE)
			(void) mac_start_ring(ring);
		/*
		 * We need to perform SW classification
		 * for packets landing in these rings
		 */
		ring->mr_state = MR_INUSE;
		ring->mr_flag = 0;
		ring->mr_classify_type = MAC_SW_CLASSIFIER;
	}
}

/*
 * Create the Rx SRS for S/W classifier and for each ring in the
 * group (if exclusive group). Also create the Tx SRS.
 */
void
mac_srs_group_setup(mac_client_impl_t *mcip, flow_entry_t *flent,
    mac_group_t *group, uint32_t link_type)
{
	mac_impl_t		*mip = mcip->mci_mip;
	mac_soft_ring_set_t	*mac_srs;
	mac_soft_ring_set_t	*tx_srs = NULL;
	mac_ring_t 		*ring;
	uint32_t		fanout_type;
	boolean_t		created_srs = B_FALSE;

	fanout_type = mac_find_fanout(flent, link_type);

	/* Create the SRS for S/W classification if none exists */
	if (flent->fe_rx_srs[0] == NULL) {
		ASSERT(flent->fe_rx_srs_cnt == 0);
		/* Setup the Rx SRS */
		mac_srs = mac_srs_create(mcip, flent, fanout_type | link_type,
		    mac_rx_deliver, mcip, NULL, NULL);

		mutex_enter(&flent->fe_lock);
		flent->fe_cb_fn = (flow_fn_t)mac_srs->srs_rx.sr_lower_proc;
		flent->fe_cb_arg1 = (void *)mip;
		flent->fe_cb_arg2 = (void *)mac_srs;
		mutex_exit(&flent->fe_lock);

		/* Setup the Tx SRS as well */
		ASSERT(flent->fe_tx_srs == NULL);
		tx_srs = mac_srs_create(mcip, flent, SRST_TX | link_type,
		    NULL, mcip, NULL, NULL);

		if (mcip->mci_share != NULL) {
			mac_srs_tx_t	*tx = &tx_srs->srs_tx;
			ASSERT((mcip->mci_state_flags & MCIS_NO_HWRINGS) == 0);
			/*
			 * A share requires a dedicated TX group.
			 * mac_reserve_tx_group() does the work needed to
			 * allocate a new group and populate that group
			 * with rings according to the driver requirements
			 * and limitations.
			 */
			tx->st_group =
			    mac_reserve_tx_group(mip, mcip->mci_share);
			ASSERT(tx->st_group != NULL);
			tx->st_group->mrg_tx_client = mcip;
		}
		mac_tx_srs_setup(mcip, flent, link_type);
		created_srs = B_TRUE;
	}

	if (group == NULL) {
		if (created_srs) {
			mac_fanout_setup(mcip, flent,
			    MCIP_RESOURCE_PROPS(mcip), mac_rx_deliver,
			    mcip, NULL);
		}
		return;
	}

	/*
	 * fanout for default SRS is done when default SRS are created
	 * above. As each ring is added to the group, we setup the
	 * SRS and fanout to it.
	 */
	switch (group->mrg_state) {
	case MAC_GROUP_STATE_RESERVED:
		/*
		 * The group is exclusively ours. Create a SRS
		 * for each ring in the group and allow the
		 * individual SRS to dynamically poll their
		 * Rx ring. Do this only if the  client is not
		 * a VLAN MAC client since for VLAN we do
		 * s/w classification for the VID check.
		 */
		if (i_mac_flow_vid(mcip->mci_flent) != VLAN_ID_NONE)
			break;
		for (ring = group->mrg_rings; ring != NULL;
		    ring = ring->mr_next) {
			switch (ring->mr_state) {
			case MR_INUSE:
			case MR_FREE:
				if (ring->mr_srs != NULL)
					break;
				if (ring->mr_state != MR_INUSE)
					(void) mac_start_ring(ring);

				ring->mr_state = MR_INUSE;

				mac_srs = mac_srs_create(mcip, flent,
				    fanout_type | link_type,
				    mac_rx_deliver, mcip, NULL, ring);
				if (mip->mi_v12n_level & MAC_VIRT_SERIALIZE) {
					mac_srs->srs_rx.sr_enqueue_always =
					    B_TRUE;
				}
				break;
			default:
				cmn_err(CE_PANIC, "srs_setup: mcip = %p "
				    "trying to add UNKNOWN ring = %p\n",
				    (void *)mcip, (void *)ring);
				break;
			}
		}
		break;
	case MAC_GROUP_STATE_SHARED:
		/*
		 * Set all rings of this group to software classified.
		 *
		 * If the group is current RESERVED, the existing mac client
		 * (the only client on this group) is using this group
		 * exclusively.  In that case we need to disable polling on
		 * the rings of the group (if it was enabled), and free the
		 * SRS associated with the rings.
		 */
		mac_rx_switch_grp_to_sw(group);
		break;
	default:
		ASSERT(B_FALSE);
		break;
	}
	mac_fanout_setup(mcip, flent, MCIP_RESOURCE_PROPS(mcip),
	    mac_rx_deliver, mcip, NULL);
}

void
mac_srs_group_teardown(mac_client_impl_t *mcip, flow_entry_t *flent,
    uint32_t link_type)
{
	mac_soft_ring_set_t	*mac_srs;
	mac_soft_ring_set_t	*tx_srs;
	mac_srs_tx_t		*tx;
	int			i;

	for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
		mac_srs = flent->fe_rx_srs[i];
		mac_rx_srs_quiesce(mac_srs, SRS_CONDEMNED);
		/*
		 * Deal with all fanout tear down etc.
		 */
		mac_srs_free(mac_srs);
		flent->fe_rx_srs[i] = NULL;
	}
	flent->fe_rx_srs_cnt = 0;

	tx_srs = flent->fe_tx_srs;
	tx = &tx_srs->srs_tx;
	switch (link_type) {
	case SRST_FLOW:
		/*
		 * For flows, we need to work with passed
		 * flent to find the Rx/Tx SRS.
		 */
		mac_tx_srs_quiesce(tx_srs, SRS_CONDEMNED);
		break;
	case SRST_LINK:
		mac_tx_client_quiesce(mcip, SRS_CONDEMNED);
		/*
		 * Release the TX resources. First the TX group, if any
		 * was assigned to the MAC client, which will cause the
		 * TX rings to be moved back to the pool. Then free the
		 * rings themselves.
		 */
		if (tx->st_group != NULL) {
			mac_release_tx_group(tx_srs->srs_mcip->mci_mip,
			    tx->st_group);
			tx->st_group = NULL;
		}
		if (tx->st_arg2 != NULL) {
			ASSERT(tx_srs->srs_type & SRST_TX);
			mac_release_tx_ring(tx->st_arg2);
		}
		break;
	default:
		ASSERT(B_FALSE);
		break;
	}
	mac_srs_free(tx_srs);
	flent->fe_tx_srs = NULL;
}

/*
 * This is the group state machine. The state of an Rx group is given by
 * the following table. The default group and its rings are started in
 * mac_start itself and the default group stays in SHARED state until
 * mac_stop at which time the group and rings are stopped and and it
 * reverts to the Registered state.
 *
 * Typically this function is called on a group after adding or removing a
 * client from it, to find out what should be the new state of the group.
 * If the new state is RESERVED, then the client that owns this group
 * exclusively is also returned. Note that adding or removing a client from
 * a group could also impact the default group and the caller needs to
 * evaluate the effect on the default group.
 *
 * Group type		# of clients	mi_nactiveclients	Group State
 *			in the group
 *
 * Non-default		0		N.A.			REGISTERED
 * Non-default		1		N.A.			RESERVED
 * Non-default		> 1		N.A.			SHARED
 *
 * Default		0		N.A.			SHARED
 * Default		1		1			RESERVED
 * Default		1		> 1			SHARED
 * Default		> 1		N.A.			SHARED
 */
mac_group_state_t
mac_rx_group_next_state(mac_group_t *grp, mac_client_impl_t **group_only_mcip)
{
	mac_impl_t		*mip = (mac_impl_t *)grp->mrg_mh;

	*group_only_mcip = NULL;

	/* Non-default group */

	if (grp != mip->mi_rx_groups) {
		if (MAC_RX_GROUP_NO_CLIENT(grp))
			return (MAC_GROUP_STATE_REGISTERED);

		*group_only_mcip = MAC_RX_GROUP_ONLY_CLIENT(grp);
		if (*group_only_mcip != NULL)
			return (MAC_GROUP_STATE_RESERVED);

		return (MAC_GROUP_STATE_SHARED);
	}

	/* Default group */

	if (MAC_RX_GROUP_NO_CLIENT(grp) || mip->mi_nactiveclients != 1)
		return (MAC_GROUP_STATE_SHARED);

	*group_only_mcip = MAC_RX_GROUP_ONLY_CLIENT(grp);
	ASSERT(*group_only_mcip != NULL);
	return (MAC_GROUP_STATE_RESERVED);
}

/*
 * OVERVIEW NOTES FOR DATAPATH
 * ===========================
 *
 * Create an SRS and setup the corresponding flow function and args.
 * Add a classification rule for the flow specified by 'flent' and program
 * the hardware classifier when applicable.
 *
 * Rx ring assignment, SRS, polling and B/W enforcement
 * ----------------------------------------------------
 *
 * We try to use H/W classification on NIC and assign traffic to a
 * MAC address to a particular Rx ring. There is a 1-1 mapping
 * between a SRS and a Rx ring. The SRS (short for soft ring set)
 * dynamically switches the underlying Rx ring between interrupt
 * and polling mode and enforces any specified B/W control.
 *
 * There is always a SRS created and tied to each H/W and S/W rule.
 * Whenever we create a H/W rule, we always add the the same rule to
 * S/W classifier and tie a SRS to it.
 *
 * In case a B/W control is specified, its broken into bytes
 * per ticks and as soon as the quota for a tick is exhausted,
 * the underlying Rx ring is forced into poll mode for remianing
 * tick. The SRS poll thread only polls for bytes that are
 * allowed to come in the SRS. We typically let 4x the configured
 * B/W worth of packets to come in the SRS (to prevent unnecessary
 * drops due to bursts) but only process the specified amount.
 *
 * A Link (primary NIC, VNIC, VLAN or aggr) can have 1 or more
 * Rx rings (and corresponding SRSs) assigned to it. The SRS
 * in turn can have softrings to do protocol level fanout or
 * softrings to do S/W based fanout or both. In case the NIC
 * has no Rx rings, we do S/W classification to respective SRS.
 * The S/W classification rule is always setup and ready. This
 * allows the MAC layer to reassign Rx rings whenever needed
 * but packets still continue to flow via the default path and
 * getting S/W classified to correct SRS.
 *
 * In other cases where a NIC or VNIC is plumbed, our goal is use
 * H/W classifier and get two Rx ring assigned for the Link. One
 * for TCP and one for UDP|SCTP. The respective SRS still do the
 * polling on the Rx ring. For Link that is plumbed for IP, there
 * is a TCP squeue which also does polling and can control the
 * the Rx ring directly (where SRS is just pass through). For
 * the following cases, the SRS does the polling underneath.
 * 1) non IP based Links (Links which are not plumbed via ifconfig)
 *    and paths which have no IP squeues (UDP & SCTP)
 * 2) If B/W control is specified on the Link
 * 3) If S/W fanout is secified
 *
 * Note1: As of current implementation, we try to assign only 1 Rx
 * ring per Link and more than 1 Rx ring for primary Link for
 * H/W based fanout. We always create following softrings per SRS:
 * 1) TCP softring which is polled by TCP squeue where possible
 *    (and also bypasses DLS)
 * 2) UDP/SCTP based which bypasses DLS
 * 3) OTH softring which goes via DLS (currently deal with IPv6
 *    and non TCP/UDP/SCTP for IPv4 packets).
 *
 * It is necessary to create 3 softrings since SRS has to poll
 * the single Rx ring underneath and enforce any link level B/W
 * control (we can't switch the Rx ring in poll mode just based
 * on TCP squeue if the same Rx ring is sharing UDP and other
 * traffic as well). Once polling is done and any Link level B/W
 * control is specified, the packets are assigned to respective
 * softring based on protocol. Since TCP has IP based squeue
 * which benefits by polling, we separate TCP packets into
 * its own softring which can be polled by IP squeue. We need
 * to separate out UDP/SCTP to UDP softring since it can bypass
 * the DLS layer which has heavy performance advanatges and we
 * need a softring (OTH) for rest.
 *
 * ToDo: The 3 softrings for protocol are needed only till we can
 * get rid of DLS from datapath, make IPv4 and IPv6 paths
 * symmetric (deal with mac_header_info for v6 and polling for
 * IPv4 TCP - ip_accept_tcp is IPv4 specific although squeues
 * are generic), and bring SAP based classification to MAC layer
 *
 * H/W and S/W based fanout and multiple Rx rings per Link
 * -------------------------------------------------------
 *
 * In case, fanout is requested (or determined automatically based
 * on Link speed and processor speed), we try to assign multiple
 * Rx rings per Link with their respective SRS. In this case
 * the NIC should be capable of fanning out incoming packets between
 * the assigned Rx rings (H/W based fanout). All the SRS
 * individually switch their Rx ring between interrupt and polling
 * mode but share a common B/W control counter in case of Link
 * level B/W is specified.
 *
 * If S/W based fanout is specified in lieu of H/W based fanout,
 * the Link SRS creates the specified number of softrings for
 * each protocol (TCP, UDP, OTH). Incoming packets are fanned
 * out to the correct softring based on their protocol and
 * protocol specific hash function.
 *
 * Primary and non primary MAC clients
 * -----------------------------------
 *
 * The NICs, VNICs, Vlans, and Aggrs are typically termed as Links
 * and are a Layer 2 construct.
 *
 * Primary NIC:
 *	The Link that owns the primary MAC address and typically
 *	is used as the data NIC in non virtualized cases. As such
 *	H/W resources are preferntially given to primary NIC. As
 *	far as code is concerned, there is no difference in the
 *	primary NIC vs VNICs. They are all treated as Links.
 *	At the very first call to mac_unicast_add() we program the S/W
 *	classifier for the primary MAC address, get a soft ring set
 *	(and soft rings based on 'ip_soft_ring_cnt')
 *	and a Rx ring assigned for polling to get enabled.
 *	When IP get plumbed and negotiates polling, we can
 *	let squeue do the polling on TCP softring.
 *
 * VNICs:
 *	Same as any other Link. As long as the H/W resource assignments
 *	are equal, the data path and setup for all Links is same.
 *
 * Flows:
 *	Can be configured on Links. They have their own SRS and the
 *	S/W classifier is programmed appropriately based on the flow.
 *	The flows typically deal with layer 3 and above and
 *	creates a soft ring set specific to the flow. The receive
 *	side function is switched from mac_rx_srs_process to
 *	mac_rx_srs_subflow_process which first tries to assign the
 *	packet to appropriate flow SRS and failing which assigns it
 *	to link SRS. This allows us to avoid the layered approach
 *	which gets complex.
 *
 * By the time mac_datapath_setup() completes, we already have the
 * soft rings set, Rx rings, soft rings, etc figured out and both H/W
 * and S/W classifiers programmed. IP is not plumbed yet (and might
 * never be for Virtual Machines guest OS path). When IP is plumbed
 * (for both NIC and VNIC), we do a capability negotiation for polling
 * and upcall functions etc.
 *
 * Rx ring Assignement NOTES
 * -------------------------
 *
 * For NICs which have only 1 Rx ring (we treat  NICs with no Rx rings
 * as NIC with a single default ring), we assign the only ring to
 * primary Link as MAC_RX_HW_DEFAULT_RING. The primary Link SRS can do
 * polling on it as long as it is the only link in use and we compare
 * the MAC address for unicast packets before accepting an incoming
 * packet (there is no need for S/W classification in this case). We
 * disable polling on the only ring the moment 2nd link gets created
 * (the polling remains enabled even though there are broadcast and
 * multicast flows created).
 *
 * If the NIC has more than 1 Rx ring, we assign the default ring (the
 * 1st ring) to deal with broadcast, multicast and traffic for other
 * NICs which needs S/W classification. We assign the primary mac
 * addresses to another ring by specifiying a classification rule for
 * primary unicast MAC address to the selected ring. The primary Link
 * (and its SRS) can continue to poll the assigned Rx ring at all times
 * independantly.
 *
 * Right now we just assign MAC_RX_HW_DEFAULT_RING to note that it is
 * primary NIC and later we will check to see how many Rx rings we
 * have and can we get a non default Rx ring for the primary MAC.
 *
 * Note: In future, if no fanout is specified, we try to assign 2 Rx
 * rings for the primary Link with the primary MAC address + TCP going
 * to one ring and primary MAC address + UDP|SCTP going to other ring.
 * Any remaining traffic for primary MAC address can go to the default
 * Rx ring and get S/W classified. This way the respective SRSs don't
 * need to do proto fanout and don't need to have softrings at all and
 * can poll their respective Rx rings.
 *
 * As an optimization, when a new NIC or VNIC is created, we can get
 * only one Rx ring and make it a TCP specific Rx ring and use the
 * H/W default Rx ring for the rest (this Rx ring is never polled).
 */
int
mac_datapath_setup(mac_client_impl_t *mcip, flow_entry_t *flent,
    uint32_t link_type)
{
	mac_impl_t		*mip = mcip->mci_mip;
	mac_group_t		*group = NULL;
	mac_group_t		*default_group;
	int			err;
	uint8_t 		*mac_addr;
	mac_rx_group_reserve_type_t	rtype = MAC_RX_RESERVE_NONDEFAULT;
	mac_group_state_t	next_state;
	mac_client_impl_t	*group_only_mcip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	switch (link_type) {
	case SRST_FLOW:
		mac_srs_group_setup(mcip, flent, NULL, link_type);
		return (0);

	case SRST_LINK:
		mac_addr = flent->fe_flow_desc.fd_dst_mac;

		/* Check if we need to reserve the default group */
		if (flent->fe_type & FLOW_PRIMARY_MAC)
			rtype = MAC_RX_RESERVE_DEFAULT;

		if ((mcip->mci_state_flags & MCIS_NO_HWRINGS) == 0) {
			/*
			 * Check to see if we can get an exclusive group for
			 * this mac address or if there already exists a
			 * group that has this mac address (case of VLANs).
			 * If no groups are available, use the default group.
			 */
			group = mac_reserve_rx_group(mcip, mac_addr, rtype);
		}

		if (group == NULL) {
			if ((mcip->mci_state_flags & MCIS_REQ_HWRINGS) != 0)
				return (ENOSPC);
			group = &mip->mi_rx_groups[0];
		}

		/*
		 * Some NICs don't support any Rx rings, so there may not
		 * even be a default group.
		 */
		if (group != NULL) {
			flent->fe_rx_ring_group = group;
			/*
			 * Add the client to the group. This could cause
			 * either this group to move to the shared state or
			 * cause the default group to move to the shared state.
			 * The actions on this group are done here, while the
			 * actions on the default group are postponed to
			 * the end of this function.
			 */
			mac_rx_group_add_client(group, mcip);
			next_state = mac_rx_group_next_state(group,
			    &group_only_mcip);

			ASSERT((next_state == MAC_GROUP_STATE_RESERVED &&
			    mcip == group_only_mcip) ||
			    (next_state == MAC_GROUP_STATE_SHARED &&
			    group_only_mcip == NULL));

			mac_set_rx_group_state(group, next_state);
		}

		/*
		 * Setup the Rx and Tx SRSes. If we got a pristine group
		 * exclusively above, mac_srs_group_setup would simply create
		 * the required SRSes. If we ended up sharing a previously
		 * reserved group, mac_srs_group_setup would also dismantle the
		 * SRSes of the previously exclusive group
		 */
		mac_srs_group_setup(mcip, flent, group, link_type);

		/* Program the S/W Classifer */
		if ((err = mac_flow_add(mip->mi_flow_tab, flent)) != 0)
			goto setup_failed;

		/* Program the H/W Classifier */
		if ((err = mac_add_macaddr(mip, group, mac_addr,
		    (mcip->mci_state_flags & MCIS_UNICAST_HW) != 0)) != 0)
			goto setup_failed;
		mcip->mci_unicast = mac_find_macaddr(mip, mac_addr);
		ASSERT(mcip->mci_unicast != NULL);
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}

	/*
	 * All broadcast and multicast traffic is received only on the default
	 * group. If we have setup the datapath for a non-default group above
	 * then move the default group to shared state to allow distribution of
	 * incoming broadcast traffic to the other groups and dismantle the
	 * SRSes over the default group.
	 */
	if (group != NULL) {
		if (group != mip->mi_rx_groups) {
			default_group = mip->mi_rx_groups;
			if (default_group->mrg_state ==
			    MAC_GROUP_STATE_RESERVED) {
				group_only_mcip = MAC_RX_GROUP_ONLY_CLIENT(
				    default_group);
				ASSERT(group_only_mcip != NULL &&
				    mip->mi_nactiveclients > 1);

				mac_set_rx_group_state(default_group,
				    MAC_GROUP_STATE_SHARED);
				mac_srs_group_setup(group_only_mcip,
				    group_only_mcip->mci_flent,
				    default_group, SRST_LINK);
			}
			ASSERT(default_group->mrg_state ==
			    MAC_GROUP_STATE_SHARED);
		}
		/*
		 * If we get an exclusive group for a VLAN MAC client we
		 * need to take the s/w path to make the additional check for
		 * the vid. Disable polling and set it to s/w classification.
		 */
		if (group->mrg_state == MAC_GROUP_STATE_RESERVED &&
		    i_mac_flow_vid(mcip->mci_flent) != VLAN_ID_NONE) {
			mac_rx_switch_grp_to_sw(group);
		}
	}
	return (0);

setup_failed:
	mac_datapath_teardown(mcip, flent, link_type);
	return (err);
}

void
mac_datapath_teardown(mac_client_impl_t *mcip, flow_entry_t *flent,
    uint32_t link_type)
{
	mac_impl_t		*mip = mcip->mci_mip;
	mac_group_t		*group = NULL;
	mac_client_impl_t	*grp_only_mcip;
	flow_entry_t		*group_only_flent;
	mac_group_t		*default_group;
	boolean_t		check_default_group = B_FALSE;
	mac_group_state_t	next_state;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	switch (link_type) {
	case SRST_FLOW:
		mac_srs_group_teardown(mcip, flent, SRST_FLOW);
		return;

	case SRST_LINK:
		/* Stop sending packets */
		mac_tx_client_block(mcip);

		/* Stop the packets coming from the H/W */
		if (mcip->mci_unicast != NULL) {
			int err;
			err = mac_remove_macaddr(mcip->mci_unicast);
			if (err != 0) {
				cmn_err(CE_WARN, "%s: failed to remove a MAC"
				    " address because of error 0x%x",
				    mip->mi_name, err);
			}
			mcip->mci_unicast = NULL;
		}

		/* Stop the packets coming from the S/W classifier */
		mac_flow_remove(mip->mi_flow_tab, flent, B_FALSE);
		mac_flow_wait(flent, FLOW_DRIVER_UPCALL);

		/* Now quiesce and destroy all SRS and soft rings */
		mac_srs_group_teardown(mcip, flent, SRST_LINK);
		ASSERT((mcip->mci_flent == flent) &&
		    (flent->fe_next == NULL));

		/*
		 * Release our hold on the group as well. We need
		 * to check if the shared group has only one client
		 * left who can use it exclusively. Also, if we
		 * were the last client, release the group.
		 */
		group = flent->fe_rx_ring_group;
		if (group != NULL) {
			mac_rx_group_remove_client(group, mcip);
			next_state = mac_rx_group_next_state(group,
			    &grp_only_mcip);
			if (next_state == MAC_GROUP_STATE_RESERVED) {
				/*
				 * Only one client left on this RX group.
				 */
				ASSERT(grp_only_mcip != NULL);
				mac_set_rx_group_state(group,
				    MAC_GROUP_STATE_RESERVED);
				group_only_flent = grp_only_mcip->mci_flent;

				/*
				 * The only remaining client has exclusive
				 * access on the group. Allow it to
				 * dynamically poll the H/W rings etc.
				 */
				mac_srs_group_setup(grp_only_mcip,
				    group_only_flent, group, SRST_LINK);
				mac_rx_group_unmark(group, MR_INCIPIENT);
			} else if (next_state == MAC_GROUP_STATE_REGISTERED) {
				/*
				 * This is a non-default group being freed up.
				 * We need to reevaluate the default group
				 * to see if the primary client can get
				 * exclusive access to the default group.
				 */
				ASSERT(group != mip->mi_rx_groups);
				mac_release_rx_group(mcip, group);
				mac_set_rx_group_state(group,
				    MAC_GROUP_STATE_REGISTERED);
				check_default_group = B_TRUE;
			} else {
				ASSERT(next_state == MAC_GROUP_STATE_SHARED);
				mac_set_rx_group_state(group,
				    MAC_GROUP_STATE_SHARED);
				mac_rx_group_unmark(group, MR_CONDEMNED);
			}
			flent->fe_rx_ring_group = NULL;
		}
		break;
	default:
		ASSERT(B_FALSE);
		break;
	}

	/*
	 * The mac client using the default group gets exclusive access to the
	 * default group if and only if it is the sole client on the entire
	 * mip. If so set the group state to reserved, and set up the SRSes
	 * over the default group.
	 */
	if (check_default_group) {
		default_group = mip->mi_rx_groups;
		ASSERT(default_group->mrg_state == MAC_GROUP_STATE_SHARED);
		next_state = mac_rx_group_next_state(default_group,
		    &grp_only_mcip);
		if (next_state == MAC_GROUP_STATE_RESERVED) {
			ASSERT(grp_only_mcip != NULL &&
			    mip->mi_nactiveclients == 1);
			mac_set_rx_group_state(default_group,
			    MAC_GROUP_STATE_RESERVED);
			mac_srs_group_setup(grp_only_mcip,
			    grp_only_mcip->mci_flent,
			    default_group, SRST_LINK);
		}
	}
}

/* DATAPATH TEAR DOWN ROUTINES (SRS and FANOUT teardown) */

static void
mac_srs_fanout_list_free(mac_soft_ring_set_t *mac_srs)
{
	ASSERT(mac_srs->srs_tcp_soft_rings != NULL);
	kmem_free(mac_srs->srs_tcp_soft_rings,
	    sizeof (mac_soft_ring_t *) * MAX_SR_FANOUT);
	mac_srs->srs_tcp_soft_rings = NULL;
	ASSERT(mac_srs->srs_udp_soft_rings != NULL);
	kmem_free(mac_srs->srs_udp_soft_rings,
	    sizeof (mac_soft_ring_t *) * MAX_SR_FANOUT);
	mac_srs->srs_udp_soft_rings = NULL;
	ASSERT(mac_srs->srs_oth_soft_rings != NULL);
	kmem_free(mac_srs->srs_oth_soft_rings,
	    sizeof (mac_soft_ring_t *) * MAX_SR_FANOUT);
	mac_srs->srs_oth_soft_rings = NULL;
}

/*
 * An RX SRS is attached to at most one mac_ring.
 * A TX SRS  has no  rings.
 */
static void
mac_srs_ring_free(mac_soft_ring_set_t *mac_srs)
{
	mac_client_impl_t	*mcip;
	mac_ring_t		*ring;
	flow_entry_t		*flent;

	ring = mac_srs->srs_ring;
	if (mac_srs->srs_type & SRST_TX) {
		ASSERT(ring == NULL);
		return;
	}

	if (ring == NULL)
		return;

	/*
	 * Broadcast flows don't have a client impl association, but they
	 * use only soft rings.
	 */
	flent = mac_srs->srs_flent;
	mcip = flent->fe_mcip;
	ASSERT(mcip != NULL);

	ring->mr_classify_type = MAC_NO_CLASSIFIER;
	ring->mr_srs = NULL;
}

/*
 * Physical unlink and free of the data structures happen below. This is
 * driven from mac_flow_destroy(), on the last refrele of a flow.
 *
 * Assumes Rx srs is 1-1 mapped with an ring.
 */
void
mac_srs_free(mac_soft_ring_set_t *mac_srs)
{
	ASSERT(mac_srs->srs_mcip == NULL ||
	    MAC_PERIM_HELD((mac_handle_t)mac_srs->srs_mcip->mci_mip));
	ASSERT((mac_srs->srs_state & (SRS_CONDEMNED | SRS_CONDEMNED_DONE |
	    SRS_PROC | SRS_PROC_FAST)) == (SRS_CONDEMNED | SRS_CONDEMNED_DONE));

	mac_pkt_drop(NULL, NULL, mac_srs->srs_first, B_FALSE);
	mac_srs_ring_free(mac_srs);
	mac_srs_soft_rings_free(mac_srs, B_TRUE);
	mac_srs_fanout_list_free(mac_srs);

	mac_srs->srs_bw = NULL;
	kmem_cache_free(mac_srs_cache, mac_srs);
}

static void
mac_srs_soft_rings_quiesce(mac_soft_ring_set_t *mac_srs, uint_t s_ring_flag)
{
	mac_soft_ring_t	*softring;

	ASSERT(MUTEX_HELD(&mac_srs->srs_lock));

	mac_srs_soft_rings_signal(mac_srs, s_ring_flag);
	if (s_ring_flag == S_RING_CONDEMNED) {
		while (mac_srs->srs_soft_ring_condemned_count !=
		    mac_srs->srs_soft_ring_count)
			cv_wait(&mac_srs->srs_async, &mac_srs->srs_lock);
	} else {
		while (mac_srs->srs_soft_ring_quiesced_count !=
		    mac_srs->srs_soft_ring_count)
			cv_wait(&mac_srs->srs_async, &mac_srs->srs_lock);
	}
	mutex_exit(&mac_srs->srs_lock);

	for (softring = mac_srs->srs_soft_ring_head; softring != NULL;
	    softring = softring->s_ring_next)
		(void) untimeout(softring->s_ring_tid);

	(void) untimeout(mac_srs->srs_tid);

	mutex_enter(&mac_srs->srs_lock);
}

/*
 * The block comment above mac_rx_classify_flow_state_change explains the
 * background. At this point upcalls from the driver (both hardware classified
 * and software classified) have been cut off. We now need to quiesce the
 * SRS worker, poll, and softring threads. The SRS worker thread serves as
 * the master controller. The steps involved are described below in the function
 */
void
mac_srs_worker_quiesce(mac_soft_ring_set_t *mac_srs)
{
	uint_t			s_ring_flag;
	uint_t			srs_poll_wait_flag;

	ASSERT(MUTEX_HELD(&mac_srs->srs_lock));
	ASSERT(mac_srs->srs_state & (SRS_CONDEMNED | SRS_QUIESCE));

	if (mac_srs->srs_state & SRS_CONDEMNED) {
		s_ring_flag = S_RING_CONDEMNED;
		srs_poll_wait_flag = SRS_POLL_THR_EXITED;
	} else {
		s_ring_flag = S_RING_QUIESCE;
		srs_poll_wait_flag = SRS_POLL_THR_QUIESCED;
	}

	/*
	 * In the case of Rx SRS wait till the poll thread is done.
	 */
	if ((mac_srs->srs_type & SRST_TX) == 0 &&
	    mac_srs->srs_poll_thr != NULL) {
		while (!(mac_srs->srs_state & srs_poll_wait_flag))
			cv_wait(&mac_srs->srs_async, &mac_srs->srs_lock);

		/*
		 * Turn off polling as part of the quiesce operation.
		 */
		MAC_SRS_POLLING_OFF(mac_srs);
		mac_srs->srs_state &= ~(SRS_POLLING | SRS_GET_PKTS);
	}

	/*
	 * Then signal the soft ring worker threads to quiesce or quit
	 * as needed and then wait till that happens.
	 */
	mac_srs_soft_rings_quiesce(mac_srs, s_ring_flag);

	if (mac_srs->srs_state & SRS_CONDEMNED)
		mac_srs->srs_state |= (SRS_QUIESCE_DONE | SRS_CONDEMNED_DONE);
	else
		mac_srs->srs_state |= SRS_QUIESCE_DONE;
	cv_signal(&mac_srs->srs_quiesce_done_cv);
}

/*
 * Signal an SRS to start a temporary quiesce, or permanent removal, or restart
 * a quiesced SRS by setting the appropriate flags and signaling the SRS worker
 * or poll thread. This function is internal to the quiescing logic and is
 * called internally from the SRS quiesce or flow quiesce or client quiesce
 * higher level functions.
 */
void
mac_srs_signal(mac_soft_ring_set_t *mac_srs, uint_t srs_flag)
{
	mac_ring_t	*ring;

	ring = mac_srs->srs_ring;
	ASSERT(ring == NULL || ring->mr_refcnt == 0);

	if (srs_flag == SRS_CONDEMNED) {
		/*
		 * The SRS is going away. We need to unbind the SRS and SR
		 * threads before removing from the global SRS list. Otherwise
		 * there is a small window where the cpu reconfig callbacks
		 * may miss the SRS in the list walk and DR could fail since
		 * there are still bound threads.
		 */
		mac_srs_threads_unbind(mac_srs);
		mac_srs_remove_glist(mac_srs);
	}
	/*
	 * Wakeup the SRS worker and poll threads.
	 */
	mutex_enter(&mac_srs->srs_lock);
	mac_srs->srs_state |= srs_flag;
	cv_signal(&mac_srs->srs_async);
	cv_signal(&mac_srs->srs_cv);
	mutex_exit(&mac_srs->srs_lock);
}

/*
 * In the Rx side, the quiescing is done bottom up. After the Rx upcalls
 * from the driver are done, then the Rx SRS is quiesced and only then can
 * we signal the soft rings. Thus this function can't be called arbitrarily
 * without satisfying the prerequisites. On the Tx side, the threads from
 * top need to quiesced, then the Tx SRS and only then can we signal the
 * Tx soft rings.
 */
static void
mac_srs_soft_rings_signal(mac_soft_ring_set_t *mac_srs, uint_t sr_flag)
{
	mac_soft_ring_t		*softring;

	for (softring = mac_srs->srs_soft_ring_head; softring != NULL;
	    softring = softring->s_ring_next)
		mac_soft_ring_signal(softring, sr_flag);
}

/*
 * The block comment above mac_rx_classify_flow_state_change explains the
 * background. At this point the SRS is quiesced and we need to restart the
 * SRS worker, poll, and softring threads. The SRS worker thread serves as
 * the master controller. The steps involved are described below in the function
 */
void
mac_srs_worker_restart(mac_soft_ring_set_t *mac_srs)
{
	boolean_t	iam_rx_srs;
	mac_soft_ring_t	*softring;

	ASSERT(MUTEX_HELD(&mac_srs->srs_lock));
	if ((mac_srs->srs_type & SRST_TX) != 0) {
		iam_rx_srs = B_FALSE;
		ASSERT((mac_srs->srs_state &
		    (SRS_POLL_THR_QUIESCED | SRS_QUIESCE_DONE | SRS_QUIESCE)) ==
		    (SRS_QUIESCE_DONE | SRS_QUIESCE));
	} else {
		iam_rx_srs = B_TRUE;
		ASSERT((mac_srs->srs_state &
		    (SRS_QUIESCE_DONE | SRS_QUIESCE)) ==
		    (SRS_QUIESCE_DONE | SRS_QUIESCE));
		if (mac_srs->srs_poll_thr != NULL) {
			ASSERT((mac_srs->srs_state & SRS_POLL_THR_QUIESCED) ==
			    SRS_POLL_THR_QUIESCED);
		}
	}

	/*
	 * Signal any quiesced soft ring workers to restart and wait for the
	 * soft ring down count to come down to zero.
	 */
	if (mac_srs->srs_soft_ring_quiesced_count != 0) {
		for (softring = mac_srs->srs_soft_ring_head; softring != NULL;
		    softring = softring->s_ring_next) {
			if (!(softring->s_ring_state & S_RING_QUIESCE))
				continue;
			mac_soft_ring_signal(softring, S_RING_RESTART);
		}
		while (mac_srs->srs_soft_ring_quiesced_count != 0)
			cv_wait(&mac_srs->srs_async, &mac_srs->srs_lock);
	}

	mac_srs->srs_state &= ~(SRS_QUIESCE_DONE | SRS_QUIESCE | SRS_RESTART);
	if (iam_rx_srs && mac_srs->srs_poll_thr != NULL) {
		/*
		 * Signal the poll thread and ask it to restart. Wait till it
		 * actually restarts and the SRS_POLL_THR_QUIESCED flag gets
		 * cleared.
		 */
		mac_srs->srs_state |= SRS_POLL_THR_RESTART;
		cv_signal(&mac_srs->srs_cv);
		while (mac_srs->srs_state & SRS_POLL_THR_QUIESCED)
			cv_wait(&mac_srs->srs_async, &mac_srs->srs_lock);
		ASSERT(!(mac_srs->srs_state & SRS_POLL_THR_RESTART));
	}
	/* Wake up any waiter waiting for the restart to complete */
	mac_srs->srs_state |= SRS_RESTART_DONE;
	cv_signal(&mac_srs->srs_quiesce_done_cv);
}

static void
mac_srs_worker_unbind(mac_soft_ring_set_t *mac_srs)
{
	mutex_enter(&mac_srs->srs_lock);
	if (!(mac_srs->srs_state & SRS_WORKER_BOUND)) {
		ASSERT(mac_srs->srs_worker_cpuid == -1);
		mutex_exit(&mac_srs->srs_lock);
		return;
	}

	mac_srs->srs_worker_cpuid = -1;
	mac_srs->srs_state &= ~SRS_WORKER_BOUND;
	thread_affinity_clear(mac_srs->srs_worker);
	mutex_exit(&mac_srs->srs_lock);
}

static void
mac_srs_poll_unbind(mac_soft_ring_set_t *mac_srs)
{
	mutex_enter(&mac_srs->srs_lock);
	if (mac_srs->srs_poll_thr == NULL ||
	    (mac_srs->srs_state & SRS_POLL_BOUND) == 0) {
		ASSERT(mac_srs->srs_poll_cpuid == -1);
		mutex_exit(&mac_srs->srs_lock);
		return;
	}

	mac_srs->srs_poll_cpuid = -1;
	mac_srs->srs_state &= ~SRS_POLL_BOUND;
	thread_affinity_clear(mac_srs->srs_poll_thr);
	mutex_exit(&mac_srs->srs_lock);
}

static void
mac_srs_threads_unbind(mac_soft_ring_set_t *mac_srs)
{
	mac_soft_ring_t	*soft_ring;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mac_srs->srs_mcip->mci_mip));

	mutex_enter(&cpu_lock);
	mac_srs_worker_unbind(mac_srs);
	if (!(mac_srs->srs_type & SRST_TX))
		mac_srs_poll_unbind(mac_srs);

	for (soft_ring = mac_srs->srs_soft_ring_head; soft_ring != NULL;
	    soft_ring = soft_ring->s_ring_next) {
		mac_soft_ring_unbind(soft_ring);
	}
	mutex_exit(&cpu_lock);
}

/*
 * When a CPU is going away, unbind all MAC threads which are bound
 * to that CPU. The affinity of the thread to the CPU is saved to allow
 * the thread to be rebound to the CPU if it comes back online.
 */
static void
mac_walk_srs_and_unbind(int cpuid)
{
	mac_soft_ring_set_t *mac_srs;
	mac_soft_ring_t *soft_ring;

	rw_enter(&mac_srs_g_lock, RW_READER);

	if ((mac_srs = mac_srs_g_list) == NULL)
		goto done;

	for (; mac_srs != NULL; mac_srs = mac_srs->srs_next) {
		if (mac_srs->srs_worker_cpuid == cpuid) {
			mac_srs->srs_worker_cpuid_save = cpuid;
			mac_srs_worker_unbind(mac_srs);
		}

		if (!(mac_srs->srs_type & SRST_TX)) {
			if (mac_srs->srs_poll_cpuid == cpuid) {
				mac_srs->srs_poll_cpuid_save = cpuid;
				mac_srs_poll_unbind(mac_srs);
			}
		}

		/* Next tackle the soft rings associated with the srs */
		mutex_enter(&mac_srs->srs_lock);
		for (soft_ring = mac_srs->srs_soft_ring_head; soft_ring != NULL;
		    soft_ring = soft_ring->s_ring_next) {
			if (soft_ring->s_ring_cpuid == cpuid) {
				soft_ring->s_ring_cpuid_save = cpuid;
				mac_soft_ring_unbind(soft_ring);
			}
		}
		mutex_exit(&mac_srs->srs_lock);
	}
done:
	rw_exit(&mac_srs_g_lock);
}

/* TX SETUP and TEARDOWN ROUTINES */

/*
 * XXXHIO need to make sure the two mac_tx_srs_{add,del}_ring()
 * handle the case where the number of rings is one. I.e. there is
 * a ring pointed to by mac_srs->srs_tx_arg2.
 */
void
mac_tx_srs_add_ring(mac_soft_ring_set_t *mac_srs, mac_ring_t *tx_ring)
{
	mac_client_impl_t *mcip = mac_srs->srs_mcip;
	mac_soft_ring_t *soft_ring;
	int count = mac_srs->srs_oth_ring_count;

	ASSERT(mac_srs->srs_state & SRS_QUIESCE);
	soft_ring = mac_soft_ring_create(count, 0, NULL,
	    (ST_RING_OTH | ST_RING_TX), maxclsyspri, mcip, mac_srs, -1,
	    NULL, mcip, (mac_resource_handle_t)tx_ring);
	mac_srs->srs_oth_ring_count++;
	/*
	 * put this soft ring in quiesce mode too so when we restart
	 * all soft rings in the srs are in the same state.
	 */
	mac_soft_ring_signal(soft_ring, S_RING_QUIESCE);
}

static void
mac_soft_ring_remove(mac_soft_ring_set_t *mac_srs, mac_soft_ring_t *softring)
{
	int sringcnt;

	mutex_enter(&mac_srs->srs_lock);
	sringcnt = mac_srs->srs_soft_ring_count;
	ASSERT(sringcnt > 0);
	mac_soft_ring_signal(softring, S_RING_CONDEMNED);

	ASSERT(mac_srs->srs_soft_ring_condemned_count == 0);
	while (mac_srs->srs_soft_ring_condemned_count != 1)
		cv_wait(&mac_srs->srs_async, &mac_srs->srs_lock);

	if (softring == mac_srs->srs_soft_ring_head) {
		mac_srs->srs_soft_ring_head = softring->s_ring_next;
		if (mac_srs->srs_soft_ring_head != NULL) {
			mac_srs->srs_soft_ring_head->s_ring_prev = NULL;
		} else {
			mac_srs->srs_soft_ring_tail = NULL;
		}
	} else {
		softring->s_ring_prev->s_ring_next =
		    softring->s_ring_next;
		if (softring->s_ring_next != NULL) {
			softring->s_ring_next->s_ring_prev =
			    softring->s_ring_prev;
		} else {
			mac_srs->srs_soft_ring_tail =
			    softring->s_ring_prev;
		}
	}
	mac_srs->srs_soft_ring_count--;

	mac_srs->srs_soft_ring_condemned_count--;
	mutex_exit(&mac_srs->srs_lock);

	mac_soft_ring_free(softring, B_FALSE);
}

void
mac_tx_srs_del_ring(mac_soft_ring_set_t *mac_srs, mac_ring_t *tx_ring)
{
	int i;
	mac_soft_ring_t *soft_ring, *remove_sring;

	mutex_enter(&mac_srs->srs_lock);
	for (i = 0; i < mac_srs->srs_oth_ring_count; i++) {
		soft_ring =  mac_srs->srs_oth_soft_rings[i];
		if (soft_ring->s_ring_tx_arg2 == tx_ring)
			break;
	}
	mutex_exit(&mac_srs->srs_lock);
	ASSERT(i < mac_srs->srs_oth_ring_count);
	remove_sring = soft_ring;
	mac_soft_ring_remove(mac_srs, remove_sring);
	mac_srs_update_fanout_list(mac_srs);
}

/*
 * mac_tx_srs_setup():
 *
 * Used to setup Tx rings. If no free Tx ring is available, then default
 * Tx ring is used.
 */
void
mac_tx_srs_setup(mac_client_impl_t *mcip, flow_entry_t *flent,
    uint32_t srs_type)
{
	mac_impl_t *mip = mcip->mci_mip;
	mac_soft_ring_set_t *tx_srs;
	int i, tx_ring_count = 0, tx_rings_reserved;
	mac_ring_handle_t *tx_ring = NULL;
	uint32_t soft_ring_type;
	mac_group_t *grp = NULL;
	mac_ring_t *ring;
	mac_srs_tx_t *tx;
	boolean_t serialize = B_FALSE;

	tx_srs = flent->fe_tx_srs;
	tx = &tx_srs->srs_tx;

	if (tx->st_group != NULL) {
		grp = tx->st_group;
		tx_ring_count = grp->mrg_cur_count;
	} else {
		tx_ring_count = mac_tx_ring_count;
	}

	if (tx_ring_count != 0) {
		tx_ring = kmem_zalloc(sizeof (mac_ring_handle_t) *
		    tx_ring_count, KM_SLEEP);
	}

	/*
	 * Just use the default ring for now. We need to use
	 * the underlying link's ring set instead of the underlying
	 * NIC's.
	 */
	if (srs_type == SRST_FLOW ||
	    (mcip->mci_state_flags & MCIS_NO_HWRINGS) != 0)
		goto use_default_ring;

	if (mcip->mci_share != NULL)
		ring = grp->mrg_rings;
	/*
	 * An attempt is made to reserve 'tx_ring_count' number
	 * of Tx rings. If tx_ring_count is 0, default Tx ring
	 * is used. If it is 1, an attempt is made to reserve one
	 * Tx ring. In both the cases, the ring information is
	 * stored in Tx SRS. If multiple Tx rings are specified,
	 * then each Tx ring will have a Tx-side soft ring. All
	 * these soft rings will be hang off Tx SRS.
	 */
	for (i = 0, tx_rings_reserved = 0;
	    i < tx_ring_count; i++, tx_rings_reserved++) {
		if (mcip->mci_share != NULL) {
			/*
			 * The ring was already chosen and associated
			 * with the TX group. Save it in the new
			 * array to keep as much of the code below common
			 * between the share and non-share cases.
			 */
			ASSERT(ring != NULL);
			tx_ring[i] = (mac_ring_handle_t)ring;
			ring = ring->mr_next;
		} else {
			tx_ring[i] =
			    (mac_ring_handle_t)mac_reserve_tx_ring(mip, NULL);
			if (tx_ring[i] == NULL)
				break;
		}
	}
	if (mac_tx_serialize || (mip->mi_v12n_level & MAC_VIRT_SERIALIZE))
		serialize = B_TRUE;
	/*
	 * Did we get the requested number of tx rings?
	 * There are 3 actions we can take depending upon the number
	 * of tx_rings we got.
	 * 1) If we got none, then hook up the tx_srs with the
	 * default ring.
	 * 2) If we got one, then get the tx_ring from the soft ring,
	 * save it in SRS and free up the soft ring.
	 * 3) If we got more than 1, then do the tx fanout among the
	 * rings we obtained.
	 */
	switch (tx_rings_reserved) {
	case 1:
		/*
		 * No need to allocate Tx soft rings. Tx-side soft
		 * rings are for Tx fanout case. Just use Tx SRS.
		 */
		/* FALLTHRU */

	case 0:
use_default_ring:
		if (tx_rings_reserved == 0)
			tx->st_arg2 = (void *)mip->mi_default_tx_ring;
		else
			tx->st_arg2 = (void *)tx_ring[0];
		/* For ring_count of 0 or 1, set the tx_mode and return */
		if (tx_srs->srs_type & SRST_BW_CONTROL)
			tx->st_mode = SRS_TX_BW;
		else if (serialize)
			tx->st_mode = SRS_TX_SERIALIZE;
		else
			tx->st_mode = SRS_TX_DEFAULT;
		break;

	default:
		/*
		 * We got multiple Tx rings for Tx fanout.
		 *
		 * cpuid of -1 is passed. This creates an unbound
		 * worker thread. Instead the code should get CPU
		 * binding information and pass that to
		 * mac_soft_ring_create(). This needs to be done
		 * in conjunction with Rx-side soft ring
		 * bindings.
		 */
		soft_ring_type = ST_RING_OTH | ST_RING_TX;
		if (tx_srs->srs_type & SRST_BW_CONTROL) {
			tx->st_mode = SRS_TX_BW_FANOUT;
		} else {
			tx->st_mode = SRS_TX_FANOUT;
			if (serialize)
				soft_ring_type |= ST_RING_WORKER_ONLY;
		}
		for (i = 0; i < tx_rings_reserved; i++) {
			(void) mac_soft_ring_create(i, 0, NULL, soft_ring_type,
			    maxclsyspri, mcip, tx_srs, -1, NULL, mcip,
			    (mac_resource_handle_t)tx_ring[i]);
		}
		mac_srs_update_fanout_list(tx_srs);
	}
	tx->st_func = mac_tx_get_func(tx->st_mode);

	DTRACE_PROBE3(tx__srs___setup__return, mac_soft_ring_set_t *, tx_srs,
	    int, tx->st_mode, int, tx_srs->srs_oth_ring_count);

	if (tx_ring_count != 0) {
		kmem_free(tx_ring,
		    sizeof (mac_ring_handle_t) * tx_ring_count);
	}
}

/*
 * Update the fanout of a client if its recorded link speed doesn't match
 * its current link speed.
 */
void
mac_fanout_recompute_client(mac_client_impl_t *mcip)
{
	uint64_t link_speed;
	mac_resource_props_t *mcip_mrp;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	link_speed = mac_client_stat_get(mcip->mci_flent->fe_mcip,
	    MAC_STAT_IFSPEED);

	if ((link_speed != 0) &&
	    (link_speed != mcip->mci_flent->fe_nic_speed)) {
		mcip_mrp = MCIP_RESOURCE_PROPS(mcip);
		mac_fanout_setup(mcip, mcip->mci_flent,
		    mcip_mrp, mac_rx_deliver, mcip, NULL);
	}
}

/*
 * Walk through the list of mac clients for the MAC.
 * For each active mac client, recompute the number of soft rings
 * associated with every client, only if current speed is different
 * from the speed that was previously used for soft ring computation.
 * If the cable is disconnected whlie the NIC is started, we would get
 * notification with speed set to 0. We do not recompute in that case.
 */
void
mac_fanout_recompute(mac_impl_t *mip)
{
	mac_client_impl_t	*mcip;


	i_mac_perim_enter(mip);
	ASSERT(!(mip->mi_state_flags & MIS_IS_VNIC));

	if (mip->mi_linkstate != LINK_STATE_UP) {
		i_mac_perim_exit(mip);
		return;
	}

	for (mcip = mip->mi_clients_list; mcip != NULL;
	    mcip = mcip->mci_client_next) {
		if ((mcip->mci_state_flags & MCIS_SHARE_BOUND) != 0 ||
		    !MCIP_DATAPATH_SETUP(mcip))
			continue;
		mac_fanout_recompute_client(mcip);
	}
	i_mac_perim_exit(mip);
}
