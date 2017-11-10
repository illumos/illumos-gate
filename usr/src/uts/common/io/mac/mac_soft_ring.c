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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2017 Joyent, Inc.
 */

/*
 * General Soft rings - Simulating Rx rings in S/W.
 *
 * Soft ring is a data abstraction containing a queue and a worker
 * thread and represents a hardware Rx ring in software. Each soft
 * ring set can have a collection of soft rings for separating
 * L3/L4 specific traffic (IPv4 from IPv6 or TCP from UDP) or for
 * allowing a higher degree of parallelism by sending traffic to
 * one of the soft rings for a SRS (using a hash on src IP or port).
 * Each soft ring worker thread can be bound to a different CPU
 * allowing the processing for each soft ring to happen in parallel
 * and independent from each other.
 *
 * Protocol soft rings:
 *
 * Each SRS has at an minimum 3 softrings. One each for IPv4 TCP,
 * IPv4 UDP and rest (OTH - for IPv6 and everything else). The
 * SRS does dynamic polling and enforces link level bandwidth but
 * it does so for all traffic (IPv4 and IPv6 and all protocols) on
 * that link. However, each protocol layer wants a different
 * behaviour. For instance IPv4 TCP has per CPU squeues which
 * enforce their own polling and flow control so IPv4 TCP traffic
 * needs to go to a separate soft ring which can be polled by the
 * TCP squeue. It also allows TCP squeue to push back flow control
 * all the way to NIC hardware (if it puts its corresponding soft
 * ring in the poll mode and soft ring queue builds up, the
 * shared srs_poll_pkt_cnt goes up and SRS automatically stops
 * more packets from entering the system).
 *
 * Similarly, the UDP benefits from a DLS bypass and packet chaining
 * so sending it to a separate soft ring is desired. All the rest of
 * the traffic (including IPv6 is sent to OTH softring). The IPv6
 * traffic current goes through OTH softring and via DLS because
 * it need more processing to be done. Irrespective of the sap
 * (IPv4 or IPv6) or the transport, the dynamic polling, B/W enforcement,
 * cpu assignment, fanout, etc apply to all traffic since they
 * are implement by the SRS which is agnostic to sap or transport.
 *
 * Fanout soft rings:
 *
 * On a multithreaded system, we can assign more CPU and multi thread
 * the stack by creating a soft ring per CPU and spreading traffic
 * based on a hash computed on src IP etc. Since we still need to
 * keep the protocol separation, we create a set of 3 soft ring per
 * CPU (specified by cpu list or degree of fanout).
 *
 * NOTE: See the block level comment on top of mac_sched.c
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
#include <sys/mac_soft_ring.h>
#include <sys/mac_flow_impl.h>
#include <sys/mac_stat.h>

static void mac_rx_soft_ring_drain(mac_soft_ring_t *);
static void mac_soft_ring_fire(void *);
static void mac_soft_ring_worker(mac_soft_ring_t *);
static void mac_tx_soft_ring_drain(mac_soft_ring_t *);

uint32_t mac_tx_soft_ring_max_q_cnt = 100000;
uint32_t mac_tx_soft_ring_hiwat = 1000;

extern kmem_cache_t *mac_soft_ring_cache;

#define	ADD_SOFTRING_TO_SET(mac_srs, softring) {			\
	if (mac_srs->srs_soft_ring_head == NULL) {			\
		mac_srs->srs_soft_ring_head = softring;			\
		mac_srs->srs_soft_ring_tail = softring;			\
	} else {							\
		/* ADD to the list */					\
		softring->s_ring_prev =					\
			mac_srs->srs_soft_ring_tail;			\
		mac_srs->srs_soft_ring_tail->s_ring_next = softring;	\
		mac_srs->srs_soft_ring_tail = softring;			\
	}								\
	mac_srs->srs_soft_ring_count++;					\
}

/*
 * mac_soft_ring_worker_wakeup
 *
 * Wake up the soft ring worker thread to process the queue as long
 * as no one else is processing it and upper layer (client) is still
 * ready to receive packets.
 */
void
mac_soft_ring_worker_wakeup(mac_soft_ring_t *ringp)
{
	ASSERT(MUTEX_HELD(&ringp->s_ring_lock));
	if (!(ringp->s_ring_state & S_RING_PROC) &&
	    !(ringp->s_ring_state & S_RING_BLANK) &&
	    (ringp->s_ring_tid == NULL)) {
		if (ringp->s_ring_wait != 0) {
			ringp->s_ring_tid =
			    timeout(mac_soft_ring_fire, ringp,
			    ringp->s_ring_wait);
		} else {
			/* Schedule the worker thread. */
			cv_signal(&ringp->s_ring_async);
		}
	}
}

/*
 * mac_soft_ring_create
 *
 * Create a soft ring, do the necessary setup and bind the worker
 * thread to the assigned CPU.
 */
mac_soft_ring_t *
mac_soft_ring_create(int id, clock_t wait, uint16_t type,
    pri_t pri, mac_client_impl_t *mcip, mac_soft_ring_set_t *mac_srs,
    processorid_t cpuid, mac_direct_rx_t rx_func, void *x_arg1,
    mac_resource_handle_t x_arg2)
{
	mac_soft_ring_t 	*ringp;
	char 			name[S_RING_NAMELEN];

	bzero(name, 64);
	ringp = kmem_cache_alloc(mac_soft_ring_cache, KM_SLEEP);

	if (type & ST_RING_TCP) {
		(void) snprintf(name, sizeof (name),
		    "mac_tcp_soft_ring_%d_%p", id, (void *)mac_srs);
	} else if (type & ST_RING_UDP) {
		(void) snprintf(name, sizeof (name),
		    "mac_udp_soft_ring_%d_%p", id, (void *)mac_srs);
	} else if (type & ST_RING_OTH) {
		(void) snprintf(name, sizeof (name),
		    "mac_oth_soft_ring_%d_%p", id, (void *)mac_srs);
	} else {
		ASSERT(type & ST_RING_TX);
		(void) snprintf(name, sizeof (name),
		    "mac_tx_soft_ring_%d_%p", id, (void *)mac_srs);
	}

	bzero(ringp, sizeof (mac_soft_ring_t));
	(void) strncpy(ringp->s_ring_name, name, S_RING_NAMELEN + 1);
	ringp->s_ring_name[S_RING_NAMELEN] = '\0';
	mutex_init(&ringp->s_ring_lock, NULL, MUTEX_DEFAULT, NULL);
	ringp->s_ring_notify_cb_info.mcbi_lockp = &ringp->s_ring_lock;

	ringp->s_ring_type = type;
	ringp->s_ring_wait = MSEC_TO_TICK(wait);
	ringp->s_ring_mcip = mcip;
	ringp->s_ring_set = mac_srs;

	/*
	 * Protect against access from DR callbacks (mac_walk_srs_bind/unbind)
	 * which can't grab the mac perimeter
	 */
	mutex_enter(&mac_srs->srs_lock);
	ADD_SOFTRING_TO_SET(mac_srs, ringp);
	mutex_exit(&mac_srs->srs_lock);

	/*
	 * set the bind CPU to -1 to indicate
	 * no thread affinity set
	 */
	ringp->s_ring_cpuid = ringp->s_ring_cpuid_save = -1;
	ringp->s_ring_worker = thread_create(NULL, 0,
	    mac_soft_ring_worker, ringp, 0, &p0, TS_RUN, pri);
	if (type & ST_RING_TX) {
		ringp->s_ring_drain_func = mac_tx_soft_ring_drain;
		ringp->s_ring_tx_arg1 = x_arg1;
		ringp->s_ring_tx_arg2 = x_arg2;
		ringp->s_ring_tx_max_q_cnt = mac_tx_soft_ring_max_q_cnt;
		ringp->s_ring_tx_hiwat =
		    (mac_tx_soft_ring_hiwat > mac_tx_soft_ring_max_q_cnt) ?
		    mac_tx_soft_ring_max_q_cnt : mac_tx_soft_ring_hiwat;
		if (mcip->mci_state_flags & MCIS_IS_AGGR) {
			mac_srs_tx_t *tx = &mac_srs->srs_tx;

			ASSERT(tx->st_soft_rings[
			    ((mac_ring_t *)x_arg2)->mr_index] == NULL);
			tx->st_soft_rings[((mac_ring_t *)x_arg2)->mr_index] =
			    ringp;
		}
	} else {
		ringp->s_ring_drain_func = mac_rx_soft_ring_drain;
		ringp->s_ring_rx_func = rx_func;
		ringp->s_ring_rx_arg1 = x_arg1;
		ringp->s_ring_rx_arg2 = x_arg2;
		if (mac_srs->srs_state & SRS_SOFTRING_QUEUE)
			ringp->s_ring_type |= ST_RING_WORKER_ONLY;
	}
	if (cpuid != -1)
		(void) mac_soft_ring_bind(ringp, cpuid);

	mac_soft_ring_stat_create(ringp);

	return (ringp);
}

/*
 * mac_soft_ring_free
 *
 * Free the soft ring once we are done with it.
 */
void
mac_soft_ring_free(mac_soft_ring_t *softring)
{
	ASSERT((softring->s_ring_state &
	    (S_RING_CONDEMNED | S_RING_CONDEMNED_DONE | S_RING_PROC)) ==
	    (S_RING_CONDEMNED | S_RING_CONDEMNED_DONE));
	mac_pkt_drop(NULL, NULL, softring->s_ring_first, B_FALSE);
	softring->s_ring_tx_arg2 = NULL;
	mac_soft_ring_stat_delete(softring);
	mac_callback_free(softring->s_ring_notify_cb_list);
	kmem_cache_free(mac_soft_ring_cache, softring);
}

int mac_soft_ring_thread_bind = 1;

/*
 * mac_soft_ring_bind
 *
 * Bind a soft ring worker thread to supplied CPU.
 */
cpu_t *
mac_soft_ring_bind(mac_soft_ring_t *ringp, processorid_t cpuid)
{
	cpu_t *cp;
	boolean_t clear = B_FALSE;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (mac_soft_ring_thread_bind == 0) {
		DTRACE_PROBE1(mac__soft__ring__no__cpu__bound,
		    mac_soft_ring_t *, ringp);
		return (NULL);
	}

	cp = cpu_get(cpuid);
	if (cp == NULL || !cpu_is_online(cp))
		return (NULL);

	mutex_enter(&ringp->s_ring_lock);
	ringp->s_ring_state |= S_RING_BOUND;
	if (ringp->s_ring_cpuid != -1)
		clear = B_TRUE;
	ringp->s_ring_cpuid = cpuid;
	mutex_exit(&ringp->s_ring_lock);

	if (clear)
		thread_affinity_clear(ringp->s_ring_worker);

	DTRACE_PROBE2(mac__soft__ring__cpu__bound, mac_soft_ring_t *,
	    ringp, processorid_t, cpuid);

	thread_affinity_set(ringp->s_ring_worker, cpuid);

	return (cp);
}

/*
 * mac_soft_ring_unbind
 *
 * Un Bind a soft ring worker thread.
 */
void
mac_soft_ring_unbind(mac_soft_ring_t *ringp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	mutex_enter(&ringp->s_ring_lock);
	if (!(ringp->s_ring_state & S_RING_BOUND)) {
		ASSERT(ringp->s_ring_cpuid == -1);
		mutex_exit(&ringp->s_ring_lock);
		return;
	}

	ringp->s_ring_cpuid = -1;
	ringp->s_ring_state &= ~S_RING_BOUND;
	thread_affinity_clear(ringp->s_ring_worker);
	mutex_exit(&ringp->s_ring_lock);
}

/*
 * PRIVATE FUNCTIONS
 */

static void
mac_soft_ring_fire(void *arg)
{
	mac_soft_ring_t	*ringp = arg;

	mutex_enter(&ringp->s_ring_lock);
	if (ringp->s_ring_tid == NULL) {
		mutex_exit(&ringp->s_ring_lock);
		return;
	}

	ringp->s_ring_tid = NULL;

	if (!(ringp->s_ring_state & S_RING_PROC)) {
		cv_signal(&ringp->s_ring_async);
	}
	mutex_exit(&ringp->s_ring_lock);
}

/*
 * mac_rx_soft_ring_drain
 *
 * Called when worker thread model (ST_RING_WORKER_ONLY) of processing
 * incoming packets is used. s_ring_first contain the queued packets.
 * s_ring_rx_func contains the upper level (client) routine where the
 * packets are destined and s_ring_rx_arg1/s_ring_rx_arg2 are the
 * cookie meant for the client.
 */
/* ARGSUSED */
static void
mac_rx_soft_ring_drain(mac_soft_ring_t *ringp)
{
	mblk_t		*mp;
	void		*arg1;
	mac_resource_handle_t arg2;
	timeout_id_t 	tid;
	mac_direct_rx_t	proc;
	size_t		sz;
	int		cnt;
	mac_soft_ring_set_t	*mac_srs = ringp->s_ring_set;

	ringp->s_ring_run = curthread;
	ASSERT(mutex_owned(&ringp->s_ring_lock));
	ASSERT(!(ringp->s_ring_state & S_RING_PROC));

	if ((tid = ringp->s_ring_tid) != NULL)
		ringp->s_ring_tid = NULL;

	ringp->s_ring_state |= S_RING_PROC;

	proc = ringp->s_ring_rx_func;
	arg1 = ringp->s_ring_rx_arg1;
	arg2 = ringp->s_ring_rx_arg2;

	while ((ringp->s_ring_first != NULL) &&
	    !(ringp->s_ring_state & S_RING_PAUSE)) {
		mp = ringp->s_ring_first;
		ringp->s_ring_first = NULL;
		ringp->s_ring_last = NULL;
		cnt = ringp->s_ring_count;
		ringp->s_ring_count = 0;
		sz = ringp->s_ring_size;
		ringp->s_ring_size = 0;
		mutex_exit(&ringp->s_ring_lock);

		if (tid != NULL) {
			(void) untimeout(tid);
			tid = NULL;
		}

		(*proc)(arg1, arg2, mp, NULL);

		/*
		 * If we have a soft ring set which is doing
		 * bandwidth control, we need to decrement its
		 * srs_size so it can have a accurate idea of
		 * what is the real data queued between SRS and
		 * its soft rings. We decrement the size for a
		 * packet only when it gets processed by both
		 * SRS and the soft ring.
		 */
		mutex_enter(&mac_srs->srs_lock);
		MAC_UPDATE_SRS_COUNT_LOCKED(mac_srs, cnt);
		MAC_UPDATE_SRS_SIZE_LOCKED(mac_srs, sz);
		mutex_exit(&mac_srs->srs_lock);

		mutex_enter(&ringp->s_ring_lock);
	}
	ringp->s_ring_state &= ~S_RING_PROC;
	if (ringp->s_ring_state & S_RING_CLIENT_WAIT)
		cv_signal(&ringp->s_ring_client_cv);
	ringp->s_ring_run = NULL;
}

/*
 * mac_soft_ring_worker
 *
 * The soft ring worker routine to process any queued packets. In
 * normal case, the worker thread is bound to a CPU. It the soft
 * ring is dealing with TCP packets, then the worker thread will
 * be bound to the same CPU as the TCP squeue.
 */
static void
mac_soft_ring_worker(mac_soft_ring_t *ringp)
{
	kmutex_t *lock = &ringp->s_ring_lock;
	kcondvar_t *async = &ringp->s_ring_async;
	mac_soft_ring_set_t *srs = ringp->s_ring_set;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "mac_soft_ring");
	mutex_enter(lock);
start:
	for (;;) {
		while (((ringp->s_ring_first == NULL ||
		    (ringp->s_ring_state & (S_RING_BLOCK|S_RING_BLANK))) &&
		    !(ringp->s_ring_state & S_RING_PAUSE)) ||
		    (ringp->s_ring_state & S_RING_PROC)) {

			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(async, lock);
			CALLB_CPR_SAFE_END(&cprinfo, lock);
		}

		/*
		 * Either we have work to do, or we have been asked to
		 * shutdown temporarily or permanently
		 */
		if (ringp->s_ring_state & S_RING_PAUSE)
			goto done;

		ringp->s_ring_drain_func(ringp);
	}
done:
	mutex_exit(lock);
	mutex_enter(&srs->srs_lock);
	mutex_enter(lock);

	ringp->s_ring_state |= S_RING_QUIESCE_DONE;
	if (!(ringp->s_ring_state & S_RING_CONDEMNED)) {
		srs->srs_soft_ring_quiesced_count++;
		cv_broadcast(&srs->srs_async);
		mutex_exit(&srs->srs_lock);
		while (!(ringp->s_ring_state &
		    (S_RING_RESTART | S_RING_CONDEMNED)))
			cv_wait(&ringp->s_ring_async, &ringp->s_ring_lock);
		mutex_exit(lock);
		mutex_enter(&srs->srs_lock);
		mutex_enter(lock);
		srs->srs_soft_ring_quiesced_count--;
		if (ringp->s_ring_state & S_RING_RESTART) {
			ASSERT(!(ringp->s_ring_state & S_RING_CONDEMNED));
			ringp->s_ring_state &= ~(S_RING_RESTART |
			    S_RING_QUIESCE | S_RING_QUIESCE_DONE);
			cv_broadcast(&srs->srs_async);
			mutex_exit(&srs->srs_lock);
			goto start;
		}
	}
	ASSERT(ringp->s_ring_state & S_RING_CONDEMNED);
	ringp->s_ring_state |= S_RING_CONDEMNED_DONE;
	CALLB_CPR_EXIT(&cprinfo);
	srs->srs_soft_ring_condemned_count++;
	cv_broadcast(&srs->srs_async);
	mutex_exit(&srs->srs_lock);
	thread_exit();
}

/*
 * mac_soft_ring_intr_enable and mac_soft_ring_intr_disable
 *
 * these functions are called to toggle the sending of packets to the
 * client. They are called by the client. the client gets the name
 * of these routine and corresponding cookie (pointing to softring)
 * during capability negotiation at setup time.
 *
 * Enabling is allow the processing thread to send packets to the
 * client while disabling does the opposite.
 */
void
mac_soft_ring_intr_enable(void *arg)
{
	mac_soft_ring_t *ringp = (mac_soft_ring_t *)arg;
	mutex_enter(&ringp->s_ring_lock);
	ringp->s_ring_state &= ~S_RING_BLANK;
	if (ringp->s_ring_first != NULL)
		mac_soft_ring_worker_wakeup(ringp);
	mutex_exit(&ringp->s_ring_lock);
}

boolean_t
mac_soft_ring_intr_disable(void *arg)
{
	mac_soft_ring_t *ringp = (mac_soft_ring_t *)arg;
	boolean_t sring_blanked = B_FALSE;
	/*
	 * Stop worker thread from sending packets above.
	 * Squeue will poll soft ring when it needs packets.
	 */
	mutex_enter(&ringp->s_ring_lock);
	if (!(ringp->s_ring_state & S_RING_PROC)) {
		ringp->s_ring_state |= S_RING_BLANK;
		sring_blanked = B_TRUE;
	}
	mutex_exit(&ringp->s_ring_lock);
	return (sring_blanked);
}

/*
 * mac_soft_ring_poll
 *
 * This routine is called by the client to poll for packets from
 * the soft ring. The function name and cookie corresponding to
 * the soft ring is exchanged during capability negotiation during
 * setup.
 */
mblk_t *
mac_soft_ring_poll(mac_soft_ring_t *ringp, int bytes_to_pickup)
{
	mblk_t	*head, *tail;
	mblk_t	*mp;
	size_t	sz = 0;
	int	cnt = 0;
	mac_soft_ring_set_t	*mac_srs = ringp->s_ring_set;

	ASSERT(mac_srs != NULL);

	mutex_enter(&ringp->s_ring_lock);
	head = tail = mp = ringp->s_ring_first;
	if (head == NULL) {
		mutex_exit(&ringp->s_ring_lock);
		return (NULL);
	}

	if (ringp->s_ring_size <= bytes_to_pickup) {
		head = ringp->s_ring_first;
		ringp->s_ring_first = NULL;
		ringp->s_ring_last = NULL;
		cnt = ringp->s_ring_count;
		ringp->s_ring_count = 0;
		sz = ringp->s_ring_size;
		ringp->s_ring_size = 0;
	} else {
		while (mp && sz <= bytes_to_pickup) {
			sz += msgdsize(mp);
			cnt++;
			tail = mp;
			mp = mp->b_next;
		}
		ringp->s_ring_count -= cnt;
		ringp->s_ring_size -= sz;
		tail->b_next = NULL;
		if (mp == NULL) {
			ringp->s_ring_first = NULL;
			ringp->s_ring_last = NULL;
			ASSERT(ringp->s_ring_count == 0);
		} else {
			ringp->s_ring_first = mp;
		}
	}

	mutex_exit(&ringp->s_ring_lock);
	/*
	 * Update the shared count and size counters so
	 * that SRS has a accurate idea of queued packets.
	 */
	mutex_enter(&mac_srs->srs_lock);
	MAC_UPDATE_SRS_COUNT_LOCKED(mac_srs, cnt);
	MAC_UPDATE_SRS_SIZE_LOCKED(mac_srs, sz);
	mutex_exit(&mac_srs->srs_lock);
	return (head);
}

/*
 * mac_soft_ring_dls_bypass
 *
 * Enable direct client (IP) callback function from the softrings.
 * Callers need to make sure they don't need any DLS layer processing
 */
void
mac_soft_ring_dls_bypass(void *arg, mac_direct_rx_t rx_func, void *rx_arg1)
{
	mac_soft_ring_t		*softring = arg;
	mac_soft_ring_set_t	*srs;

	ASSERT(rx_func != NULL);

	mutex_enter(&softring->s_ring_lock);
	softring->s_ring_rx_func = rx_func;
	softring->s_ring_rx_arg1 = rx_arg1;
	mutex_exit(&softring->s_ring_lock);

	srs = softring->s_ring_set;
	mutex_enter(&srs->srs_lock);
	srs->srs_type |= SRST_DLS_BYPASS;
	mutex_exit(&srs->srs_lock);
}

/*
 * mac_soft_ring_signal
 *
 * Typically used to set the soft ring state to QUIESCE, CONDEMNED, or
 * RESTART.
 *
 * In the Rx side, the quiescing is done bottom up. After the Rx upcalls
 * from the driver are done, then the Rx SRS is quiesced and only then can
 * we signal the soft rings. Thus this function can't be called arbitrarily
 * without satisfying the prerequisites. On the Tx side, the threads from
 * top need to quiesced, then the Tx SRS and only then can we signal the
 * Tx soft rings.
 */
void
mac_soft_ring_signal(mac_soft_ring_t *softring, uint_t sr_flag)
{
	mutex_enter(&softring->s_ring_lock);
	softring->s_ring_state |= sr_flag;
	cv_signal(&softring->s_ring_async);
	mutex_exit(&softring->s_ring_lock);
}

/*
 * mac_tx_soft_ring_drain
 *
 * The transmit side drain routine in case the soft ring was being
 * used to transmit packets.
 */
static void
mac_tx_soft_ring_drain(mac_soft_ring_t *ringp)
{
	mblk_t 			*mp;
	void 			*arg1;
	void 			*arg2;
	mblk_t 			*tail;
	uint_t			saved_pkt_count, saved_size;
	mac_tx_stats_t		stats;
	mac_soft_ring_set_t	*mac_srs = ringp->s_ring_set;

	saved_pkt_count = saved_size = 0;
	ringp->s_ring_run = curthread;
	ASSERT(mutex_owned(&ringp->s_ring_lock));
	ASSERT(!(ringp->s_ring_state & S_RING_PROC));

	ringp->s_ring_state |= S_RING_PROC;
	arg1 = ringp->s_ring_tx_arg1;
	arg2 = ringp->s_ring_tx_arg2;

	while (ringp->s_ring_first != NULL) {
		mp = ringp->s_ring_first;
		tail = ringp->s_ring_last;
		saved_pkt_count = ringp->s_ring_count;
		saved_size = ringp->s_ring_size;
		ringp->s_ring_first = NULL;
		ringp->s_ring_last = NULL;
		ringp->s_ring_count = 0;
		ringp->s_ring_size = 0;
		mutex_exit(&ringp->s_ring_lock);

		mp = mac_tx_send(arg1, arg2, mp, &stats);

		mutex_enter(&ringp->s_ring_lock);
		if (mp != NULL) {
			/* Device out of tx desc, set block */
			tail->b_next = ringp->s_ring_first;
			ringp->s_ring_first = mp;
			ringp->s_ring_count +=
			    (saved_pkt_count - stats.mts_opackets);
			ringp->s_ring_size += (saved_size - stats.mts_obytes);
			if (ringp->s_ring_last == NULL)
				ringp->s_ring_last = tail;

			if (ringp->s_ring_tx_woken_up) {
				ringp->s_ring_tx_woken_up = B_FALSE;
			} else {
				ringp->s_ring_state |= S_RING_BLOCK;
				ringp->s_st_stat.mts_blockcnt++;
			}

			ringp->s_ring_state &= ~S_RING_PROC;
			ringp->s_ring_run = NULL;
			return;
		} else {
			ringp->s_ring_tx_woken_up = B_FALSE;
			SRS_TX_STATS_UPDATE(mac_srs, &stats);
			SOFTRING_TX_STATS_UPDATE(ringp, &stats);
		}
	}

	if (ringp->s_ring_count == 0 && ringp->s_ring_state &
	    (S_RING_TX_HIWAT | S_RING_WAKEUP_CLIENT | S_RING_ENQUEUED)) {
		mac_client_impl_t *mcip =  ringp->s_ring_mcip;
		boolean_t wakeup_required = B_FALSE;

		if (ringp->s_ring_state &
		    (S_RING_TX_HIWAT|S_RING_WAKEUP_CLIENT)) {
			wakeup_required = B_TRUE;
		}
		ringp->s_ring_state &=
		    ~(S_RING_TX_HIWAT | S_RING_WAKEUP_CLIENT | S_RING_ENQUEUED);
		mutex_exit(&ringp->s_ring_lock);
		if (wakeup_required) {
			mac_tx_invoke_callbacks(mcip, (mac_tx_cookie_t)ringp);
			/*
			 * If the client is not the primary MAC client, then we
			 * need to send the notification to the clients upper
			 * MAC, i.e. mci_upper_mip.
			 */
			mac_tx_notify(mcip->mci_upper_mip != NULL ?
			    mcip->mci_upper_mip : mcip->mci_mip);
		}
		mutex_enter(&ringp->s_ring_lock);
	}
	ringp->s_ring_state &= ~S_RING_PROC;
	ringp->s_ring_run = NULL;
}
