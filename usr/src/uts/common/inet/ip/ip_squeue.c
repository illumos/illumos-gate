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
 * IP interface to squeues.
 *
 * IP uses squeues to force serialization of packets, both incoming and
 * outgoing. Each squeue is associated with a connection instance (conn_t)
 * above, and a soft ring (if enabled) below. Each CPU will have a default
 * squeue for outbound connections, and each soft ring of an interface will
 * have an squeue to which it sends incoming packets. squeues are never
 * destroyed, and if they become unused they are kept around against future
 * needs.
 *
 * IP organizes its squeues using squeue sets (squeue_set_t). For each CPU
 * in the system there will be one squeue set, all of whose squeues will be
 * bound to that CPU, plus one additional set known as the unbound set. Sets
 * associated with CPUs will have one default squeue, for outbound
 * connections, and a linked list of squeues used by various NICs for inbound
 * packets. The unbound set also has a linked list of squeues, but no default
 * squeue.
 *
 * When a CPU goes offline its squeue set is destroyed, and all its squeues
 * are moved to the unbound set. When a CPU comes online, a new squeue set is
 * created and the default set is searched for a default squeue formerly bound
 * to this CPU. If no default squeue is found, a new one is created.
 *
 * Two fields of the squeue_t, namely sq_next and sq_set, are owned by IP
 * and not the squeue code. squeue.c will not touch them, and we can modify
 * them without holding the squeue lock because of the guarantee that squeues
 * are never destroyed. ip_squeue locks must be held, however.
 *
 * All the squeue sets are protected by a single lock, the sqset_lock. This
 * is also used to protect the sq_next and sq_set fields of an squeue_t.
 *
 * The lock order is: cpu_lock --> ill_lock --> sqset_lock --> sq_lock
 *
 * There are two modes of associating connection with squeues. The first mode
 * associates each connection with the CPU that creates the connection (either
 * during open time or during accept time). The second mode associates each
 * connection with a random CPU, effectively distributing load over all CPUs
 * and all squeues in the system. The mode is controlled by the
 * ip_squeue_fanout variable.
 *
 * NOTE: The fact that there is an association between each connection and
 * squeue and squeue and CPU does not mean that each connection is always
 * processed on this CPU and on this CPU only. Any thread calling squeue_enter()
 * may process the connection on whatever CPU it is scheduled. The squeue to CPU
 * binding is only relevant for the worker thread.
 *
 * INTERFACE:
 *
 * squeue_t *ip_squeue_get(ill_rx_ring_t)
 *
 * Returns the squeue associated with an ill receive ring. If the ring is
 * not bound to a CPU, and we're currently servicing the interrupt which
 * generated the packet, then bind the squeue to CPU.
 *
 *
 * DR Notes
 * ========
 *
 * The ip_squeue_init() registers a call-back function with the CPU DR
 * subsystem using register_cpu_setup_func(). The call-back function does two
 * things:
 *
 * o When the CPU is going off-line or unconfigured, the worker thread is
 *	unbound from the CPU. This allows the CPU unconfig code to move it to
 *	another CPU.
 *
 * o When the CPU is going online, it creates a new squeue for this CPU if
 *	necessary and binds the squeue worker thread to this CPU.
 *
 * TUNABLES:
 *
 * ip_squeue_fanout: used when TCP calls IP_SQUEUE_GET(). If 1, then
 * pick the default squeue from a random CPU, otherwise use our CPU's default
 * squeue.
 *
 * ip_squeue_fanout can be accessed and changed using ndd on /dev/tcp or
 * /dev/ip.
 *
 * ip_squeue_worker_wait: global value for the sq_wait field for all squeues *
 * created. This is the time squeue code waits before waking up the worker
 * thread after queuing a request.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <netinet/ip6.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/nd.h>
#include <inet/ipclassifier.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/squeue_impl.h>
#include <sys/tihdr.h>
#include <inet/udp_impl.h>
#include <sys/strsubr.h>
#include <sys/zone.h>
#include <sys/dld.h>
#include <sys/atomic.h>

/*
 * List of all created squeue sets. The list and its size are protected by
 * sqset_lock.
 */
static squeue_set_t	**sqset_global_list; /* list 0 is the unbound list */
static uint_t		sqset_global_size;
kmutex_t		sqset_lock;

static void (*ip_squeue_create_callback)(squeue_t *) = NULL;

/*
 * ip_squeue_worker_wait: global value for the sq_wait field for all squeues
 *	created. This is the time squeue code waits before waking up the worker
 *	thread after queuing a request.
 */
uint_t ip_squeue_worker_wait = 10;

static squeue_t *ip_squeue_create(pri_t);
static squeue_set_t *ip_squeue_set_create(processorid_t);
static int ip_squeue_cpu_setup(cpu_setup_t, int, void *);
static void ip_squeue_set_move(squeue_t *, squeue_set_t *);
static void ip_squeue_set_destroy(cpu_t *);
static void ip_squeue_clean(void *, mblk_t *, void *);

#define	CPU_ISON(c) (c != NULL && CPU_ACTIVE(c) && (c->cpu_flags & CPU_EXISTS))

static squeue_t *
ip_squeue_create(pri_t pri)
{
	squeue_t *sqp;

	sqp = squeue_create(ip_squeue_worker_wait, pri);
	ASSERT(sqp != NULL);
	if (ip_squeue_create_callback != NULL)
		ip_squeue_create_callback(sqp);
	return (sqp);
}

/*
 * Create a new squeue_set. If id == -1, then we're creating the unbound set,
 * which should only happen once when we are first initialized. Otherwise id
 * is the id of the CPU that needs a set, either because we are initializing
 * or because the CPU has come online.
 *
 * If id != -1, then we need at a minimum to provide a default squeue for the
 * new set. We search the unbound set for candidates, and if none are found we
 * create a new one.
 */
static squeue_set_t *
ip_squeue_set_create(processorid_t id)
{
	squeue_set_t	*sqs;
	squeue_set_t	*src = sqset_global_list[0];
	squeue_t	**lastsqp, *sq;
	squeue_t	**defaultq_lastp = NULL;

	sqs = kmem_zalloc(sizeof (squeue_set_t), KM_SLEEP);
	sqs->sqs_cpuid = id;

	if (id == -1) {
		ASSERT(sqset_global_size == 0);
		sqset_global_list[0] = sqs;
		sqset_global_size = 1;
		return (sqs);
	}

	/*
	 * When we create an squeue set id != -1, we need to give it a
	 * default squeue, in order to support fanout of conns across
	 * CPUs. Try to find a former default squeue that matches this
	 * cpu id on the unbound squeue set. If no such squeue is found,
	 * find some non-default TCP squeue that is free. If still no such
	 * candidate is found, create a new squeue.
	 */

	ASSERT(MUTEX_HELD(&cpu_lock));
	mutex_enter(&sqset_lock);
	lastsqp = &src->sqs_head;

	while (*lastsqp) {
		if ((*lastsqp)->sq_bind == id &&
		    (*lastsqp)->sq_state & SQS_DEFAULT) {
			/*
			 * Exact match. Former default squeue of cpu 'id'
			 */
			ASSERT(!((*lastsqp)->sq_state & SQS_ILL_BOUND));
			defaultq_lastp = lastsqp;
			break;
		}
		if (defaultq_lastp == NULL &&
		    !((*lastsqp)->sq_state & (SQS_ILL_BOUND | SQS_DEFAULT))) {
			/*
			 * A free non-default TCP squeue
			 */
			defaultq_lastp = lastsqp;
		}
		lastsqp = &(*lastsqp)->sq_next;
	}

	if (defaultq_lastp != NULL) {
		/* Remove from src set and set SQS_DEFAULT */
		sq = *defaultq_lastp;
		*defaultq_lastp = sq->sq_next;
		sq->sq_next = NULL;
		if (!(sq->sq_state & SQS_DEFAULT)) {
			mutex_enter(&sq->sq_lock);
			sq->sq_state |= SQS_DEFAULT;
			mutex_exit(&sq->sq_lock);
		}
	} else {
		sq = ip_squeue_create(SQUEUE_DEFAULT_PRIORITY);
		sq->sq_state |= SQS_DEFAULT;
	}

	sq->sq_set = sqs;
	sqs->sqs_default = sq;
	squeue_bind(sq, id); /* this locks squeue mutex */

	ASSERT(sqset_global_size <= NCPU);
	sqset_global_list[sqset_global_size++] = sqs;
	mutex_exit(&sqset_lock);
	return (sqs);
}

/*
 * Called by ill_ring_add() to find an squeue to associate with a new ring.
 */

squeue_t *
ip_squeue_getfree(pri_t pri)
{
	squeue_set_t	*sqs = sqset_global_list[0];
	squeue_t	*sq;

	mutex_enter(&sqset_lock);
	for (sq = sqs->sqs_head; sq != NULL; sq = sq->sq_next) {
		/*
		 * Select a non-default TCP squeue that is free i.e. not
		 * bound to any ill.
		 */
		if (!(sq->sq_state & (SQS_DEFAULT | SQS_ILL_BOUND)))
			break;
	}

	if (sq == NULL) {
		sq = ip_squeue_create(pri);
		sq->sq_set = sqs;
		sq->sq_next = sqs->sqs_head;
		sqs->sqs_head = sq;
	}

	ASSERT(!(sq->sq_state & (SQS_POLL_THR_CONTROL | SQS_WORKER_THR_CONTROL |
	    SQS_POLL_CLEANUP_DONE | SQS_POLL_QUIESCE_DONE |
	    SQS_POLL_THR_QUIESCED)));

	mutex_enter(&sq->sq_lock);
	sq->sq_state |= SQS_ILL_BOUND;
	mutex_exit(&sq->sq_lock);
	mutex_exit(&sqset_lock);

	if (sq->sq_priority != pri) {
		thread_lock(sq->sq_worker);
		(void) thread_change_pri(sq->sq_worker, pri, 0);
		thread_unlock(sq->sq_worker);

		thread_lock(sq->sq_poll_thr);
		(void) thread_change_pri(sq->sq_poll_thr, pri, 0);
		thread_unlock(sq->sq_poll_thr);

		sq->sq_priority = pri;
	}
	return (sq);
}

/*
 * Initialize IP squeues.
 */
void
ip_squeue_init(void (*callback)(squeue_t *))
{
	int i;
	squeue_set_t	*sqs;

	ASSERT(sqset_global_list == NULL);

	ip_squeue_create_callback = callback;
	squeue_init();
	mutex_init(&sqset_lock, NULL, MUTEX_DEFAULT, NULL);
	sqset_global_list =
	    kmem_zalloc(sizeof (squeue_set_t *) * (NCPU+1), KM_SLEEP);
	sqset_global_size = 0;
	/*
	 * We are called at system boot time and we don't
	 * expect memory allocation failure.
	 */
	sqs = ip_squeue_set_create(-1);
	ASSERT(sqs != NULL);

	mutex_enter(&cpu_lock);
	/* Create squeue for each active CPU available */
	for (i = 0; i < NCPU; i++) {
		cpu_t *cp = cpu_get(i);
		if (CPU_ISON(cp) && cp->cpu_squeue_set == NULL) {
			/*
			 * We are called at system boot time and we don't
			 * expect memory allocation failure then
			 */
			cp->cpu_squeue_set = ip_squeue_set_create(cp->cpu_id);
			ASSERT(cp->cpu_squeue_set != NULL);
		}
	}

	register_cpu_setup_func(ip_squeue_cpu_setup, NULL);
	mutex_exit(&cpu_lock);
}

/*
 * Get a default squeue, either from the current CPU or a CPU derived by hash
 * from the index argument, depending upon the setting of ip_squeue_fanout.
 */
squeue_t *
ip_squeue_random(uint_t index)
{
	squeue_set_t *sqs = NULL;
	squeue_t *sq;

	/*
	 * The minimum value of sqset_global_size is 2, one for the unbound
	 * squeue set and another for the squeue set of the zeroth CPU.
	 * Even though the value could be changing, it can never go below 2,
	 * so the assert does not need the lock protection.
	 */
	ASSERT(sqset_global_size > 1);

	/* Protect against changes to sqset_global_list */
	mutex_enter(&sqset_lock);

	if (!ip_squeue_fanout)
		sqs = CPU->cpu_squeue_set;

	/*
	 * sqset_global_list[0] corresponds to the unbound squeue set.
	 * The computation below picks a set other than the unbound set.
	 */
	if (sqs == NULL)
		sqs = sqset_global_list[(index % (sqset_global_size - 1)) + 1];
	sq = sqs->sqs_default;

	mutex_exit(&sqset_lock);
	ASSERT(sq);
	return (sq);
}

/*
 * Move squeue from its current set to newset. Not used for default squeues.
 * Bind or unbind the worker thread as appropriate.
 */

static void
ip_squeue_set_move(squeue_t *sq, squeue_set_t *newset)
{
	squeue_set_t	*set;
	squeue_t	**lastsqp;
	processorid_t	cpuid = newset->sqs_cpuid;

	ASSERT(!(sq->sq_state & SQS_DEFAULT));
	ASSERT(!MUTEX_HELD(&sq->sq_lock));
	ASSERT(MUTEX_HELD(&sqset_lock));

	set = sq->sq_set;
	if (set == newset)
		return;

	lastsqp = &set->sqs_head;
	while (*lastsqp != sq)
		lastsqp = &(*lastsqp)->sq_next;

	*lastsqp = sq->sq_next;
	sq->sq_next = newset->sqs_head;
	newset->sqs_head = sq;
	sq->sq_set = newset;
	if (cpuid == -1)
		squeue_unbind(sq);
	else
		squeue_bind(sq, cpuid);
}

/*
 * Move squeue from its current set to cpuid's set and bind to cpuid.
 */

int
ip_squeue_cpu_move(squeue_t *sq, processorid_t cpuid)
{
	cpu_t *cpu;
	squeue_set_t *set;

	if (sq->sq_state & SQS_DEFAULT)
		return (-1);

	ASSERT(MUTEX_HELD(&cpu_lock));

	cpu = cpu_get(cpuid);
	if (!CPU_ISON(cpu))
		return (-1);

	mutex_enter(&sqset_lock);
	set = cpu->cpu_squeue_set;
	if (set != NULL)
		ip_squeue_set_move(sq, set);
	mutex_exit(&sqset_lock);
	return ((set == NULL) ? -1 : 0);
}

/*
 * The mac layer is calling, asking us to move an squeue to a
 * new CPU. This routine is called with cpu_lock held.
 */
void
ip_squeue_bind_ring(ill_t *ill, ill_rx_ring_t *rx_ring, processorid_t cpuid)
{
	ASSERT(ILL_MAC_PERIM_HELD(ill));
	ASSERT(rx_ring->rr_ill == ill);

	mutex_enter(&ill->ill_lock);
	if (rx_ring->rr_ring_state == RR_FREE ||
	    rx_ring->rr_ring_state == RR_FREE_INPROG) {
		mutex_exit(&ill->ill_lock);
		return;
	}

	if (ip_squeue_cpu_move(rx_ring->rr_sqp, cpuid) != -1)
		rx_ring->rr_ring_state = RR_SQUEUE_BOUND;

	mutex_exit(&ill->ill_lock);
}

void *
ip_squeue_add_ring(ill_t *ill, void *mrp)
{
	mac_rx_fifo_t		*mrfp = (mac_rx_fifo_t *)mrp;
	ill_rx_ring_t		*rx_ring, *ring_tbl;
	int			ip_rx_index;
	squeue_t		*sq = NULL;
	pri_t			pri;

	ASSERT(ILL_MAC_PERIM_HELD(ill));
	ASSERT(mrfp->mrf_type == MAC_RX_FIFO);
	ASSERT(ill->ill_dld_capab != NULL);

	ring_tbl = ill->ill_dld_capab->idc_poll.idp_ring_tbl;

	mutex_enter(&ill->ill_lock);
	for (ip_rx_index = 0; ip_rx_index < ILL_MAX_RINGS; ip_rx_index++) {
		rx_ring = &ring_tbl[ip_rx_index];
		if (rx_ring->rr_ring_state == RR_FREE)
			break;
	}

	if (ip_rx_index == ILL_MAX_RINGS) {
		/*
		 * We ran out of ILL_MAX_RINGS worth rx_ring structures. If
		 * we have devices which can overwhelm this limit,
		 * ILL_MAX_RING should be made configurable. Meanwhile it
		 * cause no panic because driver will pass ip_input a NULL
		 * handle which will make IP allocate the default squeue and
		 * Polling mode will not be used for this ring.
		 */
		cmn_err(CE_NOTE,
		    "Reached maximum number of receiving rings (%d) for %s\n",
		    ILL_MAX_RINGS, ill->ill_name);
		mutex_exit(&ill->ill_lock);
		return (NULL);
	}

	bzero(rx_ring, sizeof (ill_rx_ring_t));
	rx_ring->rr_rx = (ip_mac_rx_t)mrfp->mrf_receive;
	/* XXX: Hard code it to tcp accept for now */
	rx_ring->rr_ip_accept = (ip_accept_t)ip_accept_tcp;

	rx_ring->rr_intr_handle = mrfp->mrf_intr_handle;
	rx_ring->rr_intr_enable = (ip_mac_intr_enable_t)mrfp->mrf_intr_enable;
	rx_ring->rr_intr_disable =
	    (ip_mac_intr_disable_t)mrfp->mrf_intr_disable;
	rx_ring->rr_rx_handle = mrfp->mrf_rx_arg;
	rx_ring->rr_ill = ill;

	pri = mrfp->mrf_flow_priority;

	sq = ip_squeue_getfree(pri);

	mutex_enter(&sq->sq_lock);
	sq->sq_rx_ring = rx_ring;
	rx_ring->rr_sqp = sq;

	sq->sq_state |= SQS_POLL_CAPAB;

	rx_ring->rr_ring_state = RR_SQUEUE_UNBOUND;
	sq->sq_ill = ill;
	mutex_exit(&sq->sq_lock);
	mutex_exit(&ill->ill_lock);

	DTRACE_PROBE4(ill__ring__add, char *, ill->ill_name, ill_t *, ill, int,
	    ip_rx_index, void *, mrfp->mrf_rx_arg);

	/* Assign the squeue to the specified CPU as well */
	mutex_enter(&cpu_lock);
	(void) ip_squeue_bind_ring(ill, rx_ring, mrfp->mrf_cpu_id);
	mutex_exit(&cpu_lock);

	return (rx_ring);
}

/*
 * sanitize the squeue etc. Some of the processing
 * needs to be done from inside the perimeter.
 */
void
ip_squeue_clean_ring(ill_t *ill, ill_rx_ring_t *rx_ring)
{
	squeue_t *sqp;

	ASSERT(ILL_MAC_PERIM_HELD(ill));
	ASSERT(rx_ring != NULL);

	/* Just clean one squeue */
	mutex_enter(&ill->ill_lock);
	if (rx_ring->rr_ring_state == RR_FREE) {
		mutex_exit(&ill->ill_lock);
		return;
	}
	rx_ring->rr_ring_state = RR_FREE_INPROG;
	sqp = rx_ring->rr_sqp;

	mutex_enter(&sqp->sq_lock);
	sqp->sq_state |= SQS_POLL_CLEANUP;
	cv_signal(&sqp->sq_worker_cv);
	mutex_exit(&ill->ill_lock);
	while (!(sqp->sq_state & SQS_POLL_CLEANUP_DONE))
		cv_wait(&sqp->sq_ctrlop_done_cv, &sqp->sq_lock);
	sqp->sq_state &= ~SQS_POLL_CLEANUP_DONE;

	ASSERT(!(sqp->sq_state & (SQS_POLL_THR_CONTROL |
	    SQS_WORKER_THR_CONTROL | SQS_POLL_QUIESCE_DONE |
	    SQS_POLL_THR_QUIESCED)));

	cv_signal(&sqp->sq_worker_cv);
	mutex_exit(&sqp->sq_lock);

	/*
	 * Move the squeue to sqset_global_list[0] which holds the set of
	 * squeues not bound to any cpu. Note that the squeue is still
	 * considered bound to an ill as long as SQS_ILL_BOUND is set.
	 */
	mutex_enter(&sqset_lock);
	ip_squeue_set_move(sqp, sqset_global_list[0]);
	mutex_exit(&sqset_lock);

	/*
	 * CPU going offline can also trigger a move of the squeue to the
	 * unbound set sqset_global_list[0]. However the squeue won't be
	 * recycled for the next use as long as the SQS_ILL_BOUND flag
	 * is set. Hence we clear the SQS_ILL_BOUND flag only towards the
	 * end after the move.
	 */
	mutex_enter(&sqp->sq_lock);
	sqp->sq_state &= ~SQS_ILL_BOUND;
	mutex_exit(&sqp->sq_lock);

	mutex_enter(&ill->ill_lock);
	rx_ring->rr_ring_state = RR_FREE;
	mutex_exit(&ill->ill_lock);
}

/*
 * Stop the squeue from polling. This needs to be done
 * from inside the perimeter.
 */
void
ip_squeue_quiesce_ring(ill_t *ill, ill_rx_ring_t *rx_ring)
{
	squeue_t *sqp;

	ASSERT(ILL_MAC_PERIM_HELD(ill));
	ASSERT(rx_ring != NULL);

	sqp = rx_ring->rr_sqp;
	mutex_enter(&sqp->sq_lock);
	sqp->sq_state |= SQS_POLL_QUIESCE;
	cv_signal(&sqp->sq_worker_cv);
	while (!(sqp->sq_state & SQS_POLL_QUIESCE_DONE))
		cv_wait(&sqp->sq_ctrlop_done_cv, &sqp->sq_lock);

	mutex_exit(&sqp->sq_lock);
}

/*
 * Restart polling etc. Needs to be inside the perimeter to
 * prevent races.
 */
void
ip_squeue_restart_ring(ill_t *ill, ill_rx_ring_t *rx_ring)
{
	squeue_t *sqp;

	ASSERT(ILL_MAC_PERIM_HELD(ill));
	ASSERT(rx_ring != NULL);

	sqp = rx_ring->rr_sqp;
	mutex_enter(&sqp->sq_lock);
	/*
	 * Handle change in number of rings between the quiesce and
	 * restart operations by checking for a previous quiesce before
	 * attempting a restart.
	 */
	if (!(sqp->sq_state & SQS_POLL_QUIESCE_DONE)) {
		mutex_exit(&sqp->sq_lock);
		return;
	}
	sqp->sq_state |= SQS_POLL_RESTART;
	cv_signal(&sqp->sq_worker_cv);
	while (!(sqp->sq_state & SQS_POLL_RESTART_DONE))
		cv_wait(&sqp->sq_ctrlop_done_cv, &sqp->sq_lock);
	sqp->sq_state &= ~SQS_POLL_RESTART_DONE;
	mutex_exit(&sqp->sq_lock);
}

/*
 * sanitize all squeues associated with the ill.
 */
void
ip_squeue_clean_all(ill_t *ill)
{
	int idx;
	ill_rx_ring_t	*rx_ring;

	for (idx = 0; idx < ILL_MAX_RINGS; idx++) {
		rx_ring = &ill->ill_dld_capab->idc_poll.idp_ring_tbl[idx];
		ip_squeue_clean_ring(ill, rx_ring);
	}
}

/*
 * Used by IP to get the squeue associated with a ring. If the squeue isn't
 * yet bound to a CPU, and we're being called directly from the NIC's
 * interrupt, then we know what CPU we want to assign the squeue to, so
 * dispatch that task to a taskq.
 */
squeue_t *
ip_squeue_get(ill_rx_ring_t *ill_rx_ring)
{
	squeue_t 	*sqp;

	if ((ill_rx_ring == NULL) || ((sqp = ill_rx_ring->rr_sqp) == NULL))
		return (IP_SQUEUE_GET(CPU_PSEUDO_RANDOM()));

	return (sqp);
}

/*
 * Called when a CPU goes offline. It's squeue_set_t is destroyed, and all
 * squeues are unboudn and moved to the unbound set.
 */
static void
ip_squeue_set_destroy(cpu_t *cpu)
{
	int i;
	squeue_t *sqp, *lastsqp = NULL;
	squeue_set_t *sqs, *unbound = sqset_global_list[0];

	mutex_enter(&sqset_lock);
	if ((sqs = cpu->cpu_squeue_set) == NULL) {
		mutex_exit(&sqset_lock);
		return;
	}

	/* Move all squeues to unbound set */

	for (sqp = sqs->sqs_head; sqp; lastsqp = sqp, sqp = sqp->sq_next) {
		squeue_unbind(sqp);
		sqp->sq_set = unbound;
	}
	if (sqs->sqs_head) {
		lastsqp->sq_next = unbound->sqs_head;
		unbound->sqs_head = sqs->sqs_head;
	}

	/* Also move default squeue to unbound set */

	sqp = sqs->sqs_default;
	ASSERT(sqp != NULL);
	ASSERT((sqp->sq_state & (SQS_DEFAULT|SQS_ILL_BOUND)) == SQS_DEFAULT);

	sqp->sq_next = unbound->sqs_head;
	unbound->sqs_head = sqp;
	squeue_unbind(sqp);
	sqp->sq_set = unbound;

	for (i = 1; i < sqset_global_size; i++)
		if (sqset_global_list[i] == sqs)
			break;

	ASSERT(i < sqset_global_size);
	sqset_global_list[i] = sqset_global_list[sqset_global_size - 1];
	sqset_global_list[sqset_global_size - 1] = NULL;
	sqset_global_size--;

	mutex_exit(&sqset_lock);
	kmem_free(sqs, sizeof (*sqs));
}

/*
 * Reconfiguration callback
 */
/* ARGSUSED */
static int
ip_squeue_cpu_setup(cpu_setup_t what, int id, void *arg)
{
	cpu_t *cp = cpu_get(id);

	ASSERT(MUTEX_HELD(&cpu_lock));
	switch (what) {
	case CPU_CONFIG:
	case CPU_ON:
	case CPU_INIT:
	case CPU_CPUPART_IN:
		if (CPU_ISON(cp) && cp->cpu_squeue_set == NULL)
			cp->cpu_squeue_set = ip_squeue_set_create(cp->cpu_id);
		break;
	case CPU_UNCONFIG:
	case CPU_OFF:
	case CPU_CPUPART_OUT:
		if (cp->cpu_squeue_set != NULL) {
			ip_squeue_set_destroy(cp);
			cp->cpu_squeue_set = NULL;
		}
		break;
	default:
		break;
	}
	return (0);
}
