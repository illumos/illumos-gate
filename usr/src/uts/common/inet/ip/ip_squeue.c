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
 * IP interface to squeues.
 *
 * IP creates an squeue instance for each CPU. The squeue pointer is saved in
 * cpu_squeue field of the cpu structure. Each squeue is associated with a
 * connection instance (conn_t).
 *
 * For CPUs available at system startup time the squeue creation and association
 * with CPU happens at MP initialization time. For CPUs added during dynamic
 * reconfiguration, the initialization happens when the new CPU is configured in
 * the system. The squeue is chosen using IP_SQUEUE_GET macro which will either
 * return per-CPU squeue or random squeue based on the ip_squeue_fanout
 * variable.
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
 * The list of all created squeues is kept in squeue_set structure. This list is
 * used when ip_squeue_fanout is set and the load is distributed across all
 * squeues.
 *
 * INTERFACE:
 *
 * squeue_t *ip_squeue_get(hint)
 *
 * 	Find an squeue based on the 'hint' value. The hint is used as an index
 * 	in the array of IP squeues available. The way hint is computed may
 * 	affect the effectiveness of the squeue distribution. Currently squeues
 * 	are assigned in round-robin fashion using lbolt as a hint.
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
 * TUNEBALES:
 *
 * ip_squeue_bind: if set to 1 each squeue worker thread is bound to the CPU
 * 	associated with an squeue instance.
 *
 * ip_squeue_profile: if set to 1 squeue profiling is enabled. NOTE: squeue.c
 *	should be compiled with SQUEUE_PROFILE enabled for this variable to have
 *	an impact.
 *
 * ip_squeue_fanout: if set to 1 use ip_squeue_get() to find an squeue,
 *	otherwise get it from CPU->cpu_squeue.
 *
 * ip_squeue_bind, ip_squeue_profile and ip_squeue_fanout can be accessed and
 * changed using ndd on /dev/tcp or /dev/ip.
 *
 * ip_squeue_worker_wait: global value for the sq_wait field for all squeues
 *	created. This is the time squeue code waits before waking up the worker
 *	thread after queuing a request.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>

#include <sys/cmn_err.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_if.h>
#include <inet/nd.h>
#include <inet/ipclassifier.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/squeue_impl.h>
#include <sys/atomic.h>

/*
 * We allow multiple NICs to bind to the same CPU but want to preserve 1 <-> 1
 * mapping between squeue and NIC (or Rx ring) for performance reasons so
 * each squeue can uniquely own a NIC or a Rx ring and do polling
 * (PSARC 2004/630). So we allow up to  MAX_SQUEUES_PER_CPU squeues per CPU.
 * We start by creating MIN_SQUEUES_PER_CPU squeues per CPU but more squeues
 * can be created dynamically as needed.
 */
#define	MAX_SQUEUES_PER_CPU	32
#define	MIN_SQUEUES_PER_CPU	1
uint_t	ip_squeues_per_cpu = MIN_SQUEUES_PER_CPU;

#define	IP_NUM_SOFT_RINGS	2
uint_t ip_soft_rings_cnt = IP_NUM_SOFT_RINGS;

/*
 * List of all created squeue sets. The size is protected by cpu_lock
 */
squeue_set_t	**sqset_global_list;
uint_t		sqset_global_size;

int ip_squeue_bind = B_TRUE;
int ip_squeue_profile = B_TRUE;
static void (*ip_squeue_create_callback)(squeue_t *) = NULL;

/*
 * ip_squeue_worker_wait: global value for the sq_wait field for all squeues
 *	created. This is the time squeue code waits before waking up the worker
 *	thread after queuing a request.
 */
uint_t ip_squeue_worker_wait = 10;

static squeue_set_t *ip_squeue_set_create(cpu_t *, boolean_t);
static int ip_squeue_cpu_setup(cpu_setup_t, int, void *);

static void ip_squeue_set_bind(squeue_set_t *);
static void ip_squeue_set_unbind(squeue_set_t *);
static squeue_t *ip_find_unused_squeue(squeue_set_t *, boolean_t);
static void ip_squeue_clean(void *, mblk_t *, void *);
static void ip_squeue_clean_ring(ill_t *, ill_rx_ring_t *);

#define	CPU_ISON(c) (c != NULL && CPU_ACTIVE(c) && (c->cpu_flags & CPU_EXISTS))

/*
 * Create squeue set containing ip_squeues_per_cpu number of squeues
 * for this CPU and bind them all to the CPU.
 */
static squeue_set_t *
ip_squeue_set_create(cpu_t *cp, boolean_t reuse)
{
	int i;
	squeue_set_t	*sqs;
	squeue_t 	*sqp;
	char 		sqname[64];
	processorid_t 	id = cp->cpu_id;

	if (reuse) {
		int i;

		/*
		 * We may already have an squeue created for this CPU. Try to
		 * find one and reuse it if possible.
		 */
		for (i = 0; i < sqset_global_size; i++) {
			sqs = sqset_global_list[i];
			if (id == sqs->sqs_bind)
				return (sqs);
		}
	}

	sqs = kmem_zalloc(sizeof (squeue_set_t) +
	    (sizeof (squeue_t *) * MAX_SQUEUES_PER_CPU), KM_SLEEP);
	mutex_init(&sqs->sqs_lock, NULL, MUTEX_DEFAULT, NULL);
	sqs->sqs_list = (squeue_t **)&sqs[1];
	sqs->sqs_max_size = MAX_SQUEUES_PER_CPU;
	sqs->sqs_bind = id;

	for (i = 0; i < ip_squeues_per_cpu; i++) {
		bzero(sqname, sizeof (sqname));

		(void) snprintf(sqname, sizeof (sqname),
		    "ip_squeue_cpu_%d/%d/%d", cp->cpu_seqid,
		    cp->cpu_id, i);

		sqp = squeue_create(sqname, id, ip_squeue_worker_wait,
		    minclsyspri);

		/*
		 * The first squeue in each squeue_set is the DEFAULT
		 * squeue.
		 */
		sqp->sq_state |= SQS_DEFAULT;

		ASSERT(sqp != NULL);

		squeue_profile_enable(sqp);
		sqs->sqs_list[sqs->sqs_size++] = sqp;

		if (ip_squeue_create_callback != NULL)
			ip_squeue_create_callback(sqp);
	}

	if (ip_squeue_bind && cpu_is_online(cp))
		ip_squeue_set_bind(sqs);

	sqset_global_list[sqset_global_size++] = sqs;
	ASSERT(sqset_global_size <= NCPU);
	return (sqs);
}

/*
 * Initialize IP squeues.
 */
void
ip_squeue_init(void (*callback)(squeue_t *))
{
	int i;

	ASSERT(sqset_global_list == NULL);

	if (ip_squeues_per_cpu < MIN_SQUEUES_PER_CPU)
		ip_squeues_per_cpu = MIN_SQUEUES_PER_CPU;
	else if (ip_squeues_per_cpu > MAX_SQUEUES_PER_CPU)
		ip_squeues_per_cpu = MAX_SQUEUES_PER_CPU;

	ip_squeue_create_callback = callback;
	squeue_init();
	sqset_global_list =
	    kmem_zalloc(sizeof (squeue_set_t *) * NCPU, KM_SLEEP);
	sqset_global_size = 0;
	mutex_enter(&cpu_lock);

	/* Create squeue for each active CPU available */
	for (i = 0; i < NCPU; i++) {
		cpu_t *cp = cpu[i];
		if (CPU_ISON(cp) && cp->cpu_squeue_set == NULL) {
			cp->cpu_squeue_set = ip_squeue_set_create(cp, B_FALSE);
		}
	}

	register_cpu_setup_func(ip_squeue_cpu_setup, NULL);

	mutex_exit(&cpu_lock);

	if (ip_squeue_profile)
		squeue_profile_start();
}

/*
 * Get squeue_t structure based on index.
 * Since the squeue list can only grow, no need to grab any lock.
 */
squeue_t *
ip_squeue_random(uint_t index)
{
	squeue_set_t *sqs;

	sqs = sqset_global_list[index % sqset_global_size];
	return (sqs->sqs_list[index % sqs->sqs_size]);
}

/* ARGSUSED */
static void
ip_squeue_clean(void *arg1, mblk_t *mp, void *arg2)
{
	squeue_t	*sqp = arg2;
	ill_rx_ring_t	*ring = (ill_rx_ring_t *)mp->b_wptr;
	ill_t		*ill;

	ASSERT(sqp != NULL);
	mp->b_wptr = NULL;

	if (ring == NULL) {
		return;
	}

	/*
	 * Clean up squeue
	 */
	mutex_enter(&sqp->sq_lock);
	sqp->sq_state &= ~(SQS_ILL_BOUND|SQS_POLL_CAPAB);
	sqp->sq_rx_ring = NULL;
	mutex_exit(&sqp->sq_lock);

	ill = ring->rr_ill;
	if (ill->ill_capabilities & ILL_CAPAB_SOFT_RING) {
		ASSERT(ring->rr_handle != NULL);
		ill->ill_dls_capab->ill_dls_unbind(ring->rr_handle);
	}

	/*
	 * Cleanup the ring
	 */

	ring->rr_blank = NULL;
	ring->rr_handle = NULL;
	ring->rr_sqp = NULL;

	/*
	 * Signal ill that cleanup is done
	 */
	mutex_enter(&ill->ill_lock);
	ring->rr_ring_state = ILL_RING_FREE;
	cv_signal(&ill->ill_cv);
	mutex_exit(&ill->ill_lock);
}

/*
 * Clean up one squeue element. ill_inuse_ref is protected by ill_lock.
 * The real cleanup happens behind the squeue via ip_squeue_clean function but
 * we need to protect ourselves from 2 threads trying to cleanup at the same
 * time (possible with one port going down for aggr and someone tearing down the
 * entire aggr simultaneously). So we use ill_inuse_ref protected by ill_lock
 * to indicate when the cleanup has started (1 ref) and when the cleanup
 * is done (0 ref). When a new ring gets assigned to squeue, we start by
 * putting 2 ref on ill_inuse_ref.
 */
static void
ip_squeue_clean_ring(ill_t *ill, ill_rx_ring_t *rx_ring)
{
	conn_t *connp;
	squeue_t *sqp;
	mblk_t *mp;

	ASSERT(rx_ring != NULL);

	/* Just clean one squeue */
	mutex_enter(&ill->ill_lock);
	/*
	 * Reset the ILL_SOFT_RING_ASSIGN bit so that
	 * ip_squeue_soft_ring_affinty() will not go
	 * ahead with assigning rings.
	 */
	ill->ill_state_flags &= ~ILL_SOFT_RING_ASSIGN;
	while (rx_ring->rr_ring_state == ILL_RING_INPROC)
		/* Some operations pending on the ring. Wait */
		cv_wait(&ill->ill_cv, &ill->ill_lock);

	if (rx_ring->rr_ring_state != ILL_RING_INUSE) {
		/*
		 * Someone already trying to clean
		 * this squeue or it's already been cleaned.
		 */
		mutex_exit(&ill->ill_lock);
		return;
	}
	sqp = rx_ring->rr_sqp;

	if (sqp == NULL) {
		/*
		 * The rx_ring never had a squeue assigned to it.
		 * We are under ill_lock so we can clean it up
		 * here itself since no one can get to it.
		 */
		rx_ring->rr_blank = NULL;
		rx_ring->rr_handle = NULL;
		rx_ring->rr_sqp = NULL;
		rx_ring->rr_ring_state = ILL_RING_FREE;
		mutex_exit(&ill->ill_lock);
		return;
	}

	/* Indicate that it's being cleaned */
	rx_ring->rr_ring_state = ILL_RING_BEING_FREED;
	ASSERT(sqp != NULL);
	mutex_exit(&ill->ill_lock);

	/*
	 * Use the preallocated ill_unbind_conn for this purpose
	 */
	connp = ill->ill_dls_capab->ill_unbind_conn;

	if (connp->conn_tcp->tcp_closemp.b_prev == NULL) {
		connp->conn_tcp->tcp_closemp_used = B_TRUE;
	} else {
		cmn_err(CE_PANIC, "ip_squeue_clean_ring: "
		    "concurrent use of tcp_closemp_used: connp %p tcp %p\n",
		    (void *)connp, (void *)connp->conn_tcp);
	}

	TCP_DEBUG_GETPCSTACK(connp->conn_tcp->tcmp_stk, 15);
	mp = &connp->conn_tcp->tcp_closemp;
	CONN_INC_REF(connp);

	/*
	 * Since the field sq_rx_ring for default squeue is NULL,
	 * ip_squeue_clean() will have no way to get the ring if we
	 * don't pass the pointer to it. We use b_wptr to do so
	 * as use of b_wptr for any other purpose is not expected.
	 */

	ASSERT(mp->b_wptr == NULL);
	mp->b_wptr = (unsigned char *)rx_ring;
	squeue_enter(sqp, mp, ip_squeue_clean, connp, NULL);

	mutex_enter(&ill->ill_lock);
	while (rx_ring->rr_ring_state != ILL_RING_FREE)
		cv_wait(&ill->ill_cv, &ill->ill_lock);
	mutex_exit(&ill->ill_lock);
}

void
ip_squeue_clean_all(ill_t *ill)
{
	int idx;

	/*
	 * No need to clean if poll_capab isn't set for this ill
	 */
	if (!(ill->ill_capabilities & (ILL_CAPAB_POLL|ILL_CAPAB_SOFT_RING)))
		return;

	for (idx = 0; idx < ILL_MAX_RINGS; idx++) {
		ill_rx_ring_t *ipr = &ill->ill_dls_capab->ill_ring_tbl[idx];

		ip_squeue_clean_ring(ill, ipr);
	}

	ill->ill_capabilities &= ~(ILL_CAPAB_POLL|ILL_CAPAB_SOFT_RING);
}

typedef struct ip_taskq_arg {
	ill_t		*ip_taskq_ill;
	ill_rx_ring_t	*ip_taskq_ill_rx_ring;
	cpu_t		*ip_taskq_cpu;
} ip_taskq_arg_t;

/*
 * Do a Rx ring to squeue binding. Find a unique squeue that is not
 * managing a receive ring. If no such squeue exists, dynamically
 * create a new one in the squeue set.
 *
 * The function runs via the system taskq. The ill passed as an
 * argument can't go away since we hold a ref. The lock order is
 * ill_lock -> sqs_lock -> sq_lock.
 *
 * If we are binding a Rx ring to a squeue attached to the offline CPU,
 * no need to check that because squeues are never destroyed once
 * created.
 */
/* ARGSUSED */
static void
ip_squeue_extend(void *arg)
{
	ip_taskq_arg_t	*sq_arg = (ip_taskq_arg_t *)arg;
	ill_t		*ill = sq_arg->ip_taskq_ill;
	ill_rx_ring_t	*ill_rx_ring = sq_arg->ip_taskq_ill_rx_ring;
	cpu_t		*intr_cpu = sq_arg->ip_taskq_cpu;
	squeue_set_t 	*sqs;
	squeue_t 	*sqp = NULL;

	ASSERT(ill != NULL);
	ASSERT(ill_rx_ring != NULL);
	kmem_free(arg, sizeof (ip_taskq_arg_t));

	/*
	 * Make sure the CPU that originally took the interrupt still
	 * exists.
	 */
	if (!CPU_ISON(intr_cpu))
		intr_cpu = CPU;

	sqs = intr_cpu->cpu_squeue_set;

	/*
	 * If this ill represents link aggregation, then there might be
	 * multiple NICs trying to register them selves at the same time
	 * and in order to ensure that test and assignment of free rings
	 * is sequential, we need to hold the ill_lock.
	 */
	mutex_enter(&ill->ill_lock);
	sqp = ip_find_unused_squeue(sqs, B_FALSE);
	if (sqp == NULL) {
		/*
		 * We hit the max limit of squeues allowed per CPU.
		 * Assign this rx_ring to DEFAULT squeue of the
		 * interrupted CPU but the squeue will not manage
		 * the ring. Also print a warning.
		 */
		cmn_err(CE_NOTE, "ip_squeue_extend: CPU/sqset = %d/%p already "
		    "has max number of squeues. System performance might "
		    "become suboptimal\n", sqs->sqs_bind, (void *)sqs);

		/* the first squeue in the list is the default squeue */
		sqp = sqs->sqs_list[0];
		ASSERT(sqp != NULL);
		ill_rx_ring->rr_sqp = sqp;
		ill_rx_ring->rr_ring_state = ILL_RING_INUSE;

		mutex_exit(&ill->ill_lock);
		ill_waiter_dcr(ill);
		return;
	}

	ASSERT(MUTEX_HELD(&sqp->sq_lock));
	sqp->sq_rx_ring = ill_rx_ring;
	ill_rx_ring->rr_sqp = sqp;
	ill_rx_ring->rr_ring_state = ILL_RING_INUSE;

	sqp->sq_state |= (SQS_ILL_BOUND|SQS_POLL_CAPAB);
	mutex_exit(&sqp->sq_lock);

	mutex_exit(&ill->ill_lock);

	/* ill_waiter_dcr will also signal any waiters on ill_ring_state */
	ill_waiter_dcr(ill);
}

/*
 * Do a Rx ring to squeue binding. Find a unique squeue that is not
 * managing a receive ring. If no such squeue exists, dynamically
 * create a new one in the squeue set.
 *
 * The function runs via the system taskq. The ill passed as an
 * argument can't go away since we hold a ref. The lock order is
 * ill_lock -> sqs_lock -> sq_lock.
 *
 * If we are binding a Rx ring to a squeue attached to the offline CPU,
 * no need to check that because squeues are never destroyed once
 * created.
 */
/* ARGSUSED */
static void
ip_squeue_soft_ring_affinity(void *arg)
{
	ip_taskq_arg_t		*sq_arg = (ip_taskq_arg_t *)arg;
	ill_t			*ill = sq_arg->ip_taskq_ill;
	ill_dls_capab_t	*ill_soft_ring = ill->ill_dls_capab;
	ill_rx_ring_t		*ill_rx_ring = sq_arg->ip_taskq_ill_rx_ring;
	cpu_t			*intr_cpu = sq_arg->ip_taskq_cpu;
	cpu_t			*bind_cpu;
	int			cpu_id = intr_cpu->cpu_id;
	int			min_cpu_id, max_cpu_id;
	boolean_t		enough_uniq_cpus = B_FALSE;
	boolean_t		enough_cpus = B_FALSE;
	squeue_set_t 		*sqs, *last_sqs;
	squeue_t 		*sqp = NULL;
	int			i, j;

	ASSERT(ill != NULL);
	kmem_free(arg, sizeof (ip_taskq_arg_t));

	/*
	 * Make sure the CPU that originally took the interrupt still
	 * exists.
	 */
	if (!CPU_ISON(intr_cpu)) {
		intr_cpu = CPU;
		cpu_id = intr_cpu->cpu_id;
	}

	/*
	 * If this ill represents link aggregation, then there might be
	 * multiple NICs trying to register them selves at the same time
	 * and in order to ensure that test and assignment of free rings
	 * is sequential, we need to hold the ill_lock.
	 */
	mutex_enter(&ill->ill_lock);

	if (!(ill->ill_state_flags & ILL_SOFT_RING_ASSIGN)) {
		mutex_exit(&ill->ill_lock);
		return;
	}
	/*
	 * We need to fanout the interrupts from the NIC. We do that by
	 * telling the driver underneath to create soft rings and use
	 * worker threads (if the driver advertized SOFT_RING capability)
	 * Its still a big performance win to if we can fanout to the
	 * threads on the same core that is taking interrupts.
	 *
	 * Since we don't know the interrupt to CPU binding, we don't
	 * assign any squeues or affinity to worker threads in the NIC.
	 * At the time of the first interrupt, we know which CPU is
	 * taking interrupts and try to find other threads on the same
	 * core. Assuming, ip_threads_per_cpu is correct and cpus are
	 * numbered sequentially for each core (XXX need something better
	 * than this in future), find the lowest number and highest
	 * number thread for that core.
	 *
	 * If we have one more thread per core than number of soft rings,
	 * then don't assign any worker threads to the H/W thread (cpu)
	 * taking interrupts (capability negotiation tries to ensure this)
	 *
	 * If the number of threads per core are same as the number of
	 * soft rings, then assign the worker affinity and squeue to
	 * the same cpu.
	 *
	 * Otherwise, just fanout to higher number CPUs starting from
	 * the interrupted CPU.
	 */

	min_cpu_id = (cpu_id / ip_threads_per_cpu) * ip_threads_per_cpu;
	max_cpu_id = min_cpu_id + ip_threads_per_cpu;

	/*
	 * Quickly check if there are enough CPUs present for fanout
	 * and also max_cpu_id is less than the id of the active CPU.
	 * We use the cpu_id stored in the last squeue_set to get
	 * an idea. The scheme is by no means perfect since it doesn't
	 * take into account CPU DR operations and the fact that
	 * interrupts themselves might change. An ideal scenario
	 * would be to ensure that interrupts run cpus by themselves
	 * and worker threads never have affinity to those CPUs. If
	 * the interrupts move to CPU which had a worker thread, it
	 * should be changed. Probably callbacks similar to CPU offline
	 * are needed to make it work perfectly.
	 */
	last_sqs = sqset_global_list[sqset_global_size - 1];
	if (ip_threads_per_cpu <= ncpus && max_cpu_id <= last_sqs->sqs_bind) {
		if ((max_cpu_id - min_cpu_id) >
		    ill_soft_ring->ill_dls_soft_ring_cnt)
			enough_uniq_cpus = B_TRUE;
		else if ((max_cpu_id - min_cpu_id) >=
		    ill_soft_ring->ill_dls_soft_ring_cnt)
			enough_cpus = B_TRUE;
	}

	j = 0;
	for (i = 0; i < (ill_soft_ring->ill_dls_soft_ring_cnt + j); i++) {
		if (enough_uniq_cpus) {
			if ((min_cpu_id + i) == cpu_id) {
				j++;
				continue;
			}
			bind_cpu = cpu[min_cpu_id + i];
		} else if (enough_cpus) {
			bind_cpu = cpu[min_cpu_id + i];
		} else {
			/* bind_cpu = cpu[(cpu_id + i) % last_sqs->sqs_bind]; */
			bind_cpu = cpu[(cpu_id + i) % ncpus];
		}

		/*
		 * Check if the CPU actually exist and active. If not,
		 * use the interrupted CPU. ip_find_unused_squeue() will
		 * find the right CPU to fanout anyway.
		 */
		if (!CPU_ISON(bind_cpu))
			bind_cpu = intr_cpu;

		sqs = bind_cpu->cpu_squeue_set;
		ASSERT(sqs != NULL);
		ill_rx_ring = &ill_soft_ring->ill_ring_tbl[i - j];

		sqp = ip_find_unused_squeue(sqs, B_TRUE);
		if (sqp == NULL) {
			/*
			 * We hit the max limit of squeues allowed per CPU.
			 * Assign this rx_ring to DEFAULT squeue of the
			 * interrupted CPU but thesqueue will not manage
			 * the ring. Also print a warning.
			 */
			cmn_err(CE_NOTE, "ip_squeue_soft_ring: CPU/sqset = "
			    "%d/%p already has max number of squeues. System "
			    "performance might become suboptimal\n",
			    sqs->sqs_bind, (void *)sqs);

			/* the first squeue in the list is the default squeue */
			sqp = intr_cpu->cpu_squeue_set->sqs_list[0];
			ASSERT(sqp != NULL);

			ill_rx_ring->rr_sqp = sqp;
			ill_rx_ring->rr_ring_state = ILL_RING_INUSE;
			continue;

		}
		ASSERT(MUTEX_HELD(&sqp->sq_lock));
		ill_rx_ring->rr_sqp = sqp;
		sqp->sq_rx_ring = ill_rx_ring;
		ill_rx_ring->rr_ring_state = ILL_RING_INUSE;
		sqp->sq_state |= SQS_ILL_BOUND;

		/* assign affinity to soft ring */
		if (ip_squeue_bind && (sqp->sq_state & SQS_BOUND)) {
			ill_soft_ring->ill_dls_bind(ill_rx_ring->rr_handle,
			    sqp->sq_bind);
		}
		mutex_exit(&sqp->sq_lock);
	}
	mutex_exit(&ill->ill_lock);

	ill_soft_ring->ill_dls_change_status(ill_soft_ring->ill_tx_handle,
	    SOFT_RING_FANOUT);

	mutex_enter(&ill->ill_lock);
	ill->ill_state_flags &= ~ILL_SOFT_RING_ASSIGN;
	mutex_exit(&ill->ill_lock);

	/* ill_waiter_dcr will also signal any waiters on ill_ring_state */
	ill_waiter_dcr(ill);
}

/* ARGSUSED */
void
ip_soft_ring_assignment(ill_t *ill, ill_rx_ring_t *ip_ring,
    mblk_t *mp_chain, struct mac_header_info_s *mhip)
{
	ip_taskq_arg_t	*taskq_arg;
	boolean_t	refheld;

	mutex_enter(&ill->ill_lock);
	if (!(ill->ill_state_flags & ILL_SOFT_RING_ASSIGN)) {
		taskq_arg = (ip_taskq_arg_t *)
		    kmem_zalloc(sizeof (ip_taskq_arg_t), KM_NOSLEEP);

		if (taskq_arg == NULL)
			goto out;

		taskq_arg->ip_taskq_ill = ill;
		taskq_arg->ip_taskq_ill_rx_ring = NULL;
		taskq_arg->ip_taskq_cpu = CPU;

		/*
		 * Set ILL_SOFT_RING_ASSIGN flag. We don't want
		 * the next interrupt to schedule a task for calling
		 * ip_squeue_soft_ring_affinity();
		 */
		ill->ill_state_flags |= ILL_SOFT_RING_ASSIGN;
	} else {
		mutex_exit(&ill->ill_lock);
		goto out;
	}
	mutex_exit(&ill->ill_lock);
	refheld = ill_waiter_inc(ill);
	if (refheld) {
		if (taskq_dispatch(system_taskq,
		    ip_squeue_soft_ring_affinity, taskq_arg, TQ_NOSLEEP))
			goto out;

		/* release ref on ill if taskq dispatch fails */
		ill_waiter_dcr(ill);
	}
	/*
	 * Turn on CAPAB_SOFT_RING so that affinity assignment
	 * can be tried again later.
	 */
	mutex_enter(&ill->ill_lock);
	ill->ill_state_flags &= ~ILL_SOFT_RING_ASSIGN;
	mutex_exit(&ill->ill_lock);
	kmem_free(taskq_arg, sizeof (ip_taskq_arg_t));

out:
	ip_input(ill, NULL, mp_chain, mhip);
}

static squeue_t *
ip_find_unused_squeue(squeue_set_t *sqs, boolean_t fanout)
{
	int 		i;
	squeue_set_t	*best_sqs = NULL;
	squeue_set_t	*curr_sqs = NULL;
	int		min_sq = 0;
	squeue_t 	*sqp = NULL;
	char		sqname[64];
	cpu_t		*bind_cpu;

	/*
	 * If fanout is set and the passed squeue_set already has some
	 * squeues which are managing the NICs, try to find squeues on
	 * unused CPU.
	 */
	if (sqs->sqs_size > 1 && fanout) {
		/*
		 * First check to see if any squeue on the CPU passed
		 * is managing a NIC.
		 */
		mutex_enter(&sqs->sqs_lock);
		for (i = 0; i < sqs->sqs_size; i++) {
			mutex_enter(&sqs->sqs_list[i]->sq_lock);
			if ((sqs->sqs_list[i]->sq_state & SQS_ILL_BOUND) &&
			    !(sqs->sqs_list[i]->sq_state & SQS_DEFAULT)) {
				mutex_exit(&sqs->sqs_list[i]->sq_lock);
				break;
			}
			mutex_exit(&sqs->sqs_list[i]->sq_lock);
		}
		mutex_exit(&sqs->sqs_lock);
		if (i != sqs->sqs_size) {
			best_sqs = NULL;

			for (i = sqset_global_size - 1; i >= 0; i--) {
				curr_sqs = sqset_global_list[i];
				/*
				 * Check and make sure the CPU that sqs
				 * is bound to is valid. There could be
				 * sqs's around whose CPUs could have
				 * been DR'd out.
				 */
				mutex_enter(&cpu_lock);
				if (cpu_get(curr_sqs->sqs_bind) != NULL) {
					if (best_sqs == NULL) {
						best_sqs = curr_sqs;
						min_sq = curr_sqs->sqs_size;
					} else if (curr_sqs->sqs_size <
					    min_sq) {
						best_sqs = curr_sqs;
						min_sq = curr_sqs->sqs_size;
					}
				}
				mutex_exit(&cpu_lock);
			}

			ASSERT(best_sqs != NULL);
			sqs = best_sqs;
		}
	}

	mutex_enter(&sqs->sqs_lock);

	for (i = 0; i < sqs->sqs_size; i++) {
		mutex_enter(&sqs->sqs_list[i]->sq_lock);
		if ((sqs->sqs_list[i]->sq_state &
		    (SQS_DEFAULT|SQS_ILL_BOUND)) == 0) {
			sqp = sqs->sqs_list[i];
			break;
		}
		mutex_exit(&sqs->sqs_list[i]->sq_lock);
	}

	if (sqp == NULL) {
		/* Need to create a new squeue */
		if (sqs->sqs_size == sqs->sqs_max_size) {
			/*
			 * Reached the max limit for squeue
			 * we can allocate on this CPU.
			 */
			mutex_exit(&sqs->sqs_lock);
			return (NULL);
		}

		mutex_enter(&cpu_lock);
		if ((bind_cpu = cpu_get(sqs->sqs_bind)) == NULL) {
			/* Too bad, CPU got DR'd out, return NULL */
			mutex_exit(&cpu_lock);
			mutex_exit(&sqs->sqs_lock);
			return (NULL);
		}

		bzero(sqname, sizeof (sqname));
		(void) snprintf(sqname, sizeof (sqname),
		    "ip_squeue_cpu_%d/%d/%d", bind_cpu->cpu_seqid,
		    bind_cpu->cpu_id, sqs->sqs_size);
		mutex_exit(&cpu_lock);

		sqp = squeue_create(sqname, sqs->sqs_bind,
		    ip_squeue_worker_wait, minclsyspri);

		ASSERT(sqp != NULL);

		squeue_profile_enable(sqp);
		/*
		 * Other functions scanning sqs_list don't take sqs_lock.
		 * Once sqp is stored in sqs_list[] global visibility is
		 * ensured before incrementing the sqs_size counter.
		 */
		sqs->sqs_list[sqs->sqs_size] = sqp;
		membar_producer();
		sqs->sqs_size++;

		if (ip_squeue_create_callback != NULL)
			ip_squeue_create_callback(sqp);

		if (ip_squeue_bind) {
			mutex_enter(&cpu_lock);
			bind_cpu = cpu_get(sqs->sqs_bind);
			if (bind_cpu != NULL && cpu_is_online(bind_cpu)) {
				squeue_bind(sqp, -1);
			}
			mutex_exit(&cpu_lock);
		}
		mutex_enter(&sqp->sq_lock);
	}

	mutex_exit(&sqs->sqs_lock);
	ASSERT(sqp != NULL);
	return (sqp);
}

/*
 * Find the squeue assigned to manage this Rx ring. If the Rx ring is not
 * owned by a squeue yet, do the assignment. When the NIC registers it
 * Rx rings with IP, we don't know where the interrupts will land and
 * hence we need to wait till this point to do the assignment.
 */
squeue_t *
ip_squeue_get(ill_rx_ring_t *ill_rx_ring)
{
	squeue_t 	*sqp;
	ill_t 		*ill;
	int		interrupt;
	ip_taskq_arg_t	*taskq_arg;
	boolean_t	refheld;

	if (ill_rx_ring == NULL)
		return (IP_SQUEUE_GET(lbolt));

	sqp = ill_rx_ring->rr_sqp;
	/*
	 * Do a quick check. If it's not NULL, we are done.
	 * Squeues are never destroyed so worse we will bind
	 * this connection to a suboptimal squeue.
	 *
	 * This is the fast path case.
	 */
	if (sqp != NULL)
		return (sqp);

	ill = ill_rx_ring->rr_ill;
	ASSERT(ill != NULL);

	interrupt = servicing_interrupt();
	taskq_arg = (ip_taskq_arg_t *)kmem_zalloc(sizeof (ip_taskq_arg_t),
	    KM_NOSLEEP);

	mutex_enter(&ill->ill_lock);
	/*
	 * Check sqp under the lock again for atomicity. Possible race with
	 * a previously scheduled ip_squeue_get -> ip_squeue_extend.
	 * Do the ring to squeue binding only if we are in interrupt context
	 * AND the ring is not already bound AND there is no one else trying
	 * the bind already.
	 */
	sqp = ill_rx_ring->rr_sqp;
	if (sqp != NULL || !interrupt ||
	    ill_rx_ring->rr_ring_state != ILL_RING_INUSE || taskq_arg == NULL) {
		/*
		 * Note that the ring might get bound once we drop the lock
		 * below, if a previous request is in progress i.e. if the ring
		 * state is ILL_RING_INPROC. The incoming connection on whose
		 * behalf we are currently here might get a suboptimal squeue
		 * via the call to IP_SQUEUE_GET below, but there is no
		 * correctness issue.
		 */
		mutex_exit(&ill->ill_lock);
		if (taskq_arg != NULL)
			kmem_free(taskq_arg, sizeof (ip_taskq_arg_t));
		if (sqp != NULL)
			return (sqp);
		return (IP_SQUEUE_GET(lbolt));
	}

	/*
	 * No sqp assigned yet. Can't really do that in interrupt
	 * context. Assign the default sqp to this connection and
	 * trigger creation of new sqp and binding it to this ring
	 * via taskq. Need to make sure ill stays around.
	 */
	taskq_arg->ip_taskq_ill = ill;
	taskq_arg->ip_taskq_ill_rx_ring = ill_rx_ring;
	taskq_arg->ip_taskq_cpu = CPU;
	ill_rx_ring->rr_ring_state = ILL_RING_INPROC;
	mutex_exit(&ill->ill_lock);
	refheld = ill_waiter_inc(ill);
	if (refheld) {
		if (taskq_dispatch(system_taskq, ip_squeue_extend,
		    taskq_arg, TQ_NOSLEEP) != NULL) {
			return (IP_SQUEUE_GET(lbolt));
		}
	}
	/*
	 * The ill is closing and we could not get a reference on the ill OR
	 * taskq_dispatch failed probably due to memory allocation failure.
	 * We will try again next time.
	 */
	mutex_enter(&ill->ill_lock);
	ill_rx_ring->rr_ring_state = ILL_RING_INUSE;
	mutex_exit(&ill->ill_lock);
	kmem_free(taskq_arg, sizeof (ip_taskq_arg_t));
	if (refheld)
		ill_waiter_dcr(ill);

	return (IP_SQUEUE_GET(lbolt));
}

/*
 * NDD hooks for setting ip_squeue_xxx tuneables.
 */

/* ARGSUSED */
int
ip_squeue_bind_set(queue_t *q, mblk_t *mp, char *value,
    caddr_t addr, cred_t *cr)
{
	int *bind_enabled = (int *)addr;
	long new_value;
	int i;

	if (ddi_strtol(value, NULL, 10, &new_value) != 0)
		return (EINVAL);

	if (ip_squeue_bind == new_value)
		return (0);

	*bind_enabled = new_value;
	mutex_enter(&cpu_lock);
	if (new_value == 0) {
		for (i = 0; i < sqset_global_size; i++)
			ip_squeue_set_unbind(sqset_global_list[i]);
	} else {
		for (i = 0; i < sqset_global_size; i++)
			ip_squeue_set_bind(sqset_global_list[i]);
	}

	mutex_exit(&cpu_lock);
	return (0);
}

/*
 * Set squeue profiling.
 * 0 means "disable"
 * 1 means "enable"
 * 2 means "enable and reset"
 */
/* ARGSUSED */
int
ip_squeue_profile_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	int *profile_enabled = (int *)cp;
	long new_value;
	squeue_set_t *sqs;

	if (ddi_strtol(value, NULL, 10, &new_value) != 0)
		return (EINVAL);

	if (new_value == 0)
		squeue_profile_stop();
	else if (new_value == 1)
		squeue_profile_start();
	else if (new_value == 2) {
		int i, j;

		squeue_profile_stop();
		mutex_enter(&cpu_lock);
		for (i = 0; i < sqset_global_size; i++) {
			sqs = sqset_global_list[i];
			for (j = 0; j < sqs->sqs_size; j++) {
				squeue_profile_reset(sqs->sqs_list[j]);
			}
		}
		mutex_exit(&cpu_lock);

		new_value = 1;
		squeue_profile_start();
	}
	*profile_enabled = new_value;

	return (0);
}

/*
 * Reconfiguration callback
 */

/* ARGSUSED */
static int
ip_squeue_cpu_setup(cpu_setup_t what, int id, void *arg)
{
	cpu_t *cp = cpu[id];

	ASSERT(MUTEX_HELD(&cpu_lock));
	switch (what) {
	case CPU_CONFIG:
		/*
		 * A new CPU is added. Create an squeue for it but do not bind
		 * it yet.
		 */
		if (cp->cpu_squeue_set == NULL)
			cp->cpu_squeue_set = ip_squeue_set_create(cp, B_TRUE);
		break;
	case CPU_ON:
	case CPU_INIT:
	case CPU_CPUPART_IN:
		if (cp->cpu_squeue_set == NULL) {
			cp->cpu_squeue_set = ip_squeue_set_create(cp, B_TRUE);
		}
		if (ip_squeue_bind)
			ip_squeue_set_bind(cp->cpu_squeue_set);
		break;
	case CPU_UNCONFIG:
	case CPU_OFF:
	case CPU_CPUPART_OUT:
		ASSERT((cp->cpu_squeue_set != NULL) ||
		    (cp->cpu_flags & CPU_OFFLINE));

		if (cp->cpu_squeue_set != NULL) {
			ip_squeue_set_unbind(cp->cpu_squeue_set);
		}
		break;
	default:
		break;
	}
	return (0);
}

/* ARGSUSED */
static void
ip_squeue_set_bind(squeue_set_t *sqs)
{
	int i;
	squeue_t *sqp;

	if (!ip_squeue_bind)
		return;

	mutex_enter(&sqs->sqs_lock);
	for (i = 0; i < sqs->sqs_size; i++) {
		sqp = sqs->sqs_list[i];
		if (sqp->sq_state & SQS_BOUND)
			continue;
		squeue_bind(sqp, -1);
	}
	mutex_exit(&sqs->sqs_lock);
}

static void
ip_squeue_set_unbind(squeue_set_t *sqs)
{
	int i;
	squeue_t *sqp;

	mutex_enter(&sqs->sqs_lock);
	for (i = 0; i < sqs->sqs_size; i++) {
		sqp = sqs->sqs_list[i];

		/*
		 * CPU is going offline. Remove the thread affinity
		 * for any soft ring threads the squeue is managing.
		 */
		if (sqp->sq_state & SQS_ILL_BOUND) {
			ill_rx_ring_t	*ring = sqp->sq_rx_ring;
			ill_t		*ill = ring->rr_ill;

			if (ill->ill_capabilities & ILL_CAPAB_SOFT_RING) {
				ASSERT(ring->rr_handle != NULL);
				ill->ill_dls_capab->ill_dls_unbind(
				    ring->rr_handle);
			}
		}
		if (!(sqp->sq_state & SQS_BOUND))
			continue;
		squeue_unbind(sqp);
	}
	mutex_exit(&sqs->sqs_lock);
}
