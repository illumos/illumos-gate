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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Squeues - TCP/IP serialization mechanism.
 *
 * This is a general purpose high-performance serialization mechanism. It is
 * similar to a taskq with a single worker thread, the difference is that it
 * does not imply a context switch - the thread placing a request may actually
 * process it. It is also biased for processing requests in interrupt context.
 *
 * Each squeue has a worker thread which may optionally be bound to a CPU.
 *
 * Only one thread may process requests from a given squeue at any time. This is
 * called "entering" squeue.
 *
 * Each dispatched request is processed either by
 *
 *	a) Dispatching thread or
 *	b) Some other thread that is currently processing squeue at the time of
 *		request or
 *	c) worker thread.
 *
 * INTERFACES:
 *
 * squeue_t *squeue_create(name, bind, wait, pri)
 *
 *	name: symbolic name for squeue.
 *	wait: time to wait before waiking the worker thread after queueing
 *		request.
 *	bind: preferred CPU binding for the worker thread.
 *	pri:  thread priority for the worker thread.
 *
 *   This function never fails and may sleep. It returns a transparent pointer
 *   to the squeue_t structure that is passed to all other squeue operations.
 *
 * void squeue_bind(sqp, bind)
 *
 *   Bind squeue worker thread to a CPU specified by the 'bind' argument. The
 *   'bind' value of -1 binds to the preferred thread specified for
 *   squeue_create.
 *
 *   NOTE: Any value of 'bind' other then -1 is not supported currently, but the
 *	 API is present - in the future it may be useful to specify different
 *	 binding.
 *
 * void squeue_unbind(sqp)
 *
 *   Unbind the worker thread from its preferred CPU.
 *
 * void squeue_enter(*sqp, *mp, proc, arg, tag)
 *
 *   Post a single request for processing. Each request consists of mblock 'mp',
 *   function 'proc' to execute and an argument 'arg' to pass to this
 *   function. The function is called as (*proc)(arg, mp, sqp); The tag is an
 *   arbitrary number from 0 to 255 which will be stored in mp to track exact
 *   caller of squeue_enter. The combination of function name and the tag should
 *   provide enough information to identify the caller.
 *
 *   If no one is processing the squeue, squeue_enter() will call the function
 *   immediately. Otherwise it will add the request to the queue for later
 *   processing. Once the function is executed, the thread may continue
 *   executing all other requests pending on the queue.
 *
 *   NOTE: The tagging information is only used when SQUEUE_DEBUG is set to 1.
 *   NOTE: The argument can be conn_t only. Ideally we'd like to have generic
 *	   argument, but we want to drop connection reference count here - this
 *	   improves tail-call optimizations.
 *	   XXX: The arg should have type conn_t.
 *
 * void squeue_enter_nodrain(*sqp, *mp, proc, arg, tag)
 *
 *   Same as squeue_enter(), but the entering thread will only try to execute a
 *   single request. It will not continue executing any pending requests.
 *
 * void squeue_fill(*sqp, *mp, proc, arg, tag)
 *
 *   Just place the request on the queue without trying to execute it. Arrange
 *   for the worker thread to process the request.
 *
 * void squeue_profile_enable(sqp)
 * void squeue_profile_disable(sqp)
 *
 *    Enable or disable profiling for specified 'sqp'. Profiling is only
 *    available when SQUEUE_PROFILE is set.
 *
 * void squeue_profile_reset(sqp)
 *
 *    Reset all profiling information to zero. Profiling is only
 *    available when SQUEUE_PROFILE is set.
 *
 * void squeue_profile_start()
 * void squeue_profile_stop()
 *
 *    Globally enable or disabled profiling for all squeues.
 *
 * uintptr_t *squeue_getprivate(sqp, p)
 *
 *    Each squeue keeps small amount of private data space available for various
 *    consumers. Current consumers include TCP and NCA. Other consumers need to
 *    add their private tag to the sqprivate_t enum. The private information is
 *    limited to an uintptr_t value. The squeue has no knowledge of its content
 *    and does not manage it in any way.
 *
 *    The typical use may be a breakdown of data structures per CPU (since
 *    squeues are usually per CPU). See NCA for examples of use.
 *    Currently 'p' may have one legal value SQPRIVATE_TCP.
 *
 * processorid_t squeue_binding(sqp)
 *
 *    Returns the CPU binding for a given squeue.
 *
 * TUNABALES:
 *
 * squeue_intrdrain_ms: Maximum time in ms interrupts spend draining any
 *	squeue. Note that this is approximation - squeues have no control on the
 *	time it takes to process each request. This limit is only checked
 *	between processing individual messages.
 *    Default: 20 ms.
 *
 * squeue_writerdrain_ms: Maximum time in ms non-interrupts spend draining any
 *	squeue. Note that this is approximation - squeues have no control on the
 *	time it takes to process each request. This limit is only checked
 *	between processing individual messages.
 *    Default: 10 ms.
 *
 * squeue_workerdrain_ms: Maximum time in ms worker thread spends draining any
 *	squeue. Note that this is approximation - squeues have no control on the
 *	time it takes to process each request. This limit is only checked
 *	between processing individual messages.
 *    Default: 10 ms.
 *
 * squeue_workerwait_ms: When worker thread is interrupted because workerdrain
 *	expired, how much time to wait before waking worker thread again.
 *    Default: 10 ms.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/condvar_impl.h>
#include <sys/systm.h>
#include <sys/callb.h>
#include <sys/sdt.h>
#include <sys/ddi.h>

#include <inet/ipclassifier.h>
#include <inet/udp_impl.h>

/*
 * State flags.
 * Note: The MDB IP module depends on the values of these flags.
 */
#define	SQS_PROC	0x0001	/* being processed */
#define	SQS_WORKER	0x0002	/* worker thread */
#define	SQS_ENTER	0x0004	/* enter thread */
#define	SQS_FAST	0x0008	/* enter-fast thread */
#define	SQS_USER	0x0010	/* A non interrupt user */
#define	SQS_BOUND	0x0020	/* Worker thread is bound */
#define	SQS_PROFILE	0x0040	/* Enable profiling */
#define	SQS_REENTER	0x0080	/* Re entered thread */
#define	SQS_TMO_PROG	0x0100	/* Timeout is being set */

#include <sys/squeue_impl.h>

static void squeue_fire(void *);
static void squeue_drain(squeue_t *, uint_t, hrtime_t);
static void squeue_worker(squeue_t *sqp);

#if SQUEUE_PROFILE
static kmutex_t squeue_kstat_lock;
static int  squeue_kstat_update(kstat_t *, int);
#endif

kmem_cache_t *squeue_cache;

#define	SQUEUE_MSEC_TO_NSEC 1000000

int squeue_intrdrain_ms = 20;
int squeue_writerdrain_ms = 10;
int squeue_workerdrain_ms = 10;
int squeue_workerwait_ms = 10;

/* The values above converted to ticks or nano seconds */
static int squeue_intrdrain_ns = 0;
static int squeue_writerdrain_ns = 0;
static int squeue_workerdrain_ns = 0;
static int squeue_workerwait_tick = 0;

/*
 * The minimum packet queued when worker thread doing the drain triggers
 * polling (if squeue allows it). The choice of 3 is arbitrary. You
 * definitely don't want it to be 1 since that will trigger polling
 * on very low loads as well (ssh seems to do be one such example
 * where packet flow was very low yet somehow 1 packet ended up getting
 * queued and worker thread fires every 10ms and blanking also gets
 * triggered.
 */
int squeue_worker_poll_min = 3;

#if SQUEUE_PROFILE
/*
 * Set to B_TRUE to enable profiling.
 */
static int squeue_profile = B_FALSE;
#define	SQ_PROFILING(sqp) (squeue_profile && ((sqp)->sq_state & SQS_PROFILE))

#define	SQSTAT(sqp, x) ((sqp)->sq_stats.x++)
#define	SQDELTA(sqp, x, d) ((sqp)->sq_stats.x += (d))

struct squeue_kstat {
	kstat_named_t	sq_count;
	kstat_named_t	sq_max_qlen;
	kstat_named_t	sq_npackets_worker;
	kstat_named_t	sq_npackets_intr;
	kstat_named_t	sq_npackets_other;
	kstat_named_t	sq_nqueued_intr;
	kstat_named_t	sq_nqueued_other;
	kstat_named_t	sq_ndrains_worker;
	kstat_named_t	sq_ndrains_intr;
	kstat_named_t	sq_ndrains_other;
	kstat_named_t	sq_time_worker;
	kstat_named_t	sq_time_intr;
	kstat_named_t	sq_time_other;
} squeue_kstat = {
	{ "count",		KSTAT_DATA_UINT64 },
	{ "max_qlen",		KSTAT_DATA_UINT64 },
	{ "packets_worker",	KSTAT_DATA_UINT64 },
	{ "packets_intr",	KSTAT_DATA_UINT64 },
	{ "packets_other",	KSTAT_DATA_UINT64 },
	{ "queued_intr",	KSTAT_DATA_UINT64 },
	{ "queued_other",	KSTAT_DATA_UINT64 },
	{ "ndrains_worker",	KSTAT_DATA_UINT64 },
	{ "ndrains_intr",	KSTAT_DATA_UINT64 },
	{ "ndrains_other",	KSTAT_DATA_UINT64 },
	{ "time_worker",	KSTAT_DATA_UINT64 },
	{ "time_intr",		KSTAT_DATA_UINT64 },
	{ "time_other",		KSTAT_DATA_UINT64 },
};
#endif

#define	SQUEUE_WORKER_WAKEUP(sqp) {					\
	timeout_id_t tid = (sqp)->sq_tid;				\
									\
	ASSERT(MUTEX_HELD(&(sqp)->sq_lock));				\
	/*								\
	 * Queue isn't being processed, so take				\
	 * any post enqueue actions needed before leaving.		\
	 */								\
	if (tid != 0) {							\
		/*							\
		 * Waiting for an enter() to process mblk(s).		\
		 */							\
		clock_t	waited = lbolt - (sqp)->sq_awaken;		\
									\
		if (TICK_TO_MSEC(waited) >= (sqp)->sq_wait) {		\
			/*						\
			 * Times up and have a worker thread		\
			 * waiting for work, so schedule it.		\
			 */						\
			(sqp)->sq_tid = 0;				\
			(sqp)->sq_awaken = lbolt;			\
			cv_signal(&(sqp)->sq_async);			\
			mutex_exit(&(sqp)->sq_lock);			\
			(void) untimeout(tid);				\
			return;						\
		}							\
		mutex_exit(&(sqp)->sq_lock);				\
		return;							\
	} else if ((sqp)->sq_state & SQS_TMO_PROG) {			\
		mutex_exit(&(sqp)->sq_lock);				\
		return;							\
	} else if ((sqp)->sq_wait != 0) {				\
		clock_t	wait = (sqp)->sq_wait;				\
		/*							\
		 * Wait up to sqp->sq_wait ms for an			\
		 * enter() to process this queue. We			\
		 * don't want to contend on timeout locks		\
		 * with sq_lock held for performance reasons,		\
		 * so drop the sq_lock before calling timeout		\
		 * but we need to check if timeout is required		\
		 * after re acquiring the sq_lock. Once			\
		 * the sq_lock is dropped, someone else could		\
		 * have processed the packet or the timeout could	\
		 * have already fired.					\
		 */							\
		(sqp)->sq_state |= SQS_TMO_PROG;			\
		mutex_exit(&(sqp)->sq_lock);				\
		tid = timeout(squeue_fire, (sqp), wait);		\
		mutex_enter(&(sqp)->sq_lock);				\
		/* Check again if we still need the timeout */		\
		if ((((sqp)->sq_state & (SQS_PROC|SQS_TMO_PROG)) ==	\
			SQS_TMO_PROG) && ((sqp)->sq_tid == 0) &&	\
			((sqp)->sq_first != NULL)) {			\
				(sqp)->sq_state &= ~SQS_TMO_PROG;	\
				(sqp)->sq_awaken = lbolt;		\
				(sqp)->sq_tid = tid;			\
				mutex_exit(&(sqp)->sq_lock);		\
				return;					\
		} else {						\
			if ((sqp)->sq_state & SQS_TMO_PROG) {		\
				(sqp)->sq_state &= ~SQS_TMO_PROG;	\
				mutex_exit(&(sqp)->sq_lock);		\
				(void) untimeout(tid);			\
			} else {					\
				/*					\
				 * The timer fired before we could 	\
				 * reacquire the sq_lock. squeue_fire	\
				 * removes the SQS_TMO_PROG flag	\
				 * and we don't need to	do anything	\
				 * else.				\
				 */					\
				mutex_exit(&(sqp)->sq_lock);		\
			}						\
		}							\
	} else {							\
		/*							\
		 * Schedule the worker thread.				\
		 */							\
		(sqp)->sq_awaken = lbolt;				\
		cv_signal(&(sqp)->sq_async);				\
		mutex_exit(&(sqp)->sq_lock);				\
	}								\
	ASSERT(MUTEX_NOT_HELD(&(sqp)->sq_lock)); 			\
}

#define	ENQUEUE_MP(sqp, mp, proc, arg) {			\
	/*							\
	 * Enque our mblk.					\
	 */							\
	(mp)->b_queue = NULL;					\
	ASSERT(MUTEX_HELD(&(sqp)->sq_lock));			\
	ASSERT((mp)->b_prev == NULL && (mp)->b_next == NULL); 	\
	(mp)->b_queue = (queue_t *)(proc);			\
	(mp)->b_prev = (mblk_t *)(arg);				\
								\
	if ((sqp)->sq_last != NULL)				\
		(sqp)->sq_last->b_next = (mp);			\
	else							\
		(sqp)->sq_first = (mp);				\
	(sqp)->sq_last = (mp);					\
	(sqp)->sq_count++;					\
	ASSERT((sqp)->sq_count > 0);				\
	DTRACE_PROBE2(squeue__enqueue, squeue_t *, sqp,		\
	    mblk_t *, mp);					\
}


#define	ENQUEUE_CHAIN(sqp, mp, tail, cnt) {			\
	/*							\
	 * Enqueue our mblk chain.				\
	 */							\
	ASSERT(MUTEX_HELD(&(sqp)->sq_lock));			\
								\
	if ((sqp)->sq_last != NULL)				\
		(sqp)->sq_last->b_next = (mp);			\
	else							\
		(sqp)->sq_first = (mp);				\
	(sqp)->sq_last = (tail);				\
	(sqp)->sq_count += (cnt);				\
	ASSERT((sqp)->sq_count > 0);				\
	DTRACE_PROBE4(squeue__enqueuechain, squeue_t *, sqp,	\
		mblk_t *, mp, mblk_t *, tail, int, cnt);	\
								\
}

#define	SQS_POLLING_ON(sqp, rx_ring) {				\
	ASSERT(rx_ring != NULL);				\
	ASSERT(MUTEX_HELD(&(sqp)->sq_lock));			\
	rx_ring->rr_blank(rx_ring->rr_handle,			\
	    MIN((sqp->sq_avg_drain_time * sqp->sq_count),	\
		rx_ring->rr_max_blank_time),			\
		rx_ring->rr_max_pkt_cnt);			\
	rx_ring->rr_poll_state |= ILL_POLLING;			\
	rx_ring->rr_poll_time = lbolt;				\
}


#define	SQS_POLLING_OFF(sqp, rx_ring) {				\
	ASSERT(rx_ring != NULL);				\
	ASSERT(MUTEX_HELD(&(sqp)->sq_lock));			\
	rx_ring->rr_blank(rx_ring->rr_handle,			\
	    rx_ring->rr_min_blank_time,				\
	    rx_ring->rr_min_pkt_cnt);				\
}

void
squeue_init(void)
{
	squeue_cache = kmem_cache_create("squeue_cache",
	    sizeof (squeue_t), 64, NULL, NULL, NULL, NULL, NULL, 0);

	squeue_intrdrain_ns = squeue_intrdrain_ms * SQUEUE_MSEC_TO_NSEC;
	squeue_writerdrain_ns = squeue_writerdrain_ms * SQUEUE_MSEC_TO_NSEC;
	squeue_workerdrain_ns = squeue_workerdrain_ms * SQUEUE_MSEC_TO_NSEC;
	squeue_workerwait_tick = MSEC_TO_TICK_ROUNDUP(squeue_workerwait_ms);
}

/* ARGSUSED */
squeue_t *
squeue_create(char *name, processorid_t bind, clock_t wait, pri_t pri)
{
	squeue_t *sqp = kmem_cache_alloc(squeue_cache, KM_SLEEP);

	bzero(sqp, sizeof (squeue_t));
	(void) strncpy(sqp->sq_name, name, SQ_NAMELEN + 1);
	sqp->sq_name[SQ_NAMELEN] = '\0';

	sqp->sq_bind = bind;
	sqp->sq_wait = MSEC_TO_TICK(wait);
	sqp->sq_avg_drain_time =
	    drv_hztousec(NSEC_TO_TICK_ROUNDUP(squeue_intrdrain_ns)) /
	    NSEC_TO_TICK_ROUNDUP(squeue_intrdrain_ns);

#if SQUEUE_PROFILE
	if ((sqp->sq_kstat = kstat_create("ip", bind, name,
		"net", KSTAT_TYPE_NAMED,
		sizeof (squeue_kstat) / sizeof (kstat_named_t),
		KSTAT_FLAG_VIRTUAL)) != NULL) {
		sqp->sq_kstat->ks_lock = &squeue_kstat_lock;
		sqp->sq_kstat->ks_data = &squeue_kstat;
		sqp->sq_kstat->ks_update = squeue_kstat_update;
		sqp->sq_kstat->ks_private = sqp;
		kstat_install(sqp->sq_kstat);
	}
#endif

	sqp->sq_worker = thread_create(NULL, 0, squeue_worker,
	    sqp, 0, &p0, TS_RUN, pri);

	return (sqp);
}

/* ARGSUSED */
void
squeue_bind(squeue_t *sqp, processorid_t bind)
{
	ASSERT(bind == -1);

	mutex_enter(&sqp->sq_lock);
	if (sqp->sq_state & SQS_BOUND) {
		mutex_exit(&sqp->sq_lock);
		return;
	}

	sqp->sq_state |= SQS_BOUND;
	mutex_exit(&sqp->sq_lock);

	thread_affinity_set(sqp->sq_worker, sqp->sq_bind);
}

void
squeue_unbind(squeue_t *sqp)
{
	mutex_enter(&sqp->sq_lock);
	if (!(sqp->sq_state & SQS_BOUND)) {
		mutex_exit(&sqp->sq_lock);
		return;
	}

	sqp->sq_state &= ~SQS_BOUND;
	mutex_exit(&sqp->sq_lock);

	thread_affinity_clear(sqp->sq_worker);
}

/*
 * squeue_enter() - enter squeue sqp with mblk mp (which can be
 * a chain), while tail points to the end and cnt in number of
 * mblks in the chain.
 *
 * For a chain of single packet (i.e. mp == tail), go through the
 * fast path if no one is processing the squeue and nothing is queued.
 *
 * The proc and arg for each mblk is already stored in the mblk in
 * appropriate places.
 */
void
squeue_enter_chain(squeue_t *sqp, mblk_t *mp, mblk_t *tail,
    uint32_t cnt, uint8_t tag)
{
	int		interrupt = servicing_interrupt();
	void 		*arg;
	sqproc_t	proc;
	hrtime_t	now;
#if SQUEUE_PROFILE
	hrtime_t 	start, delta;
#endif

	ASSERT(sqp != NULL);
	ASSERT(mp != NULL);
	ASSERT(tail != NULL);
	ASSERT(cnt > 0);
	ASSERT(MUTEX_NOT_HELD(&sqp->sq_lock));

	mutex_enter(&sqp->sq_lock);
	if (!(sqp->sq_state & SQS_PROC)) {
		/*
		 * See if anything is already queued. If we are the
		 * first packet, do inline processing else queue the
		 * packet and do the drain.
		 */
		sqp->sq_run = curthread;
		if (sqp->sq_first == NULL && cnt == 1) {
			/*
			 * Fast-path, ok to process and nothing queued.
			 */
			sqp->sq_state |= (SQS_PROC|SQS_FAST);
			mutex_exit(&sqp->sq_lock);

			/*
			 * We are the chain of 1 packet so
			 * go through this fast path.
			 */
			arg = mp->b_prev;
			mp->b_prev = NULL;
			proc = (sqproc_t)mp->b_queue;
			mp->b_queue = NULL;

			ASSERT(proc != NULL);
			ASSERT(arg != NULL);
			ASSERT(mp->b_next == NULL);

#if SQUEUE_DEBUG
			sqp->sq_isintr = interrupt;
			sqp->sq_curmp = mp;
			sqp->sq_curproc = proc;
			sqp->sq_connp = arg;
			mp->b_tag = sqp->sq_tag = tag;
#endif
#if SQUEUE_PROFILE
			if (SQ_PROFILING(sqp)) {
				if (interrupt)
					SQSTAT(sqp, sq_npackets_intr);
				else
					SQSTAT(sqp, sq_npackets_other);
				start = gethrtime();
			}
#endif
			((conn_t *)arg)->conn_on_sqp = B_TRUE;
			DTRACE_PROBE3(squeue__proc__start, squeue_t *,
			    sqp, mblk_t *, mp, conn_t *, arg);
			(*proc)(arg, mp, sqp);
			DTRACE_PROBE2(squeue__proc__end, squeue_t *,
			    sqp, conn_t *, arg);
			((conn_t *)arg)->conn_on_sqp = B_FALSE;

#if SQUEUE_PROFILE
			if (SQ_PROFILING(sqp)) {
				delta = gethrtime() - start;
				if (interrupt)
					SQDELTA(sqp, sq_time_intr, delta);
				else
					SQDELTA(sqp, sq_time_other, delta);
			}
#endif
#if SQUEUE_DEBUG
			sqp->sq_curmp = NULL;
			sqp->sq_curproc = NULL;
			sqp->sq_connp = NULL;
			sqp->sq_isintr = 0;
#endif

			CONN_DEC_REF((conn_t *)arg);
			ASSERT(MUTEX_NOT_HELD(&sqp->sq_lock));
			mutex_enter(&sqp->sq_lock);
			sqp->sq_state &= ~(SQS_PROC|SQS_FAST);
			if (sqp->sq_first == NULL) {
				/*
				 * We processed inline our packet and
				 * nothing new has arrived. We are done.
				 */
				sqp->sq_run = NULL;
				mutex_exit(&sqp->sq_lock);
				return;
			} else if (sqp->sq_bind != CPU->cpu_id) {
				/*
				 * If the current thread is not running
				 * on the CPU to which this squeue is bound,
				 * then don't allow it to drain.
				 */
				sqp->sq_run = NULL;
				SQUEUE_WORKER_WAKEUP(sqp);
				return;
			}
		} else {
			ENQUEUE_CHAIN(sqp, mp, tail, cnt);
#if SQUEUE_DEBUG
			mp->b_tag = tag;
#endif
#if SQUEUE_PROFILE
			if (SQ_PROFILING(sqp)) {
				if (servicing_interrupt())
					SQSTAT(sqp, sq_nqueued_intr);
				else
					SQSTAT(sqp, sq_nqueued_other);
				if (sqp->sq_stats.sq_max_qlen < sqp->sq_count)
					sqp->sq_stats.sq_max_qlen =
					    sqp->sq_count;
			}
#endif
		}

		/*
		 * We are here because either we couldn't do inline
		 * processing (because something was already queued),
		 * or we had a chanin of more than one packet,
		 * or something else arrived after we were done with
		 * inline processing.
		 */
		ASSERT(MUTEX_HELD(&sqp->sq_lock));
		ASSERT(sqp->sq_first != NULL);

#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			start = gethrtime();
		}
#endif
#if SQUEUE_DEBUG
		sqp->sq_isintr = interrupt;
#endif

		now = gethrtime();
		if (interrupt) {
			squeue_drain(sqp, SQS_ENTER, now +
			    squeue_intrdrain_ns);
		} else {
			squeue_drain(sqp, SQS_USER, now +
			    squeue_writerdrain_ns);
		}

#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			delta = gethrtime() - start;
			if (interrupt)
				SQDELTA(sqp, sq_time_intr, delta);
			else
				SQDELTA(sqp, sq_time_other, delta);
		}
#endif
#if SQUEUE_DEBUG
		sqp->sq_isintr = 0;
#endif

		/*
		 * If we didn't do a complete drain, the worker
		 * thread was already signalled by squeue_drain.
		 */
		sqp->sq_run = NULL;
		mutex_exit(&sqp->sq_lock);
		return;
	} else {
		ASSERT(sqp->sq_run != NULL);
		/*
		 * Queue is already being processed. Just enqueue
		 * the packet and go away.
		 */
#if SQUEUE_DEBUG
		mp->b_tag = tag;
#endif
#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			if (servicing_interrupt())
				SQSTAT(sqp, sq_nqueued_intr);
			else
				SQSTAT(sqp, sq_nqueued_other);
			if (sqp->sq_stats.sq_max_qlen < sqp->sq_count)
				sqp->sq_stats.sq_max_qlen = sqp->sq_count;
		}
#endif

		ENQUEUE_CHAIN(sqp, mp, tail, cnt);
		mutex_exit(&sqp->sq_lock);
		return;
	}
}

/*
 * squeue_enter() - enter squeue *sqp with mblk *mp with argument of *arg.
 */
void
squeue_enter(squeue_t *sqp, mblk_t *mp, sqproc_t proc, void *arg,
    uint8_t tag)
{
	int	interrupt = servicing_interrupt();
	hrtime_t now;
#if SQUEUE_PROFILE
	hrtime_t start, delta;
#endif
#if SQUEUE_DEBUG
	conn_t 	*connp = (conn_t *)arg;
	ASSERT(!IPCL_IS_TCP(connp) || connp->conn_tcp->tcp_connp == connp);
	ASSERT(!IPCL_IS_UDP(connp) || connp->conn_udp->udp_connp == connp);
#endif

	ASSERT(proc != NULL);
	ASSERT(sqp != NULL);
	ASSERT(mp != NULL);
	ASSERT(mp->b_next == NULL);
	ASSERT(MUTEX_NOT_HELD(&sqp->sq_lock));

	mutex_enter(&sqp->sq_lock);
	if (!(sqp->sq_state & SQS_PROC)) {
		/*
		 * See if anything is already queued. If we are the
		 * first packet, do inline processing else queue the
		 * packet and do the drain.
		 */
		sqp->sq_run = curthread;
		if (sqp->sq_first == NULL) {
			/*
			 * Fast-path, ok to process and nothing queued.
			 */
			sqp->sq_state |= (SQS_PROC|SQS_FAST);
			mutex_exit(&sqp->sq_lock);

#if SQUEUE_DEBUG
			sqp->sq_isintr = interrupt;
			sqp->sq_curmp = mp;
			sqp->sq_curproc = proc;
			sqp->sq_connp = connp;
			mp->b_tag = sqp->sq_tag = tag;
#endif
#if SQUEUE_PROFILE
			if (SQ_PROFILING(sqp)) {
				if (interrupt)
					SQSTAT(sqp, sq_npackets_intr);
				else
					SQSTAT(sqp, sq_npackets_other);
				start = gethrtime();
			}
#endif
			((conn_t *)arg)->conn_on_sqp = B_TRUE;
			DTRACE_PROBE3(squeue__proc__start, squeue_t *,
			    sqp, mblk_t *, mp, conn_t *, arg);
			(*proc)(arg, mp, sqp);
			DTRACE_PROBE2(squeue__proc__end, squeue_t *,
			    sqp, conn_t *, arg);
			((conn_t *)arg)->conn_on_sqp = B_FALSE;

#if SQUEUE_PROFILE
			if (SQ_PROFILING(sqp)) {
				delta = gethrtime() - start;
				if (interrupt)
					SQDELTA(sqp, sq_time_intr, delta);
				else
					SQDELTA(sqp, sq_time_other, delta);
			}
#endif
#if SQUEUE_DEBUG
			sqp->sq_curmp = NULL;
			sqp->sq_curproc = NULL;
			sqp->sq_connp = NULL;
			sqp->sq_isintr = 0;
#endif

			CONN_DEC_REF((conn_t *)arg);
			ASSERT(MUTEX_NOT_HELD(&sqp->sq_lock));
			mutex_enter(&sqp->sq_lock);
			sqp->sq_state &= ~(SQS_PROC|SQS_FAST);
			if (sqp->sq_first == NULL) {
				/*
				 * We processed inline our packet and
				 * nothing new has arrived. We are done.
				 */
				sqp->sq_run = NULL;
				mutex_exit(&sqp->sq_lock);
				return;
			} else if (sqp->sq_bind != CPU->cpu_id) {
				/*
				 * If the current thread is not running
				 * on the CPU to which this squeue is bound,
				 * then don't allow it to drain.
				 */
				sqp->sq_run = NULL;
				SQUEUE_WORKER_WAKEUP(sqp);
				return;
			}
		} else {
			ENQUEUE_MP(sqp, mp, proc, arg);
#if SQUEUE_DEBUG
			mp->b_tag = tag;
#endif
#if SQUEUE_PROFILE
			if (SQ_PROFILING(sqp)) {
				if (servicing_interrupt())
					SQSTAT(sqp, sq_nqueued_intr);
				else
					SQSTAT(sqp, sq_nqueued_other);
				if (sqp->sq_stats.sq_max_qlen < sqp->sq_count)
					sqp->sq_stats.sq_max_qlen =
					    sqp->sq_count;
			}
#endif
		}

		/*
		 * We are here because either we couldn't do inline
		 * processing (because something was already queued)
		 * or something else arrived after we were done with
		 * inline processing.
		 */
		ASSERT(MUTEX_HELD(&sqp->sq_lock));
		ASSERT(sqp->sq_first != NULL);

#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			start = gethrtime();
		}
#endif
#if SQUEUE_DEBUG
		sqp->sq_isintr = interrupt;
#endif

		now = gethrtime();
		if (interrupt) {
			squeue_drain(sqp, SQS_ENTER, now +
			    squeue_intrdrain_ns);
		} else {
			squeue_drain(sqp, SQS_USER, now +
			    squeue_writerdrain_ns);
		}

#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			delta = gethrtime() - start;
			if (interrupt)
				SQDELTA(sqp, sq_time_intr, delta);
			else
				SQDELTA(sqp, sq_time_other, delta);
		}
#endif
#if SQUEUE_DEBUG
		sqp->sq_isintr = 0;
#endif

		/*
		 * If we didn't do a complete drain, the worker
		 * thread was already signalled by squeue_drain.
		 */
		sqp->sq_run = NULL;
		mutex_exit(&sqp->sq_lock);
		return;
	} else {
		ASSERT(sqp->sq_run != NULL);
		/*
		 * We let a thread processing a squeue reenter only
		 * once. This helps the case of incoming connection
		 * where a SYN-ACK-ACK that triggers the conn_ind
		 * doesn't have to queue the packet if listener and
		 * eager are on the same squeue. Also helps the
		 * loopback connection where the two ends are bound
		 * to the same squeue (which is typical on single
		 * CPU machines).
		 * We let the thread reenter only once for the fear
		 * of stack getting blown with multiple traversal.
		 */
		if (!(sqp->sq_state & SQS_REENTER) &&
		    (sqp->sq_run == curthread) && sqp->sq_first == NULL &&
		    (((conn_t *)arg)->conn_on_sqp == B_FALSE)) {
			sqp->sq_state |= SQS_REENTER;
			mutex_exit(&sqp->sq_lock);

			((conn_t *)arg)->conn_on_sqp = B_TRUE;
			DTRACE_PROBE3(squeue__proc__start, squeue_t *,
			    sqp, mblk_t *, mp, conn_t *, arg);
			(*proc)(arg, mp, sqp);
			DTRACE_PROBE2(squeue__proc__end, squeue_t *,
			    sqp, conn_t *, arg);
			((conn_t *)arg)->conn_on_sqp = B_FALSE;
			CONN_DEC_REF((conn_t *)arg);

			mutex_enter(&sqp->sq_lock);
			sqp->sq_state &= ~SQS_REENTER;
			mutex_exit(&sqp->sq_lock);
			return;
		}
		/*
		 * Queue is already being processed. Just enqueue
		 * the packet and go away.
		 */
#if SQUEUE_DEBUG
		mp->b_tag = tag;
#endif
#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			if (servicing_interrupt())
				SQSTAT(sqp, sq_nqueued_intr);
			else
				SQSTAT(sqp, sq_nqueued_other);
			if (sqp->sq_stats.sq_max_qlen < sqp->sq_count)
				sqp->sq_stats.sq_max_qlen = sqp->sq_count;
		}
#endif

		ENQUEUE_MP(sqp, mp, proc, arg);
		mutex_exit(&sqp->sq_lock);
		return;
	}
}

void
squeue_enter_nodrain(squeue_t *sqp, mblk_t *mp, sqproc_t proc, void *arg,
    uint8_t tag)
{
	int		interrupt = servicing_interrupt();
	boolean_t	being_processed;
#if SQUEUE_DEBUG
	conn_t 		*connp = (conn_t *)arg;
#endif
#if SQUEUE_PROFILE
	hrtime_t 	start, delta;
#endif

	ASSERT(proc != NULL);
	ASSERT(sqp != NULL);
	ASSERT(mp != NULL);
	ASSERT(mp->b_next == NULL);
	ASSERT(!IPCL_IS_TCP(connp) || connp->conn_tcp->tcp_connp == connp);
	ASSERT(!IPCL_IS_UDP(connp) || connp->conn_udp->udp_connp == connp);
	ASSERT(MUTEX_NOT_HELD(&sqp->sq_lock));

	mutex_enter(&sqp->sq_lock);

	being_processed = (sqp->sq_state & SQS_PROC);
	if (!being_processed && (sqp->sq_first == NULL)) {
		/*
		 * Fast-path, ok to process and nothing queued.
		 */
		sqp->sq_state |= (SQS_PROC|SQS_FAST);
		sqp->sq_run = curthread;
		mutex_exit(&sqp->sq_lock);

#if SQUEUE_DEBUG
		sqp->sq_isintr = interrupt;
		sqp->sq_curmp = mp;
		sqp->sq_curproc = proc;
		sqp->sq_connp = connp;
		mp->b_tag = sqp->sq_tag = tag;
#endif

#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			if (interrupt)
				SQSTAT(sqp, sq_npackets_intr);
			else
				SQSTAT(sqp, sq_npackets_other);
			start = gethrtime();
		}
#endif

		((conn_t *)arg)->conn_on_sqp = B_TRUE;
		DTRACE_PROBE3(squeue__proc__start, squeue_t *,
		    sqp, mblk_t *, mp, conn_t *, arg);
		(*proc)(arg, mp, sqp);
		DTRACE_PROBE2(squeue__proc__end, squeue_t *,
		    sqp, conn_t *, arg);
		((conn_t *)arg)->conn_on_sqp = B_FALSE;

#if SQUEUE_DEBUG
		sqp->sq_curmp = NULL;
		sqp->sq_curproc = NULL;
		sqp->sq_connp = NULL;
		sqp->sq_isintr = 0;
#endif
#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			delta = gethrtime() - start;
			if (interrupt)
				SQDELTA(sqp, sq_time_intr, delta);
			else
				SQDELTA(sqp, sq_time_other, delta);
		}
#endif

		CONN_DEC_REF((conn_t *)arg);
		mutex_enter(&sqp->sq_lock);
		sqp->sq_state &= ~(SQS_PROC|SQS_FAST);
		sqp->sq_run = NULL;
		if (sqp->sq_first == NULL) {
			/*
			 * We processed inline our packet and
			 * nothing new has arrived. We are done.
			 */
			mutex_exit(&sqp->sq_lock);
		} else {
			SQUEUE_WORKER_WAKEUP(sqp);
		}
		return;
	} else {
		/*
		 * We let a thread processing a squeue reenter only
		 * once. This helps the case of incoming connection
		 * where a SYN-ACK-ACK that triggers the conn_ind
		 * doesn't have to queue the packet if listener and
		 * eager are on the same squeue. Also helps the
		 * loopback connection where the two ends are bound
		 * to the same squeue (which is typical on single
		 * CPU machines).
		 * We let the thread reenter only once for the fear
		 * of stack getting blown with multiple traversal.
		 */
		if (being_processed && !(sqp->sq_state & SQS_REENTER) &&
		    (sqp->sq_run == curthread) && sqp->sq_first == NULL &&
		    (((conn_t *)arg)->conn_on_sqp == B_FALSE)) {
			sqp->sq_state |= SQS_REENTER;
			mutex_exit(&sqp->sq_lock);

			((conn_t *)arg)->conn_on_sqp = B_TRUE;
			DTRACE_PROBE3(squeue__proc__start, squeue_t *,
			    sqp, mblk_t *, mp, conn_t *, arg);
			(*proc)(arg, mp, sqp);
			DTRACE_PROBE2(squeue__proc__end, squeue_t *,
			    sqp, conn_t *, arg);
			((conn_t *)arg)->conn_on_sqp = B_FALSE;
			CONN_DEC_REF((conn_t *)arg);

			mutex_enter(&sqp->sq_lock);
			sqp->sq_state &= ~SQS_REENTER;
			mutex_exit(&sqp->sq_lock);
			return;
		}

#if SQUEUE_DEBUG
		mp->b_tag = tag;
#endif
#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			if (servicing_interrupt())
				SQSTAT(sqp, sq_nqueued_intr);
			else
				SQSTAT(sqp, sq_nqueued_other);
			if (sqp->sq_stats.sq_max_qlen < sqp->sq_count)
				sqp->sq_stats.sq_max_qlen = sqp->sq_count;
		}
#endif
		ENQUEUE_MP(sqp, mp, proc, arg);
		if (being_processed) {
			/*
			 * Queue is already being processed.
			 * No need to do anything.
			 */
			mutex_exit(&sqp->sq_lock);
			return;
		}
		SQUEUE_WORKER_WAKEUP(sqp);
	}
}

/*
 * squeue_fill() - fill squeue *sqp with mblk *mp with argument of *arg
 * without processing the squeue.
 */
/* ARGSUSED */
void
squeue_fill(squeue_t *sqp, mblk_t *mp, sqproc_t proc, void * arg,
    uint8_t tag)
{
#if SQUEUE_DEBUG
	conn_t *connp = (conn_t *)arg;
#endif
	ASSERT(proc != NULL);
	ASSERT(sqp != NULL);
	ASSERT(mp != NULL);
	ASSERT(mp->b_next == NULL);
	ASSERT(!IPCL_IS_TCP(connp) || connp->conn_tcp->tcp_connp == connp);
	ASSERT(!IPCL_IS_UDP(connp) || connp->conn_udp->udp_connp == connp);

	ASSERT(MUTEX_NOT_HELD(&sqp->sq_lock));
	mutex_enter(&sqp->sq_lock);
	ENQUEUE_MP(sqp, mp, proc, arg);
#if SQUEUE_DEBUG
	mp->b_tag = tag;
#endif
#if SQUEUE_PROFILE
	if (SQ_PROFILING(sqp)) {
		if (servicing_interrupt())
			SQSTAT(sqp, sq_nqueued_intr);
		else
			SQSTAT(sqp, sq_nqueued_other);
		if (sqp->sq_stats.sq_max_qlen < sqp->sq_count)
			sqp->sq_stats.sq_max_qlen = sqp->sq_count;
	}
#endif

	/*
	 * If queue is already being processed. No need to do anything.
	 */
	if (sqp->sq_state & SQS_PROC) {
		mutex_exit(&sqp->sq_lock);
		return;
	}

	SQUEUE_WORKER_WAKEUP(sqp);
}


/*
 * PRIVATE FUNCTIONS
 */

static void
squeue_fire(void *arg)
{
	squeue_t	*sqp = arg;
	uint_t		state;

	mutex_enter(&sqp->sq_lock);

	state = sqp->sq_state;
	if (sqp->sq_tid == 0 && !(state & SQS_TMO_PROG)) {
		mutex_exit(&sqp->sq_lock);
		return;
	}

	sqp->sq_tid = 0;
	/*
	 * The timeout fired before we got a chance to set it.
	 * Process it anyway but remove the SQS_TMO_PROG so that
	 * the guy trying to set the timeout knows that it has
	 * already been processed.
	 */
	if (state & SQS_TMO_PROG)
		sqp->sq_state &= ~SQS_TMO_PROG;

	if (!(state & SQS_PROC)) {
		sqp->sq_awaken = lbolt;
		cv_signal(&sqp->sq_async);
	}
	mutex_exit(&sqp->sq_lock);
}

static void
squeue_drain(squeue_t *sqp, uint_t proc_type, hrtime_t expire)
{
	mblk_t	*mp;
	mblk_t 	*head;
	sqproc_t proc;
	conn_t	*connp;
	clock_t	start = lbolt;
	clock_t	drain_time;
	timeout_id_t tid;
	uint_t	cnt;
	uint_t	total_cnt = 0;
	ill_rx_ring_t	*sq_rx_ring = sqp->sq_rx_ring;
	int	interrupt = servicing_interrupt();
	boolean_t poll_on = B_FALSE;
	hrtime_t now;

	ASSERT(mutex_owned(&sqp->sq_lock));
	ASSERT(!(sqp->sq_state & SQS_PROC));

#if SQUEUE_PROFILE
	if (SQ_PROFILING(sqp)) {
		if (interrupt)
			SQSTAT(sqp, sq_ndrains_intr);
		else if (!(proc_type & SQS_WORKER))
			SQSTAT(sqp, sq_ndrains_other);
		else
			SQSTAT(sqp, sq_ndrains_worker);
	}
#endif

	if ((tid = sqp->sq_tid) != 0)
		sqp->sq_tid = 0;

	sqp->sq_state |= SQS_PROC | proc_type;
	head = sqp->sq_first;
	sqp->sq_first = NULL;
	sqp->sq_last = NULL;
	cnt = sqp->sq_count;

	/*
	 * We have backlog built up. Switch to polling mode if the
	 * device underneath allows it. Need to do it only for
	 * drain by non-interrupt thread so interrupts don't
	 * come and disrupt us in between. If its a interrupt thread,
	 * no need because most devices will not issue another
	 * interrupt till this one returns.
	 */
	if ((sqp->sq_state & SQS_POLL_CAPAB) && !(proc_type & SQS_ENTER) &&
		(sqp->sq_count > squeue_worker_poll_min)) {
		ASSERT(sq_rx_ring != NULL);
		SQS_POLLING_ON(sqp, sq_rx_ring);
		poll_on = B_TRUE;
	}

	mutex_exit(&sqp->sq_lock);

	if (tid != 0)
		(void) untimeout(tid);
again:
	while ((mp = head) != NULL) {
		head = mp->b_next;
		mp->b_next = NULL;

		proc = (sqproc_t)mp->b_queue;
		mp->b_queue = NULL;
		connp = (conn_t *)mp->b_prev;
		mp->b_prev = NULL;
#if SQUEUE_DEBUG
		sqp->sq_curmp = mp;
		sqp->sq_curproc = proc;
		sqp->sq_connp = connp;
		sqp->sq_tag = mp->b_tag;
#endif

#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			if (interrupt)
				SQSTAT(sqp, sq_npackets_intr);
			else if (!(proc_type & SQS_WORKER))
				SQSTAT(sqp, sq_npackets_other);
			else
				SQSTAT(sqp, sq_npackets_worker);
		}
#endif

		connp->conn_on_sqp = B_TRUE;
		DTRACE_PROBE3(squeue__proc__start, squeue_t *,
		    sqp, mblk_t *, mp, conn_t *, connp);
		(*proc)(connp, mp, sqp);
		DTRACE_PROBE2(squeue__proc__end, squeue_t *,
		    sqp, conn_t *, connp);
		connp->conn_on_sqp = B_FALSE;
		CONN_DEC_REF(connp);
	}


#if SQUEUE_DEBUG
	sqp->sq_curmp = NULL;
	sqp->sq_curproc = NULL;
	sqp->sq_connp = NULL;
#endif

	mutex_enter(&sqp->sq_lock);
	sqp->sq_count -= cnt;
	total_cnt += cnt;

	if (sqp->sq_first != NULL) {

		now = gethrtime();
		if (!expire || (now < expire)) {
			/* More arrived and time not expired */
			head = sqp->sq_first;
			sqp->sq_first = NULL;
			sqp->sq_last = NULL;
			cnt = sqp->sq_count;
			mutex_exit(&sqp->sq_lock);
			goto again;
		}

		/*
		 * If we are not worker thread and we
		 * reached our time limit to do drain,
		 * signal the worker thread to pick
		 * up the work.
		 * If we were the worker thread, then
		 * we take a break to allow an interrupt
		 * or writer to pick up the load.
		 */
		if (proc_type != SQS_WORKER) {
			sqp->sq_awaken = lbolt;
			cv_signal(&sqp->sq_async);
		}
	}

	/*
	 * Try to see if we can get a time estimate to process a packet.
	 * Do it only in interrupt context since less chance of context
	 * switch or pinning etc. to get a better estimate.
	 */
	if (interrupt && ((drain_time = (lbolt - start)) > 0))
		sqp->sq_avg_drain_time = ((80 * sqp->sq_avg_drain_time) +
		    (20 * (drv_hztousec(drain_time)/total_cnt)))/100;

	sqp->sq_state &= ~(SQS_PROC | proc_type);

	/*
	 * If polling was turned on, turn it off and reduce the default
	 * interrupt blank interval as well to bring new packets in faster
	 * (reduces the latency when there is no backlog).
	 */
	if (poll_on && (sqp->sq_state & SQS_POLL_CAPAB)) {
		ASSERT(sq_rx_ring != NULL);
		SQS_POLLING_OFF(sqp, sq_rx_ring);
	}
}

static void
squeue_worker(squeue_t *sqp)
{
	kmutex_t *lock = &sqp->sq_lock;
	kcondvar_t *async = &sqp->sq_async;
	callb_cpr_t cprinfo;
	hrtime_t now;
#if SQUEUE_PROFILE
	hrtime_t start;
#endif

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "nca");
	mutex_enter(lock);

	for (;;) {
		while (sqp->sq_first == NULL || (sqp->sq_state & SQS_PROC)) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
still_wait:
			cv_wait(async, lock);
			if (sqp->sq_state & SQS_PROC) {
				goto still_wait;
			}
			CALLB_CPR_SAFE_END(&cprinfo, lock);
		}

#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			start = gethrtime();
		}
#endif

		ASSERT(squeue_workerdrain_ns != 0);
		now = gethrtime();
		sqp->sq_run = curthread;
		squeue_drain(sqp, SQS_WORKER, now +  squeue_workerdrain_ns);
		sqp->sq_run = NULL;

		if (sqp->sq_first != NULL) {
			/*
			 * Doing too much processing by worker thread
			 * in presense of interrupts can be sub optimal.
			 * Instead, once a drain is done by worker thread
			 * for squeue_writerdrain_ns (the reason we are
			 * here), we force wait for squeue_workerwait_tick
			 * before doing more processing even if sq_wait is
			 * set to 0.
			 *
			 * This can be counterproductive for performance
			 * if worker thread is the only means to process
			 * the packets (interrupts or writers are not
			 * allowed inside the squeue).
			 */
			if (sqp->sq_tid == 0 &&
			    !(sqp->sq_state & SQS_TMO_PROG)) {
				timeout_id_t	tid;

				sqp->sq_state |= SQS_TMO_PROG;
				mutex_exit(&sqp->sq_lock);
				tid = timeout(squeue_fire, sqp,
				    squeue_workerwait_tick);
				mutex_enter(&sqp->sq_lock);
				/*
				 * Check again if we still need
				 * the timeout
				 */
				if (((sqp->sq_state & (SQS_TMO_PROG|SQS_PROC))
				    == SQS_TMO_PROG) && (sqp->sq_tid == 0) &&
				    (sqp->sq_first != NULL)) {
					sqp->sq_state &= ~SQS_TMO_PROG;
					sqp->sq_awaken = lbolt;
					sqp->sq_tid = tid;
				} else if (sqp->sq_state & SQS_TMO_PROG) {
					/* timeout not needed */
					sqp->sq_state &= ~SQS_TMO_PROG;
					mutex_exit(&(sqp)->sq_lock);
					(void) untimeout(tid);
					mutex_enter(&sqp->sq_lock);
				}
			}
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(async, lock);
			CALLB_CPR_SAFE_END(&cprinfo, lock);
		}


#if SQUEUE_PROFILE
		if (SQ_PROFILING(sqp)) {
			SQDELTA(sqp, sq_time_worker, gethrtime() - start);
		}
#endif
	}
}

#if SQUEUE_PROFILE
static int
squeue_kstat_update(kstat_t *ksp, int rw)
{
	struct squeue_kstat *sqsp = &squeue_kstat;
	squeue_t *sqp = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (EACCES);

#if SQUEUE_DEBUG
	sqsp->sq_count.value.ui64 = sqp->sq_count;
	sqsp->sq_max_qlen.value.ui64 = sqp->sq_stats.sq_max_qlen;
#endif
	sqsp->sq_npackets_worker.value.ui64 = sqp->sq_stats.sq_npackets_worker;
	sqsp->sq_npackets_intr.value.ui64 = sqp->sq_stats.sq_npackets_intr;
	sqsp->sq_npackets_other.value.ui64 = sqp->sq_stats.sq_npackets_other;
	sqsp->sq_nqueued_intr.value.ui64 = sqp->sq_stats.sq_nqueued_intr;
	sqsp->sq_nqueued_other.value.ui64 = sqp->sq_stats.sq_nqueued_other;
	sqsp->sq_ndrains_worker.value.ui64 = sqp->sq_stats.sq_ndrains_worker;
	sqsp->sq_ndrains_intr.value.ui64 = sqp->sq_stats.sq_ndrains_intr;
	sqsp->sq_ndrains_other.value.ui64 = sqp->sq_stats.sq_ndrains_other;
	sqsp->sq_time_worker.value.ui64 = sqp->sq_stats.sq_time_worker;
	sqsp->sq_time_intr.value.ui64 = sqp->sq_stats.sq_time_intr;
	sqsp->sq_time_other.value.ui64 = sqp->sq_stats.sq_time_other;
	return (0);
}
#endif

void
squeue_profile_enable(squeue_t *sqp)
{
	mutex_enter(&sqp->sq_lock);
	sqp->sq_state |= SQS_PROFILE;
	mutex_exit(&sqp->sq_lock);
}

void
squeue_profile_disable(squeue_t *sqp)
{
	mutex_enter(&sqp->sq_lock);
	sqp->sq_state &= ~SQS_PROFILE;
	mutex_exit(&sqp->sq_lock);
}

void
squeue_profile_reset(squeue_t *sqp)
{
#if SQUEUE_PROFILE
	bzero(&sqp->sq_stats, sizeof (sqstat_t));
#endif
}

void
squeue_profile_start(void)
{
#if SQUEUE_PROFILE
	squeue_profile = B_TRUE;
#endif
}

void
squeue_profile_stop(void)
{
#if SQUEUE_PROFILE
	squeue_profile = B_FALSE;
#endif
}

uintptr_t *
squeue_getprivate(squeue_t *sqp, sqprivate_t p)
{
	ASSERT(p < SQPRIVATE_MAX);

	return (&sqp->sq_private[p]);
}

processorid_t
squeue_binding(squeue_t *sqp)
{
	return (sqp->sq_bind);
}
