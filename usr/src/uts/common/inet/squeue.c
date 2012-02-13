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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Squeues: General purpose serialization mechanism
 * ------------------------------------------------
 *
 * Background:
 * -----------
 *
 * This is a general purpose high-performance serialization mechanism
 * currently used by TCP/IP. It is implement by means of a per CPU queue,
 * a worker thread and a polling thread with are bound to the CPU
 * associated with the squeue. The squeue is strictly FIFO for both read
 * and write side and only one thread can process it at any given time.
 * The design goal of squeue was to offer a very high degree of
 * parallelization (on a per H/W execution pipeline basis) with at
 * most one queuing.
 *
 * The modules needing protection typically calls SQUEUE_ENTER_ONE() or
 * SQUEUE_ENTER() macro as soon as a thread enter the module
 * from either direction. For each packet, the processing function
 * and argument is stored in the mblk itself. When the packet is ready
 * to be processed, the squeue retrieves the stored function and calls
 * it with the supplied argument and the pointer to the packet itself.
 * The called function can assume that no other thread is processing
 * the squeue when it is executing.
 *
 * Squeue/connection binding:
 * --------------------------
 *
 * TCP/IP uses an IP classifier in conjunction with squeue where specific
 * connections are assigned to specific squeue (based on various policies),
 * at the connection creation time. Once assigned, the connection to
 * squeue mapping is never changed and all future packets for that
 * connection are processed on that squeue. The connection ("conn") to
 * squeue mapping is stored in "conn_t" member "conn_sqp".
 *
 * Since the processing of the connection cuts across multiple layers
 * but still allows packets for different connnection to be processed on
 * other CPU/squeues, squeues are also termed as "Vertical Perimeter" or
 * "Per Connection Vertical Perimeter".
 *
 * Processing Model:
 * -----------------
 *
 * Squeue doesn't necessary processes packets with its own worker thread.
 * The callers can pick if they just want to queue the packet, process
 * their packet if nothing is queued or drain and process. The first two
 * modes are typically employed when the packet was generated while
 * already doing the processing behind the squeue and last mode (drain
 * and process) is typically employed when the thread is entering squeue
 * for the first time. The squeue still imposes a finite time limit
 * for which a external thread can do processing after which it switches
 * processing to its own worker thread.
 *
 * Once created, squeues are never deleted. Hence squeue pointers are
 * always valid. This means that functions outside the squeue can still
 * refer safely to conn_sqp and their is no need for ref counts.
 *
 * Only a thread executing in the squeue can change the squeue of the
 * connection. It does so by calling a squeue framework function to do this.
 * After changing the squeue, the thread must leave the squeue. It must not
 * continue to execute any code that needs squeue protection.
 *
 * The squeue framework, after entering the squeue, checks if the current
 * squeue matches the conn_sqp. If the check fails, the packet is delivered
 * to right squeue.
 *
 * Polling Model:
 * --------------
 *
 * Squeues can control the rate of packet arrival into itself from the
 * NIC or specific Rx ring within a NIC. As part of capability negotiation
 * between IP and MAC layer, squeue are created for each TCP soft ring
 * (or TCP Rx ring - to be implemented in future). As part of this
 * negotiation, squeues get a cookie for underlying soft ring or Rx
 * ring, a function to turn off incoming packets and a function to call
 * to poll for packets. This helps schedule the receive side packet
 * processing so that queue backlog doesn't build up and packet processing
 * doesn't keep getting disturbed by high priority interrupts. As part
 * of this mode, as soon as a backlog starts building, squeue turns off
 * the interrupts and switches to poll mode. In poll mode, when poll
 * thread goes down to retrieve packets, it retrieves them in the form of
 * a chain which improves performance even more. As the squeue/softring
 * system gets more packets, it gets more efficient by switching to
 * polling more often and dealing with larger packet chains.
 *
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
#include <sys/sunddi.h>

#include <inet/ipclassifier.h>
#include <inet/udp_impl.h>

#include <sys/squeue_impl.h>

static void squeue_fire(void *);
static void squeue_drain(squeue_t *, uint_t, hrtime_t);
static void squeue_worker(squeue_t *sqp);
static void squeue_polling_thread(squeue_t *sqp);

kmem_cache_t *squeue_cache;

#define	SQUEUE_MSEC_TO_NSEC 1000000

int squeue_drain_ms = 20;
int squeue_workerwait_ms = 0;

/* The values above converted to ticks or nano seconds */
static int squeue_drain_ns = 0;
static int squeue_workerwait_tick = 0;

#define	MAX_BYTES_TO_PICKUP	150000

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

/*
 * Blank the receive ring (in this case it is the soft ring). When
 * blanked, the soft ring will not send any more packets up.
 * Blanking may not succeed when there is a CPU already in the soft
 * ring sending packets up. In that case, SQS_POLLING will not be
 * set.
 */
#define	SQS_POLLING_ON(sqp, sq_poll_capable, rx_ring) {		\
	ASSERT(MUTEX_HELD(&(sqp)->sq_lock));			\
	if (sq_poll_capable) {					\
		ASSERT(rx_ring != NULL);			\
		ASSERT(sqp->sq_state & SQS_POLL_CAPAB);		\
		if (!(sqp->sq_state & SQS_POLLING)) {		\
			if (rx_ring->rr_intr_disable(rx_ring->rr_intr_handle)) \
				sqp->sq_state |= SQS_POLLING;	\
		}						\
	}							\
}

#define	SQS_POLLING_OFF(sqp, sq_poll_capable, rx_ring) {	\
	ASSERT(MUTEX_HELD(&(sqp)->sq_lock));			\
	if (sq_poll_capable) {					\
		ASSERT(rx_ring != NULL);			\
		ASSERT(sqp->sq_state & SQS_POLL_CAPAB);		\
		if (sqp->sq_state & SQS_POLLING) {		\
			sqp->sq_state &= ~SQS_POLLING;		\
			rx_ring->rr_intr_enable(rx_ring->rr_intr_handle); \
		}						\
	}							\
}

/* Wakeup poll thread only if SQS_POLLING is set */
#define	SQS_POLL_RING(sqp) {			\
	ASSERT(MUTEX_HELD(&(sqp)->sq_lock));			\
	if (sqp->sq_state & SQS_POLLING) {			\
		ASSERT(sqp->sq_state & SQS_POLL_CAPAB);		\
		if (!(sqp->sq_state & SQS_GET_PKTS)) {		\
			sqp->sq_state |= SQS_GET_PKTS;		\
			cv_signal(&sqp->sq_poll_cv);		\
		}						\
	}							\
}

#ifdef DEBUG
#define	SQUEUE_DBG_SET(sqp, mp, proc, connp, tag) {		\
	(sqp)->sq_curmp = (mp);					\
	(sqp)->sq_curproc = (proc);				\
	(sqp)->sq_connp = (connp);				\
	(mp)->b_tag = (sqp)->sq_tag = (tag);			\
}

#define	SQUEUE_DBG_CLEAR(sqp)	{				\
	(sqp)->sq_curmp = NULL;					\
	(sqp)->sq_curproc = NULL;				\
	(sqp)->sq_connp = NULL;					\
}
#else
#define	SQUEUE_DBG_SET(sqp, mp, proc, connp, tag)
#define	SQUEUE_DBG_CLEAR(sqp)
#endif

void
squeue_init(void)
{
	squeue_cache = kmem_cache_create("squeue_cache",
	    sizeof (squeue_t), 64, NULL, NULL, NULL, NULL, NULL, 0);

	squeue_drain_ns = squeue_drain_ms * SQUEUE_MSEC_TO_NSEC;
	squeue_workerwait_tick = MSEC_TO_TICK_ROUNDUP(squeue_workerwait_ms);
}

/* ARGSUSED */
squeue_t *
squeue_create(clock_t wait, pri_t pri)
{
	squeue_t *sqp = kmem_cache_alloc(squeue_cache, KM_SLEEP);

	bzero(sqp, sizeof (squeue_t));
	sqp->sq_bind = PBIND_NONE;
	sqp->sq_priority = pri;
	sqp->sq_wait = MSEC_TO_TICK(wait);
	sqp->sq_worker = thread_create(NULL, 0, squeue_worker,
	    sqp, 0, &p0, TS_RUN, pri);

	sqp->sq_poll_thr = thread_create(NULL, 0, squeue_polling_thread,
	    sqp, 0, &p0, TS_RUN, pri);

	sqp->sq_enter = squeue_enter;
	sqp->sq_drain = squeue_drain;

	return (sqp);
}

/*
 * Bind squeue worker thread to the specified CPU, given by CPU id.
 * If the CPU id  value is -1, bind the worker thread to the value
 * specified in sq_bind field. If a thread is already bound to a
 * different CPU, unbind it from the old CPU and bind to the new one.
 */

void
squeue_bind(squeue_t *sqp, processorid_t bind)
{
	mutex_enter(&sqp->sq_lock);
	ASSERT(sqp->sq_bind != PBIND_NONE || bind != PBIND_NONE);
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (sqp->sq_state & SQS_BOUND) {
		if (sqp->sq_bind == bind) {
			mutex_exit(&sqp->sq_lock);
			return;
		}
		thread_affinity_clear(sqp->sq_worker);
	} else {
		sqp->sq_state |= SQS_BOUND;
	}

	if (bind != PBIND_NONE)
		sqp->sq_bind = bind;

	thread_affinity_set(sqp->sq_worker, sqp->sq_bind);
	mutex_exit(&sqp->sq_lock);
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
	thread_affinity_clear(sqp->sq_worker);
	mutex_exit(&sqp->sq_lock);
}

void
squeue_worker_wakeup(squeue_t *sqp)
{
	timeout_id_t tid = (sqp)->sq_tid;

	ASSERT(MUTEX_HELD(&(sqp)->sq_lock));

	if (sqp->sq_wait == 0) {
		ASSERT(tid == 0);
		ASSERT(!(sqp->sq_state & SQS_TMO_PROG));
		sqp->sq_awaken = ddi_get_lbolt();
		cv_signal(&sqp->sq_worker_cv);
		mutex_exit(&sqp->sq_lock);
		return;
	}

	/*
	 * Queue isn't being processed, so take
	 * any post enqueue actions needed before leaving.
	 */
	if (tid != 0) {
		/*
		 * Waiting for an enter() to process mblk(s).
		 */
		clock_t now = ddi_get_lbolt();
		clock_t	waited = now - sqp->sq_awaken;

		if (TICK_TO_MSEC(waited) >= sqp->sq_wait) {
			/*
			 * Times up and have a worker thread
			 * waiting for work, so schedule it.
			 */
			sqp->sq_tid = 0;
			sqp->sq_awaken = now;
			cv_signal(&sqp->sq_worker_cv);
			mutex_exit(&sqp->sq_lock);
			(void) untimeout(tid);
			return;
		}
		mutex_exit(&sqp->sq_lock);
		return;
	} else if (sqp->sq_state & SQS_TMO_PROG) {
		mutex_exit(&sqp->sq_lock);
		return;
	} else {
		clock_t	wait = sqp->sq_wait;
		/*
		 * Wait up to sqp->sq_wait ms for an
		 * enter() to process this queue. We
		 * don't want to contend on timeout locks
		 * with sq_lock held for performance reasons,
		 * so drop the sq_lock before calling timeout
		 * but we need to check if timeout is required
		 * after re acquiring the sq_lock. Once
		 * the sq_lock is dropped, someone else could
		 * have processed the packet or the timeout could
		 * have already fired.
		 */
		sqp->sq_state |= SQS_TMO_PROG;
		mutex_exit(&sqp->sq_lock);
		tid = timeout(squeue_fire, sqp, wait);
		mutex_enter(&sqp->sq_lock);
		/* Check again if we still need the timeout */
		if (((sqp->sq_state & (SQS_PROC|SQS_TMO_PROG)) ==
		    SQS_TMO_PROG) && (sqp->sq_tid == 0) &&
		    (sqp->sq_first != NULL)) {
				sqp->sq_state &= ~SQS_TMO_PROG;
				sqp->sq_tid = tid;
				mutex_exit(&sqp->sq_lock);
				return;
		} else {
			if (sqp->sq_state & SQS_TMO_PROG) {
				sqp->sq_state &= ~SQS_TMO_PROG;
				mutex_exit(&sqp->sq_lock);
				(void) untimeout(tid);
			} else {
				/*
				 * The timer fired before we could
				 * reacquire the sq_lock. squeue_fire
				 * removes the SQS_TMO_PROG flag
				 * and we don't need to	do anything
				 * else.
				 */
				mutex_exit(&sqp->sq_lock);
			}
		}
	}

	ASSERT(MUTEX_NOT_HELD(&sqp->sq_lock));
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
 *
 * The process_flag specifies if we are allowed to process the mblk
 * and drain in the entering thread context. If process_flag is
 * SQ_FILL, then we just queue the mblk and return (after signaling
 * the worker thread if no one else is processing the squeue).
 *
 * The ira argument can be used when the count is one.
 * For a chain the caller needs to prepend any needed mblks from
 * ip_recv_attr_to_mblk().
 */
/* ARGSUSED */
void
squeue_enter(squeue_t *sqp, mblk_t *mp, mblk_t *tail, uint32_t cnt,
    ip_recv_attr_t *ira, int process_flag, uint8_t tag)
{
	conn_t		*connp;
	sqproc_t	proc;
	hrtime_t	now;

	ASSERT(sqp != NULL);
	ASSERT(mp != NULL);
	ASSERT(tail != NULL);
	ASSERT(cnt > 0);
	ASSERT(MUTEX_NOT_HELD(&sqp->sq_lock));
	ASSERT(ira == NULL || cnt == 1);

	mutex_enter(&sqp->sq_lock);

	/*
	 * Try to process the packet if SQ_FILL flag is not set and
	 * we are allowed to process the squeue. The SQ_NODRAIN is
	 * ignored if the packet chain consists of more than 1 packet.
	 */
	if (!(sqp->sq_state & SQS_PROC) && ((process_flag == SQ_PROCESS) ||
	    (process_flag == SQ_NODRAIN && sqp->sq_first == NULL))) {
		/*
		 * See if anything is already queued. If we are the
		 * first packet, do inline processing else queue the
		 * packet and do the drain.
		 */
		if (sqp->sq_first == NULL && cnt == 1) {
			/*
			 * Fast-path, ok to process and nothing queued.
			 */
			sqp->sq_state |= (SQS_PROC|SQS_FAST);
			sqp->sq_run = curthread;
			mutex_exit(&sqp->sq_lock);

			/*
			 * We are the chain of 1 packet so
			 * go through this fast path.
			 */
			ASSERT(mp->b_prev != NULL);
			ASSERT(mp->b_queue != NULL);
			connp = (conn_t *)mp->b_prev;
			mp->b_prev = NULL;
			proc = (sqproc_t)mp->b_queue;
			mp->b_queue = NULL;
			ASSERT(proc != NULL && connp != NULL);
			ASSERT(mp->b_next == NULL);

			/*
			 * Handle squeue switching. More details in the
			 * block comment at the top of the file
			 */
			if (connp->conn_sqp == sqp) {
				SQUEUE_DBG_SET(sqp, mp, proc, connp,
				    tag);
				connp->conn_on_sqp = B_TRUE;
				DTRACE_PROBE3(squeue__proc__start, squeue_t *,
				    sqp, mblk_t *, mp, conn_t *, connp);
				(*proc)(connp, mp, sqp, ira);
				DTRACE_PROBE2(squeue__proc__end, squeue_t *,
				    sqp, conn_t *, connp);
				connp->conn_on_sqp = B_FALSE;
				SQUEUE_DBG_CLEAR(sqp);
				CONN_DEC_REF(connp);
			} else {
				SQUEUE_ENTER_ONE(connp->conn_sqp, mp, proc,
				    connp, ira, SQ_FILL, SQTAG_SQUEUE_CHANGE);
			}
			ASSERT(MUTEX_NOT_HELD(&sqp->sq_lock));
			mutex_enter(&sqp->sq_lock);
			sqp->sq_state &= ~(SQS_PROC|SQS_FAST);
			sqp->sq_run = NULL;
			if (sqp->sq_first == NULL ||
			    process_flag == SQ_NODRAIN) {
				if (sqp->sq_first != NULL) {
					squeue_worker_wakeup(sqp);
					return;
				}
				/*
				 * We processed inline our packet and nothing
				 * new has arrived. We are done. In case any
				 * control actions are pending, wake up the
				 * worker.
				 */
				if (sqp->sq_state & SQS_WORKER_THR_CONTROL)
					cv_signal(&sqp->sq_worker_cv);
				mutex_exit(&sqp->sq_lock);
				return;
			}
		} else {
			if (ira != NULL) {
				mblk_t	*attrmp;

				ASSERT(cnt == 1);
				attrmp = ip_recv_attr_to_mblk(ira);
				if (attrmp == NULL) {
					mutex_exit(&sqp->sq_lock);
					ip_drop_input("squeue: "
					    "ip_recv_attr_to_mblk",
					    mp, NULL);
					/* Caller already set b_prev/b_next */
					mp->b_prev = mp->b_next = NULL;
					freemsg(mp);
					return;
				}
				ASSERT(attrmp->b_cont == NULL);
				attrmp->b_cont = mp;
				/* Move connp and func to new */
				attrmp->b_queue = mp->b_queue;
				mp->b_queue = NULL;
				attrmp->b_prev = mp->b_prev;
				mp->b_prev = NULL;

				ASSERT(mp == tail);
				tail = mp = attrmp;
			}

			ENQUEUE_CHAIN(sqp, mp, tail, cnt);
#ifdef DEBUG
			mp->b_tag = tag;
#endif
		}
		/*
		 * We are here because either we couldn't do inline
		 * processing (because something was already queued),
		 * or we had a chain of more than one packet,
		 * or something else arrived after we were done with
		 * inline processing.
		 */
		ASSERT(MUTEX_HELD(&sqp->sq_lock));
		ASSERT(sqp->sq_first != NULL);
		now = gethrtime();
		sqp->sq_run = curthread;
		sqp->sq_drain(sqp, SQS_ENTER, now + squeue_drain_ns);

		/*
		 * If we didn't do a complete drain, the worker
		 * thread was already signalled by squeue_drain.
		 * In case any control actions are pending, wake
		 * up the worker.
		 */
		sqp->sq_run = NULL;
		if (sqp->sq_state & SQS_WORKER_THR_CONTROL)
			cv_signal(&sqp->sq_worker_cv);
		mutex_exit(&sqp->sq_lock);
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
		 *
		 * We let the thread reenter only once for the fear
		 * of stack getting blown with multiple traversal.
		 */
		connp = (conn_t *)mp->b_prev;
		if (!(sqp->sq_state & SQS_REENTER) &&
		    (process_flag != SQ_FILL) && (sqp->sq_first == NULL) &&
		    (sqp->sq_run == curthread) && (cnt == 1) &&
		    (connp->conn_on_sqp == B_FALSE)) {
			sqp->sq_state |= SQS_REENTER;
			mutex_exit(&sqp->sq_lock);

			ASSERT(mp->b_prev != NULL);
			ASSERT(mp->b_queue != NULL);

			mp->b_prev = NULL;
			proc = (sqproc_t)mp->b_queue;
			mp->b_queue = NULL;

			/*
			 * Handle squeue switching. More details in the
			 * block comment at the top of the file
			 */
			if (connp->conn_sqp == sqp) {
				connp->conn_on_sqp = B_TRUE;
				DTRACE_PROBE3(squeue__proc__start, squeue_t *,
				    sqp, mblk_t *, mp, conn_t *, connp);
				(*proc)(connp, mp, sqp, ira);
				DTRACE_PROBE2(squeue__proc__end, squeue_t *,
				    sqp, conn_t *, connp);
				connp->conn_on_sqp = B_FALSE;
				CONN_DEC_REF(connp);
			} else {
				SQUEUE_ENTER_ONE(connp->conn_sqp, mp, proc,
				    connp, ira, SQ_FILL, SQTAG_SQUEUE_CHANGE);
			}

			mutex_enter(&sqp->sq_lock);
			sqp->sq_state &= ~SQS_REENTER;
			mutex_exit(&sqp->sq_lock);
			return;
		}

		/*
		 * Queue is already being processed or there is already
		 * one or more paquets on the queue. Enqueue the
		 * packet and wakeup the squeue worker thread if the
		 * squeue is not being processed.
		 */
#ifdef DEBUG
		mp->b_tag = tag;
#endif
		if (ira != NULL) {
			mblk_t	*attrmp;

			ASSERT(cnt == 1);
			attrmp = ip_recv_attr_to_mblk(ira);
			if (attrmp == NULL) {
				mutex_exit(&sqp->sq_lock);
				ip_drop_input("squeue: ip_recv_attr_to_mblk",
				    mp, NULL);
				/* Caller already set b_prev/b_next */
				mp->b_prev = mp->b_next = NULL;
				freemsg(mp);
				return;
			}
			ASSERT(attrmp->b_cont == NULL);
			attrmp->b_cont = mp;
			/* Move connp and func to new */
			attrmp->b_queue = mp->b_queue;
			mp->b_queue = NULL;
			attrmp->b_prev = mp->b_prev;
			mp->b_prev = NULL;

			ASSERT(mp == tail);
			tail = mp = attrmp;
		}
		ENQUEUE_CHAIN(sqp, mp, tail, cnt);
		if (!(sqp->sq_state & SQS_PROC)) {
			squeue_worker_wakeup(sqp);
			return;
		}
		/*
		 * In case any control actions are pending, wake
		 * up the worker.
		 */
		if (sqp->sq_state & SQS_WORKER_THR_CONTROL)
			cv_signal(&sqp->sq_worker_cv);
		mutex_exit(&sqp->sq_lock);
		return;
	}
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
		sqp->sq_awaken = ddi_get_lbolt();
		cv_signal(&sqp->sq_worker_cv);
	}
	mutex_exit(&sqp->sq_lock);
}

static void
squeue_drain(squeue_t *sqp, uint_t proc_type, hrtime_t expire)
{
	mblk_t		*mp;
	mblk_t 		*head;
	sqproc_t 	proc;
	conn_t		*connp;
	timeout_id_t 	tid;
	ill_rx_ring_t	*sq_rx_ring = sqp->sq_rx_ring;
	hrtime_t 	now;
	boolean_t	did_wakeup = B_FALSE;
	boolean_t	sq_poll_capable;
	ip_recv_attr_t	*ira, iras;

	sq_poll_capable = (sqp->sq_state & SQS_POLL_CAPAB) != 0;
again:
	ASSERT(mutex_owned(&sqp->sq_lock));
	ASSERT(!(sqp->sq_state & (SQS_POLL_THR_QUIESCED |
	    SQS_POLL_QUIESCE_DONE)));

	head = sqp->sq_first;
	sqp->sq_first = NULL;
	sqp->sq_last = NULL;
	sqp->sq_count = 0;

	if ((tid = sqp->sq_tid) != 0)
		sqp->sq_tid = 0;

	sqp->sq_state |= SQS_PROC | proc_type;

	/*
	 * We have backlog built up. Switch to polling mode if the
	 * device underneath allows it. Need to do it so that
	 * more packets don't come in and disturb us (by contending
	 * for sq_lock or higher priority thread preempting us).
	 *
	 * The worker thread is allowed to do active polling while we
	 * just disable the interrupts for drain by non worker (kernel
	 * or userland) threads so they can peacefully process the
	 * packets during time allocated to them.
	 */
	SQS_POLLING_ON(sqp, sq_poll_capable, sq_rx_ring);
	mutex_exit(&sqp->sq_lock);

	if (tid != 0)
		(void) untimeout(tid);

	while ((mp = head) != NULL) {

		head = mp->b_next;
		mp->b_next = NULL;

		proc = (sqproc_t)mp->b_queue;
		mp->b_queue = NULL;
		connp = (conn_t *)mp->b_prev;
		mp->b_prev = NULL;

		/* Is there an ip_recv_attr_t to handle? */
		if (ip_recv_attr_is_mblk(mp)) {
			mblk_t	*attrmp = mp;

			ASSERT(attrmp->b_cont != NULL);

			mp = attrmp->b_cont;
			attrmp->b_cont = NULL;
			ASSERT(mp->b_queue == NULL);
			ASSERT(mp->b_prev == NULL);

			if (!ip_recv_attr_from_mblk(attrmp, &iras)) {
				/* The ill or ip_stack_t disappeared on us */
				ip_drop_input("ip_recv_attr_from_mblk",
				    mp, NULL);
				ira_cleanup(&iras, B_TRUE);
				CONN_DEC_REF(connp);
				continue;
			}
			ira = &iras;
		} else {
			ira = NULL;
		}


		/*
		 * Handle squeue switching. More details in the
		 * block comment at the top of the file
		 */
		if (connp->conn_sqp == sqp) {
			SQUEUE_DBG_SET(sqp, mp, proc, connp,
			    mp->b_tag);
			connp->conn_on_sqp = B_TRUE;
			DTRACE_PROBE3(squeue__proc__start, squeue_t *,
			    sqp, mblk_t *, mp, conn_t *, connp);
			(*proc)(connp, mp, sqp, ira);
			DTRACE_PROBE2(squeue__proc__end, squeue_t *,
			    sqp, conn_t *, connp);
			connp->conn_on_sqp = B_FALSE;
			CONN_DEC_REF(connp);
		} else {
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp, proc, connp, ira,
			    SQ_FILL, SQTAG_SQUEUE_CHANGE);
		}
		if (ira != NULL)
			ira_cleanup(ira, B_TRUE);
	}

	SQUEUE_DBG_CLEAR(sqp);

	mutex_enter(&sqp->sq_lock);

	/*
	 * Check if there is still work to do (either more arrived or timer
	 * expired). If we are the worker thread and we are polling capable,
	 * continue doing the work since no one else is around to do the
	 * work anyway (but signal the poll thread to retrieve some packets
	 * in the meanwhile). If we are not the worker thread, just
	 * signal the worker thread to take up the work if processing time
	 * has expired.
	 */
	if (sqp->sq_first != NULL) {
		/*
		 * Still more to process. If time quanta not expired, we
		 * should let the drain go on. The worker thread is allowed
		 * to drain as long as there is anything left.
		 */
		now = gethrtime();
		if ((now < expire) || (proc_type == SQS_WORKER)) {
			/*
			 * If time not expired or we are worker thread and
			 * this squeue is polling capable, continue to do
			 * the drain.
			 *
			 * We turn off interrupts for all userland threads
			 * doing drain but we do active polling only for
			 * worker thread.
			 *
			 * Calling SQS_POLL_RING() even in the case of
			 * SQS_POLLING_ON() not succeeding is ok as
			 * SQS_POLL_RING() will not wake up poll thread
			 * if SQS_POLLING bit is not set.
			 */
			if (proc_type == SQS_WORKER)
				SQS_POLL_RING(sqp);
			goto again;
		} else {
			did_wakeup = B_TRUE;
			sqp->sq_awaken = ddi_get_lbolt();
			cv_signal(&sqp->sq_worker_cv);
		}
	}

	/*
	 * If the poll thread is already running, just return. The
	 * poll thread continues to hold the proc and will finish
	 * processing.
	 */
	if (sqp->sq_state & SQS_GET_PKTS) {
		ASSERT(!(sqp->sq_state & (SQS_POLL_THR_QUIESCED |
		    SQS_POLL_QUIESCE_DONE)));
		sqp->sq_state &= ~proc_type;
		return;
	}

	/*
	 *
	 * If we are the worker thread and no work is left, send the poll
	 * thread down once more to see if something arrived. Otherwise,
	 * turn the interrupts back on and we are done.
	 */
	if ((proc_type == SQS_WORKER) && (sqp->sq_state & SQS_POLLING)) {
		/*
		 * Do one last check to see if anything arrived
		 * in the NIC. We leave the SQS_PROC set to ensure
		 * that poll thread keeps the PROC and can decide
		 * if it needs to turn polling off or continue
		 * processing.
		 *
		 * If we drop the SQS_PROC here and poll thread comes
		 * up empty handed, it can not safely turn polling off
		 * since someone else could have acquired the PROC
		 * and started draining. The previously running poll
		 * thread and the current thread doing drain would end
		 * up in a race for turning polling on/off and more
		 * complex code would be required to deal with it.
		 *
		 * Its lot simpler for drain to hand the SQS_PROC to
		 * poll thread (if running) and let poll thread finish
		 * without worrying about racing with any other thread.
		 */
		ASSERT(!(sqp->sq_state & (SQS_POLL_THR_QUIESCED |
		    SQS_POLL_QUIESCE_DONE)));
		SQS_POLL_RING(sqp);
		sqp->sq_state &= ~proc_type;
	} else {
		/*
		 * The squeue is either not capable of polling or the
		 * attempt to blank (i.e., turn SQS_POLLING_ON()) was
		 * unsuccessful or poll thread already finished
		 * processing and didn't find anything. Since there
		 * is nothing queued and we already turn polling on
		 * (for all threads doing drain), we should turn
		 * polling off and relinquish the PROC.
		 */
		ASSERT(!(sqp->sq_state & (SQS_POLL_THR_QUIESCED |
		    SQS_POLL_QUIESCE_DONE)));
		SQS_POLLING_OFF(sqp, sq_poll_capable, sq_rx_ring);
		sqp->sq_state &= ~(SQS_PROC | proc_type);
		if (!did_wakeup && sqp->sq_first != NULL) {
			squeue_worker_wakeup(sqp);
			mutex_enter(&sqp->sq_lock);
		}
		/*
		 * If we are not the worker and there is a pending quiesce
		 * event, wake up the worker
		 */
		if ((proc_type != SQS_WORKER) &&
		    (sqp->sq_state & SQS_WORKER_THR_CONTROL))
			cv_signal(&sqp->sq_worker_cv);
	}
}

/*
 * Quiesce, Restart, or Cleanup of the squeue poll thread.
 *
 * Quiesce and Restart: After an squeue poll thread has been quiesced, it does
 * not attempt to poll the underlying soft ring any more. The quiesce is
 * triggered by the mac layer when it wants to quiesce a soft ring. Typically
 * control operations such as changing the fanout of a NIC or VNIC (dladm
 * setlinkprop) need to quiesce data flow before changing the wiring.
 * The operation is done by the mac layer, but it calls back into IP to
 * quiesce the soft ring. After completing the operation (say increase or
 * decrease of the fanout) the mac layer then calls back into IP to restart
 * the quiesced soft ring.
 *
 * Cleanup: This is triggered when the squeue binding to a soft ring is
 * removed permanently. Typically interface plumb and unplumb would trigger
 * this. It can also be triggered from the mac layer when a soft ring is
 * being deleted say as the result of a fanout reduction. Since squeues are
 * never deleted, the cleanup marks the squeue as fit for recycling and
 * moves it to the zeroth squeue set.
 */
static void
squeue_poll_thr_control(squeue_t *sqp)
{
	if (sqp->sq_state & SQS_POLL_THR_RESTART) {
		/* Restart implies a previous quiesce */
		ASSERT(sqp->sq_state & SQS_POLL_THR_QUIESCED);
		sqp->sq_state &= ~(SQS_POLL_THR_QUIESCED |
		    SQS_POLL_THR_RESTART);
		sqp->sq_state |= SQS_POLL_CAPAB;
		cv_signal(&sqp->sq_worker_cv);
		return;
	}

	if (sqp->sq_state & SQS_POLL_THR_QUIESCE) {
		sqp->sq_state |= SQS_POLL_THR_QUIESCED;
		sqp->sq_state &= ~SQS_POLL_THR_QUIESCE;
		cv_signal(&sqp->sq_worker_cv);
		return;
	}
}

/*
 * POLLING Notes
 *
 * With polling mode, we want to do as much processing as we possibly can
 * in worker thread context. The sweet spot is worker thread keeps doing
 * work all the time in polling mode and writers etc. keep dumping packets
 * to worker thread. Occassionally, we send the poll thread (running at
 * lower priority to NIC to get the chain of packets to feed to worker).
 * Sending the poll thread down to NIC is dependant on 3 criterions
 *
 * 1) Its always driven from squeue_drain and only if worker thread is
 *	doing the drain.
 * 2) We clear the backlog once and more packets arrived in between.
 *	Before starting drain again, send the poll thread down if
 *	the drain is being done by worker thread.
 * 3) Before exiting the squeue_drain, if the poll thread is not already
 *	working and we are the worker thread, try to poll one more time.
 *
 * For latency sake, we do allow any thread calling squeue_enter
 * to process its packet provided:
 *
 * 1) Nothing is queued
 * 2) If more packets arrived in between, the non worker thread are allowed
 *	to do the drain till their time quanta expired provided SQS_GET_PKTS
 *	wasn't set in between.
 *
 * Avoiding deadlocks with interrupts
 * ==================================
 *
 * One of the big problem is that we can't send poll_thr down while holding
 * the sq_lock since the thread can block. So we drop the sq_lock before
 * calling sq_get_pkts(). We keep holding the SQS_PROC as long as the
 * poll thread is running so that no other thread can acquire the
 * perimeter in between. If the squeue_drain gets done (no more work
 * left), it leaves the SQS_PROC set if poll thread is running.
 */

/*
 * This is the squeue poll thread. In poll mode, it polls the underlying
 * TCP softring and feeds packets into the squeue. The worker thread then
 * drains the squeue. The poll thread also responds to control signals for
 * quiesceing, restarting, or cleanup of an squeue. These are driven by
 * control operations like plumb/unplumb or as a result of dynamic Rx ring
 * related operations that are driven from the mac layer.
 */
static void
squeue_polling_thread(squeue_t *sqp)
{
	kmutex_t *lock = &sqp->sq_lock;
	kcondvar_t *async = &sqp->sq_poll_cv;
	ip_mac_rx_t sq_get_pkts;
	ip_accept_t ip_accept;
	ill_rx_ring_t *sq_rx_ring;
	ill_t *sq_ill;
	mblk_t *head, *tail, *mp;
	uint_t cnt;
	void *sq_mac_handle;
	callb_cpr_t cprinfo;
	size_t bytes_to_pickup;
	uint32_t ctl_state;

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "sq_poll");
	mutex_enter(lock);

	for (;;) {
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(async, lock);
		CALLB_CPR_SAFE_END(&cprinfo, lock);

		ctl_state = sqp->sq_state & (SQS_POLL_THR_CONTROL |
		    SQS_POLL_THR_QUIESCED);
		if (ctl_state != 0) {
			/*
			 * If the squeue is quiesced, then wait for a control
			 * request. A quiesced squeue must not poll the
			 * underlying soft ring.
			 */
			if (ctl_state == SQS_POLL_THR_QUIESCED)
				continue;
			/*
			 * Act on control requests to quiesce, cleanup or
			 * restart an squeue
			 */
			squeue_poll_thr_control(sqp);
			continue;
		}

		if (!(sqp->sq_state & SQS_POLL_CAPAB))
			continue;

		ASSERT((sqp->sq_state &
		    (SQS_PROC|SQS_POLLING|SQS_GET_PKTS)) ==
		    (SQS_PROC|SQS_POLLING|SQS_GET_PKTS));

poll_again:
		sq_rx_ring = sqp->sq_rx_ring;
		sq_get_pkts = sq_rx_ring->rr_rx;
		sq_mac_handle = sq_rx_ring->rr_rx_handle;
		ip_accept = sq_rx_ring->rr_ip_accept;
		sq_ill = sq_rx_ring->rr_ill;
		bytes_to_pickup = MAX_BYTES_TO_PICKUP;
		mutex_exit(lock);
		head = sq_get_pkts(sq_mac_handle, bytes_to_pickup);
		mp = NULL;
		if (head != NULL) {
			/*
			 * We got the packet chain from the mac layer. It
			 * would be nice to be able to process it inline
			 * for better performance but we need to give
			 * IP a chance to look at this chain to ensure
			 * that packets are really meant for this squeue
			 * and do the IP processing.
			 */
			mp = ip_accept(sq_ill, sq_rx_ring, sqp, head,
			    &tail, &cnt);
		}
		mutex_enter(lock);
		if (mp != NULL) {
			/*
			 * The ip_accept function has already added an
			 * ip_recv_attr_t mblk if that is needed.
			 */
			ENQUEUE_CHAIN(sqp, mp, tail, cnt);
		}
		ASSERT((sqp->sq_state &
		    (SQS_PROC|SQS_POLLING|SQS_GET_PKTS)) ==
		    (SQS_PROC|SQS_POLLING|SQS_GET_PKTS));

		if (sqp->sq_first != NULL && !(sqp->sq_state & SQS_WORKER)) {
			/*
			 * We have packets to process and worker thread
			 * is not running.  Check to see if poll thread is
			 * allowed to process. Let it do processing only if it
			 * picked up some packets from the NIC otherwise
			 * wakeup the worker thread.
			 */
			if (mp != NULL) {
				hrtime_t  now;

				now = gethrtime();
				sqp->sq_run = curthread;
				sqp->sq_drain(sqp, SQS_POLL_PROC, now +
				    squeue_drain_ns);
				sqp->sq_run = NULL;

				if (sqp->sq_first == NULL)
					goto poll_again;

				/*
				 * Couldn't do the entire drain because the
				 * time limit expired, let the
				 * worker thread take over.
				 */
			}

			sqp->sq_awaken = ddi_get_lbolt();
			/*
			 * Put the SQS_PROC_HELD on so the worker
			 * thread can distinguish where its called from. We
			 * can remove the SQS_PROC flag here and turn off the
			 * polling so that it wouldn't matter who gets the
			 * processing but we get better performance this way
			 * and save the cost of turn polling off and possibly
			 * on again as soon as we start draining again.
			 *
			 * We can't remove the SQS_PROC flag without turning
			 * polling off until we can guarantee that control
			 * will return to squeue_drain immediately.
			 */
			sqp->sq_state |= SQS_PROC_HELD;
			sqp->sq_state &= ~SQS_GET_PKTS;
			cv_signal(&sqp->sq_worker_cv);
		} else if (sqp->sq_first == NULL &&
		    !(sqp->sq_state & SQS_WORKER)) {
			/*
			 * Nothing queued and worker thread not running.
			 * Since we hold the proc, no other thread is
			 * processing the squeue. This means that there
			 * is no work to be done and nothing is queued
			 * in squeue or in NIC. Turn polling off and go
			 * back to interrupt mode.
			 */
			sqp->sq_state &= ~(SQS_PROC|SQS_GET_PKTS);
			/* LINTED: constant in conditional context */
			SQS_POLLING_OFF(sqp, B_TRUE, sq_rx_ring);

			/*
			 * If there is a pending control operation
			 * wake up the worker, since it is currently
			 * not running.
			 */
			if (sqp->sq_state & SQS_WORKER_THR_CONTROL)
				cv_signal(&sqp->sq_worker_cv);
		} else {
			/*
			 * Worker thread is already running. We don't need
			 * to do anything. Indicate that poll thread is done.
			 */
			sqp->sq_state &= ~SQS_GET_PKTS;
		}
		if (sqp->sq_state & SQS_POLL_THR_CONTROL) {
			/*
			 * Act on control requests to quiesce, cleanup or
			 * restart an squeue
			 */
			squeue_poll_thr_control(sqp);
		}
	}
}

/*
 * The squeue worker thread acts on any control requests to quiesce, cleanup
 * or restart an ill_rx_ring_t by calling this function. The worker thread
 * synchronizes with the squeue poll thread to complete the request and finally
 * wakes up the requestor when the request is completed.
 */
static void
squeue_worker_thr_control(squeue_t *sqp)
{
	ill_t	*ill;
	ill_rx_ring_t	*rx_ring;

	ASSERT(MUTEX_HELD(&sqp->sq_lock));

	if (sqp->sq_state & SQS_POLL_RESTART) {
		/* Restart implies a previous quiesce. */
		ASSERT((sqp->sq_state & (SQS_PROC_HELD |
		    SQS_POLL_QUIESCE_DONE | SQS_PROC | SQS_WORKER)) ==
		    (SQS_POLL_QUIESCE_DONE | SQS_PROC | SQS_WORKER));
		/*
		 * Request the squeue poll thread to restart and wait till
		 * it actually restarts.
		 */
		sqp->sq_state &= ~SQS_POLL_QUIESCE_DONE;
		sqp->sq_state |= SQS_POLL_THR_RESTART;
		cv_signal(&sqp->sq_poll_cv);
		while (sqp->sq_state & SQS_POLL_THR_QUIESCED)
			cv_wait(&sqp->sq_worker_cv, &sqp->sq_lock);
		sqp->sq_state &= ~(SQS_POLL_RESTART | SQS_PROC |
		    SQS_WORKER);
		/*
		 * Signal any waiter that is waiting for the restart
		 * to complete
		 */
		sqp->sq_state |= SQS_POLL_RESTART_DONE;
		cv_signal(&sqp->sq_ctrlop_done_cv);
		return;
	}

	if (sqp->sq_state & SQS_PROC_HELD) {
		/* The squeue poll thread handed control to us */
		ASSERT(sqp->sq_state & SQS_PROC);
	}

	/*
	 * Prevent any other thread from processing the squeue
	 * until we finish the control actions by setting SQS_PROC.
	 * But allow ourself to reenter by setting SQS_WORKER
	 */
	sqp->sq_state |= (SQS_PROC | SQS_WORKER);

	/* Signal the squeue poll thread and wait for it to quiesce itself */
	if (!(sqp->sq_state & SQS_POLL_THR_QUIESCED)) {
		sqp->sq_state |= SQS_POLL_THR_QUIESCE;
		cv_signal(&sqp->sq_poll_cv);
		while (!(sqp->sq_state & SQS_POLL_THR_QUIESCED))
			cv_wait(&sqp->sq_worker_cv, &sqp->sq_lock);
	}

	rx_ring = sqp->sq_rx_ring;
	ill = rx_ring->rr_ill;
	/*
	 * The lock hierarchy is as follows.
	 * cpu_lock -> ill_lock -> sqset_lock -> sq_lock
	 */
	mutex_exit(&sqp->sq_lock);
	mutex_enter(&ill->ill_lock);
	mutex_enter(&sqp->sq_lock);

	SQS_POLLING_OFF(sqp, (sqp->sq_state & SQS_POLL_CAPAB) != 0,
	    sqp->sq_rx_ring);
	sqp->sq_state &= ~(SQS_POLL_CAPAB | SQS_GET_PKTS | SQS_PROC_HELD);
	if (sqp->sq_state & SQS_POLL_CLEANUP) {
		/*
		 * Disassociate this squeue from its ill_rx_ring_t.
		 * The rr_sqp, sq_rx_ring fields are protected by the
		 * corresponding squeue, ill_lock* and sq_lock. Holding any
		 * of them will ensure that the ring to squeue mapping does
		 * not change.
		 */
		ASSERT(!(sqp->sq_state & SQS_DEFAULT));

		sqp->sq_rx_ring = NULL;
		rx_ring->rr_sqp = NULL;

		sqp->sq_state &= ~(SQS_POLL_CLEANUP | SQS_POLL_THR_QUIESCED |
		    SQS_POLL_QUIESCE_DONE);
		sqp->sq_ill = NULL;

		rx_ring->rr_rx_handle = NULL;
		rx_ring->rr_intr_handle = NULL;
		rx_ring->rr_intr_enable = NULL;
		rx_ring->rr_intr_disable = NULL;
		sqp->sq_state |= SQS_POLL_CLEANUP_DONE;
	} else {
		sqp->sq_state &= ~SQS_POLL_QUIESCE;
		sqp->sq_state |= SQS_POLL_QUIESCE_DONE;
	}
	/*
	 * Signal any waiter that is waiting for the quiesce or cleanup
	 * to complete and also wait for it to actually see and reset the
	 * SQS_POLL_CLEANUP_DONE.
	 */
	cv_signal(&sqp->sq_ctrlop_done_cv);
	mutex_exit(&ill->ill_lock);
	if (sqp->sq_state & SQS_POLL_CLEANUP_DONE) {
		cv_wait(&sqp->sq_worker_cv, &sqp->sq_lock);
		sqp->sq_state &= ~(SQS_PROC | SQS_WORKER);
	}
}

static void
squeue_worker(squeue_t *sqp)
{
	kmutex_t *lock = &sqp->sq_lock;
	kcondvar_t *async = &sqp->sq_worker_cv;
	callb_cpr_t cprinfo;
	hrtime_t now;

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "sq_worker");
	mutex_enter(lock);

	for (;;) {
		for (;;) {
			/*
			 * If the poll thread has handed control to us
			 * we need to break out of the wait.
			 */
			if (sqp->sq_state & SQS_PROC_HELD)
				break;

			/*
			 * If the squeue is not being processed and we either
			 * have messages to drain or some thread has signaled
			 * some control activity we need to break
			 */
			if (!(sqp->sq_state & SQS_PROC) &&
			    ((sqp->sq_state & SQS_WORKER_THR_CONTROL) ||
			    (sqp->sq_first != NULL)))
				break;

			/*
			 * If we have started some control action, then check
			 * for the SQS_WORKER flag (since we don't
			 * release the squeue) to make sure we own the squeue
			 * and break out
			 */
			if ((sqp->sq_state & SQS_WORKER_THR_CONTROL) &&
			    (sqp->sq_state & SQS_WORKER))
				break;

			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(async, lock);
			CALLB_CPR_SAFE_END(&cprinfo, lock);
		}
		if (sqp->sq_state & SQS_WORKER_THR_CONTROL) {
			squeue_worker_thr_control(sqp);
			continue;
		}
		ASSERT(!(sqp->sq_state & (SQS_POLL_THR_QUIESCED |
		    SQS_POLL_CLEANUP_DONE | SQS_POLL_QUIESCE_DONE |
		    SQS_WORKER_THR_CONTROL | SQS_POLL_THR_CONTROL)));

		if (sqp->sq_state & SQS_PROC_HELD)
			sqp->sq_state &= ~SQS_PROC_HELD;

		now = gethrtime();
		sqp->sq_run = curthread;
		sqp->sq_drain(sqp, SQS_WORKER, now +  squeue_drain_ns);
		sqp->sq_run = NULL;
	}
}

uintptr_t *
squeue_getprivate(squeue_t *sqp, sqprivate_t p)
{
	ASSERT(p < SQPRIVATE_MAX);

	return (&sqp->sq_private[p]);
}

/* ARGSUSED */
void
squeue_wakeup_conn(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t *connp = (conn_t *)arg;
	squeue_t *sqp = connp->conn_sqp;

	/*
	 * Mark the squeue as paused before waking up the thread stuck
	 * in squeue_synch_enter().
	 */
	mutex_enter(&sqp->sq_lock);
	sqp->sq_state |= SQS_PAUSE;

	/*
	 * Notify the thread that it's OK to proceed; that is done by
	 * clearing the MSGWAITSYNC flag. The synch thread will free the mblk.
	 */
	ASSERT(mp->b_flag & MSGWAITSYNC);
	mp->b_flag &= ~MSGWAITSYNC;
	cv_broadcast(&connp->conn_sq_cv);

	/*
	 * We are doing something on behalf of another thread, so we have to
	 * pause and wait until it finishes.
	 */
	while (sqp->sq_state & SQS_PAUSE) {
		cv_wait(&sqp->sq_synch_cv, &sqp->sq_lock);
	}
	mutex_exit(&sqp->sq_lock);
}

int
squeue_synch_enter(conn_t *connp, mblk_t *use_mp)
{
	squeue_t *sqp;

again:
	sqp = connp->conn_sqp;

	mutex_enter(&sqp->sq_lock);
	if (sqp->sq_first == NULL && !(sqp->sq_state & SQS_PROC)) {
		/*
		 * We are OK to proceed if the squeue is empty, and
		 * no one owns the squeue.
		 *
		 * The caller won't own the squeue as this is called from the
		 * application.
		 */
		ASSERT(sqp->sq_run == NULL);

		sqp->sq_state |= SQS_PROC;
		sqp->sq_run = curthread;
		mutex_exit(&sqp->sq_lock);

		/*
		 * Handle squeue switching. The conn's squeue can only change
		 * while there is a thread in the squeue, which is why we do
		 * the check after entering the squeue. If it has changed, exit
		 * this squeue and redo everything with the new sqeueue.
		 */
		if (sqp != connp->conn_sqp) {
			mutex_enter(&sqp->sq_lock);
			sqp->sq_state &= ~SQS_PROC;
			sqp->sq_run = NULL;
			mutex_exit(&sqp->sq_lock);
			goto again;
		}
#if SQUEUE_DEBUG
		sqp->sq_curmp = NULL;
		sqp->sq_curproc = NULL;
		sqp->sq_connp = connp;
#endif
		connp->conn_on_sqp = B_TRUE;
		return (0);
	} else {
		mblk_t  *mp;

		mp = (use_mp == NULL) ? allocb(0, BPRI_MED) : use_mp;
		if (mp == NULL) {
			mutex_exit(&sqp->sq_lock);
			return (ENOMEM);
		}

		/*
		 * We mark the mblk as awaiting synchronous squeue access
		 * by setting the MSGWAITSYNC flag. Once squeue_wakeup_conn
		 * fires, MSGWAITSYNC is cleared, at which point we know we
		 * have exclusive access.
		 */
		mp->b_flag |= MSGWAITSYNC;

		CONN_INC_REF(connp);
		SET_SQUEUE(mp, squeue_wakeup_conn, connp);
		ENQUEUE_CHAIN(sqp, mp, mp, 1);

		ASSERT(sqp->sq_run != curthread);

		/* Wait until the enqueued mblk get processed. */
		while (mp->b_flag & MSGWAITSYNC)
			cv_wait(&connp->conn_sq_cv, &sqp->sq_lock);
		mutex_exit(&sqp->sq_lock);

		if (use_mp == NULL)
			freeb(mp);

		return (0);
	}
}

void
squeue_synch_exit(conn_t *connp)
{
	squeue_t *sqp = connp->conn_sqp;

	mutex_enter(&sqp->sq_lock);
	if (sqp->sq_run == curthread) {
		ASSERT(sqp->sq_state & SQS_PROC);

		sqp->sq_state &= ~SQS_PROC;
		sqp->sq_run = NULL;
		connp->conn_on_sqp = B_FALSE;

		if (sqp->sq_first == NULL) {
			mutex_exit(&sqp->sq_lock);
		} else {
			/*
			 * If this was a normal thread, then it would
			 * (most likely) continue processing the pending
			 * requests. Since the just completed operation
			 * was executed synchronously, the thread should
			 * not be delayed. To compensate, wake up the
			 * worker thread right away when there are outstanding
			 * requests.
			 */
			sqp->sq_awaken = ddi_get_lbolt();
			cv_signal(&sqp->sq_worker_cv);
			mutex_exit(&sqp->sq_lock);
		}
	} else {
		/*
		 * The caller doesn't own the squeue, clear the SQS_PAUSE flag,
		 * and wake up the squeue owner, such that owner can continue
		 * processing.
		 */
		ASSERT(sqp->sq_state & SQS_PAUSE);
		sqp->sq_state &= ~SQS_PAUSE;

		/* There should be only one thread blocking on sq_synch_cv. */
		cv_signal(&sqp->sq_synch_cv);
		mutex_exit(&sqp->sq_lock);
	}
}
