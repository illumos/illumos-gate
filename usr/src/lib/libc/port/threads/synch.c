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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sdt.h>

#include "lint.h"
#include "thr_uberdata.h"

/*
 * This mutex is initialized to be held by lwp#1.
 * It is used to block a thread that has returned from a mutex_lock()
 * of a LOCK_PRIO_INHERIT mutex with an unrecoverable error.
 */
mutex_t	stall_mutex = DEFAULTMUTEX;

static int shared_mutex_held(mutex_t *);
static int mutex_unlock_internal(mutex_t *, int);
static int mutex_queuelock_adaptive(mutex_t *);
static void mutex_wakeup_all(mutex_t *);

/*
 * Lock statistics support functions.
 */
void
record_begin_hold(tdb_mutex_stats_t *msp)
{
	tdb_incr(msp->mutex_lock);
	msp->mutex_begin_hold = gethrtime();
}

hrtime_t
record_hold_time(tdb_mutex_stats_t *msp)
{
	hrtime_t now = gethrtime();

	if (msp->mutex_begin_hold)
		msp->mutex_hold_time += now - msp->mutex_begin_hold;
	msp->mutex_begin_hold = 0;
	return (now);
}

/*
 * Called once at library initialization.
 */
void
mutex_setup(void)
{
	if (set_lock_byte(&stall_mutex.mutex_lockw))
		thr_panic("mutex_setup() cannot acquire stall_mutex");
	stall_mutex.mutex_owner = (uintptr_t)curthread;
}

/*
 * The default spin count of 1000 is experimentally determined.
 * On sun4u machines with any number of processors it could be raised
 * to 10,000 but that (experimentally) makes almost no difference.
 * The environment variable:
 *	_THREAD_ADAPTIVE_SPIN=count
 * can be used to override and set the count in the range [0 .. 1,000,000].
 */
int	thread_adaptive_spin = 1000;
uint_t	thread_max_spinners = 100;
int	thread_queue_verify = 0;
static	int	ncpus;

/*
 * Distinguish spinning for queue locks from spinning for regular locks.
 * We try harder to acquire queue locks by spinning.
 * The environment variable:
 *	_THREAD_QUEUE_SPIN=count
 * can be used to override and set the count in the range [0 .. 1,000,000].
 */
int	thread_queue_spin = 10000;

#define	ALL_ATTRIBUTES				\
	(LOCK_RECURSIVE | LOCK_ERRORCHECK |	\
	LOCK_PRIO_INHERIT | LOCK_PRIO_PROTECT |	\
	LOCK_ROBUST)

/*
 * 'type' can be one of USYNC_THREAD, USYNC_PROCESS, or USYNC_PROCESS_ROBUST,
 * augmented by zero or more the flags:
 *	LOCK_RECURSIVE
 *	LOCK_ERRORCHECK
 *	LOCK_PRIO_INHERIT
 *	LOCK_PRIO_PROTECT
 *	LOCK_ROBUST
 */
#pragma weak _private_mutex_init = __mutex_init
#pragma weak mutex_init = __mutex_init
#pragma weak _mutex_init = __mutex_init
/* ARGSUSED2 */
int
__mutex_init(mutex_t *mp, int type, void *arg)
{
	int basetype = (type & ~ALL_ATTRIBUTES);
	int error = 0;

	if (basetype == USYNC_PROCESS_ROBUST) {
		/*
		 * USYNC_PROCESS_ROBUST is a deprecated historical type.
		 * We change it into (USYNC_PROCESS | LOCK_ROBUST) but
		 * retain the USYNC_PROCESS_ROBUST flag so we can return
		 * ELOCKUNMAPPED when necessary (only USYNC_PROCESS_ROBUST
		 * mutexes will ever draw ELOCKUNMAPPED).
		 */
		type |= (USYNC_PROCESS | LOCK_ROBUST);
		basetype = USYNC_PROCESS;
	}

	if (!(basetype == USYNC_THREAD || basetype == USYNC_PROCESS) ||
	    (type & (LOCK_PRIO_INHERIT | LOCK_PRIO_PROTECT))
	    == (LOCK_PRIO_INHERIT | LOCK_PRIO_PROTECT)) {
		error = EINVAL;
	} else if (type & LOCK_ROBUST) {
		/*
		 * Callers of mutex_init() with the LOCK_ROBUST attribute
		 * are required to pass an initially all-zero mutex.
		 * Multiple calls to mutex_init() are allowed; all but
		 * the first return EBUSY.  A call to mutex_init() is
		 * allowed to make an inconsistent robust lock consistent
		 * (for historical usage, even though the proper interface
		 * for this is mutex_consistent()).  Note that we use
		 * atomic_or_16() to set the LOCK_INITED flag so as
		 * not to disturb surrounding bits (LOCK_OWNERDEAD, etc).
		 */
		extern void _atomic_or_16(volatile uint16_t *, uint16_t);
		if (!(mp->mutex_flag & LOCK_INITED)) {
			mp->mutex_type = (uint8_t)type;
			_atomic_or_16(&mp->mutex_flag, LOCK_INITED);
			mp->mutex_magic = MUTEX_MAGIC;
		} else if (type != mp->mutex_type ||
		    ((type & LOCK_PRIO_PROTECT) &&
		    mp->mutex_ceiling != (*(int *)arg))) {
			error = EINVAL;
		} else if (__mutex_consistent(mp) != 0) {
			error = EBUSY;
		}
		/* register a process robust mutex with the kernel */
		if (basetype == USYNC_PROCESS)
			register_lock(mp);
	} else {
		(void) _memset(mp, 0, sizeof (*mp));
		mp->mutex_type = (uint8_t)type;
		mp->mutex_flag = LOCK_INITED;
		mp->mutex_magic = MUTEX_MAGIC;
	}

	if (error == 0 && (type & LOCK_PRIO_PROTECT))
		mp->mutex_ceiling = (uint8_t)(*(int *)arg);

	return (error);
}

/*
 * Delete mp from list of ceil mutexes owned by curthread.
 * Return 1 if the head of the chain was updated.
 */
int
_ceil_mylist_del(mutex_t *mp)
{
	ulwp_t *self = curthread;
	mxchain_t **mcpp;
	mxchain_t *mcp;

	mcpp = &self->ul_mxchain;
	while ((*mcpp)->mxchain_mx != mp)
		mcpp = &(*mcpp)->mxchain_next;
	mcp = *mcpp;
	*mcpp = mcp->mxchain_next;
	lfree(mcp, sizeof (*mcp));
	return (mcpp == &self->ul_mxchain);
}

/*
 * Add mp to head of list of ceil mutexes owned by curthread.
 * Return ENOMEM if no memory could be allocated.
 */
int
_ceil_mylist_add(mutex_t *mp)
{
	ulwp_t *self = curthread;
	mxchain_t *mcp;

	if ((mcp = lmalloc(sizeof (*mcp))) == NULL)
		return (ENOMEM);
	mcp->mxchain_mx = mp;
	mcp->mxchain_next = self->ul_mxchain;
	self->ul_mxchain = mcp;
	return (0);
}

/*
 * Inherit priority from ceiling.  The inheritance impacts the effective
 * priority, not the assigned priority.  See _thread_setschedparam_main().
 */
void
_ceil_prio_inherit(int ceil)
{
	ulwp_t *self = curthread;
	struct sched_param param;

	(void) _memset(&param, 0, sizeof (param));
	param.sched_priority = ceil;
	if (_thread_setschedparam_main(self->ul_lwpid,
	    self->ul_policy, &param, PRIO_INHERIT)) {
		/*
		 * Panic since unclear what error code to return.
		 * If we do return the error codes returned by above
		 * called routine, update the man page...
		 */
		thr_panic("_thread_setschedparam_main() fails");
	}
}

/*
 * Waive inherited ceiling priority.  Inherit from head of owned ceiling locks
 * if holding at least one ceiling lock.  If no ceiling locks are held at this
 * point, disinherit completely, reverting back to assigned priority.
 */
void
_ceil_prio_waive(void)
{
	ulwp_t *self = curthread;
	struct sched_param param;

	(void) _memset(&param, 0, sizeof (param));
	if (self->ul_mxchain == NULL) {
		/*
		 * No ceil locks held.  Zero the epri, revert back to ul_pri.
		 * Since thread's hash lock is not held, one cannot just
		 * read ul_pri here...do it in the called routine...
		 */
		param.sched_priority = self->ul_pri;	/* ignored */
		if (_thread_setschedparam_main(self->ul_lwpid,
		    self->ul_policy, &param, PRIO_DISINHERIT))
			thr_panic("_thread_setschedparam_main() fails");
	} else {
		/*
		 * Set priority to that of the mutex at the head
		 * of the ceilmutex chain.
		 */
		param.sched_priority =
		    self->ul_mxchain->mxchain_mx->mutex_ceiling;
		if (_thread_setschedparam_main(self->ul_lwpid,
		    self->ul_policy, &param, PRIO_INHERIT))
			thr_panic("_thread_setschedparam_main() fails");
	}
}

/*
 * Clear the lock byte.  Retain the waiters byte and the spinners byte.
 * Return the old value of the lock word.
 */
static uint32_t
clear_lockbyte(volatile uint32_t *lockword)
{
	uint32_t old;
	uint32_t new;

	do {
		old = *lockword;
		new = old & ~LOCKMASK;
	} while (atomic_cas_32(lockword, old, new) != old);

	return (old);
}

/*
 * Increment the spinners count in the mutex lock word.
 * Return 0 on success.  Return -1 if the count would overflow.
 */
static int
spinners_incr(volatile uint32_t *lockword, uint8_t max_spinners)
{
	uint32_t old;
	uint32_t new;

	do {
		old = *lockword;
		if (((old & SPINNERMASK) >> SPINNERSHIFT) >= max_spinners)
			return (-1);
		new = old + (1 << SPINNERSHIFT);
	} while (atomic_cas_32(lockword, old, new) != old);

	return (0);
}

/*
 * Decrement the spinners count in the mutex lock word.
 * Return the new value of the lock word.
 */
static uint32_t
spinners_decr(volatile uint32_t *lockword)
{
	uint32_t old;
	uint32_t new;

	do {
		new = old = *lockword;
		if (new & SPINNERMASK)
			new -= (1 << SPINNERSHIFT);
	} while (atomic_cas_32(lockword, old, new) != old);

	return (new);
}

/*
 * Non-preemptive spin locks.  Used by queue_lock().
 * No lock statistics are gathered for these locks.
 * No DTrace probes are provided for these locks.
 */
void
spin_lock_set(mutex_t *mp)
{
	ulwp_t *self = curthread;

	no_preempt(self);
	if (set_lock_byte(&mp->mutex_lockw) == 0) {
		mp->mutex_owner = (uintptr_t)self;
		return;
	}
	/*
	 * Spin for a while, attempting to acquire the lock.
	 */
	if (self->ul_spin_lock_spin != UINT_MAX)
		self->ul_spin_lock_spin++;
	if (mutex_queuelock_adaptive(mp) == 0 ||
	    set_lock_byte(&mp->mutex_lockw) == 0) {
		mp->mutex_owner = (uintptr_t)self;
		return;
	}
	/*
	 * Try harder if we were previously at a no premption level.
	 */
	if (self->ul_preempt > 1) {
		if (self->ul_spin_lock_spin2 != UINT_MAX)
			self->ul_spin_lock_spin2++;
		if (mutex_queuelock_adaptive(mp) == 0 ||
		    set_lock_byte(&mp->mutex_lockw) == 0) {
			mp->mutex_owner = (uintptr_t)self;
			return;
		}
	}
	/*
	 * Give up and block in the kernel for the mutex.
	 */
	if (self->ul_spin_lock_sleep != UINT_MAX)
		self->ul_spin_lock_sleep++;
	(void) ___lwp_mutex_timedlock(mp, NULL);
	mp->mutex_owner = (uintptr_t)self;
}

void
spin_lock_clear(mutex_t *mp)
{
	ulwp_t *self = curthread;

	mp->mutex_owner = 0;
	if (atomic_swap_32(&mp->mutex_lockword, 0) & WAITERMASK) {
		(void) ___lwp_mutex_wakeup(mp, 0);
		if (self->ul_spin_lock_wakeup != UINT_MAX)
			self->ul_spin_lock_wakeup++;
	}
	preempt(self);
}

/*
 * Allocate the sleep queue hash table.
 */
void
queue_alloc(void)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	mutex_t *mp;
	void *data;
	int i;

	/*
	 * No locks are needed; we call here only when single-threaded.
	 */
	ASSERT(self == udp->ulwp_one);
	ASSERT(!udp->uberflags.uf_mt);
	if ((data = _private_mmap(NULL, 2 * QHASHSIZE * sizeof (queue_head_t),
	    PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, (off_t)0))
	    == MAP_FAILED)
		thr_panic("cannot allocate thread queue_head table");
	udp->queue_head = (queue_head_t *)data;
	for (i = 0; i < 2 * QHASHSIZE; i++) {
		mp = &udp->queue_head[i].qh_lock;
		mp->mutex_flag = LOCK_INITED;
		mp->mutex_magic = MUTEX_MAGIC;
	}
}

#if defined(THREAD_DEBUG)

/*
 * Debugging: verify correctness of a sleep queue.
 */
void
QVERIFY(queue_head_t *qp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *ulwp;
	ulwp_t *prev;
	uint_t index;
	uint32_t cnt = 0;
	char qtype;
	void *wchan;

	ASSERT(qp >= udp->queue_head && (qp - udp->queue_head) < 2 * QHASHSIZE);
	ASSERT(MUTEX_OWNED(&qp->qh_lock, self));
	ASSERT((qp->qh_head != NULL && qp->qh_tail != NULL) ||
	    (qp->qh_head == NULL && qp->qh_tail == NULL));
	if (!thread_queue_verify)
		return;
	/* real expensive stuff, only for _THREAD_QUEUE_VERIFY */
	qtype = ((qp - udp->queue_head) < QHASHSIZE)? MX : CV;
	for (prev = NULL, ulwp = qp->qh_head; ulwp != NULL;
	    prev = ulwp, ulwp = ulwp->ul_link, cnt++) {
		ASSERT(ulwp->ul_qtype == qtype);
		ASSERT(ulwp->ul_wchan != NULL);
		ASSERT(ulwp->ul_sleepq == qp);
		wchan = ulwp->ul_wchan;
		index = QUEUE_HASH(wchan, qtype);
		ASSERT(&udp->queue_head[index] == qp);
	}
	ASSERT(qp->qh_tail == prev);
	ASSERT(qp->qh_qlen == cnt);
}

#else	/* THREAD_DEBUG */

#define	QVERIFY(qp)

#endif	/* THREAD_DEBUG */

/*
 * Acquire a queue head.
 */
queue_head_t *
queue_lock(void *wchan, int qtype)
{
	uberdata_t *udp = curthread->ul_uberdata;
	queue_head_t *qp;

	ASSERT(qtype == MX || qtype == CV);

	/*
	 * It is possible that we could be called while still single-threaded.
	 * If so, we call queue_alloc() to allocate the queue_head[] array.
	 */
	if ((qp = udp->queue_head) == NULL) {
		queue_alloc();
		qp = udp->queue_head;
	}
	qp += QUEUE_HASH(wchan, qtype);
	spin_lock_set(&qp->qh_lock);
	/*
	 * At once per nanosecond, qh_lockcount will wrap after 512 years.
	 * Were we to care about this, we could peg the value at UINT64_MAX.
	 */
	qp->qh_lockcount++;
	QVERIFY(qp);
	return (qp);
}

/*
 * Release a queue head.
 */
void
queue_unlock(queue_head_t *qp)
{
	QVERIFY(qp);
	spin_lock_clear(&qp->qh_lock);
}

/*
 * For rwlock queueing, we must queue writers ahead of readers of the
 * same priority.  We do this by making writers appear to have a half
 * point higher priority for purposes of priority comparisons below.
 */
#define	CMP_PRIO(ulwp)	((real_priority(ulwp) << 1) + (ulwp)->ul_writer)

void
enqueue(queue_head_t *qp, ulwp_t *ulwp, void *wchan, int qtype)
{
	ulwp_t **ulwpp;
	ulwp_t *next;
	int pri = CMP_PRIO(ulwp);
	int force_fifo = (qtype & FIFOQ);
	int do_fifo;

	qtype &= ~FIFOQ;
	ASSERT(qtype == MX || qtype == CV);
	ASSERT(MUTEX_OWNED(&qp->qh_lock, curthread));
	ASSERT(ulwp->ul_sleepq != qp);

	/*
	 * LIFO queue ordering is unfair and can lead to starvation,
	 * but it gives better performance for heavily contended locks.
	 * We use thread_queue_fifo (range is 0..8) to determine
	 * the frequency of FIFO vs LIFO queuing:
	 *	0 : every 256th time	(almost always LIFO)
	 *	1 : every 128th time
	 *	2 : every 64th  time
	 *	3 : every 32nd  time
	 *	4 : every 16th  time	(the default value, mostly LIFO)
	 *	5 : every 8th   time
	 *	6 : every 4th   time
	 *	7 : every 2nd   time
	 *	8 : every time		(never LIFO, always FIFO)
	 * Note that there is always some degree of FIFO ordering.
	 * This breaks live lock conditions that occur in applications
	 * that are written assuming (incorrectly) that threads acquire
	 * locks fairly, that is, in roughly round-robin order.
	 * In any event, the queue is maintained in priority order.
	 *
	 * If we are given the FIFOQ flag in qtype, fifo queueing is forced.
	 * SUSV3 requires this for semaphores.
	 */
	do_fifo = (force_fifo ||
	    ((++qp->qh_qcnt << curthread->ul_queue_fifo) & 0xff) == 0);

	if (qp->qh_head == NULL) {
		/*
		 * The queue is empty.  LIFO/FIFO doesn't matter.
		 */
		ASSERT(qp->qh_tail == NULL);
		ulwpp = &qp->qh_head;
	} else if (do_fifo) {
		/*
		 * Enqueue after the last thread whose priority is greater
		 * than or equal to the priority of the thread being queued.
		 * Attempt first to go directly onto the tail of the queue.
		 */
		if (pri <= CMP_PRIO(qp->qh_tail))
			ulwpp = &qp->qh_tail->ul_link;
		else {
			for (ulwpp = &qp->qh_head; (next = *ulwpp) != NULL;
			    ulwpp = &next->ul_link)
				if (pri > CMP_PRIO(next))
					break;
		}
	} else {
		/*
		 * Enqueue before the first thread whose priority is less
		 * than or equal to the priority of the thread being queued.
		 * Hopefully we can go directly onto the head of the queue.
		 */
		for (ulwpp = &qp->qh_head; (next = *ulwpp) != NULL;
		    ulwpp = &next->ul_link)
			if (pri >= CMP_PRIO(next))
				break;
	}
	if ((ulwp->ul_link = *ulwpp) == NULL)
		qp->qh_tail = ulwp;
	*ulwpp = ulwp;

	ulwp->ul_sleepq = qp;
	ulwp->ul_wchan = wchan;
	ulwp->ul_qtype = qtype;
	if (qp->qh_qmax < ++qp->qh_qlen)
		qp->qh_qmax = qp->qh_qlen;
}

/*
 * Return a pointer to the queue slot of the
 * highest priority thread on the queue.
 * On return, prevp, if not NULL, will contain a pointer
 * to the thread's predecessor on the queue
 */
static ulwp_t **
queue_slot(queue_head_t *qp, void *wchan, int *more, ulwp_t **prevp)
{
	ulwp_t **ulwpp;
	ulwp_t *ulwp;
	ulwp_t *prev = NULL;
	ulwp_t **suspp = NULL;
	ulwp_t *susprev;

	ASSERT(MUTEX_OWNED(&qp->qh_lock, curthread));

	/*
	 * Find a waiter on the sleep queue.
	 */
	for (ulwpp = &qp->qh_head; (ulwp = *ulwpp) != NULL;
	    prev = ulwp, ulwpp = &ulwp->ul_link) {
		if (ulwp->ul_wchan == wchan) {
			if (!ulwp->ul_stop)
				break;
			/*
			 * Try not to return a suspended thread.
			 * This mimics the old libthread's behavior.
			 */
			if (suspp == NULL) {
				suspp = ulwpp;
				susprev = prev;
			}
		}
	}

	if (ulwp == NULL && suspp != NULL) {
		ulwp = *(ulwpp = suspp);
		prev = susprev;
		suspp = NULL;
	}
	if (ulwp == NULL) {
		if (more != NULL)
			*more = 0;
		return (NULL);
	}

	if (prevp != NULL)
		*prevp = prev;
	if (more == NULL)
		return (ulwpp);

	/*
	 * Scan the remainder of the queue for another waiter.
	 */
	if (suspp != NULL) {
		*more = 1;
		return (ulwpp);
	}
	for (ulwp = ulwp->ul_link; ulwp != NULL; ulwp = ulwp->ul_link) {
		if (ulwp->ul_wchan == wchan) {
			*more = 1;
			return (ulwpp);
		}
	}

	*more = 0;
	return (ulwpp);
}

ulwp_t *
queue_unlink(queue_head_t *qp, ulwp_t **ulwpp, ulwp_t *prev)
{
	ulwp_t *ulwp;

	ulwp = *ulwpp;
	*ulwpp = ulwp->ul_link;
	ulwp->ul_link = NULL;
	if (qp->qh_tail == ulwp)
		qp->qh_tail = prev;
	qp->qh_qlen--;
	ulwp->ul_sleepq = NULL;
	ulwp->ul_wchan = NULL;

	return (ulwp);
}

ulwp_t *
dequeue(queue_head_t *qp, void *wchan, int *more)
{
	ulwp_t **ulwpp;
	ulwp_t *prev;

	if ((ulwpp = queue_slot(qp, wchan, more, &prev)) == NULL)
		return (NULL);
	return (queue_unlink(qp, ulwpp, prev));
}

/*
 * Return a pointer to the highest priority thread sleeping on wchan.
 */
ulwp_t *
queue_waiter(queue_head_t *qp, void *wchan)
{
	ulwp_t **ulwpp;

	if ((ulwpp = queue_slot(qp, wchan, NULL, NULL)) == NULL)
		return (NULL);
	return (*ulwpp);
}

uint8_t
dequeue_self(queue_head_t *qp, void *wchan)
{
	ulwp_t *self = curthread;
	ulwp_t **ulwpp;
	ulwp_t *ulwp;
	ulwp_t *prev = NULL;
	int found = 0;
	int more = 0;

	ASSERT(MUTEX_OWNED(&qp->qh_lock, self));

	/* find self on the sleep queue */
	for (ulwpp = &qp->qh_head; (ulwp = *ulwpp) != NULL;
	    prev = ulwp, ulwpp = &ulwp->ul_link) {
		if (ulwp == self) {
			/* dequeue ourself */
			ASSERT(self->ul_wchan == wchan);
			(void) queue_unlink(qp, ulwpp, prev);
			self->ul_cvmutex = NULL;
			self->ul_cv_wake = 0;
			found = 1;
			break;
		}
		if (ulwp->ul_wchan == wchan)
			more = 1;
	}

	if (!found)
		thr_panic("dequeue_self(): curthread not found on queue");

	if (more)
		return (1);

	/* scan the remainder of the queue for another waiter */
	for (ulwp = *ulwpp; ulwp != NULL; ulwp = ulwp->ul_link) {
		if (ulwp->ul_wchan == wchan)
			return (1);
	}

	return (0);
}

/*
 * Called from call_user_handler() and _thrp_suspend() to take
 * ourself off of our sleep queue so we can grab locks.
 */
void
unsleep_self(void)
{
	ulwp_t *self = curthread;
	queue_head_t *qp;

	/*
	 * Calling enter_critical()/exit_critical() here would lead
	 * to recursion.  Just manipulate self->ul_critical directly.
	 */
	self->ul_critical++;
	while (self->ul_sleepq != NULL) {
		qp = queue_lock(self->ul_wchan, self->ul_qtype);
		/*
		 * We may have been moved from a CV queue to a
		 * mutex queue while we were attempting queue_lock().
		 * If so, just loop around and try again.
		 * dequeue_self() clears self->ul_sleepq.
		 */
		if (qp == self->ul_sleepq) {
			(void) dequeue_self(qp, self->ul_wchan);
			self->ul_writer = 0;
		}
		queue_unlock(qp);
	}
	self->ul_critical--;
}

/*
 * Common code for calling the the ___lwp_mutex_timedlock() system call.
 * Returns with mutex_owner and mutex_ownerpid set correctly.
 */
static int
mutex_lock_kernel(mutex_t *mp, timespec_t *tsp, tdb_mutex_stats_t *msp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int mtype = mp->mutex_type;
	hrtime_t begin_sleep;
	int acquired;
	int error;

	self->ul_sp = stkptr();
	self->ul_wchan = mp;
	if (__td_event_report(self, TD_SLEEP, udp)) {
		self->ul_td_evbuf.eventnum = TD_SLEEP;
		self->ul_td_evbuf.eventdata = mp;
		tdb_event(TD_SLEEP, udp);
	}
	if (msp) {
		tdb_incr(msp->mutex_sleep);
		begin_sleep = gethrtime();
	}

	DTRACE_PROBE1(plockstat, mutex__block, mp);

	for (;;) {
		/*
		 * A return value of EOWNERDEAD or ELOCKUNMAPPED
		 * means we successfully acquired the lock.
		 */
		if ((error = ___lwp_mutex_timedlock(mp, tsp)) != 0 &&
		    error != EOWNERDEAD && error != ELOCKUNMAPPED) {
			acquired = 0;
			break;
		}

		if (mtype & USYNC_PROCESS) {
			/*
			 * Defend against forkall().  We may be the child,
			 * in which case we don't actually own the mutex.
			 */
			enter_critical(self);
			if (mp->mutex_ownerpid == udp->pid) {
				mp->mutex_owner = (uintptr_t)self;
				exit_critical(self);
				acquired = 1;
				break;
			}
			exit_critical(self);
		} else {
			mp->mutex_owner = (uintptr_t)self;
			acquired = 1;
			break;
		}
	}
	if (msp)
		msp->mutex_sleep_time += gethrtime() - begin_sleep;
	self->ul_wchan = NULL;
	self->ul_sp = 0;

	if (acquired) {
		DTRACE_PROBE2(plockstat, mutex__blocked, mp, 1);
		DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
	} else {
		DTRACE_PROBE2(plockstat, mutex__blocked, mp, 0);
		DTRACE_PROBE2(plockstat, mutex__error, mp, error);
	}

	return (error);
}

/*
 * Common code for calling the ___lwp_mutex_trylock() system call.
 * Returns with mutex_owner and mutex_ownerpid set correctly.
 */
int
mutex_trylock_kernel(mutex_t *mp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int mtype = mp->mutex_type;
	int error;
	int acquired;

	for (;;) {
		/*
		 * A return value of EOWNERDEAD or ELOCKUNMAPPED
		 * means we successfully acquired the lock.
		 */
		if ((error = ___lwp_mutex_trylock(mp)) != 0 &&
		    error != EOWNERDEAD && error != ELOCKUNMAPPED) {
			acquired = 0;
			break;
		}

		if (mtype & USYNC_PROCESS) {
			/*
			 * Defend against forkall().  We may be the child,
			 * in which case we don't actually own the mutex.
			 */
			enter_critical(self);
			if (mp->mutex_ownerpid == udp->pid) {
				mp->mutex_owner = (uintptr_t)self;
				exit_critical(self);
				acquired = 1;
				break;
			}
			exit_critical(self);
		} else {
			mp->mutex_owner = (uintptr_t)self;
			acquired = 1;
			break;
		}
	}

	if (acquired) {
		DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
	} else if (error != EBUSY) {
		DTRACE_PROBE2(plockstat, mutex__error, mp, error);
	}

	return (error);
}

volatile sc_shared_t *
setup_schedctl(void)
{
	ulwp_t *self = curthread;
	volatile sc_shared_t *scp;
	sc_shared_t *tmp;

	if ((scp = self->ul_schedctl) == NULL && /* no shared state yet */
	    !self->ul_vfork &&			/* not a child of vfork() */
	    !self->ul_schedctl_called) {	/* haven't been called before */
		enter_critical(self);
		self->ul_schedctl_called = &self->ul_uberdata->uberflags;
		if ((tmp = __schedctl()) != (sc_shared_t *)(-1))
			self->ul_schedctl = scp = tmp;
		exit_critical(self);
	}
	/*
	 * Unless the call to setup_schedctl() is surrounded
	 * by enter_critical()/exit_critical(), the address
	 * we are returning could be invalid due to a forkall()
	 * having occurred in another thread.
	 */
	return (scp);
}

/*
 * Interfaces from libsched, incorporated into libc.
 * libsched.so.1 is now a filter library onto libc.
 */
#pragma weak schedctl_lookup = _schedctl_init
#pragma weak _schedctl_lookup = _schedctl_init
#pragma weak schedctl_init = _schedctl_init
schedctl_t *
_schedctl_init(void)
{
	volatile sc_shared_t *scp = setup_schedctl();
	return ((scp == NULL)? NULL : (schedctl_t *)&scp->sc_preemptctl);
}

#pragma weak schedctl_exit = _schedctl_exit
void
_schedctl_exit(void)
{
}

/*
 * Contract private interface for java.
 * Set up the schedctl data if it doesn't exist yet.
 * Return a pointer to the pointer to the schedctl data.
 */
volatile sc_shared_t *volatile *
_thr_schedctl(void)
{
	ulwp_t *self = curthread;
	volatile sc_shared_t *volatile *ptr;

	if (self->ul_vfork)
		return (NULL);
	if (*(ptr = &self->ul_schedctl) == NULL)
		(void) setup_schedctl();
	return (ptr);
}

/*
 * Block signals and attempt to block preemption.
 * no_preempt()/preempt() must be used in pairs but can be nested.
 */
void
no_preempt(ulwp_t *self)
{
	volatile sc_shared_t *scp;

	if (self->ul_preempt++ == 0) {
		enter_critical(self);
		if ((scp = self->ul_schedctl) != NULL ||
		    (scp = setup_schedctl()) != NULL) {
			/*
			 * Save the pre-existing preempt value.
			 */
			self->ul_savpreempt = scp->sc_preemptctl.sc_nopreempt;
			scp->sc_preemptctl.sc_nopreempt = 1;
		}
	}
}

/*
 * Undo the effects of no_preempt().
 */
void
preempt(ulwp_t *self)
{
	volatile sc_shared_t *scp;

	ASSERT(self->ul_preempt > 0);
	if (--self->ul_preempt == 0) {
		if ((scp = self->ul_schedctl) != NULL) {
			/*
			 * Restore the pre-existing preempt value.
			 */
			scp->sc_preemptctl.sc_nopreempt = self->ul_savpreempt;
			if (scp->sc_preemptctl.sc_yield &&
			    scp->sc_preemptctl.sc_nopreempt == 0) {
				lwp_yield();
				if (scp->sc_preemptctl.sc_yield) {
					/*
					 * Shouldn't happen.  This is either
					 * a race condition or the thread
					 * just entered the real-time class.
					 */
					lwp_yield();
					scp->sc_preemptctl.sc_yield = 0;
				}
			}
		}
		exit_critical(self);
	}
}

/*
 * If a call to preempt() would cause the current thread to yield or to
 * take deferred actions in exit_critical(), then unpark the specified
 * lwp so it can run while we delay.  Return the original lwpid if the
 * unpark was not performed, else return zero.  The tests are a repeat
 * of some of the tests in preempt(), above.  This is a statistical
 * optimization solely for cond_sleep_queue(), below.
 */
static lwpid_t
preempt_unpark(ulwp_t *self, lwpid_t lwpid)
{
	volatile sc_shared_t *scp = self->ul_schedctl;

	ASSERT(self->ul_preempt == 1 && self->ul_critical > 0);
	if ((scp != NULL && scp->sc_preemptctl.sc_yield) ||
	    (self->ul_curplease && self->ul_critical == 1)) {
		(void) __lwp_unpark(lwpid);
		lwpid = 0;
	}
	return (lwpid);
}

/*
 * Spin for a while (if 'tryhard' is true), trying to grab the lock.
 * If this fails, return EBUSY and let the caller deal with it.
 * If this succeeds, return 0 with mutex_owner set to curthread.
 */
static int
mutex_trylock_adaptive(mutex_t *mp, int tryhard)
{
	ulwp_t *self = curthread;
	int error = EBUSY;
	ulwp_t *ulwp;
	volatile sc_shared_t *scp;
	volatile uint8_t *lockp = (volatile uint8_t *)&mp->mutex_lockw;
	volatile uint64_t *ownerp = (volatile uint64_t *)&mp->mutex_owner;
	uint32_t new_lockword;
	int count = 0;
	int max_count;
	uint8_t max_spinners;

	ASSERT(!(mp->mutex_type & USYNC_PROCESS));

	if (MUTEX_OWNER(mp) == self)
		return (EBUSY);

	/* short-cut, not definitive (see below) */
	if (mp->mutex_flag & LOCK_NOTRECOVERABLE) {
		ASSERT(mp->mutex_type & LOCK_ROBUST);
		error = ENOTRECOVERABLE;
		goto done;
	}

	/*
	 * Make one attempt to acquire the lock before
	 * incurring the overhead of the spin loop.
	 */
	if (set_lock_byte(lockp) == 0) {
		*ownerp = (uintptr_t)self;
		error = 0;
		goto done;
	}
	if (!tryhard)
		goto done;
	if (ncpus == 0)
		ncpus = (int)_sysconf(_SC_NPROCESSORS_ONLN);
	if ((max_spinners = self->ul_max_spinners) >= ncpus)
		max_spinners = ncpus - 1;
	max_count = (max_spinners != 0)? self->ul_adaptive_spin : 0;
	if (max_count == 0)
		goto done;

	/*
	 * This spin loop is unfair to lwps that have already dropped into
	 * the kernel to sleep.  They will starve on a highly-contended mutex.
	 * This is just too bad.  The adaptive spin algorithm is intended
	 * to allow programs with highly-contended locks (that is, broken
	 * programs) to execute with reasonable speed despite their contention.
	 * Being fair would reduce the speed of such programs and well-written
	 * programs will not suffer in any case.
	 */
	enter_critical(self);
	if (spinners_incr(&mp->mutex_lockword, max_spinners) == -1) {
		exit_critical(self);
		goto done;
	}
	DTRACE_PROBE1(plockstat, mutex__spin, mp);
	for (count = 1; ; count++) {
		if (*lockp == 0 && set_lock_byte(lockp) == 0) {
			*ownerp = (uintptr_t)self;
			error = 0;
			break;
		}
		if (count == max_count)
			break;
		SMT_PAUSE();
		/*
		 * Stop spinning if the mutex owner is not running on
		 * a processor; it will not drop the lock any time soon
		 * and we would just be wasting time to keep spinning.
		 *
		 * Note that we are looking at another thread (ulwp_t)
		 * without ensuring that the other thread does not exit.
		 * The scheme relies on ulwp_t structures never being
		 * deallocated by the library (the library employs a free
		 * list of ulwp_t structs that are reused when new threads
		 * are created) and on schedctl shared memory never being
		 * deallocated once created via __schedctl().
		 *
		 * Thus, the worst that can happen when the spinning thread
		 * looks at the owner's schedctl data is that it is looking
		 * at some other thread's schedctl data.  This almost never
		 * happens and is benign when it does.
		 */
		if ((ulwp = (ulwp_t *)(uintptr_t)*ownerp) != NULL &&
		    ((scp = ulwp->ul_schedctl) == NULL ||
		    scp->sc_state != SC_ONPROC))
			break;
	}
	new_lockword = spinners_decr(&mp->mutex_lockword);
	if (error && (new_lockword & (LOCKMASK | SPINNERMASK)) == 0) {
		/*
		 * We haven't yet acquired the lock, the lock
		 * is free, and there are no other spinners.
		 * Make one final attempt to acquire the lock.
		 *
		 * This isn't strictly necessary since mutex_lock_queue()
		 * (the next action this thread will take if it doesn't
		 * acquire the lock here) makes one attempt to acquire
		 * the lock before putting the thread to sleep.
		 *
		 * If the next action for this thread (on failure here)
		 * were not to call mutex_lock_queue(), this would be
		 * necessary for correctness, to avoid ending up with an
		 * unheld mutex with waiters but no one to wake them up.
		 */
		if (set_lock_byte(lockp) == 0) {
			*ownerp = (uintptr_t)self;
			error = 0;
		}
		count++;
	}
	exit_critical(self);

done:
	if (error == 0 && (mp->mutex_flag & LOCK_NOTRECOVERABLE)) {
		ASSERT(mp->mutex_type & LOCK_ROBUST);
		/*
		 * We shouldn't own the mutex; clear the lock.
		 */
		mp->mutex_owner = 0;
		if (clear_lockbyte(&mp->mutex_lockword) & WAITERMASK)
			mutex_wakeup_all(mp);
		error = ENOTRECOVERABLE;
	}

	if (error) {
		if (count) {
			DTRACE_PROBE2(plockstat, mutex__spun, 0, count);
		}
		if (error != EBUSY) {
			DTRACE_PROBE2(plockstat, mutex__error, mp, error);
		}
	} else {
		if (count) {
			DTRACE_PROBE2(plockstat, mutex__spun, 1, count);
		}
		DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, count);
		if (mp->mutex_flag & LOCK_OWNERDEAD) {
			ASSERT(mp->mutex_type & LOCK_ROBUST);
			error = EOWNERDEAD;
		}
	}

	return (error);
}

/*
 * Same as mutex_trylock_adaptive(), except specifically for queue locks.
 * The owner field is not set here; the caller (spin_lock_set()) sets it.
 */
static int
mutex_queuelock_adaptive(mutex_t *mp)
{
	ulwp_t *ulwp;
	volatile sc_shared_t *scp;
	volatile uint8_t *lockp;
	volatile uint64_t *ownerp;
	int count = curthread->ul_queue_spin;

	ASSERT(mp->mutex_type == USYNC_THREAD);

	if (count == 0)
		return (EBUSY);

	lockp = (volatile uint8_t *)&mp->mutex_lockw;
	ownerp = (volatile uint64_t *)&mp->mutex_owner;
	while (--count >= 0) {
		if (*lockp == 0 && set_lock_byte(lockp) == 0)
			return (0);
		SMT_PAUSE();
		if ((ulwp = (ulwp_t *)(uintptr_t)*ownerp) != NULL &&
		    ((scp = ulwp->ul_schedctl) == NULL ||
		    scp->sc_state != SC_ONPROC))
			break;
	}

	return (EBUSY);
}

/*
 * Like mutex_trylock_adaptive(), but for process-shared mutexes.
 * Spin for a while (if 'tryhard' is true), trying to grab the lock.
 * If this fails, return EBUSY and let the caller deal with it.
 * If this succeeds, return 0 with mutex_owner set to curthread
 * and mutex_ownerpid set to the current pid.
 */
static int
mutex_trylock_process(mutex_t *mp, int tryhard)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int error = EBUSY;
	volatile uint8_t *lockp = (volatile uint8_t *)&mp->mutex_lockw;
	uint32_t new_lockword;
	int count = 0;
	int max_count;
	uint8_t max_spinners;

	ASSERT(mp->mutex_type & USYNC_PROCESS);

	if (shared_mutex_held(mp))
		return (EBUSY);

	/* short-cut, not definitive (see below) */
	if (mp->mutex_flag & LOCK_NOTRECOVERABLE) {
		ASSERT(mp->mutex_type & LOCK_ROBUST);
		error = ENOTRECOVERABLE;
		goto done;
	}

	/*
	 * Make one attempt to acquire the lock before
	 * incurring the overhead of the spin loop.
	 */
	enter_critical(self);
	if (set_lock_byte(lockp) == 0) {
		mp->mutex_owner = (uintptr_t)self;
		mp->mutex_ownerpid = udp->pid;
		exit_critical(self);
		error = 0;
		goto done;
	}
	exit_critical(self);
	if (!tryhard)
		goto done;
	if (ncpus == 0)
		ncpus = (int)_sysconf(_SC_NPROCESSORS_ONLN);
	if ((max_spinners = self->ul_max_spinners) >= ncpus)
		max_spinners = ncpus - 1;
	max_count = (max_spinners != 0)? self->ul_adaptive_spin : 0;
	if (max_count == 0)
		goto done;

	/*
	 * This is a process-shared mutex.
	 * We cannot know if the owner is running on a processor.
	 * We just spin and hope that it is on a processor.
	 */
	enter_critical(self);
	if (spinners_incr(&mp->mutex_lockword, max_spinners) == -1) {
		exit_critical(self);
		goto done;
	}
	DTRACE_PROBE1(plockstat, mutex__spin, mp);
	for (count = 1; ; count++) {
		if (*lockp == 0 && set_lock_byte(lockp) == 0) {
			mp->mutex_owner = (uintptr_t)self;
			mp->mutex_ownerpid = udp->pid;
			error = 0;
			break;
		}
		if (count == max_count)
			break;
		SMT_PAUSE();
	}
	new_lockword = spinners_decr(&mp->mutex_lockword);
	if (error && (new_lockword & (LOCKMASK | SPINNERMASK)) == 0) {
		/*
		 * We haven't yet acquired the lock, the lock
		 * is free, and there are no other spinners.
		 * Make one final attempt to acquire the lock.
		 *
		 * This isn't strictly necessary since mutex_lock_kernel()
		 * (the next action this thread will take if it doesn't
		 * acquire the lock here) makes one attempt to acquire
		 * the lock before putting the thread to sleep.
		 *
		 * If the next action for this thread (on failure here)
		 * were not to call mutex_lock_kernel(), this would be
		 * necessary for correctness, to avoid ending up with an
		 * unheld mutex with waiters but no one to wake them up.
		 */
		if (set_lock_byte(lockp) == 0) {
			mp->mutex_owner = (uintptr_t)self;
			mp->mutex_ownerpid = udp->pid;
			error = 0;
		}
		count++;
	}
	exit_critical(self);

done:
	if (error == 0 && (mp->mutex_flag & LOCK_NOTRECOVERABLE)) {
		ASSERT(mp->mutex_type & LOCK_ROBUST);
		/*
		 * We shouldn't own the mutex; clear the lock.
		 */
		mp->mutex_owner = 0;
		mp->mutex_ownerpid = 0;
		if (clear_lockbyte(&mp->mutex_lockword) & WAITERMASK) {
			no_preempt(self);
			(void) ___lwp_mutex_wakeup(mp, 1);
			preempt(self);
		}
		error = ENOTRECOVERABLE;
	}

	if (error) {
		if (count) {
			DTRACE_PROBE2(plockstat, mutex__spun, 0, count);
		}
		if (error != EBUSY) {
			DTRACE_PROBE2(plockstat, mutex__error, mp, error);
		}
	} else {
		if (count) {
			DTRACE_PROBE2(plockstat, mutex__spun, 1, count);
		}
		DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, count);
		if (mp->mutex_flag & (LOCK_OWNERDEAD | LOCK_UNMAPPED)) {
			ASSERT(mp->mutex_type & LOCK_ROBUST);
			if (mp->mutex_flag & LOCK_OWNERDEAD)
				error = EOWNERDEAD;
			else if (mp->mutex_type & USYNC_PROCESS_ROBUST)
				error = ELOCKUNMAPPED;
			else
				error = EOWNERDEAD;
		}
	}

	return (error);
}

/*
 * Mutex wakeup code for releasing a USYNC_THREAD mutex.
 * Returns the lwpid of the thread that was dequeued, if any.
 * The caller of mutex_wakeup() must call __lwp_unpark(lwpid)
 * to wake up the specified lwp.
 */
static lwpid_t
mutex_wakeup(mutex_t *mp)
{
	lwpid_t lwpid = 0;
	queue_head_t *qp;
	ulwp_t *ulwp;
	int more;

	/*
	 * Dequeue a waiter from the sleep queue.  Don't touch the mutex
	 * waiters bit if no one was found on the queue because the mutex
	 * might have been deallocated or reallocated for another purpose.
	 */
	qp = queue_lock(mp, MX);
	if ((ulwp = dequeue(qp, mp, &more)) != NULL) {
		lwpid = ulwp->ul_lwpid;
		mp->mutex_waiters = (more? 1 : 0);
	}
	queue_unlock(qp);
	return (lwpid);
}

/*
 * Mutex wakeup code for releasing all waiters on a USYNC_THREAD mutex.
 */
static void
mutex_wakeup_all(mutex_t *mp)
{
	queue_head_t *qp;
	int nlwpid = 0;
	int maxlwps = MAXLWPS;
	ulwp_t **ulwpp;
	ulwp_t *ulwp;
	ulwp_t *prev = NULL;
	lwpid_t buffer[MAXLWPS];
	lwpid_t *lwpid = buffer;

	/*
	 * Walk the list of waiters and prepare to wake up all of them.
	 * The waiters flag has already been cleared from the mutex.
	 *
	 * We keep track of lwpids that are to be unparked in lwpid[].
	 * __lwp_unpark_all() is called to unpark all of them after
	 * they have been removed from the sleep queue and the sleep
	 * queue lock has been dropped.  If we run out of space in our
	 * on-stack buffer, we need to allocate more but we can't call
	 * lmalloc() because we are holding a queue lock when the overflow
	 * occurs and lmalloc() acquires a lock.  We can't use alloca()
	 * either because the application may have allocated a small
	 * stack and we don't want to overrun the stack.  So we call
	 * alloc_lwpids() to allocate a bigger buffer using the mmap()
	 * system call directly since that path acquires no locks.
	 */
	qp = queue_lock(mp, MX);
	ulwpp = &qp->qh_head;
	while ((ulwp = *ulwpp) != NULL) {
		if (ulwp->ul_wchan != mp) {
			prev = ulwp;
			ulwpp = &ulwp->ul_link;
		} else {
			if (nlwpid == maxlwps)
				lwpid = alloc_lwpids(lwpid, &nlwpid, &maxlwps);
			(void) queue_unlink(qp, ulwpp, prev);
			lwpid[nlwpid++] = ulwp->ul_lwpid;
		}
	}

	if (nlwpid == 0) {
		queue_unlock(qp);
	} else {
		mp->mutex_waiters = 0;
		no_preempt(curthread);
		queue_unlock(qp);
		if (nlwpid == 1)
			(void) __lwp_unpark(lwpid[0]);
		else
			(void) __lwp_unpark_all(lwpid, nlwpid);
		preempt(curthread);
	}

	if (lwpid != buffer)
		(void) _private_munmap(lwpid, maxlwps * sizeof (lwpid_t));
}

/*
 * Release a process-private mutex.
 * As an optimization, if there are waiters but there are also spinners
 * attempting to acquire the mutex, then don't bother waking up a waiter;
 * one of the spinners will acquire the mutex soon and it would be a waste
 * of resources to wake up some thread just to have it spin for a while
 * and then possibly go back to sleep.  See mutex_trylock_adaptive().
 */
static lwpid_t
mutex_unlock_queue(mutex_t *mp, int release_all)
{
	lwpid_t lwpid = 0;
	uint32_t old_lockword;

	mp->mutex_owner = 0;
	DTRACE_PROBE2(plockstat, mutex__release, mp, 0);
	old_lockword = clear_lockbyte(&mp->mutex_lockword);
	if ((old_lockword & WAITERMASK) &&
	    (release_all || (old_lockword & SPINNERMASK) == 0)) {
		ulwp_t *self = curthread;
		no_preempt(self);	/* ensure a prompt wakeup */
		if (release_all)
			mutex_wakeup_all(mp);
		else
			lwpid = mutex_wakeup(mp);
		if (lwpid == 0)
			preempt(self);
	}
	return (lwpid);
}

/*
 * Like mutex_unlock_queue(), but for process-shared mutexes.
 */
static void
mutex_unlock_process(mutex_t *mp, int release_all)
{
	uint32_t old_lockword;

	mp->mutex_owner = 0;
	mp->mutex_ownerpid = 0;
	DTRACE_PROBE2(plockstat, mutex__release, mp, 0);
	old_lockword = clear_lockbyte(&mp->mutex_lockword);
	if ((old_lockword & WAITERMASK) &&
	    (release_all || (old_lockword & SPINNERMASK) == 0)) {
		ulwp_t *self = curthread;
		no_preempt(self);	/* ensure a prompt wakeup */
		(void) ___lwp_mutex_wakeup(mp, release_all);
		preempt(self);
	}
}

/*
 * Return the real priority of a thread.
 */
int
real_priority(ulwp_t *ulwp)
{
	if (ulwp->ul_epri == 0)
		return (ulwp->ul_mappedpri? ulwp->ul_mappedpri : ulwp->ul_pri);
	return (ulwp->ul_emappedpri? ulwp->ul_emappedpri : ulwp->ul_epri);
}

void
stall(void)
{
	for (;;)
		(void) mutex_lock_kernel(&stall_mutex, NULL, NULL);
}

/*
 * Acquire a USYNC_THREAD mutex via user-level sleep queues.
 * We failed set_lock_byte(&mp->mutex_lockw) before coming here.
 * If successful, returns with mutex_owner set correctly.
 */
int
mutex_lock_queue(ulwp_t *self, tdb_mutex_stats_t *msp, mutex_t *mp,
	timespec_t *tsp)
{
	uberdata_t *udp = curthread->ul_uberdata;
	queue_head_t *qp;
	hrtime_t begin_sleep;
	int error = 0;

	self->ul_sp = stkptr();
	if (__td_event_report(self, TD_SLEEP, udp)) {
		self->ul_wchan = mp;
		self->ul_td_evbuf.eventnum = TD_SLEEP;
		self->ul_td_evbuf.eventdata = mp;
		tdb_event(TD_SLEEP, udp);
	}
	if (msp) {
		tdb_incr(msp->mutex_sleep);
		begin_sleep = gethrtime();
	}

	DTRACE_PROBE1(plockstat, mutex__block, mp);

	/*
	 * Put ourself on the sleep queue, and while we are
	 * unable to grab the lock, go park in the kernel.
	 * Take ourself off the sleep queue after we acquire the lock.
	 * The waiter bit can be set/cleared only while holding the queue lock.
	 */
	qp = queue_lock(mp, MX);
	enqueue(qp, self, mp, MX);
	mp->mutex_waiters = 1;
	for (;;) {
		if (set_lock_byte(&mp->mutex_lockw) == 0) {
			mp->mutex_owner = (uintptr_t)self;
			mp->mutex_waiters = dequeue_self(qp, mp);
			break;
		}
		set_parking_flag(self, 1);
		queue_unlock(qp);
		/*
		 * __lwp_park() will return the residual time in tsp
		 * if we are unparked before the timeout expires.
		 */
		error = __lwp_park(tsp, 0);
		set_parking_flag(self, 0);
		/*
		 * We could have taken a signal or suspended ourself.
		 * If we did, then we removed ourself from the queue.
		 * Someone else may have removed us from the queue
		 * as a consequence of mutex_unlock().  We may have
		 * gotten a timeout from __lwp_park().  Or we may still
		 * be on the queue and this is just a spurious wakeup.
		 */
		qp = queue_lock(mp, MX);
		if (self->ul_sleepq == NULL) {
			if (error) {
				mp->mutex_waiters = queue_waiter(qp, mp)? 1 : 0;
				if (error != EINTR)
					break;
				error = 0;
			}
			if (set_lock_byte(&mp->mutex_lockw) == 0) {
				mp->mutex_owner = (uintptr_t)self;
				break;
			}
			enqueue(qp, self, mp, MX);
			mp->mutex_waiters = 1;
		}
		ASSERT(self->ul_sleepq == qp &&
		    self->ul_qtype == MX &&
		    self->ul_wchan == mp);
		if (error) {
			if (error != EINTR) {
				mp->mutex_waiters = dequeue_self(qp, mp);
				break;
			}
			error = 0;
		}
	}
	ASSERT(self->ul_sleepq == NULL && self->ul_link == NULL &&
	    self->ul_wchan == NULL);
	self->ul_sp = 0;
	queue_unlock(qp);

	if (msp)
		msp->mutex_sleep_time += gethrtime() - begin_sleep;

	ASSERT(error == 0 || error == EINVAL || error == ETIME);

	if (error == 0 && (mp->mutex_flag & LOCK_NOTRECOVERABLE)) {
		ASSERT(mp->mutex_type & LOCK_ROBUST);
		/*
		 * We shouldn't own the mutex; clear the lock.
		 */
		mp->mutex_owner = 0;
		if (clear_lockbyte(&mp->mutex_lockword) & WAITERMASK)
			mutex_wakeup_all(mp);
		error = ENOTRECOVERABLE;
	}

	if (error) {
		DTRACE_PROBE2(plockstat, mutex__blocked, mp, 0);
		DTRACE_PROBE2(plockstat, mutex__error, mp, error);
	} else {
		DTRACE_PROBE2(plockstat, mutex__blocked, mp, 1);
		DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
		if (mp->mutex_flag & LOCK_OWNERDEAD) {
			ASSERT(mp->mutex_type & LOCK_ROBUST);
			error = EOWNERDEAD;
		}
	}

	return (error);
}

static int
mutex_recursion(mutex_t *mp, int mtype, int try)
{
	ASSERT(mutex_is_held(mp));
	ASSERT(mtype & (LOCK_RECURSIVE|LOCK_ERRORCHECK));
	ASSERT(try == MUTEX_TRY || try == MUTEX_LOCK);

	if (mtype & LOCK_RECURSIVE) {
		if (mp->mutex_rcount == RECURSION_MAX) {
			DTRACE_PROBE2(plockstat, mutex__error, mp, EAGAIN);
			return (EAGAIN);
		}
		mp->mutex_rcount++;
		DTRACE_PROBE3(plockstat, mutex__acquire, mp, 1, 0);
		return (0);
	}
	if (try == MUTEX_LOCK) {
		DTRACE_PROBE2(plockstat, mutex__error, mp, EDEADLK);
		return (EDEADLK);
	}
	return (EBUSY);
}

/*
 * Register this USYNC_PROCESS|LOCK_ROBUST mutex with the kernel so
 * it can apply LOCK_OWNERDEAD|LOCK_UNMAPPED if it becomes necessary.
 * We use tdb_hash_lock here and in the synch object tracking code in
 * the tdb_agent.c file.  There is no conflict between these two usages.
 */
void
register_lock(mutex_t *mp)
{
	uberdata_t *udp = curthread->ul_uberdata;
	uint_t hash = LOCK_HASH(mp);
	robust_t *rlp;
	robust_t **rlpp;
	robust_t **table;

	if ((table = udp->robustlocks) == NULL) {
		lmutex_lock(&udp->tdb_hash_lock);
		if ((table = udp->robustlocks) == NULL) {
			table = lmalloc(LOCKHASHSZ * sizeof (robust_t *));
			_membar_producer();
			udp->robustlocks = table;
		}
		lmutex_unlock(&udp->tdb_hash_lock);
	}
	_membar_consumer();

	/*
	 * First search the registered table with no locks held.
	 * This is safe because the table never shrinks
	 * and we can only get a false negative.
	 */
	for (rlp = table[hash]; rlp != NULL; rlp = rlp->robust_next) {
		if (rlp->robust_lock == mp)	/* already registered */
			return;
	}

	/*
	 * The lock was not found.
	 * Repeat the operation with tdb_hash_lock held.
	 */
	lmutex_lock(&udp->tdb_hash_lock);

	for (rlpp = &table[hash];
	    (rlp = *rlpp) != NULL;
	    rlpp = &rlp->robust_next) {
		if (rlp->robust_lock == mp) {	/* already registered */
			lmutex_unlock(&udp->tdb_hash_lock);
			return;
		}
	}

	/*
	 * The lock has never been registered.
	 * Register it now and add it to the table.
	 */
	(void) ___lwp_mutex_register(mp);
	rlp = lmalloc(sizeof (*rlp));
	rlp->robust_lock = mp;
	_membar_producer();
	*rlpp = rlp;

	lmutex_unlock(&udp->tdb_hash_lock);
}

/*
 * This is called in the child of fork()/forkall() to start over
 * with a clean slate.  (Each process must register its own locks.)
 * No locks are needed because all other threads are suspended or gone.
 */
void
unregister_locks(void)
{
	uberdata_t *udp = curthread->ul_uberdata;
	uint_t hash;
	robust_t **table;
	robust_t *rlp;
	robust_t *next;

	if ((table = udp->robustlocks) != NULL) {
		for (hash = 0; hash < LOCKHASHSZ; hash++) {
			rlp = table[hash];
			while (rlp != NULL) {
				next = rlp->robust_next;
				lfree(rlp, sizeof (*rlp));
				rlp = next;
			}
		}
		lfree(table, LOCKHASHSZ * sizeof (robust_t *));
		udp->robustlocks = NULL;
	}
}

/*
 * Returns with mutex_owner set correctly.
 */
static int
mutex_lock_internal(mutex_t *mp, timespec_t *tsp, int try)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int mtype = mp->mutex_type;
	tdb_mutex_stats_t *msp = MUTEX_STATS(mp, udp);
	int error = 0;
	uint8_t ceil;
	int myprio;

	ASSERT(try == MUTEX_TRY || try == MUTEX_LOCK);

	if (!self->ul_schedctl_called)
		(void) setup_schedctl();

	if (msp && try == MUTEX_TRY)
		tdb_incr(msp->mutex_try);

	if ((mtype & (LOCK_RECURSIVE|LOCK_ERRORCHECK)) && mutex_is_held(mp))
		return (mutex_recursion(mp, mtype, try));

	if (self->ul_error_detection && try == MUTEX_LOCK &&
	    tsp == NULL && mutex_is_held(mp))
		lock_error(mp, "mutex_lock", NULL, NULL);

	if (mtype & LOCK_PRIO_PROTECT) {
		ceil = mp->mutex_ceiling;
		ASSERT(_validate_rt_prio(SCHED_FIFO, ceil) == 0);
		myprio = real_priority(self);
		if (myprio > ceil) {
			DTRACE_PROBE2(plockstat, mutex__error, mp, EINVAL);
			return (EINVAL);
		}
		if ((error = _ceil_mylist_add(mp)) != 0) {
			DTRACE_PROBE2(plockstat, mutex__error, mp, error);
			return (error);
		}
		if (myprio < ceil)
			_ceil_prio_inherit(ceil);
	}

	if ((mtype & (USYNC_PROCESS | LOCK_ROBUST))
	    == (USYNC_PROCESS | LOCK_ROBUST))
		register_lock(mp);

	if (mtype & LOCK_PRIO_INHERIT) {
		/* go straight to the kernel */
		if (try == MUTEX_TRY)
			error = mutex_trylock_kernel(mp);
		else	/* MUTEX_LOCK */
			error = mutex_lock_kernel(mp, tsp, msp);
		/*
		 * The kernel never sets or clears the lock byte
		 * for LOCK_PRIO_INHERIT mutexes.
		 * Set it here for consistency.
		 */
		switch (error) {
		case 0:
			mp->mutex_lockw = LOCKSET;
			break;
		case EOWNERDEAD:
		case ELOCKUNMAPPED:
			mp->mutex_lockw = LOCKSET;
			/* FALLTHROUGH */
		case ENOTRECOVERABLE:
			ASSERT(mtype & LOCK_ROBUST);
			break;
		case EDEADLK:
			if (try == MUTEX_LOCK)
				stall();
			error = EBUSY;
			break;
		}
	} else if (mtype & USYNC_PROCESS) {
		error = mutex_trylock_process(mp, try == MUTEX_LOCK);
		if (error == EBUSY && try == MUTEX_LOCK)
			error = mutex_lock_kernel(mp, tsp, msp);
	} else {	/* USYNC_THREAD */
		error = mutex_trylock_adaptive(mp, try == MUTEX_LOCK);
		if (error == EBUSY && try == MUTEX_LOCK)
			error = mutex_lock_queue(self, msp, mp, tsp);
	}

	switch (error) {
	case 0:
	case EOWNERDEAD:
	case ELOCKUNMAPPED:
		if (mtype & LOCK_ROBUST)
			remember_lock(mp);
		if (msp)
			record_begin_hold(msp);
		break;
	default:
		if (mtype & LOCK_PRIO_PROTECT) {
			(void) _ceil_mylist_del(mp);
			if (myprio < ceil)
				_ceil_prio_waive();
		}
		if (try == MUTEX_TRY) {
			if (msp)
				tdb_incr(msp->mutex_try_fail);
			if (__td_event_report(self, TD_LOCK_TRY, udp)) {
				self->ul_td_evbuf.eventnum = TD_LOCK_TRY;
				tdb_event(TD_LOCK_TRY, udp);
			}
		}
		break;
	}

	return (error);
}

int
fast_process_lock(mutex_t *mp, timespec_t *tsp, int mtype, int try)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;

	/*
	 * We know that USYNC_PROCESS is set in mtype and that
	 * zero, one, or both of the flags LOCK_RECURSIVE and
	 * LOCK_ERRORCHECK are set, and that no other flags are set.
	 */
	ASSERT((mtype & ~(USYNC_PROCESS|LOCK_RECURSIVE|LOCK_ERRORCHECK)) == 0);
	enter_critical(self);
	if (set_lock_byte(&mp->mutex_lockw) == 0) {
		mp->mutex_owner = (uintptr_t)self;
		mp->mutex_ownerpid = udp->pid;
		exit_critical(self);
		DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
		return (0);
	}
	exit_critical(self);

	if ((mtype & (LOCK_RECURSIVE|LOCK_ERRORCHECK)) && shared_mutex_held(mp))
		return (mutex_recursion(mp, mtype, try));

	if (try == MUTEX_LOCK) {
		if (mutex_trylock_process(mp, 1) == 0)
			return (0);
		return (mutex_lock_kernel(mp, tsp, NULL));
	}

	if (__td_event_report(self, TD_LOCK_TRY, udp)) {
		self->ul_td_evbuf.eventnum = TD_LOCK_TRY;
		tdb_event(TD_LOCK_TRY, udp);
	}
	return (EBUSY);
}

static int
mutex_lock_impl(mutex_t *mp, timespec_t *tsp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	uberflags_t *gflags;
	int mtype;

	/*
	 * Optimize the case of USYNC_THREAD, including
	 * the LOCK_RECURSIVE and LOCK_ERRORCHECK cases,
	 * no error detection, no lock statistics,
	 * and the process has only a single thread.
	 * (Most likely a traditional single-threaded application.)
	 */
	if ((((mtype = mp->mutex_type) & ~(LOCK_RECURSIVE|LOCK_ERRORCHECK)) |
	    udp->uberflags.uf_all) == 0) {
		/*
		 * Only one thread exists so we don't need an atomic operation.
		 */
		if (mp->mutex_lockw == 0) {
			mp->mutex_lockw = LOCKSET;
			mp->mutex_owner = (uintptr_t)self;
			DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
			return (0);
		}
		if (mtype && MUTEX_OWNER(mp) == self)
			return (mutex_recursion(mp, mtype, MUTEX_LOCK));
		/*
		 * We have reached a deadlock, probably because the
		 * process is executing non-async-signal-safe code in
		 * a signal handler and is attempting to acquire a lock
		 * that it already owns.  This is not surprising, given
		 * bad programming practices over the years that has
		 * resulted in applications calling printf() and such
		 * in their signal handlers.  Unless the user has told
		 * us that the signal handlers are safe by setting:
		 *	export _THREAD_ASYNC_SAFE=1
		 * we return EDEADLK rather than actually deadlocking.
		 */
		if (tsp == NULL &&
		    MUTEX_OWNER(mp) == self && !self->ul_async_safe) {
			DTRACE_PROBE2(plockstat, mutex__error, mp, EDEADLK);
			return (EDEADLK);
		}
	}

	/*
	 * Optimize the common cases of USYNC_THREAD or USYNC_PROCESS,
	 * no error detection, and no lock statistics.
	 * Include LOCK_RECURSIVE and LOCK_ERRORCHECK cases.
	 */
	if ((gflags = self->ul_schedctl_called) != NULL &&
	    (gflags->uf_trs_ted |
	    (mtype & ~(USYNC_PROCESS|LOCK_RECURSIVE|LOCK_ERRORCHECK))) == 0) {
		if (mtype & USYNC_PROCESS)
			return (fast_process_lock(mp, tsp, mtype, MUTEX_LOCK));
		if (set_lock_byte(&mp->mutex_lockw) == 0) {
			mp->mutex_owner = (uintptr_t)self;
			DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
			return (0);
		}
		if (mtype && MUTEX_OWNER(mp) == self)
			return (mutex_recursion(mp, mtype, MUTEX_LOCK));
		if (mutex_trylock_adaptive(mp, 1) != 0)
			return (mutex_lock_queue(self, NULL, mp, tsp));
		return (0);
	}

	/* else do it the long way */
	return (mutex_lock_internal(mp, tsp, MUTEX_LOCK));
}

/*
 * Of the following function names (all the same function, of course),
 * only _private_mutex_lock() is not exported from libc.  This means
 * that calling _private_mutex_lock() within libc will not invoke the
 * dynamic linker.  This is critical for any code called in the child
 * of vfork() (via posix_spawn()) because invoking the dynamic linker
 * in such a case would corrupt the parent's address space.  There are
 * other places in libc where avoiding the dynamic linker is necessary.
 * Of course, _private_mutex_lock() can be called in cases not requiring
 * the avoidance of the dynamic linker too, and often is.
 */
#pragma weak _private_mutex_lock = __mutex_lock
#pragma weak mutex_lock = __mutex_lock
#pragma weak _mutex_lock = __mutex_lock
#pragma weak pthread_mutex_lock = __mutex_lock
#pragma weak _pthread_mutex_lock = __mutex_lock
int
__mutex_lock(mutex_t *mp)
{
	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	return (mutex_lock_impl(mp, NULL));
}

#pragma weak pthread_mutex_timedlock = _pthread_mutex_timedlock
int
_pthread_mutex_timedlock(mutex_t *mp, const timespec_t *abstime)
{
	timespec_t tslocal;
	int error;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	abstime_to_reltime(CLOCK_REALTIME, abstime, &tslocal);
	error = mutex_lock_impl(mp, &tslocal);
	if (error == ETIME)
		error = ETIMEDOUT;
	return (error);
}

#pragma weak pthread_mutex_reltimedlock_np = _pthread_mutex_reltimedlock_np
int
_pthread_mutex_reltimedlock_np(mutex_t *mp, const timespec_t *reltime)
{
	timespec_t tslocal;
	int error;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	tslocal = *reltime;
	error = mutex_lock_impl(mp, &tslocal);
	if (error == ETIME)
		error = ETIMEDOUT;
	return (error);
}

#pragma weak _private_mutex_trylock = __mutex_trylock
#pragma weak mutex_trylock = __mutex_trylock
#pragma weak _mutex_trylock = __mutex_trylock
#pragma weak pthread_mutex_trylock = __mutex_trylock
#pragma weak _pthread_mutex_trylock = __mutex_trylock
int
__mutex_trylock(mutex_t *mp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	uberflags_t *gflags;
	int mtype;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	/*
	 * Optimize the case of USYNC_THREAD, including
	 * the LOCK_RECURSIVE and LOCK_ERRORCHECK cases,
	 * no error detection, no lock statistics,
	 * and the process has only a single thread.
	 * (Most likely a traditional single-threaded application.)
	 */
	if ((((mtype = mp->mutex_type) & ~(LOCK_RECURSIVE|LOCK_ERRORCHECK)) |
	    udp->uberflags.uf_all) == 0) {
		/*
		 * Only one thread exists so we don't need an atomic operation.
		 */
		if (mp->mutex_lockw == 0) {
			mp->mutex_lockw = LOCKSET;
			mp->mutex_owner = (uintptr_t)self;
			DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
			return (0);
		}
		if (mtype && MUTEX_OWNER(mp) == self)
			return (mutex_recursion(mp, mtype, MUTEX_TRY));
		return (EBUSY);
	}

	/*
	 * Optimize the common cases of USYNC_THREAD or USYNC_PROCESS,
	 * no error detection, and no lock statistics.
	 * Include LOCK_RECURSIVE and LOCK_ERRORCHECK cases.
	 */
	if ((gflags = self->ul_schedctl_called) != NULL &&
	    (gflags->uf_trs_ted |
	    (mtype & ~(USYNC_PROCESS|LOCK_RECURSIVE|LOCK_ERRORCHECK))) == 0) {
		if (mtype & USYNC_PROCESS)
			return (fast_process_lock(mp, NULL, mtype, MUTEX_TRY));
		if (set_lock_byte(&mp->mutex_lockw) == 0) {
			mp->mutex_owner = (uintptr_t)self;
			DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
			return (0);
		}
		if (mtype && MUTEX_OWNER(mp) == self)
			return (mutex_recursion(mp, mtype, MUTEX_TRY));
		if (__td_event_report(self, TD_LOCK_TRY, udp)) {
			self->ul_td_evbuf.eventnum = TD_LOCK_TRY;
			tdb_event(TD_LOCK_TRY, udp);
		}
		return (EBUSY);
	}

	/* else do it the long way */
	return (mutex_lock_internal(mp, NULL, MUTEX_TRY));
}

int
mutex_unlock_internal(mutex_t *mp, int retain_robust_flags)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int mtype = mp->mutex_type;
	tdb_mutex_stats_t *msp;
	int error = 0;
	int release_all;
	lwpid_t lwpid;

	if ((mtype & LOCK_ERRORCHECK) && !mutex_is_held(mp))
		return (EPERM);

	if (self->ul_error_detection && !mutex_is_held(mp))
		lock_error(mp, "mutex_unlock", NULL, NULL);

	if ((mtype & LOCK_RECURSIVE) && mp->mutex_rcount != 0) {
		mp->mutex_rcount--;
		DTRACE_PROBE2(plockstat, mutex__release, mp, 1);
		return (0);
	}

	if ((msp = MUTEX_STATS(mp, udp)) != NULL)
		(void) record_hold_time(msp);

	if (!retain_robust_flags && !(mtype & LOCK_PRIO_INHERIT) &&
	    (mp->mutex_flag & (LOCK_OWNERDEAD | LOCK_UNMAPPED))) {
		ASSERT(mp->mutex_type & LOCK_ROBUST);
		mp->mutex_flag &= ~(LOCK_OWNERDEAD | LOCK_UNMAPPED);
		mp->mutex_flag |= LOCK_NOTRECOVERABLE;
	}
	release_all = ((mp->mutex_flag & LOCK_NOTRECOVERABLE) != 0);

	if (mtype & LOCK_PRIO_INHERIT) {
		no_preempt(self);
		mp->mutex_owner = 0;
		mp->mutex_ownerpid = 0;
		DTRACE_PROBE2(plockstat, mutex__release, mp, 0);
		mp->mutex_lockw = LOCKCLEAR;
		error = ___lwp_mutex_unlock(mp);
		preempt(self);
	} else if (mtype & USYNC_PROCESS) {
		mutex_unlock_process(mp, release_all);
	} else {	/* USYNC_THREAD */
		if ((lwpid = mutex_unlock_queue(mp, release_all)) != 0) {
			(void) __lwp_unpark(lwpid);
			preempt(self);
		}
	}

	if (mtype & LOCK_ROBUST)
		forget_lock(mp);

	if ((mtype & LOCK_PRIO_PROTECT) && _ceil_mylist_del(mp))
		_ceil_prio_waive();

	return (error);
}

#pragma weak _private_mutex_unlock = __mutex_unlock
#pragma weak mutex_unlock = __mutex_unlock
#pragma weak _mutex_unlock = __mutex_unlock
#pragma weak pthread_mutex_unlock = __mutex_unlock
#pragma weak _pthread_mutex_unlock = __mutex_unlock
int
__mutex_unlock(mutex_t *mp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	uberflags_t *gflags;
	lwpid_t lwpid;
	int mtype;
	short el;

	/*
	 * Optimize the case of USYNC_THREAD, including
	 * the LOCK_RECURSIVE and LOCK_ERRORCHECK cases,
	 * no error detection, no lock statistics,
	 * and the process has only a single thread.
	 * (Most likely a traditional single-threaded application.)
	 */
	if ((((mtype = mp->mutex_type) & ~(LOCK_RECURSIVE|LOCK_ERRORCHECK)) |
	    udp->uberflags.uf_all) == 0) {
		if (mtype) {
			/*
			 * At this point we know that one or both of the
			 * flags LOCK_RECURSIVE or LOCK_ERRORCHECK is set.
			 */
			if ((mtype & LOCK_ERRORCHECK) && !MUTEX_OWNED(mp, self))
				return (EPERM);
			if ((mtype & LOCK_RECURSIVE) && mp->mutex_rcount != 0) {
				mp->mutex_rcount--;
				DTRACE_PROBE2(plockstat, mutex__release, mp, 1);
				return (0);
			}
		}
		/*
		 * Only one thread exists so we don't need an atomic operation.
		 * Also, there can be no waiters.
		 */
		mp->mutex_owner = 0;
		mp->mutex_lockword = 0;
		DTRACE_PROBE2(plockstat, mutex__release, mp, 0);
		return (0);
	}

	/*
	 * Optimize the common cases of USYNC_THREAD or USYNC_PROCESS,
	 * no error detection, and no lock statistics.
	 * Include LOCK_RECURSIVE and LOCK_ERRORCHECK cases.
	 */
	if ((gflags = self->ul_schedctl_called) != NULL) {
		if (((el = gflags->uf_trs_ted) | mtype) == 0) {
fast_unlock:
			if ((lwpid = mutex_unlock_queue(mp, 0)) != 0) {
				(void) __lwp_unpark(lwpid);
				preempt(self);
			}
			return (0);
		}
		if (el)		/* error detection or lock statistics */
			goto slow_unlock;
		if ((mtype & ~(LOCK_RECURSIVE|LOCK_ERRORCHECK)) == 0) {
			/*
			 * At this point we know that one or both of the
			 * flags LOCK_RECURSIVE or LOCK_ERRORCHECK is set.
			 */
			if ((mtype & LOCK_ERRORCHECK) && !MUTEX_OWNED(mp, self))
				return (EPERM);
			if ((mtype & LOCK_RECURSIVE) && mp->mutex_rcount != 0) {
				mp->mutex_rcount--;
				DTRACE_PROBE2(plockstat, mutex__release, mp, 1);
				return (0);
			}
			goto fast_unlock;
		}
		if ((mtype &
		    ~(USYNC_PROCESS|LOCK_RECURSIVE|LOCK_ERRORCHECK)) == 0) {
			/*
			 * At this point we know that zero, one, or both of the
			 * flags LOCK_RECURSIVE or LOCK_ERRORCHECK is set and
			 * that the USYNC_PROCESS flag is set.
			 */
			if ((mtype & LOCK_ERRORCHECK) && !shared_mutex_held(mp))
				return (EPERM);
			if ((mtype & LOCK_RECURSIVE) && mp->mutex_rcount != 0) {
				mp->mutex_rcount--;
				DTRACE_PROBE2(plockstat, mutex__release, mp, 1);
				return (0);
			}
			mutex_unlock_process(mp, 0);
			return (0);
		}
	}

	/* else do it the long way */
slow_unlock:
	return (mutex_unlock_internal(mp, 0));
}

/*
 * Internally to the library, almost all mutex lock/unlock actions
 * go through these lmutex_ functions, to protect critical regions.
 * We replicate a bit of code from __mutex_lock() and __mutex_unlock()
 * to make these functions faster since we know that the mutex type
 * of all internal locks is USYNC_THREAD.  We also know that internal
 * locking can never fail, so we panic if it does.
 */
void
lmutex_lock(mutex_t *mp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;

	ASSERT(mp->mutex_type == USYNC_THREAD);

	enter_critical(self);
	/*
	 * Optimize the case of no lock statistics and only a single thread.
	 * (Most likely a traditional single-threaded application.)
	 */
	if (udp->uberflags.uf_all == 0) {
		/*
		 * Only one thread exists; the mutex must be free.
		 */
		ASSERT(mp->mutex_lockw == 0);
		mp->mutex_lockw = LOCKSET;
		mp->mutex_owner = (uintptr_t)self;
		DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
	} else {
		tdb_mutex_stats_t *msp = MUTEX_STATS(mp, udp);

		if (!self->ul_schedctl_called)
			(void) setup_schedctl();

		if (set_lock_byte(&mp->mutex_lockw) == 0) {
			mp->mutex_owner = (uintptr_t)self;
			DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
		} else if (mutex_trylock_adaptive(mp, 1) != 0) {
			(void) mutex_lock_queue(self, msp, mp, NULL);
		}

		if (msp)
			record_begin_hold(msp);
	}
}

void
lmutex_unlock(mutex_t *mp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;

	ASSERT(mp->mutex_type == USYNC_THREAD);

	/*
	 * Optimize the case of no lock statistics and only a single thread.
	 * (Most likely a traditional single-threaded application.)
	 */
	if (udp->uberflags.uf_all == 0) {
		/*
		 * Only one thread exists so there can be no waiters.
		 */
		mp->mutex_owner = 0;
		mp->mutex_lockword = 0;
		DTRACE_PROBE2(plockstat, mutex__release, mp, 0);
	} else {
		tdb_mutex_stats_t *msp = MUTEX_STATS(mp, udp);
		lwpid_t lwpid;

		if (msp)
			(void) record_hold_time(msp);
		if ((lwpid = mutex_unlock_queue(mp, 0)) != 0) {
			(void) __lwp_unpark(lwpid);
			preempt(self);
		}
	}
	exit_critical(self);
}

/*
 * For specialized code in libc, like the asynchronous i/o code,
 * the following sig_*() locking primitives are used in order
 * to make the code asynchronous signal safe.  Signals are
 * deferred while locks acquired by these functions are held.
 */
void
sig_mutex_lock(mutex_t *mp)
{
	sigoff(curthread);
	(void) _private_mutex_lock(mp);
}

void
sig_mutex_unlock(mutex_t *mp)
{
	(void) _private_mutex_unlock(mp);
	sigon(curthread);
}

int
sig_mutex_trylock(mutex_t *mp)
{
	int error;

	sigoff(curthread);
	if ((error = _private_mutex_trylock(mp)) != 0)
		sigon(curthread);
	return (error);
}

/*
 * sig_cond_wait() is a cancellation point.
 */
int
sig_cond_wait(cond_t *cv, mutex_t *mp)
{
	int error;

	ASSERT(curthread->ul_sigdefer != 0);
	_private_testcancel();
	error = __cond_wait(cv, mp);
	if (error == EINTR && curthread->ul_cursig) {
		sig_mutex_unlock(mp);
		/* take the deferred signal here */
		sig_mutex_lock(mp);
	}
	_private_testcancel();
	return (error);
}

/*
 * sig_cond_reltimedwait() is a cancellation point.
 */
int
sig_cond_reltimedwait(cond_t *cv, mutex_t *mp, const timespec_t *ts)
{
	int error;

	ASSERT(curthread->ul_sigdefer != 0);
	_private_testcancel();
	error = __cond_reltimedwait(cv, mp, ts);
	if (error == EINTR && curthread->ul_cursig) {
		sig_mutex_unlock(mp);
		/* take the deferred signal here */
		sig_mutex_lock(mp);
	}
	_private_testcancel();
	return (error);
}

/*
 * For specialized code in libc, like the stdio code.
 * the following cancel_safe_*() locking primitives are used in
 * order to make the code cancellation-safe.  Cancellation is
 * deferred while locks acquired by these functions are held.
 */
void
cancel_safe_mutex_lock(mutex_t *mp)
{
	(void) _private_mutex_lock(mp);
	curthread->ul_libc_locks++;
}

int
cancel_safe_mutex_trylock(mutex_t *mp)
{
	int error;

	if ((error = _private_mutex_trylock(mp)) == 0)
		curthread->ul_libc_locks++;
	return (error);
}

void
cancel_safe_mutex_unlock(mutex_t *mp)
{
	ulwp_t *self = curthread;

	ASSERT(self->ul_libc_locks != 0);

	(void) _private_mutex_unlock(mp);

	/*
	 * Decrement the count of locks held by cancel_safe_mutex_lock().
	 * If we are then in a position to terminate cleanly and
	 * if there is a pending cancellation and cancellation
	 * is not disabled and we received EINTR from a recent
	 * system call then perform the cancellation action now.
	 */
	if (--self->ul_libc_locks == 0 &&
	    !(self->ul_vfork | self->ul_nocancel |
	    self->ul_critical | self->ul_sigdefer) &&
	    cancel_active())
		_pthread_exit(PTHREAD_CANCELED);
}

static int
shared_mutex_held(mutex_t *mparg)
{
	/*
	 * The 'volatile' is necessary to make sure the compiler doesn't
	 * reorder the tests of the various components of the mutex.
	 * They must be tested in this order:
	 *	mutex_lockw
	 *	mutex_owner
	 *	mutex_ownerpid
	 * This relies on the fact that everywhere mutex_lockw is cleared,
	 * mutex_owner and mutex_ownerpid are cleared before mutex_lockw
	 * is cleared, and that everywhere mutex_lockw is set, mutex_owner
	 * and mutex_ownerpid are set after mutex_lockw is set, and that
	 * mutex_lockw is set or cleared with a memory barrier.
	 */
	volatile mutex_t *mp = (volatile mutex_t *)mparg;
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;

	return (MUTEX_OWNED(mp, self) && mp->mutex_ownerpid == udp->pid);
}

/*
 * Some crufty old programs define their own version of _mutex_held()
 * to be simply return(1).  This breaks internal libc logic, so we
 * define a private version for exclusive use by libc, mutex_is_held(),
 * and also a new public function, __mutex_held(), to be used in new
 * code to circumvent these crufty old programs.
 */
#pragma weak mutex_held = mutex_is_held
#pragma weak _mutex_held = mutex_is_held
#pragma weak __mutex_held = mutex_is_held
int
mutex_is_held(mutex_t *mparg)
{
	volatile mutex_t *mp = (volatile mutex_t *)mparg;

	if (mparg->mutex_type & USYNC_PROCESS)
		return (shared_mutex_held(mparg));
	return (MUTEX_OWNED(mp, curthread));
}

#pragma weak _private_mutex_destroy = __mutex_destroy
#pragma weak mutex_destroy = __mutex_destroy
#pragma weak _mutex_destroy = __mutex_destroy
#pragma weak pthread_mutex_destroy = __mutex_destroy
#pragma weak _pthread_mutex_destroy = __mutex_destroy
int
__mutex_destroy(mutex_t *mp)
{
	if (mp->mutex_type & USYNC_PROCESS)
		forget_lock(mp);
	(void) _memset(mp, 0, sizeof (*mp));
	tdb_sync_obj_deregister(mp);
	return (0);
}

#pragma weak mutex_consistent = __mutex_consistent
#pragma weak _mutex_consistent = __mutex_consistent
#pragma weak pthread_mutex_consistent_np = __mutex_consistent
#pragma weak _pthread_mutex_consistent_np = __mutex_consistent
int
__mutex_consistent(mutex_t *mp)
{
	/*
	 * Do this only for an inconsistent, initialized robust lock
	 * that we hold.  For all other cases, return EINVAL.
	 */
	if (mutex_is_held(mp) &&
	    (mp->mutex_type & LOCK_ROBUST) &&
	    (mp->mutex_flag & LOCK_INITED) &&
	    (mp->mutex_flag & (LOCK_OWNERDEAD | LOCK_UNMAPPED))) {
		mp->mutex_flag &= ~(LOCK_OWNERDEAD | LOCK_UNMAPPED);
		mp->mutex_rcount = 0;
		return (0);
	}
	return (EINVAL);
}

/*
 * Spin locks are separate from ordinary mutexes,
 * but we use the same data structure for them.
 */

#pragma weak pthread_spin_init = _pthread_spin_init
int
_pthread_spin_init(pthread_spinlock_t *lock, int pshared)
{
	mutex_t *mp = (mutex_t *)lock;

	(void) _memset(mp, 0, sizeof (*mp));
	if (pshared == PTHREAD_PROCESS_SHARED)
		mp->mutex_type = USYNC_PROCESS;
	else
		mp->mutex_type = USYNC_THREAD;
	mp->mutex_flag = LOCK_INITED;
	mp->mutex_magic = MUTEX_MAGIC;
	return (0);
}

#pragma weak pthread_spin_destroy = _pthread_spin_destroy
int
_pthread_spin_destroy(pthread_spinlock_t *lock)
{
	(void) _memset(lock, 0, sizeof (*lock));
	return (0);
}

#pragma weak pthread_spin_trylock = _pthread_spin_trylock
int
_pthread_spin_trylock(pthread_spinlock_t *lock)
{
	mutex_t *mp = (mutex_t *)lock;
	ulwp_t *self = curthread;
	int error = 0;

	no_preempt(self);
	if (set_lock_byte(&mp->mutex_lockw) != 0)
		error = EBUSY;
	else {
		mp->mutex_owner = (uintptr_t)self;
		if (mp->mutex_type == USYNC_PROCESS)
			mp->mutex_ownerpid = self->ul_uberdata->pid;
		DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, 0);
	}
	preempt(self);
	return (error);
}

#pragma weak pthread_spin_lock = _pthread_spin_lock
int
_pthread_spin_lock(pthread_spinlock_t *lock)
{
	mutex_t *mp = (mutex_t *)lock;
	ulwp_t *self = curthread;
	volatile uint8_t *lockp = (volatile uint8_t *)&mp->mutex_lockw;
	int count = 0;

	ASSERT(!self->ul_critical || self->ul_bindflags);

	DTRACE_PROBE1(plockstat, mutex__spin, mp);

	/*
	 * We don't care whether the owner is running on a processor.
	 * We just spin because that's what this interface requires.
	 */
	for (;;) {
		if (*lockp == 0) {	/* lock byte appears to be clear */
			no_preempt(self);
			if (set_lock_byte(lockp) == 0)
				break;
			preempt(self);
		}
		if (count < INT_MAX)
			count++;
		SMT_PAUSE();
	}
	mp->mutex_owner = (uintptr_t)self;
	if (mp->mutex_type == USYNC_PROCESS)
		mp->mutex_ownerpid = self->ul_uberdata->pid;
	preempt(self);
	if (count) {
		DTRACE_PROBE2(plockstat, mutex__spun, 1, count);
	}
	DTRACE_PROBE3(plockstat, mutex__acquire, mp, 0, count);
	return (0);
}

#pragma weak pthread_spin_unlock = _pthread_spin_unlock
int
_pthread_spin_unlock(pthread_spinlock_t *lock)
{
	mutex_t *mp = (mutex_t *)lock;
	ulwp_t *self = curthread;

	no_preempt(self);
	mp->mutex_owner = 0;
	mp->mutex_ownerpid = 0;
	DTRACE_PROBE2(plockstat, mutex__release, mp, 0);
	(void) atomic_swap_32(&mp->mutex_lockword, 0);
	preempt(self);
	return (0);
}

#define	INITIAL_LOCKS	8	/* initial size of ul_heldlocks.array */

/*
 * Find/allocate an entry for 'lock' in our array of held locks.
 */
static mutex_t **
find_lock_entry(mutex_t *lock)
{
	ulwp_t *self = curthread;
	mutex_t **remembered = NULL;
	mutex_t **lockptr;
	uint_t nlocks;

	if ((nlocks = self->ul_heldlockcnt) != 0)
		lockptr = self->ul_heldlocks.array;
	else {
		nlocks = 1;
		lockptr = &self->ul_heldlocks.single;
	}

	for (; nlocks; nlocks--, lockptr++) {
		if (*lockptr == lock)
			return (lockptr);
		if (*lockptr == NULL && remembered == NULL)
			remembered = lockptr;
	}
	if (remembered != NULL) {
		*remembered = lock;
		return (remembered);
	}

	/*
	 * No entry available.  Allocate more space, converting
	 * the single entry into an array of entries if necessary.
	 */
	if ((nlocks = self->ul_heldlockcnt) == 0) {
		/*
		 * Initial allocation of the array.
		 * Convert the single entry into an array.
		 */
		self->ul_heldlockcnt = nlocks = INITIAL_LOCKS;
		lockptr = lmalloc(nlocks * sizeof (mutex_t *));
		/*
		 * The single entry becomes the first entry in the array.
		 */
		*lockptr = self->ul_heldlocks.single;
		self->ul_heldlocks.array = lockptr;
		/*
		 * Return the next available entry in the array.
		 */
		*++lockptr = lock;
		return (lockptr);
	}
	/*
	 * Reallocate the array, double the size each time.
	 */
	lockptr = lmalloc(nlocks * 2 * sizeof (mutex_t *));
	(void) _memcpy(lockptr, self->ul_heldlocks.array,
	    nlocks * sizeof (mutex_t *));
	lfree(self->ul_heldlocks.array, nlocks * sizeof (mutex_t *));
	self->ul_heldlocks.array = lockptr;
	self->ul_heldlockcnt *= 2;
	/*
	 * Return the next available entry in the newly allocated array.
	 */
	*(lockptr += nlocks) = lock;
	return (lockptr);
}

/*
 * Insert 'lock' into our list of held locks.
 * Currently only used for LOCK_ROBUST mutexes.
 */
void
remember_lock(mutex_t *lock)
{
	(void) find_lock_entry(lock);
}

/*
 * Remove 'lock' from our list of held locks.
 * Currently only used for LOCK_ROBUST mutexes.
 */
void
forget_lock(mutex_t *lock)
{
	*find_lock_entry(lock) = NULL;
}

/*
 * Free the array of held locks.
 */
void
heldlock_free(ulwp_t *ulwp)
{
	uint_t nlocks;

	if ((nlocks = ulwp->ul_heldlockcnt) != 0)
		lfree(ulwp->ul_heldlocks.array, nlocks * sizeof (mutex_t *));
	ulwp->ul_heldlockcnt = 0;
	ulwp->ul_heldlocks.array = NULL;
}

/*
 * Mark all held LOCK_ROBUST mutexes LOCK_OWNERDEAD.
 * Called from _thrp_exit() to deal with abandoned locks.
 */
void
heldlock_exit(void)
{
	ulwp_t *self = curthread;
	mutex_t **lockptr;
	uint_t nlocks;
	mutex_t *mp;

	if ((nlocks = self->ul_heldlockcnt) != 0)
		lockptr = self->ul_heldlocks.array;
	else {
		nlocks = 1;
		lockptr = &self->ul_heldlocks.single;
	}

	for (; nlocks; nlocks--, lockptr++) {
		/*
		 * The kernel takes care of transitioning held
		 * LOCK_PRIO_INHERIT mutexes to LOCK_OWNERDEAD.
		 * We avoid that case here.
		 */
		if ((mp = *lockptr) != NULL &&
		    mutex_is_held(mp) &&
		    (mp->mutex_type & (LOCK_ROBUST | LOCK_PRIO_INHERIT)) ==
		    LOCK_ROBUST) {
			mp->mutex_rcount = 0;
			if (!(mp->mutex_flag & LOCK_UNMAPPED))
				mp->mutex_flag |= LOCK_OWNERDEAD;
			(void) mutex_unlock_internal(mp, 1);
		}
	}

	heldlock_free(self);
}

#pragma weak cond_init = _cond_init
/* ARGSUSED2 */
int
_cond_init(cond_t *cvp, int type, void *arg)
{
	if (type != USYNC_THREAD && type != USYNC_PROCESS)
		return (EINVAL);
	(void) _memset(cvp, 0, sizeof (*cvp));
	cvp->cond_type = (uint16_t)type;
	cvp->cond_magic = COND_MAGIC;
	return (0);
}

/*
 * cond_sleep_queue(): utility function for cond_wait_queue().
 *
 * Go to sleep on a condvar sleep queue, expect to be waked up
 * by someone calling cond_signal() or cond_broadcast() or due
 * to receiving a UNIX signal or being cancelled, or just simply
 * due to a spurious wakeup (like someome calling forkall()).
 *
 * The associated mutex is *not* reacquired before returning.
 * That must be done by the caller of cond_sleep_queue().
 */
static int
cond_sleep_queue(cond_t *cvp, mutex_t *mp, timespec_t *tsp)
{
	ulwp_t *self = curthread;
	queue_head_t *qp;
	queue_head_t *mqp;
	lwpid_t lwpid;
	int signalled;
	int error;
	int release_all;

	/*
	 * Put ourself on the CV sleep queue, unlock the mutex, then
	 * park ourself and unpark a candidate lwp to grab the mutex.
	 * We must go onto the CV sleep queue before dropping the
	 * mutex in order to guarantee atomicity of the operation.
	 */
	self->ul_sp = stkptr();
	qp = queue_lock(cvp, CV);
	enqueue(qp, self, cvp, CV);
	cvp->cond_waiters_user = 1;
	self->ul_cvmutex = mp;
	self->ul_cv_wake = (tsp != NULL);
	self->ul_signalled = 0;
	if (mp->mutex_flag & LOCK_OWNERDEAD) {
		mp->mutex_flag &= ~LOCK_OWNERDEAD;
		mp->mutex_flag |= LOCK_NOTRECOVERABLE;
	}
	release_all = ((mp->mutex_flag & LOCK_NOTRECOVERABLE) != 0);
	lwpid = mutex_unlock_queue(mp, release_all);
	for (;;) {
		set_parking_flag(self, 1);
		queue_unlock(qp);
		if (lwpid != 0) {
			lwpid = preempt_unpark(self, lwpid);
			preempt(self);
		}
		/*
		 * We may have a deferred signal present,
		 * in which case we should return EINTR.
		 * Also, we may have received a SIGCANCEL; if so
		 * and we are cancelable we should return EINTR.
		 * We force an immediate EINTR return from
		 * __lwp_park() by turning our parking flag off.
		 */
		if (self->ul_cursig != 0 ||
		    (self->ul_cancelable && self->ul_cancel_pending))
			set_parking_flag(self, 0);
		/*
		 * __lwp_park() will return the residual time in tsp
		 * if we are unparked before the timeout expires.
		 */
		error = __lwp_park(tsp, lwpid);
		set_parking_flag(self, 0);
		lwpid = 0;	/* unpark the other lwp only once */
		/*
		 * We were waked up by cond_signal(), cond_broadcast(),
		 * by an interrupt or timeout (EINTR or ETIME),
		 * or we may just have gotten a spurious wakeup.
		 */
		qp = queue_lock(cvp, CV);
		mqp = queue_lock(mp, MX);
		if (self->ul_sleepq == NULL)
			break;
		/*
		 * We are on either the condvar sleep queue or the
		 * mutex sleep queue.  Break out of the sleep if we
		 * were interrupted or we timed out (EINTR or ETIME).
		 * Else this is a spurious wakeup; continue the loop.
		 */
		if (self->ul_sleepq == mqp) {		/* mutex queue */
			if (error) {
				mp->mutex_waiters = dequeue_self(mqp, mp);
				break;
			}
			tsp = NULL;	/* no more timeout */
		} else if (self->ul_sleepq == qp) {	/* condvar queue */
			if (error) {
				cvp->cond_waiters_user = dequeue_self(qp, cvp);
				break;
			}
			/*
			 * Else a spurious wakeup on the condvar queue.
			 * __lwp_park() has already adjusted the timeout.
			 */
		} else {
			thr_panic("cond_sleep_queue(): thread not on queue");
		}
		queue_unlock(mqp);
	}

	self->ul_sp = 0;
	ASSERT(self->ul_cvmutex == NULL && self->ul_cv_wake == 0);
	ASSERT(self->ul_sleepq == NULL && self->ul_link == NULL &&
	    self->ul_wchan == NULL);

	signalled = self->ul_signalled;
	self->ul_signalled = 0;
	queue_unlock(qp);
	queue_unlock(mqp);

	/*
	 * If we were concurrently cond_signal()d and any of:
	 * received a UNIX signal, were cancelled, or got a timeout,
	 * then perform another cond_signal() to avoid consuming it.
	 */
	if (error && signalled)
		(void) cond_signal_internal(cvp);

	return (error);
}

int
cond_wait_queue(cond_t *cvp, mutex_t *mp, timespec_t *tsp)
{
	ulwp_t *self = curthread;
	int error;
	int merror;

	/*
	 * The old thread library was programmed to defer signals
	 * while in cond_wait() so that the associated mutex would
	 * be guaranteed to be held when the application signal
	 * handler was invoked.
	 *
	 * We do not behave this way by default; the state of the
	 * associated mutex in the signal handler is undefined.
	 *
	 * To accommodate applications that depend on the old
	 * behavior, the _THREAD_COND_WAIT_DEFER environment
	 * variable can be set to 1 and we will behave in the
	 * old way with respect to cond_wait().
	 */
	if (self->ul_cond_wait_defer)
		sigoff(self);

	error = cond_sleep_queue(cvp, mp, tsp);

	/*
	 * Reacquire the mutex.
	 */
	if ((merror = mutex_lock_impl(mp, NULL)) != 0)
		error = merror;

	/*
	 * Take any deferred signal now, after we have reacquired the mutex.
	 */
	if (self->ul_cond_wait_defer)
		sigon(self);

	return (error);
}

/*
 * cond_sleep_kernel(): utility function for cond_wait_kernel().
 * See the comment ahead of cond_sleep_queue(), above.
 */
static int
cond_sleep_kernel(cond_t *cvp, mutex_t *mp, timespec_t *tsp)
{
	int mtype = mp->mutex_type;
	ulwp_t *self = curthread;
	int error;

	if ((mtype & LOCK_PRIO_PROTECT) && _ceil_mylist_del(mp))
		_ceil_prio_waive();

	self->ul_sp = stkptr();
	self->ul_wchan = cvp;
	mp->mutex_owner = 0;
	mp->mutex_ownerpid = 0;
	if (mtype & LOCK_PRIO_INHERIT)
		mp->mutex_lockw = LOCKCLEAR;
	/*
	 * ___lwp_cond_wait() returns immediately with EINTR if
	 * set_parking_flag(self,0) is called on this lwp before it
	 * goes to sleep in the kernel.  sigacthandler() calls this
	 * when a deferred signal is noted.  This assures that we don't
	 * get stuck in ___lwp_cond_wait() with all signals blocked
	 * due to taking a deferred signal before going to sleep.
	 */
	set_parking_flag(self, 1);
	if (self->ul_cursig != 0 ||
	    (self->ul_cancelable && self->ul_cancel_pending))
		set_parking_flag(self, 0);
	error = ___lwp_cond_wait(cvp, mp, tsp, 1);
	set_parking_flag(self, 0);
	self->ul_sp = 0;
	self->ul_wchan = NULL;
	return (error);
}

int
cond_wait_kernel(cond_t *cvp, mutex_t *mp, timespec_t *tsp)
{
	ulwp_t *self = curthread;
	int error;
	int merror;

	/*
	 * See the large comment in cond_wait_queue(), above.
	 */
	if (self->ul_cond_wait_defer)
		sigoff(self);

	error = cond_sleep_kernel(cvp, mp, tsp);

	/*
	 * Override the return code from ___lwp_cond_wait()
	 * with any non-zero return code from mutex_lock().
	 * This addresses robust lock failures in particular;
	 * the caller must see the EOWNERDEAD or ENOTRECOVERABLE
	 * errors in order to take corrective action.
	 */
	if ((merror = mutex_lock_impl(mp, NULL)) != 0)
		error = merror;

	/*
	 * Take any deferred signal now, after we have reacquired the mutex.
	 */
	if (self->ul_cond_wait_defer)
		sigon(self);

	return (error);
}

/*
 * Common code for _cond_wait() and _cond_timedwait()
 */
int
cond_wait_common(cond_t *cvp, mutex_t *mp, timespec_t *tsp)
{
	int mtype = mp->mutex_type;
	hrtime_t begin_sleep = 0;
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_cond_stats_t *csp = COND_STATS(cvp, udp);
	tdb_mutex_stats_t *msp = MUTEX_STATS(mp, udp);
	uint8_t rcount;
	int error = 0;

	/*
	 * The SUSV3 Posix spec for pthread_cond_timedwait() states:
	 *	Except in the case of [ETIMEDOUT], all these error checks
	 *	shall act as if they were performed immediately at the
	 *	beginning of processing for the function and shall cause
	 *	an error return, in effect, prior to modifying the state
	 *	of the mutex specified by mutex or the condition variable
	 *	specified by cond.
	 * Therefore, we must return EINVAL now if the timout is invalid.
	 */
	if (tsp != NULL &&
	    (tsp->tv_sec < 0 || (ulong_t)tsp->tv_nsec >= NANOSEC))
		return (EINVAL);

	if (__td_event_report(self, TD_SLEEP, udp)) {
		self->ul_sp = stkptr();
		self->ul_wchan = cvp;
		self->ul_td_evbuf.eventnum = TD_SLEEP;
		self->ul_td_evbuf.eventdata = cvp;
		tdb_event(TD_SLEEP, udp);
		self->ul_sp = 0;
	}
	if (csp) {
		if (tsp)
			tdb_incr(csp->cond_timedwait);
		else
			tdb_incr(csp->cond_wait);
	}
	if (msp)
		begin_sleep = record_hold_time(msp);
	else if (csp)
		begin_sleep = gethrtime();

	if (self->ul_error_detection) {
		if (!mutex_is_held(mp))
			lock_error(mp, "cond_wait", cvp, NULL);
		if ((mtype & LOCK_RECURSIVE) && mp->mutex_rcount != 0)
			lock_error(mp, "recursive mutex in cond_wait",
			    cvp, NULL);
		if (cvp->cond_type & USYNC_PROCESS) {
			if (!(mtype & USYNC_PROCESS))
				lock_error(mp, "cond_wait", cvp,
				    "condvar process-shared, "
				    "mutex process-private");
		} else {
			if (mtype & USYNC_PROCESS)
				lock_error(mp, "cond_wait", cvp,
				    "condvar process-private, "
				    "mutex process-shared");
		}
	}

	/*
	 * We deal with recursive mutexes by completely
	 * dropping the lock and restoring the recursion
	 * count after waking up.  This is arguably wrong,
	 * but it obeys the principle of least astonishment.
	 */
	rcount = mp->mutex_rcount;
	mp->mutex_rcount = 0;
	if ((mtype &
	    (USYNC_PROCESS | LOCK_PRIO_INHERIT | LOCK_PRIO_PROTECT)) |
	    (cvp->cond_type & USYNC_PROCESS))
		error = cond_wait_kernel(cvp, mp, tsp);
	else
		error = cond_wait_queue(cvp, mp, tsp);
	mp->mutex_rcount = rcount;

	if (csp) {
		hrtime_t lapse = gethrtime() - begin_sleep;
		if (tsp == NULL)
			csp->cond_wait_sleep_time += lapse;
		else {
			csp->cond_timedwait_sleep_time += lapse;
			if (error == ETIME)
				tdb_incr(csp->cond_timedwait_timeout);
		}
	}
	return (error);
}

/*
 * cond_wait() and _cond_wait() are cancellation points but __cond_wait()
 * is not.  Internally, libc calls the non-cancellation version.
 * Other libraries need to use pthread_setcancelstate(), as appropriate,
 * since __cond_wait() is not exported from libc.
 */
int
__cond_wait(cond_t *cvp, mutex_t *mp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	uberflags_t *gflags;

	/*
	 * Optimize the common case of USYNC_THREAD plus
	 * no error detection, no lock statistics, and no event tracing.
	 */
	if ((gflags = self->ul_schedctl_called) != NULL &&
	    (cvp->cond_type | mp->mutex_type | gflags->uf_trs_ted |
	    self->ul_td_events_enable |
	    udp->tdb.tdb_ev_global_mask.event_bits[0]) == 0)
		return (cond_wait_queue(cvp, mp, NULL));

	/*
	 * Else do it the long way.
	 */
	return (cond_wait_common(cvp, mp, NULL));
}

#pragma weak cond_wait = _cond_wait
int
_cond_wait(cond_t *cvp, mutex_t *mp)
{
	int error;

	_cancelon();
	error = __cond_wait(cvp, mp);
	if (error == EINTR)
		_canceloff();
	else
		_canceloff_nocancel();
	return (error);
}

/*
 * pthread_cond_wait() is a cancellation point.
 */
#pragma weak pthread_cond_wait = _pthread_cond_wait
int
_pthread_cond_wait(cond_t *cvp, mutex_t *mp)
{
	int error;

	error = _cond_wait(cvp, mp);
	return ((error == EINTR)? 0 : error);
}

/*
 * cond_timedwait() and _cond_timedwait() are cancellation points
 * but __cond_timedwait() is not.
 */
int
__cond_timedwait(cond_t *cvp, mutex_t *mp, const timespec_t *abstime)
{
	clockid_t clock_id = cvp->cond_clockid;
	timespec_t reltime;
	int error;

	if (clock_id != CLOCK_REALTIME && clock_id != CLOCK_HIGHRES)
		clock_id = CLOCK_REALTIME;
	abstime_to_reltime(clock_id, abstime, &reltime);
	error = cond_wait_common(cvp, mp, &reltime);
	if (error == ETIME && clock_id == CLOCK_HIGHRES) {
		/*
		 * Don't return ETIME if we didn't really get a timeout.
		 * This can happen if we return because someone resets
		 * the system clock.  Just return zero in this case,
		 * giving a spurious wakeup but not a timeout.
		 */
		if ((hrtime_t)(uint32_t)abstime->tv_sec * NANOSEC +
		    abstime->tv_nsec > gethrtime())
			error = 0;
	}
	return (error);
}

#pragma weak cond_timedwait = _cond_timedwait
int
_cond_timedwait(cond_t *cvp, mutex_t *mp, const timespec_t *abstime)
{
	int error;

	_cancelon();
	error = __cond_timedwait(cvp, mp, abstime);
	if (error == EINTR)
		_canceloff();
	else
		_canceloff_nocancel();
	return (error);
}

/*
 * pthread_cond_timedwait() is a cancellation point.
 */
#pragma weak pthread_cond_timedwait = _pthread_cond_timedwait
int
_pthread_cond_timedwait(cond_t *cvp, mutex_t *mp, const timespec_t *abstime)
{
	int error;

	error = _cond_timedwait(cvp, mp, abstime);
	if (error == ETIME)
		error = ETIMEDOUT;
	else if (error == EINTR)
		error = 0;
	return (error);
}

/*
 * cond_reltimedwait() and _cond_reltimedwait() are cancellation points
 * but __cond_reltimedwait() is not.
 */
int
__cond_reltimedwait(cond_t *cvp, mutex_t *mp, const timespec_t *reltime)
{
	timespec_t tslocal = *reltime;

	return (cond_wait_common(cvp, mp, &tslocal));
}

#pragma weak cond_reltimedwait = _cond_reltimedwait
int
_cond_reltimedwait(cond_t *cvp, mutex_t *mp, const timespec_t *reltime)
{
	int error;

	_cancelon();
	error = __cond_reltimedwait(cvp, mp, reltime);
	if (error == EINTR)
		_canceloff();
	else
		_canceloff_nocancel();
	return (error);
}

#pragma weak pthread_cond_reltimedwait_np = _pthread_cond_reltimedwait_np
int
_pthread_cond_reltimedwait_np(cond_t *cvp, mutex_t *mp,
	const timespec_t *reltime)
{
	int error;

	error = _cond_reltimedwait(cvp, mp, reltime);
	if (error == ETIME)
		error = ETIMEDOUT;
	else if (error == EINTR)
		error = 0;
	return (error);
}

#pragma weak pthread_cond_signal = cond_signal_internal
#pragma weak _pthread_cond_signal = cond_signal_internal
#pragma weak cond_signal = cond_signal_internal
#pragma weak _cond_signal = cond_signal_internal
int
cond_signal_internal(cond_t *cvp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_cond_stats_t *csp = COND_STATS(cvp, udp);
	int error = 0;
	queue_head_t *qp;
	mutex_t *mp;
	queue_head_t *mqp;
	ulwp_t **ulwpp;
	ulwp_t *ulwp;
	ulwp_t *prev = NULL;
	ulwp_t *next;
	ulwp_t **suspp = NULL;
	ulwp_t *susprev;

	if (csp)
		tdb_incr(csp->cond_signal);

	if (cvp->cond_waiters_kernel)	/* someone sleeping in the kernel? */
		error = __lwp_cond_signal(cvp);

	if (!cvp->cond_waiters_user)	/* no one sleeping at user-level */
		return (error);

	/*
	 * Move someone from the condvar sleep queue to the mutex sleep
	 * queue for the mutex that he will acquire on being waked up.
	 * We can do this only if we own the mutex he will acquire.
	 * If we do not own the mutex, or if his ul_cv_wake flag
	 * is set, just dequeue and unpark him.
	 */
	qp = queue_lock(cvp, CV);
	for (ulwpp = &qp->qh_head; (ulwp = *ulwpp) != NULL;
	    prev = ulwp, ulwpp = &ulwp->ul_link) {
		if (ulwp->ul_wchan == cvp) {
			if (!ulwp->ul_stop)
				break;
			/*
			 * Try not to dequeue a suspended thread.
			 * This mimics the old libthread's behavior.
			 */
			if (suspp == NULL) {
				suspp = ulwpp;
				susprev = prev;
			}
		}
	}
	if (ulwp == NULL && suspp != NULL) {
		ulwp = *(ulwpp = suspp);
		prev = susprev;
		suspp = NULL;
	}
	if (ulwp == NULL) {	/* no one on the sleep queue */
		cvp->cond_waiters_user = 0;
		queue_unlock(qp);
		return (error);
	}
	/*
	 * Scan the remainder of the CV queue for another waiter.
	 */
	if (suspp != NULL) {
		next = *suspp;
	} else {
		for (next = ulwp->ul_link; next != NULL; next = next->ul_link)
			if (next->ul_wchan == cvp)
				break;
	}
	if (next == NULL)
		cvp->cond_waiters_user = 0;

	/*
	 * Inform the thread that he was the recipient of a cond_signal().
	 * This lets him deal with cond_signal() and, concurrently,
	 * one or more of a cancellation, a UNIX signal, or a timeout.
	 * These latter conditions must not consume a cond_signal().
	 */
	ulwp->ul_signalled = 1;

	/*
	 * Dequeue the waiter but leave his ul_sleepq non-NULL
	 * while we move him to the mutex queue so that he can
	 * deal properly with spurious wakeups.
	 */
	*ulwpp = ulwp->ul_link;
	ulwp->ul_link = NULL;
	if (qp->qh_tail == ulwp)
		qp->qh_tail = prev;
	qp->qh_qlen--;

	mp = ulwp->ul_cvmutex;		/* the mutex he will acquire */
	ulwp->ul_cvmutex = NULL;
	ASSERT(mp != NULL);

	if (ulwp->ul_cv_wake || !MUTEX_OWNED(mp, self)) {
		lwpid_t lwpid = ulwp->ul_lwpid;

		no_preempt(self);
		ulwp->ul_sleepq = NULL;
		ulwp->ul_wchan = NULL;
		ulwp->ul_cv_wake = 0;
		queue_unlock(qp);
		(void) __lwp_unpark(lwpid);
		preempt(self);
	} else {
		mqp = queue_lock(mp, MX);
		enqueue(mqp, ulwp, mp, MX);
		mp->mutex_waiters = 1;
		queue_unlock(mqp);
		queue_unlock(qp);
	}

	return (error);
}

/*
 * Utility function called by mutex_wakeup_all(), cond_broadcast(),
 * and rw_queue_release() to (re)allocate a big buffer to hold the
 * lwpids of all the threads to be set running after they are removed
 * from their sleep queues.  Since we are holding a queue lock, we
 * cannot call any function that might acquire a lock.  mmap(), munmap(),
 * lwp_unpark_all() are simple system calls and are safe in this regard.
 */
lwpid_t *
alloc_lwpids(lwpid_t *lwpid, int *nlwpid_ptr, int *maxlwps_ptr)
{
	/*
	 * Allocate NEWLWPS ids on the first overflow.
	 * Double the allocation each time after that.
	 */
	int nlwpid = *nlwpid_ptr;
	int maxlwps = *maxlwps_ptr;
	int first_allocation;
	int newlwps;
	void *vaddr;

	ASSERT(nlwpid == maxlwps);

	first_allocation = (maxlwps == MAXLWPS);
	newlwps = first_allocation? NEWLWPS : 2 * maxlwps;
	vaddr = _private_mmap(NULL, newlwps * sizeof (lwpid_t),
	    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, (off_t)0);

	if (vaddr == MAP_FAILED) {
		/*
		 * Let's hope this never happens.
		 * If it does, then we have a terrible
		 * thundering herd on our hands.
		 */
		(void) __lwp_unpark_all(lwpid, nlwpid);
		*nlwpid_ptr = 0;
	} else {
		(void) _memcpy(vaddr, lwpid, maxlwps * sizeof (lwpid_t));
		if (!first_allocation)
			(void) _private_munmap(lwpid,
			    maxlwps * sizeof (lwpid_t));
		lwpid = vaddr;
		*maxlwps_ptr = newlwps;
	}

	return (lwpid);
}

#pragma weak pthread_cond_broadcast = cond_broadcast_internal
#pragma weak _pthread_cond_broadcast = cond_broadcast_internal
#pragma weak cond_broadcast = cond_broadcast_internal
#pragma weak _cond_broadcast = cond_broadcast_internal
int
cond_broadcast_internal(cond_t *cvp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_cond_stats_t *csp = COND_STATS(cvp, udp);
	int error = 0;
	queue_head_t *qp;
	mutex_t *mp;
	mutex_t *mp_cache = NULL;
	queue_head_t *mqp = NULL;
	ulwp_t **ulwpp;
	ulwp_t *ulwp;
	ulwp_t *prev = NULL;
	int nlwpid = 0;
	int maxlwps = MAXLWPS;
	lwpid_t buffer[MAXLWPS];
	lwpid_t *lwpid = buffer;

	if (csp)
		tdb_incr(csp->cond_broadcast);

	if (cvp->cond_waiters_kernel)	/* someone sleeping in the kernel? */
		error = __lwp_cond_broadcast(cvp);

	if (!cvp->cond_waiters_user)	/* no one sleeping at user-level */
		return (error);

	/*
	 * Move everyone from the condvar sleep queue to the mutex sleep
	 * queue for the mutex that they will acquire on being waked up.
	 * We can do this only if we own the mutex they will acquire.
	 * If we do not own the mutex, or if their ul_cv_wake flag
	 * is set, just dequeue and unpark them.
	 *
	 * We keep track of lwpids that are to be unparked in lwpid[].
	 * __lwp_unpark_all() is called to unpark all of them after
	 * they have been removed from the sleep queue and the sleep
	 * queue lock has been dropped.  If we run out of space in our
	 * on-stack buffer, we need to allocate more but we can't call
	 * lmalloc() because we are holding a queue lock when the overflow
	 * occurs and lmalloc() acquires a lock.  We can't use alloca()
	 * either because the application may have allocated a small
	 * stack and we don't want to overrun the stack.  So we call
	 * alloc_lwpids() to allocate a bigger buffer using the mmap()
	 * system call directly since that path acquires no locks.
	 */
	qp = queue_lock(cvp, CV);
	cvp->cond_waiters_user = 0;
	ulwpp = &qp->qh_head;
	while ((ulwp = *ulwpp) != NULL) {
		if (ulwp->ul_wchan != cvp) {
			prev = ulwp;
			ulwpp = &ulwp->ul_link;
			continue;
		}
		*ulwpp = ulwp->ul_link;
		ulwp->ul_link = NULL;
		if (qp->qh_tail == ulwp)
			qp->qh_tail = prev;
		qp->qh_qlen--;
		mp = ulwp->ul_cvmutex;		/* his mutex */
		ulwp->ul_cvmutex = NULL;
		ASSERT(mp != NULL);
		if (ulwp->ul_cv_wake || !MUTEX_OWNED(mp, self)) {
			ulwp->ul_sleepq = NULL;
			ulwp->ul_wchan = NULL;
			ulwp->ul_cv_wake = 0;
			if (nlwpid == maxlwps)
				lwpid = alloc_lwpids(lwpid, &nlwpid, &maxlwps);
			lwpid[nlwpid++] = ulwp->ul_lwpid;
		} else {
			if (mp != mp_cache) {
				mp_cache = mp;
				if (mqp != NULL)
					queue_unlock(mqp);
				mqp = queue_lock(mp, MX);
			}
			enqueue(mqp, ulwp, mp, MX);
			mp->mutex_waiters = 1;
		}
	}
	if (mqp != NULL)
		queue_unlock(mqp);
	if (nlwpid == 0) {
		queue_unlock(qp);
	} else {
		no_preempt(self);
		queue_unlock(qp);
		if (nlwpid == 1)
			(void) __lwp_unpark(lwpid[0]);
		else
			(void) __lwp_unpark_all(lwpid, nlwpid);
		preempt(self);
	}
	if (lwpid != buffer)
		(void) _private_munmap(lwpid, maxlwps * sizeof (lwpid_t));
	return (error);
}

#pragma weak pthread_cond_destroy = _cond_destroy
#pragma weak _pthread_cond_destroy = _cond_destroy
#pragma weak cond_destroy = _cond_destroy
int
_cond_destroy(cond_t *cvp)
{
	cvp->cond_magic = 0;
	tdb_sync_obj_deregister(cvp);
	return (0);
}

#if defined(THREAD_DEBUG)
void
assert_no_libc_locks_held(void)
{
	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
}
#endif

/* protected by link_lock */
uint64_t spin_lock_spin;
uint64_t spin_lock_spin2;
uint64_t spin_lock_sleep;
uint64_t spin_lock_wakeup;

/*
 * Record spin lock statistics.
 * Called by a thread exiting itself in thrp_exit().
 * Also called via atexit() from the thread calling
 * exit() to do all the other threads as well.
 */
void
record_spin_locks(ulwp_t *ulwp)
{
	spin_lock_spin += ulwp->ul_spin_lock_spin;
	spin_lock_spin2 += ulwp->ul_spin_lock_spin2;
	spin_lock_sleep += ulwp->ul_spin_lock_sleep;
	spin_lock_wakeup += ulwp->ul_spin_lock_wakeup;
	ulwp->ul_spin_lock_spin = 0;
	ulwp->ul_spin_lock_spin2 = 0;
	ulwp->ul_spin_lock_sleep = 0;
	ulwp->ul_spin_lock_wakeup = 0;
}

/*
 * atexit function:  dump the queue statistics to stderr.
 */
#if !defined(__lint)
#define	fprintf	_fprintf
#endif
#include <stdio.h>
void
dump_queue_statistics(void)
{
	uberdata_t *udp = curthread->ul_uberdata;
	queue_head_t *qp;
	int qn;
	uint64_t spin_lock_total = 0;

	if (udp->queue_head == NULL || thread_queue_dump == 0)
		return;

	if (fprintf(stderr, "\n%5d mutex queues:\n", QHASHSIZE) < 0 ||
	    fprintf(stderr, "queue#   lockcount    max qlen\n") < 0)
		return;
	for (qn = 0, qp = udp->queue_head; qn < QHASHSIZE; qn++, qp++) {
		if (qp->qh_lockcount == 0)
			continue;
		spin_lock_total += qp->qh_lockcount;
		if (fprintf(stderr, "%5d %12llu%12u\n", qn,
		    (u_longlong_t)qp->qh_lockcount, qp->qh_qmax) < 0)
			return;
	}

	if (fprintf(stderr, "\n%5d condvar queues:\n", QHASHSIZE) < 0 ||
	    fprintf(stderr, "queue#   lockcount    max qlen\n") < 0)
		return;
	for (qn = 0; qn < QHASHSIZE; qn++, qp++) {
		if (qp->qh_lockcount == 0)
			continue;
		spin_lock_total += qp->qh_lockcount;
		if (fprintf(stderr, "%5d %12llu%12u\n", qn,
		    (u_longlong_t)qp->qh_lockcount, qp->qh_qmax) < 0)
			return;
	}

	(void) fprintf(stderr, "\n  spin_lock_total  = %10llu\n",
	    (u_longlong_t)spin_lock_total);
	(void) fprintf(stderr, "  spin_lock_spin   = %10llu\n",
	    (u_longlong_t)spin_lock_spin);
	(void) fprintf(stderr, "  spin_lock_spin2  = %10llu\n",
	    (u_longlong_t)spin_lock_spin2);
	(void) fprintf(stderr, "  spin_lock_sleep  = %10llu\n",
	    (u_longlong_t)spin_lock_sleep);
	(void) fprintf(stderr, "  spin_lock_wakeup = %10llu\n",
	    (u_longlong_t)spin_lock_wakeup);
}
