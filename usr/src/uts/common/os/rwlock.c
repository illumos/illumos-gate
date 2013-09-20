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
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/thread.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/sobject.h>
#include <sys/turnstile.h>
#include <sys/rwlock.h>
#include <sys/rwlock_impl.h>
#include <sys/atomic.h>
#include <sys/lockstat.h>

/*
 * Big Theory Statement for readers/writer locking primitives.
 *
 * An rwlock provides exclusive access to a single thread ("writer") or
 * concurrent access to multiple threads ("readers").  See rwlock(9F)
 * for a full description of the interfaces and programming model.
 * The rest of this comment describes the implementation.
 *
 * An rwlock is a single word with the following structure:
 *
 *	---------------------------------------------------------------------
 *	| OWNER (writer) or HOLD COUNT (readers)   | WRLOCK | WRWANT | WAIT |
 *	---------------------------------------------------------------------
 *			63 / 31 .. 3			2	1	0
 *
 * The waiters bit (0) indicates whether any threads are blocked waiting
 * for the lock.  The write-wanted bit (1) indicates whether any threads
 * are blocked waiting for write access.  The write-locked bit (2) indicates
 * whether the lock is held by a writer, which determines whether the upper
 * bits (3..31 in ILP32, 3..63 in LP64) should be interpreted as the owner
 * (thread pointer) or the hold count (number of readers).
 *
 * In the absence of any contention, a writer gets the lock by setting
 * this word to (curthread | RW_WRITE_LOCKED); a reader gets the lock
 * by incrementing the hold count (i.e. adding 8, aka RW_READ_LOCK).
 *
 * A writer will fail to acquire the lock if any other thread owns it.
 * A reader will fail if the lock is either owned (in the RW_READER and
 * RW_READER_STARVEWRITER cases) or wanted by a writer (in the RW_READER
 * case). rw_tryenter() returns 0 in these cases; rw_enter() blocks until
 * the lock becomes available.
 *
 * When a thread blocks it acquires the rwlock's hashed turnstile lock and
 * attempts to set RW_HAS_WAITERS (and RW_WRITE_WANTED in the writer case)
 * atomically *only if the lock still appears busy*.  A thread must never
 * accidentally block for an available lock since there would be no owner
 * to awaken it.  casip() provides the required atomicity.  Once casip()
 * succeeds, the decision to block becomes final and irreversible.  The
 * thread will not become runnable again until it has been granted ownership
 * of the lock via direct handoff from a former owner as described below.
 *
 * In the absence of any waiters, rw_exit() just clears the lock (if it
 * is write-locked) or decrements the hold count (if it is read-locked).
 * Note that even if waiters are present, decrementing the hold count
 * to a non-zero value requires no special action since the lock is still
 * held by at least one other thread.
 *
 * On the "final exit" (transition to unheld state) of a lock with waiters,
 * rw_exit_wakeup() grabs the turnstile lock and transfers ownership directly
 * to the next writer or set of readers.  There are several advantages to this
 * approach: (1) it closes all windows for priority inversion (when a new
 * writer has grabbed the lock but has not yet inherited from blocked readers);
 * (2) it prevents starvation of equal-priority threads by granting the lock
 * in FIFO order; (3) it eliminates the need for a write-wanted count -- a
 * single bit suffices because the lock remains held until all waiting
 * writers are gone; (4) when we awaken N readers we can perform a single
 * "atomic_add(&x, N)" to set the total hold count rather than having all N
 * threads fight for the cache to perform an "atomic_add(&x, 1)" upon wakeup.
 *
 * The most interesting policy decision in rw_exit_wakeup() is which thread
 * to wake.  Starvation is always possible with priority-based scheduling,
 * but any sane wakeup policy should at least satisfy these requirements:
 *
 * (1) The highest-priority thread in the system should not starve.
 * (2) The highest-priority writer should not starve.
 * (3) No writer should starve due to lower-priority threads.
 * (4) No reader should starve due to lower-priority writers.
 * (5) If all threads have equal priority, none of them should starve.
 *
 * We used to employ a writers-always-win policy, which doesn't even
 * satisfy (1): a steady stream of low-priority writers can starve out
 * a real-time reader!  This is clearly a broken policy -- it violates
 * (1), (4), and (5) -- but it's how rwlocks always used to behave.
 *
 * A round-robin policy (exiting readers grant the lock to blocked writers
 * and vice versa) satisfies all but (3): a single high-priority writer
 * and many low-priority readers can starve out medium-priority writers.
 *
 * A strict priority policy (grant the lock to the highest priority blocked
 * thread) satisfies everything but (2): a steady stream of high-priority
 * readers can permanently starve the highest-priority writer.
 *
 * The reason we care about (2) is that it's important to process writers
 * reasonably quickly -- even if they're low priority -- because their very
 * presence causes all readers to take the slow (blocking) path through this
 * code.  There is also a general sense that writers deserve some degree of
 * deference because they're updating the data upon which all readers act.
 * Presumably this data should not be allowed to become arbitrarily stale
 * due to writer starvation.  Finally, it seems reasonable to level the
 * playing field a bit to compensate for the fact that it's so much harder
 * for a writer to get in when there are already many readers present.
 *
 * A hybrid of round-robin and strict priority can be made to satisfy
 * all five criteria.  In this "writer priority policy" exiting readers
 * always grant the lock to waiting writers, but exiting writers only
 * grant the lock to readers of the same or higher priority than the
 * highest-priority blocked writer.  Thus requirement (2) is satisfied,
 * necessarily, by a willful act of priority inversion: an exiting reader
 * will grant the lock to a blocked writer even if there are blocked
 * readers of higher priority.  The situation is mitigated by the fact
 * that writers always inherit priority from blocked readers, and the
 * writer will awaken those readers as soon as it exits the lock.
 *
 * Finally, note that this hybrid scheme -- and indeed, any scheme that
 * satisfies requirement (2) -- has an important consequence:  if a lock is
 * held as reader and a writer subsequently becomes blocked, any further
 * readers must be blocked to avoid writer starvation.  This implementation
 * detail has ramifications for the semantics of rwlocks, as it prohibits
 * recursively acquiring an rwlock as reader: any writer that wishes to
 * acquire the lock after the first but before the second acquisition as
 * reader will block the second acquisition -- resulting in deadlock.  This
 * itself is not necessarily prohibitive, as it is often straightforward to
 * prevent a single thread from recursively acquiring an rwlock as reader.
 * However, a more subtle situation arises when both a traditional mutex and
 * a reader lock are acquired by two different threads in opposite order.
 * (That is, one thread first acquires the mutex and then the rwlock as
 * reader; the other acquires the rwlock as reader and then the mutex.) As
 * with the single threaded case, this is fine absent a blocked writer: the
 * thread that acquires the mutex before acquiring the rwlock as reader will
 * be able to successfully acquire the rwlock -- even as/if the other thread
 * has the rwlock as reader and is blocked on the held mutex.  However, if
 * an unrelated writer (that is, a third thread) becomes blocked on the
 * rwlock after the first thread acquires the rwlock as reader but before
 * it's able to acquire the mutex, the second thread -- with the mutex held
 * -- will not be able to acquire the rwlock as reader due to the waiting
 * writer, deadlocking the three threads.  Unlike the single-threaded
 * (recursive) rwlock acquisition case, this case can be quite a bit
 * thornier to fix, especially as there is nothing inherently wrong in the
 * locking strategy: the deadlock is really induced by requirement (2), not
 * the consumers of the rwlock.  To permit such consumers, we allow rwlock
 * acquirers to explicitly opt out of requirement (2) by specifying
 * RW_READER_STARVEWRITER when acquiring the rwlock.  This (obviously) means
 * that inifinite readers can starve writers, but it also allows for
 * multiple readers in the presence of other synchronization primitives
 * without regard for lock-ordering.  And while certainly odd (and perhaps
 * unwise), RW_READER_STARVEWRITER can be safely used alongside RW_READER on
 * the same lock -- RW_READER_STARVEWRITER describes only the act of lock
 * acquisition with respect to waiting writers, not the lock itself.
 *
 * rw_downgrade() follows the same wakeup policy as an exiting writer.
 *
 * rw_tryupgrade() has the same failure mode as rw_tryenter() for a
 * write lock.  Both honor the WRITE_WANTED bit by specification.
 *
 * The following rules apply to manipulation of rwlock internal state:
 *
 * (1) The rwlock is only modified via the atomic primitives casip()
 *     and atomic_add_ip().
 *
 * (2) The waiters bit and write-wanted bit are only modified under
 *     turnstile_lookup().  This ensures that the turnstile is consistent
 *     with the rwlock.
 *
 * (3) Waiters receive the lock by direct handoff from the previous
 *     owner.  Therefore, waiters *always* wake up holding the lock.
 */

/*
 * The sobj_ops vector exports a set of functions needed when a thread
 * is asleep on a synchronization object of a given type.
 */
static sobj_ops_t rw_sobj_ops = {
	SOBJ_RWLOCK, rw_owner, turnstile_stay_asleep, turnstile_change_pri
};

/*
 * If the system panics on an rwlock, save the address of the offending
 * rwlock in panic_rwlock_addr, and save the contents in panic_rwlock.
 */
static rwlock_impl_t panic_rwlock;
static rwlock_impl_t *panic_rwlock_addr;

static void
rw_panic(char *msg, rwlock_impl_t *lp)
{
	if (panicstr)
		return;

	if (casptr(&panic_rwlock_addr, NULL, lp) == NULL)
		panic_rwlock = *lp;

	panic("%s, lp=%p wwwh=%lx thread=%p",
	    msg, (void *)lp, panic_rwlock.rw_wwwh, (void *)curthread);
}

/* ARGSUSED */
void
rw_init(krwlock_t *rwlp, char *name, krw_type_t type, void *arg)
{
	((rwlock_impl_t *)rwlp)->rw_wwwh = 0;
}

void
rw_destroy(krwlock_t *rwlp)
{
	rwlock_impl_t *lp = (rwlock_impl_t *)rwlp;

	if (lp->rw_wwwh != 0) {
		if ((lp->rw_wwwh & RW_DOUBLE_LOCK) == RW_DOUBLE_LOCK)
			rw_panic("rw_destroy: lock already destroyed", lp);
		else
			rw_panic("rw_destroy: lock still active", lp);
	}

	lp->rw_wwwh = RW_DOUBLE_LOCK;
}

/*
 * Verify that an rwlock is held correctly.
 */
static int
rw_locked(rwlock_impl_t *lp, krw_t rw)
{
	uintptr_t old = lp->rw_wwwh;

	if (rw == RW_READER || rw == RW_READER_STARVEWRITER)
		return ((old & RW_LOCKED) && !(old & RW_WRITE_LOCKED));

	if (rw == RW_WRITER)
		return ((old & RW_OWNER) == (uintptr_t)curthread);

	return (0);
}

uint_t (*rw_lock_backoff)(uint_t) = NULL;
void (*rw_lock_delay)(uint_t) = NULL;

/*
 * Full-service implementation of rw_enter() to handle all the hard cases.
 * Called from the assembly version if anything complicated is going on.
 * The only semantic difference between calling rw_enter() and calling
 * rw_enter_sleep() directly is that we assume the caller has already done
 * a THREAD_KPRI_REQUEST() in the RW_READER cases.
 */
void
rw_enter_sleep(rwlock_impl_t *lp, krw_t rw)
{
	uintptr_t old, new, lock_value, lock_busy, lock_wait;
	hrtime_t sleep_time;
	turnstile_t *ts;
	uint_t  backoff = 0;
	int loop_count = 0;

	if (rw == RW_READER) {
		lock_value = RW_READ_LOCK;
		lock_busy = RW_WRITE_CLAIMED;
		lock_wait = RW_HAS_WAITERS;
	} else if (rw == RW_READER_STARVEWRITER) {
		lock_value = RW_READ_LOCK;
		lock_busy = RW_WRITE_LOCKED;
		lock_wait = RW_HAS_WAITERS;
	} else {
		lock_value = RW_WRITE_LOCK(curthread);
		lock_busy = (uintptr_t)RW_LOCKED;
		lock_wait = RW_HAS_WAITERS | RW_WRITE_WANTED;
	}

	for (;;) {
		if (((old = lp->rw_wwwh) & lock_busy) == 0) {
			if (casip(&lp->rw_wwwh, old, old + lock_value) != old) {
				if (rw_lock_delay != NULL) {
					backoff = rw_lock_backoff(backoff);
					rw_lock_delay(backoff);
					if (++loop_count == ncpus_online) {
						backoff = 0;
						loop_count = 0;
					}
				}
				continue;
			}
			break;
		}

		if (panicstr)
			return;

		if ((old & RW_DOUBLE_LOCK) == RW_DOUBLE_LOCK) {
			rw_panic("rw_enter: bad rwlock", lp);
			return;
		}

		if ((old & RW_OWNER) == (uintptr_t)curthread) {
			rw_panic("recursive rw_enter", lp);
			return;
		}

		ts = turnstile_lookup(lp);

		do {
			if (((old = lp->rw_wwwh) & lock_busy) == 0)
				break;
			new = old | lock_wait;
		} while (old != new && casip(&lp->rw_wwwh, old, new) != old);

		if ((old & lock_busy) == 0) {
			/*
			 * The lock appears free now; try the dance again
			 */
			turnstile_exit(lp);
			continue;
		}

		/*
		 * We really are going to block.  Bump the stats, and drop
		 * kpri if we're a reader.
		 */
		ASSERT(lp->rw_wwwh & lock_wait);
		ASSERT(lp->rw_wwwh & RW_LOCKED);

		sleep_time = -gethrtime();
		if (rw != RW_WRITER) {
			THREAD_KPRI_RELEASE();
			CPU_STATS_ADDQ(CPU, sys, rw_rdfails, 1);
			(void) turnstile_block(ts, TS_READER_Q, lp,
			    &rw_sobj_ops, NULL, NULL);
		} else {
			CPU_STATS_ADDQ(CPU, sys, rw_wrfails, 1);
			(void) turnstile_block(ts, TS_WRITER_Q, lp,
			    &rw_sobj_ops, NULL, NULL);
		}
		sleep_time += gethrtime();

		LOCKSTAT_RECORD4(LS_RW_ENTER_BLOCK, lp, sleep_time, rw,
		    (old & RW_WRITE_LOCKED) ? 1 : 0,
		    old >> RW_HOLD_COUNT_SHIFT);

		/*
		 * We wake up holding the lock (and having kpri if we're
		 * a reader) via direct handoff from the previous owner.
		 */
		break;
	}

	ASSERT(rw_locked(lp, rw));

	membar_enter();

	LOCKSTAT_RECORD(LS_RW_ENTER_ACQUIRE, lp, rw);
}

/*
 * Return the number of readers to wake, or zero if we should wake a writer.
 * Called only by exiting/downgrading writers (readers don't wake readers).
 */
static int
rw_readers_to_wake(turnstile_t *ts)
{
	kthread_t *next_writer = ts->ts_sleepq[TS_WRITER_Q].sq_first;
	kthread_t *next_reader = ts->ts_sleepq[TS_READER_Q].sq_first;
	pri_t wpri = (next_writer != NULL) ? DISP_PRIO(next_writer) : -1;
	int count = 0;

	while (next_reader != NULL) {
		if (DISP_PRIO(next_reader) < wpri)
			break;
		next_reader->t_kpri_req++;
		next_reader = next_reader->t_link;
		count++;
	}
	return (count);
}

/*
 * Full-service implementation of rw_exit() to handle all the hard cases.
 * Called from the assembly version if anything complicated is going on.
 * There is no semantic difference between calling rw_exit() and calling
 * rw_exit_wakeup() directly.
 */
void
rw_exit_wakeup(rwlock_impl_t *lp)
{
	turnstile_t *ts;
	uintptr_t old, new, lock_value;
	kthread_t *next_writer;
	int nreaders;
	uint_t  backoff = 0;
	int loop_count = 0;

	membar_exit();

	old = lp->rw_wwwh;
	if (old & RW_WRITE_LOCKED) {
		if ((old & RW_OWNER) != (uintptr_t)curthread) {
			rw_panic("rw_exit: not owner", lp);
			lp->rw_wwwh = 0;
			return;
		}
		lock_value = RW_WRITE_LOCK(curthread);
	} else {
		if ((old & RW_LOCKED) == 0) {
			rw_panic("rw_exit: lock not held", lp);
			return;
		}
		lock_value = RW_READ_LOCK;
	}

	for (;;) {
		/*
		 * If this is *not* the final exit of a lock with waiters,
		 * just drop the lock -- there's nothing tricky going on.
		 */
		old = lp->rw_wwwh;
		new = old - lock_value;
		if ((new & (RW_LOCKED | RW_HAS_WAITERS)) != RW_HAS_WAITERS) {
			if (casip(&lp->rw_wwwh, old, new) != old) {
				if (rw_lock_delay != NULL) {
					backoff = rw_lock_backoff(backoff);
					rw_lock_delay(backoff);
					if (++loop_count == ncpus_online) {
						backoff = 0;
						loop_count = 0;
					}
				}
				continue;
			}
			break;
		}

		/*
		 * This appears to be the final exit of a lock with waiters.
		 * If we do not have the lock as writer (that is, if this is
		 * the last exit of a reader with waiting writers), we will
		 * grab the lock as writer to prevent additional readers.
		 * (This is required because a reader that is acquiring the
		 * lock via RW_READER_STARVEWRITER will not observe the
		 * RW_WRITE_WANTED bit -- and we could therefore be racing
		 * with such readers here.)
		 */
		if (!(old & RW_WRITE_LOCKED)) {
			new = RW_WRITE_LOCK(curthread) |
			    RW_HAS_WAITERS | RW_WRITE_WANTED;

			if (casip(&lp->rw_wwwh, old, new) != old)
				continue;
		}

		/*
		 * Perform the final exit of a lock that has waiters.
		 */
		ts = turnstile_lookup(lp);

		next_writer = ts->ts_sleepq[TS_WRITER_Q].sq_first;

		if ((old & RW_WRITE_LOCKED) &&
		    (nreaders = rw_readers_to_wake(ts)) > 0) {
			/*
			 * Don't drop the lock -- just set the hold count
			 * such that we grant the lock to all readers at once.
			 */
			new = nreaders * RW_READ_LOCK;
			if (ts->ts_waiters > nreaders)
				new |= RW_HAS_WAITERS;
			if (next_writer)
				new |= RW_WRITE_WANTED;
			lp->rw_wwwh = new;
			membar_enter();
			turnstile_wakeup(ts, TS_READER_Q, nreaders, NULL);
		} else {
			/*
			 * Don't drop the lock -- just transfer ownership
			 * directly to next_writer.  Note that there must
			 * be at least one waiting writer, because we get
			 * here only if (A) the lock is read-locked or
			 * (B) there are no waiting readers.  In case (A),
			 * since the lock is read-locked there would be no
			 * reason for other readers to have blocked unless
			 * the RW_WRITE_WANTED bit was set.  In case (B),
			 * since there are waiters but no waiting readers,
			 * they must all be waiting writers.
			 */
			ASSERT(lp->rw_wwwh & RW_WRITE_WANTED);
			new = RW_WRITE_LOCK(next_writer);
			if (ts->ts_waiters > 1)
				new |= RW_HAS_WAITERS;
			if (next_writer->t_link)
				new |= RW_WRITE_WANTED;
			lp->rw_wwwh = new;
			membar_enter();
			turnstile_wakeup(ts, TS_WRITER_Q, 1, next_writer);
		}
		break;
	}

	if (lock_value == RW_READ_LOCK) {
		THREAD_KPRI_RELEASE();
		LOCKSTAT_RECORD(LS_RW_EXIT_RELEASE, lp, RW_READER);
	} else {
		LOCKSTAT_RECORD(LS_RW_EXIT_RELEASE, lp, RW_WRITER);
	}
}

int
rw_tryenter(krwlock_t *rwlp, krw_t rw)
{
	rwlock_impl_t *lp = (rwlock_impl_t *)rwlp;
	uintptr_t old;

	if (rw != RW_WRITER) {
		uint_t backoff = 0;
		int loop_count = 0;
		THREAD_KPRI_REQUEST();
		for (;;) {
			if ((old = lp->rw_wwwh) & (rw == RW_READER ?
			    RW_WRITE_CLAIMED : RW_WRITE_LOCKED)) {
				THREAD_KPRI_RELEASE();
				return (0);
			}
			if (casip(&lp->rw_wwwh, old, old + RW_READ_LOCK) == old)
				break;
			if (rw_lock_delay != NULL) {
				backoff = rw_lock_backoff(backoff);
				rw_lock_delay(backoff);
				if (++loop_count == ncpus_online) {
					backoff = 0;
					loop_count = 0;
				}
			}
		}
		LOCKSTAT_RECORD(LS_RW_TRYENTER_ACQUIRE, lp, rw);
	} else {
		if (casip(&lp->rw_wwwh, 0, RW_WRITE_LOCK(curthread)) != 0)
			return (0);
		LOCKSTAT_RECORD(LS_RW_TRYENTER_ACQUIRE, lp, rw);
	}
	ASSERT(rw_locked(lp, rw));
	membar_enter();
	return (1);
}

void
rw_downgrade(krwlock_t *rwlp)
{
	rwlock_impl_t *lp = (rwlock_impl_t *)rwlp;

	THREAD_KPRI_REQUEST();
	membar_exit();

	if ((lp->rw_wwwh & RW_OWNER) != (uintptr_t)curthread) {
		rw_panic("rw_downgrade: not owner", lp);
		return;
	}

	if (atomic_add_ip_nv(&lp->rw_wwwh,
	    RW_READ_LOCK - RW_WRITE_LOCK(curthread)) & RW_HAS_WAITERS) {
		turnstile_t *ts = turnstile_lookup(lp);
		int nreaders = rw_readers_to_wake(ts);
		if (nreaders > 0) {
			uintptr_t delta = nreaders * RW_READ_LOCK;
			if (ts->ts_waiters == nreaders)
				delta -= RW_HAS_WAITERS;
			atomic_add_ip(&lp->rw_wwwh, delta);
		}
		turnstile_wakeup(ts, TS_READER_Q, nreaders, NULL);
	}
	ASSERT(rw_locked(lp, RW_READER));
	LOCKSTAT_RECORD0(LS_RW_DOWNGRADE_DOWNGRADE, lp);
}

int
rw_tryupgrade(krwlock_t *rwlp)
{
	rwlock_impl_t *lp = (rwlock_impl_t *)rwlp;
	uintptr_t old, new;

	ASSERT(rw_locked(lp, RW_READER));

	do {
		if (((old = lp->rw_wwwh) & ~RW_HAS_WAITERS) != RW_READ_LOCK)
			return (0);
		new = old + RW_WRITE_LOCK(curthread) - RW_READ_LOCK;
	} while (casip(&lp->rw_wwwh, old, new) != old);

	membar_enter();
	THREAD_KPRI_RELEASE();
	LOCKSTAT_RECORD0(LS_RW_TRYUPGRADE_UPGRADE, lp);
	ASSERT(rw_locked(lp, RW_WRITER));
	return (1);
}

int
rw_read_held(krwlock_t *rwlp)
{
	uintptr_t tmp;

	return (_RW_READ_HELD(rwlp, tmp));
}

int
rw_write_held(krwlock_t *rwlp)
{
	return (_RW_WRITE_HELD(rwlp));
}

int
rw_lock_held(krwlock_t *rwlp)
{
	return (_RW_LOCK_HELD(rwlp));
}

/*
 * Like rw_read_held(), but ASSERTs that the lock is currently held
 */
int
rw_read_locked(krwlock_t *rwlp)
{
	uintptr_t old = ((rwlock_impl_t *)rwlp)->rw_wwwh;

	ASSERT(old & RW_LOCKED);
	return ((old & RW_LOCKED) && !(old & RW_WRITE_LOCKED));
}

/*
 * Returns non-zero if the lock is either held or desired by a writer
 */
int
rw_iswriter(krwlock_t *rwlp)
{
	return (_RW_ISWRITER(rwlp));
}

kthread_t *
rw_owner(krwlock_t *rwlp)
{
	uintptr_t old = ((rwlock_impl_t *)rwlp)->rw_wwwh;

	return ((old & RW_WRITE_LOCKED) ? (kthread_t *)(old & RW_OWNER) : NULL);
}
