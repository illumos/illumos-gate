/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "thr_uberdata.h"

#include <sys/sdt.h>

#define	TRY_FLAG		0x10
#define	READ_LOCK		0
#define	WRITE_LOCK		1
#define	READ_LOCK_TRY		(READ_LOCK | TRY_FLAG)
#define	WRITE_LOCK_TRY		(WRITE_LOCK | TRY_FLAG)

#define	NLOCKS	4	/* initial number of readlock_t structs allocated */

/*
 * Find/allocate an entry for rwlp in our array of rwlocks held for reading.
 */
static readlock_t *
rwl_entry(rwlock_t *rwlp)
{
	ulwp_t *self = curthread;
	readlock_t *remembered = NULL;
	readlock_t *readlockp;
	uint_t nlocks;

	if ((nlocks = self->ul_rdlocks) != 0)
		readlockp = self->ul_readlock.array;
	else {
		nlocks = 1;
		readlockp = &self->ul_readlock.single;
	}

	for (; nlocks; nlocks--, readlockp++) {
		if (readlockp->rd_rwlock == rwlp)
			return (readlockp);
		if (readlockp->rd_count == 0 && remembered == NULL)
			remembered = readlockp;
	}
	if (remembered != NULL) {
		remembered->rd_rwlock = rwlp;
		return (remembered);
	}

	/*
	 * No entry available.  Allocate more space, converting the single
	 * readlock_t entry into an array of readlock_t entries if necessary.
	 */
	if ((nlocks = self->ul_rdlocks) == 0) {
		/*
		 * Initial allocation of the readlock_t array.
		 * Convert the single entry into an array.
		 */
		self->ul_rdlocks = nlocks = NLOCKS;
		readlockp = lmalloc(nlocks * sizeof (readlock_t));
		/*
		 * The single readlock_t becomes the first entry in the array.
		 */
		*readlockp = self->ul_readlock.single;
		self->ul_readlock.single.rd_count = 0;
		self->ul_readlock.array = readlockp;
		/*
		 * Return the next available entry in the array.
		 */
		(++readlockp)->rd_rwlock = rwlp;
		return (readlockp);
	}
	/*
	 * Reallocate the array, double the size each time.
	 */
	readlockp = lmalloc(nlocks * 2 * sizeof (readlock_t));
	(void) _memcpy(readlockp, self->ul_readlock.array,
		nlocks * sizeof (readlock_t));
	lfree(self->ul_readlock.array, nlocks * sizeof (readlock_t));
	self->ul_readlock.array = readlockp;
	self->ul_rdlocks *= 2;
	/*
	 * Return the next available entry in the newly allocated array.
	 */
	(readlockp += nlocks)->rd_rwlock = rwlp;
	return (readlockp);
}

/*
 * Free the array of rwlocks held for reading.
 */
void
rwl_free(ulwp_t *ulwp)
{
	uint_t nlocks;

	if ((nlocks = ulwp->ul_rdlocks) != 0)
		lfree(ulwp->ul_readlock.array, nlocks * sizeof (readlock_t));
	ulwp->ul_rdlocks = 0;
	ulwp->ul_readlock.single.rd_rwlock = NULL;
	ulwp->ul_readlock.single.rd_count = 0;
}

/*
 * Check if a reader version of the lock is held by the current thread.
 * rw_read_is_held() is private to libc.
 */
#pragma weak rw_read_is_held = _rw_read_held
#pragma weak rw_read_held = _rw_read_held
int
_rw_read_held(rwlock_t *rwlp)
{
	ulwp_t *self;
	readlock_t *readlockp;
	uint_t nlocks;

	/* quick answer */
	if (rwlp->rwlock_type == USYNC_PROCESS) {
		if (!((uint32_t)rwlp->rwlock_readers & URW_READERS_MASK))
			return (0);
	} else if (rwlp->rwlock_readers <= 0) {
		return (0);
	}

	/*
	 * The lock is held for reading by some thread.
	 * Search our array of rwlocks held for reading for a match.
	 */
	self = curthread;
	if ((nlocks = self->ul_rdlocks) != 0)
		readlockp = self->ul_readlock.array;
	else {
		nlocks = 1;
		readlockp = &self->ul_readlock.single;
	}

	for (; nlocks; nlocks--, readlockp++)
		if (readlockp->rd_rwlock == rwlp)
			return (readlockp->rd_count? 1 : 0);

	return (0);
}

/*
 * Check if a writer version of the lock is held by the current thread.
 * rw_write_is_held() is private to libc.
 */
#pragma weak rw_write_is_held = _rw_write_held
#pragma weak rw_write_held = _rw_write_held
int
_rw_write_held(rwlock_t *rwlp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;

	if (rwlp->rwlock_type == USYNC_PROCESS)
		return (((uint32_t)rwlp->rwlock_readers & URW_WRITE_LOCKED) &&
		    (rwlp->rwlock_ownerpid == udp->pid) &&
		    (rwlp->rwlock_owner == (uintptr_t)self));

	/* USYNC_THREAD */
	return (rwlp->rwlock_readers == -1 && mutex_is_held(&rwlp->mutex));
}

#pragma weak rwlock_init = __rwlock_init
#pragma weak _rwlock_init = __rwlock_init
/* ARGSUSED2 */
int
__rwlock_init(rwlock_t *rwlp, int type, void *arg)
{
	if (type != USYNC_THREAD && type != USYNC_PROCESS)
		return (EINVAL);
	/*
	 * Once reinitialized, we can no longer be holding a read or write lock.
	 * We can do nothing about other threads that are holding read locks.
	 */
	if (rw_read_is_held(rwlp))
		rwl_entry(rwlp)->rd_count = 0;
	(void) _memset(rwlp, 0, sizeof (*rwlp));
	rwlp->rwlock_type = (uint16_t)type;
	rwlp->rwlock_magic = RWL_MAGIC;
	rwlp->rwlock_readers = 0;
	rwlp->mutex.mutex_type = (uint8_t)type;
	rwlp->mutex.mutex_flag = LOCK_INITED;
	rwlp->mutex.mutex_magic = MUTEX_MAGIC;
	rwlp->readercv.cond_type = (uint16_t)type;
	rwlp->readercv.cond_magic = COND_MAGIC;
	rwlp->writercv.cond_type = (uint16_t)type;
	rwlp->writercv.cond_magic = COND_MAGIC;
	return (0);
}

#pragma weak rwlock_destroy = __rwlock_destroy
#pragma weak _rwlock_destroy = __rwlock_destroy
#pragma weak pthread_rwlock_destroy = __rwlock_destroy
#pragma weak _pthread_rwlock_destroy = __rwlock_destroy
int
__rwlock_destroy(rwlock_t *rwlp)
{
	/*
	 * Once destroyed, we can no longer be holding a read or write lock.
	 * We can do nothing about other threads that are holding read locks.
	 */
	if (rw_read_is_held(rwlp))
		rwl_entry(rwlp)->rd_count = 0;
	rwlp->rwlock_magic = 0;
	tdb_sync_obj_deregister(rwlp);
	return (0);
}

/*
 * Wake up the next thread sleeping on the rwlock queue and then
 * drop the queue lock.  Return non-zero if we wake up someone.
 *
 * This is called whenever a thread releases the lock and whenever a
 * thread successfully or unsuccessfully attempts to acquire the lock.
 * (Basically, whenever the state of the queue might have changed.)
 *
 * We wake up at most one thread.  If there are more threads to be
 * awakened, the next one will be waked up by the thread we wake up.
 * This ensures that queued threads will acquire the lock in priority
 * order and that queued writers will take precedence over queued
 * readers of the same priority.
 */
static int
rw_queue_release(queue_head_t *qp, rwlock_t *rwlp)
{
	ulwp_t *ulwp;
	int more;

	if (rwlp->rwlock_readers >= 0 && rwlp->rwlock_mwaiters) {
		/*
		 * The lock is free or at least is available to readers
		 * and there are (or might be) waiters on the queue.
		 */
		if (rwlp->rwlock_readers != 0 &&
		    (ulwp = queue_waiter(qp, rwlp)) == NULL)
			rwlp->rwlock_mwaiters = 0;
		else if (rwlp->rwlock_readers == 0 || !ulwp->ul_writer) {
			if ((ulwp = dequeue(qp, rwlp, &more)) == NULL)
				rwlp->rwlock_mwaiters = 0;
			else {
				ulwp_t *self = curthread;
				lwpid_t lwpid = ulwp->ul_lwpid;

				rwlp->rwlock_mwaiters = (more? 1 : 0);
				no_preempt(self);
				queue_unlock(qp);
				(void) __lwp_unpark(lwpid);
				preempt(self);
				return (1);
			}
		}
	}
	queue_unlock(qp);
	return (0);
}

/*
 * Common code for rdlock, timedrdlock, wrlock, timedwrlock, tryrdlock,
 * and trywrlock for process-shared (USYNC_PROCESS) rwlocks.
 *
 * Note: if the lock appears to be contended we call __lwp_rwlock_rdlock()
 * or __lwp_rwlock_wrlock() holding the mutex. These return with the mutex
 * released, and if they need to sleep will release the mutex first. In the
 * event of a spurious wakeup, these will return EAGAIN (because it is much
 * easier for us to re-acquire the mutex here).
 */
int
shared_rwlock_lock(rwlock_t *rwlp, timespec_t *tsp, int rd_wr)
{
	uint32_t *rwstate = (uint32_t *)&rwlp->readers;
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int try_flag;
	int error = 0;

	try_flag = (rd_wr & TRY_FLAG);
	rd_wr &= ~TRY_FLAG;
	ASSERT(rd_wr == READ_LOCK || rd_wr == WRITE_LOCK);

	if (!try_flag) {
		DTRACE_PROBE2(plockstat, rw__block, rwlp, rd_wr);
	}

	do {
		if ((error = _private_mutex_lock(&rwlp->mutex)) != 0)
			break;

		if (rd_wr == READ_LOCK) {
			/*
			 * We are a reader.
			 */

			if ((*rwstate & ~URW_READERS_MASK) == 0) {
				(*rwstate)++;
				(void) _private_mutex_unlock(&rwlp->mutex);
			} else if (try_flag) {
				if (*rwstate & URW_WRITE_LOCKED) {
					error = EBUSY;
					(void) _private_mutex_unlock(
					    &rwlp->mutex);
				} else {
					/*
					 * We have a higher priority than any
					 * queued waiters, or the waiters bit
					 * may be inaccurate. Only the kernel
					 * knows for sure.
					 */
					rwlp->rwlock_mowner = 0;
					rwlp->rwlock_mownerpid = 0;
					error = __lwp_rwlock_tryrdlock(rwlp);
				}
			} else {
				rwlp->rwlock_mowner = 0;
				rwlp->rwlock_mownerpid = 0;
				error = __lwp_rwlock_rdlock(rwlp, tsp);
			}
		} else {
			/*
			 * We are a writer.
			 */

			if (*rwstate == 0) {
				*rwstate = URW_WRITE_LOCKED;
				(void) _private_mutex_unlock(&rwlp->mutex);
			} else if (try_flag) {
				if (*rwstate & URW_WRITE_LOCKED) {
					error = EBUSY;
					(void) _private_mutex_unlock(
					    &rwlp->mutex);
				} else {
					/*
					 * The waiters bit may be inaccurate.
					 * Only the kernel knows for sure.
					 */
					rwlp->rwlock_mowner = 0;
					rwlp->rwlock_mownerpid = 0;
					error = __lwp_rwlock_trywrlock(rwlp);
				}
			} else {
				rwlp->rwlock_mowner = 0;
				rwlp->rwlock_mownerpid = 0;
				error = __lwp_rwlock_wrlock(rwlp, tsp);
			}
		}
	} while (error == EAGAIN);

	if (error == 0) {
		if (rd_wr == WRITE_LOCK) {
			rwlp->rwlock_owner = (uintptr_t)self;
			rwlp->rwlock_ownerpid = udp->pid;
		}
		if (!try_flag) {
			DTRACE_PROBE3(plockstat, rw__blocked, rwlp, rd_wr, 1);
		}
		DTRACE_PROBE2(plockstat, rw__acquire, rwlp, rd_wr);
	} else if (!try_flag) {
		DTRACE_PROBE3(plockstat, rw__blocked, rwlp, rd_wr, 0);
		DTRACE_PROBE3(plockstat, rw__error, rwlp, rd_wr, error);
	}
	return (error);
}

/*
 * Code for unlock of process-shared (USYNC_PROCESS) rwlocks.
 *
 * Note: if the lock appears to have waiters we call __lwp_rwlock_unlock()
 * holding the mutex. This returns with the mutex still held (for us to
 * release).
 */
int
shared_rwlock_unlock(rwlock_t *rwlp, int *waked)
{
	uint32_t *rwstate = (uint32_t *)&rwlp->readers;
	int error = 0;

	if ((error = _private_mutex_lock(&rwlp->mutex)) != 0)
		return (error);

	/* Reset flag used to suggest caller yields. */
	*waked = 0;

	/* Our right to unlock was checked in __rw_unlock(). */
	if (*rwstate & URW_WRITE_LOCKED) {
		rwlp->rwlock_owner = 0;
		rwlp->rwlock_ownerpid = 0;
	}

	if ((*rwstate & ~URW_READERS_MASK) == 0) {
		/* Simple multiple readers, no waiters case. */
		if (*rwstate > 0)
			(*rwstate)--;
	} else if (!(*rwstate & URW_HAS_WAITERS)) {
		/* Simple no waiters case (i.e. was write locked). */
		*rwstate = 0;
	} else {
		/*
		 * We appear to have waiters so we must call into the kernel.
		 * If there are waiters a full handoff will occur (rwstate
		 * will be updated, and one or more threads will be awoken).
		 */
		error = __lwp_rwlock_unlock(rwlp);

		/* Suggest caller yields. */
		*waked = 1;
	}

	(void) _private_mutex_unlock(&rwlp->mutex);

	if (error) {
		DTRACE_PROBE3(plockstat, rw__error, rwlp, 0, error);
	} else {
		DTRACE_PROBE2(plockstat, rw__release, rwlp, READ_LOCK);
	}

	return (error);
}


/*
 * Common code for rdlock, timedrdlock, wrlock, timedwrlock, tryrdlock,
 * and trywrlock for process-private (USYNC_THREAD) rwlocks.
 */
int
rwlock_lock(rwlock_t *rwlp, timespec_t *tsp, int rd_wr)
{
	ulwp_t *self = curthread;
	queue_head_t *qp;
	ulwp_t *ulwp;
	int try_flag;
	int error = 0;

	try_flag = (rd_wr & TRY_FLAG);
	rd_wr &= ~TRY_FLAG;
	ASSERT(rd_wr == READ_LOCK || rd_wr == WRITE_LOCK);

	/*
	 * Optimize for the case of having only a single thread.
	 * (Most likely a traditional single-threaded application.)
	 * We don't need the protection of queue_lock() in this case.
	 * We need to defer signals, however (the other form of concurrency).
	 */
	if (!self->ul_uberdata->uberflags.uf_mt) {
		sigoff(self);
		if (rwlp->rwlock_readers < 0 ||
		    (rd_wr == WRITE_LOCK && rwlp->rwlock_readers != 0)) {
			sigon(self);
			if (try_flag)
				return (EBUSY);
			/*
			 * Sombody other than ourself owns the lock.  (If we
			 * owned the lock, either for reading or writing, we
			 * would already have returned EDEADLK in our caller.)
			 * This can happen only in the child of fork1() when
			 * some now-defunct thread was holding the lock when
			 * the fork1() was executed by the current thread.
			 * In this case, we just fall into the long way
			 * to block, either forever or with a timeout.
			 */
			ASSERT(MUTEX_OWNER(&rwlp->mutex) != self);
		} else {
			if (rd_wr == READ_LOCK)
				rwlp->rwlock_readers++;
			else {
				rwlp->rwlock_readers = -1;
				rwlp->rwlock_mlockw = LOCKSET;
				rwlp->rwlock_mowner = (uintptr_t)self;
			}
			sigon(self);
			DTRACE_PROBE2(plockstat, rw__acquire, rwlp, rd_wr);
			return (0);
		}
	}

	if (!try_flag) {
		DTRACE_PROBE2(plockstat, rw__block, rwlp, rd_wr);
	}

	/*
	 * Do it the long way.
	 */
	qp = queue_lock(rwlp, MX);
	while (error == 0) {
		if (rwlp->rwlock_readers < 0 ||
		    (rd_wr == WRITE_LOCK && rwlp->rwlock_readers != 0))
			/* EMPTY */;	/* somebody holds the lock */
		else if (!rwlp->rwlock_mwaiters)
			break;		/* no queued waiters */
		else if ((ulwp = queue_waiter(qp, rwlp)) == NULL) {
			rwlp->rwlock_mwaiters = 0;
			break;		/* no queued waiters */
		} else {
			int our_pri = real_priority(self);
			int his_pri = real_priority(ulwp);

			if (rd_wr == WRITE_LOCK) {
				/*
				 * We defer to a queued thread that has
				 * a higher priority than ours.
				 */
				if (his_pri <= our_pri)
					break;
			} else {
				/*
				 * We defer to a queued thread that has
				 * a higher priority than ours or that
				 * is a writer whose priority equals ours.
				 */
				if (his_pri < our_pri ||
				    (his_pri == our_pri && !ulwp->ul_writer))
					break;
			}
		}
		/*
		 * We are about to block.
		 * If we're doing a trylock, return EBUSY instead.
		 */
		if (try_flag) {
			error = EBUSY;
			break;
		}
		/*
		 * Enqueue writers ahead of readers of the
		 * same priority.
		 */
		self->ul_writer = rd_wr;	/* *must* be 0 or 1 */
		enqueue(qp, self, rwlp, MX);
		rwlp->rwlock_mwaiters = 1;
		set_parking_flag(self, 1);
		queue_unlock(qp);
		if ((error = __lwp_park(tsp, 0)) == EINTR)
			error = 0;
		self->ul_writer = 0;
		set_parking_flag(self, 0);
		qp = queue_lock(rwlp, MX);
		if (self->ul_sleepq)	/* timeout or spurious wakeup */
			rwlp->rwlock_mwaiters = dequeue_self(qp, rwlp);
	}

	if (error == 0) {
		if (rd_wr == READ_LOCK)
			rwlp->rwlock_readers++;
		else {
			rwlp->rwlock_readers = -1;
			/* make it look like we acquired the embedded mutex */
			rwlp->rwlock_mlockw = LOCKSET;
			rwlp->rwlock_mowner = (uintptr_t)self;
		}
		if (!try_flag) {
			DTRACE_PROBE3(plockstat, rw__blocked, rwlp, rd_wr, 1);
		}
		DTRACE_PROBE2(plockstat, rw__acquire, rwlp, rd_wr);
	} else if (!try_flag) {
		DTRACE_PROBE3(plockstat, rw__blocked, rwlp, rd_wr, 0);
		DTRACE_PROBE3(plockstat, rw__error, rwlp, rd_wr, error);
	}

	(void) rw_queue_release(qp, rwlp);

	return (error);
}

int
rw_rdlock_impl(rwlock_t *rwlp, timespec_t *tsp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	readlock_t *readlockp;
	tdb_rwlock_stats_t *rwsp = RWLOCK_STATS(rwlp, udp);
	int error;

	/*
	 * If we already hold a readers lock on this rwlock,
	 * just increment our reference count and return.
	 */
	readlockp = rwl_entry(rwlp);
	if (readlockp->rd_count != 0) {
		if (readlockp->rd_count == READ_LOCK_MAX)
			return (EAGAIN);
		readlockp->rd_count++;
		DTRACE_PROBE2(plockstat, rw__acquire, rwlp, READ_LOCK);
		return (0);
	}

	/*
	 * If we hold the writer lock, bail out.
	 */
	if (rw_write_is_held(rwlp)) {
		if (self->ul_error_detection)
			rwlock_error(rwlp, "rwlock_rdlock",
			    "calling thread owns the writer lock");
		return (EDEADLK);
	}

	if (rwlp->rwlock_type == USYNC_PROCESS)		/* kernel-level */
		error = shared_rwlock_lock(rwlp, tsp, READ_LOCK);
	else						/* user-level */
		error = rwlock_lock(rwlp, tsp, READ_LOCK);

	if (error == 0) {
		readlockp->rd_count = 1;
		if (rwsp)
			tdb_incr(rwsp->rw_rdlock);
	}

	return (error);
}

#pragma weak rw_rdlock = __rw_rdlock
#pragma weak _rw_rdlock = __rw_rdlock
#pragma weak pthread_rwlock_rdlock = __rw_rdlock
#pragma weak _pthread_rwlock_rdlock = __rw_rdlock
int
__rw_rdlock(rwlock_t *rwlp)
{
	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	return (rw_rdlock_impl(rwlp, NULL));
}

void
lrw_rdlock(rwlock_t *rwlp)
{
	enter_critical(curthread);
	(void) rw_rdlock_impl(rwlp, NULL);
}

#pragma weak pthread_rwlock_reltimedrdlock_np = \
	_pthread_rwlock_reltimedrdlock_np
int
_pthread_rwlock_reltimedrdlock_np(rwlock_t *rwlp, const timespec_t *reltime)
{
	timespec_t tslocal = *reltime;
	int error;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	error = rw_rdlock_impl(rwlp, &tslocal);
	if (error == ETIME)
		error = ETIMEDOUT;
	return (error);
}

#pragma weak pthread_rwlock_timedrdlock = _pthread_rwlock_timedrdlock
int
_pthread_rwlock_timedrdlock(rwlock_t *rwlp, const timespec_t *abstime)
{
	timespec_t tslocal;
	int error;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	abstime_to_reltime(CLOCK_REALTIME, abstime, &tslocal);
	error = rw_rdlock_impl(rwlp, &tslocal);
	if (error == ETIME)
		error = ETIMEDOUT;
	return (error);
}

int
rw_wrlock_impl(rwlock_t *rwlp, timespec_t *tsp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_rwlock_stats_t *rwsp = RWLOCK_STATS(rwlp, udp);
	int error;

	/*
	 * If we hold a readers lock on this rwlock, bail out.
	 */
	if (rw_read_is_held(rwlp)) {
		if (self->ul_error_detection)
			rwlock_error(rwlp, "rwlock_wrlock",
			    "calling thread owns the readers lock");
		return (EDEADLK);
	}

	/*
	 * If we hold the writer lock, bail out.
	 */
	if (rw_write_is_held(rwlp)) {
		if (self->ul_error_detection)
			rwlock_error(rwlp, "rwlock_wrlock",
			    "calling thread owns the writer lock");
		return (EDEADLK);
	}

	if (rwlp->rwlock_type == USYNC_PROCESS) {	/* kernel-level */
		error = shared_rwlock_lock(rwlp, tsp, WRITE_LOCK);
	} else {					/* user-level */
		error = rwlock_lock(rwlp, tsp, WRITE_LOCK);
	}

	if (error == 0 && rwsp) {
		tdb_incr(rwsp->rw_wrlock);
		rwsp->rw_wrlock_begin_hold = gethrtime();
	}

	return (error);
}

#pragma weak rw_wrlock = __rw_wrlock
#pragma weak _rw_wrlock = __rw_wrlock
#pragma weak pthread_rwlock_wrlock = __rw_wrlock
#pragma weak _pthread_rwlock_wrlock = __rw_wrlock
int
__rw_wrlock(rwlock_t *rwlp)
{
	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	return (rw_wrlock_impl(rwlp, NULL));
}

void
lrw_wrlock(rwlock_t *rwlp)
{
	enter_critical(curthread);
	(void) rw_wrlock_impl(rwlp, NULL);
}

#pragma weak pthread_rwlock_reltimedwrlock_np = \
	_pthread_rwlock_reltimedwrlock_np
int
_pthread_rwlock_reltimedwrlock_np(rwlock_t *rwlp, const timespec_t *reltime)
{
	timespec_t tslocal = *reltime;
	int error;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	error = rw_wrlock_impl(rwlp, &tslocal);
	if (error == ETIME)
		error = ETIMEDOUT;
	return (error);
}

#pragma weak pthread_rwlock_timedwrlock = _pthread_rwlock_timedwrlock
int
_pthread_rwlock_timedwrlock(rwlock_t *rwlp, const timespec_t *abstime)
{
	timespec_t tslocal;
	int error;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	abstime_to_reltime(CLOCK_REALTIME, abstime, &tslocal);
	error = rw_wrlock_impl(rwlp, &tslocal);
	if (error == ETIME)
		error = ETIMEDOUT;
	return (error);
}

#pragma weak rw_tryrdlock = __rw_tryrdlock
#pragma weak _rw_tryrdlock = __rw_tryrdlock
#pragma weak pthread_rwlock_tryrdlock = __rw_tryrdlock
#pragma weak _pthread_rwlock_tryrdlock = __rw_tryrdlock
int
__rw_tryrdlock(rwlock_t *rwlp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_rwlock_stats_t *rwsp = RWLOCK_STATS(rwlp, udp);
	readlock_t *readlockp;
	int error;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);

	if (rwsp)
		tdb_incr(rwsp->rw_rdlock_try);

	/*
	 * If we already hold a readers lock on this rwlock,
	 * just increment our reference count and return.
	 */
	readlockp = rwl_entry(rwlp);
	if (readlockp->rd_count != 0) {
		if (readlockp->rd_count == READ_LOCK_MAX)
			return (EAGAIN);
		readlockp->rd_count++;
		DTRACE_PROBE2(plockstat, rw__acquire, rwlp, READ_LOCK);
		return (0);
	}

	if (rwlp->rwlock_type == USYNC_PROCESS)		/* kernel-level */
		error = shared_rwlock_lock(rwlp, NULL, READ_LOCK_TRY);
	else						/* user-level */
		error = rwlock_lock(rwlp, NULL, READ_LOCK_TRY);

	if (error == 0)
		readlockp->rd_count = 1;
	else if (rwsp)
		tdb_incr(rwsp->rw_rdlock_try_fail);

	return (error);
}

#pragma weak rw_trywrlock = __rw_trywrlock
#pragma weak _rw_trywrlock = __rw_trywrlock
#pragma weak pthread_rwlock_trywrlock = __rw_trywrlock
#pragma weak _pthread_rwlock_trywrlock = __rw_trywrlock
int
__rw_trywrlock(rwlock_t *rwlp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_rwlock_stats_t *rwsp = RWLOCK_STATS(rwlp, udp);
	int error;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);

	if (rwsp)
		tdb_incr(rwsp->rw_wrlock_try);

	if (rwlp->rwlock_type == USYNC_PROCESS) {	/* kernel-level */
		error = shared_rwlock_lock(rwlp, NULL, WRITE_LOCK_TRY);
	} else {					/* user-level */
		error = rwlock_lock(rwlp, NULL, WRITE_LOCK_TRY);
	}
	if (rwsp) {
		if (error)
			tdb_incr(rwsp->rw_wrlock_try_fail);
		else
			rwsp->rw_wrlock_begin_hold = gethrtime();
	}
	return (error);
}

#pragma weak rw_unlock = __rw_unlock
#pragma weak _rw_unlock = __rw_unlock
#pragma weak pthread_rwlock_unlock = __rw_unlock
#pragma weak _pthread_rwlock_unlock = __rw_unlock
int
__rw_unlock(rwlock_t *rwlp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_rwlock_stats_t *rwsp;
	int32_t lock_count;
	int waked;

	/* fetch the lock count once; it may change underfoot */
	lock_count = rwlp->rwlock_readers;
	if (rwlp->rwlock_type == USYNC_PROCESS) {
		/* munge it from rwstate */
		if (lock_count & URW_WRITE_LOCKED)
			lock_count = -1;
		else
			lock_count &= URW_READERS_MASK;
	}

	if (lock_count < 0) {
		/*
		 * Since the writer lock is held, we'd better be
		 * holding it, else we cannot legitimately be here.
		 */
		if (!rw_write_is_held(rwlp)) {
			if (self->ul_error_detection)
				rwlock_error(rwlp, "rwlock_unlock",
				    "writer lock held, "
				    "but not by the calling thread");
			return (EPERM);
		}
		if ((rwsp = RWLOCK_STATS(rwlp, udp)) != NULL) {
			if (rwsp->rw_wrlock_begin_hold)
				rwsp->rw_wrlock_hold_time +=
				    gethrtime() - rwsp->rw_wrlock_begin_hold;
			rwsp->rw_wrlock_begin_hold = 0;
		}
	} else if (lock_count > 0) {
		/*
		 * A readers lock is held; if we don't hold one, bail out.
		 */
		readlock_t *readlockp = rwl_entry(rwlp);
		if (readlockp->rd_count == 0) {
			if (self->ul_error_detection)
				rwlock_error(rwlp, "rwlock_unlock",
				    "readers lock held, "
				    "but not by the calling thread");
			return (EPERM);
		}
		/*
		 * If we hold more than one readers lock on this rwlock,
		 * just decrement our reference count and return.
		 */
		if (--readlockp->rd_count != 0) {
			DTRACE_PROBE2(plockstat, rw__release, rwlp, READ_LOCK);
			return (0);
		}
	} else {
		/*
		 * This is a usage error.
		 * No thread should release an unowned lock.
		 */
		if (self->ul_error_detection)
			rwlock_error(rwlp, "rwlock_unlock", "lock not owned");
		return (EPERM);
	}

	if (rwlp->rwlock_type == USYNC_PROCESS) {	/* kernel-level */
		(void) shared_rwlock_unlock(rwlp, &waked);
	} else if (!udp->uberflags.uf_mt) {		/* single threaded */
		/*
		 * In the case of having only a single thread, we don't
		 * need the protection of queue_lock() (this parallels
		 * the optimization made in rwlock_lock(), above).
		 * As in rwlock_lock(), we need to defer signals.
		 */
		sigoff(self);
		if (rwlp->rwlock_readers > 0) {
			rwlp->rwlock_readers--;
			DTRACE_PROBE2(plockstat, rw__release, rwlp, READ_LOCK);
		} else {
			rwlp->rwlock_readers = 0;
			/* make it look like we released the embedded mutex */
			rwlp->rwlock_mowner = 0;
			rwlp->rwlock_mlockw = LOCKCLEAR;
			DTRACE_PROBE2(plockstat, rw__release, rwlp, WRITE_LOCK);
		}
		sigon(self);
		waked = 0;
	} else {					/* multithreaded */
		queue_head_t *qp;

		qp = queue_lock(rwlp, MX);
		if (rwlp->rwlock_readers > 0) {
			rwlp->rwlock_readers--;
			DTRACE_PROBE2(plockstat, rw__release, rwlp, READ_LOCK);
		} else {
			rwlp->rwlock_readers = 0;
			/* make it look like we released the embedded mutex */
			rwlp->rwlock_mowner = 0;
			rwlp->rwlock_mlockw = LOCKCLEAR;
			DTRACE_PROBE2(plockstat, rw__release, rwlp, WRITE_LOCK);
		}
		waked = rw_queue_release(qp, rwlp);
	}

	/*
	 * Yield to the thread we just waked up, just in case we might
	 * be about to grab the rwlock again immediately upon return.
	 * This is pretty weak but it helps on a uniprocessor and also
	 * when cpu affinity has assigned both ourself and the other
	 * thread to the same CPU.  Note that lwp_yield() will yield
	 * the processor only if the writer is at the same or higher
	 * priority than ourself.  This provides more balanced program
	 * behavior; it doesn't guarantee acquisition of the lock by
	 * the pending writer.
	 */
	if (waked)
		lwp_yield();
	return (0);
}

void
lrw_unlock(rwlock_t *rwlp)
{
	(void) __rw_unlock(rwlp);
	exit_critical(curthread);
}
