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
 * Big Theory Statement for turnstiles.
 *
 * Turnstiles provide blocking and wakeup support, including priority
 * inheritance, for synchronization primitives (e.g. mutexes and rwlocks).
 * Typical usage is as follows:
 *
 * To block on lock 'lp' for read access in foo_enter():
 *
 *	ts = turnstile_lookup(lp);
 *	[ If the lock is still held, set the waiters bit
 *	turnstile_block(ts, TS_READER_Q, lp, &foo_sobj_ops);
 *
 * To wake threads waiting for write access to lock 'lp' in foo_exit():
 *
 *	ts = turnstile_lookup(lp);
 *	[ Either drop the lock (change owner to NULL) or perform a direct
 *	[ handoff (change owner to one of the threads we're about to wake).
 *	[ If we're going to wake the last waiter, clear the waiters bit.
 *	turnstile_wakeup(ts, TS_WRITER_Q, nwaiters, new_owner or NULL);
 *
 * turnstile_lookup() returns holding the turnstile hash chain lock for lp.
 * Both turnstile_block() and turnstile_wakeup() drop the turnstile lock.
 * To abort a turnstile operation, the client must call turnstile_exit().
 *
 * Requirements of the client:
 *
 * (1)  The lock's waiters indicator may be manipulated *only* while
 *	holding the turnstile hash chain lock (i.e. under turnstile_lookup()).
 *
 * (2)	Once the lock is marked as having waiters, the owner may be
 *	changed *only* while holding the turnstile hash chain lock.
 *
 * (3)	The caller must never block on an unheld lock.
 *
 * Consequences of these assumptions include the following:
 *
 * (a) It is impossible for a lock to be unheld but have waiters.
 *
 * (b)	The priority inheritance code can safely assume that an active
 *	turnstile's ts_inheritor never changes until the inheritor calls
 *	turnstile_pi_waive().
 *
 * These assumptions simplify the implementation of both turnstiles and
 * their clients.
 *
 * Background on priority inheritance:
 *
 * Priority inheritance allows a thread to "will" its dispatch priority
 * to all the threads blocking it, directly or indirectly.  This prevents
 * situations called priority inversions in which a high-priority thread
 * needs a lock held by a low-priority thread, which cannot run because
 * of medium-priority threads.  Without PI, the medium-priority threads
 * can starve out the high-priority thread indefinitely.  With PI, the
 * low-priority thread becomes high-priority until it releases whatever
 * synchronization object the real high-priority thread is waiting for.
 *
 * How turnstiles work:
 *
 * All active turnstiles reside in a global hash table, turnstile_table[].
 * The address of a synchronization object determines its hash index.
 * Each hash chain is protected by its own dispatcher lock, acquired
 * by turnstile_lookup().  This lock protects the hash chain linkage, the
 * contents of all turnstiles on the hash chain, and the waiters bits of
 * every synchronization object in the system that hashes to the same chain.
 * Giving the lock such broad scope simplifies the interactions between
 * the turnstile code and its clients considerably.  The blocking path
 * is rare enough that this has no impact on scalability.  (If it ever
 * does, it's almost surely a second-order effect -- the real problem
 * is that some synchronization object is *very* heavily contended.)
 *
 * Each thread has an attached turnstile in case it needs to block.
 * A thread cannot block on more than one lock at a time, so one
 * turnstile per thread is the most we ever need.  The first thread
 * to block on a lock donates its attached turnstile and adds it to
 * the appropriate hash chain in turnstile_table[].  This becomes the
 * "active turnstile" for the lock.  Each subsequent thread that blocks
 * on the same lock discovers that the lock already has an active
 * turnstile, so it stashes its own turnstile on the active turnstile's
 * freelist.  As threads wake up, the process is reversed.
 *
 * turnstile_block() puts the current thread to sleep on the active
 * turnstile for the desired lock, walks the blocking chain to apply
 * priority inheritance to everyone in its way, and yields the CPU.
 *
 * turnstile_wakeup() waives any priority the owner may have inherited
 * and wakes the specified number of waiting threads.  If the caller is
 * doing direct handoff of ownership (rather than just dropping the lock),
 * the new owner automatically inherits priority from any existing waiters.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/turnstile.h>
#include <sys/t_lock.h>
#include <sys/disp.h>
#include <sys/sobject.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/lockstat.h>
#include <sys/lwp_upimutex_impl.h>
#include <sys/schedctl.h>
#include <sys/cpu.h>
#include <sys/sdt.h>
#include <sys/cpupart.h>

extern upib_t upimutextab[UPIMUTEX_TABSIZE];

#define	IS_UPI(sobj)	\
	((uintptr_t)(sobj) - (uintptr_t)upimutextab < sizeof (upimutextab))

/*
 * The turnstile hash table is partitioned into two halves: the lower half
 * is used for upimutextab[] locks, the upper half for everything else.
 * The reason for the distinction is that SOBJ_USER_PI locks present a
 * unique problem: the upimutextab[] lock passed to turnstile_block()
 * cannot be dropped until the calling thread has blocked on its
 * SOBJ_USER_PI lock and willed its priority down the blocking chain.
 * At that point, the caller's t_lockp will be one of the turnstile locks.
 * If mutex_exit() discovers that the upimutextab[] lock has waiters, it
 * must wake them, which forces a lock ordering on us: the turnstile lock
 * for the upimutextab[] lock will be acquired in mutex_vector_exit(),
 * which will eventually call into turnstile_pi_waive(), which will then
 * acquire the caller's thread lock, which in this case is the turnstile
 * lock for the SOBJ_USER_PI lock.  In general, when two turnstile locks
 * must be held at the same time, the lock order must be the address order.
 * Therefore, to prevent deadlock in turnstile_pi_waive(), we must ensure
 * that upimutextab[] locks *always* hash to lower addresses than any
 * other locks.  You think this is cheesy?  Let's see you do better.
 */
#define	TURNSTILE_HASH_SIZE	128		/* must be power of 2 */
#define	TURNSTILE_HASH_MASK	(TURNSTILE_HASH_SIZE - 1)
#define	TURNSTILE_SOBJ_HASH(sobj)	\
	((((ulong_t)sobj >> 2) + ((ulong_t)sobj >> 9)) & TURNSTILE_HASH_MASK)
#define	TURNSTILE_SOBJ_BUCKET(sobj)		\
	((IS_UPI(sobj) ? 0 : TURNSTILE_HASH_SIZE) + TURNSTILE_SOBJ_HASH(sobj))
#define	TURNSTILE_CHAIN(sobj)	turnstile_table[TURNSTILE_SOBJ_BUCKET(sobj)]

typedef struct turnstile_chain {
	turnstile_t	*tc_first;	/* first turnstile on hash chain */
	disp_lock_t	tc_lock;	/* lock for this hash chain */
} turnstile_chain_t;

turnstile_chain_t	turnstile_table[2 * TURNSTILE_HASH_SIZE];

static	lock_t	turnstile_loser_lock;

/*
 * Make 'inheritor' inherit priority from this turnstile.
 */
static void
turnstile_pi_inherit(turnstile_t *ts, kthread_t *inheritor, pri_t epri)
{
	ASSERT(THREAD_LOCK_HELD(inheritor));
	ASSERT(DISP_LOCK_HELD(&TURNSTILE_CHAIN(ts->ts_sobj).tc_lock));

	if (epri <= inheritor->t_pri)
		return;

	if (ts->ts_inheritor == NULL) {
		ts->ts_inheritor = inheritor;
		ts->ts_epri = epri;
		disp_lock_enter_high(&inheritor->t_pi_lock);
		ts->ts_prioinv = inheritor->t_prioinv;
		inheritor->t_prioinv = ts;
		disp_lock_exit_high(&inheritor->t_pi_lock);
	} else {
		/*
		 * 'inheritor' is already inheriting from this turnstile,
		 * so just adjust its priority.
		 */
		ASSERT(ts->ts_inheritor == inheritor);
		if (ts->ts_epri < epri)
			ts->ts_epri = epri;
	}

	if (epri > DISP_PRIO(inheritor))
		thread_change_epri(inheritor, epri);
}

/*
 * If turnstile is non-NULL, remove it from inheritor's t_prioinv list.
 * Compute new inherited priority, and return it.
 */
static pri_t
turnstile_pi_tsdelete(turnstile_t *ts, kthread_t *inheritor)
{
	turnstile_t **tspp, *tsp;
	pri_t new_epri = 0;

	disp_lock_enter_high(&inheritor->t_pi_lock);
	tspp = &inheritor->t_prioinv;
	while ((tsp = *tspp) != NULL) {
		if (tsp == ts)
			*tspp = tsp->ts_prioinv;
		else
			new_epri = MAX(new_epri, tsp->ts_epri);
		tspp = &tsp->ts_prioinv;
	}
	disp_lock_exit_high(&inheritor->t_pi_lock);
	return (new_epri);
}

/*
 * Remove turnstile from inheritor's t_prioinv list, compute
 * new priority, and change the inheritor's effective priority if
 * necessary. Keep in synch with turnstile_pi_recalc().
 */
static void
turnstile_pi_waive(turnstile_t *ts)
{
	kthread_t *inheritor = ts->ts_inheritor;
	pri_t new_epri;

	ASSERT(inheritor == curthread);

	thread_lock_high(inheritor);
	new_epri = turnstile_pi_tsdelete(ts, inheritor);
	if (new_epri != DISP_PRIO(inheritor))
		thread_change_epri(inheritor, new_epri);
	ts->ts_inheritor = NULL;
	if (DISP_MUST_SURRENDER(inheritor))
		cpu_surrender(inheritor);
	thread_unlock_high(inheritor);
}

/*
 * Compute caller's new inherited priority, and change its effective
 * priority if necessary. Necessary only for SOBJ_USER_PI, because of
 * its interruptibility characteristic.
 */
void
turnstile_pi_recalc(void)
{
	kthread_t *inheritor = curthread;
	pri_t new_epri;

	thread_lock(inheritor);
	new_epri = turnstile_pi_tsdelete(NULL, inheritor);
	if (new_epri != DISP_PRIO(inheritor))
		thread_change_epri(inheritor, new_epri);
	if (DISP_MUST_SURRENDER(inheritor))
		cpu_surrender(inheritor);
	thread_unlock(inheritor);
}

/*
 * Grab the lock protecting the hash chain for sobj
 * and return the active turnstile for sobj, if any.
 */
turnstile_t *
turnstile_lookup(void *sobj)
{
	turnstile_t *ts;
	turnstile_chain_t *tc = &TURNSTILE_CHAIN(sobj);

	disp_lock_enter(&tc->tc_lock);

	for (ts = tc->tc_first; ts != NULL; ts = ts->ts_next)
		if (ts->ts_sobj == sobj)
			break;

	return (ts);
}

/*
 * Drop the lock protecting the hash chain for sobj.
 */
void
turnstile_exit(void *sobj)
{
	disp_lock_exit(&TURNSTILE_CHAIN(sobj).tc_lock);
}

/*
 * When we apply priority inheritance, we must grab the owner's thread lock
 * while already holding the waiter's thread lock.  If both thread locks are
 * turnstile locks, this can lead to deadlock: while we hold L1 and try to
 * grab L2, some unrelated thread may be applying priority inheritance to
 * some other blocking chain, holding L2 and trying to grab L1.  The most
 * obvious solution -- do a lock_try() for the owner lock -- isn't quite
 * sufficient because it can cause livelock: each thread may hold one lock,
 * try to grab the other, fail, bail out, and try again, looping forever.
 * To prevent livelock we must define a winner, i.e. define an arbitrary
 * lock ordering on the turnstile locks.  For simplicity we declare that
 * virtual address order defines lock order, i.e. if L1 < L2, then the
 * correct lock ordering is L1, L2.  Thus the thread that holds L1 and
 * wants L2 should spin until L2 is available, but the thread that holds
 * L2 and can't get L1 on the first try must drop L2 and return failure.
 * Moreover, the losing thread must not reacquire L2 until the winning
 * thread has had a chance to grab it; to ensure this, the losing thread
 * must grab L1 after dropping L2, thus spinning until the winner is done.
 * Complicating matters further, note that the owner's thread lock pointer
 * can change (i.e. be pointed at a different lock) while we're trying to
 * grab it.  If that happens, we must unwind our state and try again.
 *
 * On success, returns 1 with both locks held.
 * On failure, returns 0 with neither lock held.
 */
static int
turnstile_interlock(lock_t *wlp, lock_t *volatile *olpp)
{
	ASSERT(LOCK_HELD(wlp));

	for (;;) {
		volatile lock_t *olp = *olpp;

		/*
		 * If the locks are identical, there's nothing to do.
		 */
		if (olp == wlp)
			return (1);
		if (lock_try((lock_t *)olp)) {
			/*
			 * If 'olp' is still the right lock, return success.
			 * Otherwise, drop 'olp' and try the dance again.
			 */
			if (olp == *olpp)
				return (1);
			lock_clear((lock_t *)olp);
		} else {
			hrtime_t spin_time = 0;
			/*
			 * If we're grabbing the locks out of order, we lose.
			 * Drop the waiter's lock, and then grab and release
			 * the owner's lock to ensure that we won't retry
			 * until the winner is done (as described above).
			 */
			if (olp >= (lock_t *)turnstile_table && olp < wlp) {
				lock_clear(wlp);
				lock_set((lock_t *)olp);
				lock_clear((lock_t *)olp);
				return (0);
			}
			/*
			 * We're grabbing the locks in the right order,
			 * so spin until the owner's lock either becomes
			 * available or spontaneously changes.
			 */
			spin_time =
			    LOCKSTAT_START_TIME(LS_TURNSTILE_INTERLOCK_SPIN);
			while (olp == *olpp && LOCK_HELD(olp)) {
				if (panicstr)
					return (1);
				SMT_PAUSE();
			}
			LOCKSTAT_RECORD_TIME(LS_TURNSTILE_INTERLOCK_SPIN,
			    olp, spin_time);
		}
	}
}

/*
 * Block the current thread on a synchronization object.
 *
 * Turnstiles implement both kernel and user-level priority inheritance.
 * To avoid missed wakeups in the user-level case, lwp_upimutex_lock() calls
 * turnstile_block() holding the appropriate lock in the upimutextab (see
 * the block comment in lwp_upimutex_lock() for details).  The held lock is
 * passed to turnstile_block() as the "mp" parameter, and will be dropped
 * after priority has been willed, but before the thread actually sleeps
 * (this locking behavior leads to some subtle ordering issues; see the
 * block comment on turnstile hashing for details).  This _must_ be the only
 * lock held when calling turnstile_block() with a SOBJ_USER_PI sobj; holding
 * other locks can result in panics due to cycles in the blocking chain.
 *
 * turnstile_block() always succeeds for kernel synchronization objects.
 * For SOBJ_USER_PI locks the possible errors are EINTR for signals, and
 * EDEADLK for cycles in the blocking chain. A return code of zero indicates
 * *either* that the lock is now held, or that this is a spurious wake-up, or
 * that the lock can never be held due to an ENOTRECOVERABLE error.
 * It is up to lwp_upimutex_lock() to sort this all out.
 */

int
turnstile_block(turnstile_t *ts, int qnum, void *sobj, sobj_ops_t *sobj_ops,
    kmutex_t *mp, lwp_timer_t *lwptp)
{
	kthread_t *owner;
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	turnstile_chain_t *tc = &TURNSTILE_CHAIN(sobj);
	int error = 0;
	int loser = 0;

	ASSERT(DISP_LOCK_HELD(&tc->tc_lock));
	ASSERT(mp == NULL || IS_UPI(mp));
	ASSERT((SOBJ_TYPE(sobj_ops) == SOBJ_USER_PI) ^ (mp == NULL));

	thread_lock_high(t);

	if (ts == NULL) {
		/*
		 * This is the first thread to block on this sobj.
		 * Take its attached turnstile and add it to the hash chain.
		 */
		ts = t->t_ts;
		ts->ts_sobj = sobj;
		ts->ts_next = tc->tc_first;
		tc->tc_first = ts;
		ASSERT(ts->ts_waiters == 0);
	} else {
		/*
		 * Another thread has already donated its turnstile
		 * to block on this sobj, so ours isn't needed.
		 * Stash it on the active turnstile's freelist.
		 */
		turnstile_t *myts = t->t_ts;
		myts->ts_free = ts->ts_free;
		ts->ts_free = myts;
		t->t_ts = ts;
		ASSERT(ts->ts_sobj == sobj);
		ASSERT(ts->ts_waiters > 0);
	}

	/*
	 * Put the thread to sleep.
	 */
	ASSERT(t != CPU->cpu_idle_thread);
	ASSERT(CPU_ON_INTR(CPU) == 0);
	ASSERT(t->t_wchan0 == NULL && t->t_wchan == NULL);
	ASSERT(t->t_state == TS_ONPROC);

	if (SOBJ_TYPE(sobj_ops) == SOBJ_USER_PI) {
		curthread->t_flag |= T_WAKEABLE;
	}
	CL_SLEEP(t);		/* assign kernel priority */
	THREAD_SLEEP(t, &tc->tc_lock);
	t->t_wchan = sobj;
	t->t_sobj_ops = sobj_ops;
	DTRACE_SCHED(sleep);

	if (lwp != NULL) {
		lwp->lwp_ru.nvcsw++;
		(void) new_mstate(t, LMS_SLEEP);
		if (SOBJ_TYPE(sobj_ops) == SOBJ_USER_PI) {
			lwp->lwp_asleep = 1;
			lwp->lwp_sysabort = 0;
			/*
			 * make wchan0 non-zero to conform to the rule that
			 * threads blocking for user-level objects have a
			 * non-zero wchan0: this prevents spurious wake-ups
			 * by, for example, /proc.
			 */
			t->t_wchan0 = (caddr_t)1;
		}
	}
	ts->ts_waiters++;
	sleepq_insert(&ts->ts_sleepq[qnum], t);

	if (SOBJ_TYPE(sobj_ops) == SOBJ_MUTEX &&
	    SOBJ_OWNER(sobj_ops, sobj) == NULL)
		panic("turnstile_block(%p): unowned mutex", (void *)ts);

	/*
	 * Follow the blocking chain to its end, willing our priority to
	 * everyone who's in our way.
	 */
	while (t->t_sobj_ops != NULL &&
	    (owner = SOBJ_OWNER(t->t_sobj_ops, t->t_wchan)) != NULL) {
		if (owner == curthread) {
			if (SOBJ_TYPE(sobj_ops) != SOBJ_USER_PI) {
				panic("Deadlock: cycle in blocking chain");
			}
			/*
			 * If the cycle we've encountered ends in mp,
			 * then we know it isn't a 'real' cycle because
			 * we're going to drop mp before we go to sleep.
			 * Moreover, since we've come full circle we know
			 * that we must have willed priority to everyone
			 * in our way.  Therefore, we can break out now.
			 */
			if (t->t_wchan == (void *)mp)
				break;

			if (loser)
				lock_clear(&turnstile_loser_lock);
			/*
			 * For SOBJ_USER_PI, a cycle is an application
			 * deadlock which needs to be communicated
			 * back to the application.
			 */
			thread_unlock_nopreempt(t);
			mutex_exit(mp);
			setrun(curthread);
			swtch(); /* necessary to transition state */
			curthread->t_flag &= ~T_WAKEABLE;
			if (lwptp->lwpt_id != 0)
				(void) lwp_timer_dequeue(lwptp);
			setallwatch();
			lwp->lwp_asleep = 0;
			lwp->lwp_sysabort = 0;
			return (EDEADLK);
		}
		if (!turnstile_interlock(t->t_lockp, &owner->t_lockp)) {
			/*
			 * If we failed to grab the owner's thread lock,
			 * turnstile_interlock() will have dropped t's
			 * thread lock, so at this point we don't even know
			 * that 't' exists anymore.  The simplest solution
			 * is to restart the entire priority inheritance dance
			 * from the beginning of the blocking chain, since
			 * we *do* know that 'curthread' still exists.
			 * Application of priority inheritance is idempotent,
			 * so it's OK that we're doing it more than once.
			 * Note also that since we've dropped our thread lock,
			 * we may already have been woken up; if so, our
			 * t_sobj_ops will be NULL, the loop will terminate,
			 * and the call to swtch() will be a no-op.  Phew.
			 *
			 * There is one further complication: if two (or more)
			 * threads keep trying to grab the turnstile locks out
			 * of order and keep losing the race to another thread,
			 * these "dueling losers" can livelock the system.
			 * Therefore, once we get into this rare situation,
			 * we serialize all the losers.
			 */
			if (loser == 0) {
				loser = 1;
				lock_set(&turnstile_loser_lock);
			}
			t = curthread;
			thread_lock_high(t);
			continue;
		}

		/*
		 * We now have the owner's thread lock.  If we are traversing
		 * from non-SOBJ_USER_PI ops to SOBJ_USER_PI ops, then we know
		 * that we have caught the thread while in the TS_SLEEP state,
		 * but holding mp.  We know that this situation is transient
		 * (mp will be dropped before the holder actually sleeps on
		 * the SOBJ_USER_PI sobj), so we will spin waiting for mp to
		 * be dropped.  Then, as in the turnstile_interlock() failure
		 * case, we will restart the priority inheritance dance.
		 */
		if (SOBJ_TYPE(t->t_sobj_ops) != SOBJ_USER_PI &&
		    owner->t_sobj_ops != NULL &&
		    SOBJ_TYPE(owner->t_sobj_ops) == SOBJ_USER_PI) {
			kmutex_t *upi_lock = (kmutex_t *)t->t_wchan;

			ASSERT(IS_UPI(upi_lock));
			ASSERT(SOBJ_TYPE(t->t_sobj_ops) == SOBJ_MUTEX);

			if (t->t_lockp != owner->t_lockp)
				thread_unlock_high(owner);
			thread_unlock_high(t);
			if (loser)
				lock_clear(&turnstile_loser_lock);

			while (mutex_owner(upi_lock) == owner) {
				SMT_PAUSE();
				continue;
			}

			if (loser)
				lock_set(&turnstile_loser_lock);
			t = curthread;
			thread_lock_high(t);
			continue;
		}

		turnstile_pi_inherit(t->t_ts, owner, DISP_PRIO(t));
		if (t->t_lockp != owner->t_lockp)
			thread_unlock_high(t);
		t = owner;
	}

	if (loser)
		lock_clear(&turnstile_loser_lock);

	/*
	 * Note: 't' and 'curthread' were synonymous before the loop above,
	 * but now they may be different.  ('t' is now the last thread in
	 * the blocking chain.)
	 */
	if (SOBJ_TYPE(sobj_ops) == SOBJ_USER_PI) {
		ushort_t s = curthread->t_oldspl;
		int timedwait = 0;
		uint_t imm_timeout = 0;
		clock_t tim = -1;

		thread_unlock_high(t);
		if (lwptp->lwpt_id != 0) {
			/*
			 * We enqueued a timeout.  If it has already fired,
			 * lwptp->lwpt_imm_timeout has been set with cas,
			 * so fetch it with cas.
			 */
			timedwait = 1;
			imm_timeout =
			    atomic_cas_uint(&lwptp->lwpt_imm_timeout, 0, 0);
		}
		mutex_exit(mp);
		splx(s);

		if (ISSIG(curthread, JUSTLOOKING) ||
		    MUSTRETURN(p, curthread) || imm_timeout)
			setrun(curthread);
		swtch();
		curthread->t_flag &= ~T_WAKEABLE;
		if (timedwait)
			tim = lwp_timer_dequeue(lwptp);
		setallwatch();
		if (ISSIG(curthread, FORREAL) || lwp->lwp_sysabort ||
		    MUSTRETURN(p, curthread))
			error = EINTR;
		else if (imm_timeout || (timedwait && tim == -1))
			error = ETIME;
		lwp->lwp_sysabort = 0;
		lwp->lwp_asleep = 0;
	} else {
		thread_unlock_nopreempt(t);
		swtch();
	}

	return (error);
}

/*
 * Remove thread from specified turnstile sleep queue; retrieve its
 * free turnstile; if it is the last waiter, delete the turnstile
 * from the turnstile chain and if there is an inheritor, delete it
 * from the inheritor's t_prioinv chain.
 */
static void
turnstile_dequeue(kthread_t *t)
{
	turnstile_t *ts = t->t_ts;
	turnstile_chain_t *tc = &TURNSTILE_CHAIN(ts->ts_sobj);
	turnstile_t *tsfree, **tspp;

	ASSERT(DISP_LOCK_HELD(&tc->tc_lock));
	ASSERT(t->t_lockp == &tc->tc_lock);

	if ((tsfree = ts->ts_free) != NULL) {
		ASSERT(ts->ts_waiters > 1);
		ASSERT(tsfree->ts_waiters == 0);
		t->t_ts = tsfree;
		ts->ts_free = tsfree->ts_free;
		tsfree->ts_free = NULL;
	} else {
		/*
		 * The active turnstile's freelist is empty, so this
		 * must be the last waiter.  Remove the turnstile
		 * from the hash chain and leave the now-inactive
		 * turnstile attached to the thread we're waking.
		 * Note that the ts_inheritor for the turnstile
		 * may be NULL. If one exists, its t_prioinv
		 * chain has to be updated.
		 */
		ASSERT(ts->ts_waiters == 1);
		if (ts->ts_inheritor != NULL) {
			(void) turnstile_pi_tsdelete(ts, ts->ts_inheritor);
			/*
			 * If we ever do a "disinherit" or "unboost", we need
			 * to do it only if "t" is a thread at the head of the
			 * sleep queue. Since the sleep queue is prioritized,
			 * the disinherit is necessary only if the interrupted
			 * thread is the highest priority thread.
			 * Otherwise, there is a higher priority thread blocked
			 * on the turnstile, whose inheritance cannot be
			 * disinherited. However, disinheriting is explicitly
			 * not done here, since it would require holding the
			 * inheritor's thread lock (see turnstile_unsleep()).
			 */
			ts->ts_inheritor = NULL;
		}
		tspp = &tc->tc_first;
		while (*tspp != ts)
			tspp = &(*tspp)->ts_next;
		*tspp = ts->ts_next;
		ASSERT(t->t_ts == ts);
	}
	ts->ts_waiters--;
	sleepq_dequeue(t);
	t->t_sobj_ops = NULL;
	t->t_wchan = NULL;
	t->t_wchan0 = NULL;
	ASSERT(t->t_state == TS_SLEEP);
}

/*
 * Wake threads that are blocked in a turnstile.
 */
void
turnstile_wakeup(turnstile_t *ts, int qnum, int nthreads, kthread_t *owner)
{
	turnstile_chain_t *tc = &TURNSTILE_CHAIN(ts->ts_sobj);
	sleepq_t *sqp = &ts->ts_sleepq[qnum];

	ASSERT(DISP_LOCK_HELD(&tc->tc_lock));

	/*
	 * Waive any priority we may have inherited from this turnstile.
	 */
	if (ts->ts_inheritor != NULL) {
		turnstile_pi_waive(ts);
	}
	while (nthreads-- > 0) {
		kthread_t *t = sqp->sq_first;
		ASSERT(t->t_ts == ts);
		ASSERT(ts->ts_waiters > 1 || ts->ts_inheritor == NULL);
		DTRACE_SCHED1(wakeup, kthread_t *, t);
		turnstile_dequeue(t);
		CL_WAKEUP(t); /* previous thread lock, tc_lock, not dropped */
		/*
		 * If the caller did direct handoff of ownership,
		 * make the new owner inherit from this turnstile.
		 */
		if (t == owner) {
			kthread_t *wp = ts->ts_sleepq[TS_WRITER_Q].sq_first;
			kthread_t *rp = ts->ts_sleepq[TS_READER_Q].sq_first;
			pri_t wpri = wp ? DISP_PRIO(wp) : 0;
			pri_t rpri = rp ? DISP_PRIO(rp) : 0;
			turnstile_pi_inherit(ts, t, MAX(wpri, rpri));
			owner = NULL;
		}
		thread_unlock_high(t);		/* drop run queue lock */
	}
	if (owner != NULL)
		panic("turnstile_wakeup: owner %p not woken", (void *)owner);
	disp_lock_exit(&tc->tc_lock);
}

/*
 * Change priority of a thread sleeping in a turnstile.
 */
void
turnstile_change_pri(kthread_t *t, pri_t pri, pri_t *t_prip)
{
	sleepq_t *sqp = t->t_sleepq;

	sleepq_dequeue(t);
	*t_prip = pri;
	sleepq_insert(sqp, t);
}

/*
 * We don't allow spurious wakeups of threads blocked in turnstiles
 * for synch objects whose sobj_ops vector is initialized with the
 * following routine (e.g. kernel synchronization objects).
 * This is vital to the correctness of direct-handoff logic in some
 * synchronization primitives, and it also simplifies the PI logic.
 */
/* ARGSUSED */
void
turnstile_stay_asleep(kthread_t *t)
{
}

/*
 * Wake up a thread blocked in a turnstile. Used to enable interruptibility
 * of threads blocked on a SOBJ_USER_PI sobj.
 *
 * The implications of this interface are:
 *
 * 1. turnstile_block() may return with an EINTR.
 * 2. When the owner of an sobj releases it, but no turnstile is found (i.e.
 *    no waiters), the (prior) owner must call turnstile_pi_recalc() to
 *    waive any priority inherited from interrupted waiters.
 *
 * When a waiter is interrupted, disinheriting its willed priority from the
 * inheritor would require holding the inheritor's thread lock, while also
 * holding the waiter's thread lock which is a turnstile lock. If the
 * inheritor's thread lock is not free, and is also a turnstile lock that
 * is out of lock order, the waiter's thread lock would have to be dropped.
 * This leads to complications for the caller of turnstile_unsleep(), since
 * the caller holds the waiter's thread lock. So, instead of disinheriting
 * on waiter interruption, the owner is required to follow rule 2 above.
 *
 * Avoiding disinherit on waiter interruption seems acceptable because
 * the owner runs at an unnecessarily high priority only while sobj is held,
 * which it would have done in any case, if the waiter had not been interrupted.
 */
void
turnstile_unsleep(kthread_t *t)
{
	turnstile_dequeue(t);
	THREAD_TRANSITION(t);
	CL_SETRUN(t);
}
