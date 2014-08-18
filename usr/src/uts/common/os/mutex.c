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
 * Big Theory Statement for mutual exclusion locking primitives.
 *
 * A mutex serializes multiple threads so that only one thread
 * (the "owner" of the mutex) is active at a time.  See mutex(9F)
 * for a full description of the interfaces and programming model.
 * The rest of this comment describes the implementation.
 *
 * Mutexes come in two flavors: adaptive and spin.  mutex_init(9F)
 * determines the type based solely on the iblock cookie (PIL) argument.
 * PIL > LOCK_LEVEL implies a spin lock; everything else is adaptive.
 *
 * Spin mutexes block interrupts and spin until the lock becomes available.
 * A thread may not sleep, or call any function that might sleep, while
 * holding a spin mutex.  With few exceptions, spin mutexes should only
 * be used to synchronize with interrupt handlers.
 *
 * Adaptive mutexes (the default type) spin if the owner is running on
 * another CPU and block otherwise.  This policy is based on the assumption
 * that mutex hold times are typically short enough that the time spent
 * spinning is less than the time it takes to block.  If you need mutual
 * exclusion semantics with long hold times, consider an rwlock(9F) as
 * RW_WRITER.  Better still, reconsider the algorithm: if it requires
 * mutual exclusion for long periods of time, it's probably not scalable.
 *
 * Adaptive mutexes are overwhelmingly more common than spin mutexes,
 * so mutex_enter() assumes that the lock is adaptive.  We get away
 * with this by structuring mutexes so that an attempt to acquire a
 * spin mutex as adaptive always fails.  When mutex_enter() fails
 * it punts to mutex_vector_enter(), which does all the hard stuff.
 *
 * mutex_vector_enter() first checks the type.  If it's spin mutex,
 * we just call lock_set_spl() and return.  If it's an adaptive mutex,
 * we check to see what the owner is doing.  If the owner is running,
 * we spin until the lock becomes available; if not, we mark the lock
 * as having waiters and block.
 *
 * Blocking on a mutex is surprisingly delicate dance because, for speed,
 * mutex_exit() doesn't use an atomic instruction.  Thus we have to work
 * a little harder in the (rarely-executed) blocking path to make sure
 * we don't block on a mutex that's just been released -- otherwise we
 * might never be woken up.
 *
 * The logic for synchronizing mutex_vector_enter() with mutex_exit()
 * in the face of preemption and relaxed memory ordering is as follows:
 *
 * (1) Preemption in the middle of mutex_exit() must cause mutex_exit()
 *     to restart.  Each platform must enforce this by checking the
 *     interrupted PC in the interrupt handler (or on return from trap --
 *     whichever is more convenient for the platform).  If the PC
 *     lies within the critical region of mutex_exit(), the interrupt
 *     handler must reset the PC back to the beginning of mutex_exit().
 *     The critical region consists of all instructions up to, but not
 *     including, the store that clears the lock (which, of course,
 *     must never be executed twice.)
 *
 *     This ensures that the owner will always check for waiters after
 *     resuming from a previous preemption.
 *
 * (2) A thread resuming in mutex_exit() does (at least) the following:
 *
 *	when resuming:	set CPU_THREAD = owner
 *			membar #StoreLoad
 *
 *	in mutex_exit:	check waiters bit; do wakeup if set
 *			membar #LoadStore|#StoreStore
 *			clear owner
 *			(at this point, other threads may or may not grab
 *			the lock, and we may or may not reacquire it)
 *
 *	when blocking:	membar #StoreStore (due to disp_lock_enter())
 *			set CPU_THREAD = (possibly) someone else
 *
 * (3) A thread blocking in mutex_vector_enter() does the following:
 *
 *			set waiters bit
 *			membar #StoreLoad (via membar_enter())
 *			check CPU_THREAD for owner's t_cpu
 *				continue if owner running
 *			membar #LoadLoad (via membar_consumer())
 *			check owner and waiters bit; abort if either changed
 *			block
 *
 * Thus the global memory orderings for (2) and (3) are as follows:
 *
 * (2M) mutex_exit() memory order:
 *
 *			STORE	CPU_THREAD = owner
 *			LOAD	waiters bit
 *			STORE	owner = NULL
 *			STORE	CPU_THREAD = (possibly) someone else
 *
 * (3M) mutex_vector_enter() memory order:
 *
 *			STORE	waiters bit = 1
 *			LOAD	CPU_THREAD for each CPU
 *			LOAD	owner and waiters bit
 *
 * It has been verified by exhaustive simulation that all possible global
 * memory orderings of (2M) interleaved with (3M) result in correct
 * behavior.  Moreover, these ordering constraints are minimal: changing
 * the ordering of anything in (2M) or (3M) breaks the algorithm, creating
 * windows for missed wakeups.  Note: the possibility that other threads
 * may grab the lock after the owner drops it can be factored out of the
 * memory ordering analysis because mutex_vector_enter() won't block
 * if the lock isn't still owned by the same thread.
 *
 * The only requirements of code outside the mutex implementation are
 * (1) mutex_exit() preemption fixup in interrupt handlers or trap return,
 * (2) a membar #StoreLoad after setting CPU_THREAD in resume(),
 * (3) mutex_owner_running() preemption fixup in interrupt handlers
 * or trap returns.
 * Note: idle threads cannot grab adaptive locks (since they cannot block),
 * so the membar may be safely omitted when resuming an idle thread.
 *
 * When a mutex has waiters, mutex_vector_exit() has several options:
 *
 * (1) Choose a waiter and make that thread the owner before waking it;
 *     this is known as "direct handoff" of ownership.
 *
 * (2) Drop the lock and wake one waiter.
 *
 * (3) Drop the lock, clear the waiters bit, and wake all waiters.
 *
 * In many ways (1) is the cleanest solution, but if a lock is moderately
 * contended it defeats the adaptive spin logic.  If we make some other
 * thread the owner, but he's not ONPROC yet, then all other threads on
 * other cpus that try to get the lock will conclude that the owner is
 * blocked, so they'll block too.  And so on -- it escalates quickly,
 * with every thread taking the blocking path rather than the spin path.
 * Thus, direct handoff is *not* a good idea for adaptive mutexes.
 *
 * Option (2) is the next most natural-seeming option, but it has several
 * annoying properties.  If there's more than one waiter, we must preserve
 * the waiters bit on an unheld lock.  On cas-capable platforms, where
 * the waiters bit is part of the lock word, this means that both 0x0
 * and 0x1 represent unheld locks, so we have to cas against *both*.
 * Priority inheritance also gets more complicated, because a lock can
 * have waiters but no owner to whom priority can be willed.  So while
 * it is possible to make option (2) work, it's surprisingly vile.
 *
 * Option (3), the least-intuitive at first glance, is what we actually do.
 * It has the advantage that because you always wake all waiters, you
 * never have to preserve the waiters bit.  Waking all waiters seems like
 * begging for a thundering herd problem, but consider: under option (2),
 * every thread that grabs and drops the lock will wake one waiter -- so
 * if the lock is fairly active, all waiters will be awakened very quickly
 * anyway.  Moreover, this is how adaptive locks are *supposed* to work.
 * The blocking case is rare; the more common case (by 3-4 orders of
 * magnitude) is that one or more threads spin waiting to get the lock.
 * Only direct handoff can prevent the thundering herd problem, but as
 * mentioned earlier, that would tend to defeat the adaptive spin logic.
 * In practice, option (3) works well because the blocking case is rare.
 */

/*
 * delayed lock retry with exponential delay for spin locks
 *
 * It is noted above that for both the spin locks and the adaptive locks,
 * spinning is the dominate mode of operation.  So long as there is only
 * one thread waiting on a lock, the naive spin loop works very well in
 * cache based architectures.  The lock data structure is pulled into the
 * cache of the processor with the waiting/spinning thread and no further
 * memory traffic is generated until the lock is released.  Unfortunately,
 * once two or more threads are waiting on a lock, the naive spin has
 * the property of generating maximum memory traffic from each spinning
 * thread as the spinning threads contend for the lock data structure.
 *
 * By executing a delay loop before retrying a lock, a waiting thread
 * can reduce its memory traffic by a large factor, depending on the
 * size of the delay loop.  A large delay loop greatly reduced the memory
 * traffic, but has the drawback of having a period of time when
 * no thread is attempting to gain the lock even though several threads
 * might be waiting.  A small delay loop has the drawback of not
 * much reduction in memory traffic, but reduces the potential idle time.
 * The theory of the exponential delay code is to start with a short
 * delay loop and double the waiting time on each iteration, up to
 * a preselected maximum.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/sobject.h>
#include <sys/turnstile.h>
#include <sys/systm.h>
#include <sys/mutex_impl.h>
#include <sys/spl.h>
#include <sys/lockstat.h>
#include <sys/atomic.h>
#include <sys/cpu.h>
#include <sys/stack.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>

/*
 * The sobj_ops vector exports a set of functions needed when a thread
 * is asleep on a synchronization object of this type.
 */
static sobj_ops_t mutex_sobj_ops = {
	SOBJ_MUTEX, mutex_owner, turnstile_stay_asleep, turnstile_change_pri
};

/*
 * If the system panics on a mutex, save the address of the offending
 * mutex in panic_mutex_addr, and save the contents in panic_mutex.
 */
static mutex_impl_t panic_mutex;
static mutex_impl_t *panic_mutex_addr;

static void
mutex_panic(char *msg, mutex_impl_t *lp)
{
	if (panicstr)
		return;

	if (atomic_cas_ptr(&panic_mutex_addr, NULL, lp) == NULL)
		panic_mutex = *lp;

	panic("%s, lp=%p owner=%p thread=%p",
	    msg, (void *)lp, (void *)MUTEX_OWNER(&panic_mutex),
	    (void *)curthread);
}

/* "tunables" for per-platform backoff constants. */
uint_t mutex_backoff_cap = 0;
ushort_t mutex_backoff_base = MUTEX_BACKOFF_BASE;
ushort_t mutex_cap_factor = MUTEX_CAP_FACTOR;
uchar_t mutex_backoff_shift = MUTEX_BACKOFF_SHIFT;

void
mutex_sync(void)
{
	MUTEX_SYNC();
}

/* calculate the backoff interval */
uint_t
default_lock_backoff(uint_t backoff)
{
	uint_t cap;		/* backoff cap calculated */

	if (backoff == 0) {
		backoff = mutex_backoff_base;
		/* first call just sets the base */
		return (backoff);
	}

	/* set cap */
	if (mutex_backoff_cap == 0) {
		/*
		 * For a contended lock, in the worst case a load + cas may
		 * be queued  at the controller for each contending CPU.
		 * Therefore, to avoid queueing, the accesses for all CPUS must
		 * be spread out in time over an interval of (ncpu *
		 * cap-factor).  Maximum backoff is set to this value, and
		 * actual backoff is a random number from 0 to the current max.
		 */
		cap = ncpus_online * mutex_cap_factor;
	} else {
		cap = mutex_backoff_cap;
	}

	/* calculate new backoff value */
	backoff <<= mutex_backoff_shift;	/* increase backoff */
	if (backoff > cap) {
		if (cap < mutex_backoff_base)
			backoff = mutex_backoff_base;
		else
			backoff = cap;
	}

	return (backoff);
}

/*
 * default delay function for mutexes.
 */
void
default_lock_delay(uint_t backoff)
{
	ulong_t rnd;		/* random factor */
	uint_t cur_backoff;	/* calculated backoff */
	uint_t backctr;

	/*
	 * Modify backoff by a random amount to avoid lockstep, and to
	 * make it probable that some thread gets a small backoff, and
	 * re-checks quickly
	 */
	rnd = (((long)curthread >> PTR24_LSB) ^ (long)MUTEX_GETTICK());
	cur_backoff = (uint_t)(rnd % (backoff - mutex_backoff_base + 1)) +
	    mutex_backoff_base;

	/*
	 * Delay before trying
	 * to touch the mutex data structure.
	 */
	for (backctr = cur_backoff; backctr; backctr--) {
		MUTEX_DELAY();
	};
}

uint_t (*mutex_lock_backoff)(uint_t) = default_lock_backoff;
void (*mutex_lock_delay)(uint_t) = default_lock_delay;
void (*mutex_delay)(void) = mutex_delay_default;

/*
 * mutex_vector_enter() is called from the assembly mutex_enter() routine
 * if the lock is held or is not of type MUTEX_ADAPTIVE.
 */
void
mutex_vector_enter(mutex_impl_t *lp)
{
	kthread_id_t	owner;
	kthread_id_t	lastowner = MUTEX_NO_OWNER; /* track owner changes */
	hrtime_t	sleep_time = 0;	/* how long we slept */
	hrtime_t	spin_time = 0;	/* how long we spun */
	cpu_t 		*cpup;
	turnstile_t	*ts;
	volatile mutex_impl_t *vlp = (volatile mutex_impl_t *)lp;
	uint_t		backoff = 0;	/* current backoff */
	int		changecnt = 0;	/* count of owner changes */

	ASSERT_STACK_ALIGNED();

	if (MUTEX_TYPE_SPIN(lp)) {
		lock_set_spl(&lp->m_spin.m_spinlock, lp->m_spin.m_minspl,
		    &lp->m_spin.m_oldspl);
		return;
	}

	if (!MUTEX_TYPE_ADAPTIVE(lp)) {
		mutex_panic("mutex_enter: bad mutex", lp);
		return;
	}

	/*
	 * Adaptive mutexes must not be acquired from above LOCK_LEVEL.
	 * We can migrate after loading CPU but before checking CPU_ON_INTR,
	 * so we must verify by disabling preemption and loading CPU again.
	 */
	cpup = CPU;
	if (CPU_ON_INTR(cpup) && !panicstr) {
		kpreempt_disable();
		if (CPU_ON_INTR(CPU))
			mutex_panic("mutex_enter: adaptive at high PIL", lp);
		kpreempt_enable();
	}

	CPU_STATS_ADDQ(cpup, sys, mutex_adenters, 1);

	spin_time = LOCKSTAT_START_TIME(LS_MUTEX_ENTER_SPIN);

	backoff = mutex_lock_backoff(0);	/* set base backoff */
	for (;;) {
		mutex_lock_delay(backoff); /* backoff delay */

		if (panicstr)
			return;

		if ((owner = MUTEX_OWNER(vlp)) == NULL) {
			if (mutex_adaptive_tryenter(lp)) {
				break;
			}
			/* increase backoff only on failed attempt. */
			backoff = mutex_lock_backoff(backoff);
			changecnt++;
			continue;
		} else if (lastowner != owner) {
			lastowner = owner;
			backoff = mutex_lock_backoff(backoff);
			changecnt++;
		}

		if (changecnt >= ncpus_online) {
			backoff = mutex_lock_backoff(0);
			changecnt = 0;
		}

		if (owner == curthread)
			mutex_panic("recursive mutex_enter", lp);

		/*
		 * If lock is held but owner is not yet set, spin.
		 * (Only relevant for platforms that don't have cas.)
		 */
		if (owner == MUTEX_NO_OWNER)
			continue;

		if (mutex_owner_running(lp) != NULL)  {
			continue;
		}

		/*
		 * The owner appears not to be running, so block.
		 * See the Big Theory Statement for memory ordering issues.
		 */
		ts = turnstile_lookup(lp);
		MUTEX_SET_WAITERS(lp);
		membar_enter();

		/*
		 * Recheck whether owner is running after waiters bit hits
		 * global visibility (above).  If owner is running, spin.
		 */
		if (mutex_owner_running(lp) != NULL) {
			turnstile_exit(lp);
			continue;
		}
		membar_consumer();

		/*
		 * If owner and waiters bit are unchanged, block.
		 */
		if (MUTEX_OWNER(vlp) == owner && MUTEX_HAS_WAITERS(vlp)) {
			sleep_time -= gethrtime();
			(void) turnstile_block(ts, TS_WRITER_Q, lp,
			    &mutex_sobj_ops, NULL, NULL);
			sleep_time += gethrtime();
			/* reset backoff after turnstile */
			backoff = mutex_lock_backoff(0);
		} else {
			turnstile_exit(lp);
		}
	}

	ASSERT(MUTEX_OWNER(lp) == curthread);

	if (sleep_time != 0) {
		/*
		 * Note, sleep time is the sum of all the sleeping we
		 * did.
		 */
		LOCKSTAT_RECORD(LS_MUTEX_ENTER_BLOCK, lp, sleep_time);
	}

	/* record spin time, don't count sleep time */
	if (spin_time != 0) {
		LOCKSTAT_RECORD_TIME(LS_MUTEX_ENTER_SPIN, lp,
		    spin_time + sleep_time);
	}

	LOCKSTAT_RECORD0(LS_MUTEX_ENTER_ACQUIRE, lp);
}

/*
 * mutex_vector_tryenter() is called from the assembly mutex_tryenter()
 * routine if the lock is held or is not of type MUTEX_ADAPTIVE.
 */
int
mutex_vector_tryenter(mutex_impl_t *lp)
{
	int s;

	if (MUTEX_TYPE_ADAPTIVE(lp))
		return (0);		/* we already tried in assembly */

	if (!MUTEX_TYPE_SPIN(lp)) {
		mutex_panic("mutex_tryenter: bad mutex", lp);
		return (0);
	}

	s = splr(lp->m_spin.m_minspl);
	if (lock_try(&lp->m_spin.m_spinlock)) {
		lp->m_spin.m_oldspl = (ushort_t)s;
		return (1);
	}
	splx(s);
	return (0);
}

/*
 * mutex_vector_exit() is called from mutex_exit() if the lock is not
 * adaptive, has waiters, or is not owned by the current thread (panic).
 */
void
mutex_vector_exit(mutex_impl_t *lp)
{
	turnstile_t *ts;

	if (MUTEX_TYPE_SPIN(lp)) {
		lock_clear_splx(&lp->m_spin.m_spinlock, lp->m_spin.m_oldspl);
		return;
	}

	if (MUTEX_OWNER(lp) != curthread) {
		mutex_panic("mutex_exit: not owner", lp);
		return;
	}

	ts = turnstile_lookup(lp);
	MUTEX_CLEAR_LOCK_AND_WAITERS(lp);
	if (ts == NULL)
		turnstile_exit(lp);
	else
		turnstile_wakeup(ts, TS_WRITER_Q, ts->ts_waiters, NULL);
	LOCKSTAT_RECORD0(LS_MUTEX_EXIT_RELEASE, lp);
}

int
mutex_owned(const kmutex_t *mp)
{
	const mutex_impl_t *lp = (const mutex_impl_t *)mp;

	if (panicstr || quiesce_active)
		return (1);

	if (MUTEX_TYPE_ADAPTIVE(lp))
		return (MUTEX_OWNER(lp) == curthread);
	return (LOCK_HELD(&lp->m_spin.m_spinlock));
}

kthread_t *
mutex_owner(const kmutex_t *mp)
{
	const mutex_impl_t *lp = (const mutex_impl_t *)mp;
	kthread_id_t t;

	if (MUTEX_TYPE_ADAPTIVE(lp) && (t = MUTEX_OWNER(lp)) != MUTEX_NO_OWNER)
		return (t);
	return (NULL);
}

/*
 * The iblock cookie 'ibc' is the spl level associated with the lock;
 * this alone determines whether the lock will be ADAPTIVE or SPIN.
 *
 * Adaptive mutexes created in zeroed memory do not need to call
 * mutex_init() as their allocation in this fashion guarantees
 * their initialization.
 *   eg adaptive mutexes created as static within the BSS or allocated
 *      by kmem_zalloc().
 */
/* ARGSUSED */
void
mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc)
{
	mutex_impl_t *lp = (mutex_impl_t *)mp;

	ASSERT(ibc < (void *)KERNELBASE);	/* see 1215173 */

	if ((intptr_t)ibc > ipltospl(LOCK_LEVEL) && ibc < (void *)KERNELBASE) {
		ASSERT(type != MUTEX_ADAPTIVE && type != MUTEX_DEFAULT);
		MUTEX_SET_TYPE(lp, MUTEX_SPIN);
		LOCK_INIT_CLEAR(&lp->m_spin.m_spinlock);
		LOCK_INIT_HELD(&lp->m_spin.m_dummylock);
		lp->m_spin.m_minspl = (int)(intptr_t)ibc;
	} else {
#ifdef MUTEX_ALIGN
		static int misalign_cnt = 0;

		if (((uintptr_t)lp & (uintptr_t)(MUTEX_ALIGN - 1)) &&
		    (misalign_cnt < MUTEX_ALIGN_WARNINGS)) {
			/*
			 * The mutex is not aligned and may cross a cache line.
			 * This is not supported and may cause a panic.
			 * Show a warning that the mutex is not aligned
			 * and attempt to identify the origin.
			 * Unaligned mutexes are not (supposed to be)
			 * possible on SPARC.
			 */
			char *funcname;
			ulong_t offset = 0;

			funcname = modgetsymname((uintptr_t)caller(), &offset);
			cmn_err(CE_WARN, "mutex_init: %p is not %d byte "
			    "aligned; caller %s+%lx in module %s. "
			    "This is unsupported and may cause a panic. "
			    "Please report this to the kernel module supplier.",
			    (void *)lp, MUTEX_ALIGN,
			    funcname ? funcname : "unknown", offset,
			    mod_containing_pc(caller()));
			misalign_cnt++;
			if (misalign_cnt >= MUTEX_ALIGN_WARNINGS) {
				cmn_err(CE_WARN, "mutex_init: further unaligned"
				    " mutex warnings will be suppressed.");
			}
		}
#endif	/* MUTEX_ALIGN */
		ASSERT(type != MUTEX_SPIN);

		MUTEX_SET_TYPE(lp, MUTEX_ADAPTIVE);
		MUTEX_CLEAR_LOCK_AND_WAITERS(lp);
	}
}

void
mutex_destroy(kmutex_t *mp)
{
	mutex_impl_t *lp = (mutex_impl_t *)mp;

	if (lp->m_owner == 0 && !MUTEX_HAS_WAITERS(lp)) {
		MUTEX_DESTROY(lp);
	} else if (MUTEX_TYPE_SPIN(lp)) {
		LOCKSTAT_RECORD0(LS_MUTEX_DESTROY_RELEASE, lp);
		MUTEX_DESTROY(lp);
	} else if (MUTEX_TYPE_ADAPTIVE(lp)) {
		LOCKSTAT_RECORD0(LS_MUTEX_DESTROY_RELEASE, lp);
		if (MUTEX_OWNER(lp) != curthread)
			mutex_panic("mutex_destroy: not owner", lp);
		if (MUTEX_HAS_WAITERS(lp)) {
			turnstile_t *ts = turnstile_lookup(lp);
			turnstile_exit(lp);
			if (ts != NULL)
				mutex_panic("mutex_destroy: has waiters", lp);
		}
		MUTEX_DESTROY(lp);
	} else {
		mutex_panic("mutex_destroy: bad mutex", lp);
	}
}

/*
 * Simple C support for the cases where spin locks miss on the first try.
 */
void
lock_set_spin(lock_t *lp)
{
	int loop_count = 0;
	uint_t backoff = 0;	/* current backoff */
	hrtime_t spin_time = 0;	/* how long we spun */

	if (panicstr)
		return;

	if (ncpus == 1)
		panic("lock_set: %p lock held and only one CPU", (void *)lp);

	spin_time = LOCKSTAT_START_TIME(LS_LOCK_SET_SPIN);

	while (LOCK_HELD(lp) || !lock_spin_try(lp)) {
		if (panicstr)
			return;
		loop_count++;

		if (ncpus_online == loop_count) {
			backoff = mutex_lock_backoff(0);
			loop_count = 0;
		} else {
			backoff = mutex_lock_backoff(backoff);
		}
		mutex_lock_delay(backoff);
	}

	LOCKSTAT_RECORD_TIME(LS_LOCK_SET_SPIN, lp, spin_time);

	LOCKSTAT_RECORD0(LS_LOCK_SET_ACQUIRE, lp);
}

void
lock_set_spl_spin(lock_t *lp, int new_pil, ushort_t *old_pil_addr, int old_pil)
{
	int loop_count = 0;
	uint_t backoff = 0;	/* current backoff */
	hrtime_t spin_time = 0;	/* how long we spun */

	if (panicstr)
		return;

	if (ncpus == 1)
		panic("lock_set_spl: %p lock held and only one CPU",
		    (void *)lp);

	ASSERT(new_pil > LOCK_LEVEL);

	spin_time = LOCKSTAT_START_TIME(LS_LOCK_SET_SPL_SPIN);

	do {
		splx(old_pil);
		while (LOCK_HELD(lp)) {
			loop_count++;

			if (panicstr) {
				*old_pil_addr = (ushort_t)splr(new_pil);
				return;
			}
			if (ncpus_online == loop_count) {
				backoff = mutex_lock_backoff(0);
				loop_count = 0;
			} else {
				backoff = mutex_lock_backoff(backoff);
			}
			mutex_lock_delay(backoff);
		}
		old_pil = splr(new_pil);
	} while (!lock_spin_try(lp));

	*old_pil_addr = (ushort_t)old_pil;

	LOCKSTAT_RECORD_TIME(LS_LOCK_SET_SPL_SPIN, lp, spin_time);

	LOCKSTAT_RECORD0(LS_LOCK_SET_SPL_ACQUIRE, lp);
}
