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

#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/task.h>
#include <sys/cmn_err.h>
#include <sys/class.h>
#include <sys/sdt.h>
#include <sys/atomic.h>
#include <sys/cpu.h>
#include <sys/clock_tick.h>
#include <sys/clock_impl.h>
#include <sys/sysmacros.h>
#include <vm/rm.h>

/*
 * This file contains the implementation of clock tick accounting for threads.
 * Every tick, user threads running on various CPUs are located and charged
 * with a tick to account for their use of CPU time.
 *
 * Every tick, the clock() handler calls clock_tick_schedule() to perform tick
 * accounting for all the threads in the system. Tick accounting is done in
 * two phases:
 *
 * Tick scheduling	Done in clock_tick_schedule(). In this phase, cross
 *			calls are scheduled to multiple CPUs to perform
 *			multi-threaded tick accounting. The CPUs are chosen
 *			on a rotational basis so as to distribute the tick
 *			accounting load evenly across all CPUs.
 *
 * Tick execution	Done in clock_tick_execute(). In this phase, tick
 *			accounting is actually performed by softint handlers
 *			on multiple CPUs.
 *
 * This implementation gives us a multi-threaded tick processing facility that
 * is suitable for configurations with a large number of CPUs. On smaller
 * configurations it may be desirable to let the processing be single-threaded
 * and just allow clock() to do it as it has been done traditionally. To
 * facilitate this, a variable, clock_tick_threshold, is defined. Platforms
 * that desire multi-threading should set this variable to something
 * appropriate. A recommended value may be found in clock_tick.h. At boot time,
 * if the number of CPUs is greater than clock_tick_threshold, multi-threading
 * kicks in. Note that this is a decision made at boot time. If more CPUs
 * are dynamically added later on to exceed the threshold, no attempt is made
 * to switch to multi-threaded. Similarly, if CPUs are removed dynamically
 * no attempt is made to switch to single-threaded. This is to keep the
 * implementation simple. Also note that the threshold can be changed for a
 * specific customer configuration via /etc/system.
 *
 * The boot time decision is reflected in clock_tick_single_threaded.
 */

/*
 * clock_tick_threshold
 *	If the number of CPUs at boot time exceeds this threshold,
 *	multi-threaded tick accounting kicks in.
 *
 * clock_tick_ncpus
 *	The number of CPUs in a set. Each set is scheduled for tick execution
 *	on a separate processor.
 *
 * clock_tick_single_threaded
 *	Indicates whether or not tick accounting is single threaded.
 *
 * clock_tick_total_cpus
 *	Total number of online CPUs.
 *
 * clock_tick_cpus
 *	Array of online CPU pointers.
 *
 * clock_tick_cpu
 *	Per-CPU, cache-aligned data structures to facilitate multi-threading.
 *
 * clock_tick_active
 *	Counter that indicates the number of active tick processing softints
 *	in the system.
 *
 * clock_tick_pending
 *	Number of pending ticks that need to be accounted by the softint
 *	handlers.
 *
 * clock_tick_lock
 *	Mutex to synchronize between clock_tick_schedule() and
 *	CPU online/offline.
 *
 * clock_cpu_id
 *	CPU id of the clock() CPU. Used to detect when the clock CPU
 *	is offlined.
 *
 * clock_tick_online_cpuset
 *	CPU set of all online processors that can be X-called.
 *
 * clock_tick_proc_max
 *	Each process is allowed to accumulate a few ticks before checking
 *	for the task CPU time resource limit. We lower the number of calls
 *	to rctl_test() to make tick accounting more scalable. The tradeoff
 *	is that the limit may not get enforced in a timely manner. This is
 *	typically not a problem.
 *
 * clock_tick_set
 *	Per-set structures. Each structure contains the range of CPUs
 *	to be processed for the set.
 *
 * clock_tick_nsets;
 *	Number of sets.
 *
 * clock_tick_scan
 *	Where to begin the scan for single-threaded mode. In multi-threaded,
 *	the clock_tick_set itself contains a field for this.
 */
int			clock_tick_threshold;
int			clock_tick_ncpus;
int			clock_tick_single_threaded;
int			clock_tick_total_cpus;
cpu_t			*clock_tick_cpus[NCPU];
clock_tick_cpu_t	*clock_tick_cpu[NCPU];
ulong_t			clock_tick_active;
int			clock_tick_pending;
kmutex_t		clock_tick_lock;
processorid_t		clock_cpu_id;
cpuset_t		clock_tick_online_cpuset;
clock_t			clock_tick_proc_max;
clock_tick_set_t	*clock_tick_set;
int			clock_tick_nsets;
int			clock_tick_scan;
ulong_t			clock_tick_intr;

static uint_t	clock_tick_execute(caddr_t, caddr_t);
static void	clock_tick_execute_common(int, int, int, clock_t, int);

#define	CLOCK_TICK_ALIGN	64	/* cache alignment */

/*
 * Clock tick initialization is done in two phases:
 *
 * 1. Before clock_init() is called, clock_tick_init_pre() is called to set
 *    up single-threading so the clock() can begin to do its job.
 *
 * 2. After the slave CPUs are initialized at boot time, we know the number
 *    of CPUs. clock_tick_init_post() is called to set up multi-threading if
 *    required.
 */
void
clock_tick_init_pre(void)
{
	clock_tick_cpu_t	*ctp;
	int			i, n;
	clock_tick_set_t	*csp;
	uintptr_t		buf;
	size_t			size;

	clock_tick_single_threaded = 1;

	size = P2ROUNDUP(sizeof (clock_tick_cpu_t), CLOCK_TICK_ALIGN);
	buf = (uintptr_t)kmem_zalloc(size * NCPU + CLOCK_TICK_ALIGN, KM_SLEEP);
	buf = P2ROUNDUP(buf, CLOCK_TICK_ALIGN);

	/*
	 * Perform initialization in case multi-threading is chosen later.
	 */
	if (&create_softint != NULL) {
		clock_tick_intr = create_softint(LOCK_LEVEL,
		    clock_tick_execute, (caddr_t)NULL);
	}
	for (i = 0; i < NCPU; i++, buf += size) {
		ctp = (clock_tick_cpu_t *)buf;
		clock_tick_cpu[i] = ctp;
		mutex_init(&ctp->ct_lock, NULL, MUTEX_DEFAULT, NULL);
		if (&create_softint != NULL) {
			ctp->ct_intr = clock_tick_intr;
		}
		ctp->ct_pending = 0;
	}

	mutex_init(&clock_tick_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Compute clock_tick_ncpus here. We need it to compute the
	 * maximum number of tick sets we need to support.
	 */
	ASSERT(clock_tick_ncpus >= 0);
	if (clock_tick_ncpus == 0)
		clock_tick_ncpus = CLOCK_TICK_NCPUS;
	if (clock_tick_ncpus > max_ncpus)
		clock_tick_ncpus = max_ncpus;

	/*
	 * Allocate and initialize the tick sets.
	 */
	n = (max_ncpus + clock_tick_ncpus - 1)/clock_tick_ncpus;
	clock_tick_set = kmem_zalloc(sizeof (clock_tick_set_t) * n, KM_SLEEP);
	for (i = 0; i < n; i++) {
		csp = &clock_tick_set[i];
		csp->ct_start = i * clock_tick_ncpus;
		csp->ct_scan = csp->ct_start;
		csp->ct_end = csp->ct_start;
	}
}

void
clock_tick_init_post(void)
{
	/*
	 * If a platform does not provide create_softint() and invoke_softint(),
	 * then we assume single threaded.
	 */
	if (&invoke_softint == NULL)
		clock_tick_threshold = 0;

	ASSERT(clock_tick_threshold >= 0);

	if (clock_tick_threshold == 0)
		clock_tick_threshold = max_ncpus;

	/*
	 * If a platform does not specify a threshold or if the number of CPUs
	 * at boot time does not exceed the threshold, tick accounting remains
	 * single-threaded.
	 */
	if (ncpus <= clock_tick_threshold) {
		clock_tick_ncpus = max_ncpus;
		clock_tick_proc_max = 1;
		return;
	}

	/*
	 * OK. Multi-thread tick processing. If a platform has not specified
	 * the CPU set size for multi-threading, then use the default value.
	 * This value has been arrived through measurements on large
	 * configuration systems.
	 */
	clock_tick_single_threaded = 0;
	if (clock_tick_proc_max == 0) {
		clock_tick_proc_max = CLOCK_TICK_PROC_MAX;
		if (hires_tick)
			clock_tick_proc_max *= 10;
	}
}

static void
clock_tick_schedule_one(clock_tick_set_t *csp, int pending, processorid_t cid)
{
	clock_tick_cpu_t	*ctp;

	ASSERT(&invoke_softint != NULL);

	atomic_inc_ulong(&clock_tick_active);

	/*
	 * Schedule tick accounting for a set of CPUs.
	 */
	ctp = clock_tick_cpu[cid];
	mutex_enter(&ctp->ct_lock);
	ctp->ct_lbolt = LBOLT_NO_ACCOUNT;
	ctp->ct_pending += pending;
	ctp->ct_start = csp->ct_start;
	ctp->ct_end = csp->ct_end;
	ctp->ct_scan = csp->ct_scan;
	mutex_exit(&ctp->ct_lock);

	invoke_softint(cid, ctp->ct_intr);
	/*
	 * Return without waiting for the softint to finish.
	 */
}

static void
clock_tick_process(cpu_t *cp, clock_t mylbolt, int pending)
{
	kthread_t	*t;
	kmutex_t	*plockp;
	int		notick, intr;
	klwp_id_t	lwp;

	/*
	 * The locking here is rather tricky. thread_free_prevent()
	 * prevents the thread returned from being freed while we
	 * are looking at it. We can then check if the thread
	 * is exiting and get the appropriate p_lock if it
	 * is not.  We have to be careful, though, because
	 * the _process_ can still be freed while we've
	 * prevented thread free.  To avoid touching the
	 * proc structure we put a pointer to the p_lock in the
	 * thread structure.  The p_lock is persistent so we
	 * can acquire it even if the process is gone.  At that
	 * point we can check (again) if the thread is exiting
	 * and either drop the lock or do the tick processing.
	 */
	t = cp->cpu_thread;	/* Current running thread */
	if (CPU == cp) {
		/*
		 * 't' will be the tick processing thread on this
		 * CPU.  Use the pinned thread (if any) on this CPU
		 * as the target of the clock tick.
		 */
		if (t->t_intr != NULL)
			t = t->t_intr;
	}

	/*
	 * We use thread_free_prevent to keep the currently running
	 * thread from being freed or recycled while we're
	 * looking at it.
	 */
	thread_free_prevent(t);
	/*
	 * We cannot hold the cpu_lock to prevent the
	 * cpu_active from changing in the clock interrupt.
	 * As long as we don't block (or don't get pre-empted)
	 * the cpu_list will not change (all threads are paused
	 * before list modification).
	 */
	if (CLOCK_TICK_CPU_OFFLINE(cp)) {
		thread_free_allow(t);
		return;
	}

	/*
	 * Make sure the thread is still on the CPU.
	 */
	if ((t != cp->cpu_thread) &&
	    ((cp != CPU) || (t != cp->cpu_thread->t_intr))) {
		/*
		 * We could not locate the thread. Skip this CPU. Race
		 * conditions while performing these checks are benign.
		 * These checks are not perfect and they don't need
		 * to be.
		 */
		thread_free_allow(t);
		return;
	}

	intr = t->t_flag & T_INTR_THREAD;
	lwp = ttolwp(t);
	if (lwp == NULL || (t->t_proc_flag & TP_LWPEXIT) || intr) {
		/*
		 * Thread is exiting (or uninteresting) so don't
		 * do tick processing.
		 */
		thread_free_allow(t);
		return;
	}

	/*
	 * OK, try to grab the process lock.  See
	 * comments above for why we're not using
	 * ttoproc(t)->p_lockp here.
	 */
	plockp = t->t_plockp;
	mutex_enter(plockp);
	/* See above comment. */
	if (CLOCK_TICK_CPU_OFFLINE(cp)) {
		mutex_exit(plockp);
		thread_free_allow(t);
		return;
	}

	/*
	 * The thread may have exited between when we
	 * checked above, and when we got the p_lock.
	 */
	if (t->t_proc_flag & TP_LWPEXIT) {
		mutex_exit(plockp);
		thread_free_allow(t);
		return;
	}

	/*
	 * Either we have the p_lock for the thread's process,
	 * or we don't care about the thread structure any more.
	 * Either way we can allow thread free.
	 */
	thread_free_allow(t);

	/*
	 * If we haven't done tick processing for this
	 * lwp, then do it now. Since we don't hold the
	 * lwp down on a CPU it can migrate and show up
	 * more than once, hence the lbolt check. mylbolt
	 * is copied at the time of tick scheduling to prevent
	 * lbolt mismatches.
	 *
	 * Also, make sure that it's okay to perform the
	 * tick processing before calling clock_tick.
	 * Setting notick to a TRUE value (ie. not 0)
	 * results in tick processing not being performed for
	 * that thread.
	 */
	notick = ((cp->cpu_flags & CPU_QUIESCED) || CPU_ON_INTR(cp) ||
	    (cp->cpu_dispthread == cp->cpu_idle_thread));

	if ((!notick) && (t->t_lbolt < mylbolt)) {
		t->t_lbolt = mylbolt;
		clock_tick(t, pending);
	}

	mutex_exit(plockp);
}

void
clock_tick_schedule(int one_sec)
{
	ulong_t			active;
	int			i, end;
	clock_tick_set_t	*csp;
	cpu_t			*cp;

	if (clock_cpu_id != CPU->cpu_id)
		clock_cpu_id = CPU->cpu_id;

	if (clock_tick_single_threaded) {
		/*
		 * Each tick cycle, start the scan from a different
		 * CPU for the sake of fairness.
		 */
		end = clock_tick_total_cpus;
		clock_tick_scan++;
		if (clock_tick_scan >= end)
			clock_tick_scan = 0;

		clock_tick_execute_common(0, clock_tick_scan, end,
		    LBOLT_NO_ACCOUNT, 1);

		return;
	}

	/*
	 * If the previous invocation of handlers is not yet finished, then
	 * simply increment a pending count and return. Eventually when they
	 * finish, the pending count is passed down to the next set of
	 * handlers to process. This way, ticks that have already elapsed
	 * in the past are handled as quickly as possible to minimize the
	 * chances of threads getting away before their pending ticks are
	 * accounted. The other benefit is that if the pending count is
	 * more than one, it can be handled by a single invocation of
	 * clock_tick(). This is a good optimization for large configuration
	 * busy systems where tick accounting can get backed up for various
	 * reasons.
	 */
	clock_tick_pending++;

	active = clock_tick_active;
	active = atomic_cas_ulong(&clock_tick_active, active, active);
	if (active)
		return;

	/*
	 * We want to handle the clock CPU here. If we
	 * scheduled the accounting for the clock CPU to another
	 * processor, that processor will find only the clock() thread
	 * running and not account for any user thread below it. Also,
	 * we want to handle this before we block on anything and allow
	 * the pinned thread below the current thread to escape.
	 */
	clock_tick_process(CPU, LBOLT_NO_ACCOUNT, clock_tick_pending);

	mutex_enter(&clock_tick_lock);

	/*
	 * Schedule each set on a separate processor.
	 */
	cp = clock_cpu_list;
	for (i = 0; i < clock_tick_nsets; i++) {
		csp = &clock_tick_set[i];

		/*
		 * Pick the next online CPU in list for scheduling tick
		 * accounting. The clock_tick_lock is held by the caller.
		 * So, CPU online/offline cannot muck with this while
		 * we are picking our CPU to X-call.
		 */
		if (cp == CPU)
			cp = cp->cpu_next_onln;

		/*
		 * Each tick cycle, start the scan from a different
		 * CPU for the sake of fairness.
		 */
		csp->ct_scan++;
		if (csp->ct_scan >= csp->ct_end)
			csp->ct_scan = csp->ct_start;

		clock_tick_schedule_one(csp, clock_tick_pending, cp->cpu_id);

		cp = cp->cpu_next_onln;
	}

	if (one_sec) {
		/*
		 * Move the CPU pointer around every second. This is so
		 * all the CPUs can be X-called in a round-robin fashion
		 * to evenly distribute the X-calls. We don't do this
		 * at a faster rate than this because we don't want
		 * to affect cache performance negatively.
		 */
		clock_cpu_list = clock_cpu_list->cpu_next_onln;
	}

	mutex_exit(&clock_tick_lock);

	clock_tick_pending = 0;
}

static void
clock_tick_execute_common(int start, int scan, int end, clock_t mylbolt,
	int pending)
{
	cpu_t		*cp;
	int		i;

	ASSERT((start <= scan) && (scan <= end));

	/*
	 * Handle the thread on current CPU first. This is to prevent a
	 * pinned thread from escaping if we ever block on something.
	 * Note that in the single-threaded mode, this handles the clock
	 * CPU.
	 */
	clock_tick_process(CPU, mylbolt, pending);

	/*
	 * Perform tick accounting for the threads running on
	 * the scheduled CPUs.
	 */
	for (i = scan; i < end; i++) {
		cp = clock_tick_cpus[i];
		if ((cp == NULL) || (cp == CPU) || (cp->cpu_id == clock_cpu_id))
			continue;
		clock_tick_process(cp, mylbolt, pending);
	}

	for (i = start; i < scan; i++) {
		cp = clock_tick_cpus[i];
		if ((cp == NULL) || (cp == CPU) || (cp->cpu_id == clock_cpu_id))
			continue;
		clock_tick_process(cp, mylbolt, pending);
	}
}

/*ARGSUSED*/
static uint_t
clock_tick_execute(caddr_t arg1, caddr_t arg2)
{
	clock_tick_cpu_t	*ctp;
	int			start, scan, end, pending;
	clock_t			mylbolt;

	/*
	 * We could have raced with cpu offline. We don't want to
	 * process anything on an offlined CPU. If we got blocked
	 * on anything, we may not get scheduled when we wakeup
	 * later on.
	 */
	if (!CLOCK_TICK_XCALL_SAFE(CPU))
		goto out;

	ctp = clock_tick_cpu[CPU->cpu_id];

	mutex_enter(&ctp->ct_lock);
	pending = ctp->ct_pending;
	if (pending == 0) {
		/*
		 * If a CPU is busy at LOCK_LEVEL, then an invocation
		 * of this softint may be queued for some time. In that case,
		 * clock_tick_active will not be incremented.
		 * clock_tick_schedule() will then assume that the previous
		 * invocation is done and post a new softint. The first one
		 * that gets in will reset the pending count so the
		 * second one is a noop.
		 */
		mutex_exit(&ctp->ct_lock);
		goto out;
	}
	ctp->ct_pending = 0;
	start = ctp->ct_start;
	end = ctp->ct_end;
	scan = ctp->ct_scan;
	mylbolt = ctp->ct_lbolt;
	mutex_exit(&ctp->ct_lock);

	clock_tick_execute_common(start, scan, end, mylbolt, pending);

out:
	/*
	 * Signal completion to the clock handler.
	 */
	atomic_dec_ulong(&clock_tick_active);

	return (1);
}

/*ARGSUSED*/
static int
clock_tick_cpu_setup(cpu_setup_t what, int cid, void *arg)
{
	cpu_t			*cp, *ncp;
	int			i, set;
	clock_tick_set_t	*csp;

	/*
	 * This function performs some computations at CPU offline/online
	 * time. The computed values are used during tick scheduling and
	 * execution phases. This avoids having to compute things on
	 * an every tick basis. The other benefit is that we perform the
	 * computations only for onlined CPUs (not offlined ones). As a
	 * result, no tick processing is attempted for offlined CPUs.
	 *
	 * Also, cpu_offline() calls this function before checking for
	 * active interrupt threads. This allows us to avoid posting
	 * cross calls to CPUs that are being offlined.
	 */

	cp = cpu[cid];

	mutex_enter(&clock_tick_lock);

	switch (what) {
	case CPU_ON:
		clock_tick_cpus[clock_tick_total_cpus] = cp;
		set = clock_tick_total_cpus / clock_tick_ncpus;
		csp = &clock_tick_set[set];
		csp->ct_end++;
		clock_tick_total_cpus++;
		clock_tick_nsets =
		    (clock_tick_total_cpus + clock_tick_ncpus - 1) /
		    clock_tick_ncpus;
		CPUSET_ADD(clock_tick_online_cpuset, cp->cpu_id);
		membar_sync();
		break;

	case CPU_OFF:
		if (&sync_softint != NULL)
			sync_softint(clock_tick_online_cpuset);
		CPUSET_DEL(clock_tick_online_cpuset, cp->cpu_id);
		clock_tick_total_cpus--;
		clock_tick_cpus[clock_tick_total_cpus] = NULL;
		clock_tick_nsets =
		    (clock_tick_total_cpus + clock_tick_ncpus - 1) /
		    clock_tick_ncpus;
		set = clock_tick_total_cpus / clock_tick_ncpus;
		csp = &clock_tick_set[set];
		csp->ct_end--;

		i = 0;
		ncp = cpu_active;
		do {
			if (cp == ncp)
				continue;
			clock_tick_cpus[i] = ncp;
			i++;
		} while ((ncp = ncp->cpu_next_onln) != cpu_active);
		ASSERT(i == clock_tick_total_cpus);
		membar_sync();
		break;

	default:
		break;
	}

	mutex_exit(&clock_tick_lock);

	return (0);
}


void
clock_tick_mp_init(void)
{
	cpu_t	*cp;

	mutex_enter(&cpu_lock);

	cp = cpu_active;
	do {
		(void) clock_tick_cpu_setup(CPU_ON, cp->cpu_id, NULL);
	} while ((cp = cp->cpu_next_onln) != cpu_active);

	register_cpu_setup_func(clock_tick_cpu_setup, NULL);

	mutex_exit(&cpu_lock);
}
