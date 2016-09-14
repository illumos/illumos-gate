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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2015 by Delphix. All rights reserved.
 */

/*
 * The System Duty Cycle (SDC) scheduling class
 * --------------------------------------------
 *
 * Background
 *
 * Kernel threads in Solaris have traditionally not been large consumers
 * of CPU time.  They typically wake up, perform a small amount of
 * work, then go back to sleep waiting for either a timeout or another
 * signal.  On the assumption that the small amount of work that they do
 * is important for the behavior of the whole system, these threads are
 * treated kindly by the dispatcher and the SYS scheduling class: they run
 * without preemption from anything other than real-time and interrupt
 * threads; when preempted, they are put at the front of the queue, so they
 * generally do not migrate between CPUs; and they are allowed to stay
 * running until they voluntarily give up the CPU.
 *
 * As Solaris has evolved, new workloads have emerged which require the
 * kernel to perform significant amounts of CPU-intensive work.  One
 * example of such a workload is ZFS's transaction group sync processing.
 * Each sync operation generates a large batch of I/Os, and each I/O
 * may need to be compressed and/or checksummed before it is written to
 * storage.  The taskq threads which perform the compression and checksums
 * will run nonstop as long as they have work to do; a large sync operation
 * on a compression-heavy dataset can keep them busy for seconds on end.
 * This causes human-time-scale dispatch latency bubbles for any other
 * threads which have the misfortune to share a CPU with the taskq threads.
 *
 * The SDC scheduling class is a solution to this problem.
 *
 *
 * Overview
 *
 * SDC is centered around the concept of a thread's duty cycle (DC):
 *
 *			      ONPROC time
 *	Duty Cycle =	----------------------
 *			ONPROC + Runnable time
 *
 * This is the ratio of the time that the thread spent running on a CPU
 * divided by the time it spent running or trying to run.  It is unaffected
 * by any time the thread spent sleeping, stopped, etc.
 *
 * A thread joining the SDC class specifies a "target" DC that it wants
 * to run at.  To implement this policy, the routine sysdc_update() scans
 * the list of active SDC threads every few ticks and uses each thread's
 * microstate data to compute the actual duty cycle that that thread
 * has experienced recently.  If the thread is under its target DC, its
 * priority is increased to the maximum available (sysdc_maxpri, which is
 * 99 by default).  If the thread is over its target DC, its priority is
 * reduced to the minimum available (sysdc_minpri, 0 by default).  This
 * is a fairly primitive approach, in that it doesn't use any of the
 * intermediate priorities, but it's not completely inappropriate.  Even
 * though threads in the SDC class might take a while to do their job, they
 * are by some definition important if they're running inside the kernel,
 * so it is reasonable that they should get to run at priority 99.
 *
 * If a thread is running when sysdc_update() calculates its actual duty
 * cycle, and there are other threads of equal or greater priority on its
 * CPU's dispatch queue, sysdc_update() preempts that thread.  The thread
 * acknowledges the preemption by calling sysdc_preempt(), which calls
 * setbackdq(), which gives other threads with the same priority a chance
 * to run.  This creates a de facto time quantum for threads in the SDC
 * scheduling class.
 *
 * An SDC thread which is assigned priority 0 can continue to run if
 * nothing else needs to use the CPU that it's running on.  Similarly, an
 * SDC thread at priority 99 might not get to run as much as it wants to
 * if there are other priority-99 or higher threads on its CPU.  These
 * situations would cause the thread to get ahead of or behind its target
 * DC; the longer the situations lasted, the further ahead or behind the
 * thread would get.  Rather than condemning a thread to a lifetime of
 * paying for its youthful indiscretions, SDC keeps "base" values for
 * ONPROC and Runnable times in each thread's sysdc data, and updates these
 * values periodically.  The duty cycle is then computed using the elapsed
 * amount of ONPROC and Runnable times since those base times.
 *
 * Since sysdc_update() scans SDC threads fairly frequently, it tries to
 * keep the list of "active" threads small by pruning out threads which
 * have been asleep for a brief time.  They are not pruned immediately upon
 * going to sleep, since some threads may bounce back and forth between
 * sleeping and being runnable.
 *
 *
 * Interfaces
 *
 * void sysdc_thread_enter(t, dc, flags)
 *
 *	Moves a kernel thread from the SYS scheduling class to the
 *	SDC class. t must have an associated LWP (created by calling
 *	lwp_kernel_create()).  The thread will have a target DC of dc.
 *	Flags should be either 0 or SYSDC_THREAD_BATCH.  If
 *	SYSDC_THREAD_BATCH is specified, the thread is expected to be
 *	doing large amounts of processing.
 *
 *
 * Complications
 *
 * - Run queue balancing
 *
 *	The Solaris dispatcher is biased towards letting a thread run
 *	on the same CPU which it last ran on, if no more than 3 ticks
 *	(i.e. rechoose_interval) have passed since the thread last ran.
 *	This helps to preserve cache warmth.  On the other hand, it also
 *	tries to keep the per-CPU run queues fairly balanced; if the CPU
 *	chosen for a runnable thread has a run queue which is three or
 *	more threads longer than a neighboring CPU's queue, the runnable
 *	thread is dispatched onto the neighboring CPU instead.
 *
 *	These policies work well for some workloads, but not for many SDC
 *	threads.  The taskq client of SDC, for example, has many discrete
 *	units of work to do.  The work units are largely independent, so
 *	cache warmth is not an important consideration.  It is important
 *	that the threads fan out quickly to different CPUs, since the
 *	amount of work these threads have to do (a few seconds worth at a
 *	time) doesn't leave much time to correct thread placement errors
 *	(i.e. two SDC threads being dispatched to the same CPU).
 *
 *	To fix this, SDC uses the TS_RUNQMATCH flag introduced for FSS.
 *	This tells the dispatcher to keep neighboring run queues' lengths
 *	more evenly matched, which allows SDC threads to migrate more
 *	easily.
 *
 * - LWPs and system processes
 *
 *	SDC can only be used for kernel threads.  Since SDC uses microstate
 *	accounting data to compute each thread's actual duty cycle, all
 *	threads entering the SDC class must have associated LWPs (which
 *	store the microstate data).  This means that the threads have to
 *	be associated with an SSYS process, i.e. one created by newproc().
 *	If the microstate accounting information is ever moved into the
 *	kthread_t, this restriction could be lifted.
 *
 * - Dealing with oversubscription
 *
 *	Since SDC duty cycles are per-thread, it is possible that the
 *	aggregate requested duty cycle of all SDC threads in a processor
 *	set could be greater than the total CPU time available in that set.
 *	The FSS scheduling class has an analogous situation, which it deals
 *	with by reducing each thread's allotted CPU time proportionally.
 *	Since SDC doesn't need to be as precise as FSS, it uses a simpler
 *	solution to the oversubscription problem.
 *
 *	sysdc_update() accumulates the amount of time that max-priority SDC
 *	threads have spent on-CPU in each processor set, and uses that sum
 *	to create an implied duty cycle for that processor set:
 *
 *				accumulated CPU time
 *	   pset DC =	-----------------------------------
 *			 (# CPUs) * time since last update
 *
 *	If this implied duty cycle is above a maximum pset duty cycle (90%
 *	by default), sysdc_update() sets the priority of all SDC threads
 *	in that processor set to sysdc_minpri for a "break" period.  After
 *	the break period, it waits for a "nobreak" period before trying to
 *	enforce the pset duty cycle limit again.
 *
 * - Processor sets
 *
 *	As the above implies, SDC is processor set aware, but it does not
 *	currently allow threads to change processor sets while in the SDC
 *	class.  Instead, those threads must join the desired processor set
 *	before entering SDC. [1]
 *
 * - Batch threads
 *
 *	A thread joining the SDC class can specify the SDC_THREAD_BATCH
 *	flag.  This flag currently has no effect, but marks threads which
 *	do bulk processing.
 *
 * - t_kpri_req
 *
 *	The TS and FSS scheduling classes pay attention to t_kpri_req,
 *	which provides a simple form of priority inheritance for
 *	synchronization primitives (such as rwlocks held as READER) which
 *	cannot be traced to a unique thread.  The SDC class does not honor
 *	t_kpri_req, for a few reasons:
 *
 *	1.  t_kpri_req is notoriously inaccurate.  A measure of its
 *	    inaccuracy is that it needs to be cleared every time a thread
 *	    returns to user mode, because it is frequently non-zero at that
 *	    point.  This can happen because "ownership" of synchronization
 *	    primitives that use t_kpri_req can be silently handed off,
 *	    leaving no opportunity to will the t_kpri_req inheritance.
 *
 *	2.  Unlike in TS and FSS, threads in SDC *will* eventually run at
 *	    kernel priority.  This means that even if an SDC thread
 *	    is holding a synchronization primitive and running at low
 *	    priority, its priority will eventually be raised above 60,
 *	    allowing it to drive on and release the resource.
 *
 *	3.  The first consumer of SDC uses the taskq subsystem, which holds
 *	    a reader lock for the duration of the task's execution.  This
 *	    would mean that SDC threads would never drop below kernel
 *	    priority in practice, which defeats one of the purposes of SDC.
 *
 * - Why not FSS?
 *
 *	It might seem that the existing FSS scheduling class could solve
 *	the problems that SDC is attempting to solve.  FSS's more precise
 *	solution to the oversubscription problem would hardly cause
 *	trouble, as long as it performed well.  SDC is implemented as
 *	a separate scheduling class for two main reasons: the initial
 *	consumer of SDC does not map well onto the "project" abstraction
 *	that is central to FSS, and FSS does not expect to run at kernel
 *	priorities.
 *
 *
 * Tunables
 *
 * - sysdc_update_interval_msec:  Number of milliseconds between
 *	consecutive thread priority updates.
 *
 * - sysdc_reset_interval_msec:  Number of milliseconds between
 *	consecutive resets of a thread's base ONPROC and Runnable
 *	times.
 *
 * - sysdc_prune_interval_msec:  Number of milliseconds of sleeping
 *	before a thread is pruned from the active list.
 *
 * - sysdc_max_pset_DC:  Allowable percentage of a processor set's
 *	CPU time which SDC can give to its high-priority threads.
 *
 * - sysdc_break_msec:  Number of milliseconds of "break" taken when
 *	sysdc_max_pset_DC is exceeded.
 *
 *
 * Future work (in SDC and related subsystems)
 *
 * - Per-thread rechoose interval (0 for SDC)
 *
 *	Allow each thread to specify its own rechoose interval.  SDC
 *	threads would specify an interval of zero, which would rechoose
 *	the CPU with the lowest priority once per update.
 *
 * - Allow threads to change processor sets after joining the SDC class
 *
 * - Thread groups and per-group DC
 *
 *	It might be nice to be able to specify a duty cycle which applies
 *	to a group of threads in aggregate.
 *
 * - Per-group DC callback to allow dynamic DC tuning
 *
 *	Currently, DCs are assigned when the thread joins SDC.  Some
 *	workloads could benefit from being able to tune their DC using
 *	subsystem-specific knowledge about the workload.
 *
 * - Finer-grained priority updates
 *
 * - More nuanced management of oversubscription
 *
 * - Moving other CPU-intensive threads into SDC
 *
 * - Move msacct data into kthread_t
 *
 *	This would allow kernel threads without LWPs to join SDC.
 *
 *
 * Footnotes
 *
 * [1] The details of doing so are left as an exercise for the reader.
 */

#include <sys/types.h>
#include <sys/sysdc.h>
#include <sys/sysdc_impl.h>

#include <sys/class.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/debug.h>
#include <sys/disp.h>
#include <sys/errno.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/schedctl.h>
#include <sys/sdt.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/var.h>

/*
 * Tunables - loaded into the internal state at module load time
 */
uint_t		sysdc_update_interval_msec = 20;
uint_t		sysdc_reset_interval_msec = 400;
uint_t		sysdc_prune_interval_msec = 100;
uint_t		sysdc_max_pset_DC = 90;
uint_t		sysdc_break_msec = 80;

/*
 * Internal state - constants set up by sysdc_initparam()
 */
static clock_t	sysdc_update_ticks;	/* ticks between updates */
static uint_t	sysdc_prune_updates;	/* updates asleep before pruning */
static uint_t	sysdc_reset_updates;	/* # of updates before reset */
static uint_t	sysdc_break_updates;	/* updates to break */
static uint_t	sysdc_nobreak_updates;	/* updates to not check */
static uint_t	sysdc_minDC;		/* minimum allowed DC */
static uint_t	sysdc_maxDC;		/* maximum allowed DC */
static pri_t	sysdc_minpri;		/* minimum allowed priority */
static pri_t	sysdc_maxpri;		/* maximum allowed priority */

/*
 * Internal state
 */
static kmutex_t	sysdc_pset_lock;	/* lock protecting pset data */
static list_t	sysdc_psets;		/* list of psets with SDC threads */
static uint_t	sysdc_param_init;	/* sysdc_initparam() has been called */
static uint_t	sysdc_update_timeout_started; /* update timeout is active */
static hrtime_t	sysdc_last_update;	/* time of last sysdc_update() */
static sysdc_t	sysdc_dummy;		/* used to terminate active lists */

/*
 * Internal state - active hash table
 */
#define	SYSDC_NLISTS	8
#define	SYSDC_HASH(sdc)	(((uintptr_t)(sdc) >> 6) & (SYSDC_NLISTS - 1))
static sysdc_list_t	sysdc_active[SYSDC_NLISTS];
#define	SYSDC_LIST(sdc)		(&sysdc_active[SYSDC_HASH(sdc)])

#ifdef DEBUG
static struct {
	uint64_t	sysdc_update_times_asleep;
	uint64_t	sysdc_update_times_base_ran_backwards;
	uint64_t	sysdc_update_times_already_done;
	uint64_t	sysdc_update_times_cur_ran_backwards;
	uint64_t	sysdc_compute_pri_breaking;
	uint64_t	sysdc_activate_enter;
	uint64_t	sysdc_update_enter;
	uint64_t	sysdc_update_exited;
	uint64_t	sysdc_update_not_sdc;
	uint64_t	sysdc_update_idle;
	uint64_t	sysdc_update_take_break;
	uint64_t	sysdc_update_no_psets;
	uint64_t	sysdc_tick_not_sdc;
	uint64_t	sysdc_tick_quantum_expired;
	uint64_t	sysdc_thread_enter_enter;
} sysdc_stats;

#define	SYSDC_INC_STAT(x)	(sysdc_stats.x++)
#else
#define	SYSDC_INC_STAT(x)	((void)0)
#endif

/* macros are UPPER CASE */
#define	HOWMANY(a, b)	howmany((a), (b))
#define	MSECTOTICKS(a)	HOWMANY((a) * 1000, usec_per_tick)

static void
sysdc_initparam(void)
{
	uint_t sysdc_break_ticks;

	/* update / prune intervals */
	sysdc_update_ticks = MSECTOTICKS(sysdc_update_interval_msec);

	sysdc_prune_updates = HOWMANY(sysdc_prune_interval_msec,
	    sysdc_update_interval_msec);
	sysdc_reset_updates = HOWMANY(sysdc_reset_interval_msec,
	    sysdc_update_interval_msec);

	/* We must get at least a little time on CPU. */
	sysdc_minDC = 1;
	sysdc_maxDC = SYSDC_DC_MAX;
	sysdc_minpri = 0;
	sysdc_maxpri = maxclsyspri - 1;

	/* break parameters */
	if (sysdc_max_pset_DC > SYSDC_DC_MAX) {
		sysdc_max_pset_DC = SYSDC_DC_MAX;
	}
	sysdc_break_ticks = MSECTOTICKS(sysdc_break_msec);
	sysdc_break_updates = HOWMANY(sysdc_break_ticks, sysdc_update_ticks);

	/*
	 * We want:
	 *
	 *	sysdc_max_pset_DC = (nobreak / (break + nobreak))
	 *
	 *	==>	  nobreak = sysdc_max_pset_DC * (break + nobreak)
	 *
	 *			    sysdc_max_pset_DC * break
	 *	==>	  nobreak = -------------------------
	 *			    1 - sysdc_max_pset_DC
	 */
	sysdc_nobreak_updates =
	    HOWMANY((uint64_t)sysdc_break_updates * sysdc_max_pset_DC,
	    (SYSDC_DC_MAX - sysdc_max_pset_DC));

	sysdc_param_init = 1;
}

#undef HOWMANY
#undef MSECTOTICKS

#define	SDC_UPDATE_INITIAL	0x1	/* for the initial update */
#define	SDC_UPDATE_TIMEOUT	0x2	/* from sysdc_update() */
#define	SDC_UPDATE_TICK		0x4	/* from sysdc_tick(), on expiry */

/*
 * Updates the recorded times in the sdc, and returns the elapsed ONPROC
 * and Runnable times since the last reset.
 *
 * newO is the thread's actual ONPROC time; it's used during sysdc_update()
 * to track processor set usage.
 */
static void
sysdc_update_times(sysdc_t *sdc, uint_t flags,
    hrtime_t *O, hrtime_t *R, hrtime_t *newO)
{
	kthread_t *const t = sdc->sdc_thread;
	const uint_t	initial = (flags & SDC_UPDATE_INITIAL);
	const uint_t	update = (flags & SDC_UPDATE_TIMEOUT);
	const clock_t	now = ddi_get_lbolt();
	uint_t		do_reset;

	ASSERT(THREAD_LOCK_HELD(t));

	*O = *R = 0;

	/* If we've been sleeping, we know we haven't had any ONPROC time. */
	if (sdc->sdc_sleep_updates != 0 &&
	    sdc->sdc_sleep_updates != sdc->sdc_nupdates) {
		*newO = sdc->sdc_last_base_O;
		SYSDC_INC_STAT(sysdc_update_times_asleep);
		return;
	}

	/*
	 * If this is our first update, or we've hit the reset point,
	 * we need to reset our base_{O,R}.  Once we've updated them, we
	 * report O and R for the entire prior interval.
	 */
	do_reset = initial;
	if (update) {
		++sdc->sdc_nupdates;
		if ((sdc->sdc_nupdates % sysdc_reset_updates) == 0)
			do_reset = 1;
	}
	if (do_reset) {
		hrtime_t baseO, baseR;
		if (initial) {
			/*
			 * Start off our cycle count somewhere in the middle,
			 * to keep the resets from all happening at once.
			 *
			 * 4999 is a handy prime much larger than
			 * sysdc_reset_updates, so that we don't run into
			 * trouble if the resolution is a multiple of
			 * sysdc_reset_updates.
			 */
			sdc->sdc_nupdates = (uint_t)((gethrtime() % 4999) %
			    sysdc_reset_updates);
			baseO = baseR = 0;
		} else {
			baseO = sdc->sdc_base_O;
			baseR = sdc->sdc_base_R;
		}

		mstate_systhread_times(t, &sdc->sdc_base_O, &sdc->sdc_base_R);
		*newO = sdc->sdc_base_O;

		sdc->sdc_reset = now;
		sdc->sdc_pri_check = -1; /* force mismatch below */

		/*
		 * See below for rationale.
		 */
		if (baseO > sdc->sdc_base_O || baseR > sdc->sdc_base_R) {
			SYSDC_INC_STAT(sysdc_update_times_base_ran_backwards);
			baseO = sdc->sdc_base_O;
			baseR = sdc->sdc_base_R;
		}

		/* compute based on the entire interval */
		*O = (sdc->sdc_base_O - baseO);
		*R = (sdc->sdc_base_R - baseR);
		return;
	}

	/*
	 * If we're called from sysdc_update(), we *must* return a value
	 * for newO, so we always call mstate_systhread_times().
	 *
	 * Otherwise, if we've already done a pri check this tick,
	 * we can skip it.
	 */
	if (!update && sdc->sdc_pri_check == now) {
		SYSDC_INC_STAT(sysdc_update_times_already_done);
		return;
	}

	/* Get the current times from the thread */
	sdc->sdc_pri_check = now;
	mstate_systhread_times(t, &sdc->sdc_cur_O, &sdc->sdc_cur_R);
	*newO = sdc->sdc_cur_O;

	/*
	 * The updating of microstate accounting is not done under a
	 * consistent set of locks, particularly the t_waitrq field.  This
	 * can lead to narrow windows in which we account for time in the
	 * wrong bucket, which on the next read will be accounted for
	 * correctly.
	 *
	 * If our sdc_base_* fields were affected by one of these blips, we
	 * throw away the old data, and pretend this tick didn't happen.
	 */
	if (sdc->sdc_cur_O < sdc->sdc_base_O ||
	    sdc->sdc_cur_R < sdc->sdc_base_R) {

		sdc->sdc_base_O = sdc->sdc_cur_O;
		sdc->sdc_base_R = sdc->sdc_cur_R;

		SYSDC_INC_STAT(sysdc_update_times_cur_ran_backwards);
		return;
	}

	*O = sdc->sdc_cur_O - sdc->sdc_base_O;
	*R = sdc->sdc_cur_R - sdc->sdc_base_R;
}

/*
 * sysdc_compute_pri()
 *
 *	Recomputes the priority of the thread, leaving the result in
 *	sdc->sdc_epri.  Returns 1 if a priority update should occur
 *	(which will also trigger a cpu_surrender()), otherwise
 *	returns 0.
 */
static uint_t
sysdc_compute_pri(sysdc_t *sdc, uint_t flags)
{
	kthread_t *const t = sdc->sdc_thread;
	const uint_t	update = (flags & SDC_UPDATE_TIMEOUT);
	const uint_t	tick = (flags & SDC_UPDATE_TICK);

	hrtime_t	O, R;
	hrtime_t	newO = -1;

	ASSERT(THREAD_LOCK_HELD(t));

	sysdc_update_times(sdc, flags, &O, &R, &newO);
	ASSERT(!update || newO != -1);

	/* If we have new data, recompute our priority. */
	if ((O + R) != 0) {
		sdc->sdc_cur_DC = (O * SYSDC_DC_MAX) / (O + R);

		/* Adjust our priority to move our DC closer to the target. */
		if (sdc->sdc_cur_DC < sdc->sdc_target_DC)
			sdc->sdc_pri = sdc->sdc_maxpri;
		else
			sdc->sdc_pri = sdc->sdc_minpri;
	}

	/*
	 * If our per-pset duty cycle goes over the max, we will take a break.
	 * This forces all sysdc threads in the pset to minimum priority, in
	 * order to let everyone else have a chance at the CPU.
	 */
	if (sdc->sdc_pset->sdp_need_break) {
		SYSDC_INC_STAT(sysdc_compute_pri_breaking);
		sdc->sdc_epri = sdc->sdc_minpri;
	} else {
		sdc->sdc_epri = sdc->sdc_pri;
	}

	DTRACE_PROBE4(sysdc__compute__pri,
	    kthread_t *, t, pri_t, sdc->sdc_epri, uint_t, sdc->sdc_cur_DC,
	    uint_t, sdc->sdc_target_DC);

	/*
	 * For sysdc_update(), we compute the ONPROC time for high-priority
	 * threads, which is used to calculate the per-pset duty cycle.  We
	 * will always tell our callers to update the thread's priority,
	 * since we want to force a cpu_surrender().
	 *
	 * We reset sdc_update_ticks so that sysdc_tick() will only update
	 * the thread's priority if our timeout is delayed by a tick or
	 * more.
	 */
	if (update) {
		/* SDC threads are not allowed to change cpupart bindings. */
		ASSERT(t->t_cpupart == sdc->sdc_pset->sdp_cpupart);

		/* If we were at MAXPRI, account for our onproc time. */
		if (t->t_pri == sdc->sdc_maxpri &&
		    sdc->sdc_last_base_O != 0 &&
		    sdc->sdc_last_base_O < newO) {
			sdc->sdc_last_O = newO - sdc->sdc_last_base_O;
			sdc->sdc_pset->sdp_onproc_time +=
			    (uint64_t)sdc->sdc_last_O;
			sdc->sdc_pset->sdp_onproc_threads++;
		} else {
			sdc->sdc_last_O = 0;
		}
		sdc->sdc_last_base_O = newO;

		sdc->sdc_update_ticks = sdc->sdc_ticks + sysdc_update_ticks + 1;
		return (1);
	}

	/*
	 * Like sysdc_update(), sysdc_tick() always wants to update the
	 * thread's priority, so that the CPU is surrendered if necessary.
	 * We reset sdc_update_ticks so that if the timeout continues to be
	 * delayed, we'll update at the regular interval.
	 */
	if (tick) {
		ASSERT(sdc->sdc_ticks == sdc->sdc_update_ticks);
		sdc->sdc_update_ticks = sdc->sdc_ticks + sysdc_update_ticks;
		return (1);
	}

	/*
	 * Otherwise, only tell our callers to update the priority if it has
	 * changed.
	 */
	return (sdc->sdc_epri != t->t_pri);
}

static void
sysdc_update_pri(sysdc_t *sdc, uint_t flags)
{
	kthread_t *t = sdc->sdc_thread;

	ASSERT(THREAD_LOCK_HELD(t));

	if (sysdc_compute_pri(sdc, flags)) {
		if (!thread_change_pri(t, sdc->sdc_epri, 0)) {
			cpu_surrender(t);
		}
	}
}

/*
 * Add a thread onto the active list.  It will only be removed by
 * sysdc_update().
 */
static void
sysdc_activate(sysdc_t *sdc)
{
	sysdc_t *volatile *headp = &SYSDC_LIST(sdc)->sdl_list;
	sysdc_t		*head;
	kthread_t	*t = sdc->sdc_thread;

	SYSDC_INC_STAT(sysdc_activate_enter);

	ASSERT(sdc->sdc_next == NULL);
	ASSERT(THREAD_LOCK_HELD(t));

	do {
		head = *headp;
		sdc->sdc_next = head;
	} while (atomic_cas_ptr(headp, head, sdc) != head);
}

/*
 * sysdc_update() has two jobs:
 *
 *	1. It updates the priorities of all active SDC threads on the system.
 *	2. It measures pset CPU usage and enforces sysdc_max_pset_DC.
 */
static void
sysdc_update(void *arg)
{
	int		idx;
	sysdc_t		*freelist = NULL;
	sysdc_pset_t	*cur;
	hrtime_t	now, diff;
	uint_t		redeploy = 1;

	SYSDC_INC_STAT(sysdc_update_enter);

	ASSERT(sysdc_update_timeout_started);

	/*
	 * If this is our first time through, diff will be gigantic, and
	 * no breaks will be necessary.
	 */
	now = gethrtime();
	diff = now - sysdc_last_update;
	sysdc_last_update = now;

	mutex_enter(&sysdc_pset_lock);
	for (cur = list_head(&sysdc_psets); cur != NULL;
	    cur = list_next(&sysdc_psets, cur)) {
		boolean_t breaking = (cur->sdp_should_break != 0);

		if (cur->sdp_need_break != breaking) {
			DTRACE_PROBE2(sdc__pset__break, sysdc_pset_t *, cur,
			    boolean_t, breaking);
		}
		cur->sdp_onproc_time = 0;
		cur->sdp_onproc_threads = 0;
		cur->sdp_need_break = breaking;
	}
	mutex_exit(&sysdc_pset_lock);

	for (idx = 0; idx < SYSDC_NLISTS; idx++) {
		sysdc_list_t		*sdl = &sysdc_active[idx];
		sysdc_t *volatile	*headp = &sdl->sdl_list;
		sysdc_t			*head, *tail;
		sysdc_t			**prevptr;

		if (*headp == &sysdc_dummy)
			continue;

		/* Prevent any threads from exiting while we're poking them. */
		mutex_enter(&sdl->sdl_lock);

		/*
		 * Each sdl_list contains a singly-linked list of active
		 * threads. Threads which become active while we are
		 * processing the list will be added to sdl_list.  Since we
		 * don't want that to interfere with our own processing, we
		 * swap in an empty list.  Any newly active threads will
		 * go on to this empty list.  When finished, we'll put any
		 * such threads at the end of the processed list.
		 */
		head = atomic_swap_ptr(headp, &sysdc_dummy);
		prevptr = &head;
		while (*prevptr != &sysdc_dummy) {
			sysdc_t		*const	sdc = *prevptr;
			kthread_t	*const	t = sdc->sdc_thread;

			/*
			 * If the thread has exited, move its sysdc_t onto
			 * freelist, to be freed later.
			 */
			if (t == NULL) {
				*prevptr = sdc->sdc_next;
				SYSDC_INC_STAT(sysdc_update_exited);
				sdc->sdc_next = freelist;
				freelist = sdc;
				continue;
			}

			thread_lock(t);
			if (t->t_cid != sysdccid) {
				thread_unlock(t);
				prevptr = &sdc->sdc_next;
				SYSDC_INC_STAT(sysdc_update_not_sdc);
				continue;
			}
			ASSERT(t->t_cldata == sdc);

			/*
			 * If the thread has been sleeping for longer
			 * than sysdc_prune_interval, make it inactive by
			 * removing it from the list.
			 */
			if (!(t->t_state & (TS_RUN | TS_ONPROC)) &&
			    sdc->sdc_sleep_updates != 0 &&
			    (sdc->sdc_sleep_updates - sdc->sdc_nupdates) >
			    sysdc_prune_updates) {
				*prevptr = sdc->sdc_next;
				SYSDC_INC_STAT(sysdc_update_idle);
				sdc->sdc_next = NULL;
				thread_unlock(t);
				continue;
			}
			sysdc_update_pri(sdc, SDC_UPDATE_TIMEOUT);
			thread_unlock(t);

			prevptr = &sdc->sdc_next;
		}

		/*
		 * Add our list to the bucket, putting any new entries
		 * added while we were working at the tail of the list.
		 */
		do {
			tail = *headp;
			*prevptr = tail;
		} while (atomic_cas_ptr(headp, tail, head) != tail);

		mutex_exit(&sdl->sdl_lock);
	}

	mutex_enter(&sysdc_pset_lock);
	for (cur = list_head(&sysdc_psets); cur != NULL;
	    cur = list_next(&sysdc_psets, cur)) {

		cur->sdp_vtime_last_interval =
		    diff * cur->sdp_cpupart->cp_ncpus;
		cur->sdp_DC_last_interval =
		    (cur->sdp_onproc_time * SYSDC_DC_MAX) /
		    cur->sdp_vtime_last_interval;

		if (cur->sdp_should_break > 0) {
			cur->sdp_should_break--;	/* breaking */
			continue;
		}
		if (cur->sdp_dont_break > 0) {
			cur->sdp_dont_break--;	/* waiting before checking */
			continue;
		}
		if (cur->sdp_DC_last_interval > sysdc_max_pset_DC) {
			cur->sdp_should_break = sysdc_break_updates;
			cur->sdp_dont_break = sysdc_nobreak_updates;
			SYSDC_INC_STAT(sysdc_update_take_break);
		}
	}

	/*
	 * If there are no sysdc_psets, there can be no threads, so
	 * we can stop doing our timeout.  Since we're holding the
	 * sysdc_pset_lock, no new sysdc_psets can come in, which will
	 * prevent anyone from racing with this and dropping our timeout
	 * on the floor.
	 */
	if (list_is_empty(&sysdc_psets)) {
		SYSDC_INC_STAT(sysdc_update_no_psets);
		ASSERT(sysdc_update_timeout_started);
		sysdc_update_timeout_started = 0;

		redeploy = 0;
	}
	mutex_exit(&sysdc_pset_lock);

	while (freelist != NULL) {
		sysdc_t *cur = freelist;
		freelist = cur->sdc_next;
		kmem_free(cur, sizeof (*cur));
	}

	if (redeploy) {
		(void) timeout(sysdc_update, arg, sysdc_update_ticks);
	}
}

static void
sysdc_preempt(kthread_t *t)
{
	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(t));

	setbackdq(t);		/* give others a chance to run */
}

static void
sysdc_tick(kthread_t *t)
{
	sysdc_t *sdc;

	thread_lock(t);
	if (t->t_cid != sysdccid) {
		SYSDC_INC_STAT(sysdc_tick_not_sdc);
		thread_unlock(t);
		return;
	}
	sdc = t->t_cldata;
	if (t->t_state == TS_ONPROC &&
	    t->t_pri < t->t_disp_queue->disp_maxrunpri) {
		cpu_surrender(t);
	}

	if (t->t_state == TS_ONPROC || t->t_state == TS_RUN) {
		ASSERT(sdc->sdc_sleep_updates == 0);
	}

	ASSERT(sdc->sdc_ticks != sdc->sdc_update_ticks);
	sdc->sdc_ticks++;
	if (sdc->sdc_ticks == sdc->sdc_update_ticks) {
		SYSDC_INC_STAT(sysdc_tick_quantum_expired);
		sysdc_update_pri(sdc, SDC_UPDATE_TICK);
		ASSERT(sdc->sdc_ticks != sdc->sdc_update_ticks);
	}
	thread_unlock(t);
}

static void
sysdc_setrun(kthread_t *t)
{
	sysdc_t *sdc = t->t_cldata;

	ASSERT(THREAD_LOCK_HELD(t));	/* t should be in transition */

	sdc->sdc_sleep_updates = 0;

	if (sdc->sdc_next == NULL) {
		/*
		 * Since we're in transition, we don't want to use the
		 * full thread_update_pri().
		 */
		if (sysdc_compute_pri(sdc, 0)) {
			THREAD_CHANGE_PRI(t, sdc->sdc_epri);
		}
		sysdc_activate(sdc);

		ASSERT(sdc->sdc_next != NULL);
	}

	setbackdq(t);
}

static void
sysdc_wakeup(kthread_t *t)
{
	sysdc_setrun(t);
}

static void
sysdc_sleep(kthread_t *t)
{
	sysdc_t *sdc = t->t_cldata;

	ASSERT(THREAD_LOCK_HELD(t));	/* t should be in transition */

	sdc->sdc_sleep_updates = sdc->sdc_nupdates;
}

/*ARGSUSED*/
static int
sysdc_enterclass(kthread_t *t, id_t cid, void *parmsp, cred_t *reqpcredp,
    void *bufp)
{
	cpupart_t *const cpupart = t->t_cpupart;
	sysdc_t *sdc = bufp;
	sysdc_params_t *sdpp = parmsp;
	sysdc_pset_t *newpset = sdc->sdc_pset;
	sysdc_pset_t *pset;
	int start_timeout;

	if (t->t_cid != syscid)
		return (EPERM);

	ASSERT(ttolwp(t) != NULL);
	ASSERT(sdpp != NULL);
	ASSERT(newpset != NULL);
	ASSERT(sysdc_param_init);

	ASSERT(sdpp->sdp_minpri >= sysdc_minpri);
	ASSERT(sdpp->sdp_maxpri <= sysdc_maxpri);
	ASSERT(sdpp->sdp_DC >= sysdc_minDC);
	ASSERT(sdpp->sdp_DC <= sysdc_maxDC);

	sdc->sdc_thread = t;
	sdc->sdc_pri = sdpp->sdp_maxpri;	/* start off maximally */
	sdc->sdc_minpri = sdpp->sdp_minpri;
	sdc->sdc_maxpri = sdpp->sdp_maxpri;
	sdc->sdc_target_DC = sdpp->sdp_DC;
	sdc->sdc_ticks = 0;
	sdc->sdc_update_ticks = sysdc_update_ticks + 1;

	/* Assign ourselves to the appropriate pset. */
	sdc->sdc_pset = NULL;
	mutex_enter(&sysdc_pset_lock);
	for (pset = list_head(&sysdc_psets); pset != NULL;
	    pset = list_next(&sysdc_psets, pset)) {
		if (pset->sdp_cpupart == cpupart) {
			break;
		}
	}
	if (pset == NULL) {
		pset = newpset;
		newpset = NULL;
		pset->sdp_cpupart = cpupart;
		list_insert_tail(&sysdc_psets, pset);
	}
	pset->sdp_nthreads++;
	ASSERT(pset->sdp_nthreads > 0);

	sdc->sdc_pset = pset;

	start_timeout = (sysdc_update_timeout_started == 0);
	sysdc_update_timeout_started = 1;
	mutex_exit(&sysdc_pset_lock);

	if (newpset != NULL)
		kmem_free(newpset, sizeof (*newpset));

	/* Update t's scheduling class and priority. */
	thread_lock(t);
	t->t_clfuncs = &(sclass[cid].cl_funcs->thread);
	t->t_cid = cid;
	t->t_cldata = sdc;
	t->t_schedflag |= TS_RUNQMATCH;

	sysdc_update_pri(sdc, SDC_UPDATE_INITIAL);
	thread_unlock(t);

	/* Kick off the thread timeout if we're the first one in. */
	if (start_timeout) {
		(void) timeout(sysdc_update, NULL, sysdc_update_ticks);
	}

	return (0);
}

static void
sysdc_leave(sysdc_t *sdc)
{
	sysdc_pset_t *sdp = sdc->sdc_pset;
	sysdc_list_t *sdl = SYSDC_LIST(sdc);
	uint_t freedc;

	mutex_enter(&sdl->sdl_lock);		/* block sysdc_update() */
	sdc->sdc_thread = NULL;
	freedc = (sdc->sdc_next == NULL);
	mutex_exit(&sdl->sdl_lock);

	mutex_enter(&sysdc_pset_lock);
	ASSERT(sdp != NULL);
	ASSERT(sdp->sdp_nthreads > 0);
	--sdp->sdp_nthreads;
	if (sdp->sdp_nthreads == 0) {
		list_remove(&sysdc_psets, sdp);
	} else {
		sdp = NULL;
	}
	mutex_exit(&sysdc_pset_lock);

	if (freedc)
		kmem_free(sdc, sizeof (*sdc));
	if (sdp != NULL)
		kmem_free(sdp, sizeof (*sdp));
}

static void
sysdc_exitclass(void *buf)
{
	sysdc_leave((sysdc_t *)buf);
}

/*ARGSUSED*/
static int
sysdc_canexit(kthread_t *t, cred_t *reqpcredp)
{
	/* Threads cannot exit SDC once joined, except in a body bag. */
	return (EPERM);
}

static void
sysdc_exit(kthread_t *t)
{
	sysdc_t *sdc;

	/* We're exiting, so we just rejoin the SYS class. */
	thread_lock(t);
	ASSERT(t->t_cid == sysdccid);
	sdc = t->t_cldata;
	t->t_cid = syscid;
	t->t_cldata = NULL;
	t->t_clfuncs = &(sclass[syscid].cl_funcs->thread);
	(void) thread_change_pri(t, maxclsyspri, 0);
	t->t_schedflag &= ~TS_RUNQMATCH;
	thread_unlock_nopreempt(t);

	/* Unlink the sdc from everything. */
	sysdc_leave(sdc);
}

/*ARGSUSED*/
static int
sysdc_fork(kthread_t *t, kthread_t *ct, void *bufp)
{
	/*
	 * Threads cannot be created with SDC as their class; they must
	 * be created as SYS and then added with sysdc_thread_enter().
	 * Because of this restriction, sysdc_fork() should never be called.
	 */
	panic("sysdc cannot be forked");

	return (ENOSYS);
}

/*ARGSUSED*/
static void
sysdc_forkret(kthread_t *t, kthread_t *ct)
{
	/* SDC threads are part of system processes, which never fork. */
	panic("sysdc cannot be forked");
}

static pri_t
sysdc_globpri(kthread_t *t)
{
	return (t->t_epri);
}

/*ARGSUSED*/
static pri_t
sysdc_no_swap(kthread_t *t, int flags)
{
	/* SDC threads cannot be swapped. */
	return (-1);
}

/*
 * Get maximum and minimum priorities enjoyed by SDC threads.
 */
static int
sysdc_getclpri(pcpri_t *pcprip)
{
	pcprip->pc_clpmax = sysdc_maxpri;
	pcprip->pc_clpmin = sysdc_minpri;
	return (0);
}

/*ARGSUSED*/
static int
sysdc_getclinfo(void *arg)
{
	return (0);		/* no class-specific info */
}

/*ARGSUSED*/
static int
sysdc_alloc(void **p, int flag)
{
	sysdc_t *new;

	*p = NULL;
	if ((new = kmem_zalloc(sizeof (*new), flag)) == NULL) {
		return (ENOMEM);
	}
	if ((new->sdc_pset = kmem_zalloc(sizeof (*new->sdc_pset), flag)) ==
	    NULL) {
		kmem_free(new, sizeof (*new));
		return (ENOMEM);
	}
	*p = new;
	return (0);
}

static void
sysdc_free(void *p)
{
	sysdc_t *sdc = p;

	if (sdc != NULL) {
		/*
		 * We must have failed CL_ENTERCLASS(), so our pset should be
		 * there and unused.
		 */
		ASSERT(sdc->sdc_pset != NULL);
		ASSERT(sdc->sdc_pset->sdp_cpupart == NULL);
		kmem_free(sdc->sdc_pset, sizeof (*sdc->sdc_pset));
		kmem_free(sdc, sizeof (*sdc));
	}
}

static int sysdc_enosys();	/* Boy, ANSI-C's K&R compatibility is weird. */
static int sysdc_einval();
static void sysdc_nullsys();

static struct classfuncs sysdc_classfuncs = {
	/* messages to class manager */
	{
		sysdc_enosys,	/* admin */
		sysdc_getclinfo,
		sysdc_enosys,	/* parmsin */
		sysdc_enosys,	/* parmsout */
		sysdc_enosys,	/* vaparmsin */
		sysdc_enosys,	/* vaparmsout */
		sysdc_getclpri,
		sysdc_alloc,
		sysdc_free,
	},
	/* operations on threads */
	{
		sysdc_enterclass,
		sysdc_exitclass,
		sysdc_canexit,
		sysdc_fork,
		sysdc_forkret,
		sysdc_nullsys,	/* parmsget */
		sysdc_enosys,	/* parmsset */
		sysdc_nullsys,	/* stop */
		sysdc_exit,
		sysdc_nullsys,	/* active */
		sysdc_nullsys,	/* inactive */
		sysdc_no_swap,	/* swapin */
		sysdc_no_swap,	/* swapout */
		sysdc_nullsys,	/* trapret */
		sysdc_preempt,
		sysdc_setrun,
		sysdc_sleep,
		sysdc_tick,
		sysdc_wakeup,
		sysdc_einval,	/* donice */
		sysdc_globpri,
		sysdc_nullsys,	/* set_process_group */
		sysdc_nullsys,	/* yield */
		sysdc_einval,	/* doprio */
	}
};

static int
sysdc_enosys()
{
	return (ENOSYS);
}

static int
sysdc_einval()
{
	return (EINVAL);
}

static void
sysdc_nullsys()
{
}

/*ARGSUSED*/
static pri_t
sysdc_init(id_t cid, int clparmsz, classfuncs_t **clfuncspp)
{
	int idx;

	list_create(&sysdc_psets, sizeof (sysdc_pset_t),
	    offsetof(sysdc_pset_t, sdp_node));

	for (idx = 0; idx < SYSDC_NLISTS; idx++) {
		sysdc_active[idx].sdl_list = &sysdc_dummy;
	}

	sysdc_initparam();

	sysdccid = cid;
	*clfuncspp = &sysdc_classfuncs;

	return ((pri_t)v.v_maxsyspri);
}

static struct sclass csw = {
	"SDC",
	sysdc_init,
	0
};

static struct modlsched modlsched = {
	&mod_schedops, "system duty cycle scheduling class", &csw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlsched, NULL
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (EBUSY);		/* can't unload for now */
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* --- consolidation-private interfaces --- */
void
sysdc_thread_enter(kthread_t *t, uint_t dc, uint_t flags)
{
	void *buf = NULL;
	sysdc_params_t sdp;

	SYSDC_INC_STAT(sysdc_thread_enter_enter);

	ASSERT(sysdc_param_init);
	ASSERT(sysdccid >= 0);

	ASSERT((flags & ~SYSDC_THREAD_BATCH) == 0);

	sdp.sdp_minpri = sysdc_minpri;
	sdp.sdp_maxpri = sysdc_maxpri;
	sdp.sdp_DC = MAX(MIN(dc, sysdc_maxDC), sysdc_minDC);

	VERIFY0(CL_ALLOC(&buf, sysdccid, KM_SLEEP));

	ASSERT(t->t_lwp != NULL);
	ASSERT(t->t_cid == syscid);
	ASSERT(t->t_cldata == NULL);
	VERIFY0(CL_CANEXIT(t, NULL));
	VERIFY0(CL_ENTERCLASS(t, sysdccid, &sdp, kcred, buf));
	CL_EXITCLASS(syscid, NULL);
}
