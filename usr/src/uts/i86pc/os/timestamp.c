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
 *
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/disp.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/x86_archext.h>
#include <sys/archsystm.h>
#include <sys/cpuvar.h>
#include <sys/psm_defs.h>
#include <sys/clock.h>
#include <sys/atomic.h>
#include <sys/lockstat.h>
#include <sys/smp_impldefs.h>
#include <sys/dtrace.h>
#include <sys/time.h>
#include <sys/panic.h>
#include <sys/cpu.h>

/*
 * Using the Pentium's TSC register for gethrtime()
 * ------------------------------------------------
 *
 * The Pentium family, like many chip architectures, has a high-resolution
 * timestamp counter ("TSC") which increments once per CPU cycle.  The contents
 * of the timestamp counter are read with the RDTSC instruction.
 *
 * As with its UltraSPARC equivalent (the %tick register), TSC's cycle count
 * must be translated into nanoseconds in order to implement gethrtime().
 * We avoid inducing floating point operations in this conversion by
 * implementing the same nsec_scale algorithm as that found in the sun4u
 * platform code.  The sun4u NATIVE_TIME_TO_NSEC_SCALE block comment contains
 * a detailed description of the algorithm; the comment is not reproduced
 * here.  This implementation differs only in its value for NSEC_SHIFT:
 * we implement an NSEC_SHIFT of 5 (instead of sun4u's 4) to allow for
 * 60 MHz Pentiums.
 *
 * While TSC and %tick are both cycle counting registers, TSC's functionality
 * falls short in several critical ways:
 *
 *  (a)	TSCs on different CPUs are not guaranteed to be in sync.  While in
 *	practice they often _are_ in sync, this isn't guaranteed by the
 *	architecture.
 *
 *  (b)	The TSC cannot be reliably set to an arbitrary value.  The architecture
 *	only supports writing the low 32-bits of TSC, making it impractical
 *	to rewrite.
 *
 *  (c)	The architecture doesn't have the capacity to interrupt based on
 *	arbitrary values of TSC; there is no TICK_CMPR equivalent.
 *
 * Together, (a) and (b) imply that software must track the skew between
 * TSCs and account for it (it is assumed that while there may exist skew,
 * there does not exist drift).  To determine the skew between CPUs, we
 * have newly onlined CPUs call tsc_sync_slave(), while the CPU performing
 * the online operation calls tsc_sync_master().
 *
 * In the absence of time-of-day clock adjustments, gethrtime() must stay in
 * sync with gettimeofday().  This is problematic; given (c), the software
 * cannot drive its time-of-day source from TSC, and yet they must somehow be
 * kept in sync.  We implement this by having a routine, tsc_tick(), which
 * is called once per second from the interrupt which drives time-of-day.
 *
 * Note that the hrtime base for gethrtime, tsc_hrtime_base, is modified
 * atomically with nsec_scale under CLOCK_LOCK.  This assures that time
 * monotonically increases.
 */

#define	NSEC_SHIFT 5

static uint_t nsec_scale;
static uint_t nsec_unscale;

/*
 * These two variables used to be grouped together inside of a structure that
 * lived on a single cache line. A regression (bug ID 4623398) caused the
 * compiler to emit code that "optimized" away the while-loops below. The
 * result was that no synchronization between the onlining and onlined CPUs
 * took place.
 */
static volatile int tsc_ready;
static volatile int tsc_sync_go;

/*
 * Used as indices into the tsc_sync_snaps[] array.
 */
#define	TSC_MASTER		0
#define	TSC_SLAVE		1

/*
 * Used in the tsc_master_sync()/tsc_slave_sync() rendezvous.
 */
#define	TSC_SYNC_STOP		1
#define	TSC_SYNC_GO		2
#define	TSC_SYNC_DONE		3
#define	SYNC_ITERATIONS		10

#define	TSC_CONVERT_AND_ADD(tsc, hrt, scale) {	 	\
	unsigned int *_l = (unsigned int *)&(tsc); 	\
	(hrt) += mul32(_l[1], scale) << NSEC_SHIFT; 	\
	(hrt) += mul32(_l[0], scale) >> (32 - NSEC_SHIFT); \
}

#define	TSC_CONVERT(tsc, hrt, scale) { 			\
	unsigned int *_l = (unsigned int *)&(tsc); 	\
	(hrt) = mul32(_l[1], scale) << NSEC_SHIFT; 	\
	(hrt) += mul32(_l[0], scale) >> (32 - NSEC_SHIFT); \
}

int tsc_master_slave_sync_needed = 1;

static int	tsc_max_delta;
static hrtime_t tsc_sync_tick_delta[NCPU];
typedef struct tsc_sync {
	volatile hrtime_t master_tsc, slave_tsc;
} tsc_sync_t;
static tsc_sync_t *tscp;
static hrtime_t largest_tsc_delta = 0;
static ulong_t shortest_write_time = ~0UL;

static hrtime_t	tsc_last = 0;
static hrtime_t	tsc_last_jumped = 0;
static hrtime_t	tsc_hrtime_base = 0;
static int	tsc_jumped = 0;

static hrtime_t	shadow_tsc_hrtime_base;
static hrtime_t	shadow_tsc_last;
static uint_t	shadow_nsec_scale;
static uint32_t	shadow_hres_lock;
int get_tsc_ready();

hrtime_t
tsc_gethrtime(void)
{
	uint32_t old_hres_lock;
	hrtime_t tsc, hrt;

	do {
		old_hres_lock = hres_lock;

		if ((tsc = tsc_read()) >= tsc_last) {
			/*
			 * It would seem to be obvious that this is true
			 * (that is, the past is less than the present),
			 * but it isn't true in the presence of suspend/resume
			 * cycles.  If we manage to call gethrtime()
			 * after a resume, but before the first call to
			 * tsc_tick(), we will see the jump.  In this case,
			 * we will simply use the value in TSC as the delta.
			 */
			tsc -= tsc_last;
		} else if (tsc >= tsc_last - 2*tsc_max_delta) {
			/*
			 * There is a chance that tsc_tick() has just run on
			 * another CPU, and we have drifted just enough so that
			 * we appear behind tsc_last.  In this case, force the
			 * delta to be zero.
			 */
			tsc = 0;
		}

		hrt = tsc_hrtime_base;

		TSC_CONVERT_AND_ADD(tsc, hrt, nsec_scale);
	} while ((old_hres_lock & ~1) != hres_lock);

	return (hrt);
}

hrtime_t
tsc_gethrtime_delta(void)
{
	uint32_t old_hres_lock;
	hrtime_t tsc, hrt;
	ulong_t flags;

	do {
		old_hres_lock = hres_lock;

		/*
		 * We need to disable interrupts here to assure that we
		 * don't migrate between the call to tsc_read() and
		 * adding the CPU's TSC tick delta. Note that disabling
		 * and reenabling preemption is forbidden here because
		 * we may be in the middle of a fast trap. In the amd64
		 * kernel we cannot tolerate preemption during a fast
		 * trap. See _update_sregs().
		 */

		flags = clear_int_flag();
		tsc = tsc_read() + tsc_sync_tick_delta[CPU->cpu_id];
		restore_int_flag(flags);

		/* See comments in tsc_gethrtime() above */

		if (tsc >= tsc_last) {
			tsc -= tsc_last;
		} else if (tsc >= tsc_last - 2 * tsc_max_delta) {
			tsc = 0;
		}

		hrt = tsc_hrtime_base;

		TSC_CONVERT_AND_ADD(tsc, hrt, nsec_scale);
	} while ((old_hres_lock & ~1) != hres_lock);

	return (hrt);
}

/*
 * This is similar to the above, but it cannot actually spin on hres_lock.
 * As a result, it caches all of the variables it needs; if the variables
 * don't change, it's done.
 */
hrtime_t
dtrace_gethrtime(void)
{
	uint32_t old_hres_lock;
	hrtime_t tsc, hrt;
	ulong_t flags;

	do {
		old_hres_lock = hres_lock;

		/*
		 * Interrupts are disabled to ensure that the thread isn't
		 * migrated between the tsc_read() and adding the CPU's
		 * TSC tick delta.
		 */
		flags = clear_int_flag();

		tsc = tsc_read();

		if (gethrtimef == tsc_gethrtime_delta)
			tsc += tsc_sync_tick_delta[CPU->cpu_id];

		restore_int_flag(flags);

		/*
		 * See the comments in tsc_gethrtime(), above.
		 */
		if (tsc >= tsc_last)
			tsc -= tsc_last;
		else if (tsc >= tsc_last - 2*tsc_max_delta)
			tsc = 0;

		hrt = tsc_hrtime_base;

		TSC_CONVERT_AND_ADD(tsc, hrt, nsec_scale);

		if ((old_hres_lock & ~1) == hres_lock)
			break;

		/*
		 * If we're here, the clock lock is locked -- or it has been
		 * unlocked and locked since we looked.  This may be due to
		 * tsc_tick() running on another CPU -- or it may be because
		 * some code path has ended up in dtrace_probe() with
		 * CLOCK_LOCK held.  We'll try to determine that we're in
		 * the former case by taking another lap if the lock has
		 * changed since when we first looked at it.
		 */
		if (old_hres_lock != hres_lock)
			continue;

		/*
		 * So the lock was and is locked.  We'll use the old data
		 * instead.
		 */
		old_hres_lock = shadow_hres_lock;

		/*
		 * Again, disable interrupts to ensure that the thread
		 * isn't migrated between the tsc_read() and adding
		 * the CPU's TSC tick delta.
		 */
		flags = clear_int_flag();

		tsc = tsc_read();

		if (gethrtimef == tsc_gethrtime_delta)
			tsc += tsc_sync_tick_delta[CPU->cpu_id];

		restore_int_flag(flags);

		/*
		 * See the comments in tsc_gethrtime(), above.
		 */
		if (tsc >= shadow_tsc_last)
			tsc -= shadow_tsc_last;
		else if (tsc >= shadow_tsc_last - 2 * tsc_max_delta)
			tsc = 0;

		hrt = shadow_tsc_hrtime_base;

		TSC_CONVERT_AND_ADD(tsc, hrt, shadow_nsec_scale);
	} while ((old_hres_lock & ~1) != shadow_hres_lock);

	return (hrt);
}

hrtime_t
tsc_gethrtimeunscaled(void)
{
	uint32_t old_hres_lock;
	hrtime_t tsc;

	do {
		old_hres_lock = hres_lock;

		/* See tsc_tick(). */
		tsc = tsc_read() + tsc_last_jumped;
	} while ((old_hres_lock & ~1) != hres_lock);

	return (tsc);
}

/*
 * Convert a nanosecond based timestamp to tsc
 */
uint64_t
tsc_unscalehrtime(hrtime_t nsec)
{
	hrtime_t tsc;

	if (tsc_gethrtime_enable) {
		TSC_CONVERT(nsec, tsc, nsec_unscale);
		return (tsc);
	}
	return ((uint64_t)nsec);
}

/* Convert a tsc timestamp to nanoseconds */
void
tsc_scalehrtime(hrtime_t *tsc)
{
	hrtime_t hrt;
	hrtime_t mytsc;

	if (tsc == NULL)
		return;
	mytsc = *tsc;

	TSC_CONVERT(mytsc, hrt, nsec_scale);
	*tsc  = hrt;
}

hrtime_t
tsc_gethrtimeunscaled_delta(void)
{
	hrtime_t hrt;
	ulong_t flags;

	/*
	 * Similarly to tsc_gethrtime_delta, we need to disable preemption
	 * to prevent migration between the call to tsc_gethrtimeunscaled
	 * and adding the CPU's hrtime delta. Note that disabling and
	 * reenabling preemption is forbidden here because we may be in the
	 * middle of a fast trap. In the amd64 kernel we cannot tolerate
	 * preemption during a fast trap. See _update_sregs().
	 */

	flags = clear_int_flag();
	hrt = tsc_gethrtimeunscaled() + tsc_sync_tick_delta[CPU->cpu_id];
	restore_int_flag(flags);

	return (hrt);
}

/*
 * Called by the master in the TSC sync operation (usually the boot CPU).
 * If the slave is discovered to have a skew, gethrtimef will be changed to
 * point to tsc_gethrtime_delta(). Calculating skews is precise only when
 * the master and slave TSCs are read simultaneously; however, there is no
 * algorithm that can read both CPUs in perfect simultaneity. The proposed
 * algorithm is an approximate method based on the behaviour of cache
 * management. The slave CPU continuously reads TSC and then reads a global
 * variable which the master CPU updates. The moment the master's update reaches
 * the slave's visibility (being forced by an mfence operation) we use the TSC
 * reading taken on the slave. A corresponding TSC read will be taken on the
 * master as soon as possible after finishing the mfence operation. But the
 * delay between causing the slave to notice the invalid cache line and the
 * competion of mfence is not repeatable. This error is heuristically assumed
 * to be 1/4th of the total write time as being measured by the two TSC reads
 * on the master sandwiching the mfence. Furthermore, due to the nature of
 * bus arbitration, contention on memory bus, etc., the time taken for the write
 * to reflect globally can vary a lot. So instead of taking a single reading,
 * a set of readings are taken and the one with least write time is chosen
 * to calculate the final skew.
 *
 * TSC sync is disabled in the context of virtualization because the CPUs
 * assigned to the guest are virtual CPUs which means the real CPUs on which
 * guest runs keep changing during life time of guest OS. So we would end up
 * calculating TSC skews for a set of CPUs during boot whereas the guest
 * might migrate to a different set of physical CPUs at a later point of
 * time.
 */
void
tsc_sync_master(processorid_t slave)
{
	ulong_t flags, source, min_write_time = ~0UL;
	hrtime_t write_time, x, mtsc_after, tdelta;
	tsc_sync_t *tsc = tscp;
	int cnt;
	int hwtype;

	hwtype = get_hwenv();
	if (!tsc_master_slave_sync_needed || (hwtype & HW_VIRTUAL) != 0)
		return;

	flags = clear_int_flag();
	source = CPU->cpu_id;

	for (cnt = 0; cnt < SYNC_ITERATIONS; cnt++) {
		while (tsc_sync_go != TSC_SYNC_GO)
			SMT_PAUSE();

		tsc->master_tsc = tsc_read();
		membar_enter();
		mtsc_after = tsc_read();
		while (tsc_sync_go != TSC_SYNC_DONE)
			SMT_PAUSE();
		write_time =  mtsc_after - tsc->master_tsc;
		if (write_time <= min_write_time) {
			min_write_time = write_time;
			/*
			 * Apply heuristic adjustment only if the calculated
			 * delta is > 1/4th of the write time.
			 */
			x = tsc->slave_tsc - mtsc_after;
			if (x < 0)
				x = -x;
			if (x > (min_write_time/4))
				/*
				 * Subtract 1/4th of the measured write time
				 * from the master's TSC value, as an estimate
				 * of how late the mfence completion came
				 * after the slave noticed the cache line
				 * change.
				 */
				tdelta = tsc->slave_tsc -
				    (mtsc_after - (min_write_time/4));
			else
				tdelta = tsc->slave_tsc - mtsc_after;
			tsc_sync_tick_delta[slave] =
			    tsc_sync_tick_delta[source] - tdelta;
		}

		tsc->master_tsc = tsc->slave_tsc = write_time = 0;
		membar_enter();
		tsc_sync_go = TSC_SYNC_STOP;
	}
	if (tdelta < 0)
		tdelta = -tdelta;
	if (tdelta > largest_tsc_delta)
		largest_tsc_delta = tdelta;
	if (min_write_time < shortest_write_time)
		shortest_write_time = min_write_time;
	/*
	 * Enable delta variants of tsc functions if the largest of all chosen
	 * deltas is > smallest of the write time.
	 */
	if (largest_tsc_delta > shortest_write_time) {
		gethrtimef = tsc_gethrtime_delta;
		gethrtimeunscaledf = tsc_gethrtimeunscaled_delta;
	}
	restore_int_flag(flags);
}

/*
 * Called by a CPU which has just been onlined.  It is expected that the CPU
 * performing the online operation will call tsc_sync_master().
 *
 * TSC sync is disabled in the context of virtualization. See comments
 * above tsc_sync_master.
 */
void
tsc_sync_slave(void)
{
	ulong_t flags;
	hrtime_t s1;
	tsc_sync_t *tsc = tscp;
	int cnt;
	int hwtype;

	hwtype = get_hwenv();
	if (!tsc_master_slave_sync_needed || (hwtype & HW_VIRTUAL) != 0)
		return;

	flags = clear_int_flag();

	for (cnt = 0; cnt < SYNC_ITERATIONS; cnt++) {
		/* Re-fill the cache line */
		s1 = tsc->master_tsc;
		membar_enter();
		tsc_sync_go = TSC_SYNC_GO;
		do {
			/*
			 * Do not put an SMT_PAUSE here. For instance,
			 * if the master and slave are really the same
			 * hyper-threaded CPU, then you want the master
			 * to yield to the slave as quickly as possible here,
			 * but not the other way.
			 */
			s1 = tsc_read();
		} while (tsc->master_tsc == 0);
		tsc->slave_tsc = s1;
		membar_enter();
		tsc_sync_go = TSC_SYNC_DONE;

		while (tsc_sync_go != TSC_SYNC_STOP)
			SMT_PAUSE();
	}

	restore_int_flag(flags);
}

/*
 * Called once per second on a CPU from the cyclic subsystem's
 * CY_HIGH_LEVEL interrupt.  (No longer just cpu0-only)
 */
void
tsc_tick(void)
{
	hrtime_t now, delta;
	ushort_t spl;

	/*
	 * Before we set the new variables, we set the shadow values.  This
	 * allows for lock free operation in dtrace_gethrtime().
	 */
	lock_set_spl((lock_t *)&shadow_hres_lock + HRES_LOCK_OFFSET,
	    ipltospl(CBE_HIGH_PIL), &spl);

	shadow_tsc_hrtime_base = tsc_hrtime_base;
	shadow_tsc_last = tsc_last;
	shadow_nsec_scale = nsec_scale;

	shadow_hres_lock++;
	splx(spl);

	CLOCK_LOCK(&spl);

	now = tsc_read();

	if (gethrtimef == tsc_gethrtime_delta)
		now += tsc_sync_tick_delta[CPU->cpu_id];

	if (now < tsc_last) {
		/*
		 * The TSC has just jumped into the past.  We assume that
		 * this is due to a suspend/resume cycle, and we're going
		 * to use the _current_ value of TSC as the delta.  This
		 * will keep tsc_hrtime_base correct.  We're also going to
		 * assume that rate of tsc does not change after a suspend
		 * resume (i.e nsec_scale remains the same).
		 */
		delta = now;
		tsc_last_jumped += tsc_last;
		tsc_jumped = 1;
	} else {
		/*
		 * Determine the number of TSC ticks since the last clock
		 * tick, and add that to the hrtime base.
		 */
		delta = now - tsc_last;
	}

	TSC_CONVERT_AND_ADD(delta, tsc_hrtime_base, nsec_scale);
	tsc_last = now;

	CLOCK_UNLOCK(spl);
}

void
tsc_hrtimeinit(uint64_t cpu_freq_hz)
{
	extern int gethrtime_hires;
	longlong_t tsc;
	ulong_t flags;

	/*
	 * cpu_freq_hz is the measured cpu frequency in hertz
	 */

	/*
	 * We can't accommodate CPUs slower than 31.25 MHz.
	 */
	ASSERT(cpu_freq_hz > NANOSEC / (1 << NSEC_SHIFT));
	nsec_scale =
	    (uint_t)(((uint64_t)NANOSEC << (32 - NSEC_SHIFT)) / cpu_freq_hz);
	nsec_unscale =
	    (uint_t)(((uint64_t)cpu_freq_hz << (32 - NSEC_SHIFT)) / NANOSEC);

	flags = clear_int_flag();
	tsc = tsc_read();
	(void) tsc_gethrtime();
	tsc_max_delta = tsc_read() - tsc;
	restore_int_flag(flags);
	gethrtimef = tsc_gethrtime;
	gethrtimeunscaledf = tsc_gethrtimeunscaled;
	scalehrtimef = tsc_scalehrtime;
	unscalehrtimef = tsc_unscalehrtime;
	hrtime_tick = tsc_tick;
	gethrtime_hires = 1;
	/*
	 * Allocate memory for the structure used in the tsc sync logic.
	 * This structure should be aligned on a multiple of cache line size.
	 */
	tscp = kmem_zalloc(PAGESIZE, KM_SLEEP);
}

int
get_tsc_ready()
{
	return (tsc_ready);
}

/*
 * Adjust all the deltas by adding the passed value to the array.
 * Then use the "delt" versions of the the gethrtime functions.
 * Note that 'tdelta' _could_ be a negative number, which should
 * reduce the values in the array (used, for example, if the Solaris
 * instance was moved by a virtual manager to a machine with a higher
 * value of tsc).
 */
void
tsc_adjust_delta(hrtime_t tdelta)
{
	int		i;

	for (i = 0; i < NCPU; i++) {
		tsc_sync_tick_delta[i] += tdelta;
	}

	gethrtimef = tsc_gethrtime_delta;
	gethrtimeunscaledf = tsc_gethrtimeunscaled_delta;
}

/*
 * Functions to manage TSC and high-res time on suspend and resume.
 */

/*
 * declarations needed for time adjustment
 */
extern void	rtcsync(void);
extern tod_ops_t *tod_ops;
/* There must be a better way than exposing nsec_scale! */
extern uint_t	nsec_scale;
static uint64_t tsc_saved_tsc = 0; /* 1 in 2^64 chance this'll screw up! */
static timestruc_t tsc_saved_ts;
static int	tsc_needs_resume = 0;	/* We only want to do this once. */
int		tsc_delta_onsuspend = 0;
int		tsc_adjust_seconds = 1;
int		tsc_suspend_count = 0;
int		tsc_resume_in_cyclic = 0;

/*
 * Let timestamp.c know that we are suspending.  It needs to take
 * snapshots of the current time, and do any pre-suspend work.
 */
void
tsc_suspend(void)
{
/*
 * What we need to do here, is to get the time we suspended, so that we
 * know how much we should add to the resume.
 * This routine is called by each CPU, so we need to handle reentry.
 */
	if (tsc_gethrtime_enable) {
		/*
		 * We put the tsc_read() inside the lock as it
		 * as no locking constraints, and it puts the
		 * aquired value closer to the time stamp (in
		 * case we delay getting the lock).
		 */
		mutex_enter(&tod_lock);
		tsc_saved_tsc = tsc_read();
		tsc_saved_ts = TODOP_GET(tod_ops);
		mutex_exit(&tod_lock);
		/* We only want to do this once. */
		if (tsc_needs_resume == 0) {
			if (tsc_delta_onsuspend) {
				tsc_adjust_delta(tsc_saved_tsc);
			} else {
				tsc_adjust_delta(nsec_scale);
			}
			tsc_suspend_count++;
		}
	}

	invalidate_cache();
	tsc_needs_resume = 1;
}

/*
 * Restore all timestamp state based on the snapshots taken at
 * suspend time.
 */
void
tsc_resume(void)
{
	/*
	 * We only need to (and want to) do this once.  So let the first
	 * caller handle this (we are locked by the cpu lock), as it
	 * is preferential that we get the earliest sync.
	 */
	if (tsc_needs_resume) {
		/*
		 * If using the TSC, adjust the delta based on how long
		 * we were sleeping (or away).  We also adjust for
		 * migration and a grown TSC.
		 */
		if (tsc_saved_tsc != 0) {
			timestruc_t	ts;
			hrtime_t	now, sleep_tsc = 0;
			int		sleep_sec;
			extern void	tsc_tick(void);
			extern uint64_t cpu_freq_hz;

			/* tsc_read() MUST be before TODOP_GET() */
			mutex_enter(&tod_lock);
			now = tsc_read();
			ts = TODOP_GET(tod_ops);
			mutex_exit(&tod_lock);

			/* Compute seconds of sleep time */
			sleep_sec = ts.tv_sec - tsc_saved_ts.tv_sec;

			/*
			 * If the saved sec is less that or equal to
			 * the current ts, then there is likely a
			 * problem with the clock.  Assume at least
			 * one second has passed, so that time goes forward.
			 */
			if (sleep_sec <= 0) {
				sleep_sec = 1;
			}

			/* How many TSC's should have occured while sleeping */
			if (tsc_adjust_seconds)
				sleep_tsc = sleep_sec * cpu_freq_hz;

			/*
			 * We also want to subtract from the "sleep_tsc"
			 * the current value of tsc_read(), so that our
			 * adjustment accounts for the amount of time we
			 * have been resumed _or_ an adjustment based on
			 * the fact that we didn't actually power off the
			 * CPU (migration is another issue, but _should_
			 * also comply with this calculation).  If the CPU
			 * never powered off, then:
			 *    'now == sleep_tsc + saved_tsc'
			 * and the delta will effectively be "0".
			 */
			sleep_tsc -= now;
			if (tsc_delta_onsuspend) {
				tsc_adjust_delta(sleep_tsc);
			} else {
				tsc_adjust_delta(tsc_saved_tsc + sleep_tsc);
			}
			tsc_saved_tsc = 0;

			tsc_tick();
		}
		tsc_needs_resume = 0;
	}

}
