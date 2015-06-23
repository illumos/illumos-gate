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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/types.h>
#include <sys/tuneable.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/lgrp.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/callo.h>
#include <sys/kmem.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/swap.h>
#include <sys/vmsystm.h>
#include <sys/class.h>
#include <sys/time.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/spl.h>
#include <sys/atomic.h>
#include <sys/dumphdr.h>
#include <sys/archsystm.h>
#include <sys/fs/swapnode.h>
#include <sys/panic.h>
#include <sys/disp.h>
#include <sys/msacct.h>
#include <sys/mem_cage.h>

#include <vm/page.h>
#include <vm/anon.h>
#include <vm/rm.h>
#include <sys/cyclic.h>
#include <sys/cpupart.h>
#include <sys/rctl.h>
#include <sys/task.h>
#include <sys/sdt.h>
#include <sys/ddi_periodic.h>
#include <sys/random.h>
#include <sys/modctl.h>
#include <sys/zone.h>

/*
 * for NTP support
 */
#include <sys/timex.h>
#include <sys/inttypes.h>

#include <sys/sunddi.h>
#include <sys/clock_impl.h>

/*
 * clock() is called straight from the clock cyclic; see clock_init().
 *
 * Functions:
 *	reprime clock
 *	maintain date
 *	jab the scheduler
 */

extern kcondvar_t	fsflush_cv;
extern sysinfo_t	sysinfo;
extern vminfo_t	vminfo;
extern int	idleswtch;	/* flag set while idle in pswtch() */
extern hrtime_t volatile devinfo_freeze;

/*
 * high-precision avenrun values.  These are needed to make the
 * regular avenrun values accurate.
 */
static uint64_t hp_avenrun[3];
int	avenrun[3];		/* FSCALED average run queue lengths */
time_t	time;	/* time in seconds since 1970 - for compatibility only */

static struct loadavg_s loadavg;
/*
 * Phase/frequency-lock loop (PLL/FLL) definitions
 *
 * The following variables are read and set by the ntp_adjtime() system
 * call.
 *
 * time_state shows the state of the system clock, with values defined
 * in the timex.h header file.
 *
 * time_status shows the status of the system clock, with bits defined
 * in the timex.h header file.
 *
 * time_offset is used by the PLL/FLL to adjust the system time in small
 * increments.
 *
 * time_constant determines the bandwidth or "stiffness" of the PLL.
 *
 * time_tolerance determines maximum frequency error or tolerance of the
 * CPU clock oscillator and is a property of the architecture; however,
 * in principle it could change as result of the presence of external
 * discipline signals, for instance.
 *
 * time_precision is usually equal to the kernel tick variable; however,
 * in cases where a precision clock counter or external clock is
 * available, the resolution can be much less than this and depend on
 * whether the external clock is working or not.
 *
 * time_maxerror is initialized by a ntp_adjtime() call and increased by
 * the kernel once each second to reflect the maximum error bound
 * growth.
 *
 * time_esterror is set and read by the ntp_adjtime() call, but
 * otherwise not used by the kernel.
 */
int32_t time_state = TIME_OK;	/* clock state */
int32_t time_status = STA_UNSYNC;	/* clock status bits */
int32_t time_offset = 0;		/* time offset (us) */
int32_t time_constant = 0;		/* pll time constant */
int32_t time_tolerance = MAXFREQ;	/* frequency tolerance (scaled ppm) */
int32_t time_precision = 1;	/* clock precision (us) */
int32_t time_maxerror = MAXPHASE;	/* maximum error (us) */
int32_t time_esterror = MAXPHASE;	/* estimated error (us) */

/*
 * The following variables establish the state of the PLL/FLL and the
 * residual time and frequency offset of the local clock. The scale
 * factors are defined in the timex.h header file.
 *
 * time_phase and time_freq are the phase increment and the frequency
 * increment, respectively, of the kernel time variable.
 *
 * time_freq is set via ntp_adjtime() from a value stored in a file when
 * the synchronization daemon is first started. Its value is retrieved
 * via ntp_adjtime() and written to the file about once per hour by the
 * daemon.
 *
 * time_adj is the adjustment added to the value of tick at each timer
 * interrupt and is recomputed from time_phase and time_freq at each
 * seconds rollover.
 *
 * time_reftime is the second's portion of the system time at the last
 * call to ntp_adjtime(). It is used to adjust the time_freq variable
 * and to increase the time_maxerror as the time since last update
 * increases.
 */
int32_t time_phase = 0;		/* phase offset (scaled us) */
int32_t time_freq = 0;		/* frequency offset (scaled ppm) */
int32_t time_adj = 0;		/* tick adjust (scaled 1 / hz) */
int32_t time_reftime = 0;		/* time at last adjustment (s) */

/*
 * The scale factors of the following variables are defined in the
 * timex.h header file.
 *
 * pps_time contains the time at each calibration interval, as read by
 * microtime(). pps_count counts the seconds of the calibration
 * interval, the duration of which is nominally pps_shift in powers of
 * two.
 *
 * pps_offset is the time offset produced by the time median filter
 * pps_tf[], while pps_jitter is the dispersion (jitter) measured by
 * this filter.
 *
 * pps_freq is the frequency offset produced by the frequency median
 * filter pps_ff[], while pps_stabil is the dispersion (wander) measured
 * by this filter.
 *
 * pps_usec is latched from a high resolution counter or external clock
 * at pps_time. Here we want the hardware counter contents only, not the
 * contents plus the time_tv.usec as usual.
 *
 * pps_valid counts the number of seconds since the last PPS update. It
 * is used as a watchdog timer to disable the PPS discipline should the
 * PPS signal be lost.
 *
 * pps_glitch counts the number of seconds since the beginning of an
 * offset burst more than tick/2 from current nominal offset. It is used
 * mainly to suppress error bursts due to priority conflicts between the
 * PPS interrupt and timer interrupt.
 *
 * pps_intcnt counts the calibration intervals for use in the interval-
 * adaptation algorithm. It's just too complicated for words.
 */
struct timeval pps_time;	/* kernel time at last interval */
int32_t pps_tf[] = {0, 0, 0};	/* pps time offset median filter (us) */
int32_t pps_offset = 0;		/* pps time offset (us) */
int32_t pps_jitter = MAXTIME;	/* time dispersion (jitter) (us) */
int32_t pps_ff[] = {0, 0, 0};	/* pps frequency offset median filter */
int32_t pps_freq = 0;		/* frequency offset (scaled ppm) */
int32_t pps_stabil = MAXFREQ;	/* frequency dispersion (scaled ppm) */
int32_t pps_usec = 0;		/* microsec counter at last interval */
int32_t pps_valid = PPS_VALID;	/* pps signal watchdog counter */
int32_t pps_glitch = 0;		/* pps signal glitch counter */
int32_t pps_count = 0;		/* calibration interval counter (s) */
int32_t pps_shift = PPS_SHIFT;	/* interval duration (s) (shift) */
int32_t pps_intcnt = 0;		/* intervals at current duration */

/*
 * PPS signal quality monitors
 *
 * pps_jitcnt counts the seconds that have been discarded because the
 * jitter measured by the time median filter exceeds the limit MAXTIME
 * (100 us).
 *
 * pps_calcnt counts the frequency calibration intervals, which are
 * variable from 4 s to 256 s.
 *
 * pps_errcnt counts the calibration intervals which have been discarded
 * because the wander exceeds the limit MAXFREQ (100 ppm) or where the
 * calibration interval jitter exceeds two ticks.
 *
 * pps_stbcnt counts the calibration intervals that have been discarded
 * because the frequency wander exceeds the limit MAXFREQ / 4 (25 us).
 */
int32_t pps_jitcnt = 0;		/* jitter limit exceeded */
int32_t pps_calcnt = 0;		/* calibration intervals */
int32_t pps_errcnt = 0;		/* calibration errors */
int32_t pps_stbcnt = 0;		/* stability limit exceeded */

kcondvar_t lbolt_cv;

/*
 * Hybrid lbolt implementation:
 *
 * The service historically provided by the lbolt and lbolt64 variables has
 * been replaced by the ddi_get_lbolt() and ddi_get_lbolt64() routines, and the
 * original symbols removed from the system. The once clock driven variables are
 * now implemented in an event driven fashion, backed by gethrtime() coarsed to
 * the appropriate clock resolution. The default event driven implementation is
 * complemented by a cyclic driven one, active only during periods of intense
 * activity around the DDI lbolt routines, when a lbolt specific cyclic is
 * reprogramed to fire at a clock tick interval to serve consumers of lbolt who
 * rely on the original low cost of consulting a memory position.
 *
 * The implementation uses the number of calls to these routines and the
 * frequency of these to determine when to transition from event to cyclic
 * driven and vice-versa. These values are kept on a per CPU basis for
 * scalability reasons and to prevent CPUs from constantly invalidating a single
 * cache line when modifying a global variable. The transition from event to
 * cyclic mode happens once the thresholds are crossed, and activity on any CPU
 * can cause such transition.
 *
 * The lbolt_hybrid function pointer is called by ddi_get_lbolt() and
 * ddi_get_lbolt64(), and will point to lbolt_event_driven() or
 * lbolt_cyclic_driven() according to the current mode. When the thresholds
 * are exceeded, lbolt_event_driven() will reprogram the lbolt cyclic to
 * fire at a nsec_per_tick interval and increment an internal variable at
 * each firing. lbolt_hybrid will then point to lbolt_cyclic_driven(), which
 * will simply return the value of such variable. lbolt_cyclic() will attempt
 * to shut itself off at each threshold interval (sampling period for calls
 * to the DDI lbolt routines), and return to the event driven mode, but will
 * be prevented from doing so if lbolt_cyclic_driven() is being heavily used.
 *
 * lbolt_bootstrap is used during boot to serve lbolt consumers who don't wait
 * for the cyclic subsystem to be intialized.
 *
 */
int64_t lbolt_bootstrap(void);
int64_t lbolt_event_driven(void);
int64_t lbolt_cyclic_driven(void);
int64_t (*lbolt_hybrid)(void) = lbolt_bootstrap;
uint_t lbolt_ev_to_cyclic(caddr_t, caddr_t);

/*
 * lbolt's cyclic, installed by clock_init().
 */
static void lbolt_cyclic(void);

/*
 * Tunable to keep lbolt in cyclic driven mode. This will prevent the system
 * from switching back to event driven, once it reaches cyclic mode.
 */
static boolean_t lbolt_cyc_only = B_FALSE;

/*
 * Cache aligned, per CPU structure with lbolt usage statistics.
 */
static lbolt_cpu_t *lb_cpu;

/*
 * Single, cache aligned, structure with all the information required by
 * the lbolt implementation.
 */
lbolt_info_t *lb_info;


int one_sec = 1; /* turned on once every second */
static int fsflushcnt;	/* counter for t_fsflushr */
int	dosynctodr = 1;	/* patchable; enable/disable sync to TOD chip */
int	tod_needsync = 0;	/* need to sync tod chip with software time */
static int tod_broken = 0;	/* clock chip doesn't work */
time_t	boot_time = 0;		/* Boot time in seconds since 1970 */
cyclic_id_t clock_cyclic;	/* clock()'s cyclic_id */
cyclic_id_t deadman_cyclic;	/* deadman()'s cyclic_id */

extern void	clock_tick_schedule(int);

static int lgrp_ticks;		/* counter to schedule lgrp load calcs */

/*
 * for tod fault detection
 */
#define	TOD_REF_FREQ		((longlong_t)(NANOSEC))
#define	TOD_STALL_THRESHOLD	(TOD_REF_FREQ * 3 / 2)
#define	TOD_JUMP_THRESHOLD	(TOD_REF_FREQ / 2)
#define	TOD_FILTER_N		4
#define	TOD_FILTER_SETTLE	(4 * TOD_FILTER_N)
static enum tod_fault_type tod_faulted = TOD_NOFAULT;

static int tod_status_flag = 0;		/* used by tod_validate() */

static hrtime_t prev_set_tick = 0;	/* gethrtime() prior to tod_set() */
static time_t prev_set_tod = 0;		/* tv_sec value passed to tod_set() */

/* patchable via /etc/system */
int tod_validate_enable = 1;

/* Diagnose/Limit messages about delay(9F) called from interrupt context */
int			delay_from_interrupt_diagnose = 0;
volatile uint32_t	delay_from_interrupt_msg = 20;

/*
 * On non-SPARC systems, TOD validation must be deferred until gethrtime
 * returns non-zero values (after mach_clkinit's execution).
 * On SPARC systems, it must be deferred until after hrtime_base
 * and hres_last_tick are set (in the first invocation of hres_tick).
 * Since in both cases the prerequisites occur before the invocation of
 * tod_get() in clock(), the deferment is lifted there.
 */
static boolean_t tod_validate_deferred = B_TRUE;

/*
 * tod_fault_table[] must be aligned with
 * enum tod_fault_type in systm.h
 */
static char *tod_fault_table[] = {
	"Reversed",			/* TOD_REVERSED */
	"Stalled",			/* TOD_STALLED */
	"Jumped",			/* TOD_JUMPED */
	"Changed in Clock Rate",	/* TOD_RATECHANGED */
	"Is Read-Only"			/* TOD_RDONLY */
	/*
	 * no strings needed for TOD_NOFAULT
	 */
};

/*
 * test hook for tod broken detection in tod_validate
 */
int tod_unit_test = 0;
time_t tod_test_injector;

#define	CLOCK_ADJ_HIST_SIZE	4

static int	adj_hist_entry;

int64_t clock_adj_hist[CLOCK_ADJ_HIST_SIZE];

static void calcloadavg(int, uint64_t *);
static int genloadavg(struct loadavg_s *);
static void loadavg_update();

void (*cmm_clock_callout)() = NULL;
void (*cpucaps_clock_callout)() = NULL;

extern clock_t clock_tick_proc_max;

static int64_t deadman_counter = 0;

static void
clock(void)
{
	kthread_t	*t;
	uint_t	nrunnable;
	uint_t	w_io;
	cpu_t	*cp;
	cpupart_t *cpupart;
	extern	void	set_freemem();
	void	(*funcp)();
	int32_t ltemp;
	int64_t lltemp;
	int s;
	int do_lgrp_load;
	int i;
	clock_t now = LBOLT_NO_ACCOUNT;	/* current tick */

	if (panicstr)
		return;

	/*
	 * Make sure that 'freemem' do not drift too far from the truth
	 */
	set_freemem();


	/*
	 * Before the section which is repeated is executed, we do
	 * the time delta processing which occurs every clock tick
	 *
	 * There is additional processing which happens every time
	 * the nanosecond counter rolls over which is described
	 * below - see the section which begins with : if (one_sec)
	 *
	 * This section marks the beginning of the precision-kernel
	 * code fragment.
	 *
	 * First, compute the phase adjustment. If the low-order bits
	 * (time_phase) of the update overflow, bump the higher order
	 * bits (time_update).
	 */
	time_phase += time_adj;
	if (time_phase <= -FINEUSEC) {
		ltemp = -time_phase / SCALE_PHASE;
		time_phase += ltemp * SCALE_PHASE;
		s = hr_clock_lock();
		timedelta -= ltemp * (NANOSEC/MICROSEC);
		hr_clock_unlock(s);
	} else if (time_phase >= FINEUSEC) {
		ltemp = time_phase / SCALE_PHASE;
		time_phase -= ltemp * SCALE_PHASE;
		s = hr_clock_lock();
		timedelta += ltemp * (NANOSEC/MICROSEC);
		hr_clock_unlock(s);
	}

	/*
	 * End of precision-kernel code fragment which is processed
	 * every timer interrupt.
	 *
	 * Continue with the interrupt processing as scheduled.
	 */
	/*
	 * Count the number of runnable threads and the number waiting
	 * for some form of I/O to complete -- gets added to
	 * sysinfo.waiting.  To know the state of the system, must add
	 * wait counts from all CPUs.  Also add up the per-partition
	 * statistics.
	 */
	w_io = 0;
	nrunnable = 0;

	/*
	 * keep track of when to update lgrp/part loads
	 */

	do_lgrp_load = 0;
	if (lgrp_ticks++ >= hz / 10) {
		lgrp_ticks = 0;
		do_lgrp_load = 1;
	}

	if (one_sec) {
		loadavg_update();
		deadman_counter++;
	}

	/*
	 * First count the threads waiting on kpreempt queues in each
	 * CPU partition.
	 */

	cpupart = cp_list_head;
	do {
		uint_t cpupart_nrunnable = cpupart->cp_kp_queue.disp_nrunnable;

		cpupart->cp_updates++;
		nrunnable += cpupart_nrunnable;
		cpupart->cp_nrunnable_cum += cpupart_nrunnable;
		if (one_sec) {
			cpupart->cp_nrunning = 0;
			cpupart->cp_nrunnable = cpupart_nrunnable;
		}
	} while ((cpupart = cpupart->cp_next) != cp_list_head);


	/* Now count the per-CPU statistics. */
	cp = cpu_list;
	do {
		uint_t cpu_nrunnable = cp->cpu_disp->disp_nrunnable;

		nrunnable += cpu_nrunnable;
		cpupart = cp->cpu_part;
		cpupart->cp_nrunnable_cum += cpu_nrunnable;
		if (one_sec) {
			cpupart->cp_nrunnable += cpu_nrunnable;
			/*
			 * Update user, system, and idle cpu times.
			 */
			cpupart->cp_nrunning++;
			/*
			 * w_io is used to update sysinfo.waiting during
			 * one_second processing below.  Only gather w_io
			 * information when we walk the list of cpus if we're
			 * going to perform one_second processing.
			 */
			w_io += CPU_STATS(cp, sys.iowait);
		}

		if (one_sec && (cp->cpu_flags & CPU_EXISTS)) {
			int i, load, change;
			hrtime_t intracct, intrused;
			const hrtime_t maxnsec = 1000000000;
			const int precision = 100;

			/*
			 * Estimate interrupt load on this cpu each second.
			 * Computes cpu_intrload as %utilization (0-99).
			 */

			/* add up interrupt time from all micro states */
			for (intracct = 0, i = 0; i < NCMSTATES; i++)
				intracct += cp->cpu_intracct[i];
			scalehrtime(&intracct);

			/* compute nsec used in the past second */
			intrused = intracct - cp->cpu_intrlast;
			cp->cpu_intrlast = intracct;

			/* limit the value for safety (and the first pass) */
			if (intrused >= maxnsec)
				intrused = maxnsec - 1;

			/* calculate %time in interrupt */
			load = (precision * intrused) / maxnsec;
			ASSERT(load >= 0 && load < precision);
			change = cp->cpu_intrload - load;

			/* jump to new max, or decay the old max */
			if (change < 0)
				cp->cpu_intrload = load;
			else if (change > 0)
				cp->cpu_intrload -= (change + 3) / 4;

			DTRACE_PROBE3(cpu_intrload,
			    cpu_t *, cp,
			    hrtime_t, intracct,
			    hrtime_t, intrused);
		}

		if (do_lgrp_load &&
		    (cp->cpu_flags & CPU_EXISTS)) {
			/*
			 * When updating the lgroup's load average,
			 * account for the thread running on the CPU.
			 * If the CPU is the current one, then we need
			 * to account for the underlying thread which
			 * got the clock interrupt not the thread that is
			 * handling the interrupt and caculating the load
			 * average
			 */
			t = cp->cpu_thread;
			if (CPU == cp)
				t = t->t_intr;

			/*
			 * Account for the load average for this thread if
			 * it isn't the idle thread or it is on the interrupt
			 * stack and not the current CPU handling the clock
			 * interrupt
			 */
			if ((t && t != cp->cpu_idle_thread) || (CPU != cp &&
			    CPU_ON_INTR(cp))) {
				if (t->t_lpl == cp->cpu_lpl) {
					/* local thread */
					cpu_nrunnable++;
				} else {
					/*
					 * This is a remote thread, charge it
					 * against its home lgroup.  Note that
					 * we notice that a thread is remote
					 * only if it's currently executing.
					 * This is a reasonable approximation,
					 * since queued remote threads are rare.
					 * Note also that if we didn't charge
					 * it to its home lgroup, remote
					 * execution would often make a system
					 * appear balanced even though it was
					 * not, and thread placement/migration
					 * would often not be done correctly.
					 */
					lgrp_loadavg(t->t_lpl,
					    LGRP_LOADAVG_IN_THREAD_MAX, 0);
				}
			}
			lgrp_loadavg(cp->cpu_lpl,
			    cpu_nrunnable * LGRP_LOADAVG_IN_THREAD_MAX, 1);
		}
	} while ((cp = cp->cpu_next) != cpu_list);

	clock_tick_schedule(one_sec);

	/*
	 * Check for a callout that needs be called from the clock
	 * thread to support the membership protocol in a clustered
	 * system.  Copy the function pointer so that we can reset
	 * this to NULL if needed.
	 */
	if ((funcp = cmm_clock_callout) != NULL)
		(*funcp)();

	if ((funcp = cpucaps_clock_callout) != NULL)
		(*funcp)();

	/*
	 * Wakeup the cageout thread waiters once per second.
	 */
	if (one_sec)
		kcage_tick();

	if (one_sec) {

		int drift, absdrift;
		timestruc_t tod;
		int s;

		/*
		 * Beginning of precision-kernel code fragment executed
		 * every second.
		 *
		 * On rollover of the second the phase adjustment to be
		 * used for the next second is calculated.  Also, the
		 * maximum error is increased by the tolerance.  If the
		 * PPS frequency discipline code is present, the phase is
		 * increased to compensate for the CPU clock oscillator
		 * frequency error.
		 *
		 * On a 32-bit machine and given parameters in the timex.h
		 * header file, the maximum phase adjustment is +-512 ms
		 * and maximum frequency offset is (a tad less than)
		 * +-512 ppm. On a 64-bit machine, you shouldn't need to ask.
		 */
		time_maxerror += time_tolerance / SCALE_USEC;

		/*
		 * Leap second processing. If in leap-insert state at
		 * the end of the day, the system clock is set back one
		 * second; if in leap-delete state, the system clock is
		 * set ahead one second. The microtime() routine or
		 * external clock driver will insure that reported time
		 * is always monotonic. The ugly divides should be
		 * replaced.
		 */
		switch (time_state) {

		case TIME_OK:
			if (time_status & STA_INS)
				time_state = TIME_INS;
			else if (time_status & STA_DEL)
				time_state = TIME_DEL;
			break;

		case TIME_INS:
			if (hrestime.tv_sec % 86400 == 0) {
				s = hr_clock_lock();
				hrestime.tv_sec--;
				hr_clock_unlock(s);
				time_state = TIME_OOP;
			}
			break;

		case TIME_DEL:
			if ((hrestime.tv_sec + 1) % 86400 == 0) {
				s = hr_clock_lock();
				hrestime.tv_sec++;
				hr_clock_unlock(s);
				time_state = TIME_WAIT;
			}
			break;

		case TIME_OOP:
			time_state = TIME_WAIT;
			break;

		case TIME_WAIT:
			if (!(time_status & (STA_INS | STA_DEL)))
				time_state = TIME_OK;
		default:
			break;
		}

		/*
		 * Compute the phase adjustment for the next second. In
		 * PLL mode, the offset is reduced by a fixed factor
		 * times the time constant. In FLL mode the offset is
		 * used directly. In either mode, the maximum phase
		 * adjustment for each second is clamped so as to spread
		 * the adjustment over not more than the number of
		 * seconds between updates.
		 */
		if (time_offset == 0)
			time_adj = 0;
		else if (time_offset < 0) {
			lltemp = -time_offset;
			if (!(time_status & STA_FLL)) {
				if ((1 << time_constant) >= SCALE_KG)
					lltemp *= (1 << time_constant) /
					    SCALE_KG;
				else
					lltemp = (lltemp / SCALE_KG) >>
					    time_constant;
			}
			if (lltemp > (MAXPHASE / MINSEC) * SCALE_UPDATE)
				lltemp = (MAXPHASE / MINSEC) * SCALE_UPDATE;
			time_offset += lltemp;
			time_adj = -(lltemp * SCALE_PHASE) / hz / SCALE_UPDATE;
		} else {
			lltemp = time_offset;
			if (!(time_status & STA_FLL)) {
				if ((1 << time_constant) >= SCALE_KG)
					lltemp *= (1 << time_constant) /
					    SCALE_KG;
				else
					lltemp = (lltemp / SCALE_KG) >>
					    time_constant;
			}
			if (lltemp > (MAXPHASE / MINSEC) * SCALE_UPDATE)
				lltemp = (MAXPHASE / MINSEC) * SCALE_UPDATE;
			time_offset -= lltemp;
			time_adj = (lltemp * SCALE_PHASE) / hz / SCALE_UPDATE;
		}

		/*
		 * Compute the frequency estimate and additional phase
		 * adjustment due to frequency error for the next
		 * second. When the PPS signal is engaged, gnaw on the
		 * watchdog counter and update the frequency computed by
		 * the pll and the PPS signal.
		 */
		pps_valid++;
		if (pps_valid == PPS_VALID) {
			pps_jitter = MAXTIME;
			pps_stabil = MAXFREQ;
			time_status &= ~(STA_PPSSIGNAL | STA_PPSJITTER |
			    STA_PPSWANDER | STA_PPSERROR);
		}
		lltemp = time_freq + pps_freq;

		if (lltemp)
			time_adj += (lltemp * SCALE_PHASE) / (SCALE_USEC * hz);

		/*
		 * End of precision kernel-code fragment
		 *
		 * The section below should be modified if we are planning
		 * to use NTP for synchronization.
		 *
		 * Note: the clock synchronization code now assumes
		 * the following:
		 *   - if dosynctodr is 1, then compute the drift between
		 *	the tod chip and software time and adjust one or
		 *	the other depending on the circumstances
		 *
		 *   - if dosynctodr is 0, then the tod chip is independent
		 *	of the software clock and should not be adjusted,
		 *	but allowed to free run.  this allows NTP to sync.
		 *	hrestime without any interference from the tod chip.
		 */

		tod_validate_deferred = B_FALSE;
		mutex_enter(&tod_lock);
		tod = tod_get();
		drift = tod.tv_sec - hrestime.tv_sec;
		absdrift = (drift >= 0) ? drift : -drift;
		if (tod_needsync || absdrift > 1) {
			int s;
			if (absdrift > 2) {
				if (!tod_broken && tod_faulted == TOD_NOFAULT) {
					s = hr_clock_lock();
					hrestime = tod;
					membar_enter();	/* hrestime visible */
					timedelta = 0;
					timechanged++;
					tod_needsync = 0;
					hr_clock_unlock(s);
					callout_hrestime();

				}
			} else {
				if (tod_needsync || !dosynctodr) {
					gethrestime(&tod);
					tod_set(tod);
					s = hr_clock_lock();
					if (timedelta == 0)
						tod_needsync = 0;
					hr_clock_unlock(s);
				} else {
					/*
					 * If the drift is 2 seconds on the
					 * money, then the TOD is adjusting
					 * the clock;  record that.
					 */
					clock_adj_hist[adj_hist_entry++ %
					    CLOCK_ADJ_HIST_SIZE] = now;
					s = hr_clock_lock();
					timedelta = (int64_t)drift*NANOSEC;
					hr_clock_unlock(s);
				}
			}
		}
		one_sec = 0;
		time = gethrestime_sec();  /* for crusty old kmem readers */
		mutex_exit(&tod_lock);

		/*
		 * Some drivers still depend on this... XXX
		 */
		cv_broadcast(&lbolt_cv);

		vminfo.freemem += freemem;
		{
			pgcnt_t maxswap, resv, free;
			pgcnt_t avail =
			    MAX((spgcnt_t)(availrmem - swapfs_minfree), 0);

			maxswap = k_anoninfo.ani_mem_resv +
			    k_anoninfo.ani_max +avail;
			/* Update ani_free */
			set_anoninfo();
			free = k_anoninfo.ani_free + avail;
			resv = k_anoninfo.ani_phys_resv +
			    k_anoninfo.ani_mem_resv;

			vminfo.swap_resv += resv;
			/* number of reserved and allocated pages */
#ifdef	DEBUG
			if (maxswap < free)
				cmn_err(CE_WARN, "clock: maxswap < free");
			if (maxswap < resv)
				cmn_err(CE_WARN, "clock: maxswap < resv");
#endif
			vminfo.swap_alloc += maxswap - free;
			vminfo.swap_avail += maxswap - resv;
			vminfo.swap_free += free;
		}
		vminfo.updates++;
		if (nrunnable) {
			sysinfo.runque += nrunnable;
			sysinfo.runocc++;
		}
		if (nswapped) {
			sysinfo.swpque += nswapped;
			sysinfo.swpocc++;
		}
		sysinfo.waiting += w_io;
		sysinfo.updates++;

		/*
		 * Wake up fsflush to write out DELWRI
		 * buffers, dirty pages and other cached
		 * administrative data, e.g. inodes.
		 */
		if (--fsflushcnt <= 0) {
			fsflushcnt = tune.t_fsflushr;
			cv_signal(&fsflush_cv);
		}

		vmmeter();
		calcloadavg(genloadavg(&loadavg), hp_avenrun);
		for (i = 0; i < 3; i++)
			/*
			 * At the moment avenrun[] can only hold 31
			 * bits of load average as it is a signed
			 * int in the API. We need to ensure that
			 * hp_avenrun[i] >> (16 - FSHIFT) will not be
			 * too large. If it is, we put the largest value
			 * that we can use into avenrun[i]. This is
			 * kludgey, but about all we can do until we
			 * avenrun[] is declared as an array of uint64[]
			 */
			if (hp_avenrun[i] < ((uint64_t)1<<(31+16-FSHIFT)))
				avenrun[i] = (int32_t)(hp_avenrun[i] >>
				    (16 - FSHIFT));
			else
				avenrun[i] = 0x7fffffff;

		cpupart = cp_list_head;
		do {
			calcloadavg(genloadavg(&cpupart->cp_loadavg),
			    cpupart->cp_hp_avenrun);
		} while ((cpupart = cpupart->cp_next) != cp_list_head);

		/*
		 * Wake up the swapper thread if necessary.
		 */
		if (runin ||
		    (runout && (avefree < desfree || wake_sched_sec))) {
			t = &t0;
			thread_lock(t);
			if (t->t_state == TS_STOPPED) {
				runin = runout = 0;
				wake_sched_sec = 0;
				t->t_whystop = 0;
				t->t_whatstop = 0;
				t->t_schedflag &= ~TS_ALLSTART;
				THREAD_TRANSITION(t);
				setfrontdq(t);
			}
			thread_unlock(t);
		}
	}

	/*
	 * Wake up the swapper if any high priority swapped-out threads
	 * became runable during the last tick.
	 */
	if (wake_sched) {
		t = &t0;
		thread_lock(t);
		if (t->t_state == TS_STOPPED) {
			runin = runout = 0;
			wake_sched = 0;
			t->t_whystop = 0;
			t->t_whatstop = 0;
			t->t_schedflag &= ~TS_ALLSTART;
			THREAD_TRANSITION(t);
			setfrontdq(t);
		}
		thread_unlock(t);
	}
}

void
clock_init(void)
{
	cyc_handler_t clk_hdlr, lbolt_hdlr;
	cyc_time_t clk_when, lbolt_when;
	int i, sz;
	intptr_t buf;

	/*
	 * Setup handler and timer for the clock cyclic.
	 */
	clk_hdlr.cyh_func = (cyc_func_t)clock;
	clk_hdlr.cyh_level = CY_LOCK_LEVEL;
	clk_hdlr.cyh_arg = NULL;

	clk_when.cyt_when = 0;
	clk_when.cyt_interval = nsec_per_tick;

	/*
	 * The lbolt cyclic will be reprogramed to fire at a nsec_per_tick
	 * interval to satisfy performance needs of the DDI lbolt consumers.
	 * It is off by default.
	 */
	lbolt_hdlr.cyh_func = (cyc_func_t)lbolt_cyclic;
	lbolt_hdlr.cyh_level = CY_LOCK_LEVEL;
	lbolt_hdlr.cyh_arg = NULL;

	lbolt_when.cyt_interval = nsec_per_tick;

	/*
	 * Allocate cache line aligned space for the per CPU lbolt data and
	 * lbolt info structures, and initialize them with their default
	 * values. Note that these structures are also cache line sized.
	 */
	sz = sizeof (lbolt_info_t) + CPU_CACHE_COHERENCE_SIZE;
	buf = (intptr_t)kmem_zalloc(sz, KM_SLEEP);
	lb_info = (lbolt_info_t *)P2ROUNDUP(buf, CPU_CACHE_COHERENCE_SIZE);

	if (hz != HZ_DEFAULT)
		lb_info->lbi_thresh_interval = LBOLT_THRESH_INTERVAL *
		    hz/HZ_DEFAULT;
	else
		lb_info->lbi_thresh_interval = LBOLT_THRESH_INTERVAL;

	lb_info->lbi_thresh_calls = LBOLT_THRESH_CALLS;

	sz = (sizeof (lbolt_cpu_t) * max_ncpus) + CPU_CACHE_COHERENCE_SIZE;
	buf = (intptr_t)kmem_zalloc(sz, KM_SLEEP);
	lb_cpu = (lbolt_cpu_t *)P2ROUNDUP(buf, CPU_CACHE_COHERENCE_SIZE);

	for (i = 0; i < max_ncpus; i++)
		lb_cpu[i].lbc_counter = lb_info->lbi_thresh_calls;

	/*
	 * Install the softint used to switch between event and cyclic driven
	 * lbolt. We use a soft interrupt to make sure the context of the
	 * cyclic reprogram call is safe.
	 */
	lbolt_softint_add();

	/*
	 * Since the hybrid lbolt implementation is based on a hardware counter
	 * that is reset at every hardware reboot and that we'd like to have
	 * the lbolt value starting at zero after both a hardware and a fast
	 * reboot, we calculate the number of clock ticks the system's been up
	 * and store it in the lbi_debug_time field of the lbolt info structure.
	 * The value of this field will be subtracted from lbolt before
	 * returning it.
	 */
	lb_info->lbi_internal = lb_info->lbi_debug_time =
	    (gethrtime()/nsec_per_tick);

	/*
	 * lbolt_hybrid points at lbolt_bootstrap until now. The LBOLT_* macros
	 * and lbolt_debug_{enter,return} use this value as an indication that
	 * the initializaion above hasn't been completed. Setting lbolt_hybrid
	 * to either lbolt_{cyclic,event}_driven here signals those code paths
	 * that the lbolt related structures can be used.
	 */
	if (lbolt_cyc_only) {
		lbolt_when.cyt_when = 0;
		lbolt_hybrid = lbolt_cyclic_driven;
	} else {
		lbolt_when.cyt_when = CY_INFINITY;
		lbolt_hybrid = lbolt_event_driven;
	}

	/*
	 * Grab cpu_lock and install all three cyclics.
	 */
	mutex_enter(&cpu_lock);

	clock_cyclic = cyclic_add(&clk_hdlr, &clk_when);
	lb_info->id.lbi_cyclic_id = cyclic_add(&lbolt_hdlr, &lbolt_when);

	mutex_exit(&cpu_lock);
}

/*
 * Called before calcloadavg to get 10-sec moving loadavg together
 */

static int
genloadavg(struct loadavg_s *avgs)
{
	int avg;
	int spos; /* starting position */
	int cpos; /* moving current position */
	int i;
	int slen;
	hrtime_t hr_avg;

	/* 10-second snapshot, calculate first positon */
	if (avgs->lg_len == 0) {
		return (0);
	}
	slen = avgs->lg_len < S_MOVAVG_SZ ? avgs->lg_len : S_MOVAVG_SZ;

	spos = (avgs->lg_cur - 1) >= 0 ? avgs->lg_cur - 1 :
	    S_LOADAVG_SZ + (avgs->lg_cur - 1);
	for (i = hr_avg = 0; i < slen; i++) {
		cpos = (spos - i) >= 0 ? spos - i : S_LOADAVG_SZ + (spos - i);
		hr_avg += avgs->lg_loads[cpos];
	}

	hr_avg = hr_avg / slen;
	avg = hr_avg / (NANOSEC / LGRP_LOADAVG_IN_THREAD_MAX);

	return (avg);
}

/*
 * Run every second from clock () to update the loadavg count available to the
 * system and cpu-partitions.
 *
 * This works by sampling the previous usr, sys, wait time elapsed,
 * computing a delta, and adding that delta to the elapsed usr, sys,
 * wait increase.
 */

static void
loadavg_update()
{
	cpu_t *cp;
	cpupart_t *cpupart;
	hrtime_t cpu_total;
	int prev;

	cp = cpu_list;
	loadavg.lg_total = 0;

	/*
	 * first pass totals up per-cpu statistics for system and cpu
	 * partitions
	 */

	do {
		struct loadavg_s *lavg;

		lavg = &cp->cpu_loadavg;

		cpu_total = cp->cpu_acct[CMS_USER] +
		    cp->cpu_acct[CMS_SYSTEM] + cp->cpu_waitrq;
		/* compute delta against last total */
		scalehrtime(&cpu_total);
		prev = (lavg->lg_cur - 1) >= 0 ? lavg->lg_cur - 1 :
		    S_LOADAVG_SZ + (lavg->lg_cur - 1);
		if (lavg->lg_loads[prev] <= 0) {
			lavg->lg_loads[lavg->lg_cur] = cpu_total;
			cpu_total = 0;
		} else {
			lavg->lg_loads[lavg->lg_cur] = cpu_total;
			cpu_total = cpu_total - lavg->lg_loads[prev];
			if (cpu_total < 0)
				cpu_total = 0;
		}

		lavg->lg_cur = (lavg->lg_cur + 1) % S_LOADAVG_SZ;
		lavg->lg_len = (lavg->lg_len + 1) < S_LOADAVG_SZ ?
		    lavg->lg_len + 1 : S_LOADAVG_SZ;

		loadavg.lg_total += cpu_total;
		cp->cpu_part->cp_loadavg.lg_total += cpu_total;

	} while ((cp = cp->cpu_next) != cpu_list);

	loadavg.lg_loads[loadavg.lg_cur] = loadavg.lg_total;
	loadavg.lg_cur = (loadavg.lg_cur + 1) % S_LOADAVG_SZ;
	loadavg.lg_len = (loadavg.lg_len + 1) < S_LOADAVG_SZ ?
	    loadavg.lg_len + 1 : S_LOADAVG_SZ;
	/*
	 * Second pass updates counts
	 */
	cpupart = cp_list_head;

	do {
		struct loadavg_s *lavg;

		lavg = &cpupart->cp_loadavg;
		lavg->lg_loads[lavg->lg_cur] = lavg->lg_total;
		lavg->lg_total = 0;
		lavg->lg_cur = (lavg->lg_cur + 1) % S_LOADAVG_SZ;
		lavg->lg_len = (lavg->lg_len + 1) < S_LOADAVG_SZ ?
		    lavg->lg_len + 1 : S_LOADAVG_SZ;

	} while ((cpupart = cpupart->cp_next) != cp_list_head);

	/*
	 * Third pass totals up per-zone statistics.
	 */
	zone_loadavg_update();
}

/*
 * clock_update() - local clock update
 *
 * This routine is called by ntp_adjtime() to update the local clock
 * phase and frequency. The implementation is of an
 * adaptive-parameter, hybrid phase/frequency-lock loop (PLL/FLL). The
 * routine computes new time and frequency offset estimates for each
 * call.  The PPS signal itself determines the new time offset,
 * instead of the calling argument.  Presumably, calls to
 * ntp_adjtime() occur only when the caller believes the local clock
 * is valid within some bound (+-128 ms with NTP). If the caller's
 * time is far different than the PPS time, an argument will ensue,
 * and it's not clear who will lose.
 *
 * For uncompensated quartz crystal oscillatores and nominal update
 * intervals less than 1024 s, operation should be in phase-lock mode
 * (STA_FLL = 0), where the loop is disciplined to phase. For update
 * intervals greater than this, operation should be in frequency-lock
 * mode (STA_FLL = 1), where the loop is disciplined to frequency.
 *
 * Note: mutex(&tod_lock) is in effect.
 */
void
clock_update(int offset)
{
	int ltemp, mtemp, s;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (!(time_status & STA_PLL) && !(time_status & STA_PPSTIME))
		return;
	ltemp = offset;
	if ((time_status & STA_PPSTIME) && (time_status & STA_PPSSIGNAL))
		ltemp = pps_offset;

	/*
	 * Scale the phase adjustment and clamp to the operating range.
	 */
	if (ltemp > MAXPHASE)
		time_offset = MAXPHASE * SCALE_UPDATE;
	else if (ltemp < -MAXPHASE)
		time_offset = -(MAXPHASE * SCALE_UPDATE);
	else
		time_offset = ltemp * SCALE_UPDATE;

	/*
	 * Select whether the frequency is to be controlled and in which
	 * mode (PLL or FLL). Clamp to the operating range. Ugly
	 * multiply/divide should be replaced someday.
	 */
	if (time_status & STA_FREQHOLD || time_reftime == 0)
		time_reftime = hrestime.tv_sec;

	mtemp = hrestime.tv_sec - time_reftime;
	time_reftime = hrestime.tv_sec;

	if (time_status & STA_FLL) {
		if (mtemp >= MINSEC) {
			ltemp = ((time_offset / mtemp) * (SCALE_USEC /
			    SCALE_UPDATE));
			if (ltemp)
				time_freq += ltemp / SCALE_KH;
		}
	} else {
		if (mtemp < MAXSEC) {
			ltemp *= mtemp;
			if (ltemp)
				time_freq += (int)(((int64_t)ltemp *
				    SCALE_USEC) / SCALE_KF)
				    / (1 << (time_constant * 2));
		}
	}
	if (time_freq > time_tolerance)
		time_freq = time_tolerance;
	else if (time_freq < -time_tolerance)
		time_freq = -time_tolerance;

	s = hr_clock_lock();
	tod_needsync = 1;
	hr_clock_unlock(s);
}

/*
 * ddi_hardpps() - discipline CPU clock oscillator to external PPS signal
 *
 * This routine is called at each PPS interrupt in order to discipline
 * the CPU clock oscillator to the PPS signal. It measures the PPS phase
 * and leaves it in a handy spot for the clock() routine. It
 * integrates successive PPS phase differences and calculates the
 * frequency offset. This is used in clock() to discipline the CPU
 * clock oscillator so that intrinsic frequency error is cancelled out.
 * The code requires the caller to capture the time and hardware counter
 * value at the on-time PPS signal transition.
 *
 * Note that, on some Unix systems, this routine runs at an interrupt
 * priority level higher than the timer interrupt routine clock().
 * Therefore, the variables used are distinct from the clock()
 * variables, except for certain exceptions: The PPS frequency pps_freq
 * and phase pps_offset variables are determined by this routine and
 * updated atomically. The time_tolerance variable can be considered a
 * constant, since it is infrequently changed, and then only when the
 * PPS signal is disabled. The watchdog counter pps_valid is updated
 * once per second by clock() and is atomically cleared in this
 * routine.
 *
 * tvp is the time of the last tick; usec is a microsecond count since the
 * last tick.
 *
 * Note: In Solaris systems, the tick value is actually given by
 *       usec_per_tick.  This is called from the serial driver cdintr(),
 *	 or equivalent, at a high PIL.  Because the kernel keeps a
 *	 highresolution time, the following code can accept either
 *	 the traditional argument pair, or the current highres timestamp
 *       in tvp and zero in usec.
 */
void
ddi_hardpps(struct timeval *tvp, int usec)
{
	int u_usec, v_usec, bigtick;
	time_t cal_sec;
	int cal_usec;

	/*
	 * An occasional glitch can be produced when the PPS interrupt
	 * occurs in the clock() routine before the time variable is
	 * updated. Here the offset is discarded when the difference
	 * between it and the last one is greater than tick/2, but not
	 * if the interval since the first discard exceeds 30 s.
	 */
	time_status |= STA_PPSSIGNAL;
	time_status &= ~(STA_PPSJITTER | STA_PPSWANDER | STA_PPSERROR);
	pps_valid = 0;
	u_usec = -tvp->tv_usec;
	if (u_usec < -(MICROSEC/2))
		u_usec += MICROSEC;
	v_usec = pps_offset - u_usec;
	if (v_usec < 0)
		v_usec = -v_usec;
	if (v_usec > (usec_per_tick >> 1)) {
		if (pps_glitch > MAXGLITCH) {
			pps_glitch = 0;
			pps_tf[2] = u_usec;
			pps_tf[1] = u_usec;
		} else {
			pps_glitch++;
			u_usec = pps_offset;
		}
	} else
		pps_glitch = 0;

	/*
	 * A three-stage median filter is used to help deglitch the pps
	 * time. The median sample becomes the time offset estimate; the
	 * difference between the other two samples becomes the time
	 * dispersion (jitter) estimate.
	 */
	pps_tf[2] = pps_tf[1];
	pps_tf[1] = pps_tf[0];
	pps_tf[0] = u_usec;
	if (pps_tf[0] > pps_tf[1]) {
		if (pps_tf[1] > pps_tf[2]) {
			pps_offset = pps_tf[1];		/* 0 1 2 */
			v_usec = pps_tf[0] - pps_tf[2];
		} else if (pps_tf[2] > pps_tf[0]) {
			pps_offset = pps_tf[0];		/* 2 0 1 */
			v_usec = pps_tf[2] - pps_tf[1];
		} else {
			pps_offset = pps_tf[2];		/* 0 2 1 */
			v_usec = pps_tf[0] - pps_tf[1];
		}
	} else {
		if (pps_tf[1] < pps_tf[2]) {
			pps_offset = pps_tf[1];		/* 2 1 0 */
			v_usec = pps_tf[2] - pps_tf[0];
		} else  if (pps_tf[2] < pps_tf[0]) {
			pps_offset = pps_tf[0];		/* 1 0 2 */
			v_usec = pps_tf[1] - pps_tf[2];
		} else {
			pps_offset = pps_tf[2];		/* 1 2 0 */
			v_usec = pps_tf[1] - pps_tf[0];
		}
	}
	if (v_usec > MAXTIME)
		pps_jitcnt++;
	v_usec = (v_usec << PPS_AVG) - pps_jitter;
	pps_jitter += v_usec / (1 << PPS_AVG);
	if (pps_jitter > (MAXTIME >> 1))
		time_status |= STA_PPSJITTER;

	/*
	 * During the calibration interval adjust the starting time when
	 * the tick overflows. At the end of the interval compute the
	 * duration of the interval and the difference of the hardware
	 * counters at the beginning and end of the interval. This code
	 * is deliciously complicated by the fact valid differences may
	 * exceed the value of tick when using long calibration
	 * intervals and small ticks. Note that the counter can be
	 * greater than tick if caught at just the wrong instant, but
	 * the values returned and used here are correct.
	 */
	bigtick = (int)usec_per_tick * SCALE_USEC;
	pps_usec -= pps_freq;
	if (pps_usec >= bigtick)
		pps_usec -= bigtick;
	if (pps_usec < 0)
		pps_usec += bigtick;
	pps_time.tv_sec++;
	pps_count++;
	if (pps_count < (1 << pps_shift))
		return;
	pps_count = 0;
	pps_calcnt++;
	u_usec = usec * SCALE_USEC;
	v_usec = pps_usec - u_usec;
	if (v_usec >= bigtick >> 1)
		v_usec -= bigtick;
	if (v_usec < -(bigtick >> 1))
		v_usec += bigtick;
	if (v_usec < 0)
		v_usec = -(-v_usec >> pps_shift);
	else
		v_usec = v_usec >> pps_shift;
	pps_usec = u_usec;
	cal_sec = tvp->tv_sec;
	cal_usec = tvp->tv_usec;
	cal_sec -= pps_time.tv_sec;
	cal_usec -= pps_time.tv_usec;
	if (cal_usec < 0) {
		cal_usec += MICROSEC;
		cal_sec--;
	}
	pps_time = *tvp;

	/*
	 * Check for lost interrupts, noise, excessive jitter and
	 * excessive frequency error. The number of timer ticks during
	 * the interval may vary +-1 tick. Add to this a margin of one
	 * tick for the PPS signal jitter and maximum frequency
	 * deviation. If the limits are exceeded, the calibration
	 * interval is reset to the minimum and we start over.
	 */
	u_usec = (int)usec_per_tick << 1;
	if (!((cal_sec == -1 && cal_usec > (MICROSEC - u_usec)) ||
	    (cal_sec == 0 && cal_usec < u_usec)) ||
	    v_usec > time_tolerance || v_usec < -time_tolerance) {
		pps_errcnt++;
		pps_shift = PPS_SHIFT;
		pps_intcnt = 0;
		time_status |= STA_PPSERROR;
		return;
	}

	/*
	 * A three-stage median filter is used to help deglitch the pps
	 * frequency. The median sample becomes the frequency offset
	 * estimate; the difference between the other two samples
	 * becomes the frequency dispersion (stability) estimate.
	 */
	pps_ff[2] = pps_ff[1];
	pps_ff[1] = pps_ff[0];
	pps_ff[0] = v_usec;
	if (pps_ff[0] > pps_ff[1]) {
		if (pps_ff[1] > pps_ff[2]) {
			u_usec = pps_ff[1];		/* 0 1 2 */
			v_usec = pps_ff[0] - pps_ff[2];
		} else if (pps_ff[2] > pps_ff[0]) {
			u_usec = pps_ff[0];		/* 2 0 1 */
			v_usec = pps_ff[2] - pps_ff[1];
		} else {
			u_usec = pps_ff[2];		/* 0 2 1 */
			v_usec = pps_ff[0] - pps_ff[1];
		}
	} else {
		if (pps_ff[1] < pps_ff[2]) {
			u_usec = pps_ff[1];		/* 2 1 0 */
			v_usec = pps_ff[2] - pps_ff[0];
		} else  if (pps_ff[2] < pps_ff[0]) {
			u_usec = pps_ff[0];		/* 1 0 2 */
			v_usec = pps_ff[1] - pps_ff[2];
		} else {
			u_usec = pps_ff[2];		/* 1 2 0 */
			v_usec = pps_ff[1] - pps_ff[0];
		}
	}

	/*
	 * Here the frequency dispersion (stability) is updated. If it
	 * is less than one-fourth the maximum (MAXFREQ), the frequency
	 * offset is updated as well, but clamped to the tolerance. It
	 * will be processed later by the clock() routine.
	 */
	v_usec = (v_usec >> 1) - pps_stabil;
	if (v_usec < 0)
		pps_stabil -= -v_usec >> PPS_AVG;
	else
		pps_stabil += v_usec >> PPS_AVG;
	if (pps_stabil > MAXFREQ >> 2) {
		pps_stbcnt++;
		time_status |= STA_PPSWANDER;
		return;
	}
	if (time_status & STA_PPSFREQ) {
		if (u_usec < 0) {
			pps_freq -= -u_usec >> PPS_AVG;
			if (pps_freq < -time_tolerance)
				pps_freq = -time_tolerance;
			u_usec = -u_usec;
		} else {
			pps_freq += u_usec >> PPS_AVG;
			if (pps_freq > time_tolerance)
				pps_freq = time_tolerance;
		}
	}

	/*
	 * Here the calibration interval is adjusted. If the maximum
	 * time difference is greater than tick / 4, reduce the interval
	 * by half. If this is not the case for four consecutive
	 * intervals, double the interval.
	 */
	if (u_usec << pps_shift > bigtick >> 2) {
		pps_intcnt = 0;
		if (pps_shift > PPS_SHIFT)
			pps_shift--;
	} else if (pps_intcnt >= 4) {
		pps_intcnt = 0;
		if (pps_shift < PPS_SHIFTMAX)
			pps_shift++;
	} else
		pps_intcnt++;

	/*
	 * If recovering from kmdb, then make sure the tod chip gets resynced.
	 * If we took an early exit above, then we don't yet have a stable
	 * calibration signal to lock onto, so don't mark the tod for sync
	 * until we get all the way here.
	 */
	{
		int s = hr_clock_lock();

		tod_needsync = 1;
		hr_clock_unlock(s);
	}
}

/*
 * Handle clock tick processing for a thread.
 * Check for timer action, enforce CPU rlimit, do profiling etc.
 */
void
clock_tick(kthread_t *t, int pending)
{
	struct proc *pp;
	klwp_id_t    lwp;
	struct as *as;
	clock_t	ticks;
	int	poke = 0;		/* notify another CPU */
	int	user_mode;
	size_t	 rss;
	int i, total_usec, usec;
	rctl_qty_t secs;

	ASSERT(pending > 0);

	/* Must be operating on a lwp/thread */
	if ((lwp = ttolwp(t)) == NULL) {
		panic("clock_tick: no lwp");
		/*NOTREACHED*/
	}

	for (i = 0; i < pending; i++) {
		CL_TICK(t);	/* Class specific tick processing */
		DTRACE_SCHED1(tick, kthread_t *, t);
	}

	pp = ttoproc(t);

	/* pp->p_lock makes sure that the thread does not exit */
	ASSERT(MUTEX_HELD(&pp->p_lock));

	user_mode = (lwp->lwp_state == LWP_USER);

	ticks = (pp->p_utime + pp->p_stime) % hz;
	/*
	 * Update process times. Should use high res clock and state
	 * changes instead of statistical sampling method. XXX
	 */
	if (user_mode) {
		pp->p_utime += pending;
	} else {
		pp->p_stime += pending;
	}

	pp->p_ttime += pending;
	as = pp->p_as;

	/*
	 * Update user profiling statistics. Get the pc from the
	 * lwp when the AST happens.
	 */
	if (pp->p_prof.pr_scale) {
		atomic_add_32(&lwp->lwp_oweupc, (int32_t)pending);
		if (user_mode) {
			poke = 1;
			aston(t);
		}
	}

	/*
	 * If CPU was in user state, process lwp-virtual time
	 * interval timer. The value passed to itimerdecr() has to be
	 * in microseconds and has to be less than one second. Hence
	 * this loop.
	 */
	total_usec = usec_per_tick * pending;
	while (total_usec > 0) {
		usec = MIN(total_usec, (MICROSEC - 1));
		if (user_mode &&
		    timerisset(&lwp->lwp_timer[ITIMER_VIRTUAL].it_value) &&
		    itimerdecr(&lwp->lwp_timer[ITIMER_VIRTUAL], usec) == 0) {
			poke = 1;
			sigtoproc(pp, t, SIGVTALRM);
		}
		total_usec -= usec;
	}

	/*
	 * If CPU was in user state, process lwp-profile
	 * interval timer.
	 */
	total_usec = usec_per_tick * pending;
	while (total_usec > 0) {
		usec = MIN(total_usec, (MICROSEC - 1));
		if (timerisset(&lwp->lwp_timer[ITIMER_PROF].it_value) &&
		    itimerdecr(&lwp->lwp_timer[ITIMER_PROF], usec) == 0) {
			poke = 1;
			sigtoproc(pp, t, SIGPROF);
		}
		total_usec -= usec;
	}

	/*
	 * Enforce CPU resource controls:
	 *   (a) process.max-cpu-time resource control
	 *
	 * Perform the check only if we have accumulated more a second.
	 */
	if ((ticks + pending) >= hz) {
		(void) rctl_test(rctlproc_legacy[RLIMIT_CPU], pp->p_rctls, pp,
		    (pp->p_utime + pp->p_stime)/hz, RCA_UNSAFE_SIGINFO);
	}

	/*
	 *   (b) task.max-cpu-time resource control
	 *
	 * If we have accumulated enough ticks, increment the task CPU
	 * time usage and test for the resource limit. This minimizes the
	 * number of calls to the rct_test(). The task CPU time mutex
	 * is highly contentious as many processes can be sharing a task.
	 */
	if (pp->p_ttime >= clock_tick_proc_max) {
		secs = task_cpu_time_incr(pp->p_task, pp->p_ttime);
		pp->p_ttime = 0;
		if (secs) {
			(void) rctl_test(rc_task_cpu_time, pp->p_task->tk_rctls,
			    pp, secs, RCA_UNSAFE_SIGINFO);
		}
	}

	/*
	 * Update memory usage for the currently running process.
	 */
	rss = rm_asrss(as);
	PTOU(pp)->u_mem += rss;
	if (rss > PTOU(pp)->u_mem_max)
		PTOU(pp)->u_mem_max = rss;

	/*
	 * Notify the CPU the thread is running on.
	 */
	if (poke && t->t_cpu != CPU)
		poke_cpu(t->t_cpu->cpu_id);
}

void
profil_tick(uintptr_t upc)
{
	int ticks;
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);
	struct prof *pr = &p->p_prof;

	do {
		ticks = lwp->lwp_oweupc;
	} while (atomic_cas_32(&lwp->lwp_oweupc, ticks, 0) != ticks);

	mutex_enter(&p->p_pflock);
	if (pr->pr_scale >= 2 && upc >= pr->pr_off) {
		/*
		 * Old-style profiling
		 */
		uint16_t *slot = pr->pr_base;
		uint16_t old, new;
		if (pr->pr_scale != 2) {
			uintptr_t delta = upc - pr->pr_off;
			uintptr_t byteoff = ((delta >> 16) * pr->pr_scale) +
			    (((delta & 0xffff) * pr->pr_scale) >> 16);
			if (byteoff >= (uintptr_t)pr->pr_size) {
				mutex_exit(&p->p_pflock);
				return;
			}
			slot += byteoff / sizeof (uint16_t);
		}
		if (fuword16(slot, &old) < 0 ||
		    (new = old + ticks) > SHRT_MAX ||
		    suword16(slot, new) < 0) {
			pr->pr_scale = 0;
		}
	} else if (pr->pr_scale == 1) {
		/*
		 * PC Sampling
		 */
		model_t model = lwp_getdatamodel(lwp);
		int result;
#ifdef __lint
		model = model;
#endif
		while (ticks-- > 0) {
			if (pr->pr_samples == pr->pr_size) {
				/* buffer full, turn off sampling */
				pr->pr_scale = 0;
				break;
			}
			switch (SIZEOF_PTR(model)) {
			case sizeof (uint32_t):
				result = suword32(pr->pr_base, (uint32_t)upc);
				break;
#ifdef _LP64
			case sizeof (uint64_t):
				result = suword64(pr->pr_base, (uint64_t)upc);
				break;
#endif
			default:
				cmn_err(CE_WARN, "profil_tick: unexpected "
				    "data model");
				result = -1;
				break;
			}
			if (result != 0) {
				pr->pr_scale = 0;
				break;
			}
			pr->pr_base = (caddr_t)pr->pr_base + SIZEOF_PTR(model);
			pr->pr_samples++;
		}
	}
	mutex_exit(&p->p_pflock);
}

static void
delay_wakeup(void *arg)
{
	kthread_t	*t = arg;

	mutex_enter(&t->t_delay_lock);
	cv_signal(&t->t_delay_cv);
	mutex_exit(&t->t_delay_lock);
}

/*
 * The delay(9F) man page indicates that it can only be called from user or
 * kernel context - detect and diagnose bad calls. The following macro will
 * produce a limited number of messages identifying bad callers.  This is done
 * in a macro so that caller() is meaningful. When a bad caller is identified,
 * switching to 'drv_usecwait(TICK_TO_USEC(ticks));' may be appropriate.
 */
#define	DELAY_CONTEXT_CHECK()	{					\
	uint32_t	m;						\
	char		*f;						\
	ulong_t		off;						\
									\
	m = delay_from_interrupt_msg;					\
	if (delay_from_interrupt_diagnose && servicing_interrupt() &&	\
	    !panicstr && !devinfo_freeze &&				\
	    atomic_cas_32(&delay_from_interrupt_msg, m ? m : 1, m-1)) {	\
		f = modgetsymname((uintptr_t)caller(), &off);		\
		cmn_err(CE_WARN, "delay(9F) called from "		\
		    "interrupt context: %s`%s",				\
		    mod_containing_pc(caller()), f ? f : "...");	\
	}								\
}

/*
 * delay_common: common delay code.
 */
static void
delay_common(clock_t ticks)
{
	kthread_t	*t = curthread;
	clock_t		deadline;
	clock_t		timeleft;
	callout_id_t	id;

	/* If timeouts aren't running all we can do is spin. */
	if (panicstr || devinfo_freeze) {
		/* Convert delay(9F) call into drv_usecwait(9F) call. */
		if (ticks > 0)
			drv_usecwait(TICK_TO_USEC(ticks));
		return;
	}

	deadline = ddi_get_lbolt() + ticks;
	while ((timeleft = deadline - ddi_get_lbolt()) > 0) {
		mutex_enter(&t->t_delay_lock);
		id = timeout_default(delay_wakeup, t, timeleft);
		cv_wait(&t->t_delay_cv, &t->t_delay_lock);
		mutex_exit(&t->t_delay_lock);
		(void) untimeout_default(id, 0);
	}
}

/*
 * Delay specified number of clock ticks.
 */
void
delay(clock_t ticks)
{
	DELAY_CONTEXT_CHECK();

	delay_common(ticks);
}

/*
 * Delay a random number of clock ticks between 1 and ticks.
 */
void
delay_random(clock_t ticks)
{
	int	r;

	DELAY_CONTEXT_CHECK();

	(void) random_get_pseudo_bytes((void *)&r, sizeof (r));
	if (ticks == 0)
		ticks = 1;
	ticks = (r % ticks) + 1;
	delay_common(ticks);
}

/*
 * Like delay, but interruptible by a signal.
 */
int
delay_sig(clock_t ticks)
{
	kthread_t	*t = curthread;
	clock_t		deadline;
	clock_t		rc;

	/* If timeouts aren't running all we can do is spin. */
	if (panicstr || devinfo_freeze) {
		if (ticks > 0)
			drv_usecwait(TICK_TO_USEC(ticks));
		return (0);
	}

	deadline = ddi_get_lbolt() + ticks;
	mutex_enter(&t->t_delay_lock);
	do {
		rc = cv_timedwait_sig(&t->t_delay_cv,
		    &t->t_delay_lock, deadline);
		/* loop until past deadline or signaled */
	} while (rc > 0);
	mutex_exit(&t->t_delay_lock);
	if (rc == 0)
		return (EINTR);
	return (0);
}


#define	SECONDS_PER_DAY 86400

/*
 * Initialize the system time based on the TOD chip.  approx is used as
 * an approximation of time (e.g. from the filesystem) in the event that
 * the TOD chip has been cleared or is unresponsive.  An approx of -1
 * means the filesystem doesn't keep time.
 */
void
clkset(time_t approx)
{
	timestruc_t ts;
	int spl;
	int set_clock = 0;

	mutex_enter(&tod_lock);
	ts = tod_get();

	if (ts.tv_sec > 365 * SECONDS_PER_DAY) {
		/*
		 * If the TOD chip is reporting some time after 1971,
		 * then it probably didn't lose power or become otherwise
		 * cleared in the recent past;  check to assure that
		 * the time coming from the filesystem isn't in the future
		 * according to the TOD chip.
		 */
		if (approx != -1 && approx > ts.tv_sec) {
			cmn_err(CE_WARN, "Last shutdown is later "
			    "than time on time-of-day chip; check date.");
		}
	} else {
		/*
		 * If the TOD chip isn't giving correct time, set it to the
		 * greater of i) approx and ii) 1987. That way if approx
		 * is negative or is earlier than 1987, we set the clock
		 * back to a time when Oliver North, ALF and Dire Straits
		 * were all on the collective brain:  1987.
		 */
		timestruc_t tmp;
		time_t diagnose_date = (1987 - 1970) * 365 * SECONDS_PER_DAY;
		ts.tv_sec = (approx > diagnose_date ? approx : diagnose_date);
		ts.tv_nsec = 0;

		/*
		 * Attempt to write the new time to the TOD chip.  Set spl high
		 * to avoid getting preempted between the tod_set and tod_get.
		 */
		spl = splhi();
		tod_set(ts);
		tmp = tod_get();
		splx(spl);

		if (tmp.tv_sec != ts.tv_sec && tmp.tv_sec != ts.tv_sec + 1) {
			tod_broken = 1;
			dosynctodr = 0;
			cmn_err(CE_WARN, "Time-of-day chip unresponsive.");
		} else {
			cmn_err(CE_WARN, "Time-of-day chip had "
			    "incorrect date; check and reset.");
		}
		set_clock = 1;
	}

	if (!boot_time) {
		boot_time = ts.tv_sec;
		set_clock = 1;
	}

	if (set_clock)
		set_hrestime(&ts);

	mutex_exit(&tod_lock);
}

int	timechanged;	/* for testing if the system time has been reset */

void
set_hrestime(timestruc_t *ts)
{
	int spl = hr_clock_lock();
	hrestime = *ts;
	membar_enter();	/* hrestime must be visible before timechanged++ */
	timedelta = 0;
	timechanged++;
	hr_clock_unlock(spl);
	callout_hrestime();
}

static uint_t deadman_seconds;
static uint32_t deadman_panics;
static int deadman_enabled = 0;
static int deadman_panic_timers = 1;

static void
deadman(void)
{
	if (panicstr) {
		/*
		 * During panic, other CPUs besides the panic
		 * master continue to handle cyclics and some other
		 * interrupts.  The code below is intended to be
		 * single threaded, so any CPU other than the master
		 * must keep out.
		 */
		if (CPU->cpu_id != panic_cpu.cpu_id)
			return;

		if (!deadman_panic_timers)
			return; /* allow all timers to be manually disabled */

		/*
		 * If we are generating a crash dump or syncing filesystems and
		 * the corresponding timer is set, decrement it and re-enter
		 * the panic code to abort it and advance to the next state.
		 * The panic states and triggers are explained in panic.c.
		 */
		if (panic_dump) {
			if (dump_timeleft && (--dump_timeleft == 0)) {
				panic("panic dump timeout");
				/*NOTREACHED*/
			}
		} else if (panic_sync) {
			if (sync_timeleft && (--sync_timeleft == 0)) {
				panic("panic sync timeout");
				/*NOTREACHED*/
			}
		}

		return;
	}

	if (deadman_counter != CPU->cpu_deadman_counter) {
		CPU->cpu_deadman_counter = deadman_counter;
		CPU->cpu_deadman_countdown = deadman_seconds;
		return;
	}

	if (--CPU->cpu_deadman_countdown > 0)
		return;

	/*
	 * Regardless of whether or not we actually bring the system down,
	 * bump the deadman_panics variable.
	 *
	 * N.B. deadman_panics is incremented once for each CPU that
	 * passes through here.  It's expected that all the CPUs will
	 * detect this condition within one second of each other, so
	 * when deadman_enabled is off, deadman_panics will
	 * typically be a multiple of the total number of CPUs in
	 * the system.
	 */
	atomic_inc_32(&deadman_panics);

	if (!deadman_enabled) {
		CPU->cpu_deadman_countdown = deadman_seconds;
		return;
	}

	/*
	 * If we're here, we want to bring the system down.
	 */
	panic("deadman: timed out after %d seconds of clock "
	    "inactivity", deadman_seconds);
	/*NOTREACHED*/
}

/*ARGSUSED*/
static void
deadman_online(void *arg, cpu_t *cpu, cyc_handler_t *hdlr, cyc_time_t *when)
{
	cpu->cpu_deadman_counter = 0;
	cpu->cpu_deadman_countdown = deadman_seconds;

	hdlr->cyh_func = (cyc_func_t)deadman;
	hdlr->cyh_level = CY_HIGH_LEVEL;
	hdlr->cyh_arg = NULL;

	/*
	 * Stagger the CPUs so that they don't all run deadman() at
	 * the same time.  Simplest reason to do this is to make it
	 * more likely that only one CPU will panic in case of a
	 * timeout.  This is (strictly speaking) an aesthetic, not a
	 * technical consideration.
	 */
	when->cyt_when = cpu->cpu_id * (NANOSEC / NCPU);
	when->cyt_interval = NANOSEC;
}


void
deadman_init(void)
{
	cyc_omni_handler_t hdlr;

	if (deadman_seconds == 0)
		deadman_seconds = snoop_interval / MICROSEC;

	if (snooping)
		deadman_enabled = 1;

	hdlr.cyo_online = deadman_online;
	hdlr.cyo_offline = NULL;
	hdlr.cyo_arg = NULL;

	mutex_enter(&cpu_lock);
	deadman_cyclic = cyclic_add_omni(&hdlr);
	mutex_exit(&cpu_lock);
}

/*
 * tod_fault() is for updating tod validate mechanism state:
 * (1) TOD_NOFAULT: for resetting the state to 'normal'.
 *     currently used for debugging only
 * (2) The following four cases detected by tod validate mechanism:
 *       TOD_REVERSED: current tod value is less than previous value.
 *       TOD_STALLED: current tod value hasn't advanced.
 *       TOD_JUMPED: current tod value advanced too far from previous value.
 *       TOD_RATECHANGED: the ratio between average tod delta and
 *       average tick delta has changed.
 * (3) TOD_RDONLY: when the TOD clock is not writeable e.g. because it is
 *     a virtual TOD provided by a hypervisor.
 */
enum tod_fault_type
tod_fault(enum tod_fault_type ftype, int off)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	if (tod_faulted != ftype) {
		switch (ftype) {
		case TOD_NOFAULT:
			plat_tod_fault(TOD_NOFAULT);
			cmn_err(CE_NOTE, "Restarted tracking "
			    "Time of Day clock.");
			tod_faulted = ftype;
			break;
		case TOD_REVERSED:
		case TOD_JUMPED:
			if (tod_faulted == TOD_NOFAULT) {
				plat_tod_fault(ftype);
				cmn_err(CE_WARN, "Time of Day clock error: "
				    "reason [%s by 0x%x]. -- "
				    " Stopped tracking Time Of Day clock.",
				    tod_fault_table[ftype], off);
				tod_faulted = ftype;
			}
			break;
		case TOD_STALLED:
		case TOD_RATECHANGED:
			if (tod_faulted == TOD_NOFAULT) {
				plat_tod_fault(ftype);
				cmn_err(CE_WARN, "Time of Day clock error: "
				    "reason [%s]. -- "
				    " Stopped tracking Time Of Day clock.",
				    tod_fault_table[ftype]);
				tod_faulted = ftype;
			}
			break;
		case TOD_RDONLY:
			if (tod_faulted == TOD_NOFAULT) {
				plat_tod_fault(ftype);
				cmn_err(CE_NOTE, "!Time of Day clock is "
				    "Read-Only; set of Date/Time will not "
				    "persist across reboot.");
				tod_faulted = ftype;
			}
			break;
		default:
			break;
		}
	}
	return (tod_faulted);
}

/*
 * Two functions that allow tod_status_flag to be manipulated by functions
 * external to this file.
 */

void
tod_status_set(int tod_flag)
{
	tod_status_flag |= tod_flag;
}

void
tod_status_clear(int tod_flag)
{
	tod_status_flag &= ~tod_flag;
}

/*
 * Record a timestamp and the value passed to tod_set().  The next call to
 * tod_validate() can use these values, prev_set_tick and prev_set_tod,
 * when checking the timestruc_t returned by tod_get().  Ordinarily,
 * tod_validate() will use prev_tick and prev_tod for this task but these
 * become obsolete, and will be re-assigned with the prev_set_* values,
 * in the case when the TOD is re-written.
 */
void
tod_set_prev(timestruc_t ts)
{
	if ((tod_validate_enable == 0) || (tod_faulted != TOD_NOFAULT) ||
	    tod_validate_deferred) {
		return;
	}
	prev_set_tick = gethrtime();
	/*
	 * A negative value will be set to zero in utc_to_tod() so we fake
	 * a zero here in such a case.  This would need to change if the
	 * behavior of utc_to_tod() changes.
	 */
	prev_set_tod = ts.tv_sec < 0 ? 0 : ts.tv_sec;
}

/*
 * tod_validate() is used for checking values returned by tod_get().
 * Four error cases can be detected by this routine:
 *   TOD_REVERSED: current tod value is less than previous.
 *   TOD_STALLED: current tod value hasn't advanced.
 *   TOD_JUMPED: current tod value advanced too far from previous value.
 *   TOD_RATECHANGED: the ratio between average tod delta and
 *   average tick delta has changed.
 */
time_t
tod_validate(time_t tod)
{
	time_t diff_tod;
	hrtime_t diff_tick;

	long dtick;
	int dtick_delta;

	int off = 0;
	enum tod_fault_type tod_bad = TOD_NOFAULT;

	static int firsttime = 1;

	static time_t prev_tod = 0;
	static hrtime_t prev_tick = 0;
	static long dtick_avg = TOD_REF_FREQ;

	int cpr_resume_done = 0;
	int dr_resume_done = 0;

	hrtime_t tick = gethrtime();

	ASSERT(MUTEX_HELD(&tod_lock));

	/*
	 * tod_validate_enable is patchable via /etc/system.
	 * If TOD is already faulted, or if TOD validation is deferred,
	 * there is nothing to do.
	 */
	if ((tod_validate_enable == 0) || (tod_faulted != TOD_NOFAULT) ||
	    tod_validate_deferred) {
		return (tod);
	}

	/*
	 * If this is the first time through, we just need to save the tod
	 * we were called with and hrtime so we can use them next time to
	 * validate tod_get().
	 */
	if (firsttime) {
		firsttime = 0;
		prev_tod = tod;
		prev_tick = tick;
		return (tod);
	}

	/*
	 * Handle any flags that have been turned on by tod_status_set().
	 * In the case where a tod_set() is done and then a subsequent
	 * tod_get() fails (ie, both TOD_SET_DONE and TOD_GET_FAILED are
	 * true), we treat the TOD_GET_FAILED with precedence by switching
	 * off the flag, returning tod and leaving TOD_SET_DONE asserted
	 * until such time as tod_get() completes successfully.
	 */
	if (tod_status_flag & TOD_GET_FAILED) {
		/*
		 * tod_get() has encountered an issue, possibly transitory,
		 * when reading TOD.  We'll just return the incoming tod
		 * value (which is actually hrestime.tv_sec in this case)
		 * and when we get a genuine tod, following a successful
		 * tod_get(), we can validate using prev_tod and prev_tick.
		 */
		tod_status_flag &= ~TOD_GET_FAILED;
		return (tod);
	} else if (tod_status_flag & TOD_SET_DONE) {
		/*
		 * TOD has been modified.  Just before the TOD was written,
		 * tod_set_prev() saved tod and hrtime; we can now use
		 * those values, prev_set_tod and prev_set_tick, to validate
		 * the incoming tod that's just been read.
		 */
		prev_tod = prev_set_tod;
		prev_tick = prev_set_tick;
		dtick_avg = TOD_REF_FREQ;
		tod_status_flag &= ~TOD_SET_DONE;
		/*
		 * If a tod_set() preceded a cpr_suspend() without an
		 * intervening tod_validate(), we need to ensure that a
		 * TOD_JUMPED condition is ignored.
		 * Note this isn't a concern in the case of DR as we've
		 * just reassigned dtick_avg, above.
		 */
		if (tod_status_flag & TOD_CPR_RESUME_DONE) {
			cpr_resume_done = 1;
			tod_status_flag &= ~TOD_CPR_RESUME_DONE;
		}
	} else if (tod_status_flag & TOD_CPR_RESUME_DONE) {
		/*
		 * The system's coming back from a checkpoint resume.
		 */
		cpr_resume_done = 1;
		tod_status_flag &= ~TOD_CPR_RESUME_DONE;
		/*
		 * We need to handle the possibility of a CPR suspend
		 * operation having been initiated whilst a DR event was
		 * in-flight.
		 */
		if (tod_status_flag & TOD_DR_RESUME_DONE) {
			dr_resume_done = 1;
			tod_status_flag &= ~TOD_DR_RESUME_DONE;
		}
	} else if (tod_status_flag & TOD_DR_RESUME_DONE) {
		/*
		 * A Dynamic Reconfiguration event has taken place.
		 */
		dr_resume_done = 1;
		tod_status_flag &= ~TOD_DR_RESUME_DONE;
	}

	/* test hook */
	switch (tod_unit_test) {
	case 1: /* for testing jumping tod */
		tod += tod_test_injector;
		tod_unit_test = 0;
		break;
	case 2:	/* for testing stuck tod bit */
		tod |= 1 << tod_test_injector;
		tod_unit_test = 0;
		break;
	case 3:	/* for testing stalled tod */
		tod = prev_tod;
		tod_unit_test = 0;
		break;
	case 4:	/* reset tod fault status */
		(void) tod_fault(TOD_NOFAULT, 0);
		tod_unit_test = 0;
		break;
	default:
		break;
	}

	diff_tod = tod - prev_tod;
	diff_tick = tick - prev_tick;

	ASSERT(diff_tick >= 0);

	if (diff_tod < 0) {
		/* ERROR - tod reversed */
		tod_bad = TOD_REVERSED;
		off = (int)(prev_tod - tod);
	} else if (diff_tod == 0) {
		/* tod did not advance */
		if (diff_tick > TOD_STALL_THRESHOLD) {
			/* ERROR - tod stalled */
			tod_bad = TOD_STALLED;
		} else {
			/*
			 * Make sure we don't update prev_tick
			 * so that diff_tick is calculated since
			 * the first diff_tod == 0
			 */
			return (tod);
		}
	} else {
		/* calculate dtick */
		dtick = diff_tick / diff_tod;

		/* update dtick averages */
		dtick_avg += ((dtick - dtick_avg) / TOD_FILTER_N);

		/*
		 * Calculate dtick_delta as
		 * variation from reference freq in quartiles
		 */
		dtick_delta = (dtick_avg - TOD_REF_FREQ) /
		    (TOD_REF_FREQ >> 2);

		/*
		 * Even with a perfectly functioning TOD device,
		 * when the number of elapsed seconds is low the
		 * algorithm can calculate a rate that is beyond
		 * tolerance, causing an error.  The algorithm is
		 * inaccurate when elapsed time is low (less than
		 * 5 seconds).
		 */
		if (diff_tod > 4) {
			if (dtick < TOD_JUMP_THRESHOLD) {
				/*
				 * If we've just done a CPR resume, we detect
				 * a jump in the TOD but, actually, what's
				 * happened is that the TOD has been increasing
				 * whilst the system was suspended and the tick
				 * count hasn't kept up.  We consider the first
				 * occurrence of this after a resume as normal
				 * and ignore it; otherwise, in a non-resume
				 * case, we regard it as a TOD problem.
				 */
				if (!cpr_resume_done) {
					/* ERROR - tod jumped */
					tod_bad = TOD_JUMPED;
					off = (int)diff_tod;
				}
			}
			if (dtick_delta) {
				/*
				 * If we've just done a DR resume, dtick_avg
				 * can go a bit askew so we reset it and carry
				 * on; otherwise, the TOD is in error.
				 */
				if (dr_resume_done) {
					dtick_avg = TOD_REF_FREQ;
				} else {
					/* ERROR - change in clock rate */
					tod_bad = TOD_RATECHANGED;
				}
			}
		}
	}

	if (tod_bad != TOD_NOFAULT) {
		(void) tod_fault(tod_bad, off);

		/*
		 * Disable dosynctodr since we are going to fault
		 * the TOD chip anyway here
		 */
		dosynctodr = 0;

		/*
		 * Set tod to the correct value from hrestime
		 */
		tod = hrestime.tv_sec;
	}

	prev_tod = tod;
	prev_tick = tick;
	return (tod);
}

static void
calcloadavg(int nrun, uint64_t *hp_ave)
{
	static int64_t f[3] = { 135, 27, 9 };
	uint_t i;
	int64_t q, r;

	/*
	 * Compute load average over the last 1, 5, and 15 minutes
	 * (60, 300, and 900 seconds).  The constants in f[3] are for
	 * exponential decay:
	 * (1 - exp(-1/60)) << 13 = 135,
	 * (1 - exp(-1/300)) << 13 = 27,
	 * (1 - exp(-1/900)) << 13 = 9.
	 */

	/*
	 * a little hoop-jumping to avoid integer overflow
	 */
	for (i = 0; i < 3; i++) {
		q = (hp_ave[i]  >> 16) << 7;
		r = (hp_ave[i]  & 0xffff) << 7;
		hp_ave[i] += ((nrun - q) * f[i] - ((r * f[i]) >> 16)) >> 4;
	}
}

/*
 * lbolt_hybrid() is used by ddi_get_lbolt() and ddi_get_lbolt64() to
 * calculate the value of lbolt according to the current mode. In the event
 * driven mode (the default), lbolt is calculated by dividing the current hires
 * time by the number of nanoseconds per clock tick. In the cyclic driven mode
 * an internal variable is incremented at each firing of the lbolt cyclic
 * and returned by lbolt_cyclic_driven().
 *
 * The system will transition from event to cyclic driven mode when the number
 * of calls to lbolt_event_driven() exceeds the (per CPU) threshold within a
 * window of time. It does so by reprograming lbolt_cyclic from CY_INFINITY to
 * nsec_per_tick. The lbolt cyclic will remain ON while at least one CPU is
 * causing enough activity to cross the thresholds.
 */
int64_t
lbolt_bootstrap(void)
{
	return (0);
}

/* ARGSUSED */
uint_t
lbolt_ev_to_cyclic(caddr_t arg1, caddr_t arg2)
{
	hrtime_t ts, exp;
	int ret;

	ASSERT(lbolt_hybrid != lbolt_cyclic_driven);

	kpreempt_disable();

	ts = gethrtime();
	lb_info->lbi_internal = (ts/nsec_per_tick);

	/*
	 * Align the next expiration to a clock tick boundary.
	 */
	exp = ts + nsec_per_tick - 1;
	exp = (exp/nsec_per_tick) * nsec_per_tick;

	ret = cyclic_reprogram(lb_info->id.lbi_cyclic_id, exp);
	ASSERT(ret);

	lbolt_hybrid = lbolt_cyclic_driven;
	lb_info->lbi_cyc_deactivate = B_FALSE;
	lb_info->lbi_cyc_deac_start = lb_info->lbi_internal;

	kpreempt_enable();

	ret = atomic_dec_32_nv(&lb_info->lbi_token);
	ASSERT(ret == 0);

	return (1);
}

int64_t
lbolt_event_driven(void)
{
	hrtime_t ts;
	int64_t lb;
	int ret, cpu = CPU->cpu_seqid;

	ts = gethrtime();
	ASSERT(ts > 0);

	ASSERT(nsec_per_tick > 0);
	lb = (ts/nsec_per_tick);

	/*
	 * Switch to cyclic mode if the number of calls to this routine
	 * has reached the threshold within the interval.
	 */
	if ((lb - lb_cpu[cpu].lbc_cnt_start) < lb_info->lbi_thresh_interval) {

		if (--lb_cpu[cpu].lbc_counter == 0) {
			/*
			 * Reached the threshold within the interval, reset
			 * the usage statistics.
			 */
			lb_cpu[cpu].lbc_counter = lb_info->lbi_thresh_calls;
			lb_cpu[cpu].lbc_cnt_start = lb;

			/*
			 * Make sure only one thread reprograms the
			 * lbolt cyclic and changes the mode.
			 */
			if (panicstr == NULL &&
			    atomic_cas_32(&lb_info->lbi_token, 0, 1) == 0) {

				if (lbolt_hybrid == lbolt_cyclic_driven) {
					ret = atomic_dec_32_nv(
					    &lb_info->lbi_token);
					ASSERT(ret == 0);
				} else {
					lbolt_softint_post();
				}
			}
		}
	} else {
		/*
		 * Exceeded the interval, reset the usage statistics.
		 */
		lb_cpu[cpu].lbc_counter = lb_info->lbi_thresh_calls;
		lb_cpu[cpu].lbc_cnt_start = lb;
	}

	ASSERT(lb >= lb_info->lbi_debug_time);

	return (lb - lb_info->lbi_debug_time);
}

int64_t
lbolt_cyclic_driven(void)
{
	int64_t lb = lb_info->lbi_internal;
	int cpu;

	/*
	 * If a CPU has already prevented the lbolt cyclic from deactivating
	 * itself, don't bother tracking the usage. Otherwise check if we're
	 * within the interval and how the per CPU counter is doing.
	 */
	if (lb_info->lbi_cyc_deactivate) {
		cpu = CPU->cpu_seqid;
		if ((lb - lb_cpu[cpu].lbc_cnt_start) <
		    lb_info->lbi_thresh_interval) {

			if (lb_cpu[cpu].lbc_counter == 0)
				/*
				 * Reached the threshold within the interval,
				 * prevent the lbolt cyclic from turning itself
				 * off.
				 */
				lb_info->lbi_cyc_deactivate = B_FALSE;
			else
				lb_cpu[cpu].lbc_counter--;
		} else {
			/*
			 * Only reset the usage statistics when we have
			 * exceeded the interval.
			 */
			lb_cpu[cpu].lbc_counter = lb_info->lbi_thresh_calls;
			lb_cpu[cpu].lbc_cnt_start = lb;
		}
	}

	ASSERT(lb >= lb_info->lbi_debug_time);

	return (lb - lb_info->lbi_debug_time);
}

/*
 * The lbolt_cyclic() routine will fire at a nsec_per_tick interval to satisfy
 * performance needs of ddi_get_lbolt() and ddi_get_lbolt64() consumers.
 * It is inactive by default, and will be activated when switching from event
 * to cyclic driven lbolt. The cyclic will turn itself off unless signaled
 * by lbolt_cyclic_driven().
 */
static void
lbolt_cyclic(void)
{
	int ret;

	lb_info->lbi_internal++;

	if (!lbolt_cyc_only) {

		if (lb_info->lbi_cyc_deactivate) {
			/*
			 * Switching from cyclic to event driven mode.
			 */
			if (panicstr == NULL &&
			    atomic_cas_32(&lb_info->lbi_token, 0, 1) == 0) {

				if (lbolt_hybrid == lbolt_event_driven) {
					ret = atomic_dec_32_nv(
					    &lb_info->lbi_token);
					ASSERT(ret == 0);
					return;
				}

				kpreempt_disable();

				lbolt_hybrid = lbolt_event_driven;
				ret = cyclic_reprogram(
				    lb_info->id.lbi_cyclic_id,
				    CY_INFINITY);
				ASSERT(ret);

				kpreempt_enable();

				ret = atomic_dec_32_nv(&lb_info->lbi_token);
				ASSERT(ret == 0);
			}
		}

		/*
		 * The lbolt cyclic should not try to deactivate itself before
		 * the sampling period has elapsed.
		 */
		if (lb_info->lbi_internal - lb_info->lbi_cyc_deac_start >=
		    lb_info->lbi_thresh_interval) {
			lb_info->lbi_cyc_deactivate = B_TRUE;
			lb_info->lbi_cyc_deac_start = lb_info->lbi_internal;
		}
	}
}

/*
 * Since the lbolt service was historically cyclic driven, it must be 'stopped'
 * when the system drops into the kernel debugger. lbolt_debug_entry() is
 * called by the KDI system claim callbacks to record a hires timestamp at
 * debug enter time. lbolt_debug_return() is called by the sistem release
 * callbacks to account for the time spent in the debugger. The value is then
 * accumulated in the lb_info structure and used by lbolt_event_driven() and
 * lbolt_cyclic_driven(), as well as the mdb_get_lbolt() routine.
 */
void
lbolt_debug_entry(void)
{
	if (lbolt_hybrid != lbolt_bootstrap) {
		ASSERT(lb_info != NULL);
		lb_info->lbi_debug_ts = gethrtime();
	}
}

/*
 * Calculate the time spent in the debugger and add it to the lbolt info
 * structure. We also update the internal lbolt value in case we were in
 * cyclic driven mode going in.
 */
void
lbolt_debug_return(void)
{
	hrtime_t ts;

	if (lbolt_hybrid != lbolt_bootstrap) {
		ASSERT(lb_info != NULL);
		ASSERT(nsec_per_tick > 0);

		ts = gethrtime();
		lb_info->lbi_internal = (ts/nsec_per_tick);
		lb_info->lbi_debug_time +=
		    ((ts - lb_info->lbi_debug_ts)/nsec_per_tick);

		lb_info->lbi_debug_ts = 0;
	}
}
