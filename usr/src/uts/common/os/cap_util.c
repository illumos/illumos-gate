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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Support for determining capacity and utilization of performance relevant
 * hardware components in a computer
 *
 * THEORY
 * ------
 * The capacity and utilization of the performance relevant hardware components
 * is needed to be able to optimize performance while minimizing the amount of
 * power used on a system.  The idea is to use hardware performance counters
 * and potentially other means to determine the capacity and utilization of
 * performance relevant hardware components (eg. execution pipeline, cache,
 * memory, etc.) and attribute the utilization to the responsible CPU and the
 * thread running there.
 *
 * This will help characterize the utilization of performance relevant
 * components and how much is used by each CPU and each thread.  With
 * that data, the utilization can be aggregated to all the CPUs sharing each
 * performance relevant hardware component to calculate the total utilization
 * of each component and compare that with the component's capacity to
 * essentially determine the actual hardware load of the component.  The
 * hardware utilization attributed to each running thread can also be
 * aggregated to determine the total hardware utilization of each component to
 * a workload.
 *
 * Once that is done, one can determine how much of each performance relevant
 * hardware component is needed by a given thread or set of threads (eg. a
 * workload) and size up exactly what hardware is needed by the threads and how
 * much.  With this info, we can better place threads among CPUs to match their
 * exact hardware resource needs and potentially lower or raise the power based
 * on their utilization or pack threads onto the fewest hardware components
 * needed and power off any remaining unused components to minimize power
 * without sacrificing performance.
 *
 * IMPLEMENTATION
 * --------------
 * The code has been designed and implemented to make (un)programming and
 * reading the counters for a given CPU as lightweight and fast as possible.
 * This is very important because we need to read and potentially (un)program
 * the counters very often and in performance sensitive code.  Specifically,
 * the counters may need to be (un)programmed during context switch and/or a
 * cyclic handler when there are more counter events to count than existing
 * counters.
 *
 * Consequently, the code has been split up to allow allocating and
 * initializing everything needed to program and read the counters on a given
 * CPU once and make (un)programming and reading the counters for a given CPU
 * not have to allocate/free memory or grab any locks.  To do this, all the
 * state needed to (un)program and read the counters on a CPU is kept per CPU
 * and is made lock free by forcing any code that reads or manipulates the
 * counters or the state needed to (un)program or read the counters to run on
 * the target CPU and disable preemption while running on the target CPU to
 * protect any critical sections. All counter manipulation on the target CPU is
 * happening either from a cross-call to the target CPU or at the same PIL as
 * used by the cross-call subsystem. This guarantees that counter manipulation
 * is not interrupted by cross-calls from other CPUs.
 *
 * The synchronization has been made lock free or as simple as possible for
 * performance and to avoid getting the locking all tangled up when we interpose
 * on the CPC routines that (un)program the counters to manage the counters
 * between the kernel and user on each CPU.  When the user starts using the
 * counters on a given CPU, the kernel will unprogram the counters that it is
 * using on that CPU just before they are programmed for the user.  Then the
 * kernel will program the counters on a given CPU for its own use when the user
 * stops using them.
 *
 * There is a special interaction with DTrace cpc provider (dcpc). Before dcpc
 * enables any probe, it requests to disable and unprogram all counters used for
 * capacity and utilizations. These counters are never re-programmed back until
 * dcpc completes. When all DTrace cpc probes are removed, dcpc notifies CU
 * framework and it re-programs the counters.
 *
 * When a CPU is going offline, its CU counters are unprogrammed and disabled,
 * so that they would not be re-programmed again by some other activity on the
 * CPU that is going offline.
 *
 * The counters are programmed during boot.  However, a flag is available to
 * disable this if necessary (see cu_flag below).  A handler is provided to
 * (un)program the counters during CPU on/offline.  Basic routines are provided
 * to initialize and tear down this module, initialize and tear down any state
 * needed for a given CPU, and (un)program the counters for a given CPU.
 * Lastly, a handler is provided to read the counters and attribute the
 * utilization to the responsible CPU.
 */
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/ddi.h>
#include <sys/systm.h>
#include <sys/disp.h>
#include <sys/sdt.h>
#include <sys/sunddi.h>
#include <sys/thread.h>
#include <sys/pghw.h>
#include <sys/cmt.h>
#include <sys/policy.h>
#include <sys/x_call.h>
#include <sys/cap_util.h>

#include <sys/archsystm.h>
#include <sys/promif.h>

#if defined(__x86)
#include <sys/xc_levels.h>
#endif


/*
 * Default CPU hardware performance counter flags to use for measuring capacity
 * and utilization
 */
#define	CU_CPC_FLAGS_DEFAULT	\
	(CPC_COUNT_USER|CPC_COUNT_SYSTEM|CPC_OVF_NOTIFY_EMT)

/*
 * Possible Flags for controlling this module.
 */
#define	CU_FLAG_ENABLE		1	/* Enable module */
#define	CU_FLAG_READY		2	/* Ready to setup module */
#define	CU_FLAG_ON		4	/* Module is on */

/*
 * pg_cpu kstats calculate utilization rate and maximum utilization rate for
 * some CPUs. The rate is calculated based on data from two subsequent
 * snapshots. When the time between such two snapshots is too small, the
 * resulting rate may have low accuracy, so we only consider snapshots which
 * are separated by SAMPLE_INTERVAL nanoseconds from one another. We do not
 * update the rate if the interval is smaller than that.
 *
 * Use one tenth of a second as the minimum interval for utilization rate
 * calculation.
 *
 * NOTE: The CU_SAMPLE_INTERVAL_MIN should be higher than the scaling factor in
 * the CU_RATE() macro below to guarantee that we never divide by zero.
 *
 * Rate is the number of events per second. The rate is the number of events
 * divided by time and multiplied by the number of nanoseconds in a second. We
 * do not want time to be too small since it will cause large errors in
 * division.
 *
 * We do not want to multiply two large numbers (the instruction count and
 * NANOSEC) either since it may cause integer overflow. So we divide both the
 * numerator and the denominator by the same value.
 *
 * NOTE: The scaling factor below should be less than CU_SAMPLE_INTERVAL_MIN
 * above to guarantee that time divided by this value is always non-zero.
 */
#define	CU_RATE(val, time) \
	(((val) * (NANOSEC / CU_SCALE)) / ((time) / CU_SCALE))

#define	CU_SAMPLE_INTERVAL_MIN	(NANOSEC / 10)

#define	CU_SCALE (CU_SAMPLE_INTERVAL_MIN / 10000)

/*
 * When the time between two kstat reads for the same CPU is less than
 * CU_UPDATE_THRESHOLD use the old counter data and skip updating counter values
 * for the CPU. This helps reduce cross-calls when kstat consumers read data
 * very often or when they read PG utilization data and then CPU utilization
 * data quickly after that.
 */
#define	CU_UPDATE_THRESHOLD (NANOSEC / 10)

/*
 * The IS_HIPIL() macro verifies that the code is executed either from a
 * cross-call or from high-PIL interrupt
 */
#ifdef DEBUG
#define	IS_HIPIL() (getpil() >= XCALL_PIL)
#else
#define	IS_HIPIL()
#endif	/* DEBUG */


typedef void (*cu_cpu_func_t)(uintptr_t, int *);


/*
 * Flags to use for programming CPU hardware performance counters to measure
 * capacity and utilization
 */
int				cu_cpc_flags = CU_CPC_FLAGS_DEFAULT;

/*
 * Initial value used for programming hardware counters
 */
uint64_t			cu_cpc_preset_value = 0;

/*
 * List of CPC event requests for capacity and utilization.
 */
static kcpc_request_list_t	*cu_cpc_reqs = NULL;

/*
 * When a CPU is a member of PG with a sharing relationship that is supported
 * by the capacity/utilization framework, a kstat is created for that CPU and
 * sharing relationship.
 *
 * These kstats are updated one at a time, so we can have a single scratch
 * space to fill the data.
 *
 * CPU counter kstats fields:
 *
 *   cu_cpu_id		CPU ID for this kstat
 *
 *   cu_pg_id		PG ID for this kstat
 *
 *   cu_generation	Generation value that increases whenever any CPU goes
 *			  offline or online. Two kstat snapshots for the same
 *			  CPU may only be compared if they have the same
 *			  generation.
 *
 *   cu_pg_id		PG ID for the relationship described by this kstat
 *
 *   cu_cpu_util	Running value of CPU utilization for the sharing
 *			  relationship
 *
 *   cu_cpu_time_running Total time spent collecting CU data. The time may be
 *			   less than wall time if CU counters were stopped for
 *			   some time.
 *
 *   cu_cpu_time_stopped Total time the CU counters were stopped.
 *
 *   cu_cpu_rate	Utilization rate, expressed in operations per second.
 *
 *   cu_cpu_rate_max	Maximum observed value of utilization rate.
 *
 *   cu_cpu_relationship Name of sharing relationship for the PG in this kstat
 */
struct cu_cpu_kstat {
	kstat_named_t	cu_cpu_id;
	kstat_named_t	cu_pg_id;
	kstat_named_t	cu_generation;
	kstat_named_t	cu_cpu_util;
	kstat_named_t	cu_cpu_time_running;
	kstat_named_t	cu_cpu_time_stopped;
	kstat_named_t	cu_cpu_rate;
	kstat_named_t	cu_cpu_rate_max;
	kstat_named_t	cu_cpu_relationship;
} cu_cpu_kstat = {
	{ "cpu_id",			KSTAT_DATA_UINT32 },
	{ "pg_id",			KSTAT_DATA_INT32 },
	{ "generation",			KSTAT_DATA_UINT32 },
	{ "hw_util",			KSTAT_DATA_UINT64 },
	{ "hw_util_time_running",	KSTAT_DATA_UINT64 },
	{ "hw_util_time_stopped",	KSTAT_DATA_UINT64 },
	{ "hw_util_rate",		KSTAT_DATA_UINT64 },
	{ "hw_util_rate_max",		KSTAT_DATA_UINT64 },
	{ "relationship",		KSTAT_DATA_STRING },
};

/*
 * Flags for controlling this module
 */
uint_t				cu_flags = CU_FLAG_ENABLE;

/*
 * Error return value for cu_init() since it can't return anything to be called
 * from mp_init_tbl[] (:-(
 */
static int			cu_init_error = 0;

hrtime_t			cu_sample_interval_min = CU_SAMPLE_INTERVAL_MIN;

hrtime_t			cu_update_threshold = CU_UPDATE_THRESHOLD;

static kmutex_t			pg_cpu_kstat_lock;


/*
 * Forward declaration of interface routines
 */
void		cu_disable(void);
void		cu_enable(void);
void		cu_init(void);
void		cu_cpc_program(cpu_t *cp, int *err);
void		cu_cpc_unprogram(cpu_t *cp, int *err);
int		cu_cpu_update(struct cpu *cp, boolean_t move_to);
void		cu_pg_update(pghw_t *pg);


/*
 * Forward declaration of private routines
 */
static int	cu_cpc_init(cpu_t *cp, kcpc_request_list_t *reqs, int nreqs);
static void	cu_cpc_program_xcall(uintptr_t arg, int *err);
static int	cu_cpc_req_add(char *event, kcpc_request_list_t *reqs,
    int nreqs, cu_cntr_stats_t *stats, int kmem_flags, int *nevents);
static int	cu_cpu_callback(cpu_setup_t what, int id, void *arg);
static void	cu_cpu_disable(cpu_t *cp);
static void	cu_cpu_enable(cpu_t *cp);
static int	cu_cpu_init(cpu_t *cp, kcpc_request_list_t *reqs);
static int	cu_cpu_fini(cpu_t *cp);
static void	cu_cpu_kstat_create(pghw_t *pg, cu_cntr_info_t *cntr_info);
static int	cu_cpu_kstat_update(kstat_t *ksp, int rw);
static int	cu_cpu_run(cpu_t *cp, cu_cpu_func_t func, uintptr_t arg);
static int	cu_cpu_update_stats(cu_cntr_stats_t *stats,
    uint64_t cntr_value);
static void cu_cpu_info_detach_xcall(void);

/*
 * Disable or enable Capacity Utilization counters on all CPUs.
 */
void
cu_disable(void)
{
	cpu_t *cp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	cp = cpu_active;
	do {
		if (!(cp->cpu_flags & CPU_OFFLINE))
			cu_cpu_disable(cp);
	} while ((cp = cp->cpu_next_onln) != cpu_active);
}


void
cu_enable(void)
{
	cpu_t *cp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	cp = cpu_active;
	do {
		if (!(cp->cpu_flags & CPU_OFFLINE))
			cu_cpu_enable(cp);
	} while ((cp = cp->cpu_next_onln) != cpu_active);
}


/*
 * Setup capacity and utilization support
 */
void
cu_init(void)
{
	cpu_t	*cp;

	cu_init_error = 0;
	if (!(cu_flags & CU_FLAG_ENABLE) || (cu_flags & CU_FLAG_ON)) {
		cu_init_error = -1;
		return;
	}

	if (kcpc_init() != 0) {
		cu_init_error = -2;
		return;
	}

	/*
	 * Can't measure hardware capacity and utilization without CPU
	 * hardware performance counters
	 */
	if (cpc_ncounters <= 0) {
		cu_init_error = -3;
		return;
	}

	/*
	 * Setup CPC event request queue
	 */
	cu_cpc_reqs = kcpc_reqs_init(cpc_ncounters, KM_SLEEP);

	mutex_enter(&cpu_lock);

	/*
	 * Mark flags to say that module is ready to be setup
	 */
	cu_flags |= CU_FLAG_READY;

	cp = cpu_active;
	do {
		/*
		 * Allocate and setup state needed to measure capacity and
		 * utilization
		 */
		if (cu_cpu_init(cp, cu_cpc_reqs) != 0)
			cu_init_error = -5;

		/*
		 * Reset list of counter event requests so its space can be
		 * reused for a different set of requests for next CPU
		 */
		(void) kcpc_reqs_reset(cu_cpc_reqs);

		cp = cp->cpu_next_onln;
	} while (cp != cpu_active);

	/*
	 * Mark flags to say that module is on now and counters are ready to be
	 * programmed on all active CPUs
	 */
	cu_flags |= CU_FLAG_ON;

	/*
	 * Program counters on currently active CPUs
	 */
	cp = cpu_active;
	do {
		if (cu_cpu_run(cp, cu_cpc_program_xcall,
		    (uintptr_t)B_FALSE) != 0)
			cu_init_error = -6;

		cp = cp->cpu_next_onln;
	} while (cp != cpu_active);

	/*
	 * Register callback for CPU state changes to enable and disable
	 * CPC counters as CPUs come on and offline
	 */
	register_cpu_setup_func(cu_cpu_callback, NULL);

	mutex_exit(&cpu_lock);
}


/*
 * Return number of counter events needed to measure capacity and utilization
 * for specified CPU and fill in list of CPC requests with each counter event
 * needed if list where to add CPC requests is given
 *
 * NOTE: Use KM_NOSLEEP for kmem_{,z}alloc() since cpu_lock is held and free
 *	 everything that has been successfully allocated if any memory
 *	 allocation fails
 */
static int
cu_cpc_init(cpu_t *cp, kcpc_request_list_t *reqs, int nreqs)
{
	group_t		*cmt_pgs;
	cu_cntr_info_t	**cntr_info_array;
	cpu_pg_t	*cpu_pgs;
	cu_cpu_info_t	*cu_cpu_info;
	pg_cmt_t	*pg_cmt;
	pghw_t		*pg_hw;
	cu_cntr_stats_t	*stats;
	int		nevents;
	pghw_type_t	pg_hw_type;
	group_iter_t	iter;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * There has to be a target CPU for this
	 */
	if (cp == NULL)
		return (-1);

	/*
	 * Return 0 when CPU doesn't belong to any group
	 */
	cpu_pgs = cp->cpu_pg;
	if (cpu_pgs == NULL || GROUP_SIZE(&cpu_pgs->cmt_pgs) < 1)
		return (0);

	cmt_pgs = &cpu_pgs->cmt_pgs;
	cu_cpu_info = cp->cpu_cu_info;

	/*
	 * Grab counter statistics and info
	 */
	if (reqs == NULL) {
		stats = NULL;
		cntr_info_array = NULL;
	} else {
		if (cu_cpu_info == NULL || cu_cpu_info->cu_cntr_stats == NULL)
			return (-2);

		stats = cu_cpu_info->cu_cntr_stats;
		cntr_info_array = cu_cpu_info->cu_cntr_info;
	}

	/*
	 * See whether platform (or processor) specific code knows which CPC
	 * events to request, etc. are needed to measure hardware capacity and
	 * utilization on this machine
	 */
	nevents = cu_plat_cpc_init(cp, reqs, nreqs);
	if (nevents >= 0)
		return (nevents);

	/*
	 * Let common code decide which CPC events to request, etc. to measure
	 * capacity and utilization since platform (or processor) specific does
	 * not know....
	 *
	 * Walk CPU's PG lineage and do following:
	 *
	 * - Setup CPC request, counter info, and stats needed for each counter
	 *   event to measure capacity and and utilization for each of CPU's PG
	 *   hardware sharing relationships
	 *
	 * - Create PG CPU kstats to export capacity and utilization for each PG
	 */
	nevents = 0;
	group_iter_init(&iter);
	while ((pg_cmt = group_iterate(cmt_pgs, &iter)) != NULL) {
		cu_cntr_info_t	*cntr_info;
		int		nevents_save;
		int		nstats;

		pg_hw = (pghw_t *)pg_cmt;
		pg_hw_type = pg_hw->pghw_hw;
		nevents_save = nevents;
		nstats = 0;

		switch (pg_hw_type) {
		case PGHW_IPIPE:
			if (cu_cpc_req_add("PAPI_tot_ins", reqs, nreqs, stats,
			    KM_NOSLEEP, &nevents) != 0)
				continue;
			nstats = 1;
			break;

		case PGHW_FPU:
			if (cu_cpc_req_add("PAPI_fp_ins", reqs, nreqs, stats,
			    KM_NOSLEEP, &nevents) != 0)
				continue;
			nstats = 1;
			break;

		default:
			/*
			 * Don't measure capacity and utilization for this kind
			 * of PG hardware relationship so skip to next PG in
			 * CPU's PG lineage
			 */
			continue;
		}

		cntr_info = cntr_info_array[pg_hw_type];

		/*
		 * Nothing to measure for this hardware sharing relationship
		 */
		if (nevents - nevents_save == 0) {
			if (cntr_info != NULL) {
				kmem_free(cntr_info, sizeof (cu_cntr_info_t));
				cntr_info_array[pg_hw_type] = NULL;
			}
			continue;
		}

		/*
		 * Fill in counter info for this PG hardware relationship
		 */
		if (cntr_info == NULL) {
			cntr_info = kmem_zalloc(sizeof (cu_cntr_info_t),
			    KM_NOSLEEP);
			if (cntr_info == NULL)
				continue;
			cntr_info_array[pg_hw_type] = cntr_info;
		}
		cntr_info->ci_cpu = cp;
		cntr_info->ci_pg = pg_hw;
		cntr_info->ci_stats = &stats[nevents_save];
		cntr_info->ci_nstats = nstats;

		/*
		 * Create PG CPU kstats for this hardware relationship
		 */
		cu_cpu_kstat_create(pg_hw, cntr_info);
	}

	return (nevents);
}


/*
 * Program counters for capacity and utilization on given CPU
 *
 * If any of the following conditions is true, the counters are not programmed:
 *
 * - CU framework is disabled
 * - The cpu_cu_info field of the cpu structure is NULL
 * - DTrace is active
 * - Counters are programmed already
 * - Counters are disabled (by calls to cu_cpu_disable())
 */
void
cu_cpc_program(cpu_t *cp, int *err)
{
	cu_cpc_ctx_t	*cpu_ctx;
	kcpc_ctx_t	*ctx;
	cu_cpu_info_t	*cu_cpu_info;

	ASSERT(IS_HIPIL());
	/*
	 * Should be running on given CPU. We disable preemption to keep CPU
	 * from disappearing and make sure flags and CPC context don't change
	 * from underneath us
	 */
	kpreempt_disable();
	ASSERT(cp == CPU);

	/*
	 * Module not ready to program counters
	 */
	if (!(cu_flags & CU_FLAG_ON)) {
		*err = -1;
		kpreempt_enable();
		return;
	}

	if (cp == NULL) {
		*err = -2;
		kpreempt_enable();
		return;
	}

	cu_cpu_info = cp->cpu_cu_info;
	if (cu_cpu_info == NULL) {
		*err = -3;
		kpreempt_enable();
		return;
	}

	/*
	 * If DTrace CPC is active or counters turned on already or are
	 * disabled, just return.
	 */
	if (dtrace_cpc_in_use || (cu_cpu_info->cu_flag & CU_CPU_CNTRS_ON) ||
	    cu_cpu_info->cu_disabled) {
		*err = 1;
		kpreempt_enable();
		return;
	}

	if ((CPU->cpu_cpc_ctx != NULL) &&
	    !(CPU->cpu_cpc_ctx->kc_flags & KCPC_CTX_INVALID_STOPPED)) {
		*err = -4;
		kpreempt_enable();
		return;
	}

	/*
	 * Get CPU's CPC context needed for capacity and utilization
	 */
	cpu_ctx = &cu_cpu_info->cu_cpc_ctx;
	ASSERT(cpu_ctx != NULL);
	ASSERT(cpu_ctx->nctx >= 0);

	ASSERT(cpu_ctx->ctx_ptr_array == NULL || cpu_ctx->ctx_ptr_array_sz > 0);
	ASSERT(cpu_ctx->nctx <= cpu_ctx->ctx_ptr_array_sz);
	if (cpu_ctx->nctx <= 0 || cpu_ctx->ctx_ptr_array == NULL ||
	    cpu_ctx->ctx_ptr_array_sz <= 0) {
		*err = -5;
		kpreempt_enable();
		return;
	}

	/*
	 * Increment index in CPU's CPC context info to point at next context
	 * to program
	 *
	 * NOTE: Do this now instead of after programming counters to ensure
	 *	 that index will always point at *current* context so we will
	 *	 always be able to unprogram *current* context if necessary
	 */
	cpu_ctx->cur_index = (cpu_ctx->cur_index + 1) % cpu_ctx->nctx;

	ctx = cpu_ctx->ctx_ptr_array[cpu_ctx->cur_index];

	/*
	 * Clear KCPC_CTX_INVALID and KCPC_CTX_INVALID_STOPPED from CPU's CPC
	 * context before programming counters
	 *
	 * Context is marked with KCPC_CTX_INVALID_STOPPED when context is
	 * unprogrammed and may be marked with KCPC_CTX_INVALID when
	 * kcpc_invalidate_all() is called by cpustat(1M) and dtrace CPC to
	 * invalidate all CPC contexts before they take over all the counters.
	 *
	 * This isn't necessary since these flags are only used for thread bound
	 * CPC contexts not CPU bound CPC contexts like ones used for capacity
	 * and utilization.
	 *
	 * There is no need to protect the flag update since no one is using
	 * this context now.
	 */
	ctx->kc_flags &= ~(KCPC_CTX_INVALID | KCPC_CTX_INVALID_STOPPED);

	/*
	 * Program counters on this CPU
	 */
	kcpc_program(ctx, B_FALSE, B_FALSE);

	cp->cpu_cpc_ctx = ctx;

	/*
	 * Set state in CPU structure to say that CPU's counters are programmed
	 * for capacity and utilization now and that they are transitioning from
	 * off to on state. This will cause cu_cpu_update to update stop times
	 * for all programmed counters.
	 */
	cu_cpu_info->cu_flag |= CU_CPU_CNTRS_ON | CU_CPU_CNTRS_OFF_ON;

	/*
	 * Update counter statistics
	 */
	(void) cu_cpu_update(cp, B_FALSE);

	cu_cpu_info->cu_flag &= ~CU_CPU_CNTRS_OFF_ON;

	*err = 0;
	kpreempt_enable();
}


/*
 * Cross call wrapper routine for cu_cpc_program()
 *
 * Checks to make sure that counters on CPU aren't being used by someone else
 * before calling cu_cpc_program() since cu_cpc_program() needs to assert that
 * nobody else is using the counters to catch and prevent any broken code.
 * Also, this check needs to happen on the target CPU since the CPU's CPC
 * context can only be changed while running on the CPU.
 *
 * If the first argument is TRUE, cu_cpc_program_xcall also checks that there is
 * no valid thread bound cpc context. This is important to check to prevent
 * re-programming thread counters with CU counters when CPU is coming on-line.
 */
static void
cu_cpc_program_xcall(uintptr_t arg, int *err)
{
	boolean_t	avoid_thread_context = (boolean_t)arg;

	kpreempt_disable();

	if (CPU->cpu_cpc_ctx != NULL &&
	    !(CPU->cpu_cpc_ctx->kc_flags & KCPC_CTX_INVALID_STOPPED)) {
		*err = -100;
		kpreempt_enable();
		return;
	}

	if (avoid_thread_context && (curthread->t_cpc_ctx != NULL) &&
	    !(curthread->t_cpc_ctx->kc_flags & KCPC_CTX_INVALID_STOPPED)) {
		*err = -200;
		kpreempt_enable();
		return;
	}

	cu_cpc_program(CPU, err);
	kpreempt_enable();
}


/*
 * Unprogram counters for capacity and utilization on given CPU
 * This function should be always executed on the target CPU at high PIL
 */
void
cu_cpc_unprogram(cpu_t *cp, int *err)
{
	cu_cpc_ctx_t	*cpu_ctx;
	kcpc_ctx_t	*ctx;
	cu_cpu_info_t	*cu_cpu_info;

	ASSERT(IS_HIPIL());
	/*
	 * Should be running on given CPU with preemption disabled to keep CPU
	 * from disappearing and make sure flags and CPC context don't change
	 * from underneath us
	 */
	kpreempt_disable();
	ASSERT(cp == CPU);

	/*
	 * Module not on
	 */
	if (!(cu_flags & CU_FLAG_ON)) {
		*err = -1;
		kpreempt_enable();
		return;
	}

	cu_cpu_info = cp->cpu_cu_info;
	if (cu_cpu_info == NULL) {
		*err = -3;
		kpreempt_enable();
		return;
	}

	/*
	 * Counters turned off already
	 */
	if (!(cu_cpu_info->cu_flag & CU_CPU_CNTRS_ON)) {
		*err = 1;
		kpreempt_enable();
		return;
	}

	/*
	 * Update counter statistics
	 */
	(void) cu_cpu_update(cp, B_FALSE);

	/*
	 * Get CPU's CPC context needed for capacity and utilization
	 */
	cpu_ctx = &cu_cpu_info->cu_cpc_ctx;
	if (cpu_ctx->nctx <= 0 || cpu_ctx->ctx_ptr_array == NULL ||
	    cpu_ctx->ctx_ptr_array_sz <= 0) {
		*err = -5;
		kpreempt_enable();
		return;
	}
	ctx = cpu_ctx->ctx_ptr_array[cpu_ctx->cur_index];

	/*
	 * CPU's CPC context should be current capacity and utilization CPC
	 * context
	 */
	ASSERT(cp->cpu_cpc_ctx == ctx);
	if (cp->cpu_cpc_ctx != ctx) {
		*err = -6;
		kpreempt_enable();
		return;
	}

	/*
	 * Unprogram counters on CPU.
	 */
	kcpc_unprogram(ctx, B_FALSE);

	ASSERT(ctx->kc_flags & KCPC_CTX_INVALID_STOPPED);

	/*
	 * Unset state in CPU structure saying that CPU's counters are
	 * programmed
	 */
	cp->cpu_cpc_ctx = NULL;
	cu_cpu_info->cu_flag &= ~CU_CPU_CNTRS_ON;

	*err = 0;
	kpreempt_enable();
}


/*
 * Add given counter event to list of CPC requests
 */
static int
cu_cpc_req_add(char *event, kcpc_request_list_t *reqs, int nreqs,
    cu_cntr_stats_t *stats, int kmem_flags, int *nevents)
{
	int	n;
	int	retval;
	uint_t  flags;

	/*
	 * Return error when no counter event specified, counter event not
	 * supported by CPC's PCBE, or number of events not given
	 */
	if (event == NULL || kcpc_event_supported(event) == B_FALSE ||
	    nevents == NULL)
		return (-1);

	n = *nevents;

	/*
	 * Only count number of counter events needed if list
	 * where to add CPC requests not given
	 */
	if (reqs == NULL) {
		n++;
		*nevents = n;
		return (-3);
	}

	/*
	 * Return error when stats not given or not enough room on list of CPC
	 * requests for more counter events
	 */
	if (stats == NULL || (nreqs <= 0 && n >= nreqs))
		return (-4);

	/*
	 * Use flags in cu_cpc_flags to program counters and enable overflow
	 * interrupts/traps (unless PCBE can't handle overflow interrupts) so
	 * PCBE can catch counters before they wrap to hopefully give us an
	 * accurate (64-bit) virtualized counter
	 */
	flags = cu_cpc_flags;
	if ((kcpc_pcbe_capabilities() & CPC_CAP_OVERFLOW_INTERRUPT) == 0)
		flags &= ~CPC_OVF_NOTIFY_EMT;

	/*
	 * Add CPC request to list
	 */
	retval = kcpc_reqs_add(reqs, event, cu_cpc_preset_value,
	    flags, 0, NULL, &stats[n], kmem_flags);

	if (retval != 0)
		return (-5);

	n++;
	*nevents = n;
	return (0);
}

static void
cu_cpu_info_detach_xcall(void)
{
	ASSERT(IS_HIPIL());

	CPU->cpu_cu_info = NULL;
}


/*
 * Enable or disable collection of capacity/utilization data for a current CPU.
 * Counters are enabled if 'on' argument is True and disabled if it is False.
 * This function should be always executed at high PIL
 */
static void
cu_cpc_trigger(uintptr_t arg1, uintptr_t arg2)
{
	cpu_t		*cp = (cpu_t *)arg1;
	boolean_t	on = (boolean_t)arg2;
	int		error;
	cu_cpu_info_t	*cu_cpu_info;

	ASSERT(IS_HIPIL());
	kpreempt_disable();
	ASSERT(cp == CPU);

	if (!(cu_flags & CU_FLAG_ON)) {
		kpreempt_enable();
		return;
	}

	cu_cpu_info = cp->cpu_cu_info;
	if (cu_cpu_info == NULL) {
		kpreempt_enable();
		return;
	}

	ASSERT(!cu_cpu_info->cu_disabled ||
	    !(cu_cpu_info->cu_flag & CU_CPU_CNTRS_ON));

	if (on) {
		/*
		 * Decrement the cu_disabled counter.
		 * Once it drops to zero, call cu_cpc_program.
		 */
		if (cu_cpu_info->cu_disabled > 0)
			cu_cpu_info->cu_disabled--;
		if (cu_cpu_info->cu_disabled == 0)
			cu_cpc_program(CPU, &error);
	} else if (cu_cpu_info->cu_disabled++ == 0) {
		/*
		 * This is the first attempt to disable CU, so turn it off
		 */
		cu_cpc_unprogram(cp, &error);
		ASSERT(!(cu_cpu_info->cu_flag & CU_CPU_CNTRS_ON));
	}

	kpreempt_enable();
}


/*
 * Callback for changes in CPU states
 * Used to enable or disable hardware performance counters on CPUs that are
 * turned on or off
 *
 * NOTE: cpc should be programmed/unprogrammed while running on the target CPU.
 * We have to use thread_affinity_set to hop to the right CPU because these
 * routines expect cpu_lock held, so we can't cross-call other CPUs while
 * holding CPU lock.
 */
static int
/* LINTED E_FUNC_ARG_UNUSED */
cu_cpu_callback(cpu_setup_t what, int id, void *arg)
{
	cpu_t	*cp;
	int	retval = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (!(cu_flags & CU_FLAG_ON))
		return (-1);

	cp = cpu_get(id);
	if (cp == NULL)
		return (-2);

	switch (what) {
	case CPU_ON:
		/*
		 * Setup counters on CPU being turned on
		 */
		retval = cu_cpu_init(cp, cu_cpc_reqs);

		/*
		 * Reset list of counter event requests so its space can be
		 * reused for a different set of requests for next CPU
		 */
		(void) kcpc_reqs_reset(cu_cpc_reqs);
		break;
	case CPU_INTR_ON:
		/*
		 * Setup counters on CPU being turned on.
		 */
		retval = cu_cpu_run(cp, cu_cpc_program_xcall,
		    (uintptr_t)B_TRUE);
		break;
	case CPU_OFF:
		/*
		 * Disable counters on CPU being turned off. Counters will not
		 * be re-enabled on this CPU until it comes back online.
		 */
		cu_cpu_disable(cp);
		ASSERT(!CU_CPC_ON(cp));
		retval = cu_cpu_fini(cp);
		break;
	default:
		break;
	}
	return (retval);
}


/*
 * Disable or enable Capacity Utilization counters on a given CPU. This function
 * can be called from any CPU to disable counters on the given CPU.
 */
static void
cu_cpu_disable(cpu_t *cp)
{
	cpu_call(cp, cu_cpc_trigger, (uintptr_t)cp, (uintptr_t)B_FALSE);
}


static void
cu_cpu_enable(cpu_t *cp)
{
	cpu_call(cp, cu_cpc_trigger, (uintptr_t)cp, (uintptr_t)B_TRUE);
}


/*
 * Setup capacity and utilization support for given CPU
 *
 * NOTE: Use KM_NOSLEEP for kmem_{,z}alloc() since cpu_lock is held and free
 *	 everything that has been successfully allocated including cpu_cu_info
 *	if any memory allocation fails
 */
static int
cu_cpu_init(cpu_t *cp, kcpc_request_list_t *reqs)
{
	kcpc_ctx_t	**ctx_ptr_array;
	size_t		ctx_ptr_array_sz;
	cu_cpc_ctx_t	*cpu_ctx;
	cu_cpu_info_t	*cu_cpu_info;
	int		n;

	/*
	 * cpu_lock should be held and protect against CPU going away and races
	 * with cu_{init,fini,cpu_fini}()
	 */
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Return if not ready to setup counters yet
	 */
	if (!(cu_flags & CU_FLAG_READY))
		return (-1);

	if (cp->cpu_cu_info == NULL) {
		cp->cpu_cu_info = kmem_zalloc(sizeof (cu_cpu_info_t),
		    KM_NOSLEEP);
		if (cp->cpu_cu_info == NULL)
			return (-2);
	}

	/*
	 * Get capacity and utilization CPC context for CPU and check to see
	 * whether it has been setup already
	 */
	cu_cpu_info = cp->cpu_cu_info;
	cu_cpu_info->cu_cpu = cp;
	cu_cpu_info->cu_disabled = dtrace_cpc_in_use ? 1 : 0;

	cpu_ctx = &cu_cpu_info->cu_cpc_ctx;
	if (cpu_ctx->nctx > 0 && cpu_ctx->ctx_ptr_array != NULL &&
	    cpu_ctx->ctx_ptr_array_sz > 0) {
		return (1);
	}

	/*
	 * Should have no contexts since it hasn't been setup already
	 */
	ASSERT(cpu_ctx->nctx == 0 && cpu_ctx->ctx_ptr_array == NULL &&
	    cpu_ctx->ctx_ptr_array_sz == 0);

	/*
	 * Determine how many CPC events needed to measure capacity and
	 * utilization for this CPU, allocate space for counter statistics for
	 * each event, and fill in list of CPC event requests with corresponding
	 * counter stats for each request to make attributing counter data
	 * easier later....
	 */
	n = cu_cpc_init(cp, NULL, 0);
	if (n <= 0) {
		(void) cu_cpu_fini(cp);
		return (-3);
	}

	cu_cpu_info->cu_cntr_stats = kmem_zalloc(n * sizeof (cu_cntr_stats_t),
	    KM_NOSLEEP);
	if (cu_cpu_info->cu_cntr_stats == NULL) {
		(void) cu_cpu_fini(cp);
		return (-4);
	}

	cu_cpu_info->cu_ncntr_stats = n;

	n = cu_cpc_init(cp, reqs, n);
	if (n <= 0) {
		(void) cu_cpu_fini(cp);
		return (-5);
	}

	/*
	 * Create CPC context with given requests
	 */
	ctx_ptr_array = NULL;
	ctx_ptr_array_sz = 0;
	n = kcpc_cpu_ctx_create(cp, reqs, KM_NOSLEEP, &ctx_ptr_array,
	    &ctx_ptr_array_sz);
	if (n <= 0) {
		(void) cu_cpu_fini(cp);
		return (-6);
	}

	/*
	 * Should have contexts
	 */
	ASSERT(n > 0 && ctx_ptr_array != NULL && ctx_ptr_array_sz > 0);
	if (ctx_ptr_array == NULL || ctx_ptr_array_sz <= 0) {
		(void) cu_cpu_fini(cp);
		return (-7);
	}

	/*
	 * Fill in CPC context info for CPU needed for capacity and utilization
	 */
	cpu_ctx->cur_index = 0;
	cpu_ctx->nctx = n;
	cpu_ctx->ctx_ptr_array = ctx_ptr_array;
	cpu_ctx->ctx_ptr_array_sz = ctx_ptr_array_sz;
	return (0);
}

/*
 * Tear down capacity and utilization support for given CPU
 */
static int
cu_cpu_fini(cpu_t *cp)
{
	kcpc_ctx_t	*ctx;
	cu_cpc_ctx_t	*cpu_ctx;
	cu_cpu_info_t	*cu_cpu_info;
	int		i;
	pghw_type_t	pg_hw_type;

	/*
	 * cpu_lock should be held and protect against CPU going away and races
	 * with cu_{init,fini,cpu_init}()
	 */
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Have to at least be ready to setup counters to have allocated
	 * anything that needs to be deallocated now
	 */
	if (!(cu_flags & CU_FLAG_READY))
		return (-1);

	/*
	 * Nothing to do if CPU's capacity and utilization info doesn't exist
	 */
	cu_cpu_info = cp->cpu_cu_info;
	if (cu_cpu_info == NULL)
		return (1);

	/*
	 * Tear down any existing kstats and counter info for each hardware
	 * sharing relationship
	 */
	for (pg_hw_type = PGHW_START; pg_hw_type < PGHW_NUM_COMPONENTS;
	    pg_hw_type++) {
		cu_cntr_info_t	*cntr_info;

		cntr_info = cu_cpu_info->cu_cntr_info[pg_hw_type];
		if (cntr_info == NULL)
			continue;

		if (cntr_info->ci_kstat != NULL) {
			kstat_delete(cntr_info->ci_kstat);
			cntr_info->ci_kstat = NULL;
		}
		kmem_free(cntr_info, sizeof (cu_cntr_info_t));
	}

	/*
	 * Free counter statistics for CPU
	 */
	ASSERT(cu_cpu_info->cu_cntr_stats == NULL ||
	    cu_cpu_info->cu_ncntr_stats > 0);
	if (cu_cpu_info->cu_cntr_stats != NULL &&
	    cu_cpu_info->cu_ncntr_stats > 0) {
		kmem_free(cu_cpu_info->cu_cntr_stats,
		    cu_cpu_info->cu_ncntr_stats * sizeof (cu_cntr_stats_t));
		cu_cpu_info->cu_cntr_stats = NULL;
		cu_cpu_info->cu_ncntr_stats = 0;
	}

	/*
	 * Get capacity and utilization CPC contexts for given CPU and check to
	 * see whether they have been freed already
	 */
	cpu_ctx = &cu_cpu_info->cu_cpc_ctx;
	if (cpu_ctx != NULL && cpu_ctx->ctx_ptr_array != NULL &&
	    cpu_ctx->ctx_ptr_array_sz > 0) {
		/*
		 * Free CPC contexts for given CPU
		 */
		for (i = 0; i < cpu_ctx->nctx; i++) {
			ctx = cpu_ctx->ctx_ptr_array[i];
			if (ctx == NULL)
				continue;
			kcpc_free(ctx, 0);
		}

		/*
		 * Free CPC context pointer array
		 */
		kmem_free(cpu_ctx->ctx_ptr_array, cpu_ctx->ctx_ptr_array_sz);

		/*
		 * Zero CPC info for CPU
		 */
		bzero(cpu_ctx, sizeof (cu_cpc_ctx_t));
	}

	/*
	 * Set cp->cpu_cu_info pointer to NULL. Go through cross-call to ensure
	 * that no one is going to access the cpu_cu_info whicch we are going to
	 * free.
	 */
	if (cpu_is_online(cp))
		cpu_call(cp, (cpu_call_func_t)cu_cpu_info_detach_xcall, 0, 0);
	else
		cp->cpu_cu_info = NULL;

	/*
	 * Free CPU's capacity and utilization info
	 */
	kmem_free(cu_cpu_info, sizeof (cu_cpu_info_t));

	return (0);
}

/*
 * Create capacity & utilization kstats for given PG CPU hardware sharing
 * relationship
 */
static void
cu_cpu_kstat_create(pghw_t *pg, cu_cntr_info_t *cntr_info)
{
	kstat_t		*ks;
	char 		*sharing = pghw_type_string(pg->pghw_hw);
	char		name[KSTAT_STRLEN + 1];

	/*
	 * Just return when no counter info or CPU
	 */
	if (cntr_info == NULL || cntr_info->ci_cpu == NULL)
		return;

	/*
	 * Canonify PG name to conform to kstat name rules
	 */
	(void) strncpy(name, pghw_type_string(pg->pghw_hw), KSTAT_STRLEN + 1);
	strident_canon(name, TASKQ_NAMELEN + 1);

	if ((ks = kstat_create_zone("pg_hw_perf_cpu",
	    cntr_info->ci_cpu->cpu_id,
	    name, "processor_group", KSTAT_TYPE_NAMED,
	    sizeof (cu_cpu_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, GLOBAL_ZONEID)) == NULL)
		return;

	ks->ks_lock = &pg_cpu_kstat_lock;
	ks->ks_data = &cu_cpu_kstat;
	ks->ks_update = cu_cpu_kstat_update;
	ks->ks_data_size += strlen(sharing) + 1;

	ks->ks_private = cntr_info;
	cntr_info->ci_kstat = ks;
	kstat_install(cntr_info->ci_kstat);
}


/*
 * Propagate values from CPU capacity & utilization stats to kstats
 */
static int
cu_cpu_kstat_update(kstat_t *ksp, int rw)
{
	cpu_t		*cp;
	cu_cntr_info_t	*cntr_info = ksp->ks_private;
	struct cu_cpu_kstat	*kstat = &cu_cpu_kstat;
	pghw_t		*pg;
	cu_cntr_stats_t	*stats;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	cp = cntr_info->ci_cpu;
	pg = cntr_info->ci_pg;
	kstat->cu_cpu_id.value.ui32 = cp->cpu_id;
	kstat->cu_pg_id.value.i32 = ((pg_t *)pg)->pg_id;

	/*
	 * The caller should have priv_cpc_cpu privilege to get utilization
	 * data. Callers who do not have the privilege will see zeroes as the
	 * values.
	 */
	if (secpolicy_cpc_cpu(crgetcred()) != 0) {
		kstat->cu_generation.value.ui32 = cp->cpu_generation;
		kstat_named_setstr(&kstat->cu_cpu_relationship,
		    pghw_type_string(pg->pghw_hw));

		kstat->cu_cpu_util.value.ui64 = 0;
		kstat->cu_cpu_rate.value.ui64 = 0;
		kstat->cu_cpu_rate_max.value.ui64 = 0;
		kstat->cu_cpu_time_running.value.ui64 = 0;
		kstat->cu_cpu_time_stopped.value.ui64 = 0;

		return (0);
	}

	kpreempt_disable();

	/*
	 * Update capacity and utilization statistics needed for CPU's PG (CPU)
	 * kstats
	 */

	(void) cu_cpu_update(cp, B_TRUE);

	stats = cntr_info->ci_stats;
	kstat->cu_generation.value.ui32 = cp->cpu_generation;
	kstat_named_setstr(&kstat->cu_cpu_relationship,
	    pghw_type_string(pg->pghw_hw));

	kstat->cu_cpu_util.value.ui64 = stats->cs_value_total;
	kstat->cu_cpu_rate.value.ui64 = stats->cs_rate;
	kstat->cu_cpu_rate_max.value.ui64 = stats->cs_rate_max;
	kstat->cu_cpu_time_running.value.ui64 = stats->cs_time_running;
	kstat->cu_cpu_time_stopped.value.ui64 = stats->cs_time_stopped;

	/*
	 * Counters are stopped now, so the cs_time_stopped was last
	 * updated at cs_time_start time. Add the time passed since then
	 * to the stopped time.
	 */
	if (!(cp->cpu_cu_info->cu_flag & CU_CPU_CNTRS_ON))
		kstat->cu_cpu_time_stopped.value.ui64 +=
		    gethrtime() - stats->cs_time_start;

	kpreempt_enable();

	return (0);
}

/*
 * Run specified function with specified argument on a given CPU and return
 * whatever the function returns
 */
static int
cu_cpu_run(cpu_t *cp, cu_cpu_func_t func, uintptr_t arg)
{
	int error = 0;

	/*
	 * cpu_call() will call func on the CPU specified with given argument
	 * and return func's return value in last argument
	 */
	cpu_call(cp, (cpu_call_func_t)func, arg, (uintptr_t)&error);
	return (error);
}


/*
 * Update counter statistics on a given CPU.
 *
 * If move_to argument is True, execute the function on the CPU specified
 * Otherwise, assume that it is already runninng on the right CPU
 *
 * If move_to is specified, the caller should hold cpu_lock or have preemption
 * disabled. Otherwise it is up to the caller to guarantee that things do not
 * change in the process.
 */
int
cu_cpu_update(struct cpu *cp, boolean_t move_to)
{
	int	retval;
	cu_cpu_info_t	*cu_cpu_info = cp->cpu_cu_info;
	hrtime_t	time_snap;

	ASSERT(!move_to || MUTEX_HELD(&cpu_lock) || curthread->t_preempt > 0);

	/*
	 * Nothing to do if counters are not programmed
	 */
	if (!(cu_flags & CU_FLAG_ON) ||
	    (cu_cpu_info == NULL) ||
	    !(cu_cpu_info->cu_flag & CU_CPU_CNTRS_ON))
		return (0);

	/*
	 * Don't update CPU statistics if it was updated recently
	 * and provide old results instead
	 */
	time_snap = gethrtime();
	if ((time_snap - cu_cpu_info->cu_sample_time) < cu_update_threshold) {
		DTRACE_PROBE1(cu__drop__sample, cpu_t *, cp);
		return (0);
	}

	cu_cpu_info->cu_sample_time = time_snap;

	/*
	 * CPC counter should be read on the CPU that is running the counter. We
	 * either have to move ourselves to the target CPU or insure that we
	 * already run there.
	 *
	 * We use cross-call to the target CPU to execute kcpc_read() and
	 * cu_cpu_update_stats() there.
	 */
	retval = 0;
	if (move_to)
		(void) cu_cpu_run(cp, (cu_cpu_func_t)kcpc_read,
		    (uintptr_t)cu_cpu_update_stats);
	else {
		retval = kcpc_read((kcpc_update_func_t)cu_cpu_update_stats);
		/*
		 * Offset negative return value by -10 so we can distinguish it
		 * from error return values of this routine vs kcpc_read()
		 */
		if (retval < 0)
			retval -= 10;
	}

	return (retval);
}


/*
 * Update CPU counter statistics for current CPU.
 * This function may be called from a cross-call
 */
static int
cu_cpu_update_stats(cu_cntr_stats_t *stats, uint64_t cntr_value)
{
	cu_cpu_info_t	*cu_cpu_info = CPU->cpu_cu_info;
	uint_t		flags;
	uint64_t	delta;
	hrtime_t	time_delta;
	hrtime_t	time_snap;

	if (stats == NULL)
		return (-1);

	/*
	 * Nothing to do if counters are not programmed. This should not happen,
	 * but we check just in case.
	 */
	ASSERT(cu_flags & CU_FLAG_ON);
	ASSERT(cu_cpu_info != NULL);
	if (!(cu_flags & CU_FLAG_ON) ||
	    (cu_cpu_info == NULL))
		return (-2);

	flags = cu_cpu_info->cu_flag;
	ASSERT(flags & CU_CPU_CNTRS_ON);
	if (!(flags & CU_CPU_CNTRS_ON))
		return (-2);

	/*
	 * Take snapshot of high resolution timer
	 */
	time_snap = gethrtime();

	/*
	 * CU counters have just been programmed. We cannot assume that the new
	 * cntr_value continues from where we left off, so use the cntr_value as
	 * the new initial value.
	 */
	if (flags & CU_CPU_CNTRS_OFF_ON)
		stats->cs_value_start = cntr_value;

	/*
	 * Calculate delta in counter values between start of sampling period
	 * and now
	 */
	delta = cntr_value - stats->cs_value_start;

	/*
	 * Calculate time between start of sampling period and now
	 */
	time_delta = stats->cs_time_start ?
	    time_snap - stats->cs_time_start :
	    0;
	stats->cs_time_start = time_snap;
	stats->cs_value_start = cntr_value;

	if (time_delta > 0) { /* wrap shouldn't happen */
		/*
		 * Update either running or stopped time based on the transition
		 * state
		 */
		if (flags & CU_CPU_CNTRS_OFF_ON)
			stats->cs_time_stopped += time_delta;
		else
			stats->cs_time_running += time_delta;
	}

	/*
	 * Update rest of counter statistics if counter value didn't wrap
	 */
	if (delta > 0) {
		/*
		 * Update utilization rate if the interval between samples is
		 * sufficient.
		 */
		ASSERT(cu_sample_interval_min > CU_SCALE);
		if (time_delta > cu_sample_interval_min)
			stats->cs_rate = CU_RATE(delta, time_delta);
		if (stats->cs_rate_max < stats->cs_rate)
			stats->cs_rate_max = stats->cs_rate;

		stats->cs_value_last = delta;
		stats->cs_value_total += delta;
	}

	return (0);
}

/*
 * Update CMT PG utilization data.
 *
 * This routine computes the running total utilization and times for the
 * specified PG by adding up the total utilization and counter running and
 * stopped times of all CPUs in the PG and calculates the utilization rate and
 * maximum rate for all CPUs in the PG.
 */
void
cu_pg_update(pghw_t *pg)
{
	pg_cpu_itr_t	cpu_iter;
	pghw_type_t	pg_hwtype;
	cpu_t		*cpu;
	pghw_util_t	*hw_util = &pg->pghw_stats;
	uint64_t	old_utilization = hw_util->pghw_util;
	hrtime_t	now;
	hrtime_t	time_delta;
	uint64_t	utilization_delta;

	ASSERT(MUTEX_HELD(&cpu_lock));

	now = gethrtime();

	pg_hwtype = pg->pghw_hw;

	/*
	 * Initialize running total utilization and times for PG to 0
	 */
	hw_util->pghw_util = 0;
	hw_util->pghw_time_running = 0;
	hw_util->pghw_time_stopped = 0;

	/*
	 * Iterate over all CPUs in the PG and aggregate utilization, running
	 * time and stopped time.
	 */
	PG_CPU_ITR_INIT(pg, cpu_iter);
	while ((cpu = pg_cpu_next(&cpu_iter)) != NULL) {
		cu_cpu_info_t	*cu_cpu_info = cpu->cpu_cu_info;
		cu_cntr_info_t	*cntr_info;
		cu_cntr_stats_t	*stats;

		if (cu_cpu_info == NULL)
			continue;

		/*
		 * Update utilization data for the CPU and then
		 * aggregate per CPU running totals for PG
		 */
		(void) cu_cpu_update(cpu, B_TRUE);
		cntr_info = cu_cpu_info->cu_cntr_info[pg_hwtype];

		if (cntr_info == NULL || (stats = cntr_info->ci_stats) == NULL)
			continue;

		hw_util->pghw_util += stats->cs_value_total;
		hw_util->pghw_time_running += stats->cs_time_running;
		hw_util->pghw_time_stopped += stats->cs_time_stopped;

		/*
		 * If counters are stopped now, the pg_time_stopped was last
		 * updated at cs_time_start time. Add the time passed since then
		 * to the stopped time.
		 */
		if (!(cu_cpu_info->cu_flag & CU_CPU_CNTRS_ON))
			hw_util->pghw_time_stopped +=
			    now - stats->cs_time_start;
	}

	/*
	 * Compute per PG instruction rate and maximum rate
	 */
	time_delta = now - hw_util->pghw_time_stamp;
	hw_util->pghw_time_stamp = now;

	if (old_utilization == 0)
		return;

	/*
	 * Calculate change in utilization over sampling period and set this to
	 * 0 if the delta would be 0 or negative which may happen if any CPUs go
	 * offline during the sampling period
	 */
	if (hw_util->pghw_util > old_utilization)
		utilization_delta = hw_util->pghw_util - old_utilization;
	else
		utilization_delta = 0;

	/*
	 * Update utilization rate if the interval between samples is
	 * sufficient.
	 */
	ASSERT(cu_sample_interval_min > CU_SCALE);
	if (time_delta > CU_SAMPLE_INTERVAL_MIN)
		hw_util->pghw_rate = CU_RATE(utilization_delta, time_delta);

	/*
	 * Update the maximum observed rate
	 */
	if (hw_util->pghw_rate_max < hw_util->pghw_rate)
		hw_util->pghw_rate_max = hw_util->pghw_rate;
}
