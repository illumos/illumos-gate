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

#ifndef	_SYS_CAP_UTIL_H
#define	_SYS_CAP_UTIL_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/kcpc.h>
#include <sys/cpc_impl.h>
#include <sys/pghw.h>
#include <sys/cmt.h>

#ifdef	_KERNEL

/*
 * Capacity and utilization flags for each CPU
 */
#define	CU_CPU_CNTRS_ON		1	/* CPU performance counters are on */
#define	CU_CPU_CNTRS_OFF_ON	2	/* Off -> on transition */

/*
 * Macro that returns whether CPU performance counters turned on for given CPU
 */
#define	CU_CPC_ON(cp) \
	((cp) != NULL && (cp)->cpu_cu_info != NULL && \
	    ((cp)->cpu_cu_info->cu_flag & CU_CPU_CNTRS_ON))


/*
 * Per counter statistics
 */
typedef struct cu_cntr_stats {
	hrtime_t	cs_time_running; /* running total of time counting */
	hrtime_t	cs_time_stopped; /* ... time not counting */
	hrtime_t	cs_time_start;	/* start time of current sample  */
	uint64_t	cs_value_start;	/* starting value for next sample */
	uint64_t	cs_value_last;	/* last value */
	uint64_t	cs_value_total;	/* running total */
	uint64_t	cs_rate;	/* observed rate since last */
	uint64_t	cs_rate_max;	/* maximum rate */
	kcpc_request_t	*cs_cpc_req;	/* corresponding CPC request */
	struct cpu	*cs_cpu_start;	/* CPU where starting value gotten */
} cu_cntr_stats_t;


/*
 * Counter info for a PG hardware sharing relationship
 */
typedef struct cu_cntr_info {
	cpu_t		*ci_cpu;	/* CPU being measured */
	pghw_t		*ci_pg;		/* hardware PG being measured */
	kstat_t		*ci_kstat;	/* kstats being exported */
	cu_cntr_stats_t	*ci_stats;	/* counter statistics */
	uint_t		ci_nstats;	/* number of statistics */
} cu_cntr_info_t;


/*
 * Each CPU can have one or more CPC contexts for measuring capacity and
 * utilization
 *
 * One CPC context is needed per CPU if the counter events needed to measure
 * capacity and utilization on each CPU can be programmed onto all the counters
 * on a CPU at the same time and there are fewer or same number of desired
 * counter events as counters on each CPU.  Otherwise, the desired counter
 * events are assigned across multiple CPC contexts, so the contexts and their
 * counter events can be multiplexed onto the counters over time to get the
 * data for all of the counter events.
 */
typedef struct cu_cpc_ctx {
	int		cur_index;	/* index for current context */
	int		nctx;		/* number of CPC contexts */
	kcpc_ctx_t	**ctx_ptr_array; /* array of context pointers */
	size_t		ctx_ptr_array_sz; /* size of array */
} cu_cpc_ctx_t;

/*
 * Per CPU capacity and utilization info
 */
typedef struct cu_cpu_info {
	struct cpu	*cu_cpu;	/* CPU for the statistics */
	uint_t		cu_flag;	/* capacity & utilization flag */
	hrtime_t	cu_sample_time;	/* when last sample taken */
	cu_cpc_ctx_t	cu_cpc_ctx;	/* performance counter contexts */
	cu_cntr_stats_t	*cu_cntr_stats;	/* counter statistics array */
	uint_t		cu_ncntr_stats;	/* number of counter statistics */
	uint_t		cu_disabled;	/* count of disable requests */
	/*
	 * Per PG hardware sharing relationship counter info
	 */
	cu_cntr_info_t	*cu_cntr_info[PGHW_NUM_COMPONENTS];
} cu_cpu_info_t;

/*
 * COMMON INTERFACE ROUTINES
 */

/*
 * Setup capacity and utilization support
 */
extern void	cu_init(void);

/*
 * Tear down capacity and utilization support
 */
extern int	cu_fini(void);

/*
 * Program CPC for capacity and utilization on given CPU
 */
extern void	cu_cpc_program(struct cpu *, int *);

/*
 * Unprogram CPC for capacity and utilization on given CPU
 */
extern void	cu_cpc_unprogram(struct cpu *, int *);

/*
 * Update counter statistics on a given CPU
 */
extern int	cu_cpu_update(struct cpu *, boolean_t);

/*
 * Update utilization and capacity data for CMT PG
 */
extern void	cu_pg_update(pghw_t *);

/*
 * Disable or enable capacity and utilization on all CPUs
 */
extern void	cu_disable(void);
extern void	cu_enable(void);

/*
 * PLATFORM SPECIFIC INTERFACE ROUTINES
 */
extern int	cu_plat_cpc_init(cpu_t *, kcpc_request_list_t *, int);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CAP_UTIL_H */
