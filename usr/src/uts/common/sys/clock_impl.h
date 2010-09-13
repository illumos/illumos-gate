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
 */

#ifndef	_SYS_CLOCK_IMPL_H
#define	_SYS_CLOCK_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#if (defined(_KERNEL) || defined(_KMEMUSER))
#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/cyclic.h>
#include <sys/time.h>

/*
 * Default clock rate in Hz.
 */
#define	HZ_DEFAULT			(100)

/*
 * Thresholds over which we switch between event and cyclic driven lbolt. The
 * current default values were derived experimentally and will keep the
 * system on event driven mode when idle and respond to activity around the
 * lbolt DDI functions by switching to cyclic mode.
 */
#define	LBOLT_THRESH_CALLS		(75)
#define	LBOLT_THRESH_INTERVAL		(1)

/*
 * Both lbolt_cpu_t and lbolt_info_t are cache line sized and aligned,
 * please take that in consideration if modifying these.
 */
typedef struct lbolt_cpu {
	int64_t lbc_counter;	/* number of calls to the DDI lbolt routines */
	int64_t lbc_cnt_start;	/* beggining of the cnt interval (in ticks) */
	char lbc_pad[CPU_CACHE_COHERENCE_SIZE - (2 * sizeof (int64_t))];
} lbolt_cpu_t;

typedef struct lbolt_info {
	union {
		cyclic_id_t lbi_cyclic_id;	/* lbolt's cyclic id */
		int64_t lbi_id_pad;		/* 64bit padding */
	} id;
	int64_t lbi_thresh_calls;	/* max calls per interval */
	int64_t lbi_thresh_interval;	/* interval window for the # of calls */
	int64_t lbi_debug_ts;		/* last time we dropped into kmdb */
	int64_t lbi_debug_time;		/* time spent in the debugger */
	int64_t lbi_internal;		/* lbolt source when on cyclic mode */
	uint32_t lbi_token;		/* synchronize cyclic mode switch */
	boolean_t lbi_cyc_deactivate;	/* lbolt_cyclic self deactivation */
	int64_t lbi_cyc_deac_start;	/* deactivation interval */
} lbolt_info_t;

extern int64_t lbolt_bootstrap(void);
extern int64_t lbolt_event_driven(void);
extern int64_t lbolt_cyclic_driven(void);
extern int64_t (*lbolt_hybrid)(void);
extern uint_t lbolt_ev_to_cyclic(caddr_t, caddr_t);

extern void lbolt_softint_add(void);
extern void lbolt_softint_post(void);

extern void lbolt_debug_entry(void);
extern void lbolt_debug_return(void);

extern lbolt_info_t *lb_info;

/*
 * LBOLT_WAITFREE{,64} provide a non-waiting version of lbolt.
 */
#define	LBOLT_WAITFREE64						\
	(lbolt_hybrid == lbolt_bootstrap ? 0 :				\
	(lbolt_hybrid == lbolt_event_driven ?                           \
	    ((gethrtime_waitfree()/nsec_per_tick) -			\
	    lb_info->lbi_debug_time) :					\
	    (lb_info->lbi_internal - lb_info->lbi_debug_time)))

#define	LBOLT_WAITFREE		(clock_t)LBOLT_WAITFREE64

/*
 * LBOLT_FASTPATH{,64} should *only* be used where the cost of calling the
 * DDI lbolt routines affects performance. This is currently only used by
 * the TCP/IP code and will be removed once it's no longer required.
 */
#define	LBOLT_FASTPATH64						\
	(lbolt_hybrid == lbolt_cyclic_driven ?				\
	    (lb_info->lbi_internal - lb_info->lbi_debug_time) :		\
	    lbolt_event_driven())

#define	LBOLT_FASTPATH		(clock_t)LBOLT_FASTPATH64

/*
 * LBOLT_NO_ACCOUNT{,64} is used by lbolt consumers who fire at a periodic
 * rate, such as clock(), for which the lbolt usage statistics are not updated.
 * This is especially important for consumers whose rate may be modified by
 * the user, resulting in an unaccounted for increase in activity around the
 * lbolt routines that could cause a mode switch.
 */
#define	LBOLT_NO_ACCOUNT64						\
	(lbolt_hybrid == lbolt_bootstrap ? 0 :				\
	(lbolt_hybrid == lbolt_event_driven ?				\
	    ((gethrtime()/nsec_per_tick) - lb_info->lbi_debug_time) :	\
	    (lb_info->lbi_internal - lb_info->lbi_debug_time)))

#define	LBOLT_NO_ACCOUNT	(clock_t)LBOLT_NO_ACCOUNT64

#endif	/* _KERNEL || _KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CLOCK_IMPL_H */
