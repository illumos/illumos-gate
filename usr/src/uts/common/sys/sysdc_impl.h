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

#ifndef	_SYS_SYSDC_IMPL_H
#define	_SYS_SYSDC_IMPL_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/list.h>

#include <sys/sysdc.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct _kthread;
struct cpupart;

/*
 * Tracks per-processor-set information for SDC.  Its main use is to
 * implement per-processor-set breaks.
 */
typedef struct sysdc_pset {
	list_node_t	sdp_node;	/* node on sysdc_psets list */
	struct cpupart	*sdp_cpupart;	/* associated cpu partition */
	size_t		sdp_nthreads;	/* reference count */

	/* The remainder is only touched by sysdc_update() */
	hrtime_t	sdp_onproc_time; /* time onproc at last update */
	boolean_t	sdp_need_break;	/* threads forced to minpri */
	uint_t		sdp_should_break; /* # updates need_break is set */
	uint_t		sdp_dont_break;	/* after break, # updates until next */

	/* debugging fields */
	uint_t		sdp_onproc_threads;
	hrtime_t	sdp_vtime_last_interval;
	uint_t		sdp_DC_last_interval;
} sysdc_pset_t;

/*
 * Per-thread information, pointed to by t_cldata.
 */
typedef struct sysdc {
	uint_t		sdc_target_DC;	/* target duty cycle */
	uint_t		sdc_minpri;	/* our minimum priority */
	uint_t		sdc_maxpri;	/* our maximum priority */

	sysdc_pset_t	*sdc_pset;	/* the processor set bound to */

	/* protected by sdl_lock */
	struct _kthread	*sdc_thread;	/* back-pointer, or NULL if freeable */

	/* protected by arrangement between thread and sysdc_update() */
	struct sysdc	*sdc_next;	/* next in hash table, NULL if not in */

	/* protected by thread_lock() */
	uint_t		sdc_nupdates;	/* number of sysdc_update_times() */

	hrtime_t	sdc_base_O;	/* on-cpu time at last reset */
	hrtime_t	sdc_base_R;	/* runnable time at last reset */

	uint_t		sdc_sleep_updates; /* 0, or nupdates when we slept */
	clock_t		sdc_ticks;	/* sdc_tick() calls */
	clock_t		sdc_update_ticks; /* value of ticks for forced update */
	clock_t		sdc_pri_check;	/* lbolt when we checked our priority */
	hrtime_t	sdc_last_base_O; /* onproc time at sysdc_update() */

	uint_t		sdc_pri;	/* our last computed priority */
	uint_t		sdc_epri;	/* our actual thread priority */

	/* for debugging only */
	clock_t		sdc_reset;	/* lbolt when we reset our bases */
	hrtime_t	sdc_cur_O;	/* on-cpu time at last prio check */
	hrtime_t	sdc_cur_R;	/* runnable time at last prio check */
	hrtime_t	sdc_last_O;	/* onproc time at thread update */
	uint_t		sdc_cur_DC;	/* our actual duty cycle at last chk */
} sysdc_t;

/*
 * Hash bucket of active SDC threads.
 */
typedef struct sysdc_list {
	kmutex_t	sdl_lock;	/* lock keeping threads from exiting */
	sysdc_t	*volatile sdl_list;	/* list of active threads in bucket */
	char		sdl_pad[64 - sizeof (kmutex_t) - sizeof (sysdc_t *)];
} sysdc_list_t;

/*
 * Args to CL_ENTERCLASS().
 */
typedef struct sysdc_params {
	uint_t		sdp_minpri;
	uint_t		sdp_maxpri;
	uint_t		sdp_DC;
} sysdc_params_t;

/*
 * Duty cycles are percentages in the range [1,100].
 */
#define	SYSDC_DC_MAX		100u	/* 1 <= DC <= DC_MAX */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSDC_IMPL_H */
