/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_TIMERQ_H
#define	_FMD_TIMERQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <time.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_idspace.h>
#include <fmd_thread.h>
#include <fmd_event.h>
#include <fmd_list.h>

typedef void fmd_timer_f(void *, id_t, hrtime_t);

typedef struct fmd_timer {
	fmd_list_t tmr_list;	/* expiry or free list next/prev pointers */
	hrtime_t tmr_hrt;	/* high-res time at which timer should fire */
	fmd_idspace_t *tmr_ids;	/* idspace that contains the timer id */
	id_t tmr_id;		/* client identifier for this timer */
	fmd_timer_f *tmr_func;	/* function that should be called on expiry */
	void *tmr_arg;		/* argument to pass back to tmr_func */
	pthread_cond_t tmr_cv;	/* condition variable for waiting on tmr_func */
} fmd_timer_t;

typedef struct fmd_timerq {
	fmd_thread_t *tmq_thread; /* thread handling timer expiry for queue */
	uint_t tmq_abort;	/* flag indicating tmq_thread should abort */
	pthread_mutex_t tmq_lock; /* lock protecting timer queue contents */
	pthread_cond_t tmq_cv;	/* condition variable for tmq_list, abort */
	fmd_list_t tmq_list;	/* list of active timers, sorted by tmr_hrt */
	fmd_list_t tmq_free;	/* list of free timers */
} fmd_timerq_t;

extern id_t fmd_timerq_install(fmd_timerq_t *,
    fmd_idspace_t *, fmd_timer_f *, void *, fmd_event_t *, hrtime_t);

extern void *fmd_timerq_remove(fmd_timerq_t *, fmd_idspace_t *, id_t);
extern fmd_timerq_t *fmd_timerq_create(void);
extern void fmd_timerq_destroy(fmd_timerq_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_TIMERQ_H */
