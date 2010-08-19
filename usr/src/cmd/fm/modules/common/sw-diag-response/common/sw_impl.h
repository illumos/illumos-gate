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

#ifndef	_SW_IMPL_H
#define	_SW_IMPL_H

#include "sw.h"

/*
 * The common code between software-response and software-diagnosis
 * needs somewhere to track the subsidaries that have "registered",
 * their dispatch tables etc.  In the _fmd_init of each module we
 * call the shared sw_fmd_init code, and there we allocate a
 * struct sw_modspecific and assign this as the fmd fodule-specific
 * data with fmd_hdl_setspecific.
 */
struct sw_modspecific {
	int swms_dispcnt;
	const struct sw_subinfo *(*swms_subinfo)[SW_SUB_MAX];
	const struct sw_disp *(*swms_disptbl)[SW_SUB_MAX];
	pthread_mutex_t swms_timerlock;
	struct {
		int swt_state;		/* slot in use? */
		id_t swt_timerid;	/* fmd_timer_install result */
		id_t swt_ownerid;	/* subsidiary owner id */
	} swms_timers[SW_TIMER_MAX];
};

#define	SW_TMR_INUSE		1
#define	SW_TMR_RMVD		0
#define	SW_TMR_UNTOUCHED	-1

extern swsub_case_close_func_t *sw_sub_case_close_func(fmd_hdl_t *,
    enum sw_casetype);
extern sw_case_vrfy_func_t *sw_sub_case_vrfy_func(fmd_hdl_t *,
    enum sw_casetype);

/*
 * Software DE fmdo_close entry point.
 */
extern void swde_close(fmd_hdl_t *, fmd_case_t *);

/*
 * Shared functions for software-diagnosis and software-response fmd
 * module implementation using shared code.  Subsidiaries do not need
 * to call these functions.
 *
 * sw_fmd_init is called from _fmd_init of the two modules, to do most of
 * the real work of initializing the subsidiaries etc.
 *
 * sw_fmd_fini is called from _fmd_fini and calls the swsub_fini
 * function of each subsidiary after uninstalling all timers.
 *
 * sw_recv is the fmdo_recv entry point; it checks the event against
 * the dispatch table of each subsidiary and dispatches the first
 * match for each module.
 *
 * sw_timeout is the fmdo_timeout entry point; it looks up the unique id_t
 * of the subsidiary that installed the timer (via sw_timer_install in which
 * the id is quoted) and calls the swsub_timeout function for that subsidiary.
 *
 * swde_case_init and swde_case_fini initialize and finalize the
 * software-diagnosis case-tracking infrastructure;  swde_case_init
 * is responsible for unserializing case state.
 *
 * sw_id_to_casetype take a subsidiary id and returns the case type it
 * registered with.
 */
extern int sw_fmd_init(fmd_hdl_t *, const fmd_hdl_info_t *,
    const struct sw_subinfo *(*)[SW_SUB_MAX]);
extern void sw_fmd_fini(fmd_hdl_t *);
extern void sw_recv(fmd_hdl_t *, fmd_event_t *, nvlist_t *, const char *);
extern void sw_timeout(fmd_hdl_t *, id_t, void *);
extern void swde_case_init(fmd_hdl_t *);
extern void swde_case_fini(fmd_hdl_t *);

enum sw_casetype sw_id_to_casetype(fmd_hdl_t *, id_t);

#endif	/* _SW_IMPL_H */
