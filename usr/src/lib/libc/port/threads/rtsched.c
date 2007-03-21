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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "thr_uberdata.h"
#include <sched.h>
#include <sys/priocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/tspriocntl.h>
#include <sys/rt.h>
#include <sys/ts.h>

/*
 * The following variables are used for caching information
 * for priocntl TS and RT scheduling classs.
 */
static int rt_rrmin;
static int rt_rrmax;
static int rt_fifomin;
static int rt_fifomax;
static int rt_othermin;
static int rt_othermax;

/*
 * Set the RT priority/policy of a lwp/thread.
 */
int
_thrp_setlwpprio(lwpid_t lwpid, int policy, int pri)
{
	pcinfo_t	pcinfo;
	pcparms_t	pcparm;
	int rt = 0;

	ASSERT(((policy == SCHED_FIFO) || (policy == SCHED_RR) ||
	    (policy == SCHED_OTHER)));
	if ((policy == SCHED_FIFO) || (policy == SCHED_RR)) {
		rt = 1;
	}
	if (rt) {
		(void) strcpy(pcinfo.pc_clname, "RT");
	} else {
		(void) strcpy(pcinfo.pc_clname, "TS");
	}
	pcparm.pc_cid = PC_CLNULL;
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) < 0) {
		return (errno);
	}
	pcparm.pc_cid = pcinfo.pc_cid;
	if (rt) {
		((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs =
			(policy == SCHED_RR ? RT_TQDEF : RT_TQINF);
		((rtparms_t *)pcparm.pc_clparms)->rt_pri = pri;
	} else {
		((tsparms_t *)pcparm.pc_clparms)->ts_uprilim = TS_NOCHANGE;
		((tsparms_t *)pcparm.pc_clparms)->ts_upri = TS_NOCHANGE;
	}
	if (priocntl(P_LWPID, lwpid, PC_SETPARMS, (caddr_t)&pcparm) == -1) {
		return (errno);
	}
	return (0);
}

/*
 * Get SCHED_FIFO, SCHED_RR, SCHED_OTHER priority ranges.
 */
static void
_init_rt_prio_ranges()
{
	rt_rrmin = sched_get_priority_min(SCHED_RR);
	rt_rrmax = sched_get_priority_max(SCHED_RR);
	rt_fifomin = sched_get_priority_min(SCHED_FIFO);
	rt_fifomax = sched_get_priority_max(SCHED_FIFO);
	rt_othermin = sched_get_priority_min(SCHED_OTHER);
	rt_othermax = sched_get_priority_max(SCHED_OTHER);
}

/*
 * Validate priorities.
 */
int
_validate_rt_prio(int policy, int pri)
{
	static mutex_t	prio_lock = DEFAULTMUTEX;
	static int	initialized = 0;

	if (!initialized) {
		lmutex_lock(&prio_lock);
		if (!initialized) {	/* do this only once */
			_init_rt_prio_ranges();
			_membar_producer();
			initialized = 1;
		}
		lmutex_unlock(&prio_lock);
	}
	_membar_consumer();

	switch (policy) {
	case SCHED_FIFO:
		return (pri < rt_fifomin || pri > rt_fifomax);
	case SCHED_RR:
		return (pri < rt_rrmin || pri > rt_rrmax);
	case SCHED_OTHER:
		return (pri < rt_othermin || pri > rt_othermax);
	}
	return (1);
}
