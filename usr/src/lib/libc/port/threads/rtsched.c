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
struct pcclass ts_class, rt_class;

static rtdpent_t *rt_dptbl;	/* RT class parameter table */
static int rt_rrmin;
static int rt_rrmax;
static int rt_fifomin;
static int rt_fifomax;
static int rt_othermin;
static int rt_othermax;

/*
 * Get the RT class parameter table
 */
static void
_get_rt_dptbl()
{
	struct pcclass	*pccp;
	pcadmin_t	pcadmin;
	rtadmin_t	rtadmin;
	size_t		rtdpsize;

	pccp = &ts_class;
	/* get class's info */
	(void) strcpy(pccp->pcc_info.pc_clname, "TS");
	if (priocntl(P_PID, 0, PC_GETCID, (caddr_t)&(pccp->pcc_info)) < 0)
		goto out;

	pccp = &rt_class;
	/* get class's info */
	(void) strcpy(pccp->pcc_info.pc_clname, "RT");
	if (priocntl(P_PID, 0, PC_GETCID, (caddr_t)&(pccp->pcc_info)) < 0)
		goto out;

	/* get RT class dispatch table in rt_dptbl */
	pcadmin.pc_cid = rt_class.pcc_info.pc_cid;
	pcadmin.pc_cladmin = (caddr_t)&rtadmin;
	rtadmin.rt_cmd = RT_GETDPSIZE;
	if (priocntl(P_PID, 0, PC_ADMIN, (caddr_t)&pcadmin) < 0)
		goto out;
	rtdpsize = rtadmin.rt_ndpents * sizeof (rtdpent_t);
	if (rt_dptbl == NULL && (rt_dptbl = lmalloc(rtdpsize)) == NULL)
		goto out;
	rtadmin.rt_dpents = rt_dptbl;
	rtadmin.rt_cmd = RT_GETDPTBL;
	if (priocntl(P_PID, 0, PC_ADMIN, (caddr_t)&pcadmin) < 0)
		goto out;
	pccp->pcc_primin = 0;
	pccp->pcc_primax = ((rtinfo_t *)rt_class.pcc_info.pc_clinfo)->rt_maxpri;
	return;
out:
	thr_panic("get_rt_dptbl failed");
}

/*
 * Translate RT class's user priority to global scheduling priority.
 * This is for priorities coming from librt.
 */
pri_t
_map_rtpri_to_gp(pri_t pri)
{
	static mutex_t	map_lock = DEFAULTMUTEX;
	static int	mapped = 0;
	rtdpent_t	*rtdp;
	pri_t		gpri;

	if (!mapped) {
		lmutex_lock(&map_lock);
		if (!mapped) {		/* do this only once */
			_get_rt_dptbl();
			mapped = 1;
		}
		lmutex_unlock(&map_lock);
	}

	/* First case is the default case, other two are seldomly taken */
	if (pri <= rt_dptbl[rt_class.pcc_primin].rt_globpri) {
		gpri = pri + rt_dptbl[rt_class.pcc_primin].rt_globpri -
		    rt_class.pcc_primin;
	} else if (pri >= rt_dptbl[rt_class.pcc_primax].rt_globpri) {
		gpri = pri + rt_dptbl[rt_class.pcc_primax].rt_globpri -
		    rt_class.pcc_primax;
	} else {
		gpri =  rt_dptbl[rt_class.pcc_primin].rt_globpri + 1;
		for (rtdp = rt_dptbl+1; rtdp->rt_globpri < pri; ++rtdp, ++gpri)
			;
		if (rtdp->rt_globpri > pri)
			--gpri;
	}
	return (gpri);
}

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
	pcinfo_t info;

	(void) strcpy(info.pc_clname, "RT");
	if (priocntl(P_PID, 0, PC_GETCID, (caddr_t)&info) == -1L)
		rt_fifomin = rt_rrmin = rt_fifomax = rt_rrmax = 0;
	else {
		rtinfo_t *rtinfop = (rtinfo_t *)info.pc_clinfo;
		rt_fifomin = rt_rrmin = 0;
		rt_fifomax = rt_rrmax = rtinfop->rt_maxpri;
	}

	(void) strcpy(info.pc_clname, "TS");
	if (priocntl(P_PID, 0, PC_GETCID, (caddr_t)&info) == -1L)
		rt_othermin = rt_othermax = 0;
	else {
		tsinfo_t *tsinfop = (tsinfo_t *)info.pc_clinfo;
		pri_t pri = tsinfop->ts_maxupri / 3;
		rt_othermin = -pri;
		rt_othermax = pri;
	}
}

/*
 * Validate priorities from librt.
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
			initialized = 1;
		}
		lmutex_unlock(&prio_lock);
	}

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
