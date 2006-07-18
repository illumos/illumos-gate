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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"
#include "mtlib.h"
#include <sys/types.h>
#include <sched.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/priocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/tspriocntl.h>
#include <sys/rt.h>
#include <sys/ts.h>
#include <thread.h>
#include <string.h>
#include <stdlib.h>
#include "rtsched.h"

/*
 * The following variables are used for caching information
 * for priocntl scheduling classes.
 */
struct pcclass ts_class;
struct pcclass rt_class;
struct pcclass ia_class;
struct pcclass sys_class;

static rtdpent_t	*rt_dptbl;	/* RT class parameter table */

typedef struct { /* type definition for generic class-specific parameters */
	int	pc_clparms[PC_CLINFOSZ];
} pc_clparms_t;

static int	map_gp_to_rtpri(pri_t);

/*
 * cache priocntl information on scheduling classes by policy
 */
int
get_info_by_policy(int policy)
{
	char		*pccname;
	struct pcclass	*pccp;

	if (policy < 0) {
		errno = EINVAL;
		return (-1);
	}

	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		pccp = &rt_class;
		pccname = "RT";
		break;
	case SCHED_OTHER:
		pccp = &ts_class;
		pccname = "TS";
		break;
	case SCHED_SYS:
		pccp = &sys_class;
		pccname = "sys";
		break;
	case SCHED_IA:
		pccp = &ia_class;
		pccname = "IA";
		break;
	default:
		return (policy);
	}
	if (pccp->pcc_state != 0) {
		if (pccp->pcc_state < 0)
			errno = ENOSYS;
		return (pccp->pcc_state);
	}

	/* get class's info */
	(void) strcpy(pccp->pcc_info.pc_clname, pccname);
	if (policy == SCHED_SYS)
		pccp->pcc_info.pc_cid = 0;
	else if (priocntl(P_PID, 0, PC_GETCID, (caddr_t)&(pccp->pcc_info)) < 0)
		return (-1);

	if (policy == SCHED_FIFO || policy == SCHED_RR) {
		pcadmin_t	pcadmin;
		rtadmin_t	rtadmin;
		size_t		rtdpsize;

		/* get RT class dispatch table in rt_dptbl */
		pcadmin.pc_cid = rt_class.pcc_info.pc_cid;
		pcadmin.pc_cladmin = (caddr_t)&rtadmin;
		rtadmin.rt_cmd = RT_GETDPSIZE;
		if (priocntl(P_PID, 0, PC_ADMIN, (caddr_t)&pcadmin) < 0)
			return (-1);
		rtdpsize = (size_t)(rtadmin.rt_ndpents * sizeof (rtdpent_t));
		if (rt_dptbl == NULL &&
		    (rt_dptbl = lmalloc(rtdpsize)) == NULL) {
			errno = EAGAIN;
			return (-1);
		}
		rtadmin.rt_dpents = rt_dptbl;
		rtadmin.rt_cmd = RT_GETDPTBL;
		if (priocntl(P_PID, 0, PC_ADMIN, (caddr_t)&pcadmin) < 0)
			return (-1);
		pccp->pcc_primin = 0;
		pccp->pcc_primax = ((rtinfo_t *)rt_class.pcc_info.pc_clinfo)->
		    rt_maxpri;
	} else if (policy == SCHED_OTHER) {
		pri_t		prio;

		prio = ((tsinfo_t *)ts_class.pcc_info.pc_clinfo)->ts_maxupri/3;
		pccp->pcc_primin = -prio;
		pccp->pcc_primax = prio;
	} else {
		/* non-RT scheduling class */
		pcpri_t		pcpri;

		/*
		 * get class's global priority's min, max, and
		 * translate them into RT priority level (index) via rt_dptbl.
		 */
		pcpri.pc_cid = pccp->pcc_info.pc_cid;
		if (priocntl(0, 0, PC_GETPRIRANGE, (caddr_t)&pcpri) < 0)
			return (-1);
		pccp->pcc_primax = map_gp_to_rtpri(pcpri.pc_clpmax);
		pccp->pcc_primin = map_gp_to_rtpri(pcpri.pc_clpmin);
	}

	pccp->pcc_state = 1;
	return (1);
}

/*
 * Translate global scheduling priority to RT class's user priority.
 * Use the gp values in the rt_dptbl to do a reverse mapping
 * of a given gpri value relative to the index range of rt_dptbl.
 */
static int
map_gp_to_rtpri(pri_t gpri)
{
	rtdpent_t	*rtdp;
	pri_t		pri;

	/* need RT class info before we can translate priorities */
	if (rt_dptbl == NULL && get_info_by_policy(SCHED_FIFO) < 0)
		return (-1);

	if (gpri <= rt_dptbl[rt_class.pcc_primin].rt_globpri) {
		pri = gpri - rt_dptbl[rt_class.pcc_primin].rt_globpri + \
		    rt_class.pcc_primin;
	} else if (gpri >= rt_dptbl[rt_class.pcc_primax].rt_globpri) {
		pri = gpri - rt_dptbl[rt_class.pcc_primax].rt_globpri + \
		    rt_class.pcc_primax;
	} else {
		pri = rt_class.pcc_primin + 1;
		for (rtdp = rt_dptbl+1; rtdp->rt_globpri < gpri; ++rtdp, ++pri)
			;
		if (rtdp->rt_globpri > gpri)
			--pri;
	}

	return (pri);
}

/*
 * Translate RT class's user priority to global scheduling priority.
 */
pri_t
map_rtpri_to_gp(pri_t pri)
{
	rtdpent_t	*rtdp;
	pri_t		gpri;

	if (rt_class.pcc_state == 0)
		(void) get_info_by_policy(SCHED_FIFO);

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

static int
get_info_by_class(id_t classid)
{
	pcinfo_t	pcinfo;

	/* determine if we already know this classid */
	if (rt_class.pcc_state > 0 && rt_class.pcc_info.pc_cid == classid)
		return (1);
	if (ts_class.pcc_state > 0 && ts_class.pcc_info.pc_cid == classid)
		return (1);
	if (sys_class.pcc_state > 0 && sys_class.pcc_info.pc_cid == classid)
		return (1);
	if (ia_class.pcc_state > 0 && ia_class.pcc_info.pc_cid == classid)
		return (1);

	pcinfo.pc_cid = classid;
	if (priocntl(0, 0, PC_GETCLINFO, (caddr_t)&pcinfo) < 0) {
		if (classid == 0)	/* no kernel info for sys class */
			return (get_info_by_policy(SCHED_SYS));
		return (-1);
	}

	if (rt_class.pcc_state == 0 && strcmp(pcinfo.pc_clname, "RT") == 0)
		return (get_info_by_policy(SCHED_FIFO));
	if (ts_class.pcc_state == 0 && strcmp(pcinfo.pc_clname, "TS") == 0)
		return (get_info_by_policy(SCHED_OTHER));
	if (ia_class.pcc_state == 0 && strcmp(pcinfo.pc_clname, "IA") == 0)
		return (get_info_by_policy(SCHED_IA));

	return (1);
}

int
sched_setparam(pid_t pid, const struct sched_param *param)
{
	pri_t		prio = param->sched_priority;
	pcparms_t	pcparm;
	tsparms_t	*tsp;
	tsinfo_t	*tsi;
	int		scale;

	if (pid < 0) {
		errno = ESRCH;
		return (-1);
	}
	if (pid == 0)
		pid = P_MYID;

	/* get process's current scheduling policy */
	pcparm.pc_cid = PC_CLNULL;
	if (priocntl(P_PID, pid, PC_GETPARMS, (caddr_t)&pcparm) == -1)
		return (-1);
	if (get_info_by_class(pcparm.pc_cid) < 0)
		return (-1);

	if (pcparm.pc_cid == rt_class.pcc_info.pc_cid) {
		/* SCHED_FIFO or SCHED_RR policy */
		if (prio < rt_class.pcc_primin || prio > rt_class.pcc_primax) {
			errno = EINVAL;
			return (-1);
		}
		((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs = RT_NOCHANGE;
		((rtparms_t *)pcparm.pc_clparms)->rt_pri = prio;
	} else if (pcparm.pc_cid == ts_class.pcc_info.pc_cid) {
		/* SCHED_OTHER policy */
		tsi = (tsinfo_t *)ts_class.pcc_info.pc_clinfo;
		scale = tsi->ts_maxupri;
		tsp = (tsparms_t *)pcparm.pc_clparms;
		tsp->ts_uprilim = tsp->ts_upri = -(scale * prio) / 20;
	} else {
		/*
		 * policy is not defined by POSIX.4.
		 * just pass parameter data through to priocntl.
		 * param should contain an image of class-specific parameters
		 * (after the sched_priority member).
		 */
		*((pc_clparms_t *)pcparm.pc_clparms) =
		    *((pc_clparms_t *)(&(param->sched_priority)+1));
	}

	return ((int)priocntl(P_PID, pid, PC_SETPARMS, (caddr_t)&pcparm));
}

int
sched_getparam(pid_t pid, struct sched_param *param)
{
	pcparms_t	pcparm;
	pri_t		prio;
	int		scale;
	tsinfo_t	*tsi;

	if (pid < 0) {
		errno = ESRCH;
		return (-1);
	}
	if (pid == 0)
		pid = P_MYID;

	pcparm.pc_cid = PC_CLNULL;
	if (priocntl(P_PID, pid, PC_GETPARMS, (caddr_t)&pcparm) == -1)
		return (-1);
	if (get_info_by_class(pcparm.pc_cid) < 0)
		return (-1);

	if (pcparm.pc_cid == rt_class.pcc_info.pc_cid) {
		param->sched_priority =
			((rtparms_t *)pcparm.pc_clparms)->rt_pri;
	} else if (pcparm.pc_cid == ts_class.pcc_info.pc_cid) {
		param->sched_nicelim =
			((tsparms_t *)pcparm.pc_clparms)->ts_uprilim;
		prio = param->sched_nice =
			((tsparms_t *)pcparm.pc_clparms)->ts_upri;
		tsi = (tsinfo_t *)ts_class.pcc_info.pc_clinfo;
		scale = tsi->ts_maxupri;
		if (scale == 0)
			param->sched_priority = 0;
		else
			param->sched_priority = -(prio * 20) / scale;
	} else {
		/*
		 * policy is not defined by POSIX.4
		 * just return a copy of pcparams_t image in param.
		 */
		*((pc_clparms_t *)(&(param->sched_priority)+1)) =
		    *((pc_clparms_t *)pcparm.pc_clparms);
		param->sched_priority =
		    sched_get_priority_min((int)(pcparm.pc_cid + _SCHED_NEXT));
	}

	return (0);
}

int
sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
{
	pri_t		prio = param->sched_priority;
	pcparms_t	pcparm;
	int		oldpolicy;
	tsinfo_t	*tsi;
	tsparms_t	*tsp;
	int		scale;

	if ((oldpolicy = sched_getscheduler(pid)) < 0)
		return (-1);

	if (pid == 0)
		pid = P_MYID;

	if (get_info_by_policy(policy) < 0) {
		errno = EINVAL;
		return (-1);
	}

	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		if (prio < rt_class.pcc_primin || prio > rt_class.pcc_primax) {
			errno = EINVAL;
			return (-1);
		}
		pcparm.pc_cid = rt_class.pcc_info.pc_cid;
		((rtparms_t *)pcparm.pc_clparms)->rt_pri = prio;
		((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs =
		    (policy == SCHED_RR ? RT_TQDEF : RT_TQINF);
		break;

	case SCHED_OTHER:
		pcparm.pc_cid = ts_class.pcc_info.pc_cid;
		tsi = (tsinfo_t *)ts_class.pcc_info.pc_clinfo;
		scale = tsi->ts_maxupri;
		tsp = (tsparms_t *)pcparm.pc_clparms;
		tsp->ts_uprilim = tsp->ts_upri = -(scale * prio) / 20;
		break;

	default:
		switch (policy) {
		case SCHED_SYS:
			pcparm.pc_cid = sys_class.pcc_info.pc_cid;
			break;
		case SCHED_IA:
			pcparm.pc_cid = ia_class.pcc_info.pc_cid;
			break;
		default:
			pcparm.pc_cid = policy - _SCHED_NEXT;
			break;
		}
		/*
		 * policy is not defined by POSIX.4.
		 * just pass parameter data through to priocntl.
		 * param should contain an image of class-specific parameters
		 * (after the sched_priority member).
		 */
		*((pc_clparms_t *)pcparm.pc_clparms) =
		    *((pc_clparms_t *)&(param->sched_priority)+1);
	}

	/* setting scheduling policy & parameters for the process */
	if (priocntl(P_PID, pid, PC_SETPARMS, (caddr_t)&pcparm) == -1)
		return (-1);

	return (oldpolicy);
}

int
sched_getscheduler(pid_t pid)
{
	pcparms_t	pcparm;
	int		policy;

	if (pid < 0) {
		errno = ESRCH;
		return (-1);
	}
	if (pid == 0)
		pid = P_MYID;

	/* get scheduling policy & parameters for the process */
	pcparm.pc_cid = PC_CLNULL;
	if (priocntl(P_PID, pid, PC_GETPARMS, (caddr_t)&pcparm) == -1)
		return (-1);
	if (get_info_by_class(pcparm.pc_cid) < 0)
		return (-1);

	if (pcparm.pc_cid == rt_class.pcc_info.pc_cid)
		policy = ((((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs ==
		    RT_TQINF ? SCHED_FIFO : SCHED_RR));
	else if (pcparm.pc_cid == ts_class.pcc_info.pc_cid)
		policy = SCHED_OTHER;
	else if (pcparm.pc_cid == sys_class.pcc_info.pc_cid)
		policy = SCHED_SYS;
	else if (pcparm.pc_cid == ia_class.pcc_info.pc_cid)
		policy = SCHED_IA;
	else {
		/*
		 * policy is not defined by POSIX.4
		 * return a unique dot4 policy id.
		 */
		policy = (int)(_SCHED_NEXT + pcparm.pc_cid);
	}

	return (policy);
}

int
sched_yield(void)
{
	thr_yield();
	return (0);
}

int
sched_get_priority_max(int policy)
{
	pcpri_t	pcpri;

	if (get_info_by_policy(policy) < 0)
		return (-1);

	if (policy == SCHED_FIFO || policy == SCHED_RR)
		return (rt_class.pcc_primax);
	else if (policy == SCHED_OTHER)
		return (ts_class.pcc_primax);
	else if (policy == SCHED_SYS)
		return (sys_class.pcc_primax);
	else if (policy == SCHED_IA)
		return (ia_class.pcc_primax);
	else { /* policy not in POSIX.4 */
		pcpri.pc_cid = policy - _SCHED_NEXT;
		if (priocntl(0, 0, PC_GETPRIRANGE, (caddr_t)&pcpri) == 0)
			return (map_gp_to_rtpri(pcpri.pc_clpmax));
	}

	errno = EINVAL;
	return (-1);
}

int
sched_get_priority_min(int policy)
{
	pcpri_t pcpri;

	if (get_info_by_policy(policy) < 0)
		return (-1);

	if (policy == SCHED_FIFO || policy == SCHED_RR)
		return (rt_class.pcc_primin);
	else if (policy == SCHED_OTHER)
		return (ts_class.pcc_primin);
	else if (policy == SCHED_SYS)
		return (sys_class.pcc_primin);
	else if (policy == SCHED_IA)
		return (ia_class.pcc_primin);
	else { /* policy not in POSIX.4 */
		pcpri.pc_cid = policy - _SCHED_NEXT;
		if (priocntl(0, 0, PC_GETPRIRANGE, (caddr_t)&pcpri) == 0)
			return (map_gp_to_rtpri(pcpri.pc_clpmin));
	}

	errno = EINVAL;
	return (-1);
}

int
sched_rr_get_interval(pid_t pid, timespec_t *interval)
{
	pcparms_t pcparm;

	if (pid < 0) {
		errno = ESRCH;
		return (-1);
	}
	if (pid == 0)
		pid = P_MYID;

	if (get_info_by_policy(SCHED_RR) < 0)
		return (-1);

	pcparm.pc_cid = PC_CLNULL;
	if (priocntl(P_PID, pid, PC_GETPARMS, (caddr_t)&pcparm) == -1)
		return (-1);

	if (pcparm.pc_cid == rt_class.pcc_info.pc_cid &&
	    (((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs != RT_TQINF)) {
		/* SCHED_RR */
		interval->tv_sec = ((rtparms_t *)pcparm.pc_clparms)->rt_tqsecs;
		interval->tv_nsec =
		    ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs;
		return (0);
	}

	errno = EINVAL;
	return (-1);
}
