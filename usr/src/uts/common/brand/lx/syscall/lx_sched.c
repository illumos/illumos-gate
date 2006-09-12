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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/cpu.h>
#include <sys/rtpriocntl.h>
#include <sys/tspriocntl.h>
#include <sys/processor.h>
#include <sys/brand.h>
#include <sys/lx_pid.h>
#include <sys/lx_sched.h>
#include <sys/lx_brand.h>

extern long priocntl_common(int, procset_t *, int, caddr_t, caddr_t, uio_seg_t);

int
lx_sched_affinity(int cmd, uintptr_t pid, int len, uintptr_t maskp,
    int64_t *rval)
{
	pid_t		s_pid;
	id_t		s_tid;
	kthread_t	*t = curthread;
	lx_lwp_data_t	*lx_lwp;

	if (cmd != B_GET_AFFINITY_MASK && cmd != B_SET_AFFINITY_MASK)
		return (set_errno(EINVAL));

	/*
	 * The caller wants to know how large the mask should be.
	 */
	if (cmd == B_GET_AFFINITY_MASK && len == 0) {
		*rval = sizeof (lx_affmask_t);
		return (0);
	}

	/*
	 * Otherwise, ensure they have a large enough mask.
	 */
	if (cmd == B_GET_AFFINITY_MASK && len < sizeof (lx_affmask_t)) {
		*rval = -1;
		return (set_errno(EINVAL));
	}

	if (pid == 0) {
		s_pid = curproc->p_pid;
		s_tid = curthread->t_tid;
	} else if (lx_lpid_to_spair((pid_t)pid, &s_pid, &s_tid) == -1) {
		return (set_errno(ESRCH));
	}

	/*
	 * For now, we only support manipulating threads in the
	 * same process.
	 */
	if (curproc->p_pid != s_pid)
		return (set_errno(EPERM));

	/*
	 * We must hold the process lock so that the thread list
	 * doesn't change while we're looking at it. We'll hold
	 * the lock until we no longer reference the
	 * corresponding lwp.
	 */

	mutex_enter(&curproc->p_lock);

	do {
		if (t->t_tid == s_tid)
			break;
		t = t->t_forw;
	} while (t != curthread);

	/*
	 * If the given PID is in the current thread's process,
	 * then we _must_ find it in the process's thread list.
	 */
	ASSERT(t->t_tid == s_tid);

	lx_lwp = t->t_lwp->lwp_brand;

	if (cmd == B_SET_AFFINITY_MASK) {
		if (copyin_nowatch((void *)maskp, &lx_lwp->br_affinitymask,
		    sizeof (lx_affmask_t)) != 0) {
			mutex_exit(&curproc->p_lock);
			return (set_errno(EFAULT));
		}

		*rval = 0;
	} else {
		if (copyout_nowatch(&lx_lwp->br_affinitymask, (void *)maskp,
		    sizeof (lx_affmask_t)) != 0) {
			mutex_exit(&curproc->p_lock);
			return (set_errno(EFAULT));
		}

		*rval = sizeof (lx_affmask_t);
	}

	mutex_exit(&curproc->p_lock);
	return (0);
}

long
lx_sched_setscheduler(l_pid_t pid, int policy, struct lx_sched_param *param)
{
	klwp_t *lwp = ttolwp(curthread);
	procset_t procset;
	procset_t procset_cid;
	pcparms_t pcparm;
	pcinfo_t pcinfo;
	struct lx_sched_param sched_param;
	tsparms_t *tsp;
	int prio, maxupri;
	int rv;

	if (pid < 0)
		return (set_errno(ESRCH));

	if (rv = sched_setprocset(&procset, pid))
		return (rv);

	if (copyin(param, &sched_param, sizeof (sched_param)))
		return (set_errno(EFAULT));

	prio = sched_param.lx_sched_prio;

	if (policy < 0) {
		/*
		 * get the class id
		 */
		pcparm.pc_cid = PC_CLNULL;
		(void) do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
		if (lwp->lwp_errno)
			return (lwp->lwp_errno);

		/*
		 * get the current policy
		 */
		bzero(&pcinfo, sizeof (pcinfo));
		pcinfo.pc_cid = pcparm.pc_cid;
		(void) do_priocntlsys(PC_GETCLINFO, &procset, &pcinfo);
		if (lwp->lwp_errno)
			return (lwp->lwp_errno);

		if (strcmp(pcinfo.pc_clname, "TS") == 0)
			policy = LX_SCHED_OTHER;
		else if (strcmp(pcinfo.pc_clname, "RT") == 0)
			policy = ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs ==
				RT_TQINF ? LX_SCHED_FIFO : LX_SCHED_RR;
		else
			return (set_errno(EINVAL));
	}

	bzero(&pcinfo, sizeof (pcinfo));
	bzero(&pcparm, sizeof (pcparm));
	setprocset(&procset_cid, POP_AND, P_PID, 0, P_ALL, 0);
	switch (policy) {
	case LX_SCHED_FIFO:
	case LX_SCHED_RR:
		(void) strcpy(pcinfo.pc_clname, "RT");
		(void) do_priocntlsys(PC_GETCID, &procset_cid, &pcinfo);
		if (lwp->lwp_errno)
			return (lwp->lwp_errno);

		if (prio < 0 ||
		    prio > ((rtinfo_t *)pcinfo.pc_clinfo)->rt_maxpri)
			return (set_errno(EINVAL));
		pcparm.pc_cid = pcinfo.pc_cid;
		((rtparms_t *)pcparm.pc_clparms)->rt_pri = prio;
		((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs =
			policy == LX_SCHED_RR ? RT_TQDEF : RT_TQINF;
		break;

	case LX_SCHED_OTHER:
		(void) strcpy(pcinfo.pc_clname, "TS");
		(void) do_priocntlsys(PC_GETCID, &procset_cid, &pcinfo);
		if (lwp->lwp_errno)
			return (lwp->lwp_errno);

		maxupri = ((tsinfo_t *)pcinfo.pc_clinfo)->ts_maxupri;
		if (prio > maxupri || prio < -maxupri)
			return (set_errno(EINVAL));

		pcparm.pc_cid = pcinfo.pc_cid;
		tsp = (tsparms_t *)pcparm.pc_clparms;
		tsp->ts_upri = prio;
		tsp->ts_uprilim = TS_NOCHANGE;
		break;

	default:
		return (set_errno(EINVAL));
	}

	/*
	 * finally set scheduling policy and parameters
	 */
	(void) do_priocntlsys(PC_SETPARMS, &procset, &pcparm);

	return (0);
}

long
lx_sched_getscheduler(l_pid_t pid)
{
	klwp_t *lwp = ttolwp(curthread);
	procset_t procset;
	pcparms_t pcparm;
	pcinfo_t pcinfo;
	int policy;
	int rv;

	if (pid < 0)
		return (set_errno(ESRCH));

	if (rv = sched_setprocset(&procset, pid))
		return (rv);

	/*
	 * get the class id
	 */
	pcparm.pc_cid = PC_CLNULL;
	(void) do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * get the class info and identify the equivalent linux policy
	 */
	bzero(&pcinfo, sizeof (pcinfo));
	pcinfo.pc_cid = pcparm.pc_cid;
	(void) do_priocntlsys(PC_GETCLINFO, &procset, &pcinfo);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	if (strcmp(pcinfo.pc_clname, "TS") == 0)
		policy = LX_SCHED_OTHER;
	else if (strcmp(pcinfo.pc_clname, "RT") == 0)
		policy = ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs ==
			RT_TQINF ? LX_SCHED_FIFO : LX_SCHED_RR;
	else
		policy = set_errno(EINVAL);

	return (policy);
}

long
lx_sched_setparam(l_pid_t pid, struct lx_sched_param *param)
{
	klwp_t *lwp = ttolwp(curthread);
	procset_t procset;
	procset_t procset_cid;
	pcparms_t pcparm;
	pcinfo_t pcinfo;
	struct lx_sched_param sched_param;
	tsparms_t *tsp;
	int policy;
	int prio, maxupri;
	int rv;

	if (pid < 0)
		return (set_errno(ESRCH));

	if (rv = sched_setprocset(&procset, pid))
		return (rv);

	if (copyin(param, &sched_param, sizeof (sched_param)))
		return (set_errno(EFAULT));

	prio = sched_param.lx_sched_prio;

	/*
	 * get the class id
	 */
	pcparm.pc_cid = PC_CLNULL;
	(void) do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * get the current policy
	 */
	bzero(&pcinfo, sizeof (pcinfo));
	pcinfo.pc_cid = pcparm.pc_cid;
	(void) do_priocntlsys(PC_GETCLINFO, &procset, &pcinfo);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	if (strcmp(pcinfo.pc_clname, "TS") == 0)
		policy = LX_SCHED_OTHER;
	else if (strcmp(pcinfo.pc_clname, "RT") == 0)
		policy = ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs ==
			RT_TQINF ? LX_SCHED_FIFO : LX_SCHED_RR;
	else
		return (set_errno(EINVAL));

	bzero(&pcinfo, sizeof (pcinfo));
	bzero(&pcparm, sizeof (pcparm));
	setprocset(&procset_cid, POP_AND, P_PID, 0, P_ALL, 0);
	switch (policy) {
	case LX_SCHED_FIFO:
	case LX_SCHED_RR:
		(void) strcpy(pcinfo.pc_clname, "RT");
		(void) do_priocntlsys(PC_GETCID, &procset_cid, &pcinfo);
		if (lwp->lwp_errno)
			return (lwp->lwp_errno);

		if (prio < 0 ||
		    prio > ((rtinfo_t *)pcinfo.pc_clinfo)->rt_maxpri)
			return (set_errno(EINVAL));
		pcparm.pc_cid = pcinfo.pc_cid;
		((rtparms_t *)pcparm.pc_clparms)->rt_pri = prio;
		((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs =
			policy == LX_SCHED_RR ? RT_TQDEF : RT_TQINF;
		break;

	case LX_SCHED_OTHER:
		(void) strcpy(pcinfo.pc_clname, "TS");
		(void) do_priocntlsys(PC_GETCID, &procset_cid, &pcinfo);
		if (lwp->lwp_errno)
			return (lwp->lwp_errno);

		maxupri = ((tsinfo_t *)pcinfo.pc_clinfo)->ts_maxupri;
		if (prio > maxupri || prio < -maxupri)
			return (set_errno(EINVAL));

		pcparm.pc_cid = pcinfo.pc_cid;
		tsp = (tsparms_t *)pcparm.pc_clparms;
		tsp->ts_upri = prio;
		tsp->ts_uprilim = TS_NOCHANGE;
		break;

	default:
		return (set_errno(EINVAL));
	}

	/*
	 * finally set scheduling policy and parameters
	 */
	(void) do_priocntlsys(PC_SETPARMS, &procset, &pcparm);

	return (0);
}

long
lx_sched_getparam(l_pid_t pid, struct lx_sched_param *param)
{
	klwp_t *lwp = ttolwp(curthread);
	struct lx_sched_param local_param;
	procset_t procset;
	pcparms_t pcparm;
	pcinfo_t pcinfo;
	tsinfo_t *tsi;
	int prio, scale;
	int rv;

	if (pid < 0)
		return (set_errno(ESRCH));

	if (rv = sched_setprocset(&procset, pid))
		return (rv);

	/*
	 * get the class id
	 */
	pcparm.pc_cid = PC_CLNULL;
	(void) do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * get the class info and identify the equivalent linux policy
	 */
	bzero(&pcinfo, sizeof (pcinfo));
	pcinfo.pc_cid = pcparm.pc_cid;
	(void) do_priocntlsys(PC_GETCLINFO, &procset, &pcinfo);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	bzero(&local_param, sizeof (local_param));
	if (strcmp(pcinfo.pc_clname, "TS") == 0) {
		/*
		 * I don't know if we need to do this, coz it can't be
		 * changed from zero anyway.....
		 */
		tsi = (tsinfo_t *)pcinfo.pc_clinfo;
		prio = ((tsparms_t *)pcparm.pc_clparms)->ts_upri;
		scale = tsi->ts_maxupri;
		if (scale == 0)
			local_param.lx_sched_prio = 0;
		else
			local_param.lx_sched_prio = -(prio * 20) / scale;
	} else if (strcmp(pcinfo.pc_clname, "RT") == 0)
		local_param.lx_sched_prio =
			((rtparms_t *)pcparm.pc_clparms)->rt_pri;
	else
		rv = set_errno(EINVAL);

	if (rv == 0)
		if (copyout(&local_param, param, sizeof (local_param)))
			return (set_errno(EFAULT));

	return (rv);
}

long
lx_sched_rr_get_interval(l_pid_t pid, struct timespec *ival)
{
	klwp_t *lwp = ttolwp(curthread);
	struct timespec interval;
	procset_t procset;
	pcparms_t pcparm;
	pcinfo_t pcinfo;
	int rv;

	if (pid < 0)
		return (set_errno(ESRCH));

	if (rv = sched_setprocset(&procset, pid))
		return (rv);

	/*
	 * get the class id
	 */
	pcparm.pc_cid = PC_CLNULL;
	(void) do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * get the class info and identify the equivalent linux policy
	 */
	setprocset(&procset, POP_AND, P_PID, 0, P_ALL, 0);
	bzero(&pcinfo, sizeof (pcinfo));
	(void) strcpy(pcinfo.pc_clname, "RT");
	(void) do_priocntlsys(PC_GETCID, &procset, &pcinfo);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	if (pcparm.pc_cid == pcinfo.pc_cid &&
	    ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs != RT_TQINF) {
		interval.tv_sec = ((rtparms_t *)pcparm.pc_clparms)->rt_tqsecs;
		interval.tv_nsec = ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs;

		if (copyout(&interval, ival, sizeof (interval)))
			return (set_errno(EFAULT));

		return (0);
	}

	return (set_errno(EINVAL));
}

int
sched_setprocset(procset_t *procset, l_pid_t pid)
{
	id_t lid, rid;
	idtype_t lidtype, ridtype;

	/*
	 * define the target lwp
	 */
	if (pid == 0) {
		ridtype = P_ALL;
		lidtype = P_PID;
		rid = 0;
		lid = P_MYID;
	} else {
		if (lx_lpid_to_spair(pid, &pid, &lid) < 0)
			return (set_errno(ESRCH));
		if (pid != curproc->p_pid)
			return (set_errno(ESRCH));
		rid = 0;
		ridtype = P_ALL;
		lidtype = P_LWPID;
	}
	setprocset(procset, POP_AND, lidtype, lid, ridtype, rid);

	return (0);
}

long
do_priocntlsys(int cmd, procset_t *procset, void *arg)
{
	return (priocntl_common(PC_VERSION, procset, cmd, (caddr_t)arg, 0,
	    UIO_SYSSPACE));
}
