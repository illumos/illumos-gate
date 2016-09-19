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
/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/cpu.h>
#include <sys/rtpriocntl.h>
#include <sys/tspriocntl.h>
#include <sys/processor.h>
#include <sys/brand.h>
#include <sys/lx_sched.h>
#include <sys/lx_brand.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>

extern int yield();
extern long priocntl_common(int, procset_t *, int, caddr_t, caddr_t, uio_seg_t);

#define	BITS_PER_BYTE	8

long
lx_sched_yield(void)
{
	yield();

	return (0);
}

static void
ltos_cpuset(lx_affmask_t *lmask, cpuset_t *smask)
{
	ASSERT(NCPU <= LX_NCPU);

	cpuset_zero(smask);
	for (int i = 0; i < NCPU; i++) {
		if (BT_TEST(*lmask, i)) {
			cpuset_add(smask, i);
		}
	}
}

static void
stol_cpuset(cpuset_t *smask, lx_affmask_t *lmask)
{
	ASSERT(NCPU <= LX_NCPU);

	bzero(lmask, sizeof (*lmask));
	for (int i = 0; i < NCPU; i++) {
		if (cpu_in_set(smask, i)) {
			BT_SET(*lmask, i);
		}
	}
}

/*
 * Find and lock a process for lx_sched_* operations.
 * Sets 'pp' and 'tp' on success, with P_PR_LOCK set (but p_lock not held).
 */
static int
lx_sched_pidlock(l_pid_t pid, proc_t **pp, kthread_t **tp, boolean_t is_write)
{
	pid_t		s_pid;
	id_t		s_tid;
	proc_t		*p;
	kthread_t	*t = NULL;
	int		err = 0;
	lwpdir_t	*ld;

	if (pid < 0) {
		return (EINVAL);
	}
	if (pid == 0) {
		p = curproc;
		mutex_enter(&p->p_lock);
		sprlock_proc(p);
		mutex_exit(&p->p_lock);

		*tp = curthread;
		*pp = p;
		return (0);
	}

	if (lx_lpid_to_spair((pid_t)pid, &s_pid, &s_tid) < 0) {
		return (ESRCH);
	}
	mutex_enter(&pidlock);
	if ((p = prfind(s_pid)) == NULL) {
		mutex_exit(&pidlock);
		return (ESRCH);
	}
	mutex_enter(&p->p_lock);
	mutex_exit(&pidlock);

	err = sprtrylock_proc(p);
	if (err < 0) {
		mutex_exit(&p->p_lock);
		return (ESRCH);
	} else if (err > 0) {
		sprwaitlock_proc(p);
		err = 0;
	}

	ld = lwp_hash_lookup(p, s_tid);
	if (ld != NULL) {
		t = ld->ld_entry->le_thread;
	} else {
		sprunlock(p);
		return (ESRCH);
	}

	mutex_exit(&p->p_lock);
	if (is_write) {
		cred_t *cr = CRED();

		/*
		 * To perform a sched_setaffinity on a thread outside of the
		 * current process, either the euid/egid of the target must
		 * match, or the calling process must hold CAP_SYS_NICE.
		 * (PRIV_PROC_PRIOUP maps to CAP_SYS_NICE)
		 */
		err = 0;
		if (secpolicy_raisepriority(cr) != 0) {
			err = 0;
			mutex_enter(&p->p_crlock);
			if (crgetuid(cr) != crgetuid(p->p_cred) ||
			    crgetgid(cr) != crgetgid(p->p_cred)) {
				err = EPERM;
			}
			mutex_exit(&p->p_crlock);
			if (err != 0) {
				mutex_enter(&p->p_lock);
				sprunlock(p);
				return (err);
			}
		}
	}
	*pp = p;
	*tp = t;
	return (0);
}

long
lx_sched_getaffinity(l_pid_t pid, unsigned int len, void *maskp)
{
	proc_t		*p;
	kthread_t	*tp = NULL;
	lx_lwp_data_t	*lwpd;
	int		err;
	unsigned int	pmin, pmax;
	lx_affmask_t	lmask;
	cpuset_t	*smask;

	/*
	 * The ulong_t boundary requirement is to match Linux's behavior.
	 */
	if ((len & (sizeof (ulong_t) - 1)) != 0) {
		return (set_errno(EINVAL));
	}

	smask = cpuset_alloc(KM_SLEEP);
	if ((err = lx_sched_pidlock(pid, &p, &tp, B_FALSE)) != 0) {
		cpuset_free(smask);
		return (set_errno(err));
	}

	mutex_enter(&cpu_lock);
	mutex_enter(&p->p_lock);
	/*
	 * Grab the existing affinity mask and constrain it by the current set
	 * of active CPUs (which may have changed since it was assigned.
	 */
	lwpd = ttolxlwp(tp);
	cpuset_or(smask, lwpd->br_affinitymask);
	cpuset_and(smask, &cpu_active_set);
	sprunlock(p);
	mutex_exit(&cpu_lock);

	cpuset_bounds(smask, &pmin, &pmax);
	stol_cpuset(smask, &lmask);
	cpuset_free(smask);

	/*
	 * It is out of convenience that this check is performed so late.  If
	 * the need arises, it could be altered to be done earlier in order to
	 * match Linux error ordering.
	 */
	if (pmax >= (len * BITS_PER_BYTE)) {
		return (set_errno(EINVAL));
	}

	len = MIN(len, sizeof (lx_affmask_t));
	if (copyout(&lmask, maskp, len) != 0) {
		return (set_errno(EFAULT));
	}
	return (len);
}

long
lx_sched_setaffinity(l_pid_t pid, unsigned int len, void *maskp)
{
	proc_t		*p;
	kthread_t	*tp = NULL;
	lx_lwp_data_t	*lwpd;
	int		err;
	unsigned int	pmin, pmax;
	lx_affmask_t	lmask;
	cpuset_t	*smask;

	if (pid < 0) {
		return (set_errno(EINVAL));
	}

	if (len < sizeof (lmask)) {
		bzero(&lmask, sizeof (lmask));
	} else if (len > sizeof (lmask)) {
		len = sizeof (lmask);
	}
	if (copyin(maskp, &lmask, len) != 0) {
		return (set_errno(EFAULT));
	}
	smask = cpuset_alloc(KM_SLEEP);
	ltos_cpuset(&lmask, smask);
	if ((err = lx_sched_pidlock(pid, &p, &tp, B_TRUE)) != 0) {
		cpuset_free(smask);
		return (set_errno(err));
	}

	/*
	 * Constrain the mask to currently active CPUs.
	 */
	mutex_enter(&cpu_lock);
	mutex_enter(&p->p_lock);
	lwpd = ttolxlwp(tp);

	cpuset_and(smask, &cpu_active_set);
	if (cpuset_isnull(smask)) {
		err = EINVAL;
		goto out;
	}
	if (cpuset_isequal(lwpd->br_affinitymask, smask)) {
		err = 0;
		goto out;
	}

	/*
	 * If one (and only one) CPU is selected in the affinity mask, bind the
	 * thread to that CPU.
	 */
	cpuset_bounds(smask, &pmin, &pmax);
	VERIFY(pmin != CPUSET_NOTINSET);
	if (pmin == pmax) {
		processorid_t obind;

		(void) cpu_bind_thread(tp, pmin, &obind, &err);
		if (err != 0) {
			goto out;
		}
	} else {
		/*
		 * If the thread transitions away from a single-CPU mask, it
		 * should be unbound from that processor.
		 */
		cpuset_bounds(lwpd->br_affinitymask, &pmin, &pmax);
		if (pmin == pmax) {
			processorid_t obind;
			(void) cpu_bind_thread(tp, PBIND_NONE, &obind, &err);
		}
	}
	cpuset_zero(lwpd->br_affinitymask);
	cpuset_or(lwpd->br_affinitymask, smask);
	err = 0;

out:
	mutex_exit(&cpu_lock);
	sprunlock(p);
	cpuset_free(smask);
	if (err != 0) {
		return (set_errno(err));
	}
	return (0);
}

void
lx_affinity_forklwp(klwp_t *srclwp, klwp_t *dstlwp)
{
	proc_t *pp = lwptoproc(srclwp);
	lx_lwp_data_t *slwpd = lwptolxlwp(srclwp);
	lx_lwp_data_t *dlwpd = lwptolxlwp(dstlwp);

	/*
	 * Copy over the affinity mask.  This could be enhanced in the future
	 * to perform single-CPU binding like sched_setaffinity.
	 */
	mutex_enter(&pp->p_lock);
	cpuset_zero(dlwpd->br_affinitymask);
	cpuset_or(dlwpd->br_affinitymask, slwpd->br_affinitymask);
	mutex_exit(&pp->p_lock);
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

	if ((rv = sched_setprocset(&procset, pid)))
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

		if (strcmp(pcinfo.pc_clname, "TS") == 0) {
			policy = LX_SCHED_OTHER;
		} else if (strcmp(pcinfo.pc_clname, "RT") == 0) {
			policy = ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs ==
			    RT_TQINF ? LX_SCHED_FIFO : LX_SCHED_RR;
		} else {
			return (set_errno(EINVAL));
		}
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

	if ((rv = sched_setprocset(&procset, pid)))
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

	if ((rv = sched_setprocset(&procset, pid)))
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

	if ((rv = sched_setprocset(&procset, pid)))
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
	} else if (strcmp(pcinfo.pc_clname, "RT") == 0) {
		local_param.lx_sched_prio =
		    ((rtparms_t *)pcparm.pc_clparms)->rt_pri;
	} else {
		rv = set_errno(EINVAL);
	}

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

	if ((rv = sched_setprocset(&procset, pid)))
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
