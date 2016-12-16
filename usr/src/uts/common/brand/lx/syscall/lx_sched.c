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

/*
 * Emulation for scheduling related syscalls.
 *
 * Under a typical zone configuration the zones will always be running under
 * FSS so that no single zone can monopolize the system. Zones do not have the
 * privilege to leave FSS (for the obvious reason that this would violate the
 * global zone resource management policies). Thus, for the sched_* syscalls
 * we typically will never be able to emulate those using our other native
 * scheduling classes. Under this common case we simply track the scheduler
 * settings on the lwp's lx brand structure and we also try to adjust the
 * lwp priority within the valid range to approximate the intended effect.
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
#include <sys/lx_brand.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>
#include <sys/procset.h>
#include <sys/priocntl.h>

typedef int l_pid_t;

extern int yield();
extern long priocntl_common(int, procset_t *, int, caddr_t, caddr_t, uio_seg_t);

static int lx_sched_setprocset(procset_t *, l_pid_t);
static long lx_do_priocntlsys(int, procset_t *, void *);

#define	BITS_PER_BYTE	8

/*
 * Linux scheduler policies.
 */
#define	LX_SCHED_OTHER		0
#define	LX_SCHED_FIFO		1
#define	LX_SCHED_RR		2
#define	LX_SCHED_BATCH		3
#define	LX_SCHED_IDLE		5
#define	LX_SCHED_DEADLINE	6

/*
 * Linux scheduler priority ranges.
 */
#define	LX_SCHED_PRIORITY_MIN_OTHER	0
#define	LX_SCHED_PRIORITY_MAX_OTHER	0
#define	LX_SCHED_PRIORITY_MIN_RRFIFO	1
#define	LX_SCHED_PRIORITY_MAX_RRFIFO	99

#define	MAXPRI	60	/* See FSS_MAXUPRI */

/*
 * When emulating scheduling priorities (e.g. under FSS) we'll do the best we
 * can by adjusting the thread's priority within our range.
 */
static int lx_emul_pri_map[] = {
	0,		/* LX_SCHED_OTHER */
	MAXPRI,		/* LX_SCHED_FIFO */
	MAXPRI - 1,	/* LX_SCHED_RR */
	-MAXPRI + 1,	/* LX_SCHED_BATCH */
	0,		/* UNUSED */
	-MAXPRI,	/* LX_SCHED_IDLE */
	MAXPRI		/* LX_SCHED_DEADLINE */
};

/*
 * Determine if we should emulate the sched_* syscalls. A zone is almost always
 * going to be running under FSS in any kind of production configuration, and
 * FSS is currently the only class which zone processes won't have the privilege
 * to leave. Instead of checking for FSS explicitly, we generalize our check
 * using CL_CANEXIT.
 */
#define	EMUL_SCHED()	(CL_CANEXIT(curthread, CRED()) != 0)

struct lx_sched_param {
	int	lx_sched_prio;
};

typedef struct lx_sched_attr {
	uint32_t lx_size;

	uint32_t lx_sched_policy;
	uint64_t lx_sched_flags;

	/* For LX_SCHED_OTHER or LX_SCHED_BATCH */
	int lx_sched_nice;

	/* For LX_SCHED_FIFO or LX_SCHED_RR */
	uint32_t lx_sched_priority;

	/* For LX_SCHED_DEADLINE */
	uint64_t lx_sched_runtime;
	uint64_t lx_sched_deadline;
	uint64_t lx_sched_period;
} lx_sched_attr_t;

long
lx_sched_yield(void)
{
	yield();

	return (0);
}

static void
ltos_cpuset(lx_affmask_t *lmask, cpuset_t *smask)
{
	/* NOTE: fix this code if NCPU is ever made > LX_NCPU */

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
	/* NOTE: fix this code if NCPU is ever made > LX_NCPU */

	bzero(lmask, sizeof (*lmask));
	for (int i = 0; i < NCPU; i++) {
		if (cpu_in_set(smask, i)) {
			BT_SET(*lmask, i);
		}
	}
}

/*
 * Find and lock a process for lx_sched_* operations.
 * Sets 'pp' and 'tp' on success, with P_PR_LOCK set and p_lock held.
 * The target process must be branded.
 */
static int
lx_sched_pidlock(l_pid_t pid, proc_t **pp, kthread_t **tp, boolean_t is_write)
{
	proc_t		*p;
	kthread_t	*t = NULL;
	int		err = 0;

	if (pid < 0) {
		return (EINVAL);
	}
	if (pid == 0) {
		p = curproc;
		ASSERT(PROC_IS_BRANDED(p));
		mutex_enter(&p->p_lock);
		sprlock_proc(p);

		*tp = curthread;
		*pp = p;
		return (0);
	}

	if (lx_lpid_lock((pid_t)pid, curzone, LXP_PRLOCK, &p, &t) != 0) {
		return (ESRCH);
	}

	ASSERT(MUTEX_HELD(&p->p_lock));
	if (!(PROC_IS_BRANDED(p))) {
		sprunlock(p);
		return (EPERM);
	}

	if (is_write) {
		cred_t *cr = CRED();

		/*
		 * To perform a sched_* operation on a thread outside of the
		 * current process, either the euid/egid of the target must
		 * match, or the calling process must hold CAP_SYS_NICE.
		 * (PRIV_PROC_PRIOUP maps to CAP_SYS_NICE)
		 */
		err = 0;
		if (secpolicy_raisepriority(cr) != 0) {
			err = 0;
			mutex_exit(&p->p_lock);
			mutex_enter(&p->p_crlock);
			if (crgetuid(cr) != crgetuid(p->p_cred) ||
			    crgetgid(cr) != crgetgid(p->p_cred)) {
				err = EPERM;
			}
			mutex_exit(&p->p_crlock);
			mutex_enter(&p->p_lock);
			if (err != 0) {
				sprunlock(p);
				return (err);
			}
		}
	}
	*pp = p;
	*tp = t;
	ASSERT(MUTEX_HELD(&p->p_lock));
	return (0);
}

long
lx_sched_getaffinity(l_pid_t pid, unsigned int len, void *maskp)
{
	proc_t		*p;
	kthread_t	*tp = NULL;
	lx_lwp_data_t	*lwpd;
	int		err;
	unsigned int	pmin, pmax, compare_size;
	lx_affmask_t	lmask;
	cpuset_t	*smask;

	/*
	 * The length boundary requirement is to match Linux's behavior.
	 */
	switch (get_udatamodel()) {
	case DATAMODEL_ILP32:
		compare_size = sizeof (uint32_t);
		break;
	default:
		compare_size = sizeof (ulong_t);
		break;
	}
	if ((len & (compare_size - 1)) != 0) {
		return (set_errno(EINVAL));
	}

	smask = cpuset_alloc(KM_SLEEP);
	if ((err = lx_sched_pidlock(pid, &p, &tp, B_FALSE)) != 0) {
		cpuset_free(smask);
		return (set_errno(err));
	}

	mutex_exit(&p->p_lock);
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
	mutex_exit(&p->p_lock);
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

	if (pid < 0 || param == NULL)
		return (set_errno(EINVAL));

	if (copyin(param, &sched_param, sizeof (sched_param)))
		return (set_errno(EFAULT));

	prio = sched_param.lx_sched_prio;

	if (EMUL_SCHED()) {
		proc_t		*p;
		kthread_t	*tp = NULL;
		int		incr;
		lx_lwp_data_t	*lwpd;

		switch (policy) {
		case LX_SCHED_OTHER:
		case LX_SCHED_BATCH:
		case LX_SCHED_IDLE:
		case LX_SCHED_DEADLINE:
			if (prio != LX_SCHED_PRIORITY_MIN_OTHER)
				return (set_errno(EINVAL));
			break;
		case LX_SCHED_FIFO:
		case LX_SCHED_RR:
			if (crgetuid(CRED()) != 0)
				return (set_errno(EPERM));
			if (prio < LX_SCHED_PRIORITY_MIN_RRFIFO ||
			    prio > LX_SCHED_PRIORITY_MAX_RRFIFO)
				return (set_errno(EINVAL));
			break;
		default:
			return (set_errno(EINVAL));
		}

		/* Find and operate on the target lwp. */
		if ((rv = lx_sched_pidlock(pid, &p, &tp, B_TRUE)) != 0)
			return (set_errno(rv));

		lwpd = lwptolxlwp(ttolwp(tp));
		if (lwpd->br_schd_class == LX_SCHED_IDLE &&
		    policy != LX_SCHED_IDLE && crgetuid(CRED()) != 0) {

			sprunlock(p);
			return (set_errno(EPERM));
		}

		lwpd->br_schd_class = policy;
		lwpd->br_schd_pri = prio;

		ASSERT(policy <= LX_SCHED_DEADLINE);
		incr = lx_emul_pri_map[policy];

		CL_DOPRIO(tp, CRED(), incr, &rv);

		sprunlock(p);
		return (0);
	}

	if ((rv = lx_sched_setprocset(&procset, pid)))
		return (rv);

	/* get the class id */
	pcparm.pc_cid = PC_CLNULL;
	(void) lx_do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/* get the current policy */
	bzero(&pcinfo, sizeof (pcinfo));
	pcinfo.pc_cid = pcparm.pc_cid;
	(void) lx_do_priocntlsys(PC_GETCLINFO, &procset, &pcinfo);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	if (policy < 0) {
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
		(void) lx_do_priocntlsys(PC_GETCID, &procset_cid, &pcinfo);
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
		(void) lx_do_priocntlsys(PC_GETCID, &procset_cid, &pcinfo);
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
	(void) lx_do_priocntlsys(PC_SETPARMS, &procset, &pcparm);

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
		return (set_errno(EINVAL));

	if (EMUL_SCHED()) {
		proc_t		*p;
		kthread_t	*tp = NULL;

		/* Find and operate on the target lwp. */
		if ((rv = lx_sched_pidlock(pid, &p, &tp, B_FALSE)) != 0)
			return (set_errno(rv));

		policy = lwptolxlwp(ttolwp(tp))->br_schd_class;
		sprunlock(p);

		return (policy);
	}

	if ((rv = lx_sched_setprocset(&procset, pid)))
		return (rv);

	/*
	 * get the class id
	 */
	pcparm.pc_cid = PC_CLNULL;
	(void) lx_do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * get the class info and identify the equivalent linux policy
	 */
	bzero(&pcinfo, sizeof (pcinfo));
	pcinfo.pc_cid = pcparm.pc_cid;
	(void) lx_do_priocntlsys(PC_GETCLINFO, &procset, &pcinfo);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	if (strcmp(pcinfo.pc_clname, "TS") == 0) {
		policy = LX_SCHED_OTHER;
	} else if (strcmp(pcinfo.pc_clname, "RT") == 0) {
		policy = ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs ==
		    RT_TQINF ? LX_SCHED_FIFO : LX_SCHED_RR;
	} else {
		policy = set_errno(EINVAL);
	}

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

	if (pid < 0 || param == NULL)
		return (set_errno(EINVAL));

	if (copyin(param, &sched_param, sizeof (sched_param)))
		return (set_errno(EFAULT));

	prio = sched_param.lx_sched_prio;

	if (EMUL_SCHED()) {
		proc_t		*p;
		kthread_t	*tp = NULL;
		int		incr;

		/* Find and operate on the target lwp. */
		if ((rv = lx_sched_pidlock(pid, &p, &tp, B_TRUE)) != 0)
			return (set_errno(rv));

		policy = lwptolxlwp(ttolwp(tp))->br_schd_class;
		switch (policy) {
		case LX_SCHED_OTHER:
		case LX_SCHED_BATCH:
		case LX_SCHED_IDLE:
		case LX_SCHED_DEADLINE:
			if (prio != LX_SCHED_PRIORITY_MIN_OTHER) {
				sprunlock(p);
				return (set_errno(EINVAL));
			}
			break;
		case LX_SCHED_FIFO:
		case LX_SCHED_RR:
			if (crgetuid(CRED()) != 0) {
				sprunlock(p);
				return (set_errno(EPERM));
			}
			if (prio < LX_SCHED_PRIORITY_MIN_RRFIFO ||
			    prio > LX_SCHED_PRIORITY_MAX_RRFIFO) {
				sprunlock(p);
				return (set_errno(EINVAL));
			}
			break;
		default:
			/* this shouldn't happen */
			ASSERT(0);
			sprunlock(p);
			return (set_errno(EINVAL));
		}

		lwptolxlwp(ttolwp(tp))->br_schd_pri = prio;

		ASSERT(policy <= LX_SCHED_DEADLINE);
		incr = lx_emul_pri_map[policy];

		CL_DOPRIO(tp, CRED(), incr, &rv);
		sprunlock(p);
		return (0);
	}

	if ((rv = lx_sched_setprocset(&procset, pid)))
		return (rv);

	/*
	 * get the class id
	 */
	pcparm.pc_cid = PC_CLNULL;
	(void) lx_do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * get the current policy
	 */
	bzero(&pcinfo, sizeof (pcinfo));
	pcinfo.pc_cid = pcparm.pc_cid;
	(void) lx_do_priocntlsys(PC_GETCLINFO, &procset, &pcinfo);
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
		(void) lx_do_priocntlsys(PC_GETCID, &procset_cid, &pcinfo);
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
		(void) lx_do_priocntlsys(PC_GETCID, &procset_cid, &pcinfo);
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
	(void) lx_do_priocntlsys(PC_SETPARMS, &procset, &pcparm);

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

	if (pid < 0 || param == NULL)
		return (set_errno(EINVAL));

	if (EMUL_SCHED()) {
		proc_t		*p;
		kthread_t	*tp = NULL;

		/* Find and operate on the target lwp. */
		if ((rv = lx_sched_pidlock(pid, &p, &tp, B_FALSE)) != 0)
			return (set_errno(rv));

		local_param.lx_sched_prio = lwptolxlwp(ttolwp(tp))->br_schd_pri;
		sprunlock(p);
		if (copyout(&local_param, param, sizeof (local_param)))
			return (set_errno(EFAULT));

		return (0);
	}

	if ((rv = lx_sched_setprocset(&procset, pid)))
		return (rv);

	/*
	 * get the class id
	 */
	pcparm.pc_cid = PC_CLNULL;
	(void) lx_do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * get the class info and identify the equivalent linux policy
	 */
	bzero(&pcinfo, sizeof (pcinfo));
	pcinfo.pc_cid = pcparm.pc_cid;
	(void) lx_do_priocntlsys(PC_GETCLINFO, &procset, &pcinfo);
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
		return (set_errno(EINVAL));

	if (EMUL_SCHED()) {
		int		policy;
		proc_t		*p;
		kthread_t	*tp = NULL;

		/* Find and operate on the target lwp. */
		if ((rv = lx_sched_pidlock(pid, &p, &tp, B_FALSE)) != 0)
			return (set_errno(rv));

		policy = lwptolxlwp(ttolwp(tp))->br_schd_class;
		sprunlock(p);

		interval.tv_sec = 0;
		if (policy == LX_SCHED_RR) {
			/* Use a made-up value similar to Linux */
			interval.tv_nsec = 100000000;
		} else {
			interval.tv_nsec = 0;
		}

#if defined(_SYSCALL32_IMPL)
		if (get_udatamodel() != DATAMODEL_NATIVE) {
			timespec32_t t32;

			/*
			 * A timespec may overflow for 32-bit but EOVERFLOW
			 * is not documented as an acceptable error for
			 * sched_rr_get_interval.  Such an occurance would be
			 * exceptionally weird for the RR interval.
			 */
			TIMESPEC_TO_TIMESPEC32(&t32, &interval);

			if (copyout(&t32, ival, sizeof (t32)) != 0) {
				return (set_errno(EFAULT));
			}
		}
		else
#endif
		{
			if (copyout(&interval, ival, sizeof (interval)))
				return (set_errno(EFAULT));
		}

		return (0);
	}

	if ((rv = lx_sched_setprocset(&procset, pid)))
		return (rv);

	/*
	 * get the class id
	 */
	pcparm.pc_cid = PC_CLNULL;
	(void) lx_do_priocntlsys(PC_GETPARMS, &procset, &pcparm);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * get the class info and identify the equivalent linux policy
	 */
	bzero(&pcinfo, sizeof (pcinfo));
	pcinfo.pc_cid = pcparm.pc_cid;
	(void) lx_do_priocntlsys(PC_GETCLINFO, &procset, &pcinfo);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * get the class info and identify the equivalent linux policy
	 */
	setprocset(&procset, POP_AND, P_PID, 0, P_ALL, 0);
	bzero(&pcinfo, sizeof (pcinfo));
	(void) strcpy(pcinfo.pc_clname, "RT");
	(void) lx_do_priocntlsys(PC_GETCID, &procset, &pcinfo);
	if (lwp->lwp_errno)
		return (lwp->lwp_errno);

	/*
	 * Contrary to what the man page says, you don't have to be in RR to
	 * get this interval.
	 */
	if (((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs != RT_TQINF) {
		interval.tv_sec = ((rtparms_t *)pcparm.pc_clparms)->rt_tqsecs;
		interval.tv_nsec = ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs;

#if defined(_SYSCALL32_IMPL)
		if (get_udatamodel() != DATAMODEL_NATIVE) {
			timespec32_t t32;

			/*
			 * Like above, the 32-bit EOVERFLOW check is not
			 * appropriate here.
			 */
			TIMESPEC_TO_TIMESPEC32(&t32, &interval);

			if (copyout(&t32, ival, sizeof (t32)) != 0) {
				return (set_errno(EFAULT));
			}
		}
		else
#endif
		{
			if (copyout(&interval, ival, sizeof (interval)))
				return (set_errno(EFAULT));
		}

		return (0);
	}

	return (set_errno(EINVAL));
}

long
lx_sched_get_priority_min(uintptr_t policy)
{
	/*
	 * Linux scheduling priorities are not alterable, so there is no
	 * illumos translation necessary.
	 */
	switch (policy) {
	case LX_SCHED_FIFO:
	case LX_SCHED_RR:
		return (LX_SCHED_PRIORITY_MIN_RRFIFO);
	case LX_SCHED_OTHER:
	case LX_SCHED_BATCH:
	case LX_SCHED_IDLE:
	case LX_SCHED_DEADLINE:
		return (LX_SCHED_PRIORITY_MIN_OTHER);
	default:
		break;
	}
	return (set_errno(EINVAL));
}

long
lx_sched_get_priority_max(uintptr_t policy)
{
	/*
	 * Linux scheduling priorities are not alterable, so there is no
	 * illumos translation necessary.
	 */
	switch (policy) {
	case LX_SCHED_FIFO:
	case LX_SCHED_RR:
		return (LX_SCHED_PRIORITY_MAX_RRFIFO);
	case LX_SCHED_OTHER:
	case LX_SCHED_BATCH:
	case LX_SCHED_IDLE:
	case LX_SCHED_DEADLINE:
		return (LX_SCHED_PRIORITY_MAX_OTHER);
	default:
		break;
	}
	return (set_errno(EINVAL));
}

long
lx_sched_setattr(l_pid_t pid, lx_sched_attr_t *attr, uint32_t flags)
{
	int		rv;
	uint32_t	lx_size;
	lx_sched_attr_t local_attr;
	uint64_t	flg;

	if (pid < 0 || attr == NULL || flags != 0)
		return (set_errno(EINVAL));

	if (copyin(attr, &lx_size, sizeof (lx_size)))
		return (set_errno(EFAULT));

	if (lx_size > sizeof (local_attr))
		return (set_errno(E2BIG));

	bzero(&local_attr, sizeof (local_attr));
	if (copyin(attr, &local_attr, lx_size))
		return (set_errno(EFAULT));

	flg = local_attr.lx_sched_flags;
	if ((flg & ~LX_SCHED_FLAG_RESET_ON_FORK) != 0)
		return (set_errno(EINVAL));

	if (EMUL_SCHED()) {
		int		policy;
		proc_t		*p;
		kthread_t	*tp = NULL;
		int		incr;
		lx_lwp_data_t	*lwpd;

		/* Find and operate on the target lwp. */
		if ((rv = lx_sched_pidlock(pid, &p, &tp, B_TRUE)) != 0)
			return (set_errno(rv));

		policy = local_attr.lx_sched_policy;

		switch (policy) {
		case LX_SCHED_OTHER:
		case LX_SCHED_BATCH:
		case LX_SCHED_IDLE:
			break;
		case LX_SCHED_FIFO:
		case LX_SCHED_RR:
			if (crgetuid(CRED()) != 0) {
				sprunlock(p);
				return (set_errno(EPERM));
			}
			if (local_attr.lx_sched_priority <
			    LX_SCHED_PRIORITY_MIN_RRFIFO ||
			    local_attr.lx_sched_priority >
			    LX_SCHED_PRIORITY_MAX_RRFIFO) {
				sprunlock(p);
				return (set_errno(EINVAL));
			}
			break;

		case LX_SCHED_DEADLINE:
			if (crgetuid(CRED()) != 0) {
				sprunlock(p);
				return (set_errno(EPERM));
			}
			break;
		default:
			sprunlock(p);
			return (set_errno(EINVAL));
		}

		lwpd = lwptolxlwp(ttolwp(tp));
		lwpd->br_schd_class = policy;
		lwpd->br_schd_flags = flg;
		lwpd->br_schd_pri = local_attr.lx_sched_priority;

		lwpd->br_schd_runtime = local_attr.lx_sched_runtime;
		lwpd->br_schd_deadline = local_attr.lx_sched_deadline;
		lwpd->br_schd_period = local_attr.lx_sched_period;

		ASSERT(policy <= LX_SCHED_DEADLINE);
		incr = lx_emul_pri_map[policy];

		CL_DOPRIO(tp, CRED(), incr, &rv);
		sprunlock(p);
		return (0);
	}

	/* Currently not supported under other classes */
	return (set_errno(ENOSYS));
}

long
lx_sched_getattr(l_pid_t pid, lx_sched_attr_t *attr, uint32_t size,
    uint32_t flags)
{
	lx_sched_attr_t local_attr;
	int rv;

	if (pid < 0 || attr == NULL || flags != 0 || size < sizeof (local_attr))
		return (set_errno(EINVAL));

	bzero(&local_attr, sizeof (local_attr));
	if (EMUL_SCHED()) {
		proc_t		*p;
		kthread_t	*tp = NULL;
		lx_lwp_data_t	*lwpd;

		/* Find and operate on the target lwp. */
		if ((rv = lx_sched_pidlock(pid, &p, &tp, B_FALSE)) != 0)
			return (set_errno(rv));

		lwpd = lwptolxlwp(ttolwp(tp));
		local_attr.lx_sched_policy = lwpd->br_schd_class;
		local_attr.lx_sched_priority = lwpd->br_schd_pri;
		local_attr.lx_sched_flags = lwpd->br_schd_flags;

		local_attr.lx_sched_runtime = lwpd->br_schd_runtime;
		local_attr.lx_sched_deadline = lwpd->br_schd_deadline;
		local_attr.lx_sched_period = lwpd->br_schd_period;

		sprunlock(p);

		local_attr.lx_size = sizeof (lx_sched_attr_t);

		if (copyout(&local_attr, attr, sizeof (local_attr)))
			return (set_errno(EFAULT));

		return (0);
	}

	/* Currently not supported under other classes */
	return (set_errno(ENOSYS));
}

static int
lx_sched_setprocset(procset_t *procset, l_pid_t pid)
{
	id_t lid, rid;
	idtype_t lidtype, ridtype;

	/*
	 * define the target lwp
	 */
	if (pid == 0)
		pid = curproc->p_pid;

	if (lx_lpid_to_spair(pid, &pid, &lid) < 0)
		return (set_errno(ESRCH));
	rid = 0;
	ridtype = P_ALL;
	lidtype = P_LWPID;

	setprocset(procset, POP_AND, lidtype, lid, ridtype, rid);

	return (0);
}

static long
lx_do_priocntlsys(int cmd, procset_t *procset, void *arg)
{
	return (priocntl_common(PC_VERSION, procset, cmd, (caddr_t)arg, 0,
	    UIO_SYSSPACE));
}
