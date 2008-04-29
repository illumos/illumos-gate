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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"
#include "thr_uberdata.h"
#include <sched.h>
#include <sys/tspriocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/fxpriocntl.h>

/*
 * The following array is used for caching information
 * for priocntl scheduling classes.
 */
static pcclass_t sched_class[] = {
	{0, SCHED_OTHER, 0, 0, {-1, "TS",  0}},
	{0, SCHED_FIFO,	 0, 0, {-1, "RT",  0}},
	{0, SCHED_RR,	 0, 0, {-1, "RT",  0}},
	{0, SCHED_SYS,	 0, 0, {0,  "SYS", 0}},
	{0, SCHED_IA,	 0, 0, {-1, "IA",  0}},
	{0, SCHED_FSS,	 0, 0, {-1, "FSS", 0}},
	{0, SCHED_FX,	 0, 0, {-1, "FX",  0}},
	/*
	 * Allow unknown (to us) scheduling classes.
	 * The kernel allows space for exactly 10 scheduling classes
	 * (see the definitions of 'sclass' and 'nclass' in the kernel).
	 * We need that number of available slots here.
	 * If the kernel space is changed, this has to change too.
	 */
	{0, -1,		 0, 0, {-1, "",	   0}},
	{0, -1,		 0, 0, {-1, "",	   0}},
	{0, -1,		 0, 0, {-1, "",	   0}},
	{0, -1,		 0, 0, {-1, "",	   0}},
	{0, -1,		 0, 0, {-1, "",	   0}},
	{0, -1,		 0, 0, {-1, "",	   0}},
	{0, -1,		 0, 0, {-1, "",	   0}},
	{0, -1,		 0, 0, {-1, "",	   0}},
	{0, -1,		 0, 0, {-1, "",	   0}},
	{0, -1,		 0, 0, {-1, "",	   0}},
};

#define	NPOLICY	(sizeof (sched_class) / sizeof (pcclass_t))

#if _SCHED_NEXT != SCHED_FX + 1
#error "fatal: _SCHED_NEXT != SCHED_FX + 1"
#endif

static mutex_t class_lock = DEFAULTMUTEX;	/* protects sched_class[] */

/*
 * Helper function for get_info_by_policy(), below.
 * Don't let a manufactured policy number duplicate
 * the class of one of our base policy numbers.
 */
static int
is_base_class(const char *clname)
{
	const pcclass_t	*pccp;
	int		policy;

	for (policy = 0, pccp = sched_class;
	    policy < _SCHED_NEXT;
	    policy++, pccp++) {
		if (strcmp(clname, pccp->pcc_info.pc_clname) == 0)
			return (1);
	}
	return (0);
}

/*
 * Cache priocntl information on scheduling class by policy.
 */
const pcclass_t *
get_info_by_policy(int policy)
{
	pcclass_t *pccp = &sched_class[policy];
	pcpri_t pcpri;
	pri_t prio;
	int base = 0;

	if ((uint_t)policy >= NPOLICY || pccp->pcc_state < 0) {
		errno = EINVAL;
		return (NULL);
	}

	if (pccp->pcc_state > 0)
		return (pccp);

	lmutex_lock(&class_lock);

	/* get class info (the system class is known to have class-id == 0) */
	if (pccp->pcc_policy == -1) {
		/* policy number not defined in <sched.h> */
		ASSERT(policy >= _SCHED_NEXT);
		pccp->pcc_info.pc_cid = policy - _SCHED_NEXT;
		if (priocntl(0, 0, PC_GETCLINFO, &pccp->pcc_info) == -1 ||
		    (base = is_base_class(pccp->pcc_info.pc_clname)) != 0) {
			pccp->pcc_info.pc_clname[0] = '\0';
			pccp->pcc_info.pc_cid = -1;
			/*
			 * If we duplicated a base class, permanently
			 * disable this policy entry.  Else allow for
			 * dynamic loading of scheduling classes.
			 */
			if (base) {
				_membar_producer();
				pccp->pcc_state = -1;
			}
			errno = EINVAL;
			lmutex_unlock(&class_lock);
			return (NULL);
		}
		pccp->pcc_policy = policy;
	} else if (policy != SCHED_SYS &&
	    priocntl(0, 0, PC_GETCID, &pccp->pcc_info) == -1) {
		_membar_producer();
		pccp->pcc_state = -1;
		errno = EINVAL;
		lmutex_unlock(&class_lock);
		return (NULL);
	}

	switch (policy) {
	case SCHED_OTHER:
		prio = ((tsinfo_t *)pccp->pcc_info.pc_clinfo)->ts_maxupri;
		pccp->pcc_primin = -prio;
		pccp->pcc_primax = prio;
		break;
	case SCHED_FIFO:
	case SCHED_RR:
		prio = ((rtinfo_t *)pccp->pcc_info.pc_clinfo)->rt_maxpri;
		pccp->pcc_primin = 0;
		pccp->pcc_primax = prio;
		break;
	default:
		/*
		 * All other policy numbers, including policy numbers
		 * not defined in <sched.h>.
		 */
		pcpri.pc_cid = pccp->pcc_info.pc_cid;
		if (priocntl(0, 0, PC_GETPRIRANGE, &pcpri) == 0) {
			pccp->pcc_primin = pcpri.pc_clpmin;
			pccp->pcc_primax = pcpri.pc_clpmax;
		}
		break;
	}

	_membar_producer();
	pccp->pcc_state = 1;
	lmutex_unlock(&class_lock);
	return (pccp);
}

const pcclass_t *
get_info_by_class(id_t classid)
{
	pcinfo_t	pcinfo;
	pcclass_t	*pccp;
	int		policy;

	if (classid < 0) {
		errno = EINVAL;
		return (NULL);
	}

	/* determine if we already know this classid */
	for (policy = 0, pccp = sched_class;
	    policy < NPOLICY;
	    policy++, pccp++) {
		if (pccp->pcc_state > 0 && pccp->pcc_info.pc_cid == classid)
			return (pccp);
	}

	pcinfo.pc_cid = classid;
	if (priocntl(0, 0, PC_GETCLINFO, &pcinfo) == -1) {
		if (classid == 0)	/* no kernel info for sys class */
			return (get_info_by_policy(SCHED_SYS));
		return (NULL);
	}

	for (policy = 0, pccp = sched_class;
	    policy < NPOLICY;
	    policy++, pccp++) {
		if (pccp->pcc_state == 0 &&
		    strcmp(pcinfo.pc_clname, pccp->pcc_info.pc_clname) == 0)
			return (get_info_by_policy(pccp->pcc_policy));
	}

	/*
	 * We have encountered an unknown (to us) scheduling class.
	 * Manufacture a policy number for it.  Hopefully we still
	 * have room in the sched_class[] table.
	 */
	policy = _SCHED_NEXT + classid;
	if (policy >= NPOLICY) {
		errno = EINVAL;
		return (NULL);
	}
	lmutex_lock(&class_lock);
	pccp = &sched_class[policy];
	pccp->pcc_policy = policy;
	(void) strlcpy(pccp->pcc_info.pc_clname, pcinfo.pc_clname, PC_CLNMSZ);
	lmutex_unlock(&class_lock);
	return (get_info_by_policy(pccp->pcc_policy));
}

/*
 * Helper function: get process or lwp current scheduling policy.
 */
static const pcclass_t *
get_parms(idtype_t idtype, id_t id, pcparms_t *pcparmp)
{
	pcparmp->pc_cid = PC_CLNULL;
	if (priocntl(idtype, id, PC_GETPARMS, pcparmp) == -1)
		return (NULL);
	return (get_info_by_class(pcparmp->pc_cid));
}

/*
 * Helper function for setprio() and setparam(), below.
 */
static int
set_priority(idtype_t idtype, id_t id, int policy, int prio,
    pcparms_t *pcparmp, int settq)
{
	int rv;

	switch (policy) {
	case SCHED_OTHER:
	{
		tsparms_t *tsp = (tsparms_t *)pcparmp->pc_clparms;
		tsp->ts_uprilim = prio;
		tsp->ts_upri = prio;
		break;
	}
	case SCHED_FIFO:
	case SCHED_RR:
	{
		rtparms_t *rtp = (rtparms_t *)pcparmp->pc_clparms;
		rtp->rt_tqnsecs = settq?
		    (policy == SCHED_FIFO? RT_TQINF : RT_TQDEF) :
		    RT_NOCHANGE;
		rtp->rt_pri = prio;
		break;
	}
	default:
	{
		/*
		 * Class-independent method for setting the priority.
		 */
		pcprio_t pcprio;

		pcprio.pc_op = PC_SETPRIO;
		pcprio.pc_cid = pcparmp->pc_cid;
		pcprio.pc_val = prio;
		do {
			rv = priocntl(idtype, id, PC_DOPRIO, &pcprio);
		} while (rv == -1 && errno == ENOMEM);
		return (rv);
	}
	}

	do {
		rv = priocntl(idtype, id, PC_SETPARMS, pcparmp);
	} while (rv == -1 && errno == ENOMEM);
	return (rv);
}

/*
 * Utility function, private to libc, used by sched_setparam()
 * and posix_spawn().  Because it is called by the vfork() child of
 * posix_spawn(), we must not call any functions exported from libc.
 */
id_t
setprio(idtype_t idtype, id_t id, int prio, int *policyp)
{
	pcparms_t	pcparm;
	int		policy;
	const pcclass_t	*pccp;

	if ((pccp = get_parms(idtype, id, &pcparm)) == NULL)
		return (-1);
	if (prio < pccp->pcc_primin || prio > pccp->pcc_primax) {
		errno = EINVAL;
		return (-1);
	}

	policy = pccp->pcc_policy;
	if (policyp != NULL &&
	    (policy == SCHED_FIFO || policy == SCHED_RR)) {
		rtparms_t *rtp = (rtparms_t *)pcparm.pc_clparms;
		policy = (rtp->rt_tqnsecs == RT_TQINF? SCHED_FIFO : SCHED_RR);
	}

	if (set_priority(idtype, id, policy, prio, &pcparm, 0) == -1)
		return (-1);
	if (policyp != NULL)
		*policyp = policy;
	return (pccp->pcc_info.pc_cid);
}

int
sched_setparam(pid_t pid, const struct sched_param *param)
{
	if (pid < 0) {
		errno = ESRCH;
		return (-1);
	}
	if (pid == 0)
		pid = P_MYID;

	if (setprio(P_PID, pid, param->sched_priority, NULL) == -1)
		return (-1);
	return (0);
}

id_t
getparam(idtype_t idtype, id_t id, int *policyp, struct sched_param *param)
{
	pcparms_t pcparm;
	const pcclass_t *pccp;
	int policy;
	int priority;

	if ((pccp = get_parms(idtype, id, &pcparm)) == NULL)
		return (-1);

	switch (policy = pccp->pcc_policy) {
	case SCHED_OTHER:
	{
		tsparms_t *tsp = (tsparms_t *)pcparm.pc_clparms;
		priority = tsp->ts_upri;
		break;
	}
	case SCHED_FIFO:
	case SCHED_RR:
	{
		rtparms_t *rtp = (rtparms_t *)pcparm.pc_clparms;
		priority = rtp->rt_pri;
		policy = (rtp->rt_tqnsecs == RT_TQINF? SCHED_FIFO : SCHED_RR);
		break;
	}
	default:
	{
		/*
		 * Class-independent method for getting the priority.
		 */
		pcprio_t pcprio;

		pcprio.pc_op = PC_GETPRIO;
		pcprio.pc_cid = 0;
		pcprio.pc_val = 0;
		if (priocntl(idtype, id, PC_DOPRIO, &pcprio) == 0)
			priority = pcprio.pc_val;
		else
			priority = 0;
		break;
	}
	}

	*policyp = policy;
	(void) memset(param, 0, sizeof (*param));
	param->sched_priority = priority;

	return (pcparm.pc_cid);
}

int
sched_getparam(pid_t pid, struct sched_param *param)
{
	int policy;

	if (pid < 0) {
		errno = ESRCH;
		return (-1);
	}
	if (pid == 0)
		pid = P_MYID;

	if (getparam(P_PID, pid, &policy, param) == -1)
		return (-1);
	return (0);
}

/*
 * Utility function, private to libc, used by sched_setscheduler()
 * and posix_spawn().  Because it is called by the vfork() child of
 * posix_spawn(), we must not call any functions exported from libc.
 */
id_t
setparam(idtype_t idtype, id_t id, int policy, int prio)
{
	pcparms_t	pcparm;
	const pcclass_t	*pccp;

	if (policy == SCHED_SYS ||
	    (pccp = get_info_by_policy(policy)) == NULL ||
	    prio < pccp->pcc_primin || prio > pccp->pcc_primax) {
		errno = EINVAL;
		return (-1);
	}

	pcparm.pc_cid = pccp->pcc_info.pc_cid;
	if (set_priority(idtype, id, policy, prio, &pcparm, 1) == -1)
		return (-1);
	return (pccp->pcc_info.pc_cid);
}

int
sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
{
	pri_t		prio = param->sched_priority;
	int		oldpolicy;

	if ((oldpolicy = sched_getscheduler(pid)) < 0)
		return (-1);

	if (pid == 0)
		pid = P_MYID;

	if (setparam(P_PID, pid, policy, prio) == -1)
		return (-1);

	return (oldpolicy);
}

int
sched_getscheduler(pid_t pid)
{
	pcparms_t	pcparm;
	const pcclass_t	*pccp;
	int		policy;

	if (pid < 0) {
		errno = ESRCH;
		return (-1);
	}
	if (pid == 0)
		pid = P_MYID;

	if ((pccp = get_parms(P_PID, pid, &pcparm)) == NULL)
		return (-1);

	if ((policy = pccp->pcc_policy) == SCHED_FIFO || policy == SCHED_RR) {
		policy =
		    (((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs == RT_TQINF?
		    SCHED_FIFO : SCHED_RR);
	}

	return (policy);
}

int
sched_yield(void)
{
	yield();
	return (0);
}

int
sched_get_priority_max(int policy)
{
	const pcclass_t *pccp;

	if ((pccp = get_info_by_policy(policy)) != NULL)
		return (pccp->pcc_primax);
	errno = EINVAL;
	return (-1);
}

int
sched_get_priority_min(int policy)
{
	const pcclass_t *pccp;

	if ((pccp = get_info_by_policy(policy)) != NULL)
		return (pccp->pcc_primin);
	errno = EINVAL;
	return (-1);
}

int
sched_rr_get_interval(pid_t pid, timespec_t *interval)
{
	pcparms_t pcparm;
	const pcclass_t *pccp;

	if (pid < 0) {
		errno = ESRCH;
		return (-1);
	}
	if (pid == 0)
		pid = P_MYID;

	if ((pccp = get_parms(P_PID, pid, &pcparm)) == NULL)
		return (-1);

	/*
	 * At the moment, we have no class-independent method to fetch
	 * the process/lwp time quantum.  Since SUSv3 does not restrict
	 * this operation to the real-time class, we return an indefinite
	 * quantum (tv_sec == 0 and tv_nsec == 0) for scheduling policies
	 * for which this information isn't available.
	 */
	interval->tv_sec = 0;
	interval->tv_nsec = 0;

	switch (pccp->pcc_policy) {
	case SCHED_FIFO:
	case SCHED_RR:
		{
			rtparms_t *rtp = (rtparms_t *)pcparm.pc_clparms;
			if (rtp->rt_tqnsecs != RT_TQINF) {
				interval->tv_sec = rtp->rt_tqsecs;
				interval->tv_nsec = rtp->rt_tqnsecs;
			}
		}
		break;
	case SCHED_FX:
		{
			fxparms_t *fxp = (fxparms_t *)pcparm.pc_clparms;
			if (fxp->fx_tqnsecs != FX_TQINF) {
				interval->tv_sec = fxp->fx_tqsecs;
				interval->tv_nsec = fxp->fx_tqnsecs;
			}
		}
		break;
	}

	return (0);
}

/*
 * Initialize or update ul_policy, ul_cid, and ul_pri.
 */
void
update_sched(ulwp_t *self)
{
	volatile sc_shared_t *scp;
	pcparms_t pcparm;
	pcprio_t pcprio;
	const pcclass_t *pccp;
	int priority;
	int policy;

	ASSERT(self == curthread);

	enter_critical(self);

	if ((scp = self->ul_schedctl) == NULL &&
	    (scp = setup_schedctl()) == NULL) {		/* can't happen? */
		if (self->ul_policy < 0) {
			self->ul_cid = 0;
			self->ul_pri = 0;
			_membar_producer();
			self->ul_policy = SCHED_OTHER;
		}
		exit_critical(self);
		return;
	}

	if (self->ul_policy >= 0 &&
	    self->ul_cid == scp->sc_cid &&
	    (self->ul_pri == scp->sc_cpri ||
	    (self->ul_epri > 0 && self->ul_epri == scp->sc_cpri))) {
		exit_critical(self);
		return;
	}

	pccp = get_parms(P_LWPID, P_MYID, &pcparm);
	if (pccp == NULL) {		/* can't happen? */
		self->ul_cid = scp->sc_cid;
		self->ul_pri = scp->sc_cpri;
		_membar_producer();
		self->ul_policy = SCHED_OTHER;
		exit_critical(self);
		return;
	}

	switch (policy = pccp->pcc_policy) {
	case SCHED_OTHER:
		priority = ((tsparms_t *)pcparm.pc_clparms)->ts_upri;
		break;
	case SCHED_FIFO:
	case SCHED_RR:
		self->ul_rtclassid = pccp->pcc_info.pc_cid;
		priority = ((rtparms_t *)pcparm.pc_clparms)->rt_pri;
		policy =
		    ((rtparms_t *)pcparm.pc_clparms)->rt_tqnsecs == RT_TQINF?
		    SCHED_FIFO : SCHED_RR;
		break;
	default:
		/*
		 * Class-independent method for getting the priority.
		 */
		pcprio.pc_op = PC_GETPRIO;
		pcprio.pc_cid = 0;
		pcprio.pc_val = 0;
		if (priocntl(P_LWPID, P_MYID, PC_DOPRIO, &pcprio) == 0)
			priority = pcprio.pc_val;
		else
			priority = 0;
	}

	self->ul_cid = pcparm.pc_cid;
	self->ul_pri = priority;
	_membar_producer();
	self->ul_policy = policy;

	exit_critical(self);
}
