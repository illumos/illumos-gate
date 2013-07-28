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
 * Copyright 2013 Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/pcb.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/priocntl.h>
#include <sys/class.h>
#include <sys/disp.h>
#include <sys/procset.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/rt.h>
#include <sys/rtpriocntl.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/schedctl.h>
#include <sys/errno.h>
#include <sys/cpuvar.h>
#include <sys/vmsystm.h>
#include <sys/time.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/cpupart.h>
#include <sys/modctl.h>

static pri_t	rt_init(id_t, int, classfuncs_t **);

static struct sclass csw = {
	"RT",
	rt_init,
	0
};

static struct modlsched modlsched = {
	&mod_schedops, "realtime scheduling class", &csw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlsched, NULL
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (EBUSY);		/* don't remove RT for now */
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Class specific code for the real-time class
 */

/*
 * Extern declarations for variables defined in the rt master file
 */
#define	RTMAXPRI 59

pri_t rt_maxpri = RTMAXPRI;	/* maximum real-time priority */
rtdpent_t *rt_dptbl;	  /* real-time dispatcher parameter table */

/*
 * control flags (kparms->rt_cflags).
 */
#define	RT_DOPRI	0x01	/* change priority */
#define	RT_DOTQ		0x02	/* change RT time quantum */
#define	RT_DOSIG	0x04	/* change RT time quantum signal */

static int	rt_admin(caddr_t, cred_t *);
static int	rt_enterclass(kthread_t *, id_t, void *, cred_t *, void *);
static int	rt_fork(kthread_t *, kthread_t *, void *);
static int	rt_getclinfo(void *);
static int	rt_getclpri(pcpri_t *);
static int	rt_parmsin(void *);
static int	rt_parmsout(void *, pc_vaparms_t *);
static int	rt_vaparmsin(void *, pc_vaparms_t *);
static int	rt_vaparmsout(void *, pc_vaparms_t *);
static int	rt_parmsset(kthread_t *, void *, id_t, cred_t *);
static int	rt_donice(kthread_t *, cred_t *, int, int *);
static int	rt_doprio(kthread_t *, cred_t *, int, int *);
static void	rt_exitclass(void *);
static int	rt_canexit(kthread_t *, cred_t *);
static void	rt_forkret(kthread_t *, kthread_t *);
static void	rt_nullsys();
static void	rt_parmsget(kthread_t *, void *);
static void	rt_preempt(kthread_t *);
static void	rt_setrun(kthread_t *);
static void	rt_tick(kthread_t *);
static void	rt_wakeup(kthread_t *);
static pri_t	rt_swapin(kthread_t *, int);
static pri_t	rt_swapout(kthread_t *, int);
static pri_t	rt_globpri(kthread_t *);
static void	rt_yield(kthread_t *);
static int	rt_alloc(void **, int);
static void	rt_free(void *);

static void	rt_change_priority(kthread_t *, rtproc_t *);

static id_t	rt_cid;		/* real-time class ID */
static rtproc_t	rt_plisthead;	/* dummy rtproc at head of rtproc list */
static kmutex_t	rt_dptblock;	/* protects realtime dispatch table */
static kmutex_t	rt_list_lock;	/* protects RT thread list */

extern rtdpent_t *rt_getdptbl(void);

static struct classfuncs rt_classfuncs = {
	/* class ops */
	rt_admin,
	rt_getclinfo,
	rt_parmsin,
	rt_parmsout,
	rt_vaparmsin,
	rt_vaparmsout,
	rt_getclpri,
	rt_alloc,
	rt_free,
	/* thread ops */
	rt_enterclass,
	rt_exitclass,
	rt_canexit,
	rt_fork,
	rt_forkret,
	rt_parmsget,
	rt_parmsset,
	rt_nullsys,	/* stop */
	rt_nullsys,	/* exit */
	rt_nullsys,	/* active */
	rt_nullsys,	/* inactive */
	rt_swapin,
	rt_swapout,
	rt_nullsys,	/* trapret */
	rt_preempt,
	rt_setrun,
	rt_nullsys,	/* sleep */
	rt_tick,
	rt_wakeup,
	rt_donice,
	rt_globpri,
	rt_nullsys,	/* set_process_group */
	rt_yield,
	rt_doprio,
};

/*
 * Real-time class initialization. Called by dispinit() at boot time.
 * We can ignore the clparmsz argument since we know that the smallest
 * possible parameter buffer is big enough for us.
 */
/* ARGSUSED */
pri_t
rt_init(id_t cid, int clparmsz, classfuncs_t **clfuncspp)
{
	rt_dptbl = rt_getdptbl();
	rt_cid = cid;	/* Record our class ID */

	/*
	 * Initialize the rtproc list.
	 */
	rt_plisthead.rt_next = rt_plisthead.rt_prev = &rt_plisthead;

	/*
	 * We're required to return a pointer to our classfuncs
	 * structure and the highest global priority value we use.
	 */
	*clfuncspp = &rt_classfuncs;
	mutex_init(&rt_dptblock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&rt_list_lock, NULL, MUTEX_DEFAULT, NULL);
	return (rt_dptbl[rt_maxpri].rt_globpri);
}

/*
 * Get or reset the rt_dptbl values per the user's request.
 */
/* ARGSUSED */
static int
rt_admin(caddr_t uaddr, cred_t *reqpcredp)
{
	rtadmin_t	rtadmin;
	rtdpent_t	*tmpdpp;
	size_t		userdpsz;
	size_t		rtdpsz;
	int		i;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(uaddr, &rtadmin, sizeof (rtadmin_t)))
			return (EFAULT);
	}
#ifdef _SYSCALL32_IMPL
	else {
		/* rtadmin struct from ILP32 callers */
		rtadmin32_t rtadmin32;
		if (copyin(uaddr, &rtadmin32, sizeof (rtadmin32_t)))
			return (EFAULT);
		rtadmin.rt_dpents =
		    (struct rtdpent *)(uintptr_t)rtadmin32.rt_dpents;
		rtadmin.rt_ndpents = rtadmin32.rt_ndpents;
		rtadmin.rt_cmd = rtadmin32.rt_cmd;
	}
#endif /* _SYSCALL32_IMPL */

	rtdpsz = (rt_maxpri + 1) * sizeof (rtdpent_t);

	switch (rtadmin.rt_cmd) {

	case RT_GETDPSIZE:
		rtadmin.rt_ndpents = rt_maxpri + 1;

		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&rtadmin, uaddr, sizeof (rtadmin_t)))
				return (EFAULT);
		}
#ifdef _SYSCALL32_IMPL
		else {
			/* return rtadmin struct to ILP32 callers */
			rtadmin32_t rtadmin32;
			rtadmin32.rt_dpents =
			    (caddr32_t)(uintptr_t)rtadmin.rt_dpents;
			rtadmin32.rt_ndpents = rtadmin.rt_ndpents;
			rtadmin32.rt_cmd = rtadmin.rt_cmd;
			if (copyout(&rtadmin32, uaddr, sizeof (rtadmin32_t)))
				return (EFAULT);
		}
#endif /* _SYSCALL32_IMPL */

		break;

	case RT_GETDPTBL:
		userdpsz = MIN(rtadmin.rt_ndpents * sizeof (rtdpent_t),
		    rtdpsz);
		if (copyout(rt_dptbl, rtadmin.rt_dpents, userdpsz))
			return (EFAULT);
		rtadmin.rt_ndpents = userdpsz / sizeof (rtdpent_t);

		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&rtadmin, uaddr, sizeof (rtadmin_t)))
				return (EFAULT);
		}
#ifdef _SYSCALL32_IMPL
		else {
			/* return rtadmin struct to ILP32 callers */
			rtadmin32_t rtadmin32;
			rtadmin32.rt_dpents =
			    (caddr32_t)(uintptr_t)rtadmin.rt_dpents;
			rtadmin32.rt_ndpents = rtadmin.rt_ndpents;
			rtadmin32.rt_cmd = rtadmin.rt_cmd;
			if (copyout(&rtadmin32, uaddr, sizeof (rtadmin32_t)))
				return (EFAULT);
		}
#endif /* _SYSCALL32_IMPL */
		break;

	case RT_SETDPTBL:
		/*
		 * We require that the requesting process has sufficient
		 * priveleges.  We also require that the table supplied by
		 * the user exactly match the current rt_dptbl in size.
		 */
		if (secpolicy_dispadm(reqpcredp) != 0)
			return (EPERM);
		if (rtadmin.rt_ndpents * sizeof (rtdpent_t) != rtdpsz)
			return (EINVAL);

		/*
		 * We read the user supplied table into a temporary buffer
		 * where the time quantum values are validated before
		 * being copied to the rt_dptbl.
		 */
		tmpdpp = kmem_alloc(rtdpsz, KM_SLEEP);
		if (copyin(rtadmin.rt_dpents, tmpdpp, rtdpsz)) {
			kmem_free(tmpdpp, rtdpsz);
			return (EFAULT);
		}
		for (i = 0; i < rtadmin.rt_ndpents; i++) {

			/*
			 * Validate the user supplied time quantum values.
			 */
			if (tmpdpp[i].rt_quantum <= 0 &&
			    tmpdpp[i].rt_quantum != RT_TQINF) {
				kmem_free(tmpdpp, rtdpsz);
				return (EINVAL);
			}
		}

		/*
		 * Copy the user supplied values over the current rt_dptbl
		 * values.  The rt_globpri member is read-only so we don't
		 * overwrite it.
		 */
		mutex_enter(&rt_dptblock);
		for (i = 0; i < rtadmin.rt_ndpents; i++)
			rt_dptbl[i].rt_quantum = tmpdpp[i].rt_quantum;
		mutex_exit(&rt_dptblock);
		kmem_free(tmpdpp, rtdpsz);
		break;

	default:
		return (EINVAL);
	}
	return (0);
}


/*
 * Allocate a real-time class specific proc structure and
 * initialize it with the parameters supplied. Also move thread
 * to specified real-time priority.
 */
/* ARGSUSED */
static int
rt_enterclass(kthread_t *t, id_t cid, void *parmsp, cred_t *reqpcredp,
    void *bufp)
{
	rtkparms_t *rtkparmsp = (rtkparms_t *)parmsp;
	rtproc_t *rtpp;

	/*
	 * For a thread to enter the real-time class the thread
	 * which initiates the request must be privileged.
	 * This may have been checked previously but if our
	 * caller passed us a credential structure we assume it
	 * hasn't and we check it here.
	 */
	if (reqpcredp != NULL && secpolicy_setpriority(reqpcredp) != 0)
		return (EPERM);

	rtpp = (rtproc_t *)bufp;
	ASSERT(rtpp != NULL);

	/*
	 * If this thread's lwp is swapped out, it will be brought in
	 * when it is put onto the runqueue.
	 *
	 * Now, Initialize the rtproc structure.
	 */
	if (rtkparmsp == NULL) {
		/*
		 * Use default values
		 */
		rtpp->rt_pri = 0;
		rtpp->rt_pquantum = rt_dptbl[0].rt_quantum;
		rtpp->rt_tqsignal = 0;
	} else {
		/*
		 * Use supplied values
		 */
		if ((rtkparmsp->rt_cflags & RT_DOPRI) == 0)
			rtpp->rt_pri = 0;
		else
			rtpp->rt_pri = rtkparmsp->rt_pri;

		if (rtkparmsp->rt_tqntm == RT_TQINF)
			rtpp->rt_pquantum = RT_TQINF;
		else if (rtkparmsp->rt_tqntm == RT_TQDEF ||
		    (rtkparmsp->rt_cflags & RT_DOTQ) == 0)
			rtpp->rt_pquantum = rt_dptbl[rtpp->rt_pri].rt_quantum;
		else
			rtpp->rt_pquantum = rtkparmsp->rt_tqntm;

		if ((rtkparmsp->rt_cflags & RT_DOSIG) == 0)
			rtpp->rt_tqsignal = 0;
		else
			rtpp->rt_tqsignal = rtkparmsp->rt_tqsig;
	}
	rtpp->rt_flags = 0;
	rtpp->rt_tp = t;
	/*
	 * Reset thread priority
	 */
	thread_lock(t);
	t->t_clfuncs = &(sclass[cid].cl_funcs->thread);
	t->t_cid = cid;
	t->t_cldata = (void *)rtpp;
	t->t_schedflag &= ~TS_RUNQMATCH;
	rt_change_priority(t, rtpp);
	thread_unlock(t);
	/*
	 * Link new structure into rtproc list
	 */
	mutex_enter(&rt_list_lock);
	rtpp->rt_next = rt_plisthead.rt_next;
	rtpp->rt_prev = &rt_plisthead;
	rt_plisthead.rt_next->rt_prev = rtpp;
	rt_plisthead.rt_next = rtpp;
	mutex_exit(&rt_list_lock);
	return (0);
}


/*
 * Free rtproc structure of thread.
 */
static void
rt_exitclass(void *procp)
{
	rtproc_t *rtprocp = (rtproc_t *)procp;

	mutex_enter(&rt_list_lock);
	rtprocp->rt_prev->rt_next = rtprocp->rt_next;
	rtprocp->rt_next->rt_prev = rtprocp->rt_prev;
	mutex_exit(&rt_list_lock);
	kmem_free(rtprocp, sizeof (rtproc_t));
}


/*
 * Allocate and initialize real-time class specific
 * proc structure for child.
 */
/* ARGSUSED */
static int
rt_fork(kthread_t *t, kthread_t *ct, void *bufp)
{
	rtproc_t *prtpp;
	rtproc_t *crtpp;

	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	/*
	 * Initialize child's rtproc structure
	 */
	crtpp = (rtproc_t *)bufp;
	ASSERT(crtpp != NULL);
	prtpp = (rtproc_t *)t->t_cldata;
	thread_lock(t);
	crtpp->rt_timeleft = crtpp->rt_pquantum = prtpp->rt_pquantum;
	crtpp->rt_pri = prtpp->rt_pri;
	crtpp->rt_flags = prtpp->rt_flags & ~RTBACKQ;
	crtpp->rt_tqsignal = prtpp->rt_tqsignal;

	crtpp->rt_tp = ct;
	thread_unlock(t);

	/*
	 * Link new structure into rtproc list
	 */
	ct->t_cldata = (void *)crtpp;
	mutex_enter(&rt_list_lock);
	crtpp->rt_next = rt_plisthead.rt_next;
	crtpp->rt_prev = &rt_plisthead;
	rt_plisthead.rt_next->rt_prev = crtpp;
	rt_plisthead.rt_next = crtpp;
	mutex_exit(&rt_list_lock);
	return (0);
}


/*
 * The child goes to the back of its dispatcher queue while the
 * parent continues to run after a real time thread forks.
 */
/* ARGSUSED */
static void
rt_forkret(kthread_t *t, kthread_t *ct)
{
	proc_t *pp = ttoproc(t);
	proc_t *cp = ttoproc(ct);

	ASSERT(t == curthread);
	ASSERT(MUTEX_HELD(&pidlock));

	/*
	 * Grab the child's p_lock before dropping pidlock to ensure
	 * the process does not disappear before we set it running.
	 */
	mutex_enter(&cp->p_lock);
	mutex_exit(&pidlock);
	continuelwps(cp);
	mutex_exit(&cp->p_lock);

	mutex_enter(&pp->p_lock);
	continuelwps(pp);
	mutex_exit(&pp->p_lock);
}


/*
 * Get information about the real-time class into the buffer
 * pointed to by rtinfop.  The maximum configured real-time
 * priority is the only information we supply.  We ignore the
 * class and credential arguments because anyone can have this
 * information.
 */
/* ARGSUSED */
static int
rt_getclinfo(void *infop)
{
	rtinfo_t *rtinfop = (rtinfo_t *)infop;
	rtinfop->rt_maxpri = rt_maxpri;
	return (0);
}

/*
 * Return the user mode scheduling priority range.
 */
static int
rt_getclpri(pcpri_t *pcprip)
{
	pcprip->pc_clpmax = rt_maxpri;
	pcprip->pc_clpmin = 0;
	return (0);
}

static void
rt_nullsys()
{
}

/* ARGSUSED */
static int
rt_canexit(kthread_t *t, cred_t *cred)
{
	/*
	 * Thread can always leave RT class
	 */
	return (0);
}

/*
 * Get the real-time scheduling parameters of the thread pointed to by
 * rtprocp into the buffer pointed to by rtkparmsp.
 */
static void
rt_parmsget(kthread_t *t, void *parmsp)
{
	rtproc_t	*rtprocp = (rtproc_t *)t->t_cldata;
	rtkparms_t	*rtkparmsp = (rtkparms_t *)parmsp;

	rtkparmsp->rt_pri = rtprocp->rt_pri;
	rtkparmsp->rt_tqntm = rtprocp->rt_pquantum;
	rtkparmsp->rt_tqsig = rtprocp->rt_tqsignal;
}



/*
 * Check the validity of the real-time parameters in the buffer
 * pointed to by rtprmsp.
 * We convert the rtparms buffer from the user supplied format to
 * our internal format (i.e. time quantum expressed in ticks).
 */
static int
rt_parmsin(void *prmsp)
{
	rtparms_t *rtprmsp = (rtparms_t *)prmsp;
	longlong_t	ticks;
	uint_t		cflags;

	/*
	 * First check the validity of parameters and convert
	 * the buffer to kernel format.
	 */
	if ((rtprmsp->rt_pri < 0 || rtprmsp->rt_pri > rt_maxpri) &&
	    rtprmsp->rt_pri != RT_NOCHANGE)
		return (EINVAL);

	cflags = (rtprmsp->rt_pri != RT_NOCHANGE ? RT_DOPRI : 0);

	if ((rtprmsp->rt_tqsecs == 0 && rtprmsp->rt_tqnsecs == 0) ||
	    rtprmsp->rt_tqnsecs >= NANOSEC)
		return (EINVAL);

	if (rtprmsp->rt_tqnsecs != RT_NOCHANGE)
		cflags |= RT_DOTQ;

	if (rtprmsp->rt_tqnsecs >= 0) {
		if ((ticks = SEC_TO_TICK((longlong_t)rtprmsp->rt_tqsecs) +
		    NSEC_TO_TICK_ROUNDUP(rtprmsp->rt_tqnsecs)) > INT_MAX)
			return (ERANGE);

		((rtkparms_t *)rtprmsp)->rt_tqntm = (int)ticks;
	} else {
		if (rtprmsp->rt_tqnsecs != RT_NOCHANGE &&
		    rtprmsp->rt_tqnsecs != RT_TQINF &&
		    rtprmsp->rt_tqnsecs != RT_TQDEF)
			return (EINVAL);

		((rtkparms_t *)rtprmsp)->rt_tqntm = rtprmsp->rt_tqnsecs;
	}
	((rtkparms_t *)rtprmsp)->rt_cflags = cflags;

	return (0);
}


/*
 * Check the validity of the real-time parameters in the pc_vaparms_t
 * structure vaparmsp and put them in the buffer pointed to by rtprmsp.
 * pc_vaparms_t contains (key, value) pairs of parameter.
 * rt_vaparmsin() is the variable parameter version of rt_parmsin().
 */
static int
rt_vaparmsin(void *prmsp, pc_vaparms_t *vaparmsp)
{
	uint_t		secs = 0;
	uint_t		cnt;
	int		nsecs = 0;
	int		priflag, secflag, nsecflag, sigflag;
	longlong_t	ticks;
	rtkparms_t	*rtprmsp = (rtkparms_t *)prmsp;
	pc_vaparm_t	*vpp = &vaparmsp->pc_parms[0];


	/*
	 * First check the validity of parameters and convert them
	 * from the user supplied format to the internal format.
	 */
	priflag = secflag = nsecflag = sigflag = 0;
	rtprmsp->rt_cflags = 0;

	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {

		switch (vpp->pc_key) {
		case RT_KY_PRI:
			if (priflag++)
				return (EINVAL);
			rtprmsp->rt_cflags |= RT_DOPRI;
			rtprmsp->rt_pri = (pri_t)vpp->pc_parm;
			if (rtprmsp->rt_pri < 0 || rtprmsp->rt_pri > rt_maxpri)
				return (EINVAL);
			break;

		case RT_KY_TQSECS:
			if (secflag++)
				return (EINVAL);
			rtprmsp->rt_cflags |= RT_DOTQ;
			secs = (uint_t)vpp->pc_parm;
			break;

		case RT_KY_TQNSECS:
			if (nsecflag++)
				return (EINVAL);
			rtprmsp->rt_cflags |= RT_DOTQ;
			nsecs = (int)vpp->pc_parm;
			break;

		case RT_KY_TQSIG:
			if (sigflag++)
				return (EINVAL);
			rtprmsp->rt_cflags |= RT_DOSIG;
			rtprmsp->rt_tqsig = (int)vpp->pc_parm;
			if (rtprmsp->rt_tqsig < 0 || rtprmsp->rt_tqsig >= NSIG)
				return (EINVAL);
			break;

		default:
			return (EINVAL);
		}
	}

	if (vaparmsp->pc_vaparmscnt == 0) {
		/*
		 * Use default parameters.
		 */
		rtprmsp->rt_pri = 0;
		rtprmsp->rt_tqntm = RT_TQDEF;
		rtprmsp->rt_tqsig = 0;
		rtprmsp->rt_cflags = RT_DOPRI | RT_DOTQ | RT_DOSIG;
	} else if ((rtprmsp->rt_cflags & RT_DOTQ) != 0) {
		if ((secs == 0 && nsecs == 0) || nsecs >= NANOSEC)
			return (EINVAL);

		if (nsecs >= 0) {
			if ((ticks = SEC_TO_TICK((longlong_t)secs) +
			    NSEC_TO_TICK_ROUNDUP(nsecs)) > INT_MAX)
				return (ERANGE);

			rtprmsp->rt_tqntm = (int)ticks;
		} else {
			if (nsecs != RT_TQINF && nsecs != RT_TQDEF)
				return (EINVAL);
			rtprmsp->rt_tqntm = nsecs;
		}
	}

	return (0);
}

/*
 * Do required processing on the real-time parameter buffer
 * before it is copied out to the user.
 * All we have to do is convert the buffer from kernel to user format
 * (i.e. convert time quantum from ticks to seconds-nanoseconds).
 */
/* ARGSUSED */
static int
rt_parmsout(void *prmsp, pc_vaparms_t *vaparmsp)
{
	rtkparms_t	*rtkprmsp = (rtkparms_t *)prmsp;

	if (vaparmsp != NULL)
		return (0);

	if (rtkprmsp->rt_tqntm < 0) {
		/*
		 * Quantum field set to special value (e.g. RT_TQINF)
		 */
		((rtparms_t *)rtkprmsp)->rt_tqnsecs = rtkprmsp->rt_tqntm;
		((rtparms_t *)rtkprmsp)->rt_tqsecs = 0;
	} else {
		/* Convert quantum from ticks to seconds-nanoseconds */

		timestruc_t ts;
		TICK_TO_TIMESTRUC(rtkprmsp->rt_tqntm, &ts);
		((rtparms_t *)rtkprmsp)->rt_tqsecs = ts.tv_sec;
		((rtparms_t *)rtkprmsp)->rt_tqnsecs = ts.tv_nsec;
	}

	return (0);
}


/*
 * Copy all selected real-time class parameters to the user.
 * The parameters are specified by a key.
 */
static int
rt_vaparmsout(void *prmsp, pc_vaparms_t *vaparmsp)
{
	rtkparms_t	*rtkprmsp = (rtkparms_t *)prmsp;
	timestruc_t	ts;
	uint_t		cnt;
	uint_t		secs;
	int		nsecs;
	int		priflag, secflag, nsecflag, sigflag;
	pc_vaparm_t	*vpp = &vaparmsp->pc_parms[0];

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	priflag = secflag = nsecflag = sigflag = 0;

	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	if (rtkprmsp->rt_tqntm < 0) {
		/*
		 * Quantum field set to special value (e.g. RT_TQINF).
		 */
		secs = 0;
		nsecs = rtkprmsp->rt_tqntm;
	} else {
		/*
		 * Convert quantum from ticks to seconds-nanoseconds.
		 */
		TICK_TO_TIMESTRUC(rtkprmsp->rt_tqntm, &ts);
		secs = ts.tv_sec;
		nsecs = ts.tv_nsec;
	}


	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {

		switch (vpp->pc_key) {
		case RT_KY_PRI:
			if (priflag++)
				return (EINVAL);
			if (copyout(&rtkprmsp->rt_pri,
			    (caddr_t)(uintptr_t)vpp->pc_parm, sizeof (pri_t)))
				return (EFAULT);
			break;

		case RT_KY_TQSECS:
			if (secflag++)
				return (EINVAL);
			if (copyout(&secs, (caddr_t)(uintptr_t)vpp->pc_parm,
			    sizeof (uint_t)))
				return (EFAULT);
			break;

		case RT_KY_TQNSECS:
			if (nsecflag++)
				return (EINVAL);
			if (copyout(&nsecs, (caddr_t)(uintptr_t)vpp->pc_parm,
			    sizeof (int)))
				return (EFAULT);
			break;

		case RT_KY_TQSIG:
			if (sigflag++)
				return (EINVAL);
			if (copyout(&rtkprmsp->rt_tqsig,
			    (caddr_t)(uintptr_t)vpp->pc_parm, sizeof (int)))
				return (EFAULT);
			break;

		default:
			return (EINVAL);
		}
	}

	return (0);
}


/*
 * Set the scheduling parameters of the thread pointed to by rtprocp
 * to those specified in the buffer pointed to by rtkprmsp.
 * Note that the parameters are expected to be in kernel format
 * (i.e. time quantm expressed in ticks).  Real time parameters copied
 * in from the user should be processed by rt_parmsin() before they are
 * passed to this function.
 */
static int
rt_parmsset(kthread_t *tx, void *prmsp, id_t reqpcid, cred_t *reqpcredp)
{
	rtkparms_t *rtkprmsp = (rtkparms_t *)prmsp;
	rtproc_t *rtpp = (rtproc_t *)tx->t_cldata;

	ASSERT(MUTEX_HELD(&(ttoproc(tx))->p_lock));

	/*
	 * Basic permissions enforced by generic kernel code
	 * for all classes require that a thread attempting
	 * to change the scheduling parameters of a target thread
	 * be privileged or have a real or effective UID
	 * matching that of the target thread. We are not
	 * called unless these basic permission checks have
	 * already passed. The real-time class requires in addition
	 * that the requesting thread be real-time unless it is privileged.
	 * This may also have been checked previously but if our caller
	 * passes us a credential structure we assume it hasn't and
	 * we check it here.
	 */
	if (reqpcredp != NULL && reqpcid != rt_cid &&
	    secpolicy_raisepriority(reqpcredp) != 0)
		return (EPERM);

	thread_lock(tx);
	if ((rtkprmsp->rt_cflags & RT_DOPRI) != 0) {
		rtpp->rt_pri = rtkprmsp->rt_pri;
		rt_change_priority(tx, rtpp);
	}
	if (rtkprmsp->rt_tqntm == RT_TQINF)
		rtpp->rt_pquantum = RT_TQINF;
	else if (rtkprmsp->rt_tqntm == RT_TQDEF)
		rtpp->rt_timeleft = rtpp->rt_pquantum =
		    rt_dptbl[rtpp->rt_pri].rt_quantum;
	else if ((rtkprmsp->rt_cflags & RT_DOTQ) != 0)
		rtpp->rt_timeleft = rtpp->rt_pquantum = rtkprmsp->rt_tqntm;

	if ((rtkprmsp->rt_cflags & RT_DOSIG) != 0)
		rtpp->rt_tqsignal = rtkprmsp->rt_tqsig;

	thread_unlock(tx);
	return (0);
}


/*
 * Arrange for thread to be placed in appropriate location
 * on dispatcher queue.  Runs at splhi() since the clock
 * interrupt can cause RTBACKQ to be set.
 */
static void
rt_preempt(kthread_t *t)
{
	rtproc_t *rtpp = (rtproc_t *)(t->t_cldata);
	klwp_t *lwp;

	ASSERT(THREAD_LOCK_HELD(t));

	/*
	 * If the state is user I allow swapping because I know I won't
	 * be holding any locks.
	 */
	if ((lwp = curthread->t_lwp) != NULL && lwp->lwp_state == LWP_USER)
		t->t_schedflag &= ~TS_DONT_SWAP;
	if ((rtpp->rt_flags & RTBACKQ) != 0) {
		rtpp->rt_timeleft = rtpp->rt_pquantum;
		rtpp->rt_flags &= ~RTBACKQ;
		setbackdq(t);
	} else
		setfrontdq(t);

}

/*
 * Return the global priority associated with this rt_pri.
 */
static pri_t
rt_globpri(kthread_t *t)
{
	rtproc_t *rtprocp = (rtproc_t *)t->t_cldata;
	return (rt_dptbl[rtprocp->rt_pri].rt_globpri);
}

static void
rt_setrun(kthread_t *t)
{
	rtproc_t *rtpp = (rtproc_t *)(t->t_cldata);

	ASSERT(THREAD_LOCK_HELD(t));

	rtpp->rt_timeleft = rtpp->rt_pquantum;
	rtpp->rt_flags &= ~RTBACKQ;
	setbackdq(t);
}

/*
 * Returns the priority of the thread, -1 if the thread is loaded or ineligible
 * for swapin.
 *
 * FX and RT threads are designed so that they don't swapout; however, it
 * is possible that while the thread is swapped out and in another class, it
 * can be changed to FX or RT.  Since these threads should be swapped in as
 * soon as they're runnable, rt_swapin returns SHRT_MAX, and fx_swapin
 * returns SHRT_MAX - 1, so that it gives deference to any swapped out RT
 * threads.
 */
/* ARGSUSED */
static pri_t
rt_swapin(kthread_t *t, int flags)
{
	pri_t	tpri = -1;

	ASSERT(THREAD_LOCK_HELD(t));

	if (t->t_state == TS_RUN && (t->t_schedflag & TS_LOAD) == 0) {
		tpri = (pri_t)SHRT_MAX;
	}

	return (tpri);
}

/*
 * Return an effective priority for swapout.
 */
/* ARGSUSED */
static pri_t
rt_swapout(kthread_t *t, int flags)
{
	ASSERT(THREAD_LOCK_HELD(t));

	return (-1);
}

/*
 * Check for time slice expiration (unless thread has infinite time
 * slice).  If time slice has expired arrange for thread to be preempted
 * and placed on back of queue.
 */
static void
rt_tick(kthread_t *t)
{
	rtproc_t *rtpp = (rtproc_t *)(t->t_cldata);

	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock));

	thread_lock(t);
	if ((rtpp->rt_pquantum != RT_TQINF && --rtpp->rt_timeleft == 0) ||
	    (t->t_state == TS_ONPROC && DISP_MUST_SURRENDER(t))) {
		if (rtpp->rt_timeleft == 0 && rtpp->rt_tqsignal) {
			thread_unlock(t);
			sigtoproc(ttoproc(t), t, rtpp->rt_tqsignal);
			thread_lock(t);
		}
		rtpp->rt_flags |= RTBACKQ;
		cpu_surrender(t);
	}
	thread_unlock(t);
}


/*
 * Place the thread waking up on the dispatcher queue.
 */
static void
rt_wakeup(kthread_t *t)
{
	rtproc_t *rtpp = (rtproc_t *)(t->t_cldata);

	ASSERT(THREAD_LOCK_HELD(t));

	rtpp->rt_timeleft = rtpp->rt_pquantum;
	rtpp->rt_flags &= ~RTBACKQ;
	setbackdq(t);
}

static void
rt_yield(kthread_t *t)
{
	rtproc_t *rtpp = (rtproc_t *)(t->t_cldata);

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(t));

	rtpp->rt_flags &= ~RTBACKQ;
	setbackdq(t);
}

/* ARGSUSED */
static int
rt_donice(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	return (EINVAL);
}

/*
 * Increment the priority of the specified thread by incr and
 * return the new value in *retvalp.
 */
static int
rt_doprio(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	int newpri;
	rtproc_t *rtpp = (rtproc_t *)(t->t_cldata);
	rtkparms_t rtkparms;

	/* If there's no change to the priority, just return current setting */
	if (incr == 0) {
		*retvalp = rtpp->rt_pri;
		return (0);
	}

	newpri = rtpp->rt_pri + incr;
	if (newpri > rt_maxpri || newpri < 0)
		return (EINVAL);

	*retvalp = newpri;
	rtkparms.rt_pri = newpri;
	rtkparms.rt_tqntm = RT_NOCHANGE;
	rtkparms.rt_tqsig = 0;
	rtkparms.rt_cflags = RT_DOPRI;
	return (rt_parmsset(t, &rtkparms, rt_cid, cr));
}

static int
rt_alloc(void **p, int flag)
{
	void *bufp;
	bufp = kmem_alloc(sizeof (rtproc_t), flag);
	if (bufp == NULL) {
		return (ENOMEM);
	} else {
		*p = bufp;
		return (0);
	}
}

static void
rt_free(void *bufp)
{
	if (bufp)
		kmem_free(bufp, sizeof (rtproc_t));
}

static void
rt_change_priority(kthread_t *t, rtproc_t *rtpp)
{
	pri_t new_pri;

	ASSERT(THREAD_LOCK_HELD(t));

	new_pri = rt_dptbl[rtpp->rt_pri].rt_globpri;

	t->t_cpri = rtpp->rt_pri;
	if (t == curthread || t->t_state == TS_ONPROC) {
		cpu_t	*cp = t->t_disp_queue->disp_cpu;
		THREAD_CHANGE_PRI(t, new_pri);
		if (t == cp->cpu_dispthread)
			cp->cpu_dispatch_pri = DISP_PRIO(t);
		if (DISP_MUST_SURRENDER(t)) {
			rtpp->rt_flags |= RTBACKQ;
			cpu_surrender(t);
		} else {
			rtpp->rt_timeleft = rtpp->rt_pquantum;
		}
	} else {
		/*
		 * When the priority of a thread is changed,
		 * it may be necessary to adjust its position
		 * on a sleep queue or dispatch queue.  The
		 * function thread_change_pri() accomplishes this.
		 */
		if (thread_change_pri(t, new_pri, 0)) {
			/*
			 * The thread was on a run queue.
			 * Reset its CPU timeleft.
			 */
			rtpp->rt_timeleft = rtpp->rt_pquantum;
		} else {
			rtpp->rt_flags |= RTBACKQ;
		}
	}
}
