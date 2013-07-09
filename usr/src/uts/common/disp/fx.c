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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/session.h>
#include <sys/strsubr.h>
#include <sys/user.h>
#include <sys/priocntl.h>
#include <sys/class.h>
#include <sys/disp.h>
#include <sys/procset.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/fx.h>
#include <sys/fxpriocntl.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/vtrace.h>
#include <sys/schedctl.h>
#include <sys/tnf_probe.h>
#include <sys/sunddi.h>
#include <sys/spl.h>
#include <sys/modctl.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/cpupart.h>
#include <sys/cpucaps.h>

static pri_t fx_init(id_t, int, classfuncs_t **);

static struct sclass csw = {
	"FX",
	fx_init,
	0
};

static struct modlsched modlsched = {
	&mod_schedops, "Fixed priority sched class", &csw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlsched, NULL
};


/*
 * control flags (kparms->fx_cflags).
 */
#define	FX_DOUPRILIM	0x01    /* change user priority limit */
#define	FX_DOUPRI	0x02    /* change user priority */
#define	FX_DOTQ		0x04    /* change FX time quantum */


#define	FXMAXUPRI 60		/* maximum user priority setting */

#define	FX_MAX_UNPRIV_PRI	0	/* maximum unpriviledge priority */

/*
 * The fxproc_t structures that have a registered callback vector,
 * are also kept in an array of circular doubly linked lists. A hash on
 * the thread id (from ddi_get_kt_did()) is used to determine which list
 * each of such fxproc structures should be placed. Each list has a dummy
 * "head" which is never removed, so the list is never empty.
 */

#define	FX_CB_LISTS 16		/* number of lists, must be power of 2 */
#define	FX_CB_LIST_HASH(ktid)	((uint_t)ktid & (FX_CB_LISTS - 1))

/* Insert fxproc into callback list */
#define	FX_CB_LIST_INSERT(fxpp)						\
{									\
	int index = FX_CB_LIST_HASH(fxpp->fx_ktid);			\
	kmutex_t *lockp = &fx_cb_list_lock[index];			\
	fxproc_t *headp = &fx_cb_plisthead[index];			\
	mutex_enter(lockp);						\
	fxpp->fx_cb_next = headp->fx_cb_next;				\
	fxpp->fx_cb_prev = headp;					\
	headp->fx_cb_next->fx_cb_prev = fxpp;				\
	headp->fx_cb_next = fxpp;					\
	mutex_exit(lockp);						\
}

/*
 * Remove thread from callback list.
 */
#define	FX_CB_LIST_DELETE(fxpp)						\
{									\
	int index = FX_CB_LIST_HASH(fxpp->fx_ktid);			\
	kmutex_t *lockp = &fx_cb_list_lock[index];			\
	mutex_enter(lockp);						\
	fxpp->fx_cb_prev->fx_cb_next = fxpp->fx_cb_next;		\
	fxpp->fx_cb_next->fx_cb_prev = fxpp->fx_cb_prev;		\
	mutex_exit(lockp);						\
}

#define	FX_HAS_CB(fxpp)	(fxpp->fx_callback != NULL)

/* adjust x to be between 0 and fx_maxumdpri */

#define	FX_ADJUST_PRI(pri)						\
{									\
	if (pri < 0)							\
		pri = 0;  						\
	else if (pri > fx_maxumdpri) 					\
		pri = fx_maxumdpri;  					\
}

#define	FX_ADJUST_QUANTUM(q)						\
{									\
	if (q > INT_MAX)						\
		q = INT_MAX;						\
	else if (q <= 0)						\
		q = FX_TQINF;						\
}

#define	FX_ISVALID(pri, quantum) \
	(((pri >= 0) || (pri == FX_CB_NOCHANGE)) &&			\
	    ((quantum >= 0) || (quantum == FX_NOCHANGE) ||		\
		(quantum == FX_TQDEF) || (quantum == FX_TQINF)))


static id_t	fx_cid;		/* fixed priority class ID */
static fxdpent_t *fx_dptbl;	/* fixed priority disp parameter table */

static pri_t	fx_maxupri = FXMAXUPRI;
static pri_t	fx_maxumdpri;	/* max user mode fixed priority */

static pri_t	fx_maxglobpri;	/* maximum global priority used by fx class */
static kmutex_t	fx_dptblock;	/* protects fixed priority dispatch table */


static kmutex_t	fx_cb_list_lock[FX_CB_LISTS];	/* protects list of fxprocs */
						/* that have callbacks */
static fxproc_t	fx_cb_plisthead[FX_CB_LISTS];	/* dummy fxproc at head of */
						/* list of fxprocs with */
						/* callbacks */

static int	fx_admin(caddr_t, cred_t *);
static int	fx_getclinfo(void *);
static int	fx_parmsin(void *);
static int	fx_parmsout(void *, pc_vaparms_t *);
static int	fx_vaparmsin(void *, pc_vaparms_t *);
static int	fx_vaparmsout(void *, pc_vaparms_t *);
static int	fx_getclpri(pcpri_t *);
static int	fx_alloc(void **, int);
static void	fx_free(void *);
static int	fx_enterclass(kthread_t *, id_t, void *, cred_t *, void *);
static void	fx_exitclass(void *);
static int	fx_canexit(kthread_t *, cred_t *);
static int	fx_fork(kthread_t *, kthread_t *, void *);
static void	fx_forkret(kthread_t *, kthread_t *);
static void	fx_parmsget(kthread_t *, void *);
static int	fx_parmsset(kthread_t *, void *, id_t, cred_t *);
static void	fx_stop(kthread_t *, int, int);
static void	fx_exit(kthread_t *);
static pri_t	fx_swapin(kthread_t *, int);
static pri_t	fx_swapout(kthread_t *, int);
static void	fx_trapret(kthread_t *);
static void	fx_preempt(kthread_t *);
static void	fx_setrun(kthread_t *);
static void	fx_sleep(kthread_t *);
static void	fx_tick(kthread_t *);
static void	fx_wakeup(kthread_t *);
static int	fx_donice(kthread_t *, cred_t *, int, int *);
static int	fx_doprio(kthread_t *, cred_t *, int, int *);
static pri_t	fx_globpri(kthread_t *);
static void	fx_yield(kthread_t *);
static void	fx_nullsys();

extern fxdpent_t *fx_getdptbl(void);

static void	fx_change_priority(kthread_t *, fxproc_t *);
static fxproc_t *fx_list_lookup(kt_did_t);
static void fx_list_release(fxproc_t *);


static struct classfuncs fx_classfuncs = {
	/* class functions */
	fx_admin,
	fx_getclinfo,
	fx_parmsin,
	fx_parmsout,
	fx_vaparmsin,
	fx_vaparmsout,
	fx_getclpri,
	fx_alloc,
	fx_free,

	/* thread functions */
	fx_enterclass,
	fx_exitclass,
	fx_canexit,
	fx_fork,
	fx_forkret,
	fx_parmsget,
	fx_parmsset,
	fx_stop,
	fx_exit,
	fx_nullsys,	/* active */
	fx_nullsys,	/* inactive */
	fx_swapin,
	fx_swapout,
	fx_trapret,
	fx_preempt,
	fx_setrun,
	fx_sleep,
	fx_tick,
	fx_wakeup,
	fx_donice,
	fx_globpri,
	fx_nullsys,	/* set_process_group */
	fx_yield,
	fx_doprio,
};


int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Fixed priority class initialization. Called by dispinit() at boot time.
 * We can ignore the clparmsz argument since we know that the smallest
 * possible parameter buffer is big enough for us.
 */
/* ARGSUSED */
static pri_t
fx_init(id_t cid, int clparmsz, classfuncs_t **clfuncspp)
{
	int i;
	extern pri_t fx_getmaxumdpri(void);

	fx_dptbl = fx_getdptbl();
	fx_maxumdpri = fx_getmaxumdpri();
	fx_maxglobpri = fx_dptbl[fx_maxumdpri].fx_globpri;

	fx_cid = cid;		/* Record our class ID */

	/*
	 * Initialize the hash table for fxprocs with callbacks
	 */
	for (i = 0; i < FX_CB_LISTS; i++) {
		fx_cb_plisthead[i].fx_cb_next = fx_cb_plisthead[i].fx_cb_prev =
		    &fx_cb_plisthead[i];
	}

	/*
	 * We're required to return a pointer to our classfuncs
	 * structure and the highest global priority value we use.
	 */
	*clfuncspp = &fx_classfuncs;
	return (fx_maxglobpri);
}

/*
 * Get or reset the fx_dptbl values per the user's request.
 */
static int
fx_admin(caddr_t uaddr, cred_t *reqpcredp)
{
	fxadmin_t	fxadmin;
	fxdpent_t	*tmpdpp;
	int		userdpsz;
	int		i;
	size_t		fxdpsz;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(uaddr, &fxadmin, sizeof (fxadmin_t)))
			return (EFAULT);
	}
#ifdef _SYSCALL32_IMPL
	else {
		/* get fxadmin struct from ILP32 caller */
		fxadmin32_t fxadmin32;
		if (copyin(uaddr, &fxadmin32, sizeof (fxadmin32_t)))
			return (EFAULT);
		fxadmin.fx_dpents =
		    (struct fxdpent *)(uintptr_t)fxadmin32.fx_dpents;
		fxadmin.fx_ndpents = fxadmin32.fx_ndpents;
		fxadmin.fx_cmd = fxadmin32.fx_cmd;
	}
#endif /* _SYSCALL32_IMPL */

	fxdpsz = (fx_maxumdpri + 1) * sizeof (fxdpent_t);

	switch (fxadmin.fx_cmd) {
	case FX_GETDPSIZE:
		fxadmin.fx_ndpents = fx_maxumdpri + 1;

		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&fxadmin, uaddr, sizeof (fxadmin_t)))
				return (EFAULT);
		}
#ifdef _SYSCALL32_IMPL
		else {
			/* return fxadmin struct to ILP32 caller */
			fxadmin32_t fxadmin32;
			fxadmin32.fx_dpents =
			    (caddr32_t)(uintptr_t)fxadmin.fx_dpents;
			fxadmin32.fx_ndpents = fxadmin.fx_ndpents;
			fxadmin32.fx_cmd = fxadmin.fx_cmd;
			if (copyout(&fxadmin32, uaddr, sizeof (fxadmin32_t)))
				return (EFAULT);
		}
#endif /* _SYSCALL32_IMPL */
		break;

	case FX_GETDPTBL:
		userdpsz = MIN(fxadmin.fx_ndpents * sizeof (fxdpent_t),
		    fxdpsz);
		if (copyout(fx_dptbl, fxadmin.fx_dpents, userdpsz))
			return (EFAULT);

		fxadmin.fx_ndpents = userdpsz / sizeof (fxdpent_t);

		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&fxadmin, uaddr, sizeof (fxadmin_t)))
				return (EFAULT);
		}
#ifdef _SYSCALL32_IMPL
		else {
			/* return fxadmin struct to ILP32 callers */
			fxadmin32_t fxadmin32;
			fxadmin32.fx_dpents =
			    (caddr32_t)(uintptr_t)fxadmin.fx_dpents;
			fxadmin32.fx_ndpents = fxadmin.fx_ndpents;
			fxadmin32.fx_cmd = fxadmin.fx_cmd;
			if (copyout(&fxadmin32, uaddr, sizeof (fxadmin32_t)))
				return (EFAULT);
		}
#endif /* _SYSCALL32_IMPL */
		break;

	case FX_SETDPTBL:
		/*
		 * We require that the requesting process has sufficient
		 * privileges. We also require that the table supplied by
		 * the user exactly match the current fx_dptbl in size.
		 */
		if (secpolicy_dispadm(reqpcredp) != 0) {
			return (EPERM);
		}
		if (fxadmin.fx_ndpents * sizeof (fxdpent_t) != fxdpsz) {
			return (EINVAL);
		}

		/*
		 * We read the user supplied table into a temporary buffer
		 * where it is validated before being copied over the
		 * fx_dptbl.
		 */
		tmpdpp = kmem_alloc(fxdpsz, KM_SLEEP);
		if (copyin(fxadmin.fx_dpents, tmpdpp, fxdpsz)) {
			kmem_free(tmpdpp, fxdpsz);
			return (EFAULT);
		}
		for (i = 0; i < fxadmin.fx_ndpents; i++) {

			/*
			 * Validate the user supplied values. All we are doing
			 * here is verifying that the values are within their
			 * allowable ranges and will not panic the system. We
			 * make no attempt to ensure that the resulting
			 * configuration makes sense or results in reasonable
			 * performance.
			 */
			if (tmpdpp[i].fx_quantum <= 0 &&
			    tmpdpp[i].fx_quantum != FX_TQINF) {
				kmem_free(tmpdpp, fxdpsz);
				return (EINVAL);
			}
		}

		/*
		 * Copy the user supplied values over the current fx_dptbl
		 * values. The fx_globpri member is read-only so we don't
		 * overwrite it.
		 */
		mutex_enter(&fx_dptblock);
		for (i = 0; i < fxadmin.fx_ndpents; i++) {
			fx_dptbl[i].fx_quantum = tmpdpp[i].fx_quantum;
		}
		mutex_exit(&fx_dptblock);
		kmem_free(tmpdpp, fxdpsz);
		break;

	default:
		return (EINVAL);
	}
	return (0);
}

/*
 * Allocate a fixed priority class specific thread structure and
 * initialize it with the parameters supplied. Also move the thread
 * to specified priority.
 */
static int
fx_enterclass(kthread_t *t, id_t cid, void *parmsp, cred_t *reqpcredp,
    void *bufp)
{
	fxkparms_t	*fxkparmsp = (fxkparms_t *)parmsp;
	fxproc_t	*fxpp;
	pri_t		reqfxupri;
	pri_t		reqfxuprilim;

	fxpp = (fxproc_t *)bufp;
	ASSERT(fxpp != NULL);

	/*
	 * Initialize the fxproc structure.
	 */
	fxpp->fx_flags = 0;
	fxpp->fx_callback = NULL;
	fxpp->fx_cookie = NULL;

	if (fxkparmsp == NULL) {
		/*
		 * Use default values.
		 */
		fxpp->fx_pri = fxpp->fx_uprilim = 0;
		fxpp->fx_pquantum = fx_dptbl[fxpp->fx_pri].fx_quantum;
		fxpp->fx_nice =  NZERO;
	} else {
		/*
		 * Use supplied values.
		 */

		if ((fxkparmsp->fx_cflags & FX_DOUPRILIM) == 0) {
			reqfxuprilim = 0;
		} else {
			if (fxkparmsp->fx_uprilim > FX_MAX_UNPRIV_PRI &&
			    secpolicy_setpriority(reqpcredp) != 0)
				return (EPERM);
			reqfxuprilim = fxkparmsp->fx_uprilim;
			FX_ADJUST_PRI(reqfxuprilim);
		}

		if ((fxkparmsp->fx_cflags & FX_DOUPRI) == 0) {
			reqfxupri = reqfxuprilim;
		} else {
			if (fxkparmsp->fx_upri > FX_MAX_UNPRIV_PRI &&
			    secpolicy_setpriority(reqpcredp) != 0)
				return (EPERM);
			/*
			 * Set the user priority to the requested value
			 * or the upri limit, whichever is lower.
			 */
			reqfxupri = fxkparmsp->fx_upri;
			FX_ADJUST_PRI(reqfxupri);

			if (reqfxupri > reqfxuprilim)
				reqfxupri = reqfxuprilim;
		}


		fxpp->fx_uprilim = reqfxuprilim;
		fxpp->fx_pri = reqfxupri;

		fxpp->fx_nice = NZERO - (NZERO * reqfxupri) / fx_maxupri;

		if (((fxkparmsp->fx_cflags & FX_DOTQ) == 0) ||
		    (fxkparmsp->fx_tqntm == FX_TQDEF)) {
			fxpp->fx_pquantum = fx_dptbl[fxpp->fx_pri].fx_quantum;
		} else {
			if (secpolicy_setpriority(reqpcredp) != 0)
				return (EPERM);

			if (fxkparmsp->fx_tqntm == FX_TQINF)
				fxpp->fx_pquantum = FX_TQINF;
			else {
				fxpp->fx_pquantum = fxkparmsp->fx_tqntm;
			}
		}

	}

	fxpp->fx_timeleft = fxpp->fx_pquantum;
	cpucaps_sc_init(&fxpp->fx_caps);
	fxpp->fx_tp = t;

	thread_lock(t);			/* get dispatcher lock on thread */
	t->t_clfuncs = &(sclass[cid].cl_funcs->thread);
	t->t_cid = cid;
	t->t_cldata = (void *)fxpp;
	t->t_schedflag &= ~TS_RUNQMATCH;
	fx_change_priority(t, fxpp);
	thread_unlock(t);

	return (0);
}

/*
 * The thread is exiting.
 */
static void
fx_exit(kthread_t *t)
{
	fxproc_t *fxpp;

	thread_lock(t);
	fxpp = (fxproc_t *)(t->t_cldata);

	/*
	 * A thread could be exiting in between clock ticks, so we need to
	 * calculate how much CPU time it used since it was charged last time.
	 *
	 * CPU caps are not enforced on exiting processes - it is usually
	 * desirable to exit as soon as possible to free resources.
	 */
	(void) CPUCAPS_CHARGE(t, &fxpp->fx_caps, CPUCAPS_CHARGE_ONLY);

	if (FX_HAS_CB(fxpp)) {
		FX_CB_EXIT(FX_CALLB(fxpp), fxpp->fx_cookie);
		fxpp->fx_callback = NULL;
		fxpp->fx_cookie = NULL;
		thread_unlock(t);
		FX_CB_LIST_DELETE(fxpp);
		return;
	}

	thread_unlock(t);
}

/*
 * Exiting the class. Free fxproc structure of thread.
 */
static void
fx_exitclass(void *procp)
{
	fxproc_t *fxpp = (fxproc_t *)procp;

	thread_lock(fxpp->fx_tp);
	if (FX_HAS_CB(fxpp)) {

		FX_CB_EXIT(FX_CALLB(fxpp), fxpp->fx_cookie);

		fxpp->fx_callback = NULL;
		fxpp->fx_cookie = NULL;
		thread_unlock(fxpp->fx_tp);
		FX_CB_LIST_DELETE(fxpp);
	} else
		thread_unlock(fxpp->fx_tp);

	kmem_free(fxpp, sizeof (fxproc_t));
}

/* ARGSUSED */
static int
fx_canexit(kthread_t *t, cred_t *cred)
{
	/*
	 * A thread can always leave the FX class
	 */
	return (0);
}

/*
 * Initialize fixed-priority class specific proc structure for a child.
 * callbacks are not inherited upon fork.
 */
static int
fx_fork(kthread_t *t, kthread_t *ct, void *bufp)
{
	fxproc_t	*pfxpp;		/* ptr to parent's fxproc structure */
	fxproc_t	*cfxpp;		/* ptr to child's fxproc structure */

	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	cfxpp = (fxproc_t *)bufp;
	ASSERT(cfxpp != NULL);
	thread_lock(t);
	pfxpp = (fxproc_t *)t->t_cldata;
	/*
	 * Initialize child's fxproc structure.
	 */
	cfxpp->fx_timeleft = cfxpp->fx_pquantum = pfxpp->fx_pquantum;
	cfxpp->fx_pri = pfxpp->fx_pri;
	cfxpp->fx_uprilim = pfxpp->fx_uprilim;
	cfxpp->fx_nice = pfxpp->fx_nice;
	cfxpp->fx_callback = NULL;
	cfxpp->fx_cookie = NULL;
	cfxpp->fx_flags = pfxpp->fx_flags & ~(FXBACKQ);
	cpucaps_sc_init(&cfxpp->fx_caps);

	cfxpp->fx_tp = ct;
	ct->t_cldata = (void *)cfxpp;
	thread_unlock(t);

	/*
	 * Link new structure into fxproc list.
	 */
	return (0);
}


/*
 * Child is placed at back of dispatcher queue and parent gives
 * up processor so that the child runs first after the fork.
 * This allows the child immediately execing to break the multiple
 * use of copy on write pages with no disk home. The parent will
 * get to steal them back rather than uselessly copying them.
 */
static void
fx_forkret(kthread_t *t, kthread_t *ct)
{
	proc_t	*pp = ttoproc(t);
	proc_t	*cp = ttoproc(ct);
	fxproc_t *fxpp;

	ASSERT(t == curthread);
	ASSERT(MUTEX_HELD(&pidlock));

	/*
	 * Grab the child's p_lock before dropping pidlock to ensure
	 * the process does not disappear before we set it running.
	 */
	mutex_enter(&cp->p_lock);
	continuelwps(cp);
	mutex_exit(&cp->p_lock);

	mutex_enter(&pp->p_lock);
	mutex_exit(&pidlock);
	continuelwps(pp);

	thread_lock(t);
	fxpp = (fxproc_t *)(t->t_cldata);
	t->t_pri = fx_dptbl[fxpp->fx_pri].fx_globpri;
	ASSERT(t->t_pri >= 0 && t->t_pri <= fx_maxglobpri);
	THREAD_TRANSITION(t);
	fx_setrun(t);
	thread_unlock(t);
	/*
	 * Safe to drop p_lock now since it is safe to change
	 * the scheduling class after this point.
	 */
	mutex_exit(&pp->p_lock);

	swtch();
}


/*
 * Get information about the fixed-priority class into the buffer
 * pointed to by fxinfop. The maximum configured user priority
 * is the only information we supply.
 */
static int
fx_getclinfo(void *infop)
{
	fxinfo_t *fxinfop = (fxinfo_t *)infop;
	fxinfop->fx_maxupri = fx_maxupri;
	return (0);
}



/*
 * Return the user mode scheduling priority range.
 */
static int
fx_getclpri(pcpri_t *pcprip)
{
	pcprip->pc_clpmax = fx_maxupri;
	pcprip->pc_clpmin = 0;
	return (0);
}


static void
fx_nullsys()
{}


/*
 * Get the fixed-priority parameters of the thread pointed to by
 * fxprocp into the buffer pointed to by fxparmsp.
 */
static void
fx_parmsget(kthread_t *t, void *parmsp)
{
	fxproc_t *fxpp = (fxproc_t *)t->t_cldata;
	fxkparms_t *fxkparmsp = (fxkparms_t *)parmsp;

	fxkparmsp->fx_upri = fxpp->fx_pri;
	fxkparmsp->fx_uprilim = fxpp->fx_uprilim;
	fxkparmsp->fx_tqntm = fxpp->fx_pquantum;
}



/*
 * Check the validity of the fixed-priority parameters in the buffer
 * pointed to by fxparmsp.
 */
static int
fx_parmsin(void *parmsp)
{
	fxparms_t	*fxparmsp = (fxparms_t *)parmsp;
	uint_t		cflags;
	longlong_t	ticks;
	/*
	 * Check validity of parameters.
	 */

	if ((fxparmsp->fx_uprilim > fx_maxupri ||
	    fxparmsp->fx_uprilim < 0) &&
	    fxparmsp->fx_uprilim != FX_NOCHANGE)
		return (EINVAL);

	if ((fxparmsp->fx_upri > fx_maxupri ||
	    fxparmsp->fx_upri < 0) &&
	    fxparmsp->fx_upri != FX_NOCHANGE)
		return (EINVAL);

	if ((fxparmsp->fx_tqsecs == 0 && fxparmsp->fx_tqnsecs == 0) ||
	    fxparmsp->fx_tqnsecs >= NANOSEC)
		return (EINVAL);

	cflags = (fxparmsp->fx_upri != FX_NOCHANGE ? FX_DOUPRI : 0);

	if (fxparmsp->fx_uprilim != FX_NOCHANGE) {
		cflags |= FX_DOUPRILIM;
	}

	if (fxparmsp->fx_tqnsecs != FX_NOCHANGE)
		cflags |= FX_DOTQ;

	/*
	 * convert the buffer to kernel format.
	 */

	if (fxparmsp->fx_tqnsecs >= 0) {
		if ((ticks = SEC_TO_TICK((longlong_t)fxparmsp->fx_tqsecs) +
		    NSEC_TO_TICK_ROUNDUP(fxparmsp->fx_tqnsecs)) > INT_MAX)
			return (ERANGE);

		((fxkparms_t *)fxparmsp)->fx_tqntm = (int)ticks;
	} else {
		if ((fxparmsp->fx_tqnsecs != FX_NOCHANGE) &&
		    (fxparmsp->fx_tqnsecs != FX_TQINF) &&
		    (fxparmsp->fx_tqnsecs != FX_TQDEF))
			return (EINVAL);
		((fxkparms_t *)fxparmsp)->fx_tqntm = fxparmsp->fx_tqnsecs;
	}

	((fxkparms_t *)fxparmsp)->fx_cflags = cflags;

	return (0);
}


/*
 * Check the validity of the fixed-priority parameters in the pc_vaparms_t
 * structure vaparmsp and put them in the buffer pointed to by fxprmsp.
 * pc_vaparms_t contains (key, value) pairs of parameter.
 */
static int
fx_vaparmsin(void *prmsp, pc_vaparms_t *vaparmsp)
{
	uint_t		secs = 0;
	uint_t		cnt;
	int		nsecs = 0;
	int		priflag, secflag, nsecflag, limflag;
	longlong_t	ticks;
	fxkparms_t	*fxprmsp = (fxkparms_t *)prmsp;
	pc_vaparm_t	*vpp = &vaparmsp->pc_parms[0];


	/*
	 * First check the validity of parameters and convert them
	 * from the user supplied format to the internal format.
	 */
	priflag = secflag = nsecflag = limflag = 0;

	fxprmsp->fx_cflags = 0;

	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {

		switch (vpp->pc_key) {
		case FX_KY_UPRILIM:
			if (limflag++)
				return (EINVAL);
			fxprmsp->fx_cflags |= FX_DOUPRILIM;
			fxprmsp->fx_uprilim = (pri_t)vpp->pc_parm;
			if (fxprmsp->fx_uprilim > fx_maxupri ||
			    fxprmsp->fx_uprilim < 0)
				return (EINVAL);
			break;

		case FX_KY_UPRI:
			if (priflag++)
				return (EINVAL);
			fxprmsp->fx_cflags |= FX_DOUPRI;
			fxprmsp->fx_upri = (pri_t)vpp->pc_parm;
			if (fxprmsp->fx_upri > fx_maxupri ||
			    fxprmsp->fx_upri < 0)
				return (EINVAL);
			break;

		case FX_KY_TQSECS:
			if (secflag++)
				return (EINVAL);
			fxprmsp->fx_cflags |= FX_DOTQ;
			secs = (uint_t)vpp->pc_parm;
			break;

		case FX_KY_TQNSECS:
			if (nsecflag++)
				return (EINVAL);
			fxprmsp->fx_cflags |= FX_DOTQ;
			nsecs = (int)vpp->pc_parm;
			break;

		default:
			return (EINVAL);
		}
	}

	if (vaparmsp->pc_vaparmscnt == 0) {
		/*
		 * Use default parameters.
		 */
		fxprmsp->fx_upri = 0;
		fxprmsp->fx_uprilim = 0;
		fxprmsp->fx_tqntm = FX_TQDEF;
		fxprmsp->fx_cflags = FX_DOUPRI | FX_DOUPRILIM | FX_DOTQ;
	} else if ((fxprmsp->fx_cflags & FX_DOTQ) != 0) {
		if ((secs == 0 && nsecs == 0) || nsecs >= NANOSEC)
			return (EINVAL);

		if (nsecs >= 0) {
			if ((ticks = SEC_TO_TICK((longlong_t)secs) +
			    NSEC_TO_TICK_ROUNDUP(nsecs)) > INT_MAX)
				return (ERANGE);

			fxprmsp->fx_tqntm = (int)ticks;
		} else {
			if (nsecs != FX_TQINF && nsecs != FX_TQDEF)
				return (EINVAL);
			fxprmsp->fx_tqntm = nsecs;
		}
	}

	return (0);
}


/*
 * Nothing to do here but return success.
 */
/* ARGSUSED */
static int
fx_parmsout(void *parmsp, pc_vaparms_t *vaparmsp)
{
	register fxkparms_t	*fxkprmsp = (fxkparms_t *)parmsp;

	if (vaparmsp != NULL)
		return (0);

	if (fxkprmsp->fx_tqntm < 0) {
		/*
		 * Quantum field set to special value (e.g. FX_TQINF)
		 */
		((fxparms_t *)fxkprmsp)->fx_tqnsecs = fxkprmsp->fx_tqntm;
		((fxparms_t *)fxkprmsp)->fx_tqsecs = 0;

	} else {
		/* Convert quantum from ticks to seconds-nanoseconds */

		timestruc_t ts;
		TICK_TO_TIMESTRUC(fxkprmsp->fx_tqntm, &ts);
		((fxparms_t *)fxkprmsp)->fx_tqsecs = ts.tv_sec;
		((fxparms_t *)fxkprmsp)->fx_tqnsecs = ts.tv_nsec;
	}

	return (0);
}


/*
 * Copy all selected fixed-priority class parameters to the user.
 * The parameters are specified by a key.
 */
static int
fx_vaparmsout(void *prmsp, pc_vaparms_t *vaparmsp)
{
	fxkparms_t	*fxkprmsp = (fxkparms_t *)prmsp;
	timestruc_t	ts;
	uint_t		cnt;
	uint_t		secs;
	int		nsecs;
	int		priflag, secflag, nsecflag, limflag;
	pc_vaparm_t	*vpp = &vaparmsp->pc_parms[0];

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	priflag = secflag = nsecflag = limflag = 0;

	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	if (fxkprmsp->fx_tqntm < 0) {
		/*
		 * Quantum field set to special value (e.g. FX_TQINF).
		 */
		secs = 0;
		nsecs = fxkprmsp->fx_tqntm;
	} else {
		/*
		 * Convert quantum from ticks to seconds-nanoseconds.
		 */
		TICK_TO_TIMESTRUC(fxkprmsp->fx_tqntm, &ts);
		secs = ts.tv_sec;
		nsecs = ts.tv_nsec;
	}


	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {

		switch (vpp->pc_key) {
		case FX_KY_UPRILIM:
			if (limflag++)
				return (EINVAL);
			if (copyout(&fxkprmsp->fx_uprilim,
			    (void *)(uintptr_t)vpp->pc_parm, sizeof (pri_t)))
				return (EFAULT);
			break;

		case FX_KY_UPRI:
			if (priflag++)
				return (EINVAL);
			if (copyout(&fxkprmsp->fx_upri,
			    (void *)(uintptr_t)vpp->pc_parm, sizeof (pri_t)))
				return (EFAULT);
			break;

		case FX_KY_TQSECS:
			if (secflag++)
				return (EINVAL);
			if (copyout(&secs,
			    (void *)(uintptr_t)vpp->pc_parm, sizeof (uint_t)))
				return (EFAULT);
			break;

		case FX_KY_TQNSECS:
			if (nsecflag++)
				return (EINVAL);
			if (copyout(&nsecs,
			    (void *)(uintptr_t)vpp->pc_parm, sizeof (int)))
				return (EFAULT);
			break;

		default:
			return (EINVAL);
		}
	}

	return (0);
}

/*
 * Set the scheduling parameters of the thread pointed to by fxprocp
 * to those specified in the buffer pointed to by fxparmsp.
 */
/* ARGSUSED */
static int
fx_parmsset(kthread_t *tx, void *parmsp, id_t reqpcid, cred_t *reqpcredp)
{
	char		nice;
	pri_t		reqfxuprilim;
	pri_t		reqfxupri;
	fxkparms_t	*fxkparmsp = (fxkparms_t *)parmsp;
	fxproc_t	*fxpp;


	ASSERT(MUTEX_HELD(&(ttoproc(tx))->p_lock));

	thread_lock(tx);
	fxpp = (fxproc_t *)tx->t_cldata;

	if ((fxkparmsp->fx_cflags & FX_DOUPRILIM) == 0)
		reqfxuprilim = fxpp->fx_uprilim;
	else
		reqfxuprilim = fxkparmsp->fx_uprilim;

	/*
	 * Basic permissions enforced by generic kernel code
	 * for all classes require that a thread attempting
	 * to change the scheduling parameters of a target
	 * thread be privileged or have a real or effective
	 * UID matching that of the target thread. We are not
	 * called unless these basic permission checks have
	 * already passed. The fixed priority class requires in
	 * addition that the calling thread be privileged if it
	 * is attempting to raise the pri above its current
	 * value This may have been checked previously but if our
	 * caller passed us a non-NULL credential pointer we assume
	 * it hasn't and we check it here.
	 */

	if ((reqpcredp != NULL) &&
	    (reqfxuprilim > fxpp->fx_uprilim ||
	    ((fxkparmsp->fx_cflags & FX_DOTQ) != 0)) &&
	    secpolicy_raisepriority(reqpcredp) != 0) {
		thread_unlock(tx);
		return (EPERM);
	}

	FX_ADJUST_PRI(reqfxuprilim);

	if ((fxkparmsp->fx_cflags & FX_DOUPRI) == 0)
		reqfxupri = fxpp->fx_pri;
	else
		reqfxupri = fxkparmsp->fx_upri;


	/*
	 * Make sure the user priority doesn't exceed the upri limit.
	 */
	if (reqfxupri > reqfxuprilim)
		reqfxupri = reqfxuprilim;

	/*
	 * Set fx_nice to the nice value corresponding to the user
	 * priority we are setting.  Note that setting the nice field
	 * of the parameter struct won't affect upri or nice.
	 */

	nice = NZERO - (reqfxupri * NZERO) / fx_maxupri;

	if (nice > NZERO)
		nice = NZERO;

	fxpp->fx_uprilim = reqfxuprilim;
	fxpp->fx_pri = reqfxupri;

	if (fxkparmsp->fx_tqntm == FX_TQINF)
		fxpp->fx_pquantum = FX_TQINF;
	else if (fxkparmsp->fx_tqntm == FX_TQDEF)
		fxpp->fx_pquantum = fx_dptbl[fxpp->fx_pri].fx_quantum;
	else if ((fxkparmsp->fx_cflags & FX_DOTQ) != 0)
		fxpp->fx_pquantum = fxkparmsp->fx_tqntm;

	fxpp->fx_nice = nice;

	fx_change_priority(tx, fxpp);
	thread_unlock(tx);
	return (0);
}


/*
 * Return the global scheduling priority that would be assigned
 * to a thread entering the fixed-priority class with the fx_upri.
 */
static pri_t
fx_globpri(kthread_t *t)
{
	fxproc_t *fxpp;

	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	fxpp = (fxproc_t *)t->t_cldata;
	return (fx_dptbl[fxpp->fx_pri].fx_globpri);

}

/*
 * Arrange for thread to be placed in appropriate location
 * on dispatcher queue.
 *
 * This is called with the current thread in TS_ONPROC and locked.
 */
static void
fx_preempt(kthread_t *t)
{
	fxproc_t	*fxpp = (fxproc_t *)(t->t_cldata);

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(curthread));

	(void) CPUCAPS_CHARGE(t, &fxpp->fx_caps, CPUCAPS_CHARGE_ENFORCE);

	/*
	 * Check to see if we're doing "preemption control" here.  If
	 * we are, and if the user has requested that this thread not
	 * be preempted, and if preemptions haven't been put off for
	 * too long, let the preemption happen here but try to make
	 * sure the thread is rescheduled as soon as possible.  We do
	 * this by putting it on the front of the highest priority run
	 * queue in the FX class.  If the preemption has been put off
	 * for too long, clear the "nopreempt" bit and let the thread
	 * be preempted.
	 */
	if (t->t_schedctl && schedctl_get_nopreempt(t)) {
		if (fxpp->fx_pquantum == FX_TQINF ||
		    fxpp->fx_timeleft > -SC_MAX_TICKS) {
			DTRACE_SCHED1(schedctl__nopreempt, kthread_t *, t);
			schedctl_set_yield(t, 1);
			setfrontdq(t);
			return;
		} else {
			schedctl_set_nopreempt(t, 0);
			DTRACE_SCHED1(schedctl__preempt, kthread_t *, t);
			TNF_PROBE_2(schedctl_preempt, "schedctl FX fx_preempt",
			    /* CSTYLED */, tnf_pid, pid, ttoproc(t)->p_pid,
			    tnf_lwpid, lwpid, t->t_tid);
			/*
			 * Fall through and be preempted below.
			 */
		}
	}

	if (FX_HAS_CB(fxpp)) {
		clock_t new_quantum =  (clock_t)fxpp->fx_pquantum;
		pri_t	newpri = fxpp->fx_pri;
		FX_CB_PREEMPT(FX_CALLB(fxpp), fxpp->fx_cookie,
		    &new_quantum, &newpri);
		FX_ADJUST_QUANTUM(new_quantum);
		if ((int)new_quantum != fxpp->fx_pquantum) {
			fxpp->fx_pquantum = (int)new_quantum;
			fxpp->fx_timeleft = fxpp->fx_pquantum;
		}
		FX_ADJUST_PRI(newpri);
		fxpp->fx_pri = newpri;
		THREAD_CHANGE_PRI(t, fx_dptbl[fxpp->fx_pri].fx_globpri);
	}

	/*
	 * This thread may be placed on wait queue by CPU Caps. In this case we
	 * do not need to do anything until it is removed from the wait queue.
	 */
	if (CPUCAPS_ENFORCE(t)) {
		return;
	}

	if ((fxpp->fx_flags & (FXBACKQ)) == FXBACKQ) {
		fxpp->fx_timeleft = fxpp->fx_pquantum;
		fxpp->fx_flags &= ~FXBACKQ;
		setbackdq(t);
	} else {
		setfrontdq(t);
	}
}

static void
fx_setrun(kthread_t *t)
{
	fxproc_t *fxpp = (fxproc_t *)(t->t_cldata);

	ASSERT(THREAD_LOCK_HELD(t));	/* t should be in transition */
	fxpp->fx_flags &= ~FXBACKQ;

	if (t->t_disp_time != ddi_get_lbolt())
		setbackdq(t);
	else
		setfrontdq(t);
}


/*
 * Prepare thread for sleep. We reset the thread priority so it will
 * run at the kernel priority level when it wakes up.
 */
static void
fx_sleep(kthread_t *t)
{
	fxproc_t	*fxpp = (fxproc_t *)(t->t_cldata);

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(t));

	/*
	 * Account for time spent on CPU before going to sleep.
	 */
	(void) CPUCAPS_CHARGE(t, &fxpp->fx_caps, CPUCAPS_CHARGE_ENFORCE);

	if (FX_HAS_CB(fxpp)) {
		FX_CB_SLEEP(FX_CALLB(fxpp), fxpp->fx_cookie);
	}
	t->t_stime = ddi_get_lbolt();		/* time stamp for the swapper */
}


/*
 * Return Values:
 *
 *	-1 if the thread is loaded or is not eligible to be swapped in.
 *
 * FX and RT threads are designed so that they don't swapout; however,
 * it is possible that while the thread is swapped out and in another class, it
 * can be changed to FX or RT.  Since these threads should be swapped in
 * as soon as they're runnable, rt_swapin returns SHRT_MAX, and fx_swapin
 * returns SHRT_MAX - 1, so that it gives deference to any swapped out
 * RT threads.
 */
/* ARGSUSED */
static pri_t
fx_swapin(kthread_t *t, int flags)
{
	pri_t	tpri = -1;

	ASSERT(THREAD_LOCK_HELD(t));

	if (t->t_state == TS_RUN && (t->t_schedflag & TS_LOAD) == 0) {
		tpri = (pri_t)SHRT_MAX - 1;
	}

	return (tpri);
}

/*
 * Return Values
 *	-1 if the thread isn't loaded or is not eligible to be swapped out.
 */
/* ARGSUSED */
static pri_t
fx_swapout(kthread_t *t, int flags)
{
	ASSERT(THREAD_LOCK_HELD(t));

	return (-1);

}

/* ARGSUSED */
static void
fx_stop(kthread_t *t, int why, int what)
{
	fxproc_t *fxpp = (fxproc_t *)(t->t_cldata);

	ASSERT(THREAD_LOCK_HELD(t));

	if (FX_HAS_CB(fxpp)) {
		FX_CB_STOP(FX_CALLB(fxpp), fxpp->fx_cookie);
	}
}

/*
 * Check for time slice expiration.  If time slice has expired
 * set runrun to cause preemption.
 */
static void
fx_tick(kthread_t *t)
{
	boolean_t call_cpu_surrender = B_FALSE;
	fxproc_t *fxpp;

	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock));

	thread_lock(t);

	fxpp = (fxproc_t *)(t->t_cldata);

	if (FX_HAS_CB(fxpp)) {
		clock_t new_quantum =  (clock_t)fxpp->fx_pquantum;
		pri_t	newpri = fxpp->fx_pri;
		FX_CB_TICK(FX_CALLB(fxpp), fxpp->fx_cookie,
		    &new_quantum, &newpri);
		FX_ADJUST_QUANTUM(new_quantum);
		if ((int)new_quantum != fxpp->fx_pquantum) {
			fxpp->fx_pquantum = (int)new_quantum;
			fxpp->fx_timeleft = fxpp->fx_pquantum;
		}
		FX_ADJUST_PRI(newpri);
		if (newpri != fxpp->fx_pri) {
			fxpp->fx_pri = newpri;
			fx_change_priority(t, fxpp);
		}
	}

	/*
	 * Keep track of thread's project CPU usage.  Note that projects
	 * get charged even when threads are running in the kernel.
	 */
	call_cpu_surrender =  CPUCAPS_CHARGE(t, &fxpp->fx_caps,
	    CPUCAPS_CHARGE_ENFORCE);

	if ((fxpp->fx_pquantum != FX_TQINF) &&
	    (--fxpp->fx_timeleft <= 0)) {
		pri_t	new_pri;

		/*
		 * If we're doing preemption control and trying to
		 * avoid preempting this thread, just note that
		 * the thread should yield soon and let it keep
		 * running (unless it's been a while).
		 */
		if (t->t_schedctl && schedctl_get_nopreempt(t)) {
			if (fxpp->fx_timeleft > -SC_MAX_TICKS) {
				DTRACE_SCHED1(schedctl__nopreempt,
				    kthread_t *, t);
				schedctl_set_yield(t, 1);
				thread_unlock_nopreempt(t);
				return;
			}
			TNF_PROBE_2(schedctl_failsafe,
			    "schedctl FX fx_tick", /* CSTYLED */,
			    tnf_pid, pid, ttoproc(t)->p_pid,
			    tnf_lwpid, lwpid, t->t_tid);
		}
		new_pri = fx_dptbl[fxpp->fx_pri].fx_globpri;
		ASSERT(new_pri >= 0 && new_pri <= fx_maxglobpri);
		/*
		 * When the priority of a thread is changed,
		 * it may be necessary to adjust its position
		 * on a sleep queue or dispatch queue. Even
		 * when the priority is not changed, we need
		 * to preserve round robin on dispatch queue.
		 * The function thread_change_pri accomplishes
		 * this.
		 */
		if (thread_change_pri(t, new_pri, 0)) {
			fxpp->fx_timeleft = fxpp->fx_pquantum;
		} else {
			call_cpu_surrender = B_TRUE;
		}
	} else if (t->t_state == TS_ONPROC &&
	    t->t_pri < t->t_disp_queue->disp_maxrunpri) {
		call_cpu_surrender = B_TRUE;
	}

	if (call_cpu_surrender) {
		fxpp->fx_flags |= FXBACKQ;
		cpu_surrender(t);
	}
	thread_unlock_nopreempt(t);	/* clock thread can't be preempted */
}


static void
fx_trapret(kthread_t *t)
{
	cpu_t		*cp = CPU;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t == curthread);
	ASSERT(cp->cpu_dispthread == t);
	ASSERT(t->t_state == TS_ONPROC);
}


/*
 * Processes waking up go to the back of their queue.
 */
static void
fx_wakeup(kthread_t *t)
{
	fxproc_t	*fxpp = (fxproc_t *)(t->t_cldata);

	ASSERT(THREAD_LOCK_HELD(t));

	t->t_stime = ddi_get_lbolt();		/* time stamp for the swapper */
	if (FX_HAS_CB(fxpp)) {
		clock_t new_quantum =  (clock_t)fxpp->fx_pquantum;
		pri_t	newpri = fxpp->fx_pri;
		FX_CB_WAKEUP(FX_CALLB(fxpp), fxpp->fx_cookie,
		    &new_quantum, &newpri);
		FX_ADJUST_QUANTUM(new_quantum);
		if ((int)new_quantum != fxpp->fx_pquantum) {
			fxpp->fx_pquantum = (int)new_quantum;
			fxpp->fx_timeleft = fxpp->fx_pquantum;
		}

		FX_ADJUST_PRI(newpri);
		if (newpri != fxpp->fx_pri) {
			fxpp->fx_pri = newpri;
			THREAD_CHANGE_PRI(t, fx_dptbl[fxpp->fx_pri].fx_globpri);
		}
	}

	fxpp->fx_flags &= ~FXBACKQ;

	if (t->t_disp_time != ddi_get_lbolt())
		setbackdq(t);
	else
		setfrontdq(t);
}


/*
 * When a thread yields, put it on the back of the run queue.
 */
static void
fx_yield(kthread_t *t)
{
	fxproc_t	*fxpp = (fxproc_t *)(t->t_cldata);

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(t));

	/*
	 * Collect CPU usage spent before yielding CPU.
	 */
	(void) CPUCAPS_CHARGE(t, &fxpp->fx_caps, CPUCAPS_CHARGE_ENFORCE);

	if (FX_HAS_CB(fxpp))  {
		clock_t new_quantum =  (clock_t)fxpp->fx_pquantum;
		pri_t	newpri = fxpp->fx_pri;
		FX_CB_PREEMPT(FX_CALLB(fxpp), fxpp->fx_cookie,
		    &new_quantum, &newpri);
		FX_ADJUST_QUANTUM(new_quantum);
		if ((int)new_quantum != fxpp->fx_pquantum) {
			fxpp->fx_pquantum = (int)new_quantum;
			fxpp->fx_timeleft = fxpp->fx_pquantum;
		}
		FX_ADJUST_PRI(newpri);
		fxpp->fx_pri = newpri;
		THREAD_CHANGE_PRI(t, fx_dptbl[fxpp->fx_pri].fx_globpri);
	}

	/*
	 * Clear the preemption control "yield" bit since the user is
	 * doing a yield.
	 */
	if (t->t_schedctl)
		schedctl_set_yield(t, 0);

	if (fxpp->fx_timeleft <= 0) {
		/*
		 * Time slice was artificially extended to avoid
		 * preemption, so pretend we're preempting it now.
		 */
		DTRACE_SCHED1(schedctl__yield, int, -fxpp->fx_timeleft);
		fxpp->fx_timeleft = fxpp->fx_pquantum;
		THREAD_CHANGE_PRI(t, fx_dptbl[fxpp->fx_pri].fx_globpri);
		ASSERT(t->t_pri >= 0 && t->t_pri <= fx_maxglobpri);
	}

	fxpp->fx_flags &= ~FXBACKQ;
	setbackdq(t);
}

/*
 * Increment the nice value of the specified thread by incr and
 * return the new value in *retvalp.
 */
static int
fx_donice(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	int		newnice;
	fxproc_t	*fxpp = (fxproc_t *)(t->t_cldata);
	fxkparms_t	fxkparms;

	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock));

	/* If there's no change to priority, just return current setting */
	if (incr == 0) {
		if (retvalp) {
			*retvalp = fxpp->fx_nice - NZERO;
		}
		return (0);
	}

	if ((incr < 0 || incr > 2 * NZERO) &&
	    secpolicy_raisepriority(cr) != 0)
		return (EPERM);

	/*
	 * Specifying a nice increment greater than the upper limit of
	 * 2 * NZERO - 1 will result in the thread's nice value being
	 * set to the upper limit.  We check for this before computing
	 * the new value because otherwise we could get overflow
	 * if a privileged user specified some ridiculous increment.
	 */
	if (incr > 2 * NZERO - 1)
		incr = 2 * NZERO - 1;

	newnice = fxpp->fx_nice + incr;
	if (newnice > NZERO)
		newnice = NZERO;
	else if (newnice < 0)
		newnice = 0;

	fxkparms.fx_uprilim = fxkparms.fx_upri =
	    -((newnice - NZERO) * fx_maxupri) / NZERO;

	fxkparms.fx_cflags = FX_DOUPRILIM | FX_DOUPRI;

	fxkparms.fx_tqntm = FX_TQDEF;

	/*
	 * Reset the uprilim and upri values of the thread. Adjust
	 * time quantum accordingly.
	 */

	(void) fx_parmsset(t, (void *)&fxkparms, (id_t)0, (cred_t *)NULL);

	/*
	 * Although fx_parmsset already reset fx_nice it may
	 * not have been set to precisely the value calculated above
	 * because fx_parmsset determines the nice value from the
	 * user priority and we may have truncated during the integer
	 * conversion from nice value to user priority and back.
	 * We reset fx_nice to the value we calculated above.
	 */
	fxpp->fx_nice = (char)newnice;

	if (retvalp)
		*retvalp = newnice - NZERO;

	return (0);
}

/*
 * Increment the priority of the specified thread by incr and
 * return the new value in *retvalp.
 */
static int
fx_doprio(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	int		newpri;
	fxproc_t	*fxpp = (fxproc_t *)(t->t_cldata);
	fxkparms_t	fxkparms;

	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock));

	/* If there's no change to priority, just return current setting */
	if (incr == 0) {
		*retvalp = fxpp->fx_pri;
		return (0);
	}

	newpri = fxpp->fx_pri + incr;
	if (newpri > fx_maxupri || newpri < 0)
		return (EINVAL);

	*retvalp = newpri;
	fxkparms.fx_uprilim = fxkparms.fx_upri = newpri;
	fxkparms.fx_tqntm = FX_NOCHANGE;
	fxkparms.fx_cflags = FX_DOUPRILIM | FX_DOUPRI;

	/*
	 * Reset the uprilim and upri values of the thread.
	 */
	return (fx_parmsset(t, (void *)&fxkparms, (id_t)0, cr));
}

static void
fx_change_priority(kthread_t *t, fxproc_t *fxpp)
{
	pri_t	new_pri;

	ASSERT(THREAD_LOCK_HELD(t));
	new_pri = fx_dptbl[fxpp->fx_pri].fx_globpri;
	ASSERT(new_pri >= 0 && new_pri <= fx_maxglobpri);
	t->t_cpri = fxpp->fx_pri;
	if (t == curthread || t->t_state == TS_ONPROC) {
		/* curthread is always onproc */
		cpu_t	*cp = t->t_disp_queue->disp_cpu;
		THREAD_CHANGE_PRI(t, new_pri);
		if (t == cp->cpu_dispthread)
			cp->cpu_dispatch_pri = DISP_PRIO(t);
		if (DISP_MUST_SURRENDER(t)) {
			fxpp->fx_flags |= FXBACKQ;
			cpu_surrender(t);
		} else {
			fxpp->fx_timeleft = fxpp->fx_pquantum;
		}
	} else {
		/*
		 * When the priority of a thread is changed,
		 * it may be necessary to adjust its position
		 * on a sleep queue or dispatch queue.
		 * The function thread_change_pri accomplishes
		 * this.
		 */
		if (thread_change_pri(t, new_pri, 0)) {
			/*
			 * The thread was on a run queue. Reset
			 * its CPU timeleft from the quantum
			 * associated with the new priority.
			 */
			fxpp->fx_timeleft = fxpp->fx_pquantum;
		} else {
			fxpp->fx_flags |= FXBACKQ;
		}
	}
}

static int
fx_alloc(void **p, int flag)
{
	void *bufp;

	bufp = kmem_alloc(sizeof (fxproc_t), flag);
	if (bufp == NULL) {
		return (ENOMEM);
	} else {
		*p = bufp;
		return (0);
	}
}

static void
fx_free(void *bufp)
{
	if (bufp)
		kmem_free(bufp, sizeof (fxproc_t));
}

/*
 * Release the callback list mutex after successful lookup
 */
void
fx_list_release(fxproc_t *fxpp)
{
	int index = FX_CB_LIST_HASH(fxpp->fx_ktid);
	kmutex_t *lockp = &fx_cb_list_lock[index];
	mutex_exit(lockp);
}

fxproc_t *
fx_list_lookup(kt_did_t ktid)
{
	int index = FX_CB_LIST_HASH(ktid);
	kmutex_t *lockp = &fx_cb_list_lock[index];
	fxproc_t *fxpp;

	mutex_enter(lockp);

	for (fxpp = fx_cb_plisthead[index].fx_cb_next;
	    fxpp != &fx_cb_plisthead[index]; fxpp = fxpp->fx_cb_next) {
		if (fxpp->fx_tp->t_cid == fx_cid && fxpp->fx_ktid == ktid &&
		    fxpp->fx_callback != NULL) {
			/*
			 * The caller is responsible for calling
			 * fx_list_release to drop the lock upon
			 * successful lookup
			 */
			return (fxpp);
		}
	}
	mutex_exit(lockp);
	return ((fxproc_t *)NULL);
}


/*
 * register a callback set of routines for current thread
 * thread should already be in FX class
 */
int
fx_register_callbacks(fx_callbacks_t *fx_callback, fx_cookie_t cookie,
	pri_t pri, clock_t quantum)
{

	fxproc_t	*fxpp;

	if (fx_callback == NULL)
		return (EINVAL);

	if (secpolicy_dispadm(CRED()) != 0)
		return (EPERM);

	if (FX_CB_VERSION(fx_callback) != FX_CALLB_REV)
		return (EINVAL);

	if (!FX_ISVALID(pri, quantum))
		return (EINVAL);

	thread_lock(curthread);		/* get dispatcher lock on thread */

	if (curthread->t_cid != fx_cid) {
		thread_unlock(curthread);
		return (EINVAL);
	}

	fxpp = (fxproc_t *)(curthread->t_cldata);
	ASSERT(fxpp != NULL);
	if (FX_HAS_CB(fxpp)) {
		thread_unlock(curthread);
		return (EINVAL);
	}

	fxpp->fx_callback = fx_callback;
	fxpp->fx_cookie = cookie;

	if (pri != FX_CB_NOCHANGE) {
		fxpp->fx_pri = pri;
		FX_ADJUST_PRI(fxpp->fx_pri);
		if (quantum == FX_TQDEF) {
			fxpp->fx_pquantum = fx_dptbl[fxpp->fx_pri].fx_quantum;
		} else if (quantum == FX_TQINF) {
			fxpp->fx_pquantum = FX_TQINF;
		} else if (quantum != FX_NOCHANGE) {
			FX_ADJUST_QUANTUM(quantum);
			fxpp->fx_pquantum = quantum;
		}
	} else if (quantum != FX_NOCHANGE && quantum != FX_TQDEF) {
		if (quantum == FX_TQINF)
			fxpp->fx_pquantum = FX_TQINF;
		else {
			FX_ADJUST_QUANTUM(quantum);
			fxpp->fx_pquantum = quantum;
		}
	}

	fxpp->fx_ktid = ddi_get_kt_did();

	fx_change_priority(curthread, fxpp);

	thread_unlock(curthread);

	/*
	 * Link new structure into fxproc list.
	 */
	FX_CB_LIST_INSERT(fxpp);
	return (0);
}

/* unregister a callback set of routines for current thread */
int
fx_unregister_callbacks()
{
	fxproc_t	*fxpp;

	if ((fxpp = fx_list_lookup(ddi_get_kt_did())) == NULL) {
		/*
		 * did not have a registered callback;
		 */
		return (EINVAL);
	}

	thread_lock(fxpp->fx_tp);
	fxpp->fx_callback = NULL;
	fxpp->fx_cookie = NULL;
	thread_unlock(fxpp->fx_tp);
	fx_list_release(fxpp);

	FX_CB_LIST_DELETE(fxpp);
	return (0);
}

/*
 * modify priority and/or quantum value of a thread with callback
 */
int
fx_modify_priority(kt_did_t ktid, clock_t quantum, pri_t pri)
{
	fxproc_t	*fxpp;

	if (!FX_ISVALID(pri, quantum))
		return (EINVAL);

	if ((fxpp = fx_list_lookup(ktid)) == NULL) {
		/*
		 * either thread had exited or did not have a registered
		 * callback;
		 */
		return (ESRCH);
	}

	thread_lock(fxpp->fx_tp);

	if (pri != FX_CB_NOCHANGE) {
		fxpp->fx_pri = pri;
		FX_ADJUST_PRI(fxpp->fx_pri);
		if (quantum == FX_TQDEF) {
			fxpp->fx_pquantum = fx_dptbl[fxpp->fx_pri].fx_quantum;
		} else if (quantum == FX_TQINF) {
			fxpp->fx_pquantum = FX_TQINF;
		} else if (quantum != FX_NOCHANGE) {
			FX_ADJUST_QUANTUM(quantum);
			fxpp->fx_pquantum = quantum;
		}
	} else if (quantum != FX_NOCHANGE && quantum != FX_TQDEF) {
		if (quantum == FX_TQINF) {
			fxpp->fx_pquantum = FX_TQINF;
		} else {
			FX_ADJUST_QUANTUM(quantum);
			fxpp->fx_pquantum = quantum;
		}
	}

	fx_change_priority(fxpp->fx_tp, fxpp);

	thread_unlock(fxpp->fx_tp);
	fx_list_release(fxpp);
	return (0);
}


/*
 * return an iblock cookie for mutex initialization to be used in callbacks
 */
void *
fx_get_mutex_cookie()
{
	return ((void *)(uintptr_t)__ipltospl(DISP_LEVEL));
}

/*
 * return maximum relative priority
 */
pri_t
fx_get_maxpri()
{
	return (fx_maxumdpri);
}
