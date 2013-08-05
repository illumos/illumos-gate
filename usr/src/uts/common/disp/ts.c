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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/session.h>
#include <sys/strsubr.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/priocntl.h>
#include <sys/class.h>
#include <sys/disp.h>
#include <sys/procset.h>
#include <sys/debug.h>
#include <sys/ts.h>
#include <sys/tspriocntl.h>
#include <sys/iapriocntl.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>		/* for lbolt */
#include <sys/vtrace.h>
#include <sys/vmsystm.h>
#include <sys/schedctl.h>
#include <sys/tnf_probe.h>
#include <sys/atomic.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/cpupart.h>
#include <vm/rm.h>
#include <vm/seg_kmem.h>
#include <sys/modctl.h>
#include <sys/cpucaps.h>

static pri_t ts_init(id_t, int, classfuncs_t **);

static struct sclass csw = {
	"TS",
	ts_init,
	0
};

static struct modlsched modlsched = {
	&mod_schedops, "time sharing sched class", &csw
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
	return (EBUSY);		/* don't remove TS for now */
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Class specific code for the time-sharing class
 */


/*
 * Extern declarations for variables defined in the ts master file
 */
#define	TSMAXUPRI 60

pri_t	ts_maxupri = TSMAXUPRI;	/* max time-sharing user priority */
pri_t	ts_maxumdpri;		/* maximum user mode ts priority */

pri_t	ia_maxupri = IAMAXUPRI;	/* max interactive user priority */
pri_t	ia_boost = IA_BOOST;	/* boost value for interactive */

tsdpent_t  *ts_dptbl;	/* time-sharing disp parameter table */
pri_t	*ts_kmdpris;	/* array of global pris used by ts procs when */
			/*  sleeping or running in kernel after sleep */

static id_t ia_cid;

int ts_sleep_promote = 1;

#define	tsmedumdpri	(ts_maxumdpri >> 1)

#define	TS_NEWUMDPRI(tspp) \
{ \
	pri_t pri; \
	pri = (tspp)->ts_cpupri + (tspp)->ts_upri + (tspp)->ts_boost; \
	if (pri > ts_maxumdpri) \
		(tspp)->ts_umdpri = ts_maxumdpri; \
	else if (pri < 0) \
		(tspp)->ts_umdpri = 0; \
	else \
		(tspp)->ts_umdpri = pri; \
	ASSERT((tspp)->ts_umdpri >= 0 && (tspp)->ts_umdpri <= ts_maxumdpri); \
}

/*
 * The tsproc_t structures are kept in an array of circular doubly linked
 * lists.  A hash on the thread pointer is used to determine which list
 * each thread should be placed.  Each list has a dummy "head" which is
 * never removed, so the list is never empty.  ts_update traverses these
 * lists to update the priorities of threads that have been waiting on
 * the run queue.
 */

#define	TS_LISTS 16		/* number of lists, must be power of 2 */

/* hash function, argument is a thread pointer */
#define	TS_LIST_HASH(tp)	(((uintptr_t)(tp) >> 9) & (TS_LISTS - 1))

/* iterate to the next list */
#define	TS_LIST_NEXT(i)		(((i) + 1) & (TS_LISTS - 1))

/*
 * Insert thread into the appropriate tsproc list.
 */
#define	TS_LIST_INSERT(tspp)				\
{							\
	int index = TS_LIST_HASH(tspp->ts_tp);		\
	kmutex_t *lockp = &ts_list_lock[index];		\
	tsproc_t *headp = &ts_plisthead[index];		\
	mutex_enter(lockp);				\
	tspp->ts_next = headp->ts_next;			\
	tspp->ts_prev = headp;				\
	headp->ts_next->ts_prev = tspp;			\
	headp->ts_next = tspp;				\
	mutex_exit(lockp);				\
}

/*
 * Remove thread from tsproc list.
 */
#define	TS_LIST_DELETE(tspp)				\
{							\
	int index = TS_LIST_HASH(tspp->ts_tp);		\
	kmutex_t *lockp = &ts_list_lock[index];		\
	mutex_enter(lockp);				\
	tspp->ts_prev->ts_next = tspp->ts_next;		\
	tspp->ts_next->ts_prev = tspp->ts_prev;		\
	mutex_exit(lockp);				\
}


static int	ts_admin(caddr_t, cred_t *);
static int	ts_enterclass(kthread_t *, id_t, void *, cred_t *, void *);
static int	ts_fork(kthread_t *, kthread_t *, void *);
static int	ts_getclinfo(void *);
static int	ts_getclpri(pcpri_t *);
static int	ts_parmsin(void *);
static int	ts_parmsout(void *, pc_vaparms_t *);
static int	ts_vaparmsin(void *, pc_vaparms_t *);
static int	ts_vaparmsout(void *, pc_vaparms_t *);
static int	ts_parmsset(kthread_t *, void *, id_t, cred_t *);
static void	ts_exit(kthread_t *);
static int	ts_donice(kthread_t *, cred_t *, int, int *);
static int	ts_doprio(kthread_t *, cred_t *, int, int *);
static void	ts_exitclass(void *);
static int	ts_canexit(kthread_t *, cred_t *);
static void	ts_forkret(kthread_t *, kthread_t *);
static void	ts_nullsys();
static void	ts_parmsget(kthread_t *, void *);
static void	ts_preempt(kthread_t *);
static void	ts_setrun(kthread_t *);
static void	ts_sleep(kthread_t *);
static pri_t	ts_swapin(kthread_t *, int);
static pri_t	ts_swapout(kthread_t *, int);
static void	ts_tick(kthread_t *);
static void	ts_trapret(kthread_t *);
static void	ts_update(void *);
static int	ts_update_list(int);
static void	ts_wakeup(kthread_t *);
static pri_t	ts_globpri(kthread_t *);
static void	ts_yield(kthread_t *);
extern tsdpent_t *ts_getdptbl(void);
extern pri_t	*ts_getkmdpris(void);
extern pri_t	td_getmaxumdpri(void);
static int	ts_alloc(void **, int);
static void	ts_free(void *);

pri_t		ia_init(id_t, int, classfuncs_t **);
static int	ia_getclinfo(void *);
static int	ia_getclpri(pcpri_t *);
static int	ia_parmsin(void *);
static int	ia_vaparmsin(void *, pc_vaparms_t *);
static int	ia_vaparmsout(void *, pc_vaparms_t *);
static int	ia_parmsset(kthread_t *, void *, id_t, cred_t *);
static void	ia_parmsget(kthread_t *, void *);
static void	ia_set_process_group(pid_t, pid_t, pid_t);

static void	ts_change_priority(kthread_t *, tsproc_t *);

extern pri_t	ts_maxkmdpri;	/* maximum kernel mode ts priority */
static pri_t	ts_maxglobpri;	/* maximum global priority used by ts class */
static kmutex_t	ts_dptblock;	/* protects time sharing dispatch table */
static kmutex_t	ts_list_lock[TS_LISTS];	/* protects tsproc lists */
static tsproc_t	ts_plisthead[TS_LISTS];	/* dummy tsproc at head of lists */

static gid_t	IA_gid = 0;

static struct classfuncs ts_classfuncs = {
	/* class functions */
	ts_admin,
	ts_getclinfo,
	ts_parmsin,
	ts_parmsout,
	ts_vaparmsin,
	ts_vaparmsout,
	ts_getclpri,
	ts_alloc,
	ts_free,

	/* thread functions */
	ts_enterclass,
	ts_exitclass,
	ts_canexit,
	ts_fork,
	ts_forkret,
	ts_parmsget,
	ts_parmsset,
	ts_nullsys,	/* stop */
	ts_exit,
	ts_nullsys,	/* active */
	ts_nullsys,	/* inactive */
	ts_swapin,
	ts_swapout,
	ts_trapret,
	ts_preempt,
	ts_setrun,
	ts_sleep,
	ts_tick,
	ts_wakeup,
	ts_donice,
	ts_globpri,
	ts_nullsys,	/* set_process_group */
	ts_yield,
	ts_doprio,
};

/*
 * ia_classfuncs is used for interactive class threads; IA threads are stored
 * on the same class list as TS threads, and most of the class functions are
 * identical, but a few have different enough functionality to require their
 * own functions.
 */
static struct classfuncs ia_classfuncs = {
	/* class functions */
	ts_admin,
	ia_getclinfo,
	ia_parmsin,
	ts_parmsout,
	ia_vaparmsin,
	ia_vaparmsout,
	ia_getclpri,
	ts_alloc,
	ts_free,

	/* thread functions */
	ts_enterclass,
	ts_exitclass,
	ts_canexit,
	ts_fork,
	ts_forkret,
	ia_parmsget,
	ia_parmsset,
	ts_nullsys,	/* stop */
	ts_exit,
	ts_nullsys,	/* active */
	ts_nullsys,	/* inactive */
	ts_swapin,
	ts_swapout,
	ts_trapret,
	ts_preempt,
	ts_setrun,
	ts_sleep,
	ts_tick,
	ts_wakeup,
	ts_donice,
	ts_globpri,
	ia_set_process_group,
	ts_yield,
	ts_doprio,
};


/*
 * Time sharing class initialization.  Called by dispinit() at boot time.
 * We can ignore the clparmsz argument since we know that the smallest
 * possible parameter buffer is big enough for us.
 */
/* ARGSUSED */
static pri_t
ts_init(id_t cid, int clparmsz, classfuncs_t **clfuncspp)
{
	int i;
	extern pri_t ts_getmaxumdpri(void);

	ts_dptbl = ts_getdptbl();
	ts_kmdpris = ts_getkmdpris();
	ts_maxumdpri = ts_getmaxumdpri();
	ts_maxglobpri = MAX(ts_kmdpris[0], ts_dptbl[ts_maxumdpri].ts_globpri);

	/*
	 * Initialize the tsproc lists.
	 */
	for (i = 0; i < TS_LISTS; i++) {
		ts_plisthead[i].ts_next = ts_plisthead[i].ts_prev =
		    &ts_plisthead[i];
	}

	/*
	 * We're required to return a pointer to our classfuncs
	 * structure and the highest global priority value we use.
	 */
	*clfuncspp = &ts_classfuncs;
	return (ts_maxglobpri);
}


/*
 * Interactive class scheduler initialization
 */
/* ARGSUSED */
pri_t
ia_init(id_t cid, int clparmsz, classfuncs_t **clfuncspp)
{
	/*
	 * We're required to return a pointer to our classfuncs
	 * structure and the highest global priority value we use.
	 */
	ia_cid = cid;
	*clfuncspp = &ia_classfuncs;
	return (ts_maxglobpri);
}


/*
 * Get or reset the ts_dptbl values per the user's request.
 */
static int
ts_admin(caddr_t uaddr, cred_t *reqpcredp)
{
	tsadmin_t	tsadmin;
	tsdpent_t	*tmpdpp;
	int		userdpsz;
	int		i;
	size_t		tsdpsz;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(uaddr, &tsadmin, sizeof (tsadmin_t)))
			return (EFAULT);
	}
#ifdef _SYSCALL32_IMPL
	else {
		/* get tsadmin struct from ILP32 caller */
		tsadmin32_t tsadmin32;
		if (copyin(uaddr, &tsadmin32, sizeof (tsadmin32_t)))
			return (EFAULT);
		tsadmin.ts_dpents =
		    (struct tsdpent *)(uintptr_t)tsadmin32.ts_dpents;
		tsadmin.ts_ndpents = tsadmin32.ts_ndpents;
		tsadmin.ts_cmd = tsadmin32.ts_cmd;
	}
#endif /* _SYSCALL32_IMPL */

	tsdpsz = (ts_maxumdpri + 1) * sizeof (tsdpent_t);

	switch (tsadmin.ts_cmd) {
	case TS_GETDPSIZE:
		tsadmin.ts_ndpents = ts_maxumdpri + 1;

		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&tsadmin, uaddr, sizeof (tsadmin_t)))
				return (EFAULT);
		}
#ifdef _SYSCALL32_IMPL
		else {
			/* return tsadmin struct to ILP32 caller */
			tsadmin32_t tsadmin32;
			tsadmin32.ts_dpents =
			    (caddr32_t)(uintptr_t)tsadmin.ts_dpents;
			tsadmin32.ts_ndpents = tsadmin.ts_ndpents;
			tsadmin32.ts_cmd = tsadmin.ts_cmd;
			if (copyout(&tsadmin32, uaddr, sizeof (tsadmin32_t)))
				return (EFAULT);
		}
#endif /* _SYSCALL32_IMPL */
		break;

	case TS_GETDPTBL:
		userdpsz = MIN(tsadmin.ts_ndpents * sizeof (tsdpent_t),
		    tsdpsz);
		if (copyout(ts_dptbl, tsadmin.ts_dpents, userdpsz))
			return (EFAULT);

		tsadmin.ts_ndpents = userdpsz / sizeof (tsdpent_t);

		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&tsadmin, uaddr, sizeof (tsadmin_t)))
				return (EFAULT);
		}
#ifdef _SYSCALL32_IMPL
		else {
			/* return tsadmin struct to ILP32 callers */
			tsadmin32_t tsadmin32;
			tsadmin32.ts_dpents =
			    (caddr32_t)(uintptr_t)tsadmin.ts_dpents;
			tsadmin32.ts_ndpents = tsadmin.ts_ndpents;
			tsadmin32.ts_cmd = tsadmin.ts_cmd;
			if (copyout(&tsadmin32, uaddr, sizeof (tsadmin32_t)))
				return (EFAULT);
		}
#endif /* _SYSCALL32_IMPL */
		break;

	case TS_SETDPTBL:
		/*
		 * We require that the requesting process has sufficient
		 * priveleges.  We also require that the table supplied by
		 * the user exactly match the current ts_dptbl in size.
		 */
		if (secpolicy_dispadm(reqpcredp) != 0)
			return (EPERM);

		if (tsadmin.ts_ndpents * sizeof (tsdpent_t) != tsdpsz) {
			return (EINVAL);
		}

		/*
		 * We read the user supplied table into a temporary buffer
		 * where it is validated before being copied over the
		 * ts_dptbl.
		 */
		tmpdpp = kmem_alloc(tsdpsz, KM_SLEEP);
		if (copyin((caddr_t)tsadmin.ts_dpents, (caddr_t)tmpdpp,
		    tsdpsz)) {
			kmem_free(tmpdpp, tsdpsz);
			return (EFAULT);
		}
		for (i = 0; i < tsadmin.ts_ndpents; i++) {

			/*
			 * Validate the user supplied values.  All we are doing
			 * here is verifying that the values are within their
			 * allowable ranges and will not panic the system.  We
			 * make no attempt to ensure that the resulting
			 * configuration makes sense or results in reasonable
			 * performance.
			 */
			if (tmpdpp[i].ts_quantum <= 0) {
				kmem_free(tmpdpp, tsdpsz);
				return (EINVAL);
			}
			if (tmpdpp[i].ts_tqexp > ts_maxumdpri ||
			    tmpdpp[i].ts_tqexp < 0) {
				kmem_free(tmpdpp, tsdpsz);
				return (EINVAL);
			}
			if (tmpdpp[i].ts_slpret > ts_maxumdpri ||
			    tmpdpp[i].ts_slpret < 0) {
				kmem_free(tmpdpp, tsdpsz);
				return (EINVAL);
			}
			if (tmpdpp[i].ts_maxwait < 0) {
				kmem_free(tmpdpp, tsdpsz);
				return (EINVAL);
			}
			if (tmpdpp[i].ts_lwait > ts_maxumdpri ||
			    tmpdpp[i].ts_lwait < 0) {
				kmem_free(tmpdpp, tsdpsz);
				return (EINVAL);
			}
		}

		/*
		 * Copy the user supplied values over the current ts_dptbl
		 * values.  The ts_globpri member is read-only so we don't
		 * overwrite it.
		 */
		mutex_enter(&ts_dptblock);
		for (i = 0; i < tsadmin.ts_ndpents; i++) {
			ts_dptbl[i].ts_quantum = tmpdpp[i].ts_quantum;
			ts_dptbl[i].ts_tqexp = tmpdpp[i].ts_tqexp;
			ts_dptbl[i].ts_slpret = tmpdpp[i].ts_slpret;
			ts_dptbl[i].ts_maxwait = tmpdpp[i].ts_maxwait;
			ts_dptbl[i].ts_lwait = tmpdpp[i].ts_lwait;
		}
		mutex_exit(&ts_dptblock);
		kmem_free(tmpdpp, tsdpsz);
		break;

	default:
		return (EINVAL);
	}
	return (0);
}


/*
 * Allocate a time-sharing class specific thread structure and
 * initialize it with the parameters supplied. Also move the thread
 * to specified time-sharing priority.
 */
static int
ts_enterclass(kthread_t *t, id_t cid, void *parmsp,
	cred_t *reqpcredp, void *bufp)
{
	tsparms_t	*tsparmsp = (tsparms_t *)parmsp;
	tsproc_t	*tspp;
	pri_t		reqtsuprilim;
	pri_t		reqtsupri;
	static uint32_t	tspexists = 0;	/* set on first occurrence of */
					/*   a time-sharing process */

	tspp = (tsproc_t *)bufp;
	ASSERT(tspp != NULL);

	/*
	 * Initialize the tsproc structure.
	 */
	tspp->ts_cpupri = tsmedumdpri;
	if (cid == ia_cid) {
		/*
		 * Check to make sure caller is either privileged or the
		 * window system.  When the window system is converted
		 * to using privileges, the second check can go away.
		 */
		if (reqpcredp != NULL && !groupmember(IA_gid, reqpcredp) &&
		    secpolicy_setpriority(reqpcredp) != 0)
			return (EPERM);
		/*
		 * Belongs to IA "class", so set appropriate flags.
		 * Mark as 'on' so it will not be a swap victim
		 * while forking.
		 */
		tspp->ts_flags = TSIA | TSIASET;
		tspp->ts_boost = ia_boost;
	} else {
		tspp->ts_flags = 0;
		tspp->ts_boost = 0;
	}

	if (tsparmsp == NULL) {
		/*
		 * Use default values.
		 */
		tspp->ts_uprilim = tspp->ts_upri = 0;
		tspp->ts_nice = NZERO;
	} else {
		/*
		 * Use supplied values.
		 */
		if (tsparmsp->ts_uprilim == TS_NOCHANGE)
			reqtsuprilim = 0;
		else {
			if (tsparmsp->ts_uprilim > 0 &&
			    secpolicy_setpriority(reqpcredp) != 0)
				return (EPERM);
			reqtsuprilim = tsparmsp->ts_uprilim;
		}

		if (tsparmsp->ts_upri == TS_NOCHANGE) {
			reqtsupri = reqtsuprilim;
		} else {
			if (tsparmsp->ts_upri > 0 &&
			    secpolicy_setpriority(reqpcredp) != 0)
				return (EPERM);
			/*
			 * Set the user priority to the requested value
			 * or the upri limit, whichever is lower.
			 */
			reqtsupri = tsparmsp->ts_upri;
			if (reqtsupri > reqtsuprilim)
				reqtsupri = reqtsuprilim;
		}


		tspp->ts_uprilim = reqtsuprilim;
		tspp->ts_upri = reqtsupri;
		tspp->ts_nice = NZERO - (NZERO * reqtsupri) / ts_maxupri;
	}
	TS_NEWUMDPRI(tspp);

	tspp->ts_dispwait = 0;
	tspp->ts_timeleft = ts_dptbl[tspp->ts_cpupri].ts_quantum;
	tspp->ts_tp = t;
	cpucaps_sc_init(&tspp->ts_caps);

	/*
	 * Reset priority. Process goes to a "user mode" priority
	 * here regardless of whether or not it has slept since
	 * entering the kernel.
	 */
	thread_lock(t);			/* get dispatcher lock on thread */
	t->t_clfuncs = &(sclass[cid].cl_funcs->thread);
	t->t_cid = cid;
	t->t_cldata = (void *)tspp;
	t->t_schedflag &= ~TS_RUNQMATCH;
	ts_change_priority(t, tspp);
	thread_unlock(t);

	/*
	 * Link new structure into tsproc list.
	 */
	TS_LIST_INSERT(tspp);

	/*
	 * If this is the first time-sharing thread to occur since
	 * boot we set up the initial call to ts_update() here.
	 * Use an atomic compare-and-swap since that's easier and
	 * faster than a mutex (but check with an ordinary load first
	 * since most of the time this will already be done).
	 */
	if (tspexists == 0 && cas32(&tspexists, 0, 1) == 0)
		(void) timeout(ts_update, NULL, hz);

	return (0);
}


/*
 * Free tsproc structure of thread.
 */
static void
ts_exitclass(void *procp)
{
	tsproc_t *tspp = (tsproc_t *)procp;

	/* Remove tsproc_t structure from list */
	TS_LIST_DELETE(tspp);
	kmem_free(tspp, sizeof (tsproc_t));
}

/* ARGSUSED */
static int
ts_canexit(kthread_t *t, cred_t *cred)
{
	/*
	 * A thread can always leave a TS/IA class
	 */
	return (0);
}

static int
ts_fork(kthread_t *t, kthread_t *ct, void *bufp)
{
	tsproc_t	*ptspp;		/* ptr to parent's tsproc structure */
	tsproc_t	*ctspp;		/* ptr to child's tsproc structure */

	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	ctspp = (tsproc_t *)bufp;
	ASSERT(ctspp != NULL);
	ptspp = (tsproc_t *)t->t_cldata;
	/*
	 * Initialize child's tsproc structure.
	 */
	thread_lock(t);
	ctspp->ts_timeleft = ts_dptbl[ptspp->ts_cpupri].ts_quantum;
	ctspp->ts_cpupri = ptspp->ts_cpupri;
	ctspp->ts_boost = ptspp->ts_boost;
	ctspp->ts_uprilim = ptspp->ts_uprilim;
	ctspp->ts_upri = ptspp->ts_upri;
	TS_NEWUMDPRI(ctspp);
	ctspp->ts_nice = ptspp->ts_nice;
	ctspp->ts_dispwait = 0;
	ctspp->ts_flags = ptspp->ts_flags & ~(TSKPRI | TSBACKQ | TSRESTORE);
	ctspp->ts_tp = ct;
	cpucaps_sc_init(&ctspp->ts_caps);
	thread_unlock(t);

	/*
	 * Link new structure into tsproc list.
	 */
	ct->t_cldata = (void *)ctspp;
	TS_LIST_INSERT(ctspp);
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
ts_forkret(kthread_t *t, kthread_t *ct)
{
	proc_t	*pp = ttoproc(t);
	proc_t	*cp = ttoproc(ct);
	tsproc_t *tspp;

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
	tspp = (tsproc_t *)(t->t_cldata);
	tspp->ts_cpupri = ts_dptbl[tspp->ts_cpupri].ts_tqexp;
	TS_NEWUMDPRI(tspp);
	tspp->ts_timeleft = ts_dptbl[tspp->ts_cpupri].ts_quantum;
	tspp->ts_dispwait = 0;
	t->t_pri = ts_dptbl[tspp->ts_umdpri].ts_globpri;
	ASSERT(t->t_pri >= 0 && t->t_pri <= ts_maxglobpri);
	tspp->ts_flags &= ~TSKPRI;
	THREAD_TRANSITION(t);
	ts_setrun(t);
	thread_unlock(t);
	/*
	 * Safe to drop p_lock now since since it is safe to change
	 * the scheduling class after this point.
	 */
	mutex_exit(&pp->p_lock);

	swtch();
}


/*
 * Get information about the time-sharing class into the buffer
 * pointed to by tsinfop. The maximum configured user priority
 * is the only information we supply.  ts_getclinfo() is called
 * for TS threads, and ia_getclinfo() is called for IA threads.
 */
static int
ts_getclinfo(void *infop)
{
	tsinfo_t *tsinfop = (tsinfo_t *)infop;
	tsinfop->ts_maxupri = ts_maxupri;
	return (0);
}

static int
ia_getclinfo(void *infop)
{
	iainfo_t *iainfop = (iainfo_t *)infop;
	iainfop->ia_maxupri = ia_maxupri;
	return (0);
}


/*
 * Return the user mode scheduling priority range.
 */
static int
ts_getclpri(pcpri_t *pcprip)
{
	pcprip->pc_clpmax = ts_maxupri;
	pcprip->pc_clpmin = -ts_maxupri;
	return (0);
}


static int
ia_getclpri(pcpri_t *pcprip)
{
	pcprip->pc_clpmax = ia_maxupri;
	pcprip->pc_clpmin = -ia_maxupri;
	return (0);
}


static void
ts_nullsys()
{}


/*
 * Get the time-sharing parameters of the thread pointed to by
 * tsprocp into the buffer pointed to by tsparmsp.  ts_parmsget()
 * is called for TS threads, and ia_parmsget() is called for IA
 * threads.
 */
static void
ts_parmsget(kthread_t *t, void *parmsp)
{
	tsproc_t *tspp = (tsproc_t *)t->t_cldata;
	tsparms_t *tsparmsp = (tsparms_t *)parmsp;

	tsparmsp->ts_uprilim = tspp->ts_uprilim;
	tsparmsp->ts_upri = tspp->ts_upri;
}

static void
ia_parmsget(kthread_t *t, void *parmsp)
{
	tsproc_t *tspp = (tsproc_t *)t->t_cldata;
	iaparms_t *iaparmsp = (iaparms_t *)parmsp;

	iaparmsp->ia_uprilim = tspp->ts_uprilim;
	iaparmsp->ia_upri = tspp->ts_upri;
	if (tspp->ts_flags & TSIASET)
		iaparmsp->ia_mode = IA_SET_INTERACTIVE;
	else
		iaparmsp->ia_mode = IA_INTERACTIVE_OFF;
}


/*
 * Check the validity of the time-sharing parameters in the buffer
 * pointed to by tsparmsp.
 * ts_parmsin() is called for TS threads, and ia_parmsin() is called
 * for IA threads.
 */
static int
ts_parmsin(void *parmsp)
{
	tsparms_t	*tsparmsp = (tsparms_t *)parmsp;
	/*
	 * Check validity of parameters.
	 */
	if ((tsparmsp->ts_uprilim > ts_maxupri ||
	    tsparmsp->ts_uprilim < -ts_maxupri) &&
	    tsparmsp->ts_uprilim != TS_NOCHANGE)
		return (EINVAL);

	if ((tsparmsp->ts_upri > ts_maxupri ||
	    tsparmsp->ts_upri < -ts_maxupri) &&
	    tsparmsp->ts_upri != TS_NOCHANGE)
		return (EINVAL);

	return (0);
}

static int
ia_parmsin(void *parmsp)
{
	iaparms_t	*iaparmsp = (iaparms_t *)parmsp;

	if ((iaparmsp->ia_uprilim > ia_maxupri ||
	    iaparmsp->ia_uprilim < -ia_maxupri) &&
	    iaparmsp->ia_uprilim != IA_NOCHANGE) {
		return (EINVAL);
	}

	if ((iaparmsp->ia_upri > ia_maxupri ||
	    iaparmsp->ia_upri < -ia_maxupri) &&
	    iaparmsp->ia_upri != IA_NOCHANGE) {
		return (EINVAL);
	}

	return (0);
}


/*
 * Check the validity of the time-sharing parameters in the pc_vaparms_t
 * structure vaparmsp and put them in the buffer pointed to by tsparmsp.
 * pc_vaparms_t contains (key, value) pairs of parameter.
 * ts_vaparmsin() is called for TS threads, and ia_vaparmsin() is called
 * for IA threads. ts_vaparmsin() is the variable parameter version of
 * ts_parmsin() and ia_vaparmsin() is the variable parameter version of
 * ia_parmsin().
 */
static int
ts_vaparmsin(void *parmsp, pc_vaparms_t *vaparmsp)
{
	tsparms_t	*tsparmsp = (tsparms_t *)parmsp;
	int		priflag = 0;
	int		limflag = 0;
	uint_t		cnt;
	pc_vaparm_t	*vpp = &vaparmsp->pc_parms[0];


	/*
	 * TS_NOCHANGE (-32768) is outside of the range of values for
	 * ts_uprilim and ts_upri. If the structure tsparms_t is changed,
	 * TS_NOCHANGE should be replaced by a flag word (in the same manner
	 * as in rt.c).
	 */
	tsparmsp->ts_uprilim = TS_NOCHANGE;
	tsparmsp->ts_upri = TS_NOCHANGE;

	/*
	 * Get the varargs parameter and check validity of parameters.
	 */
	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {

		switch (vpp->pc_key) {
		case TS_KY_UPRILIM:
			if (limflag++)
				return (EINVAL);
			tsparmsp->ts_uprilim = (pri_t)vpp->pc_parm;
			if (tsparmsp->ts_uprilim > ts_maxupri ||
			    tsparmsp->ts_uprilim < -ts_maxupri)
				return (EINVAL);
			break;

		case TS_KY_UPRI:
			if (priflag++)
				return (EINVAL);
			tsparmsp->ts_upri = (pri_t)vpp->pc_parm;
			if (tsparmsp->ts_upri > ts_maxupri ||
			    tsparmsp->ts_upri < -ts_maxupri)
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
		tsparmsp->ts_upri = tsparmsp->ts_uprilim = 0;
	}

	return (0);
}

static int
ia_vaparmsin(void *parmsp, pc_vaparms_t *vaparmsp)
{
	iaparms_t	*iaparmsp = (iaparms_t *)parmsp;
	int		priflag = 0;
	int		limflag = 0;
	int		mflag = 0;
	uint_t		cnt;
	pc_vaparm_t	*vpp = &vaparmsp->pc_parms[0];

	/*
	 * IA_NOCHANGE (-32768) is outside of the range of values for
	 * ia_uprilim, ia_upri and ia_mode. If the structure iaparms_t is
	 * changed, IA_NOCHANGE should be replaced by a flag word (in the
	 * same manner as in rt.c).
	 */
	iaparmsp->ia_uprilim = IA_NOCHANGE;
	iaparmsp->ia_upri = IA_NOCHANGE;
	iaparmsp->ia_mode = IA_NOCHANGE;

	/*
	 * Get the varargs parameter and check validity of parameters.
	 */
	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {

		switch (vpp->pc_key) {
		case IA_KY_UPRILIM:
			if (limflag++)
				return (EINVAL);
			iaparmsp->ia_uprilim = (pri_t)vpp->pc_parm;
			if (iaparmsp->ia_uprilim > ia_maxupri ||
			    iaparmsp->ia_uprilim < -ia_maxupri)
				return (EINVAL);
			break;

		case IA_KY_UPRI:
			if (priflag++)
				return (EINVAL);
			iaparmsp->ia_upri = (pri_t)vpp->pc_parm;
			if (iaparmsp->ia_upri > ia_maxupri ||
			    iaparmsp->ia_upri < -ia_maxupri)
				return (EINVAL);
			break;

		case IA_KY_MODE:
			if (mflag++)
				return (EINVAL);
			iaparmsp->ia_mode = (int)vpp->pc_parm;
			if (iaparmsp->ia_mode != IA_SET_INTERACTIVE &&
			    iaparmsp->ia_mode != IA_INTERACTIVE_OFF)
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
		iaparmsp->ia_upri = iaparmsp->ia_uprilim = 0;
		iaparmsp->ia_mode = IA_SET_INTERACTIVE;
	}

	return (0);
}

/*
 * Nothing to do here but return success.
 */
/* ARGSUSED */
static int
ts_parmsout(void *parmsp, pc_vaparms_t *vaparmsp)
{
	return (0);
}


/*
 * Copy all selected time-sharing class parameters to the user.
 * The parameters are specified by a key.
 */
static int
ts_vaparmsout(void *prmsp, pc_vaparms_t *vaparmsp)
{
	tsparms_t	*tsprmsp = (tsparms_t *)prmsp;
	int		priflag = 0;
	int		limflag = 0;
	uint_t		cnt;
	pc_vaparm_t	*vpp = &vaparmsp->pc_parms[0];

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {

		switch (vpp->pc_key) {
		case TS_KY_UPRILIM:
			if (limflag++)
				return (EINVAL);
			if (copyout(&tsprmsp->ts_uprilim,
			    (caddr_t)(uintptr_t)vpp->pc_parm, sizeof (pri_t)))
				return (EFAULT);
			break;

		case TS_KY_UPRI:
			if (priflag++)
				return (EINVAL);
			if (copyout(&tsprmsp->ts_upri,
			    (caddr_t)(uintptr_t)vpp->pc_parm, sizeof (pri_t)))
				return (EFAULT);
			break;

		default:
			return (EINVAL);
		}
	}

	return (0);
}


/*
 * Copy all selected interactive class parameters to the user.
 * The parameters are specified by a key.
 */
static int
ia_vaparmsout(void *prmsp, pc_vaparms_t *vaparmsp)
{
	iaparms_t	*iaprmsp = (iaparms_t *)prmsp;
	int		priflag = 0;
	int		limflag = 0;
	int		mflag = 0;
	uint_t		cnt;
	pc_vaparm_t	*vpp = &vaparmsp->pc_parms[0];

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	if (vaparmsp->pc_vaparmscnt > PC_VAPARMCNT)
		return (EINVAL);

	for (cnt = 0; cnt < vaparmsp->pc_vaparmscnt; cnt++, vpp++) {

		switch (vpp->pc_key) {
		case IA_KY_UPRILIM:
			if (limflag++)
				return (EINVAL);
			if (copyout(&iaprmsp->ia_uprilim,
			    (caddr_t)(uintptr_t)vpp->pc_parm, sizeof (pri_t)))
				return (EFAULT);
			break;

		case IA_KY_UPRI:
			if (priflag++)
				return (EINVAL);
			if (copyout(&iaprmsp->ia_upri,
			    (caddr_t)(uintptr_t)vpp->pc_parm, sizeof (pri_t)))
				return (EFAULT);
			break;

		case IA_KY_MODE:
			if (mflag++)
				return (EINVAL);
			if (copyout(&iaprmsp->ia_mode,
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
 * Set the scheduling parameters of the thread pointed to by tsprocp
 * to those specified in the buffer pointed to by tsparmsp.
 * ts_parmsset() is called for TS threads, and ia_parmsset() is
 * called for IA threads.
 */
/* ARGSUSED */
static int
ts_parmsset(kthread_t *tx, void *parmsp, id_t reqpcid, cred_t *reqpcredp)
{
	char		nice;
	pri_t		reqtsuprilim;
	pri_t		reqtsupri;
	tsparms_t	*tsparmsp = (tsparms_t *)parmsp;
	tsproc_t	*tspp = (tsproc_t *)tx->t_cldata;

	ASSERT(MUTEX_HELD(&(ttoproc(tx))->p_lock));

	if (tsparmsp->ts_uprilim == TS_NOCHANGE)
		reqtsuprilim = tspp->ts_uprilim;
	else
		reqtsuprilim = tsparmsp->ts_uprilim;

	if (tsparmsp->ts_upri == TS_NOCHANGE)
		reqtsupri = tspp->ts_upri;
	else
		reqtsupri = tsparmsp->ts_upri;

	/*
	 * Make sure the user priority doesn't exceed the upri limit.
	 */
	if (reqtsupri > reqtsuprilim)
		reqtsupri = reqtsuprilim;

	/*
	 * Basic permissions enforced by generic kernel code
	 * for all classes require that a thread attempting
	 * to change the scheduling parameters of a target
	 * thread be privileged or have a real or effective
	 * UID matching that of the target thread. We are not
	 * called unless these basic permission checks have
	 * already passed. The time-sharing class requires in
	 * addition that the calling thread be privileged if it
	 * is attempting to raise the upri limit above its current
	 * value This may have been checked previously but if our
	 * caller passed us a non-NULL credential pointer we assume
	 * it hasn't and we check it here.
	 */
	if (reqpcredp != NULL &&
	    reqtsuprilim > tspp->ts_uprilim &&
	    secpolicy_raisepriority(reqpcredp) != 0)
		return (EPERM);

	/*
	 * Set ts_nice to the nice value corresponding to the user
	 * priority we are setting.  Note that setting the nice field
	 * of the parameter struct won't affect upri or nice.
	 */
	nice = NZERO - (reqtsupri * NZERO) / ts_maxupri;
	if (nice >= 2 * NZERO)
		nice = 2 * NZERO - 1;

	thread_lock(tx);

	tspp->ts_uprilim = reqtsuprilim;
	tspp->ts_upri = reqtsupri;
	TS_NEWUMDPRI(tspp);
	tspp->ts_nice = nice;

	if ((tspp->ts_flags & TSKPRI) != 0) {
		thread_unlock(tx);
		return (0);
	}

	tspp->ts_dispwait = 0;
	ts_change_priority(tx, tspp);
	thread_unlock(tx);
	return (0);
}


static int
ia_parmsset(kthread_t *tx, void *parmsp, id_t reqpcid, cred_t *reqpcredp)
{
	tsproc_t	*tspp = (tsproc_t *)tx->t_cldata;
	iaparms_t	*iaparmsp = (iaparms_t *)parmsp;
	proc_t		*p;
	pid_t		pid, pgid, sid;
	pid_t		on, off;
	struct stdata 	*stp;
	int		sess_held;

	/*
	 * Handle user priority changes
	 */
	if (iaparmsp->ia_mode == IA_NOCHANGE)
		return (ts_parmsset(tx, parmsp, reqpcid, reqpcredp));

	/*
	 * Check permissions for changing modes.
	 */

	if (reqpcredp != NULL && !groupmember(IA_gid, reqpcredp) &&
	    secpolicy_raisepriority(reqpcredp) != 0) {
		/*
		 * Silently fail in case this is just a priocntl
		 * call with upri and uprilim set to IA_NOCHANGE.
		 */
		return (0);
	}

	ASSERT(MUTEX_HELD(&pidlock));
	if ((p = ttoproc(tx)) == NULL) {
		return (0);
	}
	ASSERT(MUTEX_HELD(&p->p_lock));
	if (p->p_stat == SIDL) {
		return (0);
	}
	pid = p->p_pid;
	sid = p->p_sessp->s_sid;
	pgid = p->p_pgrp;
	if (iaparmsp->ia_mode == IA_SET_INTERACTIVE) {
		/*
		 * session leaders must be turned on now so all processes
		 * in the group controlling the tty will be turned on or off.
		 * if the ia_mode is off for the session leader,
		 * ia_set_process_group will return without setting the
		 * processes in the group controlling the tty on.
		 */
		thread_lock(tx);
		tspp->ts_flags |= TSIASET;
		thread_unlock(tx);
	}
	mutex_enter(&p->p_sessp->s_lock);
	sess_held = 1;
	if ((pid == sid) && (p->p_sessp->s_vp != NULL) &&
	    ((stp = p->p_sessp->s_vp->v_stream) != NULL)) {
		if ((stp->sd_pgidp != NULL) && (stp->sd_sidp != NULL)) {
			pgid = stp->sd_pgidp->pid_id;
			sess_held = 0;
			mutex_exit(&p->p_sessp->s_lock);
			if (iaparmsp->ia_mode ==
			    IA_SET_INTERACTIVE) {
				off = 0;
				on = pgid;
			} else {
				off = pgid;
				on = 0;
			}
			TRACE_3(TR_FAC_IA, TR_ACTIVE_CHAIN,
			    "active chain:pid %d gid %d %p",
			    pid, pgid, p);
			ia_set_process_group(sid, off, on);
		}
	}
	if (sess_held)
		mutex_exit(&p->p_sessp->s_lock);

	thread_lock(tx);

	if (iaparmsp->ia_mode == IA_SET_INTERACTIVE) {
		tspp->ts_flags |= TSIASET;
		tspp->ts_boost = ia_boost;
	} else {
		tspp->ts_flags &= ~TSIASET;
		tspp->ts_boost = -ia_boost;
	}
	thread_unlock(tx);

	return (ts_parmsset(tx, parmsp, reqpcid, reqpcredp));
}

static void
ts_exit(kthread_t *t)
{
	tsproc_t *tspp;

	if (CPUCAPS_ON()) {
		/*
		 * A thread could be exiting in between clock ticks,
		 * so we need to calculate how much CPU time it used
		 * since it was charged last time.
		 *
		 * CPU caps are not enforced on exiting processes - it is
		 * usually desirable to exit as soon as possible to free
		 * resources.
		 */
		thread_lock(t);
		tspp = (tsproc_t *)t->t_cldata;
		(void) cpucaps_charge(t, &tspp->ts_caps, CPUCAPS_CHARGE_ONLY);
		thread_unlock(t);
	}
}

/*
 * Return the global scheduling priority that would be assigned
 * to a thread entering the time-sharing class with the ts_upri.
 */
static pri_t
ts_globpri(kthread_t *t)
{
	tsproc_t *tspp;
	pri_t	tspri;

	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));
	tspp = (tsproc_t *)t->t_cldata;
	tspri = tsmedumdpri + tspp->ts_upri;
	if (tspri > ts_maxumdpri)
		tspri = ts_maxumdpri;
	else if (tspri < 0)
		tspri = 0;
	return (ts_dptbl[tspri].ts_globpri);
}

/*
 * Arrange for thread to be placed in appropriate location
 * on dispatcher queue.
 *
 * This is called with the current thread in TS_ONPROC and locked.
 */
static void
ts_preempt(kthread_t *t)
{
	tsproc_t	*tspp = (tsproc_t *)(t->t_cldata);
	klwp_t		*lwp = curthread->t_lwp;
	pri_t		oldpri = t->t_pri;

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(curthread));

	/*
	 * If preempted in the kernel, make sure the thread has
	 * a kernel priority if needed.
	 */
	if (!(tspp->ts_flags & TSKPRI) && lwp != NULL && t->t_kpri_req) {
		tspp->ts_flags |= TSKPRI;
		THREAD_CHANGE_PRI(t, ts_kmdpris[0]);
		ASSERT(t->t_pri >= 0 && t->t_pri <= ts_maxglobpri);
		t->t_trapret = 1;		/* so ts_trapret will run */
		aston(t);
	}

	/*
	 * This thread may be placed on wait queue by CPU Caps. In this case we
	 * do not need to do anything until it is removed from the wait queue.
	 * Do not enforce CPU caps on threads running at a kernel priority
	 */
	if (CPUCAPS_ON()) {
		(void) cpucaps_charge(t, &tspp->ts_caps,
		    CPUCAPS_CHARGE_ENFORCE);
		if (!(tspp->ts_flags & TSKPRI) && CPUCAPS_ENFORCE(t))
			return;
	}

	/*
	 * If thread got preempted in the user-land then we know
	 * it isn't holding any locks.  Mark it as swappable.
	 */
	ASSERT(t->t_schedflag & TS_DONT_SWAP);
	if (lwp != NULL && lwp->lwp_state == LWP_USER)
		t->t_schedflag &= ~TS_DONT_SWAP;

	/*
	 * Check to see if we're doing "preemption control" here.  If
	 * we are, and if the user has requested that this thread not
	 * be preempted, and if preemptions haven't been put off for
	 * too long, let the preemption happen here but try to make
	 * sure the thread is rescheduled as soon as possible.  We do
	 * this by putting it on the front of the highest priority run
	 * queue in the TS class.  If the preemption has been put off
	 * for too long, clear the "nopreempt" bit and let the thread
	 * be preempted.
	 */
	if (t->t_schedctl && schedctl_get_nopreempt(t)) {
		if (tspp->ts_timeleft > -SC_MAX_TICKS) {
			DTRACE_SCHED1(schedctl__nopreempt, kthread_t *, t);
			if (!(tspp->ts_flags & TSKPRI)) {
				/*
				 * If not already remembered, remember current
				 * priority for restoration in ts_yield().
				 */
				if (!(tspp->ts_flags & TSRESTORE)) {
					tspp->ts_scpri = t->t_pri;
					tspp->ts_flags |= TSRESTORE;
				}
				THREAD_CHANGE_PRI(t, ts_maxumdpri);
				t->t_schedflag |= TS_DONT_SWAP;
			}
			schedctl_set_yield(t, 1);
			setfrontdq(t);
			goto done;
		} else {
			if (tspp->ts_flags & TSRESTORE) {
				THREAD_CHANGE_PRI(t, tspp->ts_scpri);
				tspp->ts_flags &= ~TSRESTORE;
			}
			schedctl_set_nopreempt(t, 0);
			DTRACE_SCHED1(schedctl__preempt, kthread_t *, t);
			TNF_PROBE_2(schedctl_preempt, "schedctl TS ts_preempt",
			    /* CSTYLED */, tnf_pid, pid, ttoproc(t)->p_pid,
			    tnf_lwpid, lwpid, t->t_tid);
			/*
			 * Fall through and be preempted below.
			 */
		}
	}

	if ((tspp->ts_flags & (TSBACKQ|TSKPRI)) == TSBACKQ) {
		tspp->ts_timeleft = ts_dptbl[tspp->ts_cpupri].ts_quantum;
		tspp->ts_dispwait = 0;
		tspp->ts_flags &= ~TSBACKQ;
		setbackdq(t);
	} else if ((tspp->ts_flags & (TSBACKQ|TSKPRI)) == (TSBACKQ|TSKPRI)) {
		tspp->ts_flags &= ~TSBACKQ;
		setbackdq(t);
	} else {
		setfrontdq(t);
	}

done:
	TRACE_2(TR_FAC_DISP, TR_PREEMPT,
	    "preempt:tid %p old pri %d", t, oldpri);
}

static void
ts_setrun(kthread_t *t)
{
	tsproc_t *tspp = (tsproc_t *)(t->t_cldata);

	ASSERT(THREAD_LOCK_HELD(t));	/* t should be in transition */

	if (tspp->ts_dispwait > ts_dptbl[tspp->ts_umdpri].ts_maxwait) {
		tspp->ts_cpupri = ts_dptbl[tspp->ts_cpupri].ts_slpret;
		TS_NEWUMDPRI(tspp);
		tspp->ts_timeleft = ts_dptbl[tspp->ts_cpupri].ts_quantum;
		tspp->ts_dispwait = 0;
		if ((tspp->ts_flags & TSKPRI) == 0) {
			THREAD_CHANGE_PRI(t,
			    ts_dptbl[tspp->ts_umdpri].ts_globpri);
			ASSERT(t->t_pri >= 0 && t->t_pri <= ts_maxglobpri);
		}
	}

	tspp->ts_flags &= ~TSBACKQ;

	if (tspp->ts_flags & TSIA) {
		if (tspp->ts_flags & TSIASET)
			setfrontdq(t);
		else
			setbackdq(t);
	} else {
		if (t->t_disp_time != ddi_get_lbolt())
			setbackdq(t);
		else
			setfrontdq(t);
	}
}


/*
 * Prepare thread for sleep. We reset the thread priority so it will
 * run at the kernel priority level when it wakes up.
 */
static void
ts_sleep(kthread_t *t)
{
	tsproc_t	*tspp = (tsproc_t *)(t->t_cldata);
	int		flags;
	pri_t		old_pri = t->t_pri;

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(t));

	/*
	 * Account for time spent on CPU before going to sleep.
	 */
	(void) CPUCAPS_CHARGE(t, &tspp->ts_caps, CPUCAPS_CHARGE_ENFORCE);

	flags = tspp->ts_flags;
	if (t->t_kpri_req) {
		tspp->ts_flags = flags | TSKPRI;
		THREAD_CHANGE_PRI(t, ts_kmdpris[0]);
		ASSERT(t->t_pri >= 0 && t->t_pri <= ts_maxglobpri);
		t->t_trapret = 1;		/* so ts_trapret will run */
		aston(t);
	} else if (tspp->ts_dispwait > ts_dptbl[tspp->ts_umdpri].ts_maxwait) {
		/*
		 * If thread has blocked in the kernel (as opposed to
		 * being merely preempted), recompute the user mode priority.
		 */
		tspp->ts_cpupri = ts_dptbl[tspp->ts_cpupri].ts_slpret;
		TS_NEWUMDPRI(tspp);
		tspp->ts_timeleft = ts_dptbl[tspp->ts_cpupri].ts_quantum;
		tspp->ts_dispwait = 0;

		THREAD_CHANGE_PRI(curthread,
		    ts_dptbl[tspp->ts_umdpri].ts_globpri);
		ASSERT(curthread->t_pri >= 0 &&
		    curthread->t_pri <= ts_maxglobpri);
		tspp->ts_flags = flags & ~TSKPRI;

		if (DISP_MUST_SURRENDER(curthread))
			cpu_surrender(curthread);
	} else if (flags & TSKPRI) {
		THREAD_CHANGE_PRI(curthread,
		    ts_dptbl[tspp->ts_umdpri].ts_globpri);
		ASSERT(curthread->t_pri >= 0 &&
		    curthread->t_pri <= ts_maxglobpri);
		tspp->ts_flags = flags & ~TSKPRI;

		if (DISP_MUST_SURRENDER(curthread))
			cpu_surrender(curthread);
	}
	t->t_stime = ddi_get_lbolt();		/* time stamp for the swapper */
	TRACE_2(TR_FAC_DISP, TR_SLEEP,
	    "sleep:tid %p old pri %d", t, old_pri);
}


/*
 * Return Values:
 *
 *	-1 if the thread is loaded or is not eligible to be swapped in.
 *
 *	effective priority of the specified thread based on swapout time
 *		and size of process (epri >= 0 , epri <= SHRT_MAX).
 */
/* ARGSUSED */
static pri_t
ts_swapin(kthread_t *t, int flags)
{
	tsproc_t	*tspp = (tsproc_t *)(t->t_cldata);
	long		epri = -1;
	proc_t		*pp = ttoproc(t);

	ASSERT(THREAD_LOCK_HELD(t));

	/*
	 * We know that pri_t is a short.
	 * Be sure not to overrun its range.
	 */
	if (t->t_state == TS_RUN && (t->t_schedflag & TS_LOAD) == 0) {
		time_t swapout_time;

		swapout_time = (ddi_get_lbolt() - t->t_stime) / hz;
		if (INHERITED(t) || (tspp->ts_flags & (TSKPRI | TSIASET)))
			epri = (long)DISP_PRIO(t) + swapout_time;
		else {
			/*
			 * Threads which have been out for a long time,
			 * have high user mode priority and are associated
			 * with a small address space are more deserving
			 */
			epri = ts_dptbl[tspp->ts_umdpri].ts_globpri;
			ASSERT(epri >= 0 && epri <= ts_maxumdpri);
			epri += swapout_time - pp->p_swrss / nz(maxpgio)/2;
		}
		/*
		 * Scale epri so SHRT_MAX/2 represents zero priority.
		 */
		epri += SHRT_MAX/2;
		if (epri < 0)
			epri = 0;
		else if (epri > SHRT_MAX)
			epri = SHRT_MAX;
	}
	return ((pri_t)epri);
}

/*
 * Return Values
 *	-1 if the thread isn't loaded or is not eligible to be swapped out.
 *
 *	effective priority of the specified thread based on if the swapper
 *		is in softswap or hardswap mode.
 *
 *		Softswap:  Return a low effective priority for threads
 *			   sleeping for more than maxslp secs.
 *
 *		Hardswap:  Return an effective priority such that threads
 *			   which have been in memory for a while and are
 *			   associated with a small address space are swapped
 *			   in before others.
 *
 *		(epri >= 0 , epri <= SHRT_MAX).
 */
time_t	ts_minrun = 2;		/* XXX - t_pri becomes 59 within 2 secs */
time_t	ts_minslp = 2;		/* min time on sleep queue for hardswap */

static pri_t
ts_swapout(kthread_t *t, int flags)
{
	tsproc_t	*tspp = (tsproc_t *)(t->t_cldata);
	long		epri = -1;
	proc_t		*pp = ttoproc(t);
	time_t		swapin_time;

	ASSERT(THREAD_LOCK_HELD(t));

	if (INHERITED(t) || (tspp->ts_flags & (TSKPRI | TSIASET)) ||
	    (t->t_proc_flag & TP_LWPEXIT) ||
	    (t->t_state & (TS_ZOMB | TS_FREE | TS_STOPPED |
	    TS_ONPROC | TS_WAIT)) ||
	    !(t->t_schedflag & TS_LOAD) || !SWAP_OK(t))
		return (-1);

	ASSERT(t->t_state & (TS_SLEEP | TS_RUN));

	/*
	 * We know that pri_t is a short.
	 * Be sure not to overrun its range.
	 */
	swapin_time = (ddi_get_lbolt() - t->t_stime) / hz;
	if (flags == SOFTSWAP) {
		if (t->t_state == TS_SLEEP && swapin_time > maxslp) {
			epri = 0;
		} else {
			return ((pri_t)epri);
		}
	} else {
		pri_t pri;

		if ((t->t_state == TS_SLEEP && swapin_time > ts_minslp) ||
		    (t->t_state == TS_RUN && swapin_time > ts_minrun)) {
			pri = ts_dptbl[tspp->ts_umdpri].ts_globpri;
			ASSERT(pri >= 0 && pri <= ts_maxumdpri);
			epri = swapin_time -
			    (rm_asrss(pp->p_as) / nz(maxpgio)/2) - (long)pri;
		} else {
			return ((pri_t)epri);
		}
	}

	/*
	 * Scale epri so SHRT_MAX/2 represents zero priority.
	 */
	epri += SHRT_MAX/2;
	if (epri < 0)
		epri = 0;
	else if (epri > SHRT_MAX)
		epri = SHRT_MAX;

	return ((pri_t)epri);
}

/*
 * Check for time slice expiration.  If time slice has expired
 * move thread to priority specified in tsdptbl for time slice expiration
 * and set runrun to cause preemption.
 */
static void
ts_tick(kthread_t *t)
{
	tsproc_t *tspp = (tsproc_t *)(t->t_cldata);
	klwp_t *lwp;
	boolean_t call_cpu_surrender = B_FALSE;
	pri_t	oldpri = t->t_pri;

	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock));

	thread_lock(t);

	/*
	 * Keep track of thread's project CPU usage.  Note that projects
	 * get charged even when threads are running in the kernel.
	 */
	if (CPUCAPS_ON()) {
		call_cpu_surrender = cpucaps_charge(t, &tspp->ts_caps,
		    CPUCAPS_CHARGE_ENFORCE) && !(tspp->ts_flags & TSKPRI);
	}

	if ((tspp->ts_flags & TSKPRI) == 0) {
		if (--tspp->ts_timeleft <= 0) {
			pri_t	new_pri;

			/*
			 * If we're doing preemption control and trying to
			 * avoid preempting this thread, just note that
			 * the thread should yield soon and let it keep
			 * running (unless it's been a while).
			 */
			if (t->t_schedctl && schedctl_get_nopreempt(t)) {
				if (tspp->ts_timeleft > -SC_MAX_TICKS) {
					DTRACE_SCHED1(schedctl__nopreempt,
					    kthread_t *, t);
					schedctl_set_yield(t, 1);
					thread_unlock_nopreempt(t);
					return;
				}

				TNF_PROBE_2(schedctl_failsafe,
				    "schedctl TS ts_tick", /* CSTYLED */,
				    tnf_pid, pid, ttoproc(t)->p_pid,
				    tnf_lwpid, lwpid, t->t_tid);
			}
			tspp->ts_flags &= ~TSRESTORE;
			tspp->ts_cpupri = ts_dptbl[tspp->ts_cpupri].ts_tqexp;
			TS_NEWUMDPRI(tspp);
			tspp->ts_dispwait = 0;
			new_pri = ts_dptbl[tspp->ts_umdpri].ts_globpri;
			ASSERT(new_pri >= 0 && new_pri <= ts_maxglobpri);
			/*
			 * When the priority of a thread is changed,
			 * it may be necessary to adjust its position
			 * on a sleep queue or dispatch queue.
			 * The function thread_change_pri accomplishes
			 * this.
			 */
			if (thread_change_pri(t, new_pri, 0)) {
				if ((t->t_schedflag & TS_LOAD) &&
				    (lwp = t->t_lwp) &&
				    lwp->lwp_state == LWP_USER)
					t->t_schedflag &= ~TS_DONT_SWAP;
				tspp->ts_timeleft =
				    ts_dptbl[tspp->ts_cpupri].ts_quantum;
			} else {
				call_cpu_surrender = B_TRUE;
			}
			TRACE_2(TR_FAC_DISP, TR_TICK,
			    "tick:tid %p old pri %d", t, oldpri);
		} else if (t->t_state == TS_ONPROC &&
		    t->t_pri < t->t_disp_queue->disp_maxrunpri) {
			call_cpu_surrender = B_TRUE;
		}
	}

	if (call_cpu_surrender) {
		tspp->ts_flags |= TSBACKQ;
		cpu_surrender(t);
	}

	thread_unlock_nopreempt(t);	/* clock thread can't be preempted */
}


/*
 * If thread is currently at a kernel mode priority (has slept)
 * we assign it the appropriate user mode priority and time quantum
 * here.  If we are lowering the thread's priority below that of
 * other runnable threads we will normally set runrun via cpu_surrender() to
 * cause preemption.
 */
static void
ts_trapret(kthread_t *t)
{
	tsproc_t	*tspp = (tsproc_t *)t->t_cldata;
	cpu_t		*cp = CPU;
	pri_t		old_pri = curthread->t_pri;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t == curthread);
	ASSERT(cp->cpu_dispthread == t);
	ASSERT(t->t_state == TS_ONPROC);

	t->t_kpri_req = 0;
	if (tspp->ts_dispwait > ts_dptbl[tspp->ts_umdpri].ts_maxwait) {
		tspp->ts_cpupri = ts_dptbl[tspp->ts_cpupri].ts_slpret;
		TS_NEWUMDPRI(tspp);
		tspp->ts_timeleft = ts_dptbl[tspp->ts_cpupri].ts_quantum;
		tspp->ts_dispwait = 0;

		/*
		 * If thread has blocked in the kernel (as opposed to
		 * being merely preempted), recompute the user mode priority.
		 */
		THREAD_CHANGE_PRI(t, ts_dptbl[tspp->ts_umdpri].ts_globpri);
		cp->cpu_dispatch_pri = DISP_PRIO(t);
		ASSERT(t->t_pri >= 0 && t->t_pri <= ts_maxglobpri);
		tspp->ts_flags &= ~TSKPRI;

		if (DISP_MUST_SURRENDER(t))
			cpu_surrender(t);
	} else if (tspp->ts_flags & TSKPRI) {
		/*
		 * If thread has blocked in the kernel (as opposed to
		 * being merely preempted), recompute the user mode priority.
		 */
		THREAD_CHANGE_PRI(t, ts_dptbl[tspp->ts_umdpri].ts_globpri);
		cp->cpu_dispatch_pri = DISP_PRIO(t);
		ASSERT(t->t_pri >= 0 && t->t_pri <= ts_maxglobpri);
		tspp->ts_flags &= ~TSKPRI;

		if (DISP_MUST_SURRENDER(t))
			cpu_surrender(t);
	}

	/*
	 * Swapout lwp if the swapper is waiting for this thread to
	 * reach a safe point.
	 */
	if ((t->t_schedflag & TS_SWAPENQ) && !(tspp->ts_flags & TSIASET)) {
		thread_unlock(t);
		swapout_lwp(ttolwp(t));
		thread_lock(t);
	}

	TRACE_2(TR_FAC_DISP, TR_TRAPRET,
	    "trapret:tid %p old pri %d", t, old_pri);
}


/*
 * Update the ts_dispwait values of all time sharing threads that
 * are currently runnable at a user mode priority and bump the priority
 * if ts_dispwait exceeds ts_maxwait.  Called once per second via
 * timeout which we reset here.
 *
 * There are several lists of time sharing threads broken up by a hash on
 * the thread pointer.  Each list has its own lock.  This avoids blocking
 * all ts_enterclass, ts_fork, and ts_exitclass operations while ts_update
 * runs.  ts_update traverses each list in turn.
 *
 * If multiple threads have their priorities updated to the same value,
 * the system implicitly favors the one that is updated first (since it
 * winds up first on the run queue).  To avoid this unfairness, the
 * traversal of threads starts at the list indicated by a marker.  When
 * threads in more than one list have their priorities updated, the marker
 * is moved.  This changes the order the threads will be placed on the run
 * queue the next time ts_update is called and preserves fairness over the
 * long run.  The marker doesn't need to be protected by a lock since it's
 * only accessed by ts_update, which is inherently single-threaded (only
 * one instance can be running at a time).
 */
static void
ts_update(void *arg)
{
	int		i;
	int		new_marker = -1;
	static int	ts_update_marker;

	/*
	 * Start with the ts_update_marker list, then do the rest.
	 */
	i = ts_update_marker;
	do {
		/*
		 * If this is the first list after the current marker to
		 * have threads with priorities updated, advance the marker
		 * to this list for the next time ts_update runs.
		 */
		if (ts_update_list(i) && new_marker == -1 &&
		    i != ts_update_marker) {
			new_marker = i;
		}
	} while ((i = TS_LIST_NEXT(i)) != ts_update_marker);

	/* advance marker for next ts_update call */
	if (new_marker != -1)
		ts_update_marker = new_marker;

	(void) timeout(ts_update, arg, hz);
}

/*
 * Updates priority for a list of threads.  Returns 1 if the priority of
 * one of the threads was actually updated, 0 if none were for various
 * reasons (thread is no longer in the TS or IA class, isn't runnable,
 * hasn't waited long enough, has the preemption control no-preempt bit
 * set, etc.)
 */
static int
ts_update_list(int i)
{
	tsproc_t *tspp;
	kthread_t *tx;
	int updated = 0;

	mutex_enter(&ts_list_lock[i]);
	for (tspp = ts_plisthead[i].ts_next; tspp != &ts_plisthead[i];
	    tspp = tspp->ts_next) {
		tx = tspp->ts_tp;
		/*
		 * Lock the thread and verify state.
		 */
		thread_lock(tx);
		/*
		 * Skip the thread if it is no longer in the TS (or IA) class.
		 */
		if (tx->t_clfuncs != &ts_classfuncs.thread &&
		    tx->t_clfuncs != &ia_classfuncs.thread)
			goto next;
		tspp->ts_dispwait++;
		if ((tspp->ts_flags & TSKPRI) != 0)
			goto next;
		if (tspp->ts_dispwait <= ts_dptbl[tspp->ts_umdpri].ts_maxwait)
			goto next;
		if (tx->t_schedctl && schedctl_get_nopreempt(tx))
			goto next;
		if (tx->t_state != TS_RUN && tx->t_state != TS_WAIT &&
		    (tx->t_state != TS_SLEEP || !ts_sleep_promote)) {
			/* make next syscall/trap do CL_TRAPRET */
			tx->t_trapret = 1;
			aston(tx);
			goto next;
		}
		tspp->ts_cpupri = ts_dptbl[tspp->ts_cpupri].ts_lwait;
		TS_NEWUMDPRI(tspp);
		tspp->ts_dispwait = 0;
		updated = 1;

		/*
		 * Only dequeue it if needs to move; otherwise it should
		 * just round-robin here.
		 */
		if (tx->t_pri != ts_dptbl[tspp->ts_umdpri].ts_globpri) {
			pri_t oldpri = tx->t_pri;
			ts_change_priority(tx, tspp);
			TRACE_2(TR_FAC_DISP, TR_UPDATE,
			    "update:tid %p old pri %d", tx, oldpri);
		}
next:
		thread_unlock(tx);
	}
	mutex_exit(&ts_list_lock[i]);

	return (updated);
}

/*
 * Processes waking up go to the back of their queue.  We don't
 * need to assign a time quantum here because thread is still
 * at a kernel mode priority and the time slicing is not done
 * for threads running in the kernel after sleeping.  The proper
 * time quantum will be assigned by ts_trapret before the thread
 * returns to user mode.
 */
static void
ts_wakeup(kthread_t *t)
{
	tsproc_t	*tspp = (tsproc_t *)(t->t_cldata);

	ASSERT(THREAD_LOCK_HELD(t));

	t->t_stime = ddi_get_lbolt();		/* time stamp for the swapper */

	if (tspp->ts_flags & TSKPRI) {
		tspp->ts_flags &= ~TSBACKQ;
		if (tspp->ts_flags & TSIASET)
			setfrontdq(t);
		else
			setbackdq(t);
	} else if (t->t_kpri_req) {
		/*
		 * Give thread a priority boost if we were asked.
		 */
		tspp->ts_flags |= TSKPRI;
		THREAD_CHANGE_PRI(t, ts_kmdpris[0]);
		setbackdq(t);
		t->t_trapret = 1;	/* so that ts_trapret will run */
		aston(t);
	} else {
		if (tspp->ts_dispwait > ts_dptbl[tspp->ts_umdpri].ts_maxwait) {
			tspp->ts_cpupri = ts_dptbl[tspp->ts_cpupri].ts_slpret;
			TS_NEWUMDPRI(tspp);
			tspp->ts_timeleft =
			    ts_dptbl[tspp->ts_cpupri].ts_quantum;
			tspp->ts_dispwait = 0;
			THREAD_CHANGE_PRI(t,
			    ts_dptbl[tspp->ts_umdpri].ts_globpri);
			ASSERT(t->t_pri >= 0 && t->t_pri <= ts_maxglobpri);
		}

		tspp->ts_flags &= ~TSBACKQ;

		if (tspp->ts_flags & TSIA) {
			if (tspp->ts_flags & TSIASET)
				setfrontdq(t);
			else
				setbackdq(t);
		} else {
			if (t->t_disp_time != ddi_get_lbolt())
				setbackdq(t);
			else
				setfrontdq(t);
		}
	}
}


/*
 * When a thread yields, put it on the back of the run queue.
 */
static void
ts_yield(kthread_t *t)
{
	tsproc_t	*tspp = (tsproc_t *)(t->t_cldata);

	ASSERT(t == curthread);
	ASSERT(THREAD_LOCK_HELD(t));

	/*
	 * Collect CPU usage spent before yielding
	 */
	(void) CPUCAPS_CHARGE(t, &tspp->ts_caps, CPUCAPS_CHARGE_ENFORCE);

	/*
	 * Clear the preemption control "yield" bit since the user is
	 * doing a yield.
	 */
	if (t->t_schedctl)
		schedctl_set_yield(t, 0);
	/*
	 * If ts_preempt() artifically increased the thread's priority
	 * to avoid preemption, restore the original priority now.
	 */
	if (tspp->ts_flags & TSRESTORE) {
		THREAD_CHANGE_PRI(t, tspp->ts_scpri);
		tspp->ts_flags &= ~TSRESTORE;
	}
	if (tspp->ts_timeleft <= 0) {
		/*
		 * Time slice was artificially extended to avoid
		 * preemption, so pretend we're preempting it now.
		 */
		DTRACE_SCHED1(schedctl__yield, int, -tspp->ts_timeleft);
		tspp->ts_cpupri = ts_dptbl[tspp->ts_cpupri].ts_tqexp;
		TS_NEWUMDPRI(tspp);
		tspp->ts_timeleft = ts_dptbl[tspp->ts_cpupri].ts_quantum;
		tspp->ts_dispwait = 0;
		THREAD_CHANGE_PRI(t, ts_dptbl[tspp->ts_umdpri].ts_globpri);
		ASSERT(t->t_pri >= 0 && t->t_pri <= ts_maxglobpri);
	}
	tspp->ts_flags &= ~TSBACKQ;
	setbackdq(t);
}


/*
 * Increment the nice value of the specified thread by incr and
 * return the new value in *retvalp.
 */
static int
ts_donice(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	int		newnice;
	tsproc_t	*tspp = (tsproc_t *)(t->t_cldata);
	tsparms_t	tsparms;

	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock));

	/* If there's no change to priority, just return current setting */
	if (incr == 0) {
		if (retvalp) {
			*retvalp = tspp->ts_nice - NZERO;
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
	 * if a privileged process specified some ridiculous increment.
	 */
	if (incr > 2 * NZERO - 1)
		incr = 2 * NZERO - 1;

	newnice = tspp->ts_nice + incr;
	if (newnice >= 2 * NZERO)
		newnice = 2 * NZERO - 1;
	else if (newnice < 0)
		newnice = 0;

	tsparms.ts_uprilim = tsparms.ts_upri =
	    -((newnice - NZERO) * ts_maxupri) / NZERO;
	/*
	 * Reset the uprilim and upri values of the thread.
	 * Call ts_parmsset even if thread is interactive since we're
	 * not changing mode.
	 */
	(void) ts_parmsset(t, (void *)&tsparms, (id_t)0, (cred_t *)NULL);

	/*
	 * Although ts_parmsset already reset ts_nice it may
	 * not have been set to precisely the value calculated above
	 * because ts_parmsset determines the nice value from the
	 * user priority and we may have truncated during the integer
	 * conversion from nice value to user priority and back.
	 * We reset ts_nice to the value we calculated above.
	 */
	tspp->ts_nice = (char)newnice;

	if (retvalp)
		*retvalp = newnice - NZERO;
	return (0);
}

/*
 * Increment the priority of the specified thread by incr and
 * return the new value in *retvalp.
 */
static int
ts_doprio(kthread_t *t, cred_t *cr, int incr, int *retvalp)
{
	int		newpri;
	tsproc_t	*tspp = (tsproc_t *)(t->t_cldata);
	tsparms_t	tsparms;

	ASSERT(MUTEX_HELD(&(ttoproc(t))->p_lock));

	/* If there's no change to the priority, just return current setting */
	if (incr == 0) {
		*retvalp = tspp->ts_upri;
		return (0);
	}

	newpri = tspp->ts_upri + incr;
	if (newpri > ts_maxupri || newpri < -ts_maxupri)
		return (EINVAL);

	*retvalp = newpri;
	tsparms.ts_uprilim = tsparms.ts_upri = newpri;
	/*
	 * Reset the uprilim and upri values of the thread.
	 * Call ts_parmsset even if thread is interactive since we're
	 * not changing mode.
	 */
	return (ts_parmsset(t, &tsparms, 0, cr));
}

/*
 * ia_set_process_group marks foreground processes as interactive
 * and background processes as non-interactive iff the session
 * leader is interactive.  This routine is called from two places:
 *	strioctl:SPGRP when a new process group gets
 * 		control of the tty.
 *	ia_parmsset-when the process in question is a session leader.
 * ia_set_process_group assumes that pidlock is held by the caller,
 * either strioctl or priocntlsys.  If the caller is priocntlsys
 * (via ia_parmsset) then the p_lock of the session leader is held
 * and the code needs to be careful about acquiring other p_locks.
 */
static void
ia_set_process_group(pid_t sid, pid_t bg_pgid, pid_t fg_pgid)
{
	proc_t 		*leader, *fg, *bg;
	tsproc_t	*tspp;
	kthread_t	*tx;
	int		plocked = 0;

	ASSERT(MUTEX_HELD(&pidlock));

	/*
	 * see if the session leader is interactive AND
	 * if it is currently "on" AND controlling a tty
	 * iff it is then make the processes in the foreground
	 * group interactive and the processes in the background
	 * group non-interactive.
	 */
	if ((leader = (proc_t *)prfind(sid)) == NULL) {
		return;
	}
	if (leader->p_stat == SIDL) {
		return;
	}
	if ((tx = proctot(leader)) == NULL) {
		return;
	}
	/*
	 * XXX do all the threads in the leader
	 */
	if (tx->t_cid != ia_cid) {
		return;
	}
	tspp = tx->t_cldata;
	/*
	 * session leaders that are not interactive need not have
	 * any processing done for them.  They are typically shells
	 * that do not have focus and are changing the process group
	 * attatched to the tty, e.g. a process that is exiting
	 */
	mutex_enter(&leader->p_sessp->s_lock);
	if (!(tspp->ts_flags & TSIASET) ||
	    (leader->p_sessp->s_vp == NULL) ||
	    (leader->p_sessp->s_vp->v_stream == NULL)) {
		mutex_exit(&leader->p_sessp->s_lock);
		return;
	}
	mutex_exit(&leader->p_sessp->s_lock);

	/*
	 * If we're already holding the leader's p_lock, we should use
	 * mutex_tryenter instead of mutex_enter to avoid deadlocks from
	 * lock ordering violations.
	 */
	if (mutex_owned(&leader->p_lock))
		plocked = 1;

	if (fg_pgid == 0)
		goto skip;
	/*
	 * now look for all processes in the foreground group and
	 * make them interactive
	 */
	for (fg = (proc_t *)pgfind(fg_pgid); fg != NULL; fg = fg->p_pglink) {
		/*
		 * if the process is SIDL it's begin forked, ignore it
		 */
		if (fg->p_stat == SIDL) {
			continue;
		}
		/*
		 * sesssion leaders must be turned on/off explicitly
		 * not implicitly as happens to other members of
		 * the process group.
		 */
		if (fg->p_pid  == fg->p_sessp->s_sid) {
			continue;
		}

		TRACE_1(TR_FAC_IA, TR_GROUP_ON,
		    "group on:proc %p", fg);

		if (plocked) {
			if (mutex_tryenter(&fg->p_lock) == 0)
				continue;
		} else {
			mutex_enter(&fg->p_lock);
		}

		if ((tx = proctot(fg)) == NULL) {
			mutex_exit(&fg->p_lock);
			continue;
		}
		do {
			thread_lock(tx);
			/*
			 * if this thread is not interactive continue
			 */
			if (tx->t_cid != ia_cid) {
				thread_unlock(tx);
				continue;
			}
			tspp = tx->t_cldata;
			tspp->ts_flags |= TSIASET;
			tspp->ts_boost = ia_boost;
			TS_NEWUMDPRI(tspp);
			if ((tspp->ts_flags & TSKPRI) != 0) {
				thread_unlock(tx);
				continue;
			}
			tspp->ts_dispwait = 0;
			ts_change_priority(tx, tspp);
			thread_unlock(tx);
		} while ((tx = tx->t_forw) != fg->p_tlist);
		mutex_exit(&fg->p_lock);
	}
skip:
	if (bg_pgid == 0)
		return;
	for (bg = (proc_t *)pgfind(bg_pgid); bg != NULL; bg = bg->p_pglink) {
		if (bg->p_stat == SIDL) {
			continue;
		}
		/*
		 * sesssion leaders must be turned off explicitly
		 * not implicitly as happens to other members of
		 * the process group.
		 */
		if (bg->p_pid == bg->p_sessp->s_sid) {
			continue;
		}

		TRACE_1(TR_FAC_IA, TR_GROUP_OFF,
		    "group off:proc %p", bg);

		if (plocked) {
			if (mutex_tryenter(&bg->p_lock) == 0)
				continue;
		} else {
			mutex_enter(&bg->p_lock);
		}

		if ((tx = proctot(bg)) == NULL) {
			mutex_exit(&bg->p_lock);
			continue;
		}
		do {
			thread_lock(tx);
			/*
			 * if this thread is not interactive continue
			 */
			if (tx->t_cid != ia_cid) {
				thread_unlock(tx);
				continue;
			}
			tspp = tx->t_cldata;
			tspp->ts_flags &= ~TSIASET;
			tspp->ts_boost = -ia_boost;
			TS_NEWUMDPRI(tspp);
			if ((tspp->ts_flags & TSKPRI) != 0) {
				thread_unlock(tx);
				continue;
			}

			tspp->ts_dispwait = 0;
			ts_change_priority(tx, tspp);
			thread_unlock(tx);
		} while ((tx = tx->t_forw) != bg->p_tlist);
		mutex_exit(&bg->p_lock);
	}
}


static void
ts_change_priority(kthread_t *t, tsproc_t *tspp)
{
	pri_t	new_pri;

	ASSERT(THREAD_LOCK_HELD(t));
	new_pri = ts_dptbl[tspp->ts_umdpri].ts_globpri;
	ASSERT(new_pri >= 0 && new_pri <= ts_maxglobpri);
	tspp->ts_flags &= ~TSRESTORE;
	t->t_cpri = tspp->ts_upri;
	if (t == curthread || t->t_state == TS_ONPROC) {
		/* curthread is always onproc */
		cpu_t	*cp = t->t_disp_queue->disp_cpu;
		THREAD_CHANGE_PRI(t, new_pri);
		if (t == cp->cpu_dispthread)
			cp->cpu_dispatch_pri = DISP_PRIO(t);
		if (DISP_MUST_SURRENDER(t)) {
			tspp->ts_flags |= TSBACKQ;
			cpu_surrender(t);
		} else {
			tspp->ts_timeleft =
			    ts_dptbl[tspp->ts_cpupri].ts_quantum;
		}
	} else {
		int	frontq;

		frontq = (tspp->ts_flags & TSIASET) != 0;
		/*
		 * When the priority of a thread is changed,
		 * it may be necessary to adjust its position
		 * on a sleep queue or dispatch queue.
		 * The function thread_change_pri accomplishes
		 * this.
		 */
		if (thread_change_pri(t, new_pri, frontq)) {
			/*
			 * The thread was on a run queue. Reset
			 * its CPU timeleft from the quantum
			 * associated with the new priority.
			 */
			tspp->ts_timeleft =
			    ts_dptbl[tspp->ts_cpupri].ts_quantum;
		} else {
			tspp->ts_flags |= TSBACKQ;
		}
	}
}

static int
ts_alloc(void **p, int flag)
{
	void *bufp;
	bufp = kmem_alloc(sizeof (tsproc_t), flag);
	if (bufp == NULL) {
		return (ENOMEM);
	} else {
		*p = bufp;
		return (0);
	}
}

static void
ts_free(void *bufp)
{
	if (bufp)
		kmem_free(bufp, sizeof (tsproc_t));
}
