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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/priv.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/brand.h>
#include <sys/sobject.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/var.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/session.h>
#include <sys/pcb.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/ts.h>
#include <sys/bitmap.h>
#include <sys/poll.h>
#include <sys/shm_impl.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/copyops.h>
#include <sys/time.h>
#include <sys/msacct.h>
#include <vm/as.h>
#include <vm/rm.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <vm/seg_dev.h>
#include <vm/seg_spt.h>
#include <vm/page.h>
#include <sys/vmparam.h>
#include <sys/swap.h>
#include <fs/proc/prdata.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/contract_impl.h>
#include <sys/contract/process.h>
#include <sys/contract/process_impl.h>
#include <sys/schedctl.h>
#include <sys/pool.h>
#include <sys/zone.h>
#include <sys/atomic.h>
#include <sys/sdt.h>

#define	MAX_ITERS_SPIN	5

typedef struct prpagev {
	uint_t *pg_protv;	/* vector of page permissions */
	char *pg_incore;	/* vector of incore flags */
	size_t pg_npages;	/* number of pages in protv and incore */
	ulong_t pg_pnbase;	/* pn within segment of first protv element */
} prpagev_t;

size_t pagev_lim = 256 * 1024;	/* limit on number of pages in prpagev_t */

extern struct seg_ops segdev_ops;	/* needs a header file */
extern struct seg_ops segspt_shmops;	/* needs a header file */

static	int	set_watched_page(proc_t *, caddr_t, caddr_t, ulong_t, ulong_t);
static	void	clear_watched_page(proc_t *, caddr_t, caddr_t, ulong_t);

/*
 * Choose an lwp from the complete set of lwps for the process.
 * This is called for any operation applied to the process
 * file descriptor that requires an lwp to operate upon.
 *
 * Returns a pointer to the thread for the selected LWP,
 * and with the dispatcher lock held for the thread.
 *
 * The algorithm for choosing an lwp is critical for /proc semantics;
 * don't touch this code unless you know all of the implications.
 */
kthread_t *
prchoose(proc_t *p)
{
	kthread_t *t;
	kthread_t *t_onproc = NULL;	/* running on processor */
	kthread_t *t_run = NULL;	/* runnable, on disp queue */
	kthread_t *t_sleep = NULL;	/* sleeping */
	kthread_t *t_hold = NULL;	/* sleeping, performing hold */
	kthread_t *t_susp = NULL;	/* suspended stop */
	kthread_t *t_jstop = NULL;	/* jobcontrol stop, w/o directed stop */
	kthread_t *t_jdstop = NULL;	/* jobcontrol stop with directed stop */
	kthread_t *t_req = NULL;	/* requested stop */
	kthread_t *t_istop = NULL;	/* event-of-interest stop */
	kthread_t *t_dtrace = NULL;	/* DTrace stop */

	ASSERT(MUTEX_HELD(&p->p_lock));

	/*
	 * If the agent lwp exists, it takes precedence over all others.
	 */
	if ((t = p->p_agenttp) != NULL) {
		thread_lock(t);
		return (t);
	}

	if ((t = p->p_tlist) == NULL)	/* start at the head of the list */
		return (t);
	do {		/* for eacn lwp in the process */
		if (VSTOPPED(t)) {	/* virtually stopped */
			if (t_req == NULL)
				t_req = t;
			continue;
		}

		thread_lock(t);		/* make sure thread is in good state */
		switch (t->t_state) {
		default:
			panic("prchoose: bad thread state %d, thread 0x%p",
			    t->t_state, (void *)t);
			/*NOTREACHED*/
		case TS_SLEEP:
			/* this is filthy */
			if (t->t_wchan == (caddr_t)&p->p_holdlwps &&
			    t->t_wchan0 == NULL) {
				if (t_hold == NULL)
					t_hold = t;
			} else {
				if (t_sleep == NULL)
					t_sleep = t;
			}
			break;
		case TS_RUN:
		case TS_WAIT:
			if (t_run == NULL)
				t_run = t;
			break;
		case TS_ONPROC:
			if (t_onproc == NULL)
				t_onproc = t;
			break;
		case TS_ZOMB:		/* last possible choice */
			break;
		case TS_STOPPED:
			switch (t->t_whystop) {
			case PR_SUSPENDED:
				if (t_susp == NULL)
					t_susp = t;
				break;
			case PR_JOBCONTROL:
				if (t->t_proc_flag & TP_PRSTOP) {
					if (t_jdstop == NULL)
						t_jdstop = t;
				} else {
					if (t_jstop == NULL)
						t_jstop = t;
				}
				break;
			case PR_REQUESTED:
				if (t->t_dtrace_stop && t_dtrace == NULL)
					t_dtrace = t;
				else if (t_req == NULL)
					t_req = t;
				break;
			case PR_SYSENTRY:
			case PR_SYSEXIT:
			case PR_SIGNALLED:
			case PR_FAULTED:
				/*
				 * Make an lwp calling exit() be the
				 * last lwp seen in the process.
				 */
				if (t_istop == NULL ||
				    (t_istop->t_whystop == PR_SYSENTRY &&
				    t_istop->t_whatstop == SYS_exit))
					t_istop = t;
				break;
			case PR_CHECKPOINT:	/* can't happen? */
				break;
			default:
				panic("prchoose: bad t_whystop %d, thread 0x%p",
				    t->t_whystop, (void *)t);
				/*NOTREACHED*/
			}
			break;
		}
		thread_unlock(t);
	} while ((t = t->t_forw) != p->p_tlist);

	if (t_onproc)
		t = t_onproc;
	else if (t_run)
		t = t_run;
	else if (t_sleep)
		t = t_sleep;
	else if (t_jstop)
		t = t_jstop;
	else if (t_jdstop)
		t = t_jdstop;
	else if (t_istop)
		t = t_istop;
	else if (t_dtrace)
		t = t_dtrace;
	else if (t_req)
		t = t_req;
	else if (t_hold)
		t = t_hold;
	else if (t_susp)
		t = t_susp;
	else			/* TS_ZOMB */
		t = p->p_tlist;

	if (t != NULL)
		thread_lock(t);
	return (t);
}

/*
 * Wakeup anyone sleeping on the /proc vnode for the process/lwp to stop.
 * Also call pollwakeup() if any lwps are waiting in poll() for POLLPRI
 * on the /proc file descriptor.  Called from stop() when a traced
 * process stops on an event of interest.  Also called from exit()
 * and prinvalidate() to indicate POLLHUP and POLLERR respectively.
 */
void
prnotify(struct vnode *vp)
{
	prcommon_t *pcp = VTOP(vp)->pr_common;

	mutex_enter(&pcp->prc_mutex);
	cv_broadcast(&pcp->prc_wait);
	mutex_exit(&pcp->prc_mutex);
	if (pcp->prc_flags & PRC_POLL) {
		/*
		 * We call pollwakeup() with POLLHUP to ensure that
		 * the pollers are awakened even if they are polling
		 * for nothing (i.e., waiting for the process to exit).
		 * This enables the use of the PRC_POLL flag for optimization
		 * (we can turn off PRC_POLL only if we know no pollers remain).
		 */
		pcp->prc_flags &= ~PRC_POLL;
		pollwakeup(&pcp->prc_pollhead, POLLHUP);
	}
}

/* called immediately below, in prfree() */
static void
prfreenotify(vnode_t *vp)
{
	prnode_t *pnp;
	prcommon_t *pcp;

	while (vp != NULL) {
		pnp = VTOP(vp);
		pcp = pnp->pr_common;
		ASSERT(pcp->prc_thread == NULL);
		pcp->prc_proc = NULL;
		/*
		 * We can't call prnotify() here because we are holding
		 * pidlock.  We assert that there is no need to.
		 */
		mutex_enter(&pcp->prc_mutex);
		cv_broadcast(&pcp->prc_wait);
		mutex_exit(&pcp->prc_mutex);
		ASSERT(!(pcp->prc_flags & PRC_POLL));

		vp = pnp->pr_next;
		pnp->pr_next = NULL;
	}
}

/*
 * Called from a hook in freeproc() when a traced process is removed
 * from the process table.  The proc-table pointers of all associated
 * /proc vnodes are cleared to indicate that the process has gone away.
 */
void
prfree(proc_t *p)
{
	uint_t slot = p->p_slot;

	ASSERT(MUTEX_HELD(&pidlock));

	/*
	 * Block the process against /proc so it can be freed.
	 * It cannot be freed while locked by some controlling process.
	 * Lock ordering:
	 *	pidlock -> pr_pidlock -> p->p_lock -> pcp->prc_mutex
	 */
	mutex_enter(&pr_pidlock);	/* protects pcp->prc_proc */
	mutex_enter(&p->p_lock);
	while (p->p_proc_flag & P_PR_LOCK) {
		mutex_exit(&pr_pidlock);
		cv_wait(&pr_pid_cv[slot], &p->p_lock);
		mutex_exit(&p->p_lock);
		mutex_enter(&pr_pidlock);
		mutex_enter(&p->p_lock);
	}

	ASSERT(p->p_tlist == NULL);

	prfreenotify(p->p_plist);
	p->p_plist = NULL;

	prfreenotify(p->p_trace);
	p->p_trace = NULL;

	/*
	 * We broadcast to wake up everyone waiting for this process.
	 * No one can reach this process from this point on.
	 */
	cv_broadcast(&pr_pid_cv[slot]);

	mutex_exit(&p->p_lock);
	mutex_exit(&pr_pidlock);
}

/*
 * Called from a hook in exit() when a traced process is becoming a zombie.
 */
void
prexit(proc_t *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));

	if (pr_watch_active(p)) {
		pr_free_watchpoints(p);
		watch_disable(curthread);
	}
	/* pr_free_watched_pages() is called in exit(), after dropping p_lock */
	if (p->p_trace) {
		VTOP(p->p_trace)->pr_common->prc_flags |= PRC_DESTROY;
		prnotify(p->p_trace);
	}
	cv_broadcast(&pr_pid_cv[p->p_slot]);	/* pauselwps() */
}

/*
 * Called when a thread calls lwp_exit().
 */
void
prlwpexit(kthread_t *t)
{
	vnode_t *vp;
	prnode_t *pnp;
	prcommon_t *pcp;
	proc_t *p = ttoproc(t);
	lwpent_t *lep = p->p_lwpdir[t->t_dslot].ld_entry;

	ASSERT(t == curthread);
	ASSERT(MUTEX_HELD(&p->p_lock));

	/*
	 * The process must be blocked against /proc to do this safely.
	 * The lwp must not disappear while the process is marked P_PR_LOCK.
	 * It is the caller's responsibility to have called prbarrier(p).
	 */
	ASSERT(!(p->p_proc_flag & P_PR_LOCK));

	for (vp = p->p_plist; vp != NULL; vp = pnp->pr_next) {
		pnp = VTOP(vp);
		pcp = pnp->pr_common;
		if (pcp->prc_thread == t) {
			pcp->prc_thread = NULL;
			pcp->prc_flags |= PRC_DESTROY;
		}
	}

	for (vp = lep->le_trace; vp != NULL; vp = pnp->pr_next) {
		pnp = VTOP(vp);
		pcp = pnp->pr_common;
		pcp->prc_thread = NULL;
		pcp->prc_flags |= PRC_DESTROY;
		prnotify(vp);
	}

	if (p->p_trace)
		prnotify(p->p_trace);
}

/*
 * Called when a zombie thread is joined or when a
 * detached lwp exits.  Called from lwp_hash_out().
 */
void
prlwpfree(proc_t *p, lwpent_t *lep)
{
	vnode_t *vp;
	prnode_t *pnp;
	prcommon_t *pcp;

	ASSERT(MUTEX_HELD(&p->p_lock));

	/*
	 * The process must be blocked against /proc to do this safely.
	 * The lwp must not disappear while the process is marked P_PR_LOCK.
	 * It is the caller's responsibility to have called prbarrier(p).
	 */
	ASSERT(!(p->p_proc_flag & P_PR_LOCK));

	vp = lep->le_trace;
	lep->le_trace = NULL;
	while (vp) {
		prnotify(vp);
		pnp = VTOP(vp);
		pcp = pnp->pr_common;
		ASSERT(pcp->prc_thread == NULL &&
		    (pcp->prc_flags & PRC_DESTROY));
		pcp->prc_tslot = -1;
		vp = pnp->pr_next;
		pnp->pr_next = NULL;
	}

	if (p->p_trace)
		prnotify(p->p_trace);
}

/*
 * Called from a hook in exec() when a thread starts exec().
 */
void
prexecstart(void)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);

	/*
	 * The P_PR_EXEC flag blocks /proc operations for
	 * the duration of the exec().
	 * We can't start exec() while the process is
	 * locked by /proc, so we call prbarrier().
	 * lwp_nostop keeps the process from being stopped
	 * via job control for the duration of the exec().
	 */

	ASSERT(MUTEX_HELD(&p->p_lock));
	prbarrier(p);
	lwp->lwp_nostop++;
	p->p_proc_flag |= P_PR_EXEC;
}

/*
 * Called from a hook in exec() when a thread finishes exec().
 * The thread may or may not have succeeded.  Some other thread
 * may have beat it to the punch.
 */
void
prexecend(void)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);
	vnode_t *vp;
	prnode_t *pnp;
	prcommon_t *pcp;
	model_t model = p->p_model;
	id_t tid = curthread->t_tid;
	int tslot = curthread->t_dslot;

	ASSERT(MUTEX_HELD(&p->p_lock));

	lwp->lwp_nostop--;
	if (p->p_flag & SEXITLWPS) {
		/*
		 * We are on our way to exiting because some
		 * other thread beat us in the race to exec().
		 * Don't clear the P_PR_EXEC flag in this case.
		 */
		return;
	}

	/*
	 * Wake up anyone waiting in /proc for the process to complete exec().
	 */
	p->p_proc_flag &= ~P_PR_EXEC;
	if ((vp = p->p_trace) != NULL) {
		pcp = VTOP(vp)->pr_common;
		mutex_enter(&pcp->prc_mutex);
		cv_broadcast(&pcp->prc_wait);
		mutex_exit(&pcp->prc_mutex);
		for (; vp != NULL; vp = pnp->pr_next) {
			pnp = VTOP(vp);
			pnp->pr_common->prc_datamodel = model;
		}
	}
	if ((vp = p->p_lwpdir[tslot].ld_entry->le_trace) != NULL) {
		/*
		 * We dealt with the process common above.
		 */
		ASSERT(p->p_trace != NULL);
		pcp = VTOP(vp)->pr_common;
		mutex_enter(&pcp->prc_mutex);
		cv_broadcast(&pcp->prc_wait);
		mutex_exit(&pcp->prc_mutex);
		for (; vp != NULL; vp = pnp->pr_next) {
			pnp = VTOP(vp);
			pcp = pnp->pr_common;
			pcp->prc_datamodel = model;
			pcp->prc_tid = tid;
			pcp->prc_tslot = tslot;
		}
	}
}

/*
 * Called from a hook in relvm() just before freeing the address space.
 * We free all the watched areas now.
 */
void
prrelvm(void)
{
	proc_t *p = ttoproc(curthread);

	mutex_enter(&p->p_lock);
	prbarrier(p);	/* block all other /proc operations */
	if (pr_watch_active(p)) {
		pr_free_watchpoints(p);
		watch_disable(curthread);
	}
	mutex_exit(&p->p_lock);
	pr_free_watched_pages(p);
}

/*
 * Called from hooks in exec-related code when a traced process
 * attempts to exec(2) a setuid/setgid program or an unreadable
 * file.  Rather than fail the exec we invalidate the associated
 * /proc vnodes so that subsequent attempts to use them will fail.
 *
 * All /proc vnodes, except directory vnodes, are retained on a linked
 * list (rooted at p_plist in the process structure) until last close.
 *
 * A controlling process must re-open the /proc files in order to
 * regain control.
 */
void
prinvalidate(struct user *up)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	vnode_t *vp;
	prnode_t *pnp;
	int writers = 0;

	mutex_enter(&p->p_lock);
	prbarrier(p);	/* block all other /proc operations */

	/*
	 * At this moment, there can be only one lwp in the process.
	 */
	ASSERT(p->p_lwpcnt == 1 && p->p_zombcnt == 0);

	/*
	 * Invalidate any currently active /proc vnodes.
	 */
	for (vp = p->p_plist; vp != NULL; vp = pnp->pr_next) {
		pnp = VTOP(vp);
		switch (pnp->pr_type) {
		case PR_PSINFO:		/* these files can read by anyone */
		case PR_LPSINFO:
		case PR_LWPSINFO:
		case PR_LWPDIR:
		case PR_LWPIDDIR:
		case PR_USAGE:
		case PR_LUSAGE:
		case PR_LWPUSAGE:
			break;
		default:
			pnp->pr_flags |= PR_INVAL;
			break;
		}
	}
	/*
	 * Wake up anyone waiting for the process or lwp.
	 * p->p_trace is guaranteed to be non-NULL if there
	 * are any open /proc files for this process.
	 */
	if ((vp = p->p_trace) != NULL) {
		prcommon_t *pcp = VTOP(vp)->pr_pcommon;

		prnotify(vp);
		/*
		 * Are there any writers?
		 */
		if ((writers = pcp->prc_writers) != 0) {
			/*
			 * Clear the exclusive open flag (old /proc interface).
			 * Set prc_selfopens equal to prc_writers so that
			 * the next O_EXCL|O_WRITE open will succeed
			 * even with existing (though invalid) writers.
			 * prclose() must decrement prc_selfopens when
			 * the invalid files are closed.
			 */
			pcp->prc_flags &= ~PRC_EXCL;
			ASSERT(pcp->prc_selfopens <= writers);
			pcp->prc_selfopens = writers;
		}
	}
	vp = p->p_lwpdir[t->t_dslot].ld_entry->le_trace;
	while (vp != NULL) {
		/*
		 * We should not invalidate the lwpiddir vnodes,
		 * but the necessities of maintaining the old
		 * ioctl()-based version of /proc require it.
		 */
		pnp = VTOP(vp);
		pnp->pr_flags |= PR_INVAL;
		prnotify(vp);
		vp = pnp->pr_next;
	}

	/*
	 * If any tracing flags are in effect and any vnodes are open for
	 * writing then set the requested-stop and run-on-last-close flags.
	 * Otherwise, clear all tracing flags.
	 */
	t->t_proc_flag &= ~TP_PAUSE;
	if ((p->p_proc_flag & P_PR_TRACE) && writers) {
		t->t_proc_flag |= TP_PRSTOP;
		aston(t);		/* so ISSIG will see the flag */
		p->p_proc_flag |= P_PR_RUNLCL;
	} else {
		premptyset(&up->u_entrymask);		/* syscalls */
		premptyset(&up->u_exitmask);
		up->u_systrap = 0;
		premptyset(&p->p_sigmask);		/* signals */
		premptyset(&p->p_fltmask);		/* faults */
		t->t_proc_flag &= ~(TP_PRSTOP|TP_PRVSTOP|TP_STOPPING);
		p->p_proc_flag &= ~(P_PR_RUNLCL|P_PR_KILLCL|P_PR_TRACE);
		prnostep(ttolwp(t));
	}

	mutex_exit(&p->p_lock);
}

/*
 * Acquire the controlled process's p_lock and mark it P_PR_LOCK.
 * Return with pr_pidlock held in all cases.
 * Return with p_lock held if the the process still exists.
 * Return value is the process pointer if the process still exists, else NULL.
 * If we lock the process, give ourself kernel priority to avoid deadlocks;
 * this is undone in prunlock().
 */
proc_t *
pr_p_lock(prnode_t *pnp)
{
	proc_t *p;
	prcommon_t *pcp;

	mutex_enter(&pr_pidlock);
	if ((pcp = pnp->pr_pcommon) == NULL || (p = pcp->prc_proc) == NULL)
		return (NULL);
	mutex_enter(&p->p_lock);
	while (p->p_proc_flag & P_PR_LOCK) {
		/*
		 * This cv/mutex pair is persistent even if
		 * the process disappears while we sleep.
		 */
		kcondvar_t *cv = &pr_pid_cv[p->p_slot];
		kmutex_t *mp = &p->p_lock;

		mutex_exit(&pr_pidlock);
		cv_wait(cv, mp);
		mutex_exit(mp);
		mutex_enter(&pr_pidlock);
		if (pcp->prc_proc == NULL)
			return (NULL);
		ASSERT(p == pcp->prc_proc);
		mutex_enter(&p->p_lock);
	}
	p->p_proc_flag |= P_PR_LOCK;
	THREAD_KPRI_REQUEST();
	return (p);
}

/*
 * Lock the target process by setting P_PR_LOCK and grabbing p->p_lock.
 * This prevents any lwp of the process from disappearing and
 * blocks most operations that a process can perform on itself.
 * Returns 0 on success, a non-zero error number on failure.
 *
 * 'zdisp' is ZYES or ZNO to indicate whether prlock() should succeed when
 * the subject process is a zombie (ZYES) or fail for zombies (ZNO).
 *
 * error returns:
 *	ENOENT: process or lwp has disappeared or process is exiting
 *		(or has become a zombie and zdisp == ZNO).
 *	EAGAIN: procfs vnode has become invalid.
 *	EINTR:  signal arrived while waiting for exec to complete.
 */
int
prlock(prnode_t *pnp, int zdisp)
{
	prcommon_t *pcp;
	proc_t *p;

again:
	pcp = pnp->pr_common;
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);

	/*
	 * Return ENOENT immediately if there is no process.
	 */
	if (p == NULL)
		return (ENOENT);

	ASSERT(p == pcp->prc_proc && p->p_stat != 0 && p->p_stat != SIDL);

	/*
	 * Return ENOENT if process entered zombie state or is exiting
	 * and the 'zdisp' flag is set to ZNO indicating not to lock zombies.
	 */
	if (zdisp == ZNO &&
	    ((pcp->prc_flags & PRC_DESTROY) || (p->p_flag & SEXITING))) {
		prunlock(pnp);
		return (ENOENT);
	}

	/*
	 * If lwp-specific, check to see if lwp has disappeared.
	 */
	if (pcp->prc_flags & PRC_LWP) {
		if ((zdisp == ZNO && (pcp->prc_flags & PRC_DESTROY)) ||
		    pcp->prc_tslot == -1) {
			prunlock(pnp);
			return (ENOENT);
		}
	}

	/*
	 * Return EAGAIN if we have encountered a security violation.
	 * (The process exec'd a set-id or unreadable executable file.)
	 */
	if (pnp->pr_flags & PR_INVAL) {
		prunlock(pnp);
		return (EAGAIN);
	}

	/*
	 * If process is undergoing an exec(), wait for
	 * completion and then start all over again.
	 */
	if (p->p_proc_flag & P_PR_EXEC) {
		pcp = pnp->pr_pcommon;	/* Put on the correct sleep queue */
		mutex_enter(&pcp->prc_mutex);
		prunlock(pnp);
		if (!cv_wait_sig(&pcp->prc_wait, &pcp->prc_mutex)) {
			mutex_exit(&pcp->prc_mutex);
			return (EINTR);
		}
		mutex_exit(&pcp->prc_mutex);
		goto again;
	}

	/*
	 * We return holding p->p_lock.
	 */
	return (0);
}

/*
 * Undo prlock() and pr_p_lock().
 * p->p_lock is still held; pr_pidlock is no longer held.
 *
 * prunmark() drops the P_PR_LOCK flag and wakes up another thread,
 * if any, waiting for the flag to be dropped; it retains p->p_lock.
 *
 * prunlock() calls prunmark() and then drops p->p_lock.
 */
void
prunmark(proc_t *p)
{
	ASSERT(p->p_proc_flag & P_PR_LOCK);
	ASSERT(MUTEX_HELD(&p->p_lock));

	cv_signal(&pr_pid_cv[p->p_slot]);
	p->p_proc_flag &= ~P_PR_LOCK;
	THREAD_KPRI_RELEASE();
}

void
prunlock(prnode_t *pnp)
{
	prcommon_t *pcp = pnp->pr_common;
	proc_t *p = pcp->prc_proc;

	/*
	 * If we (or someone) gave it a SIGKILL, and it is not
	 * already a zombie, set it running unconditionally.
	 */
	if ((p->p_flag & SKILLED) &&
	    !(p->p_flag & SEXITING) &&
	    !(pcp->prc_flags & PRC_DESTROY) &&
	    !((pcp->prc_flags & PRC_LWP) && pcp->prc_tslot == -1))
		(void) pr_setrun(pnp, 0);
	prunmark(p);
	mutex_exit(&p->p_lock);
}

/*
 * Called while holding p->p_lock to delay until the process is unlocked.
 * We enter holding p->p_lock; p->p_lock is dropped and reacquired.
 * The process cannot become locked again until p->p_lock is dropped.
 */
void
prbarrier(proc_t *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));

	if (p->p_proc_flag & P_PR_LOCK) {
		/* The process is locked; delay until not locked */
		uint_t slot = p->p_slot;

		while (p->p_proc_flag & P_PR_LOCK)
			cv_wait(&pr_pid_cv[slot], &p->p_lock);
		cv_signal(&pr_pid_cv[slot]);
	}
}

/*
 * Return process/lwp status.
 * The u-block is mapped in by this routine and unmapped at the end.
 */
void
prgetstatus(proc_t *p, pstatus_t *sp, zone_t *zp)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));

	t = prchoose(p);	/* returns locked thread */
	ASSERT(t != NULL);
	thread_unlock(t);

	/* just bzero the process part, prgetlwpstatus() does the rest */
	bzero(sp, sizeof (pstatus_t) - sizeof (lwpstatus_t));
	sp->pr_nlwp = p->p_lwpcnt;
	sp->pr_nzomb = p->p_zombcnt;
	prassignset(&sp->pr_sigpend, &p->p_sig);
	sp->pr_brkbase = (uintptr_t)p->p_brkbase;
	sp->pr_brksize = p->p_brksize;
	sp->pr_stkbase = (uintptr_t)prgetstackbase(p);
	sp->pr_stksize = p->p_stksize;
	sp->pr_pid = p->p_pid;
	if (curproc->p_zone->zone_id != GLOBAL_ZONEID &&
	    (p->p_flag & SZONETOP)) {
		ASSERT(p->p_zone->zone_id != GLOBAL_ZONEID);
		/*
		 * Inside local zones, fake zsched's pid as parent pids for
		 * processes which reference processes outside of the zone.
		 */
		sp->pr_ppid = curproc->p_zone->zone_zsched->p_pid;
	} else {
		sp->pr_ppid = p->p_ppid;
	}
	sp->pr_pgid  = p->p_pgrp;
	sp->pr_sid   = p->p_sessp->s_sid;
	sp->pr_taskid = p->p_task->tk_tkid;
	sp->pr_projid = p->p_task->tk_proj->kpj_id;
	sp->pr_zoneid = p->p_zone->zone_id;
	hrt2ts(mstate_aggr_state(p, LMS_USER), &sp->pr_utime);
	hrt2ts(mstate_aggr_state(p, LMS_SYSTEM), &sp->pr_stime);
	TICK_TO_TIMESTRUC(p->p_cutime, &sp->pr_cutime);
	TICK_TO_TIMESTRUC(p->p_cstime, &sp->pr_cstime);
	prassignset(&sp->pr_sigtrace, &p->p_sigmask);
	prassignset(&sp->pr_flttrace, &p->p_fltmask);
	prassignset(&sp->pr_sysentry, &PTOU(p)->u_entrymask);
	prassignset(&sp->pr_sysexit, &PTOU(p)->u_exitmask);
	switch (p->p_model) {
	case DATAMODEL_ILP32:
		sp->pr_dmodel = PR_MODEL_ILP32;
		break;
	case DATAMODEL_LP64:
		sp->pr_dmodel = PR_MODEL_LP64;
		break;
	}
	if (p->p_agenttp)
		sp->pr_agentid = p->p_agenttp->t_tid;

	/* get the chosen lwp's status */
	prgetlwpstatus(t, &sp->pr_lwp, zp);

	/* replicate the flags */
	sp->pr_flags = sp->pr_lwp.pr_flags;
}

#ifdef _SYSCALL32_IMPL
void
prgetlwpstatus32(kthread_t *t, lwpstatus32_t *sp, zone_t *zp)
{
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	struct mstate *ms = &lwp->lwp_mstate;
	hrtime_t usr, sys;
	int flags;
	ulong_t instr;

	ASSERT(MUTEX_HELD(&p->p_lock));

	bzero(sp, sizeof (*sp));
	flags = 0L;
	if (t->t_state == TS_STOPPED) {
		flags |= PR_STOPPED;
		if ((t->t_schedflag & TS_PSTART) == 0)
			flags |= PR_ISTOP;
	} else if (VSTOPPED(t)) {
		flags |= PR_STOPPED|PR_ISTOP;
	}
	if (!(flags & PR_ISTOP) && (t->t_proc_flag & TP_PRSTOP))
		flags |= PR_DSTOP;
	if (lwp->lwp_asleep)
		flags |= PR_ASLEEP;
	if (t == p->p_agenttp)
		flags |= PR_AGENT;
	if (!(t->t_proc_flag & TP_TWAIT))
		flags |= PR_DETACH;
	if (t->t_proc_flag & TP_DAEMON)
		flags |= PR_DAEMON;
	if (p->p_proc_flag & P_PR_FORK)
		flags |= PR_FORK;
	if (p->p_proc_flag & P_PR_RUNLCL)
		flags |= PR_RLC;
	if (p->p_proc_flag & P_PR_KILLCL)
		flags |= PR_KLC;
	if (p->p_proc_flag & P_PR_ASYNC)
		flags |= PR_ASYNC;
	if (p->p_proc_flag & P_PR_BPTADJ)
		flags |= PR_BPTADJ;
	if (p->p_proc_flag & P_PR_PTRACE)
		flags |= PR_PTRACE;
	if (p->p_flag & SMSACCT)
		flags |= PR_MSACCT;
	if (p->p_flag & SMSFORK)
		flags |= PR_MSFORK;
	if (p->p_flag & SVFWAIT)
		flags |= PR_VFORKP;
	sp->pr_flags = flags;
	if (VSTOPPED(t)) {
		sp->pr_why   = PR_REQUESTED;
		sp->pr_what  = 0;
	} else {
		sp->pr_why   = t->t_whystop;
		sp->pr_what  = t->t_whatstop;
	}
	sp->pr_lwpid = t->t_tid;
	sp->pr_cursig  = lwp->lwp_cursig;
	prassignset(&sp->pr_lwppend, &t->t_sig);
	schedctl_finish_sigblock(t);
	prassignset(&sp->pr_lwphold, &t->t_hold);
	if (t->t_whystop == PR_FAULTED) {
		siginfo_kto32(&lwp->lwp_siginfo, &sp->pr_info);
		if (t->t_whatstop == FLTPAGE)
			sp->pr_info.si_addr =
			    (caddr32_t)(uintptr_t)lwp->lwp_siginfo.si_addr;
	} else if (lwp->lwp_curinfo)
		siginfo_kto32(&lwp->lwp_curinfo->sq_info, &sp->pr_info);
	if (SI_FROMUSER(&lwp->lwp_siginfo) && zp->zone_id != GLOBAL_ZONEID &&
	    sp->pr_info.si_zoneid != zp->zone_id) {
		sp->pr_info.si_pid = zp->zone_zsched->p_pid;
		sp->pr_info.si_uid = 0;
		sp->pr_info.si_ctid = -1;
		sp->pr_info.si_zoneid = zp->zone_id;
	}
	sp->pr_altstack.ss_sp =
	    (caddr32_t)(uintptr_t)lwp->lwp_sigaltstack.ss_sp;
	sp->pr_altstack.ss_size = (size32_t)lwp->lwp_sigaltstack.ss_size;
	sp->pr_altstack.ss_flags = (int32_t)lwp->lwp_sigaltstack.ss_flags;
	prgetaction32(p, PTOU(p), lwp->lwp_cursig, &sp->pr_action);
	sp->pr_oldcontext = (caddr32_t)lwp->lwp_oldcontext;
	sp->pr_ustack = (caddr32_t)lwp->lwp_ustack;
	(void) strncpy(sp->pr_clname, sclass[t->t_cid].cl_name,
	    sizeof (sp->pr_clname) - 1);
	if (flags & PR_STOPPED)
		hrt2ts32(t->t_stoptime, &sp->pr_tstamp);
	usr = ms->ms_acct[LMS_USER];
	sys = ms->ms_acct[LMS_SYSTEM] + ms->ms_acct[LMS_TRAP];
	scalehrtime(&usr);
	scalehrtime(&sys);
	hrt2ts32(usr, &sp->pr_utime);
	hrt2ts32(sys, &sp->pr_stime);

	/*
	 * Fetch the current instruction, if not a system process.
	 * We don't attempt this unless the lwp is stopped.
	 */
	if ((p->p_flag & SSYS) || p->p_as == &kas)
		sp->pr_flags |= (PR_ISSYS|PR_PCINVAL);
	else if (!(flags & PR_STOPPED))
		sp->pr_flags |= PR_PCINVAL;
	else if (!prfetchinstr(lwp, &instr))
		sp->pr_flags |= PR_PCINVAL;
	else
		sp->pr_instr = (uint32_t)instr;

	/*
	 * Drop p_lock while touching the lwp's stack.
	 */
	mutex_exit(&p->p_lock);
	if (prisstep(lwp))
		sp->pr_flags |= PR_STEP;
	if ((flags & (PR_STOPPED|PR_ASLEEP)) && t->t_sysnum) {
		int i;

		sp->pr_syscall = get_syscall32_args(lwp,
		    (int *)sp->pr_sysarg, &i);
		sp->pr_nsysarg = (ushort_t)i;
	}
	if ((flags & PR_STOPPED) || t == curthread)
		prgetprregs32(lwp, sp->pr_reg);
	if ((t->t_state == TS_STOPPED && t->t_whystop == PR_SYSEXIT) ||
	    (flags & PR_VFORKP)) {
		long r1, r2;
		user_t *up;
		auxv_t *auxp;
		int i;

		sp->pr_errno = prgetrvals(lwp, &r1, &r2);
		if (sp->pr_errno == 0) {
			sp->pr_rval1 = (int32_t)r1;
			sp->pr_rval2 = (int32_t)r2;
			sp->pr_errpriv = PRIV_NONE;
		} else
			sp->pr_errpriv = lwp->lwp_badpriv;

		if (t->t_sysnum == SYS_execve) {
			up = PTOU(p);
			sp->pr_sysarg[0] = 0;
			sp->pr_sysarg[1] = (caddr32_t)up->u_argv;
			sp->pr_sysarg[2] = (caddr32_t)up->u_envp;
			for (i = 0, auxp = up->u_auxv;
			    i < sizeof (up->u_auxv) / sizeof (up->u_auxv[0]);
			    i++, auxp++) {
				if (auxp->a_type == AT_SUN_EXECNAME) {
					sp->pr_sysarg[0] =
					    (caddr32_t)
					    (uintptr_t)auxp->a_un.a_ptr;
					break;
				}
			}
		}
	}
	if (prhasfp())
		prgetprfpregs32(lwp, &sp->pr_fpreg);
	mutex_enter(&p->p_lock);
}

void
prgetstatus32(proc_t *p, pstatus32_t *sp, zone_t *zp)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));

	t = prchoose(p);	/* returns locked thread */
	ASSERT(t != NULL);
	thread_unlock(t);

	/* just bzero the process part, prgetlwpstatus32() does the rest */
	bzero(sp, sizeof (pstatus32_t) - sizeof (lwpstatus32_t));
	sp->pr_nlwp = p->p_lwpcnt;
	sp->pr_nzomb = p->p_zombcnt;
	prassignset(&sp->pr_sigpend, &p->p_sig);
	sp->pr_brkbase = (uint32_t)(uintptr_t)p->p_brkbase;
	sp->pr_brksize = (uint32_t)p->p_brksize;
	sp->pr_stkbase = (uint32_t)(uintptr_t)prgetstackbase(p);
	sp->pr_stksize = (uint32_t)p->p_stksize;
	sp->pr_pid   = p->p_pid;
	if (curproc->p_zone->zone_id != GLOBAL_ZONEID &&
	    (p->p_flag & SZONETOP)) {
		ASSERT(p->p_zone->zone_id != GLOBAL_ZONEID);
		/*
		 * Inside local zones, fake zsched's pid as parent pids for
		 * processes which reference processes outside of the zone.
		 */
		sp->pr_ppid = curproc->p_zone->zone_zsched->p_pid;
	} else {
		sp->pr_ppid = p->p_ppid;
	}
	sp->pr_pgid  = p->p_pgrp;
	sp->pr_sid   = p->p_sessp->s_sid;
	sp->pr_taskid = p->p_task->tk_tkid;
	sp->pr_projid = p->p_task->tk_proj->kpj_id;
	sp->pr_zoneid = p->p_zone->zone_id;
	hrt2ts32(mstate_aggr_state(p, LMS_USER), &sp->pr_utime);
	hrt2ts32(mstate_aggr_state(p, LMS_SYSTEM), &sp->pr_stime);
	TICK_TO_TIMESTRUC32(p->p_cutime, &sp->pr_cutime);
	TICK_TO_TIMESTRUC32(p->p_cstime, &sp->pr_cstime);
	prassignset(&sp->pr_sigtrace, &p->p_sigmask);
	prassignset(&sp->pr_flttrace, &p->p_fltmask);
	prassignset(&sp->pr_sysentry, &PTOU(p)->u_entrymask);
	prassignset(&sp->pr_sysexit, &PTOU(p)->u_exitmask);
	switch (p->p_model) {
	case DATAMODEL_ILP32:
		sp->pr_dmodel = PR_MODEL_ILP32;
		break;
	case DATAMODEL_LP64:
		sp->pr_dmodel = PR_MODEL_LP64;
		break;
	}
	if (p->p_agenttp)
		sp->pr_agentid = p->p_agenttp->t_tid;

	/* get the chosen lwp's status */
	prgetlwpstatus32(t, &sp->pr_lwp, zp);

	/* replicate the flags */
	sp->pr_flags = sp->pr_lwp.pr_flags;
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Return lwp status.
 */
void
prgetlwpstatus(kthread_t *t, lwpstatus_t *sp, zone_t *zp)
{
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	struct mstate *ms = &lwp->lwp_mstate;
	hrtime_t usr, sys;
	int flags;
	ulong_t instr;

	ASSERT(MUTEX_HELD(&p->p_lock));

	bzero(sp, sizeof (*sp));
	flags = 0L;
	if (t->t_state == TS_STOPPED) {
		flags |= PR_STOPPED;
		if ((t->t_schedflag & TS_PSTART) == 0)
			flags |= PR_ISTOP;
	} else if (VSTOPPED(t)) {
		flags |= PR_STOPPED|PR_ISTOP;
	}
	if (!(flags & PR_ISTOP) && (t->t_proc_flag & TP_PRSTOP))
		flags |= PR_DSTOP;
	if (lwp->lwp_asleep)
		flags |= PR_ASLEEP;
	if (t == p->p_agenttp)
		flags |= PR_AGENT;
	if (!(t->t_proc_flag & TP_TWAIT))
		flags |= PR_DETACH;
	if (t->t_proc_flag & TP_DAEMON)
		flags |= PR_DAEMON;
	if (p->p_proc_flag & P_PR_FORK)
		flags |= PR_FORK;
	if (p->p_proc_flag & P_PR_RUNLCL)
		flags |= PR_RLC;
	if (p->p_proc_flag & P_PR_KILLCL)
		flags |= PR_KLC;
	if (p->p_proc_flag & P_PR_ASYNC)
		flags |= PR_ASYNC;
	if (p->p_proc_flag & P_PR_BPTADJ)
		flags |= PR_BPTADJ;
	if (p->p_proc_flag & P_PR_PTRACE)
		flags |= PR_PTRACE;
	if (p->p_flag & SMSACCT)
		flags |= PR_MSACCT;
	if (p->p_flag & SMSFORK)
		flags |= PR_MSFORK;
	if (p->p_flag & SVFWAIT)
		flags |= PR_VFORKP;
	if (p->p_pgidp->pid_pgorphaned)
		flags |= PR_ORPHAN;
	if (p->p_pidflag & CLDNOSIGCHLD)
		flags |= PR_NOSIGCHLD;
	if (p->p_pidflag & CLDWAITPID)
		flags |= PR_WAITPID;
	sp->pr_flags = flags;
	if (VSTOPPED(t)) {
		sp->pr_why   = PR_REQUESTED;
		sp->pr_what  = 0;
	} else {
		sp->pr_why   = t->t_whystop;
		sp->pr_what  = t->t_whatstop;
	}
	sp->pr_lwpid = t->t_tid;
	sp->pr_cursig  = lwp->lwp_cursig;
	prassignset(&sp->pr_lwppend, &t->t_sig);
	schedctl_finish_sigblock(t);
	prassignset(&sp->pr_lwphold, &t->t_hold);
	if (t->t_whystop == PR_FAULTED)
		bcopy(&lwp->lwp_siginfo,
		    &sp->pr_info, sizeof (k_siginfo_t));
	else if (lwp->lwp_curinfo)
		bcopy(&lwp->lwp_curinfo->sq_info,
		    &sp->pr_info, sizeof (k_siginfo_t));
	if (SI_FROMUSER(&lwp->lwp_siginfo) && zp->zone_id != GLOBAL_ZONEID &&
	    sp->pr_info.si_zoneid != zp->zone_id) {
		sp->pr_info.si_pid = zp->zone_zsched->p_pid;
		sp->pr_info.si_uid = 0;
		sp->pr_info.si_ctid = -1;
		sp->pr_info.si_zoneid = zp->zone_id;
	}
	sp->pr_altstack = lwp->lwp_sigaltstack;
	prgetaction(p, PTOU(p), lwp->lwp_cursig, &sp->pr_action);
	sp->pr_oldcontext = (uintptr_t)lwp->lwp_oldcontext;
	sp->pr_ustack = lwp->lwp_ustack;
	(void) strncpy(sp->pr_clname, sclass[t->t_cid].cl_name,
	    sizeof (sp->pr_clname) - 1);
	if (flags & PR_STOPPED)
		hrt2ts(t->t_stoptime, &sp->pr_tstamp);
	usr = ms->ms_acct[LMS_USER];
	sys = ms->ms_acct[LMS_SYSTEM] + ms->ms_acct[LMS_TRAP];
	scalehrtime(&usr);
	scalehrtime(&sys);
	hrt2ts(usr, &sp->pr_utime);
	hrt2ts(sys, &sp->pr_stime);

	/*
	 * Fetch the current instruction, if not a system process.
	 * We don't attempt this unless the lwp is stopped.
	 */
	if ((p->p_flag & SSYS) || p->p_as == &kas)
		sp->pr_flags |= (PR_ISSYS|PR_PCINVAL);
	else if (!(flags & PR_STOPPED))
		sp->pr_flags |= PR_PCINVAL;
	else if (!prfetchinstr(lwp, &instr))
		sp->pr_flags |= PR_PCINVAL;
	else
		sp->pr_instr = instr;

	/*
	 * Drop p_lock while touching the lwp's stack.
	 */
	mutex_exit(&p->p_lock);
	if (prisstep(lwp))
		sp->pr_flags |= PR_STEP;
	if ((flags & (PR_STOPPED|PR_ASLEEP)) && t->t_sysnum) {
		int i;

		sp->pr_syscall = get_syscall_args(lwp,
		    (long *)sp->pr_sysarg, &i);
		sp->pr_nsysarg = (ushort_t)i;
	}
	if ((flags & PR_STOPPED) || t == curthread)
		prgetprregs(lwp, sp->pr_reg);
	if ((t->t_state == TS_STOPPED && t->t_whystop == PR_SYSEXIT) ||
	    (flags & PR_VFORKP)) {
		user_t *up;
		auxv_t *auxp;
		int i;

		sp->pr_errno = prgetrvals(lwp, &sp->pr_rval1, &sp->pr_rval2);
		if (sp->pr_errno == 0)
			sp->pr_errpriv = PRIV_NONE;
		else
			sp->pr_errpriv = lwp->lwp_badpriv;

		if (t->t_sysnum == SYS_execve) {
			up = PTOU(p);
			sp->pr_sysarg[0] = 0;
			sp->pr_sysarg[1] = (uintptr_t)up->u_argv;
			sp->pr_sysarg[2] = (uintptr_t)up->u_envp;
			for (i = 0, auxp = up->u_auxv;
			    i < sizeof (up->u_auxv) / sizeof (up->u_auxv[0]);
			    i++, auxp++) {
				if (auxp->a_type == AT_SUN_EXECNAME) {
					sp->pr_sysarg[0] =
					    (uintptr_t)auxp->a_un.a_ptr;
					break;
				}
			}
		}
	}
	if (prhasfp())
		prgetprfpregs(lwp, &sp->pr_fpreg);
	mutex_enter(&p->p_lock);
}

/*
 * Get the sigaction structure for the specified signal.  The u-block
 * must already have been mapped in by the caller.
 */
void
prgetaction(proc_t *p, user_t *up, uint_t sig, struct sigaction *sp)
{
	int nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;

	bzero(sp, sizeof (*sp));

	if (sig != 0 && (unsigned)sig < nsig) {
		sp->sa_handler = up->u_signal[sig-1];
		prassignset(&sp->sa_mask, &up->u_sigmask[sig-1]);
		if (sigismember(&up->u_sigonstack, sig))
			sp->sa_flags |= SA_ONSTACK;
		if (sigismember(&up->u_sigresethand, sig))
			sp->sa_flags |= SA_RESETHAND;
		if (sigismember(&up->u_sigrestart, sig))
			sp->sa_flags |= SA_RESTART;
		if (sigismember(&p->p_siginfo, sig))
			sp->sa_flags |= SA_SIGINFO;
		if (sigismember(&up->u_signodefer, sig))
			sp->sa_flags |= SA_NODEFER;
		if (sig == SIGCLD) {
			if (p->p_flag & SNOWAIT)
				sp->sa_flags |= SA_NOCLDWAIT;
			if ((p->p_flag & SJCTL) == 0)
				sp->sa_flags |= SA_NOCLDSTOP;
		}
	}
}

#ifdef _SYSCALL32_IMPL
void
prgetaction32(proc_t *p, user_t *up, uint_t sig, struct sigaction32 *sp)
{
	int nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;

	bzero(sp, sizeof (*sp));

	if (sig != 0 && (unsigned)sig < nsig) {
		sp->sa_handler = (caddr32_t)(uintptr_t)up->u_signal[sig-1];
		prassignset(&sp->sa_mask, &up->u_sigmask[sig-1]);
		if (sigismember(&up->u_sigonstack, sig))
			sp->sa_flags |= SA_ONSTACK;
		if (sigismember(&up->u_sigresethand, sig))
			sp->sa_flags |= SA_RESETHAND;
		if (sigismember(&up->u_sigrestart, sig))
			sp->sa_flags |= SA_RESTART;
		if (sigismember(&p->p_siginfo, sig))
			sp->sa_flags |= SA_SIGINFO;
		if (sigismember(&up->u_signodefer, sig))
			sp->sa_flags |= SA_NODEFER;
		if (sig == SIGCLD) {
			if (p->p_flag & SNOWAIT)
				sp->sa_flags |= SA_NOCLDWAIT;
			if ((p->p_flag & SJCTL) == 0)
				sp->sa_flags |= SA_NOCLDSTOP;
		}
	}
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Count the number of segments in this process's address space.
 */
int
prnsegs(struct as *as, int reserved)
{
	int n = 0;
	struct seg *seg;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	for (seg = AS_SEGFIRST(as); seg != NULL; seg = AS_SEGNEXT(as, seg)) {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, reserved);
		caddr_t saddr, naddr;
		void *tmp = NULL;

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			(void) pr_getprot(seg, reserved, &tmp,
			    &saddr, &naddr, eaddr);
			if (saddr != naddr)
				n++;
		}

		ASSERT(tmp == NULL);
	}

	return (n);
}

/*
 * Convert uint32_t to decimal string w/o leading zeros.
 * Add trailing null characters if 'len' is greater than string length.
 * Return the string length.
 */
int
pr_u32tos(uint32_t n, char *s, int len)
{
	char cbuf[11];		/* 32-bit unsigned integer fits in 10 digits */
	char *cp = cbuf;
	char *end = s + len;

	do {
		*cp++ = (char)(n % 10 + '0');
		n /= 10;
	} while (n);

	len = (int)(cp - cbuf);

	do {
		*s++ = *--cp;
	} while (cp > cbuf);

	while (s < end)		/* optional pad */
		*s++ = '\0';

	return (len);
}

/*
 * Convert uint64_t to decimal string w/o leading zeros.
 * Return the string length.
 */
static int
pr_u64tos(uint64_t n, char *s)
{
	char cbuf[21];		/* 64-bit unsigned integer fits in 20 digits */
	char *cp = cbuf;
	int len;

	do {
		*cp++ = (char)(n % 10 + '0');
		n /= 10;
	} while (n);

	len = (int)(cp - cbuf);

	do {
		*s++ = *--cp;
	} while (cp > cbuf);

	return (len);
}

void
pr_object_name(char *name, vnode_t *vp, struct vattr *vattr)
{
	char *s = name;
	struct vfs *vfsp;
	struct vfssw *vfsswp;

	if ((vfsp = vp->v_vfsp) != NULL &&
	    ((vfsswp = vfssw + vfsp->vfs_fstype), vfsswp->vsw_name) &&
	    *vfsswp->vsw_name) {
		(void) strcpy(s, vfsswp->vsw_name);
		s += strlen(s);
		*s++ = '.';
	}
	s += pr_u32tos(getmajor(vattr->va_fsid), s, 0);
	*s++ = '.';
	s += pr_u32tos(getminor(vattr->va_fsid), s, 0);
	*s++ = '.';
	s += pr_u64tos(vattr->va_nodeid, s);
	*s++ = '\0';
}

struct seg *
break_seg(proc_t *p)
{
	caddr_t addr = p->p_brkbase;
	struct seg *seg;
	struct vnode *vp;

	if (p->p_brksize != 0)
		addr += p->p_brksize - 1;
	seg = as_segat(p->p_as, addr);
	if (seg != NULL && seg->s_ops == &segvn_ops &&
	    (SEGOP_GETVP(seg, seg->s_base, &vp) != 0 || vp == NULL))
		return (seg);
	return (NULL);
}

/*
 * Implementation of service functions to handle procfs generic chained
 * copyout buffers.
 */
typedef struct pr_iobuf_list {
	list_node_t	piol_link;	/* buffer linkage */
	size_t		piol_size;	/* total size (header + data) */
	size_t		piol_usedsize;	/* amount to copy out from this buf */
} piol_t;

#define	MAPSIZE	(64 * 1024)
#define	PIOL_DATABUF(iol)	((void *)(&(iol)[1]))

void
pr_iol_initlist(list_t *iolhead, size_t itemsize, int n)
{
	piol_t	*iol;
	size_t	initial_size = MIN(1, n) * itemsize;

	list_create(iolhead, sizeof (piol_t), offsetof(piol_t, piol_link));

	ASSERT(list_head(iolhead) == NULL);
	ASSERT(itemsize < MAPSIZE - sizeof (*iol));
	ASSERT(initial_size > 0);

	/*
	 * Someone creating chained copyout buffers may ask for less than
	 * MAPSIZE if the amount of data to be buffered is known to be
	 * smaller than that.
	 * But in order to prevent involuntary self-denial of service,
	 * the requested input size is clamped at MAPSIZE.
	 */
	initial_size = MIN(MAPSIZE, initial_size + sizeof (*iol));
	iol = kmem_alloc(initial_size, KM_SLEEP);
	list_insert_head(iolhead, iol);
	iol->piol_usedsize = 0;
	iol->piol_size = initial_size;
}

void *
pr_iol_newbuf(list_t *iolhead, size_t itemsize)
{
	piol_t	*iol;
	char	*new;

	ASSERT(itemsize < MAPSIZE - sizeof (*iol));
	ASSERT(list_head(iolhead) != NULL);

	iol = (piol_t *)list_tail(iolhead);

	if (iol->piol_size <
	    iol->piol_usedsize + sizeof (*iol) + itemsize) {
		/*
		 * Out of space in the current buffer. Allocate more.
		 */
		piol_t *newiol;

		newiol = kmem_alloc(MAPSIZE, KM_SLEEP);
		newiol->piol_size = MAPSIZE;
		newiol->piol_usedsize = 0;

		list_insert_after(iolhead, iol, newiol);
		iol = list_next(iolhead, iol);
		ASSERT(iol == newiol);
	}
	new = (char *)PIOL_DATABUF(iol) + iol->piol_usedsize;
	iol->piol_usedsize += itemsize;
	bzero(new, itemsize);
	return (new);
}

int
pr_iol_copyout_and_free(list_t *iolhead, caddr_t *tgt, int errin)
{
	int error = errin;
	piol_t	*iol;

	while ((iol = list_head(iolhead)) != NULL) {
		list_remove(iolhead, iol);
		if (!error) {
			if (copyout(PIOL_DATABUF(iol), *tgt,
			    iol->piol_usedsize))
				error = EFAULT;
			*tgt += iol->piol_usedsize;
		}
		kmem_free(iol, iol->piol_size);
	}
	list_destroy(iolhead);

	return (error);
}

int
pr_iol_uiomove_and_free(list_t *iolhead, uio_t *uiop, int errin)
{
	offset_t	off = uiop->uio_offset;
	char		*base;
	size_t		size;
	piol_t		*iol;
	int		error = errin;

	while ((iol = list_head(iolhead)) != NULL) {
		list_remove(iolhead, iol);
		base = PIOL_DATABUF(iol);
		size = iol->piol_usedsize;
		if (off <= size && error == 0 && uiop->uio_resid > 0)
			error = uiomove(base + off, size - off,
			    UIO_READ, uiop);
		off = MAX(0, off - (offset_t)size);
		kmem_free(iol, iol->piol_size);
	}
	list_destroy(iolhead);

	return (error);
}

/*
 * Return an array of structures with memory map information.
 * We allocate here; the caller must deallocate.
 */
int
prgetmap(proc_t *p, int reserved, list_t *iolhead)
{
	struct as *as = p->p_as;
	prmap_t *mp;
	struct seg *seg;
	struct seg *brkseg, *stkseg;
	struct vnode *vp;
	struct vattr vattr;
	uint_t prot;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	/*
	 * Request an initial buffer size that doesn't waste memory
	 * if the address space has only a small number of segments.
	 */
	pr_iol_initlist(iolhead, sizeof (*mp), avl_numnodes(&as->a_segtree));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	brkseg = break_seg(p);
	stkseg = as_segat(as, prgetstackbase(p));

	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, reserved);
		caddr_t saddr, naddr;
		void *tmp = NULL;

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			prot = pr_getprot(seg, reserved, &tmp,
			    &saddr, &naddr, eaddr);
			if (saddr == naddr)
				continue;

			mp = pr_iol_newbuf(iolhead, sizeof (*mp));

			mp->pr_vaddr = (uintptr_t)saddr;
			mp->pr_size = naddr - saddr;
			mp->pr_offset = SEGOP_GETOFFSET(seg, saddr);
			mp->pr_mflags = 0;
			if (prot & PROT_READ)
				mp->pr_mflags |= MA_READ;
			if (prot & PROT_WRITE)
				mp->pr_mflags |= MA_WRITE;
			if (prot & PROT_EXEC)
				mp->pr_mflags |= MA_EXEC;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
				mp->pr_mflags |= MA_SHARED;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_NORESERVE)
				mp->pr_mflags |= MA_NORESERVE;
			if (seg->s_ops == &segspt_shmops ||
			    (seg->s_ops == &segvn_ops &&
			    (SEGOP_GETVP(seg, saddr, &vp) != 0 || vp == NULL)))
				mp->pr_mflags |= MA_ANON;
			if (seg == brkseg)
				mp->pr_mflags |= MA_BREAK;
			else if (seg == stkseg) {
				mp->pr_mflags |= MA_STACK;
				if (reserved) {
					size_t maxstack =
					    ((size_t)p->p_stk_ctl +
					    PAGEOFFSET) & PAGEMASK;
					mp->pr_vaddr =
					    (uintptr_t)prgetstackbase(p) +
					    p->p_stksize - maxstack;
					mp->pr_size = (uintptr_t)naddr -
					    mp->pr_vaddr;
				}
			}
			if (seg->s_ops == &segspt_shmops)
				mp->pr_mflags |= MA_ISM | MA_SHM;
			mp->pr_pagesize = PAGESIZE;

			/*
			 * Manufacture a filename for the "object" directory.
			 */
			vattr.va_mask = AT_FSID|AT_NODEID;
			if (seg->s_ops == &segvn_ops &&
			    SEGOP_GETVP(seg, saddr, &vp) == 0 &&
			    vp != NULL && vp->v_type == VREG &&
			    VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) == 0) {
				if (vp == p->p_exec)
					(void) strcpy(mp->pr_mapname, "a.out");
				else
					pr_object_name(mp->pr_mapname,
					    vp, &vattr);
			}

			/*
			 * Get the SysV shared memory id, if any.
			 */
			if ((mp->pr_mflags & MA_SHARED) && p->p_segacct &&
			    (mp->pr_shmid = shmgetid(p, seg->s_base)) !=
			    SHMID_NONE) {
				if (mp->pr_shmid == SHMID_FREE)
					mp->pr_shmid = -1;

				mp->pr_mflags |= MA_SHM;
			} else {
				mp->pr_shmid = -1;
			}
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (0);
}

#ifdef _SYSCALL32_IMPL
int
prgetmap32(proc_t *p, int reserved, list_t *iolhead)
{
	struct as *as = p->p_as;
	prmap32_t *mp;
	struct seg *seg;
	struct seg *brkseg, *stkseg;
	struct vnode *vp;
	struct vattr vattr;
	uint_t prot;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	/*
	 * Request an initial buffer size that doesn't waste memory
	 * if the address space has only a small number of segments.
	 */
	pr_iol_initlist(iolhead, sizeof (*mp), avl_numnodes(&as->a_segtree));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	brkseg = break_seg(p);
	stkseg = as_segat(as, prgetstackbase(p));

	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, reserved);
		caddr_t saddr, naddr;
		void *tmp = NULL;

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			prot = pr_getprot(seg, reserved, &tmp,
			    &saddr, &naddr, eaddr);
			if (saddr == naddr)
				continue;

			mp = pr_iol_newbuf(iolhead, sizeof (*mp));

			mp->pr_vaddr = (caddr32_t)(uintptr_t)saddr;
			mp->pr_size = (size32_t)(naddr - saddr);
			mp->pr_offset = SEGOP_GETOFFSET(seg, saddr);
			mp->pr_mflags = 0;
			if (prot & PROT_READ)
				mp->pr_mflags |= MA_READ;
			if (prot & PROT_WRITE)
				mp->pr_mflags |= MA_WRITE;
			if (prot & PROT_EXEC)
				mp->pr_mflags |= MA_EXEC;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
				mp->pr_mflags |= MA_SHARED;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_NORESERVE)
				mp->pr_mflags |= MA_NORESERVE;
			if (seg->s_ops == &segspt_shmops ||
			    (seg->s_ops == &segvn_ops &&
			    (SEGOP_GETVP(seg, saddr, &vp) != 0 || vp == NULL)))
				mp->pr_mflags |= MA_ANON;
			if (seg == brkseg)
				mp->pr_mflags |= MA_BREAK;
			else if (seg == stkseg) {
				mp->pr_mflags |= MA_STACK;
				if (reserved) {
					size_t maxstack =
					    ((size_t)p->p_stk_ctl +
					    PAGEOFFSET) & PAGEMASK;
					uintptr_t vaddr =
					    (uintptr_t)prgetstackbase(p) +
					    p->p_stksize - maxstack;
					mp->pr_vaddr = (caddr32_t)vaddr;
					mp->pr_size = (size32_t)
					    ((uintptr_t)naddr - vaddr);
				}
			}
			if (seg->s_ops == &segspt_shmops)
				mp->pr_mflags |= MA_ISM | MA_SHM;
			mp->pr_pagesize = PAGESIZE;

			/*
			 * Manufacture a filename for the "object" directory.
			 */
			vattr.va_mask = AT_FSID|AT_NODEID;
			if (seg->s_ops == &segvn_ops &&
			    SEGOP_GETVP(seg, saddr, &vp) == 0 &&
			    vp != NULL && vp->v_type == VREG &&
			    VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) == 0) {
				if (vp == p->p_exec)
					(void) strcpy(mp->pr_mapname, "a.out");
				else
					pr_object_name(mp->pr_mapname,
					    vp, &vattr);
			}

			/*
			 * Get the SysV shared memory id, if any.
			 */
			if ((mp->pr_mflags & MA_SHARED) && p->p_segacct &&
			    (mp->pr_shmid = shmgetid(p, seg->s_base)) !=
			    SHMID_NONE) {
				if (mp->pr_shmid == SHMID_FREE)
					mp->pr_shmid = -1;

				mp->pr_mflags |= MA_SHM;
			} else {
				mp->pr_shmid = -1;
			}
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (0);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Return the size of the /proc page data file.
 */
size_t
prpdsize(struct as *as)
{
	struct seg *seg;
	size_t size;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	size = sizeof (prpageheader_t);
	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;
		size_t npage;

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			(void) pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if ((npage = (naddr - saddr) / PAGESIZE) != 0)
				size += sizeof (prasmap_t) + round8(npage);
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (size);
}

#ifdef _SYSCALL32_IMPL
size_t
prpdsize32(struct as *as)
{
	struct seg *seg;
	size_t size;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	size = sizeof (prpageheader32_t);
	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;
		size_t npage;

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			(void) pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if ((npage = (naddr - saddr) / PAGESIZE) != 0)
				size += sizeof (prasmap32_t) + round8(npage);
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (size);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Read page data information.
 */
int
prpdread(proc_t *p, uint_t hatid, struct uio *uiop)
{
	struct as *as = p->p_as;
	caddr_t buf;
	size_t size;
	prpageheader_t *php;
	prasmap_t *pmp;
	struct seg *seg;
	int error;

again:
	AS_LOCK_ENTER(as, RW_WRITER);

	if ((seg = AS_SEGFIRST(as)) == NULL) {
		AS_LOCK_EXIT(as);
		return (0);
	}
	size = prpdsize(as);
	if (uiop->uio_resid < size) {
		AS_LOCK_EXIT(as);
		return (E2BIG);
	}

	buf = kmem_zalloc(size, KM_SLEEP);
	php = (prpageheader_t *)buf;
	pmp = (prasmap_t *)(buf + sizeof (prpageheader_t));

	hrt2ts(gethrtime(), &php->pr_tstamp);
	php->pr_nmap = 0;
	php->pr_npage = 0;
	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			struct vnode *vp;
			struct vattr vattr;
			size_t len;
			size_t npage;
			uint_t prot;
			uintptr_t next;

			prot = pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if ((len = (size_t)(naddr - saddr)) == 0)
				continue;
			npage = len / PAGESIZE;
			next = (uintptr_t)(pmp + 1) + round8(npage);
			/*
			 * It's possible that the address space can change
			 * subtlely even though we're holding as->a_lock
			 * due to the nondeterminism of page_exists() in
			 * the presence of asychronously flushed pages or
			 * mapped files whose sizes are changing.
			 * page_exists() may be called indirectly from
			 * pr_getprot() by a SEGOP_INCORE() routine.
			 * If this happens we need to make sure we don't
			 * overrun the buffer whose size we computed based
			 * on the initial iteration through the segments.
			 * Once we've detected an overflow, we need to clean
			 * up the temporary memory allocated in pr_getprot()
			 * and retry. If there's a pending signal, we return
			 * EINTR so that this thread can be dislodged if
			 * a latent bug causes us to spin indefinitely.
			 */
			if (next > (uintptr_t)buf + size) {
				pr_getprot_done(&tmp);
				AS_LOCK_EXIT(as);

				kmem_free(buf, size);

				if (ISSIG(curthread, JUSTLOOKING))
					return (EINTR);

				goto again;
			}

			php->pr_nmap++;
			php->pr_npage += npage;
			pmp->pr_vaddr = (uintptr_t)saddr;
			pmp->pr_npage = npage;
			pmp->pr_offset = SEGOP_GETOFFSET(seg, saddr);
			pmp->pr_mflags = 0;
			if (prot & PROT_READ)
				pmp->pr_mflags |= MA_READ;
			if (prot & PROT_WRITE)
				pmp->pr_mflags |= MA_WRITE;
			if (prot & PROT_EXEC)
				pmp->pr_mflags |= MA_EXEC;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
				pmp->pr_mflags |= MA_SHARED;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_NORESERVE)
				pmp->pr_mflags |= MA_NORESERVE;
			if (seg->s_ops == &segspt_shmops ||
			    (seg->s_ops == &segvn_ops &&
			    (SEGOP_GETVP(seg, saddr, &vp) != 0 || vp == NULL)))
				pmp->pr_mflags |= MA_ANON;
			if (seg->s_ops == &segspt_shmops)
				pmp->pr_mflags |= MA_ISM | MA_SHM;
			pmp->pr_pagesize = PAGESIZE;
			/*
			 * Manufacture a filename for the "object" directory.
			 */
			vattr.va_mask = AT_FSID|AT_NODEID;
			if (seg->s_ops == &segvn_ops &&
			    SEGOP_GETVP(seg, saddr, &vp) == 0 &&
			    vp != NULL && vp->v_type == VREG &&
			    VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) == 0) {
				if (vp == p->p_exec)
					(void) strcpy(pmp->pr_mapname, "a.out");
				else
					pr_object_name(pmp->pr_mapname,
					    vp, &vattr);
			}

			/*
			 * Get the SysV shared memory id, if any.
			 */
			if ((pmp->pr_mflags & MA_SHARED) && p->p_segacct &&
			    (pmp->pr_shmid = shmgetid(p, seg->s_base)) !=
			    SHMID_NONE) {
				if (pmp->pr_shmid == SHMID_FREE)
					pmp->pr_shmid = -1;

				pmp->pr_mflags |= MA_SHM;
			} else {
				pmp->pr_shmid = -1;
			}

			hat_getstat(as, saddr, len, hatid,
			    (char *)(pmp + 1), HAT_SYNC_ZERORM);
			pmp = (prasmap_t *)next;
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	AS_LOCK_EXIT(as);

	ASSERT((uintptr_t)pmp <= (uintptr_t)buf + size);
	error = uiomove(buf, (caddr_t)pmp - buf, UIO_READ, uiop);
	kmem_free(buf, size);

	return (error);
}

#ifdef _SYSCALL32_IMPL
int
prpdread32(proc_t *p, uint_t hatid, struct uio *uiop)
{
	struct as *as = p->p_as;
	caddr_t buf;
	size_t size;
	prpageheader32_t *php;
	prasmap32_t *pmp;
	struct seg *seg;
	int error;

again:
	AS_LOCK_ENTER(as, RW_WRITER);

	if ((seg = AS_SEGFIRST(as)) == NULL) {
		AS_LOCK_EXIT(as);
		return (0);
	}
	size = prpdsize32(as);
	if (uiop->uio_resid < size) {
		AS_LOCK_EXIT(as);
		return (E2BIG);
	}

	buf = kmem_zalloc(size, KM_SLEEP);
	php = (prpageheader32_t *)buf;
	pmp = (prasmap32_t *)(buf + sizeof (prpageheader32_t));

	hrt2ts32(gethrtime(), &php->pr_tstamp);
	php->pr_nmap = 0;
	php->pr_npage = 0;
	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			struct vnode *vp;
			struct vattr vattr;
			size_t len;
			size_t npage;
			uint_t prot;
			uintptr_t next;

			prot = pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if ((len = (size_t)(naddr - saddr)) == 0)
				continue;
			npage = len / PAGESIZE;
			next = (uintptr_t)(pmp + 1) + round8(npage);
			/*
			 * It's possible that the address space can change
			 * subtlely even though we're holding as->a_lock
			 * due to the nondeterminism of page_exists() in
			 * the presence of asychronously flushed pages or
			 * mapped files whose sizes are changing.
			 * page_exists() may be called indirectly from
			 * pr_getprot() by a SEGOP_INCORE() routine.
			 * If this happens we need to make sure we don't
			 * overrun the buffer whose size we computed based
			 * on the initial iteration through the segments.
			 * Once we've detected an overflow, we need to clean
			 * up the temporary memory allocated in pr_getprot()
			 * and retry. If there's a pending signal, we return
			 * EINTR so that this thread can be dislodged if
			 * a latent bug causes us to spin indefinitely.
			 */
			if (next > (uintptr_t)buf + size) {
				pr_getprot_done(&tmp);
				AS_LOCK_EXIT(as);

				kmem_free(buf, size);

				if (ISSIG(curthread, JUSTLOOKING))
					return (EINTR);

				goto again;
			}

			php->pr_nmap++;
			php->pr_npage += npage;
			pmp->pr_vaddr = (caddr32_t)(uintptr_t)saddr;
			pmp->pr_npage = (size32_t)npage;
			pmp->pr_offset = SEGOP_GETOFFSET(seg, saddr);
			pmp->pr_mflags = 0;
			if (prot & PROT_READ)
				pmp->pr_mflags |= MA_READ;
			if (prot & PROT_WRITE)
				pmp->pr_mflags |= MA_WRITE;
			if (prot & PROT_EXEC)
				pmp->pr_mflags |= MA_EXEC;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
				pmp->pr_mflags |= MA_SHARED;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_NORESERVE)
				pmp->pr_mflags |= MA_NORESERVE;
			if (seg->s_ops == &segspt_shmops ||
			    (seg->s_ops == &segvn_ops &&
			    (SEGOP_GETVP(seg, saddr, &vp) != 0 || vp == NULL)))
				pmp->pr_mflags |= MA_ANON;
			if (seg->s_ops == &segspt_shmops)
				pmp->pr_mflags |= MA_ISM | MA_SHM;
			pmp->pr_pagesize = PAGESIZE;
			/*
			 * Manufacture a filename for the "object" directory.
			 */
			vattr.va_mask = AT_FSID|AT_NODEID;
			if (seg->s_ops == &segvn_ops &&
			    SEGOP_GETVP(seg, saddr, &vp) == 0 &&
			    vp != NULL && vp->v_type == VREG &&
			    VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) == 0) {
				if (vp == p->p_exec)
					(void) strcpy(pmp->pr_mapname, "a.out");
				else
					pr_object_name(pmp->pr_mapname,
					    vp, &vattr);
			}

			/*
			 * Get the SysV shared memory id, if any.
			 */
			if ((pmp->pr_mflags & MA_SHARED) && p->p_segacct &&
			    (pmp->pr_shmid = shmgetid(p, seg->s_base)) !=
			    SHMID_NONE) {
				if (pmp->pr_shmid == SHMID_FREE)
					pmp->pr_shmid = -1;

				pmp->pr_mflags |= MA_SHM;
			} else {
				pmp->pr_shmid = -1;
			}

			hat_getstat(as, saddr, len, hatid,
			    (char *)(pmp + 1), HAT_SYNC_ZERORM);
			pmp = (prasmap32_t *)next;
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	AS_LOCK_EXIT(as);

	ASSERT((uintptr_t)pmp <= (uintptr_t)buf + size);
	error = uiomove(buf, (caddr_t)pmp - buf, UIO_READ, uiop);
	kmem_free(buf, size);

	return (error);
}
#endif	/* _SYSCALL32_IMPL */

ushort_t
prgetpctcpu(uint64_t pct)
{
	/*
	 * The value returned will be relevant in the zone of the examiner,
	 * which may not be the same as the zone which performed the procfs
	 * mount.
	 */
	int nonline = zone_ncpus_online_get(curproc->p_zone);

	/*
	 * Prorate over online cpus so we don't exceed 100%
	 */
	if (nonline > 1)
		pct /= nonline;
	pct >>= 16;		/* convert to 16-bit scaled integer */
	if (pct > 0x8000)	/* might happen, due to rounding */
		pct = 0x8000;
	return ((ushort_t)pct);
}

/*
 * Return information used by ps(1).
 */
void
prgetpsinfo(proc_t *p, psinfo_t *psp)
{
	kthread_t *t;
	struct cred *cred;
	hrtime_t hrutime, hrstime;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if ((t = prchoose(p)) == NULL)	/* returns locked thread */
		bzero(psp, sizeof (*psp));
	else {
		thread_unlock(t);
		bzero(psp, sizeof (*psp) - sizeof (psp->pr_lwp));
	}

	/*
	 * only export SSYS and SMSACCT; everything else is off-limits to
	 * userland apps.
	 */
	psp->pr_flag = p->p_flag & (SSYS | SMSACCT);
	psp->pr_nlwp = p->p_lwpcnt;
	psp->pr_nzomb = p->p_zombcnt;
	mutex_enter(&p->p_crlock);
	cred = p->p_cred;
	psp->pr_uid = crgetruid(cred);
	psp->pr_euid = crgetuid(cred);
	psp->pr_gid = crgetrgid(cred);
	psp->pr_egid = crgetgid(cred);
	mutex_exit(&p->p_crlock);
	psp->pr_pid = p->p_pid;
	if (curproc->p_zone->zone_id != GLOBAL_ZONEID &&
	    (p->p_flag & SZONETOP)) {
		ASSERT(p->p_zone->zone_id != GLOBAL_ZONEID);
		/*
		 * Inside local zones, fake zsched's pid as parent pids for
		 * processes which reference processes outside of the zone.
		 */
		psp->pr_ppid = curproc->p_zone->zone_zsched->p_pid;
	} else {
		psp->pr_ppid = p->p_ppid;
	}
	psp->pr_pgid = p->p_pgrp;
	psp->pr_sid = p->p_sessp->s_sid;
	psp->pr_taskid = p->p_task->tk_tkid;
	psp->pr_projid = p->p_task->tk_proj->kpj_id;
	psp->pr_poolid = p->p_pool->pool_id;
	psp->pr_zoneid = p->p_zone->zone_id;
	if ((psp->pr_contract = PRCTID(p)) == 0)
		psp->pr_contract = -1;
	psp->pr_addr = (uintptr_t)prgetpsaddr(p);
	switch (p->p_model) {
	case DATAMODEL_ILP32:
		psp->pr_dmodel = PR_MODEL_ILP32;
		break;
	case DATAMODEL_LP64:
		psp->pr_dmodel = PR_MODEL_LP64;
		break;
	}
	hrutime = mstate_aggr_state(p, LMS_USER);
	hrstime = mstate_aggr_state(p, LMS_SYSTEM);
	hrt2ts((hrutime + hrstime), &psp->pr_time);
	TICK_TO_TIMESTRUC(p->p_cutime + p->p_cstime, &psp->pr_ctime);

	if (t == NULL) {
		int wcode = p->p_wcode;		/* must be atomic read */

		if (wcode)
			psp->pr_wstat = wstat(wcode, p->p_wdata);
		psp->pr_ttydev = PRNODEV;
		psp->pr_lwp.pr_state = SZOMB;
		psp->pr_lwp.pr_sname = 'Z';
		psp->pr_lwp.pr_bindpro = PBIND_NONE;
		psp->pr_lwp.pr_bindpset = PS_NONE;
	} else {
		user_t *up = PTOU(p);
		struct as *as;
		dev_t d;
		extern dev_t rwsconsdev, rconsdev, uconsdev;

		d = cttydev(p);
		/*
		 * If the controlling terminal is the real
		 * or workstation console device, map to what the
		 * user thinks is the console device. Handle case when
		 * rwsconsdev or rconsdev is set to NODEV for Starfire.
		 */
		if ((d == rwsconsdev || d == rconsdev) && d != NODEV)
			d = uconsdev;
		psp->pr_ttydev = (d == NODEV) ? PRNODEV : d;
		psp->pr_start = up->u_start;
		bcopy(up->u_comm, psp->pr_fname,
		    MIN(sizeof (up->u_comm), sizeof (psp->pr_fname)-1));
		bcopy(up->u_psargs, psp->pr_psargs,
		    MIN(PRARGSZ-1, PSARGSZ));
		psp->pr_argc = up->u_argc;
		psp->pr_argv = up->u_argv;
		psp->pr_envp = up->u_envp;

		/* get the chosen lwp's lwpsinfo */
		prgetlwpsinfo(t, &psp->pr_lwp);

		/* compute %cpu for the process */
		if (p->p_lwpcnt == 1)
			psp->pr_pctcpu = psp->pr_lwp.pr_pctcpu;
		else {
			uint64_t pct = 0;
			hrtime_t cur_time = gethrtime_unscaled();

			t = p->p_tlist;
			do {
				pct += cpu_update_pct(t, cur_time);
			} while ((t = t->t_forw) != p->p_tlist);

			psp->pr_pctcpu = prgetpctcpu(pct);
		}
		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas) {
			psp->pr_size = 0;
			psp->pr_rssize = 0;
		} else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, RW_READER);
			psp->pr_size = btopr(as->a_resvsize) *
			    (PAGESIZE / 1024);
			psp->pr_rssize = rm_asrss(as) * (PAGESIZE / 1024);
			psp->pr_pctmem = rm_pctmemory(as);
			AS_LOCK_EXIT(as);
			mutex_enter(&p->p_lock);
		}
	}
}

#ifdef _SYSCALL32_IMPL
void
prgetpsinfo32(proc_t *p, psinfo32_t *psp)
{
	kthread_t *t;
	struct cred *cred;
	hrtime_t hrutime, hrstime;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if ((t = prchoose(p)) == NULL)	/* returns locked thread */
		bzero(psp, sizeof (*psp));
	else {
		thread_unlock(t);
		bzero(psp, sizeof (*psp) - sizeof (psp->pr_lwp));
	}

	/*
	 * only export SSYS and SMSACCT; everything else is off-limits to
	 * userland apps.
	 */
	psp->pr_flag = p->p_flag & (SSYS | SMSACCT);
	psp->pr_nlwp = p->p_lwpcnt;
	psp->pr_nzomb = p->p_zombcnt;
	mutex_enter(&p->p_crlock);
	cred = p->p_cred;
	psp->pr_uid = crgetruid(cred);
	psp->pr_euid = crgetuid(cred);
	psp->pr_gid = crgetrgid(cred);
	psp->pr_egid = crgetgid(cred);
	mutex_exit(&p->p_crlock);
	psp->pr_pid = p->p_pid;
	if (curproc->p_zone->zone_id != GLOBAL_ZONEID &&
	    (p->p_flag & SZONETOP)) {
		ASSERT(p->p_zone->zone_id != GLOBAL_ZONEID);
		/*
		 * Inside local zones, fake zsched's pid as parent pids for
		 * processes which reference processes outside of the zone.
		 */
		psp->pr_ppid = curproc->p_zone->zone_zsched->p_pid;
	} else {
		psp->pr_ppid = p->p_ppid;
	}
	psp->pr_pgid = p->p_pgrp;
	psp->pr_sid = p->p_sessp->s_sid;
	psp->pr_taskid = p->p_task->tk_tkid;
	psp->pr_projid = p->p_task->tk_proj->kpj_id;
	psp->pr_poolid = p->p_pool->pool_id;
	psp->pr_zoneid = p->p_zone->zone_id;
	if ((psp->pr_contract = PRCTID(p)) == 0)
		psp->pr_contract = -1;
	psp->pr_addr = 0;	/* cannot represent 64-bit addr in 32 bits */
	switch (p->p_model) {
	case DATAMODEL_ILP32:
		psp->pr_dmodel = PR_MODEL_ILP32;
		break;
	case DATAMODEL_LP64:
		psp->pr_dmodel = PR_MODEL_LP64;
		break;
	}
	hrutime = mstate_aggr_state(p, LMS_USER);
	hrstime = mstate_aggr_state(p, LMS_SYSTEM);
	hrt2ts32(hrutime + hrstime, &psp->pr_time);
	TICK_TO_TIMESTRUC32(p->p_cutime + p->p_cstime, &psp->pr_ctime);

	if (t == NULL) {
		extern int wstat(int, int);	/* needs a header file */
		int wcode = p->p_wcode;		/* must be atomic read */

		if (wcode)
			psp->pr_wstat = wstat(wcode, p->p_wdata);
		psp->pr_ttydev = PRNODEV32;
		psp->pr_lwp.pr_state = SZOMB;
		psp->pr_lwp.pr_sname = 'Z';
	} else {
		user_t *up = PTOU(p);
		struct as *as;
		dev_t d;
		extern dev_t rwsconsdev, rconsdev, uconsdev;

		d = cttydev(p);
		/*
		 * If the controlling terminal is the real
		 * or workstation console device, map to what the
		 * user thinks is the console device. Handle case when
		 * rwsconsdev or rconsdev is set to NODEV for Starfire.
		 */
		if ((d == rwsconsdev || d == rconsdev) && d != NODEV)
			d = uconsdev;
		(void) cmpldev(&psp->pr_ttydev, d);
		TIMESPEC_TO_TIMESPEC32(&psp->pr_start, &up->u_start);
		bcopy(up->u_comm, psp->pr_fname,
		    MIN(sizeof (up->u_comm), sizeof (psp->pr_fname)-1));
		bcopy(up->u_psargs, psp->pr_psargs,
		    MIN(PRARGSZ-1, PSARGSZ));
		psp->pr_argc = up->u_argc;
		psp->pr_argv = (caddr32_t)up->u_argv;
		psp->pr_envp = (caddr32_t)up->u_envp;

		/* get the chosen lwp's lwpsinfo */
		prgetlwpsinfo32(t, &psp->pr_lwp);

		/* compute %cpu for the process */
		if (p->p_lwpcnt == 1)
			psp->pr_pctcpu = psp->pr_lwp.pr_pctcpu;
		else {
			uint64_t pct = 0;
			hrtime_t cur_time;

			t = p->p_tlist;
			cur_time = gethrtime_unscaled();
			do {
				pct += cpu_update_pct(t, cur_time);
			} while ((t = t->t_forw) != p->p_tlist);

			psp->pr_pctcpu = prgetpctcpu(pct);
		}
		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas) {
			psp->pr_size = 0;
			psp->pr_rssize = 0;
		} else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, RW_READER);
			psp->pr_size = (size32_t)
			    (btopr(as->a_resvsize) * (PAGESIZE / 1024));
			psp->pr_rssize = (size32_t)
			    (rm_asrss(as) * (PAGESIZE / 1024));
			psp->pr_pctmem = rm_pctmemory(as);
			AS_LOCK_EXIT(as);
			mutex_enter(&p->p_lock);
		}
	}

	/*
	 * If we are looking at an LP64 process, zero out
	 * the fields that cannot be represented in ILP32.
	 */
	if (p->p_model != DATAMODEL_ILP32) {
		psp->pr_size = 0;
		psp->pr_rssize = 0;
		psp->pr_argv = 0;
		psp->pr_envp = 0;
	}
}

#endif	/* _SYSCALL32_IMPL */

void
prgetlwpsinfo(kthread_t *t, lwpsinfo_t *psp)
{
	klwp_t *lwp = ttolwp(t);
	sobj_ops_t *sobj;
	char c, state;
	uint64_t pct;
	int retval, niceval;
	hrtime_t hrutime, hrstime;

	ASSERT(MUTEX_HELD(&ttoproc(t)->p_lock));

	bzero(psp, sizeof (*psp));

	psp->pr_flag = 0;	/* lwpsinfo_t.pr_flag is deprecated */
	psp->pr_lwpid = t->t_tid;
	psp->pr_addr = (uintptr_t)t;
	psp->pr_wchan = (uintptr_t)t->t_wchan;

	/* map the thread state enum into a process state enum */
	state = VSTOPPED(t) ? TS_STOPPED : t->t_state;
	switch (state) {
	case TS_SLEEP:		state = SSLEEP;		c = 'S';	break;
	case TS_RUN:		state = SRUN;		c = 'R';	break;
	case TS_ONPROC:		state = SONPROC;	c = 'O';	break;
	case TS_ZOMB:		state = SZOMB;		c = 'Z';	break;
	case TS_STOPPED:	state = SSTOP;		c = 'T';	break;
	case TS_WAIT:		state = SWAIT;		c = 'W';	break;
	default:		state = 0;		c = '?';	break;
	}
	psp->pr_state = state;
	psp->pr_sname = c;
	if ((sobj = t->t_sobj_ops) != NULL)
		psp->pr_stype = SOBJ_TYPE(sobj);
	retval = CL_DONICE(t, NULL, 0, &niceval);
	if (retval == 0) {
		psp->pr_oldpri = v.v_maxsyspri - t->t_pri;
		psp->pr_nice = niceval + NZERO;
	}
	psp->pr_syscall = t->t_sysnum;
	psp->pr_pri = t->t_pri;
	psp->pr_start.tv_sec = t->t_start;
	psp->pr_start.tv_nsec = 0L;
	hrutime = lwp->lwp_mstate.ms_acct[LMS_USER];
	scalehrtime(&hrutime);
	hrstime = lwp->lwp_mstate.ms_acct[LMS_SYSTEM] +
	    lwp->lwp_mstate.ms_acct[LMS_TRAP];
	scalehrtime(&hrstime);
	hrt2ts(hrutime + hrstime, &psp->pr_time);
	/* compute %cpu for the lwp */
	pct = cpu_update_pct(t, gethrtime_unscaled());
	psp->pr_pctcpu = prgetpctcpu(pct);
	psp->pr_cpu = (psp->pr_pctcpu*100 + 0x6000) >> 15;	/* [0..99] */
	if (psp->pr_cpu > 99)
		psp->pr_cpu = 99;

	(void) strncpy(psp->pr_clname, sclass[t->t_cid].cl_name,
	    sizeof (psp->pr_clname) - 1);
	bzero(psp->pr_name, sizeof (psp->pr_name));	/* XXX ??? */
	psp->pr_onpro = t->t_cpu->cpu_id;
	psp->pr_bindpro = t->t_bind_cpu;
	psp->pr_bindpset = t->t_bind_pset;
	psp->pr_lgrp = t->t_lpl->lpl_lgrpid;
}

#ifdef _SYSCALL32_IMPL
void
prgetlwpsinfo32(kthread_t *t, lwpsinfo32_t *psp)
{
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	sobj_ops_t *sobj;
	char c, state;
	uint64_t pct;
	int retval, niceval;
	hrtime_t hrutime, hrstime;

	ASSERT(MUTEX_HELD(&p->p_lock));

	bzero(psp, sizeof (*psp));

	psp->pr_flag = 0;	/* lwpsinfo_t.pr_flag is deprecated */
	psp->pr_lwpid = t->t_tid;
	psp->pr_addr = 0;	/* cannot represent 64-bit addr in 32 bits */
	psp->pr_wchan = 0;	/* cannot represent 64-bit addr in 32 bits */

	/* map the thread state enum into a process state enum */
	state = VSTOPPED(t) ? TS_STOPPED : t->t_state;
	switch (state) {
	case TS_SLEEP:		state = SSLEEP;		c = 'S';	break;
	case TS_RUN:		state = SRUN;		c = 'R';	break;
	case TS_ONPROC:		state = SONPROC;	c = 'O';	break;
	case TS_ZOMB:		state = SZOMB;		c = 'Z';	break;
	case TS_STOPPED:	state = SSTOP;		c = 'T';	break;
	case TS_WAIT:		state = SWAIT;		c = 'W';	break;
	default:		state = 0;		c = '?';	break;
	}
	psp->pr_state = state;
	psp->pr_sname = c;
	if ((sobj = t->t_sobj_ops) != NULL)
		psp->pr_stype = SOBJ_TYPE(sobj);
	retval = CL_DONICE(t, NULL, 0, &niceval);
	if (retval == 0) {
		psp->pr_oldpri = v.v_maxsyspri - t->t_pri;
		psp->pr_nice = niceval + NZERO;
	} else {
		psp->pr_oldpri = 0;
		psp->pr_nice = 0;
	}
	psp->pr_syscall = t->t_sysnum;
	psp->pr_pri = t->t_pri;
	psp->pr_start.tv_sec = (time32_t)t->t_start;
	psp->pr_start.tv_nsec = 0L;
	hrutime = lwp->lwp_mstate.ms_acct[LMS_USER];
	scalehrtime(&hrutime);
	hrstime = lwp->lwp_mstate.ms_acct[LMS_SYSTEM] +
	    lwp->lwp_mstate.ms_acct[LMS_TRAP];
	scalehrtime(&hrstime);
	hrt2ts32(hrutime + hrstime, &psp->pr_time);
	/* compute %cpu for the lwp */
	pct = cpu_update_pct(t, gethrtime_unscaled());
	psp->pr_pctcpu = prgetpctcpu(pct);
	psp->pr_cpu = (psp->pr_pctcpu*100 + 0x6000) >> 15;	/* [0..99] */
	if (psp->pr_cpu > 99)
		psp->pr_cpu = 99;

	(void) strncpy(psp->pr_clname, sclass[t->t_cid].cl_name,
	    sizeof (psp->pr_clname) - 1);
	bzero(psp->pr_name, sizeof (psp->pr_name));	/* XXX ??? */
	psp->pr_onpro = t->t_cpu->cpu_id;
	psp->pr_bindpro = t->t_bind_cpu;
	psp->pr_bindpset = t->t_bind_pset;
	psp->pr_lgrp = t->t_lpl->lpl_lgrpid;
}
#endif	/* _SYSCALL32_IMPL */

#ifdef _SYSCALL32_IMPL

#define	PR_COPY_FIELD(s, d, field)	 d->field = s->field

#define	PR_COPY_FIELD_ILP32(s, d, field)				\
	if (s->pr_dmodel == PR_MODEL_ILP32) {			\
		d->field = s->field;				\
	}

#define	PR_COPY_TIMESPEC(s, d, field)				\
	TIMESPEC_TO_TIMESPEC32(&d->field, &s->field);

#define	PR_COPY_BUF(s, d, field)	 			\
	bcopy(s->field, d->field, sizeof (d->field));

#define	PR_IGNORE_FIELD(s, d, field)

void
lwpsinfo_kto32(const struct lwpsinfo *src, struct lwpsinfo32 *dest)
{
	bzero(dest, sizeof (*dest));

	PR_COPY_FIELD(src, dest, pr_flag);
	PR_COPY_FIELD(src, dest, pr_lwpid);
	PR_IGNORE_FIELD(src, dest, pr_addr);
	PR_IGNORE_FIELD(src, dest, pr_wchan);
	PR_COPY_FIELD(src, dest, pr_stype);
	PR_COPY_FIELD(src, dest, pr_state);
	PR_COPY_FIELD(src, dest, pr_sname);
	PR_COPY_FIELD(src, dest, pr_nice);
	PR_COPY_FIELD(src, dest, pr_syscall);
	PR_COPY_FIELD(src, dest, pr_oldpri);
	PR_COPY_FIELD(src, dest, pr_cpu);
	PR_COPY_FIELD(src, dest, pr_pri);
	PR_COPY_FIELD(src, dest, pr_pctcpu);
	PR_COPY_TIMESPEC(src, dest, pr_start);
	PR_COPY_BUF(src, dest, pr_clname);
	PR_COPY_BUF(src, dest, pr_name);
	PR_COPY_FIELD(src, dest, pr_onpro);
	PR_COPY_FIELD(src, dest, pr_bindpro);
	PR_COPY_FIELD(src, dest, pr_bindpset);
	PR_COPY_FIELD(src, dest, pr_lgrp);
}

void
psinfo_kto32(const struct psinfo *src, struct psinfo32 *dest)
{
	bzero(dest, sizeof (*dest));

	PR_COPY_FIELD(src, dest, pr_flag);
	PR_COPY_FIELD(src, dest, pr_nlwp);
	PR_COPY_FIELD(src, dest, pr_pid);
	PR_COPY_FIELD(src, dest, pr_ppid);
	PR_COPY_FIELD(src, dest, pr_pgid);
	PR_COPY_FIELD(src, dest, pr_sid);
	PR_COPY_FIELD(src, dest, pr_uid);
	PR_COPY_FIELD(src, dest, pr_euid);
	PR_COPY_FIELD(src, dest, pr_gid);
	PR_COPY_FIELD(src, dest, pr_egid);
	PR_IGNORE_FIELD(src, dest, pr_addr);
	PR_COPY_FIELD_ILP32(src, dest, pr_size);
	PR_COPY_FIELD_ILP32(src, dest, pr_rssize);
	PR_COPY_FIELD(src, dest, pr_ttydev);
	PR_COPY_FIELD(src, dest, pr_pctcpu);
	PR_COPY_FIELD(src, dest, pr_pctmem);
	PR_COPY_TIMESPEC(src, dest, pr_start);
	PR_COPY_TIMESPEC(src, dest, pr_time);
	PR_COPY_TIMESPEC(src, dest, pr_ctime);
	PR_COPY_BUF(src, dest, pr_fname);
	PR_COPY_BUF(src, dest, pr_psargs);
	PR_COPY_FIELD(src, dest, pr_wstat);
	PR_COPY_FIELD(src, dest, pr_argc);
	PR_COPY_FIELD_ILP32(src, dest, pr_argv);
	PR_COPY_FIELD_ILP32(src, dest, pr_envp);
	PR_COPY_FIELD(src, dest, pr_dmodel);
	PR_COPY_FIELD(src, dest, pr_taskid);
	PR_COPY_FIELD(src, dest, pr_projid);
	PR_COPY_FIELD(src, dest, pr_nzomb);
	PR_COPY_FIELD(src, dest, pr_poolid);
	PR_COPY_FIELD(src, dest, pr_contract);
	PR_COPY_FIELD(src, dest, pr_poolid);
	PR_COPY_FIELD(src, dest, pr_poolid);

	lwpsinfo_kto32(&src->pr_lwp, &dest->pr_lwp);
}

#undef	PR_COPY_FIELD
#undef	PR_COPY_FIELD_ILP32
#undef	PR_COPY_TIMESPEC
#undef	PR_COPY_BUF
#undef	PR_IGNORE_FIELD

#endif	/* _SYSCALL32_IMPL */

/*
 * This used to get called when microstate accounting was disabled but
 * microstate information was requested.  Since Microstate accounting is on
 * regardless of the proc flags, this simply makes it appear to procfs that
 * microstate accounting is on.  This is relatively meaningless since you
 * can't turn it off, but this is here for the sake of appearances.
 */

/*ARGSUSED*/
void
estimate_msacct(kthread_t *t, hrtime_t curtime)
{
	proc_t *p;

	if (t == NULL)
		return;

	p = ttoproc(t);
	ASSERT(MUTEX_HELD(&p->p_lock));

	/*
	 * A system process (p0) could be referenced if the thread is
	 * in the process of exiting.  Don't turn on microstate accounting
	 * in that case.
	 */
	if (p->p_flag & SSYS)
		return;

	/*
	 * Loop through all the LWPs (kernel threads) in the process.
	 */
	t = p->p_tlist;
	do {
		t->t_proc_flag |= TP_MSACCT;
	} while ((t = t->t_forw) != p->p_tlist);

	p->p_flag |= SMSACCT;			/* set process-wide MSACCT */
}

/*
 * It's not really possible to disable microstate accounting anymore.
 * However, this routine simply turns off the ms accounting flags in a process
 * This way procfs can still pretend to turn microstate accounting on and
 * off for a process, but it actually doesn't do anything.  This is
 * a neutered form of preemptive idiot-proofing.
 */
void
disable_msacct(proc_t *p)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));

	p->p_flag &= ~SMSACCT;		/* clear process-wide MSACCT */
	/*
	 * Loop through all the LWPs (kernel threads) in the process.
	 */
	if ((t = p->p_tlist) != NULL) {
		do {
			/* clear per-thread flag */
			t->t_proc_flag &= ~TP_MSACCT;
		} while ((t = t->t_forw) != p->p_tlist);
	}
}

/*
 * Return resource usage information.
 */
void
prgetusage(kthread_t *t, prhusage_t *pup)
{
	klwp_t *lwp = ttolwp(t);
	hrtime_t *mstimep;
	struct mstate *ms = &lwp->lwp_mstate;
	int state;
	int i;
	hrtime_t curtime;
	hrtime_t waitrq;
	hrtime_t tmp1;

	curtime = gethrtime_unscaled();

	pup->pr_lwpid	= t->t_tid;
	pup->pr_count	= 1;
	pup->pr_create	= ms->ms_start;
	pup->pr_term    = ms->ms_term;
	scalehrtime(&pup->pr_create);
	scalehrtime(&pup->pr_term);
	if (ms->ms_term == 0) {
		pup->pr_rtime = curtime - ms->ms_start;
		scalehrtime(&pup->pr_rtime);
	} else {
		pup->pr_rtime = ms->ms_term - ms->ms_start;
		scalehrtime(&pup->pr_rtime);
	}


	pup->pr_utime    = ms->ms_acct[LMS_USER];
	pup->pr_stime    = ms->ms_acct[LMS_SYSTEM];
	pup->pr_ttime    = ms->ms_acct[LMS_TRAP];
	pup->pr_tftime   = ms->ms_acct[LMS_TFAULT];
	pup->pr_dftime   = ms->ms_acct[LMS_DFAULT];
	pup->pr_kftime   = ms->ms_acct[LMS_KFAULT];
	pup->pr_ltime    = ms->ms_acct[LMS_USER_LOCK];
	pup->pr_slptime  = ms->ms_acct[LMS_SLEEP];
	pup->pr_wtime    = ms->ms_acct[LMS_WAIT_CPU];
	pup->pr_stoptime = ms->ms_acct[LMS_STOPPED];

	prscaleusage(pup);

	/*
	 * Adjust for time waiting in the dispatcher queue.
	 */
	waitrq = t->t_waitrq;	/* hopefully atomic */
	if (waitrq != 0) {
		if (waitrq > curtime) {
			curtime = gethrtime_unscaled();
		}
		tmp1 = curtime - waitrq;
		scalehrtime(&tmp1);
		pup->pr_wtime += tmp1;
		curtime = waitrq;
	}

	/*
	 * Adjust for time spent in current microstate.
	 */
	if (ms->ms_state_start > curtime) {
		curtime = gethrtime_unscaled();
	}

	i = 0;
	do {
		switch (state = t->t_mstate) {
		case LMS_SLEEP:
			/*
			 * Update the timer for the current sleep state.
			 */
			switch (state = ms->ms_prev) {
			case LMS_TFAULT:
			case LMS_DFAULT:
			case LMS_KFAULT:
			case LMS_USER_LOCK:
				break;
			default:
				state = LMS_SLEEP;
				break;
			}
			break;
		case LMS_TFAULT:
		case LMS_DFAULT:
		case LMS_KFAULT:
		case LMS_USER_LOCK:
			state = LMS_SYSTEM;
			break;
		}
		switch (state) {
		case LMS_USER:		mstimep = &pup->pr_utime;	break;
		case LMS_SYSTEM:	mstimep = &pup->pr_stime;	break;
		case LMS_TRAP:		mstimep = &pup->pr_ttime;	break;
		case LMS_TFAULT:	mstimep = &pup->pr_tftime;	break;
		case LMS_DFAULT:	mstimep = &pup->pr_dftime;	break;
		case LMS_KFAULT:	mstimep = &pup->pr_kftime;	break;
		case LMS_USER_LOCK:	mstimep = &pup->pr_ltime;	break;
		case LMS_SLEEP:		mstimep = &pup->pr_slptime;	break;
		case LMS_WAIT_CPU:	mstimep = &pup->pr_wtime;	break;
		case LMS_STOPPED:	mstimep = &pup->pr_stoptime;	break;
		default:		panic("prgetusage: unknown microstate");
		}
		tmp1 = curtime - ms->ms_state_start;
		if (tmp1 < 0) {
			curtime = gethrtime_unscaled();
			i++;
			continue;
		}
		scalehrtime(&tmp1);
	} while (tmp1 < 0 && i < MAX_ITERS_SPIN);

	*mstimep += tmp1;

	/* update pup timestamp */
	pup->pr_tstamp = curtime;
	scalehrtime(&pup->pr_tstamp);

	/*
	 * Resource usage counters.
	 */
	pup->pr_minf  = lwp->lwp_ru.minflt;
	pup->pr_majf  = lwp->lwp_ru.majflt;
	pup->pr_nswap = lwp->lwp_ru.nswap;
	pup->pr_inblk = lwp->lwp_ru.inblock;
	pup->pr_oublk = lwp->lwp_ru.oublock;
	pup->pr_msnd  = lwp->lwp_ru.msgsnd;
	pup->pr_mrcv  = lwp->lwp_ru.msgrcv;
	pup->pr_sigs  = lwp->lwp_ru.nsignals;
	pup->pr_vctx  = lwp->lwp_ru.nvcsw;
	pup->pr_ictx  = lwp->lwp_ru.nivcsw;
	pup->pr_sysc  = lwp->lwp_ru.sysc;
	pup->pr_ioch  = lwp->lwp_ru.ioch;
}

/*
 * Convert ms_acct stats from unscaled high-res time to nanoseconds
 */
void
prscaleusage(prhusage_t *usg)
{
	scalehrtime(&usg->pr_utime);
	scalehrtime(&usg->pr_stime);
	scalehrtime(&usg->pr_ttime);
	scalehrtime(&usg->pr_tftime);
	scalehrtime(&usg->pr_dftime);
	scalehrtime(&usg->pr_kftime);
	scalehrtime(&usg->pr_ltime);
	scalehrtime(&usg->pr_slptime);
	scalehrtime(&usg->pr_wtime);
	scalehrtime(&usg->pr_stoptime);
}


/*
 * Sum resource usage information.
 */
void
praddusage(kthread_t *t, prhusage_t *pup)
{
	klwp_t *lwp = ttolwp(t);
	hrtime_t *mstimep;
	struct mstate *ms = &lwp->lwp_mstate;
	int state;
	int i;
	hrtime_t curtime;
	hrtime_t waitrq;
	hrtime_t tmp;
	prhusage_t conv;

	curtime = gethrtime_unscaled();

	if (ms->ms_term == 0) {
		tmp = curtime - ms->ms_start;
		scalehrtime(&tmp);
		pup->pr_rtime += tmp;
	} else {
		tmp = ms->ms_term - ms->ms_start;
		scalehrtime(&tmp);
		pup->pr_rtime += tmp;
	}

	conv.pr_utime = ms->ms_acct[LMS_USER];
	conv.pr_stime = ms->ms_acct[LMS_SYSTEM];
	conv.pr_ttime = ms->ms_acct[LMS_TRAP];
	conv.pr_tftime = ms->ms_acct[LMS_TFAULT];
	conv.pr_dftime = ms->ms_acct[LMS_DFAULT];
	conv.pr_kftime = ms->ms_acct[LMS_KFAULT];
	conv.pr_ltime = ms->ms_acct[LMS_USER_LOCK];
	conv.pr_slptime = ms->ms_acct[LMS_SLEEP];
	conv.pr_wtime = ms->ms_acct[LMS_WAIT_CPU];
	conv.pr_stoptime = ms->ms_acct[LMS_STOPPED];

	prscaleusage(&conv);

	pup->pr_utime	+= conv.pr_utime;
	pup->pr_stime	+= conv.pr_stime;
	pup->pr_ttime	+= conv.pr_ttime;
	pup->pr_tftime	+= conv.pr_tftime;
	pup->pr_dftime	+= conv.pr_dftime;
	pup->pr_kftime	+= conv.pr_kftime;
	pup->pr_ltime	+= conv.pr_ltime;
	pup->pr_slptime	+= conv.pr_slptime;
	pup->pr_wtime	+= conv.pr_wtime;
	pup->pr_stoptime += conv.pr_stoptime;

	/*
	 * Adjust for time waiting in the dispatcher queue.
	 */
	waitrq = t->t_waitrq;	/* hopefully atomic */
	if (waitrq != 0) {
		if (waitrq > curtime) {
			curtime = gethrtime_unscaled();
		}
		tmp = curtime - waitrq;
		scalehrtime(&tmp);
		pup->pr_wtime += tmp;
		curtime = waitrq;
	}

	/*
	 * Adjust for time spent in current microstate.
	 */
	if (ms->ms_state_start > curtime) {
		curtime = gethrtime_unscaled();
	}

	i = 0;
	do {
		switch (state = t->t_mstate) {
		case LMS_SLEEP:
			/*
			 * Update the timer for the current sleep state.
			 */
			switch (state = ms->ms_prev) {
			case LMS_TFAULT:
			case LMS_DFAULT:
			case LMS_KFAULT:
			case LMS_USER_LOCK:
				break;
			default:
				state = LMS_SLEEP;
				break;
			}
			break;
		case LMS_TFAULT:
		case LMS_DFAULT:
		case LMS_KFAULT:
		case LMS_USER_LOCK:
			state = LMS_SYSTEM;
			break;
		}
		switch (state) {
		case LMS_USER:		mstimep = &pup->pr_utime;	break;
		case LMS_SYSTEM:	mstimep = &pup->pr_stime;	break;
		case LMS_TRAP:		mstimep = &pup->pr_ttime;	break;
		case LMS_TFAULT:	mstimep = &pup->pr_tftime;	break;
		case LMS_DFAULT:	mstimep = &pup->pr_dftime;	break;
		case LMS_KFAULT:	mstimep = &pup->pr_kftime;	break;
		case LMS_USER_LOCK:	mstimep = &pup->pr_ltime;	break;
		case LMS_SLEEP:		mstimep = &pup->pr_slptime;	break;
		case LMS_WAIT_CPU:	mstimep = &pup->pr_wtime;	break;
		case LMS_STOPPED:	mstimep = &pup->pr_stoptime;	break;
		default:		panic("praddusage: unknown microstate");
		}
		tmp = curtime - ms->ms_state_start;
		if (tmp < 0) {
			curtime = gethrtime_unscaled();
			i++;
			continue;
		}
		scalehrtime(&tmp);
	} while (tmp < 0 && i < MAX_ITERS_SPIN);

	*mstimep += tmp;

	/* update pup timestamp */
	pup->pr_tstamp = curtime;
	scalehrtime(&pup->pr_tstamp);

	/*
	 * Resource usage counters.
	 */
	pup->pr_minf  += lwp->lwp_ru.minflt;
	pup->pr_majf  += lwp->lwp_ru.majflt;
	pup->pr_nswap += lwp->lwp_ru.nswap;
	pup->pr_inblk += lwp->lwp_ru.inblock;
	pup->pr_oublk += lwp->lwp_ru.oublock;
	pup->pr_msnd  += lwp->lwp_ru.msgsnd;
	pup->pr_mrcv  += lwp->lwp_ru.msgrcv;
	pup->pr_sigs  += lwp->lwp_ru.nsignals;
	pup->pr_vctx  += lwp->lwp_ru.nvcsw;
	pup->pr_ictx  += lwp->lwp_ru.nivcsw;
	pup->pr_sysc  += lwp->lwp_ru.sysc;
	pup->pr_ioch  += lwp->lwp_ru.ioch;
}

/*
 * Convert a prhusage_t to a prusage_t.
 * This means convert each hrtime_t to a timestruc_t
 * and copy the count fields uint64_t => ulong_t.
 */
void
prcvtusage(prhusage_t *pup, prusage_t *upup)
{
	uint64_t *ullp;
	ulong_t *ulp;
	int i;

	upup->pr_lwpid = pup->pr_lwpid;
	upup->pr_count = pup->pr_count;

	hrt2ts(pup->pr_tstamp,	&upup->pr_tstamp);
	hrt2ts(pup->pr_create,	&upup->pr_create);
	hrt2ts(pup->pr_term,	&upup->pr_term);
	hrt2ts(pup->pr_rtime,	&upup->pr_rtime);
	hrt2ts(pup->pr_utime,	&upup->pr_utime);
	hrt2ts(pup->pr_stime,	&upup->pr_stime);
	hrt2ts(pup->pr_ttime,	&upup->pr_ttime);
	hrt2ts(pup->pr_tftime,	&upup->pr_tftime);
	hrt2ts(pup->pr_dftime,	&upup->pr_dftime);
	hrt2ts(pup->pr_kftime,	&upup->pr_kftime);
	hrt2ts(pup->pr_ltime,	&upup->pr_ltime);
	hrt2ts(pup->pr_slptime,	&upup->pr_slptime);
	hrt2ts(pup->pr_wtime,	&upup->pr_wtime);
	hrt2ts(pup->pr_stoptime, &upup->pr_stoptime);
	bzero(upup->filltime, sizeof (upup->filltime));

	ullp = &pup->pr_minf;
	ulp = &upup->pr_minf;
	for (i = 0; i < 22; i++)
		*ulp++ = (ulong_t)*ullp++;
}

#ifdef _SYSCALL32_IMPL
void
prcvtusage32(prhusage_t *pup, prusage32_t *upup)
{
	uint64_t *ullp;
	uint32_t *ulp;
	int i;

	upup->pr_lwpid = pup->pr_lwpid;
	upup->pr_count = pup->pr_count;

	hrt2ts32(pup->pr_tstamp,	&upup->pr_tstamp);
	hrt2ts32(pup->pr_create,	&upup->pr_create);
	hrt2ts32(pup->pr_term,		&upup->pr_term);
	hrt2ts32(pup->pr_rtime,		&upup->pr_rtime);
	hrt2ts32(pup->pr_utime,		&upup->pr_utime);
	hrt2ts32(pup->pr_stime,		&upup->pr_stime);
	hrt2ts32(pup->pr_ttime,		&upup->pr_ttime);
	hrt2ts32(pup->pr_tftime,	&upup->pr_tftime);
	hrt2ts32(pup->pr_dftime,	&upup->pr_dftime);
	hrt2ts32(pup->pr_kftime,	&upup->pr_kftime);
	hrt2ts32(pup->pr_ltime,		&upup->pr_ltime);
	hrt2ts32(pup->pr_slptime,	&upup->pr_slptime);
	hrt2ts32(pup->pr_wtime,		&upup->pr_wtime);
	hrt2ts32(pup->pr_stoptime,	&upup->pr_stoptime);
	bzero(upup->filltime, sizeof (upup->filltime));

	ullp = &pup->pr_minf;
	ulp = &upup->pr_minf;
	for (i = 0; i < 22; i++)
		*ulp++ = (uint32_t)*ullp++;
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Determine whether a set is empty.
 */
int
setisempty(uint32_t *sp, uint_t n)
{
	while (n--)
		if (*sp++)
			return (0);
	return (1);
}

/*
 * Utility routine for establishing a watched area in the process.
 * Keep the list of watched areas sorted by virtual address.
 */
int
set_watched_area(proc_t *p, struct watched_area *pwa)
{
	caddr_t vaddr = pwa->wa_vaddr;
	caddr_t eaddr = pwa->wa_eaddr;
	ulong_t flags = pwa->wa_flags;
	struct watched_area *target;
	avl_index_t where;
	int error = 0;

	/* we must not be holding p->p_lock, but the process must be locked */
	ASSERT(MUTEX_NOT_HELD(&p->p_lock));
	ASSERT(p->p_proc_flag & P_PR_LOCK);

	/*
	 * If this is our first watchpoint, enable watchpoints for the process.
	 */
	if (!pr_watch_active(p)) {
		kthread_t *t;

		mutex_enter(&p->p_lock);
		if ((t = p->p_tlist) != NULL) {
			do {
				watch_enable(t);
			} while ((t = t->t_forw) != p->p_tlist);
		}
		mutex_exit(&p->p_lock);
	}

	target = pr_find_watched_area(p, pwa, &where);
	if (target != NULL) {
		/*
		 * We discovered an existing, overlapping watched area.
		 * Allow it only if it is an exact match.
		 */
		if (target->wa_vaddr != vaddr ||
		    target->wa_eaddr != eaddr)
			error = EINVAL;
		else if (target->wa_flags != flags) {
			error = set_watched_page(p, vaddr, eaddr,
			    flags, target->wa_flags);
			target->wa_flags = flags;
		}
		kmem_free(pwa, sizeof (struct watched_area));
	} else {
		avl_insert(&p->p_warea, pwa, where);
		error = set_watched_page(p, vaddr, eaddr, flags, 0);
	}

	return (error);
}

/*
 * Utility routine for clearing a watched area in the process.
 * Must be an exact match of the virtual address.
 * size and flags don't matter.
 */
int
clear_watched_area(proc_t *p, struct watched_area *pwa)
{
	struct watched_area *found;

	/* we must not be holding p->p_lock, but the process must be locked */
	ASSERT(MUTEX_NOT_HELD(&p->p_lock));
	ASSERT(p->p_proc_flag & P_PR_LOCK);


	if (!pr_watch_active(p)) {
		kmem_free(pwa, sizeof (struct watched_area));
		return (0);
	}

	/*
	 * Look for a matching address in the watched areas.  If a match is
	 * found, clear the old watched area and adjust the watched page(s).  It
	 * is not an error if there is no match.
	 */
	if ((found = pr_find_watched_area(p, pwa, NULL)) != NULL &&
	    found->wa_vaddr == pwa->wa_vaddr) {
		clear_watched_page(p, found->wa_vaddr, found->wa_eaddr,
		    found->wa_flags);
		avl_remove(&p->p_warea, found);
		kmem_free(found, sizeof (struct watched_area));
	}

	kmem_free(pwa, sizeof (struct watched_area));

	/*
	 * If we removed the last watched area from the process, disable
	 * watchpoints.
	 */
	if (!pr_watch_active(p)) {
		kthread_t *t;

		mutex_enter(&p->p_lock);
		if ((t = p->p_tlist) != NULL) {
			do {
				watch_disable(t);
			} while ((t = t->t_forw) != p->p_tlist);
		}
		mutex_exit(&p->p_lock);
	}

	return (0);
}

/*
 * Frees all the watched_area structures
 */
void
pr_free_watchpoints(proc_t *p)
{
	struct watched_area *delp;
	void *cookie;

	cookie = NULL;
	while ((delp = avl_destroy_nodes(&p->p_warea, &cookie)) != NULL)
		kmem_free(delp, sizeof (struct watched_area));

	avl_destroy(&p->p_warea);
}

/*
 * This one is called by the traced process to unwatch all the
 * pages while deallocating the list of watched_page structs.
 */
void
pr_free_watched_pages(proc_t *p)
{
	struct as *as = p->p_as;
	struct watched_page *pwp;
	uint_t prot;
	int    retrycnt, err;
	void *cookie;

	if (as == NULL || avl_numnodes(&as->a_wpage) == 0)
		return;

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));
	AS_LOCK_ENTER(as, RW_WRITER);

	pwp = avl_first(&as->a_wpage);

	cookie = NULL;
	while ((pwp = avl_destroy_nodes(&as->a_wpage, &cookie)) != NULL) {
		retrycnt = 0;
		if ((prot = pwp->wp_oprot) != 0) {
			caddr_t addr = pwp->wp_vaddr;
			struct seg *seg;
		retry:

			if ((pwp->wp_prot != prot ||
			    (pwp->wp_flags & WP_NOWATCH)) &&
			    (seg = as_segat(as, addr)) != NULL) {
				err = SEGOP_SETPROT(seg, addr, PAGESIZE, prot);
				if (err == IE_RETRY) {
					ASSERT(retrycnt == 0);
					retrycnt++;
					goto retry;
				}
			}
		}
		kmem_free(pwp, sizeof (struct watched_page));
	}

	avl_destroy(&as->a_wpage);
	p->p_wprot = NULL;

	AS_LOCK_EXIT(as);
}

/*
 * Insert a watched area into the list of watched pages.
 * If oflags is zero then we are adding a new watched area.
 * Otherwise we are changing the flags of an existing watched area.
 */
static int
set_watched_page(proc_t *p, caddr_t vaddr, caddr_t eaddr,
	ulong_t flags, ulong_t oflags)
{
	struct as *as = p->p_as;
	avl_tree_t *pwp_tree;
	struct watched_page *pwp, *newpwp;
	struct watched_page tpw;
	avl_index_t where;
	struct seg *seg;
	uint_t prot;
	caddr_t addr;

	/*
	 * We need to pre-allocate a list of structures before we grab the
	 * address space lock to avoid calling kmem_alloc(KM_SLEEP) with locks
	 * held.
	 */
	newpwp = NULL;
	for (addr = (caddr_t)((uintptr_t)vaddr & (uintptr_t)PAGEMASK);
	    addr < eaddr; addr += PAGESIZE) {
		pwp = kmem_zalloc(sizeof (struct watched_page), KM_SLEEP);
		pwp->wp_list = newpwp;
		newpwp = pwp;
	}

	AS_LOCK_ENTER(as, RW_WRITER);

	/*
	 * Search for an existing watched page to contain the watched area.
	 * If none is found, grab a new one from the available list
	 * and insert it in the active list, keeping the list sorted
	 * by user-level virtual address.
	 */
	if (p->p_flag & SVFWAIT)
		pwp_tree = &p->p_wpage;
	else
		pwp_tree = &as->a_wpage;

again:
	if (avl_numnodes(pwp_tree) > prnwatch) {
		AS_LOCK_EXIT(as);
		while (newpwp != NULL) {
			pwp = newpwp->wp_list;
			kmem_free(newpwp, sizeof (struct watched_page));
			newpwp = pwp;
		}
		return (E2BIG);
	}

	tpw.wp_vaddr = (caddr_t)((uintptr_t)vaddr & (uintptr_t)PAGEMASK);
	if ((pwp = avl_find(pwp_tree, &tpw, &where)) == NULL) {
		pwp = newpwp;
		newpwp = newpwp->wp_list;
		pwp->wp_list = NULL;
		pwp->wp_vaddr = (caddr_t)((uintptr_t)vaddr &
		    (uintptr_t)PAGEMASK);
		avl_insert(pwp_tree, pwp, where);
	}

	ASSERT(vaddr >= pwp->wp_vaddr && vaddr < pwp->wp_vaddr + PAGESIZE);

	if (oflags & WA_READ)
		pwp->wp_read--;
	if (oflags & WA_WRITE)
		pwp->wp_write--;
	if (oflags & WA_EXEC)
		pwp->wp_exec--;

	ASSERT(pwp->wp_read >= 0);
	ASSERT(pwp->wp_write >= 0);
	ASSERT(pwp->wp_exec >= 0);

	if (flags & WA_READ)
		pwp->wp_read++;
	if (flags & WA_WRITE)
		pwp->wp_write++;
	if (flags & WA_EXEC)
		pwp->wp_exec++;

	if (!(p->p_flag & SVFWAIT)) {
		vaddr = pwp->wp_vaddr;
		if (pwp->wp_oprot == 0 &&
		    (seg = as_segat(as, vaddr)) != NULL) {
			SEGOP_GETPROT(seg, vaddr, 0, &prot);
			pwp->wp_oprot = (uchar_t)prot;
			pwp->wp_prot = (uchar_t)prot;
		}
		if (pwp->wp_oprot != 0) {
			prot = pwp->wp_oprot;
			if (pwp->wp_read)
				prot &= ~(PROT_READ|PROT_WRITE|PROT_EXEC);
			if (pwp->wp_write)
				prot &= ~PROT_WRITE;
			if (pwp->wp_exec)
				prot &= ~(PROT_READ|PROT_WRITE|PROT_EXEC);
			if (!(pwp->wp_flags & WP_NOWATCH) &&
			    pwp->wp_prot != prot &&
			    (pwp->wp_flags & WP_SETPROT) == 0) {
				pwp->wp_flags |= WP_SETPROT;
				pwp->wp_list = p->p_wprot;
				p->p_wprot = pwp;
			}
			pwp->wp_prot = (uchar_t)prot;
		}
	}

	/*
	 * If the watched area extends into the next page then do
	 * it over again with the virtual address of the next page.
	 */
	if ((vaddr = pwp->wp_vaddr + PAGESIZE) < eaddr)
		goto again;

	AS_LOCK_EXIT(as);

	/*
	 * Free any pages we may have over-allocated
	 */
	while (newpwp != NULL) {
		pwp = newpwp->wp_list;
		kmem_free(newpwp, sizeof (struct watched_page));
		newpwp = pwp;
	}

	return (0);
}

/*
 * Remove a watched area from the list of watched pages.
 * A watched area may extend over more than one page.
 */
static void
clear_watched_page(proc_t *p, caddr_t vaddr, caddr_t eaddr, ulong_t flags)
{
	struct as *as = p->p_as;
	struct watched_page *pwp;
	struct watched_page tpw;
	avl_tree_t *tree;
	avl_index_t where;

	AS_LOCK_ENTER(as, RW_WRITER);

	if (p->p_flag & SVFWAIT)
		tree = &p->p_wpage;
	else
		tree = &as->a_wpage;

	tpw.wp_vaddr = vaddr =
	    (caddr_t)((uintptr_t)vaddr & (uintptr_t)PAGEMASK);
	pwp = avl_find(tree, &tpw, &where);
	if (pwp == NULL)
		pwp = avl_nearest(tree, where, AVL_AFTER);

	while (pwp != NULL && pwp->wp_vaddr < eaddr) {
		ASSERT(vaddr <=  pwp->wp_vaddr);

		if (flags & WA_READ)
			pwp->wp_read--;
		if (flags & WA_WRITE)
			pwp->wp_write--;
		if (flags & WA_EXEC)
			pwp->wp_exec--;

		if (pwp->wp_read + pwp->wp_write + pwp->wp_exec != 0) {
			/*
			 * Reset the hat layer's protections on this page.
			 */
			if (pwp->wp_oprot != 0) {
				uint_t prot = pwp->wp_oprot;

				if (pwp->wp_read)
					prot &=
					    ~(PROT_READ|PROT_WRITE|PROT_EXEC);
				if (pwp->wp_write)
					prot &= ~PROT_WRITE;
				if (pwp->wp_exec)
					prot &=
					    ~(PROT_READ|PROT_WRITE|PROT_EXEC);
				if (!(pwp->wp_flags & WP_NOWATCH) &&
				    pwp->wp_prot != prot &&
				    (pwp->wp_flags & WP_SETPROT) == 0) {
					pwp->wp_flags |= WP_SETPROT;
					pwp->wp_list = p->p_wprot;
					p->p_wprot = pwp;
				}
				pwp->wp_prot = (uchar_t)prot;
			}
		} else {
			/*
			 * No watched areas remain in this page.
			 * Reset everything to normal.
			 */
			if (pwp->wp_oprot != 0) {
				pwp->wp_prot = pwp->wp_oprot;
				if ((pwp->wp_flags & WP_SETPROT) == 0) {
					pwp->wp_flags |= WP_SETPROT;
					pwp->wp_list = p->p_wprot;
					p->p_wprot = pwp;
				}
			}
		}

		pwp = AVL_NEXT(tree, pwp);
	}

	AS_LOCK_EXIT(as);
}

/*
 * Return the original protections for the specified page.
 */
static void
getwatchprot(struct as *as, caddr_t addr, uint_t *prot)
{
	struct watched_page *pwp;
	struct watched_page tpw;

	ASSERT(AS_LOCK_HELD(as));

	tpw.wp_vaddr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	if ((pwp = avl_find(&as->a_wpage, &tpw, NULL)) != NULL)
		*prot = pwp->wp_oprot;
}

static prpagev_t *
pr_pagev_create(struct seg *seg, int check_noreserve)
{
	prpagev_t *pagev = kmem_alloc(sizeof (prpagev_t), KM_SLEEP);
	size_t total_pages = seg_pages(seg);

	/*
	 * Limit the size of our vectors to pagev_lim pages at a time.  We need
	 * 4 or 5 bytes of storage per page, so this means we limit ourself
	 * to about a megabyte of kernel heap by default.
	 */
	pagev->pg_npages = MIN(total_pages, pagev_lim);
	pagev->pg_pnbase = 0;

	pagev->pg_protv =
	    kmem_alloc(pagev->pg_npages * sizeof (uint_t), KM_SLEEP);

	if (check_noreserve)
		pagev->pg_incore =
		    kmem_alloc(pagev->pg_npages * sizeof (char), KM_SLEEP);
	else
		pagev->pg_incore = NULL;

	return (pagev);
}

static void
pr_pagev_destroy(prpagev_t *pagev)
{
	if (pagev->pg_incore != NULL)
		kmem_free(pagev->pg_incore, pagev->pg_npages * sizeof (char));

	kmem_free(pagev->pg_protv, pagev->pg_npages * sizeof (uint_t));
	kmem_free(pagev, sizeof (prpagev_t));
}

static caddr_t
pr_pagev_fill(prpagev_t *pagev, struct seg *seg, caddr_t addr, caddr_t eaddr)
{
	ulong_t lastpg = seg_page(seg, eaddr - 1);
	ulong_t pn, pnlim;
	caddr_t saddr;
	size_t len;

	ASSERT(addr >= seg->s_base && addr <= eaddr);

	if (addr == eaddr)
		return (eaddr);

refill:
	ASSERT(addr < eaddr);
	pagev->pg_pnbase = seg_page(seg, addr);
	pnlim = pagev->pg_pnbase + pagev->pg_npages;
	saddr = addr;

	if (lastpg < pnlim)
		len = (size_t)(eaddr - addr);
	else
		len = pagev->pg_npages * PAGESIZE;

	if (pagev->pg_incore != NULL) {
		/*
		 * INCORE cleverly has different semantics than GETPROT:
		 * it returns info on pages up to but NOT including addr + len.
		 */
		SEGOP_INCORE(seg, addr, len, pagev->pg_incore);
		pn = pagev->pg_pnbase;

		do {
			/*
			 * Guilty knowledge here:  We know that segvn_incore
			 * returns more than just the low-order bit that
			 * indicates the page is actually in memory.  If any
			 * bits are set, then the page has backing store.
			 */
			if (pagev->pg_incore[pn++ - pagev->pg_pnbase])
				goto out;

		} while ((addr += PAGESIZE) < eaddr && pn < pnlim);

		/*
		 * If we examined all the pages in the vector but we're not
		 * at the end of the segment, take another lap.
		 */
		if (addr < eaddr)
			goto refill;
	}

	/*
	 * Need to take len - 1 because addr + len is the address of the
	 * first byte of the page just past the end of what we want.
	 */
out:
	SEGOP_GETPROT(seg, saddr, len - 1, pagev->pg_protv);
	return (addr);
}

static caddr_t
pr_pagev_nextprot(prpagev_t *pagev, struct seg *seg,
    caddr_t *saddrp, caddr_t eaddr, uint_t *protp)
{
	/*
	 * Our starting address is either the specified address, or the base
	 * address from the start of the pagev.  If the latter is greater,
	 * this means a previous call to pr_pagev_fill has already scanned
	 * further than the end of the previous mapping.
	 */
	caddr_t base = seg->s_base + pagev->pg_pnbase * PAGESIZE;
	caddr_t addr = MAX(*saddrp, base);
	ulong_t pn = seg_page(seg, addr);
	uint_t prot, nprot;

	/*
	 * If we're dealing with noreserve pages, then advance addr to
	 * the address of the next page which has backing store.
	 */
	if (pagev->pg_incore != NULL) {
		while (pagev->pg_incore[pn - pagev->pg_pnbase] == 0) {
			if ((addr += PAGESIZE) == eaddr) {
				*saddrp = addr;
				prot = 0;
				goto out;
			}
			if (++pn == pagev->pg_pnbase + pagev->pg_npages) {
				addr = pr_pagev_fill(pagev, seg, addr, eaddr);
				if (addr == eaddr) {
					*saddrp = addr;
					prot = 0;
					goto out;
				}
				pn = seg_page(seg, addr);
			}
		}
	}

	/*
	 * Get the protections on the page corresponding to addr.
	 */
	pn = seg_page(seg, addr);
	ASSERT(pn >= pagev->pg_pnbase);
	ASSERT(pn < (pagev->pg_pnbase + pagev->pg_npages));

	prot = pagev->pg_protv[pn - pagev->pg_pnbase];
	getwatchprot(seg->s_as, addr, &prot);
	*saddrp = addr;

	/*
	 * Now loop until we find a backed page with different protections
	 * or we reach the end of this segment.
	 */
	while ((addr += PAGESIZE) < eaddr) {
		/*
		 * If pn has advanced to the page number following what we
		 * have information on, refill the page vector and reset
		 * addr and pn.  If pr_pagev_fill does not return the
		 * address of the next page, we have a discontiguity and
		 * thus have reached the end of the current mapping.
		 */
		if (++pn == pagev->pg_pnbase + pagev->pg_npages) {
			caddr_t naddr = pr_pagev_fill(pagev, seg, addr, eaddr);
			if (naddr != addr)
				goto out;
			pn = seg_page(seg, addr);
		}

		/*
		 * The previous page's protections are in prot, and it has
		 * backing.  If this page is MAP_NORESERVE and has no backing,
		 * then end this mapping and return the previous protections.
		 */
		if (pagev->pg_incore != NULL &&
		    pagev->pg_incore[pn - pagev->pg_pnbase] == 0)
			break;

		/*
		 * Otherwise end the mapping if this page's protections (nprot)
		 * are different than those in the previous page (prot).
		 */
		nprot = pagev->pg_protv[pn - pagev->pg_pnbase];
		getwatchprot(seg->s_as, addr, &nprot);

		if (nprot != prot)
			break;
	}

out:
	*protp = prot;
	return (addr);
}

size_t
pr_getsegsize(struct seg *seg, int reserved)
{
	size_t size = seg->s_size;

	/*
	 * If we're interested in the reserved space, return the size of the
	 * segment itself.  Everything else in this function is a special case
	 * to determine the actual underlying size of various segment types.
	 */
	if (reserved)
		return (size);

	/*
	 * If this is a segvn mapping of a regular file, return the smaller
	 * of the segment size and the remaining size of the file beyond
	 * the file offset corresponding to seg->s_base.
	 */
	if (seg->s_ops == &segvn_ops) {
		vattr_t vattr;
		vnode_t *vp;

		vattr.va_mask = AT_SIZE;

		if (SEGOP_GETVP(seg, seg->s_base, &vp) == 0 &&
		    vp != NULL && vp->v_type == VREG &&
		    VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) == 0) {

			u_offset_t fsize = vattr.va_size;
			u_offset_t offset = SEGOP_GETOFFSET(seg, seg->s_base);

			if (fsize < offset)
				fsize = 0;
			else
				fsize -= offset;

			fsize = roundup(fsize, (u_offset_t)PAGESIZE);

			if (fsize < (u_offset_t)size)
				size = (size_t)fsize;
		}

		return (size);
	}

	/*
	 * If this is an ISM shared segment, don't include pages that are
	 * beyond the real size of the spt segment that backs it.
	 */
	if (seg->s_ops == &segspt_shmops)
		return (MIN(spt_realsize(seg), size));

	/*
	 * If this is segment is a mapping from /dev/null, then this is a
	 * reservation of virtual address space and has no actual size.
	 * Such segments are backed by segdev and have type set to neither
	 * MAP_SHARED nor MAP_PRIVATE.
	 */
	if (seg->s_ops == &segdev_ops &&
	    ((SEGOP_GETTYPE(seg, seg->s_base) &
	    (MAP_SHARED | MAP_PRIVATE)) == 0))
		return (0);

	/*
	 * If this segment doesn't match one of the special types we handle,
	 * just return the size of the segment itself.
	 */
	return (size);
}

uint_t
pr_getprot(struct seg *seg, int reserved, void **tmp,
	caddr_t *saddrp, caddr_t *naddrp, caddr_t eaddr)
{
	struct as *as = seg->s_as;

	caddr_t saddr = *saddrp;
	caddr_t naddr;

	int check_noreserve;
	uint_t prot;

	union {
		struct segvn_data *svd;
		struct segdev_data *sdp;
		void *data;
	} s;

	s.data = seg->s_data;

	ASSERT(AS_WRITE_HELD(as));
	ASSERT(saddr >= seg->s_base && saddr < eaddr);
	ASSERT(eaddr <= seg->s_base + seg->s_size);

	/*
	 * Don't include MAP_NORESERVE pages in the address range
	 * unless their mappings have actually materialized.
	 * We cheat by knowing that segvn is the only segment
	 * driver that supports MAP_NORESERVE.
	 */
	check_noreserve =
	    (!reserved && seg->s_ops == &segvn_ops && s.svd != NULL &&
	    (s.svd->vp == NULL || s.svd->vp->v_type != VREG) &&
	    (s.svd->flags & MAP_NORESERVE));

	/*
	 * Examine every page only as a last resort.  We use guilty knowledge
	 * of segvn and segdev to avoid this: if there are no per-page
	 * protections present in the segment and we don't care about
	 * MAP_NORESERVE, then s_data->prot is the prot for the whole segment.
	 */
	if (!check_noreserve && saddr == seg->s_base &&
	    seg->s_ops == &segvn_ops && s.svd != NULL && s.svd->pageprot == 0) {
		prot = s.svd->prot;
		getwatchprot(as, saddr, &prot);
		naddr = eaddr;

	} else if (saddr == seg->s_base && seg->s_ops == &segdev_ops &&
	    s.sdp != NULL && s.sdp->pageprot == 0) {
		prot = s.sdp->prot;
		getwatchprot(as, saddr, &prot);
		naddr = eaddr;

	} else {
		prpagev_t *pagev;

		/*
		 * If addr is sitting at the start of the segment, then
		 * create a page vector to store protection and incore
		 * information for pages in the segment, and fill it.
		 * Otherwise, we expect *tmp to address the prpagev_t
		 * allocated by a previous call to this function.
		 */
		if (saddr == seg->s_base) {
			pagev = pr_pagev_create(seg, check_noreserve);
			saddr = pr_pagev_fill(pagev, seg, saddr, eaddr);

			ASSERT(*tmp == NULL);
			*tmp = pagev;

			ASSERT(saddr <= eaddr);
			*saddrp = saddr;

			if (saddr == eaddr) {
				naddr = saddr;
				prot = 0;
				goto out;
			}

		} else {
			ASSERT(*tmp != NULL);
			pagev = (prpagev_t *)*tmp;
		}

		naddr = pr_pagev_nextprot(pagev, seg, saddrp, eaddr, &prot);
		ASSERT(naddr <= eaddr);
	}

out:
	if (naddr == eaddr)
		pr_getprot_done(tmp);
	*naddrp = naddr;
	return (prot);
}

void
pr_getprot_done(void **tmp)
{
	if (*tmp != NULL) {
		pr_pagev_destroy((prpagev_t *)*tmp);
		*tmp = NULL;
	}
}

/*
 * Return true iff the vnode is a /proc file from the object directory.
 */
int
pr_isobject(vnode_t *vp)
{
	return (vn_matchops(vp, prvnodeops) && VTOP(vp)->pr_type == PR_OBJECT);
}

/*
 * Return true iff the vnode is a /proc file opened by the process itself.
 */
int
pr_isself(vnode_t *vp)
{
	/*
	 * XXX: To retain binary compatibility with the old
	 * ioctl()-based version of /proc, we exempt self-opens
	 * of /proc/<pid> from being marked close-on-exec.
	 */
	return (vn_matchops(vp, prvnodeops) &&
	    (VTOP(vp)->pr_flags & PR_ISSELF) &&
	    VTOP(vp)->pr_type != PR_PIDDIR);
}

static ssize_t
pr_getpagesize(struct seg *seg, caddr_t saddr, caddr_t *naddrp, caddr_t eaddr)
{
	ssize_t pagesize, hatsize;

	ASSERT(AS_WRITE_HELD(seg->s_as));
	ASSERT(IS_P2ALIGNED(saddr, PAGESIZE));
	ASSERT(IS_P2ALIGNED(eaddr, PAGESIZE));
	ASSERT(saddr < eaddr);

	pagesize = hatsize = hat_getpagesize(seg->s_as->a_hat, saddr);
	ASSERT(pagesize == -1 || IS_P2ALIGNED(pagesize, pagesize));
	ASSERT(pagesize != 0);

	if (pagesize == -1)
		pagesize = PAGESIZE;

	saddr += P2NPHASE((uintptr_t)saddr, pagesize);

	while (saddr < eaddr) {
		if (hatsize != hat_getpagesize(seg->s_as->a_hat, saddr))
			break;
		ASSERT(IS_P2ALIGNED(saddr, pagesize));
		saddr += pagesize;
	}

	*naddrp = ((saddr < eaddr) ? saddr : eaddr);
	return (hatsize);
}

/*
 * Return an array of structures with extended memory map information.
 * We allocate here; the caller must deallocate.
 */
int
prgetxmap(proc_t *p, list_t *iolhead)
{
	struct as *as = p->p_as;
	prxmap_t *mp;
	struct seg *seg;
	struct seg *brkseg, *stkseg;
	struct vnode *vp;
	struct vattr vattr;
	uint_t prot;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	/*
	 * Request an initial buffer size that doesn't waste memory
	 * if the address space has only a small number of segments.
	 */
	pr_iol_initlist(iolhead, sizeof (*mp), avl_numnodes(&as->a_segtree));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	brkseg = break_seg(p);
	stkseg = as_segat(as, prgetstackbase(p));

	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr, baddr;
		void *tmp = NULL;
		ssize_t psz;
		char *parr;
		uint64_t npages;
		uint64_t pagenum;

		/*
		 * Segment loop part one: iterate from the base of the segment
		 * to its end, pausing at each address boundary (baddr) between
		 * ranges that have different virtual memory protections.
		 */
		for (saddr = seg->s_base; saddr < eaddr; saddr = baddr) {
			prot = pr_getprot(seg, 0, &tmp, &saddr, &baddr, eaddr);
			ASSERT(baddr >= saddr && baddr <= eaddr);

			/*
			 * Segment loop part two: iterate from the current
			 * position to the end of the protection boundary,
			 * pausing at each address boundary (naddr) between
			 * ranges that have different underlying page sizes.
			 */
			for (; saddr < baddr; saddr = naddr) {
				psz = pr_getpagesize(seg, saddr, &naddr, baddr);
				ASSERT(naddr >= saddr && naddr <= baddr);

				mp = pr_iol_newbuf(iolhead, sizeof (*mp));

				mp->pr_vaddr = (uintptr_t)saddr;
				mp->pr_size = naddr - saddr;
				mp->pr_offset = SEGOP_GETOFFSET(seg, saddr);
				mp->pr_mflags = 0;
				if (prot & PROT_READ)
					mp->pr_mflags |= MA_READ;
				if (prot & PROT_WRITE)
					mp->pr_mflags |= MA_WRITE;
				if (prot & PROT_EXEC)
					mp->pr_mflags |= MA_EXEC;
				if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
					mp->pr_mflags |= MA_SHARED;
				if (SEGOP_GETTYPE(seg, saddr) & MAP_NORESERVE)
					mp->pr_mflags |= MA_NORESERVE;
				if (seg->s_ops == &segspt_shmops ||
				    (seg->s_ops == &segvn_ops &&
				    (SEGOP_GETVP(seg, saddr, &vp) != 0 ||
				    vp == NULL)))
					mp->pr_mflags |= MA_ANON;
				if (seg == brkseg)
					mp->pr_mflags |= MA_BREAK;
				else if (seg == stkseg)
					mp->pr_mflags |= MA_STACK;
				if (seg->s_ops == &segspt_shmops)
					mp->pr_mflags |= MA_ISM | MA_SHM;

				mp->pr_pagesize = PAGESIZE;
				if (psz == -1) {
					mp->pr_hatpagesize = 0;
				} else {
					mp->pr_hatpagesize = psz;
				}

				/*
				 * Manufacture a filename for the "object" dir.
				 */
				mp->pr_dev = PRNODEV;
				vattr.va_mask = AT_FSID|AT_NODEID;
				if (seg->s_ops == &segvn_ops &&
				    SEGOP_GETVP(seg, saddr, &vp) == 0 &&
				    vp != NULL && vp->v_type == VREG &&
				    VOP_GETATTR(vp, &vattr, 0, CRED(),
				    NULL) == 0) {
					mp->pr_dev = vattr.va_fsid;
					mp->pr_ino = vattr.va_nodeid;
					if (vp == p->p_exec)
						(void) strcpy(mp->pr_mapname,
						    "a.out");
					else
						pr_object_name(mp->pr_mapname,
						    vp, &vattr);
				}

				/*
				 * Get the SysV shared memory id, if any.
				 */
				if ((mp->pr_mflags & MA_SHARED) &&
				    p->p_segacct && (mp->pr_shmid = shmgetid(p,
				    seg->s_base)) != SHMID_NONE) {
					if (mp->pr_shmid == SHMID_FREE)
						mp->pr_shmid = -1;

					mp->pr_mflags |= MA_SHM;
				} else {
					mp->pr_shmid = -1;
				}

				npages = ((uintptr_t)(naddr - saddr)) >>
				    PAGESHIFT;
				parr = kmem_zalloc(npages, KM_SLEEP);

				SEGOP_INCORE(seg, saddr, naddr - saddr, parr);

				for (pagenum = 0; pagenum < npages; pagenum++) {
					if (parr[pagenum] & SEG_PAGE_INCORE)
						mp->pr_rss++;
					if (parr[pagenum] & SEG_PAGE_ANON)
						mp->pr_anon++;
					if (parr[pagenum] & SEG_PAGE_LOCKED)
						mp->pr_locked++;
				}
				kmem_free(parr, npages);
			}
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (0);
}

/*
 * Return the process's credentials.  We don't need a 32-bit equivalent of
 * this function because prcred_t and prcred32_t are actually the same.
 */
void
prgetcred(proc_t *p, prcred_t *pcrp)
{
	mutex_enter(&p->p_crlock);
	cred2prcred(p->p_cred, pcrp);
	mutex_exit(&p->p_crlock);
}

/*
 * Compute actual size of the prpriv_t structure.
 */

size_t
prgetprivsize(void)
{
	return (priv_prgetprivsize(NULL));
}

/*
 * Return the process's privileges.  We don't need a 32-bit equivalent of
 * this function because prpriv_t and prpriv32_t are actually the same.
 */
void
prgetpriv(proc_t *p, prpriv_t *pprp)
{
	mutex_enter(&p->p_crlock);
	cred2prpriv(p->p_cred, pprp);
	mutex_exit(&p->p_crlock);
}

#ifdef _SYSCALL32_IMPL
/*
 * Return an array of structures with HAT memory map information.
 * We allocate here; the caller must deallocate.
 */
int
prgetxmap32(proc_t *p, list_t *iolhead)
{
	struct as *as = p->p_as;
	prxmap32_t *mp;
	struct seg *seg;
	struct seg *brkseg, *stkseg;
	struct vnode *vp;
	struct vattr vattr;
	uint_t prot;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	/*
	 * Request an initial buffer size that doesn't waste memory
	 * if the address space has only a small number of segments.
	 */
	pr_iol_initlist(iolhead, sizeof (*mp), avl_numnodes(&as->a_segtree));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	brkseg = break_seg(p);
	stkseg = as_segat(as, prgetstackbase(p));

	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr, baddr;
		void *tmp = NULL;
		ssize_t psz;
		char *parr;
		uint64_t npages;
		uint64_t pagenum;

		/*
		 * Segment loop part one: iterate from the base of the segment
		 * to its end, pausing at each address boundary (baddr) between
		 * ranges that have different virtual memory protections.
		 */
		for (saddr = seg->s_base; saddr < eaddr; saddr = baddr) {
			prot = pr_getprot(seg, 0, &tmp, &saddr, &baddr, eaddr);
			ASSERT(baddr >= saddr && baddr <= eaddr);

			/*
			 * Segment loop part two: iterate from the current
			 * position to the end of the protection boundary,
			 * pausing at each address boundary (naddr) between
			 * ranges that have different underlying page sizes.
			 */
			for (; saddr < baddr; saddr = naddr) {
				psz = pr_getpagesize(seg, saddr, &naddr, baddr);
				ASSERT(naddr >= saddr && naddr <= baddr);

				mp = pr_iol_newbuf(iolhead, sizeof (*mp));

				mp->pr_vaddr = (caddr32_t)(uintptr_t)saddr;
				mp->pr_size = (size32_t)(naddr - saddr);
				mp->pr_offset = SEGOP_GETOFFSET(seg, saddr);
				mp->pr_mflags = 0;
				if (prot & PROT_READ)
					mp->pr_mflags |= MA_READ;
				if (prot & PROT_WRITE)
					mp->pr_mflags |= MA_WRITE;
				if (prot & PROT_EXEC)
					mp->pr_mflags |= MA_EXEC;
				if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
					mp->pr_mflags |= MA_SHARED;
				if (SEGOP_GETTYPE(seg, saddr) & MAP_NORESERVE)
					mp->pr_mflags |= MA_NORESERVE;
				if (seg->s_ops == &segspt_shmops ||
				    (seg->s_ops == &segvn_ops &&
				    (SEGOP_GETVP(seg, saddr, &vp) != 0 ||
				    vp == NULL)))
					mp->pr_mflags |= MA_ANON;
				if (seg == brkseg)
					mp->pr_mflags |= MA_BREAK;
				else if (seg == stkseg)
					mp->pr_mflags |= MA_STACK;
				if (seg->s_ops == &segspt_shmops)
					mp->pr_mflags |= MA_ISM | MA_SHM;

				mp->pr_pagesize = PAGESIZE;
				if (psz == -1) {
					mp->pr_hatpagesize = 0;
				} else {
					mp->pr_hatpagesize = psz;
				}

				/*
				 * Manufacture a filename for the "object" dir.
				 */
				mp->pr_dev = PRNODEV32;
				vattr.va_mask = AT_FSID|AT_NODEID;
				if (seg->s_ops == &segvn_ops &&
				    SEGOP_GETVP(seg, saddr, &vp) == 0 &&
				    vp != NULL && vp->v_type == VREG &&
				    VOP_GETATTR(vp, &vattr, 0, CRED(),
				    NULL) == 0) {
					(void) cmpldev(&mp->pr_dev,
					    vattr.va_fsid);
					mp->pr_ino = vattr.va_nodeid;
					if (vp == p->p_exec)
						(void) strcpy(mp->pr_mapname,
						    "a.out");
					else
						pr_object_name(mp->pr_mapname,
						    vp, &vattr);
				}

				/*
				 * Get the SysV shared memory id, if any.
				 */
				if ((mp->pr_mflags & MA_SHARED) &&
				    p->p_segacct && (mp->pr_shmid = shmgetid(p,
				    seg->s_base)) != SHMID_NONE) {
					if (mp->pr_shmid == SHMID_FREE)
						mp->pr_shmid = -1;

					mp->pr_mflags |= MA_SHM;
				} else {
					mp->pr_shmid = -1;
				}

				npages = ((uintptr_t)(naddr - saddr)) >>
				    PAGESHIFT;
				parr = kmem_zalloc(npages, KM_SLEEP);

				SEGOP_INCORE(seg, saddr, naddr - saddr, parr);

				for (pagenum = 0; pagenum < npages; pagenum++) {
					if (parr[pagenum] & SEG_PAGE_INCORE)
						mp->pr_rss++;
					if (parr[pagenum] & SEG_PAGE_ANON)
						mp->pr_anon++;
					if (parr[pagenum] & SEG_PAGE_LOCKED)
						mp->pr_locked++;
				}
				kmem_free(parr, npages);
			}
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (0);
}
#endif	/* _SYSCALL32_IMPL */
