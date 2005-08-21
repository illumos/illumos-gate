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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* from SVr4.0 1.74 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/ucontext.h>
#include <sys/procfs.h>
#include <sys/vnode.h>
#include <sys/acct.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/wait.h>
#include <sys/siginfo.h>
#include <sys/procset.h>
#include <sys/class.h>
#include <sys/file.h>
#include <sys/session.h>
#include <sys/kmem.h>
#include <sys/vtrace.h>
#include <sys/prsystm.h>
#include <sys/ipc.h>
#include <sys/sem_impl.h>
#include <c2/audit.h>
#include <sys/aio_impl.h>
#include <vm/as.h>
#include <sys/poll.h>
#include <sys/door.h>
#include <sys/lwpchan_impl.h>
#include <sys/utrap.h>
#include <sys/task.h>
#include <sys/exacct.h>
#include <sys/cyclic.h>
#include <sys/schedctl.h>
#include <sys/rctl.h>
#include <sys/contract_impl.h>
#include <sys/contract/process_impl.h>
#include <sys/list.h>
#include <sys/dtrace.h>
#include <sys/pool.h>
#include <sys/sdt.h>
#include <sys/corectl.h>

#if defined(__x86)
extern void ldt_free(proc_t *pp);
#endif

/*
 * convert code/data pair into old style wait status
 */
int
wstat(int code, int data)
{
	int stat = (data & 0377);

	switch (code) {
	case CLD_EXITED:
		stat <<= 8;
		break;
	case CLD_DUMPED:
		stat |= WCOREFLG;
		break;
	case CLD_KILLED:
		break;
	case CLD_TRAPPED:
	case CLD_STOPPED:
		stat <<= 8;
		stat |= WSTOPFLG;
		break;
	case CLD_CONTINUED:
		stat = WCONTFLG;
		break;
	default:
		cmn_err(CE_PANIC, "wstat: bad code");
		/* NOTREACHED */
	}
	return (stat);
}

static char *
exit_reason(char *buf, size_t bufsz, int what, int why)
{
	switch (why) {
	case CLD_EXITED:
		(void) snprintf(buf, bufsz, "exited with status %d", what);
		break;
	case CLD_KILLED:
		(void) snprintf(buf, bufsz, "exited on fatal signal %d", what);
		break;
	case CLD_DUMPED:
		(void) snprintf(buf, bufsz, "core dumped on signal %d", what);
		break;
	default:
		(void) snprintf(buf, bufsz, "encountered unknown error "
		    "(%d, %d)", why, what);
		break;
	}

	return (buf);
}

/*
 * exit system call: pass back caller's arg.
 */
void
rexit(int rval)
{
	exit(CLD_EXITED, rval);
}

/*
 * Called by proc_exit() when a zone's init exits, presumably because
 * it failed.  As long as the given zone is still in the "running"
 * state, we will re-exec() init, but first we need to reset things
 * which are usually inherited across exec() but will break init's
 * assumption that it is being exec()'d from a virgin process.  Most
 * importantly this includes closing all file descriptors (exec only
 * closes those marked close-on-exec) and resetting signals (exec only
 * resets handled signals, and we need to clear any signals which
 * killed init).  Anything else that exec(2) says would be inherited,
 * but would affect the execution of init, needs to be reset.
 */
static int
restart_init(int what, int why)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	user_t *up = PTOU(p);

	vnode_t *oldcd, *oldrd;
	sess_t *sp;
	int i, err;
	char reason_buf[64];
	const char *ipath;

	/*
	 * Let zone admin (and global zone admin if this is for a non-global
	 * zone) know that init has failed and will be restarted.
	 */
	zcmn_err(p->p_zone->zone_id, CE_WARN,
	    "init(1M) %s: restarting automatically",
	    exit_reason(reason_buf, sizeof (reason_buf), what, why));

	if (!INGLOBALZONE(p)) {
		cmn_err(CE_WARN, "init(1M) for zone %s (pid %d) %s: "
		    "restarting automatically",
		    p->p_zone->zone_name, p->p_pid, reason_buf);
	}

	/*
	 * Remove any fpollinfo_t's for this (last) thread from our file
	 * descriptors so closeall() can ASSERT() that they're all gone.
	 * Then close all open file descriptors in the process.
	 */
	pollcleanup();
	closeall(P_FINFO(p));

	/*
	 * Grab p_lock and begin clearing miscellaneous global process
	 * state that needs to be reset before we exec the new init(1M).
	 */

	mutex_enter(&p->p_lock);
	prbarrier(p);

	p->p_flag &= ~(SKILLED | SEXTKILLED | SEXITING | SDOCORE);
	up->u_cmask = CMASK;

	sigemptyset(&t->t_hold);
	sigemptyset(&t->t_sig);
	sigemptyset(&t->t_extsig);

	sigemptyset(&p->p_sig);
	sigemptyset(&p->p_extsig);

	sigdelq(p, t, 0);
	sigdelq(p, NULL, 0);

	if (p->p_killsqp) {
		siginfofree(p->p_killsqp);
		p->p_killsqp = NULL;
	}

	/*
	 * Reset any signals that are ignored back to the default disposition.
	 * Other u_signal members will be cleared when exec calls sigdefault().
	 */
	for (i = 1; i < NSIG; i++) {
		if (up->u_signal[i - 1] == SIG_IGN) {
			up->u_signal[i - 1] = SIG_DFL;
			sigemptyset(&up->u_sigmask[i - 1]);
		}
	}

	/*
	 * Clear the current signal, any signal info associated with it, and
	 * any signal information from contracts and/or contract templates.
	 */
	lwp->lwp_cursig = 0;
	lwp->lwp_extsig = 0;
	if (lwp->lwp_curinfo != NULL) {
		siginfofree(lwp->lwp_curinfo);
		lwp->lwp_curinfo = NULL;
	}
	lwp_ctmpl_clear(lwp);

	/*
	 * Reset both the process root directory and the current working
	 * directory to the root of the zone just as we do during boot.
	 */
	VN_HOLD(p->p_zone->zone_rootvp);
	oldrd = up->u_rdir;
	up->u_rdir = p->p_zone->zone_rootvp;

	VN_HOLD(p->p_zone->zone_rootvp);
	oldcd = up->u_cdir;
	up->u_cdir = p->p_zone->zone_rootvp;

	if (up->u_cwd != NULL) {
		refstr_rele(up->u_cwd);
		up->u_cwd = NULL;
	}

	mutex_exit(&p->p_lock);

	if (oldrd != NULL)
		VN_RELE(oldrd);
	if (oldcd != NULL)
		VN_RELE(oldcd);

	/*
	 * Free the controlling tty.
	 */
	mutex_enter(&pidlock);
	sp = p->p_sessp;
	if (sp->s_sidp == p->p_pidp && sp->s_vp != NULL) {
		mutex_exit(&pidlock);
		freectty(sp);
	} else {
		mutex_exit(&pidlock);
	}

	/*
	 * Now exec() the new init(1M) on top of the current process.  If we
	 * succeed, the caller will treat this like a successful system call.
	 * If we fail, we issue messages and the caller will proceed with exit.
	 */
	ipath = INGLOBALZONE(p) ? initname : zone_initname;
	err = exec_init(ipath, 0, NULL);

	if (err == 0)
		return (0);

	zcmn_err(p->p_zone->zone_id, CE_WARN,
	    "failed to restart init(1M) (err=%d): system reboot required", err);

	if (!INGLOBALZONE(p)) {
		cmn_err(CE_WARN, "failed to restart init(1M) for zone %s "
		    "(pid %d, err=%d): zoneadm(1M) boot required",
		    p->p_zone->zone_name, p->p_pid, err);
	}

	return (-1);
}

/*
 * Release resources.
 * Enter zombie state.
 * Wake up parent and init processes,
 * and dispose of children.
 */
void
exit(int why, int what)
{
	/*
	 * If proc_exit() fails, then some other lwp in the process
	 * got there first.  We just have to call lwp_exit() to allow
	 * the other lwp to finish exiting the process.  Otherwise we're
	 * restarting init, and should return.
	 */
	if (proc_exit(why, what) != 0) {
		mutex_enter(&curproc->p_lock);
		ASSERT(curproc->p_flag & SEXITLWPS);
		lwp_exit();
		/* NOTREACHED */
	}
}

/*
 * Set the SEXITING flag on the process, after making sure /proc does
 * not have it locked.  This is done in more places than proc_exit(),
 * so it is a separate function.
 */
void
proc_is_exiting(proc_t *p)
{
	mutex_enter(&p->p_lock);
	prbarrier(p);
	p->p_flag |= SEXITING;
	mutex_exit(&p->p_lock);
}

/*
 * Return value:
 *   1 - exitlwps() failed, call (or continue) lwp_exit()
 *   0 - restarting init.  Return through system call path
 */
int
proc_exit(int why, int what)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	zone_t *z = p->p_zone;
	timeout_id_t tmp_id;
	int rv;
	proc_t *q;
	sess_t *sp;
	task_t *tk;
	vnode_t *exec_vp, *execdir_vp, *cdir, *rdir;
	sigqueue_t *sqp;
	lwpdir_t *lwpdir;
	uint_t lwpdir_sz;
	lwpdir_t **tidhash;
	uint_t tidhash_sz;
	refstr_t *cwd;
	hrtime_t hrutime, hrstime;

	/*
	 * Stop and discard the process's lwps except for the current one,
	 * unless some other lwp beat us to it.  If exitlwps() fails then
	 * return and the calling lwp will call (or continue in) lwp_exit().
	 */
	proc_is_exiting(p);
	if (exitlwps(0) != 0)
		return (1);

	DTRACE_PROC(lwp__exit);
	DTRACE_PROC1(exit, int, why);

	/*
	 * Don't let init exit unless zone_icode() failed its exec, or
	 * we are shutting down the zone or the machine.
	 *
	 * Since we are single threaded, we don't need to lock the
	 * following accesses to zone_proc_initpid.
	 */
	if (p->p_pid == z->zone_proc_initpid) {
		if (z->zone_boot_err == 0 &&
		    zone_status_get(z) < ZONE_IS_SHUTTING_DOWN &&
		    zone_status_get(global_zone) < ZONE_IS_SHUTTING_DOWN &&
		    restart_init(what, why) == 0)
			return (0);
		/*
		 * Since we didn't or couldn't restart init, we clear
		 * the zone's init state and proceed with exit
		 * processing.
		 */
		z->zone_proc_initpid = -1;
	}

	/*
	 * Allocate a sigqueue now, before we grab locks.
	 * It will be given to sigcld(), below.
	 */
	sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);

	/*
	 * revoke any doors created by the process.
	 */
	if (p->p_door_list)
		door_exit();

	/*
	 * Release schedctl data structures.
	 */
	if (p->p_pagep)
		schedctl_proc_cleanup();

	/*
	 * make sure all pending kaio has completed.
	 */
	if (p->p_aio)
		aio_cleanup_exit();

	/*
	 * discard the lwpchan cache.
	 */
	if (p->p_lcp != NULL)
		lwpchan_destroy_cache(0);

	/*
	 * Clean up any DTrace helper actions or probes for the process.
	 */
	if (p->p_dtrace_helpers != NULL) {
		ASSERT(dtrace_helpers_cleanup != NULL);
		(*dtrace_helpers_cleanup)();
	}

	/* untimeout the realtime timers */
	if (p->p_itimer != NULL)
		timer_exit();

	if ((tmp_id = p->p_alarmid) != 0) {
		p->p_alarmid = 0;
		(void) untimeout(tmp_id);
	}

	/*
	 * Remove any fpollinfo_t's for this (last) thread from our file
	 * descriptors so closeall() can ASSERT() that they're all gone.
	 */
	pollcleanup();

	if (p->p_rprof_cyclic != CYCLIC_NONE) {
		mutex_enter(&cpu_lock);
		cyclic_remove(p->p_rprof_cyclic);
		mutex_exit(&cpu_lock);
	}

	mutex_enter(&p->p_lock);

	/*
	 * Clean up any DTrace probes associated with this process.
	 */
	if (p->p_dtrace_probes) {
		ASSERT(dtrace_fasttrap_exit_ptr != NULL);
		dtrace_fasttrap_exit_ptr(p);
	}

	while ((tmp_id = p->p_itimerid) != 0) {
		p->p_itimerid = 0;
		mutex_exit(&p->p_lock);
		(void) untimeout(tmp_id);
		mutex_enter(&p->p_lock);
	}

	lwp_cleanup();

	/*
	 * We are about to exit; prevent our resource associations from
	 * being changed.
	 */
	pool_barrier_enter();

	/*
	 * Block the process against /proc now that we have really
	 * acquired p->p_lock (to manipulate p_tlist at least).
	 */
	prbarrier(p);

#ifdef	SUN_SRC_COMPAT
	if (code == CLD_KILLED)
		u.u_acflag |= AXSIG;
#endif
	sigfillset(&p->p_ignore);
	sigemptyset(&p->p_siginfo);
	sigemptyset(&p->p_sig);
	sigemptyset(&p->p_extsig);
	sigemptyset(&t->t_sig);
	sigemptyset(&t->t_extsig);
	sigemptyset(&p->p_sigmask);
	sigdelq(p, t, 0);
	lwp->lwp_cursig = 0;
	lwp->lwp_extsig = 0;
	p->p_flag &= ~(SKILLED | SEXTKILLED);
	if (lwp->lwp_curinfo) {
		siginfofree(lwp->lwp_curinfo);
		lwp->lwp_curinfo = NULL;
	}

	t->t_proc_flag |= TP_LWPEXIT;
	ASSERT(p->p_lwpcnt == 1 && p->p_zombcnt == 0);
	prlwpexit(t);		/* notify /proc */
	lwp_hash_out(p, t->t_tid);
	prexit(p);

	p->p_lwpcnt = 0;
	p->p_tlist = NULL;
	sigqfree(p);
	term_mstate(t);
	p->p_mterm = gethrtime();

	exec_vp = p->p_exec;
	execdir_vp = p->p_execdir;
	p->p_exec = NULLVP;
	p->p_execdir = NULLVP;
	mutex_exit(&p->p_lock);
	if (exec_vp)
		VN_RELE(exec_vp);
	if (execdir_vp)
		VN_RELE(execdir_vp);

	pr_free_watched_pages(p);

	closeall(P_FINFO(p));

	mutex_enter(&pidlock);
	sp = p->p_sessp;
	if (sp->s_sidp == p->p_pidp && sp->s_vp != NULL) {
		mutex_exit(&pidlock);
		freectty(sp);
	} else
		mutex_exit(&pidlock);

#if defined(__x86)
	/*
	 * If the process was using a private LDT then free it.
	 */
	if (p->p_ldt)
		ldt_free(p);
#endif

#if defined(__sparc)
	if (p->p_utraps != NULL)
		utrap_free(p);
#endif
	if (p->p_semacct)			/* IPC semaphore exit */
		semexit(p);
	rv = wstat(why, what);

	acct(rv & 0xff);
	exacct_commit_proc(p, rv);

	/*
	 * Release any resources associated with C2 auditing
	 */
#ifdef C2_AUDIT
	if (audit_active) {
		/*
		 * audit exit system call
		 */
		audit_exit(why, what);
	}
#endif

	/*
	 * Free address space.
	 */
	relvm();

	/*
	 * Release held contracts.
	 */
	contract_exit(p);

	/*
	 * Depart our encapsulating process contract.
	 */
	if ((p->p_flag & SSYS) == 0) {
		ASSERT(p->p_ct_process);
		contract_process_exit(p->p_ct_process, p, rv);
	}

	/*
	 * Remove pool association, and block if requested by pool_do_bind.
	 */
	mutex_enter(&p->p_lock);
	ASSERT(p->p_pool->pool_ref > 0);
	atomic_add_32(&p->p_pool->pool_ref, -1);
	p->p_pool = pool_default;
	/*
	 * Now that our address space has been freed and all other threads
	 * in this process have exited, set the PEXITED pool flag.  This
	 * tells the pools subsystems to ignore this process if it was
	 * requested to rebind this process to a new pool.
	 */
	p->p_poolflag |= PEXITED;
	pool_barrier_exit();
	mutex_exit(&p->p_lock);

	mutex_enter(&pidlock);

	/*
	 * Delete this process from the newstate list of its parent. We
	 * will put it in the right place in the sigcld in the end.
	 */
	delete_ns(p->p_parent, p);

	/*
	 * Reassign the orphans to the next of kin.
	 * Don't rearrange init's orphanage.
	 */
	if ((q = p->p_orphan) != NULL && p != proc_init) {

		proc_t *nokp = p->p_nextofkin;

		for (;;) {
			q->p_nextofkin = nokp;
			if (q->p_nextorph == NULL)
				break;
			q = q->p_nextorph;
		}
		q->p_nextorph = nokp->p_orphan;
		nokp->p_orphan = p->p_orphan;
		p->p_orphan = NULL;
	}

	/*
	 * Reassign the children to init.
	 * Don't try to assign init's children to init.
	 */
	if ((q = p->p_child) != NULL && p != proc_init) {
		struct proc	*np;
		struct proc	*initp = proc_init;
		boolean_t	setzonetop = B_FALSE;

		if (!INGLOBALZONE(curproc))
			setzonetop = B_TRUE;

		pgdetach(p);

		do {
			np = q->p_sibling;
			/*
			 * Delete it from its current parent new state
			 * list and add it to init new state list
			 */
			delete_ns(q->p_parent, q);

			q->p_ppid = 1;
			if (setzonetop) {
				mutex_enter(&q->p_lock);
				q->p_flag |= SZONETOP;
				mutex_exit(&q->p_lock);
			}
			q->p_parent = initp;

			/*
			 * Since q will be the first child,
			 * it will not have a previous sibling.
			 */
			q->p_psibling = NULL;
			if (initp->p_child) {
				initp->p_child->p_psibling = q;
			}
			q->p_sibling = initp->p_child;
			initp->p_child = q;
			if (q->p_proc_flag & P_PR_PTRACE) {
				mutex_enter(&q->p_lock);
				sigtoproc(q, NULL, SIGKILL);
				mutex_exit(&q->p_lock);
			}
			/*
			 * sigcld() will add the child to parents
			 * newstate list.
			 */
			if (q->p_stat == SZOMB)
				sigcld(q, NULL);
		} while ((q = np) != NULL);

		p->p_child = NULL;
		ASSERT(p->p_child_ns == NULL);
	}

	TRACE_1(TR_FAC_PROC, TR_PROC_EXIT, "proc_exit: %p", p);

	mutex_enter(&p->p_lock);
	CL_EXIT(curthread); /* tell the scheduler that curthread is exiting */

	hrutime = mstate_aggr_state(p, LMS_USER);
	hrstime = mstate_aggr_state(p, LMS_SYSTEM);
	p->p_utime = (clock_t)NSEC_TO_TICK(hrutime) + p->p_cutime;
	p->p_stime = (clock_t)NSEC_TO_TICK(hrstime) + p->p_cstime;

	p->p_acct[LMS_USER]	+= p->p_cacct[LMS_USER];
	p->p_acct[LMS_SYSTEM]	+= p->p_cacct[LMS_SYSTEM];
	p->p_acct[LMS_TRAP]	+= p->p_cacct[LMS_TRAP];
	p->p_acct[LMS_TFAULT]	+= p->p_cacct[LMS_TFAULT];
	p->p_acct[LMS_DFAULT]	+= p->p_cacct[LMS_DFAULT];
	p->p_acct[LMS_KFAULT]	+= p->p_cacct[LMS_KFAULT];
	p->p_acct[LMS_USER_LOCK] += p->p_cacct[LMS_USER_LOCK];
	p->p_acct[LMS_SLEEP]	+= p->p_cacct[LMS_SLEEP];
	p->p_acct[LMS_WAIT_CPU]	+= p->p_cacct[LMS_WAIT_CPU];
	p->p_acct[LMS_STOPPED]	+= p->p_cacct[LMS_STOPPED];

	p->p_ru.minflt	+= p->p_cru.minflt;
	p->p_ru.majflt	+= p->p_cru.majflt;
	p->p_ru.nswap	+= p->p_cru.nswap;
	p->p_ru.inblock	+= p->p_cru.inblock;
	p->p_ru.oublock	+= p->p_cru.oublock;
	p->p_ru.msgsnd	+= p->p_cru.msgsnd;
	p->p_ru.msgrcv	+= p->p_cru.msgrcv;
	p->p_ru.nsignals += p->p_cru.nsignals;
	p->p_ru.nvcsw	+= p->p_cru.nvcsw;
	p->p_ru.nivcsw	+= p->p_cru.nivcsw;
	p->p_ru.sysc	+= p->p_cru.sysc;
	p->p_ru.ioch	+= p->p_cru.ioch;

	p->p_stat = SZOMB;
	p->p_proc_flag &= ~P_PR_PTRACE;
	p->p_wdata = what;
	p->p_wcode = (char)why;

	cdir = PTOU(p)->u_cdir;
	rdir = PTOU(p)->u_rdir;
	cwd = PTOU(p)->u_cwd;

	/*
	 * Release resource controls, as they are no longer enforceable.
	 */
	rctl_set_free(p->p_rctls);

	/*
	 * Give up task and project memberships.  Decrement tk_nlwps counter
	 * for our task.max-lwps resource control.  An extended accounting
	 * record, if that facility is active, is scheduled to be written.
	 * Zombie processes are false members of task0 for the remainder of
	 * their lifetime; no accounting information is recorded for them.
	 */
	tk = p->p_task;

	mutex_enter(&p->p_zone->zone_nlwps_lock);
	tk->tk_nlwps--;
	tk->tk_proj->kpj_nlwps--;
	p->p_zone->zone_nlwps--;
	mutex_exit(&p->p_zone->zone_nlwps_lock);
	task_detach(p);
	p->p_task = task0p;

	/*
	 * Clear the lwp directory and the lwpid hash table
	 * now that /proc can't bother us any more.
	 * We free the memory below, after dropping p->p_lock.
	 */
	lwpdir = p->p_lwpdir;
	lwpdir_sz = p->p_lwpdir_sz;
	tidhash = p->p_tidhash;
	tidhash_sz = p->p_tidhash_sz;
	p->p_lwpdir = NULL;
	p->p_lwpfree = NULL;
	p->p_lwpdir_sz = 0;
	p->p_tidhash = NULL;
	p->p_tidhash_sz = 0;

	/*
	 * curthread's proc pointer is changed to point at p0 because
	 * curthread's original proc pointer can be freed as soon as
	 * the child sends a SIGCLD to its parent.
	 */
	t->t_procp = &p0;

	mutex_exit(&p->p_lock);
	sigcld(p, sqp);
	mutex_exit(&pidlock);

	task_rele(tk);

	kmem_free(lwpdir, lwpdir_sz * sizeof (lwpdir_t));
	kmem_free(tidhash, tidhash_sz * sizeof (lwpdir_t *));

	/*
	 * We don't release u_cdir and u_rdir until SZOMB is set.
	 * This protects us against dofusers().
	 */
	VN_RELE(cdir);
	if (rdir)
		VN_RELE(rdir);
	if (cwd)
		refstr_rele(cwd);

	lwp_pcb_exit();

	thread_exit();
	/* NOTREACHED */
}

/*
 * Format siginfo structure for wait system calls.
 */
void
winfo(proc_t *pp, k_siginfo_t *ip, int waitflag)
{
	ASSERT(MUTEX_HELD(&pidlock));

	bzero(ip, sizeof (k_siginfo_t));
	ip->si_signo = SIGCLD;
	ip->si_code = pp->p_wcode;
	ip->si_pid = pp->p_pid;
	ip->si_ctid = PRCTID(pp);
	ip->si_zoneid = pp->p_zone->zone_id;
	ip->si_status = pp->p_wdata;
	ip->si_stime = pp->p_stime;
	ip->si_utime = pp->p_utime;

	if (waitflag) {
		pp->p_wcode = 0;
		pp->p_wdata = 0;
		pp->p_pidflag &= ~CLDPEND;
	}
}

/*
 * Wait system call.
 * Search for a terminated (zombie) child,
 * finally lay it to rest, and collect its status.
 * Look also for stopped children,
 * and pass back status from them.
 */
int
waitid(idtype_t idtype, id_t id, k_siginfo_t *ip, int options)
{
	int found;
	proc_t *cp, *pp;
	proc_t **nsp;
	int proc_gone;
	int waitflag = !(options & WNOWAIT);

	/*
	 * Obsolete flag, defined here only for binary compatibility
	 * with old statically linked executables.  Delete this when
	 * we no longer care about these old and broken applications.
	 */
#define	_WNOCHLD	0400
	options &= ~_WNOCHLD;

	if (options == 0 || (options & ~WOPTMASK))
		return (EINVAL);

	switch (idtype) {
	case P_PID:
	case P_PGID:
		if (id < 0 || id >= maxpid)
			return (EINVAL);
		/* FALLTHROUGH */
	case P_ALL:
		break;
	default:
		return (EINVAL);
	}

	pp = ttoproc(curthread);
	/*
	 * lock parent mutex so that sibling chain can be searched.
	 */
	mutex_enter(&pidlock);
	while ((cp = pp->p_child) != NULL) {

		proc_gone = 0;

		for (nsp = &pp->p_child_ns; *nsp; nsp = &(*nsp)->p_sibling_ns) {
			if (idtype == P_PID && id != (*nsp)->p_pid) {
				continue;
			}
			if (idtype == P_PGID && id != (*nsp)->p_pgrp) {
				continue;
			}

			switch ((*nsp)->p_wcode) {

			case CLD_TRAPPED:
			case CLD_STOPPED:
			case CLD_CONTINUED:
				cmn_err(CE_PANIC,
				    "waitid: wrong state %d on the p_newstate"
				    " list", (*nsp)->p_wcode);
				break;

			case CLD_EXITED:
			case CLD_DUMPED:
			case CLD_KILLED:
				if (!(options & WEXITED)) {
					/*
					 * Count how many are already gone
					 * for good.
					 */
					proc_gone++;
					break;
				}
				if (!waitflag) {
					winfo((*nsp), ip, 0);
				} else {
					proc_t *xp = *nsp;
					winfo(xp, ip, 1);
					freeproc(xp);
				}
				mutex_exit(&pidlock);
				if (waitflag) {		/* accept SIGCLD */
					sigcld_delete(ip);
					sigcld_repost();
				}
				return (0);
			}

			if (idtype == P_PID)
				break;
		}

		/*
		 * Wow! None of the threads on the p_sibling_ns list were
		 * interesting threads. Check all the kids!
		 */
		found = 0;
		cp = pp->p_child;
		do {
			if (idtype == P_PID && id != cp->p_pid) {
				continue;
			}
			if (idtype == P_PGID && id != cp->p_pgrp) {
				continue;
			}

			found++;

			switch (cp->p_wcode) {
			case CLD_TRAPPED:
				if (!(options & WTRAPPED))
					break;
				winfo(cp, ip, waitflag);
				mutex_exit(&pidlock);
				if (waitflag) {		/* accept SIGCLD */
					sigcld_delete(ip);
					sigcld_repost();
				}
				return (0);

			case CLD_STOPPED:
				if (!(options & WSTOPPED))
					break;
				/* Is it still stopped? */
				mutex_enter(&cp->p_lock);
				if (!jobstopped(cp)) {
					mutex_exit(&cp->p_lock);
					break;
				}
				mutex_exit(&cp->p_lock);
				winfo(cp, ip, waitflag);
				mutex_exit(&pidlock);
				if (waitflag) {		/* accept SIGCLD */
					sigcld_delete(ip);
					sigcld_repost();
				}
				return (0);

			case CLD_CONTINUED:
				if (!(options & WCONTINUED))
					break;
				winfo(cp, ip, waitflag);
				mutex_exit(&pidlock);
				if (waitflag) {		/* accept SIGCLD */
					sigcld_delete(ip);
					sigcld_repost();
				}
				return (0);

			case CLD_EXITED:
			case CLD_DUMPED:
			case CLD_KILLED:
				/*
				 * Don't complain if a process was found in
				 * the first loop but we broke out of the loop
				 * because of the arguments passed to us.
				 */
				if (proc_gone == 0) {
					cmn_err(CE_PANIC,
					    "waitid: wrong state on the"
					    " p_child list");
				} else {
					break;
				}
			}

			if (idtype == P_PID)
				break;
		} while ((cp = cp->p_sibling) != NULL);

		/*
		 * If we found no interesting processes at all,
		 * break out and return ECHILD.
		 */
		if (found + proc_gone == 0)
			break;

		if (options & WNOHANG) {
			bzero(ip, sizeof (k_siginfo_t));
			/*
			 * We should set ip->si_signo = SIGCLD,
			 * but there is an SVVS test that expects
			 * ip->si_signo to be zero in this case.
			 */
			mutex_exit(&pidlock);
			return (0);
		}

		/*
		 * If we found no processes of interest that could
		 * change state while we wait, we don't wait at all.
		 * Get out with ECHILD according to SVID.
		 */
		if (found == proc_gone)
			break;

		if (!cv_wait_sig_swap(&pp->p_cv, &pidlock)) {
			mutex_exit(&pidlock);
			return (EINTR);
		}
	}
	mutex_exit(&pidlock);
	return (ECHILD);
}

/*
 * For implementations that don't require binary compatibility,
 * the wait system call may be made into a library call to the
 * waitid system call.
 */
int64_t
wait(void)
{
	int error;
	k_siginfo_t info;
	rval_t	r;

	if (error =  waitid(P_ALL, (id_t)0, &info, WEXITED|WTRAPPED))
		return (set_errno(error));
	r.r_val1 = info.si_pid;
	r.r_val2 = wstat(info.si_code, info.si_status);
	return (r.r_vals);
}

int
waitsys(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
	int error;
	k_siginfo_t info;

	if (error = waitid(idtype, id, &info, options))
		return (set_errno(error));
	if (copyout(&info, infop, sizeof (k_siginfo_t)))
		return (set_errno(EFAULT));
	return (0);
}

#ifdef _SYSCALL32_IMPL

int
waitsys32(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
	int error;
	k_siginfo_t info;
	siginfo32_t info32;

	if (error = waitid(idtype, id, &info, options))
		return (set_errno(error));
	siginfo_kto32(&info, &info32);
	if (copyout(&info32, infop, sizeof (info32)))
		return (set_errno(EFAULT));
	return (0);
}

#endif	/* _SYSCALL32_IMPL */

void
proc_detach(proc_t *p)
{
	proc_t *q;

	ASSERT(MUTEX_HELD(&pidlock));

	q = p->p_parent;
	ASSERT(q != NULL);

	/*
	 * Take it off the newstate list of its parent
	 */
	delete_ns(q, p);

	if (q->p_child == p) {
		q->p_child = p->p_sibling;
		/*
		 * If the parent has no children, it better not
		 * have any with new states either!
		 */
		ASSERT(q->p_child ? 1 : q->p_child_ns == NULL);
	}

	if (p->p_sibling) {
		p->p_sibling->p_psibling = p->p_psibling;
	}

	if (p->p_psibling) {
		p->p_psibling->p_sibling = p->p_sibling;
	}
}

/*
 * Remove zombie children from the process table.
 */
void
freeproc(proc_t *p)
{
	proc_t *q;

	ASSERT(p->p_stat == SZOMB);
	ASSERT(p->p_tlist == NULL);
	ASSERT(MUTEX_HELD(&pidlock));

	sigdelq(p, NULL, 0);
	if (p->p_killsqp) {
		siginfofree(p->p_killsqp);
		p->p_killsqp = NULL;
	}

	prfree(p);	/* inform /proc */

	/*
	 * Don't free the init processes.
	 * Other dying processes will access it.
	 */
	if (p == proc_init)
		return;


	/*
	 * We wait until now to free the cred structure because a
	 * zombie process's credentials may be examined by /proc.
	 * No cred locking needed because there are no threads at this point.
	 */
	upcount_dec(crgetruid(p->p_cred), crgetzoneid(p->p_cred));
	crfree(p->p_cred);
	if (p->p_corefile != NULL) {
		corectl_path_rele(p->p_corefile);
		p->p_corefile = NULL;
	}
	if (p->p_content != NULL) {
		corectl_content_rele(p->p_content);
		p->p_content = NULL;
	}

	if (p->p_nextofkin && !((p->p_nextofkin->p_flag & SNOWAIT) ||
	    (PTOU(p->p_nextofkin)->u_signal[SIGCLD - 1] == SIG_IGN))) {
		/*
		 * This should still do the right thing since p_utime/stime
		 * get set to the correct value on process exit, so it
		 * should get properly updated
		 */
		p->p_nextofkin->p_cutime += p->p_utime;
		p->p_nextofkin->p_cstime += p->p_stime;

		p->p_nextofkin->p_cacct[LMS_USER] += p->p_acct[LMS_USER];
		p->p_nextofkin->p_cacct[LMS_SYSTEM] += p->p_acct[LMS_SYSTEM];
		p->p_nextofkin->p_cacct[LMS_TRAP] += p->p_acct[LMS_TRAP];
		p->p_nextofkin->p_cacct[LMS_TFAULT] += p->p_acct[LMS_TFAULT];
		p->p_nextofkin->p_cacct[LMS_DFAULT] += p->p_acct[LMS_DFAULT];
		p->p_nextofkin->p_cacct[LMS_KFAULT] += p->p_acct[LMS_KFAULT];
		p->p_nextofkin->p_cacct[LMS_USER_LOCK]
		    += p->p_acct[LMS_USER_LOCK];
		p->p_nextofkin->p_cacct[LMS_SLEEP] += p->p_acct[LMS_SLEEP];
		p->p_nextofkin->p_cacct[LMS_WAIT_CPU]
		    += p->p_acct[LMS_WAIT_CPU];
		p->p_nextofkin->p_cacct[LMS_STOPPED] += p->p_acct[LMS_STOPPED];

		p->p_nextofkin->p_cru.minflt	+= p->p_ru.minflt;
		p->p_nextofkin->p_cru.majflt	+= p->p_ru.majflt;
		p->p_nextofkin->p_cru.nswap	+= p->p_ru.nswap;
		p->p_nextofkin->p_cru.inblock	+= p->p_ru.inblock;
		p->p_nextofkin->p_cru.oublock	+= p->p_ru.oublock;
		p->p_nextofkin->p_cru.msgsnd	+= p->p_ru.msgsnd;
		p->p_nextofkin->p_cru.msgrcv	+= p->p_ru.msgrcv;
		p->p_nextofkin->p_cru.nsignals	+= p->p_ru.nsignals;
		p->p_nextofkin->p_cru.nvcsw	+= p->p_ru.nvcsw;
		p->p_nextofkin->p_cru.nivcsw	+= p->p_ru.nivcsw;
		p->p_nextofkin->p_cru.sysc	+= p->p_ru.sysc;
		p->p_nextofkin->p_cru.ioch	+= p->p_ru.ioch;

	}

	q = p->p_nextofkin;
	if (q && q->p_orphan == p)
		q->p_orphan = p->p_nextorph;
	else if (q) {
		for (q = q->p_orphan; q; q = q->p_nextorph)
			if (q->p_nextorph == p)
				break;
		ASSERT(q && q->p_nextorph == p);
		q->p_nextorph = p->p_nextorph;
	}

	proc_detach(p);
	pid_exit(p);	/* frees pid and proc structure */
}

/*
 * Delete process "child" from the newstate list of process "parent"
 */
void
delete_ns(proc_t *parent, proc_t *child)
{
	proc_t **ns;

	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(child->p_parent == parent);
	for (ns = &parent->p_child_ns; *ns != NULL; ns = &(*ns)->p_sibling_ns) {
		if (*ns == child) {

			ASSERT((*ns)->p_parent == parent);

			*ns = child->p_sibling_ns;
			child->p_sibling_ns = NULL;
			return;
		}
	}
}

/*
 * Add process "child" to the new state list of process "parent"
 */
void
add_ns(proc_t *parent, proc_t *child)
{
	ASSERT(child->p_sibling_ns == NULL);
	child->p_sibling_ns = parent->p_child_ns;
	parent->p_child_ns = child;
}
