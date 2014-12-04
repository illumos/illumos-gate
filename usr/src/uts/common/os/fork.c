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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/cmn_err.h>
#include <sys/acct.h>
#include <sys/tuneable.h>
#include <sys/class.h>
#include <sys/kmem.h>
#include <sys/session.h>
#include <sys/ucontext.h>
#include <sys/stack.h>
#include <sys/procfs.h>
#include <sys/prsystm.h>
#include <sys/vmsystm.h>
#include <sys/vtrace.h>
#include <sys/debug.h>
#include <sys/shm_impl.h>
#include <sys/door_data.h>
#include <vm/as.h>
#include <vm/rm.h>
#include <c2/audit.h>
#include <sys/var.h>
#include <sys/schedctl.h>
#include <sys/utrap.h>
#include <sys/task.h>
#include <sys/resource.h>
#include <sys/cyclic.h>
#include <sys/lgrp.h>
#include <sys/rctl.h>
#include <sys/contract_impl.h>
#include <sys/contract/process_impl.h>
#include <sys/list.h>
#include <sys/dtrace.h>
#include <sys/pool.h>
#include <sys/zone.h>
#include <sys/sdt.h>
#include <sys/class.h>
#include <sys/corectl.h>
#include <sys/brand.h>
#include <sys/fork.h>

static int64_t cfork(int, int, int);
static int getproc(proc_t **, pid_t, uint_t);
#define	GETPROC_USER	0x0
#define	GETPROC_KERNEL	0x1

static void fork_fail(proc_t *);
static void forklwp_fail(proc_t *);

int fork_fail_pending;

extern struct kmem_cache *process_cache;

/*
 * The vfork() system call trap is no longer invoked by libc.
 * It is retained only for the benefit of applications running
 * within a solaris10 branded zone.  It should be eliminated
 * when we no longer support solaris10 branded zones.
 */
int64_t
vfork(void)
{
	curthread->t_post_sys = 1;	/* so vfwait() will be called */
	return (cfork(1, 1, 0));
}

/*
 * forksys system call - forkx, forkallx, vforkx.  This is the
 * interface invoked by libc for fork1(), forkall(), and vfork()
 */
int64_t
forksys(int subcode, int flags)
{
	switch (subcode) {
	case 0:
		return (cfork(0, 1, flags));	/* forkx(flags) */
	case 1:
		return (cfork(0, 0, flags));	/* forkallx(flags) */
	case 2:
		curthread->t_post_sys = 1;	/* so vfwait() will be called */
		return (cfork(1, 1, flags));	/* vforkx(flags) */
	default:
		return ((int64_t)set_errno(EINVAL));
	}
}

/* ARGSUSED */
static int64_t
cfork(int isvfork, int isfork1, int flags)
{
	proc_t *p = ttoproc(curthread);
	struct as *as;
	proc_t *cp, **orphpp;
	klwp_t *clone;
	kthread_t *t;
	task_t *tk;
	rval_t	r;
	int error;
	int i;
	rctl_set_t *dup_set;
	rctl_alloc_gp_t *dup_gp;
	rctl_entity_p_t e;
	lwpdir_t *ldp;
	lwpent_t *lep;
	lwpent_t *clep;

	/*
	 * Allow only these two flags.
	 */
	if ((flags & ~(FORK_NOSIGCHLD | FORK_WAITPID)) != 0) {
		error = EINVAL;
		atomic_inc_32(&curproc->p_zone->zone_ffmisc);
		goto forkerr;
	}

	/*
	 * fork is not supported for the /proc agent lwp.
	 */
	if (curthread == p->p_agenttp) {
		error = ENOTSUP;
		atomic_inc_32(&curproc->p_zone->zone_ffmisc);
		goto forkerr;
	}

	if ((error = secpolicy_basic_fork(CRED())) != 0) {
		atomic_inc_32(&p->p_zone->zone_ffmisc);
		goto forkerr;
	}

	/*
	 * If the calling lwp is doing a fork1() then the
	 * other lwps in this process are not duplicated and
	 * don't need to be held where their kernel stacks can be
	 * cloned.  If doing forkall(), the process is held with
	 * SHOLDFORK, so that the lwps are at a point where their
	 * stacks can be copied which is on entry or exit from
	 * the kernel.
	 */
	if (!holdlwps(isfork1 ? SHOLDFORK1 : SHOLDFORK)) {
		aston(curthread);
		error = EINTR;
		atomic_inc_32(&p->p_zone->zone_ffmisc);
		goto forkerr;
	}

#if defined(__sparc)
	/*
	 * Ensure that the user stack is fully constructed
	 * before creating the child process structure.
	 */
	(void) flush_user_windows_to_stack(NULL);
#endif

	mutex_enter(&p->p_lock);
	/*
	 * If this is vfork(), cancel any suspend request we might
	 * have gotten from some other thread via lwp_suspend().
	 * Otherwise we could end up with a deadlock on return
	 * from the vfork() in both the parent and the child.
	 */
	if (isvfork)
		curthread->t_proc_flag &= ~TP_HOLDLWP;
	/*
	 * Prevent our resource set associations from being changed during fork.
	 */
	pool_barrier_enter();
	mutex_exit(&p->p_lock);

	/*
	 * Create a child proc struct. Place a VN_HOLD on appropriate vnodes.
	 */
	if (getproc(&cp, 0, GETPROC_USER) < 0) {
		mutex_enter(&p->p_lock);
		pool_barrier_exit();
		continuelwps(p);
		mutex_exit(&p->p_lock);
		error = EAGAIN;
		goto forkerr;
	}

	TRACE_2(TR_FAC_PROC, TR_PROC_FORK, "proc_fork:cp %p p %p", cp, p);

	/*
	 * Assign an address space to child
	 */
	if (isvfork) {
		/*
		 * Clear any watched areas and remember the
		 * watched pages for restoring in vfwait().
		 */
		as = p->p_as;
		if (avl_numnodes(&as->a_wpage) != 0) {
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
			as_clearwatch(as);
			p->p_wpage = as->a_wpage;
			avl_create(&as->a_wpage, wp_compare,
			    sizeof (struct watched_page),
			    offsetof(struct watched_page, wp_link));
			AS_LOCK_EXIT(as, &as->a_lock);
		}
		cp->p_as = as;
		cp->p_flag |= SVFORK;

		/*
		 * Use the parent's shm segment list information for
		 * the child as it uses its address space till it execs.
		 */
		cp->p_segacct = p->p_segacct;
	} else {
		/*
		 * We need to hold P_PR_LOCK until the address space has
		 * been duplicated and we've had a chance to remove from the
		 * child any DTrace probes that were in the parent. Holding
		 * P_PR_LOCK prevents any new probes from being added and any
		 * extant probes from being removed.
		 */
		mutex_enter(&p->p_lock);
		sprlock_proc(p);
		p->p_flag |= SFORKING;
		mutex_exit(&p->p_lock);

		error = as_dup(p->p_as, cp);
		if (error != 0) {
			mutex_enter(&p->p_lock);
			sprunlock(p);
			fork_fail(cp);
			mutex_enter(&pidlock);
			orphpp = &p->p_orphan;
			while (*orphpp != cp)
				orphpp = &(*orphpp)->p_nextorph;
			*orphpp = cp->p_nextorph;
			if (p->p_child == cp)
				p->p_child = cp->p_sibling;
			if (cp->p_sibling)
				cp->p_sibling->p_psibling = cp->p_psibling;
			if (cp->p_psibling)
				cp->p_psibling->p_sibling = cp->p_sibling;
			mutex_enter(&cp->p_lock);
			tk = cp->p_task;
			task_detach(cp);
			ASSERT(cp->p_pool->pool_ref > 0);
			atomic_dec_32(&cp->p_pool->pool_ref);
			mutex_exit(&cp->p_lock);
			pid_exit(cp, tk);
			mutex_exit(&pidlock);
			task_rele(tk);

			mutex_enter(&p->p_lock);
			p->p_flag &= ~SFORKING;
			pool_barrier_exit();
			continuelwps(p);
			mutex_exit(&p->p_lock);
			/*
			 * Preserve ENOMEM error condition but
			 * map all others to EAGAIN.
			 */
			error = (error == ENOMEM) ? ENOMEM : EAGAIN;
			atomic_inc_32(&p->p_zone->zone_ffnomem);
			goto forkerr;
		}

		/*
		 * Remove all DTrace tracepoints from the child process. We
		 * need to do this _before_ duplicating USDT providers since
		 * any associated probes may be immediately enabled.
		 */
		if (p->p_dtrace_count > 0)
			dtrace_fasttrap_fork(p, cp);

		mutex_enter(&p->p_lock);
		sprunlock(p);

		/* Duplicate parent's shared memory */
		if (p->p_segacct)
			shmfork(p, cp);

		/*
		 * Duplicate any helper actions and providers. The SFORKING
		 * we set above informs the code to enable USDT probes that
		 * sprlock() may fail because the child is being forked.
		 */
		if (p->p_dtrace_helpers != NULL) {
			ASSERT(dtrace_helpers_fork != NULL);
			(*dtrace_helpers_fork)(p, cp);
		}

		mutex_enter(&p->p_lock);
		p->p_flag &= ~SFORKING;
		mutex_exit(&p->p_lock);
	}

	/*
	 * Duplicate parent's resource controls.
	 */
	dup_set = rctl_set_create();
	for (;;) {
		dup_gp = rctl_set_dup_prealloc(p->p_rctls);
		mutex_enter(&p->p_rctls->rcs_lock);
		if (rctl_set_dup_ready(p->p_rctls, dup_gp))
			break;
		mutex_exit(&p->p_rctls->rcs_lock);
		rctl_prealloc_destroy(dup_gp);
	}
	e.rcep_p.proc = cp;
	e.rcep_t = RCENTITY_PROCESS;
	cp->p_rctls = rctl_set_dup(p->p_rctls, p, cp, &e, dup_set, dup_gp,
	    RCD_DUP | RCD_CALLBACK);
	mutex_exit(&p->p_rctls->rcs_lock);

	rctl_prealloc_destroy(dup_gp);

	/*
	 * Allocate the child's lwp directory and lwpid hash table.
	 */
	if (isfork1)
		cp->p_lwpdir_sz = 2;
	else
		cp->p_lwpdir_sz = p->p_lwpdir_sz;
	cp->p_lwpdir = cp->p_lwpfree = ldp =
	    kmem_zalloc(cp->p_lwpdir_sz * sizeof (lwpdir_t), KM_SLEEP);
	for (i = 1; i < cp->p_lwpdir_sz; i++, ldp++)
		ldp->ld_next = ldp + 1;
	cp->p_tidhash_sz = (cp->p_lwpdir_sz + 2) / 2;
	cp->p_tidhash =
	    kmem_zalloc(cp->p_tidhash_sz * sizeof (tidhash_t), KM_SLEEP);

	/*
	 * Duplicate parent's lwps.
	 * Mutual exclusion is not needed because the process is
	 * in the hold state and only the current lwp is running.
	 */
	klgrpset_clear(cp->p_lgrpset);
	if (isfork1) {
		clone = forklwp(ttolwp(curthread), cp, curthread->t_tid);
		if (clone == NULL)
			goto forklwperr;
		/*
		 * Inherit only the lwp_wait()able flag,
		 * Daemon threads should not call fork1(), but oh well...
		 */
		lwptot(clone)->t_proc_flag |=
		    (curthread->t_proc_flag & TP_TWAIT);
	} else {
		/* this is forkall(), no one can be in lwp_wait() */
		ASSERT(p->p_lwpwait == 0 && p->p_lwpdwait == 0);
		/* for each entry in the parent's lwp directory... */
		for (i = 0, ldp = p->p_lwpdir; i < p->p_lwpdir_sz; i++, ldp++) {
			klwp_t *clwp;
			kthread_t *ct;

			if ((lep = ldp->ld_entry) == NULL)
				continue;

			if ((t = lep->le_thread) != NULL) {
				clwp = forklwp(ttolwp(t), cp, t->t_tid);
				if (clwp == NULL)
					goto forklwperr;
				ct = lwptot(clwp);
				/*
				 * Inherit lwp_wait()able and daemon flags.
				 */
				ct->t_proc_flag |=
				    (t->t_proc_flag & (TP_TWAIT|TP_DAEMON));
				/*
				 * Keep track of the clone of curthread to
				 * post return values through lwp_setrval().
				 * Mark other threads for special treatment
				 * by lwp_rtt() / post_syscall().
				 */
				if (t == curthread)
					clone = clwp;
				else
					ct->t_flag |= T_FORKALL;
			} else {
				/*
				 * Replicate zombie lwps in the child.
				 */
				clep = kmem_zalloc(sizeof (*clep), KM_SLEEP);
				clep->le_lwpid = lep->le_lwpid;
				clep->le_start = lep->le_start;
				lwp_hash_in(cp, clep,
				    cp->p_tidhash, cp->p_tidhash_sz, 0);
			}
		}
	}

	/*
	 * Put new process in the parent's process contract, or put it
	 * in a new one if there is an active process template.  Send a
	 * fork event (if requested) to whatever contract the child is
	 * a member of.  Fails if the parent has been SIGKILLed.
	 */
	if (contract_process_fork(NULL, cp, p, B_TRUE) == NULL) {
		atomic_inc_32(&p->p_zone->zone_ffmisc);
		goto forklwperr;
	}

	/*
	 * No fork failures occur beyond this point.
	 */

	cp->p_lwpid = p->p_lwpid;
	if (!isfork1) {
		cp->p_lwpdaemon = p->p_lwpdaemon;
		cp->p_zombcnt = p->p_zombcnt;
		/*
		 * If the parent's lwp ids have wrapped around, so have the
		 * child's.
		 */
		cp->p_flag |= p->p_flag & SLWPWRAP;
	}

	mutex_enter(&p->p_lock);
	corectl_path_hold(cp->p_corefile = p->p_corefile);
	corectl_content_hold(cp->p_content = p->p_content);
	mutex_exit(&p->p_lock);

	/*
	 * Duplicate process context ops, if any.
	 */
	if (p->p_pctx)
		forkpctx(p, cp);

#ifdef __sparc
	utrap_dup(p, cp);
#endif
	/*
	 * If the child process has been marked to stop on exit
	 * from this fork, arrange for all other lwps to stop in
	 * sympathy with the active lwp.
	 */
	if (PTOU(cp)->u_systrap &&
	    prismember(&PTOU(cp)->u_exitmask, curthread->t_sysnum)) {
		mutex_enter(&cp->p_lock);
		t = cp->p_tlist;
		do {
			t->t_proc_flag |= TP_PRSTOP;
			aston(t);	/* so TP_PRSTOP will be seen */
		} while ((t = t->t_forw) != cp->p_tlist);
		mutex_exit(&cp->p_lock);
	}
	/*
	 * If the parent process has been marked to stop on exit
	 * from this fork, and its asynchronous-stop flag has not
	 * been set, arrange for all other lwps to stop before
	 * they return back to user level.
	 */
	if (!(p->p_proc_flag & P_PR_ASYNC) && PTOU(p)->u_systrap &&
	    prismember(&PTOU(p)->u_exitmask, curthread->t_sysnum)) {
		mutex_enter(&p->p_lock);
		t = p->p_tlist;
		do {
			t->t_proc_flag |= TP_PRSTOP;
			aston(t);	/* so TP_PRSTOP will be seen */
		} while ((t = t->t_forw) != p->p_tlist);
		mutex_exit(&p->p_lock);
	}

	if (PROC_IS_BRANDED(p))
		BROP(p)->b_lwp_setrval(clone, p->p_pid, 1);
	else
		lwp_setrval(clone, p->p_pid, 1);

	/* set return values for parent */
	r.r_val1 = (int)cp->p_pid;
	r.r_val2 = 0;

	/*
	 * pool_barrier_exit() can now be called because the child process has:
	 * - all identifying features cloned or set (p_pid, p_task, p_pool)
	 * - all resource sets associated (p_tlist->*->t_cpupart, p_as->a_mset)
	 * - any other fields set which are used in resource set binding.
	 */
	mutex_enter(&p->p_lock);
	pool_barrier_exit();
	mutex_exit(&p->p_lock);

	mutex_enter(&pidlock);
	mutex_enter(&cp->p_lock);

	/*
	 * Set flags telling the child what (not) to do on exit.
	 */
	if (flags & FORK_NOSIGCHLD)
		cp->p_pidflag |= CLDNOSIGCHLD;
	if (flags & FORK_WAITPID)
		cp->p_pidflag |= CLDWAITPID;

	/*
	 * Now that there are lwps and threads attached, add the new
	 * process to the process group.
	 */
	pgjoin(cp, p->p_pgidp);
	cp->p_stat = SRUN;
	/*
	 * We are now done with all the lwps in the child process.
	 */
	t = cp->p_tlist;
	do {
		/*
		 * Set the lwp_suspend()ed lwps running.
		 * They will suspend properly at syscall exit.
		 */
		if (t->t_proc_flag & TP_HOLDLWP)
			lwp_create_done(t);
		else {
			/* set TS_CREATE to allow continuelwps() to work */
			thread_lock(t);
			ASSERT(t->t_state == TS_STOPPED &&
			    !(t->t_schedflag & (TS_CREATE|TS_CSTART)));
			t->t_schedflag |= TS_CREATE;
			thread_unlock(t);
		}
	} while ((t = t->t_forw) != cp->p_tlist);
	mutex_exit(&cp->p_lock);

	if (isvfork) {
		CPU_STATS_ADDQ(CPU, sys, sysvfork, 1);
		mutex_enter(&p->p_lock);
		p->p_flag |= SVFWAIT;
		curthread->t_flag |= T_VFPARENT;
		DTRACE_PROC1(create, proc_t *, cp);
		cv_broadcast(&pr_pid_cv[p->p_slot]);	/* inform /proc */
		mutex_exit(&p->p_lock);
		/*
		 * Grab child's p_lock before dropping pidlock to ensure
		 * the process will not disappear before we set it running.
		 */
		mutex_enter(&cp->p_lock);
		mutex_exit(&pidlock);
		sigdefault(cp);
		continuelwps(cp);
		mutex_exit(&cp->p_lock);
	} else {
		CPU_STATS_ADDQ(CPU, sys, sysfork, 1);
		DTRACE_PROC1(create, proc_t *, cp);
		/*
		 * It is CL_FORKRET's job to drop pidlock.
		 * If we do it here, the process could be set running
		 * and disappear before CL_FORKRET() is called.
		 */
		CL_FORKRET(curthread, cp->p_tlist);
		schedctl_set_cidpri(curthread);
		ASSERT(MUTEX_NOT_HELD(&pidlock));
	}

	return (r.r_vals);

forklwperr:
	if (isvfork) {
		if (avl_numnodes(&p->p_wpage) != 0) {
			/* restore watchpoints to parent */
			as = p->p_as;
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
			as->a_wpage = p->p_wpage;
			avl_create(&p->p_wpage, wp_compare,
			    sizeof (struct watched_page),
			    offsetof(struct watched_page, wp_link));
			as_setwatch(as);
			AS_LOCK_EXIT(as, &as->a_lock);
		}
	} else {
		if (cp->p_segacct)
			shmexit(cp);
		as = cp->p_as;
		cp->p_as = &kas;
		as_free(as);
	}

	if (cp->p_lwpdir) {
		for (i = 0, ldp = cp->p_lwpdir; i < cp->p_lwpdir_sz; i++, ldp++)
			if ((lep = ldp->ld_entry) != NULL)
				kmem_free(lep, sizeof (*lep));
		kmem_free(cp->p_lwpdir,
		    cp->p_lwpdir_sz * sizeof (*cp->p_lwpdir));
	}
	cp->p_lwpdir = NULL;
	cp->p_lwpfree = NULL;
	cp->p_lwpdir_sz = 0;

	if (cp->p_tidhash)
		kmem_free(cp->p_tidhash,
		    cp->p_tidhash_sz * sizeof (*cp->p_tidhash));
	cp->p_tidhash = NULL;
	cp->p_tidhash_sz = 0;

	forklwp_fail(cp);
	fork_fail(cp);
	rctl_set_free(cp->p_rctls);
	mutex_enter(&pidlock);

	/*
	 * Detach failed child from task.
	 */
	mutex_enter(&cp->p_lock);
	tk = cp->p_task;
	task_detach(cp);
	ASSERT(cp->p_pool->pool_ref > 0);
	atomic_dec_32(&cp->p_pool->pool_ref);
	mutex_exit(&cp->p_lock);

	orphpp = &p->p_orphan;
	while (*orphpp != cp)
		orphpp = &(*orphpp)->p_nextorph;
	*orphpp = cp->p_nextorph;
	if (p->p_child == cp)
		p->p_child = cp->p_sibling;
	if (cp->p_sibling)
		cp->p_sibling->p_psibling = cp->p_psibling;
	if (cp->p_psibling)
		cp->p_psibling->p_sibling = cp->p_sibling;
	pid_exit(cp, tk);
	mutex_exit(&pidlock);

	task_rele(tk);

	mutex_enter(&p->p_lock);
	pool_barrier_exit();
	continuelwps(p);
	mutex_exit(&p->p_lock);
	error = EAGAIN;
forkerr:
	return ((int64_t)set_errno(error));
}

/*
 * Free allocated resources from getproc() if a fork failed.
 */
static void
fork_fail(proc_t *cp)
{
	uf_info_t *fip = P_FINFO(cp);

	fcnt_add(fip, -1);
	sigdelq(cp, NULL, 0);

	mutex_enter(&pidlock);
	upcount_dec(crgetruid(cp->p_cred), crgetzoneid(cp->p_cred));
	mutex_exit(&pidlock);

	/*
	 * single threaded, so no locking needed here
	 */
	crfree(cp->p_cred);

	kmem_free(fip->fi_list, fip->fi_nfiles * sizeof (uf_entry_t));

	VN_RELE(PTOU(curproc)->u_cdir);
	if (PTOU(curproc)->u_rdir)
		VN_RELE(PTOU(curproc)->u_rdir);
	if (cp->p_exec)
		VN_RELE(cp->p_exec);
	if (cp->p_execdir)
		VN_RELE(cp->p_execdir);
	if (PTOU(curproc)->u_cwd)
		refstr_rele(PTOU(curproc)->u_cwd);
	if (PROC_IS_BRANDED(cp)) {
		brand_clearbrand(cp, B_TRUE);
	}
}

/*
 * Clean up the lwps already created for this child process.
 * The fork failed while duplicating all the lwps of the parent
 * and those lwps already created must be freed.
 * This process is invisible to the rest of the system,
 * so we don't need to hold p->p_lock to protect the list.
 */
static void
forklwp_fail(proc_t *p)
{
	kthread_t *t;
	task_t *tk;
	int branded = 0;

	if (PROC_IS_BRANDED(p))
		branded = 1;

	while ((t = p->p_tlist) != NULL) {
		/*
		 * First remove the lwp from the process's p_tlist.
		 */
		if (t != t->t_forw)
			p->p_tlist = t->t_forw;
		else
			p->p_tlist = NULL;
		p->p_lwpcnt--;
		t->t_forw->t_back = t->t_back;
		t->t_back->t_forw = t->t_forw;

		tk = p->p_task;
		mutex_enter(&p->p_zone->zone_nlwps_lock);
		tk->tk_nlwps--;
		tk->tk_proj->kpj_nlwps--;
		p->p_zone->zone_nlwps--;
		mutex_exit(&p->p_zone->zone_nlwps_lock);

		ASSERT(t->t_schedctl == NULL);

		if (branded)
			BROP(p)->b_freelwp(ttolwp(t));

		if (t->t_door != NULL) {
			kmem_free(t->t_door, sizeof (door_data_t));
			t->t_door = NULL;
		}
		lwp_ctmpl_clear(ttolwp(t));

		/*
		 * Remove the thread from the all threads list.
		 * We need to hold pidlock for this.
		 */
		mutex_enter(&pidlock);
		t->t_next->t_prev = t->t_prev;
		t->t_prev->t_next = t->t_next;
		CL_EXIT(t);	/* tell the scheduler that we're exiting */
		cv_broadcast(&t->t_joincv);	/* tell anyone in thread_join */
		mutex_exit(&pidlock);

		/*
		 * Let the lgroup load averages know that this thread isn't
		 * going to show up (i.e. un-do what was done on behalf of
		 * this thread by the earlier lgrp_move_thread()).
		 */
		kpreempt_disable();
		lgrp_move_thread(t, NULL, 1);
		kpreempt_enable();

		/*
		 * The thread was created TS_STOPPED.
		 * We change it to TS_FREE to avoid an
		 * ASSERT() panic in thread_free().
		 */
		t->t_state = TS_FREE;
		thread_rele(t);
		thread_free(t);
	}
}

extern struct as kas;

/*
 * fork a kernel process.
 */
int
newproc(void (*pc)(), caddr_t arg, id_t cid, int pri, struct contract **ct,
    pid_t pid)
{
	proc_t *p;
	struct user *up;
	kthread_t *t;
	cont_process_t *ctp = NULL;
	rctl_entity_p_t e;

	ASSERT(cid != sysdccid);
	ASSERT(cid != syscid || ct == NULL);
	if (CLASS_KERNEL(cid)) {
		rctl_alloc_gp_t *init_gp;
		rctl_set_t *init_set;

		ASSERT(pid != 1);

		if (getproc(&p, pid, GETPROC_KERNEL) < 0)
			return (EAGAIN);

		/*
		 * Release the hold on the p_exec and p_execdir, these
		 * were acquired in getproc()
		 */
		if (p->p_execdir != NULL)
			VN_RELE(p->p_execdir);
		if (p->p_exec != NULL)
			VN_RELE(p->p_exec);
		p->p_flag |= SNOWAIT;
		p->p_exec = NULL;
		p->p_execdir = NULL;

		init_set = rctl_set_create();
		init_gp = rctl_set_init_prealloc(RCENTITY_PROCESS);

		/*
		 * kernel processes do not inherit /proc tracing flags.
		 */
		sigemptyset(&p->p_sigmask);
		premptyset(&p->p_fltmask);
		up = PTOU(p);
		up->u_systrap = 0;
		premptyset(&(up->u_entrymask));
		premptyset(&(up->u_exitmask));
		mutex_enter(&p->p_lock);
		e.rcep_p.proc = p;
		e.rcep_t = RCENTITY_PROCESS;
		p->p_rctls = rctl_set_init(RCENTITY_PROCESS, p, &e, init_set,
		    init_gp);
		mutex_exit(&p->p_lock);

		rctl_prealloc_destroy(init_gp);

		t = lwp_kernel_create(p, pc, arg, TS_STOPPED, pri);
	} else {
		rctl_alloc_gp_t *init_gp, *default_gp;
		rctl_set_t *init_set;
		task_t *tk, *tk_old;
		klwp_t *lwp;

		if (getproc(&p, pid, GETPROC_USER) < 0)
			return (EAGAIN);
		/*
		 * init creates a new task, distinct from the task
		 * containing kernel "processes".
		 */
		tk = task_create(0, p->p_zone);
		mutex_enter(&tk->tk_zone->zone_nlwps_lock);
		tk->tk_proj->kpj_ntasks++;
		tk->tk_nprocs++;
		mutex_exit(&tk->tk_zone->zone_nlwps_lock);

		default_gp = rctl_rlimit_set_prealloc(RLIM_NLIMITS);
		init_gp = rctl_set_init_prealloc(RCENTITY_PROCESS);
		init_set = rctl_set_create();

		mutex_enter(&pidlock);
		mutex_enter(&p->p_lock);
		tk_old = p->p_task;	/* switch to new task */

		task_detach(p);
		task_begin(tk, p);
		mutex_exit(&pidlock);

		mutex_enter(&tk_old->tk_zone->zone_nlwps_lock);
		tk_old->tk_nprocs--;
		mutex_exit(&tk_old->tk_zone->zone_nlwps_lock);

		e.rcep_p.proc = p;
		e.rcep_t = RCENTITY_PROCESS;
		p->p_rctls = rctl_set_init(RCENTITY_PROCESS, p, &e, init_set,
		    init_gp);
		rctlproc_default_init(p, default_gp);
		mutex_exit(&p->p_lock);

		task_rele(tk_old);
		rctl_prealloc_destroy(default_gp);
		rctl_prealloc_destroy(init_gp);

		if ((lwp = lwp_create(pc, arg, 0, p, TS_STOPPED, pri,
		    &curthread->t_hold, cid, 1)) == NULL) {
			task_t *tk;
			fork_fail(p);
			mutex_enter(&pidlock);
			mutex_enter(&p->p_lock);
			tk = p->p_task;
			task_detach(p);
			ASSERT(p->p_pool->pool_ref > 0);
			atomic_add_32(&p->p_pool->pool_ref, -1);
			mutex_exit(&p->p_lock);
			pid_exit(p, tk);
			mutex_exit(&pidlock);
			task_rele(tk);

			return (EAGAIN);
		}
		t = lwptot(lwp);

		ctp = contract_process_fork(sys_process_tmpl, p, curproc,
		    B_FALSE);
		ASSERT(ctp != NULL);
		if (ct != NULL)
			*ct = &ctp->conp_contract;
	}

	ASSERT3U(t->t_tid, ==, 1);
	p->p_lwpid = 1;
	mutex_enter(&pidlock);
	pgjoin(p, p->p_parent->p_pgidp);
	p->p_stat = SRUN;
	mutex_enter(&p->p_lock);
	t->t_proc_flag &= ~TP_HOLDLWP;
	lwp_create_done(t);
	mutex_exit(&p->p_lock);
	mutex_exit(&pidlock);
	return (0);
}

/*
 * create a child proc struct.
 */
static int
getproc(proc_t **cpp, pid_t pid, uint_t flags)
{
	proc_t		*pp, *cp;
	pid_t		newpid;
	struct user	*uarea;
	extern uint_t	nproc;
	struct cred	*cr;
	uid_t		ruid;
	zoneid_t	zoneid;
	task_t		*task;
	kproject_t	*proj;
	zone_t		*zone;
	int		rctlfail = 0;

	if (zone_status_get(curproc->p_zone) >= ZONE_IS_SHUTTING_DOWN)
		return (-1);	/* no point in starting new processes */

	pp = (flags & GETPROC_KERNEL) ? &p0 : curproc;
	task = pp->p_task;
	proj = task->tk_proj;
	zone = pp->p_zone;

	mutex_enter(&pp->p_lock);
	mutex_enter(&zone->zone_nlwps_lock);
	if (proj != proj0p) {
		if (task->tk_nprocs >= task->tk_nprocs_ctl)
			if (rctl_test(rc_task_nprocs, task->tk_rctls,
			    pp, 1, 0) & RCT_DENY)
				rctlfail = 1;

		if (proj->kpj_nprocs >= proj->kpj_nprocs_ctl)
			if (rctl_test(rc_project_nprocs, proj->kpj_rctls,
			    pp, 1, 0) & RCT_DENY)
				rctlfail = 1;

		if (zone->zone_nprocs >= zone->zone_nprocs_ctl)
			if (rctl_test(rc_zone_nprocs, zone->zone_rctls,
			    pp, 1, 0) & RCT_DENY)
				rctlfail = 1;

		if (rctlfail) {
			mutex_exit(&zone->zone_nlwps_lock);
			mutex_exit(&pp->p_lock);
			atomic_inc_32(&zone->zone_ffcap);
			goto punish;
		}
	}
	task->tk_nprocs++;
	proj->kpj_nprocs++;
	zone->zone_nprocs++;
	mutex_exit(&zone->zone_nlwps_lock);
	mutex_exit(&pp->p_lock);

	cp = kmem_cache_alloc(process_cache, KM_SLEEP);
	bzero(cp, sizeof (proc_t));

	/*
	 * Make proc entry for child process
	 */
	mutex_init(&cp->p_splock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&cp->p_crlock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&cp->p_pflock, NULL, MUTEX_DEFAULT, NULL);
#if defined(__x86)
	mutex_init(&cp->p_ldtlock, NULL, MUTEX_DEFAULT, NULL);
#endif
	mutex_init(&cp->p_maplock, NULL, MUTEX_DEFAULT, NULL);
	cp->p_stat = SIDL;
	cp->p_mstart = gethrtime();
	cp->p_as = &kas;
	/*
	 * p_zone must be set before we call pid_allocate since the process
	 * will be visible after that and code such as prfind_zone will
	 * look at the p_zone field.
	 */
	cp->p_zone = pp->p_zone;
	cp->p_t1_lgrpid = LGRP_NONE;
	cp->p_tr_lgrpid = LGRP_NONE;

	if ((newpid = pid_allocate(cp, pid, PID_ALLOC_PROC)) == -1) {
		if (nproc == v.v_proc) {
			CPU_STATS_ADDQ(CPU, sys, procovf, 1);
			cmn_err(CE_WARN, "out of processes");
		}
		goto bad;
	}

	mutex_enter(&pp->p_lock);
	cp->p_exec = pp->p_exec;
	cp->p_execdir = pp->p_execdir;
	mutex_exit(&pp->p_lock);

	if (cp->p_exec) {
		VN_HOLD(cp->p_exec);
		/*
		 * Each VOP_OPEN() must be paired with a corresponding
		 * VOP_CLOSE(). In this case, the executable will be
		 * closed for the child in either proc_exit() or gexec().
		 */
		if (VOP_OPEN(&cp->p_exec, FREAD, CRED(), NULL) != 0) {
			VN_RELE(cp->p_exec);
			cp->p_exec = NULLVP;
			cp->p_execdir = NULLVP;
			goto bad;
		}
	}
	if (cp->p_execdir)
		VN_HOLD(cp->p_execdir);

	/*
	 * If not privileged make sure that this user hasn't exceeded
	 * v.v_maxup processes, and that users collectively haven't
	 * exceeded v.v_maxupttl processes.
	 */
	mutex_enter(&pidlock);
	ASSERT(nproc < v.v_proc);	/* otherwise how'd we get our pid? */
	cr = CRED();
	ruid = crgetruid(cr);
	zoneid = crgetzoneid(cr);
	if (nproc >= v.v_maxup && 	/* short-circuit; usually false */
	    (nproc >= v.v_maxupttl ||
	    upcount_get(ruid, zoneid) >= v.v_maxup) &&
	    secpolicy_newproc(cr) != 0) {
		mutex_exit(&pidlock);
		zcmn_err(zoneid, CE_NOTE,
		    "out of per-user processes for uid %d", ruid);
		goto bad;
	}

	/*
	 * Everything is cool, put the new proc on the active process list.
	 * It is already on the pid list and in /proc.
	 * Increment the per uid process count (upcount).
	 */
	nproc++;
	upcount_inc(ruid, zoneid);

	cp->p_next = practive;
	practive->p_prev = cp;
	practive = cp;

	cp->p_ignore = pp->p_ignore;
	cp->p_siginfo = pp->p_siginfo;
	cp->p_flag = pp->p_flag & (SJCTL|SNOWAIT|SNOCD);
	cp->p_sessp = pp->p_sessp;
	sess_hold(pp);
	cp->p_brand = pp->p_brand;
	if (PROC_IS_BRANDED(pp))
		BROP(pp)->b_copy_procdata(cp, pp);
	cp->p_bssbase = pp->p_bssbase;
	cp->p_brkbase = pp->p_brkbase;
	cp->p_brksize = pp->p_brksize;
	cp->p_brkpageszc = pp->p_brkpageszc;
	cp->p_stksize = pp->p_stksize;
	cp->p_stkpageszc = pp->p_stkpageszc;
	cp->p_stkprot = pp->p_stkprot;
	cp->p_datprot = pp->p_datprot;
	cp->p_usrstack = pp->p_usrstack;
	cp->p_model = pp->p_model;
	cp->p_ppid = pp->p_pid;
	cp->p_ancpid = pp->p_pid;
	cp->p_portcnt = pp->p_portcnt;

	/*
	 * Initialize watchpoint structures
	 */
	avl_create(&cp->p_warea, wa_compare, sizeof (struct watched_area),
	    offsetof(struct watched_area, wa_link));

	/*
	 * Initialize immediate resource control values.
	 */
	cp->p_stk_ctl = pp->p_stk_ctl;
	cp->p_fsz_ctl = pp->p_fsz_ctl;
	cp->p_vmem_ctl = pp->p_vmem_ctl;
	cp->p_fno_ctl = pp->p_fno_ctl;

	/*
	 * Link up to parent-child-sibling chain.  No need to lock
	 * in general since only a call to freeproc() (done by the
	 * same parent as newproc()) diddles with the child chain.
	 */
	cp->p_sibling = pp->p_child;
	if (pp->p_child)
		pp->p_child->p_psibling = cp;

	cp->p_parent = pp;
	pp->p_child = cp;

	cp->p_child_ns = NULL;
	cp->p_sibling_ns = NULL;

	cp->p_nextorph = pp->p_orphan;
	cp->p_nextofkin = pp;
	pp->p_orphan = cp;

	/*
	 * Inherit profiling state; do not inherit REALPROF profiling state.
	 */
	cp->p_prof = pp->p_prof;
	cp->p_rprof_cyclic = CYCLIC_NONE;

	/*
	 * Inherit pool pointer from the parent.  Kernel processes are
	 * always bound to the default pool.
	 */
	mutex_enter(&pp->p_lock);
	if (flags & GETPROC_KERNEL) {
		cp->p_pool = pool_default;
		cp->p_flag |= SSYS;
	} else {
		cp->p_pool = pp->p_pool;
	}
	atomic_inc_32(&cp->p_pool->pool_ref);
	mutex_exit(&pp->p_lock);

	/*
	 * Add the child process to the current task.  Kernel processes
	 * are always attached to task0.
	 */
	mutex_enter(&cp->p_lock);
	if (flags & GETPROC_KERNEL)
		task_attach(task0p, cp);
	else
		task_attach(pp->p_task, cp);
	mutex_exit(&cp->p_lock);
	mutex_exit(&pidlock);

	avl_create(&cp->p_ct_held, contract_compar, sizeof (contract_t),
	    offsetof(contract_t, ct_ctlist));

	/*
	 * Duplicate any audit information kept in the process table
	 */
	if (audit_active)	/* copy audit data to cp */
		audit_newproc(cp);

	crhold(cp->p_cred = cr);

	/*
	 * Bump up the counts on the file structures pointed at by the
	 * parent's file table since the child will point at them too.
	 */
	fcnt_add(P_FINFO(pp), 1);

	if (PTOU(pp)->u_cdir) {
		VN_HOLD(PTOU(pp)->u_cdir);
	} else {
		ASSERT(pp == &p0);
		/*
		 * We must be at or before vfs_mountroot(); it will take care of
		 * assigning our current directory.
		 */
	}
	if (PTOU(pp)->u_rdir)
		VN_HOLD(PTOU(pp)->u_rdir);
	if (PTOU(pp)->u_cwd)
		refstr_hold(PTOU(pp)->u_cwd);

	/*
	 * copy the parent's uarea.
	 */
	uarea = PTOU(cp);
	bcopy(PTOU(pp), uarea, sizeof (*uarea));
	flist_fork(P_FINFO(pp), P_FINFO(cp));

	gethrestime(&uarea->u_start);
	uarea->u_ticks = ddi_get_lbolt();
	uarea->u_mem = rm_asrss(pp->p_as);
	uarea->u_acflag = AFORK;

	/*
	 * If inherit-on-fork, copy /proc tracing flags to child.
	 */
	if ((pp->p_proc_flag & P_PR_FORK) != 0) {
		cp->p_proc_flag |= pp->p_proc_flag & (P_PR_TRACE|P_PR_FORK);
		cp->p_sigmask = pp->p_sigmask;
		cp->p_fltmask = pp->p_fltmask;
	} else {
		sigemptyset(&cp->p_sigmask);
		premptyset(&cp->p_fltmask);
		uarea->u_systrap = 0;
		premptyset(&uarea->u_entrymask);
		premptyset(&uarea->u_exitmask);
	}
	/*
	 * If microstate accounting is being inherited, mark child
	 */
	if ((pp->p_flag & SMSFORK) != 0)
		cp->p_flag |= pp->p_flag & (SMSFORK|SMSACCT);

	/*
	 * Inherit fixalignment flag from the parent
	 */
	cp->p_fixalignment = pp->p_fixalignment;

	*cpp = cp;
	return (0);

bad:
	ASSERT(MUTEX_NOT_HELD(&pidlock));

	mutex_destroy(&cp->p_crlock);
	mutex_destroy(&cp->p_pflock);
#if defined(__x86)
	mutex_destroy(&cp->p_ldtlock);
#endif
	if (newpid != -1) {
		proc_entry_free(cp->p_pidp);
		(void) pid_rele(cp->p_pidp);
	}
	kmem_cache_free(process_cache, cp);

	mutex_enter(&zone->zone_nlwps_lock);
	task->tk_nprocs--;
	proj->kpj_nprocs--;
	zone->zone_nprocs--;
	mutex_exit(&zone->zone_nlwps_lock);
	atomic_inc_32(&zone->zone_ffnoproc);

punish:
	/*
	 * We most likely got into this situation because some process is
	 * forking out of control.  As punishment, put it to sleep for a
	 * bit so it can't eat the machine alive.  Sleep interval is chosen
	 * to allow no more than one fork failure per cpu per clock tick
	 * on average (yes, I just made this up).  This has two desirable
	 * properties: (1) it sets a constant limit on the fork failure
	 * rate, and (2) the busier the system is, the harsher the penalty
	 * for abusing it becomes.
	 */
	INCR_COUNT(&fork_fail_pending, &pidlock);
	delay(fork_fail_pending / ncpus + 1);
	DECR_COUNT(&fork_fail_pending, &pidlock);

	return (-1); /* out of memory or proc slots */
}

/*
 * Release virtual memory.
 * In the case of vfork(), the child was given exclusive access to its
 * parent's address space.  The parent is waiting in vfwait() for the
 * child to release its exclusive claim via relvm().
 */
void
relvm()
{
	proc_t *p = curproc;

	ASSERT((unsigned)p->p_lwpcnt <= 1);

	prrelvm();	/* inform /proc */

	if (p->p_flag & SVFORK) {
		proc_t *pp = p->p_parent;
		/*
		 * The child process is either exec'ing or exit'ing.
		 * The child is now separated from the parent's address
		 * space.  The parent process is made dispatchable.
		 *
		 * This is a delicate locking maneuver, involving
		 * both the parent's p_lock and the child's p_lock.
		 * As soon as the SVFORK flag is turned off, the
		 * parent is free to run, but it must not run until
		 * we wake it up using its p_cv because it might
		 * exit and we would be referencing invalid memory.
		 * Therefore, we hold the parent with its p_lock
		 * while protecting our p_flags with our own p_lock.
		 */
try_again:
		mutex_enter(&p->p_lock);	/* grab child's lock first */
		prbarrier(p);		/* make sure /proc is blocked out */
		mutex_enter(&pp->p_lock);

		/*
		 * Check if parent is locked by /proc.
		 */
		if (pp->p_proc_flag & P_PR_LOCK) {
			/*
			 * Delay until /proc is done with the parent.
			 * We must drop our (the child's) p->p_lock, wait
			 * via prbarrier() on the parent, then start over.
			 */
			mutex_exit(&p->p_lock);
			prbarrier(pp);
			mutex_exit(&pp->p_lock);
			goto try_again;
		}
		p->p_flag &= ~SVFORK;
		kpreempt_disable();
		p->p_as = &kas;

		/*
		 * notify hat of change in thread's address space
		 */
		hat_thread_exit(curthread);
		kpreempt_enable();

		/*
		 * child sizes are copied back to parent because
		 * child may have grown.
		 */
		pp->p_brkbase = p->p_brkbase;
		pp->p_brksize = p->p_brksize;
		pp->p_stksize = p->p_stksize;

		/*
		 * Copy back the shm accounting information
		 * to the parent process.
		 */
		pp->p_segacct = p->p_segacct;
		p->p_segacct = NULL;

		/*
		 * The parent is no longer waiting for the vfork()d child.
		 * Restore the parent's watched pages, if any.  This is
		 * safe because we know the parent is not locked by /proc
		 */
		pp->p_flag &= ~SVFWAIT;
		if (avl_numnodes(&pp->p_wpage) != 0) {
			pp->p_as->a_wpage = pp->p_wpage;
			avl_create(&pp->p_wpage, wp_compare,
			    sizeof (struct watched_page),
			    offsetof(struct watched_page, wp_link));
		}
		cv_signal(&pp->p_cv);
		mutex_exit(&pp->p_lock);
		mutex_exit(&p->p_lock);
	} else {
		if (p->p_as != &kas) {
			struct as *as;

			if (p->p_segacct)
				shmexit(p);

			/*
			 * We grab p_lock for the benefit of /proc
			 */
			kpreempt_disable();
			mutex_enter(&p->p_lock);
			prbarrier(p);	/* make sure /proc is blocked out */
			as = p->p_as;
			p->p_as = &kas;
			mutex_exit(&p->p_lock);

			/*
			 * notify hat of change in thread's address space
			 */
			hat_thread_exit(curthread);
			kpreempt_enable();

			as_free(as);
			p->p_tr_lgrpid = LGRP_NONE;
		}
	}
}

/*
 * Wait for child to exec or exit.
 * Called by parent of vfork'ed process.
 * See important comments in relvm(), above.
 */
void
vfwait(pid_t pid)
{
	int signalled = 0;
	proc_t *pp = ttoproc(curthread);
	proc_t *cp;

	/*
	 * Wait for child to exec or exit.
	 */
	for (;;) {
		mutex_enter(&pidlock);
		cp = prfind(pid);
		if (cp == NULL || cp->p_parent != pp) {
			/*
			 * Child has exit()ed.
			 */
			mutex_exit(&pidlock);
			break;
		}
		/*
		 * Grab the child's p_lock before releasing pidlock.
		 * Otherwise, the child could exit and we would be
		 * referencing invalid memory.
		 */
		mutex_enter(&cp->p_lock);
		mutex_exit(&pidlock);
		if (!(cp->p_flag & SVFORK)) {
			/*
			 * Child has exec()ed or is exit()ing.
			 */
			mutex_exit(&cp->p_lock);
			break;
		}
		mutex_enter(&pp->p_lock);
		mutex_exit(&cp->p_lock);
		/*
		 * We might be waked up spuriously from the cv_wait().
		 * We have to do the whole operation over again to be
		 * sure the child's SVFORK flag really is turned off.
		 * We cannot make reference to the child because it can
		 * exit before we return and we would be referencing
		 * invalid memory.
		 *
		 * Because this is potentially a very long-term wait,
		 * we call cv_wait_sig() (for its jobcontrol and /proc
		 * side-effects) unless there is a current signal, in
		 * which case we use cv_wait() because we cannot return
		 * from this function until the child has released the
		 * address space.  Calling cv_wait_sig() with a current
		 * signal would lead to an indefinite loop here because
		 * cv_wait_sig() returns immediately in this case.
		 */
		if (signalled)
			cv_wait(&pp->p_cv, &pp->p_lock);
		else
			signalled = !cv_wait_sig(&pp->p_cv, &pp->p_lock);
		mutex_exit(&pp->p_lock);
	}

	/* restore watchpoints to parent */
	if (pr_watch_active(pp)) {
		struct as *as = pp->p_as;
		AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
		as_setwatch(as);
		AS_LOCK_EXIT(as, &as->a_lock);
	}

	mutex_enter(&pp->p_lock);
	prbarrier(pp);	/* barrier against /proc locking */
	continuelwps(pp);
	mutex_exit(&pp->p_lock);
}
