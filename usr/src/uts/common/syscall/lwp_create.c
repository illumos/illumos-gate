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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/syscall.h>
#include <sys/proc.h>
#include <sys/processor.h>
#include <sys/fault.h>
#include <sys/ucontext.h>
#include <sys/signal.h>
#include <sys/unistd.h>
#include <sys/procfs.h>
#include <sys/prsystm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/klwp.h>
#include <sys/pool.h>

/*
 * System call to create an lwp.
 *
 * Notes on the LWP_DETACHED and LWP_DAEMON flags:
 *
 * A detached lwp (LWP_DETACHED) cannot be the specific target of
 * lwp_wait() (it is not joinable), but lwp_wait(0, ...) is required
 * to sleep until all non-daemon detached lwps have terminated before
 * returning EDEADLK because a detached lwp might create a non-detached lwp
 * that could then be returned by lwp_wait(0, ...).  See also lwp_detach().
 *
 * A daemon lwp (LWP_DAEMON) is a detached lwp that has the additional
 * property that it does not affect the termination condition of the
 * process:  The last non-daemon lwp to call lwp_exit() causes the process
 * to exit and lwp_wait(0, ...) does not sleep waiting for daemon lwps
 * to terminate.  See the block comment before lwp_wait().
 */
int
syslwp_create(ucontext_t *ucp, int flags, id_t *new_lwp)
{
	klwp_t *lwp;
	proc_t *p = ttoproc(curthread);
	kthread_t *t;
	ucontext_t uc;
#ifdef _SYSCALL32_IMPL
	ucontext32_t uc32;
#endif /* _SYSCALL32_IMPL */
	k_sigset_t sigmask;
	int	tid;
	model_t model = get_udatamodel();
	uintptr_t thrptr = 0;

	if (flags & ~(LWP_DAEMON|LWP_DETACHED|LWP_SUSPENDED))
		return (set_errno(EINVAL));

	/*
	 * lwp_create() is disallowed for the /proc agent lwp.
	 */
	if (curthread == p->p_agenttp)
		return (set_errno(ENOTSUP));

	if (model == DATAMODEL_NATIVE) {
		if (copyin(ucp, &uc, sizeof (ucontext_t)))
			return (set_errno(EFAULT));
		sigutok(&uc.uc_sigmask, &sigmask);
#if defined(__i386)
		/*
		 * libc stashed thrptr into unused kernel %sp.
		 * See setup_context() in libc.
		 */
		thrptr = (uint32_t)uc.uc_mcontext.gregs[ESP];
#endif
	}
#ifdef _SYSCALL32_IMPL
	else {
		if (copyin(ucp, &uc32, sizeof (ucontext32_t)))
			return (set_errno(EFAULT));
		sigutok(&uc32.uc_sigmask, &sigmask);
#if defined(__sparc)
		ucontext_32ton(&uc32, &uc, NULL, NULL);
#else	/* __amd64 */
		ucontext_32ton(&uc32, &uc);
		/*
		 * libc stashed thrptr into unused kernel %sp.
		 * See setup_context() in libc.
		 */
		thrptr = (uint32_t)uc32.uc_mcontext.gregs[ESP];
#endif
	}
#endif /* _SYSCALL32_IMPL */

	/*
	 * Tell machine specific code that we are creating a new lwp
	 */
	LWP_MMODEL_NEWLWP();

	(void) save_syscall_args();	/* save args for tracing first */

	mutex_enter(&curproc->p_lock);
	pool_barrier_enter();
	mutex_exit(&curproc->p_lock);
	lwp = lwp_create(lwp_rtt, NULL, 0, curproc, TS_STOPPED,
	    curthread->t_pri, &sigmask, curthread->t_cid, 0);
	mutex_enter(&curproc->p_lock);
	pool_barrier_exit();
	mutex_exit(&curproc->p_lock);
	if (lwp == NULL)
		return (set_errno(EAGAIN));

	lwp_load(lwp, uc.uc_mcontext.gregs, thrptr);

	t = lwptot(lwp);
	/*
	 * Copy the new lwp's lwpid into the caller's specified buffer.
	 */
	if (new_lwp && copyout(&t->t_tid, new_lwp, sizeof (id_t))) {
		/*
		 * caller's buffer is not writable, return
		 * EFAULT, and terminate new lwp.
		 */
		mutex_enter(&p->p_lock);
		t->t_proc_flag |= TP_EXITLWP;
		t->t_sig_check = 1;
		t->t_sysnum = 0;
		t->t_proc_flag &= ~TP_HOLDLWP;
		lwp_create_done(t);
		mutex_exit(&p->p_lock);
		return (set_errno(EFAULT));
	}

	/*
	 * clone callers context, if any.  must be invoked
	 * while -not- holding p_lock.
	 */
	if (curthread->t_ctx)
		lwp_createctx(curthread, t);

	/*
	 * copy current contract templates
	 */
	lwp_ctmpl_copy(lwp, ttolwp(curthread));

	mutex_enter(&p->p_lock);
	/*
	 * Copy the syscall arguments to the new lwp's arg area
	 * for the benefit of debuggers.
	 */
	t->t_sysnum = SYS_lwp_create;
	lwp->lwp_ap = lwp->lwp_arg;
	lwp->lwp_arg[0] = (long)ucp;
	lwp->lwp_arg[1] = (long)flags;
	lwp->lwp_arg[2] = (long)new_lwp;
	lwp->lwp_argsaved = 1;

	if (!(flags & (LWP_DETACHED|LWP_DAEMON)))
		t->t_proc_flag |= TP_TWAIT;
	if (flags & LWP_DAEMON) {
		t->t_proc_flag |= TP_DAEMON;
		p->p_lwpdaemon++;
	}

	tid = (int)t->t_tid;	/* for /proc debuggers */

	/*
	 * We now set the newly-created lwp running.
	 * If it is being created as LWP_SUSPENDED, we leave its
	 * TP_HOLDLWP flag set so it will stop in system call exit.
	 */
	if (!(flags & LWP_SUSPENDED))
		t->t_proc_flag &= ~TP_HOLDLWP;
	lwp_create_done(t);
	mutex_exit(&p->p_lock);

	return (tid);
}

/*
 * Exit the calling lwp
 */
void
syslwp_exit()
{
	proc_t *p = ttoproc(curthread);

	mutex_enter(&p->p_lock);
	lwp_exit();
	/* NOTREACHED */
}
