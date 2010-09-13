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

/*
 * Routines to support shuttle synchronization objects
 */

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/class.h>
#include <sys/debug.h>
#include <sys/sobject.h>
#include <sys/cpuvar.h>
#include <sys/schedctl.h>
#include <sys/sdt.h>

static	disp_lock_t	shuttle_lock;	/* lock on shuttle objects */

/*
 * Place the thread in question on the run q.
 */
static void
shuttle_unsleep(kthread_t *t)
{
	ASSERT(THREAD_LOCK_HELD(t));

	/* Waiting on a shuttle */
	ASSERT(t->t_wchan0 == (caddr_t)1 && t->t_wchan == NULL);
	t->t_flag &= ~T_WAKEABLE;
	t->t_wchan0 = NULL;
	t->t_sobj_ops = NULL;
	THREAD_TRANSITION(t);
	CL_SETRUN(t);
}

static kthread_t *
shuttle_owner()
{
	return (NULL);
}

/*ARGSUSED*/
static void
shuttle_change_pri(kthread_t *t, pri_t p, pri_t *t_prip)
{
	ASSERT(THREAD_LOCK_HELD(t));
	*t_prip = p;
}

static sobj_ops_t shuttle_sobj_ops = {
	SOBJ_SHUTTLE, shuttle_owner, shuttle_unsleep, shuttle_change_pri
};

/*
 * Mark the current thread as sleeping on a shuttle object, and
 * resume the specified thread. The 't' thread must be marked as ONPROC.
 *
 * No locks other than 'l' should be held at this point.
 */
void
shuttle_resume(kthread_t *t, kmutex_t *l)
{
	klwp_t	*lwp = ttolwp(curthread);
	cpu_t	*cp;
	disp_lock_t *oldtlp;

	thread_lock(curthread);
	disp_lock_enter_high(&shuttle_lock);
	if (lwp != NULL) {
		lwp->lwp_asleep = 1;			/* /proc */
		lwp->lwp_sysabort = 0;			/* /proc */
		lwp->lwp_ru.nvcsw++;
	}
	curthread->t_flag |= T_WAKEABLE;
	curthread->t_sobj_ops = &shuttle_sobj_ops;
	/*
	 * setting cpu_dispthread before changing thread state
	 * so that kernel preemption will be deferred to after swtch_to()
	 */
	cp = CPU;
	cp->cpu_dispthread = t;
	cp->cpu_dispatch_pri = DISP_PRIO(t);
	/*
	 * Set the wchan0 field so that /proc won't just do a setrun
	 * on this thread when trying to stop a process. Instead,
	 * /proc will mark the thread as VSTOPPED similar to threads
	 * that are blocked on user level condition variables.
	 */
	curthread->t_wchan0 = (caddr_t)1;
	CL_INACTIVE(curthread);
	DTRACE_SCHED1(wakeup, kthread_t *, t);
	DTRACE_SCHED(sleep);
	THREAD_SLEEP(curthread, &shuttle_lock);
	disp_lock_exit_high(&shuttle_lock);

	/*
	 * Update ustate records (there is no waitrq obviously)
	 */
	(void) new_mstate(curthread, LMS_SLEEP);

	thread_lock_high(t);
	oldtlp = t->t_lockp;

	t->t_flag &= ~T_WAKEABLE;
	t->t_wchan0 = NULL;
	t->t_sobj_ops = NULL;

	/*
	 * Make sure we end up on the right CPU if we are dealing with bound
	 * CPU's or processor partitions.
	 */
	if (t->t_bound_cpu != NULL || t->t_cpupart != cp->cpu_part) {
		aston(t);
		cp->cpu_runrun = 1;
	}

	/*
	 * We re-assign t_disp_queue and t_lockp of 't' here because
	 * 't' could have been preempted.
	 */
	if (t->t_disp_queue != cp->cpu_disp) {
		t->t_disp_queue = cp->cpu_disp;
		thread_onproc(t, cp);
	}

	/*
	 * We can't call thread_unlock_high() here because t's thread lock
	 * could have changed by thread_onproc() call above to point to
	 * CPU->cpu_thread_lock.
	 */
	disp_lock_exit_high(oldtlp);

	mutex_exit(l);
	/*
	 * Make sure we didn't receive any important events while
	 * we weren't looking
	 */
	if (lwp && (ISSIG(curthread, JUSTLOOKING) ||
	    MUSTRETURN(curproc, curthread) || schedctl_cancel_pending()))
		setrun(curthread);

	swtch_to(t);
	/*
	 * Caller must check for ISSIG/lwp_sysabort conditions
	 * and clear lwp->lwp_asleep/lwp->lwp_sysabort
	 */
}

/*
 * Mark the current thread as sleeping on a shuttle object, and
 * switch to a new thread.
 * No locks other than 'l' should be held at this point.
 */
void
shuttle_swtch(kmutex_t *l)
{
	klwp_t	*lwp = ttolwp(curthread);

	thread_lock(curthread);
	disp_lock_enter_high(&shuttle_lock);
	lwp->lwp_asleep = 1;			/* /proc */
	lwp->lwp_sysabort = 0;			/* /proc */
	lwp->lwp_ru.nvcsw++;
	curthread->t_flag |= T_WAKEABLE;
	curthread->t_sobj_ops = &shuttle_sobj_ops;
	curthread->t_wchan0 = (caddr_t)1;
	CL_INACTIVE(curthread);
	DTRACE_SCHED(sleep);
	THREAD_SLEEP(curthread, &shuttle_lock);
	(void) new_mstate(curthread, LMS_SLEEP);
	disp_lock_exit_high(&shuttle_lock);
	mutex_exit(l);
	if (ISSIG(curthread, JUSTLOOKING) ||
	    MUSTRETURN(curproc, curthread) || schedctl_cancel_pending())
		setrun(curthread);
	swtch();
	/*
	 * Caller must check for ISSIG/lwp_sysabort conditions
	 * and clear lwp->lwp_asleep/lwp->lwp_sysabort
	 */
}

/*
 * Mark the specified thread as once again sleeping on a shuttle object.  This
 * routine is called to put a server thread -- one that was dequeued but for
 * which shuttle_resume() was _not_ called -- back to sleep on a shuttle
 * object.  Because we don't hit the sched:::wakeup DTrace probe until
 * shuttle_resume(), we do _not_ have a sched:::sleep probe here.
 */
void
shuttle_sleep(kthread_t *t)
{
	klwp_t	*lwp = ttolwp(t);
	proc_t	*p = ttoproc(t);

	thread_lock(t);
	disp_lock_enter_high(&shuttle_lock);
	if (lwp != NULL) {
		lwp->lwp_asleep = 1;			/* /proc */
		lwp->lwp_sysabort = 0;			/* /proc */
		lwp->lwp_ru.nvcsw++;
	}
	t->t_flag |= T_WAKEABLE;
	t->t_sobj_ops = &shuttle_sobj_ops;
	t->t_wchan0 = (caddr_t)1;
	CL_INACTIVE(t);
	ASSERT(t->t_mstate == LMS_SLEEP);
	THREAD_SLEEP(t, &shuttle_lock);
	disp_lock_exit_high(&shuttle_lock);
	if (lwp && (ISSIG(t, JUSTLOOKING) || MUSTRETURN(p, t)))
		setrun(t);
}
