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

#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/sobject.h>
#include <sys/sleepq.h>
#include <sys/cpuvar.h>
#include <sys/condvar.h>
#include <sys/condvar_impl.h>
#include <sys/schedctl.h>
#include <sys/procfs.h>
#include <sys/sdt.h>
#include <sys/callo.h>

/*
 * CV_MAX_WAITERS is the maximum number of waiters we track; once
 * the number becomes higher than that, we look at the sleepq to
 * see whether there are *really* any waiters.
 */
#define	CV_MAX_WAITERS		1024		/* must be power of 2 */
#define	CV_WAITERS_MASK		(CV_MAX_WAITERS - 1)

/*
 * Threads don't "own" condition variables.
 */
/* ARGSUSED */
static kthread_t *
cv_owner(void *cvp)
{
	return (NULL);
}

/*
 * Unsleep a thread that's blocked on a condition variable.
 */
static void
cv_unsleep(kthread_t *t)
{
	condvar_impl_t *cvp = (condvar_impl_t *)t->t_wchan;
	sleepq_head_t *sqh = SQHASH(cvp);

	ASSERT(THREAD_LOCK_HELD(t));

	if (cvp == NULL)
		panic("cv_unsleep: thread %p not on sleepq %p",
		    (void *)t, (void *)sqh);
	DTRACE_SCHED1(wakeup, kthread_t *, t);
	sleepq_unsleep(t);
	if (cvp->cv_waiters != CV_MAX_WAITERS)
		cvp->cv_waiters--;
	disp_lock_exit_high(&sqh->sq_lock);
	CL_SETRUN(t);
}

/*
 * Change the priority of a thread that's blocked on a condition variable.
 */
static void
cv_change_pri(kthread_t *t, pri_t pri, pri_t *t_prip)
{
	condvar_impl_t *cvp = (condvar_impl_t *)t->t_wchan;
	sleepq_t *sqp = t->t_sleepq;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(&SQHASH(cvp)->sq_queue == sqp);

	if (cvp == NULL)
		panic("cv_change_pri: %p not on sleep queue", (void *)t);
	sleepq_dequeue(t);
	*t_prip = pri;
	sleepq_insert(sqp, t);
}

/*
 * The sobj_ops vector exports a set of functions needed when a thread
 * is asleep on a synchronization object of this type.
 */
static sobj_ops_t cv_sobj_ops = {
	SOBJ_CV, cv_owner, cv_unsleep, cv_change_pri
};

/* ARGSUSED */
void
cv_init(kcondvar_t *cvp, char *name, kcv_type_t type, void *arg)
{
	((condvar_impl_t *)cvp)->cv_waiters = 0;
}

/*
 * cv_destroy is not currently needed, but is part of the DDI.
 * This is in case cv_init ever needs to allocate something for a cv.
 */
/* ARGSUSED */
void
cv_destroy(kcondvar_t *cvp)
{
	ASSERT((((condvar_impl_t *)cvp)->cv_waiters & CV_WAITERS_MASK) == 0);
}

/*
 * The cv_block() function blocks a thread on a condition variable
 * by putting it in a hashed sleep queue associated with the
 * synchronization object.
 *
 * Threads are taken off the hashed sleep queues via calls to
 * cv_signal(), cv_broadcast(), or cv_unsleep().
 */
static void
cv_block(condvar_impl_t *cvp)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	sleepq_head_t *sqh;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t != CPU->cpu_idle_thread);
	ASSERT(CPU_ON_INTR(CPU) == 0);
	ASSERT(t->t_wchan0 == NULL && t->t_wchan == NULL);
	ASSERT(t->t_state == TS_ONPROC);

	t->t_schedflag &= ~TS_SIGNALLED;
	CL_SLEEP(t);			/* assign kernel priority */
	t->t_wchan = (caddr_t)cvp;
	t->t_sobj_ops = &cv_sobj_ops;
	DTRACE_SCHED(sleep);

	/*
	 * The check for t_intr is to avoid doing the
	 * account for an interrupt thread on the still-pinned
	 * lwp's statistics.
	 */
	if (lwp != NULL && t->t_intr == NULL) {
		lwp->lwp_ru.nvcsw++;
		(void) new_mstate(t, LMS_SLEEP);
	}

	sqh = SQHASH(cvp);
	disp_lock_enter_high(&sqh->sq_lock);
	if (cvp->cv_waiters < CV_MAX_WAITERS)
		cvp->cv_waiters++;
	ASSERT(cvp->cv_waiters <= CV_MAX_WAITERS);
	THREAD_SLEEP(t, &sqh->sq_lock);
	sleepq_insert(&sqh->sq_queue, t);
	/*
	 * THREAD_SLEEP() moves curthread->t_lockp to point to the
	 * lock sqh->sq_lock. This lock is later released by the caller
	 * when it calls thread_unlock() on curthread.
	 */
}

#define	cv_block_sig(t, cvp)	\
	{ (t)->t_flag |= T_WAKEABLE; cv_block(cvp); }

/*
 * Block on the indicated condition variable and release the
 * associated kmutex while blocked.
 */
void
cv_wait(kcondvar_t *cvp, kmutex_t *mp)
{
	if (panicstr)
		return;

	ASSERT(curthread->t_schedflag & TS_DONT_SWAP);
	thread_lock(curthread);			/* lock the thread */
	cv_block((condvar_impl_t *)cvp);
	thread_unlock_nopreempt(curthread);	/* unlock the waiters field */
	mutex_exit(mp);
	swtch();
	mutex_enter(mp);
}

static void
cv_wakeup(void *arg)
{
	kthread_t *t = arg;

	/*
	 * This mutex is acquired and released in order to make sure that
	 * the wakeup does not happen before the block itself happens.
	 */
	mutex_enter(t->t_wait_mp);
	mutex_exit(t->t_wait_mp);
	setrun(t);
	t->t_wait_mp = NULL;
}

/*
 * Same as cv_wait except the thread will unblock at 'tim'
 * (an absolute time) if it hasn't already unblocked.
 *
 * Returns the amount of time left from the original 'tim' value
 * when it was unblocked.
 */
clock_t
cv_timedwait(kcondvar_t *cvp, kmutex_t *mp, clock_t tim)
{
	kthread_t *t = curthread;
	callout_id_t id;
	clock_t timeleft;
	int signalled;

	if (panicstr)
		return (-1);

	timeleft = tim - lbolt;
	if (timeleft <= 0)
		return (-1);
	t->t_wait_mp = mp;
	id = realtime_timeout_default((void (*)(void *))cv_wakeup, t, timeleft);
	thread_lock(t);		/* lock the thread */
	cv_block((condvar_impl_t *)cvp);
	thread_unlock_nopreempt(t);
	mutex_exit(mp);
	swtch();
	signalled = (t->t_schedflag & TS_SIGNALLED);
	/*
	 * Get the time left. untimeout() returns -1 if the timeout has
	 * occured or the time remaining.  If the time remaining is zero,
	 * the timeout has occured between when we were awoken and
	 * we called untimeout.  We will treat this as if the timeout
	 * has occured and set timeleft to -1.
	 */
	timeleft = (t->t_wait_mp == NULL) ? -1 : untimeout_default(id, 0);
	mutex_enter(mp);
	if (timeleft <= 0) {
		timeleft = -1;
		if (signalled)	/* avoid consuming the cv_signal() */
			cv_signal(cvp);
	}
	return (timeleft);
}

int
cv_wait_sig(kcondvar_t *cvp, kmutex_t *mp)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	int cancel_pending;
	int rval = 1;
	int signalled = 0;

	if (panicstr)
		return (rval);

	/*
	 * The check for t_intr is to catch an interrupt thread
	 * that has not yet unpinned the thread underneath.
	 */
	if (lwp == NULL || t->t_intr) {
		cv_wait(cvp, mp);
		return (rval);
	}

	ASSERT(curthread->t_schedflag & TS_DONT_SWAP);
	cancel_pending = schedctl_cancel_pending();
	lwp->lwp_asleep = 1;
	lwp->lwp_sysabort = 0;
	thread_lock(t);
	cv_block_sig(t, (condvar_impl_t *)cvp);
	thread_unlock_nopreempt(t);
	mutex_exit(mp);
	if (ISSIG(t, JUSTLOOKING) || MUSTRETURN(p, t) || cancel_pending)
		setrun(t);
	/* ASSERT(no locks are held) */
	swtch();
	signalled = (t->t_schedflag & TS_SIGNALLED);
	t->t_flag &= ~T_WAKEABLE;
	mutex_enter(mp);
	if (ISSIG_PENDING(t, lwp, p)) {
		mutex_exit(mp);
		if (issig(FORREAL))
			rval = 0;
		mutex_enter(mp);
	}
	if (lwp->lwp_sysabort || MUSTRETURN(p, t))
		rval = 0;
	if (rval != 0 && cancel_pending) {
		schedctl_cancel_eintr();
		rval = 0;
	}
	lwp->lwp_asleep = 0;
	lwp->lwp_sysabort = 0;
	if (rval == 0 && signalled)	/* avoid consuming the cv_signal() */
		cv_signal(cvp);
	return (rval);
}

static clock_t
cv_timedwait_sig_internal(kcondvar_t *cvp, kmutex_t *mp, clock_t tim, int flag)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	int cancel_pending = 0;
	callout_id_t id;
	clock_t rval = 1;
	clock_t timeleft;
	int signalled = 0;

	/*
	 * If the flag is 0, then realtime_timeout() below creates a
	 * regular realtime timeout. If the flag is CALLOUT_FLAG_HRESTIME,
	 * then, it creates a special realtime timeout which is affected by
	 * changes to hrestime. See callo.h for details.
	 */
	ASSERT((flag == 0) || (flag == CALLOUT_FLAG_HRESTIME));
	if (panicstr)
		return (rval);

	/*
	 * If there is no lwp, then we don't need to wait for a signal.
	 * The check for t_intr is to catch an interrupt thread
	 * that has not yet unpinned the thread underneath.
	 */
	if (lwp == NULL || t->t_intr)
		return (cv_timedwait(cvp, mp, tim));

	/*
	 * If tim is less than or equal to lbolt, then the timeout
	 * has already occured.  So just check to see if there is a signal
	 * pending.  If so return 0 indicating that there is a signal pending.
	 * Else return -1 indicating that the timeout occured. No need to
	 * wait on anything.
	 */
	timeleft = tim - lbolt;
	if (timeleft <= 0) {
		lwp->lwp_asleep = 1;
		lwp->lwp_sysabort = 0;
		rval = -1;
		goto out;
	}

	/*
	 * Set the timeout and wait.
	 */
	cancel_pending = schedctl_cancel_pending();
	t->t_wait_mp = mp;
	id = timeout_generic(CALLOUT_REALTIME, (void (*)(void *))cv_wakeup, t,
	    TICK_TO_NSEC(timeleft), nsec_per_tick, flag);
	lwp->lwp_asleep = 1;
	lwp->lwp_sysabort = 0;
	thread_lock(t);
	cv_block_sig(t, (condvar_impl_t *)cvp);
	thread_unlock_nopreempt(t);
	mutex_exit(mp);
	if (ISSIG(t, JUSTLOOKING) || MUSTRETURN(p, t) || cancel_pending)
		setrun(t);
	/* ASSERT(no locks are held) */
	swtch();
	signalled = (t->t_schedflag & TS_SIGNALLED);
	t->t_flag &= ~T_WAKEABLE;

	/*
	 * Untimeout the thread.  untimeout() returns -1 if the timeout has
	 * occured or the time remaining.  If the time remaining is zero,
	 * the timeout has occured between when we were awoken and
	 * we called untimeout.  We will treat this as if the timeout
	 * has occured and set rval to -1.
	 */
	rval = (t->t_wait_mp == NULL) ? -1 : untimeout_default(id, 0);
	mutex_enter(mp);
	if (rval <= 0)
		rval = -1;

	/*
	 * Check to see if a signal is pending.  If so, regardless of whether
	 * or not we were awoken due to the signal, the signal is now pending
	 * and a return of 0 has the highest priority.
	 */
out:
	if (ISSIG_PENDING(t, lwp, p)) {
		mutex_exit(mp);
		if (issig(FORREAL))
			rval = 0;
		mutex_enter(mp);
	}
	if (lwp->lwp_sysabort || MUSTRETURN(p, t))
		rval = 0;
	if (rval != 0 && cancel_pending) {
		schedctl_cancel_eintr();
		rval = 0;
	}
	lwp->lwp_asleep = 0;
	lwp->lwp_sysabort = 0;
	if (rval <= 0 && signalled)	/* avoid consuming the cv_signal() */
		cv_signal(cvp);
	return (rval);
}

/*
 * Returns:
 * 	Function result in order of precedence:
 *		 0 if a signal was received
 *		-1 if timeout occured
 *		>0 if awakened via cv_signal() or cv_broadcast().
 *		   (returns time remaining)
 *
 * cv_timedwait_sig() is now part of the DDI.
 *
 * This function is now just a wrapper for cv_timedwait_sig_internal().
 */
clock_t
cv_timedwait_sig(kcondvar_t *cvp, kmutex_t *mp, clock_t tim)
{
	return (cv_timedwait_sig_internal(cvp, mp, tim, 0));
}

/*
 * Like cv_wait_sig_swap but allows the caller to indicate (with a
 * non-NULL sigret) that they will take care of signalling the cv
 * after wakeup, if necessary.  This is a vile hack that should only
 * be used when no other option is available; almost all callers
 * should just use cv_wait_sig_swap (which takes care of the cv_signal
 * stuff automatically) instead.
 */
int
cv_wait_sig_swap_core(kcondvar_t *cvp, kmutex_t *mp, int *sigret)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	int cancel_pending;
	int rval = 1;
	int signalled = 0;

	if (panicstr)
		return (rval);

	/*
	 * The check for t_intr is to catch an interrupt thread
	 * that has not yet unpinned the thread underneath.
	 */
	if (lwp == NULL || t->t_intr) {
		cv_wait(cvp, mp);
		return (rval);
	}

	cancel_pending = schedctl_cancel_pending();
	lwp->lwp_asleep = 1;
	lwp->lwp_sysabort = 0;
	thread_lock(t);
	t->t_kpri_req = 0;	/* don't need kernel priority */
	cv_block_sig(t, (condvar_impl_t *)cvp);
	/* I can be swapped now */
	curthread->t_schedflag &= ~TS_DONT_SWAP;
	thread_unlock_nopreempt(t);
	mutex_exit(mp);
	if (ISSIG(t, JUSTLOOKING) || MUSTRETURN(p, t) || cancel_pending)
		setrun(t);
	/* ASSERT(no locks are held) */
	swtch();
	signalled = (t->t_schedflag & TS_SIGNALLED);
	t->t_flag &= ~T_WAKEABLE;
	/* TS_DONT_SWAP set by disp() */
	ASSERT(curthread->t_schedflag & TS_DONT_SWAP);
	mutex_enter(mp);
	if (ISSIG_PENDING(t, lwp, p)) {
		mutex_exit(mp);
		if (issig(FORREAL))
			rval = 0;
		mutex_enter(mp);
	}
	if (lwp->lwp_sysabort || MUSTRETURN(p, t))
		rval = 0;
	if (rval != 0 && cancel_pending) {
		schedctl_cancel_eintr();
		rval = 0;
	}
	lwp->lwp_asleep = 0;
	lwp->lwp_sysabort = 0;
	if (rval == 0) {
		if (sigret != NULL)
			*sigret = signalled;	/* just tell the caller */
		else if (signalled)
			cv_signal(cvp);	/* avoid consuming the cv_signal() */
	}
	return (rval);
}

/*
 * Same as cv_wait_sig but the thread can be swapped out while waiting.
 * This should only be used when we know we aren't holding any locks.
 */
int
cv_wait_sig_swap(kcondvar_t *cvp, kmutex_t *mp)
{
	return (cv_wait_sig_swap_core(cvp, mp, NULL));
}

void
cv_signal(kcondvar_t *cvp)
{
	condvar_impl_t *cp = (condvar_impl_t *)cvp;

	/* make sure the cv_waiters field looks sane */
	ASSERT(cp->cv_waiters <= CV_MAX_WAITERS);
	if (cp->cv_waiters > 0) {
		sleepq_head_t *sqh = SQHASH(cp);
		disp_lock_enter(&sqh->sq_lock);
		ASSERT(CPU_ON_INTR(CPU) == 0);
		if (cp->cv_waiters & CV_WAITERS_MASK) {
			kthread_t *t;
			cp->cv_waiters--;
			t = sleepq_wakeone_chan(&sqh->sq_queue, cp);
			/*
			 * If cv_waiters is non-zero (and less than
			 * CV_MAX_WAITERS) there should be a thread
			 * in the queue.
			 */
			ASSERT(t != NULL);
		} else if (sleepq_wakeone_chan(&sqh->sq_queue, cp) == NULL) {
			cp->cv_waiters = 0;
		}
		disp_lock_exit(&sqh->sq_lock);
	}
}

void
cv_broadcast(kcondvar_t *cvp)
{
	condvar_impl_t *cp = (condvar_impl_t *)cvp;

	/* make sure the cv_waiters field looks sane */
	ASSERT(cp->cv_waiters <= CV_MAX_WAITERS);
	if (cp->cv_waiters > 0) {
		sleepq_head_t *sqh = SQHASH(cp);
		disp_lock_enter(&sqh->sq_lock);
		ASSERT(CPU_ON_INTR(CPU) == 0);
		sleepq_wakeall_chan(&sqh->sq_queue, cp);
		cp->cv_waiters = 0;
		disp_lock_exit(&sqh->sq_lock);
	}
}

/*
 * Same as cv_wait(), but wakes up (after wakeup_time milliseconds) to check
 * for requests to stop, like cv_wait_sig() but without dealing with signals.
 * This is a horrible kludge.  It is evil.  It is vile.  It is swill.
 * If your code has to call this function then your code is the same.
 */
void
cv_wait_stop(kcondvar_t *cvp, kmutex_t *mp, int wakeup_time)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	callout_id_t id;
	clock_t tim;

	if (panicstr)
		return;

	/*
	 * If there is no lwp, then we don't need to eventually stop it
	 * The check for t_intr is to catch an interrupt thread
	 * that has not yet unpinned the thread underneath.
	 */
	if (lwp == NULL || t->t_intr) {
		cv_wait(cvp, mp);
		return;
	}

	/*
	 * Wakeup in wakeup_time milliseconds, i.e., human time.
	 */
	tim = lbolt + MSEC_TO_TICK(wakeup_time);
	t->t_wait_mp = mp;
	id = realtime_timeout_default((void (*)(void *))cv_wakeup, t,
	    tim - lbolt);
	thread_lock(t);			/* lock the thread */
	cv_block((condvar_impl_t *)cvp);
	thread_unlock_nopreempt(t);
	mutex_exit(mp);
	/* ASSERT(no locks are held); */
	swtch();
	if (t->t_wait_mp != NULL)
		(void) untimeout_default(id, 0);

	/*
	 * Check for reasons to stop, if lwp_nostop is not true.
	 * See issig_forreal() for explanations of the various stops.
	 */
	mutex_enter(&p->p_lock);
	while (lwp->lwp_nostop == 0 && !(p->p_flag & SEXITLWPS)) {
		/*
		 * Hold the lwp here for watchpoint manipulation.
		 */
		if (t->t_proc_flag & TP_PAUSE) {
			stop(PR_SUSPENDED, SUSPEND_PAUSE);
			continue;
		}
		/*
		 * System checkpoint.
		 */
		if (t->t_proc_flag & TP_CHKPT) {
			stop(PR_CHECKPOINT, 0);
			continue;
		}
		/*
		 * Honor fork1(), watchpoint activity (remapping a page),
		 * and lwp_suspend() requests.
		 */
		if ((p->p_flag & (SHOLDFORK1|SHOLDWATCH)) ||
		    (t->t_proc_flag & TP_HOLDLWP)) {
			stop(PR_SUSPENDED, SUSPEND_NORMAL);
			continue;
		}
		/*
		 * Honor /proc requested stop.
		 */
		if (t->t_proc_flag & TP_PRSTOP) {
			stop(PR_REQUESTED, 0);
		}
		/*
		 * If some lwp in the process has already stopped
		 * showing PR_JOBCONTROL, stop in sympathy with it.
		 */
		if (p->p_stopsig && t != p->p_agenttp) {
			stop(PR_JOBCONTROL, p->p_stopsig);
			continue;
		}
		break;
	}
	mutex_exit(&p->p_lock);
	mutex_enter(mp);
}

/*
 * Like cv_timedwait_sig(), but takes an absolute hires future time
 * rather than a future time in clock ticks.  Will not return showing
 * that a timeout occurred until the future time is passed.
 * If 'when' is a NULL pointer, no timeout will occur.
 * Returns:
 * 	Function result in order of precedence:
 *		 0 if a signal was received
 *		-1 if timeout occured
 *	        >0 if awakened via cv_signal() or cv_broadcast()
 *		   or by a spurious wakeup.
 *		   (might return time remaining)
 * As a special test, if someone abruptly resets the system time
 * (but not through adjtime(2); drifting of the clock is allowed and
 * expected [see timespectohz_adj()]), then we force a return of -1
 * so the caller can return a premature timeout to the calling process
 * so it can reevaluate the situation in light of the new system time.
 * (The system clock has been reset if timecheck != timechanged.)
 */
int
cv_waituntil_sig(kcondvar_t *cvp, kmutex_t *mp,
	timestruc_t *when, int timecheck)
{
	timestruc_t now;
	timestruc_t delta;
	int rval;

	if (when == NULL)
		return (cv_wait_sig_swap(cvp, mp));

	gethrestime(&now);
	delta = *when;
	timespecsub(&delta, &now);
	if (delta.tv_sec < 0 || (delta.tv_sec == 0 && delta.tv_nsec == 0)) {
		/*
		 * We have already reached the absolute future time.
		 * Call cv_timedwait_sig() just to check for signals.
		 * We will return immediately with either 0 or -1.
		 */
		rval = cv_timedwait_sig(cvp, mp, lbolt);
	} else {
		gethrestime_lasttick(&now);
		if (timecheck == timechanged) {
			rval = cv_timedwait_sig_internal(cvp, mp,
			    lbolt + timespectohz(when, now),
			    CALLOUT_FLAG_HRESTIME);

		} else {
			/*
			 * Someone reset the system time;
			 * just force an immediate timeout.
			 */
			rval = -1;
		}
		if (rval == -1 && timecheck == timechanged) {
			/*
			 * Even though cv_timedwait_sig() returned showing a
			 * timeout, the future time may not have passed yet.
			 * If not, change rval to indicate a normal wakeup.
			 */
			gethrestime(&now);
			delta = *when;
			timespecsub(&delta, &now);
			if (delta.tv_sec > 0 || (delta.tv_sec == 0 &&
			    delta.tv_nsec > 0))
				rval = 1;
		}
	}
	return (rval);
}
