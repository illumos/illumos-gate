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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/poll_impl.h> /* only needed for kludge in sigwaiting_send() */
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/fault.h>
#include <sys/ucontext.h>
#include <sys/procfs.h>
#include <sys/wait.h>
#include <sys/class.h>
#include <sys/mman.h>
#include <sys/procset.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/prsystm.h>
#include <sys/debug.h>
#include <vm/as.h>
#include <sys/bitmap.h>
#include <c2/audit.h>
#include <sys/core.h>
#include <sys/schedctl.h>
#include <sys/contract/process_impl.h>
#include <sys/cyclic.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>
#include <sys/brand.h>

const k_sigset_t nullsmask = {0, 0, 0};

const k_sigset_t fillset =	/* MUST be contiguous */
	{FILLSET0, FILLSET1, FILLSET2};

const k_sigset_t cantmask =
	{CANTMASK0, CANTMASK1, CANTMASK2};

const k_sigset_t cantreset =
	{(sigmask(SIGILL)|sigmask(SIGTRAP)|sigmask(SIGPWR)), 0, 0};

const k_sigset_t ignoredefault =
	{(sigmask(SIGCONT)|sigmask(SIGCLD)|sigmask(SIGPWR)
	|sigmask(SIGWINCH)|sigmask(SIGURG)|sigmask(SIGWAITING)),
	(sigmask(SIGLWP)|sigmask(SIGCANCEL)|sigmask(SIGFREEZE)
	|sigmask(SIGTHAW)|sigmask(SIGXRES)|sigmask(SIGJVM1)
	|sigmask(SIGJVM2)|sigmask(SIGINFO)), 0};

const k_sigset_t stopdefault =
	{(sigmask(SIGSTOP)|sigmask(SIGTSTP)|sigmask(SIGTTOU)|sigmask(SIGTTIN)),
	0, 0};

const k_sigset_t coredefault =
	{(sigmask(SIGQUIT)|sigmask(SIGILL)|sigmask(SIGTRAP)|sigmask(SIGIOT)
	|sigmask(SIGEMT)|sigmask(SIGFPE)|sigmask(SIGBUS)|sigmask(SIGSEGV)
	|sigmask(SIGSYS)|sigmask(SIGXCPU)|sigmask(SIGXFSZ)), 0, 0};

const k_sigset_t holdvfork =
	{(sigmask(SIGTTOU)|sigmask(SIGTTIN)|sigmask(SIGTSTP)), 0, 0};

static	int	isjobstop(int);
static	void	post_sigcld(proc_t *, sigqueue_t *);

/*
 * Internal variables for counting number of user thread stop requests posted.
 * They may not be accurate at some special situation such as that a virtually
 * stopped thread starts to run.
 */
static int num_utstop;
/*
 * Internal variables for broadcasting an event when all thread stop requests
 * are processed.
 */
static kcondvar_t utstop_cv;

static kmutex_t thread_stop_lock;
void del_one_utstop(void);

/*
 * Send the specified signal to the specified process.
 */
void
psignal(proc_t *p, int sig)
{
	mutex_enter(&p->p_lock);
	sigtoproc(p, NULL, sig);
	mutex_exit(&p->p_lock);
}

/*
 * Send the specified signal to the specified thread.
 */
void
tsignal(kthread_t *t, int sig)
{
	proc_t *p = ttoproc(t);

	mutex_enter(&p->p_lock);
	sigtoproc(p, t, sig);
	mutex_exit(&p->p_lock);
}

int
signal_is_blocked(kthread_t *t, int sig)
{
	return (sigismember(&t->t_hold, sig) ||
	    (schedctl_sigblock(t) && !sigismember(&cantmask, sig)));
}

/*
 * Return true if the signal can safely be discarded on generation.
 * That is, if there is no need for the signal on the receiving end.
 * The answer is true if the process is a zombie or
 * if all of these conditions are true:
 *	the signal is being ignored
 *	the process is single-threaded
 *	the signal is not being traced by /proc
 * 	the signal is not blocked by the process
 *	the signal is not being accepted via sigwait()
 */
static int
sig_discardable(proc_t *p, int sig)
{
	kthread_t *t = p->p_tlist;

	return (t == NULL ||		/* if zombie or ... */
	    (sigismember(&p->p_ignore, sig) &&	/* signal is ignored */
	    t->t_forw == t &&			/* and single-threaded */
	    !tracing(p, sig) &&			/* and no /proc tracing */
	    !signal_is_blocked(t, sig) &&	/* and signal not blocked */
	    !sigismember(&t->t_sigwait, sig)));	/* and not being accepted */
}

/*
 * Return true if this thread is going to eat this signal soon.
 * Note that, if the signal is SIGKILL, we force stopped threads to be
 * set running (to make SIGKILL be a sure kill), but only if the process
 * is not currently locked by /proc (the P_PR_LOCK flag).  Code in /proc
 * relies on the fact that a process will not change shape while P_PR_LOCK
 * is set (it drops and reacquires p->p_lock while leaving P_PR_LOCK set).
 * We wish that we could simply call prbarrier() below, in sigtoproc(), to
 * ensure that the process is not locked by /proc, but prbarrier() drops
 * and reacquires p->p_lock and dropping p->p_lock here would be damaging.
 */
int
eat_signal(kthread_t *t, int sig)
{
	int rval = 0;
	ASSERT(THREAD_LOCK_HELD(t));

	/*
	 * Do not do anything if the target thread has the signal blocked.
	 */
	if (!signal_is_blocked(t, sig)) {
		t->t_sig_check = 1;	/* have thread do an issig */
		if (ISWAKEABLE(t) || ISWAITING(t)) {
			setrun_locked(t);
			rval = 1;
		} else if (t->t_state == TS_STOPPED && sig == SIGKILL &&
		    !(ttoproc(t)->p_proc_flag & P_PR_LOCK)) {
			ttoproc(t)->p_stopsig = 0;
			t->t_dtrace_stop = 0;
			t->t_schedflag |= TS_XSTART | TS_PSTART;
			setrun_locked(t);
		} else if (t != curthread && t->t_state == TS_ONPROC) {
			aston(t);	/* make it do issig promptly */
			if (t->t_cpu != CPU)
				poke_cpu(t->t_cpu->cpu_id);
			rval = 1;
		} else if (t->t_state == TS_RUN) {
			rval = 1;
		}
	}

	return (rval);
}

/*
 * Post a signal.
 * If a non-null thread pointer is passed, then post the signal
 * to the thread/lwp, otherwise post the signal to the process.
 */
void
sigtoproc(proc_t *p, kthread_t *t, int sig)
{
	kthread_t *tt;
	int ext = !(curproc->p_flag & SSYS) &&
	    (curproc->p_ct_process != p->p_ct_process);

	ASSERT(MUTEX_HELD(&p->p_lock));

	/* System processes don't get signals */
	if (sig <= 0 || sig >= NSIG || (p->p_flag & SSYS))
		return;

	/*
	 * Regardless of origin or directedness,
	 * SIGKILL kills all lwps in the process immediately
	 * and jobcontrol signals affect all lwps in the process.
	 */
	if (sig == SIGKILL) {
		p->p_flag |= SKILLED | (ext ? SEXTKILLED : 0);
		t = NULL;
	} else if (sig == SIGCONT) {
		/*
		 * The SSCONT flag will remain set until a stopping
		 * signal comes in (below).  This is harmless.
		 */
		p->p_flag |= SSCONT;
		sigdelq(p, NULL, SIGSTOP);
		sigdelq(p, NULL, SIGTSTP);
		sigdelq(p, NULL, SIGTTOU);
		sigdelq(p, NULL, SIGTTIN);
		sigdiffset(&p->p_sig, &stopdefault);
		sigdiffset(&p->p_extsig, &stopdefault);
		p->p_stopsig = 0;
		if ((tt = p->p_tlist) != NULL) {
			do {
				sigdelq(p, tt, SIGSTOP);
				sigdelq(p, tt, SIGTSTP);
				sigdelq(p, tt, SIGTTOU);
				sigdelq(p, tt, SIGTTIN);
				sigdiffset(&tt->t_sig, &stopdefault);
				sigdiffset(&tt->t_extsig, &stopdefault);
			} while ((tt = tt->t_forw) != p->p_tlist);
		}
		if ((tt = p->p_tlist) != NULL) {
			do {
				thread_lock(tt);
				if (tt->t_state == TS_STOPPED &&
				    tt->t_whystop == PR_JOBCONTROL) {
					tt->t_schedflag |= TS_XSTART;
					setrun_locked(tt);
				}
				thread_unlock(tt);
			} while ((tt = tt->t_forw) != p->p_tlist);
		}
	} else if (sigismember(&stopdefault, sig)) {
		/*
		 * This test has a race condition which we can't fix:
		 * By the time the stopping signal is received by
		 * the target process/thread, the signal handler
		 * and/or the detached state might have changed.
		 */
		if (PTOU(p)->u_signal[sig-1] == SIG_DFL &&
		    (sig == SIGSTOP || !p->p_pgidp->pid_pgorphaned))
			p->p_flag &= ~SSCONT;
		sigdelq(p, NULL, SIGCONT);
		sigdelset(&p->p_sig, SIGCONT);
		sigdelset(&p->p_extsig, SIGCONT);
		if ((tt = p->p_tlist) != NULL) {
			do {
				sigdelq(p, tt, SIGCONT);
				sigdelset(&tt->t_sig, SIGCONT);
				sigdelset(&tt->t_extsig, SIGCONT);
			} while ((tt = tt->t_forw) != p->p_tlist);
		}
	}

	if (sig_discardable(p, sig)) {
		DTRACE_PROC3(signal__discard, kthread_t *, p->p_tlist,
		    proc_t *, p, int, sig);
		return;
	}

	if (t != NULL) {
		/*
		 * This is a directed signal, wake up the lwp.
		 */
		sigaddset(&t->t_sig, sig);
		if (ext)
			sigaddset(&t->t_extsig, sig);
		thread_lock(t);
		(void) eat_signal(t, sig);
		thread_unlock(t);
		DTRACE_PROC2(signal__send, kthread_t *, t, int, sig);
	} else if ((tt = p->p_tlist) != NULL) {
		/*
		 * Make sure that some lwp that already exists
		 * in the process fields the signal soon.
		 * Wake up an interruptibly sleeping lwp if necessary.
		 * For SIGKILL make all of the lwps see the signal;
		 * This is needed to guarantee a sure kill for processes
		 * with a mix of realtime and non-realtime threads.
		 */
		int su = 0;

		sigaddset(&p->p_sig, sig);
		if (ext)
			sigaddset(&p->p_extsig, sig);
		do {
			thread_lock(tt);
			if (eat_signal(tt, sig) && sig != SIGKILL) {
				thread_unlock(tt);
				break;
			}
			if (SUSPENDED(tt))
				su++;
			thread_unlock(tt);
		} while ((tt = tt->t_forw) != p->p_tlist);
		/*
		 * If the process is deadlocked, make somebody run and die.
		 */
		if (sig == SIGKILL && p->p_stat != SIDL &&
		    p->p_lwprcnt == 0 && p->p_lwpcnt == su &&
		    !(p->p_proc_flag & P_PR_LOCK)) {
			thread_lock(tt);
			p->p_lwprcnt++;
			tt->t_schedflag |= TS_CSTART;
			setrun_locked(tt);
			thread_unlock(tt);
		}

		DTRACE_PROC2(signal__send, kthread_t *, tt, int, sig);
	}
}

static int
isjobstop(int sig)
{
	proc_t *p = ttoproc(curthread);

	ASSERT(MUTEX_HELD(&p->p_lock));

	if (PTOU(curproc)->u_signal[sig-1] == SIG_DFL &&
	    sigismember(&stopdefault, sig)) {
		/*
		 * If SIGCONT has been posted since we promoted this signal
		 * from pending to current, then don't do a jobcontrol stop.
		 */
		if (!(p->p_flag & SSCONT) &&
		    (sig == SIGSTOP || !p->p_pgidp->pid_pgorphaned) &&
		    curthread != p->p_agenttp) {
			sigqueue_t *sqp;

			stop(PR_JOBCONTROL, sig);
			mutex_exit(&p->p_lock);
			sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
			mutex_enter(&pidlock);
			/*
			 * Only the first lwp to continue notifies the parent.
			 */
			if (p->p_pidflag & CLDCONT)
				siginfofree(sqp);
			else {
				p->p_pidflag |= CLDCONT;
				p->p_wcode = CLD_CONTINUED;
				p->p_wdata = SIGCONT;
				sigcld(p, sqp);
			}
			mutex_exit(&pidlock);
			mutex_enter(&p->p_lock);
		}
		return (1);
	}
	return (0);
}

/*
 * Returns true if the current process has a signal to process, and
 * the signal is not held.  The signal to process is put in p_cursig.
 * This is asked at least once each time a process enters the system
 * (though this can usually be done without actually calling issig by
 * checking the pending signal masks).  A signal does not do anything
 * directly to a process; it sets a flag that asks the process to do
 * something to itself.
 *
 * The "why" argument indicates the allowable side-effects of the call:
 *
 * FORREAL:  Extract the next pending signal from p_sig into p_cursig;
 * stop the process if a stop has been requested or if a traced signal
 * is pending.
 *
 * JUSTLOOKING:  Don't stop the process, just indicate whether or not
 * a signal might be pending (FORREAL is needed to tell for sure).
 *
 * XXX: Changes to the logic in these routines should be propagated
 * to lm_sigispending().  See bug 1201594.
 */

static int issig_forreal(void);
static int issig_justlooking(void);

int
issig(int why)
{
	ASSERT(why == FORREAL || why == JUSTLOOKING);

	return ((why == FORREAL)? issig_forreal() : issig_justlooking());
}


static int
issig_justlooking(void)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	k_sigset_t set;

	/*
	 * This function answers the question:
	 * "Is there any reason to call issig_forreal()?"
	 *
	 * We have to answer the question w/o grabbing any locks
	 * because we are (most likely) being called after we
	 * put ourselves on the sleep queue.
	 */

	if (t->t_dtrace_stop | t->t_dtrace_sig)
		return (1);

	/*
	 * Another piece of complexity in this process.  When single-stepping a
	 * process, we don't want an intervening signal or TP_PAUSE request to
	 * suspend the current thread.  Otherwise, the controlling process will
	 * hang beacuse we will be stopped with TS_PSTART set in t_schedflag.
	 * We will trigger any remaining signals when we re-enter the kernel on
	 * the single step trap.
	 */
	if (lwp->lwp_pcb.pcb_flags & NORMAL_STEP)
		return (0);

	if ((lwp->lwp_asleep && MUSTRETURN(p, t)) ||
	    (p->p_flag & (SEXITLWPS|SKILLED)) ||
	    (lwp->lwp_nostop == 0 &&
	    (p->p_stopsig | (p->p_flag & (SHOLDFORK1|SHOLDWATCH)) |
	    (t->t_proc_flag &
	    (TP_PRSTOP|TP_HOLDLWP|TP_CHKPT|TP_PAUSE)))) ||
	    lwp->lwp_cursig)
		return (1);

	if (p->p_flag & SVFWAIT)
		return (0);
	set = p->p_sig;
	sigorset(&set, &t->t_sig);
	if (schedctl_sigblock(t))	/* all blockable signals blocked */
		sigandset(&set, &cantmask);
	else
		sigdiffset(&set, &t->t_hold);
	if (p->p_flag & SVFORK)
		sigdiffset(&set, &holdvfork);

	if (!sigisempty(&set)) {
		int sig;

		for (sig = 1; sig < NSIG; sig++) {
			if (sigismember(&set, sig) &&
			    (tracing(p, sig) ||
			    sigismember(&t->t_sigwait, sig) ||
			    !sigismember(&p->p_ignore, sig))) {
				/*
				 * Don't promote a signal that will stop
				 * the process when lwp_nostop is set.
				 */
				if (!lwp->lwp_nostop ||
				    PTOU(p)->u_signal[sig-1] != SIG_DFL ||
				    !sigismember(&stopdefault, sig))
					return (1);
			}
		}
	}

	return (0);
}

static int
issig_forreal(void)
{
	int sig = 0, ext = 0;
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	int toproc = 0;
	int sigcld_found = 0;
	int nostop_break = 0;

	ASSERT(t->t_state == TS_ONPROC);

	mutex_enter(&p->p_lock);
	schedctl_finish_sigblock(t);

	if (t->t_dtrace_stop | t->t_dtrace_sig) {
		if (t->t_dtrace_stop) {
			/*
			 * If DTrace's "stop" action has been invoked on us,
			 * set TP_PRSTOP.
			 */
			t->t_proc_flag |= TP_PRSTOP;
		}

		if (t->t_dtrace_sig != 0) {
			k_siginfo_t info;

			/*
			 * Post the signal generated as the result of
			 * DTrace's "raise" action as a normal signal before
			 * the full-fledged signal checking begins.
			 */
			bzero(&info, sizeof (info));
			info.si_signo = t->t_dtrace_sig;
			info.si_code = SI_DTRACE;

			sigaddq(p, NULL, &info, KM_NOSLEEP);

			t->t_dtrace_sig = 0;
		}
	}

	for (;;) {
		if (p->p_flag & (SEXITLWPS|SKILLED)) {
			lwp->lwp_cursig = sig = SIGKILL;
			lwp->lwp_extsig = ext = (p->p_flag & SEXTKILLED) != 0;
			t->t_sig_check = 1;
			break;
		}

		/*
		 * Another piece of complexity in this process.  When
		 * single-stepping a process, we don't want an intervening
		 * signal or TP_PAUSE request to suspend the current thread.
		 * Otherwise, the controlling process will hang beacuse we will
		 * be stopped with TS_PSTART set in t_schedflag.  We will
		 * trigger any remaining signals when we re-enter the kernel on
		 * the single step trap.
		 */
		if (lwp->lwp_pcb.pcb_flags & NORMAL_STEP) {
			sig = 0;
			break;
		}

		/*
		 * Hold the lwp here for watchpoint manipulation.
		 */
		if ((t->t_proc_flag & TP_PAUSE) && !lwp->lwp_nostop) {
			stop(PR_SUSPENDED, SUSPEND_PAUSE);
			continue;
		}

		if (lwp->lwp_asleep && MUSTRETURN(p, t)) {
			if ((sig = lwp->lwp_cursig) != 0) {
				/*
				 * Make sure we call ISSIG() in post_syscall()
				 * to re-validate this current signal.
				 */
				t->t_sig_check = 1;
			}
			break;
		}

		/*
		 * If the request is PR_CHECKPOINT, ignore the rest of signals
		 * or requests.  Honor other stop requests or signals later.
		 * Go back to top of loop here to check if an exit or hold
		 * event has occurred while stopped.
		 */
		if ((t->t_proc_flag & TP_CHKPT) && !lwp->lwp_nostop) {
			stop(PR_CHECKPOINT, 0);
			continue;
		}

		/*
		 * Honor SHOLDFORK1, SHOLDWATCH, and TP_HOLDLWP before dealing
		 * with signals or /proc.  Another lwp is executing fork1(),
		 * or is undergoing watchpoint activity (remapping a page),
		 * or is executing lwp_suspend() on this lwp.
		 * Again, go back to top of loop to check if an exit
		 * or hold event has occurred while stopped.
		 */
		if (((p->p_flag & (SHOLDFORK1|SHOLDWATCH)) ||
		    (t->t_proc_flag & TP_HOLDLWP)) && !lwp->lwp_nostop) {
			stop(PR_SUSPENDED, SUSPEND_NORMAL);
			continue;
		}

		/*
		 * Honor requested stop before dealing with the
		 * current signal; a debugger may change it.
		 * Do not want to go back to loop here since this is a special
		 * stop that means: make incremental progress before the next
		 * stop. The danger is that returning to top of loop would most
		 * likely drop the thread right back here to stop soon after it
		 * was continued, violating the incremental progress request.
		 */
		if ((t->t_proc_flag & TP_PRSTOP) && !lwp->lwp_nostop)
			stop(PR_REQUESTED, 0);

		/*
		 * If a debugger wants us to take a signal it will have
		 * left it in lwp->lwp_cursig.  If lwp_cursig has been cleared
		 * or if it's being ignored, we continue on looking for another
		 * signal.  Otherwise we return the specified signal, provided
		 * it's not a signal that causes a job control stop.
		 *
		 * When stopped on PR_JOBCONTROL, there is no current
		 * signal; we cancel lwp->lwp_cursig temporarily before
		 * calling isjobstop().  The current signal may be reset
		 * by a debugger while we are stopped in isjobstop().
		 *
		 * If the current thread is accepting the signal
		 * (via sigwait(), sigwaitinfo(), or sigtimedwait()),
		 * we allow the signal to be accepted, even if it is
		 * being ignored, and without causing a job control stop.
		 */
		if ((sig = lwp->lwp_cursig) != 0) {
			ext = lwp->lwp_extsig;
			lwp->lwp_cursig = 0;
			lwp->lwp_extsig = 0;
			if (sigismember(&t->t_sigwait, sig) ||
			    (!sigismember(&p->p_ignore, sig) &&
			    !isjobstop(sig))) {
				if (p->p_flag & (SEXITLWPS|SKILLED)) {
					sig = SIGKILL;
					ext = (p->p_flag & SEXTKILLED) != 0;
				}
				lwp->lwp_cursig = (uchar_t)sig;
				lwp->lwp_extsig = (uchar_t)ext;
				break;
			}
			/*
			 * The signal is being ignored or it caused a
			 * job-control stop.  If another current signal
			 * has not been established, return the current
			 * siginfo, if any, to the memory manager.
			 */
			if (lwp->lwp_cursig == 0 && lwp->lwp_curinfo != NULL) {
				siginfofree(lwp->lwp_curinfo);
				lwp->lwp_curinfo = NULL;
			}
			/*
			 * Loop around again in case we were stopped
			 * on a job control signal and a /proc stop
			 * request was posted or another current signal
			 * was established while we were stopped.
			 */
			continue;
		}

		if (p->p_stopsig && !lwp->lwp_nostop &&
		    curthread != p->p_agenttp) {
			/*
			 * Some lwp in the process has already stopped
			 * showing PR_JOBCONTROL.  This is a stop in
			 * sympathy with the other lwp, even if this
			 * lwp is blocking the stopping signal.
			 */
			stop(PR_JOBCONTROL, p->p_stopsig);
			continue;
		}

		/*
		 * Loop on the pending signals until we find a
		 * non-held signal that is traced or not ignored.
		 * First check the signals pending for the lwp,
		 * then the signals pending for the process as a whole.
		 */
		for (;;) {
			if ((sig = fsig(&t->t_sig, t)) != 0) {
				toproc = 0;
				if (tracing(p, sig) ||
				    sigismember(&t->t_sigwait, sig) ||
				    !sigismember(&p->p_ignore, sig)) {
					if (sigismember(&t->t_extsig, sig))
						ext = 1;
					break;
				}
				sigdelset(&t->t_sig, sig);
				sigdelset(&t->t_extsig, sig);
				sigdelq(p, t, sig);
			} else if ((sig = fsig(&p->p_sig, t)) != 0) {
				if (sig == SIGCLD)
					sigcld_found = 1;
				toproc = 1;
				if (tracing(p, sig) ||
				    sigismember(&t->t_sigwait, sig) ||
				    !sigismember(&p->p_ignore, sig)) {
					if (sigismember(&p->p_extsig, sig))
						ext = 1;
					break;
				}
				sigdelset(&p->p_sig, sig);
				sigdelset(&p->p_extsig, sig);
				sigdelq(p, NULL, sig);
			} else {
				/* no signal was found */
				break;
			}
		}

		if (sig == 0) {	/* no signal was found */
			if (p->p_flag & (SEXITLWPS|SKILLED)) {
				lwp->lwp_cursig = SIGKILL;
				sig = SIGKILL;
				ext = (p->p_flag & SEXTKILLED) != 0;
			}
			break;
		}

		/*
		 * If we have been informed not to stop (i.e., we are being
		 * called from within a network operation), then don't promote
		 * the signal at this time, just return the signal number.
		 * We will call issig() again later when it is safe.
		 *
		 * fsig() does not return a jobcontrol stopping signal
		 * with a default action of stopping the process if
		 * lwp_nostop is set, so we won't be causing a bogus
		 * EINTR by this action.  (Such a signal is eaten by
		 * isjobstop() when we loop around to do final checks.)
		 */
		if (lwp->lwp_nostop) {
			nostop_break = 1;
			break;
		}

		/*
		 * Promote the signal from pending to current.
		 *
		 * Note that sigdeq() will set lwp->lwp_curinfo to NULL
		 * if no siginfo_t exists for this signal.
		 */
		lwp->lwp_cursig = (uchar_t)sig;
		lwp->lwp_extsig = (uchar_t)ext;
		t->t_sig_check = 1;	/* so post_syscall will see signal */
		ASSERT(lwp->lwp_curinfo == NULL);
		sigdeq(p, toproc ? NULL : t, sig, &lwp->lwp_curinfo);

		if (tracing(p, sig))
			stop(PR_SIGNALLED, sig);

		/*
		 * Loop around to check for requested stop before
		 * performing the usual current-signal actions.
		 */
	}

	mutex_exit(&p->p_lock);

	/*
	 * If SIGCLD was dequeued from the process's signal queue,
	 * search for other pending SIGCLD's from the list of children.
	 */
	if (sigcld_found)
		sigcld_repost();

	if (sig != 0)
		(void) undo_watch_step(NULL);

	/*
	 * If we have been blocked since the p_lock was dropped off
	 * above, then this promoted signal might have been handled
	 * already when we were on the way back from sleep queue, so
	 * just ignore it.
	 * If we have been informed not to stop, just return the signal
	 * number. Also see comments above.
	 */
	if (!nostop_break) {
		sig = lwp->lwp_cursig;
	}

	return (sig != 0);
}

/*
 * Return true if the process is currently stopped showing PR_JOBCONTROL.
 * This is true only if all of the process's lwp's are so stopped.
 * If this is asked by one of the lwps in the process, exclude that lwp.
 */
int
jobstopped(proc_t *p)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if ((t = p->p_tlist) == NULL)
		return (0);

	do {
		thread_lock(t);
		/* ignore current, zombie and suspended lwps in the test */
		if (!(t == curthread || t->t_state == TS_ZOMB ||
		    SUSPENDED(t)) &&
		    (t->t_state != TS_STOPPED ||
		    t->t_whystop != PR_JOBCONTROL)) {
			thread_unlock(t);
			return (0);
		}
		thread_unlock(t);
	} while ((t = t->t_forw) != p->p_tlist);

	return (1);
}

/*
 * Put ourself (curthread) into the stopped state and notify tracers.
 */
void
stop(int why, int what)
{
	kthread_t	*t = curthread;
	proc_t		*p = ttoproc(t);
	klwp_t		*lwp = ttolwp(t);
	kthread_t	*tx;
	lwpent_t	*lep;
	int		procstop;
	int		flags = TS_ALLSTART;
	hrtime_t	stoptime;

	/*
	 * Can't stop a system process.
	 */
	if (p == NULL || lwp == NULL || (p->p_flag & SSYS) || p->p_as == &kas)
		return;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if (why != PR_SUSPENDED && why != PR_CHECKPOINT) {
		/*
		 * Don't stop an lwp with SIGKILL pending.
		 * Don't stop if the process or lwp is exiting.
		 */
		if (lwp->lwp_cursig == SIGKILL ||
		    sigismember(&t->t_sig, SIGKILL) ||
		    sigismember(&p->p_sig, SIGKILL) ||
		    (t->t_proc_flag & TP_LWPEXIT) ||
		    (p->p_flag & (SEXITLWPS|SKILLED))) {
			p->p_stopsig = 0;
			t->t_proc_flag &= ~(TP_PRSTOP|TP_PRVSTOP);
			return;
		}
	}

	/*
	 * Make sure we don't deadlock on a recursive call to prstop().
	 * prstop() sets the lwp_nostop flag.
	 */
	if (lwp->lwp_nostop)
		return;

	/*
	 * Make sure the lwp is in an orderly state for inspection
	 * by a debugger through /proc or for dumping via core().
	 */
	schedctl_finish_sigblock(t);
	t->t_proc_flag |= TP_STOPPING;	/* must set before dropping p_lock */
	mutex_exit(&p->p_lock);
	stoptime = gethrtime();
	prstop(why, what);
	(void) undo_watch_step(NULL);
	mutex_enter(&p->p_lock);
	ASSERT(t->t_state == TS_ONPROC);

	switch (why) {
	case PR_CHECKPOINT:
		/*
		 * The situation may have changed since we dropped
		 * and reacquired p->p_lock. Double-check now
		 * whether we should stop or not.
		 */
		if (!(t->t_proc_flag & TP_CHKPT)) {
			t->t_proc_flag &= ~TP_STOPPING;
			return;
		}
		t->t_proc_flag &= ~TP_CHKPT;
		flags &= ~TS_RESUME;
		break;

	case PR_JOBCONTROL:
		ASSERT(what == SIGSTOP || what == SIGTSTP ||
		    what == SIGTTIN || what == SIGTTOU);
		flags &= ~TS_XSTART;
		break;

	case PR_SUSPENDED:
		ASSERT(what == SUSPEND_NORMAL || what == SUSPEND_PAUSE);
		/*
		 * The situation may have changed since we dropped
		 * and reacquired p->p_lock.  Double-check now
		 * whether we should stop or not.
		 */
		if (what == SUSPEND_PAUSE) {
			if (!(t->t_proc_flag & TP_PAUSE)) {
				t->t_proc_flag &= ~TP_STOPPING;
				return;
			}
			flags &= ~TS_UNPAUSE;
		} else {
			if (!((t->t_proc_flag & TP_HOLDLWP) ||
			    (p->p_flag & (SHOLDFORK|SHOLDFORK1|SHOLDWATCH)))) {
				t->t_proc_flag &= ~TP_STOPPING;
				return;
			}
			/*
			 * If SHOLDFORK is in effect and we are stopping
			 * while asleep (not at the top of the stack),
			 * we return now to allow the hold to take effect
			 * when we reach the top of the kernel stack.
			 */
			if (lwp->lwp_asleep && (p->p_flag & SHOLDFORK)) {
				t->t_proc_flag &= ~TP_STOPPING;
				return;
			}
			flags &= ~TS_CSTART;
		}
		break;

	default:	/* /proc stop */
		flags &= ~TS_PSTART;
		/*
		 * Do synchronous stop unless the async-stop flag is set.
		 * If why is PR_REQUESTED and t->t_dtrace_stop flag is set,
		 * then no debugger is present and we also do synchronous stop.
		 */
		if ((why != PR_REQUESTED || t->t_dtrace_stop) &&
		    !(p->p_proc_flag & P_PR_ASYNC)) {
			int notify;

			for (tx = t->t_forw; tx != t; tx = tx->t_forw) {
				notify = 0;
				thread_lock(tx);
				if (ISTOPPED(tx) ||
				    (tx->t_proc_flag & TP_PRSTOP)) {
					thread_unlock(tx);
					continue;
				}
				tx->t_proc_flag |= TP_PRSTOP;
				tx->t_sig_check = 1;
				if (tx->t_state == TS_SLEEP &&
				    (tx->t_flag & T_WAKEABLE)) {
					/*
					 * Don't actually wake it up if it's
					 * in one of the lwp_*() syscalls.
					 * Mark it virtually stopped and
					 * notify /proc waiters (below).
					 */
					if (tx->t_wchan0 == NULL)
						setrun_locked(tx);
					else {
						tx->t_proc_flag |= TP_PRVSTOP;
						tx->t_stoptime = stoptime;
						notify = 1;
					}
				}

				/* Move waiting thread to run queue */
				if (ISWAITING(tx))
					setrun_locked(tx);

				/*
				 * force the thread into the kernel
				 * if it is not already there.
				 */
				if (tx->t_state == TS_ONPROC &&
				    tx->t_cpu != CPU)
					poke_cpu(tx->t_cpu->cpu_id);
				thread_unlock(tx);
				lep = p->p_lwpdir[tx->t_dslot].ld_entry;
				if (notify && lep->le_trace)
					prnotify(lep->le_trace);
			}
			/*
			 * We do this just in case one of the threads we asked
			 * to stop is in holdlwps() (called from cfork()) or
			 * lwp_suspend().
			 */
			cv_broadcast(&p->p_holdlwps);
		}
		break;
	}

	t->t_stoptime = stoptime;

	if (why == PR_JOBCONTROL || (why == PR_SUSPENDED && p->p_stopsig)) {
		/*
		 * Determine if the whole process is jobstopped.
		 */
		if (jobstopped(p)) {
			sigqueue_t *sqp;
			int sig;

			if ((sig = p->p_stopsig) == 0)
				p->p_stopsig = (uchar_t)(sig = what);
			mutex_exit(&p->p_lock);
			sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
			mutex_enter(&pidlock);
			/*
			 * The last lwp to stop notifies the parent.
			 * Turn off the CLDCONT flag now so the first
			 * lwp to continue knows what to do.
			 */
			p->p_pidflag &= ~CLDCONT;
			p->p_wcode = CLD_STOPPED;
			p->p_wdata = sig;
			sigcld(p, sqp);
			/*
			 * Grab p->p_lock before releasing pidlock so the
			 * parent and the child don't have a race condition.
			 */
			mutex_enter(&p->p_lock);
			mutex_exit(&pidlock);
			p->p_stopsig = 0;
		} else if (why == PR_JOBCONTROL && p->p_stopsig == 0) {
			/*
			 * Set p->p_stopsig and wake up sleeping lwps
			 * so they will stop in sympathy with this lwp.
			 */
			p->p_stopsig = (uchar_t)what;
			pokelwps(p);
			/*
			 * We do this just in case one of the threads we asked
			 * to stop is in holdlwps() (called from cfork()) or
			 * lwp_suspend().
			 */
			cv_broadcast(&p->p_holdlwps);
		}
	}

	if (why != PR_JOBCONTROL && why != PR_CHECKPOINT) {
		/*
		 * Do process-level notification when all lwps are
		 * either stopped on events of interest to /proc
		 * or are stopped showing PR_SUSPENDED or are zombies.
		 */
		procstop = 1;
		for (tx = t->t_forw; procstop && tx != t; tx = tx->t_forw) {
			if (VSTOPPED(tx))
				continue;
			thread_lock(tx);
			switch (tx->t_state) {
			case TS_ZOMB:
				break;
			case TS_STOPPED:
				/* neither ISTOPPED nor SUSPENDED? */
				if ((tx->t_schedflag &
				    (TS_CSTART | TS_UNPAUSE | TS_PSTART)) ==
				    (TS_CSTART | TS_UNPAUSE | TS_PSTART))
					procstop = 0;
				break;
			case TS_SLEEP:
				/* not paused for watchpoints? */
				if (!(tx->t_flag & T_WAKEABLE) ||
				    tx->t_wchan0 == NULL ||
				    !(tx->t_proc_flag & TP_PAUSE))
					procstop = 0;
				break;
			default:
				procstop = 0;
				break;
			}
			thread_unlock(tx);
		}
		if (procstop) {
			/* there must not be any remapped watched pages now */
			ASSERT(p->p_mapcnt == 0);
			if (p->p_proc_flag & P_PR_PTRACE) {
				/* ptrace() compatibility */
				mutex_exit(&p->p_lock);
				mutex_enter(&pidlock);
				p->p_wcode = CLD_TRAPPED;
				p->p_wdata = (why == PR_SIGNALLED)?
				    what : SIGTRAP;
				cv_broadcast(&p->p_parent->p_cv);
				/*
				 * Grab p->p_lock before releasing pidlock so
				 * parent and child don't have a race condition.
				 */
				mutex_enter(&p->p_lock);
				mutex_exit(&pidlock);
			}
			if (p->p_trace)			/* /proc */
				prnotify(p->p_trace);
			cv_broadcast(&pr_pid_cv[p->p_slot]); /* pauselwps() */
			cv_broadcast(&p->p_holdlwps);	/* holdwatch() */
		}
		if (why != PR_SUSPENDED) {
			lep = p->p_lwpdir[t->t_dslot].ld_entry;
			if (lep->le_trace)		/* /proc */
				prnotify(lep->le_trace);
			/*
			 * Special notification for creation of the agent lwp.
			 */
			if (t == p->p_agenttp &&
			    (t->t_proc_flag & TP_PRSTOP) &&
			    p->p_trace)
				prnotify(p->p_trace);
			/*
			 * The situation may have changed since we dropped
			 * and reacquired p->p_lock. Double-check now
			 * whether we should stop or not.
			 */
			if (!(t->t_proc_flag & TP_STOPPING)) {
				if (t->t_proc_flag & TP_PRSTOP)
					t->t_proc_flag |= TP_STOPPING;
			}
			t->t_proc_flag &= ~(TP_PRSTOP|TP_PRVSTOP);
			prnostep(lwp);
		}
	}

	if (why == PR_SUSPENDED) {

		/*
		 * We always broadcast in the case of SUSPEND_PAUSE.  This is
		 * because checks for TP_PAUSE take precedence over checks for
		 * SHOLDWATCH.  If a thread is trying to stop because of
		 * SUSPEND_PAUSE and tries to do a holdwatch(), it will be
		 * waiting for the rest of the threads to enter a stopped state.
		 * If we are stopping for a SUSPEND_PAUSE, we may be the last
		 * lwp and not know it, so broadcast just in case.
		 */
		if (what == SUSPEND_PAUSE ||
		    --p->p_lwprcnt == 0 || (t->t_proc_flag & TP_HOLDLWP))
			cv_broadcast(&p->p_holdlwps);

	}

	/*
	 * Need to do this here (rather than after the thread is officially
	 * stopped) because we can't call mutex_enter from a stopped thread.
	 */
	if (why == PR_CHECKPOINT)
		del_one_utstop();

	thread_lock(t);
	ASSERT((t->t_schedflag & TS_ALLSTART) == 0);
	t->t_schedflag |= flags;
	t->t_whystop = (short)why;
	t->t_whatstop = (short)what;
	CL_STOP(t, why, what);
	(void) new_mstate(t, LMS_STOPPED);
	thread_stop(t);			/* set stop state and drop lock */

	if (why != PR_SUSPENDED && why != PR_CHECKPOINT) {
		/*
		 * We may have gotten a SIGKILL or a SIGCONT when
		 * we released p->p_lock; make one last check.
		 * Also check for a /proc run-on-last-close.
		 */
		if (sigismember(&t->t_sig, SIGKILL) ||
		    sigismember(&p->p_sig, SIGKILL) ||
		    (t->t_proc_flag & TP_LWPEXIT) ||
		    (p->p_flag & (SEXITLWPS|SKILLED))) {
			p->p_stopsig = 0;
			thread_lock(t);
			t->t_schedflag |= TS_XSTART | TS_PSTART;
			setrun_locked(t);
			thread_unlock_nopreempt(t);
		} else if (why == PR_JOBCONTROL) {
			if (p->p_flag & SSCONT) {
				/*
				 * This resulted from a SIGCONT posted
				 * while we were not holding p->p_lock.
				 */
				p->p_stopsig = 0;
				thread_lock(t);
				t->t_schedflag |= TS_XSTART;
				setrun_locked(t);
				thread_unlock_nopreempt(t);
			}
		} else if (!(t->t_proc_flag & TP_STOPPING)) {
			/*
			 * This resulted from a /proc run-on-last-close.
			 */
			thread_lock(t);
			t->t_schedflag |= TS_PSTART;
			setrun_locked(t);
			thread_unlock_nopreempt(t);
		}
	}

	t->t_proc_flag &= ~TP_STOPPING;
	mutex_exit(&p->p_lock);

	swtch();
	setallwatch();	/* reestablish any watchpoints set while stopped */
	mutex_enter(&p->p_lock);
	prbarrier(p);	/* barrier against /proc locking */
}

/* Interface for resetting user thread stop count. */
void
utstop_init(void)
{
	mutex_enter(&thread_stop_lock);
	num_utstop = 0;
	mutex_exit(&thread_stop_lock);
}

/* Interface for registering a user thread stop request. */
void
add_one_utstop(void)
{
	mutex_enter(&thread_stop_lock);
	num_utstop++;
	mutex_exit(&thread_stop_lock);
}

/* Interface for cancelling a user thread stop request */
void
del_one_utstop(void)
{
	mutex_enter(&thread_stop_lock);
	num_utstop--;
	if (num_utstop == 0)
		cv_broadcast(&utstop_cv);
	mutex_exit(&thread_stop_lock);
}

/* Interface to wait for all user threads to be stopped */
void
utstop_timedwait(clock_t ticks)
{
	mutex_enter(&thread_stop_lock);
	if (num_utstop > 0)
		(void) cv_reltimedwait(&utstop_cv, &thread_stop_lock, ticks,
		    TR_CLOCK_TICK);
	mutex_exit(&thread_stop_lock);
}

/*
 * Perform the action specified by the current signal.
 * The usual sequence is:
 * 	if (issig())
 * 		psig();
 * The signal bit has already been cleared by issig(),
 * the current signal number has been stored in lwp_cursig,
 * and the current siginfo is now referenced by lwp_curinfo.
 */
void
psig(void)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	void (*func)();
	int sig, rc, code, ext;
	pid_t pid = -1;
	id_t ctid = 0;
	zoneid_t zoneid = -1;
	sigqueue_t *sqp = NULL;
	uint32_t auditing = AU_AUDITING();

	mutex_enter(&p->p_lock);
	schedctl_finish_sigblock(t);
	code = CLD_KILLED;

	if (p->p_flag & SEXITLWPS) {
		lwp_exit();
		return;			/* not reached */
	}
	sig = lwp->lwp_cursig;
	ext = lwp->lwp_extsig;

	ASSERT(sig < NSIG);

	/*
	 * Re-check lwp_cursig after we acquire p_lock.  Since p_lock was
	 * dropped between issig() and psig(), a debugger may have cleared
	 * lwp_cursig via /proc in the intervening window.
	 */
	if (sig == 0) {
		if (lwp->lwp_curinfo) {
			siginfofree(lwp->lwp_curinfo);
			lwp->lwp_curinfo = NULL;
		}
		if (t->t_flag & T_TOMASK) {	/* sigsuspend or pollsys */
			t->t_flag &= ~T_TOMASK;
			t->t_hold = lwp->lwp_sigoldmask;
		}
		mutex_exit(&p->p_lock);
		return;
	}
	func = PTOU(curproc)->u_signal[sig-1];

	/*
	 * The signal disposition could have changed since we promoted
	 * this signal from pending to current (we dropped p->p_lock).
	 * This can happen only in a multi-threaded process.
	 */
	if (sigismember(&p->p_ignore, sig) ||
	    (func == SIG_DFL && sigismember(&stopdefault, sig))) {
		lwp->lwp_cursig = 0;
		lwp->lwp_extsig = 0;
		if (lwp->lwp_curinfo) {
			siginfofree(lwp->lwp_curinfo);
			lwp->lwp_curinfo = NULL;
		}
		if (t->t_flag & T_TOMASK) {	/* sigsuspend or pollsys */
			t->t_flag &= ~T_TOMASK;
			t->t_hold = lwp->lwp_sigoldmask;
		}
		mutex_exit(&p->p_lock);
		return;
	}

	/*
	 * We check lwp_curinfo first since pr_setsig can actually
	 * stuff a sigqueue_t there for SIGKILL.
	 */
	if (lwp->lwp_curinfo) {
		sqp = lwp->lwp_curinfo;
	} else if (sig == SIGKILL && p->p_killsqp) {
		sqp = p->p_killsqp;
	}

	if (sqp != NULL) {
		if (SI_FROMUSER(&sqp->sq_info)) {
			pid = sqp->sq_info.si_pid;
			ctid = sqp->sq_info.si_ctid;
			zoneid = sqp->sq_info.si_zoneid;
		}
		/*
		 * If we have a sigqueue_t, its sq_external value
		 * trumps the lwp_extsig value.  It is theoretically
		 * possible to make lwp_extsig reflect reality, but it
		 * would unnecessarily complicate things elsewhere.
		 */
		ext = sqp->sq_external;
	}

	if (func == SIG_DFL) {
		mutex_exit(&p->p_lock);
		DTRACE_PROC3(signal__handle, int, sig, k_siginfo_t *,
		    NULL, void (*)(void), func);
	} else {
		k_siginfo_t *sip = NULL;

		/*
		 * If DTrace user-land tracing is active, give DTrace a
		 * chance to defer the signal until after tracing is
		 * complete.
		 */
		if (t->t_dtrace_on && dtrace_safe_defer_signal()) {
			mutex_exit(&p->p_lock);
			return;
		}

		/*
		 * save siginfo pointer here, in case the
		 * the signal's reset bit is on
		 *
		 * The presence of a current signal prevents paging
		 * from succeeding over a network.  We copy the current
		 * signal information to the side and cancel the current
		 * signal so that sendsig() will succeed.
		 */
		if (sigismember(&p->p_siginfo, sig)) {
			sip = &lwp->lwp_siginfo;
			if (sqp) {
				bcopy(&sqp->sq_info, sip, sizeof (*sip));
				/*
				 * If we were interrupted out of a system call
				 * due to pthread_cancel(), inform libc.
				 */
				if (sig == SIGCANCEL &&
				    sip->si_code == SI_LWP &&
				    t->t_sysnum != 0)
					schedctl_cancel_eintr();
			} else if (sig == SIGPROF && sip->si_signo == SIGPROF &&
			    t->t_rprof != NULL && t->t_rprof->rp_anystate) {
				/* EMPTY */;
			} else {
				bzero(sip, sizeof (*sip));
				sip->si_signo = sig;
				sip->si_code = SI_NOINFO;
			}
		}

		if (t->t_flag & T_TOMASK)
			t->t_flag &= ~T_TOMASK;
		else
			lwp->lwp_sigoldmask = t->t_hold;
		sigorset(&t->t_hold, &PTOU(curproc)->u_sigmask[sig-1]);
		if (!sigismember(&PTOU(curproc)->u_signodefer, sig))
			sigaddset(&t->t_hold, sig);
		if (sigismember(&PTOU(curproc)->u_sigresethand, sig))
			setsigact(sig, SIG_DFL, &nullsmask, 0);

		DTRACE_PROC3(signal__handle, int, sig, k_siginfo_t *,
		    sip, void (*)(void), func);

		if (PROC_IS_BRANDED(p) && BROP(p)->b_psig_to_proc)
			BROP(p)->b_psig_to_proc(p, t, sig);

		lwp->lwp_cursig = 0;
		lwp->lwp_extsig = 0;
		if (lwp->lwp_curinfo) {
			/* p->p_killsqp is freed by freeproc */
			siginfofree(lwp->lwp_curinfo);
			lwp->lwp_curinfo = NULL;
		}
		mutex_exit(&p->p_lock);
		lwp->lwp_ru.nsignals++;

		if (p->p_model == DATAMODEL_NATIVE)
			rc = sendsig(sig, sip, func);
#ifdef _SYSCALL32_IMPL
		else
			rc = sendsig32(sig, sip, func);
#endif	/* _SYSCALL32_IMPL */
		if (rc)
			return;
		sig = lwp->lwp_cursig = SIGSEGV;
		ext = 0;	/* lwp_extsig was set above */
		pid = -1;
		ctid = 0;
	}

	if (sigismember(&coredefault, sig)) {
		/*
		 * Terminate all LWPs but don't discard them.
		 * If another lwp beat us to the punch by calling exit(),
		 * evaporate now.
		 */
		proc_is_exiting(p);
		if (exitlwps(1) != 0) {
			mutex_enter(&p->p_lock);
			lwp_exit();
		}
		/* if we got a SIGKILL from anywhere, no core dump */
		if (p->p_flag & SKILLED) {
			sig = SIGKILL;
			ext = (p->p_flag & SEXTKILLED) != 0;
		} else {
			if (auditing)		/* audit core dump */
				audit_core_start(sig);
			if (core(sig, ext) == 0)
				code = CLD_DUMPED;
			if (auditing)		/* audit core dump */
				audit_core_finish(code);
		}
	}

	/*
	 * Generate a contract event once if the process is killed
	 * by a signal.
	 */
	if (ext) {
		proc_is_exiting(p);
		if (exitlwps(0) != 0) {
			mutex_enter(&p->p_lock);
			lwp_exit();
		}
		contract_process_sig(p->p_ct_process, p, sig, pid, ctid,
		    zoneid);
	}

	exit(code, sig);
}

/*
 * Find next unheld signal in ssp for thread t.
 */
int
fsig(k_sigset_t *ssp, kthread_t *t)
{
	proc_t *p = ttoproc(t);
	user_t *up = PTOU(p);
	int i;
	k_sigset_t temp;

	ASSERT(MUTEX_HELD(&p->p_lock));

	/*
	 * Don't promote any signals for the parent of a vfork()d
	 * child that hasn't yet released the parent's memory.
	 */
	if (p->p_flag & SVFWAIT)
		return (0);

	temp = *ssp;
	sigdiffset(&temp, &t->t_hold);

	/*
	 * Don't promote stopping signals (except SIGSTOP) for a child
	 * of vfork() that hasn't yet released the parent's memory.
	 */
	if (p->p_flag & SVFORK)
		sigdiffset(&temp, &holdvfork);

	/*
	 * Don't promote a signal that will stop
	 * the process when lwp_nostop is set.
	 */
	if (ttolwp(t)->lwp_nostop) {
		sigdelset(&temp, SIGSTOP);
		if (!p->p_pgidp->pid_pgorphaned) {
			if (up->u_signal[SIGTSTP-1] == SIG_DFL)
				sigdelset(&temp, SIGTSTP);
			if (up->u_signal[SIGTTIN-1] == SIG_DFL)
				sigdelset(&temp, SIGTTIN);
			if (up->u_signal[SIGTTOU-1] == SIG_DFL)
				sigdelset(&temp, SIGTTOU);
		}
	}

	/*
	 * Choose SIGKILL and SIGPROF before all other pending signals.
	 * The rest are promoted in signal number order.
	 */
	if (sigismember(&temp, SIGKILL))
		return (SIGKILL);
	if (sigismember(&temp, SIGPROF))
		return (SIGPROF);

	for (i = 0; i < sizeof (temp) / sizeof (temp.__sigbits[0]); i++) {
		if (temp.__sigbits[i])
			return ((i * NBBY * sizeof (temp.__sigbits[0])) +
			    lowbit(temp.__sigbits[i]));
	}

	return (0);
}

void
setsigact(int sig, void (*disp)(), const k_sigset_t *mask, int flags)
{
	proc_t *p = ttoproc(curthread);
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));

	PTOU(curproc)->u_signal[sig - 1] = disp;

	/*
	 * Honor the SA_SIGINFO flag if the signal is being caught.
	 * Force the SA_SIGINFO flag if the signal is not being caught.
	 * This is necessary to make sigqueue() and sigwaitinfo() work
	 * properly together when the signal is set to default or is
	 * being temporarily ignored.
	 */
	if ((flags & SA_SIGINFO) || disp == SIG_DFL || disp == SIG_IGN)
		sigaddset(&p->p_siginfo, sig);
	else
		sigdelset(&p->p_siginfo, sig);

	if (disp != SIG_DFL && disp != SIG_IGN) {
		sigdelset(&p->p_ignore, sig);
		PTOU(curproc)->u_sigmask[sig - 1] = *mask;
		if (!sigismember(&cantreset, sig)) {
			if (flags & SA_RESETHAND)
				sigaddset(&PTOU(curproc)->u_sigresethand, sig);
			else
				sigdelset(&PTOU(curproc)->u_sigresethand, sig);
		}
		if (flags & SA_NODEFER)
			sigaddset(&PTOU(curproc)->u_signodefer, sig);
		else
			sigdelset(&PTOU(curproc)->u_signodefer, sig);
		if (flags & SA_RESTART)
			sigaddset(&PTOU(curproc)->u_sigrestart, sig);
		else
			sigdelset(&PTOU(curproc)->u_sigrestart, sig);
		if (flags & SA_ONSTACK)
			sigaddset(&PTOU(curproc)->u_sigonstack, sig);
		else
			sigdelset(&PTOU(curproc)->u_sigonstack, sig);
	} else if (disp == SIG_IGN ||
	    (disp == SIG_DFL && sigismember(&ignoredefault, sig))) {
		/*
		 * Setting the signal action to SIG_IGN results in the
		 * discarding of all pending signals of that signal number.
		 * Setting the signal action to SIG_DFL does the same *only*
		 * if the signal's default behavior is to be ignored.
		 */
		sigaddset(&p->p_ignore, sig);
		sigdelset(&p->p_sig, sig);
		sigdelset(&p->p_extsig, sig);
		sigdelq(p, NULL, sig);
		t = p->p_tlist;
		do {
			sigdelset(&t->t_sig, sig);
			sigdelset(&t->t_extsig, sig);
			sigdelq(p, t, sig);
		} while ((t = t->t_forw) != p->p_tlist);
	} else {
		/*
		 * The signal action is being set to SIG_DFL and the default
		 * behavior is to do something: make sure it is not ignored.
		 */
		sigdelset(&p->p_ignore, sig);
	}

	if (sig == SIGCLD) {
		if (flags & SA_NOCLDWAIT)
			p->p_flag |= SNOWAIT;
		else
			p->p_flag &= ~SNOWAIT;

		if (flags & SA_NOCLDSTOP)
			p->p_flag &= ~SJCTL;
		else
			p->p_flag |= SJCTL;

		if ((p->p_flag & SNOWAIT) || disp == SIG_IGN) {
			proc_t *cp, *tp;

			mutex_exit(&p->p_lock);
			mutex_enter(&pidlock);
			for (cp = p->p_child; cp != NULL; cp = tp) {
				tp = cp->p_sibling;
				if (cp->p_stat == SZOMB &&
				    !(cp->p_pidflag & CLDWAITPID))
					freeproc(cp);
			}
			mutex_exit(&pidlock);
			mutex_enter(&p->p_lock);
		}
	}
}

/*
 * Set all signal actions not already set to SIG_DFL or SIG_IGN to SIG_DFL.
 * Called from exec_common() for a process undergoing execve()
 * and from cfork() for a newly-created child of vfork().
 * In the vfork() case, 'p' is not the current process.
 * In both cases, there is only one thread in the process.
 */
void
sigdefault(proc_t *p)
{
	kthread_t *t = p->p_tlist;
	struct user *up = PTOU(p);
	int sig;

	ASSERT(MUTEX_HELD(&p->p_lock));

	for (sig = 1; sig < NSIG; sig++) {
		if (up->u_signal[sig - 1] != SIG_DFL &&
		    up->u_signal[sig - 1] != SIG_IGN) {
			up->u_signal[sig - 1] = SIG_DFL;
			sigemptyset(&up->u_sigmask[sig - 1]);
			if (sigismember(&ignoredefault, sig)) {
				sigdelq(p, NULL, sig);
				sigdelq(p, t, sig);
			}
			if (sig == SIGCLD)
				p->p_flag &= ~(SNOWAIT|SJCTL);
		}
	}
	sigorset(&p->p_ignore, &ignoredefault);
	sigfillset(&p->p_siginfo);
	sigdiffset(&p->p_siginfo, &cantmask);
	sigdiffset(&p->p_sig, &ignoredefault);
	sigdiffset(&p->p_extsig, &ignoredefault);
	sigdiffset(&t->t_sig, &ignoredefault);
	sigdiffset(&t->t_extsig, &ignoredefault);
}

void
sigcld(proc_t *cp, sigqueue_t *sqp)
{
	proc_t *pp = cp->p_parent;

	ASSERT(MUTEX_HELD(&pidlock));

	switch (cp->p_wcode) {
	case CLD_EXITED:
	case CLD_DUMPED:
	case CLD_KILLED:
		ASSERT(cp->p_stat == SZOMB);
		/*
		 * The broadcast on p_srwchan_cv is a kludge to
		 * wakeup a possible thread in uadmin(A_SHUTDOWN).
		 */
		cv_broadcast(&cp->p_srwchan_cv);

		/*
		 * Add to newstate list of the parent
		 */
		add_ns(pp, cp);

		cv_broadcast(&pp->p_cv);
		if ((pp->p_flag & SNOWAIT) ||
		    PTOU(pp)->u_signal[SIGCLD - 1] == SIG_IGN) {
			if (!(cp->p_pidflag & CLDWAITPID))
				freeproc(cp);
		} else if (!(cp->p_pidflag & CLDNOSIGCHLD)) {
			post_sigcld(cp, sqp);
			sqp = NULL;
		}
		break;

	case CLD_STOPPED:
	case CLD_CONTINUED:
		cv_broadcast(&pp->p_cv);
		if (pp->p_flag & SJCTL) {
			post_sigcld(cp, sqp);
			sqp = NULL;
		}
		break;
	}

	if (sqp)
		siginfofree(sqp);
}

/*
 * Common code called from sigcld() and from
 * waitid() and issig_forreal() via sigcld_repost().
 * Give the parent process a SIGCLD if it does not have one pending,
 * else mark the child process so a SIGCLD can be posted later.
 */
static void
post_sigcld(proc_t *cp, sigqueue_t *sqp)
{
	proc_t *pp = cp->p_parent;
	k_siginfo_t info;

	ASSERT(MUTEX_HELD(&pidlock));
	mutex_enter(&pp->p_lock);

	/*
	 * If a SIGCLD is pending, then just mark the child process
	 * so that its SIGCLD will be posted later, when the first
	 * SIGCLD is taken off the queue or when the parent is ready
	 * to receive it or accept it, if ever.
	 */
	if (sigismember(&pp->p_sig, SIGCLD)) {
		cp->p_pidflag |= CLDPEND;
	} else {
		cp->p_pidflag &= ~CLDPEND;
		if (sqp == NULL) {
			/*
			 * This can only happen when the parent is init.
			 * (See call to sigcld(q, NULL) in exit().)
			 * Use KM_NOSLEEP to avoid deadlock. The child procs
			 * initpid can be 1 for zlogin.
			 */
			ASSERT(pp->p_pidp->pid_id ==
			    cp->p_zone->zone_proc_initpid ||
			    pp->p_pidp->pid_id == 1);
			winfo(cp, &info, 0);
			sigaddq(pp, NULL, &info, KM_NOSLEEP);
		} else {
			winfo(cp, &sqp->sq_info, 0);
			sigaddqa(pp, NULL, sqp);
			sqp = NULL;
		}
	}

	mutex_exit(&pp->p_lock);

	if (sqp)
		siginfofree(sqp);
}

/*
 * Search for a child that has a pending SIGCLD for us, the parent.
 * The queue of SIGCLD signals is implied by the list of children.
 * We post the SIGCLD signals one at a time so they don't get lost.
 * When one is dequeued, another is enqueued, until there are no more.
 */
void
sigcld_repost()
{
	proc_t *pp = curproc;
	proc_t *cp;
	sigqueue_t *sqp;

	sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
	mutex_enter(&pidlock);
	for (cp = pp->p_child; cp; cp = cp->p_sibling) {
		if (cp->p_pidflag & CLDPEND) {
			post_sigcld(cp, sqp);
			mutex_exit(&pidlock);
			return;
		}
	}
	mutex_exit(&pidlock);
	kmem_free(sqp, sizeof (sigqueue_t));
}

/*
 * count number of sigqueue send by sigaddqa()
 */
void
sigqsend(int cmd, proc_t *p, kthread_t *t, sigqueue_t *sigqp)
{
	sigqhdr_t *sqh;

	sqh = (sigqhdr_t *)sigqp->sq_backptr;
	ASSERT(sqh);

	mutex_enter(&sqh->sqb_lock);
	sqh->sqb_sent++;
	mutex_exit(&sqh->sqb_lock);

	if (cmd == SN_SEND)
		sigaddqa(p, t, sigqp);
	else
		siginfofree(sigqp);
}

int
sigsendproc(proc_t *p, sigsend_t *pv)
{
	struct cred *cr;
	proc_t *myprocp = curproc;

	ASSERT(MUTEX_HELD(&pidlock));

	if (p->p_pid == 1 && pv->sig && sigismember(&cantmask, pv->sig))
		return (EPERM);

	cr = CRED();

	if (pv->checkperm == 0 ||
	    (pv->sig == SIGCONT && p->p_sessp == myprocp->p_sessp) ||
	    prochasprocperm(p, myprocp, cr)) {
		pv->perm++;
		if (pv->sig) {
			/* Make sure we should be setting si_pid and friends */
			ASSERT(pv->sicode <= 0);
			if (SI_CANQUEUE(pv->sicode)) {
				sigqueue_t *sqp;

				mutex_enter(&myprocp->p_lock);
				sqp = sigqalloc(myprocp->p_sigqhdr);
				mutex_exit(&myprocp->p_lock);
				if (sqp == NULL)
					return (EAGAIN);
				sqp->sq_info.si_signo = pv->sig;
				sqp->sq_info.si_code = pv->sicode;
				sqp->sq_info.si_pid = myprocp->p_pid;
				sqp->sq_info.si_ctid = PRCTID(myprocp);
				sqp->sq_info.si_zoneid = getzoneid();
				sqp->sq_info.si_uid = crgetruid(cr);
				sqp->sq_info.si_value = pv->value;
				mutex_enter(&p->p_lock);
				sigqsend(SN_SEND, p, NULL, sqp);
				mutex_exit(&p->p_lock);
			} else {
				k_siginfo_t info;
				bzero(&info, sizeof (info));
				info.si_signo = pv->sig;
				info.si_code = pv->sicode;
				info.si_pid = myprocp->p_pid;
				info.si_ctid = PRCTID(myprocp);
				info.si_zoneid = getzoneid();
				info.si_uid = crgetruid(cr);
				mutex_enter(&p->p_lock);
				/*
				 * XXX: Should be KM_SLEEP but
				 * we have to avoid deadlock.
				 */
				sigaddq(p, NULL, &info, KM_NOSLEEP);
				mutex_exit(&p->p_lock);
			}
		}
	}

	return (0);
}

int
sigsendset(procset_t *psp, sigsend_t *pv)
{
	int error;

	error = dotoprocs(psp, sigsendproc, (char *)pv);
	if (error == 0 && pv->perm == 0)
		return (EPERM);

	return (error);
}

/*
 * Dequeue a queued siginfo structure.
 * If a non-null thread pointer is passed then dequeue from
 * the thread queue, otherwise dequeue from the process queue.
 */
void
sigdeq(proc_t *p, kthread_t *t, int sig, sigqueue_t **qpp)
{
	sigqueue_t **psqp, *sqp;

	ASSERT(MUTEX_HELD(&p->p_lock));

	*qpp = NULL;

	if (t != NULL) {
		sigdelset(&t->t_sig, sig);
		sigdelset(&t->t_extsig, sig);
		psqp = &t->t_sigqueue;
	} else {
		sigdelset(&p->p_sig, sig);
		sigdelset(&p->p_extsig, sig);
		psqp = &p->p_sigqueue;
	}

	for (;;) {
		if ((sqp = *psqp) == NULL)
			return;
		if (sqp->sq_info.si_signo == sig)
			break;
		else
			psqp = &sqp->sq_next;
	}
	*qpp = sqp;
	*psqp = sqp->sq_next;
	for (sqp = *psqp; sqp; sqp = sqp->sq_next) {
		if (sqp->sq_info.si_signo == sig) {
			if (t != (kthread_t *)NULL) {
				sigaddset(&t->t_sig, sig);
				t->t_sig_check = 1;
			} else {
				sigaddset(&p->p_sig, sig);
				set_proc_ast(p);
			}
			break;
		}
	}
}

/*
 * Delete a queued SIGCLD siginfo structure matching the k_siginfo_t argument.
 */
void
sigcld_delete(k_siginfo_t *ip)
{
	proc_t *p = curproc;
	int another_sigcld = 0;
	sigqueue_t **psqp, *sqp;

	ASSERT(ip->si_signo == SIGCLD);

	mutex_enter(&p->p_lock);

	if (!sigismember(&p->p_sig, SIGCLD)) {
		mutex_exit(&p->p_lock);
		return;
	}

	psqp = &p->p_sigqueue;
	for (;;) {
		if ((sqp = *psqp) == NULL) {
			mutex_exit(&p->p_lock);
			return;
		}
		if (sqp->sq_info.si_signo == SIGCLD) {
			if (sqp->sq_info.si_pid == ip->si_pid &&
			    sqp->sq_info.si_code == ip->si_code &&
			    sqp->sq_info.si_status == ip->si_status)
				break;
			another_sigcld = 1;
		}
		psqp = &sqp->sq_next;
	}
	*psqp = sqp->sq_next;

	siginfofree(sqp);

	for (sqp = *psqp; !another_sigcld && sqp; sqp = sqp->sq_next) {
		if (sqp->sq_info.si_signo == SIGCLD)
			another_sigcld = 1;
	}

	if (!another_sigcld) {
		sigdelset(&p->p_sig, SIGCLD);
		sigdelset(&p->p_extsig, SIGCLD);
	}

	mutex_exit(&p->p_lock);
}

/*
 * Delete queued siginfo structures.
 * If a non-null thread pointer is passed then delete from
 * the thread queue, otherwise delete from the process queue.
 */
void
sigdelq(proc_t *p, kthread_t *t, int sig)
{
	sigqueue_t **psqp, *sqp;

	/*
	 * We must be holding p->p_lock unless the process is
	 * being reaped or has failed to get started on fork.
	 */
	ASSERT(MUTEX_HELD(&p->p_lock) ||
	    p->p_stat == SIDL || p->p_stat == SZOMB);

	if (t != (kthread_t *)NULL)
		psqp = &t->t_sigqueue;
	else
		psqp = &p->p_sigqueue;

	while (*psqp) {
		sqp = *psqp;
		if (sig == 0 || sqp->sq_info.si_signo == sig) {
			*psqp = sqp->sq_next;
			siginfofree(sqp);
		} else
			psqp = &sqp->sq_next;
	}
}

/*
 * Insert a siginfo structure into a queue.
 * If a non-null thread pointer is passed then add to the thread queue,
 * otherwise add to the process queue.
 *
 * The function sigaddqins() is called with sigqueue already allocated.
 * It is called from sigaddqa() and sigaddq() below.
 *
 * The value of si_code implicitly indicates whether sigp is to be
 * explicitly queued, or to be queued to depth one.
 */
static void
sigaddqins(proc_t *p, kthread_t *t, sigqueue_t *sigqp)
{
	sigqueue_t **psqp;
	int sig = sigqp->sq_info.si_signo;

	sigqp->sq_external = (curproc != &p0) &&
	    (curproc->p_ct_process != p->p_ct_process);

	/*
	 * issig_forreal() doesn't bother dequeueing signals if SKILLED
	 * is set, and even if it did, we would want to avoid situation
	 * (which would be unique to SIGKILL) where one thread dequeued
	 * the sigqueue_t and another executed psig().  So we create a
	 * separate stash for SIGKILL's sigqueue_t.  Because a second
	 * SIGKILL can set SEXTKILLED, we overwrite the existing entry
	 * if (and only if) it was non-extracontractual.
	 */
	if (sig == SIGKILL) {
		if (p->p_killsqp == NULL || !p->p_killsqp->sq_external) {
			if (p->p_killsqp != NULL)
				siginfofree(p->p_killsqp);
			p->p_killsqp = sigqp;
			sigqp->sq_next = NULL;
		} else {
			siginfofree(sigqp);
		}
		return;
	}

	ASSERT(sig >= 1 && sig < NSIG);
	if (t != NULL)	/* directed to a thread */
		psqp = &t->t_sigqueue;
	else 		/* directed to a process */
		psqp = &p->p_sigqueue;
	if (SI_CANQUEUE(sigqp->sq_info.si_code) &&
	    sigismember(&p->p_siginfo, sig)) {
		for (; *psqp != NULL; psqp = &(*psqp)->sq_next)
				;
	} else {
		for (; *psqp != NULL; psqp = &(*psqp)->sq_next) {
			if ((*psqp)->sq_info.si_signo == sig) {
				siginfofree(sigqp);
				return;
			}
		}
	}
	*psqp = sigqp;
	sigqp->sq_next = NULL;
}

/*
 * The function sigaddqa() is called with sigqueue already allocated.
 * If signal is ignored, discard but guarantee KILL and generation semantics.
 * It is called from sigqueue() and other places.
 */
void
sigaddqa(proc_t *p, kthread_t *t, sigqueue_t *sigqp)
{
	int sig = sigqp->sq_info.si_signo;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(sig >= 1 && sig < NSIG);

	if (sig_discardable(p, sig))
		siginfofree(sigqp);
	else
		sigaddqins(p, t, sigqp);

	sigtoproc(p, t, sig);
}

/*
 * Allocate the sigqueue_t structure and call sigaddqins().
 */
void
sigaddq(proc_t *p, kthread_t *t, k_siginfo_t *infop, int km_flags)
{
	sigqueue_t *sqp;
	int sig = infop->si_signo;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(sig >= 1 && sig < NSIG);

	/*
	 * If the signal will be discarded by sigtoproc() or
	 * if the process isn't requesting siginfo and it isn't
	 * blocking the signal (it *could* change it's mind while
	 * the signal is pending) then don't bother creating one.
	 */
	if (!sig_discardable(p, sig) &&
	    (sigismember(&p->p_siginfo, sig) ||
	    (curproc->p_ct_process != p->p_ct_process) ||
	    (sig == SIGCLD && SI_FROMKERNEL(infop))) &&
	    ((sqp = kmem_alloc(sizeof (sigqueue_t), km_flags)) != NULL)) {
		bcopy(infop, &sqp->sq_info, sizeof (k_siginfo_t));
		sqp->sq_func = NULL;
		sqp->sq_next = NULL;
		sigaddqins(p, t, sqp);
	}
	sigtoproc(p, t, sig);
}

/*
 * Handle stop-on-fault processing for the debugger.  Returns 0
 * if the fault is cleared during the stop, nonzero if it isn't.
 */
int
stop_on_fault(uint_t fault, k_siginfo_t *sip)
{
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);

	ASSERT(prismember(&p->p_fltmask, fault));

	/*
	 * Record current fault and siginfo structure so debugger can
	 * find it.
	 */
	mutex_enter(&p->p_lock);
	lwp->lwp_curflt = (uchar_t)fault;
	lwp->lwp_siginfo = *sip;

	stop(PR_FAULTED, fault);

	fault = lwp->lwp_curflt;
	lwp->lwp_curflt = 0;
	mutex_exit(&p->p_lock);
	return (fault);
}

void
sigorset(k_sigset_t *s1, const k_sigset_t *s2)
{
	s1->__sigbits[0] |= s2->__sigbits[0];
	s1->__sigbits[1] |= s2->__sigbits[1];
	s1->__sigbits[2] |= s2->__sigbits[2];
}

void
sigandset(k_sigset_t *s1, const k_sigset_t *s2)
{
	s1->__sigbits[0] &= s2->__sigbits[0];
	s1->__sigbits[1] &= s2->__sigbits[1];
	s1->__sigbits[2] &= s2->__sigbits[2];
}

void
sigdiffset(k_sigset_t *s1, const k_sigset_t *s2)
{
	s1->__sigbits[0] &= ~(s2->__sigbits[0]);
	s1->__sigbits[1] &= ~(s2->__sigbits[1]);
	s1->__sigbits[2] &= ~(s2->__sigbits[2]);
}

/*
 * Return non-zero if curthread->t_sig_check should be set to 1, that is,
 * if there are any signals the thread might take on return from the kernel.
 * If ksigset_t's were a single word, we would do:
 *	return (((p->p_sig | t->t_sig) & ~t->t_hold) & fillset);
 */
int
sigcheck(proc_t *p, kthread_t *t)
{
	sc_shared_t *tdp = t->t_schedctl;

	/*
	 * If signals are blocked via the schedctl interface
	 * then we only check for the unmaskable signals.
	 * The unmaskable signal numbers should all be contained
	 * in __sigbits[0] and we assume this for speed.
	 */
#if (CANTMASK1 == 0 && CANTMASK2 == 0)
	if (tdp != NULL && tdp->sc_sigblock)
		return ((p->p_sig.__sigbits[0] | t->t_sig.__sigbits[0]) &
		    CANTMASK0);
#else
#error "fix me: CANTMASK1 and CANTMASK2 are not zero"
#endif

/* see uts/common/sys/signal.h for why this must be true */
#if ((MAXSIG > (2 * 32)) && (MAXSIG <= (3 * 32)))
	return (((p->p_sig.__sigbits[0] | t->t_sig.__sigbits[0]) &
	    ~t->t_hold.__sigbits[0]) |
	    ((p->p_sig.__sigbits[1] | t->t_sig.__sigbits[1]) &
	    ~t->t_hold.__sigbits[1]) |
	    (((p->p_sig.__sigbits[2] | t->t_sig.__sigbits[2]) &
	    ~t->t_hold.__sigbits[2]) & FILLSET2));
#else
#error "fix me: MAXSIG out of bounds"
#endif
}

void
sigintr(k_sigset_t *smask, int intable)
{
	proc_t *p;
	int owned;
	k_sigset_t lmask;		/* local copy of cantmask */
	klwp_t *lwp = ttolwp(curthread);

	/*
	 * Mask out all signals except SIGHUP, SIGINT, SIGQUIT
	 *    and SIGTERM. (Preserving the existing masks).
	 *    This function supports the -intr nfs and ufs mount option.
	 */

	/*
	 * don't do kernel threads
	 */
	if (lwp == NULL)
		return;

	/*
	 * get access to signal mask
	 */
	p = ttoproc(curthread);
	owned = mutex_owned(&p->p_lock);	/* this is filthy */
	if (!owned)
		mutex_enter(&p->p_lock);

	/*
	 * remember the current mask
	 */
	schedctl_finish_sigblock(curthread);
	*smask = curthread->t_hold;

	/*
	 * mask out all signals
	 */
	sigfillset(&curthread->t_hold);

	/*
	 * Unmask the non-maskable signals (e.g., KILL), as long as
	 * they aren't already masked (which could happen at exit).
	 * The first sigdiffset sets lmask to (cantmask & ~curhold).  The
	 * second sets the current hold mask to (~0 & ~lmask), which reduces
	 * to (~cantmask | curhold).
	 */
	lmask = cantmask;
	sigdiffset(&lmask, smask);
	sigdiffset(&curthread->t_hold, &lmask);

	/*
	 * Re-enable HUP, QUIT, and TERM iff they were originally enabled
	 * Re-enable INT if it's originally enabled and the NFS mount option
	 * nointr is not set.
	 */
	if (!sigismember(smask, SIGHUP))
		sigdelset(&curthread->t_hold, SIGHUP);
	if (!sigismember(smask, SIGINT) && intable)
		sigdelset(&curthread->t_hold, SIGINT);
	if (!sigismember(smask, SIGQUIT))
		sigdelset(&curthread->t_hold, SIGQUIT);
	if (!sigismember(smask, SIGTERM))
		sigdelset(&curthread->t_hold, SIGTERM);

	/*
	 * release access to signal mask
	 */
	if (!owned)
		mutex_exit(&p->p_lock);

	/*
	 * Indicate that this lwp is not to be stopped.
	 */
	lwp->lwp_nostop++;

}

void
sigunintr(k_sigset_t *smask)
{
	proc_t *p;
	int owned;
	klwp_t *lwp = ttolwp(curthread);

	/*
	 * Reset previous mask (See sigintr() above)
	 */
	if (lwp != NULL) {
		lwp->lwp_nostop--;	/* restore lwp stoppability */
		p = ttoproc(curthread);
		owned = mutex_owned(&p->p_lock);	/* this is filthy */
		if (!owned)
			mutex_enter(&p->p_lock);
		curthread->t_hold = *smask;
		/* so unmasked signals will be seen */
		curthread->t_sig_check = 1;
		if (!owned)
			mutex_exit(&p->p_lock);
	}
}

void
sigreplace(k_sigset_t *newmask, k_sigset_t *oldmask)
{
	proc_t	*p;
	int owned;
	/*
	 * Save current signal mask in oldmask, then
	 * set it to newmask.
	 */
	if (ttolwp(curthread) != NULL) {
		p = ttoproc(curthread);
		owned = mutex_owned(&p->p_lock);	/* this is filthy */
		if (!owned)
			mutex_enter(&p->p_lock);
		schedctl_finish_sigblock(curthread);
		if (oldmask != NULL)
			*oldmask = curthread->t_hold;
		curthread->t_hold = *newmask;
		curthread->t_sig_check = 1;
		if (!owned)
			mutex_exit(&p->p_lock);
	}
}

/*
 * Return true if the signal number is in range
 * and the signal code specifies signal queueing.
 */
int
sigwillqueue(int sig, int code)
{
	if (sig >= 0 && sig < NSIG) {
		switch (code) {
		case SI_QUEUE:
		case SI_TIMER:
		case SI_ASYNCIO:
		case SI_MESGQ:
			return (1);
		}
	}
	return (0);
}

/*
 * The pre-allocated pool (with _SIGQUEUE_PREALLOC entries) is
 * allocated at the first sigqueue/signotify call.
 */
sigqhdr_t *
sigqhdralloc(size_t size, uint_t maxcount)
{
	size_t i;
	sigqueue_t *sq, *next;
	sigqhdr_t *sqh;

	/*
	 * Before the introduction of process.max-sigqueue-size
	 * _SC_SIGQUEUE_MAX had this static value.
	 */
#define	_SIGQUEUE_PREALLOC	32

	i = (_SIGQUEUE_PREALLOC * size) + sizeof (sigqhdr_t);
	ASSERT(maxcount <= INT_MAX);
	sqh = kmem_alloc(i, KM_SLEEP);
	sqh->sqb_count = maxcount;
	sqh->sqb_maxcount = maxcount;
	sqh->sqb_size = i;
	sqh->sqb_pexited = 0;
	sqh->sqb_sent = 0;
	sqh->sqb_free = sq = (sigqueue_t *)(sqh + 1);
	for (i = _SIGQUEUE_PREALLOC - 1; i != 0; i--) {
		next = (sigqueue_t *)((uintptr_t)sq + size);
		sq->sq_next = next;
		sq = next;
	}
	sq->sq_next = NULL;
	cv_init(&sqh->sqb_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&sqh->sqb_lock, NULL, MUTEX_DEFAULT, NULL);
	return (sqh);
}

static void sigqrel(sigqueue_t *);

/*
 * Allocate a sigqueue/signotify structure from the per process
 * pre-allocated pool or allocate a new sigqueue/signotify structure
 * if the pre-allocated pool is exhausted.
 */
sigqueue_t *
sigqalloc(sigqhdr_t *sqh)
{
	sigqueue_t *sq = NULL;

	ASSERT(MUTEX_HELD(&curproc->p_lock));

	if (sqh != NULL) {
		mutex_enter(&sqh->sqb_lock);
		if (sqh->sqb_count > 0) {
			sqh->sqb_count--;
			if (sqh->sqb_free == NULL) {
				/*
				 * The pre-allocated pool is exhausted.
				 */
				sq = kmem_alloc(sizeof (sigqueue_t), KM_SLEEP);
				sq->sq_func = NULL;
			} else {
				sq = sqh->sqb_free;
				sq->sq_func = sigqrel;
				sqh->sqb_free = sq->sq_next;
			}
			mutex_exit(&sqh->sqb_lock);
			bzero(&sq->sq_info, sizeof (k_siginfo_t));
			sq->sq_backptr = sqh;
			sq->sq_next = NULL;
			sq->sq_external = 0;
		} else {
			mutex_exit(&sqh->sqb_lock);
		}
	}
	return (sq);
}

/*
 * Return a sigqueue structure back to the pre-allocated pool.
 */
static void
sigqrel(sigqueue_t *sq)
{
	sigqhdr_t *sqh;

	/* make sure that p_lock of the affected process is held */

	sqh = (sigqhdr_t *)sq->sq_backptr;
	mutex_enter(&sqh->sqb_lock);
	if (sqh->sqb_pexited && sqh->sqb_sent == 1) {
		mutex_exit(&sqh->sqb_lock);
		cv_destroy(&sqh->sqb_cv);
		mutex_destroy(&sqh->sqb_lock);
		kmem_free(sqh, sqh->sqb_size);
	} else {
		sqh->sqb_count++;
		sqh->sqb_sent--;
		sq->sq_next = sqh->sqb_free;
		sq->sq_backptr = NULL;
		sqh->sqb_free = sq;
		cv_signal(&sqh->sqb_cv);
		mutex_exit(&sqh->sqb_lock);
	}
}

/*
 * Free up the pre-allocated sigqueue headers of sigqueue pool
 * and signotify pool, if possible.
 * Called only by the owning process during exec() and exit().
 */
void
sigqfree(proc_t *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));

	if (p->p_sigqhdr != NULL) {	/* sigqueue pool */
		sigqhdrfree(p->p_sigqhdr);
		p->p_sigqhdr = NULL;
	}
	if (p->p_signhdr != NULL) {	/* signotify pool */
		sigqhdrfree(p->p_signhdr);
		p->p_signhdr = NULL;
	}
}

/*
 * Free up the pre-allocated header and sigq pool if possible.
 */
void
sigqhdrfree(sigqhdr_t *sqh)
{
	mutex_enter(&sqh->sqb_lock);
	if (sqh->sqb_sent == 0) {
		mutex_exit(&sqh->sqb_lock);
		cv_destroy(&sqh->sqb_cv);
		mutex_destroy(&sqh->sqb_lock);
		kmem_free(sqh, sqh->sqb_size);
	} else {
		sqh->sqb_pexited = 1;
		mutex_exit(&sqh->sqb_lock);
	}
}

/*
 * Free up a single sigqueue structure.
 * No other code should free a sigqueue directly.
 */
void
siginfofree(sigqueue_t *sqp)
{
	if (sqp != NULL) {
		if (sqp->sq_func != NULL)
			(sqp->sq_func)(sqp);
		else
			kmem_free(sqp, sizeof (sigqueue_t));
	}
}

/*
 * Generate a synchronous signal caused by a hardware
 * condition encountered by an lwp.  Called from trap().
 */
void
trapsig(k_siginfo_t *ip, int restartable)
{
	proc_t *p = ttoproc(curthread);
	int sig = ip->si_signo;
	sigqueue_t *sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);

	ASSERT(sig > 0 && sig < NSIG);

	if (curthread->t_dtrace_on)
		dtrace_safe_synchronous_signal();

	mutex_enter(&p->p_lock);
	schedctl_finish_sigblock(curthread);
	/*
	 * Avoid a possible infinite loop if the lwp is holding the
	 * signal generated by a trap of a restartable instruction or
	 * if the signal so generated is being ignored by the process.
	 */
	if (restartable &&
	    (sigismember(&curthread->t_hold, sig) ||
	    p->p_user.u_signal[sig-1] == SIG_IGN)) {
		sigdelset(&curthread->t_hold, sig);
		p->p_user.u_signal[sig-1] = SIG_DFL;
		sigdelset(&p->p_ignore, sig);
	}
	bcopy(ip, &sqp->sq_info, sizeof (k_siginfo_t));
	sigaddqa(p, curthread, sqp);
	mutex_exit(&p->p_lock);
}

/*
 * Dispatch the real time profiling signal in the traditional way,
 * honoring all of the /proc tracing mechanism built into issig().
 */
static void
realsigprof_slow(int sysnum, int nsysarg, int error)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	k_siginfo_t *sip = &lwp->lwp_siginfo;
	void (*func)();

	mutex_enter(&p->p_lock);
	func = PTOU(p)->u_signal[SIGPROF - 1];
	if (p->p_rprof_cyclic == CYCLIC_NONE ||
	    func == SIG_DFL || func == SIG_IGN) {
		bzero(t->t_rprof, sizeof (*t->t_rprof));
		mutex_exit(&p->p_lock);
		return;
	}
	if (sigismember(&t->t_hold, SIGPROF)) {
		mutex_exit(&p->p_lock);
		return;
	}
	sip->si_signo = SIGPROF;
	sip->si_code = PROF_SIG;
	sip->si_errno = error;
	hrt2ts(gethrtime(), &sip->si_tstamp);
	sip->si_syscall = sysnum;
	sip->si_nsysarg = nsysarg;
	sip->si_fault = lwp->lwp_lastfault;
	sip->si_faddr = lwp->lwp_lastfaddr;
	lwp->lwp_lastfault = 0;
	lwp->lwp_lastfaddr = NULL;
	sigtoproc(p, t, SIGPROF);
	mutex_exit(&p->p_lock);
	ASSERT(lwp->lwp_cursig == 0);
	if (issig(FORREAL))
		psig();
	sip->si_signo = 0;
	bzero(t->t_rprof, sizeof (*t->t_rprof));
}

/*
 * We are not tracing the SIGPROF signal, or doing any other unnatural
 * acts, like watchpoints, so dispatch the real time profiling signal
 * directly, bypassing all of the overhead built into issig().
 */
static void
realsigprof_fast(int sysnum, int nsysarg, int error)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	k_siginfo_t *sip = &lwp->lwp_siginfo;
	void (*func)();
	int rc;
	int code;

	/*
	 * We don't need to acquire p->p_lock here;
	 * we are manipulating thread-private data.
	 */
	func = PTOU(p)->u_signal[SIGPROF - 1];
	if (p->p_rprof_cyclic == CYCLIC_NONE ||
	    func == SIG_DFL || func == SIG_IGN) {
		bzero(t->t_rprof, sizeof (*t->t_rprof));
		return;
	}
	if (lwp->lwp_cursig != 0 ||
	    lwp->lwp_curinfo != NULL ||
	    sigismember(&t->t_hold, SIGPROF)) {
		return;
	}
	sip->si_signo = SIGPROF;
	sip->si_code = PROF_SIG;
	sip->si_errno = error;
	hrt2ts(gethrtime(), &sip->si_tstamp);
	sip->si_syscall = sysnum;
	sip->si_nsysarg = nsysarg;
	sip->si_fault = lwp->lwp_lastfault;
	sip->si_faddr = lwp->lwp_lastfaddr;
	lwp->lwp_lastfault = 0;
	lwp->lwp_lastfaddr = NULL;
	if (t->t_flag & T_TOMASK)
		t->t_flag &= ~T_TOMASK;
	else
		lwp->lwp_sigoldmask = t->t_hold;
	sigorset(&t->t_hold, &PTOU(p)->u_sigmask[SIGPROF - 1]);
	if (!sigismember(&PTOU(p)->u_signodefer, SIGPROF))
		sigaddset(&t->t_hold, SIGPROF);
	lwp->lwp_extsig = 0;
	lwp->lwp_ru.nsignals++;
	if (p->p_model == DATAMODEL_NATIVE)
		rc = sendsig(SIGPROF, sip, func);
#ifdef _SYSCALL32_IMPL
	else
		rc = sendsig32(SIGPROF, sip, func);
#endif	/* _SYSCALL32_IMPL */
	sip->si_signo = 0;
	bzero(t->t_rprof, sizeof (*t->t_rprof));
	if (rc == 0) {
		/*
		 * sendsig() failed; we must dump core with a SIGSEGV.
		 * See psig().  This code is copied from there.
		 */
		lwp->lwp_cursig = SIGSEGV;
		code = CLD_KILLED;
		proc_is_exiting(p);
		if (exitlwps(1) != 0) {
			mutex_enter(&p->p_lock);
			lwp_exit();
		}
		if (audit_active == C2AUDIT_LOADED)
			audit_core_start(SIGSEGV);
		if (core(SIGSEGV, 0) == 0)
			code = CLD_DUMPED;
		if (audit_active == C2AUDIT_LOADED)
			audit_core_finish(code);
		exit(code, SIGSEGV);
	}
}

/*
 * Arrange for the real time profiling signal to be dispatched.
 */
void
realsigprof(int sysnum, int nsysarg, int error)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);

	if (t->t_rprof->rp_anystate == 0)
		return;

	schedctl_finish_sigblock(t);

	/* test for any activity that requires p->p_lock */
	if (tracing(p, SIGPROF) || pr_watch_active(p) ||
	    sigismember(&PTOU(p)->u_sigresethand, SIGPROF)) {
		/* do it the classic slow way */
		realsigprof_slow(sysnum, nsysarg, error);
	} else {
		/* do it the cheating-a-little fast way */
		realsigprof_fast(sysnum, nsysarg, error);
	}
}

#ifdef _SYSCALL32_IMPL

/*
 * It's tricky to transmit a sigval between 32-bit and 64-bit
 * process, since in the 64-bit world, a pointer and an integer
 * are different sizes.  Since we're constrained by the standards
 * world not to change the types, and it's unclear how useful it is
 * to send pointers between address spaces this way, we preserve
 * the 'int' interpretation for 32-bit processes interoperating
 * with 64-bit processes.  The full semantics (pointers or integers)
 * are available for N-bit processes interoperating with N-bit
 * processes.
 */
void
siginfo_kto32(const k_siginfo_t *src, siginfo32_t *dest)
{
	bzero(dest, sizeof (*dest));

	/*
	 * The absolute minimum content is si_signo and si_code.
	 */
	dest->si_signo = src->si_signo;
	if ((dest->si_code = src->si_code) == SI_NOINFO)
		return;

	/*
	 * A siginfo generated by user level is structured
	 * differently from one generated by the kernel.
	 */
	if (SI_FROMUSER(src)) {
		dest->si_pid = src->si_pid;
		dest->si_ctid = src->si_ctid;
		dest->si_zoneid = src->si_zoneid;
		dest->si_uid = src->si_uid;
		if (SI_CANQUEUE(src->si_code))
			dest->si_value.sival_int =
			    (int32_t)src->si_value.sival_int;
		return;
	}

	dest->si_errno = src->si_errno;

	switch (src->si_signo) {
	default:
		dest->si_pid = src->si_pid;
		dest->si_ctid = src->si_ctid;
		dest->si_zoneid = src->si_zoneid;
		dest->si_uid = src->si_uid;
		dest->si_value.sival_int = (int32_t)src->si_value.sival_int;
		break;
	case SIGCLD:
		dest->si_pid = src->si_pid;
		dest->si_ctid = src->si_ctid;
		dest->si_zoneid = src->si_zoneid;
		dest->si_status = src->si_status;
		dest->si_stime = src->si_stime;
		dest->si_utime = src->si_utime;
		break;
	case SIGSEGV:
	case SIGBUS:
	case SIGILL:
	case SIGTRAP:
	case SIGFPE:
	case SIGEMT:
		dest->si_addr = (caddr32_t)(uintptr_t)src->si_addr;
		dest->si_trapno = src->si_trapno;
		dest->si_pc = (caddr32_t)(uintptr_t)src->si_pc;
		break;
	case SIGPOLL:
	case SIGXFSZ:
		dest->si_fd = src->si_fd;
		dest->si_band = src->si_band;
		break;
	case SIGPROF:
		dest->si_faddr = (caddr32_t)(uintptr_t)src->si_faddr;
		dest->si_tstamp.tv_sec = src->si_tstamp.tv_sec;
		dest->si_tstamp.tv_nsec = src->si_tstamp.tv_nsec;
		dest->si_syscall = src->si_syscall;
		dest->si_nsysarg = src->si_nsysarg;
		dest->si_fault = src->si_fault;
		break;
	}
}

void
siginfo_32tok(const siginfo32_t *src, k_siginfo_t *dest)
{
	bzero(dest, sizeof (*dest));

	/*
	 * The absolute minimum content is si_signo and si_code.
	 */
	dest->si_signo = src->si_signo;
	if ((dest->si_code = src->si_code) == SI_NOINFO)
		return;

	/*
	 * A siginfo generated by user level is structured
	 * differently from one generated by the kernel.
	 */
	if (SI_FROMUSER(src)) {
		dest->si_pid = src->si_pid;
		dest->si_ctid = src->si_ctid;
		dest->si_zoneid = src->si_zoneid;
		dest->si_uid = src->si_uid;
		if (SI_CANQUEUE(src->si_code))
			dest->si_value.sival_int =
			    (int)src->si_value.sival_int;
		return;
	}

	dest->si_errno = src->si_errno;

	switch (src->si_signo) {
	default:
		dest->si_pid = src->si_pid;
		dest->si_ctid = src->si_ctid;
		dest->si_zoneid = src->si_zoneid;
		dest->si_uid = src->si_uid;
		dest->si_value.sival_int = (int)src->si_value.sival_int;
		break;
	case SIGCLD:
		dest->si_pid = src->si_pid;
		dest->si_ctid = src->si_ctid;
		dest->si_zoneid = src->si_zoneid;
		dest->si_status = src->si_status;
		dest->si_stime = src->si_stime;
		dest->si_utime = src->si_utime;
		break;
	case SIGSEGV:
	case SIGBUS:
	case SIGILL:
	case SIGTRAP:
	case SIGFPE:
	case SIGEMT:
		dest->si_addr = (void *)(uintptr_t)src->si_addr;
		dest->si_trapno = src->si_trapno;
		dest->si_pc = (void *)(uintptr_t)src->si_pc;
		break;
	case SIGPOLL:
	case SIGXFSZ:
		dest->si_fd = src->si_fd;
		dest->si_band = src->si_band;
		break;
	case SIGPROF:
		dest->si_faddr = (void *)(uintptr_t)src->si_faddr;
		dest->si_tstamp.tv_sec = src->si_tstamp.tv_sec;
		dest->si_tstamp.tv_nsec = src->si_tstamp.tv_nsec;
		dest->si_syscall = src->si_syscall;
		dest->si_nsysarg = src->si_nsysarg;
		dest->si_fault = src->si_fault;
		break;
	}
}

#endif /* _SYSCALL32_IMPL */
