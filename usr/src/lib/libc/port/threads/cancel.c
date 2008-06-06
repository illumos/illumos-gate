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

#include "lint.h"
#include "thr_uberdata.h"

/*
 * pthread_cancel: tries to cancel the targeted thread.
 * If the target thread has already exited no action is taken.
 * Else send SIGCANCEL to request the other thread to cancel itself.
 */
int
pthread_cancel(thread_t tid)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *ulwp;
	int error = 0;

	if ((ulwp = find_lwp(tid)) == NULL)
		return (ESRCH);

	if (ulwp->ul_cancel_pending) {
		/*
		 * Don't send SIGCANCEL more than once.
		 */
		ulwp_unlock(ulwp, udp);
	} else if (ulwp == self) {
		/*
		 * Unlock self before cancelling.
		 */
		ulwp_unlock(self, udp);
		self->ul_nocancel = 0;	/* cancellation is now possible */
		if (self->ul_sigdefer == 0)
			do_sigcancel();
		else {
			self->ul_cancel_pending = 1;
			set_cancel_pending_flag(self, 0);
		}
	} else if (ulwp->ul_cancel_disabled) {
		/*
		 * Don't send SIGCANCEL if cancellation is disabled;
		 * just set the thread's ulwp->ul_cancel_pending flag.
		 * This avoids a potential EINTR for the target thread.
		 * We don't call set_cancel_pending_flag() here because
		 * we cannot modify another thread's schedctl data.
		 */
		ulwp->ul_cancel_pending = 1;
		ulwp_unlock(ulwp, udp);
	} else {
		/*
		 * Request the other thread to cancel itself.
		 */
		error = _lwp_kill(tid, SIGCANCEL);
		ulwp_unlock(ulwp, udp);
	}

	return (error);
}

/*
 * pthread_setcancelstate: sets the state ENABLED or DISABLED.
 * If the state is already ENABLED or is being set to ENABLED,
 * the type of cancellation is ASYNCHRONOUS, and a cancel request
 * is pending, then the thread is cancelled right here.
 * Otherwise, pthread_setcancelstate() is not a cancellation point.
 */
int
pthread_setcancelstate(int state, int *oldstate)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int was_disabled;

	/*
	 * Grab ulwp_lock(self) to protect the setting of ul_cancel_disabled
	 * since it is tested under this lock by pthread_cancel(), above.
	 * This has the side-effect of calling enter_critical() and this
	 * defers SIGCANCEL until ulwp_unlock(self) when exit_critical()
	 * is called.  (self->ul_cancel_pending is set in the SIGCANCEL
	 * handler and we must be async-signal safe here.)
	 */
	ulwp_lock(self, udp);

	was_disabled = self->ul_cancel_disabled;
	switch (state) {
	case PTHREAD_CANCEL_ENABLE:
		self->ul_cancel_disabled = 0;
		break;
	case PTHREAD_CANCEL_DISABLE:
		self->ul_cancel_disabled = 1;
		break;
	default:
		ulwp_unlock(self, udp);
		return (EINVAL);
	}
	set_cancel_pending_flag(self, 0);

	/*
	 * If this thread has been requested to be canceled and
	 * is in async mode and is or was enabled, then exit.
	 */
	if ((!self->ul_cancel_disabled || !was_disabled) &&
	    self->ul_cancel_async && self->ul_cancel_pending) {
		ulwp_unlock(self, udp);
		pthread_exit(PTHREAD_CANCELED);
	}

	ulwp_unlock(self, udp);

	if (oldstate != NULL) {
		if (was_disabled)
			*oldstate = PTHREAD_CANCEL_DISABLE;
		else
			*oldstate = PTHREAD_CANCEL_ENABLE;
	}
	return (0);
}

/*
 * pthread_setcanceltype: sets the type DEFERRED or ASYNCHRONOUS
 * If the type is being set as ASYNC, then it becomes
 * a cancellation point if there is a cancellation pending.
 */
int
pthread_setcanceltype(int type, int *oldtype)
{
	ulwp_t *self = curthread;
	int was_async;

	/*
	 * Call enter_critical() to defer SIGCANCEL until exit_critical().
	 * We do this because curthread->ul_cancel_pending is set in the
	 * SIGCANCEL handler and we must be async-signal safe here.
	 */
	enter_critical(self);

	was_async = self->ul_cancel_async;
	switch (type) {
	case PTHREAD_CANCEL_ASYNCHRONOUS:
		self->ul_cancel_async = 1;
		break;
	case PTHREAD_CANCEL_DEFERRED:
		self->ul_cancel_async = 0;
		break;
	default:
		exit_critical(self);
		return (EINVAL);
	}
	self->ul_save_async = self->ul_cancel_async;

	/*
	 * If this thread has been requested to be canceled and
	 * is in enabled mode and is or was in async mode, exit.
	 */
	if ((self->ul_cancel_async || was_async) &&
	    self->ul_cancel_pending && !self->ul_cancel_disabled) {
		exit_critical(self);
		pthread_exit(PTHREAD_CANCELED);
	}

	exit_critical(self);

	if (oldtype != NULL) {
		if (was_async)
			*oldtype = PTHREAD_CANCEL_ASYNCHRONOUS;
		else
			*oldtype = PTHREAD_CANCEL_DEFERRED;
	}
	return (0);
}

/*
 * pthread_testcancel: tests for any cancellation pending
 * if the cancellation is enabled and is pending, act on
 * it by calling thr_exit. thr_exit takes care of calling
 * cleanup handlers.
 */
void
pthread_testcancel(void)
{
	ulwp_t *self = curthread;

	if (self->ul_cancel_pending && !self->ul_cancel_disabled)
		pthread_exit(PTHREAD_CANCELED);
}

/*
 * For deferred mode, this routine makes a thread cancelable.
 * It is called from the functions which want to be cancellation
 * points and are about to block, such as cond_wait().
 */
void
_cancelon()
{
	ulwp_t *self = curthread;

	ASSERT(!(self->ul_cancelable && self->ul_cancel_disabled));
	if (!self->ul_cancel_disabled) {
		ASSERT(self->ul_cancelable >= 0);
		self->ul_cancelable++;
		if (self->ul_cancel_pending)
			pthread_exit(PTHREAD_CANCELED);
	}
}

/*
 * This routine turns cancelability off and possible calls pthread_exit().
 * It is called from functions which are cancellation points, like cond_wait().
 */
void
_canceloff()
{
	ulwp_t *self = curthread;

	ASSERT(!(self->ul_cancelable && self->ul_cancel_disabled));
	if (!self->ul_cancel_disabled) {
		if (self->ul_cancel_pending)
			pthread_exit(PTHREAD_CANCELED);
		self->ul_cancelable--;
		ASSERT(self->ul_cancelable >= 0);
	}
}

/*
 * Same as _canceloff() but don't actually cancel the thread.
 * This is used by cond_wait() and sema_wait() when they don't get EINTR.
 */
void
_canceloff_nocancel()
{
	ulwp_t *self = curthread;

	ASSERT(!(self->ul_cancelable && self->ul_cancel_disabled));
	if (!self->ul_cancel_disabled) {
		self->ul_cancelable--;
		ASSERT(self->ul_cancelable >= 0);
	}
}

/*
 * __pthread_cleanup_push: called by macro in pthread.h which defines
 * POSIX.1c pthread_cleanup_push(). Macro in pthread.h allocates the
 * cleanup struct and calls this routine to push the handler off the
 * curthread's struct.
 */
void
__pthread_cleanup_push(void (*routine)(void *),
	void *args, caddr_t fp, _cleanup_t *clnup_info)
{
	ulwp_t *self = curthread;
	__cleanup_t *infop = (__cleanup_t *)clnup_info;

	infop->func = routine;
	infop->arg = args;
	infop->fp = fp;
	infop->next = self->ul_clnup_hdr;
	self->ul_clnup_hdr = infop;
}

/*
 * __pthread_cleanup_pop: called by macro in pthread.h which defines
 * POSIX.1c pthread_cleanup_pop(). It calls this routine to pop the
 * handler off the curthread's struct and execute it if necessary.
 */
/* ARGSUSED1 */
void
__pthread_cleanup_pop(int ex, _cleanup_t *clnup_info)
{
	ulwp_t *self = curthread;
	__cleanup_t *infop = self->ul_clnup_hdr;

	self->ul_clnup_hdr = infop->next;
	if (ex)
		(*infop->func)(infop->arg);
}

/*
 * Called when either self->ul_cancel_disabled or self->ul_cancel_pending
 * is modified.  Setting SC_CANCEL_FLG informs the kernel that we have
 * a pending cancellation and we do not have cancellation disabled.
 * In this situation, we will not go to sleep on any system call but
 * will instead return EINTR immediately on any attempt to sleep,
 * with SC_EINTR_FLG set in sc_flgs.  Clearing SC_CANCEL_FLG rescinds
 * this condition, but SC_EINTR_FLG never goes away until the thread
 * terminates (indicated by clear_flags != 0).
 */
void
set_cancel_pending_flag(ulwp_t *self, int clear_flags)
{
	volatile sc_shared_t *scp;

	if (self->ul_vfork | self->ul_nocancel)
		return;
	enter_critical(self);
	if ((scp = self->ul_schedctl) != NULL ||
	    (scp = setup_schedctl()) != NULL) {
		if (clear_flags)
			scp->sc_flgs &= ~(SC_CANCEL_FLG | SC_EINTR_FLG);
		else if (self->ul_cancel_pending && !self->ul_cancel_disabled)
			scp->sc_flgs |= SC_CANCEL_FLG;
		else
			scp->sc_flgs &= ~SC_CANCEL_FLG;
	}
	exit_critical(self);
}

/*
 * Called from the PROLOGUE macro in scalls.c to inform subsequent
 * code that a cancellation point has been called and that the
 * current thread should cancel itself as soon as all of its locks
 * have been dropped (see safe_mutex_unlock()).
 */
void
set_cancel_eintr_flag(ulwp_t *self)
{
	volatile sc_shared_t *scp;

	if (self->ul_vfork | self->ul_nocancel)
		return;
	enter_critical(self);
	if ((scp = self->ul_schedctl) != NULL ||
	    (scp = setup_schedctl()) != NULL)
		scp->sc_flgs |= SC_EINTR_FLG;
	exit_critical(self);
}

/*
 * Calling set_parking_flag(curthread, 1) informs the kernel that we are
 * calling __lwp_park or ___lwp_cond_wait().  If we take a signal in
 * the unprotected (from signals) interval before reaching the kernel,
 * sigacthandler() will call set_parking_flag(curthread, 0) to inform
 * the kernel to return immediately from these system calls, giving us
 * a spurious wakeup but not a deadlock.
 */
void
set_parking_flag(ulwp_t *self, int park)
{
	volatile sc_shared_t *scp;

	enter_critical(self);
	if ((scp = self->ul_schedctl) != NULL ||
	    (scp = setup_schedctl()) != NULL) {
		if (park) {
			scp->sc_flgs |= SC_PARK_FLG;
			/*
			 * We are parking; allow the __lwp_park() call to
			 * block even if we have a pending cancellation.
			 */
			scp->sc_flgs &= ~SC_CANCEL_FLG;
		} else {
			scp->sc_flgs &= ~(SC_PARK_FLG | SC_CANCEL_FLG);
			/*
			 * We are no longer parking; restore the
			 * pending cancellation flag if necessary.
			 */
			if (self->ul_cancel_pending &&
			    !self->ul_cancel_disabled)
				scp->sc_flgs |= SC_CANCEL_FLG;
		}
	} else if (park == 0) {	/* schedctl failed, do it the long way */
		__lwp_unpark(self->ul_lwpid);
	}
	exit_critical(self);
}

/*
 * Test if the current thread is due to exit because of cancellation.
 */
int
cancel_active(void)
{
	ulwp_t *self = curthread;
	volatile sc_shared_t *scp;
	int exit_soon;

	/*
	 * If there is a pending cancellation and cancellation
	 * is not disabled (SC_CANCEL_FLG) and we received
	 * EINTR from a recent system call (SC_EINTR_FLG),
	 * then we will soon be exiting.
	 */
	enter_critical(self);
	exit_soon =
	    (((scp = self->ul_schedctl) != NULL ||
	    (scp = setup_schedctl()) != NULL) &&
	    (scp->sc_flgs & (SC_CANCEL_FLG | SC_EINTR_FLG)) ==
	    (SC_CANCEL_FLG | SC_EINTR_FLG));
	exit_critical(self);

	return (exit_soon);
}
