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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "thr_uberdata.h"

/*
 * pthread_cancel: tries to cancel the targeted thread.
 * If the target thread has already exited no action is taken.
 * Else send SIGCANCEL to request the other thread to cancel itself.
 */
#pragma weak pthread_cancel = _pthread_cancel
int
_pthread_cancel(thread_t tid)
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
		ulwp_unlock(ulwp, udp);
		ulwp->ul_nocancel = 0;	/* cancellation is now possible */
		if (ulwp->ul_sigdefer)
			ulwp->ul_cancel_pending = 1;
		else
			do_sigcancel();
	} else if (ulwp->ul_cancel_disabled) {
		/*
		 * Don't send SIGCANCEL if cancellation is disabled;
		 * just set the thread's ulwp->ul_cancel_pending flag.
		 * This avoids a potential EINTR for the target thread.
		 */
		ulwp->ul_cancel_pending = 1;
		ulwp_unlock(ulwp, udp);
	} else {
		/*
		 * Request the other thread to cancel itself.
		 */
		error = __lwp_kill(tid, SIGCANCEL);
		ulwp_unlock(ulwp, udp);
	}

	return (error);
}

/*
 * pthread_setcancelstate: sets the state ENABLED or DISABLED
 * If the state is being set as ENABLED, then it becomes
 * a cancellation point only if the type of cancellation is
 * ASYNCHRONOUS and a cancel request is pending.
 * Disabling cancellation is not a cancellation point.
 */
#pragma weak pthread_setcancelstate = _pthread_setcancelstate
int
_pthread_setcancelstate(int state, int *oldstate)
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

	/*
	 * If this thread has been requested to be canceled and
	 * is in async mode and is or was enabled, then exit.
	 */
	if ((!self->ul_cancel_disabled || !was_disabled) &&
	    self->ul_cancel_async && self->ul_cancel_pending) {
		ulwp_unlock(self, udp);
		_pthread_exit(PTHREAD_CANCELED);
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
#pragma weak pthread_setcanceltype = _pthread_setcanceltype
int
_pthread_setcanceltype(int type, int *oldtype)
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
		_pthread_exit(PTHREAD_CANCELED);
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
#pragma weak _private_testcancel = _pthread_testcancel
#pragma weak pthread_testcancel = _pthread_testcancel
void
_pthread_testcancel(void)
{
	ulwp_t *self = curthread;

	if (self->ul_cancel_pending && !self->ul_cancel_disabled)
		_pthread_exit(PTHREAD_CANCELED);
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
			_pthread_exit(PTHREAD_CANCELED);
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
			_pthread_exit(PTHREAD_CANCELED);
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
