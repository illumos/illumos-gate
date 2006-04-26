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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libaio.h"

void
sig_mutex_lock(mutex_t *mp)
{
	_sigoff();
	(void) mutex_lock(mp);
}

void
sig_mutex_unlock(mutex_t *mp)
{
	(void) mutex_unlock(mp);
	_sigon();
}

int
sig_mutex_trylock(mutex_t *mp)
{
	int error;

	_sigoff();
	if ((error = mutex_trylock(mp)) != 0)
		_sigon();
	return (error);
}

/*
 * sig_cond_wait() is a cancellation point.
 */
int
sig_cond_wait(cond_t *cv, mutex_t *mp)
{
	int error;

	pthread_testcancel();
	error = cond_wait(cv, mp);
	if (error == EINTR && _sigdeferred() != 0) {
		sig_mutex_unlock(mp);
		/* take the deferred signal here */
		sig_mutex_lock(mp);
	}
	pthread_testcancel();
	return (error);
}

/*
 * sig_cond_reltimedwait() is a cancellation point.
 */
int
sig_cond_reltimedwait(cond_t *cv, mutex_t *mp, const timespec_t *ts)
{
	int error;

	pthread_testcancel();
	error = cond_reltimedwait(cv, mp, ts);
	if (error == EINTR && _sigdeferred() != 0) {
		sig_mutex_unlock(mp);
		/* take the deferred signal here */
		sig_mutex_lock(mp);
	}
	pthread_testcancel();
	return (error);
}

int
_aio_create_worker(aio_req_t *reqp, int mode)
{
	aio_worker_t *aiowp, **workers, **nextworker;
	int *aio_workerscnt;
	void *(*func)(void *);
	sigset_t oset;
	int error;

	/*
	 * Put the new worker thread in the right queue.
	 */
	switch (mode) {
	case AIOREAD:
	case AIOWRITE:
	case AIOAREAD:
	case AIOAWRITE:
#if !defined(_LP64)
	case AIOAREAD64:
	case AIOAWRITE64:
#endif
		workers = &__workers_rw;
		nextworker = &__nextworker_rw;
		aio_workerscnt = &__rw_workerscnt;
		func = _aio_do_request;
		break;
	case AIONOTIFY:
		workers = &__workers_no;
		nextworker = &__nextworker_no;
		func = _aio_do_notify;
		aio_workerscnt = &__no_workerscnt;
		break;
	default:
		_aiopanic("_aio_create_worker: invalid mode");
		break;
	}

	if ((aiowp = _aio_worker_alloc()) == NULL)
		return (-1);

	if (reqp) {
		reqp->req_state = AIO_REQ_QUEUED;
		reqp->req_worker = aiowp;
		aiowp->work_head1 = reqp;
		aiowp->work_tail1 = reqp;
		aiowp->work_next1 = reqp;
		aiowp->work_count1 = 1;
		aiowp->work_minload1 = 1;
	}

	(void) pthread_sigmask(SIG_SETMASK, &_full_set, &oset);
	error = thr_create(NULL, AIOSTKSIZE, func, aiowp,
		THR_DAEMON | THR_SUSPENDED, &aiowp->work_tid);
	(void) pthread_sigmask(SIG_SETMASK, &oset, NULL);
	if (error) {
		if (reqp) {
			reqp->req_state = 0;
			reqp->req_worker = NULL;
		}
		_aio_worker_free(aiowp);
		return (-1);
	}

	sig_mutex_lock(&__aio_mutex);
	(*aio_workerscnt)++;
	if (*workers == NULL) {
		aiowp->work_forw = aiowp;
		aiowp->work_backw = aiowp;
		*nextworker = aiowp;
		*workers = aiowp;
	} else {
		aiowp->work_backw = (*workers)->work_backw;
		aiowp->work_forw = (*workers);
		(*workers)->work_backw->work_forw = aiowp;
		(*workers)->work_backw = aiowp;
	}
	_aio_worker_cnt++;
	sig_mutex_unlock(&__aio_mutex);

	(void) thr_continue(aiowp->work_tid);

	return (0);
}

/*
 * This is the application's AIOSIGCANCEL sigaction setting.
 */
static struct sigaction sigcanact;

/*
 * This is our AIOSIGCANCEL handler.
 * If the signal is not meant for us, call the application's handler.
 */
void
aiosigcancelhndlr(int sig, siginfo_t *sip, void *uap)
{
	aio_worker_t *aiowp;
	void (*func)(int, siginfo_t *, void *);

	if (sip != NULL && sip->si_code == SI_LWP &&
	    (aiowp = pthread_getspecific(_aio_key)) != NULL) {
		/*
		 * Only aio worker threads get here (with aiowp != NULL).
		 */
		siglongjmp(aiowp->work_jmp_buf, 1);
	} else if (sigcanact.sa_handler != SIG_IGN &&
	    sigcanact.sa_handler != SIG_DFL) {
		/*
		 * Call the application signal handler.
		 */
		func = sigcanact.sa_sigaction;
		if (sigcanact.sa_flags & SA_RESETHAND)
			sigcanact.sa_handler = SIG_DFL;
		if (!(sigcanact.sa_flags & SA_SIGINFO))
			sip = NULL;
		(void) func(sig, sip, uap);
	}
	/*
	 * SIGLWP is ignored by default.
	 */
}

/* consolidation private interface in libc */
extern int _libc_sigaction(int sig, const struct sigaction *act,
	struct sigaction *oact);

#pragma	weak sigaction = _sigaction
int
_sigaction(int sig, const struct sigaction *nact, struct sigaction *oact)
{
	struct sigaction tact;
	struct sigaction oldact;

	/*
	 * We detect SIGIO just to set the _sigio_enabled flag.
	 */
	if (sig == SIGIO && nact != NULL)
		_sigio_enabled =
		    (nact->sa_handler != SIG_DFL &&
		    nact->sa_handler != SIG_IGN);

	/*
	 * We interpose on SIGAIOCANCEL (aka SIGLWP).  Although SIGLWP
	 * is a 'reserved' signal that no application should be using, we
	 * honor the application's handler (see aiosigcancelhndlr(), above).
	 */
	if (sig == SIGAIOCANCEL) {
		oldact = sigcanact;
		if (nact != NULL) {
			sigcanact = tact = *nact;
			if (tact.sa_handler == SIG_DFL ||
			    tact.sa_handler == SIG_IGN) {
				tact.sa_flags = SA_SIGINFO;
				(void) sigemptyset(&tact.sa_mask);
			} else {
				tact.sa_flags |= SA_SIGINFO;
				tact.sa_flags &= ~(SA_NODEFER | SA_RESETHAND);
			}
			tact.sa_sigaction = aiosigcancelhndlr;
			if (_libc_sigaction(sig, &tact, NULL) == -1) {
				sigcanact = oldact;
				return (-1);
			}
		}
		if (oact)
			*oact = oldact;
		return (0);
	}

	/*
	 * Everything else, just call the real sigaction().
	 */
	return (_libc_sigaction(sig, nact, oact));
}

void
init_signals(void)
{
	struct sigaction act;

	/*
	 * See if the application has set up a handler for SIGIO.
	 */
	(void) _libc_sigaction(SIGIO, NULL, &act);
	_sigio_enabled =
	    (act.sa_handler != SIG_DFL && act.sa_handler != SIG_IGN);

	/*
	 * Arrange to catch SIGAIOCANCEL (SIGLWP).
	 * If the application has already set up a handler, preserve it.
	 */
	(void) _libc_sigaction(SIGAIOCANCEL, NULL, &sigcanact);
	act = sigcanact;
	if (act.sa_handler == SIG_DFL || act.sa_handler == SIG_IGN) {
		act.sa_flags = SA_SIGINFO;
		(void) sigemptyset(&act.sa_mask);
	} else {
		act.sa_flags |= SA_SIGINFO;
		act.sa_flags &= ~(SA_NODEFER | SA_RESETHAND);
	}
	act.sa_sigaction = aiosigcancelhndlr;
	(void) _libc_sigaction(SIGAIOCANCEL, &act, NULL);
}
