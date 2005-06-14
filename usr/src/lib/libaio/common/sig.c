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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libaio.h"
#include <dlfcn.h>

mutex_t __sigio_pendinglock = DEFAULTMUTEX;	/* protects __sigio_pending */
int __sigio_pending = 0;		/* count of pending SIGIO signals */
int _sigio_enabled = 0;			/* set if SIGIO has a signal handler */
static struct sigaction sigioact;
sigset_t __sigiomask;
struct sigaction  sigcanact;

typedef int (*sig_act_t)(int, const struct sigaction *, struct sigaction *);
static sig_act_t next_sigaction;

int
_aio_create_worker(aio_req_t *rp, int mode)
{
	struct aio_worker *aiowp, **workers, **nextworker;
	int *aio_workerscnt;
	void *(*func)(void *);
	sigset_t oset;
	int error;

	/*
	 * Put the new worker thread in the right queue.
	 */
	switch (mode) {
	case AIOWRITE:
		workers = &__workers_wr;
		nextworker = &__nextworker_wr;
		aio_workerscnt = &__wr_workerscnt;
		func = _aio_do_request;
		break;
	case AIOREAD:
		workers = &__workers_rd;
		nextworker = &__nextworker_rd;
		aio_workerscnt = &__rd_workerscnt;
		func = _aio_do_request;
		break;
	case AIOSIGEV:
		workers = &__workers_si;
		nextworker = &__nextworker_si;
		func = _aio_send_sigev;
		aio_workerscnt = &__si_workerscnt;
	}

	if ((aiowp = _aio_alloc_worker()) == NULL)
		return (-1);

	if (rp) {
		rp->req_state = AIO_REQ_QUEUED;
		rp->req_worker = aiowp;
		aiowp->work_head1 = rp;
		aiowp->work_tail1 = rp;
		aiowp->work_next1 = rp;
		aiowp->work_cnt1 = 1;
	}

	(void) _sigprocmask(SIG_SETMASK, &_worker_set, &oset);
	error = thr_create(NULL, __aiostksz, func, aiowp,
		THR_BOUND | THR_DAEMON | THR_SUSPENDED, &aiowp->work_tid);
	(void) _sigprocmask(SIG_SETMASK, &oset, NULL);
	if (error) {
		if (rp) {
			rp->req_state = AIO_REQ_FREE;
			rp->req_worker = NULL;
		}
		_aio_free_worker(aiowp);
		return (-1);
	}

	(void) mutex_lock(&__aio_mutex);
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
	(void) mutex_unlock(&__aio_mutex);

	(void) thr_continue(aiowp->work_tid);

	return (0);
}

void
_aio_cancel_on(struct aio_worker *aiowp)
{
	aiowp->work_cancel_flg = 1;
}

void
_aio_cancel_off(struct aio_worker *aiowp)
{
	aiowp->work_cancel_flg = 0;
}

/*
 * resend a SIGIO signal that was sent while the
 * __aio_mutex was locked.
 *
 * This function is called from _aio_unlock() when previously SIGIO was
 * detected and deferred (signal caught).
 * There could be several threads calling _aio_lock() - _aio_unlock() and
 * therefore __aiosendsig() must make sure that "kill" is being called
 * only one time here.
 *
 */
void
__aiosendsig(void)
{
	sigset_t	oset;
	int		send_sigio;

	(void) _sigprocmask(SIG_BLOCK, &__sigiomask, &oset);

	(void) mutex_lock(&__sigio_pendinglock);
	send_sigio = __sigio_pending;
	__sigio_pending = 0;
	(void) mutex_unlock(&__sigio_pendinglock);

	(void) _sigprocmask(SIG_SETMASK, &oset, NULL);

	if (__pid == (pid_t)-1)
		__pid = getpid();
	if (send_sigio)
		(void) kill(__pid, SIGIO);
}

/*
 * this is the low-level handler for SIGIO. the application
 * handler will not be called if the signal is being blocked.
 */
static void
aiosigiohndlr(int sig, siginfo_t *sip, void *uap)
{
	struct sigaction tact;
	int blocked;

	/*
	 * SIGIO signal is being blocked if either _sigio_masked
	 * or sigio_maskedcnt is set or if both these variables
	 * are clear and the _aio_mutex is locked. the last
	 * condition can only happen when _aio_mutex is being
	 * unlocked. this is a very small window where the mask
	 * is clear and the lock is about to be unlocked, however,
	 * it`s still set and so the signal should be defered.
	 * mutex_trylock() will be used now to check the ownership
	 * of the lock (instead of MUTEX_HELD). This is necessary because
	 * there is a window where the owner of the lock is deleted
	 * and the thread could become preempted. In that case MUTEX_HELD()
	 * will not detect the -still- ownership of the lock.
	 */
	if ((blocked = (__sigio_masked | __sigio_maskedcnt)) == 0) {
		if (mutex_trylock(&__aio_mutex) == 0)
			(void) mutex_unlock(&__aio_mutex);
		else
			blocked = 1;
	}

	if (blocked) {
		/*
		 * aio_lock() is supposed to be non re-entrant with
		 * respect to SIGIO signals. if a SIGIO signal
		 * interrupts a region of code locked by _aio_mutex
		 * the SIGIO signal should be deferred until this
		 * mutex is unlocked. a flag is set, sigio_pending,
		 * to indicate that a SIGIO signal is pending and
		 * should be resent to the process via a kill().
		 * The libaio handler must be reinstalled here, otherwise
		 * the disposition gets the default status and the
		 * next SIGIO signal would terminate the process.
		 */
		(void) mutex_lock(&__sigio_pendinglock);
		__sigio_pending = 1;
		(void) mutex_unlock(&__sigio_pendinglock);
		tact = sigioact;
		tact.sa_sigaction = aiosigiohndlr;
		(void) sigaddset(&tact.sa_mask, SIGIO);
		(void) (*next_sigaction)(SIGIO, &tact, NULL);
	} else {
		/*
		 * call the real handler.
		 */
		(sigioact.sa_sigaction)(sig, sip, uap);
	}
}

void
aiosigcancelhndlr(int sig, siginfo_t *sip, void *uap)
{
	struct aio_worker *aiowp;
	struct sigaction act;

	if (sip != NULL && sip->si_code == SI_LWP) {
		if (thr_getspecific(_aio_key, (void **)&aiowp) != 0)
			_aiopanic("aiosigcancelhndlr, thr_getspecific()\n");
		ASSERT(aiowp != NULL);
		if (aiowp->work_cancel_flg)
			siglongjmp(aiowp->work_jmp_buf, 1);
	} else if (sigcanact.sa_handler == SIG_DFL) {
		act.sa_handler = SIG_DFL;
		(void) (*next_sigaction)(SIGAIOCANCEL, &act, NULL);
		(void) kill(getpid(), sig);
	} else if (sigcanact.sa_handler != SIG_IGN) {
		(sigcanact.sa_sigaction)(sig, sip, uap);
	}
}

#pragma	weak sigaction = _sigaction
int
_sigaction(int sig, const struct sigaction *nact, struct sigaction *oact)
{
	struct sigaction tact;
	struct sigaction oldact;

	if (next_sigaction == NULL)
		next_sigaction = (sig_act_t)dlsym(RTLD_NEXT, "_sigaction");

	/*
	 * Only interpose on SIGIO when it is given a disposition other
	 * than SIG_IGN, or SIG_DFL.  Because SIGAIOCANCEL is SIGPROF,
	 * this signal always should be interposed on, so that SIGPROF
	 * can also be used by the application for profiling.
	 */
	if (sig == SIGIO || sig == SIGAIOCANCEL) {
		if (oact) {
			if (sig == SIGIO)
				*oact = sigioact;
			else
				*oact = sigcanact;
		}
		if (nact == NULL)
			return (0);

		tact = *nact;
		if (sig == SIGIO) {
			oldact = sigioact;
			sigioact = tact;
			if (tact.sa_handler == SIG_DFL ||
			    tact.sa_handler == SIG_IGN) {
				_sigio_enabled = 0;
			} else {
				_sigio_enabled = 1;
				tact.sa_sigaction = aiosigiohndlr;
			}
			tact.sa_flags &= ~SA_NODEFER;
			if ((*next_sigaction)(sig, &tact, NULL) == -1) {
				sigioact = oldact;
				return (-1);
			}
		} else {
			oldact = sigcanact;
			sigcanact = tact;
			tact.sa_sigaction = aiosigcancelhndlr;
			tact.sa_flags &= ~SA_NODEFER;
			tact.sa_flags |= SA_SIGINFO;
			if ((*next_sigaction)(sig, &tact, NULL) == -1) {
				sigcanact = oldact;
				return (-1);
			}
		}
		return (0);
	}

	return ((*next_sigaction)(sig, nact, oact));
}
