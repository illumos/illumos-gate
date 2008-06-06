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
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include "thread_pool_impl.h"

static mutex_t thread_pool_lock = DEFAULTMUTEX;
static tpool_t *thread_pools = NULL;

static void
delete_pool(tpool_t *tpool)
{
	tpool_job_t *job;

	ASSERT(tpool->tp_current == 0 && tpool->tp_active == NULL);

	/*
	 * Unlink the pool from the global list of all pools.
	 */
	lmutex_lock(&thread_pool_lock);
	if (thread_pools == tpool)
		thread_pools = tpool->tp_forw;
	if (thread_pools == tpool)
		thread_pools = NULL;
	else {
		tpool->tp_back->tp_forw = tpool->tp_forw;
		tpool->tp_forw->tp_back = tpool->tp_back;
	}
	lmutex_unlock(&thread_pool_lock);

	/*
	 * There should be no pending jobs, but just in case...
	 */
	for (job = tpool->tp_head; job != NULL; job = tpool->tp_head) {
		tpool->tp_head = job->tpj_next;
		lfree(job, sizeof (*job));
	}
	(void) pthread_attr_destroy(&tpool->tp_attr);
	lfree(tpool, sizeof (*tpool));
}

/*
 * Worker thread is terminating.
 */
static void
worker_cleanup(tpool_t *tpool)
{
	ASSERT(MUTEX_HELD(&tpool->tp_mutex));

	if (--tpool->tp_current == 0 &&
	    (tpool->tp_flags & (TP_DESTROY | TP_ABANDON))) {
		if (tpool->tp_flags & TP_ABANDON) {
			sig_mutex_unlock(&tpool->tp_mutex);
			delete_pool(tpool);
			return;
		}
		if (tpool->tp_flags & TP_DESTROY)
			(void) cond_broadcast(&tpool->tp_busycv);
	}
	sig_mutex_unlock(&tpool->tp_mutex);
}

static void
notify_waiters(tpool_t *tpool)
{
	if (tpool->tp_head == NULL && tpool->tp_active == NULL) {
		tpool->tp_flags &= ~TP_WAIT;
		(void) cond_broadcast(&tpool->tp_waitcv);
	}
}

/*
 * Called by a worker thread on return from a tpool_dispatch()d job.
 */
static void
job_cleanup(tpool_t *tpool)
{
	pthread_t my_tid = pthread_self();
	tpool_active_t *activep;
	tpool_active_t **activepp;

	sig_mutex_lock(&tpool->tp_mutex);
	/* CSTYLED */
	for (activepp = &tpool->tp_active;; activepp = &activep->tpa_next) {
		activep = *activepp;
		if (activep->tpa_tid == my_tid) {
			*activepp = activep->tpa_next;
			break;
		}
	}
	if (tpool->tp_flags & TP_WAIT)
		notify_waiters(tpool);
}

static void *
tpool_worker(void *arg)
{
	tpool_t *tpool = (tpool_t *)arg;
	int elapsed;
	tpool_job_t *job;
	void (*func)(void *);
	tpool_active_t active;

	sig_mutex_lock(&tpool->tp_mutex);
	pthread_cleanup_push(worker_cleanup, tpool);

	/*
	 * This is the worker's main loop.
	 * It will only be left if a timeout or an error has occured.
	 */
	active.tpa_tid = pthread_self();
	for (;;) {
		elapsed = 0;
		tpool->tp_idle++;
		if (tpool->tp_flags & TP_WAIT)
			notify_waiters(tpool);
		while ((tpool->tp_head == NULL ||
		    (tpool->tp_flags & TP_SUSPEND)) &&
		    !(tpool->tp_flags & (TP_DESTROY | TP_ABANDON))) {
			if (tpool->tp_current <= tpool->tp_minimum ||
			    tpool->tp_linger == 0) {
				(void) sig_cond_wait(&tpool->tp_workcv,
				    &tpool->tp_mutex);
			} else {
				timestruc_t timeout;

				timeout.tv_sec = tpool->tp_linger;
				timeout.tv_nsec = 0;
				if (sig_cond_reltimedwait(&tpool->tp_workcv,
				    &tpool->tp_mutex, &timeout) != 0) {
					elapsed = 1;
					break;
				}
			}
		}
		tpool->tp_idle--;
		if (tpool->tp_flags & TP_DESTROY)
			break;
		if (tpool->tp_flags & TP_ABANDON) {
			/* can't abandon a suspended pool */
			if (tpool->tp_flags & TP_SUSPEND) {
				tpool->tp_flags &= ~TP_SUSPEND;
				(void) cond_broadcast(&tpool->tp_workcv);
			}
			if (tpool->tp_head == NULL)
				break;
		}
		if ((job = tpool->tp_head) != NULL &&
		    !(tpool->tp_flags & TP_SUSPEND)) {
			elapsed = 0;
			func = job->tpj_func;
			arg = job->tpj_arg;
			tpool->tp_head = job->tpj_next;
			if (job == tpool->tp_tail)
				tpool->tp_tail = NULL;
			tpool->tp_njobs--;
			active.tpa_next = tpool->tp_active;
			tpool->tp_active = &active;
			sig_mutex_unlock(&tpool->tp_mutex);
			pthread_cleanup_push(job_cleanup, tpool);
			lfree(job, sizeof (*job));
			/*
			 * Call the specified function.
			 */
			func(arg);
			/*
			 * We don't know what this thread has been doing,
			 * so we reset its signal mask and cancellation
			 * state back to the initial values.
			 */
			(void) pthread_sigmask(SIG_SETMASK, &maskset, NULL);
			(void) pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,
			    NULL);
			(void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,
			    NULL);
			pthread_cleanup_pop(1);
		}
		if (elapsed && tpool->tp_current > tpool->tp_minimum) {
			/*
			 * We timed out and there is no work to be done
			 * and the number of workers exceeds the minimum.
			 * Exit now to reduce the size of the pool.
			 */
			break;
		}
	}
	pthread_cleanup_pop(1);
	return (arg);
}

/*
 * Create a worker thread, with all signals blocked.
 */
static int
create_worker(tpool_t *tpool)
{
	sigset_t oset;
	int error;

	(void) pthread_sigmask(SIG_SETMASK, &maskset, &oset);
	error = pthread_create(NULL, &tpool->tp_attr, tpool_worker, tpool);
	(void) pthread_sigmask(SIG_SETMASK, &oset, NULL);
	return (error);
}

tpool_t	*
tpool_create(uint_t min_threads, uint_t max_threads, uint_t linger,
	pthread_attr_t *attr)
{
	tpool_t	*tpool;
	void *stackaddr;
	size_t stacksize;
	size_t minstack;
	int error;

	if (min_threads > max_threads || max_threads < 1) {
		errno = EINVAL;
		return (NULL);
	}
	if (attr != NULL) {
		if (pthread_attr_getstack(attr, &stackaddr, &stacksize) != 0) {
			errno = EINVAL;
			return (NULL);
		}
		/*
		 * Allow only one thread in the pool with a specified stack.
		 * Require threads to have at least the minimum stack size.
		 */
		minstack = thr_min_stack();
		if (stackaddr != NULL) {
			if (stacksize < minstack || max_threads != 1) {
				errno = EINVAL;
				return (NULL);
			}
		} else if (stacksize != 0 && stacksize < minstack) {
			errno = EINVAL;
			return (NULL);
		}
	}

	tpool = lmalloc(sizeof (*tpool));
	if (tpool == NULL) {
		errno = ENOMEM;
		return (NULL);
	}
	(void) mutex_init(&tpool->tp_mutex, USYNC_THREAD, NULL);
	(void) cond_init(&tpool->tp_busycv, USYNC_THREAD, NULL);
	(void) cond_init(&tpool->tp_workcv, USYNC_THREAD, NULL);
	(void) cond_init(&tpool->tp_waitcv, USYNC_THREAD, NULL);
	tpool->tp_minimum = min_threads;
	tpool->tp_maximum = max_threads;
	tpool->tp_linger = linger;

	/*
	 * We cannot just copy the attribute pointer.
	 * We need to initialize a new pthread_attr_t structure
	 * with the values from the user-supplied pthread_attr_t.
	 * If the attribute pointer is NULL, we need to initialize
	 * the new pthread_attr_t structure with default values.
	 */
	error = pthread_attr_clone(&tpool->tp_attr, attr);
	if (error) {
		lfree(tpool, sizeof (*tpool));
		errno = error;
		return (NULL);
	}

	/* make all pool threads be detached daemon threads */
	(void) pthread_attr_setdetachstate(&tpool->tp_attr,
	    PTHREAD_CREATE_DETACHED);
	(void) pthread_attr_setdaemonstate_np(&tpool->tp_attr,
	    PTHREAD_CREATE_DAEMON_NP);

	/* insert into the global list of all thread pools */
	lmutex_lock(&thread_pool_lock);
	if (thread_pools == NULL) {
		tpool->tp_forw = tpool;
		tpool->tp_back = tpool;
		thread_pools = tpool;
	} else {
		thread_pools->tp_back->tp_forw = tpool;
		tpool->tp_forw = thread_pools;
		tpool->tp_back = thread_pools->tp_back;
		thread_pools->tp_back = tpool;
	}
	lmutex_unlock(&thread_pool_lock);

	return (tpool);
}

/*
 * Dispatch a work request to the thread pool.
 * If there are idle workers, awaken one.
 * Else, if the maximum number of workers has
 * not been reached, spawn a new worker thread.
 * Else just return with the job added to the queue.
 */
int
tpool_dispatch(tpool_t *tpool, void (*func)(void *), void *arg)
{
	tpool_job_t *job;

	ASSERT(!(tpool->tp_flags & (TP_DESTROY | TP_ABANDON)));

	if ((job = lmalloc(sizeof (*job))) == NULL)
		return (-1);
	job->tpj_next = NULL;
	job->tpj_func = func;
	job->tpj_arg = arg;

	sig_mutex_lock(&tpool->tp_mutex);

	if (tpool->tp_head == NULL)
		tpool->tp_head = job;
	else
		tpool->tp_tail->tpj_next = job;
	tpool->tp_tail = job;
	tpool->tp_njobs++;

	if (!(tpool->tp_flags & TP_SUSPEND)) {
		if (tpool->tp_idle > 0)
			(void) cond_signal(&tpool->tp_workcv);
		else if (tpool->tp_current < tpool->tp_maximum &&
		    create_worker(tpool) == 0)
			tpool->tp_current++;
	}

	sig_mutex_unlock(&tpool->tp_mutex);
	return (0);
}

/*
 * Assumes: by the time tpool_destroy() is called no one will use this
 * thread pool in any way and no one will try to dispatch entries to it.
 * Calling tpool_destroy() from a job in the pool will cause deadlock.
 */
void
tpool_destroy(tpool_t *tpool)
{
	tpool_active_t *activep;

	ASSERT(!tpool_member(tpool));
	ASSERT(!(tpool->tp_flags & (TP_DESTROY | TP_ABANDON)));

	sig_mutex_lock(&tpool->tp_mutex);
	pthread_cleanup_push(sig_mutex_unlock, &tpool->tp_mutex);

	/* mark the pool as being destroyed; wakeup idle workers */
	tpool->tp_flags |= TP_DESTROY;
	tpool->tp_flags &= ~TP_SUSPEND;
	(void) cond_broadcast(&tpool->tp_workcv);

	/* cancel all active workers */
	for (activep = tpool->tp_active; activep; activep = activep->tpa_next)
		(void) pthread_cancel(activep->tpa_tid);

	/* wait for all active workers to finish */
	while (tpool->tp_active != NULL) {
		tpool->tp_flags |= TP_WAIT;
		(void) sig_cond_wait(&tpool->tp_waitcv, &tpool->tp_mutex);
	}

	/* the last worker to terminate will wake us up */
	while (tpool->tp_current != 0)
		(void) sig_cond_wait(&tpool->tp_busycv, &tpool->tp_mutex);

	pthread_cleanup_pop(1);	/* sig_mutex_unlock(&tpool->tp_mutex); */
	delete_pool(tpool);
}

/*
 * Like tpool_destroy(), but don't cancel workers or wait for them to finish.
 * The last worker to terminate will delete the pool.
 */
void
tpool_abandon(tpool_t *tpool)
{
	ASSERT(!(tpool->tp_flags & (TP_DESTROY | TP_ABANDON)));

	sig_mutex_lock(&tpool->tp_mutex);
	if (tpool->tp_current == 0) {
		/* no workers, just delete the pool */
		sig_mutex_unlock(&tpool->tp_mutex);
		delete_pool(tpool);
	} else {
		/* wake up all workers, last one will delete the pool */
		tpool->tp_flags |= TP_ABANDON;
		tpool->tp_flags &= ~TP_SUSPEND;
		(void) cond_broadcast(&tpool->tp_workcv);
		sig_mutex_unlock(&tpool->tp_mutex);
	}
}

/*
 * Wait for all jobs to complete.
 * Calling tpool_wait() from a job in the pool will cause deadlock.
 */
void
tpool_wait(tpool_t *tpool)
{
	ASSERT(!tpool_member(tpool));
	ASSERT(!(tpool->tp_flags & (TP_DESTROY | TP_ABANDON)));

	sig_mutex_lock(&tpool->tp_mutex);
	pthread_cleanup_push(sig_mutex_unlock, &tpool->tp_mutex);
	while (tpool->tp_head != NULL || tpool->tp_active != NULL) {
		tpool->tp_flags |= TP_WAIT;
		(void) sig_cond_wait(&tpool->tp_waitcv, &tpool->tp_mutex);
		ASSERT(!(tpool->tp_flags & (TP_DESTROY | TP_ABANDON)));
	}
	pthread_cleanup_pop(1);	/* sig_mutex_unlock(&tpool->tp_mutex); */
}

void
tpool_suspend(tpool_t *tpool)
{
	ASSERT(!(tpool->tp_flags & (TP_DESTROY | TP_ABANDON)));

	sig_mutex_lock(&tpool->tp_mutex);
	tpool->tp_flags |= TP_SUSPEND;
	sig_mutex_unlock(&tpool->tp_mutex);
}

int
tpool_suspended(tpool_t *tpool)
{
	int suspended;

	ASSERT(!(tpool->tp_flags & (TP_DESTROY | TP_ABANDON)));

	sig_mutex_lock(&tpool->tp_mutex);
	suspended = (tpool->tp_flags & TP_SUSPEND) != 0;
	sig_mutex_unlock(&tpool->tp_mutex);

	return (suspended);
}

void
tpool_resume(tpool_t *tpool)
{
	int excess;

	ASSERT(!(tpool->tp_flags & (TP_DESTROY | TP_ABANDON)));

	sig_mutex_lock(&tpool->tp_mutex);
	if (!(tpool->tp_flags & TP_SUSPEND)) {
		sig_mutex_unlock(&tpool->tp_mutex);
		return;
	}
	tpool->tp_flags &= ~TP_SUSPEND;
	(void) cond_broadcast(&tpool->tp_workcv);
	excess = tpool->tp_njobs - tpool->tp_idle;
	while (excess-- > 0 && tpool->tp_current < tpool->tp_maximum) {
		if (create_worker(tpool) != 0)
			break;		/* pthread_create() failed */
		tpool->tp_current++;
	}
	sig_mutex_unlock(&tpool->tp_mutex);
}

int
tpool_member(tpool_t *tpool)
{
	pthread_t my_tid = pthread_self();
	tpool_active_t *activep;

	ASSERT(!(tpool->tp_flags & (TP_DESTROY | TP_ABANDON)));

	sig_mutex_lock(&tpool->tp_mutex);
	for (activep = tpool->tp_active; activep; activep = activep->tpa_next) {
		if (activep->tpa_tid == my_tid) {
			sig_mutex_unlock(&tpool->tp_mutex);
			return (1);
		}
	}
	sig_mutex_unlock(&tpool->tp_mutex);
	return (0);
}

void
postfork1_child_tpool(void)
{
	pthread_t my_tid = pthread_self();
	tpool_t *tpool;
	tpool_job_t *job;

	/*
	 * All of the thread pool workers are gone, except possibly
	 * for the current thread, if it is a thread pool worker thread.
	 * Retain the thread pools, but make them all empty.  Whatever
	 * jobs were queued or running belong to the parent process.
	 */
top:
	if ((tpool = thread_pools) == NULL)
		return;

	do {
		tpool_active_t *activep;

		(void) mutex_init(&tpool->tp_mutex, USYNC_THREAD, NULL);
		(void) cond_init(&tpool->tp_busycv, USYNC_THREAD, NULL);
		(void) cond_init(&tpool->tp_workcv, USYNC_THREAD, NULL);
		(void) cond_init(&tpool->tp_waitcv, USYNC_THREAD, NULL);
		for (job = tpool->tp_head; job; job = tpool->tp_head) {
			tpool->tp_head = job->tpj_next;
			lfree(job, sizeof (*job));
		}
		tpool->tp_tail = NULL;
		tpool->tp_njobs = 0;
		for (activep = tpool->tp_active; activep;
		    activep = activep->tpa_next) {
			if (activep->tpa_tid == my_tid) {
				activep->tpa_next = NULL;
				break;
			}
		}
		tpool->tp_idle = 0;
		tpool->tp_current = 0;
		if ((tpool->tp_active = activep) != NULL)
			tpool->tp_current = 1;
		tpool->tp_flags &= ~TP_WAIT;
		if (tpool->tp_flags & (TP_DESTROY | TP_ABANDON)) {
			tpool->tp_flags &= ~TP_DESTROY;
			tpool->tp_flags |= TP_ABANDON;
			if (tpool->tp_current == 0) {
				delete_pool(tpool);
				goto top;	/* start over */
			}
		}
	} while ((tpool = tpool->tp_forw) != thread_pools);
}
