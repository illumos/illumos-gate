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

#include <signal.h>
#include <strings.h>
#include <limits.h>

#include <fmd_alloc.h>
#include <fmd_subr.h>
#include <fmd_thread.h>
#include <fmd_timerq.h>

#include <fmd.h>

/*
 * Install a new timer to fire after at least 'delta' nanoseconds have elapsed.
 * Timers are associated with persistent integer identifiers in some idspace.
 * We allocate a new timer structure or re-use one from our freelist, and then
 * place it on the queue's list in sorted order by expiration time.  If the new
 * timer is now the earliest to expire, we awaken the fmd_timerq_exec() thread.
 */
id_t
fmd_timerq_install(fmd_timerq_t *tmq, fmd_idspace_t *ids,
    fmd_timer_f *func, void *arg, fmd_event_t *ep, hrtime_t delta)
{
	hrtime_t now = fmd_time_gethrtime();
	hrtime_t base = ep ? fmd_event_hrtime(ep) : now;

	fmd_timer_t *tp, *up;
	hrtime_t hrt;
	id_t id;

	(void) pthread_mutex_lock(&tmq->tmq_lock);

	if ((tp = fmd_list_next(&tmq->tmq_free)) == NULL) {
		tp = fmd_zalloc(sizeof (fmd_timer_t), FMD_SLEEP);
		(void) pthread_cond_init(&tp->tmr_cv, NULL);
	} else
		fmd_list_delete(&tmq->tmq_free, tp);

	if ((id = fmd_idspace_alloc(ids, tp)) == -1) {
		fmd_list_prepend(&tmq->tmq_free, tp);
		(void) pthread_mutex_unlock(&tmq->tmq_lock);
		return (id);
	}

	if (delta < 0)
		delta = 0; /* ensure delta is at least 0ns from now */

	if (base + delta < base)
		hrt = INT64_MAX; /* if wrap-around, set timer for apocalypse */
	else
		hrt = base + delta;

	tp->tmr_hrt = hrt;
	tp->tmr_ids = ids;
	tp->tmr_id = id;
	tp->tmr_func = func;
	tp->tmr_arg = arg;

	/*
	 * For now we use a simple insertion sort for tmq_list.  If we have
	 * scaling problems here due to heavy use of our timer subsystem,
	 * then tmq_list can and should be replaced with a O(logN) heap.
	 */
	for (up = fmd_list_next(&tmq->tmq_list); up; up = fmd_list_next(up)) {
		if (tp->tmr_hrt < up->tmr_hrt)
			break;
	}

	if (up != NULL)
		fmd_list_insert_before(&tmq->tmq_list, up, tp);
	else
		fmd_list_insert_after(&tmq->tmq_list, up, tp);

	if (up != NULL && fmd_list_next(&tmq->tmq_list) == tp)
		fmd_time_waitcancel(tmq->tmq_thread->thr_tid);
	else if (up == NULL && fmd_list_next(&tmq->tmq_list) == tp)
		(void) pthread_cond_signal(&tmq->tmq_cv);

	(void) pthread_mutex_unlock(&tmq->tmq_lock);

	TRACE((FMD_DBG_TMR, "timer %s:%ld insert +%lldns",
	    ids->ids_name, id, delta));

	return (id);
}

/*
 * Remove the specified timer.  If the 'id' is invalid, we'll panic inside of
 * fmd_idspace_free().  If the timer is still set, we move it to the freelist
 * and update the timer thread as needed.  If the timer 'id' is valid but
 * tmr_id is not equal to id, then the timer callback is running: we wait for
 * tmr_id to change to zero (indicating tmr_func is done) before returning.
 */
void *
fmd_timerq_remove(fmd_timerq_t *tmq, fmd_idspace_t *ids, id_t id)
{
	hrtime_t delta = 0;
	void *arg = NULL;
	fmd_timer_t *tp;

	(void) pthread_mutex_lock(&tmq->tmq_lock);
	tp = fmd_idspace_free(ids, id);
	ASSERT(tp == NULL || tp->tmr_ids == ids);

	if (tp == NULL) {
		(void) pthread_mutex_unlock(&tmq->tmq_lock);
		return (NULL); /* timer is no longer active */
	}

	if (tp->tmr_id == id) {
		fmd_list_delete(&tmq->tmq_list, tp);
		delta = tp->tmr_hrt - fmd_time_gethrtime();
		arg = tp->tmr_arg;
		tp->tmr_id = 0;
		fmd_list_append(&tmq->tmq_free, tp);

		/*
		 * If tmq_list is now empty, we must awaken the exec thread so
		 * it will sleep on tmq_cv waiting for the list to change.  We
		 * could also awaken the exec thread if we removed the head of
		 * tmq_list, but an early wakeup is harmless so we do nothing.
		 */
		if (fmd_list_next(&tmq->tmq_list) == NULL)
			fmd_time_waitcancel(tmq->tmq_thread->thr_tid);
	} else {
		/*
		 * Wait until tmr_id is zero, indicating that tmr_func is done.
		 * This relies on expired fmd_timer_t's being returned to our
		 * free list rather than having the data structure deallocated.
		 */
		while (tp->tmr_id != 0)
			(void) pthread_cond_wait(&tp->tmr_cv, &tmq->tmq_lock);
	}

	(void) pthread_mutex_unlock(&tmq->tmq_lock);

	TRACE((FMD_DBG_TMR, "timer %s:%ld remove -%lldns",
	    ids->ids_name, id, delta > 0 ? delta : 0LL));

	return (arg);
}

/*
 * fmd_timerq_exec() is the main loop of the thread that runs the timer queue.
 * We sleep on tmq_cv waiting for timers to show up on tmq_list.  When the list
 * is non-empty, we execute the callback function for each expired timer.  If
 * timers remain that are not yet expired, we nanosleep() until the next expiry
 * time.  We awaken whenever nanosleep() expires or we are interrupted by a
 * SIGALRM from fmd_timerq_install indicating that we need to rescan our list.
 */
static void
fmd_timerq_exec(fmd_timerq_t *tmq)
{
	fmd_timer_t *tp;
	sigset_t set;
	hrtime_t now;

	/*
	 * fmd_thread_create() initializes threads with all signals blocked.
	 * We must unblock SIGALRM (whose disposition has been to set to call
	 * an empty function by fmd_timerq_init()) in order to permit directed
	 * signals to interrupt our nanosleep() and make it return EINTR.
	 * This SIGALRM mechanism is used by the native clock (see fmd_time.c).
	 */
	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGALRM);
	(void) pthread_sigmask(SIG_UNBLOCK, &set, NULL);
	(void) pthread_mutex_lock(&tmq->tmq_lock);

	for (;;) {
		while (!tmq->tmq_abort && fmd_list_next(&tmq->tmq_list) == NULL)
			(void) pthread_cond_wait(&tmq->tmq_cv, &tmq->tmq_lock);

		if (tmq->tmq_abort) {
			(void) pthread_mutex_unlock(&tmq->tmq_lock);
			return; /* abort timerq thread */
		}

		for (now = fmd_time_gethrtime(); (tp = fmd_list_next(
		    &tmq->tmq_list)) != NULL; now = fmd_time_gethrtime()) {

			if (now == INT64_MAX || tp->tmr_hrt > now)
				break; /* no more timers left to expire */

			tp->tmr_id = -tp->tmr_id;
			fmd_list_delete(&tmq->tmq_list, tp);
			(void) pthread_mutex_unlock(&tmq->tmq_lock);

			TRACE((FMD_DBG_TMR, "tmr %s:%ld exec start (hrt=%llx)",
			    tp->tmr_ids->ids_name, -tp->tmr_id, tp->tmr_hrt));

			tp->tmr_func(tp->tmr_arg, -tp->tmr_id, tp->tmr_hrt);

			TRACE((FMD_DBG_TMR, "tmr %s:%ld exec end",
			    tp->tmr_ids->ids_name, -tp->tmr_id));

			(void) pthread_mutex_lock(&tmq->tmq_lock);
			(void) fmd_idspace_free(tp->tmr_ids, -tp->tmr_id);
			fmd_list_append(&tmq->tmq_free, tp);
			tp->tmr_id = 0; /* for fmd_timer_remove() */

			(void) pthread_cond_broadcast(&tp->tmr_cv);
		}

		if (tp != NULL) {
			(void) pthread_mutex_unlock(&tmq->tmq_lock);
			fmd_time_waithrtime(tp->tmr_hrt - now);
			(void) pthread_mutex_lock(&tmq->tmq_lock);
		}
	}
}

static void
fmd_timerq_alrm(int sig)
{
	TRACE((FMD_DBG_TMR, "timer thread received alarm sig#%d", sig));
}

fmd_timerq_t *
fmd_timerq_create(void)
{
	fmd_timerq_t *tmq = fmd_zalloc(sizeof (fmd_timerq_t), FMD_SLEEP);
	struct sigaction act;

	(void) pthread_mutex_init(&tmq->tmq_lock, NULL);
	(void) pthread_cond_init(&tmq->tmq_cv, NULL);

	act.sa_handler = fmd_timerq_alrm;
	act.sa_flags = 0;
	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(SIGALRM, &act, NULL);

	if ((tmq->tmq_thread = fmd_thread_create(fmd.d_rmod,
	    (fmd_thread_f *)fmd_timerq_exec, tmq)) == NULL)
		fmd_panic("failed to create timer thread");

	return (tmq);
}

void
fmd_timerq_destroy(fmd_timerq_t *tmq)
{
	struct sigaction act;
	fmd_timer_t *tmr;

	(void) pthread_mutex_lock(&tmq->tmq_lock);
	tmq->tmq_abort++;

	if (fmd_list_next(&tmq->tmq_list) != NULL)
		fmd_time_waitcancel(tmq->tmq_thread->thr_tid);
	else
		(void) pthread_cond_signal(&tmq->tmq_cv);

	(void) pthread_mutex_unlock(&tmq->tmq_lock);
	fmd_thread_destroy(tmq->tmq_thread, FMD_THREAD_JOIN);
	(void) pthread_mutex_lock(&tmq->tmq_lock);

	while ((tmr = fmd_list_next(&tmq->tmq_list)) != NULL) {
		fmd_list_delete(&tmq->tmq_list, tmr);
		(void) fmd_idspace_free(tmr->tmr_ids, tmr->tmr_id);
		fmd_free(tmr, sizeof (fmd_timer_t));
	}

	while ((tmr = fmd_list_next(&tmq->tmq_free)) != NULL) {
		fmd_list_delete(&tmq->tmq_free, tmr);
		ASSERT(tmr->tmr_id == 0);
		fmd_free(tmr, sizeof (fmd_timer_t));
	}

	act.sa_handler = SIG_DFL;
	act.sa_flags = 0;
	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(SIGALRM, &act, NULL);

	fmd_free(tmq, sizeof (fmd_timerq_t));
}
