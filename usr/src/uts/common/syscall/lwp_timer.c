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

#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/mutex.h>
#include <sys/atomic.h>
#include <sys/timer.h>
#include <sys/lwp_timer_impl.h>
#include <sys/callo.h>

/*
 * lwp_timer_timeout() is called from a timeout set up in lwp_cond_wait(),
 * lwp_mutex_timedlock(), lwp_sema_timedwait() or lwp_rwlock_lock().
 *
 * It recomputes the time remaining until the absolute time when the
 * wait is supposed to timeout and either calls realtime_timeout()
 * to reschedule itself or calls setrun() on the sleeping thread.
 *
 * This is done to ensure that the waiting thread does not wake up
 * due to timer expiration until the absolute future time of the
 * timeout has been reached.  Until that time, the thread must
 * remain on its sleep queue.
 *
 * An lwp_timer_t structure is used to pass information
 * about the sleeping thread to the timeout function.
 */

static void
lwp_timer_timeout(void *arg)
{
	lwp_timer_t *lwptp = arg;
	kthread_t *t = lwptp->lwpt_thread;
	timespec_t now, delta;

	mutex_enter(&t->t_delay_lock);
	gethrestime(&now);
	/*
	 * Requeue the timeout if no one has reset the system time
	 * and if the absolute future time has not been reached.
	 */
	if (lwptp->lwpt_timecheck == timechanged &&
	    (lwptp->lwpt_rqtime.tv_sec > now.tv_sec ||
	    (lwptp->lwpt_rqtime.tv_sec == now.tv_sec &&
	    lwptp->lwpt_rqtime.tv_nsec > now.tv_nsec))) {
		lwptp->lwpt_imm_timeout = 0;
		delta = lwptp->lwpt_rqtime;
		timespecsub(&delta, &now);
		lwptp->lwpt_id = timeout_generic(CALLOUT_REALTIME,
		    lwp_timer_timeout, lwptp, ts2hrt(&delta), nsec_per_tick,
		    (CALLOUT_FLAG_HRESTIME | CALLOUT_FLAG_ROUNDUP));
	} else {
		/*
		 * Set the thread running only if it is asleep on
		 * its lwpchan sleep queue (not if it is asleep on
		 * the t_delay_lock mutex).
		 */
		thread_lock(t);
		/* do this for the benefit of upi mutexes */
		(void) atomic_cas_uint(&lwptp->lwpt_imm_timeout, 0, 1);
		if (t->t_state == TS_SLEEP &&
		    (t->t_flag & T_WAKEABLE) &&
		    t->t_wchan0 != NULL)
			setrun_locked(t);
		thread_unlock(t);
	}
	mutex_exit(&t->t_delay_lock);
}

int
lwp_timer_copyin(lwp_timer_t *lwptp, timespec_t *tsp)
{
	timespec_t now;
	int error = 0;

	if (tsp == NULL)	/* not really an error, just need to bzero() */
		goto err;
	lwptp->lwpt_timecheck = timechanged; /* do this before gethrestime() */
	gethrestime(&now);		/* do this before copyin() */
	if (curproc->p_model == DATAMODEL_NATIVE) {
		if (copyin(tsp, &lwptp->lwpt_rqtime, sizeof (timespec_t))) {
			error = EFAULT;
			goto err;
		}
	} else {
		timespec32_t ts32;
		if (copyin(tsp, &ts32, sizeof (timespec32_t))) {
			error = EFAULT;
			goto err;
		}
		TIMESPEC32_TO_TIMESPEC(&lwptp->lwpt_rqtime, &ts32);
	}
	if (itimerspecfix(&lwptp->lwpt_rqtime)) {
		error = EINVAL;
		goto err;
	}
	/*
	 * Unless the requested timeout is zero,
	 * get the precise future (absolute) time at
	 * which we are to time out and return ETIME.
	 * We must not return ETIME before that time.
	 */
	if (lwptp->lwpt_rqtime.tv_sec == 0 && lwptp->lwpt_rqtime.tv_nsec == 0) {
		bzero(lwptp, sizeof (lwp_timer_t));
		lwptp->lwpt_imm_timeout = 1;
	} else {
		lwptp->lwpt_thread = curthread;
		lwptp->lwpt_tsp = tsp;
		lwptp->lwpt_time_error = 0;
		lwptp->lwpt_id = 0;
		lwptp->lwpt_imm_timeout = 0;
		timespecadd(&lwptp->lwpt_rqtime, &now);
	}
	return (0);
err:
	bzero(lwptp, sizeof (lwp_timer_t));
	lwptp->lwpt_time_error = error;
	return (error);
}

int
lwp_timer_enqueue(lwp_timer_t *lwptp)
{
	timespec_t now, delta;

	ASSERT(lwptp->lwpt_thread == curthread);
	ASSERT(MUTEX_HELD(&curthread->t_delay_lock));
	gethrestime(&now);
	if (lwptp->lwpt_timecheck == timechanged &&
	    (lwptp->lwpt_rqtime.tv_sec > now.tv_sec ||
	    (lwptp->lwpt_rqtime.tv_sec == now.tv_sec &&
	    lwptp->lwpt_rqtime.tv_nsec > now.tv_nsec))) {
		/*
		 * Queue the timeout.
		 */
		lwptp->lwpt_imm_timeout = 0;
		delta = lwptp->lwpt_rqtime;
		timespecsub(&delta, &now);
		lwptp->lwpt_id = timeout_generic(CALLOUT_REALTIME,
		    lwp_timer_timeout, lwptp, ts2hrt(&delta), nsec_per_tick,
		    (CALLOUT_FLAG_HRESTIME | CALLOUT_FLAG_ROUNDUP));
		return (0);
	}

	/*
	 * Time has already run out or someone reset the system time;
	 * just cause an immediate timeout.
	 */
	lwptp->lwpt_imm_timeout = 1;
	return (1);
}

clock_t
lwp_timer_dequeue(lwp_timer_t *lwptp)
{
	kthread_t *t = curthread;
	clock_t tim = -1;
	callout_id_t tmp_id;

	mutex_enter(&t->t_delay_lock);
	while ((tmp_id = lwptp->lwpt_id) != 0) {
		lwptp->lwpt_id = 0;
		mutex_exit(&t->t_delay_lock);
		tim = untimeout_default(tmp_id, 0);
		mutex_enter(&t->t_delay_lock);
	}
	mutex_exit(&t->t_delay_lock);
	return (tim);
}

int
lwp_timer_copyout(lwp_timer_t *lwptp, int error)
{
	timespec_t rmtime;
	timespec_t now;

	if (lwptp->lwpt_tsp == NULL)	/* nothing to do */
		return (error);

	rmtime.tv_sec = rmtime.tv_nsec = 0;
	if (error != ETIME) {
		gethrestime(&now);
		if ((now.tv_sec < lwptp->lwpt_rqtime.tv_sec) ||
		    ((now.tv_sec == lwptp->lwpt_rqtime.tv_sec) &&
		    (now.tv_nsec < lwptp->lwpt_rqtime.tv_nsec))) {
			rmtime = lwptp->lwpt_rqtime;
			timespecsub(&rmtime, &now);
		}
	}
	if (curproc->p_model == DATAMODEL_NATIVE) {
		if (copyout(&rmtime, lwptp->lwpt_tsp, sizeof (timespec_t)))
			error = EFAULT;
	} else {
		timespec32_t rmtime32;

		TIMESPEC_TO_TIMESPEC32(&rmtime32, &rmtime);
		if (copyout(&rmtime32, lwptp->lwpt_tsp, sizeof (timespec32_t)))
			error = EFAULT;
	}

	return (error);
}
