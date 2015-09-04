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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2015, Joyent Inc. All rights reserved.
 */

#include <sys/timer.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/debug.h>

static clock_backend_t clock_realtime;

static int
clock_realtime_settime(timespec_t *ts)
{
	mutex_enter(&tod_lock);
	tod_set(*ts);
	set_hrestime(ts);
	mutex_exit(&tod_lock);

	return (0);
}

/*
 * We normally won't execute this path; libc will see CLOCK_REALTIME and
 * fast trap directly into gethrestime().
 */
static int
clock_realtime_gettime(timespec_t *ts)
{
	gethrestime(ts);

	return (0);
}

static int
clock_realtime_getres(timespec_t *ts)
{
	ts->tv_sec = 0;
	ts->tv_nsec = nsec_per_tick;

	return (0);
}

static void
clock_realtime_fire(void *arg)
{
	int cnt2nth;
	itimer_t *it = (itimer_t *)arg;
	timeout_id_t *tidp = it->it_arg;
	timespec_t now, interval2nth;
	timespec_t *val, *interval;
	proc_t *p = it->it_proc;
	clock_t ticks;

	/*
	 * First call into the timer subsystem to get the signal going.
	 */
	it->it_fire(it);
	val = &it->it_itime.it_value;
	interval = &it->it_itime.it_interval;

	mutex_enter(&p->p_lock);

	if (!timerspecisset(interval)) {
		timerspecclear(val);
		*tidp = 0;
	} else {
		/*
		 * If this is an interval timer, we need to determine a time
		 * at which to go off in the future.  In the event that the
		 * clock has been adjusted, we want to find our new interval
		 * relatively quickly (and we don't want to simply take the
		 * current time and add the interval; it would lead to
		 * unnecessary jitter in the timer).  We therefore take steps
		 * from the time we expected to go off into the future;
		 * if the resulting time is still in the past, then we double
		 * our step size and continue.  Once the resulting time is
		 * in the future, we subtract our last step, change our step
		 * size back to the original interval, and repeat until we
		 * can get to a valid, future timeout in one step.  This
		 * assures that we will get the minimum, valid timeout
		 * value in a reasonable amount of wall time.
		 */
		for (;;) {
			interval2nth = *interval;

			/*
			 * We put a floor on interval2nth at nsec_per_tick.
			 * If we don't do this, and the interval is shorter
			 * than the time required to run through this logic,
			 * we'll never catch up to the current time (which
			 * is a moving target).
			 */
			if (interval2nth.tv_sec == 0 &&
			    interval2nth.tv_nsec < nsec_per_tick)
				interval2nth.tv_nsec = nsec_per_tick;

			for (cnt2nth = 0; ; cnt2nth++) {
				timespecadd(val, &interval2nth);
				gethrestime(&now);
				if (timerspeccmp(val, &now) > 0)
					break;
				timespecadd(&interval2nth, &interval2nth);
			}
			if (cnt2nth == 0)
				break;
			timespecsub(val, &interval2nth);
		}

		ticks = timespectohz(val, now);
		*tidp = realtime_timeout(clock_realtime_fire, it, ticks);
	}
	mutex_exit(&p->p_lock);
}

/*
 * See the block comment in clock_realtime_timer_settime(), below.
 */
static void
clock_realtime_fire_first(void *arg)
{
	itimer_t *it = (itimer_t *)arg;
	timespec_t now;
	timespec_t *val = &it->it_itime.it_value;
	timeout_id_t *tidp = it->it_arg;
	proc_t *p = it->it_proc;

	gethrestime(&now);

	if ((val->tv_sec > now.tv_sec) ||
	    (val->tv_sec == now.tv_sec && val->tv_nsec > now.tv_nsec)) {
		/*
		 * We went off too early.  We'll go to bed for one more tick,
		 * regardless of the actual difference; if the difference
		 * is greater than one tick, then we must have seen an adjtime.
		 */
		mutex_enter(&p->p_lock);
		*tidp = realtime_timeout(clock_realtime_fire, it, 1);
		mutex_exit(&p->p_lock);
		return;
	}

	clock_realtime_fire(arg);
}

/*ARGSUSED*/
static int
clock_realtime_timer_create(itimer_t *it, void (*fire)(itimer_t *))
{
	it->it_arg = kmem_zalloc(sizeof (timeout_id_t), KM_SLEEP);
	it->it_fire = fire;

	return (0);
}

static int
clock_realtime_timer_settime(itimer_t *it, int flags,
	const struct itimerspec *when)
{
	timeout_id_t tid, *tidp = it->it_arg;
	timespec_t now;
	proc_t *p = it->it_proc;
	clock_t ticks;

	gethrestime(&now);

	mutex_enter(&p->p_lock);

	while ((tid = *tidp) != 0) {
		*tidp = 0;
		mutex_exit(&p->p_lock);
		(void) untimeout(tid);
		mutex_enter(&p->p_lock);
	}

	/*
	 * The timeout has been removed; it is safe to update it_itime.
	 */
	it->it_itime = *when;

	if (timerspecisset(&it->it_itime.it_value)) {
		if (!(flags & TIMER_ABSTIME))
			timespecadd(&it->it_itime.it_value, &now);

		ticks = timespectohz(&it->it_itime.it_value, now);

		/*
		 * gethrestime() works by reading hres_last_tick, and
		 * adding in the current time delta (that is, the amount of
		 * time which has passed since the last tick of the clock).
		 * As a result, the time returned in "now", above, represents
		 * an hrestime sometime after lbolt was last bumped.
		 * The "ticks" we've been returned from timespectohz(), then,
		 * reflects the number of times the clock will tick between
		 * "now" and our desired execution time.
		 *
		 * However, when we call into realtime_timeout(), below,
		 * "ticks" will be interpreted against lbolt.  That is,
		 * if we specify 1 tick, we will be registering a callout
		 * for the next tick of the clock -- which may occur in
		 * less than (1 / hz) seconds.  More generally, we are
		 * registering a callout for "ticks" of the clock, which
		 * may be less than ("ticks" / hz) seconds (but not more than
		 * (1 / hz) seconds less).  In other words, we may go off
		 * early.
		 *
		 * This is only a problem for the initial firing of the
		 * timer, so we have the initial firing go through a
		 * different handler which implements a nanosleep-esque
		 * algorithm.
		 */
		*tidp = realtime_timeout(clock_realtime_fire_first, it, ticks);
	}

	mutex_exit(&p->p_lock);

	return (0);
}

static int
clock_realtime_timer_gettime(itimer_t *it, struct itimerspec *when)
{
	timespec_t now;
	proc_t *p = it->it_proc;

	/*
	 * We always keep it_itime up to date, so we just need to snapshot
	 * the time under p_lock, and clean it up.
	 */
	mutex_enter(&p->p_lock);
	gethrestime(&now);
	*when = it->it_itime;
	mutex_exit(&p->p_lock);

	if (!timerspecisset(&when->it_value))
		return (0);

	if (timerspeccmp(&when->it_value, &now) < 0) {
		/*
		 * If this timer should have already gone off, set it_value
		 * to 0.
		 */
		timerspecclear(&when->it_value);
	} else {
		timespecsub(&when->it_value, &now);
	}

	return (0);
}

static int
clock_realtime_timer_delete(itimer_t *it)
{
	proc_t *p = it->it_proc;
	timeout_id_t tid, *tidp = it->it_arg;

	mutex_enter(&p->p_lock);

	while ((tid = *tidp) != 0) {
		*tidp = 0;
		mutex_exit(&p->p_lock);
		(void) untimeout(tid);
		mutex_enter(&p->p_lock);
	}

	mutex_exit(&p->p_lock);

	kmem_free(tidp, sizeof (timeout_id_t));

	return (0);
}

/*ARGSUSED*/
void
clock_realtime_timer_lwpbind(itimer_t *it)
{
}

void
clock_realtime_init()
{
	clock_backend_t *be = &clock_realtime;
	struct sigevent *ev = &be->clk_default;

	ev->sigev_signo = SIGALRM;
	ev->sigev_notify = SIGEV_SIGNAL;
	ev->sigev_value.sival_ptr = NULL;

	be->clk_clock_settime = clock_realtime_settime;
	be->clk_clock_gettime = clock_realtime_gettime;
	be->clk_clock_getres = clock_realtime_getres;
	be->clk_timer_gettime = clock_realtime_timer_gettime;
	be->clk_timer_settime = clock_realtime_timer_settime;
	be->clk_timer_delete = clock_realtime_timer_delete;
	be->clk_timer_lwpbind = clock_realtime_timer_lwpbind;
	be->clk_timer_create = clock_realtime_timer_create;
	clock_add_backend(CLOCK_REALTIME, &clock_realtime);
	/*
	 * For binary compatibility with old statically linked
	 * applications, we make the behavior of __CLOCK_REALTIME0
	 * the same as CLOCK_REALTIME.
	 */
	clock_add_backend(__CLOCK_REALTIME0, &clock_realtime);
}
