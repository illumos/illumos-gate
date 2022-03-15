/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Oxide Computer Company
 */

/*
 * This clock backend implements basic support for the CLOCK_PROCESS_CPUTIME_ID
 * clock. This clock is weakly defined by POSIX as "The identifier of the
 * CPU-time clock associated with the process making a clock() or timer*()
 * function call". We interpret that as including LMS_USER, LMS_SYSTEM, and
 * LMS_TRAP microstates. This is similar to what we do in proc(5) for the
 * lwpstatus_t and the prstatus_t.
 *
 * At this time, we only provide the ability to read the current time (e.g.
 * through a call to clock_gettime(3C)). There is never a case where being able
 * to set the time makes sense today and even if so, the privileges required for
 * that are circumspect. Today, we do not support the ability to create interval
 * timers based on this backend (e.g. timer_create(3C) and timer_settime(3C)).
 * However, there is no reason that couldn't be added.
 *
 * To implement this, we leverage the existing microstate aggregation time that
 * is done in /proc.
 */

#include <sys/timer.h>
#include <sys/cyclic.h>
#include <sys/msacct.h>

static clock_backend_t clock_process;

static int
clock_process_settime(timespec_t *ts)
{
	return (EINVAL);
}

static int
clock_process_gettime(timespec_t *ts)
{
	hrtime_t hrt;
	proc_t *p = curproc;

	/*
	 * mstate_aggr_state() automatically includes LMS_TRAP when we ask for
	 * LMS_SYSTEM below.
	 */
	mutex_enter(&p->p_lock);
	hrt = mstate_aggr_state(p, LMS_USER);
	hrt += mstate_aggr_state(p, LMS_SYSTEM);
	mutex_exit(&p->p_lock);

	hrt2ts(hrt, ts);

	return (0);
}

/*
 * See the discussion in clock_thread_getres() for the why of using
 * cyclic_getres() here.
 */
static int
clock_process_getres(timespec_t *ts)
{
	hrt2ts(cyclic_getres(), (timestruc_t *)ts);

	return (0);
}

static int
clock_process_timer_create(itimer_t *it, void (*fire)(itimer_t *))
{
	return (EINVAL);
}

static int
clock_process_timer_settime(itimer_t *it, int flags,
    const struct itimerspec *when)
{
	return (EINVAL);
}

static int
clock_process_timer_gettime(itimer_t *it, struct itimerspec *when)
{
	return (EINVAL);
}

static int
clock_process_timer_delete(itimer_t *it)
{
	return (EINVAL);
}

static void
clock_process_timer_lwpbind(itimer_t *it)
{
}

void
clock_process_init(void)
{
	/*
	 * While this clock backend doesn't support notifications right now, we
	 * still fill out the default for what it would be.
	 */
	clock_process.clk_default.sigev_signo = SIGALRM;
	clock_process.clk_default.sigev_notify = SIGEV_SIGNAL;
	clock_process.clk_default.sigev_value.sival_ptr = NULL;

	clock_process.clk_clock_settime = clock_process_settime;
	clock_process.clk_clock_gettime = clock_process_gettime;
	clock_process.clk_clock_getres = clock_process_getres;
	clock_process.clk_timer_create = clock_process_timer_create;
	clock_process.clk_timer_settime = clock_process_timer_settime;
	clock_process.clk_timer_gettime = clock_process_timer_gettime;
	clock_process.clk_timer_delete = clock_process_timer_delete;
	clock_process.clk_timer_lwpbind = clock_process_timer_lwpbind;

	clock_add_backend(CLOCK_PROCESS_CPUTIME_ID, &clock_process);
}
