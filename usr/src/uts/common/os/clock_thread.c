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
 * This clock backend implements basic support for the following two clocks:
 *
 *   o CLOCK_VIRTUAL		This provides the ability to read the amount of
 *				user CPU time that the calling thread has spent
 *				on CPU. This is the LMS_USER cpu microstate.
 *
 *   o CLOCK_THREAD_CPUTIME_ID	This clock is similar to the above; however, it
 *				also includes system time. This is the LMS_USER,
 *				LMS_SYSTEM, and LMS_TRAP microstates combined
 *				together. We include LMS_TRAP here because that
 *				is what you see in a thread's lwpstatus file.
 *
 * At this time, we only provide the ability to read the current time (e.g.
 * through a call to clock_gettime(3C)). There is never a case where being able
 * to set the time makes sense today and truthfully, lying about a process's
 * runtime should be left to mdb -kw. Today, we do not support the ability to
 * create interval timers based on this backend (e.g. timer_create(3C) and
 * timer_settime(3C)). However, there is no reason that couldn't be added.
 *
 * A nice simplification here is that this clock is always about reading from
 * the current thread. This means that one can always access it. Because the
 * calling thread exists and is in this code, it means that we know it is here.
 * Any other privilege information is left to the broader kernel.
 *
 * Because the only difference between these is the question of whether or not
 * we include LMS_SYSTEM time in the value, we generally use the same actual
 * clock backend functions except for the one that implements
 * clk_clock_gettime().
 */

#include <sys/timer.h>
#include <sys/cyclic.h>
#include <sys/msacct.h>

static clock_backend_t clock_thread_usr;
static clock_backend_t clock_thread_usrsys;

static int
clock_thread_settime(timespec_t *ts)
{
	return (EINVAL);
}

static int
clock_thread_usr_gettime(timespec_t *ts)
{
	hrtime_t hrt;
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);

	hrt = lwp->lwp_mstate.ms_acct[LMS_USER];
	scalehrtime(&hrt);
	hrt2ts(hrt, ts);

	return (0);
}

static int
clock_thread_usrsys_gettime(timespec_t *ts)
{
	hrtime_t hrt;
	kthread_t *t = curthread;

	/*
	 * mstate_thread_onproc_time() takes care of doing the following:
	 *
	 *  o Combining LMS_USER, LMS_SYSTEM, and LMS_TRAP.
	 *  o Ensuring that the result is scaled
	 *  o Ensuring that the time that's elapsed to the point of our asking
	 *    is included. By definition the kernel is executing in LMS_SYSTEM
	 *    so this ensures that we add that time which isn't currently in the
	 *    microstate to this.
	 */
	thread_lock(t);
	hrt = mstate_thread_onproc_time(t);
	thread_unlock(t);

	hrt2ts(hrt, ts);
	return (0);
}

/*
 * The question of the resolution here is a thorny one. Technically this would
 * really be based upon the resolution of gethrtime_unscaled(), as we can
 * actually tell that much due to our use of CPU microstate accounting. However,
 * from a timer resolution perspective it's actually quite different and would
 * in theory be based on the system tick rate.
 *
 * This basically leaves us with two options:
 *
 *   1) Use 'nsec_per_tick' to go down the Hz path.
 *   2) Use the cyclic resolution, which basically is kind of the resolution of
 *      that timer.
 *
 * POSIX is unclear as to the effect of the resolution in the case of timer_*()
 * functions and only really says it is used to impact the implementation of
 * clock_settime() which of course isn't actually supported here. As a result,
 * we opt to prefer the cyclic resolution, which is closer to the actual
 * resolution of this subsystem. Strictly speaking, this might not be completely
 * accurate, but should be on current platforms.
 */
static int
clock_thread_getres(timespec_t *ts)
{
	hrt2ts(cyclic_getres(), (timestruc_t *)ts);

	return (0);
}

static int
clock_thread_timer_create(itimer_t *it, void (*fire)(itimer_t *))
{
	return (EINVAL);
}

static int
clock_thread_timer_settime(itimer_t *it, int flags,
    const struct itimerspec *when)
{
	return (EINVAL);
}

static int
clock_thread_timer_gettime(itimer_t *it, struct itimerspec *when)
{
	return (EINVAL);
}

static int
clock_thread_timer_delete(itimer_t *it)
{
	return (EINVAL);
}

static void
clock_thread_timer_lwpbind(itimer_t *it)
{
}

void
clock_thread_init(void)
{
	/*
	 * While this clock backends don't support notifications right now, we
	 * still fill out the default for what it would be.
	 */
	clock_thread_usr.clk_default.sigev_signo = SIGALRM;
	clock_thread_usr.clk_default.sigev_notify = SIGEV_SIGNAL;
	clock_thread_usr.clk_default.sigev_value.sival_ptr = NULL;

	clock_thread_usr.clk_clock_settime = clock_thread_settime;
	clock_thread_usr.clk_clock_gettime = clock_thread_usr_gettime;
	clock_thread_usr.clk_clock_getres = clock_thread_getres;
	clock_thread_usr.clk_timer_create = clock_thread_timer_create;
	clock_thread_usr.clk_timer_settime = clock_thread_timer_settime;
	clock_thread_usr.clk_timer_gettime = clock_thread_timer_gettime;
	clock_thread_usr.clk_timer_delete = clock_thread_timer_delete;
	clock_thread_usr.clk_timer_lwpbind = clock_thread_timer_lwpbind;

	clock_thread_usrsys.clk_default.sigev_signo = SIGALRM;
	clock_thread_usrsys.clk_default.sigev_notify = SIGEV_SIGNAL;
	clock_thread_usrsys.clk_default.sigev_value.sival_ptr = NULL;

	clock_thread_usrsys.clk_clock_settime = clock_thread_settime;
	clock_thread_usrsys.clk_clock_gettime = clock_thread_usrsys_gettime;
	clock_thread_usrsys.clk_clock_getres = clock_thread_getres;
	clock_thread_usrsys.clk_timer_create = clock_thread_timer_create;
	clock_thread_usrsys.clk_timer_settime = clock_thread_timer_settime;
	clock_thread_usrsys.clk_timer_gettime = clock_thread_timer_gettime;
	clock_thread_usrsys.clk_timer_delete = clock_thread_timer_delete;
	clock_thread_usrsys.clk_timer_lwpbind = clock_thread_timer_lwpbind;

	clock_add_backend(CLOCK_VIRTUAL, &clock_thread_usr);
	clock_add_backend(CLOCK_THREAD_CPUTIME_ID, &clock_thread_usrsys);
}
