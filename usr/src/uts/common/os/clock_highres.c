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
 * Copyright (c) 2012, Joyent Inc. All rights reserved.
 */

#include <sys/timer.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/cyclic.h>
#include <sys/cmn_err.h>
#include <sys/pset.h>
#include <sys/atomic.h>
#include <sys/policy.h>

static clock_backend_t clock_highres;

/*ARGSUSED*/
static int
clock_highres_settime(timespec_t *ts)
{
	return (EINVAL);
}

static int
clock_highres_gettime(timespec_t *ts)
{
	hrt2ts(gethrtime(), (timestruc_t *)ts);

	return (0);
}

static int
clock_highres_getres(timespec_t *ts)
{
	hrt2ts(cyclic_getres(), (timestruc_t *)ts);

	return (0);
}

/*ARGSUSED*/
static int
clock_highres_timer_create(itimer_t *it, struct sigevent *ev)
{
	/*
	 * CLOCK_HIGHRES timers of sufficiently high resolution can deny
	 * service; only allow privileged users to create such timers.
	 * Sites that do not wish to have this restriction should
	 * give users the "proc_clock_highres" privilege.
	 */
	if (secpolicy_clock_highres(CRED()) != 0) {
		it->it_arg = NULL;
		return (EPERM);
	}

	it->it_arg = kmem_zalloc(sizeof (cyclic_id_t), KM_SLEEP);

	return (0);
}

static void
clock_highres_fire(void *arg)
{
	itimer_t *it = (itimer_t *)arg;
	hrtime_t *addr = &it->it_hrtime;
	hrtime_t old = *addr, new = gethrtime();

	do {
		old = *addr;
	} while (cas64((uint64_t *)addr, old, new) != old);

	timer_fire(it);
}

static int
clock_highres_timer_settime(itimer_t *it, int flags,
	const struct itimerspec *when)
{
	cyclic_id_t cyc, *cycp = it->it_arg;
	proc_t *p = curproc;
	kthread_t *t = curthread;
	cyc_time_t cyctime;
	cyc_handler_t hdlr;
	cpu_t *cpu;
	cpupart_t *cpupart;
	int pset;

	cyctime.cyt_when = ts2hrt(&when->it_value);
	cyctime.cyt_interval = ts2hrt(&when->it_interval);

	if (cyctime.cyt_when != 0 && cyctime.cyt_interval == 0 &&
	    it->it_itime.it_interval.tv_sec == 0 &&
	    it->it_itime.it_interval.tv_nsec == 0 &&
	    (cyc = *cycp) != CYCLIC_NONE) {
		/*
		 * If our existing timer is a one-shot and our new timer is a
		 * one-shot, we'll save ourselves a world of grief and just
		 * reprogram the cyclic.
		 */
		it->it_itime = *when;

		if (!(flags & TIMER_ABSTIME))
			cyctime.cyt_when += gethrtime();

		hrt2ts(cyctime.cyt_when, &it->it_itime.it_value);
		(void) cyclic_reprogram(cyc, cyctime.cyt_when);
		return (0);
	}

	mutex_enter(&cpu_lock);
	if ((cyc = *cycp) != CYCLIC_NONE) {
		cyclic_remove(cyc);
		*cycp = CYCLIC_NONE;
	}

	if (cyctime.cyt_when == 0) {
		mutex_exit(&cpu_lock);
		return (0);
	}

	if (!(flags & TIMER_ABSTIME))
		cyctime.cyt_when += gethrtime();

	/*
	 * Now we will check for overflow (that is, we will check to see
	 * that the start time plus the interval time doesn't exceed
	 * INT64_MAX).  The astute code reviewer will observe that this
	 * one-time check doesn't guarantee that a future expiration
	 * will not wrap.  We wish to prove, then, that if a future
	 * expiration does wrap, the earliest the problem can be encountered
	 * is (INT64_MAX / 2) nanoseconds (191 years) after boot.  Formally:
	 *
	 *  Given:	s + i < m	s > 0	i > 0
	 *		s + ni > m	n > 1
	 *
	 *    (where "s" is the start time, "i" is the interval, "n" is the
	 *    number of times the cyclic has fired and "m" is INT64_MAX)
	 *
	 *  Prove:
	 *		(a)  s + (n - 1)i > (m / 2)
	 *		(b)  s + (n - 1)i < m
	 *
	 * That is, prove that we must have fired at least once 191 years
	 * after boot.  The proof is very straightforward; since the left
	 * side of (a) is minimized when i is small, it is sufficient to show
	 * that the statement is true for i's smallest possible value
	 * (((m - s) / n) + epsilon).  The same goes for (b); showing that the
	 * statement is true for i's largest possible value (m - s + epsilon)
	 * is sufficient to prove the statement.
	 *
	 * The actual arithmetic manipulation is left up to reader.
	 */
	if (cyctime.cyt_when > INT64_MAX - cyctime.cyt_interval) {
		mutex_exit(&cpu_lock);
		return (EOVERFLOW);
	}

	if (cyctime.cyt_interval == 0) {
		/*
		 * If this is a one-shot, then we set the interval to be
		 * inifinite.  If this timer is never touched, this cyclic will
		 * simply consume space in the cyclic subsystem.  As soon as
		 * timer_settime() or timer_delete() is called, the cyclic is
		 * removed (so it's not possible to run the machine out
		 * of resources by creating one-shots).
		 */
		cyctime.cyt_interval = CY_INFINITY;
	}

	it->it_itime = *when;

	hrt2ts(cyctime.cyt_when, &it->it_itime.it_value);

	hdlr.cyh_func = (cyc_func_t)clock_highres_fire;
	hdlr.cyh_arg = it;
	hdlr.cyh_level = CY_LOW_LEVEL;

	if (cyctime.cyt_when != 0)
		*cycp = cyc = cyclic_add(&hdlr, &cyctime);

	/*
	 * Now that we have the cyclic created, we need to bind it to our
	 * bound CPU and processor set (if any).
	 */
	mutex_enter(&p->p_lock);
	cpu = t->t_bound_cpu;
	cpupart = t->t_cpupart;
	pset = t->t_bind_pset;

	mutex_exit(&p->p_lock);

	cyclic_bind(cyc, cpu, pset == PS_NONE ? NULL : cpupart);

	mutex_exit(&cpu_lock);

	return (0);
}

static int
clock_highres_timer_gettime(itimer_t *it, struct itimerspec *when)
{
	/*
	 * CLOCK_HIGHRES doesn't update it_itime.
	 */
	hrtime_t start = ts2hrt(&it->it_itime.it_value);
	hrtime_t interval = ts2hrt(&it->it_itime.it_interval);
	hrtime_t diff, now = gethrtime();
	hrtime_t *addr = &it->it_hrtime;
	hrtime_t last;

	/*
	 * We're using cas64() here only to assure that we slurp the entire
	 * timestamp atomically.
	 */
	last = cas64((uint64_t *)addr, 0, 0);

	*when = it->it_itime;

	if (!timerspecisset(&when->it_value))
		return (0);

	if (start > now) {
		/*
		 * We haven't gone off yet...
		 */
		diff = start - now;
	} else {
		if (interval == 0) {
			/*
			 * This is a one-shot which should have already
			 * fired; set it_value to 0.
			 */
			timerspecclear(&when->it_value);
			return (0);
		}

		/*
		 * Calculate how far we are into this interval.
		 */
		diff = (now - start) % interval;

		/*
		 * Now check to see if we've dealt with the last interval
		 * yet.
		 */
		if (now - diff > last) {
			/*
			 * The last interval hasn't fired; set it_value to 0.
			 */
			timerspecclear(&when->it_value);
			return (0);
		}

		/*
		 * The last interval _has_ fired; we can return the amount
		 * of time left in this interval.
		 */
		diff = interval - diff;
	}

	hrt2ts(diff, &when->it_value);

	return (0);
}

static int
clock_highres_timer_delete(itimer_t *it)
{
	cyclic_id_t cyc;

	if (it->it_arg == NULL) {
		/*
		 * This timer was never fully created; we must have failed
		 * in the clock_highres_timer_create() routine.
		 */
		return (0);
	}

	mutex_enter(&cpu_lock);

	if ((cyc = *((cyclic_id_t *)it->it_arg)) != CYCLIC_NONE)
		cyclic_remove(cyc);

	mutex_exit(&cpu_lock);

	kmem_free(it->it_arg, sizeof (cyclic_id_t));

	return (0);
}

static void
clock_highres_timer_lwpbind(itimer_t *it)
{
	proc_t *p = curproc;
	kthread_t *t = curthread;
	cyclic_id_t cyc = *((cyclic_id_t *)it->it_arg);
	cpu_t *cpu;
	cpupart_t *cpupart;
	int pset;

	if (cyc == CYCLIC_NONE)
		return;

	mutex_enter(&cpu_lock);
	mutex_enter(&p->p_lock);

	/*
	 * Okay, now we can safely look at the bindings.
	 */
	cpu = t->t_bound_cpu;
	cpupart = t->t_cpupart;
	pset = t->t_bind_pset;

	/*
	 * Now we drop p_lock.  We haven't dropped cpu_lock; we're guaranteed
	 * that even if the bindings change, the CPU and/or processor set
	 * that this timer was bound to remain valid (and the combination
	 * remains self-consistent).
	 */
	mutex_exit(&p->p_lock);

	cyclic_bind(cyc, cpu, pset == PS_NONE ? NULL : cpupart);

	mutex_exit(&cpu_lock);
}

void
clock_highres_init()
{
	clock_backend_t *be = &clock_highres;
	struct sigevent *ev = &be->clk_default;

	ev->sigev_signo = SIGALRM;
	ev->sigev_notify = SIGEV_SIGNAL;
	ev->sigev_value.sival_ptr = NULL;

	be->clk_clock_settime = clock_highres_settime;
	be->clk_clock_gettime = clock_highres_gettime;
	be->clk_clock_getres = clock_highres_getres;
	be->clk_timer_create = clock_highres_timer_create;
	be->clk_timer_gettime = clock_highres_timer_gettime;
	be->clk_timer_settime = clock_highres_timer_settime;
	be->clk_timer_delete = clock_highres_timer_delete;
	be->clk_timer_lwpbind = clock_highres_timer_lwpbind;

	clock_add_backend(CLOCK_HIGHRES, &clock_highres);
}
