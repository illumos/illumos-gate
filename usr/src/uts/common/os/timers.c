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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <sys/param.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/timer.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/cyclic.h>

static void	realitexpire(void *);
static void	realprofexpire(void *);
static void	timeval_advance(struct timeval *, struct timeval *);

kmutex_t tod_lock;	/* protects time-of-day stuff */

/*
 * Constant to define the minimum interval value of the ITIMER_REALPROF timer.
 * Value is in microseconds; defaults to 500 usecs.  Setting this value
 * significantly lower may allow for denial-of-service attacks.
 */
int itimer_realprof_minimum = 500;

/*
 * macro to compare a timeval to a timestruc
 */

#define	TVTSCMP(tvp, tsp, cmp) \
	/* CSTYLED */ \
	((tvp)->tv_sec cmp (tsp)->tv_sec || \
	((tvp)->tv_sec == (tsp)->tv_sec && \
	/* CSTYLED */ \
	(tvp)->tv_usec * 1000 cmp (tsp)->tv_nsec))

/*
 * Time of day and interval timer support.
 *
 * These routines provide the kernel entry points to get and set
 * the time-of-day and per-process interval timers.  Subroutines
 * here provide support for adding and subtracting timeval structures
 * and decrementing interval timers, optionally reloading the interval
 * timers when they expire.
 */

/*
 * SunOS function to generate monotonically increasing time values.
 */
void
uniqtime(struct timeval *tv)
{
	static struct timeval last;
	static int last_timechanged;
	timestruc_t ts;
	time_t sec;
	int usec, nsec;

	/*
	 * protect modification of last
	 */
	mutex_enter(&tod_lock);
	gethrestime(&ts);

	/*
	 * Fast algorithm to convert nsec to usec -- see hrt2ts()
	 * in common/os/timers.c for a full description.
	 */
	nsec = ts.tv_nsec;
	usec = nsec + (nsec >> 2);
	usec = nsec + (usec >> 1);
	usec = nsec + (usec >> 2);
	usec = nsec + (usec >> 4);
	usec = nsec - (usec >> 3);
	usec = nsec + (usec >> 2);
	usec = nsec + (usec >> 3);
	usec = nsec + (usec >> 4);
	usec = nsec + (usec >> 1);
	usec = nsec + (usec >> 6);
	usec = usec >> 10;
	sec = ts.tv_sec;

	/*
	 * If the system hres time has been changed since the last time
	 * we are called. then all bets are off; just update our
	 * local copy of timechanged and accept the reported time as is.
	 */
	if (last_timechanged != timechanged) {
		last_timechanged = timechanged;
	}
	/*
	 * Try to keep timestamps unique, but don't be obsessive about
	 * it in the face of large differences.
	 */
	else if ((sec <= last.tv_sec) &&	/* same or lower seconds, and */
	    ((sec != last.tv_sec) ||		/* either different second or */
	    (usec <= last.tv_usec)) &&		/* lower microsecond, and */
	    ((last.tv_sec - sec) <= 5)) {	/* not way back in time */
		sec = last.tv_sec;
		usec = last.tv_usec + 1;
		if (usec >= MICROSEC) {
			usec -= MICROSEC;
			sec++;
		}
	}
	last.tv_sec = sec;
	last.tv_usec = usec;
	mutex_exit(&tod_lock);

	tv->tv_sec = sec;
	tv->tv_usec = usec;
}

/*
 * Timestamps are exported from the kernel in several places.
 * Such timestamps are commonly used for either uniqueness or for
 * sequencing - truncation to 32-bits is fine for uniqueness,
 * but sequencing is going to take more work as we get closer to 2038!
 */
void
uniqtime32(struct timeval32 *tv32p)
{
	struct timeval tv;

	uniqtime(&tv);
	TIMEVAL_TO_TIMEVAL32(tv32p, &tv);
}

int
gettimeofday(struct timeval *tp)
{
	struct timeval atv;

	if (tp) {
		uniqtime(&atv);
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&atv, tp, sizeof (atv)))
				return (set_errno(EFAULT));
		} else {
			struct timeval32 tv32;

			if (TIMEVAL_OVERFLOW(&atv))
				return (set_errno(EOVERFLOW));
			TIMEVAL_TO_TIMEVAL32(&tv32, &atv);

			if (copyout(&tv32, tp, sizeof (tv32)))
				return (set_errno(EFAULT));
		}
	}
	return (0);
}

int
getitimer(uint_t which, struct itimerval *itv)
{
	int error;

	if (get_udatamodel() == DATAMODEL_NATIVE)
		error = xgetitimer(which, itv, 0);
	else {
		struct itimerval kitv;

		if ((error = xgetitimer(which, &kitv, 1)) == 0) {
			if (ITIMERVAL_OVERFLOW(&kitv)) {
				error = EOVERFLOW;
			} else {
				struct itimerval32 itv32;

				ITIMERVAL_TO_ITIMERVAL32(&itv32, &kitv);
				if (copyout(&itv32, itv, sizeof (itv32)) != 0)
					error = EFAULT;
			}
		}
	}

	return (error ? (set_errno(error)) : 0);
}

int
xgetitimer(uint_t which, struct itimerval *itv, int iskaddr)
{
	struct proc *p = curproc;
	struct timeval now;
	struct itimerval aitv;
	hrtime_t ts, first, interval, remain;

	mutex_enter(&p->p_lock);

	switch (which) {
	case ITIMER_VIRTUAL:
	case ITIMER_PROF:
		aitv = ttolwp(curthread)->lwp_timer[which];
		break;

	case ITIMER_REAL:
		uniqtime(&now);
		aitv = p->p_realitimer;

		if (timerisset(&aitv.it_value)) {
			/*CSTYLED*/
			if (timercmp(&aitv.it_value, &now, <)) {
				timerclear(&aitv.it_value);
			} else {
				timevalsub(&aitv.it_value, &now);
			}
		}
		break;

	case ITIMER_REALPROF:
		if (curproc->p_rprof_cyclic == CYCLIC_NONE) {
			bzero(&aitv, sizeof (aitv));
			break;
		}

		aitv = curproc->p_rprof_timer;

		first = tv2hrt(&aitv.it_value);
		interval = tv2hrt(&aitv.it_interval);

		if ((ts = gethrtime()) < first) {
			/*
			 * We haven't gone off for the first time; the time
			 * remaining is simply the first time we will go
			 * off minus the current time.
			 */
			remain = first - ts;
		} else {
			if (interval == 0) {
				/*
				 * This was set as a one-shot, and we've
				 * already gone off; there is no time
				 * remaining.
				 */
				remain = 0;
			} else {
				/*
				 * We have a non-zero interval; we need to
				 * determine how far we are into the current
				 * interval, and subtract that from the
				 * interval to determine the time remaining.
				 */
				remain = interval - ((ts - first) % interval);
			}
		}

		hrt2tv(remain, &aitv.it_value);
		break;

	default:
		mutex_exit(&p->p_lock);
		return (EINVAL);
	}

	mutex_exit(&p->p_lock);

	if (iskaddr) {
		bcopy(&aitv, itv, sizeof (*itv));
	} else {
		ASSERT(get_udatamodel() == DATAMODEL_NATIVE);
		if (copyout(&aitv, itv, sizeof (*itv)))
			return (EFAULT);
	}

	return (0);
}


int
setitimer(uint_t which, struct itimerval *itv, struct itimerval *oitv)
{
	int error;

	if (oitv != NULL)
		if ((error = getitimer(which, oitv)) != 0)
			return (error);

	if (itv == NULL)
		return (0);

	if (get_udatamodel() == DATAMODEL_NATIVE)
		error = xsetitimer(which, itv, 0);
	else {
		struct itimerval32 itv32;
		struct itimerval kitv;

		if (copyin(itv, &itv32, sizeof (itv32)))
			error = EFAULT;
		ITIMERVAL32_TO_ITIMERVAL(&kitv, &itv32);
		error = xsetitimer(which, &kitv, 1);
	}

	return (error ? (set_errno(error)) : 0);
}

int
xsetitimer(uint_t which, struct itimerval *itv, int iskaddr)
{
	struct itimerval aitv;
	struct timeval now;
	struct proc *p = curproc;
	kthread_t *t;
	timeout_id_t tmp_id;
	cyc_handler_t hdlr;
	cyc_time_t when;
	cyclic_id_t cyclic;
	hrtime_t ts;
	int min;

	if (itv == NULL)
		return (0);

	if (iskaddr) {
		bcopy(itv, &aitv, sizeof (aitv));
	} else {
		ASSERT(get_udatamodel() == DATAMODEL_NATIVE);
		if (copyin(itv, &aitv, sizeof (aitv)))
			return (EFAULT);
	}

	if (which == ITIMER_REALPROF) {
		min = MAX((int)(cyclic_getres() / (NANOSEC / MICROSEC)),
		    itimer_realprof_minimum);
	} else {
		min = usec_per_tick;
	}

	if (itimerfix(&aitv.it_value, min) ||
	    (itimerfix(&aitv.it_interval, min) && timerisset(&aitv.it_value)))
		return (EINVAL);

	mutex_enter(&p->p_lock);
	switch (which) {
	case ITIMER_REAL:
		/*
		 * The SITBUSY flag prevents conflicts with multiple
		 * threads attempting to perform setitimer(ITIMER_REAL)
		 * at the same time, even when we drop p->p_lock below.
		 * Any blocked thread returns successfully because the
		 * effect is the same as if it got here first, finished,
		 * and the other thread then came through and destroyed
		 * what it did.  We are just protecting the system from
		 * malfunctioning due to the race condition.
		 */
		if (p->p_flag & SITBUSY) {
			mutex_exit(&p->p_lock);
			return (0);
		}
		p->p_flag |= SITBUSY;
		while ((tmp_id = p->p_itimerid) != 0) {
			/*
			 * Avoid deadlock in callout_delete (called from
			 * untimeout) which may go to sleep (while holding
			 * p_lock). Drop p_lock and re-acquire it after
			 * untimeout returns. Need to clear p_itimerid
			 * while holding p_lock.
			 */
			p->p_itimerid = 0;
			mutex_exit(&p->p_lock);
			(void) untimeout(tmp_id);
			mutex_enter(&p->p_lock);
		}
		if (timerisset(&aitv.it_value)) {
			uniqtime(&now);
			timevaladd(&aitv.it_value, &now);
			p->p_itimerid = realtime_timeout(realitexpire,
			    p, hzto(&aitv.it_value));
		}
		p->p_realitimer = aitv;
		p->p_flag &= ~SITBUSY;
		break;

	case ITIMER_REALPROF:
		cyclic = p->p_rprof_cyclic;
		p->p_rprof_cyclic = CYCLIC_NONE;

		mutex_exit(&p->p_lock);

		/*
		 * We're now going to acquire cpu_lock, remove the old cyclic
		 * if necessary, and add our new cyclic.
		 */
		mutex_enter(&cpu_lock);

		if (cyclic != CYCLIC_NONE)
			cyclic_remove(cyclic);

		if (!timerisset(&aitv.it_value)) {
			/*
			 * If we were passed a value of 0, we're done.
			 */
			mutex_exit(&cpu_lock);
			return (0);
		}

		hdlr.cyh_func = realprofexpire;
		hdlr.cyh_arg = p;
		hdlr.cyh_level = CY_LOW_LEVEL;

		when.cyt_when = (ts = gethrtime() + tv2hrt(&aitv.it_value));
		when.cyt_interval = tv2hrt(&aitv.it_interval);

		if (when.cyt_interval == 0) {
			/*
			 * Using the same logic as for CLOCK_HIGHRES timers, we
			 * set the interval to be INT64_MAX - when.cyt_when to
			 * effect a one-shot; see the comment in clock_highres.c
			 * for more details on why this works.
			 */
			when.cyt_interval = INT64_MAX - when.cyt_when;
		}

		cyclic = cyclic_add(&hdlr, &when);

		mutex_exit(&cpu_lock);

		/*
		 * We have now successfully added the cyclic.  Reacquire
		 * p_lock, and see if anyone has snuck in.
		 */
		mutex_enter(&p->p_lock);

		if (p->p_rprof_cyclic != CYCLIC_NONE) {
			/*
			 * We're racing with another thread establishing an
			 * ITIMER_REALPROF interval timer.  We'll let the other
			 * thread win (this is a race at the application level,
			 * so letting the other thread win is acceptable).
			 */
			mutex_exit(&p->p_lock);
			mutex_enter(&cpu_lock);
			cyclic_remove(cyclic);
			mutex_exit(&cpu_lock);

			return (0);
		}

		/*
		 * Success.  Set our tracking variables in the proc structure,
		 * cancel any outstanding ITIMER_PROF, and allocate the
		 * per-thread SIGPROF buffers, if possible.
		 */
		hrt2tv(ts, &aitv.it_value);
		p->p_rprof_timer = aitv;
		p->p_rprof_cyclic = cyclic;

		t = p->p_tlist;
		do {
			struct itimerval *itvp;

			itvp = &ttolwp(t)->lwp_timer[ITIMER_PROF];
			timerclear(&itvp->it_interval);
			timerclear(&itvp->it_value);

			if (t->t_rprof != NULL)
				continue;

			t->t_rprof =
			    kmem_zalloc(sizeof (struct rprof), KM_NOSLEEP);
			aston(t);
		} while ((t = t->t_forw) != p->p_tlist);

		break;

	case ITIMER_VIRTUAL:
		ttolwp(curthread)->lwp_timer[ITIMER_VIRTUAL] = aitv;
		break;

	case ITIMER_PROF:
		if (p->p_rprof_cyclic != CYCLIC_NONE) {
			/*
			 * Silently ignore ITIMER_PROF if ITIMER_REALPROF
			 * is in effect.
			 */
			break;
		}

		ttolwp(curthread)->lwp_timer[ITIMER_PROF] = aitv;
		break;

	default:
		mutex_exit(&p->p_lock);
		return (EINVAL);
	}
	mutex_exit(&p->p_lock);
	return (0);
}

/*
 * Delete the ITIMER_REALPROF interval timer.
 * Called only from exec_args() when exec occurs.
 * The other ITIMER_* interval timers are specified
 * to be inherited across exec(), so leave them alone.
 */
void
delete_itimer_realprof(void)
{
	kthread_t *t = curthread;
	struct proc *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	cyclic_id_t cyclic;

	mutex_enter(&p->p_lock);

	/* we are performing execve(); assert we are single-threaded */
	ASSERT(t == p->p_tlist && t == t->t_forw);

	if ((cyclic = p->p_rprof_cyclic) == CYCLIC_NONE) {
		mutex_exit(&p->p_lock);
	} else {
		p->p_rprof_cyclic = CYCLIC_NONE;
		/*
		 * Delete any current instance of SIGPROF.
		 */
		if (lwp->lwp_cursig == SIGPROF) {
			lwp->lwp_cursig = 0;
			lwp->lwp_extsig = 0;
			if (lwp->lwp_curinfo) {
				siginfofree(lwp->lwp_curinfo);
				lwp->lwp_curinfo = NULL;
			}
		}
		/*
		 * Delete any pending instances of SIGPROF.
		 */
		sigdelset(&p->p_sig, SIGPROF);
		sigdelset(&p->p_extsig, SIGPROF);
		sigdelq(p, NULL, SIGPROF);
		sigdelset(&t->t_sig, SIGPROF);
		sigdelset(&t->t_extsig, SIGPROF);
		sigdelq(p, t, SIGPROF);

		mutex_exit(&p->p_lock);

		/*
		 * Remove the ITIMER_REALPROF cyclic.
		 */
		mutex_enter(&cpu_lock);
		cyclic_remove(cyclic);
		mutex_exit(&cpu_lock);
	}
}

/*
 * Real interval timer expired:
 * send process whose timer expired an alarm signal.
 * If time is not set up to reload, then just return.
 * Else compute next time timer should go off which is > current time.
 * This is where delay in processing this timeout causes multiple
 * SIGALRM calls to be compressed into one.
 */
static void
realitexpire(void *arg)
{
	struct proc *p = arg;
	struct timeval *valp = &p->p_realitimer.it_value;
	struct timeval *intervalp = &p->p_realitimer.it_interval;
#if !defined(_LP64)
	clock_t	ticks;
#endif

	mutex_enter(&p->p_lock);
#if !defined(_LP64)
	if ((ticks = hzto(valp)) > 1) {
		/*
		 * If we are executing before we were meant to, it must be
		 * because of an overflow in a prior hzto() calculation.
		 * In this case, we want to go to sleep for the recalculated
		 * number of ticks. For the special meaning of the value "1"
		 * see comment in timespectohz().
		 */
		p->p_itimerid = realtime_timeout(realitexpire, p, ticks);
		mutex_exit(&p->p_lock);
		return;
	}
#endif
	sigtoproc(p, NULL, SIGALRM);
	if (!timerisset(intervalp)) {
		timerclear(valp);
		p->p_itimerid = 0;
	} else {
		/* advance timer value past current time */
		timeval_advance(valp, intervalp);
		p->p_itimerid = realtime_timeout(realitexpire, p, hzto(valp));
	}
	mutex_exit(&p->p_lock);
}

/*
 * Real time profiling interval timer expired:
 * Increment microstate counters for each lwp in the process
 * and ensure that running lwps are kicked into the kernel.
 * If time is not set up to reload, then just return.
 * Else compute next time timer should go off which is > current time,
 * as above.
 */
static void
realprofexpire(void *arg)
{
	struct proc *p = arg;
	kthread_t *t;

	mutex_enter(&p->p_lock);
	if (p->p_rprof_cyclic == CYCLIC_NONE ||
	    (t = p->p_tlist) == NULL) {
		mutex_exit(&p->p_lock);
		return;
	}
	do {
		int mstate;

		/*
		 * Attempt to allocate the SIGPROF buffer, but don't sleep.
		 */
		if (t->t_rprof == NULL)
			t->t_rprof = kmem_zalloc(sizeof (struct rprof),
			    KM_NOSLEEP);
		if (t->t_rprof == NULL)
			continue;

		thread_lock(t);
		switch (t->t_state) {
		case TS_SLEEP:
			/*
			 * Don't touch the lwp is it is swapped out.
			 */
			if (!(t->t_schedflag & TS_LOAD)) {
				mstate = LMS_SLEEP;
				break;
			}
			switch (mstate = ttolwp(t)->lwp_mstate.ms_prev) {
			case LMS_TFAULT:
			case LMS_DFAULT:
			case LMS_KFAULT:
			case LMS_USER_LOCK:
				break;
			default:
				mstate = LMS_SLEEP;
				break;
			}
			break;
		case TS_RUN:
		case TS_WAIT:
			mstate = LMS_WAIT_CPU;
			break;
		case TS_ONPROC:
			switch (mstate = t->t_mstate) {
			case LMS_USER:
			case LMS_SYSTEM:
			case LMS_TRAP:
				break;
			default:
				mstate = LMS_SYSTEM;
				break;
			}
			break;
		default:
			mstate = t->t_mstate;
			break;
		}
		t->t_rprof->rp_anystate = 1;
		t->t_rprof->rp_state[mstate]++;
		aston(t);
		/*
		 * force the thread into the kernel
		 * if it is not already there.
		 */
		if (t->t_state == TS_ONPROC && t->t_cpu != CPU)
			poke_cpu(t->t_cpu->cpu_id);
		thread_unlock(t);
	} while ((t = t->t_forw) != p->p_tlist);

	mutex_exit(&p->p_lock);
}

/*
 * Advances timer value past the current time of day.  See the detailed
 * comment for this logic in realitsexpire(), above.
 */
static void
timeval_advance(struct timeval *valp, struct timeval *intervalp)
{
	int cnt2nth;
	struct timeval interval2nth;

	for (;;) {
		interval2nth = *intervalp;
		for (cnt2nth = 0; ; cnt2nth++) {
			timevaladd(valp, &interval2nth);
			/*CSTYLED*/
			if (TVTSCMP(valp, &hrestime, >))
				break;
			timevaladd(&interval2nth, &interval2nth);
		}
		if (cnt2nth == 0)
			break;
		timevalsub(valp, &interval2nth);
	}
}

/*
 * Check that a proposed value to load into the .it_value or .it_interval
 * part of an interval timer is acceptable, and set it to at least a
 * specified minimal value.
 */
int
itimerfix(struct timeval *tv, int minimum)
{
	if (tv->tv_sec < 0 || tv->tv_sec > 100000000 ||
	    tv->tv_usec < 0 || tv->tv_usec >= MICROSEC)
		return (EINVAL);
	if (tv->tv_sec == 0 && tv->tv_usec != 0 && tv->tv_usec < minimum)
		tv->tv_usec = minimum;
	return (0);
}

/*
 * Same as itimerfix, except a) it takes a timespec instead of a timeval and
 * b) it doesn't truncate based on timeout granularity; consumers of this
 * interface (e.g. timer_settime()) depend on the passed timespec not being
 * modified implicitly.
 */
int
itimerspecfix(timespec_t *tv)
{
	if (tv->tv_sec < 0 || tv->tv_nsec < 0 || tv->tv_nsec >= NANOSEC)
		return (EINVAL);
	return (0);
}

/*
 * Decrement an interval timer by a specified number
 * of microseconds, which must be less than a second,
 * i.e. < 1000000.  If the timer expires, then reload
 * it.  In this case, carry over (usec - old value) to
 * reducint the value reloaded into the timer so that
 * the timer does not drift.  This routine assumes
 * that it is called in a context where the timers
 * on which it is operating cannot change in value.
 */
int
itimerdecr(struct itimerval *itp, int usec)
{
	if (itp->it_value.tv_usec < usec) {
		if (itp->it_value.tv_sec == 0) {
			/* expired, and already in next interval */
			usec -= itp->it_value.tv_usec;
			goto expire;
		}
		itp->it_value.tv_usec += MICROSEC;
		itp->it_value.tv_sec--;
	}
	itp->it_value.tv_usec -= usec;
	usec = 0;
	if (timerisset(&itp->it_value))
		return (1);
	/* expired, exactly at end of interval */
expire:
	if (timerisset(&itp->it_interval)) {
		itp->it_value = itp->it_interval;
		itp->it_value.tv_usec -= usec;
		if (itp->it_value.tv_usec < 0) {
			itp->it_value.tv_usec += MICROSEC;
			itp->it_value.tv_sec--;
		}
	} else
		itp->it_value.tv_usec = 0;		/* sec is already 0 */
	return (0);
}

/*
 * Add and subtract routines for timevals.
 * N.B.: subtract routine doesn't deal with
 * results which are before the beginning,
 * it just gets very confused in this case.
 * Caveat emptor.
 */
void
timevaladd(struct timeval *t1, struct timeval *t2)
{
	t1->tv_sec += t2->tv_sec;
	t1->tv_usec += t2->tv_usec;
	timevalfix(t1);
}

void
timevalsub(struct timeval *t1, struct timeval *t2)
{
	t1->tv_sec -= t2->tv_sec;
	t1->tv_usec -= t2->tv_usec;
	timevalfix(t1);
}

void
timevalfix(struct timeval *t1)
{
	if (t1->tv_usec < 0) {
		t1->tv_sec--;
		t1->tv_usec += MICROSEC;
	}
	if (t1->tv_usec >= MICROSEC) {
		t1->tv_sec++;
		t1->tv_usec -= MICROSEC;
	}
}

/*
 * Same as the routines above. These routines take a timespec instead
 * of a timeval.
 */
void
timespecadd(timespec_t *t1, timespec_t *t2)
{
	t1->tv_sec += t2->tv_sec;
	t1->tv_nsec += t2->tv_nsec;
	timespecfix(t1);
}

void
timespecsub(timespec_t *t1, timespec_t *t2)
{
	t1->tv_sec -= t2->tv_sec;
	t1->tv_nsec -= t2->tv_nsec;
	timespecfix(t1);
}

void
timespecfix(timespec_t *t1)
{
	if (t1->tv_nsec < 0) {
		t1->tv_sec--;
		t1->tv_nsec += NANOSEC;
	} else {
		if (t1->tv_nsec >= NANOSEC) {
			t1->tv_sec++;
			t1->tv_nsec -= NANOSEC;
		}
	}
}

/*
 * Compute number of hz until specified time.
 * Used to compute third argument to timeout() from an absolute time.
 */
clock_t
hzto(struct timeval *tv)
{
	timespec_t ts, now;

	ts.tv_sec = tv->tv_sec;
	ts.tv_nsec = tv->tv_usec * 1000;
	gethrestime_lasttick(&now);

	return (timespectohz(&ts, now));
}

/*
 * Compute number of hz until specified time for a given timespec value.
 * Used to compute third argument to timeout() from an absolute time.
 */
clock_t
timespectohz(timespec_t *tv, timespec_t now)
{
	clock_t	ticks;
	time_t	sec;
	int	nsec;

	/*
	 * Compute number of ticks we will see between now and
	 * the target time; returns "1" if the destination time
	 * is before the next tick, so we always get some delay,
	 * and returns LONG_MAX ticks if we would overflow.
	 */
	sec = tv->tv_sec - now.tv_sec;
	nsec = tv->tv_nsec - now.tv_nsec + nsec_per_tick - 1;

	if (nsec < 0) {
		sec--;
		nsec += NANOSEC;
	} else if (nsec >= NANOSEC) {
		sec++;
		nsec -= NANOSEC;
	}

	ticks = NSEC_TO_TICK(nsec);

	/*
	 * Compute ticks, accounting for negative and overflow as above.
	 * Overflow protection kicks in at about 70 weeks for hz=50
	 * and at about 35 weeks for hz=100. (Rather longer for the 64-bit
	 * kernel :-)
	 */
	if (sec < 0 || (sec == 0 && ticks < 1))
		ticks = 1;			/* protect vs nonpositive */
	else if (sec > (LONG_MAX - ticks) / hz)
		ticks = LONG_MAX;		/* protect vs overflow */
	else
		ticks += sec * hz;		/* common case */

	return (ticks);
}

/*
 * Compute number of hz with the timespec tv specified.
 * The return type must be 64 bit integer.
 */
int64_t
timespectohz64(timespec_t *tv)
{
	int64_t ticks;
	int64_t sec;
	int64_t nsec;

	sec = tv->tv_sec;
	nsec = tv->tv_nsec + nsec_per_tick - 1;

	if (nsec < 0) {
		sec--;
		nsec += NANOSEC;
	} else if (nsec >= NANOSEC) {
		sec++;
		nsec -= NANOSEC;
	}

	ticks = NSEC_TO_TICK(nsec);

	/*
	 * Compute ticks, accounting for negative and overflow as above.
	 * Overflow protection kicks in at about 70 weeks for hz=50
	 * and at about 35 weeks for hz=100. (Rather longer for the 64-bit
	 * kernel
	 */
	if (sec < 0 || (sec == 0 && ticks < 1))
		ticks = 1;			/* protect vs nonpositive */
	else if (sec > (((~0ULL) >> 1) - ticks) / hz)
		ticks = (~0ULL) >> 1;		/* protect vs overflow */
	else
		ticks += sec * hz;		/* common case */

	return (ticks);
}

/*
 * hrt2ts(): convert from hrtime_t to timestruc_t.
 *
 * All this routine really does is:
 *
 *	tsp->sec  = hrt / NANOSEC;
 *	tsp->nsec = hrt % NANOSEC;
 *
 * The black magic below avoids doing a 64-bit by 32-bit integer divide,
 * which is quite expensive.  There's actually much more going on here than
 * it might first appear -- don't try this at home.
 *
 * For the adventuresome, here's an explanation of how it works.
 *
 * Multiplication by a fixed constant is easy -- you just do the appropriate
 * shifts and adds.  For example, to multiply by 10, we observe that
 *
 *	x * 10	= x * (8 + 2)
 *		= (x * 8) + (x * 2)
 *		= (x << 3) + (x << 1).
 *
 * In general, you can read the algorithm right off the bits: the number 10
 * is 1010 in binary; bits 1 and 3 are ones, so x * 10 = (x << 1) + (x << 3).
 *
 * Sometimes you can do better.  For example, 15 is 1111 binary, so the normal
 * shift/add computation is x * 15 = (x << 0) + (x << 1) + (x << 2) + (x << 3).
 * But, it's cheaper if you capitalize on the fact that you have a run of ones:
 * 1111 = 10000 - 1, hence x * 15 = (x << 4) - (x << 0).  [You would never
 * actually perform the operation << 0, since it's a no-op; I'm just writing
 * it that way for clarity.]
 *
 * The other way you can win is if you get lucky with the prime factorization
 * of your constant.  The number 1,000,000,000, which we have to multiply
 * by below, is a good example.  One billion is 111011100110101100101000000000
 * in binary.  If you apply the bit-grouping trick, it doesn't buy you very
 * much, because it's only a win for groups of three or more equal bits:
 *
 * 111011100110101100101000000000 = 1000000000000000000000000000000
 *				  -  000100011001010011011000000000
 *
 * Thus, instead of the 13 shift/add pairs (26 operations) implied by the LHS,
 * we have reduced this to 10 shift/add pairs (20 operations) on the RHS.
 * This is better, but not great.
 *
 * However, we can factor 1,000,000,000 = 2^9 * 5^9 = 2^9 * 125 * 125 * 125,
 * and multiply by each factor.  Multiplication by 125 is particularly easy,
 * since 128 is nearby: x * 125 = (x << 7) - x - x - x, which is just four
 * operations.  So, to multiply by 1,000,000,000, we perform three multipli-
 * cations by 125, then << 9, a total of only 3 * 4 + 1 = 13 operations.
 * This is the algorithm we actually use in both hrt2ts() and ts2hrt().
 *
 * Division is harder; there is no equivalent of the simple shift-add algorithm
 * we used for multiplication.  However, we can convert the division problem
 * into a multiplication problem by pre-computing the binary representation
 * of the reciprocal of the divisor.  For the case of interest, we have
 *
 *	1 / 1,000,000,000 = 1.0001001011100000101111101000001B-30,
 *
 * to 32 bits of precision.  (The notation B-30 means "* 2^-30", just like
 * E-18 means "* 10^-18".)
 *
 * So, to compute x / 1,000,000,000, we just multiply x by the 32-bit
 * integer 10001001011100000101111101000001, then normalize (shift) the
 * result.  This constant has several large bits runs, so the multiply
 * is relatively cheap:
 *
 *	10001001011100000101111101000001 = 10001001100000000110000001000001
 *					 - 00000000000100000000000100000000
 *
 * Again, you can just read the algorithm right off the bits:
 *
 *			sec = hrt;
 *			sec += (hrt << 6);
 *			sec -= (hrt << 8);
 *			sec += (hrt << 13);
 *			sec += (hrt << 14);
 *			sec -= (hrt << 20);
 *			sec += (hrt << 23);
 *			sec += (hrt << 24);
 *			sec += (hrt << 27);
 *			sec += (hrt << 31);
 *			sec >>= (32 + 30);
 *
 * Voila!  The only problem is, since hrt is 64 bits, we need to use 96-bit
 * arithmetic to perform this calculation.  That's a waste, because ultimately
 * we only need the highest 32 bits of the result.
 *
 * The first thing we do is to realize that we don't need to use all of hrt
 * in the calculation.  The lowest 30 bits can contribute at most 1 to the
 * quotient (2^30 / 1,000,000,000 = 1.07...), so we'll deal with them later.
 * The highest 2 bits have to be zero, or hrt won't fit in a timestruc_t.
 * Thus, the only bits of hrt that matter for division are bits 30..61.
 * These 32 bits are just the lower-order word of (hrt >> 30).  This brings
 * us down from 96-bit math to 64-bit math, and our algorithm becomes:
 *
 *			tmp = (uint32_t) (hrt >> 30);
 *			sec = tmp;
 *			sec += (tmp << 6);
 *			sec -= (tmp << 8);
 *			sec += (tmp << 13);
 *			sec += (tmp << 14);
 *			sec -= (tmp << 20);
 *			sec += (tmp << 23);
 *			sec += (tmp << 24);
 *			sec += (tmp << 27);
 *			sec += (tmp << 31);
 *			sec >>= 32;
 *
 * Next, we're going to reduce this 64-bit computation to a 32-bit
 * computation.  We begin by rewriting the above algorithm to use relative
 * shifts instead of absolute shifts.  That is, instead of computing
 * tmp << 6, tmp << 8, tmp << 13, etc, we'll just shift incrementally:
 * tmp <<= 6, tmp <<= 2 (== 8 - 6), tmp <<= 5 (== 13 - 8), etc:
 *
 *			tmp = (uint32_t) (hrt >> 30);
 *			sec = tmp;
 *			tmp <<= 6; sec += tmp;
 *			tmp <<= 2; sec -= tmp;
 *			tmp <<= 5; sec += tmp;
 *			tmp <<= 1; sec += tmp;
 *			tmp <<= 6; sec -= tmp;
 *			tmp <<= 3; sec += tmp;
 *			tmp <<= 1; sec += tmp;
 *			tmp <<= 3; sec += tmp;
 *			tmp <<= 4; sec += tmp;
 *			sec >>= 32;
 *
 * Now for the final step.  Instead of throwing away the low 32 bits at
 * the end, we can throw them away as we go, only keeping the high 32 bits
 * of the product at each step.  So, for example, where we now have
 *
 *			tmp <<= 6; sec = sec + tmp;
 * we will instead have
 *			tmp <<= 6; sec = (sec + tmp) >> 6;
 * which is equivalent to
 *			sec = (sec >> 6) + tmp;
 *
 * The final shift ("sec >>= 32") goes away.
 *
 * All we're really doing here is long multiplication, just like we learned in
 * grade school, except that at each step, we only look at the leftmost 32
 * columns.  The cumulative error is, at most, the sum of all the bits we
 * throw away, which is 2^-32 + 2^-31 + ... + 2^-2 + 2^-1 == 1 - 2^-32.
 * Thus, the final result ("sec") is correct to +/- 1.
 *
 * It turns out to be important to keep "sec" positive at each step, because
 * we don't want to have to explicitly extend the sign bit.  Therefore,
 * starting with the last line of code above, each line that would have read
 * "sec = (sec >> n) - tmp" must be changed to "sec = tmp - (sec >> n)", and
 * the operators (+ or -) in all previous lines must be toggled accordingly.
 * Thus, we end up with:
 *
 *			tmp = (uint32_t) (hrt >> 30);
 *			sec = tmp + (sec >> 6);
 *			sec = tmp - (tmp >> 2);
 *			sec = tmp - (sec >> 5);
 *			sec = tmp + (sec >> 1);
 *			sec = tmp - (sec >> 6);
 *			sec = tmp - (sec >> 3);
 *			sec = tmp + (sec >> 1);
 *			sec = tmp + (sec >> 3);
 *			sec = tmp + (sec >> 4);
 *
 * This yields a value for sec that is accurate to +1/-1, so we have two
 * cases to deal with.  The mysterious-looking "+ 7" in the code below biases
 * the rounding toward zero, so that sec is always less than or equal to
 * the correct value.  With this modified code, sec is accurate to +0/-2, with
 * the -2 case being very rare in practice.  With this change, we only have to
 * deal with one case (sec too small) in the cleanup code.
 *
 * The other modification we make is to delete the second line above
 * ("sec = tmp + (sec >> 6);"), since it only has an effect when bit 31 is
 * set, and the cleanup code can handle that rare case.  This reduces the
 * *guaranteed* accuracy of sec to +0/-3, but speeds up the common cases.
 *
 * Finally, we compute nsec = hrt - (sec * 1,000,000,000).  nsec will always
 * be positive (since sec is never too large), and will at most be equal to
 * the error in sec (times 1,000,000,000) plus the low-order 30 bits of hrt.
 * Thus, nsec < 3 * 1,000,000,000 + 2^30, which is less than 2^32, so we can
 * safely assume that nsec fits in 32 bits.  Consequently, when we compute
 * sec * 1,000,000,000, we only need the low 32 bits, so we can just do 32-bit
 * arithmetic and let the high-order bits fall off the end.
 *
 * Since nsec < 3 * 1,000,000,000 + 2^30 == 4,073,741,824, the cleanup loop:
 *
 *			while (nsec >= NANOSEC) {
 *				nsec -= NANOSEC;
 *				sec++;
 *			}
 *
 * is guaranteed to complete in at most 4 iterations.  In practice, the loop
 * completes in 0 or 1 iteration over 95% of the time.
 *
 * On an SS2, this implementation of hrt2ts() takes 1.7 usec, versus about
 * 35 usec for software division -- about 20 times faster.
 */
void
hrt2ts(hrtime_t hrt, timestruc_t *tsp)
{
#if defined(__amd64)
	/*
	 * The cleverness explained above is unecessary on x86_64 CPUs where
	 * modern compilers are able to optimize down to faster operations.
	 */
	tsp->tv_sec = hrt / NANOSEC;
	tsp->tv_nsec = hrt % NANOSEC;
#else
	uint32_t sec, nsec, tmp;

	tmp = (uint32_t)(hrt >> 30);
	sec = tmp - (tmp >> 2);
	sec = tmp - (sec >> 5);
	sec = tmp + (sec >> 1);
	sec = tmp - (sec >> 6) + 7;
	sec = tmp - (sec >> 3);
	sec = tmp + (sec >> 1);
	sec = tmp + (sec >> 3);
	sec = tmp + (sec >> 4);
	tmp = (sec << 7) - sec - sec - sec;
	tmp = (tmp << 7) - tmp - tmp - tmp;
	tmp = (tmp << 7) - tmp - tmp - tmp;
	nsec = (uint32_t)hrt - (tmp << 9);
	while (nsec >= NANOSEC) {
		nsec -= NANOSEC;
		sec++;
	}
	tsp->tv_sec = (time_t)sec;
	tsp->tv_nsec = nsec;
#endif /* defined(__amd64) */
}

/*
 * Convert from timestruc_t to hrtime_t.
 */
hrtime_t
ts2hrt(const timestruc_t *tsp)
{
#if defined(__amd64) || defined(__i386)
	/*
	 * On modern x86 CPUs, the simple version is faster.
	 */
	return ((tsp->tv_sec * NANOSEC) + tsp->tv_nsec);
#else
	/*
	 * The code below is equivalent to:
	 *
	 *	hrt = tsp->tv_sec * NANOSEC + tsp->tv_nsec;
	 *
	 * but requires no integer multiply.
	 */
	hrtime_t hrt;

	hrt = tsp->tv_sec;
	hrt = (hrt << 7) - hrt - hrt - hrt;
	hrt = (hrt << 7) - hrt - hrt - hrt;
	hrt = (hrt << 7) - hrt - hrt - hrt;
	hrt = (hrt << 9) + tsp->tv_nsec;
	return (hrt);
#endif /* defined(__amd64) || defined(__i386) */
}

/*
 * For the various 32-bit "compatibility" paths in the system.
 */
void
hrt2ts32(hrtime_t hrt, timestruc32_t *ts32p)
{
	timestruc_t ts;

	hrt2ts(hrt, &ts);
	TIMESPEC_TO_TIMESPEC32(ts32p, &ts);
}

/*
 * If this ever becomes performance critical (ha!), we can borrow the
 * code from ts2hrt(), above, to multiply tv_sec by 1,000,000 and the
 * straightforward (x << 10) - (x << 5) + (x << 3) to multiply tv_usec by
 * 1,000.  For now, we'll opt for readability (besides, the compiler does
 * a passable job of optimizing constant multiplication into shifts and adds).
 */
hrtime_t
tv2hrt(struct timeval *tvp)
{
	return ((hrtime_t)tvp->tv_sec * NANOSEC +
	    (hrtime_t)tvp->tv_usec * (NANOSEC / MICROSEC));
}

void
hrt2tv(hrtime_t hrt, struct timeval *tvp)
{
#if defined(__amd64)
	/*
	 * Like hrt2ts, the simple version is faster on x86_64.
	 */
	tvp->tv_sec = hrt / NANOSEC;
	tvp->tv_usec = (hrt % NANOSEC) / (NANOSEC / MICROSEC);
#else
	uint32_t sec, nsec, tmp;
	uint32_t q, r, t;

	tmp = (uint32_t)(hrt >> 30);
	sec = tmp - (tmp >> 2);
	sec = tmp - (sec >> 5);
	sec = tmp + (sec >> 1);
	sec = tmp - (sec >> 6) + 7;
	sec = tmp - (sec >> 3);
	sec = tmp + (sec >> 1);
	sec = tmp + (sec >> 3);
	sec = tmp + (sec >> 4);
	tmp = (sec << 7) - sec - sec - sec;
	tmp = (tmp << 7) - tmp - tmp - tmp;
	tmp = (tmp << 7) - tmp - tmp - tmp;
	nsec = (uint32_t)hrt - (tmp << 9);
	while (nsec >= NANOSEC) {
		nsec -= NANOSEC;
		sec++;
	}
	tvp->tv_sec = (time_t)sec;
	/*
	 * this routine is very similar to hr2ts, but requires microseconds
	 * instead of nanoseconds, so an interger divide by 1000 routine
	 * completes the conversion
	 */
	t = (nsec >> 7) + (nsec >> 8) + (nsec >> 12);
	q = (nsec >> 1) + t + (nsec >> 15) + (t >> 11) + (t >> 14);
	q = q >> 9;
	r = nsec - q*1000;
	tvp->tv_usec = q + ((r + 24) >> 10);
#endif /* defined(__amd64) */
}

int
nanosleep(timespec_t *rqtp, timespec_t *rmtp)
{
	timespec_t rqtime;
	timespec_t rmtime;
	timespec_t now;
	int timecheck;
	int ret = 1;
	model_t datamodel = get_udatamodel();

	timecheck = timechanged;
	gethrestime(&now);

	if (datamodel == DATAMODEL_NATIVE) {
		if (copyin(rqtp, &rqtime, sizeof (rqtime)))
			return (set_errno(EFAULT));
	} else {
		timespec32_t rqtime32;

		if (copyin(rqtp, &rqtime32, sizeof (rqtime32)))
			return (set_errno(EFAULT));
		TIMESPEC32_TO_TIMESPEC(&rqtime, &rqtime32);
	}

	if (rqtime.tv_sec < 0 || rqtime.tv_nsec < 0 ||
	    rqtime.tv_nsec >= NANOSEC)
		return (set_errno(EINVAL));

	if (timerspecisset(&rqtime)) {
		timespecadd(&rqtime, &now);
		mutex_enter(&curthread->t_delay_lock);
		while ((ret = cv_waituntil_sig(&curthread->t_delay_cv,
		    &curthread->t_delay_lock, &rqtime, timecheck)) > 0)
			continue;
		mutex_exit(&curthread->t_delay_lock);
	}

	if (rmtp) {
		/*
		 * If cv_waituntil_sig() returned due to a signal, and
		 * there is time remaining, then set the time remaining.
		 * Else set time remaining to zero
		 */
		rmtime.tv_sec = rmtime.tv_nsec = 0;
		if (ret == 0) {
			timespec_t delta = rqtime;

			gethrestime(&now);
			timespecsub(&delta, &now);
			if (delta.tv_sec > 0 || (delta.tv_sec == 0 &&
			    delta.tv_nsec > 0))
				rmtime = delta;
		}

		if (datamodel == DATAMODEL_NATIVE) {
			if (copyout(&rmtime, rmtp, sizeof (rmtime)))
				return (set_errno(EFAULT));
		} else {
			timespec32_t rmtime32;

			TIMESPEC_TO_TIMESPEC32(&rmtime32, &rmtime);
			if (copyout(&rmtime32, rmtp, sizeof (rmtime32)))
				return (set_errno(EFAULT));
		}
	}

	if (ret == 0)
		return (set_errno(EINTR));
	return (0);
}

/*
 * Routines to convert standard UNIX time (seconds since Jan 1, 1970)
 * into year/month/day/hour/minute/second format, and back again.
 * Note: these routines require tod_lock held to protect cached state.
 */
static int days_thru_month[64] = {
	0, 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366, 0, 0,
	0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365, 0, 0,
	0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365, 0, 0,
	0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365, 0, 0,
};

todinfo_t saved_tod;
int saved_utc = -60;

todinfo_t
utc_to_tod(time_t utc)
{
	long dse, day, month, year;
	todinfo_t tod;

	ASSERT(MUTEX_HELD(&tod_lock));

	/*
	 * Note that tod_set_prev() assumes utc will be set to zero in
	 * the case of it being negative.  Consequently, any change made
	 * to this behavior would have to be reflected in that function
	 * as well.
	 */
	if (utc < 0)			/* should never happen */
		utc = 0;

	saved_tod.tod_sec += utc - saved_utc;
	saved_utc = utc;
	if (saved_tod.tod_sec >= 0 && saved_tod.tod_sec < 60)
		return (saved_tod);	/* only the seconds changed */

	dse = utc / 86400;		/* days since epoch */

	tod.tod_sec = utc % 60;
	tod.tod_min = (utc % 3600) / 60;
	tod.tod_hour = (utc % 86400) / 3600;
	tod.tod_dow = (dse + 4) % 7 + 1;	/* epoch was a Thursday */

	year = dse / 365 + 72;	/* first guess -- always a bit too large */
	do {
		year--;
		day = dse - 365 * (year - 70) - ((year - 69) >> 2);
	} while (day < 0);

	month = ((year & 3) << 4) + 1;
	while (day >= days_thru_month[month + 1])
		month++;

	tod.tod_day = day - days_thru_month[month] + 1;
	tod.tod_month = month & 15;
	tod.tod_year = year;

	saved_tod = tod;
	return (tod);
}

time_t
tod_to_utc(todinfo_t tod)
{
	time_t utc;
	int year = tod.tod_year;
	int month = tod.tod_month + ((year & 3) << 4);
#ifdef DEBUG
	/* only warn once, not each time called */
	static int year_warn = 1;
	static int month_warn = 1;
	static int day_warn = 1;
	static int hour_warn = 1;
	static int min_warn = 1;
	static int sec_warn = 1;
	int days_diff = days_thru_month[month + 1] - days_thru_month[month];
#endif

	ASSERT(MUTEX_HELD(&tod_lock));

#ifdef DEBUG
	if (year_warn && (year < 70 || year > 8029)) {
		cmn_err(CE_WARN,
		    "The hardware real-time clock appears to have the "
		    "wrong years value %d -- time needs to be reset\n",
		    year);
		year_warn = 0;
	}

	if (month_warn && (tod.tod_month < 1 || tod.tod_month > 12)) {
		cmn_err(CE_WARN,
		    "The hardware real-time clock appears to have the "
		    "wrong months value %d -- time needs to be reset\n",
		    tod.tod_month);
		month_warn = 0;
	}

	if (day_warn && (tod.tod_day < 1 || tod.tod_day > days_diff)) {
		cmn_err(CE_WARN,
		    "The hardware real-time clock appears to have the "
		    "wrong days value %d -- time needs to be reset\n",
		    tod.tod_day);
		day_warn = 0;
	}

	if (hour_warn && (tod.tod_hour < 0 || tod.tod_hour > 23)) {
		cmn_err(CE_WARN,
		    "The hardware real-time clock appears to have the "
		    "wrong hours value %d -- time needs to be reset\n",
		    tod.tod_hour);
		hour_warn = 0;
	}

	if (min_warn && (tod.tod_min < 0 || tod.tod_min > 59)) {
		cmn_err(CE_WARN,
		    "The hardware real-time clock appears to have the "
		    "wrong minutes value %d -- time needs to be reset\n",
		    tod.tod_min);
		min_warn = 0;
	}

	if (sec_warn && (tod.tod_sec < 0 || tod.tod_sec > 59)) {
		cmn_err(CE_WARN,
		    "The hardware real-time clock appears to have the "
		    "wrong seconds value %d -- time needs to be reset\n",
		    tod.tod_sec);
		sec_warn = 0;
	}
#endif

	utc = (year - 70);		/* next 3 lines: utc = 365y + y/4 */
	utc += (utc << 3) + (utc << 6);
	utc += (utc << 2) + ((year - 69) >> 2);
	utc += days_thru_month[month] + tod.tod_day - 1;
	utc = (utc << 3) + (utc << 4) + tod.tod_hour;	/* 24 * day + hour */
	utc = (utc << 6) - (utc << 2) + tod.tod_min;	/* 60 * hour + min */
	utc = (utc << 6) - (utc << 2) + tod.tod_sec;	/* 60 * min + sec */

	return (utc);
}
