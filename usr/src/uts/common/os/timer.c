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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/timer.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/policy.h>
#include <sys/port_impl.h>
#include <sys/port_kernel.h>
#include <sys/contract/process_impl.h>

static kmem_cache_t *clock_timer_cache;
static clock_backend_t *clock_backend[CLOCK_MAX];
static int timer_port_callback(void *, int *, pid_t, int, void *);
static void timer_close_port(void *, int, pid_t, int);

#define	CLOCK_BACKEND(clk) \
	((clk) < CLOCK_MAX && (clk) >= 0 ? clock_backend[(clk)] : NULL)

/*
 * Tunable to increase the maximum number of POSIX timers per-process.  This
 * may _only_ be tuned in /etc/system or by patching the kernel binary; it
 * _cannot_ be tuned on a running system.
 */
int timer_max = _TIMER_MAX;

/*
 * timer_lock() locks the specified interval timer.  It doesn't look at the
 * ITLK_REMOVE bit; it's up to callers to look at this if they need to
 * care.  p_lock must be held on entry; it may be dropped and reaquired,
 * but timer_lock() will always return with p_lock held.
 *
 * Note that timer_create() doesn't call timer_lock(); it creates timers
 * with the ITLK_LOCKED bit explictly set.
 */
static void
timer_lock(proc_t *p, itimer_t *it)
{
	ASSERT(MUTEX_HELD(&p->p_lock));

	while (it->it_lock & ITLK_LOCKED) {
		it->it_blockers++;
		cv_wait(&it->it_cv, &p->p_lock);
		it->it_blockers--;
	}

	it->it_lock |= ITLK_LOCKED;
}

/*
 * timer_unlock() unlocks the specified interval timer, waking up any
 * waiters.  p_lock must be held on entry; it will not be dropped by
 * timer_unlock().
 */
/* ARGSUSED */
static void
timer_unlock(proc_t *p, itimer_t *it)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(it->it_lock & ITLK_LOCKED);
	it->it_lock &= ~ITLK_LOCKED;
	cv_signal(&it->it_cv);
}

/*
 * timer_delete_locked() takes a proc pointer, timer ID and locked interval
 * timer, and deletes the specified timer.  It must be called with p_lock
 * held, and cannot be called on a timer which already has ITLK_REMOVE set;
 * the caller must check this.  timer_delete_locked() will set the ITLK_REMOVE
 * bit and will iteratively unlock and lock the interval timer until all
 * blockers have seen the ITLK_REMOVE and cleared out.  It will then zero
 * out the specified entry in the p_itimer array, and call into the clock
 * backend to complete the deletion.
 *
 * This function will always return with p_lock held.
 */
static void
timer_delete_locked(proc_t *p, timer_t tid, itimer_t *it)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(!(it->it_lock & ITLK_REMOVE));
	ASSERT(it->it_lock & ITLK_LOCKED);

	it->it_lock |= ITLK_REMOVE;

	/*
	 * If there are threads waiting to lock this timer, we'll unlock
	 * the timer, and block on the cv.  Threads blocking our removal will
	 * have the opportunity to run; when they see the ITLK_REMOVE flag
	 * set, they will immediately unlock the timer.
	 */
	while (it->it_blockers) {
		timer_unlock(p, it);
		cv_wait(&it->it_cv, &p->p_lock);
		timer_lock(p, it);
	}

	ASSERT(p->p_itimer_sz > tid);
	ASSERT(p->p_itimer[tid] == it);
	p->p_itimer[tid] = NULL;

	/*
	 * No one is blocked on this timer, and no one will be (we've set
	 * p_itimer[tid] to be NULL; no one can find it).  Now we call into
	 * the clock backend to delete the timer; it is up to the backend to
	 * guarantee that timer_fire() has completed (and will never again
	 * be called) for this timer.
	 */
	mutex_exit(&p->p_lock);

	it->it_backend->clk_timer_delete(it);

	if (it->it_portev) {
		mutex_enter(&it->it_mutex);
		if (it->it_portev) {
			port_kevent_t	*pev;
			/* dissociate timer from the event port */
			(void) port_dissociate_ksource(it->it_portfd,
			    PORT_SOURCE_TIMER, (port_source_t *)it->it_portsrc);
			pev = (port_kevent_t *)it->it_portev;
			it->it_portev = NULL;
			it->it_flags &= ~IT_PORT;
			it->it_pending = 0;
			mutex_exit(&it->it_mutex);
			(void) port_remove_done_event(pev);
			port_free_event(pev);
		} else {
			mutex_exit(&it->it_mutex);
		}
	}

	mutex_enter(&p->p_lock);

	/*
	 * We need to be careful freeing the sigqueue for this timer;
	 * if a signal is pending, the sigqueue needs to be freed
	 * synchronously in siginfofree().  The need to free the sigqueue
	 * in siginfofree() is indicated by setting sq_func to NULL.
	 */
	if (it->it_pending > 0) {
		it->it_sigq->sq_func = NULL;
	} else {
		kmem_free(it->it_sigq, sizeof (sigqueue_t));
	}

	ASSERT(it->it_blockers == 0);
	kmem_cache_free(clock_timer_cache, it);
}

/*
 * timer_grab() and its companion routine, timer_release(), are wrappers
 * around timer_lock()/_unlock() which allow the timer_*(3R) routines to
 * (a) share error handling code and (b) not grab p_lock themselves.  Routines
 * which are called with p_lock held (e.g. timer_lwpbind(), timer_lwpexit())
 * must call timer_lock()/_unlock() explictly.
 *
 * timer_grab() takes a proc and a timer ID, and returns a pointer to a
 * locked interval timer.  p_lock must _not_ be held on entry; timer_grab()
 * may acquire p_lock, but will always return with p_lock dropped.
 *
 * If timer_grab() fails, it will return NULL.  timer_grab() will fail if
 * one or more of the following is true:
 *
 *  (a)	The specified timer ID is out of range.
 *
 *  (b)	The specified timer ID does not correspond to a timer ID returned
 *	from timer_create(3R).
 *
 *  (c)	The specified timer ID is currently being removed.
 *
 */
static itimer_t *
timer_grab(proc_t *p, timer_t tid)
{
	itimer_t **itp, *it;

	if (tid < 0) {
		return (NULL);
	}

	mutex_enter(&p->p_lock);

	if ((itp = p->p_itimer) == NULL || tid >= p->p_itimer_sz ||
	    (it = itp[tid]) == NULL) {
		mutex_exit(&p->p_lock);
		return (NULL);
	}

	timer_lock(p, it);

	if (it->it_lock & ITLK_REMOVE) {
		/*
		 * Someone is removing this timer; it will soon be invalid.
		 */
		timer_unlock(p, it);
		mutex_exit(&p->p_lock);
		return (NULL);
	}

	mutex_exit(&p->p_lock);

	return (it);
}

/*
 * timer_release() releases a timer acquired with timer_grab().  p_lock
 * should not be held on entry; timer_release() will acquire p_lock but
 * will drop it before returning.
 */
static void
timer_release(proc_t *p, itimer_t *it)
{
	mutex_enter(&p->p_lock);
	timer_unlock(p, it);
	mutex_exit(&p->p_lock);
}

/*
 * timer_delete_grabbed() deletes a timer acquired with timer_grab().
 * p_lock should not be held on entry; timer_delete_grabbed() will acquire
 * p_lock, but will drop it before returning.
 */
static void
timer_delete_grabbed(proc_t *p, timer_t tid, itimer_t *it)
{
	mutex_enter(&p->p_lock);
	timer_delete_locked(p, tid, it);
	mutex_exit(&p->p_lock);
}

void
clock_timer_init()
{
	clock_timer_cache = kmem_cache_create("timer_cache",
	    sizeof (itimer_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * Push the timer_max limit up to at least 4 * NCPU.  Due to the way
	 * NCPU is defined, proper initialization of the timer limit is
	 * performed at runtime.
	 */
	timer_max = MAX(NCPU * 4, timer_max);
}

void
clock_add_backend(clockid_t clock, clock_backend_t *backend)
{
	ASSERT(clock >= 0 && clock < CLOCK_MAX);
	ASSERT(clock_backend[clock] == NULL);

	clock_backend[clock] = backend;
}

clock_backend_t *
clock_get_backend(clockid_t clock)
{
	if (clock < 0 || clock >= CLOCK_MAX)
		return (NULL);

	return (clock_backend[clock]);
}

int
clock_settime(clockid_t clock, timespec_t *tp)
{
	timespec_t t;
	clock_backend_t *backend;
	int error;

	if ((backend = CLOCK_BACKEND(clock)) == NULL)
		return (set_errno(EINVAL));

	if (secpolicy_settime(CRED()) != 0)
		return (set_errno(EPERM));

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(tp, &t, sizeof (timespec_t)) != 0)
			return (set_errno(EFAULT));
	} else {
		timespec32_t t32;

		if (copyin(tp, &t32, sizeof (timespec32_t)) != 0)
			return (set_errno(EFAULT));

		TIMESPEC32_TO_TIMESPEC(&t, &t32);
	}

	if (itimerspecfix(&t))
		return (set_errno(EINVAL));

	error = backend->clk_clock_settime(&t);

	if (error)
		return (set_errno(error));

	return (0);
}

int
clock_gettime(clockid_t clock, timespec_t *tp)
{
	timespec_t t;
	clock_backend_t *backend;
	int error;

	if ((backend = CLOCK_BACKEND(clock)) == NULL)
		return (set_errno(EINVAL));

	error = backend->clk_clock_gettime(&t);

	if (error)
		return (set_errno(error));

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(&t, tp, sizeof (timespec_t)) != 0)
			return (set_errno(EFAULT));
	} else {
		timespec32_t t32;

		if (TIMESPEC_OVERFLOW(&t))
			return (set_errno(EOVERFLOW));
		TIMESPEC_TO_TIMESPEC32(&t32, &t);

		if (copyout(&t32, tp, sizeof (timespec32_t)) != 0)
			return (set_errno(EFAULT));
	}

	return (0);
}

int
clock_getres(clockid_t clock, timespec_t *tp)
{
	timespec_t t;
	clock_backend_t *backend;
	int error;

	/*
	 * Strangely, the standard defines clock_getres() with a NULL tp
	 * to do nothing (regardless of the validity of the specified
	 * clock_id).  Go figure.
	 */
	if (tp == NULL)
		return (0);

	if ((backend = CLOCK_BACKEND(clock)) == NULL)
		return (set_errno(EINVAL));

	error = backend->clk_clock_getres(&t);

	if (error)
		return (set_errno(error));

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(&t, tp, sizeof (timespec_t)) != 0)
			return (set_errno(EFAULT));
	} else {
		timespec32_t t32;

		if (TIMESPEC_OVERFLOW(&t))
			return (set_errno(EOVERFLOW));
		TIMESPEC_TO_TIMESPEC32(&t32, &t);

		if (copyout(&t32, tp, sizeof (timespec32_t)) != 0)
			return (set_errno(EFAULT));
	}

	return (0);
}

void
timer_signal(sigqueue_t *sigq)
{
	itimer_t *it = (itimer_t *)sigq->sq_backptr;

	/*
	 * There are some conditions during a fork or an exit when we can
	 * call siginfofree() without p_lock held.  To prevent a race
	 * between timer_signal() and timer_fire() with regard to it_pending,
	 * we therefore acquire it_mutex in both paths.
	 */
	mutex_enter(&it->it_mutex);
	ASSERT(it->it_pending > 0);
	it->it_overrun = it->it_pending - 1;
	it->it_pending = 0;
	mutex_exit(&it->it_mutex);
}

/*
 * This routine is called from the clock backend.
 */
static void
timer_fire(itimer_t *it)
{
	proc_t *p;
	int proc_lock_held;

	if (it->it_flags & IT_SIGNAL) {
		/*
		 * See the comment in timer_signal() for why it is not
		 * sufficient to only grab p_lock here. Because p_lock can be
		 * held on entry to timer_signal(), the lock ordering is
		 * necessarily p_lock before it_mutex.
		 */

		p = it->it_proc;
		proc_lock_held = 1;
		mutex_enter(&p->p_lock);
	} else {
		/*
		 * IT_PORT:
		 * If a timer was ever programmed to send events to a port,
		 * the IT_PORT flag will remain set until:
		 * a) the timer is deleted (see timer_delete_locked()) or
		 * b) the port is being closed (see timer_close_port()).
		 * Both cases are synchronized with the it_mutex.
		 * We don't need to use the p_lock because it is only
		 * required in the IT_SIGNAL case.
		 * If IT_PORT was set and the port is being closed then
		 * the timer notification is set to NONE. In such a case
		 * the timer itself and the it_pending counter remain active
		 * until the application deletes the counter or the process
		 * exits.
		 */
		proc_lock_held = 0;
	}
	mutex_enter(&it->it_mutex);

	if (it->it_pending > 0) {
		if (it->it_pending < INT_MAX)
			it->it_pending++;
		mutex_exit(&it->it_mutex);
	} else {
		if (it->it_flags & IT_PORT) {
			it->it_pending = 1;
			port_send_event((port_kevent_t *)it->it_portev);
			mutex_exit(&it->it_mutex);
		} else if (it->it_flags & IT_SIGNAL) {
			it->it_pending = 1;
			mutex_exit(&it->it_mutex);
			sigaddqa(p, NULL, it->it_sigq);
		} else {
			mutex_exit(&it->it_mutex);
		}
	}

	if (proc_lock_held)
		mutex_exit(&p->p_lock);
}

/*
 * Allocate an itimer_t and find and appropriate slot for it in p_itimer.
 * Acquires p_lock and holds it on return, regardless of success.
 */
static itimer_t *
timer_alloc(proc_t *p, timer_t *id)
{
	itimer_t *it, **itp = NULL;
	uint_t i;

	ASSERT(MUTEX_NOT_HELD(&p->p_lock));

	it = kmem_cache_alloc(clock_timer_cache, KM_SLEEP);
	bzero(it, sizeof (itimer_t));
	mutex_init(&it->it_mutex, NULL, MUTEX_DEFAULT, NULL);

	mutex_enter(&p->p_lock);
retry:
	if (p->p_itimer != NULL) {
		for (i = 0; i < p->p_itimer_sz; i++) {
			if (p->p_itimer[i] == NULL) {
				itp = &(p->p_itimer[i]);
				break;
			}
		}
	}

	/*
	 * A suitable slot was not found.  If possible, allocate (or resize)
	 * the p_itimer array and try again.
	 */
	if (itp == NULL) {
		uint_t target_sz = _TIMER_ALLOC_INIT;
		itimer_t **itp_new;

		if (p->p_itimer != NULL) {
			ASSERT(p->p_itimer_sz != 0);

			target_sz = p->p_itimer_sz * 2;
		}
		/*
		 * Protect against exceeding the max or overflow
		 */
		if (target_sz > timer_max || target_sz > INT_MAX ||
		    target_sz < p->p_itimer_sz) {
			kmem_cache_free(clock_timer_cache, it);
			return (NULL);
		}
		mutex_exit(&p->p_lock);
		itp_new = kmem_zalloc(target_sz * sizeof (itimer_t *),
		    KM_SLEEP);
		mutex_enter(&p->p_lock);
		if (target_sz <= p->p_itimer_sz) {
			/*
			 * A racing thread performed the resize while we were
			 * waiting outside p_lock.  Discard our now-useless
			 * allocation and retry.
			 */
			kmem_free(itp_new, target_sz * sizeof (itimer_t *));
			goto retry;
		} else {
			/*
			 * Instantiate the larger allocation and select the
			 * first fresh entry for use.
			 */
			if (p->p_itimer != NULL) {
				uint_t old_sz;

				old_sz = p->p_itimer_sz;
				bcopy(p->p_itimer, itp_new,
				    old_sz * sizeof (itimer_t *));
				kmem_free(p->p_itimer,
				    old_sz * sizeof (itimer_t *));

				/*
				 * Short circuit to use the first free entry in
				 * the new allocation.  It's possible that
				 * other lower-indexed timers were freed while
				 * p_lock was dropped, but skipping over them
				 * is not harmful at all.  In the common case,
				 * we skip the need to walk over an array
				 * filled with timers before arriving at the
				 * slot we know is fresh from the allocation.
				 */
				i = old_sz;
			} else {
				/*
				 * For processes lacking any existing timers,
				 * we can simply select the first entry.
				 */
				i = 0;
			}
			p->p_itimer = itp_new;
			p->p_itimer_sz = target_sz;
		}
	}

	ASSERT(i <= INT_MAX);
	*id = (timer_t)i;
	return (it);
}

int
timer_create(clockid_t clock, struct sigevent *evp, timer_t *tid)
{
	struct sigevent ev;
	proc_t *p = curproc;
	clock_backend_t *backend;
	itimer_t *it;
	sigqueue_t *sigq;
	cred_t *cr = CRED();
	int error = 0;
	timer_t i;
	port_notify_t tim_pnevp;
	port_kevent_t *pkevp = NULL;

	if ((backend = CLOCK_BACKEND(clock)) == NULL)
		return (set_errno(EINVAL));

	if (evp != NULL) {
		/*
		 * short copyin() for binary compatibility
		 * fetch oldsigevent to determine how much to copy in.
		 */
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyin(evp, &ev, sizeof (struct oldsigevent)))
				return (set_errno(EFAULT));

			if (ev.sigev_notify == SIGEV_PORT ||
			    ev.sigev_notify == SIGEV_THREAD) {
				if (copyin(ev.sigev_value.sival_ptr, &tim_pnevp,
				    sizeof (port_notify_t)))
					return (set_errno(EFAULT));
			}
#ifdef	_SYSCALL32_IMPL
		} else {
			struct sigevent32 ev32;
			port_notify32_t tim_pnevp32;

			if (copyin(evp, &ev32, sizeof (struct oldsigevent32)))
				return (set_errno(EFAULT));
			ev.sigev_notify = ev32.sigev_notify;
			ev.sigev_signo = ev32.sigev_signo;
			/*
			 * See comment in sigqueue32() on handling of 32-bit
			 * sigvals in a 64-bit kernel.
			 */
			ev.sigev_value.sival_int = ev32.sigev_value.sival_int;
			if (ev.sigev_notify == SIGEV_PORT ||
			    ev.sigev_notify == SIGEV_THREAD) {
				if (copyin((void *)(uintptr_t)
				    ev32.sigev_value.sival_ptr,
				    (void *)&tim_pnevp32,
				    sizeof (port_notify32_t)))
					return (set_errno(EFAULT));
				tim_pnevp.portnfy_port =
				    tim_pnevp32.portnfy_port;
				tim_pnevp.portnfy_user =
				    (void *)(uintptr_t)tim_pnevp32.portnfy_user;
			}
#endif
		}
		switch (ev.sigev_notify) {
		case SIGEV_NONE:
			break;
		case SIGEV_SIGNAL:
			if (ev.sigev_signo < 1 || ev.sigev_signo >= NSIG)
				return (set_errno(EINVAL));
			break;
		case SIGEV_THREAD:
		case SIGEV_PORT:
			break;
		default:
			return (set_errno(EINVAL));
		}
	} else {
		/*
		 * Use the clock's default sigevent (this is a structure copy).
		 */
		ev = backend->clk_default;
	}

	/*
	 * We'll allocate our sigqueue now, before we grab p_lock.
	 * If we can't find an empty slot, we'll free it before returning.
	 */
	sigq = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);

	/*
	 * Allocate a timer and choose a slot for it. This acquires p_lock.
	 */
	it = timer_alloc(p, &i);
	ASSERT(MUTEX_HELD(&p->p_lock));

	if (it == NULL) {
		mutex_exit(&p->p_lock);
		kmem_free(sigq, sizeof (sigqueue_t));
		return (set_errno(EAGAIN));
	}

	ASSERT(i < p->p_itimer_sz && p->p_itimer[i] == NULL);

	/*
	 * If we develop other notification mechanisms, this will need
	 * to call into (yet another) backend.
	 */
	sigq->sq_info.si_signo = ev.sigev_signo;
	if (evp == NULL)
		sigq->sq_info.si_value.sival_int = i;
	else
		sigq->sq_info.si_value = ev.sigev_value;
	sigq->sq_info.si_code = SI_TIMER;
	sigq->sq_info.si_pid = p->p_pid;
	sigq->sq_info.si_ctid = PRCTID(p);
	sigq->sq_info.si_zoneid = getzoneid();
	sigq->sq_info.si_uid = crgetruid(cr);
	sigq->sq_func = timer_signal;
	sigq->sq_next = NULL;
	sigq->sq_backptr = it;
	it->it_sigq = sigq;
	it->it_backend = backend;
	it->it_lock = ITLK_LOCKED;

	if (ev.sigev_notify == SIGEV_THREAD ||
	    ev.sigev_notify == SIGEV_PORT) {
		int port;

		/*
		 * This timer is programmed to use event port notification when
		 * the timer fires:
		 * - allocate a port event structure and prepare it to be sent
		 *   to the port as soon as the timer fires.
		 * - when the timer fires :
		 *   - if event structure was already sent to the port then this
		 *	is a timer fire overflow => increment overflow counter.
		 *   - otherwise send pre-allocated event structure to the port.
		 * - the events field of the port_event_t structure counts the
		 *   number of timer fired events.
		 * - The event structured is allocated using the
		 *   PORT_ALLOC_CACHED flag.
		 *   This flag indicates that the timer itself will manage and
		 *   free the event structure when required.
		 */

		it->it_flags |= IT_PORT;
		port = tim_pnevp.portnfy_port;

		/* associate timer as event source with the port */
		error = port_associate_ksource(port, PORT_SOURCE_TIMER,
		    (port_source_t **)&it->it_portsrc, timer_close_port,
		    (void *)it, NULL);
		if (error) {
			mutex_exit(&p->p_lock);
			kmem_cache_free(clock_timer_cache, it);
			kmem_free(sigq, sizeof (sigqueue_t));
			return (set_errno(error));
		}

		/* allocate an event structure/slot */
		error = port_alloc_event(port, PORT_ALLOC_SCACHED,
		    PORT_SOURCE_TIMER, &pkevp);
		if (error) {
			(void) port_dissociate_ksource(port, PORT_SOURCE_TIMER,
			    (port_source_t *)it->it_portsrc);
			mutex_exit(&p->p_lock);
			kmem_cache_free(clock_timer_cache, it);
			kmem_free(sigq, sizeof (sigqueue_t));
			return (set_errno(error));
		}

		/* initialize event data */
		port_init_event(pkevp, i, tim_pnevp.portnfy_user,
		    timer_port_callback, it);
		it->it_portev = pkevp;
		it->it_portfd = port;
	} else {
		if (ev.sigev_notify == SIGEV_SIGNAL)
			it->it_flags |= IT_SIGNAL;
	}

	/* Populate the slot now that the timer is prepped. */
	p->p_itimer[i] = it;
	mutex_exit(&p->p_lock);

	/*
	 * Call on the backend to verify the event argument (or return
	 * EINVAL if this clock type does not support timers).
	 */
	if ((error = backend->clk_timer_create(it, timer_fire)) != 0)
		goto err;

	it->it_lwp = ttolwp(curthread);
	it->it_proc = p;

	if (copyout(&i, tid, sizeof (timer_t)) != 0) {
		error = EFAULT;
		goto err;
	}

	/*
	 * If we're here, then we have successfully created the timer; we
	 * just need to release the timer and return.
	 */
	timer_release(p, it);

	return (0);

err:
	/*
	 * If we're here, an error has occurred late in the timer creation
	 * process.  We need to regrab p_lock, and delete the incipient timer.
	 * Since we never unlocked the timer (it was born locked), it's
	 * impossible for a removal to be pending.
	 */
	ASSERT(!(it->it_lock & ITLK_REMOVE));
	timer_delete_grabbed(p, i, it);

	return (set_errno(error));
}

int
timer_gettime(timer_t tid, itimerspec_t *val)
{
	proc_t *p = curproc;
	itimer_t *it;
	itimerspec_t when;
	int error;

	if ((it = timer_grab(p, tid)) == NULL)
		return (set_errno(EINVAL));

	error = it->it_backend->clk_timer_gettime(it, &when);

	timer_release(p, it);

	if (error == 0) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&when, val, sizeof (itimerspec_t)))
				error = EFAULT;
		} else {
			if (ITIMERSPEC_OVERFLOW(&when))
				error = EOVERFLOW;
			else {
				itimerspec32_t w32;

				ITIMERSPEC_TO_ITIMERSPEC32(&w32, &when)
				if (copyout(&w32, val, sizeof (itimerspec32_t)))
					error = EFAULT;
			}
		}
	}

	return (error ? set_errno(error) : 0);
}

int
timer_settime(timer_t tid, int flags, itimerspec_t *val, itimerspec_t *oval)
{
	itimerspec_t when;
	itimer_t *it;
	proc_t *p = curproc;
	int error;

	if (oval != NULL) {
		if ((error = timer_gettime(tid, oval)) != 0)
			return (error);
	}

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(val, &when, sizeof (itimerspec_t)))
			return (set_errno(EFAULT));
	} else {
		itimerspec32_t w32;

		if (copyin(val, &w32, sizeof (itimerspec32_t)))
			return (set_errno(EFAULT));

		ITIMERSPEC32_TO_ITIMERSPEC(&when, &w32);
	}

	if (itimerspecfix(&when.it_value) ||
	    (itimerspecfix(&when.it_interval) &&
	    timerspecisset(&when.it_value))) {
		return (set_errno(EINVAL));
	}

	if ((it = timer_grab(p, tid)) == NULL)
		return (set_errno(EINVAL));

	error = it->it_backend->clk_timer_settime(it, flags, &when);

	timer_release(p, it);

	return (error ? set_errno(error) : 0);
}

int
timer_delete(timer_t tid)
{
	proc_t *p = curproc;
	itimer_t *it;

	if ((it = timer_grab(p, tid)) == NULL)
		return (set_errno(EINVAL));

	timer_delete_grabbed(p, tid, it);

	return (0);
}

int
timer_getoverrun(timer_t tid)
{
	int overrun;
	proc_t *p = curproc;
	itimer_t *it;

	if ((it = timer_grab(p, tid)) == NULL)
		return (set_errno(EINVAL));

	/*
	 * The it_overrun field is protected by p_lock; we need to acquire
	 * it before looking at the value.
	 */
	mutex_enter(&p->p_lock);
	overrun = it->it_overrun;
	mutex_exit(&p->p_lock);

	timer_release(p, it);

	return (overrun);
}

/*
 * Entered/exited with p_lock held, but will repeatedly drop and regrab p_lock.
 */
void
timer_lwpexit(void)
{
	uint_t i;
	proc_t *p = curproc;
	klwp_t *lwp = ttolwp(curthread);
	itimer_t *it, **itp;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if ((itp = p->p_itimer) == NULL)
		return;

	for (i = 0; i < p->p_itimer_sz; i++) {
		if ((it = itp[i]) == NULL)
			continue;

		timer_lock(p, it);

		if ((it->it_lock & ITLK_REMOVE) || it->it_lwp != lwp) {
			/*
			 * This timer is either being removed or it isn't
			 * associated with this lwp.
			 */
			timer_unlock(p, it);
			continue;
		}

		/*
		 * The LWP that created this timer is going away.  To the user,
		 * our behavior here is explicitly undefined.  We will simply
		 * null out the it_lwp field; if the LWP was bound to a CPU,
		 * the cyclic will stay bound to that CPU until the process
		 * exits.
		 */
		it->it_lwp = NULL;
		timer_unlock(p, it);
	}
}

/*
 * Called to notify of an LWP binding change.  Entered/exited with p_lock
 * held, but will repeatedly drop and regrab p_lock.
 */
void
timer_lwpbind()
{
	uint_t i;
	proc_t *p = curproc;
	klwp_t *lwp = ttolwp(curthread);
	itimer_t *it, **itp;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if ((itp = p->p_itimer) == NULL)
		return;

	for (i = 0; i < p->p_itimer_sz; i++) {
		if ((it = itp[i]) == NULL)
			continue;

		timer_lock(p, it);

		if (!(it->it_lock & ITLK_REMOVE) && it->it_lwp == lwp) {
			/*
			 * Drop p_lock and jump into the backend.
			 */
			mutex_exit(&p->p_lock);
			it->it_backend->clk_timer_lwpbind(it);
			mutex_enter(&p->p_lock);
		}

		timer_unlock(p, it);
	}
}

/*
 * This function should only be called if p_itimer is non-NULL.
 */
void
timer_exit(void)
{
	uint_t i;
	proc_t *p = curproc;

	ASSERT(p->p_itimer != NULL);
	ASSERT(p->p_itimer_sz != 0);

	for (i = 0; i < p->p_itimer_sz; i++) {
		(void) timer_delete((timer_t)i);
	}

	kmem_free(p->p_itimer, p->p_itimer_sz * sizeof (itimer_t *));
	p->p_itimer = NULL;
	p->p_itimer_sz = 0;
}

/*
 * timer_port_callback() is a callback function which is associated with the
 * timer event and is activated just before the event is delivered to the user.
 * The timer uses this function to update/set the overflow counter and
 * to reenable the use of the event structure.
 */

/* ARGSUSED */
static int
timer_port_callback(void *arg, int *events, pid_t pid, int flag, void *evp)
{
	itimer_t	*it = arg;

	mutex_enter(&it->it_mutex);
	if (curproc != it->it_proc) {
		/* can not deliver timer events to another proc */
		mutex_exit(&it->it_mutex);
		return (EACCES);
	}
	*events = it->it_pending;	/* 1 = 1 event, >1 # of overflows */
	it->it_pending = 0;		/* reinit overflow counter	*/
	/*
	 * This function can also be activated when the port is being closed
	 * and a timer event is already submitted to the port.
	 * In such a case the event port framework will use the
	 * close-callback function to notify the events sources.
	 * The timer close-callback function is timer_close_port() which
	 * will free all allocated resources (including the allocated
	 * port event structure).
	 * For that reason we don't need to check the value of flag here.
	 */
	mutex_exit(&it->it_mutex);
	return (0);
}

/*
 * port is being closed ... free all allocated port event structures
 * The delivered arg currently correspond to the first timer associated with
 * the port and it is not useable in this case.
 * We have to scan the list of activated timers in the current proc and
 * compare them with the delivered port id.
 */

/* ARGSUSED */
static void
timer_close_port(void *arg, int port, pid_t pid, int lastclose)
{
	proc_t		*p = curproc;
	timer_t		tid;
	itimer_t	*it;

	for (tid = 0; tid < timer_max; tid++) {
		if ((it = timer_grab(p, tid)) == NULL)
			continue;
		if (it->it_portev) {
			mutex_enter(&it->it_mutex);
			if (it->it_portfd == port) {
				port_kevent_t *pev;
				pev = (port_kevent_t *)it->it_portev;
				it->it_portev = NULL;
				it->it_flags &= ~IT_PORT;
				mutex_exit(&it->it_mutex);
				(void) port_remove_done_event(pev);
				port_free_event(pev);
			} else {
				mutex_exit(&it->it_mutex);
			}
		}
		timer_release(p, it);
	}
}
