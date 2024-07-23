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
 * Copyright 2024 Oxide Computer Company
 */

#include "lint.h"
#include "thr_uberdata.h"

static uint32_t _semvaluemax;

/*
 * Check to see if anyone is waiting for this semaphore.
 */
#pragma weak _sema_held = sema_held
int
sema_held(sema_t *sp)
{
	return (sp->count == 0);
}

#pragma weak _sema_init = sema_init
int
sema_init(sema_t *sp, unsigned int count, int type, void *arg __unused)
{
	if (_semvaluemax == 0)
		_semvaluemax = (uint32_t)_sysconf(_SC_SEM_VALUE_MAX);
	if ((type != USYNC_THREAD && type != USYNC_PROCESS) ||
	    (count > _semvaluemax))
		return (EINVAL);
	(void) memset(sp, 0, sizeof (*sp));
	sp->count = count;
	sp->type = (uint16_t)type;
	sp->magic = SEMA_MAGIC;

	/*
	 * This should be at the beginning of the function,
	 * but for the sake of old broken applications that
	 * do not have proper alignment for their semaphores
	 * (and don't check the return code from sema_init),
	 * we put it here, after initializing the semaphore regardless.
	 */
	if (((uintptr_t)sp & (_LONG_LONG_ALIGNMENT - 1)) &&
	    curthread->ul_misaligned == 0)
		return (EINVAL);

	return (0);
}

#pragma weak _sema_destroy = sema_destroy
int
sema_destroy(sema_t *sp)
{
	sp->magic = 0;
	tdb_sync_obj_deregister(sp);
	return (0);
}

static int
sema_wait_impl(sema_t *sp, timespec_t *tsp)
{
	lwp_sema_t *lsp = (lwp_sema_t *)sp;
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_sema_stats_t *ssp = SEMA_STATS(sp, udp);
	hrtime_t begin_sleep = 0;
	uint_t count;
	int error = 0;

	/*
	 * All variations of sema_wait() are cancellation points.
	 */
	_cancelon();

	if (ssp)
		tdb_incr(ssp->sema_wait);

	self->ul_sp = stkptr();
	self->ul_wchan = lsp;
	if (__td_event_report(self, TD_SLEEP, udp)) {
		self->ul_td_evbuf.eventnum = TD_SLEEP;
		self->ul_td_evbuf.eventdata = lsp;
		tdb_event(TD_SLEEP, udp);
	}
	/* just a guess, but it looks like we will sleep */
	if (ssp && lsp->count == 0) {
		begin_sleep = gethrtime();
		if (lsp->count == 0)	/* still looks like sleep */
			tdb_incr(ssp->sema_wait_sleep);
		else			/* we changed our mind */
			begin_sleep = 0;
	}

	if (lsp->type == USYNC_PROCESS) {		/* kernel-level */
		set_parking_flag(self, 1);
		if (self->ul_cursig != 0 ||
		    (self->ul_cancelable && self->ul_cancel_pending))
			set_parking_flag(self, 0);
		/* the kernel always does FIFO queueing */
		error = ___lwp_sema_timedwait(lsp, tsp, 1);
		set_parking_flag(self, 0);
	} else if (!udp->uberflags.uf_mt &&		/* single threaded */
	    lsp->count != 0) {				/* and non-blocking */
		/*
		 * Since we are single-threaded, we don't need the
		 * protection of queue_lock().  However, we do need
		 * to block signals while modifying the count.
		 */
		sigoff(self);
		lsp->count--;
		sigon(self);
	} else {				/* multithreaded or blocking */
		queue_head_t *qp;
		ulwp_t *ulwp;
		lwpid_t lwpid = 0;

		qp = queue_lock(lsp, CV);
		while (error == 0 && lsp->count == 0) {
			/*
			 * SUSV3 requires FIFO queueing for semaphores,
			 * at least for SCHED_FIFO and SCHED_RR scheduling.
			 */
			enqueue(qp, self, 1);
			lsp->sema_waiters = 1;
			set_parking_flag(self, 1);
			queue_unlock(qp);
			/*
			 * We may have received SIGCANCEL before we
			 * called queue_lock().  If so and we are
			 * cancelable we should return EINTR.
			 */
			if (self->ul_cursig != 0 ||
			    (self->ul_cancelable && self->ul_cancel_pending))
				set_parking_flag(self, 0);
			error = __lwp_park(tsp, 0);
			set_parking_flag(self, 0);
			qp = queue_lock(lsp, CV);
			if (self->ul_sleepq)	/* timeout or spurious wakeup */
				lsp->sema_waiters = dequeue_self(qp);
		}
		if (error == 0)
			lsp->count--;
		if (lsp->count != 0 && lsp->sema_waiters) {
			int more;
			if ((ulwp = dequeue(qp, &more)) != NULL) {
				no_preempt(self);
				lwpid = ulwp->ul_lwpid;
			}
			lsp->sema_waiters = more;
		}
		queue_unlock(qp);
		if (lwpid) {
			(void) __lwp_unpark(lwpid);
			preempt(self);
		}
	}

	self->ul_wchan = NULL;
	self->ul_sp = 0;
	if (ssp) {
		if (error == 0) {
			/* we just decremented the count */
			count = lsp->count;
			if (ssp->sema_min_count > count)
				ssp->sema_min_count = count;
		}
		if (begin_sleep)
			ssp->sema_wait_sleep_time += gethrtime() - begin_sleep;
	}

	if (error == EINTR)
		_canceloff();
	else
		_canceloff_nocancel();
	return (error);
}

#pragma weak _sema_wait = sema_wait
int
sema_wait(sema_t *sp)
{
	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	return (sema_wait_impl(sp, NULL));
}

/*
 * sema_relcockwait() and sema_clockwait() are currently only internal to libc
 * to aid with implementing the POSIX versions of these functions.
 */
int
sema_relclockwait(sema_t *sp, clockid_t clock, const timespec_t *reltime)
{
	timespec_t tslocal = *reltime;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	switch (clock) {
	case CLOCK_REALTIME:
	case CLOCK_HIGHRES:
		break;
	default:
		return (EINVAL);
	}
	return (sema_wait_impl(sp, &tslocal));
}

int
sema_clockwait(sema_t *sp, clockid_t clock, const timespec_t *abstime)
{
	timespec_t tslocal;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);
	switch (clock) {
	case CLOCK_REALTIME:
	case CLOCK_HIGHRES:
		break;
	default:
		return (EINVAL);
	}
	abstime_to_reltime(clock, abstime, &tslocal);
	return (sema_wait_impl(sp, &tslocal));
}

int
sema_reltimedwait(sema_t *sp, const timespec_t *reltime)
{
	return (sema_relclockwait(sp, CLOCK_REALTIME, reltime));
}

int
sema_timedwait(sema_t *sp, const timespec_t *abstime)
{
	return (sema_clockwait(sp, CLOCK_REALTIME, abstime));
}

#pragma weak _sema_trywait = sema_trywait
int
sema_trywait(sema_t *sp)
{
	lwp_sema_t *lsp = (lwp_sema_t *)sp;
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_sema_stats_t *ssp = SEMA_STATS(sp, udp);
	uint_t count;
	int error = 0;

	ASSERT(!curthread->ul_critical || curthread->ul_bindflags);

	if (ssp)
		tdb_incr(ssp->sema_trywait);

	if (lsp->type == USYNC_PROCESS) {	/* kernel-level */
		error = _lwp_sema_trywait(lsp);
	} else if (!udp->uberflags.uf_mt) {	/* single threaded */
		sigoff(self);
		if (lsp->count == 0)
			error = EBUSY;
		else
			lsp->count--;
		sigon(self);
	} else {				/* multithreaded */
		queue_head_t *qp;
		ulwp_t *ulwp;
		lwpid_t lwpid = 0;

		qp = queue_lock(lsp, CV);
		if (lsp->count == 0)
			error = EBUSY;
		else if (--lsp->count != 0 && lsp->sema_waiters) {
			int more;
			if ((ulwp = dequeue(qp, &more)) != NULL) {
				no_preempt(self);
				lwpid = ulwp->ul_lwpid;
			}
			lsp->sema_waiters = more;
		}
		queue_unlock(qp);
		if (lwpid) {
			(void) __lwp_unpark(lwpid);
			preempt(self);
		}
	}

	if (error == 0) {
		if (ssp) {
			/* we just decremented the count */
			count = lsp->count;
			if (ssp->sema_min_count > count)
				ssp->sema_min_count = count;
		}
	} else {
		if (ssp)
			tdb_incr(ssp->sema_trywait_fail);
		if (__td_event_report(self, TD_LOCK_TRY, udp)) {
			self->ul_td_evbuf.eventnum = TD_LOCK_TRY;
			tdb_event(TD_LOCK_TRY, udp);
		}
	}

	return (error);
}

#pragma weak _sema_post = sema_post
int
sema_post(sema_t *sp)
{
	lwp_sema_t *lsp = (lwp_sema_t *)sp;
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_sema_stats_t *ssp = SEMA_STATS(sp, udp);
	uint_t count;
	int error = 0;

	if (ssp)
		tdb_incr(ssp->sema_post);
	if (_semvaluemax == 0)
		_semvaluemax = (uint32_t)_sysconf(_SC_SEM_VALUE_MAX);

	if (lsp->type == USYNC_PROCESS) {	/* kernel-level */
		error = _lwp_sema_post(lsp);
	} else if (!udp->uberflags.uf_mt) {	/* single threaded */
		sigoff(self);
		if (lsp->count >= _semvaluemax)
			error = EOVERFLOW;
		else
			lsp->count++;
		sigon(self);
	} else {				/* multithreaded */
		queue_head_t *qp;
		ulwp_t *ulwp;
		lwpid_t lwpid = 0;

		qp = queue_lock(lsp, CV);
		if (lsp->count >= _semvaluemax)
			error = EOVERFLOW;
		else if (lsp->count++ == 0 && lsp->sema_waiters) {
			int more;
			if ((ulwp = dequeue(qp, &more)) != NULL) {
				no_preempt(self);
				lwpid = ulwp->ul_lwpid;
			}
			lsp->sema_waiters = more;
		}
		queue_unlock(qp);
		if (lwpid) {
			(void) __lwp_unpark(lwpid);
			preempt(self);
		}
	}

	if (error == 0) {
		if (ssp) {
			/* we just incremented the count */
			count = lsp->count;
			if (ssp->sema_max_count < count)
				ssp->sema_max_count = count;
		}
	}

	return (error);
}
