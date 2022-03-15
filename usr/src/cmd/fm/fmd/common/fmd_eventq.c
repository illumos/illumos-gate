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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <fmd_alloc.h>
#include <fmd_eventq.h>
#include <fmd_module.h>
#include <fmd_dispq.h>
#include <fmd_subr.h>

#include <fmd.h>

fmd_eventq_t *
fmd_eventq_create(fmd_module_t *mp, fmd_eventqstat_t *stats,
    pthread_mutex_t *stats_lock, uint_t limit)
{
	fmd_eventq_t *eq = fmd_zalloc(sizeof (fmd_eventq_t), FMD_SLEEP);

	(void) pthread_mutex_init(&eq->eq_lock, NULL);
	(void) pthread_cond_init(&eq->eq_cv, NULL);

	eq->eq_mod = mp;
	eq->eq_stats = stats;
	eq->eq_stats_lock = stats_lock;
	eq->eq_limit = limit;
	eq->eq_sgid = fmd_dispq_getgid(fmd.d_disp, eq);

	return (eq);
}

void
fmd_eventq_destroy(fmd_eventq_t *eq)
{
	fmd_eventqelem_t *eqe;

	while ((eqe = fmd_list_next(&eq->eq_list)) != NULL) {
		fmd_list_delete(&eq->eq_list, eqe);
		fmd_event_rele(eqe->eqe_event);
		fmd_free(eqe, sizeof (fmd_eventqelem_t));
	}

	fmd_dispq_delgid(fmd.d_disp, eq->eq_sgid);
	fmd_free(eq, sizeof (fmd_eventq_t));
}

static void
fmd_eventq_drop(fmd_eventq_t *eq, fmd_eventqelem_t *eqe)
{
	(void) pthread_mutex_lock(eq->eq_stats_lock);
	eq->eq_stats->eqs_dropped.fmds_value.ui64++;
	(void) pthread_mutex_unlock(eq->eq_stats_lock);

	fmd_event_rele(eqe->eqe_event);
	fmd_free(eqe, sizeof (fmd_eventqelem_t));
}

void
fmd_eventq_drop_topo(fmd_eventq_t *eq)
{
	fmd_eventqelem_t *eqe, *tmp;
	boolean_t got_fm_events = B_FALSE;

	/*
	 * Here we iterate through the per-module event queue in order to remove
	 * redundant FMD_EVT_TOPO events.  The trick is to not drop a given
	 * topo event if there are any FM protocol events in the queue after
	 * it, as those events need to be processed with the correct topology.
	 */
	(void) pthread_mutex_lock(&eq->eq_lock);
	eqe = fmd_list_prev(&eq->eq_list);
	while (eqe) {
		if (FMD_EVENT_TYPE(eqe->eqe_event) == FMD_EVT_TOPO) {
			if (!got_fm_events) {
				tmp = eqe;
				eqe = fmd_list_prev(eqe);
				fmd_list_delete(&eq->eq_list, tmp);
				eq->eq_size--;
				fmd_eventq_drop(eq, tmp);
			} else {
				got_fm_events = B_FALSE;
				eqe = fmd_list_prev(eqe);
			}
		} else if (FMD_EVENT_TYPE(eqe->eqe_event) == FMD_EVT_PROTOCOL) {
			got_fm_events = B_TRUE;
			eqe = fmd_list_prev(eqe);
		} else
			eqe = fmd_list_prev(eqe);
	}
	(void) pthread_mutex_unlock(&eq->eq_lock);
}

/*
 * Update statistics when an event is dispatched and placed on a module's event
 * queue.  This is essentially the same code as kstat_waitq_enter(9F).
 */
static void
fmd_eventqstat_dispatch(fmd_eventq_t *eq)
{
	fmd_eventqstat_t *eqs = eq->eq_stats;
	hrtime_t new, delta;
	uint32_t wcnt;

	(void) pthread_mutex_lock(eq->eq_stats_lock);

	new = gethrtime();
	delta = new - eqs->eqs_wlastupdate.fmds_value.ui64;
	eqs->eqs_wlastupdate.fmds_value.ui64 = new;
	wcnt = eqs->eqs_wcnt.fmds_value.ui32++;

	if (wcnt != 0) {
		eqs->eqs_wlentime.fmds_value.ui64 += delta * wcnt;
		eqs->eqs_wtime.fmds_value.ui64 += delta;
	}

	eqs->eqs_dispatched.fmds_value.ui64++;
	(void) pthread_mutex_unlock(eq->eq_stats_lock);
}

void
fmd_eventq_insert_at_head(fmd_eventq_t *eq, fmd_event_t *ep)
{
	uint_t evt = FMD_EVENT_TYPE(ep);
	fmd_eventqelem_t *eqe;
	int ok;

	/*
	 * If this event queue is acting as /dev/null, bounce the reference
	 * count to free an unreferenced event and just return immediately.
	 */
	if (eq->eq_limit == 0) {
		fmd_event_hold(ep);
		fmd_event_rele(ep);
		return;
	}

	eqe = fmd_alloc(sizeof (fmd_eventqelem_t), FMD_SLEEP);
	fmd_event_hold(ep);
	eqe->eqe_event = ep;

	(void) pthread_mutex_lock(&eq->eq_lock);

	if ((ok = eq->eq_size < eq->eq_limit || evt != FMD_EVT_PROTOCOL) != 0) {
		if (evt != FMD_EVT_CTL)
			fmd_eventqstat_dispatch(eq);

		fmd_list_prepend(&eq->eq_list, eqe);
		eq->eq_size++;
	}

	(void) pthread_cond_broadcast(&eq->eq_cv);
	(void) pthread_mutex_unlock(&eq->eq_lock);

	if (!ok)
		fmd_eventq_drop(eq, eqe);
}

void
fmd_eventq_insert_at_time(fmd_eventq_t *eq, fmd_event_t *ep)
{
	uint_t evt = FMD_EVENT_TYPE(ep);
	hrtime_t hrt = fmd_event_hrtime(ep);
	fmd_eventqelem_t *eqe, *oqe;
	int ok;

	/*
	 * If this event queue is acting as /dev/null, bounce the reference
	 * count to free an unreferenced event and just return immediately.
	 */
	if (eq->eq_limit == 0) {
		fmd_event_hold(ep);
		fmd_event_rele(ep);
		return;
	}

	eqe = fmd_alloc(sizeof (fmd_eventqelem_t), FMD_SLEEP);
	fmd_event_hold(ep);
	eqe->eqe_event = ep;

	(void) pthread_mutex_lock(&eq->eq_lock);

	/*
	 * fmd makes no guarantees that events will be delivered in time order
	 * because its transport can make no such guarantees.  Instead we make
	 * a looser guarantee that an enqueued event will be dequeued before
	 * any newer *pending* events according to event time.  This permits us
	 * to state, for example, that a timer expiry event will be delivered
	 * prior to any enqueued event whose time is after the timer expired.
	 * We use a simple insertion sort for this task, as queue lengths are
	 * typically short and events do *tend* to be received chronologically.
	 */
	for (oqe = fmd_list_prev(&eq->eq_list); oqe; oqe = fmd_list_prev(oqe)) {
		if (hrt >= fmd_event_hrtime(oqe->eqe_event))
			break; /* 'ep' is newer than the event in 'oqe' */
	}

	if ((ok = eq->eq_size < eq->eq_limit || evt != FMD_EVT_PROTOCOL) != 0) {
		if (evt != FMD_EVT_CTL)
			fmd_eventqstat_dispatch(eq);

		if (oqe == NULL)
			fmd_list_prepend(&eq->eq_list, eqe);
		else
			fmd_list_insert_after(&eq->eq_list, oqe, eqe);
		eq->eq_size++;
	}

	(void) pthread_cond_broadcast(&eq->eq_cv);
	(void) pthread_mutex_unlock(&eq->eq_lock);

	if (!ok)
		fmd_eventq_drop(eq, eqe);
}

fmd_event_t *
fmd_eventq_delete(fmd_eventq_t *eq)
{
	fmd_eventqstat_t *eqs = eq->eq_stats;
	hrtime_t new, delta;
	uint32_t wcnt;

	fmd_eventqelem_t *eqe;
	fmd_event_t *ep;
top:
	(void) pthread_mutex_lock(&eq->eq_lock);

	while (!(eq->eq_flags & FMD_EVENTQ_ABORT) &&
	    (eq->eq_size == 0 || (eq->eq_flags & FMD_EVENTQ_SUSPEND)))
		(void) pthread_cond_wait(&eq->eq_cv, &eq->eq_lock);

	if (eq->eq_flags & FMD_EVENTQ_ABORT) {
		(void) pthread_mutex_unlock(&eq->eq_lock);
		return (NULL);
	}

	eqe = fmd_list_next(&eq->eq_list);
	fmd_list_delete(&eq->eq_list, eqe);
	eq->eq_size--;

	(void) pthread_mutex_unlock(&eq->eq_lock);

	ep = eqe->eqe_event;
	fmd_free(eqe, sizeof (fmd_eventqelem_t));

	/*
	 * If we dequeued a control event, release it and go back to sleep.
	 * fmd_event_rele() on the event will block as described in fmd_ctl.c.
	 * This effectively renders control events invisible to our callers
	 * as well as to statistics and observability tools (e.g. fmstat(8)).
	 */
	if (FMD_EVENT_TYPE(ep) == FMD_EVT_CTL) {
		fmd_event_rele(ep);
		goto top;
	}

	/*
	 * Before returning, update our statistics.  This code is essentially
	 * kstat_waitq_to_runq(9F), except simplified because our queues are
	 * always consumed by a single thread (i.e. runq len == 1).
	 */
	(void) pthread_mutex_lock(eq->eq_stats_lock);

	new = gethrtime();
	delta = new - eqs->eqs_wlastupdate.fmds_value.ui64;

	eqs->eqs_wlastupdate.fmds_value.ui64 = new;
	eqs->eqs_dlastupdate.fmds_value.ui64 = new;

	ASSERT(eqs->eqs_wcnt.fmds_value.ui32 != 0);
	wcnt = eqs->eqs_wcnt.fmds_value.ui32--;

	eqs->eqs_wlentime.fmds_value.ui64 += delta * wcnt;
	eqs->eqs_wtime.fmds_value.ui64 += delta;

	if (FMD_EVENT_TYPE(ep) == FMD_EVT_PROTOCOL)
		eqs->eqs_prdequeued.fmds_value.ui64++;

	eqs->eqs_dequeued.fmds_value.ui64++;
	(void) pthread_mutex_unlock(eq->eq_stats_lock);

	return (ep);
}

/*
 * Update statistics when an event is done being processed by the eventq's
 * consumer thread.  This is essentially kstat_runq_exit(9F) simplified for
 * our principle that a single thread consumes the queue (i.e. runq len == 1).
 */
void
fmd_eventq_done(fmd_eventq_t *eq)
{
	fmd_eventqstat_t *eqs = eq->eq_stats;
	hrtime_t new, delta;

	(void) pthread_mutex_lock(eq->eq_stats_lock);

	new = gethrtime();
	delta = new - eqs->eqs_dlastupdate.fmds_value.ui64;

	eqs->eqs_dlastupdate.fmds_value.ui64 = new;
	eqs->eqs_dtime.fmds_value.ui64 += delta;

	(void) pthread_mutex_unlock(eq->eq_stats_lock);
}

void
fmd_eventq_cancel(fmd_eventq_t *eq, uint_t type, void *data)
{
	fmd_eventqelem_t *eqe, *nqe;

	(void) pthread_mutex_lock(&eq->eq_lock);

	for (eqe = fmd_list_next(&eq->eq_list); eqe != NULL; eqe = nqe) {
		nqe = fmd_list_next(eqe);

		if (fmd_event_match(eqe->eqe_event, type, data)) {
			fmd_list_delete(&eq->eq_list, eqe);
			eq->eq_size--;
			fmd_event_rele(eqe->eqe_event);
			fmd_free(eqe, sizeof (fmd_eventqelem_t));
		}
	}

	(void) pthread_mutex_unlock(&eq->eq_lock);
}

void
fmd_eventq_suspend(fmd_eventq_t *eq)
{
	(void) pthread_mutex_lock(&eq->eq_lock);
	eq->eq_flags |= FMD_EVENTQ_SUSPEND;
	(void) pthread_mutex_unlock(&eq->eq_lock);
}

void
fmd_eventq_resume(fmd_eventq_t *eq)
{
	(void) pthread_mutex_lock(&eq->eq_lock);
	eq->eq_flags &= ~FMD_EVENTQ_SUSPEND;
	(void) pthread_cond_broadcast(&eq->eq_cv);
	(void) pthread_mutex_unlock(&eq->eq_lock);
}

void
fmd_eventq_abort(fmd_eventq_t *eq)
{
	fmd_eventqelem_t *eqe;

	(void) pthread_mutex_lock(&eq->eq_lock);

	while ((eqe = fmd_list_next(&eq->eq_list)) != NULL) {
		fmd_list_delete(&eq->eq_list, eqe);
		fmd_event_rele(eqe->eqe_event);
		fmd_free(eqe, sizeof (fmd_eventqelem_t));
	}

	eq->eq_flags |= FMD_EVENTQ_ABORT;
	(void) pthread_cond_broadcast(&eq->eq_cv);
	(void) pthread_mutex_unlock(&eq->eq_lock);
}
