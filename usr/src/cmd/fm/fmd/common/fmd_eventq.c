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

#include <fmd_alloc.h>
#include <fmd_eventq.h>
#include <fmd_module.h>

fmd_eventq_t *
fmd_eventq_create(fmd_module_t *mp, uint_t limit)
{
	fmd_eventq_t *eq = fmd_zalloc(sizeof (fmd_eventq_t), FMD_SLEEP);

	(void) pthread_mutex_init(&eq->eq_lock, NULL);
	(void) pthread_cond_init(&eq->eq_cv, NULL);

	eq->eq_mod = mp;
	eq->eq_limit = limit;

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

	fmd_free(eq, sizeof (fmd_eventq_t));
}

static void
fmd_eventq_drop(fmd_eventq_t *eq, fmd_eventqelem_t *eqe)
{
	(void) pthread_mutex_lock(&eq->eq_mod->mod_stats_lock);
	eq->eq_mod->mod_stats->ms_dropped.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&eq->eq_mod->mod_stats_lock);

	fmd_event_rele(eqe->eqe_event);
	fmd_free(eqe, sizeof (fmd_eventqelem_t));
}

void
fmd_eventq_insert_at_head(fmd_eventq_t *eq, fmd_event_t *ep)
{
	fmd_eventqelem_t *eqe = fmd_alloc(sizeof (fmd_eventqelem_t), FMD_SLEEP);
	uint_t evt = ((fmd_event_impl_t *)ep)->ev_type;
	int ok;

	fmd_event_hold(ep);
	eqe->eqe_event = ep;

	(void) pthread_mutex_lock(&eq->eq_lock);

	if ((ok = eq->eq_size < eq->eq_limit || evt != FMD_EVT_PROTOCOL) != 0) {
		if (evt != FMD_EVT_CTL)
			fmd_modstat_eventq_dispatch(eq->eq_mod);

		fmd_list_prepend(&eq->eq_list, eqe);
		eq->eq_size++;
	}

	(void) pthread_mutex_unlock(&eq->eq_lock);
	(void) pthread_cond_broadcast(&eq->eq_cv);

	if (!ok)
		fmd_eventq_drop(eq, eqe);
}

void
fmd_eventq_insert_at_time(fmd_eventq_t *eq, fmd_event_t *ep)
{
	fmd_eventqelem_t *eqe = fmd_alloc(sizeof (fmd_eventqelem_t), FMD_SLEEP);
	uint_t evt = ((fmd_event_impl_t *)ep)->ev_type;
	hrtime_t hrt = fmd_event_hrtime(ep);

	fmd_eventqelem_t *oqe;
	int ok;

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
			fmd_modstat_eventq_dispatch(eq->eq_mod);

		fmd_list_insert_after(&eq->eq_list, oqe, eqe);
		eq->eq_size++;
	}

	(void) pthread_mutex_unlock(&eq->eq_lock);
	(void) pthread_cond_broadcast(&eq->eq_cv);

	if (!ok)
		fmd_eventq_drop(eq, eqe);
}

fmd_event_t *
fmd_eventq_delete(fmd_eventq_t *eq)
{
	fmd_eventqelem_t *eqe;
	fmd_event_t *ep;

	(void) pthread_mutex_lock(&eq->eq_lock);

	while (eq->eq_size == 0 && eq->eq_abort == 0)
		(void) pthread_cond_wait(&eq->eq_cv, &eq->eq_lock);

	if (eq->eq_abort) {
		(void) pthread_mutex_unlock(&eq->eq_lock);
		return (NULL);
	}

	eqe = fmd_list_next(&eq->eq_list);
	fmd_list_delete(&eq->eq_list, eqe);
	eq->eq_size--;

	(void) pthread_mutex_unlock(&eq->eq_lock);

	ep = eqe->eqe_event;
	fmd_free(eqe, sizeof (fmd_eventqelem_t));

	return (ep);
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
fmd_eventq_abort(fmd_eventq_t *eq)
{
	fmd_eventqelem_t *eqe;

	(void) pthread_mutex_lock(&eq->eq_lock);

	while ((eqe = fmd_list_next(&eq->eq_list)) != NULL) {
		fmd_list_delete(&eq->eq_list, eqe);
		fmd_event_rele(eqe->eqe_event);
		fmd_free(eqe, sizeof (fmd_eventqelem_t));
	}

	eq->eq_abort++; /* signal fmd_eventq_delete() to abort */

	(void) pthread_mutex_unlock(&eq->eq_lock);
	(void) pthread_cond_broadcast(&eq->eq_cv);
}
