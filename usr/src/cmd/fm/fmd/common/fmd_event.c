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
 */

#include <sys/fm/protocol.h>
#include <limits.h>

#include <fmd_alloc.h>
#include <fmd_subr.h>
#include <fmd_event.h>
#include <fmd_string.h>
#include <fmd_module.h>
#include <fmd_case.h>
#include <fmd_log.h>
#include <fmd_time.h>
#include <fmd_topo.h>
#include <fmd_ctl.h>

#include <fmd.h>

static void
fmd_event_nvwrap(fmd_event_impl_t *ep)
{
	(void) nvlist_remove_all(ep->ev_nvl, FMD_EVN_TTL);
	(void) nvlist_remove_all(ep->ev_nvl, FMD_EVN_TOD);

	(void) nvlist_add_uint8(ep->ev_nvl,
	    FMD_EVN_TTL, ep->ev_ttl);
	(void) nvlist_add_uint64_array(ep->ev_nvl,
	    FMD_EVN_TOD, (uint64_t *)&ep->ev_time, 2);
}

static void
fmd_event_nvunwrap(fmd_event_impl_t *ep, const fmd_timeval_t *tp)
{
	uint64_t *tod;
	uint_t n;

	if (nvlist_lookup_uint8(ep->ev_nvl, FMD_EVN_TTL, &ep->ev_ttl) != 0) {
		ep->ev_flags |= FMD_EVF_LOCAL;
		ep->ev_ttl = (uint8_t)fmd.d_xprt_ttl;
	}

	if (tp != NULL)
		ep->ev_time = *tp;
	else if (nvlist_lookup_uint64_array(ep->ev_nvl,
	    FMD_EVN_TOD, &tod, &n) == 0 && n >= 2)
		ep->ev_time = *(const fmd_timeval_t *)tod;
	else
		fmd_time_sync(&ep->ev_time, &ep->ev_hrt, 1);
}

fmd_event_t *
fmd_event_recreate(uint_t type, const fmd_timeval_t *tp,
    nvlist_t *nvl, void *data, fmd_log_t *lp, off64_t off, size_t len)
{
	fmd_event_impl_t *ep = fmd_alloc(sizeof (fmd_event_impl_t), FMD_SLEEP);

	fmd_timeval_t tod;
	hrtime_t hr0;

	(void) pthread_mutex_init(&ep->ev_lock, NULL);
	ep->ev_refs = 0;
	ASSERT(type < FMD_EVT_NTYPES);
	ep->ev_type = (uint8_t)type;
	ep->ev_state = FMD_EVS_RECEIVED;
	ep->ev_flags = FMD_EVF_REPLAY;
	ep->ev_nvl = nvl;
	ep->ev_data = data;
	ep->ev_log = lp;
	ep->ev_off = off;
	ep->ev_len = len;

	fmd_event_nvunwrap(ep, tp);

	/*
	 * If we're not restoring from a log, the event is marked volatile.  If
	 * we are restoring from a log, then hold the log pointer and increment
	 * the pending count.  If we're using a log but no offset and data len
	 * are specified, it's a checkpoint event: don't replay or set pending.
	 */
	if (lp == NULL)
		ep->ev_flags |= FMD_EVF_VOLATILE;
	else if (off != 0 && len != 0)
		fmd_log_hold_pending(lp);
	else {
		ep->ev_flags &= ~FMD_EVF_REPLAY;
		fmd_log_hold(lp);
	}

	/*
	 * Sample a (TOD, hrtime) pair from the current system clocks and then
	 * compute ev_hrt by taking the delta between this TOD and ev_time.
	 */
	fmd_time_sync(&tod, &hr0, 1);
	fmd_time_tod2hrt(hr0, &tod, &ep->ev_time, &ep->ev_hrt);

	fmd_event_nvwrap(ep);
	return ((fmd_event_t *)ep);
}

fmd_event_t *
fmd_event_create(uint_t type, hrtime_t hrt, nvlist_t *nvl, void *data)
{
	fmd_event_impl_t *ep = fmd_alloc(sizeof (fmd_event_impl_t), FMD_SLEEP);

	fmd_timeval_t tod;
	hrtime_t hr0;
	const char *p;
	uint64_t ena;

	(void) pthread_mutex_init(&ep->ev_lock, NULL);
	ep->ev_refs = 0;
	ASSERT(type < FMD_EVT_NTYPES);
	ep->ev_type = (uint8_t)type;
	ep->ev_state = FMD_EVS_RECEIVED;
	ep->ev_flags = FMD_EVF_VOLATILE | FMD_EVF_REPLAY | FMD_EVF_LOCAL;
	ep->ev_ttl = (uint8_t)fmd.d_xprt_ttl;
	ep->ev_nvl = nvl;
	ep->ev_data = data;
	ep->ev_log = NULL;
	ep->ev_off = 0;
	ep->ev_len = 0;

	/*
	 * Sample TOD and then set ev_time to the earlier TOD corresponding to
	 * the input hrtime value.  This needs to be improved later: hrestime
	 * should be sampled by the transport and passed as an input parameter.
	 */
	fmd_time_sync(&tod, &hr0, 1);

	if (hrt == FMD_HRT_NOW)
		hrt = hr0; /* use hrtime sampled by fmd_time_sync() */

	/*
	 * If this is an FMA protocol event of class "ereport.*" that contains
	 * valid ENA, we can compute a more precise bound on the event time.
	 */
	if (type == FMD_EVT_PROTOCOL && (p = strchr(data, '.')) != NULL &&
	    strncmp(data, FM_EREPORT_CLASS, (size_t)(p - (char *)data)) == 0 &&
	    nvlist_lookup_uint64(nvl, FM_EREPORT_ENA, &ena) == 0 &&
	    fmd.d_clockops == &fmd_timeops_native)
		hrt = fmd_time_ena2hrt(hrt, ena);

	fmd_time_hrt2tod(hr0, &tod, hrt, &ep->ev_time);
	ep->ev_hrt = hrt;

	fmd_event_nvwrap(ep);
	return ((fmd_event_t *)ep);
}

void
fmd_event_destroy(fmd_event_t *e)
{
	fmd_event_impl_t *ep = (fmd_event_impl_t *)e;

	ASSERT(MUTEX_HELD(&ep->ev_lock));
	ASSERT(ep->ev_refs == 0);

	/*
	 * If the current state is RECEIVED (i.e. no module has accepted the
	 * event) and the event was logged, then change the state to DISCARDED.
	 */
	if (ep->ev_state == FMD_EVS_RECEIVED)
		ep->ev_state = FMD_EVS_DISCARDED;

	/*
	 * If the current state is DISCARDED, ACCEPTED, or DIAGNOSED and the
	 * event has not yet been commited, then attempt to commit it now.
	 */
	if (ep->ev_state != FMD_EVS_RECEIVED && (ep->ev_flags & (
	    FMD_EVF_VOLATILE | FMD_EVF_REPLAY)) == FMD_EVF_REPLAY)
		fmd_log_commit(ep->ev_log, e);

	if (ep->ev_log != NULL) {
		if (ep->ev_flags & FMD_EVF_REPLAY)
			fmd_log_decommit(ep->ev_log, e);
		fmd_log_rele(ep->ev_log);
	}

	/*
	 * Perform any event type-specific cleanup activities, and then free
	 * the name-value pair list and underlying event data structure.
	 */
	switch (ep->ev_type) {
	case FMD_EVT_TIMEOUT:
		fmd_free(ep->ev_data, sizeof (fmd_modtimer_t));
		break;
	case FMD_EVT_CLOSE:
	case FMD_EVT_PUBLISH:
		fmd_case_rele(ep->ev_data);
		break;
	case FMD_EVT_CTL:
		fmd_ctl_fini(ep->ev_data);
		break;
	case FMD_EVT_TOPO:
		fmd_topo_rele(ep->ev_data);
		break;
	}

	nvlist_free(ep->ev_nvl);

	fmd_free(ep, sizeof (fmd_event_impl_t));
}

void
fmd_event_hold(fmd_event_t *e)
{
	fmd_event_impl_t *ep = (fmd_event_impl_t *)e;

	(void) pthread_mutex_lock(&ep->ev_lock);
	ep->ev_refs++;
	ASSERT(ep->ev_refs != 0);
	(void) pthread_mutex_unlock(&ep->ev_lock);

	if (ep->ev_type == FMD_EVT_CTL)
		fmd_ctl_hold(ep->ev_data);
}

void
fmd_event_rele(fmd_event_t *e)
{
	fmd_event_impl_t *ep = (fmd_event_impl_t *)e;

	if (ep->ev_type == FMD_EVT_CTL)
		fmd_ctl_rele(ep->ev_data);

	(void) pthread_mutex_lock(&ep->ev_lock);
	ASSERT(ep->ev_refs != 0);

	if (--ep->ev_refs == 0)
		fmd_event_destroy(e);
	else
		(void) pthread_mutex_unlock(&ep->ev_lock);
}

/*
 * Transition event from its current state to the specified state.  The states
 * for events are defined in fmd_event.h and work according to the diagram:
 *
 *  -------------     -------------     State      Description
 * ( RECEIVED =1 )-->( ACCEPTED =2 )    ---------- ---------------------------
 *  -----+-------\    ------+------     DISCARDED  No active references in fmd
 *       |        \         |           RECEIVED   Active refs in fmd, no case
 *  -----v-------  \  ------v------     ACCEPTED   Active refs, case assigned
 * ( DISCARDED=0 )  v( DIAGNOSED=3 )    DIAGNOSED  Active refs, case solved
 *  -------------     -------------
 *
 * Since events are reference counted on behalf of multiple subscribers, any
 * attempt to transition an event to an "earlier" or "equal" state (as defined
 * by the numeric state values shown in the diagram) is silently ignored.
 * An event begins life in the RECEIVED state, so the RECEIVED -> DISCARDED
 * transition is handled by fmd_event_destroy() when no references remain.
 */
void
fmd_event_transition(fmd_event_t *e, uint_t state)
{
	fmd_event_impl_t *ep = (fmd_event_impl_t *)e;

	(void) pthread_mutex_lock(&ep->ev_lock);

	TRACE((FMD_DBG_EVT, "event %p transition %u -> %u",
	    (void *)ep, ep->ev_state, state));

	if (state <= ep->ev_state) {
		(void) pthread_mutex_unlock(&ep->ev_lock);
		return; /* no state change necessary */
	}

	if (ep->ev_state < FMD_EVS_RECEIVED || ep->ev_state > FMD_EVS_DIAGNOSED)
		fmd_panic("illegal transition %u -> %u\n", ep->ev_state, state);

	ep->ev_state = state;
	(void) pthread_mutex_unlock(&ep->ev_lock);
}

/*
 * If the specified event is DISCARDED, ACCEPTED, OR DIAGNOSED and it has been
 * written to a log but is still marked for replay, attempt to commit it to the
 * log so that it will not be replayed.  If fmd_log_commit() is successful, it
 * will clear the FMD_EVF_REPLAY flag on the event for us.
 */
void
fmd_event_commit(fmd_event_t *e)
{
	fmd_event_impl_t *ep = (fmd_event_impl_t *)e;

	(void) pthread_mutex_lock(&ep->ev_lock);

	if (ep->ev_state != FMD_EVS_RECEIVED && (ep->ev_flags & (
	    FMD_EVF_VOLATILE | FMD_EVF_REPLAY)) == FMD_EVF_REPLAY)
		fmd_log_commit(ep->ev_log, e);

	(void) pthread_mutex_unlock(&ep->ev_lock);
}

/*
 * Compute the delta between events in nanoseconds.  To account for very old
 * events which are replayed, we must handle the case where ev_hrt is negative.
 * We convert the hrtime_t's to unsigned 64-bit integers and then handle the
 * case where 'old' is greater than 'new' (i.e. high-res time has wrapped).
 */
hrtime_t
fmd_event_delta(fmd_event_t *e1, fmd_event_t *e2)
{
	uint64_t old = ((fmd_event_impl_t *)e1)->ev_hrt;
	uint64_t new = ((fmd_event_impl_t *)e2)->ev_hrt;

	return (new >= old ? new - old : (UINT64_MAX - old) + new + 1);
}

hrtime_t
fmd_event_hrtime(fmd_event_t *ep)
{
	return (((fmd_event_impl_t *)ep)->ev_hrt);
}

int
fmd_event_match(fmd_event_t *e, uint_t type, const void *data)
{
	fmd_event_impl_t *ep = (fmd_event_impl_t *)e;

	if (ep->ev_type != type)
		return (0);

	if (type == FMD_EVT_PROTOCOL)
		return (fmd_strmatch(ep->ev_data, data));
	else if (type == FMD_EVT_TIMEOUT)
		return ((id_t)data == ((fmd_modtimer_t *)ep->ev_data)->mt_id);
	else
		return (ep->ev_data == data);
}

int
fmd_event_equal(fmd_event_t *e1, fmd_event_t *e2)
{
	fmd_event_impl_t *ep1 = (fmd_event_impl_t *)e1;
	fmd_event_impl_t *ep2 = (fmd_event_impl_t *)e2;

	return (ep1->ev_log != NULL &&
	    ep1->ev_log == ep2->ev_log && ep1->ev_off == ep2->ev_off);
}
