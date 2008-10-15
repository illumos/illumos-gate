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

/*
 * FMD Transport Subsystem
 *
 * A transport module uses some underlying mechanism to transport events.
 * This mechanism may use any underlying link-layer protocol and may support
 * additional link-layer packets unrelated to FMA.  Some appropriate link-
 * layer mechanism to create the underlying connection is expected to be
 * called prior to calling fmd_xprt_open() itself.  Alternatively, a transport
 * may be created in the suspended state by specifying the FMD_XPRT_SUSPENDED
 * flag as part of the call to fmd_xprt_open(), and then may be resumed later.
 * The underlying transport mechanism is *required* to provide ordering: that
 * is, the sequences of bytes written across the transport must be read by
 * the remote peer in the order that they are written, even across separate
 * calls to fmdo_send().  As an example, the Internet TCP protocol would be
 * a valid transport as it guarantees ordering, whereas the Internet UDP
 * protocol would not because UDP datagrams may be delivered in any order
 * as a result of delays introduced when datagrams pass through routers.
 *
 * Similar to sending events, a transport module receives events that are from
 * its peer remote endpoint using some transport-specific mechanism that is
 * unknown to FMD.  As each event is received, the transport module is
 * responsible for constructing a valid nvlist_t object from the data and then
 * calling fmd_xprt_post() to post the event to the containing FMD's dispatch
 * queue, making it available to all local modules that are not transport
 * modules that have subscribed to the event.
 *
 * The following state machine is used for each transport.  The initial state
 * is either SYN, ACK, or RUN, depending on the flags specified to xprt_create.
 *
 *       FMD_XPRT_ACCEPT   !FMD_XPRT_ACCEPT
 *             |                 |
 * waiting  +--v--+           +--v--+  waiting
 * for syn  | SYN |--+     --+| ACK |  for ack
 * event    +-----+   \   /   +-----+  event
 *             |       \ /       |
 * drop all +--v--+     X     +--v--+  send subscriptions,
 * events   | ERR |<---+ +--->| SUB |  recv subscriptions,
 *          +-----+           +-----+  wait for run event
 *             ^                 |
 *             |     +-----+     |
 *             +-----| RUN |<----+
 *                   +--^--+
 *                      |
 *               FMD_XPRT_RDONLY
 *
 * When fmd_xprt_open() is called without FMD_XPRT_ACCEPT, the Common Transport
 * Layer enqueues a "syn" event for the module in its event queue and sets the
 * state to ACK.  In state ACK, we are waiting for the transport to get an
 * "ack" event and call fmd_xprt_post() on this event.  Other events will be
 * discarded.  If an "ack" is received, we transition to state SUB.  If a
 * configurable timeout occurs or if the "ack" is invalid (e.g. invalid version
 * exchange), we transition to state ERR.  Once in state ERR, no further
 * operations are valid except fmd_xprt_close() and fmd_xprt_error() will
 * return a non-zero value to the caller indicating the transport has failed.
 *
 * When fmd_xprt_open() is called with FMD_XPRT_ACCEPT, the Common Transport
 * Layer assumes this transport is being used to accept a virtual connection
 * from a remote peer that is sending a "syn", and sets the initial state to
 * SYN.  In this state, the transport waits for a "syn" event, validates it,
 * and then transitions to state SUB if it is valid or state ERR if it is not.
 *
 * Once in state SUB, the transport module is expected to receive a sequence of
 * zero or more "subscribe" events from the remote peer, followed by a "run"
 * event.  Once in state RUN, the transport is active and any events can be
 * sent or received.  The transport module is free to call fmd_xprt_close()
 * from any state.  The fmd_xprt_error() function will return zero if the
 * transport is not in the ERR state, or non-zero if it is in the ERR state.
 *
 * Once the state machine reaches RUN, other FMA protocol events can be sent
 * and received across the transport in addition to the various control events.
 *
 * Table of Common Transport Layer Control Events
 * ==============================================
 *
 * FMA Class                     Payload
 * ---------                     -------
 * resource.fm.xprt.uuclose      string (uuid of case)
 * resource.fm.xprt.subscribe    string (class pattern)
 * resource.fm.xprt.unsubscribe  string (class pattern)
 * resource.fm.xprt.unsuback     string (class pattern)
 * resource.fm.xprt.syn          version information
 * resource.fm.xprt.ack          version information
 * resource.fm.xprt.run          version information
 *
 * Control events are used to add and delete proxy subscriptions on the remote
 * transport peer module, and to set up connections.  When a "syn" event is
 * sent, FMD will include in the payload the highest version of the FMA event
 * protocol that is supported by the sender.  When a "syn" event is received,
 * the receiving FMD will use the minimum of this version and its version of
 * the protocol, and reply with this new minimum version in the "ack" event.
 * The receiver will then use this new minimum for subsequent event semantics.
 */

#include <sys/fm/protocol.h>
#include <strings.h>
#include <limits.h>

#include <fmd_alloc.h>
#include <fmd_error.h>
#include <fmd_conf.h>
#include <fmd_subr.h>
#include <fmd_string.h>
#include <fmd_protocol.h>
#include <fmd_thread.h>
#include <fmd_eventq.h>
#include <fmd_dispq.h>
#include <fmd_ctl.h>
#include <fmd_log.h>
#include <fmd_ustat.h>
#include <fmd_case.h>
#include <fmd_api.h>
#include <fmd_fmri.h>
#include <fmd_asru.h>
#include <fmd_xprt.h>

#include <fmd.h>

/*
 * The states shown above in the transport state machine diagram are encoded
 * using arrays of class patterns and a corresponding action function.  These
 * arrays are then passed to fmd_xprt_transition() to change transport states.
 */

const fmd_xprt_rule_t _fmd_xprt_state_syn[] = {
{ "resource.fm.xprt.syn", fmd_xprt_event_syn },
{ "*", fmd_xprt_event_error },
{ NULL, NULL }
};

const fmd_xprt_rule_t _fmd_xprt_state_ack[] = {
{ "resource.fm.xprt.ack", fmd_xprt_event_ack },
{ "*", fmd_xprt_event_error },
};

const fmd_xprt_rule_t _fmd_xprt_state_err[] = {
{ "*", fmd_xprt_event_drop },
{ NULL, NULL }
};

const fmd_xprt_rule_t _fmd_xprt_state_sub[] = {
{ "resource.fm.xprt.subscribe", fmd_xprt_event_sub },
{ "resource.fm.xprt.run", fmd_xprt_event_run },
{ "resource.fm.xprt.*", fmd_xprt_event_error },
{ "*", fmd_xprt_event_drop },
{ NULL, NULL }
};

const fmd_xprt_rule_t _fmd_xprt_state_run[] = {
{ "resource.fm.xprt.subscribe", fmd_xprt_event_sub },
{ "resource.fm.xprt.unsubscribe", fmd_xprt_event_unsub },
{ "resource.fm.xprt.unsuback", fmd_xprt_event_unsuback },
{ "resource.fm.xprt.uuclose", fmd_xprt_event_uuclose },
{ "resource.fm.xprt.*", fmd_xprt_event_error },
{ NULL, NULL }
};

/*
 * Template for per-transport statistics installed by fmd on behalf of each
 * transport.  These are used to initialize the per-transport xi_stats.  For
 * each statistic, the name is prepended with "fmd.xprt.%u", where %u is the
 * transport ID (xi_id) and then are inserted into the per-module stats hash.
 * The values in this array must match fmd_xprt_stat_t from <fmd_xprt.h>.
 */
static const fmd_xprt_stat_t _fmd_xprt_stat_tmpl = {
{
{ "dispatched", FMD_TYPE_UINT64, "total events dispatched to transport" },
{ "dequeued", FMD_TYPE_UINT64, "total events dequeued by transport" },
{ "prdequeued", FMD_TYPE_UINT64, "protocol events dequeued by transport" },
{ "dropped", FMD_TYPE_UINT64, "total events dropped on queue overflow" },
{ "wcnt", FMD_TYPE_UINT32, "count of events waiting on queue" },
{ "wtime", FMD_TYPE_TIME, "total wait time on queue" },
{ "wlentime", FMD_TYPE_TIME, "total wait length * time product" },
{ "wlastupdate", FMD_TYPE_TIME, "hrtime of last wait queue update" },
{ "dtime", FMD_TYPE_TIME, "total processing time after dequeue" },
{ "dlastupdate", FMD_TYPE_TIME, "hrtime of last event dequeue completion" },
},
{ "module", FMD_TYPE_STRING, "module that owns this transport" },
{ "authority", FMD_TYPE_STRING, "authority associated with this transport" },
{ "state", FMD_TYPE_STRING, "current transport state" },
{ "received", FMD_TYPE_UINT64, "events received by transport" },
{ "discarded", FMD_TYPE_UINT64, "bad events discarded by transport" },
{ "retried", FMD_TYPE_UINT64, "retries requested of transport" },
{ "replayed", FMD_TYPE_UINT64, "events replayed by transport" },
{ "lost", FMD_TYPE_UINT64, "events lost by transport" },
{ "timeouts", FMD_TYPE_UINT64, "events received by transport with ttl=0" },
{ "subscriptions", FMD_TYPE_UINT64, "subscriptions registered to transport" },
};

static void
fmd_xprt_class_hash_create(fmd_xprt_class_hash_t *xch, fmd_eventq_t *eq)
{
	uint_t hashlen = fmd.d_str_buckets;

	xch->xch_queue = eq;
	xch->xch_hashlen = hashlen;
	xch->xch_hash = fmd_zalloc(sizeof (void *) * hashlen, FMD_SLEEP);
}

static void
fmd_xprt_class_hash_destroy(fmd_xprt_class_hash_t *xch)
{
	fmd_eventq_t *eq = xch->xch_queue;
	fmd_xprt_class_t *xcp, *ncp;
	uint_t i;

	for (i = 0; i < xch->xch_hashlen; i++) {
		for (xcp = xch->xch_hash[i]; xcp != NULL; xcp = ncp) {
			ncp = xcp->xc_next;

			if (eq != NULL)
				fmd_dispq_delete(fmd.d_disp, eq, xcp->xc_class);

			fmd_strfree(xcp->xc_class);
			fmd_free(xcp, sizeof (fmd_xprt_class_t));
		}
	}

	fmd_free(xch->xch_hash, sizeof (void *) * xch->xch_hashlen);
}

/*
 * Insert the specified class into the specified class hash, and return the
 * reference count.  A return value of one indicates this is the first insert.
 * If an eventq is associated with the hash, insert a dispq subscription for it.
 */
static uint_t
fmd_xprt_class_hash_insert(fmd_xprt_impl_t *xip,
    fmd_xprt_class_hash_t *xch, const char *class)
{
	uint_t h = fmd_strhash(class) % xch->xch_hashlen;
	fmd_xprt_class_t *xcp;

	ASSERT(MUTEX_HELD(&xip->xi_lock));

	for (xcp = xch->xch_hash[h]; xcp != NULL; xcp = xcp->xc_next) {
		if (strcmp(class, xcp->xc_class) == 0)
			return (++xcp->xc_refs);
	}

	xcp = fmd_alloc(sizeof (fmd_xprt_class_t), FMD_SLEEP);
	xcp->xc_class = fmd_strdup(class, FMD_SLEEP);
	xcp->xc_next = xch->xch_hash[h];
	xcp->xc_refs = 1;
	xch->xch_hash[h] = xcp;

	if (xch->xch_queue != NULL)
		fmd_dispq_insert(fmd.d_disp, xch->xch_queue, class);

	return (xcp->xc_refs);
}

/*
 * Delete the specified class from the specified class hash, and return the
 * reference count.  A return value of zero indicates the class was deleted.
 * If an eventq is associated with the hash, delete the dispq subscription.
 */
static uint_t
fmd_xprt_class_hash_delete(fmd_xprt_impl_t *xip,
    fmd_xprt_class_hash_t *xch, const char *class)
{
	uint_t h = fmd_strhash(class) % xch->xch_hashlen;
	fmd_xprt_class_t *xcp, **pp;

	ASSERT(MUTEX_HELD(&xip->xi_lock));
	pp = &xch->xch_hash[h];

	for (xcp = *pp; xcp != NULL; xcp = xcp->xc_next) {
		if (strcmp(class, xcp->xc_class) == 0)
			break;
		else
			pp = &xcp->xc_next;
	}

	if (xcp == NULL)
		return (-1U); /* explicitly permit an invalid delete */

	if (--xcp->xc_refs != 0)
		return (xcp->xc_refs);

	ASSERT(xcp->xc_refs == 0);
	*pp = xcp->xc_next;

	fmd_strfree(xcp->xc_class);
	fmd_free(xcp, sizeof (fmd_xprt_class_t));

	if (xch->xch_queue != NULL)
		fmd_dispq_delete(fmd.d_disp, xch->xch_queue, class);

	return (0);
}

/*
 * Queue subscribe events for the specified transport corresponding to all of
 * the active module subscriptions.  This is an extremely heavyweight operation
 * that we expect to take place rarely (i.e. when loading a transport module
 * or when it establishes a connection).  We lock all of the known modules to
 * prevent them from adding or deleting subscriptions, then snapshot their
 * subscriptions, and then unlock all of the modules.  We hold the modhash
 * lock for the duration of this operation to prevent new modules from loading.
 */
static void
fmd_xprt_subscribe_modhash(fmd_xprt_impl_t *xip, fmd_modhash_t *mhp)
{
	fmd_xprt_t *xp = (fmd_xprt_t *)xip;
	const fmd_conf_path_t *pap;
	fmd_module_t *mp;
	uint_t i, j;

	(void) pthread_rwlock_rdlock(&mhp->mh_lock);

	for (i = 0; i < mhp->mh_hashlen; i++) {
		for (mp = mhp->mh_hash[i]; mp != NULL; mp = mp->mod_next)
			fmd_module_lock(mp);
	}

	(void) pthread_mutex_lock(&xip->xi_lock);
	ASSERT(!(xip->xi_flags & FMD_XPRT_SUBSCRIBER));
	xip->xi_flags |= FMD_XPRT_SUBSCRIBER;
	(void) pthread_mutex_unlock(&xip->xi_lock);

	for (i = 0; i < mhp->mh_hashlen; i++) {
		for (mp = mhp->mh_hash[i]; mp != NULL; mp = mp->mod_next) {
			(void) fmd_conf_getprop(mp->mod_conf,
			    FMD_PROP_SUBSCRIPTIONS, &pap);
			for (j = 0; j < pap->cpa_argc; j++)
				fmd_xprt_subscribe(xp, pap->cpa_argv[j]);
		}
	}

	for (i = 0; i < mhp->mh_hashlen; i++) {
		for (mp = mhp->mh_hash[i]; mp != NULL; mp = mp->mod_next)
			fmd_module_unlock(mp);
	}

	(void) pthread_rwlock_unlock(&mhp->mh_lock);
}

static void
fmd_xprt_transition(fmd_xprt_impl_t *xip,
    const fmd_xprt_rule_t *state, const char *tag)
{
	fmd_event_t *e;
	nvlist_t *nvl;
	char *s;

	TRACE((FMD_DBG_XPRT, "xprt %u -> %s\n", xip->xi_id, tag));

	xip->xi_state = state;
	s = fmd_strdup(tag, FMD_SLEEP);

	(void) pthread_mutex_lock(&xip->xi_stats_lock);
	fmd_strfree(xip->xi_stats->xs_state.fmds_value.str);
	xip->xi_stats->xs_state.fmds_value.str = s;
	(void) pthread_mutex_unlock(&xip->xi_stats_lock);

	/*
	 * If we've reached the SUB state, take out the big hammer and snapshot
	 * all of the subscriptions of all of the loaded modules.  Then queue a
	 * run event for our remote peer indicating that it can enter RUN.
	 */
	if (state == _fmd_xprt_state_sub) {
		fmd_xprt_subscribe_modhash(xip, fmd.d_mod_hash);

		nvl = fmd_protocol_xprt_ctl(xip->xi_queue->eq_mod,
		    "resource.fm.xprt.run", xip->xi_version);

		(void) nvlist_lookup_string(nvl, FM_CLASS, &s);
		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, s);
		fmd_eventq_insert_at_time(xip->xi_queue, e);
	}
}

static void
fmd_xprt_authupdate(fmd_xprt_impl_t *xip)
{
	char *s = fmd_fmri_auth2str(xip->xi_auth);

	(void) pthread_mutex_lock(&xip->xi_stats_lock);
	fmd_strfree(xip->xi_stats->xs_authority.fmds_value.str);
	xip->xi_stats->xs_authority.fmds_value.str = s;
	(void) pthread_mutex_unlock(&xip->xi_stats_lock);
}

static int
fmd_xprt_vmismatch(fmd_xprt_impl_t *xip, nvlist_t *nvl, uint_t *rversionp)
{
	uint8_t rversion;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &rversion) != 0) {
		(void) pthread_mutex_lock(&xip->xi_stats_lock);
		xip->xi_stats->xs_discarded.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&xip->xi_stats_lock);

		fmd_xprt_transition(xip, _fmd_xprt_state_err, "ERR");
		return (1);
	}

	if (rversion > xip->xi_version) {
		fmd_dprintf(FMD_DBG_XPRT, "xprt %u protocol mismatch: %u>%u\n",
		    xip->xi_id, rversion, xip->xi_version);

		(void) pthread_mutex_lock(&xip->xi_stats_lock);
		xip->xi_stats->xs_discarded.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&xip->xi_stats_lock);

		fmd_xprt_transition(xip, _fmd_xprt_state_err, "ERR");
		return (1);
	}

	if (rversionp != NULL)
		*rversionp = rversion;

	return (0);
}

void
fmd_xprt_event_syn(fmd_xprt_impl_t *xip, nvlist_t *nvl)
{
	fmd_event_t *e;
	uint_t vers;
	char *class;

	if (fmd_xprt_vmismatch(xip, nvl, &vers))
		return; /* transitioned to error state */

	/*
	 * If the transport module didn't specify an authority, extract the
	 * one that is passed along with the xprt.syn event and use that.
	 */
	if (xip->xi_auth == NULL &&
	    nvlist_lookup_nvlist(nvl, FM_RSRC_RESOURCE, &nvl) == 0 &&
	    nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &nvl) == 0) {
		(void) nvlist_xdup(nvl, &xip->xi_auth, &fmd.d_nva);
		fmd_xprt_authupdate(xip);
	}

	nvl = fmd_protocol_xprt_ctl(xip->xi_queue->eq_mod,
	    "resource.fm.xprt.ack", xip->xi_version);

	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
	fmd_eventq_insert_at_time(xip->xi_queue, e);

	xip->xi_version = MIN(FM_RSRC_XPRT_VERSION, vers);
	fmd_xprt_transition(xip, _fmd_xprt_state_sub, "SUB");
}

void
fmd_xprt_event_ack(fmd_xprt_impl_t *xip, nvlist_t *nvl)
{
	uint_t vers;

	if (fmd_xprt_vmismatch(xip, nvl, &vers))
		return; /* transitioned to error state */

	/*
	 * If the transport module didn't specify an authority, extract the
	 * one that is passed along with the xprt.syn event and use that.
	 */
	if (xip->xi_auth == NULL &&
	    nvlist_lookup_nvlist(nvl, FM_RSRC_RESOURCE, &nvl) == 0 &&
	    nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &nvl) == 0) {
		(void) nvlist_xdup(nvl, &xip->xi_auth, &fmd.d_nva);
		fmd_xprt_authupdate(xip);
	}

	xip->xi_version = MIN(FM_RSRC_XPRT_VERSION, vers);
	fmd_xprt_transition(xip, _fmd_xprt_state_sub, "SUB");
}

/*
 * Upon transition to RUN, we take every solved case and resend a list.suspect
 * event for it to our remote peer.  If a case transitions from solved to a
 * future state (CLOSE_WAIT, CLOSED, or REPAIRED) while we are iterating over
 * the case hash, we will get it as part of examining the resource cache, next.
 */
static void
fmd_xprt_send_case(fmd_case_t *cp, void *arg)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	fmd_xprt_impl_t *xip = arg;

	fmd_event_t *e;
	nvlist_t *nvl;
	char *class;

	if (cip->ci_state != FMD_CASE_SOLVED)
		return; /* unsolved, or we'll get it during the ASRU pass */

	nvl = fmd_case_mkevent(cp, FM_LIST_SUSPECT_CLASS);
	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);

	fmd_dprintf(FMD_DBG_XPRT, "re-send %s for %s to transport %u\n",
	    FM_LIST_SUSPECT_CLASS, cip->ci_uuid, xip->xi_id);

	fmd_dispq_dispatch_gid(fmd.d_disp, e, class, xip->xi_queue->eq_sgid);
}

/*
 * Upon transition to RUN, we take every ASRU which is in the degraded state
 * and resend a fault.* event for it to our remote peer, in case the peer is
 * running in the fault manager that knows how to disable this resource.  If
 * any new resources are added to the cache during our iteration, this is no
 * problem because our subscriptions are already proxied and so any new cases
 * will result in a list.suspect event being transported if that is needed.
 */
static void
fmd_xprt_send_asru(fmd_asru_t *ap, void *arg)
{
	fmd_xprt_impl_t *xip = arg;
	nvlist_t *nvl = NULL;
	fmd_event_t *e;
	char *class;

	(void) pthread_mutex_lock(&ap->asru_lock);

	if ((ap->asru_flags & (FMD_ASRU_INTERNAL | FMD_ASRU_STATE)) ==
	    FMD_ASRU_FAULTY && fmd_case_orphaned(ap->asru_case))
		(void) nvlist_xdup(ap->asru_event, &nvl, &fmd.d_nva);

	(void) pthread_mutex_unlock(&ap->asru_lock);

	if (nvl == NULL)
		return; /* asru is internal, unusable, or not faulty */

	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);

	fmd_dprintf(FMD_DBG_XPRT, "re-send %s for %s to transport %u\n",
	    class, ap->asru_name, xip->xi_id);

	fmd_dispq_dispatch_gid(fmd.d_disp, e, class, xip->xi_queue->eq_sgid);
}

void
fmd_xprt_event_run(fmd_xprt_impl_t *xip, nvlist_t *nvl)
{
	if (!fmd_xprt_vmismatch(xip, nvl, NULL)) {
		fmd_xprt_transition(xip, _fmd_xprt_state_run, "RUN");
		fmd_case_hash_apply(fmd.d_cases, fmd_xprt_send_case, xip);
		fmd_asru_hash_apply(fmd.d_asrus, fmd_xprt_send_asru, xip);
	}
}

void
fmd_xprt_event_sub(fmd_xprt_impl_t *xip, nvlist_t *nvl)
{
	char *class;

	if (fmd_xprt_vmismatch(xip, nvl, NULL))
		return; /* transitioned to error state */

	if (nvlist_lookup_string(nvl, FM_RSRC_XPRT_SUBCLASS, &class) != 0)
		return; /* malformed protocol event */

	(void) pthread_mutex_lock(&xip->xi_lock);
	(void) fmd_xprt_class_hash_insert(xip, &xip->xi_lsub, class);
	(void) pthread_mutex_unlock(&xip->xi_lock);

	(void) pthread_mutex_lock(&xip->xi_stats_lock);
	xip->xi_stats->xs_subscriptions.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&xip->xi_stats_lock);
}

void
fmd_xprt_event_unsub(fmd_xprt_impl_t *xip, nvlist_t *nvl)
{
	fmd_event_t *e;
	char *class;

	if (fmd_xprt_vmismatch(xip, nvl, NULL))
		return; /* transitioned to error state */

	if (nvlist_lookup_string(nvl, FM_RSRC_XPRT_SUBCLASS, &class) != 0)
		return; /* malformed protocol event */

	(void) pthread_mutex_lock(&xip->xi_lock);
	(void) fmd_xprt_class_hash_delete(xip, &xip->xi_lsub, class);
	(void) pthread_mutex_unlock(&xip->xi_lock);

	(void) pthread_mutex_lock(&xip->xi_stats_lock);
	xip->xi_stats->xs_subscriptions.fmds_value.ui64--;
	(void) pthread_mutex_unlock(&xip->xi_stats_lock);

	nvl = fmd_protocol_xprt_sub(xip->xi_queue->eq_mod,
	    "resource.fm.xprt.unsuback", xip->xi_version, class);

	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);
	fmd_eventq_insert_at_time(xip->xi_queue, e);
}

void
fmd_xprt_event_unsuback(fmd_xprt_impl_t *xip, nvlist_t *nvl)
{
	char *class;

	if (fmd_xprt_vmismatch(xip, nvl, NULL))
		return; /* transitioned to error state */

	if (nvlist_lookup_string(nvl, FM_RSRC_XPRT_SUBCLASS, &class) != 0)
		return; /* malformed protocol event */

	(void) pthread_mutex_lock(&xip->xi_lock);
	(void) fmd_xprt_class_hash_delete(xip, &xip->xi_usub, class);
	(void) pthread_mutex_unlock(&xip->xi_lock);
}

void
fmd_xprt_event_uuclose(fmd_xprt_impl_t *xip, nvlist_t *nvl)
{
	fmd_case_t *cp;
	char *uuid;

	if (fmd_xprt_vmismatch(xip, nvl, NULL))
		return; /* transitioned to error state */

	if (nvlist_lookup_string(nvl, FM_RSRC_XPRT_UUID, &uuid) == 0 &&
	    (cp = fmd_case_hash_lookup(fmd.d_cases, uuid)) != NULL) {
		fmd_case_transition(cp, FMD_CASE_CLOSE_WAIT, FMD_CF_ISOLATED);
		fmd_case_rele(cp);
	}
}

void
fmd_xprt_event_error(fmd_xprt_impl_t *xip, nvlist_t *nvl)
{
	char *class = "<unknown>";

	(void) pthread_mutex_lock(&xip->xi_stats_lock);
	xip->xi_stats->xs_discarded.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&xip->xi_stats_lock);

	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	TRACE((FMD_DBG_XPRT, "xprt %u bad event %s\n", xip->xi_id, class));

	fmd_xprt_transition(xip, _fmd_xprt_state_err, "ERR");
}

void
fmd_xprt_event_drop(fmd_xprt_impl_t *xip, nvlist_t *nvl)
{
	char *class = "<unknown>";

	(void) pthread_mutex_lock(&xip->xi_stats_lock);
	xip->xi_stats->xs_discarded.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&xip->xi_stats_lock);

	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	TRACE((FMD_DBG_XPRT, "xprt %u drop event %s\n", xip->xi_id, class));

}

fmd_xprt_t *
fmd_xprt_create(fmd_module_t *mp, uint_t flags, nvlist_t *auth, void *data)
{
	fmd_xprt_impl_t *xip = fmd_zalloc(sizeof (fmd_xprt_impl_t), FMD_SLEEP);
	fmd_stat_t *statv;
	uint_t i, statc;

	char buf[PATH_MAX];
	fmd_event_t *e;
	nvlist_t *nvl;
	char *s;

	(void) pthread_mutex_init(&xip->xi_lock, NULL);
	(void) pthread_cond_init(&xip->xi_cv, NULL);
	(void) pthread_mutex_init(&xip->xi_stats_lock, NULL);

	xip->xi_auth = auth;
	xip->xi_data = data;
	xip->xi_version = FM_RSRC_XPRT_VERSION;
	xip->xi_flags = flags;

	/*
	 * Grab fmd.d_xprt_lock to block fmd_xprt_suspend_all() and then create
	 * a transport ID and make it visible in fmd.d_xprt_ids.  If transports
	 * were previously suspended, set the FMD_XPRT_DSUSPENDED flag on us to
	 * ensure that this transport will not run until fmd_xprt_resume_all().
	 */
	(void) pthread_mutex_lock(&fmd.d_xprt_lock);
	xip->xi_id = fmd_idspace_alloc(fmd.d_xprt_ids, xip);

	if (fmd.d_xprt_suspend != 0)
		xip->xi_flags |= FMD_XPRT_DSUSPENDED;

	(void) pthread_mutex_unlock(&fmd.d_xprt_lock);

	/*
	 * If the module has not yet finished _fmd_init(), set the ISUSPENDED
	 * bit so that fmdo_send() is not called until _fmd_init() completes.
	 */
	if (!(mp->mod_flags & FMD_MOD_INIT))
		xip->xi_flags |= FMD_XPRT_ISUSPENDED;

	/*
	 * Initialize the transport statistics that we keep on behalf of fmd.
	 * These are set up using a template defined at the top of this file.
	 * We rename each statistic with a prefix ensuring its uniqueness.
	 */
	statc = sizeof (_fmd_xprt_stat_tmpl) / sizeof (fmd_stat_t);
	statv = fmd_alloc(sizeof (_fmd_xprt_stat_tmpl), FMD_SLEEP);
	bcopy(&_fmd_xprt_stat_tmpl, statv, sizeof (_fmd_xprt_stat_tmpl));

	for (i = 0; i < statc; i++) {
		(void) snprintf(statv[i].fmds_name,
		    sizeof (statv[i].fmds_name), "fmd.xprt.%u.%s", xip->xi_id,
		    ((fmd_stat_t *)&_fmd_xprt_stat_tmpl + i)->fmds_name);
	}

	xip->xi_stats = (fmd_xprt_stat_t *)fmd_ustat_insert(
	    mp->mod_ustat, FMD_USTAT_NOALLOC, statc, statv, NULL);

	if (xip->xi_stats == NULL)
		fmd_panic("failed to create xi_stats (%p)\n", (void *)statv);

	xip->xi_stats->xs_module.fmds_value.str =
	    fmd_strdup(mp->mod_name, FMD_SLEEP);

	if (xip->xi_auth != NULL)
		fmd_xprt_authupdate(xip);

	/*
	 * Create the outbound eventq for this transport and link to its stats.
	 * If any suspend bits were set above, suspend the eventq immediately.
	 */
	xip->xi_queue = fmd_eventq_create(mp, &xip->xi_stats->xs_evqstat,
	    &xip->xi_stats_lock, mp->mod_stats->ms_xprtqlimit.fmds_value.ui32);

	if (xip->xi_flags & FMD_XPRT_SMASK)
		fmd_eventq_suspend(xip->xi_queue);

	/*
	 * Create our subscription hashes: local subscriptions go to xi_queue,
	 * remote subscriptions are tracked only for protocol requests, and
	 * pending unsubscriptions are associated with the /dev/null eventq.
	 */
	fmd_xprt_class_hash_create(&xip->xi_lsub, xip->xi_queue);
	fmd_xprt_class_hash_create(&xip->xi_rsub, NULL);
	fmd_xprt_class_hash_create(&xip->xi_usub, fmd.d_rmod->mod_queue);

	/*
	 * Determine our initial state based upon the creation flags.  If we're
	 * read-only, go directly to RUN.  If we're accepting a new connection,
	 * wait for a SYN.  Otherwise send a SYN and wait for an ACK.
	 */
	if ((flags & FMD_XPRT_RDWR) == FMD_XPRT_RDONLY)
		fmd_xprt_transition(xip, _fmd_xprt_state_run, "RUN");
	else if (flags & FMD_XPRT_ACCEPT)
		fmd_xprt_transition(xip, _fmd_xprt_state_syn, "SYN");
	else
		fmd_xprt_transition(xip, _fmd_xprt_state_ack, "ACK");

	/*
	 * If client.xprtlog is set to TRUE, create a debugging log for the
	 * events received by the transport in var/fm/fmd/xprt/.
	 */
	(void) fmd_conf_getprop(fmd.d_conf, "client.xprtlog", &i);
	(void) fmd_conf_getprop(fmd.d_conf, "log.xprt", &s);

	if (i) {
		(void) snprintf(buf, sizeof (buf), "%s/%u.log", s, xip->xi_id);
		xip->xi_log = fmd_log_open(fmd.d_rootdir, buf, FMD_LOG_XPRT);
	}

	ASSERT(fmd_module_locked(mp));
	fmd_list_append(&mp->mod_transports, xip);

	(void) pthread_mutex_lock(&mp->mod_stats_lock);
	mp->mod_stats->ms_xprtopen.fmds_value.ui32++;
	(void) pthread_mutex_unlock(&mp->mod_stats_lock);

	/*
	 * If this is a read-only transport, return without creating a send
	 * queue thread and setting up any connection events in our queue.
	 */
	if ((flags & FMD_XPRT_RDWR) == FMD_XPRT_RDONLY)
		goto out;

	/*
	 * Once the transport is fully initialized, create a send queue thread
	 * and start any connect events flowing to complete our initialization.
	 */
	if ((xip->xi_thread = fmd_thread_create(mp,
	    (fmd_thread_f *)fmd_xprt_send, xip)) == NULL) {

		fmd_error(EFMD_XPRT_THR,
		    "failed to create thread for transport %u", xip->xi_id);

		fmd_xprt_destroy((fmd_xprt_t *)xip);
		(void) fmd_set_errno(EFMD_XPRT_THR);
		return (NULL);
	}

	/*
	 * If the transport is not being opened to accept an inbound connect,
	 * start an outbound connection by enqueuing a SYN event for our peer.
	 */
	if (!(flags & FMD_XPRT_ACCEPT)) {
		nvl = fmd_protocol_xprt_ctl(mp,
		    "resource.fm.xprt.syn", FM_RSRC_XPRT_VERSION);

		(void) nvlist_lookup_string(nvl, FM_CLASS, &s);
		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, s);
		fmd_eventq_insert_at_time(xip->xi_queue, e);
	}
out:
	fmd_dprintf(FMD_DBG_XPRT, "opened transport %u\n", xip->xi_id);
	return ((fmd_xprt_t *)xip);
}

void
fmd_xprt_destroy(fmd_xprt_t *xp)
{
	fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)xp;
	fmd_module_t *mp = xip->xi_queue->eq_mod;
	uint_t id = xip->xi_id;

	fmd_case_impl_t *cip, *nip;
	fmd_stat_t *sp;
	uint_t i, n;

	ASSERT(fmd_module_locked(mp));
	fmd_list_delete(&mp->mod_transports, xip);

	(void) pthread_mutex_lock(&mp->mod_stats_lock);
	mp->mod_stats->ms_xprtopen.fmds_value.ui32--;
	(void) pthread_mutex_unlock(&mp->mod_stats_lock);

	(void) pthread_mutex_lock(&xip->xi_lock);

	while (xip->xi_busy != 0)
		(void) pthread_cond_wait(&xip->xi_cv, &xip->xi_lock);

	/*
	 * Remove the transport from global visibility, cancel its send-side
	 * thread, join with it, and then remove the transport from module
	 * visibility.  Once all this is done, destroy and free the transport.
	 */
	(void) fmd_idspace_free(fmd.d_xprt_ids, xip->xi_id);

	if (xip->xi_thread != NULL) {
		fmd_eventq_abort(xip->xi_queue);
		fmd_thread_destroy(xip->xi_thread, FMD_THREAD_JOIN);
	}

	if (xip->xi_log != NULL)
		fmd_log_rele(xip->xi_log);

	/*
	 * Release every case handle in the module that was cached by this
	 * transport.  This will result in these cases disappearing from the
	 * local case hash so that fmd_case_uuclose() can no longer be used.
	 */
	for (cip = fmd_list_next(&mp->mod_cases); cip != NULL; cip = nip) {
		nip = fmd_list_next(cip);
		if (cip->ci_xprt == xp)
			fmd_case_discard((fmd_case_t *)cip);
	}

	/*
	 * Destroy every class in the various subscription hashes and remove
	 * any corresponding subscriptions from the event dispatch queue.
	 */
	fmd_xprt_class_hash_destroy(&xip->xi_lsub);
	fmd_xprt_class_hash_destroy(&xip->xi_rsub);
	fmd_xprt_class_hash_destroy(&xip->xi_usub);

	/*
	 * Uniquify the stat names exactly as was done in fmd_xprt_create()
	 * before calling fmd_ustat_insert(), otherwise fmd_ustat_delete()
	 * won't find the entries in the hash table.
	 */
	n = sizeof (_fmd_xprt_stat_tmpl) / sizeof (fmd_stat_t);
	sp = fmd_alloc(sizeof (_fmd_xprt_stat_tmpl), FMD_SLEEP);
	bcopy(&_fmd_xprt_stat_tmpl, sp, sizeof (_fmd_xprt_stat_tmpl));
	for (i = 0; i < n; i++) {
		(void) snprintf(sp[i].fmds_name,
		    sizeof (sp[i].fmds_name), "fmd.xprt.%u.%s", xip->xi_id,
		    ((fmd_stat_t *)&_fmd_xprt_stat_tmpl + i)->fmds_name);
	}
	fmd_ustat_delete(mp->mod_ustat, n, sp);
	fmd_free(sp, sizeof (_fmd_xprt_stat_tmpl));

	fmd_free(xip->xi_stats, sizeof (fmd_xprt_stat_t));
	fmd_eventq_destroy(xip->xi_queue);
	nvlist_free(xip->xi_auth);
	fmd_free(xip, sizeof (fmd_xprt_impl_t));

	fmd_dprintf(FMD_DBG_XPRT, "closed transport %u\n", id);
}

void
fmd_xprt_xsuspend(fmd_xprt_t *xp, uint_t flags)
{
	fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)xp;
	uint_t oflags;

	ASSERT((flags & ~FMD_XPRT_SMASK) == 0);
	(void) pthread_mutex_lock(&xip->xi_lock);

	oflags = xip->xi_flags;
	xip->xi_flags |= flags;

	if (!(oflags & FMD_XPRT_SMASK) && (xip->xi_flags & FMD_XPRT_SMASK) != 0)
		fmd_eventq_suspend(xip->xi_queue);

	(void) pthread_cond_broadcast(&xip->xi_cv);

	while (xip->xi_busy != 0)
		(void) pthread_cond_wait(&xip->xi_cv, &xip->xi_lock);

	(void) pthread_mutex_unlock(&xip->xi_lock);
}

void
fmd_xprt_xresume(fmd_xprt_t *xp, uint_t flags)
{
	fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)xp;
	uint_t oflags;

	ASSERT((flags & ~FMD_XPRT_SMASK) == 0);
	(void) pthread_mutex_lock(&xip->xi_lock);

	oflags = xip->xi_flags;
	xip->xi_flags &= ~flags;

	if ((oflags & FMD_XPRT_SMASK) != 0 && !(xip->xi_flags & FMD_XPRT_SMASK))
		fmd_eventq_resume(xip->xi_queue);

	(void) pthread_cond_broadcast(&xip->xi_cv);
	(void) pthread_mutex_unlock(&xip->xi_lock);
}

void
fmd_xprt_send(fmd_xprt_t *xp)
{
	fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)xp;
	fmd_module_t *mp = xip->xi_queue->eq_mod;
	fmd_event_t *ep;
	int err;

	while ((ep = fmd_eventq_delete(xip->xi_queue)) != NULL) {
		if (FMD_EVENT_TTL(ep) == 0) {
			fmd_event_rele(ep);
			continue;
		}

		fmd_dprintf(FMD_DBG_XPRT, "xprt %u sending %s\n",
		    xip->xi_id, (char *)FMD_EVENT_DATA(ep));

		err = mp->mod_ops->mop_transport(mp, xp, ep);
		fmd_eventq_done(xip->xi_queue);

		if (err == FMD_SEND_RETRY) {
			fmd_eventq_insert_at_time(xip->xi_queue, ep);
			(void) pthread_mutex_lock(&xip->xi_stats_lock);
			xip->xi_stats->xs_retried.fmds_value.ui64++;
			(void) pthread_mutex_unlock(&xip->xi_stats_lock);
		}

		if (err != FMD_SEND_SUCCESS && err != FMD_SEND_RETRY) {
			(void) pthread_mutex_lock(&xip->xi_stats_lock);
			xip->xi_stats->xs_lost.fmds_value.ui64++;
			(void) pthread_mutex_unlock(&xip->xi_stats_lock);
		}

		fmd_event_rele(ep);
	}
}

void
fmd_xprt_recv(fmd_xprt_t *xp, nvlist_t *nvl, hrtime_t hrt, boolean_t logonly)
{
	fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)xp;
	const fmd_xprt_rule_t *xrp;
	fmd_t *dp = &fmd;

	fmd_event_t *e;
	char *class, *uuid, *code;
	boolean_t isproto, isereport;

	uint64_t *tod;
	uint8_t ttl;
	uint_t n;

	/*
	 * Grab the transport lock and set the busy flag to indicate we are
	 * busy receiving an event.  If [DI]SUSPEND is pending, wait until fmd
	 * resumes the transport before continuing on with the receive.
	 */
	(void) pthread_mutex_lock(&xip->xi_lock);

	while (xip->xi_flags & (FMD_XPRT_DSUSPENDED | FMD_XPRT_ISUSPENDED)) {

		if (fmd.d_signal != 0) {
			(void) pthread_mutex_unlock(&xip->xi_lock);
			return; /* fmd_destroy() is in progress */
		}

		(void) pthread_cond_wait(&xip->xi_cv, &xip->xi_lock);
	}

	xip->xi_busy++;
	ASSERT(xip->xi_busy != 0);

	(void) pthread_mutex_unlock(&xip->xi_lock);

	(void) pthread_mutex_lock(&xip->xi_stats_lock);
	xip->xi_stats->xs_received.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&xip->xi_stats_lock);

	if (nvlist_lookup_string(nvl, FM_CLASS, &class) != 0) {
		fmd_error(EFMD_XPRT_PAYLOAD, "discarding nvlist %p: missing "
		    "required \"%s\" payload element", (void *)nvl, FM_CLASS);

		(void) pthread_mutex_lock(&xip->xi_stats_lock);
		xip->xi_stats->xs_discarded.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&xip->xi_stats_lock);

		nvlist_free(nvl);
		goto done;
	}

	fmd_dprintf(FMD_DBG_XPRT, "xprt %u %s %s\n", xip->xi_id,
	    ((logonly == FMD_B_TRUE) ? "logging" : "posting"), class);

	isereport = (strncmp(class, FM_EREPORT_CLASS,
	    sizeof (FM_EREPORT_CLASS - 1)) == 0) ? FMD_B_TRUE : FMD_B_FALSE;

	/*
	 * The logonly flag should only be set for ereports.
	 */
	if ((logonly == FMD_B_TRUE) && (isereport == FMD_B_FALSE)) {
		fmd_error(EFMD_XPRT_INVAL, "discarding nvlist %p: "
		    "logonly flag is not valid for class %s",
		    (void *)nvl, class);

		(void) pthread_mutex_lock(&xip->xi_stats_lock);
		xip->xi_stats->xs_discarded.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&xip->xi_stats_lock);

		nvlist_free(nvl);
		goto done;
	}

	/*
	 * If a time-to-live value is present in the event and is zero, drop
	 * the event and bump xs_timeouts.  Otherwise decrement the TTL value.
	 */
	if (nvlist_lookup_uint8(nvl, FMD_EVN_TTL, &ttl) == 0) {
		if (ttl == 0) {
			fmd_dprintf(FMD_DBG_XPRT, "xprt %u nvlist %p (%s) "
			    "timeout: event received with ttl=0\n",
			    xip->xi_id, (void *)nvl, class);

			(void) pthread_mutex_lock(&xip->xi_stats_lock);
			xip->xi_stats->xs_timeouts.fmds_value.ui64++;
			(void) pthread_mutex_unlock(&xip->xi_stats_lock);

			nvlist_free(nvl);
			goto done;
		}
		(void) nvlist_remove(nvl, FMD_EVN_TTL, DATA_TYPE_UINT8);
		(void) nvlist_add_uint8(nvl, FMD_EVN_TTL, ttl - 1);
	}

	/*
	 * If we are using the native system clock, the underlying transport
	 * code can provide a tighter event time bound by telling us when the
	 * event was enqueued.  If we're using simulated clocks, this time
	 * has no meaning to us, so just reset the value to use HRT_NOW.
	 */
	if (dp->d_clockops != &fmd_timeops_native)
		hrt = FMD_HRT_NOW;

	/*
	 * If an event's class is in the FMD_CTL_CLASS family, then create a
	 * control event.  If a FMD_EVN_TOD member is found, create a protocol
	 * event using this time.  Otherwise create a protocol event using hrt.
	 */
	isproto = (strncmp(class, FMD_CTL_CLASS, FMD_CTL_CLASS_LEN) == 0) ?
	    FMD_B_FALSE : FMD_B_TRUE;
	if (isproto == FMD_B_FALSE)
		e = fmd_event_create(FMD_EVT_CTL, hrt, nvl, fmd_ctl_init(nvl));
	else if (nvlist_lookup_uint64_array(nvl, FMD_EVN_TOD, &tod, &n) != 0)
		e = fmd_event_create(FMD_EVT_PROTOCOL, hrt, nvl, class);
	else {
		e = fmd_event_recreate(FMD_EVT_PROTOCOL,
		    NULL, nvl, class, NULL, 0, 0);
	}

	/*
	 * If the debug log is enabled, create a temporary event, log it to the
	 * debug log, and then reset the underlying state of the event.
	 */
	if (xip->xi_log != NULL) {
		fmd_event_impl_t *ep = (fmd_event_impl_t *)e;

		fmd_log_append(xip->xi_log, e, NULL);

		ep->ev_flags |= FMD_EVF_VOLATILE;
		ep->ev_off = 0;
		ep->ev_len = 0;

		if (ep->ev_log != NULL) {
			fmd_log_rele(ep->ev_log);
			ep->ev_log = NULL;
		}
	}

	/*
	 * Iterate over the rules for the current state trying to match the
	 * event class to one of our special rules.  If a rule is matched, the
	 * event is consumed and not dispatched to other modules.  If the rule
	 * set ends without matching an event, we fall through to dispatching.
	 */
	for (xrp = xip->xi_state; xrp->xr_class != NULL; xrp++) {
		if (fmd_event_match(e, FMD_EVT_PROTOCOL, xrp->xr_class)) {
			fmd_event_hold(e);
			xrp->xr_func(xip, nvl);
			fmd_event_rele(e);
			goto done;
		}
	}

	/*
	 * Record the event in the errlog if it is an ereport.  This code will
	 * be replaced later with a per-transport intent log instead.
	 */
	if (isereport == FMD_B_TRUE) {
		(void) pthread_rwlock_rdlock(&dp->d_log_lock);
		fmd_log_append(dp->d_errlog, e, NULL);
		(void) pthread_rwlock_unlock(&dp->d_log_lock);
	}

	/*
	 * If a list.suspect event is received, create a case for the specified
	 * UUID in the case hash, with the transport module as its owner.  If
	 * the UUID is already known, fmd_case_recreate() will return NULL and
	 * we simply proceed to our normal event handling regardless.
	 */
	if (fmd_event_match(e, FMD_EVT_PROTOCOL, FM_LIST_SUSPECT_CLASS) &&
	    nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) == 0 &&
	    nvlist_lookup_string(nvl, FM_SUSPECT_DIAG_CODE, &code) == 0) {
		fmd_module_lock(xip->xi_queue->eq_mod);
		(void) fmd_case_recreate(xip->xi_queue->eq_mod,
		    xp, FMD_CASE_SOLVED, uuid, code);
		fmd_module_unlock(xip->xi_queue->eq_mod);
	}

	if (logonly == FMD_B_TRUE) {
		fmd_event_hold(e);
		fmd_event_rele(e);
	} else if (isproto == FMD_B_TRUE)
		fmd_dispq_dispatch(dp->d_disp, e, class);
	else
		fmd_modhash_dispatch(dp->d_mod_hash, e);
done:
	(void) pthread_mutex_lock(&xip->xi_lock);

	ASSERT(xip->xi_busy != 0);
	xip->xi_busy--;

	(void) pthread_cond_broadcast(&xip->xi_cv);
	(void) pthread_mutex_unlock(&xip->xi_lock);
}

void
fmd_xprt_uuclose(fmd_xprt_t *xp, const char *uuid)
{
	fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)xp;

	fmd_event_t *e;
	nvlist_t *nvl;
	char *s;

	fmd_dprintf(FMD_DBG_XPRT,
	    "xprt %u closing case %s\n", xip->xi_id, uuid);

	nvl = fmd_protocol_xprt_uuclose(xip->xi_queue->eq_mod,
	    "resource.fm.xprt.uuclose", xip->xi_version, uuid);

	(void) nvlist_lookup_string(nvl, FM_CLASS, &s);
	e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, s);
	fmd_eventq_insert_at_time(xip->xi_queue, e);
}

/*
 * Insert the specified class into our remote subscription hash.  If the class
 * is already present, bump the reference count; otherwise add it to the hash
 * and then enqueue an event for our remote peer to proxy our subscription.
 */
void
fmd_xprt_subscribe(fmd_xprt_t *xp, const char *class)
{
	fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)xp;

	uint_t refs;
	nvlist_t *nvl;
	fmd_event_t *e;
	char *s;

	if ((xip->xi_flags & FMD_XPRT_RDWR) == FMD_XPRT_RDONLY)
		return; /* read-only transports do not proxy subscriptions */

	if (!(xip->xi_flags & FMD_XPRT_SUBSCRIBER))
		return; /* transport is not yet an active subscriber */

	(void) pthread_mutex_lock(&xip->xi_lock);
	refs = fmd_xprt_class_hash_insert(xip, &xip->xi_rsub, class);
	(void) pthread_mutex_unlock(&xip->xi_lock);

	if (refs > 1)
		return; /* we've already asked our peer for this subscription */

	fmd_dprintf(FMD_DBG_XPRT,
	    "xprt %u subscribing to %s\n", xip->xi_id, class);

	nvl = fmd_protocol_xprt_sub(xip->xi_queue->eq_mod,
	    "resource.fm.xprt.subscribe", xip->xi_version, class);

	(void) nvlist_lookup_string(nvl, FM_CLASS, &s);
	e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, s);
	fmd_eventq_insert_at_time(xip->xi_queue, e);
}

/*
 * Delete the specified class from the remote subscription hash.  If the
 * reference count drops to zero, ask our remote peer to unsubscribe by proxy.
 */
void
fmd_xprt_unsubscribe(fmd_xprt_t *xp, const char *class)
{
	fmd_xprt_impl_t *xip = (fmd_xprt_impl_t *)xp;

	uint_t refs;
	nvlist_t *nvl;
	fmd_event_t *e;
	char *s;

	if ((xip->xi_flags & FMD_XPRT_RDWR) == FMD_XPRT_RDONLY)
		return; /* read-only transports do not proxy subscriptions */

	if (!(xip->xi_flags & FMD_XPRT_SUBSCRIBER))
		return; /* transport is not yet an active subscriber */

	/*
	 * If the subscription reference count drops to zero in xi_rsub, insert
	 * an entry into the xi_usub hash indicating we await an unsuback event.
	 */
	(void) pthread_mutex_lock(&xip->xi_lock);

	if ((refs = fmd_xprt_class_hash_delete(xip, &xip->xi_rsub, class)) == 0)
		(void) fmd_xprt_class_hash_insert(xip, &xip->xi_usub, class);

	(void) pthread_mutex_unlock(&xip->xi_lock);

	if (refs != 0)
		return; /* other subscriptions for this class still active */

	fmd_dprintf(FMD_DBG_XPRT,
	    "xprt %u unsubscribing from %s\n", xip->xi_id, class);

	nvl = fmd_protocol_xprt_sub(xip->xi_queue->eq_mod,
	    "resource.fm.xprt.unsubscribe", xip->xi_version, class);

	(void) nvlist_lookup_string(nvl, FM_CLASS, &s);
	e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, s);
	fmd_eventq_insert_at_time(xip->xi_queue, e);
}

static void
fmd_xprt_subscribe_xid(fmd_idspace_t *ids, id_t id, void *class)
{
	fmd_xprt_t *xp;

	if ((xp = fmd_idspace_hold(ids, id)) != NULL) {
		fmd_xprt_subscribe(xp, class);
		fmd_idspace_rele(ids, id);
	}
}

void
fmd_xprt_subscribe_all(const char *class)
{
	fmd_idspace_t *ids = fmd.d_xprt_ids;

	if (ids->ids_count != 0)
		fmd_idspace_apply(ids, fmd_xprt_subscribe_xid, (void *)class);
}

static void
fmd_xprt_unsubscribe_xid(fmd_idspace_t *ids, id_t id, void *class)
{
	fmd_xprt_t *xp;

	if ((xp = fmd_idspace_hold(ids, id)) != NULL) {
		fmd_xprt_unsubscribe(xp, class);
		fmd_idspace_rele(ids, id);
	}
}

void
fmd_xprt_unsubscribe_all(const char *class)
{
	fmd_idspace_t *ids = fmd.d_xprt_ids;

	if (ids->ids_count != 0)
		fmd_idspace_apply(ids, fmd_xprt_unsubscribe_xid, (void *)class);
}

/*ARGSUSED*/
static void
fmd_xprt_suspend_xid(fmd_idspace_t *ids, id_t id, void *arg)
{
	fmd_xprt_t *xp;

	if ((xp = fmd_idspace_hold(ids, id)) != NULL) {
		fmd_xprt_xsuspend(xp, FMD_XPRT_DSUSPENDED);
		fmd_idspace_rele(ids, id);
	}
}

void
fmd_xprt_suspend_all(void)
{
	fmd_idspace_t *ids = fmd.d_xprt_ids;

	(void) pthread_mutex_lock(&fmd.d_xprt_lock);

	if (fmd.d_xprt_suspend++ != 0) {
		(void) pthread_mutex_unlock(&fmd.d_xprt_lock);
		return; /* already suspended */
	}

	if (ids->ids_count != 0)
		fmd_idspace_apply(ids, fmd_xprt_suspend_xid, NULL);

	(void) pthread_mutex_unlock(&fmd.d_xprt_lock);
}

/*ARGSUSED*/
static void
fmd_xprt_resume_xid(fmd_idspace_t *ids, id_t id, void *arg)
{
	fmd_xprt_t *xp;

	if ((xp = fmd_idspace_hold(ids, id)) != NULL) {
		fmd_xprt_xresume(xp, FMD_XPRT_DSUSPENDED);
		fmd_idspace_rele(ids, id);
	}
}

void
fmd_xprt_resume_all(void)
{
	fmd_idspace_t *ids = fmd.d_xprt_ids;

	(void) pthread_mutex_lock(&fmd.d_xprt_lock);

	if (fmd.d_xprt_suspend == 0)
		fmd_panic("fmd_xprt_suspend/resume_all mismatch\n");

	if (--fmd.d_xprt_suspend != 0) {
		(void) pthread_mutex_unlock(&fmd.d_xprt_lock);
		return; /* not ready to be resumed */
	}

	if (ids->ids_count != 0)
		fmd_idspace_apply(ids, fmd_xprt_resume_xid, NULL);

	(void) pthread_mutex_unlock(&fmd.d_xprt_lock);
}
