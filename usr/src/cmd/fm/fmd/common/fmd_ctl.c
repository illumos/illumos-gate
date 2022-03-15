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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * FMD Control Event Subsystem
 *
 * This file provides a simple and extensible subsystem for the processing of
 * synchronous control events that can be received from the event transport
 * and used to control the behavior of the fault manager itself.  At present
 * this feature is used for the implementation of simulation controls such as
 * advancing the simulated clock using events sent by the fminject utility.
 * Control events are assigned a class of the form "resource.fm.fmd.*" and
 * are assigned a callback function defined in the _fmd_ctls[] table below.
 * As control events are received by the event transport, they are assigned a
 * special event type (ev_type = FMD_EVT_CTL) and the ev_data member is used
 * to refer to a fmd_ctl_t data structure, managed by the functions below.
 *
 * Control events are implemented so that they are synchronous with respect to
 * the rest of the fault manager event stream, which is usually asynchronous
 * (that is, the transport dispatch thread and the module receive threads all
 * execute in parallel).  Synchronous processing is required for control events
 * so that they can affect global state (e.g. the simulated clock) and ensure
 * that the results of any state changes are seen by *all* subsequent events.
 *
 * To achieve synchronization, the event itself implements a thread barrier:
 * the fmd_ctl_t maintains a reference count that mirrors the fmd_event_t
 * reference count (which for ctls counts the number of modules the event
 * was dispatched to).  As each module receive thread dequeues the event, it
 * calls fmd_event_rele() to discard the event, which calls fmd_ctl_rele().
 * fmd_ctl_rele() decrements the ctl's reference count but blocks there waiting
 * for *all* other references to be released.  When all threads have reached
 * the barrier, the final caller of fmd_ctl_rele() executes the control event
 * callback function and then wakes everyone else up.  The transport dispatch
 * thread, blocked in fmd_modhash_dispatch(), is typically this final caller.
 */

#include <strings.h>
#include <limits.h>
#include <signal.h>

#include <fmd_protocol.h>
#include <fmd_alloc.h>
#include <fmd_error.h>
#include <fmd_subr.h>
#include <fmd_time.h>
#include <fmd_module.h>
#include <fmd_thread.h>
#include <fmd_ctl.h>

#include <fmd.h>

static void
fmd_ctl_addhrt(nvlist_t *nvl)
{
	int64_t delta = 0;

	(void) nvlist_lookup_int64(nvl, FMD_CTL_ADDHRT_DELTA, &delta);
	fmd_time_addhrtime(delta);

	/*
	 * If the non-adjustable clock has reached the apocalypse, fmd(8)
	 * should exit gracefully: queue a SIGTERM for the main thread.
	 */
	if (fmd_time_gethrtime() == INT64_MAX)
		(void) pthread_kill(fmd.d_rmod->mod_thread->thr_tid, SIGTERM);
}

static void
fmd_ctl_inval(nvlist_t *nvl)
{
	char *class = "<unknown>";

	(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
	fmd_error(EFMD_CTL_INVAL, "ignoring invalid control event %s\n", class);
}

/*ARGSUSED*/
static void
fmd_ctl_pause(nvlist_t *nvl)
{
	fmd_dprintf(FMD_DBG_DISP, "unpausing modules from ctl barrier\n");
}

static const fmd_ctl_desc_t _fmd_ctls[] = {
	{ FMD_CTL_ADDHRT, FMD_CTL_ADDHRT_VERS1, fmd_ctl_addhrt },
	{ NULL, UINT_MAX, fmd_ctl_inval }
};

fmd_ctl_t *
fmd_ctl_init(nvlist_t *nvl)
{
	fmd_ctl_t *cp = fmd_alloc(sizeof (fmd_ctl_t), FMD_SLEEP);

	const fmd_ctl_desc_t *dp;
	uint8_t vers;
	char *class;

	(void) pthread_mutex_init(&cp->ctl_lock, NULL);
	(void) pthread_cond_init(&cp->ctl_cv, NULL);

	cp->ctl_nvl = nvl;
	cp->ctl_refs = 0;

	if (nvl == NULL) {
		cp->ctl_func = fmd_ctl_pause;
		return (cp);
	}

	if (nvlist_lookup_string(nvl, FM_CLASS, &class) != 0 ||
	    nvlist_lookup_uint8(nvl, FM_VERSION, &vers) != 0)
		fmd_panic("ctl_init called with bad nvlist %p", (void *)nvl);

	for (dp = _fmd_ctls; dp->cde_class != NULL; dp++) {
		if (strcmp(class, dp->cde_class) == 0)
			break;
	}

	cp->ctl_func = vers > dp->cde_vers ? &fmd_ctl_inval : dp->cde_func;
	return (cp);
}

void
fmd_ctl_fini(fmd_ctl_t *cp)
{
	fmd_free(cp, sizeof (fmd_ctl_t));
}

/*
 * Increment the ref count on the fmd_ctl_t to correspond to a reference to the
 * fmd_event_t.  This count is used to implement a barrier in fmd_ctl_rele().
 */
void
fmd_ctl_hold(fmd_ctl_t *cp)
{
	(void) pthread_mutex_lock(&cp->ctl_lock);

	cp->ctl_refs++;
	ASSERT(cp->ctl_refs != 0);

	(void) pthread_mutex_unlock(&cp->ctl_lock);
}

/*
 * Decrement the reference count on the fmd_ctl_t.  If this rele() is the last
 * one, then execute the callback function and release all the other callers.
 * Otherwise enter a loop waiting on ctl_cv for other threads to call rele().
 */
void
fmd_ctl_rele(fmd_ctl_t *cp)
{
	(void) pthread_mutex_lock(&cp->ctl_lock);

	ASSERT(cp->ctl_refs != 0);
	cp->ctl_refs--;

	if (cp->ctl_refs == 0) {
		cp->ctl_func(cp->ctl_nvl);
		(void) pthread_cond_broadcast(&cp->ctl_cv);
	} else {
		while (cp->ctl_refs != 0)
			(void) pthread_cond_wait(&cp->ctl_cv, &cp->ctl_lock);
	}

	(void) pthread_mutex_unlock(&cp->ctl_lock);
}
