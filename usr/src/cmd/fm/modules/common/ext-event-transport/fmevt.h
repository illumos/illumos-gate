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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _FMEVT_H
#define	_FMEVT_H

/*
 * ext-event-transport module - implementation detail.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <libnvpair.h>
#include <fm/fmd_api.h>
#include <fm/libfmevent.h>
#include <sys/fm/protocol.h>

#include "../../../../../lib/fm/libfmevent/common/fmev_channels.h"

extern fmd_hdl_t *fmevt_hdl;
extern const fmd_prop_t fmevt_props[];

extern void fmevt_init_outbound(fmd_hdl_t *);
extern void fmevt_fini_outbound(fmd_hdl_t *);

extern void fmevt_init_inbound(fmd_hdl_t *);
extern void fmevt_fini_inbound(fmd_hdl_t *);

extern void fmevt_recv(fmd_hdl_t *, fmd_event_t *, nvlist_t *, const char *);


/*
 * Post-processing
 */

/*
 * Structure passed to a post-processing functions with details of the
 * raw event.
 */
struct fmevt_ppargs {
	const char *pp_rawclass;	/* class from event publication */
	const char *pp_rawsubclass;	/* subclass from event publication */
	hrtime_t pp_hrt;		/* hrtime of event publication */
	int pp_user;			/* userland or kernel source? */
	int pp_priv;			/* privileged? */
	fmev_pri_t pp_pri;		/* published priority */
	char pp_uuidstr[36 + 1];	/* uuid we'll use for first event */
};

/*
 * The maximum length that a protocol event class name generated
 * in post-processing can be.
 */
#define	FMEVT_MAX_CLASS		64

/*
 * A post-processing function may derive up to this number of separate
 * protocol events for each raw event.
 */
#define	FMEVT_FANOUT_MAX	5

/*
 * Post-processing function type.  The function receives raw event
 * details in the struct fmevt_ppargs.  It must prepare up to
 * FMEVT_FANOUT_MAX protocol events (usually just one event)
 * based on the raw event, and return the number of events
 * to be posted.  The array of class pointers must have that
 * number of non-NULL entries.  You may return 0 to ditch an event;
 * in this case the caller will not perform an frees so you must
 * tidy up.
 *
 * The array of string pointers has the first member pointed to
 * some storage of size FMEV_MAX_CLASS into which the post-processing
 * function must render the protocol event classname.  If fanning
 * out into more than one event then the post-processing function
 * must allocate additional buffers (using fmd_hdl_alloc) and return
 * pointers to these in the array of string pointers (but do not change
 * the first element); buffers allocated and returned in this way will
 * be freed by the caller as it iterates over the protocol events to
 * post them.  Similarly the function must prepare an attributes
 * nvlist for each event; it can return the raw attributes or it
 * can fmd_nvl_alloc or fmd_nvl_dup and return those (to be freed
 * by the caller).
 *
 * Events will be generated based on the results as follows:
 *
 * event[i] =
 *
 *	timestamp = as supplied by incoming event and in pp_hrt
 *	class = class_array[i];  entry 0 is allocated, fmd_hdl_alloc others
 *	detector = generated detector as passed to function
 *	uuid = generated UUID, or that supplied by raw event
 *	attr = nvlist_array[i], can be absent; may return raw attributes
 *
 */
typedef uint_t fmevt_pp_func_t(
    char *[FMEVT_FANOUT_MAX],		/* event class(es) */
    nvlist_t *[FMEVT_FANOUT_MAX],	/* event attributes */
    const char *,			/* ruleset */
    const nvlist_t *,			/* detector */
    nvlist_t *,				/* raw attributes */
    const struct fmevt_ppargs *);	/* more raw event info */

extern fmevt_pp_func_t fmevt_pp_on_ereport;
extern fmevt_pp_func_t fmevt_pp_smf;
extern fmevt_pp_func_t fmevt_pp_on_sunos;
extern fmevt_pp_func_t fmevt_pp_on_private;
extern fmevt_pp_func_t fmevt_pp_unregistered;

#ifdef __cplusplus
}
#endif

#endif /* _FMEVT_H */
