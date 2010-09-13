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

#ifndef	_FMD_EVENT_H
#define	_FMD_EVENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_time.h>
#include <fmd_api.h>

struct fmd_log;				/* see <fmd_log.h> */

typedef struct fmd_event_impl {
	pthread_mutex_t ev_lock;	/* lock protecting structure contents */
	uint32_t ev_refs;		/* reference count */
	uint8_t ev_type;		/* event type (see below) */
	uint8_t ev_state;		/* event state (see below) */
	uint8_t ev_flags;		/* event flags (see below) */
	uint8_t ev_ttl;			/* event time-to-live */
	nvlist_t *ev_nvl;		/* event name/value pair payload */
	void *ev_data;			/* event type-specific data pointer */
	fmd_timeval_t ev_time;		/* upper bound on event time-of-day */
	hrtime_t ev_hrt;		/* upper bound on event hrtime */
	struct fmd_log *ev_log;		/* event log (or NULL) */
	off64_t ev_off;			/* event log offset (or zero) */
	size_t ev_len;			/* event log record length (or zero) */
} fmd_event_impl_t;

#define	FMD_EVT_PROTOCOL	0	/* protocol event (error/fault/list) */
#define	FMD_EVT_TIMEOUT		1	/* timeout expiry notification */
#define	FMD_EVT_CLOSE		2	/* case close request */
#define	FMD_EVT_STATS		3	/* statistics snapshot request */
#define	FMD_EVT_GC		4	/* garbage collection request */
#define	FMD_EVT_CTL		5	/* fmd control event (see fmd_ctl.c) */
#define	FMD_EVT_PUBLISH		6	/* case publish request */
#define	FMD_EVT_TOPO		7	/* topology change notification */
#define	FMD_EVT_NTYPES		8	/* number of event types */

#define	FMD_EVS_DISCARDED	0	/* discarded by all subscribers */
#define	FMD_EVS_RECEIVED	1	/* received but not yet processed */
#define	FMD_EVS_ACCEPTED	2	/* accepted and assigned to a case */
#define	FMD_EVS_DIAGNOSED	3	/* diagnosed and assigned to a case */

#define	FMD_EVF_VOLATILE	0x1	/* event is not yet written to a log */
#define	FMD_EVF_REPLAY		0x2	/* event is set for replay on restart */
#define	FMD_EVF_LOCAL		0x4	/* event is from fmd or a local xprt */

#define	FMD_HRT_NOW		0	/* use current hrtime as event time */

#define	FMD_EVENT_TYPE(e)	(((fmd_event_impl_t *)e)->ev_type)
#define	FMD_EVENT_DATA(e)	(((fmd_event_impl_t *)e)->ev_data)
#define	FMD_EVENT_NVL(e)	(((fmd_event_impl_t *)e)->ev_nvl)
#define	FMD_EVENT_TTL(e)	(((fmd_event_impl_t *)e)->ev_ttl)

#define	FMD_EVN_TOD	"__tod"		/* private name-value pair for ev_tod */
#define	FMD_EVN_TTL	"__ttl"		/* private name-value pair for ev_ttl */
#define	FMD_EVN_UUID	"__uuid"	/* private name-value pair for UUIDs */

extern fmd_event_t *fmd_event_recreate(uint_t, const fmd_timeval_t *,
    nvlist_t *, void *, struct fmd_log *, off64_t, size_t);

extern fmd_event_t *fmd_event_create(uint_t, hrtime_t, nvlist_t *, void *);
extern void fmd_event_destroy(fmd_event_t *);
extern void fmd_event_hold(fmd_event_t *);
extern void fmd_event_rele(fmd_event_t *);

extern void fmd_event_transition(fmd_event_t *, uint_t);
extern void fmd_event_commit(fmd_event_t *);

extern hrtime_t fmd_event_delta(fmd_event_t *, fmd_event_t *);
extern hrtime_t fmd_event_hrtime(fmd_event_t *);

extern int fmd_event_match(fmd_event_t *, uint_t, const void *);
extern int fmd_event_equal(fmd_event_t *, fmd_event_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_EVENT_H */
