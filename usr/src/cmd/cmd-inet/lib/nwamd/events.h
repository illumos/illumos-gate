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
 */

#ifndef _EVENTS_H
#define	_EVENTS_H

#include <door.h>
#include <libsysevent.h>
#include <libuutil.h>
#include <pthread.h>
#include <ucontext.h>

#include <libnwam.h>
#include <libnwam_priv.h>

struct nwamd_object;
typedef struct nwamd_object *nwamd_object_t;

#include "ncp.h"

/* Define internal-to-nwamd events here */
#define	NWAM_EVENT_TYPE_OBJECT_INIT		NWAM_EVENT_MAX + 1
#define	NWAM_EVENT_TYPE_OBJECT_FINI		NWAM_EVENT_MAX + 2
#define	NWAM_EVENT_TYPE_TIMED_CHECK_CONDITIONS	NWAM_EVENT_MAX + 3
#define	NWAM_EVENT_TYPE_TRIGGERED_CHECK_CONDITIONS NWAM_EVENT_MAX + 4
#define	NWAM_EVENT_TYPE_NCU_CHECK		NWAM_EVENT_MAX + 5
#define	NWAM_EVENT_TYPE_TIMER			NWAM_EVENT_MAX + 6
#define	NWAM_EVENT_TYPE_UPGRADE			NWAM_EVENT_MAX + 7
#define	NWAM_EVENT_TYPE_PERIODIC_SCAN		NWAM_EVENT_MAX + 8
#define	NWAM_EVENT_TYPE_QUEUE_QUIET		NWAM_EVENT_MAX + 9

#define	NEXT_FEW_SECONDS			5

/*
 * Forward definition.
 */
/*
 * Wrapper structure for libnwam event (nwam_events_msg_t),  containing
 * event id (used to uniquely identify events on the event queue),
 * associated object (if any), and uu_list_node.
 */
typedef struct nwamd_event {
	int32_t event_type;
	uint64_t event_id;
	struct timespec event_time;
	char event_object[NWAM_MAX_NAME_LEN];
	nwam_object_type_t event_object_type;
	uu_list_node_t event_node;
	boolean_t event_send;
	nwam_event_t event_msg;
} *nwamd_event_t;

typedef struct nwamd_event_method {
	int32_t event_type;
	void (*event_method)(nwamd_event_t);
} nwamd_event_method_t;

extern sysevent_handle_t *shp;

/* Event generator init/fini code */
extern void nwamd_routing_events_init(void);
extern void nwamd_routing_events_fini(void);
extern void nwamd_sysevent_events_init(void);
extern void nwamd_sysevent_events_fini(void);

/* Event init/enqueueing */
extern void nwamd_event_queue_init(void);
extern void nwamd_event_queue_fini(void);
extern void nwamd_event_sources_init(void);
extern void nwamd_event_sources_fini(void);
extern nwamd_event_t nwamd_event_init(int32_t, nwam_object_type_t, size_t,
    const char *);
extern void nwamd_event_do_not_send(nwamd_event_t);
extern nwamd_event_t nwamd_event_init_object_action(nwam_object_type_t,
    const char *, const char *, nwam_action_t);
extern nwamd_event_t nwamd_event_init_object_state(nwam_object_type_t,
    const char *, nwam_state_t, nwam_aux_state_t);
extern nwamd_event_t nwamd_event_init_priority_group_change(int64_t);
extern nwamd_event_t nwamd_event_init_link_action(const char *, nwam_action_t);
extern nwamd_event_t nwamd_event_init_link_state(const char *, boolean_t);
extern nwamd_event_t nwamd_event_init_if_state(const char *, uint32_t,
    uint32_t, uint32_t, struct sockaddr *);
extern nwamd_event_t nwamd_event_init_wlan(const char *, int32_t, boolean_t,
    nwam_wlan_t *, uint_t);
extern nwamd_event_t nwamd_event_init_ncu_check(void);
extern nwamd_event_t nwamd_event_init_init(void);
extern nwamd_event_t nwamd_event_init_shutdown(void);
extern void nwamd_event_enqueue(nwamd_event_t);
extern void nwamd_event_enqueue_timed(nwamd_event_t, int);
extern void nwamd_event_enqueue_expired_events(void);
extern boolean_t nwamd_event_enqueued(int32_t, nwam_object_type_t,
    const char *);
extern void nwamd_event_send(nwam_event_t);
extern void nwamd_event_fini(nwamd_event_t);
extern void nwamd_event_handler(void);

#endif /* _EVENTS_H */
