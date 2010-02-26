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

#include <atomic.h>
#include <errno.h>
#include <execinfo.h>
#include <libuutil.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>

#include "conditions.h"
#include "events.h"
#include "objects.h"
#include "util.h"

/*
 * events.c - contains routines which create/destroy event sources,
 * handle the event queue and process events from that queue.
 */

/* Add new event sources here. */
struct nwamd_event_source {
	char *name;
	void (*events_init)(void);
	void (*events_fini)(void);
} event_sources[] = {
	{ "routing_events",
	nwamd_routing_events_init, nwamd_routing_events_fini },
	{ "sysevent_events",
	nwamd_sysevent_events_init, nwamd_sysevent_events_fini },
};

/* Counter for event ids */
static uint64_t event_id_counter = 0;

static uu_list_pool_t *event_pool = NULL;
static uu_list_t *event_queue = NULL;
static pthread_mutex_t event_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event_queue_cond = PTHREAD_COND_INITIALIZER;

static int nwamd_event_compare(const void *, const void *, void *);

static const char *
nwamd_event_name(int event_type)
{
	if (event_type <= NWAM_EVENT_MAX)
		return (nwam_event_type_to_string(event_type));

	switch (event_type) {
	case NWAM_EVENT_TYPE_OBJECT_INIT:
		return ("OBJECT_INIT");
	case NWAM_EVENT_TYPE_OBJECT_FINI:
		return ("OBJECT_FINI");
	case NWAM_EVENT_TYPE_TIMED_CHECK_CONDITIONS:
		return ("TIMED_CHECK_CONDITIONS");
	case NWAM_EVENT_TYPE_TRIGGERED_CHECK_CONDITIONS:
		return ("TRIGGERED_CHECK_CONDITIONS");
	case NWAM_EVENT_TYPE_NCU_CHECK:
		return ("NCU_CHECK");
	case NWAM_EVENT_TYPE_TIMER:
		return ("TIMER");
	case NWAM_EVENT_TYPE_UPGRADE:
		return ("UPGRADE");
	case NWAM_EVENT_TYPE_PERIODIC_SCAN:
		return ("PERIODIC_SCAN");
	case NWAM_EVENT_TYPE_QUEUE_QUIET:
		return ("QUEUE_QUIET");
	default:
		return ("N/A");
	}
}

void
nwamd_event_sources_init(void)
{
	int i;

	/*
	 * Now we can safely initialize event sources.
	 */
	for (i = 0;
	    i < sizeof (event_sources) / sizeof (struct nwamd_event_source);
	    i++) {
		if (event_sources[i].events_init != NULL)
			event_sources[i].events_init();
	}
}

void
nwamd_event_sources_fini(void)
{
	int i;

	for (i = 0;
	    i < sizeof (event_sources) / sizeof (struct nwamd_event_source);
	    i++) {
		if (event_sources[i].events_init != NULL)
			event_sources[i].events_fini();
	}
}

/*
 * Comparison function for events, passed in as callback to
 * uu_list_pool_create(). Compare by time, so that timer
 * event queue can be sorted by nearest time to present.
 */
/* ARGSUSED */
static int
nwamd_event_compare(const void *l_arg, const void *r_arg, void *private)
{
	nwamd_event_t l = (nwamd_event_t)l_arg;
	nwamd_event_t r = (nwamd_event_t)r_arg;
	int rv;

	rv = l->event_time.tv_sec - r->event_time.tv_sec;
	if (rv == 0)
		rv = l->event_time.tv_nsec - r->event_time.tv_nsec;

	return (rv);
}

void
nwamd_event_queue_init(void)
{
	event_pool = uu_list_pool_create("event_queue_pool",
	    sizeof (struct nwamd_event),
	    offsetof(struct nwamd_event, event_node),
	    nwamd_event_compare, UU_LIST_POOL_DEBUG);
	if (event_pool == NULL)
		pfail("uu_list_pool_create failed with error %d", uu_error());
	event_queue = uu_list_create(event_pool, NULL, UU_LIST_SORTED);
	if (event_queue == NULL)
		pfail("uu_list_create failed with error %d", uu_error());
}

void
nwamd_event_queue_fini(void)
{
	void *cookie = NULL;
	nwamd_event_t event;

	while ((event = uu_list_teardown(event_queue, &cookie)) != NULL)
		nwamd_event_fini(event);
	uu_list_destroy(event_queue);
	if (event_pool != NULL)
		uu_list_pool_destroy(event_pool);
}

nwamd_event_t
nwamd_event_init(int32_t type, nwam_object_type_t object_type,
    size_t size, const char *object_name)
{
	nwamd_event_t event;

	event = calloc(1, sizeof (struct nwamd_event));
	if (event == NULL) {
		nlog(LOG_ERR, "nwamd_event_init: could not create %s event for "
		    "object %s", nwamd_event_name(type),
		    object_name != NULL ? object_name : "<no object>");
		return (NULL);
	}

	/* Is this an externally-visible event? */
	if (type <= NWAM_EVENT_MAX) {
		event->event_send = B_TRUE;
		event->event_msg = calloc(1, sizeof (struct nwam_event) + size);
		if (event->event_msg == NULL) {
			nlog(LOG_ERR,
			    "nwamd_event_init: could not create %s event",
			    nwamd_event_name(type));
			free(event);
			return (NULL);
		}
		event->event_msg->nwe_type = type;
		event->event_msg->nwe_size = sizeof (struct nwam_event) + size;
	} else {
		event->event_send = B_FALSE;
		event->event_msg = NULL;
	}

	event->event_type = type;

	if (object_name != NULL) {
		(void) strlcpy(event->event_object, object_name,
		    NWAM_MAX_NAME_LEN);
		event->event_object_type = object_type;
	} else {
		event->event_object[0] = '\0';
	}

	/* Set event id */
	event->event_id = atomic_add_64_nv(&event_id_counter, 1);
	(void) clock_gettime(CLOCK_REALTIME, &event->event_time);

	return (event);
}

void
nwamd_event_do_not_send(nwamd_event_t event)
{
	nlog(LOG_DEBUG, "nwamd_event_do_not_send: cancelling delivery of "
	    "event %s for object %s", nwamd_event_name(event->event_type),
	    event->event_object[0] != '\0' ?
	    event->event_object : "<no object>");
	event->event_send = B_FALSE;
}

void
nwamd_event_fini(nwamd_event_t event)
{
	if (event != NULL) {
		free(event->event_msg);
		free(event);
	}
}

nwamd_event_t
nwamd_event_init_object_action(nwam_object_type_t object_type,
    const char *object_name, const char *parent_name,
    nwam_action_t object_action)
{
	nwamd_event_t event;

	event = nwamd_event_init(NWAM_EVENT_TYPE_OBJECT_ACTION,
	    object_type, 0, object_name);
	if (event == NULL)
		return (NULL);

	event->event_msg->nwe_data.nwe_object_action.nwe_action = object_action;
	event->event_msg->nwe_data.nwe_object_action.nwe_object_type =
	    object_type;
	(void) strlcpy(event->event_msg->nwe_data.nwe_object_action.nwe_name,
	    object_name,
	    sizeof (event->event_msg->nwe_data.nwe_object_action.nwe_name));
	if (parent_name == NULL) {
		event->event_msg->nwe_data.nwe_object_action.nwe_parent[0] =
		    '\0';
		return (event);
	}
	(void) strlcpy
	    (event->event_msg->nwe_data.nwe_object_action.nwe_parent,
	    parent_name,
	    sizeof (event->event_msg->nwe_data.nwe_object_action.nwe_parent));
	return (event);
}

nwamd_event_t
nwamd_event_init_object_state(nwam_object_type_t object_type,
    const char *object_name, nwam_state_t state, nwam_aux_state_t aux_state)
{
	nwamd_event_t event;

	event = nwamd_event_init(NWAM_EVENT_TYPE_OBJECT_STATE,
	    object_type, 0, object_name);
	if (event == NULL)
		return (NULL);

	event->event_msg->nwe_data.nwe_object_state.nwe_state = state;
	event->event_msg->nwe_data.nwe_object_state.nwe_aux_state = aux_state;
	event->event_msg->nwe_data.nwe_object_state.nwe_object_type =
	    object_type;
	(void) strlcpy(event->event_msg->nwe_data.nwe_object_state.nwe_name,
	    object_name,
	    sizeof (event->event_msg->nwe_data.nwe_object_state.nwe_name));

	return (event);
}

nwamd_event_t
nwamd_event_init_priority_group_change(int64_t priority)
{
	nwamd_event_t event;

	event = nwamd_event_init(NWAM_EVENT_TYPE_PRIORITY_GROUP,
	    NWAM_OBJECT_TYPE_UNKNOWN, 0, NULL);
	if (event == NULL)
		return (NULL);

	event->event_msg->nwe_data.nwe_priority_group_info.nwe_priority =
	    priority;

	return (event);
}

nwamd_event_t
nwamd_event_init_link_action(const char *name, nwam_action_t link_action)
{
	nwamd_event_t event;
	nwam_error_t err;
	char *object_name;

	if ((err = nwam_ncu_name_to_typed_name(name, NWAM_NCU_TYPE_LINK,
	    &object_name)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_event_init_link_action: "
		    "nwam_ncu_name_to_typed_name: %s",
		    nwam_strerror(err));
		return (NULL);
	}
	event = nwamd_event_init(NWAM_EVENT_TYPE_LINK_ACTION,
	    NWAM_OBJECT_TYPE_NCU, 0, object_name);
	free(object_name);
	if (event == NULL)
		return (NULL);

	(void) strlcpy(event->event_msg->nwe_data.nwe_link_action.nwe_name,
	    name,
	    sizeof (event->event_msg->nwe_data.nwe_link_action.nwe_name));
	event->event_msg->nwe_data.nwe_link_action.nwe_action = link_action;

	return (event);
}

nwamd_event_t
nwamd_event_init_link_state(const char *name, boolean_t up)
{
	nwamd_event_t event;
	nwam_error_t err;
	char *object_name;

	if ((err = nwam_ncu_name_to_typed_name(name, NWAM_NCU_TYPE_LINK,
	    &object_name)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_event_init_link_state: "
		    "nwam_ncu_name_to_typed_name: %s",
		    nwam_strerror(err));
		return (NULL);
	}

	event = nwamd_event_init(NWAM_EVENT_TYPE_LINK_STATE,
	    NWAM_OBJECT_TYPE_NCU, 0, object_name);
	free(object_name);
	if (event == NULL)
		return (NULL);

	(void) strlcpy(event->event_msg->nwe_data.nwe_link_state.nwe_name, name,
	    sizeof (event->event_msg->nwe_data.nwe_link_state.nwe_name));
	event->event_msg->nwe_data.nwe_link_state.nwe_link_up = up;

	return (event);
}

nwamd_event_t
nwamd_event_init_if_state(const char *linkname, uint32_t flags,
    uint32_t addr_added, uint32_t index, struct sockaddr *addr)
{
	nwamd_event_t event;
	nwam_error_t err;
	char *object_name;

	/* linkname does not contain the lifnum */
	if ((err = nwam_ncu_name_to_typed_name(linkname,
	    NWAM_NCU_TYPE_INTERFACE, &object_name)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_event_init_if_state: "
		    "nwam_ncu_name_to_typed_name: %s",
		    nwam_strerror(err));
		return (NULL);
	}

	event = nwamd_event_init(NWAM_EVENT_TYPE_IF_STATE,
	    NWAM_OBJECT_TYPE_NCU, 0, object_name);
	free(object_name);
	if (event == NULL)
		return (NULL);

	(void) strlcpy(event->event_msg->nwe_data.nwe_if_state.nwe_name,
	    linkname,
	    sizeof (event->event_msg->nwe_data.nwe_if_state.nwe_name));
	event->event_msg->nwe_data.nwe_if_state.nwe_flags = flags;
	event->event_msg->nwe_data.nwe_if_state.nwe_index = index;
	event->event_msg->nwe_data.nwe_if_state.nwe_addr_added = addr_added;
	event->event_msg->nwe_data.nwe_if_state.nwe_addr_valid = (addr != NULL);

	if (addr != NULL) {
		bcopy(addr, &(event->event_msg->nwe_data.nwe_if_state.nwe_addr),
		    addr->sa_family == AF_INET ? sizeof (struct sockaddr_in) :
		    sizeof (struct sockaddr_in6));
	}

	return (event);
}

nwamd_event_t
nwamd_event_init_wlan(const char *name, int32_t type, boolean_t connected,
    nwam_wlan_t *wlans, uint_t num_wlans)
{
	size_t size = 0;
	char *object_name;
	nwamd_event_t event;
	nwam_error_t err;

	switch (type) {
	case NWAM_EVENT_TYPE_WLAN_SCAN_REPORT:
	case NWAM_EVENT_TYPE_WLAN_NEED_CHOICE:
		size = sizeof (nwam_wlan_t) * (num_wlans - 1);
		break;
	case NWAM_EVENT_TYPE_WLAN_NEED_KEY:
	case NWAM_EVENT_TYPE_WLAN_CONNECTION_REPORT:
		break;
	default:
		nlog(LOG_ERR, "nwamd_event_init_wlan: unexpected "
		    "event type %s (%d)", nwamd_event_name(type), type);
		return (NULL);
	}
	if ((err = nwam_ncu_name_to_typed_name(name, NWAM_NCU_TYPE_LINK,
	    &object_name)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_event_init_wlan: "
		    "nwam_ncu_name_to_typed_name: %s",
		    nwam_strerror(err));
		return (NULL);
	}

	event = nwamd_event_init(type, NWAM_OBJECT_TYPE_NCU, size, object_name);
	free(object_name);
	if (event == NULL)
		return (NULL);

	(void) strlcpy(event->event_msg->nwe_data.nwe_wlan_info.nwe_name, name,
	    sizeof (event->event_msg->nwe_data.nwe_wlan_info.nwe_name));
	event->event_msg->nwe_data.nwe_wlan_info.nwe_connected = connected;
	event->event_msg->nwe_data.nwe_wlan_info.nwe_num_wlans = num_wlans;

	/* copy the wlans */
	(void) memcpy(event->event_msg->nwe_data.nwe_wlan_info.nwe_wlans, wlans,
	    num_wlans * sizeof (nwam_wlan_t));

	return (event);
}

nwamd_event_t
nwamd_event_init_ncu_check(void)
{
	return (nwamd_event_init(NWAM_EVENT_TYPE_NCU_CHECK,
	    NWAM_OBJECT_TYPE_NCP, 0, NULL));
}

nwamd_event_t
nwamd_event_init_init(void)
{
	return (nwamd_event_init(NWAM_EVENT_TYPE_INIT,
	    NWAM_OBJECT_TYPE_UNKNOWN, 0, NULL));
}

nwamd_event_t
nwamd_event_init_shutdown(void)
{
	return (nwamd_event_init(NWAM_EVENT_TYPE_SHUTDOWN,
	    NWAM_OBJECT_TYPE_UNKNOWN, 0, NULL));
}

/*
 * Add event to the event list.
 */
void
nwamd_event_enqueue(nwamd_event_t event)
{
	nwamd_event_enqueue_timed(event, 0);
}

/*
 * Schedule an event to be added to the event list for future processing.
 * The event will be scheduled in delta_seconds seconds mod schedule delay and
 * time resolution.
 */
void
nwamd_event_enqueue_timed(nwamd_event_t event, int delta_seconds)
{
	uu_list_index_t idx;

	nlog(LOG_DEBUG, "enqueueing event %lld %d (%s) for object %s in %ds",
	    event->event_id, event->event_type,
	    nwamd_event_name(event->event_type),
	    event->event_object[0] != 0 ?  event->event_object : "none",
	    delta_seconds);

	(void) clock_gettime(CLOCK_REALTIME, &event->event_time);
	event->event_time.tv_sec += delta_seconds;

	uu_list_node_init(event, &event->event_node, event_pool);

	(void) pthread_mutex_lock(&event_queue_mutex);

	/*
	 * Find appropriate location to insert the event based on time.
	 */
	(void) uu_list_find(event_queue, event, NULL, &idx);
	(void) uu_list_insert(event_queue, event, idx);

	(void) pthread_cond_signal(&event_queue_cond);
	(void) pthread_mutex_unlock(&event_queue_mutex);
}

/*
 * Is the specified event enqueued on the event (or pending event queue)
 * for execution in when seconds? An object may be specified also.
 */
boolean_t
nwamd_event_enqueued(int32_t event_type, nwam_object_type_t object_type,
    const char *object)
{
	nwamd_event_t event;

	(void) pthread_mutex_lock(&event_queue_mutex);
	for (event = uu_list_first(event_queue);
	    event != NULL;
	    event = uu_list_next(event_queue, event)) {
		if (event->event_type != event_type)
			continue;
		if (object_type != NWAM_OBJECT_TYPE_UNKNOWN &&
		    event->event_object_type != object_type)
			continue;
		if (object != NULL && strcmp(object, event->event_object) != 0)
			continue;
		(void) pthread_mutex_unlock(&event_queue_mutex);
		return (B_TRUE);
	}
	(void) pthread_mutex_unlock(&event_queue_mutex);

	return (B_FALSE);
}

/*
 * Is the time in the past.
 */
static boolean_t
in_past(struct timespec t)
{
	struct timespec now;

	(void) clock_gettime(CLOCK_REALTIME, &now);
	if (t.tv_sec < now.tv_sec)
		return (B_TRUE);
	if (t.tv_sec > now.tv_sec)
		return (B_FALSE);
	if (t.tv_nsec < now.tv_nsec)
		return (B_TRUE);
	return (B_FALSE);
}

/*
 * Remove event at head of event list for processing.  This takes a number of
 * nanoseconds to wait.  If the number is 0 then it blocks.  If there is
 * nothing on the queue then it returns an event which says that the queue
 * is quiet.
 */
static nwamd_event_t
nwamd_event_dequeue(long nsec)
{
	nwamd_event_t event;

	(void) pthread_mutex_lock(&event_queue_mutex);
	event = uu_list_first(event_queue);
	if (event == NULL && nsec == 0) {
		do {
			(void) pthread_cond_wait(&event_queue_cond,
			    &event_queue_mutex);
		} while ((event = uu_list_first(event_queue)) == NULL);
	} else {
		struct timespec waitcap;

		if (nsec != 0) {
			(void) clock_gettime(CLOCK_REALTIME, &waitcap);
			waitcap.tv_nsec += nsec;
			waitcap.tv_sec += NSEC_TO_SEC(waitcap.tv_nsec);
			waitcap.tv_nsec = NSEC_TO_FRACNSEC(waitcap.tv_nsec);
		}

		/*
		 * Keep going as long as the first event hasn't matured and
		 * we havn't passed our maximum wait time.
		 */
		while ((event == NULL || !in_past(event->event_time)) &&
		    (nsec == 0 || !in_past(waitcap)))  {
			struct timespec eventwait;

			/*
			 * Three cases:
			 *	no maximum waittime - just use the event
			 *	both an event and cap - take the least one
			 *	just a maximum waittime - use it
			 */
			if (nsec == 0) {
				eventwait = event->event_time;
			} else if (event != NULL) {
				uint64_t diff;
				diff = SEC_TO_NSEC(event->event_time.tv_sec -
				    waitcap.tv_sec) +
				    event->event_time.tv_nsec - waitcap.tv_nsec;

				if (diff > 0)
					eventwait = waitcap;
				else
					eventwait = event->event_time;
			} else {
				/*
				 * Note that if the event is NULL then nsec is
				 * nonzero and waitcap is valid.
				 */
				eventwait = waitcap;
			}

			(void) pthread_cond_timedwait(&event_queue_cond,
			    &event_queue_mutex, &eventwait);
			event = uu_list_first(event_queue);
		}
	}

	/*
	 * At this point we've met the guard contition of the while loop.
	 * The event at the top of the queue might be mature in which case
	 * we use it.  Otherwise we hit our cap and we need to enqueue a
	 * quiesced queue event.
	 */
	if (event != NULL && in_past(event->event_time)) {
		uu_list_remove(event_queue, event);
		uu_list_node_fini(event, &event->event_node, event_pool);
	} else {
		event = nwamd_event_init(NWAM_EVENT_TYPE_QUEUE_QUIET,
		    NWAM_OBJECT_TYPE_UNKNOWN, 0, NULL);
	}

	if (event != NULL)
		nlog(LOG_DEBUG,
		    "dequeueing event %lld of type %d (%s) for object %s",
		    event->event_id, event->event_type,
		    nwamd_event_name(event->event_type),
		    event->event_object[0] != 0 ?  event->event_object :
		    "none");

	(void) pthread_mutex_unlock(&event_queue_mutex);

	return (event);
}

void
nwamd_event_send(nwam_event_t event_msg)
{
	nwam_error_t err;

	if (shutting_down && event_msg->nwe_type != NWAM_EVENT_TYPE_SHUTDOWN) {
		nlog(LOG_DEBUG, "nwamd_event_send: tossing event as nwamd "
		    "is shutting down");
		return;
	}

	err = nwam_event_send(event_msg);

	if (err != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_event_send: nwam_event_send: %s",
		    nwam_strerror(err));
	}
}

/*
 * Run state machine for object. Method is run if
 * - event method is non-null
 * - event method is valid for current object state (determined by
 * ORing the current state against the set of valid states for the method).
 *
 * If these criteria are met, the method is run.
 */
static void
nwamd_event_run_method(nwamd_event_t event)
{
	nwamd_event_method_t *event_methods;
	int i;

	event_methods = nwamd_object_event_methods(event->event_object_type);

	/* If we're shutting down, only fini events are accepted for objects */
	if (shutting_down && event->event_type != NWAM_EVENT_TYPE_OBJECT_FINI) {
		nlog(LOG_DEBUG, "nwamd_event_run_method: tossing non-fini "
		    "event %s for object %s",
		    nwamd_event_name(event->event_type), event->event_object);
		return;
	}

	for (i = 0;
	    event_methods[i].event_type != NWAM_EVENT_TYPE_NOOP;
	    i++) {
		if (event_methods[i].event_type ==
		    event->event_type &&
		    event_methods[i].event_method != NULL) {
			nlog(LOG_DEBUG,
			    "(%p) %s: running method for event %s",
			    (void *)event, event->event_object,
			    nwamd_event_name(event->event_type));
			/* run method */
			event_methods[i].event_method(event);
			return;
		}
	}
	nlog(LOG_DEBUG, "(%p) %s: no matching method for event %d (%s)",
	    (void *)event, event->event_object, event->event_type,
	    nwamd_event_name(event->event_type));
}

/*
 * Called when we are checking to see what should be activated.  First activate
 * all of the manual NCUs.  Then see if we can find a valid priority group.
 * If we can, activate it.  Otherwise try all the priority groups starting
 * with the lowest one that makes sense.
 */
static void
nwamd_activate_ncus(void) {
	int64_t prio = INVALID_PRIORITY_GROUP;
	boolean_t selected;

	nwamd_ncp_activate_manual_ncus();
	selected = nwamd_ncp_check_priority_group(&prio);
	if (selected) {
		/*
		 * Activate chosen priority group and stop anything going on in
		 * lesser priority groups.
		 */
		nwamd_ncp_activate_priority_group(prio);
		nwamd_ncp_deactivate_priority_group_all(prio + 1);
	} else {
		/*
		 * Nothing unique could be started so try them all.  Once one
		 * of them gets into a reasonable state then we will prune
		 * everything below it (see first part of this conditional).
		 */
		int64_t oldprio = INVALID_PRIORITY_GROUP;
		while (nwamd_ncp_find_next_priority_group(++oldprio, &prio)) {
			nwamd_ncp_activate_priority_group(prio);
			oldprio = prio;
		}
	}
}

/*
 * Event handler thread
 *
 * The complexity in this code comes about from wanting to delay the decision
 * making process until after bursts of events.  Keep roughly polling (waiting
 * for .1s) until we see the queue quiet event and then block.
 */
void
nwamd_event_handler(void)
{
	boolean_t got_shutdown_event = B_FALSE;
	boolean_t check_conditions = B_FALSE;
	boolean_t ncu_check = B_FALSE;
	int queue_quiet_time = 0;
	nwamd_event_t event;

	/*
	 * Dequeue events and process them.  In most cases, events have
	 * an assocated object type, and we use this to retrieve
	 * the function that will process the event.
	 */
	while (!got_shutdown_event) {
		event = nwamd_event_dequeue(queue_quiet_time);
		/* keep pulling events as long as they are close together */
		queue_quiet_time = SEC_TO_NSEC(1)/10;

		/*
		 * This is an event with no associated object.
		 */
		if (event->event_object[0] == '\0') {
			switch (event->event_type) {
			case NWAM_EVENT_TYPE_NOOP:
			case NWAM_EVENT_TYPE_INIT:
				/*
				 * The only action for an INIT event
				 * is to relay it to event listeners,
				 * which is done below.
				 */
				break;
			case NWAM_EVENT_TYPE_PRIORITY_GROUP:
				(void) pthread_mutex_lock(&active_ncp_mutex);
				current_ncu_priority_group =
				    event->event_msg->nwe_data.
				    nwe_priority_group_info.nwe_priority;
				(void) pthread_mutex_unlock(&active_ncp_mutex);
				break;
			case NWAM_EVENT_TYPE_TIMED_CHECK_CONDITIONS:
				if (!shutting_down) {
					nwamd_set_timed_check_all_conditions();
					check_conditions = B_TRUE;
				}
				break;
			case NWAM_EVENT_TYPE_TRIGGERED_CHECK_CONDITIONS:
				if (!shutting_down)
					check_conditions = B_TRUE;
				break;
			case NWAM_EVENT_TYPE_NCU_CHECK:
				if (!shutting_down)
					ncu_check = B_TRUE;
				break;
			case NWAM_EVENT_TYPE_UPGRADE:
				if (!shutting_down) {
					/*
					 * Upgrade events have no associated
					 * object.
					 */
					nwamd_event_run_method(event);
				}
				break;
			case NWAM_EVENT_TYPE_SHUTDOWN:
				got_shutdown_event = B_TRUE;
				break;

			/*
			 * We want to delay processing of condition and ncu
			 * checking until after short bursts of events.  So we
			 * keep track of times we've scheduled checking and
			 * wait for the queue to quiesce.
			 */
			case NWAM_EVENT_TYPE_QUEUE_QUIET:
				queue_quiet_time = 0; /* now we can block */
				if (!shutting_down && check_conditions) {
					nwamd_check_all_conditions();
					check_conditions = B_FALSE;
				}

				if (!shutting_down && ncu_check) {
					nwamd_activate_ncus();
					ncu_check = B_FALSE;
				}
				break;

			default:
				nlog(LOG_ERR,
				    "event %d (%s)had no object associated "
				    "with it", event->event_type,
				    nwamd_event_name(event->event_type));
				break;
			}
		} else {
			/*
			 * Event has an associated object - run event method
			 * for that object type (if any).
			 */
			nwamd_event_run_method(event);
		}
		/*
		 * Send associated message to listeners if event type is
		 * externally visible.
		 */
		if (event->event_send)
			nwamd_event_send(event->event_msg);

		nwamd_event_fini(event);
	}
	/* If we get here, we got a shutdown event. */
	nwamd_event_queue_fini();
	nwamd_object_lists_fini();
}
