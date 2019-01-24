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

/*
 * protocol.c - protocols between graph engine and restarters
 *
 *   The graph engine uses restarter_protocol_send_event() to send a
 *   restarter_event_type_t to the restarter.  For delegated restarters,
 *   this is published on the GPEC queue for the restarter, which can
 *   then be consumed by the librestart interfaces.  For services managed
 *   by svc.startd, the event is stored on the local restarter_queue list,
 *   where it can be dequeued by the restarter.
 *
 *   The svc.startd restarter uses graph_protocol_send_event() to send
 *   a graph_event_type_t to the graph engine when an instance's states are
 *   updated.
 *
 *   The graph engine uses restarter_protocol_init_delegate() to
 *   register its interest in a particular delegated restarter's instance
 *   state events.  The state_cb() registered on the event channel then
 *   invokes graph_protocol_send_event() to communicate the update to
 *   the graph engine.
 */

#include <assert.h>
#include <libintl.h>
#include <libsysevent.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <sys/time.h>
#include <errno.h>
#include <libuutil.h>

#include <librestart.h>
#include <librestart_priv.h>

#include "protocol.h"
#include "startd.h"

/* Local event queue structures. */
typedef struct graph_protocol_event_queue {
	uu_list_t		*gpeq_event_list;
	pthread_mutex_t		gpeq_lock;
} graph_protocol_event_queue_t;

typedef struct restarter_protocol_event_queue {
	uu_list_t		*rpeq_event_list;
	pthread_mutex_t		rpeq_lock;
} restarter_protocol_event_queue_t;

static uu_list_pool_t *restarter_protocol_event_queue_pool;
static restarter_protocol_event_queue_t *restarter_queue;

static uu_list_pool_t *graph_protocol_event_queue_pool;
static graph_protocol_event_queue_t *graph_queue;

void
graph_protocol_init()
{
	graph_protocol_event_queue_pool = startd_list_pool_create(
	    "graph_protocol_events", sizeof (graph_protocol_event_t),
	    offsetof(graph_protocol_event_t, gpe_link), NULL,
	    UU_LIST_POOL_DEBUG);

	graph_queue = startd_zalloc(sizeof (graph_protocol_event_queue_t));

	(void) pthread_mutex_init(&graph_queue->gpeq_lock, &mutex_attrs);
	graph_queue->gpeq_event_list = startd_list_create(
	    graph_protocol_event_queue_pool, graph_queue, 0);
}

/*
 * "data" will be freed by the consumer
 */
static void
graph_event_enqueue(const char *inst, graph_event_type_t event,
    protocol_states_t *data)
{
	graph_protocol_event_t *e;

	e = startd_zalloc(sizeof (graph_protocol_event_t));

	if (inst != NULL) {
		int size = strlen(inst) + 1;
		e->gpe_inst = startd_alloc(size);
		e->gpe_inst_sz = size;
		(void) strlcpy(e->gpe_inst, inst, size);
	}
	e->gpe_type = event;
	e->gpe_data = data;

	(void) pthread_mutex_init(&e->gpe_lock, &mutex_attrs);

	MUTEX_LOCK(&graph_queue->gpeq_lock);
	uu_list_node_init(e, &e->gpe_link, graph_protocol_event_queue_pool);
	if (uu_list_insert_before(graph_queue->gpeq_event_list, NULL, e) == -1)
		uu_die("failed to enqueue graph event (%s: %s)\n",
		    e->gpe_inst, uu_strerror(uu_error()));

	MUTEX_UNLOCK(&graph_queue->gpeq_lock);
}

void
graph_event_release(graph_protocol_event_t *e)
{
	uu_list_node_fini(e, &e->gpe_link, graph_protocol_event_queue_pool);
	(void) pthread_mutex_destroy(&e->gpe_lock);
	if (e->gpe_inst != NULL)
		startd_free(e->gpe_inst, e->gpe_inst_sz);
	startd_free(e, sizeof (graph_protocol_event_t));
}

/*
 * graph_protocol_event_t *graph_event_dequeue()
 *   The caller must hold gu_lock, and is expected to be a single thread.
 *   It is allowed to utilize graph_event_requeue() and abort processing
 *   on the event. If graph_event_requeue() is not called, the caller is
 *   expected to call graph_event_release() when finished.
 */
graph_protocol_event_t *
graph_event_dequeue()
{
	graph_protocol_event_t *e;

	MUTEX_LOCK(&graph_queue->gpeq_lock);

	e = uu_list_first(graph_queue->gpeq_event_list);
	if (e == NULL) {
		MUTEX_UNLOCK(&graph_queue->gpeq_lock);
		return (NULL);
	}

	if (uu_list_next(graph_queue->gpeq_event_list, e) != NULL)
		gu->gu_wakeup = 1;
	uu_list_remove(graph_queue->gpeq_event_list, e);
	MUTEX_UNLOCK(&graph_queue->gpeq_lock);

	return (e);
}

/*
 * void graph_event_requeue()
 *   Requeue the event back at the head of the queue.
 */
void
graph_event_requeue(graph_protocol_event_t *e)
{
	assert(e != NULL);

	log_framework(LOG_DEBUG, "Requeing event\n");

	MUTEX_LOCK(&graph_queue->gpeq_lock);
	if (uu_list_insert_after(graph_queue->gpeq_event_list, NULL, e) == -1)
		uu_die("failed to requeue graph event (%s: %s)\n",
		    e->gpe_inst, uu_strerror(uu_error()));

	MUTEX_UNLOCK(&graph_queue->gpeq_lock);
}

void
graph_protocol_send_event(const char *inst, graph_event_type_t event,
    protocol_states_t *data)
{
	graph_event_enqueue(inst, event, data);
	MUTEX_LOCK(&gu->gu_lock);
	gu->gu_wakeup = 1;
	(void) pthread_cond_broadcast(&gu->gu_cv);
	MUTEX_UNLOCK(&gu->gu_lock);
}

void
restarter_protocol_init()
{
	restarter_protocol_event_queue_pool = startd_list_pool_create(
	    "restarter_protocol_events", sizeof (restarter_protocol_event_t),
	    offsetof(restarter_protocol_event_t, rpe_link), NULL,
	    UU_LIST_POOL_DEBUG);

	restarter_queue = startd_zalloc(
	    sizeof (restarter_protocol_event_queue_t));

	(void) pthread_mutex_init(&restarter_queue->rpeq_lock, &mutex_attrs);
	restarter_queue->rpeq_event_list = startd_list_create(
	    restarter_protocol_event_queue_pool, restarter_queue, 0);

	log_framework(LOG_DEBUG, "Initialized restarter protocol\n");
}

/*
 * void restarter_event_enqueue()
 *   Enqueue a restarter event.
 */
static void
restarter_event_enqueue(const char *inst, restarter_event_type_t event,
    int32_t reason)
{
	restarter_protocol_event_t *e;
	int r;

	/* Allocate and populate the event structure. */
	e = startd_zalloc(sizeof (restarter_protocol_event_t));

	e->rpe_inst = startd_alloc(strlen(inst) + 1);
	(void) strlcpy(e->rpe_inst, inst, strlen(inst)+1);
	e->rpe_type = event;
	e->rpe_reason = reason;

	MUTEX_LOCK(&restarter_queue->rpeq_lock);
	uu_list_node_init(e, &e->rpe_link, restarter_protocol_event_queue_pool);
	r = uu_list_insert_before(restarter_queue->rpeq_event_list, NULL, e);
	assert(r == 0);

	MUTEX_UNLOCK(&restarter_queue->rpeq_lock);

}

void
restarter_event_release(restarter_protocol_event_t *e)
{
	uu_list_node_fini(e, &e->rpe_link, restarter_protocol_event_queue_pool);
	startd_free(e->rpe_inst, strlen(e->rpe_inst) + 1);
	startd_free(e, sizeof (restarter_protocol_event_t));
}

/*
 * restarter_protocol_event_t *restarter_event_dequeue()
 *   Dequeue a restarter protocol event. The caller is expected to be
 *   a single thread. It is allowed to utilize restarter_event_requeue()
 *   and abort processing on the event. The caller is expected to call
 *   restarter_event_release() when finished.
 */
restarter_protocol_event_t *
restarter_event_dequeue()
{
	restarter_protocol_event_t *e = NULL;

	MUTEX_LOCK(&restarter_queue->rpeq_lock);

	e = uu_list_first(restarter_queue->rpeq_event_list);
	if (e == NULL) {
		MUTEX_UNLOCK(&restarter_queue->rpeq_lock);
		return (NULL);
	}

	if (uu_list_next(restarter_queue->rpeq_event_list, e) != NULL)
		ru->restarter_update_wakeup = 1;
	uu_list_remove(restarter_queue->rpeq_event_list, e);
	MUTEX_UNLOCK(&restarter_queue->rpeq_lock);

	return (e);
}

static int
state_cb(sysevent_t *syse, void *cookie)
{
	char *fmri = (char *)cookie;
	char *instance_name;
	int32_t reason;
	nvlist_t *attr_list = NULL;
	int state, next_state;
	char str_state[MAX_SCF_STATE_STRING_SZ];
	char str_next_state[MAX_SCF_STATE_STRING_SZ];
	protocol_states_t *states;
	int err;
	ssize_t sz;

	/*
	 * Might fail due to a bad event or a lack of memory. Try
	 * the callback again to see if it goes better the next time.
	 */
	if (sysevent_get_attr_list(syse, &attr_list) != 0)
		return (EAGAIN);

	if ((nvlist_lookup_int32(attr_list, RESTARTER_NAME_STATE,
	    &state) != 0) ||
	    (nvlist_lookup_int32(attr_list, RESTARTER_NAME_NEXT_STATE,
	    &next_state) != 0) ||
	    (nvlist_lookup_int32(attr_list, RESTARTER_NAME_ERROR, &err) != 0) ||
	    (nvlist_lookup_string(attr_list, RESTARTER_NAME_INSTANCE,
	    &instance_name) != 0) ||
	    (nvlist_lookup_int32(attr_list, RESTARTER_NAME_REASON, &reason) !=
	    0))
		uu_die("%s: can't decode nvlist\n", fmri);

	states = startd_alloc(sizeof (protocol_states_t));
	states->ps_state = state;
	states->ps_state_next = next_state;
	states->ps_err = err;
	states->ps_reason = reason;

	graph_protocol_send_event(instance_name, GRAPH_UPDATE_STATE_CHANGE,
	    states);

	sz = restarter_state_to_string(state, str_state, sizeof (str_state));
	assert(sz < sizeof (str_state));
	sz = restarter_state_to_string(next_state, str_next_state,
	    sizeof (str_next_state));
	assert(sz < sizeof (str_next_state));
	log_framework(LOG_DEBUG, "%s: state updates for %s (%s, %s)\n", fmri,
	    instance_name, str_state, str_next_state);
	nvlist_free(attr_list);
	return (0);
}

evchan_t *
restarter_protocol_init_delegate(char *fmri)
{
	char *delegate_channel_name, *master_channel_name, *sid;
	evchan_t *delegate_channel, *master_channel;
	int r = 0;

	/* master restarter -- nothing to do */
	if (strcmp(fmri, SCF_SERVICE_STARTD) == 0) {
		uu_warn("Attempt to initialize restarter protocol delegate "
		    "with %s\n", fmri);
		return (NULL);
	}

	log_framework(LOG_DEBUG, "%s: Intializing protocol for delegate\n",
	    fmri);

	delegate_channel_name = master_channel_name = NULL;
	if ((delegate_channel_name = _restarter_get_channel_name(fmri,
	    RESTARTER_CHANNEL_DELEGATE)) == NULL ||
	    (master_channel_name = _restarter_get_channel_name(fmri,
	    RESTARTER_CHANNEL_MASTER)) == NULL ||
	    (sid = strdup("svc.startd")) == NULL) {
		if (delegate_channel_name) {
			free(delegate_channel_name);
		}
		if (master_channel_name) {
			free(master_channel_name);
		}
		uu_warn("Allocation of channel name failed");

		return (NULL);
	}

	if ((r = sysevent_evc_bind(delegate_channel_name, &delegate_channel,
	    EVCH_CREAT|EVCH_HOLD_PEND)) != 0) {
		uu_warn("%s: sysevent_evc_bind failed: %s\n",
		    delegate_channel_name, strerror(errno));
		goto out;
	}

	if ((r = sysevent_evc_bind(master_channel_name, &master_channel,
	    EVCH_CREAT|EVCH_HOLD_PEND)) != 0) {
		uu_warn("%s: sysevent_evc_bind failed: %s\n",
		    master_channel_name, strerror(errno));
		goto out;
	}

	log_framework(LOG_DEBUG,
	    "%s: Bound to channel %s (delegate), %s (master)\n", fmri,
	    delegate_channel_name, master_channel_name);

	if ((r = sysevent_evc_subscribe(master_channel, sid, EC_ALL,
	    state_cb, fmri, EVCH_SUB_KEEP)) != 0) {
		/*
		 * The following errors can be returned in this
		 * case :
		 *	EINVAL : inappropriate flags or dump flag
		 *		and the dump failed.
		 *	EEXIST : svc.startd already has a channel
		 *		named as the master channel name
		 *	ENOMEM : too many subscribers to the channel
		 */
		uu_warn("Failed to subscribe to restarter %s, channel %s with "
		    "subscriber id %s : \n", fmri, master_channel_name, sid);
		switch (r) {
		case EEXIST:
			uu_warn("Channel name already exists\n");
			break;
		case ENOMEM:
			uu_warn("Too many subscribers for the channel\n");
			break;
		default:
			uu_warn("%s\n", strerror(errno));
		}
	} else {
		log_framework(LOG_DEBUG,
		    "%s: Subscribed to channel %s with subscriber id %s\n",
		    fmri, master_channel_name, "svc.startd");
	}


out:
	free(delegate_channel_name);
	free(master_channel_name);
	free(sid);

	if (r == 0)
		return (delegate_channel);

	return (NULL);
}

void
restarter_protocol_send_event(const char *inst, evchan_t *chan,
    restarter_event_type_t event, int32_t reason)
{
	nvlist_t *attr;
	int ret;

	/*
	 * If the service is managed by the master restarter,
	 * queue the event locally.
	 */
	if (chan == NULL) {
		restarter_event_enqueue(inst, event, reason);
		MUTEX_LOCK(&ru->restarter_update_lock);
		ru->restarter_update_wakeup = 1;
		(void) pthread_cond_broadcast(&ru->restarter_update_cv);
		MUTEX_UNLOCK(&ru->restarter_update_lock);
		return;
	}

	/*
	 * Otherwise, send the event to the delegate.
	 */
	log_framework(LOG_DEBUG, "Sending %s to channel 0x%p for %s.\n",
	    event_names[event], chan, inst);
	if (nvlist_alloc(&attr, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_uint32(attr, RESTARTER_NAME_TYPE, event) != 0 ||
	    nvlist_add_string(attr, RESTARTER_NAME_INSTANCE, (char *)inst) !=
	    0 || nvlist_add_uint32(attr, RESTARTER_NAME_REASON,
	    reason) != 0)
		uu_die("Allocation failure\n");

	if ((ret = restarter_event_publish_retry(chan, "protocol", "restarter",
	    "com.sun", "svc.startd", attr, EVCH_NOSLEEP)) != 0) {

		switch (ret) {
		case ENOSPC:
			log_framework(LOG_DEBUG, "Dropping %s event for %s. "
			    "Delegate may not be running.\n",
			    event_names[event], inst);
			break;
		default:
			uu_die("%s: can't publish event: %s\n", inst,
			    strerror(errno));
		}
	}

	nvlist_free(attr);

	if (event != RESTARTER_EVENT_TYPE_ADD_INSTANCE) {
		/*
		 * Not relevant for graph loading.
		 */
		return;
	}

	/*
	 * For the purposes of loading state after interruption, this is
	 * sufficient, as svc.startd(1M) won't receive events on the contracts
	 * associated with each delegate.
	 */
	MUTEX_LOCK(&st->st_load_lock);
	if (--st->st_load_instances == 0)
		(void) pthread_cond_broadcast(&st->st_load_cv);
	MUTEX_UNLOCK(&st->st_load_lock);

}
