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

#include <arpa/inet.h>
#include <assert.h>
#include <libdllink.h>
#include <libdlstat.h>
#include <libnwam.h>
#include <libscf.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <values.h>

#include "conditions.h"
#include "events.h"
#include "objects.h"
#include "ncp.h"
#include "ncu.h"
#include "util.h"

/*
 * ncp.c - handles NCP actions.
 */

char active_ncp[NWAM_MAX_NAME_LEN];
nwam_ncp_handle_t active_ncph = NULL;
int64_t current_ncu_priority_group = INVALID_PRIORITY_GROUP;
/*
 * active_ncp_mutex protects active_ncp, active_ncph and
 * current_ncu_priority_group.
 */
pthread_mutex_t active_ncp_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * The variable ncu_wait_time specifies how long to wait to obtain a
 * DHCP lease before giving up on that NCU and moving on to the next/lower
 * priority-group.
 */
uint64_t ncu_wait_time = NCU_WAIT_TIME_DEFAULT;

/*
 * Specifies if this is the first time the NCP has been enabled. True
 * on startup so that we can differentiate between when we start up
 * with a given NCP versus when we are asked to reenable it.
 */
boolean_t initial_ncp_enable = B_TRUE;

/*
 * nwamd_ncp_handle_enable_event() should be called in the event handling
 * loop in response to an _ENABLE event, triggered as a result of an
 * nwam_ncp_enable() call from a libnwam consumer.  To enable the new NCP,
 * we first call nwamd_fini_ncus() on the old NCP.  This results in enqueueing
 * of a set of _FINI events for each NCU.  These events are handled and in
 * order to tear down config, (online*, uninitialized) state change events
 * are created and consumed directly by the fini event handler (these events
 * are not enqueued as this would result in state events for the old NCP
 * appearing after the new NCP has been enabled.  After the _FINI events are
 * enqueued, we enqueue an NCP _OBJECT_STATE event for the new NCP.  Since
 * it is enqueued after the _FINI events, we are guaranteed no events for the
 * old NCP will appear after the new NCP is activated.
 */
void
nwamd_ncp_handle_enable_event(nwamd_event_t event)
{
	char *new_ncp = event->event_object;
	nwam_ncp_handle_t new_ncph;
	nwam_error_t err;

	if (new_ncp[0] == '\0')
		return;

	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (strcmp(active_ncp, new_ncp) == 0 && !initial_ncp_enable) {
		nlog(LOG_DEBUG, "nwamd_ncp_handle_enable_event: "
		    "%s is already active", new_ncp);
		(void) pthread_mutex_unlock(&active_ncp_mutex);
		return;
	}
	(void) pthread_mutex_unlock(&active_ncp_mutex);

	nlog(LOG_DEBUG, "nwamd_ncp_handle_enable_event: activating NCP %s",
	    new_ncp);

	/*
	 * To activate new NCP, run nwamd_fini_ncus(), reset the active
	 * priority-group, set the active_ncp property and refresh the
	 * daemon.  The refresh action will trigger a re-read of the NCUs
	 * for the activated NCP.
	 */

	nwamd_fini_ncus();

	err = nwam_ncp_read(new_ncp, 0, &new_ncph);
	switch (err) {
	case NWAM_ENTITY_NOT_FOUND:
		err = nwam_ncp_create(new_ncp, 0, &new_ncph);
		break;
	case NWAM_SUCCESS:
		break;
	default:
		nlog(LOG_ERR, "nwamd_ncp_handle_enable_event: error %s",
		    nwam_strerror(err));
		return;
	}
	nwam_ncp_free(new_ncph);

	if (err == NWAM_SUCCESS) {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCP, new_ncp,
		    NWAM_STATE_ONLINE, NWAM_AUX_STATE_ACTIVE);
	} else {
		nlog(LOG_ERR, "nwamd_ncp_handle_enable_event: error %s",
		    nwam_strerror(err));
		return;
	}
}

void
nwamd_ncp_handle_action_event(nwamd_event_t event)
{
	switch (event->event_msg->nwe_data.nwe_object_action.nwe_action) {
	case NWAM_ACTION_ENABLE:
		nwamd_ncp_handle_enable_event(event);
		break;
	case NWAM_ACTION_ADD:
	case NWAM_ACTION_DESTROY:
		/* nothing to do */
		break;
	default:
		nlog(LOG_INFO, "nwam_ncp_handle_action_event: "
		    "unexpected action");
		nwamd_event_do_not_send(event);
		break;
	}
}

/*
 * The only state events we create are (online, active) events which are
 * generated as part of an NCP enable action (see above).
 */
void
nwamd_ncp_handle_state_event(nwamd_event_t event)
{
	char *new_ncp = event->event_object;
	nwam_ncp_handle_t new_ncph, old_ncph;
	nwam_error_t err;

	/* The NCP to be activated should always exist. */
	if ((err = nwam_ncp_read(new_ncp, 0, &new_ncph)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_ncp_handle_state_event: "
		    "cannot read NCP %s: : %s", new_ncp, nwam_strerror(err));
		nwamd_event_do_not_send(event);
		return;
	}

	/*
	 * To activate new NCP, reset the active priority-group, set the
	 * active_ncp property and refresh the daemon.  The refresh action will
	 * trigger a re-read of the NCUs for the activated NCP.
	 */
	(void) pthread_mutex_lock(&active_ncp_mutex);
	old_ncph = active_ncph;
	active_ncph = new_ncph;
	nwam_ncp_free(old_ncph);
	current_ncu_priority_group = INVALID_PRIORITY_GROUP;
	(void) strlcpy(active_ncp, event->event_object,
	    sizeof (active_ncp));
	(void) pthread_mutex_unlock(&active_ncp_mutex);
	(void) nwamd_set_string_property(OUR_FMRI, OUR_PG,
	    OUR_ACTIVE_NCP_PROP_NAME, new_ncp);
	(void) smf_refresh_instance(OUR_FMRI);
	initial_ncp_enable = B_FALSE;
}

int
nwamd_ncp_action(const char *ncp, nwam_action_t action)
{
	nwamd_event_t event = nwamd_event_init_object_action
	    (NWAM_OBJECT_TYPE_NCP, ncp, NULL, action);
	if (event == NULL)
		return (1);
	nwamd_event_enqueue(event);
	return (0);
}

/*
 * Below this point are routines handling NCU prioritization
 * policy for the active NCP.
 */

struct priority_group_cbarg {
	uint64_t minpriority;
	uint64_t currpriority;
	boolean_t found;
};

/* Callback used to find next pg in NCP that is >= start_pg */
static int
find_next_priority_group_cb(nwamd_object_t object, void *data)
{
	struct priority_group_cbarg *cbarg = data;
	uint64_t priority;
	nwamd_ncu_t *ncu = object->nwamd_object_data;

	if (ncu->ncu_node.u_link.nwamd_link_activation_mode !=
	    NWAM_ACTIVATION_MODE_PRIORITIZED)
		return (0);

	priority = ncu->ncu_node.u_link.nwamd_link_priority_group;

	if (priority >= cbarg->minpriority && priority < cbarg->currpriority) {
		cbarg->found = B_TRUE;
		cbarg->currpriority = priority;
	}
	return (0);
}


/* Set current_pg to next pg in NCP that is >= start_pg */
boolean_t
nwamd_ncp_find_next_priority_group(int64_t minpriority,
    int64_t *nextpriorityp)
{
	struct priority_group_cbarg cbarg;

	cbarg.minpriority = minpriority;
	cbarg.currpriority = MAXINT;
	cbarg.found = B_FALSE;

	(void) nwamd_walk_objects(NWAM_OBJECT_TYPE_NCU,
	    find_next_priority_group_cb, &cbarg);

	if (cbarg.found) {
		nlog(LOG_DEBUG, "nwamd_ncp_find_next_priority_group: "
		    "next priority group >= %lld is %lld",
		    minpriority, cbarg.currpriority);
		*nextpriorityp = cbarg.currpriority;
		return (B_TRUE);
	} else {
		nlog(LOG_DEBUG, "nwamd_ncp_find_next_priority_group: "
		    "no priority groups >= %lld exist", minpriority);
		return (B_FALSE);
	}
}

/*
 * Struct for walking NCUs in the selected priority group.  We count
 * how many of the exclusive, all and shared NCUs are online, and
 * if activate_or_deactivate is true, we either activate or deactivate
 * (depending on the value of activate) offline/online NCUs.
 */
struct nwamd_ncu_check_walk_arg {
	boolean_t manual;	/* enable manual NCUs only */
	int64_t priority_group; /* interested priority-group for this walk */
	uint64_t exclusive_ncus;
	uint64_t exclusive_online_ncus;
	uint64_t shared_ncus;
	uint64_t shared_online_ncus;
	uint64_t all_ncus;
	uint64_t all_online_ncus;
	boolean_t activate_or_deactivate;
	boolean_t activate;
};

/*
 * This function serves a number of purposes:
 * - it supports activation/deactivation of manual NCUs in the current NCP
 * (when wa->manual is true, wa->activate determines if we activate or
 * deactivate the current NCU)
 * - it supports checking/activation of a particular priority group in
 * the active NCP. This works as follows:
 *
 * Count up numbers of exclusive, shared and all NCUs, and how many of each
 * are online.  If an NCU is waiting for IP address to be assigned, it is
 * also considered online.  If activate_or_deactivate is true, we also
 * either activate (if activate is true) or deactivate prioritized NCUs
 * that are offline or online.
 */
static int
nwamd_ncu_check_or_activate(nwamd_object_t object, void *data)
{
	struct nwamd_ncu_check_walk_arg *wa = data;
	nwamd_ncu_t *ncu;
	uint64_t priority_group, priority_mode;
	nwamd_object_t if_obj;
	nwam_state_t state, if_state;
	nwam_aux_state_t aux_state, if_aux_state;
	char *name;

	state = object->nwamd_object_state;
	aux_state = object->nwamd_object_aux_state;
	name = object->nwamd_object_name;
	ncu = object->nwamd_object_data;

	/* skip NCUs in UNINITIALIZED state */
	if (state == NWAM_STATE_UNINITIALIZED) {
		nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
		    "skipping uninitialized ncu %s", name);
		return (0);
	}
	if (!wa->manual && wa->priority_group == INVALID_PRIORITY_GROUP)
		return (0);

	if (ncu->ncu_type != NWAM_NCU_TYPE_LINK) {
		nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
		    "skipping interface NCU %s", name);
		return (0);
	}
	if (!wa->manual && ncu->ncu_node.u_link.nwamd_link_activation_mode !=
	    NWAM_ACTIVATION_MODE_PRIORITIZED) {
		nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
		    "skipping non-prioritized NCU %s", name);
		return (0);
	}
	if (wa->manual && ncu->ncu_node.u_link.nwamd_link_activation_mode !=
	    NWAM_ACTIVATION_MODE_MANUAL) {
		nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
		    "skipping non-manual NCU %s", name);
		return (0);
	}

	priority_group = ncu->ncu_node.u_link.nwamd_link_priority_group;
	priority_mode = ncu->ncu_node.u_link.nwamd_link_priority_mode;
	/* Only work with NCUs in the requested priority-group */
	if (!wa->manual && priority_group != wa->priority_group) {
		nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
		    "skipping NCU %s in different priority-group", name);
		return (0);
	}
	/* Get the state of the corresponding interface NCU */
	if ((if_obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_INTERFACE,
	    ncu->ncu_name)) == NULL) {
		nlog(LOG_ERR, "nwamd_ncu_check_or_activate: "
		    "interface NCU of %s not found, skipping", name);
		return (0);
	}
	if_state = if_obj->nwamd_object_state;
	if_aux_state = if_obj->nwamd_object_aux_state;
	nwamd_object_release(if_obj);

	nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: %s ncu %s",
	    wa->activate_or_deactivate ?
	    (wa->activate ? "activating" : "deactivating") :
	    "checking", name);

	if (wa->manual) {
		if (wa->activate_or_deactivate && wa->activate) {
			if (state == NWAM_STATE_OFFLINE && ncu->ncu_enabled) {
				nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
				    "moving NCU %s to offline* from offline",
				    name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    name, NWAM_STATE_OFFLINE_TO_ONLINE,
				    NWAM_AUX_STATE_INITIALIZED);
			}
			if (state != NWAM_STATE_DISABLED &&
			    !ncu->ncu_enabled) {
				nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
				    "moving NCU %s to online* (disabling)",
				    name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    name, NWAM_STATE_ONLINE_TO_OFFLINE,
				    NWAM_AUX_STATE_MANUAL_DISABLE);
			}
		}
		return (0);
	}
	switch (priority_mode) {
	case NWAM_PRIORITY_MODE_EXCLUSIVE:
		wa->exclusive_ncus++;
		if (state == NWAM_STATE_ONLINE &&
		    (if_state == NWAM_STATE_ONLINE ||
		    if_aux_state == NWAM_AUX_STATE_IF_WAITING_FOR_ADDR))
			wa->exclusive_online_ncus++;

		/*
		 * For exclusive NCUs, we activate offline NCUs as long
		 * as no other exclusive NCUs are active.
		 */
		if (wa->activate_or_deactivate && wa->activate) {
			if (state == NWAM_STATE_OFFLINE &&
			    wa->exclusive_online_ncus == 0) {
				nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
				    "moving NCU %s to offline* from offline",
				    name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    name, NWAM_STATE_OFFLINE_TO_ONLINE,
				    NWAM_AUX_STATE_INITIALIZED);
			}
		}
		if (wa->activate_or_deactivate && !wa->activate) {
			if (aux_state != NWAM_AUX_STATE_CONDITIONS_NOT_MET) {
				nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
				    "deactivating NCU %s", name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    name, NWAM_STATE_ONLINE_TO_OFFLINE,
				    NWAM_AUX_STATE_CONDITIONS_NOT_MET);
			}
		}
		/*
		 * If we are activating or checking the priority group and
		 * too many exclusive NCUs are online, take this NCU down.
		 */
		if ((wa->activate_or_deactivate && wa->activate) ||
		    !wa->activate_or_deactivate) {
			if (state == NWAM_STATE_ONLINE &&
			    if_state == NWAM_STATE_ONLINE &&
			    wa->exclusive_online_ncus > 1) {
				nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
				    "moving NCU %s to online* since another "
				    "NCU is already active",
				    name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    name, NWAM_STATE_ONLINE_TO_OFFLINE,
				    NWAM_AUX_STATE_CONDITIONS_NOT_MET);
			}
		}
		break;
	case NWAM_PRIORITY_MODE_SHARED:
		wa->shared_ncus++;
		if (state == NWAM_STATE_ONLINE &&
		    (if_state == NWAM_STATE_ONLINE ||
		    if_aux_state == NWAM_AUX_STATE_IF_WAITING_FOR_ADDR))
			wa->shared_online_ncus++;

		if (wa->activate_or_deactivate && wa->activate) {
			if (state == NWAM_STATE_OFFLINE) {
				nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
				    "activating NCU %s", name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    name, NWAM_STATE_OFFLINE_TO_ONLINE,
				    NWAM_AUX_STATE_INITIALIZED);
			}
		}
		if (wa->activate_or_deactivate && !wa->activate) {
			if (aux_state != NWAM_AUX_STATE_CONDITIONS_NOT_MET) {
				nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
				    "deactivating NCU %s", name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    name, NWAM_STATE_ONLINE_TO_OFFLINE,
				    NWAM_AUX_STATE_CONDITIONS_NOT_MET);
			}
		}
		break;
	case NWAM_PRIORITY_MODE_ALL:
		wa->all_ncus++;
		if (state == NWAM_STATE_ONLINE &&
		    (if_state == NWAM_STATE_ONLINE ||
		    if_aux_state == NWAM_AUX_STATE_IF_WAITING_FOR_ADDR))
			wa->all_online_ncus++;

		/*
		 * For "all" NCUs, activate/deactivate all offline/online
		 * NCUs.
		 */
		if (wa->activate_or_deactivate && wa->activate) {
			if (state == NWAM_STATE_OFFLINE) {
				nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
				    "activating NCU %s", name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    name, NWAM_STATE_OFFLINE_TO_ONLINE,
				    NWAM_AUX_STATE_INITIALIZED);
			}
		}
		if (wa->activate_or_deactivate && !wa->activate) {
			if (aux_state != NWAM_AUX_STATE_CONDITIONS_NOT_MET) {
				nlog(LOG_DEBUG, "nwamd_ncu_check_or_activate: "
				    "deactivating NCU %s", name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    name, NWAM_STATE_ONLINE_TO_OFFLINE,
				    NWAM_AUX_STATE_CONDITIONS_NOT_MET);
			}
		}

		break;
	default:
		nlog(LOG_ERR, "nwamd_ncu_check_or_activate: "
		    "invalid priority-mode");
		break;
	}

	return (0);
}

void
nwamd_ncp_activate_priority_group(int64_t priority)
{
	struct nwamd_ncu_check_walk_arg wa;
	nwamd_event_t check_event, priority_event;

	if (priority == INVALID_PRIORITY_GROUP)
		return;

	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (priority == current_ncu_priority_group) {
		(void) pthread_mutex_unlock(&active_ncp_mutex);
		return;
	}
	(void) pthread_mutex_unlock(&active_ncp_mutex);

	nlog(LOG_DEBUG, "nwamd_ncp_activate_priority_group: "
	    "activating priority group %lld", priority);

	wa.manual = B_FALSE;
	wa.priority_group = priority;
	wa.exclusive_ncus = 0;
	wa.exclusive_online_ncus = 0;
	wa.shared_ncus = 0;
	wa.shared_online_ncus = 0;
	wa.all_ncus = 0;
	wa.all_online_ncus = 0;
	wa.activate_or_deactivate = B_TRUE;
	wa.activate = B_TRUE;

	if (nwamd_walk_objects(NWAM_OBJECT_TYPE_NCU,
	    nwamd_ncu_check_or_activate, &wa) != 0) {
		nlog(LOG_ERR, "nwamd_ncp_activate_priority_group: "
		    "nwamd_walk_objects() failed");
		return;
	}

	/*
	 * Enqueue event to update current_ncu_priority_group and send to
	 * any event listeners.
	 */
	priority_event = nwamd_event_init_priority_group_change(priority);
	if (priority_event == NULL)
		return;
	nwamd_event_enqueue(priority_event);

	/*
	 * Now we've activated a new priority group, enqueue an event
	 * to check up on the state of this priority group.
	 */
	check_event = nwamd_event_init_ncu_check();
	if (check_event == NULL)
		return;
	nwamd_event_enqueue_timed(check_event, ncu_wait_time);
}

void
nwamd_ncp_deactivate_priority_group(int64_t priority)
{
	struct nwamd_ncu_check_walk_arg wa;

	if (priority == INVALID_PRIORITY_GROUP)
		return;

	nlog(LOG_DEBUG, "nwamd_ncp_deactivate_priority_group: "
	    "deactivating priority group %lld", priority);

	wa.manual = B_FALSE;
	wa.priority_group = priority;
	wa.exclusive_ncus = 0;
	wa.exclusive_online_ncus = 0;
	wa.shared_ncus = 0;
	wa.shared_online_ncus = 0;
	wa.all_ncus = 0;
	wa.all_online_ncus = 0;
	wa.activate_or_deactivate = B_TRUE;
	wa.activate = B_FALSE;

	if (nwamd_walk_objects(NWAM_OBJECT_TYPE_NCU,
	    nwamd_ncu_check_or_activate, &wa) != 0) {
		nlog(LOG_ERR, "nwamd_ncp_deactivate_priority_group: "
		    "nwamd_walk_objects() failed");
		return;
	}
}

/*
 * This function deactivates all priority groups at level 'priority' and lower
 * (which is, numerically, all priorities >= priority).
 */
void
nwamd_ncp_deactivate_priority_group_all(int64_t priority)
{
	if (priority == INVALID_PRIORITY_GROUP)
		return;

	nlog(LOG_DEBUG, "nwamd_ncp_deactivate_priority_group_all: "
	    "deactivating priority group less than or equal to %lld", priority);

	do {
		nwamd_ncp_deactivate_priority_group(priority);
	} while (nwamd_ncp_find_next_priority_group(priority + 1, &priority));
}

/*
 * Returns 'true' if it found the highest priority group no higher then what
 * is passed that should be activated and sets *priority to that.
 */
boolean_t
nwamd_ncp_check_priority_group(int64_t *priority)
{
	struct nwamd_ncu_check_walk_arg wa;
	boolean_t conditions_met = B_FALSE;

	nlog(LOG_DEBUG, "nwamd_ncp_check_priority_group: "
	    "checking priority group %lld", *priority);

	if (*priority == INVALID_PRIORITY_GROUP) {
		if (!nwamd_ncp_find_next_priority_group(0, priority))
			return (B_FALSE);
	}

	while (!conditions_met) {
		(void) memset(&wa, 0, sizeof (wa));
		wa.manual = B_FALSE;
		wa.priority_group = *priority;
		wa.activate_or_deactivate = B_FALSE;

		if (nwamd_walk_objects(NWAM_OBJECT_TYPE_NCU,
		    nwamd_ncu_check_or_activate, &wa) != 0) {
			nlog(LOG_ERR, "nwamd_ncp_check_priority_group: "
			    "nwamd_walk_objects() failed");
			return (B_FALSE);
		}

		/*
		 * Are activation conditons satisifed? In other words:
		 * - exactly one of the exclusive NCUs is online
		 * - 1 or more shared NCUs are online
		 * - all of the all NCUs are online.
		 * If any of these is untrue, conditions are not satisfied.
		 */
		conditions_met = B_TRUE;
		if (wa.exclusive_ncus > 0 && wa.exclusive_online_ncus != 1)
			conditions_met = B_FALSE;
		if (wa.shared_ncus > 0 && wa.shared_online_ncus == 0)
			conditions_met = B_FALSE;
		if (wa.all_ncus > 0 && wa.all_ncus != wa.all_online_ncus)
			conditions_met = B_FALSE;
		if (wa.exclusive_online_ncus == 0 &&
		    wa.shared_online_ncus == 0 && wa.all_online_ncus == 0)
			conditions_met = B_FALSE;

		if (conditions_met) {
			return (B_TRUE);
		} else {
			/*
			 * If there is a next pg, activate it. If not, do
			 * nothing - we're stuck here unless an event occurs
			 * for our or a higher pg.
			 */
			if (!nwamd_ncp_find_next_priority_group
			    (wa.priority_group + 1, priority)) {
				nlog(LOG_DEBUG, "ran out of prio groups");
				return (B_FALSE);
			}
		}
	}
	return (B_FALSE);
}

void
nwamd_ncp_activate_manual_ncus(void)
{
	struct nwamd_ncu_check_walk_arg wa;

	nlog(LOG_DEBUG, "nwamd_ncp_activate_manual_ncus: activating NCUs");

	wa.manual = B_TRUE;
	wa.activate_or_deactivate = B_TRUE;
	wa.activate = B_TRUE;

	if (nwamd_walk_objects(NWAM_OBJECT_TYPE_NCU,
	    nwamd_ncu_check_or_activate, &wa) != 0) {
		nlog(LOG_ERR, "nwamd_ncp_activate_manual_ncus: "
		    "nwamd_walk_objects() failed");
		return;
	}
}

void
nwamd_create_ncu_check_event(uint64_t when)
{
	nwamd_event_t check_event = nwamd_event_init_ncu_check();
	if (check_event != NULL)
		nwamd_event_enqueue_timed(check_event, when);
}
