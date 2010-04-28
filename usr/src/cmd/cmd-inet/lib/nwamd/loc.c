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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <inet/ip.h>
#include <inetcfg.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlwlan.h>
#include <libscf.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libnwam.h>
#include "conditions.h"
#include "events.h"
#include "objects.h"
#include "util.h"

/*
 * loc.c - contains routines which handle location abstraction.
 */

pthread_mutex_t active_loc_mutex = PTHREAD_MUTEX_INITIALIZER;
char active_loc[NWAM_MAX_NAME_LEN];

static int
loc_create_init_fini_event(nwam_loc_handle_t loch, void *data)
{
	boolean_t *init = data;
	char *name;
	nwamd_event_t event;

	if (nwam_loc_get_name(loch, &name) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "loc_init_fini: could not get loc name");
		return (0);
	}

	event = nwamd_event_init(*init ?
	    NWAM_EVENT_TYPE_OBJECT_INIT : NWAM_EVENT_TYPE_OBJECT_FINI,
	    NWAM_OBJECT_TYPE_LOC, 0, name);
	if (event != NULL)
		nwamd_event_enqueue(event);
	free(name);

	return (0);
}

/*
 * Walk all locs, creating init events for each.
 */
void
nwamd_init_locs(void)
{
	boolean_t init = B_TRUE;

	/* Unset active location */
	(void) pthread_mutex_lock(&active_loc_mutex);
	active_loc[0] = '\0';
	(void) pthread_mutex_unlock(&active_loc_mutex);
	(void) nwam_walk_locs(loc_create_init_fini_event, &init, 0, NULL);
}

/*
 * Walk all locs, creating fini events for each.
 */
void
nwamd_fini_locs(void)
{
	boolean_t init = B_FALSE;

	(void) nwam_walk_locs(loc_create_init_fini_event, &init, 0, NULL);
}

static boolean_t
loc_is_enabled(nwam_loc_handle_t loch)
{
	nwam_value_t enabledval;
	boolean_t enabled = B_FALSE;

	if (nwam_loc_get_prop_value(loch, NWAM_LOC_PROP_ENABLED,
	    &enabledval) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "loc_is_enabled: could not retrieve "
		    "enabled value");
		return (B_FALSE);
	}
	if (nwam_value_get_boolean(enabledval, &enabled)
	    != NWAM_SUCCESS) {
		nlog(LOG_ERR, "loc_is_enabled: could not retrieve "
		    "enabled value");
		nwam_value_free(enabledval);
		return (B_FALSE);
	}
	nwam_value_free(enabledval);
	return (enabled);
}

static int64_t
loc_get_activation_mode(nwam_loc_handle_t loch)
{
	nwam_error_t err;
	uint64_t activation;
	nwam_value_t activationval;

	if (nwam_loc_get_prop_value(loch, NWAM_LOC_PROP_ACTIVATION_MODE,
	    &activationval)  != NWAM_SUCCESS) {
		nlog(LOG_ERR, "loc_get_activation_mode: could not retrieve "
		    "activation mode value");
		return (-1);
	}
	err = nwam_value_get_uint64(activationval, &activation);
	nwam_value_free(activationval);
	if (err != NWAM_SUCCESS) {
		nlog(LOG_ERR, "loc_get_activation_mode: could not retrieve "
		    "activation mode value");
		return (-1);
	}

	return ((int64_t)activation);
}

/* Enables the location. */
static void
nwamd_loc_activate(const char *object_name)
{
	char *enabled;

	nlog(LOG_DEBUG, "nwamd_loc_activate: activating loc %s",
	    object_name);

	/*
	 * Find currently enabled location and change its state to disabled
	 * if it is a manual location, or offline (if it is not).
	 * Only manual locations reach disabled, since conditional and
	 * system locations which are manually disabled simply revert to
	 * their conditions for activation.
	 */
	if ((enabled = malloc(NWAM_MAX_NAME_LEN)) != NULL &&
	    nwamd_lookup_string_property(NET_LOC_FMRI, NET_LOC_PG,
	    NET_LOC_SELECTED_PROP, enabled, NWAM_MAX_NAME_LEN) == 0) {
		/* Only change state if current != new */
		if (strcmp(enabled, object_name) != 0) {
			boolean_t do_disable = B_FALSE;
			nwamd_object_t eobj = nwamd_object_find
			    (NWAM_OBJECT_TYPE_LOC, enabled);
			if (eobj == NULL) {
				nlog(LOG_INFO, "nwamd_loc_activate: could not "
				    "find old location %s", enabled);
				goto skip_disable;
			}
			/*
			 * Disable if the old location was manual, since the
			 * only way a manual location can deactivate is if
			 * it is disabled.
			 */
			do_disable =
			    (loc_get_activation_mode(eobj->nwamd_object_handle)
			    == (int64_t)NWAM_ACTIVATION_MODE_MANUAL);
			nwamd_object_release(eobj);

			if (do_disable) {
				nlog(LOG_DEBUG, "nwamd_loc_activate: "
				    "disable needed for old location %s",
				    enabled);
				nwamd_object_set_state
				    (NWAM_OBJECT_TYPE_LOC, enabled,
				    NWAM_STATE_DISABLED,
				    NWAM_AUX_STATE_MANUAL_DISABLE);
			} else {
				nlog(LOG_DEBUG, "nwamd_loc_activate: "
				    "offline needed for old location %s",
				    enabled);
				nwamd_object_set_state
				    (NWAM_OBJECT_TYPE_LOC, enabled,
				    NWAM_STATE_OFFLINE,
				    NWAM_AUX_STATE_CONDITIONS_NOT_MET);
			}
		}
	}
skip_disable:
	free(enabled);

	if (nwamd_set_string_property(NET_LOC_FMRI, NET_LOC_PG,
	    NET_LOC_SELECTED_PROP, object_name) == 0) {
		char *state = smf_get_state(NET_LOC_FMRI);
		nlog(LOG_INFO, "nwamd_loc_activate: set %s/%s to %s; "
		    "service is in %s state", NET_LOC_PG, NET_LOC_SELECTED_PROP,
		    object_name, state == NULL ? "unknown" : state);
		free(state);
		(void) smf_restore_instance(NET_LOC_FMRI);
		if (smf_refresh_instance(NET_LOC_FMRI) == 0) {
			(void) pthread_mutex_lock(&active_loc_mutex);
			(void) strlcpy(active_loc, object_name,
			    sizeof (active_loc));
			(void) pthread_mutex_unlock(&active_loc_mutex);
			nwamd_object_set_state(NWAM_OBJECT_TYPE_LOC,
			    object_name,
			    NWAM_STATE_ONLINE, NWAM_AUX_STATE_ACTIVE);
		} else {
			nlog(LOG_ERR, "nwamd_loc_activate: "
			    "%s could not be refreshed", NET_LOC_FMRI);
			nwamd_object_set_state(NWAM_OBJECT_TYPE_LOC,
			    object_name,
			    NWAM_STATE_MAINTENANCE,
			    NWAM_AUX_STATE_METHOD_FAILED);
		}
	}
}

struct nwamd_loc_check_walk_arg {
	nwamd_object_t winning_object;
	uint64_t winning_rating;
};

/*
 * Determine which location should be activated.
 */
static int
nwamd_loc_check(nwamd_object_t object, void *data)
{
	struct nwamd_loc_check_walk_arg *wa = data;
	nwam_loc_handle_t loch = object->nwamd_object_handle;
	nwam_value_t conditionval;
	int64_t lactivation;
	uint64_t rating, activation;
	boolean_t satisfied;
	char **conditions;
	uint_t nelem;

	lactivation = loc_get_activation_mode(object->nwamd_object_handle);

	if (lactivation == -1)
		return (0);

	activation = (uint64_t)lactivation;
	switch (activation) {
	case NWAM_ACTIVATION_MODE_MANUAL:
		if (loc_is_enabled(loch)) {
			/* Manually enabled locations should always win out. */
			nlog(LOG_DEBUG, "nwamd_loc_check: %s is enabled",
			    object->nwamd_object_name);
			wa->winning_object = object;
			wa->winning_rating = UINT64_MAX;
		} else {
			nlog(LOG_DEBUG, "nwamd_loc_check: %s is disabled",
			    object->nwamd_object_name);
			if (object->nwamd_object_state != NWAM_STATE_DISABLED) {
				nwamd_object_set_state(NWAM_OBJECT_TYPE_LOC,
				    object->nwamd_object_name,
				    NWAM_STATE_DISABLED,
				    NWAM_AUX_STATE_MANUAL_DISABLE);
			}
		}

		return (0);

	case NWAM_ACTIVATION_MODE_CONDITIONAL_ANY:
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ALL:
		if (loc_is_enabled(loch)) {
			/* Manually enabled locations should always win out. */
			nlog(LOG_DEBUG, "nwamd_loc_check: %s is enabled",
			    object->nwamd_object_name);
			wa->winning_object = object;
			wa->winning_rating = UINT64_MAX;
		}

		if (nwam_loc_get_prop_value(loch,
		    NWAM_LOC_PROP_CONDITIONS, &conditionval) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "nwamd_loc_check: could not retrieve "
			    "condition value");
			return (0);
		}
		if (nwam_value_get_string_array(conditionval,
		    &conditions, &nelem) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "nwamd_loc_check: could not retrieve "
			    "condition value");
			nwam_value_free(conditionval);
			return (0);
		}
		satisfied = nwamd_check_conditions(activation, conditions,
		    nelem);

		if (satisfied) {
			rating = nwamd_rate_conditions(activation,
			    conditions, nelem);
			if (rating > wa->winning_rating) {
				wa->winning_object = object;
				wa->winning_rating = rating;
			}
		}
		nwam_value_free(conditionval);
		return (0);

	case NWAM_ACTIVATION_MODE_SYSTEM:
		if (loc_is_enabled(loch)) {
			/* Manually enabled locations should always win out. */
			nlog(LOG_DEBUG, "nwamd_loc_check: %s is enabled",
			    object->nwamd_object_name);
			wa->winning_object = object;
			wa->winning_rating = UINT64_MAX;
		}

		/* Either NoNet, Automatic or Legacy location, so skip. */

		return (0);
	default:
		return (0);
	}
	/*NOTREACHED*/
	return (0);
}

static int
nwamd_ncu_online_check(nwamd_object_t object, void *data)
{
	boolean_t *online = data;
	nwamd_ncu_t *ncu_data = object->nwamd_object_data;

	if (ncu_data->ncu_type != NWAM_NCU_TYPE_INTERFACE)
		return (0);

	if (object->nwamd_object_state == NWAM_STATE_ONLINE) {
		/* An online IP NCU found, stop walk */
		*online = B_TRUE;
		return (1);
	}
	return (0);
}

void
nwamd_loc_check_conditions(void)
{
	struct nwamd_loc_check_walk_arg wa = { NULL, 0 };
	const char *winning_loc;
	boolean_t ncu_online = B_FALSE;
	boolean_t is_active;

	/*
	 * Walk the NCUs to find out if at least one IP NCU is online.  If so,
	 * check the activation-mode and conditions.  If not, enable the NoNet
	 * location.
	 */
	(void) nwamd_walk_objects(NWAM_OBJECT_TYPE_NCU, nwamd_ncu_online_check,
	    &ncu_online);

	if (!ncu_online) {
		winning_loc = NWAM_LOC_NAME_NO_NET;
	} else {
		(void) nwamd_walk_objects(NWAM_OBJECT_TYPE_LOC, nwamd_loc_check,
		    &wa);
		if (wa.winning_object != NULL)
			winning_loc = wa.winning_object->nwamd_object_name;
		else
			winning_loc = NWAM_LOC_NAME_AUTOMATIC;
	}
	nlog(LOG_INFO, "nwamd_loc_check_conditions: winning loc is %s",
	    winning_loc);

	/* If the winning location is already active, do nothing */
	(void) pthread_mutex_lock(&active_loc_mutex);
	is_active = (strcmp(active_loc, winning_loc) == 0);
	(void) pthread_mutex_unlock(&active_loc_mutex);
	if (is_active)
		return;

	nwamd_object_set_state(NWAM_OBJECT_TYPE_LOC, winning_loc,
	    NWAM_STATE_OFFLINE_TO_ONLINE, NWAM_AUX_STATE_METHOD_RUNNING);
}

int
nwamd_loc_action(const char *loc, nwam_action_t action)
{
	nwamd_event_t event = nwamd_event_init_object_action
	    (NWAM_OBJECT_TYPE_LOC, loc, NULL, action);
	if (event == NULL)
		return (1);
	nwamd_event_enqueue(event);
	return (0);
}

/*
 * Event handling functions.
 */

/* Handle loc initialization/refresh event */
void
nwamd_loc_handle_init_event(nwamd_event_t event)
{
	nwamd_object_t object;
	nwam_loc_handle_t loch;
	nwam_error_t err;
	boolean_t manual_disabled = B_FALSE;
	nwam_state_t state;

	if ((err = nwam_loc_read(event->event_object, 0, &loch))
	    != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_loc_handle_init_event: could not "
		    "read object '%s': %s", event->event_object,
		    nwam_strerror(err));
		nwamd_event_do_not_send(event);
		return;
	}
	if ((object = nwamd_object_find(NWAM_OBJECT_TYPE_LOC,
	    event->event_object)) != NULL) {
		nwam_loc_free(object->nwamd_object_handle);
		object->nwamd_object_handle = loch;
	} else {
		object = nwamd_object_init(NWAM_OBJECT_TYPE_LOC,
		    event->event_object, loch, NULL);
		object->nwamd_object_state = NWAM_STATE_OFFLINE;
		object->nwamd_object_aux_state =
		    NWAM_AUX_STATE_CONDITIONS_NOT_MET;
	}
	manual_disabled = (loc_get_activation_mode(loch) ==
	    NWAM_ACTIVATION_MODE_MANUAL && !loc_is_enabled(loch));
	state = object->nwamd_object_state;
	nwamd_object_release(object);

	/*
	 * If this location is ONLINE, and not manual and disabled (since in
	 * that case it was online but we've just set enabled = false as part
	 * of a disable action), then it is still active but refreshing.
	 * Change states to re-activate itself.
	 */
	if (!manual_disabled && state == NWAM_STATE_ONLINE) {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_LOC,
		    event->event_object, NWAM_STATE_OFFLINE_TO_ONLINE,
		    NWAM_AUX_STATE_METHOD_RUNNING);
	}
}

/* Handle loc finish event */
void
nwamd_loc_handle_fini_event(nwamd_event_t event)
{
	nwamd_object_t object;

	nlog(LOG_DEBUG, "nwamd_loc_handle_fini_event(%s)",
	    event->event_object);

	/* Don't disable the location, as this can enable the Automatic loc */
	if ((object = nwamd_object_find(NWAM_OBJECT_TYPE_LOC,
	    event->event_object)) == NULL) {
		nlog(LOG_ERR, "nwamd_loc_handle_fini_event: "
		    "loc %s not found", event->event_object);
		nwamd_event_do_not_send(event);
		return;
	}
	nwamd_object_release_and_destroy(object);
}

void
nwamd_loc_handle_action_event(nwamd_event_t event)
{
	nwamd_object_t object;

	switch (event->event_msg->nwe_data.nwe_object_action.nwe_action) {
	case NWAM_ACTION_ENABLE:
		object = nwamd_object_find(NWAM_OBJECT_TYPE_LOC,
		    event->event_object);
		if (object == NULL) {
			nlog(LOG_ERR, "nwamd_loc_handle_action_event: "
			    "could not find location %s", event->event_object);
			nwamd_event_do_not_send(event);
			return;
		}
		if (object->nwamd_object_state == NWAM_STATE_ONLINE) {
			nlog(LOG_DEBUG, "nwamd_loc_handle_action_event: "
			    "location %s already online, nothing to do",
			    event->event_object);
			nwamd_object_release(object);
			return;
		}
		nwamd_object_release(object);

		nwamd_object_set_state(NWAM_OBJECT_TYPE_LOC,
		    event->event_object, NWAM_STATE_OFFLINE_TO_ONLINE,
		    NWAM_AUX_STATE_METHOD_RUNNING);
		break;
	case NWAM_ACTION_DISABLE:
		object = nwamd_object_find(NWAM_OBJECT_TYPE_LOC,
		    event->event_object);
		if (object == NULL) {
			nlog(LOG_ERR, "nwamd_loc_handle_action_event: "
			    "could not find location %s", event->event_object);
			nwamd_event_do_not_send(event);
			return;
		}
		if (object->nwamd_object_state == NWAM_STATE_DISABLED) {
			nlog(LOG_DEBUG, "nwamd_loc_handle_action_event: "
			    "location %s already disabled, nothing to do",
			    event->event_object);
			nwamd_object_release(object);
			return;
		}
		nwamd_object_release(object);

		nwamd_object_set_state(NWAM_OBJECT_TYPE_LOC,
		    event->event_object, NWAM_STATE_ONLINE_TO_OFFLINE,
		    NWAM_AUX_STATE_MANUAL_DISABLE);
		break;
	case NWAM_ACTION_ADD:
	case NWAM_ACTION_REFRESH:
		nwamd_loc_handle_init_event(event);
		break;
	case NWAM_ACTION_DESTROY:
		nwamd_loc_handle_fini_event(event);
		break;
	default:
		nlog(LOG_INFO, "nwam_loc_handle_action_event: "
		    "unexpected action");
		break;
	}
}

void
nwamd_loc_handle_state_event(nwamd_event_t event)
{
	nwamd_object_t object;
	nwam_state_t new_state;
	nwam_aux_state_t new_aux_state;

	if ((object = nwamd_object_find(NWAM_OBJECT_TYPE_LOC,
	    event->event_object)) == NULL) {
		nlog(LOG_ERR, "nwamd_loc_handle_state_event: "
		    "state event for nonexistent loc %s", event->event_object);
		nwamd_event_do_not_send(event);
		return;
	}
	new_state = event->event_msg->nwe_data.nwe_object_state.nwe_state;
	new_aux_state =
	    event->event_msg->nwe_data.nwe_object_state.nwe_aux_state;

	if (new_state == object->nwamd_object_state &&
	    new_aux_state == object->nwamd_object_aux_state) {
		nlog(LOG_DEBUG, "nwamd_loc_handle_state_event: "
		    "loc %s already in state (%s , %s)",
		    object->nwamd_object_name,
		    nwam_state_to_string(new_state),
		    nwam_aux_state_to_string(new_aux_state));
		nwamd_object_release(object);
		return;
	}

	object->nwamd_object_state = new_state;
	object->nwamd_object_aux_state = new_aux_state;

	nlog(LOG_DEBUG, "nwamd_loc_handle_state_event: changing state for loc "
	    "%s to (%s , %s)", object->nwamd_object_name,
	    nwam_state_to_string(object->nwamd_object_state),
	    nwam_aux_state_to_string(object->nwamd_object_aux_state));

	nwamd_object_release(object);

	/*
	 * State machine for location.
	 */
	switch (new_state) {
	case NWAM_STATE_OFFLINE_TO_ONLINE:
		nwamd_loc_activate(event->event_object);
		break;
	case NWAM_STATE_ONLINE_TO_OFFLINE:
		/*
		 * Don't need to deactivate current location - condition check
		 * will activate another.
		 */
		nwamd_loc_check_conditions();
		break;
	case NWAM_STATE_DISABLED:
	case NWAM_STATE_OFFLINE:
	case NWAM_STATE_UNINITIALIZED:
	case NWAM_STATE_MAINTENANCE:
	case NWAM_STATE_DEGRADED:
	default:
		/* do nothing */
		break;
	}
}
