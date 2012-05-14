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

#include <auth_attr.h>
#include <auth_list.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <libnwam_priv.h>
#include <libuutil.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <sys/mman.h>
#include <syslog.h>
#include <unistd.h>

#include "conditions.h"
#include "events.h"
#include "ncp.h"
#include "ncu.h"
#include "objects.h"
#include "util.h"

/*
 * door_if.c
 * This file contains functions which implement the command interface to
 * nwam via the door NWAM_DOOR.  Doors provide a LPC mechanism that allows
 * for threads in one process to cause code to execute in another process.
 * Doors also provide the ability to pass data and file descriptors.  See
 * libdoor(3LIB) for more information.
 *
 * This file exports two functions, nwamd_door_initialize() (which sets up
 * the door) and nwamd_door_fini(), which removes it.
 *
 * It sets up the static routine nwamd_door_switch() to be called when a client
 * calls the door (via door_call(3C)).  The structure nwam_request_t is
 * passed as data and contains data to specify the type of action requested
 * and any data need to meet that request.  A table consisting of entries
 * for each door request, the associated authorization and the function to
 * process that request is used to handle the various requests.
 */

struct nwamd_door_req_entry
{
	int ndre_type;
	char *ndre_auth;
	nwam_error_t (*ndre_fn)(nwamd_door_arg_t *, ucred_t *, struct passwd *);
};

static nwam_error_t nwamd_door_req_event_register(nwamd_door_arg_t *,
	ucred_t *, struct passwd *);
static nwam_error_t nwamd_door_req_event_unregister(nwamd_door_arg_t *,
	ucred_t *, struct passwd *);
static nwam_error_t nwamd_door_req_wlan_scan(nwamd_door_arg_t *,
	ucred_t *, struct passwd *);
static nwam_error_t nwamd_door_req_wlan_scan_results(nwamd_door_arg_t *,
	ucred_t *, struct passwd *);
static nwam_error_t nwamd_door_req_wlan_select(nwamd_door_arg_t *,
	ucred_t *, struct passwd *);
static nwam_error_t nwamd_door_req_wlan_set_key(nwamd_door_arg_t *,
	ucred_t *, struct passwd *);
static nwam_error_t nwamd_door_req_action(nwamd_door_arg_t *,
	ucred_t *, struct passwd *);
static nwam_error_t nwamd_door_req_state(nwamd_door_arg_t *,
	ucred_t *, struct passwd *);
static nwam_error_t nwamd_door_req_priority_group(nwamd_door_arg_t *,
	ucred_t *, struct passwd *);

/*
 * This table defines the set of door commands available, the required
 * authorizations for each command, and the function that carries out
 * each command.
 */
struct nwamd_door_req_entry door_req_table[] =
{

	{ NWAM_REQUEST_TYPE_EVENT_REGISTER, AUTOCONF_READ_AUTH,
	nwamd_door_req_event_register },
	{ NWAM_REQUEST_TYPE_EVENT_UNREGISTER, AUTOCONF_READ_AUTH,
	nwamd_door_req_event_unregister },
	{ NWAM_REQUEST_TYPE_WLAN_SCAN, AUTOCONF_WLAN_AUTH,
	nwamd_door_req_wlan_scan },
	{ NWAM_REQUEST_TYPE_WLAN_SCAN_RESULTS, AUTOCONF_READ_AUTH,
	nwamd_door_req_wlan_scan_results },
	{ NWAM_REQUEST_TYPE_WLAN_SELECT, AUTOCONF_WLAN_AUTH,
	nwamd_door_req_wlan_select },
	{ NWAM_REQUEST_TYPE_WLAN_SET_KEY, AUTOCONF_WLAN_AUTH,
	nwamd_door_req_wlan_set_key },
	/* Requires WRITE, SELECT or WLAN auth depending on action */
	{ NWAM_REQUEST_TYPE_ACTION, NULL, nwamd_door_req_action },
	{ NWAM_REQUEST_TYPE_STATE, AUTOCONF_READ_AUTH,
	nwamd_door_req_state },
	{ NWAM_REQUEST_TYPE_PRIORITY_GROUP, AUTOCONF_READ_AUTH,
	nwamd_door_req_priority_group },
};

int doorfd = -1;

/* ARGSUSED */
static nwam_error_t
nwamd_door_req_event_register(nwamd_door_arg_t *req, ucred_t *ucr,
    struct passwd *pwd)
{
	nwam_error_t err;

	err = nwam_event_queue_init
	    (req->nwda_data.nwdad_register_info.nwdad_name);
	if (err != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_door_req_event_register: "
		    "could not register events for %s",
		    req->nwda_data.nwdad_register_info.nwdad_name);
	}

	return (err);
}

/* ARGSUSED */
static nwam_error_t
nwamd_door_req_event_unregister(nwamd_door_arg_t *req, ucred_t *ucr,
    struct passwd *pwd)
{
	nwam_event_queue_fini(req->nwda_data.nwdad_register_info.nwdad_name);

	return (NWAM_SUCCESS);
}

/* ARGSUSED1 */
static nwam_error_t
nwamd_door_req_wlan_scan(nwamd_door_arg_t *req, ucred_t *ucr,
    struct passwd *pwd)
{
	nlog(LOG_DEBUG,
	    "nwamd_door_req_wlan_scan: processing WLAN scan request: "
	    "link %s", req->nwda_data.nwdad_wlan_info.nwdad_name);

	return (nwamd_wlan_scan(req->nwda_data.nwdad_wlan_info.nwdad_name));
}

/* ARGSUSED */
static nwam_error_t
nwamd_door_req_wlan_scan_results(nwamd_door_arg_t *req, ucred_t *ucr,
    struct passwd *pwd)
{
	nwamd_object_t obj;
	nwamd_ncu_t *ncu;
	nwamd_link_t *link;
	uint_t num_wlans;

	nlog(LOG_DEBUG, "nwamd_door_req_wlan_scan_results: processing WLAN "
	    "scan results request: link %s",
	    req->nwda_data.nwdad_wlan_info.nwdad_name);

	obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_LINK,
	    req->nwda_data.nwdad_wlan_info.nwdad_name);
	if (obj == NULL) {
		nlog(LOG_ERR,
		    "nwamd_door_req_wlan_scan_results: link %s not found",
		    req->nwda_data.nwdad_wlan_info.nwdad_name);
		return (NWAM_ENTITY_NOT_FOUND);
	}

	ncu = obj->nwamd_object_data;
	link = &ncu->ncu_link;
	num_wlans = link->nwamd_link_wifi_scan.nwamd_wifi_scan_curr_num;

	if (num_wlans > 0) {
		(void) memcpy
		    (req->nwda_data.nwdad_wlan_info.nwdad_wlans,
		    link->nwamd_link_wifi_scan.nwamd_wifi_scan_curr,
		    num_wlans * sizeof (nwam_wlan_t));
	}
	req->nwda_data.nwdad_wlan_info.nwdad_num_wlans = num_wlans;
	nlog(LOG_DEBUG,
	    "nwamd_door_req_wlan_scan_results: returning %d scan results",
	    num_wlans);
	nwamd_object_release(obj);

	return (NWAM_SUCCESS);
}

/* ARGSUSED */
static nwam_error_t
nwamd_door_req_wlan_select(nwamd_door_arg_t *req, ucred_t *ucr,
    struct passwd *pwd)
{
	nlog(LOG_DEBUG,
	    "nwamd_door_req_wlan_select: processing WLAN selection : "
	    "link %s ESSID %s , BSSID %s",
	    req->nwda_data.nwdad_wlan_info.nwdad_name,
	    req->nwda_data.nwdad_wlan_info.nwdad_essid,
	    req->nwda_data.nwdad_wlan_info.nwdad_bssid);
	return (nwamd_wlan_select
	    (req->nwda_data.nwdad_wlan_info.nwdad_name,
	    req->nwda_data.nwdad_wlan_info.nwdad_essid,
	    req->nwda_data.nwdad_wlan_info.nwdad_bssid,
	    req->nwda_data.nwdad_wlan_info.nwdad_security_mode,
	    req->nwda_data.nwdad_wlan_info.nwdad_add_to_known_wlans));
}

/* ARGSUSED */
static nwam_error_t
nwamd_door_req_wlan_set_key(nwamd_door_arg_t *req, ucred_t *ucr,
    struct passwd *pwd)
{
	nlog(LOG_DEBUG,
	    "nwamd_door_req_wlan_set_key: processing WLAN key input : "
	    "link %s ESSID %s BSSID %s",
	    req->nwda_data.nwdad_wlan_info.nwdad_name,
	    req->nwda_data.nwdad_wlan_info.nwdad_essid,
	    req->nwda_data.nwdad_wlan_info.nwdad_bssid);
	return (nwamd_wlan_set_key
	    (req->nwda_data.nwdad_wlan_info.nwdad_name,
	    req->nwda_data.nwdad_wlan_info.nwdad_essid,
	    req->nwda_data.nwdad_wlan_info.nwdad_bssid,
	    req->nwda_data.nwdad_wlan_info.nwdad_security_mode,
	    req->nwda_data.nwdad_wlan_info.nwdad_keyslot,
	    req->nwda_data.nwdad_wlan_info.nwdad_key));
}

static nwam_error_t
nwamd_door_req_action(nwamd_door_arg_t *req, ucred_t *ucr, struct passwd *pwd)
{
	char name[NWAM_MAX_NAME_LEN];
	char parent[NWAM_MAX_NAME_LEN];
	nwam_action_t action = req->nwda_data.nwdad_object_action.nwdad_action;
	nwam_object_type_t object_type =
	    req->nwda_data.nwdad_object_action.nwdad_object_type;
	char *obj_type_str  = (char *)nwam_object_type_to_string(object_type);
	nwam_error_t err;

	/* Check for name, parent overrun */
	if (strlcpy(name, req->nwda_data.nwdad_object_action.nwdad_name,
	    sizeof (name)) == NWAM_MAX_NAME_LEN ||
	    strlcpy(parent, req->nwda_data.nwdad_object_action.nwdad_parent,
	    sizeof (parent)) == NWAM_MAX_NAME_LEN)
		return (NWAM_INVALID_ARG);

	/*
	 * Check authorizations against actions.
	 * - ENABLE/DISABLE requires SELECT auth
	 * - ADD/DESTROY/REFRESH on Known WLANs requires WLAN auth
	 * - ADD/DESTROY on other objects requires WRITE auth
	 * - REFRESH on other objects requires either WRITE or SELECT auth
	 */
	if (action == NWAM_ACTION_ENABLE || action == NWAM_ACTION_DISABLE) {
		if (chkauthattr(AUTOCONF_SELECT_AUTH, pwd->pw_name) == 0) {
			nwam_record_audit_event(ucr,
			    action == NWAM_ACTION_ENABLE ?
			    ADT_nwam_enable : ADT_nwam_disable, name,
			    obj_type_str, ADT_FAILURE, ADT_FAIL_VALUE_AUTH);
			nlog(LOG_ERR, "nwamd_door_req_action: "
			    "need %s for %s action", AUTOCONF_SELECT_AUTH,
			    nwam_action_to_string(action));
			return (NWAM_PERMISSION_DENIED);
		}
	} else if (object_type == NWAM_OBJECT_TYPE_KNOWN_WLAN) {
		if (chkauthattr(AUTOCONF_WLAN_AUTH, pwd->pw_name) == 0) {
			nlog(LOG_ERR, "nwamd_door_req_action: "
			    "need %s for %s action on Known WLAN",
			    AUTOCONF_WLAN_AUTH, nwam_action_to_string(action));
			return (NWAM_PERMISSION_DENIED);
		}
	} else if (action == NWAM_ACTION_ADD || action == NWAM_ACTION_DESTROY) {
		if (chkauthattr(AUTOCONF_WRITE_AUTH, pwd->pw_name) == 0) {
			nlog(LOG_ERR, "nwamd_door_req_action: "
			    "need %s for %s action", AUTOCONF_WRITE_AUTH,
			    nwam_action_to_string(action));
			return (NWAM_PERMISSION_DENIED);
		}
	} else if (action == NWAM_ACTION_REFRESH) {
		if (chkauthattr(AUTOCONF_WRITE_AUTH, pwd->pw_name) == 0 &&
		    chkauthattr(AUTOCONF_SELECT_AUTH, pwd->pw_name) == 0) {
			nlog(LOG_ERR, "nwamd_door_req_action: "
			    "need either %s or %s for %s action",
			    AUTOCONF_WRITE_AUTH, AUTOCONF_SELECT_AUTH,
			    nwam_action_to_string(action));
			return (NWAM_PERMISSION_DENIED);
		}
	} else {
		nlog(LOG_ERR, "nwamd_door_req_action: received unknown "
		    "action %d (%s)", action, nwam_action_to_string(action));
		return (NWAM_INVALID_ARG);
	}

	switch (action) {
	case NWAM_ACTION_ENABLE:
	case NWAM_ACTION_DISABLE:
		nwam_record_audit_event(ucr,
		    action == NWAM_ACTION_ENABLE ?
		    ADT_nwam_enable : ADT_nwam_disable, name,
		    obj_type_str, ADT_SUCCESS, ADT_SUCCESS);

		nlog(LOG_DEBUG, "nwamd_door_req_action: %s %s",
		    action == NWAM_ACTION_ENABLE ? "enabling" : "disabling",
		    name);

		switch (object_type) {
		case NWAM_OBJECT_TYPE_ENM:
			err = nwamd_enm_action(name, action);
			break;
		case NWAM_OBJECT_TYPE_LOC:
			err = nwamd_loc_action(name, action);
			break;
		case NWAM_OBJECT_TYPE_NCU:
			err = nwamd_ncu_action(name, parent, action);
			break;
		case NWAM_OBJECT_TYPE_NCP:
			if (action == NWAM_ACTION_DISABLE) {
				nlog(LOG_ERR, "nwamd_door_req_action: "
				    "NCPs cannot be disabled");
				err = NWAM_INVALID_ARG;
			} else {
				err = nwamd_ncp_action(name, action);
			}
			break;
		default:
			nlog(LOG_ERR, "nwamd_door_req_action: received invalid "
			    "object type %d (%s)", object_type,
			    nwam_object_type_to_string(object_type));
			return (NWAM_INVALID_ARG);
		}
		break;

	case NWAM_ACTION_ADD:
	case NWAM_ACTION_REFRESH:
		/*
		 * Called whenever an object is committed in the library.
		 * Reread that committed object into nwamd.
		 */
		nlog(LOG_DEBUG, "door_switch: refreshing %s", name);

		switch (object_type) {
		case NWAM_OBJECT_TYPE_ENM:
			err = nwamd_enm_action(name, action);
			break;
		case NWAM_OBJECT_TYPE_LOC:
			err = nwamd_loc_action(name, action);
			break;
		case NWAM_OBJECT_TYPE_KNOWN_WLAN:
			err = nwamd_known_wlan_action(name, action);
			break;
		case NWAM_OBJECT_TYPE_NCU:
			err = nwamd_ncu_action(name, parent, action);
			break;
		case NWAM_OBJECT_TYPE_NCP:
			err = nwamd_ncp_action(name, action);
			break;
		default:
			nlog(LOG_ERR, "nwamd_door_req_action: received invalid "
			    "object type %d (%s)", object_type,
			    nwam_object_type_to_string(object_type));
			err = NWAM_INVALID_ARG;
			break;
		}
		break;

	case NWAM_ACTION_DESTROY:
		/* Object was destroyed, remove from nwamd */
		nlog(LOG_DEBUG, "door_switch: removing %s", name);

		switch (object_type) {
		case NWAM_OBJECT_TYPE_ENM:
			err = nwamd_enm_action(name, NWAM_ACTION_DESTROY);
			break;
		case NWAM_OBJECT_TYPE_LOC:
			err = nwamd_loc_action(name, NWAM_ACTION_DESTROY);
			break;
		case NWAM_OBJECT_TYPE_KNOWN_WLAN:
			err = nwamd_known_wlan_action(name,
			    NWAM_ACTION_DESTROY);
			break;
		case NWAM_OBJECT_TYPE_NCU:
			err = nwamd_ncu_action(name, parent,
			    NWAM_ACTION_DESTROY);
			break;
		case NWAM_OBJECT_TYPE_NCP:
			(void) pthread_mutex_lock(&active_ncp_mutex);
			if (strcmp(name, active_ncp) == 0) {
				nlog(LOG_ERR, "nwamd_door_req_action: %s is "
				    "active, cannot destroy", parent);
				err = NWAM_ENTITY_IN_USE;
			} else {
				err = nwamd_ncp_action(name,
				    NWAM_ACTION_DESTROY);
			}
			(void) pthread_mutex_unlock(&active_ncp_mutex);
			break;
		default:
			nlog(LOG_ERR, "nwamd_door_req_action: received invalid "
			    "object type %d (%s)", object_type,
			    nwam_object_type_to_string(object_type));
			err = NWAM_INVALID_ARG;
			break;
		}
		break;

	default:
		nlog(LOG_ERR, "nwamd_door_req_action: received unknown "
		    "action %d (%s)", action, nwam_action_to_string(action));
		err = NWAM_INVALID_ARG;
		break;
	}

	if (err == NWAM_SUCCESS) {
		/*
		 * At this point, we've successfully carried out an action.
		 * Configuration may have changed, so we need to recheck
		 * conditions, however we want to avoid a flurry of condition
		 * check events, so we enqueue a triggered condition check
		 * if none is due in the next few seconds.
		 */
		nwamd_create_triggered_condition_check_event(NEXT_FEW_SECONDS);
	} else {
		nlog(LOG_ERR, "nwamd_door_req_action: could not carry out "
		    "%s action on %s: %s", nwam_action_to_string(action),
		    name, nwam_strerror(err));
	}

	return (err);
}

/* ARGSUSED */
static nwam_error_t
nwamd_door_req_state(nwamd_door_arg_t *req, ucred_t *ucr, struct passwd *pwd)
{
	char name[NWAM_MAX_NAME_LEN];
	nwamd_object_t obj;
	nwam_object_type_t object_type =
	    req->nwda_data.nwdad_object_state.nwdad_object_type;
	boolean_t is_active = B_FALSE;

	/* Check for name, parent overrun */
	if (strlcpy(name, req->nwda_data.nwdad_object_state.nwdad_name,
	    sizeof (name)) == NWAM_MAX_NAME_LEN)
		return (NWAM_INVALID_ARG);

	switch (object_type) {
	case NWAM_OBJECT_TYPE_NCP:
		(void) pthread_mutex_lock(&active_ncp_mutex);
		is_active = (strcmp(active_ncp, name) == 0);
		(void) pthread_mutex_unlock(&active_ncp_mutex);
		if (is_active) {
			req->nwda_data.nwdad_object_state.nwdad_state =
			    NWAM_STATE_ONLINE;
			req->nwda_data.nwdad_object_state.
			    nwdad_aux_state = NWAM_AUX_STATE_ACTIVE;
			nlog(LOG_DEBUG,
			    "nwamd_door_req_state: NCP %s is active", name);
		} else {
			req->nwda_data.nwdad_object_state.nwdad_state =
			    NWAM_STATE_DISABLED;
			req->nwda_data.nwdad_object_state.
			    nwdad_aux_state =
			    NWAM_AUX_STATE_MANUAL_DISABLE;
			nlog(LOG_DEBUG, "nwamd_door_req_state: "
			    "NCP %s is inactive", name);
		}
		break;

	case NWAM_OBJECT_TYPE_LOC:
	case NWAM_OBJECT_TYPE_NCU:
	case NWAM_OBJECT_TYPE_ENM:
		obj = nwamd_object_find(object_type, name);
		if (obj == NULL) {
			nlog(LOG_ERR, "nwamd_door_req_state: %s %s not found",
			    nwam_object_type_to_string(object_type), name);
			return (NWAM_ENTITY_NOT_FOUND);
		}
		nlog(LOG_DEBUG, "nwamd_door_req_state: %s %s is %s",
		    nwam_object_type_to_string(object_type), name,
		    nwam_state_to_string(obj->nwamd_object_state));
		req->nwda_data.nwdad_object_state.nwdad_state =
		    obj->nwamd_object_state;
		req->nwda_data.nwdad_object_state.nwdad_aux_state =
		    obj->nwamd_object_aux_state;
		nwamd_object_release(obj);
		break;

	default:
		nlog(LOG_ERR, "nwamd_door_req_state: received invalid "
		    "object type %d (%s)", object_type,
		    nwam_object_type_to_string(object_type));
		req->nwda_status = NWAM_REQUEST_STATUS_UNKNOWN;
		return (NWAM_INVALID_ARG);
	}

	return (NWAM_SUCCESS);
}

/* ARGSUSED */
static nwam_error_t
nwamd_door_req_priority_group(nwamd_door_arg_t *req, ucred_t *ucr,
    struct passwd *pwd)
{
	(void) pthread_mutex_lock(&active_ncp_mutex);
	nlog(LOG_DEBUG, "nwamd_door_req_priority_group: "
	    "retrieving active priority-group: %d",
	    current_ncu_priority_group);
	req->nwda_data.nwdad_priority_group_info.nwdad_priority =
	    current_ncu_priority_group;
	(void) pthread_mutex_unlock(&active_ncp_mutex);

	return (NWAM_SUCCESS);
}

/* ARGSUSED */
static void
nwamd_door_switch(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc)
{
	nwamd_door_arg_t *req;
	ucred_t *ucr = NULL;
	uid_t uid;
	struct passwd *pwd = NULL;
	boolean_t found = B_FALSE;
	int i;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	req = (nwamd_door_arg_t *)argp;
	req->nwda_error = NWAM_SUCCESS;

	if (door_ucred(&ucr) != 0) {
		nlog(LOG_ERR, "nwamd_door_switch: door_ucred failed: %s",
		    strerror(errno));
		req->nwda_error = NWAM_ERROR_INTERNAL;
		req->nwda_status = NWAM_REQUEST_STATUS_FAILED;
		goto done;
	}
	uid = ucred_getruid(ucr);

	if ((pwd = getpwuid(uid)) == NULL) {
		nlog(LOG_ERR, "nwamd_door_switch: getpwuid failed: %s",
		    strerror(errno));
		endpwent();
		req->nwda_error = NWAM_ERROR_INTERNAL;
		req->nwda_status = NWAM_REQUEST_STATUS_FAILED;
		goto done;
	}

	/*
	 * Find door request entry in table, check auths and call the function
	 * handling the request.
	 */
	for (i = 0;
	    i < sizeof (door_req_table) / sizeof (struct nwamd_door_req_entry);
	    i++) {
		if (req->nwda_type != door_req_table[i].ndre_type)
			continue;

		found = B_TRUE;

		if (door_req_table[i].ndre_auth != NULL &&
		    chkauthattr(door_req_table[i].ndre_auth,
		    pwd->pw_name) == 0) {
			nlog(LOG_ERR,
			    "nwamd_door_switch: need %s for request type %d",
			    door_req_table[i].ndre_auth, req->nwda_type);
			req->nwda_error = NWAM_PERMISSION_DENIED;
			break;
		}
		req->nwda_error = door_req_table[i].ndre_fn(req, ucr, pwd);
		break;
	}
	if (!found) {
		nlog(LOG_ERR,
		    "nwamd_door_switch: received unknown request type %d",
		    req->nwda_type);
		req->nwda_status = NWAM_REQUEST_STATUS_UNKNOWN;
	} else {
		if (req->nwda_error == NWAM_SUCCESS)
			req->nwda_status = NWAM_REQUEST_STATUS_OK;
		else
			req->nwda_status = NWAM_REQUEST_STATUS_FAILED;
	}

done:
	ucred_free(ucr);
	endpwent();

	if (door_return((char *)req, sizeof (nwamd_door_arg_t), NULL, 0)
	    == -1) {
		nlog(LOG_ERR, "door_switch: type %d door_return failed: %s",
		    req->nwda_type, strerror(errno));
	}
}

/*
 * We initialize the nwamd door here.  Failure to have this happen is critical
 * to the daemon so we log a message and pass up notice to the caller who
 * will most likely abort trying to start.  This routine is meant to only
 * be called once.
 */
void
nwamd_door_init(void)
{
	const int door_mode = 0644;
	struct stat buf;

	if ((doorfd = door_create(nwamd_door_switch, NULL,
	    DOOR_NO_CANCEL | DOOR_REFUSE_DESC)) == -1)
		pfail("Unable to create door: %s", strerror(errno));

	if (stat(NWAM_DOOR, &buf) < 0) {
		int nwam_door_fd;

		if ((nwam_door_fd = creat(NWAM_DOOR, door_mode)) < 0) {
			int err = errno;
			(void) door_revoke(doorfd);
			doorfd = -1;
			pfail("Couldn't create door: %s", strerror(err));
		}
		(void) close(nwam_door_fd);
	} else {
		if (buf.st_mode != door_mode) {
			if (chmod(NWAM_DOOR, door_mode) == -1) {
				nlog(LOG_ERR, "couldn't change mode of %s: %s",
				    NWAM_DOOR, strerror(errno));
			}
		}
	}
	/* cleanup anything hanging around from a previous invocation */
	(void) fdetach(NWAM_DOOR);

	/* Place our door in the file system so that others can find us. */
	if (fattach(doorfd, NWAM_DOOR) < 0) {
		int err = errno;
		(void) door_revoke(doorfd);
		doorfd = -1;
		pfail("Couldn't attach door: %s", strerror(err));
	}
}

void
nwamd_door_fini(void)
{
	if (doorfd != -1) {
		nlog(LOG_DEBUG, "nwamd_door_fini: closing door");
		(void) door_revoke(doorfd);
		doorfd = -1;
	}
	(void) unlink(NWAM_DOOR);
}
