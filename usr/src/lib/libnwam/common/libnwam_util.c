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
#include <atomic.h>
#include <ctype.h>
#include <errno.h>
#include <inet/ip.h>
#include <libintl.h>
#include <libproc.h>
#include <libscf.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "libnwam_impl.h"
#include <libnwam_priv.h>
#include <libnwam.h>

/*
 * Utility functions for door access, common validation functions etc.
 */

pthread_mutex_t door_mutex = PTHREAD_MUTEX_INITIALIZER;
int nwam_door_fd = -1;

static int
open_door(const char *door_name, int *door_fdp)
{
	struct door_info dinfo;
	int err = 0;

	(void) pthread_mutex_lock(&door_mutex);

	if (*door_fdp != -1) {
		/* Check door fd is not old (from previous nwamd). */
		if (door_info(*door_fdp, &dinfo) != 0 ||
		    (dinfo.di_attributes & DOOR_REVOKED) != 0) {
			(void) close(*door_fdp);
			*door_fdp = -1;
		}
	}
	if (*door_fdp == -1) {
		*door_fdp = open(door_name, 0);
		if (*door_fdp == -1)
			err = errno;
	}

	(void) pthread_mutex_unlock(&door_mutex);

	return (err);
}

int
nwam_make_door_call(const char *door_name, int *door_fdp,
    void *request, size_t request_size)
{
	int err;
	door_arg_t door_args;

	door_args.data_ptr = (void *)request;
	door_args.data_size = request_size;
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = (void *)request;
	door_args.rsize = request_size;

	if ((err = open_door(door_name, door_fdp)) != 0)
		return (err);

	if (door_call(*door_fdp, &door_args) == -1)
		return (errno);

	return (0);
}

static nwam_error_t
send_msg_to_nwam(nwamd_door_arg_t *request)
{
	int err;

	if ((err = nwam_make_door_call(NWAM_DOOR, &nwam_door_fd,
	    request, sizeof (nwamd_door_arg_t))) != 0) {
		if (err == ENOENT)
			return (NWAM_ERROR_BIND);
		return (nwam_errno_to_nwam_error(err));
	}

	switch (request->nwda_status) {
	case NWAM_REQUEST_STATUS_OK:
		return (NWAM_SUCCESS);
	case NWAM_REQUEST_STATUS_UNKNOWN:
		return (NWAM_INVALID_ARG);
	case NWAM_REQUEST_STATUS_ALREADY:
		return (NWAM_ENTITY_IN_USE);
	case NWAM_REQUEST_STATUS_FAILED:
		return (request->nwda_error);
	default:
		return (NWAM_ERROR_INTERNAL);
	}
}

nwam_error_t
nwam_request_register_unregister(nwam_request_type_t type,
    const char *event_msg_file)
{
	nwamd_door_arg_t req;

	req.nwda_type = type;

	(void) strlcpy(req.nwda_data.nwdad_register_info.nwdad_name,
	    event_msg_file,
	    sizeof (req.nwda_data.nwdad_register_info.nwdad_name));

	return (send_msg_to_nwam(&req));
}

nwam_error_t
nwam_request_action(nwam_object_type_t object_type,
    const char *name, const char *parent, nwam_action_t action)
{
	nwamd_door_arg_t req;

	assert(name != NULL);

	req.nwda_type = NWAM_REQUEST_TYPE_ACTION;
	req.nwda_data.nwdad_object_action.nwdad_object_type = object_type;
	req.nwda_data.nwdad_object_action.nwdad_action = action;
	(void) strlcpy(req.nwda_data.nwdad_object_action.nwdad_name, name,
	    sizeof (req.nwda_data.nwdad_object_action.nwdad_name));
	if (parent != NULL) {
		(void) strlcpy(req.nwda_data.nwdad_object_action.nwdad_parent,
		    parent,
		    sizeof (req.nwda_data.nwdad_object_action.nwdad_parent));
	} else {
		req.nwda_data.nwdad_object_action.nwdad_parent[0] = '\0';
	}

	return (send_msg_to_nwam(&req));
}

nwam_error_t
nwam_request_state(nwam_object_type_t object_type, const char *name,
    const char *parent, nwam_state_t *statep, nwam_aux_state_t *auxp)
{
	nwamd_door_arg_t req;
	nwam_error_t err;

	assert(name != NULL && statep != NULL && auxp != NULL);

	req.nwda_type = NWAM_REQUEST_TYPE_STATE;

	req.nwda_data.nwdad_object_state.nwdad_object_type = object_type;

	(void) strlcpy(req.nwda_data.nwdad_object_state.nwdad_name, name,
	    sizeof (req.nwda_data.nwdad_object_state.nwdad_name));
	if (parent != NULL) {
		(void) strlcpy(req.nwda_data.nwdad_object_state.nwdad_parent,
		    parent,
		    sizeof (req.nwda_data.nwdad_object_state.nwdad_parent));
	}

	err = send_msg_to_nwam(&req);

	if (err == NWAM_SUCCESS) {
		*statep = req.nwda_data.nwdad_object_state.nwdad_state;
		*auxp = req.nwda_data.nwdad_object_state.nwdad_aux_state;
	}

	return (err);
}

nwam_error_t
nwam_request_wlan(nwam_request_type_t type, const char *name,
    const char *essid, const char *bssid, uint32_t security_mode,
    uint_t keyslot, const char *key, boolean_t add_to_known_wlans)
{
	nwamd_door_arg_t req;

	assert(name != NULL);

	req.nwda_type = type;

	(void) strlcpy(req.nwda_data.nwdad_wlan_info.nwdad_name, name,
	    sizeof (req.nwda_data.nwdad_wlan_info));
	if (essid != NULL) {
		(void) strlcpy(req.nwda_data.nwdad_wlan_info.nwdad_essid, essid,
		    sizeof (req.nwda_data.nwdad_wlan_info.nwdad_essid));
	} else {
		req.nwda_data.nwdad_wlan_info.nwdad_essid[0] = '\0';
	}
	if (bssid != NULL) {
		(void) strlcpy(req.nwda_data.nwdad_wlan_info.nwdad_bssid, bssid,
		    sizeof (req.nwda_data.nwdad_wlan_info.nwdad_bssid));
	} else {
		req.nwda_data.nwdad_wlan_info.nwdad_bssid[0] = '\0';
	}
	if (key != NULL) {
		(void) strlcpy(req.nwda_data.nwdad_wlan_info.nwdad_key, key,
		    sizeof (req.nwda_data.nwdad_wlan_info.nwdad_key));
		req.nwda_data.nwdad_wlan_info.nwdad_keyslot = keyslot;
	} else {
		req.nwda_data.nwdad_wlan_info.nwdad_key[0] = '\0';
	}

	req.nwda_data.nwdad_wlan_info.nwdad_security_mode = security_mode;
	req.nwda_data.nwdad_wlan_info.nwdad_add_to_known_wlans =
	    add_to_known_wlans;

	return (send_msg_to_nwam(&req));
}

nwam_error_t
nwam_request_wlan_scan_results(const char *name, uint_t *num_wlansp,
    nwam_wlan_t **wlansp)
{
	nwamd_door_arg_t req;
	nwam_error_t err;

	assert(name != NULL && num_wlansp != NULL && wlansp != NULL);

	req.nwda_type = NWAM_REQUEST_TYPE_WLAN_SCAN_RESULTS;

	(void) strlcpy(req.nwda_data.nwdad_wlan_info.nwdad_name, name,
	    sizeof (req.nwda_data.nwdad_wlan_info.nwdad_name));

	if ((err = send_msg_to_nwam(&req)) != NWAM_SUCCESS)
		return (err);

	*num_wlansp = req.nwda_data.nwdad_wlan_info.nwdad_num_wlans;

	*wlansp = calloc(*num_wlansp, sizeof (nwam_wlan_t));
	if (*wlansp == NULL)
		return (NWAM_NO_MEMORY);

	(void) memcpy(*wlansp, req.nwda_data.nwdad_wlan_info.nwdad_wlans,
	    *num_wlansp * sizeof (nwam_wlan_t));

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_request_active_priority_group(int64_t *priorityp)
{
	nwamd_door_arg_t req;
	nwam_error_t err;

	assert(priorityp != NULL);

	req.nwda_type = NWAM_REQUEST_TYPE_PRIORITY_GROUP;
	err = send_msg_to_nwam(&req);

	if (err == NWAM_SUCCESS)
		*priorityp =
		    req.nwda_data.nwdad_priority_group_info.nwdad_priority;

	return (err);
}

/* String conversion functions */

const char *
nwam_value_type_to_string(nwam_value_type_t type)
{
	switch (type) {
	case NWAM_VALUE_TYPE_BOOLEAN:
		return ("boolean");
	case NWAM_VALUE_TYPE_INT64:
		return ("int64");
	case NWAM_VALUE_TYPE_UINT64:
		return ("uint64");
	case NWAM_VALUE_TYPE_STRING:
		return ("string");
	default:
		return ("unknown");
	}
}

nwam_value_type_t
nwam_string_to_value_type(const char *typestr)
{
	if (strncmp(typestr, nwam_value_type_to_string(NWAM_VALUE_TYPE_BOOLEAN),
	    strlen(typestr)) == 0)
		return (NWAM_VALUE_TYPE_BOOLEAN);
	if (strncmp(typestr, nwam_value_type_to_string(NWAM_VALUE_TYPE_INT64),
	    strlen(typestr)) == 0)
		return (NWAM_VALUE_TYPE_INT64);
	if (strncmp(typestr, nwam_value_type_to_string(NWAM_VALUE_TYPE_UINT64),
	    strlen(typestr)) == 0)
		return (NWAM_VALUE_TYPE_UINT64);
	if (strncmp(typestr, nwam_value_type_to_string(NWAM_VALUE_TYPE_STRING),
	    strlen(typestr)) == 0)
		return (NWAM_VALUE_TYPE_STRING);
	return (NWAM_VALUE_TYPE_UNKNOWN);
}

const char *
nwam_action_to_string(nwam_action_t action)
{
	switch (action) {
	case NWAM_ACTION_ADD:
		return ("add");
	case NWAM_ACTION_REMOVE:
		return ("remove");
	case NWAM_ACTION_REFRESH:
		return ("refresh");
	case NWAM_ACTION_ENABLE:
		return ("enable");
	case NWAM_ACTION_DISABLE:
		return ("disable");
	case NWAM_ACTION_DESTROY:
		return ("destroy");
	default:
		return ("unknown");
	}
}

const char *
nwam_event_type_to_string(int event_type)
{
	switch (event_type) {
	case NWAM_EVENT_TYPE_NOOP:
		return ("NOOP");
	case NWAM_EVENT_TYPE_INIT:
		return ("INIT");
	case NWAM_EVENT_TYPE_SHUTDOWN:
		return ("SHUTDOWN");
	case NWAM_EVENT_TYPE_OBJECT_ACTION:
		return ("OBJECT_ACTION");
	case NWAM_EVENT_TYPE_OBJECT_STATE:
		return ("OBJECT_STATE");
	case NWAM_EVENT_TYPE_PRIORITY_GROUP:
		return ("PRIORITY_GROUP");
	case NWAM_EVENT_TYPE_INFO:
		return ("INFO");
	case NWAM_EVENT_TYPE_WLAN_SCAN_REPORT:
		return ("WLAN_SCAN_REPORT");
	case NWAM_EVENT_TYPE_WLAN_NEED_CHOICE:
		return ("WLAN_NEED_CHOICE");
	case NWAM_EVENT_TYPE_WLAN_NEED_KEY:
		return ("WLAN_NEED_KEY");
	case NWAM_EVENT_TYPE_WLAN_CONNECTION_REPORT:
		return ("WLAN_CONNECTION_REPORT");
	case NWAM_EVENT_TYPE_IF_ACTION:
		return ("IF_ACTION");
	case NWAM_EVENT_TYPE_IF_STATE:
		return ("IF_STATE");
	case NWAM_EVENT_TYPE_LINK_ACTION:
		return ("LINK_ACTION");
	case NWAM_EVENT_TYPE_LINK_STATE:
		return ("LINK_STATE");
	default:
		return ("UNKNOWN");
	}
}

const char *
nwam_state_to_string(nwam_state_t state)
{
	switch (state) {
	case NWAM_STATE_UNINITIALIZED:
		return ("uninitialized");
	case NWAM_STATE_INITIALIZED:
		return ("initialized");
	case NWAM_STATE_OFFLINE:
		return ("offline");
	case NWAM_STATE_OFFLINE_TO_ONLINE:
		return ("offline*");
	case NWAM_STATE_ONLINE_TO_OFFLINE:
		return ("online*");
	case NWAM_STATE_ONLINE:
		return ("online");
	case NWAM_STATE_MAINTENANCE:
		return ("maintenance");
	case NWAM_STATE_DEGRADED:
		return ("degraded");
	case NWAM_STATE_DISABLED:
		return ("disabled");
	default:
		return ("unknown");
	}
}

const char *
nwam_aux_state_to_string(nwam_aux_state_t aux_state)
{
	switch (aux_state) {
	case NWAM_AUX_STATE_UNINITIALIZED:
		return ("uninitialized");
	case NWAM_AUX_STATE_INITIALIZED:
		return ("(re)initialized but not configured");
	case NWAM_AUX_STATE_CONDITIONS_NOT_MET:
		return ("conditions for activation are unmet");
	case NWAM_AUX_STATE_MANUAL_DISABLE:
		return ("disabled by administrator");
	case NWAM_AUX_STATE_METHOD_FAILED:
		return ("method/service failed");
	case NWAM_AUX_STATE_METHOD_MISSING:
		return ("method or FMRI not specified");
	case NWAM_AUX_STATE_INVALID_CONFIG:
		return ("invalid configuration values");
	case NWAM_AUX_STATE_METHOD_RUNNING:
		return ("method/service executing");
	case NWAM_AUX_STATE_ACTIVE:
		return ("active");
	case NWAM_AUX_STATE_LINK_WIFI_SCANNING:
		return ("scanning for WiFi networks");
	case NWAM_AUX_STATE_LINK_WIFI_NEED_SELECTION:
		return ("need WiFi network selection");
	case NWAM_AUX_STATE_LINK_WIFI_NEED_KEY:
		return ("need WiFi security key");
	case NWAM_AUX_STATE_LINK_WIFI_CONNECTING:
		return ("connecting to WiFi network");
	case NWAM_AUX_STATE_IF_WAITING_FOR_ADDR:
		return ("waiting for IP address to be set");
	case NWAM_AUX_STATE_IF_DHCP_TIMED_OUT:
		return ("DHCP wait timeout, still trying...");
	case NWAM_AUX_STATE_IF_DUPLICATE_ADDR:
		return ("duplicate address detected");
	case NWAM_AUX_STATE_UP:
		return ("interface/link is up");
	case NWAM_AUX_STATE_DOWN:
		return ("interface/link is down");
	case NWAM_AUX_STATE_NOT_FOUND:
		return ("interface/link not found");
	default:
		return ("unknown");
	}
}

const char *
nwam_object_type_to_string(nwam_object_type_t type)
{
	switch (type) {
	case NWAM_OBJECT_TYPE_NCP:
		return ("ncp");
	case NWAM_OBJECT_TYPE_NCU:
		return ("ncu");
	case NWAM_OBJECT_TYPE_LOC:
		return ("loc");
	case NWAM_OBJECT_TYPE_ENM:
		return ("enm");
	case NWAM_OBJECT_TYPE_KNOWN_WLAN:
		return ("known wlan");
	default:
		return ("unknown");
	}
}

nwam_object_type_t
nwam_string_to_object_type(const char *typestr)
{
	if (strcasecmp(typestr,
	    nwam_object_type_to_string(NWAM_OBJECT_TYPE_NCP)) == 0)
		return (NWAM_OBJECT_TYPE_NCP);
	if (strcasecmp(typestr,
	    nwam_object_type_to_string(NWAM_OBJECT_TYPE_NCU)) == 0)
		return (NWAM_OBJECT_TYPE_NCU);
	if (strcasecmp(typestr,
	    nwam_object_type_to_string(NWAM_OBJECT_TYPE_LOC)) == 0)
		return (NWAM_OBJECT_TYPE_LOC);
	if (strcasecmp(typestr,
	    nwam_object_type_to_string(NWAM_OBJECT_TYPE_ENM)) == 0)
		return (NWAM_OBJECT_TYPE_ENM);
	if (strcasecmp(typestr,
	    nwam_object_type_to_string(NWAM_OBJECT_TYPE_KNOWN_WLAN)) == 0)
		return (NWAM_OBJECT_TYPE_KNOWN_WLAN);
	return (NWAM_OBJECT_TYPE_UNKNOWN);
}

nwam_error_t
nwam_errno_to_nwam_error(int errnum)
{
	switch (errnum) {
	case 0:
		return (NWAM_SUCCESS);
	case EBADF:
		return (NWAM_ERROR_BIND);
	case EPERM:
	case EACCES:
		return (NWAM_PERMISSION_DENIED);
	case ENOENT:
		return (NWAM_ENTITY_NOT_FOUND);
	case EIDRM:
		return (NWAM_ENTITY_INVALID);
	case EEXIST:
		return (NWAM_ENTITY_EXISTS);
	case EAGAIN:
	case EBUSY:
		return (NWAM_ENTITY_IN_USE);
	case ENOMEM:
	case ENOSPC:
		return (NWAM_NO_MEMORY);
	case EINVAL:
	case E2BIG:
		return (NWAM_INVALID_ARG);
	default:
		return (NWAM_ERROR_INTERNAL);
	}
}

/* Common validation functions */

/*
 * Do the flags represent a subset of valid_flags?
 */
nwam_error_t
nwam_valid_flags(uint64_t flags, uint64_t valid_flags)
{

	if ((flags | valid_flags) != valid_flags)
		return (NWAM_INVALID_ARG);
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_valid_condition(nwam_value_t value)
{
	char **conditions;
	uint_t i, numvalues;
	nwam_condition_object_type_t object_type;
	nwam_condition_t condition;

	if (nwam_value_get_string_array(value, &conditions, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		char *object_name = NULL;

		if (nwam_condition_string_to_condition(conditions[i],
		    &object_type, &condition, &object_name) != NWAM_SUCCESS)
			return (NWAM_ENTITY_INVALID_VALUE);
		if (object_name != NULL)
			free(object_name);
	}
	return (NWAM_SUCCESS);
}

/* check if boolean values are correct, generalize for array of booleans */
nwam_error_t
nwam_valid_boolean(nwam_value_t value)
{
	boolean_t *val;
	uint_t i, numvalues;

	if (nwam_value_get_boolean_array(value, &val, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		if (val[i] != B_TRUE && val[i] != B_FALSE)
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_SUCCESS);
}

/* check if uint64 values are correct, generalize for array of ints */
nwam_error_t
nwam_valid_uint64(nwam_value_t value)
{
	int64_t *val;
	uint_t i, numvalues;

	if (nwam_value_get_int64_array(value, &val, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		if (val[i] < 0)
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_SUCCESS);
}

/* check if domain names are correct, generalize for array of domains */
nwam_error_t
nwam_valid_domain(nwam_value_t value)
{
	char **domainvalues, *domain;
	uint_t i, numvalues;
	int len, j;

	if (nwam_value_get_string_array(value, &domainvalues, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		/*
		 * First and last character must be alphanumeric.
		 * Only '.' and '-' are allowed.
		 */
		domain = domainvalues[i];
		len = strlen(domain);
		if (!isalnum(domain[0]) || !isalnum(domain[len-1]))
			return (NWAM_ENTITY_INVALID_VALUE);
		for (j = 0; j < len; j++) {
			if (!isalnum(domain[j]) &&
			    domain[j] != '.' && domain[j] != '-')
				return (NWAM_ENTITY_INVALID_VALUE);
		}
	}
	return (NWAM_SUCCESS);
}

/* check if address prefix is valid */
static nwam_error_t
nwam_valid_prefix(char *addr, int max_plen)
{
	char *prefix, *end;
	int prefixlen;

	if ((prefix = strchr(addr, '/')) != NULL) {
		prefix++;
		prefixlen = strtol(prefix, &end, 10);
		if (prefix == end || prefixlen < 0 || prefixlen > max_plen)
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_SUCCESS);
}

/* check if IPv4 addresses are correct, generalize for array of addresses */
nwam_error_t
nwam_valid_host_v4(nwam_value_t value)
{
	char **addrvalues, *addr;
	uint_t i, numvalues;
	struct sockaddr_in sa;

	if (nwam_value_get_string_array(value, &addrvalues, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		addr = strdup(addrvalues[i]);
		if (nwam_valid_prefix(addr, IP_ABITS) != NWAM_SUCCESS) {
			free(addr);
			return (NWAM_ENTITY_INVALID_VALUE);
		}
		/* replace '/' with '\0' */
		addr = strsep(&addr, "/");
		if (inet_pton(AF_INET, addr, &(sa.sin_addr)) != 1) {
			free(addr);
			return (NWAM_ENTITY_INVALID_VALUE);
		}
		free(addr);
	}
	return (NWAM_SUCCESS);
}

/* Check if IPv4 address for default route is valid */
nwam_error_t
nwam_valid_route_v4(nwam_value_t value)
{
	char *addrvalue;
	struct sockaddr_in sa;

	if (nwam_value_get_string(value, &addrvalue) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	if (inet_pton(AF_INET, addrvalue, &(sa.sin_addr)) != 1)
		return (NWAM_ENTITY_INVALID_VALUE);

	return (NWAM_SUCCESS);
}

/* check if IPv6 addresses are correct, generalize for array of addresses */
nwam_error_t
nwam_valid_host_v6(nwam_value_t value)
{
	char **addrvalues, *addr;
	uint_t i, numvalues;
	struct sockaddr_in6 sa;

	if (nwam_value_get_string_array(value, &addrvalues, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		addr = strdup(addrvalues[i]);
		if (nwam_valid_prefix(addr, IPV6_ABITS) != NWAM_SUCCESS) {
			free(addr);
			return (NWAM_ENTITY_INVALID_VALUE);
		}
		/* replace '/' with '\0' */
		addr = strsep(&addr, "/");
		if (inet_pton(AF_INET6, addr, &(sa.sin6_addr)) != 1) {
			free(addr);
			return (NWAM_ENTITY_INVALID_VALUE);
		}
		free(addr);
	}
	return (NWAM_SUCCESS);
}

/* Check if IPv4 address for default route is valid */
nwam_error_t
nwam_valid_route_v6(nwam_value_t value)
{
	char *addrvalue;
	struct sockaddr_in6 sa;

	if (nwam_value_get_string(value, &addrvalue) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	if (inet_pton(AF_INET6, addrvalue, &(sa.sin6_addr)) != 1)
		return (NWAM_ENTITY_INVALID_VALUE);

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_valid_host_any(nwam_value_t value)
{
	if (nwam_valid_host_v4(value) != NWAM_SUCCESS &&
	    nwam_valid_host_v6(value) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_valid_host_or_domain(nwam_value_t value)
{
	if (nwam_valid_host_any(value) != NWAM_SUCCESS &&
	    nwam_valid_domain(value) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);
	return (NWAM_SUCCESS);
}

/* We do not validate file existence, merely that it is an absolute path. */
nwam_error_t
nwam_valid_file(nwam_value_t value)
{
	char **files;
	uint_t i, numvalues;

	if (nwam_value_get_string_array(value, &files, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		int j = 0;
		while (isspace(files[i][j]))
			j++;
		if (files[i][j] != '/')
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_SUCCESS);
}

/*
 * We do not validate existence of the object pointed to by the FMRI
 * but merely ensure that it is a valid FMRI.  We do this by
 * using scf_handle_decode_fmri(), but ignore all errors bar
 * SCF_ERROR_INVALID_ARGUMENT (which indicates the FMRI is invalid).
 */
nwam_error_t
nwam_valid_fmri(nwam_value_t value)
{
	char **valstr;
	scf_handle_t *h = NULL;
	scf_service_t *svc = NULL;
	uint_t i, numvalues;
	nwam_error_t err = NWAM_SUCCESS;

	if ((err = nwam_value_get_string_array(value, &valstr, &numvalues))
	    != NWAM_SUCCESS)
		return (err);

	h = scf_handle_create(SCF_VERSION);
	if (h == NULL)
		return (NWAM_ERROR_INTERNAL);

	if (scf_handle_bind(h) != 0) {
		err = NWAM_ERROR_INTERNAL;
		goto out;
	}

	if ((svc = scf_service_create(h)) == NULL) {
		err = NWAM_ERROR_INTERNAL;
		goto out;
	}


	for (i = 0; i < numvalues; i++) {
		if (scf_handle_decode_fmri(h, valstr[i], NULL, svc,
		    NULL, NULL, NULL, SCF_DECODE_FMRI_TRUNCATE) == 0 ||
		    scf_error() != SCF_ERROR_INVALID_ARGUMENT) {
			err = NWAM_SUCCESS;
			continue;
		}
		err = NWAM_ENTITY_INVALID_VALUE;
		break;
	}
out:
	scf_service_destroy(svc);
	scf_handle_destroy(h);
	return (err);
}

/* verifies mac-address and bssids */
nwam_error_t
nwam_valid_mac_addr(nwam_value_t value)
{
	char **mac_addrs, *addr;
	uchar_t	*hwaddr;
	int hwaddrlen, j;
	uint_t i, numvalues;

	if (nwam_value_get_string_array(value, &mac_addrs, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		addr = mac_addrs[i];
		j = 0;

		/* validate that a-fA-F0-9 and ':' only */
		while (addr[j] != 0) {
			if (!isxdigit(addr[j]) && addr[j] != ':')
				return (NWAM_ENTITY_INVALID_VALUE);
			j++;
		}

		if ((hwaddr = _link_aton(addr, &hwaddrlen)) == NULL)
			return (NWAM_ENTITY_INVALID_VALUE);
		free(hwaddr);
	}

	return (NWAM_SUCCESS);
}

boolean_t
nwam_uid_is_netadm(void)
{
	return (getuid() == UID_NETADM);
}

nwam_error_t
nwam_get_smf_string_property(const char *fmri, const char *pgname,
    const char *propname, char **valuep)
{
	scf_handle_t *h = NULL;
	scf_snapshot_t *snap = NULL;
	scf_instance_t *inst = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	nwam_error_t err = NWAM_SUCCESS;

	if ((*valuep = malloc(NWAM_MAX_NAME_LEN)) == NULL)
		return (NWAM_NO_MEMORY);

	if ((h = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(h) != 0 ||
	    (inst = scf_instance_create(h)) == NULL ||
	    (snap = scf_snapshot_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL) {
		err = NWAM_ERROR_INTERNAL;
		goto out;
	}
	if (scf_handle_decode_fmri(h, fmri, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0) {
		err = NWAM_ENTITY_NOT_FOUND;
		goto out;
	}
	/* Retrieve value from running snapshot (if present) */
	if (scf_instance_get_snapshot(inst, "running", snap) != 0) {
		scf_snapshot_destroy(snap);
		snap = NULL;
	}
	if (scf_instance_get_pg_composed(inst, snap, pgname, pg) != 0 ||
	    scf_pg_get_property(pg, propname, prop) != 0 ||
	    scf_property_get_value(prop, val) != 0 ||
	    scf_value_get_astring(val, *valuep, NWAM_MAX_NAME_LEN) == -1) {
		err = NWAM_ENTITY_NOT_FOUND;
	}
out:
	if (err != NWAM_SUCCESS)
		free(*valuep);

	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	if (snap != NULL)
		scf_snapshot_destroy(snap);
	scf_instance_destroy(inst);
	scf_handle_destroy(h);

	return (err);
}

nwam_error_t
nwam_set_smf_string_property(const char *fmri, const char *pgname,
    const char *propname, const char *propval)
{
	scf_handle_t *h = NULL;
	scf_instance_t *inst = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	scf_transaction_t *tx = NULL;
	scf_transaction_entry_t *ent = NULL;
	nwam_error_t err = NWAM_SUCCESS;
	int result;

	if ((h = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(h) != 0 ||
	    (inst = scf_instance_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL ||
	    scf_value_set_astring(val, propval) != 0 ||
	    (tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL) {
		err = NWAM_ERROR_INTERNAL;
		goto out;
	}
	if (scf_handle_decode_fmri(h, fmri, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0 ||
	    scf_instance_get_pg_composed(inst, NULL, pgname, pg) != 0) {
		err = NWAM_ENTITY_NOT_FOUND;
		goto out;
	}

retry:
	if (scf_transaction_start(tx, pg) == -1 ||
	    scf_transaction_property_change(tx, ent, propname, SCF_TYPE_ASTRING)
	    == -1 || scf_entry_add_value(ent, val) != 0) {
		err = NWAM_ERROR_INTERNAL;
		goto out;
	}

	result = scf_transaction_commit(tx);
	switch (result) {
	case 1:
		(void) smf_refresh_instance(fmri);
		break;
	case 0:
		scf_transaction_reset(tx);
		if (scf_pg_update(pg) == -1) {
			err = NWAM_ERROR_INTERNAL;
			goto out;
		}
		goto retry;
	default:
		err = NWAM_ERROR_INTERNAL;
		break;
	}
out:
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_instance_destroy(inst);
	scf_handle_destroy(h);

	return (err);
}
