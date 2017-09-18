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
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <libdlaggr.h>
#include <libdllink.h>
#include <libdlstat.h>
#include <libnwam.h>
#include <libscf.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <values.h>
#include <zone.h>

#include "conditions.h"
#include "events.h"
#include "objects.h"
#include "ncp.h"
#include "util.h"

/*
 * ncu.c - handles various NCU tasks - intialization/refresh, state machine
 * for NCUs etc.
 */

#define	VBOX_IFACE_PREFIX	"vboxnet"

static void populate_ip_ncu_properties(nwam_ncu_handle_t, nwamd_ncu_t *);

/*
 * Find ncu of specified type for link/interface name.
 */
nwamd_object_t
nwamd_ncu_object_find(nwam_ncu_type_t type, const char *name)
{
	nwam_error_t err;
	char *object_name;
	nwamd_object_t ncu_obj = NULL;

	if ((err = nwam_ncu_name_to_typed_name(name, type, &object_name))
	    != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_ncu_find: nwam_ncu_name_to_typed_name "
		    "returned %s", nwam_strerror(err));
		return (NULL);
	}
	ncu_obj = nwamd_object_find(NWAM_OBJECT_TYPE_NCU, object_name);

	free(object_name);
	return (ncu_obj);
}

nwam_error_t
nwamd_set_ncu_string(nwam_ncu_handle_t ncuh, char **strval, uint_t cnt,
    const char *prop)
{
	nwam_error_t err;
	nwam_value_t val;

	if ((err = nwam_value_create_string_array(strval, cnt, &val))
	    != NWAM_SUCCESS)
		return (err);
	err = nwam_ncu_set_prop_value(ncuh, prop, val);
	nwam_value_free(val);
	return (err);
}

nwam_error_t
nwamd_set_ncu_uint(nwam_ncu_handle_t ncuh, uint64_t *uintval, uint_t cnt,
    const char *prop)
{
	nwam_error_t err;
	nwam_value_t val;

	if ((err = nwam_value_create_uint64_array(uintval, cnt, &val))
	    != NWAM_SUCCESS)
		return (err);
	err = nwam_ncu_set_prop_value(ncuh, prop, val);
	nwam_value_free(val);
	return (err);
}

nwam_error_t
nwamd_get_ncu_string(nwam_ncu_handle_t ncuh, nwam_value_t *val, char ***strval,
    uint_t *cnt, const char *prop)
{
	nwam_error_t err;

	if ((err = nwam_ncu_get_prop_value(ncuh, prop, val)) != NWAM_SUCCESS)
		return (err);
	return (nwam_value_get_string_array(*val, strval, cnt));
}

nwam_error_t
nwamd_get_ncu_uint(nwam_ncu_handle_t ncuh, nwam_value_t *val,
    uint64_t **uintval, uint_t *cnt, const char *prop)
{
	nwam_error_t err;

	if ((err = nwam_ncu_get_prop_value(ncuh, prop, val)) != NWAM_SUCCESS)
		return (err);
	return (nwam_value_get_uint64_array(*val, uintval, cnt));
}

nwam_error_t
nwamd_get_ncu_boolean(nwam_ncu_handle_t ncuh, nwam_value_t *val,
    boolean_t **boolval, uint_t *cnt, const char *prop)
{
	nwam_error_t err;

	if ((err = nwam_ncu_get_prop_value(ncuh, prop, val)) != NWAM_SUCCESS)
		return (err);
	return (nwam_value_get_boolean_array(*val, boolval, cnt));
}

/*
 * Run link/interface state machine in response to a state change
 * or enable/disable action event.
 */
static void
nwamd_ncu_state_machine(const char *object_name)
{
	nwamd_object_t object;
	nwamd_ncu_t *ncu;
	link_state_t link_state;
	nwamd_event_t event;
	nwam_wlan_t key_wlan, connected_wlan;
	nwamd_link_t *link;
	char linkname[NWAM_MAX_NAME_LEN];
	boolean_t up;

	if ((object = nwamd_object_find(NWAM_OBJECT_TYPE_NCU, object_name))
	    == NULL) {
		nlog(LOG_ERR, "nwamd_ncu_state_machine: "
		    "request for nonexistent NCU %s", object_name);
		return;
	}

	ncu = object->nwamd_object_data;
	link = &ncu->ncu_link;

	switch (object->nwamd_object_aux_state) {
	case NWAM_AUX_STATE_INITIALIZED:
		if (ncu->ncu_type == NWAM_NCU_TYPE_LINK) {
			/*
			 * For wired/wireless links, need to get link
			 * up/down events and even if these are not supported,
			 * dlpi_open()ing the link prevents the driver from
			 * being unloaded.
			 */
			nwamd_dlpi_add_link(object);

			if (link->nwamd_link_media == DL_WIFI) {
				/*
				 * First, if we're unexpectedly connected,
				 * disconnect.
				 */
				if (!link->nwamd_link_wifi_connected &&
				    nwamd_wlan_connected(object)) {
					nlog(LOG_DEBUG,
					    "nwamd_ncu_state_machine: "
					    "WiFi unexpectedly connected, "
					    "disconnecting...");
					(void) dladm_wlan_disconnect(dld_handle,
					    link->nwamd_link_id);
					nwamd_set_selected_connected(ncu,
					    B_FALSE, B_FALSE);
				}
				/* move to scanning aux state */
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    object_name, object->nwamd_object_state,
				    NWAM_AUX_STATE_LINK_WIFI_SCANNING);
			} else {
				/*
				 * If initial wired link state is unknown, we
				 * will need to assume the link is up, since
				 * we won´t get DL_NOTE_LINK_UP/DOWN events.
				 */
				link_state = nwamd_get_link_state
				    (ncu->ncu_name);
				if (link_state == LINK_STATE_UP ||
				    link_state == LINK_STATE_UNKNOWN) {
					nwamd_object_set_state
					    (NWAM_OBJECT_TYPE_NCU,
					    object_name, NWAM_STATE_ONLINE,
					    NWAM_AUX_STATE_UP);
				} else {
					nwamd_object_set_state
					    (NWAM_OBJECT_TYPE_NCU,
					    object_name,
					    NWAM_STATE_ONLINE_TO_OFFLINE,
					    NWAM_AUX_STATE_DOWN);
				}
			}
		} else {
			/*
			 * In the current implementation, initialization has to
			 * start from scratch since the complexity of minimizing
			 * configuration change is considerable (e.g. if we
			 * refresh and had DHCP running on the physical
			 * interface, and now have changed to static assignment,
			 * we need to remove DHCP etc).  To avoid all this,
			 * unplumb before re-plumbing the protocols and
			 * addresses we wish to configure.  In the future, it
			 * would be good to try and minimize configuration
			 * changes.
			 */
			nwamd_unplumb_interface(ncu, AF_INET);
			nwamd_unplumb_interface(ncu, AF_INET6);

			/*
			 * We may be restarting the state machine.  Re-read
			 * the IP NCU properties as the ipadm_addrobj_t in
			 * nwamd_if_address should not be reused.
			 */
			populate_ip_ncu_properties(object->nwamd_object_handle,
			    ncu);

			/*
			 * Enqueue a WAITING_FOR_ADDR aux state change so that
			 * we are eligible to receive the IF_STATE events
			 * associated with static, DHCP, DHCPv6 and autoconf
			 * address assignment.  The latter two can happen
			 * quite quickly after plumbing so we need to be ready.
			 */
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    object_name, NWAM_STATE_OFFLINE_TO_ONLINE,
			    NWAM_AUX_STATE_IF_WAITING_FOR_ADDR);

			if (ncu->ncu_if.nwamd_if_ipv4)
				nwamd_plumb_interface(ncu, AF_INET);

			if (ncu->ncu_if.nwamd_if_ipv6)
				nwamd_plumb_interface(ncu, AF_INET6);

			/* Configure addresses */
			nwamd_configure_interface_addresses(ncu);
		}
		break;

	case NWAM_AUX_STATE_IF_DHCP_TIMED_OUT:
	case NWAM_AUX_STATE_IF_WAITING_FOR_ADDR:
		/*
		 * nothing to do here - RTM_NEWADDRs will trigger IF_STATE
		 * events to move us online.
		 */
		break;

	case NWAM_AUX_STATE_LINK_WIFI_SCANNING:
		/* launch scan thread */
		(void) strlcpy(linkname, ncu->ncu_name, sizeof (linkname));
		(void) nwamd_wlan_scan(linkname);
		/* Create periodic scan event */
		nwamd_ncu_create_periodic_scan_event(object);
		break;

	case NWAM_AUX_STATE_LINK_WIFI_NEED_SELECTION:
		/* send "need choice" event */
		event = nwamd_event_init_wlan
		    (ncu->ncu_name, NWAM_EVENT_TYPE_WLAN_NEED_CHOICE, B_FALSE,
		    link->nwamd_link_wifi_scan.nwamd_wifi_scan_curr,
		    link->nwamd_link_wifi_scan.nwamd_wifi_scan_curr_num);
		if (event == NULL)
			break;
		nwamd_event_enqueue(event);
		nwamd_set_selected_connected(ncu, B_FALSE, B_FALSE);
		break;

	case NWAM_AUX_STATE_LINK_WIFI_NEED_KEY:
		/*
		 * Send "need key" event.  Set selected to true, connected
		 * and have_key to false.  Do not fill in WLAN details as
		 * multiple WLANs may match the ESSID name, and each may
		 * have a different speed and channel.
		 */
		bzero(&key_wlan, sizeof (key_wlan));
		(void) strlcpy(key_wlan.nww_essid, link->nwamd_link_wifi_essid,
		    sizeof (key_wlan.nww_essid));
		(void) strlcpy(key_wlan.nww_bssid, link->nwamd_link_wifi_bssid,
		    sizeof (key_wlan.nww_bssid));
		key_wlan.nww_security_mode =
		    link->nwamd_link_wifi_security_mode;
		key_wlan.nww_selected = B_TRUE;
		key_wlan.nww_connected = B_FALSE;
		key_wlan.nww_have_key = B_FALSE;
		event = nwamd_event_init_wlan
		    (ncu->ncu_name, NWAM_EVENT_TYPE_WLAN_NEED_KEY, B_FALSE,
		    &key_wlan, 1);
		if (event == NULL)
			break;
		nwamd_event_enqueue(event);
		break;

	case NWAM_AUX_STATE_LINK_WIFI_CONNECTING:
		(void) strlcpy(linkname, ncu->ncu_name, sizeof (linkname));
		nwamd_wlan_connect(linkname);
		break;

	case NWAM_AUX_STATE_UP:
	case NWAM_AUX_STATE_DOWN:
		up = (object->nwamd_object_aux_state == NWAM_AUX_STATE_UP);
		if (ncu->ncu_type == NWAM_NCU_TYPE_LINK) {
			if (link->nwamd_link_media == DL_WIFI) {
				/*
				 * Connected/disconnected - send WLAN
				 * connection report.
				 */
				link->nwamd_link_wifi_connected = up;
				nwamd_set_selected_connected(ncu, B_TRUE, up);

				(void) strlcpy(connected_wlan.nww_essid,
				    link->nwamd_link_wifi_essid,
				    sizeof (connected_wlan.nww_essid));
				(void) strlcpy(connected_wlan.nww_bssid,
				    link->nwamd_link_wifi_bssid,
				    sizeof (connected_wlan.nww_bssid));
				connected_wlan.nww_security_mode =
				    link->nwamd_link_wifi_security_mode;
				event = nwamd_event_init_wlan
				    (ncu->ncu_name,
				    NWAM_EVENT_TYPE_WLAN_CONNECTION_REPORT, up,
				    &connected_wlan, 1);
				if (event == NULL)
					break;
				nwamd_event_enqueue(event);

				/*
				 * If disconnected, restart the state machine
				 * for the WiFi link (WiFi is always trying
				 * to connect).
				 *
				 * If connected, start signal strength
				 * monitoring thread.
				 */
				if (!up && ncu->ncu_enabled) {
					nlog(LOG_DEBUG,
					    "nwamd_ncu_state_machine: "
					    "wifi disconnect - start over "
					    "after %dsec interval",
					    WIRELESS_RETRY_INTERVAL);
					link->nwamd_link_wifi_connected =
					    B_FALSE;
					/* propogate down event to IP NCU */
					nwamd_propogate_link_up_down_to_ip
					    (ncu->ncu_name, B_FALSE);
					nwamd_object_set_state_timed
					    (NWAM_OBJECT_TYPE_NCU, object_name,
					    NWAM_STATE_OFFLINE_TO_ONLINE,
					    NWAM_AUX_STATE_INITIALIZED,
					    WIRELESS_RETRY_INTERVAL);
				} else {
					nlog(LOG_DEBUG,
					    "nwamd_ncu_state_machine: "
					    "wifi connected, start monitoring");
					(void) strlcpy(linkname, ncu->ncu_name,
					    sizeof (linkname));
					nwamd_wlan_monitor_signal(linkname);
				}
			}
		}

		/* If not in ONLINE/OFFLINE state yet, change state */
		if ((up && object->nwamd_object_state != NWAM_STATE_ONLINE) ||
		    (!up && object->nwamd_object_state != NWAM_STATE_OFFLINE)) {
			nlog(LOG_DEBUG, "nwamd_ncu_state_machine: "
			    "%s is moving %s", object_name,
			    up ? "online" : "offline");
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    object_name,
			    up ? NWAM_STATE_ONLINE : NWAM_STATE_OFFLINE,
			    up ? NWAM_AUX_STATE_UP : NWAM_AUX_STATE_DOWN);

			if (ncu->ncu_type == NWAM_NCU_TYPE_INTERFACE) {
				if (up) {
					/*
					 * Moving online, add v4/v6 default
					 * routes (if any).
					 */
					nwamd_add_default_routes(ncu);
				} else {
					/*
					 * If this is an interface NCU and we
					 * got a down event, it is a consequence
					 * of NCU refresh, so reapply addresses
					 * by reinitializing.
					 */
					nwamd_object_set_state
					    (NWAM_OBJECT_TYPE_NCU, object_name,
					    NWAM_STATE_OFFLINE_TO_ONLINE,
					    NWAM_AUX_STATE_INITIALIZED);
				}
			}
		} else {
			nlog(LOG_DEBUG, "nwamd_ncu_state_machine: "
			    "%s is %s", object_name,
			    up ? "online" : "offline");
		}
		/*
		 * NCU is UP or DOWN, trigger all condition checking, even if
		 * the NCU is already in the ONLINE state - an ENM may depend
		 * on NCU activity.
		 */
		nwamd_create_triggered_condition_check_event(NEXT_FEW_SECONDS);
		break;

	case NWAM_AUX_STATE_CONDITIONS_NOT_MET:
		/*
		 * Link/interface is moving offline.  Nothing to do except
		 * for WiFi, where we disconnect.  Don't unplumb IP on
		 * a link since it may be a transient change.
		 */
		if (ncu->ncu_type == NWAM_NCU_TYPE_LINK) {
			if (link->nwamd_link_media == DL_WIFI) {
				(void) dladm_wlan_disconnect(dld_handle,
				    link->nwamd_link_id);
				link->nwamd_link_wifi_connected = B_FALSE;
				nwamd_set_selected_connected(ncu, B_FALSE,
				    B_FALSE);
			}
		} else {
			/*
			 * Unplumb here. In the future we may elaborate on
			 * the approach used and not unplumb for WiFi
			 * until we reconnect to a different WLAN (i.e. with
			 * a different ESSID).
			 */
			nwamd_unplumb_interface(ncu, AF_INET);
			nwamd_unplumb_interface(ncu, AF_INET6);
		}
		if (object->nwamd_object_state != NWAM_STATE_OFFLINE) {
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    object_name, NWAM_STATE_OFFLINE,
			    NWAM_AUX_STATE_CONDITIONS_NOT_MET);
		}
		break;

	case NWAM_AUX_STATE_MANUAL_DISABLE:
		/* Manual disable, set enabled state appropriately. */
		ncu->ncu_enabled = B_FALSE;
		/* FALLTHROUGH */
	case NWAM_AUX_STATE_UNINITIALIZED:
	case NWAM_AUX_STATE_NOT_FOUND:
		/*
		 * Link/interface NCU has been disabled/deactivated/removed.
		 * For WiFi links disconnect, and for IP interfaces we unplumb.
		 */
		if (ncu->ncu_type == NWAM_NCU_TYPE_LINK) {
			if (link->nwamd_link_media == DL_WIFI) {
				(void) dladm_wlan_disconnect(dld_handle,
				    link->nwamd_link_id);
				link->nwamd_link_wifi_connected = B_FALSE;
				nwamd_set_selected_connected(ncu, B_FALSE,
				    B_FALSE);
			}
			nwamd_dlpi_delete_link(object);
		} else {
			/* Unplumb here. */
			if (ncu->ncu_if.nwamd_if_ipv4) {
				nwamd_unplumb_interface(ncu, AF_INET);
			}
			if (ncu->ncu_if.nwamd_if_ipv6) {
				nwamd_unplumb_interface(ncu, AF_INET6);
			}
			/* trigger location condition checking */
			nwamd_create_triggered_condition_check_event(0);
		}

		switch (object->nwamd_object_aux_state) {
		case NWAM_AUX_STATE_MANUAL_DISABLE:
			/* Change state to DISABLED if manually disabled */
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    object_name, NWAM_STATE_DISABLED,
			    NWAM_AUX_STATE_MANUAL_DISABLE);
			/* Note that NCU has been disabled */
			ncu->ncu_enabled = B_FALSE;
			break;
		case NWAM_AUX_STATE_NOT_FOUND:
			/* Change state to UNINITIALIZED for device removal */
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    object_name, NWAM_STATE_UNINITIALIZED,
			    NWAM_AUX_STATE_NOT_FOUND);
			break;
		default:
			break;
		}
		break;
	default:
		nlog(LOG_ERR, "nwamd_ncu_state_machine: unexpected state");
		break;
	}

	nwamd_object_release(object);
}

static int
ncu_create_init_fini_event(nwam_ncu_handle_t ncuh, void *data)
{
	boolean_t *init = data;
	char *name, *typedname;
	nwam_error_t err;
	nwam_value_t typeval = NULL;
	uint64_t *type;
	uint_t numvalues;
	nwamd_event_t ncu_event;

	if (nwam_ncu_get_name(ncuh, &name) != NWAM_SUCCESS) {
		nlog(LOG_ERR,
		    "ncu_create_init_fini_event: could not get NCU name");
		return (0);
	}

	nlog(LOG_DEBUG, "ncu_create_init_fini_event(%s, %p)", name, data);

	if ((err = nwamd_get_ncu_uint(ncuh, &typeval, &type, &numvalues,
	    NWAM_NCU_PROP_TYPE)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "ncu_create_init_fini_event: "
		    "could not get NCU type: %s", nwam_strerror(err));
		free(name);
		nwam_value_free(typeval);
		return (0);
	}

	/* convert name to typedname for event */
	if ((err = nwam_ncu_name_to_typed_name(name, *type, &typedname))
	    != NWAM_SUCCESS) {
		nlog(LOG_ERR, "ncu_create_init_fini_event: "
		    "NCU name translation failed: %s", nwam_strerror(err));
		free(name);
		return (0);
	}
	free(name);
	nwam_value_free(typeval);

	ncu_event = nwamd_event_init(*init ?
	    NWAM_EVENT_TYPE_OBJECT_INIT : NWAM_EVENT_TYPE_OBJECT_FINI,
	    NWAM_OBJECT_TYPE_NCU, 0, typedname);
	if (ncu_event != NULL)
		nwamd_event_enqueue(ncu_event);
	free(typedname);

	return (0);
}

/*
 * Initialization - walk the NCUs, creating initialization events for each
 * NCU.  nwamd_ncu_handle_init_event() will check if the associated
 * physical link exists or not.
 */
void
nwamd_init_ncus(void)
{
	boolean_t init = B_TRUE;

	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (active_ncph != NULL) {
		nlog(LOG_DEBUG, "nwamd_init_ncus: "
		    "(re)intializing NCUs for NCP %s", active_ncp);
		(void) nwam_ncp_walk_ncus(active_ncph,
		    ncu_create_init_fini_event, &init, NWAM_FLAG_NCU_TYPE_ALL,
		    NULL);
	}
	(void) pthread_mutex_unlock(&active_ncp_mutex);
}

void
nwamd_fini_ncus(void)
{
	boolean_t init = B_FALSE;

	/* We may not have an active NCP on initialization, so skip fini */
	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (active_ncph != NULL) {
		nlog(LOG_DEBUG, "nwamd_fini_ncus: deinitializing NCUs for %s",
		    active_ncp);
		(void) nwam_ncp_walk_ncus(active_ncph,
		    ncu_create_init_fini_event, &init, NWAM_FLAG_NCU_TYPE_ALL,
		    NULL);
	}
	(void) pthread_mutex_unlock(&active_ncp_mutex);
}

/*
 * Most properties of this type don't need to be cached locally.  Only those
 * interesting to the daemon are stored in an nwamd_ncu_t.
 */
static void
populate_common_ncu_properties(nwam_ncu_handle_t ncuh, nwamd_ncu_t *ncu_data)
{
	nwam_value_t ncu_prop;
	nwam_error_t err;
	boolean_t enablevalue;
	uint_t numvalues;
	char **parent;

	if ((err = nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_ENABLED,
	    &ncu_prop)) != NWAM_SUCCESS) {
		char *name;
		(void) nwam_ncu_name_to_typed_name(ncu_data->ncu_name,
		    ncu_data->ncu_type, &name);
		nlog(LOG_ERR, "nwam_ncu_get_prop_value %s ENABLED failed: %s",
		    name, nwam_strerror(err));
		free(name);
		ncu_data->ncu_enabled = B_TRUE;
	} else {
		if ((err = nwam_value_get_boolean(ncu_prop, &enablevalue)) !=
		    NWAM_SUCCESS) {
			nlog(LOG_ERR, "nwam_value_get_boolean ENABLED failed: "
			    "%s", nwam_strerror(err));
		} else {
			ncu_data->ncu_enabled = enablevalue;
		}
		nwam_value_free(ncu_prop);
	}

	if ((err = nwamd_get_ncu_string(ncuh, &ncu_prop, &parent,
	    &numvalues, NWAM_NCU_PROP_PARENT_NCP)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwam_ncu_get_prop_value %s PARENT failed: %s",
		    ncu_data->ncu_name, nwam_strerror(err));
	} else {
		(void) strlcpy(ncu_data->ncu_parent, parent[0],
		    sizeof (ncu_data->ncu_parent));
		nwam_value_free(ncu_prop);
	}
}

/*
 * Read in link properties.
 */
static void
populate_link_ncu_properties(nwam_ncu_handle_t ncuh, nwamd_ncu_t *ncu_data)
{
	nwam_value_t ncu_prop;
	nwam_error_t err;
	char **mac_addr;
	uint64_t *uintval;
	uint_t numvalues;

	/* activation-mode */
	if ((err = nwamd_get_ncu_uint(ncuh, &ncu_prop, &uintval, &numvalues,
	    NWAM_NCU_PROP_ACTIVATION_MODE)) != NWAM_SUCCESS) {
		nlog(LOG_ERR,
		    "populate_link_ncu_properties: could not get %s value: %s",
		    NWAM_NCU_PROP_ACTIVATION_MODE, nwam_strerror(err));
	} else {
		ncu_data->ncu_link.nwamd_link_activation_mode = uintval[0];
		nwam_value_free(ncu_prop);
	}

	/* priority-group and priority-mode for prioritized activation */
	if (ncu_data->ncu_link.nwamd_link_activation_mode ==
	    NWAM_ACTIVATION_MODE_PRIORITIZED) {
		/* ncus with prioritized activation are always enabled */
		ncu_data->ncu_enabled = B_TRUE;
		if ((err = nwamd_get_ncu_uint(ncuh, &ncu_prop, &uintval,
		    &numvalues, NWAM_NCU_PROP_PRIORITY_MODE))
		    != NWAM_SUCCESS) {
			nlog(LOG_ERR, "populate_link_ncu_properties: "
			    "could not get %s value: %s",
			    NWAM_NCU_PROP_PRIORITY_MODE, nwam_strerror(err));
		} else {
			ncu_data->ncu_link.nwamd_link_priority_mode =
			    uintval[0];
			nwam_value_free(ncu_prop);
		}

		if ((err = nwamd_get_ncu_uint(ncuh, &ncu_prop, &uintval,
		    &numvalues, NWAM_NCU_PROP_PRIORITY_GROUP))
		    != NWAM_SUCCESS) {
			nlog(LOG_ERR, "populate_link_ncu_properties: "
			    "could not get %s value: %s",
			    NWAM_NCU_PROP_PRIORITY_GROUP, nwam_strerror(err));
		} else {
			ncu_data->ncu_link.nwamd_link_priority_group =
			    uintval[0];
			nwam_value_free(ncu_prop);
		}
	}

	/* link-mac-addr */
	if ((err = nwamd_get_ncu_string(ncuh, &ncu_prop, &mac_addr, &numvalues,
	    NWAM_NCU_PROP_LINK_MAC_ADDR)) != NWAM_SUCCESS) {
		nlog(LOG_DEBUG,
		    "populate_link_ncu_properties: could not get %s value: %s",
		    NWAM_NCU_PROP_LINK_MAC_ADDR, nwam_strerror(err));
		ncu_data->ncu_link.nwamd_link_mac_addr = NULL;
	} else {
		ncu_data->ncu_link.nwamd_link_mac_addr = strdup(*mac_addr);
		ncu_data->ncu_link.nwamd_link_mac_addr_len = strlen(*mac_addr);
		nwam_value_free(ncu_prop);
	}

	/* link-mtu */
	if ((err = nwamd_get_ncu_uint(ncuh, &ncu_prop, &uintval, &numvalues,
	    NWAM_NCU_PROP_LINK_MTU)) != NWAM_SUCCESS) {
		nlog(LOG_DEBUG,
		    "populate_link_ncu_properties: could not get %s value: %s",
		    NWAM_NCU_PROP_LINK_MTU, nwam_strerror(err));
		ncu_data->ncu_link.nwamd_link_mtu = 0;
	} else {
		ncu_data->ncu_link.nwamd_link_mtu = uintval[0];
		nwam_value_free(ncu_prop);
	}

	/* link-autopush */
	if ((err = nwamd_get_ncu_string(ncuh, &ncu_prop,
	    &ncu_data->ncu_link.nwamd_link_autopush,
	    &ncu_data->ncu_link.nwamd_link_num_autopush,
	    NWAM_NCU_PROP_LINK_AUTOPUSH)) != NWAM_SUCCESS) {
		nlog(LOG_DEBUG,
		    "populate_link_ncu_properties: could not get %s value: %s",
		    NWAM_NCU_PROP_LINK_AUTOPUSH, nwam_strerror(err));
		ncu_data->ncu_link.nwamd_link_num_autopush = 0;
	}
}

static void
populate_ip_ncu_properties(nwam_ncu_handle_t ncuh, nwamd_ncu_t *ncu_data)
{
	nwamd_if_t *nif = &ncu_data->ncu_if;
	struct nwamd_if_address **nifa, *nifai, *nifait;
	boolean_t static_addr = B_FALSE, *boolvalue, dhcp_primary = B_FALSE;
	uint64_t *addrsrcvalue;
	nwam_value_t ncu_prop;
	nwam_error_t err;
	ipadm_addrobj_t ipaddr;
	ipadm_status_t ipstatus;
	char **addrvalue, ipreqhost[MAXNAMELEN];
	uint_t numvalues;
	uint64_t *ipversion;
	int i;

	nif->nwamd_if_ipv4 = B_FALSE;
	nif->nwamd_if_ipv6 = B_FALSE;
	nif->nwamd_if_dhcp_requested = B_FALSE;
	nif->nwamd_if_stateful_requested = B_FALSE;
	nif->nwamd_if_stateless_requested = B_FALSE;
	nif->nwamd_if_ipv4_default_route_set = B_FALSE;
	nif->nwamd_if_ipv6_default_route_set = B_FALSE;

	/* ip-version */
	if ((err = nwamd_get_ncu_uint(ncuh, &ncu_prop, &ipversion, &numvalues,
	    NWAM_NCU_PROP_IP_VERSION)) != NWAM_SUCCESS) {
		nlog(LOG_ERR,
		    "populate_ip_ncu_properties: could not get %s value: %s",
		    NWAM_NCU_PROP_IP_VERSION, nwam_strerror(err));
	} else {
		for (i = 0; i < numvalues; i++) {
			switch (ipversion[i]) {
			case IPV4_VERSION:
				nif->nwamd_if_ipv4 = B_TRUE;
				break;
			case IPV6_VERSION:
				nif->nwamd_if_ipv6 = B_TRUE;
				break;
			default:
				nlog(LOG_ERR, "bogus ip version %lld",
				    ipversion[i]);
				break;
			}
		}
		nwam_value_free(ncu_prop);
	}

	/* ip-primary */
	if ((err = nwamd_get_ncu_boolean(ncuh, &ncu_prop, &boolvalue,
	    &numvalues, NWAM_NCU_PROP_IP_PRIMARY)) != NWAM_SUCCESS) {
		/* ip-primary is optional, so do not LOG_ERR */
		nlog(LOG_DEBUG, "populate_ip_ncu_properties: "
		    "could not get %s value: %s",
		    NWAM_NCU_PROP_IP_PRIMARY, nwam_strerror(err));
	} else {
		if (numvalues > 0)
			dhcp_primary = boolvalue[0];
		nwam_value_free(ncu_prop);
	}

	/* ip-reqhost */
	*ipreqhost = '\0';

	if ((err = nwamd_get_ncu_string(ncuh, &ncu_prop, &addrvalue,
	    &numvalues, NWAM_NCU_PROP_IP_REQHOST)) != NWAM_SUCCESS) {
		/* ip-reqhost is optional, so do not LOG_ERR */
		nlog(LOG_DEBUG, "populate_ip_ncu_properties: "
		    "could not get %s value: %s",
		    NWAM_NCU_PROP_IP_REQHOST, nwam_strerror(err));
	} else {
		if (numvalues > 0 && strlcpy(ipreqhost, addrvalue[0],
		    sizeof (ipreqhost)) >= sizeof (ipreqhost)) {
			nlog(LOG_WARNING, "populate_ip_ncu_properties: "
			    "too long %s value: %s",
			    NWAM_NCU_PROP_IP_REQHOST, addrvalue[0]);
			*ipreqhost = '\0';
		}
		nwam_value_free(ncu_prop);
	}

	/* Free the old list. */
	for (nifai = nif->nwamd_if_list; nifai != NULL; nifai = nifait) {
		nifait = nifai->next;
		nifai->next = NULL;
		ipadm_destroy_addrobj(nifai->ipaddr);
		free(nifai);
	}
	nif->nwamd_if_list = NULL;
	nifa = &(nif->nwamd_if_list);

	if (!nif->nwamd_if_ipv4)
		goto skip_ipv4;

	/* ipv4-addrsrc */
	if ((err = nwamd_get_ncu_uint(ncuh, &ncu_prop, &addrsrcvalue,
	    &numvalues, NWAM_NCU_PROP_IPV4_ADDRSRC)) != NWAM_SUCCESS) {
		nlog(nif->nwamd_if_ipv4 ? LOG_ERR : LOG_DEBUG,
		    "populate_ip_ncu_properties: could not get %s value: %s",
		    NWAM_NCU_PROP_IPV4_ADDRSRC, nwam_strerror(err));
	} else {
		for (i = 0; i < numvalues; i++) {
			switch (addrsrcvalue[i]) {
			case NWAM_ADDRSRC_DHCP:
				nif->nwamd_if_dhcp_requested = B_TRUE;
				break;
			case NWAM_ADDRSRC_STATIC:
				static_addr = B_TRUE;
				break;
			default:
				break;
			}
		}
		nwam_value_free(ncu_prop);
	}
	if (nif->nwamd_if_dhcp_requested) {
		ipstatus = ipadm_create_addrobj(IPADM_ADDR_DHCP,
		    ncu_data->ncu_name, &ipaddr);
		if (ipstatus != IPADM_SUCCESS) {
			nlog(LOG_ERR, "populate_ip_ncu_properties: "
			    "ipadm_create_addrobj failed for v4 dhcp: %s",
			    ipadm_status2str(ipstatus));
			goto skip_ipv4_dhcp;
		}

		ipstatus = ipadm_set_wait_time(ipaddr, ncu_wait_time);
		if (ipstatus != IPADM_SUCCESS) {
			nlog(LOG_ERR, "populate_ip_ncu_properties: "
			    "ipadm_set_wait_time failed for v4 dhcp: %s",
			    ipadm_status2str(ipstatus));
			ipadm_destroy_addrobj(ipaddr);
			goto skip_ipv4_dhcp;
		}
		ipstatus = ipadm_set_primary(ipaddr, dhcp_primary);
		if (ipstatus != IPADM_SUCCESS) {
			nlog(LOG_ERR, "populate_ip_ncu_properties: "
			    "ipadm_set_primary failed for v4 dhcp: %s",
			    ipadm_status2str(ipstatus));
			ipadm_destroy_addrobj(ipaddr);
			goto skip_ipv4_dhcp;
		}
		ipstatus = ipadm_set_reqhost(ipaddr, ipreqhost);
		if (ipstatus != IPADM_SUCCESS) {
			nlog(LOG_ERR, "populate_ip_ncu_properties: "
			    "ipadm_set_reqhost failed for v4 dhcp: %s",
			    ipadm_status2str(ipstatus));
			ipadm_destroy_addrobj(ipaddr);
			goto skip_ipv4_dhcp;
		}
		if ((*nifa = calloc(sizeof (**nifa), 1)) != NULL) {
			(*nifa)->family = AF_INET;
			(*nifa)->ipaddr_atype = IPADM_ADDR_DHCP;
			(*nifa)->ipaddr = ipaddr;
			nifa = &((*nifa)->next);
			*nifa = NULL;
		} else {
			nlog(LOG_ERR, "populate_ip_ncu_properties: "
			    "couldn't allocate nwamd address for v4 dhcp: %s",
			    strerror(errno));
			ipadm_destroy_addrobj(ipaddr);
		}
	}

skip_ipv4_dhcp:
	/* ipv4-addr */
	if (static_addr) {
		if ((err = nwamd_get_ncu_string(ncuh, &ncu_prop, &addrvalue,
		    &numvalues, NWAM_NCU_PROP_IPV4_ADDR)) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "populate_ip_ncu_properties: "
			    "could not get %s value: %s",
			    NWAM_NCU_PROP_IPV4_ADDR, nwam_strerror(err));
		} else {
			for (i = 0; i < numvalues; i++) {
				ipstatus = ipadm_create_addrobj(
				    IPADM_ADDR_STATIC, ncu_data->ncu_name,
				    &ipaddr);
				if (ipstatus != IPADM_SUCCESS) {
					nlog(LOG_ERR,
					    "populate_ip_ncu_properties: "
					    "ipadm_create_addrobj failed "
					    "for %s: %s", addrvalue[i],
					    ipadm_status2str(ipstatus));
					continue;
				}
				/* ipadm_set_addr takes <addr>[/<mask>] */
				ipstatus = ipadm_set_addr(ipaddr, addrvalue[i],
				    AF_INET);
				if (ipstatus != IPADM_SUCCESS) {
					nlog(LOG_ERR,
					    "populate_ip_ncu_properties: "
					    "ipadm_set_addr failed for %s: %s",
					    addrvalue[i],
					    ipadm_status2str(ipstatus));
					ipadm_destroy_addrobj(ipaddr);
					continue;
				}

				if ((*nifa = calloc(sizeof (**nifa), 1))
				    != NULL) {
					(*nifa)->family = AF_INET;
					(*nifa)->ipaddr_atype =
					    IPADM_ADDR_STATIC;
					(*nifa)->ipaddr = ipaddr;
					nifa = &((*nifa)->next);
				} else {
					nlog(LOG_ERR,
					    "populate_ip_ncu_properties: "
					    "couldn't allocate nwamd address "
					    "for %s: %s", addrvalue[i],
					    strerror(errno));
					ipadm_destroy_addrobj(ipaddr);
				}
			}
			*nifa = NULL;

			nwam_value_free(ncu_prop);
		}
	}

	/* get default route, if any */
	if ((err = nwamd_get_ncu_string(ncuh, &ncu_prop, &addrvalue,
	    &numvalues, NWAM_NCU_PROP_IPV4_DEFAULT_ROUTE)) == NWAM_SUCCESS) {
		/* Only one default route is allowed. */
		nif->nwamd_if_ipv4_default_route.sin_family = AF_INET;
		(void) inet_pton(AF_INET, addrvalue[0],
		    &(nif->nwamd_if_ipv4_default_route.sin_addr));
		nif->nwamd_if_ipv4_default_route_set = B_TRUE;
		nwam_value_free(ncu_prop);
	}

skip_ipv4:
	if (!nif->nwamd_if_ipv6)
		goto skip_ipv6;

	/* ipv6-addrsrc */
	static_addr = B_FALSE;
	if ((err = nwamd_get_ncu_uint(ncuh, &ncu_prop, &addrsrcvalue,
	    &numvalues, NWAM_NCU_PROP_IPV6_ADDRSRC)) != NWAM_SUCCESS) {
		nlog(nif->nwamd_if_ipv6 ? LOG_ERR : LOG_DEBUG,
		    "populate_ip_ncu_properties: could not get %s value: %s",
		    NWAM_NCU_PROP_IPV6_ADDRSRC, nwam_strerror(err));
	} else {
		for (i = 0; i < numvalues; i++) {
			switch (addrsrcvalue[i]) {
			case NWAM_ADDRSRC_DHCP:
				nif->nwamd_if_stateful_requested = B_TRUE;
				break;
			case NWAM_ADDRSRC_AUTOCONF:
				nif->nwamd_if_stateless_requested = B_TRUE;
				break;
			case NWAM_ADDRSRC_STATIC:
				static_addr = B_TRUE;
				break;
			default:
				break;
			}
		}
		nwam_value_free(ncu_prop);
	}
	/*
	 * Both stateful and stateless share the same nwamd_if_address because
	 * only one ipaddr for both of these addresses can be created.
	 * ipadm_create_addr() adds both addresses from the same ipaddr.
	 */
	if (nif->nwamd_if_stateful_requested ||
	    nif->nwamd_if_stateless_requested) {
		ipstatus = ipadm_create_addrobj(IPADM_ADDR_IPV6_ADDRCONF,
		    ncu_data->ncu_name, &ipaddr);
		if (ipstatus != IPADM_SUCCESS) {
			nlog(LOG_ERR, "populate_ip_ncu_properties: "
			    "ipadm_create_addrobj failed for v6 "
			    "stateless/stateful: %s",
			    ipadm_status2str(ipstatus));
			goto skip_ipv6_addrconf;
		}
		/* create_addrobj sets both stateless and stateful to B_TRUE */
		if (!nif->nwamd_if_stateful_requested) {
			ipstatus = ipadm_set_stateful(ipaddr, B_FALSE);
			if (ipstatus != IPADM_SUCCESS) {
				nlog(LOG_ERR, "populate_ip_ncu_properties: "
				    "ipadm_set_stateful failed for v6: %s",
				    ipadm_status2str(ipstatus));
				ipadm_destroy_addrobj(ipaddr);
				goto skip_ipv6_addrconf;
			}
		}
		if (!nif->nwamd_if_stateless_requested) {
			ipstatus = ipadm_set_stateless(ipaddr, B_FALSE);
			if (ipstatus != IPADM_SUCCESS) {
				nlog(LOG_ERR, "populate_ip_ncu_properties: "
				    "ipadm_set_stateless failed for v6: %s",
				    ipadm_status2str(ipstatus));
				ipadm_destroy_addrobj(ipaddr);
				goto skip_ipv6_addrconf;
			}
		}
		if ((*nifa = calloc(sizeof (**nifa), 1)) != NULL) {
			(*nifa)->family = AF_INET6;
			(*nifa)->ipaddr_atype = IPADM_ADDR_IPV6_ADDRCONF;
			(*nifa)->ipaddr = ipaddr;
			nifa = &((*nifa)->next);
			*nifa = NULL;
		} else {
			nlog(LOG_ERR, "populate_ip_ncu_properties: "
			    "couldn't allocate nwamd address for "
			    "v6 stateless/stateful: %s", strerror(errno));
			ipadm_destroy_addrobj(ipaddr);
		}
	}

skip_ipv6_addrconf:
	/* ipv6-addr */
	if (static_addr) {
		if ((err = nwamd_get_ncu_string(ncuh, &ncu_prop, &addrvalue,
		    &numvalues, NWAM_NCU_PROP_IPV6_ADDR)) != NWAM_SUCCESS) {
			nlog(LOG_ERR, "populate_ip_ncu_properties: "
			    "could not get %s value: %s",
			    NWAM_NCU_PROP_IPV6_ADDR, nwam_strerror(err));
		} else {
			for (i = 0; i < numvalues; i++) {
				ipstatus = ipadm_create_addrobj(
				    IPADM_ADDR_STATIC, ncu_data->ncu_name,
				    &ipaddr);
				if (ipstatus != IPADM_SUCCESS) {
					nlog(LOG_ERR,
					    "populate_ip_ncu_properties: "
					    "ipadm_create_addrobj failed "
					    "for %s: %s", addrvalue[i],
					    ipadm_status2str(ipstatus));
					continue;
				}
				/* ipadm_set_addr takes <addr>[/<mask>] */
				ipstatus = ipadm_set_addr(ipaddr, addrvalue[i],
				    AF_INET6);
				if (ipstatus != IPADM_SUCCESS) {
					nlog(LOG_ERR,
					    "populate_ip_ncu_properties: "
					    "ipadm_set_addr failed for %s: %s",
					    addrvalue[i],
					    ipadm_status2str(ipstatus));
					ipadm_destroy_addrobj(ipaddr);
					continue;
				}

				if ((*nifa = calloc(sizeof (**nifa), 1))
				    != NULL) {
					(*nifa)->family = AF_INET6;
					(*nifa)->ipaddr_atype =
					    IPADM_ADDR_STATIC;
					(*nifa)->ipaddr = ipaddr;
					nifa = &((*nifa)->next);
				} else {
					nlog(LOG_ERR,
					    "populate_ip_ncu_properties: "
					    "couldn't allocate nwamd address "
					    "for %s: %s", addrvalue[i],
					    strerror(errno));
					ipadm_destroy_addrobj(ipaddr);
				}
			}
			*nifa = NULL;

			nwam_value_free(ncu_prop);
		}
	}

	/* get default route, if any */
	if ((err = nwamd_get_ncu_string(ncuh, &ncu_prop, &addrvalue,
	    &numvalues, NWAM_NCU_PROP_IPV6_DEFAULT_ROUTE)) == NWAM_SUCCESS) {
		/* Only one default route is allowed. */
		nif->nwamd_if_ipv6_default_route.sin6_family = AF_INET6;
		(void) inet_pton(AF_INET6, addrvalue[0],
		    &(nif->nwamd_if_ipv6_default_route.sin6_addr));
		nif->nwamd_if_ipv6_default_route_set = B_TRUE;
		nwam_value_free(ncu_prop);
	}

skip_ipv6:
	;
}

static nwamd_ncu_t *
nwamd_ncu_init(nwam_ncu_type_t ncu_type, const char *name)
{
	nwamd_ncu_t *rv;

	nlog(LOG_DEBUG, "nwamd_ncu_init(%d, %s)", ncu_type, name);

	if ((rv = calloc(1, sizeof (*rv))) == NULL)
		return (NULL);

	rv->ncu_type = ncu_type;
	rv->ncu_name = strdup(name);
	rv->ncu_enabled = B_FALSE;

	/* Initialize link/interface-specific data */
	if (rv->ncu_type == NWAM_NCU_TYPE_LINK) {
		(void) bzero(&rv->ncu_link, sizeof (nwamd_link_t));
		(void) dladm_name2info(dld_handle, name,
		    &rv->ncu_link.nwamd_link_id, NULL, NULL,
		    &rv->ncu_link.nwamd_link_media);
		(void) pthread_mutex_init(
		    &rv->ncu_link.nwamd_link_wifi_mutex, NULL);
		rv->ncu_link.nwamd_link_wifi_priority = MAXINT;
	} else {
		(void) bzero(&rv->ncu_if, sizeof (nwamd_if_t));
	}

	return (rv);
}

void
nwamd_ncu_free(nwamd_ncu_t *ncu)
{
	if (ncu != NULL) {
		assert(ncu->ncu_type == NWAM_NCU_TYPE_LINK ||
		    ncu->ncu_type == NWAM_NCU_TYPE_INTERFACE);
		if (ncu->ncu_type == NWAM_NCU_TYPE_LINK) {
			struct nwamd_link *l = &ncu->ncu_link;
			int i;

			free(l->nwamd_link_wifi_key);
			free(l->nwamd_link_mac_addr);
			for (i = 0; i < l->nwamd_link_num_autopush; i++)
				free(l->nwamd_link_autopush[i]);
		} else if (ncu->ncu_type == NWAM_NCU_TYPE_INTERFACE) {
			struct nwamd_if_address *nifa;

			nifa = ncu->ncu_if.nwamd_if_list;
			while (nifa != NULL) {
				struct nwamd_if_address *n;

				n = nifa;
				nifa = nifa->next;
				ipadm_destroy_addrobj(n->ipaddr);
				free(n);
			}
		}
		free(ncu->ncu_name);
		free(ncu);
	}
}

static int
nwamd_ncu_display(nwamd_object_t ncu_obj, void *data)
{
	nwamd_ncu_t *ncu = (nwamd_ncu_t *)ncu_obj->nwamd_object_data;
	data = data;
	nlog(LOG_DEBUG, "NCU (%p) %s state %s, %s",
	    (void *)ncu, ncu_obj->nwamd_object_name,
	    nwam_state_to_string(ncu_obj->nwamd_object_state),
	    nwam_aux_state_to_string(ncu_obj->nwamd_object_aux_state));
	return (0);
}

void
nwamd_log_ncus(void)
{
	nlog(LOG_DEBUG, "NCP %s", active_ncp);
	(void) nwamd_walk_objects(NWAM_OBJECT_TYPE_NCU, nwamd_ncu_display,
	    NULL);
}

int
nwamd_ncu_action(const char *ncu, const char *parent, nwam_action_t action)
{
	nwamd_event_t ncu_event = nwamd_event_init_object_action
	    (NWAM_OBJECT_TYPE_NCU, ncu, parent, action);
	if (ncu_event == NULL)
		return (1);
	nwamd_event_enqueue(ncu_event);
	return (0);
}

static void
add_phys_ncu_to_ncp(nwam_ncp_handle_t ncph, const char *name)
{
	dladm_status_t dlrtn;
	uint32_t media;
	boolean_t is_wireless;
	nwam_error_t err;
	nwam_ncu_handle_t ncuh;
	uint64_t uintval;

	if ((dlrtn = dladm_name2info(dld_handle, name, NULL, NULL, NULL,
	    &media)) != DLADM_STATUS_OK) {
		char errmsg[DLADM_STRSIZE];
		nlog(LOG_ERR, "failed to get media type for %s: %s", name,
		    dladm_status2str(dlrtn, errmsg));
		return;
	}
	is_wireless = (media == DL_WIFI);

	if ((err = nwam_ncu_create(ncph, name, NWAM_NCU_TYPE_LINK,
	    NWAM_NCU_CLASS_PHYS, &ncuh)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "failed to create link ncu for %s: %s", name,
		    nwam_strerror(err));
		if (err == NWAM_ENTITY_READ_ONLY) {
			nwamd_event_t retry_event;

			/*
			 * Root filesystem may be read-only, retry in
			 * a few seconds.
			 */
			nlog(LOG_DEBUG, "Retrying addition of phys ncu for %s",
			    name);
			retry_event = nwamd_event_init_link_action(name,
			    NWAM_ACTION_ADD);
			if (retry_event != NULL) {
				nwamd_event_enqueue_timed(retry_event,
				    NWAMD_READONLY_RETRY_INTERVAL);
			}
		}
		return;
	}

	uintval = NWAM_ACTIVATION_MODE_PRIORITIZED;
	if ((err = nwamd_set_ncu_uint(ncuh, &uintval, 1,
	    NWAM_NCU_PROP_ACTIVATION_MODE)) != NWAM_SUCCESS) {
		goto finish;
	}

	uintval = is_wireless ? 1 : 0;
	if ((err = nwamd_set_ncu_uint(ncuh, &uintval, 1,
	    NWAM_NCU_PROP_PRIORITY_GROUP)) != NWAM_SUCCESS) {
		goto finish;
	}

	uintval = is_wireless ? NWAM_PRIORITY_MODE_EXCLUSIVE :
	    NWAM_PRIORITY_MODE_SHARED;
	if ((err = nwamd_set_ncu_uint(ncuh, &uintval, 1,
	    NWAM_NCU_PROP_PRIORITY_MODE)) != NWAM_SUCCESS) {
		goto finish;
	}

	err = nwam_ncu_commit(ncuh, 0);

finish:
	nwam_ncu_free(ncuh);
	if (err != NWAM_SUCCESS) {
		nlog(LOG_ERR,
		    "failed to create automatic link ncu for %s: %s",
		    name, nwam_strerror(err));
	}
}

static void
add_ip_ncu_to_ncp(nwam_ncp_handle_t ncph, const char *name)
{
	nwam_error_t err;
	nwam_ncu_handle_t ncuh;

	if ((err = nwam_ncu_create(ncph, name, NWAM_NCU_TYPE_INTERFACE,
	    NWAM_NCU_CLASS_IP, &ncuh)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "failed to create ip ncu for %s: %s", name,
		    nwam_strerror(err));
		/*
		 * Root filesystem may be read-only, but no need to
		 * retry here since add_phys_ncu_to_ncp() enqueues
		 * a retry event which will lead to add_ip_ncu_to_ncp()
		 * being called.
		 */
		return;
	}

	/* IP NCU has the default values, so nothing else to do */
	err = nwam_ncu_commit(ncuh, 0);

finish:
	nwam_ncu_free(ncuh);
	if (err != NWAM_SUCCESS) {
		nlog(LOG_ERR,
		    "failed to create ip ncu for %s: %s", name,
		    nwam_strerror(err));
	}
}

static void
remove_ncu_from_ncp(nwam_ncp_handle_t ncph, const char *name,
    nwam_ncu_type_t type)
{
	nwam_error_t err;
	nwam_ncu_handle_t ncuh;

	if ((err = nwam_ncu_read(ncph, name, type, 0, &ncuh)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "failed to read automatic ncu %s: %s", name,
		    nwam_strerror(err));
		return;
	}

	err = nwam_ncu_destroy(ncuh, 0);
	if (err != NWAM_SUCCESS) {
		nlog(LOG_ERR, "failed to delete automatic ncu %s: %s", name,
		    nwam_strerror(err));
	}
}

/*
 * Device represented by NCU has been added or removed for the active
 * User NCP.  If an associated NCU of the given type is found, transition it
 * to the appropriate state.
 */
void
ncu_action_change_state(nwam_action_t action, nwam_ncu_type_t type,
    const char *name)
{
	nwamd_object_t ncu_obj = NULL;
	nwamd_ncu_t *ncu;

	if ((ncu_obj = nwamd_ncu_object_find(type, name)) == NULL)
		return;

	ncu = ncu_obj->nwamd_object_data;

	/*
	 * If device has been added, transition from uninitialized to offline.
	 * If device has been removed, transition to uninitialized (via online*
	 * if the NCU is currently enabled in order to tear down config).
	 */
	if (action == NWAM_ACTION_ADD) {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
		    ncu_obj->nwamd_object_name,
		    NWAM_STATE_OFFLINE, NWAM_AUX_STATE_CONDITIONS_NOT_MET);
	} else {
		if (ncu->ncu_enabled) {
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    ncu_obj->nwamd_object_name,
			    NWAM_STATE_ONLINE_TO_OFFLINE,
			    NWAM_AUX_STATE_NOT_FOUND);
		} else {
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    ncu_obj->nwamd_object_name,
			    NWAM_STATE_UNINITIALIZED,
			    NWAM_AUX_STATE_NOT_FOUND);
		}
	}
	nwamd_object_release(ncu_obj);
}

/*
 * Called with hotplug sysevent or when nwam is started and walking the
 * physical interfaces.  Add/remove both link and interface NCUs from the
 * Automatic NCP.  Assumes that both link and interface NCUs don't exist.
 */
void
nwamd_ncu_handle_link_action_event(nwamd_event_t event)
{
	nwam_ncp_handle_t ncph;
	nwam_ncu_type_t type;
	nwam_action_t action =
	    event->event_msg->nwe_data.nwe_link_action.nwe_action;
	nwam_error_t err;
	char *name;
	boolean_t automatic_ncp_active = B_FALSE;

	if (action != NWAM_ACTION_ADD && action != NWAM_ACTION_REMOVE) {
		nlog(LOG_ERR, "nwamd_ncu_handle_link_action_event: "
		    "invalid link action %s", nwam_action_to_string(action));
		nwamd_event_do_not_send(event);
		return;
	}

	nlog(LOG_DEBUG, "nwamd_ncu_handle_link_action_event: "
	    "link action '%s' event on %s", nwam_action_to_string(action),
	    event->event_object[0] == 0 ? "n/a" : event->event_object);

	if ((err = nwam_ncu_typed_name_to_name(event->event_object, &type,
	    &name)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_ncu_handle_link_action_event: "
		    "translation from typedname error: %s", nwam_strerror(err));
		nwamd_event_do_not_send(event);
		return;
	}

	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (strcmp(active_ncp, NWAM_NCP_NAME_AUTOMATIC) == 0 &&
	    active_ncph != NULL) {
		automatic_ncp_active = B_TRUE;
	}
	(void) pthread_mutex_unlock(&active_ncp_mutex);

	/*
	 * We could use active_ncph for cases where the Automatic NCP is active,
	 * but that would involve holding the active_ncp_mutex for too long.
	 */
	if ((err = nwam_ncp_read(NWAM_NCP_NAME_AUTOMATIC, 0, &ncph))
	    == NWAM_ENTITY_NOT_FOUND) {
		/* Automatic NCP doesn't exist, create it */
		err = nwam_ncp_create(NWAM_NCP_NAME_AUTOMATIC, 0, &ncph);
	}
	if (err != NWAM_SUCCESS)
		goto fail;

	/* add or remove NCUs from Automatic NCP */
	if (action == NWAM_ACTION_ADD) {
		add_phys_ncu_to_ncp(ncph, name);
		add_ip_ncu_to_ncp(ncph, name);
	} else {
		/*
		 * Order is important here, remove IP NCU first to prevent
		 * propogation of down event from link to IP.  No need to
		 * create REFRESH or DESTROY events.  They are generated by
		 * nwam_ncu_commit() and nwam_ncu_destroy().
		 */
		remove_ncu_from_ncp(ncph, name, NWAM_NCU_TYPE_INTERFACE);
		remove_ncu_from_ncp(ncph, name, NWAM_NCU_TYPE_LINK);
	}
	nwam_ncp_free(ncph);

	/*
	 * If the Automatic NCP is not active, and the associated NCUs
	 * exist, they must be moved into the appropriate states given the
	 * action that has occurred.
	 */
	if (!automatic_ncp_active) {
		ncu_action_change_state(action, NWAM_NCU_TYPE_INTERFACE, name);
		ncu_action_change_state(action, NWAM_NCU_TYPE_LINK, name);
	}

	/* Need NCU check to evaluate state in light of added/removed NCUs */
	if (!nwamd_event_enqueued(NWAM_EVENT_TYPE_NCU_CHECK,
	    NWAM_OBJECT_TYPE_NCP, NULL)) {
		nwamd_create_ncu_check_event(NEXT_FEW_SECONDS);
	}

fail:
	free(name);
	if (err != NWAM_SUCCESS) {
		nwamd_event_t retry_event = nwamd_event_init_link_action(name,
		    action);
		if (retry_event == NULL) {
			nlog(LOG_ERR, "nwamd_ncu_handle_link_action_event: "
			    "could not create retry event to read/create "
			    "%s NCP", NWAM_NCP_NAME_AUTOMATIC);
			return;
		}

		nlog(LOG_ERR, "nwamd_ncu_handle_link_action_event: "
		    "could not read/create %s NCP, retrying in %d seconds",
		    NWAM_NCP_NAME_AUTOMATIC, NWAMD_READONLY_RETRY_INTERVAL);
		nwamd_event_enqueue_timed(retry_event,
		    NWAMD_READONLY_RETRY_INTERVAL);
	}
}

/*
 * Figure out if this link is part of an aggregation.  This is fairly
 * inefficient since we generate this list for every query and search
 * linearly.  A better way would be to generate the list of links in an
 * aggregation once and then check each link against it.
 */
struct link_aggr_search_data {
	datalink_id_t linkid;
	boolean_t under;
};

static int
ncu_aggr_search(const char *name, void *data)
{
	struct link_aggr_search_data *lasd = data;
	dladm_aggr_grp_attr_t ginfo;
	datalink_id_t linkid;
	int i;

	if (dladm_name2info(dld_handle, name, &linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	if (dladm_aggr_info(dld_handle, linkid, &ginfo, DLADM_OPT_ACTIVE)
	    != DLADM_STATUS_OK || ginfo.lg_nports == 0)
		return (DLADM_WALK_CONTINUE);

	for (i = 0; i < ginfo.lg_nports; i++) {
		if (lasd->linkid == ginfo.lg_ports[i].lp_linkid) {
			lasd->under = B_TRUE;
			return (DLADM_WALK_TERMINATE);
		}
	}
	free(ginfo.lg_ports);
	return (DLADM_WALK_CONTINUE);
}

static boolean_t
nwamd_link_belongs_to_an_aggr(const char *name)
{
	struct link_aggr_search_data lasd;

	if (dladm_name2info(dld_handle, name, &lasd.linkid, NULL, NULL, NULL)
	    != DLADM_STATUS_OK)
		return (B_FALSE);
	lasd.under = B_FALSE;
	(void) dladm_walk(ncu_aggr_search, dld_handle, &lasd,
	    DATALINK_CLASS_AGGR, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	return (lasd.under);
}

/*
 * If NCU doesn't exist for interface with given name, enqueue a ADD
 * LINK_ACTION event.
 */
static int
ncu_create_link_action_event(const char *name, void *data)
{
	nwam_ncp_handle_t ncph = data;
	nwam_ncu_handle_t ncuh;
	nwamd_event_t link_event;

	/* Do not generate an event if this is a VirtualBox interface. */
	if (strncmp(name, VBOX_IFACE_PREFIX, strlen(VBOX_IFACE_PREFIX)) == 0)
		return (DLADM_WALK_CONTINUE);

	/* Do not generate an event if this link belongs to another zone. */
	if (!nwamd_link_belongs_to_this_zone(name))
		return (DLADM_WALK_CONTINUE);

	/* Do not generate an event if this link belongs to an aggregation. */
	if (nwamd_link_belongs_to_an_aggr(name)) {
		return (DLADM_WALK_CONTINUE);
	}

	/* Don't create an event if the NCU already exists. */
	if (ncph != NULL && nwam_ncu_read(ncph, name, NWAM_NCU_TYPE_LINK, 0,
	    &ncuh) == NWAM_SUCCESS) {
		nwam_ncu_free(ncuh);
		return (DLADM_WALK_CONTINUE);
	}

	nlog(LOG_DEBUG, "ncu_create_link_action_event: adding ncus for %s",
	    name);

	link_event = nwamd_event_init_link_action(name, NWAM_ACTION_ADD);
	if (link_event != NULL)
		nwamd_event_enqueue(link_event);

	return (DLADM_WALK_CONTINUE);
}

/*
 * Check if interface exists for this NCU. If not, enqueue a REMOVE
 * LINK_ACTION event.
 */
/* ARGSUSED */
static int
nwamd_destroy_ncu(nwam_ncu_handle_t ncuh, void *data)
{
	char *name;
	uint32_t flags;
	nwamd_event_t link_event;

	if (nwam_ncu_get_name(ncuh, &name) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_destroy_ncu: could not get NCU name");
		return (0);
	}

	/* Interfaces that exist return DLADM_OPT_ACTIVE flag */
	if ((dladm_name2info(dld_handle, name, NULL, &flags, NULL, NULL)
	    == DLADM_STATUS_OK && (flags & DLADM_OPT_ACTIVE)) &&
	    !nwamd_link_belongs_to_an_aggr(name)) {
		free(name);
		return (0);
	}

	nlog(LOG_DEBUG, "nwamd_destroy_ncu: destroying ncus for %s", name);

	link_event = nwamd_event_init_link_action(name, NWAM_ACTION_REMOVE);
	if (link_event != NULL)
		nwamd_event_enqueue(link_event);
	free(name);
	return (0);
}

/*
 * Called when nwamd is starting up.
 *
 * Walk all NCUs and destroy any NCU from the Automatic NCP without an
 * underlying interface (assumption here is that the interface was removed
 * when nwam was disabled).
 *
 * Walk the physical interfaces and create ADD LINK_ACTION event, which
 * will create appropriate interface and link NCUs in the Automatic NCP.
 */
void
nwamd_walk_physical_configuration(void)
{
	nwam_ncp_handle_t ncph;
	datalink_class_t dlclass = DATALINK_CLASS_PHYS;
	zoneid_t zoneid = getzoneid();

	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (strcmp(active_ncp, NWAM_NCP_NAME_AUTOMATIC) == 0 &&
	    active_ncph != NULL) {
		ncph = active_ncph;
	} else {
		if (nwam_ncp_read(NWAM_NCP_NAME_AUTOMATIC, 0, &ncph)
		    != NWAM_SUCCESS) {
			ncph = NULL;
		}
	}

	/* destroy NCUs for interfaces that don't exist */
	if (ncph != NULL) {
		(void) nwam_ncp_walk_ncus(ncph, nwamd_destroy_ncu, NULL,
		    NWAM_FLAG_NCU_TYPE_LINK, NULL);
	}

	/* In non-global zones NWAM can support VNICs */
	if (zoneid != GLOBAL_ZONEID)
		dlclass |= DATALINK_CLASS_VNIC;

	/* create NCUs for interfaces without NCUs */
	(void) dladm_walk(ncu_create_link_action_event, dld_handle, ncph,
	    dlclass, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);

	if (strcmp(active_ncp, NWAM_NCP_NAME_AUTOMATIC) != 0 ||
	    active_ncph == NULL) {
		nwam_ncp_free(ncph);
	}
	(void) pthread_mutex_unlock(&active_ncp_mutex);
}

/*
 * Handle NCU initialization/refresh event.
 */
void
nwamd_ncu_handle_init_event(nwamd_event_t event)
{
	nwamd_object_t object = NULL;
	nwam_ncu_handle_t ncuh;
	nwamd_ncu_t *ncu = NULL;
	nwam_error_t err;
	nwam_ncu_type_t type;
	char *name;
	uint32_t flags;
	boolean_t new = B_TRUE;

	nlog(LOG_DEBUG, "nwamd_ncu_handle_init_event(%s)",
	    event->event_object);

	/* Get base linkname rather than interface:linkname or link:linkname */
	err = nwam_ncu_typed_name_to_name(event->event_object,
	    &type, &name);
	if (err != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_ncu_handle_init_event: "
		    "nwam_ncu_typed_name_to_name returned %s",
		    nwam_strerror(err));
		nwamd_event_do_not_send(event);
		return;
	}

	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (active_ncph == NULL) {
		nlog(LOG_DEBUG,
		    "nwamd_ncu_handle_init_event: active NCP handle NULL");
		nwamd_event_do_not_send(event);
		free(name);
		(void) pthread_mutex_unlock(&active_ncp_mutex);
		return;
	}
	err = nwam_ncu_read(active_ncph, event->event_object,
	    type, 0, &ncuh);
	(void) pthread_mutex_unlock(&active_ncp_mutex);
	if (err != NWAM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_ncu_handle_init_event: "
		    "could not read object '%s': %s",
		    event->event_object, nwam_strerror(err));
		free(name);
		nwamd_event_do_not_send(event);
		return;
	}

	if ((object = nwamd_object_find(NWAM_OBJECT_TYPE_NCU,
	    event->event_object)) != NULL)
		new = B_FALSE;

	/*
	 * For new NCUs, or interface NCUs, we (re)initialize data from scratch.
	 * For link NCUs, we want to retain object data.
	 */
	switch (type) {
	case NWAM_NCU_TYPE_LINK:
		if (new) {
			ncu = nwamd_ncu_init(type, name);
		} else {
			ncu = object->nwamd_object_data;
			nwam_ncu_free(object->nwamd_object_handle);
		}
		populate_common_ncu_properties(ncuh, ncu);
		populate_link_ncu_properties(ncuh, ncu);
		break;
	case NWAM_NCU_TYPE_INTERFACE:
		if (!new) {
			nwam_ncu_free(object->nwamd_object_handle);
			nwamd_ncu_free(object->nwamd_object_data);
		}
		ncu = nwamd_ncu_init(type, name);
		populate_common_ncu_properties(ncuh, ncu);
		populate_ip_ncu_properties(ncuh, ncu);
		break;
	default:
		nlog(LOG_ERR, "unknown ncu type %d", type);
		free(name);
		nwam_ncu_free(ncuh);
		nwamd_event_do_not_send(event);
		nwamd_object_release(object);
		return;
	}

	if (new) {
		nlog(LOG_DEBUG, "nwamd_ncu_handle_init_event: didn't find "
		    "ncu so create it %s", name);
		object = nwamd_object_init(NWAM_OBJECT_TYPE_NCU,
		    event->event_object, ncuh, ncu);
	} else {
		nlog(LOG_DEBUG, "nwamd_ncu_handle_init_event: refreshing "
		    "ncu %s", name);
		object->nwamd_object_data = ncu;
		object->nwamd_object_handle = ncuh;
	}

	/*
	 * If the physical link for this NCU doesn't exist in the system,
	 * the state should be UNINITIALIZED/NOT_FOUND.  Interfaces that
	 * exist return DLADM_OPT_ACTIVE flag.
	 */
	if (dladm_name2info(dld_handle, name, NULL, &flags, NULL, NULL)
	    != DLADM_STATUS_OK || !(flags & DLADM_OPT_ACTIVE)) {
		nlog(LOG_DEBUG, "nwam_ncu_handle_init_event: "
		    "interface for NCU %s doesn't exist",
		    event->event_object);
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
		    object->nwamd_object_name, NWAM_STATE_UNINITIALIZED,
		    NWAM_AUX_STATE_NOT_FOUND);
		free(name);
		nwamd_object_release(object);
		return;
	}

	/*
	 * If NCU is being initialized (rather than refreshed), the
	 * object_state is INITIALIZED (from nwamd_object_init()).
	 */
	if (object->nwamd_object_state == NWAM_STATE_INITIALIZED) {
		/*
		 * If the NCU is disabled, initial state should be DISABLED.
		 *
		 * Otherwise, the initial state will be
		 * OFFLINE/CONDITIONS_NOT_MET, and the link selection
		 * algorithm will do the rest.
		 */
		if (!ncu->ncu_enabled) {
			object->nwamd_object_state = NWAM_STATE_DISABLED;
			object->nwamd_object_aux_state =
			    NWAM_AUX_STATE_MANUAL_DISABLE;
		} else {
			object->nwamd_object_state = NWAM_STATE_OFFLINE;
			object->nwamd_object_aux_state =
			    NWAM_AUX_STATE_CONDITIONS_NOT_MET;
		}
	} else {
		nwamd_link_t *link = &ncu->ncu_link;

		/*
		 * Refresh NCU.  Deal with disabled cases first, moving NCUs
		 * that are not disabled - but have the enabled value set - to
		 * the disabled state.  Then handle cases where the NCU was
		 * disabled but is no longer.  Finally,  deal with refresh of
		 * link and interface NCUs, as these are handled differently.
		 */
		if (!ncu->ncu_enabled) {
			if (object->nwamd_object_state != NWAM_STATE_DISABLED) {
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    object->nwamd_object_name,
				    NWAM_STATE_ONLINE_TO_OFFLINE,
				    NWAM_AUX_STATE_MANUAL_DISABLE);
			}
			goto done;
		} else {
			if (object->nwamd_object_state == NWAM_STATE_DISABLED) {
				int64_t c;

				/*
				 * Try to activate the NCU if manual or
				 * prioritized (when priority <= current).
				 */
				(void) pthread_mutex_lock(&active_ncp_mutex);
				c = current_ncu_priority_group;
				(void) pthread_mutex_unlock(&active_ncp_mutex);
				if (link->nwamd_link_activation_mode ==
				    NWAM_ACTIVATION_MODE_MANUAL ||
				    (link->nwamd_link_activation_mode ==
				    NWAM_ACTIVATION_MODE_PRIORITIZED &&
				    link->nwamd_link_priority_mode <= c)) {
					nwamd_object_set_state
					    (NWAM_OBJECT_TYPE_NCU,
					    object->nwamd_object_name,
					    NWAM_STATE_OFFLINE_TO_ONLINE,
					    NWAM_AUX_STATE_INITIALIZED);
				} else {
					nwamd_object_set_state
					    (NWAM_OBJECT_TYPE_NCU,
					    object->nwamd_object_name,
					    NWAM_STATE_OFFLINE_TO_ONLINE,
					    NWAM_AUX_STATE_INITIALIZED);
				}
				goto done;
			}
		}

		switch (type) {
		case NWAM_NCU_TYPE_LINK:
			if (ncu->ncu_link.nwamd_link_media == DL_WIFI) {
				/*
				 * Do rescan.  If the current state and the
				 * active priority-group do not allow wireless
				 * network selection, then it won't happen.
				 */
				(void) nwamd_wlan_scan(ncu->ncu_name);
			}
			break;
		case NWAM_NCU_TYPE_INTERFACE:
			/*
			 * If interface NCU is offline*, online or in
			 * maintenance, mark it down (from there, it will be
			 * reinitialized to reapply addresses).
			 */
			if (object->nwamd_object_state != NWAM_STATE_OFFLINE) {
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    object->nwamd_object_name,
				    NWAM_STATE_ONLINE_TO_OFFLINE,
				    NWAM_AUX_STATE_DOWN);
			} else {
				object->nwamd_object_state = NWAM_STATE_OFFLINE;
				object->nwamd_object_aux_state =
				    NWAM_AUX_STATE_CONDITIONS_NOT_MET;
			}
			break;
		}
	}

done:
	if (type == NWAM_NCU_TYPE_LINK &&
	    !nwamd_event_enqueued(NWAM_EVENT_TYPE_NCU_CHECK,
	    NWAM_OBJECT_TYPE_NCP, NULL)) {
		nwamd_create_ncu_check_event(NEXT_FEW_SECONDS);
	}
	free(name);
	nwamd_object_release(object);
}

void
nwamd_ncu_handle_fini_event(nwamd_event_t event)
{
	nwamd_object_t object;
	nwamd_event_t state_event;

	nlog(LOG_DEBUG, "nwamd_ncu_handle_fini_event(%s)",
	    event->event_object);

	/*
	 * Simulate a state event so that the state machine can correctly
	 * disable the NCU.  Then free up allocated objects.
	 */
	state_event = nwamd_event_init_object_state(NWAM_OBJECT_TYPE_NCU,
	    event->event_object, NWAM_STATE_ONLINE_TO_OFFLINE,
	    NWAM_AUX_STATE_UNINITIALIZED);
	if (state_event == NULL) {
		nwamd_event_do_not_send(event);
		return;
	}
	nwamd_ncu_handle_state_event(state_event);
	nwamd_event_fini(state_event);

	if ((object = nwamd_object_find(NWAM_OBJECT_TYPE_NCU,
	    event->event_object)) == NULL) {
		nlog(LOG_INFO, "nwamd_ncu_handle_fini_event: "
		    "ncu %s not found", event->event_object);
		nwamd_event_do_not_send(event);
		return;
	}
	nwamd_object_release_and_destroy(object);
}

void
nwamd_ncu_handle_action_event(nwamd_event_t event)
{
	nwamd_object_t object;

	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (strcmp(event->event_msg->nwe_data.nwe_object_action.nwe_parent,
	    active_ncp) != 0) {
		nlog(LOG_DEBUG, "nwamd_ncu_handle_action_event: action for "
		    "inactive NCP %s, nothing to do",
		    event->event_msg->nwe_data.nwe_object_action.nwe_parent);
		(void) pthread_mutex_unlock(&active_ncp_mutex);
		return;
	}
	(void) pthread_mutex_unlock(&active_ncp_mutex);

	switch (event->event_msg->nwe_data.nwe_object_action.nwe_action) {
	case NWAM_ACTION_ENABLE:
		object = nwamd_object_find(NWAM_OBJECT_TYPE_NCU,
		    event->event_object);
		if (object == NULL) {
			nlog(LOG_ERR, "nwamd_ncu_handle_action_event: "
			    "could not find ncu %s", event->event_object);
			nwamd_event_do_not_send(event);
			return;
		}
		if (object->nwamd_object_state == NWAM_STATE_ONLINE) {
			nlog(LOG_DEBUG, "nwamd_ncu_handle_action_event: "
			    "ncu %s already online, nothing to do",
			    event->event_object);
			nwamd_object_release(object);
			return;
		}
		nwamd_object_release(object);

		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
		    event->event_object, NWAM_STATE_OFFLINE_TO_ONLINE,
		    NWAM_AUX_STATE_INITIALIZED);
		break;
	case NWAM_ACTION_DISABLE:
		object = nwamd_object_find(NWAM_OBJECT_TYPE_NCU,
		    event->event_object);
		if (object == NULL) {
			nlog(LOG_ERR, "nwamd_ncu_handle_action_event: "
			    "could not find ncu %s", event->event_object);
			nwamd_event_do_not_send(event);
			return;
		}
		if (object->nwamd_object_state == NWAM_STATE_DISABLED) {
			nlog(LOG_DEBUG, "nwamd_ncu_handle_action_event: "
			    "ncu %s already disabled, nothing to do",
			    event->event_object);
			nwamd_object_release(object);
			return;
		}
		nwamd_object_release(object);

		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
		    event->event_object, NWAM_STATE_ONLINE_TO_OFFLINE,
		    NWAM_AUX_STATE_MANUAL_DISABLE);
		break;
	case NWAM_ACTION_ADD:
	case NWAM_ACTION_REFRESH:
		nwamd_ncu_handle_init_event(event);
		break;
	case NWAM_ACTION_DESTROY:
		nwamd_ncu_handle_fini_event(event);
		break;
	default:
		nlog(LOG_INFO, "nwam_ncu_handle_action_event: "
		    "unexpected action");
		nwamd_event_do_not_send(event);
		break;
	}
}

void
nwamd_ncu_handle_state_event(nwamd_event_t event)
{
	nwamd_object_t object;
	nwam_state_t old_state, new_state;
	nwam_aux_state_t new_aux_state;
	nwamd_ncu_t *ncu;
	boolean_t is_link, enabled, prioritized = B_FALSE;
	char linkname[NWAM_MAX_NAME_LEN];
	nwam_event_t m = event->event_msg;

	if ((object = nwamd_object_find(NWAM_OBJECT_TYPE_NCU,
	    event->event_object)) == NULL) {
		nlog(LOG_INFO, "nwamd_ncu_handle_state_event %lld: "
		    "state event for nonexistent NCU %s", event->event_id,
		    event->event_object);
		nwamd_event_do_not_send(event);
		return;
	}
	ncu = object->nwamd_object_data;
	old_state = object->nwamd_object_state;
	new_state = event->event_msg->nwe_data.nwe_object_state.nwe_state;
	new_aux_state =
	    event->event_msg->nwe_data.nwe_object_state.nwe_aux_state;

	/*
	 * For NCU state changes, we need to supply the parent NCP name also,
	 * regardless of whether the event is handled or not.  It is best to
	 * fill this in here as we have the object lock - when we create
	 * object state events we sometimes do not have the object lock, but
	 * at this point in consuming the events (and prior to the associated
	 * event message being sent out) we do.
	 */
	(void) strlcpy(m->nwe_data.nwe_object_state.nwe_parent, ncu->ncu_parent,
	    sizeof (m->nwe_data.nwe_object_state.nwe_parent));

	/*
	 * If we receive a state change event moving this NCU to
	 * DHCP_TIMED_OUT or UP state but this NCU is already ONLINE, then
	 * ignore this state change event.
	 */
	if ((new_aux_state == NWAM_AUX_STATE_IF_DHCP_TIMED_OUT ||
	    new_aux_state == NWAM_AUX_STATE_UP) &&
	    object->nwamd_object_state == NWAM_STATE_ONLINE) {
		nlog(LOG_INFO, "nwamd_ncu_handle_state_event: "
		    "NCU %s already online, not going to '%s' state",
		    object->nwamd_object_name,
		    nwam_aux_state_to_string(new_aux_state));
		nwamd_event_do_not_send(event);
		nwamd_object_release(object);
		return;
	}

	if (new_state == object->nwamd_object_state &&
	    new_aux_state == object->nwamd_object_aux_state) {
		nlog(LOG_DEBUG, "nwamd_ncu_handle_state_event: "
		    "NCU %s already in state (%s, %s)",
		    object->nwamd_object_name, nwam_state_to_string(new_state),
		    nwam_aux_state_to_string(new_aux_state));
		nwamd_object_release(object);
		return;
	}

	if (old_state == NWAM_STATE_MAINTENANCE &&
	    (new_state == NWAM_STATE_ONLINE ||
	    (new_state == NWAM_STATE_OFFLINE_TO_ONLINE &&
	    new_aux_state != NWAM_AUX_STATE_INITIALIZED))) {
		nlog(LOG_DEBUG, "nwamd_ncu_handle_state_event: "
		    "NCU %s cannot transition from state %s to state (%s, %s)",
		    object->nwamd_object_name, nwam_state_to_string(old_state),
		    nwam_state_to_string(new_state),
		    nwam_aux_state_to_string(new_aux_state));
		nwamd_event_do_not_send(event);
		nwamd_object_release(object);
		return;
	}

	object->nwamd_object_state = new_state;
	object->nwamd_object_aux_state = new_aux_state;

	nlog(LOG_DEBUG, "nwamd_ncu_handle_state_event: changing state for NCU "
	    "%s to (%s, %s)", object->nwamd_object_name,
	    nwam_state_to_string(object->nwamd_object_state),
	    nwam_aux_state_to_string(object->nwamd_object_aux_state));

	is_link = (ncu->ncu_type == NWAM_NCU_TYPE_LINK);
	if (is_link)
		(void) strlcpy(linkname, ncu->ncu_name, sizeof (linkname));
	prioritized = (ncu->ncu_type == NWAM_NCU_TYPE_LINK &&
	    ncu->ncu_link.nwamd_link_activation_mode ==
	    NWAM_ACTIVATION_MODE_PRIORITIZED);
	enabled = ncu->ncu_enabled;

	nwamd_object_release(object);

	/*
	 * State machine for NCUs
	 */
	switch (new_state) {
	case NWAM_STATE_OFFLINE_TO_ONLINE:
		if (enabled) {
			nwamd_ncu_state_machine(event->event_object);
		} else {
			nlog(LOG_DEBUG, "nwamd_ncu_handle_state_event: "
			    "cannot move disabled NCU %s online",
			    event->event_object);
			nwamd_event_do_not_send(event);
		}
		break;

	case NWAM_STATE_ONLINE_TO_OFFLINE:
		nwamd_ncu_state_machine(event->event_object);
		break;

	case NWAM_STATE_ONLINE:
		/*
		 * We usually don't need to do anything when we're in the
		 * ONLINE state.  However, for  WiFi we can be in INIT or
		 * SCAN aux states while being ONLINE.
		 */
		nwamd_ncu_state_machine(event->event_object);
		break;

	case NWAM_STATE_OFFLINE:
		/* Reassess priority group now member is offline */
		if (prioritized) {
			nwamd_create_ncu_check_event(0);
		}
		break;

	case NWAM_STATE_DISABLED:
	case NWAM_STATE_UNINITIALIZED:
	case NWAM_STATE_MAINTENANCE:
	case NWAM_STATE_DEGRADED:
	default:
		/* do nothing */
		break;
	}

	if (is_link) {
		if ((new_state == NWAM_STATE_ONLINE_TO_OFFLINE &&
		    new_aux_state != NWAM_AUX_STATE_UNINITIALIZED &&
		    new_aux_state != NWAM_AUX_STATE_NOT_FOUND) ||
		    new_state == NWAM_STATE_DISABLED) {
			/*
			 * Going offline, propogate down event to IP NCU.  Do
			 * not propogate event if new aux state is uninitialized
			 * or not found as these auxiliary states signify
			 * that an NCP switch/device removal is in progress.
			 */
			nwamd_propogate_link_up_down_to_ip(linkname, B_FALSE);
		}
		if (new_state == NWAM_STATE_ONLINE) {
			/* gone online, propogate up event to IP NCU */
			nwamd_propogate_link_up_down_to_ip(linkname, B_TRUE);
		}
	} else {
		/* If IP NCU is online, reasses priority group */
		if (new_state == NWAM_STATE_ONLINE)
			nwamd_create_ncu_check_event(0);
	}
}
