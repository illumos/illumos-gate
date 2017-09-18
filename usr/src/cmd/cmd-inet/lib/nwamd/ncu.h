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

#ifndef _NCU_H
#define	_NCU_H

#include <dhcpagent_ipc.h>
#include <dhcpagent_util.h>
#include <libdladm.h>
#include <libdlpi.h>
#include <libdlwlan.h>
#include <libinetutil.h>
#include <libipadm.h>
#include <libnwam.h>
#include <libnwam_priv.h>
#include <libuutil.h>
#include <pthread.h>
#include <sys/mac.h>

#include "events.h"

extern pthread_mutex_t active_ncp_mutex;
extern pthread_mutex_t active_loc_mutex;
extern char active_loc[];
extern uint64_t wireless_scan_interval;
extern dladm_wlan_strength_t wireless_scan_level;
extern boolean_t wireless_autoconf;
extern boolean_t wireless_strict_bssid;

/*
 * NCPs are collections of NCUs.  At the moment there is one NCP in the system
 * and its expected there will never be many.  There is a lock on the NCP which
 * must be obtained to add or remove anything from the NCP.
 *
 * NCUs are also kept in a uu list for easy walking.  Each NCU has a lock which
 * is used to protect manipulation of its contents.  One of its members is a
 * reference count which is initialized to 1 when its placed on the NCP.  As
 * references are passed around that should be manipulated as necessary
 * (helper functions YYY provided).  It is removed from the NCP by
 * ncu_destroy() but the memory containing it is not returned to the free pool
 * until the reference count falls to 0.
 *
 * As we add
 * more complex system objects their relationship becomes more complex.  That
 * is represented by the links within the NCUs.  Reference counts should be
 * used to maintain the consistency of these links.  Care should be used when
 * walking more complex structures that might contain cycles.
 */

/* Stores details of last/current WiFi scans */
typedef struct nwamd_wifi_scan {
	char nwamd_wifi_scan_link[NWAM_MAX_NAME_LEN];
	nwam_wlan_t nwamd_wifi_scan_last[NWAMD_MAX_NUM_WLANS];
	uint_t nwamd_wifi_scan_last_num;
	nwam_wlan_t nwamd_wifi_scan_curr[NWAMD_MAX_NUM_WLANS];
	uint_t nwamd_wifi_scan_curr_num;
	boolean_t nwamd_wifi_scan_changed;
	uint32_t nwamd_wifi_scan_last_time;
} nwamd_wifi_scan_t;

typedef struct nwamd_link {
	pthread_mutex_t nwamd_link_wifi_mutex;
	pthread_t nwamd_link_wifi_scan_thread;
	pthread_t nwamd_link_wifi_monitor_thread;
	char nwamd_link_wifi_essid[DLADM_STRSIZE];
	char nwamd_link_wifi_bssid[DLADM_STRSIZE];
	char nwamd_link_wifi_keyname[DLADM_STRSIZE];
	char nwamd_link_wifi_signal_strength[DLADM_STRSIZE];
	boolean_t nwamd_link_wifi_add_to_known_wlans;
	boolean_t nwamd_link_wifi_connected;
	uint32_t nwamd_link_wifi_security_mode;
	dladm_wlan_key_t *nwamd_link_wifi_key;
	nwamd_wifi_scan_t nwamd_link_wifi_scan;
	uint64_t nwamd_link_wifi_priority;
	boolean_t nwamd_link_wifi_autoconf;
	uint32_t nwamd_link_id;
	uint32_t nwamd_link_media;
	uint64_t nwamd_link_flags;
	dlpi_handle_t nwamd_link_dhp;
	pthread_t nwamd_link_dlpi_thread;
	uint64_t nwamd_link_activation_mode;
	uint64_t nwamd_link_priority_mode;
	uint64_t nwamd_link_priority_group;
	char *nwamd_link_mac_addr;
	size_t nwamd_link_mac_addr_len;
	uint64_t nwamd_link_mtu;
	char **nwamd_link_autopush;
	uint_t nwamd_link_num_autopush;
} nwamd_link_t;

struct nwamd_if_address {
	sa_family_t family;
	ipadm_addr_type_t ipaddr_atype;
	ipadm_addrobj_t ipaddr;
	boolean_t configured;
	struct sockaddr_storage conf_addr;	/* address configured for */
	struct sockaddr_storage conf_stateless_addr; /* this nwamd_if_address */
	struct nwamd_if_address *next;
};

typedef struct nwamd_if {
	boolean_t nwamd_if_dhcp_requested;
	boolean_t nwamd_if_dhcp_configured;
	boolean_t nwamd_if_stateful_requested;
	boolean_t nwamd_if_stateful_configured;
	boolean_t nwamd_if_stateless_requested;
	boolean_t nwamd_if_stateless_configured;
	struct nwamd_if_address *nwamd_if_list;
	struct sockaddr_in nwamd_if_ipv4_default_route;
	boolean_t nwamd_if_ipv4_default_route_set;
	struct sockaddr_in6 nwamd_if_ipv6_default_route;
	boolean_t nwamd_if_ipv6_default_route_set;
	boolean_t nwamd_if_ipv4;
	boolean_t nwamd_if_ipv6;
} nwamd_if_t;

typedef struct nwamd_ncu {
	nwam_ncu_type_t ncu_type;
	char *ncu_name;
	char ncu_parent[NWAM_MAX_NAME_LEN];
	boolean_t ncu_enabled; /* whether NCU has been enabled or not */
	union {
		nwamd_link_t u_link;
		nwamd_if_t u_if;
	} ncu_node;
} nwamd_ncu_t;

#define	ncu_link	ncu_node.u_link
#define	ncu_if		ncu_node.u_if

#define	LOOPBACK_IF				"lo0"

struct nwamd_dhcp_thread_arg {
	char *name;
	dhcp_ipc_type_t type;
	ipadm_addrobj_t ipaddr;
	volatile uint32_t *guard;
};

#define	WIRELESS_SCAN_INTERVAL_DEFAULT		120
#define	WIRELESS_SCAN_INTERVAL_MIN		30
#define	WIRELESS_SCAN_REQUESTED_INTERVAL_MIN	10
#define	WIRELESS_MONITOR_SIGNAL_INTERVAL	10
#define	WIRELESS_RETRY_INTERVAL			30
#define	WIRELESS_SCAN_LEVEL_DEFAULT		DLADM_WLAN_STRENGTH_WEAK
#define	NWAMD_DHCP_RETRIES			5
#define	NWAMD_DHCP_RETRY_WAIT_TIME		10
#define	NWAMD_READONLY_RETRY_INTERVAL		5

/*
 * This dladm and ipadm handles are opened before interfaces are initialized
 * and closed only when nwamd shuts down.
 */
extern dladm_handle_t dld_handle;
extern ipadm_handle_t ipadm_handle;

extern nwamd_object_t nwamd_ncu_object_find(nwam_ncu_type_t, const char *);
extern void nwamd_log_ncus(void);
extern void nwamd_ncu_free(nwamd_ncu_t *);

/* WLAN functions */
extern void nwamd_set_selected_connected(nwamd_ncu_t *, boolean_t, boolean_t);
extern nwam_error_t nwamd_wlan_select(const char *, const char *, const char *,
    uint32_t, boolean_t);
extern nwam_error_t nwamd_wlan_set_key(const char *, const char *, const char *,
    uint32_t, uint_t, char *);
extern nwam_error_t nwamd_wlan_scan(const char *);
extern void nwamd_wlan_connect(const char *);
extern boolean_t nwamd_wlan_connected(nwamd_object_t);
extern void nwamd_wlan_monitor_signal(const char *);
extern void nwamd_ncu_create_periodic_scan_event(nwamd_object_t);
extern dladm_wlan_key_t *nwamd_wlan_get_key_named(const char *, uint32_t);
extern void nwamd_set_key_name(const char *, const char *, char *, size_t);

/* Link functions */
extern link_state_t nwamd_get_link_state(const char *);
extern const char *nwamd_sockaddr_to_str(const struct sockaddr *, char *,
    size_t);
extern void nwamd_propogate_link_up_down_to_ip(const char *, boolean_t);
extern void nwamd_set_unset_link_properties(nwamd_ncu_t *, boolean_t);
/* DLPI event hooking */
extern void nwamd_dlpi_add_link(nwamd_object_t);
extern void nwamd_dlpi_delete_link(nwamd_object_t);

/* IP functions */
extern boolean_t nwamd_static_addresses_configured(nwamd_ncu_t *, sa_family_t);
extern void nwamd_plumb_interface(nwamd_ncu_t *, sa_family_t);
extern void nwamd_unplumb_interface(nwamd_ncu_t *, sa_family_t);
extern boolean_t nwamd_dhcp_managing(int, nwamd_ncu_t *);
extern void nwamd_configure_interface_addresses(nwamd_ncu_t *);
extern char *nwamd_get_dhcpinfo_data(const char *, char *);
extern void nwamd_dhcp_release(const char *);
extern void nwamd_add_default_routes(nwamd_ncu_t *);
extern void nwamd_add_route(struct sockaddr *, struct sockaddr *,
    struct sockaddr *, const char *);

/* NCU value set/get functions */
extern nwam_error_t nwamd_set_ncu_uint(nwam_ncu_handle_t, uint64_t *, uint_t,
    const char *);
extern nwam_error_t nwamd_set_ncu_string(nwam_ncu_handle_t, char **, uint_t,
    const char *);
extern nwam_error_t nwamd_get_ncu_uint(nwam_ncu_handle_t, nwam_value_t *,
    uint64_t **, uint_t *, const char *);
extern nwam_error_t nwamd_get_ncu_string(nwam_ncu_handle_t, nwam_value_t *,
    char ***, uint_t *, const char *);
extern nwam_error_t nwamd_get_ncu_boolean(nwam_ncu_handle_t, nwam_value_t *,
    boolean_t **, uint_t *, const char *);

extern void nwamd_walk_physical_configuration(void);

#endif /* _NCU_H */
