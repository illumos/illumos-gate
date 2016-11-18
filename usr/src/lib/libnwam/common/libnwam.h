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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

/*
 * This file contains data structures and APIs of libnwam.
 * Implementation is MT safe.
 */
#ifndef _LIBNWAM_H
#define	_LIBNWAM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <bsm/adt.h>
#include <net/if.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/types.h>
#include <sys/socket.h>

/*
 * Note - several interface functions below are not utilized in ON, but are
 * used by the GNOME nwam-manager.  One example is nwam_enm_get_name().
 */

/*
 * Common definitions
 */

/* nwam FMRI and properties */
#define	NWAM_FMRI		"svc:/network/physical:nwam"
#define	NWAM_PG			"nwamd"
#define	NWAM_PROP_ACTIVE_NCP	"active_ncp"

/* nwam flags used for read/commit */
/* Block waiting for commit if necessary */
#define	NWAM_FLAG_BLOCKING		0x00000001
/* Committed object must be new */
#define	NWAM_FLAG_CREATE		0x00000002
/* Tell destroy functions not to free handle */
#define	NWAM_FLAG_DO_NOT_FREE		0x00000004
/* Object is being enabled/disabled */
#define	NWAM_FLAG_ENTITY_ENABLE		0x00000008
/* Known WLAN being read, committed or destroyed */
#define	NWAM_FLAG_ENTITY_KNOWN_WLAN	0x00000010

/* nwam flags used for selecting ncu type for walk */
#define	NWAM_FLAG_NCU_TYPE_LINK		0x00000001ULL << 32
#define	NWAM_FLAG_NCU_TYPE_INTERFACE	0x00000002ULL << 32
#define	NWAM_FLAG_NCU_TYPE_ALL		(NWAM_FLAG_NCU_TYPE_LINK | \
					NWAM_FLAG_NCU_TYPE_INTERFACE)

/* nwam flags used for selecting ncu class for walk */
#define	NWAM_FLAG_NCU_CLASS_PHYS		0x00000100ULL << 32
#define	NWAM_FLAG_NCU_CLASS_IP			0x00010000ULL << 32
#define	NWAM_FLAG_NCU_CLASS_ALL_LINK		NWAM_FLAG_NCU_CLASS_PHYS
#define	NWAM_FLAG_NCU_CLASS_ALL_INTERFACE	NWAM_FLAG_NCU_CLASS_IP
#define	NWAM_FLAG_NCU_CLASS_ALL		(NWAM_FLAG_NCU_CLASS_ALL_INTERFACE | \
					NWAM_FLAG_NCU_CLASS_ALL_LINK)
#define	NWAM_FLAG_NCU_TYPE_CLASS_ALL		(NWAM_FLAG_NCU_CLASS_ALL | \
						NWAM_FLAG_NCU_TYPE_ALL)

/* flags used for selecting activation for walk */
#define	NWAM_FLAG_ACTIVATION_MODE_MANUAL		0x000000001ULL << 32
#define	NWAM_FLAG_ACTIVATION_MODE_SYSTEM		0x000000002ULL << 32
#define	NWAM_FLAG_ACTIVATION_MODE_PRIORITIZED		0x000000004ULL << 32
#define	NWAM_FLAG_ACTIVATION_MODE_CONDITIONAL_ANY	0x000000008ULL << 32
#define	NWAM_FLAG_ACTIVATION_MODE_CONDITIONAL_ALL	0x000000010ULL << 32
#define	NWAM_FLAG_ACTIVATION_MODE_ALL	(NWAM_FLAG_ACTIVATION_MODE_MANUAL |\
					NWAM_FLAG_ACTIVATION_MODE_SYSTEM |\
					NWAM_FLAG_ACTIVATION_MODE_PRIORITIZED |\
				NWAM_FLAG_ACTIVATION_MODE_CONDITIONAL_ANY |\
				NWAM_FLAG_ACTIVATION_MODE_CONDITIONAL_ALL)

/* Walk known WLANs in order of priority (lowest first) */
#define	NWAM_FLAG_KNOWN_WLAN_WALK_PRIORITY_ORDER	0x000010000ULL << 32
/* Do not perform priority collision checking for known WLANs */
#define	NWAM_FLAG_KNOWN_WLAN_NO_COLLISION_CHECK		0x000020000ULL << 32

/* nwam return codes */
typedef enum {
	NWAM_SUCCESS,			/* No error occured */
	NWAM_LIST_END,			/* End of list reached */
	NWAM_INVALID_HANDLE,		/* Entity handle is invalid */
	NWAM_HANDLE_UNBOUND,		/* Handle not bound to entity */
	NWAM_INVALID_ARG,		/* Argument is invalid */
	NWAM_PERMISSION_DENIED,		/* Insufficient privileges for action */
	NWAM_NO_MEMORY,			/* Out of memory */
	NWAM_ENTITY_EXISTS,		/* Entity already exists */
	NWAM_ENTITY_IN_USE,		/* Entity in use */
	NWAM_ENTITY_COMMITTED,		/* Entity already committed */
	NWAM_ENTITY_NOT_FOUND,		/* Entity not found */
	NWAM_ENTITY_TYPE_MISMATCH,	/* Entity type mismatch */
	NWAM_ENTITY_INVALID,		/* Validation of entity failed */
	NWAM_ENTITY_INVALID_MEMBER,	/* Entity member invalid */
	NWAM_ENTITY_INVALID_STATE,	/* Entity is not in appropriate state */
	NWAM_ENTITY_INVALID_VALUE,	/* Validation of entity value failed */
	NWAM_ENTITY_MISSING_MEMBER,	/* Required member is missing */
	NWAM_ENTITY_NO_VALUE,		/* No value associated with entity */
	NWAM_ENTITY_MULTIPLE_VALUES,	/* Multiple values for entity */
	NWAM_ENTITY_READ_ONLY,		/* Entity is marked read only */
	NWAM_ENTITY_NOT_DESTROYABLE,	/* Entity cannot be destroyed */
	NWAM_ENTITY_NOT_MANUAL,	/* Entity cannot be manually enabled/disabled */
	NWAM_WALK_HALTED,		/* Callback function returned nonzero */
	NWAM_ERROR_BIND,		/* Could not bind to backend */
	NWAM_ERROR_BACKEND_INIT,	/* Could not initialize backend */
	NWAM_ERROR_INTERNAL		/* Internal error */
} nwam_error_t;

#define	NWAM_MAX_NAME_LEN		128
#define	NWAM_MAX_VALUE_LEN		256
#define	NWAM_MAX_FMRI_LEN		NWAM_MAX_VALUE_LEN
#define	NWAM_MAX_NUM_VALUES		32
#define	NWAM_MAX_NUM_PROPERTIES		32

/* used for getting and setting of properties */
typedef enum {
	NWAM_VALUE_TYPE_BOOLEAN,
	NWAM_VALUE_TYPE_INT64,
	NWAM_VALUE_TYPE_UINT64,
	NWAM_VALUE_TYPE_STRING,
	NWAM_VALUE_TYPE_UNKNOWN
} nwam_value_type_t;

/* Holds values of various types for getting and setting of properties */
/* Forward definition */
struct nwam_value;
typedef struct nwam_value *nwam_value_t;

/* Value-related functions. */
extern nwam_error_t nwam_value_create_boolean(boolean_t, nwam_value_t *);
extern nwam_error_t nwam_value_create_boolean_array(boolean_t *, uint_t,
    nwam_value_t *);
extern nwam_error_t nwam_value_create_int64(int64_t, nwam_value_t *);
extern nwam_error_t nwam_value_create_int64_array(int64_t *, uint_t,
    nwam_value_t *);
extern nwam_error_t nwam_value_create_uint64(uint64_t, nwam_value_t *);
extern nwam_error_t nwam_value_create_uint64_array(uint64_t *, uint_t,
    nwam_value_t *);
extern nwam_error_t nwam_value_create_string(char *, nwam_value_t *);
extern nwam_error_t nwam_value_create_string_array(char **, uint_t,
    nwam_value_t *);

extern nwam_error_t nwam_value_get_boolean(nwam_value_t, boolean_t *);
extern nwam_error_t nwam_value_get_boolean_array(nwam_value_t, boolean_t **,
    uint_t *);
extern nwam_error_t nwam_value_get_int64(nwam_value_t, int64_t *);
extern nwam_error_t nwam_value_get_int64_array(nwam_value_t, int64_t **,
    uint_t *);
extern nwam_error_t nwam_value_get_uint64(nwam_value_t, uint64_t *);
extern nwam_error_t nwam_value_get_uint64_array(nwam_value_t, uint64_t **,
    uint_t *);
extern nwam_error_t nwam_value_get_string(nwam_value_t, char **);
extern nwam_error_t nwam_value_get_string_array(nwam_value_t, char ***,
    uint_t *);

extern nwam_error_t nwam_value_get_type(nwam_value_t, nwam_value_type_t *);
extern nwam_error_t nwam_value_get_numvalues(nwam_value_t, uint_t *);

extern void nwam_value_free(nwam_value_t);
extern nwam_error_t nwam_value_copy(nwam_value_t, nwam_value_t *);

extern nwam_error_t nwam_uint64_get_value_string(const char *, uint64_t,
    const char **);
extern nwam_error_t nwam_value_string_get_uint64(const char *, const char *,
    uint64_t *);

/*
 * To retrieve a localized error string
 */
extern const char *nwam_strerror(nwam_error_t);

/*
 * State and auxiliary state describe the state of ENMs, NCUs and locations.
 */
typedef enum {
	NWAM_STATE_UNINITIALIZED = 0x0,
	NWAM_STATE_INITIALIZED = 0x1,
	NWAM_STATE_OFFLINE = 0x2,
	NWAM_STATE_OFFLINE_TO_ONLINE = 0x4,
	NWAM_STATE_ONLINE_TO_OFFLINE = 0x8,
	NWAM_STATE_ONLINE = 0x10,
	NWAM_STATE_MAINTENANCE = 0x20,
	NWAM_STATE_DEGRADED = 0x40,
	NWAM_STATE_DISABLED = 0x80
} nwam_state_t;

#define	NWAM_STATE_ANY	(NWAM_STATE_UNINITIALIZED | \
			NWAM_STATE_INITIALIZED | \
			NWAM_STATE_OFFLINE | \
			NWAM_STATE_OFFLINE_TO_ONLINE | \
			NWAM_STATE_ONLINE_TO_OFFLINE | \
			NWAM_STATE_ONLINE | \
			NWAM_STATE_MAINTENANCE | \
			NWAM_STATE_DEGRADED | \
			NWAM_STATE_DISABLED)

/*
 * The auxiliary state denotes specific reasons why an object is in a particular
 * state (e.g. "script failed", "disabled by administrator", "waiting for DHCP
 * response").
 */
typedef enum {
	/* General auxiliary states */
	NWAM_AUX_STATE_UNINITIALIZED,
	NWAM_AUX_STATE_INITIALIZED,
	NWAM_AUX_STATE_CONDITIONS_NOT_MET,
	NWAM_AUX_STATE_MANUAL_DISABLE,
	NWAM_AUX_STATE_METHOD_FAILED,
	NWAM_AUX_STATE_METHOD_MISSING,
	NWAM_AUX_STATE_METHOD_RUNNING,
	NWAM_AUX_STATE_INVALID_CONFIG,
	NWAM_AUX_STATE_ACTIVE,
	/* Link-specific auxiliary states */
	NWAM_AUX_STATE_LINK_WIFI_SCANNING,
	NWAM_AUX_STATE_LINK_WIFI_NEED_SELECTION,
	NWAM_AUX_STATE_LINK_WIFI_NEED_KEY,
	NWAM_AUX_STATE_LINK_WIFI_CONNECTING,
	/* IP interface-specific auxiliary states */
	NWAM_AUX_STATE_IF_WAITING_FOR_ADDR,
	NWAM_AUX_STATE_IF_DHCP_TIMED_OUT,
	NWAM_AUX_STATE_IF_DUPLICATE_ADDR,
	/* Common link/interface auxiliary states */
	NWAM_AUX_STATE_UP,
	NWAM_AUX_STATE_DOWN,
	NWAM_AUX_STATE_NOT_FOUND
} nwam_aux_state_t;

/* Activation modes */
typedef enum {
	NWAM_ACTIVATION_MODE_MANUAL,
	NWAM_ACTIVATION_MODE_SYSTEM,
	NWAM_ACTIVATION_MODE_CONDITIONAL_ANY,
	NWAM_ACTIVATION_MODE_CONDITIONAL_ALL,
	NWAM_ACTIVATION_MODE_PRIORITIZED
} nwam_activation_mode_t;

/*
 * Conditions are of the form
 *
 * ncu|enm|loc name is|is-not active
 * ip-address is|is-not|is-in-range|is-not-in-range ipaddr[/prefixlen]
 * advertised-domain is|is-not|contains|does-not-contain string
 * system-domain is|is-not|contains|does-not-contain string
 * essid is|is-not|contains|does-not-contain string
 * bssid is|is-not <string>
 */

typedef enum {
	NWAM_CONDITION_IS,
	NWAM_CONDITION_IS_NOT,
	NWAM_CONDITION_IS_IN_RANGE,
	NWAM_CONDITION_IS_NOT_IN_RANGE,
	NWAM_CONDITION_CONTAINS,
	NWAM_CONDITION_DOES_NOT_CONTAIN
} nwam_condition_t;

typedef enum {
	NWAM_CONDITION_OBJECT_TYPE_NCP,
	NWAM_CONDITION_OBJECT_TYPE_NCU,
	NWAM_CONDITION_OBJECT_TYPE_ENM,
	NWAM_CONDITION_OBJECT_TYPE_LOC,
	NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS,
	NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN,
	NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN,
	NWAM_CONDITION_OBJECT_TYPE_ESSID,
	NWAM_CONDITION_OBJECT_TYPE_BSSID
} nwam_condition_object_type_t;

/*
 * Activation condition-related functions that convert activation
 * values to an appropriate string and back.
 */
extern nwam_error_t nwam_condition_to_condition_string(
    nwam_condition_object_type_t, nwam_condition_t, const char *, char **);
extern nwam_error_t nwam_condition_string_to_condition(const char *,
    nwam_condition_object_type_t *, nwam_condition_t *, char **);

/*
 * Only one location can be active at one time. As a
 * consequence, if the activation conditions of multiple
 * locations are satisfied, we need to compare activation
 * conditions to see if one is more specific than another.
 *
 * The following heuristics are applied to rate an
 * activation condition:
 * - "is" is the most specific condition
 * - it is followed by "is-in-range" and "contains"
 * - "is-not-in-range" and "does-not-contain" are next
 * - finally "is-not" is least specific
 *
 * Regarding the objects these conditions apply to:
 * - NCU, ENM and locations are most specific
 * - system-domain is next
 * - advertised-domain is next
 * - IP address is next
 * - wireless BSSID is next
 * - wireless ESSID is least specific
 *
 */
extern nwam_error_t nwam_condition_rate(nwam_condition_object_type_t,
    nwam_condition_t, uint64_t *);

/*
 * Location definitions.
 */

#define	NWAM_LOC_NAME_AUTOMATIC		"Automatic"
#define	NWAM_LOC_NAME_NO_NET		"NoNet"
#define	NWAM_LOC_NAME_LEGACY		"Legacy"

#define	NWAM_LOC_NAME_PRE_DEFINED(name)	\
			(strcasecmp(name, NWAM_LOC_NAME_AUTOMATIC) == 0 || \
			strcasecmp(name, NWAM_LOC_NAME_NO_NET) == 0 || \
			strcasecmp(name, NWAM_LOC_NAME_LEGACY) == 0)

/* Forward definition */
struct nwam_handle;

typedef struct nwam_handle *nwam_loc_handle_t;

/* Location properties */

typedef enum {
	NWAM_NAMESERVICES_DNS,
	NWAM_NAMESERVICES_FILES,
	NWAM_NAMESERVICES_NIS,
	NWAM_NAMESERVICES_LDAP
} nwam_nameservices_t;

typedef enum {
	NWAM_CONFIGSRC_MANUAL,
	NWAM_CONFIGSRC_DHCP
} nwam_configsrc_t;

#define	NWAM_LOC_PROP_ACTIVATION_MODE		"activation-mode"
#define	NWAM_LOC_PROP_CONDITIONS		"conditions"
#define	NWAM_LOC_PROP_ENABLED			"enabled"

/* Nameservice location properties */
#define	NWAM_LOC_PROP_NAMESERVICES		"nameservices"
#define	NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE	"nameservices-config-file"
#define	NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC	"dns-nameservice-configsrc"
#define	NWAM_LOC_PROP_DNS_NAMESERVICE_DOMAIN	"dns-nameservice-domain"
#define	NWAM_LOC_PROP_DNS_NAMESERVICE_SERVERS	"dns-nameservice-servers"
#define	NWAM_LOC_PROP_DNS_NAMESERVICE_SEARCH	"dns-nameservice-search"
#define	NWAM_LOC_PROP_NIS_NAMESERVICE_CONFIGSRC	"nis-nameservice-configsrc"
#define	NWAM_LOC_PROP_NIS_NAMESERVICE_SERVERS	"nis-nameservice-servers"
#define	NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC "ldap-nameservice-configsrc"
#define	NWAM_LOC_PROP_LDAP_NAMESERVICE_SERVERS	"ldap-nameservice-servers"
#define	NWAM_LOC_PROP_DEFAULT_DOMAIN		"default-domain"

/* NFSv4 domain */
#define	NWAM_LOC_PROP_NFSV4_DOMAIN		"nfsv4-domain"

/* IPfilter configuration */
#define	NWAM_LOC_PROP_IPFILTER_CONFIG_FILE	"ipfilter-config-file"
#define	NWAM_LOC_PROP_IPFILTER_V6_CONFIG_FILE	"ipfilter-v6-config-file"
#define	NWAM_LOC_PROP_IPNAT_CONFIG_FILE		"ipnat-config-file"
#define	NWAM_LOC_PROP_IPPOOL_CONFIG_FILE	"ippool-config-file"

/* IPsec configuration */
#define	NWAM_LOC_PROP_IKE_CONFIG_FILE		"ike-config-file"
#define	NWAM_LOC_PROP_IPSECPOLICY_CONFIG_FILE	"ipsecpolicy-config-file"

/*
 * NCP/NCU definitions.
 */

#define	NWAM_NCP_NAME_AUTOMATIC		"Automatic"
#define	NWAM_NCP_NAME_USER		"User"

#define	NWAM_NCP_AUTOMATIC(name)	\
			(strcasecmp(name, NWAM_NCP_NAME_AUTOMATIC) == 0)

typedef struct nwam_handle *nwam_ncp_handle_t;

typedef struct nwam_handle *nwam_ncu_handle_t;

typedef enum {
	NWAM_NCU_TYPE_UNKNOWN = -1,
	NWAM_NCU_TYPE_LINK,
	NWAM_NCU_TYPE_INTERFACE,
	NWAM_NCU_TYPE_ANY
} nwam_ncu_type_t;

typedef enum {
	NWAM_NCU_CLASS_UNKNOWN = -1,
	NWAM_NCU_CLASS_PHYS,
	NWAM_NCU_CLASS_IP,
	NWAM_NCU_CLASS_ANY
} nwam_ncu_class_t;

typedef enum {
	NWAM_ADDRSRC_DHCP,
	NWAM_ADDRSRC_AUTOCONF,
	NWAM_ADDRSRC_STATIC
} nwam_addrsrc_t;

typedef enum {
	NWAM_PRIORITY_MODE_EXCLUSIVE,
	NWAM_PRIORITY_MODE_SHARED,
	NWAM_PRIORITY_MODE_ALL
} nwam_priority_mode_t;

/* NCU properties common to all type/classes */
#define	NWAM_NCU_PROP_TYPE			"type"
#define	NWAM_NCU_PROP_CLASS			"class"
#define	NWAM_NCU_PROP_PARENT_NCP		"parent"
#define	NWAM_NCU_PROP_ACTIVATION_MODE		"activation-mode"
#define	NWAM_NCU_PROP_ENABLED			"enabled"
#define	NWAM_NCU_PROP_PRIORITY_GROUP		"priority-group"
#define	NWAM_NCU_PROP_PRIORITY_MODE		"priority-mode"

/* Link NCU properties */
#define	NWAM_NCU_PROP_LINK_MAC_ADDR		"link-mac-addr"
#define	NWAM_NCU_PROP_LINK_AUTOPUSH		"link-autopush"
#define	NWAM_NCU_PROP_LINK_MTU			"link-mtu"

/* IP NCU properties */
#define	NWAM_NCU_PROP_IP_VERSION		"ip-version"
#define	NWAM_NCU_PROP_IPV4_ADDRSRC		"ipv4-addrsrc"
#define	NWAM_NCU_PROP_IPV4_ADDR			"ipv4-addr"
#define	NWAM_NCU_PROP_IPV4_DEFAULT_ROUTE	"ipv4-default-route"
#define	NWAM_NCU_PROP_IPV6_ADDRSRC		"ipv6-addrsrc"
#define	NWAM_NCU_PROP_IPV6_ADDR			"ipv6-addr"
#define	NWAM_NCU_PROP_IPV6_DEFAULT_ROUTE	"ipv6-default-route"
#define	NWAM_NCU_PROP_IP_PRIMARY		"ip-primary"
#define	NWAM_NCU_PROP_IP_REQHOST		"ip-reqhost"

/* Some properties should only be set on creation */
#define	NWAM_NCU_PROP_SETONCE(prop)	\
				(strcmp(prop, NWAM_NCU_PROP_TYPE) == 0 || \
				strcmp(prop, NWAM_NCU_PROP_CLASS) == 0 || \
				strcmp(prop, NWAM_NCU_PROP_PARENT_NCP) == 0)
/*
 * ENM definitions
 */

typedef struct nwam_handle *nwam_enm_handle_t;

#define	NWAM_ENM_PROP_ACTIVATION_MODE	"activation-mode"
#define	NWAM_ENM_PROP_CONDITIONS	"conditions"
#define	NWAM_ENM_PROP_ENABLED		"enabled"

/* FMRI associated with ENM */
#define	NWAM_ENM_PROP_FMRI		"fmri"

/* Start/stop scripts associated with ENM */
#define	NWAM_ENM_PROP_START		"start"
#define	NWAM_ENM_PROP_STOP		"stop"

/*
 * Known Wireless LAN info (known WLAN) definitions.
 */

typedef struct nwam_handle *nwam_known_wlan_handle_t;

#define	NWAM_KNOWN_WLAN_PROP_BSSIDS		"bssids"
#define	NWAM_KNOWN_WLAN_PROP_PRIORITY		"priority"
#define	NWAM_KNOWN_WLAN_PROP_KEYNAME		"keyname"
#define	NWAM_KNOWN_WLAN_PROP_KEYSLOT		"keyslot"
#define	NWAM_KNOWN_WLAN_PROP_SECURITY_MODE	"security-mode"

/*
 * Location Functions
 */

/* Create a location */
extern nwam_error_t nwam_loc_create(const char *, nwam_loc_handle_t *);

/* Copy a location */
extern nwam_error_t nwam_loc_copy(nwam_loc_handle_t, const char *,
    nwam_loc_handle_t *);

/* Read a location from persistent storage */
extern nwam_error_t nwam_loc_read(const char *, uint64_t,
    nwam_loc_handle_t *);

/* Validate in-memory representation of a location */
extern nwam_error_t nwam_loc_validate(nwam_loc_handle_t, const char **);

/* Commit in-memory representation of a location to persistent storage */
extern nwam_error_t nwam_loc_commit(nwam_loc_handle_t, uint64_t);

/* Destroy a location in persistent storage */
extern nwam_error_t nwam_loc_destroy(nwam_loc_handle_t, uint64_t);

/* Free in-memory representation of a location */
extern void nwam_loc_free(nwam_loc_handle_t);

/* read all locs from persistent storage and walk through each at a time */
extern nwam_error_t nwam_walk_locs(int (*)(nwam_loc_handle_t, void *), void *,
    uint64_t, int *);

/* get/set loc name */
extern nwam_error_t nwam_loc_get_name(nwam_loc_handle_t, char **);
extern nwam_error_t nwam_loc_set_name(nwam_loc_handle_t, const char *);
extern boolean_t nwam_loc_can_set_name(nwam_loc_handle_t);

/* activate/deactivate loc */
extern nwam_error_t nwam_loc_enable(nwam_loc_handle_t);
extern nwam_error_t nwam_loc_disable(nwam_loc_handle_t);

/* walk all properties of an in-memory loc */
extern nwam_error_t nwam_loc_walk_props(nwam_loc_handle_t,
	int (*)(const char *, nwam_value_t, void *),
	void *, uint64_t, int *);

/* delete/get/set validate loc property */
extern nwam_error_t nwam_loc_delete_prop(nwam_loc_handle_t,
    const char *);
extern nwam_error_t nwam_loc_get_prop_value(nwam_loc_handle_t,
    const char *, nwam_value_t *);
extern nwam_error_t nwam_loc_set_prop_value(nwam_loc_handle_t,
    const char *, nwam_value_t);
extern nwam_error_t nwam_loc_validate_prop(nwam_loc_handle_t, const char *,
    nwam_value_t);

/* Get the read-only value for a particular loc property */
extern nwam_error_t nwam_loc_prop_read_only(const char *, boolean_t *);

/* Whether the property is multi-valued or not */
extern nwam_error_t nwam_loc_prop_multivalued(const char *, boolean_t *);

/* Retrieve data type */
extern nwam_error_t nwam_loc_get_prop_type(const char *, nwam_value_type_t *);

/* Retrieve description */
extern nwam_error_t nwam_loc_get_prop_description(const char *, const char **);

/* get default loc props */
extern nwam_error_t nwam_loc_get_default_proplist(const char ***, uint_t *);

/* get sstate of loc from nwamd */
extern nwam_error_t nwam_loc_get_state(nwam_loc_handle_t, nwam_state_t *,
	nwam_aux_state_t *);

/* Get whether the loc has manual activation-mode or not */
extern nwam_error_t nwam_loc_is_manual(nwam_loc_handle_t, boolean_t *);

/*
 * NCP/NCU functions
 */

/* Create an ncp */
extern nwam_error_t nwam_ncp_create(const char *, uint64_t,
	nwam_ncp_handle_t *);

/* Read an ncp from persistent storage */
extern nwam_error_t nwam_ncp_read(const char *, uint64_t, nwam_ncp_handle_t *);

/* Make a copy of existing ncp */
extern nwam_error_t nwam_ncp_copy(nwam_ncp_handle_t, const char *,
	nwam_ncp_handle_t *);

/* Walk ncps */
extern nwam_error_t nwam_walk_ncps(int (*)(nwam_ncp_handle_t, void *),
	void *, uint64_t, int *);

/* Get ncp name */
extern nwam_error_t nwam_ncp_get_name(nwam_ncp_handle_t, char **);

/* Get the read-only value for this ncp */
extern nwam_error_t nwam_ncp_get_read_only(nwam_ncp_handle_t, boolean_t *);

/* Destroy ncp */
extern nwam_error_t nwam_ncp_destroy(nwam_ncp_handle_t, uint64_t);

/*
 * Walk all ncus associated with ncp.  Specific types/classes of ncu can
 * be selected via flags, or all via NWAM_FLAG_ALL.
 */
extern nwam_error_t nwam_ncp_walk_ncus(nwam_ncp_handle_t,
    int(*)(nwam_ncu_handle_t, void *), void *, uint64_t, int *);

/* Activate ncp */
extern nwam_error_t nwam_ncp_enable(nwam_ncp_handle_t);

/* Free in-memory representation of ncp */
extern void nwam_ncp_free(nwam_ncp_handle_t);

/* Get state of NCP from nwamd */
extern nwam_error_t nwam_ncp_get_state(nwam_ncp_handle_t, nwam_state_t *,
	nwam_aux_state_t *);

/* Get the active priority-group */
extern nwam_error_t nwam_ncp_get_active_priority_group(int64_t *);

/* Create an ncu or read it from persistent storage */
extern nwam_error_t nwam_ncu_create(nwam_ncp_handle_t, const char *,
	nwam_ncu_type_t, nwam_ncu_class_t, nwam_ncu_handle_t *);
extern nwam_error_t nwam_ncu_read(nwam_ncp_handle_t, const char *,
	nwam_ncu_type_t, uint64_t, nwam_ncu_handle_t *);

/* Destroy an ncu in persistent storage or free the in-memory representation */
extern nwam_error_t nwam_ncu_destroy(nwam_ncu_handle_t, uint64_t);
extern void nwam_ncu_free(nwam_ncu_handle_t);

/* make a copy of existing ncu */
extern nwam_error_t nwam_ncu_copy(nwam_ncu_handle_t, const char *,
	nwam_ncu_handle_t *);

/* Commit ncu changes to persistent storage */
extern nwam_error_t nwam_ncu_commit(nwam_ncu_handle_t, uint64_t);

/* activate/deactivate an individual NCU (must be part of the active NCP) */
extern nwam_error_t nwam_ncu_enable(nwam_ncu_handle_t);
extern nwam_error_t nwam_ncu_disable(nwam_ncu_handle_t);

/* Get state of NCU from nwamd */
extern nwam_error_t nwam_ncu_get_state(nwam_ncu_handle_t, nwam_state_t *,
	nwam_aux_state_t *);

/* Get NCU type */
extern nwam_error_t nwam_ncu_get_ncu_type(nwam_ncu_handle_t, nwam_ncu_type_t *);

/* Get NCU class */
extern nwam_error_t nwam_ncu_get_ncu_class(nwam_ncu_handle_t,
	nwam_ncu_class_t *);

/* Validate ncu content */
extern nwam_error_t nwam_ncu_validate(nwam_ncu_handle_t, const char **);

/* Walk all properties in in-memory representation of ncu */
extern nwam_error_t nwam_ncu_walk_props(nwam_ncu_handle_t,
	int (*)(const char *, nwam_value_t, void *),
	void *, uint64_t, int *);

/* Get/set name of ncu, get parent ncp */
extern nwam_error_t nwam_ncu_get_name(nwam_ncu_handle_t, char **);
extern nwam_error_t nwam_ncu_name_to_typed_name(const char *, nwam_ncu_type_t,
    char **);
extern nwam_error_t nwam_ncu_typed_name_to_name(const char *, nwam_ncu_type_t *,
    char **);
extern nwam_error_t nwam_ncu_get_default_proplist(nwam_ncu_type_t,
    nwam_ncu_class_t, const char ***, uint_t *);
extern nwam_error_t nwam_ncu_get_ncp(nwam_ncu_handle_t, nwam_ncp_handle_t *);

/* delete/get/set/validate property from/in in-memory representation of ncu */
extern nwam_error_t nwam_ncu_delete_prop(nwam_ncu_handle_t,
	const char *);
extern nwam_error_t nwam_ncu_get_prop_value(nwam_ncu_handle_t,
	const char *, nwam_value_t *);
extern nwam_error_t nwam_ncu_set_prop_value(nwam_ncu_handle_t,
	const char *, nwam_value_t);

extern nwam_error_t nwam_ncu_validate_prop(nwam_ncu_handle_t, const char *,
	nwam_value_t);

/* Retrieve data type */
extern nwam_error_t nwam_ncu_get_prop_type(const char *, nwam_value_type_t *);
/* Retrieve prop description */
extern nwam_error_t nwam_ncu_get_prop_description(const char *, const char **);

/* Get the read-only value from the handle or parent NCP */
extern nwam_error_t nwam_ncu_get_read_only(nwam_ncu_handle_t, boolean_t *);

/* Get the read-only value for a particular NCU property */
extern nwam_error_t nwam_ncu_prop_read_only(const char *, boolean_t *);

/* Whether the property is multi-valued or not */
extern nwam_error_t nwam_ncu_prop_multivalued(const char *, boolean_t *);

/* Get whether the NCU has manual activation-mode or not */
extern nwam_error_t nwam_ncu_is_manual(nwam_ncu_handle_t, boolean_t *);

/* Get the flag from the given class for walks */
extern uint64_t nwam_ncu_class_to_flag(nwam_ncu_class_t);

/* Get the NCU type from the given class */
extern nwam_ncu_type_t nwam_ncu_class_to_type(nwam_ncu_class_t);

/* ENM functions */
/*
 * Obtain a specific enm handle, either be creating a new enm
 * or reading an existing one from persistent storage.
 */
extern nwam_error_t nwam_enm_create(const char *, const char *,
	nwam_enm_handle_t *);
extern nwam_error_t nwam_enm_read(const char *, uint64_t, nwam_enm_handle_t *);

/* Make a copy of existing enm */
extern nwam_error_t nwam_enm_copy(nwam_enm_handle_t, const char *,
	nwam_enm_handle_t *);

/*
 * Obtain handles for all existing enms.  Caller-specified callback
 * function will be called once for each enm, passing the handle and
 * the caller-specified arg.
 */
extern nwam_error_t nwam_walk_enms(int (*)(nwam_enm_handle_t, void *), void *,
	uint64_t, int *);

/*
 * Commit an enm to persistent storage.  Does not free the handle.
 */
extern nwam_error_t nwam_enm_commit(nwam_enm_handle_t, uint64_t);

/*
 * Remove an enm from persistent storage.
 */
extern nwam_error_t nwam_enm_destroy(nwam_enm_handle_t, uint64_t);

/*
 * Free an enm handle
 */
extern void nwam_enm_free(nwam_enm_handle_t);

/*
 * Validate an enm, or a specific enm property.  If validating
 * an entire enm, the invalid property type is returned.
 */
extern nwam_error_t nwam_enm_validate(nwam_enm_handle_t, const char **);
extern nwam_error_t nwam_enm_validate_prop(nwam_enm_handle_t, const char *,
	nwam_value_t);

/* Retrieve data type */
extern nwam_error_t nwam_enm_get_prop_type(const char *, nwam_value_type_t *);
/* Retrieve prop description */
extern nwam_error_t nwam_enm_get_prop_description(const char *, const char **);

/*
 * Delete/get/set enm property values.
 */
extern nwam_error_t nwam_enm_delete_prop(nwam_enm_handle_t,
	const char *);
extern nwam_error_t nwam_enm_get_prop_value(nwam_enm_handle_t,
	const char *, nwam_value_t *);
extern nwam_error_t nwam_enm_set_prop_value(nwam_enm_handle_t,
	const char *, nwam_value_t);

extern nwam_error_t nwam_enm_get_default_proplist(const char ***, uint_t *);

/* Get the read-only value for a particular ENM property */
extern nwam_error_t nwam_enm_prop_read_only(const char *, boolean_t *);

/* Whether the property is multi-valued or not */
extern nwam_error_t nwam_enm_prop_multivalued(const char *, boolean_t *);

/*
 * Walk all properties of a specific enm.  For each property, specified
 * callback function is called.  Caller is responsible for freeing memory
 * allocated for each property.
 */
extern nwam_error_t nwam_enm_walk_props(nwam_enm_handle_t,
    int (*)(const char *, nwam_value_t, void *),
    void *, uint64_t, int *);

/*
 * Get/set the name of an enm.  When getting the name, the library will
 * allocate a buffer; the caller is responsible for freeing the memory.
 */
extern nwam_error_t nwam_enm_get_name(nwam_enm_handle_t, char **);
extern nwam_error_t nwam_enm_set_name(nwam_enm_handle_t, const char *);
extern boolean_t nwam_enm_can_set_name(nwam_enm_handle_t);

/*
 * Start/stop an enm.
 */
extern nwam_error_t nwam_enm_enable(nwam_enm_handle_t);
extern nwam_error_t nwam_enm_disable(nwam_enm_handle_t);

/*
 * Get state of ENM from nwamd.
 */
extern nwam_error_t nwam_enm_get_state(nwam_enm_handle_t, nwam_state_t *,
	nwam_aux_state_t *);

/*
 * Get whether the ENM has manual activation-mode or not.
 */
extern nwam_error_t nwam_enm_is_manual(nwam_enm_handle_t, boolean_t *);

/*
 * Known Wireless LAN (WLAN) info.
 */

/* Create a known WLAN */
extern nwam_error_t nwam_known_wlan_create(const char *,
    nwam_known_wlan_handle_t *);

/* Read a known WLAN from persistent storage */
extern nwam_error_t nwam_known_wlan_read(const char *, uint64_t,
    nwam_known_wlan_handle_t *);

/*
 * Destroy a known WLAN in persistent storage or free the in-memory
 * representation.
 */
extern nwam_error_t nwam_known_wlan_destroy(nwam_known_wlan_handle_t, uint64_t);
extern void nwam_known_wlan_free(nwam_known_wlan_handle_t);

/* make a copy of existing known WLAN */
extern nwam_error_t nwam_known_wlan_copy(nwam_known_wlan_handle_t, const char *,
    nwam_known_wlan_handle_t *);

/* Commit known WLAN changes to persistent storage */
extern nwam_error_t nwam_known_wlan_commit(nwam_known_wlan_handle_t, uint64_t);

/* Validate known WLAN content */
extern nwam_error_t nwam_known_wlan_validate(nwam_known_wlan_handle_t,
    const char **);

/* Walk known WLANs */
extern nwam_error_t nwam_walk_known_wlans
	(int(*)(nwam_known_wlan_handle_t, void *), void *, uint64_t, int *);

/* get/set known WLAN name */
extern nwam_error_t nwam_known_wlan_get_name(nwam_known_wlan_handle_t, char **);
extern nwam_error_t nwam_known_wlan_set_name(nwam_known_wlan_handle_t,
    const char *);
extern boolean_t nwam_known_wlan_can_set_name(nwam_known_wlan_handle_t);

/* walk all properties of an in-memory known WLAN */
extern nwam_error_t nwam_known_wlan_walk_props(nwam_known_wlan_handle_t,
    int (*)(const char *, nwam_value_t, void *),
    void *, uint64_t, int *);

/* delete/get/set/validate known WLAN property */
extern nwam_error_t nwam_known_wlan_delete_prop(nwam_known_wlan_handle_t,
    const char *);
extern nwam_error_t nwam_known_wlan_get_prop_value(nwam_known_wlan_handle_t,
    const char *, nwam_value_t *);
extern nwam_error_t nwam_known_wlan_set_prop_value(nwam_known_wlan_handle_t,
    const char *, nwam_value_t);
extern nwam_error_t nwam_known_wlan_validate_prop(nwam_known_wlan_handle_t,
    const char *, nwam_value_t);

/* Retrieve data type */
extern nwam_error_t nwam_known_wlan_get_prop_type(const char *,
    nwam_value_type_t *);
/* Retrieve prop description */
extern nwam_error_t nwam_known_wlan_get_prop_description(const char *,
    const char **);

/* get default known WLAN props */
extern nwam_error_t nwam_known_wlan_get_default_proplist(const char ***,
    uint_t *);

/* Whether the property is multi-valued or not */
extern nwam_error_t nwam_known_wlan_prop_multivalued(const char *, boolean_t *);

/* Add a bssid to the known WLANs */
extern nwam_error_t nwam_known_wlan_add_to_known_wlans(const char *,
    const char *, uint32_t, uint_t, const char *);

/* Remove a bssid from known WLANs */
extern nwam_error_t nwam_known_wlan_remove_from_known_wlans(const char *,
    const char *, const char *);

/*
 * nwam_wlan_t is used for scan/need choice/need key events and by
 * nwam_wlan_get_scan_results().  The following fields are valid:
 *
 * - for scan and need choice event, ESSID, BSSID, signal strength, security
 * mode, speed, channel, bsstype, key index, and if we already have a key
 * (have_key), if the WLAN is the current selection (selected) and
 * if the current WLAN is connected (connected).
 * - for need key events, ESSID, security mode, have_key, selected and connected
 * values are set.  The rest of the fields are not set since multiple WLANs
 * may match the ESSID and have different speeds, channels etc.  If an
 * ESSID/BSSID selection is specified, the BSSID will be set also.
 *
 */
typedef struct {
	char nww_essid[NWAM_MAX_NAME_LEN];
	char nww_bssid[NWAM_MAX_NAME_LEN];
	char nww_signal_strength[NWAM_MAX_NAME_LEN];
	uint32_t nww_security_mode; /* a dladm_wlan_secmode_t */
	uint32_t nww_speed; /* a dladm_wlan_speed_t */
	uint32_t nww_channel; /* a dladm_wlan_channel_t */
	uint32_t nww_bsstype; /* a dladm_wlan_bsstype_t */
	uint_t nww_keyindex;
	boolean_t nww_have_key;
	boolean_t nww_selected;
	boolean_t nww_connected;
} nwam_wlan_t;

/*
 * Active WLAN definitions. Used to scan WLANs/choose a WLAN/set a WLAN key.
 */
extern nwam_error_t nwam_wlan_scan(const char *);
extern nwam_error_t nwam_wlan_get_scan_results(const char *, uint_t *,
    nwam_wlan_t **);
extern nwam_error_t nwam_wlan_select(const char *, const char *, const char *,
    uint32_t, boolean_t);
extern nwam_error_t nwam_wlan_set_key(const char *, const char *, const char *,
    uint32_t, uint_t, const char *);

/*
 * Event notification definitions
 */
#define	NWAM_EVENT_TYPE_NOOP			0
#define	NWAM_EVENT_TYPE_INIT			1
#define	NWAM_EVENT_TYPE_SHUTDOWN		2
#define	NWAM_EVENT_TYPE_OBJECT_ACTION		3
#define	NWAM_EVENT_TYPE_OBJECT_STATE		4
#define	NWAM_EVENT_TYPE_PRIORITY_GROUP		5
#define	NWAM_EVENT_TYPE_INFO			6
#define	NWAM_EVENT_TYPE_WLAN_SCAN_REPORT	7
#define	NWAM_EVENT_TYPE_WLAN_NEED_CHOICE	8
#define	NWAM_EVENT_TYPE_WLAN_NEED_KEY		9
#define	NWAM_EVENT_TYPE_WLAN_CONNECTION_REPORT	10
#define	NWAM_EVENT_TYPE_IF_ACTION		11
#define	NWAM_EVENT_TYPE_IF_STATE		12
#define	NWAM_EVENT_TYPE_LINK_ACTION		13
#define	NWAM_EVENT_TYPE_LINK_STATE		14
#define	NWAM_EVENT_MAX				NWAM_EVENT_TYPE_LINK_STATE

#define	NWAM_EVENT_STATUS_OK			0
#define	NWAM_EVENT_STATUS_NOT_HANDLED		1

#define	NWAM_EVENT_NETWORK_OBJECT_UNDEFINED	0
#define	NWAM_EVENT_NETWORK_OBJECT_LINK		1
#define	NWAM_EVENT_NETWORK_OBJECT_INTERFACE	2

#define	NWAM_EVENT_REQUEST_UNDEFINED		0
#define	NWAM_EVENT_REQUEST_WLAN			1
#define	NWAM_EVENT_REQUEST_KEY			2

/*
 * Actions for nwamd to perform, used in conjunction with
 * nwam_request_type_t in nwam_door_arg_t.
 * Add string representations to nwam_action_to_string() in libnwam_util.c.
 */
typedef enum {
	NWAM_ACTION_UNKNOWN = -1,
	NWAM_ACTION_ADD,
	NWAM_ACTION_REMOVE,
	NWAM_ACTION_REFRESH,
	NWAM_ACTION_ENABLE,
	NWAM_ACTION_DISABLE,
	NWAM_ACTION_DESTROY
} nwam_action_t;

typedef enum {
	NWAM_OBJECT_TYPE_UNKNOWN = -1,
	NWAM_OBJECT_TYPE_NCP = 0,
	NWAM_OBJECT_TYPE_NCU = 1,
	NWAM_OBJECT_TYPE_LOC = 2,
	NWAM_OBJECT_TYPE_ENM = 3,
	NWAM_OBJECT_TYPE_KNOWN_WLAN = 4
} nwam_object_type_t;

typedef struct nwam_event *nwam_event_t;
struct nwam_event {
	int nwe_type;
	uint32_t nwe_size;

	union {
		struct nwam_event_object_action {
			nwam_object_type_t nwe_object_type;
			char nwe_name[NWAM_MAX_NAME_LEN];
			char nwe_parent[NWAM_MAX_NAME_LEN];
			nwam_action_t nwe_action;
		} nwe_object_action;

		struct nwam_event_object_state {
			nwam_object_type_t nwe_object_type;
			char nwe_name[NWAM_MAX_NAME_LEN];
			char nwe_parent[NWAM_MAX_NAME_LEN];
			nwam_state_t nwe_state;
			nwam_aux_state_t nwe_aux_state;
		} nwe_object_state;

		struct nwam_event_priority_group_info {
			int64_t nwe_priority;
		} nwe_priority_group_info;

		struct nwam_event_info {
			char nwe_message[NWAM_MAX_VALUE_LEN];
		} nwe_info;

		/*
		 * wlan_info stores both scan results and the single
		 * WLAN we require a key for in the case of _WLAN_NEED_KEY
		 * events.  For _WLAN_CONNECTION_REPORT events, it stores
		 * the WLAN the connection succeeded/failed for, indicating
		 * success/failure using the 'connected' boolean.
		 */
		struct nwam_event_wlan_info {
			char nwe_name[NWAM_MAX_NAME_LEN];
			boolean_t nwe_connected;
			uint16_t nwe_num_wlans;
			nwam_wlan_t nwe_wlans[1];
			/*
			 * space may be allocated by user here for the
			 * number of wlans
			 */
		} nwe_wlan_info;

		struct nwam_event_if_action {
			char nwe_name[NWAM_MAX_NAME_LEN];
			nwam_action_t nwe_action;
		} nwe_if_action;

		struct nwam_event_if_state {
			char nwe_name[NWAM_MAX_NAME_LEN];
			uint32_t nwe_flags;
			uint32_t nwe_addr_valid; /* boolean */
			uint32_t nwe_addr_added; /* boolean */
			struct sockaddr_storage nwe_addr;
			struct sockaddr_storage nwe_netmask;
		} nwe_if_state;

		struct nwam_event_link_state {
			char nwe_name[NWAM_MAX_NAME_LEN];
			boolean_t nwe_link_up;
			/* link_state_t from sys/mac.h */
		} nwe_link_state;

		struct nwam_event_link_action {
			char nwe_name[NWAM_MAX_NAME_LEN];
			nwam_action_t nwe_action;
		} nwe_link_action;
	} nwe_data;
};

/* NWAM client functions, used to register/unregister and receive events */
extern nwam_error_t nwam_events_init(void);
extern void nwam_events_fini(void);
extern nwam_error_t nwam_event_wait(nwam_event_t *);
extern void nwam_event_free(nwam_event_t);

/* Event-related string conversion functions */
extern const char *nwam_action_to_string(nwam_action_t);
extern const char *nwam_event_type_to_string(int);
extern const char *nwam_state_to_string(nwam_state_t);
extern const char *nwam_aux_state_to_string(nwam_aux_state_t);

extern const char *nwam_object_type_to_string(nwam_object_type_t);
extern nwam_object_type_t nwam_string_to_object_type(const char *);

/* Utility strtok_r-like function */
extern char *nwam_tokenize_by_unescaped_delim(char *, char, char **);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBNWAM_H */
