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

/*
 * This file contains hidden implementation structures and APIs of libnwam,
 * and is not installed in the proto area.  Implementation is MT safe.
 */


#ifndef _LIBNWAM_IMPL_H
#define	_LIBNWAM_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libnwam_priv.h>
#include <libnwam.h>

/*
 * We separate global flags (which are applicable to all object types) from
 * local flags (which only apply to specific object types).  These definitions
 * mask off the global vs. local portions of the flags value, with the former
 * being the low-order 32 bits and the latter the high-order 32 bits.
 */
#define	NWAM_FLAG_GLOBAL_MASK		0xFFFFFFFF
#define	NWAM_FLAG_LOCAL_MASK		0xFFFFFFFFULL << 32
#define	NWAM_WALK_FILTER_MASK		NWAM_FLAG_LOCAL_MASK

/*
 * Maximum object size is the size of a maximally-sized name/values property
 * multiplied by the maximum number of properties.  The maximum object size
 * and the maximum number of objects are used to determine how much space
 * needs to be allocated for door calls to retrieve objects from the
 * backend.
 */
#define	NWAM_MAX_OBJECT_LEN 		\
	((NWAM_MAX_NAME_LEN +		\
	(NWAM_MAX_VALUE_LEN * NWAM_MAX_NUM_VALUES)) * \
	NWAM_MAX_NUM_PROPERTIES)

#define	NWAM_MAX_NUM_OBJECTS		4192

#define	NWAM_MAX_OBJECT_LIST_LEN	\
	(NWAM_MAX_NUM_OBJECTS * NWAM_MAX_NAME_LEN)

#define	NWAM_BACKEND_DOOR_ARG_SIZE      \
	(sizeof (nwam_backend_door_arg_t) + \
	(NWAM_MAX_OBJECT_LEN > NWAM_MAX_OBJECT_LIST_LEN ? \
	NWAM_MAX_OBJECT_LEN : NWAM_MAX_OBJECT_LIST_LEN))


#define	NWAMD_DOOR_ARG_SIZE		\
	(sizeof (nwamd_door_arg_t) + \
	(NWAMD_MAX_NUM_WLANS * sizeof (nwam_wlan_t));

#define	NWAM_CONF_DIR			"/etc/nwam/"

#define	NWAM_LOC_OBJECT_STRING	"loc"
#define	NWAM_LOC_CONF_FILE	NWAM_CONF_DIR "loc.conf"

struct nwam_handle {
	nwam_object_type_t nwh_object_type;
	char nwh_name[NWAM_MAX_NAME_LEN];
	boolean_t nwh_committed;
	void *nwh_data;
};

#define	NWAM_OBJECT_NAMES_STRING	"object-names"
#define	NWAM_NCP_OBJECT_STRING		"ncp"
#define	NWAM_NCP_CONF_FILE_PRE		"ncp-"
#define	NWAM_NCP_CONF_FILE_SUF		".conf"
#define	NWAM_NCU_LINK_NAME_PRE		"link:"
#define	NWAM_NCU_INTERFACE_NAME_PRE	"interface:"

struct nwam_value {
	nwam_value_type_t nwv_value_type;
	uint_t nwv_value_numvalues;
	union {
		boolean_t *nwv_boolean;
		int64_t *nwv_int64;
		uint64_t *nwv_uint64;
		char **nwv_string;
	} nwv_values;
};

/* Used in property table retrieval of property attributes */
#define	NWAM_TYPE_ANY		1
#define	NWAM_CLASS_ANY		1

typedef nwam_error_t (*nwam_prop_validate_func_t)(nwam_value_t);

/* Used to hold validation/description data for properties */
struct nwam_prop_table_entry {
	const char *prop_name;
	nwam_value_type_t prop_type;
	boolean_t prop_is_readonly;
	uint_t prop_min_numvalues;
	uint_t prop_max_numvalues;
	nwam_prop_validate_func_t prop_validate;
	const char *prop_description;
	uint64_t prop_type_membership;
	uint64_t prop_class_membership;
};

struct nwam_prop_table {
	uint_t num_entries;
	struct nwam_prop_table_entry *entries;
};

#define	NWAM_ENM_OBJECT_STRING	"enm"
#define	NWAM_ENM_CONF_FILE	NWAM_CONF_DIR "enm.conf"

#define	NWAM_KNOWN_WLAN_OBJECT_STRING	"known-wlan"
#define	NWAM_KNOWN_WLAN_CONF_FILE	NWAM_CONF_DIR "known-wlan.conf"

/* Definitions that are used to map uint64 property values to strings */
#define	NWAM_ACTIVATION_MODE_MANUAL_STRING		"manual"
#define	NWAM_ACTIVATION_MODE_SYSTEM_STRING		"system"
#define	NWAM_ACTIVATION_MODE_PRIORITIZED_STRING		"prioritized"
#define	NWAM_ACTIVATION_MODE_CONDITIONAL_ANY_STRING	"conditional-any"
#define	NWAM_ACTIVATION_MODE_CONDITIONAL_ALL_STRING	"conditional-all"

#define	NWAM_CONDITION_IS_STRING			"is"
#define	NWAM_CONDITION_IS_NOT_STRING			"is-not"
#define	NWAM_CONDITION_IS_IN_RANGE_STRING		"is-in-range"
#define	NWAM_CONDITION_IS_NOT_IN_RANGE_STRING		"is-not-in-range"
#define	NWAM_CONDITION_CONTAINS_STRING			"contains"
#define	NWAM_CONDITION_DOES_NOT_CONTAIN_STRING		"does-not-contain"

#define	NWAM_CONDITION_OBJECT_TYPE_NCP_STRING		"ncp"
#define	NWAM_CONDITION_OBJECT_TYPE_NCU_STRING		"ncu"
#define	NWAM_CONDITION_OBJECT_TYPE_ENM_STRING		"enm"
#define	NWAM_CONDITION_OBJECT_TYPE_LOC_STRING		"loc"
#define	NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS_STRING	"ip-address"
#define	NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN_STRING	"advertised-domain"
#define	NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN_STRING	"system-domain"
#define	NWAM_CONDITION_OBJECT_TYPE_ESSID_STRING		"essid"
#define	NWAM_CONDITION_OBJECT_TYPE_BSSID_STRING		"bssid"

#define	NWAM_CONDITION_ACTIVE_STRING			"active"

#define	NWAM_NAMESERVICES_DNS_STRING			"dns"
#define	NWAM_NAMESERVICES_FILES_STRING			"files"
#define	NWAM_NAMESERVICES_NIS_STRING			"nis"
#define	NWAM_NAMESERVICES_LDAP_STRING			"ldap"

#define	NWAM_CONFIGSRC_MANUAL_STRING		"manual"
#define	NWAM_CONFIGSRC_DHCP_STRING		"dhcp"

#define	NWAM_NCU_TYPE_LINK_STRING			"link"
#define	NWAM_NCU_TYPE_INTERFACE_STRING			"interface"

#define	NWAM_NCU_CLASS_PHYS_STRING			"phys"
#define	NWAM_NCU_CLASS_IP_STRING			"ip"

#define	NWAM_IP_VERSION_IPV4_STRING			"ipv4"
#define	NWAM_IP_VERSION_IPV6_STRING			"ipv6"

#define	NWAM_ADDRSRC_DHCP_STRING			"dhcp"
#define	NWAM_ADDRSRC_AUTOCONF_STRING			"autoconf"
#define	NWAM_ADDRSRC_STATIC_STRING			"static"

#define	NWAM_PRIORITY_MODE_EXCLUSIVE_STRING		"exclusive"
#define	NWAM_PRIORITY_MODE_SHARED_STRING		"shared"
#define	NWAM_PRIORITY_MODE_ALL_STRING			"all"

/*
 * Functions that interact with nwamd's door server to request
 * object actions, states or to register for receipt of events from nwamd.
 * See libnwam_door.c.
 */
extern nwam_error_t nwam_request_register_unregister(nwam_request_type_t,
	const char *);
extern nwam_error_t nwam_request_action(nwam_object_type_t, const char *,
	const char *, nwam_action_t);
extern nwam_error_t nwam_request_state(nwam_object_type_t, const char *,
	const char *, nwam_state_t *, nwam_aux_state_t *);
extern nwam_error_t nwam_request_wlan(nwam_request_type_t, const char *,
	const char *, const char *, uint32_t, uint_t, const char *, boolean_t);
extern nwam_error_t nwam_request_wlan_scan_results(const char *name,
	uint_t *, nwam_wlan_t **);
extern nwam_error_t nwam_request_active_priority_group(int64_t *);

/*
 * Functions that access and manipulate backend representation of data -
 * see libnwam_backend.c.
 */
extern nwam_error_t nwam_read_object_from_backend(char *, char *,
	uint64_t, void *);
extern nwam_error_t nwam_update_object_in_backend(char *, char *,
	uint64_t, void *);
extern nwam_error_t nwam_remove_object_from_backend(char *, char *,
	uint64_t);

/*
 * Functions that handle files-specific backend persistent representation
 * of data - see libnwam_files.c.
 */
extern nwam_error_t nwam_read_object_from_files_backend(char *,
	char *, uint64_t, void *);
extern nwam_error_t nwam_update_object_in_files_backend(char *,
	char *, uint64_t, void *);
extern nwam_error_t nwam_remove_object_from_files_backend(char *,
	char *, uint64_t);

/*
 * Utility functions for nwam data (values and lists of values) associated
 * with objects - see libnwam_values.c.
 */
nwam_error_t nwam_alloc_object_list(void *);
void nwam_free_object_list(void *);
nwam_error_t nwam_object_list_add_object_list(void *, char *, void *);
nwam_error_t nwam_object_list_remove_object_list(void *, char *);
nwam_error_t nwam_dup_object_list(void *, void *);
nwam_error_t nwam_next_object_list(void *, char *, char **, void *);
nwam_error_t nwam_next_object_prop(void *, char *, char **, nwam_value_t *);
extern nwam_error_t nwam_pack_object_list(void *, char **, size_t *);
extern nwam_error_t nwam_unpack_object_list(char *, size_t, void *);

extern const char *nwam_value_type_to_string(nwam_value_type_t);
extern nwam_value_type_t nwam_string_to_value_type(const char *);
extern nwam_error_t nwam_delete_prop(void *, const char *);
extern nwam_error_t nwam_set_prop_value(void *, const char *, nwam_value_t);
extern nwam_error_t nwam_get_prop_value(void *, const char *, nwam_value_t *);

/*
 * Utility functions for nwam objects (NCUs, ENMs, locations and known WLANs).
 * See libnwam_object.c.
 */
nwam_error_t nwam_handle_create(nwam_object_type_t, const char *,
	struct nwam_handle **);
nwam_error_t nwam_read(nwam_object_type_t, const char *, const char *,
	uint64_t, struct nwam_handle **);
nwam_error_t nwam_create(nwam_object_type_t, const char *, const char *,
	struct nwam_handle **);
nwam_error_t nwam_get_name(struct nwam_handle *, char **);
nwam_error_t nwam_set_name(struct nwam_handle *, const char *);
nwam_error_t nwam_walk(nwam_object_type_t, const char *,
	int(*)(struct nwam_handle *, void *), void *, uint64_t, int *,
	int(*)(struct nwam_handle *, uint64_t, void *));
void nwam_free(struct nwam_handle *);
nwam_error_t nwam_copy(const char *, struct nwam_handle *, const char *,
	struct nwam_handle **);
nwam_error_t nwam_walk_props(struct nwam_handle *,
	int(*)(const char *, nwam_value_t, void *), void *, uint64_t, int *);
nwam_error_t nwam_commit(const char *, struct nwam_handle *, uint64_t);
nwam_error_t nwam_destroy(const char *, struct nwam_handle *, uint64_t);
nwam_error_t nwam_enable(const char *, struct nwam_handle *);
nwam_error_t nwam_disable(const char *, struct nwam_handle *);
struct nwam_prop_table_entry *nwam_get_prop_table_entry(struct nwam_prop_table,
	const char *);
nwam_error_t nwam_get_prop_description(struct nwam_prop_table, const char *,
	const char **);
nwam_error_t nwam_get_prop_type(struct nwam_prop_table, const char *,
	nwam_value_type_t *);
nwam_error_t nwam_prop_multivalued(struct nwam_prop_table, const char *,
	boolean_t *);
nwam_error_t nwam_prop_read_only(struct nwam_prop_table, const char *,
	boolean_t *);
nwam_error_t nwam_validate_prop(struct nwam_prop_table, struct nwam_handle *,
	const char *, nwam_value_t);
nwam_error_t nwam_validate(struct nwam_prop_table, struct nwam_handle *,
	const char **);
nwam_error_t nwam_get_default_proplist(struct nwam_prop_table, uint64_t,
	uint64_t, const char ***, uint_t *);
nwam_error_t nwam_get_state(const char *, struct nwam_handle *, nwam_state_t *,
	nwam_aux_state_t *);

/*
 * Generic validation functions - see libnwam_util.c.
 */
extern nwam_error_t nwam_valid_flags(uint64_t, uint64_t);
extern nwam_error_t nwam_valid_condition(nwam_value_t);
extern nwam_error_t nwam_valid_boolean(nwam_value_t);
extern nwam_error_t nwam_valid_uint64(nwam_value_t);
extern nwam_error_t nwam_valid_domain(nwam_value_t);
extern nwam_error_t nwam_valid_host_any(nwam_value_t);
extern nwam_error_t nwam_valid_host_v4(nwam_value_t);
extern nwam_error_t nwam_valid_route_v4(nwam_value_t);
extern nwam_error_t nwam_valid_host_v6(nwam_value_t);
extern nwam_error_t nwam_valid_route_v6(nwam_value_t);
extern nwam_error_t nwam_valid_host_or_domain(nwam_value_t);
extern nwam_error_t nwam_valid_file(nwam_value_t);
extern nwam_error_t nwam_valid_fmri(nwam_value_t);
extern nwam_error_t nwam_valid_mac_addr(nwam_value_t);

/* Misc. util functions */
extern boolean_t nwam_uid_is_special(void);
extern nwam_error_t nwam_set_smf_string_property(const char *, const char *,
	const char *, const char *);
extern nwam_error_t nwam_get_smf_string_property(const char *, const char *,
	const char *, char **);
extern int nwam_make_door_call(const char *, int *, void *, size_t);
extern nwam_error_t nwam_errno_to_nwam_error(int);

/* Needed in libnwam_files.c to check if NCP filename is valid */
extern nwam_error_t nwam_ncp_file_to_name(const char *path, char **name);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBNWAM_IMPL_H */
