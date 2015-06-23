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

#ifndef	_LIBSCF_H
#define	_LIBSCF_H


#include <stddef.h>
#include <sys/types.h>
#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct scf_version *scf_version_t;
#define	SCF_VERSION	((scf_version_t)1UL)

/*
 * Opaque structures
 */
typedef struct scf_handle scf_handle_t;
typedef struct scf_scope scf_scope_t;
typedef struct scf_service scf_service_t;
typedef struct scf_instance scf_instance_t;
typedef struct scf_propertygroup scf_propertygroup_t;
typedef struct scf_property scf_property_t;

typedef struct scf_snapshot scf_snapshot_t;
typedef struct scf_snaplevel scf_snaplevel_t;

typedef struct scf_transaction scf_transaction_t;
typedef struct scf_transaction_entry scf_transaction_entry_t;
typedef struct scf_value scf_value_t;

typedef struct scf_iter scf_iter_t;

typedef struct scf_pg_tmpl scf_pg_tmpl_t;
typedef struct scf_prop_tmpl scf_prop_tmpl_t;
typedef struct scf_tmpl_errors scf_tmpl_errors_t;

typedef struct scf_simple_app_props scf_simple_app_props_t;
typedef struct scf_simple_prop scf_simple_prop_t;

/*
 * Types
 */
typedef enum {
	SCF_TYPE_INVALID = 0,

	SCF_TYPE_BOOLEAN,
	SCF_TYPE_COUNT,
	SCF_TYPE_INTEGER,
	SCF_TYPE_TIME,
	SCF_TYPE_ASTRING,
	SCF_TYPE_OPAQUE,

	SCF_TYPE_USTRING = 100,

	SCF_TYPE_URI = 200,
	SCF_TYPE_FMRI,

	SCF_TYPE_HOST = 300,
	SCF_TYPE_HOSTNAME,
	SCF_TYPE_NET_ADDR_V4,
	SCF_TYPE_NET_ADDR_V6,
	SCF_TYPE_NET_ADDR
} scf_type_t;

typedef struct scf_time {
	int64_t		t_seconds;
	int32_t		t_ns;
} scf_time_t;

/*
 * There is no explicit initializer for this structure.  Functions
 * which set or populate this structure assume that it is either
 * uninitialized or destroyed.
 */
typedef struct scf_values {
	scf_type_t		value_type;
	void			*reserved;	/* reserved for future use */
	int			value_count;
	char			**values_as_strings;
	union {
		uint64_t	*v_count;
		uint8_t		*v_boolean;
		int64_t		*v_integer;
		char		**v_astring;
		char		**v_ustring;
		char		**v_opaque;
		scf_time_t	*v_time;
	} values;
} scf_values_t;

typedef struct scf_count_ranges {
	int		scr_num_ranges;
	uint64_t	*scr_min;
	uint64_t	*scr_max;
} scf_count_ranges_t;

typedef struct scf_int_ranges {
	int		sir_num_ranges;
	int64_t		*sir_min;
	int64_t		*sir_max;
} scf_int_ranges_t;

/*
 * Return codes
 */
#define	SCF_SUCCESS			0
#define	SCF_COMPLETE			1
#define	SCF_FAILED			-1

typedef enum scf_error {
	SCF_ERROR_NONE = 1000,		/* no error */
	SCF_ERROR_NOT_BOUND,		/* handle not bound */
	SCF_ERROR_NOT_SET,		/* cannot use unset argument */
	SCF_ERROR_NOT_FOUND,		/* nothing of that name found */
	SCF_ERROR_TYPE_MISMATCH,	/* type does not match value */
	SCF_ERROR_IN_USE,		/* cannot modify while in-use */
	SCF_ERROR_CONNECTION_BROKEN,	/* repository connection gone */
	SCF_ERROR_INVALID_ARGUMENT,	/* bad argument */
	SCF_ERROR_NO_MEMORY,		/* no memory available */
	SCF_ERROR_CONSTRAINT_VIOLATED,	/* required constraint not met */
	SCF_ERROR_EXISTS,		/* object already exists */
	SCF_ERROR_NO_SERVER,		/* repository server unavailable */
	SCF_ERROR_NO_RESOURCES,		/* server has insufficient resources */
	SCF_ERROR_PERMISSION_DENIED,	/* insufficient privileges for action */
	SCF_ERROR_BACKEND_ACCESS,	/* backend refused access */
	SCF_ERROR_HANDLE_MISMATCH,	/* mismatched SCF handles */
	SCF_ERROR_HANDLE_DESTROYED,	/* object bound to destroyed handle */
	SCF_ERROR_VERSION_MISMATCH,	/* incompatible SCF version */
	SCF_ERROR_BACKEND_READONLY,	/* backend is read-only */
	SCF_ERROR_DELETED,		/* object has been deleted */
	SCF_ERROR_TEMPLATE_INVALID,	/* template data is invalid */

	SCF_ERROR_CALLBACK_FAILED = 1080, /* user callback function failed */

	SCF_ERROR_INTERNAL = 1101	/* internal error */
} scf_error_t;

/*
 * This enum MUST be kept in sync with
 * struct _scf_tmpl_error_desc em_desc() in scf_tmpl.c
 */
typedef enum scf_tmpl_error_type {
	SCF_TERR_MISSING_PG,		/* property group missing */
	SCF_TERR_WRONG_PG_TYPE,		/* property group type incorrect */
	SCF_TERR_MISSING_PROP,		/* missing required property */
	SCF_TERR_WRONG_PROP_TYPE,	/* property type incorrect */
	SCF_TERR_CARDINALITY_VIOLATION,	/* wrong number of values */
	SCF_TERR_VALUE_CONSTRAINT_VIOLATED, /* constraint violated for value */
	SCF_TERR_RANGE_VIOLATION,	/* value violated specified range */
	SCF_TERR_PG_REDEFINE,		/* global or restarter pg_pattern */
					/* redefined by the instance */
	SCF_TERR_PROP_TYPE_MISMATCH,	/* property and value type mismatch */
	SCF_TERR_VALUE_OUT_OF_RANGE,	/* value is out of range in template */
	SCF_TERR_INVALID_VALUE,		/* value is not valid for the */
					/* template */
	SCF_TERR_PG_PATTERN_CONFLICT,	/* pg_pattern conflicts with higher */
					/* level definition */
	SCF_TERR_PROP_PATTERN_CONFLICT,	/* prop_pattern conflicts with higher */
					/* level definition */
	SCF_TERR_GENERAL_REDEFINE,	/* global or restarter template */
					/* redefined */
	SCF_TERR_INCLUDE_VALUES,	/* No supporting constraints or */
					/* values for include_values */
	SCF_TERR_PG_PATTERN_INCOMPLETE,	/* Required pg_pattern is missing */
					/* name or type attribute. */
	SCF_TERR_PROP_PATTERN_INCOMPLETE    /* Required prop_pattern is */
					    /* missing a type attribute. */
} scf_tmpl_error_type_t;

typedef struct scf_tmpl_error scf_tmpl_error_t;

/*
 * scf_tmpl_strerror() human readable flag
 */
#define	SCF_TMPL_STRERROR_HUMAN	0x1

/*
 * Standard services
 */
#define	SCF_SERVICE_CONFIGD	((const char *) \
				    "svc:/system/svc/repository:default")
#define	SCF_INSTANCE_GLOBAL	((const char *) \
				    "svc:/system/svc/global:default")
#define	SCF_SERVICE_GLOBAL	((const char *) \
				    "svc:/system/svc/global")
#define	SCF_SERVICE_STARTD	((const char *) \
				    "svc:/system/svc/restarter:default")
#define	SCF_INSTANCE_EMI	((const char *) \
				    "svc:/system/early-manifest-import:default")
#define	SCF_INSTANCE_FS_MINIMAL	((const char *) \
				    "svc:/system/filesystem/minimal:default")
#define	SCF_INSTANCE_MI		((const char *) \
				    "svc:/system/manifest-import:default")

/*
 * Major milestones
 */
#define	SCF_MILESTONE_SINGLE_USER \
	((const char *) "svc:/milestone/single-user:default")
#define	SCF_MILESTONE_MULTI_USER \
	((const char *) "svc:/milestone/multi-user:default")
#define	SCF_MILESTONE_MULTI_USER_SERVER \
	((const char *) "svc:/milestone/multi-user-server:default")

/*
 * standard scope names
 */
#define	SCF_SCOPE_LOCAL			((const char *)"localhost")

/*
 * Property group types
 */
#define	SCF_GROUP_APPLICATION		((const char *)"application")
#define	SCF_GROUP_FRAMEWORK		((const char *)"framework")
#define	SCF_GROUP_DEPENDENCY		((const char *)"dependency")
#define	SCF_GROUP_METHOD		((const char *)"method")
#define	SCF_GROUP_TEMPLATE		((const char *)"template")
#define	SCF_GROUP_TEMPLATE_PG_PATTERN	((const char *)"template_pg_pattern")
#define	SCF_GROUP_TEMPLATE_PROP_PATTERN	((const char *)"template_prop_pattern")

/*
 * Dependency types
 */
#define	SCF_DEP_REQUIRE_ALL		((const char *)"require_all")
#define	SCF_DEP_REQUIRE_ANY		((const char *)"require_any")
#define	SCF_DEP_EXCLUDE_ALL		((const char *)"exclude_all")
#define	SCF_DEP_OPTIONAL_ALL		((const char *)"optional_all")

#define	SCF_DEP_RESET_ON_ERROR		((const char *)"error")
#define	SCF_DEP_RESET_ON_RESTART	((const char *)"restart")
#define	SCF_DEP_RESET_ON_REFRESH	((const char *)"refresh")
#define	SCF_DEP_RESET_ON_NONE		((const char *)"none")

/*
 * Standard property group names
 */
#define	SCF_PG_GENERAL			((const char *)"general")
#define	SCF_PG_GENERAL_OVR		((const char *)"general_ovr")
#define	SCF_PG_RESTARTER		((const char *)"restarter")
#define	SCF_PG_RESTARTER_ACTIONS	((const char *)"restarter_actions")
#define	SCF_PG_METHOD_CONTEXT		((const char *)"method_context")
#define	SCF_PG_APP_DEFAULT		((const char *)"application")
#define	SCF_PG_DEPENDENTS		((const char *)"dependents")
#define	SCF_PG_OPTIONS			((const char *)"options")
#define	SCF_PG_OPTIONS_OVR		((const char *)"options_ovr")
#define	SCF_PG_STARTD			((const char *)"startd")
#define	SCF_PG_STARTD_PRIVATE		((const char *)"svc-startd-private")
#define	SCF_PG_DEATHROW			((const char *)"deathrow")
#define	SCF_PG_MANIFESTFILES		((const char *)"manifestfiles")

/*
 * Template property group names and prefixes
 */
#define	SCF_PG_TM_COMMON_NAME		((const char *)"tm_common_name")
#define	SCF_PG_TM_DESCRIPTION		((const char *)"tm_description")

#define	SCF_PG_TM_MAN_PREFIX		((const char *)"tm_man_")
#define	SCF_PG_TM_DOC_PREFIX		((const char *)"tm_doc_")

/*
 * Standard property names
 */
#define	SCF_PROPERTY_ACTIVE_POSTFIX	((const char *)"active")
#define	SCF_PROPERTY_AUX_STATE		((const char *)"auxiliary_state")
#define	SCF_PROPERTY_AUX_FMRI		((const char *)"auxiliary_fmri")
#define	SCF_PROPERTY_AUX_TTY		((const char *)"auxiliary_tty")
#define	SCF_PROPERTY_CONTRACT		((const char *)"contract")
#define	SCF_PROPERTY_COREFILE_PATTERN	((const char *)"corefile_pattern")
#define	SCF_PROPERTY_DEGRADED		((const char *)"degraded")
#define	SCF_PROPERTY_DEGRADE_IMMEDIATE	((const char *)"degrade_immediate")
#define	SCF_PROPERTY_DODUMP		((const char *)"do_dump")
#define	SCF_PROPERTY_DURATION		((const char *)"duration")
#define	SCF_PROPERTY_ENABLED		((const char *)"enabled")
#define	SCF_PROPERTY_DEATHROW		((const char *)"deathrow")
#define	SCF_PROPERTY_ENTITY_STABILITY	((const char *)"entity_stability")
#define	SCF_PROPERTY_ENTITIES		((const char *)"entities")
#define	SCF_PROPERTY_EXEC		((const char *)"exec")
#define	SCF_PROPERTY_GROUP		((const char *)"group")
#define	SCF_PROPERTY_GROUPING		((const char *)"grouping")
#define	SCF_PROPERTY_IGNORE		((const char *)"ignore_error")
#define	SCF_PROPERTY_INTERNAL_SEPARATORS ((const char *)"internal_separators")
#define	SCF_PROPERTY_LIMIT_PRIVILEGES	((const char *)"limit_privileges")
#define	SCF_PROPERTY_MAINT_OFF		((const char *)"maint_off")
#define	SCF_PROPERTY_MAINT_ON		((const char *)"maint_on")
#define	SCF_PROPERTY_MAINT_ON_IMMEDIATE	((const char *)"maint_on_immediate")
#define	SCF_PROPERTY_MAINT_ON_IMMTEMP	((const char *)"maint_on_immtemp")
#define	SCF_PROPERTY_MAINT_ON_TEMPORARY	((const char *)"maint_on_temporary")
#define	SCF_PROPERTY_METHOD_PID		((const char *)"method_pid")
#define	SCF_PROPERTY_MILESTONE		((const char *)"milestone")
#define	SCF_PROPERTY_NEED_SESSION	((const char *)"need_session")
#define	SCF_PROPERTY_NEXT_STATE		((const char *)"next_state")
#define	SCF_PROPERTY_PACKAGE		((const char *)"package")
#define	SCF_PROPERTY_PRIVILEGES		((const char *)"privileges")
#define	SCF_PROPERTY_PROFILE		((const char *)"profile")
#define	SCF_PROPERTY_PROJECT		((const char *)"project")
#define	SCF_PROPERTY_REFRESH		((const char *)"refresh")
#define	SCF_PROPERTY_RESOURCE_POOL	((const char *)"resource_pool")
#define	SCF_PROPERTY_ENVIRONMENT	((const char *)"environment")
#define	SCF_PROPERTY_RESTART		((const char *)"restart")
#define	SCF_PROPERTY_RESTARTER		((const char *)"restarter")
#define	SCF_PROPERTY_RESTART_INTERVAL	((const char *)"restart_interval")
#define	SCF_PROPERTY_RESTART_ON		((const char *)"restart_on")
#define	SCF_PROPERTY_RESTORE		((const char *)"restore")
#define	SCF_PROPERTY_SINGLE_INSTANCE	((const char *)"single_instance")
#define	SCF_PROPERTY_START_METHOD_TIMESTAMP	\
	((const char *)"start_method_timestamp")
#define	SCF_PROPERTY_START_METHOD_WAITSTATUS	\
	((const char *)"start_method_waitstatus")
#define	SCF_PROPERTY_START_PID		((const char *)"start_pid")
#define	SCF_PROPERTY_STATE		((const char *)"state")
#define	SCF_PROPERTY_STABILITY		((const char *)"stability")
#define	SCF_PROPERTY_STATE_TIMESTAMP	((const char *)"state_timestamp")
#define	SCF_PROPERTY_SUPP_GROUPS	((const char *)"supp_groups")
#define	SCF_PROPERTY_TIMEOUT		((const char *)"timeout_seconds")
#define	SCF_PROPERTY_TIMEOUT_RETRY	((const char *)"timeout_retry")
#define	SCF_PROPERTY_TRANSIENT_CONTRACT	((const char *)"transient_contract")
#define	SCF_PROPERTY_TYPE		((const char *)"type")
#define	SCF_PROPERTY_USE_PROFILE	((const char *)"use_profile")
#define	SCF_PROPERTY_USER		((const char *)"user")
#define	SCF_PROPERTY_UTMPX_PREFIX	((const char *)"utmpx_prefix")
#define	SCF_PROPERTY_WORKING_DIRECTORY	((const char *)"working_directory")

/*
 * Template property names
 */
#define	SCF_PROPERTY_TM_CARDINALITY_MIN	((const char *)"cardinality_min")
#define	SCF_PROPERTY_TM_CARDINALITY_MAX	((const char *)"cardinality_max")
#define	SCF_PROPERTY_TM_CHOICES_INCLUDE_VALUES ((const char *) \
					    "choices_include_values")
#define	SCF_PROPERTY_TM_CHOICES_NAME	((const char *)"choices_name")
#define	SCF_PROPERTY_TM_CHOICES_RANGE	((const char *)"choices_range")
#define	SCF_PROPERTY_TM_CONSTRAINT_NAME	((const char *)"constraint_name")
#define	SCF_PROPERTY_TM_CONSTRAINT_RANGE ((const char *)"constraint_range")
#define	SCF_PROPERTY_TM_MANPATH		((const char *)"manpath")
#define	SCF_PROPERTY_TM_NAME		((const char *)"name")
#define	SCF_PROPERTY_TM_PG_PATTERN	((const char *)"pg_pattern")
#define	SCF_PROPERTY_TM_REQUIRED	((const char *)"required")
#define	SCF_PROPERTY_TM_SECTION		((const char *)"section")
#define	SCF_PROPERTY_TM_TARGET		((const char *)"target")
#define	SCF_PROPERTY_TM_TITLE		((const char *)"title")
#define	SCF_PROPERTY_TM_TYPE		((const char *)"type")
#define	SCF_PROPERTY_TM_URI		((const char *)"uri")
#define	SCF_PROPERTY_TM_VALUE_PREFIX	((const char *)"value_")
#define	SCF_PROPERTY_TM_VALUES_NAME	((const char *)"values_name")
#define	SCF_PROPERTY_TM_VISIBILITY	((const char *)"visibility")
#define	SCF_PROPERTY_TM_COMMON_NAME_PREFIX	((const char *)"common_name_")
#define	SCF_PROPERTY_TM_DESCRIPTION_PREFIX	((const char *)"description_")
#define	SCF_PROPERTY_TM_UNITS_PREFIX		((const char *)"units_")

/*
 * Templates wildcard string
 */
#define	SCF_TMPL_WILDCARD	((const char *)"*")

/*
 * Strings used by restarters for state and next_state properties.
 * MAX_SCF_STATE_STRING holds the max length of a state string, including the
 * terminating null.
 */

#define	MAX_SCF_STATE_STRING_SZ		14

#define	SCF_STATE_STRING_NONE		((const char *)"none")
#define	SCF_STATE_STRING_UNINIT		((const char *)"uninitialized")
#define	SCF_STATE_STRING_MAINT		((const char *)"maintenance")
#define	SCF_STATE_STRING_OFFLINE	((const char *)"offline")
#define	SCF_STATE_STRING_DISABLED	((const char *)"disabled")
#define	SCF_STATE_STRING_ONLINE		((const char *)"online")
#define	SCF_STATE_STRING_DEGRADED	((const char *)"degraded")
#define	SCF_STATE_STRING_LEGACY		((const char *)"legacy_run")

#define	SCF_STATE_UNINIT		0x00000001
#define	SCF_STATE_MAINT			0x00000002
#define	SCF_STATE_OFFLINE		0x00000004
#define	SCF_STATE_DISABLED		0x00000008
#define	SCF_STATE_ONLINE		0x00000010
#define	SCF_STATE_DEGRADED		0x00000020
#define	SCF_STATE_ALL			0x0000003F

/*
 * software fma svc-transition class
 */
#define	SCF_NOTIFY_PARAMS_VERSION	0X0
#define	SCF_NOTIFY_NAME_FMRI		((const char *)"fmri")
#define	SCF_NOTIFY_NAME_VERSION		((const char *)"version")
#define	SCF_NOTIFY_NAME_TSET		((const char *)"tset")
#define	SCF_NOTIFY_PG_POSTFIX		((const char *)"fmnotify")
#define	SCF_NOTIFY_PARAMS		((const char *)"notify-params")
#define	SCF_NOTIFY_PARAMS_INST \
	((const char *)"svc:/system/fm/notify-params:default")
#define	SCF_SVC_TRANSITION_CLASS \
	((const char *)"ireport.os.smf.state-transition")
#define	SCF_NOTIFY_PARAMS_PG_TYPE	((const char *)"notify_params")

/*
 * Useful transition macros
 */
#define	SCF_TRANS_SHIFT_INITIAL_STATE(s)	((s) << 16)
#define	SCF_TRANSITION_ALL \
	(SCF_TRANS_SHIFT_INITIAL_STATE(SCF_STATE_ALL) | SCF_STATE_ALL)
#define	SCF_TRANS(f, t)	(SCF_TRANS_SHIFT_INITIAL_STATE(f) | (t))
#define	SCF_TRANS_VALID(t)	(!((t) & ~SCF_TRANSITION_ALL))
#define	SCF_TRANS_INITIAL_STATE(t)	((t) >> 16 & SCF_STATE_ALL)
#define	SCF_TRANS_FINAL_STATE(t)	((t) & SCF_STATE_ALL)

/*
 * Prefixes for states in state transition notification
 */
#define	SCF_STN_PREFIX_FROM		((const char *)"from-")
#define	SCF_STN_PREFIX_TO		((const char *)"to-")

#define	SCF_PG_FLAG_NONPERSISTENT	0x1

#define	SCF_TRACE_LIBRARY		0x1
#define	SCF_TRACE_DAEMON		0x2

#define	SMF_IMMEDIATE			0x1
#define	SMF_TEMPORARY			0x2
#define	SMF_AT_NEXT_BOOT		0x4

scf_error_t scf_error(void);
const char *scf_strerror(scf_error_t);

ssize_t scf_limit(uint32_t code);
#define	SCF_LIMIT_MAX_NAME_LENGTH	-2000U
#define	SCF_LIMIT_MAX_VALUE_LENGTH	-2001U
#define	SCF_LIMIT_MAX_PG_TYPE_LENGTH	-2002U
#define	SCF_LIMIT_MAX_FMRI_LENGTH	-2003U

scf_handle_t *scf_handle_create(scf_version_t);

int scf_handle_decorate(scf_handle_t *, const char *, scf_value_t *);
#define	SCF_DECORATE_CLEAR	((scf_value_t *)0)

int scf_handle_bind(scf_handle_t *);
int scf_handle_unbind(scf_handle_t *);
void scf_handle_destroy(scf_handle_t *);

int scf_type_base_type(scf_type_t type, scf_type_t *out);
const char *scf_type_to_string(scf_type_t);
scf_type_t scf_string_to_type(const char *);

/* values */
scf_value_t *scf_value_create(scf_handle_t *);
scf_handle_t *scf_value_handle(const scf_value_t *);
void scf_value_destroy(scf_value_t *);

scf_type_t scf_value_base_type(const scf_value_t *);
scf_type_t scf_value_type(const scf_value_t *);
int scf_value_is_type(const scf_value_t *, scf_type_t);

void scf_value_reset(scf_value_t *);

int scf_value_get_boolean(const scf_value_t *, uint8_t *);
int scf_value_get_count(const scf_value_t *, uint64_t *);
int scf_value_get_integer(const scf_value_t *, int64_t *);
int scf_value_get_time(const scf_value_t *, int64_t *, int32_t *);
ssize_t scf_value_get_astring(const scf_value_t *, char *, size_t);
ssize_t scf_value_get_ustring(const scf_value_t *, char *, size_t);
ssize_t scf_value_get_opaque(const scf_value_t *, void *, size_t);

void scf_value_set_boolean(scf_value_t *, uint8_t);
void scf_value_set_count(scf_value_t *, uint64_t);
void scf_value_set_integer(scf_value_t *, int64_t);
int scf_value_set_time(scf_value_t *, int64_t, int32_t);
int scf_value_set_astring(scf_value_t *, const char *);
int scf_value_set_ustring(scf_value_t *, const char *);
int scf_value_set_opaque(scf_value_t *, const void *, size_t);

ssize_t scf_value_get_as_string(const scf_value_t *, char *, size_t);
ssize_t scf_value_get_as_string_typed(const scf_value_t *, scf_type_t,
    char *, size_t);
int scf_value_set_from_string(scf_value_t *, scf_type_t, const char *);

scf_iter_t *scf_iter_create(scf_handle_t *);
scf_handle_t *scf_iter_handle(const scf_iter_t *);
void scf_iter_reset(scf_iter_t *);
void scf_iter_destroy(scf_iter_t *);

int scf_iter_handle_scopes(scf_iter_t *, const scf_handle_t *);
int scf_iter_scope_services(scf_iter_t *, const scf_scope_t *);
int scf_iter_service_instances(scf_iter_t *, const scf_service_t *);
int scf_iter_service_pgs(scf_iter_t *, const scf_service_t *);
int scf_iter_instance_pgs(scf_iter_t *, const scf_instance_t *);
int scf_iter_instance_pgs_composed(scf_iter_t *, const scf_instance_t *,
    const scf_snapshot_t *);
int scf_iter_service_pgs_typed(scf_iter_t *, const scf_service_t *,
    const char *);
int scf_iter_instance_pgs_typed(scf_iter_t *, const scf_instance_t *,
    const char *);
int scf_iter_instance_pgs_typed_composed(scf_iter_t *, const scf_instance_t *,
    const scf_snapshot_t *, const char *);
int scf_iter_snaplevel_pgs(scf_iter_t *, const scf_snaplevel_t *);
int scf_iter_snaplevel_pgs_typed(scf_iter_t *, const scf_snaplevel_t *,
    const char *);
int scf_iter_instance_snapshots(scf_iter_t *, const scf_instance_t *);
int scf_iter_pg_properties(scf_iter_t *, const scf_propertygroup_t *);
int scf_iter_property_values(scf_iter_t *, const scf_property_t *);

int scf_iter_next_scope(scf_iter_t *, scf_scope_t *);
int scf_iter_next_service(scf_iter_t *, scf_service_t *);
int scf_iter_next_instance(scf_iter_t *, scf_instance_t *);
int scf_iter_next_pg(scf_iter_t *, scf_propertygroup_t *);
int scf_iter_next_property(scf_iter_t *, scf_property_t *);
int scf_iter_next_snapshot(scf_iter_t *, scf_snapshot_t *);
int scf_iter_next_value(scf_iter_t *, scf_value_t *);

scf_scope_t *scf_scope_create(scf_handle_t *);
scf_handle_t *scf_scope_handle(const scf_scope_t *);

/* XXX eventually remove this */
#define	scf_handle_get_local_scope(h, s) \
	scf_handle_get_scope((h), SCF_SCOPE_LOCAL, (s))

int scf_handle_get_scope(scf_handle_t *, const char *, scf_scope_t *);
void scf_scope_destroy(scf_scope_t *);
ssize_t scf_scope_get_name(const scf_scope_t *, char *, size_t);

ssize_t scf_scope_to_fmri(const scf_scope_t *, char *, size_t);

scf_service_t *scf_service_create(scf_handle_t *);
scf_handle_t *scf_service_handle(const scf_service_t *);
void scf_service_destroy(scf_service_t *);
int scf_scope_get_parent(const scf_scope_t *, scf_scope_t *);
ssize_t scf_service_get_name(const scf_service_t *, char *, size_t);
ssize_t scf_service_to_fmri(const scf_service_t *, char *, size_t);
int scf_service_get_parent(const scf_service_t *, scf_scope_t *);
int scf_scope_get_service(const scf_scope_t *, const char *, scf_service_t *);
int scf_scope_add_service(const scf_scope_t *, const char *, scf_service_t *);
int scf_service_delete(scf_service_t *);

scf_instance_t *scf_instance_create(scf_handle_t *);
scf_handle_t *scf_instance_handle(const scf_instance_t *);
void scf_instance_destroy(scf_instance_t *);
ssize_t scf_instance_get_name(const scf_instance_t *, char *, size_t);
ssize_t scf_instance_to_fmri(const scf_instance_t *, char *, size_t);
int scf_service_get_instance(const scf_service_t *, const char *,
    scf_instance_t *);
int scf_service_add_instance(const scf_service_t *, const char *,
    scf_instance_t *);
int scf_instance_delete(scf_instance_t *);

scf_snapshot_t *scf_snapshot_create(scf_handle_t *);
scf_handle_t *scf_snapshot_handle(const scf_snapshot_t *);
void scf_snapshot_destroy(scf_snapshot_t *);
ssize_t scf_snapshot_get_name(const scf_snapshot_t *, char *, size_t);
int scf_snapshot_get_parent(const scf_snapshot_t *, scf_instance_t *);
int scf_instance_get_snapshot(const scf_instance_t *, const char *,
    scf_snapshot_t *);
int scf_snapshot_update(scf_snapshot_t *);

scf_snaplevel_t *scf_snaplevel_create(scf_handle_t *);
scf_handle_t *scf_snaplevel_handle(const scf_snaplevel_t *);
void scf_snaplevel_destroy(scf_snaplevel_t *);
int scf_snaplevel_get_parent(const scf_snaplevel_t *, scf_snapshot_t *);
ssize_t scf_snaplevel_get_scope_name(const scf_snaplevel_t *, char *, size_t);
ssize_t scf_snaplevel_get_service_name(const scf_snaplevel_t *, char *, size_t);
ssize_t scf_snaplevel_get_instance_name(const scf_snaplevel_t *, char *,
    size_t);
int scf_snaplevel_get_pg(const scf_snaplevel_t *, const char *,
    scf_propertygroup_t *pg);
int scf_snapshot_get_base_snaplevel(const scf_snapshot_t *, scf_snaplevel_t *);
int scf_snaplevel_get_next_snaplevel(const scf_snaplevel_t *,
    scf_snaplevel_t *);

scf_propertygroup_t *scf_pg_create(scf_handle_t *);
scf_handle_t *scf_pg_handle(const scf_propertygroup_t *);
void scf_pg_destroy(scf_propertygroup_t *);
ssize_t scf_pg_to_fmri(const scf_propertygroup_t *,  char *, size_t);
ssize_t scf_pg_get_name(const scf_propertygroup_t *, char *, size_t);
ssize_t scf_pg_get_type(const scf_propertygroup_t *, char *, size_t);
int scf_pg_get_flags(const scf_propertygroup_t *, uint32_t *);
int scf_pg_get_parent_service(const scf_propertygroup_t *, scf_service_t *);
int scf_pg_get_parent_instance(const scf_propertygroup_t *, scf_instance_t *);
int scf_pg_get_parent_snaplevel(const scf_propertygroup_t *, scf_snaplevel_t *);
int scf_service_get_pg(const scf_service_t *, const char *,
    scf_propertygroup_t *);
int scf_instance_get_pg(const scf_instance_t *, const char *,
    scf_propertygroup_t *);
int scf_instance_get_pg_composed(const scf_instance_t *, const scf_snapshot_t *,
    const char *, scf_propertygroup_t *);
int scf_service_add_pg(const scf_service_t *,  const char *, const char *,
    uint32_t, scf_propertygroup_t *);
int scf_instance_add_pg(const scf_instance_t *,  const char *, const char *,
    uint32_t, scf_propertygroup_t *);
int scf_pg_delete(scf_propertygroup_t *);

int scf_pg_get_underlying_pg(const scf_propertygroup_t *,
    scf_propertygroup_t *);
int scf_instance_get_parent(const scf_instance_t *, scf_service_t *);

int scf_pg_update(scf_propertygroup_t *);

scf_property_t *scf_property_create(scf_handle_t *);
scf_handle_t *scf_property_handle(const scf_property_t *);
void scf_property_destroy(scf_property_t *);
int scf_property_is_type(const scf_property_t *, scf_type_t);
int scf_property_type(const scf_property_t *, scf_type_t *);
ssize_t scf_property_get_name(const scf_property_t *, char *, size_t);
int scf_property_get_value(const scf_property_t *, scf_value_t *);
ssize_t scf_property_to_fmri(const scf_property_t *, char *, size_t);
int scf_pg_get_property(const scf_propertygroup_t *,  const char *,
    scf_property_t *);

scf_transaction_t *scf_transaction_create(scf_handle_t *);
scf_handle_t *scf_transaction_handle(const scf_transaction_t *);
int scf_transaction_start(scf_transaction_t *, scf_propertygroup_t *);
void scf_transaction_destroy(scf_transaction_t *);
void scf_transaction_destroy_children(scf_transaction_t *);

void scf_transaction_reset(scf_transaction_t *);
void scf_transaction_reset_all(scf_transaction_t *);

int scf_transaction_commit(scf_transaction_t *);

scf_transaction_entry_t *scf_entry_create(scf_handle_t *);
scf_handle_t *scf_entry_handle(const scf_transaction_entry_t *);
void scf_entry_reset(scf_transaction_entry_t *);
void scf_entry_destroy(scf_transaction_entry_t *);
void scf_entry_destroy_children(scf_transaction_entry_t *);

int scf_transaction_property_change(scf_transaction_t *,
    scf_transaction_entry_t *, const char *, scf_type_t);
int scf_transaction_property_delete(scf_transaction_t *,
    scf_transaction_entry_t *, const char *);
int scf_transaction_property_new(scf_transaction_t *,
    scf_transaction_entry_t *, const char *, scf_type_t);
int scf_transaction_property_change_type(scf_transaction_t *,
    scf_transaction_entry_t *, const char *, scf_type_t);

int scf_entry_add_value(scf_transaction_entry_t *, scf_value_t *);

int scf_handle_decode_fmri(scf_handle_t *, const char *, scf_scope_t *,
    scf_service_t *, scf_instance_t *, scf_propertygroup_t *, scf_property_t *,
    int);
#define	SCF_DECODE_FMRI_EXACT			0x00000001
#define	SCF_DECODE_FMRI_TRUNCATE		0x00000002
#define	SCF_DECODE_FMRI_REQUIRE_INSTANCE	0x00000004
#define	SCF_DECODE_FMRI_REQUIRE_NO_INSTANCE	0x00000008

ssize_t scf_myname(scf_handle_t *, char *, size_t);

/*
 * Property group template interfaces.
 */
scf_pg_tmpl_t *scf_tmpl_pg_create(scf_handle_t *);
void scf_tmpl_pg_destroy(scf_pg_tmpl_t *);
void scf_tmpl_pg_reset(scf_pg_tmpl_t *);
int scf_tmpl_get_by_pg(scf_propertygroup_t *, scf_pg_tmpl_t *, int);
int scf_tmpl_get_by_pg_name(const char *, const char *,
    const char *, const char *, scf_pg_tmpl_t *, int);
int scf_tmpl_iter_pgs(scf_pg_tmpl_t *, const char *, const char *,
    const char *, int);
#define	SCF_PG_TMPL_FLAG_REQUIRED	0x1
#define	SCF_PG_TMPL_FLAG_EXACT		0x2
#define	SCF_PG_TMPL_FLAG_CURRENT	0x4

ssize_t scf_tmpl_pg_name(const scf_pg_tmpl_t *, char **);
ssize_t scf_tmpl_pg_common_name(const scf_pg_tmpl_t *, const char *, char **);
ssize_t scf_tmpl_pg_description(const scf_pg_tmpl_t *, const char *, char **);
ssize_t scf_tmpl_pg_type(const scf_pg_tmpl_t *, char **);

ssize_t scf_tmpl_pg_target(const scf_pg_tmpl_t *, char **);
#define	SCF_TM_TARGET_ALL		((const char *)"all")
#define	SCF_TM_TARGET_DELEGATE		((const char *)"delegate")
#define	SCF_TM_TARGET_INSTANCE		((const char *)"instance")
#define	SCF_TM_TARGET_THIS		((const char *)"this")

int scf_tmpl_pg_required(const scf_pg_tmpl_t *, uint8_t *);

/*
 * Property template interfaces.
 */
scf_prop_tmpl_t *scf_tmpl_prop_create(scf_handle_t *);
void scf_tmpl_prop_destroy(scf_prop_tmpl_t *);
void scf_tmpl_prop_reset(scf_prop_tmpl_t *);
int scf_tmpl_get_by_prop(scf_pg_tmpl_t *, const char *,
    scf_prop_tmpl_t *, int);
int scf_tmpl_iter_props(scf_pg_tmpl_t *, scf_prop_tmpl_t *, int);
#define	SCF_PROP_TMPL_FLAG_REQUIRED	0x1

ssize_t scf_tmpl_prop_name(const scf_prop_tmpl_t *, char **);
int scf_tmpl_prop_type(const scf_prop_tmpl_t *, scf_type_t *);
int scf_tmpl_prop_required(const scf_prop_tmpl_t *, uint8_t *);
ssize_t scf_tmpl_prop_common_name(const scf_prop_tmpl_t *, const char *,
    char **);
ssize_t scf_tmpl_prop_description(const scf_prop_tmpl_t *, const char *,
    char **);
ssize_t scf_tmpl_prop_units(const scf_prop_tmpl_t *, const char *, char **);
int scf_tmpl_prop_cardinality(const scf_prop_tmpl_t *prop, uint64_t *,
    uint64_t *);
int scf_tmpl_prop_internal_seps(const scf_prop_tmpl_t *, scf_values_t *);

int scf_tmpl_prop_visibility(const scf_prop_tmpl_t *, uint8_t *);
#define	SCF_TMPL_VISIBILITY_HIDDEN		1
#define	SCF_TMPL_VISIBILITY_READONLY		2
#define	SCF_TMPL_VISIBILITY_READWRITE		3

const char *scf_tmpl_visibility_to_string(uint8_t);
#define	SCF_TM_VISIBILITY_HIDDEN	((const char *)"hidden")
#define	SCF_TM_VISIBILITY_READONLY	((const char *)"readonly")
#define	SCF_TM_VISIBILITY_READWRITE	((const char *)"readwrite")

int scf_tmpl_value_name_constraints(const scf_prop_tmpl_t *prop,
    scf_values_t *vals);
void scf_count_ranges_destroy(scf_count_ranges_t *);
void scf_int_ranges_destroy(scf_int_ranges_t *);
int scf_tmpl_value_count_range_constraints(const scf_prop_tmpl_t *,
    scf_count_ranges_t *);
int scf_tmpl_value_int_range_constraints(const scf_prop_tmpl_t *,
    scf_int_ranges_t *);
int scf_tmpl_value_count_range_choices(const scf_prop_tmpl_t *,
    scf_count_ranges_t *);
int scf_tmpl_value_int_range_choices(const scf_prop_tmpl_t *,
    scf_int_ranges_t *);
int scf_tmpl_value_name_choices(const scf_prop_tmpl_t *prop,
    scf_values_t *vals);

void scf_values_destroy(scf_values_t *);

ssize_t scf_tmpl_value_common_name(const scf_prop_tmpl_t *, const char *,
    const char *, char **);
ssize_t scf_tmpl_value_description(const scf_prop_tmpl_t *, const char *,
    const char *, char **);

int scf_tmpl_value_in_constraint(const scf_prop_tmpl_t *pt, scf_value_t *value,
    scf_tmpl_errors_t **errs);

/*
 * Template validation interfaces
 */
int scf_tmpl_validate_fmri(scf_handle_t *, const char *,
    const char *, scf_tmpl_errors_t **, int);
#define	SCF_TMPL_VALIDATE_FLAG_CURRENT	0x1

void scf_tmpl_errors_destroy(scf_tmpl_errors_t *errs);
scf_tmpl_error_t *scf_tmpl_next_error(scf_tmpl_errors_t *);
void scf_tmpl_reset_errors(scf_tmpl_errors_t *errs);
int scf_tmpl_strerror(scf_tmpl_error_t *err, char *s, size_t n, int flag);
int scf_tmpl_error_source_fmri(const scf_tmpl_error_t *, char **);
int scf_tmpl_error_type(const scf_tmpl_error_t *, scf_tmpl_error_type_t *);
int scf_tmpl_error_pg_tmpl(const scf_tmpl_error_t *, char **, char **);
int scf_tmpl_error_pg(const scf_tmpl_error_t *, char **, char **);
int scf_tmpl_error_prop_tmpl(const scf_tmpl_error_t *, char **, char **);
int scf_tmpl_error_prop(const scf_tmpl_error_t *, char **, char **);
int scf_tmpl_error_value(const scf_tmpl_error_t *, char **);

/*
 * Simplified calls
 */
int smf_enable_instance(const char *, int);
int smf_disable_instance(const char *, int);
int smf_refresh_instance(const char *);
int smf_restart_instance(const char *);
int smf_maintain_instance(const char *, int);
int smf_degrade_instance(const char *, int);
int smf_restore_instance(const char *);
char *smf_get_state(const char *);

int scf_simple_walk_instances(uint_t, void *,
    int (*inst_callback)(scf_handle_t *, scf_instance_t *, void *));

scf_simple_prop_t *scf_simple_prop_get(scf_handle_t *, const char *,
    const char *, const char *);
void scf_simple_prop_free(scf_simple_prop_t *);
scf_simple_app_props_t *scf_simple_app_props_get(scf_handle_t *, const char *);
void scf_simple_app_props_free(scf_simple_app_props_t *);
const scf_simple_prop_t *scf_simple_app_props_next(
    const scf_simple_app_props_t *, scf_simple_prop_t *);
const scf_simple_prop_t *scf_simple_app_props_search(
    const scf_simple_app_props_t *, const char *, const char *);
ssize_t scf_simple_prop_numvalues(const scf_simple_prop_t *);
scf_type_t scf_simple_prop_type(const scf_simple_prop_t *);
char *scf_simple_prop_name(const scf_simple_prop_t *);
char *scf_simple_prop_pgname(const scf_simple_prop_t *);
uint8_t *scf_simple_prop_next_boolean(scf_simple_prop_t *);
uint64_t *scf_simple_prop_next_count(scf_simple_prop_t *);
int64_t *scf_simple_prop_next_integer(scf_simple_prop_t *);
int64_t *scf_simple_prop_next_time(scf_simple_prop_t *, int32_t *);
char *scf_simple_prop_next_astring(scf_simple_prop_t *);
char *scf_simple_prop_next_ustring(scf_simple_prop_t *);
void *scf_simple_prop_next_opaque(scf_simple_prop_t *, size_t *);
void scf_simple_prop_next_reset(scf_simple_prop_t *);

/*
 * smf_state_from_string()
 * return SCF_STATE_* value for the input
 * -1 on error. String "all" maps to SCF_STATE_ALL macro
 */
int32_t smf_state_from_string(const char *);

/*
 * smf_state_to_string()
 * return SCF_STATE_STRING* value for the input
 * NULL on error.
 */
const char *smf_state_to_string(int32_t);

/*
 * Notification interfaces
 */
int smf_notify_set_params(const char *, nvlist_t *);
int smf_notify_get_params(nvlist_t **, nvlist_t *);
int smf_notify_del_params(const char *, const char *, int32_t);

/*
 * SMF exit status definitions
 */
#define	SMF_EXIT_OK		  0
#define	SMF_EXIT_ERR_FATAL	 95
#define	SMF_EXIT_ERR_CONFIG	 96
#define	SMF_EXIT_MON_DEGRADE	 97
#define	SMF_EXIT_MON_OFFLINE	 98
#define	SMF_EXIT_ERR_NOSMF	 99
#define	SMF_EXIT_ERR_PERM	100

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSCF_H */
