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

#ifndef	_LIBRESTART_H
#define	_LIBRESTART_H

#include <libsysevent.h>
#include <libcontract.h>
#include <libscf.h>
#include <limits.h>
#include <priv.h>
#include <pwd.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * There are 3 parts to librestart.
 *	1) The event protocol from the master restarter to its delegates.
 *	2) A functional interface for updating the repository.
 *	3) Convenience functions for common restarter tasks.
 *
 * Event protocol
 *	We need a reliable event protocol, as there's no way to define
 *	restarter events as idempotent.
 *
 *	Currently using sysevent channels as the reliable event implementation.
 *	This could change if the implementation proves unsuitable, but
 *	the API defined here should abstract anything but a change in
 *	the fundamental event model.
 *
 *	We offer functions to tease apart the event rather than generic
 *	nvpair interfaces. This is because each event type has a well-
 *	defined set of fields.
 */

/*
 * Some of the functions have external contracted consumers, review contracts
 * when making incompatible changes.
 */

typedef struct restarter_event_handle restarter_event_handle_t;
typedef struct restarter_event restarter_event_t;

typedef uint32_t restarter_event_type_t;

/*
 * Define an event protocol version. In theory, we could use this in
 * the future to support delegated restarters which use an older
 * protocol. In practice, increment RESTARTER_EVENT_VERSION whenever the
 * protocol might have changed.
 */
#define	RESTARTER_EVENT_VERSION		5

#define	RESTARTER_FLAG_DEBUG		1

#define	RESTARTER_ERRMSGSZ		1024

/*
 * Event types
 *	RESTARTER_EVENT_TYPE_ADD_INSTANCE
 *		responsible for a new (stopped) instance
 *	RESTARTER_EVENT_TYPE_REMOVE_INSTANCE
 *		no longer responsible for this instance; stop it and return
 *	RESTARTER_EVENT_TYPE_ENABLE
 *		no guarantee that dependencies are met; see
 *		RESTARTER_EVENT_TYPE_START
 *	RESTARTER_EVENT_TYPE_DISABLE
 *		no guarantee that instance was running
 *	RESTARTER_EVENT_TYPE_ADMIN_DEGRADED
 *	RESTARTER_EVENT_TYPE_ADMIN_REFRESH
 *	RESTARTER_EVENT_TYPE_ADMIN_RESTART
 *	RESTARTER_EVENT_TYPE_ADMIN_MAINT_OFF
 *	RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON
 *	RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON_IMMEDIATE
 *	RESTARTER_EVENT_TYPE_ADMIN_MAINT_OFF
 *	RESTARTER_EVENT_TYPE_STOP
 *		dependencies are, or are becoming, unsatisfied
 *	RESTARTER_EVENT_TYPE_START
 *		dependencies have become satisfied
 *	RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE
 *		instance caused a dependency cycle
 *	RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY
 *		instance has an invalid dependency
 */

#define	RESTARTER_EVENT_TYPE_INVALID			0
#define	RESTARTER_EVENT_TYPE_ADD_INSTANCE		1
#define	RESTARTER_EVENT_TYPE_REMOVE_INSTANCE		2
#define	RESTARTER_EVENT_TYPE_ENABLE			3
#define	RESTARTER_EVENT_TYPE_DISABLE			4
#define	RESTARTER_EVENT_TYPE_ADMIN_DEGRADED		5
#define	RESTARTER_EVENT_TYPE_ADMIN_REFRESH		6
#define	RESTARTER_EVENT_TYPE_ADMIN_RESTART		7
#define	RESTARTER_EVENT_TYPE_ADMIN_MAINT_OFF		8
#define	RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON		9
#define	RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON_IMMEDIATE	10
#define	RESTARTER_EVENT_TYPE_STOP			11
#define	RESTARTER_EVENT_TYPE_START			12
#define	RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE		13
#define	RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY		14
#define	RESTARTER_EVENT_TYPE_ADMIN_DISABLE		15
#define	RESTARTER_EVENT_TYPE_STOP_RESET			16

#define	RESTARTER_EVENT_ERROR			-1

#define	RESTARTER_EVENT_INSTANCE_DISABLED	0
#define	RESTARTER_EVENT_INSTANCE_ENABLED	1

typedef enum {
	RESTARTER_STATE_NONE,
	RESTARTER_STATE_UNINIT,
	RESTARTER_STATE_MAINT,
	RESTARTER_STATE_OFFLINE,
	RESTARTER_STATE_DISABLED,
	RESTARTER_STATE_ONLINE,
	RESTARTER_STATE_DEGRADED
} restarter_instance_state_t;

/*
 * These values are ordered by severity of required restart, as we use
 * integer comparisons to determine error flow.
 */
typedef enum {
	RERR_UNSUPPORTED = -1,
	RERR_NONE = 0,			/* no error, restart, refresh */
	RERR_FAULT,			/* fault occurred */
	RERR_RESTART,			/* transition due to restart */
	RERR_REFRESH			/* transition due to refresh */
} restarter_error_t;
/*
 * restarter_store_contract() and restarter_remove_contract() types
 */
typedef enum {
	RESTARTER_CONTRACT_PRIMARY,
	RESTARTER_CONTRACT_TRANSIENT
} restarter_contract_type_t;

/*
 * restarter_bind_handle() registers a delegate with svc.startd to
 * begin consuming events.
 *
 * On initial bind, the delgated restarter receives an event for each
 * instance it is responsible for, as if that instance was new.
 *
 * callers must have superuser privileges
 *
 * The event handler can return 0 for success, or EAGAIN to request
 * retry of event delivery. EAGAIN may be returned 3 times before the
 * event is discarded.
 */
int restarter_bind_handle(uint32_t, const char *,
    int (*event_handler)(restarter_event_t *), int,
    restarter_event_handle_t **);

restarter_event_type_t restarter_event_get_type(restarter_event_t *);
uint64_t restarter_event_get_seq(restarter_event_t *);
void restarter_event_get_time(restarter_event_t *, hrtime_t *);
ssize_t restarter_event_get_instance(restarter_event_t *, char *, size_t);
restarter_event_handle_t *restarter_event_get_handle(restarter_event_t *);

/*
 * The following functions work only on certain types of events.
 * They fail with a return of -1 if they're called on an inappropriate event.
 */
int restarter_event_get_enabled(restarter_event_t *);
int restarter_event_get_current_states(restarter_event_t *,
    restarter_instance_state_t *, restarter_instance_state_t *);

/*
 * State transition reasons
 */

typedef enum {
	restarter_str_none,
	restarter_str_administrative_request,
	restarter_str_bad_repo_state,
	restarter_str_clear_request,
	restarter_str_ct_ev_core,
	restarter_str_ct_ev_exit,
	restarter_str_ct_ev_hwerr,
	restarter_str_ct_ev_signal,
	restarter_str_dependencies_satisfied,
	restarter_str_dependency_activity,
	restarter_str_dependency_cycle,
	restarter_str_disable_request,
	restarter_str_enable_request,
	restarter_str_fault_threshold_reached,
	restarter_str_insert_in_graph,
	restarter_str_invalid_dependency,
	restarter_str_invalid_restarter,
	restarter_str_method_failed,
	restarter_str_per_configuration,
	restarter_str_refresh,
	restarter_str_restart_request,
	restarter_str_restarting_too_quickly,
	restarter_str_service_request,
	restarter_str_startd_restart
} restarter_str_t;

struct restarter_state_transition_reason {
	restarter_str_t	str_key;
	const char	*str_short;
	const char	*str_long;
};

/*
 * Functions for updating the repository.
 */

/*
 * When setting state to "maintenance", callers of restarter_set_states() can
 * set aux_state to "service_request" to communicate that another service has
 * requested maintenance state for the target service.
 *
 * Callers should use restarter_inst_validate_aux_fmri() to validate the fmri
 * of the requested service and pass "service_request" for aux_state when
 * calling restarter_set_states(). See inetd and startd for examples.
 */
int restarter_set_states(restarter_event_handle_t *, const char *,
    restarter_instance_state_t, restarter_instance_state_t,
    restarter_instance_state_t, restarter_instance_state_t, restarter_error_t,
    restarter_str_t);
int restarter_event_publish_retry(evchan_t *, const char *, const char *,
    const char *, const char *, nvlist_t *, uint32_t);

/*
 * functions for retrieving the state transition reason messages
 */

#define	RESTARTER_STRING_VERSION	1

uint32_t restarter_str_version(void);
const char *restarter_get_str_short(restarter_str_t);
const char *restarter_get_str_long(restarter_str_t);

int restarter_store_contract(scf_instance_t *, ctid_t,
    restarter_contract_type_t);
int restarter_remove_contract(scf_instance_t *, ctid_t,
    restarter_contract_type_t);

ssize_t restarter_state_to_string(restarter_instance_state_t, char *, size_t);
restarter_instance_state_t restarter_string_to_state(char *);

#define	RESTARTER_METHOD_CONTEXT_VERSION	7

struct method_context {
	/* Stable */
	uid_t		uid, euid;
	gid_t		gid, egid;
	int		ngroups;		/* -1 means use initgroups(). */
	gid_t		groups[NGROUPS_MAX];
	priv_set_t	*lpriv_set, *priv_set;
	char		*corefile_pattern;	/* Optional. */
	char		*project;		/* NULL for no change */
	char		*resource_pool;		/* NULL for project default */
	char		*working_dir;		/* NULL for :default */
	char		**env;			/* NULL for no env */
	size_t		env_sz;			/* size of env array */

	/* Private */
	char		*vbuf;
	ssize_t		vbuf_sz;
	struct passwd	pwd;
	char		*pwbuf;
	ssize_t		pwbufsz;
};

/*
 * An error structure that contains a message string, and a type
 * that can be used to determine course of action by the reciever
 * of the error structure.
 *
 * type - usually will be an errno equivalent but could contain
 * 	defined error types for exampe SCF_ERROR_XXX
 * msg - must be at the end of the structure as if the message is
 * 	longer than EMSGSIZE we will reallocate the structure to
 * 	handle the overflow
 */
typedef struct mc_error {
	int	destroy;	/* Flag to indicate destruction steps */
	int	type;		/* Type of error for decision making */
	int	size;		/* The size of the error message string */
	char 	msg[RESTARTER_ERRMSGSZ];
} mc_error_t;

int restarter_rm_libs_loadable(void);
/* instance, restarter name, method name, command line, structure pointer */
mc_error_t *restarter_get_method_context(uint_t, scf_instance_t *,
    scf_snapshot_t *, const char *, const char *, struct method_context **);
void restarter_mc_error_destroy(mc_error_t *);
int restarter_set_method_context(struct method_context *, const char **);
void restarter_free_method_context(struct method_context *);


int restarter_is_null_method(const char *);
int restarter_is_kill_method(const char *);
int restarter_is_kill_proc_method(const char *);

/* Validate the inst fmri specified in  restarter_actions/auxiliary_fmri */
int restarter_inst_validate_ractions_aux_fmri(scf_instance_t *);

/* Delete instance's restarter_actions/auxiliary_fmri property */
int restarter_inst_reset_ractions_aux_fmri(scf_instance_t *);

/* Get boolean value from instance's restarter_actions/auxiliary_tty */
int restarter_inst_ractions_from_tty(scf_instance_t *);

/* Delete instance's restarter/auxiliary_fmri property */
int restarter_inst_reset_aux_fmri(scf_instance_t *);

/* Get boolean value from instance's restarter_actions/do_dump */
int restarter_inst_dump(scf_instance_t *);

/*
 * Set instance's restarter/auxiliary_fmri, value come from
 * restarter_actions/auxliary_fmri
 */
int restarter_inst_set_aux_fmri(scf_instance_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBRESTART_H */
