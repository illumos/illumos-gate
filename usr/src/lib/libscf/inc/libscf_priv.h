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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBSCF_PRIV_H
#define	_LIBSCF_PRIV_H


#include <libscf.h>
#include <unistd.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NOTE
 *
 * The contents of this file are private to the implementation of Solaris
 * and are subject to change at any time without notice.
 */

#define	SCF_PG_GENERAL_TYPE		SCF_GROUP_FRAMEWORK
#define	SCF_PG_GENERAL_FLAGS		0

#define	SCF_PG_GENERAL_OVR_TYPE		SCF_GROUP_FRAMEWORK
#define	SCF_PG_GENERAL_OVR_FLAGS	SCF_PG_FLAG_NONPERSISTENT

#define	SCF_PG_DEATHROW_TYPE		SCF_GROUP_FRAMEWORK
#define	SCF_PG_DEATHROW_FLAGS		SCF_PG_FLAG_NONPERSISTENT

#define	SCF_PG_OPTIONS_TYPE		SCF_GROUP_FRAMEWORK
#define	SCF_PG_OPTIONS_FLAGS		0

#define	SCF_PG_OPTIONS_OVR_TYPE		SCF_GROUP_FRAMEWORK
#define	SCF_PG_OPTIONS_OVR_FLAGS	SCF_PG_FLAG_NONPERSISTENT

#define	SCF_PG_RESTARTER_TYPE		SCF_GROUP_FRAMEWORK
#define	SCF_PG_RESTARTER_FLAGS		SCF_PG_FLAG_NONPERSISTENT

#define	SCF_PG_RESTARTER_ACTIONS_TYPE	SCF_GROUP_FRAMEWORK
#define	SCF_PG_RESTARTER_ACTIONS_FLAGS	SCF_PG_FLAG_NONPERSISTENT

#define	SCF_PROPERTY_CLEAR		((const char *)"maint_off")
#define	SCF_PROPERTY_MAINTENANCE	((const char *)"maint_on")

#define	SCF_PROPERTY_LOGFILE		((const char *)"logfile")
#define	SCF_PROPERTY_ALT_LOGFILE	((const char *)"alt_logfile")

#define	SCF_LEGACY_SERVICE		((const char *)"smf/legacy_run")

#define	SCF_LEGACY_PROPERTY_NAME	((const char *)"name")
#define	SCF_LEGACY_PROPERTY_INODE	((const char *)"inode")
#define	SCF_LEGACY_PROPERTY_SUFFIX	((const char *)"suffix")

#define	SCF_FMRI_TYPE_SVC		0x1
#define	SCF_FMRI_TYPE_FILE		0x2

/*
 * Strings for use in constructing FMRIs
 */
#define	SCF_FMRI_SVC_PREFIX		"svc:"
#define	SCF_FMRI_FILE_PREFIX		"file:"
#define	SCF_FMRI_SCOPE_PREFIX		"//"
#define	SCF_FMRI_LOCAL_SCOPE		"localhost"
#define	SCF_FMRI_SCOPE_SUFFIX		"@localhost"
#define	SCF_FMRI_SERVICE_PREFIX		"/"
#define	SCF_FMRI_INSTANCE_PREFIX	":"
#define	SCF_FMRI_PROPERTYGRP_PREFIX	"/:properties/"
#define	SCF_FMRI_PROPERTY_PREFIX	"/"
#define	SCF_FMRI_LEGACY_PREFIX		"lrc:"

/*
 * sulogin Service FMRI
 */
#define	SVC_SULOGIN_FMRI ((const char *)"svc:/system/sulogin")

typedef struct scf_decoration_info {
	const char *sdi_name;
	scf_type_t sdi_type;
	scf_value_t *sdi_value;		/* can be SCF_DECORATE_CLEAR */
} scf_decoration_info_t;

typedef int (*scf_decoration_func)(const scf_decoration_info_t *, void *);

/*
 * calls a callback function for each decoration on the handle.  If the
 * callback returns 0, the iteration stops and returns 0.  If the callback
 * returns a non-zero value, the iteration continues.  After full completion,
 * 1 is returned.  On error, -1 is returned.
 */
int _scf_handle_decorations(scf_handle_t *, scf_decoration_func *,
    scf_value_t *, void *);

/*
 * wait for a change to the propertygroup -- may return early.
 * For now, only one of these can be outstanding at a time.
 *
 * The second argument is how long, in seconds, to wait for a response.
 *
 * Returns SCF_COMPLETE on timeout, -1 on error, and SCF_SUCCESS in every
 * other case.  You must call scf_pg_update() to see if the object has
 * actually changed.
 */
int _scf_pg_wait(scf_propertygroup_t *, int);

/*
 * set up notifications for changes to a class of property groups (by name
 * and type)
 *
 * Only one thread can be sleeping in _scf_notify_wait() -- others will
 * fail.  Deletions give an fmri in the output path.
 *
 * These do not survive unbind()->bind() -- in fact, that is currently the
 * only way to clear them.
 */
int _scf_notify_add_pgname(scf_handle_t *, const char *);
int _scf_notify_add_pgtype(scf_handle_t *, const char *);
int _scf_notify_wait(scf_propertygroup_t *, char *, size_t);

/*
 * Internal interfaces for snapshot creation:
 *	_scf_snapshot_take_new(), _scf_snapshot_take_new_named(), and
 *	_scf_snapshot_take_attach() create a set of snaplevels
 *	containing frozen versions of both the instance's property groups and
 *	its parent service's property groups. _scf_snapshot_take_new() and
 *	_scf_snapshot_take_new_named() create a new snapshot to which the
 *	new snaplevels are attached, while _scf_snapshot_take_attach()
 *	attaches the new snaplevels to a pre-existing snapshot.
 *
 *	_scf_snapshot_take_new_named() records the passed in names into the
 *	snaplevel instead of the instance and service name.  This creates
 *	an inconsistency, which should be resolved by using
 *	_scf_snapshot_attach() to attach the new snaplevels to a snapshot
 *	underneath the appropriate instance.  The first snapshot can
 *	then be deleted.
 *
 *	_scf_snapshot_attach(snap1, snap2) points snap2 at the snaplevels
 *	pointed to by snap1.  After a call to either
 *	_scf_snapshot_take_attach(snap1, snap2) or
 *	_scf_snapshot_attach(inst, snap), scf_snapshot_update() will be
 *	required for any open references to snap or snap2 to see the new
 *	snaplevels.
 *
 *	_scf_snapshot_delete() deletes the snapshot object.  While
 *	snaplevels, being only loosely connected to snapshots, stay
 *	around until they are no longer referenced, any references *through
 *	this snapshot object* will be invalidated.
 *
 * _scf_snapshot_take_new() can fail with at least _HANDLE_MISMATCH,
 * _CONNECTION_BROKEN, _INVALID_ARGUMENT, _NO_RESOURCES, _PERMISSION_DENIED,
 * _NOT_SET, _EXISTS.
 *
 * _scf_snapshot_take_new_named() can fail with at least _HANDLE_MISMATCH,
 * _CONNECTION_BROKEN, _INVALID_ARGUMENT, _NO_RESOURCES, _PERMISSION_DENIED,
 * _NOT_SET, _EXISTS.
 *
 * _scf_snapshot_take_attach() can fail with _CONNECTION_BROKEN, _NOT_SET,
 * _PERMISSION_DENIED, _NO_RESOURCES, _INVALID_ARGUMENT.
 *
 * _scf_snapshot_attach() can fail with _HANDLE_MISMATCH, _CONNECTION_BROKEN,
 * _NOT_SET, _NO_RESOURCES, _PERMISSION_DENIED.
 */
int _scf_snapshot_take_new(scf_instance_t *, const char *, scf_snapshot_t *);
int _scf_snapshot_take_new_named(scf_instance_t *,
    const char *, const char *, const char *, scf_snapshot_t *);
int _scf_snapshot_take_attach(scf_instance_t *, scf_snapshot_t *);
int _scf_snapshot_attach(scf_snapshot_t *, scf_snapshot_t *);
int _scf_snapshot_delete(scf_snapshot_t *);

/*
 * Destructively portions up the first argument into the different portions
 * of a svc: fmri, and returns pointers to the applicable portions.  Omitted
 * portions are set to NULL, except for the scope, which is set to the
 * default local scope if not specified.
 *
 * Parsing is attempted in the order of: svc:, file:. The identified type
 * of the service is returned in the second argument and may take a value
 * of: SCF_FMRI_TYPE_SVC or SCF_FMRI_TYPE_FILE.
 *
 * Note that some of the returned pointers (in particular the scope) may not
 * point into the passed buffer.
 */
int scf_parse_fmri(char *, int *, const char **, const char **, const char **,
    const char **, const char **);

int scf_parse_svc_fmri(char *, const char **, const char **, const char **,
    const char **, const char **);

int scf_parse_file_fmri(char *fmri, const char **scope, const char **path);

ssize_t scf_canonify_fmri(const char *, char *, size_t);

const char *scf_type_to_string(scf_type_t);
scf_type_t scf_string_to_type(const char *);

int _smf_refresh_instance_i(scf_instance_t *);

typedef struct scf_simple_handle {
	scf_handle_t		*h;
	scf_snapshot_t		*snap;
	scf_instance_t		*inst;
	scf_propertygroup_t	*running_pg;
	scf_propertygroup_t	*editing_pg;
} scf_simple_handle_t;

void scf_simple_handle_destroy(scf_simple_handle_t *);
scf_simple_handle_t *scf_general_pg_setup(const char *, const char *);
scf_transaction_t *scf_transaction_setup(scf_simple_handle_t *);
int scf_transaction_restart(scf_simple_handle_t *, scf_transaction_t *);
int scf_read_count_property(scf_simple_handle_t *, char *, uint64_t *);
int scf_set_count_property(scf_transaction_t *, char *, uint64_t, boolean_t);

/*
 * Walks all the instances matching a given fmri list.  Each fmri in the array
 * can be one of the following:
 *
 * 	- Full instance name
 * 	- Full service name
 * 	- Full property group or property name
 * 	- Partial service or instance name
 * 	- A globbed pattern
 *
 * The matching rules for partial fmris are a slightly more complex.  We allow
 * for any substring anchored at the end of the instance or service name,
 * provided it begins with a complete element in the fmri.  For example, given
 * the fmri "svc:/system/filesystem/local:default", any of the following would
 * be acceptable matches: 'default', 'local', 'local:default',
 * 'filesystem/local'.  The following would not be acceptable:
 * 'system/filesystem', 'filesystem/loc', 'system/local'.  Possible flag values:
 *
 * 	SCF_WALK_MULTIPLE	Allow individual arguments to correspond to
 * 				multiple instances.
 *
 * 	SCF_WALK_LEGACY		Walk legacy services (indicated by a non-NULL
 * 				propery group).
 *
 * 	SCF_WALK_SERVICE	If the user specifies a service, pass the
 * 				service to the callback without iterating over
 * 				its instances.
 *
 * 	SCF_WALK_PROPERTY	Allow FMRIs which match property groups or
 * 				individual properties.  Incompatible with
 * 				SCF_WALK_LEGACY.
 *
 * 	SCF_WALK_NOINSTANCE	Walk only services.  Must be used in
 * 				conjunction with SCF_WALK_SERVICE.
 *
 * 	SCF_WALK_EXPLICIT	Walk only services if the match is exact
 *				else return instances. Must be used in
 *				conjunction with SCF_WALK_SERVICE.
 *
 * If no arguments are given, then all instances in the service graph are
 * walked.
 *
 * The second to last parameter is set to UU_EXIT_FATAL if one of the arguments
 * is an invalid FMRI or matches multiple FMRIs when SCF_WALK_MULTIPLE is not
 * set.
 *
 * The last parameter is a user-supplied error function that is called when
 * reporting invalid arguments.
 */

#define	SCF_WALK_MULTIPLE	0x01
#define	SCF_WALK_LEGACY		0x02
#define	SCF_WALK_SERVICE	0x04
#define	SCF_WALK_PROPERTY	0x08
#define	SCF_WALK_NOINSTANCE	0x10
#define	SCF_WALK_EXPLICIT	0x20

/*
 * The default locations of the repository dbs
 */
#define	REPOSITORY_DB		"/etc/svc/repository.db"
#define	NONPERSIST_DB		"/etc/svc/volatile/svc_nonpersist.db"
#define	FAST_REPOSITORY_DB	"/etc/svc/volatile/fast_repository.db"


typedef struct scf_walkinfo {
	const char		*fmri;
	scf_scope_t		*scope;
	scf_service_t		*svc;
	scf_instance_t		*inst;
	scf_propertygroup_t	*pg;
	scf_property_t		*prop;
	int			count;	/* svcprop special */
} scf_walkinfo_t;

typedef int (*scf_walk_callback)(void *, scf_walkinfo_t *);

scf_error_t scf_walk_fmri(scf_handle_t *, int, char **, int,
    scf_walk_callback, void *, int *, void (*)(const char *, ...));

/*
 * Requests a backup of the repository with a particular name, which
 * can be any alphabetic string.  Only privileged users can do this.
 *
 * Can fail with:
 *	_NOT_BOUND, _CONNECTION_BROKEN, _PERMISSION_DENIED, _INVALID_ARGUMENT,
 *	_INTERNAL (path too long, or the backup failed for an odd reason),
 *	_BACKEND_READONLY (filesystem is still read-only)
 */
int _scf_request_backup(scf_handle_t *, const char *);

/*
 * Repository switch client
 */
int _scf_repository_switch(scf_handle_t *, int);

/*
 * Determines whether a property group requires authorization to read; this
 * does not in any way reflect whether the caller has that authorization.
 * To determine that, the caller must attempt to read the value of one of the
 * group's properties.
 *
 * Can fail with:
 *	_NOT_BOUND, _CONNECTION_BROKEN, _INVALID_ARGUMENT, _INTERNAL,
 *	_NO_RESOURCES, _CONSTRAINT_VIOLATED, _DELETED.
 */
int _scf_pg_is_read_protected(const scf_propertygroup_t *, boolean_t *);

/*
 * Sets annotation data for SMF audit logging.  Once this function has been
 * set, the next audit record will be preceded by an ADT_smf_annotation
 * with the information provided in this function.  This function is used
 * to mark operations which comprise multiple primitive operations such as
 * svccfg import.
 */
int _scf_set_annotation(scf_handle_t *h, const char *operation,
    const char *file);

/*
 * scf_pattern_t
 */
typedef struct scf_pattern {
	enum	{
		PATTERN_INVALID,	/* Uninitialized state */
		PATTERN_EXACT,
		PATTERN_GLOB,
		PATTERN_PARTIAL
	} sp_type;
	char			*sp_arg;	/* Original argument */
	struct scf_match	*sp_matches;	/* List of matches */
	int			sp_matchcount;	/* # of matches */
} scf_pattern_t;

int scf_cmp_pattern(char *, scf_pattern_t *);

int gen_filenms_from_fmri(const char *, const char *, char *, char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSCF_PRIV_H */
