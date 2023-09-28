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
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2020 Joyent, Inc.
 */


#include <sys/contract/process.h>
#include <assert.h>
#include <errno.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "startd.h"

#define	SMF_SNAPSHOT_RUNNING	"running"

#define	INFO_EVENTS_ALL "info_events_all"

char *
inst_fmri_to_svc_fmri(const char *fmri)
{
	char *buf, *sfmri;
	const char *scope, *svc;
	int r;
	boolean_t local;

	buf = startd_alloc(max_scf_fmri_size);
	sfmri = startd_alloc(max_scf_fmri_size);

	(void) strcpy(buf, fmri);

	r = scf_parse_svc_fmri(buf, &scope, &svc, NULL, NULL, NULL);
	assert(r == 0);

	local = strcmp(scope, SCF_SCOPE_LOCAL) == 0;

	(void) snprintf(sfmri, max_scf_fmri_size, "svc:%s%s/%s",
	    local ? "" : "//", local ? "" : scope, svc);

	startd_free(buf, max_scf_fmri_size);

	return (sfmri);
}

/*
 * Wrapper for the scf_*_create() functions.  On SCF_ERROR_NO_MEMORY and
 * SCF_ERROR_NO_RESOURCES, retries or dies.  So this can only fail with
 * SCF_ERROR_INVALID_ARGUMENT, if h is NULL.
 */
void *
libscf_object_create(void *f(scf_handle_t *), scf_handle_t *h)
{
	void *o;
	uint_t try, msecs;
	scf_error_t err;

	o = f(h);
	if (o != NULL)
		return (o);
	err = scf_error();
	if (err != SCF_ERROR_NO_MEMORY && err != SCF_ERROR_NO_RESOURCES)
		return (NULL);

	msecs = ALLOC_DELAY;

	for (try = 0; try < ALLOC_RETRY; ++try) {
		(void) poll(NULL, 0, msecs);
		msecs *= ALLOC_DELAY_MULT;
		o = f(h);
		if (o != NULL)
			return (o);
		err = scf_error();
		if (err != SCF_ERROR_NO_MEMORY && err != SCF_ERROR_NO_RESOURCES)
			return (NULL);
	}

	uu_die("Insufficient memory.\n");
	/* NOTREACHED */
}

scf_snapshot_t *
libscf_get_running_snapshot(scf_instance_t *inst)
{
	scf_handle_t *h;
	scf_snapshot_t *snap;

	h = scf_instance_handle(inst);
	if (h == NULL)
		return (NULL);

	snap = scf_snapshot_create(h);
	if (snap == NULL)
		return (NULL);

	if (scf_instance_get_snapshot(inst, SMF_SNAPSHOT_RUNNING, snap) == 0)
		return (snap);

	scf_snapshot_destroy(snap);
	return (NULL);
}

/*
 * Make sure a service has a "running" snapshot.  If it doesn't, make one from
 * the editing configuration.
 */
scf_snapshot_t *
libscf_get_or_make_running_snapshot(scf_instance_t *inst, const char *fmri,
    boolean_t retake)
{
	scf_handle_t *h;
	scf_snapshot_t *snap;

	h = scf_instance_handle(inst);

	snap = scf_snapshot_create(h);
	if (snap == NULL)
		goto err;

	if (scf_instance_get_snapshot(inst, SMF_SNAPSHOT_RUNNING, snap) == 0)
		return (snap);

	switch (scf_error()) {
	case SCF_ERROR_NOT_FOUND:
		break;

	case SCF_ERROR_DELETED:
		scf_snapshot_destroy(snap);
		return (NULL);

	default:
err:
		log_error(LOG_NOTICE,
		    "Could not check for running snapshot of %s (%s).\n", fmri,
		    scf_strerror(scf_error()));
		scf_snapshot_destroy(snap);
		return (NULL);
	}

	if (_scf_snapshot_take_new(inst, SMF_SNAPSHOT_RUNNING, snap) == 0) {
		log_framework(LOG_DEBUG, "Took running snapshot for %s.\n",
		    fmri);
	} else {
		if (retake && scf_error() == SCF_ERROR_BACKEND_READONLY)
			restarter_mark_pending_snapshot(fmri,
			    RINST_RETAKE_RUNNING);
		else
			log_error(LOG_DEBUG,
			    "Could not create running snapshot for %s "
			    "(%s).\n", fmri, scf_strerror(scf_error()));

		scf_snapshot_destroy(snap);
		snap = NULL;
	}

	return (snap);
}

/*
 * When a service comes up, point the "start" snapshot at the "running"
 * snapshot.  Returns 0 on success, ENOTSUP if fmri designates something other
 * than an instance, ECONNABORTED, ENOENT if the instance does not exist, or
 * EACCES.
 */
int
libscf_snapshots_poststart(scf_handle_t *h, const char *fmri, boolean_t retake)
{
	scf_instance_t *inst = NULL;
	scf_snapshot_t *running, *start = NULL;
	int ret = 0, r;

	r = libscf_fmri_get_instance(h, fmri, &inst);
	switch (r) {
	case 0:
		break;

	case ENOTSUP:
	case ECONNABORTED:
	case ENOENT:
		return (r);

	case EINVAL:
	default:
		assert(0);
		abort();
	}

	start = safe_scf_snapshot_create(h);

again:
	running = libscf_get_or_make_running_snapshot(inst, fmri, retake);
	if (running == NULL) {
		ret = 0;
		goto out;
	}

lookup:
	if (scf_instance_get_snapshot(inst, "start", start) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			if (_scf_snapshot_take_new(inst, "start", start) != 0) {
				switch (scf_error()) {
				case SCF_ERROR_CONNECTION_BROKEN:
				default:
					ret = ECONNABORTED;
					goto out;

				case SCF_ERROR_DELETED:
					ret = ENOENT;
					goto out;

				case SCF_ERROR_EXISTS:
					goto lookup;

				case SCF_ERROR_NO_RESOURCES:
					uu_die("Repository server out of "
					    "resources.\n");
					/* NOTREACHED */

				case SCF_ERROR_BACKEND_READONLY:
					goto readonly;

				case SCF_ERROR_PERMISSION_DENIED:
					uu_die("Insufficient privileges.\n");
					/* NOTREACHED */

				case SCF_ERROR_BACKEND_ACCESS:
					ret = EACCES;
					goto out;

				case SCF_ERROR_HANDLE_MISMATCH:
				case SCF_ERROR_INTERNAL:
				case SCF_ERROR_INVALID_ARGUMENT:
				case SCF_ERROR_NOT_SET:
					bad_error("_scf_snapshot_take_new",
					    scf_error());
				}
			}
			break;

		case SCF_ERROR_DELETED:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_INVALID_ARGUMENT:
			bad_error("scf_instance_get_snapshot", scf_error());
		}
	}

	if (_scf_snapshot_attach(running, start) == 0) {
		log_framework(LOG_DEBUG, "Updated \"start\" snapshot for %s.\n",
		    fmri);
	} else {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
			scf_snapshot_destroy(running);
			goto again;

		case SCF_ERROR_NO_RESOURCES:
			uu_die("Repository server out of resources.\n");
			/* NOTREACHED */

		case SCF_ERROR_PERMISSION_DENIED:
			uu_die("Insufficient privileges.\n");
			/* NOTREACHED */

		case SCF_ERROR_BACKEND_ACCESS:
			ret = EACCES;
			goto out;

		case SCF_ERROR_BACKEND_READONLY:
readonly:
			if (retake)
				restarter_mark_pending_snapshot(fmri,
				    RINST_RETAKE_START);
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
			bad_error("_scf_snapshot_attach", scf_error());
		}
	}

out:
	scf_snapshot_destroy(start);
	scf_snapshot_destroy(running);
	scf_instance_destroy(inst);

	return (ret);
}

/*
 * Before a refresh, update the "running" snapshot from the editing
 * configuration.
 *
 * Returns 0 on success and -1 on failure.
 */
int
libscf_snapshots_refresh(scf_instance_t *inst, const char *fmri)
{
	scf_handle_t *h;
	scf_snapshot_t *snap;
	boolean_t err = 1;

	h = scf_instance_handle(inst);
	if (h == NULL)
		goto out;

	snap = scf_snapshot_create(h);
	if (snap == NULL)
		goto out;

	if (scf_instance_get_snapshot(inst, SMF_SNAPSHOT_RUNNING, snap) == 0) {
		if (_scf_snapshot_take_attach(inst, snap) == 0)
			err = 0;
	} else {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			err = 0;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_NOT_SET:
			assert(0);
			abort();
			/* NOTREACHED */

		default:
			goto out;
		}

		log_error(LOG_DEBUG,
		    "Service %s has no %s snapshot; creating one.\n", fmri,
		    SMF_SNAPSHOT_RUNNING);

		if (_scf_snapshot_take_new(inst, SMF_SNAPSHOT_RUNNING,
		    snap) == 0)
			err = 0;
	}

out:
	scf_snapshot_destroy(snap);

	if (!err)
		return (0);

	log_error(LOG_WARNING,
	    "Could not update \"running\" snapshot for refresh of %s.\n", fmri);
	return (-1);
}

/*
 * int libscf_read_single_astring()
 *   Reads a single astring value of the requested property into the
 *   pre-allocated buffer (conventionally of size max_scf_value_size).
 *   Multiple values constitute an error.
 *
 * Returns 0 on success or LIBSCF_PROPERTY_ABSENT or LIBSCF_PROPERTY_ERROR.
 */
static int
libscf_read_single_astring(scf_handle_t *h, scf_property_t *prop, char **ret)
{
	scf_value_t *val = safe_scf_value_create(h);
	int r = 0;

	if (scf_property_get_value(prop, val) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			r = LIBSCF_PROPERTY_ABSENT;
		else
			r = LIBSCF_PROPERTY_ERROR;
		goto read_single_astring_fail;
	}

	if (scf_value_get_astring(val, *ret, max_scf_value_size) <= 0) {
		r = LIBSCF_PROPERTY_ERROR;
		goto read_single_astring_fail;
	}

read_single_astring_fail:
	scf_value_destroy(val);
	return (r);
}

/*
 * libscf_get_stn_tset
 */
int32_t
libscf_get_stn_tset(scf_instance_t *inst)
{
	scf_handle_t		*h = scf_instance_handle(inst);
	scf_propertygroup_t	*pg = scf_pg_create(h);
	char			*pgname = NULL;
	int32_t			t, f, tset;

	assert(inst != NULL);

	pgname =  startd_alloc(max_scf_fmri_size);
	if (h == NULL || pg == NULL) {
		tset = -1;
		goto cleanup;
	}

	for (tset = 0, t = 1; t < SCF_STATE_ALL; t <<= 1) {
		f = t << 16;

		(void) strcpy(pgname, SCF_STN_PREFIX_TO);
		(void) strlcat(pgname, smf_state_to_string(t),
		    max_scf_fmri_size);

		if (scf_instance_get_pg_composed(inst, NULL, pgname, pg) ==
		    SCF_SUCCESS) {
			tset |= t;
		} else if (scf_error() != SCF_ERROR_NOT_FOUND && scf_error() !=
		    SCF_ERROR_DELETED) {
			tset = -1;
			goto cleanup;
		}

		(void) strcpy(pgname, SCF_STN_PREFIX_FROM);
		(void) strlcat(pgname, smf_state_to_string(t),
		    max_scf_fmri_size);

		if (scf_instance_get_pg_composed(inst, NULL, pgname, pg) ==
		    SCF_SUCCESS) {
			tset |= f;
		} else if (scf_error() != SCF_ERROR_NOT_FOUND && scf_error() !=
		    SCF_ERROR_DELETED) {
			tset = -1;
			goto cleanup;
		}
	}

cleanup:
	scf_pg_destroy(pg);
	startd_free(pgname, max_scf_fmri_size);

	return (tset);
}

static int32_t
libscf_get_global_stn_tset(scf_handle_t *h)
{
	scf_instance_t	*inst = scf_instance_create(h);
	int32_t		tset = -1;

	if (inst == NULL) {
		goto cleanup;
	}

	if (scf_handle_decode_fmri(h, SCF_INSTANCE_GLOBAL, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0) {
		goto cleanup;
	}

	tset = libscf_get_stn_tset(inst);

cleanup:
	scf_instance_destroy(inst);

	if (tset == -1)
		log_framework(LOG_WARNING,
		    "Failed to get system wide notification parameters: %s\n",
		    scf_strerror(scf_error()));

	return (tset);
}

static int
libscf_read_state(const scf_propertygroup_t *pg, const char *prop_name,
    restarter_instance_state_t *state)
{
	scf_handle_t *h;
	scf_property_t *prop;
	char *char_state = startd_alloc(max_scf_value_size);
	int ret = 0;

	h = scf_pg_handle(pg);
	prop = safe_scf_property_create(h);

	if (scf_pg_get_property(pg, prop_name, prop) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			ret = LIBSCF_PROPERTY_ABSENT;
		else
			ret = LIBSCF_PROPERTY_ERROR;
	} else {
		ret = libscf_read_single_astring(h, prop, &char_state);
		if (ret != 0) {
			if (ret != LIBSCF_PROPERTY_ABSENT)
				ret = LIBSCF_PROPERTY_ERROR;
		} else {
			*state = restarter_string_to_state(char_state);
			ret = 0;
		}
	}

	startd_free(char_state, max_scf_value_size);
	scf_property_destroy(prop);
	return (ret);
}

/*
 * int libscf_read_states(const scf_propertygroup_t *,
 *   restarter_instance_state_t *, restarter_instance_state_t *)
 *
 *   Set the current state and next_state values for the given service instance.
 *   Returns 0 on success, or a libscf error code on failure.
 */
int
libscf_read_states(const scf_propertygroup_t *pg,
    restarter_instance_state_t *state, restarter_instance_state_t *next_state)
{
	int state_ret, next_state_ret, ret;

	state_ret = libscf_read_state(pg, SCF_PROPERTY_STATE, state);
	next_state_ret = libscf_read_state(pg, SCF_PROPERTY_NEXT_STATE,
	    next_state);

	if (state_ret == LIBSCF_PROPERTY_ERROR ||
	    next_state_ret == LIBSCF_PROPERTY_ERROR) {
		ret = LIBSCF_PROPERTY_ERROR;
	} else if (state_ret == 0 && next_state_ret == 0) {
		ret = 0;
	} else if (state_ret == LIBSCF_PROPERTY_ABSENT &&
	    next_state_ret == LIBSCF_PROPERTY_ABSENT) {
		*state = RESTARTER_STATE_UNINIT;
		*next_state = RESTARTER_STATE_NONE;
		ret = 0;
	} else if (state_ret == LIBSCF_PROPERTY_ABSENT ||
	    next_state_ret == LIBSCF_PROPERTY_ABSENT) {
		log_framework(LOG_DEBUG,
		    "Only one repository state exists, setting "
		    "restarter states to MAINTENANCE and NONE\n");
		*state = RESTARTER_STATE_MAINT;
		*next_state = RESTARTER_STATE_NONE;
		ret = 0;
	} else {
		ret = LIBSCF_PROPERTY_ERROR;
	}

	return (ret);
}

/*
 * depgroup_empty()
 *
 * Returns 0 if not empty.
 * Returns 1 if empty.
 * Returns -1 on error (check scf_error()).
 */
int
depgroup_empty(scf_handle_t *h, scf_propertygroup_t *pg)
{
	int empty = 1;
	scf_iter_t *iter;
	scf_property_t *prop;
	int ret;

	iter = safe_scf_iter_create(h);
	prop = safe_scf_property_create(h);

	if (scf_iter_pg_properties(iter, pg) != SCF_SUCCESS) {
		scf_property_destroy(prop);
		scf_iter_destroy(iter);
		return (-1);
	}

	ret = scf_iter_next_property(iter, prop);
	if (ret < 0) {
		scf_property_destroy(prop);
		scf_iter_destroy(iter);
		return (-1);
	}

	if (ret == 1)
		empty = 0;

	scf_property_destroy(prop);
	scf_iter_destroy(iter);

	return (empty);
}

gv_type_t
depgroup_read_scheme(scf_handle_t *h, scf_propertygroup_t *pg)
{
	scf_property_t *prop;
	char *scheme = startd_alloc(max_scf_value_size);
	gv_type_t ret;

	prop = safe_scf_property_create(h);

	if (scf_pg_get_property(pg, SCF_PROPERTY_TYPE, prop) == -1 ||
	    libscf_read_single_astring(h, prop, &scheme) != 0) {
		scf_property_destroy(prop);
		startd_free(scheme, max_scf_value_size);
		return (GVT_UNSUPPORTED);
	}

	if (strcmp(scheme, "service") == 0)
		ret = GVT_INST;
	else if (strcmp(scheme, "path") == 0)
		ret = GVT_FILE;
	else
		ret = GVT_UNSUPPORTED;

	startd_free(scheme, max_scf_value_size);
	scf_property_destroy(prop);
	return (ret);
}

depgroup_type_t
depgroup_read_grouping(scf_handle_t *h, scf_propertygroup_t *pg)
{
	char *grouping = startd_alloc(max_scf_value_size);
	depgroup_type_t ret;
	scf_property_t *prop = safe_scf_property_create(h);

	if (scf_pg_get_property(pg, SCF_PROPERTY_GROUPING, prop) == -1 ||
	    libscf_read_single_astring(h, prop, &grouping) != 0) {
		scf_property_destroy(prop);
		startd_free(grouping, max_scf_value_size);
		return (DEPGRP_UNSUPPORTED);
	}

	if (strcmp(grouping, SCF_DEP_REQUIRE_ANY) == 0)
		ret = DEPGRP_REQUIRE_ANY;
	else if (strcmp(grouping, SCF_DEP_REQUIRE_ALL) == 0)
		ret = DEPGRP_REQUIRE_ALL;
	else if (strcmp(grouping, SCF_DEP_OPTIONAL_ALL) == 0)
		ret = DEPGRP_OPTIONAL_ALL;
	else if (strcmp(grouping, SCF_DEP_EXCLUDE_ALL) == 0)
		ret = DEPGRP_EXCLUDE_ALL;
	else {
		ret = DEPGRP_UNSUPPORTED;
	}
	startd_free(grouping, max_scf_value_size);
	scf_property_destroy(prop);
	return (ret);
}

restarter_error_t
depgroup_read_restart(scf_handle_t *h, scf_propertygroup_t *pg)
{
	scf_property_t *prop = safe_scf_property_create(h);
	char *restart_on = startd_alloc(max_scf_value_size);
	restarter_error_t ret;

	if (scf_pg_get_property(pg, SCF_PROPERTY_RESTART_ON, prop) == -1 ||
	    libscf_read_single_astring(h, prop, &restart_on) != 0) {
		startd_free(restart_on, max_scf_value_size);
		scf_property_destroy(prop);
		return (RERR_UNSUPPORTED);
	}

	if (strcmp(restart_on, SCF_DEP_RESET_ON_ERROR) == 0)
		ret = RERR_FAULT;
	else if (strcmp(restart_on, SCF_DEP_RESET_ON_RESTART) == 0)
		ret = RERR_RESTART;
	else if (strcmp(restart_on, SCF_DEP_RESET_ON_REFRESH) == 0)
		ret = RERR_REFRESH;
	else if (strcmp(restart_on, SCF_DEP_RESET_ON_NONE) == 0)
		ret = RERR_NONE;
	else
		ret = RERR_UNSUPPORTED;

	startd_free(restart_on, max_scf_value_size);
	scf_property_destroy(prop);
	return (ret);
}

/*
 * int get_boolean()
 *   Fetches the value of a boolean property of the given property group.
 *   Returns
 *     0 - success
 *     ECONNABORTED - repository connection broken
 *     ECANCELED - pg was deleted
 *     ENOENT - the property doesn't exist or has no values
 *     EINVAL - the property has the wrong type
 *		the property is not single-valued
 *     EACCES - the current user does not have permission to read the value
 */
static int
get_boolean(scf_propertygroup_t *pg, const char *propname, uint8_t *valuep)
{
	scf_handle_t *h;
	scf_property_t *prop;
	scf_value_t *val;
	int ret = 0, r;
	scf_type_t type;

	h = scf_pg_handle(pg);
	prop = safe_scf_property_create(h);
	val = safe_scf_value_create(h);

	if (scf_pg_get_property(pg, propname, prop) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
			ret = ECANCELED;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_pg_get_property", scf_error());
		}
	}

	if (scf_property_type(prop, &type) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_NOT_SET:
			bad_error("scf_property_type", scf_error());
		}
	}

	if (type != SCF_TYPE_BOOLEAN) {
		ret = EINVAL;
		goto out;
	}

	if (scf_property_get_value(prop, val) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_CONSTRAINT_VIOLATED:
			ret = EINVAL;
			goto out;

		case SCF_ERROR_PERMISSION_DENIED:
			ret = EACCES;
			goto out;

		case SCF_ERROR_NOT_SET:
			bad_error("scf_property_get_value", scf_error());
		}
	}

	r = scf_value_get_boolean(val, valuep);
	assert(r == 0);

out:
	scf_value_destroy(val);
	scf_property_destroy(prop);
	return (ret);
}

/*
 * get info event property from restarter:default
 */
int
libscf_get_info_events_all(scf_propertygroup_t *pg)
{
	uint8_t	v;
	int r = 0;

	if (get_boolean(pg, INFO_EVENTS_ALL, &v) == 0) {
		r = v;
	} else if (scf_error() != SCF_ERROR_NOT_FOUND) {
		uu_warn("Failed get_boolean %s/%s: %s\n",
		    SCF_PG_OPTIONS, INFO_EVENTS_ALL,
		    scf_strerror(scf_error()));
	}

	return (r);
}

/*
 * int get_count()
 *   Fetches the value of a count property of the given property group.
 *   Returns
 *     0 - success
 *     ECONNABORTED - repository connection broken
 *                    unknown libscf error
 *     ECANCELED - pg was deleted
 *     ENOENT - the property doesn't exist or has no values
 *     EINVAL - the property has the wrong type
 *              the property is not single-valued
 *     EACCES - the current user does not have permission to read the value
 */
static int
get_count(scf_propertygroup_t *pg, const char *propname, uint64_t *valuep)
{
	scf_handle_t *h;
	scf_property_t *prop;
	scf_value_t *val;
	int ret = 0, r;

	h = scf_pg_handle(pg);
	prop = safe_scf_property_create(h);
	val = safe_scf_value_create(h);

	if (scf_pg_get_property(pg, propname, prop) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
			ret = ECANCELED;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_pg_get_property", scf_error());
		}
	}

	if (scf_property_is_type(prop, SCF_TYPE_COUNT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_TYPE_MISMATCH:
			ret = EINVAL;
			goto out;

		case SCF_ERROR_DELETED:
			ret = ECANCELED;
			goto out;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_property_is_type", scf_error());
		}
	}

	if (scf_property_get_value(prop, val) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
			ret = ECANCELED;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_CONSTRAINT_VIOLATED:
			ret = EINVAL;
			goto out;

		case SCF_ERROR_PERMISSION_DENIED:
			ret = EACCES;
			goto out;

		case SCF_ERROR_NOT_SET:
			bad_error("scf_property_get_value", scf_error());
		}
	}

	r = scf_value_get_count(val, valuep);
	assert(r == 0);

out:
	scf_value_destroy(val);
	scf_property_destroy(prop);
	return (ret);
}


static void
get_restarter(scf_handle_t *h, scf_propertygroup_t *pg, char **restarter)
{
	scf_property_t *prop = safe_scf_property_create(h);

	if (scf_pg_get_property(pg, SCF_PROPERTY_RESTARTER, prop) == -1 ||
	    libscf_read_single_astring(h, prop, restarter) != 0)
		*restarter[0] = '\0';

	scf_property_destroy(prop);
}

/*
 * int libscf_instance_get_fmri(scf_instance_t *, char **)
 *   Give a valid SCF instance, return its FMRI.  Returns 0 on success,
 *   ECONNABORTED, or ECANCELED if inst is deleted.
 */
int
libscf_instance_get_fmri(scf_instance_t *inst, char **retp)
{
	char *inst_fmri = startd_alloc(max_scf_fmri_size);

	inst_fmri[0] = 0;
	if (scf_instance_to_fmri(inst, inst_fmri, max_scf_fmri_size) <= 0) {
		startd_free(inst_fmri, max_scf_fmri_size);
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_NOT_SET:
			assert(0);
			abort();
		}
	}

	*retp = inst_fmri;
	return (0);
}

/*
 * int libscf_fmri_get_instance(scf_handle_t *, const char *,
 *	scf_instance_t **)
 *   Given a valid SCF handle and an FMRI, return the SCF instance that matches
 *   exactly.  The instance must be released using scf_instance_destroy().
 *   Returns 0 on success, EINVAL if the FMRI is invalid, ENOTSUP if the FMRI
 *   is valid but designates something other than an instance, ECONNABORTED if
 *   the repository connection is broken, or ENOENT if the instance does not
 *   exist.
 */
int
libscf_fmri_get_instance(scf_handle_t *h, const char *fmri,
    scf_instance_t **instp)
{
	scf_instance_t *inst;
	int r;

	inst = safe_scf_instance_create(h);

	r = libscf_lookup_instance(fmri, inst);

	if (r == 0)
		*instp = inst;
	else
		scf_instance_destroy(inst);

	return (r);
}

int
libscf_lookup_instance(const char *fmri, scf_instance_t *inst)
{
	if (scf_handle_decode_fmri(scf_instance_handle(inst), fmri, NULL, NULL,
	    inst, NULL, NULL, SCF_DECODE_FMRI_EXACT) != SCF_SUCCESS) {
		switch (scf_error()) {
		case SCF_ERROR_INVALID_ARGUMENT:
			return (EINVAL);

		case SCF_ERROR_CONSTRAINT_VIOLATED:
			return (ENOTSUP);

		case SCF_ERROR_CONNECTION_BROKEN:
			return (ECONNABORTED);

		case SCF_ERROR_NOT_FOUND:
			return (ENOENT);

		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			bad_error("scf_handle_decode_fmri", scf_error());
		}
	}

	return (0);
}

/*
 * int libscf_get_deathrow()
 * Read deathrow for inst. Returns 0, ECONNABORTED if the connection to the
 * repository is broken, ECANCELED if inst is deleted, or ENOENT if inst
 * has no deathrow property group.
 *
 * If deathrow/deathrow was missing or invalid, *deathrow will be -1 and a
 * debug message is logged.
 */
int
libscf_get_deathrow(scf_handle_t *h, scf_instance_t *inst, int *deathrow)
{
	scf_propertygroup_t *pg;
	int r;
	uint8_t deathrow_8;

	pg = safe_scf_pg_create(h);

	if (scf_instance_get_pg_composed(inst, NULL, SCF_PG_DEATHROW, pg) !=
	    0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			scf_pg_destroy(pg);
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			scf_pg_destroy(pg);
			return (ECANCELED);

		case SCF_ERROR_NOT_FOUND:
			*deathrow = -1;
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("libscf_get_deathrow", scf_error());
		}
	} else {
		switch (r = get_boolean(pg,
		    SCF_PROPERTY_DEATHROW, &deathrow_8)) {
		case 0:
			*deathrow = deathrow_8;
			break;

		case ECONNABORTED:
		case ECANCELED:
			scf_pg_destroy(pg);
			return (r);

		case ENOENT:
		case EINVAL:
			*deathrow = -1;
			break;

		default:
			bad_error("get_boolean", r);
		}
	}

	scf_pg_destroy(pg);

	return (0);
}

/*
 * void libscf_get_basic_instance_data()
 *   Read enabled, enabled_ovr, and restarter_fmri (into an allocated
 *   buffer) for inst.  Returns 0, ECONNABORTED if the connection to the
 *   repository is broken, ECANCELED if inst is deleted, or ENOENT if inst
 *   has no general property group.
 *
 *   On success, restarter_fmri may be NULL.  If general/enabled was missing
 *   or invalid, *enabledp will be -1 and a debug message is logged.
 */
int
libscf_get_basic_instance_data(scf_handle_t *h, scf_instance_t *inst,
    const char *fmri, int *enabledp, int *enabled_ovrp, char **restarter_fmri)
{
	scf_propertygroup_t *pg;
	int r;
	uint8_t enabled_8;

	pg = safe_scf_pg_create(h);

	if (enabled_ovrp == NULL)
		goto enabled;

	if (scf_instance_get_pg_composed(inst, NULL, SCF_PG_GENERAL_OVR, pg) !=
	    0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			scf_pg_destroy(pg);
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			scf_pg_destroy(pg);
			return (ECANCELED);

		case SCF_ERROR_NOT_FOUND:
			*enabled_ovrp = -1;
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg_composed", scf_error());
		}
	} else {
		switch (r = get_boolean(pg, SCF_PROPERTY_ENABLED, &enabled_8)) {
		case 0:
			*enabled_ovrp = enabled_8;
			break;

		case ECONNABORTED:
		case ECANCELED:
			scf_pg_destroy(pg);
			return (r);

		case ENOENT:
		case EINVAL:
			*enabled_ovrp = -1;
			break;

		case EACCES:
		default:
			bad_error("get_boolean", r);
		}
	}

enabled:
	/*
	 * Since general/restarter can be at the service level, we must do
	 * a composed lookup.  These properties are immediate, though, so we
	 * must use the "editing" snapshot.  Technically enabled shouldn't be
	 * at the service level, but looking it up composed, too, doesn't
	 * hurt.
	 */
	if (scf_instance_get_pg_composed(inst, NULL, SCF_PG_GENERAL, pg) != 0) {
		scf_pg_destroy(pg);
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_NOT_FOUND:
			return (ENOENT);

		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg_composed", scf_error());
		}
	}

	switch (r = get_boolean(pg, SCF_PROPERTY_ENABLED, &enabled_8)) {
	case 0:
		*enabledp = enabled_8;
		break;

	case ECONNABORTED:
	case ECANCELED:
		scf_pg_destroy(pg);
		return (r);

	case ENOENT:
		/*
		 * DEBUG because this happens when svccfg import creates
		 * a temporary service.
		 */
		log_framework(LOG_DEBUG,
		    "general/enabled property of %s is missing.\n", fmri);
		*enabledp = -1;
		break;

	case EINVAL:
		log_framework(LOG_ERR,
		    "general/enabled property of %s is invalid.\n", fmri);
		*enabledp = -1;
		break;

	case EACCES:
	default:
		bad_error("get_boolean", r);
	}

	if (restarter_fmri != NULL)
		get_restarter(h, pg, restarter_fmri);

	scf_pg_destroy(pg);

	return (0);
}

/*
 * Sets pg to the name property group of s_inst.  If it doesn't exist, it is
 * added.
 *
 * Fails with
 *   ECONNABORTED - repository disconnection or unknown libscf error
 *   ECANCELED - inst is deleted
 *   EPERM - permission is denied
 *   EACCES - backend denied access
 *   EROFS - backend readonly
 */
int
libscf_inst_get_or_add_pg(scf_instance_t *inst, const char *name,
    const char *type, uint32_t flags, scf_propertygroup_t *pg)
{
	uint32_t f;

again:
	if (scf_instance_get_pg(inst, name, pg) == 0) {
		if (scf_pg_get_flags(pg, &f) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				return (ECONNABORTED);

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_NOT_SET:
				bad_error("scf_pg_get_flags", scf_error());
			}
		}

		if (f == flags)
			return (0);

		if (scf_pg_delete(pg) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				return (ECONNABORTED);

			case SCF_ERROR_DELETED:
				break;

			case SCF_ERROR_PERMISSION_DENIED:
				return (EPERM);

			case SCF_ERROR_BACKEND_ACCESS:
				return (EACCES);

			case SCF_ERROR_BACKEND_READONLY:
				return (EROFS);

			case SCF_ERROR_NOT_SET:
				bad_error("scf_pg_delete", scf_error());
			}
		}
	} else {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg", scf_error());
		}
	}

add:
	if (scf_instance_add_pg(inst, name, type, flags, pg) == 0)
		return (0);

	switch (scf_error()) {
	case SCF_ERROR_CONNECTION_BROKEN:
	default:
		return (ECONNABORTED);

	case SCF_ERROR_DELETED:
		return (ECANCELED);

	case SCF_ERROR_EXISTS:
		goto again;

	case SCF_ERROR_PERMISSION_DENIED:
		return (EPERM);

	case SCF_ERROR_BACKEND_ACCESS:
		return (EACCES);

	case SCF_ERROR_BACKEND_READONLY:
		return (EROFS);

	case SCF_ERROR_HANDLE_MISMATCH:
	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_NOT_SET:
		bad_error("scf_instance_add_pg", scf_error());
		/* NOTREACHED */
	}
}

/*
 * Returns
 *   0 - success
 *   ECONNABORTED - repository connection broken
 *		  - unknown libscf error
 *   ECANCELED
 */
static scf_error_t
transaction_add_set(scf_transaction_t *tx, scf_transaction_entry_t *ent,
    const char *pname, scf_type_t ty)
{
	for (;;) {
		if (scf_transaction_property_change_type(tx, ent, pname,
		    ty) == 0)
			return (0);

		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_IN_USE:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_transaction_property_change_type",
			    scf_error());
		}

		if (scf_transaction_property_new(tx, ent, pname, ty) == 0)
			return (0);

		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_EXISTS:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_IN_USE:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_transaction_property_new", scf_error());
			/* NOTREACHED */
		}
	}
}

/*
 * Returns
 *   0 - success
 *   ECONNABORTED - repository connection broken
 *		  - unknown libscf error
 *   ECANCELED - pg was deleted
 *   EPERM
 *   EACCES
 *   EROFS
 */
static int
pg_set_prop_value(scf_propertygroup_t *pg, const char *pname, scf_value_t *v)
{
	scf_handle_t *h;
	scf_transaction_t *tx;
	scf_transaction_entry_t *e;
	scf_type_t ty;
	scf_error_t scfe;
	int ret, r;

	h = scf_pg_handle(pg);
	tx = safe_scf_transaction_create(h);
	e = safe_scf_entry_create(h);

	ty = scf_value_type(v);
	assert(ty != SCF_TYPE_INVALID);

	for (;;) {
		if (scf_transaction_start(tx, pg) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				ret = ECANCELED;
				goto out;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_NOT_SET:
				bad_error("scf_transaction_start", ret);
			}
		}

		ret = transaction_add_set(tx, e, pname, ty);
		switch (ret) {
		case 0:
			break;

		case ECONNABORTED:
		case ECANCELED:
			goto out;

		default:
			bad_error("transaction_add_set", ret);
		}

		r = scf_entry_add_value(e, v);
		assert(r == 0);

		r = scf_transaction_commit(tx);
		if (r == 1)
			break;
		if (r != 0) {
			scfe = scf_error();
			scf_transaction_reset(tx);
			switch (scfe) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				ret = ECANCELED;
				goto out;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_NOT_SET:
				bad_error("scf_transaction_commit", scfe);
			}
		}

		scf_transaction_reset(tx);

		if (scf_pg_update(pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				ret = ECANCELED;
				goto out;

			case SCF_ERROR_NOT_SET:
				bad_error("scf_pg_update", scf_error());
			}
		}
	}

	ret = 0;

out:
	scf_transaction_destroy(tx);
	scf_entry_destroy(e);
	return (ret);
}

/*
 * Returns
 *   0 - success
 *   ECONNABORTED - repository connection broken
 *		  - unknown libscf error
 *   ECANCELED - inst was deleted
 *   EPERM
 *   EACCES
 *   EROFS
 */
int
libscf_inst_set_boolean_prop(scf_instance_t *inst, const char *pgname,
    const char *pgtype, uint32_t pgflags, const char *pname, int val)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg = NULL;
	scf_value_t *v;
	int ret = 0;

	h = scf_instance_handle(inst);
	pg = safe_scf_pg_create(h);
	v = safe_scf_value_create(h);

	ret = libscf_inst_get_or_add_pg(inst, pgname, pgtype, pgflags, pg);
	switch (ret) {
	case 0:
		break;

	case ECONNABORTED:
	case ECANCELED:
	case EPERM:
	case EACCES:
	case EROFS:
		goto out;

	default:
		bad_error("libscf_inst_get_or_add_pg", ret);
	}

	scf_value_set_boolean(v, val);

	ret = pg_set_prop_value(pg, pname, v);
	switch (ret) {
	case 0:
	case ECONNABORTED:
	case ECANCELED:
	case EPERM:
	case EACCES:
	case EROFS:
		break;

	default:
		bad_error("pg_set_prop_value", ret);
	}

out:
	scf_pg_destroy(pg);
	scf_value_destroy(v);
	return (ret);
}

/*
 * Returns
 *   0 - success
 *   ECONNABORTED - repository connection broken
 *		  - unknown libscf error
 *   ECANCELED - inst was deleted
 *   EPERM
 *   EACCES
 *   EROFS
 */
int
libscf_inst_set_count_prop(scf_instance_t *inst, const char *pgname,
    const char *pgtype, uint32_t pgflags, const char *pname, uint64_t count)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg = NULL;
	scf_value_t *v;
	int ret = 0;

	h = scf_instance_handle(inst);
	pg = safe_scf_pg_create(h);
	v = safe_scf_value_create(h);

	ret = libscf_inst_get_or_add_pg(inst, pgname, pgtype, pgflags, pg);
	switch (ret) {
	case 0:
		break;

	case ECONNABORTED:
	case ECANCELED:
	case EPERM:
	case EACCES:
	case EROFS:
		goto out;

	default:
		bad_error("libscf_inst_get_or_add_pg", ret);
	}

	scf_value_set_count(v, count);

	ret = pg_set_prop_value(pg, pname, v);
	switch (ret) {
	case 0:
	case ECONNABORTED:
	case ECANCELED:
	case EPERM:
	case EACCES:
	case EROFS:
		break;

	default:
		bad_error("pg_set_prop_value", ret);
	}

out:
	scf_pg_destroy(pg);
	scf_value_destroy(v);
	return (ret);
}

/*
 * Returns 0 on success, ECONNABORTED if the repository connection is broken,
 * ECANCELED if inst is deleted, EROFS if the backend is readonly, or EPERM if
 * permission was denied.
 */
int
libscf_set_enable_ovr(scf_instance_t *inst, int enable)
{
	return (libscf_inst_set_boolean_prop(inst, SCF_PG_GENERAL_OVR,
	    SCF_PG_GENERAL_OVR_TYPE, SCF_PG_GENERAL_OVR_FLAGS,
	    SCF_PROPERTY_ENABLED, enable));
}

/*
 * Returns 0 on success, ECONNABORTED if the repository connection is broken,
 * ECANCELED if inst is deleted, EROFS if the backend is readonly, or EPERM if
 * permission was denied.
 */
int
libscf_set_deathrow(scf_instance_t *inst, int deathrow)
{
	return (libscf_inst_set_boolean_prop(inst, SCF_PG_DEATHROW,
	    SCF_PG_DEATHROW_TYPE, SCF_PG_DEATHROW_FLAGS,
	    SCF_PROPERTY_DEATHROW, deathrow));
}

/*
 * Since we're clearing the over-ridden enabled state for the service, we'll
 * also take the opportunity to remove any comment.
 *
 * Returns 0, ECONNABORTED, ECANCELED, or EPERM.
 */
int
libscf_delete_enable_ovr(scf_instance_t *inst)
{
	int r = scf_instance_delete_prop(inst, SCF_PG_GENERAL_OVR,
	    SCF_PROPERTY_ENABLED);
	if (r != 0)
		return (r);
	return (scf_instance_delete_prop(inst, SCF_PG_GENERAL_OVR,
	    SCF_PROPERTY_COMMENT));
}

/*
 * Fails with
 *   ECONNABORTED - repository connection was broken
 *   ECANCELED - pg was deleted
 *   ENOENT - pg has no milestone property
 *   EINVAL - the milestone property is misconfigured
 */
static int
pg_get_milestone(scf_propertygroup_t *pg, scf_property_t *prop,
    scf_value_t *val, char *buf, size_t buf_sz)
{
	if (scf_pg_get_property(pg, SCF_PROPERTY_MILESTONE, prop) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_NOT_FOUND:
			return (ENOENT);

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_pg_get_property", scf_error());
		}
	}

	if (scf_property_get_value(prop, val) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_NOT_FOUND:
			return (EINVAL);

		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_PERMISSION_DENIED:
			bad_error("scf_property_get_value", scf_error());
		}
	}

	if (scf_value_get_astring(val, buf, buf_sz) < 0) {
		switch (scf_error()) {
		case SCF_ERROR_TYPE_MISMATCH:
			return (EINVAL);

		case SCF_ERROR_NOT_SET:
		default:
			bad_error("scf_value_get_astring", scf_error());
		}
	}

	return (0);
}

/*
 * Fails with
 *   ECONNABORTED - repository connection was broken
 *   ECANCELED - inst was deleted
 *   ENOENT - inst has no milestone property
 *   EINVAL - the milestone property is misconfigured
 */
int
libscf_get_milestone(scf_instance_t *inst, scf_property_t *prop,
    scf_value_t *val, char *buf, size_t buf_sz)
{
	scf_propertygroup_t *pg;
	int r;

	pg = safe_scf_pg_create(scf_instance_handle(inst));

	if (scf_instance_get_pg(inst, SCF_PG_OPTIONS_OVR, pg) == 0) {
		switch (r = pg_get_milestone(pg, prop, val, buf, buf_sz)) {
		case 0:
		case ECONNABORTED:
		case EINVAL:
			goto out;

		case ECANCELED:
		case ENOENT:
			break;

		default:
			bad_error("pg_get_milestone", r);
		}
	} else {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			r = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
			r = ECANCELED;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg", scf_error());
		}
	}

	if (scf_instance_get_pg(inst, SCF_PG_OPTIONS, pg) == 0) {
		r = pg_get_milestone(pg, prop, val, buf, buf_sz);
	} else {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			r = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
			r = ECANCELED;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			r = ENOENT;
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg", scf_error());
		}
	}

out:
	scf_pg_destroy(pg);

	return (r);
}

/*
 * Get the runlevel character from the runlevel property of the given property
 * group.  Fails with
 *   ECONNABORTED - repository connection was broken
 *   ECANCELED - prop's property group was deleted
 *   ENOENT - the property has no values
 *   EINVAL - the property has more than one value
 *	      the property is of the wrong type
 *	      the property value is malformed
 */
int
libscf_extract_runlevel(scf_property_t *prop, char *rlp)
{
	scf_value_t *val;
	char buf[2];

	val = safe_scf_value_create(scf_property_handle(prop));

	if (scf_property_get_value(prop, val) != 0) {
		scf_value_destroy(val);
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			return (ECONNABORTED);

		case SCF_ERROR_NOT_SET:
			return (ENOENT);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_CONSTRAINT_VIOLATED:
			return (EINVAL);

		case SCF_ERROR_NOT_FOUND:
			return (ENOENT);

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_PERMISSION_DENIED:
		default:
			bad_error("scf_property_get_value", scf_error());
		}
	}

	if (scf_value_get_astring(val, buf, sizeof (buf)) < 0) {
		scf_value_destroy(val);
		if (scf_error() != SCF_ERROR_TYPE_MISMATCH)
			bad_error("scf_value_get_astring", scf_error());

		return (EINVAL);
	}

	scf_value_destroy(val);

	if (buf[0] == '\0' || buf[1] != '\0')
		return (EINVAL);

	*rlp = buf[0];

	return (0);
}

/*
 * Delete the "runlevel" property from the given property group.  Also set the
 * "milestone" property to the given string.  Fails with ECONNABORTED,
 * ECANCELED, EPERM, EACCES, or EROFS.
 */
int
libscf_clear_runlevel(scf_propertygroup_t *pg, const char *milestone)
{
	scf_handle_t *h;
	scf_transaction_t *tx;
	scf_transaction_entry_t *e_rl, *e_ms;
	scf_value_t *val;
	scf_error_t serr;
	boolean_t isempty = B_TRUE;
	int ret = 0, r;

	h = scf_pg_handle(pg);
	tx = safe_scf_transaction_create(h);
	e_rl = safe_scf_entry_create(h);
	e_ms = safe_scf_entry_create(h);
	val = safe_scf_value_create(h);

	if (milestone) {
		r = scf_value_set_astring(val, milestone);
		assert(r == 0);
	}

	for (;;) {
		if (scf_transaction_start(tx, pg) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				ret = ECANCELED;
				goto out;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_NOT_SET:
				bad_error("scf_transaction_start", scf_error());
			}
		}

		if (scf_transaction_property_delete(tx, e_rl,
		    "runlevel") == 0) {
			isempty = B_FALSE;
		} else {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				ret = ECANCELED;
				goto out;

			case SCF_ERROR_NOT_FOUND:
				break;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_INVALID_ARGUMENT:
				bad_error("scf_transaction_property_delete",
				    scf_error());
			}
		}

		if (milestone) {
			ret = transaction_add_set(tx, e_ms,
			    SCF_PROPERTY_MILESTONE, SCF_TYPE_ASTRING);
			switch (ret) {
			case 0:
				break;

			case ECONNABORTED:
			case ECANCELED:
				goto out;

			default:
				bad_error("transaction_add_set", ret);
			}

			isempty = B_FALSE;

			r = scf_entry_add_value(e_ms, val);
			assert(r == 0);
		}

		if (isempty)
			goto out;

		r = scf_transaction_commit(tx);
		if (r == 1)
			break;
		if (r != 0) {
			serr = scf_error();
			scf_transaction_reset(tx);
			switch (serr) {
			case SCF_ERROR_CONNECTION_BROKEN:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			default:
				bad_error("scf_transaction_commit", serr);
			}
		}

		scf_transaction_reset(tx);

		if (scf_pg_update(pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_NOT_SET:
				ret = ECANCELED;
				goto out;

			default:
				assert(0);
				abort();
			}
		}
	}

out:
	scf_transaction_destroy(tx);
	scf_entry_destroy(e_rl);
	scf_entry_destroy(e_ms);
	scf_value_destroy(val);
	return (ret);
}

/*
 * int libscf_get_template_values(scf_instance_t *, scf_snapshot_t *,
 *	char **)
 *
 *   Return template values for inst in *common_name suitable for use in
 *   restarter_inst_t->ri_common_name.  Called by restarter_insert_inst().
 *
 *   Returns 0 on success, ECANCELED if the instance is deleted, ECHILD if
 *   a value fetch failed for a property, ENOENT if the instance has no
 *   tm_common_name property group or the property group is deleted, and
 *   ECONNABORTED if the repository connection is broken.
 */
int
libscf_get_template_values(scf_instance_t *inst, scf_snapshot_t *snap,
    char **common_name, char **c_common_name)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	int ret = 0, r;
	char *cname = startd_alloc(max_scf_value_size);
	char *c_cname = startd_alloc(max_scf_value_size);
	int common_name_initialized = B_FALSE;
	int c_common_name_initialized = B_FALSE;

	h = scf_instance_handle(inst);
	pg = safe_scf_pg_create(h);
	prop = safe_scf_property_create(h);

	/*
	 * The tm_common_name property group, as with all template property
	 * groups, is optional.
	 */
	if (scf_instance_get_pg_composed(inst, snap, SCF_PG_TM_COMMON_NAME, pg)
	    == -1) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			ret = ECANCELED;
			goto template_values_out;

		case SCF_ERROR_NOT_FOUND:
			goto template_values_out;

		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto template_values_out;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg_composed", scf_error());
		}
	}

	/*
	 * The name we wish uses the current locale name as the property name.
	 */
	if (st->st_locale != NULL) {
		if (scf_pg_get_property(pg, st->st_locale, prop) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_DELETED:
			case SCF_ERROR_NOT_FOUND:
				break;

			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto template_values_out;

			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_SET:
				bad_error("scf_pg_get_property", scf_error());
			}
		} else {
			if ((r = libscf_read_single_astring(h, prop, &cname)) !=
			    0) {
				if (r != LIBSCF_PROPERTY_ABSENT)
					ret = ECHILD;
				goto template_values_out;
			}

			*common_name = cname;
			common_name_initialized = B_TRUE;
		}
	}

	/*
	 * Also pull out the C locale name, as a fallback for the case where
	 * service offers no localized name.
	 */
	if (scf_pg_get_property(pg, "C", prop) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			ret = ENOENT;
			goto template_values_out;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto template_values_out;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_pg_get_property", scf_error());
		}
	} else {
		if ((r = libscf_read_single_astring(h, prop, &c_cname)) != 0) {
			if (r != LIBSCF_PROPERTY_ABSENT)
				ret = ECHILD;
			goto template_values_out;
		}

		*c_common_name = c_cname;
		c_common_name_initialized = B_TRUE;
	}


template_values_out:
	if (common_name_initialized == B_FALSE)
		startd_free(cname, max_scf_value_size);
	if (c_common_name_initialized == B_FALSE)
		startd_free(c_cname, max_scf_value_size);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);

	return (ret);
}

/*
 * int libscf_get_startd_properties(scf_handle_t *, scf_instance_t *,
 *	scf_snapshot_t *, uint_t *, char **)
 *
 *   Return startd settings for inst in *flags suitable for use in
 *   restarter_inst_t->ri_flags.  Called by restarter_insert_inst().
 *
 *   Returns 0 on success, ECANCELED if the instance is deleted, ECHILD if
 *   a value fetch failed for a property, ENOENT if the instance has no
 *   general property group or the property group is deleted, and
 *   ECONNABORTED if the repository connection is broken.
 */
int
libscf_get_startd_properties(scf_instance_t *inst,
    scf_snapshot_t *snap, uint_t *flags, char **prefixp)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	int style = RINST_CONTRACT;
	char *style_str = startd_alloc(max_scf_value_size);
	int ret = 0, r;

	h = scf_instance_handle(inst);
	pg = safe_scf_pg_create(h);
	prop = safe_scf_property_create(h);

	/*
	 * The startd property group is optional.
	 */
	if (scf_instance_get_pg_composed(inst, snap, SCF_PG_STARTD, pg) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			ret = ECANCELED;
			goto instance_flags_out;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto instance_flags_out;

		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto instance_flags_out;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg_composed", scf_error());
		}
	}

	/*
	 * 1.  Duration property.
	 */
	if (scf_pg_get_property(pg, SCF_PROPERTY_DURATION, prop) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			ret = ENOENT;
			goto instance_flags_out;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto instance_flags_out;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_pg_get_property", scf_error());
		}
	} else {
		errno = 0;
		if ((r = libscf_read_single_astring(h, prop, &style_str))
		    != 0) {
			if (r != LIBSCF_PROPERTY_ABSENT)
				ret = ECHILD;
			goto instance_flags_out;
		}

		if (strcmp(style_str, "child") == 0)
			style = RINST_WAIT;
		else if (strcmp(style_str, "transient") == 0)
			style = RINST_TRANSIENT;
	}

	/*
	 * 2.  utmpx prefix property.
	 */
	if (scf_pg_get_property(pg, SCF_PROPERTY_UTMPX_PREFIX, prop) == 0) {
		errno = 0;
		if ((r = libscf_read_single_astring(h, prop, prefixp)) != 0) {
			if (r != LIBSCF_PROPERTY_ABSENT)
				ret = ECHILD;
			goto instance_flags_out;
		}
	} else {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			ret = ENOENT;
			goto instance_flags_out;

		case SCF_ERROR_NOT_FOUND:
			goto instance_flags_out;

		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto instance_flags_out;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_pg_get_property", scf_error());
		}
	}

instance_flags_out:
	startd_free(style_str, max_scf_value_size);
	*flags = (*flags & ~RINST_STYLE_MASK) | style;

	scf_property_destroy(prop);
	scf_pg_destroy(pg);

	return (ret);
}

/*
 * int libscf_read_method_ids(scf_handle_t *, scf_instance_t *, ctid_t *,
 *   ctid_t *, pid_t *)
 *
 *  Sets given id_t variables to primary and transient contract IDs and start
 *  PID.  Returns 0, ECONNABORTED, and ECANCELED.
 */
int
libscf_read_method_ids(scf_handle_t *h, scf_instance_t *inst, const char *fmri,
    ctid_t *primary, ctid_t *transient, pid_t *start_pid)
{
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	uint64_t p, t;
	int ret = 0;

	*primary = 0;
	*transient = 0;
	*start_pid = -1;

	pg = safe_scf_pg_create(h);
	prop = safe_scf_property_create(h);
	val = safe_scf_value_create(h);

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto read_id_err;

		case SCF_ERROR_DELETED:
			ret = ECANCELED;
			goto read_id_err;

		case SCF_ERROR_NOT_FOUND:
			goto read_id_err;

		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg", scf_error());
		}
	}

	ret = get_count(pg, SCF_PROPERTY_CONTRACT, &p);
	switch (ret) {
	case 0:
		break;

	case EINVAL:
		log_error(LOG_NOTICE,
		    "%s: Ignoring %s/%s: multivalued or not of type count\n",
		    fmri, SCF_PG_RESTARTER, SCF_PROPERTY_CONTRACT);
		/* FALLTHROUGH */
	case ENOENT:
		ret = 0;
		goto read_trans;

	case ECONNABORTED:
	case ECANCELED:
		goto read_id_err;

	case EACCES:
	default:
		bad_error("get_count", ret);
	}

	*primary = p;

read_trans:
	ret = get_count(pg, SCF_PROPERTY_TRANSIENT_CONTRACT, &t);
	switch (ret) {
	case 0:
		break;

	case EINVAL:
		log_error(LOG_NOTICE,
		    "%s: Ignoring %s/%s: multivalued or not of type count\n",
		    fmri, SCF_PG_RESTARTER, SCF_PROPERTY_TRANSIENT_CONTRACT);
		/* FALLTHROUGH */

	case ENOENT:
		ret = 0;
		goto read_pid_only;

	case ECONNABORTED:
	case ECANCELED:
		goto read_id_err;

	case EACCES:
	default:
		bad_error("get_count", ret);
	}

	*transient = t;

read_pid_only:
	ret = get_count(pg, SCF_PROPERTY_START_PID, &p);
	switch (ret) {
	case 0:
		break;

	case EINVAL:
		log_error(LOG_NOTICE,
		    "%s: Ignoring %s/%s: multivalued or not of type count\n",
		    fmri, SCF_PG_RESTARTER, SCF_PROPERTY_START_PID);
		/* FALLTHROUGH */
	case ENOENT:
		ret = 0;
		goto read_id_err;

	case ECONNABORTED:
	case ECANCELED:
		goto read_id_err;

	case EACCES:
	default:
		bad_error("get_count", ret);
	}

	*start_pid = p;

read_id_err:
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	return (ret);
}

/*
 * Returns with
 *   0 - success
 *   ECONNABORTED - repository connection broken
 *		  - unknown libscf error
 *   ECANCELED - s_inst was deleted
 *   EPERM
 *   EACCES
 *   EROFS
 */
int
libscf_write_start_pid(scf_instance_t *s_inst, pid_t pid)
{
	scf_handle_t *h;
	scf_transaction_entry_t *t_pid;
	scf_value_t *v_pid;
	scf_propertygroup_t *pg;
	int ret = 0;

	h = scf_instance_handle(s_inst);

	pg = safe_scf_pg_create(h);
	t_pid = safe_scf_entry_create(h);
	v_pid = safe_scf_value_create(h);

get_pg:
	ret = libscf_inst_get_or_add_pg(s_inst, SCF_PG_RESTARTER,
	    SCF_PG_RESTARTER_TYPE, SCF_PG_RESTARTER_FLAGS, pg);
	switch (ret) {
	case 0:
		break;

	case ECONNABORTED:
	case ECANCELED:
	case EPERM:
	case EACCES:
	case EROFS:
		goto write_start_err;

	default:
		bad_error("libscf_inst_get_or_add_pg", ret);
	}

	scf_value_set_count(v_pid, pid);

	ret = pg_set_prop_value(pg, SCF_PROPERTY_START_PID, v_pid);
	switch (ret) {
	case 0:
	case ECONNABORTED:
	case EPERM:
	case EACCES:
	case EROFS:
		break;

	case ECANCELED:
		goto get_pg;

	default:
		bad_error("pg_set_prop_value", ret);
	}

write_start_err:
	scf_entry_destroy(t_pid);
	scf_value_destroy(v_pid);
	scf_pg_destroy(pg);

	return (ret);
}

/*
 * Add a property indicating the instance log file.  If the dir is
 * equal to LOG_PREFIX_EARLY, then the property restarter/alt_logfile
 * of the instance is used; otherwise, restarter/logfile is used.
 *
 * Returns
 *   0 - success
 *   ECONNABORTED
 *   ECANCELED
 *   EPERM
 *   EACCES
 *   EROFS
 *   EAGAIN
 */
int
libscf_note_method_log(scf_instance_t *inst, const char *dir, const char *file)
{
	scf_handle_t *h;
	scf_value_t *v;
	scf_propertygroup_t *pg;
	int ret = 0;
	char *logname;
	const char *propname;

	h = scf_instance_handle(inst);
	pg = safe_scf_pg_create(h);
	v = safe_scf_value_create(h);

	logname = uu_msprintf("%s%s", dir, file);

	if (logname == NULL) {
		ret = errno;
		goto out;
	}

	ret = libscf_inst_get_or_add_pg(inst, SCF_PG_RESTARTER,
	    SCF_PG_RESTARTER_TYPE, SCF_PG_RESTARTER_FLAGS, pg);
	switch (ret) {
	case 0:
		break;

	case ECONNABORTED:
	case ECANCELED:
	case EPERM:
	case EACCES:
	case EROFS:
		goto out;

	default:
		bad_error("libscf_inst_get_or_add_pg", ret);
	}

	(void) scf_value_set_astring(v, logname);

	if (strcmp(LOG_PREFIX_EARLY, dir) == 0)
		propname = SCF_PROPERTY_ALT_LOGFILE;
	else
		propname = SCF_PROPERTY_LOGFILE;

	ret = pg_set_prop_value(pg, propname, v);
	switch (ret) {
	case 0:
	case ECONNABORTED:
	case ECANCELED:
	case EPERM:
	case EACCES:
	case EROFS:
		break;

	default:
		bad_error("pg_set_prop_value", ret);
	}

out:
	scf_pg_destroy(pg);
	scf_value_destroy(v);
	uu_free(logname);
	return (ret);
}

/*
 * Returns
 *   0 - success
 *   ENAMETOOLONG - name is too long
 *   ECONNABORTED
 *   ECANCELED
 *   EPERM
 *   EACCES
 *   EROFS
 */
int
libscf_write_method_status(scf_instance_t *s_inst, const char *name,
    int status)
{
	scf_handle_t *h;
	scf_transaction_t *tx;
	scf_transaction_entry_t *e_time, *e_stat;
	scf_value_t *v_time, *v_stat;
	scf_propertygroup_t *pg;
	int ret = 0, r;
	char pname[30];
	struct timeval tv;
	scf_error_t scfe;

	if (strlen(name) + sizeof ("_method_waitstatus") > sizeof (pname))
		return (ENAMETOOLONG);

	h = scf_instance_handle(s_inst);

	pg = safe_scf_pg_create(h);
	tx = safe_scf_transaction_create(h);
	e_time = safe_scf_entry_create(h);
	v_time = safe_scf_value_create(h);
	e_stat = safe_scf_entry_create(h);
	v_stat = safe_scf_value_create(h);

	ret = libscf_inst_get_or_add_pg(s_inst, SCF_PG_RESTARTER,
	    SCF_PG_RESTARTER_TYPE, SCF_PG_RESTARTER_FLAGS, pg);
	switch (ret) {
	case 0:
		break;

	case ECONNABORTED:
	case ECANCELED:
	case EPERM:
	case EACCES:
	case EROFS:
		goto out;

	default:
		bad_error("libscf_inst_get_or_add_pg", ret);
	}

	(void) gettimeofday(&tv, NULL);

	r = scf_value_set_time(v_time, tv.tv_sec, tv.tv_usec * 1000);
	assert(r == 0);

	scf_value_set_integer(v_stat, status);

	for (;;) {
		if (scf_transaction_start(tx, pg) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				ret = ECANCELED;
				goto out;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_NOT_SET:
				bad_error("scf_transaction_start", ret);
			}
		}

		(void) snprintf(pname, sizeof (pname), "%s_method_timestamp",
		    name);
		ret = transaction_add_set(tx, e_time, pname, SCF_TYPE_TIME);
		switch (ret) {
		case 0:
			break;

		case ECONNABORTED:
		case ECANCELED:
			goto out;

		default:
			bad_error("transaction_add_set", ret);
		}

		r = scf_entry_add_value(e_time, v_time);
		assert(r == 0);

		(void) snprintf(pname, sizeof (pname), "%s_method_waitstatus",
		    name);
		ret = transaction_add_set(tx, e_stat, pname, SCF_TYPE_INTEGER);
		switch (ret) {
		case 0:
			break;

		case ECONNABORTED:
		case ECANCELED:
			goto out;

		default:
			bad_error("transaction_add_set", ret);
		}

		r = scf_entry_add_value(e_stat, v_stat);
		if (r != 0)
			bad_error("scf_entry_add_value", scf_error());

		r = scf_transaction_commit(tx);
		if (r == 1)
			break;
		if (r != 0) {
			scfe = scf_error();
			scf_transaction_reset_all(tx);
			switch (scfe) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				ret = ECANCELED;
				goto out;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_NOT_SET:
				bad_error("scf_transaction_commit", scfe);
			}
		}

		scf_transaction_reset_all(tx);

		if (scf_pg_update(pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				ret = ECANCELED;
				goto out;

			case SCF_ERROR_NOT_SET:
				bad_error("scf_pg_update", scf_error());
			}
		}
	}

out:
	scf_transaction_destroy(tx);
	scf_entry_destroy(e_time);
	scf_value_destroy(v_time);
	scf_entry_destroy(e_stat);
	scf_value_destroy(v_stat);
	scf_pg_destroy(pg);

	return (ret);
}

extern int32_t stn_global;
/*
 * Call dgraph_add_instance() for each instance in the repository.
 */
void
libscf_populate_graph(scf_handle_t *h)
{
	scf_scope_t *scope;
	scf_service_t *svc;
	scf_instance_t *inst;
	scf_iter_t *svc_iter;
	scf_iter_t *inst_iter;

	scope = safe_scf_scope_create(h);
	svc = safe_scf_service_create(h);
	inst = safe_scf_instance_create(h);
	svc_iter = safe_scf_iter_create(h);
	inst_iter = safe_scf_iter_create(h);

	deathrow_init();

	stn_global = libscf_get_global_stn_tset(h);

	if (scf_handle_get_local_scope(h, scope) !=
	    SCF_SUCCESS)
		uu_die("retrieving local scope failed: %s\n",
		    scf_strerror(scf_error()));

	if (scf_iter_scope_services(svc_iter, scope) == -1)
		uu_die("walking local scope's services failed\n");

	while (scf_iter_next_service(svc_iter, svc) > 0) {
		if (scf_iter_service_instances(inst_iter, svc) == -1)
			uu_die("unable to walk service's instances");

		while (scf_iter_next_instance(inst_iter, inst) > 0) {
			char *fmri;

			if (libscf_instance_get_fmri(inst, &fmri) == 0) {
				int err;

				err = dgraph_add_instance(fmri, inst, B_TRUE);
				if (err != 0 && err != EEXIST)
					log_error(LOG_WARNING,
					    "Failed to add %s (%s).\n", fmri,
					    strerror(err));
				startd_free(fmri, max_scf_fmri_size);
			}
		}
	}

	deathrow_fini();

	scf_iter_destroy(inst_iter);
	scf_iter_destroy(svc_iter);
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
	scf_scope_destroy(scope);
}

/*
 * Monitors get handled differently since there can be multiple of them.
 *
 * Returns exec string on success.  If method not defined, returns
 * LIBSCF_PGROUP_ABSENT; if exec property missing, returns
 * LIBSCF_PROPERTY_ABSENT.  Returns LIBSCF_PROPERTY_ERROR on other failures.
 */
char *
libscf_get_method(scf_handle_t *h, int type, restarter_inst_t *inst,
    scf_snapshot_t *snap, method_restart_t *restart_on, uint_t *cte_mask,
    uint8_t *need_sessionp, uint64_t *timeout, uint8_t *timeout_retry)
{
	scf_instance_t *scf_inst = NULL;
	scf_propertygroup_t *pg = NULL, *pg_startd = NULL;
	scf_property_t *prop = NULL;
	const char *name;
	char *method = startd_alloc(max_scf_value_size);
	char *ig = startd_alloc(max_scf_value_size);
	char *restart = startd_alloc(max_scf_value_size);
	char *ret;
	int error = 0, r;

	scf_inst = safe_scf_instance_create(h);
	pg = safe_scf_pg_create(h);
	pg_startd = safe_scf_pg_create(h);
	prop = safe_scf_property_create(h);

	ret = NULL;

	*restart_on = METHOD_RESTART_UNKNOWN;

	switch (type) {
	case METHOD_START:
		name = "start";
		break;
	case METHOD_STOP:
		name = "stop";
		break;
	case METHOD_REFRESH:
		name = "refresh";
		break;
	default:
		error = LIBSCF_PROPERTY_ERROR;
		goto get_method_cleanup;
	}

	if (scf_handle_decode_fmri(h, inst->ri_i.i_fmri, NULL, NULL, scf_inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) == -1) {
		log_error(LOG_WARNING,
		    "%s: get_method decode instance FMRI failed: %s\n",
		    inst->ri_i.i_fmri, scf_strerror(scf_error()));
		error = LIBSCF_PROPERTY_ERROR;
		goto get_method_cleanup;
	}

	if (scf_instance_get_pg_composed(scf_inst, snap, name, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			error = LIBSCF_PGROUP_ABSENT;
		else
			error = LIBSCF_PROPERTY_ERROR;
		goto get_method_cleanup;
	}

	if (scf_pg_get_property(pg, SCF_PROPERTY_EXEC, prop) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			error = LIBSCF_PROPERTY_ABSENT;
		else
			error = LIBSCF_PROPERTY_ERROR;
		goto get_method_cleanup;
	}

	error = libscf_read_single_astring(h, prop, &method);
	if (error != 0) {
		log_error(LOG_WARNING,
		    "%s: get_method failed: can't get a single astring "
		    "from %s/%s\n", inst->ri_i.i_fmri, name, SCF_PROPERTY_EXEC);
		goto get_method_cleanup;
	}

	error = expand_method_tokens(method, scf_inst, snap, type, &ret);
	if (error != 0) {
		log_instance(inst, B_TRUE, "Could not expand method tokens "
		    "in \"%s\": %s.", method, ret);
		error = LIBSCF_PROPERTY_ERROR;
		goto get_method_cleanup;
	}

	r = get_count(pg, SCF_PROPERTY_TIMEOUT, timeout);
	switch (r) {
	case 0:
		break;

	case ECONNABORTED:
		error = LIBSCF_PROPERTY_ERROR;
		goto get_method_cleanup;

	case EINVAL:
		log_instance(inst, B_TRUE, "%s/%s is multi-valued or not of "
		    "type count.  Using infinite timeout.", name,
		    SCF_PROPERTY_TIMEOUT);
		/* FALLTHROUGH */
	case ECANCELED:
	case ENOENT:
		*timeout = METHOD_TIMEOUT_INFINITE;
		break;

	case EACCES:
	default:
		bad_error("get_count", r);
	}

	/* Both 0 and -1 (ugh) are considered infinite timeouts. */
	if (*timeout == -1 || *timeout == 0)
		*timeout = METHOD_TIMEOUT_INFINITE;

	if (scf_instance_get_pg_composed(scf_inst, snap, SCF_PG_STARTD,
	    pg_startd) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_DELETED:
			error = LIBSCF_PROPERTY_ERROR;
			goto get_method_cleanup;

		case SCF_ERROR_NOT_FOUND:
			*cte_mask = 0;
			break;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg_composed", scf_error());
		}
	} else {
		if (scf_pg_get_property(pg_startd, SCF_PROPERTY_IGNORE,
		    prop) == -1) {
			if (scf_error() == SCF_ERROR_NOT_FOUND)
				*cte_mask = 0;
			else {
				error = LIBSCF_PROPERTY_ERROR;
				goto get_method_cleanup;
			}
		} else {
			error = libscf_read_single_astring(h, prop, &ig);
			if (error != 0) {
				log_error(LOG_WARNING,
				    "%s: get_method failed: can't get a single "
				    "astring from %s/%s\n", inst->ri_i.i_fmri,
				    name, SCF_PROPERTY_IGNORE);
				goto get_method_cleanup;
			}

			if (strcmp(ig, "core") == 0)
				*cte_mask = CT_PR_EV_CORE;
			else if (strcmp(ig, "signal") == 0)
				*cte_mask = CT_PR_EV_SIGNAL;
			else if (strcmp(ig, "core,signal") == 0 ||
			    strcmp(ig, "signal,core") == 0)
				*cte_mask = CT_PR_EV_CORE | CT_PR_EV_SIGNAL;
			else
				*cte_mask = 0;
		}

		r = get_boolean(pg_startd, SCF_PROPERTY_NEED_SESSION,
		    need_sessionp);
		switch (r) {
		case 0:
			break;

		case ECONNABORTED:
			error = LIBSCF_PROPERTY_ERROR;
			goto get_method_cleanup;

		case ECANCELED:
		case ENOENT:
		case EINVAL:
			*need_sessionp = 0;
			break;

		case EACCES:
		default:
			bad_error("get_boolean", r);
		}

		/*
		 * Determine whether service has overriden retry after
		 * method timeout.  Default to retry if no value is
		 * specified.
		 */
		r = get_boolean(pg_startd, SCF_PROPERTY_TIMEOUT_RETRY,
		    timeout_retry);
		switch (r) {
		case 0:
			break;

		case ECONNABORTED:
			error = LIBSCF_PROPERTY_ERROR;
			goto get_method_cleanup;

		case ECANCELED:
		case ENOENT:
		case EINVAL:
			*timeout_retry = 1;
			break;

		case EACCES:
		default:
			bad_error("get_boolean", r);
		}
	}

	if (type != METHOD_START)
		goto get_method_cleanup;

	/* Only start methods need to honor the restart_on property. */

	if (scf_pg_get_property(pg, SCF_PROPERTY_RESTART_ON, prop) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			*restart_on = METHOD_RESTART_ALL;
		else
			error = LIBSCF_PROPERTY_ERROR;
		goto get_method_cleanup;
	}

	error = libscf_read_single_astring(h, prop, &restart);
	if (error != 0) {
		log_error(LOG_WARNING,
		    "%s: get_method failed: can't get a single astring "
		    "from %s/%s\n", inst->ri_i.i_fmri, name,
		    SCF_PROPERTY_RESTART_ON);
		goto get_method_cleanup;
	}

	if (strcmp(restart, "all") == 0)
		*restart_on = METHOD_RESTART_ALL;
	else if (strcmp(restart, "external_fault") == 0)
		*restart_on = METHOD_RESTART_EXTERNAL_FAULT;
	else if (strcmp(restart, "any_fault") == 0)
		*restart_on = METHOD_RESTART_ANY_FAULT;

get_method_cleanup:
	startd_free(ig, max_scf_value_size);
	startd_free(method, max_scf_value_size);
	startd_free(restart, max_scf_value_size);

	scf_instance_destroy(scf_inst);
	scf_pg_destroy(pg);
	scf_pg_destroy(pg_startd);
	scf_property_destroy(prop);

	if (error != 0 && ret != NULL) {
		free(ret);
		ret = NULL;
	}

	errno = error;
	return (ret);
}

/*
 * Returns 1 if we've reached the fault threshold
 */
int
update_fault_count(restarter_inst_t *inst, int type)
{
	assert(type == FAULT_COUNT_INCR || type == FAULT_COUNT_RESET);

	if (type == FAULT_COUNT_INCR) {
		inst->ri_i.i_fault_count++;
		log_framework(LOG_INFO, "%s: Increasing fault count to %d\n",
		    inst->ri_i.i_fmri, inst->ri_i.i_fault_count);
	}
	if (type == FAULT_COUNT_RESET)
		inst->ri_i.i_fault_count = 0;

	if (inst->ri_i.i_fault_count >= FAULT_THRESHOLD)
		return (1);

	return (0);
}

/*
 * int libscf_unset_action()
 *   Delete any pending timestamps for the specified action which is
 *   older than the supplied ts.
 *
 *   Returns 0 on success, ECONNABORTED, EACCES, or EPERM on failure.
 */
int
libscf_unset_action(scf_handle_t *h, scf_propertygroup_t *pg,
    admin_action_t a, hrtime_t ts)
{
	scf_transaction_t *t;
	scf_transaction_entry_t *e;
	scf_property_t *prop;
	scf_value_t *val;
	hrtime_t rep_ts;
	int ret = 0, r;

	t = safe_scf_transaction_create(h);
	e = safe_scf_entry_create(h);
	prop = safe_scf_property_create(h);
	val = safe_scf_value_create(h);

	for (;;) {
		if (scf_pg_update(pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto unset_action_cleanup;

			case SCF_ERROR_DELETED:
				goto unset_action_cleanup;

			case SCF_ERROR_NOT_SET:
				assert(0);
				abort();
			}
		}

		if (scf_transaction_start(t, pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto unset_action_cleanup;

			case SCF_ERROR_DELETED:
				goto unset_action_cleanup;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto unset_action_cleanup;

			case SCF_ERROR_BACKEND_ACCESS:
			case SCF_ERROR_BACKEND_READONLY:
				ret = EACCES;
				goto unset_action_cleanup;

			case SCF_ERROR_IN_USE:
			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_SET:
				assert(0);
				abort();
			}
		}

		/* Return failure only if the property hasn't been deleted. */
		if (scf_pg_get_property(pg, admin_actions[a], prop) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto unset_action_cleanup;

			case SCF_ERROR_DELETED:
			case SCF_ERROR_NOT_FOUND:
				goto unset_action_cleanup;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
				assert(0);
				abort();
			}
		}

		if (scf_property_get_value(prop, val) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto unset_action_cleanup;

			case SCF_ERROR_DELETED:
			case SCF_ERROR_NOT_FOUND:
				goto unset_action_cleanup;

			case SCF_ERROR_CONSTRAINT_VIOLATED:
				/*
				 * More than one value was associated with
				 * this property -- this is incorrect. Take
				 * the opportunity to clean up and clear the
				 * entire property.
				 */
				rep_ts = ts;
				break;

			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_NOT_SET:
				assert(0);
				abort();
			}
		} else if (scf_value_get_integer(val, &rep_ts) == -1) {
			assert(scf_error() == SCF_ERROR_TYPE_MISMATCH);
			rep_ts = 0;
		}

		/* Repository ts is more current. Don't clear the action. */
		if (rep_ts > ts)
			goto unset_action_cleanup;

		r = scf_transaction_property_change_type(t, e,
		    admin_actions[a], SCF_TYPE_INTEGER);
		assert(r == 0);

		r = scf_transaction_commit(t);
		if (r == 1)
			break;

		if (r != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto unset_action_cleanup;

			case SCF_ERROR_DELETED:
				break;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto unset_action_cleanup;

			case SCF_ERROR_BACKEND_ACCESS:
			case SCF_ERROR_BACKEND_READONLY:
				ret = EACCES;
				goto unset_action_cleanup;

			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
				assert(0);
				abort();
			}
		}

		scf_transaction_reset(t);
	}

unset_action_cleanup:
	scf_transaction_destroy(t);
	scf_entry_destroy(e);
	scf_property_destroy(prop);
	scf_value_destroy(val);

	return (ret);
}

/*
 * Decorates & binds hndl.  hndl must be unbound.  Returns
 *   0 - success
 *   -1 - repository server is not running
 *   -1 - repository server is out of resources
 */
static int
handle_decorate_and_bind(scf_handle_t *hndl)
{
	scf_value_t *door_dec_value;

	door_dec_value = safe_scf_value_create(hndl);

	/*
	 * Decorate if alternate door path set.
	 */
	if (st->st_door_path) {
		if (scf_value_set_astring(door_dec_value, st->st_door_path) !=
		    0)
			uu_die("$STARTD_ALT_DOOR is too long.\n");

		if (scf_handle_decorate(hndl, "door_path", door_dec_value) != 0)
			bad_error("scf_handle_decorate", scf_error());
	}

	scf_value_destroy(door_dec_value);

	if (scf_handle_bind(hndl) == 0)
		return (0);

	switch (scf_error()) {
	case SCF_ERROR_NO_SERVER:
	case SCF_ERROR_NO_RESOURCES:
		return (-1);

	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_IN_USE:
	default:
		bad_error("scf_handle_bind", scf_error());
		/* NOTREACHED */
	}
}

scf_handle_t *
libscf_handle_create_bound(scf_version_t v)
{
	scf_handle_t *hndl = scf_handle_create(v);

	if (hndl == NULL)
		return (hndl);

	if (handle_decorate_and_bind(hndl) == 0)
		return (hndl);

	scf_handle_destroy(hndl);
	return (NULL);
}

void
libscf_handle_rebind(scf_handle_t *h)
{
	(void) scf_handle_unbind(h);

	MUTEX_LOCK(&st->st_configd_live_lock);

	/*
	 * Try to rebind the handle before sleeping in case the server isn't
	 * really dead.
	 */
	while (handle_decorate_and_bind(h) != 0)
		(void) pthread_cond_wait(&st->st_configd_live_cv,
		    &st->st_configd_live_lock);

	MUTEX_UNLOCK(&st->st_configd_live_lock);
}

/*
 * Create a handle and try to bind it until it succeeds.  Always returns
 * a bound handle.
 */
scf_handle_t *
libscf_handle_create_bound_loop()
{
	scf_handle_t *h;

	while ((h = scf_handle_create(SCF_VERSION)) == NULL) {
		/* This should have been caught earlier. */
		assert(scf_error() != SCF_ERROR_VERSION_MISMATCH);
		(void) sleep(2);
	}

	if (handle_decorate_and_bind(h) != 0)
		libscf_handle_rebind(h);

	return (h);
}

/*
 * Call cb for each dependency property group of inst.  cb is invoked with
 * a pointer to the scf_propertygroup_t and arg.  If the repository connection
 * is broken, returns ECONNABORTED.  If inst is deleted, returns ECANCELED.
 * If cb returns non-zero, the walk is stopped and EINTR is returned.
 * Otherwise returns 0.
 */
int
walk_dependency_pgs(scf_instance_t *inst, callback_t cb, void *arg)
{
	scf_handle_t *h;
	scf_snapshot_t *snap;
	scf_iter_t *iter;
	scf_propertygroup_t *pg;
	int r;

	h = scf_instance_handle(inst);

	iter = safe_scf_iter_create(h);
	pg = safe_scf_pg_create(h);

	snap = libscf_get_running_snapshot(inst);

	if (scf_iter_instance_pgs_typed_composed(iter, inst, snap,
	    SCF_GROUP_DEPENDENCY) != 0) {
		scf_snapshot_destroy(snap);
		scf_pg_destroy(pg);
		scf_iter_destroy(iter);
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			assert(0);
			abort();
		}
	}

	for (;;) {
		r = scf_iter_next_pg(iter, pg);
		if (r == 0)
			break;
		if (r == -1) {
			scf_snapshot_destroy(snap);
			scf_pg_destroy(pg);
			scf_iter_destroy(iter);

			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
				return (ECONNABORTED);

			case SCF_ERROR_DELETED:
				return (ECANCELED);

			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_HANDLE_MISMATCH:
			default:
				bad_error("scf_iter_next_pg", scf_error());
			}
		}

		r = cb(pg, arg);

		if (r != 0)
			break;
	}

	scf_snapshot_destroy(snap);
	scf_pg_destroy(pg);
	scf_iter_destroy(iter);

	return (r == 0 ? 0 : EINTR);
}

/*
 * Call cb for each of the string values of prop.  cb is invoked with
 * a pointer to the string and arg.  If the connection to the repository is
 * broken, ECONNABORTED is returned.  If the property is deleted, ECANCELED is
 * returned.  If the property does not have astring type, EINVAL is returned.
 * If cb returns non-zero, the walk is stopped and EINTR is returned.
 * Otherwise 0 is returned.
 */
int
walk_property_astrings(scf_property_t *prop, callback_t cb, void *arg)
{
	scf_handle_t *h;
	scf_value_t *val;
	scf_iter_t *iter;
	char *buf;
	int r;
	ssize_t sz;

	if (scf_property_is_type(prop, SCF_TYPE_ASTRING) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_TYPE_MISMATCH:
			return (EINVAL);

		case SCF_ERROR_NOT_SET:
			assert(0);
			abort();
		}
	}

	h = scf_property_handle(prop);

	val = safe_scf_value_create(h);
	iter = safe_scf_iter_create(h);

	if (scf_iter_property_values(iter, prop) != 0) {
		scf_iter_destroy(iter);
		scf_value_destroy(val);
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
			assert(0);
			abort();
		}
	}

	buf = startd_alloc(max_scf_value_size);

	for (;;) {
		r = scf_iter_next_value(iter, val);
		if (r < 0) {
			startd_free(buf, max_scf_value_size);
			scf_iter_destroy(iter);
			scf_value_destroy(val);

			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
				return (ECONNABORTED);

			case SCF_ERROR_DELETED:
				return (ECANCELED);

			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_PERMISSION_DENIED:
			default:
				bad_error("scf_iter_next_value", scf_error());
			}
		}
		if (r == 0)
			break;

		sz = scf_value_get_astring(val, buf, max_scf_value_size);
		assert(sz >= 0);

		r = cb(buf, arg);

		if (r != 0)
			break;
	}

	startd_free(buf, max_scf_value_size);
	scf_value_destroy(val);
	scf_iter_destroy(iter);

	return (r == 0 ? 0 : EINTR);
}

/*
 * Returns 0 or ECONNABORTED.
 */
int
libscf_create_self(scf_handle_t *h)
{
	scf_scope_t *scope;
	scf_service_t *svc;
	scf_instance_t *inst;
	instance_data_t idata;
	int ret = 0, r;
	ctid_t ctid;
	uint64_t uint64;
	uint_t count = 0, msecs = ALLOC_DELAY;

	const char * const startd_svc = "system/svc/restarter";
	const char * const startd_inst = "default";

	/* If SCF_SERVICE_STARTD changes, our strings must change, too. */
	assert(strcmp(SCF_SERVICE_STARTD,
	    "svc:/system/svc/restarter:default") == 0);

	scope = safe_scf_scope_create(h);
	svc = safe_scf_service_create(h);
	inst = safe_scf_instance_create(h);

	if (scf_handle_get_scope(h, SCF_SCOPE_LOCAL, scope) != 0) {
		assert(scf_error() == SCF_ERROR_CONNECTION_BROKEN);
		ret = ECONNABORTED;
		goto out;
	}

get_svc:
	if (scf_scope_get_service(scope, startd_svc, svc) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_DELETED:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_scope_get_service", scf_error());
		}

add_svc:
		if (scf_scope_add_service(scope, startd_svc, svc) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_DELETED:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_EXISTS:
				goto get_svc;

			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_BACKEND_ACCESS:
			case SCF_ERROR_BACKEND_READONLY:
				uu_warn("Could not create %s: %s\n",
				    SCF_SERVICE_STARTD,
				    scf_strerror(scf_error()));
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
				bad_error("scf_scope_add_service", scf_error());
			}
		}
	}

	if (scf_service_get_instance(svc, startd_inst, NULL) == 0)
		goto out;

	switch (scf_error()) {
	case SCF_ERROR_CONNECTION_BROKEN:
	default:
		ret = ECONNABORTED;
		goto out;

	case SCF_ERROR_NOT_FOUND:
		break;

	case SCF_ERROR_DELETED:
		goto add_svc;

	case SCF_ERROR_HANDLE_MISMATCH:
	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_NOT_SET:
		bad_error("scf_service_get_instance", scf_error());
	}

add_inst:
	if (scf_service_add_instance(svc, startd_inst, inst) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_EXISTS:
			break;

		case SCF_ERROR_PERMISSION_DENIED:
		case SCF_ERROR_BACKEND_ACCESS:
			uu_die("Could not create %s: %s\n", SCF_SERVICE_STARTD,
			    scf_strerror(scf_error()));
			/* NOTREACHED */

		case SCF_ERROR_BACKEND_READONLY:
			log_error(LOG_NOTICE,
			    "Could not create %s: backend readonly.\n",
			    SCF_SERVICE_STARTD);
			goto out;

		case SCF_ERROR_DELETED:
			goto add_svc;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_service_add_instance", scf_error());
		}
	}

	/* Set start time. */
	idata.i_fmri = SCF_SERVICE_STARTD;
	idata.i_state = RESTARTER_STATE_NONE;
	idata.i_next_state = RESTARTER_STATE_NONE;
set_state:
	switch (r = _restarter_commit_states(h, &idata,
	    RESTARTER_STATE_ONLINE, RESTARTER_STATE_NONE,
	    restarter_get_str_short(restarter_str_insert_in_graph))) {
	case 0:
		break;

	case ENOMEM:
		++count;
		if (count < ALLOC_RETRY) {
			(void) poll(NULL, 0, msecs);
			msecs *= ALLOC_DELAY_MULT;
			goto set_state;
		}

		uu_die("Insufficient memory.\n");
		/* NOTREACHED */

	case ECONNABORTED:
		ret = ECONNABORTED;
		goto out;

	case ENOENT:
		goto add_inst;

	case EPERM:
	case EACCES:
	case EROFS:
		uu_warn("Could not timestamp %s: %s\n", idata.i_fmri,
		    strerror(r));
		break;

	case EINVAL:
	default:
		bad_error("_restarter_commit_states", r);
	}

	/* Set general/enabled. */
	ret = libscf_inst_set_boolean_prop(inst, SCF_PG_GENERAL,
	    SCF_PG_GENERAL_TYPE, SCF_PG_GENERAL_FLAGS, SCF_PROPERTY_ENABLED, 1);
	switch (ret) {
	case 0:
	case ECONNABORTED:
	case EPERM:
	case EACCES:
	case EROFS:
		break;

	case ECANCELED:
		goto add_inst;

	default:
		bad_error("libscf_inst_set_boolean_prop", ret);
	}

	ret = libscf_write_start_pid(inst, getpid());
	switch (ret) {
	case 0:
	case ECONNABORTED:
	case EPERM:
	case EACCES:
	case EROFS:
		break;

	case ECANCELED:
		goto add_inst;

	default:
		bad_error("libscf_write_start_pid", ret);
	}

	ctid = proc_get_ctid();
	if (ctid > 0) {

		uint64 = (uint64_t)ctid;
		ret = libscf_inst_set_count_prop(inst,
		    SCF_PG_RESTARTER, SCF_PG_RESTARTER_TYPE,
		    SCF_PG_RESTARTER_FLAGS, SCF_PROPERTY_CONTRACT, uint64);

		switch (ret) {
		case 0:
		case ECONNABORTED:
		case EPERM:
		case EACCES:
		case EROFS:
			break;

		case ECANCELED:
			goto add_inst;

		default:
			bad_error("libscf_inst_set_count_prop", ret);
		}
	}

	ret = libscf_note_method_log(inst, LOG_PREFIX_EARLY,
	    STARTD_DEFAULT_LOG);
	if (ret == 0) {
		ret = libscf_note_method_log(inst, LOG_PREFIX_NORMAL,
		    STARTD_DEFAULT_LOG);
	}

	switch (ret) {
		case 0:
		case ECONNABORTED:
		case EPERM:
		case EACCES:
		case EROFS:
		case EAGAIN:
			break;

		case ECANCELED:
			goto add_inst;

		default:
			bad_error("libscf_note_method_log", ret);
	}

out:
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
	scf_scope_destroy(scope);
	return (ret);
}

/*
 * Returns
 *   0 - success
 *   ENOENT - SCF_SERVICE_STARTD does not exist in repository
 *   EPERM
 *   EACCES
 *   EROFS
 */
int
libscf_set_reconfig(int set)
{
	scf_handle_t *h;
	scf_instance_t *inst;
	scf_propertygroup_t *pg;
	int ret = 0;

	h = libscf_handle_create_bound_loop();
	inst = safe_scf_instance_create(h);
	pg = safe_scf_pg_create(h);

again:
	if (scf_handle_decode_fmri(h, SCF_SERVICE_STARTD, NULL, NULL,
	    inst, NULL, NULL,  SCF_DECODE_FMRI_EXACT) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			libscf_handle_rebind(h);
			goto again;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto reconfig_out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			bad_error("scf_handle_decode_fmri", scf_error());
		}
	}

	ret = libscf_inst_set_boolean_prop(inst, "system", SCF_GROUP_FRAMEWORK,
	    SCF_PG_FLAG_NONPERSISTENT, "reconfigure", set);
	switch (ret) {
	case 0:
	case EPERM:
	case EACCES:
	case EROFS:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		goto again;

	case ECANCELED:
		ret = ENOENT;
		break;

	default:
		bad_error("libscf_inst_set_boolean_prop", ret);
	}

reconfig_out:
	scf_pg_destroy(pg);
	scf_instance_destroy(inst);
	scf_handle_destroy(h);
	return (ret);
}

/*
 * Set inst->ri_m_inst to the scf instance for inst.  If it has been deleted,
 * set inst->ri_mi_deleted to true.  If the repository connection is broken, it
 * is rebound with libscf_handle_rebound().
 */
void
libscf_reget_instance(restarter_inst_t *inst)
{
	scf_handle_t *h;
	int r;

	h = scf_instance_handle(inst->ri_m_inst);

again:
	r = libscf_lookup_instance(inst->ri_i.i_fmri, inst->ri_m_inst);
	switch (r) {
	case 0:
	case ENOENT:
		inst->ri_mi_deleted = (r == ENOENT);
		return;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		goto again;

	case EINVAL:
	case ENOTSUP:
	default:
		bad_error("libscf_lookup_instance", r);
	}
}
