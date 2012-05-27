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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * scf_tmpl.c
 *
 * This file implements the bulk of the libscf templates interfaces.
 * Templates describe metadata about a service or instance in general,
 * and individual configuration properties on those services and instances.
 * Human-consumable descriptions can be provided, along with definitions
 * of valid configuration.  See service_bundle.dtd.1 for XML definitions
 * of templates, and the svccfg code for information on how those definitions
 * are translated into the repository.
 *
 * The main data structures are scf_pg_tmpl and scf_prop_tmpl.  These
 * are allocated by the callers through scf_tmpl_[pg|prop]_create(), and
 * destroyed with scf_tmpl_[pg|prop]_destroy().  They are populated by
 * scf_tmpl_get_by_pg_name(), scf_tmpl_get_by_pg(), and
 * scf_tmpl_get_by_prop().  They also store the iterator state for
 * scf_tmpl_iter_pgs() and scf_tmpl_iter_props().
 *
 * These data structures are then consumed by other functions to
 * gather information about the template (e.g. name, description,
 * choices, constraints, etc.).
 *
 * scf_tmpl_validate_fmri() does instance validation against template
 * data, and populates a set of template errors which can be explored using
 * the scf_tmpl_next_error() and the scf_tmpl_error*() suite of functions.
 *
 * The main data structures for template errors are scf_tmpl_errors,
 * defined in this file, and scf_tmpl_error, defined in libscf_priv.h.
 * scf_tmpl_error is shared with svccfg to offer common printing
 * of error messages between libscf and svccfg.
 *
 * General convenience functions are towards the top of this file,
 * followed by pg and prop template discovery functions, followed
 * by functions which gather information about the discovered
 * template.  Validation and error functions are at the end of this file.
 */

#include "lowlevel_impl.h"
#include "libscf_impl.h"
#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <locale.h>
#include <ctype.h>
#include <inttypes.h>

#define	SCF_TMPL_PG_COMMON_NAME_C	"common_name_C"

#define	SCF__TMPL_ITER_NONE		0
#define	SCF__TMPL_ITER_INST		1
#define	SCF__TMPL_ITER_RESTARTER	2
#define	SCF__TMPL_ITER_GLOBAL		3

#define	SCF_TMPL_PG_NT		0
#define	SCF_TMPL_PG_N		1
#define	SCF_TMPL_PG_T		2
#define	SCF_TMPL_PG_WILD	3

struct scf_pg_tmpl {
	int pt_populated;
	scf_handle_t *pt_h;
	scf_propertygroup_t *pt_pg;
	scf_service_t *pt_orig_svc;
	scf_service_t *pt_svc;
	scf_instance_t *pt_orig_inst;
	scf_instance_t *pt_inst;
	scf_snapshot_t *pt_snap;
	int pt_is_iter;
	scf_iter_t *pt_iter;
	int pt_iter_last;
};

#define	SCF_WALK_ERROR		-1
#define	SCF_WALK_NEXT		0
#define	SCF_WALK_DONE		1

struct pg_tmpl_walk {
	const char *pw_snapname;
	const char *pw_pgname;
	const char *pw_pgtype;
	scf_instance_t *pw_inst;
	scf_service_t *pw_svc;
	scf_snapshot_t *pw_snap;
	scf_propertygroup_t *pw_pg;
	const char *pw_target;
	char *pw_tmpl_pgname;
};

typedef struct pg_tmpl_walk pg_tmpl_walk_t;

typedef int walk_template_inst_func_t(scf_service_t *_svc,
    scf_instance_t *_inst, pg_tmpl_walk_t *p);

struct scf_prop_tmpl {
	int prt_populated;
	scf_handle_t *prt_h;
	scf_pg_tmpl_t *prt_t;
	scf_propertygroup_t *prt_pg;
	char *prt_pg_name;
	scf_iter_t *prt_iter;
};

/*
 * Common server errors are usually passed back to the caller.  This
 * array defines them centrally so that they don't need to be enumerated
 * in every libscf call.
 */
static const scf_error_t errors_server[] = {
	SCF_ERROR_BACKEND_ACCESS,
	SCF_ERROR_CONNECTION_BROKEN,
	SCF_ERROR_DELETED,
	SCF_ERROR_HANDLE_DESTROYED,
	SCF_ERROR_INTERNAL,
	SCF_ERROR_NO_MEMORY,
	SCF_ERROR_NO_RESOURCES,
	SCF_ERROR_NOT_BOUND,
	SCF_ERROR_PERMISSION_DENIED,
	0
	};

/*
 * int ismember()
 *
 * Returns 1 if the supplied error is a member of the error array, 0
 * if it is not.
 */
int
ismember(const scf_error_t error, const scf_error_t error_array[])
{
	int i;

	for (i = 0; error_array[i] != 0; ++i) {
		if (error == error_array[i])
			return (1);
	}

	return (0);
}

/*
 * char *_scf_tmpl_get_fmri()
 *
 * Given a pg_tmpl, returns the FMRI of the service or instance that
 * template describes.  The allocated string must be freed with free().
 *
 * On failure, returns NULL and sets scf_error() to _CONNECTION_BROKEN,
 * _DELETED, or _NO_MEMORY.
 */
static char *
_scf_tmpl_get_fmri(const scf_pg_tmpl_t *t)
{
	ssize_t sz = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH) + 1;
	int r;
	char *buf = malloc(sz);

	assert(t->pt_svc != NULL || t->pt_inst != NULL);
	assert(t->pt_svc == NULL || t->pt_inst == NULL);

	if (buf == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (buf);
	}

	if (t->pt_inst != NULL)
		r = scf_instance_to_fmri(t->pt_inst, buf, sz);
	else
		r = scf_service_to_fmri(t->pt_svc, buf, sz);

	if (r == -1) {
		if (ismember(scf_error(), errors_server)) {
			free(buf);
			buf = NULL;
		} else {
			assert(0);
			abort();
		}
	}

	return (buf);
}

/*
 * char *_scf_get_pg_type()
 *
 * Given a propertygroup, returns an allocated string containing the
 * type.  The string must be freed with free().
 *
 * On failure, returns NULL and sets scf_error() to: _CONNECTION_BROKEN,
 * _DELETED, or _NO_MEMORY.
 */
static char *
_scf_get_pg_type(scf_propertygroup_t *pg)
{
	ssize_t sz = scf_limit(SCF_LIMIT_MAX_PG_TYPE_LENGTH) + 1;
	char *buf = malloc(sz);

	if (buf == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	} else if (scf_pg_get_type(pg, buf, sz) == -1) {
		if (ismember(scf_error(), errors_server)) {
			free(buf);
			buf = NULL;
		} else {
			assert(0);
			abort();
		}
	}

	return (buf);
}

/*
 * char *_scf_get_prop_name()
 *
 * Given a property, returns the name in an allocated string.  The string must
 * be freed with free().
 *
 * On error, returns NULL and sets scf_error() to _CONNECTION_BROKEN,
 * _DELETED, or _NO_MEMORY.
 */
static char *
_scf_get_prop_name(scf_property_t *prop)
{
	ssize_t sz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	char *buf = malloc(sz);

	if (buf == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	} else if (scf_property_get_name(prop, buf, sz) == -1) {
		if (ismember(scf_error(), errors_server)) {
			free(buf);
			buf = NULL;
		} else {
			assert(0);
			abort();
		}
	}

	return (buf);
}

/*
 * char *_scf_get_prop_type()
 *
 * Given a property, returns the type in an allocated string.  The string must
 * be freed with free().
 *
 * On error, returns NULL and sets scf_error() to _CONNECTION_BROKEN,
 * _DELETED, or _NO_MEMORY.
 */
static char *
_scf_get_prop_type(scf_property_t *prop)
{
	scf_type_t type;
	char *ret;

	if (scf_property_type(prop, &type) == -1) {
		if (ismember(scf_error(), errors_server)) {
			return (NULL);
		} else {
			assert(0);
			abort();
		}
	}

	ret = strdup(scf_type_to_string(type));
	if (ret == NULL)
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);

	return (ret);
}

/*
 * int _read_single_value_from_pg()
 *
 * Reads a single value from the pg and property name specified.  On success,
 * returns an allocated value that must be freed.
 *
 * Returns -1 on failure, sets scf_error() to:
 *  SCF_ERROR_BACKEND_ACCESS
 *  SCF_ERROR_CONNECTION_BROKEN
 *  SCF_ERROR_CONSTRAINT_VIOLATED
 *    Property has more than one value associated with it.
 *  SCF_ERROR_DELETED
 *  SCF_ERROR_HANDLE_DESTROYED
 *  SCF_ERROR_INTERNAL
 *  SCF_ERROR_INVALID_ARGUMENT
 *    prop_name not a valid property name.
 *  SCF_ERROR_NO_MEMORY
 *  SCF_ERROR_NO_RESOURCES
 *  SCF_ERROR_NOT_BOUND
 *  SCF_ERROR_NOT_FOUND
 *    Property doesn't exist or exists and has no value.
 *  SCF_ERROR_NOT_SET
 *    Property group specified by pg is not set.
 *  SCF_ERROR_PERMISSION_DENIED
 */
static int
_read_single_value_from_pg(scf_propertygroup_t *pg, const char *prop_name,
    scf_value_t **val)
{
	scf_handle_t *h;
	scf_property_t *prop;
	int ret = 0;

	assert(val != NULL);
	if ((h = scf_pg_handle(pg)) == NULL) {
		assert(scf_error() == SCF_ERROR_HANDLE_DESTROYED);
		return (-1);
	}

	prop = scf_property_create(h);
	*val = scf_value_create(h);

	if (prop == NULL || *val == NULL) {
		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
		goto read_single_value_from_pg_fail;
	}

	if (scf_pg_get_property(pg, prop_name, prop) != 0) {
		assert(scf_error() != SCF_ERROR_HANDLE_MISMATCH);
		goto read_single_value_from_pg_fail;
	}

	if (scf_property_get_value(prop, *val) == -1) {
		assert(scf_error() != SCF_ERROR_NOT_SET);
		assert(scf_error() != SCF_ERROR_HANDLE_MISMATCH);
		goto read_single_value_from_pg_fail;
	}

	goto read_single_value_from_pg_done;

read_single_value_from_pg_fail:
	scf_value_destroy(*val);
	*val = NULL;
	ret = -1;

read_single_value_from_pg_done:
	scf_property_destroy(prop);
	return (ret);
}

/*
 * char *_scf_read_single_astring_from_pg()
 *
 * Reads an astring from the pg and property name specified.  On success,
 * returns an allocated string.  The string must be freed with free().
 *
 * Returns NULL on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_CONSTRAINT_VIOLATED
 *     Property has more than one value associated with it.
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     prop_name not a valid property name.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_NOT_SET
 *     The property group specified by pg is not set.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TYPE_MISMATCH
 */
char *
_scf_read_single_astring_from_pg(scf_propertygroup_t *pg, const char *prop_name)
{
	scf_value_t *val;
	char *ret = NULL;
	ssize_t rsize = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH) + 1;

	assert(rsize != 0);
	if (_read_single_value_from_pg(pg, prop_name, &val) == -1)
		return (NULL);

	ret = malloc(rsize);
	if (ret == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	if (scf_value_get_astring(val, ret, rsize) < 0) {
		assert(scf_error() != SCF_ERROR_NOT_SET);
		free(ret);
		ret = NULL;
	}

cleanup:
	scf_value_destroy(val);
	return (ret);
}

/*
 * char *_scf_read_tmpl_prop_type_as_string()
 *
 * Reads the property type and returns it as an allocated string.  The string
 * must be freed with free().
 *
 * Returns NULL on failure, sets scf_error() to _BACKEND_ACCESS,
 * _CONNECTION_BROKEN, _DELETED, _HANDLE_DESTROYED, _INTERNAL, _NO_MEMORY,
 * _NO_RESOURCES, _NOT_BOUND, _PERMISSION_DENIED, or _TEMPLATE_INVALID.
 */
char *
_scf_read_tmpl_prop_type_as_string(const scf_prop_tmpl_t *pt)
{
	char *type;

	type = _scf_read_single_astring_from_pg(pt->prt_pg,
	    SCF_PROPERTY_TM_TYPE);
	if (type == NULL) {
		if (ismember(scf_error(), errors_server)) {
			return (NULL);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			return (NULL);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	return (type);
}

/*
 * int _read_single_boolean_from_pg()
 *
 * Reads a boolean from the pg and property name specified.
 *
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_CONSTRAINT_VIOLATED
 *     Property has more than one value associated with it.
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     prop_name is not a valid property name.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_NOT_SET
 *     The property group specified by pg is not set.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TYPE_MISMATCH
 */
static int
_read_single_boolean_from_pg(scf_propertygroup_t *pg, const char *prop_name,
    uint8_t *bool)
{
	scf_value_t *val;
	int ret = 0;

	if (_read_single_value_from_pg(pg, prop_name, &val) == -1)
		return (-1);

	if (scf_value_get_boolean(val, bool) < 0) {
		assert(scf_error() != SCF_ERROR_NOT_SET);
		ret = -1;
	}

	scf_value_destroy(val);
	return (ret);
}

/*
 * static char ** _append_astrings_values()
 *
 * This function reads the values from the property prop_name in pg and
 * appends to an existing scf_values_t *vals.  vals may be empty, but
 * must exist.  The function skips over zero-length and duplicate values.
 *
 * Returns NULL on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     prop_name is not a valid property name.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *   SCF_ERROR_NOT_SET
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TYPE_MISMATCH
 */
static char **
_append_astrings_values(scf_propertygroup_t *pg, const char *prop_name,
    scf_values_t *vals)
{
	scf_handle_t *h;
	scf_property_t *prop;
	scf_value_t *val;
	scf_iter_t *iter;
	ssize_t rsize = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH) + 1;
	int err, count, cursz, i;

	assert(vals != NULL);
	assert(vals->value_type == SCF_TYPE_ASTRING);
	assert(vals->reserved == NULL);
	count = vals->value_count;
	if (count == 0) {
		cursz = 8;
		vals->values.v_astring = calloc(cursz, sizeof (char *));
		if (vals->values.v_astring == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			return (NULL);
		}
	} else {
		/*
		 * The array may be bigger, but it is irrelevant since
		 * we will always re-allocate a new one.
		 */
		cursz = count;
	}

	if ((h = scf_pg_handle(pg)) == NULL) {
		assert(scf_error() == SCF_ERROR_HANDLE_DESTROYED);
		return (NULL);
	}

	prop = scf_property_create(h);
	val = scf_value_create(h);
	iter = scf_iter_create(h);

	if (prop == NULL || val == NULL || iter == NULL) {
		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
		goto append_single_astring_from_pg_fail;
	}

	if (scf_pg_get_property(pg, prop_name, prop) != 0) {
		assert(scf_error() != SCF_ERROR_HANDLE_MISMATCH);
		goto append_single_astring_from_pg_fail;
	}

	if (scf_iter_property_values(iter, prop) != 0) {
		assert(scf_error() != SCF_ERROR_NOT_SET);
		assert(scf_error() != SCF_ERROR_HANDLE_MISMATCH);
		goto append_single_astring_from_pg_fail;
	}

	while ((err = scf_iter_next_value(iter, val)) == 1) {
		int flag;
		int r;

		if (count + 1 >= cursz) {
			void *aux;

			cursz *= 2;
			if ((aux = calloc(cursz, sizeof (char *))) == NULL) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				goto append_single_astring_from_pg_fail;
			}
			(void) memcpy(aux, vals->values.v_astring,
			    count * sizeof (char *));
			free(vals->values.v_astring);
			vals->values.v_astring = aux;
		}

		vals->values.v_astring[count] = malloc(rsize);
		if (vals->values.v_astring[count] == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto append_single_astring_from_pg_fail;
		}

		if ((r = scf_value_get_astring(val,
		    vals->values.v_astring[count], rsize)) <= 0) {
			/* discard zero length strings */
			if (r == 0) {
				free(vals->values.v_astring[count]);
				continue;
			}
			assert(scf_error() != SCF_ERROR_NOT_SET);
			goto append_single_astring_from_pg_fail;
		}
		for (i = 0, flag = 0; i < count; ++i) {
			/* find  and discard duplicates */
			if (strncmp(vals->values.v_astring[i],
			    vals->values.v_astring[count], rsize) == 0) {
				free(vals->values.v_astring[count]);
				flag = 1;
				break;
			}
		}
		if (flag == 1)
			continue;

		count++;
	}

	vals->value_count = count;

	if (err != 0) {
		assert(scf_error() != SCF_ERROR_NOT_SET);
		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
		assert(scf_error() != SCF_ERROR_HANDLE_MISMATCH);
		goto append_single_astring_from_pg_fail;
	} else {
		vals->values_as_strings = vals->values.v_astring;
	}

	goto append_single_astring_from_pg_done;

append_single_astring_from_pg_fail:
	for (i = 0; i <= count; ++i) {
		if (vals->values.v_astring[i] != NULL)
			free(vals->values.v_astring[i]);
		vals->values.v_astring[i] = NULL;
	}
	free(vals->values.v_astring);
	vals->values.v_astring = NULL;
	vals->value_count = 0;

append_single_astring_from_pg_done:
	scf_iter_destroy(iter);
	scf_property_destroy(prop);
	scf_value_destroy(val);
	return (vals->values.v_astring);
}

/*
 * Returns NULL on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     prop_name is not a valid property name.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *   SCF_ERROR_NOT_SET
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TYPE_MISMATCH
 */
static char **
_read_astrings_values(scf_propertygroup_t *pg, const char *prop_name,
    scf_values_t *vals)
{
	assert(vals != NULL);
	vals->value_count = 0;
	vals->value_type = SCF_TYPE_ASTRING;
	vals->reserved = NULL;
	return (_append_astrings_values(pg, prop_name, vals));
}

void
_scf_sanitize_locale(char *locale)
{
	for (; *locale != '\0'; locale++)
		if (!isalnum(*locale) && *locale != '_')
			*locale = '_';
}

/*
 * The returned string needs to be freed by the caller
 * Returns NULL on failure.  Sets scf_error() to:
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_INVALID_ARGUMENT
 *     Name isn't short enough to add the locale to.
 */
static char *
_add_locale_to_name(const char *name, const char *locale)
{
	char *lname = NULL;
	ssize_t lsz;
	char *loc;

	if (locale == NULL)
		locale = setlocale(LC_MESSAGES, NULL);
	loc = strdup(locale);
	if (loc == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	} else {
		_scf_sanitize_locale(loc);
	}

	lsz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	lname = malloc(lsz);
	if (lname == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	(void) strlcpy(lname, name, lsz);
	if (strlcat(lname, loc, lsz) >= lsz) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		free(lname);
		lname = NULL;
	}
cleanup:
	free(loc);

	return (lname);
}

/*
 * char *_tmpl_pg_name(pg, type, use_type)
 *
 * pg and type can both be NULL.  Returns the name of the most specific
 * template property group name based on the inputs.
 * If use_type is set and pg is not NULL, a property group name for a
 * property group template that has type defined is returned, even if no
 * type is provided.
 *
 * Returns NULL on failure and sets scf_error() to:
 *   SCF_ERROR_INVALID_ARGUMENT
 *     can't combine the arguments and get a reasonable length name
 *   SCF_ERROR_NO_MEMORY
 *
 */
static char *
_tmpl_pg_name(const char *pg, const char *type, int use_type)
{
	char *name;
	ssize_t limit, size = 0;

	limit = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	name = malloc(limit);
	if (name == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	if (pg == NULL && type == NULL) {
		if (strlcpy(name, SCF_PG_TM_PG_PATTERN_PREFIX, limit) >=
		    limit) {
			assert(0);
			abort();
		}
		return (name);
	} else if (pg != NULL && type != NULL) {
		size = snprintf(name, limit, "%s%s",
		    SCF_PG_TM_PG_PATTERN_NT_PREFIX, pg);
	} else if (pg != NULL && type == NULL && use_type == 1) {
		size = snprintf(name, limit, "%s%s",
		    SCF_PG_TM_PG_PATTERN_NT_PREFIX, pg);
	} else if (pg != NULL && type == NULL) {
		size = snprintf(name, limit, "%s%s",
		    SCF_PG_TM_PG_PATTERN_N_PREFIX, pg);
	} else if (type != NULL && pg == NULL) {
		size = snprintf(name, limit, "%s%s",
		    SCF_PG_TM_PG_PATTERN_T_PREFIX, type);
	} else {
		assert(0);
		abort();
	}

	if (size >= limit) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		free(name);
		return (NULL);
	} else {
		return (name);
	}
}

/*
 * _scf_get_pg_name()
 * Gets the name of the supplied property group.  On success, returns an
 * allocated string.  The string must be freed by free().
 *
 * Returns NULL on failure and sets scf_error() to _CONNECTION_BROKEN,
 * _DELETED, or _NO_MEMORY.
 */
static char *
_scf_get_pg_name(scf_propertygroup_t *pg)
{
	ssize_t sz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	char *buf = malloc(sz);

	if (buf == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	} else if (scf_pg_get_name(pg, buf, sz) == -1) {
		if (ismember(scf_error(), errors_server)) {
			free(buf);
			buf = NULL;
		} else {
			assert(0);
			abort();
		}
	}

	return (buf);
}

/*
 * char *_tmpl_prop_name()
 *
 * Returns the name of the property template prop (which is the name of
 * the property template property group) in the property group
 * template t. Returns NULL on failure and sets scf_error() to:
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_INVALID_ARGUMENT
 *     can't combine the arguments and get a reasonable length name
 *   SCF_ERROR_NO_MEMORY
 */
static char *
_tmpl_prop_name(const char *prop, scf_pg_tmpl_t *t)
{
	char *name = NULL, *pg_name = NULL;
	size_t prefix_size;
	ssize_t limit, size = 0;

	assert(prop != NULL);
	assert(t->pt_pg != NULL);

	limit = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	name = malloc(limit);
	if (name == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	if ((pg_name = _scf_get_pg_name(t->pt_pg)) == NULL) {
		free(name);
		return (NULL);
	}

	prefix_size = strlen(SCF_PG_TM_PG_PAT_BASE);
	if (strncmp(pg_name, SCF_PG_TM_PG_PAT_BASE, prefix_size) != 0) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		free(name);
		free(pg_name);
		return (NULL);
	}

	size = snprintf(name, limit, "%s%s_%s", SCF_PG_TM_PROP_PATTERN_PREFIX,
	    pg_name + prefix_size, prop);

	if (size >= limit) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		free(name);
		free(pg_name);
		return (NULL);
	} else {
		free(pg_name);
		return (name);
	}
}

/*
 *  int _get_snapshot()
 *
 *  Gets the specified snapshot.  If "snapshot" isn't defined, use the
 *  running snapshot.  If the snapshot isn't found, that may or may
 *  not be an error depending on the caller.  Return 0 in that case,
 *  but leave scf_error() set to SCF_ERROR_NOT_FOUND.  On all other
 *  errors, set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     The handle argument is NULL, or snaphot is not a valid snapshot name
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 */
static int
_get_snapshot(scf_instance_t *inst, const char *snapshot,
    scf_snapshot_t **snap)
{
	int err;
	scf_handle_t *h;

	h = scf_instance_handle(inst);
	if (h == NULL) {
		*snap = NULL;
		return (-1);
	}

	if ((*snap = scf_snapshot_create(h)) == NULL) {
		return (-1);
	}

	/* Use running snapshot by default. */
	if (snapshot == NULL)
		err = scf_instance_get_snapshot(inst, "running", *snap);
	else
		err = scf_instance_get_snapshot(inst, snapshot, *snap);

	if (err != 0) {
		if (ismember(scf_error(), errors_server)) {
			scf_snapshot_destroy(*snap);
			*snap = NULL;
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_INVALID_ARGUMENT:
			scf_snapshot_destroy(*snap);
			*snap = NULL;
			return (-1);

		case SCF_ERROR_NOT_FOUND:
			scf_snapshot_destroy(*snap);
			*snap = NULL;
			return (0);

		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			assert(0);
			abort();
		}
	}

	/*
	 * Explicitly set SCF_ERROR_NONE so that the SCF_ERROR_NOT_FOUND
	 * return above is explicitly guaranteed to be from
	 * scf_instance_get_snapshot().
	 */
	(void) scf_set_error(SCF_ERROR_NONE);
	return (0);
}

/*
 * Returns NULL on error, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_CONSTRAINT_VIOLATED
 *     The restarter's FMRI does not match an existing instance.
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     The restarter's FMRI is not a valid FMRI.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_TEMPLATE_INVALID
 *     restarter property is not SCF_TYPE_ASTRING or has more than one value
 */
static scf_instance_t *
_get_restarter_inst(scf_handle_t *h, scf_service_t *svc,
    scf_instance_t *inst, scf_snapshot_t *s)
{
	char *restarter = NULL;
	scf_instance_t *ri = NULL;
	scf_propertygroup_t *pg = NULL;
	int ret = 0;

	assert(svc != NULL || inst != NULL);
	assert(svc ==  NULL || inst == NULL);

	if ((ri = scf_instance_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL) {
		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
		goto _get_restarter_inst_fail;
	}

	if (inst != NULL)
		ret = scf_instance_get_pg_composed(inst, s, SCF_PG_GENERAL,
		    pg);
	else
		ret = scf_service_get_pg(svc, SCF_PG_GENERAL, pg);

	if (ret != 0) {
		if (ismember(scf_error(), errors_server)) {
			goto _get_restarter_inst_fail;
		} else switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			/* Assume default restarter. */
			break;

		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_HANDLE_MISMATCH:
			/*
			 * If the arguments to the above functions
			 * aren't derived from the same handle, there's
			 * something wrong with the internal implementation,
			 * not the public caller further up the chain.
			 */
		case SCF_ERROR_INVALID_ARGUMENT:
		default:
			assert(0);
			abort();
		}
	} else {
		restarter = _scf_read_single_astring_from_pg(pg,
		    SCF_PROPERTY_RESTARTER);
		/* zero length string is NOT a valid restarter */
		if (restarter != NULL && restarter[0] == '\0') {
			free(restarter);
			restarter = NULL;
		} else if (restarter == NULL) {
			if (ismember(scf_error(), errors_server)) {
				goto _get_restarter_inst_fail;
			} else switch (scf_error()) {
			case SCF_ERROR_NOT_FOUND:
				break;

			case SCF_ERROR_CONSTRAINT_VIOLATED:
			case SCF_ERROR_TYPE_MISMATCH:
				(void) scf_set_error(
				    SCF_ERROR_TEMPLATE_INVALID);
				goto _get_restarter_inst_fail;

			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_INVALID_ARGUMENT:
			default:
				assert(0);
				abort();
			}
		}
	}

	if (restarter == NULL) {
		/* Use default restarter */
		restarter = strdup(SCF_SERVICE_STARTD);
		if (restarter == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto _get_restarter_inst_fail;
		}
	}

	if (scf_handle_decode_fmri(h, restarter, NULL, NULL, ri, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT|SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0) {
		if (ismember(scf_error(), errors_server)) {
			goto _get_restarter_inst_fail;
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_FOUND:
			goto _get_restarter_inst_fail;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}
	free(restarter);
	scf_pg_destroy(pg);

	return (ri);

_get_restarter_inst_fail:
	free(restarter);
	scf_instance_destroy(ri);
	scf_pg_destroy(pg);
	return (NULL);
}

/*
 * Returns NULL on error, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_CONSTRAINT_VIOLATED
 *     Restarter property has more than one value associated with it,
 *     or FMRI does not meet restrictions in scf_handle_decode_fmri() flags.
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     The fmri argument in scf_handle_decode_fmri() is not a valid FMRI.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 */
static scf_instance_t *
_get_global_inst(scf_handle_t *h)
{
	scf_instance_t *ri;

	if ((ri = scf_instance_create(h)) == NULL) {
		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
		(void) scf_set_error(SCF_ERROR_NO_RESOURCES);
		return (NULL);
	}

	if (scf_handle_decode_fmri(h, SCF_INSTANCE_GLOBAL, NULL, NULL, ri,
	    NULL, NULL,
	    SCF_DECODE_FMRI_EXACT|SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0) {
		if (ismember(scf_error(), errors_server)) {
			scf_instance_destroy(ri);
			return (NULL);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_FOUND:
			scf_instance_destroy(ri);
			return (NULL);

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	return (ri);
}

/*
 * Call the supplied function for each of the service or instance, the
 * service's restarter, and the globally defined template instance.
 * If the function returns SCF_WALK_ERROR, the walk is ended.  If
 * the function returns SCF_WALK_NEXT, the next entity is tried.
 *
 * The function is only expected to return SCF_WALK_DONE if it has
 * found a property group match in the current entity, and has
 * populated p->pw_pg with the matching property group.
 *
 * The caller of _walk_template_instances() MUST check if the passed parameters
 * inst and svc match the fields pw_inst and pw_svc in the resulting
 * pg_tmpl_walk_t and call the destructor for the unmatching objects. The walker
 * may silently drop them if the template definition is in the restarter or in
 * the global instance.
 */
static void
_walk_template_instances(scf_service_t *svc, scf_instance_t *inst,
    scf_snapshot_t *snap, walk_template_inst_func_t *func,
    pg_tmpl_walk_t *p, int flag)
{
	scf_instance_t *tmpl_inst = NULL;
	scf_handle_t *h;
	int ret;
	char *tg = NULL;

	assert(svc != NULL || inst != NULL);
	assert(svc == NULL || inst == NULL);

	if (inst != NULL)
		h = scf_instance_handle(inst);
	else
		h = scf_service_handle(svc);
	if (h == NULL)
		goto done;

	/* First, use supplied service or instance */
	p->pw_target = SCF_TM_TARGET_THIS;
	ret = func(svc, inst, p);
	switch (ret) {
	case SCF_WALK_NEXT:
		break;
	case SCF_WALK_DONE:
		/*
		 * Check that the template scoping matches and if not,
		 * continue.
		 */
		assert(p->pw_pg != NULL);
		tg = _scf_read_single_astring_from_pg(p->pw_pg,
		    SCF_PROPERTY_TM_TARGET);
		if (tg == NULL || /* scf_error() was set */
		    (strcmp(tg, SCF_TM_TARGET_INSTANCE) != 0 &&
		    strcmp(tg, SCF_TM_TARGET_THIS) != 0 &&
		    (flag & SCF_PG_TMPL_FLAG_EXACT) !=
		    SCF_PG_TMPL_FLAG_EXACT)) {
			scf_pg_destroy(p->pw_pg);
			p->pw_pg = NULL;
			if (tg != NULL) {
				free(tg);
				tg = NULL;
				break;
			}
		}
		/*FALLTHROUGH*/
	case SCF_WALK_ERROR:
		goto done;
		/*NOTREACHED*/
	default:
		assert(0);
		abort();
	}

	/* Next the restarter. */
	p->pw_target = SCF_TM_TARGET_DELEGATE;
	tmpl_inst = _get_restarter_inst(h, svc, inst, snap);
	if (tmpl_inst != NULL) {
		ret = func(NULL, tmpl_inst, p);
		switch (ret) {
		case SCF_WALK_NEXT:
			break;
		case SCF_WALK_DONE:
			/*
			 * Check that the template scoping matches and if not,
			 * continue.
			 */
			assert(p->pw_pg != NULL);
			tg = _scf_read_single_astring_from_pg(p->pw_pg,
			    SCF_PROPERTY_TM_TARGET);
			if (tg == NULL || /* scf_error() was set */
			    strcmp(tg, SCF_TM_TARGET_DELEGATE) != 0) {
				scf_pg_destroy(p->pw_pg);
				p->pw_pg = NULL;
				if (tg != NULL) {
					free(tg);
					tg = NULL;
					break;
				}
			}
			/*FALLTHROUGH*/
		case SCF_WALK_ERROR:
			goto done;
			/*NOTREACHED*/
		default:
			assert(0);
			abort();
		}
	}

	p->pw_target = SCF_TM_TARGET_ALL;
	scf_instance_destroy(tmpl_inst);
	tmpl_inst = _get_global_inst(h);
	if (tmpl_inst != NULL) {
		ret = func(NULL, tmpl_inst, p);
		switch (ret) {
		case SCF_WALK_NEXT:
			break;
		case SCF_WALK_DONE:
			/*
			 * Check that the template scoping matches and if not,
			 * continue.
			 */
			assert(p->pw_pg != NULL);
			tg = _scf_read_single_astring_from_pg(p->pw_pg,
			    SCF_PROPERTY_TM_TARGET);
			if (tg == NULL || /* scf_error() was set */
			    strcmp(tg, SCF_TM_TARGET_ALL) != 0) {
				scf_pg_destroy(p->pw_pg);
				p->pw_pg = NULL;
				if (tg != NULL) {
					free(tg);
					tg = NULL;
					break;
				}
			}
			/*FALLTHROUGH*/
		case SCF_WALK_ERROR:
			goto done;
			/*NOTREACHED*/
		default:
			assert(0);
			abort();
		}
	}

done:
	free(tg);
	if (ret != SCF_WALK_DONE)
		scf_instance_destroy(tmpl_inst);
	p->pw_target = NULL;
}

/*
 * _get_pg() returns 0 on success and -1 on failure.  Sets scf_error()
 * on failure.
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_MISMATCH
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     name is not a valid property group.
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *   SCF_ERROR_NOT_SET
 */
static int
_get_pg(scf_service_t *svc, scf_instance_t *inst,
    const scf_snapshot_t *snap, const char *name, scf_propertygroup_t *pg)
{
	int ret;

	assert(svc != NULL || inst != NULL);
	assert(svc == NULL || inst == NULL);
	assert(pg != NULL);

	if (inst != NULL)
		ret = scf_instance_get_pg_composed(inst, snap, name, pg);
	else
		ret = scf_service_get_pg(svc, name, pg);

	return (ret);
}

/*
 * Returns SCF_WALK_NEXT for not found, SCF_WALK_ERROR for error,
 * and SCF_WALK_DONE for found.
 * On error, destroy pg and set it to NULL.
 *
 * Sets scf_error() if SCF_WALK_ERROR is returned to _BACKEND_ACCESS,
 * _CONNECTION_BROKEN, _INTERNAL, _INVALID_ARGUMENT (name is not a
 *  valid property group), _NO_RESOURCES, or _NOT_BOUND.
 */
static int
_lookup_pg(scf_service_t *svc, scf_instance_t *inst,
    const scf_snapshot_t *snap, const char *name, scf_propertygroup_t *pg)
{
	int ret;

	ret = _get_pg(svc, inst, snap, name, pg);

	if (ret == 0) {
		return (SCF_WALK_DONE);
	} else {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			return (SCF_WALK_NEXT);

		case SCF_ERROR_BACKEND_ACCESS:
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_INTERNAL:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_NO_RESOURCES:
			scf_pg_destroy(pg);
			pg = NULL;
			return (SCF_WALK_ERROR);

		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			assert(0);
			abort();
		}
	}

	/*NOTREACHED*/
}

/*
 * If match, return 0.  If no match, return 1.  If error, return -1.
 * On error set scf_error() to _BACKEND_ACCESS, _CONNECTION_BROKEN,
 * _HANDLE_DESTROYED, _INTERNAL, _NO_MEMORY, _NO_RESOURCES, _NOT_BOUND,
 * _NOT_SET (property group specified by pg is not set), _PERMISSION_DENIED,
 * or _TEMPLATE_INVALID (target property is not SCF_TYPE_ASTRING or has
 * more than one value).
 */
static int
check_target_match(scf_propertygroup_t *pg, const char *target)
{
	char *pg_target;
	int ret = 0;

	pg_target = _scf_read_single_astring_from_pg(pg,
	    SCF_PROPERTY_TM_TARGET);
	if (pg_target == NULL) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
		case SCF_ERROR_NOT_FOUND:
			return (1);

		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(
			    SCF_ERROR_TEMPLATE_INVALID);
			/*FALLTHROUGH*/

		case SCF_ERROR_BACKEND_ACCESS:
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_HANDLE_DESTROYED:
		case SCF_ERROR_INTERNAL:
		case SCF_ERROR_NO_RESOURCES:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_PERMISSION_DENIED:
			return (-1);

		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_INVALID_ARGUMENT:
		default:
			assert(0);
			abort();
		}
		/*NOTREACHED*/
	}

	/* For a desired target of 'this', check for 'this' and 'instance'. */
	if ((strcmp(target, SCF_TM_TARGET_INSTANCE) == 0 ||
	    strcmp(target, SCF_TM_TARGET_THIS) == 0) &&
	    (strcmp(pg_target, SCF_TM_TARGET_INSTANCE) == 0 ||
	    strcmp(pg_target, SCF_TM_TARGET_THIS) == 0)) {
		goto cleanup;
	}

	if (strcmp(target, SCF_TM_TARGET_DELEGATE) == 0 &&
	    strcmp(pg_target, SCF_TM_TARGET_DELEGATE) == 0) {
		goto cleanup;
	}

	if (strcmp(target, SCF_TM_TARGET_ALL) == 0 &&
	    strcmp(pg_target, SCF_TM_TARGET_ALL) == 0) {
		goto cleanup;
	}

	ret = 1;
cleanup:
	free(pg_target);
	return (ret);
}

/*
 * Check if a matching template property group exists for each of:
 * name and type, name only, type only, and completely wildcarded
 * template.
 *
 * Both pg_name and pg_type are optional.
 *
 * Returns NULL on failure, sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     can't combine the _tmpl_pg_name arguments and get a reasonable
 *     length name, or pg_name is not a valid property group.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     target property is not SCF_TYPE_ASTRING or has more than one value.
 */
static scf_propertygroup_t *
_find_template_pg_match(scf_service_t *svc, scf_instance_t *inst,
    const scf_snapshot_t *snap, const char *pg_name, const char *pg_type,
    const char *target, char **tmpl_pg_name)
{
	int ret, r;
	scf_propertygroup_t *pg = NULL;
	scf_handle_t *h;
	scf_iter_t *iter;
	char *name, *type;

	assert(inst != NULL || svc != NULL);
	assert(inst == NULL || svc == NULL);

	if (inst != NULL)
		h = scf_instance_handle(inst);
	else
		h = scf_service_handle(svc);
	if (h == NULL) {
		return (NULL);
	}

	if ((pg = scf_pg_create(h)) == NULL ||
	    (iter = scf_iter_create(h)) == NULL) {
		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
		scf_pg_destroy(pg);
		return (NULL);
	}

	/*
	 * We're going to walk through the possible pg templates that
	 * could match the supplied name and type.  We do this
	 * by explicit name lookups when possible to avoid having to
	 * keep track of a most-explicit-match during iteration.
	 */

	/* First look for a template with name and type set and matching. */
	*tmpl_pg_name = _tmpl_pg_name(pg_name, pg_type, 1);
	if (*tmpl_pg_name == NULL)
		goto fail;
	ret = _lookup_pg(svc, inst, snap, *tmpl_pg_name, pg);
	if (ret != SCF_WALK_NEXT) {
		if (pg != NULL) {
			if ((r = check_target_match(pg, target)) == 0)
				goto done;
			else if (r == -1)
				goto fail;
		} else {
			goto done;
		}
	}
	free(*tmpl_pg_name);

	/*
	 * Need to search on a name-only match before searching on
	 * type matches.
	 */

	*tmpl_pg_name = _tmpl_pg_name(pg_name, NULL, 0);
	if (*tmpl_pg_name == NULL)
		goto fail;
	ret = _lookup_pg(svc, inst, snap, *tmpl_pg_name, pg);
	if (ret != SCF_WALK_NEXT) {
		if (pg != NULL) {
			if ((r = check_target_match(pg, target)) == 0)
				goto done;
			else if (r == -1)
				goto fail;
		} else {
			goto done;
		}
	}
	free(*tmpl_pg_name);

	/* Next, see if there's an "nt" template where the type matches. */
	if (pg_type != NULL && pg_name == NULL) {
		if (inst != NULL)
			ret = scf_iter_instance_pgs_typed_composed(iter, inst,
			    snap, SCF_GROUP_TEMPLATE_PG_PATTERN);
		else
			ret = scf_iter_service_pgs_typed(iter, svc,
			    SCF_GROUP_TEMPLATE_PG_PATTERN);

		if (ret != 0) {
			if (ismember(scf_error(), errors_server)) {
				goto fail;
			} else {
				assert(0);
				abort();
			}
		}

		while ((ret = scf_iter_next_pg(iter, pg)) == 1) {
			/* Make sure this is a name and type specified pg. */
			name = _scf_read_single_astring_from_pg(pg,
			    SCF_PROPERTY_TM_NAME);
			if (name == NULL)
				continue;
			type = _scf_read_single_astring_from_pg(pg,
			    SCF_PROPERTY_TM_TYPE);
			if (type == NULL) {
				free(name);
				continue;
			}
			if (strcmp(pg_type, type) == 0 &&
			    check_target_match(pg, target) == 0) {
				*tmpl_pg_name = name;
				free(type);
				goto done;
			}
			free(type);
			free(name);
		}
		if (ret == -1) {
			if (ismember(scf_error(), errors_server)) {
				goto fail;
			} else {
				assert(0);
				abort();
			}
		}
	}

	*tmpl_pg_name = _tmpl_pg_name(NULL, pg_type, 0);
	if (*tmpl_pg_name == NULL)
		goto fail;
	ret = _lookup_pg(svc, inst, snap, *tmpl_pg_name, pg);
	if (ret != SCF_WALK_NEXT) {
		if (pg != NULL) {
			if ((r = check_target_match(pg, target)) == 0)
				goto done;
			else if (r == -1)
				goto fail;
		} else {
			goto done;
		}
	}
	free(*tmpl_pg_name);

	*tmpl_pg_name = _tmpl_pg_name(NULL, NULL, 0);
	if (*tmpl_pg_name == NULL)
		goto fail;
	ret = _lookup_pg(svc, inst, snap, *tmpl_pg_name, pg);
	if (ret != SCF_WALK_NEXT) {
		if (pg != NULL) {
			if ((r = check_target_match(pg, target)) == 0)
				goto done;
			else if (r == -1)
				goto fail;
		} else {
			goto done;
		}
	}

	(void) scf_set_error(SCF_ERROR_NOT_FOUND);
fail:
	scf_pg_destroy(pg);
	if (*tmpl_pg_name != NULL)
		free(*tmpl_pg_name);
	*tmpl_pg_name = NULL;
	pg = NULL;
done:
	if (ret == SCF_WALK_ERROR)
		free(*tmpl_pg_name);
	scf_iter_destroy(iter);
	return (pg);
}

/*
 * Finds the pg match in either the supplied service or instance.
 * Returns SCF_WALK_ERROR, SCF_WALK_NEXT, or SCF_WALK_DONE.
 * If returning SCF_WALK_ERROR, sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     The snaphot is not a valid snapshot name,
 *     or can't create a reasonable property group template name.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     target property is not SCF_TYPE_ASTRING or has more than one value.
 */
static int
find_pg_match(scf_service_t *svc, scf_instance_t *inst, pg_tmpl_walk_t *p)
{
	scf_snapshot_t *tmpl_snap = NULL;
	scf_propertygroup_t *pg;
	scf_handle_t *h;
	char *tmpl_pg_name;

	assert(svc != NULL || inst != NULL);
	assert(svc == NULL || inst == NULL);

	if (inst != NULL)
		h = scf_instance_handle(inst);
	else
		h = scf_service_handle(svc);
	if (h == NULL)
		return (SCF_WALK_ERROR);

	if (p->pw_snapname != NULL) {
		if (_get_snapshot(inst, p->pw_snapname, &tmpl_snap) == -1)
			return (SCF_WALK_ERROR);
	}
	pg = _find_template_pg_match(svc, inst, tmpl_snap, p->pw_pgname,
	    p->pw_pgtype, p->pw_target, &tmpl_pg_name);

	if (pg != NULL) {
		p->pw_snap = tmpl_snap;
		p->pw_pg = pg;
		p->pw_tmpl_pgname = tmpl_pg_name;
		p->pw_inst = inst;
		p->pw_svc = svc;
		return (SCF_WALK_DONE);
	}

	scf_snapshot_destroy(tmpl_snap);
	return (SCF_WALK_NEXT);
}

/*
 * return 0 on success and -1 on failure.
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_HANDLE_MISMATCH
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     FMRI argument, snapshot name, pg_name, or pg is invalid.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *   SCF_ERROR_NOT_SET
 */
int
scf_tmpl_get_by_pg(scf_propertygroup_t *pg, scf_pg_tmpl_t *pg_tmpl, int flags)
{
	char *fmribuf = NULL, *snapbuf = NULL, *pg_name = NULL, *pg_type = NULL;
	int ret;
	ssize_t fbufsz = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH) + 1;
	ssize_t nbufsz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	ssize_t tbufsz = scf_limit(SCF_LIMIT_MAX_PG_TYPE_LENGTH) + 1;
	scf_instance_t *inst = NULL;
	scf_snaplevel_t *snaplvl = NULL;
	scf_service_t *svc = NULL;
	scf_handle_t *h;
	scf_snapshot_t *snap = NULL;
	pg_tmpl_walk_t *p = NULL;

	assert(fbufsz != 0 && nbufsz != 0 && tbufsz != 0);

	scf_tmpl_pg_reset(pg_tmpl);

	if ((h = scf_pg_handle(pg)) == NULL)
		return (-1);

	if ((inst = scf_instance_create(h)) == NULL ||
	    (svc = scf_service_create(h)) == NULL ||
	    (snaplvl = scf_snaplevel_create(h)) == NULL) {
		goto fail;
	}

	if ((fmribuf = malloc(fbufsz)) == NULL ||
	    (pg_name = malloc(nbufsz)) == NULL ||
	    (pg_type = malloc(tbufsz)) == NULL ||
	    (p = calloc(1, sizeof (pg_tmpl_walk_t))) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto fail;
	}

	if (scf_pg_get_name(pg, pg_name, nbufsz) < 0) {
		goto fail;
	}

	if (scf_pg_get_type(pg, pg_type, tbufsz) < 0) {
		goto fail;
	}
	p->pw_pgname = pg_name;
	p->pw_pgtype = pg_type;

	ret = scf_pg_get_parent_snaplevel(pg, snaplvl);
	if (ret == -1) {
		switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			/* Parent type doesn't match.  Keep looking. */
			break;

		case SCF_ERROR_DELETED:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_NOT_SET:
			/* Pass these back to the caller. */
			goto fail;

		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			assert(0);
			abort();
		}

		/*
		 * No snapshot.  We'll use 'editing' by default since
		 * snap and snapbuf are NULL.
		 */
		p->pw_snapname = NULL;

	} else {
		if ((snap = scf_snapshot_create(h)) == NULL) {
			goto fail;
		}

		ret = scf_snaplevel_get_parent(snaplvl, snap);
		if (ret == -1) {
			if (ismember(scf_error(), errors_server)) {
				goto fail;
			} else {
				assert(0);
				abort();
			}
		}

		/* Grab snapshot name while we're here. */
		if ((snapbuf = malloc(nbufsz)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto fail;
		}
		if (scf_snapshot_get_name(snap, snapbuf, nbufsz) < 0) {
			if (ismember(scf_error(), errors_server)) {
				goto fail;
			} else {
				assert(0);
				abort();
			}
		}
		p->pw_snapname = snapbuf;

		ret = scf_snapshot_get_parent(snap, inst);
		if (ret == -1) {
			if (ismember(scf_error(), errors_server)) {
				goto fail;
			} else {
				assert(0);
				abort();
			}
		}

		_walk_template_instances(NULL, inst, snap,
		    (walk_template_inst_func_t *)find_pg_match, p, flags);
	}

	/* No snapshot parent.  Go looking for instance parent. */
	if (snapbuf == NULL) {
		/* First look for instance parent. */
		ret = scf_pg_get_parent_instance(pg, inst);
		if (ret == 0) {
			_walk_template_instances(NULL, inst, snap,
			    (walk_template_inst_func_t *)find_pg_match,
			    p, flags);
		/* OK, check for service parent */
		} else if (ret == -1 &&
		    scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED) {
			ret = scf_pg_get_parent_service(pg, svc);
			if (ret == 0) {
				_walk_template_instances(svc, NULL, snap,
				    (walk_template_inst_func_t *)find_pg_match,
				    p, flags);
			} else {
				switch (scf_error()) {
				case SCF_ERROR_CONSTRAINT_VIOLATED:
					(void) scf_set_error(
					    SCF_ERROR_NOT_FOUND);
					/*FALLTHROUGH*/

				case SCF_ERROR_CONNECTION_BROKEN:
				case SCF_ERROR_DELETED:
				case SCF_ERROR_HANDLE_MISMATCH:
				case SCF_ERROR_NOT_BOUND:
				case SCF_ERROR_NOT_SET:
					goto fail;

				default:
					assert(0);
					abort();
				}
			}
		} else {
			goto fail;
		}
	}

	if (p->pw_pg != NULL) {
		pg_tmpl->pt_h = h;
		pg_tmpl->pt_pg = p->pw_pg;
		pg_tmpl->pt_inst = p->pw_inst;
		/* we may get a different instance back */
		if (p->pw_inst != inst)
			scf_instance_destroy(inst);
		pg_tmpl->pt_snap = p->pw_snap;
		pg_tmpl->pt_svc = p->pw_svc;
		/* we may get a different service back */
		if (p->pw_svc != svc)
			scf_service_destroy(svc);
		pg_tmpl->pt_populated = 1;
		free(p->pw_tmpl_pgname);
		ret = 0;
		goto done;
	}

	(void) scf_set_error(SCF_ERROR_NOT_FOUND);

fail:
	ret = -1;
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
done:
	scf_snapshot_destroy(snap);
	free(snapbuf);
	free(fmribuf);
	free(pg_name);
	free(pg_type);
	free(p);
	scf_snaplevel_destroy(snaplvl);
	return (ret);
}

/*
 * int scf_tmpl_get_by_pg_name()
 *
 * Get a template by a combination of the name and type.  Either name
 * or type can be null, which indicates a wildcard.  flags may be
 * SCF_PG_TMPL_FLAG_CURRENT (use current properties rather than
 * the defined or running snapshot), and SCF_PG_TMPL_FLAG_EXACT (match
 * only templates defined by the FMRI in question, not by its restarter
 * or globally).  Returns 0 on success and -1 on error, and sets
 * scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *     The connection to the repository was lost.
 *   SCF_ERROR_DELETED
 *     The instance has been deleted.
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     FMRI isn't valid, pg_name is too long to look for a template, or
 *     snapshot specified isn't a valid name
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *     The server does not have adequate resources to complete the request.
 *   SCF_ERROR_NOT_BOUND
 *     The handle is not currently bound.
 *   SCF_ERROR_NOT_FOUND
 *     Object matching FMRI doesn't exist in the repository, or snapshot
 *     doesn't exist.
 */
int
scf_tmpl_get_by_pg_name(const char *fmri, const char *snapshot,
    const char *pg_name, const char *pg_type, scf_pg_tmpl_t *pg_tmpl, int flags)
{
	scf_instance_t *inst = NULL;
	scf_service_t *svc = NULL;
	scf_snapshot_t *snap = NULL;
	pg_tmpl_walk_t *p = NULL;
	scf_handle_t *h;
	int ret;

	assert(pg_tmpl != NULL);
	h = pg_tmpl->pt_h;
	assert(h != NULL);

	scf_tmpl_pg_reset(pg_tmpl);

	if ((inst = scf_instance_create(h)) == NULL ||
	    (svc = scf_service_create(h)) == NULL) {
		goto fail;
	}

	p = calloc(1, sizeof (pg_tmpl_walk_t));
	if (p == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto fail;
	}

	ret = scf_handle_decode_fmri(h, fmri, NULL, NULL, inst, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT);
	if (ret == 0) {
		scf_service_destroy(svc);
		svc = NULL;
	} else if (ret != 0 &&
	    scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED) {
		ret = scf_handle_decode_fmri(h, fmri, NULL, svc,
		    NULL, NULL, NULL, SCF_DECODE_FMRI_EXACT);
		if (ret == 0) {
			scf_instance_destroy(inst);
			inst = NULL;
		}
	}
	if (ret != 0) {
		if (ismember(scf_error(), errors_server)) {
			goto fail;
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
			goto fail;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_FOUND:
			goto fail;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	assert(svc == NULL || inst == NULL);
	assert(svc != NULL || inst != NULL);

	/* If we have a service fmri, snapshot is ignored. */
	if (inst != NULL) {
		if (snapshot == NULL || strcmp(snapshot, "running") == 0 ||
		    (flags & SCF_PG_TMPL_FLAG_CURRENT) ==
		    SCF_PG_TMPL_FLAG_CURRENT) {
			if (_get_snapshot(inst, NULL, &snap) == -1)
				goto fail;
		} else {
			if (_get_snapshot(inst, snapshot, &snap) == -1) {
				goto fail;
			} else if (scf_error() == SCF_ERROR_NOT_FOUND) {
				goto fail;
			}
		}
	}

	p->pw_snapname = snapshot;
	p->pw_pgname = pg_name;
	p->pw_pgtype = pg_type;

	/*
	 * For each of instance, restarter, global
	 *    - check for a tm_pg_pattern_nt_<name> matching type
	 *    - check for a tm_pg_pattern_t_<type> matching type
	 *    - check for any tm_pg_pattern_
	 * Currently plan to return the most specific match only.
	 */
	_walk_template_instances(svc, inst, snap,
	    (walk_template_inst_func_t *)find_pg_match, p, flags);

	if (p->pw_pg != NULL) {
		pg_tmpl->pt_h = h;
		pg_tmpl->pt_pg = p->pw_pg;
		pg_tmpl->pt_inst = p->pw_inst;
		/* we may get a different instance back */
		if (p->pw_inst != inst)
			scf_instance_destroy(inst);
		pg_tmpl->pt_snap = p->pw_snap;
		pg_tmpl->pt_svc = p->pw_svc;
		/* we may get a different service back */
		if (p->pw_svc != svc)
			scf_service_destroy(svc);
		pg_tmpl->pt_populated = 1;
		scf_snapshot_destroy(snap);
		free(p->pw_tmpl_pgname);
		free(p);
		return (0);
	}

	(void) scf_set_error(SCF_ERROR_NOT_FOUND);
fail:
	free(p);
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
	scf_snapshot_destroy(snap);
	return (-1);
}

/*
 * Returns NULL on failure, sets scf_error() to _CONNECTION_BROKEN,
 * _DELETED, _NO_RESOURCES, or _NOT_BOUND.
 */
static scf_iter_t *
_get_svc_or_inst_iter(scf_handle_t *h, scf_pg_tmpl_t *t)
{
	scf_iter_t *iter;
	int ret;

	assert(t->pt_svc != NULL || t->pt_inst != NULL);
	assert(t->pt_svc == NULL || t->pt_inst == NULL);

	if ((iter = scf_iter_create(h)) == NULL) {
		return (NULL);
	}

	/* Iterate on property groups of type template_pg_pattern */

	if (t->pt_inst != NULL)
		ret = scf_iter_instance_pgs_typed_composed(iter,
		    t->pt_inst, t->pt_snap,
		    SCF_GROUP_TEMPLATE_PG_PATTERN);
	if (t->pt_svc != NULL)
		ret = scf_iter_service_pgs_typed(iter, t->pt_svc,
		    SCF_GROUP_TEMPLATE_PG_PATTERN);

	if (ret != 0) {
		if (ismember(scf_error(), errors_server)) {
			scf_iter_destroy(iter);
			return (NULL);
		} else {
			assert(0);
			abort();
		}
	}

	return (iter);
}

/*
 * Returns NULL on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     Handle argument is NULL, or snaphot is not a valid snapshot name.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 */
static scf_iter_t *
_get_next_iterator(scf_handle_t *h, scf_pg_tmpl_t *t, const char *snapshot,
    int exact)
{
	scf_iter_t  *iter = NULL;
	ssize_t limit;

	limit = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	assert(limit != 0);

	/*
	 * Check what level we last iterated on: none, service,
	 * restarter, or global.  Make sure that if one in the middle
	 * doesn't exist, we move on to the next entity.
	 *
	 * Before we drop any references to pt_inst or pt_svc we must
	 * destroy them so we don't leak them.
	 */
	do {
		switch (t->pt_iter_last) {
		case SCF__TMPL_ITER_NONE:
			t->pt_iter_last = SCF__TMPL_ITER_INST;
			if (t->pt_inst != t->pt_orig_inst)
				scf_instance_destroy(t->pt_inst);
			t->pt_inst = t->pt_orig_inst;
			if (t->pt_svc != t->pt_orig_svc)
				scf_service_destroy(t->pt_svc);
			t->pt_svc = t->pt_orig_svc;
			break;

		case SCF__TMPL_ITER_INST:
			/*
			 * Don't go any further than the specified instance
			 * if exact was set.
			 */
			if (exact == 1) {
				(void) scf_set_error(SCF_ERROR_NOT_FOUND);
				goto fail;
			}
			t->pt_iter_last = SCF__TMPL_ITER_RESTARTER;
			if (t->pt_inst != t->pt_orig_inst)
				scf_instance_destroy(t->pt_inst);
			t->pt_inst = _get_restarter_inst(h, t->pt_orig_svc,
			    t->pt_orig_inst, t->pt_snap);
			if (t->pt_svc != t->pt_orig_svc)
				scf_service_destroy(t->pt_svc);
			t->pt_svc = NULL;
			break;

		case SCF__TMPL_ITER_RESTARTER:
			t->pt_iter_last = SCF__TMPL_ITER_GLOBAL;
			if (t->pt_inst != t->pt_orig_inst)
				scf_instance_destroy(t->pt_inst);
			t->pt_inst = _get_global_inst(h);
			if (t->pt_svc != t->pt_orig_svc)
				scf_service_destroy(t->pt_svc);
			t->pt_svc = NULL;
			break;

		case SCF__TMPL_ITER_GLOBAL:
			(void) scf_set_error(SCF_ERROR_NOT_FOUND);
			return (NULL);

		default:
			assert(0);
			abort();
		}
	} while (t->pt_inst == NULL && t->pt_svc == NULL);

	/* Set pt_snap to the snapshot for this instance */
	if (t->pt_inst != NULL) {
		scf_snapshot_destroy(t->pt_snap);
		if (_get_snapshot(t->pt_inst, snapshot,
		    &t->pt_snap) == -1)
			goto fail;
	}

	iter = _get_svc_or_inst_iter(h, t);
fail:
	return (iter);
}

/*
 * scf_pg_tmpl_t *scf_tmpl_pg_create(scf_handle_t *)
 *
 * Returns NULL on failure, sets scf_error() to _INVALID_ARGUMENT
 * or _NO_MEMORY.
 */
scf_pg_tmpl_t *
scf_tmpl_pg_create(scf_handle_t *handle)
{
	scf_pg_tmpl_t *pg_tmpl = NULL;

	if (handle == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (NULL);
	}
	pg_tmpl = calloc(1, sizeof (scf_pg_tmpl_t));
	if (pg_tmpl == NULL)
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	else
		pg_tmpl->pt_h = handle;

	return (pg_tmpl);
}

/*
 * Retrieves name or type of a template pg.
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     pname property is not SCF_TYPE_ASTRING or has more than one value.
 */
static ssize_t
_scf_tmpl_prop_value(scf_propertygroup_t *pg, const char *pname, char **out)
{
	assert(strcmp(pname, SCF_PROPERTY_TM_NAME) == 0 ||
	    strcmp(pname, SCF_PROPERTY_TM_TYPE) == 0);

	*out = _scf_read_single_astring_from_pg(pg, pname);

	if (*out != NULL && *out[0] == '\0') {
		(void) scf_set_error(SCF_ERROR_NONE);
		free(*out);
		*out = strdup(SCF_TMPL_WILDCARD);
		if (*out == NULL)
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	}
	if (*out == NULL) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			return (-1);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	return (strlen(*out));
}

/*
 * int scf_tmpl_iter_pgs()
 *
 * Iterates through the property group templates for the fmri given.
 * When t is uninitialized or reset, sets t to the first property group
 * template in fmri. On subsequent calls, sets t to the next property group
 * template in frmi.
 * Returns 1 on success, 0 when no property group templates are left to
 * iterate, -1 on error.
 * The flags argument may include SCF_PG_TMPL_FLAG_REQUIRED,
 * SCF_PG_TMPL_FLAG_CURRENT,  and/or SCF_PG_TMPL_FLAG_EXACT.
 *
 * Returns -1 on error and sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *      The handle argument is NULL, fmri is invalid, or snapshot is invalid.
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *   SCF_ERROR_PERMISSION_DENIED
 */
int
scf_tmpl_iter_pgs(scf_pg_tmpl_t *t, const char *fmri, const char *snapshot,
    const char *type, int flags)
{
	scf_handle_t *h;
	scf_service_t *svc = NULL;
	scf_instance_t *inst = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_snapshot_t *snap = NULL;
	scf_pg_tmpl_t *pg_tmpl = NULL;
	int err;
	int found = 0;
	char *tmpl_type;
	uint8_t required;
	int ret;

	if (t == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (-1);
	}

	h = t->pt_h;

	if (t->pt_populated == 0) {
		if ((svc = scf_service_create(h)) == NULL ||
		    (inst = scf_instance_create(h)) == NULL ||
		    (pg = scf_pg_create(h)) == NULL) {
			goto fail_non_populated;
		}

		ret = scf_handle_decode_fmri(h, fmri, NULL, NULL, inst, NULL,
		    NULL, SCF_DECODE_FMRI_EXACT);
		if (ret == 0) {
			scf_service_destroy(svc);
			svc = NULL;
		} else if (ret != 0 &&
		    scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED) {
			ret = scf_handle_decode_fmri(h, fmri, NULL, svc,
			    NULL, NULL, NULL, SCF_DECODE_FMRI_EXACT);
			if (ret == 0) {
				scf_instance_destroy(inst);
				inst = NULL;
			}
		}

		if (ret != 0) {
			if (ismember(scf_error(), errors_server)) {
				goto fail_non_populated;
			} else switch (scf_error()) {
			case SCF_ERROR_CONSTRAINT_VIOLATED:
				(void) scf_set_error(
				    SCF_ERROR_INVALID_ARGUMENT);
				goto fail_non_populated;

			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_FOUND:
				goto fail_non_populated;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_SET:
			default:
				assert(0);
				abort();
			}
		}

		assert(svc == NULL || inst == NULL);
		assert(svc != NULL || inst != NULL);

		if (inst != NULL) {
			if (snapshot == NULL ||
			    strcmp(snapshot, "running") == 0 ||
			    (flags & SCF_PG_TMPL_FLAG_CURRENT) ==
			    SCF_PG_TMPL_FLAG_CURRENT) {
				if (_get_snapshot(inst, NULL, &snap) == -1)
					goto fail_non_populated;
			} else {
				(void) scf_set_error(SCF_ERROR_NONE);
				if (_get_snapshot(inst, snapshot,
				    &snap) == -1) {
					goto fail_non_populated;
				} else if (scf_error() == SCF_ERROR_NOT_FOUND) {
					goto fail_non_populated;
				}
			}
		} else {
			scf_snapshot_destroy(snap);
			snap = NULL;
		}

		pg_tmpl = t;
		pg_tmpl->pt_orig_inst = inst;
		pg_tmpl->pt_orig_svc = svc;
		pg_tmpl->pt_snap = snap;
		pg_tmpl->pt_is_iter = 1;
		pg_tmpl->pt_iter_last = SCF__TMPL_ITER_NONE;
		pg_tmpl->pt_pg = pg;
		pg_tmpl->pt_populated = 1;
	} else {
		if (t->pt_is_iter != 1) {
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
			return (-1);
		}
		pg_tmpl = t;
		assert(pg_tmpl->pt_pg != NULL);
	}

	if (pg_tmpl->pt_iter == NULL) {
		pg_tmpl->pt_iter = _get_next_iterator(h, pg_tmpl, snapshot,
		    (flags & SCF_PG_TMPL_FLAG_EXACT) ? 1 : 0);
		if (pg_tmpl->pt_iter == NULL) {
			if (scf_error() == SCF_ERROR_NOT_FOUND)
				return (0);
			else
				return (-1);
		}
	}

	while (found == 0) {
		while ((err = scf_iter_next_pg(pg_tmpl->pt_iter,
		    pg_tmpl->pt_pg)) != 1) {
			if (err == -1) {
				if (ismember(scf_error(), errors_server)) {
					return (-1);
				} else switch (scf_error()) {
				case SCF_ERROR_HANDLE_MISMATCH:
					return (-1);

				case SCF_ERROR_NOT_SET:
				case SCF_ERROR_INVALID_ARGUMENT:
				default:
					assert(0);
					abort();
				}
			} else if (err == 0)  {
				/* This iteration is done.  Get the next one */
				scf_iter_destroy(pg_tmpl->pt_iter);
				pg_tmpl->pt_iter = _get_next_iterator(h,
				    pg_tmpl, snapshot,
				    (flags & SCF_PG_TMPL_FLAG_EXACT) ? 1 : 0);
				if (pg_tmpl->pt_iter == NULL) {
					if (scf_error() == SCF_ERROR_NOT_FOUND)
						return (0);
					else
						return (-1);
				}
				continue;
			} else {
				assert(0);
				abort();
			}
		}

		/*
		 * Discard pgs which don't exist at the right scoping.  This
		 * check also makes sure that if we're looking at, for
		 * example, svc:/system/svc/restarter:default, that we
		 * don't hand back the same property groups twice.
		 */
		switch (t->pt_iter_last) {
		case SCF__TMPL_ITER_INST:
			ret = check_target_match(pg_tmpl->pt_pg,
			    SCF_TM_TARGET_THIS);
			break;
		case SCF__TMPL_ITER_RESTARTER:
			ret = check_target_match(pg_tmpl->pt_pg,
			    SCF_TM_TARGET_DELEGATE);
			break;
		case SCF__TMPL_ITER_GLOBAL:
			ret = check_target_match(pg_tmpl->pt_pg,
			    SCF_TM_TARGET_ALL);
			break;
		case SCF__TMPL_ITER_NONE:
		default:
			assert(0);
			abort();
		}

		if (ret != 0)
			continue;

		/*
		 * If walking only required property groups, check if
		 * the retrieved group is required.
		 */
		if (flags & SCF_PG_TMPL_FLAG_REQUIRED) {
			if (scf_tmpl_pg_required(pg_tmpl, &required) == 0) {
				if (required == 0)
					continue;
			} else {
				return (-1);
			}
		}

		/*
		 * If type != NULL, check if type property matches.  If no
		 * type property exists, consider it a match.
		 */
		if (type != NULL) {
			if (scf_tmpl_pg_type(pg_tmpl, &tmpl_type) != -1) {
				if (strcmp(tmpl_type, SCF_TMPL_WILDCARD)
				    == 0 || strcmp(type, tmpl_type) == 0) {
					free(tmpl_type);
					break;
				}
				free(tmpl_type);
			} else if (scf_error() == SCF_ERROR_NOT_FOUND ||
			    scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED ||
			    scf_error() == SCF_ERROR_TYPE_MISMATCH) {
				break;
			} else {
				return (-1);
			}
		} else {
			break;
		}
	}

	return (1);

fail_non_populated:
	scf_service_destroy(svc);
	scf_instance_destroy(inst);
	scf_pg_destroy(pg);
	scf_snapshot_destroy(snap);
	return (-1);
}

void
scf_tmpl_pg_destroy(scf_pg_tmpl_t *t)
{
	if (t == NULL)
		return;

	scf_pg_destroy(t->pt_pg);
	scf_instance_destroy(t->pt_inst);
	if (t->pt_inst != t->pt_orig_inst)
		scf_instance_destroy(t->pt_orig_inst);
	scf_snapshot_destroy(t->pt_snap);
	scf_service_destroy(t->pt_orig_svc);
	if (t->pt_svc != t->pt_orig_svc)
		scf_service_destroy(t->pt_svc);
	scf_iter_destroy(t->pt_iter);
	free(t);
}

void
scf_tmpl_pg_reset(scf_pg_tmpl_t *t)
{
	scf_pg_destroy(t->pt_pg);
	t->pt_pg = NULL;

	scf_instance_destroy(t->pt_inst);
	if (t->pt_inst != t->pt_orig_inst)
		scf_instance_destroy(t->pt_orig_inst);
	t->pt_inst = NULL;
	t->pt_orig_inst = NULL;

	scf_snapshot_destroy(t->pt_snap);
	t->pt_snap = NULL;

	scf_service_destroy(t->pt_orig_svc);
	if (t->pt_svc != t->pt_orig_svc)
		scf_service_destroy(t->pt_svc);
	t->pt_orig_svc = NULL;
	t->pt_svc = NULL;

	scf_iter_destroy(t->pt_iter);
	t->pt_iter = NULL;

	t->pt_populated = 0;
	t->pt_is_iter = 0;
	t->pt_iter_last = 0;

	/* Do not reset t->pt_h. */
}

/*
 * int scf_tmpl_get_by_prop()
 *
 * Get the property template given a property group template and property
 * name.  No flags are currently defined for this function.
 *
 * Returns NULL on failure, and sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Template object matching property doesn't exist in the repository.
 *   SCF_ERROR_TYPE_MISMATCH
 *     Matching template object is the wrong type in the repository.
 */
int
scf_tmpl_get_by_prop(scf_pg_tmpl_t *t, const char *prop,
    scf_prop_tmpl_t *prop_tmpl, int flags)
{
	char *tmpl_prop_name;
	scf_propertygroup_t *pg = NULL;
	char *pg_type;
	int found = 0;

	if (flags != 0) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (-1);
	}

	scf_tmpl_prop_reset(prop_tmpl);
	if ((pg = scf_pg_create(scf_pg_handle(t->pt_pg))) == NULL)
		return (-1);

	tmpl_prop_name = _tmpl_prop_name(prop, t);
	if (tmpl_prop_name == NULL) {
		assert(scf_error() != SCF_ERROR_NOT_SET);
		return (-1);
	}

	if (_get_pg(t->pt_svc, t->pt_inst, t->pt_snap,
	    tmpl_prop_name, pg) != 0) {
		if (!ismember(scf_error(), errors_server)) {
			switch (scf_error()) {
			case SCF_ERROR_NOT_FOUND:
			case SCF_ERROR_INVALID_ARGUMENT:
				break;

			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_HANDLE_MISMATCH:
			default:
				assert(0);
				abort();
			}
		}
	} else {
		/*
		 * We've only found a template property group if the type
		 * is correct.
		 */
		if ((pg_type = _scf_get_pg_type(pg)) != NULL &&
		    strcmp(pg_type, SCF_GROUP_TEMPLATE_PROP_PATTERN) == 0)
			found++;
		else
			(void) scf_set_error(SCF_ERROR_TYPE_MISMATCH);


		free(pg_type);
	}

	if (found == 0) {
		scf_pg_destroy(pg);
		free(tmpl_prop_name);
		return (-1);
	}

	prop_tmpl->prt_h = scf_pg_handle(t->pt_pg);
	prop_tmpl->prt_t = t;
	prop_tmpl->prt_pg = pg;
	prop_tmpl->prt_pg_name = tmpl_prop_name;
	prop_tmpl->prt_populated = 1;

	return (0);
}

/*
 * scf_prop_tmpl_t *scf_tmpl_prop_create(scf_handle_t *);
 *
 * Returns NULL on failure, sets scf_error() to _INVALID_ARGUMENT, or
 * _NO_MEMORY.
 */
scf_prop_tmpl_t *
scf_tmpl_prop_create(scf_handle_t *handle)
{
	scf_prop_tmpl_t *pt;

	if (handle == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (NULL);
	}
	pt = calloc(1, sizeof (scf_prop_tmpl_t));
	if (pt == NULL)
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	else
		pt->prt_h = handle;

	return (pt);
}

/*
 * int scf_tmpl_iter_props()
 *
 * Iterates over all property templates defined in the specified property
 * group template.  The iterator state is stored on the property template
 * data structure, and the data structure should be allocated with
 * scf_tmpl_prop_create().  To continue the iteration, the previously
 * returned structure should be passed in as an argument to this function.
 * flags can include SCF_PROP_TMPL_FLAG_REQUIRED.  The function returns
 * 1 when a result was found, and 0 when the iteration is complete.
 *
 * Returns -1 on failure, and sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     Template data is invalid.  One of the property templates in this
 *     pg_tmpl is malformed.
 */
int
scf_tmpl_iter_props(scf_pg_tmpl_t *t, scf_prop_tmpl_t *pt, int flags)
{
	scf_prop_tmpl_t *prop_tmpl;
	char *pg_pat;
	char *pg_name = NULL;
	int err;
	int ret;
	ssize_t size = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	uint8_t required;
	scf_handle_t *h;
	scf_propertygroup_t *pg = NULL;
	scf_iter_t *iter = NULL;

	assert(size != 0);
	if (t == NULL || pt == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (-1);
	}

	assert(t->pt_inst == NULL || t->pt_svc == NULL);
	assert(t->pt_inst != NULL || t->pt_svc != NULL);

	if ((pg_name = malloc(size)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (-1);
	}

	if (pt->prt_populated == 0) {
		if ((h = scf_pg_handle(t->pt_pg)) == NULL)
			goto fail_non_populated;

		if ((pg = scf_pg_create(h)) == NULL ||
		    (iter = scf_iter_create(h)) == NULL)
			goto fail_non_populated;

		if (t->pt_inst != NULL)
			err = scf_iter_instance_pgs_typed_composed(iter,
			    t->pt_inst, t->pt_snap,
			    SCF_GROUP_TEMPLATE_PROP_PATTERN);
		else if (t->pt_svc != NULL)
			err = scf_iter_service_pgs_typed(iter, t->pt_svc,
			    SCF_GROUP_TEMPLATE_PROP_PATTERN);

		if (err != 0) {
			if (ismember(scf_error(), errors_server)) {
				goto fail_non_populated;
			} else switch (scf_error()) {
			case SCF_ERROR_INVALID_ARGUMENT:
				goto fail_non_populated;

			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_HANDLE_MISMATCH:
			default:
				assert(0);
				abort();
			}

		}
		prop_tmpl = pt;
		prop_tmpl->prt_t = t;
		prop_tmpl->prt_populated = 1;
		prop_tmpl->prt_pg = pg;
		prop_tmpl->prt_iter = iter;
	} else {
		prop_tmpl = pt;
	}

	while ((err = scf_iter_next_pg(prop_tmpl->prt_iter,
	    prop_tmpl->prt_pg)) > 0) {
		/*
		 * Check if the name matches the appropriate property
		 * group template name.
		 */
		pg_pat = _scf_read_single_astring_from_pg(prop_tmpl->prt_pg,
		    SCF_PROPERTY_TM_PG_PATTERN);
		if (pg_pat == NULL) {
			if (ismember(scf_error(), errors_server)) {
				uu_free(pg_name);
				return (-1);
			} else switch (scf_error()) {
			case SCF_ERROR_NOT_FOUND:
				continue;

			case SCF_ERROR_CONSTRAINT_VIOLATED:
			case SCF_ERROR_TYPE_MISMATCH:
				(void) scf_set_error(
				    SCF_ERROR_TEMPLATE_INVALID);
				free(pg_name);
				return (-1);

			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
			default:
				assert(0);
				abort();
			}
		}
		if ((ret = scf_pg_get_name(t->pt_pg, pg_name, size)) <= 0) {
			free(pg_pat);
			if (ret == 0)
				continue;

			if (ismember(scf_error(), errors_server)) {
				free(pg_name);
				return (-1);
			} else {
				assert(0);
				abort();
			}
		}
		if (strcmp(pg_pat, pg_name) != 0) {
			free(pg_pat);
			continue;
		}
		free(pg_pat);

		/*
		 * If walking only required properties, check if
		 * the retrieved property is required.
		 */
		if (flags & SCF_PROP_TMPL_FLAG_REQUIRED) {
			if (scf_tmpl_prop_required(prop_tmpl, &required) == 0) {
				if (required == 0)
					continue;
			} else {
				free(pg_name);
				return (-1);
			}
		}
		free(pg_name);
		return (0);
	}

	if (err == -1) {
		if (ismember(scf_error(), errors_server)) {
			free(pg_name);
			return (-1);
		} else {
			assert(0);
			abort();
		}
	} else if (err == 0)  {
		scf_iter_destroy(prop_tmpl->prt_iter);
		prop_tmpl->prt_iter = NULL;
		prop_tmpl->prt_populated = 0;
	}
	free(pg_name);

	return (1);

fail_non_populated:
	free(pg_name);
	scf_pg_destroy(pg);
	scf_iter_destroy(iter);
	return (-1);
}

void
scf_tmpl_prop_destroy(scf_prop_tmpl_t *t)
{
	if (t == NULL)
		return;

	scf_pg_destroy(t->prt_pg);
	free(t->prt_pg_name);
	free(t->prt_iter);
	free(t);
}

void
scf_tmpl_prop_reset(scf_prop_tmpl_t *t)
{
	scf_pg_destroy(t->prt_pg);
	t->prt_pg = NULL;

	free(t->prt_pg_name);
	t->prt_pg_name = NULL;

	free(t->prt_iter);
	t->prt_iter = NULL;

	t->prt_populated = 0;
	t->prt_h = NULL;
	t->prt_t = NULL;
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     The name of the template property group (the pname property) has
 *     an improper repository format and is not type astring or has
 *     more than one value.
 */
ssize_t
scf_tmpl_pg_name(const scf_pg_tmpl_t *t, char **out)
{
	return (_scf_tmpl_prop_value(t->pt_pg, SCF_PROPERTY_TM_NAME, out));
}

/*
 * returns an allocated string that must be freed
 *
 * Returns NULL on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     name not a valid property name
 *     name and locale are too long to make a property name
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static char *
_read_localized_astring_from_pg(scf_propertygroup_t *pg, const char *name,
    const char *locale)
{
	char *str;
	char *lname_prop;

	str = _add_locale_to_name(name, locale);
	if (str == NULL)
		return (NULL);
	lname_prop = _scf_read_single_astring_from_pg(pg, str);
	if (lname_prop == NULL) {
		free(str);
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			return (NULL);
		str = _add_locale_to_name(name, "C");
		if (str == NULL)
			return (NULL);
		lname_prop = _scf_read_single_astring_from_pg(pg, str);
	}
	free(str);
	if (lname_prop == NULL) {
		if (scf_error() == SCF_ERROR_TYPE_MISMATCH ||
		    scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED)
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
	}
	return (lname_prop);
}

/*
 * returns an allocated string that must be freed
 *
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     locale is too long to make a valid property name
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
ssize_t
scf_tmpl_pg_common_name(const scf_pg_tmpl_t *t, const char *locale, char **out)
{
	assert(out != NULL);
	if ((*out = _read_localized_astring_from_pg(t->pt_pg,
	    SCF_PROPERTY_TM_COMMON_NAME_PREFIX, locale)) == NULL)
		return (-1);

	return (strlen(*out));
}

/*
 * returns an allocated string that must be freed
 *
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     locale is too long to make a valid property name
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
ssize_t
scf_tmpl_pg_description(const scf_pg_tmpl_t *t, const char *locale, char **out)
{
	assert(out != NULL);
	if ((*out = _read_localized_astring_from_pg(t->pt_pg,
	    SCF_PROPERTY_TM_DESCRIPTION_PREFIX, locale)) == NULL)
		return (-1);

	return (strlen(*out));
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     'type' property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     'type' property is not SCF_TYPE_ASTRING or has more than one value.
 */
ssize_t
scf_tmpl_pg_type(const scf_pg_tmpl_t *t, char **out)
{
	return (_scf_tmpl_prop_value(t->pt_pg, SCF_PROPERTY_TM_TYPE, out));
}

/*
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     required property is not SCF_TYPE_BOOLEAN or has more than one value.
 */
int
scf_tmpl_pg_required(const scf_pg_tmpl_t *t, uint8_t *out)
{

	if (_read_single_boolean_from_pg(t->pt_pg, SCF_PROPERTY_TM_REQUIRED,
	    out) == -1) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			return (-1);

		case SCF_ERROR_NOT_FOUND:
			*out = 0;
			return (0);

		case SCF_ERROR_INVALID_ARGUMENT:
		default:
			assert(0);
			abort();
		}
	}

	return (0);
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     target property is not SCF_TYPE_ASTRING or has more than one value.
 */
ssize_t
scf_tmpl_pg_target(const scf_pg_tmpl_t *t, char **out)
{
	*out = _scf_read_single_astring_from_pg(t->pt_pg,
	    SCF_PROPERTY_TM_TARGET);

	if (*out == NULL) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			return (-1);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	return (strlen(*out));
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
ssize_t
scf_tmpl_prop_name(const scf_prop_tmpl_t *t, char **out)
{
	*out = _scf_read_single_astring_from_pg(t->prt_pg,
	    SCF_PROPERTY_TM_NAME);

	if (*out != NULL && *out[0] == '\0') {
		free(*out);
		*out = NULL;
		(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
	}
	if (*out == NULL) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_TEMPLATE_INVALID:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			return (-1);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	return (strlen(*out));
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     'type' property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     'type' property is not SCF_TYPE_ASTRING, has more than one value,
 *     is SCF_TYPE_INVALID, or is the empty string.
 */
int
scf_tmpl_prop_type(const scf_prop_tmpl_t *t, scf_type_t *out)
{
	char *type;

	type = _scf_read_single_astring_from_pg(t->prt_pg,
	    SCF_PROPERTY_TM_TYPE);
	if (type != NULL && type[0] == '\0') {
		free(type);
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		return (-1);
	}
	if (type == NULL) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			/*FALLTHROUGH*/

		case SCF_ERROR_NOT_FOUND:
			return (-1);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	*out = scf_string_to_type(type);
	free(type);

	if (*out == SCF_TYPE_INVALID) {
		(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
		return (-1);
	}

	return (0);
}

/*
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *    Property group which represents t was deleted.
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     required property is not SCF_TYPE_ASTRING has more than one value.
 */
int
scf_tmpl_prop_required(const scf_prop_tmpl_t *t, uint8_t *out)
{
	if (_read_single_boolean_from_pg(t->prt_pg, SCF_PROPERTY_TM_REQUIRED,
	    out) == -1) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			return (-1);

		case SCF_ERROR_NOT_FOUND:
			*out = 0;
			return (0);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	return (0);
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_INVALID_ARGUMENT
 *     locale is too long to make a property name
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     common_name property is not SCF_TYPE_ASTRING has more than one value.
 */
ssize_t
scf_tmpl_prop_common_name(const scf_prop_tmpl_t *t, const char *locale,
    char **out)
{
	assert(out != NULL);
	if ((*out = _read_localized_astring_from_pg(t->prt_pg,
	    SCF_PROPERTY_TM_COMMON_NAME_PREFIX, locale)) == NULL)
		return (-1);

	return (strlen(*out));
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_INVALID_ARGUMENT
 *     locale is too long to make a property name
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     description property is not SCF_TYPE_ASTRING has more than one value.
 */
ssize_t
scf_tmpl_prop_description(const scf_prop_tmpl_t *t, const char *locale,
    char **out)
{
	assert(out != NULL);
	if ((*out = _read_localized_astring_from_pg(t->prt_pg,
	    SCF_PROPERTY_TM_DESCRIPTION_PREFIX, locale)) == NULL)
		return (-1);

	return (strlen(*out));
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_INVALID_ARGUMENT
 *     locale is too long to make a property name
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     units property is not SCF_TYPE_ASTRING has more than one value.
 */
ssize_t
scf_tmpl_prop_units(const scf_prop_tmpl_t *t, const char *locale, char **out)
{
	assert(out != NULL);
	if ((*out = _read_localized_astring_from_pg(t->prt_pg,
	    SCF_PROPERTY_TM_UNITS_PREFIX, locale)) == NULL)
		return (-1);

	return (strlen(*out));
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     visibility property is not SCF_TYPE_ASTRING has more than one value.
 */
int
scf_tmpl_prop_visibility(const scf_prop_tmpl_t *t, uint8_t *out)
{
	char *visibility;

	visibility = _scf_read_single_astring_from_pg(t->prt_pg,
	    SCF_PROPERTY_TM_VISIBILITY);
	if (visibility == NULL) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		/* prop doesn't exist we take the default value */
		case SCF_ERROR_NOT_FOUND:
			*out = SCF_TMPL_VISIBILITY_READWRITE;
			return (0);

		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			return (-1);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	} else if (strcmp(visibility, SCF_TM_VISIBILITY_READWRITE) == 0) {
		*out = SCF_TMPL_VISIBILITY_READWRITE;
	} else if (strcmp(visibility, SCF_TM_VISIBILITY_HIDDEN) == 0) {
		*out = SCF_TMPL_VISIBILITY_HIDDEN;
	} else if (strcmp(visibility, SCF_TM_VISIBILITY_READONLY) == 0) {
		*out = SCF_TMPL_VISIBILITY_READONLY;
	} else {
		free(visibility);
		(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
		return (-1);
	}

	free(visibility);
	return (0);
}

/*
 * Return an allocated string containing the value that must be freed
 * with free().
 *
 * On error set scf_error() _NO_MEMORY, or _NOT_SET (val has not been set
 * to a value).
 */
static char *
_scf_value_get_as_string(scf_value_t *val)
{
	ssize_t sz = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH) + 1;
	char *buf = malloc(sz);

	if (buf == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	} else if (scf_value_get_as_string(val, buf, sz) == -1) {
		free(buf);
		buf = NULL;
	}

	return (buf);
}

/*
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
int
scf_tmpl_prop_cardinality(const scf_prop_tmpl_t *t, uint64_t *min,
    uint64_t *max)
{
	scf_value_t *val_min = NULL;
	scf_value_t *val_max = NULL;
	int ret = 0;

	if (_read_single_value_from_pg(t->prt_pg,
	    SCF_PROPERTY_TM_CARDINALITY_MIN, &val_min) == 0) {
		if (scf_value_get_count(val_min, min) < 0)
			goto error;
	} else {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			*min = 0;
		else
			goto error;
	}

	if (_read_single_value_from_pg(t->prt_pg,
	    SCF_PROPERTY_TM_CARDINALITY_MAX, &val_max) == 0) {
		if (scf_value_get_count(val_max, max) < 0)
			goto error;
	} else {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			*max = UINT64_MAX;
		else
			goto error;
	}
	goto cleanup;

error:
	if (ismember(scf_error(), errors_server)) {
		ret = -1;
	} else switch (scf_error()) {
	case SCF_ERROR_TYPE_MISMATCH:
	case SCF_ERROR_CONSTRAINT_VIOLATED:
		(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
		/*FALLTHROUGH*/

	case SCF_ERROR_NOT_FOUND:
	case SCF_ERROR_TEMPLATE_INVALID:
		ret = -1;
		break;

	case SCF_ERROR_NOT_SET:
	case SCF_ERROR_INVALID_ARGUMENT:
	default:
		assert(0);
		abort();
	}

cleanup:
	scf_value_destroy(val_min);
	scf_value_destroy(val_max);

	return (ret);
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
int
scf_tmpl_prop_internal_seps(const scf_prop_tmpl_t *t, scf_values_t *vals)
{
	if (_read_astrings_values(t->prt_pg,
	    SCF_PROPERTY_INTERNAL_SEPARATORS, vals) == NULL) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			/*FALLTHROUGH*/

		case SCF_ERROR_NOT_FOUND:
			return (-1);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	} else if (vals->value_count == 0) {
		/* property has no value */
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		scf_values_destroy(vals);
		return (-1);
	}

	return (0);
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
int
scf_tmpl_value_name_constraints(const scf_prop_tmpl_t *t,
    scf_values_t *vals)
{
	char **ret;

	ret = _read_astrings_values(t->prt_pg,
	    SCF_PROPERTY_TM_CONSTRAINT_NAME, vals);

	if (ret == NULL) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			/*FALLTHROUGH*/

		case SCF_ERROR_NOT_FOUND:
			return (-1);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	} else if (vals->value_count == 0) {
		/* property has no value */
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		scf_values_destroy(vals);
		return (-1);
	}

	return (0);
}

/*
 * Returns NULL on failure.  Sets scf_error():
 * Caller is responsible for freeing returned pointer after use.
 *   SCF_ERROR_CONSTRAINT_VIOLATED
 *    More tokens than the array size supplied.
 *   SCF_ERROR_NO_MEMORY
 */
static void *
_separate_by_separator(char *string, const char *sep, char **array, int size)
{
	char *str, *token;
	char *lasts;
	int n = 0;

	assert(array != NULL);
	assert(string != NULL);
	assert(sep != NULL);
	assert(size > 0);

	str = strdup(string);
	if (str == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	if ((array[n] = strtok_r(str, sep, &lasts)) == NULL) {
		assert(0);
		abort();
	}

	n++;
	while ((token = strtok_r(NULL, sep, &lasts)) != NULL) {
		if (n >= size) {
			goto error;
		}
		array[n] = token;
		n++;
	}
	if (n < size) {
		goto error;
	}

	return (str);
error:
	free(str);
	(void) scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
	return (NULL);
}

/*
 * check if name is among values of CHOICES_INCLUDE_VALUES
 * return 0 if name is present, 1 name is not present, -1 on failure
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_check_choices_include_values(scf_propertygroup_t *pg, const char *name)
{
	int n = 0, r = 1;
	char **ret;
	scf_values_t vals;

	if ((ret = _read_astrings_values(pg,
	    SCF_PROPERTY_TM_CHOICES_INCLUDE_VALUES, &vals)) == NULL) {
		if (ismember(scf_error(), errors_server)) {
			return (-1);
		} else switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			return (1);

		case SCF_ERROR_TYPE_MISMATCH:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			return (-1);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	for (n = 0; n < vals.value_count; ++n) {
		if (strcmp(name, ret[n]) == 0) {
			r = 0;
			break;
		}
	}
	scf_values_destroy(&vals);
	return (r);
}

void
scf_count_ranges_destroy(scf_count_ranges_t *ranges)
{
	if (ranges == NULL)
		return;

	ranges->scr_num_ranges = 0;
	free(ranges->scr_min);
	free(ranges->scr_max);
	ranges->scr_min = NULL;
	ranges->scr_max = NULL;
}

void
scf_int_ranges_destroy(scf_int_ranges_t *ranges)
{
	if (ranges == NULL)
		return;

	ranges->sir_num_ranges = 0;
	free(ranges->sir_min);
	free(ranges->sir_max);
	ranges->sir_min = NULL;
	ranges->sir_max = NULL;
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_CONSTRAINT_VIOLATED
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_scf_tmpl_get_count_ranges(const scf_prop_tmpl_t *t, const char *prop,
    scf_count_ranges_t *ranges)
{
	scf_values_t vals;
	int i = 0;
	char **ret;
	char *one_range[2];
	char *endptr;
	char *str = NULL;
	uint64_t *min = NULL;
	uint64_t *max = NULL;

	assert(ranges != NULL);
	if ((ret = _read_astrings_values(t->prt_pg, prop, &vals)) == NULL)
		goto error;
	if (vals.value_count == 0) {
		/* range values are empty */
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		goto cleanup;
	}

	min = malloc(vals.value_count * sizeof (uint64_t));
	max = malloc(vals.value_count * sizeof (uint64_t));
	if (min == NULL || max == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}
	for (i = 0; i < vals.value_count; ++i) {
		/* min and max should be separated by a "," */
		if ((str = _separate_by_separator(ret[i], ",", one_range,
		    2)) == NULL)
			goto cleanup;
		errno = 0;
		min[i] = strtoull(one_range[0], &endptr, 10);
		if (errno != 0 || endptr == one_range[0] || *endptr) {
			(void) scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
			goto cleanup;
		}
		errno = 0;
		max[i] = strtoull(one_range[1], &endptr, 10);
		if (errno != 0 || endptr == one_range[1] || *endptr) {
			(void) scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
			goto cleanup;
		}
		if (min[i] > max[i]) {
			(void) scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
			goto cleanup;
		}
		free(str);
		str = NULL;
	}
	ranges->scr_num_ranges = vals.value_count;
	ranges->scr_min = min;
	ranges->scr_max = max;
	scf_values_destroy(&vals);
	return (0);
cleanup:
	free(str);
	free(min);
	free(max);
	scf_values_destroy(&vals);
error:
	if (ismember(scf_error(), errors_server)) {
		return (-1);
	} else switch (scf_error()) {
	case SCF_ERROR_TYPE_MISMATCH:
		(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
		/*FALLTHROUGH*/

	case SCF_ERROR_CONSTRAINT_VIOLATED:
	case SCF_ERROR_NOT_FOUND:
		return (-1);

	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_NOT_SET:
	default:
		assert(0);
		abort();
	}
	/*NOTREACHED*/
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_CONSTRAINT_VIOLATED
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_scf_tmpl_get_int_ranges(const scf_prop_tmpl_t *t, const char *prop,
    scf_int_ranges_t *ranges)
{
	scf_values_t vals;
	int n = 0;
	char **ret;
	char *one_range[2];
	char *endptr;
	char *str = NULL;
	int64_t *min = NULL;
	int64_t *max = NULL;

	assert(ranges != NULL);
	if ((ret = _read_astrings_values(t->prt_pg, prop, &vals)) == NULL)
		goto error;
	if (vals.value_count == 0) {
		/* range values are empty */
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		goto cleanup;
	}

	min = malloc(vals.value_count * sizeof (int64_t));
	max = malloc(vals.value_count * sizeof (int64_t));
	if (min == NULL || max == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}
	while (n < vals.value_count) {
		/* min and max should be separated by a "," */
		if ((str = _separate_by_separator(ret[n], ",", one_range, 2))
		    == NULL)
			goto cleanup;
		errno = 0;
		min[n] = strtoll(one_range[0], &endptr, 10);
		if (errno != 0 || endptr == one_range[0] || *endptr) {
			(void) scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
			goto cleanup;
		}
		errno = 0;
		max[n] = strtoll(one_range[1], &endptr, 10);
		if (errno != 0 || endptr == one_range[1] || *endptr) {
			(void) scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
			goto cleanup;
		}
		if (min[n] > max[n]) {
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			goto cleanup;
		}
		++n;
		free(str);
		str = NULL;
	}
	ranges->sir_num_ranges = vals.value_count;
	ranges->sir_min = min;
	ranges->sir_max = max;
	scf_values_destroy(&vals);
	return (0);
cleanup:
	free(str);
	free(min);
	free(max);
	scf_values_destroy(&vals);
error:
	if (ismember(scf_error(), errors_server)) {
		return (-1);
	} else switch (scf_error()) {
	case SCF_ERROR_TYPE_MISMATCH:
		(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
		/*FALLTHROUGH*/

	case SCF_ERROR_CONSTRAINT_VIOLATED:
	case SCF_ERROR_NOT_FOUND:
	case SCF_ERROR_TEMPLATE_INVALID:
		return (-1);

	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_NOT_SET:
	default:
		assert(0);
		abort();
	}
	/*NOTREACHED*/
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_CONSTRAINT_VIOLATED
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
int
scf_tmpl_value_count_range_constraints(const scf_prop_tmpl_t *t,
    scf_count_ranges_t *ranges)
{
	return (_scf_tmpl_get_count_ranges(t, SCF_PROPERTY_TM_CONSTRAINT_RANGE,
	    ranges));
}

int
scf_tmpl_value_int_range_constraints(const scf_prop_tmpl_t *t,
    scf_int_ranges_t *ranges)
{
	return (_scf_tmpl_get_int_ranges(t, SCF_PROPERTY_TM_CONSTRAINT_RANGE,
	    ranges));
}

int
scf_tmpl_value_count_range_choices(const scf_prop_tmpl_t *t,
    scf_count_ranges_t *ranges)
{
	return (_scf_tmpl_get_count_ranges(t, SCF_PROPERTY_TM_CHOICES_RANGE,
	    ranges));
}

int
scf_tmpl_value_int_range_choices(const scf_prop_tmpl_t *t,
    scf_int_ranges_t *ranges)
{
	return (_scf_tmpl_get_int_ranges(t, SCF_PROPERTY_TM_CHOICES_RANGE,
	    ranges));
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
int
scf_tmpl_value_name_choices(const scf_prop_tmpl_t *t, scf_values_t *vals)
{
	int c_flag = 0; /* have not read any value yet */
	int r;
	char **ret;

	/* First, look for explicitly declared choices. */
	if ((ret = _read_astrings_values(t->prt_pg,
	    SCF_PROPERTY_TM_CHOICES_NAME, vals)) != NULL) {
		c_flag = 1;
	} else if (scf_error() != SCF_ERROR_NOT_FOUND) {
		goto error;
	}

	/* Next, check for choices included by 'values'. */
	if ((r = _check_choices_include_values(t->prt_pg, "values")) == 0) {
		/* read values_name */
		if (c_flag == 1)
			/* append values */
			ret = _append_astrings_values(t->prt_pg,
			    SCF_PROPERTY_TM_VALUES_NAME, vals);
		else
			/* read values */
			ret = _read_astrings_values(t->prt_pg,
			    SCF_PROPERTY_TM_VALUES_NAME, vals);
		if (ret != NULL) {
			c_flag = 1;
		} else if (scf_error() != SCF_ERROR_NOT_FOUND) {
			goto error;
		}
	} else if (r == -1) {
		goto error;
	}

	/* Finally check for choices included by 'constraints'. */
	if ((r = _check_choices_include_values(t->prt_pg, "constraints")) ==
	    0) {
		/* read constraint_name */
		if (c_flag == 1)
			/* append values */
			ret = _append_astrings_values(t->prt_pg,
			    SCF_PROPERTY_TM_CONSTRAINT_NAME, vals);
		else
			/* read values */
			ret = _read_astrings_values(t->prt_pg,
			    SCF_PROPERTY_TM_CONSTRAINT_NAME, vals);
		if (ret != NULL) {
			c_flag = 1;
		} else if (scf_error() != SCF_ERROR_NOT_FOUND) {
			goto error;
		}
	} else if (r == -1) {
		goto error;
	}

	if (c_flag == 0 || vals->value_count == 0) {
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		return (-1);
	}

	return (0);

error:
	if (ismember(scf_error(), errors_server)) {
		return (-1);
	} else switch (scf_error()) {
	case SCF_ERROR_TYPE_MISMATCH:
		(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
		return (-1);

	case SCF_ERROR_NOT_SET:
	case SCF_ERROR_INVALID_ARGUMENT:
	default:
		assert(0);
		abort();
	}
	/*NOTREACHED*/
}

void
scf_values_destroy(scf_values_t *vals)
{
	int i;
	char **items = NULL;
	char **str = NULL;

	if (vals == NULL)
		return;

	str = vals->values_as_strings;

	/* free values */
	switch (vals->value_type) {
	case SCF_TYPE_BOOLEAN:
		free(vals->values.v_boolean);
		break;
	case SCF_TYPE_COUNT:
		free(vals->values.v_count);
		break;
	case SCF_TYPE_INTEGER:
		free(vals->values.v_integer);
		break;
	case SCF_TYPE_ASTRING:
		items = vals->values.v_astring;
		str = NULL;
		break;
	case SCF_TYPE_USTRING:
		items = vals->values.v_ustring;
		str = NULL;
		break;
	case SCF_TYPE_OPAQUE:
		items = vals->values.v_opaque;
		str = NULL;
		break;
	case SCF_TYPE_TIME:
		free(vals->values.v_time);
		break;
	default:
		assert(0);
		abort();
	}
	for (i = 0; i < vals->value_count; ++i) {
		if (items != NULL)
			free(items[i]);
		if (str != NULL)
			free(str[i]);
	}
	vals->value_count = 0;
	free(items);
	free(str);
}

/*
 * char *_make_value_name()
 *
 * Construct the prefix for a value common name or value description property.
 * It takes the form:
 *   value_<BASE32 name>_<common_name|description>_
 * This is then combined with a localized suffix by the caller to look
 * up the property in the repository:
 *   value_<BASE32 name>_<common_name|description>_<lang>
 *
 * Returns NULL on failure.  Sets scf_error():
 *   SCF_ERROR_INVALID_ARGUMENT
 *     Name isn't short enough make a value name with.
 *   SCF_ERROR_NO_MEMORY
 */
static char *
_make_value_name(char *desc_name, const char *value)
{
	char *name = NULL;
	char *encoded = NULL;
	ssize_t sz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;

	name = malloc(sz);
	encoded = malloc(sz);
	if (name == NULL || encoded == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		free(name);
		free(encoded);
		return (NULL);
	}

	if (scf_encode32(value, strlen(value), encoded, sz, NULL,
	    SCF_ENCODE32_PAD) != 0) {
		/* Shouldn't happen. */
		assert(0);
	}

	(void) strlcpy(name, SCF_PROPERTY_TM_VALUE_PREFIX, sz);

	if (strlcat(name, encoded, sz) >= sz) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		free(name);
		free(encoded);
		return (NULL);
	}

	if (strlcat(name, "_", sz) >= sz) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		free(name);
		free(encoded);
		return (NULL);
	}

	if (strlcat(name, desc_name, sz) >= sz) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		free(name);
		free(encoded);
		return (NULL);
	}

	if (strlcat(name, "_", sz) >= sz) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		free(name);
		free(encoded);
		return (NULL);
	}

	free(encoded);
	return (name);
}

/*
 * ssize_t scf_tmpl_value_common_name()
 *
 * Populates "out" with an allocated string containing the value's
 * common name.  Returns the size of the string on successful return.
 * out must be freed with free() on successful return.
 *
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *     Property group was deleted.
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     name not a valid property name
 *     name and locale are too long to make a property name
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     property is not SCF_TYPE_ASTRING has more than one value.
 */
ssize_t
scf_tmpl_value_common_name(const scf_prop_tmpl_t *t, const char *locale,
    const char *value, char **out)
{
	char *value_name = NULL;

	value_name = _make_value_name("common_name", value);
	if (value_name == NULL)
		return (-1);

	*out = _read_localized_astring_from_pg(t->prt_pg, value_name, locale);

	free(value_name);

	if (*out == NULL)
		return (-1);

	return (strlen(*out));
}

/*
 * ssize_t scf_tmpl_value_description()
 *
 * Populates "out" with an allocated string containing the value's
 * description.  Returns the size of the string on successful return.
 * out must be freed with free() on successful return.
 *
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *     Property group was deleted.
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *     name not a valid property name
 *     name and locale are too long to make a property name
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *     Property doesn't exist or exists and has no value.
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 *     property is not SCF_TYPE_ASTRING has more than one value.
 */
ssize_t
scf_tmpl_value_description(const scf_prop_tmpl_t *t, const char *locale,
    const char *value, char **out)
{
	char *value_name = NULL;

	value_name = _make_value_name("description", value);
	if (value_name == NULL)
		return (-1);


	*out = _read_localized_astring_from_pg(t->prt_pg, value_name, locale);

	free(value_name);

	if (*out == NULL)
		return (-1);

	return (strlen(*out));
}

/*
 * Templates error messages format, in human readable form.
 * Each line is one error item:
 *
 * prefix error message
 * 	FMRI="err->te_errs->tes_fmri"
 * 	Property group="err->te_pg_name"
 * 	Property name="err->te_prop_name"
 * 	expected value 1="err->te_ev1"
 * 	expected value 2="err->te_ev2"
 * 	actual value="err->te_actual"
 * 	Tempalte source="err->te_tmpl_fmri"
 * 	pg_pattern name="err->tmpl_pg_name"
 * 	pg_pattern type="err->tmpl_pg_type"
 * 	prop_pattern name="err->tmpl_prop_name"
 * 	prop_pattern type="err->tmpl_prop_type"
 *
 * To add a new error type, include scf_tmpl_error_type_t in libscf.h
 * add one entry in em_desc[], and update the functions pointed by the
 * _tmpl_error_access array with the new error code. Also, update the
 * scf_tmpl_error_* functions to provide access to desired
 * scf_tmpl_error_t fields.
 *
 * To add a new error item, add a new field to scf_tmpl_error_t, a new field
 * in _scf_tmpl_error_desc or a new non-error-dependent string, add a new entry
 * in _tmpl_error_access array and create the appropriate get_val, get_desc
 * functions.
 *
 * Changes to both the validation logic and the error types and items must
 * be coordinated with the code in svccfg to ensure both libscf and svccfg's
 * manifest validation validate the same things.
 */

/*
 * Container for all template errors on a validated object.
 */
struct scf_tmpl_errors {
	int			tes_index;
	int			tes_num_errs;
	scf_tmpl_error_t	**tes_errs;
	int			tes_errs_size;
	const char		*tes_fmri;
	const char		*tes_prefix;
	int			tes_flag; /* if set, scf_tmpl_error_destroy */
					    /* will free strings in tes_errs  */
};

/*
 * Templates error-dependent labels
 */
struct _scf_tmpl_error_desc {
	const char *em_msg;
	const char *em_ev1;
	const char *em_ev2;
	const char *em_actual;
};

/*
 * This array MUST be kept in synch with the template error definition of
 * scf_tmpl_error_type_t in libscf.h
 */
static struct _scf_tmpl_error_desc em_desc[] = {
	/* SCF_TERR_MISSING_PG */
	{ "Required property group missing", "Name of missing property group",
	    "Type of missing property group", NULL },
	/* SCF_TERR_WRONG_PG_TYPE */
	{ "Property group has bad type", "Specified type", NULL,
	    "Actual type" },
	/* SCF_TERR_MISSING_PROP */
	{ "Required property missing", "Name of missing property", NULL, NULL },
	/* SCF_TERR_WRONG_PROP_TYPE */
	{ "Property has bad type", "Specified property type", NULL,
	    "Actual property type" },
	/* SCF_TERR_CARDINALITY_VIOLATION */
	{ "Number of property values violates cardinality restriction",
	    "Cardinality minimum", "Cardinality maximum",
	    "Actual number of values" },
	/* SCF_TERR_VALUE_CONSTRAINT_VIOLATED */
	{ "Property has illegal value", NULL, NULL, "Illegal value" },
	/* SCF_TERR_RANGE_VIOLATION */
	{ "Property value is out of range", NULL, NULL, "Actual value" },
	/* SCF_TERR_PG_REDEFINE */
	{ "Instance redefines pg_pattern", "Instance pg_pattern name",
	    "Instance pg_pattern type", NULL },
	/* SCF_TERR_PROP_TYPE_MISMATCH */
	{ "Property type and value type mismatch", NULL, NULL, "Value type" },
	/* SCF_TERR_VALUE_OUT_OF_RANGE */
	{ "Value is out of range", NULL, NULL, "Value" },
	/* SCF_TERR_INVALID_VALUE */
	{ "Value is not valid", NULL, NULL, "Value" },
	/* SCF_TERR_PG_PATTERN_CONFLICT */
	{ "Conflicting pg_pattern specifications", "Template source",
	    "pg_pattern name", "pg_pattern type" },
	/* SCF_TERR_PROP_PATTERN_CONFLICT */
	{ "Conflicting prop_pattern specifications", "Template source",
	    "prop_pattern name", "prop_pattern type" },
	/* SCF_TERR_GENERAL_REDEFINE */
	{ "Service or instance pg_pattern redefines a global or restarter "
	    "pg_pattern", "Template source", "pg_pattern name",
	    "pg_pattern type" },
	/* SCF_TERR_INCLUDE_VALUES */
	{ "Missing constraints or values for include_values element",
	    "include_values type", NULL, NULL },
	/* SCF_TERR_PG_PATTERN_INCOMPLETE */
	{ "Required pg_pattern is missing a name or type attribute",
	    NULL, NULL, NULL },
	/* SCF_TERR_PROP_PATTERN_INCOMPLETE */
	{ "Required prop_pattern is missing a type attribute",
	    NULL, NULL, NULL }
};

/*
 * Templates non error-dependent labels
 */
static const char *em_fmri = "FMRI";
static const char *em_pg_name = "Property group";
static const char *em_prop_name = "Property name";
static const char *em_tmpl_fmri = "Template source";
static const char *em_tmpl_pg_name = "pg_pattern name";
static const char *em_tmpl_pg_type = "pg_pattern type";
static const char *em_tmpl_prop_name = "prop_pattern name";
static const char *em_tmpl_prop_type = "prop_pattern type";

static const char *
_get_fmri_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
	case SCF_TERR_INCLUDE_VALUES:
		return (dgettext(TEXT_DOMAIN, em_fmri));
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	default:
		return (NULL);
	}
}

static const char *
_get_pg_name_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
		return (dgettext(TEXT_DOMAIN, em_pg_name));
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	case SCF_TERR_INCLUDE_VALUES:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
	default:
		return (NULL);
	}
}

static const char *
_get_prop_name_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
		return (dgettext(TEXT_DOMAIN, em_prop_name));
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	case SCF_TERR_INCLUDE_VALUES:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
	default:
		return (NULL);
	}
}

static const char *
_get_ev1_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	case SCF_TERR_INCLUDE_VALUES:
		return (dgettext(TEXT_DOMAIN, em_desc[err->te_type].em_ev1));
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
	default:
		return (NULL);
	}
}

static const char *
_get_ev2_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
		return (dgettext(TEXT_DOMAIN, em_desc[err->te_type].em_ev2));
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_INCLUDE_VALUES:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
	default:
		return (NULL);
	}
}

static const char *
_get_actual_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	case SCF_TERR_INCLUDE_VALUES:
		return (dgettext(TEXT_DOMAIN,
		    em_desc[err->te_type].em_actual));
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
	default:
		return (NULL);
	}
}

static const char *
_get_tmpl_fmri_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	case SCF_TERR_INCLUDE_VALUES:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
		return (dgettext(TEXT_DOMAIN, em_tmpl_fmri));
	default:
		return (NULL);
	}
}

static const char *
_get_tmpl_pg_name_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	case SCF_TERR_INCLUDE_VALUES:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
		return (dgettext(TEXT_DOMAIN, em_tmpl_pg_name));
	default:
		return (NULL);
	}
}

static const char *
_get_tmpl_pg_type_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	case SCF_TERR_INCLUDE_VALUES:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
		return (dgettext(TEXT_DOMAIN, em_tmpl_pg_type));
	default:
		return (NULL);
	}
}

static const char *
_get_tmpl_prop_name_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_INCLUDE_VALUES:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
		return (dgettext(TEXT_DOMAIN, em_tmpl_prop_name));
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	default:
		return (NULL);
	}
}

static const char *
_get_tmpl_prop_type_desc(scf_tmpl_error_t *err)
{
	switch (err->te_type) {
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_INCLUDE_VALUES:
		return (dgettext(TEXT_DOMAIN, em_tmpl_prop_type));
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_PG_REDEFINE:
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
	default:
		return (NULL);
	}
}

static const char *
_get_fmri_val(scf_tmpl_error_t *err)
{
	assert(err != NULL && err->te_errs != NULL &&
	    err->te_errs->tes_fmri != NULL);
	return (err->te_errs->tes_fmri);
}

static const char *
_get_pg_name_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_pg_name);
}

static const char *
_get_prop_name_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_prop_name);
}

static const char *
_get_ev1_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_ev1);
}

static const char *
_get_ev2_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_ev2);
}

static const char *
_get_actual_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_actual);
}

static const char *
_get_tmpl_fmri_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_tmpl_fmri);
}

static const char *
_get_tmpl_pg_name_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_tmpl_pg_name);
}

static const char *
_get_tmpl_pg_type_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_tmpl_pg_type);
}

static const char *
_get_tmpl_prop_name_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_tmpl_prop_name);
}

static const char *
_get_tmpl_prop_type_val(scf_tmpl_error_t *err)
{
	assert(err != NULL);
	return (err->te_tmpl_prop_type);
}

/*
 * Templates error item retrival functions
 */
typedef const char *(*get_em)(scf_tmpl_error_t *);

/*
 * if new items (lines) are added to the templates error messages,
 * new entries in this array (and new fuctions) will be required.
 */
static struct _tmpl_error_access {
	get_em get_desc;
	get_em get_val;
} _tmpl_error_items[] = {
	{ (get_em)_get_fmri_desc, (get_em)_get_fmri_val },
	{ (get_em)_get_pg_name_desc, (get_em)_get_pg_name_val },
	{ (get_em)_get_prop_name_desc, (get_em)_get_prop_name_val },
	{ (get_em)_get_ev1_desc, (get_em)_get_ev1_val },
	{ (get_em)_get_ev2_desc, (get_em)_get_ev2_val },
	{ (get_em)_get_actual_desc, (get_em)_get_actual_val },
	{ (get_em)_get_tmpl_fmri_desc, (get_em)_get_tmpl_fmri_val },
	{ (get_em)_get_tmpl_pg_name_desc, (get_em)_get_tmpl_pg_name_val },
	{ (get_em)_get_tmpl_pg_type_desc, (get_em)_get_tmpl_pg_type_val },
	{ (get_em)_get_tmpl_prop_name_desc, (get_em)_get_tmpl_prop_name_val },
	{ (get_em)_get_tmpl_prop_type_desc, (get_em)_get_tmpl_prop_type_val },
	{ NULL }
};

/*
 * Allocate a new scf_tmpl_error_t and add it to the errs list provided.
 * Returns NULL on failure.  Sets scf_error():
 *   SCF_ERROR_NO_MEMORY
 */
static scf_tmpl_error_t *
_create_error(scf_tmpl_errors_t *errs)
{
	scf_tmpl_error_t *ret;
	scf_tmpl_error_t **saved_errs;

	assert(errs != NULL);
	ret = calloc(1, sizeof (scf_tmpl_error_t));
	if (ret == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	ret->te_errs = errs;

	assert(errs->tes_num_errs <= errs->tes_errs_size);
	if (errs->tes_num_errs == errs->tes_errs_size) {
		/* Time to grow the pointer array. */
		saved_errs = errs->tes_errs;
		errs->tes_errs = calloc(2 * errs->tes_errs_size,
		    sizeof (scf_tmpl_error_t *));
		if (errs->tes_errs == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			errs->tes_errs = saved_errs;
			free(ret);
			return (NULL);
		}
		(void) memcpy(errs->tes_errs, saved_errs, errs->tes_errs_size *
		    sizeof (scf_tmpl_error_t *));
		errs->tes_errs_size = 2 * errs->tes_errs_size;
		free(saved_errs);
	}

	errs->tes_errs[errs->tes_num_errs] = ret;
	errs->tes_num_errs++;

	return (ret);
}

/*
 *
 * If destroy_strings is set, scf_tmpl_errors_destroy will free the
 * strings in scf_tmpl_error_t entries.
 *
 * Returns NULL on failure.  Sets scf_error():
 *    SCF_ERROR_NO_MEMORY
 */
scf_tmpl_errors_t *
_scf_create_errors(const char *fmri, int destroy_strings)
{
	scf_tmpl_errors_t *ret;
	int errs_size = 20;

	assert(fmri != NULL);

	ret = calloc(1, sizeof (scf_tmpl_errors_t));
	if (ret == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	ret->tes_index = 0;
	ret->tes_num_errs = 0;
	if ((ret->tes_fmri = strdup(fmri)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		free(ret);
		return (NULL);
	}

	ret->tes_prefix = strdup("");
	if (ret->tes_prefix == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		free((char *)ret->tes_fmri);
		free(ret);
		return (NULL);
	}
	ret->tes_flag = destroy_strings;

	/* Make space for a few errors. */
	ret->tes_errs = calloc(errs_size, sizeof (scf_tmpl_error_t *));
	if (ret->tes_errs == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		free((char *)ret->tes_fmri);
		free((char *)ret->tes_prefix);
		free(ret);
		return (NULL);
	}
	ret->tes_errs_size = errs_size;

	return (ret);
}

/*
 * return 0 on success, if fails set scf_error() to:
 *
 *    SCF_ERROR_NO_MEMORY
 */
int
_scf_tmpl_error_set_prefix(scf_tmpl_errors_t *errs, const char *prefix)
{
	free((void *) errs->tes_prefix);
	if (prefix == NULL)
		errs->tes_prefix = strdup("");
	else
		errs->tes_prefix = strdup(prefix);
	if (errs->tes_prefix == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (-1);
	}
	return (0);
}

/*
 *
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_NO_MEMORY
 */
int
_scf_tmpl_add_error(scf_tmpl_errors_t *errs, scf_tmpl_error_type_t type,
    const char *pg_name, const char *prop_name,
    const char *ev1, const char *ev2, const char *actual,
    const char *tmpl_fmri, const char *tmpl_pg_name, const char *tmpl_pg_type,
    const char *tmpl_prop_name, const char *tmpl_prop_type)
{
	scf_tmpl_error_t *err;

	assert(errs != NULL);
	assert(tmpl_fmri != NULL);

	err = _create_error(errs);
	if (err == NULL)
		return (-1);

	err->te_type = type;
	err->te_pg_name = pg_name;
	err->te_prop_name = prop_name;
	err->te_ev1 = ev1;
	err->te_ev2 = ev2;
	err->te_actual = actual;
	err->te_tmpl_fmri = tmpl_fmri;
	err->te_tmpl_pg_name = tmpl_pg_name;
	err->te_tmpl_pg_type = tmpl_pg_type;
	err->te_tmpl_prop_name = tmpl_prop_name;
	err->te_tmpl_prop_type = tmpl_prop_type;

	return (0);
}

/*
 * returns an allocated string that must be freed with free()
 * string contains converted 64-bit integer value
 * flag set for signed values
 * if fails return NULL and set scf_error() to:
 *   SCF_ERROR_NO_MEMORY
 */
static char *
_val_to_string(uint64_t val, int flag)
{
	ssize_t sz = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH) + 1;
	char *buf;

	buf = malloc(sz);
	if (buf == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	if (flag == 0)
		(void) snprintf(buf, sz, "%" PRIu64, val);
	else
		(void) snprintf(buf, sz, "%" PRIi64, (int64_t)val);

	return (buf);
}

/*
 * return 0 on success, -1 on failure.
 * set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_add_tmpl_missing_pg_error(scf_tmpl_errors_t *errs, scf_pg_tmpl_t *t)
{
	char *ev1 = NULL;
	char *ev2 = NULL;
	char *t_fmri = NULL;
	char *t_pg_name = NULL;
	char *t_pg_type = NULL;

	if ((t_fmri = _scf_tmpl_get_fmri(t)) == NULL)
		return (-1);
	if (scf_tmpl_pg_name(t, &t_pg_name) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_type(t, &t_pg_type) == -1) {
		goto cleanup;
	}
	if ((ev1 = strdup(t_pg_name)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}
	if ((ev2 = strdup(t_pg_type)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	return (_scf_tmpl_add_error(errs, SCF_TERR_MISSING_PG, NULL, NULL, ev1,
	    ev2, NULL, t_fmri, t_pg_name, t_pg_type, NULL, NULL));
cleanup:
	free(ev1);
	free(ev2);
	free(t_fmri);
	free(t_pg_name);
	free(t_pg_type);
	return (-1);
}

/*
 * return 0 on success, -1 on failure.
 * set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_add_tmpl_wrong_pg_type_error(scf_tmpl_errors_t *errs, scf_pg_tmpl_t *t,
    scf_propertygroup_t *pg)
{
	char *pg_name = NULL;
	char *ev1 = NULL;
	char *actual = NULL;
	char *t_fmri = NULL;
	char *t_pg_name = NULL;
	char *t_pg_type = NULL;

	if ((t_fmri = _scf_tmpl_get_fmri(t)) == NULL)
		return (-1);
	if ((pg_name = _scf_get_pg_name(pg)) == NULL)
		goto cleanup;
	if ((actual = _scf_get_pg_type(pg)) == NULL)
		goto cleanup;
	if (scf_tmpl_pg_name(t, &t_pg_name) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_type(t, &t_pg_type) == -1) {
		goto cleanup;
	}
	if ((ev1 = strdup(t_pg_type)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	return (_scf_tmpl_add_error(errs, SCF_TERR_WRONG_PG_TYPE, pg_name, NULL,
	    ev1, NULL, actual, t_fmri, t_pg_name, t_pg_type, NULL, NULL));
cleanup:
	free(pg_name);
	free(ev1);
	free(actual);
	free(t_fmri);
	free(t_pg_name);
	free(t_pg_type);
	return (-1);
}

/*
 * return 0 on success, -1 on failure.
 * set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_add_tmpl_missing_prop_error(scf_tmpl_errors_t *errs, scf_pg_tmpl_t *t,
    scf_propertygroup_t *pg, const scf_prop_tmpl_t *pt)
{
	char *pg_name = NULL;
	char *ev1 = NULL;
	char *t_fmri = NULL;
	char *t_pg_name = NULL;
	char *t_pg_type = NULL;
	char *t_prop_name = NULL;
	char *t_prop_type = NULL;

	if ((t_fmri = _scf_tmpl_get_fmri(t)) == NULL)
		return (-1);
	if ((pg_name = _scf_get_pg_name(pg)) == NULL)
		goto cleanup;
	if (scf_tmpl_pg_name(t, &t_pg_name) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_type(t, &t_pg_type) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_prop_name(pt, &t_prop_name) == -1) {
		goto cleanup;
	}
	t_prop_type = _scf_read_tmpl_prop_type_as_string(pt);
	if (t_prop_type != NULL && t_prop_type[0] == '\0') {
		free(t_prop_type);
		t_prop_type = NULL;
	} else if (t_prop_type == NULL) {
		goto cleanup;
	}
	if (t_prop_type == NULL)
		if ((t_prop_type = strdup(SCF_TMPL_WILDCARD)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	if ((ev1 = strdup(t_prop_name)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	return (_scf_tmpl_add_error(errs, SCF_TERR_MISSING_PROP, pg_name, NULL,
	    ev1, NULL, NULL, t_fmri, t_pg_name, t_pg_type, t_prop_name,
	    t_prop_type));
cleanup:
	free(pg_name);
	free(ev1);
	free(t_fmri);
	free(t_pg_name);
	free(t_pg_type);
	free(t_prop_name);
	free(t_prop_type);
	return (-1);
}

/*
 * return 0 on success, -1 on failure.
 * set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_add_tmpl_wrong_prop_type_error(scf_tmpl_errors_t *errs,
    scf_propertygroup_t *pg, const scf_prop_tmpl_t *pt, scf_property_t *prop)
{
	char *pg_name = NULL;
	char *prop_name = NULL;
	char *ev1 = NULL;
	char *actual = NULL;
	char *t_fmri = NULL;
	char *t_pg_name = NULL;
	char *t_pg_type = NULL;
	char *t_prop_name = NULL;
	char *t_prop_type = NULL;

	if ((t_fmri = _scf_tmpl_get_fmri(pt->prt_t)) == NULL)
		return (-1);
	if ((pg_name = _scf_get_pg_name(pg)) == NULL)
		goto cleanup;
	if ((prop_name = _scf_get_prop_name(prop)) == NULL)
		goto cleanup;
	if ((actual = _scf_get_prop_type(prop)) == NULL)
		goto cleanup;
	if (scf_tmpl_pg_name(pt->prt_t, &t_pg_name) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_type(pt->prt_t, &t_pg_type) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_prop_name(pt, &t_prop_name) == -1) {
		goto cleanup;
	}
	t_prop_type = _scf_read_tmpl_prop_type_as_string(pt);
	if (t_prop_type != NULL && t_prop_type[0] == '\0') {
		free(t_prop_type);
		t_prop_type = NULL;
	} else if (t_prop_type == NULL) {
		goto cleanup;
	}
	if (t_prop_type == NULL)
		if ((t_prop_type = strdup(SCF_TMPL_WILDCARD)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	if ((ev1 = strdup(t_prop_type)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	return (_scf_tmpl_add_error(errs, SCF_TERR_WRONG_PROP_TYPE, pg_name,
	    prop_name, ev1, NULL, actual, t_fmri, t_pg_name, t_pg_type,
	    t_prop_name, t_prop_type));
cleanup:
	free(pg_name);
	free(prop_name);
	free(ev1);
	free(actual);
	free(t_fmri);
	free(t_pg_name);
	free(t_pg_type);
	free(t_prop_name);
	free(t_prop_type);
	return (-1);
}

/*
 * return 0 on success, -1 on failure.
 * set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_add_tmpl_count_error(scf_tmpl_errors_t *errs, scf_tmpl_error_type_t type,
    scf_propertygroup_t *pg, const scf_prop_tmpl_t *pt, scf_property_t *prop,
    uint64_t count, uint64_t *min, uint64_t *max)
{
	char *pg_name = NULL;
	char *prop_name = NULL;
	char *s_min = NULL;
	char *s_max = NULL;
	char *num = NULL;
	char *t_fmri = NULL;
	char *t_pg_name = NULL;
	char *t_pg_type = NULL;
	char *t_prop_name = NULL;
	char *t_prop_type = NULL;

	if ((t_fmri = _scf_tmpl_get_fmri(pt->prt_t)) == NULL)
		return (-1);
	switch (type) {
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_CARDINALITY_VIOLATION:
		if ((pg_name = _scf_get_pg_name(pg)) == NULL)
			goto cleanup;
		if ((prop_name = _scf_get_prop_name(prop)) == NULL)
			goto cleanup;
		break;
	case SCF_TERR_VALUE_OUT_OF_RANGE:
		/* keep pg_name = NULL and prop_name = NULL */
		break;
	}
	if (scf_tmpl_pg_name(pt->prt_t, &t_pg_name) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_type(pt->prt_t, &t_pg_type) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_prop_name(pt, &t_prop_name) == -1) {
		goto cleanup;
	}
	t_prop_type = _scf_read_tmpl_prop_type_as_string(pt);
	if (t_prop_type != NULL && t_prop_type[0] == '\0') {
		free(t_prop_type);
		t_prop_type = NULL;
	} else if (t_prop_type == NULL) {
		goto cleanup;
	}
	if (t_prop_type == NULL)
		if ((t_prop_type = strdup(SCF_TMPL_WILDCARD)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	if (min == NULL) {
		if ((s_min = strdup("")) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	} else {
		if ((s_min = _val_to_string(*min, 0)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	}
	if (max == NULL) {
		if ((s_max = strdup("")) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	} else {
		if ((s_max = _val_to_string(*max, 0)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	}
	if ((num = _val_to_string(count, 0)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	return (_scf_tmpl_add_error(errs, type, pg_name, prop_name, s_min,
	    s_max, num, t_fmri, t_pg_name, t_pg_type, t_prop_name,
	    t_prop_type));
cleanup:
	free(pg_name);
	free(prop_name);
	free(s_min);
	free(s_max);
	free(num);
	free(t_fmri);
	free(t_pg_name);
	free(t_pg_type);
	free(t_prop_name);
	free(t_prop_type);
	return (-1);
}

/*
 * return 0 on success, -1 on failure.
 * set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_add_tmpl_constraint_error(scf_tmpl_errors_t *errs, scf_tmpl_error_type_t type,
    scf_propertygroup_t *pg, const scf_prop_tmpl_t *pt, scf_property_t *prop,
    scf_value_t *val)
{
	scf_type_t val_type;
	char *pg_name = NULL;
	char *prop_name = NULL;
	char *value = NULL;
	char *t_fmri = NULL;
	char *t_pg_name = NULL;
	char *t_pg_type = NULL;
	char *t_prop_name = NULL;
	char *t_prop_type = NULL;

	if ((t_fmri = _scf_tmpl_get_fmri(pt->prt_t)) == NULL)
		return (-1);
	switch (type) {
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
		if ((pg_name = _scf_get_pg_name(pg)) == NULL)
			goto cleanup;
		if ((prop_name = _scf_get_prop_name(prop)) == NULL)
			goto cleanup;
		/*FALLTHROUGH*/
	case SCF_TERR_INVALID_VALUE:
		/* keep pg_name = NULL and prop_name = NULL */
		if ((value = _scf_value_get_as_string(val)) == NULL)
			goto cleanup;
		break;
	case SCF_TERR_PROP_TYPE_MISMATCH:
		/* keep pg_name = NULL and prop_name = NULL */
		/* use value for value type */
		val_type = scf_value_type(val);
		if ((value = strdup(scf_type_to_string(val_type))) ==
		    NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
		break;
	}
	if (scf_tmpl_pg_name(pt->prt_t, &t_pg_name) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_type(pt->prt_t, &t_pg_type) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_prop_name(pt, &t_prop_name) == -1) {
		goto cleanup;
	}
	t_prop_type = _scf_read_tmpl_prop_type_as_string(pt);
	if (t_prop_type != NULL && t_prop_type[0] == '\0') {
		free(t_prop_type);
		t_prop_type = NULL;
	} else if (t_prop_type == NULL) {
		goto cleanup;
	}
	if (t_prop_type == NULL)
		if ((t_prop_type = strdup(SCF_TMPL_WILDCARD)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}

	return (_scf_tmpl_add_error(errs, type, pg_name, prop_name, NULL, NULL,
	    value, t_fmri, t_pg_name, t_pg_type, t_prop_name, t_prop_type));
cleanup:
	assert(scf_error() != SCF_ERROR_NOT_SET);
	free(pg_name);
	free(prop_name);
	free(value);
	free(t_fmri);
	free(t_pg_name);
	free(t_pg_type);
	free(t_prop_name);
	free(t_prop_type);
	return (-1);
}

/*
 * return 0 on success, -1 on failure.
 * set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_add_tmpl_int_error(scf_tmpl_errors_t *errs, scf_tmpl_error_type_t type,
    scf_propertygroup_t *pg, const scf_prop_tmpl_t *pt, scf_property_t *prop,
    int64_t val, int64_t *min, int64_t *max)
{
	char *pg_name = NULL;
	char *prop_name = NULL;
	char *s_min = NULL;
	char *s_max = NULL;
	char *value = NULL;
	char *t_fmri = NULL;
	char *t_pg_name = NULL;
	char *t_pg_type = NULL;
	char *t_prop_name = NULL;
	char *t_prop_type = NULL;

	if ((t_fmri = _scf_tmpl_get_fmri(pt->prt_t)) == NULL)
		return (-1);

	switch (type) {
	case SCF_TERR_RANGE_VIOLATION:
		if ((pg_name = _scf_get_pg_name(pg)) == NULL)
			goto cleanup;
		if ((prop_name = _scf_get_prop_name(prop)) == NULL)
			goto cleanup;
		break;
	case SCF_TERR_VALUE_OUT_OF_RANGE:
		/* keep pg_name = NULL and prop_name = NULL */
		break;
	}
	if (scf_tmpl_pg_name(pt->prt_t, &t_pg_name) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_type(pt->prt_t, &t_pg_type) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_prop_name(pt, &t_prop_name) == -1) {
		goto cleanup;
	}
	t_prop_type = _scf_read_tmpl_prop_type_as_string(pt);
	if (t_prop_type != NULL && t_prop_type[0] == '\0') {
		free(t_prop_type);
		t_prop_type = NULL;
	} else if (t_prop_type == NULL) {
		goto cleanup;
	}
	if (t_prop_type == NULL)
		if ((t_prop_type = strdup(SCF_TMPL_WILDCARD)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	if (min == NULL) {
		if ((s_min = strdup("")) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	} else {
		if ((s_min = _val_to_string(*((uint64_t *)min), 1)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	}
	if (max == NULL) {
		if ((s_max = strdup("")) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	} else {
		if ((s_max = _val_to_string(*((uint64_t *)max), 1)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
	}
	if ((value = _val_to_string((uint64_t)val, 1)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	return (_scf_tmpl_add_error(errs, type, pg_name, prop_name, s_min,
	    s_max, value, t_fmri, t_pg_name, t_pg_type, t_prop_name,
	    t_prop_type));
cleanup:
	free(pg_name);
	free(prop_name);
	free(s_min);
	free(s_max);
	free(value);
	free(t_fmri);
	free(t_pg_name);
	free(t_pg_type);
	free(t_prop_name);
	free(t_prop_type);
	return (-1);
}

/*
 * return 0 on success, -1 on failure.
 * set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_add_tmpl_pg_redefine_error(scf_tmpl_errors_t *errs, scf_pg_tmpl_t *t,
    scf_pg_tmpl_t *r)
{
	char *ev1 = NULL;
	char *ev2 = NULL;
	char *t_fmri = NULL;
	char *t_pg_name = NULL;
	char *t_pg_type = NULL;

	if ((t_fmri = _scf_tmpl_get_fmri(r)) == NULL)
		return (-1);
	if (scf_tmpl_pg_name(r, &t_pg_name) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_type(r, &t_pg_type) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_name(t, &ev1) == -1) {
		goto cleanup;
	}
	if (scf_tmpl_pg_type(t, &ev2) == -1) {
		goto cleanup;
	}

	return (_scf_tmpl_add_error(errs, SCF_TERR_PG_REDEFINE, NULL, NULL,
	    ev1, ev2, NULL, t_fmri, t_pg_name, t_pg_type, NULL, NULL));
cleanup:
	free(ev1);
	free(ev2);
	free(t_fmri);
	free(t_pg_name);
	free(t_pg_type);
	return (-1);
}

/*
 * return 0 if value is within count ranges constraint.
 * return -1 otherwise
 */
static int
_check_count_ranges(scf_count_ranges_t *cr, uint64_t v)
{
	int i;

	for (i = 0; i < cr->scr_num_ranges; ++i) {
		if (v >= cr->scr_min[i] &&
		    v <= cr->scr_max[i]) {
			/* value is within ranges constraint */
			return (0);
		}
	}
	return (-1);
}

/*
 * return 0 if value is within count ranges constraint.
 * return -1 otherwise
 */
static int
_check_int_ranges(scf_int_ranges_t *ir, int64_t v)
{
	int i;

	for (i = 0; i < ir->sir_num_ranges; ++i) {
		if (v >= ir->sir_min[i] &&
		    v <= ir->sir_max[i]) {
			/* value is within integer ranges constraint */
			return (0);
		}
	}
	return (-1);
}

/*
 * int _value_in_constraint()
 *
 * Checks whether the supplied value violates any of the constraints
 * specified in the supplied property template.  If it does, an appropriate
 * error is appended to "errs".  pg and prop, if supplied, are used to
 * augment the information in the error.  Returns 0 on success.
 *
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_value_in_constraint(scf_propertygroup_t *pg, scf_property_t *prop,
    const scf_prop_tmpl_t *pt, scf_value_t *value, scf_tmpl_errors_t *errs)
{
	scf_type_t type, tmpl_type;
	scf_values_t vals;
	scf_tmpl_error_type_t terr_type;
	uint64_t v_count;
	int64_t v_int;
	char *vstr;
	ssize_t sz = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH) + 1;
	ssize_t ret = 0;
	char **constraints;
	int n = 0;
	int r;
	int err_flag = 0;
	scf_count_ranges_t cr;
	scf_int_ranges_t ir;

	type = scf_value_type(value);
	if (type == SCF_TYPE_INVALID) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (-1);
	}

	/* Check if template type matches value type. */
	if (scf_tmpl_prop_type(pt, &tmpl_type) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			/* type is not wildcarded */
			return (-1);
	} else if (tmpl_type != type) {
		if (errs != NULL) {
			if (pg == NULL && prop == NULL) {
				if (_add_tmpl_constraint_error(errs,
				    SCF_TERR_PROP_TYPE_MISMATCH, NULL, pt,
				    NULL, value) == -1)
					return (-1);
			}
		}
		return (1);
	}

	/* Numeric values should be checked against any range constraints. */
	switch (type) {
	case SCF_TYPE_COUNT:
		r = scf_value_get_count(value, &v_count);
		assert(r == 0);

		if (scf_tmpl_value_count_range_constraints(pt, &cr) != 0) {
			if (scf_error() == SCF_ERROR_NOT_FOUND)
				break;
			if (scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED)
				(void) scf_set_error(
				    SCF_ERROR_TEMPLATE_INVALID);
			return (-1);
		} else {
			if (_check_count_ranges(&cr, v_count) == 0) {
				/* value is within ranges constraint */
				scf_count_ranges_destroy(&cr);
				return (0);
			}
			scf_count_ranges_destroy(&cr);
		}

		/*
		 * If we get here, we have a possible constraint
		 * violation.
		 */
		err_flag |= 0x1; /* RANGE_VIOLATION, count */
		break;
	case SCF_TYPE_INTEGER:
		if (scf_value_get_integer(value, &v_int) != 0)
			assert(0);
		if (scf_tmpl_value_int_range_constraints(pt, &ir) != 0) {
			if (scf_error() == SCF_ERROR_NOT_FOUND)
				break;
			if (scf_error() != SCF_ERROR_CONSTRAINT_VIOLATED)
				(void) scf_set_error(
				    SCF_ERROR_TEMPLATE_INVALID);
			return (-1);
		} else {
			if (_check_int_ranges(&ir, v_int) == 0) {
				/* value is within ranges constraint */
				scf_int_ranges_destroy(&ir);
				return (0);
			}
			scf_int_ranges_destroy(&ir);
		}
		/*
		 * If we get here, we have a possible constraint
		 * violation.
		 */
		err_flag |= 0x2; /* RANGE_VIOLATION, integer */
		break;
	default:
		break;
	}

	vstr = malloc(sz);
	if (vstr == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (-1);
	}

	/*
	 * If a set of names is provided, confirm value has one of
	 * those names.
	 */
	if (scf_tmpl_value_name_constraints(pt, &vals) != 0) {
		free(vstr);
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			return (-1);
		}
	} else {
		r = scf_value_get_as_string_typed(value, type, vstr, sz);

		/*
		 * All errors (INVALID_ARGUMENT, NOT_SET, TYPE_MISMATCH)
		 * should be impossible or already caught above.
		 */
		assert(r > 0);

		constraints = vals.values.v_astring;
		for (n = 0; constraints[n] != NULL; ++n) {
			if (strcmp(constraints[n], vstr) == 0) {
				/* value is within constraint */
				scf_values_destroy(&vals);
				free(vstr);
				return (0);
			}
		}
		/* if we get here, we have a constraint violation */
		err_flag |= 0x4; /* CONSTRAINT_VIOLATED */
		scf_values_destroy(&vals);
		free(vstr);
	}
	if (err_flag != 0)
		ret = 1;
	/* register the errors found */
	if (ret == 1 && errs != NULL) {
		if ((err_flag & 0x1) == 0x1) {
			/*
			 * Help make the error more human-friendly.  If
			 * pg and prop are provided, we know we're
			 * validating repository data.  If they're not,
			 * we're validating a potentially hypothetical
			 * value.
			 */
			if (pg == NULL && prop == NULL)
				terr_type = SCF_TERR_VALUE_OUT_OF_RANGE;
			else
				terr_type = SCF_TERR_RANGE_VIOLATION;
			if (_add_tmpl_count_error(errs, terr_type, pg, pt,
			    prop, v_count, 0, 0) == -1)
				ret = -1;
		}
		if ((err_flag & 0x2) == 0x2) {
			if (pg == NULL && prop == NULL)
				terr_type = SCF_TERR_VALUE_OUT_OF_RANGE;
			else
				terr_type = SCF_TERR_RANGE_VIOLATION;
			if (_add_tmpl_int_error(errs, terr_type, pg, pt, prop,
			    v_int, 0, 0) == -1)
				ret = -1;
		}
		if ((err_flag & 0x4) == 0x4) {
			if (pg == NULL && prop == NULL)
				terr_type = SCF_TERR_INVALID_VALUE;
			else
				terr_type = SCF_TERR_VALUE_CONSTRAINT_VIOLATED;
			if (_add_tmpl_constraint_error(errs, terr_type, pg,
			    pt, prop, value) == -1)
				ret = -1;
		}
	}
	return (ret);
}

/*
 * Returns -1 on failure.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
int
scf_tmpl_value_in_constraint(const scf_prop_tmpl_t *pt, scf_value_t *value,
    scf_tmpl_errors_t **errs)
{
	scf_tmpl_errors_t *e = NULL;

	if (errs != NULL) {
		char *fmri;

		if ((fmri = _scf_tmpl_get_fmri(pt->prt_t)) == NULL)
			return (-1);
		*errs = _scf_create_errors(fmri, 1);
		free(fmri);
		if (*errs == NULL)
			return (-1);
		e = *errs;
	}

	return (_value_in_constraint(NULL, NULL, pt, value, e));
}

scf_tmpl_error_t *
scf_tmpl_next_error(scf_tmpl_errors_t *errs)
{
	if (errs->tes_index < errs->tes_num_errs) {
		assert(errs->tes_errs[errs->tes_index] != NULL);
		return (errs->tes_errs[errs->tes_index++]);
	} else {
		return (NULL);
	}
}

void
scf_tmpl_reset_errors(scf_tmpl_errors_t *errs)
{
	errs->tes_index = 0;
}

int
scf_tmpl_strerror(scf_tmpl_error_t *err,  char *s, size_t n, int flag)
{
	const char *str;
	int i;
	int ret = -1;
	int nsz = 0;	/* err msg length */
	int sz = n;	/* available buffer size */
	char *buf = s;	/* where to append in buffer */
	char *s0 = (flag == SCF_TMPL_STRERROR_HUMAN) ? ":\n\t" : ": ";
	char *s1 = (flag == SCF_TMPL_STRERROR_HUMAN) ? "\n\t" : "; ";
	char *sep = s0;
	const char *val;

	/* prefix */
	if (err->te_errs->tes_prefix != NULL) {
		ret = snprintf(buf, sz, "%s", dgettext(TEXT_DOMAIN,
		    err->te_errs->tes_prefix));
		nsz += ret;
		sz = (sz - ret) > 0 ? sz - ret : 0;
		buf = (sz > 0) ? s + nsz : NULL;
	}
	/* error message */
	ret = snprintf(buf, sz, "%s", dgettext(TEXT_DOMAIN,
	    em_desc[err->te_type].em_msg));
	nsz += ret;
	sz = (sz - ret) > 0 ? sz - ret : 0;
	buf = (sz > 0) ? s + nsz : NULL;

	for (i = 0; _tmpl_error_items[i].get_desc != NULL; ++i) {
		if ((str = _tmpl_error_items[i].get_desc(err)) == NULL)
			/* no item to print */
			continue;
		val = _tmpl_error_items[i].get_val(err);
		ret = snprintf(buf, sz, "%s%s=\"%s\"", sep, str,
		    (val == NULL) ? "" : val);
		nsz += ret;
		sz = (sz - ret) > 0 ? sz - ret : 0;
		buf = (sz > 0) ? s + nsz : NULL;
		sep = s1;
	}
	return (nsz);
}

/*
 * return 0 on success, -1 on failure.
 * set scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_validate_cardinality(scf_propertygroup_t *pg, scf_prop_tmpl_t *pt,
    scf_property_t *prop, scf_tmpl_errors_t *errs)
{
	uint64_t min, max;
	scf_handle_t *h;
	scf_iter_t *iter = NULL;
	scf_value_t *val = NULL;
	int count = 0;
	int ret = -1;
	int r;

	if (scf_tmpl_prop_cardinality(pt, &min, &max) != 0) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			return (0);
		else
			return (-1);
	}

	/* Any number of values permitted.  Just return success. */
	if (min == 0 && max == UINT64_MAX) {
		return (0);
	}

	h = scf_property_handle(prop);
	if (h == NULL) {
		assert(scf_error() == SCF_ERROR_HANDLE_DESTROYED);
		goto cleanup;
	}

	iter = scf_iter_create(h);
	val = scf_value_create(h);
	if (iter == NULL || val == NULL) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else {
			assert(0);
			abort();
		}
	}

	if (scf_iter_property_values(iter, prop) != 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else {
			assert(0);
			abort();
		}
	}

	while ((r = scf_iter_next_value(iter, val)) == 1)
		count++;

	if (r < 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else {
			assert(0);
			abort();
		}
	}

	if (count < min || count > max)
		if (_add_tmpl_count_error(errs, SCF_TERR_CARDINALITY_VIOLATION,
		    pg, pt, prop, (uint64_t)count, &min, &max) == -1)
			goto cleanup;

	ret = 0;

cleanup:
	scf_iter_destroy(iter);
	scf_value_destroy(val);
	return (ret);
}

/*
 * Returns -1 on error.  Sets scf_error():
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_check_property(scf_prop_tmpl_t *pt, scf_propertygroup_t *pg,
    scf_property_t *prop, scf_tmpl_errors_t *errs)
{
	scf_type_t tmpl_type;
	uint8_t required;
	scf_handle_t *h;
	scf_iter_t *iter = NULL;
	scf_value_t *val = NULL;
	int r;
	int ret = -1;

	h = scf_pg_handle(pg);
	if (h == NULL) {
		assert(scf_error() == SCF_ERROR_HANDLE_DESTROYED);
		return (-1);
	}

	iter = scf_iter_create(h);
	val = scf_value_create(h);
	if (iter == NULL || val == NULL) {
		if (ismember(scf_error(), errors_server)) {
			scf_iter_destroy(iter);
			scf_value_destroy(val);
			return (-1);
		} else {
			assert(0);
			abort();
		}
	}

	if (scf_tmpl_prop_required(pt, &required) != 0)
		goto cleanup;

	/* Check type */
	if (scf_tmpl_prop_type(pt, &tmpl_type) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			goto cleanup;
		} else if (required) {
			/* If required, type must be specified. */
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			goto cleanup;
		}
	} else if (scf_property_is_type(prop, tmpl_type) != 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else switch (scf_error()) {
		case SCF_ERROR_TYPE_MISMATCH:
			if (_add_tmpl_wrong_prop_type_error(errs, pg, pt,
			    prop) == -1)
				goto cleanup;
			break;

		case SCF_ERROR_INVALID_ARGUMENT:
			/*
			 * tmpl_prop_type shouldn't have handed back
			 * an invalid property type.
			 */
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}


	/* Cardinality */
	if (_validate_cardinality(pg, pt, prop, errs) == -1)
		goto cleanup;

	/* Value constraints */
	/*
	 * Iterate through each value, and confirm it is defined as
	 * constrained.
	 */
	if (scf_iter_property_values(iter, prop) != 0) {
		assert(scf_error() != SCF_ERROR_NOT_SET &&
		    scf_error() != SCF_ERROR_HANDLE_MISMATCH);
		goto cleanup;
	}

	while ((r = scf_iter_next_value(iter, val)) == 1) {
		if (_value_in_constraint(pg, prop, pt, val, errs) == -1) {
			if (ismember(scf_error(), errors_server)) {
				goto cleanup;
			} else switch (scf_error()) {
			case SCF_ERROR_TEMPLATE_INVALID:
				goto cleanup;

			case SCF_ERROR_INVALID_ARGUMENT:
			default:
				assert(0);
				abort();
			}
		}
	}

	if (r < 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else {
			assert(0);
			abort();
		}
	}

	ret = 0;

cleanup:
	scf_iter_destroy(iter);
	scf_value_destroy(val);
	return (ret);
}

/*
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_check_pg(scf_pg_tmpl_t *t, scf_propertygroup_t *pg, char *pg_name,
    char *type, scf_tmpl_errors_t *errs)
{
	scf_prop_tmpl_t *pt = NULL;
	char *pg_type = NULL;
	scf_iter_t *iter = NULL;
	uint8_t pg_required;
	scf_property_t *prop = NULL;
	scf_handle_t *h;
	int r;
	char *prop_name = NULL;
	ssize_t nsize = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	int ret = -1;

	assert(pg_name != NULL);
	assert(t != NULL);
	assert(pg != NULL);
	assert(type != NULL);
	assert(nsize != 0);

	if ((h = scf_pg_handle(pg)) == NULL) {
		assert(scf_error() == SCF_ERROR_HANDLE_DESTROYED);
		return (-1);
	}
	if ((pt = scf_tmpl_prop_create(h)) == NULL) {
		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
		return (-1);
	}

	if ((prop = scf_property_create(h)) == NULL) {
		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
		goto cleanup;
	}

	if ((iter = scf_iter_create(h)) == NULL) {
		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
		goto cleanup;
	}
	if ((prop_name = malloc(nsize)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	if (scf_tmpl_pg_required(t, &pg_required) != 0)
		goto cleanup;

	if (scf_tmpl_pg_type(t, &pg_type) == -1) {
		goto cleanup;
	} else if (pg_required != 0 &&
	    strcmp(SCF_TMPL_WILDCARD, pg_type) == 0) {
		/* Type must be specified for required pgs. */
		(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
		goto cleanup;
	}

	if (pg_type != NULL) {
		if (strcmp(pg_type, type) != 0 &&
		    strcmp(pg_type, SCF_TMPL_WILDCARD) != 0) {
			if (_add_tmpl_wrong_pg_type_error(errs, t, pg) == -1)
				goto cleanup;
		}
	}


	/* Iterate through properties in the repository and check them. */
	if (scf_iter_pg_properties(iter, pg) != 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else {
			assert(0);
			abort();
		}
	}

	while ((r = scf_iter_next_property(iter, prop)) == 1) {
		if (scf_property_get_name(prop, prop_name, nsize) == -1) {
			assert(scf_error() != SCF_ERROR_NOT_SET);
			goto cleanup;
		}
		if (scf_tmpl_get_by_prop(t, prop_name, pt, 0) != 0) {
			if (ismember(scf_error(), errors_server)) {
				goto cleanup;
			} else switch (scf_error()) {
			case SCF_ERROR_NOT_FOUND:
				/* No template.  Continue. */
				continue;

			case SCF_ERROR_INVALID_ARGUMENT:
			default:
				assert(0);
				abort();
			}
		}

		if (_check_property(pt, pg, prop, errs) != 0)
			goto cleanup;
	}

	if (r < 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else {
			assert(0);
			abort();
		}
	}

	scf_tmpl_prop_reset(pt);
	free(prop_name);
	prop_name = NULL;
	/*
	 * Confirm required properties are present.
	 */
	while ((r = scf_tmpl_iter_props(t, pt,
	    SCF_PROP_TMPL_FLAG_REQUIRED)) == 0) {
		scf_type_t prop_type;

		if (scf_tmpl_prop_name(pt, &prop_name) == -1)
			goto cleanup;

		/* required properties cannot have type wildcarded */
		if (scf_tmpl_prop_type(pt, &prop_type) == -1) {
			if (scf_error() == SCF_ERROR_NOT_FOUND)
				(void) scf_set_error(
				    SCF_ERROR_TEMPLATE_INVALID);
			goto cleanup;
		}

		if (scf_pg_get_property(pg, prop_name, prop) != 0) {
			if (ismember(scf_error(), errors_server)) {
				goto cleanup;
			} else switch (scf_error()) {
			case SCF_ERROR_NOT_FOUND:
				if (_add_tmpl_missing_prop_error(errs, t, pg,
				    pt) == -1)
					goto cleanup;
				break;

			case SCF_ERROR_INVALID_ARGUMENT:
				(void) scf_set_error(
				    SCF_ERROR_TEMPLATE_INVALID);
				goto cleanup;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_SET:
			default:
				assert(0);
				abort();
			}
		}
		free(prop_name);
		prop_name = NULL;
	}
	if (r < 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_TEMPLATE_INVALID:
			goto cleanup;

		case SCF_ERROR_INVALID_ARGUMENT:
		default:
			assert(0);
			abort();
		}
	}

	ret = 0;
cleanup:
	scf_tmpl_prop_destroy(pt);
	scf_iter_destroy(iter);
	scf_property_destroy(prop);
	free(prop_name);
	free(pg_type);
	return (ret);
}

/*
 * Checks if instance fmri redefines any pgs defined in restarter or global
 * Return -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
static int
_scf_tmpl_check_pg_redef(scf_handle_t *h, const char *fmri,
    const char *snapname, scf_tmpl_errors_t *errs)
{
	scf_pg_tmpl_t *t = NULL;
	scf_pg_tmpl_t *r = NULL;
	char *pg_name = NULL;
	char *pg_name_r = NULL;
	char *pg_type = NULL;
	char *pg_type_r = NULL;
	char *target = NULL;
	int ret_val = -1;
	int ret;

	t = scf_tmpl_pg_create(h);
	r = scf_tmpl_pg_create(h);
	if (t == NULL || r == NULL)
		goto cleanup;

	while ((ret = scf_tmpl_iter_pgs(t, fmri, snapname, NULL,
	    SCF_PG_TMPL_FLAG_EXACT)) == 1) {
		if (scf_tmpl_pg_name(t, &pg_name) == -1) {
			goto cleanup;
		}
		if (scf_tmpl_pg_type(t, &pg_type) == -1) {
			goto cleanup;
		}
		/* look for a redefinition of a global/restarter pg_pattern */
		while ((ret = scf_tmpl_iter_pgs(r, fmri, snapname, pg_type,
		    0)) == 1) {
			if (scf_tmpl_pg_name(r, &pg_name_r) == -1) {
				goto cleanup;
			} else if (strcmp(pg_name_r, SCF_TMPL_WILDCARD) != 0 &&
			    strcmp(pg_name, SCF_TMPL_WILDCARD) != 0 &&
			    strcmp(pg_name, pg_name_r) != 0) {
				/* not a match */
				free(pg_name_r);
				pg_name_r = NULL;
				continue;
			}
			if (scf_tmpl_pg_type(r, &pg_type_r) == -1) {
				goto cleanup;
			} else if (strcmp(pg_type_r, SCF_TMPL_WILDCARD) != 0 &&
			    strcmp(pg_type, SCF_TMPL_WILDCARD) != 0 &&
			    strcmp(pg_type, pg_type_r) != 0) {
				/* not a match */
				free(pg_name_r);
				pg_name_r = NULL;
				free(pg_type_r);
				pg_type_r = NULL;
				continue;
			}
			if (scf_tmpl_pg_target(r, &target) == -1) {
				target = NULL;
				goto cleanup;
			}
			if (strcmp(target, SCF_TM_TARGET_ALL) == 0 ||
			    strcmp(target, SCF_TM_TARGET_DELEGATE) == 0) {
				/* found a pg_pattern redefinition */
				if (_add_tmpl_pg_redefine_error(errs, t,
				    r) == -1)
					goto cleanup;
				free(pg_name_r);
				pg_name_r = NULL;
				free(pg_type_r);
				pg_type_r = NULL;
				free(target);
				target = NULL;
				break;
			}
			free(pg_name_r);
			pg_name_r = NULL;
			free(pg_type_r);
			pg_type_r = NULL;
			free(target);
			target = NULL;
		}
		if (ret == -1)
			goto cleanup;
		scf_tmpl_pg_reset(r);

		free(pg_name);
		free(pg_type);
		pg_name = NULL;
		pg_type = NULL;
	}
	if (ret == -1)
		goto cleanup;

	ret_val = 0;

cleanup:
	scf_tmpl_pg_destroy(t);
	scf_tmpl_pg_destroy(r);
	free(pg_name);
	free(pg_type);
	free(pg_name_r);
	free(pg_type_r);
	free(target);

	if (ret_val == -1) {
		if (!ismember(scf_error(), errors_server)) {
			switch (scf_error()) {
			case SCF_ERROR_TYPE_MISMATCH:
				(void) scf_set_error(
				    SCF_ERROR_TEMPLATE_INVALID);
				/*FALLTHROUGH*/

			case SCF_ERROR_CONSTRAINT_VIOLATED:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_FOUND:
			case SCF_ERROR_TEMPLATE_INVALID:
				break;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_SET:
			default:
				assert(0);
				abort();
			}
		}
	}
	return (ret_val);
}

/*
 * Returns -1 on failure, sets scf_error() to:
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_CONNECTION_BROKEN
 *   SCF_ERROR_DELETED
 *   SCF_ERROR_HANDLE_DESTROYED
 *   SCF_ERROR_INTERNAL
 *   SCF_ERROR_INVALID_ARGUMENT
 *   SCF_ERROR_NO_MEMORY
 *   SCF_ERROR_NO_RESOURCES
 *   SCF_ERROR_NOT_BOUND
 *   SCF_ERROR_NOT_FOUND
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_TEMPLATE_INVALID
 */
int
scf_tmpl_validate_fmri(scf_handle_t *h, const char *fmri, const char *snapshot,
    scf_tmpl_errors_t **errs, int flags)
{
	scf_pg_tmpl_t *t = NULL;
	scf_iter_t *iter = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_instance_t *inst = NULL;
	scf_snapshot_t *snap = NULL;
	char *type = NULL;
	char *pg_name = NULL;
	ssize_t rsize = scf_limit(SCF_LIMIT_MAX_PG_TYPE_LENGTH) + 1;
	ssize_t nsize = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	int ret = -1;
	int r;

	assert(errs != NULL);

	if ((*errs = _scf_create_errors(fmri, 1)) == NULL)
		return (-1);

	if ((pg = scf_pg_create(h)) == NULL ||
	    (iter = scf_iter_create(h)) == NULL ||
	    (inst = scf_instance_create(h)) == NULL ||
	    (t = scf_tmpl_pg_create(h)) == NULL) {
		/*
		 * Sets SCF_ERROR_INVALID_ARGUMENT, SCF_ERROR_NO_MEMORY,
		 * SCF_ERROR_NO_RESOURCES, SCF_ERROR_INTERNAL or
		 * SCF_ERROR_HANDLE_DESTROYED.
		 */
		goto cleanup;
	}

	if ((type = malloc(rsize)) == NULL ||
	    (pg_name = malloc(nsize)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	if (scf_handle_decode_fmri(h, fmri, NULL, NULL, inst, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT|SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			/*FALLTHROUGH*/

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_FOUND:
			goto cleanup;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
		default:
			assert(0);
			abort();
		}
	}

	if (snapshot == NULL || strcmp(snapshot, "running") == 0 ||
	    (flags & SCF_TMPL_VALIDATE_FLAG_CURRENT)) {
		if (_get_snapshot(inst, NULL, &snap) == -1)
			goto cleanup;
	} else {
		(void) scf_set_error(SCF_ERROR_NONE);
		if (_get_snapshot(inst, snapshot, &snap) == -1) {
			goto cleanup;
		} else if (scf_error() == SCF_ERROR_NOT_FOUND) {
			goto cleanup;
		}
	}
	if (_scf_tmpl_check_pg_redef(h, fmri, snapshot, *errs) != 0) {
		goto cleanup;
	}

	/*
	 * Check that property groups on this instance conform to the template.
	 */
	if (scf_iter_instance_pgs_composed(iter, inst, snap) != 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else {
			assert(0);
			abort();
		}
	}

	while ((r = scf_iter_next_pg(iter, pg)) == 1) {
		if (scf_pg_get_name(pg, pg_name, nsize) == -1) {
			if (ismember(scf_error(), errors_server)) {
				goto cleanup;
			} else {
				assert(0);
				abort();
			}
		}

		if (scf_pg_get_type(pg, type, rsize) == -1) {
			if (ismember(scf_error(), errors_server)) {
				goto cleanup;
			} else {
				assert(0);
				abort();
			}
		}

		if (scf_tmpl_get_by_pg_name(fmri, snapshot, pg_name, type, t,
		    0) != 0) {
			if (ismember(scf_error(), errors_server)) {
				goto cleanup;
			} else switch (scf_error()) {
			case SCF_ERROR_NOT_FOUND:
				continue;

			case SCF_ERROR_INVALID_ARGUMENT:
				goto cleanup;

			default:
				assert(0);
				abort();
			}
		}

		if (_check_pg(t, pg, pg_name, type, *errs) != 0)
			goto cleanup;
	}
	if (r < 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else {
			assert(0);
			abort();
		}
	}

	scf_tmpl_pg_reset(t);

	/*
	 * Confirm required property groups are present.
	 */
	while ((r = scf_tmpl_iter_pgs(t, fmri, snapshot, NULL,
	    SCF_PG_TMPL_FLAG_REQUIRED)) == 1) {
		free(pg_name);
		free(type);

		if (scf_tmpl_pg_name(t, &pg_name) == -1)
			goto cleanup;
		if (scf_tmpl_pg_type(t, &type) == -1)
			goto cleanup;
		/*
		 * required property group templates should not have
		 * wildcarded name or type
		 */
		if (strcmp(pg_name, SCF_TMPL_WILDCARD) == 0 ||
		    strcmp(type, SCF_TMPL_WILDCARD) == 0) {
			(void) scf_set_error(SCF_ERROR_TEMPLATE_INVALID);
			goto cleanup;
		}

		if (_get_pg(NULL, inst, snap, pg_name, pg) != 0) {
			if (ismember(scf_error(), errors_server)) {
				goto cleanup;
			} else switch (scf_error()) {
			case SCF_ERROR_NOT_FOUND:
				if (_add_tmpl_missing_pg_error(*errs, t) == -1)
					goto cleanup;
				continue;

			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_SET:
			default:
				assert(0);
				abort();
			}
		}
	}
	if (r < 0) {
		if (ismember(scf_error(), errors_server)) {
			goto cleanup;
		} else switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_INVALID_ARGUMENT:
			goto cleanup;

		default:
			assert(0);
			abort();
		}
	}

	ret = 0;
	if ((*errs)->tes_num_errs > 0)
		ret = 1;
cleanup:
	if (ret != 1) {
		/* there are no errors to report */
		scf_tmpl_errors_destroy(*errs);
		*errs = NULL;
	}
	scf_tmpl_pg_destroy(t);
	free(type);
	free(pg_name);

	scf_iter_destroy(iter);
	scf_pg_destroy(pg);
	scf_instance_destroy(inst);
	scf_snapshot_destroy(snap);

	return (ret);
}

void
scf_tmpl_errors_destroy(scf_tmpl_errors_t *errs)
{
	int i;
	scf_tmpl_error_t *e;

	if (errs == NULL)
		return;

	for (i = 0; i < errs->tes_num_errs; ++i) {
		e = errs->tes_errs[i];
		if (errs->tes_flag != 0) {
			free((char *)e->te_pg_name);
			free((char *)e->te_prop_name);
			free((char *)e->te_ev1);
			free((char *)e->te_ev2);
			free((char *)e->te_actual);
			free((char *)e->te_tmpl_fmri);
			free((char *)e->te_tmpl_pg_name);
			free((char *)e->te_tmpl_pg_type);
			free((char *)e->te_tmpl_prop_name);
			free((char *)e->te_tmpl_prop_type);
		}
		free(e);
	}
	free((char *)errs->tes_fmri);
	free((char *)errs->tes_prefix);
	free(errs->tes_errs);
	free(errs);
}

int
scf_tmpl_error_source_fmri(const scf_tmpl_error_t *err, char **fmri)
{
	assert(err != NULL);
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_REDEFINE:
		*fmri = (char *)err->te_tmpl_fmri;
		return (0);
		/*NOTREACHED*/
	default:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
	}
	return (-1);
}

int
scf_tmpl_error_type(const scf_tmpl_error_t *err, scf_tmpl_error_type_t *type)
{
	assert(err != NULL);
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_REDEFINE:
		*type = err->te_type;
		return (0);
		/*NOTREACHED*/
	default:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
	}
	return (-1);
}

int
scf_tmpl_error_pg_tmpl(const scf_tmpl_error_t *err, char **name, char **type)
{
	assert(err != NULL);
	switch (err->te_type) {
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_REDEFINE:
		if (err->te_tmpl_pg_name != NULL &&
		    err->te_tmpl_pg_type != NULL) {
			if (name != NULL)
				*name = (char *)err->te_tmpl_pg_name;
			if (type != NULL)
				*type = (char *)err->te_tmpl_pg_type;
			return (0);
		}
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		break;
	default:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
	}
	return (-1);
}

int
scf_tmpl_error_pg(const scf_tmpl_error_t *err, char **name, char **type)
{
	assert(err != NULL);
	switch (err->te_type) {
	case SCF_TERR_WRONG_PG_TYPE:
		if (err->te_pg_name != NULL &&
		    err->te_actual != NULL) {
			if (name != NULL)
				*name = (char *)err->te_pg_name;
			if (type != NULL)
				*type = (char *)err->te_actual;
			return (0);
		}
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		break;
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
		if (err->te_pg_name != NULL &&
		    err->te_tmpl_pg_type != NULL) {
			if (name != NULL)
				*name = (char *)err->te_pg_name;
			if (type != NULL)
				*type = (char *)err->te_tmpl_pg_type;
			return (0);
		}
		/*FALLTHROUGH*/
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		break;
	case SCF_TERR_PG_REDEFINE:
		if (err->te_ev1 != NULL && err->te_ev2 != NULL) {
			if (name != NULL)
				*name = (char *)err->te_ev1;
			if (type != NULL)
				*type = (char *)err->te_ev2;
			return (0);
		}
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		break;
	default:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
	}
	return (-1);
}

int
scf_tmpl_error_prop_tmpl(const scf_tmpl_error_t *err, char **name, char **type)
{
	assert(err != NULL);
	switch (err->te_type) {
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
		if (err->te_tmpl_prop_name != NULL &&
		    err->te_tmpl_prop_type != NULL) {
			if (name != NULL)
				*name = (char *)err->te_tmpl_prop_name;
			if (type != NULL)
				*type = (char *)err->te_tmpl_prop_type;
			return (0);
		}
		/*FALLTHROUGH*/
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_PG_REDEFINE:
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		break;
	default:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
	}
	return (-1);
}

int
scf_tmpl_error_prop(const scf_tmpl_error_t *err, char **name, char **type)
{
	assert(err != NULL);
	switch (err->te_type) {
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
		if (err->te_prop_name != NULL &&
		    err->te_tmpl_prop_type != NULL) {
			if (name != NULL)
				*name = (char *)err->te_prop_name;
			if (type != NULL)
				*type = (char *)err->te_tmpl_prop_type;
			return (0);
		}
		/*FALLTHROUGH*/
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
	case SCF_TERR_PG_REDEFINE:
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		break;
	default:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
	}
	return (-1);
}

int
scf_tmpl_error_value(const scf_tmpl_error_t *err, char **val)
{
	assert(err != NULL);
	switch (err->te_type) {
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
	case SCF_TERR_RANGE_VIOLATION:
	case SCF_TERR_VALUE_OUT_OF_RANGE:
	case SCF_TERR_INVALID_VALUE:
		if (err->te_actual != NULL) {
			if (val != NULL)
				*val = (char *)err->te_actual;
			return (0);
		}
		/*FALLTHROUGH*/
	case SCF_TERR_MISSING_PG:
	case SCF_TERR_WRONG_PG_TYPE:
	case SCF_TERR_MISSING_PROP:
	case SCF_TERR_WRONG_PROP_TYPE:
	case SCF_TERR_CARDINALITY_VIOLATION:
	case SCF_TERR_PROP_TYPE_MISMATCH:
	case SCF_TERR_PG_REDEFINE:
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		break;
	default:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
	}
	return (-1);
}

const char *
scf_tmpl_visibility_to_string(uint8_t vis)
{
	if (vis == SCF_TMPL_VISIBILITY_READONLY)
		return (SCF_TM_VISIBILITY_READONLY);
	else if (vis == SCF_TMPL_VISIBILITY_HIDDEN)
		return (SCF_TM_VISIBILITY_HIDDEN);
	else if (vis == SCF_TMPL_VISIBILITY_READWRITE)
		return (SCF_TM_VISIBILITY_READWRITE);
	else
		return ("unknown");
}
