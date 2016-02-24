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
 */

#include "libscf_impl.h"

#include <assert.h>
#include <strings.h>

/*
 * Errors returned by smf_notify_{del|get|set}_params()
 */
static const scf_error_t errs_1[] = {
	SCF_ERROR_BACKEND_ACCESS,
	SCF_ERROR_BACKEND_READONLY,
	SCF_ERROR_CONNECTION_BROKEN,
	SCF_ERROR_DELETED,
	SCF_ERROR_INTERNAL,
	SCF_ERROR_INVALID_ARGUMENT,
	SCF_ERROR_NO_MEMORY,
	SCF_ERROR_NO_RESOURCES,
	SCF_ERROR_NOT_FOUND,
	SCF_ERROR_PERMISSION_DENIED,
	0
};

/*
 * Errors returned by smf_notify_{del|get|set}_params()
 * Except SCF_ERROR_INVALID_ARGUMENT
 */
static const scf_error_t errs_2[] = {
	SCF_ERROR_BACKEND_ACCESS,
	SCF_ERROR_BACKEND_READONLY,
	SCF_ERROR_CONNECTION_BROKEN,
	SCF_ERROR_DELETED,
	SCF_ERROR_INTERNAL,
	SCF_ERROR_NO_MEMORY,
	SCF_ERROR_NO_RESOURCES,
	SCF_ERROR_NOT_FOUND,
	SCF_ERROR_PERMISSION_DENIED,
	0
};

/*
 * Helper function that abort() on unexpected errors.
 * The expected error set is a zero-terminated array of scf_error_t
 */
static int
check_scf_error(scf_error_t e, const scf_error_t *errs)
{
	if (ismember(e, errs))
		return (1);

	assert(0);
	abort();

	/*NOTREACHED*/
}

/*
 * Mapping of state transition to pgname.
 */
static struct st_pgname {
	const char	*st_pgname;
	int32_t		st_state;
} st_pgnames[] = {
	{ "to-uninitialized", SCF_TRANS(0, SCF_STATE_UNINIT) },
	{ "from-uninitialized", SCF_TRANS(SCF_STATE_UNINIT, 0) },
	{ "to-maintenance", SCF_TRANS(0, SCF_STATE_MAINT) },
	{ "from-maintenance", SCF_TRANS(SCF_STATE_MAINT, 0) },
	{ "to-offline", SCF_TRANS(0, SCF_STATE_OFFLINE) },
	{ "from-offline", SCF_TRANS(SCF_STATE_OFFLINE, 0) },
	{ "to-disabled", SCF_TRANS(0, SCF_STATE_DISABLED) },
	{ "from-disabled", SCF_TRANS(SCF_STATE_DISABLED, 0) },
	{ "to-online", SCF_TRANS(0, SCF_STATE_ONLINE) },
	{ "from-online", SCF_TRANS(SCF_STATE_ONLINE, 0) },
	{ "to-degraded", SCF_TRANS(0, SCF_STATE_DEGRADED) },
	{ "from-degraded", SCF_TRANS(SCF_STATE_DEGRADED, 0) },
	{ NULL, 0 }
};

/*
 * Check if class matches or is a subclass of SCF_SVC_TRANSITION_CLASS
 *
 * returns 1, otherwise return 0
 */
static boolean_t
is_svc_stn(const char *class)
{
	int n = strlen(SCF_SVC_TRANSITION_CLASS);

	if (class && strncmp(class, SCF_SVC_TRANSITION_CLASS, n) == 0)
		if (class[n] == '\0' || class[n] == '.')
			return (1);
	return (0);
}

/*
 * Return the len of the base class. For instance, "class.class1.class2.*"
 * will return the length of "class.class1.class2"
 * This function does not check if the class or base class is valid.
 * A class such as "class.class1....****" is not valid but will return the
 * length of "class.class1....***"
 */
static size_t
base_class_len(const char *c)
{
	const char *p;
	size_t n;

	if ((n = strlen(c)) == 0)
		return (0);

	p = c + n;

	/* get rid of any trailing asterisk */
	if (*--p == '*')
		n--;

	/* make sure the class doesn't end in '.' */
	while (p >= c && *--p == '.')
		n--;

	return (n);
}

/*
 * Allocates and builds the pgname for an FMA dotted class.
 * The pgname will be of the form "class.class1.class2,SCF_NOTIFY_PG_POSTFIX"
 *
 * NULL on error
 */
static char *
class_to_pgname(const char *class)
{
	size_t n;
	ssize_t sz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	char *pgname = NULL;

	n = base_class_len(class);

	if (n == 0) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (NULL);
	}

	if ((pgname = malloc(sz)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto error;
	}

	if (snprintf(pgname, sz, "%.*s,%s", (int)n, class,
	    SCF_NOTIFY_PG_POSTFIX) >= sz) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto error;
	}
	return (pgname);

error:
	free(pgname);
	pgname = NULL;

	return (pgname);
}

/*
 * Get the pg from the running snapshot of the instance (composed or not)
 */
static int
get_pg(scf_service_t *s, scf_instance_t *i, const char *n,
    scf_propertygroup_t *pg, int composed)
{
	scf_handle_t	*h = scf_instance_handle(i);
	scf_error_t	scf_e = scf_error();
	scf_snapshot_t	*snap = scf_snapshot_create(h);
	scf_snaplevel_t	*slvl = scf_snaplevel_create(h);
	int r = -1;

	if (h == NULL) {
		/*
		 * Use the error stored in scf_e
		 */
		(void) scf_set_error(scf_e);
		goto out;
	}
	if (s == NULL) {
		if (snap == NULL || slvl == NULL)
			goto out;
		if (scf_instance_get_snapshot(i, "running", snap) != 0)
			goto out;

		if (composed) {
			if (scf_instance_get_pg_composed(i, snap, n, pg) != 0)
				goto out;
		} else {
			if (scf_snapshot_get_base_snaplevel(snap, slvl) != 0 ||
			    scf_snaplevel_get_pg(slvl, n, pg) != 0)
				goto out;
		}
	} else {
		if (scf_service_get_pg(s, n, pg) != 0)
			goto out;
	}

	r = 0;
out:
	scf_snaplevel_destroy(slvl);
	scf_snapshot_destroy(snap);

	return (r);
}

/*
 * Add a pg if it does not exist, or get it if it exists.
 * It operates on the instance if the service parameter is NULL.
 *
 * returns 0 on success or -1 on failure
 */
static int
get_or_add_pg(scf_service_t *s, scf_instance_t *i, const char *n, const char *t,
    uint32_t flags, scf_propertygroup_t *pg)
{
	int r;

	if (s == NULL)
		r = scf_instance_add_pg(i, n, t, flags, pg);
	else
		r = scf_service_add_pg(s, n, t, flags, pg);

	if (r == 0)
		return (0);
	else if (scf_error() != SCF_ERROR_EXISTS)
		return (-1);

	if (s == NULL)
		r = scf_instance_get_pg(i, n, pg);
	else
		r = scf_service_get_pg(s, n, pg);

	return (r);
}

/*
 * Delete the property group form the instance or service.
 * If service is NULL, use instance, otherwise use only the service.
 *
 * Return SCF_SUCCESS or SCF_FAILED on
 * 	SCF_ERROR_BACKEND_ACCESS
 * 	SCF_ERROR_BACKEND_READONLY
 * 	SCF_ERROR_CONNECTION_BROKEN
 * 	SCF_ERROR_DELETED
 * 	SCF_ERROR_HANDLE_MISMATCH
 * 	SCF_ERROR_INTERNAL
 * 	SCF_ERROR_INVALID_ARGUMENT
 * 	SCF_ERROR_NO_RESOURCES
 * 	SCF_ERROR_NOT_BOUND
 * 	SCF_ERROR_NOT_FOUND
 * 	SCF_ERROR_NOT_SET
 * 	SCF_ERROR_PERMISSION_DENIED
 */
static int
del_pg(scf_service_t *s, scf_instance_t *i, const char *n,
    scf_propertygroup_t *pg)
{
	if ((s == NULL ? scf_instance_get_pg(i, n, pg) :
	    scf_service_get_pg(s, n, pg)) != SCF_SUCCESS)
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			return (SCF_SUCCESS);
		else
			return (SCF_FAILED);

	if (scf_pg_delete(pg) != SCF_SUCCESS)
		if (scf_error() == SCF_ERROR_DELETED)
			return (SCF_SUCCESS);
		else
			return (SCF_FAILED);

	return (SCF_SUCCESS);
}

static scf_type_t
get_scf_type(nvpair_t *p)
{
	switch (nvpair_type(p)) {
	case DATA_TYPE_BOOLEAN:
	case DATA_TYPE_BOOLEAN_VALUE:
	case DATA_TYPE_BOOLEAN_ARRAY:
		return (SCF_TYPE_BOOLEAN);

	case DATA_TYPE_BYTE:
	case DATA_TYPE_UINT8:
	case DATA_TYPE_UINT16:
	case DATA_TYPE_UINT32:
	case DATA_TYPE_UINT64:
	case DATA_TYPE_BYTE_ARRAY:
	case DATA_TYPE_UINT8_ARRAY:
	case DATA_TYPE_UINT16_ARRAY:
	case DATA_TYPE_UINT32_ARRAY:
	case DATA_TYPE_UINT64_ARRAY:
		return (SCF_TYPE_COUNT);

	case DATA_TYPE_INT8:
	case DATA_TYPE_INT16:
	case DATA_TYPE_INT32:
	case DATA_TYPE_INT64:
	case DATA_TYPE_INT8_ARRAY:
	case DATA_TYPE_INT16_ARRAY:
	case DATA_TYPE_INT32_ARRAY:
	case DATA_TYPE_INT64_ARRAY:
		return (SCF_TYPE_INTEGER);

	case DATA_TYPE_STRING:
	case DATA_TYPE_STRING_ARRAY:
		return (SCF_TYPE_ASTRING);

	default:
		return (SCF_TYPE_INVALID);
	}
}

static int
add_entry(scf_transaction_entry_t *te, scf_value_t *val)
{
	if (scf_entry_add_value(te, val) != 0) {
		scf_value_destroy(val);
		return (SCF_FAILED);
	}

	return (SCF_SUCCESS);
}

static int
add_boolean_entry(scf_handle_t *h, scf_transaction_entry_t *te, uint8_t v)
{
	scf_value_t *val = scf_value_create(h);

	if (val == NULL)
		return (SCF_FAILED);

	scf_value_set_boolean(val, v);

	return (add_entry(te, val));
}

static int
add_count_entry(scf_handle_t *h, scf_transaction_entry_t *te, uint64_t v)
{
	scf_value_t *val = scf_value_create(h);

	if (val == NULL)
		return (SCF_FAILED);

	scf_value_set_count(val, v);

	return (add_entry(te, val));
}

static int
add_integer_entry(scf_handle_t *h, scf_transaction_entry_t *te, int64_t v)
{
	scf_value_t *val = scf_value_create(h);

	if (val == NULL)
		return (SCF_FAILED);

	scf_value_set_integer(val, v);

	return (add_entry(te, val));
}

static int
add_astring_entry(scf_handle_t *h, scf_transaction_entry_t *te, char *s)
{
	scf_value_t *val = scf_value_create(h);

	if (val == NULL)
		return (SCF_FAILED);

	if (scf_value_set_astring(val, s) != 0) {
		scf_value_destroy(val);
		return (SCF_FAILED);
	}

	return (add_entry(te, val));
}

static int
get_nvpair_vals(scf_handle_t *h, scf_transaction_entry_t *te, nvpair_t *p)
{
	scf_value_t *val = scf_value_create(h);
	uint_t n = 1;
	int i;

	if (val == NULL)
		return (SCF_FAILED);

	switch (nvpair_type(p)) {
	case DATA_TYPE_BOOLEAN:
		return (add_boolean_entry(h, te, 1));
	case DATA_TYPE_BOOLEAN_VALUE:
		{
			boolean_t v;

			(void) nvpair_value_boolean_value(p, &v);
			return (add_boolean_entry(h, te, (uint8_t)v));
		}
	case DATA_TYPE_BOOLEAN_ARRAY:
		{
			boolean_t *v;

			(void) nvpair_value_boolean_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_boolean_entry(h, te, (uint8_t)v[i]) !=
				    SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_BYTE:
		{
			uchar_t v;

			(void) nvpair_value_byte(p, &v);
			return (add_count_entry(h, te, v));
		}
	case DATA_TYPE_UINT8:
		{
			uint8_t v;

			(void) nvpair_value_uint8(p, &v);
			return (add_count_entry(h, te, v));
		}
	case DATA_TYPE_UINT16:
		{
			uint16_t v;

			(void) nvpair_value_uint16(p, &v);
			return (add_count_entry(h, te, v));
		}
	case DATA_TYPE_UINT32:
		{
			uint32_t v;

			(void) nvpair_value_uint32(p, &v);
			return (add_count_entry(h, te, v));
		}
	case DATA_TYPE_UINT64:
		{
			uint64_t v;

			(void) nvpair_value_uint64(p, &v);
			return (add_count_entry(h, te, v));
		}
	case DATA_TYPE_BYTE_ARRAY:
		{
			uchar_t *v;

			(void) nvpair_value_byte_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_count_entry(h, te, v[i]) != SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_UINT8_ARRAY:
		{
			uint8_t *v;

			(void) nvpair_value_uint8_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_count_entry(h, te, v[i]) != SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_UINT16_ARRAY:
		{
			uint16_t *v;

			(void) nvpair_value_uint16_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_count_entry(h, te, v[i]) != SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_UINT32_ARRAY:
		{
			uint32_t *v;

			(void) nvpair_value_uint32_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_count_entry(h, te, v[i]) != SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_UINT64_ARRAY:
		{
			uint64_t *v;

			(void) nvpair_value_uint64_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_count_entry(h, te, v[i]) != SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_INT8:
		{
			int8_t v;

			(void) nvpair_value_int8(p, &v);
			return (add_integer_entry(h, te, v));
		}
	case DATA_TYPE_INT16:
		{
			int16_t v;

			(void) nvpair_value_int16(p, &v);
			return (add_integer_entry(h, te, v));
		}
	case DATA_TYPE_INT32:
		{
			int32_t v;

			(void) nvpair_value_int32(p, &v);
			return (add_integer_entry(h, te, v));
		}
	case DATA_TYPE_INT64:
		{
			int64_t v;

			(void) nvpair_value_int64(p, &v);
			return (add_integer_entry(h, te, v));
		}
	case DATA_TYPE_INT8_ARRAY:
		{
			int8_t *v;

			(void) nvpair_value_int8_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_integer_entry(h, te, v[i]) !=
				    SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_INT16_ARRAY:
		{
			int16_t *v;

			(void) nvpair_value_int16_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_integer_entry(h, te, v[i]) !=
				    SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_INT32_ARRAY:
		{
			int32_t *v;

			(void) nvpair_value_int32_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_integer_entry(h, te, v[i]) !=
				    SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_INT64_ARRAY:
		{
			int64_t *v;

			(void) nvpair_value_int64_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_integer_entry(h, te, v[i]) !=
				    SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	case DATA_TYPE_STRING:
		{
			char *str;

			(void) nvpair_value_string(p, &str);
			return (add_astring_entry(h, te, str));
		}
	case DATA_TYPE_STRING_ARRAY:
		{
			char **v;

			(void) nvpair_value_string_array(p, &v, &n);
			for (i = 0; i < n; ++i) {
				if (add_astring_entry(h, te, v[i]) !=
				    SCF_SUCCESS)
					return (SCF_FAILED);
			}
			return (SCF_SUCCESS);
		}
	default:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (SCF_FAILED);
	}

	/*NOTREACHED*/
}

/*
 * Add new transaction entry to scf_transaction_t
 *
 * Can fail with
 *	SCF_ERROR_BACKEND_ACCESS
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_INTERNAL
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_FOUND
 */
static int
prep_transaction(scf_transaction_t *tx, scf_transaction_entry_t *te,
    const char *prop, scf_type_t type)
{
	if (scf_transaction_property_new(tx, te, prop, type) != SCF_SUCCESS &&
	    (scf_error() != SCF_ERROR_EXISTS ||
	    scf_transaction_property_change(tx, te, prop, type) !=
	    SCF_SUCCESS)) {
		if (check_scf_error(scf_error(), errs_2)) {
			return (SCF_FAILED);
		}
	}

	return (SCF_SUCCESS);
}

/*
 * notify_set_params()
 * returns 0 on success or -1 on failure
 *	SCF_ERROR_BACKEND_ACCESS
 *	SCF_ERROR_BACKEND_READONLY
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_INTERNAL
 *	SCF_ERROR_INVALID_ARGUMENT
 *	SCF_ERROR_NO_MEMORY
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_FOUND
 *	SCF_ERROR_PERMISSION_DENIED
 */
static int
notify_set_params(scf_propertygroup_t *pg, nvlist_t *params)
{
	scf_handle_t		*h = scf_pg_handle(pg);
	scf_error_t		scf_e = scf_error();
	scf_transaction_t	*tx = scf_transaction_create(h);
	int	bufsz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	char	*propname = malloc(bufsz);
	int	r = -1;
	int	err;

	if (h == NULL) {
		/*
		 * Use the error stored in scf_e
		 */
		(void) scf_set_error(scf_e);
		goto cleanup;
	}
	if (tx == NULL)
		goto cleanup;

	if (propname == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	do {
		nvpair_t *nvp;

		/*
		 * make sure we have the most recent version of the pg
		 * start the transaction
		 */
		if (scf_pg_update(pg) == SCF_FAILED ||
		    scf_transaction_start(tx, pg) != SCF_SUCCESS) {
			if (check_scf_error(scf_error(), errs_2)) {
				goto cleanup;
			}
		}

		for (nvp = nvlist_next_nvpair(params, NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(params, nvp)) {
			nvlist_t	*m;
			nvpair_t	*p;

			/* we ONLY take nvlists here */
			if (nvpair_type(nvp) != DATA_TYPE_NVLIST) {
				char *name = nvpair_name(nvp);

				/*
				 * if this is output from
				 * smf_notify_get_params() we want to skip
				 * the tset value of the nvlist
				 */
				if (strcmp(name, SCF_NOTIFY_NAME_TSET) == 0)
					continue;

				(void) scf_set_error(
				    SCF_ERROR_INVALID_ARGUMENT);
				goto cleanup;
			}

			if (nvpair_value_nvlist(nvp, &m) != 0) {
				(void) scf_set_error(
				    SCF_ERROR_INVALID_ARGUMENT);
				goto cleanup;
			}

			/*
			 * Traverse each mechanism list
			 */
			for (p = nvlist_next_nvpair(m, NULL); p != NULL;
			    p = nvlist_next_nvpair(m, p)) {
				scf_transaction_entry_t *te =
				    scf_entry_create(h);
				/* map the nvpair type to scf type */
				scf_type_t type = get_scf_type(p);

				if (te == NULL) {
					if (scf_error() !=
					    SCF_ERROR_INVALID_ARGUMENT) {
						scf_entry_destroy(te);
						goto cleanup;
					} else {
						assert(0);
						abort();
					}
				}

				if (type == SCF_TYPE_INVALID) {
					(void) scf_set_error(
					    SCF_ERROR_INVALID_ARGUMENT);
					scf_entry_destroy(te);
					goto cleanup;
				}

				if (snprintf(propname, bufsz, "%s,%s",
				    nvpair_name(nvp), nvpair_name(p)) >=
				    bufsz) {
					(void) scf_set_error(
					    SCF_ERROR_INVALID_ARGUMENT);
					scf_entry_destroy(te);
					goto cleanup;
				}

				if (prep_transaction(tx, te, propname, type) !=
				    SCF_SUCCESS) {
					scf_entry_destroy(te);
					goto cleanup;
				}

				if (get_nvpair_vals(h, te, p) != SCF_SUCCESS) {
					if (check_scf_error(scf_error(),
					    errs_2)) {
						goto cleanup;
					}
				}
			}
		}
		err = scf_transaction_commit(tx);
		scf_transaction_destroy_children(tx);
	} while (err == 0);

	if (err == -1) {
		if (check_scf_error(scf_error(), errs_2)) {
			goto cleanup;
		}
	}

	r = 0;

cleanup:
	scf_transaction_destroy_children(tx);
	scf_transaction_destroy(tx);
	free(propname);

	return (r);
}

/*
 * Decode fmri. Populates service OR instance depending on which one is an
 * exact match to the fmri parameter.
 *
 * The function destroys and sets the unused entity (service or instance) to
 * NULL.
 *
 * return SCF_SUCCESS or SCF_FAILED on
 * 	SCF_ERROR_BACKEND_ACCESS
 * 	SCF_ERROR_CONNECTION_BROKEN
 * 	SCF_ERROR_CONSTRAINT_VIOLATED
 * 	SCF_ERROR_DELETED
 * 	SCF_ERROR_HANDLE_MISMATCH
 * 	SCF_ERROR_INTERNAL
 * 	SCF_ERROR_INVALID_ARGUMENT
 * 	SCF_ERROR_NO_RESOURCES
 * 	SCF_ERROR_NOT_BOUND
 * 	SCF_ERROR_NOT_FOUND
 * 	SCF_ERROR_NOT_SET
 */
static int
decode_fmri(const char *fmri, scf_handle_t *h, scf_service_t **s,
    scf_instance_t **i)
{
	if (scf_handle_decode_fmri(h, fmri, NULL, *s, NULL, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED) {
			scf_service_destroy(*s);
			*s = NULL;
		} else {
			return (SCF_FAILED);
		}
	}
	if (*s == NULL)
		if (scf_handle_decode_fmri(h, fmri, NULL, NULL, *i,
		    NULL, NULL, SCF_DECODE_FMRI_EXACT) != SCF_SUCCESS) {
			return (SCF_FAILED);
	}

	return (SCF_SUCCESS);
}

/*
 * Return size in bytes for an SCF_TYPE_*. Not all libscf types are supported
 */
static int
get_type_size(scf_type_t t)
{
	switch (t) {
	case SCF_TYPE_BOOLEAN:
		return (sizeof (uint8_t));
	case SCF_TYPE_COUNT:
		return (sizeof (uint64_t));
	case SCF_TYPE_INTEGER:
		return (sizeof (int64_t));
	case SCF_TYPE_ASTRING:
	case SCF_TYPE_USTRING:
		return (sizeof (void *));
	default:
		return (-1);
	}

	/*NOTREACHED*/
}

/*
 * Return a pointer to the array of values according to its type
 */
static void **
get_v_pointer(scf_values_t *v)
{
	switch (v->value_type) {
	case SCF_TYPE_BOOLEAN:
		return ((void **)&v->values.v_boolean);
	case SCF_TYPE_COUNT:
		return ((void **)&v->values.v_count);
	case SCF_TYPE_INTEGER:
		return ((void **)&v->values.v_integer);
	case SCF_TYPE_ASTRING:
		return ((void **)&v->values.v_astring);
	case SCF_TYPE_USTRING:
		return ((void **)&v->values.v_ustring);
	default:
		return (NULL);
	}

	/*NOTREACHED*/
}

/*
 * Populate scf_values_t value array at position c.
 */
static int
get_value(scf_value_t *val, scf_values_t *v, int c, char *buf, int sz)
{
	switch (v->value_type) {
	case SCF_TYPE_BOOLEAN:
		return (scf_value_get_boolean(val, v->values.v_boolean + c));
	case SCF_TYPE_COUNT:
		return (scf_value_get_count(val, v->values.v_count + c));
	case SCF_TYPE_INTEGER:
		return (scf_value_get_integer(val, v->values.v_integer + c));
	case SCF_TYPE_ASTRING:
		if (scf_value_get_astring(val, buf, sz) < 0 ||
		    (v->values.v_astring[c] = strdup(buf)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			return (-1);
		}
		return (0);
	case SCF_TYPE_USTRING:
		if (scf_value_get_ustring(val, buf, sz) < 0 ||
		    (v->values.v_ustring[c] = strdup(buf)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			return (-1);
		}
		return (0);
	default:
		return (-1);
	}

	/*NOTREACHED*/
}

/*
 * Populate scf_values_t structure with values from prop
 */
static int
values_get(scf_property_t *prop, scf_values_t *v)
{
	scf_handle_t	*h = scf_property_handle(prop);
	scf_error_t	scf_e = scf_error();
	scf_value_t	*val = scf_value_create(h);
	scf_iter_t	*it = scf_iter_create(h);
	scf_type_t	type = SCF_TYPE_INVALID;
	ssize_t		sz = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH) + 1;
	char		*buf = malloc(sz);
	void **p;
	int err, elem_sz, count, cursz;
	int r = SCF_FAILED;

	assert(v != NULL);
	assert(v->reserved == NULL);
	if (buf == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}
	if (h == NULL) {
		/*
		 * Use the error stored in scf_e
		 */
		(void) scf_set_error(scf_e);
		goto cleanup;
	}
	if (val == NULL || it == NULL)
		goto cleanup;

	if (scf_property_type(prop, &type) != SCF_SUCCESS)
		goto cleanup;
	if (scf_property_is_type(prop, v->value_type) != SCF_SUCCESS)
		goto error;

	elem_sz = get_type_size(type);
	assert(elem_sz > 0);

	p = get_v_pointer(v);
	assert(p != NULL);

	cursz = count = v->value_count;
	if (scf_iter_property_values(it, prop) != 0) {
		goto error;
	}

	while ((err = scf_iter_next_value(it, val)) == 1) {
		if (count + 1 >= cursz) {
			void *tmp;

			/* set initial size or double it */
			cursz = cursz ? 2 * cursz : 8;
			if ((tmp = realloc(*p, cursz * elem_sz)) == NULL) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				goto error;
			}
			*p = tmp;
		}

		if (get_value(val, v, count, buf, sz) != 0)
			goto error;

		count++;
	}

	v->value_count = count;

	if (err != 0)
		goto error;

	r = SCF_SUCCESS;
	goto cleanup;

error:
	v->value_count = count;
	scf_values_destroy(v);

cleanup:
	free(buf);
	scf_iter_destroy(it);
	scf_value_destroy(val);
	return (r);
}

/*
 * Add values from property p to existing nvlist_t nvl. The data type in the
 * nvlist is inferred from the scf_type_t of the property.
 *
 * Returns SCF_SUCCESS or SCF_FAILED on
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_HANDLE_DESTROYED
 *	SCF_ERROR_HANDLE_MISMATCH
 *	SCF_ERROR_INVALID_ARGUMENT
 *	SCF_ERROR_NO_MEMORY
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_BOUND
 *	SCF_ERROR_NOT_SET
 *	SCF_ERROR_PERMISSION_DENIED
 *	SCF_ERROR_TYPE_MISMATCH
 */
static int
add_prop_to_nvlist(scf_property_t *p, const char *pname, nvlist_t *nvl,
    int array)
{
	scf_values_t	vals = { 0 };
	scf_type_t	type, base_type;
	int r = SCF_FAILED;
	int err = 0;

	if (p == NULL || pname == NULL || *pname == '\0' || nvl == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (r);
	}

	if (scf_property_type(p, &type) != 0)
		goto cleanup;

	/*
	 * scf_values_t does not support subtypes of SCF_TYPE_USTRING,
	 * mapping them all to SCF_TYPE_USTRING
	 */
	base_type = scf_true_base_type(type);
	if (base_type == SCF_TYPE_ASTRING && type != SCF_TYPE_ASTRING)
		type = SCF_TYPE_USTRING;

	vals.value_type = type;
	if (values_get(p, &vals) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_INVALID_ARGUMENT) {
			assert(0);
			abort();
		}
		goto cleanup;
	}

	switch (vals.value_type) {
	case SCF_TYPE_BOOLEAN:
		{
			boolean_t *v;
			int i;
			int n = vals.value_count;

			v = calloc(n, sizeof (boolean_t));
			if (v == NULL) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				goto cleanup;
			}
			for (i = 0; i < n; ++i)
				v[i] = (boolean_t)vals.values.v_boolean[i];

			if (n == 1 && !array)
				err = nvlist_add_boolean_value(nvl, pname, *v);
			else
				err = nvlist_add_boolean_array(nvl, pname,
				    v, n);
			if (err != 0) {
				free(v);
				goto cleanup;
			}
			free(v);
		}
		break;

	case SCF_TYPE_COUNT:
		if (vals.value_count == 1 && !array)
			err = nvlist_add_uint64(nvl, pname,
			    *vals.values.v_count);
		else
			err = nvlist_add_uint64_array(nvl, pname,
			    vals.values.v_count, vals.value_count);
		if (err != 0)
			goto cleanup;

		break;

	case SCF_TYPE_INTEGER:
		if (vals.value_count == 1 && !array)
			err = nvlist_add_int64(nvl, pname,
			    *vals.values.v_integer);
		else
			err = nvlist_add_int64_array(nvl, pname,
			    vals.values.v_integer, vals.value_count);
		if (err != 0)
			goto cleanup;

		break;

	case SCF_TYPE_ASTRING:
		if (vals.value_count == 1 && !array)
			err = nvlist_add_string(nvl, pname,
			    *vals.values.v_astring);
		else
			err = nvlist_add_string_array(nvl, pname,
			    vals.values.v_astring, vals.value_count);
		if (err != 0)
			goto cleanup;
		break;

	default:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto cleanup;
	}

	r = SCF_SUCCESS;
cleanup:
	scf_values_destroy(&vals);
	switch (err) {
	case 0:
		break;
	case EINVAL:
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		break;
	case ENOMEM:
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		break;
	default:
		/* we should *never* get here */
		abort();
	}

	return (r);
}

/*
 * Parse property name "mechanism,parameter" into separate mechanism
 * and parameter.  *mech must be freed by caller.  *val points into
 * *mech and must not be freed.
 *
 * Returns SCF_SUCCESS or SCF_FAILED on
 * 	SCF_ERROR_NO_MEMORY
 * 	SCF_ERROR_NOT_FOUND
 */
static int
get_mech_name(const char *name, char **mech, char **val)
{
	char *p;
	char *m;

	if ((m = strdup(name)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (SCF_FAILED);
	}
	if ((p = strchr(m, ',')) == NULL) {
		free(m);
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		return (SCF_FAILED);
	}
	*p = '\0';
	*val = p + 1;
	*mech = m;

	return (SCF_SUCCESS);
}

/*
 * Return the number of transitions in a transition set.
 * If the transition set is invalid, it returns zero.
 */
static uint_t
num_of_transitions(int32_t t)
{
	int i;
	int n = 0;

	if (SCF_TRANS_VALID(t)) {
		for (i = 0x1; i < SCF_STATE_ALL; i <<= 1) {
			if (i & t)
				++n;
			if (SCF_TRANS_INITIAL_STATE(t) & i)
				++n;
		}
	}

	return (n);
}

/*
 * Return the SCF_STATE_* macro value for the state in the FMA classes for
 * SMF state transitions. They are of type:
 *     SCF_SVC_TRANSITION_CLASS.<state>
 *     ireport.os.smf.state-transition.<state>
 */
static int32_t
class_to_transition(const char *c)
{
	const char *p;
	int r = 0;
	size_t n;

	if (!is_svc_stn(c)) {
		return (0);
	}

	/*
	 * if we get here, c is SCF_SVC_TRANSITION_CLASS or longer
	 */
	p = c + strlen(SCF_SVC_TRANSITION_CLASS);
	if (*p == '.')
		++p;
	else
		return (0);

	if ((n = base_class_len(p)) == 0)
		return (0);

	if ((r = state_from_string(p, n)) == -1)
		r = 0;

	return (r);
}

/*
 * return SCF_SUCCESS or SCF_FAILED on
 *	SCF_ERROR_BACKEND_ACCESS
 *	SCF_ERROR_BACKEND_READONLY
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_INTERNAL
 *	SCF_ERROR_INVALID_ARGUMENT
 *	SCF_ERROR_NO_MEMORY
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_FOUND
 *	SCF_ERROR_PERMISSION_DENIED
 */
int
smf_notify_set_params(const char *class, nvlist_t *attr)
{
	uint32_t	ver;
	int32_t		tset;
	scf_handle_t		*h = _scf_handle_create_and_bind(SCF_VERSION);
	scf_error_t		scf_e = scf_error();
	scf_service_t		*s = scf_service_create(h);
	scf_instance_t		*i = scf_instance_create(h);
	scf_propertygroup_t	*pg = scf_pg_create(h);
	nvlist_t	*params = NULL;
	char		*fmri = (char *)SCF_NOTIFY_PARAMS_INST;
	char		*pgname = NULL;
	int		r = SCF_FAILED;
	boolean_t	is_stn;
	int		 j;

	assert(class != NULL);
	if (h == NULL) {
		/*
		 * use saved error if _scf_handle_create_and_bind() fails
		 */
		(void) scf_set_error(scf_e);
		goto cleanup;
	}
	if (i == NULL || s == NULL || pg == NULL)
		goto cleanup;

	/* check version */
	if (nvlist_lookup_uint32(attr, SCF_NOTIFY_NAME_VERSION, &ver) != 0 ||
	    ver != SCF_NOTIFY_PARAMS_VERSION) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto cleanup;
	}

	if (nvlist_lookup_nvlist(attr, SCF_NOTIFY_PARAMS, &params) != 0) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto cleanup;
	}

	is_stn = is_svc_stn(class);
	/* special case SMF state transition notification */
	if (is_stn &&
	    (nvlist_lookup_string(attr, SCF_NOTIFY_NAME_FMRI, &fmri) != 0 ||
	    nvlist_lookup_int32(attr, SCF_NOTIFY_NAME_TSET, &tset) != 0 ||
	    !SCF_TRANS_VALID(tset))) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto cleanup;
	}
	if (decode_fmri(fmri, h, &s, &i) != SCF_SUCCESS)
		if (scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED) {
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		} else if (check_scf_error(scf_error(), errs_1)) {
			goto cleanup;
		}

	if (is_stn) {
		tset |= class_to_transition(class);

		if (!SCF_TRANS_VALID(tset)) {
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
			goto cleanup;
		}

		for (j = 0; st_pgnames[j].st_pgname != NULL; ++j) {
			/* if this transition is not in the tset, continue */
			if (!(tset & st_pgnames[j].st_state))
				continue;

			if (get_or_add_pg(s, i, st_pgnames[j].st_pgname,
			    SCF_NOTIFY_PARAMS_PG_TYPE, 0, pg) != 0 &&
			    check_scf_error(scf_error(), errs_2))
				goto cleanup;

			if (notify_set_params(pg, params) != 0)
				goto cleanup;
		}
		if (s == NULL) {
			/* We only need to refresh the instance */
			if (_smf_refresh_instance_i(i) != 0 &&
			    check_scf_error(scf_error(), errs_1))
				goto cleanup;
		} else {
			/* We have to refresh all instances in the service */
			if (_smf_refresh_all_instances(s) != 0 &&
			    check_scf_error(scf_error(), errs_1))
				goto cleanup;
		}
	} else {
		if ((pgname = class_to_pgname(class)) == NULL)
			goto cleanup;
		if (get_or_add_pg(s, i, pgname, SCF_GROUP_APPLICATION, 0, pg) !=
		    0) {
			if (check_scf_error(scf_error(), errs_2)) {
				goto cleanup;
			}
		}
		if (notify_set_params(pg, params) != 0) {
			goto cleanup;
		}
		if (_smf_refresh_instance_i(i) != 0 &&
		    check_scf_error(scf_error(), errs_1))
			goto cleanup;
	}

	r = SCF_SUCCESS;
cleanup:
	scf_instance_destroy(i);
	scf_service_destroy(s);
	scf_pg_destroy(pg);
	scf_handle_destroy(h);
	free(pgname);

	return (r);
}

/*
 * returns SCF_SUCCESS or SCF_FAILED on
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_HANDLE_DESTROYED
 *	SCF_ERROR_HANDLE_MISMATCH
 *	SCF_ERROR_INVALID_ARGUMENT
 *	SCF_ERROR_NO_MEMORY
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_BOUND
 *	SCF_ERROR_NOT_FOUND
 *	SCF_ERROR_NOT_SET
 *	SCF_ERROR_PERMISSION_DENIED
 */
int
_scf_notify_get_params(scf_propertygroup_t *pg, nvlist_t *params)
{
	scf_handle_t	*h = scf_pg_handle(pg);
	scf_error_t	scf_e = scf_error();
	scf_property_t	*p = scf_property_create(h);
	scf_iter_t	*it = scf_iter_create(h);
	int sz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	char *name = malloc(sz);
	int r = SCF_FAILED;
	int err;

	if (h == NULL) {
		/*
		 * Use the error stored in scf_e
		 */
		(void) scf_set_error(scf_e);
		goto cleanup;
	}
	if (it == NULL || p == NULL)
		goto cleanup;

	if (name == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	if (scf_iter_pg_properties(it, pg) != SCF_SUCCESS) {
		if (check_scf_error(scf_error(), errs_1)) {
			goto cleanup;
		}
	}

	while ((err = scf_iter_next_property(it, p)) == 1) {
		nvlist_t *nvl;
		int nvl_new = 0;
		char *mech;
		char *val;

		if (scf_property_get_name(p, name, sz) == SCF_FAILED) {
			if (check_scf_error(scf_error(), errs_1)) {
				goto cleanup;
			}
		}

		if (get_mech_name(name, &mech, &val) != SCF_SUCCESS) {
			if (scf_error() == SCF_ERROR_NOT_FOUND)
				continue;
			goto cleanup;
		}

		if (nvlist_lookup_nvlist(params, mech, &nvl) != 0) {
			if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				free(mech);
				goto cleanup;
			}
			nvl_new = 1;
		}

		if (add_prop_to_nvlist(p, val, nvl, 1) != SCF_SUCCESS) {
			if (check_scf_error(scf_error(), errs_2)) {
				free(mech);
				nvlist_free(nvl);
				goto cleanup;
			}
		}
		if (nvl_new) {
			if (nvlist_add_nvlist(params, mech, nvl) != 0) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				free(mech);
				nvlist_free(nvl);
				goto cleanup;
			}
			nvlist_free(nvl);
		}

		free(mech);
	}

	if (err == 0) {
		r = SCF_SUCCESS;
	} else if (check_scf_error(scf_error(), errs_2)) {
		goto cleanup;
	}

cleanup:
	scf_iter_destroy(it);
	scf_property_destroy(p);
	free(name);

	return (r);
}

/*
 * Look up pg containing an SMF state transition parameters. If it cannot find
 * the pg in the composed view of the instance, it will look in the global
 * instance for the system wide parameters.
 * Instance, service and global instance have to be passed by caller.
 *
 * returns SCF_SUCCESS or SCF_FAILED on
 *	SCF_ERROR_BACKEND_ACCESS
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_HANDLE_DESTROYED
 *	SCF_ERROR_HANDLE_MISMATCH
 *	SCF_ERROR_INTERNAL
 *	SCF_ERROR_INVALID_ARGUMENT
 *	SCF_ERROR_NO_MEMORY
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_BOUND
 *	SCF_ERROR_NOT_FOUND
 *	SCF_ERROR_NOT_SET
 */
static int
get_stn_pg(scf_service_t *s, scf_instance_t *i, scf_instance_t *g,
    const char *pgname, scf_propertygroup_t *pg)
{
	if (get_pg(s, i, pgname, pg, 1) == 0 ||
	    scf_error() == SCF_ERROR_NOT_FOUND &&
	    get_pg(NULL, g, pgname, pg, 0) == 0)
		return (SCF_SUCCESS);

	return (SCF_FAILED);
}

/*
 * Populates nvlist_t params with the source fmri for the pg
 *
 * return SCF_SUCCESS or SCF_FAILED on
 * 	SCF_ERROR_DELETED
 * 	SCF_ERROR_CONNECTION_BROKEN
 * 	SCF_ERROR_NO_MEMORY
 */
static int
get_pg_source(scf_propertygroup_t *pg, nvlist_t *params)
{
	size_t sz = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH) + 1;
	char *fmri = malloc(sz);
	char *p;
	int r = SCF_FAILED;

	if (fmri == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto out;
	}

	if (scf_pg_to_fmri(pg, fmri, sz) == -1) {
		if (check_scf_error(scf_error(), errs_1)) {
			goto out;
		}
	}

	/* get rid of the properties part of the pg source */
	if ((p = strrchr(fmri, ':')) != NULL && p > fmri)
		*(p - 1) = '\0';
	if (nvlist_add_string(params, SCF_NOTIFY_PARAMS_SOURCE_NAME, fmri) !=
	    0) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto out;
	}

	r = SCF_SUCCESS;
out:
	free(fmri);
	return (r);
}

/*
 * Specialized function to get SMF state transition notification parameters
 *
 * return SCF_SUCCESS or SCF_FAILED on
 *	SCF_ERROR_BACKEND_ACCESS
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_INTERNAL
 *	SCF_ERROR_INVALID_ARGUMENT
 *	SCF_ERROR_NO_MEMORY
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_FOUND
 *	SCF_ERROR_PERMISSION_DENIED
 */
int
_scf_get_svc_notify_params(const char *fmri, nvlist_t *nvl, int32_t tset,
    int getsource, int getglobal)
{
	scf_handle_t		*h = _scf_handle_create_and_bind(SCF_VERSION);
	scf_error_t		scf_e = scf_error();
	scf_service_t		*s = scf_service_create(h);
	scf_instance_t		*i = scf_instance_create(h);
	scf_instance_t		*g = scf_instance_create(h);
	scf_propertygroup_t	*pg = scf_pg_create(h);
	int r = SCF_FAILED;
	nvlist_t **params = NULL;
	uint_t c, nvl_num = 0;
	int not_found = 1;
	int j;
	const char *pgname;

	assert(fmri != NULL && nvl != NULL);
	if (h == NULL) {
		/*
		 * use saved error if _scf_handle_create_and_bind() fails
		 */
		(void) scf_set_error(scf_e);
		goto cleanup;
	}
	if (s == NULL || i == NULL || g == NULL || pg == NULL)
		goto cleanup;

	if (decode_fmri(fmri, h, &s, &i) != SCF_SUCCESS ||
	    scf_handle_decode_fmri(h, SCF_INSTANCE_GLOBAL, NULL, NULL, g, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		if (scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED) {
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		} else if (check_scf_error(scf_error(), errs_1)) {
			goto cleanup;
		}
	}

	nvl_num = num_of_transitions(tset);
	if ((params = calloc(nvl_num, sizeof (nvlist_t *))) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	for (c = 0; c < nvl_num; ++c)
		if (nvlist_alloc(params + c, NV_UNIQUE_NAME, 0) != 0) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}

	for (c = 0, j = 0; st_pgnames[j].st_pgname != NULL; ++j) {
		/* if this transition is not in the tset, continue */
		if (!(tset & st_pgnames[j].st_state))
			continue;

		assert(c < nvl_num);
		pgname = st_pgnames[j].st_pgname;

		if (nvlist_add_int32(params[c], SCF_NOTIFY_NAME_TSET,
		    st_pgnames[j].st_state) != 0) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto cleanup;
		}
		if ((getglobal ? get_stn_pg(s, i, g, pgname, pg) :
		    get_pg(s, i, pgname, pg, 1)) == SCF_SUCCESS) {
			not_found = 0;
			if (_scf_notify_get_params(pg, params[c]) !=
			    SCF_SUCCESS)
				goto cleanup;
			if (getsource && get_pg_source(pg, params[c]) !=
			    SCF_SUCCESS)
				goto cleanup;
		} else if (scf_error() == SCF_ERROR_NOT_FOUND ||
		    scf_error() == SCF_ERROR_DELETED) {
			/* keep driving */
			/*EMPTY*/
		} else if (check_scf_error(scf_error(), errs_1)) {
			goto cleanup;
		}
		++c;
	}

	if (not_found) {
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		goto cleanup;
	}

	assert(c == nvl_num);

	if (nvlist_add_nvlist_array(nvl, SCF_NOTIFY_PARAMS, params, nvl_num) !=
	    0 || nvlist_add_uint32(nvl, SCF_NOTIFY_NAME_VERSION,
	    SCF_NOTIFY_PARAMS_VERSION) != 0) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	r = SCF_SUCCESS;

cleanup:
	scf_pg_destroy(pg);
	scf_instance_destroy(i);
	scf_instance_destroy(g);
	scf_service_destroy(s);
	scf_handle_destroy(h);
	if (params != NULL)
		for (c = 0; c < nvl_num; ++c)
			nvlist_free(params[c]);
	free(params);

	return (r);
}

/*
 * Specialized function to get fma notification parameters
 *
 * return SCF_SUCCESS or SCF_FAILED on
 *	SCF_ERROR_BACKEND_ACCESS
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_INTERNAL
 *	SCF_ERROR_INVALID_ARGUMENT
 *	SCF_ERROR_NO_MEMORY
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_FOUND
 *	SCF_ERROR_PERMISSION_DENIED
 */
int
_scf_get_fma_notify_params(const char *class, nvlist_t *nvl, int getsource)
{
	scf_handle_t		*h = _scf_handle_create_and_bind(SCF_VERSION);
	scf_error_t		scf_e = scf_error();
	scf_instance_t		*i = scf_instance_create(h);
	scf_propertygroup_t	*pg = scf_pg_create(h);
	int r = SCF_FAILED;
	nvlist_t *params = NULL;
	char *pgname = NULL;

	if (h == NULL) {
		/*
		 * use saved error if _scf_handle_create_and_bind() fails
		 */
		(void) scf_set_error(scf_e);
		goto cleanup;
	}
	if (i == NULL || pg == NULL)
		goto cleanup;

	if (scf_handle_decode_fmri(h, SCF_NOTIFY_PARAMS_INST, NULL, NULL, i,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) != SCF_SUCCESS) {
		if (check_scf_error(scf_error(), errs_1)) {
			goto cleanup;
		}
	}

	if ((pgname = class_to_pgname(class)) == NULL)
		goto cleanup;

	while (get_pg(NULL, i, pgname, pg, 0) != 0) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			char *p = strrchr(pgname, '.');

			if (p != NULL) {
				*p = ',';
				/*
				 * since the resulting string is shorter,
				 * there is no risk of buffer overflow
				 */
				(void) strcpy(p + 1, SCF_NOTIFY_PG_POSTFIX);
				continue;
			}
		}

		if (check_scf_error(scf_error(), errs_1)) {
			goto cleanup;
		}
	}

	if (nvlist_alloc(&params, NV_UNIQUE_NAME, 0) != 0) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	if (_scf_notify_get_params(pg, params) != SCF_SUCCESS)
		goto cleanup;

	if (getsource && get_pg_source(pg, params) != SCF_SUCCESS)
		goto cleanup;

	if (nvlist_add_nvlist_array(nvl, SCF_NOTIFY_PARAMS, &params, 1) != 0 ||
	    nvlist_add_uint32(nvl, SCF_NOTIFY_NAME_VERSION,
	    SCF_NOTIFY_PARAMS_VERSION) != 0) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto cleanup;
	}

	r = SCF_SUCCESS;

cleanup:
	nvlist_free(params);
	scf_pg_destroy(pg);
	scf_instance_destroy(i);
	scf_handle_destroy(h);
	free(pgname);

	return (r);
}

/*
 * Retrieve the notification parameters for the Event described in the
 * input nvlist_t nvl.
 * The function will allocate an nvlist_t to store the notification
 * parameters. The notification parameters in the output nvlist will have
 * the following format:
 *
 *        version (uint32_t)
 *        SCF_NOTIFY_PARAMS (array of embedded nvlists)
 *             (start of notify-params[0])
 *                  tset (int32_t)
 *                  <mechanism-name> (embedded nvlist)
 *                       <parameter-name> <parameter-type>
 *                       ...
 *                  (end <mechanism-name>)
 *                  ...
 *             (end of notify-params[0])
 *             ...
 *
 * return SCF_SUCCESS or SCF_FAILED on
 *	SCF_ERROR_BACKEND_ACCESS
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_INTERNAL
 *	SCF_ERROR_INVALID_ARGUMENT
 *	SCF_ERROR_NO_MEMORY
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_FOUND
 *	SCF_ERROR_PERMISSION_DENIED
 */
int
smf_notify_get_params(nvlist_t **params, nvlist_t *nvl)
{
	char *class;
	char *from;	/* from state */
	char *to;	/* to state */
	nvlist_t *attr;
	char *fmri;
	int32_t tset = 0;
	int r = SCF_FAILED;

	if (params == NULL || nvlist_lookup_string(nvl, "class", &class) != 0) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (r);
	}
	if (nvlist_alloc(params, NV_UNIQUE_NAME, 0) != 0) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (r);
	}

	if (is_svc_stn(class)) {
		if (nvlist_lookup_nvlist(nvl, "attr", &attr) != 0 ||
		    nvlist_lookup_string(attr, "svc-string", &fmri) != 0 ||
		    nvlist_lookup_string(attr, "from-state", &from) != 0 ||
		    nvlist_lookup_string(attr, "to-state", &to) != 0) {
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
			goto cleanup;
		}

		tset = SCF_TRANS(smf_state_from_string(from),
		    smf_state_from_string(to));
		if (!SCF_TRANS_VALID(tset)) {
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
			goto cleanup;
		}
		tset |= class_to_transition(class);

		r = _scf_get_svc_notify_params(fmri, *params, tset, 0, 1);
	} else {
		r = _scf_get_fma_notify_params(class, *params, 0);
	}

cleanup:
	if (r == SCF_FAILED) {
		nvlist_free(*params);
		*params = NULL;
	}

	return (r);
}

/*
 * return SCF_SUCCESS or SCF_FAILED on
 *	SCF_ERROR_BACKEND_ACCESS
 *	SCF_ERROR_BACKEND_READONLY
 *	SCF_ERROR_CONNECTION_BROKEN
 *	SCF_ERROR_DELETED
 *	SCF_ERROR_INTERNAL
 *	SCF_ERROR_INVALID_ARGUMENT
 *	SCF_ERROR_NO_MEMORY
 *	SCF_ERROR_NO_RESOURCES
 *	SCF_ERROR_NOT_FOUND
 *	SCF_ERROR_PERMISSION_DENIED
 */
int
smf_notify_del_params(const char *class, const char *fmri, int32_t tset)
{
	scf_handle_t		*h = _scf_handle_create_and_bind(SCF_VERSION);
	scf_error_t		scf_e = scf_error();
	scf_service_t		*s = scf_service_create(h);
	scf_instance_t		*i = scf_instance_create(h);
	scf_propertygroup_t	*pg = scf_pg_create(h);
	int r = SCF_FAILED;
	char *pgname = NULL;
	int j;

	if (class == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto cleanup;
	}

	if (h == NULL) {
		/*
		 * use saved error if _scf_handle_create_and_bind() fails
		 */
		(void) scf_set_error(scf_e);
		goto cleanup;
	}
	if (s == NULL || i == NULL || pg == NULL)
		goto cleanup;

	if (is_svc_stn(class)) {
		tset |= class_to_transition(class);

		if (!SCF_TRANS_VALID(tset) || fmri == NULL) {
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
			goto cleanup;
		}

		if (decode_fmri(fmri, h, &s, &i) != SCF_SUCCESS) {
			if (scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED)
				(void) scf_set_error(
				    SCF_ERROR_INVALID_ARGUMENT);
			if (check_scf_error(scf_error(), errs_1)) {
				goto cleanup;
			}
		}

		for (j = 0; st_pgnames[j].st_pgname != NULL; ++j) {
			/* if this transition is not in the tset, continue */
			if (!(tset & st_pgnames[j].st_state))
				continue;

			if (del_pg(s, i, st_pgnames[j].st_pgname, pg) !=
			    SCF_SUCCESS &&
			    scf_error() != SCF_ERROR_DELETED &&
			    scf_error() != SCF_ERROR_NOT_FOUND) {
				if (check_scf_error(scf_error(),
				    errs_1)) {
					goto cleanup;
				}
			}
		}
		if (s == NULL) {
			/* We only need to refresh the instance */
			if (_smf_refresh_instance_i(i) != 0 &&
			    check_scf_error(scf_error(), errs_1))
				goto cleanup;
		} else {
			/* We have to refresh all instances in the service */
			if (_smf_refresh_all_instances(s) != 0 &&
			    check_scf_error(scf_error(), errs_1))
				goto cleanup;
		}
	} else {
		if ((pgname = class_to_pgname(class)) == NULL)
			goto cleanup;

		if (scf_handle_decode_fmri(h, SCF_NOTIFY_PARAMS_INST, NULL,
		    NULL, i, NULL, NULL, SCF_DECODE_FMRI_EXACT) != SCF_SUCCESS)
			goto cleanup;

		if (del_pg(NULL, i, pgname, pg) != SCF_SUCCESS &&
		    scf_error() != SCF_ERROR_DELETED &&
		    scf_error() != SCF_ERROR_NOT_FOUND) {
			if (check_scf_error(scf_error(), errs_1)) {
				goto cleanup;
			}
		}

		if (_smf_refresh_instance_i(i) != 0 &&
		    check_scf_error(scf_error(), errs_1))
			goto cleanup;
	}


	r = SCF_SUCCESS;

cleanup:
	scf_pg_destroy(pg);
	scf_instance_destroy(i);
	scf_service_destroy(s);
	scf_handle_destroy(h);
	free(pgname);

	return (r);
}
