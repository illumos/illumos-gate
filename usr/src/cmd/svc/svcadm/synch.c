/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * synchronous svcadm logic
 */

#include <locale.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>


/*
 * Definitions from svcadm.c.
 */
extern scf_handle_t *h;
extern ssize_t max_scf_fmri_sz;

extern void do_scfdie(int) __NORETURN;
extern int inst_get_state(scf_instance_t *, char *, const char *,
    scf_propertygroup_t **);
extern ssize_t get_astring_prop(const scf_propertygroup_t *, const char *,
    scf_property_t *, scf_value_t *, char *, size_t);
extern int get_bool_prop(scf_propertygroup_t *, const char *, uint8_t *);

#define	scfdie()	do_scfdie(__LINE__)

int has_potential(scf_instance_t *, int);

/*
 * Determines if the specified instance is enabled, composing the
 * general and general_ovr property groups.  For simplicity, we map
 * most errors to "not enabled".
 */
int
is_enabled(scf_instance_t *inst)
{
	scf_propertygroup_t *pg;
	uint8_t bp;

	if ((pg = scf_pg_create(h)) == NULL)
		scfdie();

	if (scf_instance_get_pg(inst, SCF_PG_GENERAL_OVR, pg) == 0 &&
	    get_bool_prop(pg, SCF_PROPERTY_ENABLED, &bp) == 0) {
		scf_pg_destroy(pg);
		return (bp);
	}

	if (scf_instance_get_pg(inst, SCF_PG_GENERAL, pg) == 0 &&
	    get_bool_prop(pg, SCF_PROPERTY_ENABLED, &bp) == 0) {
		scf_pg_destroy(pg);
		return (bp);
	}

	scf_pg_destroy(pg);
	return (B_FALSE);
}

/*
 * Reads an astring property from a property group.  If the named
 * property doesn't exist, returns NULL.  The result of a successful
 * call should be freed.
 */
static char *
read_astring_prop(scf_propertygroup_t *pg, scf_value_t *val,
    scf_property_t *prop, const char *name)
{
	char *value;
	size_t value_sz;

	if (scf_pg_get_property(pg, name, prop) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			return (NULL);
		default:
			scfdie();
		}
	}

	if (scf_property_get_value(prop, val) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			return (NULL);
		default:
			scfdie();
		}
	}

	value_sz = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	if ((value = malloc(value_sz)) == NULL)
		scfdie();

	if (scf_value_get_astring(val, value, value_sz) <= 0) {
		free(value);
		return (NULL);
	}

	return (value);
}

/*
 * Creates and returns an scf_iter for the values of the named
 * multi-value property.  Returns NULL on failure.
 */
static scf_iter_t *
prop_walk_init(scf_propertygroup_t *pg, const char *name)
{
	scf_iter_t *iter;
	scf_property_t *prop;

	if ((iter = scf_iter_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL)
		scfdie();

	if (scf_pg_get_property(pg, name, prop) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			goto error;
		default:
			scfdie();
		}
	}

	if (scf_iter_property_values(iter, prop) != 0) {
		if (scf_error() != SCF_ERROR_DELETED)
			scfdie();
		goto error;
	}

	scf_property_destroy(prop);
	return (iter);
error:
	scf_property_destroy(prop);
	scf_iter_destroy(iter);
	return (NULL);
}

/*
 * Reads the next value from the multi-value property using the
 * scf_iter obtained by prop_walk_init, and places it in the buffer
 * pointed to by fmri.  Returns -1 on failure, 0 when done, and non-0
 * when returning a value.
 */
static int
prop_walk_step(scf_iter_t *iter, char *fmri, size_t len)
{
	int r;
	scf_value_t *val;

	if ((val = scf_value_create(h)) == NULL)
		scfdie();

	r = scf_iter_next_value(iter, val);
	if (r == 0)
		goto out;
	if (r == -1) {
		if (scf_error() != SCF_ERROR_DELETED)
			scfdie();
		goto out;
	}
	if (scf_value_get_astring(val, fmri, len) <= 0) {
		r = -1;
		goto out;
	}

out:
	scf_value_destroy(val);
	return (r);
}

/*
 * Determines if a file dependency is satisfied, taking into account
 * whether it is an exclusion dependency or not.  If we can't access
 * the file, we err on the side of caution and assume the dependency
 * isn't satisfied.
 */
static int
file_has_potential(char *fmri, int exclude)
{
	const char *path;
	struct stat st;

	int good = exclude ? B_FALSE : B_TRUE;

	if (scf_parse_file_fmri(fmri, NULL, &path) != 0)
		return (good);

	if (stat(path, &st) == 0)
		return (good);

	if (errno == EACCES) {
		uu_warn(gettext("Unable to access \"%s\".\n"), path);
		return (B_FALSE);
	}

	return (!good);
}

/*
 * Determines if a dependency on a service instance is satisfiable.
 * Returns 0 if not, 1 if it is, or 2 if it is an optional or exclude
 * dependency and the service only "weakly" satisfies (i.e. is disabled
 * or is in maintenance state).
 */
static int
inst_has_potential(scf_instance_t *inst, int enabled, int optional, int exclude)
{
	char state[MAX_SCF_STATE_STRING_SZ];

	if (!enabled)
		return ((optional || exclude) ? 2 : 0);

	/*
	 * Normally we would return a positive value on failure;
	 * relying on startd to place the service in maintenance.  But
	 * if we can't read a service's state, we have to assume it is
	 * out to lunch.
	 */
	if (inst_get_state(inst, state, NULL, NULL) != 0)
		return (0);

	/*
	 * Optional dependencies which are offline always have a possibility of
	 * coming online.
	 */
	if (optional && strcmp(state, SCF_STATE_STRING_OFFLINE) == 0)
		return (2);

	if (strcmp(state, SCF_STATE_STRING_MAINT) == 0) {
		/*
		 * Enabled services in maintenance state satisfy
		 * optional-all dependencies.
		 */
		return ((optional || exclude) ? 2 : 0);
	}

	/*
	 * We're enabled and not in maintenance.
	 */
	if (exclude)
		return (0);

	if (strcmp(state, SCF_STATE_STRING_ONLINE) == 0 ||
	    strcmp(state, SCF_STATE_STRING_DEGRADED) == 0)
		return (1);

	return (has_potential(inst, B_FALSE));
}

/*
 * Determines if a dependency on an fmri is satisfiable, handling the
 * separate cases for file, service, and instance fmris.  Returns false
 * if not, or true if it is.  Takes into account if the dependency is
 * an optional or exclusive one.
 */
static int
fmri_has_potential(char *fmri, int isfile, int optional, int exclude,
    int restarter)
{
	scf_instance_t *inst;
	scf_service_t *svc;
	scf_iter_t *iter;
	int good = exclude ? B_FALSE : B_TRUE;
	int enabled;
	int r, result;
	int optbad;

	assert(!optional || !exclude);

	if (isfile)
		return (file_has_potential(fmri, exclude));

	if ((inst = scf_instance_create(h)) == NULL ||
	    (svc = scf_service_create(h)) == NULL ||
	    (iter = scf_iter_create(h)) == NULL)
		scfdie();

	if (scf_handle_decode_fmri(h, fmri, NULL, NULL, inst, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) == 0) {
		enabled = is_enabled(inst);
		result =
		    (inst_has_potential(inst, enabled, optional, exclude) != 0);
		goto out;
	}

	if (scf_handle_decode_fmri(h, fmri, NULL, svc, NULL, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) != 0) {
		/*
		 * If we are checking a restarter dependency, a bad
		 * or nonexistent service will never be noticed.
		 */
		result = restarter ? B_FALSE : good;
		goto out;
	}

	if (scf_iter_service_instances(iter, svc) != 0) {
		if (scf_error() != SCF_ERROR_DELETED)
			scfdie();
		result = good;
		goto out;
	}

	optbad = 0;
	for (;;) {
		r = scf_iter_next_instance(iter, inst);
		if (r == 0) {
			result = exclude || (optional && !optbad);
			goto out;
		}
		if (r == -1) {
			if (scf_error() != SCF_ERROR_DELETED)
				scfdie();
			result = good;
			goto out;
		}

		enabled = is_enabled(inst);
		r = inst_has_potential(inst, enabled, optional, exclude);

		/*
		 * Exclusion dependencies over services map to
		 * require-none for its instances.
		 */
		if (exclude)
			r = (r == 0);

		if (r == 1) {
			/*
			 * Remember, if this is an exclusion dependency
			 * (which means we are here because there
			 * exists an instance which wasn't satisfiable
			 * in that regard), good means bad.
			 */
			result = good;
			goto out;
		}

		if (optional && r == 0)
			optbad = 1;
	}

out:
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
	scf_iter_destroy(iter);
	return (result);
}

static int
eval_require_any(scf_iter_t *iter, char *value, size_t value_sz, int isfile)
{
	int r, empty = B_TRUE;

	for (;;) {
		/*
		 * For reasons unknown, an empty require_any dependency
		 * group is considered by startd to be satisfied.
		 * This insanity fortunately doesn't extend to
		 * dependencies on services with no instances.
		 */
		if ((r = prop_walk_step(iter, value, value_sz)) <= 0)
			return ((r == 0 && empty) ? B_TRUE : r);
		if (fmri_has_potential(value, isfile, B_FALSE, B_FALSE,
		    B_FALSE))
			return (1);
		empty = B_FALSE;
	}
}

static int
eval_all(scf_iter_t *iter, char *value, size_t value_sz,
    int isfile, int optional, int exclude)
{
	int r;

	for (;;) {
		if ((r = prop_walk_step(iter, value, value_sz)) <= 0)
			return ((r == 0) ? 1 : r);
		if (!fmri_has_potential(value, isfile, optional, exclude,
		    B_FALSE))
			return (0);
	}
}

static int
eval_require_all(scf_iter_t *iter, char *value, size_t value_sz, int isfile)
{
	return (eval_all(iter, value, value_sz, isfile, B_FALSE, B_FALSE));
}

static int
eval_optional_all(scf_iter_t *iter, char *value, size_t value_sz, int isfile)
{
	return (eval_all(iter, value, value_sz, isfile, B_TRUE, B_FALSE));
}

static int
eval_exclude_all(scf_iter_t *iter, char *value, size_t value_sz, int isfile)
{
	return (eval_all(iter, value, value_sz, isfile, B_FALSE, B_TRUE));
}

/*
 * Examines the state and health of an instance's restarter and
 * dependencies, and determines the impact of both on the instance's
 * ability to be brought on line.  A true return value indicates that
 * instance appears to be a likely candidate for the online club.
 * False indicates that there is no hope for the instance.
 */
int
has_potential(scf_instance_t *inst, int restarter_only)
{
	scf_snapshot_t *snap;
	scf_iter_t *iter, *viter = NULL;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	char *type = NULL, *grouping = NULL;
	char *value;
	size_t value_sz;
	int result = B_TRUE, r;
	int isfile;

	value_sz = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	if ((iter = scf_iter_create(h)) == NULL ||
	    (snap = scf_snapshot_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (value = malloc(value_sz)) == NULL)
		scfdie();

	/*
	 * First we check our restarter as an implicit dependency.
	 */
	if (scf_instance_get_pg_composed(inst, NULL, SCF_PG_GENERAL, pg) != 0)
		scfdie();

	r = get_astring_prop(pg, SCF_PROPERTY_RESTARTER, prop, val, value,
	    value_sz);
	if (r == -ENOENT) {
		(void) strlcpy(value, SCF_SERVICE_STARTD, value_sz);
	} else if (r < 0 || r > max_scf_fmri_sz) {
		/*
		 * Normally we would return true and let the restarter
		 * tell our caller there is a problem by changing the
		 * instance's state, but that's not going to happen if
		 * the restarter is invalid.
		 */
		result = B_FALSE;
		goto out;
	}

	if (!fmri_has_potential(value, B_FALSE, B_FALSE, B_FALSE, B_TRUE)) {
		result = B_FALSE;
		goto out;
	}

	if (restarter_only)
		goto out;

	/*
	 * Now we check explicit dependencies.
	 */
	if (scf_instance_get_snapshot(inst, "running", snap) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();
		scf_snapshot_destroy(snap);
		snap = NULL;
	}

	if (scf_iter_instance_pgs_typed_composed(iter, inst, snap,
	    SCF_GROUP_DEPENDENCY) != 0) {
		if (scf_error() != SCF_ERROR_DELETED)
			scfdie();
		goto out;
	}

	for (;;) {
		r = scf_iter_next_pg(iter, pg);
		if (r == 0)
			break;
		if (r == -1) {
			if (scf_error() != SCF_ERROR_DELETED)
				scfdie();
			goto out;
		}

		if ((grouping = read_astring_prop(pg, val, prop,
		    SCF_PROPERTY_GROUPING)) == NULL)
			goto out;

		if ((type = read_astring_prop(pg, val, prop,
		    SCF_PROPERTY_TYPE)) == NULL)
			goto out;

		if (strcmp(type, "path") == 0) {
			isfile = B_TRUE;
		} else if (strcmp(type, "service") == 0) {
			isfile = B_FALSE;
		} else {
			free(type);
			goto out;
		}
		free(type);

		if ((viter = prop_walk_init(pg, SCF_PROPERTY_ENTITIES)) == NULL)
			goto out;

		if (strcmp(grouping, SCF_DEP_REQUIRE_ALL) == 0) {
			r = eval_require_all(viter, value, value_sz, isfile);
		} else if (strcmp(grouping, SCF_DEP_REQUIRE_ANY) == 0) {
			r = eval_require_any(viter, value, value_sz, isfile);
		} else if (strcmp(grouping, SCF_DEP_EXCLUDE_ALL) == 0) {
			r = eval_exclude_all(viter, value, value_sz, isfile);
		} else if (strcmp(grouping, SCF_DEP_OPTIONAL_ALL) == 0) {
			r = eval_optional_all(viter, value, value_sz, isfile);
		} else {
			scf_iter_destroy(viter);
			free(grouping);
			grouping = NULL;
			goto out;
		}

		scf_iter_destroy(viter);
		free(grouping);
		grouping = NULL;

		if (r == 0) {
			result = B_FALSE;
			goto out;
		} else if (r == -1) {
			goto out;
		}
	}

out:
	free(value);
	scf_property_destroy(prop);
	scf_value_destroy(val);
	scf_pg_destroy(pg);
	if (snap != NULL)
		scf_snapshot_destroy(snap);
	if (grouping != NULL)
		free(grouping);
	scf_iter_destroy(iter);
	return (result);
}
