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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include "libscf_impl.h"

#include <assert.h>
#include <libuutil.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <errno.h>
#include <libgen.h>
#include <assert.h>
#include "midlevel_impl.h"
#include "lowlevel_impl.h"

#ifndef NDEBUG
#define	bad_error(func, err)	{					\
	uu_warn("%s:%d: %s failed with unexpected error %d.  Aborting.\n", \
	    __FILE__, __LINE__, func, err);				\
	abort();							\
}
#else
#define	bad_error(func, err)	abort()
#endif

/* Path to speedy files area must end with a slash */
#define	SMF_SPEEDY_FILES_PATH		"/etc/svc/volatile/"

void
scf_simple_handle_destroy(scf_simple_handle_t *simple_h)
{
	if (simple_h == NULL)
		return;

	scf_pg_destroy(simple_h->running_pg);
	scf_pg_destroy(simple_h->editing_pg);
	scf_snapshot_destroy(simple_h->snap);
	scf_instance_destroy(simple_h->inst);
	scf_handle_destroy(simple_h->h);
	uu_free(simple_h);
}

/*
 * Given a base service FMRI and the names of a property group and property,
 * assemble_fmri() merges them into a property FMRI.  Note that if the base
 * FMRI is NULL, assemble_fmri() gets the base FMRI from scf_myname().
 */

static char *
assemble_fmri(scf_handle_t *h, const char *base, const char *pg,
    const char *prop)
{
	size_t	fmri_sz, pglen;
	ssize_t baselen;
	char	*fmri_buf;

	if (prop == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (NULL);
	}

	if (pg == NULL)
		pglen = strlen(SCF_PG_APP_DEFAULT);
	else
		pglen = strlen(pg);

	if (base == NULL) {
		if ((baselen = scf_myname(h, NULL, 0)) == -1)
			return (NULL);
	} else {
		baselen = strlen(base);
	}

	fmri_sz = baselen + sizeof (SCF_FMRI_PROPERTYGRP_PREFIX) - 1 +
	    pglen + sizeof (SCF_FMRI_PROPERTY_PREFIX) - 1 +
	    strlen(prop) + 1;

	if ((fmri_buf = malloc(fmri_sz)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	if (base == NULL) {
		if (scf_myname(h, fmri_buf, fmri_sz) == -1) {
			free(fmri_buf);
			return (NULL);
		}
	} else {
		(void) strcpy(fmri_buf, base);
	}

	(void) strcat(fmri_buf, SCF_FMRI_PROPERTYGRP_PREFIX);

	if (pg == NULL)
		(void) strcat(fmri_buf, SCF_PG_APP_DEFAULT);
	else
		(void) strcat(fmri_buf, pg);

	(void) strcat(fmri_buf, SCF_FMRI_PROPERTY_PREFIX);
	(void) strcat(fmri_buf, prop);
	return (fmri_buf);
}

/*
 * Given a property, this function allocates and fills an scf_simple_prop_t
 * with the data it contains.
 */

static scf_simple_prop_t *
fill_prop(scf_property_t *prop, const char *pgname, const char *propname,
    scf_handle_t *h)
{
	scf_simple_prop_t 		*ret;
	scf_iter_t 			*iter;
	scf_value_t 			*val;
	int 				iterret, i;
	ssize_t 			valsize, numvals;
	union scf_simple_prop_val 	*vallist = NULL, *vallist_backup = NULL;

	if ((ret = malloc(sizeof (*ret))) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	ret->pr_next = NULL;
	ret->pr_pg = NULL;
	ret->pr_iter = 0;

	if (pgname == NULL)
		ret->pr_pgname = strdup(SCF_PG_APP_DEFAULT);
	else
		ret->pr_pgname = strdup(pgname);

	if (ret->pr_pgname == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		free(ret);
		return (NULL);
	}

	if ((ret->pr_propname = strdup(propname)) == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		free(ret->pr_pgname);
		free(ret);
		return (NULL);
	}

	if (scf_property_type(prop, &ret->pr_type) == -1)
		goto error3;

	if ((iter = scf_iter_create(h)) == NULL)
		goto error3;
	if ((val = scf_value_create(h)) == NULL) {
		scf_iter_destroy(iter);
		goto error3;
	}

	if (scf_iter_property_values(iter, prop) == -1)
		goto error1;

	for (numvals = 0; (iterret = scf_iter_next_value(iter, val)) == 1;
	    numvals++) {
		vallist_backup = vallist;
		if ((vallist = realloc(vallist, (numvals + 1) *
		    sizeof (*vallist))) == NULL) {
			vallist = vallist_backup;
			goto error1;
		}

		switch (ret->pr_type) {
		case SCF_TYPE_BOOLEAN:
			if (scf_value_get_boolean(val,
			    &vallist[numvals].pv_bool) == -1)
				goto error1;
			break;

		case SCF_TYPE_COUNT:
			if (scf_value_get_count(val,
			    &vallist[numvals].pv_uint) == -1)
				goto error1;
			break;

		case SCF_TYPE_INTEGER:
			if (scf_value_get_integer(val,
			    &vallist[numvals].pv_int) == -1)
				goto error1;
			break;

		case SCF_TYPE_TIME:
			if (scf_value_get_time(val,
			    &vallist[numvals].pv_time.t_sec,
			    &vallist[numvals].pv_time.t_nsec) == -1)
				goto error1;
			break;

		case SCF_TYPE_ASTRING:
			vallist[numvals].pv_str = NULL;
			if ((valsize = scf_value_get_astring(val, NULL, 0)) ==
			    -1)
				goto error1;
			if ((vallist[numvals].pv_str = malloc(valsize+1)) ==
			    NULL) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				goto error1;
			}
			if (scf_value_get_astring(val,
			    vallist[numvals].pv_str, valsize+1) == -1) {
				free(vallist[numvals].pv_str);
				goto error1;
			}
			break;

		case SCF_TYPE_USTRING:
		case SCF_TYPE_HOST:
		case SCF_TYPE_HOSTNAME:
		case SCF_TYPE_NET_ADDR:
		case SCF_TYPE_NET_ADDR_V4:
		case SCF_TYPE_NET_ADDR_V6:
		case SCF_TYPE_URI:
		case SCF_TYPE_FMRI:
			vallist[numvals].pv_str = NULL;
			if ((valsize = scf_value_get_ustring(val, NULL, 0)) ==
			    -1)
				goto error1;
			if ((vallist[numvals].pv_str = malloc(valsize+1)) ==
			    NULL) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				goto error1;
			}
			if (scf_value_get_ustring(val,
			    vallist[numvals].pv_str, valsize+1) == -1) {
				free(vallist[numvals].pv_str);
				goto error1;
			}
			break;

		case SCF_TYPE_OPAQUE:
			vallist[numvals].pv_opaque.o_value = NULL;
			if ((valsize = scf_value_get_opaque(val, NULL, 0)) ==
			    -1)
				goto error1;
			if ((vallist[numvals].pv_opaque.o_value =
			    malloc(valsize)) == NULL) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				goto error1;
			}
			vallist[numvals].pv_opaque.o_size = valsize;
			if (scf_value_get_opaque(val,
			    vallist[numvals].pv_opaque.o_value,
			    valsize) == -1) {
				free(vallist[numvals].pv_opaque.o_value);
				goto error1;
			}
			break;

		default:
			(void) scf_set_error(SCF_ERROR_INTERNAL);
			goto error1;

		}
	}

	if (iterret == -1) {
		int err = scf_error();
		if (err != SCF_ERROR_CONNECTION_BROKEN &&
		    err != SCF_ERROR_PERMISSION_DENIED)
			(void) scf_set_error(SCF_ERROR_INTERNAL);
		goto error1;
	}

	ret->pr_vallist = vallist;
	ret->pr_numvalues = numvals;

	scf_iter_destroy(iter);
	(void) scf_value_destroy(val);

	return (ret);

	/*
	 * Exit point for a successful call.  Below this line are exit points
	 * for failures at various stages during the function.
	 */

error1:
	if (vallist == NULL)
		goto error2;

	switch (ret->pr_type) {
	case SCF_TYPE_ASTRING:
	case SCF_TYPE_USTRING:
	case SCF_TYPE_HOST:
	case SCF_TYPE_HOSTNAME:
	case SCF_TYPE_NET_ADDR:
	case SCF_TYPE_NET_ADDR_V4:
	case SCF_TYPE_NET_ADDR_V6:
	case SCF_TYPE_URI:
	case SCF_TYPE_FMRI: {
		for (i = 0; i < numvals; i++) {
			free(vallist[i].pv_str);
		}
		break;
	}
	case SCF_TYPE_OPAQUE: {
		for (i = 0; i < numvals; i++) {
			free(vallist[i].pv_opaque.o_value);
		}
		break;
	}
	default:
		break;
	}

	free(vallist);

error2:
	scf_iter_destroy(iter);
	(void) scf_value_destroy(val);

error3:
	free(ret->pr_pgname);
	free(ret->pr_propname);
	free(ret);
	return (NULL);
}

/*
 * insert_app_props iterates over a property iterator, getting all the
 * properties from a property group, and adding or overwriting them into
 * a simple_app_props_t.  This is used by scf_simple_app_props_get to provide
 * service/instance composition while filling the app_props_t.
 * insert_app_props iterates over a single property group.
 */

static int
insert_app_props(scf_iter_t *propiter, char *pgname, char *propname, struct
    scf_simple_pg *thispg, scf_property_t *prop, size_t namelen,
    scf_handle_t *h)
{
	scf_simple_prop_t	*thisprop, *prevprop, *newprop;
	uint8_t			found;
	int			propiter_ret;

	while ((propiter_ret = scf_iter_next_property(propiter, prop)) == 1) {

		if (scf_property_get_name(prop, propname, namelen) < 0) {
			if (scf_error() == SCF_ERROR_NOT_SET)
				(void) scf_set_error(SCF_ERROR_INTERNAL);
			return (-1);
		}

		thisprop = thispg->pg_proplist;
		prevprop = thispg->pg_proplist;
		found = 0;

		while ((thisprop != NULL) && (!found)) {
			if (strcmp(thisprop->pr_propname, propname) == 0) {
				found = 1;
				if ((newprop = fill_prop(prop, pgname,
				    propname, h)) == NULL)
					return (-1);

				if (thisprop == thispg->pg_proplist)
					thispg->pg_proplist = newprop;
				else
					prevprop->pr_next = newprop;

				newprop->pr_pg = thispg;
				newprop->pr_next = thisprop->pr_next;
				scf_simple_prop_free(thisprop);
				thisprop = NULL;
			} else {
				if (thisprop != thispg->pg_proplist)
					prevprop = prevprop->pr_next;
				thisprop = thisprop->pr_next;
			}
		}

		if (!found) {
			if ((newprop = fill_prop(prop, pgname, propname, h)) ==
			    NULL)
				return (-1);

			if (thispg->pg_proplist == NULL)
				thispg->pg_proplist = newprop;
			else
				prevprop->pr_next = newprop;

			newprop->pr_pg = thispg;
		}
	}

	if (propiter_ret == -1) {
		if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
			(void) scf_set_error(SCF_ERROR_INTERNAL);
		return (-1);
	}

	return (0);
}


/*
 * Sets up e in tx to set pname's values.  Returns 0 on success or -1 on
 * failure, with scf_error() set to
 *   SCF_ERROR_HANDLE_MISMATCH - tx & e are derived from different handles
 *   SCF_ERROR_INVALID_ARGUMENT - pname or ty are invalid
 *   SCF_ERROR_NOT_BOUND - handle is not bound
 *   SCF_ERROR_CONNECTION_BROKEN - connection was broken
 *   SCF_ERROR_NOT_SET - tx has not been started
 *   SCF_ERROR_DELETED - the pg tx was started on was deleted
 */
static int
transaction_property_set(scf_transaction_t *tx, scf_transaction_entry_t *e,
    const char *pname, scf_type_t ty)
{
	for (;;) {
		if (scf_transaction_property_change_type(tx, e, pname, ty) == 0)
			return (0);

		switch (scf_error()) {
		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_DELETED:
		default:
			return (-1);

		case SCF_ERROR_NOT_FOUND:
			break;
		}

		if (scf_transaction_property_new(tx, e, pname, ty) == 0)
			return (0);

		switch (scf_error()) {
		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_DELETED:
		default:
			return (-1);

		case SCF_ERROR_EXISTS:
			break;
		}
	}
}

static int
get_inst_enabled(const scf_instance_t *inst, const char *pgname)
{
	scf_propertygroup_t 	*gpg = NULL;
	scf_property_t 		*eprop = NULL;
	scf_value_t 		*v = NULL;
	scf_handle_t		*h = NULL;
	uint8_t			enabled;
	int			ret = -1;

	if ((h = scf_instance_handle(inst)) == NULL)
		return (-1);

	if ((gpg = scf_pg_create(h)) == NULL ||
	    (eprop = scf_property_create(h)) == NULL ||
	    (v = scf_value_create(h)) == NULL)
		goto out;

	if (scf_instance_get_pg(inst, pgname, gpg) ||
	    scf_pg_get_property(gpg, SCF_PROPERTY_ENABLED, eprop) ||
	    scf_property_get_value(eprop, v) ||
	    scf_value_get_boolean(v, &enabled))
		goto out;
	ret = enabled;

out:
	scf_pg_destroy(gpg);
	scf_property_destroy(eprop);
	scf_value_destroy(v);
	return (ret);
}

/*
 * set_inst_enabled() is a "master" enable/disable call that takes the
 * instance and the desired state for the enabled bit in the instance's
 * named property group.  If the group doesn't exist, it's created with the
 * given flags.  Called by smf_{dis,en}able_instance().
 */
static int
set_inst_enabled(const scf_instance_t *inst, uint8_t desired,
    const char *pgname, uint32_t pgflags)
{
	scf_transaction_t 	*tx = NULL;
	scf_transaction_entry_t *ent = NULL;
	scf_propertygroup_t 	*gpg = NULL;
	scf_property_t 		*eprop = NULL;
	scf_value_t 		*v = NULL;
	scf_handle_t		*h = NULL;
	int 			ret = -1;
	int			committed;
	uint8_t			b;

	if ((h = scf_instance_handle(inst)) == NULL)
		return (-1);

	if ((gpg = scf_pg_create(h)) == NULL ||
	    (eprop = scf_property_create(h)) == NULL ||
	    (v = scf_value_create(h)) == NULL ||
	    (tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL)
		goto out;

general_pg_get:
	if (scf_instance_get_pg(inst, SCF_PG_GENERAL, gpg) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			goto out;

		if (scf_instance_add_pg(inst, SCF_PG_GENERAL,
		    SCF_GROUP_FRAMEWORK, SCF_PG_GENERAL_FLAGS, gpg) == -1) {
			if (scf_error() != SCF_ERROR_EXISTS)
				goto out;
			goto general_pg_get;
		}
	}

	if (strcmp(pgname, SCF_PG_GENERAL) != 0) {
get:
		if (scf_instance_get_pg(inst, pgname, gpg) == -1) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				goto out;

			if (scf_instance_add_pg(inst, pgname,
			    SCF_GROUP_FRAMEWORK, pgflags, gpg) == -1) {
				if (scf_error() != SCF_ERROR_EXISTS)
					goto out;
				goto get;
			}
		}
	}

	if (scf_pg_get_property(gpg, SCF_PROPERTY_ENABLED, eprop) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			goto out;
		else
			goto set;
	}

	/*
	 * If it's already set the way we want, forgo the transaction.
	 */
	if (scf_property_get_value(eprop, v) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_NOT_FOUND:
			/* Misconfigured, so set anyway. */
			goto set;

		default:
			goto out;
		}
	}
	if (scf_value_get_boolean(v, &b) == -1) {
		if (scf_error() != SCF_ERROR_TYPE_MISMATCH)
			goto out;
		goto set;
	}
	if (b == desired) {
		ret = 0;
		goto out;
	}

set:
	do {
		if (scf_transaction_start(tx, gpg) == -1)
			goto out;

		if (transaction_property_set(tx, ent, SCF_PROPERTY_ENABLED,
		    SCF_TYPE_BOOLEAN) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_DELETED:
			default:
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
				bad_error("transaction_property_set",
				    scf_error());
			}
		}

		scf_value_set_boolean(v, desired);
		if (scf_entry_add_value(ent, v) == -1)
			goto out;

		committed = scf_transaction_commit(tx);
		if (committed == -1)
			goto out;

		scf_transaction_reset(tx);

		if (committed == 0) { /* out-of-sync */
			if (scf_pg_update(gpg) == -1)
				goto out;
		}
	} while (committed == 0);

	ret = 0;

out:
	scf_value_destroy(v);
	scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_property_destroy(eprop);
	scf_pg_destroy(gpg);

	return (ret);
}

static int
delete_inst_enabled(const scf_instance_t *inst, const char *pgname)
{
	scf_transaction_t 	*tx = NULL;
	scf_transaction_entry_t *ent = NULL;
	scf_propertygroup_t 	*gpg = NULL;
	scf_handle_t		*h = NULL;
	int			ret = -1;
	int			committed;

	if ((h = scf_instance_handle(inst)) == NULL)
		return (-1);

	if ((gpg = scf_pg_create(h)) == NULL ||
	    (tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL)
		goto out;

	if (scf_instance_get_pg(inst, pgname, gpg) != 0)
		goto error;
	do {
		if (scf_transaction_start(tx, gpg) == -1 ||
		    scf_transaction_property_delete(tx, ent,
		    SCF_PROPERTY_ENABLED) == -1 ||
		    (committed = scf_transaction_commit(tx)) == -1)
			goto error;

		scf_transaction_reset(tx);

		if (committed == 0 && scf_pg_update(gpg) == -1)
			goto error;
	} while (committed == 0);

	ret = 0;
	goto out;

error:
	switch (scf_error()) {
	case SCF_ERROR_DELETED:
	case SCF_ERROR_NOT_FOUND:
		/* success */
		ret = 0;
	}

out:
	scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_pg_destroy(gpg);

	return (ret);
}

/*
 * Returns 0 on success or -1 on failure.  On failure leaves scf_error() set to
 *   SCF_ERROR_HANDLE_DESTROYED - inst's handle has been destroyed
 *   SCF_ERROR_NOT_BOUND - inst's handle is not bound
 *   SCF_ERROR_CONNECTION_BROKEN - the repository connection was broken
 *   SCF_ERROR_NOT_SET - inst is not set
 *   SCF_ERROR_DELETED - inst was deleted
 *   SCF_ERROR_PERMISSION_DENIED
 *   SCF_ERROR_BACKEND_ACCESS
 *   SCF_ERROR_BACKEND_READONLY
 */
static int
set_inst_action_inst(scf_instance_t *inst, const char *action)
{
	scf_handle_t			*h;
	scf_transaction_t		*tx = NULL;
	scf_transaction_entry_t		*ent = NULL;
	scf_propertygroup_t		*pg = NULL;
	scf_property_t			*prop = NULL;
	scf_value_t			*v = NULL;
	int				trans, ret = -1;
	int64_t				t;
	hrtime_t			timestamp;

	if ((h = scf_instance_handle(inst)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (v = scf_value_create(h)) == NULL ||
	    (tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL)
		goto out;

get:
	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER_ACTIONS, pg) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_DELETED:
		default:
			goto out;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
			bad_error("scf_instance_get_pg", scf_error());
		}

		/* Try creating the restarter_actions property group. */
add:
		if (scf_instance_add_pg(inst, SCF_PG_RESTARTER_ACTIONS,
		    SCF_PG_RESTARTER_ACTIONS_TYPE,
		    SCF_PG_RESTARTER_ACTIONS_FLAGS, pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_DELETED:
			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_BACKEND_ACCESS:
			case SCF_ERROR_BACKEND_READONLY:
			default:
				goto out;

			case SCF_ERROR_EXISTS:
				goto get;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
				bad_error("scf_instance_add_pg", scf_error());
			}
		}
	}

	for (;;) {
		timestamp = gethrtime();

		if (scf_pg_get_property(pg, action, prop) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				goto out;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_NOT_FOUND:
				break;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
				bad_error("scf_pg_get_property", scf_error());
			}
		} else if (scf_property_get_value(prop, v) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				goto out;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_CONSTRAINT_VIOLATED:
			case SCF_ERROR_NOT_FOUND:
				break;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
				bad_error("scf_property_get_value",
				    scf_error());
			}
		} else if (scf_value_get_integer(v, &t) != 0) {
			bad_error("scf_value_get_integer", scf_error());
		} else if (t > timestamp) {
			break;
		}

		if (scf_transaction_start(tx, pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_BACKEND_ACCESS:
			case SCF_ERROR_BACKEND_READONLY:
			default:
				goto out;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_IN_USE:
				bad_error("scf_transaction_start", scf_error());
			}
		}

		if (transaction_property_set(tx, ent, action,
		    SCF_TYPE_INTEGER) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_DELETED:
			default:
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
				bad_error("transaction_property_set",
				    scf_error());
			}
		}

		scf_value_set_integer(v, timestamp);
		if (scf_entry_add_value(ent, v) == -1)
			bad_error("scf_entry_add_value", scf_error());

		trans = scf_transaction_commit(tx);
		if (trans == 1)
			break;

		if (trans != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_BACKEND_ACCESS:
			case SCF_ERROR_BACKEND_READONLY:
			default:
				goto out;

			case SCF_ERROR_DELETED:
				scf_transaction_reset(tx);
				goto add;

			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
				bad_error("scf_transaction_commit",
				    scf_error());
			}
		}

		scf_transaction_reset(tx);
		if (scf_pg_update(pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				goto out;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_NOT_BOUND:
				bad_error("scf_pg_update", scf_error());
			}
		}
	}

	ret = 0;

out:
	scf_value_destroy(v);
	scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	return (ret);
}

static int
set_inst_action(const char *fmri, const char *action)
{
	scf_handle_t *h;
	scf_instance_t *inst;
	int ret = -1;

	h = _scf_handle_create_and_bind(SCF_VERSION);
	if (h == NULL)
		return (-1);

	inst = scf_instance_create(h);

	if (inst != NULL) {
		if (scf_handle_decode_fmri(h, fmri, NULL, NULL, inst, NULL,
		    NULL, SCF_DECODE_FMRI_EXACT) == 0) {
			ret = set_inst_action_inst(inst, action);
			if (ret == -1 && scf_error() == SCF_ERROR_DELETED)
				(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		} else {
			switch (scf_error()) {
			case SCF_ERROR_CONSTRAINT_VIOLATED:
				(void) scf_set_error(
				    SCF_ERROR_INVALID_ARGUMENT);
				break;
			case SCF_ERROR_DELETED:
				(void) scf_set_error(SCF_ERROR_NOT_FOUND);
				break;
			}
		}

		scf_instance_destroy(inst);
	}

	scf_handle_destroy(h);

	return (ret);
}


/*
 * get_inst_state() gets the state string from an instance, and returns
 * the SCF_STATE_* constant that coincides with the instance's current state.
 */

static int
get_inst_state(scf_instance_t *inst, scf_handle_t *h)
{
	scf_propertygroup_t	*pg = NULL;
	scf_property_t		*prop = NULL;
	scf_value_t		*val = NULL;
	char			state[MAX_SCF_STATE_STRING_SZ];
	int			ret = -1;

	if (((pg = scf_pg_create(h)) == NULL) ||
	    ((prop = scf_property_create(h)) == NULL) ||
	    ((val = scf_value_create(h)) == NULL))
		goto out;

	/* Pull the state property from the instance */

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) == -1 ||
	    scf_pg_get_property(pg, SCF_PROPERTY_STATE, prop) == -1 ||
	    scf_property_get_value(prop, val) == -1) {
		if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
			(void) scf_set_error(SCF_ERROR_INTERNAL);
		goto out;
	}

	if (scf_value_get_astring(val, state, sizeof (state)) <= 0) {
		(void) scf_set_error(SCF_ERROR_INTERNAL);
		goto out;
	}

	if (strcmp(state, SCF_STATE_STRING_UNINIT) == 0) {
		ret = SCF_STATE_UNINIT;
	} else if (strcmp(state, SCF_STATE_STRING_MAINT) == 0) {
		ret = SCF_STATE_MAINT;
	} else if (strcmp(state, SCF_STATE_STRING_OFFLINE) == 0) {
		ret = SCF_STATE_OFFLINE;
	} else if (strcmp(state, SCF_STATE_STRING_DISABLED) == 0) {
		ret = SCF_STATE_DISABLED;
	} else if (strcmp(state, SCF_STATE_STRING_ONLINE) == 0) {
		ret = SCF_STATE_ONLINE;
	} else if (strcmp(state, SCF_STATE_STRING_DEGRADED) == 0) {
		ret = SCF_STATE_DEGRADED;
	}

out:
	scf_pg_destroy(pg);
	scf_property_destroy(prop);
	(void) scf_value_destroy(val);

	return (ret);
}

/*
 * Sets an instance to be enabled or disabled after reboot, using the
 * temporary (overriding) general_ovr property group to reflect the
 * present state, if it is different.
 */
static int
set_inst_enabled_atboot(scf_instance_t *inst, uint8_t desired)
{
	int enabled;
	int persistent;
	int ret = -1;

	if ((persistent = get_inst_enabled(inst, SCF_PG_GENERAL)) < 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			goto out;
		persistent = B_FALSE;
	}
	if ((enabled = get_inst_enabled(inst, SCF_PG_GENERAL_OVR)) < 0) {
		enabled = persistent;
		if (persistent != desired) {
			/*
			 * Temporarily store the present enabled state.
			 */
			if (set_inst_enabled(inst, persistent,
			    SCF_PG_GENERAL_OVR, SCF_PG_GENERAL_OVR_FLAGS))
				goto out;
		}
	}
	if (persistent != desired)
		if (set_inst_enabled(inst, desired, SCF_PG_GENERAL,
		    SCF_PG_GENERAL_FLAGS))
			goto out;
	if (enabled == desired)
		ret = delete_inst_enabled(inst, SCF_PG_GENERAL_OVR);
	else
		ret = 0;

out:
	return (ret);
}

static int
set_inst_enabled_flags(const char *fmri, int flags, uint8_t desired)
{
	int ret = -1;
	scf_handle_t *h;
	scf_instance_t *inst;

	if (flags & ~(SMF_TEMPORARY | SMF_AT_NEXT_BOOT) ||
	    flags & SMF_TEMPORARY && flags & SMF_AT_NEXT_BOOT) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (ret);
	}

	if ((h = _scf_handle_create_and_bind(SCF_VERSION)) == NULL)
		return (ret);

	if ((inst = scf_instance_create(h)) == NULL) {
		scf_handle_destroy(h);
		return (ret);
	}

	if (scf_handle_decode_fmri(h, fmri, NULL, NULL, inst, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) == -1) {
		if (scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED)
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto out;
	}

	if (flags & SMF_AT_NEXT_BOOT) {
		ret = set_inst_enabled_atboot(inst, desired);
	} else {
		if (set_inst_enabled(inst, desired, flags & SMF_TEMPORARY ?
		    SCF_PG_GENERAL_OVR : SCF_PG_GENERAL, flags & SMF_TEMPORARY ?
		    SCF_PG_GENERAL_OVR_FLAGS : SCF_PG_GENERAL_FLAGS))
			goto out;

		/*
		 * Make the persistent value effective by deleting the
		 * temporary one.
		 */
		if (flags & SMF_TEMPORARY)
			ret = 0;
		else
			ret = delete_inst_enabled(inst, SCF_PG_GENERAL_OVR);
	}

out:
	scf_instance_destroy(inst);
	scf_handle_destroy(h);
	if (ret == -1 && scf_error() == SCF_ERROR_DELETED)
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
	return (ret);
}

/*
 * Create and return a pg from the instance associated with the given handle.
 * This function is only called in scf_transaction_setup and
 * scf_transaction_restart where the h->rh_instance pointer is properly filled
 * in by scf_general_setup_pg().
 */
static scf_propertygroup_t *
get_instance_pg(scf_simple_handle_t *simple_h)
{
	scf_propertygroup_t	*ret_pg = scf_pg_create(simple_h->h);
	char			*pg_name;
	ssize_t			namelen;

	if (ret_pg == NULL) {
		return (NULL);
	}

	namelen = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	assert(namelen > 0);

	if ((pg_name = malloc(namelen)) == NULL) {
		if (scf_error() == SCF_ERROR_NOT_SET) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		}
		return (NULL);
	}

	if (scf_pg_get_name(simple_h->running_pg, pg_name, namelen) < 0) {
		if (scf_error() == SCF_ERROR_NOT_SET) {
			(void) scf_set_error(SCF_ERROR_INTERNAL);
		}
		return (NULL);
	}

	/* Get pg from instance */
	if (scf_instance_get_pg(simple_h->inst, pg_name, ret_pg) == -1) {
		return (NULL);
	}

	return (ret_pg);
}

int
smf_enable_instance(const char *fmri, int flags)
{
	return (set_inst_enabled_flags(fmri, flags, B_TRUE));
}

int
smf_disable_instance(const char *fmri, int flags)
{
	return (set_inst_enabled_flags(fmri, flags, B_FALSE));
}

int
_smf_refresh_instance_i(scf_instance_t *inst)
{
	return (set_inst_action_inst(inst, SCF_PROPERTY_REFRESH));
}

int
_smf_refresh_all_instances(scf_service_t *s)
{
	scf_handle_t	*h = scf_service_handle(s);
	scf_instance_t	*i = scf_instance_create(h);
	scf_iter_t	*it = scf_iter_create(h);
	int err, r = -1;

	if (h == NULL || i == NULL || it == NULL)
		goto error;

	if (scf_iter_service_instances(it, s) != 0)
		goto error;

	while ((err = scf_iter_next_instance(it, i)) == 1)
		if (_smf_refresh_instance_i(i) != 0)
			goto error;

	if (err == -1)
		goto error;

	r = 0;
error:
	scf_instance_destroy(i);
	scf_iter_destroy(it);

	return (r);
}

int
smf_refresh_instance(const char *instance)
{
	return (set_inst_action(instance, SCF_PROPERTY_REFRESH));
}

int
smf_restart_instance(const char *instance)
{
	return (set_inst_action(instance, SCF_PROPERTY_RESTART));
}

int
smf_maintain_instance(const char *instance, int flags)
{
	if (flags & SMF_TEMPORARY)
		return (set_inst_action(instance,
		    (flags & SMF_IMMEDIATE) ?
		    SCF_PROPERTY_MAINT_ON_IMMTEMP :
		    SCF_PROPERTY_MAINT_ON_TEMPORARY));
	else
		return (set_inst_action(instance,
		    (flags & SMF_IMMEDIATE) ?
		    SCF_PROPERTY_MAINT_ON_IMMEDIATE :
		    SCF_PROPERTY_MAINT_ON));
}

int
smf_degrade_instance(const char *instance, int flags)
{
	scf_simple_prop_t		*prop;
	const char			*state_str;

	if (flags & SMF_TEMPORARY)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	if ((prop = scf_simple_prop_get(NULL, instance, SCF_PG_RESTARTER,
	    SCF_PROPERTY_STATE)) == NULL)
		return (SCF_FAILED);

	if ((state_str = scf_simple_prop_next_astring(prop)) == NULL) {
		scf_simple_prop_free(prop);
		return (SCF_FAILED);
	}

	if (strcmp(state_str, SCF_STATE_STRING_ONLINE) != 0) {
		scf_simple_prop_free(prop);
		return (scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED));
	}
	scf_simple_prop_free(prop);

	return (set_inst_action(instance, (flags & SMF_IMMEDIATE) ?
	    SCF_PROPERTY_DEGRADE_IMMEDIATE : SCF_PROPERTY_DEGRADED));
}

int
smf_restore_instance(const char *instance)
{
	scf_simple_prop_t		*prop;
	const char			*state_str;
	int				ret;

	if ((prop = scf_simple_prop_get(NULL, instance, SCF_PG_RESTARTER,
	    SCF_PROPERTY_STATE)) == NULL)
		return (SCF_FAILED);

	if ((state_str = scf_simple_prop_next_astring(prop)) == NULL) {
		scf_simple_prop_free(prop);
		return (SCF_FAILED);
	}

	if (strcmp(state_str, SCF_STATE_STRING_MAINT) == 0) {
		ret = set_inst_action(instance, SCF_PROPERTY_MAINT_OFF);
	} else if (strcmp(state_str, SCF_STATE_STRING_DEGRADED) == 0) {
		ret = set_inst_action(instance, SCF_PROPERTY_RESTORE);
	} else {
		ret = scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
	}

	scf_simple_prop_free(prop);
	return (ret);
}

char *
smf_get_state(const char *instance)
{
	scf_simple_prop_t		*prop;
	const char			*state_str;
	char				*ret;

	if ((prop = scf_simple_prop_get(NULL, instance, SCF_PG_RESTARTER,
	    SCF_PROPERTY_STATE)) == NULL)
		return (NULL);

	if ((state_str = scf_simple_prop_next_astring(prop)) == NULL) {
		scf_simple_prop_free(prop);
		return (NULL);
	}

	if ((ret = strdup(state_str)) == NULL)
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);

	scf_simple_prop_free(prop);
	return (ret);
}

/*
 * scf_general_pg_setup(fmri, pg_name)
 * Create a scf_simple_handle_t and fill in the instance, snapshot, and
 * property group fields associated with the given fmri and property group
 * name.
 * Returns:
 *      Handle  on success
 *      Null  on error with scf_error set to:
 *              SCF_ERROR_HANDLE_MISMATCH,
 *              SCF_ERROR_INVALID_ARGUMENT,
 *              SCF_ERROR_CONSTRAINT_VIOLATED,
 *              SCF_ERROR_NOT_FOUND,
 *              SCF_ERROR_NOT_SET,
 *              SCF_ERROR_DELETED,
 *              SCF_ERROR_NOT_BOUND,
 *              SCF_ERROR_CONNECTION_BROKEN,
 *              SCF_ERROR_INTERNAL,
 *              SCF_ERROR_NO_RESOURCES,
 *              SCF_ERROR_BACKEND_ACCESS
 */
scf_simple_handle_t *
scf_general_pg_setup(const char *fmri, const char *pg_name)
{
	scf_simple_handle_t	*ret;

	ret = uu_zalloc(sizeof (*ret));
	if (ret == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	} else {

		ret->h = _scf_handle_create_and_bind(SCF_VERSION);
		ret->inst = scf_instance_create(ret->h);
		ret->snap = scf_snapshot_create(ret->h);
		ret->running_pg = scf_pg_create(ret->h);
	}

	if ((ret->h == NULL) || (ret->inst == NULL) ||
	    (ret->snap == NULL) || (ret->running_pg == NULL)) {
		goto out;
	}

	if (scf_handle_decode_fmri(ret->h, fmri, NULL, NULL, ret->inst,
	    NULL, NULL, NULL) == -1) {
		goto out;
	}

	if ((scf_instance_get_snapshot(ret->inst, "running", ret->snap))
	    != 0) {
		goto out;
	}

	if (scf_instance_get_pg_composed(ret->inst, ret->snap, pg_name,
	    ret->running_pg) != 0) {
		goto out;
	}

	return (ret);

out:
	scf_simple_handle_destroy(ret);
	return (NULL);
}

/*
 * scf_transaction_setup(h)
 * creates and starts the transaction
 * Returns:
 *      transaction  on success
 *      NULL on failure with scf_error set to:
 *      SCF_ERROR_NO_MEMORY,
 *	SCF_ERROR_INVALID_ARGUMENT,
 *      SCF_ERROR_HANDLE_DESTROYED,
 *	SCF_ERROR_INTERNAL,
 *	SCF_ERROR_NO_RESOURCES,
 *      SCF_ERROR_NOT_BOUND,
 *	SCF_ERROR_CONNECTION_BROKEN,
 *      SCF_ERROR_NOT_SET,
 *	SCF_ERROR_DELETED,
 *	SCF_ERROR_CONSTRAINT_VIOLATED,
 *      SCF_ERROR_HANDLE_MISMATCH,
 *	SCF_ERROR_BACKEND_ACCESS,
 *	SCF_ERROR_IN_USE
 */
scf_transaction_t *
scf_transaction_setup(scf_simple_handle_t *simple_h)
{
	scf_transaction_t	*tx = NULL;

	if ((tx = scf_transaction_create(simple_h->h)) == NULL) {
		return (NULL);
	}

	if ((simple_h->editing_pg = get_instance_pg(simple_h)) == NULL) {
		return (NULL);
	}

	if (scf_transaction_start(tx, simple_h->editing_pg) == -1) {
		scf_pg_destroy(simple_h->editing_pg);
		simple_h->editing_pg = NULL;
		return (NULL);
	}

	return (tx);
}

int
scf_transaction_restart(scf_simple_handle_t *simple_h, scf_transaction_t *tx)
{
	scf_transaction_reset(tx);

	if (scf_pg_update(simple_h->editing_pg) == -1) {
		return (SCF_FAILED);
	}

	if (scf_transaction_start(tx, simple_h->editing_pg) == -1) {
		return (SCF_FAILED);
	}

	return (SCF_SUCCESS);
}

/*
 * scf_read_count_property(scf_simple_handle_t *simple_h, char *prop_name,
 * uint64_t *ret_count)
 *
 * For the given property name, return the count value.
 * RETURNS:
 *	SCF_SUCCESS
 *	SCF_FAILED on failure with scf_error() set to:
 *		SCF_ERROR_HANDLE_DESTROYED
 *		SCF_ERROR_INTERNAL
 *		SCF_ERROR_NO_RESOURCES
 *		SCF_ERROR_NO_MEMORY
 *		SCF_ERROR_HANDLE_MISMATCH
 *		SCF_ERROR_INVALID_ARGUMENT
 *		SCF_ERROR_NOT_BOUND
 *		SCF_ERROR_CONNECTION_BROKEN
 *		SCF_ERROR_NOT_SET
 *		SCF_ERROR_DELETED
 *		SCF_ERROR_BACKEND_ACCESS
 *		SCF_ERROR_CONSTRAINT_VIOLATED
 *		SCF_ERROR_TYPE_MISMATCH
 */
int
scf_read_count_property(
	scf_simple_handle_t	*simple_h,
	char			*prop_name,
	uint64_t		*ret_count)
{
	scf_property_t		*prop = scf_property_create(simple_h->h);
	scf_value_t		*val = scf_value_create(simple_h->h);
	int			ret = SCF_FAILED;

	if ((val == NULL) || (prop == NULL)) {
		goto out;
	}

	/*
	 * Get the property struct that goes with this property group and
	 * property name.
	 */
	if (scf_pg_get_property(simple_h->running_pg, prop_name, prop) != 0) {
		goto out;
	}

	/* Get the value structure */
	if (scf_property_get_value(prop, val) == -1) {
		goto out;
	}

	/*
	 * Now get the count value.
	 */
	if (scf_value_get_count(val, ret_count) == -1) {
		goto out;
	}

	ret = SCF_SUCCESS;

out:
	scf_property_destroy(prop);
	scf_value_destroy(val);
	return (ret);
}

/*
 * scf_trans_add_count_property(trans, propname, count, create_flag)
 *
 * Set a count property transaction entry into the pending SMF transaction.
 * The transaction is created and committed outside of this function.
 * Returns:
 *	SCF_SUCCESS
 *	SCF_FAILED on failure with scf_error() set to:
 *			SCF_ERROR_HANDLE_DESTROYED,
 *			SCF_ERROR_INVALID_ARGUMENT,
 *			SCF_ERROR_NO_MEMORY,
 *			SCF_ERROR_HANDLE_MISMATCH,
 *			SCF_ERROR_NOT_SET,
 *			SCF_ERROR_IN_USE,
 *			SCF_ERROR_NOT_FOUND,
 *			SCF_ERROR_EXISTS,
 *			SCF_ERROR_TYPE_MISMATCH,
 *			SCF_ERROR_NOT_BOUND,
 *			SCF_ERROR_CONNECTION_BROKEN,
 *			SCF_ERROR_INTERNAL,
 *			SCF_ERROR_DELETED,
 *			SCF_ERROR_NO_RESOURCES,
 *			SCF_ERROR_BACKEND_ACCESS
 */
int
scf_set_count_property(
	scf_transaction_t	*trans,
	char			*propname,
	uint64_t		count,
	boolean_t		create_flag)
{
	scf_handle_t		*handle = scf_transaction_handle(trans);
	scf_value_t		*value = scf_value_create(handle);
	scf_transaction_entry_t	*entry = scf_entry_create(handle);

	if ((value == NULL) || (entry == NULL)) {
		return (SCF_FAILED);
	}

	/*
	 * Property must be set in transaction and won't take
	 * effect until the transaction is committed.
	 *
	 * Attempt to change the current value. However, create new property
	 * if it doesn't exist and the create flag is set.
	 */
	if (scf_transaction_property_change(trans, entry, propname,
	    SCF_TYPE_COUNT) == 0) {
		scf_value_set_count(value, count);
		if (scf_entry_add_value(entry, value) == 0) {
			return (SCF_SUCCESS);
		}
	} else {
		if ((create_flag == B_TRUE) &&
		    (scf_error() == SCF_ERROR_NOT_FOUND)) {
			if (scf_transaction_property_new(trans, entry, propname,
			    SCF_TYPE_COUNT) == 0) {
				scf_value_set_count(value, count);
				if (scf_entry_add_value(entry, value) == 0) {
					return (SCF_SUCCESS);
				}
			}
		}
	}

	/*
	 * cleanup if there were any errors that didn't leave these
	 * values where they would be cleaned up later.
	 */
	if (value != NULL)
		scf_value_destroy(value);
	if (entry != NULL)
		scf_entry_destroy(entry);
	return (SCF_FAILED);
}

int
scf_simple_walk_instances(uint_t state_flags, void *private,
    int (*inst_callback)(scf_handle_t *, scf_instance_t *, void *))
{
	scf_scope_t 		*scope = NULL;
	scf_service_t		*svc = NULL;
	scf_instance_t		*inst = NULL;
	scf_iter_t		*svc_iter = NULL, *inst_iter = NULL;
	scf_handle_t		*h = NULL;
	int			ret = SCF_FAILED;
	int			svc_iter_ret, inst_iter_ret;
	int			inst_state;

	if ((h = _scf_handle_create_and_bind(SCF_VERSION)) == NULL)
		return (ret);

	if (((scope = scf_scope_create(h)) == NULL) ||
	    ((svc = scf_service_create(h)) == NULL) ||
	    ((inst = scf_instance_create(h)) == NULL) ||
	    ((svc_iter = scf_iter_create(h)) == NULL) ||
	    ((inst_iter = scf_iter_create(h)) == NULL))
		goto out;

	/*
	 * Get the local scope, and set up nested iteration through every
	 * local service, and every instance of every service.
	 */

	if ((scf_handle_get_local_scope(h, scope) != SCF_SUCCESS) ||
	    (scf_iter_scope_services(svc_iter, scope) != SCF_SUCCESS))
		goto out;

	while ((svc_iter_ret = scf_iter_next_service(svc_iter, svc)) > 0) {

		if ((scf_iter_service_instances(inst_iter, svc)) !=
		    SCF_SUCCESS)
			goto out;

		while ((inst_iter_ret =
		    scf_iter_next_instance(inst_iter, inst)) > 0) {
			/*
			 * If get_inst_state fails from an internal error,
			 * IE, being unable to get the property group or
			 * property containing the state of the instance,
			 * we continue instead of failing, as this might just
			 * be an improperly configured instance.
			 */
			if ((inst_state = get_inst_state(inst, h)) == -1) {
				if (scf_error() == SCF_ERROR_INTERNAL) {
					continue;
				} else {
					goto out;
				}
			}

			if ((uint_t)inst_state & state_flags) {
				if (inst_callback(h, inst, private) !=
				    SCF_SUCCESS) {
					(void) scf_set_error(
					    SCF_ERROR_CALLBACK_FAILED);
					goto out;
				}
			}
		}

		if (inst_iter_ret == -1)
			goto out;
		scf_iter_reset(inst_iter);
	}

	if (svc_iter_ret != -1)
		ret = SCF_SUCCESS;

out:
	scf_scope_destroy(scope);
	scf_service_destroy(svc);
	scf_instance_destroy(inst);
	scf_iter_destroy(svc_iter);
	scf_iter_destroy(inst_iter);
	scf_handle_destroy(h);

	return (ret);
}


scf_simple_prop_t *
scf_simple_prop_get(scf_handle_t *hin, const char *instance, const char *pgname,
			const char *propname)
{
	char 			*fmri_buf, *svcfmri = NULL;
	ssize_t 		fmri_sz;
	scf_property_t 		*prop = NULL;
	scf_service_t 		*svc = NULL;
	scf_simple_prop_t 	*ret;
	scf_handle_t		*h = NULL;
	boolean_t		local_h = B_TRUE;

	/* If the user passed in a handle, use it. */
	if (hin != NULL) {
		h = hin;
		local_h = B_FALSE;
	}

	if (local_h && ((h = _scf_handle_create_and_bind(SCF_VERSION)) == NULL))
		return (NULL);

	if ((fmri_buf = assemble_fmri(h, instance, pgname, propname)) == NULL) {
		if (local_h)
			scf_handle_destroy(h);
		return (NULL);
	}

	if ((svc = scf_service_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL)
		goto error1;
	if (scf_handle_decode_fmri(h, fmri_buf, NULL, NULL, NULL, NULL, prop,
	    SCF_DECODE_FMRI_REQUIRE_INSTANCE) == -1) {
		switch (scf_error()) {
		/*
		 * If the property isn't found in the instance, we grab the
		 * underlying service, create an FMRI out of it, and then
		 * query the datastore again at the service level for the
		 * property.
		 */
		case SCF_ERROR_NOT_FOUND:
			if (scf_handle_decode_fmri(h, fmri_buf, NULL, svc,
			    NULL, NULL, NULL, SCF_DECODE_FMRI_TRUNCATE) == -1)
				goto error1;

			fmri_sz = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH) + 1;
			assert(fmri_sz > 0);

			if (scf_service_to_fmri(svc, fmri_buf, fmri_sz) == -1)
				goto error1;
			if ((svcfmri = assemble_fmri(h, fmri_buf, pgname,
			    propname)) == NULL)
				goto error1;
			if (scf_handle_decode_fmri(h, svcfmri, NULL, NULL,
			    NULL, NULL, prop, 0) == -1) {
				free(svcfmri);
				goto error1;
			}
			free(svcfmri);
			break;
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		default:
			goto error1;
		}
	}
	/*
	 * At this point, we've successfully pulled the property from the
	 * datastore, and simply need to copy its innards into an
	 * scf_simple_prop_t.
	 */
	if ((ret = fill_prop(prop, pgname, propname, h)) == NULL)
		goto error1;

	scf_service_destroy(svc);
	scf_property_destroy(prop);
	free(fmri_buf);
	if (local_h)
		scf_handle_destroy(h);
	return (ret);

	/*
	 * Exit point for a successful call.  Below this line are exit points
	 * for failures at various stages during the function.
	 */

error1:
	scf_service_destroy(svc);
	scf_property_destroy(prop);
error2:
	free(fmri_buf);
	if (local_h)
		scf_handle_destroy(h);
	return (NULL);
}


void
scf_simple_prop_free(scf_simple_prop_t *prop)
{
	int i;

	if (prop == NULL)
		return;

	free(prop->pr_propname);
	free(prop->pr_pgname);
	switch (prop->pr_type) {
	case SCF_TYPE_OPAQUE: {
		for (i = 0; i < prop->pr_numvalues; i++) {
			free(prop->pr_vallist[i].pv_opaque.o_value);
		}
		break;
	}
	case SCF_TYPE_ASTRING:
	case SCF_TYPE_USTRING:
	case SCF_TYPE_HOST:
	case SCF_TYPE_HOSTNAME:
	case SCF_TYPE_NET_ADDR:
	case SCF_TYPE_NET_ADDR_V4:
	case SCF_TYPE_NET_ADDR_V6:
	case SCF_TYPE_URI:
	case SCF_TYPE_FMRI: {
		for (i = 0; i < prop->pr_numvalues; i++) {
			free(prop->pr_vallist[i].pv_str);
		}
		break;
	}
	default:
		break;
	}
	free(prop->pr_vallist);
	free(prop);
}


scf_simple_app_props_t *
scf_simple_app_props_get(scf_handle_t *hin, const char *inst_fmri)
{
	scf_instance_t 		*inst = NULL;
	scf_service_t 		*svc = NULL;
	scf_propertygroup_t 	*pg = NULL;
	scf_property_t 		*prop = NULL;
	scf_simple_app_props_t	*ret = NULL;
	scf_iter_t		*pgiter = NULL, *propiter = NULL;
	struct scf_simple_pg	*thispg = NULL, *nextpg;
	scf_simple_prop_t	*thisprop, *nextprop;
	scf_handle_t		*h = NULL;
	int			pgiter_ret, propiter_ret;
	ssize_t			namelen;
	char 			*propname = NULL, *pgname = NULL, *sys_fmri;
	uint8_t			found;
	boolean_t		local_h = B_TRUE;

	/* If the user passed in a handle, use it. */
	if (hin != NULL) {
		h = hin;
		local_h = B_FALSE;
	}

	if (local_h && ((h = _scf_handle_create_and_bind(SCF_VERSION)) == NULL))
		return (NULL);

	if (inst_fmri == NULL) {
		if ((namelen = scf_myname(h, NULL, 0)) == -1) {
			if (local_h)
				scf_handle_destroy(h);
			return (NULL);
		}
		if ((sys_fmri = malloc(namelen + 1)) == NULL) {
			if (local_h)
				scf_handle_destroy(h);
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			return (NULL);
		}
		if (scf_myname(h, sys_fmri, namelen + 1) == -1) {
			if (local_h)
				scf_handle_destroy(h);
			free(sys_fmri);
			return (NULL);
		}
	} else {
		if ((sys_fmri = strdup(inst_fmri)) == NULL) {
			if (local_h)
				scf_handle_destroy(h);
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			return (NULL);
		}
	}

	namelen = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	assert(namelen > 0);

	if ((inst = scf_instance_create(h)) == NULL ||
	    (svc = scf_service_create(h)) == NULL ||
	    (pgiter = scf_iter_create(h)) == NULL ||
	    (propiter = scf_iter_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL) {
		free(sys_fmri);
		goto error2;
	}

	if (scf_handle_decode_fmri(h, sys_fmri, NULL, svc, inst, NULL, NULL,
	    SCF_DECODE_FMRI_REQUIRE_INSTANCE) == -1) {
		free(sys_fmri);
		if (scf_error() == SCF_ERROR_CONSTRAINT_VIOLATED)
			(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto error2;
	}

	if ((ret = malloc(sizeof (*ret))) == NULL ||
	    (thispg = malloc(sizeof (*thispg))) == NULL ||
	    (propname = malloc(namelen)) == NULL ||
	    (pgname = malloc(namelen)) == NULL) {
		free(thispg);
		free(ret);
		free(sys_fmri);
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		goto error2;
	}

	ret->ap_fmri = sys_fmri;
	thispg->pg_name = NULL;
	thispg->pg_proplist = NULL;
	thispg->pg_next = NULL;
	ret->ap_pglist = thispg;

	if (scf_iter_service_pgs_typed(pgiter, svc, SCF_GROUP_APPLICATION) !=
	    0) {
		if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
			(void) scf_set_error(SCF_ERROR_INTERNAL);
		goto error1;
	}

	while ((pgiter_ret = scf_iter_next_pg(pgiter, pg)) == 1) {
		if (thispg->pg_name != NULL) {
			if ((nextpg = malloc(sizeof (*nextpg))) == NULL) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				goto error1;
			}
			nextpg->pg_name = NULL;
			nextpg->pg_next = NULL;
			nextpg->pg_proplist = NULL;
			thispg->pg_next = nextpg;
			thispg = nextpg;
		} else {
			/* This is the first iteration */
			nextpg = thispg;
		}

		if ((nextpg->pg_name = malloc(namelen)) == NULL) {
			(void) scf_set_error(SCF_ERROR_NO_MEMORY);
			goto error1;
		}

		if (scf_pg_get_name(pg, nextpg->pg_name, namelen) < 0) {
			if (scf_error() == SCF_ERROR_NOT_SET)
				(void) scf_set_error(SCF_ERROR_INTERNAL);
			goto error1;
		}

		thisprop = NULL;

		scf_iter_reset(propiter);

		if (scf_iter_pg_properties(propiter, pg) != 0) {
			if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
				(void) scf_set_error(SCF_ERROR_INTERNAL);
			goto error1;
		}

		while ((propiter_ret = scf_iter_next_property(propiter, prop))
		    == 1) {
			if (scf_property_get_name(prop, propname, namelen) <
			    0) {
				if (scf_error() == SCF_ERROR_NOT_SET)
					(void) scf_set_error(
					    SCF_ERROR_INTERNAL);
				goto error1;
			}
			if (thisprop != NULL) {
				if ((nextprop = fill_prop(prop,
				    nextpg->pg_name, propname, h)) == NULL)
					goto error1;
				thisprop->pr_next = nextprop;
				thisprop = nextprop;
			} else {
				/* This is the first iteration */
				if ((thisprop = fill_prop(prop,
				    nextpg->pg_name, propname, h)) == NULL)
					goto error1;
				nextpg->pg_proplist = thisprop;
				nextprop = thisprop;
			}
			nextprop->pr_pg = nextpg;
			nextprop->pr_next = NULL;
		}

		if (propiter_ret == -1) {
			if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
				(void) scf_set_error(SCF_ERROR_INTERNAL);
			goto error1;
		}
	}

	if (pgiter_ret == -1) {
		if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
			(void) scf_set_error(SCF_ERROR_INTERNAL);
		goto error1;
	}

	/*
	 * At this point, we've filled the scf_simple_app_props_t with all the
	 * properties at the service level.  Now we iterate over all the
	 * properties at the instance level, overwriting any duplicate
	 * properties, in order to provide service/instance composition.
	 */

	scf_iter_reset(pgiter);
	scf_iter_reset(propiter);

	if (scf_iter_instance_pgs_typed(pgiter, inst, SCF_GROUP_APPLICATION)
	    != 0) {
		if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
			(void) scf_set_error(SCF_ERROR_INTERNAL);
		goto error1;
	}

	while ((pgiter_ret = scf_iter_next_pg(pgiter, pg)) == 1) {

		thispg = ret->ap_pglist;
		found = 0;

		/*
		 * Find either the end of the list, so we can append the
		 * property group, or an existing property group that matches
		 * it, so we can insert/overwrite its properties.
		 */

		if (scf_pg_get_name(pg, pgname, namelen) < 0) {
			if (scf_error() == SCF_ERROR_NOT_SET)
				(void) scf_set_error(SCF_ERROR_INTERNAL);
			goto error1;
		}

		while ((thispg != NULL) && (thispg->pg_name != NULL)) {
			if (strcmp(thispg->pg_name, pgname) == 0) {
				found = 1;
				break;
			}
			if (thispg->pg_next == NULL)
				break;

			thispg = thispg->pg_next;
		}

		scf_iter_reset(propiter);

		if (scf_iter_pg_properties(propiter, pg) != 0) {
			if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
				(void) scf_set_error(SCF_ERROR_INTERNAL);
			goto error1;
		}

		if (found) {
			/*
			 * insert_app_props inserts or overwrites the
			 * properties in thispg.
			 */

			if (insert_app_props(propiter, pgname, propname,
			    thispg, prop, namelen, h) == -1)
				goto error1;

		} else {
			/*
			 * If the property group wasn't found, we're adding
			 * a newly allocated property group to the end of the
			 * list.
			 */

			if ((nextpg = malloc(sizeof (*nextpg))) == NULL) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				goto error1;
			}
			nextpg->pg_next = NULL;
			nextpg->pg_proplist = NULL;
			thisprop = NULL;

			if ((nextpg->pg_name = strdup(pgname)) == NULL) {
				(void) scf_set_error(SCF_ERROR_NO_MEMORY);
				free(nextpg);
				goto error1;
			}

			if (thispg->pg_name == NULL) {
				free(thispg);
				ret->ap_pglist = nextpg;
			} else {
				thispg->pg_next = nextpg;
			}

			while ((propiter_ret =
			    scf_iter_next_property(propiter, prop)) == 1) {
				if (scf_property_get_name(prop, propname,
				    namelen) < 0) {
					if (scf_error() == SCF_ERROR_NOT_SET)
						(void) scf_set_error(
						    SCF_ERROR_INTERNAL);
					goto error1;
				}
				if (thisprop != NULL) {
					if ((nextprop = fill_prop(prop,
					    pgname, propname, h)) ==
					    NULL)
						goto error1;
					thisprop->pr_next = nextprop;
					thisprop = nextprop;
				} else {
					/* This is the first iteration */
					if ((thisprop = fill_prop(prop,
					    pgname, propname, h)) ==
					    NULL)
						goto error1;
					nextpg->pg_proplist = thisprop;
					nextprop = thisprop;
				}
				nextprop->pr_pg = nextpg;
				nextprop->pr_next = NULL;
			}

			if (propiter_ret == -1) {
				if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
					(void) scf_set_error(
					    SCF_ERROR_INTERNAL);
				goto error1;
			}
		}

	}

	if (pgiter_ret == -1) {
		if (scf_error() != SCF_ERROR_CONNECTION_BROKEN)
			(void) scf_set_error(SCF_ERROR_INTERNAL);
		goto error1;
	}

	if (ret->ap_pglist->pg_name == NULL)
		goto error1;

	scf_iter_destroy(pgiter);
	scf_iter_destroy(propiter);
	scf_pg_destroy(pg);
	scf_property_destroy(prop);
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
	free(propname);
	free(pgname);
	if (local_h)
		scf_handle_destroy(h);

	return (ret);

	/*
	 * Exit point for a successful call.  Below this line are exit points
	 * for failures at various stages during the function.
	 */

error1:
	scf_simple_app_props_free(ret);

error2:
	scf_iter_destroy(pgiter);
	scf_iter_destroy(propiter);
	scf_pg_destroy(pg);
	scf_property_destroy(prop);
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
	free(propname);
	free(pgname);
	if (local_h)
		scf_handle_destroy(h);
	return (NULL);
}


void
scf_simple_app_props_free(scf_simple_app_props_t *propblock)
{
	struct scf_simple_pg 	*pgthis, *pgnext;
	scf_simple_prop_t 	*propthis, *propnext;

	if ((propblock == NULL) || (propblock->ap_pglist == NULL))
		return;

	for (pgthis = propblock->ap_pglist; pgthis != NULL; pgthis = pgnext) {
		pgnext = pgthis->pg_next;

		propthis = pgthis->pg_proplist;

		while (propthis != NULL) {
			propnext = propthis->pr_next;
			scf_simple_prop_free(propthis);
			propthis = propnext;
		}

		free(pgthis->pg_name);
		free(pgthis);
	}

	free(propblock->ap_fmri);
	free(propblock);
}

const scf_simple_prop_t *
scf_simple_app_props_next(const scf_simple_app_props_t *propblock,
    scf_simple_prop_t *last)
{
	struct scf_simple_pg 	*this;

	if (propblock == NULL) {
		(void) scf_set_error(SCF_ERROR_NOT_SET);
		return (NULL);
	}

	this = propblock->ap_pglist;

	/*
	 * We're looking for the first property in this block if last is
	 * NULL
	 */

	if (last == NULL) {
		/* An empty pglist is legal, it just means no properties */
		if (this == NULL) {
			(void) scf_set_error(SCF_ERROR_NONE);
			return (NULL);
		}
		/*
		 * Walk until we find a pg with a property in it, or we run
		 * out of property groups.
		 */
		while ((this->pg_proplist == NULL) && (this->pg_next != NULL))
			this = this->pg_next;

		if (this->pg_proplist == NULL) {
			(void) scf_set_error(SCF_ERROR_NONE);
			return (NULL);
		}

		return (this->pg_proplist);

	}
	/*
	 * If last isn't NULL, then return the next prop in the property group,
	 * or walk the property groups until we find another property, or
	 * run out of property groups.
	 */
	if (last->pr_next != NULL)
		return (last->pr_next);

	if (last->pr_pg->pg_next == NULL) {
		(void) scf_set_error(SCF_ERROR_NONE);
		return (NULL);
	}

	this = last->pr_pg->pg_next;

	while ((this->pg_proplist == NULL) && (this->pg_next != NULL))
		this = this->pg_next;

	if (this->pg_proplist == NULL) {
		(void) scf_set_error(SCF_ERROR_NONE);
		return (NULL);
	}

	return (this->pg_proplist);
}

const scf_simple_prop_t *
scf_simple_app_props_search(const scf_simple_app_props_t *propblock,
    const char *pgname, const char *propname)
{
	struct scf_simple_pg 	*pg;
	scf_simple_prop_t 	*prop;

	if ((propblock == NULL) || (propname == NULL)) {
		(void) scf_set_error(SCF_ERROR_NOT_SET);
		return (NULL);
	}

	pg = propblock->ap_pglist;

	/*
	 * If pgname is NULL, we're searching the default application
	 * property group, otherwise we look for the specified group.
	 */
	if (pgname == NULL) {
		while ((pg != NULL) &&
		    (strcmp(SCF_PG_APP_DEFAULT, pg->pg_name) != 0))
			pg = pg->pg_next;
	} else {
		while ((pg != NULL) && (strcmp(pgname, pg->pg_name) != 0))
			pg = pg->pg_next;
	}

	if (pg == NULL) {
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		return (NULL);
	}

	prop = pg->pg_proplist;

	while ((prop != NULL) && (strcmp(propname, prop->pr_propname) != 0))
		prop = prop->pr_next;

	if (prop == NULL) {
		(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		return (NULL);
	}

	return (prop);
}

void
scf_simple_prop_next_reset(scf_simple_prop_t *prop)
{
	if (prop == NULL)
		return;
	prop->pr_iter = 0;
}

ssize_t
scf_simple_prop_numvalues(const scf_simple_prop_t *prop)
{
	if (prop == NULL)
		return (scf_set_error(SCF_ERROR_NOT_SET));

	return (prop->pr_numvalues);
}


scf_type_t
scf_simple_prop_type(const scf_simple_prop_t *prop)
{
	if (prop == NULL)
		return (scf_set_error(SCF_ERROR_NOT_SET));

	return (prop->pr_type);
}


char *
scf_simple_prop_name(const scf_simple_prop_t *prop)
{
	if ((prop == NULL) || (prop->pr_propname == NULL)) {
		(void) scf_set_error(SCF_ERROR_NOT_SET);
		return (NULL);
	}

	return (prop->pr_propname);
}


char *
scf_simple_prop_pgname(const scf_simple_prop_t *prop)
{
	if ((prop == NULL) || (prop->pr_pgname == NULL)) {
		(void) scf_set_error(SCF_ERROR_NOT_SET);
		return (NULL);
	}

	return (prop->pr_pgname);
}


static union scf_simple_prop_val *
scf_next_val(scf_simple_prop_t *prop, scf_type_t type)
{
	if (prop == NULL) {
		(void) scf_set_error(SCF_ERROR_NOT_SET);
		return (NULL);
	}

	switch (prop->pr_type) {
	case SCF_TYPE_USTRING:
	case SCF_TYPE_HOST:
	case SCF_TYPE_HOSTNAME:
	case SCF_TYPE_NET_ADDR:
	case SCF_TYPE_NET_ADDR_V4:
	case SCF_TYPE_NET_ADDR_V6:
	case SCF_TYPE_URI:
	case SCF_TYPE_FMRI: {
		if (type != SCF_TYPE_USTRING) {
			(void) scf_set_error(SCF_ERROR_TYPE_MISMATCH);
			return (NULL);
		}
		break;
		}
	default: {
		if (type != prop->pr_type) {
			(void) scf_set_error(SCF_ERROR_TYPE_MISMATCH);
			return (NULL);
		}
		break;
		}
	}

	if (prop->pr_iter >= prop->pr_numvalues) {
		(void) scf_set_error(SCF_ERROR_NONE);
		return (NULL);
	}

	return (&prop->pr_vallist[prop->pr_iter++]);
}


uint8_t *
scf_simple_prop_next_boolean(scf_simple_prop_t *prop)
{
	union scf_simple_prop_val *ret;

	ret = scf_next_val(prop, SCF_TYPE_BOOLEAN);

	if (ret == NULL)
		return (NULL);

	return (&ret->pv_bool);
}


uint64_t *
scf_simple_prop_next_count(scf_simple_prop_t *prop)
{
	union scf_simple_prop_val *ret;

	ret = scf_next_val(prop, SCF_TYPE_COUNT);

	if (ret == NULL)
		return (NULL);

	return (&ret->pv_uint);
}


int64_t *
scf_simple_prop_next_integer(scf_simple_prop_t *prop)
{
	union scf_simple_prop_val *ret;

	ret = scf_next_val(prop, SCF_TYPE_INTEGER);

	if (ret == NULL)
		return (NULL);

	return (&ret->pv_int);
}

int64_t *
scf_simple_prop_next_time(scf_simple_prop_t *prop, int32_t *nsec)
{
	union scf_simple_prop_val *ret;

	ret = scf_next_val(prop, SCF_TYPE_TIME);

	if (ret == NULL)
		return (NULL);

	if (nsec != NULL)
		*nsec = ret->pv_time.t_nsec;

	return (&ret->pv_time.t_sec);
}

char *
scf_simple_prop_next_astring(scf_simple_prop_t *prop)
{
	union scf_simple_prop_val *ret;

	ret = scf_next_val(prop, SCF_TYPE_ASTRING);

	if (ret == NULL)
		return (NULL);

	return (ret->pv_str);
}

char *
scf_simple_prop_next_ustring(scf_simple_prop_t *prop)
{
	union scf_simple_prop_val *ret;

	ret = scf_next_val(prop, SCF_TYPE_USTRING);

	if (ret == NULL)
		return (NULL);

	return (ret->pv_str);
}

void *
scf_simple_prop_next_opaque(scf_simple_prop_t *prop, size_t *length)
{
	union scf_simple_prop_val *ret;

	ret = scf_next_val(prop, SCF_TYPE_OPAQUE);

	if (ret == NULL) {
		*length = 0;
		return (NULL);
	}

	*length = ret->pv_opaque.o_size;
	return (ret->pv_opaque.o_value);
}

/*
 * Generate a filename based on the fmri and the given name and return
 * it in the buffer of MAXPATHLEN provided by the caller.
 * If temp_filename is non-zero, also generate a temporary, unique filename
 * and return it in the temp buffer of MAXPATHLEN provided by the caller.
 * The path to the generated pathname is also created.
 * Given fmri should begin with a scheme such as "svc:".
 * Returns
 *      0 on success
 *      -1 if filename would exceed MAXPATHLEN or
 *	-2 if unable to create directory to filename path
 */
int
gen_filenms_from_fmri(const char *fmri, const char *name, char *filename,
    char *temp_filename)
{
	int		len;

	len = strlen(SMF_SPEEDY_FILES_PATH);
	len += strlen(fmri);
	len += 2;			/* for slash and null */
	len += strlen(name);
	len += 6;			/* For X's needed for mkstemp */

	if (len > MAXPATHLEN)
		return (-1);

	/* Construct directory name first - speedy path ends in slash */
	(void) strcpy(filename, SMF_SPEEDY_FILES_PATH);
	(void) strcat(filename, fmri);
	if (mkdirp(filename, 0755) == -1) {
		/* errno is set */
		if (errno != EEXIST)
			return (-2);
	}

	(void) strcat(filename, "/");
	(void) strcat(filename, name);

	if (temp_filename) {
		(void) strcpy(temp_filename, filename);
		(void) strcat(temp_filename, "XXXXXX");
	}

	return (0);
}

scf_type_t
scf_true_base_type(scf_type_t type)
{
	scf_type_t base = type;

	do {
		type = base;
		(void) scf_type_base_type(type, &base);
	} while (base != type);

	return (base);
}

/*
 * Convenience routine which frees all strings and opaque data
 * allocated by scf_read_propvec.
 *
 * Like free(3C), this function preserves the value of errno.
 */
void
scf_clean_propvec(scf_propvec_t *propvec)
{
	int saved_errno = errno;
	scf_propvec_t *prop;

	for (prop = propvec; prop->pv_prop != NULL; prop++) {
		assert(prop->pv_type != SCF_TYPE_INVALID);
		if (prop->pv_type == SCF_TYPE_OPAQUE) {
			scf_opaque_t *o = prop->pv_ptr;

			if (o->so_addr != NULL)
				free(o->so_addr);
		} else if (scf_true_base_type(prop->pv_type) ==
		    SCF_TYPE_ASTRING) {
			if (*(char **)prop->pv_ptr != NULL)
				free(*(char **)prop->pv_ptr);
		}
	}

	errno = saved_errno;
}

static int
count_props(scf_propvec_t *props)
{
	int count = 0;

	for (; props->pv_prop != NULL; props++)
		count++;
	return (count);
}

/*
 * Reads a vector of properties from the specified fmri/property group.
 * If 'running' is true, reads from the running snapshot instead of the
 * editing snapshot.
 *
 * For string types, a buffer is allocated using malloc(3C) to hold the
 * zero-terminated string, a pointer to which is stored in the
 * caller-provided char **.  It is the caller's responsbility to free
 * this string.  To simplify error handling, unread strings are
 * initialized to NULL.
 *
 * For opaque types, a buffer is allocated using malloc(3C) to hold the
 * opaque data.  A pointer to this buffer and its size are stored in
 * the caller-provided scf_opaque_t.  It is the caller's responsibility
 * to free this buffer.  To simplify error handling, the address fields
 * for unread opaque data are initialized to NULL.
 *
 * All other data is stored directly in caller-provided variables or
 * structures.
 *
 * If this function fails to read a specific property, *badprop is set
 * to point at that property's entry in the properties array.
 *
 * On all failures, all memory allocated by this function is freed.
 */
int
scf_read_propvec(const char *fmri, const char *pgname, boolean_t running,
    scf_propvec_t *properties, scf_propvec_t **badprop)
{
	scf_handle_t *h = _scf_handle_create_and_bind(SCF_VERSION);
	scf_service_t *s = scf_service_create(h);
	scf_instance_t *i = scf_instance_create(h);
	scf_snapshot_t *snap = running ? scf_snapshot_create(h) : NULL;
	scf_propertygroup_t *pg = scf_pg_create(h);
	scf_property_t *p = scf_property_create(h);
	scf_value_t *v = scf_value_create(h);
	boolean_t instance = B_TRUE;
	scf_propvec_t *prop;
	int error = 0;

	if (h == NULL || s == NULL || i == NULL || (running && snap == NULL) ||
	    pg == NULL || p == NULL || v == NULL)
		goto scferror;

	if (scf_handle_decode_fmri(h, fmri, NULL, s, i, NULL, NULL, 0) == -1)
		goto scferror;

	if (scf_instance_to_fmri(i, NULL, 0) == -1) {
		if (scf_error() != SCF_ERROR_NOT_SET)
			goto scferror;
		instance = B_FALSE;
	}

	if (running) {
		if (!instance) {
			error = SCF_ERROR_TYPE_MISMATCH;
			goto out;
		}

		if (scf_instance_get_snapshot(i, "running", snap) !=
		    SCF_SUCCESS)
			goto scferror;
	}

	if ((instance ? scf_instance_get_pg_composed(i, snap, pgname, pg) :
	    scf_service_get_pg(s, pgname, pg)) == -1)
		goto scferror;

	for (prop = properties; prop->pv_prop != NULL; prop++) {
		if (prop->pv_type == SCF_TYPE_OPAQUE)
			((scf_opaque_t *)prop->pv_ptr)->so_addr = NULL;
		else if (scf_true_base_type(prop->pv_type) == SCF_TYPE_ASTRING)
			*((char **)prop->pv_ptr) = NULL;
	}

	for (prop = properties; prop->pv_prop != NULL; prop++) {
		int ret = 0;

		if (scf_pg_get_property(pg, prop->pv_prop, p) == -1 ||
		    scf_property_get_value(p, v) == -1) {
			*badprop = prop;
			goto scferror;
		}
		switch (prop->pv_type) {
		case SCF_TYPE_BOOLEAN: {
			uint8_t b;

			ret = scf_value_get_boolean(v, &b);
			if (ret == -1)
				break;
			if (prop->pv_aux != 0) {
				uint64_t *bits = prop->pv_ptr;
				*bits = b ? (*bits | prop->pv_aux) :
				    (*bits & ~prop->pv_aux);
			} else {
				boolean_t *bool = prop->pv_ptr;
				*bool = b ? B_TRUE : B_FALSE;
			}
			break;
		}
		case SCF_TYPE_COUNT:
			ret = scf_value_get_count(v, prop->pv_ptr);
			break;
		case SCF_TYPE_INTEGER:
			ret = scf_value_get_integer(v, prop->pv_ptr);
			break;
		case SCF_TYPE_TIME: {
			scf_time_t *time = prop->pv_ptr;

			ret = scf_value_get_time(v, &time->t_seconds,
			    &time->t_ns);
			break;
		}
		case SCF_TYPE_OPAQUE: {
			scf_opaque_t *opaque = prop->pv_ptr;
			ssize_t size = scf_value_get_opaque(v, NULL, 0);

			if (size == -1) {
				*badprop = prop;
				goto scferror;
			}
			if ((opaque->so_addr = malloc(size)) == NULL) {
				error = SCF_ERROR_NO_MEMORY;
				goto out;
			}
			opaque->so_size = size;
			ret = scf_value_get_opaque(v, opaque->so_addr, size);
			break;
		}
		default: {
			char *s;
			ssize_t size;

			assert(scf_true_base_type(prop->pv_type) ==
			    SCF_TYPE_ASTRING);

			size = scf_value_get_astring(v, NULL, 0);
			if (size == -1) {
				*badprop = prop;
				goto scferror;
			}
			if ((s = malloc(++size)) == NULL) {
				error = SCF_ERROR_NO_MEMORY;
				goto out;
			}
			ret = scf_value_get_astring(v, s, size);
			*(char **)prop->pv_ptr = s;
		}

		if (ret == -1) {
			*badprop = prop;
			goto scferror;
		}

		}
	}

	goto out;

scferror:
	error = scf_error();
	scf_clean_propvec(properties);

out:
	scf_value_destroy(v);
	scf_property_destroy(p);
	scf_pg_destroy(pg);
	scf_snapshot_destroy(snap);
	scf_instance_destroy(i);
	scf_service_destroy(s);
	scf_handle_destroy(h);

	if (error != 0) {
		(void) scf_set_error(error);
		return (SCF_FAILED);
	}

	return (SCF_SUCCESS);
}

/*
 * Writes a vector of properties to the specified fmri/property group.
 *
 * If this function fails to write a specific property, *badprop is set
 * to point at that property's entry in the properties array.
 *
 * One significant difference between this function and the
 * scf_read_propvec function is that for string types, pv_ptr is a
 * char *, not a char **.  This means that you can't write a propvec
 * you just read, but makes other uses (hopefully the majority) simpler.
 */
int
scf_write_propvec(const char *fmri, const char *pgname,
    scf_propvec_t *properties, scf_propvec_t **badprop)
{
	scf_handle_t *h = _scf_handle_create_and_bind(SCF_VERSION);
	scf_service_t *s = scf_service_create(h);
	scf_instance_t *inst = scf_instance_create(h);
	scf_snapshot_t *snap = scf_snapshot_create(h);
	scf_propertygroup_t *pg = scf_pg_create(h);
	scf_property_t *p = scf_property_create(h);
	scf_transaction_t *tx = scf_transaction_create(h);
	scf_value_t **v = NULL;
	scf_transaction_entry_t **e = NULL;
	boolean_t instance = B_TRUE;
	int i, n;
	scf_propvec_t *prop;
	int error = 0, ret;

	n = count_props(properties);
	v = calloc(n, sizeof (scf_value_t *));
	e = calloc(n, sizeof (scf_transaction_entry_t *));

	if (v == NULL || e == NULL) {
		error = SCF_ERROR_NO_MEMORY;
		goto out;
	}

	if (h == NULL || s == NULL || inst == NULL || pg == NULL || p == NULL ||
	    tx == NULL)
		goto scferror;

	for (i = 0; i < n; i++) {
		v[i] = scf_value_create(h);
		e[i] = scf_entry_create(h);
		if (v[i] == NULL || e[i] == NULL)
			goto scferror;
	}

	if (scf_handle_decode_fmri(h, fmri, NULL, s, inst, NULL, NULL, 0)
	    != SCF_SUCCESS)
		goto scferror;

	if (scf_instance_to_fmri(inst, NULL, 0) == -1) {
		if (scf_error() != SCF_ERROR_NOT_SET)
			goto scferror;
		instance = B_FALSE;
	}

	if ((instance ? scf_instance_get_pg(inst, pgname, pg) :
	    scf_service_get_pg(s, pgname, pg)) == -1)
		goto scferror;

top:
	if (scf_transaction_start(tx, pg) == -1)
		goto scferror;

	for (prop = properties, i = 0; prop->pv_prop != NULL; prop++, i++) {
		ret = scf_transaction_property_change(tx, e[i], prop->pv_prop,
		    prop->pv_type);
		if (ret == -1 && scf_error() == SCF_ERROR_NOT_FOUND)
			ret = scf_transaction_property_new(tx, e[i],
			    prop->pv_prop, prop->pv_type);

		if (ret == -1) {
			*badprop = prop;
			goto scferror;
		}

		switch (prop->pv_type) {
		case SCF_TYPE_BOOLEAN: {
			boolean_t b = (prop->pv_aux != 0) ?
			    (*(uint64_t *)prop->pv_ptr & prop->pv_aux) != 0 :
			    *(boolean_t *)prop->pv_ptr;

			scf_value_set_boolean(v[i], b ? 1 : 0);
			break;
		}
		case SCF_TYPE_COUNT:
			scf_value_set_count(v[i], *(uint64_t *)prop->pv_ptr);
			break;
		case SCF_TYPE_INTEGER:
			scf_value_set_integer(v[i], *(int64_t *)prop->pv_ptr);
			break;
		case SCF_TYPE_TIME: {
			scf_time_t *time = prop->pv_ptr;

			ret = scf_value_set_time(v[i], time->t_seconds,
			    time->t_ns);
			break;
		}
		case SCF_TYPE_OPAQUE: {
			scf_opaque_t *opaque = prop->pv_ptr;

			ret = scf_value_set_opaque(v[i], opaque->so_addr,
			    opaque->so_size);
			break;
		}
		case SCF_TYPE_ASTRING:
			ret = scf_value_set_astring(v[i],
			    (const char *)prop->pv_ptr);
			break;
		default:
			ret = scf_value_set_from_string(v[i], prop->pv_type,
			    (const char *)prop->pv_ptr);
		}

		if (ret == -1 || scf_entry_add_value(e[i], v[i]) == -1) {
			*badprop = prop;
			goto scferror;
		}
	}

	ret = scf_transaction_commit(tx);
	if (ret == 1)
		goto out;

	if (ret == 0 && scf_pg_update(pg) != -1) {
		scf_transaction_reset(tx);
		goto top;
	}

scferror:
	error = scf_error();

out:
	if (v != NULL) {
		for (i = 0; i < n; i++)
			scf_value_destroy(v[i]);
		free(v);
	}

	if (e != NULL) {
		for (i = 0; i < n; i++)
			scf_entry_destroy(e[i]);
		free(e);
	}

	scf_transaction_destroy(tx);
	scf_property_destroy(p);
	scf_pg_destroy(pg);
	scf_snapshot_destroy(snap);
	scf_instance_destroy(inst);
	scf_service_destroy(s);
	scf_handle_destroy(h);

	if (error != 0) {
		(void) scf_set_error(error);
		return (SCF_FAILED);
	}

	return (SCF_SUCCESS);
}

/*
 * Returns
 *   0 - success
 *   ECONNABORTED - repository connection broken
 *   ECANCELED - inst was deleted
 *   EPERM
 *   EACCES
 *   EROFS
 *   ENOMEM
 */
int
scf_instance_delete_prop(scf_instance_t *inst, const char *pgname,
    const char *pname)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg;
	scf_transaction_t *tx;
	scf_transaction_entry_t *e;
	int error = 0, ret = 1, r;

	h = scf_instance_handle(inst);

	if ((pg = scf_pg_create(h)) == NULL) {
		return (ENOMEM);
	}

	if (scf_instance_get_pg(inst, pgname, pg) != 0) {
		error = scf_error();
		scf_pg_destroy(pg);
		switch (error) {
		case SCF_ERROR_NOT_FOUND:
			return (SCF_SUCCESS);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg", scf_error());
		}
	}

	tx = scf_transaction_create(h);
	e = scf_entry_create(h);
	if (tx == NULL || e == NULL) {
		ret = ENOMEM;
		goto out;
	}

	for (;;) {
		if (scf_transaction_start(tx, pg) != 0) {
			goto scferror;
		}

		if (scf_transaction_property_delete(tx, e, pname) != 0) {
			goto scferror;
		}

		if ((r = scf_transaction_commit(tx)) == 1) {
			ret = 0;
			goto out;
		}

		if (r == -1) {
			goto scferror;
		}

		scf_transaction_reset(tx);
		if (scf_pg_update(pg) == -1) {
			goto scferror;
		}
	}

scferror:
	switch (scf_error()) {
	case SCF_ERROR_DELETED:
	case SCF_ERROR_NOT_FOUND:
		ret = 0;
		break;

	case SCF_ERROR_PERMISSION_DENIED:
		ret = EPERM;
		break;

	case SCF_ERROR_BACKEND_ACCESS:
		ret = EACCES;
		break;

	case SCF_ERROR_BACKEND_READONLY:
		ret = EROFS;
		break;

	case SCF_ERROR_CONNECTION_BROKEN:
	default:
		ret = ECONNABORTED;
		break;

	case SCF_ERROR_HANDLE_MISMATCH:
	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_NOT_BOUND:
	case SCF_ERROR_NOT_SET:
		bad_error("scf_instance_delete_prop", scf_error());
	}

out:
	scf_transaction_destroy(tx);
	scf_entry_destroy(e);
	scf_pg_destroy(pg);

	return (ret);
}

/*
 * Check the "application/auto_enable" property for the passed FMRI.
 * scf_simple_prop_get() should find the property on an instance
 * or on the service FMRI.  The routine returns:
 * -1: inconclusive (likely no such property or FMRI)
 *  0: auto_enable is false
 *  1: auto_enable is true
 */
static int
is_auto_enabled(char *fmri)
{
	scf_simple_prop_t *prop;
	int retval = -1;
	uint8_t *ret;

	prop = scf_simple_prop_get(NULL, fmri, SCF_GROUP_APPLICATION,
	    "auto_enable");
	if (!prop)
		return (retval);
	ret = scf_simple_prop_next_boolean(prop);
	retval = (*ret != 0);
	scf_simple_prop_free(prop);
	return (retval);
}

/*
 * Check an array of services and enable any that don't have the
 * "application/auto_enable" property set to "false", which is
 * the interface to turn off this behaviour (see PSARC 2004/739).
 */
void
_check_services(char **svcs)
{
	char *s;

	for (; *svcs; svcs++) {
		if (is_auto_enabled(*svcs) == 0)
			continue;
		if ((s = smf_get_state(*svcs)) != NULL) {
			if (strcmp(SCF_STATE_STRING_DISABLED, s) == 0)
				(void) smf_enable_instance(*svcs,
				    SMF_TEMPORARY);
			free(s);
		}
	}
}

/*ARGSUSED*/
static int
str_compare(const char *s1, const char *s2, size_t n)
{
	return (strcmp(s1, s2));
}

static int
str_n_compare(const char *s1, const char *s2, size_t n)
{
	return (strncmp(s1, s2, n));
}

int32_t
state_from_string(const char *state, size_t l)
{
	int (*str_cmp)(const char *, const char *, size_t);

	if (l == 0)
		str_cmp = str_compare;
	else
		str_cmp = str_n_compare;

	if (str_cmp(SCF_STATE_STRING_UNINIT, state, l) == 0)
		return (SCF_STATE_UNINIT);
	else if (str_cmp(SCF_STATE_STRING_MAINT, state, l) == 0)
		return (SCF_STATE_MAINT);
	else if (str_cmp(SCF_STATE_STRING_OFFLINE, state, l) == 0)
		return (SCF_STATE_OFFLINE);
	else if (str_cmp(SCF_STATE_STRING_DISABLED, state, l) == 0)
		return (SCF_STATE_DISABLED);
	else if (str_cmp(SCF_STATE_STRING_ONLINE, state, l) == 0)
		return (SCF_STATE_ONLINE);
	else if (str_cmp(SCF_STATE_STRING_DEGRADED, state, l) == 0)
		return (SCF_STATE_DEGRADED);
	else if (str_cmp("all", state, l) == 0)
		return (SCF_STATE_ALL);
	else
		return (-1);
}

/*
 * int32_t smf_state_from_string()
 * return the value of the macro SCF_STATE_* for the corresponding state
 * it returns SCF_STATE_ALL if "all" is passed. -1 if the string passed doesn't
 * correspond to any valid state.
 */
int32_t
smf_state_from_string(const char *state)
{
	return (state_from_string(state, 0));
}

/*
 * smf_state_to_string()
 * Takes an int32_t representing an SMF state and returns
 * the corresponding string. The string is read only and need not to be
 * freed.
 * returns NULL on invalid input.
 */
const char *
smf_state_to_string(int32_t s)
{
	switch (s) {
	case SCF_STATE_UNINIT:
		return (SCF_STATE_STRING_UNINIT);
	case SCF_STATE_MAINT:
		return (SCF_STATE_STRING_MAINT);
	case SCF_STATE_OFFLINE:
		return (SCF_STATE_STRING_OFFLINE);
	case SCF_STATE_DISABLED:
		return (SCF_STATE_STRING_DISABLED);
	case SCF_STATE_ONLINE:
		return (SCF_STATE_STRING_ONLINE);
	case SCF_STATE_DEGRADED:
		return (SCF_STATE_STRING_DEGRADED);
	case SCF_STATE_ALL:
		return ("all");
	default:
		return (NULL);
	}
}
