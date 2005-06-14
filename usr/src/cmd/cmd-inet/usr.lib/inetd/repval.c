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
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains routines to manipulate lists of repository values that
 * are used to store process ids and the internal state. There are routines
 * to read/write the lists from/to the repository and routines to modify or
 * inspect the lists. It also contains routines that deal with the
 * repository side of contract ids.
 */

#include <errno.h>
#include <stdlib.h>
#include <libintl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "inetd_impl.h"


/*
 * Number of consecutive repository bind retries performed by bind_to_rep()
 * before failing.
 */
#define	BIND_TO_REP_RETRIES	10

/* Name of property group where inetd's state for a service is stored. */
#define	PG_NAME_INSTANCE_STATE (const char *) "inetd_state"

/* uu_list repval list pool */
static uu_list_pool_t *rep_val_pool = NULL;

/*
 * Repository object pointers that get set-up in repval_init() and closed down
 * in repval_fini(). They're used in _retrieve_rep_vals(), _store_rep_vals(),
 * add_remove_contract_norebind(), and adopt_repository_contracts().  They're
 * global so they can be initialized once on inetd startup, and re-used
 * there-after in the referenced functions.
 */
static scf_handle_t		*rep_handle = NULL;
static scf_propertygroup_t	*pg = NULL;
static scf_instance_t		*inst = NULL;
static scf_transaction_t	*trans = NULL;
static scf_transaction_entry_t	*entry = NULL;
static scf_property_t		*prop = NULL;

/*
 * Try and make the given handle bind be bound to the repository. If
 * it's already bound, or we succeed a new bind return 0; else return
 * -1 on failure, with the SCF error set to one of the following:
 * SCF_ERROR_NO_SERVER
 * SCF_ERROR_NO_RESOURCES
 */
int
make_handle_bound(scf_handle_t *hdl)
{
	uint_t retries;

	for (retries = 0; retries <= BIND_TO_REP_RETRIES; retries++) {
		if ((scf_handle_bind(hdl) == 0) ||
		    (scf_error() == SCF_ERROR_IN_USE))
			return (0);

		assert(scf_error() != SCF_ERROR_INVALID_ARGUMENT);
	}

	return (-1);
}

int
repval_init(void)
{
	debug_msg("Entering repval_init");

	/*
	 * Create the repval list pool.
	 */
	rep_val_pool = uu_list_pool_create("rep_val_pool", sizeof (rep_val_t),
	    offsetof(rep_val_t, link), NULL, UU_LIST_POOL_DEBUG);
	if (rep_val_pool == NULL) {
		error_msg("%s: %s", gettext("Failed to create rep_val pool"),
		    uu_strerror(uu_error()));
		return (-1);
	}

	/*
	 * Create and bind a repository handle, and create all repository
	 * objects that we'll use later that are associated with it. On any
	 * errors we simply return -1 and let repval_fini() clean-up after
	 * us.
	 */
	if ((rep_handle = scf_handle_create(SCF_VERSION)) == NULL) {
		error_msg("%s: %s",
		    gettext("Failed to create repository handle"),
		    scf_strerror(scf_error()));
		goto cleanup;
	} else if (make_handle_bound(rep_handle) == -1) {
		goto cleanup;
	} else if (((pg = scf_pg_create(rep_handle)) == NULL) ||
	    ((inst = scf_instance_create(rep_handle)) == NULL) ||
	    ((trans = scf_transaction_create(rep_handle)) == NULL) ||
	    ((entry = scf_entry_create(rep_handle)) == NULL) ||
	    ((prop = scf_property_create(rep_handle)) == NULL)) {
		error_msg("%s: %s",
		    gettext("Failed to create repository object"),
		    scf_strerror(scf_error()));
		goto cleanup;
	}

	return (0);
cleanup:
	repval_fini();
	return (-1);
}

void
repval_fini(void)
{
	debug_msg("Entering repval_fini");

	if (rep_handle != NULL) {
		/*
		 * We unbind from the repository before we free the repository
		 * objects for efficiency reasons.
		 */
		(void) scf_handle_unbind(rep_handle);

		scf_pg_destroy(pg);
		pg = NULL;
		scf_instance_destroy(inst);
		inst = NULL;
		scf_transaction_destroy(trans);
		trans = NULL;
		scf_entry_destroy(entry);
		entry = NULL;
		scf_property_destroy(prop);
		prop = NULL;

		scf_handle_destroy(rep_handle);
		rep_handle = NULL;
	}

	if (rep_val_pool != NULL) {
		uu_list_pool_destroy(rep_val_pool);
		rep_val_pool = NULL;
	}
}

uu_list_t *
create_rep_val_list(void)
{
	uu_list_t	*ret;

	debug_msg("Entering create_rep_val_list");

	if ((ret = uu_list_create(rep_val_pool, NULL, 0)) == NULL)
		assert(uu_error() == UU_ERROR_NO_MEMORY);

	return (ret);
}

void
destroy_rep_val_list(uu_list_t *list)
{
	debug_msg("Entering destroy_rep_val_list");

	if (list != NULL) {
		empty_rep_val_list(list);
		uu_list_destroy(list);
	}
}

rep_val_t *
find_rep_val(uu_list_t *list, int64_t val)
{
	rep_val_t *rv;

	debug_msg("Entering find_rep_val: val: %lld", val);

	for (rv = uu_list_first(list); rv != NULL;
	    rv = uu_list_next(list, rv)) {
		if (rv->val == val)
			break;
	}
	return (rv);
}

int
add_rep_val(uu_list_t *list, int64_t val)
{
	rep_val_t *rv;

	debug_msg("Entering add_rep_val: val: %lld", val);

	if ((rv = malloc(sizeof (rep_val_t))) == NULL)
		return (-1);

	uu_list_node_init(rv, &rv->link, rep_val_pool);
	rv->val = val;
	rv->scf_val = NULL;
	(void) uu_list_insert_after(list, NULL, rv);

	return (0);
}

void
remove_rep_val(uu_list_t *list, int64_t val)
{
	rep_val_t *rv;

	debug_msg("Entering remove_rep_val: val: %lld", val);

	if ((rv = find_rep_val(list, val)) != NULL) {
		uu_list_remove(list, rv);
		assert(rv->scf_val == NULL);
		free(rv);
	}
}

void
empty_rep_val_list(uu_list_t *list)
{
	void		*cookie = NULL;
	rep_val_t	*rv;

	debug_msg("Entering empty_rep_val_list");

	while ((rv = uu_list_teardown(list, &cookie)) != NULL) {
		if (rv->scf_val != NULL)
			scf_value_destroy(rv->scf_val);
		free(rv);
	}
}

int64_t
get_single_rep_val(uu_list_t *list)
{
	rep_val_t *rv = uu_list_first(list);

	debug_msg("Entering get_single_rep_val");

	assert(rv != NULL);
	return (rv->val);
}

int
set_single_rep_val(uu_list_t *list, int64_t val)
{
	rep_val_t *rv = uu_list_first(list);

	debug_msg("Entering set_single_rep_val");

	if (rv == NULL) {
		if (add_rep_val(list, val) == -1)
			return (-1);
	} else {
		rv->val = val;
	}

	return (0);
}

/*
 * Partner to add_tr_entry_values. This function frees the scf_values created
 * in add_tr_entry_values() in the list 'vals'.
 */
static void
remove_tr_entry_values(uu_list_t *vals)
{
	rep_val_t	*rval;

	debug_msg("Entering remove_tr_entry_values");

	for (rval = uu_list_first(vals); rval != NULL;
	    rval = uu_list_next(vals, rval)) {
		if (rval->scf_val != NULL) {
			scf_value_destroy(rval->scf_val);
			rval->scf_val = NULL;
		}
	}
}

/*
 * This function creates and associates with transaction entry 'entry' an
 * scf value for each value in 'vals'. The pointers to the scf values
 * are stored in the list for later cleanup by remove_tr_entry_values.
 * Returns 0 on success, else -1 on error with scf_error() set to:
 * SCF_ERROR_NO_MEMORY if memory allocation failed.
 * SCF_ERROR_CONNECTION_BROKEN if the connection to the repository was broken.
 */
static int
add_tr_entry_values(scf_handle_t *hdl, scf_transaction_entry_t *entry,
    uu_list_t *vals)
{
	rep_val_t *rval;

	debug_msg("Entering add_tr_entry_values");

	for (rval = uu_list_first(vals); rval != NULL;
	    rval = uu_list_next(vals, rval)) {

		assert(rval->scf_val == NULL);
		if ((rval->scf_val = scf_value_create(hdl)) == NULL) {
			remove_tr_entry_values(vals);
			return (-1);
		}

		scf_value_set_integer(rval->scf_val, rval->val);

		if (scf_entry_add_value(entry, rval->scf_val) < 0) {
			remove_tr_entry_values(vals);
			return (-1);
		}
	}

	return (0);
}

/*
 * Stores the values contained in the list 'vals' into the property 'prop_name'
 * of the instance with fmri 'inst_fmri', within the instance's instance
 * state property group.
 *
 * Returns 0 on success, else one of the following on failure:
 * SCF_ERROR_NO_MEMORY if memory allocation failed.
 * SCF_ERROR_NO_RESOURCES if the server doesn't have required resources.
 * SCF_ERROR_VERSION_MISMATCH if program compiled against a newer libscf
 * than on system.
 * SCF_ERROR_PERMISSION_DENIED if insufficient privileges to modify pg.
 * SCF_ERROR_BACKEND_ACCESS if the repository back-end refused the pg modify.
 * SCF_ERROR_CONNECTION_BROKEN if the connection to the repository was broken.
 */
static scf_error_t
_store_rep_vals(uu_list_t *vals, const char *inst_fmri, const char *prop_name)
{
	int			cret;
	int			ret;

	debug_msg("Entering _store_rep_vals: fmri: %s, prop: %s", inst_fmri,
	    prop_name);

	if (scf_handle_decode_fmri(rep_handle, inst_fmri, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) == -1)
		return (scf_error());

	/*
	 * Fetch the instance state pg, and if it doesn't exist try and
	 * create it.
	 */
	if (scf_instance_get_pg(inst, PG_NAME_INSTANCE_STATE, pg) < 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			return (scf_error());
		if (scf_instance_add_pg(inst, PG_NAME_INSTANCE_STATE,
		    SCF_GROUP_FRAMEWORK, SCF_PG_FLAG_NONPERSISTENT, pg) < 0)
			return (scf_error());
	}

	/*
	 * Perform a transaction to write the values to the requested property.
	 * If someone got there before us, loop and retry.
	 */
	do {
		if (scf_transaction_start(trans, pg) < 0)
			return (scf_error());

		if ((scf_transaction_property_new(trans, entry,
		    prop_name, SCF_TYPE_INTEGER) < 0) &&
		    (scf_transaction_property_change_type(trans, entry,
		    prop_name, SCF_TYPE_INTEGER) < 0)) {
			ret = scf_error();
			goto cleanup;
		}

		if (add_tr_entry_values(rep_handle, entry, vals) < 0) {
			ret = scf_error();
			goto cleanup;
		}

		if ((cret = scf_transaction_commit(trans)) < 0) {
			ret = scf_error();
			goto cleanup;
		} else if (cret == 0) {
			scf_transaction_reset(trans);
			scf_entry_reset(entry);
			remove_tr_entry_values(vals);
			if (scf_pg_update(pg) < 0) {
				ret = scf_error();
				goto cleanup;
			}
		}
	} while (cret == 0);

	ret = 0;
cleanup:
	scf_transaction_reset(trans);
	scf_entry_reset(entry);
	remove_tr_entry_values(vals);
	return (ret);
}

/*
 * Retrieves the repository values of property 'prop_name', of the instance
 * with fmri 'fmri', from within the instance's instance state property
 * group and adds them to the value list 'list'.
 *
 * Returns 0 on success, else one of the following values on error:
 * SCF_ERROR_NOT_FOUND if the property doesn't exist.
 * SCF_ERROR_NO_MEMORY if memory allocation failed.
 * SCF_ERROR_CONNECTION_BROKEN if the connection to the repository was broken.
 * SCF_ERROR_TYPE_MISMATCH if the property was of an unexpected type.
 *
 */
static scf_error_t
_retrieve_rep_vals(uu_list_t *list, const char *fmri, const char *prop_name)
{
	scf_simple_prop_t	*sp;
	int64_t			*ip;

	debug_msg("Entering _retrieve_rep_vals: fmri: %s, prop: %s", fmri,
	    prop_name);

	if ((sp = scf_simple_prop_get(rep_handle, fmri, PG_NAME_INSTANCE_STATE,
	    prop_name)) == NULL)
		return (scf_error());

	while ((ip = scf_simple_prop_next_integer(sp)) != NULL) {
		if (add_rep_val(list, *ip) == -1) {
			empty_rep_val_list(list);
			scf_simple_prop_free(sp);
			return (SCF_ERROR_NO_MEMORY);
		}
	}
	if (scf_error() != SCF_ERROR_NONE) {
		assert(scf_error() == SCF_ERROR_TYPE_MISMATCH);
		empty_rep_val_list(list);
		scf_simple_prop_free(sp);
		return (scf_error());
	}

	scf_simple_prop_free(sp);
	return (0);
}

/*
 * A routine that loops trying to read/write repository values until
 * either success, an error other that a broken repository connection or
 * the number of retries reaches REP_OP_RETRIES.
 * Returns 0 on success, else the error value from either _store_rep_vals or
 * retrieve_rep_vals (based on whether 'store' was set or not), or one of the
 * following if a rebind failed:
 * SCF_ERROR_NO_RESOURCES if the server doesn't have adequate resources.
 * SCF_ERROR_NO_SERVER if the server isn't running.
 */
static scf_error_t
store_retrieve_rep_vals(uu_list_t *vals, const char *fmri,
    const char *prop, boolean_t store)
{
	scf_error_t	ret;
	uint_t		retries;

	debug_msg("Entering store_retrieve_rep_vals, store: %d", store);


	for (retries = 0; retries <= REP_OP_RETRIES; retries++) {
		if (make_handle_bound(rep_handle) == -1) {
			ret = scf_error();
			break;
		}

		if ((ret = (store ? _store_rep_vals(vals, fmri, prop) :
		    _retrieve_rep_vals(vals, fmri, prop))) !=
		    SCF_ERROR_CONNECTION_BROKEN)
			break;

		(void) scf_handle_unbind(rep_handle);
	}

	return (ret);
}

scf_error_t
store_rep_vals(uu_list_t *vals, const char *fmri, const char *prop)
{
	return (store_retrieve_rep_vals(vals, fmri, prop, B_TRUE));
}

scf_error_t
retrieve_rep_vals(uu_list_t *vals, const char *fmri, const char *prop)
{
	return (store_retrieve_rep_vals(vals, fmri, prop, B_FALSE));
}

/*
 * Fails with ECONNABORTED, ENOENT, EACCES, EROFS, ENOMEM, or EPERM.
 */
static int
add_remove_contract_norebind(const char *fmri, boolean_t add, ctid_t ctid)
{
	int err;

	if (scf_handle_decode_fmri(rep_handle, fmri, NULL, NULL, inst, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			return (ECONNABORTED);

		case SCF_ERROR_NOT_FOUND:
			return (ENOENT);

		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			assert(0);
			abort();
		}
	}

redo:
	if (add)
		err = restarter_store_contract(inst, ctid,
		    RESTARTER_CONTRACT_PRIMARY);
	else
		err = restarter_remove_contract(inst, ctid,
		    RESTARTER_CONTRACT_PRIMARY);
	switch (err) {
	case 0:
	case ENOMEM:
	case ECONNABORTED:
		return (err);

	case ECANCELED:
		return (ENOENT);

	case EPERM:
		assert(0);
		return (err);

	case EACCES:
		error_msg(add ? gettext("Failed to write contract id %ld for "
		    "instance %s to repository: backend access denied.") :
		    gettext("Failed to remove contract id %ld for instance %s "
		    "from repository: backend access denied."), ctid, fmri);
		return (err);

	case EROFS:
		error_msg(add ? gettext("Failed to write contract id %ld for "
		    "instance %s to repository: backend is read-only.") :
		    gettext("Failed to remove contract id %ld for instance %s "
		    "from repository: backend is read-only."), ctid, fmri);
		return (err);

	case EINVAL:
	case EBADF:
	default:
		assert(0);
		abort();
		/* NOTREACHED */
	}
}

/*
 * Tries to add/remove (dependent on the value of 'add') the specified
 * contract id to the specified instance until either success, an error
 * other that connection broken occurs, or the number of bind retries reaches
 * REP_OP_RETRIES.
 * Returns 0 on success else fails with one of ENOENT, EACCES, EROFS, EPERM,
 * ECONNABORTED or ENOMEM.
 */
int
add_remove_contract(const char *fmri, boolean_t add, ctid_t ctid)
{
	uint_t	retries;
	int	err;

	for (retries = 0; retries <= REP_OP_RETRIES; retries++) {
		if (make_handle_bound(rep_handle) == -1) {
			err = ECONNABORTED;
			break;
		}

		if ((err = add_remove_contract_norebind(fmri, add, ctid)) !=
		    ECONNABORTED)
			break;

		(void) scf_handle_unbind(rep_handle);
	}

	return (err);
}

/*
 * Iterate over all contracts associated with the instance specified by
 * fmri; if sig !=0, we send each contract the specified signal, otherwise
 * we call adopt_contract() to take ownership.  This really ought to be
 * reworked to use a callback mechanism if more functionality is added.
 *
 * Returns 0 on success or ENOENT if the instance, its restarter property
 * group, or its contract property don't exist, or EINVAL if the property
 * is not of the correct type, ENOMEM if there was a memory allocation
 * failure, EPERM if there were permission problems accessing the repository,
 * or ECONNABORTED if the connection with the repository was broken.
 */
int
iterate_repository_contracts(const char *fmri, int sig)
{
	scf_iter_t	*iter;
	scf_value_t	*val = NULL;
	uint64_t	c;
	int		err;
	int		ret = 0;
	uint_t		retries = 0;

	debug_msg("Entering iterate_repository_contracts");

	if (make_handle_bound(rep_handle) == -1)
		return (ECONNABORTED);

	if (((iter = scf_iter_create(rep_handle)) == NULL) ||
	    ((val = scf_value_create(rep_handle)) == NULL)) {
		ret = ENOMEM;
		goto out;
	}

rep_retry:
	if (scf_handle_decode_fmri(rep_handle, fmri, NULL, NULL, inst, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
rebind:
			(void) scf_handle_unbind(rep_handle);

			if (retries++ == REP_OP_RETRIES) {
				ret = ECONNABORTED;
				goto out;
			}

			if (make_handle_bound(rep_handle) == -1) {
				ret = ECONNABORTED;
				goto out;
			}

			goto rep_retry;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			assert(0);
			abort();
		}
	}

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			goto rebind;

		case SCF_ERROR_NOT_SET:
			ret = 0;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			assert(0);
			abort();
		}
	}

	if (scf_pg_get_property(pg, SCF_PROPERTY_CONTRACT, prop) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			goto rebind;

		case SCF_ERROR_NOT_SET:
			ret = 0;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			assert(0);
			abort();
		}
	}

	if (scf_property_is_type(prop, SCF_TYPE_COUNT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			goto rebind;

		case SCF_ERROR_NOT_SET:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_TYPE_MISMATCH:
			ret = EINVAL;
			goto out;

		default:
			assert(0);
			abort();
		}
	}

	if (scf_iter_property_values(iter, prop) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			goto rebind;

		case SCF_ERROR_NOT_SET:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			assert(0);
			abort();
		}
	}

	for (;;) {
		err = scf_iter_next_value(iter, val);
		if (err == 0) {
			break;
		} else if (err != 1) {
			assert(scf_error() == SCF_ERROR_CONNECTION_BROKEN);
			goto rebind;
		}

		err = scf_value_get_count(val, &c);
		assert(err == 0);

		if (sig == 0) {
			/* Try to adopt the contract */
			if (adopt_contract((ctid_t)c, fmri) != 0) {
				/*
				 * Adoption failed.  No reason to think it'll
				 * work later, so remove the id from our list
				 * in the repository.
				 *
				 * Beware: add_remove_contract_norebind() uses
				 * the global scf_ handles.  Fortunately we're
				 * done with them.  We need to be cognizant of
				 * repository disconnection, though.
				 */
				switch (add_remove_contract_norebind(fmri,
				    B_FALSE, (ctid_t)c)) {
				case 0:
				case ENOENT:
				case EACCES:
				case EROFS:
					break;

				case ECONNABORTED:
					goto rebind;

				default:
					assert(0);
					abort();
				}
			}
		} else {
			/*
			 * Send a signal to all in the contract; ESRCH just
			 * means they all exited before we could kill them
			 */
			if (sigsend(P_CTID, (ctid_t)c, sig) == -1 &&
			    errno != ESRCH) {
				warn_msg(gettext("Unable to signal all contract"
				    "members of instance %s: %s"), fmri,
				    strerror(errno));
			}
		}
	}

out:
	scf_value_destroy(val);
	scf_iter_destroy(iter);
	return (ret);
}
