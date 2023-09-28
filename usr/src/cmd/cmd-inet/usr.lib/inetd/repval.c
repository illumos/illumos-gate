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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libscf_priv.h>
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
 * Pathname storage for paths generated from the fmri.
 * Used when updating the ctid and (start) pid files for an inetd service.
 */
static char genfmri_filename[MAXPATHLEN] = "";
static char genfmri_temp_filename[MAXPATHLEN] = "";

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

	if ((ret = uu_list_create(rep_val_pool, NULL, 0)) == NULL)
		assert(uu_error() == UU_ERROR_NO_MEMORY);

	return (ret);
}

void
destroy_rep_val_list(uu_list_t *list)
{
	if (list != NULL) {
		empty_rep_val_list(list);
		uu_list_destroy(list);
	}
}

rep_val_t *
find_rep_val(uu_list_t *list, int64_t val)
{
	rep_val_t *rv;

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

	assert(rv != NULL);
	return (rv->val);
}

int
set_single_rep_val(uu_list_t *list, int64_t val)
{
	rep_val_t *rv = uu_list_first(list);

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
 * Writes the repository values in the vals list to
 * a file that is generated based on the passed in fmri and name.
 * Returns 0 on success,
 * ENAMETOOLONG if unable to generate filename from fmri (including
 * the inability to create the directory for the generated filename) and
 * ENOENT on all other failures.
 */
static int
repvals_to_file(const char *fmri, const char *name, uu_list_t *vals)
{
	int		tfd;
	FILE		*tfp;		/* temp fp */
	rep_val_t	*spval;		/* Contains a start_pid or ctid */
	int		ret = 0;

	if (gen_filenms_from_fmri(fmri, name, genfmri_filename,
	    genfmri_temp_filename) != 0) {
		/* Failure either from fmri too long or mkdir failure */
		return (ENAMETOOLONG);
	}

	if ((tfd = mkstemp(genfmri_temp_filename)) == -1) {
		return (ENOENT);
	}

	if (fchmod(tfd, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
		(void) close(tfd);
		ret = ENOENT;
		goto unlink_out;
	}

	if ((tfp = fdopen(tfd, "w")) == NULL) {
		(void) close(tfd);
		ret = ENOENT;
		goto unlink_out;
	}

	for (spval = uu_list_first(vals); spval != NULL;
	    spval = uu_list_next(vals, spval)) {
		if (fprintf(tfp, "%lld\n", spval->val) <= 0) {
			(void) fclose(tfp);
			ret = ENOENT;
			goto unlink_out;
		}
	}
	if (fclose(tfp) != 0) {
		ret = ENOENT;
		goto unlink_out;
	}
	if (rename(genfmri_temp_filename, genfmri_filename) != 0) {
		ret = ENOENT;
		goto unlink_out;
	}
	return (0);

unlink_out:
	if (unlink(genfmri_temp_filename) != 0) {
		warn_msg(gettext("Removal of temp file "
		    "%s failed. Please remove manually."),
		    genfmri_temp_filename);
	}
	return (ret);
}

/*
 * A routine that loops trying to read/write values until either success,
 * an error other than a broken repository connection or
 * the number of retries reaches REP_OP_RETRIES.
 * This action is used to read/write the values:
 *   reads/writes to a file for the START_PIDS property due to scalability
 *	problems with libscf
 *   reads/writes to the repository for all other properties.
 * Returns 0 on success, else the error value from either _store_rep_vals or
 * _retrieve_rep_vals (based on whether 'store' was set or not), or one of the
 * following:
 * SCF_ERROR_NO_RESOURCES if the server doesn't have adequate resources
 * SCF_ERROR_NO_MEMORY if a memory allocation failure
 * SCF_ERROR_NO_SERVER if the server isn't running.
 * SCF_ERROR_CONSTRAINT_VIOLATED if an error in dealing with the speedy files
 */
static scf_error_t
store_retrieve_rep_vals(uu_list_t *vals, const char *fmri,
    const char *prop, boolean_t store)
{
	scf_error_t	ret = 0;
	uint_t		retries;
	FILE		*tfp;		/* temp fp */
	int64_t		tval;		/* temp val holder */
	int		fscanf_ret;
	int		fopen_retry_cnt = 2;

	/* inetd specific action for START_PIDS property */
	if (strcmp(prop, PR_NAME_START_PIDS) == 0) {
		/*
		 * Storage performance of START_PIDS is important,
		 * so each instance has its own file and all start_pids
		 * in the list are written to a temp file and then
		 * moved (renamed).
		 */
		if (store) {
			/* Write all values in list to file */
			if (repvals_to_file(fmri, "pid", vals)) {
				return (SCF_ERROR_CONSTRAINT_VIOLATED);
			}
		} else {
			/* no temp name needed */
			if (gen_filenms_from_fmri(fmri, "pid", genfmri_filename,
			    NULL) != 0)
				return (SCF_ERROR_CONSTRAINT_VIOLATED);

retry_fopen:
			/* It's ok if no file, there are just no pids */
			if ((tfp = fopen(genfmri_filename, "r")) == NULL) {
				if ((errno == EINTR) && (fopen_retry_cnt > 0)) {
					fopen_retry_cnt--;
					goto retry_fopen;
				}
				return (0);
			}
			/* fscanf may not set errno, so clear it first */
			errno = 0;
			while ((fscanf_ret = fscanf(tfp, "%lld", &tval)) == 1) {
				/* If tval isn't a valid pid, then fail. */
				if ((tval > MAXPID) || (tval <= 0)) {
					empty_rep_val_list(vals);
					return (SCF_ERROR_CONSTRAINT_VIOLATED);
				}
				if (add_rep_val(vals, tval) == -1) {
					empty_rep_val_list(vals);
					return (SCF_ERROR_NO_MEMORY);
				}
				errno = 0;
			}
			/* EOF is ok when no errno */
			if ((fscanf_ret != EOF) || (errno != 0)) {
				empty_rep_val_list(vals);
				return (SCF_ERROR_CONSTRAINT_VIOLATED);
			}
			if (fclose(tfp) != 0) {
				/* for close failure just log a message */
				warn_msg(gettext("Close of file %s failed."),
				    genfmri_filename);
			}
		}
	} else {
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
 * Adds/removes a contract id to/from the cached list kept in the instance.
 * Then the cached list is written to a file named "ctid" in a directory
 * based on the fmri.  Cached list is written to a file due to scalability
 * problems in libscf.  The file "ctid" is used when inetd is restarted
 * so that inetd can adopt the contracts that it had previously.
 * Returns:
 *   0 on success
 *   ENAMETOOLONG if unable to generate filename from fmri (including
 *   the inability to create the directory for the generated filename)
 *   ENOENT - failure accessing file
 *   ENOMEM - memory allocation failure
 */
int
add_remove_contract(instance_t *inst, boolean_t add, ctid_t ctid)
{
	FILE		*tfp;		/* temp fp */
	int		ret = 0;
	int		repval_ret = 0;
	int		fopen_retry_cnt = 2;

	/*
	 * Storage performance of contract ids is important,
	 * so each instance has its own file.  An add of a
	 * ctid will be appended to the ctid file.
	 * The removal of a ctid will result in the remaining
	 * ctids in the list being written to a temp file and then
	 * moved (renamed).
	 */
	if (add) {
		if (gen_filenms_from_fmri(inst->fmri, "ctid", genfmri_filename,
		    NULL) != 0) {
			/* Failure either from fmri too long or mkdir failure */
			return (ENAMETOOLONG);
		}

retry_fopen:
		if ((tfp = fopen(genfmri_filename, "a")) == NULL) {
			if ((errno == EINTR) && (fopen_retry_cnt > 0)) {
				fopen_retry_cnt--;
				goto retry_fopen;
			}
			ret = ENOENT;
			goto out;
		}

		/* Always store ctids as long long */
		if (fprintf(tfp, "%llu\n", (uint64_t)ctid) <= 0) {
			(void) fclose(tfp);
			ret = ENOENT;
			goto out;
		}

		if (fclose(tfp) != 0) {
			ret = ENOENT;
			goto out;
		}

		if (add_rep_val(inst->start_ctids, ctid) != 0) {
			ret = ENOMEM;
			goto out;
		}
	} else {
		remove_rep_val(inst->start_ctids, ctid);

		/* Write all values in list to file */
		if ((repval_ret = repvals_to_file(inst->fmri, "ctid",
		    inst->start_ctids)) != 0) {
			ret = repval_ret;
			goto out;
		}
	}

out:
	return (ret);
}

/*
 * If sig !=0, iterate over all contracts in the cached list of contract
 * ids kept in the instance.  Send each contract the specified signal.
 * If sig == 0, read in the contract ids that were last associated
 * with this instance (reload the cache) and call adopt_contract()
 * to take ownership.
 *
 * Returns 0 on success;
 * ENAMETOOLONG if unable to generate filename from fmri (including
 * the inability to create the directory for the generated filename) and
 * ENXIO if a failure accessing the file
 * ENOMEM if there was a memory allocation failure
 * ENOENT if the instance, its restarter property group, or its
 *   contract property don't exist
 * EIO if invalid data read from the file
 */
int
iterate_repository_contracts(instance_t *inst, int sig)
{
	int		ret = 0;
	FILE		*fp;
	rep_val_t	*spval = NULL;	/* Contains a start_pid */
	uint64_t	tval;		/* temp val holder */
	uu_list_t	*uup = NULL;
	int		fscanf_ret;
	int		fopen_retry_cnt = 2;

	if (sig != 0) {
		/*
		 * Send a signal to all in the contract; ESRCH just
		 * means they all exited before we could kill them
		 */
		for (spval = uu_list_first(inst->start_ctids); spval != NULL;
		    spval = uu_list_next(inst->start_ctids, spval)) {
			if (sigsend(P_CTID, (ctid_t)spval->val, sig) == -1 &&
			    errno != ESRCH) {
				warn_msg(gettext("Unable to signal all "
				    "contract members of instance %s: %s"),
				    inst->fmri, strerror(errno));
			}
		}
		return (0);
	}

	/*
	 * sig == 0 case.
	 * Attempt to adopt the contract for each ctid.
	 */
	if (gen_filenms_from_fmri(inst->fmri, "ctid", genfmri_filename,
	    NULL) != 0) {
		/* Failure either from fmri too long or mkdir failure */
		return (ENAMETOOLONG);
	}

retry_fopen:
	/* It's ok if no file, there are no ctids to adopt */
	if ((fp = fopen(genfmri_filename, "r")) == NULL) {
		if ((errno == EINTR) && (fopen_retry_cnt > 0)) {
			fopen_retry_cnt--;
			goto retry_fopen;
		}
		return (0);
	}

	/*
	 * Read ctids from file into 2 lists:
	 * - temporary list to be traversed (uup)
	 * - cached list that can be modified if adoption of
	 *   contract fails (inst->start_ctids).
	 * Always treat ctids as long longs.
	 */
	uup = create_rep_val_list();
	/* fscanf may not set errno, so clear it first */
	errno = 0;
	while ((fscanf_ret = fscanf(fp, "%llu", &tval)) == 1) {
		/* If tval isn't a valid ctid, then fail. */
		if (tval == 0) {
			(void) fclose(fp);
			ret = EIO;
			goto out;
		}
		if ((add_rep_val(uup, tval) == -1) ||
		    (add_rep_val(inst->start_ctids, tval) == -1)) {
			(void) fclose(fp);
			ret = ENOMEM;
			goto out;
		}
		errno = 0;
	}
	/* EOF is not a failure when no errno */
	if ((fscanf_ret != EOF) || (errno != 0)) {
		ret = EIO;
		goto out;
	}

	if (fclose(fp) != 0) {
		ret = ENXIO;
		goto out;
	}

	for (spval = uu_list_first(uup); spval != NULL;
	    spval = uu_list_next(uup, spval)) {
		/* Try to adopt the contract */
		if (adopt_contract((ctid_t)spval->val,
		    inst->fmri) != 0) {
			/*
			 * Adoption failed.  No reason to think it'll
			 * work later, so remove the id from our list
			 * in the instance.
			 */
			remove_rep_val(inst->start_ctids, spval->val);
		}
	}
out:
	if (uup) {
		empty_rep_val_list(uup);
		destroy_rep_val_list(uup);
	}

	if (ret != 0)
		empty_rep_val_list(inst->start_ctids);

	return (ret);
}
