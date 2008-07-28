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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <libintl.h>
#include <string.h>
#include <rcm_module.h>
#include <sys/pset.h>

#include <pool.h>

/*
 * RCM module ops.
 */
static int pool_register(rcm_handle_t *);
static int pool_unregister(rcm_handle_t *);
static int pool_get_info(rcm_handle_t *, char *, id_t, uint_t, char **,
    char **, nvlist_t *, rcm_info_t **);
static int pool_request_suspend(rcm_handle_t *, char *, id_t,
    timespec_t *, uint_t, char **, rcm_info_t **);
static int pool_notify_resume(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int pool_notify_remove(rcm_handle_t *, char *, id_t, uint_t,
    char **, rcm_info_t **);
static int pool_request_offline(rcm_handle_t *, char *, id_t, uint_t,
    char **, rcm_info_t **);
static int pool_notify_online(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int pool_request_capacity_change(rcm_handle_t *, char *, id_t, uint_t,
    nvlist_t *, char **, rcm_info_t **);
static int pool_notify_capacity_change(rcm_handle_t *, char *, id_t, uint_t,
    nvlist_t *, char **, rcm_info_t **);

/*
 * Pool-specific callback functions.
 */
static int pset_validate_remove(nvlist_t *, char **);

static struct {
	const char *rsrc;
	int (*capacity_change_cb)(nvlist_t *, char **);
} registrations[] = {
	{ "SUNW_cpu", pset_validate_remove },
	{ NULL, NULL }
};

static int registered = 0;

static struct rcm_mod_ops pool_ops = {
	RCM_MOD_OPS_VERSION,
	pool_register,
	pool_unregister,
	pool_get_info,
	pool_request_suspend,
	pool_notify_resume,
	pool_request_offline,
	pool_notify_online,
	pool_notify_remove,
	pool_request_capacity_change,
	pool_notify_capacity_change,
	NULL
};

struct rcm_mod_ops *
rcm_mod_init(void)
{
	rcm_log_message(RCM_TRACE1, "Pools RCM module created\n");
	return (&pool_ops);
}


int
rcm_mod_fini(void)
{
	rcm_log_message(RCM_TRACE1, "Pools RCM module unloaded\n");
	return (RCM_SUCCESS);
}

const char *
rcm_mod_info(void)
{
	return ("Pools RCM module 1.4");
}

static int
pool_check_pset(pool_conf_t *conf, pool_resource_t *res,
    processorid_t *del_cpus, char **errorp)
{
	int64_t tmp;
	int i, j;
	uint_t num_cpus;
	uint64_t min_cpus;
	uint_t num_found = 0;
	processorid_t *cpulist;
	psetid_t psetid;
	pool_value_t *pval;
	pool_elem_t *elem = pool_resource_to_elem(conf, res);

	if ((pval = pool_value_alloc()) == NULL)
		return (-1);
	if (pool_get_property(conf, elem, "pset.min", pval) != POC_UINT) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: cannot find property 'pset.min' in pset\n"));
		pool_value_free(pval);
		return (-1);
	}
	(void) pool_value_get_uint64(pval, &min_cpus);
	if (pool_get_property(conf, elem, "pset.sys_id", pval) != POC_INT) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: cannot get pset.sys_id\n"));
		pool_value_free(pval);
		return (-1);
	}
	(void) pool_value_get_int64(pval, &tmp);
	pool_value_free(pval);
	psetid = (psetid_t)tmp;
	rcm_log_message(RCM_TRACE1, "POOL: checking pset: %d\n", psetid);

	rcm_log_message(RCM_TRACE1, "POOL: min_cpus is %llu\n", min_cpus);
	if (pset_info(psetid, NULL, &num_cpus, NULL) != 0) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: pset_info(%d) failed: %s\n"), psetid,
		    strerror(errno));
		return (-1);
	}
	if ((cpulist = malloc(num_cpus * sizeof (processorid_t))) == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: malloc failed: %s\n"), strerror(errno));
		return (-1);
	}
	if (pset_info(psetid, NULL, &num_cpus, cpulist) != 0) {
		free(cpulist);
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: pset_info(%d) failed: %s\n"), psetid,
		    strerror(errno));
		return (-1);
	}
	for (i = 0; del_cpus[i] != -1; i++)
		for (j = 0; j < num_cpus; j++)
			if (cpulist[j] == del_cpus[i])
				num_found++;
	free(cpulist);
	if (num_found > 0 && (num_cpus - num_found) < (uint_t)min_cpus) {
		int len;
		char *errval;
		const char *errfmt =
		    gettext("POOL: processor set (%1$d) would go "
		    "below its minimum value of %2$u\n");

		/*
		 * We would go below the min value. Fail this request.
		 */
		len = strlen(errfmt) + 4 * 2; /* 4 digits for psetid and min */
		if ((errval = malloc((len + 1) * sizeof (char))) != NULL) {
			(void) snprintf(errval, len + 1, errfmt, psetid,
			    (uint_t)min_cpus);
			*errorp = errval;
		}

		rcm_log_message(RCM_ERROR, (char *)errfmt, psetid,
		    (uint_t)min_cpus);

		return (-1);
	}
	rcm_log_message(RCM_TRACE1, "POOL: pset %d is fine\n", psetid);
	return (0);
}

/*
 * pset_validate_remove()
 * 	Check to see if the requested cpu removal would be acceptable.
 * 	Returns RCM_FAILURE if not.
 */
static int
pset_validate_remove(nvlist_t *nvl, char **errorp)
{
	int error = RCM_SUCCESS;
	int32_t old_total, new_total, removed_total;
	processorid_t *removed_list = NULL; /* list terminated by (-1). */
	processorid_t *old_cpu_list = NULL, *new_cpu_list = NULL;
	int i, j;
	pool_conf_t *conf;
	pool_value_t *pvals[] = { NULL, NULL };
	pool_resource_t **res = NULL;
	uint_t nelem;
	const char *generic_error = gettext("POOL: Error processing request\n");

	if ((conf = pool_conf_alloc()) == NULL)
		return (RCM_FAILURE);
	if (pool_conf_open(conf, pool_dynamic_location(), PO_RDONLY) < 0) {
		rcm_log_message(RCM_TRACE1,
		    "POOL: failed to parse config file: '%s'\n",
		    pool_dynamic_location());
		pool_conf_free(conf);
		return (RCM_SUCCESS);
	}

	if ((error = nvlist_lookup_int32(nvl, "old_total", &old_total)) != 0) {
		(void) pool_conf_close(conf);
		pool_conf_free(conf);
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: unable to find 'old_total' in nvlist: %s\n"),
		    strerror(error));
		*errorp = strdup(generic_error);
		return (RCM_FAILURE);
	}
	if ((error = nvlist_lookup_int32(nvl, "new_total", &new_total)) != 0) {
		(void) pool_conf_close(conf);
		pool_conf_free(conf);
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: unable to find 'new_total' in nvlist: %s\n"),
		    strerror(error));
		*errorp = strdup(generic_error);
		return (RCM_FAILURE);
	}
	if (new_total >= old_total) {
		(void) pool_conf_close(conf);
		pool_conf_free(conf);
		/*
		 * This doesn't look like a cpu removal.
		 */
		rcm_log_message(RCM_TRACE1,
		    gettext("POOL: 'old_total' (%d) is less than 'new_total' "
			    "(%d)\n"), old_total, new_total);
		return (RCM_SUCCESS);
	}
	if ((removed_list = malloc((old_total - new_total + 1) * sizeof (int)))
	    == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: malloc failed: %s\n"), strerror(errno));

		error = RCM_FAILURE;
		goto out;
	}
	if ((error = nvlist_lookup_int32_array(nvl, "old_cpu_list",
		    &old_cpu_list, &nelem)) != 0) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: 'old_cpu_list' not found in nvlist: %s\n"),
		    strerror(error));
		error = RCM_FAILURE;
		goto out;
	}
	if ((int32_t)nelem != old_total) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: 'old_cpu_list' size mismatch: %1$d vs "
		    "%2$d\n"), nelem, old_total);
		error = RCM_FAILURE;
		goto out;
	}
	if ((error = nvlist_lookup_int32_array(nvl, "new_cpu_list",
		    &new_cpu_list, &nelem)) != 0) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: 'new_cpu_list' not found in nvlist: %s\n"),
		    strerror(error));
		error = RCM_FAILURE;
		goto out;
	}
	if (nelem != new_total) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: 'new_cpu_list' size mismatch: %1$d vs "
		    "%2$d\n"), nelem, new_total);
		error = RCM_FAILURE;
		goto out;
	}

	for (i = 0, removed_total = 0; i < old_total; i++) {
		for (j = 0; j < new_total; j++)
			if (old_cpu_list[i] == new_cpu_list[j])
				break;
		if (j == new_total) /* not found in new_cpu_list */
			removed_list[removed_total++] = old_cpu_list[i];
	}
	removed_list[removed_total] = -1;

	if (removed_total != (old_total - new_total)) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: error finding removed cpu list\n"));
		error = RCM_FAILURE;
		goto out;
	}
	if ((pvals[0] = pool_value_alloc()) == NULL) {
		rcm_log_message(RCM_ERROR, gettext("POOL: pool_value_alloc"
		    " failed: %s\n"), strerror(errno));
		error = RCM_FAILURE;
		goto out;
	}
	/*
	 * Look for resources with "'type' = 'pset'"
	 */
	pool_value_set_name(pvals[0], "type");
	pool_value_set_string(pvals[0], "pset");
	if ((res = pool_query_resources(conf, &nelem, pvals)) == NULL) {
		rcm_log_message(RCM_ERROR,
		    gettext("POOL: No psets found in configuration\n"));
		pool_value_free(pvals[0]);
		error =	 RCM_FAILURE;
		goto out;
	}
	pool_value_free(pvals[0]);
	for (i = 0; res[i] != NULL; i++)
		/*
		 * Ask each pset if removing these cpus would cause it to go
		 * below it's minimum value.
		 */
		if (pool_check_pset(conf, res[i], removed_list, errorp) < 0) {
			error = RCM_FAILURE;
			break;
		}
	free(res);
out:
	if (removed_list)
		free(removed_list);
	if (conf) {
		(void) pool_conf_close(conf);
		pool_conf_free(conf);
	}

	/*
	 * Set the error string if not already set.
	 */
	if (error != RCM_SUCCESS && *errorp == NULL)
		*errorp = strdup(generic_error);
	return (error);
}

/*
 * Returns RCM_SUCCESS in a number of error cases, since RCM_FAILURE would
 * mean that the capacity change would be disallowed by this module,
 * which is not what we mean.
 */
static int
pool_request_capacity_change(rcm_handle_t *hdl, char *rsrcname, id_t id,
    uint_t flags, nvlist_t *nvlist, char **errorp, rcm_info_t **dependent_info)
{
	int i;

	*errorp = NULL;
	rcm_log_message(RCM_TRACE1,
	    "POOL: requesting capacity change for: %s (flag: %d)\n",
	    rsrcname, flags);
	if (flags & RCM_FORCE) {
		rcm_log_message(RCM_TRACE1,
		    "POOL: Allowing forced operation to pass through...\n");
		return (RCM_SUCCESS);
	}
	for (i = 0; registrations[i].rsrc != NULL; i++) {
		if (strcmp(rsrcname, registrations[i].rsrc) == 0) {
			return ((*registrations[i].capacity_change_cb)(nvlist,
			    errorp));
		}
	}

	return (RCM_SUCCESS);
}

static int
pool_notify_capacity_change(rcm_handle_t *hdl, char *rsrcname, id_t id,
    uint_t flags, nvlist_t *nvlist, char **info, rcm_info_t **dependent_info)
{
	rcm_log_message(RCM_TRACE1,
	    "POOL: notifying capacity change for: %s (flags: %d)\n",
	    rsrcname, flags);
	return (RCM_SUCCESS);
}

static int
pool_register(rcm_handle_t *hdl)
{
	int i;

	rcm_log_message(RCM_TRACE1, "Registering Pools RCM module\n");
	if (registered)
		return (RCM_SUCCESS);
	registered++;
	for (i = 0; registrations[i].rsrc != NULL; i++) {
		if (rcm_register_capacity(hdl, (char *)registrations[i].rsrc,
				    0, NULL) != RCM_SUCCESS) {
				rcm_log_message(RCM_ERROR,
				    gettext("POOL: failed to register capacity "
				    "change for '%s'\n"),
				    registrations[i].rsrc);
			}
	}
	return (RCM_SUCCESS);
}

static int
pool_unregister(rcm_handle_t *hdl)
{
	int i;

	rcm_log_message(RCM_TRACE1, "Pools RCM un-registered\n");
	if (registered) {
		registered--;
		for (i = 0; registrations[i].rsrc != NULL; i++)
			if (rcm_unregister_capacity(hdl,
			    (char *)registrations[i].rsrc, 0) != RCM_SUCCESS) {
				rcm_log_message(RCM_ERROR,
				    gettext("POOL: unregister capacity failed "
				    "for '%s'\n"), registrations[i].rsrc);
			}
	}
	return (RCM_SUCCESS);
}

static int
pool_get_info(rcm_handle_t *hdl, char *rsrcname, id_t pid, uint_t flag,
    char **infop, char **errorp, nvlist_t *props, rcm_info_t **dependent_info)
{
	rcm_log_message(RCM_TRACE1, "POOL: RCM get info: '%s'\n", rsrcname);
	if ((*infop = strdup(gettext("POOL: In use by pool(4) subsystem")))
	    == NULL) {
		rcm_log_message(RCM_ERROR, gettext("POOL: get info(%s) malloc "
		    "failure\n"), rsrcname);
		*infop = NULL;
		*errorp = NULL;
		return (RCM_FAILURE);
	}
	return (RCM_SUCCESS);
}


static int
pool_request_suspend(rcm_handle_t *hdl, char *rsrcname,
    id_t id, timespec_t *time, uint_t flags, char **reason,
    rcm_info_t **dependent_info)
{
	rcm_log_message(RCM_TRACE1,
	    "POOL: requesting suspend for: %s\n", rsrcname);
	return (RCM_SUCCESS);
}

static int
pool_notify_resume(rcm_handle_t *hdl, char *rsrcname,
    id_t pid, uint_t flags, char **reason, rcm_info_t **dependent_info)
{
	rcm_log_message(RCM_TRACE1,
	    "POOL: notifying resume of: %s\n", rsrcname);
	return (RCM_SUCCESS);
}

static int
pool_request_offline(rcm_handle_t *hdl, char *rsrcname, id_t pid, uint_t flag,
    char **reason, rcm_info_t **dependent_info)
{
	rcm_log_message(RCM_TRACE1,
	    "POOL: requesting offline for: %s\n", rsrcname);
	return (RCM_SUCCESS);
}

static int
pool_notify_online(rcm_handle_t *hdl, char *rsrcname, id_t pid, uint_t flags,
    char **reason, rcm_info_t **dependent_info)
{
	rcm_log_message(RCM_TRACE1,
	    "POOL: notifying online for: %s\n", rsrcname);
	return (RCM_SUCCESS);
}
static int
pool_notify_remove(rcm_handle_t *hdl, char *rsrcname, id_t pid,
    uint_t flag, char **reason, rcm_info_t **dependent_info)
{
	rcm_log_message(RCM_TRACE1,
	    "POOL: notifying removal of: %s\n", rsrcname);
	return (RCM_SUCCESS);
}
