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

/*
 * RCM backend for the DR Daemon
 */

#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <kstat.h>
#include <libnvpair.h>
#include <librcm.h>
#include <locale.h>

#include "drd.h"

/*
 * RCM Backend Support
 */
static int drd_rcm_init(void);
static int drd_rcm_fini(void);
static int drd_rcm_cpu_config_request(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_cpu_config_notify(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_cpu_unconfig_request(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_cpu_unconfig_notify(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_io_config_request(drctl_rsrc_t *rsrc, int nrsrc);
static int drd_rcm_io_config_notify(drctl_rsrc_t *rsrc, int nrsrc);
static int drd_rcm_io_unconfig_request(drctl_rsrc_t *rsrc, int nrsrc);
static int drd_rcm_io_unconfig_notify(drctl_rsrc_t *rsrc, int nrsrc);

drd_backend_t drd_rcm_backend = {
	drd_rcm_init,			/* init */
	drd_rcm_fini,			/* fini */
	drd_rcm_cpu_config_request,	/* cpu_config_request */
	drd_rcm_cpu_config_notify,	/* cpu_config_notify */
	drd_rcm_cpu_unconfig_request,	/* cpu_unconfig_request */
	drd_rcm_cpu_unconfig_notify,	/* cpu_unconfig_notify */
	drd_rcm_io_config_request,	/* io_config_request */
	drd_rcm_io_config_notify,	/* io_config_notify */
	drd_rcm_io_unconfig_request,	/* io_unconfig_request */
	drd_rcm_io_unconfig_notify	/* io_unconfig_notify */
};

#define	RCM_CPU_ALL		"SUNW_cpu"
#define	RCM_CPU			RCM_CPU_ALL"/cpu"
#define	RCM_CPU_MAX_LEN		(32)

/* global RCM handle used in all RCM operations */
static rcm_handle_t *rcm_hdl;

/* functions that call into RCM */
static int drd_rcm_online_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_add_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_del_cpu_request(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_offline_cpu_request(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_remove_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_restore_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc);
static int drd_rcm_del_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc);

/* utility functions */
static char **drd_rcm_cpu_rlist_init(drctl_rsrc_t *, int nrsrc, int status);
static void drd_rcm_cpu_rlist_fini(char **rlist);
static drctl_rsrc_t *cpu_rsrcstr_to_rsrc(const char *, drctl_rsrc_t *, int);
static int get_sys_cpuids(cpuid_t **cpuids, int *ncpuids);
static boolean_t is_cpu_in_list(cpuid_t cpuid, cpuid_t *list, int len);
static char *rcm_info_table(rcm_info_t *rinfo);

/* debugging utility functions */
static void dump_cpu_list(char *prefix, cpuid_t *cpuids, int ncpuids);
static void dump_cpu_rsrc_list(char *prefix, drctl_rsrc_t *, int nrsrc);
static void dump_cpu_rlist(char **rlist);

static int
drd_rcm_init(void)
{
	int	rv;

	drd_dbg("drd_rcm_init...");

	rv = rcm_alloc_handle(NULL, 0, NULL, &rcm_hdl);
	if (rv == RCM_FAILURE) {
		drd_err("unable to allocate RCM handle: %s", strerror(errno));
		return (-1);
	}

	return (0);
}

static int
drd_rcm_fini(void)
{
	drd_dbg("drd_rcm_fini...");

	if (rcm_hdl != NULL)
		rcm_free_handle(rcm_hdl);

	return (0);
}

static int
drd_rcm_cpu_config_request(drctl_rsrc_t *rsrcs, int nrsrc)
{
	int	idx;

	drd_dbg("drd_rcm_cpu_config_request...");
	dump_cpu_rsrc_list(NULL, rsrcs, nrsrc);

	/*
	 * There is no RCM operation to request the addition
	 * of resources.  So, by definition, the operation for
	 * all the CPUs is allowed.
	 */
	for (idx = 0; idx < nrsrc; idx++)
		rsrcs[idx].status = DRCTL_STATUS_ALLOW;

	dump_cpu_rsrc_list("returning:", rsrcs, nrsrc);

	return (0);
}

static int
drd_rcm_cpu_config_notify(drctl_rsrc_t *rsrcs, int nrsrc)
{
	int	rv = 0;

	drd_dbg("drd_rcm_cpu_config_notify...");
	dump_cpu_rsrc_list(NULL, rsrcs, nrsrc);

	/* notify RCM about the newly added CPUs */
	if (drd_rcm_online_cpu_notify(rsrcs, nrsrc) != 0) {
		rv = -1;
		goto done;
	}

	/* notify RCM about the increased CPU capacity */
	if (drd_rcm_add_cpu_notify(rsrcs, nrsrc) != 0) {
		rv = -1;
	}

done:
	dump_cpu_rsrc_list("returning:", rsrcs, nrsrc);

	return (rv);
}

static int
drd_rcm_cpu_unconfig_request(drctl_rsrc_t *rsrcs, int nrsrc)
{
	int	rv = 0;
	int	idx;

	drd_dbg("drd_rcm_cpu_unconfig_request...");
	dump_cpu_rsrc_list(NULL, rsrcs, nrsrc);

	/* contact RCM to request a decrease in CPU capacity */
	if (drd_rcm_del_cpu_request(rsrcs, nrsrc) != 0) {
		rv = -1;
		goto done;
	}

	/* contact RCM to request the removal of CPUs */
	if (drd_rcm_offline_cpu_request(rsrcs, nrsrc) != 0) {
		rv = -1;
		goto done;
	}

done:
	/*
	 * If any errors occurred, the status field for
	 * a CPU may still be in the INIT state. Set the
	 * status for any such CPU to DENY to ensure it
	 * gets processed properly.
	 */
	for (idx = 0; idx < nrsrc; idx++) {
		if (rsrcs[idx].status == DRCTL_STATUS_INIT)
			rsrcs[idx].status = DRCTL_STATUS_DENY;
	}

	dump_cpu_rsrc_list("returning:", rsrcs, nrsrc);

	return (rv);
}

static int
drd_rcm_cpu_unconfig_notify(drctl_rsrc_t *rsrcs, int nrsrc)
{
	int	rv = 0;

	drd_dbg("drd_rcm_cpu_unconfig_notify...");
	dump_cpu_rsrc_list(NULL, rsrcs, nrsrc);

	/*
	 * Notify RCM about the CPUs that were removed.
	 * Failures are ignored so that CPUs that could
	 * not be unconfigured can be processed by RCM.
	 */
	(void) drd_rcm_remove_cpu_notify(rsrcs, nrsrc);

	/*
	 * Notify RCM about any CPUs that did not make it
	 * in to the unconfigured state.
	 */
	if (drd_rcm_restore_cpu_notify(rsrcs, nrsrc) != 0) {
		rv = -1;
		goto done;
	}

	/* notify RCM about the decreased CPU capacity */
	if (drd_rcm_del_cpu_notify(rsrcs, nrsrc) != 0) {
		rv = -1;
	}

done:
	dump_cpu_rsrc_list("returning:", rsrcs, nrsrc);

	return (rv);
}

static int
drd_rcm_online_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc)
{
	char		**rlist;
	int		rv = 0;
	rcm_info_t	*rinfo;

	drd_dbg("drd_rcm_online_cpu_notify...");

	if ((rlist = drd_rcm_cpu_rlist_init(rsrcs, nrsrc,
	    DRCTL_STATUS_CONFIG_SUCCESS)) == NULL) {
		drd_dbg("  no CPUs were successfully added, nothing to do");
		return (0);
	}

	rcm_notify_online_list(rcm_hdl, rlist, 0, &rinfo);
	if (rv != RCM_SUCCESS) {
		drd_info("rcm_notify_online_list failed: %d", rv);
		rcm_free_info(rinfo);
		rv = -1;
	}

	drd_rcm_cpu_rlist_fini(rlist);

	return (rv);
}

static int
drd_rcm_add_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc)
{
	cpuid_t		*cpus = NULL;
	int		ncpus;
	int		rv = -1;
	cpuid_t		*oldcpus = NULL;
	cpuid_t		*newcpus = NULL;
	int		oldncpus = 0;
	int		newncpus = 0;
	nvlist_t	*nvl = NULL;
	int		idx;
	rcm_info_t	*rinfo;

	drd_dbg("drd_rcm_add_cpu_notify...");

	if ((rsrcs == NULL) || (nrsrc == 0)) {
		drd_err("add_cpu_notify: cpu list empty");
		goto done;
	}

	ncpus = nrsrc;
	cpus = (cpuid_t *)malloc(nrsrc * sizeof (cpuid_t));

	for (idx = 0; idx < nrsrc; idx++) {
		drd_dbg("  cpu[%d] = %d", idx, rsrcs[idx].res_cpu_id);
		cpus[idx] = rsrcs[idx].res_cpu_id;
	}

	/* allocate an nvlist for the RCM call */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		goto done;

	/*
	 * Added CPU capacity, so newcpus is the current list
	 * of CPUs in the system.
	 */
	if (get_sys_cpuids(&newcpus, &newncpus) == -1)
		goto done;

	/*
	 * Since the operation added CPU capacity, the old CPU
	 * list is the new CPU list with the CPUs involved in
	 * the operation removed.
	 */
	oldcpus = (cpuid_t *)calloc(newncpus, sizeof (cpuid_t));
	if (oldcpus == NULL)
		goto done;

	for (idx = 0; idx < newncpus; idx++) {
		if (!is_cpu_in_list(newcpus[idx], cpus, ncpus))
			oldcpus[oldncpus++] = newcpus[idx];
	}

	/* dump pre and post lists */
	dump_cpu_list("oldcpus: ", oldcpus, oldncpus);
	dump_cpu_list("newcpus: ", newcpus, newncpus);
	dump_cpu_list("delta:   ", cpus, ncpus);

	/* setup the nvlist for the RCM call */
	if (nvlist_add_string(nvl, "state", "capacity") ||
	    nvlist_add_int32(nvl, "old_total", oldncpus) ||
	    nvlist_add_int32(nvl, "new_total", newncpus) ||
	    nvlist_add_int32_array(nvl, "old_cpu_list", oldcpus, oldncpus) ||
	    nvlist_add_int32_array(nvl, "new_cpu_list", newcpus, newncpus)) {
		goto done;
	}

	rv = rcm_notify_capacity_change(rcm_hdl, RCM_CPU_ALL, 0, nvl, &rinfo);
	rv = (rv == RCM_SUCCESS) ? 0 : -1;

done:
	s_nvfree(nvl);
	s_free(cpus);
	s_free(oldcpus);
	s_free(newcpus);

	return (rv);
}

static int
drd_rcm_del_cpu_request(drctl_rsrc_t *rsrcs, int nrsrc)
{
	cpuid_t		*cpus = NULL;
	int		ncpus;
	int		rv = -1;
	cpuid_t		*oldcpus = NULL;
	cpuid_t		*newcpus = NULL;
	int		oldncpus = 0;
	int		newncpus = 0;
	nvlist_t	*nvl = NULL;
	int		idx;
	rcm_info_t	*rinfo;

	drd_dbg("drd_rcm_del_cpu_request...");

	if ((rsrcs == NULL) || (nrsrc == 0)) {
		drd_err("del_cpu_request: cpu list empty");
		goto done;
	}

	ncpus = nrsrc;
	cpus = (cpuid_t *)malloc(nrsrc * sizeof (cpuid_t));

	for (idx = 0; idx < nrsrc; idx++) {
		cpus[idx] = rsrcs[idx].res_cpu_id;
	}

	/* allocate an nvlist for the RCM call */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		goto done;
	}

	/*
	 * Removing CPU capacity, so oldcpus is the current
	 * list of CPUs in the system.
	 */
	if (get_sys_cpuids(&oldcpus, &oldncpus) == -1) {
		goto done;
	}

	/*
	 * Since this is a request to remove CPU capacity,
	 * the new CPU list is the old CPU list with the CPUs
	 * involved in the operation removed.
	 */
	newcpus = (cpuid_t *)calloc(oldncpus, sizeof (cpuid_t));
	if (newcpus == NULL) {
		goto done;
	}

	for (idx = 0; idx < oldncpus; idx++) {
		if (!is_cpu_in_list(oldcpus[idx], cpus, ncpus))
			newcpus[newncpus++] = oldcpus[idx];
	}

	/* dump pre and post lists */
	dump_cpu_list("oldcpus: ", oldcpus, oldncpus);
	dump_cpu_list("newcpus: ", newcpus, newncpus);
	dump_cpu_list("delta:   ", cpus, ncpus);

	/* setup the nvlist for the RCM call */
	if (nvlist_add_string(nvl, "state", "capacity") ||
	    nvlist_add_int32(nvl, "old_total", oldncpus) ||
	    nvlist_add_int32(nvl, "new_total", newncpus) ||
	    nvlist_add_int32_array(nvl, "old_cpu_list", oldcpus, oldncpus) ||
	    nvlist_add_int32_array(nvl, "new_cpu_list", newcpus, newncpus)) {
		goto done;
	}

	rv = rcm_request_capacity_change(rcm_hdl, RCM_CPU_ALL, 0, nvl, &rinfo);
	if (rv != RCM_SUCCESS) {
		drd_dbg("RCM call failed: %d", rv);
		/*
		 * Since the capcity change was blocked, we
		 * mark all CPUs as blocked. It is up to the
		 * user to reframe the query so that it can
		 * succeed.
		 */
		for (idx = 0; idx < nrsrc; idx++) {
			rsrcs[idx].status = DRCTL_STATUS_DENY;
		}

		/* tack on message to first resource */
		rsrcs[0].offset = (uintptr_t)strdup("unable to remove "
		    "specified number of CPUs");
		drd_dbg("  unable to remove specified number of CPUs");
		goto done;
	}

	rv = 0;

done:
	s_nvfree(nvl);
	s_free(cpus);
	s_free(oldcpus);
	s_free(newcpus);

	return (rv);
}

static int
drd_rcm_offline_cpu_request(drctl_rsrc_t *rsrcs, int nrsrc)
{
	char		**rlist;
	drctl_rsrc_t	*rsrc;
	int		idx;
	int		state;
	int		rv = 0;
	rcm_info_t	*rinfo = NULL;
	rcm_info_tuple_t *tuple = NULL;
	const char	*rsrcstr;
	const char	*errstr;

	drd_dbg("drd_rcm_offline_cpu_request...");

	if ((rlist = drd_rcm_cpu_rlist_init(rsrcs, nrsrc,
	    DRCTL_STATUS_INIT)) == NULL) {
		drd_err("unable to generate resource list");
		return (-1);
	}

	rv = rcm_request_offline_list(rcm_hdl, rlist, 0, &rinfo);
	if (rv == RCM_SUCCESS) {
		drd_dbg("RCM success, rinfo=%p", rinfo);
		goto done;
	}

	drd_dbg("RCM call failed (%d):", rv);

	/*
	 * Loop through the result of the operation and add
	 * any error messages to the resource structure.
	 */
	while ((tuple = rcm_info_next(rinfo, tuple)) != NULL) {

		/* find the resource of interest */
		rsrcstr = rcm_info_rsrc(tuple);
		rsrc = cpu_rsrcstr_to_rsrc(rsrcstr, rsrcs, nrsrc);

		if (rsrc == NULL) {
			drd_dbg("unable to find resource for %s", rsrcstr);
			continue;
		}

		errstr = rcm_info_error(tuple);

		if (errstr) {
			drd_dbg("  %s: '%s'", rsrcstr, errstr);
			rsrc->offset = (uintptr_t)strdup(errstr);
		}
	}

	rcm_free_info(rinfo);
	rv = 0;

done:
	/*
	 * Set the state of the resource based on the RCM
	 * state. CPUs in the offline state have the ok to
	 * proceed. All others have been blocked.
	 */
	for (idx = 0; rlist[idx] != NULL; idx++) {

		state = 0;
		rcm_get_rsrcstate(rcm_hdl, rlist[idx], &state);

		/* find the resource of interest */
		rsrc = cpu_rsrcstr_to_rsrc(rlist[idx], rsrcs, nrsrc);

		if (rsrc == NULL) {
			drd_dbg("unable to find resource for %s", rlist[idx]);
			continue;
		}

		rsrc->status = ((state == RCM_STATE_OFFLINE) ?
		    DRCTL_STATUS_ALLOW : DRCTL_STATUS_DENY);
	}

	drd_rcm_cpu_rlist_fini(rlist);

	return (rv);
}

static int
drd_rcm_remove_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc)
{
	char		**rlist;
	int		rv = 0;
	rcm_info_t	*rinfo;

	drd_dbg("drd_rcm_remove_cpu_notify...");

	if ((rlist = drd_rcm_cpu_rlist_init(rsrcs, nrsrc,
	    DRCTL_STATUS_CONFIG_SUCCESS)) == NULL) {
		drd_dbg("  no CPUs in the success state, nothing to do");
		return (0);
	}

	rv = rcm_notify_remove_list(rcm_hdl, rlist, 0, &rinfo);
	if (rv != RCM_SUCCESS) {
		drd_info("rcm_notify_remove_list failed: %d", rv);
		rcm_free_info(rinfo);
		rv = -1;
	}

	drd_rcm_cpu_rlist_fini(rlist);

	return (rv);
}

static int
drd_rcm_restore_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc)
{
	char		**rlist;
	char		**full_rlist;
	int		idx;
	int		ridx;
	int		state;
	int		rv = 0;
	rcm_info_t	*rinfo;

	drd_dbg("drd_rcm_restore_cpu_notify...");

	if ((full_rlist = drd_rcm_cpu_rlist_init(rsrcs, nrsrc,
	    DRCTL_STATUS_CONFIG_FAILURE)) == NULL) {
		drd_dbg("  no CPUs in the failed state, nothing to do");
		return (0);
	}

	/*
	 * Since the desired result of this operation is to
	 * restore resources to the online state, filter out
	 * the resources already in the online state before
	 * passing the list to RCM.
	 */

	/* allocate a zero filled array to ensure NULL terminated list */
	rlist = (char **)calloc((nrsrc + 1), sizeof (char *));
	if (rlist == NULL) {
		drd_err("calloc failed: %s", strerror(errno));
		rv = -1;
		goto done;
	}

	for (idx = 0, ridx = 0; full_rlist[idx] != NULL; idx++) {
		state = 0;
		rcm_get_rsrcstate(rcm_hdl, full_rlist[idx], &state);
		if (state != RCM_STATE_ONLINE) {
			rlist[ridx] = full_rlist[idx];
			ridx++;
		}
	}

	/* check if everything got filtered out */
	if (ridx == 0) {
		drd_dbg("  all CPUs already online, nothing to do");
		goto done;
	}

	rv = rcm_notify_online_list(rcm_hdl, rlist, 0, &rinfo);
	if (rv != RCM_SUCCESS) {
		drd_info("rcm_notify_online_list failed: %d", rv);
		rcm_free_info(rinfo);
		rv = -1;
	}

done:
	drd_rcm_cpu_rlist_fini(full_rlist);
	s_free(rlist);

	return (rv);
}

static int
drd_rcm_del_cpu_notify(drctl_rsrc_t *rsrcs, int nrsrc)
{
	cpuid_t		*cpus = NULL;
	int		rv = -1;
	cpuid_t		*oldcpus = NULL;
	cpuid_t		*newcpus = NULL;
	int		oldncpus = 0;
	int		newncpus = 0;
	nvlist_t	*nvl = NULL;
	int		idx;
	int		cidx;
	rcm_info_t	*rinfo;

	drd_dbg("drd_rcm_del_cpu_notify...");

	if ((rsrcs == NULL) || (nrsrc == 0)) {
		drd_err("del_cpu_notify: cpu list empty");
		goto done;
	}

	cpus = (cpuid_t *)malloc(nrsrc * sizeof (cpuid_t));

	/*
	 * Filter out the CPUs that could not be unconfigured.
	 */
	for (idx = 0, cidx = 0; idx < nrsrc; idx++) {
		if (rsrcs[idx].status != DRCTL_STATUS_CONFIG_SUCCESS)
			continue;
		drd_dbg("  cpu[%d] = %d", idx, rsrcs[idx].res_cpu_id);
		cpus[cidx] = rsrcs[idx].res_cpu_id;
		cidx++;
	}

	drd_dbg("  ncpus = %d", cidx);

	/* nothing to do */
	if (cidx == 0) {
		rv = 0;
		goto done;
	}

	/* allocate an nvlist for the RCM call */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		goto done;
	}

	/*
	 * Removed CPU capacity, so newcpus is the current list
	 * of CPUs in the system.
	 */
	if (get_sys_cpuids(&newcpus, &newncpus) == -1) {
		goto done;
	}

	/*
	 * Since the operation removed CPU capacity, the old CPU
	 * list is the new CPU list with the CPUs involved in
	 * the operation added.
	 */
	oldcpus = (cpuid_t *)calloc(newncpus + cidx, sizeof (cpuid_t));
	if (oldcpus == NULL) {
		goto done;
	}

	for (idx = 0; idx < newncpus; idx++) {
		if (!is_cpu_in_list(newcpus[idx], cpus, cidx))
			oldcpus[oldncpus++] = newcpus[idx];
	}

	for (idx = 0; idx < cidx; idx++) {
		oldcpus[oldncpus++] = cpus[idx];
	}

	/* dump pre and post lists */
	dump_cpu_list("oldcpus: ", oldcpus, oldncpus);
	dump_cpu_list("newcpus: ", newcpus, newncpus);
	dump_cpu_list("delta:   ", cpus, cidx);

	/* setup the nvlist for the RCM call */
	if (nvlist_add_string(nvl, "state", "capacity") ||
	    nvlist_add_int32(nvl, "old_total", oldncpus) ||
	    nvlist_add_int32(nvl, "new_total", newncpus) ||
	    nvlist_add_int32_array(nvl, "old_cpu_list", oldcpus, oldncpus) ||
	    nvlist_add_int32_array(nvl, "new_cpu_list", newcpus, newncpus)) {
		goto done;
	}

	rv = rcm_notify_capacity_change(rcm_hdl, RCM_CPU_ALL, 0, nvl, &rinfo);
	rv = (rv == RCM_SUCCESS) ? 0 : -1;

done:
	s_nvfree(nvl);
	s_free(cpus);
	s_free(oldcpus);
	s_free(newcpus);

	return (rv);
}

/*
 * Given a list of resource structures, create a list of CPU
 * resource strings formatted as expected by RCM. Only resources
 * that are in the state specified by the status argument are
 * included in the resulting list.
 */
static char **
drd_rcm_cpu_rlist_init(drctl_rsrc_t *rsrcs, int nrsrc, int status)
{
	char	rbuf[RCM_CPU_MAX_LEN];
	char	**rlist;
	int	idx;
	int	ridx;

	drd_dbg("drd_rcm_cpu_rlist_init...");

	if ((rsrcs == NULL) || (nrsrc == 0)) {
		drd_dbg("cpu list is empty");
		return (NULL);
	}

	/* allocate a zero filled array to ensure NULL terminated list */
	rlist = (char **)calloc((nrsrc + 1), sizeof (char *));
	if (rlist == NULL) {
		drd_err("calloc failed: %s", strerror(errno));
		return (NULL);
	}

	for (idx = 0, ridx = 0; idx < nrsrc; idx++) {

		drd_dbg("  checking cpu %d, status=%d, expected status=%d",
		    rsrcs[idx].res_cpu_id, rsrcs[idx].status, status);

		/*
		 * Filter out the CPUs that are not in
		 * the requested state.
		 */
		if (rsrcs[idx].status != status)
			continue;

		/* generate the resource string */
		(void) sprintf(rbuf, "%s%d", RCM_CPU, rsrcs[idx].res_cpu_id);

		rlist[ridx] = strdup(rbuf);
		if (rlist[ridx] == NULL) {
			drd_err("strdup failed: %s", strerror(errno));
			drd_rcm_cpu_rlist_fini(rlist);
			return (NULL);
		}

		ridx++;
	}

	/* cleanup if the list is empty */
	if (ridx == 0) {
		s_free(rlist);
	}

	drd_dbg("final rlist:");
	dump_cpu_rlist(rlist);

	return (rlist);
}

static void
drd_rcm_cpu_rlist_fini(char **rlist)
{
	int idx;

	drd_dbg("drd_rcm_cpu_rlist_fini...");

	dump_cpu_rlist(rlist);

	for (idx = 0; rlist[idx] != NULL; idx++) {
		s_free(rlist[idx]);
	}

	s_free(rlist);
}

/*
 * Convert an RCM CPU resource string into a numerical cpuid.
 * Assumes the resource string has the form: "SUNW_cpu/cpu<C>"
 * where "<C>" is the numerical cpuid of interest.
 */
static cpuid_t
cpu_rsrcstr_to_cpuid(const char *rsrc)
{
	char	*cpuid_off;
	cpuid_t	cpuid;

	/*
	 * Search for the last occurrance of 'u' in the
	 * expected RCM resource string "SUNW_cpu/cpu<C>".
	 * This will give a pointer to the cpuid portion.
	 */
	cpuid_off = strrchr(rsrc, 'u');
	cpuid_off++;

	cpuid = atoi(cpuid_off);

	return (cpuid);
}

/*
 * Given an RCM CPU resource string, return a pointer to the
 * corresponding resource structure from the given resource list.
 * NULL is returned if no matching resource structure can be
 * found.
 */
static drctl_rsrc_t *
cpu_rsrcstr_to_rsrc(const char *rsrcstr, drctl_rsrc_t *rsrcs, int nrsrc)
{
	cpuid_t	cpuid;
	int	idx;

	cpuid = cpu_rsrcstr_to_cpuid(rsrcstr);

	for (idx = 0; idx < nrsrc; idx++) {
		if (rsrcs[idx].res_cpu_id == cpuid)
			return (&rsrcs[idx]);
	}

	return (NULL);
}

static int
get_sys_cpuids(cpuid_t **cpuids, int *ncpuids)
{
	int		ncpu = 0;
	int		maxncpu;
	kstat_t		*ksp;
	kstat_ctl_t	*kc = NULL;
	cpuid_t		*cp;

	drd_dbg("get_sys_cpuids...");

	if ((maxncpu = sysconf(_SC_NPROCESSORS_MAX)) == -1)
		return (-1);

	if ((kc = kstat_open()) == NULL)
		return (-1);

	if ((cp = (cpuid_t *)calloc(maxncpu, sizeof (cpuid_t))) == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	for (ksp = kc->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, "cpu_info") == 0)
			cp[ncpu++] = ksp->ks_instance;
	}

	dump_cpu_list("syscpus: ", cp, ncpu);

	(void) kstat_close(kc);

	*cpuids = cp;
	*ncpuids = ncpu;

	return (0);
}

static boolean_t
is_cpu_in_list(cpuid_t cpuid, cpuid_t *list, int len)
{
	int idx;

	if (list == NULL)
		return (B_FALSE);

	for (idx = 0; idx < len; idx++) {
		if (list[idx] == cpuid)
			return (B_TRUE);
	}

	return (B_FALSE);
}

#define	CPUIDS_PER_LINE		16
#define	LINEWIDTH		(2 * (CPUIDS_PER_LINE * 4))

static void
dump_cpu_list(char *prefix, cpuid_t *cpuids, int ncpuids)
{
	char	line[LINEWIDTH];
	char	*curr;
	int	i, j;

	/* return if not debugging */
	if (drd_debug == 0)
		return;

	/* print just the prefix if CPU list is empty */
	if (ncpuids == 0) {
		if (prefix)
			drd_dbg("%s", prefix);
		return;
	}

	for (i = 0; i < ncpuids; i += CPUIDS_PER_LINE) {

		bzero(line, LINEWIDTH);
		curr = line;

		/* start with the prefix */
		(void) sprintf(curr, "%s", (prefix) ? prefix : "");
		curr = line + strlen(line);

		/* format the CPUs for this line */
		for (j = 0; (j < CPUIDS_PER_LINE) && ((i + j) < ncpuids); j++) {
			(void) sprintf(curr, "%3d ", cpuids[i + j]);
			curr = line + strlen(line);
		}

		drd_dbg("%s", line);
	}
}

static void
dump_cpu_rsrc_list(char *prefix, drctl_rsrc_t *rsrcs, int nrsrc)
{
	int	idx;
	char	*errstr;

	/* just return if not debugging */
	if (drd_debug == 0)
		return;

	if (prefix)
		drd_dbg("%s", prefix);

	for (idx = 0; idx < nrsrc; idx++) {

		/* get a pointer to the error string */
		errstr = (char *)(uintptr_t)rsrcs[idx].offset;

		drd_dbg("  cpu[%d]: cpuid=%d, status=%d, errstr='%s'", idx,
		    rsrcs[idx].res_cpu_id, rsrcs[idx].status,
		    (errstr != NULL) ? errstr : "");
	}
}

static void
dump_cpu_rlist(char **rlist)
{
	int	idx;
	int	state;

	static char *rcm_state_str[] = {
		"UNKNOWN",		"ONLINE",		"ONLINING",
		"OFFLINE_FAIL",		"OFFLINING",		"OFFLINE",
		"REMOVING",		"INVALID_7",		"INVALID_8",
		"INVALID_9",		"RESUMING",		"SUSPEND_FAIL",
		"SUSPENDING",		"SUSPEND",		"REMOVE",
		"OFFLINE_QUERYING",	"OFFLINE_QUERY_FAIL",	"OFFLINE_QUERY",
		"SUSPEND_QUERYING",	"SUSPEND_QUERY_FAIL",	"SUSPEND_QUERY"
	};

	/* just return if not debugging */
	if (drd_debug == 0)
		return;

	if (rlist == NULL) {
		drd_dbg("  empty rlist");
		return;
	}

	for (idx = 0; rlist[idx] != NULL; idx++) {
		state = 0;
		rcm_get_rsrcstate(rcm_hdl, rlist[idx], &state);
		drd_dbg("  rlist[%d]: rsrc=%s, state=%-2d (%s)", idx,
		    rlist[idx], state, rcm_state_str[state]);
	}
}

static int
drd_rcm_io_config_request(drctl_rsrc_t *rsrc, int nrsrc)
{
	drd_dbg("drd_rcm_io_config_request...");

	if (nrsrc != 1) {
		drd_dbg("drd_rcm_cpu_config_request: only 1 resource "
		    "allowed for I/O requests, passed %d resources\n", nrsrc);
		rsrc->status = DRCTL_STATUS_DENY;

		return (-1);
	}

	/*
	 * There is no RCM operation to request the addition
	 * of resources.  So, by definition, the operation for
	 * the current resource is allowed.
	 */
	rsrc->status = DRCTL_STATUS_ALLOW;

	return (0);
}

/*ARGSUSED*/
static int
drd_rcm_io_config_notify(drctl_rsrc_t *rsrcs, int nrsrc)
{
	drd_dbg("drd_rcm_io_config_notify...");

	if (nrsrc != 1) {
		drd_dbg("drd_rcm_cpu_config_notify: only 1 resource "
		    "allowed for I/O requests, passed %d resources\n", nrsrc);

		return (-1);
	}

	return (0);
}


static int
drd_rcm_io_unconfig_request(drctl_rsrc_t *rsrc, int nrsrc)
{
	int		rv;
	char		*dev = rsrc->res_dev_path;
	rcm_info_t	*rinfo = NULL;

	if (nrsrc != 1) {
		drd_dbg("drd_io_unconfig_request: only 1 resource "
		    "allowed for I/O requests, passed %d resources\n", nrsrc);
		rsrc->status = DRCTL_STATUS_DENY;

		return (-1);
	}

	if ((rv = rcm_request_offline(rcm_hdl, dev, 0, &rinfo)) == RCM_SUCCESS)
		rsrc->status = DRCTL_STATUS_ALLOW;
	else {
		rcm_notify_online(rcm_hdl, dev, 0, NULL);
		rsrc->status = DRCTL_STATUS_DENY;
		rsrc->offset = (uintptr_t)rcm_info_table(rinfo);

	}

	rcm_free_info(rinfo);
	drd_dbg("drd_rcm_io_unconfig_request(%s) = %d", dev, rv);

	return (rv);
}

static int
drd_rcm_io_unconfig_notify(drctl_rsrc_t *rsrc, int nrsrc)
{
	drd_dbg("drd_rcm_io_unconfig_notify...");

	if (nrsrc != 1) {
		drd_dbg("drd_io_cpu_unconfig_notify: only 1 resource "
		    "allowed for I/O requests, passed %d resources\n", nrsrc);

		return (-1);
	}

	return (rcm_notify_remove(rcm_hdl, rsrc->res_dev_path, 0, NULL));
}

#define	MAX_FORMAT	80

/*
 * Convert rcm_info_t data into a printable table.
 */
static char *
rcm_info_table(rcm_info_t *rinfo)
{
	int		i;
	size_t		w;
	size_t		width = 0;
	size_t		w_rsrc = 0;
	size_t		w_info = 0;
	size_t		table_size = 0;
	uint_t		tuples = 0;
	rcm_info_tuple_t *tuple = NULL;
	char		*rsrc;
	char		*info;
	char		*table;
	static char	format[MAX_FORMAT];
	const char	*infostr;

	/* Protect against invalid arguments */
	if (rinfo == NULL)
		return (NULL);

	/* Set localized table header strings */
	rsrc = dgettext(TEXT_DOMAIN, "Resource");
	info = dgettext(TEXT_DOMAIN, "Information");

	/* A first pass, to size up the RCM information */
	while (tuple = rcm_info_next(rinfo, tuple)) {
		if ((infostr = rcm_info_info(tuple)) != NULL) {
			tuples++;
			if ((w = strlen(rcm_info_rsrc(tuple))) > w_rsrc)
				w_rsrc = w;
			if ((w = strlen(infostr)) > w_info)
				w_info = w;
		}
	}

	/* If nothing was sized up above, stop early */
	if (tuples == 0)
		return (NULL);

	/* Adjust column widths for column headings */
	if ((w = strlen(rsrc)) > w_rsrc)
		w_rsrc = w;
	else if ((w_rsrc - w) % 2)
		w_rsrc++;
	if ((w = strlen(info)) > w_info)
		w_info = w;
	else if ((w_info - w) % 2)
		w_info++;

	/*
	 * Compute the total line width of each line,
	 * accounting for intercolumn spacing.
	 */
	width = w_info + w_rsrc + 4;

	/* Allocate space for the table */
	table_size = (2 + tuples) * (width + 1) + 2;

	/* zero fill for the strcat() call below */
	table = calloc(table_size, sizeof (char));
	if (table == NULL)
		return (NULL);

	/* Place a table header into the string */

	/* The resource header */
	(void) strcat(table, "\n");
	w = strlen(rsrc);
	for (i = 0; i < ((w_rsrc - w) / 2); i++)
		(void) strcat(table, " ");
	(void) strcat(table, rsrc);
	for (i = 0; i < ((w_rsrc - w) / 2); i++)
		(void) strcat(table, " ");

	/* The information header */
	(void) strcat(table, "  ");
	w = strlen(info);
	for (i = 0; i < ((w_info - w) / 2); i++)
		(void) strcat(table, " ");
	(void) strcat(table, info);
	for (i = 0; i < ((w_info - w) / 2); i++)
		(void) strcat(table, " ");
	/* Underline the headers */
	(void) strcat(table, "\n");
	for (i = 0; i < w_rsrc; i++)
		(void) strcat(table, "-");
	(void) strcat(table, "  ");
	for (i = 0; i < w_info; i++)
		(void) strcat(table, "-");

	/* Construct the format string */
	(void) snprintf(format, MAX_FORMAT, "%%-%ds  %%-%ds",
	    (int)w_rsrc, (int)w_info);

	/* Add the tuples to the table string */
	tuple = NULL;
	while ((tuple = rcm_info_next(rinfo, tuple)) != NULL) {
		if ((infostr = rcm_info_info(tuple)) != NULL) {
			(void) strcat(table, "\n");
			(void) sprintf(&((table)[strlen(table)]),
			    format, rcm_info_rsrc(tuple),
			    infostr);
		}
	}
	drd_dbg("rcm_info_table: %s\n", table);

	return (table);
}
