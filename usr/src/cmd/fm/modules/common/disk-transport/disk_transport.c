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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Disk error transport module
 *
 * This transport module is responsible for translating between disk errors
 * and FMA ereports.  It is a read-only transport module, and checks for the
 * following failures:
 *
 *	- overtemp
 *	- predictive failure
 *	- self-test failure
 *	- solid state media wearout
 *
 * These failures are detected via the TOPO_METH_DISK_STATUS method, which
 * leverages libdiskstatus to do the actual analysis.  This transport module is
 * in charge of the following tasks:
 *
 *	- discovering available devices
 *	- periodically checking devices
 *	- managing device addition/removal
 */

#include <ctype.h>
#include <fm/fmd_api.h>
#include <fm/libdiskstatus.h>
#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include <fm/topo_mod.h>
#include <limits.h>
#include <string.h>
#include <sys/fm/io/scsi.h>
#include <sys/fm/protocol.h>

static struct dt_stat {
	fmd_stat_t dropped;
} dt_stats = {
	{ "dropped", FMD_TYPE_UINT64, "number of dropped ereports" }
};

typedef struct disk_monitor {
	fmd_hdl_t	*dm_hdl;
	fmd_xprt_t	*dm_xprt;
	id_t		dm_timer;
	hrtime_t	dm_interval;
	char		*dm_sim_search;
	char		*dm_sim_file;
	boolean_t	dm_timer_istopo;
} disk_monitor_t;

static void
dt_post_ereport(fmd_hdl_t *hdl, fmd_xprt_t *xprt, const char *protocol,
    const char *faultname, uint64_t ena, nvlist_t *detector, nvlist_t *payload)
{
	nvlist_t *nvl;
	int e = 0;
	char fullclass[PATH_MAX];

	(void) snprintf(fullclass, sizeof (fullclass), "%s.io.%s.disk.%s",
	    FM_EREPORT_CLASS, protocol, faultname);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) == 0) {
		e |= nvlist_add_string(nvl, FM_CLASS, fullclass);
		e |= nvlist_add_uint8(nvl, FM_VERSION, FM_EREPORT_VERSION);
		e |= nvlist_add_uint64(nvl, FM_EREPORT_ENA, ena);
		e |= nvlist_add_nvlist(nvl, FM_EREPORT_DETECTOR, detector);
		e |= nvlist_merge(nvl, payload, 0);

		if (e == 0) {
			fmd_xprt_post(hdl, xprt, nvl, 0);
		} else {
			nvlist_free(nvl);
			dt_stats.dropped.fmds_value.ui64++;
		}
	} else {
		dt_stats.dropped.fmds_value.ui64++;
	}
}

/*
 * Check a single topo node for failure.  This simply invokes the disk status
 * method, and generates any ereports as necessary.
 */
static int
dt_analyze_disk(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	nvlist_t *result;
	nvlist_t *fmri, *faults;
	char *protocol;
	int err;
	disk_monitor_t *dmp = arg;
	nvpair_t *elem;
	boolean_t fault;
	nvlist_t *details;
	char *fmristr;
	nvlist_t *in = NULL;

	if (topo_node_resource(node, &fmri, &err) != 0) {
		fmd_hdl_error(dmp->dm_hdl, "failed to get fmri: %s\n",
		    topo_strerror(err));
		return (TOPO_WALK_ERR);
	}

	if (topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0) {
		nvlist_free(fmri);
		return (TOPO_WALK_ERR);
	}

	if (dmp->dm_sim_search) {
		fmristr = NULL;
		if (topo_fmri_nvl2str(thp, fmri, &fmristr, &err) == 0 &&
		    strstr(fmristr, dmp->dm_sim_search) != 0)
			(void) nvlist_add_string(in, "path", dmp->dm_sim_file);
		topo_hdl_strfree(thp, fmristr);
	}

	/*
	 * Try to invoke the method.  If this fails (most likely because the
	 * method is not supported), then ignore this node.
	 */
	if (topo_method_invoke(node, TOPO_METH_DISK_STATUS,
	    TOPO_METH_DISK_STATUS_VERSION, in, &result, &err) != 0) {
		nvlist_free(fmri);
		nvlist_free(in);
		return (TOPO_WALK_NEXT);
	}

	nvlist_free(in);

	/*
	 * Check for faults and post ereport(s) if needed
	 */
	if (nvlist_lookup_nvlist(result, "faults", &faults) == 0 &&
	    nvlist_lookup_string(result, "protocol", &protocol) == 0) {
		elem = NULL;
		while ((elem = nvlist_next_nvpair(faults, elem)) != NULL) {
			if (nvpair_type(elem) != DATA_TYPE_BOOLEAN_VALUE)
				continue;

			(void) nvpair_value_boolean_value(elem, &fault);
			if (!fault ||
			    nvlist_lookup_nvlist(result, nvpair_name(elem),
			    &details) != 0)
				continue;

			if (strcmp(nvpair_name(elem),
			    FM_EREPORT_SCSI_SSMWEAROUT) == 0 &&
			    fmd_prop_get_int32(dmp->dm_hdl,
			    "ignore-ssm-wearout") == FMD_B_TRUE)
				continue;

			dt_post_ereport(dmp->dm_hdl, dmp->dm_xprt, protocol,
			    nvpair_name(elem),
			    fmd_event_ena_create(dmp->dm_hdl), fmri, details);
		}
	}

	nvlist_free(result);
	nvlist_free(fmri);

	return (TOPO_WALK_NEXT);
}

/*
 * Periodic timeout.  Iterates over all hc:// topo nodes, calling
 * dt_analyze_disk() for each one.
 */
/*ARGSUSED*/
static void
dt_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;
	disk_monitor_t *dmp = fmd_hdl_getspecific(hdl);

	dmp->dm_hdl = hdl;

	thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);
	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, dt_analyze_disk,
	    dmp, &err)) == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to get topology: %s\n",
		    topo_strerror(err));
		return;
	}

	if (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR) {
		topo_walk_fini(twp);
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to walk topology\n");
		return;
	}

	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);

	dmp->dm_timer = fmd_timer_install(hdl, NULL, NULL, dmp->dm_interval);
	dmp->dm_timer_istopo = B_FALSE;
}

/*
 * Called when the topology may have changed.  We want to examine all disks in
 * case a new one has been inserted, but we don't want to overwhelm the system
 * in the event of a flurry of topology changes, as most likely only a small
 * number of disks are changing.  To avoid this, we set the timer for a small
 * but non-trivial interval (by default 1 minute), and ignore intervening
 * changes during this period.  This still gives us a reasonable response time
 * to newly inserted devices without overwhelming the system if lots of hotplug
 * activity is going on.
 */
/*ARGSUSED*/
static void
dt_topo_change(fmd_hdl_t *hdl, topo_hdl_t *thp)
{
	disk_monitor_t *dmp = fmd_hdl_getspecific(hdl);

	if (dmp->dm_timer_istopo)
		return;

	fmd_timer_remove(hdl, dmp->dm_timer);
	dmp->dm_timer = fmd_timer_install(hdl, NULL, NULL,
	    fmd_prop_get_int64(hdl, "min-interval"));
	dmp->dm_timer_istopo = B_TRUE;
}

static const fmd_prop_t fmd_props[] = {
	{ "interval", FMD_TYPE_TIME, "1h" },
	{ "min-interval", FMD_TYPE_TIME, "1min" },
	{ "simulate", FMD_TYPE_STRING, "" },
	{ "ignore-ssm-wearout", FMD_TYPE_BOOL, "false"},
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_ops = {
	NULL,			/* fmdo_recv */
	dt_timeout,		/* fmdo_timeout */
	NULL, 			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
	NULL,			/* fmdo_send */
	dt_topo_change,		/* fmdo_topo_change */
};

static const fmd_hdl_info_t fmd_info = {
	"Disk Transport Agent", "1.1", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	disk_monitor_t *dmp;
	char *simulate;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (dt_stats) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&dt_stats);

	dmp = fmd_hdl_zalloc(hdl, sizeof (disk_monitor_t), FMD_SLEEP);
	fmd_hdl_setspecific(hdl, dmp);

	dmp->dm_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);
	dmp->dm_interval = fmd_prop_get_int64(hdl, "interval");

	/*
	 * Determine if we have the simulate property set.  This property allows
	 * the developer to substitute a faulty device based off all or part of
	 * an FMRI string.  For example, one could do:
	 *
	 *	setprop simulate "bay=4/disk=4	/path/to/sim.so"
	 *
	 * When the transport module encounters an FMRI containing the given
	 * string, then it will open the simulator file instead of the
	 * corresponding device.  This can be any file, but is intended to be a
	 * libdiskstatus simulator shared object, capable of faking up SCSI
	 * responses.
	 *
	 * The property consists of two strings, an FMRI fragment and an
	 * absolute path, separated by whitespace.
	 */
	simulate = fmd_prop_get_string(hdl, "simulate");
	if (simulate[0] != '\0') {
		const char *sep;
		size_t len;

		for (sep = simulate; *sep != '\0'; sep++) {
			if (isspace(*sep))
				break;
		}

		if (*sep != '\0') {
			len = sep - simulate;

			dmp->dm_sim_search = fmd_hdl_alloc(hdl,
			    len + 1, FMD_SLEEP);
			(void) memcpy(dmp->dm_sim_search, simulate, len);
			dmp->dm_sim_search[len] = '\0';
		}

		for (; *sep != '\0'; sep++) {
			if (!isspace(*sep))
				break;
		}

		if (*sep != '\0') {
			dmp->dm_sim_file = fmd_hdl_strdup(hdl, sep, FMD_SLEEP);
		} else if (dmp->dm_sim_search) {
			fmd_hdl_strfree(hdl, dmp->dm_sim_search);
			dmp->dm_sim_search = NULL;
		}
	}
	fmd_prop_free_string(hdl, simulate);

	/*
	 * Call our initial timer routine.  This will do an initial check of all
	 * the disks, and then start the periodic timeout.
	 */
	dmp->dm_timer = fmd_timer_install(hdl, NULL, NULL, 0);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	disk_monitor_t *dmp;

	dmp = fmd_hdl_getspecific(hdl);
	if (dmp) {
		fmd_xprt_close(hdl, dmp->dm_xprt);
		fmd_hdl_strfree(hdl, dmp->dm_sim_search);
		fmd_hdl_strfree(hdl, dmp->dm_sim_file);
		fmd_hdl_free(hdl, dmp, sizeof (*dmp));
	}
}
