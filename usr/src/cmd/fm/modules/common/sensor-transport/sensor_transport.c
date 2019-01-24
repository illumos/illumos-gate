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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include <fm/topo_mod.h>
#include <fm/topo_method.h>

#include <sys/fm/protocol.h>
#include <sys/systeminfo.h>

#include <string.h>

#define	ST_EREPORT_CLASS	"ereport.sensor.failure"

typedef struct sensor_fault {
	struct sensor_fault	*sf_next;
	char			*sf_fru;
	uint32_t		sf_num_fails;
	boolean_t		sf_last_faulted;
	boolean_t		sf_faulted;
	boolean_t		sf_unknown;
} sensor_fault_t;

typedef struct sensor_transport {
	fmd_hdl_t	*st_hdl;
	fmd_xprt_t	*st_xprt;
	hrtime_t	st_interval;
	id_t		st_timer;
	sensor_fault_t	*st_faults;
	boolean_t	st_first;
	/*
	 * The number of consecutive sensor readings indicating failure that
	 * we'll tolerate before sending an ereport.
	 */
	uint32_t	st_tolerance;
	nvlist_t	*st_spoofs;
} sensor_transport_t;

typedef struct st_stats {
	fmd_stat_t st_bad_fmri;
	fmd_stat_t st_topo_errs;
	fmd_stat_t st_repairs;
} st_stats_t;

st_stats_t st_stats = {
	{ "bad_fmri", FMD_TYPE_UINT64, "bad or missing resource/FRU FMRI" },
	{ "topo_errors", FMD_TYPE_UINT64, "errors walking topology" },
	{ "repairs", FMD_TYPE_UINT64, "auto repairs" }
};

static int st_check_component_complaints;
static int have_complained;
static char *spoof_prop = NULL;

static int
st_check_component(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	sensor_transport_t *stp = arg;
	fmd_hdl_t *hdl = stp->st_hdl;
	const char *name = topo_node_name(node);
	nvlist_t *nvl, *props, *rsrc, *fru;
	char *fmri;
	int err, ret;
	int32_t last_source, source = -1;
	boolean_t nonrecov, faulted, predictive, source_diff, injected;
	nvpair_t *nvp;
	uint64_t ena;
	nvlist_t *event;
	sensor_fault_t *sfp, **current;

	if (strcmp(name, FAN) != 0 && strcmp(name, PSU) != 0)
		return (0);

	if (topo_node_resource(node, &rsrc, NULL) != 0) {
		st_stats.st_bad_fmri.fmds_value.ui64++;
		return (0);
	}

	/*
	 * If the resource isn't present, don't bother invoking the sensor
	 * failure method.  It may be that the sensors aren't part of the same
	 * physical FRU and will report failure if the FRU is no longer there.
	 */
	if ((ret = topo_fmri_present(thp, rsrc, &err)) < 0) {
		fmd_hdl_debug(hdl, "topo_fmri_present() failed for %s=%d",
		    name, topo_node_instance(node));
		nvlist_free(rsrc);
		return (0);
	}

	if (!ret) {
		fmd_hdl_debug(hdl, "%s=%d is not present, ignoring",
		    name, topo_node_instance(node));
		nvlist_free(rsrc);
		return (0);
	}

	if (topo_method_invoke(node, TOPO_METH_SENSOR_FAILURE,
	    TOPO_METH_SENSOR_FAILURE_VERSION, stp->st_spoofs, &nvl, &err) !=
	    0) {
		if (err == ETOPO_METHOD_NOTSUP) {
			st_check_component_complaints++;
			if (!have_complained) {
				fmd_hdl_debug(hdl, "Method %s not supported "
				    "on %s=%d", TOPO_METH_SENSOR_FAILURE, name,
				    topo_node_instance(node));
			}
			nvlist_free(rsrc);
			return (0);
		}
		nvl = NULL;
	}

	if (topo_node_fru(node, &fru, NULL, &err) != 0) {
		st_stats.st_bad_fmri.fmds_value.ui64++;
		nvlist_free(nvl);
		nvlist_free(rsrc);
		return (0);
	}

	if (topo_fmri_nvl2str(thp, fru, &fmri, &err) != 0) {
		st_stats.st_bad_fmri.fmds_value.ui64++;
		nvlist_free(nvl);
		nvlist_free(fru);
		nvlist_free(rsrc);
		return (0);
	}

	nvlist_free(fru);

	faulted = nonrecov = source_diff = injected = B_FALSE;
	predictive = B_TRUE;
	if (nvl != NULL)  {
		nvp = NULL;
		while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
			if (nvpair_value_nvlist(nvp, &props) != 0)
				continue;

			faulted = B_TRUE;

			/*
			 * We need some simple rules to handle the case where
			 * there are multiple facility nodes that indicate
			 * a problem with this FRU, but disagree on the values
			 * of nonrecov, predictive or source:
			 *
			 * 1) nonrecov will be set to true if one or more
			 *   facility nodes indicates true.  Otherwise it will
			 *   default to false
			 *
			 * 2) predictive will default to false and remain false
			 *    if one or more facility nodes indicate false.
			 *
			 * 3) source will be set to unknown unless all facility
			 *    nodes agree on the source
			 *
			 * 4) injected defaults to false, but will be set to
			 *    true if any of the sensor states were injected.
			 */
			if (nonrecov == B_FALSE)
				if (nvlist_lookup_boolean_value(props,
				    "nonrecov", &nonrecov) != 0)
					nonrecov = B_FALSE;
			if (predictive == B_TRUE)
				if (nvlist_lookup_boolean_value(props,
				    "predictive", &predictive) != 0)
					predictive = B_FALSE;
			(void) nvlist_lookup_boolean_value(props,
			    "injected", &injected);

			last_source = source;
			if (nvlist_lookup_uint32(props, "source",
			    (uint32_t *)&source) != 0)
				source = TOPO_SENSOR_ERRSRC_UNKNOWN;
			if (last_source != -1 && last_source != source)
				source_diff = B_TRUE;
		}
		if (source_diff)
			source = TOPO_SENSOR_ERRSRC_UNKNOWN;
	}

	/*
	 * See if we know about this fru.
	 */
	for (current = &stp->st_faults; *current != NULL;
	    current = &(*current)->sf_next) {
		if (topo_fmri_strcmp(thp, fmri,
		    (*current)->sf_fru))
			break;
	}

	sfp = *current;
	if (sfp == NULL) {
		/*
		 * We add this FRU to our list under two circumstances:
		 *
		 *	1. This FRU is faulted and needs to be remembered to
		 *	   avoid duplicate ereports.
		 *
		 *	2. This is the initial pass, and we want to repair the
		 *	   FRU in case it was repaired while we were offline.
		 */
		if (stp->st_first || faulted) {
			sfp = fmd_hdl_zalloc(hdl, sizeof (sensor_fault_t),
			    FMD_SLEEP);
			sfp->sf_fru = fmd_hdl_strdup(hdl, fmri, FMD_SLEEP);
			sfp->sf_next = stp->st_faults;
			stp->st_faults = sfp;
		} else {
			goto out;
		}
	}

	if (faulted)
		sfp->sf_num_fails++;

	if (nvl == NULL)
		sfp->sf_unknown = B_TRUE;

	if (faulted) {
		/*
		 * Construct and post the ereport.
		 *
		 * XXFM we only post one ereport per fru.  It should be possible
		 * to uniquely identify faulty resources instead and post one
		 * per resource, even if they share the same FRU.
		 */
		if (!sfp->sf_last_faulted &&
		    (sfp->sf_num_fails > stp->st_tolerance)) {
			ena = fmd_event_ena_create(hdl);
			event = fmd_nvl_alloc(hdl, FMD_SLEEP);

			(void) nvlist_add_string(event, "type", name);
			(void) nvlist_add_boolean_value(event, "nonrecov",
			    nonrecov);
			(void) nvlist_add_boolean_value(event, "predictive",
			    predictive);
			(void) nvlist_add_uint32(event, "source",
			    (uint32_t)source);
			(void) nvlist_add_nvlist(event, "details", nvl);
			(void) nvlist_add_string(event, FM_CLASS,
			    ST_EREPORT_CLASS);
			(void) nvlist_add_uint8(event, FM_VERSION,
			    FM_EREPORT_VERSION);
			(void) nvlist_add_uint64(event, FM_EREPORT_ENA, ena);
			(void) nvlist_add_nvlist(event, FM_EREPORT_DETECTOR,
			    rsrc);
			(void) nvlist_add_boolean_value(event, "__injected",
			    injected);
			fmd_xprt_post(hdl, stp->st_xprt, event, 0);
			fmd_hdl_debug(hdl, "posted ereport: %s",
			    ST_EREPORT_CLASS);
		}

		sfp->sf_faulted = B_TRUE;
	}

out:
	topo_hdl_strfree(thp, fmri);
	nvlist_free(rsrc);
	nvlist_free(nvl);
	return (0);
}

int st_timeout_verbose = 0;

/*ARGSUSED*/
static void
st_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	sensor_transport_t *stp;
	sensor_fault_t *sfp, **current;
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;

	if (st_timeout_verbose)
		fmd_hdl_debug(hdl, "timeout: checking topology");

	stp = fmd_hdl_getspecific(hdl);
	thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);

	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, st_check_component,
	    stp, &err)) == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to walk topology: %s\n",
		    topo_strerror(err));
		st_stats.st_topo_errs.fmds_value.ui64++;
		return;
	}

	if (st_check_component_complaints)
		have_complained++;

	/*
	 * Initialize values in our internal FRU list for this iteration of
	 * sensor reads.  Keep track of whether the FRU was faulted in the
	 * previous pass so we don't send multiple ereports for the same
	 * problem.
	 */
	for (sfp = stp->st_faults; sfp != NULL; sfp = sfp->sf_next) {
		sfp->sf_unknown = B_FALSE;
		if (sfp->sf_num_fails > stp->st_tolerance)
			sfp->sf_last_faulted = sfp->sf_faulted;
		sfp->sf_faulted = B_FALSE;
	}

	if (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR) {
		topo_walk_fini(twp);
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_error(hdl, "failed to walk topology\n");
		st_stats.st_topo_errs.fmds_value.ui64++;
		return;
	}

	/*
	 * Remove any faults that weren't seen in the last pass.
	 */
	for (current = &stp->st_faults; *current != NULL; ) {
		sfp = *current;
		if (!sfp->sf_faulted && !sfp->sf_unknown) {
			fmd_hdl_debug(hdl, "repairing %s", sfp->sf_fru);
			fmd_repair_fru(hdl, sfp->sf_fru);
			st_stats.st_repairs.fmds_value.ui64++;
			*current = sfp->sf_next;
			fmd_hdl_strfree(hdl, sfp->sf_fru);
			fmd_hdl_free(hdl, sfp, sizeof (sensor_fault_t));
		} else {
			current = &sfp->sf_next;
		}
	}

	stp->st_first = B_FALSE;
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);

	stp->st_timer = fmd_timer_install(hdl, NULL, NULL, stp->st_interval);
}

/*
 * Parse the value of the spoof-sensor-state module property and store the
 * result in an nvlist of nvlists.  The format of the value is 3-tuple,
 * delimited by colons, as follows:
 *
 * FMRIPATTERN:SENSORNAME:SENSORSTATE;...
 *
 * where FMRIPATTERN can be a string with wildcards that matches the FMRI
 * of a node associated with the target sensor facility.
 *
 * where SENSORNAME is the node name of the target sensor facility
 *
 * where SENSORSTATE is the desired sensor state value to spoof.
 *
 * Multiple tuples can be specifed, delimited by semicolons.
 *
 * If any errors are encountered while parsing the value, all parsing is
 * ceased and an ereport will be generated indicating a failure to parse
 * the value.
 */
/*ARGSUSED*/
static int
parse_spoof_param(fmd_hdl_t *hdl, char *param, sensor_transport_t *stp)
{
	char *sensor, *last_sensor, *field, *last_field;
	nvlist_t *spoof;

	if (nvlist_alloc(&stp->st_spoofs, NV_UNIQUE_NAME, 0) != 0) {
		return (-1);
	}

	sensor = strtok_r(param, ";", &last_sensor);
	while (sensor != NULL) {
		if (nvlist_alloc(&spoof, NV_UNIQUE_NAME, 0) != 0)
			goto err;

		if ((field = strtok_r(sensor, ":", &last_field)) == NULL ||
		    nvlist_add_string(spoof, ST_SPOOF_FMRI, field) != 0)
			goto err;

		if ((field = strtok_r(NULL, ":", &last_field)) == NULL ||
		    nvlist_add_string(spoof, ST_SPOOF_SENSOR, field) != 0)
			goto err;

		if ((field = strtok_r(NULL, ":", &last_field)) == NULL ||
		    nvlist_add_uint32(spoof, ST_SPOOF_STATE,
		    strtol(field, NULL, 0)) != 0)
			goto err;

		if (nvlist_add_nvlist(stp->st_spoofs, sensor, spoof) != 0)
			goto err;

		spoof = NULL;
		sensor = strtok_r(NULL, ";", &last_sensor);
	}

	return (0);
err:
	nvlist_free(spoof);
	nvlist_free(stp->st_spoofs);
	stp->st_spoofs = NULL;
	return (-1);
}

static const fmd_prop_t fmd_props[] = {
	{ "interval", FMD_TYPE_TIME, "1min" },
	{ "tolerance", FMD_TYPE_UINT32, "1" },
	{ "spoof_sensor_state", FMD_TYPE_STRING, NULL },
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_ops = {
	NULL,			/* fmdo_recv */
	st_timeout,		/* fmdo_timeout */
	NULL,			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
	NULL,			/* fmdo_send */
	NULL			/* fmdo_topo */
};

static const fmd_hdl_info_t fmd_info = {
	"Sensor Transport Agent", "1.1", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	sensor_transport_t *stp;
	char buf[SYS_NMLN];

	/*
	 * The sensor-transport module is currently only supported on x86
	 * platforms.  So to avoid unnecessarily wasting cpu cycles on sparc
	 * walking the hc scheme tree every 60 seconds, we'll bail out before
	 * registering the handle.
	 */
	if ((sysinfo(SI_ARCHITECTURE, buf, sizeof (buf)) == -1) ||
	    (strcmp(buf, "i386") != 0))
		return;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (st_stats) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&st_stats);

	stp = fmd_hdl_zalloc(hdl, sizeof (sensor_transport_t), FMD_SLEEP);
	stp->st_interval = fmd_prop_get_int64(hdl, "interval");
	stp->st_tolerance = fmd_prop_get_int32(hdl, "tolerance");
	spoof_prop = fmd_prop_get_string(hdl, "spoof_sensor_state");

	if (spoof_prop != NULL && parse_spoof_param(hdl, spoof_prop, stp) != 0)
		fmd_hdl_error(hdl, "Error parsing config file");

	fmd_hdl_setspecific(hdl, stp);

	stp->st_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);
	stp->st_hdl = hdl;
	stp->st_first = B_TRUE;

	/* kick off the first asynchronous discovery */
	stp->st_timer = fmd_timer_install(hdl, NULL, NULL, 0);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	sensor_transport_t *stp;
	sensor_fault_t *sfp;

	stp = fmd_hdl_getspecific(hdl);
	if (stp != NULL) {
		fmd_xprt_close(hdl, stp->st_xprt);

		while ((sfp = stp->st_faults) != NULL) {
			stp->st_faults = sfp->sf_next;

			fmd_hdl_strfree(hdl, sfp->sf_fru);
			fmd_hdl_free(hdl, sfp, sizeof (sensor_fault_t));
		}
		nvlist_free(stp->st_spoofs);
		fmd_hdl_free(hdl, stp, sizeof (sensor_transport_t));
	}
	fmd_prop_free_string(hdl, spoof_prop);
}
