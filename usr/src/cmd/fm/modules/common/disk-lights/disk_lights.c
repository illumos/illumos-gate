/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * Disk Lights Agent (FMA)
 *
 * This Fault Management Daemon (fmd) module periodically scans the topology
 * tree, enumerates all disks with associated fault indicators, and then
 * synchronises the fault status of resources in the FMA Resource Cache with
 * the indicators.  In short: it turns the fault light on for befallen disks.
 *
 * Presently, we recognise associated fault indicators for disks by looking
 * for the following structure in the topology tree:
 *
 *    /bay=N
 *      |
 *      +---- /disk=0   <---------------- our Disk
 *      |
 *      +---- /bay=N?indicator=fail <---- the Fault Light
 *      \---- /bay=N?indicator=ident
 *
 * That is: a DISK node will have a parent BAY; that BAY will itself have
 * child Facility nodes, one of which will be called "fail".  If any of the
 * above does not hold, we simply do nothing for this disk.
 */

#include <string.h>
#include <strings.h>
#include <libnvpair.h>
#include <fm/libtopo.h>
#include <fm/topo_list.h>
#include <fm/topo_hc.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>


typedef struct disk_lights {
	fmd_hdl_t *dl_fmd;
	uint64_t dl_poll_interval;
	uint64_t dl_coalesce_interval;
	id_t dl_timer;
	boolean_t dl_triggered;
} disk_lights_t;

static void disklights_topo(fmd_hdl_t *, topo_hdl_t *);
static void disklights_recv(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *);
static void disklights_timeout(fmd_hdl_t *, id_t, void *);

static const fmd_hdl_ops_t fmd_ops = {
	disklights_recv,	/* fmdo_recv */
	disklights_timeout,	/* fmdo_timeout */
	NULL,			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
	NULL,			/* fmdo_send */
	disklights_topo,	/* fmdo_topo */
};

/*
 * POLL_INTERVAL is the period after which we perform an unsolicited poll
 * to ensure we remain in sync with reality.
 */
#define	DL_PROP_POLL_INTERVAL		"poll-interval"

/*
 * COALESCE_INTERVAL is how long we wait after we are trigged by either a
 * topology change or a relevant list.* event, in order to allow a series
 * of events to coalesce.
 */
#define	DL_PROP_COALESCE_INTERVAL	"coalesce-interval"

static const fmd_prop_t fmd_props[] = {
	{ DL_PROP_POLL_INTERVAL, FMD_TYPE_TIME, "5min" },
	{ DL_PROP_COALESCE_INTERVAL, FMD_TYPE_TIME, "3s" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"Disk Lights Agent",
	"1.0",
	&fmd_ops,
	fmd_props
};

/*
 * Fetch the Facility Node properties (name, type) from the FMRI
 * for this node, or return -1 if we can't.
 */
static int
get_facility_props(topo_hdl_t *hdl, tnode_t *node, char **facname,
    char **factype)
{
	int e, ret = -1;
	nvlist_t *fmri = NULL, *fnvl;
	char *nn = NULL, *tt = NULL;

	if (topo_node_resource(node, &fmri, &e) != 0)
		goto out;

	if (nvlist_lookup_nvlist(fmri, FM_FMRI_FACILITY, &fnvl) != 0)
		goto out;

	if (nvlist_lookup_string(fnvl, FM_FMRI_FACILITY_NAME, &nn) != 0)
		goto out;

	if (nvlist_lookup_string(fnvl, FM_FMRI_FACILITY_TYPE, &tt) != 0)
		goto out;

	*facname = topo_hdl_strdup(hdl, nn);
	*factype = topo_hdl_strdup(hdl, tt);
	ret = 0;

out:
	nvlist_free(fmri);
	return (ret);
}

typedef struct dl_fault_walk_inner {
	char *fwi_name;
	uint32_t fwi_mode;
} dl_fault_walk_inner_t;

static int
dl_fault_walk_inner(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	dl_fault_walk_inner_t *fwi = arg;
	char *facname = NULL, *factype = NULL;
	int err;

	/*
	 * We're only interested in BAY children that are valid Facility Nodes.
	 */
	if (topo_node_flags(node) != TOPO_NODE_FACILITY ||
	    get_facility_props(thp, node, &facname, &factype) != 0) {
		goto out;
	}

	if (strcmp(fwi->fwi_name, facname) != 0)
		goto out;

	/*
	 * Attempt to set the LED mode appropriately.  If this fails, give up
	 * and move on.
	 */
	(void) topo_prop_set_uint32(node, TOPO_PGROUP_FACILITY, TOPO_LED_MODE,
	    TOPO_PROP_MUTABLE, fwi->fwi_mode, &err);

out:
	topo_hdl_strfree(thp, facname);
	topo_hdl_strfree(thp, factype);
	return (TOPO_WALK_NEXT);
}

static int
dl_fault_walk_outer(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	disk_lights_t *dl = arg;
	dl_fault_walk_inner_t fwi;
	tnode_t *pnode;
	int err, has_fault;
	nvlist_t *fmri = NULL;

	bzero(&fwi, sizeof (fwi));

	/*
	 * We are only looking for DISK nodes in the topology that have a parent
	 * BAY.
	 */
	if (strcmp(DISK, topo_node_name(node)) != 0 ||
	    (pnode = topo_node_parent(node)) == NULL ||
	    strcmp(BAY, topo_node_name(pnode)) != 0) {
		return (TOPO_WALK_NEXT);
	}

	/*
	 * Check to see if the Resource this FMRI describes is Faulty:
	 */
	if (topo_node_resource(node, &fmri, &err) != 0)
		return (TOPO_WALK_NEXT);
	has_fault = fmd_nvl_fmri_has_fault(dl->dl_fmd, fmri,
	    FMD_HAS_FAULT_RESOURCE, NULL);
	nvlist_free(fmri);

	/*
	 * Walk the children of this BAY and flush out our fault status if
	 * we find an appropriate indicator node.
	 */
	fwi.fwi_name = "fail";
	fwi.fwi_mode = has_fault ? TOPO_LED_STATE_ON : TOPO_LED_STATE_OFF;
	(void) topo_node_child_walk(thp, pnode, dl_fault_walk_inner, &fwi,
	    &err);

	return (TOPO_WALK_NEXT);
}

/*
 * Walk all of the topology nodes looking for DISKs that match the structure
 * described in the overview.  Once we find them, check their fault status
 * and update their fault indiciator accordingly.
 */
static void
dl_examine_topo(disk_lights_t *dl)
{
	int err;
	topo_hdl_t *thp = NULL;
	topo_walk_t *twp = NULL;

	thp = fmd_hdl_topo_hold(dl->dl_fmd, TOPO_VERSION);
	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, dl_fault_walk_outer,
	    dl, &err)) == NULL) {
		fmd_hdl_error(dl->dl_fmd, "failed to get topology: %s\n",
		    topo_strerror(err));
		goto out;
	}

	if (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR) {
		fmd_hdl_error(dl->dl_fmd, "failed to walk topology: %s\n",
		    topo_strerror(err));
		goto out;
	}

out:
	if (twp != NULL)
		topo_walk_fini(twp);
	if (thp != NULL)
		fmd_hdl_topo_rele(dl->dl_fmd, thp);
}

static void
dl_trigger_enum(disk_lights_t *dl)
{
	/*
	 * If we're already on the short-poll coalesce timer, then return
	 * immediately.
	 */
	if (dl->dl_triggered == B_TRUE)
		return;
	dl->dl_triggered = B_TRUE;

	/*
	 * Replace existing poll timer with coalesce timer:
	 */
	if (dl->dl_timer != 0)
		fmd_timer_remove(dl->dl_fmd, dl->dl_timer);
	dl->dl_timer = fmd_timer_install(dl->dl_fmd, NULL, NULL,
	    dl->dl_coalesce_interval);
}

/*ARGSUSED*/
static void
disklights_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	disk_lights_t *dl = fmd_hdl_getspecific(hdl);

	dl->dl_triggered = B_FALSE;

	dl_examine_topo(dl);

	/*
	 * Install the long-interval timer for the next poll.
	 */
	dl->dl_timer = fmd_timer_install(hdl, NULL, NULL, dl->dl_poll_interval);
}

/*ARGSUSED*/
static void
disklights_topo(fmd_hdl_t *hdl, topo_hdl_t *thp)
{
	disk_lights_t *dl = fmd_hdl_getspecific(hdl);

	dl_trigger_enum(dl);
}

/*ARGSUSED*/
static void
disklights_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class)
{
	disk_lights_t *dl = fmd_hdl_getspecific(hdl);

	dl_trigger_enum(dl);
}

void
_fmd_init(fmd_hdl_t *hdl)
{
	disk_lights_t *dl;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	dl = fmd_hdl_zalloc(hdl, sizeof (*dl), FMD_SLEEP);
	fmd_hdl_setspecific(hdl, dl);

	/*
	 * Load Configuration:
	 */
	dl->dl_fmd = hdl;
	dl->dl_poll_interval = fmd_prop_get_int64(hdl, DL_PROP_POLL_INTERVAL);
	dl->dl_coalesce_interval = fmd_prop_get_int64(hdl,
	    DL_PROP_COALESCE_INTERVAL);

	/*
	 * Schedule the initial enumeration:
	 */
	dl_trigger_enum(dl);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	disk_lights_t *dl = fmd_hdl_getspecific(hdl);

	fmd_hdl_free(hdl, dl, sizeof (*dl));
}
