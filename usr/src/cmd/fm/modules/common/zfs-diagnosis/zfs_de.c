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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <stddef.h>
#include <strings.h>
#include <libuutil.h>
#include <fm/fmd_api.h>
#include <sys/fs/zfs.h>
#include <sys/fm/protocol.h>
#include <sys/fm/fs/zfs.h>

typedef struct zfs_case_data {
	uint64_t	zc_version;
	uint64_t	zc_ena;
	uint64_t	zc_pool_guid;
	uint64_t	zc_vdev_guid;
	int		zc_has_timer;
	int		zc_pool_state;
} zfs_case_data_t;

typedef struct zfs_case {
	int		zc_version;
	zfs_case_data_t	zc_data;
	fmd_case_t	*zc_case;
	uu_list_node_t	zc_node;
	id_t		zc_timer;
} zfs_case_t;

#define	CASE_DATA		"data"
#define	CASE_DATA_VERSION	1

static int zfs_case_timeout;

uu_list_pool_t *zfs_case_pool;
uu_list_t *zfs_cases;

static void
zfs_case_serialize(fmd_hdl_t *hdl, zfs_case_t *zcp)
{
	fmd_buf_write(hdl, zcp->zc_case, CASE_DATA, &zcp->zc_data,
	    sizeof (zcp->zc_data));
}

static zfs_case_t *
zfs_case_unserialize(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	zfs_case_t *zcp;

	zcp = fmd_hdl_zalloc(hdl, sizeof (zfs_case_t), FMD_SLEEP);
	zcp->zc_case = cp;

	fmd_buf_read(hdl, cp, CASE_DATA, &zcp->zc_data,
	    sizeof (zcp->zc_data));

	if (zcp->zc_data.zc_version != CASE_DATA_VERSION) {
		fmd_hdl_free(hdl, zcp, sizeof (zfs_case_t));
		return (NULL);
	}

	if (zcp->zc_data.zc_has_timer)
		zcp->zc_timer = fmd_timer_install(hdl, zcp,
		    NULL, zfs_case_timeout);

	(void) uu_list_insert_before(zfs_cases, NULL, zcp);

	fmd_case_setspecific(hdl, cp, zcp);

	return (zcp);
}

/*ARGSUSED*/
static void
zfs_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	zfs_case_t *zcp;
	int32_t pool_state;
	uint64_t ena, pool_guid, vdev_guid;
	nvlist_t *detector;
	boolean_t isresource;

	isresource = fmd_nvl_class_match(hdl, nvl, "resource.fs.zfs.*");

	if (isresource) {
		/*
		 * For our faked-up 'ok' resource (see below), we have no normal
		 * payload members.
		 */
		if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_ZFS_VDEV_GUID,
		    &vdev_guid) != 0)
			pool_state = SPA_LOAD_OPEN;
		else
			pool_state = SPA_LOAD_NONE;
		detector = NULL;
	} else {
		(void) nvlist_lookup_nvlist(nvl,
		    FM_EREPORT_DETECTOR, &detector);
		(void) nvlist_lookup_int32(nvl,
		    FM_EREPORT_PAYLOAD_ZFS_POOL_CONTEXT, &pool_state);
	}

	/*
	 * Without a retire agent, we subscribe to our own faults and just
	 * discard them.
	 */
	if (fmd_nvl_class_match(hdl, nvl, "fault.fs.zfs.*"))
		return;

	/*
	 * Ignore all block level (.io and .checksum) errors not associated with
	 * a pool open.  We should really update a bean counter, and eventually
	 * do some real predictive analysis based on these faults.
	 */
	if ((fmd_nvl_class_match(hdl, nvl, "ereport.fs.zfs.io") ||
	    fmd_nvl_class_match(hdl, nvl, "ereport.fs.zfs.checksum")) &&
	    pool_state == SPA_LOAD_NONE)
		return;

	/*
	 * We also ignore all ereports generated during an import of a pool,
	 * since the only possible fault (.pool) would result in import failure,
	 * and hence no persistent fault.  Some day we may want to do something
	 * with these ereports, so we continue generating them internally.
	 */
	if (pool_state == SPA_LOAD_IMPORT)
		return;

	/*
	 * Determine if this ereport corresponds to an open case.  Cases are
	 * indexed by ENA, since ZFS does all the work of chaining together
	 * related ereports.
	 *
	 * We also detect if an ereport corresponds to an open case by context,
	 * such as:
	 *
	 * 	- An error occurred during an open of a pool with an existing
	 *	  case.
	 *
	 * 	- An error occurred for a device which already has an open
	 *	  case.
	 */
	if (!isresource) {
		(void) nvlist_lookup_uint64(nvl, FM_EREPORT_ENA, &ena);
		(void) nvlist_lookup_uint64(nvl,
		    FM_EREPORT_PAYLOAD_ZFS_POOL_GUID, &pool_guid);
		if (fmd_nvl_class_match(hdl, nvl, "ereport.fs.zfs.vdev.*"))
			(void) nvlist_lookup_uint64(nvl,
			    FM_EREPORT_PAYLOAD_ZFS_VDEV_GUID, &vdev_guid);
		else
			vdev_guid = 0;
	} else {
		(void) nvlist_lookup_uint64(nvl,
		    FM_EREPORT_PAYLOAD_ZFS_POOL_GUID, &pool_guid);
		if (nvlist_lookup_uint64(nvl,
		    FM_EREPORT_PAYLOAD_ZFS_VDEV_GUID, &vdev_guid) != 0)
			vdev_guid = 0;
		ena = 0;
	}

	for (zcp = uu_list_first(zfs_cases); zcp != NULL;
	    zcp = uu_list_next(zfs_cases, zcp)) {
		/*
		 * Matches a known ENA.
		 */
		if (zcp->zc_data.zc_ena == ena)
			break;

		/*
		 * Matches a case involving load errors for this same pool.
		 */
		if (zcp->zc_data.zc_pool_guid == pool_guid &&
		    zcp->zc_data.zc_pool_state == SPA_LOAD_OPEN &&
		    pool_state == SPA_LOAD_OPEN)
			break;

		/*
		 * Device errors for the same device.
		 */
		if (vdev_guid != 0 && zcp->zc_data.zc_vdev_guid == vdev_guid)
			break;
	}

	if (zcp == NULL) {
		fmd_case_t *cs;
		zfs_case_data_t data;

		/*
		 * If this is one of our 'fake' resource ereports, and there is
		 * no case open, simply discard it.
		 */
		if (isresource)
			return;

		/*
		 * Open a new case.
		 */
		cs = fmd_case_open(hdl, NULL);

		/*
		 * Initialize the case buffer.  To commonize code, we actually
		 * create the buffer with existing data, and then call
		 * zfs_case_unserialize() to instantiate the in-core structure.
		 */
		fmd_buf_create(hdl, cs, CASE_DATA,
		    sizeof (zfs_case_data_t));

		data.zc_version = CASE_DATA_VERSION;
		data.zc_ena = ena;
		data.zc_pool_guid = pool_guid;
		data.zc_vdev_guid = vdev_guid;
		data.zc_has_timer = 0;
		data.zc_pool_state = (int)pool_state;

		fmd_buf_write(hdl, cs, CASE_DATA, &data, sizeof (data));

		zcp = zfs_case_unserialize(hdl, cs);
		assert(zcp != NULL);
	}

	/*
	 * The 'resource.fs.zfs.ok' event is a special internal-only event that
	 * signifies that a pool or device that was previously faulted has now
	 * come online (as detected by ZFS).  This allows us to close the
	 * associated case.
	 */
	if (isresource) {
		fmd_case_close(hdl, zcp->zc_case);
		return;
	}

	/*
	 * Associate the ereport with this case.
	 */
	fmd_case_add_ereport(hdl, zcp->zc_case, ep);

	/*
	 * Don't do anything else if this case is already solved.
	 */
	if (fmd_case_solved(hdl, zcp->zc_case))
		return;

	/*
	 * Determine if we should solve the case and generate a fault.  We solve
	 * a case if:
	 *
	 * 	a. A pool failed to open (ereport.fs.zfs.pool)
	 * 	b. A device failed to open (ereport.fs.zfs.pool) while a pool
	 *	   was up and running.
	 *
	 * We may see a series of ereports associated with a pool open, all
	 * chained together by the same ENA.  If the pool open succeeds, then
	 * we'll see no further ereports.  To detect when a pool open has
	 * succeeded, we associate a timer with the event.  When it expires, we
	 * close the case.
	 */
	if (fmd_nvl_class_match(hdl, nvl, "ereport.fs.zfs.zpool")) {
		/*
		 * Pool level fault.
		 */
		nvlist_t *fault;

		fault = fmd_nvl_create_fault(hdl, "fault.fs.zfs.pool",
		    100, detector, NULL, detector);
		fmd_case_add_suspect(hdl, zcp->zc_case, fault);
		fmd_case_solve(hdl, zcp->zc_case);

		if (zcp->zc_data.zc_has_timer) {
			fmd_timer_remove(hdl, zcp->zc_timer);
			zcp->zc_data.zc_has_timer = 0;
			zfs_case_serialize(hdl, zcp);
		}

	} else if (fmd_nvl_class_match(hdl, nvl, "ereport.fs.zfs.vdev.*") &&
	    pool_state == SPA_LOAD_NONE) {
		/*
		 * Device fault.
		 */
		nvlist_t *fault;

		fault = fmd_nvl_create_fault(hdl, "fault.fs.zfs.device",
		    100, detector, NULL, detector);
		fmd_case_add_suspect(hdl, zcp->zc_case, fault);
		fmd_case_solve(hdl, zcp->zc_case);

		if (zcp->zc_data.zc_has_timer) {
			fmd_timer_remove(hdl, zcp->zc_timer);
			zcp->zc_data.zc_has_timer = 0;
			zfs_case_serialize(hdl, zcp);
		}

	} else if (pool_state == SPA_LOAD_OPEN) {
		/*
		 * Error incurred during a pool open.  Reset the timer
		 * associated with this case.
		 */
		if (zcp->zc_data.zc_has_timer)
			fmd_timer_remove(hdl, zcp->zc_timer);
		zcp->zc_timer = fmd_timer_install(hdl, zcp, NULL,
		    zfs_case_timeout);
		if (!zcp->zc_data.zc_has_timer) {
			zcp->zc_data.zc_has_timer = 1;
			zfs_case_serialize(hdl, zcp);
		}
	}
}

/*
 * Timeout - indicates that a pool had faults, but was eventually opened
 * successfully.
 */
/* ARGSUSED */
static void
zfs_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	zfs_case_t *zcp = data;

	zcp->zc_data.zc_has_timer = 0;

	fmd_case_close(hdl, zcp->zc_case);
}

static void
zfs_close(fmd_hdl_t *hdl, fmd_case_t *cs)
{
	zfs_case_t *zcp = fmd_case_getspecific(hdl, cs);

	if (zcp->zc_data.zc_has_timer)
		fmd_timer_remove(hdl, zcp->zc_timer);
	uu_list_remove(zfs_cases, zcp);
	fmd_hdl_free(hdl, zcp, sizeof (zfs_case_t));
}

static const fmd_hdl_ops_t fmd_ops = {
	zfs_recv,	/* fmdo_recv */
	zfs_timeout,	/* fmdo_timeout */
	zfs_close,	/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
};

static const fmd_prop_t fmd_props[] = {
	{ "case_timeout", FMD_TYPE_UINT32, "5" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"ZFS Diagnosis Engine", "1.0", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	fmd_case_t *cp;

	if ((zfs_case_pool = uu_list_pool_create("zfs_case_pool",
	    sizeof (zfs_case_t), offsetof(zfs_case_t, zc_node),
	    NULL, 0)) == NULL)
		return;

	if ((zfs_cases = uu_list_create(zfs_case_pool, NULL, 0)) == NULL) {
		uu_list_pool_destroy(zfs_case_pool);
		return;
	}

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0) {
		uu_list_destroy(zfs_cases);
		uu_list_pool_destroy(zfs_case_pool);
		return;
	}

	/*
	 * Iterate over all active cases and unserialize the associated buffers,
	 * adding them to our list of open cases.
	 */
	for (cp = fmd_case_next(hdl, NULL);
	    cp != NULL; cp = fmd_case_next(hdl, cp))
		(void) zfs_case_unserialize(hdl, cp);

	zfs_case_timeout = fmd_prop_get_int32(hdl, "case_timeout") * NANOSEC;
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	zfs_case_t *zcp;
	uu_list_walk_t *walk;

	/*
	 * Remove all active cases.
	 */
	walk = uu_list_walk_start(zfs_cases, UU_WALK_ROBUST);
	while ((zcp = uu_list_walk_next(walk)) != NULL) {
		uu_list_remove(zfs_cases, zcp);
		fmd_hdl_free(hdl, zcp, sizeof (zfs_case_t));
	}
	uu_list_walk_end(walk);

	uu_list_destroy(zfs_cases);
	uu_list_pool_destroy(zfs_case_pool);
}
