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

#include <assert.h>
#include <stddef.h>
#include <strings.h>
#include <libuutil.h>
#include <libzfs.h>
#include <fm/fmd_api.h>
#include <sys/fs/zfs.h>
#include <sys/fm/protocol.h>
#include <sys/fm/fs/zfs.h>

/*
 * Our serd engines are named 'zfs_<pool_guid>_<vdev_guid>_{checksum,io}'.  This
 * #define reserves enough space for two 64-bit hex values plus the length of
 * the longest string.
 */
#define	MAX_SERDLEN	(16 * 2 + sizeof ("zfs___checksum"))

/*
 * On-disk case structure.  This must maintain backwards compatibility with
 * previous versions of the DE.  By default, any members appended to the end
 * will be filled with zeros if they don't exist in a previous version.
 */
typedef struct zfs_case_data {
	uint64_t	zc_version;
	uint64_t	zc_ena;
	uint64_t	zc_pool_guid;
	uint64_t	zc_vdev_guid;
	int		zc_has_timer;		/* defunct */
	int		zc_pool_state;
	char		zc_serd_checksum[MAX_SERDLEN];
	char		zc_serd_io[MAX_SERDLEN];
	int		zc_has_remove_timer;
} zfs_case_data_t;

/*
 * In-core case structure.
 */
typedef struct zfs_case {
	boolean_t	zc_present;
	uint32_t	zc_version;
	zfs_case_data_t	zc_data;
	fmd_case_t	*zc_case;
	uu_list_node_t	zc_node;
	id_t		zc_remove_timer;
} zfs_case_t;

#define	CASE_DATA			"data"
#define	CASE_DATA_VERSION_INITIAL	1
#define	CASE_DATA_VERSION_SERD		2

static hrtime_t zfs_remove_timeout;

uu_list_pool_t *zfs_case_pool;
uu_list_t *zfs_cases;

#define	ZFS_MAKE_RSRC(type)	\
    FM_RSRC_CLASS "." ZFS_ERROR_CLASS "." type
#define	ZFS_MAKE_EREPORT(type)	\
    FM_EREPORT_CLASS "." ZFS_ERROR_CLASS "." type

/*
 * Write out the persistent representation of an active case.
 */
static void
zfs_case_serialize(fmd_hdl_t *hdl, zfs_case_t *zcp)
{
	/*
	 * Always update cases to the latest version, even if they were the
	 * previous version when unserialized.
	 */
	zcp->zc_data.zc_version = CASE_DATA_VERSION_SERD;
	fmd_buf_write(hdl, zcp->zc_case, CASE_DATA, &zcp->zc_data,
	    sizeof (zcp->zc_data));
}

/*
 * Read back the persistent representation of an active case.
 */
static zfs_case_t *
zfs_case_unserialize(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	zfs_case_t *zcp;

	zcp = fmd_hdl_zalloc(hdl, sizeof (zfs_case_t), FMD_SLEEP);
	zcp->zc_case = cp;

	fmd_buf_read(hdl, cp, CASE_DATA, &zcp->zc_data,
	    sizeof (zcp->zc_data));

	if (zcp->zc_data.zc_version > CASE_DATA_VERSION_SERD) {
		fmd_hdl_free(hdl, zcp, sizeof (zfs_case_t));
		return (NULL);
	}

	/*
	 * fmd_buf_read() will have already zeroed out the remainder of the
	 * buffer, so we don't have to do anything special if the version
	 * doesn't include the SERD engine name.
	 */

	if (zcp->zc_data.zc_has_remove_timer)
		zcp->zc_remove_timer = fmd_timer_install(hdl, zcp,
		    NULL, zfs_remove_timeout);

	(void) uu_list_insert_before(zfs_cases, NULL, zcp);

	fmd_case_setspecific(hdl, cp, zcp);

	return (zcp);
}

/*
 * Iterate over any active cases.  If any cases are associated with a pool or
 * vdev which is no longer present on the system, close the associated case.
 */
static void
zfs_mark_vdev(uint64_t pool_guid, nvlist_t *vd)
{
	uint64_t vdev_guid;
	uint_t c, children;
	nvlist_t **child;
	zfs_case_t *zcp;
	int ret;

	ret = nvlist_lookup_uint64(vd, ZPOOL_CONFIG_GUID, &vdev_guid);
	assert(ret == 0);

	/*
	 * Mark any cases associated with this (pool, vdev) pair.
	 */
	for (zcp = uu_list_first(zfs_cases); zcp != NULL;
	    zcp = uu_list_next(zfs_cases, zcp)) {
		if (zcp->zc_data.zc_pool_guid == pool_guid &&
		    zcp->zc_data.zc_vdev_guid == vdev_guid)
			zcp->zc_present = B_TRUE;
	}

	/*
	 * Iterate over all children.
	 */
	if (nvlist_lookup_nvlist_array(vd, ZPOOL_CONFIG_CHILDREN, &child,
	    &children) != 0) {
		for (c = 0; c < children; c++)
			zfs_mark_vdev(pool_guid, child[c]);
	}
}

/*ARGSUSED*/
static int
zfs_mark_pool(zpool_handle_t *zhp, void *unused)
{
	zfs_case_t *zcp;
	uint64_t pool_guid;
	nvlist_t *config, *vd;
	int ret;

	pool_guid = zpool_get_prop_int(zhp, ZPOOL_PROP_GUID, NULL);
	/*
	 * Mark any cases associated with just this pool.
	 */
	for (zcp = uu_list_first(zfs_cases); zcp != NULL;
	    zcp = uu_list_next(zfs_cases, zcp)) {
		if (zcp->zc_data.zc_pool_guid == pool_guid &&
		    zcp->zc_data.zc_vdev_guid == 0)
			zcp->zc_present = B_TRUE;
	}

	if ((config = zpool_get_config(zhp, NULL)) == NULL) {
		zpool_close(zhp);
		return (-1);
	}

	ret = nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &vd);
	assert(ret == 0);

	zfs_mark_vdev(pool_guid, vd);

	zpool_close(zhp);

	return (0);
}

static void
zfs_purge_cases(fmd_hdl_t *hdl)
{
	zfs_case_t *zcp;
	uu_list_walk_t *walk;
	libzfs_handle_t *zhdl = fmd_hdl_getspecific(hdl);

	/*
	 * There is no way to open a pool by GUID, or lookup a vdev by GUID.  No
	 * matter what we do, we're going to have to stomach a O(vdevs * cases)
	 * algorithm.  In reality, both quantities are likely so small that
	 * neither will matter. Given that iterating over pools is more
	 * expensive than iterating over the in-memory case list, we opt for a
	 * 'present' flag in each case that starts off cleared.  We then iterate
	 * over all pools, marking those that are still present, and removing
	 * those that aren't found.
	 *
	 * Note that we could also construct an FMRI and rely on
	 * fmd_nvl_fmri_present(), but this would end up doing the same search.
	 */

	/*
	 * Mark the cases an not present.
	 */
	for (zcp = uu_list_first(zfs_cases); zcp != NULL;
	    zcp = uu_list_next(zfs_cases, zcp))
		zcp->zc_present = B_FALSE;

	/*
	 * Iterate over all pools and mark the pools and vdevs found.  If this
	 * fails (most probably because we're out of memory), then don't close
	 * any of the cases and we cannot be sure they are accurate.
	 */
	if (zpool_iter(zhdl, zfs_mark_pool, NULL) != 0)
		return;

	/*
	 * Remove those cases which were not found.
	 */
	walk = uu_list_walk_start(zfs_cases, UU_WALK_ROBUST);
	while ((zcp = uu_list_walk_next(walk)) != NULL) {
		if (!zcp->zc_present)
			fmd_case_close(hdl, zcp->zc_case);
	}
	uu_list_walk_end(walk);
}

/*
 * Construct the name of a serd engine given the pool/vdev GUID and type (io or
 * checksum).
 */
static void
zfs_serd_name(char *buf, uint64_t pool_guid, uint64_t vdev_guid,
    const char *type)
{
	(void) snprintf(buf, MAX_SERDLEN, "zfs_%llx_%llx_%s", pool_guid,
	    vdev_guid, type);
}

/*
 * Solve a given ZFS case.  This first checks to make sure the diagnosis is
 * still valid, as well as cleaning up any pending timer associated with the
 * case.
 */
static void
zfs_case_solve(fmd_hdl_t *hdl, zfs_case_t *zcp, const char *faultname,
    boolean_t checkunusable)
{
	nvlist_t *detector, *fault;
	boolean_t serialize;

	/*
	 * Construct the detector from the case data.  The detector is in the
	 * ZFS scheme, and is either the pool or the vdev, depending on whether
	 * this is a vdev or pool fault.
	 */
	if (nvlist_alloc(&detector, NV_UNIQUE_NAME, 0) != 0)
		return;

	if (nvlist_add_uint8(detector, FM_VERSION, ZFS_SCHEME_VERSION0) != 0 ||
	    nvlist_add_string(detector, FM_FMRI_SCHEME,
	    FM_FMRI_SCHEME_ZFS) != 0 ||
	    nvlist_add_uint64(detector, FM_FMRI_ZFS_POOL,
	    zcp->zc_data.zc_pool_guid) != 0 ||
	    (zcp->zc_data.zc_vdev_guid != 0 &&
	    nvlist_add_uint64(detector, FM_FMRI_ZFS_VDEV,
	    zcp->zc_data.zc_vdev_guid) != 0)) {
		nvlist_free(detector);
		return;
	}

	/*
	 * We also want to make sure that the detector (pool or vdev) properly
	 * reflects the diagnosed state, when the fault corresponds to internal
	 * ZFS state (i.e. not checksum or I/O error-induced).  Otherwise, a
	 * device which was unavailable early in boot (because the driver/file
	 * wasn't available) and is now healthy will be mis-diagnosed.
	 */
	if (!fmd_nvl_fmri_present(hdl, detector) ||
	    (checkunusable && !fmd_nvl_fmri_unusable(hdl, detector))) {
		fmd_case_close(hdl, zcp->zc_case);
		nvlist_free(detector);
		return;
	}

	fault = fmd_nvl_create_fault(hdl, faultname, 100, detector, NULL,
	    detector);
	fmd_case_add_suspect(hdl, zcp->zc_case, fault);
	fmd_case_solve(hdl, zcp->zc_case);

	serialize = B_FALSE;
	if (zcp->zc_data.zc_has_remove_timer) {
		fmd_timer_remove(hdl, zcp->zc_remove_timer);
		zcp->zc_data.zc_has_remove_timer = 0;
		serialize = B_TRUE;
	}
	if (serialize)
		zfs_case_serialize(hdl, zcp);

	nvlist_free(detector);
}

/*
 * Main fmd entry point.
 */
/*ARGSUSED*/
static void
zfs_fm_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	zfs_case_t *zcp, *dcp;
	int32_t pool_state;
	uint64_t ena, pool_guid, vdev_guid;
	nvlist_t *detector;
	boolean_t isresource;
	boolean_t checkremove;

	isresource = fmd_nvl_class_match(hdl, nvl, "resource.fs.zfs.*");

	if (isresource) {
		/*
		 * For resources, we don't have a normal payload.
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
	 * We also ignore all ereports generated during an import of a pool,
	 * since the only possible fault (.pool) would result in import failure,
	 * and hence no persistent fault.  Some day we may want to do something
	 * with these ereports, so we continue generating them internally.
	 */
	if (pool_state == SPA_LOAD_IMPORT)
		return;

	/*
	 * Device I/O errors are ignored during pool open.
	 */
	if (pool_state == SPA_LOAD_OPEN &&
	    (fmd_nvl_class_match(hdl, nvl, "ereport.fs.zfs.checksum") ||
	    fmd_nvl_class_match(hdl, nvl, "ereport.fs.zfs.io")))
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
	(void) nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_ZFS_POOL_GUID, &pool_guid);
	if (nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_ZFS_VDEV_GUID, &vdev_guid) != 0)
		vdev_guid = 0;
	if (nvlist_lookup_uint64(nvl, FM_EREPORT_ENA, &ena) != 0)
		ena = 0;

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
		zfs_case_data_t data = { 0 };

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

		data.zc_version = CASE_DATA_VERSION_SERD;
		data.zc_ena = ena;
		data.zc_pool_guid = pool_guid;
		data.zc_vdev_guid = vdev_guid;
		data.zc_pool_state = (int)pool_state;

		fmd_buf_write(hdl, cs, CASE_DATA, &data, sizeof (data));

		zcp = zfs_case_unserialize(hdl, cs);
		assert(zcp != NULL);
	}

	if (isresource) {
		if (fmd_nvl_class_match(hdl, nvl,
		    ZFS_MAKE_RSRC(FM_RESOURCE_AUTOREPLACE))) {
			/*
			 * The 'resource.fs.zfs.autoreplace' event indicates
			 * that the pool was loaded with the 'autoreplace'
			 * property set.  In this case, any pending device
			 * failures should be ignored, as the asynchronous
			 * autoreplace handling will take care of them.
			 */
			fmd_case_close(hdl, zcp->zc_case);
		} else if (fmd_nvl_class_match(hdl, nvl,
		    ZFS_MAKE_RSRC(FM_RESOURCE_REMOVED))) {
			/*
			 * The 'resource.fs.zfs.removed' event indicates that
			 * device removal was detected, and the device was
			 * closed asynchronously.  If this is the case, we
			 * assume that any recent I/O errors were due to the
			 * device removal, not any fault of the device itself.
			 * We reset the SERD engine, and cancel any pending
			 * timers.
			 */
			if (zcp->zc_data.zc_has_remove_timer) {
				fmd_timer_remove(hdl, zcp->zc_remove_timer);
				zcp->zc_data.zc_has_remove_timer = 0;
				zfs_case_serialize(hdl, zcp);
			}
			if (zcp->zc_data.zc_serd_io[0] != '\0')
				fmd_serd_reset(hdl,
				    zcp->zc_data.zc_serd_io);
			if (zcp->zc_data.zc_serd_checksum[0] != '\0')
				fmd_serd_reset(hdl,
				    zcp->zc_data.zc_serd_checksum);
		}
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
	if (fmd_nvl_class_match(hdl, nvl,
	    ZFS_MAKE_EREPORT(FM_EREPORT_ZFS_POOL))) {
		/*
		 * Pool level fault.  Before solving the case, go through and
		 * close any open device cases that may be pending.
		 */
		for (dcp = uu_list_first(zfs_cases); dcp != NULL;
		    dcp = uu_list_next(zfs_cases, dcp)) {
			if (dcp->zc_data.zc_pool_guid ==
			    zcp->zc_data.zc_pool_guid &&
			    dcp->zc_data.zc_vdev_guid != 0)
				fmd_case_close(hdl, dcp->zc_case);
		}

		zfs_case_solve(hdl, zcp, "fault.fs.zfs.pool", B_TRUE);
	} else if (fmd_nvl_class_match(hdl, nvl, "ereport.fs.zfs.vdev.*")) {
		/*
		 * Device fault.  If this occurred during pool open, then defer
		 * reporting the fault.  If the pool itself could not be opeend,
		 * we only report the pool fault, not every device fault that
		 * may have caused the problem.  If we do not see a pool fault
		 * within the timeout period, then we'll solve the device case.
		 */
		zfs_case_solve(hdl, zcp, "fault.fs.zfs.device",  B_TRUE);
	} else if (fmd_nvl_class_match(hdl, nvl,
	    ZFS_MAKE_EREPORT(FM_EREPORT_ZFS_IO)) ||
	    fmd_nvl_class_match(hdl, nvl,
	    ZFS_MAKE_EREPORT(FM_EREPORT_ZFS_CHECKSUM)) ||
	    fmd_nvl_class_match(hdl, nvl,
	    ZFS_MAKE_EREPORT(FM_EREPORT_ZFS_IO_FAILURE)) ||
	    fmd_nvl_class_match(hdl, nvl,
	    ZFS_MAKE_EREPORT(FM_EREPORT_ZFS_PROBE_FAILURE))) {
		char *failmode = NULL;

		/*
		 * If this is a checksum or I/O error, then toss it into the
		 * appropriate SERD engine and check to see if it has fired.
		 * Ideally, we want to do something more sophisticated,
		 * (persistent errors for a single data block, etc).  For now,
		 * a single SERD engine is sufficient.
		 */
		if (fmd_nvl_class_match(hdl, nvl,
		    ZFS_MAKE_EREPORT(FM_EREPORT_ZFS_IO))) {
			if (zcp->zc_data.zc_serd_io[0] == '\0') {
				zfs_serd_name(zcp->zc_data.zc_serd_io,
				    pool_guid, vdev_guid, "io");
				fmd_serd_create(hdl, zcp->zc_data.zc_serd_io,
				    fmd_prop_get_int32(hdl, "io_N"),
				    fmd_prop_get_int64(hdl, "io_T"));
				zfs_case_serialize(hdl, zcp);
			}
			if (fmd_serd_record(hdl, zcp->zc_data.zc_serd_io, ep))
				checkremove = B_TRUE;
		} else if (fmd_nvl_class_match(hdl, nvl,
		    ZFS_MAKE_EREPORT(FM_EREPORT_ZFS_CHECKSUM))) {
			if (zcp->zc_data.zc_serd_checksum[0] == '\0') {
				zfs_serd_name(zcp->zc_data.zc_serd_checksum,
				    pool_guid, vdev_guid, "checksum");
				fmd_serd_create(hdl,
				    zcp->zc_data.zc_serd_checksum,
				    fmd_prop_get_int32(hdl, "checksum_N"),
				    fmd_prop_get_int64(hdl, "checksum_T"));
				zfs_case_serialize(hdl, zcp);
			}
			if (fmd_serd_record(hdl,
			    zcp->zc_data.zc_serd_checksum, ep)) {
				zfs_case_solve(hdl, zcp,
				    "fault.fs.zfs.vdev.checksum", B_FALSE);
			}
		} else if (fmd_nvl_class_match(hdl, nvl,
		    ZFS_MAKE_EREPORT(FM_EREPORT_ZFS_IO_FAILURE)) &&
		    (nvlist_lookup_string(nvl,
		    FM_EREPORT_PAYLOAD_ZFS_POOL_FAILMODE, &failmode) == 0) &&
		    failmode != NULL) {
			if (strncmp(failmode, FM_EREPORT_FAILMODE_CONTINUE,
			    strlen(FM_EREPORT_FAILMODE_CONTINUE)) == 0) {
				zfs_case_solve(hdl, zcp,
				    "fault.fs.zfs.io_failure_continue",
				    B_FALSE);
			} else if (strncmp(failmode, FM_EREPORT_FAILMODE_WAIT,
			    strlen(FM_EREPORT_FAILMODE_WAIT)) == 0) {
				zfs_case_solve(hdl, zcp,
				    "fault.fs.zfs.io_failure_wait", B_FALSE);
			}
		} else if (fmd_nvl_class_match(hdl, nvl,
		    ZFS_MAKE_EREPORT(FM_EREPORT_ZFS_PROBE_FAILURE))) {
			checkremove = B_TRUE;
		}

		/*
		 * Because I/O errors may be due to device removal, we postpone
		 * any diagnosis until we're sure that we aren't about to
		 * receive a 'resource.fs.zfs.removed' event.
		 */
		if (checkremove) {
			if (zcp->zc_data.zc_has_remove_timer)
				fmd_timer_remove(hdl, zcp->zc_remove_timer);
			zcp->zc_remove_timer = fmd_timer_install(hdl, zcp, NULL,
			    zfs_remove_timeout);
			if (!zcp->zc_data.zc_has_remove_timer) {
				zcp->zc_data.zc_has_remove_timer = 1;
				zfs_case_serialize(hdl, zcp);
			}
		}
	}
}

/*
 * The timeout is fired when we diagnosed an I/O error, and it was not due to
 * device removal (which would cause the timeout to be cancelled).
 */
/* ARGSUSED */
static void
zfs_fm_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	zfs_case_t *zcp = data;

	if (id == zcp->zc_remove_timer)
		zfs_case_solve(hdl, zcp, "fault.fs.zfs.vdev.io", B_FALSE);
}

static void
zfs_fm_close(fmd_hdl_t *hdl, fmd_case_t *cs)
{
	zfs_case_t *zcp = fmd_case_getspecific(hdl, cs);

	if (zcp->zc_data.zc_serd_checksum[0] != '\0')
		fmd_serd_destroy(hdl, zcp->zc_data.zc_serd_checksum);
	if (zcp->zc_data.zc_serd_io[0] != '\0')
		fmd_serd_destroy(hdl, zcp->zc_data.zc_serd_io);
	if (zcp->zc_data.zc_has_remove_timer)
		fmd_timer_remove(hdl, zcp->zc_remove_timer);
	uu_list_remove(zfs_cases, zcp);
	fmd_hdl_free(hdl, zcp, sizeof (zfs_case_t));
}

/*
 * We use the fmd gc entry point to look for old cases that no longer apply.
 * This allows us to keep our set of case data small in a long running system.
 */
static void
zfs_fm_gc(fmd_hdl_t *hdl)
{
	zfs_purge_cases(hdl);
}

static const fmd_hdl_ops_t fmd_ops = {
	zfs_fm_recv,	/* fmdo_recv */
	zfs_fm_timeout,	/* fmdo_timeout */
	zfs_fm_close,	/* fmdo_close */
	NULL,		/* fmdo_stats */
	zfs_fm_gc,	/* fmdo_gc */
};

static const fmd_prop_t fmd_props[] = {
	{ "case_timeout", FMD_TYPE_TIME, "5sec" },
	{ "checksum_N", FMD_TYPE_UINT32, "10" },
	{ "checksum_T", FMD_TYPE_TIME, "10min" },
	{ "io_N", FMD_TYPE_UINT32, "10" },
	{ "io_T", FMD_TYPE_TIME, "10min" },
	{ "remove_timeout", FMD_TYPE_TIME, "5sec" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"ZFS Diagnosis Engine", "1.0", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	fmd_case_t *cp;
	libzfs_handle_t *zhdl;

	if ((zhdl = libzfs_init()) == NULL)
		return;

	if ((zfs_case_pool = uu_list_pool_create("zfs_case_pool",
	    sizeof (zfs_case_t), offsetof(zfs_case_t, zc_node),
	    NULL, 0)) == NULL) {
		libzfs_fini(zhdl);
		return;
	}

	if ((zfs_cases = uu_list_create(zfs_case_pool, NULL, 0)) == NULL) {
		uu_list_pool_destroy(zfs_case_pool);
		libzfs_fini(zhdl);
		return;
	}

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0) {
		uu_list_destroy(zfs_cases);
		uu_list_pool_destroy(zfs_case_pool);
		libzfs_fini(zhdl);
		return;
	}

	fmd_hdl_setspecific(hdl, zhdl);

	/*
	 * Iterate over all active cases and unserialize the associated buffers,
	 * adding them to our list of open cases.
	 */
	for (cp = fmd_case_next(hdl, NULL);
	    cp != NULL; cp = fmd_case_next(hdl, cp))
		(void) zfs_case_unserialize(hdl, cp);

	/*
	 * Clear out any old cases that are no longer valid.
	 */
	zfs_purge_cases(hdl);

	zfs_remove_timeout = fmd_prop_get_int64(hdl, "remove_timeout");
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	zfs_case_t *zcp;
	uu_list_walk_t *walk;
	libzfs_handle_t *zhdl;

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

	zhdl = fmd_hdl_getspecific(hdl);
	libzfs_fini(zhdl);
}
