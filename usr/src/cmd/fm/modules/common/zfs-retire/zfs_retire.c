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
 * The ZFS retire agent is responsible for managing hot spares across all pools.
 * When we see a device fault or a device removal, we try to open the associated
 * pool and look for any hot spares.  We iterate over any available hot spares
 * and attempt a 'zpool replace' for each one.
 *
 * For vdevs diagnosed as faulty, the agent is also responsible for proactively
 * marking the vdev FAULTY (for I/O errors) or DEGRADED (for checksum errors).
 */

#include <fm/fmd_api.h>
#include <sys/fs/zfs.h>
#include <sys/fm/protocol.h>
#include <sys/fm/fs/zfs.h>
#include <libzfs.h>
#include <string.h>

/*
 * Find a pool with a matching GUID.
 */
typedef struct find_cbdata {
	uint64_t	cb_guid;
	zpool_handle_t	*cb_zhp;
} find_cbdata_t;

static int
find_pool(zpool_handle_t *zhp, void *data)
{
	find_cbdata_t *cbp = data;

	if (cbp->cb_guid ==
	    zpool_get_prop_int(zhp, ZPOOL_PROP_GUID, NULL)) {
		cbp->cb_zhp = zhp;
		return (1);
	}

	zpool_close(zhp);
	return (0);
}

/*
 * Find a vdev within a tree with a matching GUID.
 */
static nvlist_t *
find_vdev(nvlist_t *nv, uint64_t search)
{
	uint64_t guid;
	nvlist_t **child;
	uint_t c, children;
	nvlist_t *ret;

	if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid) == 0 &&
	    guid == search)
		return (nv);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		return (NULL);

	for (c = 0; c < children; c++) {
		if ((ret = find_vdev(child[c], search)) != NULL)
			return (ret);
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_L2CACHE,
	    &child, &children) != 0)
		return (NULL);

	for (c = 0; c < children; c++) {
		if ((ret = find_vdev(child[c], search)) != NULL)
			return (ret);
	}

	return (NULL);
}

/*
 * Given a (pool, vdev) GUID pair, find the matching pool and vdev.
 */
static zpool_handle_t *
find_by_guid(libzfs_handle_t *zhdl, uint64_t pool_guid, uint64_t vdev_guid,
    nvlist_t **vdevp)
{
	find_cbdata_t cb;
	zpool_handle_t *zhp;
	nvlist_t *config, *nvroot;

	/*
	 * Find the corresponding pool and make sure the vdev still exists.
	 */
	cb.cb_guid = pool_guid;
	if (zpool_iter(zhdl, find_pool, &cb) != 1)
		return (NULL);

	zhp = cb.cb_zhp;
	config = zpool_get_config(zhp, NULL);
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) != 0) {
		zpool_close(zhp);
		return (NULL);
	}

	if ((*vdevp = find_vdev(nvroot, vdev_guid)) == NULL) {
		zpool_close(zhp);
		return (NULL);
	}

	return (zhp);
}

/*
 * Given a vdev, attempt to replace it with every known spare until one
 * succeeds.
 */
static void
replace_with_spare(zpool_handle_t *zhp, nvlist_t *vdev)
{
	nvlist_t *config, *nvroot, *replacement;
	nvlist_t **spares;
	uint_t s, nspares;
	char *dev_name;

	config = zpool_get_config(zhp, NULL);
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) != 0)
		return;

	/*
	 * Find out if there are any hot spares available in the pool.
	 */
	if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_SPARES,
	    &spares, &nspares) != 0)
		return;

	if (nvlist_alloc(&replacement, NV_UNIQUE_NAME, 0) != 0)
		return;

	if (nvlist_add_string(replacement, ZPOOL_CONFIG_TYPE,
	    VDEV_TYPE_ROOT) != 0) {
		nvlist_free(replacement);
		return;
	}

	dev_name = zpool_vdev_name(NULL, zhp, vdev);

	/*
	 * Try to replace each spare, ending when we successfully
	 * replace it.
	 */
	for (s = 0; s < nspares; s++) {
		char *spare_name;

		if (nvlist_lookup_string(spares[s], ZPOOL_CONFIG_PATH,
		    &spare_name) != 0)
			continue;

		if (nvlist_add_nvlist_array(replacement,
		    ZPOOL_CONFIG_CHILDREN, &spares[s], 1) != 0)
			continue;

		if (zpool_vdev_attach(zhp, dev_name, spare_name,
		    replacement, B_TRUE) == 0)
			break;
	}

	free(dev_name);
	nvlist_free(replacement);
}

/*ARGSUSED*/
static void
zfs_retire_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class)
{
	uint64_t pool_guid, vdev_guid;
	zpool_handle_t *zhp;
	nvlist_t *resource, *fault;
	nvlist_t **faults;
	uint_t f, nfaults;
	libzfs_handle_t *zhdl = fmd_hdl_getspecific(hdl);
	boolean_t fault_device, degrade_device;
	boolean_t is_repair;
	char *scheme;
	nvlist_t *vdev;
	char *uuid;
	int repair_done = 0;

	/*
	 * If this is a resource notifying us of device removal, then simply
	 * check for an available spare and continue.
	 */
	if (strcmp(class, "resource.fs.zfs.removed") == 0) {
		if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_ZFS_POOL_GUID,
		    &pool_guid) != 0 ||
		    nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_ZFS_VDEV_GUID,
		    &vdev_guid) != 0)
			return;

		if ((zhp = find_by_guid(zhdl, pool_guid, vdev_guid,
		    &vdev)) == NULL)
			return;

		if (fmd_prop_get_int32(hdl, "spare_on_remove"))
			replace_with_spare(zhp, vdev);
		zpool_close(zhp);
		return;
	}

	if (strcmp(class, FM_LIST_REPAIRED_CLASS) == 0)
		is_repair = B_TRUE;
	else
		is_repair = B_FALSE;

	/*
	 * We subscribe to zfs faults as well as all repair events.
	 */
	if (nvlist_lookup_nvlist_array(nvl, FM_SUSPECT_FAULT_LIST,
	    &faults, &nfaults) != 0)
		return;

	for (f = 0; f < nfaults; f++) {
		fault = faults[f];

		fault_device = B_FALSE;
		degrade_device = B_FALSE;

		/*
		 * While we subscribe to fault.fs.zfs.*, we only take action
		 * for faults targeting a specific vdev (open failure or SERD
		 * failure).
		 */
		if (fmd_nvl_class_match(hdl, fault, "fault.fs.zfs.vdev.io"))
			fault_device = B_TRUE;
		else if (fmd_nvl_class_match(hdl, fault,
		    "fault.fs.zfs.vdev.checksum"))
			degrade_device = B_TRUE;
		else if (fmd_nvl_class_match(hdl, fault, "fault.fs.zfs.device"))
			fault_device = B_FALSE;
		else
			continue;

		if (nvlist_lookup_nvlist(fault, FM_FAULT_RESOURCE,
		    &resource) != 0 ||
		    nvlist_lookup_string(resource, FM_FMRI_SCHEME,
		    &scheme) != 0)
			continue;

		if (strcmp(scheme, FM_FMRI_SCHEME_ZFS) != 0)
			continue;

		if (nvlist_lookup_uint64(resource, FM_FMRI_ZFS_POOL,
		    &pool_guid) != 0 ||
		    nvlist_lookup_uint64(resource, FM_FMRI_ZFS_VDEV,
		    &vdev_guid) != 0)
			continue;

		if ((zhp = find_by_guid(zhdl, pool_guid, vdev_guid,
		    &vdev)) == NULL)
			continue;

		/*
		 * If this is a repair event, then mark the vdev as repaired and
		 * continue.
		 */
		if (is_repair) {
			repair_done = 1;
			(void) zpool_vdev_clear(zhp, vdev_guid);
			zpool_close(zhp);
			continue;
		}

		/*
		 * Actively fault the device if needed.
		 */
		if (fault_device)
			(void) zpool_vdev_fault(zhp, vdev_guid);
		if (degrade_device)
			(void) zpool_vdev_degrade(zhp, vdev_guid);

		/*
		 * Attempt to substitute a hot spare.
		 */
		replace_with_spare(zhp, vdev);
		zpool_close(zhp);
	}

	if (strcmp(class, FM_LIST_REPAIRED_CLASS) == 0 && repair_done &&
	    nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) == 0)
		fmd_case_uuresolved(hdl, uuid);
}

static const fmd_hdl_ops_t fmd_ops = {
	zfs_retire_recv,	/* fmdo_recv */
	NULL,			/* fmdo_timeout */
	NULL,			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
};

static const fmd_prop_t fmd_props[] = {
	{ "spare_on_remove", FMD_TYPE_BOOL, "true" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"ZFS Retire Agent", "1.0", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	libzfs_handle_t *zhdl;

	if ((zhdl = libzfs_init()) == NULL)
		return;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0) {
		libzfs_fini(zhdl);
		return;
	}

	fmd_hdl_setspecific(hdl, zhdl);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	libzfs_handle_t *zhdl = fmd_hdl_getspecific(hdl);

	if (zhdl != NULL)
		libzfs_fini(zhdl);
}
