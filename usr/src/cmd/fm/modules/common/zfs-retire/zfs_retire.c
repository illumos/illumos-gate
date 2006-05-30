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

/*
 * The ZFS retire agent is responsible for managing hot spares across all pools.
 * When we see a device fault, we try to open the associated pool and look for
 * any hot spares.  We iterate over any available hot spares and attempt a
 * 'zpool replace' for each one.
 */

#include <fm/fmd_api.h>
#include <sys/fs/zfs.h>
#include <sys/fm/protocol.h>
#include <sys/fm/fs/zfs.h>
#include <libzfs.h>

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

	if (cbp->cb_guid == zpool_get_guid(zhp)) {
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

	return (NULL);
}

/*ARGSUSED*/
static void
zfs_retire_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class)
{
	uint64_t pool_guid, vdev_guid;
	char *dev_name;
	zpool_handle_t *zhp;
	nvlist_t *resource, *config, *nvroot;
	nvlist_t *vdev;
	nvlist_t **spares, **faults;
	uint_t s, nspares, f, nfaults;
	nvlist_t *replacement;
	find_cbdata_t cb;
	libzfs_handle_t *zhdl = fmd_hdl_getspecific(hdl);

	/*
	 * Get information from the fault.
	 */
	if (nvlist_lookup_nvlist_array(nvl, FM_SUSPECT_FAULT_LIST,
	    &faults, &nfaults) != 0)
		return;

	for (f = 0; f < nfaults; f++) {
		if (nvlist_lookup_nvlist(faults[f], FM_FAULT_RESOURCE,
		    &resource) != 0 ||
		    nvlist_lookup_uint64(resource, FM_FMRI_ZFS_POOL,
		    &pool_guid) != 0 ||
		    nvlist_lookup_uint64(resource, FM_FMRI_ZFS_VDEV,
		    &vdev_guid) != 0)
			continue;

		/*
		 * From the pool guid and vdev guid, get the pool name and
		 * device name.
		 */
		cb.cb_guid = pool_guid;
		if (zpool_iter(zhdl, find_pool, &cb) != 1)
			continue;

		zhp = cb.cb_zhp;
		config = zpool_get_config(zhp, NULL);
		if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &nvroot) != 0) {
			zpool_close(zhp);
			continue;
		}

		if ((vdev = find_vdev(nvroot, vdev_guid)) == NULL) {
			zpool_close(zhp);
			continue;
		}

		/*
		 * Find out if there are any hot spares available in the pool.
		 */
		if (nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_SPARES,
		    &spares, &nspares) != 0) {
			zpool_close(zhp);
			continue;
		}

		if (nvlist_alloc(&replacement, NV_UNIQUE_NAME, 0) != 0) {
			zpool_close(zhp);
			continue;
		}

		if (nvlist_add_string(replacement, ZPOOL_CONFIG_TYPE,
		    VDEV_TYPE_ROOT) != 0) {
			nvlist_free(replacement);
			zpool_close(zhp);
			continue;
		}

		dev_name = zpool_vdev_name(zhdl, zhp, vdev);

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
		zpool_close(zhp);
	}
}

static const fmd_hdl_ops_t fmd_ops = {
	zfs_retire_recv,	/* fmdo_recv */
	NULL,			/* fmdo_timeout */
	NULL,			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
};

static const fmd_prop_t fmd_props[] = {
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
