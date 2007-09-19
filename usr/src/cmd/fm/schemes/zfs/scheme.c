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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_fmri.h>
#include <strings.h>
#include <libzfs.h>

typedef struct cbdata {
	uint64_t	cb_guid;
	zpool_handle_t	*cb_pool;
} cbdata_t;

libzfs_handle_t *g_zfs;

static int
find_pool(zpool_handle_t *zhp, void *data)
{
	cbdata_t *cbp = data;

	if (zpool_get_prop_int(zhp, ZPOOL_PROP_GUID, NULL) == cbp->cb_guid) {
		cbp->cb_pool = zhp;
		return (1);
	}

	zpool_close(zhp);

	return (0);
}

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	uint64_t pool_guid, vdev_guid;
	cbdata_t cb;
	ssize_t len;
	const char *name;
	char guidbuf[64];

	(void) nvlist_lookup_uint64(nvl, FM_FMRI_ZFS_POOL, &pool_guid);

	/*
	 * Attempt to convert the pool guid to a name.
	 */
	cb.cb_guid = pool_guid;
	cb.cb_pool = NULL;

	if (zpool_iter(g_zfs, find_pool, &cb) == 1) {
		name = zpool_get_name(cb.cb_pool);
	} else {
		(void) snprintf(guidbuf, sizeof (guidbuf), "%llx", pool_guid);
		name = guidbuf;
	}

	if (nvlist_lookup_uint64(nvl, FM_FMRI_ZFS_VDEV, &vdev_guid) == 0)
		len = snprintf(buf, buflen, "%s://pool=%s/vdev=%llx",
		    FM_FMRI_SCHEME_ZFS, name, vdev_guid);
	else
		len = snprintf(buf, buflen, "%s://pool=%s",
		    FM_FMRI_SCHEME_ZFS, name);

	if (cb.cb_pool)
		zpool_close(cb.cb_pool);

	return (len);
}

static nvlist_t *
find_vdev_iter(nvlist_t *nv, uint64_t search)
{
	uint_t c, children;
	nvlist_t **child;
	uint64_t guid;
	nvlist_t *ret;

	(void) nvlist_lookup_uint64(nv, ZPOOL_CONFIG_GUID, &guid);

	if (search == guid)
		return (nv);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		return (0);

	for (c = 0; c < children; c++)
		if ((ret = find_vdev_iter(child[c], search)) != 0)
			return (ret);

	return (NULL);
}

static nvlist_t *
find_vdev(zpool_handle_t *zhp, uint64_t guid)
{
	nvlist_t *config;
	nvlist_t *nvroot;

	config = zpool_get_config(zhp, NULL);

	(void) nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &nvroot);

	return (find_vdev_iter(nvroot, guid));
}

int
fmd_fmri_present(nvlist_t *nvl)
{
	uint64_t pool_guid, vdev_guid;
	cbdata_t cb;
	int ret;

	(void) nvlist_lookup_uint64(nvl, FM_FMRI_ZFS_POOL, &pool_guid);

	cb.cb_guid = pool_guid;
	cb.cb_pool = NULL;

	if (zpool_iter(g_zfs, find_pool, &cb) != 1)
		return (0);

	if (nvlist_lookup_uint64(nvl, FM_FMRI_ZFS_VDEV, &vdev_guid) != 0) {
		zpool_close(cb.cb_pool);
		return (1);
	}

	ret = (find_vdev(cb.cb_pool, vdev_guid) != NULL);

	zpool_close(cb.cb_pool);

	return (ret);
}

int
fmd_fmri_unusable(nvlist_t *nvl)
{
	uint64_t pool_guid, vdev_guid;
	cbdata_t cb;
	nvlist_t *vd;
	int ret;

	(void) nvlist_lookup_uint64(nvl, FM_FMRI_ZFS_POOL, &pool_guid);

	cb.cb_guid = pool_guid;
	cb.cb_pool = NULL;

	if (zpool_iter(g_zfs, find_pool, &cb) != 1)
		return (1);

	if (nvlist_lookup_uint64(nvl, FM_FMRI_ZFS_VDEV, &vdev_guid) != 0) {
		ret = (zpool_get_state(cb.cb_pool) == POOL_STATE_UNAVAIL);
		zpool_close(cb.cb_pool);
		return (ret);
	}

	vd = find_vdev(cb.cb_pool, vdev_guid);
	if (vd == NULL) {
		ret = 1;
	} else {
		vdev_stat_t *vs;
		uint_t c;

		(void) nvlist_lookup_uint64_array(vd, ZPOOL_CONFIG_STATS,
		    (uint64_t **)&vs, &c);

		ret = (vs->vs_state < VDEV_STATE_DEGRADED);
	}

	zpool_close(cb.cb_pool);

	return (ret);
}

int
fmd_fmri_init(void)
{
	g_zfs = libzfs_init();

	if (g_zfs == NULL)
		return (-1);
	else
		return (0);
}

void
fmd_fmri_fini(void)
{
	if (g_zfs)
		libzfs_fini(g_zfs);
}
