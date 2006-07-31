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
 * For export and destroy, we have to support iterating over all datasets and
 * unmounting and/or destroying them.
 *
 * For import, we need to iterate over all datasets, mounting and sharing
 * them as indicated by the mountpoint and sharenfs properties.
 *
 * This file contains the routines to support this.
 */

#include <libintl.h>
#include <libzfs.h>
#include <sys/mount.h>

#include "zpool_util.h"

typedef struct cbdata {
	int	cb_force;
	int	cb_failed;
	const char *cb_mntopts;
} cbdata_t;

/*
 * Unmount a single ZFS dataset.
 */
int
do_unmount(zfs_handle_t *zfsp, void *data)
{
	cbdata_t *cbp = data;

	if (zfs_unmount(zfsp, NULL, cbp->cb_force ? MS_FORCE : 0) != 0)
		cbp->cb_failed = 1;

	zfs_close(zfsp);

	return (0);
}

/*
 * Unmount all datasets within the given pool.
 *
 * XXZFS it would be much more efficient, and correct, to iterate over
 * mountpoints based on /etc/mnttab.
 */
int
unmount_datasets(zpool_handle_t *zhp, int force)
{
	cbdata_t cb = { 0 };
	zfs_handle_t *zfsp;

	/* For unavailable pools, we don't do anything */
	if (zpool_get_state(zhp) == POOL_STATE_UNAVAIL)
		return (0);

	if ((zfsp = zfs_open(g_zfs, zpool_get_name(zhp),
	    ZFS_TYPE_FILESYSTEM)) == NULL)
		return (-1);

	cb.cb_force = force;

	if (zfs_iter_dependents(zfsp, do_unmount, &cb) != 0 ||
	    cb.cb_failed != 0) {
		zfs_close(zfsp);
		return (-1);
	}

	if (do_unmount(zfsp, &cb) != 0 || cb.cb_failed != 0)
		return (-1);

	return (0);
}

/*
 * Mount and share a single dataset
 */
static int
do_mount_share(zfs_handle_t *zfsp, void *data)
{
	cbdata_t *cbp = data;
	int ret;

	if (zfs_get_type(zfsp) != ZFS_TYPE_FILESYSTEM) {
		zfs_close(zfsp);
		return (0);
	}

	if (zfs_mount(zfsp, cbp->cb_mntopts, 0) != 0)
		cbp->cb_failed = 1;
	else if (zfs_share(zfsp) != 0)
		cbp->cb_failed = 1;

	ret = zfs_iter_children(zfsp, do_mount_share, data);

	zfs_close(zfsp);
	return (ret);
}

/*
 * Go through and mount all datasets within a pool.  We need to mount all
 * datasets in order, so that we mount parents before any children.  A complete
 * fix would gather all mountpoints, sort them, and mount them in lexical order.
 * There are many more problems if you start to have nested filesystems - we
 * just want to get inherited filesystems right.
 *
 * Perform share as needed when mounting a dataset is successful.
 */
int
mount_share_datasets(zpool_handle_t *zhp, const char *options)
{
	cbdata_t cb = { 0 };
	zfs_handle_t *zfsp;

	cb.cb_mntopts = options;

	/* For unavailable pools, we don't do anything */
	if (zpool_get_state(zhp) == POOL_STATE_UNAVAIL)
		return (0);

	if ((zfsp = zfs_open(g_zfs, zpool_get_name(zhp),
	    ZFS_TYPE_FILESYSTEM)) == NULL)
		return (-1);

	if (do_mount_share(zfsp, &cb) != 0 || cb.cb_failed != 0)
		return (-1);

	return (0);
}
