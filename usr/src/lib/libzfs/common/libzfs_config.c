/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The pool configuration repository is stored in /etc/zfs/zpool.cache as a
 * single packed nvlist.  While it would be nice to just read in this
 * file from userland, this wouldn't work from a local zone.  So we have to have
 * a zpool ioctl to return the complete configuration for all pools.  In the
 * global zone, this will be identical to reading the file and unpacking it in
 * userland.
 */

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <libuutil.h>

#include "libzfs_impl.h"

static uu_avl_t *namespace_avl;
static uint64_t namespace_generation;

typedef struct config_node {
	char		*cn_name;
	nvlist_t	*cn_config;
	uu_avl_node_t	cn_avl;
} config_node_t;

/* ARGSUSED */
static int
config_node_compare(const void *a, const void *b, void *unused)
{
	int ret;

	const config_node_t *ca = (config_node_t *)a;
	const config_node_t *cb = (config_node_t *)b;

	ret = strcmp(ca->cn_name, cb->cn_name);

	if (ret < 0)
		return (-1);
	else if (ret > 0)
		return (1);
	else
		return (0);
}

/*
 * Loads the pool namespace, or re-loads it if the cache has changed.
 */
static void
namespace_reload()
{
	nvlist_t *config;
	config_node_t *cn;
	nvpair_t *elem;
	zfs_cmd_t zc = { 0 };
	uu_avl_walk_t *walk;

	if (namespace_generation == 0) {
		/*
		 * This is the first time we've accessed the configuration
		 * cache.  Initialize the AVL tree and then fall through to the
		 * common code.
		 */
		uu_avl_pool_t *pool;

		if ((pool = uu_avl_pool_create("config_pool",
		    sizeof (config_node_t),
		    offsetof(config_node_t, cn_avl),
		    config_node_compare, UU_DEFAULT)) == NULL)
			no_memory();

		if ((namespace_avl = uu_avl_create(pool, NULL,
		    UU_DEFAULT)) == NULL)
			no_memory();
	}

	/*
	 * Issue the ZFS_IOC_POOL_CONFIGS ioctl.
	 * This can fail for one of two reasons:
	 *
	 * 	EEXIST		The generation counts match, nothing to do.
	 * 	ENOMEM		The zc_config_dst buffer isn't large enough to
	 * 			hold the config; zc_config_dst_size will have
	 *			been modified to tell us how much to allocate.
	 */
	zc.zc_config_dst_size = 1024;
	zc.zc_config_dst = (uint64_t)(uintptr_t)
	    zfs_malloc(zc.zc_config_dst_size);
	for (;;) {
		zc.zc_cookie = namespace_generation;
		if (ioctl(zfs_fd, ZFS_IOC_POOL_CONFIGS, &zc) != 0) {
			switch (errno) {
			case EEXIST:
				/*
				 * The namespace hasn't changed.
				 */
				free((void *)(uintptr_t)zc.zc_config_dst);
				return;

			case ENOMEM:
				free((void *)(uintptr_t)zc.zc_config_dst);
				zc.zc_config_dst = (uint64_t)(uintptr_t)
				    zfs_malloc(zc.zc_config_dst_size);
				break;

			default:
				zfs_baderror(errno);
			}
		} else {
			namespace_generation = zc.zc_cookie;
			break;
		}
	}

	verify(nvlist_unpack((void *)(uintptr_t)zc.zc_config_dst,
	    zc.zc_config_dst_size, &config, 0) == 0);

	free((void *)(uintptr_t)zc.zc_config_dst);

	/*
	 * Clear out any existing configuration information.
	 */
	if ((walk = uu_avl_walk_start(namespace_avl, UU_WALK_ROBUST)) == NULL)
		no_memory();

	while ((cn = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_remove(namespace_avl, cn);
		nvlist_free(cn->cn_config);
		free(cn->cn_name);
		free(cn);
	}

	elem = NULL;
	while ((elem = nvlist_next_nvpair(config, elem)) != NULL) {
		nvlist_t *child;
		uu_avl_index_t where;

		cn = zfs_malloc(sizeof (config_node_t));
		cn->cn_name = zfs_strdup(nvpair_name(elem));

		verify(nvpair_value_nvlist(elem, &child) == 0);
		verify(nvlist_dup(child, &cn->cn_config, 0) == 0);
		verify(uu_avl_find(namespace_avl, cn, NULL, &where) == NULL);

		uu_avl_insert(namespace_avl, cn, where);
	}

	nvlist_free(config);
}

/*
 * Retrive the configuration for the given pool.  The configuration is a nvlist
 * describing the vdevs, as well as the statistics associated with each one.
 */
nvlist_t *
zpool_get_config(zpool_handle_t *zhp, nvlist_t **oldconfig)
{
	if (oldconfig)
		*oldconfig = zhp->zpool_old_config;
	return (zhp->zpool_config);
}

/*
 * Refresh the vdev statistics associated with the given pool.  This is used in
 * iostat to show configuration changes and determine the delta from the last
 * time the function was called.  This function can fail, in case the pool has
 * been destroyed.
 */
int
zpool_refresh_stats(zpool_handle_t *zhp)
{
	zfs_cmd_t zc = { 0 };
	int error;
	nvlist_t *config;

	(void) strcpy(zc.zc_name, zhp->zpool_name);

	if (zhp->zpool_config_size == 0)
		zhp->zpool_config_size = 1 << 16;

	zc.zc_config_dst_size = zhp->zpool_config_size;
	zc.zc_config_dst = (uint64_t)(uintptr_t)
	    zfs_malloc(zc.zc_config_dst_size);

	while ((error = ioctl(zfs_fd, ZFS_IOC_POOL_STATS, &zc)) != 0) {
		error = errno;

		if (error == ENXIO) {
			/*
			 * We can't open one or more top-level vdevs,
			 * but we have the config.
			 */
			break;
		}

		free((void *)(uintptr_t)zc.zc_config_dst);

		if (error == ENOENT || error == EINVAL) {
			/*
			 * There's no such pool (ENOENT)
			 * or the config is bogus (EINVAL).
			 */
			return (error);
		}

		if (error != ENOMEM)
			zfs_baderror(error);

		zc.zc_config_dst =
		    (uint64_t)(uintptr_t)zfs_malloc(zc.zc_config_dst_size);
	}

	verify(nvlist_unpack((void *)(uintptr_t)zc.zc_config_dst,
	    zc.zc_config_dst_size, &config, 0) == 0);

	zhp->zpool_config_size = zc.zc_config_dst_size;
	free((void *)(uintptr_t)zc.zc_config_dst);

	set_pool_health(config);

	if (zhp->zpool_config != NULL) {
		uint64_t oldtxg, newtxg;

		verify(nvlist_lookup_uint64(zhp->zpool_config,
		    ZPOOL_CONFIG_POOL_TXG, &oldtxg) == 0);
		verify(nvlist_lookup_uint64(config,
		    ZPOOL_CONFIG_POOL_TXG, &newtxg) == 0);

		if (zhp->zpool_old_config != NULL)
			nvlist_free(zhp->zpool_old_config);

		if (oldtxg != newtxg) {
			nvlist_free(zhp->zpool_config);
			zhp->zpool_old_config = NULL;
		} else {
			zhp->zpool_old_config = zhp->zpool_config;
		}
	}

	zhp->zpool_config = config;

	return (error);
}

/*
 * Iterate over all pools in the system.
 */
int
zpool_iter(zpool_iter_f func, void *data)
{
	config_node_t *cn;
	zpool_handle_t *zhp;
	int ret;

	namespace_reload();

	for (cn = uu_avl_first(namespace_avl); cn != NULL;
	    cn = uu_avl_next(namespace_avl, cn)) {

		if ((zhp = zpool_open_silent(cn->cn_name)) == NULL)
			continue;

		if ((ret = func(zhp, data)) != 0)
			return (ret);
	}

	return (0);
}

/*
 * Iterate over root datasets, calling the given function for each.  The zfs
 * handle passed each time must be explicitly closed by the callback.
 */
int
zfs_iter_root(zfs_iter_f func, void *data)
{
	config_node_t *cn;
	zfs_handle_t *zhp;
	int ret;

	namespace_reload();

	for (cn = uu_avl_first(namespace_avl); cn != NULL;
	    cn = uu_avl_next(namespace_avl, cn)) {

		if ((zhp = make_dataset_handle(cn->cn_name)) == NULL)
			continue;

		if ((ret = func(zhp, data)) != 0)
			return (ret);
	}

	return (0);
}
