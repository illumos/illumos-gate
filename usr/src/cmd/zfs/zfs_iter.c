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

#include <libintl.h>
#include <libuutil.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <libzfs.h>

#include "zfs_util.h"

/*
 * This is a private interface used to gather up all the datasets specified on
 * the command line so that we can iterate over them in order.
 *
 * First, we iterate over all filesystems, gathering them together into an
 * AVL tree sorted by name.  For snapshots, we order them according to
 * creation time.  We report errors for any explicitly specified datasets
 * that we couldn't open.
 *
 * When finished, we have an AVL tree of ZFS handles.  We go through and execute
 * the provided callback for each one, passing whatever data the user supplied.
 */

typedef struct zfs_node {
	zfs_handle_t	*zn_handle;
	uu_avl_node_t	zn_avlnode;
} zfs_node_t;

typedef struct callback_data {
	uu_avl_t	*cb_avl;
	int		cb_recurse;
	zfs_type_t	cb_types;
} callback_data_t;

uu_avl_pool_t *avl_pool;

/*
 * Called for each dataset.  If the object the object is of an appropriate type,
 * add it to the avl tree and recurse over any children as necessary.
 */
int
zfs_callback(zfs_handle_t *zhp, void *data)
{
	callback_data_t *cb = data;
	int dontclose = 0;

	/*
	 * If this object is of the appropriate type, add it to the AVL tree.
	 */
	if (zfs_get_type(zhp) & cb->cb_types) {
		uu_avl_index_t idx;
		zfs_node_t *node = safe_malloc(sizeof (zfs_node_t));

		node->zn_handle = zhp;
		uu_avl_node_init(node, &node->zn_avlnode, avl_pool);
		if (uu_avl_find(cb->cb_avl, node, NULL, &idx) == NULL) {
			uu_avl_insert(cb->cb_avl, node, idx);
			dontclose = 1;
		} else {
			free(node);
		}
	}

	/*
	 * If 'recurse' is set, and the datasets can have datasets of the
	 * appropriate type, then recurse over its children.
	 */
	if (cb->cb_recurse && (zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM ||
	    (cb->cb_types & ZFS_TYPE_SNAPSHOT)))
		(void) zfs_iter_children(zhp, zfs_callback, data);

	if (!dontclose)
		zfs_close(zhp);

	return (0);
}

/* ARGSUSED */
static int
zfs_compare(const void *larg, const void *rarg, void *unused)
{
	zfs_handle_t *l = ((zfs_node_t *)larg)->zn_handle;
	zfs_handle_t *r = ((zfs_node_t *)rarg)->zn_handle;
	const char *lname = zfs_get_name(l);
	const char *rname = zfs_get_name(r);
	char *lat, *rat;
	uint64_t lcreate, rcreate;
	int ret;

	lat = (char *)strchr(lname, '@');
	rat = (char *)strchr(rname, '@');

	if (lat != NULL)
		*lat = '\0';
	if (rat != NULL)
		*rat = '\0';

	ret = strcmp(lname, rname);
	if (ret == 0) {
		/*
		 * If we're comparing a dataset to one of its snapshots, we
		 * always make the full dataset first.
		 */
		if (lat == NULL) {
			ret = -1;
		} else if (rat == NULL) {
			ret = 1;
		} else {
			/*
			 * If we have two snapshots from the same dataset, then
			 * we want to sort them according to creation time.  We
			 * use the hidden CREATETXG property to get an absolute
			 * ordering of snapshots.
			 */
			lcreate = zfs_prop_get_int(l, ZFS_PROP_CREATETXG);
			rcreate = zfs_prop_get_int(r, ZFS_PROP_CREATETXG);

			if (lcreate < rcreate)
				ret = -1;
			else if (lcreate > rcreate)
				ret = 1;
		}
	}

	if (lat != NULL)
		*lat = '@';
	if (rat != NULL)
		*rat = '@';

	return (ret);
}

int
zfs_for_each(int argc, char **argv, int recurse, zfs_type_t types,
    zfs_iter_f callback, void *data)
{
	callback_data_t cb;
	int ret = 0;
	zfs_node_t *node;
	uu_avl_walk_t *walk;

	avl_pool = uu_avl_pool_create("zfs_pool", sizeof (zfs_node_t),
	    offsetof(zfs_node_t, zn_avlnode), zfs_compare, UU_DEFAULT);

	if (avl_pool == NULL) {
		(void) fprintf(stderr,
		    gettext("internal error: out of memory\n"));
		exit(1);
	}

	cb.cb_recurse = recurse;
	cb.cb_types = types;
	if ((cb.cb_avl = uu_avl_create(avl_pool, NULL, UU_DEFAULT)) == NULL) {
		(void) fprintf(stderr,
		    gettext("internal error: out of memory\n"));
		exit(1);
	}

	if (argc == 0) {
		/*
		 * If given no arguments, iterate over all datasets.
		 */
		cb.cb_recurse = 1;
		ret = zfs_iter_root(zfs_callback, &cb);
	} else {
		int i;
		zfs_handle_t *zhp;
		zfs_type_t argtype;

		/*
		 * If we're recursive, then we always allow filesystems as
		 * arguments.  If we also are interested in snapshots, then we
		 * can take volumes as well.
		 */
		argtype = types;
		if (recurse) {
			argtype |= ZFS_TYPE_FILESYSTEM;
			if (types & ZFS_TYPE_SNAPSHOT)
				argtype |= ZFS_TYPE_VOLUME;
		}

		for (i = 0; i < argc; i++) {
			if ((zhp = zfs_open(argv[i], argtype)) != NULL)
				ret = zfs_callback(zhp, &cb);
			else
				ret = 1;
		}
	}

	/*
	 * At this point we've got our AVL tree full of zfs handles, so iterate
	 * over each one and execute the real user callback.
	 */
	for (node = uu_avl_first(cb.cb_avl); node != NULL;
	    node = uu_avl_next(cb.cb_avl, node))
		ret |= callback(node->zn_handle, data);

	/*
	 * Finally, clean up the AVL tree.
	 */
	if ((walk = uu_avl_walk_start(cb.cb_avl, UU_WALK_ROBUST)) == NULL) {
		(void) fprintf(stderr,
		    gettext("internal error: out of memory"));
		exit(1);
	}

	while ((node = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_remove(cb.cb_avl, node);
		zfs_close(node->zn_handle);
		free(node);
	}

	uu_avl_walk_end(walk);
	uu_avl_destroy(cb.cb_avl);
	uu_avl_pool_destroy(avl_pool);

	return (ret);
}
