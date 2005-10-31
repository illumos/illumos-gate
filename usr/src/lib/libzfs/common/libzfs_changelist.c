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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zone.h>

#include <libzfs.h>

#include "libzfs_impl.h"

/*
 * Structure to keep track of dataset state.  Before changing the 'sharenfs' or
 * 'mountpoint' property, we record whether the filesystem was previously
 * mounted/shared.  This prior state dictates whether we remount/reshare the
 * dataset after the property has been changed.
 *
 * The interface consists of the following sequence of functions:
 *
 * 	changelist_gather()
 * 	changelist_prefix()
 * 	< change property >
 * 	changelist_postfix()
 * 	changelist_free()
 *
 * Other interfaces:
 *
 * changelist_rename() - renames all datasets appropriately when doing a rename
 * changelist_unshare() - unshares all the nodes in a given changelist
 * changelist_haszonedchild() - check if there is any child exported to
 *				a local zone
 */
typedef struct prop_changenode {
	zfs_handle_t		*cn_handle;
	int			cn_shared;
	int			cn_mounted;
	int			cn_zoned;
	uu_list_node_t		cn_listnode;
} prop_changenode_t;

struct prop_changelist {
	zfs_prop_t		cl_prop;
	zfs_prop_t		cl_realprop;
	uu_list_pool_t		*cl_pool;
	uu_list_t		*cl_list;
	int			cl_waslegacy;
	int			cl_allchildren;
	int			cl_flags;
	int			cl_haszonedchild;
};

/*
 * If the property is 'mountpoint', go through and unmount filesystems as
 * necessary.  We don't do the same for 'sharenfs', because we can just re-share
 * with different options without interrupting service.
 */
int
changelist_prefix(prop_changelist_t *clp)
{
	prop_changenode_t *cn;
	int ret = 0;

	if (clp->cl_prop != ZFS_PROP_MOUNTPOINT)
		return (0);

	for (cn = uu_list_first(clp->cl_list); cn != NULL;
	    cn = uu_list_next(clp->cl_list, cn)) {
		/*
		 * if we are in a global zone, but this dataset is exported to
		 * a local zone, do nothing.
		 */
		if ((getzoneid() == GLOBAL_ZONEID) && cn->cn_zoned)
			continue;

		/*
		 * If we have a volume and this was a rename, remove the
		 * /dev/zvol links
		 */
		if (cn->cn_handle->zfs_volblocksize &&
		    clp->cl_realprop == ZFS_PROP_NAME) {
			if (zvol_remove_link(cn->cn_handle->zfs_name) != 0)
				ret = -1;
		} else if (zfs_unmount(cn->cn_handle, NULL, clp->cl_flags) != 0)
			ret = -1;
	}

	return (ret);
}

/*
 * If the proeprty is 'mountpoint' or 'sharenfs', go through and remount and/or
 * reshare the filesystems as necessary.  In changelist_gather() we recorded
 * whether the filesystem was previously shared or mounted.  The action we take
 * depends on the previous state, and whether the value was previously 'legacy'.
 * For non-legacy properties, we only remount/reshare the filesystem if it was
 * previously mounted/shared.  Otherwise, we always remount/reshare the
 * filesystem.
 */
int
changelist_postfix(prop_changelist_t *clp)
{
	prop_changenode_t *cn;
	int ret = 0;

	/*
	 * If we're changing the mountpoint, attempt to destroy the underlying
	 * mountpoint.  All other datasets will have inherited from this dataset
	 * (in which case their mountpoints exist in the filesystem in the new
	 * location), or have explicit mountpoints set (in which case they won't
	 * be in the changelist).
	 */
	if ((cn = uu_list_last(clp->cl_list)) == NULL)
		return (0);

	if (clp->cl_prop == ZFS_PROP_MOUNTPOINT)
		remove_mountpoint(cn->cn_handle);

	/*
	 * We walk the datasets in reverse, because we want to mount any parent
	 * datasets before mounting the children.
	 */
	for (cn = uu_list_last(clp->cl_list); cn != NULL;
	    cn = uu_list_prev(clp->cl_list, cn)) {
		/*
		 * if we are in a global zone, but this dataset is exported to
		 * a local zone, do nothing.
		 */
		if ((getzoneid() == GLOBAL_ZONEID) && cn->cn_zoned)
			continue;

		zfs_refresh_properties(cn->cn_handle);

		/*
		 * If this is a volume and we're doing a rename, recreate the
		 * /dev/zvol links.
		 */
		if (cn->cn_handle->zfs_volblocksize &&
		    clp->cl_realprop == ZFS_PROP_NAME) {
			if (zvol_create_link(cn->cn_handle->zfs_name) != 0)
				ret = -1;
			continue;
		}

		if ((clp->cl_waslegacy || cn->cn_mounted) &&
		    !zfs_is_mounted(cn->cn_handle, NULL) &&
		    zfs_mount(cn->cn_handle, NULL, 0) != 0)
			ret = -1;

		/*
		 * We always re-share even if the filesystem is currently
		 * shared, so that we can adopt any new options.
		 */
		if ((cn->cn_shared ||
		    (clp->cl_prop == ZFS_PROP_SHARENFS && clp->cl_waslegacy))) {
			char shareopts[ZFS_MAXPROPLEN];
			if (zfs_prop_get(cn->cn_handle, ZFS_PROP_SHARENFS,
			    shareopts, sizeof (shareopts), NULL, NULL, 0,
			    FALSE) == 0 && strcmp(shareopts, "off") == 0)
				ret = zfs_unshare(cn->cn_handle, NULL);
			else
				ret = zfs_share(cn->cn_handle);
		}
	}

	return (ret);
}

/*
 * If we rename a filesystem, and child filesystem handles are no longer valid,
 * since we identify datasets by their name in the ZFS namespace.  So, we have
 * to go through and fix up all the names appropriately.  We could do this
 * automatically if libzfs kept track of all open handles, but this is a lot
 * less work.
 */
void
changelist_rename(prop_changelist_t *clp, const char *src, const char *dst)
{
	prop_changenode_t *cn;
	char newname[ZFS_MAXNAMELEN];

	for (cn = uu_list_first(clp->cl_list); cn != NULL;
	    cn = uu_list_next(clp->cl_list, cn)) {
		/*
		 * Destroy the previous mountpoint if needed.
		 */
		remove_mountpoint(cn->cn_handle);

		(void) strlcpy(newname, dst, sizeof (newname));
		(void) strcat(newname, cn->cn_handle->zfs_name + strlen(src));

		(void) strlcpy(cn->cn_handle->zfs_name, newname,
		    sizeof (cn->cn_handle->zfs_name));
	}
}

/*
 * Given a gathered changelist for the "sharenfs" property,
 * unshare all the nodes in the list.
 */
int
changelist_unshare(prop_changelist_t *clp)
{
	prop_changenode_t *cn;
	int ret = 0;

	if (clp->cl_prop != ZFS_PROP_SHARENFS)
		return (0);

	for (cn = uu_list_first(clp->cl_list); cn != NULL;
	    cn = uu_list_next(clp->cl_list, cn)) {

		if (zfs_unshare(cn->cn_handle, NULL) != 0)
			ret = -1;
	}

	return (ret);
}

/*
 * Check if there is any child exported to a local zone in a
 * given changelist. This information has already been recorded
 * while gathering the changelist via changelist_gather().
 */
int
changelist_haszonedchild(prop_changelist_t *clp)
{
	return (clp->cl_haszonedchild);
}

/*
 * Release any memory associated with a changelist.
 */
void
changelist_free(prop_changelist_t *clp)
{
	prop_changenode_t *cn;
	uu_list_walk_t *walk;

	verify((walk = uu_list_walk_start(clp->cl_list,
	    UU_WALK_ROBUST)) != NULL);

	while ((cn = uu_list_walk_next(walk)) != NULL) {

		uu_list_remove(clp->cl_list, cn);

		zfs_close(cn->cn_handle);
		free(cn);
	}

	uu_list_pool_destroy(clp->cl_pool);

	free(clp);
}

static int
change_one(zfs_handle_t *zhp, void *data)
{
	prop_changelist_t *clp = data;
	char property[ZFS_MAXPROPLEN];
	char where[64];
	prop_changenode_t *cn;
	zfs_source_t sourcetype;

	/*
	 * We only want to unmount/unshare those filesystems which may
	 * inherit from the target filesystem.  If we find any filesystem
	 * with a locally set mountpoint, we ignore any children since changing
	 * the property will not affect them.  If this is a rename, we iterate
	 * over all children regardless, since we need them unmounted in order
	 * to do the rename.  Also, if this is a volume and we're doing a
	 * rename, then always add it to the changelist.
	 */

	if (!(zhp->zfs_volblocksize && clp->cl_realprop == ZFS_PROP_NAME) &&
	    zfs_prop_get(zhp, clp->cl_prop, property,
	    sizeof (property), &sourcetype, where, sizeof (where),
	    FALSE) != 0)
		return (0);

	if (clp->cl_allchildren || sourcetype == ZFS_SRC_DEFAULT ||
	    sourcetype == ZFS_SRC_INHERITED) {
		cn = zfs_malloc(sizeof (prop_changenode_t));

		cn->cn_handle = zhp;
		cn->cn_mounted = zfs_is_mounted(zhp, NULL);
		cn->cn_shared = zfs_is_shared(zhp, NULL);
		cn->cn_zoned = zfs_prop_get_int(zhp, ZFS_PROP_ZONED);

		/* indicate if any child is exported to a local zone */
		if ((getzoneid() == GLOBAL_ZONEID) && cn->cn_zoned)
			clp->cl_haszonedchild = TRUE;

		uu_list_node_init(cn, &cn->cn_listnode, clp->cl_pool);
		verify(uu_list_insert_before(clp->cl_list,
		    uu_list_first(clp->cl_list), cn) == 0);

		return (zfs_iter_children(zhp, change_one, data));
	} else {
		zfs_close(zhp);
	}

	return (0);
}


/*
 * Given a ZFS handle and a property, construct a complete list of datasets that
 * need to be modified as part of this process.  For anything but the
 * 'mountpoint' and 'sharenfs' properties, this just returns an empty list.
 * Otherwise, we iterate over all children and look for any datasets which
 * inherit this property.  For each such dataset, we add it to the list and mark
 * whether it was shared beforehand.
 */
prop_changelist_t *
changelist_gather(zfs_handle_t *zhp, zfs_prop_t prop, int flags)
{
	prop_changelist_t *clp = zfs_malloc(sizeof (prop_changelist_t));
	prop_changenode_t *cn;
	zfs_handle_t *temp;
	char property[ZFS_MAXPROPLEN];

	clp->cl_pool = uu_list_pool_create("changelist_pool",
	    sizeof (prop_changenode_t),
	    offsetof(prop_changenode_t, cn_listnode),
	    NULL, 0);
	assert(clp->cl_pool != NULL);

	clp->cl_list = uu_list_create(clp->cl_pool, NULL, 0);
	clp->cl_flags = flags;

	/*
	 * If this is a rename or the 'zoned' property, we pretend we're
	 * changing the mountpoint and flag it so we can catch all children in
	 * change_one().
	 */
	if (prop == ZFS_PROP_NAME || prop == ZFS_PROP_ZONED) {
		clp->cl_prop = ZFS_PROP_MOUNTPOINT;
		clp->cl_allchildren = TRUE;
	} else {
		clp->cl_prop = prop;
	}
	clp->cl_realprop = prop;

	if (clp->cl_prop != ZFS_PROP_MOUNTPOINT &&
	    clp->cl_prop != ZFS_PROP_SHARENFS)
		return (clp);

	if (zfs_iter_children(zhp, change_one, clp) != 0) {
		changelist_free(clp);
		return (NULL);
	}

	/*
	 * We have to re-open ourselves because we auto-close all the handles
	 * and can't tell the difference.
	 */
	if ((temp = zfs_open(zfs_get_name(zhp), ZFS_TYPE_ANY)) == NULL) {
		free(clp);
		return (NULL);
	}

	/*
	 * Always add ourself to the list.  We add ourselves to the end so that
	 * we're the last to be unmounted.
	 */
	cn = zfs_malloc(sizeof (prop_changenode_t));
	cn->cn_handle = temp;
	cn->cn_mounted = zfs_is_mounted(temp, NULL);
	cn->cn_shared = zfs_is_shared(temp, NULL);
	cn->cn_zoned = zfs_prop_get_int(zhp, ZFS_PROP_ZONED);

	uu_list_node_init(cn, &cn->cn_listnode, clp->cl_pool);
	verify(uu_list_insert_after(clp->cl_list,
	    uu_list_last(clp->cl_list), cn) == 0);

	/*
	 * If the property was previously 'legacy' or 'none', record this fact,
	 * as the behavior of changelist_postfix() will be different.
	 */
	if (zfs_prop_get(zhp, prop, property, sizeof (property),
	    NULL, NULL, 0, FALSE) == 0 &&
	    (strcmp(property, "legacy") == 0 || strcmp(property, "none") == 0 ||
	    strcmp(property, "off") == 0))
		clp->cl_waslegacy = TRUE;

	return (clp);
}
