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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2015 EveryCity Ltd.
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

/*
 * System includes
 */
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <libintl.h>
#include <libnvpair.h>
#include <libzfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfstab.h>
#include <sys/zone.h>
#include <sys/mkdev.h>
#include <unistd.h>

#include <libbe.h>
#include <libbe_priv.h>

#define	BE_TMP_MNTPNT		"/tmp/.be.XXXXXX"

typedef struct dir_data {
	char *dir;
	char *ds;
} dir_data_t;

/* Private function prototypes */
static int be_mount_callback(zfs_handle_t *, void *);
static int be_unmount_callback(zfs_handle_t *, void *);
static int be_get_legacy_fs_callback(zfs_handle_t *, void *);
static int fix_mountpoint(zfs_handle_t *);
static int fix_mountpoint_callback(zfs_handle_t *, void *);
static int get_mountpoint_from_vfstab(char *, const char *, char *, size_t,
    boolean_t);
static int loopback_mount_shared_fs(zfs_handle_t *, be_mount_data_t *);
static int loopback_mount_zonepath(const char *, be_mount_data_t *);
static int iter_shared_fs_callback(zfs_handle_t *, void *);
static int zpool_shared_fs_callback(zpool_handle_t *, void *);
static int unmount_shared_fs(be_unmount_data_t *);
static int add_to_fs_list(be_fs_list_data_t *, const char *);
static int be_mount_root(zfs_handle_t *, char *);
static int be_unmount_root(zfs_handle_t *, be_unmount_data_t *);
static int be_mount_zones(zfs_handle_t *, be_mount_data_t *);
static int be_unmount_zones(be_unmount_data_t *);
static int be_mount_one_zone(zfs_handle_t *, be_mount_data_t *, char *, char *,
    char *);
static int be_unmount_one_zone(be_unmount_data_t *, char *, char *, char *);
static int be_get_ds_from_dir_callback(zfs_handle_t *, void *);
static int mount_zfs(zfs_handle_t *, char *);


/* ********************************************************************	*/
/*			Public Functions				*/
/* ********************************************************************	*/

/*
 * Function:	be_mount
 * Description:	Mounts a BE and its subordinate datasets at a given mountpoint.
 * Parameters:
 *		be_attrs - pointer to nvlist_t of attributes being passed in.
 *			The following attributes are used by this function:
 *
 *			BE_ATTR_ORIG_BE_NAME		*required
 *			BE_ATTR_MOUNTPOINT		*required
 *			BE_ATTR_MOUNT_FLAGS		*optional
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Public
 */
int
be_mount(nvlist_t *be_attrs)
{
	char		*be_name = NULL;
	char		*mountpoint = NULL;
	uint16_t	flags = 0;
	int		ret = BE_SUCCESS;

	/* Initialize libzfs handle */
	if (!be_zfs_init())
		return (BE_ERR_INIT);

	/* Get original BE name */
	if (nvlist_lookup_string(be_attrs, BE_ATTR_ORIG_BE_NAME, &be_name)
	    != 0) {
		be_print_err(gettext("be_mount: failed to lookup "
		    "BE_ATTR_ORIG_BE_NAME attribute\n"));
		return (BE_ERR_INVAL);
	}

	/* Validate original BE name */
	if (!be_valid_be_name(be_name)) {
		be_print_err(gettext("be_mount: invalid BE name %s\n"),
		    be_name);
		return (BE_ERR_INVAL);
	}

	/* Get mountpoint */
	if (nvlist_lookup_string(be_attrs, BE_ATTR_MOUNTPOINT, &mountpoint)
	    != 0) {
		be_print_err(gettext("be_mount: failed to lookup "
		    "BE_ATTR_MOUNTPOINT attribute\n"));
		return (BE_ERR_INVAL);
	}

	/* Get flags */
	if (nvlist_lookup_pairs(be_attrs, NV_FLAG_NOENTOK,
	    BE_ATTR_MOUNT_FLAGS, DATA_TYPE_UINT16, &flags, NULL) != 0) {
		be_print_err(gettext("be_mount: failed to lookup "
		    "BE_ATTR_MOUNT_FLAGS attribute\n"));
		return (BE_ERR_INVAL);
	}

	ret = _be_mount(be_name, &mountpoint, flags);

	be_zfs_fini();

	return (ret);
}

/*
 * Function:	be_unmount
 * Description:	Unmounts a BE and its subordinate datasets.
 * Parameters:
 *		be_attrs - pointer to nvlist_t of attributes being passed in.
 *			The following attributes are used by this function:
 *
 *			BE_ATTR_ORIG_BE_NAME		*required
 *			BE_ATTR_UNMOUNT_FLAGS		*optional
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Public
 */
int
be_unmount(nvlist_t *be_attrs)
{
	char		*be_name = NULL;
	char		*be_name_mnt = NULL;
	char		*ds = NULL;
	uint16_t	flags = 0;
	int		ret = BE_SUCCESS;

	/* Initialize libzfs handle */
	if (!be_zfs_init())
		return (BE_ERR_INIT);

	/* Get original BE name */
	if (nvlist_lookup_string(be_attrs, BE_ATTR_ORIG_BE_NAME, &be_name)
	    != 0) {
		be_print_err(gettext("be_unmount: failed to lookup "
		    "BE_ATTR_ORIG_BE_NAME attribute\n"));
		return (BE_ERR_INVAL);
	}

	/* Check if we have mountpoint argument instead of BE name */
	if (be_name[0] == '/') {
		if ((ds = be_get_ds_from_dir(be_name)) != NULL) {
			if ((be_name_mnt = strrchr(ds, '/')) != NULL) {
				be_name = be_name_mnt + 1;
			}
		} else {
			be_print_err(gettext("be_unmount: no datasets mounted "
			    "at '%s'\n"), be_name);
			return (BE_ERR_INVAL);
		}
	}

	/* Validate original BE name */
	if (!be_valid_be_name(be_name)) {
		be_print_err(gettext("be_unmount: invalid BE name %s\n"),
		    be_name);
		return (BE_ERR_INVAL);
	}

	/* Get unmount flags */
	if (nvlist_lookup_pairs(be_attrs, NV_FLAG_NOENTOK,
	    BE_ATTR_UNMOUNT_FLAGS, DATA_TYPE_UINT16, &flags, NULL) != 0) {
		be_print_err(gettext("be_unmount: failed to loookup "
		    "BE_ATTR_UNMOUNT_FLAGS attribute\n"));
		return (BE_ERR_INVAL);
	}

	ret = _be_unmount(be_name, flags);

	be_zfs_fini();

	return (ret);
}

/* ********************************************************************	*/
/*			Semi-Private Functions				*/
/* ******************************************************************** */

/*
 * Function:	_be_mount
 * Description:	Mounts a BE.  If the altroot is not provided, this function
 *		will generate a temporary mountpoint to mount the BE at.  It
 *		will return this temporary mountpoint to the caller via the
 *		altroot reference pointer passed in.  This returned value is
 *		allocated on heap storage and is the repsonsibility of the
 *		caller to free.
 * Parameters:
 *		be_name - pointer to name of BE to mount.
 *		altroot - reference pointer to altroot of where to mount BE.
 *		flags - flag indicating special handling for mounting the BE
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
_be_mount(char *be_name, char **altroot, int flags)
{
	be_transaction_data_t	bt = { 0 };
	be_mount_data_t	md = { 0 };
	zfs_handle_t	*zhp;
	char		obe_root_ds[MAXPATHLEN];
	char		*mp = NULL;
	char		*tmp_altroot = NULL;
	int		ret = BE_SUCCESS, err = 0;
	uuid_t		uu = { 0 };
	boolean_t	gen_tmp_altroot = B_FALSE;

	if (be_name == NULL || altroot == NULL)
		return (BE_ERR_INVAL);

	/* Set be_name as obe_name in bt structure */
	bt.obe_name = be_name;

	/* Find which zpool obe_name lives in */
	if ((err = zpool_iter(g_zfs, be_find_zpool_callback, &bt)) == 0) {
		be_print_err(gettext("be_mount: failed to "
		    "find zpool for BE (%s)\n"), bt.obe_name);
		return (BE_ERR_BE_NOENT);
	} else if (err < 0) {
		be_print_err(gettext("be_mount: zpool_iter failed: %s\n"),
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/* Generate string for obe_name's root dataset */
	be_make_root_ds(bt.obe_zpool, bt.obe_name, obe_root_ds,
	    sizeof (obe_root_ds));
	bt.obe_root_ds = obe_root_ds;

	/* Get handle to BE's root dataset */
	if ((zhp = zfs_open(g_zfs, bt.obe_root_ds, ZFS_TYPE_FILESYSTEM)) ==
	    NULL) {
		be_print_err(gettext("be_mount: failed to "
		    "open BE root dataset (%s): %s\n"), bt.obe_root_ds,
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/* Make sure BE's root dataset isn't already mounted somewhere */
	if (zfs_is_mounted(zhp, &mp)) {
		ZFS_CLOSE(zhp);
		be_print_err(gettext("be_mount: %s is already mounted "
		    "at %s\n"), bt.obe_name, mp != NULL ? mp : "");
		free(mp);
		return (BE_ERR_MOUNTED);
	}

	/*
	 * Fix this BE's mountpoint if its root dataset isn't set to
	 * either 'legacy' or '/'.
	 */
	if ((ret = fix_mountpoint(zhp)) != BE_SUCCESS) {
		be_print_err(gettext("be_mount: mountpoint check "
		    "failed for %s\n"), bt.obe_root_ds);
		ZFS_CLOSE(zhp);
		return (ret);
	}

	/*
	 * If altroot not provided, create a temporary alternate root
	 * to mount on
	 */
	if (*altroot == NULL) {
		if ((ret = be_make_tmp_mountpoint(&tmp_altroot))
		    != BE_SUCCESS) {
			be_print_err(gettext("be_mount: failed to "
			    "make temporary mountpoint\n"));
			ZFS_CLOSE(zhp);
			return (ret);
		}
		gen_tmp_altroot = B_TRUE;
	} else {
		tmp_altroot = *altroot;
	}

	md.altroot = tmp_altroot;
	md.shared_fs = flags & BE_MOUNT_FLAG_SHARED_FS;
	md.shared_rw = flags & BE_MOUNT_FLAG_SHARED_RW;

	/* Mount the BE's root file system */
	if (getzoneid() == GLOBAL_ZONEID) {
		if ((ret = be_mount_root(zhp, tmp_altroot)) != BE_SUCCESS) {
			be_print_err(gettext("be_mount: failed to "
			    "mount BE root file system\n"));
			if (gen_tmp_altroot)
				free(tmp_altroot);
			ZFS_CLOSE(zhp);
			return (ret);
		}
	} else {
		/* Legacy mount the zone root dataset */
		if ((ret = be_mount_zone_root(zhp, &md)) != BE_SUCCESS) {
			be_print_err(gettext("be_mount: failed to "
			    "mount BE zone root file system\n"));
			free(md.altroot);
			ZFS_CLOSE(zhp);
			return (ret);
		}
	}

	/* Iterate through BE's children filesystems */
	if ((err = zfs_iter_filesystems(zhp, be_mount_callback,
	    tmp_altroot)) != 0) {
		be_print_err(gettext("be_mount: failed to "
		    "mount BE (%s) on %s\n"), bt.obe_name, tmp_altroot);
		if (gen_tmp_altroot)
			free(tmp_altroot);
		ZFS_CLOSE(zhp);
		return (err);
	}

	/*
	 * Mount shared file systems if mount flag says so.
	 */
	if (md.shared_fs) {
		/*
		 * Mount all ZFS file systems not under the BE's root dataset
		 */
		(void) zpool_iter(g_zfs, zpool_shared_fs_callback, &md);

		/* TODO: Mount all non-ZFS file systems - Not supported yet */
	}

	/*
	 * If we're in the global zone and the global zone has a valid uuid,
	 * mount all supported non-global zones.
	 */
	if (getzoneid() == GLOBAL_ZONEID &&
	    !(flags & BE_MOUNT_FLAG_NO_ZONES) &&
	    be_get_uuid(bt.obe_root_ds, &uu) == BE_SUCCESS) {
		if (be_mount_zones(zhp, &md) != BE_SUCCESS) {
			ret = BE_ERR_NO_MOUNTED_ZONE;
		}
	}

	ZFS_CLOSE(zhp);

	/*
	 * If a NULL altroot was passed in, pass the generated altroot
	 * back to the caller in altroot.
	 */
	if (gen_tmp_altroot) {
		if (ret == BE_SUCCESS || ret == BE_ERR_NO_MOUNTED_ZONE)
			*altroot = tmp_altroot;
		else
			free(tmp_altroot);
	}

	return (ret);
}

/*
 * Function:	_be_unmount
 * Description:	Unmount a BE.
 * Parameters:
 *		be_name - pointer to name of BE to unmount.
 *		flags - flags for unmounting the BE.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
_be_unmount(char *be_name, int flags)
{
	be_transaction_data_t	bt = { 0 };
	be_unmount_data_t	ud = { 0 };
	zfs_handle_t	*zhp;
	uuid_t		uu = { 0 };
	char		obe_root_ds[MAXPATHLEN];
	char		mountpoint[MAXPATHLEN];
	char		*mp = NULL;
	int		ret = BE_SUCCESS;
	int		zret = 0;

	if (be_name == NULL)
		return (BE_ERR_INVAL);

	/* Set be_name as obe_name in bt structure */
	bt.obe_name = be_name;

	/* Find which zpool obe_name lives in */
	if ((zret = zpool_iter(g_zfs, be_find_zpool_callback, &bt)) == 0) {
		be_print_err(gettext("be_unmount: failed to "
		    "find zpool for BE (%s)\n"), bt.obe_name);
		return (BE_ERR_BE_NOENT);
	} else if (zret < 0) {
		be_print_err(gettext("be_unmount: "
		    "zpool_iter failed: %s\n"),
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		return (ret);
	}

	/* Generate string for obe_name's root dataset */
	be_make_root_ds(bt.obe_zpool, bt.obe_name, obe_root_ds,
	    sizeof (obe_root_ds));
	bt.obe_root_ds = obe_root_ds;

	/* Get handle to BE's root dataset */
	if ((zhp = zfs_open(g_zfs, bt.obe_root_ds, ZFS_TYPE_FILESYSTEM)) ==
	    NULL) {
		be_print_err(gettext("be_unmount: failed to "
		    "open BE root dataset (%s): %s\n"), bt.obe_root_ds,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		return (ret);
	}

	/* Make sure BE's root dataset is mounted somewhere */
	if (!zfs_is_mounted(zhp, &mp)) {

		be_print_err(gettext("be_unmount: "
		    "(%s) not mounted\n"), bt.obe_name);

		/*
		 * BE is not mounted, fix this BE's mountpoint if its root
		 * dataset isn't set to either 'legacy' or '/'.
		 */
		if ((ret = fix_mountpoint(zhp)) != BE_SUCCESS) {
			be_print_err(gettext("be_unmount: mountpoint check "
			    "failed for %s\n"), bt.obe_root_ds);
			ZFS_CLOSE(zhp);
			return (ret);
		}

		ZFS_CLOSE(zhp);
		return (BE_ERR_NOTMOUNTED);
	}

	/*
	 * If we didn't get a mountpoint from the zfs_is_mounted call,
	 * try and get it from its property.
	 */
	if (mp == NULL) {
		if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
		    sizeof (mountpoint), NULL, NULL, 0, B_FALSE) != 0) {
			be_print_err(gettext("be_unmount: failed to "
			    "get mountpoint of (%s)\n"), bt.obe_name);
			ZFS_CLOSE(zhp);
			return (BE_ERR_ZFS);
		}
	} else {
		(void) strlcpy(mountpoint, mp, sizeof (mountpoint));
		free(mp);
	}

	/* If BE mounted as current root, fail */
	if (strcmp(mountpoint, "/") == 0) {
		be_print_err(gettext("be_unmount: "
		    "cannot unmount currently running BE\n"));
		ZFS_CLOSE(zhp);
		return (BE_ERR_UMOUNT_CURR_BE);
	}

	ud.altroot = mountpoint;
	ud.force = flags & BE_UNMOUNT_FLAG_FORCE;

	/* Unmount all supported non-global zones if we're in the global zone */
	if (getzoneid() == GLOBAL_ZONEID &&
	    be_get_uuid(bt.obe_root_ds, &uu) == BE_SUCCESS) {
		if ((ret = be_unmount_zones(&ud)) != BE_SUCCESS) {
			ZFS_CLOSE(zhp);
			return (ret);
		}
	}

	/* TODO: Unmount all non-ZFS file systems - Not supported yet */

	/* Unmount all ZFS file systems not under the BE root dataset */
	if ((ret = unmount_shared_fs(&ud)) != BE_SUCCESS) {
		be_print_err(gettext("be_unmount: failed to "
		    "unmount shared file systems\n"));
		ZFS_CLOSE(zhp);
		return (ret);
	}

	/* Unmount all children datasets under the BE's root dataset */
	if ((zret = zfs_iter_filesystems(zhp, be_unmount_callback,
	    &ud)) != 0) {
		be_print_err(gettext("be_unmount: failed to "
		    "unmount BE (%s)\n"), bt.obe_name);
		ZFS_CLOSE(zhp);
		return (zret);
	}

	/* Unmount this BE's root filesystem */
	if (getzoneid() == GLOBAL_ZONEID) {
		if ((ret = be_unmount_root(zhp, &ud)) != BE_SUCCESS) {
			ZFS_CLOSE(zhp);
			return (ret);
		}
	} else {
		if ((ret = be_unmount_zone_root(zhp, &ud)) != BE_SUCCESS) {
			ZFS_CLOSE(zhp);
			return (ret);
		}
	}

	ZFS_CLOSE(zhp);

	return (BE_SUCCESS);
}

/*
 * Function:	be_mount_zone_root
 * Description:	Mounts the zone root dataset for a zone.
 * Parameters:
 *		zfs - zfs_handle_t pointer to zone root dataset
 *		md - be_mount_data_t pointer to data for zone to be mounted
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_mount_zone_root(zfs_handle_t *zhp, be_mount_data_t *md)
{
	struct stat buf;
	char	mountpoint[MAXPATHLEN];
	int	err = 0;

	/* Get mountpoint property of dataset */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), NULL, NULL, 0, B_FALSE) != 0) {
		be_print_err(gettext("be_mount_zone_root: failed to "
		    "get mountpoint property for %s: %s\n"), zfs_get_name(zhp),
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Make sure zone's root dataset is set to 'legacy'.  This is
	 * currently a requirement in this implementation of zones
	 * support.
	 */
	if (strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) != 0) {
		be_print_err(gettext("be_mount_zone_root: "
		    "zone root dataset mountpoint is not 'legacy'\n"));
		return (BE_ERR_ZONE_ROOT_NOT_LEGACY);
	}

	/* Create the mountpoint if it doesn't exist */
	if (lstat(md->altroot, &buf) != 0) {
		if (mkdirp(md->altroot, 0755) != 0) {
			err = errno;
			be_print_err(gettext("be_mount_zone_root: failed "
			    "to create mountpoint %s\n"), md->altroot);
			return (errno_to_be_err(err));
		}
	}

	/*
	 * Legacy mount the zone root dataset.
	 *
	 * As a workaround for 6176743, we mount the zone's root with the
	 * MS_OVERLAY option in case an alternate BE is mounted, and we're
	 * mounting the root for the zone from the current BE here.  When an
	 * alternate BE is mounted, it ties up the zone's zoneroot directory
	 * for the current BE since the zone's zonepath is loopback mounted
	 * from the current BE.
	 *
	 * TODO: The MS_OVERLAY option needs to be removed when 6176743
	 * is fixed.
	 */
	if (mount(zfs_get_name(zhp), md->altroot, MS_OVERLAY, MNTTYPE_ZFS,
	    NULL, 0, NULL, 0) != 0) {
		err = errno;
		be_print_err(gettext("be_mount_zone_root: failed to "
		    "legacy mount zone root dataset (%s) at %s\n"),
		    zfs_get_name(zhp), md->altroot);
		return (errno_to_be_err(err));
	}

	return (BE_SUCCESS);
}

/*
 * Function:	be_unmount_zone_root
 * Description:	Unmounts the zone root dataset for a zone.
 * Parameters:
 *		zhp - zfs_handle_t pointer to zone root dataset
 *		ud - be_unmount_data_t pointer to data for zone to be unmounted
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wise use only)
 */
int
be_unmount_zone_root(zfs_handle_t *zhp, be_unmount_data_t *ud)
{
	char	mountpoint[MAXPATHLEN];

	/* Unmount the dataset */
	if (zfs_unmount(zhp, NULL, ud->force ? MS_FORCE : 0) != 0) {
		be_print_err(gettext("be_unmount_zone_root: failed to "
		    "unmount zone root dataset %s: %s\n"), zfs_get_name(zhp),
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/* Get the current mountpoint property for the zone root dataset */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), NULL, NULL, 0, B_FALSE) != 0) {
		be_print_err(gettext("be_unmount_zone_root: failed to "
		    "get mountpoint property for zone root dataset (%s): %s\n"),
		    zfs_get_name(zhp), libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/* If mountpoint not already set to 'legacy', set it to 'legacy' */
	if (strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) != 0) {
		if (zfs_prop_set(zhp, zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
		    ZFS_MOUNTPOINT_LEGACY) != 0) {
			be_print_err(gettext("be_unmount_zone_root: "
			    "failed to set mountpoint of zone root dataset "
			    "%s to 'legacy': %s\n"), zfs_get_name(zhp),
			    libzfs_error_description(g_zfs));
			return (zfs_err_to_be_err(g_zfs));
		}
	}

	return (BE_SUCCESS);
}

/*
 * Function:	be_get_legacy_fs
 * Description:	This function iterates through all non-shared file systems
 *		of a BE and finds the ones with a legacy mountpoint.  For
 *		those file systems, it reads the BE's vfstab to get the
 *		mountpoint.  If found, it adds that file system to the
 *		be_fs_list_data_t passed in.
 *
 *		This function can be used to gather legacy mounted file systems
 *		for both global BEs and non-global zone BEs.  To get data for
 *		a non-global zone BE, the zoneroot_ds and zoneroot parameters
 *		will be specified, otherwise they should be set to NULL.
 * Parameters:
 *		be_name - global BE name from which to get legacy file
 *			system list.
 *		be_root_ds - root dataset of global BE.
 *		zoneroot_ds - root dataset of zone.
 *		zoneroot - zoneroot path of zone.
 *		fld - be_fs_list_data_t pointer.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_get_legacy_fs(char *be_name, char *be_root_ds, char *zoneroot_ds,
    char *zoneroot, be_fs_list_data_t *fld)
{
	zfs_handle_t		*zhp = NULL;
	char			mountpoint[MAXPATHLEN];
	boolean_t		mounted_here = B_FALSE;
	boolean_t		zone_mounted_here = B_FALSE;
	int			ret = BE_SUCCESS, err = 0;

	if (be_name == NULL || be_root_ds == NULL || fld == NULL)
		return (BE_ERR_INVAL);

	/* Get handle to BE's root dataset */
	if ((zhp = zfs_open(g_zfs, be_root_ds, ZFS_TYPE_FILESYSTEM))
	    == NULL) {
		be_print_err(gettext("be_get_legacy_fs: failed to "
		    "open BE root dataset (%s): %s\n"), be_root_ds,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		return (ret);
	}

	/* If BE is not already mounted, mount it. */
	if (!zfs_is_mounted(zhp, &fld->altroot)) {
		if ((ret = _be_mount(be_name, &fld->altroot,
		    zoneroot_ds ? BE_MOUNT_FLAG_NULL :
		    BE_MOUNT_FLAG_NO_ZONES)) != BE_SUCCESS) {
			be_print_err(gettext("be_get_legacy_fs: "
			    "failed to mount BE %s\n"), be_name);
			goto cleanup;
		}

		mounted_here = B_TRUE;
	} else if (fld->altroot == NULL) {
		be_print_err(gettext("be_get_legacy_fs: failed to "
		    "get altroot of mounted BE %s: %s\n"),
		    be_name, libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		goto cleanup;
	}

	/*
	 * If a zone root dataset was passed in, we're wanting to get
	 * legacy mounted file systems for that zone, not the global
	 * BE.
	 */
	if (zoneroot_ds != NULL) {
		be_mount_data_t		zone_md = { 0 };

		/* Close off handle to global BE's root dataset */
		ZFS_CLOSE(zhp);

		/* Get handle to zone's root dataset */
		if ((zhp = zfs_open(g_zfs, zoneroot_ds,
		    ZFS_TYPE_FILESYSTEM)) == NULL) {
			be_print_err(gettext("be_get_legacy_fs: failed to "
			    "open zone BE root dataset (%s): %s\n"),
			    zoneroot_ds, libzfs_error_description(g_zfs));
			ret = zfs_err_to_be_err(g_zfs);
			goto cleanup;
		}

		/* Make sure the zone we're looking for is mounted */
		if (!zfs_is_mounted(zhp, &zone_md.altroot)) {
			char	zone_altroot[MAXPATHLEN];

			/* Generate alternate root path for zone */
			(void) snprintf(zone_altroot, sizeof (zone_altroot),
			    "%s%s", fld->altroot, zoneroot);
			if ((zone_md.altroot = strdup(zone_altroot)) == NULL) {
				be_print_err(gettext("be_get_legacy_fs: "
				    "memory allocation failed\n"));
				ret = BE_ERR_NOMEM;
				goto cleanup;
			}

			if ((ret = be_mount_zone_root(zhp, &zone_md))
			    != BE_SUCCESS) {
				be_print_err(gettext("be_get_legacy_fs: "
				    "failed to mount zone root %s\n"),
				    zoneroot_ds);
				free(zone_md.altroot);
				zone_md.altroot = NULL;
				goto cleanup;
			}
			zone_mounted_here = B_TRUE;
		}

		free(fld->altroot);
		fld->altroot = zone_md.altroot;
	}

	/*
	 * If the root dataset is in the vfstab with a mountpoint of "/",
	 * add it to the list
	 */
	if (get_mountpoint_from_vfstab(fld->altroot, zfs_get_name(zhp),
	    mountpoint, sizeof (mountpoint), B_FALSE) == BE_SUCCESS) {
		if (strcmp(mountpoint, "/") == 0) {
			if (add_to_fs_list(fld, zfs_get_name(zhp))
			    != BE_SUCCESS) {
				be_print_err(gettext("be_get_legacy_fs: "
				    "failed to add %s to fs list\n"),
				    zfs_get_name(zhp));
				ret = BE_ERR_INVAL;
				goto cleanup;
			}
		}
	}

	/* Iterate subordinate file systems looking for legacy mounts */
	if ((ret = zfs_iter_filesystems(zhp, be_get_legacy_fs_callback,
	    fld)) != 0) {
		be_print_err(gettext("be_get_legacy_fs: "
		    "failed to iterate  %s to get legacy mounts\n"),
		    zfs_get_name(zhp));
	}

cleanup:
	/* If we mounted the zone BE, unmount it */
	if (zone_mounted_here) {
		be_unmount_data_t	zone_ud = { 0 };

		zone_ud.altroot = fld->altroot;
		zone_ud.force = B_TRUE;
		if ((err = be_unmount_zone_root(zhp, &zone_ud)) != BE_SUCCESS) {
			be_print_err(gettext("be_get_legacy_fs: "
			    "failed to unmount zone root %s\n"),
			    zoneroot_ds);
			if (ret == BE_SUCCESS)
				ret = err;
		}
	}

	/* If we mounted this BE, unmount it */
	if (mounted_here) {
		if ((err = _be_unmount(be_name, 0)) != BE_SUCCESS) {
			be_print_err(gettext("be_get_legacy_fs: "
			    "failed to unmount %s\n"), be_name);
			if (ret == BE_SUCCESS)
				ret = err;
		}
	}

	ZFS_CLOSE(zhp);

	free(fld->altroot);
	fld->altroot = NULL;

	return (ret);
}

/*
 * Function:	be_free_fs_list
 * Description:	Function used to free the members of a be_fs_list_data_t
 *			structure.
 * Parameters:
 *		fld - be_fs_list_data_t pointer to free.
 * Returns:
 *		None
 * Scope:
 *		Semi-private (library wide use only)
 */
void
be_free_fs_list(be_fs_list_data_t *fld)
{
	int	i;

	if (fld == NULL)
		return;

	free(fld->altroot);

	if (fld->fs_list == NULL)
		return;

	for (i = 0; i < fld->fs_num; i++)
		free(fld->fs_list[i]);

	free(fld->fs_list);
}

/*
 * Function:	be_get_ds_from_dir(char *dir)
 * Description:	Given a directory path, find the underlying dataset mounted
 *		at that directory path if there is one.   The returned name
 *		is allocated in heap storage, so the caller is responsible
 *		for freeing it.
 * Parameters:
 *		dir - char pointer of directory to find.
 * Returns:
 *		NULL - if directory is not mounted from a dataset.
 *		name of dataset mounted at dir.
 * Scope:
 *		Semi-private (library wide use only)
 */
char *
be_get_ds_from_dir(char *dir)
{
	dir_data_t	dd = { 0 };
	char		resolved_dir[MAXPATHLEN];

	/* Make sure length of dir is within the max length */
	if (dir == NULL || strlen(dir) >= MAXPATHLEN)
		return (NULL);

	/* Resolve dir in case its lofs mounted */
	(void) strlcpy(resolved_dir, dir, sizeof (resolved_dir));
	z_resolve_lofs(resolved_dir, sizeof (resolved_dir));

	dd.dir = resolved_dir;

	(void) zfs_iter_root(g_zfs, be_get_ds_from_dir_callback, &dd);

	return (dd.ds);
}

/*
 * Function:	be_make_tmp_mountpoint
 * Description:	This function generates a random temporary mountpoint
 *		and creates that mountpoint directory.  It returns the
 *		mountpoint in heap storage, so the caller is responsible
 *		for freeing it.
 * Parameters:
 *		tmp_mp - reference to pointer of where to store generated
 *			temporary mountpoint.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_make_tmp_mountpoint(char **tmp_mp)
{
	int	err = 0;

	if ((*tmp_mp = (char *)calloc(1, sizeof (BE_TMP_MNTPNT) + 1)) == NULL) {
		be_print_err(gettext("be_make_tmp_mountpoint: "
		    "malloc failed\n"));
		return (BE_ERR_NOMEM);
	}
	(void) strlcpy(*tmp_mp, BE_TMP_MNTPNT, sizeof (BE_TMP_MNTPNT) + 1);
	if (mkdtemp(*tmp_mp) == NULL) {
		err = errno;
		be_print_err(gettext("be_make_tmp_mountpoint: mkdtemp() failed "
		    "for %s: %s\n"), *tmp_mp, strerror(err));
		free(*tmp_mp);
		*tmp_mp = NULL;
		return (errno_to_be_err(err));
	}

	return (BE_SUCCESS);
}

/*
 * Function:	be_mount_pool
 * Description: This function determines if the pool's datase is mounted
 *		and if not it is used to mount the pool's dataset. The
 *		function returns the current mountpoint if we are able
 *		to mount the dataset.
 * Parameters:
 *		zhp - handle to the pool's dataset
 *		tmp_mntpnt - The temporary mountpoint that the pool's
 *			      dataset is mounted on. This is set only
 *			      if the attempt to mount the dataset at it's
 *			      set mountpoint fails, and we've used a
 *			      temporary mount point for this dataset. It
 *			      is expected that the caller will free this
 *			      memory.
 *		orig_mntpnt - The original mountpoint for the pool. If a
 *			      temporary mount point was needed this will
 *			      be used to reset the mountpoint property to
 *			      it's original mountpoint. It is expected that
 *			      the caller will free this memory.
 *		pool_mounted - This flag indicates that the pool was mounted
 *			       in this function.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_mount_pool(
	zfs_handle_t *zhp,
	char **tmp_mntpnt,
	char **orig_mntpnt,
	boolean_t *pool_mounted)
{

	char		mountpoint[MAXPATHLEN];
	int		ret = 0;

	*tmp_mntpnt = NULL;
	*orig_mntpnt = NULL;
	*pool_mounted = B_FALSE;

	if (!zfs_is_mounted(zhp, NULL)) {
		if (zfs_mount(zhp, NULL, 0) != 0) {
			if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
			    sizeof (mountpoint), NULL, NULL, 0, B_FALSE) != 0) {
				be_print_err(gettext("be_mount_pool: failed to "
				    "get mountpoint of (%s): %s\n"),
				    zfs_get_name(zhp),
				    libzfs_error_description(g_zfs));
				return (zfs_err_to_be_err(g_zfs));
			}
			if ((*orig_mntpnt = strdup(mountpoint)) == NULL) {
				be_print_err(gettext("be_mount_pool: memory "
				    "allocation failed\n"));
				return (BE_ERR_NOMEM);
			}
			/*
			 * attempt to mount on a temp mountpoint
			 */
			if ((ret = be_make_tmp_mountpoint(tmp_mntpnt))
			    != BE_SUCCESS) {
				be_print_err(gettext("be_mount_pool: failed "
				    "to make temporary mountpoint\n"));
				free(*orig_mntpnt);
				*orig_mntpnt = NULL;
				return (ret);
			}

			if (zfs_prop_set(zhp,
			    zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
			    *tmp_mntpnt) != 0) {
				be_print_err(gettext("be_mount_pool: failed "
				    "to set mountpoint of pool dataset %s to "
				    "%s: %s\n"), zfs_get_name(zhp),
				    *orig_mntpnt,
				    libzfs_error_description(g_zfs));
				free(*tmp_mntpnt);
				free(*orig_mntpnt);
				*orig_mntpnt = NULL;
				*tmp_mntpnt = NULL;
				return (zfs_err_to_be_err(g_zfs));
			}

			if (zfs_mount(zhp, NULL, 0) != 0) {
				be_print_err(gettext("be_mount_pool: failed "
				    "to mount dataset %s at %s: %s\n"),
				    zfs_get_name(zhp), *tmp_mntpnt,
				    libzfs_error_description(g_zfs));
				ret = zfs_err_to_be_err(g_zfs);
				if (zfs_prop_set(zhp,
				    zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
				    mountpoint) != 0) {
					be_print_err(gettext("be_mount_pool: "
					    "failed to set mountpoint of pool "
					    "dataset %s to %s: %s\n"),
					    zfs_get_name(zhp), *tmp_mntpnt,
					    libzfs_error_description(g_zfs));
				}
				free(*tmp_mntpnt);
				free(*orig_mntpnt);
				*orig_mntpnt = NULL;
				*tmp_mntpnt = NULL;
				return (ret);
			}
		}
		*pool_mounted = B_TRUE;
	}

	return (BE_SUCCESS);
}

/*
 * Function:	be_unmount_pool
 * Description: This function is used to unmount the pool's dataset if we
 *		mounted it previously using be_mount_pool().
 * Parameters:
 *		zhp - handle to the pool's dataset
 *		tmp_mntpnt - If a temprary mount point was used this will
 *			     be set. Since this was created in be_mount_pool
 *			     we will need to clean it up here.
 *		orig_mntpnt - The original mountpoint for the pool. This is
 *			      used to set the dataset mountpoint property
 *			      back to it's original value in the case where a
 *			      temporary mountpoint was used.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_unmount_pool(
	zfs_handle_t *zhp,
	char *tmp_mntpnt,
	char *orig_mntpnt)
{
	if (zfs_unmount(zhp, NULL, 0) != 0) {
		be_print_err(gettext("be_unmount_pool: failed to "
		    "unmount pool (%s): %s\n"), zfs_get_name(zhp),
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}
	if (orig_mntpnt != NULL) {
		if (tmp_mntpnt != NULL &&
		    strcmp(orig_mntpnt, tmp_mntpnt) != 0) {
			(void) rmdir(tmp_mntpnt);
		}
		if (zfs_prop_set(zhp,
		    zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
		    orig_mntpnt) != 0) {
			be_print_err(gettext("be_unmount_pool: failed "
			    "to set the mountpoint for dataset (%s) to "
			    "%s: %s\n"), zfs_get_name(zhp), orig_mntpnt,
			    libzfs_error_description(g_zfs));
			return (zfs_err_to_be_err(g_zfs));
		}
	}

	return (BE_SUCCESS);
}

/* ********************************************************************	*/
/*			Private Functions				*/
/* ********************************************************************	*/

/*
 * Function:	be_mount_callback
 * Description:	Callback function used to iterate through all of a BE's
 *		subordinate file systems and to mount them accordingly.
 * Parameters:
 *		zhp - zfs_handle_t pointer to current file system being
 *			processed.
 *		data - pointer to the altroot of where to mount BE.
 * Returns:
 *		0 - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_mount_callback(zfs_handle_t *zhp, void *data)
{
	zprop_source_t	sourcetype;
	const char	*fs_name = zfs_get_name(zhp);
	char		source[ZFS_MAX_DATASET_NAME_LEN];
	char		*altroot = data;
	char		zhp_mountpoint[MAXPATHLEN];
	char		mountpoint[MAXPATHLEN];
	int		ret = 0;

	/* Get dataset's mountpoint and source values */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, zhp_mountpoint,
	    sizeof (zhp_mountpoint), &sourcetype, source, sizeof (source),
	    B_FALSE) != 0) {
		be_print_err(gettext("be_mount_callback: failed to "
		    "get mountpoint and sourcetype for %s\n"),
		    fs_name);
		ZFS_CLOSE(zhp);
		return (BE_ERR_ZFS);
	}

	/*
	 * Set this filesystem's 'canmount' property to 'noauto' just incase
	 * it's been set 'on'.
	 */
	if (zfs_prop_set(zhp, zfs_prop_to_name(ZFS_PROP_CANMOUNT), "noauto")) {
		be_print_err(gettext("be_mount_callback: failed to "
		    "set canmount to 'noauto' (%s)\n"), fs_name);
		ZFS_CLOSE(zhp);
		return (BE_ERR_ZFS);
	}

	/*
	 * If the mountpoint is none, there's nothing to do, goto next.
	 * If the mountpoint is legacy, legacy mount it with mount(2).
	 * If the mountpoint is inherited, its mountpoint should
	 * already be set.  If it's not, then explicitly fix-up
	 * the mountpoint now by appending its explicitly set
	 * mountpoint value to the BE mountpoint.
	 */
	if (strcmp(zhp_mountpoint, ZFS_MOUNTPOINT_NONE) == 0) {
		goto next;
	} else if (strcmp(zhp_mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0) {
		/*
		 * If the mountpoint is set to 'legacy', we need to
		 * dig into this BE's vfstab to figure out where to
		 * mount it, and just mount it via mount(2).
		 */
		if (get_mountpoint_from_vfstab(altroot, fs_name,
		    mountpoint, sizeof (mountpoint), B_TRUE) == BE_SUCCESS) {

			/* Legacy mount the file system */
			if (mount(fs_name, mountpoint, MS_DATA,
			    MNTTYPE_ZFS, NULL, 0, NULL, 0) != 0) {
				be_print_err(
				    gettext("be_mount_callback: "
				    "failed to mount %s on %s\n"),
				    fs_name, mountpoint);
			}
		} else {
			be_print_err(
			    gettext("be_mount_callback: "
			    "no entry for %s in vfstab, "
			    "skipping ...\n"), fs_name);
		}

		goto next;

	} else if ((sourcetype & (ZPROP_SRC_INHERITED|ZPROP_SRC_LOCAL)) == 0) {
		/*
		 * Skip dataset if mountpoint is not inherited
		 * or explicitly set.
		 */
		be_print_err(gettext("be_mount_callback: "
		    "mountpoint sourcetype of %s is %d, skipping ...\n"),
		    fs_name, sourcetype);

		goto next;
	}

	/* Mount this filesystem */
	if (mount_zfs(zhp, altroot) != 0) {
		be_print_err(gettext("be_mount_callback: failed to "
		    "mount dataset %s at %s: %s\n"), fs_name, mountpoint,
		    strerror(errno));
		ZFS_CLOSE(zhp);
		return (BE_ERR_MOUNT);
	}

next:
	/* Iterate through this dataset's children and mount them */
	if ((ret = zfs_iter_filesystems(zhp, be_mount_callback,
	    altroot)) != 0) {
		ZFS_CLOSE(zhp);
		return (ret);
	}


	ZFS_CLOSE(zhp);
	return (0);
}

/*
 * Function:	be_unmount_callback
 * Description:	Callback function used to iterate through all of a BE's
 *		subordinate file systems and to unmount them.
 * Parameters:
 *		zhp - zfs_handle_t pointer to current file system being
 *			processed.
 *		data - pointer to the mountpoint of where BE is mounted.
 * Returns:
 *		0 - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_unmount_callback(zfs_handle_t *zhp, void *data)
{
	be_unmount_data_t	*ud = data;
	zprop_source_t	sourcetype;
	const char	*fs_name = zfs_get_name(zhp);
	char		source[ZFS_MAX_DATASET_NAME_LEN];
	char		mountpoint[MAXPATHLEN];
	char		*zhp_mountpoint;
	int		ret = 0;

	/* Iterate down this dataset's children first */
	if (zfs_iter_filesystems(zhp, be_unmount_callback, ud)) {
		ret = BE_ERR_UMOUNT;
		goto done;
	}

	/* Is dataset even mounted ? */
	if (!zfs_is_mounted(zhp, NULL))
		goto done;

	/* Unmount this file system */
	if (zfs_unmount(zhp, NULL, ud->force ? MS_FORCE : 0) != 0) {
		be_print_err(gettext("be_unmount_callback: "
		    "failed to unmount %s: %s\n"), fs_name,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		goto done;
	}

	/* Get dataset's current mountpoint and source value */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), &sourcetype, source, sizeof (source),
	    B_FALSE) != 0) {
		be_print_err(gettext("be_unmount_callback: "
		    "failed to get mountpoint and sourcetype for %s: %s\n"),
		    fs_name, libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		goto done;
	}

	if (sourcetype & ZPROP_SRC_INHERITED) {
		/*
		 * If the mountpoint is inherited we don't need to
		 * do anything.  When its parent gets processed
		 * its mountpoint will be set accordingly.
		 */
		goto done;
	} else if (sourcetype & ZPROP_SRC_LOCAL) {

		if (strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0) {
			/*
			 * If the mountpoint is set to 'legacy', its already
			 * been unmounted (from above call to zfs_unmount), and
			 * we don't need to do anything else with it.
			 */
			goto done;

		} else {
			/*
			 * Else process dataset with explicitly set mountpoint.
			 */

			/*
			 * Get this dataset's mountpoint relative to
			 * the BE's mountpoint.
			 */
			if ((strncmp(mountpoint, ud->altroot,
			    strlen(ud->altroot)) == 0) &&
			    (mountpoint[strlen(ud->altroot)] == '/')) {

				zhp_mountpoint = mountpoint +
				    strlen(ud->altroot);

				/* Set this dataset's mountpoint value */
				if (zfs_prop_set(zhp,
				    zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
				    zhp_mountpoint)) {
					be_print_err(
					    gettext("be_unmount_callback: "
					    "failed to set mountpoint for "
					    "%s to %s: %s\n"), fs_name,
					    zhp_mountpoint,
					    libzfs_error_description(g_zfs));
					ret = zfs_err_to_be_err(g_zfs);
				}
			} else {
				/*
				 * Nothing to do, mountpoint shouldn't be
				 * corrected.
				 */
				goto done;
			}
		}
	} else {
		be_print_err(gettext("be_unmount_callback: "
		    "mountpoint sourcetype of %s is %d, skipping ...\n"),
		    fs_name, sourcetype);
		ret = BE_ERR_ZFS;
	}

done:
	/* Set this filesystem's 'canmount' property to 'noauto' */
	if (zfs_prop_set(zhp, zfs_prop_to_name(ZFS_PROP_CANMOUNT), "noauto")) {
		be_print_err(gettext("be_unmount_callback: "
		    "failed to set canmount to 'noauto' (%s)\n"), fs_name);
		if (ret == 0)
			ret = BE_ERR_ZFS;
	}

	ZFS_CLOSE(zhp);
	return (ret);
}

/*
 * Function:	be_get_legacy_fs_callback
 * Description:	The callback function is used to iterate through all
 *		non-shared file systems of a BE, finding ones that have
 *		a legacy mountpoint and an entry in the BE's vfstab.
 *		It adds these file systems to the callback data.
 * Parameters:
 *		zhp - zfs_handle_t pointer to current file system being
 *			processed.
 *		data - be_fs_list_data_t pointer
 * Returns:
 *		0 - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_get_legacy_fs_callback(zfs_handle_t *zhp, void *data)
{
	be_fs_list_data_t	*fld = data;
	const char		*fs_name = zfs_get_name(zhp);
	char			zhp_mountpoint[MAXPATHLEN];
	char			mountpoint[MAXPATHLEN];
	int			ret = 0;

	/* Get this dataset's mountpoint property */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, zhp_mountpoint,
	    sizeof (zhp_mountpoint), NULL, NULL, 0, B_FALSE) != 0) {
		be_print_err(gettext("be_get_legacy_fs_callback: "
		    "failed to get mountpoint for %s: %s\n"),
		    fs_name, libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		ZFS_CLOSE(zhp);
		return (ret);
	}

	/*
	 * If mountpoint is legacy, try to get its mountpoint from this BE's
	 * vfstab.  If it exists in the vfstab, add this file system to the
	 * callback data.
	 */
	if (strcmp(zhp_mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0) {
		if (get_mountpoint_from_vfstab(fld->altroot, fs_name,
		    mountpoint, sizeof (mountpoint), B_FALSE) != BE_SUCCESS) {
			be_print_err(gettext("be_get_legacy_fs_callback: "
			    "no entry for %s in vfstab, "
			    "skipping ...\n"), fs_name);

			goto next;
		}

		/* Record file system into the callback data. */
		if (add_to_fs_list(fld, zfs_get_name(zhp)) != BE_SUCCESS) {
			be_print_err(gettext("be_get_legacy_fs_callback: "
			    "failed to add %s to fs list\n"), mountpoint);
			ZFS_CLOSE(zhp);
			return (BE_ERR_NOMEM);
		}
	}

next:
	/* Iterate through this dataset's children file systems */
	if ((ret = zfs_iter_filesystems(zhp, be_get_legacy_fs_callback,
	    fld)) != 0) {
		ZFS_CLOSE(zhp);
		return (ret);
	}
	ZFS_CLOSE(zhp);
	return (0);
}

/*
 * Function:	add_to_fs_list
 * Description:	Function used to add a file system to the fs_list array in
 *			a be_fs_list_data_t structure.
 * Parameters:
 *		fld - be_fs_list_data_t pointer
 *		fs - file system to add
 * Returns:
 *		BE_SUCCESS - Success
 *		1 - Failure
 * Scope:
 *		Private
 */
static int
add_to_fs_list(be_fs_list_data_t *fld, const char *fs)
{
	if (fld == NULL || fs == NULL)
		return (1);

	if ((fld->fs_list = (char **)realloc(fld->fs_list,
	    sizeof (char *)*(fld->fs_num + 1))) == NULL) {
		be_print_err(gettext("add_to_fs_list: "
		    "memory allocation failed\n"));
		return (1);
	}

	if ((fld->fs_list[fld->fs_num++] = strdup(fs)) == NULL) {
		be_print_err(gettext("add_to_fs_list: "
		    "memory allocation failed\n"));
		return (1);
	}

	return (BE_SUCCESS);
}

/*
 * Function:	zpool_shared_fs_callback
 * Description:	Callback function used to iterate through all existing pools
 *		to find and mount all shared filesystems.  This function
 *		processes the pool's "pool data" dataset, then uses
 *		iter_shared_fs_callback to iterate through the pool's
 *		datasets.
 * Parameters:
 *		zlp - zpool_handle_t pointer to the current pool being
 *			looked at.
 *		data - be_mount_data_t pointer
 * Returns:
 *		0 - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
zpool_shared_fs_callback(zpool_handle_t *zlp, void *data)
{
	be_mount_data_t	*md = data;
	zfs_handle_t	*zhp = NULL;
	const char	*zpool = zpool_get_name(zlp);
	int		ret = 0;

	/*
	 * Get handle to pool's "pool data" dataset
	 */
	if ((zhp = zfs_open(g_zfs, zpool, ZFS_TYPE_FILESYSTEM)) == NULL) {
		be_print_err(gettext("zpool_shared_fs: "
		    "failed to open pool dataset %s: %s\n"), zpool,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		zpool_close(zlp);
		return (ret);
	}

	/* Process this pool's "pool data" dataset */
	(void) loopback_mount_shared_fs(zhp, md);

	/* Interate through this pool's children */
	(void) zfs_iter_filesystems(zhp, iter_shared_fs_callback, md);

	ZFS_CLOSE(zhp);
	zpool_close(zlp);

	return (0);
}

/*
 * Function:	iter_shared_fs_callback
 * Description:	Callback function used to iterate through a pool's datasets
 *		to find and mount all shared filesystems.  It makes sure to
 *		find the BE container dataset of the pool, if it exists, and
 *		does not process and iterate down that path.
 *
 *		Note - This function iterates linearly down the
 *		hierarchical dataset paths and mounts things as it goes
 *		along.  It does not make sure that something deeper down
 *		a dataset path has an interim mountpoint for something
 *		processed earlier.
 *
 * Parameters:
 *		zhp - zfs_handle_t pointer to the current dataset being
 *			processed.
 *		data - be_mount_data_t pointer
 * Returns:
 *		0 - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
iter_shared_fs_callback(zfs_handle_t *zhp, void *data)
{
	be_mount_data_t	*md = data;
	const char	*name = zfs_get_name(zhp);
	char		container_ds[MAXPATHLEN];
	char		tmp_name[MAXPATHLEN];
	char		*pool;

	/* Get the pool's name */
	(void) strlcpy(tmp_name, name, sizeof (tmp_name));
	pool = strtok(tmp_name, "/");

	if (pool) {
		/* Get the name of this pool's container dataset */
		be_make_container_ds(pool, container_ds,
		    sizeof (container_ds));

		/*
		 * If what we're processing is this pool's BE container
		 * dataset, skip it.
		 */
		if (strcmp(name, container_ds) == 0) {
			ZFS_CLOSE(zhp);
			return (0);
		}
	} else {
		/* Getting the pool name failed, return error */
		be_print_err(gettext("iter_shared_fs_callback: "
		    "failed to get pool name from %s\n"), name);
		ZFS_CLOSE(zhp);
		return (BE_ERR_POOL_NOENT);
	}

	/* Mount this shared filesystem */
	(void) loopback_mount_shared_fs(zhp, md);

	/* Iterate this dataset's children file systems */
	(void) zfs_iter_filesystems(zhp, iter_shared_fs_callback, md);
	ZFS_CLOSE(zhp);

	return (0);
}

/*
 * Function:	loopback_mount_shared_fs
 * Description:	This function loopback mounts a file system into the altroot
 *		area of the BE being mounted.  Since these are shared file
 *		systems, they are expected to be already mounted for the
 *		current BE, and this function just loopback mounts them into
 *		the BE mountpoint.  If they are not mounted for the current
 *		live system, they are skipped and not mounted into the BE
 *		we're mounting.
 * Parameters:
 *		zhp - zfs_handle_t pointer to the dataset to loopback mount
 *		md - be_mount_data_t pointer
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
loopback_mount_shared_fs(zfs_handle_t *zhp, be_mount_data_t *md)
{
	char		zhp_mountpoint[MAXPATHLEN];
	char		mountpoint[MAXPATHLEN];
	char		*mp = NULL;
	char		optstr[MAX_MNTOPT_STR];
	int		mflag = MS_OPTIONSTR;
	int		err;

	/*
	 * Check if file system is currently mounted and not delegated
	 * to a non-global zone (if we're in the global zone)
	 */
	if (zfs_is_mounted(zhp, &mp) && (getzoneid() != GLOBAL_ZONEID ||
	    !zfs_prop_get_int(zhp, ZFS_PROP_ZONED))) {
		/*
		 * If we didn't get a mountpoint from the zfs_is_mounted call,
		 * get it from the mountpoint property.
		 */
		if (mp == NULL) {
			if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT,
			    zhp_mountpoint, sizeof (zhp_mountpoint), NULL,
			    NULL, 0, B_FALSE) != 0) {
				be_print_err(
				    gettext("loopback_mount_shared_fs: "
				    "failed to get mountpoint property\n"));
				return (BE_ERR_ZFS);
			}
		} else {
			(void) strlcpy(zhp_mountpoint, mp,
			    sizeof (zhp_mountpoint));
			free(mp);
		}

		(void) snprintf(mountpoint, sizeof (mountpoint), "%s%s",
		    md->altroot, zhp_mountpoint);

		/* Mount it read-only if read-write was not requested */
		if (!md->shared_rw) {
			mflag |= MS_RDONLY;
		}

		/* Add the "nosub" option to the mount options string */
		(void) strlcpy(optstr, MNTOPT_NOSUB, sizeof (optstr));

		/* Loopback mount this dataset at the altroot */
		if (mount(zhp_mountpoint, mountpoint, mflag, MNTTYPE_LOFS,
		    NULL, 0, optstr, sizeof (optstr)) != 0) {
			err = errno;
			be_print_err(gettext("loopback_mount_shared_fs: "
			    "failed to loopback mount %s at %s: %s\n"),
			    zhp_mountpoint, mountpoint, strerror(err));
			return (BE_ERR_MOUNT);
		}
	}

	return (BE_SUCCESS);
}

/*
 * Function:	loopback_mount_zonepath
 * Description:	This function loopback mounts a zonepath into the altroot
 *		area of the BE being mounted.
 * Parameters:
 *		zonepath - pointer to zone path in the current BE
 *		md - be_mount_data_t pointer
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
loopback_mount_zonepath(const char *zonepath, be_mount_data_t *md)
{
	FILE		*fp = (FILE *)NULL;
	struct stat	st;
	char		*p;
	char		*p1;
	char		*parent_dir;
	struct extmnttab	extmtab;
	dev_t		dev = NODEV;
	char		*parentmnt;
	char		alt_parentmnt[MAXPATHLEN];
	struct mnttab	mntref;
	char		altzonepath[MAXPATHLEN];
	char		optstr[MAX_MNTOPT_STR];
	int		mflag = MS_OPTIONSTR;
	int		ret;
	int		err;

	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		err = errno;
		be_print_err(gettext("loopback_mount_zonepath: "
		    "failed to open /etc/mnttab\n"));
		return (errno_to_be_err(err));
	}

	/*
	 * before attempting the loopback mount of zonepath under altroot,
	 * we need to make sure that all intermediate file systems in the
	 * zone path are also mounted under altroot
	 */

	/* get the parent directory for zonepath */
	p = strrchr(zonepath, '/');
	if (p != NULL && p != zonepath) {
		if ((parent_dir = (char *)calloc(sizeof (char),
		    p - zonepath + 1)) == NULL) {
			ret = BE_ERR_NOMEM;
			goto done;
		}
		(void) strlcpy(parent_dir, zonepath, p - zonepath + 1);
		if (stat(parent_dir, &st) < 0) {
			ret = errno_to_be_err(errno);
			be_print_err(gettext("loopback_mount_zonepath: "
			    "failed to stat %s"),
			    parent_dir);
			free(parent_dir);
			goto done;
		}
		free(parent_dir);

		/*
		 * After the above stat call, st.st_dev contains ID of the
		 * device over which parent dir resides.
		 * Now, search mnttab and find mount point of parent dir device.
		 */

		resetmnttab(fp);
		while (getextmntent(fp, &extmtab, sizeof (extmtab)) == 0) {
			dev = makedev(extmtab.mnt_major, extmtab.mnt_minor);
			if (st.st_dev == dev && strcmp(extmtab.mnt_fstype,
			    MNTTYPE_ZFS) == 0) {
				p1 = strchr(extmtab.mnt_special, '/');
				if (p1 == NULL || strncmp(p1 + 1,
				    BE_CONTAINER_DS_NAME, 4) != 0 ||
				    (*(p1 + 5) != '/' && *(p1 + 5) != '\0')) {
					/*
					 * if parent dir is in a shared file
					 * system, check whether it is already
					 * loopback mounted under altroot or
					 * not.  It would have been mounted
					 * already under altroot if it is in
					 * a non-shared filesystem.
					 */
					parentmnt = strdup(extmtab.mnt_mountp);
					(void) snprintf(alt_parentmnt,
					    sizeof (alt_parentmnt), "%s%s",
					    md->altroot, parentmnt);
					mntref.mnt_mountp = alt_parentmnt;
					mntref.mnt_special = parentmnt;
					mntref.mnt_fstype = MNTTYPE_LOFS;
					mntref.mnt_mntopts = NULL;
					mntref.mnt_time = NULL;
					resetmnttab(fp);
					if (getmntany(fp, (struct mnttab *)
					    &extmtab, &mntref) != 0) {
						ret = loopback_mount_zonepath(
						    parentmnt, md);
						if (ret != BE_SUCCESS) {
							free(parentmnt);
							goto done;
						}
					}
					free(parentmnt);
				}
				break;
			}
		}
	}


	if (!md->shared_rw) {
		mflag |= MS_RDONLY;
	}

	(void) snprintf(altzonepath, sizeof (altzonepath), "%s%s",
	    md->altroot, zonepath);

	/* Add the "nosub" option to the mount options string */
	(void) strlcpy(optstr, MNTOPT_NOSUB, sizeof (optstr));

	/* Loopback mount this dataset at the altroot */
	if (mount(zonepath, altzonepath, mflag, MNTTYPE_LOFS,
	    NULL, 0, optstr, sizeof (optstr)) != 0) {
		err = errno;
		be_print_err(gettext("loopback_mount_zonepath: "
		    "failed to loopback mount %s at %s: %s\n"),
		    zonepath, altzonepath, strerror(err));
		ret = BE_ERR_MOUNT;
		goto done;
	}
	ret = BE_SUCCESS;

done :
	(void) fclose(fp);
	return (ret);
}

/*
 * Function:	unmount_shared_fs
 * Description:	This function iterates through the mnttab and finds all
 *		loopback mount entries that reside within the altroot of
 *		where the BE is mounted, and unmounts it.
 * Parameters:
 *		ud - be_unmount_data_t pointer
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
unmount_shared_fs(be_unmount_data_t *ud)
{
	FILE		*fp = NULL;
	struct mnttab	*table = NULL;
	struct mnttab	ent;
	struct mnttab	*entp = NULL;
	size_t		size = 0;
	int		read_chunk = 32;
	int		i;
	int		altroot_len;
	int		err = 0;

	errno = 0;

	/* Read in the mnttab into a table */
	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		err = errno;
		be_print_err(gettext("unmount_shared_fs: "
		    "failed to open mnttab\n"));
		return (errno_to_be_err(err));
	}

	while (getmntent(fp, &ent) == 0) {
		if (size % read_chunk == 0) {
			table = (struct mnttab *)realloc(table,
			    (size + read_chunk) * sizeof (ent));
		}
		entp = &table[size++];

		/*
		 * Copy over the current mnttab entry into our table,
		 * copying only the fields that we care about.
		 */
		(void) memset(entp, 0, sizeof (*entp));
		if ((entp->mnt_mountp = strdup(ent.mnt_mountp)) == NULL ||
		    (entp->mnt_fstype = strdup(ent.mnt_fstype)) == NULL) {
			be_print_err(gettext("unmount_shared_fs: "
			    "memory allocation failed\n"));
			return (BE_ERR_NOMEM);
		}
	}
	(void) fclose(fp);

	/*
	 * Process the mnttab entries in reverse order, looking for
	 * loopback mount entries mounted under our altroot.
	 */
	altroot_len = strlen(ud->altroot);
	for (i = size; i > 0; i--) {
		entp = &table[i - 1];

		/* If not of type lofs, skip */
		if (strcmp(entp->mnt_fstype, MNTTYPE_LOFS) != 0)
			continue;

		/* If inside the altroot, unmount it */
		if (strncmp(entp->mnt_mountp, ud->altroot, altroot_len) == 0 &&
		    entp->mnt_mountp[altroot_len] == '/') {
			if (umount(entp->mnt_mountp) != 0) {
				err = errno;
				if (err == EBUSY) {
					(void) sleep(1);
					err = errno = 0;
					if (umount(entp->mnt_mountp) != 0)
						err = errno;
				}
				if (err != 0) {
					be_print_err(gettext(
					    "unmount_shared_fs: "
					    "failed to unmount shared file "
					    "system %s: %s\n"),
					    entp->mnt_mountp, strerror(err));
					return (errno_to_be_err(err));
				}
			}
		}
	}

	return (BE_SUCCESS);
}

/*
 * Function:	get_mountpoint_from_vfstab
 * Description:	This function digs into the vfstab in the given altroot,
 *		and searches for an entry for the fs passed in.  If found,
 *		it returns the mountpoint of that fs in the mountpoint
 *		buffer passed in.  If the get_alt_mountpoint flag is set,
 *		it returns the mountpoint with the altroot prepended.
 * Parameters:
 *		altroot - pointer to the alternate root location
 *		fs - pointer to the file system name to look for in the
 *			vfstab in altroot
 *		mountpoint - pointer to buffer of where the mountpoint of
 *			fs will be returned.
 *		size_mp - size of mountpoint argument
 *		get_alt_mountpoint - flag to indicate whether or not the
 *			mountpoint should be populated with the altroot
 *			prepended.
 * Returns:
 *		BE_SUCCESS - Success
 *		1 - Failure
 * Scope:
 *		Private
 */
static int
get_mountpoint_from_vfstab(char *altroot, const char *fs, char *mountpoint,
    size_t size_mp, boolean_t get_alt_mountpoint)
{
	struct vfstab	vp;
	FILE		*fp = NULL;
	char		alt_vfstab[MAXPATHLEN];

	/* Generate path to alternate root vfstab */
	(void) snprintf(alt_vfstab, sizeof (alt_vfstab), "%s/etc/vfstab",
	    altroot);

	/* Open alternate root vfstab */
	if ((fp = fopen(alt_vfstab, "r")) == NULL) {
		be_print_err(gettext("get_mountpoint_from_vfstab: "
		    "failed to open vfstab (%s)\n"), alt_vfstab);
		return (1);
	}

	if (getvfsspec(fp, &vp, (char *)fs) == 0) {
		/*
		 * Found entry for fs, grab its mountpoint.
		 * If the flag to prepend the altroot into the mountpoint
		 * is set, prepend it.  Otherwise, just return the mountpoint.
		 */
		if (get_alt_mountpoint) {
			(void) snprintf(mountpoint, size_mp, "%s%s", altroot,
			    vp.vfs_mountp);
		} else {
			(void) strlcpy(mountpoint, vp.vfs_mountp, size_mp);
		}
	} else {
		(void) fclose(fp);
		return (1);
	}

	(void) fclose(fp);

	return (BE_SUCCESS);
}

/*
 * Function:	fix_mountpoint_callback
 * Description:	This callback function is used to iterate through a BE's
 *		children filesystems to check if its mountpoint is currently
 *		set to be mounted at some specified altroot.  If so, fix it by
 *		removing altroot from the beginning of its mountpoint.
 *
 *		Note - There's no way to tell if a child filesystem's
 *		mountpoint isn't broken, and just happens to begin with
 *		the altroot we're looking for.  In this case, this function
 *		will errantly remove the altroot portion from the beginning
 *		of this filesystem's mountpoint.
 *
 * Parameters:
 *		zhp - zfs_handle_t pointer to filesystem being processed.
 *		data - altroot of where BE is to be mounted.
 * Returns:
 *		0 - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
fix_mountpoint_callback(zfs_handle_t *zhp, void *data)
{
	zprop_source_t	sourcetype;
	char		source[ZFS_MAX_DATASET_NAME_LEN];
	char		mountpoint[MAXPATHLEN];
	char		*zhp_mountpoint = NULL;
	char		*altroot = data;
	int		ret = 0;

	/* Get dataset's mountpoint and source values */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), &sourcetype, source, sizeof (source),
	    B_FALSE) != 0) {
		be_print_err(gettext("fix_mountpoint_callback: "
		    "failed to get mountpoint and sourcetype for %s\n"),
		    zfs_get_name(zhp));
		ZFS_CLOSE(zhp);
		return (BE_ERR_ZFS);
	}

	/*
	 * If the mountpoint is not inherited and the mountpoint is not
	 * 'legacy', this file system potentially needs its mountpoint
	 * fixed.
	 */
	if (!(sourcetype & ZPROP_SRC_INHERITED) &&
	    strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) != 0) {

		/*
		 * Check if this file system's current mountpoint is
		 * under the altroot we're fixing it against.
		 */
		if (strncmp(mountpoint, altroot, strlen(altroot)) == 0 &&
		    mountpoint[strlen(altroot)] == '/') {

			/*
			 * Get this dataset's mountpoint relative to the
			 * altroot.
			 */
			zhp_mountpoint = mountpoint + strlen(altroot);

			/* Fix this dataset's mountpoint value */
			if (zfs_prop_set(zhp,
			    zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
			    zhp_mountpoint)) {
				be_print_err(gettext("fix_mountpoint_callback: "
				    "failed to set mountpoint for %s to "
				    "%s: %s\n"), zfs_get_name(zhp),
				    zhp_mountpoint,
				    libzfs_error_description(g_zfs));
				ret = zfs_err_to_be_err(g_zfs);
				ZFS_CLOSE(zhp);
				return (ret);
			}
		}
	}

	/* Iterate through this dataset's children and fix them */
	if ((ret = zfs_iter_filesystems(zhp, fix_mountpoint_callback,
	    altroot)) != 0) {
		ZFS_CLOSE(zhp);
		return (ret);
	}


	ZFS_CLOSE(zhp);
	return (0);
}

/*
 * Function:	be_mount_root
 * Description:	This function mounts the root dataset of a BE at the
 *		specified altroot.
 * Parameters:
 *		zhp - zfs_handle_t pointer to root dataset of a BE that is
 *		to be mounted at altroot.
 *		altroot - location of where to mount the BE root.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_mount_root(zfs_handle_t *zhp, char *altroot)
{
	char		mountpoint[MAXPATHLEN];

	/* Get mountpoint property of dataset */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), NULL, NULL, 0, B_FALSE) != 0) {
		be_print_err(gettext("be_mount_root: failed to "
		    "get mountpoint property for %s: %s\n"), zfs_get_name(zhp),
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Set the canmount property for the BE's root dataset to 'noauto' just
	 * in case it's been set to 'on'.
	 */
	if (zfs_prop_set(zhp, zfs_prop_to_name(ZFS_PROP_CANMOUNT), "noauto")
	    != 0) {
		be_print_err(gettext("be_mount_root: failed to "
		    "set canmount property to 'noauto' (%s): %s\n"),
		    zfs_get_name(zhp), libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/* Mount the BE's root filesystem */
	if (mount_zfs(zhp, altroot) != 0) {
		be_print_err(gettext("be_mount_root: failed to "
		    "mount dataset %s at %s: %s\n"), zfs_get_name(zhp),
		    altroot, strerror(errno));
		return (BE_ERR_ZFS);
	}

	return (BE_SUCCESS);
}

/*
 * Function:	be_unmount_root
 * Description:	This function unmounts the root dataset of a BE, but before
 *		unmounting, it looks at the BE's vfstab to determine
 *		if the root dataset mountpoint should be left as 'legacy'
 *		or '/'.  If the vfstab contains an entry for this root
 *		dataset with a mountpoint of '/', it sets the mountpoint
 *		property to 'legacy'.
 *
 * Parameters:
 *		zhp - zfs_handle_t pointer of the BE root dataset that
 *		is currently mounted.
 *		ud - be_unmount_data_t pointer providing unmount data
 *		for the given BE root dataset.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_unmount_root(zfs_handle_t *zhp, be_unmount_data_t *ud)
{
	char		mountpoint[MAXPATHLEN];
	boolean_t	is_legacy = B_FALSE;

	/* See if this is a legacy mounted root */
	if (get_mountpoint_from_vfstab(ud->altroot, zfs_get_name(zhp),
	    mountpoint, sizeof (mountpoint), B_FALSE) == BE_SUCCESS &&
	    strcmp(mountpoint, "/") == 0) {
		is_legacy = B_TRUE;
	}

	/* Unmount the dataset */
	if (zfs_unmount(zhp, NULL, ud->force ? MS_FORCE : 0) != 0) {
		be_print_err(gettext("be_unmount_root: failed to "
		    "unmount BE root dataset %s: %s\n"), zfs_get_name(zhp),
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/* Set canmount property for this BE's root filesystem to noauto */
	if (zfs_prop_set(zhp, zfs_prop_to_name(ZFS_PROP_CANMOUNT), "noauto")
	    != 0) {
		be_print_err(gettext("be_unmount_root: failed to "
		    "set canmount property for %s to 'noauto': %s\n"),
		    zfs_get_name(zhp), libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Set mountpoint for BE's root dataset back to '/', or 'legacy'
	 * if its a legacy mounted root.
	 */
	if (zfs_prop_set(zhp, zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
	    is_legacy ? ZFS_MOUNTPOINT_LEGACY : "/") != 0) {
		be_print_err(gettext("be_unmount_root: failed to "
		    "set mountpoint of %s to %s\n"), zfs_get_name(zhp),
		    is_legacy ? ZFS_MOUNTPOINT_LEGACY : "/");
		return (zfs_err_to_be_err(g_zfs));
	}

	return (BE_SUCCESS);
}

/*
 * Function:	fix_mountpoint
 * Description:	This function checks the mountpoint of an unmounted BE to make
 *		sure that it is set to either 'legacy' or '/'.  If it's not,
 *		then we're in a situation where an unmounted BE has some random
 *		mountpoint set for it.  (This could happen if the system was
 *		rebooted while an inactive BE was mounted).  This function
 *		attempts to fix its mountpoints.
 * Parameters:
 *		zhp - zfs_handle_t pointer to root dataset of the BE
 *		whose mountpoint needs to be checked.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
fix_mountpoint(zfs_handle_t *zhp)
{
	be_unmount_data_t	ud = { 0 };
	char	*altroot = NULL;
	char	mountpoint[MAXPATHLEN];
	int	ret = BE_SUCCESS;

	/*
	 * Record what this BE's root dataset mountpoint property is currently
	 * set to.
	 */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), NULL, NULL, 0, B_FALSE) != 0) {
		be_print_err(gettext("fix_mountpoint: failed to get "
		    "mountpoint property of (%s): %s\n"), zfs_get_name(zhp),
		    libzfs_error_description(g_zfs));
		return (BE_ERR_ZFS);
	}

	/*
	 * If the root dataset mountpoint is set to 'legacy' or '/', we're okay.
	 */
	if (strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0 ||
	    strcmp(mountpoint, "/") == 0) {
		return (BE_SUCCESS);
	}

	/*
	 * Iterate through this BE's children datasets and fix
	 * them if they need fixing.
	 */
	if (zfs_iter_filesystems(zhp, fix_mountpoint_callback, mountpoint)
	    != 0) {
		return (BE_ERR_ZFS);
	}

	/*
	 * The process of mounting and unmounting the root file system
	 * will fix its mountpoint to correctly be either 'legacy' or '/'
	 * since be_unmount_root will do the right thing by looking at
	 * its vfstab.
	 */

	/* Generate temporary altroot to mount the root file system */
	if ((ret = be_make_tmp_mountpoint(&altroot)) != BE_SUCCESS) {
		be_print_err(gettext("fix_mountpoint: failed to "
		    "make temporary mountpoint\n"));
		return (ret);
	}

	/* Mount and unmount the root. */
	if ((ret = be_mount_root(zhp, altroot)) != BE_SUCCESS) {
		be_print_err(gettext("fix_mountpoint: failed to "
		    "mount BE root file system\n"));
		goto cleanup;
	}
	ud.altroot = altroot;
	if ((ret = be_unmount_root(zhp, &ud)) != BE_SUCCESS) {
		be_print_err(gettext("fix_mountpoint: failed to "
		    "unmount BE root file system\n"));
		goto cleanup;
	}

cleanup:
	free(altroot);

	return (ret);
}

/*
 * Function:	be_mount_zones
 * Description:	This function finds all supported non-global zones in the
 *		given global BE and mounts them with respect to where the
 *		global BE is currently mounted.  The global BE datasets
 *		(including its shared datasets) are expected to already
 *		be mounted.
 * Parameters:
 *		be_zhp - zfs_handle_t pointer to the root dataset of the
 *			global BE.
 *		md - be_mount_data_t pointer to data for global BE.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_mount_zones(zfs_handle_t *be_zhp, be_mount_data_t *md)
{
	zoneBrandList_t	*brands = NULL;
	zoneList_t	zlst = NULL;
	char		*zonename = NULL;
	char		*zonepath = NULL;
	char		*zonepath_ds = NULL;
	int		k;
	int		ret = BE_SUCCESS;

	z_set_zone_root(md->altroot);

	if ((brands = be_get_supported_brandlist()) == NULL) {
		be_print_err(gettext("be_mount_zones: "
		    "no supported brands\n"));
		return (BE_SUCCESS);
	}

	zlst = z_get_nonglobal_zone_list_by_brand(brands);
	if (zlst == NULL) {
		z_free_brand_list(brands);
		return (BE_SUCCESS);
	}

	for (k = 0; (zonename = z_zlist_get_zonename(zlst, k)) != NULL; k++) {
		if (z_zlist_get_current_state(zlst, k) ==
		    ZONE_STATE_INSTALLED) {
			zonepath = z_zlist_get_zonepath(zlst, k);

			/*
			 * Get the dataset of this zonepath in current BE.
			 * If its not a dataset, skip it.
			 */
			if ((zonepath_ds = be_get_ds_from_dir(zonepath))
			    == NULL)
				continue;

			/*
			 * Check if this zone is supported based on
			 * the dataset of its zonepath
			 */
			if (!be_zone_supported(zonepath_ds)) {
				free(zonepath_ds);
				zonepath_ds = NULL;
				continue;
			}

			/*
			 * if BE's shared file systems are already mounted,
			 * zone path dataset would have already been lofs
			 * mounted under altroot. Otherwise, we need to do
			 * it here.
			 */
			if (!md->shared_fs) {
				ret = loopback_mount_zonepath(zonepath, md);
				if (ret != BE_SUCCESS)
					goto done;
			}


			/* Mount this zone */
			ret = be_mount_one_zone(be_zhp, md, zonename,
			    zonepath, zonepath_ds);

			free(zonepath_ds);
			zonepath_ds = NULL;

			if (ret != BE_SUCCESS) {
				be_print_err(gettext("be_mount_zones: "
				    "failed to mount zone %s under "
				    "altroot %s\n"), zonename, md->altroot);
				goto done;
			}
		}
	}

done:
	z_free_brand_list(brands);
	z_free_zone_list(zlst);
	/*
	 * libinstzones caches mnttab and uses cached version for resolving lofs
	 * mounts when we call z_resolve_lofs. It creates the cached version
	 * when the first call to z_resolve_lofs happens. So, library's cached
	 * mnttab doesn't contain entries for lofs mounts created in the above
	 * loop. Because of this, subsequent calls to z_resolve_lofs would fail
	 * to resolve these lofs mounts. So, here we destroy library's cached
	 * mnttab to force its recreation when the next call to z_resolve_lofs
	 * happens.
	 */
	z_destroyMountTable();
	return (ret);
}

/*
 * Function:	be_unmount_zones
 * Description:	This function finds all supported non-global zones in the
 *		given mounted global BE and unmounts them.
 * Parameters:
 *		ud - unmount_data_t pointer data for the global BE.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_unmount_zones(be_unmount_data_t *ud)
{
	zoneBrandList_t		*brands = NULL;
	zoneList_t		zlst = NULL;
	char			*zonename = NULL;
	char			*zonepath = NULL;
	char			alt_zonepath[MAXPATHLEN];
	char			*zonepath_ds = NULL;
	int			k;
	int			ret = BE_SUCCESS;

	z_set_zone_root(ud->altroot);

	if ((brands = be_get_supported_brandlist()) == NULL) {
		be_print_err(gettext("be_unmount_zones: "
		    "no supported brands\n"));
		return (BE_SUCCESS);
	}

	zlst = z_get_nonglobal_zone_list_by_brand(brands);
	if (zlst == NULL) {
		z_free_brand_list(brands);
		return (BE_SUCCESS);
	}

	for (k = 0; (zonename = z_zlist_get_zonename(zlst, k)) != NULL; k++) {
		if (z_zlist_get_current_state(zlst, k) ==
		    ZONE_STATE_INSTALLED) {
			zonepath = z_zlist_get_zonepath(zlst, k);

			/* Build zone's zonepath wrt the global BE altroot */
			(void) snprintf(alt_zonepath, sizeof (alt_zonepath),
			    "%s%s", ud->altroot, zonepath);

			/*
			 * Get the dataset of this zonepath.  If its not
			 * a dataset, skip it.
			 */
			if ((zonepath_ds = be_get_ds_from_dir(alt_zonepath))
			    == NULL)
				continue;

			/*
			 * Check if this zone is supported based on the
			 * dataset of its zonepath.
			 */
			if (!be_zone_supported(zonepath_ds)) {
				free(zonepath_ds);
				zonepath_ds = NULL;
				continue;
			}

			/* Unmount this zone */
			ret = be_unmount_one_zone(ud, zonename, zonepath,
			    zonepath_ds);

			free(zonepath_ds);
			zonepath_ds = NULL;

			if (ret != BE_SUCCESS) {
				be_print_err(gettext("be_unmount_zones:"
				    " failed to unmount zone %s from "
				    "altroot %s\n"), zonename, ud->altroot);
				goto done;
			}
		}
	}

done:
	z_free_brand_list(brands);
	z_free_zone_list(zlst);
	return (ret);
}

/*
 * Function:	be_mount_one_zone
 * Description:	This function is called to mount one zone for a given
 *		global BE.
 * Parameters:
 *		be_zhp - zfs_handle_t pointer to the root dataset of the
 *			global BE
 *		md - be_mount_data_t pointer to data for global BE
 *		zonename - name of zone to mount
 *		zonepath - zonepath of zone to mount
 *		zonepath_ds - dataset for the zonepath
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_mount_one_zone(zfs_handle_t *be_zhp, be_mount_data_t *md, char *zonename,
    char *zonepath, char *zonepath_ds)
{
	be_mount_data_t	zone_md = { 0 };
	zfs_handle_t	*zone_zhp = NULL;
	char		zone_altroot[MAXPATHLEN];
	char		zoneroot[MAXPATHLEN];
	char		zoneroot_ds[MAXPATHLEN];
	int		ret = BE_SUCCESS;

	/* Find the active zone root dataset for this zone for this BE */
	if ((ret = be_find_active_zone_root(be_zhp, zonepath_ds, zoneroot_ds,
	    sizeof (zoneroot_ds))) == BE_ERR_ZONE_NO_ACTIVE_ROOT) {
		be_print_err(gettext("be_mount_one_zone: did not "
		    "find active zone root for zone %s, skipping ...\n"),
		    zonename);
		return (BE_SUCCESS);
	} else if (ret != BE_SUCCESS) {
		be_print_err(gettext("be_mount_one_zone: failed to "
		    "find active zone root for zone %s\n"), zonename);
		return (ret);
	}

	/* Get handle to active zoneroot dataset */
	if ((zone_zhp = zfs_open(g_zfs, zoneroot_ds, ZFS_TYPE_FILESYSTEM))
	    == NULL) {
		be_print_err(gettext("be_mount_one_zone: failed to "
		    "open zone root dataset (%s): %s\n"), zoneroot_ds,
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/* Generate string for zone's altroot path */
	be_make_zoneroot(zonepath, zoneroot, sizeof (zoneroot));
	(void) strlcpy(zone_altroot, md->altroot, sizeof (zone_altroot));
	(void) strlcat(zone_altroot, zoneroot, sizeof (zone_altroot));

	/* Build mount_data for the zone */
	zone_md.altroot = zone_altroot;
	zone_md.shared_fs = md->shared_fs;
	zone_md.shared_rw = md->shared_rw;

	/* Mount the zone's root file system */
	if ((ret = be_mount_zone_root(zone_zhp, &zone_md)) != BE_SUCCESS) {
		be_print_err(gettext("be_mount_one_zone: failed to "
		    "mount zone root file system at %s\n"), zone_altroot);
		goto done;
	}

	/* Iterate through zone's children filesystems */
	if ((ret = zfs_iter_filesystems(zone_zhp, be_mount_callback,
	    zone_altroot)) != 0) {
		be_print_err(gettext("be_mount_one_zone: failed to "
		    "mount zone subordinate file systems at %s\n"),
		    zone_altroot);
		goto done;
	}

	/* TODO: Mount all shared file systems for this zone */

done:
	ZFS_CLOSE(zone_zhp);
	return (ret);
}

/*
 * Function:	be_unmount_one_zone
 * Description:	This function unmount one zone for a give global BE.
 * Parameters:
 *		ud - be_unmount_data_t pointer to data for global BE
 *		zonename - name of zone to unmount
 *		zonepath - zonepath of the zone to unmount
 *		zonepath_ds - dataset for the zonepath
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_unmount_one_zone(be_unmount_data_t *ud, char *zonename, char *zonepath,
    char *zonepath_ds)
{
	be_unmount_data_t	zone_ud = { 0 };
	zfs_handle_t	*zone_zhp = NULL;
	char		zone_altroot[MAXPATHLEN];
	char		zoneroot[MAXPATHLEN];
	char		zoneroot_ds[MAXPATHLEN];
	int		ret = BE_SUCCESS;

	/* Generate string for zone's alternate root path */
	be_make_zoneroot(zonepath, zoneroot, sizeof (zoneroot));
	(void) strlcpy(zone_altroot, ud->altroot, sizeof (zone_altroot));
	(void) strlcat(zone_altroot, zoneroot, sizeof (zone_altroot));

	/* Build be_unmount_data for zone */
	zone_ud.altroot = zone_altroot;
	zone_ud.force = ud->force;

	/* Find the mounted zone root dataset for this zone for this BE */
	if ((ret = be_find_mounted_zone_root(zone_altroot, zonepath_ds,
	    zoneroot_ds, sizeof (zoneroot_ds))) == BE_ERR_NO_MOUNTED_ZONE) {
		be_print_err(gettext("be_unmount_one_zone: did not "
		    "find any zone root mounted for zone %s\n"), zonename);
		return (BE_SUCCESS);
	} else if (ret != BE_SUCCESS) {
		be_print_err(gettext("be_unmount_one_zone: failed to "
		    "find mounted zone root for zone %s\n"), zonename);
		return (ret);
	}

	/* Get handle to zoneroot dataset mounted for this BE */
	if ((zone_zhp = zfs_open(g_zfs, zoneroot_ds, ZFS_TYPE_FILESYSTEM))
	    == NULL) {
		be_print_err(gettext("be_unmount_one_zone: failed to "
		    "open mounted zone root dataset (%s): %s\n"), zoneroot_ds,
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/* TODO: Unmount all shared file systems for this zone */

	/* Iterate through zone's children filesystems and unmount them */
	if ((ret = zfs_iter_filesystems(zone_zhp, be_unmount_callback,
	    &zone_ud)) != 0) {
		be_print_err(gettext("be_unmount_one_zone: failed to "
		    "unmount zone subordinate file systems at %s\n"),
		    zone_altroot);
		goto done;
	}

	/* Unmount the zone's root filesystem */
	if ((ret = be_unmount_zone_root(zone_zhp, &zone_ud)) != BE_SUCCESS) {
		be_print_err(gettext("be_unmount_one_zone: failed to "
		    "unmount zone root file system at %s\n"), zone_altroot);
		goto done;
	}

done:
	ZFS_CLOSE(zone_zhp);
	return (ret);
}

/*
 * Function:	be_get_ds_from_dir_callback
 * Description:	This is a callback function used to iterate all datasets
 *		to find the one that is currently mounted at the directory
 *		being searched for.  If matched, the name of the dataset is
 *		returned in heap storage, so the caller is responsible for
 *		freeing it.
 * Parameters:
 *		zhp - zfs_handle_t pointer to current dataset being processed.
 *		data - dir_data_t pointer providing name of directory being
 *			searched for.
 * Returns:
 *		1 - This dataset is mounted at directory being searched for.
 *		0 - This dataset is not mounted at directory being searched for.
 * Scope:
 *		Private
 */
static int
be_get_ds_from_dir_callback(zfs_handle_t *zhp, void *data)
{
	dir_data_t	*dd = data;
	char		*mp = NULL;
	int		zret = 0;

	if (zfs_get_type(zhp) != ZFS_TYPE_FILESYSTEM) {
		ZFS_CLOSE(zhp);
		return (0);
	}

	if (zfs_is_mounted(zhp, &mp) && mp != NULL &&
	    strcmp(mp, dd->dir) == 0) {
		if ((dd->ds = strdup(zfs_get_name(zhp))) == NULL) {
			be_print_err(gettext("be_get_ds_from_dir_callback: "
			    "memory allocation failed\n"));
			ZFS_CLOSE(zhp);
			return (0);
		}
		ZFS_CLOSE(zhp);
		return (1);
	}

	zret = zfs_iter_filesystems(zhp, be_get_ds_from_dir_callback, dd);

	ZFS_CLOSE(zhp);

	return (zret);
}

/*
 * Function:    mount_zfs
 * Description: This is a function to mount zfs filesystem to alternative
 *              root without changing zfs mountpoint property. Logic is
 *              similar to zfs_mount.
 * Parameters:
 *              zhp - zfs_handle_t pointer to current dataset being processed.
 *              altroot - char pointer to current alternative root.
 * Returns:
 *              BE_SUCCESS - Success
 *              be_errno_t - Failure
 * Scope:
 *              Private
 */
static int
mount_zfs(zfs_handle_t *zhp, char *altroot)
{
	int	flags = 0;
	char	mountpoint[MAXPATHLEN];
	char	real_mountpoint[MAXPATHLEN];
	char	source[MAXNAMELEN];
	char	optstr[MAX_MNTOPT_STR];
	zprop_source_t	sourcetype;
	struct stat	buf;

	optstr[0] = '\0';

	/* Get dataset's mountpoint and source values */
	if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), &sourcetype, source, sizeof (source),
	    B_FALSE) != 0) {
		be_print_err(gettext("mount_zfs: "
		    "failed to get mountpoint and sourcetype for %s\n"),
		    zfs_get_name(zhp));
		ZFS_CLOSE(zhp);
		return (BE_ERR_ZFS);
	}

	if (strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0 ||
	    strcmp(mountpoint, "/") == 0) {
	/*
	 * We are called  only from be_mount_root or be_mount_callback
	 * when mountpoint != LEGACY
	 */
		mountpoint[0] = '\0';
	}

	(void) snprintf(real_mountpoint, MAXPATHLEN, "%s%s", altroot,
	    mountpoint);

	if (zpool_get_prop_int(zfs_get_pool_handle(zhp), ZPOOL_PROP_READONLY,
	    NULL))
		flags |= MS_RDONLY;

	/* Create the directory if it doesn't already exist */
	if (lstat(real_mountpoint, &buf) != 0) {
		if (mkdirp(real_mountpoint, 0755) != 0) {
			be_print_err(gettext("mount_zfs: "
			    "failed to create mountpoint for %s\n"),
			    zfs_get_name(zhp));
			ZFS_CLOSE(zhp);
			return (BE_ERR_ZFS);
		}
	}

	if (mount(zfs_get_name(zhp), real_mountpoint, MS_OPTIONSTR | flags,
	    MNTTYPE_ZFS, NULL, 0, optstr, sizeof (optstr))) {
		be_print_err(gettext("mount_zfs: failed to "
		    "mount dataset %s at %s\n"), zfs_get_name(zhp),
		    real_mountpoint);
		return (BE_ERR_ZFS);
	}

	return (BE_SUCCESS);
}
