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
 */

/*
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#include <assert.h>
#include <libintl.h>
#include <libnvpair.h>
#include <libzfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/mnttab.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/efi_partition.h>

#include <libbe.h>
#include <libbe_priv.h>

char	*mnttab = MNTTAB;

/*
 * Private function prototypes
 */
static int set_bootfs(char *boot_rpool, char *be_root_ds);
static int set_canmount(be_node_list_t *, char *);
static boolean_t be_do_install_mbr(char *, nvlist_t *);
static int be_do_installboot_helper(zpool_handle_t *, nvlist_t *, char *,
    char *);
static int be_do_installboot(be_transaction_data_t *);
static int be_get_grub_vers(be_transaction_data_t *, char **, char **);
static int get_ver_from_capfile(char *, char **);
static int be_promote_zone_ds(char *, char *);
static int be_promote_ds_callback(zfs_handle_t *, void *);

/* ******************************************************************** */
/*			Public Functions				*/
/* ******************************************************************** */

/*
 * Function:	be_activate
 * Description:	Calls _be_activate which activates the BE named in the
 *		attributes passed in through be_attrs. The process of
 *		activation sets the bootfs property of the root pool, resets
 *		the canmount property to noauto, and sets the default in the
 *		grub menu to the entry corresponding to the entry for the named
 *		BE.
 * Parameters:
 *		be_attrs - pointer to nvlist_t of attributes being passed in.
 *			The follow attribute values are used by this function:
 *
 *			BE_ATTR_ORIG_BE_NAME		*required
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Public
 */
int
be_activate(nvlist_t *be_attrs)
{
	int	ret = BE_SUCCESS;
	char	*be_name = NULL;

	/* Initialize libzfs handle */
	if (!be_zfs_init())
		return (BE_ERR_INIT);

	/* Get the BE name to activate */
	if (nvlist_lookup_string(be_attrs, BE_ATTR_ORIG_BE_NAME, &be_name)
	    != 0) {
		be_print_err(gettext("be_activate: failed to "
		    "lookup BE_ATTR_ORIG_BE_NAME attribute\n"));
		be_zfs_fini();
		return (BE_ERR_INVAL);
	}

	/* Validate BE name */
	if (!be_valid_be_name(be_name)) {
		be_print_err(gettext("be_activate: invalid BE name %s\n"),
		    be_name);
		be_zfs_fini();
		return (BE_ERR_INVAL);
	}

	ret = _be_activate(be_name);

	be_zfs_fini();

	return (ret);
}

/* ******************************************************************** */
/*			Semi Private Functions				*/
/* ******************************************************************** */

/*
 * Function:	_be_activate
 * Description:	This does the actual work described in be_activate.
 * Parameters:
 *		be_name - pointer to the name of BE to activate.
 *
 * Return:
 *		BE_SUCCESS - Success
 *		be_errnot_t - Failure
 * Scope:
 *		Public
 */
int
_be_activate(char *be_name)
{
	be_transaction_data_t cb = { 0 };
	zfs_handle_t	*zhp = NULL;
	char		root_ds[MAXPATHLEN];
	char		active_ds[MAXPATHLEN];
	be_node_list_t	*be_nodes = NULL;
	uuid_t		uu = {0};
	int		entry, ret = BE_SUCCESS;
	int		zret = 0;

	/*
	 * TODO: The BE needs to be validated to make sure that it is actually
	 * a bootable BE.
	 */

	if (be_name == NULL)
		return (BE_ERR_INVAL);

	/* Set obe_name to be_name in the cb structure */
	cb.obe_name = be_name;

	/* find which zpool the be is in */
	if ((zret = zpool_iter(g_zfs, be_find_zpool_callback, &cb)) == 0) {
		be_print_err(gettext("be_activate: failed to "
		    "find zpool for BE (%s)\n"), cb.obe_name);
		return (BE_ERR_BE_NOENT);
	} else if (zret < 0) {
		be_print_err(gettext("be_activate: "
		    "zpool_iter failed: %s\n"),
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		return (ret);
	}

	be_make_root_ds(cb.obe_zpool, cb.obe_name, root_ds, sizeof (root_ds));
	cb.obe_root_ds = strdup(root_ds);

	if (getzoneid() == GLOBAL_ZONEID) {
		if ((ret = be_do_installboot(&cb)) != BE_SUCCESS)
			return (ret);

		if (!be_has_menu_entry(root_ds, cb.obe_zpool, &entry)) {
			if ((ret = be_append_menu(cb.obe_name, cb.obe_zpool,
			    NULL, NULL, NULL)) != BE_SUCCESS) {
				be_print_err(gettext("be_activate: Failed to "
				    "add BE (%s) to the menu\n"),
				    cb.obe_name);
				goto done;
			}
		}
		if (be_has_grub()) {
			if ((ret = be_change_grub_default(cb.obe_name,
			    cb.obe_zpool)) != BE_SUCCESS) {
				be_print_err(gettext("be_activate: failed to "
				    "change the default entry in menu.lst\n"));
				goto done;
			}
		}
	}

	if ((ret = _be_list(cb.obe_name, &be_nodes)) != BE_SUCCESS) {
		return (ret);
	}

	if ((ret = set_canmount(be_nodes, "noauto")) != BE_SUCCESS) {
		be_print_err(gettext("be_activate: failed to set "
		    "canmount dataset property\n"));
		goto done;
	}

	if (getzoneid() == GLOBAL_ZONEID) {
		if ((ret = set_bootfs(be_nodes->be_rpool,
		    root_ds)) != BE_SUCCESS) {
			be_print_err(gettext("be_activate: failed to set "
			    "bootfs pool property for %s\n"), root_ds);
			goto done;
		}
	}

	if ((zhp = zfs_open(g_zfs, root_ds, ZFS_TYPE_FILESYSTEM)) != NULL) {
		/*
		 * We don't need to close the zfs handle at this
		 * point because The callback funtion
		 * be_promote_ds_callback() will close it for us.
		 */
		if (be_promote_ds_callback(zhp, NULL) != 0) {
			be_print_err(gettext("be_activate: "
			    "failed to activate the "
			    "datasets for %s: %s\n"),
			    root_ds,
			    libzfs_error_description(g_zfs));
			ret = BE_ERR_PROMOTE;
			goto done;
		}
	} else {
		be_print_err(gettext("be_activate: failed to open "
		    "dataset (%s): %s\n"), root_ds,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		goto done;
	}

	if (getzoneid() == GLOBAL_ZONEID &&
	    be_get_uuid(cb.obe_root_ds, &uu) == BE_SUCCESS &&
	    (ret = be_promote_zone_ds(cb.obe_name, cb.obe_root_ds))
	    != BE_SUCCESS) {
		be_print_err(gettext("be_activate: failed to promote "
		    "the active zonepath datasets for zones in BE %s\n"),
		    cb.obe_name);
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		if (!be_zone_compare_uuids(root_ds)) {
			be_print_err(gettext("be_activate: activating zone "
			    "root dataset from non-active global BE is not "
			    "supported\n"));
			ret = BE_ERR_NOTSUP;
			goto done;
		}
		if ((zhp = zfs_open(g_zfs, root_ds,
		    ZFS_TYPE_FILESYSTEM)) == NULL) {
			be_print_err(gettext("be_activate: failed to open "
			    "dataset (%s): %s\n"), root_ds,
			    libzfs_error_description(g_zfs));
			ret = zfs_err_to_be_err(g_zfs);
			goto done;
		}
		/* Find current active zone root dataset */
		if ((ret = be_find_active_zone_root(zhp, cb.obe_zpool,
		    active_ds, sizeof (active_ds))) != BE_SUCCESS) {
			be_print_err(gettext("be_activate: failed to find "
			    "active zone root dataset\n"));
			ZFS_CLOSE(zhp);
			goto done;
		}
		/* Do nothing if requested BE is already active */
		if (strcmp(root_ds, active_ds) == 0) {
			ret = BE_SUCCESS;
			ZFS_CLOSE(zhp);
			goto done;
		}

		/* Set active property for BE */
		if (zfs_prop_set(zhp, BE_ZONE_ACTIVE_PROPERTY, "on") != 0) {
			be_print_err(gettext("be_activate: failed to set "
			    "active property (%s): %s\n"), root_ds,
			    libzfs_error_description(g_zfs));
			ret = zfs_err_to_be_err(g_zfs);
			ZFS_CLOSE(zhp);
			goto done;
		}
		ZFS_CLOSE(zhp);

		/* Unset active property for old active root dataset */
		if ((zhp = zfs_open(g_zfs, active_ds,
		    ZFS_TYPE_FILESYSTEM)) == NULL) {
			be_print_err(gettext("be_activate: failed to open "
			    "dataset (%s): %s\n"), active_ds,
			    libzfs_error_description(g_zfs));
			ret = zfs_err_to_be_err(g_zfs);
			goto done;
		}
		if (zfs_prop_set(zhp, BE_ZONE_ACTIVE_PROPERTY, "off") != 0) {
			be_print_err(gettext("be_activate: failed to unset "
			    "active property (%s): %s\n"), active_ds,
			    libzfs_error_description(g_zfs));
			ret = zfs_err_to_be_err(g_zfs);
			ZFS_CLOSE(zhp);
			goto done;
		}
		ZFS_CLOSE(zhp);
	}
done:
	be_free_list(be_nodes);
	return (ret);
}

/*
 * Function:	be_activate_current_be
 * Description:	Set the currently "active" BE to be "active on boot"
 * Paramters:
 *		none
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errnot_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_activate_current_be(void)
{
	int ret = BE_SUCCESS;
	be_transaction_data_t bt = { 0 };

	if ((ret = be_find_current_be(&bt)) != BE_SUCCESS) {
		return (ret);
	}

	if ((ret = _be_activate(bt.obe_name)) != BE_SUCCESS) {
		be_print_err(gettext("be_activate_current_be: failed to "
		    "activate %s\n"), bt.obe_name);
		return (ret);
	}

	return (BE_SUCCESS);
}

/*
 * Function:	be_is_active_on_boot
 * Description:	Checks if the BE name passed in has the "active on boot"
 *		property set to B_TRUE.
 * Paramters:
 *		be_name - the name of the BE to check
 * Returns:
 *		B_TRUE - if active on boot.
 *		B_FALSE - if not active on boot.
 * Scope:
 *		Semi-private (library wide use only)
 */
boolean_t
be_is_active_on_boot(char *be_name)
{
	be_node_list_t *be_node = NULL;

	if (be_name == NULL) {
		be_print_err(gettext("be_is_active_on_boot: "
		    "be_name must not be NULL\n"));
		return (B_FALSE);
	}

	if (_be_list(be_name, &be_node) != BE_SUCCESS) {
		return (B_FALSE);
	}

	if (be_node == NULL) {
		return (B_FALSE);
	}

	if (be_node->be_active_on_boot) {
		be_free_list(be_node);
		return (B_TRUE);
	} else {
		be_free_list(be_node);
		return (B_FALSE);
	}
}

/* ******************************************************************** */
/*			Private Functions				*/
/* ******************************************************************** */

/*
 * Function:	set_bootfs
 * Description:	Sets the bootfs property on the boot pool to be the
 *		root dataset of the activated BE.
 * Parameters:
 *		boot_pool - The pool we're setting bootfs in.
 *		be_root_ds - The main dataset for the BE.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
set_bootfs(char *boot_rpool, char *be_root_ds)
{
	zpool_handle_t *zhp;
	int err = BE_SUCCESS;

	if ((zhp = zpool_open(g_zfs, boot_rpool)) == NULL) {
		be_print_err(gettext("set_bootfs: failed to open pool "
		    "(%s): %s\n"), boot_rpool, libzfs_error_description(g_zfs));
		err = zfs_err_to_be_err(g_zfs);
		return (err);
	}

	err = zpool_set_prop(zhp, "bootfs", be_root_ds);
	if (err) {
		be_print_err(gettext("set_bootfs: failed to set "
		    "bootfs property for pool %s: %s\n"), boot_rpool,
		    libzfs_error_description(g_zfs));
		err = zfs_err_to_be_err(g_zfs);
		zpool_close(zhp);
		return (err);
	}

	zpool_close(zhp);
	return (BE_SUCCESS);
}

/*
 * Function:	set_canmount
 * Description:	Sets the canmount property on the datasets of the
 *		activated BE.
 * Parameters:
 *		be_nodes - The be_node_t returned from be_list
 *		value - The value of canmount we setting, on|off|noauto.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
set_canmount(be_node_list_t *be_nodes, char *value)
{
	char		ds_path[MAXPATHLEN];
	zfs_handle_t	*zhp = NULL;
	be_node_list_t	*list = be_nodes;
	int		err = BE_SUCCESS;

	while (list != NULL) {
		be_dataset_list_t *datasets = list->be_node_datasets;

		be_make_root_ds(list->be_rpool, list->be_node_name, ds_path,
		    sizeof (ds_path));

		if ((zhp = zfs_open(g_zfs, ds_path, ZFS_TYPE_DATASET)) ==
		    NULL) {
			be_print_err(gettext("set_canmount: failed to open "
			    "dataset (%s): %s\n"), ds_path,
			    libzfs_error_description(g_zfs));
			err = zfs_err_to_be_err(g_zfs);
			return (err);
		}
		if (zfs_prop_get_int(zhp, ZFS_PROP_MOUNTED)) {
			/*
			 * it's already mounted so we can't change the
			 * canmount property anyway.
			 */
			err = BE_SUCCESS;
		} else {
			err = zfs_prop_set(zhp,
			    zfs_prop_to_name(ZFS_PROP_CANMOUNT), value);
			if (err) {
				ZFS_CLOSE(zhp);
				be_print_err(gettext("set_canmount: failed to "
				    "set dataset property (%s): %s\n"),
				    ds_path, libzfs_error_description(g_zfs));
				err = zfs_err_to_be_err(g_zfs);
				return (err);
			}
		}
		ZFS_CLOSE(zhp);

		while (datasets != NULL) {
			be_make_root_ds(list->be_rpool,
			    datasets->be_dataset_name, ds_path,
			    sizeof (ds_path));

			if ((zhp = zfs_open(g_zfs, ds_path, ZFS_TYPE_DATASET))
			    == NULL) {
				be_print_err(gettext("set_canmount: failed to "
				    "open dataset %s: %s\n"), ds_path,
				    libzfs_error_description(g_zfs));
				err = zfs_err_to_be_err(g_zfs);
				return (err);
			}
			if (zfs_prop_get_int(zhp, ZFS_PROP_MOUNTED)) {
				/*
				 * it's already mounted so we can't change the
				 * canmount property anyway.
				 */
				err = BE_SUCCESS;
				ZFS_CLOSE(zhp);
				break;
			}
			err = zfs_prop_set(zhp,
			    zfs_prop_to_name(ZFS_PROP_CANMOUNT), value);
			if (err) {
				ZFS_CLOSE(zhp);
				be_print_err(gettext("set_canmount: "
				    "Failed to set property value %s "
				    "for dataset %s: %s\n"), value, ds_path,
				    libzfs_error_description(g_zfs));
				err = zfs_err_to_be_err(g_zfs);
				return (err);
			}
			ZFS_CLOSE(zhp);
			datasets = datasets->be_next_dataset;
		}
		list = list->be_next_node;
	}
	return (err);
}

/*
 * Function:	be_get_grub_vers
 * Description:	Gets the grub version number from /boot/grub/capability. If
 *              capability file doesn't exist NULL is returned.
 * Parameters:
 *              bt - The transaction data for the BE we're getting the grub
 *                   version for.
 *              cur_vers - used to return the current version of grub from
 *                         the root pool.
 *              new_vers - used to return the grub version of the BE we're
 *                         activating.
 * Return:
 *              BE_SUCCESS - Success
 *              be_errno_t - Failed to find version
 * Scope:
 *		Private
 */
static int
be_get_grub_vers(be_transaction_data_t *bt, char **cur_vers, char **new_vers)
{
	zfs_handle_t	*zhp = NULL;
	zfs_handle_t	*pool_zhp = NULL;
	int ret = BE_SUCCESS;
	char cap_file[MAXPATHLEN];
	char *temp_mntpnt = NULL;
	char *zpool_mntpt = NULL;
	char *ptmp_mntpnt = NULL;
	char *orig_mntpnt = NULL;
	boolean_t be_mounted = B_FALSE;
	boolean_t pool_mounted = B_FALSE;

	if (!be_has_grub()) {
		be_print_err(gettext("be_get_grub_vers: Not supported on "
		    "this architecture\n"));
		return (BE_ERR_NOTSUP);
	}

	if (bt == NULL || bt->obe_name == NULL || bt->obe_zpool == NULL ||
	    bt->obe_root_ds == NULL) {
		be_print_err(gettext("be_get_grub_vers: Invalid BE\n"));
		return (BE_ERR_INVAL);
	}

	if ((pool_zhp = zfs_open(g_zfs, bt->obe_zpool, ZFS_TYPE_FILESYSTEM)) ==
	    NULL) {
		be_print_err(gettext("be_get_grub_vers: zfs_open failed: %s\n"),
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Check to see if the pool's dataset is mounted. If it isn't we'll
	 * attempt to mount it.
	 */
	if ((ret = be_mount_pool(pool_zhp, &ptmp_mntpnt,
	    &orig_mntpnt, &pool_mounted)) != BE_SUCCESS) {
		be_print_err(gettext("be_get_grub_vers: pool dataset "
		    "(%s) could not be mounted\n"), bt->obe_zpool);
		ZFS_CLOSE(pool_zhp);
		return (ret);
	}

	/*
	 * Get the mountpoint for the root pool dataset.
	 */
	if (!zfs_is_mounted(pool_zhp, &zpool_mntpt)) {
		be_print_err(gettext("be_get_grub_vers: pool "
		    "dataset (%s) is not mounted. Can't read the "
		    "grub capability file.\n"), bt->obe_zpool);
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	/*
	 * get the version of the most recent grub update.
	 */
	(void) snprintf(cap_file, sizeof (cap_file), "%s%s",
	    zpool_mntpt, BE_CAP_FILE);
	free(zpool_mntpt);
	zpool_mntpt = NULL;

	if ((ret = get_ver_from_capfile(cap_file, cur_vers)) != BE_SUCCESS)
		goto cleanup;

	if ((zhp = zfs_open(g_zfs, bt->obe_root_ds, ZFS_TYPE_FILESYSTEM)) ==
	    NULL) {
		be_print_err(gettext("be_get_grub_vers: failed to "
		    "open BE root dataset (%s): %s\n"), bt->obe_root_ds,
		    libzfs_error_description(g_zfs));
		free(cur_vers);
		ret = zfs_err_to_be_err(g_zfs);
		goto cleanup;
	}
	if (!zfs_is_mounted(zhp, &temp_mntpnt)) {
		if ((ret = _be_mount(bt->obe_name, &temp_mntpnt,
		    BE_MOUNT_FLAG_NO_ZONES)) != BE_SUCCESS) {
			be_print_err(gettext("be_get_grub_vers: failed to "
			    "mount BE (%s)\n"), bt->obe_name);
			free(*cur_vers);
			*cur_vers = NULL;
			ZFS_CLOSE(zhp);
			goto cleanup;
		}
		be_mounted = B_TRUE;
	}
	ZFS_CLOSE(zhp);

	/*
	 * Now get the grub version for the BE being activated.
	 */
	(void) snprintf(cap_file, sizeof (cap_file), "%s%s", temp_mntpnt,
	    BE_CAP_FILE);
	ret = get_ver_from_capfile(cap_file, new_vers);
	if (ret != BE_SUCCESS) {
		free(*cur_vers);
		*cur_vers = NULL;
	}
	if (be_mounted)
		(void) _be_unmount(bt->obe_name, 0);

cleanup:
	if (pool_mounted) {
		int iret = BE_SUCCESS;
		iret = be_unmount_pool(pool_zhp, ptmp_mntpnt, orig_mntpnt);
		if (ret == BE_SUCCESS)
			ret = iret;
		free(orig_mntpnt);
		free(ptmp_mntpnt);
	}
	ZFS_CLOSE(pool_zhp);

	free(temp_mntpnt);
	return (ret);
}

/*
 * Function:	get_ver_from_capfile
 * Description: Parses the capability file passed in looking for the VERSION
 *              line. If found the version is returned in vers, if not then
 *              NULL is returned in vers.
 *
 * Parameters:
 *              file - the path to the capability file we want to parse.
 *              vers - the version string that will be passed back.
 * Return:
 *              BE_SUCCESS - Success
 *              be_errno_t - Failed to find version
 * Scope:
 *		Private
 */
static int
get_ver_from_capfile(char *file, char **vers)
{
	FILE *fp = NULL;
	char line[BUFSIZ];
	char *last = NULL;
	int err = BE_SUCCESS;
	errno = 0;

	if (!be_has_grub()) {
		be_print_err(gettext("get_ver_from_capfile: Not supported "
		    "on this architecture\n"));
		return (BE_ERR_NOTSUP);
	}

	/*
	 * Set version string to NULL; the only case this shouldn't be set
	 * to be NULL is when we've actually found a version in the capability
	 * file, which is set below.
	 */
	*vers = NULL;

	/*
	 * If the capability file doesn't exist, we're returning success
	 * because on older releases, the capability file did not exist
	 * so this is a valid scenario.
	 */
	if (access(file, F_OK) == 0) {
		if ((fp = fopen(file, "r")) == NULL) {
			err = errno;
			be_print_err(gettext("get_ver_from_capfile: failed to "
			    "open file %s with error %s\n"), file,
			    strerror(err));
			err = errno_to_be_err(err);
			return (err);
		}

		while (fgets(line, BUFSIZ, fp)) {
			char *tok = strtok_r(line, "=", &last);

			if (tok == NULL || tok[0] == '#') {
				continue;
			} else if (strcmp(tok, "VERSION") == 0) {
				*vers = strdup(last);
				break;
			}
		}
		(void) fclose(fp);
	}

	return (BE_SUCCESS);
}

/*
 * To be able to boot EFI labeled disks, stage1 needs to be written
 * into the MBR. We do not do this if we're on disks with a traditional
 * fdisk partition table only, or if any foreign EFI partitions exist.
 * In the trivial case of a whole-disk vdev we always write stage1 into
 * the MBR.
 */
static boolean_t
be_do_install_mbr(char *diskname, nvlist_t *child)
{
	struct uuid allowed_uuids[] = {
		EFI_UNUSED,
		EFI_RESV1,
		EFI_BOOT,
		EFI_ROOT,
		EFI_SWAP,
		EFI_USR,
		EFI_BACKUP,
		EFI_RESV2,
		EFI_VAR,
		EFI_HOME,
		EFI_ALTSCTR,
		EFI_RESERVED,
		EFI_SYSTEM,
		EFI_BIOS_BOOT,
		EFI_SYMC_PUB,
		EFI_SYMC_CDS
	};

	uint64_t whole;
	struct dk_gpt *gpt;
	struct uuid *u;
	int fd, npart, i, j;

	(void) nvlist_lookup_uint64(child, ZPOOL_CONFIG_WHOLE_DISK,
	    &whole);

	if (whole)
		return (B_TRUE);

	if ((fd = open(diskname, O_RDONLY|O_NDELAY)) < 0)
		return (B_FALSE);

	if ((npart = efi_alloc_and_read(fd, &gpt)) <= 0)
		return (B_FALSE);

	for (i = 0; i != npart; i++) {
		int match = 0;

		u = &gpt->efi_parts[i].p_guid;

		for (j = 0;
		    j != sizeof (allowed_uuids) / sizeof (struct uuid);
		    j++)
			if (bcmp(u, &allowed_uuids[j],
			    sizeof (struct uuid)) == 0)
				match++;

		if (match == 0)
			return (B_FALSE);
	}

	return (B_TRUE);
}

static int
be_do_installboot_helper(zpool_handle_t *zphp, nvlist_t *child, char *stage1,
    char *stage2)
{
	char install_cmd[MAXPATHLEN];
	char be_run_cmd_errbuf[BUFSIZ];
	char diskname[MAXPATHLEN];
	char *vname;
	char *path, *dsk_ptr;
	char *flag = "";

	if (nvlist_lookup_string(child, ZPOOL_CONFIG_PATH, &path) != 0) {
		be_print_err(gettext("be_do_installboot: "
		    "failed to get device path\n"));
		return (BE_ERR_NODEV);
	}

	/*
	 * Modify the vdev path to point to the raw disk.
	 */
	path = strdup(path);
	if (path == NULL)
		return (BE_ERR_NOMEM);

	dsk_ptr = strstr(path, "/dsk/");
	if (dsk_ptr != NULL) {
		*dsk_ptr = '\0';
		dsk_ptr++;
	} else {
		dsk_ptr = "";
	}

	(void) snprintf(diskname, sizeof (diskname), "%s/r%s", path, dsk_ptr);
	free(path);

	vname = zpool_vdev_name(g_zfs, zphp, child, B_FALSE);
	if (vname == NULL) {
		be_print_err(gettext("be_do_installboot: "
		    "failed to get device name: %s\n"),
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	if (be_is_isa("i386")) {
		if (be_do_install_mbr(diskname, child))
			flag = "-m -f";
		(void) snprintf(install_cmd, sizeof (install_cmd),
		    "%s %s %s %s %s", BE_INSTALL_GRUB, flag,
		    stage1, stage2, diskname);
	} else {
		flag = "-F zfs";
		(void) snprintf(install_cmd, sizeof (install_cmd),
		    "%s %s %s %s", BE_INSTALL_BOOT, flag, stage2, diskname);
	}

	if (be_run_cmd(install_cmd, be_run_cmd_errbuf, BUFSIZ, NULL, 0)
	    != BE_SUCCESS) {
		be_print_err(gettext("be_do_installboot: install "
		    "failed for device %s.\n"), vname);
		/* Assume localized cmd err output. */
		be_print_err(gettext("  Command: \"%s\"\n"),
		    install_cmd);
		be_print_err("%s", be_run_cmd_errbuf);
		free(vname);
		return (BE_ERR_BOOTFILE_INST);
	}
	free(vname);

	return (BE_SUCCESS);
}

/*
 * Function:	be_do_copy_grub_cap
 * Description:	This function will copy grub capability file to BE.
 *
 * Parameters:
 *              bt - The transaction data for the BE we're activating.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 *
 * Scope:
 *		Private
 */
static int
be_do_copy_grub_cap(be_transaction_data_t *bt)
{
	zpool_handle_t  *zphp = NULL;
	zfs_handle_t	*zhp = NULL;
	char cap_file[MAXPATHLEN];
	char zpool_cap_file[MAXPATHLEN];
	char line[BUFSIZ];
	char *tmp_mntpnt = NULL;
	char *orig_mntpnt = NULL;
	char *pool_mntpnt = NULL;
	char *ptmp_mntpnt = NULL;
	FILE *cap_fp = NULL;
	FILE *zpool_cap_fp = NULL;
	int err = 0;
	int ret = BE_SUCCESS;
	boolean_t pool_mounted = B_FALSE;
	boolean_t be_mounted = B_FALSE;

	/*
	 * Copy the grub capability file from the BE we're activating
	 * into the root pool.
	 */
	zhp = zfs_open(g_zfs, bt->obe_zpool, ZFS_TYPE_FILESYSTEM);
	if (zhp == NULL) {
		be_print_err(gettext("be_do_installboot: zfs_open "
		    "failed: %s\n"), libzfs_error_description(g_zfs));
		zpool_close(zphp);
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Check to see if the pool's dataset is mounted. If it isn't we'll
	 * attempt to mount it.
	 */
	if ((ret = be_mount_pool(zhp, &ptmp_mntpnt,
	    &orig_mntpnt, &pool_mounted)) != BE_SUCCESS) {
		be_print_err(gettext("be_do_installboot: pool dataset "
		    "(%s) could not be mounted\n"), bt->obe_zpool);
		ZFS_CLOSE(zhp);
		zpool_close(zphp);
		return (ret);
	}

	/*
	 * Get the mountpoint for the root pool dataset.
	 */
	if (!zfs_is_mounted(zhp, &pool_mntpnt)) {
		be_print_err(gettext("be_do_installboot: pool "
		    "dataset (%s) is not mounted. Can't check the grub "
		    "version from the grub capability file.\n"), bt->obe_zpool);
		ret = BE_ERR_NO_MENU;
		goto done;
	}

	(void) snprintf(zpool_cap_file, sizeof (zpool_cap_file), "%s%s",
	    pool_mntpnt, BE_CAP_FILE);

	free(pool_mntpnt);

	if ((zhp = zfs_open(g_zfs, bt->obe_root_ds, ZFS_TYPE_FILESYSTEM)) ==
	    NULL) {
		be_print_err(gettext("be_do_installboot: failed to "
		    "open BE root dataset (%s): %s\n"), bt->obe_root_ds,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		goto done;
	}

	if (!zfs_is_mounted(zhp, &tmp_mntpnt)) {
		if ((ret = _be_mount(bt->obe_name, &tmp_mntpnt,
		    BE_MOUNT_FLAG_NO_ZONES)) != BE_SUCCESS) {
			be_print_err(gettext("be_do_installboot: failed to "
			    "mount BE (%s)\n"), bt->obe_name);
			ZFS_CLOSE(zhp);
			goto done;
		}
		be_mounted = B_TRUE;
	}
	ZFS_CLOSE(zhp);

	(void) snprintf(cap_file, sizeof (cap_file), "%s%s", tmp_mntpnt,
	    BE_CAP_FILE);
	free(tmp_mntpnt);

	if ((cap_fp = fopen(cap_file, "r")) == NULL) {
		err = errno;
		be_print_err(gettext("be_do_installboot: failed to open grub "
		    "capability file\n"));
		ret = errno_to_be_err(err);
		goto done;
	}
	if ((zpool_cap_fp = fopen(zpool_cap_file, "w")) == NULL) {
		err = errno;
		be_print_err(gettext("be_do_installboot: failed to open new "
		    "grub capability file\n"));
		ret = errno_to_be_err(err);
		(void) fclose(cap_fp);
		goto done;
	}

	while (fgets(line, BUFSIZ, cap_fp)) {
		(void) fputs(line, zpool_cap_fp);
	}

	(void) fclose(zpool_cap_fp);
	(void) fclose(cap_fp);

done:
	if (be_mounted)
		(void) _be_unmount(bt->obe_name, 0);

	if (pool_mounted) {
		int iret = 0;
		iret = be_unmount_pool(zhp, ptmp_mntpnt, orig_mntpnt);
		if (ret == BE_SUCCESS)
			ret = iret;
		free(orig_mntpnt);
		free(ptmp_mntpnt);
	}
	return (ret);
}

/*
 * Function:	be_is_install_needed
 * Description:	Check detached version files to detect if bootloader
 *		install/update is needed.
 *
 * Parameters:
 *              bt - The transaction data for the BE we're activating.
 *		update - set B_TRUE is update is needed.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 *
 * Scope:
 *		Private
 */
static int
be_is_install_needed(be_transaction_data_t *bt, boolean_t *update)
{
	int	ret = BE_SUCCESS;
	char	*cur_vers = NULL, *new_vers = NULL;

	assert(bt != NULL);
	assert(update != NULL);

	if (!be_has_grub()) {
		/*
		 * no detached versioning, let installboot to manage
		 * versioning.
		 */
		*update = B_TRUE;
		return (ret);
	}

	*update = B_FALSE;	/* set default */

	/*
	 * We need to check to see if the version number from
	 * the BE being activated is greater than the current
	 * one.
	 */
	ret = be_get_grub_vers(bt, &cur_vers, &new_vers);
	if (ret != BE_SUCCESS) {
		be_print_err(gettext("be_activate: failed to get grub "
		    "versions from capability files.\n"));
		return (ret);
	}
	/* update if we have both versions and can compare */
	if (cur_vers != NULL) {
		if (new_vers != NULL) {
			if (atof(cur_vers) < atof(new_vers))
				*update = B_TRUE;
			free(new_vers);
		}
		free(cur_vers);
	} else if (new_vers != NULL) {
		/* we only got new version - update */
		*update = B_TRUE;
		free(new_vers);
	}
	return (ret);
}

/*
 * Function:	be_do_installboot
 * Description:	This function runs installgrub/installboot using the boot
 *		loader files from the BE we're activating and installing
 *		them on the pool the BE lives in.
 *
 * Parameters:
 *              bt - The transaction data for the BE we're activating.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 *
 * Scope:
 *		Private
 */
static int
be_do_installboot(be_transaction_data_t *bt)
{
	zpool_handle_t  *zphp = NULL;
	zfs_handle_t	*zhp = NULL;
	nvlist_t **child, *nv, *config;
	uint_t c, children = 0;
	char *tmp_mntpt = NULL;
	char stage1[MAXPATHLEN];
	char stage2[MAXPATHLEN];
	char *vname;
	int ret = BE_SUCCESS;
	boolean_t be_mounted = B_FALSE;
	boolean_t update = B_FALSE;

	/*
	 * check versions. This call is to support detached
	 * version implementation like grub. Embedded versioning is
	 * checked by actual installer.
	 */
	ret = be_is_install_needed(bt, &update);
	if (ret != BE_SUCCESS || update == B_FALSE)
		return (ret);

	if ((zhp = zfs_open(g_zfs, bt->obe_root_ds, ZFS_TYPE_FILESYSTEM)) ==
	    NULL) {
		be_print_err(gettext("be_do_installboot: failed to "
		    "open BE root dataset (%s): %s\n"), bt->obe_root_ds,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		return (ret);
	}
	if (!zfs_is_mounted(zhp, &tmp_mntpt)) {
		if ((ret = _be_mount(bt->obe_name, &tmp_mntpt,
		    BE_MOUNT_FLAG_NO_ZONES)) != BE_SUCCESS) {
			be_print_err(gettext("be_do_installboot: failed to "
			    "mount BE (%s)\n"), bt->obe_name);
			ZFS_CLOSE(zhp);
			return (ret);
		}
		be_mounted = B_TRUE;
	}
	ZFS_CLOSE(zhp);

	if (be_has_grub()) {
		(void) snprintf(stage1, sizeof (stage1), "%s%s",
		    tmp_mntpt, BE_GRUB_STAGE_1);
		(void) snprintf(stage2, sizeof (stage2), "%s%s",
		    tmp_mntpt, BE_GRUB_STAGE_2);
	} else {
		char *platform = be_get_platform();

		if (platform == NULL) {
			be_print_err(gettext("be_do_installboot: failed to "
			    "detect system platform name\n"));
			if (be_mounted)
				(void) _be_unmount(bt->obe_name, 0);
			free(tmp_mntpt);
			return (BE_ERR_BOOTFILE_INST);
		}

		stage1[0] = '\0';	/* sparc has no stage1 */
		(void) snprintf(stage2, sizeof (stage2),
		    "%s/usr/platform/%s%s", tmp_mntpt,
		    platform, BE_SPARC_BOOTBLK);
	}

	if ((zphp = zpool_open(g_zfs, bt->obe_zpool)) == NULL) {
		be_print_err(gettext("be_do_installboot: failed to open "
		    "pool (%s): %s\n"), bt->obe_zpool,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		if (be_mounted)
			(void) _be_unmount(bt->obe_name, 0);
		free(tmp_mntpt);
		return (ret);
	}

	if ((config = zpool_get_config(zphp, NULL)) == NULL) {
		be_print_err(gettext("be_do_installboot: failed to get zpool "
		    "configuration information. %s\n"),
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		goto done;
	}

	/*
	 * Get the vdev tree
	 */
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &nv) != 0) {
		be_print_err(gettext("be_do_installboot: failed to get vdev "
		    "tree: %s\n"), libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		goto done;
	}

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN, &child,
	    &children) != 0) {
		be_print_err(gettext("be_do_installboot: failed to traverse "
		    "the vdev tree: %s\n"), libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		goto done;
	}
	for (c = 0; c < children; c++) {
		uint_t i, nchildren = 0;
		nvlist_t **nvchild;
		vname = zpool_vdev_name(g_zfs, zphp, child[c], B_FALSE);
		if (vname == NULL) {
			be_print_err(gettext(
			    "be_do_installboot: "
			    "failed to get device name: %s\n"),
			    libzfs_error_description(g_zfs));
			ret = zfs_err_to_be_err(g_zfs);
			goto done;
		}
		if (strcmp(vname, "mirror") == 0 || vname[0] != 'c') {
			free(vname);

			if (nvlist_lookup_nvlist_array(child[c],
			    ZPOOL_CONFIG_CHILDREN, &nvchild, &nchildren) != 0) {
				be_print_err(gettext("be_do_installboot: "
				    "failed to traverse the vdev tree: %s\n"),
				    libzfs_error_description(g_zfs));
				ret = zfs_err_to_be_err(g_zfs);
				goto done;
			}

			for (i = 0; i < nchildren; i++) {
				ret = be_do_installboot_helper(zphp, nvchild[i],
				    stage1, stage2);
				if (ret != BE_SUCCESS)
					goto done;
			}
		} else {
			free(vname);

			ret = be_do_installboot_helper(zphp, child[c], stage1,
			    stage2);
			if (ret != BE_SUCCESS)
				goto done;
		}
	}

	if (be_has_grub()) {
		ret = be_do_copy_grub_cap(bt);
	}

done:
	ZFS_CLOSE(zhp);
	if (be_mounted)
		(void) _be_unmount(bt->obe_name, 0);
	zpool_close(zphp);
	free(tmp_mntpt);
	return (ret);
}

/*
 * Function:	be_promote_zone_ds
 * Description:	This function finds the zones for the BE being activated
 *              and the active zonepath dataset for each zone. Then each
 *              active zonepath dataset is promoted.
 *
 * Parameters:
 *              be_name - the name of the global zone BE that we need to
 *                       find the zones for.
 *              be_root_ds - the root dataset for be_name.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 *
 * Scope:
 *		Private
 */
static int
be_promote_zone_ds(char *be_name, char *be_root_ds)
{
	char		*zone_ds = NULL;
	char		*temp_mntpt = NULL;
	char		origin[MAXPATHLEN];
	char		zoneroot_ds[MAXPATHLEN];
	zfs_handle_t	*zhp = NULL;
	zfs_handle_t	*z_zhp = NULL;
	zoneList_t	zone_list = NULL;
	zoneBrandList_t *brands = NULL;
	boolean_t	be_mounted = B_FALSE;
	int		zone_index = 0;
	int		err = BE_SUCCESS;

	/*
	 * Get the supported zone brands so we can pass that
	 * to z_get_nonglobal_zone_list_by_brand. Currently
	 * only the ipkg and labeled brand zones are supported
	 *
	 */
	if ((brands = be_get_supported_brandlist()) == NULL) {
		be_print_err(gettext("be_promote_zone_ds: no supported "
		    "brands\n"));
		return (BE_SUCCESS);
	}

	if ((zhp = zfs_open(g_zfs, be_root_ds,
	    ZFS_TYPE_FILESYSTEM)) == NULL) {
		be_print_err(gettext("be_promote_zone_ds: Failed to open "
		    "dataset (%s): %s\n"), be_root_ds,
		    libzfs_error_description(g_zfs));
		err = zfs_err_to_be_err(g_zfs);
		z_free_brand_list(brands);
		return (err);
	}

	if (!zfs_is_mounted(zhp, &temp_mntpt)) {
		if ((err = _be_mount(be_name, &temp_mntpt,
		    BE_MOUNT_FLAG_NO_ZONES)) != BE_SUCCESS) {
			be_print_err(gettext("be_promote_zone_ds: failed to "
			    "mount the BE for zones procesing.\n"));
			ZFS_CLOSE(zhp);
			z_free_brand_list(brands);
			return (err);
		}
		be_mounted = B_TRUE;
	}

	/*
	 * Set the zone root to the temp mount point for the BE we just mounted.
	 */
	z_set_zone_root(temp_mntpt);

	/*
	 * Get all the zones based on the brands we're looking for. If no zones
	 * are found that we're interested in unmount the BE and move on.
	 */
	if ((zone_list = z_get_nonglobal_zone_list_by_brand(brands)) == NULL) {
		if (be_mounted)
			(void) _be_unmount(be_name, 0);
		ZFS_CLOSE(zhp);
		z_free_brand_list(brands);
		free(temp_mntpt);
		return (BE_SUCCESS);
	}
	for (zone_index = 0; z_zlist_get_zonename(zone_list, zone_index)
	    != NULL; zone_index++) {
		char *zone_path = NULL;

		/* Skip zones that aren't at least installed */
		if (z_zlist_get_current_state(zone_list, zone_index) <
		    ZONE_STATE_INSTALLED)
			continue;

		if (((zone_path =
		    z_zlist_get_zonepath(zone_list, zone_index)) == NULL) ||
		    ((zone_ds = be_get_ds_from_dir(zone_path)) == NULL) ||
		    !be_zone_supported(zone_ds))
			continue;

		if (be_find_active_zone_root(zhp, zone_ds,
		    zoneroot_ds, sizeof (zoneroot_ds)) != 0) {
			be_print_err(gettext("be_promote_zone_ds: "
			    "Zone does not have an active root "
			    "dataset, skipping this zone.\n"));
			continue;
		}

		if ((z_zhp = zfs_open(g_zfs, zoneroot_ds,
		    ZFS_TYPE_FILESYSTEM)) == NULL) {
			be_print_err(gettext("be_promote_zone_ds: "
			    "Failed to open dataset "
			    "(%s): %s\n"), zoneroot_ds,
			    libzfs_error_description(g_zfs));
			err = zfs_err_to_be_err(g_zfs);
			goto done;
		}

		if (zfs_prop_get(z_zhp, ZFS_PROP_ORIGIN, origin,
		    sizeof (origin), NULL, NULL, 0, B_FALSE) != 0) {
			ZFS_CLOSE(z_zhp);
			continue;
		}

		/*
		 * We don't need to close the zfs handle at this
		 * point because the callback funtion
		 * be_promote_ds_callback() will close it for us.
		 */
		if (be_promote_ds_callback(z_zhp, NULL) != 0) {
			be_print_err(gettext("be_promote_zone_ds: "
			    "failed to activate the "
			    "datasets for %s: %s\n"),
			    zoneroot_ds,
			    libzfs_error_description(g_zfs));
			err = BE_ERR_PROMOTE;
			goto done;
		}
	}
done:
	if (be_mounted)
		(void) _be_unmount(be_name, 0);
	ZFS_CLOSE(zhp);
	free(temp_mntpt);
	z_free_brand_list(brands);
	z_free_zone_list(zone_list);
	return (err);
}

/*
 * Function:	be_promote_ds_callback
 * Description:	This function is used to promote the datasets for the BE
 *		being activated as well as the datasets for the zones BE
 *		being activated.
 *
 * Parameters:
 *              zhp - the zfs handle for zone BE being activated.
 *		data - not used.
 * Return:
 *		0 - Success
 *		be_errno_t - Failure
 *
 * Scope:
 *		Private
 */
static int
/* LINTED */
be_promote_ds_callback(zfs_handle_t *zhp, void *data)
{
	char	origin[MAXPATHLEN];
	char	*sub_dataset = NULL;
	int	ret = 0;

	if (zhp != NULL) {
		sub_dataset = strdup(zfs_get_name(zhp));
		if (sub_dataset == NULL) {
			ret = BE_ERR_NOMEM;
			goto done;
		}
	} else {
		be_print_err(gettext("be_promote_ds_callback: "
		    "Invalid zfs handle passed into function\n"));
		ret = BE_ERR_INVAL;
		goto done;
	}

	/*
	 * This loop makes sure that we promote the dataset to the
	 * top of the tree so that it is no longer a decendent of any
	 * dataset. The ZFS close and then open is used to make sure that
	 * the promotion is updated before we move on.
	 */
	while (zfs_prop_get(zhp, ZFS_PROP_ORIGIN, origin,
	    sizeof (origin), NULL, NULL, 0, B_FALSE) == 0) {
		if (zfs_promote(zhp) != 0) {
			if (libzfs_errno(g_zfs) != EZFS_EXISTS) {
				be_print_err(gettext("be_promote_ds_callback: "
				    "promote of %s failed: %s\n"),
				    zfs_get_name(zhp),
				    libzfs_error_description(g_zfs));
				ret = zfs_err_to_be_err(g_zfs);
				goto done;
			} else {
				/*
				 * If the call to zfs_promote returns the
				 * error EZFS_EXISTS we've hit a snapshot name
				 * collision. This means we're probably
				 * attemping to promote a zone dataset above a
				 * parent dataset that belongs to another zone
				 * which this zone was cloned from.
				 *
				 * TODO: If this is a zone dataset at some
				 * point we should skip this if the zone
				 * paths for the dataset and the snapshot
				 * don't match.
				 */
				be_print_err(gettext("be_promote_ds_callback: "
				    "promote of %s failed due to snapshot "
				    "name collision: %s\n"), zfs_get_name(zhp),
				    libzfs_error_description(g_zfs));
				ret = zfs_err_to_be_err(g_zfs);
				goto done;
			}
		}
		ZFS_CLOSE(zhp);
		if ((zhp = zfs_open(g_zfs, sub_dataset,
		    ZFS_TYPE_FILESYSTEM)) == NULL) {
			be_print_err(gettext("be_promote_ds_callback: "
			    "Failed to open dataset (%s): %s\n"), sub_dataset,
			    libzfs_error_description(g_zfs));
			ret = zfs_err_to_be_err(g_zfs);
			goto done;
		}
	}

	/* Iterate down this dataset's children and promote them */
	ret = zfs_iter_filesystems(zhp, be_promote_ds_callback, NULL);

done:
	free(sub_dataset);
	ZFS_CLOSE(zhp);
	return (ret);
}
