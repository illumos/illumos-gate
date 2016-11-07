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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
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
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfstab.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <deflt.h>
#include <wait.h>
#include <libdevinfo.h>
#include <libgen.h>

#include <libbe.h>
#include <libbe_priv.h>
#include <boot_utils.h>
#include <ficl.h>
#include <ficlplatform/emu.h>

/* Private function prototypes */
static int update_dataset(char *, int, char *, char *, char *);
static int _update_vfstab(char *, char *, char *, char *, be_fs_list_data_t *);
static int be_open_menu(char *, char *, FILE **, char *, boolean_t);
static int be_create_menu(char *, char *, FILE **, char *);
static char *be_get_auto_name(char *, char *, boolean_t);

/*
 * Global error printing
 */
boolean_t do_print = B_FALSE;

/*
 * Private datatypes
 */
typedef struct zone_be_name_cb_data {
	char *base_be_name;
	int num;
} zone_be_name_cb_data_t;

/* ********************************************************************	*/
/*			Public Functions				*/
/* ******************************************************************** */

/*
 * Callback for ficl to suppress all output from ficl, as we do not
 * want to confuse user with messages from ficl, and we are only
 * checking results from function calls.
 */
/*ARGSUSED*/
static void
ficlSuppressTextOutput(ficlCallback *cb, char *text)
{
	/* This function is intentionally doing nothing. */
}

/*
 * Function:	be_get_boot_args
 * Description:	Returns the fast boot argument string for enumerated BE.
 * Parameters:
 *		fbarg - pointer to argument string.
 *		entry - index of BE.
 * Returns:
 *		fast boot argument string.
 * Scope:
 *		Public
 */
int
be_get_boot_args(char **fbarg, int entry)
{
	be_node_list_t *node, *be_nodes = NULL;
	be_transaction_data_t bt = {0};
	char *mountpoint = NULL;
	boolean_t be_mounted = B_FALSE;
	int ret = BE_SUCCESS;
	int index;
	ficlVm *vm;

	*fbarg = NULL;
	if (!be_zfs_init())
		return (BE_ERR_INIT);

	/*
	 * need pool name, menu.lst has entries from our pool only
	 */
	ret = be_find_current_be(&bt);
	if (ret != BE_SUCCESS) {
		be_zfs_fini();
		return (ret);
	}

	/*
	 * be_get_boot_args() is for loader, fail with grub will trigger
	 * normal boot.
	 */
	if (be_has_grub()) {
		ret = BE_ERR_INIT;
		goto done;
	}

	ret = _be_list(NULL, &be_nodes);
	if (ret != BE_SUCCESS)
		goto done;

	/*
	 * iterate through be_nodes,
	 * if entry == -1, stop if be_active_on_boot,
	 * else stop if index == entry.
	 */
	index = 0;
	for (node = be_nodes; node != NULL; node = node->be_next_node) {
		if (strcmp(node->be_rpool, bt.obe_zpool) != 0)
			continue;
		if (entry == BE_ENTRY_DEFAULT &&
		    node->be_active_on_boot == B_TRUE)
			break;
		if (index == entry)
			break;
		index++;
	}
	if (node == NULL) {
		be_free_list(be_nodes);
		ret = BE_ERR_NOENT;
		goto done;
	}

	/* try to mount inactive be */
	if (node->be_active == B_FALSE) {
		ret = _be_mount(node->be_node_name, &mountpoint,
		    BE_MOUNT_FLAG_NO_ZONES);
		if (ret != BE_SUCCESS && ret != BE_ERR_MOUNTED) {
			be_free_list(be_nodes);
			goto done;
		} else
			be_mounted = B_TRUE;
	}

	vm = bf_init("", ficlSuppressTextOutput);
	if (vm != NULL) {
		/*
		 * zfs MAXNAMELEN is 256, so we need to pick buf large enough
		 * to contain such names.
		 */
		char buf[MAXNAMELEN * 2];
		char *kernel_options = NULL;
		char *kernel = NULL;
		char *tmp;
		zpool_handle_t *zph;

		/*
		 * just try to interpret following words. on error
		 * we will be missing kernelname, and will get out.
		 */
		(void) snprintf(buf, sizeof (buf), "set currdev=zfs:%s:",
		    node->be_root_ds);
		ret = ficlVmEvaluate(vm, buf);
		if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
			be_print_err(gettext("be_get_boot_args: error "
			    "interpreting boot config: %d\n"), ret);
			bf_fini();
			ret = BE_ERR_NO_MENU;
			goto cleanup;
		}
		(void) snprintf(buf, sizeof (buf),
		    "include /boot/forth/loader.4th");
		ret = ficlVmEvaluate(vm, buf);
		if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
			be_print_err(gettext("be_get_boot_args: error "
			    "interpreting boot config: %d\n"), ret);
			bf_fini();
			ret = BE_ERR_NO_MENU;
			goto cleanup;
		}
		(void) snprintf(buf, sizeof (buf), "start");
		ret = ficlVmEvaluate(vm, buf);
		if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
			be_print_err(gettext("be_get_boot_args: error "
			    "interpreting boot config: %d\n"), ret);
			bf_fini();
			ret = BE_ERR_NO_MENU;
			goto cleanup;
		}
		(void) snprintf(buf, sizeof (buf), "boot");
		ret = ficlVmEvaluate(vm, buf);
		bf_fini();
		if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
			be_print_err(gettext("be_get_boot_args: error "
			    "interpreting boot config: %d\n"), ret);
			ret = BE_ERR_NO_MENU;
			goto cleanup;
		}

		kernel_options = getenv("boot-args");
		kernel = getenv("kernelname");

		if (kernel == NULL) {
			be_print_err(gettext("be_get_boot_args: no kernel\n"));
			ret = BE_ERR_NOENT;
			goto cleanup;
		}

		if ((zph = zpool_open(g_zfs, node->be_rpool)) == NULL) {
			be_print_err(gettext("be_get_boot_args: failed to "
			    "open root pool (%s): %s\n"), node->be_rpool,
			    libzfs_error_description(g_zfs));
			ret = zfs_err_to_be_err(g_zfs);
			goto cleanup;
		}
		ret = zpool_get_physpath(zph, buf, sizeof (buf));
		zpool_close(zph);
		if (ret != 0) {
			be_print_err(gettext("be_get_boot_args: failed to "
			    "get physpath\n"));
			goto cleanup;
		}

		/* zpool_get_physpath() can return space separated list */
		tmp = buf;
		tmp = strsep(&tmp, " ");

		if (kernel_options == NULL || *kernel_options == '\0')
			(void) asprintf(fbarg, "/ %s "
			    "-B zfs-bootfs=%s,bootpath=\"%s\"\n", kernel,
			    node->be_root_ds, tmp);
		else
			(void) asprintf(fbarg, "/ %s %s "
			    "-B zfs-bootfs=%s,bootpath=\"%s\"\n", kernel,
			    kernel_options, node->be_root_ds, tmp);

		if (fbarg == NULL)
			ret = BE_ERR_NOMEM;
		else
			ret = 0;
	} else
		ret = BE_ERR_NOMEM;
cleanup:
	if (be_mounted == B_TRUE)
		(void) _be_unmount(node->be_node_name, BE_UNMOUNT_FLAG_FORCE);
	be_free_list(be_nodes);
done:
	free(mountpoint);
	free(bt.obe_name);
	free(bt.obe_root_ds);
	free(bt.obe_zpool);
	free(bt.obe_snap_name);
	free(bt.obe_altroot);
	be_zfs_fini();
	return (ret);
}

/*
 * Function:	be_max_avail
 * Description:	Returns the available size for the zfs dataset passed in.
 * Parameters:
 *		dataset - The dataset we want to get the available space for.
 *		ret - The available size will be returned in this.
 * Returns:
 *		The error returned by the zfs get property function.
 * Scope:
 *		Public
 */
int
be_max_avail(char *dataset, uint64_t *ret)
{
	zfs_handle_t *zhp;
	int err = 0;

	/* Initialize libzfs handle */
	if (!be_zfs_init())
		return (BE_ERR_INIT);

	zhp = zfs_open(g_zfs, dataset, ZFS_TYPE_DATASET);
	if (zhp == NULL) {
		/*
		 * The zfs_open failed return an error
		 */
		err = zfs_err_to_be_err(g_zfs);
	} else {
		err = be_maxsize_avail(zhp, ret);
	}
	ZFS_CLOSE(zhp);
	be_zfs_fini();
	return (err);
}

/*
 * Function:	libbe_print_errors
 * Description:	Turns on/off error output for the library.
 * Parameter:
 *		set_do_print - Boolean that turns library error
 *			       printing on or off.
 * Returns:
 *		None
 * Scope:
 *		Public;
 */
void
libbe_print_errors(boolean_t set_do_print)
{
	do_print = set_do_print;
}

/* ********************************************************************	*/
/*			Semi-Private Functions				*/
/* ******************************************************************** */

/*
 * Function:	be_zfs_init
 * Description:	Initializes the libary global libzfs handle.
 * Parameters:
 *		None
 * Returns:
 *		B_TRUE - Success
 *		B_FALSE - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
boolean_t
be_zfs_init(void)
{
	be_zfs_fini();

	if ((g_zfs = libzfs_init()) == NULL) {
		be_print_err(gettext("be_zfs_init: failed to initialize ZFS "
		    "library\n"));
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Function:	be_zfs_fini
 * Description:	Closes the library global libzfs handle if it currently open.
 * Parameter:
 *		None
 * Returns:
 *		None
 * Scope:
 *		Semi-private (library wide use only)
 */
void
be_zfs_fini(void)
{
	if (g_zfs)
		libzfs_fini(g_zfs);

	g_zfs = NULL;
}

/*
 * Function:	be_get_defaults
 * Description:	Open defaults and gets be default paramets
 * Parameters:
 *		defaults - be defaults struct
 * Returns:
 *		None
 * Scope:
 *		Semi-private (library wide use only)
 */
void
be_get_defaults(struct be_defaults *defaults)
{
	void	*defp;

	defaults->be_deflt_grub = B_FALSE;
	defaults->be_deflt_rpool_container = B_FALSE;
	defaults->be_deflt_bename_starts_with[0] = '\0';

	if ((defp = defopen_r(BE_DEFAULTS)) != NULL) {
		const char *res = defread_r(BE_DFLT_BENAME_STARTS, defp);
		if (res != NULL && res[0] != '\0') {
			(void) strlcpy(defaults->be_deflt_bename_starts_with,
			    res, ZFS_MAX_DATASET_NAME_LEN);
			defaults->be_deflt_rpool_container = B_TRUE;
		}
		if (be_is_isa("i386")) {
			res = defread_r(BE_DFLT_BE_HAS_GRUB, defp);
			if (res != NULL && res[0] != '\0') {
				if (strcasecmp(res, "true") == 0)
					defaults->be_deflt_grub = B_TRUE;
			}
		}
		defclose_r(defp);
	}
}

/*
 * Function:	be_make_root_ds
 * Description:	Generate string for BE's root dataset given the pool
 *		it lives in and the BE name.
 * Parameters:
 *		zpool - pointer zpool name.
 *		be_name - pointer to BE name.
 *		be_root_ds - pointer to buffer to return BE root dataset in.
 *		be_root_ds_size - size of be_root_ds
 * Returns:
 *		None
 * Scope:
 *		Semi-private (library wide use only)
 */
void
be_make_root_ds(const char *zpool, const char *be_name, char *be_root_ds,
    int be_root_ds_size)
{
	struct be_defaults be_defaults;
	be_get_defaults(&be_defaults);
	char	*root_ds = NULL;

	if (getzoneid() == GLOBAL_ZONEID) {
		if (be_defaults.be_deflt_rpool_container) {
			(void) snprintf(be_root_ds, be_root_ds_size,
			    "%s/%s", zpool, be_name);
		} else {
			(void) snprintf(be_root_ds, be_root_ds_size,
			    "%s/%s/%s", zpool, BE_CONTAINER_DS_NAME, be_name);
		}
	} else {
		/*
		 * In non-global zone we can use path from mounted root dataset
		 * to generate BE's root dataset string.
		 */
		if ((root_ds = be_get_ds_from_dir("/")) != NULL) {
			(void) snprintf(be_root_ds, be_root_ds_size, "%s/%s",
			    dirname(root_ds), be_name);
		} else {
			be_print_err(gettext("be_make_root_ds: zone root "
			    "dataset is not mounted\n"));
			return;
		}
	}
}

/*
 * Function:	be_make_container_ds
 * Description:	Generate string for the BE container dataset given a pool name.
 * Parameters:
 *		zpool - pointer zpool name.
 *		container_ds - pointer to buffer to return BE container
 *			dataset in.
 *		container_ds_size - size of container_ds
 * Returns:
 *		None
 * Scope:
 *		Semi-private (library wide use only)
 */
void
be_make_container_ds(const char *zpool,  char *container_ds,
    int container_ds_size)
{
	struct be_defaults be_defaults;
	be_get_defaults(&be_defaults);
	char	*root_ds = NULL;

	if (getzoneid() == GLOBAL_ZONEID) {
		if (be_defaults.be_deflt_rpool_container) {
			(void) snprintf(container_ds, container_ds_size,
			    "%s", zpool);
		} else {
			(void) snprintf(container_ds, container_ds_size,
			    "%s/%s", zpool, BE_CONTAINER_DS_NAME);
		}
	} else {
		if ((root_ds = be_get_ds_from_dir("/")) != NULL) {
			(void) strlcpy(container_ds, dirname(root_ds),
			    container_ds_size);
		} else {
			be_print_err(gettext("be_make_container_ds: zone root "
			    "dataset is not mounted\n"));
			return;
		}
	}
}

/*
 * Function:	be_make_name_from_ds
 * Description:	This function takes a dataset name and strips off the
 *		BE container dataset portion from the beginning.  The
 *		returned name is allocated in heap storage, so the caller
 *		is responsible for freeing it.
 * Parameters:
 *		dataset - dataset to get name from.
 *		rc_loc - dataset underwhich the root container dataset lives.
 * Returns:
 *		name of dataset relative to BE container dataset.
 *		NULL if dataset is not under a BE root dataset.
 * Scope:
 *		Semi-primate (library wide use only)
 */
char *
be_make_name_from_ds(const char *dataset, char *rc_loc)
{
	char	ds[ZFS_MAX_DATASET_NAME_LEN];
	char	*tok = NULL;
	char	*name = NULL;
	struct be_defaults be_defaults;
	int	rlen = strlen(rc_loc);

	be_get_defaults(&be_defaults);

	/*
	 * First token is the location of where the root container dataset
	 * lives; it must match rc_loc.
	 */
	if (strncmp(dataset, rc_loc, rlen) == 0 && dataset[rlen] == '/')
		(void) strlcpy(ds, dataset + rlen + 1, sizeof (ds));
	else
		return (NULL);

	if (be_defaults.be_deflt_rpool_container) {
		if ((name = strdup(ds)) == NULL) {
			be_print_err(gettext("be_make_name_from_ds: "
			    "memory allocation failed\n"));
			return (NULL);
		}
	} else {
		/* Second token must be BE container dataset name */
		if ((tok = strtok(ds, "/")) == NULL ||
		    strcmp(tok, BE_CONTAINER_DS_NAME) != 0)
			return (NULL);

		/* Return the remaining token if one exists */
		if ((tok = strtok(NULL, "")) == NULL)
			return (NULL);

		if ((name = strdup(tok)) == NULL) {
			be_print_err(gettext("be_make_name_from_ds: "
			    "memory allocation failed\n"));
			return (NULL);
		}
	}

	return (name);
}

/*
 * Function:	be_maxsize_avail
 * Description:	Returns the available size for the zfs handle passed in.
 * Parameters:
 *		zhp - A pointer to the open zfs handle.
 *		ret - The available size will be returned in this.
 * Returns:
 *		The error returned by the zfs get property function.
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_maxsize_avail(zfs_handle_t *zhp, uint64_t *ret)
{
	return ((*ret = zfs_prop_get_int(zhp, ZFS_PROP_AVAILABLE)));
}

/*
 * Function:	be_append_menu
 * Description:	Appends an entry for a BE into the menu.lst.
 * Parameters:
 *		be_name - pointer to name of BE to add boot menu entry for.
 *		be_root_pool - pointer to name of pool BE lives in.
 *		boot_pool - Used if the pool containing the grub menu is
 *			    different than the one contaiing the BE. This
 *			    will normally be NULL.
 *		be_orig_root_ds - The root dataset for the BE. This is
 *			used to check to see if an entry already exists
 *			for this BE.
 *		description - pointer to description of BE to be added in
 *			the title line for this BEs entry.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_append_menu(char *be_name, char *be_root_pool, char *boot_pool,
    char *be_orig_root_ds, char *description)
{
	zfs_handle_t *zhp = NULL;
	char menu_file[MAXPATHLEN];
	char be_root_ds[MAXPATHLEN];
	char line[BUFSIZ];
	char temp_line[BUFSIZ];
	char title[MAXPATHLEN];
	char *entries[BUFSIZ];
	char *tmp_entries[BUFSIZ];
	char *pool_mntpnt = NULL;
	char *ptmp_mntpnt = NULL;
	char *orig_mntpnt = NULL;
	boolean_t found_be = B_FALSE;
	boolean_t found_orig_be = B_FALSE;
	boolean_t found_title = B_FALSE;
	boolean_t pool_mounted = B_FALSE;
	boolean_t collect_lines = B_FALSE;
	FILE *menu_fp = NULL;
	int err = 0, ret = BE_SUCCESS;
	int i, num_tmp_lines = 0, num_lines = 0;

	if (be_name == NULL || be_root_pool == NULL)
		return (BE_ERR_INVAL);

	if (boot_pool == NULL)
		boot_pool = be_root_pool;

	if ((zhp = zfs_open(g_zfs, be_root_pool, ZFS_TYPE_DATASET)) == NULL) {
		be_print_err(gettext("be_append_menu: failed to open "
		    "pool dataset for %s: %s\n"), be_root_pool,
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Check to see if the pool's dataset is mounted. If it isn't we'll
	 * attempt to mount it.
	 */
	if ((ret = be_mount_pool(zhp, &ptmp_mntpnt, &orig_mntpnt,
	    &pool_mounted)) != BE_SUCCESS) {
		be_print_err(gettext("be_append_menu: pool dataset "
		    "(%s) could not be mounted\n"), be_root_pool);
		ZFS_CLOSE(zhp);
		return (ret);
	}

	/*
	 * Get the mountpoint for the root pool dataset.
	 */
	if (!zfs_is_mounted(zhp, &pool_mntpnt)) {
		be_print_err(gettext("be_append_menu: pool "
		    "dataset (%s) is not mounted. Can't set "
		    "the default BE in the grub menu.\n"), be_root_pool);
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	/*
	 * Check to see if this system supports grub
	 */
	if (be_has_grub()) {
		(void) snprintf(menu_file, sizeof (menu_file),
		    "%s%s", pool_mntpnt, BE_GRUB_MENU);
	} else {
		(void) snprintf(menu_file, sizeof (menu_file),
		    "%s%s", pool_mntpnt, BE_SPARC_MENU);
	}

	be_make_root_ds(be_root_pool, be_name, be_root_ds, sizeof (be_root_ds));

	/*
	 * Iterate through menu first to make sure the BE doesn't already
	 * have an entry in the menu.
	 *
	 * Additionally while iterating through the menu, if we have an
	 * original root dataset for a BE we're cloning from, we need to keep
	 * track of that BE's menu entry. We will then use the lines from
	 * that entry to create the entry for the new BE.
	 */
	if ((ret = be_open_menu(be_root_pool, menu_file,
	    &menu_fp, "r", B_TRUE)) != BE_SUCCESS) {
		goto cleanup;
	} else if (menu_fp == NULL) {
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	free(pool_mntpnt);
	pool_mntpnt = NULL;

	while (fgets(line, BUFSIZ, menu_fp)) {
		char *tok = NULL;

		(void) strlcpy(temp_line, line, BUFSIZ);
		tok = strtok(line, BE_WHITE_SPACE);

		if (tok == NULL || tok[0] == '#') {
			continue;
		} else if (strcmp(tok, "title") == 0) {
			collect_lines = B_FALSE;
			if ((tok = strtok(NULL, "\n")) == NULL)
				(void) strlcpy(title, "", sizeof (title));
			else
				(void) strlcpy(title, tok, sizeof (title));
			found_title = B_TRUE;

			if (num_tmp_lines != 0) {
				for (i = 0; i < num_tmp_lines; i++) {
					free(tmp_entries[i]);
					tmp_entries[i] = NULL;
				}
				num_tmp_lines = 0;
			}
		} else if (strcmp(tok, "bootfs") == 0) {
			char *bootfs = strtok(NULL, BE_WHITE_SPACE);
			found_title = B_FALSE;
			if (bootfs == NULL)
				continue;

			if (strcmp(bootfs, be_root_ds) == 0) {
				found_be = B_TRUE;
				break;
			}

			if (be_orig_root_ds != NULL &&
			    strcmp(bootfs, be_orig_root_ds) == 0 &&
			    !found_orig_be) {
				char str[BUFSIZ];
				found_orig_be = B_TRUE;
				num_lines = 0;
				/*
				 * Store the new title line
				 */
				(void) snprintf(str, BUFSIZ, "title %s\n",
				    description ? description : be_name);
				entries[num_lines] = strdup(str);
				num_lines++;
				/*
				 * If there are any lines between the title
				 * and the bootfs line store these. Also
				 * free the temporary lines.
				 */
				for (i = 0; i < num_tmp_lines; i++) {
					entries[num_lines] = tmp_entries[i];
					tmp_entries[i] = NULL;
					num_lines++;
				}
				num_tmp_lines = 0;
				/*
				 * Store the new bootfs line.
				 */
				(void) snprintf(str, BUFSIZ, "bootfs %s\n",
				    be_root_ds);
				entries[num_lines] = strdup(str);
				num_lines++;
				collect_lines = B_TRUE;
			}
		} else if (found_orig_be && collect_lines) {
			/*
			 * get the rest of the lines for the original BE and
			 * store them.
			 */
			if (strstr(line, BE_GRUB_COMMENT) != NULL ||
			    strstr(line, "BOOTADM") != NULL)
				continue;
			if (strcmp(tok, "splashimage") == 0) {
				entries[num_lines] =
				    strdup("splashimage "
				    "/boot/splashimage.xpm\n");
			} else {
				entries[num_lines] = strdup(temp_line);
			}
			num_lines++;
		} else if (found_title && !found_orig_be) {
			tmp_entries[num_tmp_lines] = strdup(temp_line);
			num_tmp_lines++;
		}
	}

	(void) fclose(menu_fp);

	if (found_be) {
		/*
		 * If an entry for this BE was already in the menu, then if
		 * that entry's title matches what we would have put in
		 * return success.  Otherwise return failure.
		 */
		char *new_title = description ? description : be_name;

		if (strcmp(title, new_title) == 0) {
			ret = BE_SUCCESS;
			goto cleanup;
		} else {
			if (be_remove_menu(be_name, be_root_pool,
			    boot_pool) != BE_SUCCESS) {
				be_print_err(gettext("be_append_menu: "
				    "Failed to remove existing unusable "
				    "entry '%s' in boot menu.\n"), be_name);
				ret = BE_ERR_BE_EXISTS;
				goto cleanup;
			}
		}
	}

	/* Append BE entry to the end of the file */
	menu_fp = fopen(menu_file, "a+");
	err = errno;
	if (menu_fp == NULL) {
		be_print_err(gettext("be_append_menu: failed "
		    "to open menu.lst file %s\n"), menu_file);
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	if (found_orig_be) {
		/*
		 * write out all the stored lines
		 */
		for (i = 0; i < num_lines; i++) {
			(void) fprintf(menu_fp, "%s", entries[i]);
			free(entries[i]);
		}
		num_lines = 0;

		/*
		 * Check to see if this system supports grub
		 */
		if (be_has_grub())
			(void) fprintf(menu_fp, "%s\n", BE_GRUB_COMMENT);
		ret = BE_SUCCESS;
	} else {
		(void) fprintf(menu_fp, "title %s\n",
		    description ? description : be_name);
		(void) fprintf(menu_fp, "bootfs %s\n", be_root_ds);

		/*
		 * Check to see if this system supports grub
		 */
		if (be_has_grub()) {
			(void) fprintf(menu_fp, "kernel$ "
			    "/platform/i86pc/kernel/$ISADIR/unix -B "
			    "$ZFS-BOOTFS\n");
			(void) fprintf(menu_fp, "module$ "
			    "/platform/i86pc/$ISADIR/boot_archive\n");
			(void) fprintf(menu_fp, "%s\n", BE_GRUB_COMMENT);
		}
		ret = BE_SUCCESS;
	}
	(void) fclose(menu_fp);
cleanup:
	if (pool_mounted) {
		int err = BE_SUCCESS;
		err = be_unmount_pool(zhp, ptmp_mntpnt, orig_mntpnt);
		if (ret == BE_SUCCESS)
			ret = err;
		free(orig_mntpnt);
		free(ptmp_mntpnt);
	}
	ZFS_CLOSE(zhp);
	if (num_tmp_lines > 0) {
		for (i = 0; i < num_tmp_lines; i++) {
			free(tmp_entries[i]);
			tmp_entries[i] = NULL;
		}
	}
	if (num_lines > 0) {
		for (i = 0; i < num_lines; i++) {
			free(entries[i]);
			entries[i] = NULL;
		}
	}
	return (ret);
}

/*
 * Function:	be_remove_menu
 * Description:	Removes a BE's entry from a menu.lst file.
 * Parameters:
 *		be_name - the name of BE whose entry is to be removed from
 *			the menu.lst file.
 *		be_root_pool - the pool that be_name lives in.
 *		boot_pool - the pool where the BE is, if different than
 *			the pool containing the boot menu.  If this is
 *			NULL it will be set to be_root_pool.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_remove_menu(char *be_name, char *be_root_pool, char *boot_pool)
{
	zfs_handle_t	*zhp = NULL;
	char		be_root_ds[MAXPATHLEN];
	char		**buffer = NULL;
	char		menu_buf[BUFSIZ];
	char		menu[MAXPATHLEN];
	char		*pool_mntpnt = NULL;
	char		*ptmp_mntpnt = NULL;
	char		*orig_mntpnt = NULL;
	char		*tmp_menu = NULL;
	FILE		*menu_fp = NULL;
	FILE		*tmp_menu_fp = NULL;
	struct stat	sb;
	int		ret = BE_SUCCESS;
	int		i;
	int		fd;
	int		err = 0;
	int		nlines = 0;
	int		default_entry = 0;
	int		entry_cnt = 0;
	int		entry_del = 0;
	int		num_entry_del = 0;
	int		tmp_menu_len = 0;
	boolean_t	write = B_TRUE;
	boolean_t	do_buffer = B_FALSE;
	boolean_t	pool_mounted = B_FALSE;

	if (boot_pool == NULL)
		boot_pool = be_root_pool;

	/* Get name of BE's root dataset */
	be_make_root_ds(be_root_pool, be_name, be_root_ds, sizeof (be_root_ds));

	/* Get handle to pool dataset */
	if ((zhp = zfs_open(g_zfs, be_root_pool, ZFS_TYPE_DATASET)) == NULL) {
		be_print_err(gettext("be_remove_menu: "
		    "failed to open pool dataset for %s: %s"),
		    be_root_pool, libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Check to see if the pool's dataset is mounted. If it isn't we'll
	 * attempt to mount it.
	 */
	if ((ret = be_mount_pool(zhp, &ptmp_mntpnt, &orig_mntpnt,
	    &pool_mounted)) != BE_SUCCESS) {
		be_print_err(gettext("be_remove_menu: pool dataset "
		    "(%s) could not be mounted\n"), be_root_pool);
		ZFS_CLOSE(zhp);
		return (ret);
	}

	/*
	 * Get the mountpoint for the root pool dataset.
	 */
	if (!zfs_is_mounted(zhp, &pool_mntpnt)) {
		be_print_err(gettext("be_remove_menu: pool "
		    "dataset (%s) is not mounted. Can't set "
		    "the default BE in the grub menu.\n"), be_root_pool);
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	/* Get path to boot menu */
	(void) strlcpy(menu, pool_mntpnt, sizeof (menu));

	/*
	 * Check to see if this system supports grub
	 */
	if (be_has_grub())
		(void) strlcat(menu, BE_GRUB_MENU, sizeof (menu));
	else
		(void) strlcat(menu, BE_SPARC_MENU, sizeof (menu));

	/* Get handle to boot menu file */
	if ((ret = be_open_menu(be_root_pool, menu, &menu_fp, "r",
	    B_TRUE)) != BE_SUCCESS) {
		goto cleanup;
	} else if (menu_fp == NULL) {
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	free(pool_mntpnt);
	pool_mntpnt = NULL;

	/* Grab the stats of the original menu file */
	if (stat(menu, &sb) != 0) {
		err = errno;
		be_print_err(gettext("be_remove_menu: "
		    "failed to stat file %s: %s\n"), menu, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	/* Create a tmp file for the modified menu.lst */
	tmp_menu_len = strlen(menu) + 7;
	if ((tmp_menu = (char *)malloc(tmp_menu_len)) == NULL) {
		be_print_err(gettext("be_remove_menu: malloc failed\n"));
		ret = BE_ERR_NOMEM;
		goto cleanup;
	}
	(void) memset(tmp_menu, 0, tmp_menu_len);
	(void) strlcpy(tmp_menu, menu, tmp_menu_len);
	(void) strlcat(tmp_menu, "XXXXXX", tmp_menu_len);
	if ((fd = mkstemp(tmp_menu)) == -1) {
		err = errno;
		be_print_err(gettext("be_remove_menu: mkstemp failed\n"));
		ret = errno_to_be_err(err);
		free(tmp_menu);
		tmp_menu = NULL;
		goto cleanup;
	}
	if ((tmp_menu_fp = fdopen(fd, "w")) == NULL) {
		err = errno;
		be_print_err(gettext("be_remove_menu: "
		    "could not open tmp file for write: %s\n"), strerror(err));
		(void) close(fd);
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	while (fgets(menu_buf, BUFSIZ, menu_fp)) {
		char tline [BUFSIZ];
		char *tok = NULL;

		(void) strlcpy(tline, menu_buf, sizeof (tline));

		/* Tokenize line */
		tok = strtok(tline, BE_WHITE_SPACE);

		if (tok == NULL || tok[0] == '#') {
			/* Found empty line or comment line */
			if (do_buffer) {
				/* Buffer this line */
				if ((buffer = (char **)realloc(buffer,
				    sizeof (char *)*(nlines + 1))) == NULL) {
					ret = BE_ERR_NOMEM;
					goto cleanup;
				}
				if ((buffer[nlines++] = strdup(menu_buf))
				    == NULL) {
					ret = BE_ERR_NOMEM;
					goto cleanup;
				}

			} else if (write || strncmp(menu_buf, BE_GRUB_COMMENT,
			    strlen(BE_GRUB_COMMENT)) != 0) {
				/* Write this line out */
				(void) fputs(menu_buf, tmp_menu_fp);
			}
		} else if (strcmp(tok, "default") == 0) {
			/*
			 * Record what 'default' is set to because we might
			 * need to adjust this upon deleting an entry.
			 */
			tok = strtok(NULL, BE_WHITE_SPACE);

			if (tok != NULL) {
				default_entry = atoi(tok);
			}

			(void) fputs(menu_buf, tmp_menu_fp);
		} else if (strcmp(tok, "title") == 0) {
			/*
			 * If we've reached a 'title' line and do_buffer is
			 * is true, that means we've just buffered an entire
			 * entry without finding a 'bootfs' directive.  We
			 * need to write that entry out and keep searching.
			 */
			if (do_buffer) {
				for (i = 0; i < nlines; i++) {
					(void) fputs(buffer[i], tmp_menu_fp);
					free(buffer[i]);
				}
				free(buffer);
				buffer = NULL;
				nlines = 0;
			}

			/*
			 * Turn writing off and buffering on, and increment
			 * our entry counter.
			 */
			write = B_FALSE;
			do_buffer = B_TRUE;
			entry_cnt++;

			/* Buffer this 'title' line */
			if ((buffer = (char **)realloc(buffer,
			    sizeof (char *)*(nlines + 1))) == NULL) {
				ret = BE_ERR_NOMEM;
				goto cleanup;
			}
			if ((buffer[nlines++] = strdup(menu_buf)) == NULL) {
				ret = BE_ERR_NOMEM;
				goto cleanup;
			}

		} else if (strcmp(tok, "bootfs") == 0) {
			char *bootfs = NULL;

			/*
			 * Found a 'bootfs' line.  See if it matches the
			 * BE we're looking for.
			 */
			if ((bootfs = strtok(NULL, BE_WHITE_SPACE)) == NULL ||
			    strcmp(bootfs, be_root_ds) != 0) {
				/*
				 * Either there's nothing after the 'bootfs'
				 * or this is not the BE we're looking for,
				 * write out the line(s) we've buffered since
				 * finding the title.
				 */
				for (i = 0; i < nlines; i++) {
					(void) fputs(buffer[i], tmp_menu_fp);
					free(buffer[i]);
				}
				free(buffer);
				buffer = NULL;
				nlines = 0;

				/*
				 * Turn writing back on, and turn off buffering
				 * since this isn't the entry we're looking
				 * for.
				 */
				write = B_TRUE;
				do_buffer = B_FALSE;

				/* Write this 'bootfs' line out. */
				(void) fputs(menu_buf, tmp_menu_fp);
			} else {
				/*
				 * Found the entry we're looking for.
				 * Record its entry number, increment the
				 * number of entries we've deleted, and turn
				 * writing off.  Also, throw away the lines
				 * we've buffered for this entry so far, we
				 * don't need them.
				 */
				entry_del = entry_cnt - 1;
				num_entry_del++;
				write = B_FALSE;
				do_buffer = B_FALSE;

				for (i = 0; i < nlines; i++) {
					free(buffer[i]);
				}
				free(buffer);
				buffer = NULL;
				nlines = 0;
			}
		} else {
			if (do_buffer) {
				/* Buffer this line */
				if ((buffer = (char **)realloc(buffer,
				    sizeof (char *)*(nlines + 1))) == NULL) {
					ret = BE_ERR_NOMEM;
					goto cleanup;
				}
				if ((buffer[nlines++] = strdup(menu_buf))
				    == NULL) {
					ret = BE_ERR_NOMEM;
					goto cleanup;
				}
			} else if (write) {
				/* Write this line out */
				(void) fputs(menu_buf, tmp_menu_fp);
			}
		}
	}

	(void) fclose(menu_fp);
	menu_fp = NULL;
	(void) fclose(tmp_menu_fp);
	tmp_menu_fp = NULL;

	/* Copy the modified menu.lst into place */
	if (rename(tmp_menu, menu) != 0) {
		err = errno;
		be_print_err(gettext("be_remove_menu: "
		    "failed to rename file %s to %s: %s\n"),
		    tmp_menu, menu, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}
	free(tmp_menu);
	tmp_menu = NULL;

	/*
	 * If we've removed an entry, see if we need to
	 * adjust the default value in the menu.lst.  If the
	 * entry we've deleted comes before the default entry
	 * we need to adjust the default value accordingly.
	 *
	 * be_has_grub is used here to check to see if this system
	 * supports grub.
	 */
	if (be_has_grub() && num_entry_del > 0) {
		if (entry_del <= default_entry) {
			default_entry = default_entry - num_entry_del;
			if (default_entry < 0)
				default_entry = 0;

			/*
			 * Adjust the default value by rewriting the
			 * menu.lst file.  This may be overkill, but to
			 * preserve the location of the 'default' entry
			 * in the file, we need to do this.
			 */

			/* Get handle to boot menu file */
			if ((menu_fp = fopen(menu, "r")) == NULL) {
				err = errno;
				be_print_err(gettext("be_remove_menu: "
				    "failed to open menu.lst (%s): %s\n"),
				    menu, strerror(err));
				ret = errno_to_be_err(err);
				goto cleanup;
			}

			/* Create a tmp file for the modified menu.lst */
			tmp_menu_len = strlen(menu) + 7;
			if ((tmp_menu = (char *)malloc(tmp_menu_len))
			    == NULL) {
				be_print_err(gettext("be_remove_menu: "
				    "malloc failed\n"));
				ret = BE_ERR_NOMEM;
				goto cleanup;
			}
			(void) memset(tmp_menu, 0, tmp_menu_len);
			(void) strlcpy(tmp_menu, menu, tmp_menu_len);
			(void) strlcat(tmp_menu, "XXXXXX", tmp_menu_len);
			if ((fd = mkstemp(tmp_menu)) == -1) {
				err = errno;
				be_print_err(gettext("be_remove_menu: "
				    "mkstemp failed: %s\n"), strerror(err));
				ret = errno_to_be_err(err);
				free(tmp_menu);
				tmp_menu = NULL;
				goto cleanup;
			}
			if ((tmp_menu_fp = fdopen(fd, "w")) == NULL) {
				err = errno;
				be_print_err(gettext("be_remove_menu: "
				    "could not open tmp file for write: %s\n"),
				    strerror(err));
				(void) close(fd);
				ret = errno_to_be_err(err);
				goto cleanup;
			}

			while (fgets(menu_buf, BUFSIZ, menu_fp)) {
				char tline [BUFSIZ];
				char *tok = NULL;

				(void) strlcpy(tline, menu_buf, sizeof (tline));

				/* Tokenize line */
				tok = strtok(tline, BE_WHITE_SPACE);

				if (tok == NULL) {
					/* Found empty line, write it out */
					(void) fputs(menu_buf, tmp_menu_fp);
				} else if (strcmp(tok, "default") == 0) {
					/* Found the default line, adjust it */
					(void) snprintf(tline, sizeof (tline),
					    "default %d\n", default_entry);

					(void) fputs(tline, tmp_menu_fp);
				} else {
					/* Pass through all other lines */
					(void) fputs(menu_buf, tmp_menu_fp);
				}
			}

			(void) fclose(menu_fp);
			menu_fp = NULL;
			(void) fclose(tmp_menu_fp);
			tmp_menu_fp = NULL;

			/* Copy the modified menu.lst into place */
			if (rename(tmp_menu, menu) != 0) {
				err = errno;
				be_print_err(gettext("be_remove_menu: "
				    "failed to rename file %s to %s: %s\n"),
				    tmp_menu, menu, strerror(err));
				ret = errno_to_be_err(err);
				goto cleanup;
			}

			free(tmp_menu);
			tmp_menu = NULL;
		}
	}

	/* Set the perms and ownership of the updated file */
	if (chmod(menu, sb.st_mode) != 0) {
		err = errno;
		be_print_err(gettext("be_remove_menu: "
		    "failed to chmod %s: %s\n"), menu, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}
	if (chown(menu, sb.st_uid, sb.st_gid) != 0) {
		err = errno;
		be_print_err(gettext("be_remove_menu: "
		    "failed to chown %s: %s\n"), menu, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}

cleanup:
	if (pool_mounted) {
		int err = BE_SUCCESS;
		err = be_unmount_pool(zhp, ptmp_mntpnt, orig_mntpnt);
		if (ret == BE_SUCCESS)
			ret = err;
		free(orig_mntpnt);
		free(ptmp_mntpnt);
	}
	ZFS_CLOSE(zhp);

	free(buffer);
	if (menu_fp != NULL)
		(void) fclose(menu_fp);
	if (tmp_menu_fp != NULL)
		(void) fclose(tmp_menu_fp);
	if (tmp_menu != NULL) {
		(void) unlink(tmp_menu);
		free(tmp_menu);
	}

	return (ret);
}

/*
 * Function:	be_default_grub_bootfs
 * Description:	This function returns the dataset in the default entry of
 *		the grub menu. If no default entry is found with a valid bootfs
 *		entry NULL is returned.
 * Parameters:
 *		be_root_pool - This is the name of the root pool where the
 *			       grub menu can be found.
 *              def_bootfs - This is used to pass back the bootfs string. On
 *				error NULL is returned here.
 * Returns:
 *		Success - BE_SUCCESS is returned.
 *		Failure - a be_errno_t is returned.
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_default_grub_bootfs(const char *be_root_pool, char **def_bootfs)
{
	zfs_handle_t	*zhp = NULL;
	char		grub_file[MAXPATHLEN];
	FILE		*menu_fp;
	char		line[BUFSIZ];
	char		*pool_mntpnt = NULL;
	char		*ptmp_mntpnt = NULL;
	char		*orig_mntpnt = NULL;
	int		default_entry = 0, entries = 0;
	int		found_default = 0;
	int		ret = BE_SUCCESS;
	boolean_t	pool_mounted = B_FALSE;

	errno = 0;

	/*
	 * Check to see if this system supports grub
	 */
	if (!be_has_grub()) {
		be_print_err(gettext("be_default_grub_bootfs: operation "
		    "not supported on this architecture\n"));
		return (BE_ERR_NOTSUP);
	}

	*def_bootfs = NULL;

	/* Get handle to pool dataset */
	if ((zhp = zfs_open(g_zfs, be_root_pool, ZFS_TYPE_DATASET)) == NULL) {
		be_print_err(gettext("be_default_grub_bootfs: "
		    "failed to open pool dataset for %s: %s"),
		    be_root_pool, libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Check to see if the pool's dataset is mounted. If it isn't we'll
	 * attempt to mount it.
	 */
	if ((ret = be_mount_pool(zhp, &ptmp_mntpnt, &orig_mntpnt,
	    &pool_mounted)) != BE_SUCCESS) {
		be_print_err(gettext("be_default_grub_bootfs: pool dataset "
		    "(%s) could not be mounted\n"), be_root_pool);
		ZFS_CLOSE(zhp);
		return (ret);
	}

	/*
	 * Get the mountpoint for the root pool dataset.
	 */
	if (!zfs_is_mounted(zhp, &pool_mntpnt)) {
		be_print_err(gettext("be_default_grub_bootfs: failed "
		    "to get mount point for the root pool. Can't set "
		    "the default BE in the grub menu.\n"));
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	(void) snprintf(grub_file, MAXPATHLEN, "%s%s",
	    pool_mntpnt, BE_GRUB_MENU);

	if ((ret = be_open_menu((char *)be_root_pool, grub_file,
	    &menu_fp, "r", B_FALSE)) != BE_SUCCESS) {
		goto cleanup;
	} else if (menu_fp == NULL) {
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	free(pool_mntpnt);
	pool_mntpnt = NULL;

	while (fgets(line, BUFSIZ, menu_fp)) {
		char *tok = strtok(line, BE_WHITE_SPACE);

		if (tok != NULL && tok[0] != '#') {
			if (!found_default) {
				if (strcmp(tok, "default") == 0) {
					tok = strtok(NULL, BE_WHITE_SPACE);
					if (tok != NULL) {
						default_entry = atoi(tok);
						rewind(menu_fp);
						found_default = 1;
					}
				}
				continue;
			}
			if (strcmp(tok, "title") == 0) {
				entries++;
			} else if (default_entry == entries - 1) {
				if (strcmp(tok, "bootfs") == 0) {
					tok = strtok(NULL, BE_WHITE_SPACE);
					(void) fclose(menu_fp);

					if (tok == NULL) {
						ret = BE_SUCCESS;
						goto cleanup;
					}

					if ((*def_bootfs = strdup(tok)) !=
					    NULL) {
						ret = BE_SUCCESS;
						goto cleanup;
					}
					be_print_err(gettext(
					    "be_default_grub_bootfs: "
					    "memory allocation failed\n"));
					ret = BE_ERR_NOMEM;
					goto cleanup;
				}
			} else if (default_entry < entries - 1) {
				/*
				 * no bootfs entry for the default entry.
				 */
				break;
			}
		}
	}
	(void) fclose(menu_fp);

cleanup:
	if (pool_mounted) {
		int err = BE_SUCCESS;
		err = be_unmount_pool(zhp, ptmp_mntpnt, orig_mntpnt);
		if (ret == BE_SUCCESS)
			ret = err;
		free(orig_mntpnt);
		free(ptmp_mntpnt);
	}
	ZFS_CLOSE(zhp);
	return (ret);
}

/*
 * Function:	be_change_grub_default
 * Description:	This function takes two parameters. These are the name of
 *		the BE we want to have as the default booted in the grub
 *		menu and the root pool where the path to the grub menu exists.
 *		The code takes this and finds the BE's entry in the grub menu
 *		and changes the default entry to point to that entry in the
 *		list.
 * Parameters:
 *		be_name - This is the name of the BE wanted as the default
 *			for the next boot.
 *		be_root_pool - This is the name of the root pool where the
 *			grub menu can be found.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_change_grub_default(char *be_name, char *be_root_pool)
{
	zfs_handle_t	*zhp = NULL;
	char	grub_file[MAXPATHLEN];
	char	*temp_grub;
	char	*pool_mntpnt = NULL;
	char	*ptmp_mntpnt = NULL;
	char	*orig_mntpnt = NULL;
	char	line[BUFSIZ];
	char	temp_line[BUFSIZ];
	char	be_root_ds[MAXPATHLEN];
	FILE	*grub_fp = NULL;
	FILE	*temp_fp = NULL;
	struct stat	sb;
	int	temp_grub_len = 0;
	int	fd, entries = 0;
	int	err = 0;
	int	ret = BE_SUCCESS;
	boolean_t	found_default = B_FALSE;
	boolean_t	pool_mounted = B_FALSE;

	errno = 0;

	/*
	 * Check to see if this system supports grub
	 */
	if (!be_has_grub()) {
		be_print_err(gettext("be_change_grub_default: operation "
		    "not supported on this architecture\n"));
		return (BE_ERR_NOTSUP);
	}

	/* Generate string for BE's root dataset */
	be_make_root_ds(be_root_pool, be_name, be_root_ds, sizeof (be_root_ds));

	/* Get handle to pool dataset */
	if ((zhp = zfs_open(g_zfs, be_root_pool, ZFS_TYPE_DATASET)) == NULL) {
		be_print_err(gettext("be_change_grub_default: "
		    "failed to open pool dataset for %s: %s"),
		    be_root_pool, libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Check to see if the pool's dataset is mounted. If it isn't we'll
	 * attempt to mount it.
	 */
	if ((ret = be_mount_pool(zhp, &ptmp_mntpnt, &orig_mntpnt,
	    &pool_mounted)) != BE_SUCCESS) {
		be_print_err(gettext("be_change_grub_default: pool dataset "
		    "(%s) could not be mounted\n"), be_root_pool);
		ZFS_CLOSE(zhp);
		return (ret);
	}

	/*
	 * Get the mountpoint for the root pool dataset.
	 */
	if (!zfs_is_mounted(zhp, &pool_mntpnt)) {
		be_print_err(gettext("be_change_grub_default: pool "
		    "dataset (%s) is not mounted. Can't set "
		    "the default BE in the grub menu.\n"), be_root_pool);
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	(void) snprintf(grub_file, MAXPATHLEN, "%s%s",
	    pool_mntpnt, BE_GRUB_MENU);

	if ((ret = be_open_menu(be_root_pool, grub_file,
	    &grub_fp, "r+", B_TRUE)) != BE_SUCCESS) {
		goto cleanup;
	} else if (grub_fp == NULL) {
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	free(pool_mntpnt);
	pool_mntpnt = NULL;

	/* Grab the stats of the original menu file */
	if (stat(grub_file, &sb) != 0) {
		err = errno;
		be_print_err(gettext("be_change_grub_default: "
		    "failed to stat file %s: %s\n"), grub_file, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	/* Create a tmp file for the modified menu.lst */
	temp_grub_len = strlen(grub_file) + 7;
	if ((temp_grub = (char *)malloc(temp_grub_len)) == NULL) {
		be_print_err(gettext("be_change_grub_default: "
		    "malloc failed\n"));
		ret = BE_ERR_NOMEM;
		goto cleanup;
	}
	(void) memset(temp_grub, 0, temp_grub_len);
	(void) strlcpy(temp_grub, grub_file, temp_grub_len);
	(void) strlcat(temp_grub, "XXXXXX", temp_grub_len);
	if ((fd = mkstemp(temp_grub)) == -1) {
		err = errno;
		be_print_err(gettext("be_change_grub_default: "
		    "mkstemp failed: %s\n"), strerror(err));
		ret = errno_to_be_err(err);
		free(temp_grub);
		temp_grub = NULL;
		goto cleanup;
	}
	if ((temp_fp = fdopen(fd, "w")) == NULL) {
		err = errno;
		be_print_err(gettext("be_change_grub_default: "
		    "failed to open %s file: %s\n"),
		    temp_grub, strerror(err));
		(void) close(fd);
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	while (fgets(line, BUFSIZ, grub_fp)) {
		char *tok = strtok(line, BE_WHITE_SPACE);

		if (tok == NULL || tok[0] == '#') {
			continue;
		} else if (strcmp(tok, "title") == 0) {
			entries++;
			continue;
		} else if (strcmp(tok, "bootfs") == 0) {
			char *bootfs = strtok(NULL, BE_WHITE_SPACE);
			if (bootfs == NULL)
				continue;

			if (strcmp(bootfs, be_root_ds) == 0) {
				found_default = B_TRUE;
				break;
			}
		}
	}

	if (!found_default) {
		be_print_err(gettext("be_change_grub_default: failed "
		    "to find entry for %s in the grub menu\n"),
		    be_name);
		ret = BE_ERR_BE_NOENT;
		goto cleanup;
	}

	rewind(grub_fp);

	while (fgets(line, BUFSIZ, grub_fp)) {
		char *tok = NULL;

		(void) strncpy(temp_line, line, BUFSIZ);

		if ((tok = strtok(temp_line, BE_WHITE_SPACE)) != NULL &&
		    strcmp(tok, "default") == 0) {
			(void) snprintf(temp_line, BUFSIZ, "default %d\n",
			    entries - 1 >= 0 ? entries - 1 : 0);
			(void) fputs(temp_line, temp_fp);
		} else {
			(void) fputs(line, temp_fp);
		}
	}

	(void) fclose(grub_fp);
	grub_fp = NULL;
	(void) fclose(temp_fp);
	temp_fp = NULL;

	if (rename(temp_grub, grub_file) != 0) {
		err = errno;
		be_print_err(gettext("be_change_grub_default: "
		    "failed to rename file %s to %s: %s\n"),
		    temp_grub, grub_file, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}
	free(temp_grub);
	temp_grub = NULL;

	/* Set the perms and ownership of the updated file */
	if (chmod(grub_file, sb.st_mode) != 0) {
		err = errno;
		be_print_err(gettext("be_change_grub_default: "
		    "failed to chmod %s: %s\n"), grub_file, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}
	if (chown(grub_file, sb.st_uid, sb.st_gid) != 0) {
		err = errno;
		be_print_err(gettext("be_change_grub_default: "
		    "failed to chown %s: %s\n"), grub_file, strerror(err));
		ret = errno_to_be_err(err);
	}

cleanup:
	if (pool_mounted) {
		int err = BE_SUCCESS;
		err = be_unmount_pool(zhp, ptmp_mntpnt, orig_mntpnt);
		if (ret == BE_SUCCESS)
			ret = err;
		free(orig_mntpnt);
		free(ptmp_mntpnt);
	}
	ZFS_CLOSE(zhp);
	if (grub_fp != NULL)
		(void) fclose(grub_fp);
	if (temp_fp != NULL)
		(void) fclose(temp_fp);
	if (temp_grub != NULL) {
		(void) unlink(temp_grub);
		free(temp_grub);
	}

	return (ret);
}

/*
 * Function:	be_update_menu
 * Description:	This function is used by be_rename to change the BE name in
 *		an existing entry in the grub menu to the new name of the BE.
 * Parameters:
 *		be_orig_name - the original name of the BE
 *		be_new_name - the new name the BE is being renameed to.
 *		be_root_pool - The pool which contains the grub menu
 *		boot_pool - the pool where the BE is, if different than
 *			the pool containing the boot menu.  If this is
 *			NULL it will be set to be_root_pool.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_update_menu(char *be_orig_name, char *be_new_name, char *be_root_pool,
    char *boot_pool)
{
	zfs_handle_t *zhp = NULL;
	char menu_file[MAXPATHLEN];
	char be_root_ds[MAXPATHLEN];
	char be_new_root_ds[MAXPATHLEN];
	char line[BUFSIZ];
	char *pool_mntpnt = NULL;
	char *ptmp_mntpnt = NULL;
	char *orig_mntpnt = NULL;
	char *temp_menu = NULL;
	FILE *menu_fp = NULL;
	FILE *new_fp = NULL;
	struct stat sb;
	int temp_menu_len = 0;
	int tmp_fd;
	int ret = BE_SUCCESS;
	int err = 0;
	boolean_t pool_mounted = B_FALSE;

	errno = 0;

	if (boot_pool == NULL)
		boot_pool = be_root_pool;

	if ((zhp = zfs_open(g_zfs, be_root_pool, ZFS_TYPE_DATASET)) == NULL) {
		be_print_err(gettext("be_update_menu: failed to open "
		    "pool dataset for %s: %s\n"), be_root_pool,
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	/*
	 * Check to see if the pool's dataset is mounted. If it isn't we'll
	 * attempt to mount it.
	 */
	if ((ret = be_mount_pool(zhp, &ptmp_mntpnt, &orig_mntpnt,
	    &pool_mounted)) != BE_SUCCESS) {
		be_print_err(gettext("be_update_menu: pool dataset "
		    "(%s) could not be mounted\n"), be_root_pool);
		ZFS_CLOSE(zhp);
		return (ret);
	}

	/*
	 * Get the mountpoint for the root pool dataset.
	 */
	if (!zfs_is_mounted(zhp, &pool_mntpnt)) {
		be_print_err(gettext("be_update_menu: failed "
		    "to get mount point for the root pool. Can't set "
		    "the default BE in the grub menu.\n"));
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	/*
	 * Check to see if this system supports grub
	 */
	if (be_has_grub()) {
		(void) snprintf(menu_file, sizeof (menu_file),
		    "%s%s", pool_mntpnt, BE_GRUB_MENU);
	} else {
		(void) snprintf(menu_file, sizeof (menu_file),
		    "%s%s", pool_mntpnt, BE_SPARC_MENU);
	}

	be_make_root_ds(be_root_pool, be_orig_name, be_root_ds,
	    sizeof (be_root_ds));
	be_make_root_ds(be_root_pool, be_new_name, be_new_root_ds,
	    sizeof (be_new_root_ds));

	if ((ret = be_open_menu(be_root_pool, menu_file,
	    &menu_fp, "r", B_TRUE)) != BE_SUCCESS) {
		goto cleanup;
	} else if (menu_fp == NULL) {
		ret = BE_ERR_NO_MENU;
		goto cleanup;
	}

	free(pool_mntpnt);
	pool_mntpnt = NULL;

	/* Grab the stat of the original menu file */
	if (stat(menu_file, &sb) != 0) {
		err = errno;
		be_print_err(gettext("be_update_menu: "
		    "failed to stat file %s: %s\n"), menu_file, strerror(err));
		(void) fclose(menu_fp);
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	/* Create tmp file for modified menu.lst */
	temp_menu_len = strlen(menu_file) + 7;
	if ((temp_menu = (char *)malloc(temp_menu_len))
	    == NULL) {
		be_print_err(gettext("be_update_menu: "
		    "malloc failed\n"));
		(void) fclose(menu_fp);
		ret = BE_ERR_NOMEM;
		goto cleanup;
	}
	(void) memset(temp_menu, 0, temp_menu_len);
	(void) strlcpy(temp_menu, menu_file, temp_menu_len);
	(void) strlcat(temp_menu, "XXXXXX", temp_menu_len);
	if ((tmp_fd = mkstemp(temp_menu)) == -1) {
		err = errno;
		be_print_err(gettext("be_update_menu: "
		    "mkstemp failed: %s\n"), strerror(err));
		(void) fclose(menu_fp);
		free(temp_menu);
		ret = errno_to_be_err(err);
		goto cleanup;
	}
	if ((new_fp = fdopen(tmp_fd, "w")) == NULL) {
		err = errno;
		be_print_err(gettext("be_update_menu: "
		    "fdopen failed: %s\n"), strerror(err));
		(void) close(tmp_fd);
		(void) fclose(menu_fp);
		free(temp_menu);
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	while (fgets(line, BUFSIZ, menu_fp)) {
		char tline[BUFSIZ];
		char new_line[BUFSIZ];
		char *c = NULL;

		(void) strlcpy(tline, line, sizeof (tline));

		/* Tokenize line */
		c = strtok(tline, BE_WHITE_SPACE);

		if (c == NULL) {
			/* Found empty line, write it out. */
			(void) fputs(line, new_fp);
		} else if (c[0] == '#') {
			/* Found a comment line, write it out. */
			(void) fputs(line, new_fp);
		} else if (strcmp(c, "title") == 0) {
			char *name = NULL;
			char *desc = NULL;

			/*
			 * Found a 'title' line, parse out BE name or
			 * the description.
			 */
			name = strtok(NULL, BE_WHITE_SPACE);

			if (name == NULL) {
				/*
				 * Nothing after 'title', just push
				 * this line through
				 */
				(void) fputs(line, new_fp);
			} else {
				/*
				 * Grab the remainder of the title which
				 * could be a multi worded description
				 */
				desc = strtok(NULL, "\n");

				if (strcmp(name, be_orig_name) == 0) {
					/*
					 * The first token of the title is
					 * the old BE name, replace it with
					 * the new one, and write it out
					 * along with the remainder of
					 * description if there is one.
					 */
					if (desc) {
						(void) snprintf(new_line,
						    sizeof (new_line),
						    "title %s %s\n",
						    be_new_name, desc);
					} else {
						(void) snprintf(new_line,
						    sizeof (new_line),
						    "title %s\n", be_new_name);
					}

					(void) fputs(new_line, new_fp);
				} else {
					(void) fputs(line, new_fp);
				}
			}
		} else if (strcmp(c, "bootfs") == 0) {
			/*
			 * Found a 'bootfs' line, parse out the BE root
			 * dataset value.
			 */
			char *root_ds = strtok(NULL, BE_WHITE_SPACE);

			if (root_ds == NULL) {
				/*
				 * Nothing after 'bootfs', just push
				 * this line through
				 */
				(void) fputs(line, new_fp);
			} else {
				/*
				 * If this bootfs is the one we're renaming,
				 * write out the new root dataset value
				 */
				if (strcmp(root_ds, be_root_ds) == 0) {
					(void) snprintf(new_line,
					    sizeof (new_line), "bootfs %s\n",
					    be_new_root_ds);

					(void) fputs(new_line, new_fp);
				} else {
					(void) fputs(line, new_fp);
				}
			}
		} else {
			/*
			 * Found some other line we don't care
			 * about, write it out.
			 */
			(void) fputs(line, new_fp);
		}
	}

	(void) fclose(menu_fp);
	(void) fclose(new_fp);
	(void) close(tmp_fd);

	if (rename(temp_menu, menu_file) != 0) {
		err = errno;
		be_print_err(gettext("be_update_menu: "
		    "failed to rename file %s to %s: %s\n"),
		    temp_menu, menu_file, strerror(err));
		ret = errno_to_be_err(err);
	}
	free(temp_menu);

	/* Set the perms and ownership of the updated file */
	if (chmod(menu_file, sb.st_mode) != 0) {
		err = errno;
		be_print_err(gettext("be_update_menu: "
		    "failed to chmod %s: %s\n"), menu_file, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}
	if (chown(menu_file, sb.st_uid, sb.st_gid) != 0) {
		err = errno;
		be_print_err(gettext("be_update_menu: "
		    "failed to chown %s: %s\n"), menu_file, strerror(err));
		ret = errno_to_be_err(err);
	}

cleanup:
	if (pool_mounted) {
		int err = BE_SUCCESS;
		err = be_unmount_pool(zhp, ptmp_mntpnt, orig_mntpnt);
		if (ret == BE_SUCCESS)
			ret = err;
		free(orig_mntpnt);
		free(ptmp_mntpnt);
	}
	ZFS_CLOSE(zhp);
	return (ret);
}

/*
 * Function:	be_has_menu_entry
 * Description:	Checks to see if the BEs root dataset has an entry in the grub
 *		menu.
 * Parameters:
 *		be_dataset - The root dataset of the BE
 *		be_root_pool - The pool which contains the boot menu
 *		entry - A pointer the the entry number of the BE if found.
 * Returns:
 *		B_TRUE - Success
 *		B_FALSE - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
boolean_t
be_has_menu_entry(char *be_dataset, char *be_root_pool, int *entry)
{
	zfs_handle_t *zhp = NULL;
	char		menu_file[MAXPATHLEN];
	FILE		*menu_fp;
	char		line[BUFSIZ];
	char		*last;
	char		*rpool_mntpnt = NULL;
	char		*ptmp_mntpnt = NULL;
	char		*orig_mntpnt = NULL;
	int		ent_num = 0;
	boolean_t	ret = 0;
	boolean_t	pool_mounted = B_FALSE;


	/*
	 * Check to see if this system supports grub
	 */
	if ((zhp = zfs_open(g_zfs, be_root_pool, ZFS_TYPE_DATASET)) == NULL) {
		be_print_err(gettext("be_has_menu_entry: failed to open "
		    "pool dataset for %s: %s\n"), be_root_pool,
		    libzfs_error_description(g_zfs));
		return (B_FALSE);
	}

	/*
	 * Check to see if the pool's dataset is mounted. If it isn't we'll
	 * attempt to mount it.
	 */
	if (be_mount_pool(zhp, &ptmp_mntpnt, &orig_mntpnt,
	    &pool_mounted) != 0) {
		be_print_err(gettext("be_has_menu_entry: pool dataset "
		    "(%s) could not be mounted\n"), be_root_pool);
		ZFS_CLOSE(zhp);
		return (B_FALSE);
	}

	/*
	 * Get the mountpoint for the root pool dataset.
	 */
	if (!zfs_is_mounted(zhp, &rpool_mntpnt)) {
		be_print_err(gettext("be_has_menu_entry: pool "
		    "dataset (%s) is not mounted. Can't set "
		    "the default BE in the grub menu.\n"), be_root_pool);
		ret = B_FALSE;
		goto cleanup;
	}

	if (be_has_grub()) {
		(void) snprintf(menu_file, MAXPATHLEN, "/%s%s",
		    rpool_mntpnt, BE_GRUB_MENU);
	} else {
		(void) snprintf(menu_file, MAXPATHLEN, "/%s%s",
		    rpool_mntpnt, BE_SPARC_MENU);
	}

	if (be_open_menu(be_root_pool, menu_file, &menu_fp, "r",
	    B_FALSE) != 0) {
		ret = B_FALSE;
		goto cleanup;
	} else if (menu_fp == NULL) {
		ret = B_FALSE;
		goto cleanup;
	}

	free(rpool_mntpnt);
	rpool_mntpnt = NULL;

	while (fgets(line, BUFSIZ, menu_fp)) {
		char *tok = strtok_r(line, BE_WHITE_SPACE, &last);

		if (tok != NULL && tok[0] != '#') {
			if (strcmp(tok, "bootfs") == 0) {
				tok = strtok_r(last, BE_WHITE_SPACE, &last);
				if (tok != NULL && strcmp(tok,
				    be_dataset) == 0) {
					(void) fclose(menu_fp);
					/*
					 * The entry number needs to be
					 * decremented here because the title
					 * will always be the first line for
					 * an entry. Because of this we'll
					 * always be off by one entry when we
					 * check for bootfs.
					 */
					*entry = ent_num - 1;
					ret = B_TRUE;
					goto cleanup;
				}
			} else if (strcmp(tok, "title") == 0)
				ent_num++;
		}
	}

cleanup:
	if (pool_mounted) {
		(void) be_unmount_pool(zhp, ptmp_mntpnt, orig_mntpnt);
		free(orig_mntpnt);
		free(ptmp_mntpnt);
	}
	ZFS_CLOSE(zhp);
	(void) fclose(menu_fp);
	return (ret);
}

/*
 * Function:	be_update_vfstab
 * Description:	This function digs into a BE's vfstab and updates all
 *		entries with file systems listed in be_fs_list_data_t.
 *		The entry's root container dataset and be_name will be
 *		updated with the parameters passed in.
 * Parameters:
 *		be_name - name of BE to update
 *		old_rc_loc - dataset under which the root container dataset
 *			of the old BE resides in.
 *		new_rc_loc - dataset under which the root container dataset
 *			of the new BE resides in.
 *		fld - be_fs_list_data_t pointer providing the list of
 *			file systems to look for in vfstab.
 *		mountpoint - directory of where BE is currently mounted.
 *			If NULL, then BE is not currently mounted.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_update_vfstab(char *be_name, char *old_rc_loc, char *new_rc_loc,
    be_fs_list_data_t *fld, char *mountpoint)
{
	char		*tmp_mountpoint = NULL;
	char		alt_vfstab[MAXPATHLEN];
	int		ret = BE_SUCCESS, err = BE_SUCCESS;

	if (fld == NULL || fld->fs_list == NULL || fld->fs_num == 0)
		return (BE_SUCCESS);

	/* If BE not already mounted, mount the BE */
	if (mountpoint == NULL) {
		if ((ret = _be_mount(be_name, &tmp_mountpoint,
		    BE_MOUNT_FLAG_NO_ZONES)) != BE_SUCCESS) {
			be_print_err(gettext("be_update_vfstab: "
			    "failed to mount BE (%s)\n"), be_name);
			return (ret);
		}
	} else {
		tmp_mountpoint = mountpoint;
	}

	/* Get string for vfstab in the mounted BE. */
	(void) snprintf(alt_vfstab, sizeof (alt_vfstab), "%s/etc/vfstab",
	    tmp_mountpoint);

	/* Update the vfstab */
	ret = _update_vfstab(alt_vfstab, be_name, old_rc_loc, new_rc_loc,
	    fld);

	/* Unmount BE if we mounted it */
	if (mountpoint == NULL) {
		if ((err = _be_unmount(be_name, 0)) == BE_SUCCESS) {
			/* Remove temporary mountpoint */
			(void) rmdir(tmp_mountpoint);
		} else {
			be_print_err(gettext("be_update_vfstab: "
			    "failed to unmount BE %s mounted at %s\n"),
			    be_name, tmp_mountpoint);
			if (ret == BE_SUCCESS)
				ret = err;
		}

		free(tmp_mountpoint);
	}

	return (ret);
}

/*
 * Function:	be_update_zone_vfstab
 * Description:	This function digs into a zone BE's vfstab and updates all
 *		entries with file systems listed in be_fs_list_data_t.
 *		The entry's root container dataset and be_name will be
 *		updated with the parameters passed in.
 * Parameters:
 *		zhp - zfs_handle_t pointer to zone root dataset.
 *		be_name - name of zone BE to update
 *		old_rc_loc - dataset under which the root container dataset
 *			of the old zone BE resides in.
 *		new_rc_loc - dataset under which the root container dataset
 *			of the new zone BE resides in.
 *		fld - be_fs_list_data_t pointer providing the list of
 *			file systems to look for in vfstab.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_update_zone_vfstab(zfs_handle_t *zhp, char *be_name, char *old_rc_loc,
    char *new_rc_loc, be_fs_list_data_t *fld)
{
	be_mount_data_t		md = { 0 };
	be_unmount_data_t	ud = { 0 };
	char			alt_vfstab[MAXPATHLEN];
	boolean_t		mounted_here = B_FALSE;
	int			ret = BE_SUCCESS;

	/*
	 * If zone root not already mounted, mount it at a
	 * temporary location.
	 */
	if (!zfs_is_mounted(zhp, &md.altroot)) {
		/* Generate temporary mountpoint to mount zone root */
		if ((ret = be_make_tmp_mountpoint(&md.altroot)) != BE_SUCCESS) {
			be_print_err(gettext("be_update_zone_vfstab: "
			    "failed to make temporary mountpoint to "
			    "mount zone root\n"));
			return (ret);
		}

		if (be_mount_zone_root(zhp, &md) != BE_SUCCESS) {
			be_print_err(gettext("be_update_zone_vfstab: "
			    "failed to mount zone root %s\n"),
			    zfs_get_name(zhp));
			free(md.altroot);
			return (BE_ERR_MOUNT_ZONEROOT);
		}
		mounted_here = B_TRUE;
	}

	/* Get string from vfstab in the mounted zone BE */
	(void) snprintf(alt_vfstab, sizeof (alt_vfstab), "%s/etc/vfstab",
	    md.altroot);

	/* Update the vfstab */
	ret = _update_vfstab(alt_vfstab, be_name, old_rc_loc, new_rc_loc,
	    fld);

	/* Unmount zone root if we mounted it */
	if (mounted_here) {
		ud.force = B_TRUE;

		if (be_unmount_zone_root(zhp, &ud) == BE_SUCCESS) {
			/* Remove the temporary mountpoint */
			(void) rmdir(md.altroot);
		} else {
			be_print_err(gettext("be_update_zone_vfstab: "
			    "failed to unmount zone root %s from %s\n"),
			    zfs_get_name(zhp), md.altroot);
			if (ret == 0)
				ret = BE_ERR_UMOUNT_ZONEROOT;
		}
	}

	free(md.altroot);
	return (ret);
}

/*
 * Function:	be_auto_snap_name
 * Description:	Generate an auto snapshot name constructed based on the
 *		current date and time.  The auto snapshot name is of the form:
 *
 *			<date>-<time>
 *
 *		where <date> is in ISO standard format, so the resultant name
 *		is of the form:
 *
 *			%Y-%m-%d-%H:%M:%S
 *
 * Parameters:
 *		None
 * Returns:
 *		Success - pointer to auto generated snapshot name.  The name
 *			is allocated in heap storage so the caller is
 *			responsible for free'ing the name.
 *		Failure - NULL
 * Scope:
 *		Semi-private (library wide use only)
 */
char *
be_auto_snap_name(void)
{
	time_t		utc_tm = NULL;
	struct tm	*gmt_tm = NULL;
	char		gmt_time_str[64];
	char		*auto_snap_name = NULL;

	if (time(&utc_tm) == -1) {
		be_print_err(gettext("be_auto_snap_name: time() failed\n"));
		return (NULL);
	}

	if ((gmt_tm = gmtime(&utc_tm)) == NULL) {
		be_print_err(gettext("be_auto_snap_name: gmtime() failed\n"));
		return (NULL);
	}

	(void) strftime(gmt_time_str, sizeof (gmt_time_str), "%F-%T", gmt_tm);

	if ((auto_snap_name = strdup(gmt_time_str)) == NULL) {
		be_print_err(gettext("be_auto_snap_name: "
		    "memory allocation failed\n"));
		return (NULL);
	}

	return (auto_snap_name);
}

/*
 * Function:	be_auto_be_name
 * Description:	Generate an auto BE name constructed based on the BE name
 *		of the original BE being cloned.
 * Parameters:
 *		obe_name - name of the original BE being cloned.
 * Returns:
 *		Success - pointer to auto generated BE name.  The name
 *			is allocated in heap storage so the caller is
 *			responsible for free'ing the name.
 *		Failure - NULL
 * Scope:
 *		Semi-private (library wide use only)
 */
char *
be_auto_be_name(char *obe_name)
{
	return (be_get_auto_name(obe_name, NULL, B_FALSE));
}

/*
 * Function:	be_auto_zone_be_name
 * Description:	Generate an auto BE name for a zone constructed based on
 *              the BE name of the original zone BE being cloned.
 * Parameters:
 *              container_ds - container dataset for the zone.
 *		zbe_name - name of the original zone BE being cloned.
 * Returns:
 *		Success - pointer to auto generated BE name.  The name
 *			is allocated in heap storage so the caller is
 *			responsible for free'ing the name.
 *		Failure - NULL
 * Scope:
 *		Semi-private (library wide use only)
 */
char *
be_auto_zone_be_name(char *container_ds, char *zbe_name)
{
	return (be_get_auto_name(zbe_name, container_ds, B_TRUE));
}

/*
 * Function:	be_valid_be_name
 * Description:	Validates a BE name.
 * Parameters:
 *		be_name - name of BE to validate
 * Returns:
 *		B_TRUE - be_name is valid
 *		B_FALSE - be_name is invalid
 * Scope:
 *		Semi-private (library wide use only)
 */

boolean_t
be_valid_be_name(const char *be_name)
{
	const char	*c = NULL;
	struct be_defaults be_defaults;

	if (be_name == NULL)
		return (B_FALSE);

	be_get_defaults(&be_defaults);

	/*
	 * A BE name must not be a multi-level dataset name.  We also check
	 * that it does not contain the ' ' and '%' characters.  The ' ' is
	 * a valid character for datasets, however we don't allow that in a
	 * BE name.  The '%' is invalid, but zfs_name_valid() allows it for
	 * internal reasons, so we explicitly check for it here.
	 */
	c = be_name;
	while (*c != '\0' && *c != '/' && *c != ' ' && *c != '%')
		c++;

	if (*c != '\0')
		return (B_FALSE);

	/*
	 * The BE name must comply with a zfs dataset filesystem. We also
	 * verify its length to be < BE_NAME_MAX_LEN.
	 */
	if (!zfs_name_valid(be_name, ZFS_TYPE_FILESYSTEM) ||
	    strlen(be_name) > BE_NAME_MAX_LEN)
		return (B_FALSE);

	if (be_defaults.be_deflt_bename_starts_with[0] != '\0' &&
	    strstr(be_name, be_defaults.be_deflt_bename_starts_with) == NULL) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Function:	be_valid_auto_snap_name
 * Description:	This function checks that a snapshot name is a valid auto
 *		generated snapshot name.  A valid auto generated snapshot
 *		name is of the form:
 *
 *			%Y-%m-%d-%H:%M:%S
 *
 *		An older form of the auto generated snapshot name also
 *		included the snapshot's BE cleanup policy and a reserved
 *		field.  Those names will also be verified by this function.
 *
 *		Examples of valid auto snapshot names are:
 *
 *			2008-03-31-18:41:30
 *			2008-03-31-22:17:24
 *			<policy>:-:2008:04-05-09:12:55
 *			<policy>:-:2008:04-06-15:34:12
 *
 * Parameters:
 *		name - name of the snapshot to be validated.
 * Returns:
 *		B_TRUE - the name is a valid auto snapshot name.
 *		B_FALSE - the name is not a valid auto snapshot name.
 * Scope:
 *		Semi-private (library wide use only)
 */
boolean_t
be_valid_auto_snap_name(char *name)
{
	struct tm gmt_tm;

	char *policy = NULL;
	char *reserved = NULL;
	char *date = NULL;
	char *c = NULL;

	/* Validate the snapshot name by converting it into utc time */
	if (strptime(name, "%Y-%m-%d-%T", &gmt_tm) != NULL &&
	    (mktime(&gmt_tm) != -1)) {
		return (B_TRUE);
	}

	/*
	 * Validate the snapshot name against the older form of an
	 * auto generated snapshot name.
	 */
	policy = strdup(name);

	/*
	 * Get the first field from the snapshot name,
	 * which is the BE policy
	 */
	c = strchr(policy, ':');
	if (c == NULL) {
		free(policy);
		return (B_FALSE);
	}
	c[0] = '\0';

	/* Validate the policy name */
	if (!valid_be_policy(policy)) {
		free(policy);
		return (B_FALSE);
	}

	/* Get the next field, which is the reserved field. */
	if (c[1] == NULL || c[1] == '\0') {
		free(policy);
		return (B_FALSE);
	}
	reserved = c+1;
	c = strchr(reserved, ':');
	if (c == NULL) {
		free(policy);
		return (B_FALSE);
	}
	c[0] = '\0';

	/* Validate the reserved field */
	if (strcmp(reserved, "-") != 0) {
		free(policy);
		return (B_FALSE);
	}

	/* The remaining string should be the date field */
	if (c[1] == NULL || c[1] == '\0') {
		free(policy);
		return (B_FALSE);
	}
	date = c+1;

	/* Validate the date string by converting it into utc time */
	if (strptime(date, "%Y-%m-%d-%T", &gmt_tm) == NULL ||
	    (mktime(&gmt_tm) == -1)) {
		be_print_err(gettext("be_valid_auto_snap_name: "
		    "invalid auto snapshot name\n"));
		free(policy);
		return (B_FALSE);
	}

	free(policy);
	return (B_TRUE);
}

/*
 * Function:	be_default_policy
 * Description:	Temporary hardcoded policy support.  This function returns
 *		the default policy type to be used to create a BE or a BE
 *		snapshot.
 * Parameters:
 *		None
 * Returns:
 *		Name of default BE policy.
 * Scope:
 *		Semi-private (library wide use only)
 */
char *
be_default_policy(void)
{
	return (BE_PLCY_STATIC);
}

/*
 * Function:	valid_be_policy
 * Description:	Temporary hardcoded policy support.  This function valids
 *		whether a policy is a valid known policy or not.
 * Paramters:
 *		policy - name of policy to validate.
 * Returns:
 *		B_TRUE - policy is a valid.
 *		B_FALSE - policy is invalid.
 * Scope:
 *		Semi-private (library wide use only)
 */
boolean_t
valid_be_policy(char *policy)
{
	if (policy == NULL)
		return (B_FALSE);

	if (strcmp(policy, BE_PLCY_STATIC) == 0 ||
	    strcmp(policy, BE_PLCY_VOLATILE) == 0) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Function:	be_print_err
 * Description:	This function prints out error messages if do_print is
 *		set to B_TRUE or if the BE_PRINT_ERR environment variable
 *		is set to true.
 * Paramters:
 *		prnt_str - the string we wish to print and any arguments
 *		for the format of that string.
 * Returns:
 *		void
 * Scope:
 *		Semi-private (library wide use only)
 */
void
be_print_err(char *prnt_str, ...)
{
	va_list ap;
	char buf[BUFSIZ];
	char *env_buf;
	static boolean_t env_checked = B_FALSE;

	if (!env_checked) {
		if ((env_buf = getenv("BE_PRINT_ERR")) != NULL) {
			if (strcasecmp(env_buf, "true") == 0) {
				do_print = B_TRUE;
			}
		}
		env_checked = B_TRUE;
	}

	if (do_print) {
		va_start(ap, prnt_str);
		/* LINTED variable format specifier */
		(void) vsnprintf(buf, BUFSIZ, prnt_str, ap);
		(void) fputs(buf, stderr);
		va_end(ap);
	}
}

/*
 * Function:	be_find_current_be
 * Description:	Find the currently "active" BE. Fill in the
 * 		passed in be_transaction_data_t reference with the
 *		active BE's data.
 * Paramters:
 *		none
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errnot_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 * Notes:
 *		The caller is responsible for initializing the libzfs handle
 *		and freeing the memory used by the active be_name.
 */
int
be_find_current_be(be_transaction_data_t *bt)
{
	int	zret;

	if ((zret = zpool_iter(g_zfs, be_zpool_find_current_be_callback,
	    bt)) == 0) {
		be_print_err(gettext("be_find_current_be: failed to "
		    "find current BE name\n"));
		return (BE_ERR_BE_NOENT);
	} else if (zret < 0) {
		be_print_err(gettext("be_find_current_be: "
		    "zpool_iter failed: %s\n"),
		    libzfs_error_description(g_zfs));
		return (zfs_err_to_be_err(g_zfs));
	}

	return (BE_SUCCESS);
}

/*
 * Function:	be_zpool_find_current_be_callback
 * Description: Callback function used to iterate through all existing pools
 *		to find the BE that is the currently booted BE.
 * Parameters:
 *		zlp - zpool_handle_t pointer to the current pool being
 *			looked at.
 *		data - be_transaction_data_t pointer.
 *			Upon successfully finding the current BE, the
 *			obe_zpool member of this parameter is set to the
 *			pool it is found in.
 * Return:
 *		1 - Found current BE in this pool.
 *		0 - Did not find current BE in this pool.
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_zpool_find_current_be_callback(zpool_handle_t *zlp, void *data)
{
	be_transaction_data_t	*bt = data;
	zfs_handle_t		*zhp = NULL;
	const char		*zpool =  zpool_get_name(zlp);
	char			be_container_ds[MAXPATHLEN];
	char			*zpath = NULL;

	/*
	 * Generate string for BE container dataset
	 */
	if (getzoneid() != GLOBAL_ZONEID) {
		if ((zpath = be_get_ds_from_dir("/")) != NULL) {
			(void) strlcpy(be_container_ds, dirname(zpath),
			    sizeof (be_container_ds));
		} else {
			be_print_err(gettext(
			    "be_zpool_find_current_be_callback: "
			    "zone root dataset is not mounted\n"));
			return (0);
		}
	} else {
		be_make_container_ds(zpool, be_container_ds,
		    sizeof (be_container_ds));
	}

	/*
	 * Check if a BE container dataset exists in this pool.
	 */
	if (!zfs_dataset_exists(g_zfs, be_container_ds, ZFS_TYPE_FILESYSTEM)) {
		zpool_close(zlp);
		return (0);
	}

	/*
	 * Get handle to this zpool's BE container dataset.
	 */
	if ((zhp = zfs_open(g_zfs, be_container_ds, ZFS_TYPE_FILESYSTEM)) ==
	    NULL) {
		be_print_err(gettext("be_zpool_find_current_be_callback: "
		    "failed to open BE container dataset (%s)\n"),
		    be_container_ds);
		zpool_close(zlp);
		return (0);
	}

	/*
	 * Iterate through all potential BEs in this zpool
	 */
	if (zfs_iter_filesystems(zhp, be_zfs_find_current_be_callback, bt)) {
		/*
		 * Found current BE dataset; set obe_zpool
		 */
		if ((bt->obe_zpool = strdup(zpool)) == NULL) {
			be_print_err(gettext(
			    "be_zpool_find_current_be_callback: "
			    "memory allocation failed\n"));
			ZFS_CLOSE(zhp);
			zpool_close(zlp);
			return (0);
		}

		ZFS_CLOSE(zhp);
		zpool_close(zlp);
		return (1);
	}

	ZFS_CLOSE(zhp);
	zpool_close(zlp);

	return (0);
}

/*
 * Function:	be_zfs_find_current_be_callback
 * Description:	Callback function used to iterate through all BEs in a
 *		pool to find the BE that is the currently booted BE.
 * Parameters:
 *		zhp - zfs_handle_t pointer to current filesystem being checked.
 *		data - be_transaction-data_t pointer
 *			Upon successfully finding the current BE, the
 *			obe_name and obe_root_ds members of this parameter
 *			are set to the BE name and BE's root dataset
 *			respectively.
 * Return:
 *		1 - Found current BE.
 *		0 - Did not find current BE.
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_zfs_find_current_be_callback(zfs_handle_t *zhp, void *data)
{
	be_transaction_data_t	*bt = data;
	char			*mp = NULL;

	/*
	 * Check if dataset is mounted, and if so where.
	 */
	if (zfs_is_mounted(zhp, &mp)) {
		/*
		 * If mounted at root, set obe_root_ds and obe_name
		 */
		if (mp != NULL && strcmp(mp, "/") == 0) {
			free(mp);

			if ((bt->obe_root_ds = strdup(zfs_get_name(zhp)))
			    == NULL) {
				be_print_err(gettext(
				    "be_zfs_find_current_be_callback: "
				    "memory allocation failed\n"));
				ZFS_CLOSE(zhp);
				return (0);
			}

			if ((bt->obe_name = strdup(basename(bt->obe_root_ds)))
			    == NULL) {
				be_print_err(gettext(
				    "be_zfs_find_current_be_callback: "
				    "memory allocation failed\n"));
				ZFS_CLOSE(zhp);
				return (0);
			}

			ZFS_CLOSE(zhp);
			return (1);
		}

		free(mp);
	}
	ZFS_CLOSE(zhp);

	return (0);
}

/*
 * Function:	be_check_be_roots_callback
 * Description:	This function checks whether or not the dataset name passed
 *		is hierachically located under the BE root container dataset
 *		for this pool.
 * Parameters:
 *		zlp - zpool_handle_t pointer to current pool being processed.
 *		data - name of dataset to check
 * Returns:
 *		0 - dataset is not in this pool's BE root container dataset
 *		1 - dataset is in this pool's BE root container dataset
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_check_be_roots_callback(zpool_handle_t *zlp, void *data)
{
	const char	*zpool = zpool_get_name(zlp);
	char		*ds = data;
	char		be_container_ds[MAXPATHLEN];

	/* Generate string for this pool's BE root container dataset */
	be_make_container_ds(zpool, be_container_ds, sizeof (be_container_ds));

	/*
	 * If dataset lives under the BE root container dataset
	 * of this pool, return failure.
	 */
	if (strncmp(be_container_ds, ds, strlen(be_container_ds)) == 0 &&
	    ds[strlen(be_container_ds)] == '/') {
		zpool_close(zlp);
		return (1);
	}

	zpool_close(zlp);
	return (0);
}

/*
 * Function:	zfs_err_to_be_err
 * Description:	This function takes the error stored in the libzfs handle
 *		and maps it to an be_errno_t. If there are no matching
 *		be_errno_t's then BE_ERR_ZFS is returned.
 * Paramters:
 *		zfsh - The libzfs handle containing the error we're looking up.
 * Returns:
 *		be_errno_t
 * Scope:
 *		Semi-private (library wide use only)
 */
int
zfs_err_to_be_err(libzfs_handle_t *zfsh)
{
	int err = libzfs_errno(zfsh);

	switch (err) {
	case 0:
		return (BE_SUCCESS);
	case EZFS_PERM:
		return (BE_ERR_PERM);
	case EZFS_INTR:
		return (BE_ERR_INTR);
	case EZFS_NOENT:
		return (BE_ERR_NOENT);
	case EZFS_NOSPC:
		return (BE_ERR_NOSPC);
	case EZFS_MOUNTFAILED:
		return (BE_ERR_MOUNT);
	case EZFS_UMOUNTFAILED:
		return (BE_ERR_UMOUNT);
	case EZFS_EXISTS:
		return (BE_ERR_BE_EXISTS);
	case EZFS_BUSY:
		return (BE_ERR_DEV_BUSY);
	case EZFS_POOLREADONLY:
		return (BE_ERR_ROFS);
	case EZFS_NAMETOOLONG:
		return (BE_ERR_NAMETOOLONG);
	case EZFS_NODEVICE:
		return (BE_ERR_NODEV);
	case EZFS_POOL_INVALARG:
		return (BE_ERR_INVAL);
	case EZFS_PROPTYPE:
		return (BE_ERR_INVALPROP);
	case EZFS_BADTYPE:
		return (BE_ERR_DSTYPE);
	case EZFS_PROPNONINHERIT:
		return (BE_ERR_NONINHERIT);
	case EZFS_PROPREADONLY:
		return (BE_ERR_READONLYPROP);
	case EZFS_RESILVERING:
	case EZFS_POOLUNAVAIL:
		return (BE_ERR_UNAVAIL);
	case EZFS_DSREADONLY:
		return (BE_ERR_READONLYDS);
	default:
		return (BE_ERR_ZFS);
	}
}

/*
 * Function:	errno_to_be_err
 * Description:	This function takes an errno and maps it to an be_errno_t.
 *		If there are no matching be_errno_t's then BE_ERR_UNKNOWN is
 *		returned.
 * Paramters:
 *		err - The errno we're compairing against.
 * Returns:
 *		be_errno_t
 * Scope:
 *		Semi-private (library wide use only)
 */
int
errno_to_be_err(int err)
{
	switch (err) {
	case EPERM:
		return (BE_ERR_PERM);
	case EACCES:
		return (BE_ERR_ACCESS);
	case ECANCELED:
		return (BE_ERR_CANCELED);
	case EINTR:
		return (BE_ERR_INTR);
	case ENOENT:
		return (BE_ERR_NOENT);
	case ENOSPC:
	case EDQUOT:
		return (BE_ERR_NOSPC);
	case EEXIST:
		return (BE_ERR_BE_EXISTS);
	case EBUSY:
		return (BE_ERR_BUSY);
	case EROFS:
		return (BE_ERR_ROFS);
	case ENAMETOOLONG:
		return (BE_ERR_NAMETOOLONG);
	case ENXIO:
		return (BE_ERR_NXIO);
	case EINVAL:
		return (BE_ERR_INVAL);
	case EFAULT:
		return (BE_ERR_FAULT);
	default:
		return (BE_ERR_UNKNOWN);
	}
}

/*
 * Function:	be_err_to_str
 * Description:	This function takes a be_errno_t and maps it to a message.
 *		If there are no matching be_errno_t's then NULL is returned.
 * Paramters:
 *		be_errno_t - The be_errno_t we're mapping.
 * Returns:
 *		string or NULL if the error code is not known.
 * Scope:
 *		Semi-private (library wide use only)
 */
char *
be_err_to_str(int err)
{
	switch (err) {
	case BE_ERR_ACCESS:
		return (gettext("Permission denied."));
	case BE_ERR_ACTIVATE_CURR:
		return (gettext("Activation of current BE failed."));
	case BE_ERR_AUTONAME:
		return (gettext("Auto naming failed."));
	case BE_ERR_BE_NOENT:
		return (gettext("No such BE."));
	case BE_ERR_BUSY:
		return (gettext("Mount busy."));
	case BE_ERR_DEV_BUSY:
		return (gettext("Device busy."));
	case BE_ERR_CANCELED:
		return (gettext("Operation canceled."));
	case BE_ERR_CLONE:
		return (gettext("BE clone failed."));
	case BE_ERR_COPY:
		return (gettext("BE copy failed."));
	case BE_ERR_CREATDS:
		return (gettext("Dataset creation failed."));
	case BE_ERR_CURR_BE_NOT_FOUND:
		return (gettext("Can't find current BE."));
	case BE_ERR_DESTROY:
		return (gettext("Failed to destroy BE or snapshot."));
	case BE_ERR_DESTROY_CURR_BE:
		return (gettext("Cannot destroy current BE."));
	case BE_ERR_DEMOTE:
		return (gettext("BE demotion failed."));
	case BE_ERR_DSTYPE:
		return (gettext("Invalid dataset type."));
	case BE_ERR_BE_EXISTS:
		return (gettext("BE exists."));
	case BE_ERR_INIT:
		return (gettext("be_zfs_init failed."));
	case BE_ERR_INTR:
		return (gettext("Interupted system call."));
	case BE_ERR_INVAL:
		return (gettext("Invalid argument."));
	case BE_ERR_INVALPROP:
		return (gettext("Invalid property for dataset."));
	case BE_ERR_INVALMOUNTPOINT:
		return (gettext("Unexpected mountpoint."));
	case BE_ERR_MOUNT:
		return (gettext("Mount failed."));
	case BE_ERR_MOUNTED:
		return (gettext("Already mounted."));
	case BE_ERR_NAMETOOLONG:
		return (gettext("name > BUFSIZ."));
	case BE_ERR_NOENT:
		return (gettext("Doesn't exist."));
	case BE_ERR_POOL_NOENT:
		return (gettext("No such pool."));
	case BE_ERR_NODEV:
		return (gettext("No such device."));
	case BE_ERR_NOTMOUNTED:
		return (gettext("File system not mounted."));
	case BE_ERR_NOMEM:
		return (gettext("Not enough memory."));
	case BE_ERR_NONINHERIT:
		return (gettext(
		    "Property is not inheritable for the BE dataset."));
	case BE_ERR_NXIO:
		return (gettext("No such device or address."));
	case BE_ERR_NOSPC:
		return (gettext("No space on device."));
	case BE_ERR_NOTSUP:
		return (gettext("Operation not supported."));
	case BE_ERR_OPEN:
		return (gettext("Open failed."));
	case BE_ERR_PERM:
		return (gettext("Not owner."));
	case BE_ERR_UNAVAIL:
		return (gettext("The BE is currently unavailable."));
	case BE_ERR_PROMOTE:
		return (gettext("BE promotion failed."));
	case BE_ERR_ROFS:
		return (gettext("Read only file system."));
	case BE_ERR_READONLYDS:
		return (gettext("Read only dataset."));
	case BE_ERR_READONLYPROP:
		return (gettext("Read only property."));
	case BE_ERR_RENAME_ACTIVE:
		return (gettext("Renaming the active BE is not supported."));
	case BE_ERR_SS_EXISTS:
		return (gettext("Snapshot exists."));
	case BE_ERR_SS_NOENT:
		return (gettext("No such snapshot."));
	case BE_ERR_UMOUNT:
		return (gettext("Unmount failed."));
	case BE_ERR_UMOUNT_CURR_BE:
		return (gettext("Can't unmount the current BE."));
	case BE_ERR_UMOUNT_SHARED:
		return (gettext("Unmount of a shared File System failed."));
	case BE_ERR_FAULT:
		return (gettext("Bad address."));
	case BE_ERR_UNKNOWN:
		return (gettext("Unknown error."));
	case BE_ERR_ZFS:
		return (gettext("ZFS returned an error."));
	case BE_ERR_GEN_UUID:
		return (gettext("Failed to generate uuid."));
	case BE_ERR_PARSE_UUID:
		return (gettext("Failed to parse uuid."));
	case BE_ERR_NO_UUID:
		return (gettext("No uuid"));
	case BE_ERR_ZONE_NO_PARENTBE:
		return (gettext("No parent uuid"));
	case BE_ERR_ZONE_MULTIPLE_ACTIVE:
		return (gettext("Multiple active zone roots"));
	case BE_ERR_ZONE_NO_ACTIVE_ROOT:
		return (gettext("No active zone root"));
	case BE_ERR_ZONE_ROOT_NOT_LEGACY:
		return (gettext("Zone root not legacy"));
	case BE_ERR_MOUNT_ZONEROOT:
		return (gettext("Failed to mount a zone root."));
	case BE_ERR_UMOUNT_ZONEROOT:
		return (gettext("Failed to unmount a zone root."));
	case BE_ERR_NO_MOUNTED_ZONE:
		return (gettext("Zone is not mounted"));
	case BE_ERR_ZONES_UNMOUNT:
		return (gettext("Unable to unmount a zone BE."));
	case BE_ERR_NO_MENU:
		return (gettext("Missing boot menu file."));
	case BE_ERR_BAD_MENU_PATH:
		return (gettext("Invalid path for menu.lst file"));
	case BE_ERR_ZONE_SS_EXISTS:
		return (gettext("Zone snapshot exists."));
	case BE_ERR_BOOTFILE_INST:
		return (gettext("Error installing boot files."));
	case BE_ERR_EXTCMD:
		return (gettext("Error running an external command."));
	default:
		return (NULL);
	}
}

/*
 * Function:    be_has_grub
 * Description: Boolean function indicating whether the current system
 *		uses grub.
 * Return:      B_FALSE - the system does not have grub
 *              B_TRUE - the system does have grub.
 * Scope:
 *		Semi-private (library wide use only)
 */
boolean_t
be_has_grub(void)
{
	static struct be_defaults be_defaults;
	static boolean_t be_deflts_set = B_FALSE;

	/* Cache the defaults, because be_has_grub is used often. */
	if (be_deflts_set == B_FALSE) {
		be_get_defaults(&be_defaults);
		be_deflts_set = B_TRUE;
	}

	return (be_defaults.be_deflt_grub);
}

/*
 * Function:    be_is_isa
 * Description: Boolean function indicating whether the instruction set
 *              architecture of the executing system matches the name provided.
 *              The string must match a system defined architecture (e.g.
 *              "i386", "sparc") and is case sensitive.
 * Parameters:  name - string representing the name of instruction set
 *			architecture being tested
 * Returns:     B_FALSE - the system instruction set architecture is different
 *			from the one specified
 *              B_TRUE - the system instruction set architecture is the same
 *			as the one specified
 * Scope:
 *		Semi-private (library wide use only)
 */
boolean_t
be_is_isa(char *name)
{
	return ((strcmp((char *)be_get_default_isa(), name) == 0));
}

/*
 * Function: be_get_default_isa
 * Description:
 *      Returns the default instruction set architecture of the
 *      machine it is executed on. (eg. sparc, i386, ...)
 *      NOTE:   SYS_INST environment variable may override default
 *              return value
 * Parameters:
 *		none
 * Returns:
 *		NULL - the architecture returned by sysinfo() was too
 *			long for local variables
 *		char * - pointer to a string containing the default
 *			implementation
 * Scope:
 *		Semi-private (library wide use only)
 */
char *
be_get_default_isa(void)
{
	int	i;
	char	*envp;
	static char	default_inst[ARCH_LENGTH] = "";

	if (default_inst[0] == '\0') {
		if ((envp = getenv("SYS_INST")) != NULL) {
			if ((int)strlen(envp) >= ARCH_LENGTH)
				return (NULL);
			else
				(void) strcpy(default_inst, envp);
		} else  {
			i = sysinfo(SI_ARCHITECTURE, default_inst, ARCH_LENGTH);
			if (i < 0 || i > ARCH_LENGTH)
				return (NULL);
		}
	}
	return (default_inst);
}

/*
 * Function: be_get_platform
 * Description:
 *      Returns the platfom name
 * Parameters:
 *		none
 * Returns:
 *		NULL - the platform name returned by sysinfo() was too
 *			long for local variables
 *		char * - pointer to a string containing the platform name
 * Scope:
 *		Semi-private (library wide use only)
 */
char *
be_get_platform(void)
{
	int	i;
	static char	default_inst[ARCH_LENGTH] = "";

	if (default_inst[0] == '\0') {
		i = sysinfo(SI_PLATFORM, default_inst, ARCH_LENGTH);
		if (i < 0 || i > ARCH_LENGTH)
			return (NULL);
	}
	return (default_inst);
}

/*
 * Function: be_run_cmd
 * Description:
 *	Runs a command in a separate subprocess.  Splits out stdout from stderr
 *	and sends each to its own buffer.  Buffers must be pre-allocated and
 *	passed in as arguments.  Buffer sizes are also passed in as arguments.
 *
 *	Notes / caveats:
 *	- Command being run is assumed to not have any stdout or stderr
 *		redirection.
 *	- Commands which emit total stderr output of greater than PIPE_BUF
 *		bytes can hang.  For such commands, a different implementation
 *		which uses poll(2) must be used.
 *	- stdout_buf can be NULL.  In this case, stdout_bufsize is ignored, and
 *		the stream which would have gone to it is sent to the bit
 *		bucket.
 *	- stderr_buf cannot be NULL.
 *	- Only subprocess errors are appended to the stderr_buf.  Errors
 *		running the command are reported through be_print_err().
 *	- Data which would overflow its respective buffer is sent to the bit
 *		bucket.
 *
 * Parameters:
 *		command: command to run.  Assumed not to have embedded stdout
 *			or stderr redirection.  May have stdin redirection,
 *			however.
 *		stderr_buf: buffer returning subprocess stderr data.  Errors
 *			reported by this function are reported through
 *			be_print_err().
 *		stderr_bufsize: size of stderr_buf
 *		stdout_buf: buffer returning subprocess stdout data.
 *		stdout_bufsize: size of stdout_buf
 * Returns:
 *		BE_SUCCESS - The command ran successfully without returning
 *			errors.
 *		BE_ERR_EXTCMD
 *			- The command could not be run.
 *			- The command terminated with error status.
 *			- There were errors extracting or returning subprocess
 *				data.
 *		BE_ERR_NOMEM - The command exceeds the command buffer size.
 *		BE_ERR_INVAL - An invalid argument was specified.
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_run_cmd(char *command, char *stderr_buf, int stderr_bufsize,
    char *stdout_buf, int stdout_bufsize)
{
	char *temp_filename = strdup(tmpnam(NULL));
	FILE *stdout_str = NULL;
	FILE *stderr_str = NULL;
	char cmdline[BUFSIZ];
	char oneline[BUFSIZ];
	int exit_status;
	int rval = BE_SUCCESS;

	if ((command == NULL) || (stderr_buf == NULL) ||
	    (stderr_bufsize <= 0) || (stdout_bufsize <  0) ||
	    ((stdout_buf != NULL) ^ (stdout_bufsize != 0))) {
		return (BE_ERR_INVAL);
	}

	/* Set up command so popen returns stderr, not stdout */
	if (snprintf(cmdline, BUFSIZ, "%s 2> %s", command,
	    temp_filename) >= BUFSIZ) {
		rval = BE_ERR_NOMEM;
		goto cleanup;
	}

	/* Set up the fifo that will make stderr available. */
	if (mkfifo(temp_filename, 0600) != 0) {
		(void) be_print_err(gettext("be_run_cmd: mkfifo: %s\n"),
		    strerror(errno));
		rval = BE_ERR_EXTCMD;
		goto cleanup;
	}

	if ((stdout_str = popen(cmdline, "r")) == NULL) {
		(void) be_print_err(gettext("be_run_cmd: popen: %s\n"),
		    strerror(errno));
		rval = BE_ERR_EXTCMD;
		goto cleanup;
	}

	if ((stderr_str = fopen(temp_filename, "r")) == NULL) {
		(void) be_print_err(gettext("be_run_cmd: fopen: %s\n"),
		    strerror(errno));
		(void) pclose(stdout_str);
		rval = BE_ERR_EXTCMD;
		goto cleanup;
	}

	/* Read stdout first, as it usually outputs more than stderr. */
	oneline[BUFSIZ-1] = '\0';
	while (fgets(oneline, BUFSIZ-1, stdout_str) != NULL) {
		if (stdout_str != NULL) {
			(void) strlcat(stdout_buf, oneline, stdout_bufsize);
		}
	}

	while (fgets(oneline, BUFSIZ-1, stderr_str) != NULL) {
		(void) strlcat(stderr_buf, oneline, stderr_bufsize);
	}

	/* Close pipe, get exit status. */
	if ((exit_status = pclose(stdout_str)) == -1) {
		(void) be_print_err(gettext("be_run_cmd: pclose: %s\n"),
		    strerror(errno));
		rval = BE_ERR_EXTCMD;
	} else if (WIFEXITED(exit_status)) {
		exit_status = (int)((char)WEXITSTATUS(exit_status));
		/*
		 * error code BC_NOUPDT means more recent version
		 * is installed
		 */
		if (exit_status != BC_SUCCESS && exit_status != BC_NOUPDT) {
			(void) snprintf(oneline, BUFSIZ, gettext("be_run_cmd: "
			    "command terminated with error status: %d\n"),
			    exit_status);
			(void) strlcat(stderr_buf, oneline, stderr_bufsize);
			rval = BE_ERR_EXTCMD;
		}
	} else {
		(void) snprintf(oneline, BUFSIZ, gettext("be_run_cmd: command "
		    "terminated on signal: %s\n"),
		    strsignal(WTERMSIG(exit_status)));
		(void) strlcat(stderr_buf, oneline, stderr_bufsize);
		rval = BE_ERR_EXTCMD;
	}

cleanup:
	(void) unlink(temp_filename);
	(void) free(temp_filename);

	return (rval);
}

/* ********************************************************************	*/
/*			Private Functions				*/
/* ******************************************************************** */

/*
 * Function:	update_dataset
 * Description:	This function takes a dataset name and replaces the zpool
 *		and be_name components of the dataset with the new be_name
 *		zpool passed in.
 * Parameters:
 *		dataset - name of dataset
 *		dataset_len - lenth of buffer in which dataset is passed in.
 *		be_name - name of new BE name to update to.
 *		old_rc_loc - dataset under which the root container dataset
 *			for the old BE lives.
 *		new_rc_loc - dataset under which the root container dataset
 *			for the new BE lives.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
update_dataset(char *dataset, int dataset_len, char *be_name,
    char *old_rc_loc, char *new_rc_loc)
{
	char	*ds = NULL;
	char	*sub_ds = NULL;

	/* Tear off the BE container dataset */
	if ((ds = be_make_name_from_ds(dataset, old_rc_loc)) == NULL) {
		return (BE_ERR_INVAL);
	}

	/* Get dataset name relative to BE root, if there is one */
	sub_ds = strchr(ds, '/');

	/* Generate the BE root dataset name */
	be_make_root_ds(new_rc_loc, be_name, dataset, dataset_len);

	/* If a subordinate dataset name was found, append it */
	if (sub_ds != NULL)
		(void) strlcat(dataset, sub_ds, dataset_len);

	free(ds);
	return (BE_SUCCESS);
}

/*
 * Function:	_update_vfstab
 * Description:	This function updates a vfstab file to reflect the new
 *		root container dataset location and be_name for all
 *		entries listed in the be_fs_list_data_t structure passed in.
 * Parameters:
 *		vfstab - vfstab file to modify
 *		be_name - name of BE to update.
 *		old_rc_loc - dataset under which the root container dataset
 *			of the old BE resides in.
 *		new_rc_loc - dataset under which the root container dataset
 *			of the new BE resides in.
 *		fld - be_fs_list_data_t pointer providing the list of
 *			file systems to look for in vfstab.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
_update_vfstab(char *vfstab, char *be_name, char *old_rc_loc,
    char *new_rc_loc, be_fs_list_data_t *fld)
{
	struct vfstab	vp;
	char		*tmp_vfstab = NULL;
	char		comments_buf[BUFSIZ];
	FILE		*comments = NULL;
	FILE		*vfs_ents = NULL;
	FILE		*tfile = NULL;
	struct stat	sb;
	char		dev[MAXPATHLEN];
	char		*c;
	int		fd;
	int		ret = BE_SUCCESS, err = 0;
	int		i;
	int		tmp_vfstab_len = 0;

	errno = 0;

	/*
	 * Open vfstab for reading twice.  First is for comments,
	 * second is for actual entries.
	 */
	if ((comments = fopen(vfstab, "r")) == NULL ||
	    (vfs_ents = fopen(vfstab, "r")) == NULL) {
		err = errno;
		be_print_err(gettext("_update_vfstab: "
		    "failed to open vfstab (%s): %s\n"), vfstab,
		    strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	/* Grab the stats of the original vfstab file */
	if (stat(vfstab, &sb) != 0) {
		err = errno;
		be_print_err(gettext("_update_vfstab: "
		    "failed to stat file %s: %s\n"), vfstab,
		    strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	/* Create tmp file for modified vfstab */
	if ((tmp_vfstab = (char *)malloc(strlen(vfstab) + 7))
	    == NULL) {
		be_print_err(gettext("_update_vfstab: "
		    "malloc failed\n"));
		ret = BE_ERR_NOMEM;
		goto cleanup;
	}
	tmp_vfstab_len = strlen(vfstab) + 7;
	(void) memset(tmp_vfstab, 0, tmp_vfstab_len);
	(void) strlcpy(tmp_vfstab, vfstab, tmp_vfstab_len);
	(void) strlcat(tmp_vfstab, "XXXXXX", tmp_vfstab_len);
	if ((fd = mkstemp(tmp_vfstab)) == -1) {
		err = errno;
		be_print_err(gettext("_update_vfstab: "
		    "mkstemp failed: %s\n"), strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}
	if ((tfile = fdopen(fd, "w")) == NULL) {
		err = errno;
		be_print_err(gettext("_update_vfstab: "
		    "could not open file for write\n"));
		(void) close(fd);
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	while (fgets(comments_buf, BUFSIZ, comments)) {
		for (c = comments_buf; *c != '\0' && isspace(*c); c++)
			;
		if (*c == '\0') {
			continue;
		} else if (*c == '#') {
			/*
			 * If line is a comment line, just put
			 * it through to the tmp vfstab.
			 */
			(void) fputs(comments_buf, tfile);
		} else {
			/*
			 * Else line is a vfstab entry, grab it
			 * into a vfstab struct.
			 */
			if (getvfsent(vfs_ents, &vp) != 0) {
				err = errno;
				be_print_err(gettext("_update_vfstab: "
				    "getvfsent failed: %s\n"), strerror(err));
				ret = errno_to_be_err(err);
				goto cleanup;
			}

			if (vp.vfs_special == NULL || vp.vfs_mountp == NULL) {
				(void) putvfsent(tfile, &vp);
				continue;
			}

			/*
			 * If the entry is one of the entries in the list
			 * of file systems to update, modify it's device
			 * field to be correct for this BE.
			 */
			for (i = 0; i < fld->fs_num; i++) {
				if (strcmp(vp.vfs_special, fld->fs_list[i])
				    == 0) {
					/*
					 * Found entry that needs an update.
					 * Replace the root container dataset
					 * location and be_name in the
					 * entry's device.
					 */
					(void) strlcpy(dev, vp.vfs_special,
					    sizeof (dev));

					if ((ret = update_dataset(dev,
					    sizeof (dev), be_name, old_rc_loc,
					    new_rc_loc)) != 0) {
						be_print_err(
						    gettext("_update_vfstab: "
						    "Failed to update device "
						    "field for vfstab entry "
						    "%s\n"), fld->fs_list[i]);
						goto cleanup;
					}

					vp.vfs_special = dev;
					break;
				}
			}

			/* Put entry through to tmp vfstab */
			(void) putvfsent(tfile, &vp);
		}
	}

	(void) fclose(comments);
	comments = NULL;
	(void) fclose(vfs_ents);
	vfs_ents = NULL;
	(void) fclose(tfile);
	tfile = NULL;

	/* Copy tmp vfstab into place */
	if (rename(tmp_vfstab, vfstab) != 0) {
		err = errno;
		be_print_err(gettext("_update_vfstab: "
		    "failed to rename file %s to %s: %s\n"), tmp_vfstab,
		    vfstab, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}

	/* Set the perms and ownership of the updated file */
	if (chmod(vfstab, sb.st_mode) != 0) {
		err = errno;
		be_print_err(gettext("_update_vfstab: "
		    "failed to chmod %s: %s\n"), vfstab, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}
	if (chown(vfstab, sb.st_uid, sb.st_gid) != 0) {
		err = errno;
		be_print_err(gettext("_update_vfstab: "
		    "failed to chown %s: %s\n"), vfstab, strerror(err));
		ret = errno_to_be_err(err);
		goto cleanup;
	}

cleanup:
	if (comments != NULL)
		(void) fclose(comments);
	if (vfs_ents != NULL)
		(void) fclose(vfs_ents);
	(void) unlink(tmp_vfstab);
	(void) free(tmp_vfstab);
	if (tfile != NULL)
		(void) fclose(tfile);

	return (ret);
}


/*
 * Function:	be_get_auto_name
 * Description:	Generate an auto name constructed based on the BE name
 *		of the original BE or zone BE being cloned.
 * Parameters:
 *		obe_name - name of the original BE or zone BE being cloned.
 *              container_ds - container dataset for the zone.
 *                             Note: if zone_be is false this should be
 *                                  NULL.
 *		zone_be - flag that indicates if we are operating on a zone BE.
 * Returns:
 *		Success - pointer to auto generated BE name.  The name
 *			is allocated in heap storage so the caller is
 *			responsible for free'ing the name.
 *		Failure - NULL
 * Scope:
 *		Private
 */
static char *
be_get_auto_name(char *obe_name, char *be_container_ds, boolean_t zone_be)
{
	be_node_list_t	*be_nodes = NULL;
	be_node_list_t	*cur_be = NULL;
	char		auto_be_name[MAXPATHLEN];
	char		base_be_name[MAXPATHLEN];
	char		cur_be_name[MAXPATHLEN];
	char		*num_str = NULL;
	char		*c = NULL;
	int		num = 0;
	int		cur_num = 0;

	errno = 0;

	/*
	 * Check if obe_name is already in an auto BE name format.
	 * If it is, then strip off the increment number to get the
	 * base name.
	 */
	(void) strlcpy(base_be_name, obe_name, sizeof (base_be_name));

	if ((num_str = strrchr(base_be_name, BE_AUTO_NAME_DELIM))
	    != NULL) {
		/* Make sure remaining string is all digits */
		c = num_str + 1;
		while (c[0] != '\0' && isdigit(c[0]))
			c++;
		/*
		 * If we're now at the end of the string strip off the
		 * increment number.
		 */
		if (c[0] == '\0')
			num_str[0] = '\0';
	}

	if (zone_be) {
		if (be_container_ds == NULL)
			return (NULL);
		if (be_get_zone_be_list(obe_name, be_container_ds,
		    &be_nodes) != BE_SUCCESS) {
			be_print_err(gettext("be_get_auto_name: "
			    "be_get_zone_be_list failed\n"));
			return (NULL);
		}
	} else if (_be_list(NULL, &be_nodes) != BE_SUCCESS) {
		be_print_err(gettext("be_get_auto_name: be_list failed\n"));
		return (NULL);
	}

	for (cur_be = be_nodes; cur_be != NULL; cur_be = cur_be->be_next_node) {
		(void) strlcpy(cur_be_name, cur_be->be_node_name,
		    sizeof (cur_be_name));

		/* If cur_be_name doesn't match at least base be name, skip. */
		if (strncmp(cur_be_name, base_be_name, strlen(base_be_name))
		    != 0)
			continue;

		/* Get the string following the base be name */
		num_str = cur_be_name + strlen(base_be_name);

		/*
		 * If nothing follows the base be name, this cur_be_name
		 * is the BE named with the base be name, skip.
		 */
		if (num_str == NULL || num_str[0] == '\0')
			continue;

		/*
		 * Remove the name delimiter.  If its not there,
		 * cur_be_name isn't part of this BE name stream, skip.
		 */
		if (num_str[0] == BE_AUTO_NAME_DELIM)
			num_str++;
		else
			continue;

		/* Make sure remaining string is all digits */
		c = num_str;
		while (c[0] != '\0' && isdigit(c[0]))
			c++;
		if (c[0] != '\0')
			continue;

		/* Convert the number string to an int */
		cur_num = atoi(num_str);

		/*
		 * If failed to convert the string, skip it.  If its too
		 * long to be converted to an int, we wouldn't auto generate
		 * this number anyway so there couldn't be a conflict.
		 * We treat it as a manually created BE name.
		 */
		if (cur_num == 0 && errno == EINVAL)
			continue;

		/*
		 * Compare current number to current max number,
		 * take higher of the two.
		 */
		if (cur_num > num)
			num = cur_num;
	}

	/*
	 * Store off a copy of 'num' incase we need it later.  If incrementing
	 * 'num' causes it to roll over, this means 'num' is the largest
	 * positive int possible; we'll need it later in the loop to determine
	 * if we've exhausted all possible increment numbers.  We store it in
	 * 'cur_num'.
	 */
	cur_num = num;

	/* Increment 'num' to get new auto BE name number */
	if (++num <= 0) {
		int ret = 0;

		/*
		 * Since incrementing 'num' caused it to rollover, start
		 * over at 0 and find the first available number.
		 */
		for (num = 0; num < cur_num; num++) {

			(void) snprintf(cur_be_name, sizeof (cur_be_name),
			    "%s%c%d", base_be_name, BE_AUTO_NAME_DELIM, num);

			ret = zpool_iter(g_zfs, be_exists_callback,
			    cur_be_name);

			if (ret == 0) {
				/*
				 * BE name doesn't exist, break out
				 * to use 'num'.
				 */
				break;
			} else if (ret == 1) {
				/* BE name exists, continue looking */
				continue;
			} else {
				be_print_err(gettext("be_get_auto_name: "
				    "zpool_iter failed: %s\n"),
				    libzfs_error_description(g_zfs));
				be_free_list(be_nodes);
				return (NULL);
			}
		}

		/*
		 * If 'num' equals 'cur_num', we've exhausted all possible
		 * auto BE names for this base BE name.
		 */
		if (num == cur_num) {
			be_print_err(gettext("be_get_auto_name: "
			    "No more available auto BE names for base "
			    "BE name %s\n"), base_be_name);
			be_free_list(be_nodes);
			return (NULL);
		}
	}

	be_free_list(be_nodes);

	/*
	 * Generate string for auto BE name.
	 */
	(void) snprintf(auto_be_name, sizeof (auto_be_name), "%s%c%d",
	    base_be_name, BE_AUTO_NAME_DELIM, num);

	if ((c = strdup(auto_be_name)) == NULL) {
		be_print_err(gettext("be_get_auto_name: "
		    "memory allocation failed\n"));
		return (NULL);
	}

	return (c);
}

/*
 * Function:	be_get_console_prop
 * Description:	Determine console device.
 * Returns:
 *		Success - pointer to console setting.
 *		Failure - NULL
 * Scope:
 *		Private
 */
static char *
be_get_console_prop(void)
{
	di_node_t	dn;
	char *console = NULL;

	if ((dn = di_init("/", DINFOPROP)) == DI_NODE_NIL) {
		be_print_err(gettext("be_get_console_prop: "
		    "di_init() failed\n"));
		return (NULL);
	}

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, dn,
	    "console", &console) != -1) {
		di_fini(dn);
		return (console);
	}

	if (console == NULL) {
		if (di_prop_lookup_strings(DDI_DEV_T_ANY, dn,
		    "output-device", &console) != -1) {
			di_fini(dn);
			if (strncmp(console, "screen", strlen("screen")) == 0)
				console = BE_DEFAULT_CONSOLE;
		}
	}

	/*
	 * Default console to text
	 */
	if (console == NULL) {
		console = BE_DEFAULT_CONSOLE;
	}

	return (console);
}

/*
 * Function:	be_create_menu
 * Description:
 *		This function is used if no menu.lst file exists. In
 *		this case a new file is created and if needed default
 *		lines are added to the file.
 * Parameters:
 *		pool - The name of the pool the menu.lst file is on
 *		menu_file - The name of the file we're creating.
 *		menu_fp - A pointer to the file pointer of the file we
 *			  created. This is also used to pass back the file
 *			  pointer to the newly created file.
 *		mode - the original mode used for the failed attempt to
 *		       non-existent file.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_create_menu(
	char *pool,
	char *menu_file,
	FILE **menu_fp,
	char *mode)
{
	be_node_list_t	*be_nodes = NULL;
	char *menu_path = NULL;
	char *be_rpool = NULL;
	char *be_name = NULL;
	char *console = NULL;
	errno = 0;

	if (menu_file == NULL || menu_fp == NULL || mode == NULL)
		return (BE_ERR_INVAL);

	menu_path = strdup(menu_file);
	if (menu_path == NULL)
		return (BE_ERR_NOMEM);

	(void) dirname(menu_path);
	if (*menu_path == '.') {
		free(menu_path);
		return (BE_ERR_BAD_MENU_PATH);
	}
	if (mkdirp(menu_path,
	    S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == -1 &&
	    errno != EEXIST) {
		free(menu_path);
		be_print_err(gettext("be_create_menu: Failed to create the %s "
		    "directory: %s\n"), menu_path, strerror(errno));
		return (errno_to_be_err(errno));
	}
	free(menu_path);

	/*
	 * Check to see if this system supports grub
	 */
	if (be_has_grub()) {
		/*
		 * The grub menu is missing so we need to create it
		 * and fill in the first few lines.
		 */
		FILE *temp_fp = fopen(menu_file, "a+");
		if (temp_fp == NULL) {
			*menu_fp = NULL;
			return (errno_to_be_err(errno));
		}

		if ((console = be_get_console_prop()) != NULL) {

			/*
			 * If console is redirected to serial line,
			 * GRUB splash screen will not be enabled.
			 */
			if (strncmp(console, "text", strlen("text")) == 0 ||
			    strncmp(console, "graphics",
			    strlen("graphics")) == 0) {

				(void) fprintf(temp_fp, "%s\n", BE_GRUB_SPLASH);
				(void) fprintf(temp_fp, "%s\n",
				    BE_GRUB_FOREGROUND);
				(void) fprintf(temp_fp, "%s\n",
				    BE_GRUB_BACKGROUND);
				(void) fprintf(temp_fp, "%s\n",
				    BE_GRUB_DEFAULT);
			} else {
				be_print_err(gettext("be_create_menu: "
				    "console on serial line, "
				    "GRUB splash image will be disabled\n"));
			}
		}

		(void) fprintf(temp_fp,	"timeout 30\n");
		(void) fclose(temp_fp);

	} else {
		/*
		 * The menu file doesn't exist so we need to create a
		 * blank file.
		 */
		FILE *temp_fp = fopen(menu_file, "w+");
		if (temp_fp == NULL) {
			*menu_fp = NULL;
			return (errno_to_be_err(errno));
		}
		(void) fclose(temp_fp);
	}

	/*
	 * Now we need to add all the BE's back into the the file.
	 */
	if (_be_list(NULL, &be_nodes) == BE_SUCCESS) {
		while (be_nodes != NULL) {
			if (strcmp(pool, be_nodes->be_rpool) == 0) {
				(void) be_append_menu(be_nodes->be_node_name,
				    be_nodes->be_rpool, NULL, NULL, NULL);
			}
			if (be_nodes->be_active_on_boot) {
				be_rpool = strdup(be_nodes->be_rpool);
				be_name = strdup(be_nodes->be_node_name);
			}

			be_nodes = be_nodes->be_next_node;
		}
	}
	be_free_list(be_nodes);

	/*
	 * Check to see if this system supports grub
	 */
	if (be_has_grub()) {
		int err = be_change_grub_default(be_name, be_rpool);
		if (err != BE_SUCCESS)
			return (err);
	}
	*menu_fp = fopen(menu_file, mode);
	if (*menu_fp == NULL)
		return (errno_to_be_err(errno));

	return (BE_SUCCESS);
}

/*
 * Function:	be_open_menu
 * Description:
 *		This function is used it open the menu.lst file. If this
 *              file does not exist be_create_menu is called to create it
 *              and the open file pointer is returned. If the file does
 *              exist it is simply opened using the mode passed in.
 * Parameters:
 *		pool - The name of the pool the menu.lst file is on
 *		menu_file - The name of the file we're opening.
 *		menu_fp - A pointer to the file pointer of the file we're
 *			  opening. This is also used to pass back the file
 *			  pointer.
 *		mode - the original mode to be used for opening the menu.lst
 *                     file.
 *              create_menu - If this is true and the menu.lst file does not
 *                            exist we will attempt to re-create it. However
 *                            if it's false the error returned from the fopen
 *                            will be returned.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_open_menu(
	char *pool,
	char *menu_file,
	FILE **menu_fp,
	char *mode,
	boolean_t create_menu)
{
	int	err = 0;
	boolean_t	set_print = B_FALSE;

	*menu_fp = fopen(menu_file, mode);
	err = errno;
	if (*menu_fp == NULL) {
		if (err == ENOENT && create_menu) {
			be_print_err(gettext("be_open_menu: menu.lst "
			    "file %s does not exist,\n"), menu_file);
			if (!do_print) {
				set_print = B_TRUE;
				do_print = B_TRUE;
			}
			be_print_err(gettext("WARNING: menu.lst "
			    "file %s does not exist,\n         generating "
			    "a new menu.lst file\n"), menu_file);
			if (set_print)
				do_print = B_FALSE;
			err = 0;
			if ((err = be_create_menu(pool, menu_file,
			    menu_fp, mode)) == ENOENT)
				return (BE_ERR_NO_MENU);
			else if (err != BE_SUCCESS)
				return (err);
			else if (*menu_fp == NULL)
				return (BE_ERR_NO_MENU);
		} else {
			be_print_err(gettext("be_open_menu: failed "
			    "to open menu.lst file %s\n"), menu_file);
			if (err == ENOENT)
				return (BE_ERR_NO_MENU);
			else
				return (errno_to_be_err(err));
		}
	}
	return (BE_SUCCESS);
}
