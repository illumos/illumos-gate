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

#include "mdescplugin.h"

static char *device_format_disk_name(char *devfs_path);
static char *device_get_disk_name_from_dir(char *basedir, char *path);
static cfga_list_data_t *device_get_disk_cfga_info(char *cfgpath);

/* These 3 variable are defined and set in mdescplugin.c */
extern picl_nodehdl_t	root_node;
extern md_t		*mdp;
extern mde_cookie_t	rootnode;

/* This routine is defined in cpu_prop_update.c */
extern void set_prop_info(ptree_propinfo_t *propinfo, int size, char *name,
    int type);

int
disk_discovery(void)
{
	int			status = PICL_FAILURE;
	picl_nodehdl_t		discovery_node;
	picl_nodehdl_t		new_node;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;
	char			*cfgpath, *dev_path, *nac;
	cfga_list_data_t	*disk_data;
	int			x, num_nodes, ndisks;
	mde_cookie_t		*disklistp;

	num_nodes = md_node_count(mdp);

	disklistp = (mde_cookie_t *) alloca(sizeof (mde_cookie_t) *num_nodes);
	if (disklistp == NULL) {
		return (status);
	}

	/*
	 * Starting at the root node, scan the "fwd" dag for
	 * all the disks in this description.
	 */

	ndisks = md_scan_dag(mdp, rootnode, md_find_name(mdp, "disk_nac"),
	    md_find_name(mdp, "fwd"), disklistp);

	if (ndisks <= 0) {
		return (status);
	}

	status = ptree_create_and_add_node(root_node, DISK_DISCOVERY_NAME,
	    PICL_CLASS_PICL, &discovery_node);
	if (status != PICL_SUCCESS)
		return (status);

	for (x = 0; x < ndisks; x++) {
		if (md_get_prop_str(mdp, disklistp[x], "phys_path",
			&dev_path) != 0) {
			continue;
		}

		if (md_get_prop_str(mdp, disklistp[x], "nac_name",
			&nac) != 0) {
			continue;
		}

		(void) ptree_create_and_add_node(discovery_node, "disk",
		    PICL_CLASS_DISK, &new_node);

		set_prop_info(&propinfo, PICL_PROPNAMELEN_MAX, "Path",
		    PICL_PTYPE_CHARSTRING);

		(void) ptree_create_and_add_prop(new_node, &propinfo,
		    (void *)dev_path, &proph);

		set_prop_info(&propinfo, PICL_PROPNAMELEN_MAX, "Location",
		    PICL_PTYPE_CHARSTRING);

		(void) ptree_create_and_add_prop(new_node, &propinfo,
		    (void *)nac, &proph);

		set_prop_info(&propinfo, PICL_PROPNAMELEN_MAX, "State",
		    PICL_PTYPE_CHARSTRING);

		cfgpath = device_format_disk_name(dev_path);

		if (cfgpath == NULL) {
			(void) ptree_create_and_add_prop(new_node, &propinfo,
			    (void *)strdup(UNCONFIGURED), &proph);
			continue;
		}

		disk_data = device_get_disk_cfga_info(cfgpath);
		if (disk_data == NULL) {
			continue;
		}

		switch (disk_data->ap_o_state) {
		case CFGA_STAT_UNCONFIGURED:
			(void) ptree_create_and_add_prop(new_node, &propinfo,
			    (void *)strdup(UNCONFIGURED), &proph);
			break;

		case CFGA_STAT_CONFIGURED:
			(void) ptree_create_and_add_prop(new_node, &propinfo,
			    (void *)strdup(CONFIGURED), &proph);
			break;

		default:
			break;
		}
	}
	return (status);
}

static cfga_list_data_t *
device_get_disk_cfga_info(char *cfgpath)
{
	char			**apid_names;
	char			apid_name[CFGA_AP_LOG_ID_LEN];
	cfga_err_t		cfga_err;
	struct cfga_list_data	*list_data;
	int			list_len, count;

	(void) strcpy(apid_name, cfgpath);

	apid_names = (char **)malloc(2 * sizeof (char *));
	apid_names[0] = apid_name;
	apid_names[1] = NULL;

	cfga_err = config_list_ext(1, (char * const *)apid_names, &list_data,
	    &list_len, NULL, NULL, NULL, CFGA_FLAG_LIST_ALL);
	free(apid_names);

	if (cfga_err != CFGA_OK || list_len == 0) {
		return (NULL);
	}

	/* free any extra entries if this is not unique */
	if (list_len > 1) {
		for (count = 1; count < list_len; count++) {
			free(&list_data[count]);
		}
	}

	return (&list_data[0]);
}


static char *
device_format_disk_name(char *devfs_path)
{
	char	devname[256];
	char	*diskname, *dev_cpy;
	char	apid_name[CFGA_AP_LOG_ID_LEN];

	(void) snprintf(devname, sizeof (devname), "/devices%s:a,raw",
	    devfs_path);

	diskname = device_get_disk_name_from_dir("/dev/rdsk", devname);
	if (diskname != NULL) {
		*strrchr(diskname, 's') = '\0';
		dev_cpy = strdup(diskname);
		*strchr(dev_cpy, 't') = '\0';

		(void) snprintf(apid_name, sizeof (apid_name), "%s::dsk/%s",
			dev_cpy, diskname);
		return (strdup(apid_name));
	}

	return (NULL);
}

/*
 * Getting a disk name is annoying.  Walking controllers
 * doesn't work if disks were added out of order (ie a new
 * controller card was installed), and DKIO controller numbers
 * seem to always be 0.  So we do it the old fashioned way:
 *
 * We get a target name (in the /devices tree), and we want
 * the node in /dev/rdsk that is a symlink to it.  So we walk
 * /dev/rdsk, stating each entry.  Since stat follows the symlink
 * automatically, we just compare the device and inode numbers
 * to the device and inode numbers of the target.  According to
 * the stat man page, this constitues a unique match.  The only
 * little cleanup is that this includes a slice #, which we take
 *  off.
 */

static char *
device_get_disk_name_from_dir(char *basedir, char *path)
{
	DIR		*dir;
	struct dirent	*dirent;
	struct stat	srcstat, targstat;
	int		loc_err;
	char		fullname[256 + MAXNAMLEN];
	char		*ptr;

	loc_err = stat(path, &srcstat);
	if (loc_err < 0) {
		return (NULL);
	}

	dir = opendir(basedir);
	if (dir == NULL) {
		return (NULL);
	}

	while ((dirent = readdir(dir)) != NULL) {
		(void) snprintf(fullname, sizeof (fullname),
			"%s/%s", basedir, dirent->d_name);

		loc_err = stat(fullname, &targstat);
		if (loc_err == 0) {
			if ((memcmp((void *)&(targstat.st_ino),
				(void *)&(srcstat.st_ino),
				sizeof (ino_t)) == 0) &&
				(memcmp((void *)&(targstat.st_dev),
				(void *)&(srcstat.st_dev),
				sizeof (dev_t)) == 0)) {

				ptr = strdup(dirent->d_name);

				(void) closedir(dir);
				return (ptr);
			}
		}
	}

	(void) closedir(dir);
	return (NULL);
}
