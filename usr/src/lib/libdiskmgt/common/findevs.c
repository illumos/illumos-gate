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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2011 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.
 */

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <ctype.h>
#include <libgen.h>
#include <unistd.h>
#include <devid.h>
#include <sys/fs/zfs.h>

#include "libdiskmgt.h"
#include "disks_private.h"

/* specify which disk links to use in the /dev directory */
#define	DEVLINK_REGEX		"rdsk/.*"
#define	DEVLINK_FLOPPY_REGEX	"rdiskette[0-9]"

#define	FLOPPY_NAME	"rdiskette"

#define	MAXPROPLEN		1024
#define	DEVICE_ID_PROP		"devid"
#define	PROD_ID_PROP		"inquiry-product-id"
#define	PROD_ID_USB_PROP	"usb-product-name"
#define	REMOVABLE_PROP		"removable-media"
#define	HOTPLUGGABLE_PROP	"hotpluggable"
#define	SCSI_OPTIONS_PROP	"scsi-options"
#define	VENDOR_ID_PROP		"inquiry-vendor-id"
#define	VENDOR_ID_USB_PROP	"usb-vendor-name"
#define	WWN_PROP		"node-wwn"

static char *ctrltypes[] = {
	DDI_NT_FC_ATTACHMENT_POINT,
	DDI_NT_NVME_ATTACHMENT_POINT,
	DDI_NT_SATA_ATTACHMENT_POINT,
	DDI_NT_SATA_NEXUS,
	DDI_NT_SCSI_ATTACHMENT_POINT,
	DDI_NT_SCSI_NEXUS,
	NULL
};

static char *bustypes[] = {
	"sbus",
	"pci",
	"usb",
	NULL
};

static bus_t		*add_bus(struct search_args *args, di_node_t node,
			    di_minor_t minor, controller_t *cp);
static controller_t	*add_controller(struct search_args *args,
			    di_node_t node, di_minor_t minor);
static int		add_devpath(di_devlink_t devlink, void *arg);
static int		add_devs(di_node_t node, di_minor_t minor, void *arg);
static int		add_disk2controller(disk_t *diskp,
			    struct search_args *args);
static int		add_disk2path(disk_t *dp, path_t *pp,
			    di_path_state_t st, char *wwn);
static int		add_int2array(int p, int **parray);
static int		add_ptr2array(void *p, void ***parray);
static char		*bus_type(di_node_t node, di_minor_t minor,
			    di_prom_handle_t ph);
static void		remove_controller(controller_t *cp,
			    controller_t *currp);
static void		clean_paths(struct search_args *args);
static disk_t		*create_disk(char *deviceid, char *kernel_name,
			    struct search_args *args);
static char		*ctype(di_node_t node, di_minor_t minor);
static boolean_t	disk_is_cdrom(const char *type);
static alias_t		*find_alias(disk_t *diskp, char *kernel_name);
static bus_t		*find_bus(struct search_args *args, char *name);
static controller_t	*find_controller(struct search_args *args, char *name);
static disk_t		*get_disk_by_deviceid(disk_t *listp, char *devid);
static void		get_disk_name_from_path(char *path, char *name,
			    int size);
static char		*get_byte_prop(char *prop_name, di_node_t node);
static di_node_t	get_parent_bus(di_node_t node,
			    struct search_args *args);
static int		get_prom_int(char *prop_name, di_node_t node,
			    di_prom_handle_t ph);
static char		*get_prom_str(char *prop_name, di_node_t node,
			    di_prom_handle_t ph);
static int		get_prop(char *prop_name, di_node_t node);
static char		*get_str_prop(char *prop_name, di_node_t node);
static int		have_disk(struct search_args *args, char *devid,
			    char *kernel_name, disk_t **diskp);
static int		is_ctds(char *name);
static int		is_drive(di_minor_t minor);
static int		is_zvol(di_node_t node, di_minor_t minor);
static int		is_ctrl(di_node_t node, di_minor_t minor);
static int		new_alias(disk_t *diskp, char *kernel_path,
			    char *devlink_path, struct search_args *args);
static int		new_devpath(alias_t *ap, char *devpath);
static path_t		*new_path(controller_t *cp, disk_t *diskp,
			    di_node_t node, di_path_state_t st, char *wwn);
static void		remove_invalid_controller(char *name,
			    controller_t *currp, struct search_args *args);

/*
 * The functions in this file do a dev tree walk to build up a model of the
 * disks, controllers and paths on the system.  This model is returned in the
 * args->disk_listp and args->controller_listp members of the args param.
 * There is no global data for this file so it is thread safe.  It is up to
 * the caller to merge the resulting model with any existing model that is
 * cached.  The caller must also free the memory for this model when it is
 * no longer needed.
 */
void
findevs(struct search_args *args)
{
	di_node_t		di_root;

	args->bus_listp = NULL;
	args->controller_listp = NULL;
	args->disk_listp = NULL;

	args->dev_walk_status = 0;
	args->handle = di_devlink_init(NULL, 0);

	/*
	 * Have to make several passes at this with the new devfs caching.
	 * First, we find non-mpxio devices. Then we find mpxio/multipath
	 * devices.
	 */
	di_root = di_init("/", DINFOCACHE);
	args->ph = di_prom_init();
	(void) di_walk_minor(di_root, NULL, 0, args, add_devs);
	di_fini(di_root);

	di_root = di_init("/", DINFOCPYALL|DINFOPATH);
	(void) di_walk_minor(di_root, NULL, 0, args, add_devs);
	di_fini(di_root);

	(void) di_devlink_fini(&(args->handle));

	clean_paths(args);
}

/*
 * Definitions of private functions
 */

static bus_t *
add_bus(struct search_args *args, di_node_t node, di_minor_t minor,
    controller_t *cp)
{
	char		*btype;
	char		*devpath;
	bus_t		*bp;
	char		kstat_name[MAXPATHLEN];
	di_node_t	pnode;

	if (node == DI_NODE_NIL) {
		return (NULL);
	}

	if ((btype = bus_type(node, minor, args->ph)) == NULL) {
		return (add_bus(args, di_parent_node(node),
		    di_minor_next(di_parent_node(node), NULL), cp));
	}

	devpath = di_devfs_path(node);

	if ((bp = find_bus(args, devpath)) != NULL) {
		di_devfs_path_free((void *) devpath);

		if (cp != NULL) {
			if (add_ptr2array(cp,
			    (void ***)&bp->controllers) != 0) {
				args->dev_walk_status = ENOMEM;
				return (NULL);
			}
		}
		return (bp);
	}

	/* Special handling for root node. */
	if (strcmp(devpath, "/") == 0) {
		di_devfs_path_free((void *) devpath);
		return (NULL);
	}

	if (dm_debug) {
		(void) fprintf(stderr, "INFO: add_bus %s\n", devpath);
	}

	bp = (bus_t *)calloc(1, sizeof (bus_t));
	if (bp == NULL) {
		return (NULL);
	}

	bp->name = strdup(devpath);
	di_devfs_path_free((void *) devpath);
	if (bp->name == NULL) {
		args->dev_walk_status = ENOMEM;
		cache_free_bus(bp);
		return (NULL);
	}

	bp->btype = strdup(btype);
	if (bp->btype == NULL) {
		args->dev_walk_status = ENOMEM;
		cache_free_bus(bp);
		return (NULL);
	}

	(void) snprintf(kstat_name, sizeof (kstat_name), "%s%d",
	    di_node_name(node), di_instance(node));

	if ((bp->kstat_name = strdup(kstat_name)) == NULL) {
		args->dev_walk_status = ENOMEM;
		cache_free_bus(bp);
		return (NULL);
	}

	/* if parent node is a bus, get its name */
	if ((pnode = get_parent_bus(node, args)) != NULL) {
		devpath = di_devfs_path(pnode);
		bp->pname = strdup(devpath);
		di_devfs_path_free((void *) devpath);
		if (bp->pname == NULL) {
			args->dev_walk_status = ENOMEM;
			cache_free_bus(bp);
			return (NULL);
		}

	} else {
		bp->pname = NULL;
	}

	bp->freq = get_prom_int("clock-frequency", node, args->ph);

	bp->controllers = (controller_t **)calloc(1, sizeof (controller_t *));
	if (bp->controllers == NULL) {
		args->dev_walk_status = ENOMEM;
		cache_free_bus(bp);
		return (NULL);
	}
	bp->controllers[0] = NULL;

	if (cp != NULL) {
		if (add_ptr2array(cp, (void ***)&bp->controllers) != 0) {
			args->dev_walk_status = ENOMEM;
			return (NULL);
		}
	}

	bp->next = args->bus_listp;
	args->bus_listp = bp;

	return (bp);
}

static controller_t *
add_controller(struct search_args *args, di_node_t node, di_minor_t minor)
{
	char		*devpath;
	controller_t	*cp;
	char		kstat_name[MAXPATHLEN];
	char		*c_type = DM_CTYPE_UNKNOWN;

	devpath = di_devfs_path(node);

	if ((cp = find_controller(args, devpath)) != NULL) {
		di_devfs_path_free((void *) devpath);
		return (cp);
	}

	/* Special handling for fp attachment node. */
	if (strcmp(di_node_name(node), "fp") == 0) {
		di_node_t pnode;

		pnode = di_parent_node(node);
		if (pnode != DI_NODE_NIL) {
			di_devfs_path_free((void *) devpath);
			devpath = di_devfs_path(pnode);

			if ((cp = find_controller(args, devpath)) != NULL) {
				di_devfs_path_free((void *) devpath);
				return (cp);
			}

			/* not in the list, create it */
			node = pnode;
			c_type = DM_CTYPE_FIBRE;
		}
	}

	if (dm_debug) {
		(void) fprintf(stderr, "INFO: add_controller %s\n", devpath);
	}

	cp = (controller_t *)calloc(1, sizeof (controller_t));
	if (cp == NULL) {
		return (NULL);
	}

	cp->name = strdup(devpath);
	di_devfs_path_free((void *) devpath);
	if (cp->name == NULL) {
		cache_free_controller(cp);
		return (NULL);
	}

	if (strcmp(c_type, DM_CTYPE_UNKNOWN) == 0) {
		c_type = ctype(node, minor);
	}
	cp->ctype = c_type;

	(void) snprintf(kstat_name, sizeof (kstat_name), "%s%d",
	    di_node_name(node), di_instance(node));

	if ((cp->kstat_name = strdup(kstat_name)) == NULL) {
		cache_free_controller(cp);
		return (NULL);
	}

	if (libdiskmgt_str_eq(cp->ctype, "scsi")) {
		cp->scsi_options = get_prop(SCSI_OPTIONS_PROP, node);
	}

	if (libdiskmgt_str_eq(di_node_name(node), "scsi_vhci")) {
		cp->multiplex = 1;
	} else {
		cp->multiplex = 0;
	}

	cp->freq = get_prom_int("clock-frequency", node, args->ph);

	cp->disks = (disk_t **)calloc(1, sizeof (disk_t *));
	if (cp->disks == NULL) {
		cache_free_controller(cp);
		return (NULL);
	}
	cp->disks[0] = NULL;

	cp->next = args->controller_listp;
	args->controller_listp = cp;

	cp->bus = add_bus(args, di_parent_node(node),
	    di_minor_next(di_parent_node(node), NULL), cp);

	return (cp);
}

static int
add_devpath(di_devlink_t devlink, void *arg)
{
	struct search_args *args;
	char		*devidstr;
	disk_t		*diskp;
	char		kernel_name[MAXPATHLEN];

	args =	(struct search_args *)arg;

	/*
	 * Get the diskp value from calling have_disk. Can either be found
	 * by kernel name or devid.
	 */

	diskp = NULL;
	devidstr = get_str_prop(DEVICE_ID_PROP, args->node);
	(void) snprintf(kernel_name, sizeof (kernel_name), "%s%d",
	    di_node_name(args->node), di_instance(args->node));

	(void) have_disk(args, devidstr, kernel_name, &diskp);

	/*
	 * The devlink_path is usually of the form /dev/rdsk/c0t0d0s0.
	 * For diskettes it is /dev/rdiskette*.
	 * On Intel we would also get each fdisk partition as well
	 * (e.g. /dev/rdsk/c0t0d0p0).
	 */
	if (diskp != NULL) {
		alias_t	*ap;
		char	*devlink_path;

		if (diskp->drv_type != DM_DT_FLOPPY) {
			/*
			 * Add other controllers for multipath disks.
			 * This will have no effect if the controller
			 * relationship is already set up.
			 */
			if (add_disk2controller(diskp, args) != 0) {
				args->dev_walk_status = ENOMEM;
			}
		}

		(void) snprintf(kernel_name, sizeof (kernel_name), "%s%d",
		    di_node_name(args->node), di_instance(args->node));
		devlink_path = (char *)di_devlink_path(devlink);

		if (dm_debug > 1) {
			(void) fprintf(stderr,
			    "INFO:     devpath %s\n", devlink_path);
		}

		if ((ap = find_alias(diskp, kernel_name)) == NULL) {
			if (new_alias(diskp, kernel_name, devlink_path,
			    args) != 0) {
				args->dev_walk_status = ENOMEM;
			}
		} else {
			/*
			 * It is possible that we have already added this
			 * devpath.  Do not add it again. new_devpath will
			 * return a 0 if found, and not add the path.
			 */
			if (new_devpath(ap, devlink_path) != 0) {
				args->dev_walk_status = ENOMEM;
			}
		}
	}

	return (DI_WALK_CONTINUE);
}

static int
add_devs(di_node_t node, di_minor_t minor, void *arg)
{
	struct search_args	*args;
	int result = DI_WALK_CONTINUE;

	args = (struct search_args *)arg;

	if (dm_debug > 1) {
		/* This is all just debugging code */
		char	*devpath;
		char	dev_name[MAXPATHLEN];

		devpath = di_devfs_path(node);
		(void) snprintf(dev_name, sizeof (dev_name), "%s:%s", devpath,
		    di_minor_name(minor));
		di_devfs_path_free((void *) devpath);

		(void) fprintf(stderr,
		    "INFO: dev: %s, node: %s%d, minor: 0x%x, type: %s\n",
		    dev_name, di_node_name(node), di_instance(node),
		    di_minor_spectype(minor),
		    (di_minor_nodetype(minor) != NULL ?
		    di_minor_nodetype(minor) : "NULL"));
	}

	if (bus_type(node, minor, args->ph) != NULL) {
		if (add_bus(args, node, minor, NULL) == NULL) {
			args->dev_walk_status = ENOMEM;
			result = DI_WALK_TERMINATE;
		}

	} else if (is_ctrl(node, minor)) {
		if (add_controller(args, node, minor) == NULL) {
			args->dev_walk_status = ENOMEM;
			result = DI_WALK_TERMINATE;
		}

	} else if (di_minor_spectype(minor) == S_IFCHR &&
	    (is_drive(minor) || is_zvol(node, minor))) {
		char	*devidstr;
		char	kernel_name[MAXPATHLEN];
		disk_t	*diskp;

		(void) snprintf(kernel_name, sizeof (kernel_name), "%s%d",
		    di_node_name(node), di_instance(node));
		devidstr = get_str_prop(DEVICE_ID_PROP, node);

		args->node = node;
		args->minor = minor;
		/*
		 * Check if we already got this disk and
		 * this is another slice.
		 */
		if (!have_disk(args, devidstr, kernel_name, &diskp)) {
			args->dev_walk_status = 0;
			/*
			 * This is a newly found disk, create the
			 * disk structure.
			 */
			diskp = create_disk(devidstr, kernel_name, args);
			if (diskp == NULL) {
				args->dev_walk_status = ENOMEM;
			}

			if (diskp->drv_type != DM_DT_FLOPPY) {
				/* add the controller relationship */
				if (args->dev_walk_status == 0) {
					if (add_disk2controller(diskp,
					    args) != 0) {
						args->dev_walk_status = ENOMEM;
					}
				}
			}
		}
		if (is_zvol(node, minor)) {
			char zvdsk[MAXNAMELEN];
			char *str;
			alias_t *ap;

			if (di_prop_lookup_strings(di_minor_devt(minor),
			    node, "name", &str) == -1)
				return (DI_WALK_CONTINUE);
			(void) snprintf(zvdsk, MAXNAMELEN, "/dev/zvol/rdsk/%s",
			    str);
			if ((ap = find_alias(diskp, kernel_name)) == NULL) {
				if (new_alias(diskp, kernel_name,
				    zvdsk, args) != 0) {
					args->dev_walk_status = ENOMEM;
				}
			} else {
				/*
				 * It is possible that we have already added
				 * this devpath.
				 * Do not add it again. new_devpath will
				 * return a 0 if found, and not add the path.
				 */
				if (new_devpath(ap, zvdsk) != 0) {
					args->dev_walk_status = ENOMEM;
				}
			}
		}

		/* Add the devpaths for the drive. */
		if (args->dev_walk_status == 0) {
			char	*devpath;
			char	slice_path[MAXPATHLEN];
			char	*pattern;

			/*
			 * We will come through here once for each of
			 * the raw slice device names.
			 */
			devpath = di_devfs_path(node);
			(void) snprintf(slice_path,
			    sizeof (slice_path), "%s:%s",
			    devpath, di_minor_name(minor));
			di_devfs_path_free((void *) devpath);

			if (libdiskmgt_str_eq(di_minor_nodetype(minor),
			    DDI_NT_FD)) {
				pattern = DEVLINK_FLOPPY_REGEX;
			} else {
				pattern = DEVLINK_REGEX;
			}

			/* Walk the /dev tree to get the devlinks. */
			(void) di_devlink_walk(args->handle, pattern,
			    slice_path, DI_PRIMARY_LINK, arg, add_devpath);
		}

		if (args->dev_walk_status != 0) {
			result = DI_WALK_TERMINATE;
		}
	}

	return (result);
}

static int
add_disk2controller(disk_t *diskp, struct search_args *args)
{
	di_node_t	pnode;
	controller_t	*cp;
	di_minor_t	minor;
	di_node_t	node;
	int		i;

	node = args->node;

	pnode = di_parent_node(node);
	if (pnode == DI_NODE_NIL) {
		return (0);
	}

	minor = di_minor_next(pnode, NULL);
	if (minor == NULL) {
		return (0);
	}

	if ((cp = add_controller(args, pnode, minor)) == NULL) {
		return (ENOMEM);
	}

	/* check if the disk <-> ctrl assoc is already there */
	for (i = 0; diskp->controllers[i]; i++) {
		if (cp == diskp->controllers[i]) {
			return (0);
		}
	}

	/* this is a new controller for this disk */

	/* add the disk to the controller */
	if (add_ptr2array(diskp, (void ***)&cp->disks) != 0) {
		return (ENOMEM);
	}

	/* add the controller to the disk */
	if (add_ptr2array(cp, (void ***)&diskp->controllers) != 0) {
		return (ENOMEM);
	}

	/*
	 * Set up paths for mpxio controlled drives.
	 */
	if (libdiskmgt_str_eq(di_node_name(pnode), "scsi_vhci")) {
		/* note: mpxio di_path stuff is all consolidation private */
		di_path_t   pi = DI_PATH_NIL;

		while (
		    (pi = di_path_client_next_path(node, pi)) != DI_PATH_NIL) {
			int	cnt;
			uchar_t	*bytes;
			char	str[MAXPATHLEN];
			char	*wwn;

			di_node_t phci_node = di_path_phci_node(pi);

			/* get the node wwn */
			cnt = di_path_prop_lookup_bytes(pi, WWN_PROP, &bytes);
			wwn = NULL;
			if (cnt > 0) {
				int	i;
				str[0] = 0;

				for (i = 0; i < cnt; i++) {
					/*
					 * A byte is only 2 hex chars + null.
					 */
					char bstr[8];

					(void) snprintf(bstr,
					    sizeof (bstr), "%.2x", bytes[i]);
					(void) strlcat(str, bstr, sizeof (str));
				}
				wwn = str;
			}

			if (new_path(cp, diskp, phci_node,
			    di_path_state(pi), wwn) == NULL) {
				return (ENOMEM);
			}
		}
	}

	return (0);
}

static int
add_disk2path(disk_t *dp, path_t *pp, di_path_state_t st, char *wwn)
{
	/* add the disk to the path */
	if (add_ptr2array(dp, (void ***)&pp->disks) != 0) {
		cache_free_path(pp);
		return (0);
	}

	/* add the path to the disk */
	if (add_ptr2array(pp, (void ***)&dp->paths) != 0) {
		cache_free_path(pp);
		return (0);
	}

	/* add the path state for this disk */
	if (add_int2array(st, &pp->states) != 0) {
		cache_free_path(pp);
		return (0);
	}

	/* add the path state for this disk */
	if (wwn != NULL) {
		char	*wp;

		if ((wp = strdup(wwn)) != NULL) {
			if (add_ptr2array(wp, (void ***)(&pp->wwns)) != 0) {
				cache_free_path(pp);
				return (0);
			}
		}
	}

	return (1);
}

static int
add_int2array(int p, int **parray)
{
	int		i;
	int		cnt;
	int		*pa;
	int		*new_array;

	pa = *parray;

	cnt = 0;
	if (pa != NULL) {
		for (; pa[cnt] != -1; cnt++)
			;
	}

	new_array = (int *)calloc(cnt + 2, sizeof (int *));
	if (new_array == NULL) {
		return (ENOMEM);
	}

	/* copy the existing array */
	for (i = 0; i < cnt; i++) {
		new_array[i] = pa[i];
	}

	new_array[i] = p;
	new_array[i + 1] = -1;

	free(pa);
	*parray = new_array;

	return (0);
}

static int
add_ptr2array(void *p, void ***parray)
{
	int		i;
	int		cnt;
	void		**pa;
	void		**new_array;

	pa = *parray;

	cnt = 0;
	if (pa != NULL) {
		for (; pa[cnt]; cnt++)
			;
	}

	new_array = (void **)calloc(cnt + 2, sizeof (void *));
	if (new_array == NULL) {
		return (ENOMEM);
	}

	/* copy the existing array */
	for (i = 0; i < cnt; i++) {
		new_array[i] = pa[i];
	}

	new_array[i] = p;
	new_array[i + 1] = NULL;

	free(pa);
	*parray = new_array;

	return (0);
}

/*
 * This function checks to see if a controller has other associations
 * that may be valid. If we are calling this function, we have found that
 * a controller for an mpxio device is showing up independently of the
 * mpxio controller, noted as /scsi_vhci. This can happen with some FC
 * cards that have inbound management devices that show up as well, with
 * the real controller data associated. We do not want to display these
 * 'devices' as real devices in libdiskmgt.
 */
static void
remove_controller(controller_t *cp, controller_t *currp)
{
	int	i;

	if (cp == currp) {
		if (dm_debug) {
			(void) fprintf(stderr, "ERROR: removing current"
			    " controller\n");
		}
		return;
	}

	if (cp->disks != NULL && cp->disks[0] != NULL) {
		if (dm_debug) {
			(void) fprintf(stderr,
			    "INFO: removing inbound management controller"
			    " with disk ptrs.\n");
		}
		/*
		 * loop through the disks and remove the reference to the
		 * controller for this disk structure. The disk itself
		 * is still a valid device, the controller being removed
		 * is a 'path' so any disk that has a reference to it
		 * as a controller needs to have this reference removed.
		 */
		for (i = 0; cp->disks[i]; i++) {
			disk_t *dp = cp->disks[i];
			int j;

			for (j = 0; dp->controllers[j]; j++) {
				int k;

				if (libdiskmgt_str_eq(dp->controllers[j]->name,
				    cp->name)) {

					if (dm_debug) {
						(void) fprintf(stderr,
						    "INFO: REMOVING disk %s on "
						    "controller %s\n",
						    dp->kernel_name, cp->name);
					}
					for (k = j; dp->controllers[k]; k++) {
						dp->controllers[k] =
						    dp->controllers[k + 1];
					}
				}
			}
		}
	}
	/*
	 * Paths are removed with the call to cache_free_controller()
	 * below.
	 */

	if (cp->paths != NULL && cp->paths[0] != NULL) {
		if (dm_debug) {
			(void) fprintf(stderr,
			    "INFO: removing inbound management controller"
			    " with path ptrs. \n");
		}
	}
	cache_free_controller(cp);
}

/*
 * If we have a controller in the list that is really a path then we need to
 * take that controller out of the list since nodes that are paths are not
 * considered to be controllers.
 */
static void
clean_paths(struct search_args *args)
{
	controller_t	*cp;

	cp = args->controller_listp;
	while (cp != NULL) {
		path_t	**pp;

		pp = cp->paths;
		if (pp != NULL) {
			int i;

			for (i = 0; pp[i]; i++) {
				remove_invalid_controller(pp[i]->name, cp,
				    args);
			}
		}
		cp = cp->next;
	}
}

static disk_t *
create_disk(char *deviceid, char *kernel_name, struct search_args *args)
{
	disk_t	*diskp;
	char	*type;
	char	*prod_id;
	char	*vendor_id;

	if (dm_debug) {
		(void) fprintf(stderr, "INFO: create_disk %s\n", kernel_name);
	}

	diskp = calloc(1, sizeof (disk_t));
	if (diskp == NULL) {
		return (NULL);
	}

	diskp->controllers = (controller_t **)
	    calloc(1, sizeof (controller_t *));
	if (diskp->controllers == NULL) {
		cache_free_disk(diskp);
		return (NULL);
	}
	diskp->controllers[0] = NULL;

	diskp->devid = NULL;
	if (deviceid != NULL) {
		if ((diskp->device_id = strdup(deviceid)) == NULL) {
			cache_free_disk(diskp);
			return (NULL);
		}
		(void) devid_str_decode(deviceid, &(diskp->devid), NULL);
	}

	if (kernel_name != NULL) {
		diskp->kernel_name = strdup(kernel_name);
		if (diskp->kernel_name == NULL) {
			cache_free_disk(diskp);
			return (NULL);
		}
	}

	diskp->paths = NULL;
	diskp->aliases = NULL;

	diskp->cd_rom = 0;
	diskp->rpm = 0;
	diskp->solid_state = -1;
	type = di_minor_nodetype(args->minor);

	prod_id = get_str_prop(PROD_ID_PROP, args->node);
	if (prod_id != NULL) {
		if ((diskp->product_id = strdup(prod_id)) == NULL) {
			cache_free_disk(diskp);
			return (NULL);
		}
	} else {
		prod_id = get_str_prop(PROD_ID_USB_PROP, args->node);
		if (prod_id != NULL) {
			if ((diskp->product_id = strdup(prod_id)) == NULL) {
				cache_free_disk(diskp);
				return (NULL);
			}
		}
	}

	vendor_id = get_str_prop(VENDOR_ID_PROP, args->node);
	if (vendor_id != NULL) {
		if ((diskp->vendor_id = strdup(vendor_id)) == NULL) {
			cache_free_disk(diskp);
			return (NULL);
		}
	} else {
		vendor_id = get_str_prop(VENDOR_ID_USB_PROP, args->node);
		if (vendor_id != NULL) {
			if ((diskp->vendor_id = strdup(vendor_id)) == NULL) {
				cache_free_disk(diskp);
				return (NULL);
			}
		}
	}

	/*
	 * DVD, CD-ROM, CD-RW, MO, etc. are all reported as CD-ROMS.
	 * We try to use uscsi later to determine the real type.
	 * The cd_rom flag tells us that the kernel categorized the drive
	 * as a CD-ROM.  We leave the drv_type as UNKNOWN for now.
	 * The combination of the cd_rom flag being set with the drv_type of
	 * unknown is what triggers the uscsi probe in drive.c.
	 */
	if (disk_is_cdrom(type)) {
		diskp->drv_type = DM_DT_UNKNOWN;
		diskp->cd_rom = 1;
		diskp->removable = 1;
	} else if (libdiskmgt_str_eq(type, DDI_NT_FD)) {
		diskp->drv_type = DM_DT_FLOPPY;
		diskp->removable = 1;
	} else {
		/* not a CD-ROM or Floppy */
		diskp->removable = get_prop(REMOVABLE_PROP, args->node);

		if (diskp->removable == -1) {
			diskp->removable = 0;
			diskp->drv_type = DM_DT_FIXED;
		}
	}

	diskp->next = args->disk_listp;
	args->disk_listp = diskp;

	return (diskp);
}

static char *
ctype(di_node_t node, di_minor_t minor)
{
	char	*type;
	char	*name;

	type = di_minor_nodetype(minor);
	name = di_node_name(node);

	/* IDE disks use SCSI nexus as the type, so handle this special case */
	if ((libdiskmgt_str_eq(type, DDI_NT_SCSI_NEXUS) ||
	    libdiskmgt_str_eq(type, DDI_PSEUDO)) &&
	    libdiskmgt_str_eq(name, "ide"))
		return (DM_CTYPE_ATA);

	if (libdiskmgt_str_eq(type, DDI_NT_FC_ATTACHMENT_POINT) ||
	    (libdiskmgt_str_eq(type, DDI_NT_NEXUS) &&
	    libdiskmgt_str_eq(name, "fp")))
		return (DM_CTYPE_FIBRE);

	if (libdiskmgt_str_eq(type, DDI_NT_NVME_ATTACHMENT_POINT))
		return (DM_CTYPE_NVME);

	if (libdiskmgt_str_eq(type, DDI_NT_SATA_NEXUS) ||
	    libdiskmgt_str_eq(type, DDI_NT_SATA_ATTACHMENT_POINT))
		return (DM_CTYPE_SATA);

	if (libdiskmgt_str_eq(type, DDI_NT_SCSI_NEXUS) ||
	    libdiskmgt_str_eq(type, DDI_NT_SCSI_ATTACHMENT_POINT))
		return (DM_CTYPE_SCSI);

	if (libdiskmgt_str_eq(di_minor_name(minor), "scsa2usb"))
		return (DM_CTYPE_USB);

	if (libdiskmgt_str_eq(type, DDI_PSEUDO) &&
	    libdiskmgt_str_eq(name, "xpvd"))
		return (DM_CTYPE_XEN);

	if (dm_debug) {
		(void) fprintf(stderr,
		    "INFO: unknown controller type=%s name=%s\n", type, name);
	}

	return (DM_CTYPE_UNKNOWN);
}

static boolean_t
disk_is_cdrom(const char *type)
{
	return (strncmp(type, DDI_NT_CD, strlen(DDI_NT_CD)) == 0);
}

static alias_t *
find_alias(disk_t *diskp, char *kernel_name)
{
	alias_t	*ap;

	ap = diskp->aliases;
	while (ap != NULL) {
		if (libdiskmgt_str_eq(ap->kstat_name, kernel_name)) {
			return (ap);
		}
		ap = ap->next;
	}

	return (NULL);
}

static bus_t *
find_bus(struct search_args *args, char *name)
{
	bus_t *listp;

	listp = args->bus_listp;
	while (listp != NULL) {
		if (libdiskmgt_str_eq(listp->name, name)) {
			return (listp);
		}
		listp = listp->next;
	}

	return (NULL);
}

static controller_t *
find_controller(struct search_args *args, char *name)
{
	controller_t *listp;

	listp = args->controller_listp;
	while (listp != NULL) {
		if (libdiskmgt_str_eq(listp->name, name)) {
			return (listp);
		}
		listp = listp->next;
	}

	return (NULL);
}

/*
 * Check if we have the drive in our list, based upon the device id.
 * We got the device id from the dev tree walk.  This is encoded
 * using devid_str_encode(3DEVID).   In order to check the device ids we need
 * to use the devid_compare(3DEVID) function, so we need to decode the
 * string representation of the device id.
 */
static disk_t *
get_disk_by_deviceid(disk_t *listp, char *devidstr)
{
	ddi_devid_t	devid;

	if (devidstr == NULL || devid_str_decode(devidstr, &devid, NULL) != 0) {
		return (NULL);
	}

	while (listp != NULL) {
		if (listp->devid != NULL &&
		    devid_compare(listp->devid, devid) == 0) {
			break;
		}
		listp = listp->next;
	}

	devid_free(devid);
	return (listp);
}

/*
 * Get the base disk name with no path prefix and no slice (if there is one).
 * The name parameter should be big enough to hold the name.
 * This handles diskette names ok (/dev/rdiskette0) since there is no slice,
 * and converts the raw diskette name.
 * But, we don't know how to strip off the slice from third party drive
 * names.  That just means that their drive name will include a slice on
 * it.
 */
static void
get_disk_name_from_path(char *path, char *name, int size)
{
	char		*basep;
	int		cnt = 0;

	basep = strrchr(path, '/');
	if (basep == NULL) {
		basep = path;
	} else {
		basep++;
	}

	size = size - 1;	/* leave room for terminating 0 */

	if (is_ctds(basep)) {
		while (*basep != 0 && *basep != 's' && cnt < size) {
			*name++ = *basep++;
				cnt++;
		}
		*name = 0;
	} else {
		if (strncmp(basep, FLOPPY_NAME,
		    sizeof (FLOPPY_NAME) - 1) == 0) {
			/*
			 * a floppy, convert rdiskette name to diskette name,
			 * by skipping over the 'r' for raw diskette
			 */
			basep++;
		}

		/* not a ctds name, just copy it */
		(void) strlcpy(name, basep, size);
	}
}

static char *
get_byte_prop(char *prop_name, di_node_t node)
{
	int	cnt;
	uchar_t	*bytes;
	int	i;
	char	str[MAXPATHLEN];

	cnt = di_prop_lookup_bytes(DDI_DEV_T_ANY, node, prop_name, &bytes);
	if (cnt < 1) {
		return (NULL);
	}

	str[0] = 0;
	for (i = 0; i < cnt; i++) {
		char bstr[8];	/* a byte is only 2 hex chars + null */

		(void) snprintf(bstr, sizeof (bstr), "%.2x", bytes[i]);
		(void) strlcat(str, bstr, sizeof (str));
	}
	return (strdup(str));
}

static di_node_t
get_parent_bus(di_node_t node, struct search_args *args)
{
	di_node_t pnode;

	pnode = di_parent_node(node);
	if (pnode == DI_NODE_NIL) {
		return (NULL);
	}

	if (bus_type(pnode, di_minor_next(pnode, NULL), args->ph) != NULL) {
		return (pnode);
	}

	return (get_parent_bus(pnode, args));
}

static int
get_prom_int(char *prop_name, di_node_t node, di_prom_handle_t ph)
{
	int *n;

	if (di_prom_prop_lookup_ints(ph, node, prop_name, &n) == 1) {
		return (*n);
	}

	return (0);
}

static char *
get_prom_str(char *prop_name, di_node_t node, di_prom_handle_t ph)
{
	char *str;

	if (di_prom_prop_lookup_strings(ph, node, prop_name, &str) == 1) {
		return (str);
	}

	return (NULL);
}

/*
 * Get one of the positive int or boolean properties.
 */
static int
get_prop(char *prop_name, di_node_t node)
{
	int num;
	int *ip;

	if ((num = di_prop_lookup_ints(DDI_DEV_T_ANY, node, prop_name, &ip))
	    >= 0) {
		if (num == 0) {
			/* boolean */
			return (1);
		} else if (num == 1) {
			/* single int */
			return (*ip);
		}
	}
	return (-1);
}

static char *
get_str_prop(char *prop_name, di_node_t node)
{
	char *str;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, prop_name, &str) == 1) {
		return (str);
	}

	return (NULL);
}

/*
 * Check if we have the drive in our list, based upon the device id, if the
 * drive has a device id, or the kernel name, if it doesn't have a device id.
 */
static int
have_disk(struct search_args *args, char *devidstr, char *kernel_name,
    disk_t **diskp)
{
	disk_t *listp;

	*diskp = NULL;
	listp = args->disk_listp;
	if (devidstr != NULL) {
		if ((*diskp = get_disk_by_deviceid(listp, devidstr)) != NULL) {
			return (1);
		}

	} else {
		/* no devid, try matching the kernel names on the drives */
		while (listp != NULL) {
			if (libdiskmgt_str_eq(kernel_name,
			    listp->kernel_name)) {
				*diskp = listp;
				return (1);
			}
			listp = listp->next;
		}
	}
	return (0);
}

static char *
bus_type(di_node_t node, di_minor_t minor, di_prom_handle_t ph)
{
	char	*type;
	int	i;

	type = get_prom_str("device_type", node, ph);
	if (type == NULL) {
		type = di_node_name(node);
	}

	for (i = 0; bustypes[i]; i++) {
		if (libdiskmgt_str_eq(type, bustypes[i])) {
			return (type);
		}
	}

	if (minor != NULL && strcmp(di_minor_nodetype(minor),
	    DDI_NT_USB_ATTACHMENT_POINT) == 0) {
		return ("usb");
	}

	return (NULL);
}

/*
 * If the input name is in c[t]ds format then return 1, otherwise return 0.
 */
static int
is_ctds(char *name)
{
	char	*p;

	p = name;

	if (*p++ != 'c') {
		return (0);
	}
	/* skip controller digits */
	while (isdigit(*p)) {
		p++;
	}

	/* handle optional target */
	if (*p == 't') {
		p++;
		/* skip over target */
		while (isdigit(*p) || isupper(*p)) {
			p++;
		}
	}

	if (*p++ != 'd') {
		return (0);
	}
	while (isdigit(*p)) {
		p++;
	}

	if (*p++ != 's') {
		return (0);
	}

	/* check the slice number */
	while (isdigit(*p)) {
		p++;
	}

	if (*p != 0) {
		return (0);
	}

	return (1);
}

static int
is_drive(di_minor_t minor)
{
	return (strncmp(di_minor_nodetype(minor), DDI_NT_BLOCK,
	    strlen(DDI_NT_BLOCK)) == 0);
}

static int
is_zvol(di_node_t node, di_minor_t minor)
{
	if ((strncmp(di_node_name(node), ZFS_DRIVER, 3) == 0) &&
	    minor(di_minor_devt(minor)))
		return (1);
	return (0);
}

static int
is_ctrl(di_node_t node, di_minor_t minor)
{
	char	*type;
	char	*name;
	int	type_index;

	type = di_minor_nodetype(minor);
	type_index = 0;

	while (ctrltypes[type_index] != NULL) {
		if (libdiskmgt_str_eq(type, ctrltypes[type_index])) {
			return (1);
		}
		type_index++;
	}

	name = di_node_name(node);
	if (libdiskmgt_str_eq(type, DDI_PSEUDO) &&
	    (libdiskmgt_str_eq(name, "ide") ||
	    libdiskmgt_str_eq(name, "xpvd")))
		return (1);

	return (0);
}

static int
new_alias(disk_t *diskp, char *kernel_name, char *devlink_path,
    struct search_args *args)
{
	alias_t		*aliasp;
	char		alias[MAXPATHLEN];
	di_node_t	pnode;

	aliasp = malloc(sizeof (alias_t));
	if (aliasp == NULL) {
		return (ENOMEM);
	}

	aliasp->alias = NULL;
	aliasp->kstat_name = NULL;
	aliasp->wwn = NULL;
	aliasp->devpaths = NULL;
	aliasp->orig_paths = NULL;

	get_disk_name_from_path(devlink_path, alias, sizeof (alias));

	aliasp->alias = strdup(alias);
	if (aliasp->alias == NULL) {
		cache_free_alias(aliasp);
		return (ENOMEM);
	}

	if (kernel_name != NULL) {
		aliasp->kstat_name = strdup(kernel_name);
		if (aliasp->kstat_name == NULL) {
			cache_free_alias(aliasp);
			return (ENOMEM);
		}
	} else {
		aliasp->kstat_name = NULL;
	}

	aliasp->lun = get_prop(DM_LUN, args->node);
	aliasp->target = get_prop(DM_TARGET, args->node);
	aliasp->wwn = get_byte_prop(WWN_PROP, args->node);

	pnode = di_parent_node(args->node);
	if (pnode != DI_NODE_NIL) {
		char prop_name[MAXPROPLEN];

		(void) snprintf(prop_name, sizeof (prop_name),
		    "target%d-sync-speed", aliasp->target);
		diskp->sync_speed = get_prop(prop_name, pnode);
		(void) snprintf(prop_name, sizeof (prop_name), "target%d-wide",
		    aliasp->target);
		diskp->wide = get_prop(prop_name, pnode);
	}

	if (new_devpath(aliasp, devlink_path) != 0) {
		cache_free_alias(aliasp);
		return (ENOMEM);
	}

	aliasp->next = diskp->aliases;
	diskp->aliases = aliasp;

	return (0);
}

/*
 * Append the new devpath to the end of the devpath list.  This is important
 * since we may want to use the order of the devpaths to match up the vtoc
 * entries.
 */
static int
new_devpath(alias_t *ap, char *devpath)
{
	slice_t	*newdp;
	slice_t *alistp;

	/*
	 * First, search the alias list to be sure that this devpath is
	 * not already there.
	 */

	for (alistp = ap->devpaths; alistp != NULL; alistp = alistp->next) {
		if (libdiskmgt_str_eq(alistp->devpath, devpath)) {
			return (0);
		}
	}

	/*
	 * Otherwise, not found so add this new devpath to the list.
	 */

	newdp = malloc(sizeof (slice_t));
	if (newdp == NULL) {
		return (ENOMEM);
	}

	newdp->devpath = strdup(devpath);
	if (newdp->devpath == NULL) {
		free(newdp);
		return (ENOMEM);
	}
	newdp->slice_num = -1;
	newdp->next = NULL;

	if (ap->devpaths == NULL) {
		ap->devpaths = newdp;
	} else {
		/* append the devpath to the end of the list */
		slice_t	*dp;

		dp = ap->devpaths;
		while (dp->next != NULL) {
			dp = dp->next;
		}

		dp->next = newdp;
	}

	return (0);
}

static path_t *
new_path(controller_t *cp, disk_t *dp, di_node_t node, di_path_state_t st,
    char *wwn)
{
	char		*devpath;
	path_t		*pp;
	di_minor_t	minor;

	/* Special handling for fp attachment node. */
	if (strcmp(di_node_name(node), "fp") == 0) {
		di_node_t pnode;

		pnode = di_parent_node(node);
		if (pnode != DI_NODE_NIL) {
			node = pnode;
		}
	}

	devpath = di_devfs_path(node);

	/* check if the path is already there */
	pp = NULL;
	if (cp->paths != NULL) {
		int i;

		for (i = 0; cp->paths[i]; i++) {
			if (libdiskmgt_str_eq(devpath, cp->paths[i]->name)) {
				pp = cp->paths[i];
				break;
			}
		}
	}

	if (pp != NULL) {
		/* the path exists, add this disk to it */

		di_devfs_path_free((void *) devpath);
		if (!add_disk2path(dp, pp, st, wwn)) {
			return (NULL);
		}
		return (pp);
	}

	/* create a new path */

	pp = calloc(1, sizeof (path_t));
	if (pp == NULL) {
		di_devfs_path_free((void *) devpath);
		return (NULL);
	}

	pp->name = strdup(devpath);
	di_devfs_path_free((void *) devpath);
	if (pp->name == NULL) {
		cache_free_path(pp);
		return (NULL);
	}

	/* add the disk to the path */
	if (!add_disk2path(dp, pp, st, wwn)) {
		return (NULL);
	}

	/* add the path to the controller */
	if (add_ptr2array(pp, (void ***)&cp->paths) != 0) {
		cache_free_path(pp);
		return (NULL);
	}

	/* add the controller to the path */
	pp->controller = cp;

	minor = di_minor_next(node, NULL);
	if (minor != NULL) {
		pp->ctype = ctype(node, minor);
	} else {
		pp->ctype = DM_CTYPE_UNKNOWN;
	}

	return (pp);
}

/*
 * We pass in the current controller pointer (currp) so we can double check
 * that we aren't corrupting the list by removing the element we are on.  This
 * should never happen, but it doesn't hurt to double check.
 */
static void
remove_invalid_controller(char *name, controller_t *currp,
    struct search_args *args)
{
	controller_t *cp;
	bus_t *bp;
	controller_t *prevp;

	bp = args->bus_listp;
	while (bp != NULL) {
		int i;

		for (i = 0; bp->controllers[i]; i++) {
			if (libdiskmgt_str_eq(bp->controllers[i]->name, name)) {
				int j;
				/*
				 * remove pointer to invalid controller.
				 * (it is a path)
				 */
				for (j = i; bp->controllers[j]; j++) {
					bp->controllers[j] =
					    bp->controllers[j + 1];
				}
			}
		}
		bp = bp->next;
	}

	if (args->controller_listp == NULL) {
		return;
	}

	cp = args->controller_listp;
	if (libdiskmgt_str_eq(cp->name, name)) {
		args->controller_listp = cp->next;
		if (dm_debug) {
			(void) fprintf(stderr,
			    "INFO: Removed controller %s from list\n",
			    cp->name);
		}
		remove_controller(cp, currp);
		return;
	}

	prevp = cp;
	cp = cp->next;
	while (cp != NULL) {
		if (libdiskmgt_str_eq(cp->name, name)) {
			if (dm_debug) {
				(void) fprintf(stderr,
				    "INFO: Removed controller %s from list\n",
				    cp->name);
			}
			prevp->next = cp->next;
			remove_controller(cp, currp);
			return;
		}
		prevp = cp;
		cp = cp->next;
	}
}
