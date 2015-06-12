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
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 * Copyright 2015 Gary Mills
 */

#ifndef _LIBBE_H
#define	_LIBBE_H

#include <libnvpair.h>
#include <uuid/uuid.h>
#include <libzfs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	BE_ATTR_ORIG_BE_NAME	"orig_be_name"
#define	BE_ATTR_ORIG_BE_POOL	"orig_be_pool"
#define	BE_ATTR_SNAP_NAME	"snap_name"

#define	BE_ATTR_NEW_BE_NAME	"new_be_name"
#define	BE_ATTR_NEW_BE_POOL	"new_be_pool"
#define	BE_ATTR_NEW_BE_DESC	"new_be_desc"
#define	BE_ATTR_POLICY		"policy"
#define	BE_ATTR_ZFS_PROPERTIES	"zfs_properties"

#define	BE_ATTR_FS_NAMES	"fs_names"
#define	BE_ATTR_FS_NUM		"fs_num"
#define	BE_ATTR_SHARED_FS_NAMES	"shared_fs_names"
#define	BE_ATTR_SHARED_FS_NUM	"shared_fs_num"

#define	BE_ATTR_MOUNTPOINT	"mountpoint"
#define	BE_ATTR_MOUNT_FLAGS	"mount_flags"
#define	BE_ATTR_UNMOUNT_FLAGS	"unmount_flags"
#define	BE_ATTR_DESTROY_FLAGS	"destroy_flags"
#define	BE_ATTR_ROOT_DS		"root_ds"
#define	BE_ATTR_UUID_STR	"uuid_str"

#define	BE_ATTR_ACTIVE		"active"
#define	BE_ATTR_ACTIVE_ON_BOOT	"active_boot"
#define	BE_ATTR_GLOBAL_ACTIVE	"global_active"
#define	BE_ATTR_SPACE		"space_used"
#define	BE_ATTR_DATASET		"dataset"
#define	BE_ATTR_STATUS		"status"
#define	BE_ATTR_DATE		"date"
#define	BE_ATTR_MOUNTED		"mounted"

/*
 * libbe error codes
 *
 * NOTE: there is a copy of this enum in beadm/messages.py. To keep these
 *       in sync please make sure to add any new error messages at the end
 *       of this enumeration.
 */
enum {
	BE_SUCCESS = 0,
	BE_ERR_ACCESS = 4000,	/* permission denied */
	BE_ERR_ACTIVATE_CURR,	/* Activation of current BE failed */
	BE_ERR_AUTONAME,	/* auto naming failed */
	BE_ERR_BE_NOENT,	/* No such BE */
	BE_ERR_BUSY,		/* mount busy */
	BE_ERR_CANCELED,	/* operation canceled */
	BE_ERR_CLONE,		/* BE clone failed */
	BE_ERR_COPY,		/* BE copy failed */
	BE_ERR_CREATDS,		/* dataset creation failed */
	BE_ERR_CURR_BE_NOT_FOUND,	/* Can't find current BE */
	BE_ERR_DESTROY,		/* failed to destroy BE or snapshot */
	BE_ERR_DEMOTE,		/* BE demotion failed */
	BE_ERR_DSTYPE,		/* invalid dataset type */
	BE_ERR_BE_EXISTS,	/* BE exists */
	BE_ERR_INIT,		/* be_zfs_init failed */
	BE_ERR_INTR,		/* interupted system call */
	BE_ERR_INVAL,		/* invalid argument */
	BE_ERR_INVALPROP,	/* invalid property for dataset */
	BE_ERR_INVALMOUNTPOINT,	/* Unexpected mountpoint */
	BE_ERR_MOUNT,		/* mount failed */
	BE_ERR_MOUNTED,		/* already mounted */
	BE_ERR_NAMETOOLONG, 	/* name > BUFSIZ */
	BE_ERR_NOENT,		/* Doesn't exist */
	BE_ERR_POOL_NOENT,	/* No such pool */
	BE_ERR_NODEV,		/* No such device */
	BE_ERR_NOTMOUNTED,	/* File system not mounted */
	BE_ERR_NOMEM,		/* not enough memory */
	BE_ERR_NONINHERIT,	/* property is not inheritable for BE dataset */
	BE_ERR_NXIO,		/* No such device or address */
	BE_ERR_NOSPC,		/* No space on device */
	BE_ERR_NOTSUP,		/* Operation not supported */
	BE_ERR_OPEN,		/* open failed */
	BE_ERR_PERM,		/* Not owner */
	BE_ERR_UNAVAIL,		/* The BE is currently unavailable */
	BE_ERR_PROMOTE,		/* BE promotion failed */
	BE_ERR_ROFS,		/* read only file system */
	BE_ERR_READONLYDS,	/* read only dataset */
	BE_ERR_READONLYPROP,	/* read only property */
	BE_ERR_SS_EXISTS,	/* snapshot exists */
	BE_ERR_SS_NOENT,	/* No such snapshot */
	BE_ERR_UMOUNT,		/* unmount failed */
	BE_ERR_UMOUNT_CURR_BE,	/* Can't unmount current BE */
	BE_ERR_UMOUNT_SHARED,	/* unmount of shared File System failed */
	BE_ERR_UNKNOWN,		/* Unknown error */
	BE_ERR_ZFS,		/* ZFS returned an error */
	BE_ERR_DESTROY_CURR_BE,	/* Cannot destroy current BE */
	BE_ERR_GEN_UUID,	/* Failed to generate uuid */
	BE_ERR_PARSE_UUID,	/* Failed to parse uuid */
	BE_ERR_NO_UUID,		/* BE has no uuid */
	BE_ERR_ZONE_NO_PARENTBE,    /* Zone root dataset has no parent uuid */
	BE_ERR_ZONE_MULTIPLE_ACTIVE, /* Zone has multiple active roots */
	BE_ERR_ZONE_NO_ACTIVE_ROOT, /* Zone has no active root for this BE */
	BE_ERR_ZONE_ROOT_NOT_LEGACY, /* Zone root dataset mntpt is not legacy */
	BE_ERR_NO_MOUNTED_ZONE,	/* Zone not mounted in alternate BE */
	BE_ERR_MOUNT_ZONEROOT,	/* Failed to mount a zone root */
	BE_ERR_UMOUNT_ZONEROOT,	/* Failed to unmount a zone root */
	BE_ERR_ZONES_UNMOUNT,	/* Unable to unmount a zone. */
	BE_ERR_FAULT,		/* Bad Address */
	BE_ERR_RENAME_ACTIVE,	/* Renaming the active BE is not supported */
	BE_ERR_NO_MENU,		/* Missing boot menu file */
	BE_ERR_DEV_BUSY,	/* Device is Busy */
	BE_ERR_BAD_MENU_PATH,	/* Invalid path for menu.lst file */
	BE_ERR_ZONE_SS_EXISTS,	/* zone snapshot already exists */
	BE_ERR_ADD_SPLASH_ICT,	/* Add_splash_image ICT failed */
	BE_ERR_BOOTFILE_INST,	/* Error installing boot files */
	BE_ERR_EXTCMD		/* External command error */
} be_errno_t;

/*
 * Data structures used to return the listing and information of BEs.
 */
typedef struct be_dataset_list {
	uint64_t	be_ds_space_used;
	boolean_t	be_ds_mounted;
	char		*be_dataset_name;
	time_t		be_ds_creation;	/* Date/time stamp when created */
	char		*be_ds_mntpt;
	char		*be_ds_plcy_type;	/* cleanup policy type */
	struct be_dataset_list	*be_next_dataset;
} be_dataset_list_t;

typedef struct be_snapshot_list {
	uint64_t be_snapshot_space_used;	/* bytes of disk space used */
	char	*be_snapshot_name;
	time_t	be_snapshot_creation;	/* Date/time stamp when created */
	char	*be_snapshot_type;	/* cleanup policy type */
	struct	be_snapshot_list *be_next_snapshot;
} be_snapshot_list_t;

typedef struct be_node_list {
	boolean_t be_mounted;		/* is BE currently mounted */
	boolean_t be_active_on_boot;	/* is this BE active on boot */
	boolean_t be_active;		/* is this BE active currently */
	boolean_t be_global_active;	/* is zone's BE associated with */
					/* an active global BE */
	uint64_t be_space_used;
	char *be_node_name;
	char *be_rpool;
	char *be_root_ds;
	char *be_mntpt;
	char *be_policy_type;		/* cleanup policy type */
	char *be_uuid_str;		/* string representation of uuid */
	time_t be_node_creation;	/* Date/time stamp when created */
	struct be_dataset_list *be_node_datasets;
	uint_t be_node_num_datasets;
	struct be_snapshot_list *be_node_snapshots;
	uint_t be_node_num_snapshots;
	struct be_node_list *be_next_node;
} be_node_list_t;

/* Flags used with mounting a BE */
#define	BE_MOUNT_FLAG_NULL		0x00000000
#define	BE_MOUNT_FLAG_SHARED_FS		0x00000001
#define	BE_MOUNT_FLAG_SHARED_RW		0x00000002
#define	BE_MOUNT_FLAG_NO_ZONES		0x00000004

/* Flags used with unmounting a BE */
#define	BE_UNMOUNT_FLAG_NULL		0x00000000
#define	BE_UNMOUNT_FLAG_FORCE		0x00000001

/* Flags used with destroying a BE */
#define	BE_DESTROY_FLAG_NULL		0x00000000
#define	BE_DESTROY_FLAG_SNAPSHOTS	0x00000001
#define	BE_DESTROY_FLAG_FORCE_UNMOUNT	0x00000002

/* sort rules for be_sort() */
typedef enum {
	BE_SORT_UNSPECIFIED = -1,
	BE_SORT_DATE = 0,
	BE_SORT_DATE_REV,
	BE_SORT_NAME,
	BE_SORT_NAME_REV,
	BE_SORT_SPACE,
	BE_SORT_SPACE_REV
} be_sort_t;

/*
 * BE functions
 */
int be_init(nvlist_t *);
int be_destroy(nvlist_t *);
int be_copy(nvlist_t *);

int be_mount(nvlist_t *);
int be_unmount(nvlist_t *);

int be_rename(nvlist_t *);

int be_activate(nvlist_t *);

int be_create_snapshot(nvlist_t *);
int be_destroy_snapshot(nvlist_t *);
int be_rollback(nvlist_t *);

/*
 * Functions for listing and getting information about existing BEs.
 */
int be_list(char *, be_node_list_t **);
void be_free_list(be_node_list_t *);
int be_max_avail(char *, uint64_t *);
char *be_err_to_str(int);
int be_sort(be_node_list_t **, int);

/*
 * Library functions
 */
void libbe_print_errors(boolean_t);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBBE_H */
