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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * WARNING:
 * The interfaces defined in this header file are for Sun private use only.
 * The contents of this file are subject to change without notice in
 * future releases.
 */

#ifndef	_DEVICE_INFO_H
#define	_DEVICE_INFO_H

#ifdef	__cplusplus
extern "C" {
#endif

/* error return values */
#define	DEVFS_ERR	-1	/* operation not successful */
#define	DEVFS_INVAL	-2	/* invalid argument */
#define	DEVFS_NOMEM	-3	/* out of memory */
#define	DEVFS_PERM	-4 	/* permission denied - not root */
#define	DEVFS_NOTSUP	-5	/* operation not supported */
#define	DEVFS_LIMIT	-6	/* exceeded maximum size of property value */
#define	DEVFS_NOTFOUND	-7	/* request not found */

/*
 * for devfs_set_boot_dev()
 * default behavior is to translate the input logical device name
 * to most compact prom name(i.e. a prom alias, if one exists)
 * as possible.  And to prepend the new entry to the existing
 * list.
 */

/* perform no translation on the input device path */
#define	BOOTDEV_LITERAL		0x1
/* convert the input device path only a prom device path; not an alias */
#define	BOOTDEV_PROMDEV		0x2
/* overwrite the existing entry in boot-device - default is to prepend */
#define	BOOTDEV_OVERWRITE	0x4

/*
 * for devfs_get_prom_names()
 * returns a list of prom names for a given logical device name.
 * the list is sorted first in order of exact aliases, inexact alias
 * matches (where an option override was needed), and finally the
 * equivalent prom device path.  Each sublist is sorted in collating
 * order.
 */
#define	BOOTDEV_NO_PROM_PATH		0x1
#define	BOOTDEV_NO_INEXACT_ALIAS	0x2
#define	BOOTDEV_NO_EXACT_ALIAS		0x4

/* for devfs_get_boot_dev() */
struct boot_dev {
	char *bootdev_element;	/* an entry from the boot-device variable */
	char **bootdev_trans;	/* 0 or more logical dev translations */
};

/* for devfs_get_all_prom_names() */
struct devfs_prom_path {
	char *obp_path;
	char **alias_list;
	struct devfs_prom_path *next;
};

/* prototypes */

/* return the driver for a given device path */
extern int devfs_path_to_drv(char *devfs_path, char *drv_buf);

/* convert a logical or physical device name to the equivalent prom path */
extern int devfs_dev_to_prom_name(char *, char *);

/* return the driver name after resolving any aliases */
extern char *devfs_resolve_aliases(char *drv);

/* set the boot-device configuration variable */
extern int devfs_bootdev_set_list(const char *, const uint_t);

/* is the boot-device variable modifiable on this platform? */
extern int devfs_bootdev_modifiable(void);

/*
 * retrieve the boot-device config variable and corresponding logical
 * device names
 */
extern int devfs_bootdev_get_list(const char *, struct boot_dev ***);
/*
 * free a list of bootdev structs
 */
extern void devfs_bootdev_free_list(struct boot_dev **);
/*
 * given a logical device name, return a list of equivalent
 * prom names (aliases and device paths)
 */
extern int devfs_get_prom_names(const char *, uint_t, char ***);
/*
 * like devfs_get_prom_names(), but deals with 1 to many mappings
 * introduced by mpxio devices
 */
extern int devfs_get_all_prom_names(const char *, uint_t,
    struct devfs_prom_path **);
/*
 * free a list of devfs_prom_path structures
 */
extern void devfs_free_all_prom_names(struct devfs_prom_path *);

/*
 * map a device name from install OS environment to target OS environment or
 * vice-versa.
 */
extern int devfs_target2install(const char *, const char *, char *, size_t);
extern int devfs_install2target(const char *, const char *, char *, size_t);

/*
 * Minor perm parsing library support for devfsadm, add_drv etc.
 */
#define	MINOR_PERM_FILE		"/etc/minor_perm"
#define	MAX_MINOR_PERM_LINE	256
#define	DEFAULT_DEV_USER	"root"
#define	DEFAULT_DEV_GROUP	"sys"

/*
 * Possible errors the callers of devfs_read_minor_perm() need
 * to be prepared to deal with via callback.
 */
typedef enum {
	MP_FOPEN_ERR,
	MP_FCLOSE_ERR,
	MP_IGNORING_LINE_ERR,
	MP_ALLOC_ERR,
	MP_NVLIST_ERR,
	MP_CANT_FIND_USER_ERR,
	MP_CANT_FIND_GROUP_ERR
} minorperm_err_t;


/*
 * Create/free mperm list of minor perm entries
 */
extern struct mperm *devfs_read_minor_perm(void (*)(minorperm_err_t, int));
extern void devfs_free_minor_perm(struct mperm *);

/*
 * Load all minor perm entries, and add/remove minor perm entry
 */
extern int devfs_load_minor_perm(struct mperm *,
	void (*)(minorperm_err_t, int));
extern int devfs_add_minor_perm(char *, void (*)(minorperm_err_t, int));
extern int devfs_rm_minor_perm(char *, void (*)(minorperm_err_t, int));

/* devfsadm dca_flags values: some are used by libdevinfo devlink_create() */
#define	DCA_CREATE_LINK		0x000000001
#define	DCA_FREE_LIST		0x000000002
#define	DCA_LOAD_DRV		0x000000004
#define	DCA_CHECK_TYPE		0x000000010
/* UNUSED was DCA_NOTIFY_RCM	0x000000020 (can be recycled) */
#define	DCA_FLUSH_PATHINST	0x000000040
#define	DCA_HOT_PLUG		0x000000080
#define	DCA_DEVLINK_SYNC	0x000000100
#define	DCA_DEVLINK_CACHE	0x000000200

#ifdef	__cplusplus
}
#endif

#endif	/* _DEVICE_INFO_H */
