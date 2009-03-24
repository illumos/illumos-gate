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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBGRUBMGMT_H
#define	_LIBGRUBMGMT_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mntent.h>
#include <sys/uadmin.h>
#include <libzfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	GRUB_ENTRY_DEFAULT	-1	/* Use the default entry */

/*
 * Data structure for describing the GRUB menu
 */
typedef struct grub_menu grub_menu_t;
typedef struct grub_line grub_line_t;
typedef struct grub_entry grub_entry_t;

/*
 * Data structure for describing the file system where the
 * GRUB menu resides
 */
typedef struct grub_fsdesc {
	int	gfs_is_tmp_mounted;	/* is temporary mounted */
	char	gfs_dev[MAXNAMELEN];	/* device/zfs dataset to mount */
	char	gfs_mountp[MAXPATHLEN];	/* mount point */
} grub_fsdesc_t;

/*
 * Data structure for collecting data for Fast Reboot
 */
typedef struct grub_boot_args {
	grub_fsdesc_t	gba_fsd;
	int		gba_kernel_fd;
	char		gba_kernel[BOOTARGS_MAX];
	char		gba_module[BOOTARGS_MAX];
	char		gba_bootargs[BOOTARGS_MAX];
} grub_boot_args_t;

/*
 * Wrapper functions for retriving boot arguments for Fast Reboot.
 * grub_get_boot_args() calls grub_menu_init() and grub_menu_fini().
 * If menupath is NULL, it will use 'currently active' GRUB menu file.
 *
 * All _get_boot_args functions will mount the root file system for the
 * given entry if not mounted, and open and validate the kernel file.
 * Caller must allocate bargs, and call grub_cleanup_boot_args() to
 * clean up mount points and open file handles when done.
 *
 * grub_get_boot_args:
 *	Collects boot argument from the specified GRUB menu entry.
 *	If entrynum == -1, default GRUB menu entry will be used.
 *
 * grub_cleanup_boot_args:
 *	Cleans up and releases all the resources allocated by
 *	grub_get_boot_args.  Closes kernel file.  Umounts root file
 *	system if temporarily mounted.
 */
extern int grub_get_boot_args(grub_boot_args_t *bargs, const char *menupath,
    int entrynum);
extern void grub_cleanup_boot_args(grub_boot_args_t *bargs);

extern const char *grub_strerror(int);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBGRUBMGMT_H */
