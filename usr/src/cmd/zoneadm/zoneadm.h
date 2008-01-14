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

#ifndef _ZONEADM_H
#define	_ZONEADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	CMD_HELP	0
#define	CMD_BOOT	1
#define	CMD_HALT	2
#define	CMD_READY	3
#define	CMD_REBOOT	4
#define	CMD_LIST	5
#define	CMD_VERIFY	6
#define	CMD_INSTALL	7
#define	CMD_UNINSTALL	8
#define	CMD_MOUNT	9
#define	CMD_UNMOUNT	10
#define	CMD_CLONE	11
#define	CMD_MOVE	12
#define	CMD_DETACH	13
#define	CMD_ATTACH	14
#define	CMD_MARK	15
#define	CMD_APPLY	16

#define	CMD_MIN		CMD_HELP
#define	CMD_MAX		CMD_APPLY

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

#define	Z_ERR		1
#define	Z_USAGE		2
#define	Z_FATAL		3

#define	SW_CMP_NONE	0x0
#define	SW_CMP_SRC	0x01
#define	SW_CMP_SILENT	0x02

/*
 * zoneadm.c
 */
extern char *target_zone;

extern int clone_copy(char *source_zonepath, char *zonepath);
extern char *cmd_to_str(int cmd_num);
extern void zerror(const char *fmt, ...);
extern void zperror(const char *str, boolean_t zonecfg_error);
extern void zperror2(const char *zone, const char *str);

/*
 * zfs.c
 */
extern int clone_snapshot_zfs(char *snap_name, char *zonepath);
extern int clone_zfs(char *source_zone, char *source_zonepath, char *zonepath);
extern void create_zfs_zonepath(char *zonepath);
extern int destroy_zfs(char *zonepath);
extern boolean_t is_zonepath_zfs(char *zonepath);
extern int move_zfs(char *zonepath, char *new_zonepath);
extern int verify_datasets(zone_dochandle_t handle);
extern int verify_fs_zfs(struct zone_fstab *fstab);
extern int init_zfs(void);

/*
 * sw_cmp.c
 */
extern int sw_cmp(zone_dochandle_t l_handle, zone_dochandle_t s_handle,
    uint_t flag);
extern int sw_up_to_date(zone_dochandle_t l_handle, zone_dochandle_t s_handle,
    char *zonepath);

#endif	/* _ZONEADM_H */
