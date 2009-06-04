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

#ifndef _INSTZONES_API_H
#define	_INSTZONES_API_H


/*
 * Module:	instzones_api.h
 * Group:	libinstzones
 * Description:	This module contains the libinstzones API data structures,
 *		constants, and function prototypes.
 */

/*
 * required includes
 */

/* System includes */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <libzonecfg.h>

/*
 * C++ prefix
 */

#ifdef __cplusplus
extern "C" {
#endif


/* function prototypes */

/* PRINTFLIKE1 */
typedef void (*_z_printf_fcn_t)(char *a_format, ...);

/* zone list structure */

typedef struct _zoneListElement_t *zoneList_t;

/* zone brand list structure */

typedef struct _zoneBrandList zoneBrandList_t;

/* flag for zone locking functions */

typedef unsigned long ZLOCKS_T;

/* flags for zone locking */

#define	ZLOCKS_ZONE_ADMIN	((ZLOCKS_T)0x00000001)	/* zone admin */
#define	ZLOCKS_PKG_ADMIN	((ZLOCKS_T)0x00000002)	/* package admin */
#define	ZLOCKS_PATCH_ADMIN	((ZLOCKS_T)0x00000004)	/* patch admin */
#define	ZLOCKS_ALL		((ZLOCKS_T)0xFFFFFFFF)	/* all locks */
#define	ZLOCKS_NONE		((ZLOCKS_T)0x00000000)	/* no locks */

/*
 * external function definitions
 */

/* zones.c */

extern boolean_t	z_zones_are_implemented(void);
extern void		z_set_zone_root(const char *zroot);
extern boolean_t	z_zlist_is_zone_runnable(zoneList_t a_zoneList,
				int a_zoneIndex);
extern boolean_t	z_zlist_restore_zone_state(zoneList_t a_zoneList,
				int a_zoneIndex);
extern boolean_t	z_zlist_change_zone_state(zoneList_t a_zoneList,
				int a_zoneIndex, zone_state_t a_newState);
extern char		*z_get_zonename(void);
extern zone_state_t	z_zlist_get_current_state(zoneList_t a_zoneList,
				int a_zoneIndex);
extern char 		**z_zlist_get_inherited_pkg_dirs(zoneList_t a_zoneList,
				int a_zoneIndex);
extern zone_state_t	z_zlist_get_original_state(zoneList_t a_zoneList,
				int a_zoneIndex);
extern int		z_zoneExecCmdArray(int *r_status, char **r_results,
				char *a_inputFile, char *a_path, char *a_argv[],
				const char *a_zoneName, int *a_fds);
extern int		z_zone_exec(const char *zonename, const char *path,
				char *argv[], char *a_stdoutPath,
				char *a_stderrPath, int *a_fds);
extern boolean_t	z_create_zone_admin_file(char *a_zoneAdminFilename,
				char *a_userAdminFilename);
extern void		z_free_zone_list(zoneList_t a_zoneList);
extern zoneList_t	z_get_nonglobal_zone_list(void);
extern zoneList_t	z_get_nonglobal_zone_list_by_brand(zoneBrandList_t *);
extern void		z_free_brand_list(zoneBrandList_t *a_brandList);
extern zoneBrandList_t	*z_make_brand_list(const char *brandList,
				const char *delim);
extern boolean_t	z_lock_zones(zoneList_t a_zlst, ZLOCKS_T a_lflags);
extern boolean_t	z_non_global_zones_exist(void);
extern boolean_t	z_running_in_global_zone(void);
extern void		z_set_output_functions(_z_printf_fcn_t a_echo_fcn,
				_z_printf_fcn_t a_echo_debug_fcn,
				_z_printf_fcn_t a_progerr_fcn);
extern int		z_set_zone_spec(const char *zlist);
extern int		z_verify_zone_spec(void);
extern boolean_t	z_on_zone_spec(const char *zonename);
extern boolean_t	z_global_only(void);
extern boolean_t	z_unlock_zones(zoneList_t a_zlst, ZLOCKS_T a_lflags);
extern boolean_t	z_lock_this_zone(ZLOCKS_T a_lflags);
extern boolean_t	z_unlock_this_zone(ZLOCKS_T a_lflags);
extern char		*z_zlist_get_zonename(zoneList_t a_zoneList,
				int a_zoneId);
extern char		*z_zlist_get_zonepath(zoneList_t a_zoneList,
				int a_zoneId);
extern char		*z_zlist_get_scratch(zoneList_t a_zoneList,
				int a_zoneId);
extern boolean_t	z_umount_lz_mount(char *a_lzMountPoint);
extern boolean_t	z_mount_in_lz(char **r_lzMountPoint,
				char **r_lzRootPath,
				char *a_zoneName, char *a_gzPath,
				char *a_mountPointPrefix);
extern boolean_t	z_is_zone_branded(char *zoneName);
extern boolean_t	z_is_zone_brand_in_list(char *zoneName,
			    zoneBrandList_t *brands);
extern boolean_t	z_zones_are_implemented(void);

/* zones_exec.c */
extern int		z_ExecCmdArray(int *r_status, char **r_results,
				char *a_inputFile, char *a_cmd, char **a_args);
/*VARARGS*/
extern int		z_ExecCmdList(int *r_status, char **r_results,
				char *a_inputFile, char *a_cmd, ...);

/* zones_paths.c */
extern boolean_t	z_add_inherited_file_system(
				char *a_inheritedFileSystem);
extern boolean_t	z_path_is_inherited(char *a_path, char a_ftype,
				char *a_rootDir);
extern char **		z_get_inherited_file_systems(void);
extern char		*z_make_zone_root(char *);
extern void		z_path_canonize(char *file);
extern void		z_canoninplace(char *file);
extern void		z_free_inherited_file_systems(void);

/* zones_lofs.c */
extern void z_destroyMountTable(void);
extern int z_createMountTable(void);
extern int z_isPathWritable(const char *);
extern void z_resolve_lofs(char *path, size_t);

/* zones_states.c */
extern int UmountAllZones(char *mntpnt);

/*
 * C++ postfix
 */

#ifdef __cplusplus
}
#endif

#endif /* _INSTZONES_API_H */
