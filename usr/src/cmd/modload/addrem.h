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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _CMD_MODLOAD_ADDREM_H
#define	_CMD_MODLOAD_ADDREM_H

#include <sys/modctl.h>
#include <device_info.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* defines for add_drv.c, update_drv.c, and rem_drv.c */

#define	SUCCESS	0
#define	FAILURE -1
#define	NOERR	0
#define	ERROR	-1
#define	UNIQUE	-2
#define	NOT_UNIQUE -3
#define	NONE_FOUND -4

#define	MAX_CMD_LINE	256
#define	MAX_N2M_ALIAS_LINE	FILENAME_MAX + FILENAME_MAX + 1
#define	MAXLEN_NAM_TO_MAJ_ENT	FILENAME_MAX + MAX_STR_MAJOR + 1
#define	OPT_LEN		128
#define	CADDR_HEX_STR	16
#define	UINT_STR	10
#define	MODLINE_ENT_MAX	(4 * UINT_STR) + CADDR_HEX_STR + MODMAXNAMELEN
#define	MAX_STR_MAJOR	UINT_STR
#define	STR_LONG	10
#define	PERM_STR	4
#define	MAX_PERM_ENTRY	(2 * STR_LONG) + PERM_STR + (2 * FILENAME_MAX) + 1
#define	MAX_DBFILE_ENTRY	MAX_PERM_ENTRY

#define	CLEAN_MINOR_PERM	0x00000001
#define	CLEAN_DRV_ALIAS		0x00000002
#define	CLEAN_NAM_MAJ		0x00000004
#define	CLEAN_DRV_CLASSES	0x00000010
#define	CLEAN_DEV_POLICY	0x00000020
#define	CLEAN_DRV_PRIV		0x00000040
#define	CLEAN_ALL		(CLEAN_MINOR_PERM | CLEAN_DRV_ALIAS | \
				CLEAN_NAM_MAJ | CLEAN_DRV_CLASSES | \
				CLEAN_DEV_POLICY | CLEAN_DRV_PRIV)

/* add_drv/rem_drv database files */
#define	DRIVER_ALIAS	"/etc/driver_aliases"
#define	DRIVER_CLASSES	"/etc/driver_classes"
#define	MINOR_PERM	"/etc/minor_perm"
#define	NAM_TO_MAJ	"/etc/name_to_major"
#define	REM_NAM_TO_MAJ	"/etc/rem_name_to_major"

#define	ADD_REM_LOCK	"/var/run/AdDrEm.lck"

#if defined(__x86)
#define	DRVDIR64	"amd64"
#elif defined(__sparc)
#define	DRVDIR64	"sparcv9"
#endif

/* pointers to add_drv/rem_drv database files */
char *driver_aliases;
char *driver_classes;
char *minor_perm;
char *name_to_major;
char *rem_name_to_major;
char *device_policy;
char *extra_privs;

/* devfs root string */
char *devfs_root;

/* module path searching structure */
struct drvmod_dir {
	char direc[FILENAME_MAX + 1];
	struct drvmod_dir *next;
};

struct drvmod_dir *moddir;

/* names of things: directories, commands, files */
#define	KERNEL_DRV	"/kernel/drv"
#define	USR_KERNEL_DRV	"/usr/kernel/drv"
#define	DRVCONFIG_PATH	"/usr/sbin/drvconfig"
#define	DRVCONFIG	"drvconfig"
#define	DEVFSADM_PATH	"/usr/sbin/devfsadm"
#define	DEVFSADM	"devfsadm"
#define	DEVFS_ROOT	"/devices"
#define	RECONFIGURE	"/reconfigure"
#define	MODUNLOAD_PATH	"/usr/sbin/modunload"

extern void log_minorperm_error(minorperm_err_t, int);
extern void remove_entry(int, char *);
extern char *get_next_entry(char *, char *);
extern char *get_perm_entry(char *, char *);
extern int check_perms_aliases(int, int);
extern int check_name_to_major(int);
extern void enter_lock(void);
extern void err_exit(void) __NORETURN;
extern void exit_unlock(void);
extern char *get_entry(char *, char *, char, int);
extern int build_filenames(char *);
extern int append_to_file(char *, char *, char *, char, char *, int);
extern int append_to_minor_perm(char *, char *, char *);
extern int get_major_no(char *, char *);
extern int get_driver_name(int, char *, char *);
extern int delete_entry(char *, char *, char *, char *);
extern int check_space_within_quote(char *);
extern void list_entry(char *, char *, char *);
extern int update_minor_entry(char *, char *);
extern int check_perm_opts(char *);
extern int update_name_to_major(char *, major_t *, int);
extern int do_the_update(char *, char *);
extern int fill_n2m_array(char *, char **, int *);
extern int aliases_unique(char *);
extern int aliases_exist(char *);
extern int aliases_paths_exist(char *);
extern int update_driver_aliases(char *, char *);
extern int unique_driver_name(char *, char *, int *);
extern int unique_drv_alias(char *);
extern int check_duplicate_driver_alias(char *, char *);
extern int trim_duplicate_aliases(char *, char *, char **);
extern int get_max_major(char *);
extern void get_modid(char *, int *);
extern int config_driver(char *, major_t, char *, char *, int, int);
extern int unconfig_driver(char *, major_t, char *, int);
extern void load_driver(char *, int);
extern int create_reconfig(char *);
extern void cleanup_moddir(void);

/* drvsubr.c */
#define	XEND	".XXXXXX"
#define	MAXMODPATHS	1024

/* module path list separators */
#define	MOD_SEP	" :"
#define	DIR_SEP "/"

/* [un]config_driver flags */
#define	CONFIG_DRV_VERBOSE	0x01		/* verbose */
#define	CONFIG_DRV_FORCE	0x02		/* unconfig even if in use */
#define	CONFIG_DRV_UPDATE_ONLY	0x04		/* -u update only */

#ifdef	__cplusplus
}
#endif

#endif /* _CMD_MODLOAD_ADDREM_H */
