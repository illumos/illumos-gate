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

#ifndef	_DEVALLOC_H
#define	_DEVALLOC_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <fcntl.h>
#include <sys/param.h>
#include <secdb.h>

/*
 * These are unsupported, SUNWprivate interfaces.
 */

#define	DA_UID			(uid_t)0	/* root */
#define	DA_GID			(gid_t)3	/* sys */
#define	ALLOC_MODE		0600
#define	DEALLOC_MODE		0000

#define	LOGINDEVPERM		"/etc/logindevperm"
#define	DA_DB_LOCK		"/etc/security/.da_db_lock"
#define	DA_DEV_LOCK		"/etc/security/.da_dev_lock"
#define	DEVALLOC		"/etc/security/device_allocate"
#define	DEVMAP			"/etc/security/device_maps"
#define	DEFATTRS		"/etc/security/tsol/devalloc_defaults"
#define	TMPALLOC		"/etc/security/.device_allocate"
#define	TMPMAP			"/etc/security/.device_maps"
#define	TMPATTRS		"/etc/security/tsol/.devalloc_defaults"

#define	DA_DEFAULT_MIN		"admin_low"
#define	DA_DEFAULT_MAX		"admin_high"
#define	DA_DEFAULT_CLEAN	"/bin/true"
#define	DA_DEFAULT_AUDIO_CLEAN	"/etc/security/lib/audio_clean_wrapper"
#define	DA_DEFAULT_DISK_CLEAN	"/etc/security/lib/disk_clean"
#define	DA_DEFAULT_TAPE_CLEAN	"/etc/security/lib/st_clean"

#define	DA_ON_STR		"DEVICE_ALLOCATION=ON\n"
#define	DA_OFF_STR		"DEVICE_ALLOCATION=OFF\n"
#define	DA_IS_LABELED		"system_labeled"
#define	DA_DBMODE		0644
#define	DA_COUNT		5	/* allocatable devices suppported */
					/* audio, cd, floppy, rmdisk, tape */
#define	DA_AUTHLEN		MAX_CANON   /* approx. sum of strlen of all */
					    /* device auths in auth_list.h */
#define	DA_MAXNAME		80
#define	DA_MAX_DEVNO		((8 * sizeof (uint64_t)) - 1)
#define	DA_BUFSIZE		4096

#define	DA_RDWR			O_RDWR|O_CREAT|O_NONBLOCK
#define	DA_RDONLY		O_RDONLY|O_NONBLOCK

#define	DA_ANYUSER		"*"
#define	DA_NOUSER		"@"

#define	DA_SILENT		0x00000001
#define	DA_VERBOSE		0x00000002
#define	DA_ADD			0x00000004
#define	DA_REMOVE		0x00000008
#define	DA_UPDATE		0x00000010
#define	DA_ADD_ZONE		0x00000020
#define	DA_REMOVE_ZONE		0x00000040
#define	DA_FORCE		0x00000080
#define	DA_ALLOC_ONLY		0x00000100
#define	DA_MAPS_ONLY		0x00000200
#define	DA_ON			0x00000400
#define	DA_OFF			0x00000800
#define	DA_NO_OVERRIDE		0x00001000
#define	DA_DEFATTRS		0x00002000
#define	DA_EVENT		0x00004000

#define	DA_AUDIO		0x00001000
#define	DA_CD			0x00002000
#define	DA_FLOPPY		0x00004000
#define	DA_TAPE			0x00008000
#define	DA_RMDISK		0x00010000

#define	DA_AUDIO_NAME		"audio"
#define	DA_SOUND_NAME		"sound"
#define	DA_AUDIO_TYPE		DA_AUDIO_NAME
#define	DA_AUDIO_DIR		"/dev/sound/"

#define	DA_CD_NAME		"cdrom"
#define	DA_CD_TYPE		"sr"

#define	DA_DISK_DIR		"/dev/dsk/"
#define	DA_DISK_DIRR		"/dev/rdsk/"
#define	DA_DISKR_DIR		"/dev/(r)dsk"

#define	DA_FLOPPY_NAME		"floppy"
#define	DA_FLOPPY_TYPE		"fd"

#define	DA_RMDISK_NAME		"rmdisk"
#define	DA_RMDISK_TYPE		DA_RMDISK_NAME

#define	DA_TAPE_NAME		"tape"
#define	DA_TAPE_DIR		"/dev/rmt/"
#define	DA_TAPE_TYPE		"st"

typedef struct _devinfo_t {
	char	*devname;
	char	*devtype;
	char	*devauths;
	char	*devexec;
	char	*devopts;
	char	*devlist;
	int	instance;
} devinfo_t;

typedef struct _deventry_t {
	devinfo_t		devinfo;
	struct _deventry_t	*next;
} deventry_t;

typedef struct _devlist_t {
	deventry_t	*audio;
	deventry_t	*cd;
	deventry_t	*floppy;
	deventry_t	*tape;
	deventry_t	*rmdisk;
} devlist_t;

typedef struct _da_optargs {
	int		optflag;
	char		*rootdir;
	char		**devnames;
	devinfo_t	*devinfo;
} da_args;

typedef struct _da_defs {
	char		*devtype;
	kva_t		*devopts;
} da_defs_t;

da_defs_t *getdadefent(void);
da_defs_t *getdadeftype(char *);
void freedadefent(da_defs_t *);
void setdadefent(void);
void enddadefent(void);
int da_is_on(void);
int da_check_logindevperm(char *);
int da_open_devdb(char *, FILE **, FILE **, int);
int da_update_device(da_args *);
int da_update_defattrs(da_args *);
int da_add_list(devlist_t *, char *, int, int);
int da_remove_list(devlist_t *, char *, int, char *, int);
int da_rm_list_entry(devlist_t *, char *, int, char *);
void da_print_device(int, devlist_t *);


#ifdef	__cplusplus
}
#endif

#endif	/* _DEVALLOC_H */
