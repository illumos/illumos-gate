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

#ifndef _FB_FILESET_H
#define	_FB_FILESET_H

#include "filebench.h"
#include "config.h"

#ifndef HAVE_OFF64_T
/*
 * We are probably on linux.
 * According to http://www.suse.de/~aj/linux_lfs.html, defining the
 * above, automatically changes type of off_t to off64_t. so let
 * us use only off_t as off64_t is not defined
 */
#define	off64_t off_t
#endif /* HAVE_OFF64_T */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <pthread.h>

#include "vars.h"
#define	FILE_ALLOC_BLOCK (off64_t)(1024 * 1024)

#ifdef	__cplusplus
extern "C" {
#endif

#define	FSE_MAXTID 16384

#define	FSE_MAXPATHLEN 16
#define	FSE_TYPE_FILE		0x00
#define	FSE_TYPE_DIR		0x01
#define	FSE_TYPE_LEAFDIR	0x02
#define	FSE_TYPE_MASK		0x03
#define	FSE_FREE		0x04
#define	FSE_EXISTS		0x08
#define	FSE_BUSY		0x10
#define	FSE_REUSING		0x20
#define	FSE_THRD_WAITNG		0x40

typedef struct filesetentry {
	struct filesetentry	*fse_next;
	struct filesetentry	*fse_parent;
	struct filesetentry	*fse_filenext;	/* List of files */
	struct filesetentry	*fse_dirnext;	/* List of directories */
	struct filesetentry	*fse_leafdirnext; /* List of leaf dirs */
	struct fileset		*fse_fileset;	/* Parent fileset */
	char			*fse_path;
	int			fse_depth;
	off64_t			fse_size;
	int			fse_flags;	/* protected by fs_pick_lock */
} filesetentry_t;

/* type of fileset entry to obtain */
#define	FILESET_PICKFILE    0x00 /* Pick a file from the set */
#define	FILESET_PICKDIR	    0x01 /* Pick a directory */
#define	FILESET_PICKLEAFDIR 0x02 /* Pick a leaf directory */
#define	FILESET_PICKMASK    0x03 /* Pick type mask */
/* other pick flags */
#define	FILESET_PICKUNIQUE  0x04 /* Pick a unique file or leafdir from the */
				    /* fileset until empty */
#define	FILESET_PICKRESET   0x08 /* Reset FILESET_PICKUNIQUE selection list */
#define	FILESET_PICKEXISTS  0x10 /* Pick an existing file */
#define	FILESET_PICKNOEXIST 0x20 /* Pick a file that doesn't exist */

/* fileset attributes */
#define	FILESET_IS_RAW_DEV  0x01 /* fileset is a raw device */
#define	FILESET_IS_FILE	    0x02 /* Fileset is emulating a single file */

typedef struct fileset {
	struct fileset	*fs_next;	/* Next in list */
	avd_t		fs_name;	/* Name */
	avd_t		fs_path;	/* Pathname prefix in fileset */
	avd_t		fs_entries;	/* Number of entries attr */
					/* (possibly random) */
	fbint_t		fs_constentries; /* Constant version of enties attr */
	avd_t		fs_leafdirs;	/* Number of leaf directories attr */
					/* (possibly random) */
	fbint_t		fs_constleafdirs; /* Constant version of leafdirs */
					    /* attr */
	avd_t		fs_preallocpercent; /* Prealloc size */
	int		fs_attrs;	/* Attributes */
	avd_t		fs_dirwidth;	/* Explicit or mean for distribution */
	avd_t		fs_dirdepthrv;	/* random variable for dir depth */
	avd_t		fs_size;	/* Explicit or mean for distribution */
	avd_t		fs_dirgamma;	/* Dirdepth Gamma distribution */
					/* (* 1000) defaults to 1500, set */
					/* to 0 for explicit depth */
	avd_t		fs_sizegamma;	/* Filesize and dirwidth Gamma */
					/* distribution (* 1000), default */
					/* is 1500, set to 0 for explicit */
	avd_t		fs_create;	/* Attr */
	avd_t		fs_prealloc;	/* Attr */
	avd_t		fs_paralloc;	/* Attr */
	avd_t		fs_cached;	/* Attr */
	avd_t		fs_reuse;	/* Attr */
	double		fs_meandepth;	/* Computed mean depth */
	double		fs_meanwidth;	/* Specified mean dir width */
	double		fs_meansize;	/* Specified mean file size */
	int		fs_realfiles;	/* Actual files */
	int		fs_realleafdirs; /* Actual explicit leaf directories */
	off64_t		fs_bytes;	/* Total space consumed by files */

	int64_t		fs_idle_files;	/* number of files NOT busy */
	pthread_cond_t	fs_idle_files_cv; /* idle files condition variable */
	fbint_t		fs_num_act_files;   /* total number of files */
					    /* actually existing in the */
					    /* host or server's file system */
	int64_t		fs_idle_dirs;	/* number of dirs NOT busy */
	pthread_cond_t	fs_idle_dirs_cv; /* idle dirs condition variable */

	int64_t		fs_idle_leafdirs; /* number of dirs NOT busy */
	pthread_cond_t	fs_idle_leafdirs_cv; /* idle dirs condition variable */
	fbint_t		fs_num_act_leafdirs; /* total number of leaf dirs */
					    /* actually existing in the */
					    /* host or server's file system */
	pthread_mutex_t	fs_pick_lock;	/* per fileset "pick" function lock */
	pthread_cond_t	fs_thrd_wait_cv; /* per fileset file busy wait cv */
	filesetentry_t	*fs_filelist;	/* List of files */
	filesetentry_t	*fs_filefree;	/* Ptr to next free file */
	filesetentry_t	*fs_filerotor[FSE_MAXTID];	/* next file to */
							/* select */
	filesetentry_t	*fs_file_ne_rotor;	/* next non existent file */
						/* to select for createfile */
	filesetentry_t	*fs_dirlist;	/* List of directories */
	filesetentry_t	*fs_dirfree;	/* List of free directories */
	filesetentry_t	*fs_dirrotor;	/* Ptr to next directory to select */
	filesetentry_t	*fs_leafdirlist; /* List of leaf directories */
	filesetentry_t	*fs_leafdirfree; /* Ptr to next free leaf directory */
	filesetentry_t	*fs_leafdirrotor;	/* Ptr to next leaf */
						/* directory to select */
} fileset_t;

int fileset_createset(fileset_t *);
int fileset_openfile(fileset_t *fileset, filesetentry_t *entry,
    int flag, int mode, int attrs);
fileset_t *fileset_define(avd_t);
fileset_t *fileset_find(char *name);
filesetentry_t *fileset_pick(fileset_t *fileset, int flags, int tid);
char *fileset_resolvepath(filesetentry_t *entry);
void fileset_usage(void);
void fileset_iter(int (*cmd)(fileset_t *fileset, int first));
int fileset_print(fileset_t *fileset, int first);
void fileset_unbusy(filesetentry_t *entry, int update_exist,
    int new_exist_val);

#ifdef	__cplusplus
}
#endif

#endif	/* _FB_FILESET_H */
