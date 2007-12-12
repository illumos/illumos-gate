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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FB_FILESET_H
#define	_FB_FILESET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#define	FSE_DIR		0x01
#define	FSE_FREE	0x02
#define	FSE_EXISTS	0x04
#define	FSE_BUSY	0x08
#define	FSE_REUSING	0x10

typedef struct filesetentry {
	struct filesetentry	*fse_next;
	struct filesetentry	*fse_parent;
	struct filesetentry	*fse_filenext;	/* List of files */
	struct filesetentry	*fse_dirnext;	/* List of directories */
	struct fileset		*fse_fileset;	/* Parent fileset */
	pthread_mutex_t		fse_lock;
	char			*fse_path;
	int			fse_depth;
	off64_t			fse_size;
	int			fse_flags;
} filesetentry_t;

#define	FILESET_PICKANY	    0x1 /* Pick any file from the set */
#define	FILESET_PICKUNIQUE  0x2 /* Pick a unique file from set until empty */
#define	FILESET_PICKRESET   0x4 /* Reset FILESET_PICKUNIQUE selection list */
#define	FILESET_PICKDIR	    0x8 /* Pick a directory */
#define	FILESET_PICKEXISTS  0x10 /* Pick an existing file */
#define	FILESET_PICKNOEXIST 0x20 /* Pick a file that doesn't exist */

/* fileset attributes */
#define	FILESET_IS_RAW_DEV  0x01 /* fileset is a raw device */
#define	FILESET_IS_FILE	    0x02 /* Fileset is emulating a single file */

typedef struct fileset {
	struct fileset	*fs_next;	/* Next in list */
	char		fs_name[128];	/* Name */
	var_string_t	fs_path;	/* Pathname prefix in fs */
	var_integer_t	fs_entries;	/* Set size */
	var_integer_t	fs_preallocpercent; /* Prealloc size */
	int		fs_attrs;	/* Attributes */
	var_integer_t	fs_dirwidth;	/* Explicit or 0 for distribution */
	var_integer_t	fs_size;	/* Explicit or 0 for distribution */
	var_integer_t	fs_dirgamma;  /* Dirwidth Gamma distribution (* 1000) */
	var_integer_t	fs_sizegamma; /* Filesize Gamma distribution (* 1000) */
	var_integer_t	fs_create;	/* Attr */
	var_integer_t	fs_prealloc;	/* Attr */
	var_integer_t	fs_paralloc;	/* Attr */
	var_integer_t	fs_cached;	/* Attr */
	var_integer_t	fs_reuse;	/* Attr */
	double		fs_meandepth;	/* Computed mean depth */
	double		fs_meanwidth;	/* Specified mean dir width */
	double		fs_meansize;	/* Specified mean file size */
	int		fs_realfiles;	/* Actual files */
	off64_t		fs_bytes; /* Space potentially consumed by all files */
	filesetentry_t	*fs_filelist;	/* List of files */
	filesetentry_t	*fs_dirlist;	/* List of directories */
	filesetentry_t	*fs_filefree;	/* Ptr to next free file */
	filesetentry_t	*fs_dirfree;	/* Ptr to next free directory */
	filesetentry_t	*fs_filerotor[FSE_MAXTID]; /* next file to select */
	filesetentry_t	*fs_dirrotor;	/* Ptr to next directory to select */
} fileset_t;

int fileset_createset(fileset_t *);
int fileset_openfile(fileset_t *fileset, filesetentry_t *entry,
    int flag, int mode, int attrs);
fileset_t *fileset_define(char *);
fileset_t *fileset_find(char *name);
filesetentry_t *fileset_pick(fileset_t *fileset, int flags, int tid);
char *fileset_resolvepath(filesetentry_t *entry);
void fileset_usage(void);
void fileset_iter(int (*cmd)(fileset_t *fileset, int first));
int fileset_print(fileset_t *fileset, int first);
int fileset_checkraw(fileset_t *fileset);


#ifdef	__cplusplus
}
#endif

#endif	/* _FB_FILESET_H */
