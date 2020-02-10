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

/*
 * Copyright 2018 Nexenta Systems, Inc.
 */

#ifndef _SHAREFS_SHAREFS_H
#define	_SHAREFS_SHAREFS_H

/*
 * This header provides service for the sharefs module.
 */

#include <sys/modctl.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/gfs.h>
#include <sharefs/share.h>
#include <sharefs/sharetab.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SHAREFS_ROOT	"/etc/dfs"
#define	SHAREFS_BASE	"sharetab"

/*
 * Lengths of strings.
 */
typedef struct sharefs_lens {
	int	shl_path;
	int	shl_res;
	int	shl_fstype;
	int	shl_opts;
	int	shl_descr;
} sharefs_lens_t;

/*
 * VFS data object
 */
typedef struct sharefs_vfs {
	vnode_t	*sharefs_vfs_root;
} sharefs_vfs_t;

#define	SHAREFS_NAME_MAX	MAXNAMELEN

typedef struct sharetab_globals {
	/*
	 * The lock ordering whenever sharefs_lock and sharetab_lock both
	 * need to be held is: sharefs_lock and then sharetab_lock.
	 */
	krwlock_t	sharefs_lock;	/* lock for the vnode ops */
	sharetab_t	*sharefs_sharetab;	/* The sharetab. */

	uint_t		sharetab_count;	/* How many shares? */
	krwlock_t	sharetab_lock;	/* lock for the cached sharetab */
	size_t		sharetab_size;	/* How big is the sharetab file? */

	timestruc_t	sharetab_mtime;	/* Last mod to sharetab */
	timestruc_t	sharetab_snap_time;	/* Last snap */
	uint_t		sharetab_generation;	/* Which copy is it? */
} sharetab_globals_t;

#define	SHAREFS_INO_FILE	0x80

extern vnode_t *sharefs_create_root_file(vfs_t *);
extern sharetab_globals_t *sharetab_get_globals(zone_t *zone);

/*
 * Sharetab file
 *
 * Note that even though the sharetab code does not explictly
 * use 'sharefs_file', it is required by GFS that the first
 * field of the private data be a gfs_file_t.
 */
typedef struct shnode_t {
	gfs_file_t	sharefs_file;		/* gfs file */
	char		*sharefs_snap;		/* snapshot of the share */
	size_t		sharefs_size;		/* size of the snapshot */
	uint_t		sharefs_count;		/* number of shares */
	uint_t		sharefs_refs;		/* reference count */
	uint_t		sharefs_real_vp;	/* Are we a real or snap */
	uint_t		sharefs_generation;	/* Which copy are we? */
	timestruc_t	sharefs_snap_time;	/* When were we modded? */
} shnode_t;

/*
 * Some conversion macros:
 */
#define	VTOSH(vp)	((shnode_t *)((vp)->v_data))

extern const fs_operation_def_t	sharefs_tops_data[];
extern vnodeops_t		*sharefs_ops_data;

extern void sharefs_data_init(void);

extern void sharefs_sharetab_init(void);

#ifdef __cplusplus
}
#endif

#endif /* !_SHAREFS_SHAREFS_H */
