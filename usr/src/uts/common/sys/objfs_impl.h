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

#ifndef	_OBJFS_IMPL_H
#define	_OBJFS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/modctl.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/gfs.h>
#include <sys/objfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * VFS data object
 */
typedef struct objfs_vfs {
	vnode_t	*objfs_vfs_root;
} objfs_vfs_t;

/*
 * Common vop_ entry points
 */
extern int objfs_dir_open(vnode_t **, int, cred_t *, caller_context_t *);
extern int objfs_dir_access(vnode_t *, int, int, cred_t *,
    caller_context_t *);
extern int objfs_common_close(vnode_t *, int, int, offset_t, cred_t *,
    caller_context_t *);

/*
 * Common vop_ support functions
 */
extern int objfs_common_getattr(vnode_t *, vattr_t *);

/*
 * Miscellaneous support functions
 */
extern int objfs_nobjs(void);

#define	OBJFS_NAME_MAX	MAXNAMELEN

/*
 * The root vnode has an inode number of 0xffffffff.  All other vnodes have an
 * inode that is an OR of the module id with the type of vnode.
 *
 * ----------------------------------------
 * |     type         |      mod_id       |
 * ----------------------------------------
 * 63                 31                  0
 *
 * This way, module directories will have an inode value equal to their module
 * id.
 */

#define	OBJFS_INO(modid, type)	\
	(((uint64_t)(type) << 32) | (modid))

/*
 * Root directory
 */
typedef gfs_dir_t	objfs_rootnode_t;

#define	OBJFS_INO_ROOT	0xffffffff

extern const fs_operation_def_t objfs_tops_root[];
extern vnodeops_t *objfs_ops_root;

extern vnode_t *objfs_create_root(vfs_t *);

/*
 * Object directory
 */

typedef struct objfs_odirnode {
	gfs_dir_t		objfs_odir_dir;		/* gfs dir */
	struct modctl		*objfs_odir_modctl;	/* modctl pointer */
} objfs_odirnode_t;

#define	OBJFS_INO_ODIR(modid)	OBJFS_INO(modid, 0)

extern const fs_operation_def_t objfs_tops_odir[];
extern vnodeops_t *objfs_ops_odir;

extern vnode_t *objfs_create_odirnode(vnode_t *, struct modctl *);

/*
 * Data file
 */
typedef struct objfs_datanode {
	gfs_file_t		objfs_data_file;	/* gfs file */
	objfs_info_t		objfs_data_info;
	int			objfs_data_gencount;	/* gen when opened */
} objfs_datanode_t;

#define	OBJFS_INO_DATA(modid)	OBJFS_INO(modid, 1)

extern const fs_operation_def_t objfs_tops_data[];
extern vnodeops_t *objfs_ops_data;

extern void objfs_data_init(void);
extern vnode_t *objfs_create_data(vnode_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _OBJFS_IMPL_H */
