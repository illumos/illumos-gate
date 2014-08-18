/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_FS_BOOTFS_IMPL_H
#define	_SYS_FS_BOOTFS_IMPL_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/avl.h>
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>
#include <sys/kstat.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The bootfs node is the file system specific version of the vnode for the
 * bootfs file system. Because the bootfs file system is entirely a read-only
 * file system, this structure requires no locking as the contents are
 * immutable.
 */
typedef struct bootfs_node {
	char			*bvn_name;	/* entry name */
	struct vnode		*bvn_vnp;	/* Corresponding vnode */
	avl_tree_t		bvn_dir;	/* directory entries, if VDIR */
	avl_node_t		bvn_link;	/* dirent link */
	list_node_t		bvn_alink;	/* link for all nodes */
	uint64_t		bvn_addr;	/* Address in pmem */
	uint64_t		bvn_size;	/* Size of the file */
	struct bootfs_node	*bvn_parent;	/* .. */
	vattr_t			bvn_attr;	/* attributes for the node */
} bootfs_node_t;

typedef struct bootfs_stat {
	kstat_named_t	bfss_nfiles;
	kstat_named_t	bfss_ndirs;
	kstat_named_t	bfss_nbytes;
	kstat_named_t	bfss_ndups;
	kstat_named_t	bfss_ndiscards;
} bootfs_stat_t;

typedef struct bootfs {
	vfs_t			*bfs_vfsp;
	char			*bfs_mntpath;
	bootfs_node_t		*bfs_rootvn;
	kstat_t			*bfs_kstat;
	list_t			bfs_nodes;
	minor_t			bfs_minor;
	uint_t			bfs_ninode;
	bootfs_stat_t		bfs_stat;
} bootfs_t;

extern void bootfs_construct(bootfs_t *);
extern void bootfs_destruct(bootfs_t *);
extern int bootfs_node_constructor(void *, void *, int);
extern void bootfs_node_destructor(void *, void *);

extern struct vnodeops *bootfs_vnodeops;
extern const fs_operation_def_t bootfs_vnodeops_template[];
extern kmem_cache_t *bootfs_node_cache;
extern major_t bootfs_major;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FS_BOOTFS_IMPL_H */
