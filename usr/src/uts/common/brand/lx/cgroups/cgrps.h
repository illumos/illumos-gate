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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef	_LXCGRPS_H
#define	_LXCGRPS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * cgrps.h: declarations, data structures and macros for lx_cgroup
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/policy.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/systm.h>
#include <sys/var.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/priv.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/cmn_err.h>
#include <sys/zone.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/atomic.h>
#include <vm/anon.h>

#define	CG_PSNSIZE	256	/* max size of pseudo file name entries */
#define	CG_PSDSIZE	16	/* pretend that a dir entry takes 16 bytes */

#define	CG_START_ID	0	/* initial node ID for allocation */

/*
 * The order of these entries must be in sync with the cg_ssde_dir array.
 */
typedef enum cgrp_ssid {
	CG_SSID_GENERIC = 1,
	CG_SSID_NUM		/* last ssid for range checking */
} cgrp_ssid_t;

typedef enum cgrp_nodetype {
	CG_CGROUP_DIR = 1,	/* cgroup directory entry */
	CG_PROCS,
	CG_TASKS,
} cgrp_nodetype_t;

typedef struct cgrp_subsys_dirent {
	cgrp_nodetype_t cgrp_ssd_type;
	char		*cgrp_ssd_name;
} cgrp_subsys_dirent_t;

/*
 * cgroups per-mount data structure.
 *
 * All fields are protected by cg_contents.
 */
typedef struct cgrp_mnt {
	struct vfs	*cg_vfsp;	/* filesystem's vfs struct */
	struct cgrp_node *cg_rootnode;	/* root cgrp_node */
	char 		*cg_mntpath;	/* name of cgroup mount point */
	cgrp_ssid_t	cg_ssid;	/* subsystem type */
	dev_t		cg_dev;		/* unique dev # of mounted `device' */
	uint_t		cg_gen;		/* node ID source for files */
	kmutex_t	cg_contents;	/* lock for cgrp_mnt structure */
	kmutex_t	cg_renamelck;	/* rename lock for this mount */
} cgrp_mnt_t;

/*
 * cgrp_node is the file system dependent node for cgroups.
 *
 *	cgn_rwlock protects access of the directory list at cgn_dir
 *	as well as syncronizing read and writes to the cgrp_node
 *
 *	cgn_contents protects growing, shrinking, reading and writing
 *	the file along with cgn_rwlock (see below).
 *
 *	cgn_tlock protects updates to cgn_mode and cgn_nlink
 *
 *	cg_contents in the cgrp_mount data structure protects
 *	cgn_forw and cgn_back which are used to maintain a linked
 *	list of all cgroup files associated with that file system
 *
 *	The ordering of the locking is:
 *	cg_rwlock -> cgn_contents
 *
 *	cgn_tlock doesn't require any cgrp_node locks
 */

typedef struct cgrp_node {
	struct cgrp_node	*cgn_back;	/* lnked lst of cgrp_nodes */
	struct cgrp_node	*cgn_forw;	/* lnked lst of cgrp_nodes */
	struct cgrp_dirent	*cgn_dir;	/* dirent list */
	struct cgrp_node	*cgn_parent;	/* dir containing this node */
	uint_t			cgn_dirents;	/* number of dirents */
	cgrp_nodetype_t		cgn_type;	/* type for this node */
	struct vnode 		*cgn_vnode;	/* vnode for this cgrp_node */
	int 			cgn_id;		/* ID number for the cgroup */
	struct vattr		cgn_attr;	/* attributes */
	krwlock_t		cgn_contents;	/* serialize mods */
	krwlock_t		cgn_rwlock;	/* rw - serialize */
						/* mods and dir updates */
	kmutex_t		cgn_tlock;	/* time, flag, and nlink lock */
} cgrp_node_t;

/*
 * File system independent to cgroups conversion macros
 */
#define	VFSTOCGM(vfsp)		((cgrp_mnt_t *)(vfsp)->vfs_data)
#define	VTOCGM(vp)		((cgrp_mnt_t *)(vp)->v_vfsp->vfs_data)
#define	VTOCGN(vp)		((struct cgrp_node *)(vp)->v_data)
#define	CGNTOV(cn)		((cn)->cgn_vnode)
#define	cgnode_hold(cn)		VN_HOLD(CGNTOV(cn))
#define	cgnode_rele(cn)		VN_RELE(CGNTOV(cn))

/*
 * Attributes
 */
#define	cgn_mask	cgn_attr.va_mask
#define	cgn_mode	cgn_attr.va_mode
#define	cgn_uid		cgn_attr.va_uid
#define	cgn_gid		cgn_attr.va_gid
#define	cgn_fsid	cgn_attr.va_fsid
#define	cgn_nodeid	cgn_attr.va_nodeid
#define	cgn_nlink	cgn_attr.va_nlink
#define	cgn_size	cgn_attr.va_size
#define	cgn_atime	cgn_attr.va_atime
#define	cgn_mtime	cgn_attr.va_mtime
#define	cgn_ctime	cgn_attr.va_ctime
#define	cgn_rdev	cgn_attr.va_rdev
#define	cgn_blksize	cgn_attr.va_blksize
#define	cgn_nblocks	cgn_attr.va_nblocks
#define	cgn_seq		cgn_attr.va_seq

/*
 * cgroup directories are made up of a linked list of cg_dirent structures
 * hanging off directory cgrp_nodes.  File names are not fixed length,
 * but are null terminated.
 */
typedef struct cgrp_dirent {
	struct cgrp_node	*cgd_cgrp_node;	/* cg node for this file */
	struct cgrp_dirent	*cgd_next;	/* next directory entry */
	struct cgrp_dirent	*cgd_prev;	/* prev directory entry */
	uint_t			cgd_offset;	/* "offset" of dir entry */
	uint_t			cgd_hash;	/* a hash of cgd_name */
	struct cgrp_dirent	*cgd_link;	/* linked via hash table */
	struct cgrp_node	*cgd_parent;	/* parent, dir we are in */
	char			*cgd_name;	/* null terminated */
} cgrp_dirent_t;

enum de_op	{ DE_CREATE, DE_MKDIR, DE_RENAME };	/* direnter ops */
enum dr_op	{ DR_REMOVE, DR_RMDIR, DR_RENAME };	/* dirremove ops */

extern struct vnodeops *cgrp_vnodeops;

int cgrp_dirdelete(cgrp_node_t *, cgrp_node_t *, char *, enum dr_op, cred_t *);
int cgrp_direnter(cgrp_mnt_t *, cgrp_node_t *, char *, enum de_op,
    cgrp_node_t *, struct vattr *, cgrp_node_t **, cred_t *,
    caller_context_t *);
void cgrp_dirinit(cgrp_node_t *, cgrp_node_t *, cred_t *);
int cgrp_dirlookup(cgrp_node_t *, char *, cgrp_node_t **, cred_t *);
void cgrp_dirtrunc(cgrp_node_t *);
void cgrp_node_init(cgrp_mnt_t *, cgrp_node_t *, vattr_t *, cred_t *);
int cgrp_taccess(void *, int, cred_t *);
ino_t cgrp_inode(cgrp_nodetype_t, unsigned int);
int cgrp_num_pseudo_ents(cgrp_ssid_t);

#ifdef	__cplusplus
}
#endif

#endif /* _LXCGRPS_H */
