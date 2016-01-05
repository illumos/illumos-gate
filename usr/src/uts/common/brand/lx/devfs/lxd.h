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

#ifndef	_LXD_H
#define	_LXD_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * lxd.h: declarations, data structures and macros for lxd (lxd devfs).
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
#include <sys/lx_types.h>

#if defined(_KERNEL)

#include <sys/lx_brand.h>

/*
 * It's unlikely that we need to create more than 50-60 subdirs/symlinks
 * as front files so we size the file system hash for 2x that number.
 * The back devfs typically has ~80 nodes so this is also a comfortable size
 * for the back hash table.
 */
#define	LXD_HASH_SZ	128

#define	LXD_BACK_HASH(v)	((((intptr_t)(v)) >> 10) & ((LXD_HASH_SZ) - 1))

#define	LXD_NM_HASH(ldn, name, hash)				\
	{							\
		char Xc, *Xcp;					\
		hash = (uint_t)(uintptr_t)(ldn) >> 8;		\
		for (Xcp = (name); (Xc = *Xcp) != 0; Xcp++)	\
			hash = (hash << 4) + hash + (uint_t)Xc;	\
		hash &= (LXD_HASH_SZ - 1);			\
	}


enum lxd_node_type	{ LXDNT_NONE, LXDNT_BACK, LXDNT_FRONT };

/*
 * lxd per-mount data structure.
 *
 * All fields are protected by lxd_contents.
 * File renames on a specific file system are protected lxdm_renamelck.
 */
typedef struct lxd_mnt {
	struct vfs	*lxdm_vfsp;	/* filesystem's vfs struct */
	struct lxd_node *lxdm_rootnode;	/* root lxd_node */
	char 		*lxdm_mntpath;	/* name of lxd mount point */
	dev_t		lxdm_dev;	/* unique dev # of mounted `device' */
	kmutex_t	lxdm_contents;	/* per-mount lock */
	kmutex_t	lxdm_renamelck;	/* rename lock for this mount */
	uint_t		lxdm_gen;	/* node ID source for files */

	/* protects buckets in both "dir ent" and "back" hash tables */
	kmutex_t	lxdm_hash_mutex[LXD_HASH_SZ];

	/* per-mount data for "back" vnodes in the fs */
	uint_t		lxdm_back_refcnt; /* # outstanding "back" vnodes */
	struct lxd_node *lxdm_back_htable[LXD_HASH_SZ];

	/*
	 * Per-mount directory data for "front" nodes in the fs.
	 * Each front node has a directory entry but directory entries can live
	 * on either front or back nodes.
	 */
	uint_t		lxdm_dent_refcnt; /* # outstanding dir ents */
	struct lxd_dirent *lxdm_dent_htable[LXD_HASH_SZ];
} lxd_mnt_t;

/*
 * lxd_node is the file system dependent node for lxd.
 *
 * The node is used to represent both front and back files. For front files
 * the node can represent either a directory or symlink.
 */
typedef struct lxd_node {
	enum lxd_node_type	lxdn_type;

	/* Data for "front" nodes */
	struct lxd_node		*lxdn_prev;	/* lnked lst of lxd nodes */
	struct lxd_node		*lxdn_next;	/* lnked lst of lxd nodes */
	struct lxd_node		*lxdn_parent;	/* dir containing this node */
	krwlock_t		lxdn_rwlock;	/* serialize mods/dir updates */
	kmutex_t		lxdn_tlock;	/* time, flag, and nlink lock */

	/* these could be in a union ala tmpfs but not really necessary */
	uint_t			lxdn_dirents;	/* number of dirents */
	struct lxd_dirent	*lxdn_dir;	/* dirent list */
	char			*lxdn_symlink;	/* pointer to symlink */
	struct vattr		lxdn_attr;	/* attributes */

	/* Hash table link */
	struct lxd_node		*lxdn_hnxt;	/* link in per-mount entry */
						/* hash table */
	vnode_t 		*lxdn_vnode;	/* vnode for this lxd_node */

	vnode_t			*lxdn_real_vp;	/* back file - real vnode */
} lxd_node_t;

/*
 * Attributes
 */
#define	lxdn_mask	lxdn_attr.va_mask
#define	lxdn_mode	lxdn_attr.va_mode
#define	lxdn_uid	lxdn_attr.va_uid
#define	lxdn_gid	lxdn_attr.va_gid
#define	lxdn_fsid	lxdn_attr.va_fsid
#define	lxdn_nodeid	lxdn_attr.va_nodeid
#define	lxdn_nlink	lxdn_attr.va_nlink
#define	lxdn_size	lxdn_attr.va_size
#define	lxdn_atime	lxdn_attr.va_atime
#define	lxdn_mtime	lxdn_attr.va_mtime
#define	lxdn_ctime	lxdn_attr.va_ctime
#define	lxdn_rdev	lxdn_attr.va_rdev
#define	lxdn_blksize	lxdn_attr.va_blksize
#define	lxdn_nblocks	lxdn_attr.va_nblocks
#define	lxdn_seq	lxdn_attr.va_seq

/*
 * lx devfs conversion macros
 */
#define	VFSTOLXDM(vfsp)		((lxd_mnt_t *)(vfsp)->vfs_data)
#define	VTOLXDM(vp)		((lxd_mnt_t *)(vp)->v_vfsp->vfs_data)
#define	VTOLDN(vp)		((lxd_node_t *)(vp)->v_data)
#define	LDNTOV(ln)		((ln)->lxdn_vnode)
#define	ldnode_hold(ln)		VN_HOLD(LDNTOV(ln))
#define	ldnode_rele(ln)		VN_RELE(LDNTOV(ln))

#define	REALVP(vp)		(VTOLDN(vp)->lxdn_real_vp)

/*
 * front directories are made up of a linked list of lxd_dirent structures
 * hanging off directory lxdn_nodes.  File names are not fixed length, but are
 * null terminated.
 */
typedef struct lxd_dirent {
	lxd_node_t		*lddir_node;	/* lxd node for this file */
	struct lxd_dirent	*lddir_next;	/* next directory entry */
	struct lxd_dirent	*lddir_prev;	/* prev directory entry */
	uint_t			lddir_offset;	/* "offset" of dir entry */
	uint_t			lddir_hash;	/* a hash of lddir_name */
	struct lxd_dirent	*lddir_link;	/* linked via hash table */
	lxd_node_t		*lddir_parent;	/* parent, dir we are in */
	char			*lddir_name;	/* null terminated */
} lxd_dirent_t;

enum de_op	{ DE_CREATE, DE_MKDIR, DE_RENAME };	/* direnter ops */
enum dr_op	{ DR_REMOVE, DR_RMDIR, DR_RENAME };	/* dirremove ops */

typedef struct lxd_minor_translator {
	char	*lxd_mt_path;		/* illumos minor node path */
	minor_t	lxd_mt_minor;		/* illumos minor node number */
	int	lxd_mt_lx_major;	/* linux major node number */
	int	lxd_mt_lx_minor;	/* linux minor node number */
} lxd_minor_translator_t;

enum lxd_xl_tp	{ DTT_INVALID, DTT_LIST, DTT_CUSTOM };

#define	xl_list		lxd_xl_minor.lxd_xl_list
#define	xl_custom	lxd_xl_minor.lxd_xl_custom

typedef struct lxd_devt_translator {
	char		*lxd_xl_driver;	/* driver name */
	major_t		lxd_xl_major;	/* driver number */

	enum lxd_xl_tp	lxd_xl_type;	/* dictates how we intrep. xl_minor */
	union {
		uintptr_t		lxd_xl_foo; /* required to compile */
		lxd_minor_translator_t	*lxd_xl_list;
		int			(*lxd_xl_custom)(dev_t, lx_dev_t *);
	} lxd_xl_minor;
} lxd_devt_translator_t;

extern struct vnodeops *lxd_vnodeops;
extern lxd_devt_translator_t lxd_devt_translators[];

vnode_t *lxd_make_back_node(vnode_t *, lxd_mnt_t *);
void lxd_free_back_node(lxd_node_t *);
int lxd_dirdelete(lxd_node_t *, lxd_node_t *, char *, enum dr_op, cred_t *);
int lxd_direnter(lxd_mnt_t *, lxd_node_t *, char *, enum de_op, lxd_node_t *,
	lxd_node_t *, struct vattr *, lxd_node_t **, cred_t *,
	caller_context_t *);
void lxd_dirinit(lxd_node_t *, lxd_node_t *, cred_t *);
int lxd_dirlookup(lxd_node_t *, char *, lxd_node_t **, cred_t *);
void lxd_dirtrunc(lxd_node_t *);
void lxd_node_init(lxd_mnt_t *, lxd_node_t *, vnode_t *, vattr_t *, cred_t *);
int lxd_naccess(void *, int, cred_t *);

#endif /* KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _LXD_H */
