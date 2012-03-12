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
 * Copyright 2012, Joyent, Inc. All rights reserved.
 */

#ifndef	_SYS_FS_HLOFS_INFO_H
#define	_SYS_FS_HLOFS_INFO_H

#include <sys/t_lock.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <sys/vfs_opreg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * hlnode is the file system dependent node for hyprlofs.
 * It is modeled on the tmpfs tmpnode.
 *
 *	hln_rwlock protects access of the directory list at hln_dir
 *	as well as syncronizing read/writes to directory hlnodes.
 *	hln_tlock protects updates to hln_mode and hln_nlink.
 *	hln_tlock doesn't require any hlnode locks.
 */
typedef struct hlnode {
	struct hlnode	*hln_back;		/* linked list of hlnodes */
	struct hlnode	*hln_forw;		/* linked list of hlnodes */
	union {
		struct {
			struct hldirent	*un_dirlist; /* dirent list */
			uint_t	un_dirents;	/* number of dirents */
		} un_dirstruct;
		vnode_t	*un_realvp;		/* real vnode */
	} un_hlnode;
	vnode_t 	*hln_vnode;		/* vnode for this hlnode */
	int 		hln_gen;		/* pseudo gen num for hlfid */
	int 		hln_looped;		/* flag indicating loopback */
	vattr_t		hln_attr;		/* attributes */
	krwlock_t	hln_rwlock;		/* rw - serialize mods and */
						/* directory updates */
	kmutex_t	hln_tlock;		/* time, flag, and nlink lock */
} hlnode_t;

/*
 * hyprlofs per-mount data structure.
 * All fields are protected by hlm_contents.
 */
typedef struct {
	vfs_t		*hlm_vfsp;	/* filesystem's vfs struct */
	hlnode_t	*hlm_rootnode;	/* root hlnode */
	char 		*hlm_mntpath;	/* name of hyprlofs mount point */
	dev_t		hlm_dev;	/* unique dev # of mounted `device' */
	uint_t		hlm_gen;	/* pseudo generation number for files */
	kmutex_t	hlm_contents;	/* lock for hlfsmount structure */
} hlfsmount_t;

/*
 * hyprlofs directories are made up of a linked list of hldirent structures
 * hanging off directory hlnodes.  File names are not fixed length,
 * but are null terminated.
 */
typedef struct hldirent {
	hlnode_t	*hld_hlnode;		/* hlnode for this file */
	struct hldirent	*hld_next;		/* next directory entry */
	struct hldirent	*hld_prev;		/* prev directory entry */
	uint_t		hld_offset;		/* "offset" of dir entry */
	uint_t		hld_hash;		/* a hash of td_name */
	struct hldirent	*hld_link;		/* linked via the hash table */
	hlnode_t	*hld_parent;		/* parent, dir we are in */
	char		*hld_name;		/* must be null terminated */
						/* max length is MAXNAMELEN */
} hldirent_t;

/*
 * hlfid overlays the fid structure (for VFS_VGET)
 */
typedef struct {
	uint16_t hlfid_len;
	ino32_t	hlfid_ino;
	int32_t	hlfid_gen;
} hlfid_t;

/*
 * File system independent to hyprlofs conversion macros
 */
#define	VFSTOHLM(vfsp)		((hlfsmount_t *)(vfsp)->vfs_data)
#define	VTOHLM(vp)		((hlfsmount_t *)(vp)->v_vfsp->vfs_data)
#define	VTOHLN(vp)		((hlnode_t *)(vp)->v_data)
#define	HLNTOV(tp)		((tp)->hln_vnode)
#define	REALVP(vp)		((vnode_t *)VTOHLN(vp)->hln_realvp)
#define	hlnode_hold(tp)		VN_HOLD(HLNTOV(tp))
#define	hlnode_rele(tp)		VN_RELE(HLNTOV(tp))

#define	hln_dir		un_hlnode.un_dirstruct.un_dirlist
#define	hln_dirents	un_hlnode.un_dirstruct.un_dirents
#define	hln_realvp	un_hlnode.un_realvp

/*
 * Attributes
 */
#define	hln_mask	hln_attr.va_mask
#define	hln_type	hln_attr.va_type
#define	hln_mode	hln_attr.va_mode
#define	hln_uid		hln_attr.va_uid
#define	hln_gid		hln_attr.va_gid
#define	hln_fsid	hln_attr.va_fsid
#define	hln_nodeid	hln_attr.va_nodeid
#define	hln_nlink	hln_attr.va_nlink
#define	hln_size	hln_attr.va_size
#define	hln_atime	hln_attr.va_atime
#define	hln_mtime	hln_attr.va_mtime
#define	hln_ctime	hln_attr.va_ctime
#define	hln_rdev	hln_attr.va_rdev
#define	hln_blksize	hln_attr.va_blksize
#define	hln_nblocks	hln_attr.va_nblocks
#define	hln_seq		hln_attr.va_seq

#define	HL_MUSTHAVE	1

/*
 * enums
 */
enum de_op	{ DE_CREATE, DE_MKDIR }; /* direnter ops */
enum dr_op	{ DR_REMOVE, DR_RMDIR }; /* dirremove ops */

/*
 * hyprlofs_minfree is the amount (in pages) of anonymous memory that hyprlofs
 * leaves free for the rest of the system. The default value for
 * hyprlofs_minfree is btopr(HYPRLOFSMINFREE) but it can be patched to a
 * different number of pages.  Since hyprlofs doesn't actually use much
 * memory, its unlikely this ever needs to be patched.
 */
#define	HYPRLOFSMINFREE	8 * 1024 * 1024	/* 8 Megabytes */

extern size_t	hyprlofs_minfree;		/* Anonymous memory in pages */

/*
 * hyprlofs can allocate only a certain percentage of kernel memory,
 * which is used for hlnodes, directories, file names, etc.
 * This is statically set as HYPRLOFSMAXFRACKMEM of physical memory.
 * The actual number of allocatable bytes can be patched in hyprlofs_maxkmem.
 */
#define	HYPRLOFSMAXFRACKMEM	25	/* 1/25 of physical memory */

extern size_t 	hyprlofs_kmemspace;
extern size_t	hyprlofs_maxkmem; /* Allocatable kernel memory in bytes */

extern	void	hyprlofs_node_init(hlfsmount_t *, hlnode_t *, vattr_t *,
		    cred_t *);
extern	int	hyprlofs_dirlookup(hlnode_t *, char *, hlnode_t **, cred_t *);
extern	int	hyprlofs_dirdelete(hlnode_t *, hlnode_t *, char *, enum dr_op,
		    cred_t *);
extern	void	hyprlofs_dirinit(hlnode_t *, hlnode_t *);
extern	void	hyprlofs_dirtrunc(hlnode_t *);
extern	void	*hyprlofs_memalloc(size_t, int);
extern	void	hyprlofs_memfree(void *, size_t);
extern	int	hyprlofs_taccess(void *, int, cred_t *);
extern	int	hyprlofs_direnter(hlfsmount_t *, hlnode_t *, char *, enum de_op,
		    vnode_t *, vattr_t *, hlnode_t **, cred_t *);

extern struct vnodeops *hyprlofs_vnodeops;
extern const struct fs_operation_def hyprlofs_vnodeops_template[];

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_HLOFS_INFO_H */
