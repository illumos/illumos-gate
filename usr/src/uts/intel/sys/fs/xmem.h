/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FS_XMEM_H
#define	_SYS_FS_XMEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/t_lock.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <sys/fs/seg_xmem.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 *	xmemnode is the file system dependent node for xmemfs.
 *
 *	xn_rwlock protects access of the directory list at xn_dir
 *	as well as syncronizing read and writes to the xmemnode
 *
 *	xn_contents protects growing, shrinking, reading and writing
 *	the file along with xn_rwlock (see below).
 *
 *	xn_tlock protects updates to xn_mode and xn_nlink
 *
 *	xm_contents in the xmount filesystem data structure protects
 *	xn_forw and xn_back which are used to maintain a linked
 *	list of all xmemfs files associated with that file system
 *
 *	XXX - valid ? The pp array represents the store for xmemfs.
 * 	To grow or shrink the file or fill in holes requires
 *	manipulation of the pp array. These operations are protected
 *	by a combination of xn_rwlock and xn_contents. Growing or shrinking
 * 	the array requires the write lock on xn_rwlock and xn_contents.
 *	Filling in a slot in the array requires the write lock on xn_contents.
 *	Reading the array requires the read lock on xn_contents.
 *
 *	The ordering of the locking is:
 *	xn_rwlock -> xn_contents -> page locks on pages in file
 *
 *	xn_tlock doesn't require any xmemnode locks
 */

struct xmemnode {
	struct xmemnode	*xn_back;		/* linked list of xmemnodes */
	struct xmemnode	*xn_forw;		/* linked list of xmemnodes */
	union {
		struct {
			struct xdirent	*un_dirlist; /* dirent list */
			uint_t	un_dirents;	/* number of dirents */
		} un_dirstruct;
		char 		*un_symlink;	/* pointer to symlink */
		struct {
			page_t	***un_ppa;	/* page backing for file */
			size_t	un_size;	/* size repres. by array */
		} un_ppstruct;
	} un_xmemnode;
	struct vnode 	*xn_vnode;		/* vnode for this xmemnode */
	int 		xn_gen;			/* pseudo gen number for xfid */
	struct vattr	xn_attr;		/* attributes */
	krwlock_t	xn_contents;		/* vm side -serialize mods */
	krwlock_t	xn_rwlock;		/* rw,trunc size - serialize */
						/* mods and directory updates */
	kmutex_t	xn_tlock;		/* time, flag, and nlink lock */
};

/*
 * each xn_ppa[] entry points to an array of page_t pointers.
 */
#define	xn_ppa		un_xmemnode.un_ppstruct.un_ppa
#define	xn_ppasz	un_xmemnode.un_ppstruct.un_size
#define	xn_dir		un_xmemnode.un_dirstruct.un_dirlist
#define	xn_dirents	un_xmemnode.un_dirstruct.un_dirents
#define	xn_symlink	un_xmemnode.un_symlink

/*
 * Attributes
 */
#define	xn_mask		xn_attr.va_mask
#define	xn_type		xn_attr.va_type
#define	xn_mode		xn_attr.va_mode
#define	xn_uid		xn_attr.va_uid
#define	xn_gid		xn_attr.va_gid
#define	xn_fsid		xn_attr.va_fsid
#define	xn_nodeid	xn_attr.va_nodeid
#define	xn_nlink	xn_attr.va_nlink
#define	xn_size		xn_attr.va_size
#define	xn_atime	xn_attr.va_atime
#define	xn_mtime	xn_attr.va_mtime
#define	xn_ctime	xn_attr.va_ctime
#define	xn_rdev		xn_attr.va_rdev
#define	xn_blksize	xn_attr.va_blksize
#define	xn_nblocks	xn_attr.va_nblocks
#define	xn_seq		xn_attr.va_seq

/*
 * xmemfs directories are made up of a linked list of xdirent structures
 * hanging off directory xmemnodes.  File names are not fixed length,
 * but are null terminated.
 */
struct xdirent {
	struct xmemnode	*xd_xmemnode;		/* xmemnode for this file */
	struct xdirent	*xd_next;		/* next directory entry */
	struct xdirent	*xd_prev;		/* prev directory entry */
	uint_t		xd_offset;		/* "offset" of dir entry */
	uint_t		xd_hash;		/* a hash of xd_name */
	struct xdirent	*xd_link;		/* linked via the hash table */
	struct xmemnode	*xd_parent;		/* parent, dir we are in */
	char		*xd_name;		/* must be null terminated */
						/* max length is MAXNAMELEN */
};

/*
 * xfid overlays the fid structure (for VFS_VGET)
 */
struct xfid {
	uint16_t	xfid_len;
	ino32_t		xfid_ino;
	int32_t		xfid_gen;
};

#define	ESAME	(-1)		/* trying to rename linked files (special) */

extern struct vnodeops *xmem_vnodeops;
extern const struct fs_operation_def xmem_vnodeops_template[];

/*
 * xmemfs per-mount data structure.
 *
 * All fields are protected by xm_contents.
 * File renames on a particular file system are protected xm_renamelck.
 */
struct xmount {
	struct vfs	*xm_vfsp;	/* filesystem's vfs struct */
	struct xmemnode	*xm_rootnode;	/* root xmemnode */
	char 		*xm_mntpath;	/* name of xmemfs mount point */
	uint_t		xm_flags;	/* Miscellaneous Flags */
	size_t		xm_bsize;	/* block size for this file system */
	uint_t		xm_bshift;	/* for converting offset to block # */
	pgcnt_t		xm_ppb;		/* pages per block */
	struct	map	*xm_map;	/* Map for kernel addresses */
	caddr_t		xm_mapaddr;	/* Base of above map */
	size_t		xm_mapsize;	/* size of above map */
	caddr_t		xm_vmmapaddr;	/* Base of heap for above map */
	size_t		xm_vmmapsize;	/* size of heap for above map */
	ulong_t		xm_max;		/* file system max reservation */
	pgcnt_t		xm_mem;		/* pages of reserved memory */
	dev_t		xm_dev;		/* unique dev # of mounted `device' */
	uint_t		xm_gen;		/* pseudo generation number for files */
	kmutex_t	xm_contents;	/* lock for xmount structure */
	kmutex_t	xm_renamelck;	/* rename lock for this mount */
	uint_t		xm_xpgcnt;	/* index and count for xpg_array */
	void		**xm_xpgarray;	/* array of pointers */
};

#ifndef DEBUG
#define	XMEMPRINTF(level, args)
#else
extern int	xmemlevel;
/*PRINTFLIKE1*/
extern void	xmemprintf(const char *, ...)
	__KPRINTFLIKE(1);
#define	XMEMPRINTF(level, args)		if (level >= xmemlevel) xmemprintf args
#endif

#endif	/* _KERNEL */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/*
 * Make sizeof struct xmemfs_args the same on x86 and amd64.
 */

struct xmemfs_args {
	offset_t	xa_fssize;	/* file system size in bytes */
	offset_t	xa_bsize;	/* block size for this file system */
	uint_t		xa_flags;	/* flags for this mount */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/* Flag bits */
#define	XARGS_RESERVEMEM	1	/* pre reserve memory */
#define	XARGS_LARGEPAGES	2	/* Use large pages */

#ifdef _KERNEL

/*
 * File system independent to xmemfs conversion macros
 */
#define	VFSTOXM(vfsp)		((struct xmount *)(vfsp)->vfs_data)
#define	VTOXM(vp)		((struct xmount *)(vp)->v_vfsp->vfs_data)
#define	VTOXN(vp)		((struct xmemnode *)(vp)->v_data)
#define	XNTOV(xp)		((xp)->xn_vnode)
#define	xmemnode_hold(tp)	VN_HOLD(XNTOV(tp))
#define	xmemnode_rele(tp)	VN_RELE(XNTOV(tp))

/*
 * enums
 */
enum de_op	{ DE_CREATE, DE_MKDIR, DE_LINK, DE_RENAME }; /* direnter ops */
enum dr_op	{ DR_REMOVE, DR_RMDIR, DR_RENAME };	/* dirremove ops */

/*
 * xmemfs_minfree is the amount (in pages) of memory that xmemfs
 * leaves free for the rest of the system.
 * NB: If xmemfs allocates too much space, other processes will be
 * unable to execute. 320 is chosen arbitrarily to be about right for
 * an RDBMS environment with all of it's buffers coming from xmemfs.
 */
#define	XMEMMINFREE	320 * 1024 * 1024	/* 320 Megabytes */
/*
 * number of simultaneous reads/writes is limited by NUM_SIMULMAPS
 * below. We cannot set it much higher as we expect typical block
 * size to be 2MB or 4MB and we cannot afford to reserve and keep
 * too much kernel virtual memory for ourselves.
 */
#define	SEGXMEM_NUM_SIMULMAPS	4

extern pgcnt_t	xmemfs_minfree;		/* memory in pages */

extern	void	xmemnode_init(struct xmount *, struct xmemnode *,
				struct vattr *, struct cred *);
extern	int	xmemnode_trunc(struct xmount *, struct xmemnode *, u_offset_t);
extern	int	xdirlookup(struct xmemnode *, char *, struct xmemnode **,
			struct cred *);
extern	int	xdirdelete(struct xmemnode *, struct xmemnode *, char *,
				enum dr_op, struct cred *);
extern	void	xdirinit(struct xmemnode *, struct xmemnode *);
extern	void	xdirtrunc(struct xmemnode *);
extern	void	*xmem_memalloc(size_t, int);
extern	void	xmem_memfree(void *, size_t);
extern	int	xmem_xaccess(void *, int, struct cred *);
extern	int	xdirenter(struct xmount *, struct xmemnode *, char *,
	enum de_op, struct xmemnode *, struct xmemnode *, struct vattr *,
	struct xmemnode **, struct cred *);
extern int xmem_fillpages(struct xmemnode *, struct vnode *, offset_t,
					offset_t, int);
extern int xmem_sticky_remove_access(struct xmemnode *, struct xmemnode *,
	struct cred *);

#endif	/* _KERNEL */

#define	XMEM_MUSTHAVE	1

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_XMEM_H */
