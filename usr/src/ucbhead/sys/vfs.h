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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_VFS_H
#define	_SYS_VFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/statvfs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Data associated with mounted file systems.
 */

/*
 * File system identifier. Should be unique (at least per machine).
 */
typedef struct {
	int val[2];			/* file system id type */
} fsid_t;

/*
 * File identifier.  Should be unique per filesystem on a single
 * machine.  This is typically called by a stateless file server
 * in order to generate "file handles".
 */
#define	MAXFIDSZ	16
#define	freefid(fidp) \
    kmem_free((caddr_t)(fidp), sizeof (struct fid) - MAXFIDSZ + (fidp)->fid_len)

typedef struct fid {
	ushort_t	fid_len;		/* length of data in bytes */
	char		fid_data[MAXFIDSZ];	/* data (variable length) */
} fid_t;

/*
 * Structure per mounted file system.  Each mounted file system has
 * an array of operations and an instance record.  The file systems
 * are kept on a singly linked list headed by "rootvfs" and terminated
 * by NULL.
 */
typedef struct vfs {
	struct vfs	*vfs_next;		/* next VFS in VFS list */
	struct vfsops	*vfs_op;		/* operations on VFS */
	struct vnode	*vfs_vnodecovered;	/* vnode mounted on */
	ulong_t		vfs_flag;		/* flags */
	ulong_t		vfs_bsize;		/* native block size */
	int		vfs_fstype;		/* file system type index */
	fsid_t		vfs_fsid;		/* file system id */
	caddr_t		vfs_data;		/* private data */
	l_dev_t		vfs_dev;		/* device of mounted VFS */
	ulong_t		vfs_bcount;		/* I/O count (accounting) */
	ushort_t	vfs_nsubmounts;		/* immediate sub-mount count */
} vfs_t;

/*
 * VFS flags.
 */
#define	VFS_RDONLY	0x01		/* read-only vfs */
#define	VFS_MLOCK	0x02		/* lock vfs so that subtree is stable */
#define	VFS_MWAIT	0x04		/* someone is waiting for lock */
#define	VFS_NOSUID	0x08		/* setuid disallowed */
#define	VFS_REMOUNT	0x10		/* modify mount options only */
#define	VFS_NOTRUNC	0x20		/* does not truncate long file names */

/*
 * Argument structure for mount(2).
 */
struct mounta {
	char	*spec;
	char	*dir;
	int	flags;
	char	*fstype;
	char	*dataptr;
	int	datalen;
};

/*
 * Reasons for calling the vfs_mountroot() operation.
 */

enum whymountroot { ROOT_INIT, ROOT_REMOUNT, ROOT_UNMOUNT };
typedef enum whymountroot whymountroot_t;

/*
 * Operations supported on virtual file system.
 */
typedef struct vfsops {
#if defined(__STDC__)
	int	(*vfs_mount)(struct vfs *, struct vnode *, struct mounta *,
			struct cred *);
	int	(*vfs_unmount)(struct vfs *, struct cred *);
	int	(*vfs_root)(struct vfs *, struct vnode **);
	int	(*vfs_statvfs)(struct vfs *, struct statvfs64 *);
	int	(*vfs_sync)(struct vfs *, short, struct cred *);
	int	(*vfs_vget)(struct vfs *, struct vnode **, struct fid *);
	int	(*vfs_mountroot)(struct vfs *, enum whymountroot);
	int	(*vfs_swapvp)(struct vfs *, struct vnode **, char *);
	int	(*vfs_filler[4])(void);
#else
	int	(*vfs_mount)();		/* mount file system */
	int	(*vfs_unmount)();	/* unmount file system */
	int	(*vfs_root)();		/* get root vnode */
	int	(*vfs_statvfs)();	/* get file system statistics */
	int	(*vfs_sync)();		/* flush fs buffers */
	int	(*vfs_vget)();		/* get vnode from fid */
	int	(*vfs_mountroot)();	/* mount the root filesystem */
	int	(*vfs_swapvp)();	/* return vnode for swap */
	int	(*vfs_filler[4])();	/* for future expansion */
#endif
} vfsops_t;

#define	VFS_MOUNT(vfsp, mvp, uap, cr) \
	(*(vfsp)->vfs_op->vfs_mount)(vfsp, mvp, uap, cr)
#define	VFS_UNMOUNT(vfsp, cr)	(*(vfsp)->vfs_op->vfs_unmount)(vfsp, cr)
#define	VFS_ROOT(vfsp, vpp)	(*(vfsp)->vfs_op->vfs_root)(vfsp, vpp)
#define	VFS_STATVFS(vfsp, sp)	(*(vfsp)->vfs_op->vfs_statvfs)(vfsp, sp)
#define	VFS_SYNC(vfsp)	(*(vfsp)->vfs_op->vfs_sync)(vfsp)
#define	VFS_VGET(vfsp, vpp, fidp) \
		(*(vfsp)->vfs_op->vfs_vget)(vfsp, vpp, fidp)
#define	VFS_MOUNTROOT(vfsp, init) \
		(*(vfsp)->vfs_op->vfs_mountroot)(vfsp, init)
#define	VFS_SWAPVP(vfsp, vpp, nm) \
		(*(vfsp)->vfs_op->vfs_swapvp)(vfsp, vpp, nm)

/*
 * Filesystem type switch table.
 */
typedef struct vfssw {
	char		*vsw_name;	/* type name string */
#if defined(__STDC__)
	int		(*vsw_init)(struct vfssw *, int);
#else
	int		(*vsw_init)();	/* init routine */
#endif
	struct vfsops	*vsw_vfsops;	/* filesystem operations vector */
	int		vsw_flag;	/* flags */
} vfssw_t;

/*
 * Public operations.
 */
#if defined(__STDC__)
void	vfs_mountroot(void);
void	vfs_add(vnode_t *, struct vfs *, int);
void	vfs_remove(struct vfs *);
int	vfs_lock(struct vfs *);
void	vfs_unlock(struct vfs *);
struct vfs *getvfs(fsid_t *);
struct vfs *vfs_devsearch(dev_t);
struct vfssw *vfs_getvfssw(char *);
u_int	vf_to_stf(u_int);
#else
extern void	vfs_mountroot();	/* mount the root */
extern void	vfs_add();		/* add a new vfs to mounted vfs list */
extern void	vfs_remove();		/* remove a vfs from mounted vfs list */
extern int	vfs_lock();		/* lock a vfs */
extern void	vfs_unlock();		/* unlock a vfs */
extern vfs_t	*getvfs();		/* return vfs given fsid */
extern vfs_t	*vfs_devsearch();	/* find vfs given device */
extern vfssw_t	*vfs_getvfssw();	/* find vfssw ptr given fstype name */
extern ulong_t	vf_to_stf();		/* map VFS flags to statfs flags */
#endif

#define	VFS_INIT(vfsp, op, data)	{ \
	(vfsp)->vfs_next = (struct vfs *)0; \
	(vfsp)->vfs_op = (op); \
	(vfsp)->vfs_flag = 0; \
	(vfsp)->vfs_data = (data); \
	(vfsp)->vfs_nsubmounts = 0; \
}

/*
 * Globals.
 */
extern struct vfs *rootvfs;		/* ptr to root vfs structure */
extern struct vfssw vfssw[];		/* table of filesystem types */
extern char rootfstype[];		/* name of root fstype */
extern int nfstype;			/* # of elements in vfssw array */

/*
 * file system statistics, from SunOS 4.1
 */
#if _FILE_OFFSET_BITS == 32
struct statfs {
	int f_type;		/* type of info, zero for now */
	int f_bsize;		/* fundamental file system block size */
	int f_blocks;		/* total blocks in file system */
	int f_bfree;		/* free blocks in fs */
	int f_bavail;		/* free blocks avail to non-superuser */
	int f_files;		/* total file nodes in file system */
	int f_ffree;		/* free files nodes in fs */
	fsid_t f_fsid;		/* file system id */
	int f_spare[7];		/* spare for later */
};
#elif _FILE_OFFSET_BITS == 64
struct statfs {
	long f_type;		/* type of info, zero for now */
	ulong_t f_bsize;	/* fundamental file system block size */
	fsblkcnt_t f_blocks;	/* total blocks in file system */
	fsblkcnt_t f_bfree;	/* free blocks in fs */
	fsblkcnt_t f_bavail;	/* free blocks avail to non-superuser */
	fsfilcnt_t f_files;	/* total file nodes in file system */
	fsfilcnt_t f_ffree;	/* free files nodes in fs */
	fsid_t f_fsid;		/* file system id */
	int f_spare[7];		/* spare for later */
};
#endif
#if	defined(_LARGEFILE64_SOURCE)
struct statfs64 {
	long f_type;		/* type of info, zero for now */

	ulong_t f_bsize;	/* fundamental file system block size */
	fsblkcnt_t f_blocks;	/* total blocks in file system */
	fsblkcnt_t f_bfree;	/* free blocks in fs */
	fsblkcnt_t f_bavail;	/* free blocks avail to non-superuser */
	fsfilcnt_t f_files;	/* total file nodes in file system */
	fsfilcnt_t f_ffree;	/* free files nodes in fs */
	fsid_t f_fsid;		/* file system id */
	int f_spare[7];		/* spare for later */
};
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_VFS_H */
