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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_SNODE_H
#define	_SYS_FS_SNODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/cred.h>
#include <sys/vnode.h>

/*
 * The snode represents a special file in any filesystem.  There is
 * one snode for each active special file.  Filesystems that support
 * special files use specvp(vp, dev, type, cr) to convert a normal
 * vnode to a special vnode in the ops lookup() and create().
 *
 * To handle having multiple snodes that represent the same
 * underlying device vnode without cache aliasing problems,
 * the s_commonvp is used to point to the "common" vnode used for
 * caching data.  If an snode is created internally by the kernel,
 * then the s_realvp field is NULL and s_commonvp points to s_vnode.
 * The other snodes which are created as a result of a lookup of a
 * device in a file system have s_realvp pointing to the vp which
 * represents the device in the file system while the s_commonvp points
 * into the "common" vnode for the device in another snode.
 */

/*
 * Include SUNDDI type definitions so that the s_dip tag doesn't urk.
 */
#include <sys/dditypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct snode {
	/* These fields are protected by stable_lock */
	struct	snode *s_next;		/* must be first */
	struct	vnode *s_vnode;		/* vnode associated with this snode */
	/*
	 * These fields are initialized once.
	 */
	struct	vnode *s_realvp;	/* vnode for the fs entry (if any) */
	struct	vnode *s_commonvp;	/* common device vnode */
	dev_t	s_dev;			/* device the snode represents */
	dev_info_t *s_dip;		/* dev_info (common snode only) */
	/*
	 * Doesn't always need to be updated atomically because it is a hint.
	 * No lock required.
	 */
	u_offset_t s_nextr;		/* next byte read offset (read-ahead) */

	/* These fields are protected by spec_syncbusy */
	struct	snode *s_list;		/* used for syncing */
	/* These fields are protected by s_lock */
	struct devplcy *s_plcy;		/* device node open policy (cs only) */
	u_offset_t s_size;		/* block device size in bytes */
	uint_t	s_flag;			/* flags, see below */
	dev_t	s_fsid;			/* file system identifier */
	time_t  s_atime;		/* time of last access */
	time_t  s_mtime;		/* time of last modification */
	time_t  s_ctime;		/* time of last attributes change */
	int	s_count;		/* count of opened references */
	long	s_mapcnt;		/* count of mappings of pages */
	/* The locks themselves */
	kmutex_t	s_lock;		/* protects snode fields */
	kcondvar_t	s_cv;		/* synchronize open/closes */
};

/* flags */
#define	SUPD		0x01		/* update device access time */
#define	SACC		0x02		/* update device modification time */
#define	SCHG		0x04		/* update device change time */
#define	SPRIV		0x08		/* file open for private access */
#define	SLOFFSET	0x10		/* device takes 64-bit uio offsets */
#define	SLOCKED		0x20		/* use to serialize open/closes */
#define	SWANT		0x40		/* some process waiting on lock */
#define	SANYOFFSET	0x80		/* device takes any uio offset */
#define	SCLONE		0x100		/* represents a cloned device */
#define	SNEEDCLOSE	0x200		/* needs driver close call */
#define	SDIPSET		0x400		/* the vnode has an association with */
					/* the driver, even though it may */
					/* not currently have an association */
					/* with a specific hardware instance */
					/* if s_dip is NULL */
#define	SSIZEVALID	0x800		/* s_size field is valid */
#define	SMUXED		0x1000		/* this snode is a stream that has */
					/* been multiplexed */
#define	SSELFCLONE	0x2000		/* represents a self cloning device */
#define	SNOFLUSH	0x4000		/* do not flush device on fsync */
#define	SCLOSING	0x8000		/* in last close(9E) */
#define	SFENCED		0x10000		/* snode fenced off for I/O retire */

#ifdef _KERNEL
/*
 * Convert between vnode and snode
 */
#define	VTOS(vp)	((struct snode *)((vp)->v_data))
#define	VTOCS(vp)	(VTOS(VTOS(vp)->s_commonvp))
#define	STOV(sp)	((sp)->s_vnode)

extern int spec_debug;

#define	SPEC_FENCE_DEBUG	0x0001	/* emit fence related debug messages */

#define	FENDBG(args)	if (spec_debug & SPEC_FENCE_DEBUG) cmn_err args


/*
 * Forward declarations
 */
struct vfssw;
struct cred;

extern struct vfs	spec_vfs;
extern struct vfsops	spec_vfsops;
extern struct kmem_cache *snode_cache;

/*
 * specfs functions
 */
offset_t	spec_maxoffset(struct vnode *);
struct vnodeops	*spec_getvnodeops(void);
struct vnode *specvp(struct vnode *, dev_t, vtype_t, struct cred *);
struct vnode *makespecvp(dev_t, vtype_t);
struct vnode *other_specvp(struct vnode *);
struct vnode *common_specvp(struct vnode *);
struct vnode *specfind(dev_t, vtype_t);
struct vnode *commonvp(dev_t, vtype_t);
struct vnode *makectty(vnode_t *);
void	sdelete(struct snode *);
void 	smark(struct snode *, int);
int	specinit(int, char *);
int	device_close(struct vnode *, int, struct cred *);
int	spec_putpage(struct vnode *, offset_t, size_t, int, struct cred *,
		caller_context_t *);
int	spec_segmap(dev_t, off_t, struct as *, caddr_t *, off_t,
		    uint_t, uint_t, uint_t, cred_t *);
struct vnode *specvp_devfs(struct vnode *, dev_t, vtype_t,
		    struct cred *, dev_info_t *);
void	spec_assoc_vp_with_devi(struct vnode *, dev_info_t *);
dev_info_t *spec_hold_devi_by_vp(struct vnode *);
int	spec_sync(struct vfs *, short, struct cred *);
void	spec_snode_walk(int (*callback)(struct snode *, void *), void *);
int	spec_devi_open_count(struct snode *, dev_info_t **);
int	spec_is_clone(struct vnode *);
int	spec_is_selfclone(struct vnode *);
int	spec_fence_snode(dev_info_t *dip, struct vnode *vp);
int	spec_unfence_snode(dev_info_t *dip);
void	spec_size_invalidate(dev_t, vtype_t);


/*
 * UNKNOWN_SIZE: If driver does not support the [Ss]ize or [Nn]blocks property
 * then the size is assumed to be "infinite".  Note that this "infinite" value
 * may need to be converted to a smaller "infinite" value to avoid EOVERFLOW at
 * field width conversion locations like the stat(2) and NFS code running
 * against a special file.  Special file code outside specfs may check the
 * type of the vnode (VCHR|VBLK) and use MAXOFFSET_T directly to detect
 * UNKNOWN_SIZE.
 */
#define	UNKNOWN_SIZE		MAXOFFSET_T

/*
 * SPEC_MAXOFFSET_T: Solaris does not fully support 64-bit offsets for D_64BIT
 * (SLOFFSET) block drivers on a 32-bit kernels: daddr_t is still a signed
 * 32-bit quantity - which limits the byte offset to 1TB. This issue goes
 * beyond a driver needing to convert from daddr_t to diskaddr_t if it sets
 * D_64BIT. Many of the DDI interfaces which take daddr_t arguments have no
 * 64-bit counterpart (bioclone, blkflush, bread, bread_common, breada, getblk,
 * getblk_common). SPEC_MAXOFFSET_T is used by 32-bit kernel code to enforce
 * this restriction.
 */
#ifdef	_ILP32
#ifdef	_LONGLONG_TYPE
#define	SPEC_MAXOFFSET_T	((1LL << ((NBBY * sizeof (daddr32_t)) +	\
				DEV_BSHIFT - 1)) - 1)
#else	/* !defined(_LONGLONG_TYPE) */
#define	SPEC_MAXOFFSET_T	MAXOFF_T
#endif	/* _LONGLONG_TYPE */
#endif	/* _ILP32 */

/*
 * Snode lookup stuff.
 * These routines maintain a table of snodes hashed by dev so
 * that the snode for an dev can be found if it already exists.
 * NOTE: STABLESIZE must be a power of 2 for STABLEHASH to work!
 */

#define	STABLESIZE	256
#define	STABLEHASH(dev)	((getmajor(dev) + getminor(dev)) & (STABLESIZE - 1))
extern struct snode *stable[];
extern kmutex_t	stable_lock;
extern kmutex_t	spec_syncbusy;

/*
 * Variables used by during asynchronous VOP_PUTPAGE operations.
 */
extern struct async_reqs *spec_async_reqs;	/* async request list */
extern kmutex_t spec_async_lock;		/* lock to protect async list */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_SNODE_H */
