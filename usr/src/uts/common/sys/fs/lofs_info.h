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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Loopback mount info - one per mount
 */

#ifndef _SYS_FS_LOFS_INFO_H
#define	_SYS_FS_LOFS_INFO_H

#ifdef _KERNEL
#include <sys/vfs_opreg.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

struct lnode;

struct lobucket {
	kmutex_t	lh_lock;	/* lock protecting bucket contents */
	struct lnode	*lh_chain;	/* vnode chain for this bucket */
	uint_t		lh_count;	/* Number of vnodes in chain */
	/* Pad up to 64-byte boundary to avoid false sharing */
#ifdef _LP64
	char		_pad[44];
#else
	char		_pad[48];
#endif
};

struct lo_retired_ht {
	struct lo_retired_ht	*lrh_next;
	struct lobucket		*lrh_table;
	uint_t			lrh_size;
};

struct loinfo {
	struct vfs	*li_realvfs;	/* real vfs of mount */
	struct vfs	*li_mountvfs;	/* loopback vfs */
	struct vnode	*li_rootvp;	/* root vnode of this vfs */
	int		 li_mflag;	/* mount flags to inherit */
	int		 li_dflag;	/* mount flags to not inherit */
	uint_t		 li_refct;	/* # outstanding vnodes */
	volatile uint_t	 li_htsize;	/* # buckets in hashtable */
	struct lobucket *volatile li_hashtable; /* table of per-mount vnodes */
	struct lfsnode	*li_lfs;	/* list of other vfss */
	kmutex_t	 li_lfslock;	/* lock protecting li_lfs */
	kmutex_t	 li_htlock;	/* protect hashtable, htsize, retired */
	struct lo_retired_ht *li_retired; /* list of retired hashtables */
	int		 li_flag;	/* filesystem behavior flags */
};

/* inheritable mount flags - propagated from real vfs to loopback */
#define	INHERIT_VFS_FLAG	\
	(VFS_RDONLY|VFS_NOSETUID|VFS_NODEVICES|VFS_XATTR|VFS_NBMAND|VFS_NOEXEC)

/*
 * "nosub" is used to provide NFS server-like semantics for lo_lookup(): never
 * traverse mount points for sub-mounts.  The lookup will instead look under
 * the mount point.
 */
#define	MNTOPT_LOFS_NOSUB	"nosub"
#define	MNTOPT_LOFS_SUB		"sub"

/*
 * Flag values (for li_flag)
 */
#define	LO_NOSUB	0x02	/* don't traverse sub-mounts */

/*
 * lfsnodes are allocated as new real vfs's are encountered
 * when looking up things in a loopback name space
 * It contains a new vfs which is paired with the real vfs
 * so that vfs ops (fsstat) can get to the correct real vfs
 * given just a loopback vfs
 */
struct lfsnode {
	struct lfsnode	*lfs_next;	/* next in loinfo list */
	struct vfs	*lfs_realvfs;	/* real vfs */
	struct vnode    *lfs_realrootvp; /* real root vp */
	struct vfs	 lfs_vfs;	/* new loopback vfs */
};

#define	vtoli(VFSP)	((struct loinfo *)((VFSP)->vfs_data))

#ifdef _KERNEL
extern struct vfs *lo_realvfs(struct vfs *, struct vnode **);
extern void lofs_subrinit(void);
extern void lofs_subrfini(void);

extern void lsetup(struct loinfo *, uint_t);
extern void ldestroy(struct loinfo *);

extern const struct fs_operation_def lo_vnodeops_template[];

extern struct vnodeops *lo_vnodeops;
extern vfsops_t *lo_vfsops;
extern struct mod_ops mod_fsops;

#endif /* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_LOFS_INFO_H */
