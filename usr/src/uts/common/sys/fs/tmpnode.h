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

#ifndef _SYS_FS_TMPNODE_H
#define	_SYS_FS_TMPNODE_H

#include <sys/t_lock.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <sys/vfs_opreg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * tmpnode is the file system dependent node for tmpfs.
 *
 *	tn_rwlock protects access of the directory list at tn_dir
 *	as well as syncronizing read and writes to the tmpnode
 *
 *	tn_contents protects growing, shrinking, reading and writing
 *	the file along with tn_rwlock (see below).
 *
 *	tn_tlock protects updates to tn_mode and tn_nlink
 *
 *	tm_contents in the tmount filesystem data structure protects
 *	tn_forw and tn_back which are used to maintain a linked
 *	list of all tmpfs files associated with that file system
 *
 *	The anon array represents the secondary store for tmpfs.
 * 	To grow or shrink the file or fill in holes requires
 *	manipulation of the anon array. These operations are protected
 *	by a combination of tn_rwlock and tn_contents. Growing or shrinking
 * 	the array requires the write lock on tn_rwlock and tn_contents.
 *	Filling in a slot in the array requires the write lock on tn_contents.
 *	Reading the array requires the read lock on tn_contents.
 *
 *	The ordering of the locking is:
 *	tn_rwlock -> tn_contents -> page locks on pages in file
 *
 *	tn_tlock doesn't require any tmpnode locks
 */

struct tmpnode {
	struct tmpnode	*tn_back;		/* linked list of tmpnodes */
	struct tmpnode	*tn_forw;		/* linked list of tmpnodes */
	union {
		struct {
			struct tdirent	*un_dirlist; /* dirent list */
			uint_t	un_dirents;	/* number of dirents */
		} un_dirstruct;
		char 		*un_symlink;	/* pointer to symlink */
		struct {
			struct anon_hdr	*un_anon; /* anon backing for file */
			pgcnt_t	un_size;	/* size repres. by array */
		} un_anonstruct;
	} un_tmpnode;
	struct vnode 	*tn_vnode;		/* vnode for this tmpnode */
	int 		tn_gen;			/* pseudo gen number for tfid */
	struct vattr	tn_attr;		/* attributes */
	krwlock_t	tn_contents;		/* vm side -serialize mods */
	krwlock_t	tn_rwlock;		/* rw,trunc size - serialize */
						/* mods and directory updates */
	kmutex_t	tn_tlock;		/* time, flag, and nlink lock */
	struct tmpnode *tn_xattrdp;		/* ext. attribute directory */
	uint_t		tn_flags;		/* tmpnode specific flags */
};

#define	tn_dir		un_tmpnode.un_dirstruct.un_dirlist
#define	tn_dirents	un_tmpnode.un_dirstruct.un_dirents
#define	tn_symlink	un_tmpnode.un_symlink
#define	tn_anon		un_tmpnode.un_anonstruct.un_anon
#define	tn_asize	un_tmpnode.un_anonstruct.un_size

/*
 * tmnode flag values.
 */
#define	ISXATTR		0x1

/*
 * Attributes
 */
#define	tn_mask		tn_attr.va_mask
#define	tn_type		tn_attr.va_type
#define	tn_mode		tn_attr.va_mode
#define	tn_uid		tn_attr.va_uid
#define	tn_gid		tn_attr.va_gid
#define	tn_fsid		tn_attr.va_fsid
#define	tn_nodeid	tn_attr.va_nodeid
#define	tn_nlink	tn_attr.va_nlink
#define	tn_size		tn_attr.va_size
#define	tn_atime	tn_attr.va_atime
#define	tn_mtime	tn_attr.va_mtime
#define	tn_ctime	tn_attr.va_ctime
#define	tn_rdev		tn_attr.va_rdev
#define	tn_blksize	tn_attr.va_blksize
#define	tn_nblocks	tn_attr.va_nblocks
#define	tn_seq		tn_attr.va_seq

/*
 * tmpfs directories are made up of a linked list of tdirent structures
 * hanging off directory tmpnodes.  File names are not fixed length,
 * but are null terminated.
 */
struct tdirent {
	struct tmpnode	*td_tmpnode;		/* tnode for this file */
	struct tdirent	*td_next;		/* next directory entry */
	struct tdirent	*td_prev;		/* prev directory entry */
	uint_t		td_offset;		/* "offset" of dir entry */
	uint_t		td_hash;		/* a hash of td_name */
	struct tdirent	*td_link;		/* linked via the hash table */
	struct tmpnode	*td_parent;		/* parent, dir we are in */
	char		*td_name;		/* must be null terminated */
						/* max length is MAXNAMELEN */
};

/*
 * tfid overlays the fid structure (for VFS_VGET)
 */
struct tfid {
	uint16_t tfid_len;
	ino32_t	tfid_ino;
	int32_t	tfid_gen;
};

#define	ESAME	(-1)		/* trying to rename linked files (special) */

extern struct vnodeops *tmp_vnodeops;
extern const struct fs_operation_def tmp_vnodeops_template[];

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_TMPNODE_H */
