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
 * High Sierra filesystem structure definitions
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_HSFS_NODE_H
#define	_SYS_FS_HSFS_NODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/taskq.h>

struct	hs_direntry {
	uint_t		ext_lbn;	/* LBN of start of extent */
	uint_t		ext_size;    	/* no. of data bytes in extent */
	struct timeval	cdate;		/* creation date */
	struct timeval	mdate;		/* last modification date */
	struct timeval	adate;		/* last access date */
	enum vtype	type;		/* file type */
	mode_t		mode;		/* mode and type of file (UNIX) */
	uint_t		nlink;		/* no. of links to file */
	uid_t		uid;		/* owner's user id */
	gid_t		gid;		/* owner's group id */
	ino64_t		inode;		/* inode number from rrip data */
	dev_t		r_dev;		/* major/minor device numbers */
	uint_t		xar_prot :1;	/* 1 if protection in XAR */
	uchar_t		xar_len;	/* no. of Logical blocks in XAR */
	uchar_t		intlf_sz;	/* intleaving size */
	uchar_t		intlf_sk;	/* intleaving skip factor */
	ushort_t	sym_link_flag;	/* flags for sym link */
	char		*sym_link; 	/* path of sym link for readlink() */
};

struct	ptable {
	uchar_t	filler[7];		/* filler */
	uchar_t	dname_len;		/* length of directory name */
	uchar_t	dname[HS_DIR_NAMELEN+1];	/* directory name */
};

struct ptable_idx {
	struct ptable_idx *idx_pptbl_idx; /* parent's path table index entry */
	struct ptable	*idx_mptbl;	/* path table entry for myself */
	ushort_t idx_nochild;		/* no. of children */
	ushort_t idx_childid;		/* directory no of first child */
};

/*
 * hsnode structure:
 *
 * hs_offset, hs_ptbl_idx, base  apply to VDIR type only
 *
 * nodeid uniquely identifies an hsnode, ISO9660 means
 * nodeid can be very big.
 * For directories it is the disk address of
 * the data extent of the dir (the directory itself,
 * ".", and ".." all point to same data extent).
 * For non-directories, it is the disk address of the
 * directory entry for the file; note that this does
 * not permit hard links, as it assumes a single dir
 * entry per file.
 */

struct  hsnode {
	struct hsnode	*hs_hash;	/* next hsnode in hash list */
	struct hsnode	*hs_freef;	/* next hsnode in free list */
	struct hsnode	*hs_freeb;	/* previous hsnode in free list */
	struct vnode	*hs_vnode;	/* the real vnode for the file */
	struct hs_direntry hs_dirent;	/* the directory entry for this file */
	ino64_t		hs_nodeid;	/* "inode" number for hsnode */
	uint_t		hs_dir_lbn;	/* LBN of directory entry */
	uint_t		hs_dir_off;	/* offset in LBN of directory entry */
	struct ptable_idx	*hs_ptbl_idx;	/* path table index */
	uint_t		hs_offset;	/* start offset in dir for searching */
	long		hs_mapcnt;	/* mappings to file pages */
	uint_t		hs_seq;		/* sequence number */
	uint_t		hs_flags;	/* (see below) */
	u_offset_t	hs_prev_offset; /* Last read end offset (readahead) */
	int		hs_num_contig;  /* Count of contiguous reads */
	int		hs_ra_bytes;    /* Bytes to readahead */
	kmutex_t	hs_contents_lock;	/* protects hsnode contents */
						/* 	except hs_offset */
};

/* hs_flags */
#define	HREF	1			/* hsnode is referenced */

/* hs_modes */

#define	HFDIR	0040000			/* directory */
#define	HFREG	0100000			/* regular file */

struct  hsfid {
	ushort_t	hf_len;		/* length of fid */
	ushort_t	hf_dir_off;	/* offset in LBN of directory entry */
	uint_t		hf_dir_lbn;	/* LBN of directory */
	uint32_t	hf_ino;		/* The inode number or HS_DUMMY_INO */
};


/*
 * All of the fields in the hs_volume are read-only once they have been
 * initialized.
 */
struct	hs_volume {
	ulong_t		vol_size; 	/* no. of Logical blocks in Volume */
	uint_t		lbn_size;	/* no. of bytes in a block */
	uint_t		lbn_shift;	/* shift to convert lbn to bytes */
	uint_t		lbn_secshift;	/* shift to convert lbn to sec */
	uint_t		lbn_maxoffset;	/* max lbn-relative offset and mask */
	uchar_t		file_struct_ver; /* version of directory structure */
	uid_t		vol_uid;	/* uid of volume */
	gid_t		vol_gid;	/* gid of volume */
	uint_t		vol_prot;	/* protection (mode) of volume */
	struct timeval	cre_date;	/* volume creation time */
	struct timeval	mod_date;	/* volume modification time */
	struct	hs_direntry root_dir;	/* dir entry for Root Directory */
	ushort_t	ptbl_len;	/* number of bytes in Path Table */
	uint_t		ptbl_lbn;	/* logical block no of Path Table */
	ushort_t	vol_set_size;	/* number of CD in this vol set */
	ushort_t	vol_set_seq;	/* the sequence number of this CD */
	char		vol_id[32];		/* volume id in PVD */
};

/*
 * The hsnode table is no longer fixed in size but grows
 * and shrinks dynamically. However a cache of nodes is still maintained
 * for efficiency. This cache size (nhsnode) is a tunable which
 * is either specified in /etc/system or calculated as the number
 * that will fit into the number of bytes defined by HS_HSNODESPACE (below).
 */
#define	HS_HASHSIZE	32		/* hsnode hash table size */
#define	HS_HSNODESPACE	16384		/* approx. space used for hsnodes */

/*
 * We usually use the starting extent LBA for the inode numbers of files and
 * directories. As this will not work for zero sized files, we assign a dummy
 * inode number to all zero sized files. We use the number 16 as this is the
 * LBA for the PVD, this number cannot be a valid starting extent LBA for a
 * file. In case that the node number is the HS_DUMMY_INO, we use the LBA and
 * offset of the directory entry of this file (which is what we used before
 * we started to support correct hard links).
 */
#define	HS_DUMMY_INO	16	/* dummy inode number for empty files */

/*
 * Hsfs I/O Scheduling parameters and data structures.
 * Deadline for reads is set at 5000 usec.
 */
#define	HSFS_READ_DEADLINE 5000
#define	HSFS_NORMAL 0x0

/*
 * This structure holds information for a read request that is enqueued
 * for processing by the scheduling function. An AVL tree is used to
 * access the read requests in a sorted manner.
 */
struct hio {
	struct buf	*bp;		/* The buf for this read */
	struct hio	*contig_chain;  /* Next adjacent read if any */
	offset_t	io_lblkno;	/* Starting disk block of io */
	u_offset_t	nblocks;	/* # disk blocks */
	uint64_t	io_timestamp;	/* usec timestamp for deadline */
	ksema_t		*sema;		/* Completion flag */
	avl_node_t	io_offset_node; /* Avl tree requirements */
	avl_node_t	io_deadline_node;
};

/*
 * This structure holds information about all the read requests issued
 * during a read-ahead invocation. This is then enqueued on a task-queue
 * for processing by a background thread that takes this read-ahead to
 * completion and cleans up.
 */
struct hio_info {
	struct buf	*bufs;	/* array of bufs issued for this R/A */
	caddr_t		*vas;	/* The kmem_alloced chunk for the bufs */
	ksema_t		*sema;	/* Semaphores used in the bufs */
	uint_t		bufsused; /* # of bufs actually used */
	uint_t		bufcnt;   /* Tot bufs allocated. */
	struct page	*pp;	  /* The list of I/O locked pages */
	struct hsfs	*fsp; /* The filesystem structure */
};

/*
 * This is per-filesystem structure that stores toplevel data structures for
 * the I/O scheduler.
 */
struct hsfs_queue {
	/*
	 * A dummy hio holding the LBN of the last read processed. Easy
	 * to use in AVL_NEXT for Circular Look behavior.
	 */
	struct hio	*next;

	/*
	 * A pre-allocated buf for issuing coalesced reads. The scheduling
	 * function is mostly single threaded by necessity.
	 */
	struct buf	*nbuf;
	kmutex_t	hsfs_queue_lock; /* Protects the AVL trees */

	/*
	 * Makes most of the scheduling function Single-threaded.
	 */
	kmutex_t	strategy_lock;
	avl_tree_t	read_tree;	 /* Reads ordered by LBN */
	avl_tree_t	deadline_tree;	 /* Reads ordered by timestamp */
	taskq_t		*ra_task;	 /* Read-ahead Q */
	int		max_ra_bytes;	 /* Max read-ahead quantum */

	/* Device Max Transfer size in DEV_BSIZE */
	uint_t		dev_maxtransfer;
};

/*
 * High Sierra filesystem structure.
 * There is one of these for each mounted High Sierra filesystem.
 */
enum hs_vol_type {
	HS_VOL_TYPE_HS = 0, HS_VOL_TYPE_ISO = 1, HS_VOL_TYPE_ISO_V2 = 2,
	HS_VOL_TYPE_JOLIET = 3
};
#define	HSFS_MAGIC 0x03095500
struct hsfs {
	struct hsfs	*hsfs_next;	/* ptr to next entry in linked list */
	long		hsfs_magic;	/* should be HSFS_MAGIC */
	struct vfs	*hsfs_vfs;	/* vfs for this fs */
	struct vnode	*hsfs_rootvp;	/* vnode for root of filesystem */
	struct vnode	*hsfs_devvp;	/* device mounted on */
	enum hs_vol_type hsfs_vol_type; /* see above */
	struct hs_volume hsfs_vol;	/* File Structure Volume Descriptor */
	struct ptable	*hsfs_ptbl;	/* pointer to incore Path Table */
	int		hsfs_ptbl_size;	/* size of incore path table */
	struct ptable_idx *hsfs_ptbl_idx; /* pointer to path table index */
	int		hsfs_ptbl_idx_size;	/* no. of path table index */
	ulong_t		hsfs_ext_impl;	/* ext. information bits */
	ushort_t	hsfs_sua_off;	/* the SUA offset */
	ushort_t	hsfs_namemax;	/* maximum file name length */
	ushort_t	hsfs_namelen;	/* "official" max. file name length */
	ulong_t		hsfs_err_flags;	/* ways in which fs is non-conformant */
	char		*hsfs_fsmnt;	/* name mounted on */
	ulong_t		hsfs_flags;	/* hsfs-specific mount flags */
	krwlock_t	hsfs_hash_lock;	/* protect hash table & hst_nohsnode */
	struct hsnode	*hsfs_hash[HS_HASHSIZE]; /* head of hash lists */
	uint32_t	hsfs_nohsnode;	/* no. of allocated hsnodes */
	kmutex_t	hsfs_free_lock;	/* protects free list */
	struct hsnode	*hsfs_free_f;	/* first entry of free list */
	struct hsnode	*hsfs_free_b;	/* last entry of free list */

	/*
	 * Counters exported through kstats.
	 */
	uint64_t	physical_read_bytes;
	uint64_t	cache_read_pages;
	uint64_t	readahead_bytes;
	uint64_t	coalesced_bytes;
	uint64_t	total_pages_requested;
	kstat_t		*hsfs_kstats;

	struct hsfs_queue *hqueue;	/* I/O Scheduling parameters */
};

/*
 * Error types: bit offsets into hsfs_err_flags.
 * Also serves as index into hsfs_error[], so must be
 * kept in sync with that data structure.
 */
#define	HSFS_ERR_TRAILING_JUNK		0
#define	HSFS_ERR_LOWER_CASE_NM		1
#define	HSFS_ERR_BAD_ROOT_DIR		2
#define	HSFS_ERR_UNSUP_TYPE		3
#define	HSFS_ERR_BAD_FILE_LEN		4
#define	HSFS_ERR_BAD_JOLIET_FILE_LEN	5
#define	HSFS_ERR_TRUNC_JOLIET_FILE_LEN	6
#define	HSFS_ERR_BAD_DIR_ENTRY		7
#define	HSFS_ERR_NEG_SUA_LEN		8
#define	HSFS_ERR_BAD_SUA_LEN		9

#define	HSFS_HAVE_LOWER_CASE(fsp) \
	((fsp)->hsfs_err_flags & (1 << HSFS_ERR_LOWER_CASE_NM))


/*
 * File system parameter macros
 */
#define	hs_blksize(HSFS, HSP, OFF)	/* file system block size */ \
	((HSP)->hs_vn.v_flag & VROOT ? \
	    ((OFF) >= \
		((HSFS)->hsfs_rdirsec & ~((HSFS)->hsfs_spcl - 1))*HS_SECSIZE ?\
		((HSFS)->hsfs_rdirsec & ((HSFS)->hsfs_spcl - 1))*HS_SECSIZE :\
		(HSFS)->hsfs_clsize): \
	    (HSFS)->hsfs_clsize)
#define	hs_blkoff(OFF)		/* offset within block */ \
	((OFF) & (HS_SECSIZE - 1))

/*
 * Conversion macros
 */
#define	VFS_TO_HSFS(VFSP)	((struct hsfs *)(VFSP)->vfs_data)
#define	HSFS_TO_VFS(FSP)	((FSP)->hsfs_vfs)

#define	VTOH(VP)		((struct hsnode *)(VP)->v_data)
#define	HTOV(HP)		(((HP)->hs_vnode))

/*
 * Convert between Logical Block Number and Sector Number.
 */
#define	LBN_TO_SEC(lbn, vfsp)	((lbn)>>((struct hsfs *)((vfsp)->vfs_data))->  \
				hsfs_vol.lbn_secshift)

#define	SEC_TO_LBN(sec, vfsp)	((sec)<<((struct hsfs *)((vfsp)->vfs_data))->  \
				hsfs_vol.lbn_secshift)

#define	LBN_TO_BYTE(lbn, vfsp)	((lbn)<<((struct hsfs *)((vfsp)->vfs_data))->  \
				hsfs_vol.lbn_shift)
#define	BYTE_TO_LBN(boff, vfsp)	((boff)>>((struct hsfs *)((vfsp)->vfs_data))-> \
				hsfs_vol.lbn_shift)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_HSFS_NODE_H */
