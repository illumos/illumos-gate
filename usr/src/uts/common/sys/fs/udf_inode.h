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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved */

#ifndef	_SYS_FS_UDF_INODE_H
#define	_SYS_FS_UDF_INODE_H

#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SUN_IMPL_ID	"*SUN SOLARIS UDF"
#define	SUN_IMPL_ID_LEN	16
#define	SUN_OS_CLASS	4
#define	SUN_OS_ID	2

/*
 * Size of each cluster
 * and bits to be shifted
 */
#define	CLSTR_SIZE	8
#define	CLSTR_MASK	7


/*
 * enums
 */
enum de_op { DE_CREATE, DE_MKDIR, DE_LINK, DE_RENAME };	/* direnter ops */
enum dr_op { DR_REMOVE, DR_RMDIR, DR_RENAME };		/* dirremove ops */

/*
 * The following macros optimize certain frequently calculated
 * quantities by using shifts and masks in place of divisions
 * modulos and multiplications.
 */

#define	blkoff(udfvfsp, loc)	/* calculates (loc % udfcfs->udf_lbsize) */ \
		((loc) & (udfvfsp)->udf_lbmask)

#define	lblkno(udf_vfsp, loc)	\
	((int32_t)((loc) / (udf_vfsp)->udf_lbsize))

#define	fsbtodb(udf, blk)	\
	((blk) << udf->udf_l2d_shift)


struct udf_fid {
	uint16_t	udfid_len;	/* Length of data */
	uint16_t	udfid_prn;	/* the partition number of icb */
	uint32_t	udfid_icb_lbn;	/* file entry block no */
	uint32_t	udfid_uinq_lo;	/* uniq id to validate the vnode */
};




#define	MAXNAMLEN	255




struct ud_part {
	uint16_t	udp_flags;	/* See below */
	uint16_t	udp_number;	/* partition Number */
	uint32_t	udp_seqno;	/* to find the prevailaing desc */
	uint32_t	udp_access;	/* access type */
	uint32_t	udp_start;	/* Starting block no of partition */
	uint32_t	udp_length;	/* Lenght of the partition */
	uint32_t	udp_unall_loc;	/* unall space tbl or bitmap loc */
	uint32_t	udp_unall_len;	/* unall space tbl or bitmap length */
	uint32_t	udp_freed_loc;	/* freed space tbl or bitmap loc */
	uint32_t	udp_freed_len;	/* freed space tbl or bitmap length */
					/* From part desc */

	uint32_t	udp_nfree;	/* No of free blocks in the partition */
	uint32_t	udp_nblocks;	/* Total no of blks in the partition */
					/* From lvid */
	uint32_t	udp_last_alloc;	/* Last allocated space in bitmap */

	int32_t		udp_cache_count;	/* Cache is used for metadata */
	daddr_t		udp_cache[CLSTR_SIZE];
};

/*
 * udp_flags
 */
#define	UDP_BITMAPS	0x00
#define	UDP_SPACETBLS	0x01

/*
 * udp_access
 */
#define	UDP_MT_RO	0x0001		/* ROM */
#define	UDP_MT_WO	0x0002		/* WORM */
#define	UDP_MT_RW	0x0003		/* RW */
#define	UDP_MT_OW	0x0004		/* OW */



#define	MAX_SPM		4

struct ud_map {
	uint32_t	udm_flags;	/* Flags */
	uint16_t	udm_vsn;	/* Volume Sequence Number */
	uint16_t	udm_pn;		/* Partition Number */
	uint32_t	udm_vat_icb;	/* VAT ICB location */
	uint32_t	udm_nent;	/* Number of vat entries */
	uint32_t	*udm_count;	/* Number of entrues in each table */
	struct buf	**udm_bp;	/* VAT translation tables */
	uint32_t	**udm_addr;


	int32_t		udm_plen;
	int32_t		udm_nspm;
	uint32_t	udm_spsz;
	uint32_t	udm_loc[MAX_SPM];
	struct buf	*udm_sbp[MAX_SPM];
	caddr_t		udm_spaddr[MAX_SPM];
};

/*
 * udm_flags
 */
#define	UDM_MAP_NORM	0x00
#define	UDM_MAP_VPM	0x01
#define	UDM_MAP_SPM	0x02

struct udf_vfs {
	struct vfs	*udf_vfs;	/* Back link */
	struct udf_vfs	*udf_next;	/* Chain of udf file-system's */
	struct udf_vfs	*udf_wnext;	/* work list link */

	struct buf	*udf_vds;	/* most of the superblock */
	struct buf	*udf_iseq;	/* Integrity of the fs */
	struct vnode	*udf_root;	/* Root vnode */
	struct vnode	*udf_devvp;	/* Block device vnode */

	char		*udf_fsmnt;	/* Path name of directory mouted on */
	uint32_t	udf_flags;	/* Flags */
	uint32_t	udf_mtype;	/* Media type */

	int32_t		udf_rdclustsz;	/* read cluster size */
	int32_t		udf_wrclustsz;	/* write cluster size */

	uint64_t	udf_maxfsize;	/* Max file size allowed in this fs */
	int32_t		udf_maxfbits;	/* No of bit's for max file size */

	char		udf_volid[32];	/* volume identifier */
					/* from pvd */
	uint16_t	udf_tsno;	/* Taken from pvd and */
					/* used in making tags */

	int32_t		udf_lbsize;	/* Block size */
					/* from lvd */
	int32_t		udf_lbmask;	/* udf_lbsize - 1 */
	int32_t		udf_l2b_shift;	/* lbsize to bytes */
	int32_t		udf_l2d_shift;	/* right shift's to */
					/* make lbsize to DEV_BSIZE */

	int32_t		udf_npart;	/* No. of partition's in the volume */
					/* restricted to 1 till udf 1.50 */
	struct ud_part	*udf_parts;	/* pointer to array of partitions */
					/* from part desc's */

	int32_t		udf_nmaps;
	struct ud_map	*udf_maps;

	int32_t		udf_fragmented;	/* File System fragmented */
	int32_t		udf_mark_bad;	/* force fsck at next mount */

	/*
	 * sum of udp_nfree and udp_nblocks
	 * from the array udf_parts[0] to udf_parts[udf_nparts - 1]
	 */
	uint32_t	udf_freeblks;	/* Total udf_lbsize Free Blocks */
	uint32_t	udf_totalblks;	/* Total number of Blocks */
				/* udf_parts[0].udp_nfree == udf_freespace */
				/* till udf 1.50 (DVD-R?) */
	uint64_t	udf_maxuniq;	/* Maximum unique ID on the fs */
	uint32_t	udf_nfiles;	/* No of files */
	uint32_t	udf_ndirs;	/* No of directories */
	uint32_t	udf_miread;	/* minimum read revision */
	uint32_t	udf_miwrite;	/* minimum write revision */
	uint32_t	udf_mawrite;	/* maximum read revision */
					/* from lvid */

	time_t		udf_time;	/* Last time super block is written */
	uint32_t	udf_mod;	/* file system was modified */
	uint32_t	udf_clean;	/* state of the file system */
	kmutex_t	udf_lock;	/* protects contents */

	kmutex_t	udf_rename_lck;	/* lock for udf_rename */

	/*
	 * Have them cached here for fast access
	 */
	struct pri_vol_desc	*udf_pvd;
	struct log_vol_desc	*udf_lvd;
	struct log_vol_int_desc *udf_lvid;

	uint32_t		udf_mvds_loc;
	uint32_t		udf_mvds_len;

	uint32_t		udf_rvds_loc;
	uint32_t		udf_rvds_len;

	uint32_t		udf_iseq_loc;
	uint32_t		udf_iseq_len;

	uint16_t		udf_fsd_prn;
	uint32_t		udf_fsd_loc;
	uint32_t		udf_fsd_len;

	uint16_t		udf_ricb_prn;
	uint32_t		udf_ricb_loc;
	uint32_t		udf_ricb_len;
	daddr_t			udf_root_blkno;
};


#ifndef	__lint
_NOTE(MUTEX_PROTECTS_DATA(udf_vfs::udf_lock,
		udf_vfs::udf_fragmented))
_NOTE(MUTEX_PROTECTS_DATA(udf_vfs::udf_lock,
		udf_vfs::udf_freeblks udf_vfs::udf_totalblks))
_NOTE(MUTEX_PROTECTS_DATA(udf_vfs::udf_lock,
		udf_vfs::udf_maxuniq udf_vfs::udf_nfiles
		udf_vfs::udf_ndirs))
_NOTE(MUTEX_PROTECTS_DATA(udf_vfs::udf_lock,
		udf_vfs::udf_time
		udf_vfs::udf_mod udf_vfs::udf_clean))

_NOTE(READ_ONLY_DATA(udf_vfs::udf_nmaps udf_vfs::udf_maps))

_NOTE(READ_ONLY_DATA(udf_vfs::udf_mtype
		udf_vfs::udf_rdclustsz
		udf_vfs::udf_wrclustsz
		udf_vfs::udf_maxfsize
		udf_vfs::udf_maxfbits
		udf_vfs::udf_lbsize
		udf_vfs::udf_l2b_shift
		udf_vfs::udf_lbmask
		udf_vfs::udf_l2d_shift))

_NOTE(READ_ONLY_DATA(udf_vfs::udf_pvd
		udf_vfs::udf_lvd
		udf_vfs::udf_lvid))

_NOTE(READ_ONLY_DATA(udf_vfs::udf_mvds_loc
		udf_vfs::udf_mvds_len
		udf_vfs::udf_iseq_loc
		udf_vfs::udf_iseq_len
		udf_vfs::udf_fsd_prn
		udf_vfs::udf_fsd_loc
		udf_vfs::udf_fsd_len
		udf_vfs::udf_ricb_prn
		udf_vfs::udf_ricb_loc
		udf_vfs::udf_ricb_len
		udf_vfs::udf_root_blkno))

_NOTE(READ_ONLY_DATA(ud_part::udp_flags
		ud_part::udp_number
		ud_part::udp_seqno
		ud_part::udp_access
		ud_part::udp_start
		ud_part::udp_length
		ud_part::udp_unall_loc
		ud_part::udp_unall_len
		ud_part::udp_freed_loc
		ud_part::udp_freed_len
		ud_part::udp_nblocks))

_NOTE(MUTEX_PROTECTS_DATA(udf_vfs::udf_lock,
		ud_part::udp_nfree
		ud_part::udp_last_alloc
		ud_part::udp_cache_count
		ud_part::udp_cache))
#endif

/*
 * udf_mtype
 */
#define	UDF_MT_RO	UDP_MT_RO		/* ROM */
#define	UDF_MT_WO	UDP_MT_OW		/* WORM */
#define	UDF_MT_RW	UDP_MT_RW		/* RW */
#define	UDF_MT_OW	UDP_MT_OW		/* OW */

/*
 * udf_flags
 */
#define	UDF_FL_RDONLY	0x0001		/* file system is read only */
#define	UDF_FL_RW	0x0002		/* file system is read write */

/*
 * udf_clean
 */
#define	UDF_DIRTY	0x00
#define	UDF_CLEAN	0x01


#define	RD_CLUSTSZ(ip)		((ip)->i_udf->udf_rdclustsz)
#define	WR_CLUSTSZ(ip)		((ip)->i_udf->udf_wrclustsz)

/*
 * Size can be a 64-bit value and therefore we sign extend fs_bmask
 * to a 64-bit value too so that the higher 32 bits are masked
 * properly. Note that the type of fs_bmask has to be signed. Otherwise
 * compiler will set the higher 32 bits as zero and we don't want
 * this to happen.
 */

#ifdef	UNDEF
#define	blkroundup(fs, size)	/* calculates roundup(size, fs->fs_bsize) */ \
	(((size) + (fs)->udf_lbsize - 1) & (offset_t)(fs)->udf_lbmask)
#endif

#define	blkroundup(fs, size)	/* calculates roundup(size, fs->fs_bsize) */ \
	(((size) + (fs)->udf_lbmask) & (offset_t)(~(fs)->udf_lbmask))

#define	blksize(fs)	(fs->udf_lbsize)


/*
 * Convert between inode pointers and vnode pointers
 */
#define	VTOI(VP)	((struct ud_inode *)(VP)->v_data)
#define	ITOV(IP)	((IP)->i_vnode)
#define	i_vfs		i_vnode->v_vfsp

struct icb_ext {
	uint16_t	ib_flags;

	/* Direct Entry will go here */
	uint16_t	ib_prn;		/* partition reference number */
	uint32_t	ib_block;	/* block offset into partition */
	uint64_t	ib_offset;	/* offset into the file bytes */
	int32_t		ib_count;	/* No of bytes in current ext */
	uint32_t	ib_marker1;	/* 0xAAAAAAAA */
	uint32_t	ib_marker2;	/* 0xBBBBBBBB */
};


/* ib_flags */
#define	IB_UN_REC	0x1		/* The entry is not allocated */
#define	IB_UN_RE_AL	0x2		/* The entry is not recorded */
					/* and not unallocated */
#define	IB_CON		0x3		/* Continuation entry */

#define	IB_MASK		0x3

#define	IB_ALLOCATED(flags)	\
	(((flags) & IB_MASK) != IB_UN_RE_AL)

#define	EXT_PER_MALLOC	8


struct ud_inode {
	struct ud_inode	*i_forw;
	struct ud_inode	*i_back;
	struct ud_inode	*i_freef;
	struct ud_inode	*i_freeb;

	struct vnode	*i_vnode;	/* vnode associated with this inode */
	struct vnode	*i_devvp;	/* vnode for block I/O */
	struct udf_vfs	*i_udf;		/* incore fs associated with inode */
	krwlock_t	i_rwlock;	/* serializes write/setattr requests */
	krwlock_t	i_contents;	/* protects (most of) inode contents */
	dev_t		i_dev;		/* device where inode resides */
	u_offset_t	i_diroff;	/* last loc for fast name lookup */

	daddr_t		i_icb_lbano;	/* Loc of file icb on disk */
	uint16_t	i_icb_prn;	/* partition reference number */
	kcondvar_t	i_wrcv;		/* sleep/wakeup for write throttle */
	uint32_t	i_flag;
	uint32_t	i_icb_block;

	int16_t		i_astrat;	/* ICB strategy */
	int16_t		i_desc_type;	/* Allocation desc type */
	int32_t		i_ext_count;	/* Number of extents allocated */
	int32_t		i_ext_used;	/* Number of extents used */
	struct icb_ext	*i_ext;		/* array of extents */

	kmutex_t	i_con_lock;
	struct icb_ext	*i_con;
	int32_t		i_con_count;
	int32_t		i_con_used;
	int32_t		i_con_read;

	uint32_t	i_cur_max_ext;
	vtype_t		i_type;		/* File type */
	uint16_t	i_char;		/* File characteristics */
	uint16_t	i_perm;		/* File permissions */

	uid_t		i_uid;		/* File owner's uid */
	gid_t		i_gid;		/* File owner's gid */
	uint32_t	i_nlink;	/* number of links to file */
	uint32_t	i_maxent;	/* Max entries that are recorded */
	u_offset_t	i_size;		/* File size in bytes */
	uint64_t	i_lbr;		/* Logical blocks recorded */
	uint64_t	i_uniqid;	/* from the file entry */

	timespec32_t	i_atime;
	timespec32_t	i_mtime;
	timespec32_t	i_ctime;

	size_t		i_delaylen;	/* delayed writes, units=bytes */
	offset_t	i_delayoff;	/* where we started delaying */
	offset_t	i_nextrio;	/* where to start the next clust */
	uint64_t	i_writes;	/* remaining bytes in write q */
	kmutex_t	i_tlock;	/* protects time fields, i_flag */
	major_t		i_major;
	minor_t		i_minor;

	uint32_t	i_marker1;	/* 0xAAAAAAAA */
	uint32_t	i_seq;		/* sequence number attribute */
	offset_t	i_nextr;	/* next byte read offset (read-ahead) */
	long		i_mapcnt;	/* number of mappings of pages */
	int		*i_map;		/* block list for the file */
	dev_t		i_rdev;		/* INCORE rdev from */
	uint32_t	i_marker2;	/* 0xBBBBBBBB */
	uint32_t	i_data_off;	/* Data offset into embedded file */
	uint32_t	i_max_emb;
	uint32_t	i_marker3;
};


#ifndef	__lint
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_astrat))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_desc_type))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_ext_count))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_ext_used))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_ext))

_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_type))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_char))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_perm))

_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_uid))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_gid))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_nlink))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_size))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_lbr))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_uniqid))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_major))
_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents, ud_inode::i_minor))

_NOTE(MUTEX_PROTECTS_DATA(ud_inode::i_tlock, ud_inode::i_atime))
_NOTE(MUTEX_PROTECTS_DATA(ud_inode::i_tlock, ud_inode::i_mtime))
_NOTE(MUTEX_PROTECTS_DATA(ud_inode::i_tlock, ud_inode::i_ctime))
_NOTE(MUTEX_PROTECTS_DATA(ud_inode::i_tlock, ud_inode::i_delayoff))
_NOTE(MUTEX_PROTECTS_DATA(ud_inode::i_tlock, ud_inode::i_delaylen))
_NOTE(MUTEX_PROTECTS_DATA(ud_inode::i_tlock, ud_inode::i_nextrio))
_NOTE(MUTEX_PROTECTS_DATA(ud_inode::i_tlock, ud_inode::i_writes))
_NOTE(MUTEX_PROTECTS_DATA(ud_inode::i_tlock, ud_inode::i_flag))

_NOTE(RWLOCK_PROTECTS_DATA(ud_inode::i_contents,
		icb_ext::ib_flags icb_ext::ib_prn
		icb_ext::ib_block
		icb_ext::ib_count icb_ext::ib_offset))
#endif


/* i_flag */
#define	IUPD		0x0001		/* file has been modified */
#define	IACC		0x0002		/* inode access time to be updated */
#define	IMOD		0x0004		/* inode has been modified */
#define	ICHG		0x0008		/* inode has been changed */
#define	INOACC		0x0010		/* no access time update in getpage */
#define	IMODTIME	0x0020		/* mod time already set */
#define	IREF		0x0040		/* inode is being referenced */
#define	ISYNC		0x0080		/* do all allocation synchronously */
#define	IMODACC		0x0200		/* only access time changed; */
#define	IATTCHG		0x0400		/* only size/blocks have changed */
#define	IBDWRITE	0x0800		/* the inode has been scheduled for */
					/* write operation asynchrously */

/*
 * i_char
 * Do not change used by MANDLOCK macro in vnode.h
 */
#define	ISUID		VSUID		/* set user id on execution */
#define	ISGID		VSGID		/* set group id on execution */
#define	ISVTX		VSVTX		/* save swapped text even after use */
/*
 * Setuid	--S---------
 * Setgid	-G----------
 * SaveTXT	T-----------
 */

/* i_perm */
#define	IEXEC		0x0400		/* read, write, execute permissions */
#define	IWRITE		0x0800
#define	IREAD		0x1000
#define	IATTR		0x2000
#define	IDELE		0x4000

#define	UP_MASK		0x1CE7
#define	VA2UD_PERM(perm)	\
	(((perm) & 0x7) | (((perm) & 0x38) << 2) | (((perm) & 0x1C0) << 4))
#define	UD2VA_PERM(perm)	\
	(((perm) & 0x7) | (((perm) & 0xE0) >> 2) | (((perm) & 0x1C00) >> 4))

/*
 * Permissions
 * Other	-----------DARWX
 * Group	------DARWX-----
 * Owner	-DARWX----------
 */
#define	UD_DPERM2UPERM(dperm)	((((dperm) >> 4) & 0x1C0) |	\
					(((dperm) >> 2) & 0x38) |	\
					((dperm) & 0x7))
#define	UD_UPERM2DPERM(uperm)	((((uperm) & 0x1C0) << 4) |	\
					(((uperm) & 0x38) << 2) |	\
					((uperm) & 0x7))


/* specify how the inode info is written in ud_syncip() */
#define	I_SYNC	1	/* wait for the inode written to disk */
#define	I_DSYNC	2	/* wait for the inode written to disk */
			/* only if IATTCHG is set */
#define	I_ASYNC	0	/* don't wait for the inode written */


#define	UD_HASH_SZ	512

#if ((UD_HASH_SZ & (UD_HASH_SZ - 1)) == 0)
#define	UD_INOHASH(dev, bno)	(hash2ints((int)dev, (int)bno) & UD_HASH_SZ - 1)
#else
#define	UD_INOHASH(dev, bno)	(hash2ints((int)dev, (int)bno) % UD_HASH_SZ)
#endif

union ihead {
	union	ihead		*ih_head[2];
	struct	ud_inode	*ih_chain[2];
};


#define	IMARK(ip) ud_imark(ip)
#define	ITIMES_NOLOCK(ip) ud_itimes_nolock(ip)

#define	ITIMES(ip) { \
	mutex_enter(&(ip)->i_tlock); \
	ITIMES_NOLOCK(ip); \
	mutex_exit(&(ip)->i_tlock); \
}

#define	ESAME	(-1)		/* trying to rename linked files (special) */

#define	UDF_HOLE	(daddr32_t)-1	/* value used when no block allocated */


extern int32_t ud_trace;
#define	ud_printf(xyz)	\
		if (ud_trace) {	\
			cmn_err(CE_NOTE, xyz);	\
		}

#ifndef	__lint
_NOTE(SCHEME_PROTECTS_DATA("Unshared data",
		buf
		dirent64
		fid
		flock64
		statvfs64
		timespec32
		udf_fid
		uio
		vattr
		vfs
		vnode))

_NOTE(SCHEME_PROTECTS_DATA("Unshared data",
		file_entry
		file_id
		icb_tag
		indirect_entry
		log_vol_int_desc
		long_ad
		lvid_iu
		regid
		short_ad
		tag
		tstamp))

_NOTE(LOCK_ORDER(ud_inode::i_rwlock
		ud_inode::i_contents
		ud_inode::i_tlock))
#endif

/*
 * udf_vfsops.c
 */
void		ud_update_superblock(struct vfs *);


/*
 * udf_vnops.c
 */
int32_t		ud_rdwri(enum uio_rw, int32_t, struct ud_inode *, caddr_t,
			int32_t, offset_t, enum uio_seg, int32_t *,
			struct cred *cr);
int32_t		ud_putapage(struct vnode *, page_t *, u_offset_t *,
			size_t *, int32_t, struct cred *);


/*
 * udf_inode.c
 */
int32_t	ud_iget(struct vfs *, uint16_t, uint32_t, struct ud_inode **,
    struct buf *, struct cred *);
void	ud_iinactive(struct ud_inode *, struct cred *);
void	ud_iupdat(struct ud_inode *, int32_t);
int32_t	ud_itrunc(struct ud_inode *, u_offset_t, int32_t, struct cred *);
int32_t	ud_iaccess(struct ud_inode *, int32_t, struct cred *, int dolock);
int32_t	ud_iflush(struct vfs *);
void	ud_imark(struct ud_inode *);
void	ud_itimes_nolock(struct ud_inode *);
void	ud_delcache(struct ud_inode *);
void	ud_idrop(struct ud_inode *);
void	ud_init_inodes(void);


/*
 * udf_alloc.c
 */
int32_t		ud_alloc_space(struct vfs *, uint16_t, uint32_t,
			uint32_t, uint32_t *, uint32_t *, int32_t, int32_t);
void		ud_free_space(struct vfs *, uint16_t, uint32_t, uint32_t);
int32_t		ud_ialloc(struct ud_inode *, struct ud_inode **,
			struct vattr *, struct cred *);
void		ud_ifree(struct ud_inode *, vtype_t);
int32_t		ud_freesp(struct vnode *, struct flock64 *, int32_t,
			struct cred *);
int32_t		ud_alloc_from_cache(struct udf_vfs *, struct ud_part *,
			uint32_t *);
int32_t		ud_release_cache(struct udf_vfs *);


/*
 * udf_subr.c
 */
void		ud_vfs_add(struct udf_vfs *);
void		ud_vfs_remove(struct udf_vfs *);
daddr_t		ud_xlate_to_daddr(struct udf_vfs *, uint16_t,
			uint32_t, int32_t, uint32_t *);
int32_t		ud_ip_off2bno(struct ud_inode *, uint32_t, uint32_t *);
void		ud_dtime2utime(struct timespec32 *, struct tstamp const *);
void		ud_utime2dtime(struct timespec32 const *, struct tstamp *);
int32_t		ud_syncip(struct ud_inode *, int32_t, int32_t);
void		ud_update(int32_t);
int32_t		ud_fbwrite(struct fbuf *, struct ud_inode *);
void		ud_sbwrite(struct udf_vfs *);
int32_t		ud_sync_indir(struct ud_inode *);
void		ud_update_regid(struct regid *);
int32_t		ud_read_icb_till_off(struct ud_inode *, u_offset_t);
void		ud_make_tag(struct udf_vfs *, struct tag *,
			uint16_t, uint32_t, uint16_t);
int32_t		ud_make_dev_spec_ear(struct dev_spec_ear *, major_t, minor_t);
int32_t		ud_make_ftimes_ear(struct ftimes_ear *,
			int32_t, struct timespec32 *);
int32_t		ud_get_next_fid(struct ud_inode *, struct fbuf **, uint32_t,
			struct file_id **, uint8_t **, uint8_t *);
int32_t		ud_verify_tag_and_desc(struct tag *, uint16_t, uint32_t,
		int32_t, int32_t);
uint16_t	ud_crc(uint8_t *, int32_t);
int32_t		ud_compressunicode(int32_t, int32_t, uint16_t *, uint8_t *);
uint32_t	ud_check_te_unrec(struct udf_vfs *, caddr_t, uint32_t);
int32_t		ud_compress(int32_t, int32_t *, uint8_t *, uint8_t *);
int32_t		ud_uncompress(int32_t, int32_t *, uint8_t *, uint8_t *);
struct buf	*ud_bread(dev_t, daddr_t, long);
int		ud_sticky_remove_access(struct ud_inode *, struct ud_inode *,
			struct cred *);


/*
 * udf_dir.c
 */
int32_t		ud_dirlook(struct ud_inode *,
			char *, struct ud_inode **, struct cred *, int32_t);
int32_t		ud_direnter(struct ud_inode *, char *, enum de_op,
			struct ud_inode *, struct ud_inode *, struct vattr *,
			struct ud_inode **, struct cred *, caller_context_t *);
int32_t		ud_dirremove(struct ud_inode *,
			char *, struct ud_inode *, struct vnode *,
			enum dr_op, struct cred *, caller_context_t *);


/*
 * udf_bmap.c
 */
int32_t		ud_bmap_has_holes(struct ud_inode *);
int32_t		ud_bmap_write(struct ud_inode *, u_offset_t,
			int, int32_t, struct cred *);
int32_t		ud_bmap_read(struct ud_inode *, u_offset_t,
			daddr_t *, int32_t *);
void		ud_insert_new_ext(struct ud_inode *,
			int32_t, struct icb_ext *);
int32_t		ud_alloc_and_make_ext(struct ud_inode *, int32_t);
int32_t		ud_create_new_icb(struct ud_inode *);
void		ud_append_new_ext(struct ud_inode *, uint16_t,
			u_offset_t, uint32_t, uint16_t, uint32_t);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UDF_INODE_H */
