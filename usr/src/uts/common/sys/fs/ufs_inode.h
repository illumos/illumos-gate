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
 * Copyright (c) 1983, 2010, Oracle and/or its affiliates. All rights reserved.
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

#ifndef	_SYS_FS_UFS_INODE_H
#define	_SYS_FS_UFS_INODE_H

#include <sys/isa_defs.h>
#include <sys/fbuf.h>
#include <sys/fdbuffer.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/t_lock.h>
#include <sys/thread.h>
#include <sys/cred.h>
#include <sys/time.h>
#include <sys/types32.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_lockfs.h>
#include <sys/fs/ufs_trans.h>
#include <sys/kstat.h>
#include <sys/fs/ufs_acl.h>
#include <sys/fs/ufs_panic.h>
#include <sys/dnlc.h>

#ifdef _KERNEL
#include <sys/vfs_opreg.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The I node is the focus of all local file activity in UNIX.
 * There is a unique inode allocated for each active file,
 * each current directory, each mounted-on file, each mapping,
 * and the root.  An inode is `named' by its dev/inumber pair.
 * Data in icommon is read in from permanent inode on volume.
 *
 * Each inode has 5 locks associated with it:
 *	i_rwlock:	Serializes ufs_write and ufs_setattr request
 *			and allows ufs_read requests to proceed in parallel.
 *			Serializes reads/updates to directories.
 *	vfs_dqrwlock:	Manages quota sub-system quiescence.  See below.
 *	i_contents:	Protects almost all of the fields in the inode
 *			except for those listed below. When held
 *			in writer mode also protects those fields
 *			listed under i_tlock.
 *	i_tlock:	When i_tlock is held with the i_contents reader
 *			lock the i_atime, i_mtime, i_ctime,
 *			i_delayoff, i_delaylen, i_nextrio, i_writes, i_flag
 *			i_seq, i_writer & i_mapcnt fields are protected.
 *			For more i_flag locking info see below.
 *	ih_lock:	Protects inode hash chain buckets
 *	ifree_lock:	Protects inode freelist
 *
 * Lock ordering:
 *	i_rwlock > i_contents > i_tlock
 *	i_rwlock > vfs_dqrwlock > i_contents(writer) > i_tlock
 *	i_contents > i_tlock
 *	vfs_dqrwlock > i_contents(writer) > i_tlock
 *	ih_lock > i_contents > i_tlock
 *
 * Making major changes to quota sub-system state, while the file
 * system is mounted required the addition of another lock.  The
 * primary lock in the quota sub-system is vfs_dqrwlock in the ufsvfs
 * structure.  This lock is used to manage quota sub-system quiescence
 * for a particular file system. Major changes to quota sub-system
 * state (disabling quotas, enabling quotas, and setting new quota
 * limits) all require the file system to be quiescent and grabbing
 * vfs_dqrwlock as writer accomplishes this.  On the other hand,
 * grabbing vfs_dqrwlock as reader makes the quota sub-system
 * non-quiescent and lets the quota sub-system know that now is not a
 * good time to change major quota sub-system state.  Typically
 * vfs_dqrwlock is grabbed for reading before i_contents is grabbed for
 * writing.  However, there are cases where vfs_dqrwlock is grabbed for
 * reading without a corresponding i_contents write grab because there
 * is no relevant inode.  There are also cases where i_contents is
 * grabbed for writing when a vfs_dqrwlock read grab is not needed
 * because the inode changes do not affect quotas.
 *
 * Unfortunately, performance considerations have required that we be more
 * intelligent about using i_tlock when updating i_flag.  Ideally, we would
 * have simply separated out several of the bits in i_flag into their own
 * ints to avoid problems.  But, instead, we have implemented the following
 * rules:
 *
 *	o You can update any i_flag field while holding the writer-contents,
 *	  or by holding the reader-contents AND holding i_tlock.
 *	  You can only call ITIMES_NOLOCK while holding the writer-contents,
 *	  or by holding the reader-contents AND holding i_tlock.
 *
 *	o For a directory, holding the reader-rw_lock is sufficient for setting
 *	  IACC.
 *
 *	o Races with IREF are avoided by holding the reader contents lock
 *	  and by holding i_tlock in ufs_rmidle, ufs_putapage, and ufs_getpage.
 *	  And by holding the writer-contents in ufs_iinactive.
 *
 *	o The callers are no longer required to handle the calls to ITIMES
 *	  and ITIMES_NOLOCK.  The functions that set the i_flag bits are
 *	  responsible for managing those calls.  The exceptions are the
 *	  bmap routines.
 *
 * SVR4 Extended Fundamental Type (EFT) support:
 * 	The inode structure has been enhanced to support
 *	32-bit user-id, 32-bit group-id, and 32-bit device number.
 *	Standard SVR4 ufs also supports 32-bit mode field.  For the reason
 *	of backward compatibility with the previous ufs disk format,
 *	32-bit mode field is not supported.
 *
 *	The current inode structure is 100% backward compatible with
 *	the previous inode structure if no user-id or group-id exceeds
 *	USHRT_MAX, and no major or minor number of a device number
 *	stored in an inode exceeds 255.
 *
 * Rules for managing i_seq:
 *	o i_seq is locked under the same rules as i_flag
 *	o The i_ctime or i_mtime MUST never change without increasing
 *	  the value of i_seq.
 *	o You may increase the value of i_seq without the timestamps
 *	  changing, this may decrease the callers performance but will
 *	  be functionally correct.
 *	o The common case is when IUPD or ICHG is set, increase i_seq
 *	  and immediately call ITIMES* or ufs_iupdat to create a new timestamp.
 *	o A less common case is the setting of IUPD or ICHG and while still
 *	  holding the correct lock defer the timestamp and i_seq update
 *	  until later, but it must still be done before the lock is released.
 *	  bmap_write is an example of this, where the caller does the update.
 *	o If multiple changes are being made with the timestamps being
 *	  updated only at the end, a single increase of i_seq is allowed.
 *	o If changes are made with IUPD or ICHG being set, but
 *	  the controlling lock is being dropped before the timestamp is
 *	  updated, there is a risk that another thread will also change
 *	  the file, update i_flag, and push just one timestamp update.
 *	  There is also the risk that another thread calls ITIMES or
 *	  ufs_iupdat without setting IUPD|ICHG and thus not changing i_seq,
 *	  this will cause ufs_imark to change the timestamps without changing
 *	  i_seq. If the controlling lock is dropped, ISEQ must be set to
 *	  force i_seq to be increased on next ufs_imark, but i_seq MUST still
 *	  be increased by the original setting thread before its deferred
 *	  call to ITIMES to insure it is increased the correct number of times.
 */

#define	UID_LONG  (o_uid_t)65535
				/* flag value to indicate uid is 32-bit long */
#define	GID_LONG  (o_uid_t)65535
				/* flag value to indicate gid is 32-bit long */

#define	NDADDR	12		/* direct addresses in inode */
#define	NIADDR	3		/* indirect addresses in inode */
#define	FSL_SIZE (NDADDR + NIADDR - 1) * sizeof (daddr32_t)
				/* max fast symbolic name length is 56 */

#define	i_fs	i_ufsvfs->vfs_bufp->b_un.b_fs
#define	i_vfs	i_vnode->v_vfsp

struct 	icommon {
	o_mode_t ic_smode;	/*  0: mode and type of file */
	short	ic_nlink;	/*  2: number of links to file */
	o_uid_t	ic_suid;	/*  4: owner's user id */
	o_gid_t	ic_sgid;	/*  6: owner's group id */
	u_offset_t ic_lsize;	/*  8: number of bytes in file */
#ifdef _KERNEL
	struct timeval32 ic_atime;	/* 16: time last accessed */
	struct timeval32 ic_mtime;	/* 24: time last modified */
	struct timeval32 ic_ctime;	/* 32: last time inode changed */
#else
	time32_t ic_atime;	/* 16: time last accessed */
	int32_t	ic_atspare;
	time32_t ic_mtime;	/* 24: time last modified */
	int32_t	ic_mtspare;
	time32_t ic_ctime;	/* 32: last time inode changed */
	int32_t	ic_ctspare;
#endif
	daddr32_t	ic_db[NDADDR];	/* 40: disk block addresses */
	daddr32_t	ic_ib[NIADDR];	/* 88: indirect blocks */
	int32_t	ic_flags;	/* 100: cflags */
	int32_t	ic_blocks;	/* 104: 512 byte blocks actually held */
	int32_t	ic_gen;		/* 108: generation number */
	int32_t	ic_shadow;	/* 112: shadow inode */
	uid_t	ic_uid;		/* 116: long EFT version of uid */
	gid_t	ic_gid;		/* 120: long EFT version of gid */
	uint32_t ic_oeftflag;	/* 124: extended attr directory ino, 0 = none */
};

/*
 * Large directories can be cached. Directory caching can take the following
 * states:
 */
typedef enum {
	CD_DISABLED_NOMEM = -2,
	CD_DISABLED_TOOBIG,
	CD_DISABLED,
	CD_ENABLED
} cachedir_t;

/*
 * Large Files: Note we use the inline functions load_double, store_double
 * to load and store the long long values of i_size. Therefore the
 * address of i_size must be eight byte aligned. Kmem_alloc of incore
 * inode structure makes sure that the structure is 8-byte aligned.
 * XX64 - reorder this structure?
 */
typedef struct inode {
	struct	inode *i_chain[2];	/* must be first */
	struct inode *i_freef;	/* free list forward - must be before i_ic */
	struct inode *i_freeb;	/* free list back - must be before i_ic */
	struct 	icommon	i_ic;	/* Must be here */
	struct	vnode *i_vnode;	/* vnode associated with this inode */
	struct	vnode *i_devvp;	/* vnode for block I/O */
	dev_t	i_dev;		/* device where inode resides */
	ino_t	i_number;	/* i number, 1-to-1 with device address */
	off_t	i_diroff;	/* offset in dir, where we found last entry */
				/* just a hint - no locking needed */
	struct ufsvfs *i_ufsvfs; /* incore fs associated with inode */
	struct	dquot *i_dquot;	/* quota structure controlling this file */
	krwlock_t i_rwlock;	/* serializes write/setattr requests */
	krwlock_t i_contents;	/* protects (most of) inode contents */
	kmutex_t i_tlock;	/* protects time fields, i_flag */
	offset_t i_nextr;	/*					*/
				/* next byte read offset (read-ahead)	*/
				/*   No lock required			*/
				/*					*/
	uint_t	i_flag;		/* inode flags */
	uint_t	i_seq;		/* modification sequence number */
	cachedir_t i_cachedir;	/* Cache this directory on next lookup */
				/* - no locking needed  */
	long	i_mapcnt;	/* mappings to file pages */
	int	*i_map;		/* block list for the corresponding file */
	dev_t	i_rdev;		/* INCORE rdev from i_oldrdev by ufs_iget */
	size_t	i_delaylen;	/* delayed writes, units=bytes */
	offset_t i_delayoff;	/* where we started delaying */
	offset_t i_nextrio;	/* where to start the next clust */
	long	i_writes;	/* number of outstanding bytes in write q */
	kcondvar_t i_wrcv;	/* sleep/wakeup for write throttle */
	offset_t i_doff;	/* dinode byte offset in file system */
	si_t *i_ufs_acl;	/* pointer to acl entry */
	dcanchor_t i_danchor;	/* directory cache anchor */
	kthread_t *i_writer;	/* thread which is in window in wrip() */
} inode_t;

struct dinode {
	union {
		struct	icommon di_icom;
		char	di_size[128];
	} di_un;
};

#define	i_mode		i_ic.ic_smode
#define	i_nlink		i_ic.ic_nlink
#define	i_uid		i_ic.ic_uid
#define	i_gid		i_ic.ic_gid
#define	i_smode		i_ic.ic_smode
#define	i_suid		i_ic.ic_suid
#define	i_sgid		i_ic.ic_sgid

#define	i_size		i_ic.ic_lsize
#define	i_db		i_ic.ic_db
#define	i_ib		i_ic.ic_ib

#define	i_atime		i_ic.ic_atime
#define	i_mtime		i_ic.ic_mtime
#define	i_ctime		i_ic.ic_ctime

#define	i_shadow	i_ic.ic_shadow
#define	i_oeftflag	i_ic.ic_oeftflag
#define	i_blocks	i_ic.ic_blocks
#define	i_cflags	i_ic.ic_flags
#ifdef _LITTLE_ENDIAN
/*
 * Originally done on x86, but carried on to all other little
 * architectures, which provides for file system compatibility.
 */
#define	i_ordev		i_ic.ic_db[1]	/* USL SVR4 compatibility */
#else
#define	i_ordev		i_ic.ic_db[0]	/* was i_oldrdev */
#endif
#define	i_gen		i_ic.ic_gen
#define	i_forw		i_chain[0]
#define	i_back		i_chain[1]

/* EFT transition aids - obsolete */
#define	oEFT_MAGIC	0x90909090
#define	di_oeftflag	di_ic.ic_oeftflag

#define	di_ic		di_un.di_icom
#define	di_mode		di_ic.ic_smode
#define	di_nlink	di_ic.ic_nlink
#define	di_uid		di_ic.ic_uid
#define	di_gid		di_ic.ic_gid
#define	di_smode	di_ic.ic_smode
#define	di_suid		di_ic.ic_suid
#define	di_sgid		di_ic.ic_sgid

#define	di_size		di_ic.ic_lsize
#define	di_db		di_ic.ic_db
#define	di_ib		di_ic.ic_ib

#define	di_atime	di_ic.ic_atime
#define	di_mtime	di_ic.ic_mtime
#define	di_ctime	di_ic.ic_ctime
#define	di_cflags	di_ic.ic_flags

#ifdef _LITTLE_ENDIAN
#define	di_ordev	di_ic.ic_db[1]
#else
#define	di_ordev	di_ic.ic_db[0]
#endif
#define	di_shadow	di_ic.ic_shadow
#define	di_blocks	di_ic.ic_blocks
#define	di_gen		di_ic.ic_gen

/* flags */
#define	IUPD		0x0001		/* file has been modified */
#define	IACC		0x0002		/* inode access time to be updated */
#define	IMOD		0x0004		/* inode has been modified */
#define	ICHG		0x0008		/* inode has been changed */
#define	INOACC		0x0010		/* no access time update in getpage */
#define	IMODTIME	0x0020		/* mod time already set */
#define	IREF		0x0040		/* inode is being referenced */
#define	ISYNC		0x0080		/* do all allocation synchronously */
#define	IFASTSYMLNK	0x0100		/* fast symbolic link */
#define	IMODACC		0x0200		/* only access time changed; */
					/*   filesystem won't become active */
#define	IATTCHG		0x0400		/* only size/blocks have changed */
#define	IBDWRITE	0x0800		/* the inode has been scheduled for */
					/* write operation asynchronously */
#define	ISTALE		0x1000		/* inode couldn't be read from disk */
#define	IDEL		0x2000		/* inode is being deleted */
#define	IDIRECTIO	0x4000		/* attempt directio */
#define	ISEQ		0x8000		/* deferred i_seq increase */
#define	IJUNKIQ		0x10000		/* on junk idle queue */
#define	IQUIET		0x20000		/* No file system full messages */

/* cflags */
#define	IXATTR		0x0001		/* extended attribute */
#define	IFALLOCATE	0x0002		/* fallocate'd file */
#define	ICOMPRESS	0x0004		/* compressed for dcfs - see */
					/*   `ufs_ioctl()`_FIO_COMPRESSED */

/* modes */
#define	IFMT		0170000		/* type of file */
#define	IFIFO		0010000		/* named pipe (fifo) */
#define	IFCHR		0020000		/* character special */
#define	IFDIR		0040000		/* directory */
#define	IFBLK		0060000		/* block special */
#define	IFREG		0100000		/* regular */
#define	IFLNK		0120000		/* symbolic link */
#define	IFSHAD		0130000		/* shadow indode */
#define	IFSOCK		0140000		/* socket */
#define	IFATTRDIR	0160000		/* Attribute directory */

#define	ISUID		04000		/* set user id on execution */
#define	ISGID		02000		/* set group id on execution */
#define	ISVTX		01000		/* save swapped text even after use */
#define	IREAD		0400		/* read, write, execute permissions */
#define	IWRITE		0200
#define	IEXEC		0100

/* specify how the inode info is written in ufs_syncip() */
#define	I_SYNC		1		/* wait for the inode written to disk */
#define	I_DSYNC		2		/* wait for the inode written to disk */
					/* only if IATTCHG is set */
#define	I_ASYNC		0		/* don't wait for the inode written */

/* flags passed to ufs_itrunc(), indirtrunc(), and free() */
#define	I_FREE	0x00000001		/* inode is being freed */
#define	I_DIR	0x00000002		/* inode is a directory */
#define	I_IBLK	0x00000004		/* indirect block */
#define	I_CHEAP	0x00000008		/* cheap free */
#define	I_SHAD	0x00000010		/* inode is a shadow inode */
#define	I_QUOTA	0x00000020		/* quota file */
#define	I_NOCANCEL	0x40		/* Don't cancel these fragments */
#define	I_ACCT	0x00000080		/* Update ufsvfs' unreclaimed_blocks */

/*
 * If ufs_dircheckforname() fails to find an entry with the given name,
 * this "slot" structure holds state for ufs_direnter_*() as to where
 * there is space to put an entry with that name.
 * If ufs_dircheckforname() finds an entry with the given name, this structure
 * holds state for ufs_dirrename() and ufs_dirremove() as to where the
 * entry is. "status" indicates what ufs_dircheckforname() found:
 *      NONE            name not found, large enough free slot not found,
 *      FOUND           name not found, large enough free slot found
 *      EXIST           name found
 * If ufs_dircheckforname() fails due to an error, this structure is not
 * filled in.
 *
 * After ufs_dircheckforname() succeeds the values are:
 *      status  offset          size            fbp, ep
 *      ------  ------          ----            -------
 *      NONE    end of dir      needed          not valid
 *      FOUND   start of entry  of ent          both valid if fbp != NULL
 *      EXIST   start of entry  of prev ent     valid
 *
 * "endoff" is set to 0 if the an entry with the given name is found, or if no
 * free slot could be found or made; this means that the directory should not
 * be truncated.  If the entry was found, the search terminates so
 * ufs_dircheckforname() didn't find out where the last valid entry in the
 * directory was, so it doesn't know where to cut the directory off; if no free
 * slot could be found or made, the directory has to be extended to make room
 * for the new entry, so there's nothing to cut off.
 * Otherwise, "endoff" is set to the larger of the offset of the last
 * non-empty entry in the directory, or the offset at which the new entry will
 * be placed, whichever is larger.  This is used by ufs_diraddentry(); if a new
 * entry is to be added to the directory, any complete directory blocks at the
 * end of the directory that contain no non-empty entries are lopped off the
 * end, thus shrinking the directory dynamically.
 */
typedef enum {NONE, FOUND, EXIST} slotstat_t;
struct ufs_slot {
	struct	direct *ep;	/* pointer to slot */
	struct	fbuf *fbp;	/* dir buf where slot is */
	off_t	offset;		/* offset of area with free space */
	off_t	endoff;		/* last useful location found in search */
	slotstat_t status;	/* status of slot */
	int	size;		/* size of area at slotoffset */
	int	cached;		/* cached directory */
};

/*
 * Statistics on inodes
 * Not protected by locks
 */
struct instats {
	kstat_named_t in_size;		/* current cache size */
	kstat_named_t in_maxsize;	/* maximum cache size */
	kstat_named_t in_hits;		/* cache hits */
	kstat_named_t in_misses;	/* cache misses */
	kstat_named_t in_malloc;	/* kmem_alloce'd */
	kstat_named_t in_mfree;		/* kmem_free'd */
	kstat_named_t in_maxreached;	/* Largest size reached by cache */
	kstat_named_t in_frfront;	/* # put at front of freelist */
	kstat_named_t in_frback;	/* # put at back of freelist */
	kstat_named_t in_qfree;		/* q's to delete thread */
	kstat_named_t in_scan;		/* # inodes scanned */
	kstat_named_t in_tidles;	/* # inodes idled by idle thread */
	kstat_named_t in_lidles;	/* # inodes idled by ufs_lookup */
	kstat_named_t in_vidles;	/* # inodes idled by ufs_vget */
	kstat_named_t in_kcalloc;	/* # inodes kmem_cache_alloced */
	kstat_named_t in_kcfree;	/* # inodes kmem_cache_freed */
	kstat_named_t in_poc;		/* # push-on-close's */
};

#ifdef _KERNEL

/*
 * Extended attributes
 */

#define	XATTR_DIR_NAME	"/@/"
extern int	ufs_ninode;		/* high-water mark for inode cache */

extern struct vnodeops *ufs_vnodeops;	/* vnode operations for ufs */
extern const struct fs_operation_def ufs_vnodeops_template[];

/*
 * Convert between inode pointers and vnode pointers
 */
#define	VTOI(VP)	((struct inode *)(VP)->v_data)
#define	ITOV(IP)	((struct vnode *)(IP)->i_vnode)

/*
 * convert to fs
 */
#define	ITOF(IP)	((struct fs *)(IP)->i_fs)

/*
 * Convert between vnode types and inode formats
 */
extern enum vtype	iftovt_tab[];

#ifdef notneeded

/* Look at sys/mode.h and os/vnode.c */

extern int		vttoif_tab[];

#endif

/*
 * Mark an inode with the current (unique) timestamp.
 * (Note that UFS's concept of time only keeps 32 bits of seconds
 * in the on-disk format).
 */
struct timeval32 iuniqtime;
extern kmutex_t ufs_iuniqtime_lock;

#define	ITIMES_NOLOCK(ip) ufs_itimes_nolock(ip)

#define	ITIMES(ip) { \
	mutex_enter(&(ip)->i_tlock); \
	ITIMES_NOLOCK(ip); \
	mutex_exit(&(ip)->i_tlock); \
}

/*
 * The following interfaces are used to do atomic loads and stores
 * of an inode's i_size, which is a long long data type.
 *
 * For LP64, we just to a load or a store - atomicity and alignment
 * are 8-byte guaranteed.  For x86 there are no such instructions,
 * so we grab i_contents as reader to get the size; we already hold
 * it as writer when we're setting the size.
 */

#ifdef _LP64

#define	UFS_GET_ISIZE(resultp, ip)	*(resultp) = (ip)->i_size
#define	UFS_SET_ISIZE(value, ip)	(ip)->i_size = (value)

#else	/* _LP64 */

#define	UFS_GET_ISIZE(resultp, ip)				\
	{							\
		rw_enter(&(ip)->i_contents, RW_READER);		\
		*(resultp) = (ip)->i_size;			\
		rw_exit(&(ip)->i_contents);			\
	}
#define	UFS_SET_ISIZE(value, ip)				\
	{							\
		ASSERT(RW_WRITE_HELD(&(ip)->i_contents));	\
		(ip)->i_size = (value);				\
	}

#endif	/* _LP64 */

/*
 * Allocate the specified block in the inode
 * and make sure any in-core pages are initialized.
 */
#define	BMAPALLOC(ip, off, size, cr) \
	bmap_write((ip), (u_offset_t)(off), (size), BI_NORMAL, NULL, cr)

#define	ESAME	(-1)		/* trying to rename linked files (special) */

#define	UFS_HOLE	(daddr32_t)-1	/* value used when no block allocated */

/*
 * enums
 */

/* direnter ops */
enum de_op { DE_CREATE, DE_MKDIR, DE_LINK, DE_RENAME, DE_SYMLINK, DE_ATTRDIR};

/* dirremove ops */
enum dr_op { DR_REMOVE, DR_RMDIR, DR_RENAME };

/*
 * block initialization type for bmap_write
 *
 * BI_NORMAL - allocate and zero fill pages in memory
 * BI_ALLOC_ONLY - only allocate the block, do not zero out pages in mem
 * BI_FALLOCATE - allocate only, do not zero out pages, and store as negative
 *                block number in inode block list
 */
enum bi_type { BI_NORMAL, BI_ALLOC_ONLY, BI_FALLOCATE };

/*
 * This overlays the fid structure (see vfs.h)
 *
 * LP64 note: we use int32_t instead of ino_t since UFS does not use
 * inode numbers larger than 32-bits and ufid's are passed to NFS
 * which expects them to not grow in size beyond 10 bytes (12 including
 * the length).
 */
struct ufid {
	ushort_t ufid_len;
	ushort_t ufid_flags;
	int32_t	ufid_ino;
	int32_t	ufid_gen;
};

/*
 * each ufs thread (see ufs_thread.c) is managed by this struct
 */
struct ufs_q {
	union uq_head {
		void		*_uq_generic;	/* first entry on q */
		struct inode	*_uq_i;
		ufs_failure_t	*_uq_uf;
	} _uq_head;
	int		uq_ne;		/* # of entries/failures found */
	int		uq_lowat;	/* thread runs when ne == lowat */
	int		uq_hiwat;	/* synchronous idle if ne >= hiwat */
	ushort_t	uq_flags;	/* flags (see below) */
	kcondvar_t	uq_cv;		/* for sleep/wakeup */
	kthread_id_t	uq_threadp;	/* thread managing this q */
	kmutex_t	uq_mutex;	/* protects this struct */
};

#define	uq_head		_uq_head._uq_generic
#define	uq_ihead	_uq_head._uq_i
#define	uq_ufhead	_uq_head._uq_uf

/*
 * uq_flags
 */
#define	UQ_EXIT		(0x0001)	/* q server exits at its convenience */
#define	UQ_WAIT		(0x0002)	/* thread is waiting on q server */
#define	UQ_SUSPEND	(0x0004)	/* request for suspension */
#define	UQ_SUSPENDED	(0x0008)	/* thread has suspended itself */

/*
 * When logging is enabled, statvfs must account for blocks and files that
 * may be on the delete queue.  Protected by ufsvfsp->vfs_delete.uq_mutex
 */
struct ufs_delq_info {
	u_offset_t	delq_unreclaimed_blocks;
	ulong_t		delq_unreclaimed_files;
};


/*
 * global idle queues
 * The queues are sized dynamically in proportion to ufs_ninode
 * which, unless overridden, scales with the amount of memory.
 * The idle queue is halved whenever it hits the low water mark
 * (1/4 of ufs_ninode), but can burst to sizes much larger. The number
 * of hash queues is currently maintained to give on average IQHASHQLEN
 * entries when the idle queue is at the low water mark.
 * Note, we do not need to search along the hash queues, but use them
 * in order to batch together geographically local inodes to allow
 * their updates (via the log or buffer cache) to require less disk seeks.
 * This gives an incredible performance boost for logging and a boost for
 * non logging file systems.
 */
typedef struct {
	inode_t *i_chain[2];	/* must match inode_t, but unused */
	inode_t *i_freef;	/* must match inode_t, idle list forward */
	inode_t *i_freeb;	/* must match inode_t, idle list back  */
} iqhead_t;

extern struct ufs_q ufs_idle_q;		/* used by global ufs idle thread */
extern iqhead_t *ufs_junk_iq;		/* junk idle queues */
extern iqhead_t *ufs_useful_iq;		/* useful idle queues */
extern int ufs_njunk_iq;		/* number of entries in junk iq */
extern int ufs_nuseful_iq;		/* number of entries in useful iq */
extern int ufs_niqhash;			/* number of iq hash qs - power of 2 */
extern int ufs_iqhashmask;		/* iq hash mask = ufs_niqhash - 1 */

#define	IQHASHQLEN 32			/* see comments above */
#define	INOCGSHIFT 7			/* 128 inodes per cylinder group */
#define	IQHASH(ip) (((ip)->i_number >> INOCGSHIFT) & ufs_iqhashmask)
#define	IQNEXT(i) ((i) + 1) & ufs_iqhashmask /* next idle queue */

extern struct ufs_q	ufs_hlock;	/* used by global ufs hlock thread */

/*
 * vfs_lfflags flags
 */
#define	UFS_LARGEFILES	((ushort_t)0x1)	/* set if mount allows largefiles */

/*
 * vfs_dfritime flags
 */
#define	UFS_DFRATIME	0x1		/* deferred access time */

/*
 * UFS VFS private data.
 *
 * UFS file system instances may be linked on several lists.
 *
 * -	The vfs_next field chains together every extant ufs instance; this
 *	list is rooted at ufs_instances and should be used in preference to
 *	the overall vfs list (which is properly the province of the generic
 *	file system code, not of file system implementations).  This same list
 *	link is used during forcible unmounts to chain together instances that
 *	can't yet be completely dismantled,
 *
 * -	The vfs_wnext field is used within ufs_update to form a work list of
 *	UFS instances to be synced out.
 */
typedef struct ufsvfs {
	struct vfs	*vfs_vfs;	/* back link			*/
	struct ufsvfs	*vfs_next;	/* instance list link		*/
	struct ufsvfs	*vfs_wnext;	/* work list link		*/
	struct vnode	*vfs_root;	/* root vnode			*/
	struct buf	*vfs_bufp;	/* buffer containing superblock */
	struct vnode	*vfs_devvp;	/* block device vnode		*/
	ushort_t	vfs_lfflags;	/* Large files (set by mount)   */
	ushort_t	vfs_qflags;	/* QUOTA: filesystem flags	*/
	struct inode	*vfs_qinod;	/* QUOTA: pointer to quota file */
	uint_t		vfs_btimelimit;	/* QUOTA: block time limit	*/
	uint_t		vfs_ftimelimit;	/* QUOTA: file time limit	*/
	krwlock_t	vfs_dqrwlock;	/* QUOTA: protects quota fields */
	/*
	 * some fs local threads
	 */
	struct ufs_q	vfs_delete;	/* delayed inode delete */
	struct ufs_q	vfs_reclaim;	/* reclaim open, deleted files */

	/*
	 * This is copied from the super block at mount time.
	 */
	int		vfs_nrpos;	/* # rotational positions */
	/*
	 * This lock protects cg's and super block pointed at by
	 * vfs_bufp->b_fs.  Locks contents of fs and cg's and contents
	 * of vfs_dio.
	 */
	kmutex_t	vfs_lock;
	struct ulockfs	vfs_ulockfs;	/* ufs lockfs support */
	uint_t		vfs_dio;	/* delayed io (_FIODIO) */
	uint_t		vfs_nointr;	/* disallow lockfs interrupts */
	uint_t		vfs_nosetsec;	/* disallow ufs_setsecattr */
	uint_t		vfs_syncdir;	/* synchronous local directory ops */
	uint_t		vfs_dontblock;	/* don't block on forced umount */

	/*
	 * trans (logging ufs) stuff
	 */
	uint_t		vfs_domatamap;	/* set if matamap enabled */
	ulong_t		vfs_maxacl;	/* transaction stuff - max acl size */
	ulong_t		vfs_dirsize;	/* logspace for directory creation */
	ulong_t		vfs_avgbfree;	/* average free blks in cg (blkpref) */
	/*
	 * Some useful constants
	 */
	int	vfs_nindirshift;	/* calc. from fs_nindir */
	int	vfs_nindiroffset;	/* calc. from fs_ninidr */
	int	vfs_ioclustsz;		/* bytes in read/write cluster */
	int	vfs_iotransz;		/* max device i/o transfer size  */

	vfs_ufsfx_t	vfs_fsfx;	/* lock/fix-on-panic support */
	/*
	 * More useful constants
	 */
	int	vfs_minfrags;		/* calc. from fs_minfree */
	/*
	 * Force DirectIO on all files
	 */
	uint_t	vfs_forcedirectio;
	/*
	 * Deferred inode time related fields
	 */
	clock_t		vfs_iotstamp;	/* last I/O timestamp */
	uint_t		vfs_dfritime;	/* deferred inode time flags */
	/*
	 * Some more useful info
	 */
	dev_t		vfs_dev;	/* device mounted from */
	struct ml_unit	*vfs_log;	/* pointer to embedded log struct */
	uint_t		vfs_noatime;    /* disable inode atime updates */
	/*
	 * snapshot stuff
	 */
	void		*vfs_snapshot;	/* snapshot handle */
	/*
	 *  Controls logging "file system full" messages to messages file
	 */
	clock_t		vfs_lastwhinetime;

	int 		vfs_nolog_si;	/* not logging summary info */
	int		vfs_validfs;	/* indicates mounted fs */

	/*
	 * Additional information about vfs_delete above
	 */
	struct ufs_delq_info vfs_delete_info; /* what's on the delete queue */
} ufsvfs_t;

#define	vfs_fs	vfs_bufp->b_un.b_fs

/*
 * values for vfs_validfs
 */
#define	UT_UNMOUNTED	0
#define	UT_MOUNTED	1
#define	UT_HLOCKING	2

/* inohsz is guaranteed to be a power of 2 */
#define	INOHASH(ino)	(((int)ino) & (inohsz - 1))

#define	ISFALLOCBLK(ip, bn)	\
	(((bn) < 0) && ((bn) % ip->i_fs->fs_frag == 0) && \
	((ip)->i_cflags & IFALLOCATE && (bn) != UFS_HOLE))

union ihead {
	union	ihead	*ih_head[2];
	struct	inode	*ih_chain[2];
};

extern	union	ihead	*ihead;
extern  kmutex_t	*ih_lock;
extern  int	*ih_ne;
extern	int	inohsz;

extern	clock_t	ufs_iowait;

#endif /* _KERNEL */

/*
 * ufs function prototypes
 */
#if defined(_KERNEL) && !defined(_BOOT)

extern	void	ufs_iinit(void);
extern	int	ufs_iget(struct vfs *, ino_t, struct inode **, cred_t *);
extern	int	ufs_iget_alloced(struct vfs *, ino_t, struct inode **,
    cred_t *);
extern	void	ufs_reset_vnode(vnode_t *);
extern	void	ufs_iinactive(struct inode *);
extern	void	ufs_iupdat(struct inode *, int);
extern	int	ufs_rmidle(struct inode *);
extern	int	ufs_itrunc(struct inode *, u_offset_t, int, cred_t *);
extern	int	ufs_iaccess(struct inode *, int, cred_t *, int);
extern  int	rdip(struct inode *, struct uio *, int, struct cred *);
extern  int	wrip(struct inode *, struct uio *, int, struct cred *);

extern void	ufs_imark(struct inode *);
extern void	ufs_itimes_nolock(struct inode *);

extern	int	ufs_diraccess(struct inode *, int, struct cred *);
extern	int	ufs_dirlook(struct inode *, char *, struct inode **,
    cred_t *, int, int);
extern	int	ufs_direnter_cm(struct inode *, char *, enum de_op,
    struct vattr *, struct inode **, cred_t *, int);
extern	int	ufs_direnter_lr(struct inode *, char *, enum de_op,
    struct inode *, struct inode *, cred_t *);
extern	int	ufs_dircheckpath(ino_t, struct inode *, struct inode *,
    struct cred *);
extern	int	ufs_dirmakeinode(struct inode *, struct inode **,
    struct vattr *, enum de_op, cred_t *);
extern	int	ufs_dirremove(struct inode *, char *, struct inode *,
    vnode_t *, enum dr_op, cred_t *);
extern  int	ufs_dircheckforname(struct inode *, char *, int,
    struct ufs_slot *, struct inode **, struct cred *, int);
extern	int	ufs_xattrdirempty(struct inode *, ino_t, cred_t *);
extern	int	blkatoff(struct inode *, off_t, char **, struct fbuf **);

extern	void	sbupdate(struct vfs *);

extern	int	ufs_ialloc(struct inode *, ino_t, mode_t, struct inode **,
    cred_t *);
extern	void	ufs_ifree(struct inode *, ino_t, mode_t);
extern	void	free(struct inode *, daddr_t, off_t, int);
extern	int	alloc(struct inode *, daddr_t, int, daddr_t *, cred_t *);
extern	int	realloccg(struct inode *, daddr_t, daddr_t, int, int,
    daddr_t *, cred_t *);
extern	int	ufs_allocsp(struct vnode *, struct flock64 *, cred_t *);
extern	int	ufs_freesp(struct vnode *, struct flock64 *, int, cred_t *);
extern	ino_t	dirpref(inode_t *);
extern	daddr_t	blkpref(struct inode *, daddr_t, int, daddr32_t *);
extern	daddr_t	contigpref(ufsvfs_t *, size_t, size_t);

extern	int	ufs_rdwri(enum uio_rw, int, struct inode *, caddr_t, ssize_t,
	offset_t, enum uio_seg, int *, cred_t *);

extern	int	bmap_read(struct inode *, u_offset_t, daddr_t *, int *);
extern	int	bmap_write(struct inode *, u_offset_t, int, enum bi_type,
    daddr_t *, struct cred *);
extern	int	bmap_has_holes(struct inode *);
extern	int	bmap_find(struct inode *, boolean_t, u_offset_t *);
extern	int	bmap_set_bn(struct vnode *, u_offset_t, daddr32_t);

extern	void	ufs_vfs_add(struct ufsvfs *);
extern	void	ufs_vfs_remove(struct ufsvfs *);

extern	void	ufs_sbwrite(struct ufsvfs *);
extern	void	ufs_update(int);
extern	int	ufs_getsummaryinfo(dev_t, struct ufsvfs *, struct fs *);
extern	int	ufs_putsummaryinfo(dev_t, struct ufsvfs *, struct fs *);
extern	int	ufs_syncip(struct inode *, int, int, top_t);
extern	int	ufs_sync_indir(struct inode *);
extern	int	ufs_indirblk_sync(struct inode *, offset_t);
extern	int	ufs_badblock(struct inode *, daddr_t);
extern	int	ufs_indir_badblock(struct inode *, daddr32_t *);
extern	void	ufs_notclean(struct ufsvfs *);
extern	void	ufs_checkclean(struct vfs *);
extern	int	isblock(struct fs *, uchar_t *, daddr_t);
extern	void	setblock(struct fs *, uchar_t *, daddr_t);
extern	void	clrblock(struct fs *, uchar_t *, daddr_t);
extern	int	isclrblock(struct fs *, uchar_t *, daddr_t);
extern	void	fragacct(struct fs *, int, int32_t *, int);
extern	int	skpc(char, uint_t, char *);
extern	int	ufs_fbwrite(struct fbuf *, struct inode *);
extern	int	ufs_fbiwrite(struct fbuf *, struct inode *, daddr_t, long);
extern	int	ufs_putapage(struct vnode *, struct page *, u_offset_t *,
				size_t *, int, struct cred *);
extern inode_t	*ufs_alloc_inode(ufsvfs_t *, ino_t);
extern void	ufs_free_inode(inode_t *);

/*
 * special stuff
 */
extern	void	ufs_setreclaim(struct inode *);
extern	int	ufs_scan_inodes(int, int (*)(struct inode *, void *), void *,
				struct ufsvfs *);
extern	int	ufs_sync_inode(struct inode *, void *);
extern	int	ufs_sticky_remove_access(struct inode *, struct inode *,
    struct cred *);
/*
 * quota
 */
extern	int	chkiq(struct ufsvfs *, int, struct inode *, uid_t, int,
			struct cred *, char **errp, size_t *lenp);

/*
 * ufs thread stuff
 */
extern	void	ufs_thread_delete(struct vfs *);
extern	void	ufs_delete_drain(struct vfs *, int, int);
extern	void	ufs_delete(struct ufsvfs *, struct inode *, int);
extern	void	ufs_inode_cache_reclaim(void *);
extern	void	ufs_idle_drain(struct vfs *);
extern	void	ufs_idle_some(int);
extern	void	ufs_thread_idle(void);
extern	void	ufs_thread_reclaim(struct vfs *);
extern	void	ufs_thread_init(struct ufs_q *, int);
extern	void	ufs_thread_start(struct ufs_q *, void (*)(), struct vfs *);
extern	void	ufs_thread_exit(struct ufs_q *);
extern	void	ufs_thread_suspend(struct ufs_q *);
extern	void	ufs_thread_continue(struct ufs_q *);
extern	void	ufs_thread_hlock(void *);
extern	void	ufs_delete_init(struct ufsvfs *, int);
extern	void	ufs_delete_adjust_stats(struct ufsvfs *, struct statvfs64 *);
extern	void	ufs_delete_drain_wait(struct ufsvfs *, int);

/*
 * ufs lockfs stuff
 */
struct seg;
extern int ufs_reconcile_fs(struct vfs *, struct ufsvfs *, int);
extern int ufs_quiesce(struct ulockfs *);
extern int ufs_flush(struct vfs *);
extern int ufs_fiolfs(struct vnode *, struct lockfs *, int);
extern int ufs__fiolfs(struct vnode *, struct lockfs *, int, int);
extern int ufs_fiolfss(struct vnode *, struct lockfs *);
extern int ufs_fioffs(struct vnode *, char *, struct cred *);
extern int ufs_check_lockfs(struct ufsvfs *, struct ulockfs *, ulong_t);
extern int ufs_lockfs_begin(struct ufsvfs *, struct ulockfs **, ulong_t);
extern int ufs_lockfs_trybegin(struct ufsvfs *, struct ulockfs **, ulong_t);
extern int ufs_lockfs_begin_getpage(struct ufsvfs *, struct ulockfs **,
		struct seg *, int, uint_t *);
extern void ufs_lockfs_end(struct ulockfs *);
/*
 * ufs acl stuff
 */
extern int ufs_si_inherit(struct inode *, struct inode *, o_mode_t, cred_t *);
extern void si_cache_init(void);
extern int ufs_si_load(struct inode *, cred_t *);
extern void ufs_si_del(struct inode *);
extern int ufs_acl_access(struct inode *, int, cred_t *);
extern void ufs_si_cache_flush(dev_t);
extern int ufs_si_free(si_t *, struct vfs *, cred_t *);
extern int ufs_acl_setattr(struct inode *, struct vattr *, cred_t *);
extern int ufs_acl_get(struct inode *, vsecattr_t *, int, cred_t *);
extern int ufs_acl_set(struct inode *, vsecattr_t *, int, cred_t *);
/*
 * ufs directio stuff
 */
extern void ufs_directio_init();
extern int ufs_directio_write(struct inode *, uio_t *, int, int, cred_t *,
    int *);
extern int ufs_directio_read(struct inode *, uio_t *, cred_t *, int *);
#define	DIRECTIO_FAILURE	(0)
#define	DIRECTIO_SUCCESS	(1)

/*
 * ufs extensions for PXFS
 */

int ufs_rdwr_data(vnode_t *vp, u_offset_t offset, size_t len, fdbuffer_t *fdb,
    int flags, cred_t *cr);
int ufs_alloc_data(vnode_t *vp, u_offset_t offset, size_t *len, fdbuffer_t *fdb,
    int flags, cred_t *cr);

/*
 * prototypes to support the forced unmount
 */

void ufs_freeze(struct ulockfs *, struct lockfs *);
int ufs_thaw(struct vfs *, struct ufsvfs *, struct ulockfs *);

/*
 * extended attributes
 */

int ufs_xattrmkdir(inode_t *, inode_t **, int, struct cred *);
int ufs_xattr_getattrdir(vnode_t *, inode_t **, int, struct cred *);
void ufs_unhook_shadow(inode_t *, inode_t *);

#endif	/* defined(_KERNEL) && !defined(_BOOT) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_INODE_H */
