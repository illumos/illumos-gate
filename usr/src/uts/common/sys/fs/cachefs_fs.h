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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FS_CACHEFS_FS_H
#define	_SYS_FS_CACHEFS_FS_H

#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/types32.h>
#include <sys/t_lock.h>
#include <sys/thread.h>
#include <sys/kmem.h>
#include <sys/inttypes.h>
#include <sys/time_impl.h>
#include <sys/systm.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CFSDEBUG
#define	CFSDEBUG_ALL		0xffffffff
#define	CFSDEBUG_NONE		0x0
#define	CFSDEBUG_GENERAL	0x1
#define	CFSDEBUG_SUBR		0x2
#define	CFSDEBUG_CNODE		0x4
#define	CFSDEBUG_DIR		0x8
#define	CFSDEBUG_STRICT		0x10
#define	CFSDEBUG_VOPS		0x20
#define	CFSDEBUG_VFSOP		0x40
#define	CFSDEBUG_RESOURCE	0x80
#define	CFSDEBUG_CHEAT		0x100
#define	CFSDEBUG_INVALIDATE	0x200
#define	CFSDEBUG_DLOG		0x400
#define	CFSDEBUG_FILEGRP	0x800
#define	CFSDEBUG_IOCTL		0x1000
#define	CFSDEBUG_FRONT		0x2000
#define	CFSDEBUG_BACK		0x4000
#define	CFSDEBUG_ALLOCMAP	0x8000
#define	CFSDEBUG_ASYNCPOP	0x10000
#define	CFSDEBUG_VOPS_NFSV4	0x20000

#define	CFSCLEANFLAG

extern int cachefsdebug;

#define	CFS_DEBUG(N)    if (cachefsdebug & (N))
#endif /* DEBUG */

#if 0
#ifdef CFSDEBUG
	/*
	 * Testing usage of cd_access and friends.
	 * Note we steal an unused bit in t_flag.
	 * This will certainly bite us later.
	 */
#define	CFS_CD_DEBUG
#define	T_CD_HELD	0x01000
#endif
#endif

/*
 * Note: in an RL debugging kernel, CFSVERSION is augmented by 100
 *
 * Version History:
 *
 * Beginning -- Solaris 2.3 and 2.4: 1
 *
 * In Solaris 2.5 alpha, the size of fid_t changed: 2
 *
 * In 2.6: Chart, RL pointers/idents became rl_entry: 3
 *	added which RL list to attrcache header: 4
 *
 * Large Files support made version to 6.
 *
 * Sequence numbers made version to 7.
 *
 * 64-bit on-disk cache will make version 8. Not yet supported.
 */

#if 0
#define	CFSRLDEBUG
#endif

#ifdef CFSRLDEBUG
#define	CFSVERSION		110
#define	CFSVERSION64		111	/* 64-bit cache - not yet used */
#else /* CFSRLDEBUG */
#define	CFSVERSION		7
#define	CFSVERSION64		8	/* 64-bit cache - not yet used */
#endif /* CFSRLDEBUG */

/* Some default values */
#define	DEF_FILEGRP_SIZE	256
#define	DEF_POP_SIZE		0x10000		/* 64K */
#define	CACHELABEL_NAME		".cfs_label"
#define	RESOURCE_NAME		".cfs_resource"
#define	CACHEFS_FSINFO		".cfs_fsinfo"
#define	ATTRCACHE_NAME		".cfs_attrcache"
#define	CACHEFS_LOSTFOUND_NAME	"lost+found"
#define	BACKMNT_NAME		".cfs_mnt_points"
#define	CACHEFS_LOCK_FILE	".cfs_lock"
#define	CACHEFS_DLOG_FILE	".cfs_dlog"
#define	CACHEFS_DMAP_FILE	".cfs_dmap"
#define	CACHEFS_MNT_FILE	".cfs_mnt"
#define	CACHEFS_UNMNT_FILE	".cfs_unmnt"
#define	LOG_STATUS_NAME		".cfs_logging"
#define	NOBACKUP_NAME		".nsr"
#define	CACHEFS_PREFIX		".cfs_"
#define	CACHEFS_PREFIX_LEN	5
#define	ROOTLINK_NAME		"root"
#define	CFS_FRONTFILE_NAME_SIZE	18
#define	CACHEFS_BASETYPE	"cachefs" /* used in statvfs() */
#define	CFS_MAXFREECNODES	20
#define	CACHEFSTAB		"/etc/cachefstab"
#define	CACHEFS_ROOTRUN		"/var/run"
#define	CACHEFS_LOCKDIR_PRE	".cachefs." /* used by mount(1M)/fsck(1M) */

/*
 * The options structure is passed in as part of the mount arguments.
 * It is stored in the .options file and kept track of in the fscache
 * structure.
 */
struct cachefsoptions {
	uint_t		opt_flags;		/* mount flags */
	int		opt_popsize;		/* cache population size */
	int		opt_fgsize;		/* filegrp size, default 256 */
};

typedef struct cachefscache cachefscache_t;

/*
 * all the stuff needed to manage a queue of requests to be processed
 * by async threads.
 */
struct cachefs_workq {
	struct cachefs_req	*wq_head;		/* head of work q */
	struct cachefs_req	*wq_tail;		/* tail of work q */
	int			wq_length;		/* # of requests on q */
	int			wq_thread_count;	/* # of threads */
	int			wq_max_len;		/* longest queue */
	int			wq_halt_request;	/* halt requested */
	unsigned int		wq_keepone:1;		/* keep one thread */
	unsigned int		wq_logwork:1;		/* write logfile */
	kcondvar_t		wq_req_cv;		/* wait on work to do */
	kcondvar_t		wq_halt_cv;		/* wait/signal halt */
	kmutex_t		wq_queue_lock;		/* protect queue */
	cachefscache_t		*wq_cachep;		/* sometimes NULL */
};

/*
 * cfs_cid is stored on disk, so it needs to be the same 32-bit vs. 64-bit.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/* identifies a file in the cache */
struct cfs_cid {
	ino64_t	cid_fileno;		/* fileno */
	int	cid_flags;		/* flags */
};
typedef struct cfs_cid cfs_cid_t;
#define	CFS_CID_LOCAL	1	/* local file */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/*
 * XX64 - for now redefine	all time_t fields that are used by both kernel
 * and user space apps as a 32-bit quantity,
 */

#if (defined(_SYSCALL32) && defined(_LP64))

/*
 * The cfs_* types are used to represent on-disk data, since its size is
 * independent of the kernel memory model (in the LP64 case)
 */
typedef time32_t		cfs_time_t;
typedef timestruc32_t		cfs_timestruc_t;
typedef vattr32_t		cfs_vattr_t;
typedef fid32_t			cfs_fid_t;

#define	cfs_timespec		timespec32
#define	cfs_vattr		vattr32
#define	cfs_fid			fid32

/*
 * CACHEFS_DEV_COPY copies between two dev_t's. It expands or compresses
 * them based on type changes (if needed).
 */
#define	CACHEFS_DEV_TO_DEV32_COPY(in_dev, out_dev, error)		\
	if (cmpldev((dev32_t *)&(out_dev), in_dev) == 0)		\
		error = EOVERFLOW;

#define	CACHEFS_DEV32_TO_DEV_COPY(in_dev, out_dev)			\
	out_dev = (dev_t)expldev(in_dev);

#define	TIME_OVERFLOW(tval)						\
	((tval) < TIME32_MIN || (tval) > TIME32_MAX)

/* Set the referred to time value. Set error if overflow */
#define	CACHEFS_TIME_TO_TIME32_COPY(in_tval, out_tval, error)		\
	out_tval = (in_tval);						\
	if (TIME_OVERFLOW(in_tval))					\
		error = EOVERFLOW;

#define	CACHEFS_TIME32_TO_TIME_COPY(in_tval, out_tval)			\
	out_tval = (in_tval);

/* Set the cfs_timestruc_t with values from input timestruc_t */
#define	CACHEFS_TS_TO_TS32_COPY(in_tsp, out_tsp, error)			\
	(out_tsp)->tv_nsec = (in_tsp)->tv_nsec;				\
	CACHEFS_TIME_TO_TIME32_COPY((in_tsp)->tv_sec, (out_tsp)->tv_sec, error)

#define	CACHEFS_TS32_TO_TS_COPY(in_tsp, out_tsp)			\
	(out_tsp)->tv_nsec = (in_tsp)->tv_nsec;				\
	CACHEFS_TIME32_TO_TIME_COPY((in_tsp)->tv_sec, (out_tsp)->tv_sec)

/* CACHEFS_FID_COPY copies between two fids */
#define	CACHEFS_FID_COPY(in_fidp, out_fidp)				\
	(out_fidp)->fid_len = (in_fidp)->fid_len;			\
	bcopy((in_fidp)->fid_data, (out_fidp)->fid_data, (in_fidp)->fid_len)

#define	CACHEFS_VATTR_TO_VATTR32_COPY(in_vattrp, out_vattrp, error)	\
	(out_vattrp)->va_mask = (in_vattrp)->va_mask;			\
	(out_vattrp)->va_type = (in_vattrp)->va_type;			\
	(out_vattrp)->va_mode = (in_vattrp)->va_mode;			\
	(out_vattrp)->va_uid = (in_vattrp)->va_uid;			\
	(out_vattrp)->va_gid = (in_vattrp)->va_gid;			\
	CACHEFS_DEV_TO_DEV32_COPY((in_vattrp)->va_fsid,			\
		(out_vattrp)->va_fsid, error);				\
	(out_vattrp)->va_nodeid = (in_vattrp)->va_nodeid;		\
	(out_vattrp)->va_nlink = (in_vattrp)->va_nlink;			\
	(out_vattrp)->va_size = (in_vattrp)->va_size;			\
	CACHEFS_TS_TO_TS32_COPY(&(in_vattrp)->va_atime,			\
		&(out_vattrp)->va_atime, error);			\
	CACHEFS_TS_TO_TS32_COPY(&(in_vattrp)->va_mtime,			\
		&(out_vattrp)->va_mtime, error);			\
	CACHEFS_TS_TO_TS32_COPY(&(in_vattrp)->va_ctime, 		\
		&(out_vattrp)->va_ctime, error);			\
	CACHEFS_DEV_TO_DEV32_COPY((in_vattrp)->va_rdev,			\
		(out_vattrp)->va_rdev, error);				\
	(out_vattrp)->va_blksize = (in_vattrp)->va_blksize;		\
	(out_vattrp)->va_nblocks = (in_vattrp)->va_nblocks;		\
	(out_vattrp)->va_seq = 0

#define	CACHEFS_VATTR32_TO_VATTR_COPY(in_vattrp, out_vattrp)		\
	(out_vattrp)->va_mask = (in_vattrp)->va_mask;			\
	(out_vattrp)->va_type = (in_vattrp)->va_type;			\
	(out_vattrp)->va_mode = (in_vattrp)->va_mode;			\
	(out_vattrp)->va_uid = (in_vattrp)->va_uid;			\
	(out_vattrp)->va_gid = (in_vattrp)->va_gid;			\
	CACHEFS_DEV32_TO_DEV_COPY((in_vattrp)->va_fsid,			\
		(out_vattrp)->va_fsid);					\
	(out_vattrp)->va_nodeid = (in_vattrp)->va_nodeid;		\
	(out_vattrp)->va_nlink = (in_vattrp)->va_nlink;			\
	(out_vattrp)->va_size = (in_vattrp)->va_size;			\
	CACHEFS_TS32_TO_TS_COPY(&(in_vattrp)->va_atime,			\
		&(out_vattrp)->va_atime);				\
	CACHEFS_TS32_TO_TS_COPY(&(in_vattrp)->va_mtime,			\
		&(out_vattrp)->va_mtime);				\
	CACHEFS_TS32_TO_TS_COPY(&(in_vattrp)->va_ctime,			\
		&(out_vattrp)->va_ctime);				\
	CACHEFS_DEV32_TO_DEV_COPY((in_vattrp)->va_rdev,			\
		(out_vattrp)->va_rdev);					\
	(out_vattrp)->va_blksize = (in_vattrp)->va_blksize;		\
	(out_vattrp)->va_nblocks = (in_vattrp)->va_nblocks;		\
	(out_vattrp)->va_seq = 0

#else /* not _SYSCALL32 && _LP64 */

/*
 * The cfs_* types are used to represent on-disk data, since its size is
 * independent of the kernel memory model (in the LP64 case)
 */
typedef time_t			cfs_time_t;
typedef timestruc_t		cfs_timestruc_t;
typedef vattr_t			cfs_vattr_t;
typedef fid_t			cfs_fid_t;

#define	cfs_timespec		timespec
#define	cfs_vattr		vattr
#define	cfs_fid			fid

#define	TIME_OVERFLOW(tval)	FALSE

#define	CACHEFS_DEV_TO_DEV32_COPY(in_dev, out_dev, error)		\
	out_dev = (in_dev)

#define	CACHEFS_DEV32_TO_DEV_COPY(in_dev, out_dev)			\
	out_dev = (in_dev)

#define	CACHEFS_TIME_TO_TIME32_COPY(in_tval, out_tval, error)		\
	out_tval = (in_tval)

#define	CACHEFS_TIME32_TO_TIME_COPY(in_tval, out_tval)			\
	out_tval = (in_tval)

#define	CACHEFS_TS_TO_TS32_COPY(in_tsp, out_tsp, error)			\
	*(out_tsp) = *(in_tsp)

#define	CACHEFS_TS32_TO_TS_COPY(in_tsp, out_tsp)			\
	*(out_tsp) = *(in_tsp)

#define	CACHEFS_FID_COPY(in_fidp, out_fidp)				\
	*(out_fidp) = *(in_fidp)

#define	CACHEFS_VATTR_TO_VATTR32_COPY(in_vattrp, out_vattrp, error)	\
	*(out_vattrp) = *(in_vattrp);					\
	(out_vattrp)->va_seq = 0

#define	CACHEFS_VATTR32_TO_VATTR_COPY(in_vattrp, out_vattrp)		\
	*(out_vattrp) = *(in_vattrp);					\
	(out_vattrp)->va_seq = 0

#endif /* _SYSCALL32 && _LP64 */

/*
 * The "cfs_*" structs below refer to the on-disk structures. Presently
 * they are 32-bit based. When they change to 64-bit, we'd have to modify the
 * macros below accordingly.
 */
#define	CACHEFS_DEV_TO_CFS_DEV_COPY(in_dev, out_dev, error)		\
	CACHEFS_DEV_TO_DEV32_COPY(in_dev, out_dev, error)

#define	CACHEFS_CFS_DEV_TO_DEV_COPY(in_dev, out_dev)		\
	CACHEFS_DEV32_TO_DEV_COPY(in_dev, out_dev)

#define	CACHEFS_TIME_TO_CFS_TIME_COPY(in_tval, out_tval, error)		\
	CACHEFS_TIME_TO_TIME32_COPY(in_tval, out_tval, error)

#define	CACHEFS_CFS_TIME_TO_TIME_COPY(in_tval, out_tval)		\
	CACHEFS_TIME32_TO_TIME_COPY(in_tval, out_tval)

#define	CACHEFS_TS_TO_CFS_TS_COPY(in_tsp, out_tsp, error)		\
	CACHEFS_TS_TO_TS32_COPY(in_tsp, out_tsp, error)

#define	CACHEFS_CFS_TS_TO_TS_COPY(in_tsp, out_tsp)			\
	CACHEFS_TS32_TO_TS_COPY(in_tsp, out_tsp)

#define	CACHEFS_VATTR_TO_CFS_VATTR_COPY(in_vattrp, out_vattrp, error)	\
	CACHEFS_VATTR_TO_VATTR32_COPY(in_vattrp, out_vattrp, error)

#define	CACHEFS_CFS_VATTR_TO_VATTR_COPY(in_vattrp, out_vattrp)		\
	CACHEFS_VATTR32_TO_VATTR_COPY(in_vattrp, out_vattrp)

#include <sys/fs/cachefs_fscache.h>
#include <sys/fs/cachefs_filegrp.h>

/*
 * One cache_label structure per cache. Contains mainly user defined or
 * default values for cache resource management. Contents is static.
 * The value cl_maxfiles is not used any where in cachefs code. If and when
 * this is really used the cl_maxfiles should be declared as a 64bit value
 * for large file support.
 * The maxblks, blkhiwat, blklowat, blocktresh, blockmin, may need to be
 * 64bit values when we actually start supporting file systems of size
 * greater than 1 terabyte.
 */
struct cache_label {
	int	cl_cfsversion;	/* cfs version number */
	int	cl_maxblks;	/* max blocks to be used by cache */
	int	cl_blkhiwat;	/* high water-mark for block usage */
	int	cl_blklowat;	/* low water-mark for block usage */
	int	cl_maxinodes;	/* max inodes to be used by cache */
	int	cl_filehiwat;	/* high water-mark for inode usage */
	int	cl_filelowat;	/* low water-mark for indoe usage */
	int	cl_blocktresh;	/* block max usage treshold */
	int	cl_blockmin;	/* block min usage treshold */
	int	cl_filetresh;	/* inode max usage treshold */
	int	cl_filemin;	/* inode min usage treshold */
	int	cl_maxfiles;	/* max cache file size */
};

/*
 * One cache_usage structure per cache. Keeps track of cache usage figures.
 * Contents gets updated frequently.
 */
struct cache_usage {
	int	cu_blksused;	/* actual number of blocks used */
	int	cu_filesused;	/* actual number of files used */
	uint_t	cu_flags;	/* Cache state flags */
	ushort_t cu_unique;	/* Fid persistent uniquifier */
};

#define	CUSAGE_ACTIVE	1	/* Cache is active */
#define	CUSAGE_NEED_ADJUST 2	/* Adjust uniquifier before assigning new fid */

/*
 * RL list identifiers.
 */
enum cachefs_rl_type {
	CACHEFS_RL_NONE = 0x101,
	CACHEFS_RL_FREE,
	CACHEFS_RL_GC,
	CACHEFS_RL_ACTIVE,
	CACHEFS_RL_ATTRFILE,
	CACHEFS_RL_MODIFIED,
	CACHEFS_RL_PACKED,
	CACHEFS_RL_PACKED_PENDING,
	CACHEFS_RL_MF
};
#define	CACHEFS_RL_START CACHEFS_RL_NONE
#define	CACHEFS_RL_END CACHEFS_RL_MF
#define	CACHEFS_RL_CNT	(CACHEFS_RL_END - CACHEFS_RL_START + 1)
#define	CACHEFS_RL_INDEX(X)	(X - CACHEFS_RL_START)

struct cachefs_rl_listhead {
	uint_t		rli_front;		/* front of list */
	uint_t		rli_back;		/* back of list */
	int		rli_blkcnt;		/* number of 8k blocks */
	int		rli_itemcnt;		/* number of items on list */
};
typedef struct cachefs_rl_listhead cachefs_rl_listhead_t;

/*
 * Resource List information.  One per cache.
 */
struct cachefs_rl_info {
	uint_t		rl_entries;	/* number of entries allocated in rl */
	cfs_time_t	rl_gctime;	/* time of item on front of gc list */

	/* heads of the various lists */
	cachefs_rl_listhead_t	rl_items[CACHEFS_RL_CNT];
};
typedef struct cachefs_rl_info cachefs_rl_info_t;

/*
 * rl_debug and rl_entry are stored on disk, so they need to be
 * the same 32-bit vs. 64-bit.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

#ifdef CFSRLDEBUG
/*
 * RL debugging thingy
 */

#define	CACHEFS_RLDB_STACKSIZE	16
#define	CACHEFS_RLDB_DEF_MAXCOUNT 5

typedef struct rl_debug {
	hrtime_t db_hrtime;

	uint_t db_attrc: 1;
	uint_t db_fsck: 1;
	ino64_t db_fsid;
	ino64_t db_fileno;
	enum cachefs_rl_type db_current;

	int db_stackheight;
	pc_t db_stack[CACHEFS_RLDB_STACKSIZE];

	struct rl_debug *db_next;
} rl_debug_t;

extern time_t cachefs_dbvalid;
extern struct kmem_cache *cachefs_rl_debug_cache;
extern kmutex_t cachefs_rl_debug_mutex;
#endif /* CFSRLDEBUG */

/*
 * RL Entry type.
 */

typedef struct rl_entry {
	uint_t rl_attrc: 1;
	uint_t rl_fsck: 1; /* used by fsck; true => rl_current is correct */
	uint_t rl_local: 1; /* 1 means a local file */

#ifdef CFSRLDEBUG
	cfs_time_t rl_dbvalid; /* this == cachefs_dbvalid => trust rl_debug */
	rl_debug_t *rl_debug;
#endif /* CFSRLDEBUG */

	ino64_t rl_fsid;
	ino64_t rl_fileno;

	enum cachefs_rl_type rl_current;
	uint_t rl_fwd_idx;
	uint_t rl_bkwd_idx;
} rl_entry_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/*
 * rl entries per MAXBSIZE chunk.  rl_entry_t's size need not divide
 * MAXBSIZE, as long as this constant is an integer (through integer
 * division) (see cachefs_rl_entry_get()).
 */

#define	CACHEFS_RLPMBS	(MAXBSIZE / (uint_t)sizeof (rl_entry_t))

/*
 * struct cache contains cache-wide information, and provides access
 * to lower level info. There is one cache structure per cache.
 */
struct cachefscache {
	struct cachefscache	*c_next;	/* list of caches */
	uint_t			c_flags;	/* misc flags */
	struct cache_label	c_label;	/* cache resource info */
	struct cache_usage	c_usage;	/* cache usage info */
	struct cachefs_rl_info	c_rlinfo;	/* rl global pointers */
	struct vnode		*c_resfilevp;	/* resource file vp */
	uint_t			c_rl_window;	/* window mapped in */
	rl_entry_t		*c_rl_entries;	/* mapping for rl entries */
	struct vnode		*c_dirvp;	/* cache directory vp */
	struct vnode		*c_lockvp;	/* lock file vp */
	struct vnode		*c_lostfoundvp;	/* lost+found directory vp */
	int			c_refcnt;	/* active fs ref count */
	struct fscache		*c_fslist;	/* fscache list head */
	struct cachefs_workq	c_workq;	/* async work */
	kmutex_t		c_contentslock; /* protect cache struct */
	kmutex_t		c_fslistlock;	/* protect fscache list */
	kmutex_t		c_mflock;	/* protect modified fixes */
	ushort_t		c_unique;	/* In core fid uniquifier */
	kcondvar_t		c_cwcv;		/* gc wait on work to do */
	kcondvar_t		c_cwhaltcv;	/* wait on gc thread exit */
	uint_t			c_gc_count;	/* garbage collection count */
	time_t			c_gc_time;	/* last garbage collection */
	time_t			c_gc_before;	/* atime of front before gc */
	time_t			c_gc_after;	/* atime of front after gc */
	uint_t			c_apop_inqueue;	/* # async pops queued */
	pid_t			c_rootdaemonid;	/* pid of root cachefsd */
	struct cachefs_log_cookie
				*c_log;		/* in-core logging stuff */
	struct cachefs_log_control
				*c_log_ctl;	/* on-disk logging stuff */
	kmutex_t		c_log_mutex;	/* protects c_log* */
};

extern struct kmem_cache *cachefs_cache_kmcache;

#define	CACHEFS_MAX_APOP_INQUEUE	50	/* default value for below */
extern uint_t cachefs_max_apop_inqueue;		/* max populations pending */

/*
 * Various cache structure flags.
 */
#define	CACHE_NOCACHE		0x1	/* all cache refs go to back fs */
#define	CACHE_ALLOC_PENDING	0x4	/* Allocation pending */
#define	CACHE_NOFILL		0x8	/* No fill mode */
#define	CACHE_GARBAGE_COLLECT	0x10	/* Garbage collect in progress */
#define	CACHE_CACHEW_THREADRUN	0x20	/* Cachep worker thread is alive */
#define	CACHE_CACHEW_THREADEXIT 0x40	/* cachew thread should exit */
#define	CACHE_DIRTY		0x80
#define	CACHE_PACKED_PENDING	0x100	/* Packed pending work to do */
#define	CACHE_CHECK_RLTYPE	0x200	/* double-check with resource lists */

/*
 * Values for the mount options flag, opt_flags.
 */
/*
 * Mount options
 */
#define	CFS_WRITE_AROUND	0x01	/* write-around */
#define	CFS_NONSHARED		0x02	/* write to cache and back file */
#define	CFS_NOCONST_MODE	0x08	/* no-op consistency mode */
#define	CFS_ACCESS_BACKFS	0x10	/* pass VOP_ACCESS to backfs */
#define	CFS_CODCONST_MODE	0x80	/* cod consistency mode */
#define	CFS_DISCONNECTABLE	0x100	/* server not reponding option */
#define	CFS_SOFT		0x200	/* soft mounted */
#define	CFS_NOACL		0x400	/* ACLs are disabled in this fs */
#define	CFS_LLOCK		0x800	/* use local file/record locks */
#define	CFS_SLIDE		0x1000	/* slide backfs under cachefs */
#define	CFS_NOFILL		0x2000	/* start in nofill mode */
#define	CFS_BACKFS_NFSV4	0x4000	/* back filesystem is NFSv4 */

#define	MAXCOOKIE_SIZE	36

#define	C_BACK_CHECK	0x2

/*
 * Macro to determine if this is a snr error where we should do a
 * state transition.
 */

#define	CFS_TIMEOUT(FSCP, ERROR) \
	(ERROR && CFS_ISFS_SNR(FSCP) && \
	(((ERROR) == ETIMEDOUT) || ((ERROR) == EIO)))

/*
 * Macros to assert that cachefs fscache and cnode are in
 * sync with NFSv4. Note that NFSv4 always passes-through
 * the vnode calls directly to the backfilesystem. For
 * this to work:
 * (1) cachefs is always setup for connected operation,
 * (2) cachefs options (example disconnectable (snr), nonshared, etc)
 *     are disabled, and
 * (3) the back filesystem vnode pointer always exists
 *      (except after a remove operation)
 * (4) the front filesystem vnode pointer is always NULL.
 */
#ifdef DEBUG
#define	CFS_BACKFS_NFSV4_ASSERT_FSCACHE(fscp) \
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) { \
		ASSERT((fscp)->fs_info.fi_mntflags == CFS_BACKFS_NFSV4); \
		ASSERT((fscp)->fs_cdconnected == CFS_CD_CONNECTED); \
	}
#define	CFS_BACKFS_NFSV4_ASSERT_CNODE(cp) \
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) { \
		if (MUTEX_HELD(&cp->c_statelock)) { \
			ASSERT((cp)->c_backvp != NULL || \
				((cp)->c_flags & CN_DESTROY) != 0); \
			ASSERT((cp)->c_frontvp == NULL); \
		} else { \
			mutex_enter(&(cp)->c_statelock); \
			ASSERT((cp)->c_backvp != NULL || \
				((cp)->c_flags & CN_DESTROY) != 0); \
			ASSERT((cp)->c_frontvp == NULL); \
			mutex_exit(&cp->c_statelock); \
		} \
	}
#else
#define	CFS_BACKFS_NFSV4_ASSERT_FSCACHE(fscp)
#define	CFS_BACKFS_NFSV4_ASSERT_CNODE(cp)
#endif	/* DEBUG */

#ifdef CFSDEBUG
#define	CFS_DPRINT_BACKFS_NFSV4(fscp, x) \
	if (CFS_ISFS_BACKFS_NFSV4(fscp)) { \
		CFS_DEBUG(CFSDEBUG_VOPS_NFSV4) \
			printf x; \
	}
#else
#define	CFS_DPRINT_BACKFS_NFSV4(fscp, x)
#endif /* CFSDEBUG */

/*
 * cachefs_allocmap and cfs_cachefs_metadata are stored on disk,
 * so they need to be the same 32-bit vs. 64-bit.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/*
 * Large file support. The start offset of the cached file can be
 * greater than 2GB and by coelescing the different chunks we may
 * end up having a chunk of siz3 > 2GB.
 */

struct cachefs_allocmap {
	u_offset_t		am_start_off;	/* Start offset of this chunk */
	u_offset_t		am_size;	/* size of this chunk */
};

#define	C_MAX_ALLOCINFO_SLOTS	32

/*
 * CFS fastsymlinks. For symlink of size < C_FSL_SIZE, the symlink
 * is stored in the cnode allocmap array.
 */
#define	C_FSL_SIZE	(sizeof (struct cachefs_allocmap) * \
			C_MAX_ALLOCINFO_SLOTS)

/*
 * Structure representing a cached object in memory.
 */
struct cachefs_metadata {
	struct vattr		md_vattr;	/* attributes */
	o_mode_t		md_aclclass;	/* CLASS_OBJ perm for ACL */
	ushort_t		md_pad1;	/* compiler padding */
	fid_t			md_cookie;	/* back fid */
	int			md_flags;	/* various flags */
	uint_t			md_rlno;	/* rl entry */
	enum cachefs_rl_type	md_rltype;	/* rl type */
	int			md_consttype;	/* type of consistency */
	fid_t			md_fid;		/* fid of front file */
	uint_t			md_frontblks;	/* # blks used in frontfs */
	uint_t			md_gen;		/* fid uniquifier */
	struct cfs_cid		md_parent;	/* id of parent */
	timestruc_t		md_timestamp;	/* front file timestamp */
	timestruc_t		md_x_time;	/* see consistency routines */
	timestruc_t		md_localmtime;	/* persistent local mtime */
	timestruc_t		md_localctime;	/* persistent local ctime */
	uint_t			md_resettimes;	/* when to reset local times */
	ino64_t			md_localfileno;	/* persistent local inum */
	uint_t			md_resetfileno;	/* when to reset local fileno */
	uint_t			md_seq;		/* seq number for putpage */
	int			md_allocents;	/* nbr of entries in allocmap */
	struct cachefs_allocmap	md_allocinfo[C_MAX_ALLOCINFO_SLOTS];
};
typedef struct cachefs_metadata cachefs_metadata_t;

#if (defined(_SYSCALL32) && defined(_LP64))

/*
 * fid_t is long aligned, so user fid could be only 4 byte aligned.
 * Since vnode/vfs calls require fid_t (which would be 8 byte aligned in
 * _LP64), we would have to copy the user's value (and on-disk data) in/out.
 */
/* on-disk metadata structure - fid aligned to int, time is 32-bit */

struct cfs_cachefs_metadata {
	struct cfs_vattr	md_vattr;	/* attributes */
	o_mode_t		md_aclclass;	/* CLASS_OBJ perm for ACL */
	cfs_fid_t		md_cookie;	/* back fid */
	int			md_flags;	/* various flags */
	uint_t			md_rlno;	/* rl entry */
	enum cachefs_rl_type	md_rltype;	/* rl type */
	int			md_consttype;	/* type of consistency */
	cfs_fid_t		md_fid;		/* fid of front file */
	uint_t			md_frontblks;	/* # blks used in frontfs */
	uint_t			md_gen;		/* fid uniquifier */
	struct cfs_cid		md_parent;	/* id of parent */
	cfs_timestruc_t		md_timestamp;	/* front file timestamp */
	cfs_timestruc_t		md_x_time;	/* see consistency routines */
	cfs_timestruc_t		md_localmtime;	/* persistent local mtime */
	cfs_timestruc_t		md_localctime;	/* persistent local ctime */
	uint_t			md_resettimes;	/* when to reset local times */
	ino64_t			md_localfileno;	/* persistent local inum */
	uint_t			md_resetfileno;	/* when to reset local fileno */
	uint_t			md_seq;		/* seq number for putpage */
	int			md_allocents;	/* nbr of entries in allocmap */
	struct cachefs_allocmap	md_allocinfo[C_MAX_ALLOCINFO_SLOTS];
};
typedef struct cfs_cachefs_metadata cfs_cachefs_metadata_t;

#else /* not _SYSCALL32 && _LP64 */

typedef cachefs_metadata_t	cfs_cachefs_metadata_t;

#define	cfs_cachefs_metadata	cachefs_metadata

#endif /* _SYSCALL32 && _LP64 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/*
 * Various flags to be stored in md_flags field of the metadata.
 */
#define	MD_CREATEDONE	0x1		/* create was done to backfs */
#define	MD_POPULATED	0x2		/* front file or dir is populated */
#define	MD_FILE		0x4		/* front file or dir exists */
#define	MD_FASTSYMLNK	0x8		/* fast symbolic link */
#define	MD_PACKED	0x10		/* file is packed */
#define	MD_INVALREADDIR	0x40		/* repopulate on readdir */
#define	MD_PUTPAGE	0x200		/* we have already logged a putpage */
#define	MD_FREE		0x400		/* not used */
#define	MD_PUSHDONE	0x800		/* set if file pushed to back fs */
#define	MD_MAPPING	0x1000		/* set if cid mapping space written */
#define	MD_ACL		0x2000		/* file has a cached acl */
#define	MD_ACLDIR	0x4000		/* front `dir' exists for holding acl */
#define	MD_LOCALMTIME	0x8000		/* do not overwrite md_localmtime */
#define	MD_LOCALCTIME	0x10000		/* do not overwrite md_localctime */
#define	MD_LOCALFILENO	0x20000		/* do not overwrite md_localfileno */
#define	MD_NEEDATTRS	0x40000		/* new attrs needed at next check */

#define	C_MAX_MOUNT_FSCDIRNAME		128
/*
 * cachefs mount structure and related data
 */
struct cachefs_mountargs {
	struct cachefsoptions	cfs_options;	/* consistency modes, etc. */
	char			*cfs_fsid;	/* CFS ID fpr file system */
	char			cfs_cacheid[C_MAX_MOUNT_FSCDIRNAME];
	/* CFS fscdir name */
	char			*cfs_cachedir;	/* path for this cache dir */
	char			*cfs_backfs;	/* back filesystem dir */
	uint_t			cfs_acregmin;	/* same as nfs values */
	uint_t			cfs_acregmax;
	uint_t			cfs_acdirmin;
	uint_t			cfs_acdirmax;
	char			*cfs_hostname;  /* server name */
	char			*cfs_backfsname; /* back filesystem name */
};

#ifdef _SYSCALL32
struct cachefs_mountargs32 {
	struct cachefsoptions	cfs_options;	/* consistency modes, etc. */
	caddr32_t		cfs_fsid;	/* CFS ID fpr file system */
	char			cfs_cacheid[C_MAX_MOUNT_FSCDIRNAME];
	/* CFS fscdir name */
	caddr32_t		cfs_cachedir;	/* path for this cache dir */
	caddr32_t		cfs_backfs;	/* back filesystem dir */
	uint32_t		cfs_acregmin;	/* same as nfs values */
	uint32_t		cfs_acregmax;
	uint32_t		cfs_acdirmin;
	uint32_t		cfs_acdirmax;
	caddr32_t		cfs_hostname;  /* server name */
	caddr32_t		cfs_backfsname; /* back filesystem name */
};
#endif /* _SYSCALL32 */

/*
 * struct cachefsops - consistency modules.
 */
struct cachefsops {
	int	(*co_init_cobject)();
	int	(*co_check_cobject)();
	void	(*co_modify_cobject)();
	void	(*co_invalidate_cobject)();
	void	(*co_convert_cobject)();
};



/*
 * The attrcache file consists of a attrcache_header structure and an
 * array of attrcache_slot structures (one per front file).
 */

/*
 * Attrcache file format
 *
 *	Header
 *	Offset array (# of entries = file group size)
 *	alloc list	(1 bit per entry, 0 = free) Note that the
 *			file will be extended as needed
 *	attrcache entries
 *
 */
struct attrcache_header {
	uint_t		ach_count;		/* number of entries */
	int		ach_nffs;		/* number of front files */
	int		ach_nblks;		/* number of allocated blocks */
	uint_t		ach_rlno;		/* rl entry for this file */
	enum cachefs_rl_type ach_rl_current;	/* which list we're on */
};

/*
 * We assume that the seek offset to metadata will never be > 2GB.
 * The filegrp size is 256 and the current calculations of the sizes
 * of the data structures show that the ach_offset value here will not
 * be > 2GB.
 */

struct attrcache_index {
	uint_t	ach_written:1;		/* 1 if metadata written */
	uint_t	ach_offset:31;		/* seek offset to metadata */
};

/*
 * cnode structure, one per file.
 */
#define	c_attr			c_metadata.md_vattr
#define	c_cookie		c_metadata.md_cookie
#define	c_fileno		c_id.cid_fileno

/*
 * LOCKS:	c_rwlock	Read / Write serialization
 *		c_statelock	Protects most other fields in the cnode
 *		c_popcv		Condvar used to prevent routines from nuking
 *				a cnode which is currently being populated.
 *				Threads blocked on it will be woken when the
 *				populate completes.
 *		c_iocv		broadcast, but never waited on - unused?
 *		c_iomutex	c_nio and c_ioflags
 *
 * Fields protected by other locks:
 *
 *		c_next		fg_cnodelock in the filegrp struct
 *		c_idleback	fs_idlelock in fscache struct
 *		c_idlefront	fs_idlelock in fscache struct
 *
 * Large File support: c_size goes to u_offset_t and the apopoff type
 * goes to offset_t.
 */
struct cnode {
	int		c_flags;	/* see below */
	struct cnode	*c_next;	/* next cnode in fgp list */
	struct cnode	*c_idleback;	/* idle list back ptr */
	struct cnode	*c_idlefront;	/* idle list front ptr */
	struct vnode	*c_frontvp;	/* front vnode pointer */
	struct vnode	*c_backvp;	/* back vnode pointer */
	struct vnode	*c_acldirvp;	/* dir for storing dflt ACL */
	u_offset_t	c_size;		/* client view of the size */
	struct filegrp	*c_filegrp;	/* back pointer to filegrp */
	struct cfs_cid	c_id;		/* unique file number */
	int		c_invals;	/* # of recent dir invals */
	int		c_usage;	/* Usefulness of cache */
	struct vnode	*c_vnode;	/* pointer to vnode */
	struct cachefs_metadata	c_metadata;	/* cookie, ... */
	int		c_error;
	kmutex_t	c_statelock;	/* statelock */
	krwlock_t	c_rwlock;	/* serialize write/setattr requests */
	kcondvar_t	c_popcv;	/* cnode populate cond var. */
	kthread_id_t	c_popthrp;	/* threadp performing pop */
	vnode_t		*c_unldvp;	/* dir to unlink in */
	char		*c_unlname;	/* name to unlink */
	cred_t		*c_unlcred;	/* creds for unlink */
	int		c_nio;		/* Number of io's pending */
	uint_t		c_ioflags;
	kcondvar_t	c_iocv;		/* IO cond var. */
	kmutex_t	c_iomutex;
	cred_t		*c_cred;
	int		c_ipending;	/* 1 if inactive is pending */
	int		c_mapcnt;	/* number of mapped blocks */
	offset_t	c_apopoffset;	/* offset for async pop */
	uint_t		c_apoplen;	/* length for async pop */
	u_offset_t	c_modaddr;	/* writepage offset */
	int		c_rdcnt;	/* # of read opens for backvp */
	int		c_wrcnt;	/* # of write opens for backvp */
};
typedef struct cnode cnode_t;

extern struct kmem_cache *cachefs_cnode_cache;

/*
 * Directory caching parameters - First cut...
 */
#define	CFS_DIRCACHE_COST	3
#define	CFS_DIRCACHE_INVAL	3
#define	CFS_DIRCACHE_ENABLE	(CFS_DIRCACHE_INVAL * CFS_DIRCACHE_COST)

/*
 * Conversion macros
 */
#define	VTOC(VP)		((struct cnode *)((void *)((VP)->v_data)))
#define	CTOV(CP)		((CP)->c_vnode)
#define	VFS_TO_FSCACHE(VFSP)	((struct fscache *)((void *)((VFSP)->vfs_data)))
#define	C_TO_FSCACHE(CP)	(VFS_TO_FSCACHE(CTOV(CP)->v_vfsp))

/*
 * Various flags stored in the flags field of the cnode structure.
 */
#define	CN_NOCACHE	0x1		/* no-cache mode */
#define	CN_DESTROY	0x2		/* destroy when inactive */
#define	CN_ROOT		0x4		/* root of the file system */
#define	CN_IDLE		0x8		/* file is idle */
#define	CN_NEEDOPEN	0x10		/* need to open backvp */
#define	CN_UPDATED	0x40		/* Metadata was updated - needs sync */
#define	CDIRTY		0x80
#define	CN_NEED_FRONT_SYNC	0x100	/* front file needs to be sync'd */
#define	CN_ALLOC_PENDING	0x200	/* Need to alloc attr cache entry */
#define	CN_STALE	0x400		/* cnode is stale */
#define	CN_MODIFIED	0x800		/* Object has been written to */
#define	CN_POPULATION_PENDING	0x1000	/* Population data needs to be sync'd */
#define	CN_ASYNC_POPULATE	0x2000	/* async population pending */
#define	CN_ASYNC_POP_WORKING	0x4000	/* async population in progress */
#define	CN_PENDRM	0x8000		/* hold off unlink until reconnected */
#define	CN_MAPWRITE	0x100000	/* mmapped file that is being written */
#define	CN_CMODINPROG	0x200000	/* writepage() in progress */

/*
 * io flags (in c_ioflag)
 */
#define	CIO_PUTPAGES	0x1		/* putpage pending: off==0, len==0 */

#define	CFS_MAX_THREADS		5
#define	CFS_ASYNC_TIMEOUT	(60 * hz)

enum cachefs_cmd {
	CFS_INVALID,
	CFS_CACHE_SYNC,
	CFS_PUTPAGE,
	CFS_IDLE,
	CFS_POPULATE,
	CFS_NOOP
};

struct cachefs_fs_sync_req {
	struct cachefscache *cf_cachep;
};

struct cachefs_idle_req {
	vnode_t *ci_vp;
};

/*
 * Large File support the offset in the vnode for putpage request
 * can now be greater than 2GB.
 */

struct cachefs_putpage_req {
	vnode_t *cp_vp;
	offset_t cp_off;
	int cp_len;
	int cp_flags;
};

/*
 * Large File support the offset in the vnode for populate request
 * can now be greater than 2GB.
 */

struct cachefs_populate_req {
	vnode_t *cpop_vp;
	offset_t cpop_off;
	size_t cpop_size;
};

struct cachefs_req {
	struct cachefs_req	*cfs_next;
	enum cachefs_cmd	cfs_cmd;	/* Command to execute */
	cred_t *cfs_cr;
	union {
		struct cachefs_fs_sync_req cu_fs_sync;
		struct cachefs_idle_req cu_idle;
		struct cachefs_putpage_req cu_putpage;
		struct cachefs_populate_req cu_populate;
	} cfs_req_u;
	kmutex_t cfs_req_lock;	/* Protects contents */
};

extern struct kmem_cache *cachefs_req_cache;

/*
 * Large file support: We allow cachefs to understand the 64 bit inode type.
 */

struct cachefs_fid {
	ushort_t	cf_len;
	ino64_t		cf_fileno;
	uint_t		cf_gen;
};
#define	CFS_FID_SIZE	(sizeof (struct cachefs_fid) - sizeof (ushort_t))

/*
 *
 * cachefs kstat stuff.  each time you mount a cachefs filesystem, it
 * gets a unique number.  it'll get that number again if you remount
 * the same thing.  the number is unique until reboot, but it doesn't
 * survive reboots.
 *
 * each cachefs kstat uses this per-filesystem identifier.  to get the
 * valid identifiers, the `cachefs.0.key' kstat has a mapping of all
 * the available filesystems.  its structure, cachefs_kstat_key, is
 * below.
 *
 */

typedef struct cachefs_kstat_key {
	int ks_id;
	int ks_mounted;
	uint64_t ks_vfsp;
	uint64_t ks_mountpoint;
	uint64_t ks_backfs;
	uint64_t ks_cachedir;
	uint64_t ks_cacheid;
} cachefs_kstat_key_t;
extern cachefs_kstat_key_t *cachefs_kstat_key;
extern int cachefs_kstat_key_n;

/*
 * cachefs debugging aid.  cachefs_debug_info_t is a cookie that we
 * can keep around to see what was happening at a certain time.
 *
 * for example, if we have a deadlock on the cnode's statelock
 * (i.e. someone is not letting go of it), we can add a
 * cachefs_debug_info_t * to the cnode structure, and call
 * cachefs_debug_save() whenever we grab the lock.  then, when we're
 * deadlocked, we can see what was going on when we grabbed the lock
 * in the first place, and (hopefully) why we didn't release it.
 */

#define	CACHEFS_DEBUG_DEPTH		(16)
typedef struct cachefs_debug_info {
	char		*cdb_message;	/* arbitrary message */
	uint_t		cdb_flags;	/* arbitrary flags */
	int		cdb_int;	/* arbitrary int */
	void		*cdb_pointer;	/* arbitrary pointer */
	uint_t		cdb_count;	/* how many times called */

	cachefscache_t	*cdb_cachep;	/* relevant cachep (maybe undefined) */
	struct fscache	*cdb_fscp;	/* relevant fscache */
	struct cnode	*cdb_cnode;	/* relevant cnode */
	vnode_t		*cdb_frontvp;	/* relevant front vnode */
	vnode_t		*cdb_backvp;	/* relevant back vnode */

	kthread_id_t	cdb_thread;	/* thread who called */
	hrtime_t	cdb_timestamp;	/* when */
	int		cdb_depth;	/* depth of saved stack */
	pc_t		cdb_stack[CACHEFS_DEBUG_DEPTH]; /* stack trace */
	struct cachefs_debug_info *cdb_next; /* pointer to next */
} cachefs_debug_info_t;

/*
 * cachefs function prototypes
 */
#if defined(_KERNEL)
extern int cachefs_getcookie(vnode_t *, struct fid *, struct vattr *,
		cred_t *, uint32_t);
cachefscache_t *cachefs_cache_create(void);
void cachefs_cache_destroy(cachefscache_t *cachep);
int cachefs_cache_activate_ro(cachefscache_t *cachep, vnode_t *cdvp);
void cachefs_cache_activate_rw(cachefscache_t *cachep);
void cachefs_cache_dirty(struct cachefscache *cachep, int lockit);
int cachefs_cache_rssync(struct cachefscache *cachep);
void cachefs_cache_sync(struct cachefscache *cachep);
uint_t cachefs_cache_unique(cachefscache_t *cachep);
void cachefs_do_req(struct cachefs_req *);

/* cachefs_cnode.c */
void cachefs_cnode_idle(struct vnode *vp, cred_t *cr);
void cachefs_cnode_idleclean(fscache_t *fscp, int unmount);
int cachefs_cnode_inactive(register struct vnode *vp, cred_t *cr);
void cachefs_cnode_listadd(struct cnode *cp);
void cachefs_cnode_listrem(struct cnode *cp);
void cachefs_cnode_free(struct cnode *cp);
void cachefs_cnode_cleanfreelist();
void cachefs_cnode_idleadd(struct cnode *cp);
void cachefs_cnode_idlerem(struct cnode *cp);
int cachefs_cnode_find(filegrp_t *fgp, cfs_cid_t *cidp, fid_t *cookiep,
    struct cnode **cpp, struct vnode *vp, vattr_t *vap);
int cachefs_cnode_make(cfs_cid_t *cidp, fscache_t *fscp, fid_t *cookiep,
    vattr_t *vap, vnode_t *backvp, cred_t *cr, int flag, cnode_t **cpp);
int cachefs_cid_inuse(filegrp_t *fgp, cfs_cid_t *cidp);
int cachefs_fileno_inuse(fscache_t *fscp, ino64_t fileno);
int cachefs_cnode_create(fscache_t *fscp, vattr_t *vap, int flag,
    cnode_t **cpp);
void cachefs_cnode_move(cnode_t *cp);
int cachefs_cnode_lostfound(cnode_t *cp, char *rname);
void cachefs_cnode_sync(cnode_t *cp);
void cachefs_cnode_traverse(fscache_t *fscp, void (*routinep)(cnode_t *));
void cachefs_cnode_stale(cnode_t *cp);
void cachefs_cnode_setlocalstats(cnode_t *cp);
void cachefs_cnode_disable_caching(cnode_t *cp);

void cachefs_enable_caching(struct fscache *);

/* cachefs_fscache.c */
void fscache_destroy(fscache_t *);

/* cachefs_ioctl.h */
int cachefs_pack_common(vnode_t *vp, cred_t *cr);
void cachefs_inum_register(fscache_t *fscp, ino64_t real, ino64_t fake);
ino64_t cachefs_inum_real2fake(fscache_t *fscp, ino64_t real);


/* cachefs_subr.c */
int cachefs_sync_metadata(cnode_t *);
int cachefs_cnode_cnt(int);
int cachefs_getbackvp(struct fscache *, struct cnode *);
int cachefs_getfrontfile(cnode_t *);
void cachefs_removefrontfile(cachefs_metadata_t *mdp, cfs_cid_t *cidp,
    filegrp_t *fgp);
void cachefs_nocache(cnode_t *);
void cachefs_inval_object(cnode_t *);
void make_ascii_name(cfs_cid_t *cidp, char *strp);
int cachefs_async_halt(struct cachefs_workq *, int);
int cachefs_async_okay(void);
int cachefs_check_allocmap(cnode_t *cp, u_offset_t off);
void cachefs_update_allocmap(cnode_t *, u_offset_t, size_t);
int cachefs_cachesymlink(struct cnode *cp, cred_t *cr);
int cachefs_stuffsymlink(cnode_t *cp, caddr_t buf, int buflen);
int cachefs_readlink_back(cnode_t *cp, cred_t *cr, caddr_t *bufp, int *buflenp);
/*
 * void cachefs_cluster_allocmap(struct cnode *, u_offset_t, u_offset_t *,
 *	size_t *, size_t);
 */
void cachefs_cluster_allocmap(u_offset_t, u_offset_t *, size_t *, size_t,
		struct cnode *);
int cachefs_populate(cnode_t *, u_offset_t, size_t, vnode_t *, vnode_t *,
	u_offset_t, cred_t *);
int cachefs_stats_kstat_snapshot(kstat_t *, void *, int);
cachefs_debug_info_t *cachefs_debug_save(cachefs_debug_info_t *, int,
    char *, uint_t, int, void *, cachefscache_t *, struct fscache *,
    struct cnode *);
void cachefs_debug_show(cachefs_debug_info_t *);
uint32_t cachefs_cred_checksum(cred_t *cr);
int cachefs_frontfile_size(cnode_t *cp, u_offset_t length);
int cachefs_req_create(void *, void *, int);
void cachefs_req_destroy(void *, void *);
int cachefs_stop_cache(cnode_t *);


/* cachefs_resource.c */
void cachefs_rlent_moveto_nolock(cachefscache_t *cachep,
    enum cachefs_rl_type type, uint_t entno, size_t);
void cachefs_rlent_moveto(cachefscache_t *, enum cachefs_rl_type, uint_t,
    size_t);
void cachefs_rlent_verify(cachefscache_t *, enum cachefs_rl_type, uint_t);
void cachefs_rl_changefileno(cachefscache_t *cachep, uint_t entno,
	ino64_t fileno);
int cachefs_rlent_data(cachefscache_t *cachep, rl_entry_t *valp,
    uint_t *entnop);
void cachefs_move_modified_to_mf(cachefscache_t *cachep, fscache_t *fscp);
int cachefs_allocblocks(cachefscache_t *, size_t, enum cachefs_rl_type);
void cachefs_freeblocks(cachefscache_t *, size_t, enum cachefs_rl_type);
void cachefs_freefile(cachefscache_t *);
int cachefs_allocfile(cachefscache_t *);
int cachefs_rl_alloc(struct cachefscache *cachep, rl_entry_t *valp,
    uint_t *entnop);
int cachefs_rl_attrc(struct cachefscache *, int, int);
void cachefs_cachep_worker_thread(cachefscache_t *);
void cachefs_rl_cleanup(cachefscache_t *);
int cachefs_rl_entry_get(cachefscache_t *, uint_t, rl_entry_t **);
#ifdef CFSRLDEBUG
void cachefs_rl_debug_save(rl_entry_t *);
void cachefs_rl_debug_show(rl_entry_t *);
void cachefs_rl_debug_destroy(rl_entry_t *);
#endif /* CFSRLDEBUG */

/* cachefs_log.c */
int cachefs_log_kstat_snapshot(kstat_t *, void *, int);
void cachefs_log_process_queue(cachefscache_t *, int);
int cachefs_log_logfile_open(cachefscache_t *, char *);
struct cachefs_log_cookie
	*cachefs_log_create_cookie(struct cachefs_log_control *);
void cachefs_log_error(cachefscache_t *, int, int);
void cachefs_log_destroy_cookie(struct cachefs_log_cookie *);

void cachefs_log_mount(cachefscache_t *, int, struct vfs *,
    fscache_t *, char *, enum uio_seg, char *);
void cachefs_log_umount(cachefscache_t *, int, struct vfs *);
void cachefs_log_getpage(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t, u_offset_t, size_t);
void cachefs_log_readdir(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t, u_offset_t, int);
void cachefs_log_readlink(cachefscache_t *, int, struct vfs *,
    fid_t *, ino64_t, uid_t, size_t);
void cachefs_log_remove(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t);
void cachefs_log_rmdir(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t);
void cachefs_log_truncate(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t, u_offset_t);
void cachefs_log_putpage(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t, u_offset_t, size_t);
void cachefs_log_create(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t);
void cachefs_log_mkdir(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t);
void cachefs_log_rename(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    int, uid_t);
void cachefs_log_symlink(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t, int);
void cachefs_log_populate(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    u_offset_t, size_t);
void cachefs_log_csymlink(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    int);
void cachefs_log_filldir(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    u_offset_t);
void cachefs_log_mdcreate(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uint_t);
void cachefs_log_gpfront(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t, u_offset_t, uint_t);
void cachefs_log_rfdir(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    uid_t);
void cachefs_log_ualloc(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    u_offset_t, size_t);
void cachefs_log_calloc(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t,
    u_offset_t, size_t);
void cachefs_log_nocache(cachefscache_t *, int, struct vfs *, fid_t *, ino64_t);

/* cachefs_vnops.c */
struct vnodeops *cachefs_getvnodeops(void);
int cachefs_lookup_common(vnode_t *dvp, char *nm, vnode_t **vpp,
    struct pathname *pnp, int flags, vnode_t *rdir, cred_t *cr);
int cachefs_putpage_common(struct vnode *vp, offset_t off,
    size_t len, int flags, cred_t *cr);
ino64_t cachefs_fileno_conflict(fscache_t *fscp, ino64_t old);
int cachefs_remove_connected(vnode_t *dvp, char *nm, cred_t *cr,
    vnode_t *vp);
int cachefs_remove_disconnected(vnode_t *dvp, char *nm, cred_t *cr,
    vnode_t *vp);
int cachefs_cacheacl(cnode_t *, vsecattr_t *);
void cachefs_purgeacl(cnode_t *);
int cachefs_vtype_aclok(vnode_t *);

/* cachefs_vfsops.c */
int cachefs_init_vfsops(int);
int cachefs_init_vnops(char *);
void cachefs_kstat_mount(struct fscache *, char *, char *, char *, char *);
void cachefs_kstat_umount(int);
int cachefs_kstat_key_update(kstat_t *, int);
int cachefs_kstat_key_snapshot(kstat_t *, void *, int);

extern void cachefs_workq_init(struct cachefs_workq *);
extern void cachefs_addqueue(struct cachefs_req *, struct cachefs_workq *);


extern void *cachefs_kmem_alloc(size_t, int);
extern void *cachefs_kmem_zalloc(size_t, int);
extern void cachefs_kmem_free(void *, size_t);
extern char *cachefs_strdup(char *);

#endif /* defined (_KERNEL) */



#define	C_RL_MAXENTS	0x4000		/* Whatever */

/*
 * ioctls.
 */
#include <sys/ioccom.h>
#define	_FIOCOD		_IO('f', 78)		/* consistency on demand */
#define	_FIOSTOPCACHE	_IO('f', 86)		/* stop using cache */

#define	CACHEFSIO_PACK		_IO('f', 81)
#define	CACHEFSIO_UNPACK	_IO('f', 82)
#define	CACHEFSIO_UNPACKALL	_IO('f', 83)
#define	CACHEFSIO_PACKINFO	_IO('f', 84)
#define	CACHEFSIO_DCMD		_IO('f', 85)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FS_CACHEFS_FS_H */
