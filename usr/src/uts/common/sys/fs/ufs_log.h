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

#ifndef _SYS_FS_UFS_LOG_H
#define	_SYS_FS_UFS_LOG_H

#include <sys/buf.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_filio.h>
#include <sys/fs/ufs_inode.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct lufs_save {
	buf_t		*sv_bp;
	size_t		sv_nb_left;
	int		sv_error;
} lufs_save_t;

typedef struct lufs_buf {
	buf_t		lb_buf;
	void		*lb_ptr;
} lufs_buf_t;

/*
 * Log space is stored as extents
 */
#define	LUFS_EXTENTS	(UINT32_C(0))
#define	LS_SECTORS	2

typedef struct extent {
	uint32_t	lbno;	/* Logical block # within the space */
	uint32_t	pbno;	/* Physical block number of extent. */
				/* in disk blocks for non-MTB ufs */
				/* in frags for MTB ufs */
	uint32_t	nbno;	/* # blocks in this extent */
} extent_t;

typedef struct ic_extent {
	uint32_t	ic_lbno;	/* Logical block # within the space */
	uint32_t	ic_nbno;	/* # blocks in this extent */
	daddr_t		ic_pbno;	/* Physical block number of extent. */
					/* (always in disk blocks) 	*/
} ic_extent_t;

typedef struct extent_block {
	uint32_t	type;		/* Set to LUFS_EXTENTS to identify */
					/*   structure on disk. */
	int32_t		chksum;		/* Checksum over entire block. */
	uint32_t	nextents;	/* Size of extents array. */
	uint32_t	nbytes;		/* # bytes mapped by extent_block. */
	uint32_t	nextbno;	/* blkno of next extent_block. */
	extent_t	extents[1];
} extent_block_t;

typedef struct ic_extent_block {
	uint32_t	ic_nextents;	/* Size of extents array. */
	uint32_t	ic_nbytes;	/* # bytes mapped by extent_block. */
	uint32_t	ic_nextbno;	/* blkno of next extent_block. */
	ic_extent_t	ic_extents[1];
} ic_extent_block_t;

/*
 * Don't size the incore buffers too small or too large
 */
#define	LDL_MINTRANSFER		(UINT32_C(32768))	/* 32 k */
#define	LDL_MAXTRANSFER		(UINT32_C(1048576))	/* 1 M */

/*
 * LDL_DIVISOR (ldl_divisor) is the number to calculate the log size
 * from the file system size according to the calculation in lufs_enable()
 */
#define	LDL_DIVISOR		1024 /* 1024 gives 1MB per 1GB */

/*
 * This gives the maximum size of log for which the 1MB per 1GB rule
 * applies. The size of the log will only be greater than this based
 * on the cylinder group space requirements.
 */
#define	LDL_SOFTLOGCAP		(256 * 1024 * 1024)

/*
 * But set reasonable min/max units
 */
#define	LDL_MINLOGSIZE		(1024 * 1024)
#define	LDL_MAXLOGSIZE		(512 * 1024 * 1024)

/*
 * Log space requirement per cylinder group. This needs to accommodate a
 * cg delta (inc. header) and have a factor to cover other deltas involved
 * in a single transaction which could touch all cyl groups in a file system.
 */
#define	LDL_CGSIZEREQ(fs) \
	((fs)->fs_cgsize + ((fs)->fs_cgsize >> 1))

#define	LDL_MINBUFSIZE		(32 * 1024)
#define	LDL_USABLE_BSIZE	(DEV_BSIZE - sizeof (sect_trailer_t))
#define	NB_LEFT_IN_SECTOR(off) 	(LDL_USABLE_BSIZE - ((off) - dbtob(btodb(off))))

typedef struct cirbuf {
	buf_t		*cb_bp;		/* buf's with space in circular buf */
	buf_t		*cb_dirty;	/* filling this buffer for log write */
	buf_t		*cb_free;	/* free bufs list */
	caddr_t		cb_va;		/* address of circular buffer */
	size_t		cb_nb;		/* size of circular buffer */
	krwlock_t	cb_rwlock;	/* r/w lock to protect list mgmt. */
} cirbuf_t;

#define	LUFS_VERSION		(UINT32_C(1))	/* Version 1 */
#define	LUFS_VERSION_LATEST	LUFS_VERSION

/*
 * The old Disksuite unit structure has been split into two parts -- the
 * incore part which is created at run time and the ondisk structure.  To
 * minimize code changes, the incore structure retains the old name,
 * ml_unit_t and the ondisk structure is called ml_odunit_t.  The ondisk
 * structure is stored at the beginning of the log.
 *
 * This structure must fit into a sector (512b)
 *
 */
typedef struct ml_odunit {
	uint32_t	od_version;	/* version number */
	uint32_t	od_badlog;	/* is the log okay? */
	uint32_t	od_unused1;

	/*
	 * Important constants
	 */
	uint32_t	od_maxtransfer;	/* max transfer in bytes */
	uint32_t	od_devbsize;	/* device bsize */
	int32_t		od_bol_lof;	/* byte offset to begin of log */
	int32_t		od_eol_lof;	/* byte offset to end of log */

	/*
	 * The disk space is split into state and circular log
	 */
	uint32_t	od_requestsize;	/* size requested by user */
	uint32_t	od_statesize;	/* size of state area in bytes */
	uint32_t	od_logsize;	/* size of log area in bytes */
	int32_t		od_statebno;	/* first block of state area */
	int32_t		od_unused2;

	/*
	 * Head and tail of log
	 */
	int32_t		od_head_lof;	/* byte offset of head */
	uint32_t	od_head_ident;	/* head sector id # */
	int32_t		od_tail_lof;	/* byte offset of tail */
	uint32_t	od_tail_ident;	/* tail sector id # */
	uint32_t	od_chksum;	/* checksum to verify ondisk contents */

	/*
	 * Used for error recovery
	 */
	uint32_t	od_head_tid;	/* used for logscan; set at sethead */

	/*
	 * Debug bits
	 */
	int32_t		od_debug;

	/*
	 * Misc
	 */
	struct timeval	od_timestamp;	/* time of last state change */
} ml_odunit_t;

typedef struct ml_unit {
	struct ml_unit	*un_next;	/* next incore log */
	int		un_flags;	/* Incore state */
	buf_t		*un_bp;		/* contains memory for un_ondisk */
	struct ufsvfs	*un_ufsvfs;	/* backpointer to ufsvfs */
	dev_t		un_dev;		/* for convenience */
	ic_extent_block_t *un_ebp;	/* block of extents */
	size_t		un_nbeb;	/* # bytes used by *un_ebp */
	struct mt_map	*un_deltamap;	/* deltamap */
	struct mt_map	*un_logmap;	/* logmap includes moby trans stuff */
	struct mt_map	*un_matamap;	/* optional - matamap */

	/*
	 * Used for managing transactions
	 */
	uint32_t	un_maxresv;	/* maximum reservable space */
	uint32_t	un_resv;	/* reserved byte count for this trans */
	uint32_t	un_resv_wantin;	/* reserved byte count for next trans */

	/*
	 * Used during logscan
	 */
	uint32_t	un_tid;

	/*
	 * Read/Write Buffers
	 */
	cirbuf_t	un_rdbuf;	/* read buffer space */
	cirbuf_t	un_wrbuf;	/* write buffer space */

	/*
	 * Ondisk state
	 */
	ml_odunit_t	un_ondisk;	/* ondisk log information */

	/*
	 * locks
	 */
	kmutex_t	un_log_mutex;	/* allows one log write at a time */
	kmutex_t	un_state_mutex;	/* only 1 state update at a time */
} ml_unit_t;

/*
 * Macros to allow access to the ondisk elements via the ml_unit_t incore
 * structure.
 */

#define	un_version	un_ondisk.od_version
#define	un_badlog	un_ondisk.od_badlog
#define	un_maxtransfer	un_ondisk.od_maxtransfer
#define	un_devbsize	un_ondisk.od_devbsize
#define	un_bol_lof	un_ondisk.od_bol_lof
#define	un_eol_lof	un_ondisk.od_eol_lof
#define	un_statesize	un_ondisk.od_statesize
#define	un_logsize	un_ondisk.od_logsize
#define	un_statebno	un_ondisk.od_statebno
#define	un_requestsize	un_ondisk.od_requestsize
#define	un_head_lof	un_ondisk.od_head_lof
#define	un_head_ident	un_ondisk.od_head_ident
#define	un_tail_lof	un_ondisk.od_tail_lof
#define	un_tail_ident	un_ondisk.od_tail_ident
#define	un_chksum	un_ondisk.od_chksum
#define	un_head_tid	un_ondisk.od_head_tid
#define	un_debug	un_ondisk.od_debug
#define	un_timestamp	un_ondisk.od_timestamp

/*
 *	un_flags
 */
#define	LDL_SCAN	0x0001	/* log scan in progress */
#define	LDL_ERROR	0x0002	/* in error state */
#define	LDL_NOROLL	0x0004  /* Log Not Yet Rollable */

typedef struct sect_trailer {
	uint32_t	st_tid;		/* transaction id */
	uint32_t	st_ident;	/* unique sector id */
} sect_trailer_t;

/*
 * map block
 */
#define	MAPBLOCKSIZE	(8192)
#define	MAPBLOCKSHIFT	(13)
#define	MAPBLOCKOFF	(MAPBLOCKSIZE-1)
#define	MAPBLOCKMASK	(~MAPBLOCKOFF)
#define	DEV_BMASK	(DEV_BSIZE - 1)

/*
 * cached roll buffer
 */
typedef struct crb {
	int64_t		c_mof;		/* master file offset of buffer */
	caddr_t		c_buf;		/* pointer to cached roll buffer */
	uint32_t	c_nb;		/* size of buffer */
	ushort_t	c_refcnt;	/* reference count on crb */
	uchar_t		c_invalid;	/* crb should not be used */
} crb_t;

#define	CRB_END ((crb_t *)1) /* must be non zero */

/*
 * delta header
 */
struct delta {
	int64_t		d_mof;	/* byte offset on device to start writing */
				/*   delta */
	int32_t		d_nb;	/* # bytes in the delta */
	delta_t 	d_typ;	/* Type of delta.  Defined in ufs_trans.h */
};
/*
 * common map entry
 */
typedef struct mapentry	mapentry_t;
struct mapentry {
	/*
	 * doubly linked list of all mapentries in map -- MUST BE FIRST
	 */
	mapentry_t	*me_next;
	mapentry_t	*me_prev;

	mapentry_t	*me_hash;
	mapentry_t	*me_agenext;
	mapentry_t	*me_cancel;
	crb_t		*me_crb;
	int		(*me_func)();
	ulong_t		me_arg;
	ulong_t		me_age;
	struct delta	me_delta;
	uint32_t	me_tid;
	off_t		me_lof;
	ushort_t	me_flags;
};

#define	me_mof	me_delta.d_mof
#define	me_nb	me_delta.d_nb
#define	me_dt	me_delta.d_typ

/*
 * me_flags
 */
#define	ME_SCAN		(0x0001)	/* entry from log scan */
#define	ME_HASH		(0x0002)	/* on hash   list */
#define	ME_CANCEL	(0x0004)	/* on cancel list */
#define	ME_AGE		(0x0008)	/* on age    list */
#define	ME_LIST		(0x0010)	/* on list   list */
#define	ME_ROLL		(0x0020)	/* on pseudo-roll list */
#define	ME_USER		(0x0040)	/* User Block DT_CANCEL entry */

/*
 * MAP TYPES
 */
enum maptypes	{
	deltamaptype, logmaptype, matamaptype
};

/*
 * MAP
 */
#define	DELTAMAP_NHASH	(512)
#define	LOGMAP_NHASH	(2048)
#define	MAP_INDEX(mof, mtm) \
	(((mof) >> MAPBLOCKSHIFT) & (mtm->mtm_nhash-1))
#define	MAP_HASH(mof, mtm) \
	((mtm)->mtm_hash + MAP_INDEX((mof), (mtm)))

typedef struct mt_map {
	/*
	 * anchor doubly linked list this map's entries -- MUST BE FIRST
	 */
	mapentry_t	*mtm_next;
	mapentry_t	*mtm_prev;

	enum maptypes	mtm_type;	/* map type */
	int		mtm_flags;	/* generic flags */
	int		mtm_ref;	/* PTE like ref bit */
	ulong_t		mtm_debug;	/* set at create time */
	ulong_t		mtm_age;	/* mono-inc; tags mapentries */
	mapentry_t	*mtm_cancel;	/* to be canceled at commit */
	ulong_t		mtm_nhash;	/* # of hash anchors */
	mapentry_t	**mtm_hash;	/* array of singly linked lists */
	struct topstats	*mtm_tops;	/* trans ops - enabled by an ioctl */
	long		mtm_nme;	/* # of mapentries */
	long		mtm_nmet;	/* # of mapentries this transaction */
	long		mtm_cfrags;	/* Canceled frags */
	long		mtm_cfragmax;	/* Maximum canceled frags */
	/*
	 * used after logscan to set the log's tail
	 */
	off_t		mtm_tail_lof;
	size_t		mtm_tail_nb;

	/*
	 * debug field for Scan test
	 */
	off_t		mtm_trimlof;	/* log was trimmed to this lof */
	off_t		mtm_trimtail;	/* tail lof before trimming */
	off_t		mtm_trimalof;	/* lof of last allocation delta */
	off_t		mtm_trimclof;	/* lof of last commit delta */
	off_t		mtm_trimrlof;	/* lof of last rolled delta */
	ml_unit_t	*mtm_ul;	/* log unit for this map */

	/*
	 * moby trans stuff
	 */
	uint32_t		mtm_tid;
	uint32_t		mtm_committid;
	ushort_t		mtm_closed;
	ushort_t		mtm_seq;
	long			mtm_wantin;
	long			mtm_active;
	long			mtm_activesync;
	ulong_t			mtm_dirty;
	kmutex_t		mtm_lock;
	kcondvar_t		mtm_cv_commit;
	kcondvar_t		mtm_cv_next;
	kcondvar_t		mtm_cv_eot;

	/*
	 * mutex that protects all the fields in mt_map except
	 * mtm_mapnext and mtm_refcnt
	 */
	kmutex_t	mtm_mutex;

	/*
	 * logmap only condition variables
	 */
	kcondvar_t	mtm_to_roll_cv; /* roll log or kill roll thread */
	kcondvar_t	mtm_from_roll_cv; /* log rolled or thread exiting */

	/*
	 * rw lock for the agenext mapentry field
	 */
	krwlock_t	mtm_rwlock;
	/*
	 * DEBUG: runtestscan
	 */
	kmutex_t	mtm_scan_mutex;

	/*
	 * logmap only taskq sync count variable, protected by mtm_lock.
	 * keeps track of the number of pending top_issue_sync
	 * dispatches.
	 */
	int		mtm_taskq_sync_count;

	/*
	 * logmap only condition variable, to synchronize with lufs_unsnarf.
	 */
	kcondvar_t	mtm_cv;
} mt_map_t;

/*
 * mtm_flags
 */
#define	MTM_ROLL_EXIT		0x00000001 /* force roll thread to exit */
#define	MTM_ROLL_RUNNING	0x00000002 /* roll thread is running */
#define	MTM_FORCE_ROLL		0x00000004 /* force at least one roll cycle */
#define	MTM_ROLLING		0x00000008 /* currently rolling the log */
#define	MTM_CANCELED		0x00000010 /* cancel entries were removed */

/*
 * Generic range checking macros
 */
#define	OVERLAP(sof, snb, dof, dnb) \
	(((sof) >= (dof) && (sof) < ((dof) + (dnb))) || \
	((dof) >= (sof) && (dof) < ((sof) + (snb))))
#define	WITHIN(sof, snb, dof, dnb) \
	(((sof) >= (dof)) && (((sof) + (snb)) <= ((dof) + (dnb))))
#define	DATAoverlapME(mof, hnb, me) \
	(OVERLAP((mof), (hnb), (me)->me_mof, (me)->me_nb))
#define	MEwithinDATA(me, mof, hnb) \
	(WITHIN((me)->me_mof, (me)->me_nb, (mof), (hnb)))
#define	DATAwithinME(mof, hnb, me) \
	(WITHIN((mof), (hnb), (me)->me_mof, (me)->me_nb))
#define	DATAwithinCRB(mof, nb, crb) \
	(WITHIN((mof), (nb), (crb)->c_mof, (crb)->c_nb))

/*
 * TRANSACTION OPS STATS
 */
typedef struct topstats {
	uint64_t	mtm_top_num[TOP_MAX];
	uint64_t	mtm_top_size_etot[TOP_MAX];
	uint64_t	mtm_top_size_rtot[TOP_MAX];
	uint64_t	mtm_top_size_max[TOP_MAX];
	uint64_t	mtm_top_size_min[TOP_MAX];
	uint64_t	mtm_delta_num[DT_MAX];
} topstats_t;

/*
 * fio_lufs_stats_t is used by _FIO_GET_TOP_STATS ioctl for getting topstats
 */
typedef struct fio_lufs_stats {
	uint32_t	ls_debug;	/* out: un_debug value */
	uint32_t	_ls_pad;	/* make size 64-bit aligned on x86 */
	topstats_t	ls_topstats;	/* out: transaction stats */
} fio_lufs_stats_t;

/*
 * roll buf structure; one per roll buffer
 */
typedef uint16_t rbsecmap_t;
typedef struct rollbuf {
	buf_t rb_bh;		/* roll buffer header */
	struct rollbuf *rb_next; /* link for mof ordered roll bufs */
	crb_t *rb_crb;		/* cached roll buffer to roll */
	mapentry_t *rb_age;	/* age list */
	rbsecmap_t rb_secmap;	/* sector map */
} rollbuf_t;

/*
 * un_debug
 *	MT_TRANSACT		- keep per thread accounting of tranactions
 *	MT_MATAMAP		- double check deltas and ops against matamap
 *	MT_WRITE_CHECK		- check master+deltas against metadata write
 *	MT_LOG_WRITE_CHECK	- read after write for log writes
 *	MT_CHECK_MAP		- check map after every insert/delete
 *	MT_TRACE		- trace transactions (used with MT_TRANSACT)
 *	MT_SIZE			- fail on size errors (used with MT_TRANSACT)
 *	MT_NOASYNC		- force every op to be sync
 *	MT_FORCEROLL		- forcibly roll the log after every commit
 *	MT_SCAN			- running runtestscan; special case as needed
 */
#define	MT_NONE			(0x00000000)
#define	MT_TRANSACT		(0x00000001)
#define	MT_MATAMAP		(0x00000002)
#define	MT_WRITE_CHECK		(0x00000004)
#define	MT_LOG_WRITE_CHECK	(0x00000008)
#define	MT_CHECK_MAP		(0x00000010)
#define	MT_TRACE		(0x00000020)
#define	MT_SIZE			(0x00000040)
#define	MT_NOASYNC		(0x00000080)
#define	MT_FORCEROLL		(0x00000100)
#define	MT_SCAN			(0x00000200)

struct logstats {
	kstat_named_t ls_lreads;	/* master reads */
	kstat_named_t ls_lwrites;	/* master writes */
	kstat_named_t ls_lreadsinmem;	/* log reads in memory */
	kstat_named_t ls_ldlreads;	/* log reads */
	kstat_named_t ls_ldlwrites;	/* log writes */
	kstat_named_t ls_mreads;	/* log master reads */
	kstat_named_t ls_rreads;	/* log roll reads */
	kstat_named_t ls_rwrites;	/* log roll writes */
};

#ifdef _KERNEL

typedef struct threadtrans {
	ulong_t		deltas_size;	/* size of deltas this transaction */
	uint32_t	last_async_tid;	/* last async transaction id */
	uchar_t		any_deltas;	/* any deltas done this transaction */
#ifdef DEBUG
	uint_t		topid;		/* transaction type */
	ulong_t		esize;		/* estimated trans size */
	ulong_t		rsize;		/* real trans size */
	dev_t		dev;		/* device */
#endif /* DEBUG */
} threadtrans_t;

/*
 * Log layer protos -- lufs_log.c
 */
extern void		ldl_strategy(ml_unit_t *, buf_t *);
extern void		ldl_round_commit(ml_unit_t *);
extern void		ldl_push_commit(ml_unit_t *);
extern int		ldl_need_commit(ml_unit_t *);
extern int		ldl_has_space(ml_unit_t *, mapentry_t *);
extern void		ldl_write(ml_unit_t *, caddr_t, offset_t, mapentry_t *);
extern void		ldl_waito(ml_unit_t *);
extern int		ldl_read(ml_unit_t *, caddr_t, offset_t, off_t,
					mapentry_t *);
extern void		ldl_sethead(ml_unit_t *, off_t, uint32_t);
extern void		ldl_settail(ml_unit_t *, off_t, size_t);
extern ulong_t		ldl_logscan_nbcommit(off_t);
extern int		ldl_logscan_read(ml_unit_t *, off_t *, size_t, caddr_t);
extern void		ldl_logscan_begin(ml_unit_t *);
extern void		ldl_logscan_end(ml_unit_t *);
extern int		ldl_need_roll(ml_unit_t *);
extern void		ldl_seterror(ml_unit_t *, char *);
extern size_t		ldl_bufsize(ml_unit_t *);
extern void		ldl_savestate(ml_unit_t *);
extern void		free_cirbuf(cirbuf_t *);
extern void		alloc_rdbuf(cirbuf_t *, size_t, size_t);
extern void		alloc_wrbuf(cirbuf_t *, size_t);

/*
 * trans driver layer -- lufs.c
 */
extern int		trans_not_wait(struct buf *cb);
extern int		trans_not_done(struct buf *cb);
extern int		trans_wait(struct buf *cb);
extern int		trans_done(struct buf *cb);
extern void		lufs_strategy(ml_unit_t *, buf_t *);
extern void		lufs_read_strategy(ml_unit_t *, buf_t *);
extern void		lufs_write_strategy(ml_unit_t *, buf_t *);
extern void		lufs_init(void);
extern uint32_t		lufs_hd_genid(const ml_unit_t *);
extern int		lufs_enable(struct vnode *, struct fiolog *, cred_t *);
extern int		lufs_disable(vnode_t *, struct fiolog *);

/*
 * transaction op layer -- lufs_top.c
 */
extern void	_init_top(void);
extern int	top_read_roll(rollbuf_t *, ml_unit_t *);


/*
 * map layer -- lufs_map.c
 */
extern void		map_free_entries(mt_map_t *);
extern int		matamap_overlap(mt_map_t *, offset_t, off_t);
extern int		matamap_within(mt_map_t *, offset_t, off_t);
extern int		deltamap_need_commit(mt_map_t *);
extern void		deltamap_add(mt_map_t *, offset_t, off_t, delta_t,
				int (*)(), ulong_t, threadtrans_t *tp);
extern mapentry_t	*deltamap_remove(mt_map_t *, offset_t, off_t);
extern void		deltamap_del(mt_map_t *, offset_t, off_t);
extern void		deltamap_push(ml_unit_t *);
extern void		logmap_cancel_remove(mt_map_t *);
extern int		logmap_need_commit(mt_map_t *);
extern int		logmap_need_roll_async(mt_map_t *);
extern int		logmap_need_roll_sync(mt_map_t *);
extern void		logmap_start_roll(ml_unit_t *);
extern void		logmap_kill_roll(ml_unit_t *);
extern void		logmap_forceroll(mt_map_t *);
extern void		logmap_forceroll_nowait(mt_map_t *);
extern int		logmap_overlap(mt_map_t *, offset_t, off_t);
extern void		logmap_remove_roll(mt_map_t *, offset_t, off_t);
extern int		logmap_next_roll(mt_map_t *, offset_t *);
extern int		logmap_list_get(mt_map_t *, offset_t, off_t,
				mapentry_t **);
extern int		logmap_list_get_roll(mt_map_t *, offset_t, rollbuf_t *);
extern void		logmap_list_put(mt_map_t *, mapentry_t *);
extern void		logmap_list_put_roll(mt_map_t *, mapentry_t *);
extern int		logmap_setup_read(mapentry_t *, rollbuf_t *);
extern void		logmap_make_space(struct mt_map *, ml_unit_t *,
				mapentry_t *);
extern void		logmap_add(ml_unit_t *, char *, offset_t, mapentry_t *);
extern void		logmap_add_buf(ml_unit_t *, char *, offset_t,
				mapentry_t *, caddr_t, uint32_t);
extern void		logmap_commit(ml_unit_t *, uint32_t);
extern void		logmap_sethead(mt_map_t *, ml_unit_t *);
extern void		logmap_settail(mt_map_t *, ml_unit_t *);
extern void		logmap_roll_dev(ml_unit_t *ul);
extern void		logmap_cancel(ml_unit_t *, offset_t, off_t, int);
extern void		logmap_free_cancel(mt_map_t *, mapentry_t **);
extern int		logmap_iscancel(mt_map_t *, offset_t, off_t);
extern void		logmap_logscan(ml_unit_t *);
extern mt_map_t		*map_put(mt_map_t *);
extern mt_map_t		*map_get(ml_unit_t *, enum maptypes, int);
extern void		_init_map(void);

/*
 * scan and roll threads -- lufs_thread.c
 */
extern void	trans_roll(ml_unit_t *);

/*
 * DEBUG
 */
#ifdef	DEBUG
extern int	map_put_debug(mt_map_t *);
extern int	map_get_debug(ml_unit_t *, mt_map_t *);
extern int	top_write_debug(ml_unit_t *, mapentry_t *, offset_t, off_t);
extern int	matamap_overlap(mt_map_t *, offset_t, off_t);
extern int	ldl_sethead_debug(ml_unit_t *);
extern int	map_check_linkage(mt_map_t *);
extern int	logmap_logscan_debug(mt_map_t *, mapentry_t *);
extern int	map_check_ldl_write(ml_unit_t *, caddr_t, offset_t,
								mapentry_t *);
extern int	logmap_logscan_commit_debug(off_t, mt_map_t *);
extern int	logmap_logscan_add_debug(struct delta *, mt_map_t *);
extern int	top_delta_debug(ml_unit_t *, offset_t, off_t, delta_t);
extern int	top_begin_debug(ml_unit_t *, top_t, ulong_t);
extern int	top_end_debug(ml_unit_t *, mt_map_t *, top_t, ulong_t);
extern int	top_roll_debug(ml_unit_t *);
extern int	top_init_debug(void);
extern int	lufs_initialize_debug(ml_odunit_t *);
#endif	/* DEBUG */

extern uint64_t delta_stats[DT_MAX];
extern uint64_t roll_stats[DT_MAX];
extern struct logstats logstats;
extern int ufs_crb_enable;

extern uint_t topkey;
extern uint32_t ufs_ncg_log;

extern uint_t lufs_debug;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_LOG_H */
