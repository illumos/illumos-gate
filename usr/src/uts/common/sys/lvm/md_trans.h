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

#ifndef _SYS_MD_TRANS_H
#define	_SYS_MD_TRANS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/lvm/mdvar.h>
#include <sys/buf.h>
#include <sys/fs/ufs_trans.h>
#include <sys/lvm/md_rename.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LDL_META_SBLK		(16)

#define	LDL_MINLOGSIZE		(1024*1024)
#define	LDL_MAXLOGSIZE		(1024*1024*1024)
#define	LDL_MINBUFSIZE		(32*1024)
#define	LDL_USABLE_BSIZE	(DEV_BSIZE - sizeof (sect_trailer_t))
#define	NB_LEFT_IN_SECTOR(off) 	(LDL_USABLE_BSIZE - ((off) - dbtob(btodb(off))))

typedef struct cirbuf32 {
	caddr32_t	xx_cb_bp;	/* buf's with space in circular buf */
	caddr32_t	xx_cb_dirty;	/* filling this buffer for log write */
	caddr32_t	xx_cb_free;	/* free bufs list */
	caddr32_t	xx_cb_va;	/* address of circular buffer */
	uint_t		xx_cb_nb;	/* size of circular buffer */
	uint_t		xx_cb_rwlock[3]; /* r/w lock to protect list mgmt. */
} cirbuf32_t;

typedef struct cirbuf_ic {
	buf_t		*cb_bp;		/* buf's with space in circular buf */
	buf_t		*cb_dirty;	/* filling this buffer for log write */
	buf_t		*cb_free;	/* free bufs list */
	caddr_t		cb_va;		/* address of circular buffer */
	size_t		cb_nb;		/* size of circular buffer */
	md_krwlock_t	cb_rwlock;	/* r/w lock to protect list mgmt. */
} cirbuf_ic_t;


typedef struct ml_unit {
	uint_t		un_revision;	/* revision number */
	/*
	 * mdd infrastructure stuff
	 */
	mddb_recid_t	un_recid;	/* db record id */
	mdkey_t		un_key;		/* namespace key */
	md_dev64_t	un_dev;		/* device number */
	uint_t		un_opencnt;	/* open count */

	/*
	 * metatrans infrastructure stuff
	 */
	uint_t		un_transcnt;	/* #open metatrans devices */

	/*
	 * log specific stuff
	 */
	off32_t		un_head_lof;	/* byte offset of head */
	uint_t		un_head_ident;	/* head sector id # */
	off32_t		un_tail_lof;	/* byte offset of tail */
	uint_t		un_tail_ident;	/* tail sector id # */
	off32_t		un_bol_lof;	/* byte offset of begin of log */
	off32_t		un_eol_lof;	/* byte offset of end of log */
	daddr32_t	un_nblks;	/* total blocks of log space */
	daddr32_t	un_tblks;	/* total blocks in log device */
	uint_t		un_maxtransfer;	/* max transfer in bytes */
	uint_t		un_status;	/* status bits */
	uint_t		un_maxresv;	/* maximum reservable space */
	daddr32_t	un_pwsblk;	/* block number of prewrite area */
	ulong_t		un_devbsize;	/* device bsize */
	uint_t		un_resv;	/* reserved byte count for this trans */
	uint_t		un_resv_wantin;	/* reserved byte count for next trans */
	mt_l_error_t	un_error;	/* error state */
	uint_t		un_tid;		/* used during logscan */
	uint_t		un_head_tid;	/* used for logscan; set at sethead */
	struct timeval32 un_timestamp;	/* time of last state change */
	/*
	 * spares
	 */
	uint_t		un_spare[16];
	/*
	 * following are incore only elements.
	 * Incore elements must always be at the end
	 * of this data struture.
	 */
	struct ml_unit	*un_next;
	struct mt_unit	*un_utlist;
	struct mt_map	*un_logmap;
	cirbuf_ic_t	un_rdbuf;
	cirbuf_ic_t	un_wrbuf;
	kmutex_t	un_log_mutex;
} ml_unit_t;


#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct ml_unit32_od {
	uint_t		un_revision;	/* revision number */
	/*
	 * mdd infrastructure stuff
	 */
	caddr32_t	xx_un_next;	/* next log unit struct */
	mddb_recid_t	un_recid;	/* db record id */
	mdkey_t		un_key;		/* namespace key */
	dev32_t		un_dev;		/* device number */
	uint_t		un_opencnt;	/* open count */

	/*
	 * metatrans infrastructure stuff
	 */
	uint_t		un_transcnt;	/* #open metatrans devices */
	caddr32_t	xx_un_utlist;	/* list of metatrans devices */
	caddr32_t	xx_un_logmap;	/* address of logmap */

	/*
	 * log specific stuff
	 */
	off32_t		un_head_lof;	/* byte offset of head */
	uint_t		un_head_ident;	/* head sector id # */
	off32_t		un_tail_lof;	/* byte offset of tail */
	uint_t		un_tail_ident;	/* tail sector id # */
	off32_t		un_bol_lof;	/* byte offset of begin of log */
	off32_t		un_eol_lof;	/* byte offset of end of log */
	daddr32_t	un_nblks;	/* total blocks of log space */
	daddr32_t	un_tblks;	/* total blocks in log device */
	uint_t		un_maxtransfer;	/* max transfer in bytes */
	uint_t		un_status;	/* status bits */
	uint_t		un_maxresv;	/* maximum reservable space */
	daddr32_t	un_pwsblk;	/* block number of prewrite area */
	uint_t		un_devbsize;	/* device bsize */
	uint_t		un_resv;	/* reserved byte count for this trans */
	uint_t		un_resv_wantin;	/* reserved byte count for next trans */
	mt_l_error_t	un_error;	/* error state */
	uint_t		un_tid;		/* used during logscan */
	uint_t		un_head_tid;	/* used for logscan; set at sethead */
	cirbuf32_t	xx_un_rdbuf;	/* read buffer space */
	cirbuf32_t	xx_un_wrbuf;	/* write buffer space */
	int		xx_un_log_mutex[2]; /* allows one log write at a time */
	struct timeval32 un_timestamp;	/* time of last state change */
	/*
	 * spares
	 */
	uint_t		un_spare[16];
} ml_unit32_od_t;
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif



#define	ML_UNIT_ONDSZ	((size_t)((caddr_t)&((ml_unit_t *)0)->un_spare[15] +\
				sizeof (uint_t)))


/*
 *	un_status
 */
#define	LDL_BEING_RESET	0x0001	/* delete the log record at snarf */
#define	LDL_FIND_TAIL	0x0002	/* find tail of the log */
#define	LDL_SCAN_ACTIVE	0x0004	/* log scan in progress */
#define	LDL_METADEVICE	0x0008	/* underlying device is metadevice */
#define	LDL_PWVALID	0x0010	/* prewrite area is valid */
#define	LDL_INFO	0x0020	/* prewrite state is valid */

typedef struct sect_trailer {
	uint_t		st_tid;		/* transaction id */
	uint_t		st_ident;	/* unique sector id */
} sect_trailer_t;


/*
 * ioctls
 */
#define	MD_IOCGET_LOG		(MDIOC_MISC|0)
#define	MD_IOC_DEBUG		(MDIOC_MISC|4)
#define	MD_IOCGET_TRANSSTATS	(MDIOC_MISC|5)
#define	MD_IOC_TSD		(MDIOC_MISC|6)
#define	MD_IOC_TRYGETBLK	(MDIOC_MISC|7)
#define	MD_IOC_TRYPAGE		(MDIOC_MISC|8)
#define	MD_IOC_SETSHADOW	(MDIOC_MISC|11)
#define	MD_IOC_INJECTERRORS	(MDIOC_MISC|13)
#define	MD_IOC_STOPERRORS	(MDIOC_MISC|14)
#define	MD_IOC_UFSERROR		(MDIOC_MISC|15)
#define	MD_IOC_ISDEBUG		(MDIOC_MISC|17)

#define	MD_IOC_TRANS_DETACH	(MDIOC_MISC|32)

/*
 * following bits are used in status word in the common section
 * of unit structure
 */
#define	MD_UN_LOG_DELETED	(0x00010000)	/* don't need to del @snarf */

/*
 * map block
 */
#define	MAPBLOCKSIZE	(8192)
#define	MAPBLOCKSHIFT	(13)
#define	MAPBLOCKOFF	(MAPBLOCKSIZE-1)
#define	MAPBLOCKMASK	(~MAPBLOCKOFF)

/*
 * delta header
 */
struct delta {
	offset_t	d_mof;
	off32_t		d_nb;
	dev32_t		d_dev;
	delta_t 	d_typ;
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
	int		(*me_func)();
	uintptr_t	me_arg;
	off_t		me_lof;
	uint_t		me_flags;
	uint_t		me_tid;
	uint_t		me_age;
	struct delta	me_delta;
};

#define	me_mof	me_delta.d_mof
#define	me_nb	me_delta.d_nb
#define	me_dt	me_delta.d_typ
#define	me_dev	me_delta.d_dev

/*
 * me_flags
 */
#define	ME_FREE		(0x0001)	/* on free   list */
#define	ME_HASH		(0x0002)	/* on hash   list */
#define	ME_CANCEL	(0x0004)	/* on cancel list */
#define	ME_AGE		(0x0008)	/* on age    list */
#define	ME_LIST		(0x0010)	/* on list   list */
#define	ME_ROLL		(0x0020)	/* on pseudo-roll list */

/*
 * TRANSACTION OPS STATS
 * mt_top_size_* should be 64bit but that would
 * require test recompilations. It does not hurt the kernel
 * so leave as 32 bit for now.
 */
struct topstats {
	uint_t		mtm_top_num[TOP_MAX];
	uint_t		mtm_top_size_etot[TOP_MAX];
	uint_t		mtm_top_size_rtot[TOP_MAX];
	uint_t		mtm_top_size_max[TOP_MAX];
	uint_t		mtm_top_size_min[TOP_MAX];
	uint_t		mtm_delta_num[DT_MAX];
};

/*
 * MAP STATS (global struct that is not updated if compiled w/o ASSERTs)
 * some members of transstats need to be 64bit. See the comment above.
 */
struct transstats {
	/* trans.c */
	uint_t		ts_trans_zalloc;
	uint_t		ts_trans_zalloc_nosleep;
	uint_t		ts_trans_alloc;
	uint_t		ts_trans_alloc_nosleep;
	uint_t		ts_trans_free;
	uint_t		ts_trans_alloced;
	uint_t		ts_trans_freed;
	uint_t		ts_trans_write;
	uint_t		ts_trans_write_roll;

	/* trans_delta.c */
	uint_t		ts_mapentry_alloc;
	uint_t		ts_mapentry_alloc_list;
	uint_t		ts_mapentry_free;

	uint_t		ts_delta_add;
	uint_t		ts_delta_add_scan;
	uint_t		ts_delta_add_hit;

	uint_t		ts_delta_remove;
	uint_t		ts_delta_remove_scan;
	uint_t		ts_delta_remove_hit;

	uint_t		ts_delta_del;
	uint_t		ts_delta_del_scan;

	uint_t		ts_delta_push;

	uint_t		ts_overlap;
	uint_t		ts_overlap_scan;
	uint_t		ts_overlap_hit;

	uint_t		ts_remove_roll;
	uint_t		ts_remove_roll_scan;
	uint_t		ts_remove_roll_hit;
	uint_t		ts_remove_roll_dolock;
	uint_t		ts_remove_roll_sud;

	uint_t		ts_next_roll;
	uint_t		ts_next_roll_scan;
	uint_t		ts_next_roll_hit;

	uint_t		ts_list_age;
	uint_t		ts_list_age_scan;

	uint_t		ts_list_get;
	uint_t		ts_list_get_scan;
	uint_t		ts_list_get_hit;
	uint_t		ts_list_get_again;

	uint_t		ts_list_put;
	uint_t		ts_list_put_scan;

	uint_t		ts_read_mstr;

	uint_t		ts_logmap_secmap_roll;

	uint_t		ts_read_log;

	uint_t		ts_logmap_abort;
	uint_t		ts_logmap_abort_hit;

	uint_t		ts_list_add;
	uint_t		ts_list_add_scan;
	uint_t		ts_list_add_cancel;
	uint_t		ts_list_add_unhash;

	uint_t		ts_free_cancel;
	uint_t		ts_free_cancel_again;
	uint_t		ts_free_cancel_scan;
	uint_t		ts_free_cancel_hit;

	uint_t		ts_commit;
	uint_t		ts_commit_hit;

	uint_t		ts_logmap_roll_dev;
	uint_t		ts_logmap_roll_dev_scan;
	uint_t		ts_logmap_roll_dev_hit;

	uint_t		ts_logmap_roll_sud;
	uint_t		ts_logmap_roll_sud_hit;

	uint_t		ts_logmap_ud_done;
	uint_t		ts_logmap_ud_done_scan;

	uint_t		ts_logmap_ud_wait;
	uint_t		ts_logmap_ud_wait_hit;

	uint_t		ts_logmap_ud_commit;
	uint_t		ts_logmap_ud_commit_scan;

	uint_t		ts_logmap_cancel;
	uint_t		ts_logmap_cancel_scan;
	uint_t		ts_logmap_cancel_hit;

	uint_t		ts_logmap_iscancel;
	uint_t		ts_logmap_iscancel_scan;
	uint_t		ts_logmap_iscancel_hit;

	uint_t		ts_logscan;
	uint_t		ts_logscan_ud;
	uint_t		ts_logscan_delta;
	uint_t		ts_logscan_cancel;
	uint_t		ts_logscan_commit;

	/* trans_thread.c */
	uint_t		ts_prewrite;
	uint_t		ts_prewrite_read;
	uint_t		ts_prewrite_write;
	uint_t		ts_trans_roll;
	uint_t		ts_trans_roll_wait;
	uint_t		ts_trans_roll_wait_nada;
	uint_t		ts_trans_roll_wait_slow;
	uint_t		ts_trans_roll_force;
	uint_t		ts_trans_roll_nsud;
	uint_t		ts_trans_roll_ref;
	uint_t		ts_trans_roll_full;
	uint_t		ts_trans_roll_logmap;
	uint_t		ts_trans_roll_read;
	uint_t		ts_trans_roll_reread;
	uint_t		ts_trans_roll_wait_inuse;
	uint_t		ts_trans_roll_prewrite;
	uint_t		ts_trans_roll_write;

	/* trans_top.c */
	uint_t		ts_delta;
	uint_t		ts_ud_delta;
	uint_t		ts_ud_delta_log;
	uint_t		ts_cancel;
	uint_t		ts_iscancel;
	uint_t		ts_error;
	uint_t		ts_iserror;
	uint_t		ts_beginsync;
	uint_t		ts_active;
	uint_t		ts_activesync;
	uint_t		ts_beginasync;
	uint_t		ts_endsync;
	uint_t		ts_wantin;
	uint_t		ts_endasync;
	uint_t		ts_read;
	uint_t		ts_read_roll;
	uint_t		ts_readmt;
	uint_t		ts_write;
	uint_t		ts_writemt;
	uint_t		ts_writemt_done;
	uint_t		ts_log;

	/* trans_log.c */
	uint_t		ts_logcommitdb;

	uint_t		ts_push_dirty_bp;
	uint_t		ts_push_dirty_bp_extra;
	uint_t		ts_push_dirty_bp_fail;

	uint_t		ts_alloc_bp;
	uint_t		ts_alloc_bp_free;

	uint_t		ts_find_bp;
	uint_t		ts_find_bp_scan;
	uint_t		ts_find_bp_hit;

	uint_t		ts_find_read_lof;
	uint_t		ts_find_read_lof_scan;
	uint_t		ts_find_read_lof_hit;

	uint_t		ts_get_read_bp;
	uint_t		ts_get_read_bp_wr;
	uint_t		ts_get_read_bp_rd;

	uint_t		ts_extend_write_bp;
	uint_t		ts_extend_write_bp_hit;

	uint_t		ts_storebuf;
	uint_t		ts_fetchbuf;
	uint_t		ts_round_commit;
	uint_t		ts_push_commit;

	uint_t		ts_inval_range;
	uint_t		ts_inval_range_scan;
	uint_t		ts_inval_range_hit;

	uint_t		ts_writelog;
	uint_t		ts_writelog_max;

	uint_t		ts_readlog;
	uint_t		ts_readlog_max;

	uint_t		ts_get_write_bp;
	uint_t		ts_get_write_bp_steal;

	uint_t		ts_writesync;
	uint_t		ts_writesync_log;
	uint_t		ts_writesync_nolog;

	uint_t		ts_longmof_cnt;

} transstats;

#ifdef	DEBUG
#define	TRANSSTATS(f)		(transstats.f++)
#define	TRANSSTATSADD(f, n)	(transstats.f += (n))
#define	TRANSSTATSMAX(m, v)	\
		if ((v) > transstats.m)\
			transstats.m = (v);
#else
#define	TRANSSTATS(f)
#define	TRANSSTATSADD(f, n)
#define	TRANSSTATSMAX(m, v)
#endif /* DEBUG */

/*
 * MAP TYPES
 */
enum maptypes	{
	deltamaptype, udmaptype, logmaptype, matamaptype, shadowmaptype
};

/*
 * MAP
 */
#define	DELTAMAP_NHASH	(512)
#define	LOGMAP_NHASH	(2048)
#define	MAP_INDEX(dev, mof, mtm) \
	((((mof) >> MAPBLOCKSHIFT) + (dev)) & ((mtm)->mtm_nhash-1))
#define	MAP_HASH(dev, mof, mtm) \
	(mtm->mtm_hash + MAP_INDEX(dev, mof, mtm))

typedef struct mt_map {
	/*
	 * anchor doubly linked list this map's entries -- MUST BE FIRST
	 */
	mapentry_t	*mtm_next;
	mapentry_t	*mtm_prev;

	int		mtm_flags;	/* generic flags */
	int		mtm_ref;	/* PTE like ref bit */
	uint_t		mtm_debug;	/* set at create time */
	uint_t		mtm_age;	/* mono-inc; tags mapentries */
	mapentry_t	*mtm_cancel;	/* to be canceled at commit */
	uint_t		mtm_nhash;	/* # of hash anchors */
	mapentry_t	**mtm_hash;	/* array of singly linked lists */
	struct topstats	*mtm_tops;	/* trans ops - enabled by an ioctl */
	int		mtm_nme;	/* # of mapentries */
	int		mtm_nmet;	/* # of mapentries this transaction */
	int		mtm_nud;	/* # of active userdata writes */
	int		mtm_nsud;	/* # of userdata scanned deltas */
	md_dev64_t	mtm_dev;	/* device identifying map */

	/*
	 * the following are protected by the global map_mutex
	 */
	struct mt_map	*mtm_mapnext;	/* singly linked list of all maps */
	uint_t		mtm_refcnt;	/* reference count to this map */
	enum maptypes	mtm_type;	/* type of map */

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
	struct ml_unit	*mtm_ul;	/* log unit for this map */

	/*
	 * moby trans stuff
	 */
	uint_t			mtm_tid;
	uint_t			mtm_committid;
	ushort_t		mtm_closed;
	ushort_t		mtm_seq;
	int			mtm_wantin;
	int			mtm_active;
	int			mtm_activesync;
	uint_t			mtm_dirty;
	kmutex_t		mtm_lock;
	kcondvar_t		mtm_cv_commit;
	kcondvar_t		mtm_cv_next;
	kcondvar_t		mtm_cv_eot;

	/*
	 * mutex that protects all the fields in mt_map except
	 * mtm_mapnext and mtm_refcnt
	 */
	kmutex_t	mtm_mutex;
	kcondvar_t	mtm_cv;		/* generic conditional */

	/*
	 * rw lock for the mapentry fields agenext and locnext
	 */
	md_krwlock_t	mtm_rwlock;
	/*
	 * DEBUG: runtestscan
	 */
	kmutex_t	mtm_scan_mutex;
} mt_map_t;

/*
 * mtm_flags
 */
#define	MTM_ROLL_EXIT		(0x00000001)
#define	MTM_ROLL_RUNNING	(0x00000002)
#define	MTM_FORCE_ROLL		(0x00000004)

/*
 * Generic range checking macros
 */
#define	OVERLAP(sof, snb, dof, dnb) \
	((sof >= dof && sof < (dof + dnb)) || \
	(dof >= sof && dof < (sof + snb)))

#define	WITHIN(sof, snb, dof, dnb) ((sof >= dof) && ((sof+snb) <= (dof+dnb)))

#define	DATAoverlapME(mof, hnb, me) (OVERLAP(mof, hnb, me->me_mof, me->me_nb))
#define	MEwithinDATA(me, mof, hnb) (WITHIN(me->me_mof, me->me_nb, mof, hnb))
#define	DATAwithinME(mof, hnb, me) (WITHIN(mof, hnb, me->me_mof, me->me_nb))


typedef struct mt_unit {
	struct mdc_unit	c;		/* common stuff */
	/*
	 * infrastructure
	 */
	mt_flags_t	un_flags;
	/*
	 * log and master device
	 */
	mdkey_t		un_m_key;
	md_dev64_t	un_m_dev;
	mdkey_t		un_l_key;
	md_dev64_t	un_l_dev;
	daddr32_t	un_l_sblk;	/* start block */
	daddr32_t	un_l_pwsblk;	/* prewrite start block */
	daddr32_t	un_l_nblks;	/* # of usable log blocks */
	daddr32_t	un_l_tblks;	/* total log blocks */
	daddr32_t	un_l_head;	/* sector offset of log head */
	daddr32_t	un_l_tail;	/* sector offset of log tail */
	uint_t		un_l_resv;	/* current log reservations */
	uint_t		un_l_maxresv;	/* max log reservations */
	uint_t		un_l_maxtransfer; /* maximum transfer at init */
	mddb_recid_t	un_l_recid;	/* database id */
	mt_l_error_t	un_l_error;	/* error state */
	struct timeval32 un_l_timestamp; /* time of last log state chg */
	md_dev64_t	un_s_dev;	/* shadow device for testing only */
	mt_debug_t	un_debug;	/* debug flags; set at create */
	md_dev64_t	un_dev;		/* this metatrans device */
	int		un_logreset;	/* part of _FIOLOGRESET ioctl stuff */
	struct timeval32 un_timestamp;	/* time of last trans state change */
	/*
	 * spares
	 */
	ulong_t		un_spare[16];
	/*
	 * following are incore only elements.
	 * Incore elements must always be at the end
	 * of this data struture.
	 */
	struct mt_unit	*un_next;
	struct ml_unit	*un_l_unit;
	struct ufstrans *un_ut;
	mt_map_t	*un_deltamap;
	mt_map_t	*un_udmap;
	mt_map_t	*un_logmap;
	mt_map_t	*un_matamap;
	mt_map_t	*un_shadowmap;
} mt_unit_t;


typedef struct mt_unit32_od {
	mdc_unit32_od_t	c;		/* common stuff */
	/*
	 * infrastructure
	 */
	mt_flags_t	un_flags;
	caddr32_t	xx_un_next;	/* anchored in log unit */
	/*
	 * log and master device
	 */
	mdkey_t		un_m_key;
	dev32_t		un_m_dev;
	mdkey_t		un_l_key;
	dev32_t		un_l_dev;
	daddr32_t	un_l_sblk;	/* start block */
	daddr32_t	un_l_pwsblk;	/* prewrite start block */
	daddr32_t	un_l_nblks;	/* # of usable log blocks */
	daddr32_t	un_l_tblks;	/* total log blocks */
	daddr32_t	un_l_head;	/* sector offset of log head */
	daddr32_t	un_l_tail;	/* sector offset of log tail */
	uint_t		un_l_resv;	/* current log reservations */
	uint_t		un_l_maxresv;	/* max log reservations */
	uint_t		un_l_maxtransfer; /* maximum transfer at init */
	mddb_recid_t	un_l_recid;	/* database id */
	caddr32_t	xx_un_l_unit;	/* log device unit struct */
	mt_l_error_t	un_l_error;	/* error state */
	struct timeval32 un_l_timestamp;	/* time of last log state chg */
	dev32_t		un_s_dev;	/* shadow device for testing only */

	mt_debug_t	un_debug;	/* debug flags; set at create */
	caddr32_t	xx_un_ut;	/* ufstrans struct */
	dev32_t		un_dev;		/* this metatrans device */
	caddr32_t	xx_un_deltamap;	/* deltamap */
	caddr32_t	xx_un_udmap;	/* userdata map */
	caddr32_t	xx_un_logmap;	/* logmap includes moby trans stuff */
	caddr32_t	xx_un_matamap;	/* optional - matamap */
	caddr32_t	xx_un_shadowmap; /* optional - shadowmap */
	int		un_logreset;	/* part of _FIOLOGRESET ioctl stuff */
	struct timeval32 un_timestamp;	/* time of last trans state change */
	/*
	 * spares
	 */
	uint_t		un_spare[16];
} mt_unit32_od_t;

/*
 * prewrite info (per buf); stored as array at beginning of prewrite area
 */
struct prewrite {
	int		pw_bufsize;	/* every buffer is this size */
	daddr32_t	pw_blkno;	/* block number */
	dev32_t		pw_dev;		/* device to write to */
	ushort_t	pw_secmap;	/* bitmap 	*/
					/* 1's write this sector in the buf */
	ushort_t	pw_flags;
};
/*
 * pw_flags
 */
#define	PW_INUSE	0x0001	/* this prewrite buf is in use */
#define	PW_WAIT		0x0002	/* write in progress; wait for completion */
#define	PW_REM		0x0004	/* remove deltas */

/*
 * log state
 */
struct  logstate {
	off32_t		ls_head_lof;	/* log head */
	uint_t		ls_head_ident;	/* log head ident */
	uint_t		ls_head_tid;	/* log head tid */
	uint_t		ls_chksum;	/* checksum of structure */
	off32_t		ls_bol_lof;	/* needed for TS_Tools/dumplog.c */
	off32_t		ls_eol_lof;	/* needed for TS_Tools/dumplog.c */
	uint_t		ls_maxtransfer;	/* needed for TS_Tools/dumplog.c */
	daddr32_t	ls_pwsblk;	/* needed for TS_Tools/dumplog.c */
};

/*
 * log state defines
 */
#define	LS_SECTORS	(2)	/* number of sectors used by state area */

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
 *	MT_SHADOW		- copy metatrans device writes to shadow dev.
 *	MT_PREWRITE		- process prewrite area every roll
 */
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
#define	MT_SHADOW		(0x00000400)
#define	MT_PREWRITE		(0x00000800)

/* Type 2 trans records */
#define	TRANS_REC	1
#define	LOG_REC		2

#ifdef _KERNEL

typedef struct md_tps {			/* trans parent save */
	DAEMON_QUEUE
	struct mt_unit	*ps_un;
	mdi_unit_t	*ps_ui;
	buf_t		*ps_bp;
	size_t		ps_count;	/* Used for testing only. */
	kmutex_t	ps_mx;		/* protects ps_count. */
} md_tps_t;

/*
 * Log layer protos -- trans_log.c
 */
extern void		_init_ldl(void);
extern void		_fini_ldl(void);
extern void		md_ldl_round_commit(mt_unit_t *);
extern void		md_ldl_push_commit(mt_unit_t *);
extern int		md_ldl_need_commit(ml_unit_t *);
extern int		md_ldl_has_space(ml_unit_t *, mapentry_t *);
extern void		md_ldl_write(mt_unit_t *, caddr_t, offset_t,
					mapentry_t *);
extern void		md_ldl_waito(ml_unit_t *);
extern int		md_ldl_read(ml_unit_t *, caddr_t, offset_t, off_t,
					mapentry_t *);
extern void		md_ldl_sethead(ml_unit_t *, off_t, uint_t,
					struct buf *);
extern void		md_ldl_settail(ml_unit_t *, off_t, off_t,
					struct buf *);
extern void		ldl_setpwvalid(ml_unit_t *);
extern int		ldl_build_incore(ml_unit_t *, int);
extern ml_unit_t	*ldl_findlog(mddb_recid_t);
extern mddb_recid_t	ldl_create(mdkey_t, mt_unit_t *);
extern void		ldl_utadd(mt_unit_t *);
extern int		ldl_open_dev(mt_unit_t *, ml_unit_t *);
extern void		ldl_close_dev(ml_unit_t *);
extern int		ldl_snarf(void);
extern void		ldl_logscan_seterror(ml_unit_t *);
extern void		ldl_logscan_saverror(ml_unit_t *);
extern size_t		md_ldl_logscan_nbcommit(off_t);
extern int		md_ldl_logscan_read(ml_unit_t *, off_t *, size_t,
					caddr_t);
extern void		md_ldl_logscan_begin(ml_unit_t *, daddr_t);
extern void		md_ldl_logscan_end(ml_unit_t *);
extern int		md_ldl_need_roll(ml_unit_t *);
extern int		md_ldl_empty(ml_unit_t *);
extern int		ldl_pwvalid(ml_unit_t *);
extern void		ldl_waitscan(ml_unit_t *);
extern void		ldl_errorbp(set_t, buf_t *, char *);
extern void		md_ldl_seterror(ml_unit_t *);
extern int		ldl_isherror(ml_unit_t *);
extern int		ldl_iserror(ml_unit_t *);
extern int		ldl_isanyerror(ml_unit_t *);
extern void		ldl_start_scan(mt_unit_t *);
extern void		ldl_opened_trans(mt_unit_t *, int);
extern void		ldl_open_trans(mt_unit_t *, int);
extern int		ldl_logreset(mt_unit_t *, buf_t *);
extern void		ldl_close_trans(mt_unit_t *);
extern size_t		md_ldl_bufsize(ml_unit_t *);
extern void		ldl_open_underlying(mt_unit_t *);
extern void		ldl_snarf_done();
extern int		ldl_reset(mt_unit_t *, int, int);
extern void		ldl_cleanup(ml_unit_t *);

/*
 * trans driver layer -- mdtrans.c
 */
extern kmem_cache_t	*trans_child_cache;
extern void		*md_trans_zalloc(size_t);
extern void		*md_trans_zalloc_nosleep(size_t);
extern void		*md_trans_alloc(size_t);
extern void		*md_trans_alloc_nosleep(size_t);
extern void		md_trans_free(void *, size_t);
extern int		md_trans_not_wait(struct buf *cb);
extern int		md_trans_not_done(struct buf *cb);
extern int		md_trans_wait(struct buf *cb);
extern int		trans_done(struct buf *cb);
extern int		trans_done_shadow(struct buf *cb);
extern void		trans_child_init(struct buf *bp);
extern void		trans_close_all_devs(mt_unit_t *);
extern int		trans_open_all_devs(mt_unit_t *);
extern int		trans_build_incore(void *, int);
extern void		trans_commit(mt_unit_t *, int);
extern int		trans_detach(mt_unit_t *, int);
extern void		trans_attach(mt_unit_t *, int);
extern int		trans_reset(mt_unit_t *, minor_t, int, int);

/*
 * transaction ioctl -- trans_ioctl.c
 */

/* rename named service functions */
md_ren_list_svc_t	trans_rename_listkids;
md_ren_svc_t		trans_rename_check;
md_ren_roleswap_svc_t	trans_renexch_update_kids;
md_ren_roleswap_svc_t	trans_rename_update_self;
md_ren_roleswap_svc_t	trans_exchange_parent_update_to;
md_ren_roleswap_svc_t	trans_exchange_self_update_from_down;

/*
 * transaction op layer -- trans_top.c
 */
extern void	_init_md_top(void);
extern void	_fini_top(void);
extern void	top_read(struct buf *, char *, mt_unit_t *, int, void *);
extern void	md_top_read_roll(struct buf *, mt_unit_t *, ushort_t *);
extern void	top_build_incore(mt_unit_t *);
extern void	top_reset(mt_unit_t *, int, int);
extern void	top_write(struct buf *, char *, mt_unit_t *, int, void *);

/*
 * map layer -- trans_delta.c
 */
extern void		md_map_free_entries(mt_map_t *);
extern int		md_matamap_overlap(mt_map_t *, offset_t, off_t);
extern int		md_matamap_within(mt_map_t *, offset_t, off_t);
extern int		md_deltamap_need_commit(mt_map_t *);
extern void		md_deltamap_add(mt_map_t *, offset_t, off_t, delta_t,
				int (*)(), uintptr_t);
extern mapentry_t	*md_deltamap_remove(mt_map_t *, offset_t, off_t);
extern void		md_deltamap_del(mt_map_t *, offset_t, off_t);
extern void		md_deltamap_push(mt_unit_t *);
extern int		md_logmap_need_commit(mt_map_t *);
extern int		md_logmap_need_roll_async(mt_map_t *);
extern int		md_logmap_need_roll_sync(mt_map_t *);
extern int		md_logmap_need_roll(mt_map_t *);
extern void		md_logmap_start_roll(mt_unit_t *);
extern void		md_logmap_kill_roll(mt_map_t *);
extern void		md_logmap_forceroll(mt_map_t *);
extern int		md_logmap_overlap(mt_map_t *, md_dev64_t, offset_t,
				off_t);
extern void		md_logmap_remove_roll(mt_map_t *, md_dev64_t, offset_t,
				off_t);
extern int		md_logmap_next_roll(mt_map_t *, offset_t *,
				md_dev64_t *);
extern void		md_logmap_list_get(mt_map_t *, md_dev64_t, offset_t,
				off_t, mapentry_t **);
extern void		md_logmap_list_get_roll(mt_map_t *, md_dev64_t,
				offset_t, off_t, mapentry_t **);
extern void		md_logmap_list_put(mt_map_t *, mapentry_t *);
extern void		md_logmap_read_mstr(ml_unit_t *, struct buf *, int,
				void *);
extern void		md_logmap_secmap_roll(mapentry_t *, offset_t,
				ushort_t *);
extern int		logmap_read_log(ml_unit_t *, char *, offset_t, off_t,
				mapentry_t *);
extern void		md_logmap_make_space(mt_map_t *, ml_unit_t *,
				mapentry_t *);
extern void		md_logmap_add(mt_unit_t *, md_dev64_t, char *, offset_t,
				mapentry_t *);
extern void		md_logmap_add_ud(mt_unit_t *, md_dev64_t, char *,
				offset_t, mapentry_t *);
extern void		md_logmap_commit(mt_unit_t *);
extern void		md_logmap_sethead(mt_map_t *, ml_unit_t *,
				struct buf *);
extern void		md_logmap_roll_dev(mt_map_t *, ml_unit_t *ul,
				md_dev64_t);
extern void		md_logmap_roll_sud(mt_map_t *, ml_unit_t *ul,
				md_dev64_t, offset_t, off_t);
extern int		md_logmap_ud_done(struct buf *);
extern void		md_logmap_ud_wait();
extern void		md_logmap_cancel(mt_unit_t *, md_dev64_t, offset_t,
				off_t);
extern int		md_logmap_iscancel(mt_map_t *, md_dev64_t, offset_t,
				off_t);
extern void		md_logmap_logscan(mt_unit_t *, daddr_t);
extern void		map_build_incore(mt_unit_t *);
extern void		map_reset(mt_unit_t *, int, int);
extern void		_init_md_map(void);
extern void		_fini_map(void);

/*
 * scan and roll threads -- trans_thread.c
 */
extern void	md_trans_roll(ml_unit_t *);
extern void	trans_scan(mt_unit_t *);
extern void	trans_roll_prewrite(ml_unit_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MD_TRANS_H */
