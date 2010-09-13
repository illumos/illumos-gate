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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MD_MIRROR_H
#define	_SYS_MD_MIRROR_H

#include <sys/callb.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_mirror_shared.h>
#include <sys/lvm/md_rename.h>
#ifdef	_KERNEL
#include <sys/sunddi.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * following bits are used in status word in the common section
 * of unit structure
 */
#define	SMS_IS(sm, state) (((sm)->sm_state & (state)) != 0)
#define	SMS_BY_INDEX_IS(un, index, state) \
		(((un)->un_sm[(index)].sm_state & (state)) != 0)

#define	SMS_BY_INDEX_IS_TARGET(un, index) \
		((un)->un_sm[(index)].sm_flags & MD_SM_RESYNC_TARGET)

#define	SUBMIRROR_IS_READABLE(un, isubmirror)				\
	((((un)->un_sm[(isubmirror)].sm_state & SMS_IGNORE) == 0) &&	\
	    ((un)->un_sm[(isubmirror)].sm_state & 			\
	    (SMS_RUNNING | SMS_COMP_ERRED | SMS_COMP_RESYNC)))

#define	SUBMIRROR_IS_WRITEABLE(un, isubmirror)			\
	((un)->un_sm[(isubmirror)].sm_state &			\
	    (SMS_RUNNING | SMS_COMP_ERRED | SMS_COMP_RESYNC |	\
	    SMS_ATTACHED_RESYNC | SMS_OFFLINE_RESYNC))

/*
 * Default resync block size for MN resync messages
 */
#define	MD_DEF_RESYNC_BLK_SZ		8192

/*
 * macro to test if the current block is within the current resync region
 */
#define	IN_RESYNC_REGION(un, ps) \
	((un->un_rs_prev_overlap != NULL) && (ps->ps_firstblk >= \
	    un->un_rs_prev_overlap->ps_firstblk) && \
	    (ps->ps_lastblk <=  un->un_rs_prev_overlap->ps_lastblk))
/*
 * Default resync update interval (in minutes).
 */
#define	MD_DEF_MIRROR_RESYNC_INTVL	5

/*
 * Defines for flags argument in function set_sm_comp_state()
 */
#define	MD_STATE_NO_XMIT	0x0000 /* Local action, (sent from master) */
#define	MD_STATE_XMIT		0x0001 /* Non-local action, send to master */
#define	MD_STATE_WMUPDATE	0x0002 /* Action because of watermark update */
#define	MD_STATE_OCHELD		0x0004 /* open/close lock held */

/*
 * Defines for flags argument in function check_comp_4_hotspares()
 */
#define	MD_HOTSPARE_NO_XMIT	0x0000 /* Local action, (sent from master) */
#define	MD_HOTSPARE_XMIT	0x0001 /* Non-local action, send to master */
#define	MD_HOTSPARE_WMUPDATE	0x0002 /* Action because of watermark update */
#define	MD_HOTSPARE_LINKHELD	0x0004 /* md_link_rw lock held */

/*
 * Defines for argument in function send_mn_resync_done_message()
 */
#define	RESYNC_ERR		0x1
#define	CLEAR_OPT_NOT_DONE	0x2

/*
 * Defines for argument in function resync_read_blk_range()
 */
#define	MD_FIRST_RESYNC_NEXT	0x1
#define	MD_SEND_MESS_XMIT	0x2
#define	MD_RESYNC_FLAG_ERR	0x4

/*
 * Define for argument in function wait_for_overlaps()
 */
#define	MD_OVERLAP_ALLOW_REPEAT	0x1	/* Allow if ps already in tree */
#define	MD_OVERLAP_NO_REPEAT	0	/* ps must not already be in tree */

/*
 * Define for max retries of mirror_owner
 */
#define	MD_OWNER_RETRIES	10

/*
 * mm_submirror32_od and mm_unit32_od are used only for 32 bit old format
 */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct  mm_submirror32_od {	/* submirrors */
	mdkey_t		sm_key;
	dev32_t		sm_dev;
	sm_state_t	sm_state;
	sm_flags_t	sm_flags;
	caddr32_t	xx_sm_shared_by_blk;	/* really void *) */
	caddr32_t	xx_sm_shared_by_indx;	/* really void *) */
	caddr32_t	xx_sm_get_component_count;
	caddr32_t	xx_sm_get_bcss;	/* block count skip size */
	md_m_shared32_od_t sm_shared;	/* used for mirroring plain devices */
	int		sm_hsp_id;	/* used for mirroring plain devices */
	struct timeval32 sm_timestamp;	/* time of last state change */
} mm_submirror32_od_t;

typedef struct	mm_submirror {		/* submirrors */
	mdkey_t		sm_key;
	md_dev64_t	sm_dev;		/* 64 bit */
	sm_state_t	sm_state;
	sm_flags_t	sm_flags;
	md_m_shared_t	sm_shared;	/* used for mirroring plain devices */
	int		sm_hsp_id;	/* used for mirroring plain devices */
	md_timeval32_t	sm_timestamp;	/* time of last state change, 32 bit */
} mm_submirror_t;

typedef struct mm_unit32_od {
	mdc_unit32_od_t	c;			/* common stuff */

	int		un_last_read;		/* last submirror index read */
	uint_t		un_changecnt;
	ushort_t	un_nsm;			/* number of submirrors */
	mm_submirror32_od_t un_sm[NMIRROR];
	int		un_overlap_tree_flag;
	int		xx_un_overlap_tree_mx[2];	/* replaces mutex */
	ushort_t	xx_un_overlap_tree_cv;
	caddr32_t	xx_un_overlap_root;
	mm_rd_opt_t	un_read_option;		/* mirror read option */
	mm_wr_opt_t	un_write_option;	/* mirror write option */
	mm_pass_num_t	un_pass_num;		/* resync pass number */
	/*
	 * following used to keep dirty bitmaps
	 */
	int		xx_un_resync_mx[2];	/* replaces mutex */
	ushort_t	xx_un_resync_cv;
	uint_t		un_resync_flg;
	uint_t		un_waiting_to_mark;
	uint_t		un_waiting_to_commit;
	caddr32_t	xx_un_outstanding_writes;	/* outstanding write */
	caddr32_t	xx_un_goingclean_bm;
	caddr32_t	xx_un_goingdirty_bm;
	caddr32_t	xx_un_dirty_bm;
	caddr32_t	xx_un_resync_bm;
	uint_t		un_rrd_blksize;	/* The blocksize of the dirty bits */
	uint_t		un_rrd_num;	/* The number of resync regions */
	mddb_recid_t	un_rr_dirty_recid;	/* resync region bm record id */
	/*
	 * following stuff is private to resync process
	 */
	int		un_rs_copysize;
	int		un_rs_dests;	/* destinations */
	daddr32_t	un_rs_resync_done;	/* used for percent done */
	daddr32_t	un_rs_resync_2_do;	/* user for percent done */
	int		un_rs_dropped_lock;
	caddr32_t	un_rs_type;		/* type of resync in progress */
	/*
	 * Incore elements in this old structure are no longer referenced by
	 * current 64 bit kernel.  Comment them out for maintenance purpose.
	 *
	 * 	mm_submirror_ic_t	un_smic[NMIRROR];
	 * 	kmutex_t		un_ovrlap_chn_mx;
	 * 	kcondvar_t		un_ovrlap_chn_cv;
	 * 	struct md_mps		*un_ovrlap_chn;
	 * 	kmutex_t		un_resync_mx;
	 * 	kcondvar_t		un_resync_cv;
	 * 	short			*un_outstanding_writes;
	 * 	uchar_t			*un_goingclean_bm;
	 * 	uchar_t			*un_goingdirty_bm;
	 * 	uchar_t			*un_dirty_bm;
	 * 	uchar_t			*un_resync_bm;
	 * 	char			*un_rs_buffer;
	 */
} mm_unit32_od_t;
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/* Types of resync in progress (used for un_rs_type) */
#define	MD_RS_NONE		0		/* No resync */
#define	MD_RS_OPTIMIZED		0x0001		/* Optimized resync */
#define	MD_RS_COMPONENT		0x0002		/* Component resync */
#define	MD_RS_SUBMIRROR		0x0003		/* Submirror resync */
#define	MD_RS_ABR		0x0004		/* Application based resync */

/*
 * un_rs_type is split into the following bitfields:
 *
 * 0-3	Resync type (as above)
 * 4-7	Submirror index [0..3]
 * 8-31	Component index
 */
#define	RS_TYPE_MASK	0xF
#define	RS_SMI_MASK	0xF0
#define	RS_CI_MASK	0x1FFF00

#define	RS_TYPE(x)	((x) & RS_TYPE_MASK)
#define	RS_SMI(x)	(((x) & RS_SMI_MASK) >> 4)
#define	RS_CI(x)	(((x) & RS_CI_MASK) >> 8)

#define	SET_RS_TYPE(x, v)	{					\
				    (x) &= ~RS_TYPE_MASK;		\
				    (x) |= ((v) & RS_TYPE_MASK);	\
				}
#define	SET_RS_TYPE_NONE(x)	{					\
				    (x) &= ~RS_TYPE_MASK;		\
				}
#define	SET_RS_SMI(x, v)	{					\
				    (x) &= ~RS_SMI_MASK; 		\
				    (x) |= (((v) << 4) & RS_SMI_MASK);	\
				}
#define	SET_RS_CI(x, v)		{					\
				    (x) &= ~RS_CI_MASK;			\
				    (x) |= (((v) << 8) & RS_CI_MASK);	\
				}

typedef struct	mm_submirror_ic {
	intptr_t	(*sm_shared_by_blk)(md_dev64_t, void *,
				diskaddr_t, u_longlong_t *);
	intptr_t	(*sm_shared_by_indx)(md_dev64_t, void *, int);
	int		(*sm_get_component_count)(md_dev64_t, void *);
	int		(*sm_get_bcss)(md_dev64_t, void *, int, diskaddr_t *,
				size_t *, u_longlong_t *, u_longlong_t *);
} mm_submirror_ic_t;

typedef struct md_mps {
	DAEMON_QUEUE
	buf_t		*ps_bp;
	struct mm_unit	*ps_un;
	mdi_unit_t	*ps_ui;
	uint_t		 ps_childbflags;
	caddr_t		 ps_addr;
	diskaddr_t	 ps_firstblk;
	diskaddr_t	 ps_lastblk;
	uint_t		 ps_flags;
	uint_t		 ps_allfrom_sm;		/* entire read came from here */
	uint_t		 ps_writable_sm;
	uint_t		 ps_current_sm;
	uint_t		 ps_active_cnt;
	int		 ps_frags;
	uint_t		 ps_changecnt;
	struct md_mps	*ps_unused1;
	struct md_mps	*ps_unused2;
	void		 (*ps_call)();
	kmutex_t	 ps_mx;
	avl_node_t	ps_overlap_node;
} md_mps_t;

#define	MD_MPS_ON_OVERLAP	0x0001
#define	MD_MPS_ERROR		0x0002
#define	MD_MPS_WRITE_AFTER_READ	0x0004
#define	MD_MPS_WOW		0x0008
#define	MD_MPS_DONTFREE		0x0010
#define	MD_MPS_DONE		0x0020
#define	MD_MPS_MAPPED		0x0040		/* re: MD_STR_MAPPED	*/
#define	MD_MPS_NOBLOCK		0x0080		/* re: MD_NOBLOCK	*/
#define	MD_MPS_ABR		0x0100		/* re: MD_STR_ABR	*/
#define	MD_MPS_DMR		0x0200		/* re: MD_STR_DMR	*/
#define	MD_MPS_WMUPDATE		0x0400		/* re: MD_STR_WMUPDATE	*/
#define	MD_MPS_DIRTY_RD		0x0800		/* re: MD_STR_DIRTY_RD	*/
#define	MD_MPS_RESYNC_READ	0x1000
#define	MD_MPS_FLAG_ERROR	0x2000		/* re: MD_STR_FLAG_ERR	*/
#define	MD_MPS_BLOCKABLE_IO	0x4000		/* re: MD_STR_BLOCK_OK  */

#define	MPS_FREE(kc, ps)			\
{						\
	if ((ps)->ps_flags & MD_MPS_DONTFREE)	\
		(ps)->ps_flags |= MD_MPS_DONE;	\
	else					\
		kmem_cache_free((kc), (ps));	\
}

typedef struct md_mcs {
	DAEMON_QUEUE
	md_mps_t	*cs_ps;
	minor_t		 cs_mdunit;
	/* Add new structure members HERE!! */
	buf_t		 cs_buf;
	/*  DO NOT add structure members here; cs_buf is dynamically sized */
} md_mcs_t;

typedef struct  mm_mirror_ic {
	kmutex_t	un_overlap_tree_mx;
	kcondvar_t	un_overlap_tree_cv;
	avl_tree_t	un_overlap_root;
	kmutex_t	un_resync_mx;
	kcondvar_t	un_resync_cv;
	short		*un_outstanding_writes; /* outstanding write array */
	uchar_t		*un_goingclean_bm;
	uchar_t		*un_goingdirty_bm;
	uchar_t		*un_dirty_bm;
	uchar_t		*un_resync_bm;
	char		*un_rs_buffer;
	int		un_suspend_wr_flag;
	kmutex_t	un_suspend_wr_mx;
	kcondvar_t	un_suspend_wr_cv;
	md_mn_nodeid_t	un_mirror_owner;	/* Node which owns mirror */
	diskaddr_t	un_resync_startbl;	/* Start block for resync */
	kmutex_t	un_owner_mx;		/* Mutex for un_owner_state */
	uint_t		un_owner_state;		/* See below */
	uint_t		un_mirror_owner_status;	/* status for ioctl request */
	kmutex_t	un_dmr_mx;		/* mutex for DMR requests */
	kcondvar_t	un_dmr_cv;		/* condvar for DMR requests */
	int		un_dmr_last_read;	/* last DMR submirror read */
	callb_cpr_t	un_rs_cprinfo;		/* CPR info for resync thread */
	kmutex_t	un_rs_cpr_mx;		/* mutex for resync CPR info */
	kmutex_t	un_prr_cpr_mx;		/* mutex for prr CPR info */
	uint_t		un_resync_completed;	/* type of last resync */
	int		un_abr_count;		/* count of sp's with abr set */

	uchar_t		*un_pernode_dirty_bm[MD_MNMAXSIDES];
	uchar_t		*un_pernode_dirty_sum;

	krwlock_t	un_pernode_dirty_mx[MD_MNMAXSIDES];
	ushort_t	un_rr_clean_start_bit;  /* where to start next clean */

#ifdef	_KERNEL
	ddi_taskq_t	*un_drl_task;		/* deferred RR_CLEAN taskq */
#else
	void		*un_drl_task;		/* deferred RR_CLEAN taskq */
#endif	/* _KERNEL */
	uint_t		un_waiting_to_clear;	/* Blocked waiting to clear */

}mm_mirror_ic_t;

#define	MM_MN_OWNER_SENT	0x0001		/* RPC in progress */
#define	MM_MN_BECOME_OWNER	0x0002		/* Ownership change in prog. */
#define	MM_MN_PREVENT_CHANGE	0x0004		/* Disallow ownership change */

typedef struct mm_unit {
	mdc_unit_t	c;			/* common stuff */

	int		un_last_read;		/* last submirror index read */
	uint_t		un_changecnt;
	ushort_t	un_nsm;			/* number of submirrors */
	mm_submirror_t	un_sm[NMIRROR];
	int		un_overlap_tree_flag;
	mm_rd_opt_t	un_read_option;		/* mirror read option */
	mm_wr_opt_t	un_write_option;	/* mirror write option */
	mm_pass_num_t	un_pass_num;		/* resync pass number */
	/*
	 * following used to keep dirty bitmaps
	 */
	uint_t		un_resync_flg;
	uint_t		un_waiting_to_mark;
	uint_t		un_waiting_to_commit;
	uint_t		un_rrd_blksize;	  /* The blocksize of the dirty bits */
	uint_t		un_rrd_num;	  /* The number of resync regions */
	mddb_recid_t	un_rr_dirty_recid; /* resync region bm db record id */
	/*
	 * following stuff is private to resync process
	 */
	int 		un_rs_copysize;
	int 		un_rs_dests;		/* destinations */
	diskaddr_t	un_rs_resync_done;	/* used for percent done */
	diskaddr_t	un_rs_resync_2_do;	/* user for percent done */
	int		un_rs_dropped_lock;
	uint_t		un_rs_type;		/* type of resync */
	/*
	 * Incore only elements
	 */
	mm_submirror_ic_t un_smic[NMIRROR];	/* NMIRROR elements array */
	mm_mirror_ic_t	un_mmic;
	kmutex_t	un_rrp_inflight_mx;
	/*
	 * resync thread control
	 */
	kthread_t	*un_rs_thread;		/* Resync thread ID */
	kmutex_t	un_rs_thread_mx;	/* Thread cv mutex */
	kcondvar_t	un_rs_thread_cv;	/* Cond. Var. for thread */
	uint_t		un_rs_thread_flags;	/* Thread control flags */
	md_mps_t	*un_rs_prev_overlap;	/* existing overlap request */
	timeout_id_t	un_rs_resync_to_id;	/* resync progress timeout */
	kmutex_t	un_rs_progress_mx;	/* Resync progress mutex */
	kcondvar_t	un_rs_progress_cv;	/* Cond. Var. for progress */
	uint_t		un_rs_progress_flags;	/* Thread control flags */
	void		*un_rs_msg;		/* Intra-node resync message */
} mm_unit_t;

#define	un_overlap_tree_mx	un_mmic.un_overlap_tree_mx
#define	un_overlap_tree_cv	un_mmic.un_overlap_tree_cv
#define	un_overlap_root		un_mmic.un_overlap_root
#define	un_resync_mx		un_mmic.un_resync_mx
#define	un_resync_cv		un_mmic.un_resync_cv
#define	un_outstanding_writes	un_mmic.un_outstanding_writes
#define	un_goingclean_bm	un_mmic.un_goingclean_bm
#define	un_goingdirty_bm	un_mmic.un_goingdirty_bm
#define	un_dirty_bm		un_mmic.un_dirty_bm
#define	un_resync_bm		un_mmic.un_resync_bm
#define	un_rs_buffer		un_mmic.un_rs_buffer
#define	un_suspend_wr_mx	un_mmic.un_suspend_wr_mx
#define	un_suspend_wr_cv	un_mmic.un_suspend_wr_cv
#define	un_suspend_wr_flag	un_mmic.un_suspend_wr_flag
#define	un_mirror_owner		un_mmic.un_mirror_owner
#define	un_resync_startbl	un_mmic.un_resync_startbl
#define	un_owner_mx		un_mmic.un_owner_mx
#define	un_owner_state		un_mmic.un_owner_state
#define	un_mirror_reqs		un_mmic.un_mirror_reqs
#define	un_mirror_reqs_done	un_mmic.un_mirror_reqs_done
#define	un_mirror_owner_status	un_mmic.un_mirror_owner_status
#define	un_dmr_mx		un_mmic.un_dmr_mx
#define	un_dmr_cv		un_mmic.un_dmr_cv
#define	un_dmr_last_read	un_mmic.un_dmr_last_read
#define	un_rs_cprinfo		un_mmic.un_rs_cprinfo
#define	un_rs_cpr_mx		un_mmic.un_rs_cpr_mx
#define	un_prr_cpr_mx		un_mmic.un_prr_cpr_mx
#define	un_resync_completed	un_mmic.un_resync_completed
#define	un_abr_count		un_mmic.un_abr_count
#define	un_pernode_dirty_bm	un_mmic.un_pernode_dirty_bm
#define	un_pernode_dirty_sum	un_mmic.un_pernode_dirty_sum
#define	un_pernode_dirty_mx	un_mmic.un_pernode_dirty_mx
#define	un_rr_clean_start_bit	un_mmic.un_rr_clean_start_bit
#define	un_drl_task		un_mmic.un_drl_task
#define	un_waiting_to_clear	un_mmic.un_waiting_to_clear

#define	MM_RF_GATECLOSED	0x0001
#define	MM_RF_COMMIT_NEEDED	0x0002
#define	MM_RF_COMMITING		0x0004
#define	MM_RF_STALL_CLEAN	(MM_RF_COMMITING | \
				    MM_RF_COMMIT_NEEDED | \
				    MM_RF_GATECLOSED)


#define	MD_MN_MIRROR_UNOWNED	0
#define	MD_MN_MIRROR_OWNER(un)	 (un->un_mirror_owner == md_mn_mynode_id)
#define	MD_MN_NO_MIRROR_OWNER(un)	\
	(un->un_mirror_owner == MD_MN_MIRROR_UNOWNED)

typedef struct err_comp {
	struct err_comp	*ec_next;
	int		ec_smi;
	int		ec_ci;
} err_comp_t;

extern	int	md_min_rr_size;
extern	int	md_def_num_rr;

/* Optimized resync records controllers */
#define	MD_MIN_RR_SIZE		(md_min_rr_size)
#define	MD_DEF_NUM_RR		(md_def_num_rr)
#define	MD_MAX_NUM_RR		(4192*NBBY - sizeof (struct optim_resync))

/* default resync buffer size */
#define	MD_DEF_RESYNC_BUF_SIZE	(1024)

/* Structure for optimized resync records */
#define	OR_MAGIC	0xFECA	/* Only missing the L */
typedef struct optim_resync {
	uint_t	or_revision;
	uint_t	or_magic;
	uint_t	or_blksize;
	uint_t	or_num;
	uchar_t	or_rr[1];
} optim_resync_t;

/* Type 2 for mirror records */
#define	MIRROR_REC	1
#define	RESYNC_REC	2

#ifdef _KERNEL

#define	NO_SUBMIRRORS	(0)
#define	ALL_SUBMIRRORS	(0xFFF)
#define	SMI2BIT(smi)	(1 << (smi))

/* For use with mirror_other_sources() */
#define	WHOLE_SM	(-1)

#define	BLK_TO_RR(i, b, un)  {\
	(i) = ((b) / ((un))->un_rrd_blksize); \
	if ((i) > ((un))->un_rrd_num) \
		{ panic("md: BLK_TO_RR"); } \
}

#define	RR_TO_BLK(b, i, un) \
	(b) = ((i) * ((un))->un_rrd_blksize)

#define	IS_GOING_DIRTY(i, un)	(isset((un)->un_goingdirty_bm, (i)))
#define	CLR_GOING_DIRTY(i, un)	(clrbit((un)->un_goingdirty_bm, (i)))
#define	SET_GOING_DIRTY(i, un)	(setbit((un)->un_goingdirty_bm, (i)))

#define	IS_GOING_CLEAN(i, un)	(isset((un)->un_goingclean_bm, (i)))
#define	CLR_GOING_CLEAN(i, un)	(clrbit((un)->un_goingclean_bm, (i)))
#define	SET_GOING_CLEAN(i, un)	(setbit((un)->un_goingclean_bm, (i)))

#define	IS_REGION_DIRTY(i, un)	(isset((un)->un_dirty_bm, (i)))
#define	CLR_REGION_DIRTY(i, un)	(clrbit((un)->un_dirty_bm, (i)))
#define	SET_REGION_DIRTY(i, un)	(setbit((un)->un_dirty_bm, (i)))

#define	IS_KEEPDIRTY(i, un)	(isset((un)->un_resync_bm, (i)))
#define	CLR_KEEPDIRTY(i, un)	(clrbit((un)->un_resync_bm, (i)))

#define	IS_PERNODE_DIRTY(n, i, un) \
	(isset((un)->un_pernode_dirty_bm[(n)-1], (i)))
#define	CLR_PERNODE_DIRTY(n, i, un) \
	(clrbit((un)->un_pernode_dirty_bm[(n)-1], (i)))
#define	SET_PERNODE_DIRTY(n, i, un) \
	(setbit((un)->un_pernode_dirty_bm[(n)-1], (i)))

/*
 * Write-On-Write handling.
 *   flags for md_mirror_wow_flg
 *   structure for quing copy-writes
 *   macros for relative locating of header and buffer
 */
#define	WOW_DISABLE	0x0001	/* turn off WOW detection */
#define	WOW_PHYS_ENABLE	0x0020	/* turn on WOW for PHYS */
#define	WOW_LOGIT	0x0002	/* log non-disabled WOW detections */
#define	WOW_NOCOPY	0x0004	/* repeat normal write on WOW detection */

typedef	struct wowhdr {
	DAEMON_QUEUE
	md_mps_t	*wow_ps;
	int		wow_offset;
} wowhdr_t;

#define	WOWBUF_HDR(wowbuf)	((void *)(wowbuf-sizeof (wowhdr_t)))
#define	WOWHDR_BUF(wowhdr)	((char *)wowhdr+sizeof (wowhdr_t))

/*
 * Structure used to to save information about DMR reads.  Used to save
 * the count of all DMR reads and the timestamp of the last one executed.
 * We declare a global with this structure and it can be read by a debugger to
 * verify that the DMR ioctl has been executed and the number of times that it
 * has been executed.
 */
typedef struct dmr_stats {
	uint_t		dmr_count;
	struct timeval	dmr_timestamp;
} dmr_stats_t;

/* Externals from mirror.c */
extern mddb_recid_t	mirror_get_sm_unit(md_dev64_t);
extern void		mirror_release_sm_unit(md_dev64_t);

extern void		mirror_set_sm_state(mm_submirror_t *,
				mm_submirror_ic_t *, sm_state_t, int);

extern void		mirror_commit(mm_unit_t *, int, mddb_recid_t *);
extern int		poke_hotspares(void);
extern void		build_submirror(mm_unit_t *, int, int);
extern int		mirror_build_incore(mm_unit_t *, int);
extern void		reset_mirror(mm_unit_t *, minor_t, int);
extern int		mirror_internal_open(minor_t, int, int, int, IOLOCK *);
extern int		mirror_internal_close(minor_t, int, int, IOLOCK *);
extern void		set_sm_comp_state(mm_unit_t *, int, int, int,
			    mddb_recid_t *, uint_t, IOLOCK *);
extern int		mirror_other_sources(mm_unit_t *, int, int, int);
extern int		mirror_resync_message(md_mn_rs_params_t *, IOLOCK *);
extern void		md_mirror_strategy(buf_t *, int, void *);
extern int		mirror_directed_read(dev_t, vol_directed_rd_t *, int);
extern void		mirror_check_failfast(minor_t mnum);
extern int		check_comp_4_hotspares(mm_unit_t *, int, int, uint_t,
			    mddb_recid_t, IOLOCK *);
extern void		mirror_overlap_tree_remove(md_mps_t *ps);
extern void		mirror_child_init(md_mcs_t *cs);

/* Externals from mirror_ioctl.c */
extern void		reset_comp_states(mm_submirror_t *,
			    mm_submirror_ic_t *);
extern int		mirror_grow_unit(mm_unit_t *un, md_error_t *ep);
extern int		md_mirror_ioctl(dev_t dev, int cmd, void *data,
			    int mode, IOLOCK *lockp);
extern mm_unit_t	*mirror_getun(minor_t, md_error_t *, int, IOLOCK *);
extern void		mirror_get_status(mm_unit_t *un, IOLOCK *lockp);
extern int		mirror_choose_owner(mm_unit_t *un, md_mn_req_owner_t *);

/* rename named service functions */
md_ren_list_svc_t	mirror_rename_listkids;
md_ren_svc_t		mirror_rename_check;
md_ren_roleswap_svc_t	mirror_renexch_update_kids;
md_ren_roleswap_svc_t	mirror_exchange_parent_update_to;
md_ren_roleswap_svc_t	mirror_exchange_self_update_from_down;

/* Externals from mirror_resync.c */
extern int		unit_setup_resync(mm_unit_t *, int);
extern int		mirror_resync_unit(minor_t mnum, md_resync_ioctl_t *ri,
			    md_error_t *ep, IOLOCK *);
extern int		mirror_ioctl_resync(md_resync_ioctl_t *p, IOLOCK *);
extern int		mirror_mark_resync_region(mm_unit_t *, diskaddr_t,
				diskaddr_t, md_mn_nodeid_t);
extern void		resync_start_timeout(set_t setno);
extern int		mirror_resize_resync_regions(mm_unit_t *, diskaddr_t);
extern int		mirror_add_resync_regions(mm_unit_t *, diskaddr_t);
extern int		mirror_probedevs(md_probedev_t *, IOLOCK *);
extern void		mirror_copy_rr(int, uchar_t *, uchar_t *);
extern void		mirror_process_unit_resync(mm_unit_t *);
extern int		mirror_set_dirty_rr(md_mn_rr_dirty_params_t *);
extern int		mirror_set_clean_rr(md_mn_rr_clean_params_t *);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MD_MIRROR_H */
