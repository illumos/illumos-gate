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

#ifndef _SYS_MD_RAID_H
#define	_SYS_MD_RAID_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_rename.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * following bits are used in status word in the common section
 * of unit structure: un_status
 */
#define	RAID_UNMAGIC		0xBADBABE0
#define	RAID_PSMAGIC		0xBADBABE1
#define	RAID_CSMAGIC		0xBADBABE2
#define	RAID_PWMAGIC		0xBADBABE3
#define	RAID_BUFMAGIC		0xBADBABE4
/*
 * These are the major constants for the definition of a raid device
 */
#define	PWCNT_MIN	10	/* mininum # prewrites */
#define	PWCNT_MAX	100	/* maximum # prewrites */
#define	RAID_MIN_INTERLACE	(DEV_BSIZE * 2)

#define	UNIT_STATE(un) ((un)->un_state)
#define	COLUMN_STATE(un, column) ((un)->un_column[(column)].un_devstate)

#define	COLUMN_STATE_ONLY(un, column) (\
	((un)->un_column[(column)].un_devstate == RCS_INIT) || \
	((un)->un_column[(column)].un_devstate == RCS_OKAY) || \
	((un)->un_column[(column)].un_devstate == RCS_ERRED) || \
	((un)->un_column[(column)].un_devstate == RCS_RESYNC) || \
	((un)->un_column[(column)].un_devstate == RCS_LAST_ERRED) || \
	((un)->un_column[(column)].un_devstate == RCS_REGEN)))

#define	COLUMN_ISUP(un, column) (\
	((un)->un_column[(column)].un_devstate == RCS_OKAY) || \
	((un)->un_column[(column)].un_devstate == RCS_RESYNC) || \
	((un)->un_column[(column)].un_devstate == RCS_LAST_ERRED))

#define	COLUMN_ISOKAY(un, column) (\
	((un)->un_column[(column)].un_devstate == RCS_OKAY))

#define	COLUMN_ISLASTERR(un, column) (\
	((un)->un_column[(column)].un_devstate == RCS_LAST_ERRED))

#define	WRITE_ALT(un, column) ( \
	((un)->un_column[(column)].un_alt_dev != NODEV64) && \
	(((un)->un_column[(column)].un_devflags & MD_RAID_WRITE_ALT)))

#define	HOTSPARED(un, column) ( \
	((un)->un_column[(column)].un_hs_id != 0))

#define	OVERLAPED(blk1, lblk1, blk2, lblk2) (				\
	(((blk1 > lblk2) ? 1 : 0) ||					\
	((lblk1 < blk2) ? 1 : 0)))


/*
 * Note: magic is needed only to set rpw_magic, not rpw_magic_ext!
 */
#define	RAID_FILLIN_RPW(buf, un, sum, colnum, 				\
			blkno, blkcnt, id,  				\
			colcount, col, magic) { 			\
	if ((un)->c.un_revision & MD_64BIT_META_DEV) { 		\
		raid_pwhdr_t *rpw64	= (raid_pwhdr_t *)(void *)(buf);\
		rpw64->rpw_magic	= magic;			\
		rpw64->rpw_sum		= sum;				\
		rpw64->rpw_columnnum	= colnum;			\
		rpw64->rpw_blkno	= (diskaddr_t)blkno;		\
		rpw64->rpw_blkcnt	= blkcnt;			\
		rpw64->rpw_id		= id;				\
		rpw64->rpw_colcount	= colcount;			\
		rpw64->rpw_column	= col;				\
		rpw64->rpw_unit		= MD_SID(un);			\
		rpw64->rpw_magic_ext	= RAID_PWMAGIC;			\
		rpw64->rpw_origcolumncnt  = (un)->un_origcolumncnt;	\
		rpw64->rpw_totalcolumncnt  = (un)->un_totalcolumncnt;	\
		rpw64->rpw_segsize	= (un)->un_segsize;		\
		rpw64->rpw_segsincolumn	= (diskaddr_t)((un)->un_segsincolumn);\
		rpw64->rpw_pwcnt	= (un)->un_pwcnt;		\
		rpw64->rpw_pwsize	= (un)->un_pwsize;		\
		rpw64->rpw_devstart	=				\
			(diskaddr_t)((un)->un_column[col].un_orig_devstart);\
		rpw64->rpw_pwstart	=				\
			(diskaddr_t)((un)->un_column[col].un_orig_pwstart);\
	} else { 							\
		raid_pwhdr32_od_t *rpw32 =				\
				(raid_pwhdr32_od_t *)(void *)(buf);	\
		rpw32->rpw_magic	= magic;			\
		rpw32->rpw_sum		= sum;				\
		rpw32->rpw_columnnum	= colnum;			\
		rpw32->rpw_blkno	= (daddr_t)blkno;		\
		rpw32->rpw_blkcnt	= blkcnt;			\
		rpw32->rpw_id		= id;				\
		rpw32->rpw_colcount	= colcount;			\
		rpw32->rpw_column	= col;				\
		rpw32->rpw_unit		= MD_SID(un);			\
		rpw32->rpw_magic_ext	= RAID_PWMAGIC;			\
		rpw32->rpw_origcolumncnt  = (un)->un_origcolumncnt;	\
		rpw32->rpw_totalcolumncnt = (un)->un_totalcolumncnt;	\
		rpw32->rpw_segsize	= (daddr_t)((un)->un_segsize);	\
		rpw32->rpw_segsincolumn	= (daddr_t)((un)->un_segsincolumn);\
		rpw32->rpw_pwcnt	= (un)->un_pwcnt;		\
		rpw32->rpw_pwsize	= (un)->un_pwsize;		\
		rpw32->rpw_devstart	=				\
			(daddr_t)((un)->un_column[col].un_orig_devstart);\
		rpw32->rpw_pwstart	=				\
			(daddr_t)((un)->un_column[col].un_orig_pwstart);\
	} 								\
}

#define	RAID_CONVERT_RPW(rpw32, rpw64) { 				\
	(rpw64)->rpw_magic		= (rpw32)->rpw_magic;		\
	(rpw64)->rpw_sum		= (rpw32)->rpw_sum;		\
	(rpw64)->rpw_columnnum		= (rpw32)->rpw_columnnum;	\
	(rpw64)->rpw_blkno		= (rpw32)->rpw_blkno;		\
	(rpw64)->rpw_blkcnt		= (rpw32)->rpw_blkcnt;		\
	(rpw64)->rpw_id			= (rpw32)->rpw_id;		\
	(rpw64)->rpw_colcount		= (rpw32)->rpw_colcount;	\
	(rpw64)->rpw_column		= (rpw32)->rpw_column;		\
	(rpw64)->rpw_unit		= (rpw32)->rpw_unit;		\
	(rpw64)->rpw_magic_ext		= (rpw32)->rpw_magic_ext;	\
	(rpw64)->rpw_origcolumncnt	= (rpw32)->rpw_origcolumncnt;	\
	(rpw64)->rpw_totalcolumncnt	= (rpw32)->rpw_totalcolumncnt;	\
	(rpw64)->rpw_segsize		= (rpw32)->rpw_segsize;		\
	(rpw64)->rpw_segsincolumn	= (rpw32)->rpw_segsincolumn;	\
	(rpw64)->rpw_pwcnt		= (rpw32)->rpw_pwcnt;		\
	(rpw64)->rpw_pwsize		= (rpw32)->rpw_pwsize;		\
	(rpw64)->rpw_devstart		= (rpw32)->rpw_devstart;	\
	(rpw64)->rpw_pwstart		= (rpw32)->rpw_pwstart;		\
}

typedef struct mr_scoreboard {
	int		sb_column;
	int		sb_flags;
	diskaddr_t	sb_start_blk;
	diskaddr_t	sb_last_blk;
	void		*sb_cs;
} mr_scoreboard_t;

#define	SB_AVAIL	(0x00000001)	/* useable and valid blocks */
#define	SB_INUSE	(0x00000002)	/* being used */
#define	SB_UNUSED	(0x00000004)	/* useable and no valid blocks */
#define	SB_INVAL_PEND	(0x00000008)	/* being invalidated */

typedef struct mr_pw_reserve {
	uint_t		pw_magic;
	int		pw_column;
	int		pw_free;
	mr_scoreboard_t	pw_sb[1];
} mr_pw_reserve_t;


#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct mr_column {
	rcs_state_t	un_devstate;
	rcs_flags_t	un_devflags;
	md_timeval32_t	un_devtimestamp; /* time of last state change, 32 bit */

	mddb_recid_t	un_hs_id;
	diskaddr_t	un_hs_pwstart;
	diskaddr_t	un_hs_devstart;
	mdkey_t		un_hs_key;


	md_dev64_t	un_orig_dev;		/* original device, 64 bit */
	mdkey_t		un_orig_key;
	diskaddr_t	un_orig_pwstart;
	diskaddr_t	un_orig_devstart;

	md_dev64_t	un_dev;			/* current read/write dev */
	diskaddr_t	un_pwstart;
	diskaddr_t	un_devstart;

	md_dev64_t	un_alt_dev;		/* write to if resync */
	diskaddr_t	un_alt_pwstart;
	diskaddr_t	un_alt_devstart;
} mr_column_t;

/*
 * mr_column32_od is for old 32 bit format only
 */
typedef struct mr_column32_od {
	rcs_state_t	un_devstate;
	rcs_flags_t	un_devflags;
	struct timeval32 un_devtimestamp;	/* time of last state change */
	caddr32_t	xx_un_pw_reserve;

	mddb_recid_t	un_hs_id;
	daddr32_t	un_hs_pwstart;
	daddr32_t	un_hs_devstart;
	mdkey_t		un_hs_key;

	dev32_t		un_orig_dev;	/* original device */
	mdkey_t		un_orig_key;
	daddr32_t	un_orig_pwstart;
	daddr32_t	un_orig_devstart;

	dev32_t		un_dev;		/* current read/write dev */
	daddr32_t	un_pwstart;
	daddr32_t	un_devstart;

	dev32_t		un_alt_dev;	/* write to if resync */
	daddr32_t	un_alt_pwstart;
	daddr32_t	un_alt_devstart;
} mr_column32_od_t;


/*
 * Incore only elements structures
 */
typedef struct mr_column_ic {
	mr_pw_reserve_t *un_pw_reserve;
} mr_column_ic_t;

/*
 * Do not rearrange elements as mutexes must be aligned on
 * an 8 byte boundary. Element _t_un_linlck_mx corresponds to
 * _t_un_linlck_cv and element _t_un_mx corresponds to _t_un_cv
 */
typedef struct mr_unit_ic {
	caddr_t			_t_un_pbuffer;
	caddr_t			_t_un_dbuffer;
	struct md_raidcs	*_t_un_linlck_chn;
	kmutex_t		_t_un_linlck_mx;
	kmutex_t		_t_un_mx;
	kcondvar_t		_t_un_linlck_cv;
	kcondvar_t		_t_un_cv;
	mr_column_ic_t		*_t_un_column_ic;
} mr_unit_ic_t;

typedef struct mr_unit {
	mdc_unit_t	c;
	int		un_raid_res;
	uint_t		un_magic;
	rus_state_t	un_state;
	md_timeval32_t	un_timestamp;	/* 32 bit fixed size */
	uint_t		un_origcolumncnt;
	uint_t		un_totalcolumncnt;
	uint_t		un_rflags;
	uint_t		un_segsize;
	diskaddr_t	un_segsincolumn;
	uint_t		un_maxio;	/* in blks */
	uint_t		un_iosize;	/* in blks */
	uint_t		un_linlck_flg;
	uint_t		un_pwcnt;
	uint_t		un_pwsize;
	long long	un_pwid;
	uint_t		un_percent_done;
	uint_t		un_resync_copysize;	/* in blks */
	hsp_t		un_hsp_id;
	/*
	 * This union has to begin at an 8 byte aligned address.
	 * If not, this structure has different sizes in 32 / 64 bit
	 * environments, since in a 64 bit environment the compiler
	 * adds paddings before a long long, if it doesn't start at an 8byte
	 * aligned address.
	 * Be careful if you add or remove structure elements before it!
	 */

	union	{
		struct	{
			diskaddr_t	_t_un_resync_line_index;
			uint_t		_t_un_resync_segment;
			int		_t_un_resync_index;
		} _resync;
		struct	{
			diskaddr_t	_t_un_grow_tb;
			uint_t		_t_un_init_colcnt;
			u_longlong_t	_t_un_init_iocnt;
		} _init;
	} _t_un;

	/*
	 * This union has to begin at an 8 byte aligned address.
	 * Be careful if you add or remove structure elements before it!
	 */
	union {
		mr_unit_ic_t	*_mr_ic;
		uint_t		_mr_ic_pad[2];
	} un_mr_ic;

	mr_column_t	un_column[1];
} mr_unit_t;

#define	mr_ic		un_mr_ic._mr_ic
#define	un_pbuffer	mr_ic->_t_un_pbuffer
#define	un_dbuffer	mr_ic->_t_un_dbuffer
#define	un_linlck_chn	mr_ic->_t_un_linlck_chn
#define	un_linlck_mx	mr_ic->_t_un_linlck_mx
#define	un_linlck_cv	mr_ic->_t_un_linlck_cv
#define	un_mx		mr_ic->_t_un_mx
#define	un_cv		mr_ic->_t_un_cv
#define	un_column_ic	mr_ic->_t_un_column_ic

/*
 * For old 32 bit format use only
 */
typedef struct mr_unit32_od {
	mdc_unit32_od_t		c;
	caddr32_t		xx_un_raid_res;
	uint_t			un_magic;
	rus_state_t		un_state;
	struct timeval32	un_timestamp;
	uint_t			un_origcolumncnt;
	uint_t			un_totalcolumncnt;
	uint_t			un_rflags;
	uint_t			un_segsize;
	uint_t			un_segsincolumn;
	uint_t			un_maxio;
	uint_t			un_iosize;
	caddr32_t		xx_un_pbuffer;
	caddr32_t		xx_un_dbuffer;
	uint_t			un_linlck_flg;
	caddr32_t		xx_un_linlck_chn;
	uint_t			un_pwcnt;
	uint_t			un_pwsize;
	long long		un_pwid;
	uint_t			un_rebuild_size;
	uint_t			un_percent_done;
	union   {
		struct  {
			uint_t	_t_un_resync_segment;
			int	_t_un_resync_index;
			uint_t	 _t_un_resync_line_index;
		} _resync;
		struct  {
			daddr32_t _t_un_grow_tb;
			uint_t  _t_un_init_colcnt;
			uint_t  _t_un_init_iocnt;
		} _init;
	} _t_un;
	uint_t			un_resync_copysize;

	/*
	 * This spot is 8 byte aligned!!!
	 * Don't change this arrangement.
	 */
	union {
		struct {
			mr_unit_ic_t *_t_mr_ic;
		} _mric;
		struct {
			uint_t xx_un_linlck_mx[2];
		} _lckmx;
	} _unic;

	short			xx_un_linlck_cv;
	int			xx_un_mx[2];
	short			xx_un_cv;
	hsp_t			un_hsp_id;
	mr_column32_od_t	un_column[1];
} mr_unit32_od_t;

typedef struct raid_pwhdr {
	uint_t		rpw_magic;
	uint_t		rpw_sum;
	int		rpw_columnnum;
	diskaddr_t	rpw_blkno;
	uint_t		rpw_blkcnt;
	long long	rpw_id;
	uint_t		rpw_colcount;
	uint_t		rpw_column;
	uint_t		rpw_unit;
	uint_t		rpw_magic_ext;
	uint_t		rpw_origcolumncnt;
	uint_t		rpw_totalcolumncnt;
	uint_t		rpw_segsize;
	diskaddr_t	rpw_segsincolumn;
	uint_t		rpw_pwcnt;
	uint_t		rpw_pwsize;
	diskaddr_t	rpw_devstart;
	diskaddr_t	rpw_pwstart;
	char 		rpw_filler[12];
} raid_pwhdr_t;

/*
 * For old 32 bit pre-write area
 */
typedef struct raid_pwhdr32_od {
	uint_t		rpw_magic;
	uint_t		rpw_sum;
	int		rpw_columnnum;
	daddr32_t	rpw_blkno;
	daddr32_t	rpw_blkcnt;
	long long	rpw_id;
	uint_t		rpw_colcount;
	uint_t		rpw_column;
	uint_t		rpw_unit;
	uint_t		rpw_magic_ext;
	uint_t		rpw_origcolumncnt;
	uint_t		rpw_totalcolumncnt;
	uint_t		rpw_segsize;
	uint_t		rpw_segsincolumn;
	uint_t		rpw_pwcnt;
	uint_t		rpw_pwsize;
	uint_t		rpw_devstart;
	uint_t		rpw_pwstart;
	rus_state_t	rpw_unit_state;
	rcs_state_t	rpw_next_column_state;
	rcs_state_t	rpw_prev_column_state;
} raid_pwhdr32_od_t;
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef	_KERNEL

/*
 * the buffer header is only bp_mapin if it is needed.  It is needed on
 * all writes and on some reads.  ps_mapin is non zero if the buffer is
 * maped in.  ps_mapin_mx protect ps_mapin.  The protocol for usage is
 *
 * 1) check for non-zero and continue if non-zero
 * 2) aquire the ps_mapin_mx
 * 3) recheck for non-zero and continue if non-zero
 * 4) bp_mapin
 * 5) set ps_mapin to non-zero
 * 6) drop ps_mapin_mx
 *
 * the reason for this is to avoid the mutex when possible.
 */
typedef struct md_raidps {			/* raid parent save */
	DAEMON_QUEUE
	uint_t		ps_magic;
	mr_unit_t	*ps_un;
	mdi_unit_t	*ps_ui;
	buf_t		*ps_bp;
	caddr_t		ps_addr;
	int		ps_flags;
	int		ps_error;
	int		ps_frags;
	int		ps_pwfrags;
	int		ps_mapin;	/* buffer maped in if non zero */
	kmutex_t	ps_mx;
	kmutex_t	ps_mapin_mx;	/* protects ps_mapin */
} md_raidps_t;

/* flags for parent save area */

#define	MD_RPS_ERROR		0x0001
#define	MD_RPS_READ		0x0020
#define	MD_RPS_WRITE		0x0040
#define	MD_RPS_DONE		0x0080
#define	MD_RPS_INUSE		0x0100
#define	MD_RPS_IODONE		0x0200
#define	MD_RPS_HSREQ		0x0400

/*
 * used in cs_state to describe the type of io operation in progress
 */
enum	raid_io_stage {
		RAID_NONE = 0x0,
		RAID_READ_DONE = 0x1,
		RAID_WRITE_DONE = 0x2,
		RAID_PREWRITE_DONE = 0x4,
		RAID_WRITE_PONLY_DONE = 0x8,
		RAID_WRITE_DONLY_DONE = 0x10,
		RAID_LINE_PWDONE = 0x20
};

typedef struct md_raidcbuf {
	DAEMON_QUEUE
	uint_t			cbuf_magic;
	struct md_raidcbuf	*cbuf_next;		/* 0x10 */
	mr_unit_t		*cbuf_un;
	md_raidps_t		*cbuf_ps;
	int			cbuf_column;
	size_t			cbuf_bcount;		/* 0x20 */
	caddr_t			cbuf_buffer;
	int			cbuf_sum;
	int			cbuf_pwslot;
	int			cbuf_pwcnt;		/* 0x30 */
	int			cbuf_flags;
	buf_t			cbuf_bp;
	uint_t			cbuf_pad[4];
} md_raidcbuf_t;
#define	CBUF_PW_INVALIDATE	(0x00000001)
#define	CBUF_WRITE		(0x00000002)

typedef struct md_raidcs {
	DAEMON_QUEUE
	uint_t			cs_magic;
	minor_t			cs_mdunit;
	mr_unit_t		*cs_un;
	int			cs_flags;
	md_raidps_t		*cs_ps;
	diskaddr_t		cs_line;
	void			(*cs_call)();
	void			(*cs_error_call)();
	void			(*cs_retry_call)();
	struct md_raidcs	*cs_linlck_next;
	struct md_raidcs	*cs_linlck_prev;
	long long		cs_pwid;
	int			cs_dcolumn;
	int			cs_dpwslot;
	uint_t			cs_dflags;
	int			cs_pcolumn;
	int			cs_ppwslot;
	uint_t			cs_pflags;
	size_t			cs_bcount;
	uint_t			cs_blkcnt;
	diskaddr_t		cs_blkno;
	diskaddr_t		cs_lastblk;
	int			cs_loop;
	caddr_t			cs_addr;	/* base address of io */
	off_t			cs_offset;	/* offset into the base */
	caddr_t			cs_dbuffer;
	caddr_t			cs_pbuffer;
	int			cs_frags;
	int			cs_strategy_flag;
	void			*cs_strategy_private;
	md_raidcbuf_t		*cs_buflist;
	int			cs_error;
	int			cs_resync_check;
	int			cs_rstate;
	enum raid_io_stage	cs_stage; 		/* current io stage */
	md_raidcbuf_t		*cs_pw_inval_list;

	kmutex_t		cs_mx;

	buf_t			cs_pbuf;
	uint_t			cs_pad1;
	buf_t			cs_hbuf;
	uint_t			cs_pad2;
	/* Add new structure members HERE!! */
	buf_t			cs_dbuf;
	/*  DO NOT add struture members here; cs_dbuf is dynamically sized */
} md_raidcs_t;

/* value definitions for cs_resync_check */
#define	RCL_OKAY		0x01	/* write to both orig and alt */
#define	RCL_ERRED		0x08	/* treat column as rcs_ERRED */

#define	RCL_DATA_MASK		0x000000ff
#define	RCL_PARITY_MASK		0x0000ff00
#define	RCL_PARITY_OFFSET	8	/* insure masks match offset */

#define	RCL_PARITY(value)	(((value) & RCL_PARITY_MASK) >> \
				    RCL_PARITY_OFFSET)

#define	RCL_DATA(value)		((value) & RCL_DATA_MASK)

/* value definitions for cs_flags */
#define	MD_RCS_ISCALL		0x000001	/* call cs_call in interrupt */
#define	MD_RCS_UNDBUF		0x000002	/* holding unit data buffer */
#define	MD_RCS_UNPBUF		0x000004	/* holding unit parity buffer */
#define	MD_RCS_MPBUF		0x000008
#define	MD_RCS_HAVE_PW_SLOTS	0x000010	/* pw slots gotten */
#define	MD_RCS_PWDONE		0x000040	/* pwfrags are decremented */
#define	MD_RCS_READER		0x000100	/* reader line lock needed */
#define	MD_RCS_WRITER		0x000200	/* writer line lock needed */
#define	MD_RCS_LLOCKD		0x000400	/* line lock held */
#define	MD_RCS_WAITING		0x000800	/* line lock waiting */
#define	MD_RCS_LINE		0x001000	/* full line write */
#define	MD_RCS_ERROR		0x010000	/* I/O error on this child */
#define	MD_RCS_RECOVERY		0x020000

/* value definitions for cs_pflags or cs_dflags */
#define	MD_RCS_ISUP		0x0002

/* value definitions for gcs_flags */
#define	MD_RGCS_ALLOCBUF	0x0001
/* returned value from raid_replay() */
#define	RAID_RPLY_SUCCESS	0x0000
#define	RAID_RPLY_ALLOCFAIL	0x0001
#define	RAID_RPLY_COMPREPLAY	0x0002
#define	RAID_RPLY_READONLY	0x0004
#define	RAID_RPLY_EIO		0x0008

typedef struct raid_rplybuf {
	caddr_t			rpl_data;
	buf_t			*rpl_buf;
} raid_rplybuf_t;

typedef struct raid_rplylst {
	struct raid_rplylst	*rpl_next;
	uint_t			rpl_colcnt;
	long long		rpl_id;
	int			rpl_column1;
	uint_t			rpl_slot1;
	raid_pwhdr_t		rpl_pwhdr1;
	int			rpl_column2;
	uint_t			rpl_slot2;
	raid_pwhdr_t		rpl_pwhdr2;
} raid_rplylst_t;

/* Externals from raid.c */
extern int	raid_build_incore(void *, int);
extern void	reset_raid(mr_unit_t *, minor_t, int);

/* Externals from raid_ioctl.c */
extern int	md_raid_ioctl(dev_t dev, int cmd, void *data,
		    int mode, IOLOCK *lockp);

/* rename named service functions */
md_ren_svc_t		raid_rename_check;
md_ren_svc_t		raid_rename_lock;
md_ren_void_svc_t	raid_rename_unlock;


/* redefinitions of the union shared by resync and init */
#define		un_resync_segment 	_t_un._resync._t_un_resync_segment
#define		un_resync_index		_t_un._resync._t_un_resync_index
#define		un_resync_line_index	_t_un._resync._t_un_resync_line_index

#define		un_grow_tb 		_t_un._init._t_un_grow_tb
#define		un_init_colcnt		_t_un._init._t_un_init_colcnt
#define		un_init_iocnt		_t_un._init._t_un_init_iocnt

#define	MD_RFLAG_NEEDBUF	(0x0001)
#define	MD_RFLAG_CLEAR		(0x0002)
#define	MD_RFLAG_KEEP		(0x0004)
#define	MD_RFLAG_NEEDPW		(0x0008)


extern void 		raid_set_state(mr_unit_t *un, int col,
			    rcs_state_t new_state, int force);
extern int		raid_replay(mr_unit_t *un);
extern void		raid_commit(mr_unit_t *un, mddb_recid_t *extras);
extern char		*raid_unit_state(rus_state_t state);
extern intptr_t		raid_hotspares();
extern void		raid_hs_release(hs_cmds_t cmd, mr_unit_t *un,
			    mddb_recid_t *recids, int hs_index);
extern int		raid_internal_open(minor_t mnum, int flag, int otyp,
			    int oflags);
extern int		raid_internal_close(minor_t mnum, int otyp,
			    int init_pw, int cflags);
extern int		raid_build_pwslot(mr_unit_t *unit, int column_index);
extern void		raid_free_pwslot(mr_unit_t *unit, int column_index);
extern void		release_resync_request(minor_t mnum);
extern int		resync_request(minor_t mnum, int column_index,
				size_t copysize, md_error_t *ep);
extern int		raid_resync_unit(minor_t mnum, md_error_t *ep);
extern void		raid_line_reader_lock(md_raidcs_t *cs,
			    int resync_thread);
extern void		raid_line_exit(md_raidcs_t *cs);
extern int		raid_state_cnt(mr_unit_t *un, rcs_state_t state);
extern int		raid_build_pw_reservation(mr_unit_t *un,
				int colindex);
extern int		init_pw_area(mr_unit_t *un, md_dev64_t dev_to_write,
			    diskaddr_t pwstart, uint_t col);
extern void		init_buf(buf_t *bp, int flags, size_t size);
extern void		destroy_buf(buf_t *bp);
extern void		reset_buf(buf_t *bp, int flags, size_t size);
extern void		md_raid_strategy(buf_t *pb, int flag, void *private);
extern void		raid_free_pw_reservation(mr_unit_t *un,
				int colindex);
extern void		raid_fillin_rpw(mr_unit_t *un,
				raid_pwhdr_t *pwhdrp, int col);
#endif  /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MD_RAID_H */
