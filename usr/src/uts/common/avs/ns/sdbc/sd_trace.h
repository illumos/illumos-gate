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


#ifndef _SD_TRACE_H
#define	_SD_TRACE_H

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef _SD_NOTRACE
#define	SDALERT(f, cd, len, fba, flg, ret)
#define	SDTRACE(f, cd, len, fba, flg, ret)
#define	DATA_LOG_CHAIN(ttype, c_ent, stp, ln)
#define	DATA_LOG(ttype, c_ent, stp, ln)
#else
#define	SDALERT(f, cd, len, fba, flg, ret) \
	_sd_alert(f, (int)cd, (int)len, (nsc_off_t)fba, (int)flg, (int)ret)
#define	SDTRACE(f, cd, len, fba, flg, ret) \
	if (_sd_trace_mask & (f)) \
		_sd_trace(f, (int)cd, (int)len, (nsc_off_t)fba,\
		    (int)flg, (int)ret)
#define	DATA_LOG_CHAIN(ttype, c_ent, stp, ln) \
	_sd_data_log_chain((int)(ttype), c_ent, (nsc_off_t)(stp), \
	    (nsc_size_t)(ln))
#if defined(_SD_FBA_DATA_LOG) || defined(lint)
#define	DATA_LOG(ttype, c_ent, stp, ln) \
	_sd_data_log((int)(ttype), c_ent, (nsc_off_t)(stp), (nsc_size_t)(ln))
#else
#define	DATA_LOG(ttype, c_ent, stp, ln) \
	SDTRACE(ttype, CENTRY_CD(c_ent), \
		ln, (nsc_off_t)(BLK_TO_FBA_NUM(CENTRY_BLK(c_ent)) + stp), \
		*(int *)((c_ent)->cc_data+FBA_SIZE(stp)), \
		*(int *)((c_ent)->cc_data+FBA_SIZE(stp+ln)-4))
#endif /* (_SD_FBA_DATA_LOG) */
#endif

#define	SDT_INV_CD	-1
#define	SDT_ANY_CD	-2
#define	SDT_INV_BL	0xffffffff

typedef struct _sdtr
{
	ushort_t t_func;	/* function being traced */
	ushort_t t_len;		/* allocation type */
	nsc_off_t t_fba;	/* fixed block offset */
	int t_flg;		/* buffer size requested */
	int t_ret;		/* return value */
	int t_time;		/* micro_second timer, or lbolt */
				/* low order only on LP64 systems */
} _sdtr_t;

typedef struct _sdtr_table
{
	int tt_cd;		/* cache device */
	int tt_max;		/* entries in table */
	int tt_in;		/* entries added */
	int tt_out;		/* entries read */
	int tt_cnt;		/* unread entries */
	int tt_cntout;		/* tt_cnt after dump */
	int tt_mask;		/* copy of _sd_trace_mask */
	int tt_lost;		/* lost after alert */
	char tt_alert;		/* alert signaled */
	char tt_lbolt;		/* use 'lbolt' instead of microsec */
	char tt_good;		/* use locking (races with end-action) */
	char tt_type;		/* memory region 0 or 1 (_SD_MEM_TRACE) */
	_sdtr_t tt_buf[1];	/* per-device trace records [0..tt_max] */
} _sdtr_table_t;

#if defined(_KERNEL)
typedef struct _sdbc_trace_s {
	_sdtr_table_t	*tbl;	/* points to the trace table for a cd */
	kmutex_t	*t_lock;  /* the lock for this cd */
	} _sdbc_trace_t;
#endif /* _KERNEL */

/* sd_adump() flags */
#define	SD_SET_SIZE	0x01	/* create log if it doesn't exist */
#define	SD_SET_MASK	0x02
#define	SD_SET_LBOLT	0x04
#define	SD_SET_GOOD	0x08
#define	SD_ADUMP_WAIT	0x10	/* wakeup for buffer full or alert */
#define	SD_ALERT_WAIT	0x20	/* wakeup for alert messages */

/* Trace function, category, mask bits */
#define	ST_FUNC		0x000f	/* functions per category */
#define	ST_CATMASK	0x0ff0  /* Category mask	*/

#define	ST_BCACHE	0x0010	/* BCACHE entry points */
#define	ST_BSUB		0x0020	/* BCACHE subroutines */
#define	ST_IO		0x0040	/* IO subsystem */
#define	ST_CCIO		0x0080	/* concurrent (dual) copy */
#define	ST_FT		0x0100	/* Fault-tolerant subsystem */
#define	ST_DL		0x0200	/* Data-logging (debug) */
#define	ST_STATS	0x0400	/* cache statistics */
#define	ST_CKD		0x0800	/* SIMCKD traces */

#define	ST_ENTER	0x1000	/* function entry */
#define	ST_EXIT		0x2000	/* function exit */
#define	ST_INFO		0x4000	/* see t_flg */
#define	ST_ALERT	0x8000	/* force write to daemon */

/*
 * dump file pseudo-entries
 */
#define	SDF_LOST	0x0000	/* trace is missing entries */
#define	SDF_CD		0x0001	/* new device (following entries) */

/*
 * ST_BCACHE functions
 */
#define	SDF_OPEN	0x00 | ST_BCACHE
#define	SDF_CLOSE	0x01 | ST_BCACHE
#define	SDF_HALLOC	0x02 | ST_BCACHE
#define	SDF_HFREE	0x03 | ST_BCACHE
#define	SDF_ALLOCBUF	0x04 | ST_BCACHE
#define	SDF_FREEBUF	0x05 | ST_BCACHE
#define	SDF_WRITE	0x06 | ST_BCACHE
#define	SDF_READ	0x07 | ST_BCACHE
#define	SDF_UNCOMMIT	0x08 | ST_BCACHE
#define	SDF_ZERO	0x09 | ST_BCACHE
#define	SDF_HINT	0x0a | ST_BCACHE
#define	SDF_ATTACH	0x0b | ST_BCACHE | ST_FT
#define	SDF_DETACH	0x0c | ST_BCACHE | ST_FT
#define	SDF_NOTIFY	0x0d | ST_BCACHE

/*
 * ST_BSUB - bcache subroutines
 */
#define	SDF_ENT_GET	0x00 | ST_BSUB
#define	SDF_ENT_ALLOC	0x01 | ST_BSUB
#define	SDF_READ_EA	0x02 | ST_BSUB
#define	SDF_ENT_FREE	0x03 | ST_BSUB
#define	SDF_WR_ALLOC	0x04 | ST_BSUB
#define	SDF_WR_FREE	0x05 | ST_BSUB
#define	SDF_WR_ALLOCONE	0x06 | ST_BSUB


/*
 * SD_IO - I/O subsustem
 */
#define	SDF_FLCLIST	0x00 | ST_IO
#define	SDF_FLCENT	0x01 | ST_IO
#define	SDF_FLCLIST_EA	0x02 | ST_IO
#define	SDF_FLCENT_EA	0x03 | ST_IO
#define	SDF_FLDONE	0x04 | ST_IO
#define	SDF_IOB_ALLOC	0x05 | ST_IO

/*
 * ST_FT - Fault-tolerant subsystem
 */
#define	SDF_AWAITR	0x00 | ST_FT
#define	SDF_RECOVER	0x01 | ST_FT
#define	SDF_FT_CLONE	0x02 | ST_FT
#define	SDF_REFLECT	0x03 | ST_FT
#define	SDF_ONLINE	0x04 | ST_FT

/*
 * ST_STATS - Statistics points
 */
#define	SDF_REPLACE	0x00 | ST_STATS
#define	SDF_DISCONNECT	0x01 | ST_STATS

/*
 * ST_INFO
 */
#define	SDF_COVERAGE	0x00 | ST_INFO

/*
 * ST_DL
 */

#define	SDF_ALLOC	0x00 | ST_DL
#define	SDF_RD		0x01 | ST_DL
#define	SDF_WR		0x02 | ST_DL
#define	SDF_WRSYNC	0x03 | ST_DL
#define	SDF_FLSHLIST	0x04 | ST_DL
#define	SDF_FLSHENT	0x05 | ST_DL
#define	SDF_RDIO	0x06 | ST_DL
#define	SDF_FLEA	0x07 | ST_DL
#define	SDF_FLSTEA	0x08 | ST_DL
#define	SDF_WRSYEA	0x09 | ST_DL

/*
 * More entry points
 */

#ifdef _SD_FNAME
/*
 * function category names
 * 	change these when changing functions above
 *	compress name to fit in 8 printable characters
 */
char *_bcache_fname[16] =
{
	"open",
	"close",
	"al_hndl",
	"fr_hndl",
	"al_buf",
	"fr_buf",
	"write",
	"read",
	"ucommit",
	"zero",
	"hint",
	"attach",
	"detach",
	"notify",
};

char *_bsub_fname[16] =
{
	"get_cent",
	"al_cent",
	"read_ea",
	"fr_cent",
	"al_went",
	"fr_went",
	"al_wone",
};

char *_io_fname[16] =
{
	"flclist",
	"flcent",
	"eaclist",
	"eacent",
	"fldone",
	"get_iob",
};

char *_ccio_fname[16] =
{
	"ccio",
	"dc_albuf",
	"dc_frbuf",
	"dc_write",
	"dc_read",
	"dc_zero",
};

char *_ft_fname[16] =
{
	"wait_rec",
	"cache_rc",
	"ft_clone",
	"reflect",
	"online",
};

char *_stats_fname[16] =
{
	"LRU-repl",
	"Disconn",
};

char *_info_fname[16] =
{
	"Cover",
};

char *_dlog_fname[16] =
{
	"alloc",
	"rd",
	"wr",
	"wrsync",
	"flshlist",
	"flshent",
	"rdio",
	"flea",
	"flstea",
	"wrsyea",
};

#endif	/* _ST_NAMES */
#ifdef _KERNEL

extern int _sd_trace_mask;

extern void _sdbc_tr_unload(void);
extern int _sdbc_tr_load(void);
extern int _sdbc_tr_configure(int cd);
extern void _sdbc_tr_deconfigure(void);
extern int _sd_adump(void *args, int *rvp);
extern void _sd_alert(int f, int cd, int len, nsc_off_t fba, int flg, int ret);
extern void _sd_trace(int f, int cd, int len, nsc_off_t fba, int flg,
    int ret);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SD_TRACE_H */
