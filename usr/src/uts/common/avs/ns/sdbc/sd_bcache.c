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

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/buf.h>
#include <sys/ddi.h>

#include <sys/nsc_thread.h>
#include <sys/nsctl/nsctl.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "sd_bcache.h"
#include "sd_trace.h"
#include "sd_io.h"
#include "sd_bio.h"
#include "sd_ft.h"
#include "sd_misc.h"
#include "sd_pcu.h"

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>
#include <sys/nsctl/safestore.h>
#ifndef DS_DDICT
#include <sys/ddi_impldefs.h>
#endif


/*
 * kstat interface
 */

static kstat_t *sdbc_global_stats_kstat;
static int sdbc_global_stats_update(kstat_t *ksp, int rw);

typedef struct {
	kstat_named_t	ci_sdbc_count;
	kstat_named_t	ci_sdbc_loc_count;
	kstat_named_t	ci_sdbc_rdhits;
	kstat_named_t	ci_sdbc_rdmiss;
	kstat_named_t	ci_sdbc_wrhits;
	kstat_named_t	ci_sdbc_wrmiss;
	kstat_named_t	ci_sdbc_blksize;
	kstat_named_t	ci_sdbc_lru_blocks;
#ifdef DEBUG
	kstat_named_t	ci_sdbc_lru_noreq;
	kstat_named_t	ci_sdbc_lru_req;
#endif
	kstat_named_t	ci_sdbc_wlru_inq;
	kstat_named_t	ci_sdbc_cachesize;
	kstat_named_t	ci_sdbc_numblocks;
	kstat_named_t	ci_sdbc_num_shared;
	kstat_named_t	ci_sdbc_wrcancelns;
	kstat_named_t	ci_sdbc_destaged;
	kstat_named_t	ci_sdbc_nodehints;
} sdbc_global_stats_t;

static sdbc_global_stats_t sdbc_global_stats = {
	{SDBC_GKSTAT_COUNT,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_LOC_COUNT,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_RDHITS,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_RDMISS,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_WRHITS,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_WRMISS,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_BLKSIZE,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_LRU_BLOCKS,	KSTAT_DATA_ULONG},
#ifdef DEBUG
	{SDBC_GKSTAT_LRU_NOREQ,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_LRU_REQ,		KSTAT_DATA_ULONG},
#endif
	{SDBC_GKSTAT_WLRU_INQ,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_CACHESIZE,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_NUMBLOCKS,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_NUM_SHARED,	KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_WRCANCELNS,	KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_DESTAGED,		KSTAT_DATA_ULONG},
	{SDBC_GKSTAT_NODEHINTS,		KSTAT_DATA_ULONG},
};

static kstat_t **sdbc_cd_kstats;
static kstat_t **sdbc_cd_io_kstats;
static kmutex_t *sdbc_cd_io_kstats_mutexes;
static kstat_t *sdbc_global_io_kstat;
static kmutex_t sdbc_global_io_kstat_mutex;
static int sdbc_cd_stats_update(kstat_t *ksp, int rw);
static int cd_kstat_add(int cd);
static int cd_kstat_remove(int cd);

typedef struct {
	kstat_named_t	ci_sdbc_vol_name;
	kstat_named_t	ci_sdbc_failed;
	kstat_named_t	ci_sdbc_cd;
	kstat_named_t	ci_sdbc_cache_read;
	kstat_named_t	ci_sdbc_cache_write;
	kstat_named_t	ci_sdbc_disk_read;
	kstat_named_t	ci_sdbc_disk_write;
	kstat_named_t	ci_sdbc_filesize;
	kstat_named_t	ci_sdbc_numdirty;
	kstat_named_t	ci_sdbc_numio;
	kstat_named_t	ci_sdbc_numfail;
	kstat_named_t	ci_sdbc_destaged;
	kstat_named_t	ci_sdbc_wrcancelns;
	kstat_named_t	ci_sdbc_cdhints;
} sdbc_cd_stats_t;

static sdbc_cd_stats_t sdbc_cd_stats = {
	{SDBC_CDKSTAT_VOL_NAME,		KSTAT_DATA_CHAR},
	{SDBC_CDKSTAT_FAILED,		KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_CD,		KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_CACHE_READ,	KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_CACHE_WRITE,	KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_DISK_READ,	KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_DISK_WRITE,	KSTAT_DATA_ULONG},
#ifdef NSC_MULTI_TERABYTE
	{SDBC_CDKSTAT_FILESIZE,		KSTAT_DATA_UINT64},
#else
	{SDBC_CDKSTAT_FILESIZE,		KSTAT_DATA_ULONG},
#endif
	{SDBC_CDKSTAT_NUMDIRTY,		KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_NUMIO,		KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_NUMFAIL,		KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_DESTAGED,		KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_WRCANCELNS,	KSTAT_DATA_ULONG},
	{SDBC_CDKSTAT_CDHINTS,		KSTAT_DATA_ULONG},
};

#ifdef DEBUG
/*
 * dynmem kstat interface
 */
static kstat_t *sdbc_dynmem_kstat_dm;
static int simplect_dm;
static int sdbc_dynmem_kstat_update_dm(kstat_t *ksp, int rw);

typedef struct {
	kstat_named_t  ci_sdbc_monitor_dynmem;
	kstat_named_t  ci_sdbc_max_dyn_list;
	kstat_named_t  ci_sdbc_cache_aging_ct1;
	kstat_named_t  ci_sdbc_cache_aging_ct2;
	kstat_named_t  ci_sdbc_cache_aging_ct3;
	kstat_named_t  ci_sdbc_cache_aging_sec1;
	kstat_named_t  ci_sdbc_cache_aging_sec2;
	kstat_named_t  ci_sdbc_cache_aging_sec3;
	kstat_named_t  ci_sdbc_cache_aging_pcnt1;
	kstat_named_t  ci_sdbc_cache_aging_pcnt2;
	kstat_named_t  ci_sdbc_max_holds_pcnt;

	kstat_named_t  ci_sdbc_alloc_ct;
	kstat_named_t  ci_sdbc_dealloc_ct;
	kstat_named_t  ci_sdbc_history;
	kstat_named_t  ci_sdbc_nodatas;
	kstat_named_t  ci_sdbc_candidates;
	kstat_named_t  ci_sdbc_deallocs;
	kstat_named_t  ci_sdbc_hosts;
	kstat_named_t  ci_sdbc_pests;
	kstat_named_t  ci_sdbc_metas;
	kstat_named_t  ci_sdbc_holds;
	kstat_named_t  ci_sdbc_others;
	kstat_named_t  ci_sdbc_notavail;

	kstat_named_t  ci_sdbc_process_directive;

	kstat_named_t  ci_sdbc_simplect;
} sdbc_dynmem_dm_t;

static sdbc_dynmem_dm_t sdbc_dynmem_dm = {
	{SDBC_DMKSTAT_MONITOR_DYNMEM,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_MAX_DYN_LIST,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_CACHE_AGING_CT1,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_CACHE_AGING_CT2,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_CACHE_AGING_CT3,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_CACHE_AGING_SEC1,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_CACHE_AGING_SEC2,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_CACHE_AGING_SEC3,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_CACHE_AGING_PCNT1,	KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_CACHE_AGING_PCNT2,	KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_MAX_HOLDS_PCNT,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_ALLOC_CNT,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_DEALLOC_CNT,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_HISTORY,			KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_NODATAS,			KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_CANDIDATES,		KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_DEALLOCS,			KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_HOSTS,			KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_PESTS,			KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_METAS,			KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_HOLDS,			KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_OTHERS,			KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_NOTAVAIL,			KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_PROCESS_DIRECTIVE,	KSTAT_DATA_ULONG},
	{SDBC_DMKSTAT_SIMPLECT,			KSTAT_DATA_ULONG}
};
#endif

/* End of dynmem kstats */

#ifdef DEBUG
int *dmchainpull_table;  /* dmchain wastage stats */
#endif

/*
 * dynmem process vars
 */
extern _dm_process_vars_t dynmem_processing_dm;

/* metadata for volumes */
ss_voldata_t *_sdbc_gl_file_info;

size_t _sdbc_gl_file_info_size;

/* metadata for cache write blocks */
static ss_centry_info_t *_sdbc_gl_centry_info;

/* wblocks * sizeof(ss_centry_info_t) */
static size_t _sdbc_gl_centry_info_size;

static int _SD_DELAY_QUEUE = 1;
static int sdbc_allocb_inuse, sdbc_allocb_lost, sdbc_allocb_hit;
static int sdbc_allocb_pageio1, sdbc_allocb_pageio2;
static int sdbc_centry_hit, sdbc_centry_inuse, sdbc_centry_lost;
static int sdbc_dmchain_not_avail;
static int sdbc_allocb_deallocd;
static int sdbc_centry_deallocd;
static int sdbc_check_cot;
static int sdbc_ra_hash; /* 1-block read-ahead fails due to hash hit */
static int sdbc_ra_none; /* 1-block read-ahead fails due to "would block" */


/*
 * Set the following variable to 1 to enable pagelist io mutual
 * exclusion on all _sd_alloc_buf() operations.
 *
 * This is set to ON to prevent front end / back end races between new
 * NSC_WRTHRU io operations coming in through _sd_alloc_buf(), and
 * previously written data being flushed out to disk by the sdbc
 * flusher at the back end.
 * -- see bugtraq 4287564
 * -- Simon Crosland, Mon Nov  8 16:34:09 GMT 1999
 */
static int sdbc_pageio_always = 1;

int sdbc_use_dmchain = 0; /* start time switch for dm chaining */
int sdbc_prefetch1 = 1;   /* do 1-block read-ahead */
/*
 * if sdbc_static_cache is 1 allocate all cache memory at startup.
 * deallocate only at shutdown.
 */
int sdbc_static_cache = 1;

#ifdef DEBUG
/*
 * Pagelist io mutual exclusion debug facility.
 */
#define	SDBC_PAGEIO_OFF		0	/* no debug */
#define	SDBC_PAGEIO_RDEV	1	/* force NSC_PAGEIO for specified dev */
#define	SDBC_PAGEIO_RAND	2	/* randomly force NSC_PAGEIO */
#define	SDBC_PAGEIO_ALL		3	/* always force NSC_PAGEIO */
static int sdbc_pageio_debug = SDBC_PAGEIO_OFF;
static dev_t sdbc_pageio_rdev = (dev_t)-1;
#endif

/*
 * INF SD cache global data
 */

_sd_cd_info_t	*_sd_cache_files;
_sd_stats_t   	*_sd_cache_stats;
kmutex_t	_sd_cache_lock;

_sd_hash_table_t	*_sd_htable;
_sd_queue_t	_sd_lru_q;

_sd_cctl_t	*_sd_cctl[_SD_CCTL_GROUPS];
int		_sd_cctl_groupsz;

_sd_net_t  _sd_net_config;

extern krwlock_t sdbc_queue_lock;

unsigned int _sd_node_hint;

#define	_SD_LRU_Q	(&_sd_lru_q)
int BLK_FBAS;		/* number of FBA's in a cache block */
int CACHE_BLOCK_SIZE;	/* size in bytes of a cache block */
int CBLOCKS;
_sd_bitmap_t BLK_FBA_BITS;
static int sdbc_prefetch_valid_cnt;
static int sdbc_prefetch_busy_cnt;
static int sdbc_prefetch_trailing;
static int sdbc_prefetch_deallocd;
static int sdbc_prefetch_pageio1;
static int sdbc_prefetch_pageio2;
static int sdbc_prefetch_hit;
static int sdbc_prefetch_lost;
static int _sd_prefetch_opt = 1; /* 0 to disable & use _prefetch_sb_vec[] */
static nsc_vec_t _prefetch_sb_vec[_SD_MAX_BLKS + 1];

_sd_bitmap_t _fba_bits[] = {
	0x0000, 0x0001, 0x0003, 0x0007,
	0x000f,	0x001f, 0x003f, 0x007f,
	0x00ff,
#if defined(_SD_8K_BLKSIZE)
		0x01ff, 0x03ff, 0x07ff,
	0x0fff,	0x1fff, 0x3fff, 0x7fff,
	0xffff,
#endif
};


static int _sd_ccsync_cnt = 256;
static _sd_cctl_sync_t *_sd_ccent_sync;

nsc_io_t *sdbc_io;

#ifdef _MULTI_DATAMODEL
_sd_stats32_t *_sd_cache_stats32 = NULL;
#endif


#ifdef DEBUG
int cmn_level = CE_PANIC;
#else
int cmn_level = CE_WARN;
#endif

/*
 * Forward declare all statics that are used before defined to enforce
 * parameter checking
 * Some (if not all) of these could be removed if the code were reordered
 */

static void _sdbc_stats_deconfigure(void);
static int _sdbc_stats_configure(int cblocks);
static int _sdbc_lruq_configure(_sd_queue_t *);
static void _sdbc_lruq_deconfigure(void);
static int _sdbc_mem_configure(int cblocks, spcs_s_info_t kstatus);
static void _sdbc_mem_deconfigure(int cblocks);
static void _sd_ins_queue(_sd_queue_t *, _sd_cctl_t *centry);
static int _sd_flush_cd(int cd);
static int _sd_check_buffer_alloc(int cd, nsc_off_t fba_pos, nsc_size_t fba_len,
    _sd_buf_handle_t **hp);
static int _sd_doread(_sd_buf_handle_t *handle, _sd_cctl_t *cc_ent,
    nsc_off_t fba_pos, nsc_size_t fba_len, int flag);
static void _sd_async_read_ea(blind_t xhandle, nsc_off_t fba_pos,
    nsc_size_t fba_len, int error);
static void _sd_async_write_ea(blind_t xhandle, nsc_off_t fba_pos,
    nsc_size_t fba_len, int error);
static void _sd_queue_write(_sd_buf_handle_t *handle, nsc_off_t fba_pos,
    nsc_size_t fba_len);
static int _sd_remote_store(_sd_cctl_t *cc_ent, nsc_off_t fba_pos,
    nsc_size_t fba_len);
static int _sd_copy_direct(_sd_buf_handle_t *handle1, _sd_buf_handle_t *handle2,
    nsc_off_t fba_pos1, nsc_off_t fba_pos2, nsc_size_t fba_len);
static int _sd_sync_write(_sd_buf_handle_t *handle, nsc_off_t fba_pos,
    nsc_size_t fba_len, int flag);
static int _sd_sync_write2(_sd_buf_handle_t *wr_handle, nsc_off_t wr_st_pos,
    nsc_size_t fba_len, int flag, _sd_buf_handle_t *rd_handle,
    nsc_off_t rd_st_pos);
static int sdbc_fd_attach_cd(blind_t xcd);
static int sdbc_fd_detach_cd(blind_t xcd);
static int sdbc_fd_flush_cd(blind_t xcd);
static int _sdbc_gl_centry_configure(spcs_s_info_t);
static int _sdbc_gl_file_configure(spcs_s_info_t);
static void _sdbc_gl_centry_deconfigure(void);
static void _sdbc_gl_file_deconfigure(void);
static int sdbc_doread_prefetch(_sd_cctl_t *cc_ent, nsc_off_t fba_pos,
    nsc_size_t fba_len);
static _sd_bitmap_t update_dirty(_sd_cctl_t *cc_ent, sdbc_cblk_fba_t st_off,
    sdbc_cblk_fba_t st_len);
static int _sd_prefetch_buf(int cd, nsc_off_t fba_pos, nsc_size_t fba_len,
    int flag, _sd_buf_handle_t *handle, int locked);

/* dynmem support */
static int _sd_setup_category_on_type(_sd_cctl_t *header);
static int _sd_setup_mem_chaining(_sd_cctl_t *header, int flag);

static int sdbc_check_cctl_cot(_sd_cctl_t *);

static int sdbc_dmqueues_configure();
static void sdbc_dmqueues_deconfigure();
static _sd_cctl_t *sdbc_get_dmchain(int, int *, int);
static int sdbc_dmchain_avail(_sd_cctl_t *);
void sdbc_requeue_dmchain(_sd_queue_t *, _sd_cctl_t *, int, int);
static void sdbc_ins_dmqueue_back(_sd_queue_t *, _sd_cctl_t *);
void sdbc_ins_dmqueue_front(_sd_queue_t *, _sd_cctl_t *);
void sdbc_remq_dmchain(_sd_queue_t *, _sd_cctl_t *);
static void sdbc_clear_dmchain(_sd_cctl_t *, _sd_cctl_t *);
void sdbc_requeue_head_dm_try(_sd_cctl_t *);
static _sd_cctl_t *sdbc_alloc_dmc(int, nsc_off_t, nsc_size_t, int *,
    sdbc_allocbuf_t *, int);
static _sd_cctl_t *sdbc_alloc_lru(int, nsc_off_t, int *, int);
static _sd_cctl_t *sdbc_alloc_from_dmchain(int, nsc_off_t, sdbc_allocbuf_t *,
    int);
static void sdbc_centry_init_dm(_sd_cctl_t *);
static int sdbc_centry_memalloc_dm(_sd_cctl_t *, int, int);
static void sdbc_centry_alloc_end(sdbc_allocbuf_t *);




/* _SD_DEBUG */
#if defined(_SD_DEBUG) || defined(DEBUG)
static int _sd_cctl_valid(_sd_cctl_t *);
#endif

static
nsc_def_t _sdbc_fd_def[] = {
	"Attach",	(uintptr_t)sdbc_fd_attach_cd,	0,
	"Detach",	(uintptr_t)sdbc_fd_detach_cd,	0,
	"Flush",	(uintptr_t)sdbc_fd_flush_cd,	0,
	0,		0,				0
};


/*
 * _sdbc_cache_configure - initialize cache blocks, queues etc.
 *
 * ARGUMENTS:
 * 	cblocks  - Number of cache blocks
 *
 * RETURNS:
 *	0 on success.
 *	SDBC_EENABLEFAIL or SDBC_EMEMCONFIG on failure.
 *
 */



int
_sdbc_cache_configure(int cblocks, spcs_s_info_t kstatus)
{
	CBLOCKS = cblocks;

	_sd_cache_files = (_sd_cd_info_t *)
	    kmem_zalloc(sdbc_max_devs * sizeof (_sd_cd_info_t),
	    KM_SLEEP);

	if (_sdbc_stats_configure(cblocks))
		return (SDBC_EENABLEFAIL);

	if (sdbc_use_dmchain) {
		if (sdbc_dmqueues_configure())
			return (SDBC_EENABLEFAIL);
	} else {
		if (_sdbc_lruq_configure(_SD_LRU_Q))
			return (SDBC_EENABLEFAIL);
	}


	if (_sdbc_mem_configure(cblocks, kstatus))
		return (SDBC_EMEMCONFIG);

	CACHE_BLOCK_SIZE = BLK_SIZE(1);
	BLK_FBAS = FBA_NUM(CACHE_BLOCK_SIZE);
	BLK_FBA_BITS = _fba_bits[BLK_FBAS];

	sdbc_allocb_pageio1 = 0;
	sdbc_allocb_pageio2 = 0;
	sdbc_allocb_hit = 0;
	sdbc_allocb_inuse = 0;
	sdbc_allocb_lost = 0;
	sdbc_centry_inuse = 0;
	sdbc_centry_lost = 0;
	sdbc_centry_hit = 0;
	sdbc_centry_deallocd = 0;
	sdbc_dmchain_not_avail = 0;
	sdbc_allocb_deallocd = 0;

	sdbc_prefetch_valid_cnt = 0;
	sdbc_prefetch_busy_cnt = 0;
	sdbc_prefetch_trailing = 0;
	sdbc_prefetch_deallocd = 0;
	sdbc_prefetch_pageio1 = 0;
	sdbc_prefetch_pageio2 = 0;
	sdbc_prefetch_hit = 0;
	sdbc_prefetch_lost = 0;

	sdbc_check_cot = 0;
	sdbc_prefetch1 = 1;
	sdbc_ra_hash = 0;
	sdbc_ra_none = 0;

	return (0);
}

/*
 * _sdbc_cache_deconfigure - cache is being deconfigured. Release any
 * memory that we acquired during the configuration process and return
 * to the unconfigured state.
 *
 *  NOTE: all users of the cache should be inactive at this point,
 *  i.e. we are unregistered from sd and all cache daemons/threads are
 *  gone.
 *
 */
void
_sdbc_cache_deconfigure(void)
{
	/* CCIO shutdown must happen before memory is free'd */

	if (_sd_cache_files) {
		kmem_free(_sd_cache_files,
		    sdbc_max_devs * sizeof (_sd_cd_info_t));
		_sd_cache_files = (_sd_cd_info_t *)NULL;
	}


	BLK_FBA_BITS = 0;
	BLK_FBAS = 0;
	CACHE_BLOCK_SIZE = 0;
	_sdbc_mem_deconfigure(CBLOCKS);
	_sdbc_gl_centry_deconfigure();
	_sdbc_gl_file_deconfigure();

	if (sdbc_use_dmchain)
		sdbc_dmqueues_deconfigure();
	else
		_sdbc_lruq_deconfigure();
	_sdbc_stats_deconfigure();

	CBLOCKS = 0;
}


/*
 * _sdbc_stats_deconfigure - cache is being deconfigured turn off
 * stats. This could seemingly do more but we leave most of the
 * data intact until cache is configured again.
 *
 */
static void
_sdbc_stats_deconfigure(void)
{
	int i;

#ifdef DEBUG
	if (sdbc_dynmem_kstat_dm) {
		kstat_delete(sdbc_dynmem_kstat_dm);
		sdbc_dynmem_kstat_dm  = NULL;
	}
#endif

	if (sdbc_global_stats_kstat) {
		kstat_delete(sdbc_global_stats_kstat);
		sdbc_global_stats_kstat  = NULL;
	}

	if (sdbc_cd_kstats) {
		for (i = 0; i < sdbc_max_devs; i++) {
			if (sdbc_cd_kstats[i]) {
				kstat_delete(sdbc_cd_kstats[i]);
				sdbc_cd_kstats[i] = NULL;
			}
		}
		kmem_free(sdbc_cd_kstats, sizeof (kstat_t *) * sdbc_max_devs);
		sdbc_cd_kstats = NULL;
	}

	if (sdbc_global_io_kstat) {
		kstat_delete(sdbc_global_io_kstat);
		mutex_destroy(&sdbc_global_io_kstat_mutex);
		sdbc_global_io_kstat = NULL;
	}

	if (sdbc_cd_io_kstats) {
		for (i = 0; i < sdbc_max_devs; i++) {
			if (sdbc_cd_io_kstats[i]) {
				kstat_delete(sdbc_cd_io_kstats[i]);
				sdbc_cd_io_kstats[i] = NULL;
			}
		}
		kmem_free(sdbc_cd_io_kstats, sizeof (kstat_t *) *
		    sdbc_max_devs);
		sdbc_cd_io_kstats = NULL;
	}

	if (sdbc_cd_io_kstats_mutexes) {
	/* mutexes are already destroyed in cd_kstat_remove() */
		kmem_free(sdbc_cd_io_kstats_mutexes,
		    sizeof (kmutex_t) * sdbc_max_devs);
		sdbc_cd_io_kstats_mutexes = NULL;
	}


	if (_sd_cache_stats) {
		kmem_free(_sd_cache_stats,
		    sizeof (_sd_stats_t) +
		    (sdbc_max_devs - 1) * sizeof (_sd_shared_t));
		_sd_cache_stats = NULL;
	}
#ifdef _MULTI_DATAMODEL
	if (_sd_cache_stats32) {
		kmem_free(_sd_cache_stats32, sizeof (_sd_stats32_t) +
		    (sdbc_max_devs - 1) * sizeof (_sd_shared_t));
		_sd_cache_stats32 = NULL;
	}
#endif
}

static int
_sdbc_stats_configure(int cblocks)
{

	_sd_cache_stats = kmem_zalloc(sizeof (_sd_stats_t) +
	    (sdbc_max_devs - 1) * sizeof (_sd_shared_t), KM_SLEEP);
	_sd_cache_stats->st_blksize = (int)BLK_SIZE(1);
	_sd_cache_stats->st_cachesize = cblocks * BLK_SIZE(1);
	_sd_cache_stats->st_numblocks = cblocks;
	_sd_cache_stats->st_wrcancelns = 0;
	_sd_cache_stats->st_destaged = 0;
#ifdef _MULTI_DATAMODEL
	_sd_cache_stats32 = kmem_zalloc(sizeof (_sd_stats32_t) +
	    (sdbc_max_devs - 1) * sizeof (_sd_shared_t), KM_SLEEP);
#endif

	/* kstat implementation - global stats */
	sdbc_global_stats_kstat = kstat_create(SDBC_KSTAT_MODULE, 0,
	    SDBC_KSTAT_GSTATS, SDBC_KSTAT_CLASS, KSTAT_TYPE_NAMED,
	    sizeof (sdbc_global_stats)/sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL|KSTAT_FLAG_WRITABLE);

	if (sdbc_global_stats_kstat != NULL) {
		sdbc_global_stats_kstat->ks_data = &sdbc_global_stats;
		sdbc_global_stats_kstat->ks_update = sdbc_global_stats_update;
		sdbc_global_stats_kstat->ks_private = _sd_cache_stats;
		kstat_install(sdbc_global_stats_kstat);
	} else {
		cmn_err(CE_WARN, "!sdbc: gstats kstat failed");
	}

	/* global I/O kstats */
	sdbc_global_io_kstat = kstat_create(SDBC_KSTAT_MODULE, 0,
	    SDBC_IOKSTAT_GSTATS, "disk", KSTAT_TYPE_IO, 1, 0);

	if (sdbc_global_io_kstat) {
		mutex_init(&sdbc_global_io_kstat_mutex, NULL, MUTEX_DRIVER,
		    NULL);
		sdbc_global_io_kstat->ks_lock =
		    &sdbc_global_io_kstat_mutex;
		kstat_install(sdbc_global_io_kstat);
	}

	/*
	 * kstat implementation - cd stats
	 * NOTE: one kstat instance for each open cache descriptor
	 */
	sdbc_cd_kstats = kmem_zalloc(sizeof (kstat_t *) * sdbc_max_devs,
	    KM_SLEEP);

	/*
	 * kstat implementation - i/o kstats per cache descriptor
	 * NOTE: one I/O kstat instance for each cd
	 */
	sdbc_cd_io_kstats = kmem_zalloc(sizeof (kstat_t *) * sdbc_max_devs,
	    KM_SLEEP);

	sdbc_cd_io_kstats_mutexes = kmem_zalloc(sizeof (kmutex_t) *
	    sdbc_max_devs, KM_SLEEP);

#ifdef DEBUG
	/* kstat implementation - dynamic memory stats */
	sdbc_dynmem_kstat_dm = kstat_create(SDBC_KSTAT_MODULE, 0,
	    SDBC_KSTAT_DYNMEM, SDBC_KSTAT_CLASS, KSTAT_TYPE_NAMED,
	    sizeof (sdbc_dynmem_dm)/sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL|KSTAT_FLAG_WRITABLE);

	if (sdbc_dynmem_kstat_dm != NULL) {
		sdbc_dynmem_kstat_dm->ks_data = &sdbc_dynmem_dm;
		sdbc_dynmem_kstat_dm->ks_update = sdbc_dynmem_kstat_update_dm;
		sdbc_dynmem_kstat_dm->ks_private = &dynmem_processing_dm;
		kstat_install(sdbc_dynmem_kstat_dm);
	} else {
		cmn_err(CE_WARN, "!sdbc: dynmem kstat failed");
	}
#endif

	return (0);
}

/*
 * sdbc_dmqueues_configure()
 * initialize the queues of dynamic memory chains.
 */

_sd_queue_t *sdbc_dm_queues;
static int max_dm_queues;


static int
sdbc_dmqueues_configure()
{
	int i;

	/*
	 * CAUTION! this code depends on max_dyn_list not changing
	 * if it does change behavior may be incorrect, as cc_alloc_size_dm
	 * depends on max_dyn_list and indexes to dmqueues are derived from
	 * cc_alloc_size_dm.
	 * see _sd_setup_category_on_type() and _sd_dealloc_dm()
	 * TODO: prevent max_dyn_list from on-the-fly modification (easy) or
	 * allow for on-the-fly changes to number of dm queues (hard).
	 */
	max_dm_queues = dynmem_processing_dm.max_dyn_list;

	++max_dm_queues; /* need a "0" queue for centrys with no memory */

	sdbc_dm_queues = (_sd_queue_t *)
	    kmem_zalloc(max_dm_queues * sizeof (_sd_queue_t), KM_SLEEP);

#ifdef DEBUG
	dmchainpull_table = (int *)kmem_zalloc(max_dm_queues *
	    max_dm_queues * sizeof (int), KM_SLEEP);
#endif

	for (i = 0; i < max_dm_queues; ++i) {
		(void) _sdbc_lruq_configure(&sdbc_dm_queues[i]);
		sdbc_dm_queues[i].sq_dmchain_cblocks = i;
	}

	return (0);
}

static void
sdbc_dmqueues_deconfigure()
{
	/* CAUTION! this code depends on max_dyn_list not changing */

	if (sdbc_dm_queues)
		kmem_free(sdbc_dm_queues, max_dm_queues * sizeof (_sd_queue_t));
	sdbc_dm_queues = NULL;
	max_dm_queues = 0;
}

#define	GOOD_LRUSIZE(q) ((q->sq_inq >= 0) || (q->sq_inq <= CBLOCKS))

/*
 * _sdbc_lruq_configure - initialize the lru queue
 *
 * ARGUMENTS: NONE
 * RETURNS:   0
 *
 */

static int
_sdbc_lruq_configure(_sd_queue_t *_sd_lru)
{

	_sd_lru->sq_inq = 0;

	mutex_init(&_sd_lru->sq_qlock, NULL, MUTEX_DRIVER, NULL);

	_sd_lru->sq_qhead.cc_next = _sd_lru->sq_qhead.cc_prev
	    = &(_sd_lru->sq_qhead);
	return (0);
}

/*
 * _sdbc_lruq_deconfigure - deconfigure the lru queue
 *
 * ARGUMENTS: NONE
 *
 */

static void
_sdbc_lruq_deconfigure(void)
{
	_sd_queue_t *_sd_lru;

	_sd_lru = _SD_LRU_Q;

	mutex_destroy(&_sd_lru->sq_qlock);
	bzero(_sd_lru, sizeof (_sd_queue_t));

}

/*
 * _sdbc_mem_configure - initialize the cache memory.
 *		Create and initialize the hash table.
 *		Create cache control blocks and fill them with relevent
 *		information and enqueue onto the lru queue.
 *		Initialize the Write control blocks (blocks that contain
 *		information as to where the data will be mirrored)
 *		Initialize the Fault tolerant blocks (blocks that contain
 *		information about the mirror nodes dirty writes)
 *
 * ARGUMENTS:
 *	cblocks - Number of cache blocks.
 * RETURNS:   0
 *
 */
static int
_sdbc_mem_configure(int cblocks, spcs_s_info_t kstatus)
{
	int num_blks, i, blk;
	_sd_cctl_t *centry;
	_sd_net_t *netc;
	_sd_cctl_t *prev_entry_dm, *first_entry_dm;

	if ((_sd_htable = _sdbc_hash_configure(cblocks)) == NULL) {
		spcs_s_add(kstatus, SDBC_ENOHASH);
		return (-1);
	}

	_sd_cctl_groupsz = (cblocks / _SD_CCTL_GROUPS) +
	    ((cblocks % _SD_CCTL_GROUPS) != 0);

	for (i = 0; i < _SD_CCTL_GROUPS; i++) {
		_sd_cctl[i] = (_sd_cctl_t *)
		    nsc_kmem_zalloc(_sd_cctl_groupsz * sizeof (_sd_cctl_t),
		    KM_SLEEP, sdbc_cache_mem);

		if (_sd_cctl[i] == NULL) {
			spcs_s_add(kstatus, SDBC_ENOCB);
			return (-1);
		}
	}

	_sd_ccent_sync = (_sd_cctl_sync_t *)
	    nsc_kmem_zalloc(_sd_ccsync_cnt * sizeof (_sd_cctl_sync_t),
	    KM_SLEEP, sdbc_local_mem);

	if (_sd_ccent_sync == NULL) {
		spcs_s_add(kstatus, SDBC_ENOCCTL);
		return (-1);
	}

	for (i = 0; i < _sd_ccsync_cnt; i++) {
		mutex_init(&_sd_ccent_sync[i]._cc_lock, NULL, MUTEX_DRIVER,
		    NULL);
		cv_init(&_sd_ccent_sync[i]._cc_blkcv, NULL, CV_DRIVER, NULL);
	}

	blk = 0;

	netc = &_sd_net_config;

	num_blks = (netc->sn_cpages * (int)netc->sn_psize)/BLK_SIZE(1);

	prev_entry_dm = 0;
	first_entry_dm = 0;
	for (i = 0; i < num_blks; i++, blk++) {
		centry = _sd_cctl[(blk/_sd_cctl_groupsz)] +
		    (blk%_sd_cctl_groupsz);
		centry->cc_sync = &_sd_ccent_sync[blk % _sd_ccsync_cnt];
		centry->cc_next = centry->cc_prev = NULL;
		centry->cc_dirty_next = centry->cc_dirty_link = NULL;
		centry->cc_await_use = centry->cc_await_page = 0;
		centry->cc_inuse = centry->cc_pageio = 0;
		centry->cc_flag = 0;
		centry->cc_iocount = 0;
		centry->cc_valid = 0;

		if (!first_entry_dm)
			first_entry_dm = centry;
		if (prev_entry_dm)
			prev_entry_dm->cc_link_list_dm = centry;
		prev_entry_dm = centry;
		centry->cc_link_list_dm = first_entry_dm;
		centry->cc_data = 0;
		centry->cc_write = NULL;
		centry->cc_dirty = 0;

		{
		_sd_queue_t *q;
			if (sdbc_use_dmchain) {
				q = &sdbc_dm_queues[0];
				centry->cc_cblocks = 0;
			} else
				q = _SD_LRU_Q;

			_sd_ins_queue(q, centry);
		}

	}

	if (_sdbc_gl_centry_configure(kstatus) != 0)
		return (-1);

	if (_sdbc_gl_file_configure(kstatus) != 0)
		return (-1);

	return (0);
}

/*
 * _sdbc_gl_file_configure()
 * 	allocate and initialize space for the global filename data.
 *
 */
static int
_sdbc_gl_file_configure(spcs_s_info_t kstatus)
{
	ss_voldata_t *fileinfo;
	ss_voldata_t tempfinfo;
	ss_vdir_t vdir;
	ss_vdirkey_t key;
	int err = 0;

	_sdbc_gl_file_info_size = safestore_config.ssc_maxfiles *
	    sizeof (ss_voldata_t);

	if ((_sdbc_gl_file_info = kmem_zalloc(_sdbc_gl_file_info_size,
	    KM_NOSLEEP)) == NULL) {
		spcs_s_add(kstatus, SDBC_ENOSFNV);
		return (-1);
	}

	/* setup the key to get a directory stream of all volumes */
	key.vk_type  = CDIR_ALL;

	fileinfo = _sdbc_gl_file_info;

	/*
	 * if coming up after a crash, "refresh" the host
	 * memory copy from safestore.
	 */
	if (_sdbc_warm_start()) {

		if (SSOP_GETVDIR(sdbc_safestore, &key, &vdir)) {
			cmn_err(CE_WARN, "!sdbc(_sdbc_gl_file_configure): "
			    "cannot read safestore");
			return (-1);
		}


		/*
		 * cycle through the vdir getting volume data
		 * and volume tokens
		 */

		while ((err = SSOP_GETVDIRENT(sdbc_safestore, &vdir, fileinfo))
		    == SS_OK) {
			++fileinfo;
		}

		if (err != SS_EOF) {
			/*
			 * fail to configure since
			 * recovery is not possible.
			 */
			spcs_s_add(kstatus, SDBC_ENOREFRESH);
			return (-1);
		}

	} else { /* normal initialization, not a warm start */

		/*
		 * if this fails, continue: cache will start
		 * in writethru mode
		 */

		if (SSOP_GETVDIR(sdbc_safestore, &key, &vdir)) {
			cmn_err(CE_WARN, "!sdbc(_sdbc_gl_file_configure): "
			    "cannot read safestore");
			return (-1);
		}

		/*
		 * cycle through the vdir getting just the volume tokens
		 * and initializing volume entries
		 */

		while ((err = SSOP_GETVDIRENT(sdbc_safestore, &vdir,
		    &tempfinfo)) == 0) {
			/*
			 * initialize the host memory copy of the
			 * global file region.  this means setting the
			 * _pinned and _attached fields to _SD_NO_HOST
			 * because the default of zero conflicts with
			 * the min nodeid of zero.
			 */
			fileinfo->sv_vol = tempfinfo.sv_vol;
			fileinfo->sv_pinned = _SD_NO_HOST;
			fileinfo->sv_attached = _SD_NO_HOST;
			fileinfo->sv_cd = _SD_NO_CD;

			/* initialize the directory entry */
			if ((err = SSOP_SETVOL(sdbc_safestore, fileinfo))
			    == SS_ERR) {
				cmn_err(CE_WARN,
				    "!sdbc(_sdbc_gl_file_configure): "
				    "volume entry write failure %p",
				    (void *)fileinfo->sv_vol);
				break;
			}

			++fileinfo;
		}

		/* coming up clean, continue in w-t mode */
		if (err != SS_EOF)
			cmn_err(CE_WARN, "!sdbc(_sdbc_gl_file_configure) "
			    "unable to init safe store volinfo");
	}

	return (0);
}

static void
_sdbc_gl_centry_deconfigure(void)
{
	if (_sdbc_gl_centry_info)
		kmem_free(_sdbc_gl_centry_info, _sdbc_gl_centry_info_size);

	_sdbc_gl_centry_info = NULL;
	_sdbc_gl_centry_info_size = 0;
}

static int
_sdbc_gl_centry_configure(spcs_s_info_t kstatus)
{

	int wblocks;
	ss_centry_info_t *cinfo;
	ss_cdirkey_t key;
	ss_cdir_t cdir;
	int err = 0;


	wblocks = safestore_config.ssc_wsize / BLK_SIZE(1);
	_sdbc_gl_centry_info_size = sizeof (ss_centry_info_t) * wblocks;

	if ((_sdbc_gl_centry_info = kmem_zalloc(_sdbc_gl_centry_info_size,
	    KM_NOSLEEP)) == NULL) {
		cmn_err(CE_WARN, "!sdbc(_sdbc_gl_centry_configure) "
		    "alloc failed for gl_centry_info region");

		_sdbc_gl_centry_deconfigure();
		return (-1);
	}

	/*
	 * synchronize the centry info area with safe store
	 */

	/* setup the key to get a directory stream of all centrys */
	key.ck_type  = CDIR_ALL;

	cinfo = _sdbc_gl_centry_info;

	if (_sdbc_warm_start()) {

		if (SSOP_GETCDIR(sdbc_safestore, &key, &cdir)) {
			cmn_err(CE_WARN, "!sdbc(_sdbc_gl_centry_configure): "
			    "cannot read safestore");
			return (-1);
		}


		/*
		 * cycle through the cdir getting resource
		 * tokens and reading centrys
		 */

		while ((err = SSOP_GETCDIRENT(sdbc_safestore, &cdir, cinfo))
		    == 0) {
			++cinfo;
		}

		if (err != SS_EOF) {
			/*
			 * fail to configure since
			 * recovery is not possible.
			 */
			_sdbc_gl_centry_deconfigure();
			spcs_s_add(kstatus, SDBC_EGLDMAFAIL);
			return (-1);
		}

	} else {

		if (SSOP_GETCDIR(sdbc_safestore, &key, &cdir)) {
			cmn_err(CE_WARN, "!sdbc(_sdbc_gl_centry_configure): "
			    "cannot read safestore");
			return (-1);
		}

		/*
		 * cycle through the cdir getting resource
		 * tokens and initializing centrys
		 */

		while ((err = SSOP_GETCDIRENT(sdbc_safestore, &cdir, cinfo))
		    == 0) {
			cinfo->sc_cd = -1;
			cinfo->sc_fpos = -1;

			if ((err = SSOP_SETCENTRY(sdbc_safestore, cinfo))
			    == SS_ERR) {
				cmn_err(CE_WARN,
				    "!sdbc(_sdbc_gl_centry_configure): "
				    "cache entry write failure %p",
				    (void *)cinfo->sc_res);
				break;
			}

			++cinfo;
		}

		/* coming up clean, continue in w-t mode */
		if (err != SS_EOF) {
			cmn_err(CE_WARN, "!sdbc(sdbc_gl_centry_configure) "
			    "_sdbc_gl_centry_info initialization failed");
		}
	}

	return (0);
}


static void
_sdbc_gl_file_deconfigure(void)
{

	if (_sdbc_gl_file_info)
		kmem_free(_sdbc_gl_file_info, _sdbc_gl_file_info_size);

	_sdbc_gl_file_info = NULL;

	_sdbc_gl_file_info_size = 0;
}


/*
 * _sdbc_mem_deconfigure - deconfigure the cache memory.
 * Release any memory/locks/sv's acquired during _sdbc_mem_configure.
 *
 * ARGUMENTS:
 *	cblocks - Number of cache blocks.
 *
 */
/* ARGSUSED */
static void
_sdbc_mem_deconfigure(int cblocks)
{
	int i;

	if (_sd_ccent_sync) {
		for (i = 0; i < _sd_ccsync_cnt; i++) {
			mutex_destroy(&_sd_ccent_sync[i]._cc_lock);
			cv_destroy(&_sd_ccent_sync[i]._cc_blkcv);
		}
		nsc_kmem_free(_sd_ccent_sync,
		    _sd_ccsync_cnt * sizeof (_sd_cctl_sync_t));
	}
	_sd_ccent_sync = NULL;

	for (i = 0; i < _SD_CCTL_GROUPS; i++) {
		if (_sd_cctl[i] != NULL) {
			nsc_kmem_free(_sd_cctl[i],
			    _sd_cctl_groupsz * sizeof (_sd_cctl_t));
			_sd_cctl[i] = NULL;
		}
	}
	_sd_cctl_groupsz = 0;

	_sdbc_hash_deconfigure(_sd_htable);
	_sd_htable = NULL;

}


#if defined(_SD_DEBUG) || defined(DEBUG)
static int
_sd_cctl_valid(_sd_cctl_t *addr)
{
	_sd_cctl_t *end;
	int i, valid;

	valid = 0;
	for (i = 0; i < _SD_CCTL_GROUPS; i++) {
		end = _sd_cctl[i] + _sd_cctl_groupsz;
		if (addr >= _sd_cctl[i] && addr < end) {
			valid = 1;
			break;
		}
	}

	return (valid);
}
#endif


/*
 * _sd_ins_queue - insert centry into LRU queue
 * (during initialization, locking not required)
 */
static void
_sd_ins_queue(_sd_queue_t *q, _sd_cctl_t *centry)
{
	_sd_cctl_t *q_head;

	ASSERT(_sd_cctl_valid(centry));

	q_head = &q->sq_qhead;
	centry->cc_prev = q_head;
	centry->cc_next = q_head->cc_next;
	q_head->cc_next->cc_prev = centry;
	q_head->cc_next = centry;
	q->sq_inq++;

	ASSERT(GOOD_LRUSIZE(q));
}



void
_sd_requeue(_sd_cctl_t *centry)
{
	_sd_queue_t *q = _SD_LRU_Q;

	/* was FAST */
	mutex_enter(&q->sq_qlock);
#if defined(_SD_DEBUG)
	if (1) {
		_sd_cctl_t *cp, *cn, *qp;
		cp = centry->cc_prev;
		cn = centry->cc_next;
		qp = (q->sq_qhead).cc_prev;
		if (!_sd_cctl_valid(centry) ||
		    (cp !=  &(q->sq_qhead) && !_sd_cctl_valid(cp)) ||
		    (cn !=  &(q->sq_qhead) && !_sd_cctl_valid(cn)) ||
		    !_sd_cctl_valid(qp))
			cmn_err(CE_PANIC,
			    "_sd_requeue %x prev %x next %x qp %x",
			    centry, cp, cn, qp);
	}
#endif
	centry->cc_prev->cc_next = centry->cc_next;
	centry->cc_next->cc_prev = centry->cc_prev;
	centry->cc_next = &(q->sq_qhead);
	centry->cc_prev = q->sq_qhead.cc_prev;
	q->sq_qhead.cc_prev->cc_next = centry;
	q->sq_qhead.cc_prev = centry;
	centry->cc_seq = q->sq_seq++;
	/* was FAST */
	mutex_exit(&q->sq_qlock);
	(q->sq_req_stat)++;

}

void
_sd_requeue_head(_sd_cctl_t *centry)
{
	_sd_queue_t *q = _SD_LRU_Q;

	/* was FAST */
	mutex_enter(&q->sq_qlock);
#if defined(_SD_DEBUG)
	if (1) {
		_sd_cctl_t *cp, *cn, *qn;
		cp = centry->cc_prev;
		cn = centry->cc_next;
		qn = (q->sq_qhead).cc_prev;
		if (!_sd_cctl_valid(centry) ||
		    (cp != &(q->sq_qhead) && !_sd_cctl_valid(cp)) ||
		    (cn != &(q->sq_qhead) && !_sd_cctl_valid(cn)) ||
		    !_sd_cctl_valid(qn))
			cmn_err(CE_PANIC,
			    "_sd_requeue_head %x prev %x next %x qn %x",
			    centry, cp, cn, qn);
	}
#endif
	centry->cc_prev->cc_next = centry->cc_next;
	centry->cc_next->cc_prev = centry->cc_prev;
	centry->cc_prev = &(q->sq_qhead);
	centry->cc_next = q->sq_qhead.cc_next;
	q->sq_qhead.cc_next->cc_prev = centry;
	q->sq_qhead.cc_next = centry;
	centry->cc_seq = q->sq_seq++;
	centry->cc_flag &= ~CC_QHEAD;
	/* was FAST */
	mutex_exit(&q->sq_qlock);
}



/*
 * _sd_open -   Open a file.
 *
 * ARGUMENTS:
 *	filename -  Name of the file to be opened.
 *	flag	-  Flag associated with open.
 *			(currently used to determine a ckd device)
 * RETURNS:
 *	cd - the cache descriptor.
 */

int
_sd_open(char *filename, int flag)
{
	int cd;

	if (!_sd_cache_initialized) {
		cmn_err(CE_WARN, "!sdbc(_sd_open) cache not initialized");
		return (-EINVAL);
	}
	cd = _sd_open_cd(filename, -1, flag);
	SDTRACE(SDF_OPEN, (cd < 0) ? SDT_INV_CD : cd, 0, SDT_INV_BL, 0, cd);

	return (cd);
}


static int
_sd_open_io(char *filename, int flag, blind_t *cdp, nsc_iodev_t *iodev)
{
	_sd_cd_info_t *cdi;
	int cd;
	int rc = 0;

	if ((cd = _sd_open(filename, flag)) >= 0) {

		cdi = &(_sd_cache_files[cd]);
		cdi->cd_iodev = iodev;
		nsc_set_owner(cdi->cd_rawfd, cdi->cd_iodev);

		*cdp = (blind_t)(unsigned long)cd;
	} else
		rc = -cd;

	return (rc);
}



int
_sd_open_cd(char *filename, const int cd, const int flag)
{
	int new_cd, rc = 0, alloc_cd = -1;
	ss_voldata_t *cdg;
	int preexists = 0;
	_sd_cd_info_t *cdi;
	int failover_open, open_failed;
	major_t devmaj;
	minor_t devmin;

	if (_sdbc_shutdown_in_progress)
		return (-EIO);

	if (strlen(filename) > (NSC_MAXPATH-1))
		return (-ENAMETOOLONG);

	/*
	 * If the cd is >= 0, then this is a open for a specific cd.
	 * This happens when the mirror node crashes, and we attempt to
	 * reopen the files with the same cache descriptors as existed on
	 * the other node
	 */

retry_open:
	failover_open = 0;
	open_failed   = 0;
	if (cd >= 0) {
		failover_open++;
		cdi = &(_sd_cache_files[cd]);
		mutex_enter(&_sd_cache_lock);
		if (cdi->cd_info == NULL)
			cdi->cd_info = &_sd_cache_stats->st_shared[cd];
		else if (cdi->cd_info->sh_alloc &&
		    strcmp(cdi->cd_info->sh_filename, filename)) {
			cmn_err(CE_WARN, "!sdbc(_sd_open_cd) cd %d mismatch",
			    cd);
			mutex_exit(&_sd_cache_lock);
			return (-EEXIST);
		}

		if (cdi->cd_info->sh_failed != 2) {
			if (cdi->cd_info->sh_alloc != 0)
				preexists = 1;
			else {
				cdi->cd_info->sh_alloc = CD_ALLOC_IN_PROGRESS;
				(void) strcpy(cdi->cd_info->sh_filename,
				    filename);
				if (_sd_cache_stats->st_count < sdbc_max_devs)
					_sd_cache_stats->st_count++;
			}
		}

		mutex_exit(&_sd_cache_lock);
		alloc_cd = cd;

		goto known_cd;
	}

	new_cd = 0;
	mutex_enter(&_sd_cache_lock);

	for (cdi = &(_sd_cache_files[new_cd]),
	    cdg = _sdbc_gl_file_info + new_cd;
	    new_cd < (sdbc_max_devs); new_cd++, cdi++, cdg++) {
		if (strlen(cdg->sv_volname) != 0)
			if (strcmp(cdg->sv_volname, filename))
				continue;

		if (cdi->cd_info == NULL)
			cdi->cd_info = &_sd_cache_stats->st_shared[new_cd];

		if (cdi->cd_info->sh_failed != 2) {
			if (cdi->cd_info->sh_alloc != 0)
				preexists = 1;
			else {
				if (cd == -2) {
					mutex_exit(&_sd_cache_lock);
					return (-1);
				}
				cdi->cd_info->sh_alloc = CD_ALLOC_IN_PROGRESS;
				(void) strcpy(cdi->cd_info->sh_filename,
				    filename);
				(void) strcpy(cdg->sv_volname, filename);

				cdg->sv_cd = new_cd;
				/* update safestore */
				SSOP_SETVOL(sdbc_safestore, cdg);
				if (_sd_cache_stats->st_count < sdbc_max_devs)
					_sd_cache_stats->st_count++;
				cdi->cd_flag = 0;
			}
		}
		alloc_cd = new_cd;
		break;
	}

	mutex_exit(&_sd_cache_lock);

	if (alloc_cd == -1)
		return (-ENOSPC);

known_cd:
	/*
	 * If preexists: someone else is attempting to open this file as
	 * well. Do only one open, but block everyone else here till the
	 * open is completed.
	 */
	if (preexists) {
		while (cdi->cd_info->sh_alloc == CD_ALLOC_IN_PROGRESS) {
			delay(drv_usectohz(20000));
		}
		if ((cdi->cd_info->sh_alloc != CD_ALLOCATED))
			goto retry_open;
		return (alloc_cd);
	}

	if (!(cdi->cd_rawfd =
	    nsc_open(filename, NSC_SDBC_ID|NSC_DEVICE, _sdbc_fd_def,
	    (blind_t)(unsigned long)alloc_cd, &rc)) ||
	    !nsc_getval(cdi->cd_rawfd, "DevMaj", (int *)&devmaj) ||
	    !nsc_getval(cdi->cd_rawfd, "DevMin", (int *)&devmin)) {
		if (cdi->cd_rawfd) {
			(void) nsc_close(cdi->cd_rawfd);
			cdi->cd_rawfd = NULL;
		}
		/*
		 * take into account that there may be pinned data on a
		 * device that can no longer be opened
		 */
		open_failed++;
		if (!(cdi->cd_info->sh_failed) && !failover_open) {
			cdi->cd_info->sh_alloc = 0;
			mutex_enter(&_sd_cache_lock);
			_sd_cache_stats->st_count--;
			mutex_exit(&_sd_cache_lock);
			if (!rc)
				rc = EIO;
			return (-rc);
		}
	}

	cdi->cd_strategy = nsc_get_strategy(devmaj);
	cdi->cd_crdev	= makedevice(devmaj, devmin);
	cdi->cd_desc	= alloc_cd;
	cdi->cd_dirty_head = cdi->cd_dirty_tail = NULL;
	cdi->cd_io_head	= cdi->cd_io_tail = NULL;
	cdi->cd_hint	= 0;
#ifdef DEBUG
	/* put the dev_t in the ioerr_inject_table */
	_sdbc_ioj_set_dev(alloc_cd, cdi->cd_crdev);
#endif

	cdi->cd_global = (_sdbc_gl_file_info + alloc_cd);
	if (open_failed) {
		cdi->cd_info->sh_failed = 2;
	} else if (cdi->cd_info->sh_failed != 2)
		if ((cdi->cd_global->sv_pinned == _SD_SELF_HOST) &&
		    !failover_open)
			cdi->cd_info->sh_failed = 1;
		else
			cdi->cd_info->sh_failed = 0;

	cdi->cd_flag	|= flag;
	mutex_init(&cdi->cd_lock, NULL, MUTEX_DRIVER, NULL);

#ifndef _SD_NOTRACE
	(void) _sdbc_tr_configure(alloc_cd);
#endif
	cdi->cd_info->sh_alloc = CD_ALLOCATED;
	cdi->cd_global = (_sdbc_gl_file_info + alloc_cd);
	cdi->cd_info->sh_cd = (unsigned short) alloc_cd;
	mutex_enter(&_sd_cache_lock);
	_sd_cache_stats->st_loc_count++;
	mutex_exit(&_sd_cache_lock);

	if (cd_kstat_add(alloc_cd) < 0) {
		cmn_err(CE_WARN, "!Could not create kstats for cache descriptor"
		    " %d", alloc_cd);
	}


	return (open_failed ? -EIO : alloc_cd);
}


/*
 * _sd_close -   Close a cache descriptor.
 *
 * ARGUMENTS:
 *	cd   -   the cache descriptor to be closed.
 * RETURNS:
 *	0 on success.
 *	Error otherwise.
 *
 * Note: Under Construction.
 */

int
_sd_close(int cd)
{
	int rc;
	_sd_cd_info_t *cdi = &(_sd_cache_files[cd]);

	if (!FILE_OPENED(cd)) {
		rc = EINVAL;
		goto out;
	}

	SDTRACE(ST_ENTER|SDF_CLOSE, cd, 0, SDT_INV_BL, 0, 0);

	mutex_enter(&_sd_cache_lock);
	if ((cdi->cd_info->sh_alloc == 0) ||
	    (cdi->cd_info->sh_alloc & CD_CLOSE_IN_PROGRESS)) {
		mutex_exit(&_sd_cache_lock);
		SDTRACE(ST_EXIT|SDF_CLOSE, cd, 0, SDT_INV_BL, 0, EINVAL);
		rc = EINVAL;
		goto out;
	}
	cdi->cd_info->sh_alloc |= CD_CLOSE_IN_PROGRESS;
	mutex_exit(&_sd_cache_lock);

	/*
	 * _sd_flush_cd() will return -1 for the case where pinned
	 * data is present, but has been transfered to the mirror
	 * node.  In this case it is safe to close the device as
	 * though _sd_flush_cd() had returned 0.
	 */

	rc = _sd_flush_cd(cd);
	if (rc == -1)
		rc = 0;

	if (rc != 0) {
		mutex_enter(&_sd_cache_lock);
		if ((rc == EAGAIN) &&
		    (cdi->cd_global->sv_pinned == _SD_NO_HOST)) {
			cdi->cd_global->sv_pinned = _SD_SELF_HOST;
			SSOP_SETVOL(sdbc_safestore, cdi->cd_global);
		}

		cdi->cd_info->sh_alloc &= ~CD_CLOSE_IN_PROGRESS;
		mutex_exit(&_sd_cache_lock);
		SDTRACE(ST_EXIT|SDF_CLOSE, cd, 0, SDT_INV_BL,
		    _SD_CD_WBLK_USED(cd), rc);
		goto out;
	}

	rc = nsc_close(cdi->cd_rawfd);
	if (rc) {
		mutex_enter(&_sd_cache_lock);
		cdi->cd_info->sh_alloc &= ~CD_CLOSE_IN_PROGRESS;
		mutex_exit(&_sd_cache_lock);
		SDTRACE(ST_EXIT|SDF_CLOSE, cd, 0, SDT_INV_BL, 0, rc);
		goto out;
	}
	mutex_enter(&_sd_cache_lock);
	_sd_cache_stats->st_loc_count--;
	mutex_exit(&_sd_cache_lock);

	if (cd_kstat_remove(cd) < 0) {
		cmn_err(CE_WARN, "!Could not remove kstat for cache descriptor "
		    "%d", cd);
	}

	cdi->cd_info->sh_alloc = 0;
	cdi->cd_info->sh_failed = 0;
	/* cdi->cd_info = NULL; */
	cdi->cd_flag = 0;
	SDTRACE(ST_EXIT|SDF_CLOSE, cd, 0, SDT_INV_BL, 0, NSC_DONE);
	rc = NSC_DONE;
	goto out;

out:
	return (rc);
}


static int
_sd_close_io(blind_t xcd)
{
	_sd_cd_info_t *cdi;
	int cd = (int)(unsigned long)xcd;
	int rc = 0;

	if ((rc = _sd_close((int)cd)) == NSC_DONE) {
		cdi = &(_sd_cache_files[cd]);
		cdi->cd_iodev = NULL;
	}

	return (rc);
}


/*
 * _sdbc_remote_store_pinned - reflect pinned/failed blocks for cd
 * to our remote mirror. Returns count of blocks reflected or -1 on error.
 *
 */
int
_sdbc_remote_store_pinned(int cd)
{
	int cnt = 0;
	_sd_cd_info_t *cdi = &(_sd_cache_files[cd]);
	_sd_cctl_t *cc_ent, *cc_list;

	ASSERT(cd >= 0);
	if (cdi->cd_info->sh_failed) {

		if (cdi->cd_global->sv_pinned == _SD_NO_HOST) {
			cdi->cd_global->sv_pinned = _SD_SELF_HOST;
			SSOP_SETVOL(sdbc_safestore, cdi->cd_global);
		}

		mutex_enter(&cdi->cd_lock);
		cc_ent = cc_list = cdi->cd_fail_head;
		while (cc_ent) {
			cnt++;

			/* is this always necessary? jgk */

			if (SSOP_WRITE_CBLOCK(sdbc_safestore,
			    cc_ent->cc_write->sc_res, cc_ent->cc_data,
			    CACHE_BLOCK_SIZE, 0)) {
				mutex_exit(&cdi->cd_lock);
				return (-1);
			}

			/* update the cache block metadata */
			CENTRY_SET_FTPOS(cc_ent);
			cc_ent->cc_write->sc_flag = cc_ent->cc_flag;

			cc_ent->cc_write->sc_dirty = CENTRY_DIRTY(cc_ent);

			SSOP_SETCENTRY(sdbc_safestore, cc_ent->cc_write);

			cc_ent = cc_ent->cc_dirty_next;
			if (!cc_ent)
				cc_ent = cc_list = cc_list->cc_dirty_link;
		}
		mutex_exit(&cdi->cd_lock);
	}

	return (cnt);
}

/*
 * _sd_flush_cd()
 *	reflect pinned blocks to mirrored node
 *	wait for dirty blocks to be flushed
 * returns:
 *	EIO	I/O failure, or pinned blocks and no mirror
 *	EAGAIN	Hang: count of outstanding writes isn't decreasing
 *	-1	pinned blocks, reflected to mirror
 *	0	success
 */
static int
_sd_flush_cd(int cd)
{
	int rc;

	if ((rc = _sd_wait_for_flush(cd)) == 0)
		return (0);

	/*
	 * if we timed out simply return otherwise
	 * it must be an i/o type of error
	 */
	if (rc == EAGAIN)
		return (rc);

	if (_sd_is_mirror_down())
		return (EIO); /* already failed, no mirror */

	/* flush any pinned/failed blocks to mirror */
	if (_sdbc_remote_store_pinned(cd) >= 0)
		/*
		 * At this point it looks like we have blocks on the
		 * failed list and taking up space on this node but
		 * no longer have responsibility for the blocks.
		 * These blocks will in fact be freed from the cache
		 * and the failed list when the mirror picks them up
		 * from safe storage and then calls _sd_cd_discard_mirror
		 * which will issue an rpc telling us to finish up.
		 *
		 * Should the other node die before sending the rpc then
		 * we are safe with these blocks simply waiting on the
		 * failed list.
		 */
		return (-1);
	else
		return (rc);
}

/*
 * _sdbc_io_attach_cd -- set up for client access to device, reserve raw device
 *
 * ARGUMENTS:
 *	cd   -	the cache descriptor to attach.
 *
 * RETURNS:
 *	0 on success.
 *	Error otherwise.
 */
int
_sdbc_io_attach_cd(blind_t xcd)
{
	int rc = 0;
	_sd_cd_info_t *cdi;
	int cd = (int)(unsigned long)xcd;

	SDTRACE(ST_ENTER|SDF_ATTACH, cd, 0, SDT_INV_BL, 0, 0);
	if (!_sd_cache_initialized ||
	    _sdbc_shutdown_in_progress ||
	    !FILE_OPENED(cd)) {
		SDTRACE(ST_EXIT|SDF_ATTACH, cd, 0, SDT_INV_BL, 0, EINVAL);

		DTRACE_PROBE(_sdbc_io_attach_cd_end1);

		return (EINVAL);
	}
	cdi = &(_sd_cache_files[cd]);

	/*
	 * check if disk is failed without raw device open.  If it is,
	 * it has to be recovered using _sd_disk_online
	 */

	if (cdi->cd_global->sv_pinned == _SD_SELF_HOST) {
		_sd_print(3,
		    "_sdbc_io_attach_cd: pinned data. returning EINVAL");

		DTRACE_PROBE(_sdbc_io_attach_cd_end2);

		return (EINVAL);
	}

	if ((cdi->cd_info == NULL) || (cdi->cd_info->sh_failed)) {
		DTRACE_PROBE1(_sdbc_io_attach_cd_end3,
		    struct _sd_shared *, cdi->cd_info);

		return (EINVAL);
	}

#if defined(_SD_FAULT_RES)
	/* wait for node recovery to finish */
	if (_sd_node_recovery)
		(void) _sd_recovery_wait();
#endif

	/* this will provoke a sdbc_fd_attach_cd call .. */

	rc = nsc_reserve(cdi->cd_rawfd, NSC_MULTI);
	SDTRACE(ST_EXIT|SDF_ATTACH, cd, 0, SDT_INV_BL, 0, rc);

	return (rc);
}

/*
 * sdbc_fd_attach_cd -- setup cache for access to raw device underlying cd.
 * This is provoked by some piece of sdbc doing a reserve on the raw device.
 *
 * ARGUMENTS:
 *	cd   -	the cache descriptor to attach.
 *
 * RETURNS:
 *	0 on success.
 *	Error otherwise.
 */
static int
sdbc_fd_attach_cd(blind_t xcd)
{
	int rc = 0;
	int cd = (int)(unsigned long)xcd;
	_sd_cd_info_t *cdi;

	if (!_sd_cache_initialized || !FILE_OPENED(cd)) {
		SDTRACE(ST_INFO|SDF_ATTACH, cd, 0, SDT_INV_BL, 0, EINVAL);

		DTRACE_PROBE(sdbc_fd_attach_cd_end1);

		return (EINVAL);
	}
	cdi = &(_sd_cache_files[cd]);

#if defined(_SD_FAULT_RES)
	/* retrieve pinned/failed data */
	if (!_sd_node_recovery) {
		(void) _sd_repin_cd(cd);
	}
#endif

	rc = nsc_partsize(cdi->cd_rawfd, &cdi->cd_info->sh_filesize);
	if (rc != 0) {
		SDTRACE(ST_INFO|SDF_ATTACH, cd, 0, SDT_INV_BL, 0, rc);

		DTRACE_PROBE(sdbc_fd_attach_cd_end3);

		return (rc);
	}

	cdi->cd_global->sv_attached = _SD_SELF_HOST;

	SSOP_SETVOL(sdbc_safestore, cdi->cd_global);

	mutex_enter(&_sd_cache_lock);
	cdi->cd_info->sh_flag |= CD_ATTACHED;
	mutex_exit(&_sd_cache_lock);

	return (0);
}

/*
 * _sdbc_io_detach_cd -- release raw device
 * Called when a cache client is being detached from this cd.
 *
 * ARGUMENTS:
 *	cd   -   the cache descriptor to detach.
 * RETURNS:
 *	0 on success.
 *	Error otherwise.
 */
int
_sdbc_io_detach_cd(blind_t xcd)
{
	int cd = (int)(unsigned long)xcd;
	_sd_cd_info_t *cdi;


	SDTRACE(ST_ENTER|SDF_DETACH, cd, 0, SDT_INV_BL, 0, 0);
	if (!_sd_cache_initialized || !FILE_OPENED(cd)) {
		SDTRACE(ST_EXIT|SDF_DETACH, cd, 0, SDT_INV_BL, 0, EINVAL);

		DTRACE_PROBE(_sdbc_io_detach_cd_end1);

		return (EINVAL);
	}

#if defined(_SD_FAULT_RES)
	if (_sd_node_recovery)
		(void) _sd_recovery_wait();
#endif
	/* relinquish responsibility for device */
	cdi = &(_sd_cache_files[cd]);
	if (!(cdi->cd_rawfd) || !nsc_held(cdi->cd_rawfd)) {
		cmn_err(CE_WARN, "!sdbc(_sdbc_detach_cd)(%d) not attached", cd);
		SDTRACE(ST_EXIT|SDF_DETACH, cd, 0, SDT_INV_BL, 0, EPROTO);
		DTRACE_PROBE1(_sdbc_io_detach_cd_end2,
		    nsc_fd_t *, cdi->cd_rawfd);

		return (EPROTO);
	}
	/* this will provoke/allow a call to sdbc_fd_detach_cd */
	nsc_release(cdi->cd_rawfd);

	SDTRACE(ST_EXIT|SDF_DETACH, cd, 0, SDT_INV_BL, 0, 0);

	return (0);
}

/*
 * _sdbc_detach_cd -- flush dirty writes to disk, release raw device
 * Called when raw device is being detached from this cd.
 *
 * ARGUMENTS:
 *	cd   -   the cache descriptor to detach.
 *	rd_only   -  non-zero if detach is for read access.
 * RETURNS:
 *	0 on success.
 *	Error otherwise.
 */
static int
sdbc_detach_cd(blind_t xcd, int rd_only)
{
	int rc;
	int cd = (int)(unsigned long)xcd;
	_sd_cd_info_t *cdi;

	SDTRACE(ST_INFO|SDF_DETACH, cd, 0, SDT_INV_BL, 0, 0);

	if (!_sd_cache_initialized || !FILE_OPENED(cd)) {
		SDTRACE(ST_INFO|SDF_DETACH, cd, 0, SDT_INV_BL, 0, EINVAL);

		DTRACE_PROBE(sdbc_detach_cd_end1);

		return (EINVAL);
	}


	rc = _sd_flush_cd(cd);
	if (rc > 0) {
		SDTRACE(ST_INFO|SDF_DETACH, cd, 0, SDT_INV_BL, 0, rc);

		DTRACE_PROBE(sdbc_detach_cd_end2);

		return (rc);
	}

	if (!rd_only) {
		_sd_hash_invalidate_cd(cd);
		cdi = &(_sd_cache_files[cd]);

		if (cdi->cd_global->sv_attached == _SD_SELF_HOST) {
			cdi->cd_global->sv_attached = _SD_NO_HOST;
			SSOP_SETVOL(sdbc_safestore, cdi->cd_global);
		} else {
			cmn_err(CE_WARN,
			    "!sdbc(_sdbc_detach_cd) (%d) attached by node %d",
			    cd, cdi->cd_global->sv_attached);
			SDTRACE(SDF_DETACH, cd, 0, SDT_INV_BL, 0, EPROTO);

			DTRACE_PROBE1(sdbc_detach_cd_end3,
			    int, cdi->cd_global->sv_attached);

			return (EPROTO);
		}

		mutex_enter(&_sd_cache_lock);
		cdi->cd_info->sh_flag &= ~CD_ATTACHED;
		mutex_exit(&_sd_cache_lock);
	}

	SDTRACE(ST_INFO|SDF_DETACH, cd, 0, SDT_INV_BL, 0, 0);

	return (0);
}

/*
 * _sdbc_fd_detach_cd -- flush dirty writes to disk, release raw device
 * Called when raw device is being detached from this cd.
 *
 * ARGUMENTS:
 *	xcd   -   the cache descriptor to detach.
 * RETURNS:
 *	0 on success.
 *	Error otherwise.
 */
static int
sdbc_fd_detach_cd(blind_t xcd)
{
	return (sdbc_detach_cd(xcd, 0));
}

/*
 * sdbc_fd_flush_cd - raw device "xcd" is being detached and needs
 * flushing.  We only need to flush we don't need to hash invalidate
 * this file.
 */
static int
sdbc_fd_flush_cd(blind_t xcd)
{
	return (sdbc_detach_cd(xcd, 1));
}

/*
 * _sd_get_pinned - re-issue PINNED callbacks for cache device
 *
 * ARGUMENTS:
 *	cd   -   the cache descriptor to reissue pinned calbacks from.
 * RETURNS:
 *	0 on success.
 *	Error otherwise.
 */
int
_sd_get_pinned(blind_t xcd)
{
	_sd_cd_info_t *cdi;
	_sd_cctl_t *cc_list, *cc_ent;
	int cd = (int)(unsigned long)xcd;

	cdi = &_sd_cache_files[cd];

	if (cd < 0 || cd >= sdbc_max_devs) {
		DTRACE_PROBE(_sd_get_pinned_end1);
		return (EINVAL);
	}

	if (!FILE_OPENED(cd)) {
		DTRACE_PROBE(_sd_get_pinned_end2);
		return (0);
	}

	mutex_enter(&cdi->cd_lock);

	if (!cdi->cd_info->sh_failed) {
		mutex_exit(&cdi->cd_lock);

		DTRACE_PROBE(_sd_get_pinned_end3);
		return (0);
	}

	cc_ent = cc_list = cdi->cd_fail_head;
	while (cc_ent) {
		if (CENTRY_PINNED(cc_ent))
			nsc_pinned_data(cdi->cd_iodev,
			    BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)), BLK_FBAS);
		cc_ent = cc_ent->cc_dirty_next;
		if (!cc_ent)
			cc_ent = cc_list = cc_list->cc_dirty_link;
	}

	mutex_exit(&cdi->cd_lock);

	return (0);
}

/*
 * _sd_allocate_buf - allocate a vector of buffers for io.
 * 			*This call has been replaced by _sd_alloc_buf*
 */

_sd_buf_handle_t *
_sd_allocate_buf(int cd, nsc_off_t fba_pos, nsc_size_t fba_len, int flag,
    int *sts)
{
	_sd_buf_handle_t *handle = NULL;

	*sts = _sd_alloc_buf((blind_t)(unsigned long)cd, fba_pos, fba_len,
	    flag, &handle);
	if (*sts == NSC_HIT)
		*sts = NSC_DONE;
	return (handle);
}


/*
 * _sd_prefetch_buf - _sd_alloc_buf w/flag = NSC_RDAHEAD|NSC_RDBUF
 *	no 'bufvec' (data is not read by caller)
 *	skip leading valid or busy entries (data available sooner)
 *	truncate on busy block (to avoid deadlock)
 *	release trailing valid entries, adjust length before starting I/O.
 */
static int
_sd_prefetch_buf(int cd, nsc_off_t fba_pos, nsc_size_t fba_len, int flag,
    _sd_buf_handle_t *handle, int locked)
{
	_sd_cd_info_t *cdi;
	nsc_off_t cblk; 	/* position of temp cache block */
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_off_t io_pos;	/* offset in FBA's */
	nsc_size_t fba_orig_len;
	int sts, stall;
	_sd_cctl_t *centry = NULL;
	_sd_cctl_t *lentry = NULL;
	_sd_cctl_t *ioent = NULL;
	_sd_cctl_t *last_ioent = NULL;
	sdbc_allocbuf_t alloc_tok = {0};
	int this_entry_type = 0;
	nsc_size_t request_blocks = 0; /* number of cache blocks required */
	int pageio;

	handle->bh_flag |= NSC_HACTIVE;
	ASSERT(cd >= 0);
	cdi = &_sd_cache_files[cd];

	/* prefetch: truncate if req'd */
	if (fba_len > sdbc_max_fbas)
		fba_len = sdbc_max_fbas;
	if ((fba_pos + fba_len) > cdi->cd_info->sh_filesize) {
		if (fba_pos >= cdi->cd_info->sh_filesize) {
			sts = EIO;
			goto done;
		}
		fba_len = cdi->cd_info->sh_filesize - fba_pos;
	}

	fba_orig_len = fba_len;

	_SD_SETUP_HANDLE(handle, cd, fba_pos, fba_len, flag);
	handle->bh_centry = NULL;

	cblk = FBA_TO_BLK_NUM(fba_pos);
	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = BLK_FBAS - st_cblk_off;

	/*
	 * count number of blocks on chain that is required
	 */
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
		end_cblk_len = 0;
	} else {
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);
	}

	request_blocks = 1;  /* at least one */

	/* middle piece */
	request_blocks += (fba_len - (st_cblk_len + end_cblk_len)) >>
	    BLK_FBA_SHFT;

	if (end_cblk_len)
		++request_blocks;

	stall = 0;
	do {
		pageio = ((flag & NSC_PAGEIO) != 0 || sdbc_pageio_always != 0);
cget:
		if (centry = (_sd_cctl_t *)
		    _sd_hash_search(cd, cblk, _sd_htable)) {
try:
			/* prefetch: skip leading valid blocks */
			if ((ioent == NULL) &&
			    SDBC_VALID_BITS(st_cblk_off, st_cblk_len, centry)) {
skip:
				sdbc_prefetch_valid_cnt++;
				--request_blocks;
				lentry = centry;
				centry = NULL;
				cblk++;
				fba_len -= st_cblk_len;
				st_cblk_off = 0;
				st_cblk_len = (sdbc_cblk_fba_t)
				    ((fba_len > (nsc_size_t)BLK_FBAS) ?
				    BLK_FBAS : fba_len);
				continue;
			}

			if (SET_CENTRY_INUSE(centry)) {
				/*
				 * prefetch: skip leading busy
				 * or truncate at busy block
				 */
				if (ioent == NULL)
					goto skip;
				sdbc_prefetch_busy_cnt++;
				fba_orig_len -= fba_len;
				fba_len = 0;
				centry = lentry; /* backup */
				break;
			}

			/*
			 * bug 4529671
			 * now that we own the centry make sure that
			 * it is still good.  it could have been processed
			 * by _sd_dealloc_dm() in the window between
			 * _sd_hash_search() and SET_CENTRY_INUSE().
			 */
			if ((_sd_cctl_t *)
			    _sd_hash_search(cd, cblk, _sd_htable) != centry) {
				sdbc_prefetch_deallocd++;
#ifdef DEBUG
				cmn_err(CE_WARN,
				    "!prefetch centry %p cd %d cblk %" NSC_SZFMT
				    " fba_len %" NSC_SZFMT " lost to dealloc?! "
				    "cc_data %p",
				    (void *)centry, cd, cblk, fba_orig_len,
				    (void *)centry->cc_data);
#endif

				CLEAR_CENTRY_INUSE(centry);
				continue;
			}

			if (CC_CD_BLK_MATCH(cd, cblk, centry)) {
				/*
				 * Do pagelist io mutual exclusion
				 * before messing with the centry.
				 */
				if (pageio && SET_CENTRY_PAGEIO(centry)) {
					/* flusher not done with pageio */
					/*
					 * prefetch: skip leading busy
					 * or truncate at busy block
					 */
					CLEAR_CENTRY_INUSE(centry);
					if (ioent == NULL)
						goto skip;
					sdbc_prefetch_pageio1++;
					fba_orig_len -= fba_len;
					fba_len = 0;
					centry = lentry; /* backup */
					break;

				}

				sdbc_prefetch_hit++;
				this_entry_type = HASH_ENTRY_DM;
				pageio = 0;
				centry->cc_toflush = 0;

				centry->cc_hits++;

				/* this will reset the age flag */
				sdbc_centry_init_dm(centry);

				DTRACE_PROBE1(_sd_prefetch_buf,
				    _sd_cctl_t *, centry);
			} else {
				/* block mismatch */
				sdbc_prefetch_lost++;

				CLEAR_CENTRY_INUSE(centry);
				continue;
			}
		} else {
			centry = sdbc_centry_alloc(cd, cblk, request_blocks,
			    &stall, &alloc_tok, ALLOC_NOWAIT);

			if (centry == NULL) {
				/*
				 * prefetch: cache is very busy. just do
				 * the i/o for the blocks already acquired,
				 * if any.
				 */
				fba_orig_len -= fba_len;
				fba_len = 0;
				/*
				 * if we have a chain of centry's
				 * then back up (set centry to lentry).
				 * if there is no chain (ioent == NULL)
				 * then centry remains NULL.  this can occur
				 * if all previous centrys were hash hits
				 * on valid blocks that were processed in
				 * the skip logic above.
				 */
				if (ioent)
					centry = lentry; /* backup */
				break;
			}

			/*
			 * dmchaining adjustment.
			 * if centry was obtained from the dmchain
			 * then clear local pageio variable because the
			 * centry already has cc_pageio set.
			 */
			if (CENTRY_PAGEIO(centry))
				pageio = 0;

			DTRACE_PROBE1(_sd_alloc_buf, _sd_cctl_t *, centry);

			this_entry_type = ELIGIBLE_ENTRY_DM;
			if (centry->cc_aging_dm & FOUND_IN_HASH_DM)
				this_entry_type = HASH_ENTRY_DM;
			else {
				if (centry->cc_aging_dm & FOUND_HOLD_OVER_DM)
					this_entry_type = HOLD_ENTRY_DM;
			}
		}

		centry->cc_chain = NULL;

		centry->cc_aging_dm &= ~(FOUND_IN_HASH_DM|FOUND_HOLD_OVER_DM);

		/*
		 * Do pagelist io mutual exclusion now if we did not do
		 * it above.
		 */

		if (pageio && SET_CENTRY_PAGEIO(centry)) {
			/* flusher not done with pageio */
			sdbc_prefetch_pageio2++;

			/*
			 * prefetch: skip leading busy
			 * or truncate at busy block
			 */
			CLEAR_CENTRY_INUSE(centry);
			if (ioent == NULL)
				goto skip;
			sdbc_prefetch_busy_cnt++;
			fba_orig_len -= fba_len;
			fba_len = 0;
			centry = lentry; /* backup */
			break;
		}

		pageio = 0;

		fba_len -= st_cblk_len;

		if (ioent == NULL)  {
			if (!SDBC_VALID_BITS(st_cblk_off, st_cblk_len,
			    centry)) {
				io_pos = BLK_TO_FBA_NUM(cblk) + st_cblk_off;
				ioent = last_ioent = centry;
			} else {
				DATA_LOG(SDF_ALLOC, centry, st_cblk_off,
				    st_cblk_len);
				DTRACE_PROBE4(_sd_prefetch_buf_data1,
				    uint64_t, (uint64_t)(BLK_TO_FBA_NUM(cblk) +
				    st_cblk_off), int, st_cblk_len,
				    char *, *(int64_t *)(centry->cc_data +
				    FBA_SIZE(st_cblk_off)), char *,
				    *(int64_t *)(centry->cc_data +
				    FBA_SIZE(st_cblk_off + st_cblk_len) - 8));
			}

			handle->bh_centry = centry;
			st_cblk_off = 0;
			st_cblk_len = (sdbc_cblk_fba_t)
			    ((fba_len > (nsc_size_t)BLK_FBAS) ?
			    BLK_FBAS : fba_len);
		} else {
			if (!SDBC_VALID_BITS(st_cblk_off, st_cblk_len, centry))
				last_ioent = centry;
			else {
				DTRACE_PROBE4(_sd_prefetch_buf_data2,
				    uint64_t, (uint64_t)(BLK_TO_FBA_NUM(cblk) +
				    st_cblk_off), int, st_cblk_len,
				    char *, *(int64_t *)(centry->cc_data +
				    FBA_SIZE(st_cblk_off)), char *,
				    *(int64_t *)(centry->cc_data +
				    FBA_SIZE(st_cblk_off + st_cblk_len) - 8));
			}

			lentry->cc_chain = centry;
			if (fba_len < (nsc_size_t)BLK_FBAS)
				st_cblk_len = (sdbc_cblk_fba_t)fba_len;
		}
		lentry = centry;
		cblk++;

		/* if this block has a new identity clear prefetch history */
		if (this_entry_type != HASH_ENTRY_DM)
			centry->cc_aging_dm &=
			    ~(PREFETCH_BUF_I | PREFETCH_BUF_E);

		centry->cc_aging_dm &= ~(ENTRY_FIELD_DM);
		centry->cc_aging_dm |= this_entry_type | PREFETCH_BUF_E;
		if (flag & NSC_METADATA)
			centry->cc_aging_dm |= STICKY_METADATA_DM;

		--request_blocks;
	} while (fba_len > 0);


	if (locked) {
		rw_exit(&sdbc_queue_lock);
		locked = 0;
	}

	sdbc_centry_alloc_end(&alloc_tok);

	if (centry) {
		centry->cc_chain = NULL;
		if (sts = _sd_setup_category_on_type(handle->bh_centry)) {
			(void) _sd_free_buf(handle);
			goto done;
		}

		(void) _sd_setup_mem_chaining(handle->bh_centry, 0);
	}


	if (ioent) {
		/* prefetch: trailing valid can be released, adjust len */
		if ((centry != last_ioent)) {
			centry = last_ioent->cc_chain;
			last_ioent->cc_chain = NULL;
			while (centry) {
				lentry = centry->cc_chain;
				centry->cc_aging_dm &= ~PREFETCH_BUF_E;
				_sd_centry_release(centry);
				centry = lentry;
				sdbc_prefetch_trailing++;
			}
			fba_len = (CENTRY_BLK(last_ioent) -
			    CENTRY_BLK(ioent) + 1) *  BLK_FBAS -
			    BLK_FBA_OFF(io_pos);
			fba_orig_len = fba_len + (io_pos - fba_pos);
		}

		_SD_DISCONNECT_CALLBACK(handle);
		sts = _sd_doread(handle,  ioent, io_pos,
		    (fba_pos + fba_orig_len - io_pos), flag);
		if (sts > 0)
			(void) _sd_free_buf(handle);
	} else {
		CACHE_FBA_READ(cd, fba_orig_len);
		CACHE_READ_HIT;
		FBA_READ_IO_KSTATS(cd, FBA_SIZE(fba_orig_len));

		sts = NSC_HIT;
	}
done:
	if (locked)
		rw_exit(&sdbc_queue_lock);

	return (sts);
}


/*
 * _sd_cc_wait - wait for inuse cache block to become available
 * Usage:
 *	if (SET_CENTRY_INUSE(centry)) {
 *		_sd_cc_wait(cd, blk, centry, CC_INUSE);
 *		goto try_again;
 *	}
 * -or-
 *	if (SET_CENTRY_PAGEIO(centry)) {
 *		_sd_cc_wait(cd, blk, centry, CC_PAGEIO);
 *		goto try_again;
 *	}
 */
void
_sd_cc_wait(int cd, nsc_off_t cblk, _sd_cctl_t *centry, int flag)
{
	volatile ushort_t *waiters;
	volatile uchar_t *uflag;

	if (flag == CC_INUSE) {
		waiters = &(centry->cc_await_use);
		uflag = &(CENTRY_INUSE(centry));
	} else if (flag == CC_PAGEIO) {
		waiters = &(centry->cc_await_page);
		uflag = &(CENTRY_PAGEIO(centry));
	} else {
		/* Oops! */
#ifdef DEBUG
		cmn_err(CE_WARN, "!_sd_cc_wait: unknown flag value (%x)", flag);
#endif
		return;
	}

	mutex_enter(&centry->cc_lock);
	if (CC_CD_BLK_MATCH(cd, cblk, centry) && (*uflag) != 0) {
		(*waiters)++;
		sd_serialize();
		if ((*uflag) != 0) {
			unsigned stime = nsc_usec();
			cv_wait(&centry->cc_blkcv, &centry->cc_lock);
			(*waiters)--;
			mutex_exit(&centry->cc_lock);
			SDTRACE(ST_INFO|SDF_ENT_GET,
			    cd, 0, BLK_TO_FBA_NUM(cblk), (nsc_usec()-stime), 0);
		} else {
			(*waiters)--;
			mutex_exit(&centry->cc_lock);
		}
	} else
		mutex_exit(&centry->cc_lock);

}

/*
 * _sd_alloc_buf  - Allocate a vector of buffers for io.
 *
 * ARGUMENTS:
 *	cd	 - Cache descriptor (from a previous open)
 *	fba_pos	 - disk position (512-byte FBAs)
 *	fba_len  - length in disk FBAs.
 *	flag	 - allocation type. Flag is one or more of
 *		   NSC_RDBUF, NSC_WRBUF, NSC_NOBLOCK and hints.
 *		   NSC_RDAHEAD - prefetch for future read.
 *	handle_p - pointer to a handle pointer.
 *		   If the handle pointer is non-null, its used as a
 *		   pre-allocated handle. Else a new handle will be allocated
 *		   and stored in *handle_p
 *
 * RETURNS:
 * 	errno if return > 0.
 *	else NSC_HIT or NSC_DONE on success
 *	or   NSC_PENDING on io in progress and NSC_NOBLOCK
 *		specified in the flag.
 * USAGE:
 *	This routine allocates the cache blocks requested and creates a list
 *	of entries for this request.
 *	If NSC_NOBLOCK was not specified, this call could block on read io.
 *	If flag specified NSC_RDBUF and the request is not an entire
 *	hit, an io is initiated.
 */
int
_sd_alloc_buf(blind_t xcd, nsc_off_t fba_pos, nsc_size_t fba_len, int flag,
    _sd_buf_handle_t **handle_p)
{
	int cd = (int)(unsigned long)xcd;
	_sd_cd_info_t *cdi;
	_sd_buf_handle_t *handle;
	int sts;
	nsc_off_t st_cblk, cblk; /* position of start and temp cache block */
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_off_t io_pos;	/* offset in FBA's */
	_sd_bufvec_t *bufvec;
	_sd_cctl_t *centry, *lentry, *ioent = NULL;
	nsc_size_t fba_orig_len = fba_len;	/* FBA length of orig request */
	int stall, pageio;
	unsigned char cc_flag;
	int this_entry_type;
	int locked = 0;
	nsc_size_t dmchain_request_blocks; /* size of dmchain in cache blocks */
	sdbc_allocbuf_t alloc_tok = {0};
	int min_frag = 0;	/* frag statistics */
	int max_frag = 0;	/* frag statistics */
	int nfrags = 0;		/* frag statistics */
#ifdef DEBUG
	int err = 0;
#endif


	ASSERT(*handle_p != NULL);
	handle = *handle_p;

	if (_sdbc_shutdown_in_progress)
		return (EIO);

	if (xcd == NSC_ANON_CD)
		cd = _CD_NOHASH;

	KSTAT_RUNQ_ENTER(cd);

	/*
	 * Force large writes on nvram systems to be write-through to
	 * avoid the (slow) bcopy into nvram.
	 */

	if (flag & NSC_WRBUF) {
		if (fba_len > (nsc_size_t)sdbc_wrthru_len) {
			flag |= NSC_WRTHRU;
		}
	}

#ifdef DEBUG
	if (sdbc_pageio_debug != SDBC_PAGEIO_OFF) {
		switch (sdbc_pageio_debug) {
		case SDBC_PAGEIO_RDEV:
			if (cd != _CD_NOHASH &&
			    sdbc_pageio_rdev != (dev_t)-1 &&
			    _sd_cache_files[cd].cd_crdev == sdbc_pageio_rdev)
				flag |= NSC_PAGEIO;
			break;

		case SDBC_PAGEIO_RAND:
			if ((nsc_lbolt() % 3) == 0)
				flag |= NSC_PAGEIO;
			break;

		case SDBC_PAGEIO_ALL:
			flag |= NSC_PAGEIO;
			break;
		}
	}
#endif /* DEBUG */

	if (fba_len > (nsc_size_t)BLK_FBAS) {
		rw_enter(&sdbc_queue_lock, RW_WRITER);
		locked = 1;
	}

	/*
	 * _CD_NOHASH: client wants temporary (not hashed) cache memory
	 * not associated with a local disk.  Skip local disk checks.
	 */
	if (cd == _CD_NOHASH) {
		flag &= ~(NSC_RDBUF | NSC_WRBUF | NSC_RDAHEAD);
		handle = *handle_p;
		handle->bh_flag |= NSC_HACTIVE;
		goto setup;
	}

	SDTRACE(ST_ENTER|SDF_ALLOCBUF, cd, fba_len, fba_pos, flag, 0);


	if ((flag & NSC_RDAHEAD) && _sd_prefetch_opt) {
		sts = _sd_prefetch_buf(cd, fba_pos, fba_len, flag, handle,
		    locked);
		goto done;
	}

#if !defined(_SD_NOCHECKS)
	if (flag & NSC_RDAHEAD) { /* _sd_prefetch_opt == 0 */
		nsc_size_t file_size;	/* file_size in FBA's */
		/* prefetch: truncate if req'd */
		if (fba_len > sdbc_max_fbas)
			fba_len = sdbc_max_fbas;
		file_size = _sd_cache_files[(cd)].cd_info->sh_filesize;
		if ((fba_pos + fba_len) > file_size) {
			fba_len = file_size - fba_pos;
#ifdef NSC_MULTI_TERABYTE
			if ((int64_t)fba_len <= 0) {
#else
			if ((int32_t)fba_len <= 0) {
#endif
				sts = EIO;
				SDTRACE(ST_EXIT|SDF_ALLOCBUF, cd, fba_len,
				    fba_pos, flag, sts);
				goto done;
			}
		}
	} else
	if (sts = _sd_check_buffer_alloc(cd, fba_pos, fba_len, handle_p)) {
		SDTRACE(ST_EXIT|SDF_ALLOCBUF, cd, fba_len, fba_pos, flag, sts);
		goto done;
	}
#endif
	if (fba_len == 0) {
		SDTRACE(ST_EXIT|SDF_ALLOCBUF, cd, fba_len, fba_pos,
		    flag, EINVAL);
		sts = EINVAL;
		goto done;
	}

	handle->bh_flag |= NSC_HACTIVE;
	cdi = &_sd_cache_files[cd];

	if (cdi->cd_recovering) {
		/*
		 * If recovering this device, then block all allocates
		 * for reading or writing. If we allow reads then
		 * this path could see old data before we recover.
		 * If we allow writes then new data could be overwritten
		 * by old data.
		 * This is clearly still not a complete solution as
		 * the thread doing this allocate could conceivably be
		 * by this point (and in _sd_write/_sd_read for that matter
		 * which don't even have this protection). But this type
		 * of path seems to only exist in a failover situation
		 * where a device has failed on the other node and works
		 * on this node so the problem is not a huge one but exists
		 * never the less.
		 */
		if (sts = _sd_recovery_wblk_wait(cd)) {
			handle->bh_flag &= ~NSC_HACTIVE;
			SDTRACE(ST_EXIT|SDF_ALLOCBUF, cd, fba_len, fba_pos,
			    flag, sts);
			goto done;
		}
	}

	/* write & disk failed, return error immediately */
	if ((flag & NSC_WRBUF) && cdi->cd_info->sh_failed) {
		handle->bh_flag &= ~NSC_HACTIVE;
		SDTRACE(ST_EXIT|SDF_ALLOCBUF, cd, fba_len, fba_pos, flag, EIO);
		sts = EIO;
		goto done;
	}

setup:

	_SD_SETUP_HANDLE(handle, cd, fba_pos, fba_len, flag);
	handle->bh_centry = NULL;
	bufvec = handle->bh_bufvec;
	if (flag & NSC_RDAHEAD) { /* _sd_prefetch_opt == 0 */
		/* CKD prefetch: bufvec not req'd, use placeholder */
		bufvec->bufaddr = NULL;
		bufvec->bufvmeaddr = NULL;
		bufvec->buflen  = 0;
		bufvec = _prefetch_sb_vec;
	}
	st_cblk = FBA_TO_BLK_NUM(fba_pos);
	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = BLK_FBAS - st_cblk_off;
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);
	cblk = st_cblk;


	/*
	 * count number of blocks on chain that is required
	 */

	/* middle piece */
	dmchain_request_blocks =
	    (fba_len - (st_cblk_len + end_cblk_len)) >> BLK_FBA_SHFT;

	/* start piece */
	++dmchain_request_blocks;

	/* end piece */
	if (end_cblk_len)
		++dmchain_request_blocks;


	cc_flag = 0;
	if ((handle->bh_flag & NSC_PINNABLE) && (handle->bh_flag & NSC_WRBUF))
		cc_flag |= CC_PINNABLE;
	if (handle->bh_flag & (NSC_NOCACHE|NSC_SEQ_IO))
		cc_flag |= CC_QHEAD;
	lentry = NULL;
	stall = 0;

	do {
		pageio = ((flag & NSC_PAGEIO) != 0 || sdbc_pageio_always != 0);
cget:
		if ((centry = (_sd_cctl_t *)
		    _sd_hash_search(cd, cblk, _sd_htable)) != 0) {

			if (SET_CENTRY_INUSE(centry)) {
				/* already inuse: wait for block, retry */
				sdbc_allocb_inuse++;
				if (locked)
					rw_exit(&sdbc_queue_lock);
				_sd_cc_wait(cd, cblk, centry, CC_INUSE);
				if (locked)
					rw_enter(&sdbc_queue_lock, RW_WRITER);
				goto cget;
			}

			/*
			 * bug 4529671
			 * now that we own the centry make sure that
			 * it is still good.  it could have been processed
			 * by _sd_dealloc_dm() in the window between
			 * _sd_hash_search() and SET_CENTRY_INUSE().
			 */
			if ((_sd_cctl_t *)
			    _sd_hash_search(cd, cblk, _sd_htable) != centry) {
				sdbc_allocb_deallocd++;
#ifdef DEBUG
				cmn_err(CE_WARN,
				    "!centry %p cd %d cblk %" NSC_SZFMT
				    " fba_len %" NSC_SZFMT " lost to dealloc?! "
				    "cc_data %p", (void *)centry, cd, cblk,
				    fba_orig_len, (void *)centry->cc_data);
#endif

				CLEAR_CENTRY_INUSE(centry);
				goto cget;
			}

			if (CC_CD_BLK_MATCH(cd, cblk, centry)) {
				/*
				 * Do pagelist io mutual exclusion
				 * before messing with the centry.
				 */
				if (pageio && SET_CENTRY_PAGEIO(centry)) {
					/* wait for flusher to finish pageio */
					sdbc_allocb_pageio1++;

					CLEAR_CENTRY_INUSE(centry);
					if (locked)
						rw_exit(&sdbc_queue_lock);
					_sd_cc_wait(cd, cblk, centry,
					    CC_PAGEIO);
					if (locked)
						rw_enter(&sdbc_queue_lock,
						    RW_WRITER);
					goto cget;
				}

				sdbc_allocb_hit++;
				this_entry_type = HASH_ENTRY_DM;
				pageio = 0;
				centry->cc_toflush = 0;

				centry->cc_hits++;

				/* this will reset the age flag */
				sdbc_centry_init_dm(centry);

				DTRACE_PROBE1(_sd_alloc_buf1,
				    _sd_cctl_t *, centry);
			} else {
				/* block mismatch: release, alloc new block */
				sdbc_allocb_lost++;

				CLEAR_CENTRY_INUSE(centry);

				goto cget;

			}
		} else {
			centry = sdbc_centry_alloc(cd, cblk,
			    dmchain_request_blocks, &stall,
			    &alloc_tok, locked ? ALLOC_LOCKED : 0);

			/*
			 * dmchaining adjustment.
			 * if centry was obtained from the dmchain
			 * then clear local pageio variable because the
			 * centry already has cc_pageio set.
			 */
			if (CENTRY_PAGEIO(centry))
				pageio = 0;

			DTRACE_PROBE1(_sd_alloc_buf2, _sd_cctl_t *, centry);

			this_entry_type = ELIGIBLE_ENTRY_DM;
			if (centry->cc_aging_dm & FOUND_IN_HASH_DM)
				this_entry_type = HASH_ENTRY_DM;
			else {
				if (centry->cc_aging_dm & FOUND_HOLD_OVER_DM)
					this_entry_type = HOLD_ENTRY_DM;
			}
		}

		centry->cc_aging_dm &= ~(FOUND_IN_HASH_DM|FOUND_HOLD_OVER_DM);

		/*
		 * Do pagelist io mutual exclusion now if we did not do
		 * it above.
		 */

		if (pageio && SET_CENTRY_PAGEIO(centry)) {
			/* wait for flusher to finish pageio */
			sdbc_allocb_pageio2++;


			CLEAR_CENTRY_INUSE(centry);
			if (locked)
				rw_exit(&sdbc_queue_lock);
			_sd_cc_wait(cd, cblk, centry, CC_PAGEIO);
			if (locked)
				rw_enter(&sdbc_queue_lock, RW_WRITER);
			goto cget;
		}

		pageio = 0;

		if (CENTRY_DIRTY(centry)) {
			/*
			 * end action might set PEND_DIRTY flag
			 * must lock if need to change flag bits
			 */
			if (centry->cc_flag != (centry->cc_flag | cc_flag)) {
				/* was FAST */
				mutex_enter(&centry->cc_lock);
				centry->cc_flag |= cc_flag;
				/* was FAST */
				mutex_exit(&centry->cc_lock);
			}
		} else
			centry->cc_flag |= cc_flag;

		centry->cc_chain = NULL;

		/*
		 * step 0:check valid bits in each cache ele as
		 * the chain grows - set ioent/io_pos to first
		 * instance of invalid data
		 */
		if (cblk == st_cblk) {
			handle->bh_centry = centry;
			fba_len -= st_cblk_len;
			lentry = centry;
			if (flag & NSC_RDBUF)  {
				if (!SDBC_VALID_BITS(st_cblk_off, st_cblk_len,
				    centry)) {
					io_pos = fba_pos;
					ioent = centry;
				} else {
					DATA_LOG(SDF_ALLOC, centry, st_cblk_off,
					    st_cblk_len);

					DTRACE_PROBE4(_sd_alloc_data1,
					    uint64_t, (uint64_t)
					    (BLK_TO_FBA_NUM(cblk) +
					    st_cblk_off), int, st_cblk_len,
					    char *, *(int64_t *)
					    (centry->cc_data +
					    FBA_SIZE(st_cblk_off)),
					    char *, *(int64_t *)
					    (centry->cc_data +
					    FBA_SIZE(st_cblk_off + st_cblk_len)
					    - 8));
				}
			}
			cblk++;
		} else if (fba_len == (nsc_size_t)end_cblk_len) {
			lentry->cc_chain = centry;
			fba_len -= end_cblk_len;
			if (flag & NSC_RDBUF) {
				if (ioent == NULL) {
					if (!SDBC_VALID_BITS(0, end_cblk_len,
					    centry)) {
						io_pos = BLK_TO_FBA_NUM(cblk);
						ioent = centry;
					} else {
						DATA_LOG(SDF_ALLOC, centry, 0,
						    end_cblk_len);

						DTRACE_PROBE4(_sd_alloc_data2,
						    uint64_t,
						    BLK_TO_FBA_NUM(cblk),
						    int, end_cblk_len,
						    char *, *(int64_t *)
						    (centry->cc_data),
						    char *, *(int64_t *)
						    (centry->cc_data +
						    FBA_SIZE(end_cblk_len)
						    - 8));
					}
				}
			}
		} else {
			lentry->cc_chain = centry;
			lentry = centry;
			fba_len -= BLK_FBAS;
			if (flag & NSC_RDBUF) {
				if (ioent == NULL) {
					if (!FULLY_VALID(centry)) {
						io_pos = BLK_TO_FBA_NUM(cblk);
						ioent = centry;
					} else {
						DATA_LOG(SDF_ALLOC, centry, 0,
						    BLK_FBAS);

						DTRACE_PROBE4(_sd_alloc_data3,
						    uint64_t, (uint64_t)
						    BLK_TO_FBA_NUM(cblk),
						    int, BLK_FBAS,
						    char *, *(int64_t *)
						    (centry->cc_data),
						    char *, *(int64_t *)
						    (centry->cc_data +
						    FBA_SIZE(BLK_FBAS) - 8));
					}
				}
			}
			cblk++;
		}

		/* if this block has a new identity clear prefetch history */
		if (this_entry_type != HASH_ENTRY_DM)
			centry->cc_aging_dm &=
			    ~(PREFETCH_BUF_I | PREFETCH_BUF_E);

		centry->cc_aging_dm &= ~(ENTRY_FIELD_DM);
		centry->cc_aging_dm |= this_entry_type;
		if (flag & NSC_METADATA)
			centry->cc_aging_dm |= STICKY_METADATA_DM;

		--dmchain_request_blocks;
	} while (fba_len);

	if (locked) {
		rw_exit(&sdbc_queue_lock);
		locked = 0;
	}

	ASSERT(dmchain_request_blocks == 0);

	/*
	 * do any necessary cleanup now that all the blocks are allocated.
	 */
	sdbc_centry_alloc_end(&alloc_tok);

	/* be sure you nul term. the chain */
	centry->cc_chain = NULL;

	/*
	 * step one: establish HOST/PARASITE/OTHER relationships
	 * between the centry ele in the list and calc the alloc size
	 * (fill in CATAGORY based on TYPE and immediate neighbors)
	 */
	if (sts = _sd_setup_category_on_type(handle->bh_centry)) {
#ifdef DEBUG
		err = _sd_free_buf(handle);
		if (err) {
			cmn_err(CE_WARN, "!sdbc(_sd_alloc_buf): _sd_free_buf "
			    "failed: err:%d handle:%p", err, (void *)handle);
		}
#else
		(void) _sd_free_buf(handle);
#endif
		goto done;
	}

	/*
	 * step two: alloc the needed mem and fill in the data and chaining
	 * fields (leave bufvec for step three)
	 */
	(void) _sd_setup_mem_chaining(handle->bh_centry, 0);

	/*
	 * step three: do the bufvec
	 */
	fba_len = fba_orig_len;
	centry = handle->bh_centry;
	bufvec = handle->bh_bufvec;

	while (centry) {
		DTRACE_PROBE3(_sd_alloc_buf_centrys, _sd_cctl_t *, centry,
		    int, cd, uint64_t,
		    (uint64_t)BLK_TO_FBA_NUM(CENTRY_BLK(centry)));

		if (fba_len == fba_orig_len) {
			bufvec->bufaddr = (centry->cc_data +
			    FBA_SIZE(st_cblk_off));
			bufvec->bufvmeaddr = 0; /* not used */
			bufvec->buflen  = FBA_SIZE(st_cblk_len);
			bufvec++;
			fba_len -= st_cblk_len;
		} else if (fba_len == (nsc_size_t)end_cblk_len) {
			_sd_bufvec_t *pbufvec = bufvec - 1;

			if ((pbufvec->bufaddr + pbufvec->buflen) ==
			    centry->cc_data) {
				/* contiguous */
				pbufvec->buflen += FBA_SIZE(end_cblk_len);
			} else {

				bufvec->bufaddr = centry->cc_data;
				bufvec->bufvmeaddr = 0; /* not used */
				bufvec->buflen = FBA_SIZE(end_cblk_len);
				bufvec++;
			}

			fba_len -= end_cblk_len;
		} else {
			_sd_bufvec_t *pbufvec = bufvec - 1;

			if ((pbufvec->bufaddr + pbufvec->buflen) ==
			    centry->cc_data) {
				/* contiguous */
				pbufvec->buflen += CACHE_BLOCK_SIZE;
			} else {

				bufvec->bufaddr = centry->cc_data;
				bufvec->bufvmeaddr = 0; /* not used */
				bufvec->buflen  = CACHE_BLOCK_SIZE;
				bufvec++;
			}

			fba_len -= BLK_FBAS;
		}

		centry = centry->cc_chain;
	}

	/* be sure you nul term. the chain */
	bufvec->bufaddr = NULL;
	bufvec->bufvmeaddr = 0;
	bufvec->buflen = 0;

	/* frag statistics */
	{
		_sd_bufvec_t *tbufvec;

		for (tbufvec = handle->bh_bufvec; tbufvec != bufvec;
		    ++tbufvec) {
			if ((min_frag > tbufvec->buflen) || (min_frag == 0))
				min_frag = tbufvec->buflen;

			if (max_frag < tbufvec->buflen)
				max_frag = tbufvec->buflen;
		}

		nfrags = bufvec - handle->bh_bufvec;
		min_frag = FBA_LEN(min_frag);
		max_frag = FBA_LEN(max_frag);
	}

	/* buffer memory frag stats */
	DTRACE_PROBE4(_sd_alloc_buf_frag, uint64_t, (uint64_t)fba_orig_len,
	    int, nfrags, int, min_frag, int, max_frag);


	if (flag & NSC_WRBUF) {
		if (_SD_IS_WRTHRU(handle))
			goto alloc_done;
		if (_sd_alloc_write(handle->bh_centry, &stall)) {
			_sd_unblock(&_sd_flush_cv);
			handle->bh_flag |= NSC_FORCED_WRTHRU;
		} else {
			for (centry = handle->bh_centry;
			    centry; centry = centry->cc_chain) {

				CENTRY_SET_FTPOS(centry);
				SSOP_SETCENTRY(sdbc_safestore,
				    centry->cc_write);
			}
		}
	}

alloc_done:
	if (locked) {
		rw_exit(&sdbc_queue_lock);
		locked = 0;
	}
	if (ioent) {
		_SD_DISCONNECT_CALLBACK(handle);
		sts = _sd_doread(handle,  ioent, io_pos,
		    (fba_pos + fba_orig_len - io_pos), flag);
		if (sts > 0)
			(void) _sd_free_buf(handle);
	} else
		if (flag & NSC_RDBUF) {
			CACHE_FBA_READ(cd, fba_orig_len);
			CACHE_READ_HIT;
			FBA_READ_IO_KSTATS(cd, FBA_SIZE(fba_orig_len));

			sts = NSC_HIT;
	} else
		sts = (stall) ? NSC_DONE : NSC_HIT;

	SDTRACE(ST_EXIT|SDF_ALLOCBUF, cd, fba_orig_len, fba_pos, flag, sts);

done:
	if (locked)
		rw_exit(&sdbc_queue_lock);

	KSTAT_RUNQ_EXIT(cd);

	return (sts);
}

/*
 * consistency checking for ccents
 */

#define	ELIGIBLE(p) (p & ELIGIBLE_ENTRY_DM)
#define	HOLD(p) (p & HOLD_ENTRY_DM)
#define	HASHE(p) (p & HASH_ENTRY_DM)

#define	HOST(p) (p & HOST_ENTRY_DM)
#define	PARA(p) (p & PARASITIC_ENTRY_DM)
#define	OTHER(p) \
	(!(p & (HOST_ENTRY_DM | PARASITIC_ENTRY_DM | ELIGIBLE_ENTRY_DM)))

#define	AVAIL(p) (p & AVAIL_ENTRY_DM)

/*
 * sdbc_check_cctl_cot -- consistency check for _sd_setup_category_on_type()
 * may only be called on entry to state machine (when ccent is either
 * ELIGIBLE_ENTRY_DM, HOLD_ENTRY_DM or HASH_ENTRY_DM).
 *
 * print message or panic (DEBUG) if inconsistency detected.
 */
static int
sdbc_check_cctl_cot(_sd_cctl_t *centry)
{
	uint_t age;
	int size;
	uchar_t *data;
	int host_or_other;
	int para;
	int ccent_ok = 1;

	age = centry->cc_aging_dm;
	size = centry->cc_alloc_size_dm;
	data = centry->cc_data;
	host_or_other = size && data;
	para = !size && data;

	/*
	 * on entry to _sd_setup_category_on_type(),
	 * one of three mutually exclusive entry field bits must be set
	 */

	switch ((age & (ELIGIBLE_ENTRY_DM | HOLD_ENTRY_DM | HASH_ENTRY_DM))) {
		case ELIGIBLE_ENTRY_DM:
		case HOLD_ENTRY_DM:
		case HASH_ENTRY_DM:
			/* ok */
			break;
		default:
			/* zero or multiple flag bits */
			ccent_ok = 0;
			break;
	}

	/* categories are mutually exclusive */
	if (HOST(age) && PARA(age))
		ccent_ok = 0;

	/* these bits should be cleared out (STICKY_METADATA_DM not used) */
	if (age & (AVAIL_ENTRY_DM | FOUND_HOLD_OVER_DM | FOUND_IN_HASH_DM |
	    STICKY_METADATA_DM))
		ccent_ok = 0;

	/* eligible has no data and no size */
	if (ELIGIBLE(age) && (size || data))
		ccent_ok = 0;

	/* parasite has zero size and non-zero data */
	if (PARA(age) && !para)
		ccent_ok = 0;

	/* host has non-zero size and non-zero data */
	if (HOST(age) && !host_or_other)
		ccent_ok = 0;

	/* "other" is just like a host */
	if (OTHER(age) && !host_or_other)
		ccent_ok = 0;

	/* a HOLD or a HASH must have a size */
	if ((size) && !(age & (HASH_ENTRY_DM | HOLD_ENTRY_DM)))
		ccent_ok = 0;

	if (!ccent_ok)
		cmn_err(cmn_level,
		    "!sdbc(sdbc_check_cctl_cot): inconsistent ccent %p "
		    "age %x size %d data %p", (void *)centry, age, size,
		    (void *)data);

	return (ccent_ok);
}

/*
 * sdbc_mark_cctl_cot  -- mark cctls bad and invalidate when
 *			  inconsistency found in _sd_setup_category_on_type()
 * returns nothing
 *
 * Note:  this is an error recovery path that is triggered when an
 * inconsistency in a cctl is detected.  _sd_centry_release() will take
 * these cache entries out of circulation and place them on a separate list
 * for debugging purposes.
 */
void
sdbc_mark_cctl_cot(_sd_cctl_t *header, _sd_cctl_t *centry)
{
	_sd_cctl_t *cur_ent = header;

	/* the entire chain is guilty by association */
	while (cur_ent) {

		(void) _sd_hash_delete((struct _sd_hash_hd *)cur_ent,
		    _sd_htable);

		cur_ent->cc_aging_dm |= BAD_CHAIN_DM;

		cur_ent = cur_ent->cc_chain;
	}

	centry->cc_aging_dm |= BAD_ENTRY_DM; /* this is the problem child */
}

/*
 * _sd_setup_category_on_type(_sd_cctl_t *) - Setup the centry CATEGORY based on
 * centry TYPE and immediate neighbors. Identify each eligible (ie not HASH)
 * centry as a host/parasite. host actually have memory allocated to
 * them and parasites are chained to the host and point to page offsets within
 * the host's memory.
 *
 * RETURNS:
 *	0 on success, EINTR if inconsistency detected in centry
 *
 * Note:
 *	none
 */
static int
_sd_setup_category_on_type(_sd_cctl_t *header)
{
	_sd_cctl_t *prev_ent, *next_ent, *centry;
	_sd_cctl_t *anchor = NULL;
	int	 current_pest_count, local_max_dyn_list;
	int	 cl;
	int ret = 0;

	ASSERT(header);

	if (sdbc_use_dmchain)
		local_max_dyn_list = max_dm_queues - 1;
	else {
		/* pickup a fresh copy - has the world changed */
		local_max_dyn_list = dynmem_processing_dm.max_dyn_list;
	}

	prev_ent = 0;
	centry = header;
	next_ent = centry->cc_chain;
	current_pest_count = 0;
	cl = 2;

	/* try to recover from bad cctl */
	if (sdbc_check_cot && !sdbc_check_cctl_cot(centry))
		ret = EINTR;

	while (cl && (ret == 0)) {
		switch (cl) {
			case (1):  /* chain to next/monitor for completion */
				prev_ent = centry;
				centry = next_ent;
				next_ent = 0;
				cl = 0;
				if (centry) {

					if (sdbc_check_cot &&
					    !sdbc_check_cctl_cot(centry)) {
						ret = EINTR;
						break;
					}

					next_ent = centry->cc_chain;
					cl = 2;
				}
			break;

			case (2): /* vector to appropriate routine */
				if (!(centry->cc_aging_dm & ELIGIBLE_ENTRY_DM))
					cl = 5;
				else if (prev_ent && (prev_ent->cc_aging_dm &
				    ELIGIBLE_ENTRY_DM))
					cl = 15;
				else
					cl = 10;
			break;

			case (5): /* process NON-ELIGIBLE entries */
				if (!(centry->cc_aging_dm &
				    (HASH_ENTRY_DM|HOLD_ENTRY_DM))) {
					/* no catagory */

					/* consistency check */
					if (centry->cc_alloc_size_dm ||
					    centry->cc_data) {
						cmn_err(cmn_level,
						    "!sdbc(setup_cot): "
						    "OTHER with data/size %p",
						    (void *)centry);

						ret = EINTR;
						break;
					}

					centry->cc_aging_dm &=
					    ~CATAGORY_ENTRY_DM;
					centry->cc_alloc_size_dm = BLK_SIZE(1);
					DTRACE_PROBE1(_sd_setup_category,
					    _sd_cctl_t *, centry);
				}
				cl = 1;
			break;

			/*
			 * no prev entry (ie top of list) or no prev
			 * ELIGIBLE entry
			 */
			case (10):
				/*
				 * this is an eligible entry, does it start
				 * a list or is it a loner
				 */
				/* consistency check */
				if (centry->cc_alloc_size_dm ||
				    centry->cc_data) {
					cmn_err(cmn_level, "!sdbc(setup_cot): "
					    "HOST with data/size %p",
					    (void *)centry);
					ret = EINTR;
					break;
				}

				if (next_ent && (next_ent->cc_aging_dm &
				    ELIGIBLE_ENTRY_DM)) {


					/* it starts a list */
					/* host catagory */
					centry->cc_aging_dm |= HOST_ENTRY_DM;
					/* start out with one page */
					centry->cc_alloc_size_dm = BLK_SIZE(1);
					anchor = centry;
					DTRACE_PROBE1(_sd_setup_category,
					    _sd_cctl_t *, anchor);
					cl = 1;
				} else {
					/*
					 * it's a loner
					 * drop status to no category and
					 * restart
					 */
					cl = 2;
					centry->cc_aging_dm &=
					    ~ELIGIBLE_ENTRY_DM;
				}
			break;

			case (15): /* default to parasite catagory */

				/* consistency check */
				if (centry->cc_alloc_size_dm ||
				    centry->cc_data) {
					cmn_err(cmn_level, "!sdbc(setup_cot): "
					    "PARA with data/size %p",
					    (void *)centry);

					ret = EINTR;
					break;
				}

				if (current_pest_count < local_max_dyn_list-1) {
					/* continue to grow the pest list */
					current_pest_count++;
					centry->cc_aging_dm |=
					    PARASITIC_ENTRY_DM;

					/*
					 * offset of host ent mem this will pt
					 * to
					 */
					centry->cc_alloc_size_dm =
					    anchor->cc_alloc_size_dm;
					/*
					 * up the host mem req by one for
					 * this parasite
					 */
					DTRACE_PROBE1(_sd_setup_category,
					    _sd_cctl_t *, centry);

					anchor->cc_alloc_size_dm += BLK_SIZE(1);

					cl = 1;
				} else {
					/*
					 * term this pest list - restart fresh
					 * on this entry
					 */
					current_pest_count = 0;
					prev_ent->cc_aging_dm &=
					    ~(HOST_ENTRY_DM|ELIGIBLE_ENTRY_DM);
					cl = 2;
				}
			break;
			} /* switch(cl) */
	} /* while (cl) */

	if (ret != 0)
		sdbc_mark_cctl_cot(header, centry);

	return (ret);
}

/*
 * _sd_setup_mem_chaining(_sd_cctl_t *) - Allocate memory, setup
 * mem ptrs an host/pest chaining. Do the actual allocation as described in
 * sd_setup_category_on_type().
 *
 * RETURNS:
 *	0 on success
 *	non-zero on error
 *
 * Note:
 *	if called with ALLOC_NOWAIT, caller must check for non-zero return
 */
static int
_sd_setup_mem_chaining(_sd_cctl_t *header, int flag)
{
	_sd_cctl_t *prev_ent, *next_ent, *centry;
	_sd_cctl_t *anchor = NULL;
	int cl, rc = 0;

	ASSERT(header);

	if (!header)
		return (0);

	prev_ent = 0;
	centry = header;
	next_ent = centry->cc_chain;
	cl = 2;
	while (cl) {
		switch (cl) {
			case (1):  /* chain to next/monitor for completion */
				centry->cc_aging_dm &= ~ELIGIBLE_ENTRY_DM;
				prev_ent = centry;
				centry = next_ent;
				next_ent = 0;
				cl = 0;
				if (centry) {
					next_ent = centry->cc_chain;
					cl = 2;
				}
			break;

			case (2): /* vector to appropriate routine */
				if (centry->cc_aging_dm & HOST_ENTRY_DM)
					cl = 10;
				else if (centry->cc_aging_dm &
				    PARASITIC_ENTRY_DM)
					cl = 15;
				else
					cl = 5;
			break;

			case (5): /* OTHER processing - alloc mem */
				if (rc = sdbc_centry_memalloc_dm(centry,
				    centry->cc_alloc_size_dm, flag))
					/* The allocation failed */
					cl = 0;
				else
					cl = 1;
			break;

				/*
				 * HOST entry processing - save the anchor pt,
				 * alloc the memory,
				 */
			case (10): /* setup head and nxt ptrs */
				anchor = centry;
				if (rc = sdbc_centry_memalloc_dm(centry,
				    centry->cc_alloc_size_dm, flag))
					/* The allocation failed */
					cl = 0;
				else
					cl = 1;
			break;

				/*
				 * PARASITIC entry processing - setup w/no
				 * memory, setup head/next ptrs,
				 */
			case (15):
				/*
				 * fudge the data mem ptr to an offset from
				 * the anchor alloc
				 */
				if (!(centry->cc_aging_dm &
				    (HASH_ENTRY_DM| HOLD_ENTRY_DM))) {
					centry->cc_head_dm = anchor;

					/* chain prev to this */
					prev_ent->cc_next_dm = centry;

					/*
					 * generate the actual data ptr into
					 * host entry memory
					 */
					centry->cc_data = anchor->cc_data +
					    centry->cc_alloc_size_dm;
					centry->cc_alloc_size_dm = 0;
				}
				cl = 1;
			break;
		} /* switch(cl) */
	} /* while (cl) */

	return (rc);
}

/*
 * _sd_check_buffer_alloc - Check if buffer allocation is invalid.
 *
 * RETURNS:
 *	0 if its ok to continue with allocation.
 *	Else errno to be returned to the user.
 *
 * Note:
 *	This routine could block if the device is not local and
 *	recovery is in progress.
 */

/* ARGSUSED */
static int
_sd_check_buffer_alloc(int cd, nsc_off_t fba_pos, nsc_size_t fba_len,
    _sd_buf_handle_t **hp)
{
	/*
	 * This check exists to ensure that someone will not pass in an
	 * arbitrary pointer and try to pass it off as a handle.
	 */
	if ((*hp)->bh_flag & (~_SD_VALID_FLAGS)) {
		cmn_err(CE_WARN, "!sdbc(_sd_check_buffer_alloc) "
		    "cd %d invalid handle %p flags %x",
		    cd, (void *)*hp, (*hp)->bh_flag);
		return (EINVAL);
	}

	if ((_sd_cache_initialized == 0) || (FILE_OPENED(cd) == 0)) {
		cmn_err(CE_WARN, "!sdbc(_sd_check_buffer_alloc) "
		    "cd %d not open. Cache init %d",
		    cd, _sd_cache_initialized);
		return (EINVAL);
	}
	ASSERT(cd >= 0);
	if (!(_sd_cache_files[cd].cd_rawfd) ||
	    !nsc_held(_sd_cache_files[cd].cd_rawfd)) {
		cmn_err(CE_WARN,
		    "!sdbc(_sd_check_buffer_alloc) cd %d is not attached", cd);
		return (EINVAL);
	}

	ASSERT_IO_SIZE(fba_pos, fba_len, cd);
	ASSERT_LEN(fba_len);

	return (0);
}

/*
 * sdbc_check_handle -- check that handle is valid
 * return 1 if ok, 0 otherwise (if debug then panic).
 */
static int
sdbc_check_handle(_sd_buf_handle_t *handle)
{
	int ret = 1;

	if (!_SD_HANDLE_ACTIVE(handle)) {

		cmn_err(cmn_level, "!sdbc(_sd_free_buf): invalid handle %p"
		    "cd %d fpos %" NSC_SZFMT " flen %" NSC_SZFMT " flag %x",
		    (void *)handle, HANDLE_CD(handle), handle->bh_fba_pos,
		    handle->bh_fba_len, handle->bh_flag);

		ret = 0;
	}

	return (ret);
}

/*
 * _sd_free_buf -  Free the buffers allocated in _sd_alloc_buf.
 *
 * ARGUMENTS:
 *	handle	-  The handle allocated in _sd_alloc_buf.
 *
 * RETURNS:
 *	0 on success.
 *	Else errno.
 *
 * NOTE:
 *	If handle was allocated through _sd_alloc_buf, the handle allocated
 *	flag (NSC_HALLOCATED) will be reset by _sd_alloc_buf. This indicates
 *	that _sd_free_buf should free up the handle as well.
 *	All other handles directly allocated from _sd_alloc_handle will have
 *	that flag set. Any handle with valid blocks will have the handle
 *	active flag. It is an error if the active flag is not set.
 *	(if free_buf were called without going through alloc_buf)
 */

int
_sd_free_buf(_sd_buf_handle_t *handle)
{
	_sd_cctl_t *centry, *cc_chain;
	int cd = HANDLE_CD(handle);
	int flen = handle->bh_fba_len;
	int fpos = handle->bh_fba_pos;

	SDTRACE(ST_ENTER|SDF_FREEBUF, HANDLE_CD(handle),
	    handle->bh_fba_len, handle->bh_fba_pos, 0, 0);

	if (sdbc_check_handle(handle) == 0)
		return (EINVAL);

	if (handle->bh_flag & NSC_MIXED) {
		/*
		 * Data in this handle will be a mix of data from the
		 * source device and data from another device, so
		 * invalidate all the blocks.
		 */
		handle->bh_flag &= ~NSC_QUEUE;
		centry = handle->bh_centry;
		while (centry) {
			centry->cc_valid = 0;
			centry = centry->cc_chain;
		}
	}

	if ((handle->bh_flag & NSC_QUEUE)) {
		handle->bh_flag &= ~NSC_QUEUE;
		_sd_queue_write(handle, handle->bh_fba_pos, handle->bh_fba_len);
	}

	handle->bh_flag &= ~NSC_HACTIVE;

	centry = handle->bh_centry;
	while (centry) {
		cc_chain = centry->cc_chain;
		_sd_centry_release(centry);
		centry = cc_chain;
	}

	/*
	 * help prevent dup call to _sd_centry_release if this handle
	 * is erroneously _sd_free_buf'd twice.  (should not happen).
	 */
	handle->bh_centry = NULL;

	if ((handle->bh_flag & NSC_HALLOCATED) == 0) {
		handle->bh_flag |= NSC_HALLOCATED;
		(void) _sd_free_handle(handle);
	} else {
		handle->bh_flag = NSC_HALLOCATED;
	}

	SDTRACE(ST_EXIT|SDF_FREEBUF, cd, flen, fpos, 0, 0);

	return (0);
}


static int _sd_lruq_srch = 0x2000;

/*
 * sdbc_get_dmchain -- get a candidate centry chain pointing to
 * 			contiguous memory
 *	ARGUMENTS:
 *	cblocks  - number of cache blocks requested
 *	stall	- pointer to stall count (no blocks avail)
 *	flag	- ALLOC_NOWAIT flag
 *
 *	RETURNS:
 * 		a cache entry or possible NULL if ALLOC_NOWAIT set
 *	USAGE:
 *		attempt to satisfy entire request from queue
 *		that has no memory allocated.
 *		if this fails then attempt a partial allocation
 *		with a preallocated block of requested size up to
 *		max_dyn_list.
 *		then look for largest chain less than max_dyn_list.
 */
static _sd_cctl_t *
sdbc_get_dmchain(int cblocks, int *stall, int flag)
{
	_sd_cctl_t *cc_dmchain = NULL;
	_sd_queue_t *q;
	_sd_cctl_t *qhead;
	int num_tries;
	int cblocks_orig = cblocks;
	int nowait = flag & ALLOC_NOWAIT;
	int i;

	num_tries = _sd_lruq_srch;

	ASSERT(cblocks != 0);

	while (!cc_dmchain) {
		/* get it from the os if possible */
		q = &sdbc_dm_queues[0];
		qhead = &(q->sq_qhead);

		if (q->sq_inq >= cblocks) {
			mutex_enter(&q->sq_qlock);
			if (q->sq_inq >= cblocks) {
				_sd_cctl_t *cc_ent;

				cc_dmchain = qhead->cc_next;

				/*
				 * set the inuse and pageio bits
				 * Note: this code expects the cc_ent to
				 * be available.  no other thread may set the
				 * inuse or pageio bit for an entry on the
				 * 0 queue.
				 */
				cc_ent = qhead;
				for (i = 0; i < cblocks; ++i) {
					cc_ent = cc_ent->cc_next;

					if (SET_CENTRY_INUSE(cc_ent)) {
						cmn_err(CE_PANIC,
						    "centry inuse on 0 q! %p",
						    (void *)cc_ent);
					}

					if (SET_CENTRY_PAGEIO(cc_ent)) {
						cmn_err(CE_PANIC,
						    "centry pageio on 0 q! %p",
						    (void *)cc_ent);
					}
				}
				/* got a dmchain */

				/* remove this chain from the 0 queue */
				cc_dmchain->cc_prev->cc_next = cc_ent->cc_next;
				cc_ent->cc_next->cc_prev = cc_dmchain->cc_prev;
				cc_dmchain->cc_prev = NULL;
				cc_ent->cc_next = NULL;

				q->sq_inq -= cblocks;

				ASSERT(GOOD_LRUSIZE(q));

			}
			mutex_exit(&q->sq_qlock);
			if (cc_dmchain)
				continue;
		}

		/* look for a pre-allocated block of the requested size */


		if (cblocks > (max_dm_queues - 1))
			cblocks = max_dm_queues - 1;

		q = &sdbc_dm_queues[cblocks];
		qhead = &(q->sq_qhead);

		if (q->sq_inq != 0) {
			_sd_cctl_t *tmp_dmchain;

			mutex_enter(&q->sq_qlock);

			for (tmp_dmchain = qhead->cc_next; tmp_dmchain != qhead;
			    tmp_dmchain = tmp_dmchain->cc_next) {

				/*
				 * get a dmchain
				 * set the inuse and pageio bits
				 */
				if (sdbc_dmchain_avail(tmp_dmchain)) {
					/* put on MRU end of queue */
					sdbc_requeue_dmchain(q, tmp_dmchain,
					    1, 0);
					cc_dmchain = tmp_dmchain;
					break;
				}
				sdbc_dmchain_not_avail++;
			}

			mutex_exit(&q->sq_qlock);
			if (cc_dmchain)
				continue;
		}

		/*
		 * spin block
		 * nudge the deallocator,  accelerate ageing
		 */

		mutex_enter(&dynmem_processing_dm.thread_dm_lock);
		cv_broadcast(&dynmem_processing_dm.thread_dm_cv);
		mutex_exit(&dynmem_processing_dm.thread_dm_lock);

		if (nowait)
			break;

		if (!(--num_tries)) {
			delay(drv_usectohz(20000));
			(void) (*stall)++;
			num_tries = _sd_lruq_srch;
			cblocks = cblocks_orig;
		} else { /* see if smaller request size is available */
			if (!(--cblocks))
				cblocks = cblocks_orig;
		}

	} /* while (!cc_dmchain) */

	return (cc_dmchain);
}

static int
sdbc_dmchain_avail(_sd_cctl_t *cc_ent)
{
	int chain_avail = 1;
	_sd_cctl_t *anchor = cc_ent;

	while (cc_ent) {

		ASSERT(_sd_cctl_valid(cc_ent));

		if (cc_ent->cc_aging_dm & BAD_CHAIN_DM) {
			chain_avail = 0;
			break;
		}

		if (CENTRY_DIRTY(cc_ent)) {
			chain_avail = 0;
			break;
		}
		if (SET_CENTRY_INUSE(cc_ent)) {
			chain_avail = 0;
			break;
		}

		if ((SET_CENTRY_PAGEIO(cc_ent))) {

			CLEAR_CENTRY_INUSE(cc_ent);
			chain_avail = 0;
			break;
		}

		if (CENTRY_DIRTY(cc_ent)) {

			CLEAR_CENTRY_PAGEIO(cc_ent);
			CLEAR_CENTRY_INUSE(cc_ent);
			chain_avail = 0;
			break;
		}

		cc_ent->cc_flag = 0;
		cc_ent->cc_toflush = 0;

		cc_ent = cc_ent->cc_next_dm;
	}

	if (!chain_avail)
		sdbc_clear_dmchain(anchor, cc_ent);
	else {
		cc_ent = anchor;

		/*
		 * prevent possible deadlocks in _sd_cc_wait():
		 * remove from hash and wakeup any waiters now that we
		 * have acquired the chain.
		 */
		while (cc_ent) {
			(void) _sd_hash_delete((struct _sd_hash_hd *)cc_ent,
			    _sd_htable);

			mutex_enter(&cc_ent->cc_lock);
			if (cc_ent->cc_await_use) {
				cv_broadcast(&cc_ent->cc_blkcv);
			}
			mutex_exit(&cc_ent->cc_lock);

			cc_ent->cc_creat = nsc_lbolt();
			cc_ent->cc_hits = 0;

			cc_ent = cc_ent->cc_next_dm;
		}
	}

	return (chain_avail);
}

static void
sdbc_clear_dmchain(_sd_cctl_t *cc_ent_start, _sd_cctl_t *cc_ent_end)
{
	_sd_cctl_t *cc_ent = cc_ent_start;
	_sd_cctl_t *prev_ent;

	ASSERT(_sd_cctl_valid(cc_ent));

	while (cc_ent != cc_ent_end) {

		ASSERT(_sd_cctl_valid(cc_ent));

		prev_ent = cc_ent;
		cc_ent = cc_ent->cc_next_dm;

		CLEAR_CENTRY_PAGEIO(prev_ent);
		CLEAR_CENTRY_INUSE(prev_ent);
	}

}

/*
 * put a dmchain on the LRU end of a queue
 */
void
sdbc_ins_dmqueue_front(_sd_queue_t *q, _sd_cctl_t *cc_ent)
{
	_sd_cctl_t *qhead = &(q->sq_qhead);

	ASSERT(_sd_cctl_valid(cc_ent));

	mutex_enter(&q->sq_qlock);
	cc_ent->cc_next = qhead->cc_next;
	cc_ent->cc_prev = qhead;
	qhead->cc_next->cc_prev = cc_ent;
	qhead->cc_next = cc_ent;
	q->sq_inq++;
	cc_ent->cc_cblocks = q->sq_dmchain_cblocks;

	ASSERT(GOOD_LRUSIZE(q));

	mutex_exit(&q->sq_qlock);

}

/*
 * put a dmchain on the MRU end of a queue
 */
static void
sdbc_ins_dmqueue_back(_sd_queue_t *q, _sd_cctl_t *cc_ent)
{
	_sd_cctl_t *qhead = &(q->sq_qhead);

	ASSERT(_sd_cctl_valid(cc_ent));

	mutex_enter(&q->sq_qlock);
	cc_ent->cc_next = qhead;
	cc_ent->cc_prev = qhead->cc_prev;
	qhead->cc_prev->cc_next = cc_ent;
	qhead->cc_prev = cc_ent;
	cc_ent->cc_seq = q->sq_seq++;
	q->sq_inq++;
	cc_ent->cc_cblocks = q->sq_dmchain_cblocks;

	ASSERT(GOOD_LRUSIZE(q));

	mutex_exit(&q->sq_qlock);

}

/*
 * remove dmchain from a queue
 */
void
sdbc_remq_dmchain(_sd_queue_t *q, _sd_cctl_t *cc_ent)
{

	ASSERT(_sd_cctl_valid(cc_ent));

	mutex_enter(&q->sq_qlock);
	cc_ent->cc_prev->cc_next = cc_ent->cc_next;
	cc_ent->cc_next->cc_prev = cc_ent->cc_prev;
	cc_ent->cc_next = cc_ent->cc_prev = NULL; /* defensive programming */
	cc_ent->cc_cblocks = -1; /* indicate not on any queue */

	q->sq_inq--;

	ASSERT(GOOD_LRUSIZE(q));

	mutex_exit(&q->sq_qlock);

}

/*
 * requeue a dmchain to the MRU end of its queue.
 * if getlock is 0 on entry the queue lock (sq_qlock) must be held
 */
void
sdbc_requeue_dmchain(_sd_queue_t *q, _sd_cctl_t *cc_ent, int mru,
    int getlock)
{
	_sd_cctl_t *qhead = &(q->sq_qhead);


	ASSERT(_sd_cctl_valid(cc_ent));

	if (getlock)
		mutex_enter(&q->sq_qlock);

	/* inline of sdbc_remq_dmchain() */
	cc_ent->cc_prev->cc_next = cc_ent->cc_next;
	cc_ent->cc_next->cc_prev = cc_ent->cc_prev;

	if (mru) { /* put on MRU end of queue */
		/* inline of sdbc_ins_dmqueue_back */
		cc_ent->cc_next = qhead;
		cc_ent->cc_prev = qhead->cc_prev;
		qhead->cc_prev->cc_next = cc_ent;
		qhead->cc_prev = cc_ent;
		cc_ent->cc_seq = q->sq_seq++;
		(q->sq_req_stat)++;
	} else { /* put on LRU end of queue i.e. requeue to head */
		/* inline of sdbc_ins_dmqueue_front */
		cc_ent->cc_next = qhead->cc_next;
		cc_ent->cc_prev = qhead;
		qhead->cc_next->cc_prev = cc_ent;
		qhead->cc_next = cc_ent;
		cc_ent->cc_seq = q->sq_seq++;

		/*
		 * clear the CC_QHEAD bit on all members of the chain
		 */
		{
			_sd_cctl_t *tcent;

			for (tcent = cc_ent;  tcent; tcent = tcent->cc_next_dm)
				tcent->cc_flag &= ~CC_QHEAD;
		}
	}

	if (getlock)
		mutex_exit(&q->sq_qlock);

}

/*
 * sdbc_dmchain_dirty(cc_ent)
 * return first dirty cc_ent in dmchain, NULL if chain is not dirty
 */
static _sd_cctl_t *
sdbc_dmchain_dirty(_sd_cctl_t *cc_ent)
{
	for (/* CSTYLED */;  cc_ent; cc_ent = cc_ent->cc_next_dm)
		if (CENTRY_DIRTY(cc_ent))
			break;

	return (cc_ent);
}

/*
 * sdbc_requeue_head_dm_try()
 * attempt to requeue a dmchain to the head of the queue
 */
void
sdbc_requeue_head_dm_try(_sd_cctl_t *cc_ent)
{
	int qidx;
	_sd_queue_t *q;

	if (!sdbc_dmchain_dirty(cc_ent)) {
		qidx = cc_ent->cc_cblocks;
		q = &sdbc_dm_queues[qidx];
		sdbc_requeue_dmchain(q, cc_ent, 0, 1); /* requeue head */
	}
}

/*
 * sdbc_centry_alloc_blks -- allocate cache entries with memory
 *
 * ARGUMENTS:
 *	cd	- Cache descriptor (from a previous open)
 *	cblk	- cache block number.
 *	reqblks	- number of cache blocks to be allocated
 *	flag	- can be ALLOC_NOWAIT
 * RETURNS:
 *	A cache block chain or NULL if ALLOC_NOWAIT and request fails
 *
 *	Note: caller must check for null return if called with
 *	ALLOC_NOWAIT set.
 */
_sd_cctl_t *
sdbc_centry_alloc_blks(int cd, nsc_off_t cblk, nsc_size_t reqblks, int flag)
{
	sdbc_allocbuf_t alloc_tok = {0}; /* must be 0 */
	int stall = 0;
	_sd_cctl_t *centry = NULL;
	_sd_cctl_t *lentry = NULL;
	_sd_cctl_t *anchor = NULL;
	_sd_cctl_t *next_centry;

	ASSERT(reqblks);

	while (reqblks) {
		centry = sdbc_centry_alloc(cd, cblk, reqblks, &stall,
		    &alloc_tok, flag);

		if (!centry)
			break;

		centry->cc_chain = NULL;

		if (lentry == NULL)
			anchor = centry;
		else
			lentry->cc_chain = centry;

		lentry = centry;

		centry->cc_aging_dm &= ~(ENTRY_FIELD_DM);

		if (centry->cc_aging_dm & FOUND_IN_HASH_DM)
			centry->cc_aging_dm |= HASH_ENTRY_DM;
		else
			if (centry->cc_aging_dm & FOUND_HOLD_OVER_DM)
				centry->cc_aging_dm |= HOLD_ENTRY_DM;
			else
				centry->cc_aging_dm |= ELIGIBLE_ENTRY_DM;

		centry->cc_aging_dm &= ~(FOUND_IN_HASH_DM|FOUND_HOLD_OVER_DM);
		--reqblks;
	}

	sdbc_centry_alloc_end(&alloc_tok);

	if (reqblks || (_sd_setup_category_on_type(anchor))) {
		centry = anchor;
		while (centry) {
			next_centry = centry->cc_chain;
			_sd_centry_release(centry);
			centry = next_centry;
		}
		anchor = NULL;

	} else
		/* This is where the memory is actually allocated */
		if (_sd_setup_mem_chaining(anchor, flag))
			anchor = NULL;

	return (anchor);
}


/*
 * sdbc_centry_alloc - sdbc internal function to allocate a new cache block.
 *
 * ARGUMENTS:
 *	cd	- Cache descriptor (from a previous open)
 *	cblk	- cache block number.
 *	stall	- pointer to stall count (no blocks avail)
 *	req_blocks - number of cache blocks remaining in caller's i/o request
 *	alloc_tok - pointer to token initialized to 0 on first call to function
 *	flag	- lock status of sdbc_queue_lock or ALLOC_NOWAIT flag
 * RETURNS:
 *	A cache block, or possibly NULL if ALLOC_NOWAIT set .
 *
 * USAGE:
 *	switch to the appropriate allocation function.
 *	this function is used when callers need more than one cache block.
 *	it is called repeatedly until the entire request is satisfied,
 *	at which time the caller will then do the memory allocation.
 *	if only one cache block is needed callers may use
 *	sdbc_centry_alloc_blks() which also allocates memory.
 *
 *	Note: caller must check for null return if called with
 *	ALLOC_NOWAIT set.
 */

_sd_cctl_t *
sdbc_centry_alloc(int cd, nsc_off_t cblk, nsc_size_t req_blocks, int *stall,
    sdbc_allocbuf_t *alloc_tok, int flag)
{
	_sd_cctl_t *centry;

	if (sdbc_use_dmchain)
		centry = sdbc_alloc_dmc(cd, cblk, req_blocks, stall, alloc_tok,
		    flag);
	else
		centry = sdbc_alloc_lru(cd, cblk, stall, flag);

	return (centry);
}

/*
 * sdbc_alloc_dmc -- allocate a centry from a dmchain
 *
 * ARGUMENTS:
 *	cd	- Cache descriptor (from a previous open)
 *	cblk	- cache block number.
 *	stall	- pointer to stall count (no blocks avail)
 *	req_blocks - number of cache blocks in clients i/o request
 *	alloc_tok - pointer to token initialized to 0 on first call to function
 *	flag	- lock status of sdbc_queue_lock, or ALLOC_NOWAIT flag
 * RETURNS:
 *	A cache block or possibly NULL if ALLOC_NOWAIT set
 *
 * USAGE:
 *	if dmchain is empty, allocate one.
 */
static _sd_cctl_t *
sdbc_alloc_dmc(int cd, nsc_off_t cblk, nsc_size_t req_blocks, int *stall,
    sdbc_allocbuf_t *alloc_tok, int flag)
{
	sdbc_allocbuf_impl_t *dmc = (sdbc_allocbuf_impl_t *)alloc_tok;
	_sd_cctl_t *centry = NULL;

	if (!dmc->sab_dmchain) {
		/*
		 * Note - sdbc_get_dmchain() returns
		 * with cc_inuse and cc_pageio set
		 * for all members of dmchain.
		 */
		if (dmc->sab_dmchain =
		    sdbc_get_dmchain(req_blocks, stall, flag)) {

			/* remember q it came from */
			if (dmc->sab_dmchain->cc_alloc_size_dm)
				dmc->sab_q = dmc->sab_dmchain->cc_cblocks;
		}
	}

	/*
	 * Note: dmchain pointer is advanced in sdbc_alloc_from_dmchain()
	 */
	if (dmc->sab_dmchain) /* could be NULL if ALLOC_NOWAIT set */
		centry = sdbc_alloc_from_dmchain(cd, cblk, alloc_tok, flag);

	return (centry);
}

/*
 * sdbc_alloc_from_dmchain -- allocate centry from a dmchain of centrys
 *
 * ARGUMENTS:
 *	cd	- Cache descriptor (from a previous open)
 *	cblk	- cache block number.
 *	alloc_tok - pointer to token
 *	flag	- lock status of sdbc_queue_lock or ALLOC_NOWAIT
 *
 * RETURNS:
 *	A cache block or possibly NULL if ALLOC_NOWAIT set.
 *
 * USAGE:
 *	This routine allocates a new cache block from the supplied dmchain.
 *	Assumes that dmchain is non-NULL and that all cache entries in
 *	the dmchain have been removed from hash and have their cc_inuse and
 *	cc_pageio bits set.
 */
static _sd_cctl_t *
sdbc_alloc_from_dmchain(int cd, nsc_off_t cblk, sdbc_allocbuf_t *alloc_tok,
    int flag)
{
	_sd_cctl_t *cc_ent, *old_ent;
	int categorize_centry;
	int locked = flag & ALLOC_LOCKED;
	int nowait = flag & ALLOC_NOWAIT;
	sdbc_allocbuf_impl_t *dmc = (sdbc_allocbuf_impl_t *)alloc_tok;

	SDTRACE(ST_ENTER|SDF_ENT_ALLOC, cd, 0, BLK_TO_FBA_NUM(cblk), 0, 0);

	ASSERT(dmc->sab_dmchain);

	cc_ent = dmc->sab_dmchain;

	ASSERT(_sd_cctl_valid(cc_ent));

	cc_ent->cc_valid = 0;
	categorize_centry = 0;
	if (cc_ent->cc_data)
		categorize_centry = FOUND_HOLD_OVER_DM;

alloc_try:
	if (cd == _CD_NOHASH)
		CENTRY_BLK(cc_ent) = cblk;
	else if ((old_ent = (_sd_cctl_t *)
	    _sd_hash_insert(cd, cblk, (struct _sd_hash_hd *)cc_ent,
	    _sd_htable)) != cc_ent) {

		if (SET_CENTRY_INUSE(old_ent)) {
			sdbc_centry_inuse++;

			if (nowait) {
				cc_ent = NULL;
				goto out;
			}

			if (locked)
				rw_exit(&sdbc_queue_lock);
			_sd_cc_wait(cd, cblk, old_ent, CC_INUSE);
			if (locked)
				rw_enter(&sdbc_queue_lock, RW_WRITER);
			goto alloc_try;
		}

		/*
		 * bug 4529671
		 * now that we own the centry make sure that
		 * it is still good. it could have been processed
		 * by _sd_dealloc_dm() in the window between
		 * _sd_hash_insert() and SET_CENTRY_INUSE().
		 */
		if ((_sd_cctl_t *)_sd_hash_search(cd, cblk, _sd_htable)
		    != old_ent) {
			sdbc_centry_deallocd++;
#ifdef DEBUG
			cmn_err(CE_WARN, "!cc_ent %p cd %d cblk %" NSC_SZFMT
			    " lost to dealloc?! cc_data %p", (void *)old_ent,
			    cd, cblk, (void *)old_ent->cc_data);
#endif

			CLEAR_CENTRY_INUSE(old_ent);

			if (nowait) {
				cc_ent = NULL;
				goto out;
			}

			goto alloc_try;
		}

		if (CC_CD_BLK_MATCH(cd, cblk, old_ent)) {
			sdbc_centry_hit++;
			old_ent->cc_toflush = 0;
			/* _sd_centry_release(cc_ent); */
			cc_ent = old_ent;
			categorize_centry = FOUND_IN_HASH_DM;
		} else {
			sdbc_centry_lost++;

			CLEAR_CENTRY_INUSE(old_ent);

			if (nowait) {
				cc_ent = NULL;
				goto out;
			}

			goto alloc_try;
		}
	}

	/*
	 * advance the dmchain pointer, but only if we got the
	 * cc_ent from the dmchain
	 */
	if (categorize_centry != FOUND_IN_HASH_DM) {
		if (cc_ent->cc_data)
			dmc->sab_dmchain = dmc->sab_dmchain->cc_next_dm;
		else
			dmc->sab_dmchain = dmc->sab_dmchain->cc_next;
	}


	SDTRACE(ST_EXIT|SDF_ENT_ALLOC, cd, 0, BLK_TO_FBA_NUM(cblk), 0, 0);

	mutex_enter(&cc_ent->cc_lock);
	if (cc_ent->cc_await_use) {
		cv_broadcast(&cc_ent->cc_blkcv);
	}
	mutex_exit(&cc_ent->cc_lock);

	sdbc_centry_init_dm(cc_ent);

	cc_ent->cc_aging_dm |= categorize_centry;

	out:

	SDTRACE(ST_INFO|SDF_ENT_ALLOC, cd, 0, BLK_TO_FBA_NUM(cblk), 0, 0);

	return (cc_ent);
}

/*
 * sdbc_centry_alloc_end -- tidy up after all cache blocks have been
 *	allocated for a request
 * ARGUMENTS:
 *	alloc_tok  - pointer to allocation token
 * RETURNS
 *	nothing
 * USAGE:
 *	at this time only useful when sdbc_use_dmchain is true.
 *	if there are cache blocks remaining on the chain then the inuse and
 *	pageio bits must be cleared (they were set in sdbc_get_dmchain().
 *
 */
static void
sdbc_centry_alloc_end(sdbc_allocbuf_t *alloc_tok)
{
	_sd_cctl_t *next_centry;
	_sd_cctl_t *prev_centry;
	_sd_queue_t *q;
	sdbc_allocbuf_impl_t *dmc = (sdbc_allocbuf_impl_t *)alloc_tok;
#ifdef DEBUG
	int chainpull = 0;
#endif

	if (!sdbc_use_dmchain)
		return;

	next_centry = dmc->sab_dmchain;

	while (next_centry != NULL) {
		CLEAR_CENTRY_PAGEIO(next_centry);

		prev_centry = next_centry;

		if (next_centry->cc_data) {
#ifdef DEBUG
			++chainpull;
#endif
			next_centry = next_centry->cc_next_dm;

			/* clear bit after final reference */

			CLEAR_CENTRY_INUSE(prev_centry);
		} else {
			next_centry = next_centry->cc_next;

			/*
			 * a floater from the 0 queue, insert on q.
			 *
			 * since this centry is not on any queue
			 * the inuse bit can be cleared before
			 * inserting on the q.  this is also required
			 * since sdbc_get_dmchain() does not expect
			 * inuse bits to be set on 0 queue entry's.
			 */

			CLEAR_CENTRY_INUSE(prev_centry);
			q = &sdbc_dm_queues[0];
			sdbc_ins_dmqueue_front(q, prev_centry);
		}
	}

#ifdef DEBUG
	/* compute wastage stats */
	ASSERT((chainpull >= 0) && (chainpull < max_dm_queues));
	if (chainpull)
		(*(dmchainpull_table + (dmc->sab_q *
		    max_dm_queues + chainpull)))++;
#endif

}


/*
 * sdbc_alloc_lru - allocate a new cache block from the lru queue
 *
 * ARGUMENTS:
 *	cd	- Cache descriptor (from a previous open)
 *	cblk	- cache block number.
 *	stall	- pointer to stall count (no blocks avail)
 *	flag	- lock status of sdbc_queue_lock or ALLOC_NOWAIT
 *
 * RETURNS:
 *	A cache block or NULL if ALLOC_NOWAIT specified
 *
 * USAGE:
 *	This routine allocates a new cache block from the lru.
 *	If an allocation cannot be done, we block, unless ALLOC_NOWAIT is set.
 */

static _sd_cctl_t *
sdbc_alloc_lru(int cd, nsc_off_t cblk, int *stall, int flag)
{
	_sd_cctl_t *cc_ent, *old_ent, *ccnext;
	_sd_queue_t *q = _SD_LRU_Q;
	_sd_cctl_t *qhead = &(q->sq_qhead);
	int tries = 0, num_tries;
	int categorize_centry;
	int locked = flag & ALLOC_LOCKED;
	int nowait = flag & ALLOC_NOWAIT;

	if (nowait) {
		num_tries = q->sq_inq / 100; /* only search 1% of q */

		if (num_tries <= 0) /* ensure num_tries is non-zero */
			num_tries = q->sq_inq;
	} else
		num_tries = _sd_lruq_srch;

	SDTRACE(ST_ENTER|SDF_ENT_ALLOC, cd, 0, BLK_TO_FBA_NUM(cblk), 0, 0);
retry_alloc_centry:

	for (cc_ent = (qhead->cc_next); cc_ent != qhead; cc_ent = ccnext) {
		if (--num_tries <= 0)
			if (nowait) {
				cc_ent = NULL;
				goto out;
			} else
				break;

		ccnext = cc_ent->cc_next;

		if (cc_ent->cc_aging_dm & BAD_CHAIN_DM)
			continue;

		if (CENTRY_DIRTY(cc_ent))
			continue;
		if (SET_CENTRY_INUSE(cc_ent))
			continue;

		if (CENTRY_DIRTY(cc_ent)) {
			sdbc_centry_lost++;

			CLEAR_CENTRY_INUSE(cc_ent);
			continue;
		}
		cc_ent->cc_flag = 0; /* CC_INUSE */
		cc_ent->cc_toflush = 0;

		/*
		 * Inlined requeue of the LRU. (should match _sd_requeue)
		 */
		/* was FAST */
		mutex_enter(&q->sq_qlock);
#if defined(_SD_DEBUG)
	if (1) {
		_sd_cctl_t *cp, *cn, *qp;
		cp = cc_ent->cc_prev;
		cn = cc_ent->cc_next;
		qp = (q->sq_qhead).cc_prev;
		if (!_sd_cctl_valid(cc_ent) ||
		    (cp != &(q->sq_qhead) && !_sd_cctl_valid(cp)) ||
		    (cn != &(q->sq_qhead) && !_sd_cctl_valid(cn)) ||
		    !_sd_cctl_valid(qp))
			cmn_err(CE_PANIC,
			    "_sd_centry_alloc %x prev %x next %x qp %x",
			    cc_ent, cp, cn, qp);
	}
#endif
		cc_ent->cc_prev->cc_next = cc_ent->cc_next;
		cc_ent->cc_next->cc_prev = cc_ent->cc_prev;
		cc_ent->cc_next = qhead;
		cc_ent->cc_prev = qhead->cc_prev;
		qhead->cc_prev->cc_next = cc_ent;
		qhead->cc_prev = cc_ent;
		cc_ent->cc_seq = q->sq_seq++;
		/* was FAST */
		mutex_exit(&q->sq_qlock);
		/*
		 * End inlined requeue.
		 */

#if defined(_SD_STATS)
		if (_sd_hash_delete(cc_ent, _sd_htable) == 0)
			SDTRACE(SDF_REPLACE,
			    CENTRY_CD(cc_ent), cc_ent->cc_hits,
			    BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
			    nsc_lbolt(), cc_ent->cc_creat);
		cc_ent->cc_creat = nsc_lbolt();
		cc_ent->cc_hits = 0;
#else
#if defined(_SD_DEBUG)
		if (_sd_hash_delete(cc_ent, _sd_htable) == 0) {
			SDTRACE(SDF_REPLACE|ST_DL,
			    CENTRY_CD(cc_ent),
			    cc_ent->cc_valid,
			    BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
			    cd, BLK_TO_FBA_NUM(cblk));
			if (cc_ent->cc_await_use ||
			    ((cd == CENTRY_CD(cc_ent)) &&
			    (cblk == CENTRY_BLK(cc_ent))))
				DATA_LOG(SDF_REPLACE|ST_DL, cc_ent, 0,
				    BLK_FBAS);
		}
#else
		(void) _sd_hash_delete((struct _sd_hash_hd *)cc_ent,
		    _sd_htable);
#endif
#endif
		cc_ent->cc_creat = nsc_lbolt();
		cc_ent->cc_hits = 0;

		cc_ent->cc_valid = 0;
		categorize_centry = 0;
		if (cc_ent->cc_data)
			categorize_centry = FOUND_HOLD_OVER_DM;

	alloc_try:
		if (cd == _CD_NOHASH)
			CENTRY_BLK(cc_ent) = cblk;
		else if ((old_ent = (_sd_cctl_t *)
		    _sd_hash_insert(cd, cblk, (struct _sd_hash_hd *)cc_ent,
		    _sd_htable)) != cc_ent) {

			if (SET_CENTRY_INUSE(old_ent)) {
				sdbc_centry_inuse++;

				if (nowait) {
					_sd_centry_release(cc_ent);
					cc_ent = NULL;
					goto out;
				}

				if (locked)
					rw_exit(&sdbc_queue_lock);
				_sd_cc_wait(cd, cblk, old_ent, CC_INUSE);
				if (locked)
					rw_enter(&sdbc_queue_lock, RW_WRITER);
				goto alloc_try;
			}

			/*
			 * bug 4529671
			 * now that we own the centry make sure that
			 * it is still good. it could have been processed
			 * by _sd_dealloc_dm() in the window between
			 * _sd_hash_insert() and SET_CENTRY_INUSE().
			 */
			if ((_sd_cctl_t *)
			    _sd_hash_search(cd, cblk, _sd_htable) != old_ent) {
				sdbc_centry_deallocd++;
#ifdef DEBUG
				cmn_err(CE_WARN, "!cc_ent %p cd %d cblk %"
				    NSC_SZFMT " lost to dealloc?! cc_data %p",
				    (void *)old_ent, cd, cblk,
				    (void *)old_ent->cc_data);
#endif

				CLEAR_CENTRY_INUSE(old_ent);

				if (nowait) {
					_sd_centry_release(cc_ent);
					cc_ent = NULL;
					goto out;
				}

				goto alloc_try;
			}

			if (CC_CD_BLK_MATCH(cd, cblk, old_ent)) {
				sdbc_centry_hit++;
				old_ent->cc_toflush = 0;
				_sd_centry_release(cc_ent);
				cc_ent = old_ent;
				categorize_centry = FOUND_IN_HASH_DM;
			} else {
				sdbc_centry_lost++;

				CLEAR_CENTRY_INUSE(old_ent);

				if (nowait) {
					_sd_centry_release(cc_ent);
					cc_ent = NULL;
					goto out;
				}

				goto alloc_try;
			}
		}

		SDTRACE(ST_EXIT|SDF_ENT_ALLOC, cd, tries,
		    BLK_TO_FBA_NUM(cblk), 0, 0);

		if (cc_ent->cc_await_use) {
			mutex_enter(&cc_ent->cc_lock);
			cv_broadcast(&cc_ent->cc_blkcv);
			mutex_exit(&cc_ent->cc_lock);
		}

		sdbc_centry_init_dm(cc_ent);

		cc_ent->cc_aging_dm |= categorize_centry;

	out:
		return (cc_ent);
	}

	SDTRACE(ST_INFO|SDF_ENT_ALLOC, cd, ++tries, BLK_TO_FBA_NUM(cblk), 0, 0);

	delay(drv_usectohz(20000));
	(void) (*stall)++;
	num_tries = _sd_lruq_srch;
	goto retry_alloc_centry;
}

/*
 * sdbc_centry_init_dm - setup the cache block for dynamic memory allocation
 *
 * ARGUMENTS:
 *	centry	 - Cache block.
 *
 * RETURNS:
 *	NONE
 *
 * USAGE:
 *	This routine is the central point in which cache entry blocks are setup
 */
static void
sdbc_centry_init_dm(_sd_cctl_t *centry)
{

	/* an entry already setup - don't touch simply refresh age */
	if (centry->cc_data) {
		centry->cc_aging_dm &= ~(FINAL_AGING_DM);

		DTRACE_PROBE1(sdbc_centry_init_dm_end,
		    char *, centry->cc_data);
		return;
	}

	centry->cc_aging_dm &= ~(FINAL_AGING_DM | CATAGORY_ENTRY_DM);

	if (centry->cc_head_dm || centry->cc_next_dm)
		cmn_err(cmn_level, "!sdbc(sdbc_centry_init_dm): "
		    "non-zero mem chain in ccent %p", (void *)centry);

	centry->cc_head_dm = 0;

	if (!sdbc_use_dmchain)
		centry->cc_next_dm = 0;

	centry->cc_data = 0;

}

/*
 * sdbc_centry_memalloc_dm
 *
 * Actually allocate the cache memory, storing it in the cc_data field for
 * the cctl
 *
 * ARGS:
 *	centry: cache control block for which to allocate the memory
 *	alloc_request: number of bytes to allocate
 *	flag: if called with ALLOC_NOWAIT, caller must check for non-zero return
 *
 * RETURNS:
 *	0 on success
 *	non-zero on error
 */
static int
sdbc_centry_memalloc_dm(_sd_cctl_t *centry, int alloc_request, int flag)
{
	int cblocks;
	_sd_queue_t *newq;
	int sleep;
	sleep = (flag & ALLOC_NOWAIT) ? KM_NOSLEEP : KM_SLEEP;

	if (!centry->cc_data && (alloc_request > 0)) {
		/* host or other */
		dynmem_processing_dm.alloc_ct++;
		centry->cc_data = (unsigned char *)
		    kmem_alloc((size_t)centry->cc_alloc_size_dm, sleep);


		if (sdbc_use_dmchain) {
			cblocks = centry->cc_alloc_size_dm >> _sd_cblock_shift;
			newq = &sdbc_dm_queues[cblocks];

			/* set the dmqueue index */
			centry->cc_cblocks = cblocks;

			/* put on appropriate queue */
			sdbc_ins_dmqueue_back(newq, centry);
		}

		/*
		 * for KM_NOSLEEP (should never happen with KM_SLEEP)
		 */
		if (!centry->cc_data)
			return (LOW_RESOURCES_DM);
		centry->cc_head_dm = centry;
		centry->cc_alloc_ct_dm++;
	}

	return (0);
}

/*
 * _sd_centry_release - release a cache block
 *
 * ARGUMENTS:
 *	centry	 - Cache block.
 *
 * RETURNS:
 *	NONE
 *
 * USAGE:
 *	This routine frees up a cache block. It also frees up a write
 *	block if allocated and its valid to release it.
 */

void
_sd_centry_release(_sd_cctl_t *centry)
{
	ss_centry_info_t *wctl;

	SDTRACE(ST_ENTER|SDF_ENT_FREE, CENTRY_CD(centry), 0,
	    BLK_TO_FBA_NUM(CENTRY_BLK(centry)), 0, 0);

	CLEAR_CENTRY_PAGEIO(centry);

	if ((wctl = centry->cc_write) != 0) {
		/* was FAST */
		mutex_enter(&centry->cc_lock);
		if (CENTRY_DIRTY(centry))
			wctl = NULL;
		else {
			centry->cc_write = NULL;
			centry->cc_flag &= ~(CC_PINNABLE);
		}
		/* was FAST */
		mutex_exit(&centry->cc_lock);
		if (wctl)  {
			wctl->sc_dirty = 0;
			SSOP_SETCENTRY(sdbc_safestore, wctl);
			SSOP_DEALLOCRESOURCE(sdbc_safestore, wctl->sc_res);
		}
	}

	if (!(centry->cc_aging_dm & BAD_CHAIN_DM)) {
		if (sdbc_use_dmchain) {
			if (centry->cc_alloc_size_dm) {

				/* see if this can be queued to head */
				if (CENTRY_QHEAD(centry)) {
					sdbc_requeue_head_dm_try(centry);
				} else {
					int qidx;
					_sd_queue_t *q;

					qidx = centry->cc_cblocks;
					q = &sdbc_dm_queues[qidx];

					if (_sd_lru_reinsert(q, centry)) {
						sdbc_requeue_dmchain(q,
						    centry, 1, 1);
					}
				}
			} else {
				/*
				 * Fix for bug 4949134:
				 * If an internal block is marked with CC_QHEAD
				 * but the HOST block is not, the chain will
				 * never age properly, and will never be made
				 * available.  Only the HOST of the dmchain is
				 * checked for CC_QHEAD, so clearing an internal
				 * block indiscriminately (as is being done
				 * here) does no damage.
				 *
				 * The same result could instead be achieved by
				 * not setting the CC_QHEAD flag in the first
				 * place, if the block is an internal dmchain
				 * block, and if it is found in the hash table.
				 * The current solution was chosen since it is
				 * the least intrusive.
				 */
				centry->cc_flag &= ~CC_QHEAD;
			}
		} else {
			if (CENTRY_QHEAD(centry)) {
				if (!CENTRY_DIRTY(centry))
					_sd_requeue_head(centry);
			} else if (_sd_lru_reinsert(_SD_LRU_Q, centry))
				_sd_requeue(centry);
		}
	}

	SDTRACE(ST_EXIT|SDF_ENT_FREE, CENTRY_CD(centry), 0,
	    BLK_TO_FBA_NUM(CENTRY_BLK(centry)), 0, 0);

	/* only clear inuse after final reference to centry */

	CLEAR_CENTRY_INUSE(centry);
}


/*
 * lookup to centry info associated with safestore resource
 * return pointer to the centry info structure
 */
ss_centry_info_t *
sdbc_get_cinfo_byres(ss_resource_t *res)
{
	ss_centry_info_t *cinfo;
	ss_centry_info_t *cend;
	int found = 0;

	ASSERT(res != NULL);

	if (res == NULL)
		return (NULL);

	cinfo = _sdbc_gl_centry_info;
	cend = _sdbc_gl_centry_info +
	    (_sdbc_gl_centry_info_size / sizeof (ss_centry_info_t)) - 1;

	for (; cinfo <= cend; ++cinfo)
		if (cinfo->sc_res == res) {
			++found;
			break;
		}

	if (!found)
		cinfo = NULL; /* bad */

	return (cinfo);
}

/*
 * _sd_alloc_write - Allocate a write block (for remote mirroring)
 *		   and set centry->cc_write
 *
 * ARGUMENTS:
 *	centry	 - Head of Cache chain
 *	stall	 - pointer to stall count (no blocks avail)
 *
 * RETURNS:
 *	0 - and sets  cc_write for all entries when write contl block obtained.
 *	-1 - if a write control block could not be obtained.
 */

int
_sd_alloc_write(_sd_cctl_t *centry, int *stall)
{

	ss_resourcelist_t *reslist;
	ss_resourcelist_t *savereslist;
	ss_resource_t *res;
	_sd_cctl_t *ce;
	int err;
	int need;


	need = 0;

	for (ce = centry; ce; ce = ce->cc_chain) {
		if (!(ce->cc_write))
			need++;
	}

	if (!need)
		return (0);

	if ((SSOP_ALLOCRESOURCE(sdbc_safestore, need, stall, &reslist))
	    == SS_OK) {
		savereslist = reslist;
		for (ce = centry; ce; ce = ce->cc_chain) {
			if (ce->cc_write)
				continue;
			err = SSOP_GETRESOURCE(sdbc_safestore, &reslist, &res);
			if (err == SS_OK)
				ce->cc_write = sdbc_get_cinfo_byres(res);

			ASSERT(err == SS_OK); /* panic if DEBUG on */
			ASSERT(ce->cc_write != NULL);

			/*
			 * this is bad and should not happen.
			 * we use the saved reslist to cleanup
			 * and return.
			 */
			if ((err != SS_OK) || !ce->cc_write) {

				cmn_err(CE_WARN, "!_sd_alloc_write: "
				    "bad resource list 0x%p"
				    "changing to forced write thru mode",
				    (void *)savereslist);

				(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);

				while (SSOP_GETRESOURCE(sdbc_safestore,
				    &savereslist, &res) == SS_OK) {

					SSOP_DEALLOCRESOURCE(sdbc_safestore,
					    res);
				}

				return (-1);

			}

		}
		return (0);
	}

	/* no safestore resources available.  do sync write */
	_sd_unblock(&_sd_flush_cv);
	return (-1);
}

/*
 * _sd_read - Interface call to do read.
 *
 * ARGUMENTS:
 *	handle  - handle allocated earlier on.
 *	fba_pos - disk block number to read from.
 *	fba_len - length in fbas.
 *	flag	- flag: (NSC_NOBLOCK for async io)
 *
 * RETURNS:
 *	errno if return > 0
 *	NSC_DONE or NSC_PENDING otherwise.
 *
 * USAGE:
 *	This routine checks if the request is valid and calls the underlying
 *	doread routine (also called by alloc_buf)
 */

int
_sd_read(_sd_buf_handle_t *handle, nsc_off_t fba_pos, nsc_size_t fba_len,
    int flag)
{
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	_sd_cctl_t *cc_ent = NULL;
	nsc_size_t fba_orig_len = fba_len;
	int ret;
	int cd = HANDLE_CD(handle);

	if (_sdbc_shutdown_in_progress || (handle->bh_flag & NSC_ABUF)) {
		ret = EIO;
		goto out;
	}


#if !defined(_SD_NOCHECKS)
	if (!_SD_HANDLE_ACTIVE(handle)) {
		cmn_err(CE_WARN, "!sdbc(_sd_read) handle %p not active",
		    (void *)handle);
		ret = EINVAL;
		goto out;
	}
	ASSERT_HANDLE_LIMITS(handle, fba_pos, fba_len);
#endif
	if (fba_len == 0) {
		ret = NSC_DONE;
		goto out;
	}

	KSTAT_RUNQ_ENTER(cd);

	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = BLK_FBAS - st_cblk_off;
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else {
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);
	}

	cc_ent = handle->bh_centry;
	while (CENTRY_BLK(cc_ent) != FBA_TO_BLK_NUM(fba_pos))
		cc_ent = cc_ent->cc_chain;

	if (!SDBC_VALID_BITS(st_cblk_off, st_cblk_len, cc_ent))
		goto need_io;
	DATA_LOG(SDF_RD, cc_ent, st_cblk_off, st_cblk_len);

	DTRACE_PROBE4(_sd_read_data1, uint64_t,
	    (uint64_t)(BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)) + st_cblk_off),
	    uint64_t, (uint64_t)st_cblk_len, char *,
	    *(int64_t *)(cc_ent->cc_data + FBA_SIZE(st_cblk_off)),
	    char *, *(int64_t *)(cc_ent->cc_data +
	    FBA_SIZE(st_cblk_off + st_cblk_len) - 8));

	fba_pos += st_cblk_len;
	fba_len -= st_cblk_len;
	cc_ent = cc_ent->cc_chain;

	while (fba_len > (nsc_size_t)end_cblk_len) {
		if (!FULLY_VALID(cc_ent))
			goto need_io;
		DATA_LOG(SDF_RD, cc_ent, 0, BLK_FBAS);

		DTRACE_PROBE4(_sd_read_data2, uint64_t,
		    (uint64_t)BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
		    uint64_t, (uint64_t)BLK_FBAS,
		    char *, *(int64_t *)(cc_ent->cc_data),
		    char *, *(int64_t *)(cc_ent->cc_data +
		    FBA_SIZE(BLK_FBAS) - 8));

		fba_pos += BLK_FBAS;
		fba_len -= BLK_FBAS;
		cc_ent = cc_ent->cc_chain;
	}
	if (fba_len) {
		if (!SDBC_VALID_BITS(0, end_cblk_len, cc_ent))
			goto need_io;
		DATA_LOG(SDF_RD, cc_ent, 0, end_cblk_len);

		DTRACE_PROBE4(_sd_read_data3, uint64_t,
		    (uint64_t)BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
		    uint64_t, (uint64_t)end_cblk_len,
		    char *, *(int64_t *)(cc_ent->cc_data),
		    char *, *(int64_t *)(cc_ent->cc_data +
		    FBA_SIZE(end_cblk_len) - 8));
	}

	CACHE_FBA_READ(handle->bh_cd, fba_orig_len);
	CACHE_READ_HIT;

	FBA_READ_IO_KSTATS(handle->bh_cd, FBA_SIZE(fba_orig_len));

	ret = NSC_HIT;
	goto stats_exit;
need_io:
	_SD_DISCONNECT_CALLBACK(handle);

	ret = _sd_doread(handle, cc_ent, fba_pos, fba_len, flag);

stats_exit:
	KSTAT_RUNQ_EXIT(cd);
out:
	return (ret);
}


/*
 * sdbc_doread_prefetch - read ahead one cache block
 *
 * ARGUMENTS:
 *	cc_ent - cache entry
 *	fba_pos - disk block number to read from
 *	fba_len - length in fbas.
 *
 * RETURNS:
 *	number of fbas, if any, that are to be read beyond (fba_pos + fba_len)
 *
 * USAGE:
 *	if readahead is to be done allocate a cache block and place
 *	on the cc_chain of cc_ent
 */
static int
sdbc_doread_prefetch(_sd_cctl_t *cc_ent, nsc_off_t fba_pos, nsc_size_t fba_len)
{
	nsc_off_t st_cblk = FBA_TO_BLK_NUM(fba_pos);
	nsc_off_t next_cblk = FBA_TO_BLK_NUM(fba_pos + BLK_FBAS);
	nsc_size_t filesize;
	int fba_count = 0; /* number of fbas to prefetch */
	_sd_cctl_t *cc_ra; /* the read ahead cache entry */
	int cd = CENTRY_CD(cc_ent);
	nsc_size_t vol_fill;

	filesize = _sd_cache_files[cd].cd_info->sh_filesize;
	vol_fill = filesize - (fba_pos + fba_len);

	/* readahead only for small reads */
	if ((fba_len <= FBA_LEN(CACHE_BLOCK_SIZE)) && (fba_pos != 0) &&
	    (vol_fill > 0)) {

		/*
		 * if prev block is in cache and next block is not,
		 * then read ahead one block
		 */
		if (_sd_hash_search(cd, st_cblk - 1, _sd_htable)) {
			if (!_sd_hash_search(cd, next_cblk, _sd_htable)) {

				cc_ra = sdbc_centry_alloc_blks
				    (cd, next_cblk, 1, ALLOC_NOWAIT);
				if (cc_ra) {
					/* if in cache don't readahead */
					if (cc_ra->cc_aging_dm &
					    HASH_ENTRY_DM) {
						++sdbc_ra_hash;
						_sd_centry_release(cc_ra);
					} else {
						cc_ent->cc_chain = cc_ra;
						cc_ra->cc_chain = 0;
						fba_count =
						    (vol_fill >
						    (nsc_size_t)BLK_FBAS) ?
						    BLK_FBAS : (int)vol_fill;
						/*
						 * indicate implicit prefetch
						 * and mark for release in
						 * _sd_read_complete()
						 */
						cc_ra->cc_aging_dm |=
						    (PREFETCH_BUF_I |
						    PREFETCH_BUF_IR);
					}
				} else {
					++sdbc_ra_none;
				}
			}
		}

	}

	return (fba_count);
}

/*
 * _sd_doread - Check if blocks in cache. If not completely true, do io.
 *
 * ARGUMENTS:
 *	handle  - handle allocated earlier on.
 *	fba_pos - disk block number to read from.
 *	fba_len - length in fbas.
 *	flag	- flag: (NSC_NOBLOCK for async io)
 *
 * RETURNS:
 *	errno if return > 0
 *	NSC_DONE(from disk), or NSC_PENDING otherwise.
 *
 * Comments:
 *	It initiates an io and either blocks waiting for the completion
 *	or return NSC_PENDING, depending on whether the flag bit
 *	NSC_NOBLOCK is reset or set.
 *
 */


static int
_sd_doread(_sd_buf_handle_t *handle, _sd_cctl_t *cc_ent, nsc_off_t fba_pos,
    nsc_size_t fba_len, int flag)
{
	int cd, err;
	nsc_size_t fba_orig_len; /* length in FBA's of the original request */
	nsc_size_t file_len;	/* length in bytes of io to be done */
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	int num_bdl;
	_sd_cctl_t *cc_temp;
	struct buf *bp;
	unsigned int want_bits;
	void (*fn)(blind_t, nsc_off_t, nsc_size_t, int);
	sdbc_cblk_fba_t end_cblk_fill;	/* FBA's to fill to end of last block */
	nsc_size_t vol_end_fill; /* # of FBA's to fill to end of the volume */

	cd = HANDLE_CD(handle);
	SDTRACE(ST_ENTER|SDF_READ, cd, fba_len, fba_pos, flag, 0);

	ASSERT(cd >= 0);
	if (_sd_cache_files[cd].cd_info->sh_failed) {
		SDTRACE(ST_EXIT|SDF_READ, cd, fba_len, fba_pos, flag, EIO);
		return (EIO);
	}

	/*
	 * adjust the position and length so that the entire cache
	 * block is read in
	 */

	/* first, adjust to beginning of cache block */

	fba_len += BLK_FBA_OFF(fba_pos); /* add start offset to length */
	fba_pos &= ~BLK_FBA_MASK; /* move position back to start of block */

	/* compute fill to end of cache block */
	end_cblk_fill = (BLK_FBAS - 1) - ((fba_len - 1) % BLK_FBAS);
	vol_end_fill = _sd_cache_files[(cd)].cd_info->sh_filesize -
	    (fba_pos + fba_len);

	/* fill to lesser of cache block or end of volume */
	fba_len += ((nsc_size_t)end_cblk_fill < vol_end_fill) ? end_cblk_fill :
	    vol_end_fill;

	DTRACE_PROBE2(_sd_doread_rfill, nsc_off_t, fba_pos,
	    nsc_size_t, fba_len);


	/* for small reads do 1-block readahead if previous block is in cache */
	if (sdbc_prefetch1)
		fba_len += sdbc_doread_prefetch(cc_ent, fba_pos, fba_len);

	fba_orig_len = fba_len;
	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = BLK_FBAS - st_cblk_off;
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else {
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);
	}

	cc_temp = cc_ent;
	num_bdl = 0;
	while (cc_temp)	{
		num_bdl += (SDBC_LOOKUP_IOCOUNT(CENTRY_DIRTY(cc_temp)));
		cc_temp = cc_temp->cc_chain;
	}
	bp = sd_alloc_iob(_sd_cache_files[cd].cd_crdev,
	    fba_pos, num_bdl, B_READ);
	if (bp == NULL) {
		SDTRACE(ST_EXIT|SDF_READ, cd, fba_len, fba_pos, flag, E2BIG);
		return (E2BIG);
	}

	want_bits = SDBC_GET_BITS(st_cblk_off, st_cblk_len);
	if (want_bits & CENTRY_DIRTY(cc_ent))
		_sd_ccent_rd(cc_ent, want_bits, bp);
	else {
		sd_add_fba(bp, &cc_ent->cc_addr, st_cblk_off, st_cblk_len);
	}
	file_len = FBA_SIZE(st_cblk_len);
	cc_ent = cc_ent->cc_chain;
	fba_len -= st_cblk_len;

	while (fba_len > (nsc_size_t)end_cblk_len) {
		if (CENTRY_DIRTY(cc_ent))
			_sd_ccent_rd(cc_ent, (uint_t)BLK_FBA_BITS, bp);
		else {
			sd_add_fba(bp, &cc_ent->cc_addr, 0, BLK_FBAS);
		}
		file_len += CACHE_BLOCK_SIZE;
		cc_ent = cc_ent->cc_chain;
		fba_len -= BLK_FBAS;
	}

	if (fba_len) {
		want_bits = SDBC_GET_BITS(0, end_cblk_len);
		if (want_bits & CENTRY_DIRTY(cc_ent))
			_sd_ccent_rd(cc_ent, want_bits, bp);
		else {
			sd_add_fba(bp, &cc_ent->cc_addr, 0, end_cblk_len);
		}
		file_len += FBA_SIZE(end_cblk_len);
	}

	CACHE_READ_MISS;
	FBA_READ_IO_KSTATS(cd, file_len);

	DISK_FBA_READ(cd, FBA_NUM(file_len));

	fn = (handle->bh_flag & NSC_NOBLOCK) ? _sd_async_read_ea : NULL;
	err = sd_start_io(bp, _sd_cache_files[cd].cd_strategy, fn, handle);

	if (err != NSC_PENDING) {
		_sd_read_complete(handle, fba_pos, fba_orig_len, err);
	}

	SDTRACE(ST_EXIT|SDF_READ, cd, fba_orig_len, fba_pos, flag, err);

	return (err);
}



/*
 * _sd_read_complete - Do whatever is necessary after a read io is done.
 *
 * ARGUMENTS:
 *	handle  - handle allocated earlier on.
 *	fba_pos - disk block number to read from.
 *	fba_len - length in fbas.
 *	error   - error from io if any.
 *
 * RETURNS:
 *	NONE.
 *
 * Comments:
 *	This routine marks the cache blocks valid if the io completed
 *	sucessfully. Called from the async end action as well as after
 * 	a synchrnous read completes.
 */

void
_sd_read_complete(_sd_buf_handle_t *handle, nsc_off_t fba_pos,
    nsc_size_t fba_len, int error)
{
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_size_t cur_fba_len; /* length in FBA's */
	_sd_cctl_t *cc_iocent;
	_sd_cctl_t *first_iocent; /* first buffer when processing prefetch */

	cc_iocent = handle->bh_centry;

	if ((handle->bh_error = error) == 0) {
		while (CENTRY_BLK(cc_iocent) != FBA_TO_BLK_NUM(fba_pos))
			cc_iocent = cc_iocent->cc_chain;

		cur_fba_len = fba_len;
		st_cblk_off = BLK_FBA_OFF(fba_pos);
		st_cblk_len = BLK_FBAS - st_cblk_off;
		if ((nsc_size_t)st_cblk_len >= fba_len) {
			end_cblk_len = 0;
			st_cblk_len = (sdbc_cblk_fba_t)fba_len;
		} else {
			end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);
		}

		SDBC_SET_VALID_BITS(st_cblk_off, st_cblk_len, cc_iocent);
		DATA_LOG(SDF_RDIO, cc_iocent, st_cblk_off, st_cblk_len);

		DTRACE_PROBE4(_sd_read_complete_data1, uint64_t, (uint64_t)
		    BLK_TO_FBA_NUM(CENTRY_BLK(cc_iocent)) + st_cblk_off,
		    int, st_cblk_len, char *,
		    *(int64_t *)(cc_iocent->cc_data + FBA_SIZE(st_cblk_off)),
		    char *, *(int64_t *)(cc_iocent->cc_data +
		    FBA_SIZE(st_cblk_off + st_cblk_len) - 8));


		first_iocent = cc_iocent;
		cc_iocent = cc_iocent->cc_chain;
		cur_fba_len -= st_cblk_len;

		while (cur_fba_len > (nsc_size_t)end_cblk_len) {
			SET_FULLY_VALID(cc_iocent);
			DATA_LOG(SDF_RDIO, cc_iocent, 0, BLK_FBAS);

			DTRACE_PROBE4(_sd_read_complete_data2, uint64_t,
			    (uint64_t)BLK_TO_FBA_NUM(CENTRY_BLK(cc_iocent)),
			    int, BLK_FBAS, char *,
			    *(int64_t *)(cc_iocent->cc_data), char *,
			    *(int64_t *)(cc_iocent->cc_data +
			    FBA_SIZE(BLK_FBAS) - 8));

			/*
			 * 4755485 release implicit prefetch buffers
			 *
			 * the cc_chain of the first buffer must NULL'd
			 * else _sd_free_buf() will do a double free when
			 * it traverses the chain.
			 *
			 * if a buffer has been marked PREFETCH_BUF_IR then
			 * it is guaranteed that
			 *    1. it is the second in a chain of two.
			 *    2. cur_fba_len is BLK_FBAS.
			 *    3. end_cblk_len is zero.
			 *
			 * because of 1 (and 2) above, we can safely exit the
			 * while loop via the break statement without
			 * executing the last two statements.  the break
			 * statement is necessary because it would be unsafe
			 * to access cc_iocent which could be reallocated
			 * immediately after the _sd_centry_release().
			 */
			if (cc_iocent->cc_aging_dm & PREFETCH_BUF_IR) {
				cc_iocent->cc_aging_dm &= ~(PREFETCH_BUF_IR);
				_sd_centry_release(cc_iocent);
				first_iocent->cc_chain = NULL;
				break;
			}

			cc_iocent = cc_iocent->cc_chain;
			cur_fba_len -= BLK_FBAS;
		}
		if (end_cblk_len) {
			SDBC_SET_VALID_BITS(0, end_cblk_len, cc_iocent);
			DATA_LOG(SDF_RDIO, cc_iocent, 0, end_cblk_len);

			DTRACE_PROBE4(_sd_read_complete_data3, uint64_t,
			    (uint64_t)BLK_TO_FBA_NUM(CENTRY_BLK(cc_iocent)),
			    int, end_cblk_len, char *,
			    *(int64_t *)(cc_iocent->cc_data), char *,
			    *(int64_t *)(cc_iocent->cc_data +
			    FBA_SIZE(end_cblk_len) - 8));
		}
	}

}


/*
 * _sd_async_read_ea - End action for async reads.
 *
 * ARGUMENTS:
 *	xhandle  - handle allocated earlier on (cast to blind_t).
 *	fba_pos - disk block number read from.
 *	fba_len - length in fbas.
 *	error   - error from io if any.
 *
 * RETURNS:
 *	NONE.
 *
 * Comments:
 *	This routine is called at interrupt level when the io is done.
 *	This is called only when read is asynchronous (NSC_NOBLOCK)
 */

static void
_sd_async_read_ea(blind_t xhandle, nsc_off_t fba_pos, nsc_size_t fba_len,
    int error)
{
	_sd_buf_handle_t *handle = xhandle;
	int cd;

	if (error) {
		cd = HANDLE_CD(handle);
		ASSERT(cd >= 0);
		_sd_cache_files[cd].cd_info->sh_failed = 1;
	}
	SDTRACE(ST_ENTER|SDF_READ_EA, HANDLE_CD(handle),
	    handle->bh_fba_len, handle->bh_fba_pos, 0, error);

	_sd_read_complete(handle, fba_pos, fba_len, error);

#if defined(_SD_DEBUG_PATTERN)
	check_buf_consistency(handle, "rd");
#endif

	SDTRACE(ST_EXIT|SDF_READ_EA, HANDLE_CD(handle),
	    handle->bh_fba_len, handle->bh_fba_pos, 0, 0);
	_SD_READ_CALLBACK(handle);
}


/*
 * _sd_async_write_ea - End action for async writes.
 *
 * ARGUMENTS:
 *	xhandle  - handle allocated earlier on. (cast to blind_t)
 *	fba_pos - disk block number written to.
 *	fba_len - length in fbas.
 *	error   - error from io if any.
 *
 * RETURNS:
 *	NONE.
 *
 * Comments:
 *	This routine is called at interrupt level when the write io is done.
 *	This is called only when we are in write-through mode and the write
 *	call indicated asynchronous callback. (NSC_NOBLOCK)
 */

/* ARGSUSED */

static void
_sd_async_write_ea(blind_t xhandle, nsc_off_t fba_pos, nsc_size_t fba_len,
    int error)
{
	_sd_buf_handle_t *handle = xhandle;
	handle->bh_error = error;

	if (error)
		_sd_cache_files[HANDLE_CD(handle)].cd_info->sh_failed = 1;

	_SD_WRITE_CALLBACK(handle);
}

/*
 * update_dirty - set dirty bits in cache block which is already dirty
 *	cc_inuse is held, need cc_lock to avoid race with _sd_process_pending
 *	must check for I/O in-progress and set PEND_DIRTY.
 *	return previous dirty bits
 *	[if set _sd_process_pending will re-issue]
 */
static _sd_bitmap_t
update_dirty(_sd_cctl_t *cc_ent, sdbc_cblk_fba_t st_off, sdbc_cblk_fba_t st_len)
{
	_sd_bitmap_t old;

	/* was FAST */
	mutex_enter(&cc_ent->cc_lock);
	old = CENTRY_DIRTY(cc_ent);
	if (old) {
		/*
		 * If we are writing to an FBA that is still marked dirty,
		 * record a write cancellation.
		 */
		if (old & SDBC_GET_BITS(st_off, st_len)) {
			CACHE_WRITE_CANCELLATION(CENTRY_CD(cc_ent));
		}

		/* This is a write to a block that was already dirty */
		SDBC_SET_DIRTY(st_off, st_len, cc_ent);
		sd_serialize();
		if (CENTRY_IO_INPROGRESS(cc_ent))
			cc_ent->cc_flag |= CC_PEND_DIRTY;
	}
	/* was FAST */
	mutex_exit(&cc_ent->cc_lock);
	return (old);
}

/*
 * _sd_write - Interface call to commit part of handle.
 *
 * ARGUMENTS:
 *	handle  - handle allocated earlier o.
 *	fba_pos - disk block number to write to.
 *	fba_len - length in fbas.
 *	flag    - (NSC_NOBLOCK | NSC_WRTHRU)
 *
 * RETURNS:
 *	errno if return > 0
 *	NSC_HIT (in cache), NSC_DONE (to disk) or NSC_PENDING otherwise.
 *
 * Comments:
 *	This routine checks validity of the handle and then calls the
 *	sync-write function if this write is determined to be write-through.
 *	Else, it reflects the data to the write blocks on the mirror node,
 *	(allocated in alloc_buf). If the cache block is not dirty, it is
 *	marked dirty and queued up for io processing later on.
 *	If parts are already dirty but io is not in progress yet, it is
 *	marked dirty and left alone (it is already in the queue)
 *	If parts are already dirty but io is in progress, it is marked
 *	dirty and also a flag is set indicating that this buffer should
 *	be reprocessed after the io-end-action.
 *	Attempt is made to coalesce multiple writes into a single list
 *	for io processing later on.
 *
 *	Issuing of writes may be delayed until the handle is released;
 *	_sd_queue_write() sets NSC_QUEUE, indicating that dirty bits
 *	and reflection to mirror have already been done, just queue I/O.
 */



int
_sd_write(_sd_buf_handle_t *handle, nsc_off_t fba_pos, nsc_size_t fba_len,
    int flag)
{
	int cd = HANDLE_CD(handle);
	int num_queued, ret, queue_only, store_only;
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_size_t cur_fba_len;	/* position in disk blocks */
	_sd_cctl_t *cc_ent = NULL;
	_sd_cctl_t *cur_chain = NULL, *dirty_next = NULL;


	if (_sdbc_shutdown_in_progress) {
		ret = EIO;
		goto out;
	}


	if (!_SD_HANDLE_ACTIVE(handle)) {
		SDALERT(SDF_WRITE,
		    SDT_INV_CD, 0, SDT_INV_BL, handle->bh_flag, 0);
		ret = EINVAL;
		goto out;
	}
#if !defined(_SD_NOCHECKS)
	ASSERT_HANDLE_LIMITS(handle, fba_pos, fba_len);
	if ((handle->bh_flag & NSC_WRBUF) == 0) {
		ret = EINVAL;
		goto out;
	}
#endif
	if (fba_len == 0) {
		ret = NSC_DONE;
		goto out;
	}

	/*
	 * store_only: don't queue this I/O yet
	 * queue_only: queue I/O to disk, don't store in mirror node
	 */
	if (flag & NSC_QUEUE)
		queue_only = 1, store_only = 0;
	else
		if (_SD_DELAY_QUEUE && (fba_len != handle->bh_fba_len))
			queue_only = 0, store_only = 1;
	else
		queue_only = store_only = 0;

	if (!queue_only && _SD_FORCE_DISCONNECT(fba_len))
		_SD_DISCONNECT_CALLBACK(handle);

	if (_sd_cache_files[cd].cd_info->sh_failed) {
		ret = EIO;
		goto out;
	}

	KSTAT_RUNQ_ENTER(cd);

	SDTRACE(ST_ENTER|SDF_WRITE, cd, fba_len, fba_pos, flag, 0);

#if defined(_SD_DEBUG_PATTERN)
	check_buf_consistency(handle, "wr");
#endif

	cc_ent = handle->bh_centry;

	while (CENTRY_BLK(cc_ent) != FBA_TO_BLK_NUM(fba_pos))
		cc_ent = cc_ent->cc_chain;

	if (((handle->bh_flag | flag) & _SD_WRTHRU_MASK) ||
	    (!queue_only && _sd_remote_store(cc_ent, fba_pos, fba_len))) {
		flag |= NSC_WRTHRU;

		ret = _sd_sync_write(handle, fba_pos, fba_len, flag);
		goto stats_exit;
	}

	if (store_only)		/* enqueue in _sd_free_buf() */
		handle->bh_flag |= NSC_QUEUE;
	cur_fba_len = fba_len;
	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = BLK_FBAS - st_cblk_off;
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else {
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);
	}

	if (CENTRY_DIRTY(cc_ent) && update_dirty(cc_ent, st_cblk_off,
	    st_cblk_len))
		goto loop1;
	if (store_only) {
		SDBC_SET_TOFLUSH(st_cblk_off, st_cblk_len, cc_ent);
		goto loop1;
	}
	SDBC_SET_DIRTY(st_cblk_off, st_cblk_len, cc_ent);
	cur_chain = dirty_next = cc_ent;
	num_queued = 1;

loop1:
	DATA_LOG(SDF_WR, cc_ent, st_cblk_off, st_cblk_len);

	DTRACE_PROBE4(_sd_write_data1, uint64_t, (uint64_t)
	    (BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)) + st_cblk_off),
	    int, st_cblk_len, char *,
	    *(int64_t *)(cc_ent->cc_data + FBA_SIZE(st_cblk_off)),
	    char *, *(int64_t *)(cc_ent->cc_data +
	    FBA_SIZE(st_cblk_off+ st_cblk_len) - 8));

	cur_fba_len -= st_cblk_len;
	cc_ent = cc_ent->cc_chain;

	while (cur_fba_len > (nsc_size_t)end_cblk_len) {
		if (CENTRY_DIRTY(cc_ent) && update_dirty(cc_ent, 0, BLK_FBAS)) {
			if (cur_chain) {
				_sd_enqueue_dirty(cd, cur_chain, dirty_next,
				    num_queued);
				cur_chain = dirty_next = NULL;
			}
			goto loop2;
		}
		if (store_only) {
			SDBC_SET_TOFLUSH(0, BLK_FBAS, cc_ent);
			goto loop2;
		}
		SDBC_SET_DIRTY(0, BLK_FBAS, cc_ent);
		if (dirty_next) {
			dirty_next->cc_dirty_next = cc_ent;
			dirty_next = cc_ent;
			num_queued++;
		} else {
			cur_chain = dirty_next = cc_ent;
			num_queued = 1;
		}
	loop2:
		DATA_LOG(SDF_WR, cc_ent, 0, BLK_FBAS);

		DTRACE_PROBE4(_sd_write_data2, uint64_t,
		    (uint64_t)(BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent))),
		    int, BLK_FBAS, char *, *(int64_t *)(cc_ent->cc_data),
		    char *, *(int64_t *)(cc_ent->cc_data +
		    FBA_SIZE(BLK_FBAS) - 8));

		cc_ent = cc_ent->cc_chain;
		cur_fba_len -= BLK_FBAS;
	}

#if defined(_SD_DEBUG)
	if (cur_fba_len != end_cblk_len)
		cmn_err(CE_WARN, "!fba_len %" NSC_SZFMT " end_cblk_len %d in "
		    "_sd_write", cur_fba_len, end_cblk_len);
#endif

	if (cur_fba_len) {
		if (CENTRY_DIRTY(cc_ent) && update_dirty(cc_ent, 0,
		    end_cblk_len)) {
			if (cur_chain) {
				_sd_enqueue_dirty(cd, cur_chain, dirty_next,
				    num_queued);
				cur_chain = dirty_next = NULL;
			}
			goto loop3;
		}
		if (store_only) {
			SDBC_SET_TOFLUSH(0, end_cblk_len, cc_ent);
			goto loop3;
		}
		SDBC_SET_DIRTY(0, end_cblk_len, cc_ent);
		if (dirty_next) {
			dirty_next->cc_dirty_next = cc_ent;
			dirty_next = cc_ent;
			num_queued++;
		} else {
			cur_chain = dirty_next = cc_ent;
			num_queued = 1;
		}
	}
loop3:
	if (cur_fba_len) {
		DATA_LOG(SDF_WR, cc_ent, 0, end_cblk_len);

		DTRACE_PROBE4(_sd_write_data3, uint64_t,
		    (uint64_t)(BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent))),
		    int, end_cblk_len, char *, *(int64_t *)(cc_ent->cc_data),
		    char *, *(int64_t *)(cc_ent->cc_data +
		    FBA_SIZE(end_cblk_len) - 8));

	}

	if (!store_only && cur_chain) {
		_sd_enqueue_dirty(cd, cur_chain, dirty_next, num_queued);
	}

	if (!queue_only) {
		CACHE_FBA_WRITE(cd,  fba_len);
		CACHE_WRITE_HIT;

		FBA_WRITE_IO_KSTATS(cd, FBA_SIZE(fba_len));
	}

	ret = NSC_HIT;

stats_exit:
	SDTRACE(ST_EXIT|SDF_WRITE, cd, fba_len, fba_pos, flag, ret);
	KSTAT_RUNQ_EXIT(cd);
out:
	return (ret);
}


/*
 * _sd_queue_write(handle, fba_pos, fba_len): Queues delayed writes for
 *					    flushing
 *
 * ARGUMENTS:  handle  - handle allocated with NSC_WRBUF
 *	fba_pos - starting fba pos from _sd_alloc_buf()
 *	fba_len - fba len from _sd_alloc_buf()
 *
 * USAGE    :  Called if _SD_DELAY_QUEUE is set. Finds all blocks in the
 *	handle marked for flushing and queues them to be written in
 *	optimized (i.e. sequential) order
 */
static void
_sd_queue_write(_sd_buf_handle_t *handle, nsc_off_t fba_pos, nsc_size_t fba_len)
{
	nsc_off_t fba_end;
	sdbc_cblk_fba_t sblk, len, dirty;
	_sd_cctl_t *cc_ent;
	nsc_off_t flush_pos;
	int flush_pos_valid = 0;
	nsc_size_t flush_len = 0;

	cc_ent = handle->bh_centry;
	fba_end = fba_pos + fba_len;
	fba_pos = BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)); /* 1st block */
	while (fba_pos < fba_end) {
		dirty = cc_ent->cc_toflush;
		cc_ent->cc_toflush = 0;
		/*
		 * Full block
		 */
		if (_SD_BMAP_ISFULL(dirty)) {
			if (flush_pos_valid == 0) {
				flush_pos_valid = 1;
				flush_pos = fba_pos;
			}
			flush_len += BLK_FBAS;
		}
		/*
		 * Partial block
		 */
		else while (dirty) {
			sblk = SDBC_LOOKUP_STPOS(dirty);
			len  = SDBC_LOOKUP_LEN(dirty);
			SDBC_LOOKUP_MODIFY(dirty);

			if (sblk && flush_pos_valid) {
				(void) _sd_write(handle, flush_pos, flush_len,
				    NSC_QUEUE);
				flush_pos_valid = 0;
				flush_len = 0;
			}
			if (flush_pos_valid == 0) {
				flush_pos_valid = 1;
				flush_pos = fba_pos + sblk;
			}
			flush_len += len;
		}
		fba_pos += BLK_FBAS;
		cc_ent = cc_ent->cc_chain;
		/*
		 * If we find a gap, write out what we've got
		 */
		if (flush_pos_valid && (flush_pos + flush_len) != fba_pos) {
			(void) _sd_write(handle, flush_pos, flush_len,
			    NSC_QUEUE);
			flush_pos_valid = 0;
			flush_len = 0;
		}
	}
	if (flush_pos_valid)
		(void) _sd_write(handle, flush_pos, flush_len, NSC_QUEUE);
}


static int
_sd_remote_store(_sd_cctl_t *cc_ent, nsc_off_t fba_pos, nsc_size_t fba_len)
{
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	ss_resource_t *ss_res;

	if (_sd_nodes_configured <= 2 && _sd_is_mirror_down())
		return (0);
	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = BLK_FBAS - st_cblk_off;
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else {
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);
	}

	fba_len -= st_cblk_len;

	ss_res = cc_ent->cc_write->sc_res;
	if (SSOP_WRITE_CBLOCK(sdbc_safestore, ss_res,
	    cc_ent->cc_data + FBA_SIZE(st_cblk_off), FBA_SIZE(st_cblk_len),
	    FBA_SIZE(st_cblk_off))) {

		cmn_err(CE_WARN,
		    "!sdbc(_sd_write) safe store failed. Going synchronous");
		SDTRACE(SDF_REFLECT, CENTRY_CD(cc_ent), fba_len,
		    fba_pos, 0, -1);
		return (-1);
	}

	cc_ent = cc_ent->cc_chain;
	while (fba_len > (nsc_size_t)end_cblk_len) {
		fba_len -= BLK_FBAS;

		if (SSOP_WRITE_CBLOCK(sdbc_safestore, ss_res, cc_ent->cc_data,
		    CACHE_BLOCK_SIZE, 0)) {

			cmn_err(CE_WARN, "!sdbc(_sd_write) safe store failed. "
			    "Going synchronous");
			SDTRACE(SDF_REFLECT, CENTRY_CD(cc_ent), fba_len,
			    fba_pos, 0, -1);
			return (-1);
		}

		cc_ent = cc_ent->cc_chain;
	} /* end while */

	if (fba_len) {
		if (SSOP_WRITE_CBLOCK(sdbc_safestore, ss_res,
		    cc_ent->cc_data, FBA_SIZE(end_cblk_len), 0)) {

			cmn_err(CE_WARN, "!sdbc(_sd_write) nvmem dma failed. "
			    "Going synchronous");
			SDTRACE(SDF_REFLECT, CENTRY_CD(cc_ent), fba_len,
			    fba_pos, 0, -1);
			return (-1);
		}
	}
	return (0);
}


/*
 * _sd_sync_write2 - Write-through function.
 *
 * ARGUMENTS:
 *	wr_handle - handle into which to write the data.
 *	wr_st_pos - starting FBA position in wr_handle.
 *	fba_len   - length in fbas.
 *	flag	- NSC_NOBLOCK for async io.
 *	rd_handle - handle from which to read the data, or NULL.
 *	rd_st_pos - starting FBA position in rd_handle.
 *
 * RETURNS:
 *	errno if return > 0
 *	NSC_DONE or NSC_PENDING otherwise.
 *
 * Comments:
 *	This routine initiates io of the indicated portion. It returns
 *	synchronously after io is completed if NSC_NOBLOCK is not set.
 *	Else NSC_PENDING is returned with a subsequent write callback on
 *	io completion.
 *
 *	See _sd_copy_direct() for usage when
 *	    (wr_handle != rd_handle && rd_handle != NULL)
 */

static int
_sd_sync_write2(_sd_buf_handle_t *wr_handle, nsc_off_t wr_st_pos,
    nsc_size_t fba_len, int flag, _sd_buf_handle_t *rd_handle,
    nsc_off_t rd_st_pos)
{
	void (*fn)(blind_t, nsc_off_t, nsc_size_t, int);
	_sd_cctl_t *wr_ent, *rd_ent;
	nsc_size_t this_len;
	nsc_off_t rd_pos, wr_pos;
	nsc_size_t log_bytes;
	int cd = HANDLE_CD(wr_handle);
	int err;
	uint_t dirty;
	struct buf *bp;

	LINTUSED(flag);

	_SD_DISCONNECT_CALLBACK(wr_handle);

	if (rd_handle == NULL) {
		rd_handle = wr_handle;
		rd_st_pos = wr_st_pos;
	}

	wr_ent = wr_handle->bh_centry;
	while (CENTRY_BLK(wr_ent) != FBA_TO_BLK_NUM(wr_st_pos))
		wr_ent = wr_ent->cc_chain;

	rd_ent = rd_handle->bh_centry;
	while (CENTRY_BLK(rd_ent) != FBA_TO_BLK_NUM(rd_st_pos))
		rd_ent = rd_ent->cc_chain;

	bp = sd_alloc_iob(_sd_cache_files[cd].cd_crdev,
	    wr_st_pos, FBA_TO_BLK_LEN(fba_len) + 2, B_WRITE);

	if (bp == NULL)
		return (E2BIG);

	wr_pos = BLK_FBA_OFF(wr_st_pos);
	rd_pos = BLK_FBA_OFF(rd_st_pos);
	log_bytes = 0;

	do {
		this_len = min((BLK_FBAS - rd_pos), (BLK_FBAS - wr_pos));

		if (this_len > fba_len)
			this_len = fba_len;

		/*
		 * clear dirty bits in the write handle.
		 */

		if (CENTRY_DIRTY(wr_ent)) {
			mutex_enter(&wr_ent->cc_lock);

			if (CENTRY_DIRTY(wr_ent)) {
				if (this_len == (nsc_size_t)BLK_FBAS ||
				    rd_handle != wr_handle) {
					/*
					 * optimization for when we have a
					 * full cache block, or are doing
					 * copy_direct (see below).
					 */

					wr_ent->cc_write->sc_dirty = 0;
				} else {
					dirty = wr_ent->cc_write->sc_dirty;
					dirty &= ~(SDBC_GET_BITS(
					    wr_pos, this_len));
					wr_ent->cc_write->sc_dirty = dirty;
				}

				SSOP_SETCENTRY(sdbc_safestore,
				    wr_ent->cc_write);
			}

			mutex_exit(&wr_ent->cc_lock);
		}

		/*
		 * update valid bits in the write handle.
		 */

		if (rd_handle == wr_handle) {
			if (this_len == (nsc_size_t)BLK_FBAS) {
				SET_FULLY_VALID(wr_ent);
			} else {
				SDBC_SET_VALID_BITS(wr_pos, this_len, wr_ent);
			}
		} else {
			/*
			 * doing copy_direct, so mark the write handle
			 * as invalid since the data is on disk, but not
			 * in cache.
			 */
			wr_ent->cc_valid = 0;
		}

		DATA_LOG(SDF_WRSYNC, rd_ent, rd_pos, this_len);

		DTRACE_PROBE4(_sd_sync_write2_data, uint64_t,
		    (uint64_t)BLK_TO_FBA_NUM(CENTRY_BLK(rd_ent)) + rd_pos,
		    uint64_t, (uint64_t)this_len, char *,
		    *(int64_t *)(rd_ent->cc_data + FBA_SIZE(rd_pos)),
		    char *, *(int64_t *)(rd_ent->cc_data +
		    FBA_SIZE(rd_pos + this_len) - 8));

		sd_add_fba(bp, &rd_ent->cc_addr, rd_pos, this_len);

		log_bytes += FBA_SIZE(this_len);
		fba_len -= this_len;

		wr_pos += this_len;
		if (wr_pos >= (nsc_size_t)BLK_FBAS) {
			wr_ent = wr_ent->cc_chain;
			wr_pos = 0;
		}

		rd_pos += this_len;
		if (rd_pos >= (nsc_size_t)BLK_FBAS) {
			rd_ent = rd_ent->cc_chain;
			rd_pos = 0;
		}

	} while (fba_len > 0);

	DISK_FBA_WRITE(cd, FBA_NUM(log_bytes));
	CACHE_WRITE_MISS;

	FBA_WRITE_IO_KSTATS(cd, log_bytes);

	fn = (wr_handle->bh_flag & NSC_NOBLOCK) ? _sd_async_write_ea : NULL;

	err = sd_start_io(bp, _sd_cache_files[cd].cd_strategy, fn, wr_handle);

	if (err != NSC_PENDING) {
		DATA_LOG_CHAIN(SDF_WRSYEA, wr_handle->bh_centry,
		    wr_st_pos, FBA_NUM(log_bytes));
	}

	return (err);
}


static int
_sd_sync_write(_sd_buf_handle_t *handle, nsc_off_t fba_pos, nsc_size_t fba_len,
    int flag)
{
	return (_sd_sync_write2(handle, fba_pos, fba_len, flag, NULL, 0));
}


/*
 * _sd_zero - Interface call to zero out a portion of cache blocks.
 *
 * ARGUMENTS:
 *	handle  - handle allocated earlier on.
 *	fba_pos - disk block number to zero from.
 *	fba_len - length in fbas.
 *	flag    - NSC_NOBLOCK for async io.
 *
 * RETURNS:
 *	errno if return > 0
 *	NSC_DONE or NSC_PENDING otherwise.
 *
 * Comments:
 *	This routine zeroes out the indicated portion of the cache blocks
 *	and commits the data to disk.
 *	(See write for more details on the commit)
 */


int
_sd_zero(_sd_buf_handle_t *handle, nsc_off_t fba_pos, nsc_size_t fba_len,
    int flag)
{
	int cd;
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_size_t cur_fba_len;	/* position in disk blocks */
	int ret;
	_sd_cctl_t *cc_ent;

	if (_sdbc_shutdown_in_progress) {
		DTRACE_PROBE(shutdown);
		return (EIO);
	}

	if (!_SD_HANDLE_ACTIVE(handle)) {
		cmn_err(CE_WARN, "!sdbc(_sd_zero) handle %p not active",
		    (void *)handle);

		DTRACE_PROBE1(handle_active, int, handle->bh_flag);

		return (EINVAL);
	}
	ASSERT_HANDLE_LIMITS(handle, fba_pos, fba_len);
	if ((handle->bh_flag & NSC_WRBUF) == 0) {
		DTRACE_PROBE1(handle_write, int, handle->bh_flag);
		return (EINVAL);
	}

	if (fba_len == 0) {
		DTRACE_PROBE(zero_len);
		return (NSC_DONE);
	}

	if (_SD_FORCE_DISCONNECT(fba_len))
		_SD_DISCONNECT_CALLBACK(handle);

	cd = HANDLE_CD(handle);
	SDTRACE(ST_ENTER|SDF_ZERO, cd, fba_len, fba_pos, flag, 0);

	cc_ent = handle->bh_centry;
	while (CENTRY_BLK(cc_ent) != FBA_TO_BLK_NUM(fba_pos))
		cc_ent = cc_ent->cc_chain;
	cur_fba_len = fba_len;
	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = BLK_FBAS - st_cblk_off;
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else {
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);
	}

	cur_fba_len -= st_cblk_len;
	bzero(cc_ent->cc_data + FBA_SIZE(st_cblk_off), FBA_SIZE(st_cblk_len));

	cc_ent = cc_ent->cc_chain;
	while (cur_fba_len > (nsc_size_t)end_cblk_len) {
		cur_fba_len -= BLK_FBAS;
		bzero(cc_ent->cc_data, CACHE_BLOCK_SIZE);
		cc_ent = cc_ent->cc_chain;
	}
	if (cur_fba_len) {
		bzero(cc_ent->cc_data, FBA_SIZE(cur_fba_len));
	}

	ret = _sd_write(handle, fba_pos, fba_len, flag);
	SDTRACE(ST_EXIT|SDF_ZERO, cd, fba_len, fba_pos, flag, ret);

	return (ret);
}


/*
 * _sd_copy - Copies portions of 2 handles.
 *
 * ARGUMENTS:
 *	handle1  - handle allocated earlier on.
 *	handle2  - handle allocated earlier on.
 *	fba_pos1 - disk block number to read from.
 *	fba_pos2 - disk block number to write to.
 *	fba_len - length in fbas.
 *
 * RETURNS:
 *	errno if return > 0
 *	NSC_DONE otherwise.
 *
 * Comments:
 *	This routine copies the 2 handles.
 *	WARNING: this could put the cache blocks in the destination handle
 *	in an inconsistent state. (the blocks could be valid in cache,
 *	but the copy makes the cache different from disk)
 *
 */


int
_sd_copy(_sd_buf_handle_t *handle1, _sd_buf_handle_t *handle2,
    nsc_off_t fba_pos1, nsc_off_t fba_pos2, nsc_size_t fba_len)
{
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_off_t off1, off2;	/* offsets in FBA's into the disk */
	nsc_size_t cur_fba_len;	/* position in disk blocks */
	_sd_cctl_t *cc_ent1, *cc_ent2;

	if (_sdbc_shutdown_in_progress) {
		DTRACE_PROBE(shutdown);
		return (EIO);
	}
	if (!_SD_HANDLE_ACTIVE(handle1) || !_SD_HANDLE_ACTIVE(handle2)) {
		cmn_err(CE_WARN, "!sdbc(_sd_copy) handle %p or %p not active",
		    (void *)handle1, (void *)handle2);

		DTRACE_PROBE2(handle_active1, int, handle1->bh_flag,
		    int, handle2->bh_flag);

		return (EINVAL);
	}
	ASSERT_HANDLE_LIMITS(handle1, fba_pos1, fba_len);
	ASSERT_HANDLE_LIMITS(handle2, fba_pos2, fba_len);

	cc_ent1 = handle1->bh_centry;
	while (CENTRY_BLK(cc_ent1) != FBA_TO_BLK_NUM(fba_pos1))
		cc_ent1 = cc_ent1->cc_chain;

	cc_ent2 = handle2->bh_centry;
	while (CENTRY_BLK(cc_ent2) != FBA_TO_BLK_NUM(fba_pos2))
		cc_ent2 = cc_ent2->cc_chain;

	if (BLK_FBA_OFF(fba_pos1) != BLK_FBA_OFF(fba_pos2)) {
		/* Different offsets, do it slowly (per fba) */

		while (fba_len) {
			off1 = FBA_SIZE(BLK_FBA_OFF(fba_pos1));
			off2 = FBA_SIZE(BLK_FBA_OFF(fba_pos2));

			bcopy(cc_ent1->cc_data+off1, cc_ent2->cc_data+off2,
			    FBA_SIZE(1));

			fba_pos1++;
			fba_pos2++;
			fba_len--;

			if (FBA_TO_BLK_NUM(fba_pos1) != CENTRY_BLK(cc_ent1))
				cc_ent1 = cc_ent1->cc_chain;
			if (FBA_TO_BLK_NUM(fba_pos2) != CENTRY_BLK(cc_ent2))
				cc_ent2 = cc_ent2->cc_chain;
		}

		DTRACE_PROBE(_sd_copy_end);
		return (NSC_DONE);
	}
	cur_fba_len = fba_len;
	st_cblk_off = BLK_FBA_OFF(fba_pos1);
	st_cblk_len = BLK_FBAS - st_cblk_off;
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	} else {
		end_cblk_len = BLK_FBA_OFF(fba_pos1 + fba_len);
	}

	bcopy(cc_ent1->cc_data + FBA_SIZE(st_cblk_off),
	    cc_ent2->cc_data + FBA_SIZE(st_cblk_off), FBA_SIZE(st_cblk_len));
	cur_fba_len -= st_cblk_len;
	cc_ent1 = cc_ent1->cc_chain;
	cc_ent2 = cc_ent2->cc_chain;

	while (cur_fba_len > (nsc_size_t)end_cblk_len) {
		bcopy(cc_ent1->cc_data, cc_ent2->cc_data, CACHE_BLOCK_SIZE);
		cc_ent1 = cc_ent1->cc_chain;
		cc_ent2 = cc_ent2->cc_chain;
		cur_fba_len -= BLK_FBAS;
	}
	if (cur_fba_len) {
		bcopy(cc_ent1->cc_data, cc_ent2->cc_data,
		    FBA_SIZE(end_cblk_len));
	}

	return (NSC_DONE);
}


/*
 * _sd_copy_direct - Copies data from one handle direct to another disk.
 *
 * ARGUMENTS:
 *	handle1  - handle to read from
 *	handle2  - handle to write to
 *	fba_pos1 - disk block number to read from.
 *	fba_pos2 - disk block number to write to.
 *	fba_len - length in fbas.
 *
 * RETURNS:
 *	errno if return > 0
 *	NSC_DONE otherwise.
 *
 * Comments:
 *	This routine copies data from handle1 directly (sync write)
 *	onto the disk pointed to by handle2. The handle2 is then
 *	invalidated since the data it contains is now stale compared to
 *	the disk.
 */

static int
_sd_copy_direct(_sd_buf_handle_t *handle1, _sd_buf_handle_t *handle2,
    nsc_off_t fba_pos1, nsc_off_t fba_pos2, nsc_size_t fba_len)
{
	int rc;

	if (_sdbc_shutdown_in_progress) {
		DTRACE_PROBE(shutdown);
		return (EIO);
	}

	if (!_SD_HANDLE_ACTIVE(handle1) || !_SD_HANDLE_ACTIVE(handle2)) {
		cmn_err(CE_WARN,
		    "!sdbc(_sd_copy_direct) handle %p or %p not active",
		    (void *)handle1, (void *)handle2);

		DTRACE_PROBE2(handle_active2, int, handle1->bh_flag,
		    int, handle2->bh_flag);

		return (EINVAL);
	}

	ASSERT_HANDLE_LIMITS(handle1, fba_pos1, fba_len);
	ASSERT_HANDLE_LIMITS(handle2, fba_pos2, fba_len);

	if ((handle2->bh_flag & NSC_WRITE) == 0) {
		cmn_err(CE_WARN,
		    "!sdbc(_sd_copy_direct) handle2 %p is not writeable",
		    (void *)handle2);
		DTRACE_PROBE1(handle2_write, int, handle2->bh_flag);
		return (EINVAL);
	}

	rc = _sd_sync_write2(handle2, fba_pos2, fba_len, 0, handle1, fba_pos1);

	return (rc);
}


/*
 * _sd_enqueue_dirty - Enqueue a list of dirty buffers.
 *
 * ARGUMENTS:
 *	cd	- cache descriptor.
 *	chain	- pointer to list.
 *	cc_last - last entry in the chain.
 *	numq    - number of entries in the list.
 *
 * RETURNS:
 *	NONE.
 *
 * Comments:
 *	This routine queues up the dirty blocks for io processing.
 *	It uses the cc_last to try to coalesce multiple lists into a
 *	single list, if consecutive writes are sequential in nature.
 */

void
_sd_enqueue_dirty(int cd, _sd_cctl_t *chain, _sd_cctl_t *cc_last, int numq)
{
	_sd_cd_info_t *cdi;
	_sd_cctl_t *last_ent;
	int start_write = 0, maxq = SGIO_MAX;

	ASSERT(cd >= 0);
	cdi = &(_sd_cache_files[cd]);
#if defined(_SD_DEBUG)
	if (chain->cc_dirty_link)
		cmn_err(CE_WARN, "!dirty_link set in enq %x fl %x",
		    chain->cc_dirty_link, chain->cc_flag);
#endif

	/* was FAST */
	mutex_enter(&(cdi->cd_lock));
	cdi->cd_info->sh_numdirty += numq;
	if (cc_last == NULL)
		numq = 0;

	if (cdi->cd_dirty_head == NULL)  {
		cdi->cd_dirty_head = cdi->cd_dirty_tail = chain;
		cdi->cd_last_ent = cc_last;
		cdi->cd_lastchain_ptr = chain;
		cdi->cd_lastchain = numq;
	} else {
		if ((cc_last) && (last_ent = cdi->cd_last_ent) &&
		    (CENTRY_BLK(chain) == (CENTRY_BLK(last_ent)+1)) &&
		    (SDBC_DIRTY_NEIGHBORS(last_ent, chain)) &&
		    (cdi->cd_lastchain + numq < maxq)) {
			cdi->cd_last_ent->cc_dirty_next = chain;
			cdi->cd_last_ent = cc_last;
			cdi->cd_lastchain += numq;
		} else {
			cdi->cd_dirty_tail->cc_dirty_link = chain;
			cdi->cd_dirty_tail = chain;
			cdi->cd_last_ent = cc_last;
			cdi->cd_lastchain_ptr = chain;
			cdi->cd_lastchain = numq;
			start_write = 1;
		}
	}
	/* was FAST */
	mutex_exit(&(cdi->cd_lock));
	if (start_write)
		(void) _SD_CD_WRITER(cd);
}

/*
 * _sd_enqueue_dirty_chain  - Enqueue a chain of a list of dirty buffers.
 *
 * ARGUMENTS:
 *	cd	- cache descriptor.
 *	chain_first	- first list in  this chain.
 *	chain_last 	- last list in this chain.
 *	numq    - number of entries being queue (total of all lists)
 *
 * RETURNS:
 *	NONE.
 *
 * Comments:
 *	This routine is called from the processing after io completions.
 *	If the buffers are still dirty, they are queued up in one shot.
 */

void
_sd_enqueue_dirty_chain(int cd, _sd_cctl_t *chain_first,
    _sd_cctl_t *chain_last, int numq)
{
	_sd_cd_info_t *cdi;

	ASSERT(cd >= 0);
	cdi = &(_sd_cache_files[cd]);
	if (chain_last->cc_dirty_link)
		cmn_err(CE_PANIC,
		    "!_sd_enqueue_dirty_chain: chain_last %p dirty_link %p",
		    (void *)chain_last, (void *)chain_last->cc_dirty_link);
	/* was FAST */
	mutex_enter(&(cdi->cd_lock));
	cdi->cd_last_ent = NULL;
	cdi->cd_lastchain_ptr = NULL;
	cdi->cd_lastchain = 0;

	cdi->cd_info->sh_numdirty += numq;
	if (cdi->cd_dirty_head == NULL)  {
		cdi->cd_dirty_head = chain_first;
		cdi->cd_dirty_tail = chain_last;
	} else {
		cdi->cd_dirty_tail->cc_dirty_link = chain_first;
		cdi->cd_dirty_tail = chain_last;
	}
	/* was FAST */
	mutex_exit(&(cdi->cd_lock));
}

/*
 *	Convert the 64 bit statistic structure to 32bit version.
 *	Possibly losing information when cache is > 4gb. Ha!
 *
 *	NOTE: this code isn't really MT ready since the copied to struct
 *	is static. However the race is pretty benign and isn't a whole
 *	lot worse than the vanilla version which copies data to user
 *	space from kernel structures that can be changing under it too.
 *	We can't use a local stack structure since the data size is
 *	70k or so and kernel stacks are tiny (8k).
 */
#ifndef _MULTI_DATAMODEL
/* ARGSUSED */
#endif
static int
convert_stats(_sd_stats32_t *uptr)
{
#ifndef _MULTI_DATAMODEL
	return (SDBC_EMODELCONVERT);
#else
	int rc = 0;

	/*
	 * This could be done in less code with bcopy type operations
	 * but this is simpler to follow and easier to change if
	 * the structures change.
	 */

	_sd_cache_stats32->net_dirty = _sd_cache_stats->net_dirty;
	_sd_cache_stats32->net_pending = _sd_cache_stats->net_pending;
	_sd_cache_stats32->net_free = _sd_cache_stats->net_free;
	_sd_cache_stats32->st_count = _sd_cache_stats->st_count;
	_sd_cache_stats32->st_loc_count = _sd_cache_stats->st_loc_count;
	_sd_cache_stats32->st_rdhits = _sd_cache_stats->st_rdhits;
	_sd_cache_stats32->st_rdmiss = _sd_cache_stats->st_rdmiss;
	_sd_cache_stats32->st_wrhits = _sd_cache_stats->st_wrhits;
	_sd_cache_stats32->st_wrmiss = _sd_cache_stats->st_wrmiss;
	_sd_cache_stats32->st_blksize = _sd_cache_stats->st_blksize;

	_sd_cache_stats32->st_lru_blocks = _sd_cache_stats->st_lru_blocks;
	_sd_cache_stats32->st_lru_noreq = _sd_cache_stats->st_lru_noreq;
	_sd_cache_stats32->st_lru_req = _sd_cache_stats->st_lru_req;

	_sd_cache_stats32->st_wlru_inq = _sd_cache_stats->st_wlru_inq;

	_sd_cache_stats32->st_cachesize = _sd_cache_stats->st_cachesize;
	_sd_cache_stats32->st_numblocks = _sd_cache_stats->st_numblocks;
	_sd_cache_stats32->st_wrcancelns = _sd_cache_stats->st_wrcancelns;
	_sd_cache_stats32->st_destaged = _sd_cache_stats->st_destaged;

	/*
	 * bcopy the shared stats which has nothing that needs conversion
	 * in them
	 */

	bcopy(_sd_cache_stats->st_shared, _sd_cache_stats32->st_shared,
	    sizeof (_sd_shared_t) * sdbc_max_devs);

	if (copyout(_sd_cache_stats32, uptr, sizeof (_sd_stats32_t) +
	    (sdbc_max_devs - 1) * sizeof (_sd_shared_t)))
		rc = EFAULT;

	return (rc);
#endif /* _MULTI_DATAMODEL */
}


int
_sd_get_stats(_sd_stats_t *uptr, int convert_32)
{
	int rc = 0;

	if (_sd_cache_stats == NULL) {
		static _sd_stats_t dummy;
#ifdef _MULTI_DATAMODEL
		static _sd_stats32_t dummy32;
#endif

		if (convert_32) {
#ifdef _MULTI_DATAMODEL
			if (copyout(&dummy32, uptr, sizeof (_sd_stats32_t)))
				rc = EFAULT;
#else
			rc = SDBC_EMODELCONVERT;
#endif
		} else if (copyout(&dummy, uptr, sizeof (_sd_stats_t)))
			rc = EFAULT;
		return (rc);
	}

	_sd_cache_stats->st_lru_blocks = _sd_lru_q.sq_inq;
	_sd_cache_stats->st_lru_noreq  = _sd_lru_q.sq_noreq_stat;
	_sd_cache_stats->st_lru_req    = _sd_lru_q.sq_req_stat;

	if (sdbc_safestore) {
		ssioc_stats_t ss_stats;

		if (SSOP_CTL(sdbc_safestore, SSIOC_STATS,
		    (uintptr_t)&ss_stats) == 0)
			_sd_cache_stats->st_wlru_inq = ss_stats.wq_inq;
		else
			_sd_cache_stats->st_wlru_inq = 0;
	}

	if (convert_32)
		rc = convert_stats((_sd_stats32_t *)uptr);
	else if (copyout(_sd_cache_stats, uptr,
	    sizeof (_sd_stats_t) + (sdbc_max_devs - 1) * sizeof (_sd_shared_t)))
		rc = EFAULT;

	return (rc);
}


int
_sd_set_hint(int cd, uint_t hint)
{
	int ret = 0;
	if (FILE_OPENED(cd))  {
		SDTRACE(ST_ENTER|SDF_HINT, cd, 1, SDT_INV_BL, hint, 0);
		_sd_cache_files[cd].cd_hint |= (hint & _SD_HINT_MASK);
		SDTRACE(ST_EXIT|SDF_HINT, cd, 1, SDT_INV_BL, hint, ret);
	} else
		ret = EINVAL;

	return (ret);
}



int
_sd_clear_hint(int cd, uint_t hint)
{
	int ret = 0;
	if (FILE_OPENED(cd)) {
		SDTRACE(ST_ENTER|SDF_HINT, cd, 2, SDT_INV_BL, hint, 0);
		_sd_cache_files[cd].cd_hint &= ~(hint & _SD_HINT_MASK);
		SDTRACE(ST_EXIT|SDF_HINT, cd, 2, SDT_INV_BL, hint, ret);
	} else
		ret = EINVAL;

	return (ret);
}


int
_sd_get_cd_hint(int cd, uint_t *hint)
{
	*hint = 0;
	if (FILE_OPENED(cd)) {
		*hint = _sd_cache_files[cd].cd_hint;
		return (0);
	} else
		return (EINVAL);
}

static int
_sd_node_hint_caller(blind_t hint, int  hint_action)
{
	int rc;

	switch (hint_action) {
		case NSC_GET_NODE_HINT:
			rc = _sd_get_node_hint((uint_t *)hint);
		break;
		case NSC_SET_NODE_HINT:
			rc = _sd_set_node_hint((uint_t)(unsigned long)hint);
		break;
		case NSC_CLEAR_NODE_HINT:
			rc = _sd_clear_node_hint((uint_t)(unsigned long)hint);
		break;
		default:
			rc = EINVAL;
		break;
	}

	return (rc);
}

int
_sd_set_node_hint(uint_t hint)
{
	SDTRACE(ST_ENTER|SDF_HINT, SDT_INV_CD, 3, SDT_INV_BL, hint, 0);
	if ((_sd_node_hint & NSC_NO_FORCED_WRTHRU) &&
	    (hint & NSC_FORCED_WRTHRU))
		return (EINVAL);
	_sd_node_hint |= (hint & _SD_HINT_MASK);
	SDTRACE(ST_EXIT|SDF_HINT, SDT_INV_CD, 3, SDT_INV_BL,  hint, 0);
	return (0);
}


int
_sd_clear_node_hint(uint_t hint)
{
	SDTRACE(ST_ENTER|SDF_HINT, SDT_INV_CD, 4, SDT_INV_BL, hint, 0);
	_sd_node_hint &= ~(hint & _SD_HINT_MASK);
	SDTRACE(ST_EXIT|SDF_HINT, SDT_INV_CD, 4, SDT_INV_BL, hint, 0);
	return (0);
}


int
_sd_get_node_hint(uint_t *hint)
{
	*hint = _sd_node_hint;
	return (0);
}


int
_sd_get_partsize(blind_t xcd, nsc_size_t *ptr)
{
	int cd = (int)(unsigned long)xcd;

	if (FILE_OPENED(cd)) {
		*ptr = _sd_cache_files[cd].cd_info->sh_filesize;
		return (0);
	} else
		return (EINVAL);
}


int
_sd_get_maxfbas(blind_t xcd, int flag, nsc_size_t *ptr)
{
	int cd = (int)(unsigned long)xcd;

	if (!FILE_OPENED(cd))
		return (EINVAL);

	if (flag & NSC_CACHEBLK)
		*ptr = BLK_FBAS;
	else
		*ptr = sdbc_max_fbas;

	return (0);
}


int
_sd_control(blind_t xcd, int cmd, void *ptr, int len)
{
	_sd_cd_info_t *cdi;
	int cd = (int)(unsigned long)xcd;

	cdi = &(_sd_cache_files[cd]);
	return (nsc_control(cdi->cd_rawfd, cmd, ptr, len));
}


int
_sd_discard_pinned(blind_t xcd, nsc_off_t fba_pos, nsc_size_t fba_len)
{
	int cd = (int)(unsigned long)xcd;
	_sd_cctl_t *cc_ent, **cc_lst, **cc_tmp, *nxt;
	ss_centry_info_t *wctl;
	int found = 0;
	nsc_off_t cblk;
	_sd_cd_info_t *cdi = &_sd_cache_files[cd];
	int rc;

	if ((!FILE_OPENED(cd)) || (!cdi->cd_info->sh_failed)) {

		return (EINVAL);
	}

	for (cblk = FBA_TO_BLK_NUM(fba_pos);
	    cblk < FBA_TO_BLK_LEN(fba_pos + fba_len); cblk++) {
		if (cc_ent =
		    (_sd_cctl_t *)_sd_hash_search(cd, cblk, _sd_htable)) {
			if (!CENTRY_PINNED(cc_ent))
				continue;

			/*
			 * remove cc_ent from failed links
			 * cc_lst - pointer to "cc_dirty_link" pointer
			 *	    starts at &cd_failed_head.
			 * cc_tmp - pointer to "cc_dirty_next"
			 *	    except when equal to cc_lst.
			 */
			mutex_enter(&cdi->cd_lock);
			cc_tmp = cc_lst = &(cdi->cd_fail_head);
			while (*cc_tmp != cc_ent) {
				cc_tmp = &((*cc_tmp)->cc_dirty_next);
				if (!*cc_tmp)
					cc_lst = &((*cc_lst)->cc_dirty_link),
					    cc_tmp = cc_lst;
			}
			if (*cc_tmp) {
				found++;
				if (cc_lst != cc_tmp) /* break chain */
					*cc_tmp = NULL;
				nxt = cc_ent->cc_dirty_next;
				if (nxt) {
					nxt->cc_dirty_link =
					    (*cc_lst)->cc_dirty_link;
					*cc_lst = nxt;
				} else {
					*cc_lst = (*cc_lst)->cc_dirty_link;
				}
				cdi->cd_info->sh_numfail--;
				nsc_unpinned_data(cdi->cd_iodev,
				    BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
				    BLK_FBAS);
			}
			mutex_exit(&cdi->cd_lock);

			/* clear dirty bits */
			/* was FAST */
			mutex_enter(&cc_ent->cc_lock);
			cc_ent->cc_valid = cc_ent->cc_dirty = 0;
			cc_ent->cc_flag &= ~(CC_QHEAD|CC_PEND_DIRTY|CC_PINNED);
			cc_ent->cc_dirty_link = NULL;
			wctl = cc_ent->cc_write;
			cc_ent->cc_write = NULL;
			/* was FAST */
			mutex_exit(&cc_ent->cc_lock);

			/* release cache block to head of LRU */
			if (wctl) {
				wctl->sc_flag = 0;
				wctl->sc_dirty = 0;
				SSOP_SETCENTRY(sdbc_safestore, wctl);
				SSOP_DEALLOCRESOURCE(sdbc_safestore,
				    wctl->sc_res);
			}

			if (!sdbc_use_dmchain)
				_sd_requeue_head(cc_ent);
		}
	}

	rc = found ? NSC_DONE : EINVAL;

	return (rc);
}


/*
 * Handle allocation
 */

_sd_buf_hlist_t  _sd_handle_list;

/*
 * _sdbc_handles_unload - cache is being unloaded.
 */
void
_sdbc_handles_unload(void)
{
	mutex_destroy(&_sd_handle_list.hl_lock);

}

/*
 * _sdbc_handles_load - cache is being unloaded.
 */
int
_sdbc_handles_load(void)
{
	mutex_init(&_sd_handle_list.hl_lock, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

int
_sdbc_handles_configure()
{
	_sd_handle_list.hl_count = 0;

	_sd_handle_list.hl_top.bh_next = &_sd_handle_list.hl_top;
	_sd_handle_list.hl_top.bh_prev = &_sd_handle_list.hl_top;

	return (0);
}



/*
 * _sdbc_handles_deconfigure - cache is being deconfigured
 */
void
_sdbc_handles_deconfigure(void)
{
	_sd_handle_list.hl_count = 0;
}


_sd_buf_handle_t *
_sd_alloc_handle(sdbc_callback_fn_t d_cb, sdbc_callback_fn_t r_cb,
    sdbc_callback_fn_t w_cb)
{
	_sd_buf_handle_t *handle;

	handle = (_sd_buf_handle_t *)kmem_zalloc(sizeof (_sd_buf_handle_t),
	    KM_SLEEP);
	/* maintain list and count for debugging */
	mutex_enter(&_sd_handle_list.hl_lock);

	handle->bh_prev = &_sd_handle_list.hl_top;
	handle->bh_next = _sd_handle_list.hl_top.bh_next;
	_sd_handle_list.hl_top.bh_next->bh_prev = handle;
	_sd_handle_list.hl_top.bh_next = handle;

	++_sd_handle_list.hl_count;
	mutex_exit(&_sd_handle_list.hl_lock);
#if !defined(_SD_NOCHECKS)
	ASSERT(!(handle->bh_flag & (NSC_HALLOCATED | NSC_HACTIVE)));
#endif
	handle->bh_disconnect_cb = d_cb;
	handle->bh_read_cb = r_cb;
	handle->bh_write_cb = w_cb;
	handle->bh_flag |= NSC_HALLOCATED;
	handle->bh_alloc_thread = nsc_threadp();

	return (handle);
}

int
_sd_free_handle(_sd_buf_handle_t *handle)
{

	if ((handle->bh_flag & NSC_HALLOCATED) == 0) {
		cmn_err(CE_WARN, "!sdbc(_sd_free_handle) handle %p not valid",
		    (void *)handle);

		DTRACE_PROBE(_sd_free_handle_end);

		return (EINVAL);
	}
	if (_SD_HANDLE_ACTIVE(handle)) {
		cmn_err(CE_WARN,
		    "!sdbc(_sd_free_handle) attempt to free active handle %p",
		    (void *)handle);

		DTRACE_PROBE1(free_handle_active, int, handle->bh_flag);

		return (EINVAL);
	}


	/* remove from queue before free */
	mutex_enter(&_sd_handle_list.hl_lock);
	handle->bh_prev->bh_next = handle->bh_next;
	handle->bh_next->bh_prev = handle->bh_prev;
	--_sd_handle_list.hl_count;
	mutex_exit(&_sd_handle_list.hl_lock);

	kmem_free(handle, sizeof (_sd_buf_handle_t));

	return (0);
}




#if !defined  (_SD_8K_BLKSIZE)
#define	_SD_MAX_MAP 0x100
#else 	/* !(_SD_8K_BLKSIZE)    */
#define	_SD_MAX_MAP 0x10000
#endif 	/* !(_SD_8K_BLKSIZE) 	*/

char _sd_contig_bmap[_SD_MAX_MAP];
_sd_map_info_t _sd_lookup_map[_SD_MAX_MAP];

void
_sd_init_contig_bmap(void)
{
	int i, j;

	for (i = 1; i < _SD_MAX_MAP; i = ((i << 1) | 1))
		for (j = i; j < _SD_MAX_MAP; j <<= 1)
			_sd_contig_bmap[j] = 1;
}




void
_sd_init_lookup_map(void)
{
	unsigned int i, j, k;
	int stpos, len;
	_sd_bitmap_t mask;

	for (i = 0; i < _SD_MAX_MAP; i++) {
		for (j = i, k = 0; j && ((j & 1) == 0); j >>= 1, k++)
		;
		stpos =  k;
		_sd_lookup_map[i].mi_stpos = (unsigned char)k;

		for (k = 0; j & 1; j >>= 1, k++)
		;
		len = k;
		_sd_lookup_map[i].mi_len = (unsigned char)k;

		_sd_lookup_map[i].mi_mask = SDBC_GET_BITS(stpos, len);
	}
	for (i = 0; i < _SD_MAX_MAP; i++) {
		mask = (_sd_bitmap_t)i;
		for (j = 0; mask; j++)
			SDBC_LOOKUP_MODIFY(mask);

		_sd_lookup_map[i].mi_dirty_count = (unsigned char)j;
	}
	for (i = 0; i < _SD_MAX_MAP; i++) {
		_sd_lookup_map[i].mi_io_count = SDBC_LOOKUP_DTCOUNT(i);
		mask = ~i;
		_sd_lookup_map[i].mi_io_count += SDBC_LOOKUP_DTCOUNT(mask);
	}
}


nsc_def_t _sd_sdbc_def[] = {
	"Open",		(uintptr_t)_sd_open_io,			0,
	"Close",	(uintptr_t)_sd_close_io,		0,
	"Attach",	(uintptr_t)_sdbc_io_attach_cd,		0,
	"Detach",	(uintptr_t)_sdbc_io_detach_cd,		0,
	"AllocBuf",	(uintptr_t)_sd_alloc_buf,		0,
	"FreeBuf",	(uintptr_t)_sd_free_buf,		0,
	"Read",		(uintptr_t)_sd_read,			0,
	"Write",	(uintptr_t)_sd_write,			0,
	"Zero",		(uintptr_t)_sd_zero,			0,
	"Copy",		(uintptr_t)_sd_copy,			0,
	"CopyDirect",	(uintptr_t)_sd_copy_direct,		0,
	"Uncommit",	(uintptr_t)_sd_uncommit,		0,
	"AllocHandle",	(uintptr_t)_sd_alloc_handle,		0,
	"FreeHandle",	(uintptr_t)_sd_free_handle,		0,
	"Discard",	(uintptr_t)_sd_discard_pinned,		0,
	"Sizes",	(uintptr_t)_sd_cache_sizes,		0,
	"GetPinned",	(uintptr_t)_sd_get_pinned,		0,
	"NodeHints",	(uintptr_t)_sd_node_hint_caller,	0,
	"PartSize",	(uintptr_t)_sd_get_partsize,		0,
	"MaxFbas",	(uintptr_t)_sd_get_maxfbas,		0,
	"Control",	(uintptr_t)_sd_control,			0,
	"Provide",	NSC_CACHE,				0,
	0,		0,					0
};

/*
 * do the SD_GET_CD_CLUSTER_DATA ioctl (get the global filename data)
 */
/* ARGSUSED */
int
sd_get_file_info_data(char *uaddrp)
{
	return (ENOTTY);
}

/*
 * do the SD_GET_CD_CLUSTER_SIZE ioctl (get size of global filename area)
 */
int
sd_get_file_info_size(void *uaddrp)
{
	if (copyout(&_sdbc_gl_file_info_size, uaddrp,
	    sizeof (_sdbc_gl_file_info_size))) {
		return (EFAULT);
	}

	return (0);
}


/*
 * SD_GET_GLMUL_SIZES ioctl
 * get sizes of the global info regions (for this node only)
 */
/* ARGSUSED */
int
sd_get_glmul_sizes(int *uaddrp)
{
	return (ENOTTY);
}

/*
 * SD_GET_GLMUL_INFO ioctl
 * get the global metadata for write blocks (for this node only)
 */
/* ARGSUSED */
int
sd_get_glmul_info(char *uaddrp)
{

	return (ENOTTY);
}

int
sdbc_global_stats_update(kstat_t *ksp, int rw)
{
	sdbc_global_stats_t *sdbc_gstats;
	_sd_stats_t *gstats_vars;
	uint_t hint;

	sdbc_gstats = (sdbc_global_stats_t *)(ksp->ks_data);

	gstats_vars = _sd_cache_stats;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	/* default to READ */
	sdbc_gstats->ci_sdbc_count.value.ul = gstats_vars->st_count;
	sdbc_gstats->ci_sdbc_loc_count.value.ul = gstats_vars->st_loc_count;
	sdbc_gstats->ci_sdbc_rdhits.value.ul = (ulong_t)gstats_vars->st_rdhits;
	sdbc_gstats->ci_sdbc_rdmiss.value.ul = (ulong_t)gstats_vars->st_rdmiss;
	sdbc_gstats->ci_sdbc_wrhits.value.ul = (ulong_t)gstats_vars->st_wrhits;
	sdbc_gstats->ci_sdbc_wrmiss.value.ul = (ulong_t)gstats_vars->st_wrmiss;

	sdbc_gstats->ci_sdbc_blksize.value.ul =
	    (ulong_t)gstats_vars->st_blksize;
	sdbc_gstats->ci_sdbc_lru_blocks.value.ul = (ulong_t)_sd_lru_q.sq_inq;
#ifdef DEBUG
	sdbc_gstats->ci_sdbc_lru_noreq.value.ul =
	    (ulong_t)_sd_lru_q.sq_noreq_stat;
	sdbc_gstats->ci_sdbc_lru_req.value.ul = (ulong_t)_sd_lru_q.sq_req_stat;
#endif
	sdbc_gstats->ci_sdbc_wlru_inq.value.ul =
	    (ulong_t)gstats_vars->st_wlru_inq;
	sdbc_gstats->ci_sdbc_cachesize.value.ul =
	    (ulong_t)gstats_vars->st_cachesize;
	sdbc_gstats->ci_sdbc_numblocks.value.ul =
	    (ulong_t)gstats_vars->st_numblocks;
	sdbc_gstats->ci_sdbc_wrcancelns.value.ul =
	    (ulong_t)gstats_vars->st_wrcancelns;
	sdbc_gstats->ci_sdbc_destaged.value.ul =
	    (ulong_t)gstats_vars->st_destaged;
	sdbc_gstats->ci_sdbc_num_shared.value.ul = (ulong_t)sdbc_max_devs;
	(void) _sd_get_node_hint(&hint);
	sdbc_gstats->ci_sdbc_nodehints.value.ul = (ulong_t)hint;


	return (0);
}

int
sdbc_cd_stats_update(kstat_t *ksp, int rw)
{
	sdbc_cd_stats_t *sdbc_shstats;
	_sd_shared_t *shstats_vars;
	int name_len;
	uint_t hint;

	sdbc_shstats = (sdbc_cd_stats_t *)(ksp->ks_data);

	shstats_vars = (_sd_shared_t *)(ksp->ks_private);

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	/* copy tail of filename to kstat. leave 1 byte for null char */
	if (shstats_vars->sh_filename != NULL) {
		name_len = (int)strlen(shstats_vars->sh_filename);
		name_len -= (KSTAT_DATA_CHAR_LEN - 1);

		if (name_len < 0) {
			name_len = 0;
		}

		(void) strlcpy(sdbc_shstats->ci_sdbc_vol_name.value.c,
		    shstats_vars->sh_filename + name_len, KSTAT_DATA_CHAR_LEN);
	} else {
		cmn_err(CE_WARN, "!Kstat error: no volume name associated "
		    "with cache descriptor");
	}

	sdbc_shstats->ci_sdbc_failed.value.ul =
	    (ulong_t)shstats_vars->sh_failed;
	sdbc_shstats->ci_sdbc_cd.value.ul = (ulong_t)shstats_vars->sh_cd;
	sdbc_shstats->ci_sdbc_cache_read.value.ul =
	    (ulong_t)shstats_vars->sh_cache_read;
	sdbc_shstats->ci_sdbc_cache_write.value.ul =
	    (ulong_t)shstats_vars->sh_cache_write;
	sdbc_shstats->ci_sdbc_disk_read.value.ul =
	    (ulong_t)shstats_vars->sh_disk_read;
	sdbc_shstats->ci_sdbc_disk_write.value.ul =
	    (ulong_t)shstats_vars->sh_disk_write;
#ifdef NSC_MULTI_TERABYTE
	sdbc_shstats->ci_sdbc_filesize.value.ui64 =
	    (uint64_t)shstats_vars->sh_filesize;
#else
	sdbc_shstats->ci_sdbc_filesize.value.ul =
	    (ulong_t)shstats_vars->sh_filesize;
#endif
	sdbc_shstats->ci_sdbc_numdirty.value.ul =
	    (ulong_t)shstats_vars->sh_numdirty;
	sdbc_shstats->ci_sdbc_numio.value.ul = (ulong_t)shstats_vars->sh_numio;
	sdbc_shstats->ci_sdbc_numfail.value.ul =
	    (ulong_t)shstats_vars->sh_numfail;
	sdbc_shstats->ci_sdbc_destaged.value.ul =
	    (ulong_t)shstats_vars->sh_destaged;
	sdbc_shstats->ci_sdbc_wrcancelns.value.ul =
	    (ulong_t)shstats_vars->sh_wrcancelns;
	(void) _sd_get_cd_hint(shstats_vars->sh_cd, &hint);
	sdbc_shstats->ci_sdbc_cdhints.value.ul = (ulong_t)hint;


	return (0);
}


/*
 * cd_kstat_add
 *
 * Installs all kstats and associated infrastructure (mutex, buffer),
 * associated with a particular cache descriptor.  This function is called
 * when the cache descriptor is opened in _sd_open().
 * "cd" -- cache descriptor number whose kstats we wish to add
 * returns: 0 on success, -1 on failure
 */
static int
cd_kstat_add(int cd)
{
	char name[KSTAT_STRLEN];

	if (cd < 0 || cd >= sdbc_max_devs) {
		cmn_err(CE_WARN, "!invalid cache descriptor: %d", cd);
		return (-1);
	}

	/* create a regular kstat for this cache descriptor */
	if (!sdbc_cd_kstats) {
		cmn_err(CE_WARN, "!sdbc_cd_kstats not allocated");
		return (-1);
	}

	(void) snprintf(name, KSTAT_STRLEN, "%s%d", SDBC_KSTAT_CDSTATS, cd);

	sdbc_cd_kstats[cd] = kstat_create(SDBC_KSTAT_MODULE,
	    cd, name, SDBC_KSTAT_CLASS, KSTAT_TYPE_NAMED,
	    sizeof (sdbc_cd_stats)/sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL|KSTAT_FLAG_WRITABLE);

	if (sdbc_cd_kstats[cd] != NULL) {
		sdbc_cd_kstats[cd]->ks_data = &sdbc_cd_stats;
		sdbc_cd_kstats[cd]->ks_update = sdbc_cd_stats_update;
		sdbc_cd_kstats[cd]->ks_private =
		    &_sd_cache_stats->st_shared[cd];
		kstat_install(sdbc_cd_kstats[cd]);
	} else {
		cmn_err(CE_WARN, "!cdstats %d kstat allocation failed", cd);
	}

	/* create an I/O kstat for this cache descriptor */
	if (!sdbc_cd_io_kstats) {
		cmn_err(CE_WARN, "!sdbc_cd_io_kstats not allocated");
		return (-1);
	}

	(void) snprintf(name, KSTAT_STRLEN, "%s%d", SDBC_IOKSTAT_CDSTATS, cd);

	sdbc_cd_io_kstats[cd] = kstat_create(
	    SDBC_KSTAT_MODULE, cd, name, "disk", KSTAT_TYPE_IO, 1, 0);

	if (sdbc_cd_io_kstats[cd]) {
		if (!sdbc_cd_io_kstats_mutexes) {
			cmn_err(CE_WARN, "!sdbc_cd_io_kstats_mutexes not "
			    "allocated");
			return (-1);
		}

		mutex_init(&sdbc_cd_io_kstats_mutexes[cd], NULL,
		    MUTEX_DRIVER, NULL);

		sdbc_cd_io_kstats[cd]->ks_lock = &sdbc_cd_io_kstats_mutexes[cd];

		kstat_install(sdbc_cd_io_kstats[cd]);

	} else {
		cmn_err(CE_WARN, "!sdbc cd %d io kstat allocation failed", cd);
	}

	return (0);
}

/*
 * cd_kstat_remove
 *
 * Uninstalls all kstats and associated infrastructure (mutex, buffer),
 * associated with a particular cache descriptor.  This function is called
 * when the cache descriptor is closed in _sd_close().
 * "cd" -- cache descriptor number whose kstats we wish to remove
 * returns: 0 on success, -1 on failure
 */
static int
cd_kstat_remove(int cd)
{
	if (cd < 0 || cd >= sdbc_max_devs) {
		cmn_err(CE_WARN, "!invalid cache descriptor: %d", cd);
		return (-1);
	}

	/* delete the regular kstat corresponding to this cache descriptor */
	if (sdbc_cd_kstats && sdbc_cd_kstats[cd]) {
		kstat_delete(sdbc_cd_kstats[cd]);
		sdbc_cd_kstats[cd] = NULL;
	}

	/* delete the I/O kstat corresponding to this cache descriptor */
	if (sdbc_cd_io_kstats && sdbc_cd_io_kstats[cd]) {
		kstat_delete(sdbc_cd_io_kstats[cd]);
		sdbc_cd_io_kstats[cd] = NULL;

		if (sdbc_cd_io_kstats_mutexes) {
			/* destroy the mutex associated with this I/O kstat */
			mutex_destroy(&sdbc_cd_io_kstats_mutexes[cd]);
		}
	}

	return (0);
}

#ifdef DEBUG
/*
 * kstat update
 */
int
sdbc_dynmem_kstat_update_dm(kstat_t *ksp, int rw)
{
	sdbc_dynmem_dm_t *sdbc_dynmem;
	_dm_process_vars_t *process_vars;
	_dm_process_vars_t local_dm_process_vars;

	simplect_dm++;

	sdbc_dynmem = (sdbc_dynmem_dm_t *)(ksp->ks_data);

	/* global dynmem_processing_dm */
	process_vars = (_dm_process_vars_t *)(ksp->ks_private);

	if (rw == KSTAT_WRITE) {
		simplect_dm = sdbc_dynmem->ci_sdbc_simplect.value.ul;
		local_dm_process_vars.monitor_dynmem_process =
		    sdbc_dynmem->ci_sdbc_monitor_dynmem.value.ul;
		local_dm_process_vars.max_dyn_list =
		    sdbc_dynmem->ci_sdbc_max_dyn_list.value.ul;
		local_dm_process_vars.cache_aging_ct1 =
		    sdbc_dynmem->ci_sdbc_cache_aging_ct1.value.ul;
		local_dm_process_vars.cache_aging_ct2 =
		    sdbc_dynmem->ci_sdbc_cache_aging_ct2.value.ul;
		local_dm_process_vars.cache_aging_ct3 =
		    sdbc_dynmem->ci_sdbc_cache_aging_ct3.value.ul;
		local_dm_process_vars.cache_aging_sec1 =
		    sdbc_dynmem->ci_sdbc_cache_aging_sec1.value.ul;
		local_dm_process_vars.cache_aging_sec2 =
		    sdbc_dynmem->ci_sdbc_cache_aging_sec2.value.ul;
		local_dm_process_vars.cache_aging_sec3 =
		    sdbc_dynmem->ci_sdbc_cache_aging_sec3.value.ul;
		local_dm_process_vars.cache_aging_pcnt1 =
		    sdbc_dynmem->ci_sdbc_cache_aging_pcnt1.value.ul;
		local_dm_process_vars.cache_aging_pcnt2 =
		    sdbc_dynmem->ci_sdbc_cache_aging_pcnt2.value.ul;
		local_dm_process_vars.max_holds_pcnt =
		    sdbc_dynmem->ci_sdbc_max_holds_pcnt.value.ul;
		local_dm_process_vars.process_directive =
		    sdbc_dynmem->ci_sdbc_process_directive.value.ul;
		(void) sdbc_edit_xfer_process_vars_dm(&local_dm_process_vars);

		if (process_vars->process_directive & WAKE_DEALLOC_THREAD_DM) {
			process_vars->process_directive &=
			    ~WAKE_DEALLOC_THREAD_DM;
			mutex_enter(&dynmem_processing_dm.thread_dm_lock);
			cv_broadcast(&dynmem_processing_dm.thread_dm_cv);
			mutex_exit(&dynmem_processing_dm.thread_dm_lock);
		}

		return (0);
	}

	/* default to READ */
	sdbc_dynmem->ci_sdbc_simplect.value.ul = simplect_dm;
	sdbc_dynmem->ci_sdbc_monitor_dynmem.value.ul =
	    process_vars->monitor_dynmem_process;
	sdbc_dynmem->ci_sdbc_max_dyn_list.value.ul =
	    process_vars->max_dyn_list;
	sdbc_dynmem->ci_sdbc_cache_aging_ct1.value.ul =
	    process_vars->cache_aging_ct1;
	sdbc_dynmem->ci_sdbc_cache_aging_ct2.value.ul =
	    process_vars->cache_aging_ct2;
	sdbc_dynmem->ci_sdbc_cache_aging_ct3.value.ul =
	    process_vars->cache_aging_ct3;
	sdbc_dynmem->ci_sdbc_cache_aging_sec1.value.ul =
	    process_vars->cache_aging_sec1;
	sdbc_dynmem->ci_sdbc_cache_aging_sec2.value.ul =
	    process_vars->cache_aging_sec2;
	sdbc_dynmem->ci_sdbc_cache_aging_sec3.value.ul =
	    process_vars->cache_aging_sec3;
	sdbc_dynmem->ci_sdbc_cache_aging_pcnt1.value.ul =
	    process_vars->cache_aging_pcnt1;
	sdbc_dynmem->ci_sdbc_cache_aging_pcnt2.value.ul =
	    process_vars->cache_aging_pcnt2;
	sdbc_dynmem->ci_sdbc_max_holds_pcnt.value.ul =
	    process_vars->max_holds_pcnt;
	sdbc_dynmem->ci_sdbc_process_directive.value.ul =
	    process_vars->process_directive;

	sdbc_dynmem->ci_sdbc_alloc_ct.value.ul = process_vars->alloc_ct;
	sdbc_dynmem->ci_sdbc_dealloc_ct.value.ul = process_vars->dealloc_ct;
	sdbc_dynmem->ci_sdbc_history.value.ul = process_vars->history;
	sdbc_dynmem->ci_sdbc_nodatas.value.ul = process_vars->nodatas;
	sdbc_dynmem->ci_sdbc_candidates.value.ul = process_vars->candidates;
	sdbc_dynmem->ci_sdbc_deallocs.value.ul = process_vars->deallocs;
	sdbc_dynmem->ci_sdbc_hosts.value.ul = process_vars->hosts;
	sdbc_dynmem->ci_sdbc_pests.value.ul = process_vars->pests;
	sdbc_dynmem->ci_sdbc_metas.value.ul = process_vars->metas;
	sdbc_dynmem->ci_sdbc_holds.value.ul = process_vars->holds;
	sdbc_dynmem->ci_sdbc_others.value.ul = process_vars->others;
	sdbc_dynmem->ci_sdbc_notavail.value.ul = process_vars->notavail;

	return (0);
}
#endif
