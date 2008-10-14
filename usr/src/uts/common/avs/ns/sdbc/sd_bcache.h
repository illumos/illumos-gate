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

#ifndef _SD_BCACHE_H
#define	_SD_BCACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DS_DDICT
#include <sys/nsctl/contract.h>
#endif
#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/sdbc_ioctl.h>
#include <sys/nsctl/sd_hash.h>
#include <sys/nsctl/sd_cache.h>
#include <sys/nsctl/sd_conf.h>
#include <sys/nsctl/safestore.h>

/*
 * Definitions for kstats
 */
#define	SDBC_KSTAT_CLASS	"storedge"
#define	SDBC_KSTAT_MODULE	"sdbc"

#ifdef DEBUG
#define	SDBC_KSTAT_DYNMEM	"dynmem"
#endif

#define	SDBC_KSTAT_CDNAME	"cdname"
#define	SDBC_KSTAT_CDSTATS	"cd"
#define	SDBC_KSTAT_GSTATS	"global"
#define	SDBC_KSTAT_STATS	"sdbcstats"
#define	SDBC_IOKSTAT_GSTATS	"gsdbc"
#define	SDBC_IOKSTAT_CDSTATS	"sdbc"

/* Global kstat field names */
#define	SDBC_GKSTAT_COUNT	"sdbc_count"
#define	SDBC_GKSTAT_LOC_COUNT	"sdbc_loc_count"
#define	SDBC_GKSTAT_RDHITS	"sdbc_rdhits"
#define	SDBC_GKSTAT_RDMISS	"sdbc_rdmiss"
#define	SDBC_GKSTAT_WRHITS	"sdbc_wrhits"
#define	SDBC_GKSTAT_WRMISS	"sdbc_wrmiss"
#define	SDBC_GKSTAT_BLKSIZE	"sdbc_blksize"
#define	SDBC_GKSTAT_LRU_BLOCKS	"sdbc_lru_blocks"

#ifdef DEBUG
#define	SDBC_GKSTAT_LRU_NOREQ	"sdbc_lru_noreq"
#define	SDBC_GKSTAT_LRU_REQ	"sdbc_lru_req"
#endif

#define	SDBC_GKSTAT_WLRU_INQ	"sdbc_wlru_inq"
#define	SDBC_GKSTAT_CACHESIZE	"sdbc_cachesize"
#define	SDBC_GKSTAT_NUMBLOCKS	"sdbc_numblocks"
#define	SDBC_GKSTAT_NUM_SHARED	"sdbc_num_shared"
#define	SDBC_GKSTAT_WRCANCELNS	"sdbc_wrcancelns"
#define	SDBC_GKSTAT_DESTAGED	"sdbc_destaged"
#define	SDBC_GKSTAT_NODEHINTS	"sdbc_nodehints"

/* per-cache descriptor kstats field names */
#define	SDBC_CDKSTAT_VOL_NAME	"sdbc_vol_name"
#define	SDBC_CDKSTAT_FAILED	"sdbc_failed"
#define	SDBC_CDKSTAT_CD		"sdbc_cd"
#define	SDBC_CDKSTAT_CACHE_READ	"sdbc_cache_read"
#define	SDBC_CDKSTAT_CACHE_WRITE	"sdbc_cache_write"
#define	SDBC_CDKSTAT_DISK_READ	"sdbc_disk_read"
#define	SDBC_CDKSTAT_DISK_WRITE	"sdbc_disk_write"
#define	SDBC_CDKSTAT_FILESIZE	"sdbc_filesize"
#define	SDBC_CDKSTAT_NUMDIRTY	"sdbc_numdirty"
#define	SDBC_CDKSTAT_NUMIO	"sdbc_numio"
#define	SDBC_CDKSTAT_NUMFAIL	"sdbc_numfail"
#define	SDBC_CDKSTAT_DESTAGED	"sdbc_destaged"
#define	SDBC_CDKSTAT_WRCANCELNS	"sdbc_wrcancelns"
#define	SDBC_CDKSTAT_CDHINTS	"sdbc_cdhints"

#ifdef DEBUG
/* dynmem kstats field names */
#define	SDBC_DMKSTAT_MONITOR_DYNMEM	"sdbc_monitor_dynmem"
#define	SDBC_DMKSTAT_MAX_DYN_LIST	"sdbc_max_dyn_list"
#define	SDBC_DMKSTAT_CACHE_AGING_CT1	"sdbc_cache_aging_ct1"
#define	SDBC_DMKSTAT_CACHE_AGING_CT2	"sdbc_cache_aging_ct2"
#define	SDBC_DMKSTAT_CACHE_AGING_CT3	"sdbc_cache_aging_ct3"
#define	SDBC_DMKSTAT_CACHE_AGING_SEC1	"sdbc_cache_aging_sec1"
#define	SDBC_DMKSTAT_CACHE_AGING_SEC2	"sdbc_cache_aging_sec2"
#define	SDBC_DMKSTAT_CACHE_AGING_SEC3	"sdbc_cache_aging_sec3"
#define	SDBC_DMKSTAT_CACHE_AGING_PCNT1	"sdbc_cache_aging_pcnt1"
#define	SDBC_DMKSTAT_CACHE_AGING_PCNT2	"sdbc_cache_aging_pcnt2"
#define	SDBC_DMKSTAT_MAX_HOLDS_PCNT	"sdbc_max_holds_pcnt"
#define	SDBC_DMKSTAT_ALLOC_CNT		"sdbc_alloc_cnt"
#define	SDBC_DMKSTAT_DEALLOC_CNT	"sdbc_dealloc_cnt"
#define	SDBC_DMKSTAT_HISTORY		"sdbc_history"
#define	SDBC_DMKSTAT_NODATAS		"sdbc_nodatas"
#define	SDBC_DMKSTAT_CANDIDATES		"sdbc_candidates"
#define	SDBC_DMKSTAT_DEALLOCS		"sdbc_deallocs"
#define	SDBC_DMKSTAT_HOSTS		"sdbc_hosts"
#define	SDBC_DMKSTAT_PESTS		"sdbc_pests"
#define	SDBC_DMKSTAT_METAS		"sdbc_metas"
#define	SDBC_DMKSTAT_HOLDS		"sdbc_holds"
#define	SDBC_DMKSTAT_OTHERS		"sdbc_others"
#define	SDBC_DMKSTAT_NOTAVAIL		"sdbc_notavail"
#define	SDBC_DMKSTAT_PROCESS_DIRECTIVE	"sdbc_process_directive"
#define	SDBC_DMKSTAT_SIMPLECT		"sdbc_simplect"

#endif

/* ... values are in range [0-BLK_FBAS] */
typedef uint32_t sdbc_cblk_fba_t; /* FBA len or offset in cache block */

typedef	unsigned char *ucaddr_t; /* unsigned char pointer */

/*
 * Atomic exchange function
 */

#ifdef _KERNEL

/*
 * Note: ldstub sets all bits in the memory byte.
 * so far this is compatible with the usage of xmem_bu() whereby
 * the values of ptr are either 0 or 1, and the xmem_bu() is used
 * to set the byte to 1.
 */
#define	xmem_bu(val, ptr)	nsc_ldstub((uint8_t *)ptr)
#define	atomic_swap		xmem_bu
#define	sd_serialize		nsc_membar_stld

#endif /* _KERNEL */

#if defined(_KERNEL) || defined(_KMEMUSER)

#if defined(_SD_8K_BLKSIZE)
typedef unsigned short	_sd_bitmap_t;
#else
typedef unsigned char	_sd_bitmap_t;
#endif

/*
 * CCTL flag types
 */

/*
 * Note: CC_INUSE and CC_PAGEIO are dummy flags that are used in
 * individual flags bytes (cc_inuse and cc_pageio) NOT cc_flag.
 * Thus they can take any convenient value, however, they must be
 * distinct and non-zero.
 */
#define	CC_INUSE 	0x01	/* Cache entry is in use */
#define	CC_PAGEIO 	0x02	/* Pagelist IO is active for cache entry */

/*
 * Real cc_flag values.
 */
#define	CC_PEND_DIRTY	0x02    /* The entry needs to be reprocessed for io */
#define	CC_PINNED	0x04	/* The entry has data that is "pinned" */
#define	CC_PINNABLE	0x08	/* Issue pin if write fails */
#define	CC_QHEAD	0x10	/* NSC_NOCACHE: requeue at head */

/* specify the size of _sd_cctl[] array */
#define	_SD_CCTL_GROUPS 32

/*
 * Individual SDBC cache block entry
 *	"cc_lock" must be held when changing dirty/valid bits.
 *	"cc_inuse" (optimistic) atomic exchange replaces check/set of
 *	  CC_INUSE bit in cc_flag; special handling of rare collisions.
 *	"cc_pageio" flusher / client locking of pagelist io operations,
 *	  atomic exchange - needs machine ld/st protection.
 *	"cc_iostatus" is set by flusher without holding cc_lock,
 *	  writer will set CC_PEND_DIRTY if cc_iostatus is set.
 * Thus "cc_inuse", "cc_iostatus" and "cc_pageio" are volatile.
 *
 * The cc_await_* values are in the main _sd_cctl to avoid over
 * signalling _cc_blkcv.
 *
 * The _sd_cctl structure is aligned to group related members and
 * to ensure good packing.
 */

typedef struct _sd_cctl_sync {
	kcondvar_t	_cc_blkcv;	/* Synchronisation var to block on */
	kmutex_t	_cc_lock;	/* Cache entry spinlock		*/
} _sd_cctl_sync_t;

typedef struct sd_addr_s {		/* Generic address structure */
	unsigned char 	*sa_virt;	/* Virtual address of data */
} sd_addr_t;

/*
 * See notes above.
 */

typedef struct _sd_cctl {
	_sd_hash_hd_t cc_head;		/* hash information - must be first */
	struct _sd_cctl *cc_next, *cc_prev; /* next and prev in a chain */
	struct _sd_cctl *cc_chain;	/* chaining request centries */
	struct _sd_cctl *cc_dirty_next; /* for chaining sequential writes */
	struct _sd_cctl *cc_dirty_link; /* for chaining the dirty lists   */
	struct _sd_cctl *cc_dirty_net_next; /* for chaining net writes */
	struct _sd_cctl *cc_dirty_net_link; /* for chaining net lists   */
	uint_t		cc_seq;		/* sequence number: for lru optim */
	volatile int	net_iostatus;	/* net status of io 	*/
	volatile _sd_bitmap_t net_dirty; /* net cache block dirty mask */
	_sd_bitmap_t	cc_valid;	/* Cache block valid mask	   */
	_sd_bitmap_t	cc_toflush;	/* Cache block deferred dirty mask */
	volatile _sd_bitmap_t cc_dirty;	/* Cache block dirty mask	   */
	volatile ushort_t cc_await_use;	/* # waiting for this entry (inuse) */
	volatile ushort_t cc_await_page; /* # waiting for this entry (pageio) */
	volatile uchar_t cc_inuse;	/* atomic_swap(CC_INUSE, cc_inuse) */
	volatile uchar_t cc_pageio;	/* atomic_swap(CC_PAGEIO, cc_pageio) */
	uchar_t		cc_flag;	/* flag */
	char		cc_iocount;	/* number of ios in progress */
	volatile uchar_t cc_iostatus;	/* status of io		   */
	uchar_t		cc_prot;	/* Segmented LRU protection flag   */
	sd_addr_t	cc_addr;	/* Data address information	   */
	ss_centry_info_t  *cc_write;	/* mirrored writes control block */
	struct _sd_cctl_sync *cc_sync;	/* Cache block synchronisation blk */

	/* support for backend i/o memory coalescing */
	sd_addr_t	cc_anon_addr;	/* address for backend mem coalescing */
	int		cc_anon_len;	/* length of anon mem */

	clock_t		cc_creat;
	int		cc_hits;

	/* dynamic memory support fields */
	uint_t			cc_aging_dm;		/* For bit settings */
							/* see defines */
	int			cc_alloc_size_dm;	/* mem allocation */
							/* size bytes */
	struct _sd_cctl	*cc_head_dm;			/* ptr to host centry */
							/* for a host/pest */
							/* chain */
	struct _sd_cctl	*cc_next_dm;			/* ptr to next centry */
							/* in host/pest chain */
	struct _sd_cctl	*cc_link_list_dm;		/* simple link list */
							/* ptr of all centrys */
	/* dynmem chains */
	/* _sd_queue_t	*cc_dmchain_q;	dmqueue */
	int		cc_cblocks;	/* number of centrys for size_dm */

	/* debugging stats */
	int			cc_alloc_ct_dm;
	int			cc_dealloc_ct_dm;

} _sd_cctl_t;

/* cache entry allocation tokens */
typedef struct sdbc_allocbuf_s {
	intptr_t opaque[2]; /* must be initialized to 0 */
} sdbc_allocbuf_t;

typedef struct sdbc_allocbuf_impl_s {
	_sd_cctl_t *sab_dmchain;
	int sab_q; /* dmqueue of last chain allocated */
	int reserved;  /* stats ? */
} sdbc_allocbuf_impl_t;

/*
 * bits for flag argument to sdbc_centry_alloc() and callees.
 */
#define	ALLOC_LOCKED		0x1	/* locked status of sdbc_queue_lock */
#define	ALLOC_NOWAIT		0x2	/* do not block, return NULL */

/*
 * definitions supporting the dynmem dealloc thread
 */
#define	LOW_RESOURCES_DM		-1

#define	NO_THREAD_DM			-1
#define	PROCESS_CACHE_DM		0
#define	CACHE_SHUTDOWN_DM		1
#define	CACHE_THREAD_TERMINATED_DM	2
#define	TIME_DELAY_LVL0			3
#define	TIME_DELAY_LVL1			4
#define	TIME_DELAY_LVL2			5
#define	HISTORY_LVL0			(ushort_t)0
#define	HISTORY_LVL1			(ushort_t)0x00ff
#define	HISTORY_LVL2			(ushort_t)0xff00
/*
 * definitions supporing the ddditional fields in the cache
 * entry structure for dyn mem
 */
#define	FIRST_AGING_DM		0x00000001
#define	FINAL_AGING_DM		0x000000ff
#define	FOUND_IN_HASH_DM	0x00000100	/* used to bring cent info */
						/* out of sd_centry_alloc() */
#define	FOUND_HOLD_OVER_DM	0x00000200	/* used to bring cent info */
						/* out of sd_centry_alloc() */
#define	HOST_ENTRY_DM		0x00000400
#define	PARASITIC_ENTRY_DM	0x00000800
#define	STICKY_METADATA_DM	0x00001000
#define	CATAGORY_ENTRY_DM	(HOST_ENTRY_DM|PARASITIC_ENTRY_DM| \
				    STICKY_METADATA_DM)
#define	ELIGIBLE_ENTRY_DM	0x00002000
#define	HASH_ENTRY_DM		0x00008000
#define	HOLD_ENTRY_DM		0x00010000
#define	ENTRY_FIELD_DM		(ELIGIBLE_ENTRY_DM|HASH_ENTRY_DM|HOLD_ENTRY_DM)
#define	AVAIL_ENTRY_DM		0x00020000

/* info only */
#define	PREFETCH_BUF_I		0x00040000	/* implicit read-ahead */
#define	PREFETCH_BUF_E		0x00080000	/* explicit read-ahead */
#define	PREFETCH_BUF_IR		0x00100000	/* release when read complete */

/* error processing */
#define	BAD_ENTRY_DM		0x20000000 /* inconsistent ccent */
#define	BAD_CHAIN_DM		0x40000000 /* chain containing bad ccent */

/*
 * definitions supporting the dynmem monitoring
 */
#define	RPT_SHUTDOWN_PROCESS_DM	0x00000001
#define	RPT_DEALLOC_STATS1_DM	0x00000002	/* nodat,cand,host,pest,meta, */
						/* other,dealloc */
#define	RPT_DEALLOC_STATS2_DM	0x00000004 /* hysterisis,grossct */
/*
 * definitions supporting the processing directive bit flags
 */
#define	WAKE_DEALLOC_THREAD_DM		0x00000001	/* one shot - acted */
							/* on then cleared */
#define	MAX_OUT_ACCEL_HIST_FLAG_DM	0x00000002	/* one shot - acted */
							/* on then cleared */
/*
 * Default - Max - Min definitions
 */
#define	MAX_DYN_LIST_DEFAULT		8
#define	MONITOR_DYNMEM_PROCESS_DEFAULT	0
#define	CACHE_AGING_CT_DEFAULT		3
#define	CACHE_AGING_SEC1_DEFAULT	10
#define	CACHE_AGING_SEC2_DEFAULT	5
#define	CACHE_AGING_SEC3_DEFAULT	1
#define	CACHE_AGING_PCNT1_DEFAULT	50
#define	CACHE_AGING_PCNT2_DEFAULT	25
#define	MAX_HOLDS_PCNT_DEFAULT		0
#define	PROCESS_DIRECTIVE_DEFAULT	0

#define	CACHE_AGING_CT_MAX	FINAL_AGING_DM	/* 255 */
#define	CACHE_AGING_SEC1_MAX	255	/* arbitrary but easy to remember */
#define	CACHE_AGING_SEC2_MAX	255	/* arbitrary but easy to remember */
#define	CACHE_AGING_SEC3_MAX	255	/* arbitrary but easy to remember */
#define	CACHE_AGING_PCNT1_MAX	100
#define	CACHE_AGING_PCNT2_MAX	100
#define	MAX_HOLDS_PCNT_MAX	100
/*
 * dynmem global structure defn
 */
typedef struct _dm_process_vars {
	kcondvar_t	thread_dm_cv;
	kmutex_t	thread_dm_lock;
	int	sd_dealloc_flagx; 	/* gen'l purpose bit flag */
	int	monitor_dynmem_process; /* bit flag indicating what to report */
	int	max_dyn_list;		/* max num of pages to allow list to */
					/* grow */
	/* cache aging parameter set */
	int	cache_aging_ct1;	/* hosts/pests - aging hits which */
					/* trigger dealloc */
	int	cache_aging_ct2;	/* metas - aging hits which */
					/* trigger dealloc not yet imple */
	int	cache_aging_ct3;	/* holds - aging hits which */
					/* trigger dealloc */
	int	cache_aging_sec1;	/* sleep time between cache list */
					/* exam - 100% to pcnt1 free */
	int	cache_aging_sec2;	/* sleep time between cache list */
					/* exam - pcnt1 to pcnt2 free */
	int	cache_aging_sec3;	/* sleep time between cache list */
					/* exam - pcnt2 to 0% free */
	int	cache_aging_pcnt1;	/* % free when to kick in accel */
					/* aging - sec2 */
	int	cache_aging_pcnt2;	/* % free when to kick in accel */
					/* aging - sec3 */
	int	max_holds_pcnt;		/* max % of cents to act as holdovers */
	/* stats - debug */
	int	alloc_ct;		/* gross count */
	int	dealloc_ct;		/* gross count */
	/* thread stats - debug and on the fly tuning of dealloc vars */
	int	history;		/* history flag */
	int	nodatas;		/* # cctls w/o data assigned */
	int	notavail;		/* # cctls w/data but in use */
	int	candidates;		/* # cand. for dealloc checking */
	int	deallocs;		/* # deallocs */
	int	hosts;			/* # hosts */
	int	pests;			/* # pests */
	int	metas;			/* # metas - sticky meata data */
	int	holds;			/* # holdovers - single page, fully */
					/* aged but not dealloc'd or hash */
					/* del'd */
	int	others;			/* # everybody else */
	int	process_directive;	/* processing directive bitmap flag */
	/* standard stats (no prefetch tallies here) */
	int	read_hits;		/* found in cache memory */
	int	read_misses;		/* not found in cache memory */
	int	write_hits;		/* found in cache memory */
	int	write_misses;		/* not found in cache memory */
	int	write_thru;		/* not bothering to put in cache mem */
	/*
	 * prefetch tracked by _sd_prefetch_valid_cnt and _sd_prefetch_busy_cnt
	 * might want different usage ?
	 */
	int	prefetch_hits;
	int	prefetch_misses;
} _dm_process_vars_t;

/*
 * dynmem interface
 */
int sdbc_edit_xfer_process_vars_dm(_dm_process_vars_t *process_vars);

/*
 * Defines to hide the sd_addr_t structure
 */

#define	cc_data		cc_addr.sa_virt


/*
 * Defines to hide the synchronisation block
 */

#define	cc_blkcv	cc_sync->_cc_blkcv
#define	cc_lock		cc_sync->_cc_lock

/*
 * This struct exists solely so that sd_info is able to
 * extract this kind of data from sdbc without passing out
 * the entire _sd_cctl_t which has lots of pointers which
 * makes it impossible to deal with in 32bit program and an
 * LP64 kernel.
 */

typedef struct {
	int		ci_write;	/* 0 == no wrt data */
	_sd_bitmap_t	ci_dirty;	/* dirty bits */
	_sd_bitmap_t	ci_valid;	/* valid bits */
	int		ci_cd;		/* the cd */
	nsc_off_t	ci_dblk;	/* the disk block number */
} sdbc_info_t;

typedef struct _sd_wr_cctl {
	ss_resource_t wc_res;
	ss_centry_info_t wc_centry_info;
} _sd_wr_cctl_t;

typedef struct _sd_queue {
	struct _sd_cctl sq_qhead;	/* LRU queue head */
	kmutex_t   sq_qlock;		/* LRU spinlock	  */
	char	   sq_await;		/* number blocked on lru sema */
	int	   sq_inq;		/* Number of LRU entries in q */
	unsigned int sq_seq;		/* sequence number for lru optim */
	unsigned int sq_req_stat;
	unsigned int sq_noreq_stat;

	/* dmchain support */
	int	sq_dmchain_cblocks;	/* dmchain len in ccents */
} _sd_queue_t;



/*
 * The net structure contains which memory net has been configured for
 * cache, the amount of space allocated, the write control and fault
 * tolerant blocks etc
 */

typedef struct _sd_net {
	unsigned short	sn_psize;	/* Page size of memory in this net */
	unsigned char	sn_configured;	/* is this network configured */
	size_t	sn_csize;		/* Cache size in bytes */
	uint_t	sn_wsize;		/* Write size in bytes */
	int 	sn_cpages;		/* number of pages for Cache	  */
}_sd_net_t;

#endif /* _KERNEL || _KMEMUSER */


/*
 * Shared structure shared between cds and statistics
 *
 * NOTE - this structure is visible as an ioctl result.
 * If anything changes here _sd_get_stats() and convert_stats()
 * will need to be changed.
 */
typedef struct _sd_shared {
	nsc_size_t sh_filesize;		/* Filesize  (in FBAs) */
	volatile uchar_t sh_alloc;	/* Is this allocated? */
	volatile uchar_t sh_failed;	/* Disk failure status (0 == ok, */
					/* 1 == i/o error, 2 == open failed ) */
	unsigned short sh_cd;		/* the cache descriptor. (for stats) */
	int sh_cache_read;		/* Number of FBAs read from cache */
	int sh_cache_write;		/* Number of FBAs written  to cache */
	int sh_disk_read;		/* Number of FBAs read from disk */
	int sh_disk_write;		/* Number of FBAs written  to disk */
	volatile int sh_numdirty;	/* Number of dirty blocks */
	volatile int sh_numio;		/* Number of blocks on way to disk */
	volatile int sh_numfail;	/* Number of blocks failed */
	int sh_flushloop;		/* Loops delayed so far */
	int sh_flag;			/* Flags visible to user programs    */
	int sh_destaged;		/* number of bytes destaged to disk */
	int sh_wrcancelns;		/* number of writes to dirty blocks */
	char sh_filename[NSC_MAXPATH];
} _sd_shared_t;


#if defined(_KERNEL) || defined(_KMEMUSER)

/*
 * Cache descriptor information.
 */
typedef struct _sd_cd_info {
	int cd_desc;			/* The cache descriptor		*/
	int cd_flag;			/* Flag				*/
	nsc_fd_t *cd_rawfd;		/* File descriptor for raw device */
	strategy_fn_t cd_strategy;	/* Cached copy of strategy func */
	dev_t cd_crdev;			/* The device this represents	*/
	nsc_iodev_t *cd_iodev;		/* I/O device for callbacks	*/
	kmutex_t cd_lock; 		/* spinlock guarding this cd	*/
	volatile uchar_t  cd_writer;	/* Disk writer status		*/
	unsigned int  cd_hint;		/* Hints for this descriptor	*/
	ss_voldata_t *cd_global;  /* RM information for this cd   */
	struct _sd_cctl *cd_dirty_head, *cd_dirty_tail;	/* dirty chain	*/
	struct _sd_cctl *cd_last_ent;	/* last entry in dirty chain, for */
	int cd_lastchain;		/* sequential optimization	*/
	struct _sd_cctl *cd_lastchain_ptr; /* last sequential chain	*/
	struct _sd_cctl *cd_io_head, *cd_io_tail; /* io in progress q	*/
	struct _sd_cctl *cd_fail_head;
	struct _sd_shared *cd_info;	/* shared info (filename, size)  */
	char cd_failover;		/* done nsc_reserve during failover */
	volatile char cd_recovering;    /* cd is being recovered failover or */
					/* disk_online */
	char cd_write_inprogress;
	struct sd_net_hnd *net_hnd;
} _sd_cd_info_t;

typedef struct _sd_buf_hlist {
	_sd_buf_handle_t hl_top;
	kmutex_t hl_lock;
	short   hl_count;
} _sd_buf_hlist_t;

#endif /* _KERNEL || _KMEMUSER */

/*
 * Index into the following st_mem_sizes[] array
 */
#define	_SD_LOCAL_MEM 	0x00	/* type of memory to allocate */
#define	_SD_CACHE_MEM	0x01
#define	_SD_IOBUF_MEM	0x02
#define	_SD_HASH_MEM	0x03
#define	_SD_GLOBAL_MEM 	0x04
#define	_SD_STATS_MEM 	0x05
#define	_SD_MAX_MEM	_SD_STATS_MEM + 1

/* maintain stat struct layout */
#define	NUM_WQ_PAD 4
/*
 * cache statistics structure
 *
 * NOTE - if anything changes here _sd_get_stats() and convert_stats()
 * must be changed and _sd_stats32_t must also be synchronized.
 *
 */
typedef struct _sd_stats {
	int net_dirty;
	int net_pending;
	int net_free;
	int st_count;			/* number of opens for device	*/
	int st_loc_count;		/* number of open devices	*/
	int st_rdhits;			/* number of read hits		*/
	int st_rdmiss;			/* number of read misses	*/
	int st_wrhits;			/* number of write hits		*/
	int st_wrmiss;			/* number of write misses	*/
	int st_blksize;			/* cache block size (in bytes)	*/
	uint_t st_lru_blocks;
	uint_t st_lru_noreq;
	uint_t st_lru_req;
	int st_wlru_inq;		/* number of write blocks	*/
	int st_cachesize;		/* cache size (in bytes)	*/
	int st_numblocks;		/* # of cache blocks		*/
	int st_wrcancelns;		/* # of write cancellations	*/
	int st_destaged;		/* # of bytes destaged to disk	*/
	_sd_shared_t st_shared[1];	/* shared structures		*/
} _sd_stats_t;

typedef struct _sd_stats_32 {
	int net_dirty;
	int net_pending;
	int net_free;
	int st_count;			/* number of opens for device	*/
	int st_loc_count;		/* number of open devices	*/
	int st_rdhits;			/* number of read hits		*/
	int st_rdmiss;			/* number of read misses	*/
	int st_wrhits;			/* number of write hits		*/
	int st_wrmiss;			/* number of write misses	*/
	int st_blksize;			/* cache block size (in bytes)	*/
	uint_t st_lru_blocks;
	uint_t st_lru_noreq;
	uint_t st_lru_req;
	int st_wlru_inq;		/* number of write blocks	*/
	int st_cachesize;		/* cache size (in bytes)	*/
	int st_numblocks;		/* # of cache blocks		*/
	int st_wrcancelns;		/* # of write cancellations	*/
	int st_destaged;		/* # of bytes destaged to disk	*/
	_sd_shared_t st_shared[1];	/* shared structures		*/
} _sd_stats32_t;


#if defined(_KERNEL) || defined(_KMEMUSER)

/*
 * The map structure contains mapping between a mask and relevent information
 * that would take some computation at runtime.
 * Given a mask, what is the first LSB set (stpos)
 * Given a mask, what are the consecutive number of LSB bits set (len)
 * Given a mask, what would be a new mask if the consecutive LSB bits are reset
 * Given a mask, how many ios would be needed to flush this block.
 * Given a mask, how many buffer descriptor lists (bdls) would be needed
 *	on a read.
 */

typedef struct _sd_map_info {
	unsigned char mi_stpos;		/* position of first LSB set	*/
	unsigned char mi_len;		/* Length of consecutive LSB set */
	unsigned char mi_dirty_count;	/* number of fragmented bits	*/
	unsigned char mi_io_count;	/* number of bdls for a given mask */
	_sd_bitmap_t  mi_mask;		/* new mask with cons. LSB's reset */
} _sd_map_info_t;


/*
 * cc_inuse is set with atomic exchange instruction
 * when clearing, must check for waiters.
 * sd_serialize prohibits speculative reads
 */
#define	CENTRY_INUSE(centry)	((centry)->cc_inuse)
#define	SET_CENTRY_INUSE(centry) \
	((centry)->cc_inuse || atomic_swap(CC_INUSE, &(centry)->cc_inuse))
#define	CLEAR_CENTRY_INUSE(centry) { \
	(centry)->cc_inuse = 0; \
	sd_serialize(); \
	if ((centry)->cc_await_use) { \
		mutex_enter(&(centry)->cc_lock); \
		cv_broadcast(&(centry)->cc_blkcv); \
		mutex_exit(&(centry)->cc_lock); \
	} \
}


/*
 * cc_pageio is set with atomic exchange instruction
 * when clearing, must check for waiters.
 * sd_serialize prohibits speculative reads
 */
#define	CENTRY_PAGEIO(centry)	((centry)->cc_pageio)
#define	SET_CENTRY_PAGEIO(centry) \
	((centry)->cc_pageio || atomic_swap(CC_PAGEIO, &(centry)->cc_pageio))
#define	WAIT_CENTRY_PAGEIO(centry, stat) { \
	while (SET_CENTRY_PAGEIO(centry)) { \
		(stat)++; \
		_sd_cc_wait(CENTRY_CD(centry), CENTRY_BLK(centry), \
			centry, CC_PAGEIO); \
	} \
}
#define	CLEAR_CENTRY_PAGEIO(centry) { \
	(centry)->cc_pageio = 0; \
	sd_serialize(); \
	if ((centry)->cc_await_page) { \
		mutex_enter(&(centry)->cc_lock); \
		cv_broadcast(&(centry)->cc_blkcv); \
		mutex_exit(&(centry)->cc_lock); \
	} \
}


#define	CENTRY_DIRTY_PENDING(centry)	((centry)->cc_flag & CC_PEND_DIRTY)
#define	CENTRY_PINNED(centry)	((centry)->cc_flag & CC_PINNED)
#define	CENTRY_PINNABLE(centry)	((centry)->cc_flag & CC_PINNABLE)
#define	CENTRY_QHEAD(centry)	((centry)->cc_flag & CC_QHEAD)

#define	CENTRY_DIRTY(centry)	((centry)->cc_dirty)
#define	CENTRY_CD(centry)	((centry)->cc_head.hh_cd)
#define	CENTRY_BLK(centry)	((centry)->cc_head.hh_blk_num)
#define	CENTRY_IO_INPROGRESS(centry)	((centry)->cc_iostatus)

#define	HANDLE_CD(handle)		((handle)->bh_cd)

#endif /* _KERNEL || _KMEMUSER */

#if defined(_KERNEL)

#define	CENTRY_SET_FTPOS(centry) \
	(centry)->cc_write->sc_cd = CENTRY_CD(centry), \
	(centry)->cc_write->sc_fpos = CENTRY_BLK(centry)

#define	CC_CD_BLK_MATCH(cd, blk, centry)  \
	(((centry)->cc_head.hh_cd == cd) && \
	((centry)->cc_head.hh_blk_num == blk))


#define	_SD_ZEROADDR	((ucaddr_t)(_sd_net_config.sn_zeroaddr))


#define	ASSERT_LEN(len) \
	if (len > _SD_MAX_FBAS) {\
		cmn_err(CE_WARN, \
		    "sdbc(ASSERT_LEN) fba exceeds limits. fba_len %" NSC_SZFMT \
		    ". Max %d", len, _SD_MAX_FBAS); \
		return (EIO);    }

#define	ASSERT_IO_SIZE(fba_num, fba_len, cd) \
	if ((fba_num + fba_len) > \
	    (_sd_cache_files[(cd)].cd_info->sh_filesize)) { \
		cmn_err(CE_WARN, \
		    "sdbc(ASSERT_IO_SIZE) io beyond end of file." \
		    " fpos %" NSC_SZFMT " len %" NSC_SZFMT " file size 0 - %" \
		    NSC_SZFMT "\n", fba_num, fba_len, \
		    (_sd_cache_files[(cd)].cd_info->sh_filesize)); \
		return (EIO); \
	}


#define	ASSERT_HANDLE_LIMITS(m_h1, m_fpos, m_flen) \
	if (((m_fpos) < (m_h1)->bh_fba_pos) || \
	    (((m_fpos) + (m_flen)) > \
	    ((m_h1)->bh_fba_pos + (m_h1)->bh_fba_len))) { \
		cmn_err(CE_WARN, \
		    "sdbc(ASSERT_HANDLE_LIMITS) operation out of bounds" \
		    " cd %x want %" NSC_SZFMT " to %" NSC_SZFMT ". Handle %" \
		    NSC_SZFMT " to %" NSC_SZFMT, HANDLE_CD(m_h1), m_fpos,\
		    m_flen, (m_h1)->bh_fba_pos, (m_h1)->bh_fba_len); \
		return (EINVAL); \
	}


#define	_SD_HANDLE_ACTIVE(handle)	((handle)->bh_flag & NSC_HACTIVE)

#define	_SD_CD_HINTS(cd)	(_sd_cache_files[(cd)].cd_hint)
#define	_SD_NODE_HINTS		(_sd_node_hint)

#define	_SD_SETUP_HANDLE(hndl, cd, fpos, flen, flag) { \
		hndl->bh_cd = cd; \
		hndl->bh_vec = hndl->bh_bufvec; \
		hndl->bh_fba_pos = fpos; \
		hndl->bh_fba_len = flen; \
		hndl->bh_busy_thread = nsc_threadp(); \
		if (cd == _CD_NOHASH) \
			hndl->bh_flag |= \
			    (flag | _SD_NODE_HINTS | NSC_HACTIVE); \
		else \
			hndl->bh_flag |= \
			    (flag | _SD_CD_HINTS(cd) | \
			    _SD_NODE_HINTS | NSC_HACTIVE); \
	}

#define	_SD_NOT_WRTHRU(handle)  (((handle)->bh_flag & _SD_WRTHRU_MASK) == 0)
#define	_SD_IS_WRTHRU(handle)   ((handle)->bh_flag & _SD_WRTHRU_MASK)

#define	FILE_OPENED(cd)	(((cd) >= 0) && ((cd) < (sdbc_max_devs)) && \
			(_sd_cache_files[(cd)].cd_info != NULL) && \
			(_sd_cache_files[(cd)].cd_info->sh_alloc \
			& CD_ALLOCATED))

/*
 * bitmap stuff
 */

#define	SDBC_LOOKUP_STPOS(mask)	(_sd_lookup_map[(mask)].mi_stpos)
#define	SDBC_LOOKUP_LEN(mask)	(_sd_lookup_map[(mask)].mi_len)
#define	SDBC_LOOKUP_MASK(mask)	(_sd_lookup_map[(mask)].mi_mask)
#define	SDBC_LOOKUP_DTCOUNT(mask) (_sd_lookup_map[(mask)].mi_dirty_count)
#define	SDBC_LOOKUP_IOCOUNT(mask) (_sd_lookup_map[(mask)].mi_io_count)
#define	SDBC_LOOKUP_MODIFY(mask) (mask &= ~(_sd_lookup_map[(mask)].mi_mask))

#define	SDBC_IS_FRAGMENTED(bmap)	(!_sd_contig_bmap[(bmap)])
#define	SDBC_IS_CONTIGUOUS(bmap)	(_sd_contig_bmap[(bmap)])

#endif /* _KERNEL */

#if defined(_KERNEL) || defined(_KMEMUSER)

#define	SDBC_GET_BITS(fba_off, fba_len) \
	(_fba_bits[(fba_len)] << (fba_off))

#define	SDBC_SET_VALID_BITS(fba_off, fba_len, cc_entry) \
	(cc_entry)->cc_valid |= SDBC_GET_BITS(fba_off, fba_len)

#define	SDBC_SET_DIRTY(fba_off, fba_len, cc_entry) { \
	_sd_bitmap_t dirty, newdb = SDBC_GET_BITS(fba_off, fba_len); \
	ss_centry_info_t *gl = (cc_entry)->cc_write; \
	(cc_entry)->cc_valid |= newdb; \
	dirty = ((cc_entry)->cc_dirty |= newdb);  \
	gl->sc_dirty = dirty; \
	gl->sc_flag = (int)(cc_entry)->cc_flag;	\
	SSOP_SETCENTRY(sdbc_safestore, gl); }

#define	SDBC_SET_TOFLUSH(fba_off, fba_len, cc_entry) { \
	_sd_bitmap_t dirty, newdb = SDBC_GET_BITS(fba_off, fba_len); \
	ss_centry_info_t *gl = (cc_entry)->cc_write; \
	(cc_entry)->cc_toflush |= newdb; \
	(cc_entry)->cc_valid |= newdb;  \
	dirty = (cc_entry)->cc_toflush | (cc_entry)->cc_dirty; \
	gl->sc_dirty = dirty;	\
	SSOP_SETCENTRY(sdbc_safestore, gl); }

#define	SDBC_VALID_BITS(fba_off, fba_len, cc_entry) \
	((((cc_entry)->cc_valid) & (SDBC_GET_BITS(fba_off, fba_len))) \
	== (SDBC_GET_BITS(fba_off, fba_len)))


#define	SDBC_DIRTY_NEIGHBORS(last, next) \
	((SDBC_IS_CONTIGUOUS((last)->cc_dirty)) && \
	(SDBC_IS_CONTIGUOUS((next)->cc_dirty)) && \
(((last)->cc_dirty & (1 << (BLK_FBAS - 1))) && ((next)->cc_dirty & 0x01)))


#define	FULLY_VALID(cc_entry)	((cc_entry)->cc_valid == BLK_FBA_BITS)
#define	SET_FULLY_VALID(cc_entry) \
	((cc_entry)->cc_valid = BLK_FBA_BITS)

#define	FULLY_DIRTY(cc_entry)   ((cc_entry)->cc_dirty == BLK_FBA_BITS)

#define	_SD_BIT_ISSET(bmap, bit) 	((bmap & (1 << bit)) ? 1 : 0)
#define	_SD_BMAP_ISFULL(bmap)		(bmap == BLK_FBA_BITS)

#endif /* _KERNEL || _KMEMUSER */

#if defined(_KERNEL)

#if !defined(_SD_NOSTATS)
#define	CACHE_FBA_READ(cd, blks) \
	if (((cd) >= 0) && ((cd) < sdbc_max_devs))\
		_sd_cache_stats->st_shared[(cd)].sh_cache_read += (blks)
#define	DISK_FBA_READ(cd, blks) \
	if (((cd) >= 0) && ((cd) < sdbc_max_devs))\
		_sd_cache_stats->st_shared[(cd)].sh_disk_read += (blks)
#define	CACHE_FBA_WRITE(cd, blks) \
	if (((cd) >= 0) && ((cd) < sdbc_max_devs))\
		_sd_cache_stats->st_shared[(cd)].sh_cache_write += (blks)
#define	DISK_FBA_WRITE(cd, blks) \
	if (((cd) >= 0) && ((cd) < sdbc_max_devs))\
		_sd_cache_stats->st_shared[(cd)].sh_disk_write += (blks)
#define	CACHE_READ_HIT		_sd_cache_stats->st_rdhits++
#define	CACHE_READ_MISS		_sd_cache_stats->st_rdmiss++
#define	CACHE_WRITE_HIT		_sd_cache_stats->st_wrhits++
#define	CACHE_WRITE_MISS 	_sd_cache_stats->st_wrmiss++

#define	CACHE_WRITE_CANCELLATION(cd) {\
	if ((cd) < sdbc_max_devs)\
		_sd_cache_stats->st_shared[(cd)].sh_wrcancelns++;\
	_sd_cache_stats->st_wrcancelns++;\
}

#define	WRITE_DESTAGED(cd, bytes) {\
	if (((cd) >= 0) && ((cd) < sdbc_max_devs))\
		_sd_cache_stats->st_shared[(cd)].sh_destaged += (bytes);\
	_sd_cache_stats->st_destaged += (bytes);\
}

#define	FBA_READ_IO_KSTATS(cd, bytes) {\
	if (((cd) >= 0) && ((cd) < sdbc_max_devs) && sdbc_cd_io_kstats[(cd)]) {\
		KSTAT_IO_PTR(sdbc_cd_io_kstats[(cd)])->reads++;\
		KSTAT_IO_PTR(sdbc_cd_io_kstats[(cd)])->nread += (bytes);\
	}\
	if (sdbc_global_io_kstat) {\
		KSTAT_IO_PTR(sdbc_global_io_kstat)->reads++;\
		KSTAT_IO_PTR(sdbc_global_io_kstat)->nread += (bytes);\
	}\
}

#define	FBA_WRITE_IO_KSTATS(cd, bytes) {\
	if (((cd) >= 0) && ((cd) < sdbc_max_devs) && sdbc_cd_io_kstats[(cd)]) {\
		KSTAT_IO_PTR(sdbc_cd_io_kstats[(cd)])->writes++;\
		KSTAT_IO_PTR(sdbc_cd_io_kstats[(cd)])->nwritten += (bytes);\
	}\
	if (sdbc_global_io_kstat) {\
		KSTAT_IO_PTR(sdbc_global_io_kstat)->writes++;\
		KSTAT_IO_PTR(sdbc_global_io_kstat)->nwritten += (bytes);\
	}\
}

/* start timer measuring amount of time spent in the cache */
#define	KSTAT_RUNQ_ENTER(cd) {\
	if (((cd) >= 0) && ((cd) < sdbc_max_devs) && \
	    sdbc_cd_io_kstats[(cd)] && sdbc_cd_io_kstats_mutexes) {\
		mutex_enter(sdbc_cd_io_kstats[(cd)]->ks_lock);\
		kstat_runq_enter(KSTAT_IO_PTR(sdbc_cd_io_kstats[(cd)]));\
		mutex_exit(sdbc_cd_io_kstats[(cd)]->ks_lock);\
	}\
	if (sdbc_global_io_kstat) {\
		mutex_enter(sdbc_global_io_kstat->ks_lock);\
		kstat_runq_enter(KSTAT_IO_PTR(sdbc_global_io_kstat));\
		mutex_exit(sdbc_global_io_kstat->ks_lock);\
	}\
}

/* stop timer measuring amount of time spent in the cache */
#define	KSTAT_RUNQ_EXIT(cd) {\
	if (((cd) >= 0) && ((cd) < sdbc_max_devs) && \
	    sdbc_cd_io_kstats[(cd)] && sdbc_cd_io_kstats_mutexes) {\
		mutex_enter(sdbc_cd_io_kstats[(cd)]->ks_lock);\
		kstat_runq_exit(KSTAT_IO_PTR(sdbc_cd_io_kstats[(cd)]));\
		mutex_exit(sdbc_cd_io_kstats[(cd)]->ks_lock);\
	}\
	if (sdbc_global_io_kstat) {\
		mutex_enter(sdbc_global_io_kstat->ks_lock);\
		kstat_runq_exit(KSTAT_IO_PTR(sdbc_global_io_kstat));\
		mutex_exit(sdbc_global_io_kstat->ks_lock);\
	}\
}

#else
#define	CACHE_FBA_READ(cd, blks)
#define	DISK_FBA_READ(cd, blks)
#define	CACHE_FBA_WRITE(cd, blks)
#define	DISK_FBA_WRITE(cd, blks)
#define	CACHE_READ_HIT
#define	CACHE_READ_MISS
#define	CACHE_WRITE_HIT
#define	CACHE_WRITE_MISS
#define	CACHE_WRITE_CANCELLATION(cd)
#define	WRITE_DESTAGED(cd, bytes)
#endif

#endif /* _KERNEL */

/* defines for sh_alloc */

#define	CD_ALLOC_IN_PROGRESS 	0x0001
#define	CD_ALLOCATED		0x0002
#define	CD_CLOSE_IN_PROGRESS	0x0010

/* defines for sh_flag */

#define	CD_ATTACHED		0x0001

#ifdef _KERNEL

typedef void (*sdbc_ea_fn_t) (blind_t, nsc_off_t, nsc_size_t, int);

#define	_SD_DISCONNECT_CALLBACK(hndl)	\
	if ((hndl)->bh_disconnect_cb) { \
		SDTRACE(SDF_DISCONNECT, (hndl)->bh_cd, (hndl)->bh_fba_len, \
			(hndl)->bh_fba_pos, (hndl)->bh_flag, 0); \
		((*((hndl)->bh_disconnect_cb))(hndl)); \
	}
#define	_SD_READ_CALLBACK(hndl)	\
	if ((hndl)->bh_read_cb) \
	    ((*((hndl)->bh_read_cb))(hndl)); \
	else cmn_err(CE_WARN, \
	    "sdbc(_SD_READ_CALLBACK) not registered. io lost");
#define	_SD_WRITE_CALLBACK(hndl)	\
	if ((hndl)->bh_write_cb) \
		((*((hndl)->bh_write_cb))(hndl)); \
	else cmn_err(CE_WARN, \
	    "sdbc(_SD_WRITE_CALLBACK) not registered. io lost");

#endif /* _KERNEL */


#if defined(_SD_LRU_OPTIMIZE)
/*
 * Do not requeue if we fall into the tail 25% of the lru
 */
#define	LRU_REQ_LIMIT(q) 	(q->sq_inq >> 2)

#define	_sd_lru_reinsert(q, ent) \
	(((q->sq_seq - ent->cc_seq) > LRU_REQ_LIMIT(q)) ?\
	1 : ((q->sq_noreq_stat)++, 0))
#else
#define	_sd_lru_reinsert(ent) 1
#endif

#if defined(_KERNEL)
#define	SD_WR_NUMIO 	100
#define	SD_DCON_THRESH	0x10000	/* Disconnect if io len greater than 64 */

/*
 * These defines are the hardwired values after sd_config_param was
 * zapped. Ought to remove the use of these entirely ....
 */

#define	_SD_CD_WRITER(cd)	((_sd_cache_files[(cd)].cd_info->sh_numdirty>\
				SD_WR_NUMIO) ? \
				cd_writer(cd) : 0)
#define	_SD_FORCE_DISCONNECT(len)	(SD_DCON_THRESH < FBA_SIZE(len))

/* -------------------------------- END sd_config_param defines ---------- */

#define	_SD_CD_WBLK_USED(cd)	(_sd_cache_stats->st_shared[(cd)].sh_numio +\
				_sd_cache_stats->st_shared[(cd)].sh_numdirty)

#define	_SD_CD_ALL_WRITES(cd)	(_sd_cache_stats->st_shared[(cd)].sh_numio +\
				_sd_cache_stats->st_shared[(cd)].sh_numdirty+\
				_sd_cache_stats->st_shared[(cd)].sh_numfail)



/*
 * ncall usage
 */
#define	SD_ENABLE		(NCALL_SDBC +  0)
#define	SD_DISABLE		(NCALL_SDBC +  1)
#define	SD_DUAL_WRITE		(NCALL_SDBC +  2)
#define	SD_DUAL_READ		(NCALL_SDBC +  3)
#define	SD_SET_CD		(NCALL_SDBC +  4)
#define	SD_GETSIZE		(NCALL_SDBC +  5)
#define	SD_DUAL_OPEN		(NCALL_SDBC +  6)
#define	SD_REMOTE_FLUSH		(NCALL_SDBC +  7)
#define	SD_SGREMOTE_FLUSH	(NCALL_SDBC +  8)
#define	SD_DISK_IO		(NCALL_SDBC +  9)
#define	SD_GET_BMAP		(NCALL_SDBC + 10)
#define	SD_CD_DISCARD		(NCALL_SDBC + 11)
#define	SD_PING			(NCALL_SDBC + 12)
#define	SD_DC_MAIN_LOOP		(NCALL_SDBC + 13)
#define	SD_DATA			(NCALL_SDBC + 14)
#define	SD_BDATA		(NCALL_SDBC + 15)
#define	SD_UPDATE		(NCALL_SDBC + 16)
#define	SD_GET_SYSID		(NCALL_SDBC + 17)

#ifdef lint
#include <sys/nsctl/nsctl.h>
#define	LINTUSED(x)	(void)(x)++
#else
#define	LINTUSED(x)
#endif


extern int BLK_FBAS;
extern _sd_bitmap_t BLK_FBA_BITS;
extern _sd_bitmap_t _fba_bits[];
extern _sd_cctl_t	*_sd_cctl[];
extern _sd_cd_info_t	*_sd_cache_files;
extern _sd_hash_table_t *_sd_htable;
extern _sd_map_info_t _sd_lookup_map[];
extern _sd_net_t	 _sd_net_config;
extern _sd_queue_t _sd_lru_q;
extern _sd_stats_t *_sd_cache_stats;
extern char _sd_contig_bmap[];
extern int CACHE_BLOCK_SIZE;
extern int CBLOCKS;
extern int _sd_cctl_groupsz;
extern int sdbc_static_cache;
extern kmutex_t _sd_cache_lock;
extern nsc_def_t _sd_sdbc_def[];
extern nsc_io_t *sdbc_io;
extern nsc_mem_t *sdbc_iobuf_mem, *sdbc_hash_mem;
extern uint_t _sd_node_hint;
extern int _sd_minidsp;
extern krwlock_t sdbc_queue_lock;
extern safestore_ops_t *sdbc_safestore;
extern ss_common_config_t safestore_config;
extern ss_voldata_t *_sdbc_gl_file_info;

extern int _sdbc_cache_configure(int cblocks, spcs_s_info_t kstatus);
extern void _sdbc_cache_deconfigure(void);
extern void _sd_requeue(_sd_cctl_t *centry);
extern void _sd_requeue_head(_sd_cctl_t *centry);
extern int _sd_open(char *filename, int flag);
extern int _sd_open_cd(char *filename, const int cd, const int flag);
extern int _sd_close(int cd);
extern int _sdbc_remote_store_pinned(int cd);
extern int _sdbc_io_attach_cd(blind_t xcd);
extern int _sdbc_io_detach_cd(blind_t xcd);
extern int _sd_get_pinned(blind_t cd);
extern void _sd_cc_copy(_sd_cctl_t *cc_real, _sd_cctl_t *cc_shadow);
extern _sd_buf_handle_t *_sd_allocate_buf(int cd, nsc_off_t fba_pos,
    nsc_size_t fba_len, int flag, int *sts);
extern void _sd_cc_wait(int cd, nsc_off_t cblk, _sd_cctl_t *centry, int flag);
extern int _sd_alloc_buf(blind_t xcd, nsc_off_t fba_pos, nsc_size_t fba_len,
    int flag, _sd_buf_handle_t **handle_p);
extern int _sd_free_buf(_sd_buf_handle_t *handle);
extern _sd_cctl_t *_sd_centry_alloc(int, int, int *, int, int);
extern int _sd_centry_setup_dm(_sd_cctl_t *, int, int);
extern void _sdbc_dealloc_deconfigure_dm(void);
extern int _sdbc_dealloc_configure_dm(void);
extern _sd_cctl_t *_sd_shadow_centry(_sd_cctl_t *, _sd_cctl_t *, int, int, int);
extern void _sd_centry_release(_sd_cctl_t *centry);
extern int _sd_alloc_write(_sd_cctl_t *centry, int *stall);
extern int _sd_read(_sd_buf_handle_t *handle, nsc_off_t fba_pos,
    nsc_size_t fba_len, int flag);
extern void _sd_read_complete(_sd_buf_handle_t *handle, nsc_off_t fba_pos,
    nsc_size_t fba_len, int error);
extern int _sd_write(_sd_buf_handle_t *handle, nsc_off_t fba_pos,
    nsc_size_t fba_len, int flag);
extern int _sd_zero(_sd_buf_handle_t *handle, nsc_off_t fba_pos,
    nsc_size_t fba_len, int flag);
extern int _sd_copy(_sd_buf_handle_t *handle1, _sd_buf_handle_t *handle2,
    nsc_off_t fba_pos1, nsc_off_t fba_pos2, nsc_size_t fba_len);
extern void _sd_enqueue_dirty(int cd, _sd_cctl_t *chain, _sd_cctl_t *cc_last,
    int numq);
extern void _sd_enqueue_dirty_chain(int cd, _sd_cctl_t *chain_first,
    _sd_cctl_t *chain_last, int numq);
extern int _sd_get_stats(_sd_stats_t *uptr, int convert_32);
extern int _sd_set_hint(int cd, uint_t hint);
extern int _sd_clear_hint(int cd, uint_t hint);
extern int _sd_get_cd_hint(int cd, uint_t *hint);
extern int _sd_set_node_hint(uint_t hint);
extern int _sd_clear_node_hint(uint_t hint);
extern int _sd_get_node_hint(uint_t *hint);
extern int _sd_get_partsize(blind_t cd, nsc_size_t *ptr);
extern int _sd_get_maxfbas(blind_t cd, int flag, nsc_size_t *ptr);
extern int _sd_discard_pinned(blind_t cd, nsc_off_t fba_pos,
    nsc_size_t fba_len);
extern void _sdbc_handles_unload(void);
extern int _sdbc_handles_load(void);
extern int _sdbc_handles_configure();
extern void _sdbc_handles_deconfigure(void);
extern _sd_buf_handle_t *_sd_alloc_handle(sdbc_callback_fn_t d_cb,
    sdbc_callback_fn_t r_cb, sdbc_callback_fn_t w_cb);
extern int _sd_free_handle(_sd_buf_handle_t *handle);
extern void _sd_init_contig_bmap(void);
extern void _sd_init_lookup_map(void);
extern int sd_get_file_info_size(void *uaddrp);
extern int sd_get_file_info_data(char *uaddrp);
extern int sd_get_glmul_sizes(int *uaddrp);
extern int sd_get_glmul_info(char *uaddrp);
extern _sd_cctl_t *sdbc_centry_alloc(int, nsc_off_t, nsc_size_t, int *,
					sdbc_allocbuf_t *, int);
extern _sd_cctl_t *sdbc_centry_alloc_blks(int, nsc_off_t, nsc_size_t, int);
extern int _sdbc_ft_hold_io;
extern kcondvar_t _sdbc_ft_hold_io_cv;
extern kmutex_t _sdbc_ft_hold_io_lk;

#ifdef DEBUG
/* for testing only */
extern int _sdbc_flush_flag; /* inhibit flush for testing */
extern int _sdbc_clear_ioerr(int);
extern int _sdbc_inject_ioerr(int, int, int);
extern void _sdbc_ioj_set_dev(int, dev_t);
extern void _sdbc_ioj_load();
extern void _sdbc_ioj_unload();
#endif

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SD_BCACHE_H */
