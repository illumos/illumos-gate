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

#ifndef _RDC_IO_H
#define	_RDC_IO_H

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/unistat/spcs_s.h>
#ifdef DS_DDICT
#define	bool_t	int
#endif
#include  <sys/nsctl/rdc_prot.h>
#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/rdc_ioctl.h>

/*
 * Definitions for kstats
 */
#define	RDC_MKSTAT_MAXSETS		"maxsets"
#define	RDC_MKSTAT_MAXFBAS		"maxfbas"
#define	RDC_MKSTAT_RPC_TIMEOUT		"rpc_timeout"
#define	RDC_MKSTAT_HEALTH_THRES		"health_thres"
#define	RDC_MKSTAT_BITMAP_WRITES	"bitmap_writes"
#define	RDC_MKSTAT_CLNT_COTS_CALLS	"clnt_cots_calls"
#define	RDC_MKSTAT_CLNT_CLTS_CALLS	"clnt_clts_calls"
#define	RDC_MKSTAT_SVC_COTS_CALLS	"svc_cots_calls"
#define	RDC_MKSTAT_SVC_CLTS_CALLS	"svc_clts_calls"
#define	RDC_MKSTAT_BITMAP_REF_DELAY	"bitmap_ref_delay"

#define	RDC_IKSTAT_FLAGS		"flags"
#define	RDC_IKSTAT_SYNCFLAGS		"syncflags"
#define	RDC_IKSTAT_BMPFLAGS		"bmpflags"
#define	RDC_IKSTAT_SYNCPOS		"syncpos"
#define	RDC_IKSTAT_VOLSIZE		"volsize"
#define	RDC_IKSTAT_BITSSET		"bitsset"
#define	RDC_IKSTAT_AUTOSYNC		"autosync"
#define	RDC_IKSTAT_MAXQFBAS		"maxqfbas"
#define	RDC_IKSTAT_MAXQITEMS		"maxqitems"
#define	RDC_IKSTAT_FILE			"primary_vol"
#define	RDC_IKSTAT_SECFILE		"secondary_vol"
#define	RDC_IKSTAT_BITMAP		"bitmap"
#define	RDC_IKSTAT_PRIMARY_HOST		"primary_host"
#define	RDC_IKSTAT_SECONDARY_HOST	"secondary_host"
#define	RDC_IKSTAT_TYPE_FLAG		"type_flag"
#define	RDC_IKSTAT_BMP_SIZE		"bmp_size"
#define	RDC_IKSTAT_DISK_STATUS		"disk_status"
#define	RDC_IKSTAT_IF_DOWN		"if_down"
#define	RDC_IKSTAT_IF_RPC_VERSION	"if_rpc_version"
#define	RDC_IKSTAT_ASYNC_THROTTLE_DELAY	"async_throttle_delay"
#define	RDC_IKSTAT_ASYNC_BLOCK_HWM	"async_block_hwm"
#define	RDC_IKSTAT_ASYNC_ITEM_HWM	"async_item_hwm"
#define	RDC_IKSTAT_QUEUE_TYPE		"async_queue_type"
#define	RDC_IKSTAT_ASYNC_ITEMS		"async_queue_items"
#define	RDC_IKSTAT_ASYNC_BLOCKS		"async_queue_blocks"

/*
 * Queue types
 */
#define	RDC_DISKQUE	0X01
#define	RDC_MEMQUE	0x02
#define	RDC_NOQUE	-1

#define	RDC_ACTIVE	0x1
#define	RDC_INACTIVE	0x2

#ifdef _KERNEL

extern nstset_t *_rdc_ioset;
extern nstset_t *_rdc_flset;

#ifdef DEBUG
extern int RDC_MAX_SYNC_THREADS;
extern int rdc_maxthreads_last;
int num_sync_threads;
#else
#define	RDC_MAX_SYNC_THREADS	8
#endif
#ifdef DEBUG
#define	RDC_AVAIL_THR_TUNE(n)	\
	do { \
		if (rdc_maxthreads_last < RDC_MAX_SYNC_THREADS) { \
			(void) nst_add_thread(n.rdc_syncset, \
		    RDC_MAX_SYNC_THREADS - rdc_maxthreads_last);\
		} \
		if (rdc_maxthreads_last > RDC_MAX_SYNC_THREADS) { \
			(void) nst_del_thread(n.rdc_syncset, \
			    rdc_maxthreads_last - RDC_MAX_SYNC_THREADS); \
		} \
		n.avail_thr = RDC_MAX_SYNC_THREADS - n.active_thr; \
		if (n.avail_thr < 0) { \
			n.avail_thr = 0; \
		} \
		rdc_maxthreads_last = RDC_MAX_SYNC_THREADS; \
		num_sync_threads = nst_nthread(n.rdc_syncset); \
	} while (0);
#else
#define	RDC_AVAIL_THR_TUNE(n)	\
	do { \
		n.avail_thr = RDC_MAX_SYNC_THREADS - n.active_thr; \
		if (n.avail_thr < 0) \
			n.avail_thr = 0; \
	} while (0);

#endif

typedef struct syncloop_info {
	int		active_thr;
	int		avail_thr; /* should be MAX_RDC_SYNC_THREADS - active */
	kmutex_t	lock;
	nstset_t	*rdc_syncset;
} sync_info_t;

sync_info_t sync_info;

/*
 * Static server information
 */
typedef struct servinfo {
	struct knetconfig	*ri_knconf;	/* bound TLI fd */
	struct netbuf		ri_addr;	/* server's address */
	struct sec_data		*ri_secdata;	/* sec data for rpcsec module */
	char			*ri_hostname;	/* server's hostname */
	int			ri_hostnamelen; /* server's hostname length */
} rdc_srv_t;

/*
 * Interface structure, including health monitoring.
 */
typedef struct rdc_if_s {
	struct rdc_if_s *next;		/* chain pointer */
	struct netbuf ifaddr;
	struct netbuf r_ifaddr;
	rdc_srv_t *srv;			/* servinfo of server end */
	int	if_down;		/* i/f is down (set on primary) */
	int	isprimary;		/* this end is a primary */
	int	issecondary;		/* this end is a secondary */
	rpcvers_t rpc_version;		/* RPC protocol version in use */
	int	no_ping;		/* set on secondary to hold off RPCs */
	int	old_pulse;		/* previous (current) pulse value */
	int	new_pulse;		/* new (incoming) pulse value */
	int	deadness;		/* how close to death are we? */
	volatile int exiting;		/* daemon exit flag */
	time_t	last;			/* time of last ping */
} rdc_if_t;


typedef struct rdc_aio_s {
	struct rdc_aio_s *next;
	nsc_buf_t *handle;
	nsc_buf_t *qhandle;
	nsc_off_t pos;
	nsc_off_t qpos;
	nsc_size_t len;
	nsc_size_t orig_len;
	int	flag;
	int	iostatus;
	int	index;
	uint_t	seq;		/* sequence on async Q */
} rdc_aio_t;

/* values for (rdc_aio_t *)->iostatus */
enum {
	RDC_IO_NONE = 0,	/* not used */
	RDC_IO_INIT,		/* io started */
	RDC_IO_DONE,		/* io done successfully */
	RDC_IO_FAILED,		/* io failed */
	RDC_IO_DISCARDED,	/* io discarded */
	RDC_IO_CANCELLED	/* group_log in progress */
};


#define	RDC_MAX_QBLOCKS	16384	/* 8MB temporary q for diskq to flush to */
#define	RDC_LOW_QBLOCKS 13927	/* roughly 85% of queue full */
#define	RDC_HALF_MQUEUE 8192	/* half of the memory queue */

typedef struct netqueue {
	rdc_aio_t *net_qhead;
	rdc_aio_t *net_qtail;
	kmutex_t net_qlock;
	int hwmhit;			/* queue full hit? reset after hwm */
	int qfill_sleeping;		/* waiting for work? */
	int qfflags;			/* diskq/memq flusher flags */
	kcondvar_t qfcv;		/* for timed waits */
	volatile nsc_size_t blocks;	/* number of FBAs in q */
	volatile uint64_t nitems;	/* number of items in q */
	volatile int  inflbls;		/* number of inflight blocks */
	volatile int  inflitems;	/* number of inflight items */
	uint64_t  nitems_hwm;		/* highest items on queue */
	nsc_size_t  blocks_hwm;		/* highest blocks on queue */
	long throttle_delay;		/* Number of times we delayed x 2 */
} net_queue;


/*
 * Bitmap header structures.
 * These must be fixed size in all data models.
 * If we ever support little-endian machines (eg. Intel) we will need
 * to add byte-swapping logic.
 */

typedef struct {
	int32_t magic;
	int32_t serial_mode;
	int32_t use_mirror;
	int32_t mirror_down;
	int32_t sync_needed;
	char bitmapname[NSC_MAXPATH];
	char filename[NSC_MAXPATH];
	int32_t volume_failed;
} rdc_headerv2_t;
#define	RDC_HDR_V2	0x52444302	/* RDC2 */

#define	RDC_SYNC	0x1
#define	RDC_REV_SYNC	0x2
#define	RDC_FULL_SYNC	0x3

#define	RDC_FAILED	0x1
#define	RDC_COMPLETED	0x2

typedef struct {
	char	file[NSC_MAXPATH];
	char	bitmap[NSC_MAXPATH];
} rdc_hdr_addr_t;

typedef struct {
	int32_t		magic;
	rdc_hdr_addr_t	primary;
	rdc_hdr_addr_t	secondary;
	int32_t		flags;
	int32_t		autosync;
	int32_t		maxqfbas;
	int32_t		maxqitems;
	int32_t		syshostid;	/* for cluster bitmaps */
} rdc_headerv3_t;
#define	RDC_HDR_V3	0x52444303	/* RDC3 */

typedef struct {
	int32_t		magic;
	rdc_hdr_addr_t	primary;
	rdc_hdr_addr_t	secondary;
	int32_t		flags;
	int32_t		autosync;
	int32_t		maxqfbas;
	int32_t		maxqitems;
	int32_t		syshostid;	/* for cluster bitmaps */
	int32_t		asyncthr;
} rdc_headerv4_t;
#define	RDC_HDR_V4	0x52444304	/* RDC4 */

typedef struct {
	int32_t		magic;
	rdc_hdr_addr_t	primary;
	rdc_hdr_addr_t	secondary;
	int32_t		flags;
	int32_t		autosync;
	int64_t		maxqfbas;
	int64_t		maxqitems;
	int32_t		syshostid;	/* for cluster bitmaps */
	int32_t		asyncthr;
	int32_t		refcntsize;	/* size in bytes of each refcount */
} rdc_headerv5_t;
#define	RDC_HDR_V5	0x52444305	/* RDC5 */

typedef rdc_headerv5_t	rdc_header_t;	/* Current header type */
#define	RDC_HDR_MAGIC	RDC_HDR_V5	/* Current header magic number */

#endif	/* _KERNEL */

#define	RDC_BITMAP_FBA	1		/* Offset at which the bitmap starts */
#define	RDC_BITREF_FBA(krdc) (RDC_BITMAP_FBA + FBA_LEN(krdc->bitmap_size))

#ifdef _KERNEL

#define	RDC_FUTILE_ATTEMPTS	50
typedef struct aio_buf_s {
	struct aio_buf_s	*next;		/* next aio_buf */
	nsc_buf_t		*rdc_abufp;	/* actual anon buf */
	int			kindex;		/* index we are attached to */
} aio_buf_t;

typedef struct rdc_thrsync {
	kmutex_t	lock;
	int		threads;
	int		complete;
	kcondvar_t	cv;
} rdc_thrsync_t;

typedef struct sync_status_s {
	int	offset;
	struct sync_status_s *next;
} sync_status_t;

typedef struct rdc_syncthr {
	nsc_off_t		offset;
	nsc_size_t		len;
	struct rdc_k_info	*krdc;
	sync_status_t		*status;
} rdc_syncthr_t;

/*
 * RDC buffer header
 */

typedef struct rdc_buf_s {
	nsc_buf_t	rdc_bufh;	/* exported buffer header */
	nsc_buf_t	*rdc_bufp;	/* underlying buffer */
	aio_buf_t	*rdc_anon;	/* ANON async buffer */
	struct rdc_fd_s	*rdc_fd;	/* back link */
	size_t		rdc_vsize;	/* size of allocated nsc_vec_t */
	int		rdc_flags;	/* flags */
	kmutex_t	aio_lock;	/* lock for rdc_anon */
	rdc_thrsync_t	rdc_sync;	/* for thread syncronization */
} rdc_buf_t;

#define	RDC_VEC_ALLOC	0x1		/* local kmem vector for remote io */
#define	RDC_ALLOC	0x2		/* rdc_bufp is nsc_buf_alloc'd */
#define	RDC_ASYNC_VEC	0x4		/* Keep tmp handle for async flusher */
#define	RDC_REMOTE_BUF	0x8		/* buffer alloc'd for remote io only */
#define	RDC_NULL_BUF	0x10		/* tell diskq to only store io_hdr */
#define	RDC_ASYNC_BUF	0x20		/* this buf is to an async vol */
#define	RDC_NULLBUFREAD	0x0f000000	/* read because RDC_NULL_BUF detected */

#define	BUF_IS_ASYNC(h)	(((h) != NULL) && (h)->rdc_flags & RDC_ASYNC_BUF)
#define	RDC_REMOTE(h)	(((h) != NULL) && ((h)->rdc_flags & RDC_REMOTE_BUF) && \
			(((h)->rdc_flags & RDC_ASYNC_VEC) == 0))

/* check a handle against a supplied pos/len pair */

#define	RDC_HANDLE_LIMITS(h, p, l) \
		(((h)->sb_user & RDC_DISKQUE) || \
		((p) >= (h)->sb_pos) && \
		(((p) + (l)) <= ((h)->sb_pos + (h)->sb_len)))

/* check a dset against a supplied pos/len pair */

#define	RDC_DSET_LIMITS(d, p, l) \
		(((p) >= (d)->pos) && \
		(((p) + (l)) <= ((d)->pos + (d)->fbalen)))

/*
 * RDC device info structures
 */

typedef struct _rdc_info_dev_s {
	nsc_fd_t	*bi_fd;		/* file descriptor */
	nsc_iodev_t	*bi_iodev;	/* I/O device structure */
	struct rdc_k_info *bi_krdc;	/* back link */
	int		bi_rsrv;	/* Count of reserves held */
	int		bi_orsrv;	/* Reserves for other io provider */
	int		bi_failed;	/* Count of failed (faked) reserves */
	int		bi_ofailed;	/* Other io provider failed reserves */
	int		bi_flag;	/* Reserve flags */
} _rdc_info_dev_t;


typedef struct rdc_info_dev_s {
	struct rdc_info_dev_s	*id_next;	/* forward link */
	_rdc_info_dev_t		id_cache_dev;	/* cached device info */
	_rdc_info_dev_t		id_raw_dev;	/* raw device info */
	kmutex_t		id_rlock;	/* reserve/release lock */
	kcondvar_t		id_rcv;		/* nsc_release pending cv */
	int			id_sets;	/* # of sets referencing */
	int			id_release;	/* # of pending nsc_releases */
	int			id_flag;	/* flags */
} rdc_info_dev_t;


typedef struct rdc_path_s {
	nsc_path_t		*rp_tok;	/* nsc_register_path token */
	int			rp_ref;		/* # of rdc_fd_t's */
} rdc_path_t;


/*
 * Values for id_flag
 */
#define	RDC_ID_CLOSING		0x1		/* device is closing */

#include <sys/nsctl/rdc_diskq.h>

/*
 * value for diskio.seq.
 */
#define	RDC_NOSEQ		(0)		/* ignore sequence */
#define	RDC_NEWSEQ		(1)		/* start of sequence */

typedef struct rdc_sleepq {
	struct rdc_sleepq	*next;
	uint_t			seq;		/* sequence in queue */
	int			idx;		/* idx number of request */
	int			pindex;		/* primary host set index */
	int			sindex;		/* secondary host set index */
	uint64_t		qpos;		/* offset on primary's queue */
	int			nocache;	/* cache flag to alloc_buf */
} rdc_sleepq_t;

/*
 * RDC group structure
 */
typedef struct rdc_group {
	int		count;
	int		rdc_writer;
	int		unregistering;
	kmutex_t	lock;
	net_queue	ra_queue;	/* io todo async queues */
	kcondvar_t	iowaitcv;	/* wait for flusher */
	kcondvar_t	unregistercv;	/* wait for unregister */
	int		rdc_thrnum;	/* number of threads */
	int		rdc_addthrnum;	/* number threads added to thr set */
	kmutex_t	addthrnumlk;	/* lock for above */
	rdc_sleepq_t	*sleepq;	/* head of waiting tasks */
	/*
	 * Dual use, the outgoing sequence number on the client.
	 * The next expected sequence number on the server.
	 * Protected by the ra_queue lock.
	 */
	uint_t		seq;
	/*
	 * Dual use, the last acknowledged sequence number.
	 * Used to ensure that the queue doesn't overflow on server
	 * and to stall transmissions on the client.
	 * Protected by the ra_queue lock.
	 */
	uint_t		seqack;
	int		asyncstall;	/* count of asleep threads */
	int		asyncdis;	/* discard stalled output */
	kcondvar_t	asyncqcv;	/* output stall here */
	int		flags;		/* memory or disk. status etc */
	disk_queue	diskq;		/* disk queue */
	nsc_fd_t	*diskqfd;	/* diskq handle */
	nsc_path_t	*q_tok;		/* q registration */
	int		diskqrsrv;	/* reserve count */
	kmutex_t	diskqmutex;	/* enables/disables/reserves */
	uint_t		synccount;	/* number of group members syncing */
} rdc_group_t;

/* group state */
#define	RDC_DISKQ_KILL		0x01	/* a force kill of diskq pending */

#define	RDC_IS_DISKQ(grp)	(grp->flags & RDC_DISKQUE)
#define	RDC_IS_MEMQ(grp)	(grp->flags & RDC_MEMQUE)

/*
 * These flags are used in the
 * aux_state field, and are used to track:
 * AUXSYNCIP: When the code has a sync thread running, used instead
 * of the RC_SYNCING flag which gets cleared before the sync thread
 * terminates.
 * AUXWRITE: Set when rdc_sync_write_thr is running, so the rdc_unintercept
 * code can wait until a one-to-many write has actually terminated.
 */
#define	RDC_AUXSYNCIP	0x01		/* a sync is in progress */
#define	RDC_AUXWRITE	0x02		/* I've got a write in progress */


/*
 * RDC kernel-private information
 */
typedef struct rdc_k_info {
	int			index;		/* Index into array */
	int			remote_index;	/* -1 means unknown */
	int			type_flag;
	int			rpc_version;	/* RPC version this set supps */
	int			spare1;
	nsc_off_t		syncbitpos;
	kmutex_t		syncbitmutex;	/* lock for syncbitpos */
	volatile int		busy_count;	/* ioctls in progress */
	volatile int		sync_done;
	int			aux_state; /* syncing ,don't disable */
	rdc_thrsync_t		syncs;		/* _rdc_sync thread tracking */
	rdc_info_dev_t		*devices;
	nsc_iodev_t		*iodev;		/* I/O device structure */
	rdc_path_t		cache_path;
	rdc_path_t		raw_path;
	rdc_if_t		*intf;
	rdc_srv_t		*lsrv;		/* list of servinfo */
	nsc_size_t		maxfbas;	/* returned from nsc_maxfbas */
	unsigned char		*dcio_bitmap;
	void			*bitmap_ref;	/* Incore bitmap bit ref */
	struct rdc_group	*group;
	nsc_size_t		bitmap_size;
	int			bmaprsrv;	/* bitmap reserve count */
	int			bitmap_write;
	nsc_fd_t		*bitmapfd;
	nsc_fd_t		*remote_fd;	/* FCAL direct io */
	volatile int		disk_status;	/* set to halt sync */
	int			closing;
	nsc_path_t		*b_tok;		/* Bitmap registration */
	int			b_ref;
	kmutex_t		dc_sleep;
	kmutex_t		bmapmutex;	/* mutex for bitmap ops */
	kcondvar_t		busycv;		/* wait for ioctl to complete */
	kcondvar_t		closingcv;	/* unregister_path/close */
	kcondvar_t		haltcv;		/* wait for sync to halt */
	kcondvar_t		synccv;		/* wait for sync to halt */
	struct rdc_net_dataset  *net_dataset;	/* replaces hnds */
	int64_t			io_time;	/* moved from cd_info */
	struct rdc_k_info	*many_next;	/* 1-to-many circular list */
	struct rdc_k_info	*multi_next;	/* to multihop krdc */
	struct rdc_k_info	*group_next;	/* group circular list */
	kstat_t			*io_kstats;	/* io kstat */
	kstat_t			*bmp_kstats;	/* bitmap io kstat */
	kstat_t			*set_kstats;	/* set kstat */
	kmutex_t		kstat_mutex;	/* mutex for kstats */
	kmutex_t		bmp_kstat_mutex;	/* mutex for kstats */
	struct bm_ref_ops	*bm_refs;
} rdc_k_info_t;

#define	c_fd		devices->id_cache_dev.bi_fd
#define	c_rsrv		devices->id_cache_dev.bi_rsrv
#define	c_failed	devices->id_cache_dev.bi_failed
#define	c_flag		devices->id_cache_dev.bi_flag

#define	c_tok		cache_path.rp_tok
#define	c_ref		cache_path.rp_ref

#define	r_fd		devices->id_raw_dev.bi_fd
#define	r_rsrv		devices->id_raw_dev.bi_rsrv
#define	r_failed	devices->id_raw_dev.bi_failed
#define	r_flag		devices->id_raw_dev.bi_flag

#define	r_tok		raw_path.rp_tok
#define	r_ref		raw_path.rp_ref

/*
 * flags for _rdc_rsrv_devs()
 */

/*
 * which device(s) to reserve - integer bitmap.
 */

#define	RDC_CACHE	0x1	/* data device in cache mode */
#define	RDC_RAW		0x2	/* data device in raw mode */
#define	RDC_BMP		0x4	/* bitmap device */
#define	RDC_QUE		0x8	/* diskq device */

/*
 * device usage after reserve - integer flag.
 */

#define	RDC_INTERNAL	0x1	/* reserve for rdc internal purposes */
#define	RDC_EXTERNAL	0x2	/* reserve in response to io provider Attach */

/*
 * Utility macro for nsc_*() io function returns.
 */

#define	RDC_SUCCESS(rc)	(((rc) == NSC_DONE) || ((rc) == NSC_HIT))

/*
 * RDC file descriptor structure
 */

typedef struct rdc_fd_s {
	rdc_k_info_t	*rdc_info;	/* devices info structure */
	int		rdc_type;	/* open type, diskq or bitmap */
	int		rdc_oflags;	/* raw or cached open type */
} rdc_fd_t;

/*
 * fd and rsrv macros
 */

#define	RSRV(bi)	(((bi)->bi_rsrv > 0) || ((bi)->bi_failed > 0))
#define	ORSRV(bi)	(((bi)->bi_orsrv > 0) || ((bi)->bi_ofailed > 0))
#define	RFAILED(bi)	(((bi)->bi_failed > 0) || ((bi)->bi_ofailed > 0))

#define	IS_RSRV(bi)	(RSRV(bi) || ORSRV(bi))

#define	IS_CRSRV(gcd)	(IS_RSRV(&(gcd)->devices->id_cache_dev))
#define	IS_RRSRV(gcd)	(IS_RSRV(&(gcd)->devices->id_raw_dev))

#define	IS_RFAILED(gcd)	\
		(RFAILED(&(gcd)->devices->id_cache_dev) || \
		RFAILED(&(gcd)->devices->id_raw_dev))

#define	RDC_IS_BMP(rdc)	((rdc)->rdc_type == RDC_BMP)
#define	RDC_IS_QUE(rdc) ((rdc)->rdc_type == RDC_QUE)
#define	RDC_IS_RAW(rdc)	(((rdc)->rdc_oflags & NSC_CACHE) == 0)
#define	RDC_U_FD(gcd)	(IS_CRSRV(gcd) ? (gcd)->c_fd : (gcd)->r_fd)
#define	RDC_FD(rdc)	(RDC_U_FD(rdc->rdc_info))


typedef struct rdc_host_u {
	char *nodename;
	int netaddr;
	struct netbuf *naddr;
} rdc_host_t;

/*
 * Reply from remote read
 * - convenience defines for the client side code.
 * - keep this in sync with the readres structure in rdc_prot.h/.x
 */
#define	rdcrdresult	readres
#define	rr_status	status
#define	rr_ok		readres_u.reply
#define	rr_bufsize	rr_ok.data.data_len
#define	rr_data		rr_ok.data.data_val

/*
 * Flags for remote read rpc
 *
 * _START must be a unique rpc, _DATA and _END may be OR-d together.
 */
#define	RDC_RREAD_DATA	0x1	/* Intermediate rpc with data payload */
#define	RDC_RREAD_START	0x2	/* Setup rpc */
#define	RDC_RREAD_END	0x4	/* End rpc */
#define	RDC_RREAD_FAIL	0x8	/* Primary is failed */

/*
 * Flags for remote write rpc
 */
#define	RDC_RWRITE_FAIL	0x8	/* Primary is failed */

/*
 * macro used to determine if the incomming sq, with sequence
 * value x, should be placed before the sq with sequence value y.
 * This has to account for integer wrap.
 */
#define	RDC_INFRONT(x, y) (((x < y) && ((y - x) < 1000)) ? 1 : \
	((x > y) && ((x - y) > 1000)) ? 1 : 0)




#endif /* _KERNEL */

/*
 * RDC user-visible information
 */
typedef rdc_set_t rdc_u_info_t;


/*
 * RDC flags for set state / set cd RPC.
 * Must remain compatible with rdc RPC protocol version v3.
 */
#define	CCIO_NONE		0x0000
#define	CCIO_ENABLE		0x0008
#define	CCIO_SLAVE		0x0010
#define	CCIO_DONE		0x0020
#define	CCIO_ENABLELOG		0x0100
#define	CCIO_RSYNC		0x0400
#define	CCIO_REMOTE		0x2000


/*
 * In kernel type flags (krdc->type_flag).
 */
#define	RDC_CONFIGURED		0x1
#define	RDC_DISABLEPEND		0x2	/* Suspend/Disable is in progress */
#define	RDC_ASYNCMODE		0x4
#define	RDC_RESUMEPEND		0x8
#define	RDC_RESPONSIBLE		0x10
#define	RDC_BUSYWAIT		0x20
#define	RDC_UNREGISTER		0x40	/* Unregister is in progress */
#define	RDC_QDISABLEPEND	0x100	/* Q Suspend/Disable is in progress */

#define	IS_ENABLED(urdc)	((IS_CONFIGURED(&rdc_k_info[(urdc)->index]) && \
	(rdc_get_vflags(urdc) & RDC_ENABLED)))
#define	IS_CONFIGURED(krdc)	((krdc)->type_flag & RDC_CONFIGURED)
#define	IS_MANY(krdc)		((krdc)->many_next != (krdc))
#define	IS_MULTI(krdc)		((krdc)->multi_next != NULL)

#define	IS_VALID_INDEX(index)	((index) >= 0 && (index) < rdc_max_sets && \
					IS_CONFIGURED(&rdc_k_info[(index)]))

#define	RDC_NOFLUSH	0	/* Do not do a flush when starting logging */
#define	RDC_NOREMOTE	0	/* Do no remote logging notifications */
#define	RDC_FLUSH	1	/* Do a flush when starting logging */
#define	RDC_ALLREMOTE	2	/* Notify all remote group members */
#define	RDC_OTHERREMOTE	4	/* Notify all remote group members except */
				/* the one corresponding to the current set, */
				/* to prevent recursion in the case where */
				/* the request was initiated from the remote */
				/* node. */
#define	RDC_FORCE_GROUP 8	/* set all group memebers logging regardless */

#ifdef _KERNEL

/*
 * Functions, vars
 */

#define	RDC_SYNC_EVENT_TIMEOUT	(60 * HZ)
typedef struct {
	clock_t lbolt;
	int event;
	int ack;
	int daemon_waiting;		/* Daemon waiting in ioctl */
	int kernel_waiting;		/* Kernel waiting for daemon to reply */
	char master[NSC_MAXPATH];
	char group[NSC_MAXPATH];
	kmutex_t mutex;
	kcondvar_t cv;
	kcondvar_t done_cv;
} rdc_sync_event_t;
extern rdc_sync_event_t rdc_sync_event;
extern clock_t rdc_sync_event_timeout;
extern kmutex_t rdc_sync_mutex;

extern rdc_u_info_t *rdc_u_info;
extern rdc_k_info_t *rdc_k_info;

extern int rdc_max_sets;

extern unsigned long rdc_async_timeout;

extern int rdc_self_host();
extern uint64_t mirror_getsize(int index);
extern void rdc_sleepqdiscard(rdc_group_t *);


#ifdef	DEBUG
extern void rdc_stallzero(int);
#endif

struct rdc_net_dataitem {
	void *dptr;
	int   len;	/* byte count */
	int   mlen;	/* actual malloced size */
	struct rdc_net_dataitem *next;
};
typedef struct rdc_net_dataitem rdc_net_dataitem_t;

struct rdc_net_dataset {
	int id;
	int inuse;
	int delpend;
	int nitems;
	nsc_off_t pos;
	nsc_size_t fbalen;
	rdc_net_dataitem_t *head;
	rdc_net_dataitem_t *tail;
	struct rdc_net_dataset *next;
};
typedef struct rdc_net_dataset rdc_net_dataset_t;


#endif /* _KERNEL */


#define	RDC_TCP_DEV		"/dev/tcp"

#define	RDC_VERS_MIN	RDC_VERSION5
#define	RDC_VERS_MAX	RDC_VERSION7

#define	RDC_HEALTH_THRESHOLD	20
#define	RDC_MIN_HEALTH_THRES	5
#define	SNDR_MAXTHREADS		16
/*
 * These next two defines are the default value of the async queue size
 * They have been calculated to be 8MB of data with an average of
 * 2K IO size
 */
#define	RDC_MAXTHRES_QUEUE 	16384	/* max # of fbas on async q */
#define	RDC_MAX_QITEMS		4096	/* max # of items on async q */
#define	RDC_ASYNCTHR		2	/* number of async threads */

#define	RDC_RPC_MAX		(RDC_MAXDATA + sizeof (net_data5) +\
					(RPC_MAXDATASIZE - 8192))
#define	ATM_NONE 0
#define	ATM_INIT 1
#define	ATM_EXIT 2

#define	RDC_CLNT_TMOUT		16

#define	BMAP_BLKSIZE 1024
#define	BMAP_BLKSIZEV7 RDC_MAXDATA

/* right now we can only trace 1m or less writes to the bitmap (32 bits wide) */
#define	RDC_MAX_MAXFBAS	2048

#if defined(_KERNEL)
/* kstat interface */

/*
 * Per module kstats
 * only one instance
 */
typedef struct {
	kstat_named_t	m_maxsets;		/* Max # of sndr sets */
	kstat_named_t	m_maxfbas;		/* Max # of FBAS from nsctl */
	kstat_named_t	m_rpc_timeout;		/* global RPC timeout */
	kstat_named_t	m_health_thres;		/* Health thread timeout */
	kstat_named_t	m_bitmap_writes;	/* True for bitmap writes */
	kstat_named_t	m_clnt_cots_calls;	/* # of clnt COTS calls */
	kstat_named_t	m_clnt_clts_calls;	/* # of clnt CLTS calls */
	kstat_named_t	m_svc_cots_calls;	/* # of server COTS calls */
	kstat_named_t	m_svc_clts_calls;	/* # of server CLTS calls */
	kstat_named_t	m_bitmap_ref_delay;	/* # of bitmap ref overflows */
} sndr_m_stats_t;

/*
 * Per set kstats
 * one instance per configured set
 */
typedef struct {
	kstat_named_t	s_flags;	/* from rdc_set_t */
	kstat_named_t	s_syncflags;	/* from rdc_set_t */
	kstat_named_t	s_bmpflags;	/* from rdc_set_t */
	kstat_named_t	s_syncpos;	/* from rdc_set_t */
	kstat_named_t	s_volsize;	/* from rdc_set_t */
	kstat_named_t	s_bits_set;	/* from rdc_set_t */
	kstat_named_t	s_autosync;	/* from rdc_set_t */
	kstat_named_t	s_maxqfbas;	/* from rdc_set_t */
	kstat_named_t	s_maxqitems;	/* from rdc_set_t */
	kstat_named_t	s_primary_vol;	/* from rdc_set_t */
	kstat_named_t	s_secondary_vol;	/* from rdc_set_t */
	kstat_named_t	s_bitmap;	/* from rdc_set_t */
	kstat_named_t	s_primary_intf;	/* from rdc_set_t */
	kstat_named_t	s_secondary_intf;	/* from rdc_set_t */
	kstat_named_t	s_type_flag;	/* from rdc_k_info_t */
	kstat_named_t	s_bitmap_size;	/* from rdc_k_info_t */
	kstat_named_t	s_disk_status;	/* from rdc_k_info_t */
	kstat_named_t	s_if_if_down;	/* from rdc_if_t */
	kstat_named_t	s_if_rpc_version;	/* from rdc_if_t */
	kstat_named_t	s_aqueue_blk_hwm;	/* from rdc_k_info_t */
	kstat_named_t	s_aqueue_itm_hwm;	/* from rdc_k_info_t */
	kstat_named_t	s_aqueue_throttle;	/* from rdc_k_info_t */
	kstat_named_t	s_aqueue_items;
	kstat_named_t	s_aqueue_blocks;
	kstat_named_t	s_aqueue_type;
} rdc_info_stats_t;
#endif /* _KERNEL */

#ifndef _SunOS_5_6 	/* i.e. 2.7+ */
typedef int xdr_t;
#else	/* i.e. 2.6- */
typedef unsigned long rpcprog_t;
typedef unsigned long rpcvers_t;
typedef unsigned long rpcproc_t;
typedef unsigned long rpcprot_t;
typedef unsigned long rpcport_t;
#endif /* _SunOS_5_6 */


#ifdef _KERNEL

extern nsc_size_t MAX_RDC_FBAS;
extern volatile int net_exit;
extern nsc_size_t rdc_maxthres_queue;	/* max # of fbas on async q */
extern int rdc_max_qitems;		/* max # of items on async q */
extern int rdc_asyncthr;	/* # of async threads */

#ifdef DEBUG
extern kmutex_t rdc_cntlock;
extern int rdc_datasetcnt;
#endif

/*
 * Macro to keep tabs on dataset memory usage.
 */
#ifdef DEBUG
#define	RDC_DSMEMUSE(x) \
	mutex_enter(&rdc_cntlock);\
	rdc_datasetcnt += (x);\
	mutex_exit(&rdc_cntlock);
#else
#define	RDC_DSMEMUSE(x)
#endif





extern kmutex_t rdc_ping_lock;
extern rdc_if_t *rdc_if_top;

extern int _rdc_enqueue_write(rdc_k_info_t *, nsc_off_t, nsc_size_t, int,
    nsc_buf_t *);
extern int rdc_net_state(int, int);
extern int rdc_net_getbmap(int, int);
extern int rdc_net_getsize(int, uint64_t *);
extern int rdc_net_write(int, int, nsc_buf_t *, nsc_off_t, nsc_size_t, uint_t,
    int, netwriteres *);
extern int rdc_net_read(int, int, nsc_buf_t *, nsc_off_t, nsc_size_t);
extern int _rdc_remote_read(rdc_k_info_t *, nsc_buf_t *, nsc_off_t, nsc_size_t,
    int);
extern int _rdc_multi_write(nsc_buf_t *, nsc_off_t, nsc_size_t, int,
    rdc_k_info_t *);
extern int rdc_start_server(struct rdc_svc_args *, int);
extern aio_buf_t *rdc_aio_buf_get(rdc_buf_t *, int);
extern void rdc_aio_buf_del(rdc_buf_t *, rdc_k_info_t *);
extern aio_buf_t *rdc_aio_buf_add(int, rdc_buf_t *);
extern int rdc_net_getstate(rdc_k_info_t *, int *, int *, int *, int);
extern kmutex_t rdc_conf_lock;
extern kmutex_t rdc_many_lock;
extern int rdc_drain_queue(int);
extern int flush_group_queue(int);
extern void rdc_dev_close(rdc_k_info_t *);
extern int rdc_dev_open(rdc_set_t *, int);
extern void rdc_get_details(rdc_k_info_t *);
extern int rdc_lookup_bitmap(char *);
extern int rdc_lookup_enabled(char *, int);
extern int rdc_lookup_byaddr(rdc_set_t *);
extern int rdc_lookup_byname(rdc_set_t *);
extern int rdc_intercept(rdc_k_info_t *);
extern int rdc_unintercept(rdc_k_info_t *);
extern int _rdc_rsrv_devs(rdc_k_info_t *, int, int);
extern void _rdc_rlse_devs(rdc_k_info_t *, int);
extern void _rdc_unload(void);
extern int _rdc_load(void);
extern int _rdc_configure(void);
extern void _rdc_deconfigure(void);
extern void _rdc_async_throttle(rdc_k_info_t *, long);
extern int rdc_writer(int);
extern int rdc_dump_alloc_bufs_cd(int);
extern void rdc_dump_alloc_bufs(rdc_if_t *);
extern int rdc_check_secondary(rdc_if_t *, int);
extern void rdc_dump_queue(int);
extern int rdc_isactive_if(struct netbuf *, struct netbuf *);
extern rdc_if_t *rdc_add_to_if(rdc_srv_t *, struct netbuf *, struct netbuf *,
    int);
extern void rdc_remove_from_if(rdc_if_t *);
extern void rdc_set_if_vers(rdc_u_info_t *, rpcvers_t);

extern void rdc_print_svinfo(rdc_srv_t *, char *);
extern rdc_srv_t *rdc_create_svinfo(char *, struct netbuf *,
			struct knetconfig *);
extern void rdc_destroy_svinfo(rdc_srv_t *);

extern void init_rdc_netbuf(struct netbuf *);
extern void free_rdc_netbuf(struct netbuf *);
extern void dup_rdc_netbuf(const struct netbuf *, struct netbuf *);
extern int rdc_netbuf_toint(struct netbuf *);
extern struct netbuf *rdc_int_tonetbuf(int);
extern void rdc_lor(const uchar_t *, uchar_t *, int);
extern int rdc_resume2(rdc_k_info_t *);
extern void rdc_set_flags(rdc_u_info_t *, int);
extern void rdc_clr_flags(rdc_u_info_t *, int);
extern int rdc_get_vflags(rdc_u_info_t *);
extern void rdc_set_mflags(rdc_u_info_t *, int);
extern void rdc_clr_mflags(rdc_u_info_t *, int);
extern int rdc_get_mflags(rdc_u_info_t *);
extern void rdc_set_flags_log(rdc_u_info_t *, int, char *);
extern void rdc_group_log(rdc_k_info_t *krdc, int flush, char *why);
extern int _rdc_config(void *, int, spcs_s_info_t, int *);
extern void rdc_many_enter(rdc_k_info_t *);
extern void rdc_many_exit(rdc_k_info_t *);
extern void rdc_group_enter(rdc_k_info_t *);
extern void rdc_group_exit(rdc_k_info_t *);
extern int _rdc_sync_event_wait(void *, void *, int, spcs_s_info_t, int *);
extern int _rdc_sync_event_notify(int, char *, char *);
extern int _rdc_link_down(void *, int, spcs_s_info_t, int *);
extern void rdc_delgroup(rdc_group_t *);
extern int rdc_write_bitmap_fba(rdc_k_info_t *, nsc_off_t);
extern int rdc_bitmapset(int, char *, char *, void *, int, nsc_off_t, int);
extern rdc_net_dataset_t *rdc_net_add_set(int);
extern rdc_net_dataset_t *rdc_net_get_set(int, int);
extern void rdc_net_put_set(int, rdc_net_dataset_t *);
extern void rdc_net_del_set(int, rdc_net_dataset_t *);
extern void rdc_net_free_set(rdc_k_info_t *, rdc_net_dataset_t *);
extern int rdc_lookup_byhostdev(char *intf, char *file);
extern int rdc_lookup_configured(char *path);
extern void rdc_dump_dsets(int);
extern void set_busy(rdc_k_info_t *);
extern void wakeup_busy(rdc_k_info_t *);


#ifdef	DEBUG
extern int rdc_async6(void *, int mode, int *);
extern int rdc_readgen(void *, int, int *);
#endif

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _RDC_IO_H */
