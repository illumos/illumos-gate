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


#ifndef _SYS_XDB_H
#define	_SYS_XDB_H

#ifdef __cplusplus
extern "C" {
#endif

#define	XDB_DBG_ALL	0xf
#define	XDB_DBG_IO	0x1
#define	XDB_DBG_INFO	0x2
#define	XDB_DBPRINT(lvl, fmt) { if (xdb_debug & lvl) cmn_err fmt; }

/*
 * Info of the exported blk device
 */
#define	XDB_DEV_RO	(1 << 0) /* backend and frontend are read-only */
#define	XDB_DEV_BE_LOFI	(1 << 1) /* backend device is a lofi device */
#define	XDB_DEV_BE_RMB	(1 << 2) /* backend device is removable */
#define	XDB_DEV_BE_CD	(1 << 3) /* backend device is cdrom */
#define	XDB_DEV_FE_CD	(1 << 4) /* frontend device is cdrom */

#define	XDB_IS_RO(vdp)		((vdp)->xs_type & XDB_DEV_RO)
#define	XDB_IS_BE_LOFI(vdp)	((vdp)->xs_type & XDB_DEV_BE_LOFI)
#define	XDB_IS_BE_RMB(vdp)	((vdp)->xs_type & XDB_DEV_BE_RMB)
#define	XDB_IS_BE_CD(vdp)	((vdp)->xs_type & XDB_DEV_BE_CD)
#define	XDB_IS_FE_CD(vdp)	((vdp)->xs_type & XDB_DEV_FE_CD)

/*
 * Other handy macrosx
 */
#define	XDB_MINOR2INST(m)	(int)(m)
#define	XDB_INST2MINOR(i)	(minor_t)(i)
#define	XDB_INST2SOFTS(instance)			\
	((xdb_t *)ddi_get_soft_state(xdb_statep, (instance)))
#define	XDB_MAX_IO_PAGES(v) ((v)->xs_nentry * BLKIF_MAX_SEGMENTS_PER_REQUEST)
/* get kva of a mapped-in page coresponding to (xreq-index, seg) pair */
#define	XDB_IOPAGE_VA(_pagebase, _xreqidx, _seg)	\
	((_pagebase) + ((_xreqidx)			\
	* BLKIF_MAX_SEGMENTS_PER_REQUEST		\
	+ (_seg)) * PAGESIZE)
#define	XDB_XREQ2BP(xreq) (&(xreq)->xr_buf)
#define	XDB_BP2XREQ(bp) \
	((xdb_request_t *)((char *)(bp) - offsetof(xdb_request_t, xr_buf)))

/* describe one blkif segment */
typedef struct xdb_seg {
	uint8_t fs; /* start sector # within this page (segment) */
	uint8_t ls; /* end sector # within this page (segment) */
} xdb_seg_t;

typedef struct xdb xdb_t;

/* one blkif_request_t matches one xdb_request_t */
typedef struct xdb_request {
	/* buf associated with this I/O request */
	buf_t		xr_buf;
	/* softstate instance associated with this I/O request */
	xdb_t		*xr_vdp;
	/* the next segment we're going to process */
	int		xr_curseg;
	/* index of this xdb_request_t in vdp->xs_req */
	int		xr_idx;
	/* next index for a statical linked list */
	int		xr_next;
	/* 'id' copied from blkif_request_t */
	uint64_t	xr_id;
	/* 'operation' copied from blkif_request_t */
	uint8_t		xr_op;
	/* how many pages(segments) in this I/O request */
	uint8_t		xr_buf_pages;
	/* all segments of this I/O request */
	xdb_seg_t	xr_segs[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	/* all grant table handles used in this I/O request */
	grant_handle_t	xr_page_hdls[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	struct page	xr_plist[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	struct page	*xr_pplist[BLKIF_MAX_SEGMENTS_PER_REQUEST];
} xdb_request_t;

/* Soft state data structure for each backend vbd */
struct xdb {
	/* devinfo node pointer of this xdb */
	dev_info_t	*xs_dip;
	/* coresponding frontend domain id */
	domid_t		xs_peer;
	/* read-only, removable, cdrom? */
	uint32_t	xs_type;
	/* # of total sectors */
	uint64_t	xs_sectors;
	/* blkif I/O request ring buffer */
	xendev_ring_t	*xs_ring;
	/* handle to access the ring buffer */
	ddi_acc_handle_t xs_ring_hdl;
	ldi_ident_t	xs_ldi_li;
	ldi_handle_t	xs_ldi_hdl;
	/* base kva for mapped-in I/O page from frontend domain */
	caddr_t		xs_iopage_va;
	/* mutex lock for I/O related code path */
	kmutex_t	xs_iomutex;
	/*
	 * mutex lock for event handling related code path
	 * need to be grabbed before xs_iomutex
	 */
	kmutex_t	xs_cbmutex;
	/* # of on-going I/O buf in backend domain */
	uint_t		xs_ionum;
	/* task thread for pushing buf to underlying target driver */
	ddi_taskq_t	*xs_iotaskq;
	/* cv used in I/O code path, protected by xs_iomutex */
	kcondvar_t	xs_iocv;
	kcondvar_t	xs_ionumcv;
	/*
	 * head and tail of linked list for I/O bufs need to be pushed to
	 * underlying target driver
	 */
	buf_t		*xs_f_iobuf;
	buf_t		*xs_l_iobuf;
	/* head of free list of xdb_request_t */
	int		xs_free_req;
	/* pre-allocated xdb_request_t pool */
	xdb_request_t	*xs_req;
	kstat_t		*xs_kstats;
	uint64_t	xs_stat_req_reads;
	uint64_t	xs_stat_req_writes;
	uint64_t	xs_stat_req_barriers;
	uint64_t	xs_stat_req_flushes;
	enum blkif_protocol xs_blk_protocol;
	size_t		xs_nentry;
	size_t		xs_entrysize;

	/* Protected by xs_cbmutex */
	boolean_t	xs_hp_connected;	/* hot plug scripts have run */
	boolean_t	xs_fe_initialised;	/* frontend is initialized */
	char			*xs_lofi_path;
	char			*xs_params_path;
	struct xenbus_watch	*xs_watch_params;
	struct xenbus_watch	*xs_watch_media_req;
	ddi_taskq_t		*xs_watch_taskq;
	int			xs_watch_taskq_count;

	/* Protected by xs_cbmutex and xs_iomutex */
	boolean_t	xs_if_connected;	/* connected to frontend */

	/* Protected by xs_iomutex */
	boolean_t	xs_send_buf;

#ifdef DEBUG
	uint64_t *page_addrs; /* for debug aid */
#endif /* DEBUG */
};

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XDB_H */
