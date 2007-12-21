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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _SYS_XDB_H
#define	_SYS_XDB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#define	XDB_DEV_RO	(1)	/* read-only or writable */
#define	XDB_IS_RO(vdp)	((vdp)->xs_type & XDB_DEV_RO)
#define	XDB_DEV_LOFI	(1 << 1) /* lofi device or physical device */
#define	XDB_IS_LOFI(vdp)	((vdp)->xs_type & XDB_DEV_LOFI)
#define	XDB_DEV_CD	(1 << 2) /* cdrom disc */
#define	XDB_IS_CD(vdp)	((vdp)->xs_type & XDB_DEV_CD)
#define	XDB_DEV_RMB	(1 << 3) /* removable device */
#define	XDB_IS_RMB(vdp)	((vdp)->xs_type & XDB_DEV_RMB)

/*
 * Xdb interface status
 */
enum xdb_state {
	/*
	 * initial state
	 */
	XDB_UNKNOWN,
	/*
	 * frontend xenbus state changed to XenbusStateConnected,
	 * we finally connect
	 */
	XDB_CONNECTED,
	/*
	 * frontend xenbus state changed to XenbusStateClosed,
	 * interface disconnected
	 */
	XDB_DISCONNECTED
};

/*
 * backend device status
 */
enum xdb_dev_state {
	/* initial state */
	XDB_DEV_UNKNOWN,
	/* backend device is ready (hotplug script finishes successfully) */
	XDB_DEV_READY
};

/*
 * frontend status
 */
enum xdb_fe_state {
	/* initial state */
	XDB_FE_UNKNOWN,
	/*
	 * frontend's xenbus state has changed to
	 * XenbusStateInitialised, is ready for connecting
	 */
	XDB_FE_READY
};

/*
 * Other handy macrosx
 */
#define	XDB_MINOR2INST(m)	(int)(m)
#define	XDB_INST2MINOR(i)	(minor_t)(i)
#define	XDB_INST2SOFTS(instance)			\
	((xdb_t *)ddi_get_soft_state(xdb_statep, (instance)))
#define	XDB_MAX_IO_PAGES BLKIF_RING_SIZE * BLKIF_MAX_SEGMENTS_PER_REQUEST
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
	/* xdb interface status */
	enum xdb_state	xs_if_status;
	/* backend device status */
	enum xdb_dev_state xs_dev_status;
	/* frontend status */
	enum xdb_fe_state xs_fe_status;
	/* head of free list of xdb_request_t */
	int		xs_free_req;
	/* pre-allocated xdb_request_t pool */
	xdb_request_t	xs_req[BLKIF_RING_SIZE];
	kstat_t		*xs_kstats;
	uint64_t	xs_stat_req_reads;
	uint64_t	xs_stat_req_writes;
	uint64_t	xs_stat_req_barriers;
	uint64_t	xs_stat_req_flushes;
#ifdef DEBUG
	uint64_t page_addrs[XDB_MAX_IO_PAGES]; /* for debug aid */
#endif /* DEBUG */
};

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XDB_H */
