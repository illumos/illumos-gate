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

/*
 * Copyright (c) 2014 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.
 */

#ifndef _SYS_XDF_H
#define	_SYS_XDF_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmlb.h>
#include <sys/dkio.h>

#include <sys/gnttab.h>
#include <xen/sys/xendev.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * VBDs have standard 512 byte blocks
 * A single blkif_request can transfer up to 11 pages of data, 1 page/segment
 */
#define	XB_BSIZE	DEV_BSIZE
#define	XB_BMASK	(XB_BSIZE - 1)
#define	XB_BSHIFT	9
#define	XB_DTOB(bn, vdp)	((bn) * (vdp)->xdf_xdev_secsize)

#define	XB_MAX_SEGLEN	(8 * XB_BSIZE)
#define	XB_SEGOFFSET	(XB_MAX_SEGLEN - 1)
#define	XB_MAX_XFER	(XB_MAX_SEGLEN * BLKIF_MAX_SEGMENTS_PER_REQUEST)
#define	XB_MAXPHYS	(XB_MAX_XFER * BLKIF_RING_SIZE)

/* Number of sectors per segement */
#define	XB_NUM_SECTORS_PER_SEG	(PAGESIZE / XB_BSIZE)
/* sectors are number 0 through XB_NUM_SECTORS_PER_SEG - 1 */
#define	XB_LAST_SECTOR_IN_SEG	(XB_NUM_SECTORS_PER_SEG - 1)


/*
 * Slice for absolute disk transaction.
 *
 * Hack Alert.  XB_SLICE_NONE is a magic value that can be written into the
 * b_private field of buf structures passed to xdf_strategy().  When present
 * it indicates that the I/O is using an absolute offset.  (ie, the I/O is
 * not bound to any one partition.)  This magic value is currently used by
 * the pv_cmdk driver.  This hack is shamelessly stolen from the sun4v vdc
 * driver, another virtual disk device driver.  (Although in the case of
 * vdc the hack is less egregious since it is self contained within the
 * vdc driver, where as here it is used as an interface between the pv_cmdk
 * driver and the xdf driver.)
 */
#define	XB_SLICE_NONE		0xFF

/*
 * blkif status
 */
typedef enum xdf_state {
	/*
	 * initial state
	 */
	XD_UNKNOWN = 0,
	/*
	 * ring and evtchn alloced, xenbus state changed to
	 * XenbusStateInitialised, wait for backend to connect
	 */
	XD_INIT = 1,
	/*
	 * backend and frontend xenbus state has changed to
	 * XenbusStateConnected.  IO is now allowed, but we are not still
	 * fully initialized.
	 */
	XD_CONNECTED = 2,
	/*
	 * We're fully initialized and allowing regular IO.
	 */
	XD_READY = 3,
	/*
	 * vbd interface close request received from backend, no more I/O
	 * requestis allowed to be put into ring buffer, while interrupt handler
	 * is allowed to run to finish any outstanding I/O request, disconnect
	 * process is kicked off by changing xenbus state to XenbusStateClosed
	 */
	XD_CLOSING = 4,
	/*
	 * disconnection process finished, both backend and frontend's
	 * xenbus state has been changed to XenbusStateClosed, can be detached
	 */
	XD_CLOSED = 5,
	/*
	 * We're either being suspended or resuming from a suspend.  If we're
	 * in the process of suspending, we block all new IO, but but allow
	 * existing IO to drain.
	 */
	XD_SUSPEND = 6
} xdf_state_t;

/*
 * 16 partitions + fdisk
 */
#define	XDF_PSHIFT	6
#define	XDF_PMASK	((1 << XDF_PSHIFT) - 1)
#define	XDF_PEXT	(1 << XDF_PSHIFT)
#define	XDF_MINOR(i, m) (((i) << XDF_PSHIFT) | (m))
#define	XDF_INST(m)	((m) >> XDF_PSHIFT)
#define	XDF_PART(m)	((m) & XDF_PMASK)

/*
 * one blkif_request_t will have one corresponding ge_slot_t
 * where we save those grant table refs used in this blkif_request_t
 *
 * the id of this ge_slot_t will also be put into 'id' field in
 * each blkif_request_t when sent out to the ring buffer.
 */
typedef struct ge_slot {
	list_node_t	gs_vreq_link;
	struct v_req	*gs_vreq;
	domid_t		gs_oeid;
	int		gs_isread;
	grant_ref_t	gs_ghead;
	int		gs_ngrefs;
	grant_ref_t	gs_ge[BLKIF_MAX_SEGMENTS_PER_REQUEST];
} ge_slot_t;

/*
 * vbd I/O request
 *
 * An instance of this structure is bound to each buf passed to
 * the driver's strategy by setting the pointer into bp->av_back.
 * The id of this vreq will also be put into 'id' field in each
 * blkif_request_t when sent out to the ring buffer for one DMA
 * window of this buf.
 *
 * Vreq mainly contains DMA information for this buf. In one vreq/buf,
 * there could be more than one DMA window, each of which will be
 * mapped to one blkif_request_t/ge_slot_t. Ge_slot_t contains all grant
 * table entry information for this buf. The ge_slot_t for current DMA
 * window is pointed to by v_gs in vreq.
 *
 * So, grant table entries will only be alloc'ed when the DMA window is
 * about to be transferred via blkif_request_t to the ring buffer. And
 * they will be freed right after the blkif_response_t is seen. By this
 * means, we can make use of grant table entries more efficiently.
 */
typedef struct v_req {
	list_node_t	v_link;
	list_t		v_gs;
	int		v_status;
	buf_t		*v_buf;
	uint_t		v_ndmacs;
	uint_t		v_dmaw;
	uint_t		v_ndmaws;
	uint_t		v_nslots;
	uint64_t	v_blkno;
	ddi_dma_handle_t v_memdmahdl;
	ddi_acc_handle_t v_align;
	ddi_dma_handle_t v_dmahdl;
	ddi_dma_cookie_t v_dmac;
	caddr_t		v_abuf;
	uint8_t		v_flush_diskcache;
	boolean_t	v_runq;
} v_req_t;

/*
 * Status set and checked in vreq->v_status by vreq_setup()
 *
 * These flags will help us to continue the vreq setup work from last failure
 * point, instead of starting from scratch after each failure.
 */
#define	VREQ_INIT		0x0
#define	VREQ_INIT_DONE		0x1
#define	VREQ_DMAHDL_ALLOCED	0x2
#define	VREQ_MEMDMAHDL_ALLOCED	0x3
#define	VREQ_DMAMEM_ALLOCED	0x4
#define	VREQ_DMABUF_BOUND	0x5
#define	VREQ_GS_ALLOCED		0x6
#define	VREQ_DMAWIN_DONE	0x7

/*
 * virtual block device per-instance softstate
 */
typedef struct xdf {
	dev_info_t	*xdf_dip;
	char		*xdf_addr;
	ddi_iblock_cookie_t xdf_ibc; /* mutex iblock cookie */
	domid_t		xdf_peer; /* otherend's dom ID */
	xendev_ring_t	*xdf_xb_ring; /* I/O ring buffer */
	ddi_acc_handle_t xdf_xb_ring_hdl; /* access handler for ring buffer */
	list_t		xdf_vreq_act; /* active vreq list */
	buf_t		*xdf_f_act; /* active buf list head */
	buf_t		*xdf_l_act; /* active buf list tail */
	buf_t		*xdf_i_act; /* active buf list index */
	xdf_state_t	xdf_state; /* status of this virtual disk */
	boolean_t	xdf_suspending;
	ulong_t		xdf_vd_open[OTYPCNT];
	ulong_t		xdf_vd_lyropen[XDF_PEXT];
	ulong_t		xdf_connect_req;
	kthread_t	*xdf_connect_thread;
	ulong_t		xdf_vd_exclopen;
	kmutex_t	xdf_iostat_lk; /* muxes lock for the iostat ptr */
	kmutex_t	xdf_dev_lk; /* mutex lock for I/O path */
	kmutex_t	xdf_cb_lk; /* mutex lock for event handling path */
	kcondvar_t	xdf_dev_cv; /* cv used in I/O path */
	uint_t		xdf_dinfo; /* disk info from backend xenstore */
	diskaddr_t	xdf_xdev_nblocks; /* total size in block */
	uint_t		xdf_xdev_secsize; /* disk blksize from backend */
	cmlb_geom_t	xdf_pgeom;
	boolean_t	xdf_pgeom_set;
	boolean_t	xdf_pgeom_fixed;
	kstat_t		*xdf_xdev_iostat;
	cmlb_handle_t	xdf_vd_lbl;
	ddi_softintr_t	xdf_softintr_id;
	timeout_id_t	xdf_timeout_id;
	struct gnttab_free_callback xdf_gnt_callback;
	boolean_t	xdf_feature_barrier;
	boolean_t	xdf_flush_supported;
	boolean_t	xdf_media_req_supported;
	boolean_t	xdf_wce;
	boolean_t	xdf_cmlb_reattach;
	char		*xdf_flush_mem;
	char		*xdf_cache_flush_block;
	int		xdf_evtchn;
	enum dkio_state	xdf_mstate;
	kcondvar_t	xdf_mstate_cv;
	kcondvar_t	xdf_hp_status_cv;
	struct buf	*xdf_ready_bp;
	ddi_taskq_t	*xdf_ready_tq;
	kthread_t	*xdf_ready_tq_thread;
	struct buf	*xdf_ready_tq_bp;
	ddi_devid_t	xdf_tgt_devid;
#ifdef	DEBUG
	int		xdf_dmacallback_num;
	kthread_t	*xdf_oe_change_thread;
#endif
} xdf_t;

/*
 * VBD I/O requests must be aligned on a 512-byte boundary and specify
 * a transfer size which is a mutiple of 512-bytes
 */
#define	ALIGNED_XFER(bp) \
	((((uintptr_t)((bp)->b_un.b_addr) & XB_BMASK) == 0) && \
	(((bp)->b_bcount & XB_BMASK) == 0))

#define	U_INVAL(u)	(((u)->uio_loffset & (offset_t)(XB_BMASK)) || \
	((u)->uio_iov->iov_len & (offset_t)(XB_BMASK)))

/* wrap pa_to_ma() for xdf to run in dom0 */
#define	PATOMA(addr)	(DOMAIN_IS_INITDOMAIN(xen_info) ? addr : pa_to_ma(addr))

#define	XD_IS_RO(vbd)	VOID2BOOLEAN((vbd)->xdf_dinfo & VDISK_READONLY)
#define	XD_IS_CD(vbd)	VOID2BOOLEAN((vbd)->xdf_dinfo & VDISK_CDROM)
#define	XD_IS_RM(vbd)	VOID2BOOLEAN((vbd)->xdf_dinfo & VDISK_REMOVABLE)
#define	IS_READ(bp)	VOID2BOOLEAN((bp)->b_flags & B_READ)
#define	IS_ERROR(bp)	VOID2BOOLEAN((bp)->b_flags & B_ERROR)

#define	XDF_UPDATE_IO_STAT(vdp, bp)					\
	{								\
		kstat_io_t *kip = KSTAT_IO_PTR((vdp)->xdf_xdev_iostat);	\
		size_t n_done = (bp)->b_bcount - (bp)->b_resid;		\
		if ((bp)->b_flags & B_READ) {				\
			kip->reads++;					\
			kip->nread += n_done;				\
		} else {                                                \
			kip->writes++;					\
			kip->nwritten += n_done;			\
		}							\
	}

#ifdef DEBUG
#define	DPRINTF(flag, args)	{if (xdf_debug & (flag)) prom_printf args; }
#define	SETDMACBON(vbd)		{(vbd)->xdf_dmacallback_num++; }
#define	SETDMACBOFF(vbd)	{(vbd)->xdf_dmacallback_num--; }
#define	ISDMACBON(vbd)		((vbd)->xdf_dmacallback_num > 0)
#else
#define	DPRINTF(flag, args)
#define	SETDMACBON(vbd)
#define	SETDMACBOFF(vbd)
#define	ISDMACBON(vbd)
#endif /* DEBUG */

#define	DDI_DBG		0x1
#define	DMA_DBG		0x2
#define	INTR_DBG	0x8
#define	IO_DBG		0x10
#define	IOCTL_DBG	0x20
#define	SUSRES_DBG	0x40
#define	LBL_DBG		0x80

#ifdef XPV_HVM_DRIVER
extern int xdf_lb_getinfo(dev_info_t *, int, void *, void *);
extern int xdf_lb_rdwr(dev_info_t *, uchar_t, void *, diskaddr_t, size_t,
    void *);
extern void xdfmin(struct buf *bp);
extern dev_info_t *xdf_hvm_hold(const char *);
extern boolean_t xdf_hvm_connect(dev_info_t *);
extern int xdf_hvm_setpgeom(dev_info_t *, cmlb_geom_t *);
extern boolean_t xdf_is_cd(dev_info_t *);
extern boolean_t xdf_is_rm(dev_info_t *);
extern boolean_t xdf_media_req_supported(dev_info_t *);
#endif /* XPV_HVM_DRIVER */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XDF_H */
