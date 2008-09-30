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

/*
 * Note: This is the backend part of the split PV disk driver. This driver
 * is not a nexus driver, nor is it a leaf driver(block/char/stream driver).
 * Currently, it does not create any minor node. So, although, it runs in
 * backend domain, it will not be used directly from within dom0.
 * It simply gets block I/O requests issued by frontend from a shared page
 * (blkif ring buffer - defined by Xen) between backend and frontend domain,
 * generates a buf, and push it down to underlying disk target driver via
 * ldi interface. When buf is done, this driver will generate a response
 * and put it into ring buffer to inform frontend of the status of the I/O
 * request issued by it. When a new virtual device entry is added in xenstore,
 * there will be an watch event sent from Xen to xvdi framework, who will,
 * in turn, create the devinfo node and try to attach this driver
 * (see xvdi_create_dev). When frontend peer changes its state to
 * XenbusStateClose, an event will also be sent from Xen to xvdi framework,
 * who will detach and remove this devinfo node (see i_xvdi_oestate_handler).
 * I/O requests get from ring buffer and event coming from xenstore cannot be
 * trusted. We verify them in xdb_get_buf() and xdb_check_state_transition().
 *
 * Virtual device configuration is read/written from/to the database via
 * xenbus_* interfaces. Driver also use xvdi_* to interact with hypervisor.
 * There is an on-going effort to make xvdi_* cover all xenbus_*.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/list.h>
#include <sys/dkio.h>
#include <sys/cmlb.h>
#include <sys/vtoc.h>
#include <sys/modctl.h>
#include <sys/bootconf.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>
#include <public/io/xenbus.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/sys/xendev.h>
#include <sys/gnttab.h>
#include <sys/scsi/generic/inquiry.h>
#include <vm/seg_kmem.h>
#include <vm/hat_i86.h>
#include <sys/gnttab.h>
#include <sys/lofi.h>
#include <io/xdf.h>
#include <xen/io/blkif_impl.h>
#include <io/xdb.h>

static xdb_t *xdb_statep;
static int xdb_debug = 0;

static int xdb_push_response(xdb_t *, uint64_t, uint8_t, uint16_t);
static int xdb_get_request(xdb_t *, blkif_request_t *);
static void blkif_get_x86_32_req(blkif_request_t *, blkif_x86_32_request_t *);
static void blkif_get_x86_64_req(blkif_request_t *, blkif_x86_64_request_t *);

#ifdef DEBUG
/*
 * debug aid functions
 */

static void
logva(xdb_t *vdp, uint64_t va)
{
	uint64_t *page_addrs;
	int i;

	page_addrs = vdp->page_addrs;
	for (i = 0; i < XDB_MAX_IO_PAGES(vdp); i++) {
		if (page_addrs[i] == va)
			debug_enter("VA remapping found!");
	}

	for (i = 0; i < XDB_MAX_IO_PAGES(vdp); i++) {
		if (page_addrs[i] == 0) {
			page_addrs[i] = va;
			break;
		}
	}
	ASSERT(i < XDB_MAX_IO_PAGES(vdp));
}

static void
unlogva(xdb_t *vdp, uint64_t va)
{
	uint64_t *page_addrs;
	int i;

	page_addrs = vdp->page_addrs;
	for (i = 0; i < XDB_MAX_IO_PAGES(vdp); i++) {
		if (page_addrs[i] == va) {
			page_addrs[i] = 0;
			break;
		}
	}
	ASSERT(i < XDB_MAX_IO_PAGES(vdp));
}

static void
xdb_dump_request_oe(blkif_request_t *req)
{
	int i;

	/*
	 * Exploit the public interface definitions for BLKIF_OP_READ
	 * etc..
	 */
	char *op_name[] = { "read", "write", "barrier", "flush" };

	XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE, "op=%s", op_name[req->operation]));
	XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE, "num of segments=%d",
	    req->nr_segments));
	XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE, "handle=%d", req->handle));
	XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE, "id=%llu",
	    (unsigned long long)req->id));
	XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE, "start sector=%llu",
	    (unsigned long long)req->sector_number));
	for (i = 0; i < req->nr_segments; i++) {
		XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE, "gref=%d, first sec=%d,"
		    "last sec=%d", req->seg[i].gref, req->seg[i].first_sect,
		    req->seg[i].last_sect));
	}
}
#endif /* DEBUG */

/*
 * Statistics.
 */
static char *xdb_stats[] = {
	"rd_reqs",
	"wr_reqs",
	"br_reqs",
	"fl_reqs",
	"oo_reqs"
};

static int
xdb_kstat_update(kstat_t *ksp, int flag)
{
	xdb_t *vdp;
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	vdp = ksp->ks_private;
	knp = ksp->ks_data;

	/*
	 * Assignment order should match that of the names in
	 * xdb_stats.
	 */
	(knp++)->value.ui64 = vdp->xs_stat_req_reads;
	(knp++)->value.ui64 = vdp->xs_stat_req_writes;
	(knp++)->value.ui64 = vdp->xs_stat_req_barriers;
	(knp++)->value.ui64 = vdp->xs_stat_req_flushes;
	(knp++)->value.ui64 = 0; /* oo_req */

	return (0);
}

static boolean_t
xdb_kstat_init(xdb_t *vdp)
{
	int nstat = sizeof (xdb_stats) / sizeof (xdb_stats[0]);
	char **cp = xdb_stats;
	kstat_named_t *knp;

	if ((vdp->xs_kstats = kstat_create("xdb",
	    ddi_get_instance(vdp->xs_dip),
	    "req_statistics", "block", KSTAT_TYPE_NAMED,
	    nstat, 0)) == NULL)
		return (B_FALSE);

	vdp->xs_kstats->ks_private = vdp;
	vdp->xs_kstats->ks_update = xdb_kstat_update;

	knp = vdp->xs_kstats->ks_data;
	while (nstat > 0) {
		kstat_named_init(knp, *cp, KSTAT_DATA_UINT64);
		knp++;
		cp++;
		nstat--;
	}

	kstat_install(vdp->xs_kstats);

	return (B_TRUE);
}

static int xdb_biodone(buf_t *);

static buf_t *
xdb_get_buf(xdb_t *vdp, blkif_request_t *req, xdb_request_t *xreq)
{
	buf_t *bp;
	uint8_t segs, curseg;
	int sectors;
	int i, err;
	gnttab_map_grant_ref_t mapops[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	ddi_acc_handle_t acchdl;

	acchdl = vdp->xs_ring_hdl;
	bp = XDB_XREQ2BP(xreq);
	curseg = xreq->xr_curseg;
	/* init a new xdb request */
	if (req != NULL) {
		ASSERT(MUTEX_HELD(&vdp->xs_iomutex));
		boolean_t pagemapok = B_TRUE;
		uint8_t op = ddi_get8(acchdl, &req->operation);

		xreq->xr_vdp = vdp;
		xreq->xr_op = op;
		xreq->xr_id = ddi_get64(acchdl, &req->id);
		segs = xreq->xr_buf_pages = ddi_get8(acchdl, &req->nr_segments);
		if (segs == 0) {
			if (op != BLKIF_OP_FLUSH_DISKCACHE)
				cmn_err(CE_WARN, "!non-BLKIF_OP_FLUSH_DISKCACHE"
				    " is seen from domain %d with zero "
				    "length data buffer!", vdp->xs_peer);
			bioinit(bp);
			bp->b_bcount = 0;
			bp->b_lblkno = 0;
			bp->b_un.b_addr = NULL;
			return (bp);
		} else if (op == BLKIF_OP_FLUSH_DISKCACHE) {
			cmn_err(CE_WARN, "!BLKIF_OP_FLUSH_DISKCACHE"
			    " is seen from domain %d with non-zero "
			    "length data buffer!", vdp->xs_peer);
		}

		/*
		 * segs should be no bigger than BLKIF_MAX_SEGMENTS_PER_REQUEST
		 * according to the definition of blk interface by Xen
		 * we do sanity check here
		 */
		if (segs > BLKIF_MAX_SEGMENTS_PER_REQUEST)
			segs = xreq->xr_buf_pages =
			    BLKIF_MAX_SEGMENTS_PER_REQUEST;

		for (i = 0; i < segs; i++) {
			uint8_t fs, ls;

			mapops[i].host_addr =
			    (uint64_t)(uintptr_t)XDB_IOPAGE_VA(
			    vdp->xs_iopage_va, xreq->xr_idx, i);
			mapops[i].dom = vdp->xs_peer;
			mapops[i].ref = ddi_get32(acchdl, &req->seg[i].gref);
			mapops[i].flags = GNTMAP_host_map;
			if (op != BLKIF_OP_READ)
				mapops[i].flags |= GNTMAP_readonly;

			fs = ddi_get8(acchdl, &req->seg[i].first_sect);
			ls = ddi_get8(acchdl, &req->seg[i].last_sect);

			/*
			 * first_sect should be no bigger than last_sect and
			 * both of them should be no bigger than
			 * (PAGESIZE / XB_BSIZE - 1) according to definition
			 * of blk interface by Xen, so sanity check again
			 */
			if (fs > (PAGESIZE / XB_BSIZE - 1))
				fs = PAGESIZE / XB_BSIZE - 1;
			if (ls > (PAGESIZE / XB_BSIZE - 1))
				ls = PAGESIZE / XB_BSIZE - 1;
			if (fs > ls)
				fs = ls;

			xreq->xr_segs[i].fs = fs;
			xreq->xr_segs[i].ls = ls;
		}

		/* map in io pages */
		err = xen_map_gref(GNTTABOP_map_grant_ref, mapops, i, B_FALSE);
		if (err != 0)
			return (NULL);
		for (i = 0; i < segs; i++) {
			/*
			 * Although HYPERVISOR_grant_table_op() returned no
			 * error, mapping of each single page can fail. So,
			 * we have to do the check here and handle the error
			 * if needed
			 */
			if (mapops[i].status != GNTST_okay) {
				int j;
				for (j = 0; j < i; j++) {
#ifdef DEBUG
					unlogva(vdp, mapops[j].host_addr);
#endif
					xen_release_pfn(
					    xreq->xr_plist[j].p_pagenum);
				}
				pagemapok = B_FALSE;
				break;
			}
			/* record page mapping handle for unmapping later */
			xreq->xr_page_hdls[i] = mapops[i].handle;
#ifdef DEBUG
			logva(vdp, mapops[i].host_addr);
#endif
			/*
			 * Pass the MFNs down using the shadow list (xr_pplist)
			 *
			 * This is pretty ugly since we have implict knowledge
			 * of how the rootnex binds buffers.
			 * The GNTTABOP_map_grant_ref op makes us do some ugly
			 * stuff since we're not allowed to touch these PTEs
			 * from the VM.
			 *
			 * Obviously, these aren't real page_t's. The rootnex
			 * only needs p_pagenum.
			 * Also, don't use btop() here or 32 bit PAE breaks.
			 */
			xreq->xr_pplist[i] = &xreq->xr_plist[i];
			xreq->xr_plist[i].p_pagenum =
			    xen_assign_pfn(mapops[i].dev_bus_addr >> PAGESHIFT);
		}

		/*
		 * not all pages mapped in successfully, unmap those mapped-in
		 * page and return failure
		 */
		if (!pagemapok) {
			gnttab_unmap_grant_ref_t unmapop;

			for (i = 0; i < segs; i++) {
				if (mapops[i].status != GNTST_okay)
					continue;
				unmapop.host_addr =
				    (uint64_t)(uintptr_t)XDB_IOPAGE_VA(
				    vdp->xs_iopage_va, xreq->xr_idx, i);
				unmapop.dev_bus_addr = NULL;
				unmapop.handle = mapops[i].handle;
				(void) HYPERVISOR_grant_table_op(
				    GNTTABOP_unmap_grant_ref, &unmapop, 1);
			}

			return (NULL);
		}
		bioinit(bp);
		bp->b_lblkno = ddi_get64(acchdl, &req->sector_number);
		bp->b_flags = B_BUSY | B_SHADOW | B_PHYS;
		bp->b_flags |= (ddi_get8(acchdl, &req->operation) ==
		    BLKIF_OP_READ) ? B_READ : (B_WRITE | B_ASYNC);
	} else {
		uint64_t blkst;
		int isread;

		/* reuse this buf */
		blkst = bp->b_lblkno + bp->b_bcount / DEV_BSIZE;
		isread = bp->b_flags & B_READ;
		bioreset(bp);
		bp->b_lblkno = blkst;
		bp->b_flags = B_BUSY | B_SHADOW | B_PHYS;
		bp->b_flags |= isread ? B_READ : (B_WRITE | B_ASYNC);
		XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE, "reuse buf, xreq is %d!!",
		    xreq->xr_idx));
	}

	/* form a buf */
	bp->b_un.b_addr = XDB_IOPAGE_VA(vdp->xs_iopage_va, xreq->xr_idx,
	    curseg) + xreq->xr_segs[curseg].fs * DEV_BSIZE;
	bp->b_shadow = &xreq->xr_pplist[curseg];
	bp->b_iodone = xdb_biodone;
	sectors = 0;
	for (i = curseg; i < xreq->xr_buf_pages; i++) {
		/*
		 * The xreq->xr_segs[i].fs of the first seg can be non-zero
		 * otherwise, we'll break it into multiple bufs
		 */
		if ((i != curseg) && (xreq->xr_segs[i].fs != 0)) {
			break;
		}
		sectors += (xreq->xr_segs[i].ls - xreq->xr_segs[i].fs + 1);
	}
	xreq->xr_curseg = i;
	bp->b_bcount = sectors * DEV_BSIZE;
	bp->b_bufsize = bp->b_bcount;

	return (bp);
}

static xdb_request_t *
xdb_get_req(xdb_t *vdp)
{
	xdb_request_t *req;
	int idx;

	ASSERT(MUTEX_HELD(&vdp->xs_iomutex));
	ASSERT(vdp->xs_free_req != -1);
	req = &vdp->xs_req[vdp->xs_free_req];
	vdp->xs_free_req = req->xr_next;
	idx = req->xr_idx;
	bzero(req, sizeof (xdb_request_t));
	req->xr_idx = idx;
	return (req);
}

static void
xdb_free_req(xdb_request_t *req)
{
	xdb_t *vdp = req->xr_vdp;

	ASSERT(MUTEX_HELD(&vdp->xs_iomutex));
	req->xr_next = vdp->xs_free_req;
	vdp->xs_free_req = req->xr_idx;
}

static void
xdb_response(xdb_t *vdp, blkif_request_t *req, boolean_t ok)
{
	ddi_acc_handle_t acchdl = vdp->xs_ring_hdl;

	if (xdb_push_response(vdp, ddi_get64(acchdl, &req->id),
	    ddi_get8(acchdl, &req->operation), ok))
		xvdi_notify_oe(vdp->xs_dip);
}

static void
xdb_init_ioreqs(xdb_t *vdp)
{
	int i;

	ASSERT(vdp->xs_nentry);

	if (vdp->xs_req == NULL)
		vdp->xs_req = kmem_alloc(vdp->xs_nentry *
		    sizeof (xdb_request_t), KM_SLEEP);
#ifdef DEBUG
	if (vdp->page_addrs == NULL)
		vdp->page_addrs = kmem_zalloc(XDB_MAX_IO_PAGES(vdp) *
		    sizeof (uint64_t), KM_SLEEP);
#endif
	for (i = 0; i < vdp->xs_nentry; i++) {
		vdp->xs_req[i].xr_idx = i;
		vdp->xs_req[i].xr_next = i + 1;
	}
	vdp->xs_req[vdp->xs_nentry - 1].xr_next = -1;
	vdp->xs_free_req = 0;

	/* alloc va in host dom for io page mapping */
	vdp->xs_iopage_va = vmem_xalloc(heap_arena,
	    XDB_MAX_IO_PAGES(vdp) * PAGESIZE, PAGESIZE, 0, 0, 0, 0,
	    VM_SLEEP);
	for (i = 0; i < XDB_MAX_IO_PAGES(vdp); i++)
		hat_prepare_mapping(kas.a_hat,
		    vdp->xs_iopage_va + i * PAGESIZE, NULL);
}

static void
xdb_uninit_ioreqs(xdb_t *vdp)
{
	int i;

	for (i = 0; i < XDB_MAX_IO_PAGES(vdp); i++)
		hat_release_mapping(kas.a_hat,
		    vdp->xs_iopage_va + i * PAGESIZE);
	vmem_xfree(heap_arena, vdp->xs_iopage_va,
	    XDB_MAX_IO_PAGES(vdp) * PAGESIZE);
	if (vdp->xs_req != NULL) {
		kmem_free(vdp->xs_req, vdp->xs_nentry * sizeof (xdb_request_t));
		vdp->xs_req = NULL;
	}
#ifdef DEBUG
	if (vdp->page_addrs != NULL) {
		kmem_free(vdp->page_addrs, XDB_MAX_IO_PAGES(vdp) *
		    sizeof (uint64_t));
		vdp->page_addrs = NULL;
	}
#endif
}

static uint_t
xdb_intr(caddr_t arg)
{
	blkif_request_t req;
	blkif_request_t *reqp = &req;
	xdb_request_t *xreq;
	buf_t *bp;
	uint8_t op;
	xdb_t *vdp = (xdb_t *)arg;
	int ret = DDI_INTR_UNCLAIMED;
	dev_info_t *dip = vdp->xs_dip;

	XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE,
	    "xdb@%s: I/O request received from dom %d",
	    ddi_get_name_addr(dip), vdp->xs_peer));

	mutex_enter(&vdp->xs_iomutex);

	/* shouldn't touch ring buffer if not in connected state */
	if (vdp->xs_if_status != XDB_CONNECTED) {
		mutex_exit(&vdp->xs_iomutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * We'll loop till there is no more request in the ring
	 * We won't stuck in this loop for ever since the size of ring buffer
	 * is limited, and frontend will stop pushing requests into it when
	 * the ring buffer is full
	 */

	/* req_event will be increased in xvdi_ring_get_request() */
	while (xdb_get_request(vdp, reqp)) {
		ret = DDI_INTR_CLAIMED;

		op = ddi_get8(vdp->xs_ring_hdl, &reqp->operation);
		if (op == BLKIF_OP_READ			||
		    op == BLKIF_OP_WRITE		||
		    op == BLKIF_OP_WRITE_BARRIER	||
		    op == BLKIF_OP_FLUSH_DISKCACHE) {
#ifdef DEBUG
			xdb_dump_request_oe(reqp);
#endif
			xreq = xdb_get_req(vdp);
			ASSERT(xreq);
			switch (op) {
			case BLKIF_OP_READ:
				vdp->xs_stat_req_reads++;
				break;
			case BLKIF_OP_WRITE_BARRIER:
				vdp->xs_stat_req_barriers++;
				/* FALLTHRU */
			case BLKIF_OP_WRITE:
				vdp->xs_stat_req_writes++;
				break;
			case BLKIF_OP_FLUSH_DISKCACHE:
				vdp->xs_stat_req_flushes++;
				break;
			}

			xreq->xr_curseg = 0; /* start from first segment */
			bp = xdb_get_buf(vdp, reqp, xreq);
			if (bp == NULL) {
				/* failed to form a buf */
				xdb_free_req(xreq);
				xdb_response(vdp, reqp, B_FALSE);
				continue;
			}
			bp->av_forw = NULL;

			XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE,
			    " buf %p, blkno %lld, size %lu, addr %p",
			    (void *)bp, (longlong_t)bp->b_blkno,
			    (ulong_t)bp->b_bcount, (void *)bp->b_un.b_addr));

			/* send bp to underlying blk driver */
			if (vdp->xs_f_iobuf == NULL) {
				vdp->xs_f_iobuf = vdp->xs_l_iobuf = bp;
			} else {
				vdp->xs_l_iobuf->av_forw = bp;
				vdp->xs_l_iobuf = bp;
			}
		} else {
			xdb_response(vdp, reqp, B_FALSE);
			XDB_DBPRINT(XDB_DBG_IO, (CE_WARN, "xdb@%s: "
			    "Unsupported cmd received from dom %d",
			    ddi_get_name_addr(dip), vdp->xs_peer));
		}
	}
	/* notify our taskq to push buf to underlying blk driver */
	if (ret == DDI_INTR_CLAIMED)
		cv_broadcast(&vdp->xs_iocv);

	mutex_exit(&vdp->xs_iomutex);

	return (ret);
}

static int
xdb_biodone(buf_t *bp)
{
	int i, err, bioerr;
	uint8_t segs;
	gnttab_unmap_grant_ref_t unmapops[BLKIF_MAX_SEGMENTS_PER_REQUEST];
	xdb_request_t *xreq = XDB_BP2XREQ(bp);
	xdb_t *vdp = xreq->xr_vdp;
	buf_t *nbp;

	bioerr = geterror(bp);
	if (bioerr)
		XDB_DBPRINT(XDB_DBG_IO, (CE_WARN, "xdb@%s: I/O error %d",
		    ddi_get_name_addr(vdp->xs_dip), bioerr));

	/* check if we are done w/ this I/O request */
	if ((bioerr == 0) && (xreq->xr_curseg < xreq->xr_buf_pages)) {
		nbp = xdb_get_buf(vdp, NULL, xreq);
		if (nbp) {
			err = ldi_strategy(vdp->xs_ldi_hdl, nbp);
			if (err == 0) {
				XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE,
				    "sent buf to backend ok"));
				return (DDI_SUCCESS);
			}
			bioerr = EIO;
			XDB_DBPRINT(XDB_DBG_IO, (CE_WARN, "xdb@%s: "
			    "sent buf to backend dev failed, err=%d",
			    ddi_get_name_addr(vdp->xs_dip), err));
		} else {
			bioerr = EIO;
		}
	}

	/* unmap io pages */
	segs = xreq->xr_buf_pages;
	/*
	 * segs should be no bigger than BLKIF_MAX_SEGMENTS_PER_REQUEST
	 * according to the definition of blk interface by Xen
	 */
	ASSERT(segs <= BLKIF_MAX_SEGMENTS_PER_REQUEST);
	for (i = 0; i < segs; i++) {
		unmapops[i].host_addr = (uint64_t)(uintptr_t)XDB_IOPAGE_VA(
		    vdp->xs_iopage_va, xreq->xr_idx, i);
#ifdef DEBUG
		mutex_enter(&vdp->xs_iomutex);
		unlogva(vdp, unmapops[i].host_addr);
		mutex_exit(&vdp->xs_iomutex);
#endif
		unmapops[i].dev_bus_addr = NULL;
		unmapops[i].handle = xreq->xr_page_hdls[i];
	}
	err = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref,
	    unmapops, segs);
	ASSERT(!err);

	/*
	 * If we have reached a barrier write or a cache flush , then we must
	 * flush all our I/Os.
	 */
	if (xreq->xr_op == BLKIF_OP_WRITE_BARRIER ||
	    xreq->xr_op == BLKIF_OP_FLUSH_DISKCACHE) {
		/*
		 * XXX At this point the write did succeed, so I don't
		 * believe we should report an error because the flush
		 * failed. However, this is a debatable point, so
		 * maybe we need to think more carefully about this.
		 * For now, just cast to void.
		 */
		(void) ldi_ioctl(vdp->xs_ldi_hdl,
		    DKIOCFLUSHWRITECACHE, NULL, FKIOCTL, kcred, NULL);
	}

	mutex_enter(&vdp->xs_iomutex);

	/* send response back to frontend */
	if (vdp->xs_if_status == XDB_CONNECTED) {
		if (xdb_push_response(vdp, xreq->xr_id, xreq->xr_op, bioerr))
			xvdi_notify_oe(vdp->xs_dip);
		XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE,
		    "sent resp back to frontend, id=%llu",
		    (unsigned long long)xreq->xr_id));
	}
	/* free io resources */
	biofini(bp);
	xdb_free_req(xreq);

	vdp->xs_ionum--;
	if ((vdp->xs_if_status != XDB_CONNECTED) && (vdp->xs_ionum == 0)) {
		/* we're closing, someone is waiting for I/O clean-up */
		cv_signal(&vdp->xs_ionumcv);
	}

	mutex_exit(&vdp->xs_iomutex);

	return (DDI_SUCCESS);
}

static int
xdb_bindto_frontend(xdb_t *vdp)
{
	int err;
	char *oename;
	grant_ref_t gref;
	evtchn_port_t evtchn;
	dev_info_t *dip = vdp->xs_dip;
	char protocol[64] = "";

	/*
	 * Gather info from frontend
	 */
	oename = xvdi_get_oename(dip);
	if (oename == NULL)
		return (DDI_FAILURE);

	err = xenbus_gather(XBT_NULL, oename,
	    "ring-ref", "%lu", &gref, "event-channel", "%u", &evtchn, NULL);
	if (err != 0) {
		xvdi_fatal_error(dip, err,
		    "Getting ring-ref and evtchn from frontend");
		return (DDI_FAILURE);
	}

	vdp->xs_blk_protocol = BLKIF_PROTOCOL_NATIVE;
	vdp->xs_nentry = BLKIF_RING_SIZE;
	vdp->xs_entrysize = sizeof (union blkif_sring_entry);

	err = xenbus_gather(XBT_NULL, oename,
	    "protocol", "%63s", protocol, NULL);
	if (err)
		(void) strcpy(protocol, "unspecified, assuming native");
	else {
		/*
		 * We must check for NATIVE first, so that the fast path
		 * is taken for copying data from the guest to the host.
		 */
		if (strcmp(protocol, XEN_IO_PROTO_ABI_NATIVE) != 0) {
			if (strcmp(protocol, XEN_IO_PROTO_ABI_X86_32) == 0) {
				vdp->xs_blk_protocol = BLKIF_PROTOCOL_X86_32;
				vdp->xs_nentry = BLKIF_X86_32_RING_SIZE;
				vdp->xs_entrysize =
				    sizeof (union blkif_x86_32_sring_entry);
			} else if (strcmp(protocol, XEN_IO_PROTO_ABI_X86_64) ==
			    0) {
				vdp->xs_blk_protocol = BLKIF_PROTOCOL_X86_64;
				vdp->xs_nentry = BLKIF_X86_64_RING_SIZE;
				vdp->xs_entrysize =
				    sizeof (union blkif_x86_64_sring_entry);
			} else {
				xvdi_fatal_error(dip, err, "unknown protocol");
				return (DDI_FAILURE);
			}
		}
	}
#ifdef DEBUG
	cmn_err(CE_NOTE, "!xdb@%s: blkif protocol '%s' ",
	    ddi_get_name_addr(dip), protocol);
#endif

	/*
	 * map and init ring
	 *
	 * The ring parameters must match those which have been allocated
	 * in the front end.
	 */
	err = xvdi_map_ring(dip, vdp->xs_nentry, vdp->xs_entrysize,
	    gref, &vdp->xs_ring);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);
	/*
	 * This will be removed after we use shadow I/O ring request since
	 * we don't need to access the ring itself directly, thus the access
	 * handle is not needed
	 */
	vdp->xs_ring_hdl = vdp->xs_ring->xr_acc_hdl;

	/*
	 * bind event channel
	 */
	err = xvdi_bind_evtchn(dip, evtchn);
	if (err != DDI_SUCCESS) {
		xvdi_unmap_ring(vdp->xs_ring);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
xdb_unbindfrom_frontend(xdb_t *vdp)
{
	xvdi_free_evtchn(vdp->xs_dip);
	xvdi_unmap_ring(vdp->xs_ring);
}

#define	LOFI_CTRL_NODE	"/dev/lofictl"
#define	LOFI_DEV_NODE	"/devices/pseudo/lofi@0:"
#define	LOFI_MODE	FREAD | FWRITE | FEXCL

static int
xdb_setup_node(xdb_t *vdp, char *path)
{
	dev_info_t *dip;
	char *xsnode, *node;
	ldi_handle_t ldi_hdl;
	struct lofi_ioctl *li;
	int minor;
	int err;
	unsigned int len;

	dip = vdp->xs_dip;
	xsnode = xvdi_get_xsname(dip);
	if (xsnode == NULL)
		return (DDI_FAILURE);

	err = xenbus_read(XBT_NULL, xsnode, "dynamic-device-path",
	    (void **)&node, &len);
	if (err == ENOENT)
		err = xenbus_read(XBT_NULL, xsnode, "params", (void **)&node,
		    &len);
	if (err != 0) {
		xvdi_fatal_error(vdp->xs_dip, err, "reading 'params'");
		return (DDI_FAILURE);
	}

	if (!XDB_IS_LOFI(vdp)) {
		(void) strlcpy(path, node, MAXPATHLEN + 1);
		kmem_free(node, len);
		return (DDI_SUCCESS);
	}

	do {
		err = ldi_open_by_name(LOFI_CTRL_NODE, LOFI_MODE, kcred,
		    &ldi_hdl, vdp->xs_ldi_li);
	} while (err == EBUSY);
	if (err != 0) {
		kmem_free(node, len);
		return (DDI_FAILURE);
	}

	li = kmem_zalloc(sizeof (*li), KM_SLEEP);
	(void) strlcpy(li->li_filename, node, MAXPATHLEN + 1);
	kmem_free(node, len);
	if (ldi_ioctl(ldi_hdl, LOFI_MAP_FILE, (intptr_t)li,
	    LOFI_MODE | FKIOCTL, kcred, &minor) != 0) {
		cmn_err(CE_WARN, "xdb@%s: Failed to create lofi dev for %s",
		    ddi_get_name_addr(dip), li->li_filename);
		(void) ldi_close(ldi_hdl, LOFI_MODE, kcred);
		kmem_free(li, sizeof (*li));
		return (DDI_FAILURE);
	}
	/*
	 * return '/devices/...' instead of '/dev/lofi/...' since the
	 * former is available immediately after calling ldi_ioctl
	 */
	(void) snprintf(path, MAXPATHLEN + 1, LOFI_DEV_NODE "%d", minor);
	(void) xenbus_printf(XBT_NULL, xsnode, "node", "%s", path);
	(void) ldi_close(ldi_hdl, LOFI_MODE, kcred);
	kmem_free(li, sizeof (*li));
	return (DDI_SUCCESS);
}

static void
xdb_teardown_node(xdb_t *vdp)
{
	dev_info_t *dip;
	char *xsnode, *node;
	ldi_handle_t ldi_hdl;
	struct lofi_ioctl *li;
	int err;
	unsigned int len;

	if (!XDB_IS_LOFI(vdp))
		return;

	dip = vdp->xs_dip;
	xsnode = xvdi_get_xsname(dip);
	if (xsnode == NULL)
		return;

	err = xenbus_read(XBT_NULL, xsnode, "dynamic-device-path",
	    (void **)&node, &len);
	if (err == ENOENT)
		err = xenbus_read(XBT_NULL, xsnode, "params", (void **)&node,
		    &len);
	if (err != 0) {
		xvdi_fatal_error(vdp->xs_dip, err, "reading 'params'");
		return;
	}

	li = kmem_zalloc(sizeof (*li), KM_SLEEP);
	(void) strlcpy(li->li_filename, node, MAXPATHLEN + 1);
	kmem_free(node, len);

	do {
		err = ldi_open_by_name(LOFI_CTRL_NODE, LOFI_MODE, kcred,
		    &ldi_hdl, vdp->xs_ldi_li);
	} while (err == EBUSY);

	if (err != 0) {
		kmem_free(li, sizeof (*li));
		return;
	}

	if (ldi_ioctl(ldi_hdl, LOFI_UNMAP_FILE, (intptr_t)li,
	    LOFI_MODE | FKIOCTL, kcred, NULL) != 0) {
		cmn_err(CE_WARN, "xdb@%s: Failed to delete lofi dev for %s",
		    ddi_get_name_addr(dip), li->li_filename);
	}

	(void) ldi_close(ldi_hdl, LOFI_MODE, kcred);
	kmem_free(li, sizeof (*li));
}

static int
xdb_open_device(xdb_t *vdp)
{
	uint64_t devsize;
	dev_info_t *dip;
	char *xsnode;
	char *nodepath;
	char *mode = NULL;
	char *type = NULL;
	int err;

	dip = vdp->xs_dip;
	xsnode = xvdi_get_xsname(dip);
	if (xsnode == NULL)
		return (DDI_FAILURE);

	err = xenbus_gather(XBT_NULL, xsnode,
	    "mode", NULL, &mode, "type", NULL, &type, NULL);
	if (err != 0) {
		if (mode)
			kmem_free(mode, strlen(mode) + 1);
		if (type)
			kmem_free(type, strlen(type) + 1);
		xvdi_fatal_error(dip, err,
		    "Getting mode and type from backend device");
		return (DDI_FAILURE);
	}
	if (strcmp(type, "file") == 0) {
		vdp->xs_type |= XDB_DEV_LOFI;
	}
	kmem_free(type, strlen(type) + 1);
	if ((strcmp(mode, "r") == NULL) || (strcmp(mode, "ro") == NULL)) {
		vdp->xs_type |= XDB_DEV_RO;
	}
	kmem_free(mode, strlen(mode) + 1);

	/*
	 * try to open backend device
	 */
	if (ldi_ident_from_dip(dip, &vdp->xs_ldi_li) != 0)
		return (DDI_FAILURE);

	nodepath = kmem_zalloc(MAXPATHLEN + 1, KM_SLEEP);
	err = xdb_setup_node(vdp, nodepath);
	if (err != DDI_SUCCESS) {
		xvdi_fatal_error(dip, err,
		    "Getting device path of backend device");
		ldi_ident_release(vdp->xs_ldi_li);
		kmem_free(nodepath, MAXPATHLEN + 1);
		return (DDI_FAILURE);
	}

	if (ldi_open_by_name(nodepath,
	    FREAD | (XDB_IS_RO(vdp) ? 0 : FWRITE),
	    kcred, &vdp->xs_ldi_hdl, vdp->xs_ldi_li) != 0) {
		xdb_teardown_node(vdp);
		ldi_ident_release(vdp->xs_ldi_li);
		cmn_err(CE_WARN, "xdb@%s: Failed to open: %s",
		    ddi_get_name_addr(dip), nodepath);
		kmem_free(nodepath, MAXPATHLEN + 1);
		return (DDI_FAILURE);
	}

	/* check if it's a CD/DVD disc */
	if (ldi_prop_get_int(vdp->xs_ldi_hdl, LDI_DEV_T_ANY | DDI_PROP_DONTPASS,
	    "inquiry-device-type", DTYPE_DIRECT) == DTYPE_RODIRECT)
		vdp->xs_type |= XDB_DEV_CD;
	/* check if it's a removable disk */
	if (ldi_prop_exists(vdp->xs_ldi_hdl,
	    LDI_DEV_T_ANY | DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "removable-media"))
		vdp->xs_type |= XDB_DEV_RMB;

	if (ldi_get_size(vdp->xs_ldi_hdl, &devsize) != DDI_SUCCESS) {
		(void) ldi_close(vdp->xs_ldi_hdl,
		    FREAD | (XDB_IS_RO(vdp) ? 0 : FWRITE), kcred);
		xdb_teardown_node(vdp);
		ldi_ident_release(vdp->xs_ldi_li);
		kmem_free(nodepath, MAXPATHLEN + 1);
		return (DDI_FAILURE);
	}
	vdp->xs_sectors = devsize / XB_BSIZE;

	kmem_free(nodepath, MAXPATHLEN + 1);
	return (DDI_SUCCESS);
}

static void
xdb_close_device(xdb_t *vdp)
{
	(void) ldi_close(vdp->xs_ldi_hdl,
	    FREAD | (XDB_IS_RO(vdp) ? 0 : FWRITE), kcred);
	xdb_teardown_node(vdp);
	ldi_ident_release(vdp->xs_ldi_li);
	vdp->xs_ldi_li = NULL;
	vdp->xs_ldi_hdl = NULL;
}

/*
 * Kick-off connect process
 * If xs_fe_status == XDB_FE_READY and xs_dev_status == XDB_DEV_READY
 * the xs_if_status will be changed to XDB_CONNECTED on success,
 * otherwise, xs_if_status will not be changed
 */
static int
xdb_start_connect(xdb_t *vdp)
{
	uint32_t dinfo;
	xenbus_transaction_t xbt;
	int err, svdst;
	char *xsnode;
	dev_info_t *dip = vdp->xs_dip;
	char *barrier;
	uint_t len;

	/*
	 * Start connect to frontend only when backend device are ready
	 * and frontend has moved to XenbusStateInitialised, which means
	 * ready to connect
	 */
	ASSERT((vdp->xs_fe_status == XDB_FE_READY) &&
	    (vdp->xs_dev_status == XDB_DEV_READY));

	if (((xsnode = xvdi_get_xsname(dip)) == NULL)		 ||
	    ((vdp->xs_peer = xvdi_get_oeid(dip)) == (domid_t)-1) ||
	    (xdb_open_device(vdp) != DDI_SUCCESS))
		return (DDI_FAILURE);

	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateInitialised);

	if (xdb_bindto_frontend(vdp) != DDI_SUCCESS)
		goto errout1;

	/* init i/o requests */
	xdb_init_ioreqs(vdp);

	if (ddi_add_intr(dip, 0, NULL, NULL, xdb_intr, (caddr_t)vdp)
	    != DDI_SUCCESS)
		goto errout2;

	/*
	 * we can recieve intr any time from now on
	 * mark that we're ready to take intr
	 */
	mutex_enter(&vdp->xs_iomutex);
	/*
	 * save it in case we need to restore when we
	 * fail to write xenstore later
	 */
	svdst = vdp->xs_if_status;
	vdp->xs_if_status = XDB_CONNECTED;
	mutex_exit(&vdp->xs_iomutex);

	/* write into xenstore the info needed by frontend */
trans_retry:
	if (xenbus_transaction_start(&xbt)) {
		xvdi_fatal_error(dip, EIO, "transaction start");
		goto errout3;
	}

	/*
	 * If feature-barrier isn't present in xenstore, add it.
	 */
	if (xenbus_read(xbt, xsnode, "feature-barrier",
	    (void **)&barrier, &len) != 0) {
		if ((err = xenbus_printf(xbt, xsnode, "feature-barrier",
		    "%d", 1)) != 0) {
			cmn_err(CE_WARN, "xdb@%s: failed to write "
			    "'feature-barrier'", ddi_get_name_addr(dip));
			xvdi_fatal_error(dip, err, "writing 'feature-barrier'");
			goto abort_trans;
		}
	} else
		kmem_free(barrier, len);

	dinfo = 0;
	if (XDB_IS_RO(vdp))
		dinfo |= VDISK_READONLY;
	if (XDB_IS_CD(vdp))
		dinfo |= VDISK_CDROM;
	if (XDB_IS_RMB(vdp))
		dinfo |= VDISK_REMOVABLE;
	if (err = xenbus_printf(xbt, xsnode, "info", "%u", dinfo)) {
		xvdi_fatal_error(dip, err, "writing 'info'");
		goto abort_trans;
	}

	/* hard-coded 512-byte sector size */
	if (err = xenbus_printf(xbt, xsnode, "sector-size", "%u", DEV_BSIZE)) {
		xvdi_fatal_error(dip, err, "writing 'sector-size'");
		goto abort_trans;
	}

	if (err = xenbus_printf(xbt, xsnode, "sectors", "%"PRIu64,
	    vdp->xs_sectors)) {
		xvdi_fatal_error(dip, err, "writing 'sectors'");
		goto abort_trans;
	}

	if (err = xenbus_printf(xbt, xsnode, "instance", "%d",
	    ddi_get_instance(dip))) {
		xvdi_fatal_error(dip, err, "writing 'instance'");
		goto abort_trans;
	}

	if ((err = xvdi_switch_state(dip, xbt, XenbusStateConnected)) > 0) {
		xvdi_fatal_error(dip, err, "writing 'state'");
		goto abort_trans;
	}

	if (err = xenbus_transaction_end(xbt, 0)) {
		if (err == EAGAIN)
			/* transaction is ended, don't need to abort it */
			goto trans_retry;
		xvdi_fatal_error(dip, err, "completing transaction");
		goto errout3;
	}

	return (DDI_SUCCESS);

abort_trans:
	(void) xenbus_transaction_end(xbt, 1);
errout3:
	mutex_enter(&vdp->xs_iomutex);
	vdp->xs_if_status = svdst;
	mutex_exit(&vdp->xs_iomutex);
	ddi_remove_intr(dip, 0, NULL);
errout2:
	xdb_uninit_ioreqs(vdp);
	xdb_unbindfrom_frontend(vdp);
errout1:
	xdb_close_device(vdp);
	return (DDI_FAILURE);
}

/*
 * Kick-off disconnect process
 * xs_if_status will not be changed
 */
static int
xdb_start_disconnect(xdb_t *vdp)
{
	/*
	 * Kick-off disconnect process
	 */
	if (xvdi_switch_state(vdp->xs_dip, XBT_NULL, XenbusStateClosing) > 0)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/*
 * Disconnect from frontend and close backend device
 * ifstatus will be changed to XDB_DISCONNECTED
 * Xenbus state will be changed to XenbusStateClosed
 */
static void
xdb_close(dev_info_t *dip)
{
	xdb_t *vdp = (xdb_t *)ddi_get_driver_private(dip);

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));

	mutex_enter(&vdp->xs_iomutex);

	if (vdp->xs_if_status != XDB_CONNECTED) {
		vdp->xs_if_status = XDB_DISCONNECTED;
		cv_broadcast(&vdp->xs_iocv);
		mutex_exit(&vdp->xs_iomutex);
		(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosed);
		return;
	}
	vdp->xs_if_status = XDB_DISCONNECTED;
	cv_broadcast(&vdp->xs_iocv);

	mutex_exit(&vdp->xs_iomutex);

	/* stop accepting I/O request from frontend */
	ddi_remove_intr(dip, 0, NULL);
	/* clear all on-going I/Os, if any */
	mutex_enter(&vdp->xs_iomutex);
	while (vdp->xs_ionum > 0)
		cv_wait(&vdp->xs_ionumcv, &vdp->xs_iomutex);
	mutex_exit(&vdp->xs_iomutex);

	/* clean up resources and close this interface */
	xdb_uninit_ioreqs(vdp);
	xdb_unbindfrom_frontend(vdp);
	xdb_close_device(vdp);
	vdp->xs_peer = (domid_t)-1;
	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosed);
}

/*
 * Xdb_check_state_transition will check the XenbusState change to see
 * if the change is a valid transition or not.
 * The new state is written by frontend domain, or by running xenstore-write
 * to change it manually in dom0
 */
static int
xdb_check_state_transition(xdb_t *vdp, XenbusState oestate)
{
	enum xdb_state status;
	int stcheck;
#define	STOK	0 /* need further process */
#define	STNOP	1 /* no action need taking */
#define	STBUG	2 /* unexpected state change, could be a bug */

	status = vdp->xs_if_status;
	stcheck = STOK;

	switch (status) {
	case XDB_UNKNOWN:
		if (vdp->xs_fe_status == XDB_FE_UNKNOWN) {
			if ((oestate == XenbusStateUnknown)		||
			    (oestate == XenbusStateConnected))
				stcheck = STBUG;
			else if ((oestate == XenbusStateInitialising)	||
			    (oestate == XenbusStateInitWait))
				stcheck = STNOP;
		} else {
			if ((oestate == XenbusStateUnknown)		||
			    (oestate == XenbusStateInitialising)	||
			    (oestate == XenbusStateInitWait)		||
			    (oestate == XenbusStateConnected))
				stcheck = STBUG;
			else if (oestate == XenbusStateInitialised)
				stcheck = STNOP;
		}
		break;
	case XDB_CONNECTED:
		if ((oestate == XenbusStateUnknown)		||
		    (oestate == XenbusStateInitialising)	||
		    (oestate == XenbusStateInitWait)		||
		    (oestate == XenbusStateInitialised))
			stcheck = STBUG;
		else if (oestate == XenbusStateConnected)
			stcheck = STNOP;
		break;
	case XDB_DISCONNECTED:
	default:
			stcheck = STBUG;
	}

	if (stcheck == STOK)
		return (DDI_SUCCESS);

	if (stcheck == STBUG)
		cmn_err(CE_NOTE, "xdb@%s: unexpected otherend "
		    "state change to %d!, when status is %d",
		    ddi_get_name_addr(vdp->xs_dip), oestate, status);

	return (DDI_FAILURE);
}

static void
xdb_send_buf(void *arg)
{
	buf_t *bp;
	xdb_t *vdp = (xdb_t *)arg;

	mutex_enter(&vdp->xs_iomutex);

	while (vdp->xs_if_status != XDB_DISCONNECTED) {
		while ((bp = vdp->xs_f_iobuf) != NULL) {
			vdp->xs_f_iobuf = bp->av_forw;
			bp->av_forw = NULL;
			vdp->xs_ionum++;
			mutex_exit(&vdp->xs_iomutex);
			if (bp->b_bcount != 0) {
				int err = ldi_strategy(vdp->xs_ldi_hdl, bp);
				if (err != 0) {
					bp->b_flags |= B_ERROR;
					(void) xdb_biodone(bp);
					XDB_DBPRINT(XDB_DBG_IO, (CE_WARN,
					    "xdb@%s: sent buf to backend dev"
					    "failed, err=%d",
					    ddi_get_name_addr(vdp->xs_dip),
					    err));
				} else {
					XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE,
					    "sent buf to backend ok"));
				}
			} else /* no I/O need to be done */
				(void) xdb_biodone(bp);

			mutex_enter(&vdp->xs_iomutex);
		}

		if (vdp->xs_if_status != XDB_DISCONNECTED)
			cv_wait(&vdp->xs_iocv, &vdp->xs_iomutex);
	}

	mutex_exit(&vdp->xs_iomutex);
}

/*ARGSUSED*/
static void
xdb_hp_state_change(dev_info_t *dip, ddi_eventcookie_t id, void *arg,
    void *impl_data)
{
	xendev_hotplug_state_t state = *(xendev_hotplug_state_t *)impl_data;
	xdb_t *vdp = (xdb_t *)ddi_get_driver_private(dip);

	XDB_DBPRINT(XDB_DBG_INFO, (CE_NOTE, "xdb@%s: "
	    "hotplug status change to %d!", ddi_get_name_addr(dip), state));

	mutex_enter(&vdp->xs_cbmutex);
	if (state == Connected) {
		/* Hotplug script has completed successfully */
		if (vdp->xs_dev_status == XDB_DEV_UNKNOWN) {
			vdp->xs_dev_status = XDB_DEV_READY;
			if (vdp->xs_fe_status == XDB_FE_READY)
				/* try to connect to frontend */
				if (xdb_start_connect(vdp) != DDI_SUCCESS)
					(void) xdb_start_disconnect(vdp);
		}
	}
	mutex_exit(&vdp->xs_cbmutex);
}

/*ARGSUSED*/
static void
xdb_oe_state_change(dev_info_t *dip, ddi_eventcookie_t id, void *arg,
    void *impl_data)
{
	XenbusState new_state = *(XenbusState *)impl_data;
	xdb_t *vdp = (xdb_t *)ddi_get_driver_private(dip);

	XDB_DBPRINT(XDB_DBG_INFO, (CE_NOTE, "xdb@%s: "
	    "otherend state change to %d!", ddi_get_name_addr(dip), new_state));

	mutex_enter(&vdp->xs_cbmutex);

	if (xdb_check_state_transition(vdp, new_state) == DDI_FAILURE) {
		mutex_exit(&vdp->xs_cbmutex);
		return;
	}

	switch (new_state) {
	case XenbusStateInitialised:
		ASSERT(vdp->xs_if_status == XDB_UNKNOWN);

		/* frontend is ready for connecting */
		vdp->xs_fe_status = XDB_FE_READY;

		if (vdp->xs_dev_status == XDB_DEV_READY)
			if (xdb_start_connect(vdp) != DDI_SUCCESS)
				(void) xdb_start_disconnect(vdp);
		break;
	case XenbusStateClosing:
		(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosing);
		break;
	case XenbusStateClosed:
		/* clean up */
		xdb_close(dip);

	}

	mutex_exit(&vdp->xs_cbmutex);
}

static int
xdb_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	xdb_t *vdp;
	ddi_iblock_cookie_t ibc;
	int instance;

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_FAILURE);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/* DDI_ATTACH */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(xdb_statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	vdp = ddi_get_soft_state(xdb_statep, instance);
	vdp->xs_dip = dip;
	if (ddi_get_iblock_cookie(dip, 0, &ibc) != DDI_SUCCESS)
		goto errout1;

	if (!xdb_kstat_init(vdp))
		goto errout1;

	mutex_init(&vdp->xs_iomutex, NULL, MUTEX_DRIVER, (void *)ibc);
	mutex_init(&vdp->xs_cbmutex, NULL, MUTEX_DRIVER, (void *)ibc);
	cv_init(&vdp->xs_iocv, NULL, CV_DRIVER, NULL);
	cv_init(&vdp->xs_ionumcv, NULL, CV_DRIVER, NULL);

	ddi_set_driver_private(dip, vdp);

	vdp->xs_iotaskq = ddi_taskq_create(dip, "xdb_iotask", 1,
	    TASKQ_DEFAULTPRI, 0);
	if (vdp->xs_iotaskq == NULL)
		goto errout2;
	(void) ddi_taskq_dispatch(vdp->xs_iotaskq, xdb_send_buf, vdp,
	    DDI_SLEEP);

	/* Watch frontend and hotplug state change */
	if (xvdi_add_event_handler(dip, XS_OE_STATE, xdb_oe_state_change,
	    NULL) != DDI_SUCCESS)
		goto errout3;
	if (xvdi_add_event_handler(dip, XS_HP_STATE, xdb_hp_state_change,
	    NULL) != DDI_SUCCESS) {
		goto errout4;
	}

	/*
	 * Kick-off hotplug script
	 */
	if (xvdi_post_event(dip, XEN_HP_ADD) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xdb@%s: failed to start hotplug script",
		    ddi_get_name_addr(dip));
		goto errout4;
	}

	/*
	 * start waiting for hotplug event and otherend state event
	 * mainly for debugging, frontend will not take any op seeing this
	 */
	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateInitWait);

	XDB_DBPRINT(XDB_DBG_INFO, (CE_NOTE, "xdb@%s: attached!",
	    ddi_get_name_addr(dip)));
	return (DDI_SUCCESS);

errout4:
	xvdi_remove_event_handler(dip, NULL);
errout3:
	mutex_enter(&vdp->xs_cbmutex);
	mutex_enter(&vdp->xs_iomutex);
	vdp->xs_if_status = XDB_DISCONNECTED;
	cv_broadcast(&vdp->xs_iocv);
	mutex_exit(&vdp->xs_iomutex);
	mutex_exit(&vdp->xs_cbmutex);
	ddi_taskq_destroy(vdp->xs_iotaskq);
errout2:
	ddi_set_driver_private(dip, NULL);
	cv_destroy(&vdp->xs_iocv);
	cv_destroy(&vdp->xs_ionumcv);
	mutex_destroy(&vdp->xs_cbmutex);
	mutex_destroy(&vdp->xs_iomutex);
	kstat_delete(vdp->xs_kstats);
errout1:
	ddi_soft_state_free(xdb_statep, instance);
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
xdb_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	xdb_t *vdp = XDB_INST2SOFTS(instance);

	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_FAILURE);
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/* DDI_DETACH handling */

	/* shouldn't detach, if still used by frontend */
	mutex_enter(&vdp->xs_iomutex);
	if (vdp->xs_if_status != XDB_DISCONNECTED) {
		mutex_exit(&vdp->xs_iomutex);
		return (DDI_FAILURE);
	}
	mutex_exit(&vdp->xs_iomutex);

	xvdi_remove_event_handler(dip, NULL);
	/* can do nothing about it, if it fails */
	(void) xvdi_post_event(dip, XEN_HP_REMOVE);

	ddi_taskq_destroy(vdp->xs_iotaskq);
	cv_destroy(&vdp->xs_iocv);
	cv_destroy(&vdp->xs_ionumcv);
	mutex_destroy(&vdp->xs_cbmutex);
	mutex_destroy(&vdp->xs_iomutex);
	kstat_delete(vdp->xs_kstats);
	ddi_set_driver_private(dip, NULL);
	ddi_soft_state_free(xdb_statep, instance);

	XDB_DBPRINT(XDB_DBG_INFO, (CE_NOTE, "xdb@%s: detached!",
	    ddi_get_name_addr(dip)));
	return (DDI_SUCCESS);
}

static struct dev_ops xdb_dev_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	ddi_getinfo_1to1, /* devo_getinfo */
	nulldev,	/* devo_identify */
	nulldev,	/* devo_probe */
	xdb_attach,	/* devo_attach */
	xdb_detach,	/* devo_detach */
	nodev,		/* devo_reset */
	NULL,		/* devo_cb_ops */
	NULL,		/* devo_bus_ops */
	NULL,		/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module. */
	"vbd backend driver",	/* Name of the module */
	&xdb_dev_ops			/* driver ops */
};

static struct modlinkage xdb_modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int rv;

	if ((rv = ddi_soft_state_init((void **)&xdb_statep,
	    sizeof (xdb_t), 0)) == 0)
		if ((rv = mod_install(&xdb_modlinkage)) != 0)
			ddi_soft_state_fini((void **)&xdb_statep);
	return (rv);
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&xdb_modlinkage)) != 0)
		return (rv);
	ddi_soft_state_fini((void **)&xdb_statep);
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&xdb_modlinkage, modinfop));
}

static int
xdb_get_request(xdb_t *vdp, blkif_request_t *req)
{
	void *src = xvdi_ring_get_request(vdp->xs_ring);

	if (src == NULL)
		return (0);

	switch (vdp->xs_blk_protocol) {
	case BLKIF_PROTOCOL_NATIVE:
		(void) memcpy(req, src, sizeof (*req));
		break;
	case BLKIF_PROTOCOL_X86_32:
		blkif_get_x86_32_req(req, src);
		break;
	case BLKIF_PROTOCOL_X86_64:
		blkif_get_x86_64_req(req, src);
		break;
	default:
		cmn_err(CE_PANIC, "xdb@%s: unrecognised protocol: %d",
		    ddi_get_name_addr(vdp->xs_dip),
		    vdp->xs_blk_protocol);
	}
	return (1);
}

static int
xdb_push_response(xdb_t *vdp, uint64_t id, uint8_t op, uint16_t status)
{
	ddi_acc_handle_t acchdl = vdp->xs_ring_hdl;
	blkif_response_t *rsp = xvdi_ring_get_response(vdp->xs_ring);
	blkif_x86_32_response_t *rsp_32 = (blkif_x86_32_response_t *)rsp;
	blkif_x86_64_response_t *rsp_64 = (blkif_x86_64_response_t *)rsp;

	ASSERT(rsp);

	switch (vdp->xs_blk_protocol) {
	case BLKIF_PROTOCOL_NATIVE:
		ddi_put64(acchdl, &rsp->id, id);
		ddi_put8(acchdl, &rsp->operation, op);
		ddi_put16(acchdl, (uint16_t *)&rsp->status,
		    status == 0 ? BLKIF_RSP_OKAY : BLKIF_RSP_ERROR);
		break;
	case BLKIF_PROTOCOL_X86_32:
		ddi_put64(acchdl, &rsp_32->id, id);
		ddi_put8(acchdl, &rsp_32->operation, op);
		ddi_put16(acchdl, (uint16_t *)&rsp_32->status,
		    status == 0 ? BLKIF_RSP_OKAY : BLKIF_RSP_ERROR);
		break;
	case BLKIF_PROTOCOL_X86_64:
		ddi_put64(acchdl, &rsp_64->id, id);
		ddi_put8(acchdl, &rsp_64->operation, op);
		ddi_put16(acchdl, (uint16_t *)&rsp_64->status,
		    status == 0 ? BLKIF_RSP_OKAY : BLKIF_RSP_ERROR);
		break;
	default:
		cmn_err(CE_PANIC, "xdb@%s: unrecognised protocol: %d",
		    ddi_get_name_addr(vdp->xs_dip),
		    vdp->xs_blk_protocol);
	}

	return (xvdi_ring_push_response(vdp->xs_ring));
}

static void
blkif_get_x86_32_req(blkif_request_t *dst, blkif_x86_32_request_t *src)
{
	int i, n = BLKIF_MAX_SEGMENTS_PER_REQUEST;
	dst->operation = src->operation;
	dst->nr_segments = src->nr_segments;
	dst->handle = src->handle;
	dst->id = src->id;
	dst->sector_number = src->sector_number;
	if (n > src->nr_segments)
		n = src->nr_segments;
	for (i = 0; i < n; i++)
		dst->seg[i] = src->seg[i];
}

static void
blkif_get_x86_64_req(blkif_request_t *dst, blkif_x86_64_request_t *src)
{
	int i, n = BLKIF_MAX_SEGMENTS_PER_REQUEST;
	dst->operation = src->operation;
	dst->nr_segments = src->nr_segments;
	dst->handle = src->handle;
	dst->id = src->id;
	dst->sector_number = src->sector_number;
	if (n > src->nr_segments)
		n = src->nr_segments;
	for (i = 0; i < n; i++)
		dst->seg[i] = src->seg[i];
}
