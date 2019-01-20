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
#include <public/io/xs_wire.h>
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

static void xdb_close(dev_info_t *);
static int xdb_push_response(xdb_t *, uint64_t, uint8_t, uint16_t);
static int xdb_get_request(xdb_t *, blkif_request_t *);
static void blkif_get_x86_32_req(blkif_request_t *, blkif_x86_32_request_t *);
static void blkif_get_x86_64_req(blkif_request_t *, blkif_x86_64_request_t *);
static int xdb_biodone(buf_t *);


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

static char *
i_pathname(dev_info_t *dip)
{
	char *path, *rv;

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);
	rv = strdup(path);
	kmem_free(path, MAXPATHLEN);

	return (rv);
}

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
			 * XB_LAST_SECTOR_IN_SEG according to definition
			 * of blk interface by Xen, so sanity check again
			 */
			if (fs > XB_LAST_SECTOR_IN_SEG)
				fs = XB_LAST_SECTOR_IN_SEG;
			if (ls > XB_LAST_SECTOR_IN_SEG)
				ls = XB_LAST_SECTOR_IN_SEG;
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
				unmapop.dev_bus_addr = 0;
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

	/*
	 * Run through the segments. There are XB_NUM_SECTORS_PER_SEG sectors
	 * per segment. On some OSes (e.g. Linux), there may be empty gaps
	 * between segments. (i.e. the first segment may end on sector 6 and
	 * the second segment start on sector 4).
	 *
	 * if a segments first sector is not set to 0, and this is not the
	 * first segment in our buf, end this buf now.
	 *
	 * if a segments last sector is not set to XB_LAST_SECTOR_IN_SEG, and
	 * this is not the last segment in the request, add this segment into
	 * the buf, then end this buf (updating the pointer to point to the
	 * next segment next time around).
	 */
	for (i = curseg; i < xreq->xr_buf_pages; i++) {
		if ((xreq->xr_segs[i].fs != 0) && (i != curseg)) {
			break;
		}
		sectors += (xreq->xr_segs[i].ls - xreq->xr_segs[i].fs + 1);
		if ((xreq->xr_segs[i].ls != XB_LAST_SECTOR_IN_SEG) &&
		    (i != (xreq->xr_buf_pages - 1))) {
			i++;
			break;
		}
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
	xdb_t		*vdp = (xdb_t *)arg;
	dev_info_t	*dip = vdp->xs_dip;
	blkif_request_t	req, *reqp = &req;
	xdb_request_t	*xreq;
	buf_t		*bp;
	uint8_t		op;
	int		ret = DDI_INTR_UNCLAIMED;

	XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE,
	    "xdb@%s: I/O request received from dom %d",
	    ddi_get_name_addr(dip), vdp->xs_peer));

	mutex_enter(&vdp->xs_iomutex);

	/* shouldn't touch ring buffer if not in connected state */
	if (!vdp->xs_if_connected) {
		mutex_exit(&vdp->xs_iomutex);
		return (DDI_INTR_UNCLAIMED);
	}
	ASSERT(vdp->xs_hp_connected && vdp->xs_fe_initialised);

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
		unmapops[i].dev_bus_addr = 0;
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
		    DKIOCFLUSHWRITECACHE, 0, FKIOCTL, kcred, NULL);
	}

	mutex_enter(&vdp->xs_iomutex);

	/* send response back to frontend */
	if (vdp->xs_if_connected) {
		ASSERT(vdp->xs_hp_connected && vdp->xs_fe_initialised);
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
	if (!vdp->xs_if_connected && (vdp->xs_ionum == 0)) {
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

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));

	/*
	 * Switch to the XenbusStateInitialised state.  This let's the
	 * frontend know that we're about to negotiate a connection.
	 */
	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateInitialised);

	/*
	 * Gather info from frontend
	 */
	oename = xvdi_get_oename(dip);
	if (oename == NULL)
		return (DDI_FAILURE);

	err = xenbus_gather(XBT_NULL, oename,
	    XBP_RING_REF, "%lu", &gref,
	    XBP_EVENT_CHAN, "%u", &evtchn,
	    NULL);
	if (err != 0) {
		xvdi_dev_error(dip, err,
		    "Getting ring-ref and evtchn from frontend");
		return (DDI_FAILURE);
	}

	vdp->xs_blk_protocol = BLKIF_PROTOCOL_NATIVE;
	vdp->xs_nentry = BLKIF_RING_SIZE;
	vdp->xs_entrysize = sizeof (union blkif_sring_entry);

	err = xenbus_gather(XBT_NULL, oename,
	    XBP_PROTOCOL, "%63s", protocol, NULL);
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
	 * Map and init ring.  The ring parameters must match those which
	 * have been allocated in the front end.
	 */
	if (xvdi_map_ring(dip, vdp->xs_nentry, vdp->xs_entrysize,
	    gref, &vdp->xs_ring) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * This will be removed after we use shadow I/O ring request since
	 * we don't need to access the ring itself directly, thus the access
	 * handle is not needed
	 */
	vdp->xs_ring_hdl = vdp->xs_ring->xr_acc_hdl;

	/* bind event channel */
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
	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));

	xvdi_free_evtchn(vdp->xs_dip);
	xvdi_unmap_ring(vdp->xs_ring);
}

/*
 * xdb_params_change() initiates a allows change to the underlying device/file
 * that the backend is accessing.  It does this by disconnecting from the
 * frontend, closing the old device, clearing a bunch of xenbus parameters,
 * and switching back to the XenbusStateInitialising state.  The frontend
 * should notice this transition to the XenbusStateInitialising state and
 * should attempt to reconnect to us (the backend).
 */
static void
xdb_params_change(xdb_t *vdp, char *params, boolean_t update_xs)
{
	xenbus_transaction_t	xbt;
	dev_info_t		*dip = vdp->xs_dip;
	char			*xsname;
	int			err;

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));
	ASSERT(vdp->xs_params_path != NULL);

	if ((xsname = xvdi_get_xsname(dip)) == NULL)
		return;
	if (strcmp(vdp->xs_params_path, params) == 0)
		return;

	/*
	 * Close the device we're currently accessing and update the
	 * path which points to our backend device/file.
	 */
	xdb_close(dip);
	vdp->xs_fe_initialised = B_FALSE;

trans_retry:
	if ((err = xenbus_transaction_start(&xbt)) != 0) {
		xvdi_dev_error(dip, err, "params change transaction init");
		goto errout;
	}

	/*
	 * Delete all the xenbus properties that are connection dependant
	 * and go back to the initializing state so that the frontend
	 * driver can re-negotiate a connection.
	 */
	if (((err = xenbus_rm(xbt, xsname, XBP_FB)) != 0) ||
	    ((err = xenbus_rm(xbt, xsname, XBP_INFO)) != 0) ||
	    ((err = xenbus_rm(xbt, xsname, "sector-size")) != 0) ||
	    ((err = xenbus_rm(xbt, xsname, XBP_SECTORS)) != 0) ||
	    ((err = xenbus_rm(xbt, xsname, "instance")) != 0) ||
	    ((err = xenbus_rm(xbt, xsname, "node")) != 0) ||
	    (update_xs && ((err = xenbus_printf(xbt, xsname,
	    "params", "%s", params)) != 0)) ||
	    ((err = xvdi_switch_state(dip,
	    xbt, XenbusStateInitialising) > 0))) {
		(void) xenbus_transaction_end(xbt, 1);
		xvdi_dev_error(dip, err, "params change transaction setup");
		goto errout;
	}

	if ((err = xenbus_transaction_end(xbt, 0)) != 0) {
		if (err == EAGAIN) {
			/* transaction is ended, don't need to abort it */
			goto trans_retry;
		}
		xvdi_dev_error(dip, err, "params change transaction commit");
		goto errout;
	}

	/* Change the device that we plan to access */
	strfree(vdp->xs_params_path);
	vdp->xs_params_path = strdup(params);
	return;

errout:
	(void) xvdi_switch_state(dip, xbt, XenbusStateInitialising);
}

/*
 * xdb_watch_params_cb() - This callback is invoked whenever there
 * is an update to the following xenbus parameter:
 *     /local/domain/0/backend/vbd/<domU_id>/<domU_dev>/params
 *
 * This normally happens during xm block-configure operations, which
 * are used to change CD device images for HVM domUs.
 */
/*ARGSUSED*/
static void
xdb_watch_params_cb(dev_info_t *dip, const char *path, void *arg)
{
	xdb_t			*vdp = (xdb_t *)ddi_get_driver_private(dip);
	char			*xsname, *oename, *str, *str2;

	if (((xsname = xvdi_get_xsname(dip)) == NULL) ||
	    ((oename = xvdi_get_oename(dip)) == NULL)) {
		return;
	}

	mutex_enter(&vdp->xs_cbmutex);

	if (xenbus_read_str(xsname, "params", &str) != 0) {
		mutex_exit(&vdp->xs_cbmutex);
		return;
	}

	if (strcmp(vdp->xs_params_path, str) == 0) {
		/* Nothing todo */
		mutex_exit(&vdp->xs_cbmutex);
		strfree(str);
		return;
	}

	/*
	 * If the frontend isn't a cd device, doesn't support media
	 * requests, or has locked the media, then we can't change
	 * the params value.  restore the current value.
	 */
	str2 = NULL;
	if (!XDB_IS_FE_CD(vdp) ||
	    (xenbus_read_str(oename, XBP_MEDIA_REQ, &str2) != 0) ||
	    (strcmp(str2, XBV_MEDIA_REQ_LOCK) == 0)) {
		if (str2 != NULL)
			strfree(str2);
		strfree(str);

		str = i_pathname(dip);
		cmn_err(CE_NOTE,
		    "!%s: media locked, ignoring params update", str);
		strfree(str);

		mutex_exit(&vdp->xs_cbmutex);
		return;
	}

	XDB_DBPRINT(XDB_DBG_INFO, (CE_NOTE,
	    "block-configure params request: \"%s\"", str));

	xdb_params_change(vdp, str, B_FALSE);
	mutex_exit(&vdp->xs_cbmutex);
	strfree(str);
}

/*
 * xdb_watch_media_req_cb() - This callback is invoked whenever there
 * is an update to the following xenbus parameter:
 *     /local/domain/<domU_id>/device/vbd/<domU_dev>/media-req
 *
 * Media requests are only supported on CD devices and are issued by
 * the frontend.  Currently the only supported media request operaions
 * are "lock" and "eject".  A "lock" prevents the backend from changing
 * the backing device/file (via xm block-configure).  An "eject" requests
 * tells the backend device that it should disconnect from the frontend
 * and closing the backing device/file that is currently in use.
 */
/*ARGSUSED*/
static void
xdb_watch_media_req_cb(dev_info_t *dip, const char *path, void *arg)
{
	xdb_t			*vdp = (xdb_t *)ddi_get_driver_private(dip);
	char			*oename, *str;

	mutex_enter(&vdp->xs_cbmutex);

	if ((oename = xvdi_get_oename(dip)) == NULL) {
		mutex_exit(&vdp->xs_cbmutex);
		return;
	}

	if (xenbus_read_str(oename, XBP_MEDIA_REQ, &str) != 0) {
		mutex_exit(&vdp->xs_cbmutex);
		return;
	}

	if (!XDB_IS_FE_CD(vdp)) {
		xvdi_dev_error(dip, EINVAL,
		    "media-req only supported for cdrom devices");
		mutex_exit(&vdp->xs_cbmutex);
		return;
	}

	if (strcmp(str, XBV_MEDIA_REQ_EJECT) != 0) {
		mutex_exit(&vdp->xs_cbmutex);
		strfree(str);
		return;
	}
	strfree(str);

	XDB_DBPRINT(XDB_DBG_INFO, (CE_NOTE, "media eject request"));

	xdb_params_change(vdp, "", B_TRUE);
	(void) xenbus_printf(XBT_NULL, oename,
	    XBP_MEDIA_REQ, "%s", XBV_MEDIA_REQ_NONE);
	mutex_exit(&vdp->xs_cbmutex);
}

/*
 * If we're dealing with a cdrom device, let the frontend know that
 * we support media requests via XBP_MEDIA_REQ_SUP, and setup a watch
 * to handle those frontend media request changes, which modify the
 * following xenstore parameter:
 *	/local/domain/<domU_id>/device/vbd/<domU_dev>/media-req
 */
static boolean_t
xdb_media_req_init(xdb_t *vdp)
{
	dev_info_t		*dip = vdp->xs_dip;
	char			*xsname, *oename;

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));

	if (((xsname = xvdi_get_xsname(dip)) == NULL) ||
	    ((oename = xvdi_get_oename(dip)) == NULL))
		return (B_FALSE);

	if (!XDB_IS_FE_CD(vdp))
		return (B_TRUE);

	if (xenbus_printf(XBT_NULL, xsname, XBP_MEDIA_REQ_SUP, "%d", 1) != 0)
		return (B_FALSE);

	if (xvdi_add_xb_watch_handler(dip, oename,
	    XBP_MEDIA_REQ, xdb_watch_media_req_cb, NULL) != DDI_SUCCESS) {
		xvdi_dev_error(dip, EAGAIN,
		    "Failed to register watch for cdrom media requests");
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Get our params value.  Also, if we're using "params" then setup a
 * watch to handle xm block-configure operations which modify the
 * following xenstore parameter:
 *	/local/domain/0/backend/vbd/<domU_id>/<domU_dev>/params
 */
static boolean_t
xdb_params_init(xdb_t *vdp)
{
	dev_info_t		*dip = vdp->xs_dip;
	char			*str, *xsname;
	int			err;

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));
	ASSERT(vdp->xs_params_path == NULL);

	if ((xsname = xvdi_get_xsname(dip)) == NULL)
		return (B_FALSE);

	err = xenbus_read_str(xsname, "params", &str);
	if (err != 0) {
		return (B_FALSE);
	}
	vdp->xs_params_path = str;

	if (xvdi_add_xb_watch_handler(dip, xsname, "params",
	    xdb_watch_params_cb, NULL) != DDI_SUCCESS) {
		strfree(vdp->xs_params_path);
		vdp->xs_params_path = NULL;
		return (B_FALSE);
	}

	return (B_TRUE);
}

#define	LOFI_CTRL_NODE	"/dev/lofictl"
#define	LOFI_DEV_NODE	"/devices/pseudo/lofi@0:"
#define	LOFI_MODE	(FREAD | FWRITE | FEXCL)

static int
xdb_setup_node(xdb_t *vdp, char *path)
{
	dev_info_t		*dip = vdp->xs_dip;
	char			*xsname, *str;
	ldi_handle_t		ldi_hdl;
	struct lofi_ioctl	*li;
	int			minor, err;

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));

	if ((xsname = xvdi_get_xsname(dip)) == NULL)
		return (DDI_FAILURE);

	if ((err = xenbus_read_str(xsname, "type", &str)) != 0) {
		xvdi_dev_error(dip, err, "Getting type from backend device");
		return (DDI_FAILURE);
	}
	if (strcmp(str, "file") == 0)
		vdp->xs_type |= XDB_DEV_BE_LOFI;
	strfree(str);

	if (!XDB_IS_BE_LOFI(vdp)) {
		(void) strlcpy(path, vdp->xs_params_path, MAXPATHLEN);
		ASSERT(vdp->xs_lofi_path == NULL);
		return (DDI_SUCCESS);
	}

	do {
		err = ldi_open_by_name(LOFI_CTRL_NODE, LOFI_MODE, kcred,
		    &ldi_hdl, vdp->xs_ldi_li);
	} while (err == EBUSY);
	if (err != 0) {
		return (DDI_FAILURE);
	}

	li = kmem_zalloc(sizeof (*li), KM_SLEEP);
	(void) strlcpy(li->li_filename, vdp->xs_params_path,
	    sizeof (li->li_filename));
	err = ldi_ioctl(ldi_hdl, LOFI_MAP_FILE, (intptr_t)li,
	    LOFI_MODE | FKIOCTL, kcred, &minor);
	(void) ldi_close(ldi_hdl, LOFI_MODE, kcred);
	kmem_free(li, sizeof (*li));

	if (err != 0) {
		cmn_err(CE_WARN, "xdb@%s: Failed to create lofi dev for %s",
		    ddi_get_name_addr(dip), vdp->xs_params_path);
		return (DDI_FAILURE);
	}

	/*
	 * return '/devices/...' instead of '/dev/lofi/...' since the
	 * former is available immediately after calling ldi_ioctl
	 */
	(void) snprintf(path, MAXPATHLEN, LOFI_DEV_NODE "%d", minor);
	(void) xenbus_printf(XBT_NULL, xsname, "node", "%s", path);

	ASSERT(vdp->xs_lofi_path == NULL);
	vdp->xs_lofi_path = strdup(path);

	return (DDI_SUCCESS);
}

static void
xdb_teardown_node(xdb_t *vdp)
{
	dev_info_t *dip = vdp->xs_dip;
	ldi_handle_t ldi_hdl;
	struct lofi_ioctl *li;
	int err;

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));

	if (!XDB_IS_BE_LOFI(vdp))
		return;

	vdp->xs_type &= ~XDB_DEV_BE_LOFI;
	ASSERT(vdp->xs_lofi_path != NULL);

	li = kmem_zalloc(sizeof (*li), KM_SLEEP);
	(void) strlcpy(li->li_filename, vdp->xs_params_path,
	    sizeof (li->li_filename));

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

	strfree(vdp->xs_lofi_path);
	vdp->xs_lofi_path = NULL;
}

static int
xdb_open_device(xdb_t *vdp)
{
	dev_info_t *dip = vdp->xs_dip;
	uint64_t devsize;
	int blksize;
	char *nodepath;
	char *xsname;
	char *str;
	int err;

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));

	if (strlen(vdp->xs_params_path) == 0) {
		/*
		 * it's possible to have no backing device when dealing
		 * with a pv cdrom drive that has no virtual cd associated
		 * with it.
		 */
		ASSERT(XDB_IS_FE_CD(vdp));
		ASSERT(vdp->xs_sectors == 0);
		ASSERT(vdp->xs_ldi_li == NULL);
		ASSERT(vdp->xs_ldi_hdl == NULL);
		return (DDI_SUCCESS);
	}

	/*
	 * after the hotplug scripts have "connected" the device, check to see
	 * if we're using a dynamic device.  If so, replace the params path
	 * with the dynamic one.
	 */
	xsname = xvdi_get_xsname(dip);
	err = xenbus_read_str(xsname, "dynamic-device-path", &str);
	if (err == 0) {
		strfree(vdp->xs_params_path);
		vdp->xs_params_path = str;
	}

	if (ldi_ident_from_dip(dip, &vdp->xs_ldi_li) != 0)
		return (DDI_FAILURE);

	nodepath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	/* try to open backend device */
	if (xdb_setup_node(vdp, nodepath) != DDI_SUCCESS) {
		xvdi_dev_error(dip, ENXIO,
		    "Getting device path of backend device");
		ldi_ident_release(vdp->xs_ldi_li);
		kmem_free(nodepath, MAXPATHLEN);
		return (DDI_FAILURE);
	}

	if (ldi_open_by_name(nodepath,
	    FREAD | (XDB_IS_RO(vdp) ? 0 : FWRITE),
	    kcred, &vdp->xs_ldi_hdl, vdp->xs_ldi_li) != 0) {
		xdb_teardown_node(vdp);
		ldi_ident_release(vdp->xs_ldi_li);
		cmn_err(CE_WARN, "xdb@%s: Failed to open: %s",
		    ddi_get_name_addr(dip), nodepath);
		kmem_free(nodepath, MAXPATHLEN);
		return (DDI_FAILURE);
	}

	if (ldi_get_size(vdp->xs_ldi_hdl, &devsize) != DDI_SUCCESS) {
		(void) ldi_close(vdp->xs_ldi_hdl,
		    FREAD | (XDB_IS_RO(vdp) ? 0 : FWRITE), kcred);
		xdb_teardown_node(vdp);
		ldi_ident_release(vdp->xs_ldi_li);
		kmem_free(nodepath, MAXPATHLEN);
		return (DDI_FAILURE);
	}

	blksize = ldi_prop_get_int64(vdp->xs_ldi_hdl,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "blksize", DEV_BSIZE);
	if (blksize == DEV_BSIZE)
		blksize = ldi_prop_get_int(vdp->xs_ldi_hdl,
		    LDI_DEV_T_ANY | DDI_PROP_DONTPASS |
		    DDI_PROP_NOTPROM, "device-blksize", DEV_BSIZE);

	vdp->xs_sec_size = blksize;
	vdp->xs_sectors = devsize / blksize;

	/* check if the underlying device is a CD/DVD disc */
	if (ldi_prop_get_int(vdp->xs_ldi_hdl, LDI_DEV_T_ANY | DDI_PROP_DONTPASS,
	    INQUIRY_DEVICE_TYPE, DTYPE_DIRECT) == DTYPE_RODIRECT)
		vdp->xs_type |= XDB_DEV_BE_CD;

	/* check if the underlying device is a removable disk */
	if (ldi_prop_exists(vdp->xs_ldi_hdl,
	    LDI_DEV_T_ANY | DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "removable-media"))
		vdp->xs_type |= XDB_DEV_BE_RMB;

	kmem_free(nodepath, MAXPATHLEN);
	return (DDI_SUCCESS);
}

static void
xdb_close_device(xdb_t *vdp)
{
	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));

	if (strlen(vdp->xs_params_path) == 0) {
		ASSERT(XDB_IS_FE_CD(vdp));
		ASSERT(vdp->xs_sectors == 0);
		ASSERT(vdp->xs_ldi_li == NULL);
		ASSERT(vdp->xs_ldi_hdl == NULL);
		return;
	}

	(void) ldi_close(vdp->xs_ldi_hdl,
	    FREAD | (XDB_IS_RO(vdp) ? 0 : FWRITE), kcred);
	xdb_teardown_node(vdp);
	ldi_ident_release(vdp->xs_ldi_li);
	vdp->xs_type &= ~(XDB_DEV_BE_CD | XDB_DEV_BE_RMB);
	vdp->xs_sectors = 0;
	vdp->xs_ldi_li = NULL;
	vdp->xs_ldi_hdl = NULL;
}

/*
 * Kick-off connect process
 * If xs_fe_initialised == B_TRUE and xs_hp_connected == B_TRUE
 * the xs_if_connected will be changed to B_TRUE on success,
 */
static void
xdb_start_connect(xdb_t *vdp)
{
	xenbus_transaction_t	xbt;
	dev_info_t		*dip = vdp->xs_dip;
	boolean_t		fb_exists;
	int			err, instance = ddi_get_instance(dip);
	uint64_t		sectors;
	uint_t			dinfo, ssize;
	char			*xsname;

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));

	if (((xsname = xvdi_get_xsname(dip)) == NULL) ||
	    ((vdp->xs_peer = xvdi_get_oeid(dip)) == (domid_t)-1))
		return;

	mutex_enter(&vdp->xs_iomutex);
	/*
	 * if the hotplug scripts haven't run or if the frontend is not
	 * initialized, then we can't try to connect.
	 */
	if (!vdp->xs_hp_connected || !vdp->xs_fe_initialised) {
		ASSERT(!vdp->xs_if_connected);
		mutex_exit(&vdp->xs_iomutex);
		return;
	}

	/* If we're already connected then there's nothing todo */
	if (vdp->xs_if_connected) {
		mutex_exit(&vdp->xs_iomutex);
		return;
	}
	mutex_exit(&vdp->xs_iomutex);

	/*
	 * Start connect to frontend only when backend device are ready
	 * and frontend has moved to XenbusStateInitialised, which means
	 * ready to connect.
	 */
	XDB_DBPRINT(XDB_DBG_INFO, (CE_NOTE,
	    "xdb@%s: starting connection process", ddi_get_name_addr(dip)));

	if (xdb_open_device(vdp) != DDI_SUCCESS)
		return;

	if (xdb_bindto_frontend(vdp) != DDI_SUCCESS) {
		xdb_close_device(vdp);
		return;
	}

	/* init i/o requests */
	xdb_init_ioreqs(vdp);

	if (ddi_add_intr(dip, 0, NULL, NULL, xdb_intr, (caddr_t)vdp)
	    != DDI_SUCCESS) {
		xdb_uninit_ioreqs(vdp);
		xdb_unbindfrom_frontend(vdp);
		xdb_close_device(vdp);
		return;
	}

	dinfo = 0;
	if (XDB_IS_RO(vdp))
		dinfo |= VDISK_READONLY;
	if (XDB_IS_BE_RMB(vdp))
		dinfo |= VDISK_REMOVABLE;
	if (XDB_IS_BE_CD(vdp))
		dinfo |= VDISK_CDROM;
	if (XDB_IS_FE_CD(vdp))
		dinfo |= VDISK_REMOVABLE | VDISK_CDROM;

	/*
	 * we can recieve intr any time from now on
	 * mark that we're ready to take intr
	 */
	mutex_enter(&vdp->xs_iomutex);
	ASSERT(vdp->xs_fe_initialised);
	vdp->xs_if_connected = B_TRUE;
	mutex_exit(&vdp->xs_iomutex);

trans_retry:
	/* write into xenstore the info needed by frontend */
	if ((err = xenbus_transaction_start(&xbt)) != 0) {
		xvdi_dev_error(dip, err, "connect transaction init");
		goto errout;
	}

	/* If feature-barrier isn't present in xenstore, add it.  */
	fb_exists = xenbus_exists(xsname, XBP_FB);

	ssize = (vdp->xs_sec_size == 0) ? DEV_BSIZE : vdp->xs_sec_size;
	sectors = vdp->xs_sectors;
	if (((!fb_exists &&
	    (err = xenbus_printf(xbt, xsname, XBP_FB, "%d", 1)))) ||
	    (err = xenbus_printf(xbt, xsname, XBP_INFO, "%u", dinfo)) ||
	    (err = xenbus_printf(xbt, xsname, XBP_SECTOR_SIZE, "%u", ssize)) ||
	    (err = xenbus_printf(xbt, xsname,
	    XBP_SECTORS, "%"PRIu64, sectors)) ||
	    (err = xenbus_printf(xbt, xsname, "instance", "%d", instance)) ||
	    ((err = xvdi_switch_state(dip, xbt, XenbusStateConnected)) > 0)) {
		(void) xenbus_transaction_end(xbt, 1);
		xvdi_dev_error(dip, err, "connect transaction setup");
		goto errout;
	}

	if ((err = xenbus_transaction_end(xbt, 0)) != 0) {
		if (err == EAGAIN) {
			/* transaction is ended, don't need to abort it */
			goto trans_retry;
		}
		xvdi_dev_error(dip, err, "connect transaction commit");
		goto errout;
	}

	return;

errout:
	xdb_close(dip);
}

/*
 * Disconnect from frontend and close backend device
 */
static void
xdb_close(dev_info_t *dip)
{
	xdb_t *vdp = (xdb_t *)ddi_get_driver_private(dip);

	ASSERT(MUTEX_HELD(&vdp->xs_cbmutex));
	mutex_enter(&vdp->xs_iomutex);

	/*
	 * if the hotplug scripts haven't run or if the frontend is not
	 * initialized, then we can't be connected, so there's no
	 * connection to close.
	 */
	if (!vdp->xs_hp_connected || !vdp->xs_fe_initialised) {
		ASSERT(!vdp->xs_if_connected);
		mutex_exit(&vdp->xs_iomutex);
		return;
	}

	/* if we're not connected, there's nothing to do */
	if (!vdp->xs_if_connected) {
		cv_broadcast(&vdp->xs_iocv);
		mutex_exit(&vdp->xs_iomutex);
		return;
	}

	XDB_DBPRINT(XDB_DBG_INFO, (CE_NOTE, "closing while connected"));

	vdp->xs_if_connected = B_FALSE;
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
}

static void
xdb_send_buf(void *arg)
{
	xdb_t	*vdp = (xdb_t *)arg;
	buf_t	*bp;
	int	err;

	mutex_enter(&vdp->xs_iomutex);
	while (vdp->xs_send_buf) {
		if ((bp = vdp->xs_f_iobuf) == NULL) {
			/* wait for some io to send */
			XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE,
			    "send buf waiting for io"));
			cv_wait(&vdp->xs_iocv, &vdp->xs_iomutex);
			continue;
		}

		vdp->xs_f_iobuf = bp->av_forw;
		bp->av_forw = NULL;
		vdp->xs_ionum++;

		mutex_exit(&vdp->xs_iomutex);
		if (bp->b_bcount == 0) {
			/* no I/O needs to be done */
			(void) xdb_biodone(bp);
			mutex_enter(&vdp->xs_iomutex);
			continue;
		}

		err = EIO;
		if (vdp->xs_ldi_hdl != NULL)
			err = ldi_strategy(vdp->xs_ldi_hdl, bp);
		if (err != 0) {
			bp->b_flags |= B_ERROR;
			(void) xdb_biodone(bp);
			XDB_DBPRINT(XDB_DBG_IO, (CE_WARN,
			    "xdb@%s: sent buf to backend devfailed, err=%d",
			    ddi_get_name_addr(vdp->xs_dip), err));
		} else {
			XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE,
			    "sent buf to backend ok"));
		}
		mutex_enter(&vdp->xs_iomutex);
	}
	XDB_DBPRINT(XDB_DBG_IO, (CE_NOTE, "send buf finishing"));
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

	if (state != Connected)
		return;

	mutex_enter(&vdp->xs_cbmutex);

	/* If hotplug script have already run, there's nothing todo */
	if (vdp->xs_hp_connected) {
		mutex_exit(&vdp->xs_cbmutex);
		return;
	}

	vdp->xs_hp_connected = B_TRUE;
	xdb_start_connect(vdp);
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

	/*
	 * Now it'd really be nice if there was a well defined state
	 * transition model for xen frontend drivers, but unfortunatly
	 * there isn't.  So we're stuck with assuming that all state
	 * transitions are possible, and we'll just have to deal with
	 * them regardless of what state we're in.
	 */
	switch (new_state) {
	case XenbusStateUnknown:
	case XenbusStateInitialising:
	case XenbusStateInitWait:
		/* tear down our connection to the frontend */
		xdb_close(dip);
		vdp->xs_fe_initialised = B_FALSE;
		break;

	case XenbusStateInitialised:
		/*
		 * If we were conected, then we need to drop the connection
		 * and re-negotiate it.
		 */
		xdb_close(dip);
		vdp->xs_fe_initialised = B_TRUE;
		xdb_start_connect(vdp);
		break;

	case XenbusStateConnected:
		/* nothing todo here other than congratulate the frontend */
		break;

	case XenbusStateClosing:
		/* monkey see monkey do */
		(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateClosing);
		break;

	case XenbusStateClosed:
		/* tear down our connection to the frontend */
		xdb_close(dip);
		vdp->xs_fe_initialised = B_FALSE;
		(void) xvdi_switch_state(dip, XBT_NULL, new_state);
		break;
	}

	mutex_exit(&vdp->xs_cbmutex);
}

static int
xdb_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ddi_iblock_cookie_t	ibc;
	xdb_t			*vdp;
	int			instance = ddi_get_instance(dip);
	char			*xsname, *oename;
	char			*str;

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_FAILURE);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}
	/* DDI_ATTACH */

	if (((xsname = xvdi_get_xsname(dip)) == NULL) ||
	    ((oename = xvdi_get_oename(dip)) == NULL))
		return (DDI_FAILURE);

	/*
	 * Disable auto-detach.  This is necessary so that we don't get
	 * detached while we're disconnected from the front end.
	 */
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, DDI_NO_AUTODETACH, 1);

	if (ddi_get_iblock_cookie(dip, 0, &ibc) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_soft_state_zalloc(xdb_statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	vdp = ddi_get_soft_state(xdb_statep, instance);
	vdp->xs_dip = dip;
	mutex_init(&vdp->xs_iomutex, NULL, MUTEX_DRIVER, (void *)ibc);
	mutex_init(&vdp->xs_cbmutex, NULL, MUTEX_DRIVER, (void *)ibc);
	cv_init(&vdp->xs_iocv, NULL, CV_DRIVER, NULL);
	cv_init(&vdp->xs_ionumcv, NULL, CV_DRIVER, NULL);
	ddi_set_driver_private(dip, vdp);

	if (!xdb_kstat_init(vdp))
		goto errout1;

	/* Check if the frontend device is supposed to be a cdrom */
	if (xenbus_read_str(oename, XBP_DEV_TYPE, &str) != 0)
		return (DDI_FAILURE);
	if (strcmp(str, XBV_DEV_TYPE_CD) == 0)
		vdp->xs_type |= XDB_DEV_FE_CD;
	strfree(str);

	/* Check if the frontend device is supposed to be read only */
	if (xenbus_read_str(xsname, "mode", &str) != 0)
		return (DDI_FAILURE);
	if ((strcmp(str, "r") == 0) || (strcmp(str, "ro") == 0))
		vdp->xs_type |= XDB_DEV_RO;
	strfree(str);

	mutex_enter(&vdp->xs_cbmutex);
	if (!xdb_media_req_init(vdp) || !xdb_params_init(vdp)) {
		xvdi_remove_xb_watch_handlers(dip);
		mutex_exit(&vdp->xs_cbmutex);
		goto errout2;
	}
	mutex_exit(&vdp->xs_cbmutex);

	vdp->xs_send_buf = B_TRUE;
	vdp->xs_iotaskq = ddi_taskq_create(dip, "xdb_iotask", 1,
	    TASKQ_DEFAULTPRI, 0);
	(void) ddi_taskq_dispatch(vdp->xs_iotaskq, xdb_send_buf, vdp,
	    DDI_SLEEP);

	/* Watch frontend and hotplug state change */
	if ((xvdi_add_event_handler(dip, XS_OE_STATE, xdb_oe_state_change,
	    NULL) != DDI_SUCCESS) ||
	    (xvdi_add_event_handler(dip, XS_HP_STATE, xdb_hp_state_change,
	    NULL) != DDI_SUCCESS))
		goto errout3;

	/*
	 * Kick-off hotplug script
	 */
	if (xvdi_post_event(dip, XEN_HP_ADD) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "xdb@%s: failed to start hotplug script",
		    ddi_get_name_addr(dip));
		goto errout3;
	}

	/*
	 * start waiting for hotplug event and otherend state event
	 * mainly for debugging, frontend will not take any op seeing this
	 */
	(void) xvdi_switch_state(dip, XBT_NULL, XenbusStateInitWait);

	XDB_DBPRINT(XDB_DBG_INFO, (CE_NOTE, "xdb@%s: attached!",
	    ddi_get_name_addr(dip)));
	return (DDI_SUCCESS);

errout3:
	ASSERT(vdp->xs_hp_connected && vdp->xs_if_connected);

	xvdi_remove_event_handler(dip, NULL);

	/* Disconnect from the backend */
	mutex_enter(&vdp->xs_cbmutex);
	mutex_enter(&vdp->xs_iomutex);
	vdp->xs_send_buf = B_FALSE;
	cv_broadcast(&vdp->xs_iocv);
	mutex_exit(&vdp->xs_iomutex);
	mutex_exit(&vdp->xs_cbmutex);

	/* wait for all io to dtrain and destroy io taskq */
	ddi_taskq_destroy(vdp->xs_iotaskq);

	/* tear down block-configure watch */
	mutex_enter(&vdp->xs_cbmutex);
	xvdi_remove_xb_watch_handlers(dip);
	mutex_exit(&vdp->xs_cbmutex);

errout2:
	/* remove kstats */
	kstat_delete(vdp->xs_kstats);

errout1:
	/* free up driver state */
	ddi_set_driver_private(dip, NULL);
	cv_destroy(&vdp->xs_iocv);
	cv_destroy(&vdp->xs_ionumcv);
	mutex_destroy(&vdp->xs_cbmutex);
	mutex_destroy(&vdp->xs_iomutex);
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

	/* refuse to detach if we're still in use by the frontend */
	mutex_enter(&vdp->xs_iomutex);
	if (vdp->xs_if_connected) {
		mutex_exit(&vdp->xs_iomutex);
		return (DDI_FAILURE);
	}
	vdp->xs_send_buf = B_FALSE;
	cv_broadcast(&vdp->xs_iocv);
	mutex_exit(&vdp->xs_iomutex);

	xvdi_remove_event_handler(dip, NULL);
	(void) xvdi_post_event(dip, XEN_HP_REMOVE);

	ddi_taskq_destroy(vdp->xs_iotaskq);

	mutex_enter(&vdp->xs_cbmutex);
	xvdi_remove_xb_watch_handlers(dip);
	mutex_exit(&vdp->xs_cbmutex);

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
	ddi_quiesce_not_needed, /* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module. */
	"vbd backend driver",		/* Name of the module */
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
