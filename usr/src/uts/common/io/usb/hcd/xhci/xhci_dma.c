/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

/*
 * xHCI DMA Management Routines
 *
 * Please see the big theory statement in xhci.c for more information.
 */

#include <sys/usb/hcd/xhci/xhci.h>

int
xhci_check_dma_handle(xhci_t *xhcip, xhci_dma_buffer_t *xdb)
{
	ddi_fm_error_t de;

	if (!DDI_FM_DMA_ERR_CAP(xhcip->xhci_fm_caps))
		return (0);

	ddi_fm_dma_err_get(xdb->xdb_dma_handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

void
xhci_dma_acc_attr(xhci_t *xhcip, ddi_device_acc_attr_t *accp)
{
	accp->devacc_attr_version = DDI_DEVICE_ATTR_V0;
	accp->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	accp->devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (DDI_FM_DMA_ERR_CAP(xhcip->xhci_fm_caps)) {
		accp->devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		accp->devacc_attr_access = DDI_DEFAULT_ACC;
	}
}

/*
 * These are DMA attributes that we assign when making a transfer. The SGL is
 * variable and based on the caller, which varies based on the type of transfer
 * we're doing.
 */
void
xhci_dma_transfer_attr(xhci_t *xhcip, ddi_dma_attr_t *attrp, uint_t sgl)
{
	VERIFY3U(sgl, >, 0);
	VERIFY3U(sgl, <=, XHCI_TRANSFER_DMA_SGL);
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * The range of data that we can use is based on what hardware supports.
	 */
	attrp->dma_attr_addr_lo = 0x0;
	if (xhcip->xhci_caps.xcap_flags & XCAP_AC64) {
		attrp->dma_attr_addr_hi = UINT64_MAX;
	} else {
		attrp->dma_attr_addr_hi = UINT32_MAX;
	}

	/*
	 * The count max indicates the total amount that will fit into one
	 * cookie, which is one TRB in our world. In other words 64k.
	 */
	attrp->dma_attr_count_max = XHCI_TRB_MAX_TRANSFER;

	/*
	 * The alignment and segment are related. The alignment describes the
	 * alignment of the PA. The segment describes a boundary that the DMA
	 * allocation cannot cross. In other words, for a given chunk of memory
	 * it cannot cross a 64-byte boundary. However, the physical address
	 * only needs to be aligned to align bytes.
	 */
	attrp->dma_attr_align = XHCI_DMA_ALIGN;
	attrp->dma_attr_seg = XHCI_TRB_MAX_TRANSFER - 1;


	attrp->dma_attr_burstsizes = 0xfff;

	/*
	 * This is the maximum we can send. Technically this is limited by the
	 * descriptors and not by hardware, hence why we use a large value for
	 * the max that'll be less than any memory allocation we ever throw at
	 * it.
	 */
	attrp->dma_attr_minxfer = 0x1;
	attrp->dma_attr_maxxfer = UINT32_MAX;

	/*
	 * This is determined by the caller.
	 */
	attrp->dma_attr_sgllen = sgl;

	/*
	 * The granularity describes the addressing granularity. e.g. can things
	 * ask for chunks in units of this number of bytes. For PCI this should
	 * always be one.
	 */
	attrp->dma_attr_granular = 1;

	if (DDI_FM_DMA_ERR_CAP(xhcip->xhci_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

/*
 * This routine tries to create DMA attributes for normal allocations for data
 * structures and the like. By default we use the same values as the transfer
 * attributes, but have explicit comments about how they're different.
 */
void
xhci_dma_dma_attr(xhci_t *xhcip, ddi_dma_attr_t *attrp)
{
	/*
	 * Note, we always use a single SGL for these DMA allocations as these
	 * are used for small data structures.
	 */
	xhci_dma_transfer_attr(xhcip, attrp, XHCI_DEF_DMA_SGL);

	/*
	 * The maximum size of any of these structures is 4k as opposed to the
	 * 64K max described above. Similarly the boundary requirement is
	 * reduced to 4k.
	 */
	attrp->dma_attr_count_max = xhcip->xhci_caps.xcap_pagesize;
	attrp->dma_attr_maxxfer = xhcip->xhci_caps.xcap_pagesize;
	attrp->dma_attr_seg = xhcip->xhci_caps.xcap_pagesize - 1;
}

/*
 * Fill in attributes for a scratchpad entry. The scratchpad entries are
 * somewhat different in so far as they are closest to a normal DMA attribute,
 * except they have stricter alignments, needing to be page sized.
 *
 * In addition, because we never access this memory ourselves, we can just mark
 * it all as relaxed ordering.
 */
void
xhci_dma_scratchpad_attr(xhci_t *xhcip, ddi_dma_attr_t *attrp)
{
	xhci_dma_dma_attr(xhcip, attrp);
	attrp->dma_attr_align = xhcip->xhci_caps.xcap_pagesize;
	attrp->dma_attr_flags |= DDI_DMA_RELAXED_ORDERING;
}

/*
 * This should be used for the simple case of a single SGL entry, which is the
 * vast majority of the non-transfer allocations.
 */
uint64_t
xhci_dma_pa(xhci_dma_buffer_t *xdb)
{
	ASSERT(xdb->xdb_ncookies == 1);
	return (xdb->xdb_cookies[0].dmac_laddress);
}

void
xhci_dma_free(xhci_dma_buffer_t *xdb)
{
	if (xdb->xdb_ncookies != 0) {
		VERIFY(xdb->xdb_dma_handle != NULL);
		(void) ddi_dma_unbind_handle(xdb->xdb_dma_handle);
		xdb->xdb_ncookies = 0;
		bzero(xdb->xdb_cookies, sizeof (ddi_dma_cookie_t) *
		    XHCI_TRANSFER_DMA_SGL);
		xdb->xdb_len = 0;
	}

	if (xdb->xdb_acc_handle != NULL) {
		ddi_dma_mem_free(&xdb->xdb_acc_handle);
		xdb->xdb_acc_handle = NULL;
		xdb->xdb_va = NULL;
	}

	if (xdb->xdb_dma_handle != NULL) {
		ddi_dma_free_handle(&xdb->xdb_dma_handle);
		xdb->xdb_dma_handle = NULL;
	}

	ASSERT(xdb->xdb_va == NULL);
	ASSERT(xdb->xdb_ncookies == 0);
	ASSERT(xdb->xdb_cookies[0].dmac_laddress == 0);
	ASSERT(xdb->xdb_len == 0);
}

boolean_t
xhci_dma_alloc(xhci_t *xhcip, xhci_dma_buffer_t *xdb,
    ddi_dma_attr_t *attrp, ddi_device_acc_attr_t *accp, boolean_t zero,
    size_t size, boolean_t wait)
{
	int ret, i;
	uint_t flags = DDI_DMA_CONSISTENT;
	size_t len;
	ddi_dma_cookie_t cookie;
	uint_t ncookies;
	int (*memcb)(caddr_t);

	if (wait == B_TRUE) {
		memcb = DDI_DMA_SLEEP;
	} else {
		memcb = DDI_DMA_DONTWAIT;
	}

	ret = ddi_dma_alloc_handle(xhcip->xhci_dip, attrp, memcb, NULL,
	    &xdb->xdb_dma_handle);
	if (ret != 0) {
		xhci_log(xhcip, "!failed to allocate DMA handle: %d", ret);
		xdb->xdb_dma_handle = NULL;
		return (B_FALSE);
	}

	ret = ddi_dma_mem_alloc(xdb->xdb_dma_handle, size, accp, flags, memcb,
	    NULL, &xdb->xdb_va, &len, &xdb->xdb_acc_handle);
	if (ret != DDI_SUCCESS) {
		xhci_log(xhcip, "!failed to allocate DMA memory: %d", ret);
		xdb->xdb_va = NULL;
		xdb->xdb_acc_handle = NULL;
		xhci_dma_free(xdb);
		return (B_FALSE);
	}

	if (zero == B_TRUE)
		bzero(xdb->xdb_va, len);

	ret = ddi_dma_addr_bind_handle(xdb->xdb_dma_handle, NULL,
	    xdb->xdb_va, len, DDI_DMA_RDWR | flags, memcb, NULL, &cookie,
	    &ncookies);
	if (ret != 0) {
		xhci_log(xhcip, "!failed to bind DMA memory: %d", ret);
		xhci_dma_free(xdb);
		return (B_FALSE);
	}

	/*
	 * Note we explicitly store the logical length of this allocation. The
	 * physical length is available via the cookies.
	 */
	xdb->xdb_len = size;
	xdb->xdb_ncookies = ncookies;
	xdb->xdb_cookies[0] = cookie;
	for (i = 1; i < ncookies; i++) {
		ddi_dma_nextcookie(xdb->xdb_dma_handle, &xdb->xdb_cookies[i]);
	}


	return (B_TRUE);
}

void
xhci_transfer_free(xhci_t *xhcip, xhci_transfer_t *xt)
{
	if (xt == NULL)
		return;

	VERIFY(xhcip != NULL);
	xhci_dma_free(&xt->xt_buffer);
	if (xt->xt_isoc != NULL) {
		ASSERT(xt->xt_ntrbs > 0);
		kmem_free(xt->xt_isoc, sizeof (usb_isoc_pkt_descr_t) *
		    xt->xt_ntrbs);
		xt->xt_isoc = NULL;
	}
	if (xt->xt_trbs != NULL) {
		ASSERT(xt->xt_ntrbs > 0);
		kmem_free(xt->xt_trbs, sizeof (xhci_trb_t) * xt->xt_ntrbs);
		xt->xt_trbs = NULL;
	}
	kmem_free(xt, sizeof (xhci_transfer_t));
}

xhci_transfer_t *
xhci_transfer_alloc(xhci_t *xhcip, xhci_endpoint_t *xep, size_t size, int trbs,
    int usb_flags)
{
	int kmflags;
	boolean_t dmawait;
	xhci_transfer_t *xt;
	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;

	if (usb_flags & USB_FLAGS_SLEEP) {
		kmflags = KM_SLEEP;
		dmawait = B_TRUE;
	} else {
		kmflags = KM_NOSLEEP;
		dmawait = B_FALSE;
	}

	xt = kmem_zalloc(sizeof (xhci_transfer_t), kmflags);
	if (xt == NULL)
		return (NULL);

	if (size != 0) {
		int sgl = XHCI_DEF_DMA_SGL;

		/*
		 * For BULK transfers, we always increase the number of SGL
		 * entries that we support to make things easier for the kernel.
		 * However, for control transfers, we currently opt to keep
		 * things a bit simpler and use our default of one SGL.  There's
		 * no good technical reason for this, rather it just keeps
		 * things a bit easier.
		 *
		 * To simplify things, we don't use additional SGL entries for
		 * ISOC transfers. While this isn't the best, it isn't too far
		 * off from what ehci and co. have done before. If this becomes
		 * a technical issue, it's certainly possible to increase the
		 * SGL entry count.
		 */
		if (xep->xep_type == USB_EP_ATTR_BULK)
			sgl = XHCI_TRANSFER_DMA_SGL;

		xhci_dma_acc_attr(xhcip, &acc);
		xhci_dma_transfer_attr(xhcip, &attr, sgl);
		if (xhci_dma_alloc(xhcip, &xt->xt_buffer, &attr, &acc, B_FALSE,
		    size, dmawait) == B_FALSE) {
			kmem_free(xt, sizeof (xhci_transfer_t));
			return (NULL);
		}

		/*
		 * ISOC transfers are a bit special and don't need additional
		 * TRBs for data.
		 */
		if (xep->xep_type != USB_EP_ATTR_ISOCH)
			trbs += xt->xt_buffer.xdb_ncookies;
	}

	xt->xt_trbs = kmem_zalloc(sizeof (xhci_trb_t) * trbs, kmflags);
	if (xt->xt_trbs == NULL) {
		xhci_dma_free(&xt->xt_buffer);
		kmem_free(xt, sizeof (xhci_transfer_t));
		return (NULL);
	}

	/*
	 * For ISOCH transfers, we need to also allocate the results data.
	 */
	if (xep->xep_type == USB_EP_ATTR_ISOCH) {
		xt->xt_isoc = kmem_zalloc(sizeof (usb_isoc_pkt_descr_t) * trbs,
		    kmflags);
		if (xt->xt_isoc == NULL) {
			kmem_free(xt->xt_trbs, sizeof (xhci_trb_t) * trbs);
			xhci_dma_free(&xt->xt_buffer);
			kmem_free(xt, sizeof (xhci_transfer_t));
			return (NULL);
		}
	}

	xt->xt_ntrbs = trbs;
	xt->xt_cr = USB_CR_OK;

	return (xt);
}

/*
 * Abstract the notion of copying out to handle the case of multiple DMA
 * cookies. If tobuf is true, we are copying to the kernel provided buffer,
 * otherwise we're copying into the DMA memory.
 */
void
xhci_transfer_copy(xhci_transfer_t *xt, void *buf, size_t len,
    boolean_t tobuf)
{
	void *dmabuf = xt->xt_buffer.xdb_va;
	if (tobuf == B_TRUE)
		bcopy(dmabuf, buf, len);
	else
		bcopy(buf, dmabuf, len);
}

int
xhci_transfer_sync(xhci_t *xhcip, xhci_transfer_t *xt, uint_t type)
{
	XHCI_DMA_SYNC(xt->xt_buffer, type);
	return (xhci_check_dma_handle(xhcip, &xt->xt_buffer));
}

/*
 * We're required to try and inform the xHCI controller about the number of data
 * packets that are required. The algorithm to use is described in xHCI 1.1 /
 * 4.11.2.4. While it might be tempting to just try and calculate the number of
 * packets based on simple rounding of the remaining number of bytes, that
 * misses a critical problem -- DMA boundaries may cause us to need additional
 * packets that are missed initially. Consider a transfer made up of four
 * different DMA buffers sized in bytes: 4096, 4096, 256, 256, with a 512 byte
 * packet size.
 *
 * Remain	4608	512	256	0
 * Bytes	4096	4096	256	256
 * Naive TD	9	1	1	0
 * Act TD 	10	2	1	0
 *
 * This means that the only safe way forward here is to work backwards and see
 * how many we need to work up to this point.
 */
static int
xhci_transfer_get_tdsize(xhci_transfer_t *xt, uint_t off, uint_t mps)
{
	int i;
	uint_t npkt = 0;

	/*
	 * There are always zero packets for the last TRB.
	 */
	ASSERT(xt->xt_buffer.xdb_ncookies > 0);
	for (i = xt->xt_buffer.xdb_ncookies - 1; i > off; i--) {
		size_t len;

		/*
		 * The maximum value we can return is 31 packets. So, in that
		 * case we short-circuit and return.
		 */
		if (npkt >= 31)
			return (31);

		len = roundup(xt->xt_buffer.xdb_cookies[i].dmac_size, mps);
		npkt += len / mps;
	}

	return (npkt);
}

void
xhci_transfer_trb_fill_data(xhci_endpoint_t *xep, xhci_transfer_t *xt, int off,
    boolean_t in)
{
	uint_t mps, tdsize, flags;
	int i;

	VERIFY(xt->xt_buffer.xdb_ncookies > 0);
	VERIFY(xep->xep_pipe != NULL);
	VERIFY(off + xt->xt_buffer.xdb_ncookies <= xt->xt_ntrbs);
	mps = xep->xep_pipe->p_ep.wMaxPacketSize;

	for (i = 0; i < xt->xt_buffer.xdb_ncookies; i++) {
		uint64_t pa, dmasz;

		pa = xt->xt_buffer.xdb_cookies[i].dmac_laddress;
		dmasz = xt->xt_buffer.xdb_cookies[i].dmac_size;

		tdsize = xhci_transfer_get_tdsize(xt, i, mps);

		flags = XHCI_TRB_TYPE_NORMAL;
		if (i == 0 && xep->xep_type == USB_EP_ATTR_CONTROL) {
			flags = XHCI_TRB_TYPE_DATA;
			if (in == B_TRUE)
				flags |= XHCI_TRB_DIR_IN;
		}

		/*
		 * When reading data in (from the device), we may get shorter
		 * transfers than the buffer allowed for. To make sure we get
		 * notified about that and handle that, we need to set the ISP
		 * flag.
		 */
		if (in == B_TRUE) {
			flags |= XHCI_TRB_ISP;
			xt->xt_data_tohost = B_TRUE;
		}

		/*
		 * When we have more than one cookie, we are technically
		 * chaining together things according to the controllers view,
		 * hence why we need to set the chain flag.
		 */
		if (xt->xt_buffer.xdb_ncookies > 1 &&
		    i != (xt->xt_buffer.xdb_ncookies - 1)) {
			flags |= XHCI_TRB_CHAIN;
		}

		/*
		 * If we have a non-control transfer, then we need to make sure
		 * that we set ourselves up to be interrupted, which we set for
		 * the last entry.
		 */
		if (i + 1 == xt->xt_buffer.xdb_ncookies &&
		    xep->xep_type != USB_EP_ATTR_CONTROL) {
			flags |= XHCI_TRB_IOC;
		}

		xt->xt_trbs[off + i].trb_addr = LE_64(pa);
		xt->xt_trbs[off + i].trb_status = LE_32(XHCI_TRB_LEN(dmasz) |
		    XHCI_TRB_TDREM(tdsize) | XHCI_TRB_INTR(0));
		xt->xt_trbs[off + i].trb_flags = LE_32(flags);
	}
}

/*
 * These are utility functions for isochronus transfers to help calculate the
 * transfer burst count (TBC) and transfer last burst packet count (TLPBC)
 * entries for an isochronus entry. See xHCI 1.1 / 4.11.2.3 for how to calculate
 * them.
 */
void
xhci_transfer_calculate_isoc(xhci_device_t *xd, xhci_endpoint_t *xep,
    uint_t trb_len, uint_t *tbc, uint_t *tlbpc)
{
	uint_t mps, tdpc, burst;

	/*
	 * Even if we're asked to send no data, that actually requires the
	 * equivalent of sending one byte of data.
	 */
	if (trb_len == 0)
		trb_len = 1;

	mps = XHCI_EPCTX_GET_MPS(xd->xd_endout[xep->xep_num]->xec_info2);
	burst = XHCI_EPCTX_GET_MAXB(xd->xd_endout[xep->xep_num]->xec_info2);

	/*
	 * This is supposed to correspond to the Transfer Descriptor Packet
	 * Count from xHCI 1.1 / 4.14.1.
	 */
	tdpc = howmany(trb_len, mps);
	*tbc = howmany(tdpc, burst + 1) - 1;

	if ((tdpc % (burst + 1)) == 0)
		*tlbpc = burst;
	else
		*tlbpc = (tdpc % (burst + 1)) - 1;
}
