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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * igc ring related functions. This is where the bulk of our I/O occurs.
 */

#include <sys/stddef.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>

#include "igc.h"

/*
 * Structure used to consolidate TX information about a given packet.
 */
typedef struct igc_tx_state {
	list_t itx_bufs;
	mac_ether_offload_info_t itx_meoi;
	uint32_t itx_cksum;
	uint32_t itx_mss;
	uint32_t itx_lso;
	igc_tx_buffer_t *itx_cur_buf;
	size_t itx_buf_rem;
	mblk_t *itx_free_mp;
	uint32_t itx_ndescs;
} igc_tx_state_t;

/*
 * DMA attributes that are used for descriptor rings. .
 */
static const ddi_dma_attr_t igc_desc_dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	/*
	 * DMA descriptor rings can show up anywhere in the address space. The
	 * card supports a 64-bit address for this.
	 */
	.dma_attr_addr_lo = 0,
	.dma_attr_addr_hi = UINT64_MAX,
	/*
	 * The I210 datasheet says that the ring descriptor length can support
	 * at most 32K entries that are each 16 bytes long. Hence the following
	 * max.
	 */
	.dma_attr_count_max = 0x80000,
	/*
	 * The I210 datasheet, which is the closest we have for the I225,
	 * requires 128 byte alignment for rings. Note, igb and e1000g default
	 * to a 4KiB alignment here.
	 */
	.dma_attr_align = 0x80,
	/*
	 * Borrowed from igb(4D).
	 */
	.dma_attr_burstsizes = 0xfff,
	/*
	 * We set the minimum and maximum based upon what the RDLEN/TDLEN
	 * register will actually support.
	 */
	.dma_attr_minxfer = 0x80,
	.dma_attr_maxxfer = 0x80000,
	/*
	 * The receive ring must be continuous, indicated by the maximum sgllen
	 * value, which means that this doesn't have any boundary crossing
	 * constraints.
	 */
	.dma_attr_seg = UINT64_MAX,
	.dma_attr_sgllen = 1,
	/*
	 * For descriptor rings, hardware asks for the size in 128 byte chunks,
	 * so we set that here again.
	 */
	.dma_attr_granular = 0x80,
	.dma_attr_flags = 0
};

/*
 * DMA attributes that cover pre-allocated data buffers. Note, RX buffers are
 * slightly more constrained than TX buffers because the RX buffer addr[0] can
 * sometimes be used as a no snoop enable bit. Therefore we purposefully avoid
 * that in our allocations here to allow for use of that in the future if
 * desired.
 */
static const ddi_dma_attr_t igc_data_dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	/*
	 * Packet data can go anywhere in memory.
	 */
	.dma_attr_addr_lo = 0,
	.dma_attr_addr_hi = UINT64_MAX,
	/*
	 * The maximum size of an RX packet is 127 KiB in the SRRCTL register.
	 * For TX, the maximum value is a 16-bit quantity because that's the
	 * tx descriptor's size. So we cap it at this value.
	 */
	.dma_attr_count_max = UINT16_MAX,
	/*
	 * The hardware strictly requires only 2 byte alignment in RX
	 * descriptors in case no snoop is enabled and no such constraints in
	 * TX. We end up increasing this to a request for 16 byte alignment so
	 * that we can guarantee the IP header alignment and offsetting needs to
	 * happen on all rx descriptors.
	 */
	.dma_attr_align = 0x10,
	/*
	 * We're not constrained here at least via PCIe, so we use the wider
	 * setting here. Similarly to the ring descriptors we just set the
	 * granularity widely.
	 */
	.dma_attr_minxfer = 0x1,
	.dma_attr_maxxfer = UINT32_MAX,
	.dma_attr_seg = UINT64_MAX,
	/*
	 * The hardware allows for arbitrary chaining of descriptors; however,
	 * we want to move to a world where we are allocating page sized buffers
	 * at most and therefore constrain the number of cookies for these
	 * buffers. Transmit caps the buffer allocation size at the page size,
	 * but receive does not today. We set the granularity to 1 to reflect
	 * the device's flexibility.
	 */
	.dma_attr_sgllen = 1,
	.dma_attr_granular = 1,
	.dma_attr_flags = 0
};

/*
 * These are the DMA attributes we use when performing DMA TX binding for an
 * mblk_t.
 */
static const ddi_dma_attr_t igc_tx_dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	/*
	 * Packet data can go anywhere in memory.
	 */
	.dma_attr_addr_lo = 0,
	.dma_attr_addr_hi = UINT64_MAX,
	/*
	 * For TX, the maximum value is a 16-bit quantity because that's the
	 * tx descriptor's size.
	 */
	.dma_attr_count_max = UINT16_MAX,
	/*
	 * TX data can go anywhere, but we ask for 16 byte alignment just to
	 * keep things somewhat aligned in the system.
	 */
	.dma_attr_align = 0x10,
	/*
	 * We're not constrained here at least via PCIe, so we use the wider
	 * setting here. Similarly to the ring descriptors we just set the
	 * granularity widely.
	 */
	.dma_attr_minxfer = 0x1,
	.dma_attr_maxxfer = UINT32_MAX,
	.dma_attr_seg = UINT64_MAX,
	/*
	 * We size our transmit cookies so that the maximum sized LSO packet can
	 * go through here.
	 */
	.dma_attr_sgllen = IGC_MAX_TX_COOKIES,
	.dma_attr_granular = 1,
	.dma_attr_flags = 0

};

/*
 * All of these wrappers are so we only have one place to tack into FMA
 * register accesses in the future.
 */
static void
igc_dma_acc_attr(igc_t *igc, ddi_device_acc_attr_t *accp)
{
	bzero(accp, sizeof (ddi_device_acc_attr_t));

	accp->devacc_attr_version = DDI_DEVICE_ATTR_V1;
	accp->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	accp->devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	accp->devacc_attr_access = DDI_DEFAULT_ACC;
}

static void
igc_dma_desc_attr(igc_t *igc, ddi_dma_attr_t *attrp)
{
	bcopy(&igc_desc_dma_attr, attrp, sizeof (ddi_dma_attr_t));
}

static void
igc_dma_data_attr(igc_t *igc, ddi_dma_attr_t *attrp)
{
	bcopy(&igc_data_dma_attr, attrp, sizeof (ddi_dma_attr_t));
}

static void
igc_dma_tx_attr(igc_t *igc, ddi_dma_attr_t *attrp)
{
	bcopy(&igc_tx_dma_attr, attrp, sizeof (ddi_dma_attr_t));
}

static void
igc_dma_free(igc_dma_buffer_t *idb)
{
	/* Proxy for DMA handle bound */
	if (idb->idb_size != 0) {
		(void) ddi_dma_unbind_handle(idb->idb_hdl);
		idb->idb_size = 0;
	}

	if (idb->idb_acc != NULL) {
		ddi_dma_mem_free(&idb->idb_acc);
		idb->idb_acc = NULL;
		idb->idb_va = NULL;
		idb->idb_alloc_len = 0;
	}

	if (idb->idb_hdl != NULL) {
		ddi_dma_free_handle(&idb->idb_hdl);
		idb->idb_hdl = NULL;
	}

	ASSERT0(idb->idb_size);
	ASSERT0(idb->idb_alloc_len);
	ASSERT3P(idb->idb_acc, ==, NULL);
	ASSERT3P(idb->idb_hdl, ==, NULL);
	ASSERT3P(idb->idb_va, ==, NULL);
}

static bool
igc_dma_alloc(igc_t *igc, igc_dma_buffer_t *idb, ddi_dma_attr_t *attrp,
    size_t size)
{
	int ret;
	ddi_device_acc_attr_t acc;
	uint_t flags = DDI_DMA_STREAMING;

	bzero(idb, sizeof (igc_dma_buffer_t));
	ret = ddi_dma_alloc_handle(igc->igc_dip, attrp, DDI_DMA_DONTWAIT, NULL,
	    &idb->idb_hdl);
	if (ret != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "!failed to allocate DMA "
		    "handle: %d", ret);
		return (false);
	}

	igc_dma_acc_attr(igc, &acc);
	ret = ddi_dma_mem_alloc(idb->idb_hdl, size, &acc, flags,
	    DDI_DMA_DONTWAIT, NULL, &idb->idb_va, &idb->idb_alloc_len,
	    &idb->idb_acc);
	if (ret != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "!failed to allocate %lu bytes "
		    "of DMA memory: %d", size, ret);
		igc_dma_free(idb);
		return (false);
	}

	bzero(idb->idb_va, idb->idb_alloc_len);
	ret = ddi_dma_addr_bind_handle(idb->idb_hdl, NULL, idb->idb_va,
	    idb->idb_alloc_len, DDI_DMA_RDWR | flags, DDI_DMA_DONTWAIT, NULL,
	    NULL, NULL);
	if (ret != DDI_SUCCESS) {
		dev_err(igc->igc_dip, CE_WARN, "!failed to bind %lu bytes of "
		    "DMA memory: %d", idb->idb_alloc_len, ret);
		igc_dma_free(idb);
		return (false);
	}

	idb->idb_size = size;
	return (true);
}

static void
igc_rx_recycle(caddr_t arg)
{
	igc_rx_buffer_t *buf = (igc_rx_buffer_t *)arg;
	igc_rx_ring_t *ring = buf->irb_ring;
	caddr_t mblk_va;
	size_t mblk_len;

	/*
	 * The mblk is free regardless of what happens next, so make sure we
	 * clean up.
	 */
	buf->irb_mp = NULL;

	/*
	 * The mblk_t is pre-created ahead of binding. If loaned is not set then
	 * this simply means we're tearing down this as part of tearing down the
	 * device as opposed to getting it from the rest of the stack and
	 * therefore there's nothing else to do.
	 */
	if (!buf->irb_loaned) {
		return;
	}

	/*
	 * Ensure we mark this buffer as no longer loaned and then insert it
	 * onto the free list.
	 */
	buf->irb_loaned = false;

	/*
	 * Create a new mblk and insert it on the free list.
	 */
	mblk_va = buf->irb_dma.idb_va + IGC_RX_BUF_IP_ALIGN;
	mblk_len = buf->irb_dma.idb_size - IGC_RX_BUF_IP_ALIGN;
	buf->irb_mp = desballoc((uchar_t *)mblk_va, mblk_len, 0,
	    &buf->irb_free_rtn);

	mutex_enter(&ring->irr_free_lock);
	ring->irr_free_list[ring->irr_nfree] = buf;
	ring->irr_nfree++;
#ifdef	DEBUG
	igc_t *igc = ring->irr_igc;
	ASSERT3U(ring->irr_nfree, <=, igc->igc_rx_nfree);
#endif
	cv_signal(&ring->irr_free_cv);
	mutex_exit(&ring->irr_free_lock);
}

static void
igc_rx_bufs_free(igc_t *igc, igc_rx_ring_t *ring)
{
	for (uint32_t i = 0; i < igc->igc_rx_nbuf; i++) {
		igc_rx_buffer_t *buf = &ring->irr_arena[i];

		ASSERT3U(buf->irb_loaned, ==, false);
		freemsg(buf->irb_mp);
		buf->irb_mp = NULL;
		igc_dma_free(&buf->irb_dma);
	}
}

static bool
igc_rx_bufs_alloc(igc_t *igc, igc_rx_ring_t *ring)
{
	for (uint32_t i = 0; i < igc->igc_rx_nbuf; i++) {
		igc_rx_buffer_t *buf = &ring->irr_arena[i];
		ddi_dma_attr_t attr;
		caddr_t mblk_va;
		size_t mblk_len;

		buf->irb_ring = ring;
		igc_dma_data_attr(igc, &attr);
		if (!igc_dma_alloc(igc, &buf->irb_dma, &attr,
		    igc->igc_rx_buf_size)) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate RX "
			    "ring %u buffer %u", ring->irr_idx, i);
			return (false);
		}

		buf->irb_free_rtn.free_func = igc_rx_recycle;
		buf->irb_free_rtn.free_arg = (caddr_t)buf;

		/*
		 * We ignore whether or not this was successful because we have
		 * to handle the case that we will have buffers without mblk's
		 * due to loaning and related.
		 */
		mblk_va = buf->irb_dma.idb_va + IGC_RX_BUF_IP_ALIGN;
		mblk_len = buf->irb_dma.idb_size - IGC_RX_BUF_IP_ALIGN;
		buf->irb_mp = desballoc((uchar_t *)mblk_va, mblk_len, 0,
		    &buf->irb_free_rtn);

		if (i < igc->igc_rx_ndesc) {
			ring->irr_work_list[i] = buf;
		} else {
			ring->irr_free_list[ring->irr_nfree] = buf;
			ring->irr_nfree++;
		}
	}

	return (true);
}

void
igc_rx_data_free(igc_t *igc)
{
	for (uint32_t i = 0; i < igc->igc_nrx_rings; i++) {
		igc_rx_ring_t *ring = &igc->igc_rx_rings[i];

		if (ring->irr_arena != NULL) {
			igc_rx_bufs_free(igc, ring);
			kmem_free(ring->irr_arena, sizeof (igc_rx_buffer_t) *
			    igc->igc_rx_nbuf);
			ring->irr_arena = NULL;
		}

		if (ring->irr_free_list != NULL) {
			kmem_free(ring->irr_free_list, igc->igc_rx_nfree *
			    sizeof (igc_rx_buffer_t *));
			ring->irr_free_list = NULL;
		}

		if (ring->irr_work_list != NULL) {
			kmem_free(ring->irr_work_list, igc->igc_rx_ndesc *
			    sizeof (igc_rx_buffer_t *));
			ring->irr_work_list = NULL;
		}

		if (ring->irr_ring != NULL) {
			igc_dma_free(&ring->irr_desc_dma);
			ring->irr_ring = NULL;
			ring->irr_next = 0;
		}
	}
}

bool
igc_rx_data_alloc(igc_t *igc)
{
	for (uint32_t i = 0; i < igc->igc_nrx_rings; i++) {
		igc_rx_ring_t *ring = &igc->igc_rx_rings[i];
		ddi_dma_attr_t desc_attr;
		size_t desc_len;

		igc_dma_desc_attr(igc, &desc_attr);
		desc_len = sizeof (union igc_adv_rx_desc) *
		    igc->igc_rx_ndesc;
		if (!igc_dma_alloc(igc, &ring->irr_desc_dma, &desc_attr,
		    desc_len)) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate "
			    "RX descriptor ring %u", i);
			goto cleanup;
		}
		ring->irr_ring = (void *)ring->irr_desc_dma.idb_va;

		ring->irr_work_list = kmem_zalloc(sizeof (igc_rx_buffer_t *) *
		    igc->igc_rx_ndesc, KM_NOSLEEP);
		if (ring->irr_work_list == NULL) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate "
			    "RX descriptor ring %u rx work list", i);
			goto cleanup;
		}

		ring->irr_free_list = kmem_zalloc(sizeof (igc_rx_buffer_t *) *
		    igc->igc_rx_nfree, KM_NOSLEEP);
		if (ring->irr_free_list == NULL) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate "
			    "RX descriptor ring %u rx free list", i);
			goto cleanup;
		}


		ring->irr_arena = kmem_zalloc(sizeof (igc_rx_buffer_t) *
		    igc->igc_rx_nbuf, KM_NOSLEEP);
		if (ring->irr_arena == NULL) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate "
			    "RX descriptor ring %u rx buf arena", i);
			goto cleanup;
		}

		if (!igc_rx_bufs_alloc(igc, ring)) {
			goto cleanup;
		}
	}

	return (true);

cleanup:
	igc_rx_data_free(igc);
	return (false);
}

/*
 * Write / update a descriptor ring entry. This had been implemented in a few
 * places, so this was intended as a consolidation of those.
 */
static inline void
igc_rx_ring_desc_write(igc_rx_ring_t *ring, uint32_t idx)
{
	const ddi_dma_cookie_t *cookie;
	uint64_t addr;
	igc_dma_buffer_t *irb = &ring->irr_work_list[idx]->irb_dma;

	cookie = ddi_dma_cookie_one(irb->idb_hdl);
	addr = cookie->dmac_laddress + IGC_RX_BUF_IP_ALIGN;
	ring->irr_ring[idx].read.pkt_addr = LE_64(addr);
	ring->irr_ring[idx].read.hdr_addr = LE_64(0);
}

/*
 * Fully initialize a receive ring. This involves:
 *
 *  - Doing an initial programming and sync of the descriptor ring
 *  - Programming the base and length registers
 *  - Programming the ring's buffer size and descriptor type
 *  - Programming the queue's receive control register
 */
static void
igc_rx_ring_hw_init(igc_t *igc, igc_rx_ring_t *ring)
{
	uint32_t val, high, low;
	const ddi_dma_cookie_t *desc;

	for (uint32_t i = 0; i < igc->igc_rx_ndesc; i++) {
		igc_rx_ring_desc_write(ring, i);
	}
	IGC_DMA_SYNC(&ring->irr_desc_dma, DDI_DMA_SYNC_FORDEV);

	/*
	 * Program the ring's address.
	 */
	desc = ddi_dma_cookie_one(ring->irr_desc_dma.idb_hdl);
	high = (uint32_t)(desc->dmac_laddress >> 32);
	low = (uint32_t)desc->dmac_laddress;
	igc_write32(igc, IGC_RDBAH(ring->irr_idx), high);
	igc_write32(igc, IGC_RDBAL(ring->irr_idx), low);

	/*
	 * Program the ring length.
	 */
	val = igc->igc_rx_ndesc * sizeof (union igc_adv_rx_desc);
	igc_write32(igc, IGC_RDLEN(ring->irr_idx), val);

	/*
	 * Program the descriptor type and buffer length.
	 */
	val = (igc->igc_rx_buf_size >> IGC_SRRCTL_BSIZEPKT_SHIFT) |
	    IGC_SRRCTL_DESCTYPE_ADV_ONEBUF;
	igc_write32(igc, IGC_SRRCTL(ring->irr_idx), val);

	/*
	 * Program the ring control register itself. Note, we crib the threshold
	 * values directly from igb and didn't think much harder than that.
	 */
	val = igc_read32(igc, IGC_RXDCTL(ring->irr_idx));
	val &= IGC_RXDCTL_PRESERVE;
	val |= IGC_RXDCTL_QUEUE_ENABLE;
	val = IGC_RXDCTL_SET_PTHRESH(val, 16);
	val = IGC_RXDCTL_SET_HTHRESH(val, 8);
	val = IGC_RXDCTL_SET_WTHRESH(val, 1);
	igc_write32(igc, IGC_RXDCTL(ring->irr_idx), val);
}

void
igc_rx_hw_init(igc_t *igc)
{
	uint32_t rctl, rxcsum;

	/*
	 * Start by setting up the receive control register.
	 *
	 * We clear out any bits in the multicast shift portion. This'll leave
	 * it so [47:36] of the address are used as part of the look up. We also
	 * don't want to receive bad packets, so make sure that's cleared out.
	 * In addition, we clear out loopback mode.
	 */
	rctl = igc_read32(igc, IGC_RCTL);
	rctl &= ~(3 << IGC_RCTL_MO_SHIFT);
	rctl &= ~IGC_RCTL_SBP;
	rctl &= ~(IGC_RCTL_LBM_MAC | IGC_RCTL_LBM_TCVR);

	/*
	 * Set things up such that we're enabled, we receive broadcast packets,
	 * and we allow for large packets. We leave the rx descriptor threshold
	 * at 2048 bytes and make sure to always strip the Ethernet CRC as mac
	 * doesn't want it.
	 */
	rctl |= IGC_RCTL_EN | IGC_RCTL_BAM | IGC_RCTL_LPE |
	    IGC_RCTL_RDMTS_HALF | IGC_RCTL_SECRC;

	/*
	 * Set the multicast filter based on hardware.
	 */
	rctl |= igc->igc_hw.mac.mc_filter_type << IGC_RCTL_MO_SHIFT;

	/*
	 * Make sure each ring is set up and its registers are programmed.
	 */
	for (uint32_t i = 0; i < igc->igc_nrx_rings; i++) {
		igc_rx_ring_hw_init(igc, &igc->igc_rx_rings[i]);
	}

	/*
	 * As we always set LPE (large packet enable) in the receive control
	 * register, we must go through and explicitly update the maximum frame
	 * size.
	 */
	igc_write32(igc, IGC_RLPML, igc->igc_max_frame);

	/*
	 * Explicitly enable IPv4 and TCP checksums. We leave PCSD set to zero
	 * for the moment as we're not enabling RSS, which is what would be
	 * required to get that. After this is where we would set up the VMDq
	 * mode and RSS if we supported multiple RX rings.
	 */
	rxcsum = IGC_RXCSUM_IPOFL | IGC_RXCSUM_TUOFL;
	igc_write32(igc, IGC_RXCSUM, rxcsum);

	/*
	 * Enable the receive unit finally
	 */
	igc_write32(igc, IGC_RCTL, rctl);

	/*
	 * Only after the receive unit is initialized can we actually set up the
	 * ring head and tail pointers.
	 */
	for (uint32_t i = 0; i < igc->igc_nrx_rings; i++) {
		igc_write32(igc, IGC_RDH(igc->igc_rx_rings[i].irr_idx), 0);
		igc_write32(igc, IGC_RDT(igc->igc_rx_rings[i].irr_idx),
		    igc->igc_rx_ndesc - 1);
	}
}

static inline uint32_t
igc_next_desc(uint32_t cur, uint32_t count, uint32_t size)
{
	uint32_t out;

	if (cur + count < size) {
		out = cur + count;
	} else {
		out = cur + count - size;
	}

	return (out);
}

static inline uint32_t
igc_prev_desc(uint32_t cur, uint32_t count, uint32_t size)
{
	uint32_t out;

	if (cur >= count) {
		out = cur - count;
	} else {
		out = cur - count + size;
	}

	return (out);
}


static mblk_t *
igc_rx_copy(igc_rx_ring_t *ring, uint32_t idx, uint32_t len)
{
	const igc_rx_buffer_t *buf = ring->irr_work_list[idx];
	mblk_t *mp;

	IGC_DMA_SYNC(&buf->irb_dma, DDI_DMA_SYNC_FORKERNEL);
	mp = allocb(len + IGC_RX_BUF_IP_ALIGN, 0);
	if (mp == NULL) {
		ring->irr_stat.irs_copy_nomem.value.ui64++;
		return (NULL);
	}

	mp->b_rptr += IGC_RX_BUF_IP_ALIGN;
	bcopy(buf->irb_dma.idb_va + IGC_RX_BUF_IP_ALIGN, mp->b_rptr, len);
	mp->b_wptr = mp->b_rptr + len;
	ring->irr_stat.irs_ncopy.value.ui64++;
	return (mp);
}

static mblk_t *
igc_rx_bind(igc_rx_ring_t *ring, uint32_t idx, uint32_t len)
{
	igc_rx_buffer_t *buf = ring->irr_work_list[idx];
	igc_rx_buffer_t *sub;

	ASSERT(MUTEX_HELD(&ring->irr_lock));

	/*
	 * If there are no free buffers, we can't bind. Try to grab this now so
	 * we can minimize free list contention.
	 */
	mutex_enter(&ring->irr_free_lock);
	if (ring->irr_nfree == 0) {
		ring->irr_stat.irs_bind_nobuf.value.ui64++;
		mutex_exit(&ring->irr_free_lock);
		return (NULL);
	}
	ring->irr_nfree--;
	sub = ring->irr_free_list[ring->irr_nfree];
	mutex_exit(&ring->irr_free_lock);

	/*
	 * Check if we have an mblk_t here. If not, we'll need to allocate one
	 * again. If that fails, we'll fail this and fall back to copy, though
	 * the odds of that working are small.
	 */
	if (buf->irb_mp == NULL) {
		caddr_t mblk_va = buf->irb_dma.idb_va + IGC_RX_BUF_IP_ALIGN;
		size_t mblk_len = buf->irb_dma.idb_size - IGC_RX_BUF_IP_ALIGN;
		buf->irb_mp = desballoc((uchar_t *)mblk_va, mblk_len, 0,
		    &buf->irb_free_rtn);
		if (buf->irb_mp == NULL) {
			ring->irr_stat.irs_bind_nomp.value.ui64++;
			mutex_enter(&ring->irr_free_lock);
			ring->irr_free_list[ring->irr_nfree] = sub;
			ring->irr_nfree++;
			mutex_exit(&ring->irr_free_lock);
			return (NULL);
		}
	}
	buf->irb_mp->b_wptr = buf->irb_mp->b_rptr + len;
	IGC_DMA_SYNC(&buf->irb_dma, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * Swap an entry on the free list to replace this on the work list.
	 */
	ring->irr_work_list[idx] = sub;
	ring->irr_stat.irs_nbind.value.ui64++;

	/*
	 * Update the buffer to make sure that we indicate it's been loaned for
	 * future recycling.
	 */
	buf->irb_loaned = true;

	return (buf->irb_mp);
}

/*
 * Go through the status bits defined in hardware to see if we can set checksum
 * information.
 */
static void
igc_rx_hcksum(igc_rx_ring_t *ring, mblk_t *mp, uint32_t status)
{
	uint32_t cksum = 0;
	const uint32_t l4_valid = IGC_RXD_STAT_TCPCS | IGC_RXD_STAT_UDPCS;
	const uint32_t l4_invalid = IGC_RXDEXT_STATERR_L4E;

	if ((status & IGC_RXD_STAT_IXSM) != 0) {
		ring->irr_stat.irs_ixsm.value.ui64++;
		return;
	}

	if ((status & l4_invalid) != 0) {
		ring->irr_stat.irs_l4cksum_err.value.ui64++;
	} else if ((status & l4_valid) != 0) {
		cksum |= HCK_FULLCKSUM_OK;
	}

	if ((status & IGC_RXDEXT_STATERR_IPE) != 0) {
		ring->irr_stat.irs_l3cksum_err.value.ui64++;
	} else if ((status & IGC_RXD_STAT_IPCS) != 0) {
		cksum |= HCK_IPV4_HDRCKSUM_OK;
	}

	if (cksum != 0) {
		ring->irr_stat.irs_hcksum_hit.value.ui64++;
		mac_hcksum_set(mp, 0, 0, 0, 0, cksum);
	} else {
		ring->irr_stat.irs_hcksum_miss.value.ui64++;
	}
}

mblk_t *
igc_ring_rx(igc_rx_ring_t *ring, int poll_bytes)
{
	union igc_adv_rx_desc *cur_desc;
	uint32_t cur_status, cur_head;
	uint64_t rx_bytes = 0, rx_frames = 0;
	igc_t *igc = ring->irr_igc;
	mblk_t *mp_head = NULL, **mp_tail = NULL;

	ASSERT(MUTEX_HELD(&ring->irr_lock));
	IGC_DMA_SYNC(&ring->irr_desc_dma, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * Set up the invariants that we will maintain for the loop and then set
	 * up our mblk queue.
	 */
	cur_head = ring->irr_next;
	cur_desc = &ring->irr_ring[cur_head];
	cur_status = LE_32(cur_desc->wb.upper.status_error);
	mp_head = NULL;
	mp_tail = &mp_head;

	while ((cur_status & IGC_RXD_STAT_DD) != 0) {
		uint16_t cur_length = 0;
		mblk_t *mp;

		/*
		 * Check that we have no errors on this packet. This packet
		 * should also have EOP set because we only use a single
		 * descriptor today. We primarily just check for the RXE error.
		 * Most other error types were dropped in the extended format.
		 */
		if ((cur_status & IGC_RXDEXT_STATERR_RXE) != 0 ||
		    (cur_status & IGC_RXD_STAT_EOP) == 0) {
			ring->irr_stat.irs_desc_error.value.ui64++;
			goto discard;
		}


		/*
		 * We don't bump rx_frames here, because we do that at the end,
		 * even if we've discarded frames so we can know to write the
		 * tail register.
		 */
		cur_length = LE_16(cur_desc->wb.upper.length);
		rx_bytes += cur_length;

		mp = NULL;
		if (cur_length > igc->igc_rx_bind_thresh) {
			mp = igc_rx_bind(ring, cur_head, cur_length);
		}

		if (mp == NULL) {
			mp = igc_rx_copy(ring, cur_head, cur_length);
		}

		if (mp != NULL) {
			igc_rx_hcksum(ring, mp, cur_status);
			*mp_tail = mp;
			mp_tail = &mp->b_next;
		}

discard:
		/*
		 * Prepare the frame for use again. Note, we can't assume that
		 * the memory in the buffer is valid.
		 */
		igc_rx_ring_desc_write(ring, cur_head);

		/*
		 * Go through and update the values that our loop is using now.
		 */
		cur_head = igc_next_desc(cur_head, 1, igc->igc_rx_ndesc);
		cur_desc = &ring->irr_ring[cur_head];
		cur_status = LE_32(cur_desc->wb.upper.status_error);

		/*
		 * If we're polling, we need to check against the number of
		 * received bytes. If we're in interrupt mode, we have a maximum
		 * number of frames we're allowed to check.
		 */
		rx_frames++;
		if (poll_bytes != IGC_RX_POLL_INTR &&
		    (cur_length + rx_bytes) > poll_bytes) {
			break;
		} else if (poll_bytes == IGC_RX_POLL_INTR &&
		    rx_frames >= igc->igc_rx_intr_nframes) {
			break;
		}
	}

	/*
	 * Go ahead and re-arm the ring and update our stats along the way as
	 * long as we received at least one frame. Because we modified the
	 * descriptor ring as part of resetting frames, we must resync.
	 */
	if (rx_frames != 0) {
		uint32_t tail;

		IGC_DMA_SYNC(&ring->irr_desc_dma, DDI_DMA_SYNC_FORDEV);
		ring->irr_next = cur_head;
		tail = igc_prev_desc(cur_head, 1, igc->igc_rx_ndesc);
		igc_write32(igc, IGC_RDT(ring->irr_idx), tail);

		ring->irr_stat.irs_rbytes.value.ui64 += rx_bytes;
		ring->irr_stat.irs_ipackets.value.ui64 += rx_frames;
	}

#ifdef	DEBUG
	if (rx_frames == 0) {
		ASSERT0(rx_bytes);
	}
#endif

	return (mp_head);
}

/*
 * This is called from the stop entry point after the hardware has been reset.
 * After the hardware has been reset, the other possible consumer of rx buffers
 * are those that have been loaned up the stack. As such, we need to wait on
 * each free list until the number of free entries have gotten back to the
 * expected number.
 */
void
igc_rx_drain(igc_t *igc)
{
	for (uint32_t i = 0; i < igc->igc_nrx_rings; i++) {
		igc_rx_ring_t *ring = &igc->igc_rx_rings[i];

		mutex_enter(&ring->irr_free_lock);
		while (ring->irr_nfree < igc->igc_rx_nfree) {
			cv_wait(&ring->irr_free_cv, &ring->irr_free_lock);
		}
		mutex_exit(&ring->irr_free_lock);
	}
}

static void
igc_tx_bufs_free(igc_t *igc, igc_tx_ring_t *ring)
{
	for (uint32_t i = 0; i < igc->igc_tx_nbuf; i++) {
		igc_tx_buffer_t *buf = &ring->itr_arena[i];

		/*
		 * While we try to clean up the ring reasonably well, if for
		 * some reason we insert descriptors that the device doesn't
		 * like, then parts of the ring may not end up cleaned up. In
		 * such cases we'll need to free the mblk here ourselves and
		 * clean up any binding.
		 */
		if (buf->itb_bind) {
			buf->itb_bind = false;
			(void) ddi_dma_unbind_handle(buf->itb_bind_hdl);
		}
		freemsgchain(buf->itb_mp);
		igc_dma_free(&buf->itb_dma);
		if (buf->itb_bind_hdl != NULL) {
			ddi_dma_free_handle(&buf->itb_bind_hdl);
		}
	}
}

static bool
igc_tx_bufs_alloc(igc_t *igc, igc_tx_ring_t *ring)
{
	for (uint32_t i = 0; i < igc->igc_tx_nbuf; i++) {
		igc_tx_buffer_t *buf = &ring->itr_arena[i];
		ddi_dma_attr_t attr;
		int ret;

		igc_dma_data_attr(igc, &attr);
		if (!igc_dma_alloc(igc, &buf->itb_dma, &attr,
		    igc->igc_tx_buf_size)) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate TX "
			    "ring %u buffer %u", ring->itr_idx, i);
			return (false);
		}

		igc_dma_tx_attr(igc, &attr);
		if ((ret = ddi_dma_alloc_handle(igc->igc_dip, &attr,
		    DDI_DMA_DONTWAIT, NULL, &buf->itb_bind_hdl)) !=
		    DDI_SUCCESS) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate TX "
			    "ring %u TX DMA handle %u: %d", ring->itr_idx, i,
			    ret);
			return (false);
		}

		list_insert_tail(&ring->itr_free_list, buf);
	}

	return (true);
}

void
igc_tx_data_free(igc_t *igc)
{
	for (uint32_t i = 0; i < igc->igc_ntx_rings; i++) {
		igc_tx_ring_t *ring = &igc->igc_tx_rings[i];

		/*
		 * Empty the free list before we destroy the list to avoid
		 * blowing an assertion.
		 */
		while (list_remove_head(&ring->itr_free_list) != NULL)
			;

		if (ring->itr_arena != NULL) {
			igc_tx_bufs_free(igc, ring);
			kmem_free(ring->itr_arena, sizeof (igc_tx_buffer_t) *
			    igc->igc_tx_nbuf);
			ring->itr_arena = NULL;
		}

		list_destroy(&ring->itr_free_list);

		if (ring->itr_work_list != NULL) {
			kmem_free(ring->itr_work_list, igc->igc_tx_ndesc *
			    sizeof (igc_tx_buffer_t *));
			ring->itr_work_list = NULL;
		}

		if (ring->itr_ring != NULL) {
			igc_dma_free(&ring->itr_desc_dma);
			ring->itr_ring = NULL;
			ring->itr_ring_head = 0;
			ring->itr_ring_tail = 0;
			ring->itr_ring_free = 0;
		}
	}
}

bool
igc_tx_data_alloc(igc_t *igc)
{
	for (uint32_t i = 0; i < igc->igc_ntx_rings; i++) {
		igc_tx_ring_t *ring = &igc->igc_tx_rings[i];
		ddi_dma_attr_t desc_attr;
		size_t desc_len;

		igc_dma_desc_attr(igc, &desc_attr);
		desc_len = sizeof (union igc_adv_tx_desc) *
		    igc->igc_tx_ndesc;
		if (!igc_dma_alloc(igc, &ring->itr_desc_dma, &desc_attr,
		    desc_len)) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate "
			    "TX descriptor ring %u", i);
			goto cleanup;
		}
		ring->itr_ring = (void *)ring->itr_desc_dma.idb_va;

		ring->itr_work_list = kmem_zalloc(sizeof (igc_tx_buffer_t *) *
		    igc->igc_tx_ndesc, KM_NOSLEEP);
		if (ring->itr_work_list == NULL) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate "
			    "TX descriptor ring %u tx work list", i);
			goto cleanup;
		}

		list_create(&ring->itr_free_list, sizeof (igc_tx_buffer_t),
		    offsetof(igc_tx_buffer_t, itb_node));

		ring->itr_arena = kmem_zalloc(sizeof (igc_tx_buffer_t) *
		    igc->igc_tx_nbuf, KM_NOSLEEP);
		if (ring->itr_arena == NULL) {
			dev_err(igc->igc_dip, CE_WARN, "!failed to allocate "
			    "TX descriptor ring %u tx buf arena", i);
			goto cleanup;
		}

		if (!igc_tx_bufs_alloc(igc, ring)) {
			goto cleanup;
		}
	}

	return (true);

cleanup:
	igc_tx_data_free(igc);
	return (false);
}

static void
igc_tx_ring_hw_init(igc_t *igc, igc_tx_ring_t *ring)
{
	uint32_t val, high, low;
	const ddi_dma_cookie_t *desc;

	/*
	 * Program the ring's address.
	 */
	desc = ddi_dma_cookie_one(ring->itr_desc_dma.idb_hdl);
	high = (uint32_t)(desc->dmac_laddress >> 32);
	low = (uint32_t)desc->dmac_laddress;
	igc_write32(igc, IGC_TDBAH(ring->itr_idx), high);
	igc_write32(igc, IGC_TDBAL(ring->itr_idx), low);

	/*
	 * Program the ring length.
	 */
	val = igc->igc_tx_ndesc * sizeof (union igc_adv_tx_desc);
	igc_write32(igc, IGC_TDLEN(ring->itr_idx), val);

	/*
	 * Initialize the head and tail pointers that are in use. We can do this
	 * for TX unlike RX because we don't want the device to transmit
	 * anything.
	 */
	igc_write32(igc, IGC_TDH(ring->itr_idx), 0);
	igc_write32(igc, IGC_TDT(ring->itr_idx), 0);
	ring->itr_ring_head = 0;
	ring->itr_ring_tail = 0;
	ring->itr_ring_free = igc->igc_tx_ndesc;

	/*
	 * Ensure that a tx queue is disabled prior to taking any action. We do
	 * a subsequent read just in case relaxed ordering is enabled. We are
	 * required to set the various thresholds for when prefetch should
	 * occur, how many valid descriptors it waits before prefetch, and then
	 * what the write back granularity is. Picking these numbers is a bit
	 * weird.
	 *
	 * igb historically didn't modify these values. e1000g varied based on
	 * the hardware type and has done any number of different things here.
	 * The generic datasheet recommendation in the I210 is to set WTHRESH to
	 * 1 and leave everything else at zero. Drivers in other systems vary
	 * their settings.
	 *
	 * Right now we end up basically just following the datasheet and also
	 * rely on the ITR that we set. This can probably be improved upon at
	 * some point.
	 */
	igc_write32(igc, IGC_TXDCTL(0), 0);
	(void) igc_read32(igc, IGC_STATUS);
	val = 0;
	val = IGC_TXDCTL_SET_PTHRESH(val, 0);
	val = IGC_TXDCTL_SET_HTHRESH(val, 0);
	val = IGC_TXDCTL_SET_WTHRESH(val, 1);
	val |= IGC_TXDCTL_QUEUE_ENABLE;
	igc_write32(igc, IGC_TXDCTL(0), val);
}

void
igc_tx_hw_init(igc_t *igc)
{
	uint32_t val;

	for (uint32_t i = 0; i < igc->igc_ntx_rings; i++) {
		igc_tx_ring_hw_init(igc, &igc->igc_tx_rings[i]);
	}

	val = igc_read32(igc, IGC_TCTL);
	val &= ~IGC_TCTL_CT;
	val |= IGC_TCTL_PSP | IGC_TCTL_RTLC | IGC_TCTL_EN |
	    (IGC_COLLISION_THRESHOLD << IGC_CT_SHIFT);
	igc_write32(igc, IGC_TCTL, val);
}

static void
igc_tx_buf_reset(igc_tx_buffer_t *buf)
{
	buf->itb_mp = NULL;
	buf->itb_len = 0;
	buf->itb_last_desc = 0;
	buf->itb_first = false;
	if (buf->itb_bind) {
		(void) ddi_dma_unbind_handle(buf->itb_bind_hdl);
	}
	buf->itb_bind = false;
}

/*
 * When we are recycling packets, we need to sync the ring and then walk from
 * what we last processed up to what is in the tail or the first entry that is
 * not done. It is not clear that the I225 hardware has the separate write back
 * feature that igb does, so instead we have to look for the packet being noted
 * as done in the descriptor.
 */
void
igc_tx_recycle(igc_t *igc, igc_tx_ring_t *ring)
{
	uint32_t head, tail, ndesc = 0;
	list_t to_free;
	mblk_t *mp = NULL;
	bool notify = false;

	/*
	 * Snapshot the current head and tail before we do more processing. The
	 * driver bumps the tail when transmitting and bumps the head only here,
	 * so we know that anything in the region of [head, tail) is safe for us
	 * to touch (if the hardware is done) while anything in the region of
	 * [tail, head) is not.
	 */
	mutex_enter(&ring->itr_lock);
	if (ring->itr_recycle) {
		mutex_exit(&ring->itr_lock);
		return;
	}
	ring->itr_recycle = true;
	head = ring->itr_ring_head;
	tail = ring->itr_ring_tail;
	mutex_exit(&ring->itr_lock);

	list_create(&to_free, sizeof (igc_tx_buffer_t),
	    offsetof(igc_tx_buffer_t, itb_node));

	IGC_DMA_SYNC(&ring->itr_desc_dma, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * We need to walk the transmit descriptors to see what we can free.
	 * Here is where we need to deal with the wrinkle the theory statement
	 * discusses (see 'TX Data Path Design' in igc.c). We look at the head
	 * of the ring and see what item has the tail that we expect to be done
	 * and use that to determine if we are done with the entire packet. If
	 * we're done with the entire packet, then we walk the rest of the
	 * descriptors and will proceed.
	 */
	while (head != tail) {
		uint32_t status, last_desc, next_desc;
		igc_tx_buffer_t *check_buf = ring->itr_work_list[head];

		ASSERT3P(check_buf, !=, NULL);
		ASSERT3U(check_buf->itb_first, ==, true);

		last_desc = check_buf->itb_last_desc;
		status = LE_32(ring->itr_ring[last_desc].wb.status);
		if ((status & IGC_TXD_STAT_DD) == 0) {
			break;
		}

		/*
		 * We need to clean up this packet. This involves walking each
		 * descriptor, resetting it, finding each tx buffer, and mblk,
		 * and cleaning that up. A descriptor may or may not have a tx
		 * buffer associated with it.
		 */
		next_desc = igc_next_desc(last_desc, 1, igc->igc_tx_ndesc);
		for (uint32_t desc = head; desc != next_desc;
		    desc = igc_next_desc(desc, 1, igc->igc_tx_ndesc)) {
			igc_tx_buffer_t *buf;
			bzero(&ring->itr_ring[desc],
			    sizeof (union igc_adv_tx_desc));
			ndesc++;
			buf = ring->itr_work_list[desc];
			if (buf == NULL)
				continue;
			ring->itr_work_list[desc] = NULL;

			if (buf->itb_mp != NULL) {
				buf->itb_mp->b_next = mp;
				mp = buf->itb_mp;
			}
			igc_tx_buf_reset(buf);
			list_insert_tail(&to_free, buf);
		}

		head = next_desc;
	}

	mutex_enter(&ring->itr_lock);
	ring->itr_ring_head = head;
	ring->itr_ring_free += ndesc;
	list_move_tail(&ring->itr_free_list, &to_free);
	if (ring->itr_mac_blocked && ring->itr_ring_free >
	    igc->igc_tx_notify_thresh) {
		ring->itr_mac_blocked = false;
		notify = true;
	}
	ring->itr_recycle = false;
	mutex_exit(&ring->itr_lock);

	if (notify) {
		mac_tx_ring_update(igc->igc_mac_hdl, ring->itr_rh);
	}

	freemsgchain(mp);
	list_destroy(&to_free);
}

static igc_tx_buffer_t *
igc_tx_buffer_alloc(igc_tx_ring_t *ring)
{
	igc_tx_buffer_t *buf;
	mutex_enter(&ring->itr_lock);
	buf = list_remove_head(&ring->itr_free_list);
	if (buf == NULL) {
		ring->itr_stat.its_no_tx_bufs.value.ui64++;
	}
	mutex_exit(&ring->itr_lock);

	return (buf);
}

/*
 * Utilize a new tx buffer to perform a DMA binding for this mblk.
 */
static bool
igc_tx_ring_bind(igc_tx_ring_t *ring, mblk_t *mp, igc_tx_state_t *tx)
{
	size_t len = MBLKL(mp);
	igc_tx_buffer_t *buf;
	int ret;
	uint_t ncookie;

	buf = igc_tx_buffer_alloc(ring);
	if (buf == NULL) {
		return (false);
	}

	ret = ddi_dma_addr_bind_handle(buf->itb_bind_hdl, NULL,
	    (void *)mp->b_rptr, len, DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL, NULL, &ncookie);
	if (ret != DDI_DMA_MAPPED) {
		/*
		 * Binding failed. Give this buffer back.
		 */
		ring->itr_stat.its_tx_bind_fail.value.ui64++;
		mutex_enter(&ring->itr_lock);
		list_insert_tail(&ring->itr_free_list, buf);
		mutex_exit(&ring->itr_lock);
		return (false);
	}

	/*
	 * Now that this is successful, we append it to the list and update our
	 * tracking structure. We don't do this earlier so we can keep using the
	 * extent buffer for copying as that's the fallback path.
	 */
	buf->itb_len = len;
	buf->itb_bind = true;
	tx->itx_ndescs += ncookie;
	tx->itx_buf_rem = 0;
	tx->itx_cur_buf = buf;
	list_insert_tail(&tx->itx_bufs, tx->itx_cur_buf);
	ring->itr_stat.its_tx_bind.value.ui64++;
	return (true);
}

/*
 * Copy the current mblk into a series of one or more tx buffers depending on
 * what's available.
 */
static bool
igc_tx_ring_copy(igc_tx_ring_t *ring, mblk_t *mp, igc_tx_state_t *tx)
{
	size_t len = MBLKL(mp);
	size_t off = 0;

	while (len > 0) {
		const void *src;
		void *dest;
		size_t to_copy;

		/*
		 * If the current buffer is used for binding, then we must get a
		 * new one. If it is used for copying, we can keep going until
		 * it is full.
		 */
		if (tx->itx_cur_buf != NULL && (tx->itx_cur_buf->itb_bind ||
		    tx->itx_buf_rem == 0)) {
			tx->itx_cur_buf = NULL;
			tx->itx_buf_rem = 0;
		}

		if (tx->itx_cur_buf == NULL) {
			tx->itx_cur_buf = igc_tx_buffer_alloc(ring);
			if (tx->itx_cur_buf == NULL) {
				return (false);
			}
			list_insert_tail(&tx->itx_bufs, tx->itx_cur_buf);
			tx->itx_buf_rem = tx->itx_cur_buf->itb_dma.idb_size;
			/*
			 * Each DMA buffer used for TX only requires a single
			 * cookie. So note that descriptor requirement here and
			 * flag this tx buffer as being used for copying.
			 */
			tx->itx_ndescs++;
			tx->itx_cur_buf->itb_bind = false;
		}

		to_copy = MIN(len, tx->itx_buf_rem);
		src = mp->b_rptr + off;
		dest = tx->itx_cur_buf->itb_dma.idb_va +
		    tx->itx_cur_buf->itb_len;
		bcopy(src, dest, to_copy);

		tx->itx_buf_rem -= to_copy;
		tx->itx_cur_buf->itb_len += to_copy;
		len -= to_copy;
		off += to_copy;
	}

	ring->itr_stat.its_tx_copy.value.ui64++;
	return (true);
}

/*
 * We only need to load a context descriptor if what we're loading has changed.
 * This checks if it has and if so, updates the fields that have changed. Note,
 * a packet that doesn't require offloads won't end up taking us through this
 * path.
 */
static bool
igc_tx_ring_context_changed(igc_tx_ring_t *ring, igc_tx_state_t *tx)
{
	bool change = false;
	igc_tx_context_data_t *data = &ring->itr_tx_ctx;

	if (data->itc_l2hlen != tx->itx_meoi.meoi_l2hlen) {
		change = true;
		data->itc_l2hlen = tx->itx_meoi.meoi_l2hlen;
	}

	if (data->itc_l3hlen != tx->itx_meoi.meoi_l3hlen) {
		change = true;
		data->itc_l3hlen = tx->itx_meoi.meoi_l3hlen;
	}

	if (data->itc_l3proto != tx->itx_meoi.meoi_l3proto) {
		change = true;
		data->itc_l3proto = tx->itx_meoi.meoi_l3proto;
	}

	if (data->itc_l4proto != tx->itx_meoi.meoi_l4proto) {
		change = true;
		data->itc_l4proto = tx->itx_meoi.meoi_l4proto;
	}

	if (data->itc_l4hlen != tx->itx_meoi.meoi_l4hlen) {
		change = true;
		data->itc_l4hlen = tx->itx_meoi.meoi_l4hlen;
	}

	if (data->itc_mss != tx->itx_mss) {
		change = true;
		data->itc_mss = tx->itx_mss;
	}

	if (data->itc_cksum != tx->itx_cksum) {
		change = true;
		data->itc_cksum = tx->itx_cksum;
	}

	if (data->itc_lso != tx->itx_lso) {
		change = true;
		data->itc_lso = tx->itx_lso;
	}

	return (change);
}

/*
 * Fill out common descriptor information. First and last descriptor information
 * is handled after this.
 */
static void
igc_tx_ring_write_buf_descs(igc_t *igc, igc_tx_ring_t *ring,
    igc_tx_buffer_t *buf)
{
	ddi_dma_handle_t hdl = buf->itb_bind ? buf->itb_bind_hdl :
	    buf->itb_dma.idb_hdl;
	uint_t nc = ddi_dma_ncookies(hdl);
	size_t rem_len = buf->itb_len;

	ASSERT(MUTEX_HELD(&ring->itr_lock));
	ASSERT3U(rem_len, !=, 0);

	for (uint_t i = 0; i < nc; i++, ring->itr_ring_tail =
	    igc_next_desc(ring->itr_ring_tail, 1, igc->igc_tx_ndesc)) {
		const ddi_dma_cookie_t *c = ddi_dma_cookie_get(hdl, i);
		union igc_adv_tx_desc *desc;
		uint32_t type = IGC_ADVTXD_DTYP_DATA | IGC_ADVTXD_DCMD_DEXT |
		    IGC_ADVTXD_DCMD_IFCS;
		uint32_t desc_len = MIN(rem_len, c->dmac_size);

		/* Quick sanity check on max data descriptor */
		ASSERT3U(desc_len, <, 0x10000);
		ASSERT3U(desc_len, >, 0x0);
		type |= desc_len;
		rem_len -= desc_len;
		desc = &ring->itr_ring[ring->itr_ring_tail];
		desc->read.buffer_addr = LE_64(c->dmac_laddress);
		desc->read.cmd_type_len = LE_32(type);
		desc->read.olinfo_status = LE_32(0);

		/*
		 * Save the transmit buffer in the first descriptor entry that
		 * we use for this.
		 */
		if (i == 0) {
			ring->itr_work_list[ring->itr_ring_tail] = buf;
		}
	}
}

/*
 * We have created our chain of tx buffers that have been copied and bound. Now
 * insert them into place and insert a context descriptor if it will be
 * required. Unlike igb we don't save the old context descriptor to try to reuse
 * it and instead just always set it.
 */
static bool
igc_tx_ring_write_descs(igc_t *igc, igc_tx_ring_t *ring, mblk_t *mp,
    igc_tx_state_t *tx)
{
	bool do_ctx = false;
	igc_tx_buffer_t *buf;
	uint32_t ctx_desc, first_desc, last_desc, flags, status;

	/*
	 * If either checksumming or LSO is set, we may need a context
	 * descriptor. We assume we will and then if not will adjust that.
	 */
	if (tx->itx_cksum != 0 || tx->itx_lso != 0) {
		do_ctx = true;
		tx->itx_ndescs++;
	}

	mutex_enter(&ring->itr_lock);
	if (tx->itx_ndescs + igc->igc_tx_gap > ring->itr_ring_free) {
		/*
		 * Attempt to recycle descriptors before we give up.
		 */
		mutex_exit(&ring->itr_lock);
		igc_tx_recycle(igc, ring);
		mutex_enter(&ring->itr_lock);
		if (tx->itx_ndescs + igc->igc_tx_gap > ring->itr_ring_free) {
			mutex_exit(&ring->itr_lock);
			return (false);
		}
	}

	/*
	 * Now see if the context descriptor has changed, if required. If not,
	 * then we can reduce the number of descriptors required. We want to do
	 * this after we've checked for descriptors because this will mutate the
	 * next tx descriptor we have to load.
	 */
	if (do_ctx && !igc_tx_ring_context_changed(ring, tx)) {
		do_ctx = false;
		tx->itx_ndescs--;
	}

	ring->itr_ring_free -= tx->itx_ndescs;
	ctx_desc = ring->itr_ring_tail;
	if (do_ctx) {
		struct igc_adv_tx_context_desc *ctx;
		uint32_t len = tx->itx_meoi.meoi_l3hlen |
		    (tx->itx_meoi.meoi_l2hlen << IGC_ADVTXD_MACLEN_SHIFT);
		uint32_t tucmd = IGC_ADVTXD_DCMD_DEXT | IGC_ADVTXD_DTYP_CTXT;
		uint32_t l4idx = 0;

		if ((tx->itx_lso & HW_LSO) != 0 ||
		    (tx->itx_cksum & HCK_IPV4_HDRCKSUM) != 0) {
			if (tx->itx_meoi.meoi_l3proto == ETHERTYPE_IP) {
				tucmd |= IGC_ADVTXD_TUCMD_IPV4;
			} else {
				ASSERT3U(tx->itx_meoi.meoi_l3proto, ==,
				    ETHERTYPE_IPV6);
				tucmd |= IGC_ADVTXD_TUCMD_IPV6;
			}
		}

		if ((tx->itx_lso & HW_LSO) != 0 ||
		    (tx->itx_cksum & HCK_PARTIALCKSUM) != 0) {
			if (tx->itx_meoi.meoi_l4proto == IPPROTO_TCP) {
				tucmd |= IGC_ADVTXD_TUCMD_L4T_TCP;
			} else if (tx->itx_meoi.meoi_l4proto == IPPROTO_UDP) {
				tucmd |= IGC_ADVTXD_TUCMD_L4T_UDP;
			}
		}

		/*
		 * The L4LEN and MSS fields are only required if we're
		 * performing TSO. The index is always zero regardless because
		 * the I225 only has one context per queue.
		 */
		if ((tx->itx_lso & HW_LSO) != 0) {
			l4idx |= tx->itx_meoi.meoi_l4hlen <<
			    IGC_ADVTXD_L4LEN_SHIFT;
			l4idx |= tx->itx_mss << IGC_ADVTXD_MSS_SHIFT;
		}

		ctx = (void *)&ring->itr_ring[ctx_desc];
		ctx->vlan_macip_lens = LE_32(len);
		ctx->launch_time = 0;
		ctx->type_tucmd_mlhl = LE_32(tucmd);
		ctx->mss_l4len_idx = LE_32(l4idx);
		ring->itr_ring_tail = igc_next_desc(ring->itr_ring_tail, 1,
		    igc->igc_tx_ndesc);
		DTRACE_PROBE4(igc__context__desc, igc_t *, igc, igc_tx_ring_t *,
		    ring, igc_tx_state_t *, tx,
		    struct igc_adv_tx_context_desc *, ctx);
	}

	first_desc = ring->itr_ring_tail;

	while ((buf = list_remove_head(&tx->itx_bufs)) != NULL) {
		igc_tx_ring_write_buf_descs(igc, ring, buf);
	}

	/*
	 * The last descriptor must have end of packet set and is the entry that
	 * we ask for status on. That is, we don't actually ask for the status
	 * of each transmit buffer, only the final one so we can more easily
	 * collect everything including the context descriptor if present.
	 */
	last_desc = igc_prev_desc(ring->itr_ring_tail, 1, igc->igc_tx_ndesc);
	flags = IGC_ADVTXD_DCMD_EOP | IGC_ADVTXD_DCMD_RS;
	ring->itr_ring[last_desc].read.cmd_type_len |= LE_32(flags);

	/*
	 * We must now go back and set settings on the first data descriptor to
	 * indicate what checksumming and offload features we require. Note, we
	 * keep the IDX field as zero because there is only one context field
	 * per queue in the I225.
	 *
	 * We also save the mblk_t on the first tx buffer in the set which
	 * should always be saved with the first descriptor we use, which may
	 * include the context descriptor. Because this descriptor tracks when
	 * the entire packet is sent and we won't collect it until we're done
	 * with the entire packet, it's okay to leave this on the start.
	 */
	flags = 0;
	status = 0;
	if ((tx->itx_cksum & HCK_IPV4_HDRCKSUM) != 0) {
		status |= IGC_TXD_POPTS_IXSM << 8;
	}

	if ((tx->itx_cksum & HCK_PARTIALCKSUM) != 0) {
		status |= IGC_TXD_POPTS_TXSM << 8;
	}

	if ((tx->itx_lso & HW_LSO) != 0) {
		size_t payload = tx->itx_meoi.meoi_len -
		    tx->itx_meoi.meoi_l2hlen - tx->itx_meoi.meoi_l3hlen -
		    tx->itx_meoi.meoi_l4hlen;
		flags |= IGC_ADVTXD_DCMD_TSE;
		status |= payload << IGC_ADVTXD_PAYLEN_SHIFT;
	} else {
		status |= tx->itx_meoi.meoi_len << IGC_ADVTXD_PAYLEN_SHIFT;
	}

	ring->itr_ring[first_desc].read.cmd_type_len |= LE_32(flags);
	ring->itr_ring[first_desc].read.olinfo_status |= LE_32(status);
	ring->itr_work_list[first_desc]->itb_mp = mp;
	ring->itr_work_list[first_desc]->itb_first = true;
	ring->itr_work_list[first_desc]->itb_last_desc = last_desc;

	/*
	 * If we have a context descriptor, we must adjust the first work list
	 * item to point to the context descriptor. See 'TX Data Path Design' in
	 * the theory statemenet for more information.
	 */
	if (do_ctx) {
		ring->itr_work_list[ctx_desc] = ring->itr_work_list[first_desc];
		ring->itr_work_list[first_desc] = NULL;
	}

	ring->itr_stat.its_obytes.value.ui64 += tx->itx_meoi.meoi_len;
	ring->itr_stat.its_opackets.value.ui64++;

	IGC_DMA_SYNC(&ring->itr_desc_dma, DDI_DMA_SYNC_FORDEV);
	igc_write32(igc, IGC_TDT(ring->itr_idx), ring->itr_ring_tail);
	mutex_exit(&ring->itr_lock);
	return (true);
}

static bool
igc_meoi_checks(mblk_t *mp, igc_tx_state_t *tx)
{
	/*
	 * Inability to parse all the way through L4 is not a concern unless
	 * requested offloads require it.
	 */
	(void) mac_ether_offload_info(mp, &tx->itx_meoi);

	const mac_ether_offload_info_t *meoi = &tx->itx_meoi;
	if ((tx->itx_cksum & HCK_IPV4_HDRCKSUM) != 0) {
		if ((meoi->meoi_flags & MEOI_L3INFO_SET) == 0 ||
		    meoi->meoi_l3proto != ETHERTYPE_IP) {
			return (false);
		}
	}
	if ((tx->itx_cksum & HCK_PARTIALCKSUM) != 0) {
		if ((meoi->meoi_flags & MEOI_L4INFO_SET) == 0) {
			return (false);
		}
	}
	if ((tx->itx_lso & HW_LSO) != 0) {
		if ((tx->itx_cksum & HCK_PARTIALCKSUM) == 0) {
			return (false);
		}
		if (meoi->meoi_l3proto == ETHERTYPE_IP &&
		    (tx->itx_cksum & HCK_IPV4_HDRCKSUM) == 0) {
			return (false);
		}
	}
	return (true);
}

mblk_t *
igc_ring_tx(void *arg, mblk_t *mp)
{
	igc_tx_ring_t *ring = arg;
	igc_t *igc = ring->itr_igc;
	igc_tx_state_t tx = { 0 };

	ASSERT3P(mp->b_next, ==, NULL);

	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &tx.itx_cksum);
	mac_lso_get(mp, &tx.itx_mss, &tx.itx_lso);

	/*
	 * Attempt to parse headers and confirm that they are adequate for any
	 * requested offloads.
	 */
	if (!igc_meoi_checks(mp, &tx)) {
		freemsg(mp);
		ring->itr_stat.its_bad_meo.value.ui64++;
		return (NULL);
	}

	/*
	 * Note, we don't really care that the following check of the number of
	 * free descriptors may race with other threads due to a lack of the
	 * lock.
	 */
	if (ring->itr_ring_free < igc->igc_tx_recycle_thresh) {
		igc_tx_recycle(igc, ring);
	}

	mutex_enter(&ring->itr_lock);
	if (ring->itr_ring_free < igc->igc_tx_notify_thresh) {
		ring->itr_stat.its_ring_full.value.ui64++;
		ring->itr_mac_blocked = true;
		mutex_exit(&ring->itr_lock);
		return (mp);
	}
	mutex_exit(&ring->itr_lock);

	/*
	 * If we end up some day supporting lso and it was requested, then we
	 * need to check that the header and the payoad are all in one
	 * contiguous block. If they're not then we'll need to force a copy into
	 * the descriptor for the headers.
	 */

	/*
	 * This list tracks the various tx buffers that we've allocated and will
	 * use.
	 */
	list_create(&tx.itx_bufs, sizeof (igc_tx_buffer_t),
	    offsetof(igc_tx_buffer_t, itb_node));

	for (mblk_t *cur_mp = mp; cur_mp != NULL; cur_mp = cur_mp->b_cont) {
		size_t len = MBLKL(cur_mp);

		if (len == 0) {
			continue;
		}

		if (len > igc->igc_tx_bind_thresh &&
		    igc_tx_ring_bind(ring, cur_mp, &tx)) {
			continue;
		}

		if (!igc_tx_ring_copy(ring, cur_mp, &tx))
			goto tx_failure;
	}

	if (!igc_tx_ring_write_descs(igc, ring, mp, &tx)) {
		goto tx_failure;
	}

	list_destroy(&tx.itx_bufs);
	return (NULL);

tx_failure:
	/*
	 * We are out of descriptors. Clean up and give the mblk back to MAC.
	 */
	for (igc_tx_buffer_t *buf = list_head(&tx.itx_bufs); buf != NULL;
	    buf = list_next(&tx.itx_bufs, buf)) {
		igc_tx_buf_reset(buf);
	}

	mutex_enter(&ring->itr_lock);
	list_move_tail(&ring->itr_free_list, &tx.itx_bufs);
	ring->itr_mac_blocked = true;
	mutex_exit(&ring->itr_lock);
	list_destroy(&tx.itx_bufs);

	return (mp);
}
