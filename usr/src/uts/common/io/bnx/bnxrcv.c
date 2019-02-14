/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnxrcv.h"


#define	BNX_RECV_INIT_FAIL_THRESH 1

#ifndef	NUM_RX_CHAIN
#error NUM_RX_CHAIN is not defined.
#else
/*
 * Range check NUM_RX_CHAIN.  Technically the LM controls this definition,
 * but it makes sense to use what the LM uses.
 */
#if NUM_RX_CHAIN < 0
#error Invalid NUM_RX_CHAIN definition.
#elif NUM_RX_CHAIN > 1
#warning NUM_RX_CHAIN is greater than 1.
#endif
#endif


static ddi_dma_attr_t bnx_rx_jmb_dma_attrib = {
	DMA_ATTR_V0,			/* dma_attr_version */
	0,				/* dma_attr_addr_lo */
	0xffffffffffffffff,		/* dma_attr_addr_hi */
	0x0ffffff,			/* dma_attr_count_max */
	BNX_DMA_ALIGNMENT,		/* dma_attr_align */
	0xffffffff,			/* dma_attr_burstsizes */
	1,				/* dma_attr_minxfer */
	0x00ffffff,			/* dma_attr_maxxfer */
	0xffffffff,			/* dma_attr_seg */
	BNX_RECV_MAX_FRAGS,		/* dma_attr_sgllen */
	BNX_MIN_BYTES_PER_FRAGMENT,	/* dma_attr_granular */
	0,				/* dma_attr_flags */
};

static int
bnx_rxbuffer_alloc(um_device_t *const umdevice, um_rxpacket_t *const umpacket)
{
	int rc;
	size_t pktsize;
	size_t reallen;
	uint_t dc_count;
	lm_packet_t *lmpacket;
	ddi_dma_cookie_t cookie;

	lmpacket = &(umpacket->lmpacket);

	rc = ddi_dma_alloc_handle(umdevice->os_param.dip,
	    &bnx_rx_jmb_dma_attrib, DDI_DMA_DONTWAIT,
	    (void *)0, &(umpacket->dma_handle));
	if (rc != DDI_SUCCESS) {
		return (-1);
	}

	/*
	 * The buffer size as set by the lower module is the actual buffer
	 * size plus room for a small, 16 byte inline rx buffer descriptor
	 * header plus an implied two byte TCP shift optimization.  We
	 * don't need to adjust the size at all.
	 */
	pktsize = lmpacket->u1.rx.buf_size;

	rc = ddi_dma_mem_alloc(umpacket->dma_handle, pktsize,
	    &bnxAccessAttribBUF, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
	    (void *)0, (caddr_t *)&lmpacket->u1.rx.mem_virt, &reallen,
	    &umpacket->dma_acc_handle);
	if (rc != DDI_SUCCESS) {
		goto error1;
	}

	/* Bind the message block buffer address to the handle. */
	rc = ddi_dma_addr_bind_handle(umpacket->dma_handle, NULL,
	    (caddr_t)lmpacket->u1.rx.mem_virt, pktsize,
	    DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL,
	    &cookie, &dc_count);
	if (rc != DDI_DMA_MAPPED) {
		goto error2;
	}

	lmpacket->u1.rx.mem_phy.as_u64 = cookie.dmac_laddress;

	return (0);

error2:
	ddi_dma_mem_free(&(umpacket->dma_acc_handle));

error1:
	ddi_dma_free_handle(&(umpacket->dma_handle));

	return (-1);
}

static void
bnx_rxbuffer_free(um_device_t * const umdevice, um_rxpacket_t * const umpacket)
{
	lm_packet_t *lmpacket;

	lmpacket = &(umpacket->lmpacket);

	lmpacket->u1.rx.mem_phy.as_u64 = 0;
	lmpacket->u1.rx.buf_size = 0;

	(void) ddi_dma_unbind_handle(umpacket->dma_handle);

	lmpacket->u1.rx.mem_virt = NULL;
	ddi_dma_mem_free(&umpacket->dma_acc_handle);

	ddi_dma_free_handle(&(umpacket->dma_handle));
}

static void
bnx_recv_ring_init(um_device_t * const umdevice, const unsigned int ringidx)
{
	s_list_t *srcq;
	s_list_t *dstq;
	lm_rx_chain_t *lmrxring;
	um_recv_qinfo *recvinfo;
	um_rxpacket_t *umpacket;

	recvinfo = &_RX_QINFO(umdevice, ringidx);

	recvinfo->processing = B_FALSE;

	lmrxring = &umdevice->lm_dev.rx_info.chain[ringidx];

	srcq = &(lmrxring->free_descq);

	dstq = &(recvinfo->buffq);

	s_list_init(dstq, NULL, NULL, 0);

	/* CONSTANTCONDITION */
	/*
	 * Put all available packet descriptors in our special wait queue.
	 * The wait queue is an area to store packet descriptors that do
	 * not yet have buffers associated with them.
	 */
	while (1) {
		umpacket = (um_rxpacket_t *)s_list_pop_head(srcq);
		if (umpacket == NULL) {
			break;
		}

		s_list_push_tail(dstq, &(umpacket->lmpacket.link));
	}

	dstq  = &(recvinfo->waitq);

	s_list_init(dstq, NULL, NULL, 0);
}

static void
bnx_recv_ring_fill(um_device_t * const umdevice, const unsigned int ringidx)
{
	s_list_t *srcq;
	s_list_t *dstq;
	um_rxpacket_t *umpacket;
	um_recv_qinfo *recvinfo;

	recvinfo = &(_RX_QINFO(umdevice, ringidx));

	srcq = &(recvinfo->buffq);

	dstq = &(umdevice->lm_dev.rx_info.chain[ringidx].free_descq);

	/* CONSTANTCONDITION */
	/* Populate as many of the packet descriptors as we can. */
	while (1) {
		umpacket = (um_rxpacket_t *)s_list_pop_head(srcq);
		if (umpacket == NULL) {
			break;
		}

		if (bnx_rxbuffer_alloc(umdevice, umpacket) != 0) {
			s_list_push_head(srcq, &umpacket->lmpacket.link);
			break;
		}

		s_list_push_tail(dstq, &umpacket->lmpacket.link);
	}
}

/*
 * NOTE!!!  This function assumes the rcv_mutex is already held.
 */
static void
bnx_recv_ring_recv(um_device_t *const umdevice, const unsigned int ringidx)
{
	mblk_t *head = NULL;
	mblk_t *tail = NULL;
	s_list_t *srcq;
	s_list_t *recvq;
	s_list_t *freeq;
	boolean_t dcopy;
	boolean_t lm_rcvq_empty;
	lm_packet_t *lmpacket;
	um_rxpacket_t *umpacket;
	um_recv_qinfo *recvinfo;

	recvinfo = &(_RX_QINFO(umdevice, ringidx));

	/*
	 * We can't hold the receive mutex across the receive function or
	 * deadlock results.  So that other threads know we are still doing
	 * business, toggle a flag they can look at.  If the flag says,
	 * we're processing, other threads should back off.
	 */
	recvinfo->processing = B_TRUE;

	srcq  = &(recvinfo->waitq);
	freeq = &(umdevice->lm_dev.rx_info.chain[ringidx].free_descq);

	recvq = &(umdevice->lm_dev.rx_info.chain[ringidx].active_descq);
	if (s_list_entry_cnt(recvq)) {
		lm_rcvq_empty = B_FALSE;
	} else {
		lm_rcvq_empty = B_TRUE;
	}

	/* CONSTANTCONDITION */
	/* Send the rx packets up. */
	while (1) {
		mblk_t *mp = NULL;
		unsigned int pktlen;
		int ofld_flags;

		umpacket = (um_rxpacket_t *)s_list_pop_head(srcq);
		if (umpacket == NULL) {
			break;
		}

		lmpacket = &(umpacket->lmpacket);

		if (lmpacket->status != LM_STATUS_SUCCESS) {
			s_list_push_tail(freeq, &(lmpacket->link));
			continue;
		}

		pktlen = lmpacket->size;

		/*
		 * FIXME -- Implement mm_flush_cache().
		 *
		 * The LM uses mm_flush_cache() to make sure the processor is
		 * working with current data.  The call to ddi_dma_sync should
		 * go there instead.  How mm_flush_cache() should be
		 * implemented depends on what test mode we are in.
		 *
		 * if (lmdevice->params.test_mode & TEST_MODE_VERIFY_RX_CRC) {
		 *	// The LM will need access to the complete rx buffer.
		 * } else {
		 *	// The LM only needs access to the 16 byte inline rx BD.
		 *	// Be sure in this case to ddi_dma_sync() as many
		 *	// fragments as necessary to get the full rx BD in
		 *	// host memory.
		 * }
		 */
		(void) ddi_dma_sync(umpacket->dma_handle, 0,
		    pktlen + L2RX_FRAME_HDR_LEN, DDI_DMA_SYNC_FORKERNEL);

		dcopy = B_FALSE;

		if (pktlen < umdevice->rx_copy_threshold) {
			lm_device_t *lmdevice;
			lmdevice = &(umdevice->lm_dev);

			if ((lmdevice->params.keep_vlan_tag == 0) &&
			    (lmpacket->u1.rx.flags &
			    LM_RX_FLAG_VALID_VLAN_TAG)) {

				/*
				 * The hardware stripped the VLAN tag
				 * we must now reinsert the tag.  This is
				 * done to be compatiable with older firmware
				 * who could not handle VLAN tags
				 */
				mp = allocb(pktlen + 6, BPRI_MED);
				if (mp != NULL) {
					uint8_t *dataptr;
					const uint16_t tpid = htons(0x8100);
					uint16_t vlan_tag;

					vlan_tag =
					    htons(lmpacket->u1.rx.vlan_tag);

					/*
					 * For analysis of the packet contents,
					 * we first need to advance
					 * the pointer beyond the inlined return
					 * buffer descriptor.
					 */
					dataptr = lmpacket->u1.rx.mem_virt +
					    L2RX_FRAME_HDR_LEN;

					/* TCP alignment optimization. */
					mp->b_rptr += 2;

					/*
					 * First copy the dest/source MAC
					 * addresses
					 */
					bcopy(dataptr, mp->b_rptr, 12);

					/* Second copy the VLAN tag */
					bcopy(&tpid, mp->b_rptr + 12, 2);
					bcopy(&vlan_tag, mp->b_rptr + 14, 2);

					/* Third copy the reset of the packet */
					dataptr = dataptr + 12;

					bcopy(dataptr, mp->b_rptr + 16,
					    pktlen - 12);
					mp->b_wptr = mp->b_rptr + pktlen + 4;

					dcopy = B_TRUE;

					goto sendup;
				}
			} else {
				/*  The hardware didn't strip the VLAN tag  */
				mp = allocb(pktlen + 2, BPRI_MED);
				if (mp != NULL) {
					uint8_t *dataptr;

					/*
					 * For analysis of the packet contents,
					 * we first need to advance
					 * the pointer beyond the inlined return
					 * buffer descriptor.
					 */
					dataptr = lmpacket->u1.rx.mem_virt +
					    L2RX_FRAME_HDR_LEN;

					/* TCP alignment optimization. */
					mp->b_rptr += 2;

					bcopy(dataptr, mp->b_rptr, pktlen);
					mp->b_wptr = mp->b_rptr + pktlen;

					dcopy = B_TRUE;

					goto sendup;
				}
			}

			umdevice->recv_discards++;

			s_list_push_tail(freeq, &(lmpacket->link));

			continue;
		}

		if (lm_rcvq_empty == B_TRUE && !(s_list_entry_cnt(srcq))) {
			/*
			 * If the hardware is out of receive buffers and we are
			 * on the last receive packet, we need to drop the
			 * packet.  We do this because we might not be able to
			 * allocate _any_ new receive buffers before the ISR
			 * completes.  If this happens, the driver will enter
			 * an infinite interrupt loop where the hardware is
			 * requesting rx buffers the driver cannot allocate.
			 * So that the system doesn't livelock, we leave one
			 * buffer perpetually available.  Note that we do this
			 * _after_ giving the double copy code a chance to
			 * claim the packet.
			 */

			/*
			 * FIXME -- Make sure to add one more to the rx packet
			 * descriptor count before allocating them.
			 */

			umdevice->recv_discards++;

			s_list_push_tail(freeq, &(lmpacket->link));

			continue;
		}

sendup:

		/*
		 * Check if the checksum was offloaded.
		 * If so, pass the result to stack.
		 */
		ofld_flags = 0;
		if ((umdevice->dev_var.enabled_oflds &
		    LM_OFFLOAD_RX_IP_CKSUM) &&
		    (lmpacket->u1.rx.flags & LM_RX_FLAG_IP_CKSUM_IS_GOOD)) {
			ofld_flags |= HCK_IPV4_HDRCKSUM_OK;
		}

		if (((umdevice->dev_var.enabled_oflds &
		    LM_OFFLOAD_RX_TCP_CKSUM) &&
		    (lmpacket->u1.rx.flags & LM_RX_FLAG_TCP_CKSUM_IS_GOOD)) ||
		    ((umdevice->dev_var.enabled_oflds &
		    LM_OFFLOAD_RX_UDP_CKSUM) &&
		    (lmpacket->u1.rx.flags & LM_RX_FLAG_UDP_CKSUM_IS_GOOD))) {
			ofld_flags |= HCK_FULLCKSUM_OK;
		}

		if (ofld_flags != 0) {
			mac_hcksum_set(mp, 0, 0, 0, 0, ofld_flags);
		}

		/*
		 * Push the packet descriptor onto one of the queues before we
		 * attempt to send the packet up.  If the send-up function
		 * hangs during driver unload, we want all our packet
		 * descriptors to be available for deallocation.
		 */
		if (dcopy == B_TRUE) {
			s_list_push_tail(freeq, &(lmpacket->link));
		}

		if (head == NULL) {
			head = mp;
			tail = mp;
		} else {
			tail->b_next = mp;
			tail = mp;
		}
		tail->b_next = NULL;
	}

	if (head) {
		mutex_exit(&umdevice->os_param.rcv_mutex);

		mac_rx(umdevice->os_param.macp,
		    umdevice->os_param.rx_resc_handle[ringidx], head);

		mutex_enter(&umdevice->os_param.rcv_mutex);
	}

	recvinfo->processing = B_FALSE;
}

static void
bnx_recv_ring_dump(um_device_t *const umdevice, const unsigned int ringidx)
{
	s_list_t *srcq;
	s_list_t *dstq;
	um_rxpacket_t *umpacket;

	srcq = &(_RX_QINFO(umdevice, ringidx).waitq);
	dstq = &(umdevice->lm_dev.rx_info.chain[ringidx].free_descq);

	/* CONSTANTCONDITION */
	/* Dump all the packets pending a send-up. */
	while (1) {
		umpacket = (um_rxpacket_t *)s_list_pop_head(srcq);
		if (umpacket == NULL) {
			break;
		}

		s_list_push_tail(dstq, &(umpacket->lmpacket.link));
	}
}

static void
bnx_recv_ring_free(um_device_t *const umdevice, const unsigned int ringidx)
{
	s_list_t *srcq;
	s_list_t *dstq;
	um_rxpacket_t *umpacket;

	srcq = &(umdevice->lm_dev.rx_info.chain[ringidx].free_descq);

	dstq = &(_RX_QINFO(umdevice, ringidx).buffq);

	/* CONSTANTCONDITION */
	/*
	 * Back out all the packets submitted to the "available for hardware
	 * use" queue.  Free the buffers associated with the descriptors as
	 * we go.
	 */
	while (1) {
		umpacket = (um_rxpacket_t *)s_list_pop_head(srcq);
		if (umpacket == NULL) {
			break;
		}

		bnx_rxbuffer_free(umdevice, umpacket);

		s_list_push_tail(dstq, &umpacket->lmpacket.link);
	}
}

static void
bnx_recv_ring_fini(um_device_t *const umdevice, const unsigned int ringidx)
{
	s_list_t *srcq;
	um_rxpacket_t *umpacket;
	um_recv_qinfo *recvinfo;

	recvinfo = &(_RX_QINFO(umdevice, ringidx));

	srcq = &(recvinfo->buffq);

	/* CONSTANTCONDITION */
	while (1) {
		umpacket = (um_rxpacket_t *)s_list_pop_head(srcq);
		if (umpacket == NULL) {
			break;
		}

		/*
		 * Intentionally throw the packet away.  The memory was
		 * allocated by the lower module and will be reclaimed when
		 * we do our final memory cleanup.
		 */
	}
}

int
bnx_rxpkts_init(um_device_t *const umdevice)
{
	int i;
	int alloccnt;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	alloccnt = 0;

	for (i = RX_CHAIN_IDX0; i < NUM_RX_CHAIN; i++) {
		int post_count = 0;

		bnx_recv_ring_init(umdevice, i);

		bnx_recv_ring_fill(umdevice, i);

		post_count =
		    s_list_entry_cnt(&lmdevice->rx_info.chain[i].free_descq);

		if (post_count != lmdevice->params.l2_rx_desc_cnt[i]) {
			cmn_err(CE_NOTE,
			    "!%s: %d rx buffers requested.  %d allocated.\n",
			    umdevice->dev_name,
			    umdevice->lm_dev.params.l2_rx_desc_cnt[i],
			    post_count);
		}

		alloccnt += post_count;
	}

	/* FIXME -- Set rxbuffer allocation failure threshold. */
	if (alloccnt < BNX_RECV_INIT_FAIL_THRESH) {
		cmn_err(CE_WARN,
		    "%s: Failed to allocate minimum number of RX buffers.\n",
		    umdevice->dev_name);

/* BEGIN CSTYLED */
#if BNX_RECV_INIT_FAIL_THRESH > 1
#warning Need to implement code to free previously allocated rx buffers in bnx_rxpkts_init error path.
#endif
/* END CSTYLED */

		return (-1);
	}

	return (0);
}

void
bnx_rxpkts_intr(um_device_t *const umdevice)
{
	int i;
	um_recv_qinfo * recvinfo;

	for (i = RX_CHAIN_IDX0; i < NUM_RX_CHAIN; i++) {
		recvinfo = &(_RX_QINFO(umdevice, i));

		if (recvinfo->processing == B_FALSE) {
			/* Send the packets up the stack. */
			bnx_recv_ring_recv(umdevice, i);
		}
	}
}

void
bnx_rxpkts_post(um_device_t *const umdevice)
{
	int i;
	um_recv_qinfo *recvinfo;

	for (i = RX_CHAIN_IDX0; i < NUM_RX_CHAIN; i++) {
		recvinfo = &(_RX_QINFO(umdevice, i));

		if (recvinfo->processing == B_FALSE) {
			/* Allocate new rx buffers. */
			bnx_recv_ring_fill(umdevice, i);

			/* Submit the rx buffers to the hardware. */
			(void) lm_post_buffers(&(umdevice->lm_dev), i, NULL);
		}
	}
}

void
bnx_rxpkts_recycle(um_device_t *const umdevice)
{
	int i;

	for (i = NUM_RX_CHAIN - 1; i >= RX_CHAIN_IDX0; i--) {
		bnx_recv_ring_dump(umdevice, i);

		lm_abort(&(umdevice->lm_dev), ABORT_OP_RX_CHAIN, i);
	}
}

void
bnx_rxpkts_fini(um_device_t *const umdevice)
{
	int i;

	for (i = NUM_RX_CHAIN - 1; i >= RX_CHAIN_IDX0; i--) {
		/* Dump shouldn't be necessary, but just to be safe... */
		bnx_recv_ring_dump(umdevice, i);

		/* Recycle shouldn't be necessary, but just to be safe... */
		lm_abort(&(umdevice->lm_dev), ABORT_OP_RX_CHAIN, i);

		bnx_recv_ring_free(umdevice, i);
		bnx_recv_ring_fini(umdevice, i);
	}
}
