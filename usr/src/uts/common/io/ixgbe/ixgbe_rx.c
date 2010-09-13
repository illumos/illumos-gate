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
 * Copyright(c) 2007-2010 Intel Corporation. All rights reserved.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "ixgbe_sw.h"

/* function prototypes */
static mblk_t *ixgbe_rx_bind(ixgbe_rx_data_t *, uint32_t, uint32_t);
static mblk_t *ixgbe_rx_copy(ixgbe_rx_data_t *, uint32_t, uint32_t);
static void ixgbe_rx_assoc_hcksum(mblk_t *, uint32_t);
static mblk_t *ixgbe_lro_bind(ixgbe_rx_data_t *, uint32_t, uint32_t, uint32_t);
static mblk_t *ixgbe_lro_copy(ixgbe_rx_data_t *, uint32_t, uint32_t, uint32_t);
static int ixgbe_lro_get_start(ixgbe_rx_data_t *, uint32_t);
static uint32_t ixgbe_lro_get_first(ixgbe_rx_data_t *, uint32_t);

#ifndef IXGBE_DEBUG
#pragma inline(ixgbe_rx_assoc_hcksum)
#pragma inline(ixgbe_lro_get_start)
#pragma inline(ixgbe_lro_get_first)
#endif

/*
 * ixgbe_rx_recycle - The call-back function to reclaim rx buffer.
 *
 * This function is called when an mp is freed by the user thru
 * freeb call (Only for mp constructed through desballoc call).
 * It returns back the freed buffer to the free list.
 */
void
ixgbe_rx_recycle(caddr_t arg)
{
	ixgbe_t *ixgbe;
	ixgbe_rx_ring_t *rx_ring;
	ixgbe_rx_data_t	*rx_data;
	rx_control_block_t *recycle_rcb;
	uint32_t free_index;
	uint32_t ref_cnt;

	recycle_rcb = (rx_control_block_t *)(uintptr_t)arg;
	rx_data = recycle_rcb->rx_data;
	rx_ring = rx_data->rx_ring;
	ixgbe = rx_ring->ixgbe;

	if (recycle_rcb->ref_cnt == 0) {
		/*
		 * This case only happens when rx buffers are being freed
		 * in ixgbe_stop() and freemsg() is called.
		 */
		return;
	}

	ASSERT(recycle_rcb->mp == NULL);

	/*
	 * Using the recycled data buffer to generate a new mblk
	 */
	recycle_rcb->mp = desballoc((unsigned char *)
	    recycle_rcb->rx_buf.address,
	    recycle_rcb->rx_buf.size,
	    0, &recycle_rcb->free_rtn);

	/*
	 * Put the recycled rx control block into free list
	 */
	mutex_enter(&rx_data->recycle_lock);

	free_index = rx_data->rcb_tail;
	ASSERT(rx_data->free_list[free_index] == NULL);

	rx_data->free_list[free_index] = recycle_rcb;
	rx_data->rcb_tail = NEXT_INDEX(free_index, 1, rx_data->free_list_size);

	mutex_exit(&rx_data->recycle_lock);

	/*
	 * The atomic operation on the number of the available rx control
	 * blocks in the free list is used to make the recycling mutual
	 * exclusive with the receiving.
	 */
	atomic_inc_32(&rx_data->rcb_free);
	ASSERT(rx_data->rcb_free <= rx_data->free_list_size);

	/*
	 * Considering the case that the interface is unplumbed
	 * and there are still some buffers held by the upper layer.
	 * When the buffer is returned back, we need to free it.
	 */
	ref_cnt = atomic_dec_32_nv(&recycle_rcb->ref_cnt);
	if (ref_cnt == 0) {
		if (recycle_rcb->mp != NULL) {
			freemsg(recycle_rcb->mp);
			recycle_rcb->mp = NULL;
		}

		ixgbe_free_dma_buffer(&recycle_rcb->rx_buf);

		mutex_enter(&ixgbe->rx_pending_lock);
		atomic_dec_32(&rx_data->rcb_pending);
		atomic_dec_32(&ixgbe->rcb_pending);

		/*
		 * When there is not any buffer belonging to this rx_data
		 * held by the upper layer, the rx_data can be freed.
		 */
		if ((rx_data->flag & IXGBE_RX_STOPPED) &&
		    (rx_data->rcb_pending == 0))
			ixgbe_free_rx_ring_data(rx_data);

		mutex_exit(&ixgbe->rx_pending_lock);
	}
}

/*
 * ixgbe_rx_copy - Use copy to process the received packet.
 *
 * This function will use bcopy to process the packet
 * and send the copied packet upstream.
 */
static mblk_t *
ixgbe_rx_copy(ixgbe_rx_data_t *rx_data, uint32_t index, uint32_t pkt_len)
{
	ixgbe_t *ixgbe;
	rx_control_block_t *current_rcb;
	mblk_t *mp;

	ixgbe = rx_data->rx_ring->ixgbe;
	current_rcb = rx_data->work_list[index];

	DMA_SYNC(&current_rcb->rx_buf, DDI_DMA_SYNC_FORKERNEL);

	if (ixgbe_check_dma_handle(current_rcb->rx_buf.dma_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ixgbe->ixgbe_state, IXGBE_ERROR);
		return (NULL);
	}

	/*
	 * Allocate buffer to receive this packet
	 */
	mp = allocb(pkt_len + IPHDR_ALIGN_ROOM, 0);
	if (mp == NULL) {
		ixgbe_log(ixgbe, "ixgbe_rx_copy: allocate buffer failed");
		return (NULL);
	}

	/*
	 * Copy the data received into the new cluster
	 */
	mp->b_rptr += IPHDR_ALIGN_ROOM;
	bcopy(current_rcb->rx_buf.address, mp->b_rptr, pkt_len);
	mp->b_wptr = mp->b_rptr + pkt_len;

	return (mp);
}

/*
 * ixgbe_rx_bind - Use existing DMA buffer to build mblk for receiving.
 *
 * This function will use pre-bound DMA buffer to receive the packet
 * and build mblk that will be sent upstream.
 */
static mblk_t *
ixgbe_rx_bind(ixgbe_rx_data_t *rx_data, uint32_t index, uint32_t pkt_len)
{
	rx_control_block_t *current_rcb;
	rx_control_block_t *free_rcb;
	uint32_t free_index;
	mblk_t *mp;
	ixgbe_t	*ixgbe = rx_data->rx_ring->ixgbe;

	/*
	 * If the free list is empty, we cannot proceed to send
	 * the current DMA buffer upstream. We'll have to return
	 * and use bcopy to process the packet.
	 */
	if (ixgbe_atomic_reserve(&rx_data->rcb_free, 1) < 0)
		return (NULL);

	current_rcb = rx_data->work_list[index];
	/*
	 * If the mp of the rx control block is NULL, try to do
	 * desballoc again.
	 */
	if (current_rcb->mp == NULL) {
		current_rcb->mp = desballoc((unsigned char *)
		    current_rcb->rx_buf.address,
		    current_rcb->rx_buf.size,
		    0, &current_rcb->free_rtn);
		/*
		 * If it is failed to built a mblk using the current
		 * DMA buffer, we have to return and use bcopy to
		 * process the packet.
		 */
		if (current_rcb->mp == NULL) {
			atomic_inc_32(&rx_data->rcb_free);
			return (NULL);
		}
	}
	/*
	 * Sync up the data received
	 */
	DMA_SYNC(&current_rcb->rx_buf, DDI_DMA_SYNC_FORKERNEL);

	if (ixgbe_check_dma_handle(current_rcb->rx_buf.dma_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		atomic_inc_32(&rx_data->rcb_free);
		atomic_or_32(&ixgbe->ixgbe_state, IXGBE_ERROR);
		return (NULL);
	}

	mp = current_rcb->mp;
	current_rcb->mp = NULL;
	atomic_inc_32(&current_rcb->ref_cnt);

	mp->b_wptr = mp->b_rptr + pkt_len;
	mp->b_next = mp->b_cont = NULL;

	/*
	 * Strip off one free rx control block from the free list
	 */
	free_index = rx_data->rcb_head;
	free_rcb = rx_data->free_list[free_index];
	ASSERT(free_rcb != NULL);
	rx_data->free_list[free_index] = NULL;
	rx_data->rcb_head = NEXT_INDEX(free_index, 1, rx_data->free_list_size);

	/*
	 * Put the rx control block to the work list
	 */
	rx_data->work_list[index] = free_rcb;

	return (mp);
}

/*
 * ixgbe_lro_bind - Use existing DMA buffer to build LRO mblk for receiving.
 *
 * This function will use pre-bound DMA buffers to receive the packet
 * and build LRO mblk that will be sent upstream.
 */
static mblk_t *
ixgbe_lro_bind(ixgbe_rx_data_t *rx_data, uint32_t lro_start,
    uint32_t lro_num, uint32_t pkt_len)
{
	rx_control_block_t *current_rcb;
	union ixgbe_adv_rx_desc *current_rbd;
	rx_control_block_t *free_rcb;
	uint32_t free_index;
	int lro_next;
	uint32_t last_pkt_len;
	uint32_t i;
	mblk_t *mp;
	mblk_t *mblk_head;
	mblk_t **mblk_tail;
	ixgbe_t	*ixgbe = rx_data->rx_ring->ixgbe;

	/*
	 * If the free list is empty, we cannot proceed to send
	 * the current DMA buffer upstream. We'll have to return
	 * and use bcopy to process the packet.
	 */
	if (ixgbe_atomic_reserve(&rx_data->rcb_free, lro_num) < 0)
		return (NULL);
	current_rcb = rx_data->work_list[lro_start];

	/*
	 * If any one of the rx data blocks can not support
	 * lro bind  operation,  We'll have to return and use
	 * bcopy to process the lro  packet.
	 */
	for (i = lro_num; i > 0; i--) {
		/*
		 * Sync up the data received
		 */
		DMA_SYNC(&current_rcb->rx_buf, DDI_DMA_SYNC_FORKERNEL);

		if (ixgbe_check_dma_handle(current_rcb->rx_buf.dma_handle) !=
		    DDI_FM_OK) {
			ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
			atomic_add_32(&rx_data->rcb_free, lro_num);
			atomic_or_32(&ixgbe->ixgbe_state, IXGBE_ERROR);
			return (NULL);
		}

		/*
		 * If the mp of the rx control block is NULL, try to do
		 * desballoc again.
		 */
		if (current_rcb->mp == NULL) {
			current_rcb->mp = desballoc((unsigned char *)
			    current_rcb->rx_buf.address,
			    current_rcb->rx_buf.size,
			    0, &current_rcb->free_rtn);
			/*
			 * If it is failed to built a mblk using the current
			 * DMA buffer, we have to return and use bcopy to
			 * process the packet.
			 */
			if (current_rcb->mp == NULL) {
				atomic_add_32(&rx_data->rcb_free, lro_num);
				return (NULL);
			}
		}
		if (current_rcb->lro_next != -1)
			lro_next = current_rcb->lro_next;
		current_rcb = rx_data->work_list[lro_next];
	}

	mblk_head = NULL;
	mblk_tail = &mblk_head;
	lro_next = lro_start;
	last_pkt_len = pkt_len - ixgbe->rx_buf_size * (lro_num - 1);
	current_rcb = rx_data->work_list[lro_next];
	current_rbd = &rx_data->rbd_ring[lro_next];
	while (lro_num --) {
		mp = current_rcb->mp;
		current_rcb->mp = NULL;
		atomic_inc_32(&current_rcb->ref_cnt);
		if (lro_num != 0)
			mp->b_wptr = mp->b_rptr + ixgbe->rx_buf_size;
		else
			mp->b_wptr = mp->b_rptr + last_pkt_len;
		mp->b_next = mp->b_cont = NULL;
		*mblk_tail = mp;
		mblk_tail = &mp->b_cont;

		/*
		 * Strip off one free rx control block from the free list
		 */
		free_index = rx_data->rcb_head;
		free_rcb = rx_data->free_list[free_index];
		ASSERT(free_rcb != NULL);
		rx_data->free_list[free_index] = NULL;
		rx_data->rcb_head = NEXT_INDEX(free_index, 1,
		    rx_data->free_list_size);

		/*
		 * Put the rx control block to the work list
		 */
		rx_data->work_list[lro_next] = free_rcb;
		lro_next = current_rcb->lro_next;
		current_rcb->lro_next = -1;
		current_rcb->lro_prev = -1;
		current_rcb->lro_pkt = B_FALSE;
		current_rbd->read.pkt_addr = free_rcb->rx_buf.dma_address;
		current_rbd->read.hdr_addr = 0;
		if (lro_next == -1)
			break;
		current_rcb = rx_data->work_list[lro_next];
		current_rbd = &rx_data->rbd_ring[lro_next];
	}
	return (mblk_head);
}

/*
 * ixgbe_lro_copy - Use copy to process the received LRO packet.
 *
 * This function will use bcopy to process the LRO  packet
 * and send the copied packet upstream.
 */
static mblk_t *
ixgbe_lro_copy(ixgbe_rx_data_t *rx_data, uint32_t lro_start,
    uint32_t lro_num, uint32_t pkt_len)
{
	ixgbe_t *ixgbe;
	rx_control_block_t *current_rcb;
	union ixgbe_adv_rx_desc *current_rbd;
	mblk_t *mp;
	uint32_t last_pkt_len;
	int lro_next;
	uint32_t i;

	ixgbe = rx_data->rx_ring->ixgbe;

	/*
	 * Allocate buffer to receive this LRO packet
	 */
	mp = allocb(pkt_len + IPHDR_ALIGN_ROOM, 0);
	if (mp == NULL) {
		ixgbe_log(ixgbe, "LRO copy MP alloc failed");
		return (NULL);
	}

	current_rcb = rx_data->work_list[lro_start];

	/*
	 * Sync up the LRO packet data received
	 */
	for (i = lro_num; i > 0; i--) {
		DMA_SYNC(&current_rcb->rx_buf, DDI_DMA_SYNC_FORKERNEL);

		if (ixgbe_check_dma_handle(current_rcb->rx_buf.dma_handle) !=
		    DDI_FM_OK) {
			ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
			atomic_or_32(&ixgbe->ixgbe_state, IXGBE_ERROR);
			return (NULL);
		}
		if (current_rcb->lro_next != -1)
			lro_next = current_rcb->lro_next;
		current_rcb = rx_data->work_list[lro_next];
	}
	lro_next = lro_start;
	current_rcb = rx_data->work_list[lro_next];
	current_rbd = &rx_data->rbd_ring[lro_next];
	last_pkt_len = pkt_len - ixgbe->rx_buf_size * (lro_num - 1);

	/*
	 * Copy the data received into the new cluster
	 */
	mp->b_rptr += IPHDR_ALIGN_ROOM;
	mp->b_wptr += IPHDR_ALIGN_ROOM;
	while (lro_num --) {
		if (lro_num != 0) {
			bcopy(current_rcb->rx_buf.address, mp->b_wptr,
			    ixgbe->rx_buf_size);
			mp->b_wptr += ixgbe->rx_buf_size;
		} else {
			bcopy(current_rcb->rx_buf.address, mp->b_wptr,
			    last_pkt_len);
			mp->b_wptr += last_pkt_len;
		}
		lro_next = current_rcb->lro_next;
		current_rcb->lro_next = -1;
		current_rcb->lro_prev = -1;
		current_rcb->lro_pkt = B_FALSE;
		current_rbd->read.pkt_addr = current_rcb->rx_buf.dma_address;
		current_rbd->read.hdr_addr = 0;
		if (lro_next == -1)
			break;
		current_rcb = rx_data->work_list[lro_next];
		current_rbd = &rx_data->rbd_ring[lro_next];
	}

	return (mp);
}

/*
 * ixgbe_lro_get_start - get the start rcb index in one LRO packet
 */
static int
ixgbe_lro_get_start(ixgbe_rx_data_t *rx_data, uint32_t rx_next)
{
	int lro_prev;
	int lro_start;
	uint32_t lro_num = 1;
	rx_control_block_t *prev_rcb;
	rx_control_block_t *current_rcb = rx_data->work_list[rx_next];
	lro_prev = current_rcb->lro_prev;

	while (lro_prev != -1) {
		lro_num ++;
		prev_rcb = rx_data->work_list[lro_prev];
		lro_start = lro_prev;
		lro_prev = prev_rcb->lro_prev;
	}
	rx_data->lro_num = lro_num;
	return (lro_start);
}

/*
 * ixgbe_lro_get_first - get the first LRO rcb index
 */
static uint32_t
ixgbe_lro_get_first(ixgbe_rx_data_t *rx_data, uint32_t rx_next)
{
	rx_control_block_t *current_rcb;
	uint32_t lro_first;
	lro_first = rx_data->lro_first;
	current_rcb = rx_data->work_list[lro_first];
	while ((!current_rcb->lro_pkt) && (lro_first != rx_next)) {
		lro_first =  NEXT_INDEX(lro_first, 1, rx_data->ring_size);
		current_rcb = rx_data->work_list[lro_first];
	}
	rx_data->lro_first = lro_first;
	return (lro_first);
}

/*
 * ixgbe_rx_assoc_hcksum - Check the rx hardware checksum status and associate
 * the hcksum flags.
 */
static void
ixgbe_rx_assoc_hcksum(mblk_t *mp, uint32_t status_error)
{
	uint32_t hcksum_flags = 0;

	/*
	 * Check TCP/UDP checksum
	 */
	if ((status_error & IXGBE_RXD_STAT_L4CS) &&
	    !(status_error & IXGBE_RXDADV_ERR_TCPE))
		hcksum_flags |= HCK_FULLCKSUM_OK;

	/*
	 * Check IP Checksum
	 */
	if ((status_error & IXGBE_RXD_STAT_IPCS) &&
	    !(status_error & IXGBE_RXDADV_ERR_IPE))
		hcksum_flags |= HCK_IPV4_HDRCKSUM_OK;

	if (hcksum_flags != 0) {
		mac_hcksum_set(mp, 0, 0, 0, 0, hcksum_flags);
	}
}

/*
 * ixgbe_ring_rx - Receive the data of one ring.
 *
 * This function goes throught h/w descriptor in one specified rx ring,
 * receives the data if the descriptor status shows the data is ready.
 * It returns a chain of mblks containing the received data, to be
 * passed up to mac_rx().
 */
mblk_t *
ixgbe_ring_rx(ixgbe_rx_ring_t *rx_ring, int poll_bytes)
{
	union ixgbe_adv_rx_desc *current_rbd;
	rx_control_block_t *current_rcb;
	mblk_t *mp;
	mblk_t *mblk_head;
	mblk_t **mblk_tail;
	uint32_t rx_next;
	uint32_t rx_tail;
	uint32_t pkt_len;
	uint32_t status_error;
	uint32_t pkt_num;
	uint32_t rsc_cnt;
	uint32_t lro_first;
	uint32_t lro_start;
	uint32_t lro_next;
	boolean_t lro_eop;
	uint32_t received_bytes;
	ixgbe_t *ixgbe = rx_ring->ixgbe;
	ixgbe_rx_data_t *rx_data;

	if ((ixgbe->ixgbe_state & IXGBE_SUSPENDED) ||
	    (ixgbe->ixgbe_state & IXGBE_ERROR) ||
	    (ixgbe->ixgbe_state & IXGBE_OVERTEMP) ||
	    !(ixgbe->ixgbe_state & IXGBE_STARTED))
		return (NULL);

	rx_data = rx_ring->rx_data;
	lro_eop = B_FALSE;
	mblk_head = NULL;
	mblk_tail = &mblk_head;

	/*
	 * Sync the receive descriptors before accepting the packets
	 */
	DMA_SYNC(&rx_data->rbd_area, DDI_DMA_SYNC_FORKERNEL);

	if (ixgbe_check_dma_handle(rx_data->rbd_area.dma_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ixgbe->ixgbe_state, IXGBE_ERROR);
		return (NULL);
	}

	/*
	 * Get the start point of rx bd ring which should be examined
	 * during this cycle.
	 */
	rx_next = rx_data->rbd_next;
	current_rbd = &rx_data->rbd_ring[rx_next];
	received_bytes = 0;
	pkt_num = 0;
	status_error = current_rbd->wb.upper.status_error;
	while (status_error & IXGBE_RXD_STAT_DD) {
		/*
		 * If adapter has found errors, but the error
		 * is hardware checksum error, this does not discard the
		 * packet: let upper layer compute the checksum;
		 * Otherwise discard the packet.
		 */
		if ((status_error & IXGBE_RXDADV_ERR_FRAME_ERR_MASK) ||
		    ((!ixgbe->lro_enable) &&
		    (!(status_error & IXGBE_RXD_STAT_EOP)))) {
			IXGBE_DEBUG_STAT(rx_ring->stat_frame_error);
			goto rx_discard;
		}

		IXGBE_DEBUG_STAT_COND(rx_ring->stat_cksum_error,
		    (status_error & IXGBE_RXDADV_ERR_TCPE) ||
		    (status_error & IXGBE_RXDADV_ERR_IPE));

		if (ixgbe->lro_enable) {
			rsc_cnt =  (current_rbd->wb.lower.lo_dword.data &
			    IXGBE_RXDADV_RSCCNT_MASK) >>
			    IXGBE_RXDADV_RSCCNT_SHIFT;
			if (rsc_cnt != 0) {
				if (status_error & IXGBE_RXD_STAT_EOP) {
					pkt_len = current_rbd->wb.upper.length;
					if (rx_data->work_list[rx_next]->
					    lro_prev != -1) {
						lro_start =
						    ixgbe_lro_get_start(rx_data,
						    rx_next);
						ixgbe->lro_pkt_count++;
						pkt_len +=
						    (rx_data->lro_num  - 1) *
						    ixgbe->rx_buf_size;
						lro_eop = B_TRUE;
					}
				} else {
					lro_next = (status_error &
					    IXGBE_RXDADV_NEXTP_MASK) >>
					    IXGBE_RXDADV_NEXTP_SHIFT;
					rx_data->work_list[lro_next]->lro_prev
					    = rx_next;
					rx_data->work_list[rx_next]->lro_next =
					    lro_next;
					rx_data->work_list[rx_next]->lro_pkt =
					    B_TRUE;
					goto rx_discard;
				}

			} else {
				pkt_len = current_rbd->wb.upper.length;
			}
		} else {
			pkt_len = current_rbd->wb.upper.length;
		}


		if ((poll_bytes != IXGBE_POLL_NULL) &&
		    ((received_bytes + pkt_len) > poll_bytes))
			break;

		received_bytes += pkt_len;
		mp = NULL;

		/*
		 * For packets with length more than the copy threshold,
		 * we'll first try to use the existing DMA buffer to build
		 * an mblk and send the mblk upstream.
		 *
		 * If the first method fails, or the packet length is less
		 * than the copy threshold, we'll allocate a new mblk and
		 * copy the packet data to the new mblk.
		 */
		if (lro_eop) {
			mp = ixgbe_lro_bind(rx_data, lro_start,
			    rx_data->lro_num, pkt_len);
			if (mp == NULL)
				mp = ixgbe_lro_copy(rx_data, lro_start,
				    rx_data->lro_num, pkt_len);
			lro_eop = B_FALSE;
			rx_data->lro_num = 0;

		} else {
			if (pkt_len > ixgbe->rx_copy_thresh)
				mp = ixgbe_rx_bind(rx_data, rx_next, pkt_len);

			if (mp == NULL)
				mp = ixgbe_rx_copy(rx_data, rx_next, pkt_len);
		}
		if (mp != NULL) {
			/*
			 * Check h/w checksum offload status
			 */
			if (ixgbe->rx_hcksum_enable)
				ixgbe_rx_assoc_hcksum(mp, status_error);

			*mblk_tail = mp;
			mblk_tail = &mp->b_next;
		}

rx_discard:
		/*
		 * Reset rx descriptor read bits
		 */
		current_rcb = rx_data->work_list[rx_next];
		if (ixgbe->lro_enable) {
			if (!current_rcb->lro_pkt) {
				current_rbd->read.pkt_addr =
				    current_rcb->rx_buf.dma_address;
				current_rbd->read.hdr_addr = 0;
			}
		} else {
			current_rbd->read.pkt_addr =
			    current_rcb->rx_buf.dma_address;
			current_rbd->read.hdr_addr = 0;
		}

		rx_next = NEXT_INDEX(rx_next, 1, rx_data->ring_size);

		/*
		 * The receive function is in interrupt context, so here
		 * rx_limit_per_intr is used to avoid doing receiving too long
		 * per interrupt.
		 */
		if (++pkt_num > ixgbe->rx_limit_per_intr) {
			IXGBE_DEBUG_STAT(rx_ring->stat_exceed_pkt);
			break;
		}

		current_rbd = &rx_data->rbd_ring[rx_next];
		status_error = current_rbd->wb.upper.status_error;
	}

	rx_ring->stat_rbytes += received_bytes;
	rx_ring->stat_ipackets += pkt_num;

	DMA_SYNC(&rx_data->rbd_area, DDI_DMA_SYNC_FORDEV);

	rx_data->rbd_next = rx_next;

	/*
	 * Update the h/w tail accordingly
	 */
	if (ixgbe->lro_enable) {
		lro_first = ixgbe_lro_get_first(rx_data, rx_next);
		rx_tail = PREV_INDEX(lro_first, 1, rx_data->ring_size);
	} else
		rx_tail = PREV_INDEX(rx_next, 1, rx_data->ring_size);

	IXGBE_WRITE_REG(&ixgbe->hw, IXGBE_RDT(rx_ring->hw_index), rx_tail);

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ixgbe->ixgbe_state, IXGBE_ERROR);
	}

	return (mblk_head);
}

mblk_t *
ixgbe_ring_rx_poll(void *arg, int n_bytes)
{
	ixgbe_rx_ring_t *rx_ring = (ixgbe_rx_ring_t *)arg;
	mblk_t *mp = NULL;

	ASSERT(n_bytes >= 0);

	if (n_bytes == 0)
		return (NULL);

	mutex_enter(&rx_ring->rx_lock);
	mp = ixgbe_ring_rx(rx_ring, n_bytes);
	mutex_exit(&rx_ring->rx_lock);

	return (mp);
}
