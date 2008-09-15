/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2008 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

/*
 * **********************************************************************
 *									*
 * Module Name:								*
 *   e1000g_rx.c							*
 *									*
 * Abstract:								*
 *   This file contains some routines that take care of Receive		*
 *   interrupt and also for the received packets it sends up to		*
 *   upper layer.							*
 *   It tries to do a zero copy if free buffers are available in	*
 *   the pool.								*
 *									*
 * **********************************************************************
 */

#include "e1000g_sw.h"
#include "e1000g_debug.h"

static p_rx_sw_packet_t e1000g_get_buf(e1000g_rx_ring_t *rx_ring);
#pragma	inline(e1000g_get_buf)
static void e1000g_priv_devi_list_clean();

/*
 * e1000g_rxfree_func - the call-back function to reclaim rx buffer
 *
 * This function is called when an mp is freed by the user thru
 * freeb call (Only for mp constructed through desballoc call)
 * It returns back the freed buffer to the freelist
 */
void
e1000g_rxfree_func(p_rx_sw_packet_t packet)
{
	e1000g_rx_ring_t *rx_ring;

	rx_ring = (e1000g_rx_ring_t *)(uintptr_t)packet->rx_ring;

	/*
	 * Here the rx recycling processes different rx packets in different
	 * threads, so we protect it with RW_READER to ensure it won't block
	 * other rx recycling threads.
	 */
	rw_enter(&e1000g_rx_detach_lock, RW_READER);

	if (packet->flag == E1000G_RX_SW_FREE) {
		rw_exit(&e1000g_rx_detach_lock);
		return;
	}

	if (packet->flag == E1000G_RX_SW_STOP) {
		packet->flag = E1000G_RX_SW_FREE;
		rw_exit(&e1000g_rx_detach_lock);

		rw_enter(&e1000g_rx_detach_lock, RW_WRITER);
		rx_ring->pending_count--;
		e1000g_mblks_pending--;

		if (rx_ring->pending_count == 0) {
			while (rx_ring->pending_list != NULL) {
				packet = rx_ring->pending_list;
				rx_ring->pending_list =
				    rx_ring->pending_list->next;

				ASSERT(packet->mp == NULL);
				e1000g_free_rx_sw_packet(packet);
			}
		}

		/*
		 * If e1000g_force_detach is enabled, we need to clean up
		 * the idle priv_dip entries in the private dip list while
		 * e1000g_mblks_pending is zero.
		 */
		if (e1000g_force_detach && (e1000g_mblks_pending == 0))
			e1000g_priv_devi_list_clean();
		rw_exit(&e1000g_rx_detach_lock);
		return;
	}

	if (packet->flag == E1000G_RX_SW_DETACH) {
		packet->flag = E1000G_RX_SW_FREE;
		rw_exit(&e1000g_rx_detach_lock);

		ASSERT(packet->mp == NULL);
		e1000g_free_rx_sw_packet(packet);

		/*
		 * Here the e1000g_mblks_pending may be modified by different
		 * rx recycling threads simultaneously, so we need to protect
		 * it with RW_WRITER.
		 */
		rw_enter(&e1000g_rx_detach_lock, RW_WRITER);
		e1000g_mblks_pending--;

		/*
		 * If e1000g_force_detach is enabled, we need to clean up
		 * the idle priv_dip entries in the private dip list while
		 * e1000g_mblks_pending is zero.
		 */
		if (e1000g_force_detach && (e1000g_mblks_pending == 0))
			e1000g_priv_devi_list_clean();
		rw_exit(&e1000g_rx_detach_lock);
		return;
	}

	packet->flag = E1000G_RX_SW_FREE;

	if (packet->mp == NULL) {
		/*
		 * Allocate a mblk that binds to the data buffer
		 */
		packet->mp = desballoc((unsigned char *)
		    packet->rx_buf->address - E1000G_IPALIGNROOM,
		    packet->rx_buf->size + E1000G_IPALIGNROOM,
		    BPRI_MED, &packet->free_rtn);

		if (packet->mp != NULL) {
			packet->mp->b_rptr += E1000G_IPALIGNROOM;
			packet->mp->b_wptr += E1000G_IPALIGNROOM;
		} else {
			E1000G_STAT(rx_ring->stat_esballoc_fail);
		}
	}

	mutex_enter(&rx_ring->freelist_lock);
	QUEUE_PUSH_TAIL(&rx_ring->free_list, &packet->Link);
	rx_ring->avail_freepkt++;
	mutex_exit(&rx_ring->freelist_lock);

	rw_exit(&e1000g_rx_detach_lock);
}

/*
 * e1000g_priv_devi_list_clean - clean up e1000g_private_devi_list
 *
 * We will walk the e1000g_private_devi_list to free the entry marked
 * with the E1000G_PRIV_DEVI_DETACH flag.
 */
static void
e1000g_priv_devi_list_clean()
{
	private_devi_list_t *devi_node, *devi_del;

	if (e1000g_private_devi_list == NULL)
		return;

	devi_node = e1000g_private_devi_list;
	while ((devi_node != NULL) &&
	    (devi_node->flag == E1000G_PRIV_DEVI_DETACH)) {
		e1000g_private_devi_list = devi_node->next;
		kmem_free(devi_node->priv_dip,
		    sizeof (struct dev_info));
		kmem_free(devi_node,
		    sizeof (private_devi_list_t));
		devi_node = e1000g_private_devi_list;
	}
	if (e1000g_private_devi_list == NULL)
		return;
	while (devi_node->next != NULL) {
		if (devi_node->next->flag == E1000G_PRIV_DEVI_DETACH) {
			devi_del = devi_node->next;
			devi_node->next = devi_del->next;
			kmem_free(devi_del->priv_dip,
			    sizeof (struct dev_info));
			kmem_free(devi_del,
			    sizeof (private_devi_list_t));
		} else {
			devi_node = devi_node->next;
		}
	}
}

/*
 * e1000g_rx_setup - setup rx data structures
 *
 * This routine initializes all of the receive related
 * structures. This includes the receive descriptors, the
 * actual receive buffers, and the rx_sw_packet software
 * structures.
 */
void
e1000g_rx_setup(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	p_rx_sw_packet_t packet;
	struct e1000_rx_desc *descriptor;
	uint32_t buf_low;
	uint32_t buf_high;
	uint32_t reg_val;
	uint32_t rctl;
	uint32_t rxdctl;
	uint32_t ert;
	int i;
	int size;
	e1000g_rx_ring_t *rx_ring;

	hw = &Adapter->shared;
	rx_ring = Adapter->rx_ring;

	/*
	 * zero out all of the receive buffer descriptor memory
	 * assures any previous data or status is erased
	 */
	bzero(rx_ring->rbd_area,
	    sizeof (struct e1000_rx_desc) * Adapter->rx_desc_num);

	if (!Adapter->rx_buffer_setup) {
		/* Init the list of "Receive Buffer" */
		QUEUE_INIT_LIST(&rx_ring->recv_list);

		/* Init the list of "Free Receive Buffer" */
		QUEUE_INIT_LIST(&rx_ring->free_list);

		/*
		 * Setup Receive list and the Free list. Note that
		 * the both were allocated in one packet area.
		 */
		packet = rx_ring->packet_area;
		descriptor = rx_ring->rbd_first;

		for (i = 0; i < Adapter->rx_desc_num;
		    i++, packet = packet->next, descriptor++) {
			ASSERT(packet != NULL);
			ASSERT(descriptor != NULL);
			descriptor->buffer_addr =
			    packet->rx_buf->dma_address;

			/* Add this rx_sw_packet to the receive list */
			QUEUE_PUSH_TAIL(&rx_ring->recv_list,
			    &packet->Link);
		}

		for (i = 0; i < Adapter->rx_freelist_num;
		    i++, packet = packet->next) {
			ASSERT(packet != NULL);
			/* Add this rx_sw_packet to the free list */
			QUEUE_PUSH_TAIL(&rx_ring->free_list,
			    &packet->Link);
		}
		rx_ring->avail_freepkt = Adapter->rx_freelist_num;

		Adapter->rx_buffer_setup = B_TRUE;
	} else {
		/* Setup the initial pointer to the first rx descriptor */
		packet = (p_rx_sw_packet_t)
		    QUEUE_GET_HEAD(&rx_ring->recv_list);
		descriptor = rx_ring->rbd_first;

		for (i = 0; i < Adapter->rx_desc_num; i++) {
			ASSERT(packet != NULL);
			ASSERT(descriptor != NULL);
			descriptor->buffer_addr =
			    packet->rx_buf->dma_address;

			/* Get next rx_sw_packet */
			packet = (p_rx_sw_packet_t)
			    QUEUE_GET_NEXT(&rx_ring->recv_list, &packet->Link);
			descriptor++;
		}
	}

	E1000_WRITE_REG(&Adapter->shared, E1000_RDTR, Adapter->rx_intr_delay);
	E1000G_DEBUGLOG_1(Adapter, E1000G_INFO_LEVEL,
	    "E1000_RDTR: 0x%x\n", Adapter->rx_intr_delay);
	if (hw->mac.type >= e1000_82540) {
		E1000_WRITE_REG(&Adapter->shared, E1000_RADV,
		    Adapter->rx_intr_abs_delay);
		E1000G_DEBUGLOG_1(Adapter, E1000G_INFO_LEVEL,
		    "E1000_RADV: 0x%x\n", Adapter->rx_intr_abs_delay);
	}

	/*
	 * Setup our descriptor pointers
	 */
	rx_ring->rbd_next = rx_ring->rbd_first;

	size = Adapter->rx_desc_num * sizeof (struct e1000_rx_desc);
	E1000_WRITE_REG(hw, E1000_RDLEN(0), size);
	size = E1000_READ_REG(hw, E1000_RDLEN(0));

	/* To get lower order bits */
	buf_low = (uint32_t)rx_ring->rbd_dma_addr;
	/* To get the higher order bits */
	buf_high = (uint32_t)(rx_ring->rbd_dma_addr >> 32);

	E1000_WRITE_REG(hw, E1000_RDBAH(0), buf_high);
	E1000_WRITE_REG(hw, E1000_RDBAL(0), buf_low);

	/*
	 * Setup our HW Rx Head & Tail descriptor pointers
	 */
	E1000_WRITE_REG(hw, E1000_RDT(0),
	    (uint32_t)(rx_ring->rbd_last - rx_ring->rbd_first));
	E1000_WRITE_REG(hw, E1000_RDH(0), 0);

	/*
	 * Setup the Receive Control Register (RCTL), and ENABLE the
	 * receiver. The initial configuration is to: Enable the receiver,
	 * accept broadcasts, discard bad packets (and long packets),
	 * disable VLAN filter checking, set the receive descriptor
	 * minimum threshold size to 1/2, and the receive buffer size to
	 * 2k.
	 */
	rctl = E1000_RCTL_EN |		/* Enable Receive Unit */
	    E1000_RCTL_BAM |		/* Accept Broadcast Packets */
	    E1000_RCTL_LPE |		/* Large Packet Enable bit */
	    (hw->mac.mc_filter_type << E1000_RCTL_MO_SHIFT) |
	    E1000_RCTL_RDMTS_HALF |
	    E1000_RCTL_LBM_NO;		/* Loopback Mode = none */

	if (Adapter->strip_crc)
		rctl |= E1000_RCTL_SECRC;	/* Strip Ethernet CRC */

	if ((Adapter->max_frame_size > FRAME_SIZE_UPTO_2K) &&
	    (Adapter->max_frame_size <= FRAME_SIZE_UPTO_4K))
		rctl |= E1000_RCTL_SZ_4096 | E1000_RCTL_BSEX;
	else if ((Adapter->max_frame_size > FRAME_SIZE_UPTO_4K) &&
	    (Adapter->max_frame_size <= FRAME_SIZE_UPTO_8K))
		rctl |= E1000_RCTL_SZ_8192 | E1000_RCTL_BSEX;
	else if ((Adapter->max_frame_size > FRAME_SIZE_UPTO_8K) &&
	    (Adapter->max_frame_size <= FRAME_SIZE_UPTO_16K))
		rctl |= E1000_RCTL_SZ_16384 | E1000_RCTL_BSEX;
	else
		rctl |= E1000_RCTL_SZ_2048;

	if (e1000_tbi_sbp_enabled_82543(hw))
		rctl |= E1000_RCTL_SBP;

	/*
	 * Enable early receives on supported devices, only takes effect when
	 * packet size is equal or larger than the specified value (in 8 byte
	 * units), e.g. using jumbo frames when setting to E1000_ERT_2048
	 */
	if ((hw->mac.type == e1000_82573) ||
	    (hw->mac.type == e1000_82574) ||
	    (hw->mac.type == e1000_ich9lan) ||
	    (hw->mac.type == e1000_ich10lan)) {

		ert = E1000_ERT_2048;

		/*
		 * Special modification when ERT and
		 * jumbo frames are enabled
		 */
		if (Adapter->default_mtu > ETHERMTU) {
			rxdctl = E1000_READ_REG(hw, E1000_RXDCTL(0));
			E1000_WRITE_REG(hw, E1000_RXDCTL(0), rxdctl | 0x3);
			ert |= (1 << 13);
		}

		E1000_WRITE_REG(hw, E1000_ERT, ert);
	}

	reg_val =
	    E1000_RXCSUM_TUOFL |	/* TCP/UDP checksum offload Enable */
	    E1000_RXCSUM_IPOFL;		/* IP checksum offload Enable */

	E1000_WRITE_REG(hw, E1000_RXCSUM, reg_val);

	/*
	 * Workaround: Set bit 16 (IPv6_ExDIS) to disable the
	 * processing of received IPV6 extension headers
	 */
	if ((hw->mac.type == e1000_82571) || (hw->mac.type == e1000_82572)) {
		reg_val = E1000_READ_REG(hw, E1000_RFCTL);
		reg_val |= (E1000_RFCTL_IPV6_EX_DIS |
		    E1000_RFCTL_NEW_IPV6_EXT_DIS);
		E1000_WRITE_REG(hw, E1000_RFCTL, reg_val);
	}

	/* Write to enable the receive unit */
	E1000_WRITE_REG(hw, E1000_RCTL, rctl);
}

/*
 * e1000g_get_buf - get an rx sw packet from the free_list
 */
static p_rx_sw_packet_t
e1000g_get_buf(e1000g_rx_ring_t *rx_ring)
{
	p_rx_sw_packet_t packet;

	mutex_enter(&rx_ring->freelist_lock);
	packet = (p_rx_sw_packet_t)
	    QUEUE_POP_HEAD(&rx_ring->free_list);
	if (packet != NULL)
		rx_ring->avail_freepkt--;
	mutex_exit(&rx_ring->freelist_lock);

	return (packet);
}

/*
 * e1000g_receive - main receive routine
 *
 * This routine will process packets received in an interrupt
 */
mblk_t *
e1000g_receive(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	mblk_t *nmp;
	mblk_t *ret_mp;
	mblk_t *ret_nmp;
	struct e1000_rx_desc *current_desc;
	struct e1000_rx_desc *last_desc;
	p_rx_sw_packet_t packet;
	p_rx_sw_packet_t newpkt;
	uint16_t length;
	uint32_t pkt_count;
	uint32_t desc_count;
	boolean_t accept_frame;
	boolean_t end_of_packet;
	boolean_t need_copy;
	e1000g_rx_ring_t *rx_ring;
	dma_buffer_t *rx_buf;
	uint16_t cksumflags;

	ret_mp = NULL;
	ret_nmp = NULL;
	pkt_count = 0;
	desc_count = 0;
	cksumflags = 0;

	hw = &Adapter->shared;
	rx_ring = Adapter->rx_ring;

	/* Sync the Rx descriptor DMA buffers */
	(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
	    0, 0, DDI_DMA_SYNC_FORKERNEL);

	if (e1000g_check_dma_handle(rx_ring->rbd_dma_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		Adapter->chip_state = E1000G_ERROR;
	}

	current_desc = rx_ring->rbd_next;
	if (!(current_desc->status & E1000_RXD_STAT_DD)) {
		/*
		 * don't send anything up. just clear the RFD
		 */
		E1000G_DEBUG_STAT(rx_ring->stat_none);
		return (ret_mp);
	}

	/*
	 * Loop through the receive descriptors starting at the last known
	 * descriptor owned by the hardware that begins a packet.
	 */
	while ((current_desc->status & E1000_RXD_STAT_DD) &&
	    (pkt_count < Adapter->rx_limit_onintr)) {

		desc_count++;
		/*
		 * Now this can happen in Jumbo frame situation.
		 */
		if (current_desc->status & E1000_RXD_STAT_EOP) {
			/* packet has EOP set */
			end_of_packet = B_TRUE;
		} else {
			/*
			 * If this received buffer does not have the
			 * End-Of-Packet bit set, the received packet
			 * will consume multiple buffers. We won't send this
			 * packet upstack till we get all the related buffers.
			 */
			end_of_packet = B_FALSE;
		}

		/*
		 * Get a pointer to the actual receive buffer
		 * The mp->b_rptr is mapped to The CurrentDescriptor
		 * Buffer Address.
		 */
		packet =
		    (p_rx_sw_packet_t)QUEUE_GET_HEAD(&rx_ring->recv_list);
		ASSERT(packet != NULL);

		rx_buf = packet->rx_buf;

		length = current_desc->length;

#ifdef __sparc
		if (packet->dma_type == USE_DVMA)
			dvma_sync(rx_buf->dma_handle, 0,
			    DDI_DMA_SYNC_FORKERNEL);
		else
			(void) ddi_dma_sync(rx_buf->dma_handle,
			    E1000G_IPALIGNROOM, length,
			    DDI_DMA_SYNC_FORKERNEL);
#else
		(void) ddi_dma_sync(rx_buf->dma_handle,
		    E1000G_IPALIGNROOM, length,
		    DDI_DMA_SYNC_FORKERNEL);
#endif

		if (e1000g_check_dma_handle(
		    rx_buf->dma_handle) != DDI_FM_OK) {
			ddi_fm_service_impact(Adapter->dip,
			    DDI_SERVICE_DEGRADED);
			Adapter->chip_state = E1000G_ERROR;
		}

		accept_frame = (current_desc->errors == 0) ||
		    ((current_desc->errors &
		    (E1000_RXD_ERR_TCPE | E1000_RXD_ERR_IPE)) != 0);

		if (hw->mac.type == e1000_82543) {
			unsigned char last_byte;

			last_byte =
			    *((unsigned char *)rx_buf->address + length - 1);

			if (TBI_ACCEPT(hw,
			    current_desc->status, current_desc->errors,
			    current_desc->length, last_byte,
			    Adapter->min_frame_size, Adapter->max_frame_size)) {

				e1000_tbi_adjust_stats(Adapter,
				    length, hw->mac.addr);

				length--;
				accept_frame = B_TRUE;
			} else if (e1000_tbi_sbp_enabled_82543(hw) &&
			    (current_desc->errors == E1000_RXD_ERR_CE)) {
				accept_frame = B_TRUE;
			}
		}

		/*
		 * Indicate the packet to the NOS if it was good.
		 * Normally, hardware will discard bad packets for us.
		 * Check for the packet to be a valid Ethernet packet
		 */
		if (!accept_frame) {
			/*
			 * error in incoming packet, either the packet is not a
			 * ethernet size packet, or the packet has an error. In
			 * either case, the packet will simply be discarded.
			 */
			E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
			    "Process Receive Interrupts: Error in Packet\n");

			E1000G_STAT(rx_ring->stat_error);
			/*
			 * Returning here as we are done here. There is
			 * no point in waiting for while loop to elapse
			 * and the things which were done. More efficient
			 * and less error prone...
			 */
			goto rx_drop;
		}

		/*
		 * If the Ethernet CRC is not stripped by the hardware,
		 * we need to strip it before sending it up to the stack.
		 */
		if (end_of_packet && !Adapter->strip_crc) {
			if (length > ETHERFCSL) {
				length -= ETHERFCSL;
			} else {
				/*
				 * If the fragment is smaller than the CRC,
				 * drop this fragment, do the processing of
				 * the end of the packet.
				 */
				ASSERT(rx_ring->rx_mblk_tail != NULL);
				rx_ring->rx_mblk_tail->b_wptr -=
				    ETHERFCSL - length;
				rx_ring->rx_mblk_len -=
				    ETHERFCSL - length;

				QUEUE_POP_HEAD(&rx_ring->recv_list);

				goto rx_end_of_packet;
			}
		}

		need_copy = B_TRUE;

		if (length <= Adapter->rx_bcopy_thresh)
			goto rx_copy;

		/*
		 * Get the pre-constructed mblk that was associated
		 * to the receive data buffer.
		 */
		if (packet->mp == NULL) {
			packet->mp = desballoc((unsigned char *)
			    rx_buf->address - E1000G_IPALIGNROOM,
			    length + E1000G_IPALIGNROOM,
			    BPRI_MED, &packet->free_rtn);

			if (packet->mp != NULL) {
				packet->mp->b_rptr += E1000G_IPALIGNROOM;
				packet->mp->b_wptr += E1000G_IPALIGNROOM;
			} else {
				E1000G_STAT(rx_ring->stat_esballoc_fail);
			}
		}

		if (packet->mp != NULL) {
			/*
			 * We have two sets of buffer pool. One associated with
			 * the Rxdescriptors and other a freelist buffer pool.
			 * Each time we get a good packet, Try to get a buffer
			 * from the freelist pool using e1000g_get_buf. If we
			 * get free buffer, then replace the descriptor buffer
			 * address with the free buffer we just got, and pass
			 * the pre-constructed mblk upstack. (note no copying)
			 *
			 * If we failed to get a free buffer, then try to
			 * allocate a new buffer(mp) and copy the recv buffer
			 * content to our newly allocated buffer(mp). Don't
			 * disturb the desriptor buffer address. (note copying)
			 */
			newpkt = e1000g_get_buf(rx_ring);

			if (newpkt != NULL) {
				/*
				 * Get the mblk associated to the data,
				 * and strip it off the sw packet.
				 */
				nmp = packet->mp;
				packet->mp = NULL;
				packet->flag = E1000G_RX_SW_SENDUP;

				/*
				 * Now replace old buffer with the new
				 * one we got from free list
				 * Both the RxSwPacket as well as the
				 * Receive Buffer Descriptor will now
				 * point to this new packet.
				 */
				packet = newpkt;

				current_desc->buffer_addr =
				    newpkt->rx_buf->dma_address;

				need_copy = B_FALSE;
			} else {
				E1000G_DEBUG_STAT(rx_ring->stat_no_freepkt);
			}
		}

rx_copy:
		if (need_copy) {
			/*
			 * No buffers available on free list,
			 * bcopy the data from the buffer and
			 * keep the original buffer. Dont want to
			 * do this.. Yack but no other way
			 */
			if ((nmp = allocb(length + E1000G_IPALIGNROOM,
			    BPRI_MED)) == NULL) {
				/*
				 * The system has no buffers available
				 * to send up the incoming packet, hence
				 * the packet will have to be processed
				 * when there're more buffers available.
				 */
				E1000G_STAT(rx_ring->stat_allocb_fail);
				goto rx_drop;
			}
			nmp->b_rptr += E1000G_IPALIGNROOM;
			nmp->b_wptr += E1000G_IPALIGNROOM;
			/*
			 * The free list did not have any buffers
			 * available, so, the received packet will
			 * have to be copied into a mp and the original
			 * buffer will have to be retained for future
			 * packet reception.
			 */
			bcopy(rx_buf->address, nmp->b_wptr, length);
		}

		/*
		 * The rx_sw_packet MUST be popped off the
		 * RxSwPacketList before either a putnext or freemsg
		 * is done on the mp that has now been created by the
		 * desballoc. If not, it is possible that the free
		 * routine will get called from the interrupt context
		 * and try to put this packet on the free list
		 */
		(p_rx_sw_packet_t)QUEUE_POP_HEAD(&rx_ring->recv_list);

		ASSERT(nmp != NULL);
		nmp->b_wptr += length;

		if (rx_ring->rx_mblk == NULL) {
			/*
			 *  TCP/UDP checksum offload and
			 *  IP checksum offload
			 */
			if (!(current_desc->status & E1000_RXD_STAT_IXSM)) {
				/*
				 * Check TCP/UDP checksum
				 */
				if ((current_desc->status &
				    E1000_RXD_STAT_TCPCS) &&
				    !(current_desc->errors &
				    E1000_RXD_ERR_TCPE))
					cksumflags |= HCK_FULLCKSUM |
					    HCK_FULLCKSUM_OK;
				/*
				 * Check IP Checksum
				 */
				if ((current_desc->status &
				    E1000_RXD_STAT_IPCS) &&
				    !(current_desc->errors &
				    E1000_RXD_ERR_IPE))
					cksumflags |= HCK_IPV4_HDRCKSUM;
			}
		}

		/*
		 * We need to maintain our packet chain in the global
		 * Adapter structure, for the Rx processing can end
		 * with a fragment that has no EOP set.
		 */
		if (rx_ring->rx_mblk == NULL) {
			/* Get the head of the message chain */
			rx_ring->rx_mblk = nmp;
			rx_ring->rx_mblk_tail = nmp;
			rx_ring->rx_mblk_len = length;
		} else {	/* Not the first packet */
			/* Continue adding buffers */
			rx_ring->rx_mblk_tail->b_cont = nmp;
			rx_ring->rx_mblk_tail = nmp;
			rx_ring->rx_mblk_len += length;
		}
		ASSERT(rx_ring->rx_mblk != NULL);
		ASSERT(rx_ring->rx_mblk_tail != NULL);
		ASSERT(rx_ring->rx_mblk_tail->b_cont == NULL);

		/*
		 * Now this MP is ready to travel upwards but some more
		 * fragments are coming.
		 * We will send packet upwards as soon as we get EOP
		 * set on the packet.
		 */
		if (!end_of_packet) {
			/*
			 * continue to get the next descriptor,
			 * Tail would be advanced at the end
			 */
			goto rx_next_desc;
		}

rx_end_of_packet:
		/*
		 * Found packet with EOP
		 * Process the last fragment.
		 */
		if (cksumflags != 0) {
			(void) hcksum_assoc(rx_ring->rx_mblk,
			    NULL, NULL, 0, 0, 0, 0, cksumflags, 0);
			cksumflags = 0;
		}

		/*
		 * Count packets that span multi-descriptors
		 */
		E1000G_DEBUG_STAT_COND(rx_ring->stat_multi_desc,
		    (rx_ring->rx_mblk->b_cont != NULL));

		/*
		 * Append to list to send upstream
		 */
		if (ret_mp == NULL) {
			ret_mp = ret_nmp = rx_ring->rx_mblk;
		} else {
			ret_nmp->b_next = rx_ring->rx_mblk;
			ret_nmp = rx_ring->rx_mblk;
		}
		ret_nmp->b_next = NULL;

		rx_ring->rx_mblk = NULL;
		rx_ring->rx_mblk_tail = NULL;
		rx_ring->rx_mblk_len = 0;

		pkt_count++;

rx_next_desc:
		/*
		 * Zero out the receive descriptors status
		 */
		current_desc->status = 0;

		if (current_desc == rx_ring->rbd_last)
			rx_ring->rbd_next = rx_ring->rbd_first;
		else
			rx_ring->rbd_next++;

		last_desc = current_desc;
		current_desc = rx_ring->rbd_next;

		/*
		 * Put the buffer that we just indicated back
		 * at the end of our list
		 */
		QUEUE_PUSH_TAIL(&rx_ring->recv_list,
		    &packet->Link);
	}	/* while loop */

	/* Sync the Rx descriptor DMA buffers */
	(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
	    0, 0, DDI_DMA_SYNC_FORDEV);

	/*
	 * Advance the E1000's Receive Queue #0 "Tail Pointer".
	 */
	E1000_WRITE_REG(hw, E1000_RDT(0),
	    (uint32_t)(last_desc - rx_ring->rbd_first));

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		Adapter->chip_state = E1000G_ERROR;
	}

	Adapter->rx_pkt_cnt = pkt_count;

	return (ret_mp);

rx_drop:
	/*
	 * Zero out the receive descriptors status
	 */
	current_desc->status = 0;

	/* Sync the Rx descriptor DMA buffers */
	(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
	    0, 0, DDI_DMA_SYNC_FORDEV);

	if (current_desc == rx_ring->rbd_last)
		rx_ring->rbd_next = rx_ring->rbd_first;
	else
		rx_ring->rbd_next++;

	last_desc = current_desc;

	(p_rx_sw_packet_t)QUEUE_POP_HEAD(&rx_ring->recv_list);

	QUEUE_PUSH_TAIL(&rx_ring->recv_list, &packet->Link);
	/*
	 * Reclaim all old buffers already allocated during
	 * Jumbo receives.....for incomplete reception
	 */
	if (rx_ring->rx_mblk != NULL) {
		freemsg(rx_ring->rx_mblk);
		rx_ring->rx_mblk = NULL;
		rx_ring->rx_mblk_tail = NULL;
		rx_ring->rx_mblk_len = 0;
	}
	/*
	 * Advance the E1000's Receive Queue #0 "Tail Pointer".
	 */
	E1000_WRITE_REG(hw, E1000_RDT(0),
	    (uint32_t)(last_desc - rx_ring->rbd_first));

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		Adapter->chip_state = E1000G_ERROR;
	}

	return (ret_mp);
}
