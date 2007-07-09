/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2007 Intel Corporation. All rights reserved.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * **********************************************************************
 *									*
 * Module Name:								*
 *   e1000g_rx.c							*
 *									*
 * Abstract:								*
 *   This file contains some routines that takes care of Receive	*
 *   interrupt and also for the received packet				*
 *   it sends up to upper layer.					*
 *   It tries to do a zero copy if free buffers are available in	*
 *   the pool. Also it implements shortcut to Ipq			*
 *									*
 *									*
 *   This driver runs on the following hardware:			*
 *   - Wisemane based PCI gigabit ethernet adapters			*
 *									*
 * Environment:								*
 *   Kernel Mode -							*
 *									*
 * **********************************************************************
 */

#include "e1000g_sw.h"
#include "e1000g_debug.h"

/*
 * local prototypes
 */
static RX_SW_PACKET *e1000g_get_buf(e1000g_rx_ring_t *rx_ring);
#pragma	inline(e1000g_get_buf)

/*
 * **********************************************************************
 * Name:      e1000g_rxfree_func					*
 *									*
 * Description:								*
 *									*
 *	This functionis called when a mp is freed by the user thru	*
 *	freeb call (Only for mp constructed through desballoc call)	*
 *	It returns back the freed buffer to the freelist		*
 *									*
 *									*
 * Parameter Passed:							*
 *									*
 * Return Value:							*
 *									*
 * Functions called:							*
 *									*
 * **********************************************************************
 */
void
e1000g_rxfree_func(RX_SW_PACKET *packet)
{
	struct e1000g *Adapter;
	e1000g_rx_ring_t *rx_ring;

	/*
	 * Here the rx recycling processes different rx packets in different
	 * threads, so we protect it with RW_READER to ensure it won't block
	 * other rx recycling threads.
	 */
	rw_enter(&e1000g_rx_detach_lock, RW_READER);

	if (!(packet->flag & E1000G_RX_SW_SENDUP)) {
		rw_exit(&e1000g_rx_detach_lock);
		return;
	}

	if (packet->flag & E1000G_RX_SW_DETACHED) {
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
		rw_exit(&e1000g_rx_detach_lock);
		return;
	}

	packet->flag &= ~E1000G_RX_SW_SENDUP;

	rx_ring = (e1000g_rx_ring_t *)packet->rx_ring;
	Adapter = rx_ring->adapter;

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
			Adapter->rx_esballoc_fail++;
		}
	}

	mutex_enter(&rx_ring->freelist_lock);
	QUEUE_PUSH_TAIL(&rx_ring->free_list, &packet->Link);
	Adapter->rx_avail_freepkt++;
	mutex_exit(&rx_ring->freelist_lock);

	rw_exit(&e1000g_rx_detach_lock);
}

/*
 * **********************************************************************
 * Name:	SetupReceiveStructures					*
 *									*
 * Description: This routine initializes all of the receive related	*
 *	      structures.  This includes the receive descriptors, the	*
 *	      actual receive buffers, and the RX_SW_PACKET software	*
 *	      structures.						*
 *									*
 *	      NOTE -- The device must have been reset before this	*
 *		      routine is called.				*
 *									*
 * Author:      Hari Seshadri						*
 * Functions Called :      get_32bit_value;				*
 *									*
 *									*
 *									*
 * Arguments:								*
 *      Adapter - A pointer to our context sensitive "Adapter"		*
 *	structure.							*
 *									*
 * Returns:								*
 *      (none)								*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  -----------------------------------------------------	*
 *									*
 * **********************************************************************
 */
void
SetupReceiveStructures(struct e1000g *Adapter)
{
	PRX_SW_PACKET packet;
	struct e1000_rx_desc *descriptor;
	uint32_t BufferLow;
	uint32_t BufferHigh;
	uint32_t reg_val;
	int i;
	int size;
	e1000g_rx_ring_t *rx_ring;

	rx_ring = Adapter->rx_ring;

	/*
	 * zero out all of the receive buffer descriptor memory
	 * assures any previous data or status is erased
	 */
	bzero(rx_ring->rbd_area,
	    sizeof (struct e1000_rx_desc) * Adapter->NumRxDescriptors);

	if (Adapter->init_count == 0) {
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

		for (i = 0; i < Adapter->NumRxDescriptors;
		    i++, packet = packet->next, descriptor++) {

			ASSERT(packet != NULL);
			ASSERT(descriptor != NULL);
#ifdef __sparc
			descriptor->buffer_addr =
			    DWORD_SWAP(packet->rx_buf->dma_address);
#else
			descriptor->buffer_addr =
			    packet->rx_buf->dma_address;
#endif
			/* Add this RX_SW_PACKET to the receive list */
			QUEUE_PUSH_TAIL(&rx_ring->recv_list,
			    &packet->Link);
		}

		for (i = 0; i < Adapter->NumRxFreeList;
		    i++, packet = packet->next) {
			ASSERT(packet != NULL);
			/* Add this RX_SW_PACKET to the free list */
			QUEUE_PUSH_TAIL(&rx_ring->free_list,
			    &packet->Link);
		}
		Adapter->rx_avail_freepkt = Adapter->NumRxFreeList;
	} else {
		/* Setup the initial pointer to the first rx descriptor */
		packet = (PRX_SW_PACKET)
		    QUEUE_GET_HEAD(&rx_ring->recv_list);
		descriptor = rx_ring->rbd_first;

		for (i = 0; i < Adapter->NumRxDescriptors; i++) {
			ASSERT(packet != NULL);
			ASSERT(descriptor != NULL);
#ifdef __sparc
			descriptor->buffer_addr =
			    DWORD_SWAP(packet->rx_buf->dma_address);
#else
			descriptor->buffer_addr =
			    packet->rx_buf->dma_address;
#endif
			/* Get next RX_SW_PACKET */
			packet = (PRX_SW_PACKET)
			    QUEUE_GET_NEXT(&rx_ring->recv_list, &packet->Link);
			descriptor++;
		}
	}

	/*
	 * Setup our descriptor pointers
	 */
	rx_ring->rbd_next = rx_ring->rbd_first;

	size = Adapter->NumRxDescriptors * sizeof (struct e1000_rx_desc);
	E1000_WRITE_REG(&Adapter->Shared, RDLEN, size);
	size = E1000_READ_REG(&Adapter->Shared, RDLEN);

	/* To get lower order bits */
	BufferLow = (uint32_t)rx_ring->rbd_dma_addr;
	/* To get the higher order bits */
	BufferHigh = (uint32_t)(rx_ring->rbd_dma_addr >> 32);

	E1000_WRITE_REG(&Adapter->Shared, RDBAH, BufferHigh);
	E1000_WRITE_REG(&Adapter->Shared, RDBAL, BufferLow);

	/*
	 * Setup our HW Rx Head & Tail descriptor pointers
	 */
	E1000_WRITE_REG(&Adapter->Shared, RDT,
	    (uint32_t)(rx_ring->rbd_last - rx_ring->rbd_first));
	E1000_WRITE_REG(&Adapter->Shared, RDH, 0);

	/*
	 * Setup the Receive Control Register (RCTL), and ENABLE the
	 * receiver. The initial configuration is to: Enable the receiver,
	 * accept broadcasts, discard bad packets (and long packets),
	 * disable VLAN filter checking, set the receive descriptor
	 * minimum threshold size to 1/2, and the receive buffer size to
	 * 2k.
	 */
	reg_val = E1000_RCTL_EN |	/* Enable Receive Unit */
	    E1000_RCTL_BAM |		/* Accept Broadcast Packets */
	    E1000_RCTL_LPE |		/* Large Packet Enable bit */
	    (Adapter->Shared.mc_filter_type << E1000_RCTL_MO_SHIFT) |
	    E1000_RCTL_RDMTS_HALF |
	    E1000_RCTL_LBM_NO;		/* Loopback Mode = none */

	if (Adapter->strip_crc)
		reg_val |= E1000_RCTL_SECRC;    /* Strip Ethernet CRC */

	switch (Adapter->Shared.max_frame_size) {
	case ETHERMAX:
		reg_val |= E1000_RCTL_SZ_2048;
		break;
	case FRAME_SIZE_UPTO_4K:
		reg_val |= E1000_RCTL_SZ_4096 | E1000_RCTL_BSEX;
		break;
	case FRAME_SIZE_UPTO_8K:
		reg_val |= E1000_RCTL_SZ_8192 | E1000_RCTL_BSEX;
		break;
	case FRAME_SIZE_UPTO_10K:
	case FRAME_SIZE_UPTO_16K:
		reg_val |= E1000_RCTL_SZ_16384 | E1000_RCTL_BSEX;
		break;
	default:
		reg_val |= E1000_RCTL_SZ_2048;
		break;
	}

	if (Adapter->Shared.tbi_compatibility_on == 1)
		reg_val |= E1000_RCTL_SBP;

	E1000_WRITE_REG(&Adapter->Shared, RCTL, reg_val);

	reg_val =
	    E1000_RXCSUM_TUOFL |	/* TCP/UDP checksum offload Enable */
	    E1000_RXCSUM_IPOFL;		/* IP checksum offload Enable */

	E1000_WRITE_REG(&Adapter->Shared, RXCSUM, reg_val);

	Adapter->Shared.autoneg_failed = 1;

	Adapter->rx_bcopy_thresh = DEFAULTRXBCOPYTHRESHOLD;
}

/*
 * **********************************************************************
 * Name:	SetupMulticastTable					*
 *									*
 * Description: This routine initializes all of the multicast related	*
 *	structures.							*
 *	NOTE -- The device must have been reset before this routine	*
 *		is called.						*
 *									*
 * Author:      Hari Seshadri						*
 *									*
 * Arguments:								*
 *      Adapter - A pointer to our context sensitive "Adapter"		*
 *	structure.							*
 *									*
 * Returns:								*
 *      (none)								*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  -----------------------------------------------------	*
 *									*
 * **********************************************************************
 */
void
SetupMulticastTable(struct e1000g *Adapter)
{
	PUCHAR MulticastBuffer;
	UINT32 MulticastAddressCount;
	UINT32 TempRctlReg;
	USHORT PciCommandWord;
	int i;

	/*
	 * The e1000g has the ability to do perfect filtering of 16
	 * addresses. The driver uses one of the e1000g's 16 receive
	 * address registers for its node/network/mac/individual address.
	 * So, we have room for up to 15 multicast addresses in the CAM,
	 * additional MC addresses are handled by the MTA (Multicast Table
	 * Array)
	 */

	TempRctlReg = E1000_READ_REG(&Adapter->Shared, RCTL);

	MulticastBuffer = (PUCHAR) (Adapter->mcast_table);

	if (Adapter->mcast_count > MAX_NUM_MULTICAST_ADDRESSES) {
		e1000g_log(Adapter, CE_WARN,
		    "Adapter requested more than %d MC Addresses.\n",
		    MAX_NUM_MULTICAST_ADDRESSES);
		MulticastAddressCount = MAX_NUM_MULTICAST_ADDRESSES;
	} else {
		/*
		 * Set the number of MC addresses that we are being
		 * requested to use
		 */
		MulticastAddressCount = Adapter->mcast_count;
	}
	/*
	 * The Wiseman 2.0 silicon has an errata by which the receiver will
	 * hang  while writing to the receive address registers if the receiver
	 * is not in reset before writing to the registers. Updating the RAR
	 * is done during the setting up of the multicast table, hence the
	 * receiver has to be put in reset before updating the multicast table
	 * and then taken out of reset at the end
	 */
	/*
	 * if WMI was enabled then dis able it before issueing the global
	 * reset to the hardware.
	 */
	/*
	 * Only required for WISEMAN_2_0
	 */
	if (Adapter->Shared.mac_type == e1000_82542_rev2_0) {
		e1000_pci_clear_mwi(&Adapter->Shared);
		/*
		 * The e1000g must be in reset before changing any RA
		 * registers. Reset receive unit.  The chip will remain in
		 * the reset state until software explicitly restarts it.
		 */
		E1000_WRITE_REG(&Adapter->Shared, RCTL, E1000_RCTL_RST);
		/* Allow receiver time to go in to reset */
		DelayInMilliseconds(5);
	}

	e1000_mc_addr_list_update(&Adapter->Shared, MulticastBuffer,
	    MulticastAddressCount, 0, Adapter->unicst_total);

	/*
	 * Only for Wiseman_2_0
	 * If MWI was enabled then re-enable it after issueing (as we
	 * disabled it up there) the receive reset command.
	 * Wainwright does not have a receive reset command and only thing
	 * close to it is global reset which will require tx setup also
	 */
	if (Adapter->Shared.mac_type == e1000_82542_rev2_0) {
		/*
		 * if WMI was enabled then reenable it after issueing the
		 * global or receive reset to the hardware.
		 */

		/*
		 * Take receiver out of reset
		 * clear E1000_RCTL_RST bit (and all others)
		 */
		E1000_WRITE_REG(&Adapter->Shared, RCTL, 0);
		DelayInMilliseconds(5);
		if (Adapter->Shared.pci_cmd_word & CMD_MEM_WRT_INVALIDATE)
			e1000_pci_set_mwi(&Adapter->Shared);
	}

	/*
	 * Restore original value
	 */
	E1000_WRITE_REG(&Adapter->Shared, RCTL, TempRctlReg);
}

/*
 * **********************************************************************
 * Name:	e1000g_get_buf						*
 *									*
 * Description: This routine gets newpkt.				*
 *									*
 * Author:      Hari Seshadri						*
 *									*
 * Arguments:								*
 *									*
 * Returns:								*
 *      RX_SW_PACKET*							*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  -----------------------------------------------------	*
 *									*
 * **********************************************************************
 */
static RX_SW_PACKET *
e1000g_get_buf(e1000g_rx_ring_t *rx_ring)
{
	struct e1000g *Adapter;
	RX_SW_PACKET *packet;

	Adapter = rx_ring->adapter;

	mutex_enter(&rx_ring->freelist_lock);
	packet = (PRX_SW_PACKET)
	    QUEUE_POP_HEAD(&rx_ring->free_list);
	if (packet != NULL)
		Adapter->rx_avail_freepkt--;
	mutex_exit(&rx_ring->freelist_lock);

	return (packet);
}

/*
 * **********************************************************************
 * Name:	e1000g_receive						*
 *									*
 * Description: This routine will process packets spanning multiple	*
 * 		buffers							*
 *	- Called from the e1000g_intr Handles interrupt for RX side	*
 *	- Checks the interrupt cause and process it. At the time of	*
 *	  calling the interrupt cause register has been already		*
 *	  cleared.							*
 *									*
 * Author:      Vinay K Awasthi						*
 *									*
 * Date  :      Feb 9, 2000						*
 *									*
 * Arguments:								*
 *      Adapter - A pointer to our context sensitive "Adapter"		*
 *      structure.							*
 *									*
 * Returns:								*
 *      Pointer to list of mblks to pass up to GLD			*
 * Functions Called:							*
 *      (none)								*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  -----------------------------------------------------	*
 *									*
 * **********************************************************************
 */
mblk_t *
e1000g_receive(struct e1000g *Adapter)
{
	/*
	 * Need :
	 * This function addresses the need to process jumbo frames using
	 * standard 2048 byte buffers. In solaris, getting large aligned
	 * buffers in low memory systems is hard and often it comprises
	 * of multiple cookies rather than just one cookie which our HW
	 * wants. In low memory systems, it is hard to get lots of large
	 * chunks of memory i.e. you can get 256 2k buffers but it is hard
	 * to get 64 8k buffers. Pagesize is playing an important role here.
	 * If system administrator is willing to tune stream and system dma
	 * resources then we may not need this function. At the same time
	 * we may not have this option.
	 * This function will also make our driver do Jumbo frames on Wiseman
	 * hardware.
	 */

	mblk_t *nmp;
	mblk_t *ret_mp;
	mblk_t *ret_nmp;
	struct e1000_rx_desc *current_desc;
	struct e1000_rx_desc *last_desc;
	PRX_SW_PACKET packet;
	PRX_SW_PACKET newpkt;
	USHORT length;
	uint32_t pkt_count;
	uint32_t desc_count;
	unsigned char LastByte;
	boolean_t AcceptFrame;
	boolean_t end_of_packet;
	boolean_t need_copy;
	e1000g_rx_ring_t *rx_ring;
	dma_buffer_t *rx_buf;
	uint16_t cksumflags;
	uint32_t sync_offset;
	uint32_t sync_len;

	ret_mp = NULL;
	ret_nmp = NULL;
	pkt_count = 0;
	desc_count = 0;
	cksumflags = 0;

	rx_ring = Adapter->rx_ring;

	sync_offset = rx_ring->rbd_next - rx_ring->rbd_first;

	/* Sync the Rx descriptor DMA buffers */
	(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
	    0, 0, DDI_DMA_SYNC_FORCPU);

	current_desc = rx_ring->rbd_next;
	if (!(current_desc->status & E1000_RXD_STAT_DD)) {
		/*
		 * don't send anything up. just clear the RFD
		 */
		Adapter->rx_none++;
		return (ret_mp);
	}

	/*
	 * Loop through the receive descriptors starting at the last known
	 * descriptor owned by the hardware that begins a packet.
	 */
	while ((current_desc->status & E1000_RXD_STAT_DD) &&
	    (pkt_count < Adapter->MaxNumReceivePackets)) {

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
		    (PRX_SW_PACKET)QUEUE_GET_HEAD(&rx_ring->recv_list);
		ASSERT(packet != NULL);

		rx_buf = packet->rx_buf;

		length = current_desc->length;

		switch (packet->dma_type) {
#ifdef __sparc
		case USE_DVMA:
			dvma_sync(rx_buf->dma_handle, 0,
			    DDI_DMA_SYNC_FORKERNEL);
			break;
#endif
		case USE_DMA:
			(void) ddi_dma_sync(rx_buf->dma_handle,
			    E1000G_IPALIGNROOM, length,
			    DDI_DMA_SYNC_FORCPU);
			break;
		default:
			ASSERT(B_FALSE);
			break;
		}

		LastByte =
		    *((unsigned char *)rx_buf->address + length - 1);

		if (TBI_ACCEPT(&Adapter->Shared,
		    current_desc->status,
		    current_desc->errors,
		    current_desc->length, LastByte)) {

			AcceptFrame = B_TRUE;
			mutex_enter(&Adapter->TbiCntrMutex);
			AdjustTbiAcceptedStats(Adapter, length,
			    Adapter->Shared.mac_addr);
			mutex_exit(&Adapter->TbiCntrMutex);
			length--;
		} else {
			AcceptFrame = B_FALSE;
		}
		/*
		 * Indicate the packet to the NOS if it was good.
		 * Normally, hardware will discard bad packets for us.
		 * Check for the packet to be a valid Ethernet packet
		 */

		/*
		 * There can be few packets which are less than 2k but
		 * more than 1514 bytes length. They are really jumbo
		 * packets, but for our driver's buffer they can still
		 * fit in one buffer as minimum buffer size if 2K. In our
		 * above condition, we are taking all EOP packets as
		 * JumboPacket=False... JumboPacket=FALSE just tells us
		 * that now we can process this packet...as we have
		 * received complete packet.
		 */

		if (!((current_desc->errors == 0) ||
		    (current_desc->errors &
		    (E1000_RXD_ERR_TCPE | E1000_RXD_ERR_IPE)) ||
		    ((Adapter->Shared.tbi_compatibility_on == 1) &&
		    (current_desc->errors == E1000_RXD_ERR_CE)) ||
		    AcceptFrame)) {
			/*
			 * error in incoming packet, either the packet is not a
			 * ethernet size packet, or the packet has an error. In
			 * either case, the packet will simply be discarded.
			 */
			e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
			    "Process Receive Interrupts: Error in Packet\n");

			Adapter->rx_error++;
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
			if (length > CRC_LENGTH) {
				length -= CRC_LENGTH;
			} else {
				/*
				 * If the fragment is smaller than the CRC,
				 * drop this fragment, do the processing of
				 * the end of the packet.
				 */
				ASSERT(Adapter->rx_mblk_tail != NULL);
				Adapter->rx_mblk_tail->b_wptr -=
				    CRC_LENGTH - length;
				Adapter->rx_packet_len -=
				    CRC_LENGTH - length;

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
				Adapter->rx_esballoc_fail++;
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
				packet->flag |= E1000G_RX_SW_SENDUP;

				/*
				 * Now replace old buffer with the new
				 * one we got from free list
				 * Both the RxSwPacket as well as the
				 * Receive Buffer Descriptor will now
				 * point to this new packet.
				 */
				packet = newpkt;
#ifdef __sparc
				current_desc->buffer_addr =
				    DWORD_SWAP(newpkt->rx_buf->dma_address);
#else
				current_desc->buffer_addr =
				    newpkt->rx_buf->dma_address;
#endif
				need_copy = B_FALSE;
			} else {
				Adapter->rx_no_freepkt++;
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
			if ((nmp =
			    allocb(length + E1000G_IPALIGNROOM,
			    BPRI_MED)) == NULL) {
				/*
				 * The system has no buffers available
				 * to send up the incoming packet, hence
				 * the packet will have to be processed
				 * when there're more buffers available.
				 */
				Adapter->rx_allocb_fail++;
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
			bcopy(rx_buf->address,
			    nmp->b_wptr, length);
		}

		/*
		 * The RX_SW_PACKET MUST be popped off the
		 * RxSwPacketList before either a putnext or freemsg
		 * is done on the mp that has now been created by the
		 * desballoc. If not, it is possible that the free
		 * routine will get called from the interrupt context
		 * and try to put this packet on the free list
		 */
		(PRX_SW_PACKET)QUEUE_POP_HEAD(&rx_ring->recv_list);

		ASSERT(nmp != NULL);
		nmp->b_wptr += length;

		if ((Adapter->rx_mblk == NULL) &&
		    (GET_ETHER_TYPE((struct ether_header *)nmp->b_rptr) ==
		    ETHERTYPE_IP)) {
			/*
			 *  TCP/UDP checksum offload and
			 *  IP checksum offload
			 */
			if (!(current_desc->status &
			    E1000_RXD_STAT_IXSM)) {
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
		if (Adapter->rx_mblk == NULL) {
			/* Get the head of the message chain */
			Adapter->rx_mblk = nmp;
			Adapter->rx_mblk_tail = nmp;
			Adapter->rx_packet_len = length;
		} else {	/* Not the first packet */
			/* Continue adding buffers */
			Adapter->rx_mblk_tail->b_cont = nmp;
			Adapter->rx_mblk_tail = nmp;
			Adapter->rx_packet_len += length;
		}
		ASSERT(Adapter->rx_mblk != NULL);
		ASSERT(Adapter->rx_mblk_tail != NULL);
		ASSERT(Adapter->rx_mblk_tail->b_cont == NULL);

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
			(void) hcksum_assoc(Adapter->rx_mblk,
			    NULL, NULL, 0, 0, 0, 0, cksumflags, 0);
			cksumflags = 0;
		}

		/*
		 * Jumbo Frame Counters
		 */
		if (Adapter->ProfileJumboTraffic) {
			if ((Adapter->rx_packet_len > ETHERMAX) &&
			    (Adapter->rx_packet_len <= FRAME_SIZE_UPTO_4K))
				Adapter->JumboRx_4K++;

			if ((Adapter->rx_packet_len > FRAME_SIZE_UPTO_4K) &&
			    (Adapter->rx_packet_len <= FRAME_SIZE_UPTO_8K))
				Adapter->JumboRx_8K++;

			if ((Adapter->rx_packet_len > FRAME_SIZE_UPTO_8K) &&
			    (Adapter->rx_packet_len <= FRAME_SIZE_UPTO_16K))
				Adapter->JumboRx_16K++;
		}
		/*
		 * Count packets that span multi-descriptors
		 */
		if (Adapter->rx_mblk->b_cont != NULL)
			Adapter->rx_multi_desc++;

		/*
		 * Append to list to send upstream
		 */
		if (ret_mp == NULL) {
			ret_mp = ret_nmp = Adapter->rx_mblk;
		} else {
			ret_nmp->b_next = Adapter->rx_mblk;
			ret_nmp = Adapter->rx_mblk;
		}
		ret_nmp->b_next = NULL;

		Adapter->rx_mblk = NULL;
		Adapter->rx_mblk_tail = NULL;
		Adapter->rx_packet_len = 0;

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

	if (pkt_count >= Adapter->MaxNumReceivePackets)
		Adapter->rx_exceed_pkt++;

	/* Sync the Rx descriptor DMA buffers */
	sync_len = desc_count;
	/* Check the wrap-around case */
	if ((sync_offset + sync_len) <= Adapter->NumRxDescriptors) {
		(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
		    sync_offset * sizeof (struct e1000_rx_desc),
		    sync_len * sizeof (struct e1000_rx_desc),
		    DDI_DMA_SYNC_FORDEV);
	} else {
		(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
		    sync_offset * sizeof (struct e1000_rx_desc),
		    0,
		    DDI_DMA_SYNC_FORDEV);
		sync_len = sync_offset + sync_len - Adapter->NumRxDescriptors;
		(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
		    0,
		    sync_len * sizeof (struct e1000_rx_desc),
		    DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * Advance the E1000's Receive Queue #0 "Tail Pointer".
	 */
	E1000_WRITE_REG(&Adapter->Shared, RDT,
	    (uint32_t)(last_desc - rx_ring->rbd_first));

	return (ret_mp);

rx_drop:
	/*
	 * Zero out the receive descriptors status
	 */
	current_desc->status = 0;

	/* Sync the Rx descriptor DMA buffers */
	sync_len = desc_count;
	/* Check the wrap-around case */
	if ((sync_offset + sync_len) <= Adapter->NumRxDescriptors) {
		(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
		    sync_offset * sizeof (struct e1000_rx_desc),
		    sync_len * sizeof (struct e1000_rx_desc),
		    DDI_DMA_SYNC_FORDEV);
	} else {
		(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
		    sync_offset * sizeof (struct e1000_rx_desc),
		    0,
		    DDI_DMA_SYNC_FORDEV);
		sync_len = sync_offset + sync_len - Adapter->NumRxDescriptors;
		(void) ddi_dma_sync(rx_ring->rbd_dma_handle,
		    0,
		    sync_len * sizeof (struct e1000_rx_desc),
		    DDI_DMA_SYNC_FORDEV);
	}

	if (current_desc == rx_ring->rbd_last)
		rx_ring->rbd_next = rx_ring->rbd_first;
	else
		rx_ring->rbd_next++;

	last_desc = current_desc;

	(PRX_SW_PACKET)QUEUE_POP_HEAD(&rx_ring->recv_list);

	QUEUE_PUSH_TAIL(&rx_ring->recv_list, &packet->Link);
	/*
	 * Reclaim all old buffers already allocated during
	 * Jumbo receives.....for incomplete reception
	 */
	if (Adapter->rx_mblk != NULL) {
		freemsg(Adapter->rx_mblk);
		Adapter->rx_mblk = NULL;
		Adapter->rx_mblk_tail = NULL;
		Adapter->rx_packet_len = 0;
	}
	/*
	 * Advance the E1000's Receive Queue #0 "Tail Pointer".
	 */
	E1000_WRITE_REG(&Adapter->Shared, RDT,
	    (uint32_t)(last_desc - rx_ring->rbd_first));

	return (ret_mp);
}
