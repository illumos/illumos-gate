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
 *   e1000g_tx.c							*
 *									*
 * Abstract:								*
 *   This file contains some routines that takes care of Transmit	*
 *   interrupt and also makes the hardware to send the data pointed	*
 *   by the packet out on   to the physical medium.			*
 *									*
 *									*
 * Environment:								*
 *   Kernel Mode -							*
 *									*
 * Source History:							*
 *   The code in this file is based somewhat on the "send" code		*
 *   developed for the Intel Pro/100 family(Speedo1 and Speedo3) by	*
 *   Steve Lindsay, and partly on some sample DDK code			*
 *   of solaris.							*
 *									*
 *   March 12, 1997 Steve Lindsay					*
 *   1st created - Ported from E100B send.c file			*
 *									*
 * **********************************************************************
 */

#include "e1000g_sw.h"
#include "e1000g_debug.h"

static boolean_t e1000g_send(struct e1000g *, mblk_t *);
static int e1000g_tx_copy(struct e1000g *, PTX_SW_PACKET, mblk_t *, uint32_t);
static int e1000g_tx_bind(struct e1000g *, PTX_SW_PACKET, mblk_t *);
static int e1000g_fill_tx_ring(e1000g_tx_ring_t *, LIST_DESCRIBER *,
    uint_t, boolean_t);
static void e1000g_fill_context_descriptor(e1000g_tx_ring_t *,
    struct e1000_context_desc *);
static int e1000g_fill_tx_desc(struct e1000g *,
    PTX_SW_PACKET, uint64_t, size_t);
static uint32_t e1000g_fill_82544_desc(uint64_t Address, size_t Length,
    PDESC_ARRAY desc_array);
static int e1000g_tx_workaround_PCIX_82544(struct e1000g *,
    PTX_SW_PACKET, uint64_t, size_t);
static int e1000g_tx_workaround_jumbo_82544(struct e1000g *,
    PTX_SW_PACKET, uint64_t, size_t);
static uint32_t e1000g_tx_free_desc_num(e1000g_tx_ring_t *);
static void e1000g_82547_timeout(void *);
static void e1000g_82547_tx_move_tail(e1000g_tx_ring_t *);
static void e1000g_82547_tx_move_tail_work(e1000g_tx_ring_t *);

#ifndef e1000g_DEBUG
#pragma inline(e1000g_tx_copy)
#pragma inline(e1000g_tx_bind)
#pragma inline(e1000g_fill_tx_ring)
#pragma inline(e1000g_fill_context_descriptor)
#pragma inline(e1000g_fill_tx_desc)
#pragma inline(e1000g_fill_82544_desc)
#pragma inline(e1000g_tx_workaround_PCIX_82544)
#pragma inline(e1000g_tx_workaround_jumbo_82544)
#pragma inline(FreeTxSwPacket)
#pragma inline(e1000g_tx_free_desc_num)
#endif

/*
 * **********************************************************************
 * Name:      FreeTxSwPacket						*
 *									*
 * Description:								*
 *	       Frees up the previusly allocated Dma handle for given	*
 *	       transmit sw packet.					*
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
FreeTxSwPacket(register PTX_SW_PACKET packet)
{
	switch (packet->data_transfer_type) {
	case USE_BCOPY:
		packet->tx_buf->len = 0;
		break;
#ifdef __sparc
	case USE_DVMA:
		dvma_unload(packet->tx_dma_handle, 0, -1);
		break;
#endif
	case USE_DMA:
		ddi_dma_unbind_handle(packet->tx_dma_handle);
		break;
	default:
		break;
	}

	/*
	 * The mblk has been stripped off the sw packet
	 * and will be freed in a triggered soft intr.
	 */
	ASSERT(packet->mp == NULL);

	packet->data_transfer_type = USE_NONE;
	packet->num_mblk_frag = 0;
	packet->num_desc = 0;
}

uint_t
e1000g_tx_freemsg(caddr_t arg1, caddr_t arg2)
{
	struct e1000g *Adapter;
	mblk_t *mp;

	Adapter = (struct e1000g *)arg1;

	if ((Adapter == NULL) || (arg2 != NULL))
		return (DDI_INTR_UNCLAIMED);

	if (!mutex_tryenter(&Adapter->tx_msg_chain->lock))
		return (DDI_INTR_CLAIMED);

	mp = Adapter->tx_msg_chain->head;
	Adapter->tx_msg_chain->head = NULL;
	Adapter->tx_msg_chain->tail = NULL;

	mutex_exit(&Adapter->tx_msg_chain->lock);

	freemsgchain(mp);

	return (DDI_INTR_CLAIMED);
}

static uint32_t
e1000g_tx_free_desc_num(e1000g_tx_ring_t *tx_ring)
{
	struct e1000g *Adapter;
	int num;

	Adapter = tx_ring->adapter;

	num = tx_ring->tbd_oldest - tx_ring->tbd_next;
	if (num <= 0)
		num += Adapter->NumTxDescriptors;

	return (num);
}

mblk_t *
e1000g_m_tx(void *arg, mblk_t *mp)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	mblk_t *next;

	rw_enter(&Adapter->chip_lock, RW_READER);

	if (!Adapter->started) {
		freemsgchain(mp);
		mp = NULL;
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (!e1000g_send(Adapter, mp)) {
			mp->b_next = next;
			break;
		}

		mp = next;
	}

	rw_exit(&Adapter->chip_lock);
	return (mp);
}

/*
 * **********************************************************************
 * Name:	e1000g_send						*
 *									*
 * Description:								*
 *	Called from e1000g_m_tx with an mp ready to send. this		*
 *	routine sets up the transmit descriptors and sends to		*
 *	the wire. It also pushes the just transmitted packet to		*
 *	the used tx sw packet list					*
 *									*
 * Arguments:								*
 *	Pointer to the mblk to be sent, pointer to this adapter		*
 *									*
 * Returns:								*
 *	B_TRUE, B_FALSE							*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  -----------------------------------------------------	*
 * **********************************************************************
 */
static boolean_t
e1000g_send(struct e1000g *Adapter, mblk_t *mp)
{
	PTX_SW_PACKET packet;
	LIST_DESCRIBER pending_list;
	size_t len;
	size_t msg_size;
	uint32_t frag_count;
	int desc_count;
	uint32_t desc_total;
	uint32_t force_bcopy;
	mblk_t *nmp;
	mblk_t *tmp;
	e1000g_tx_ring_t *tx_ring;
	/* IP Head/TCP/UDP checksum offload */
	uint_t cksum_start;
	uint_t cksum_stuff;
	uint_t cksum_flags;
	boolean_t cksum_load;
	uint8_t ether_header_size;

	/* Get the total size and frags number of the message */
	force_bcopy = 0;
	frag_count = 0;
	msg_size = 0;
	for (nmp = mp; nmp; nmp = nmp->b_cont) {
		frag_count++;
		msg_size += MBLKL(nmp);
	}

	/* Empty packet */
	if (msg_size == 0) {
		freemsg(mp);
		return (B_TRUE);
	}

	/* Make sure packet is less than the max frame size */
	if (msg_size > Adapter->Shared.max_frame_size + VLAN_TAGSZ) {
		/*
		 * For the over size packet, we'll just drop it.
		 * So we return B_TRUE here.
		 */
		e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
		    "Tx packet out of bound. length = %d \n", msg_size);
		freemsg(mp);
		Adapter->tx_over_size++;
		return (B_TRUE);
	}

	tx_ring = Adapter->tx_ring;

	/*
	 * Check and reclaim tx descriptors.
	 * This low water mark check should be done all the time as
	 * Transmit interrupt delay can produce Transmit interrupts little
	 * late and that may cause few problems related to reaping Tx
	 * Descriptors... As you may run short of them before getting any
	 * transmit interrupt...
	 */
	if ((Adapter->NumTxDescriptors - e1000g_tx_free_desc_num(tx_ring)) >
	    Adapter->tx_recycle_low_water) {
		if (Adapter->Shared.mac_type == e1000_82547) {
			mutex_enter(&tx_ring->tx_lock);
			e1000g_82547_tx_move_tail(tx_ring);
			mutex_exit(&tx_ring->tx_lock);
		}
		Adapter->tx_recycle++;
		(void) e1000g_recycle(tx_ring);
	}

	if (e1000g_tx_free_desc_num(tx_ring) < MAX_TX_DESC_PER_PACKET) {
		Adapter->tx_lack_desc++;
		goto tx_no_resource;
	}

	/*
	 * If there are many frags of the message, then bcopy them
	 * into one tx descriptor buffer will get better performance.
	 */
	if (frag_count >= Adapter->tx_frags_limit) {
		Adapter->tx_exceed_frags++;
		force_bcopy |= FORCE_BCOPY_EXCEED_FRAGS;
	}

	/*
	 * If the message size is less than the minimum ethernet packet size,
	 * we'll use bcopy to send it, and padd it to 60 bytes later.
	 */
	if (msg_size < MINIMUM_ETHERNET_PACKET_SIZE) {
		Adapter->tx_under_size++;
		force_bcopy |= FORCE_BCOPY_UNDER_SIZE;
	}

	/* Initialize variables */
	desc_count = 1;	/* The initial value should be greater than 0 */
	desc_total = 0;
	QUEUE_INIT_LIST(&pending_list);

	/* Retrieve checksum info */
	hcksum_retrieve(mp, NULL, NULL, &cksum_start, &cksum_stuff,
	    NULL, NULL, &cksum_flags);

	cksum_load = B_FALSE;
	if (cksum_flags) {
		if (((struct ether_vlan_header *)mp->b_rptr)->ether_tpid ==
		    htons(ETHERTYPE_VLAN))
			ether_header_size = sizeof (struct ether_vlan_header);
		else
			ether_header_size = sizeof (struct ether_header);

		if ((ether_header_size != tx_ring->ether_header_size) ||
		    (cksum_flags != tx_ring->cksum_flags) ||
		    (cksum_stuff != tx_ring->cksum_stuff) ||
		    (cksum_start != tx_ring->cksum_start)) {

			tx_ring->ether_header_size = ether_header_size;
			tx_ring->cksum_flags = cksum_flags;
			tx_ring->cksum_start = cksum_start;
			tx_ring->cksum_stuff = cksum_stuff;

			cksum_load = B_TRUE;
		}
	}

	/* Process each mblk fragment and fill tx descriptors */
	packet = NULL;
	nmp = mp;
	while (nmp) {
		tmp = nmp->b_cont;

		len = MBLKL(nmp);
		/* Check zero length mblks */
		if (len == 0) {
			Adapter->tx_empty_frags++;
			/*
			 * If there're no packet buffers have been used,
			 * or we just completed processing a buffer, then
			 * skip the empty mblk fragment.
			 * Otherwise, there's still a pending buffer that
			 * needs to be processed (tx_copy).
			 */
			if (desc_count > 0) {
				nmp = tmp;
				continue;
			}
		}

		/*
		 * Get a new TxSwPacket to process mblk buffers.
		 */
		if (desc_count > 0) {

			mutex_enter(&tx_ring->freelist_lock);
			packet = (PTX_SW_PACKET)
			    QUEUE_POP_HEAD(&tx_ring->free_list);
			mutex_exit(&tx_ring->freelist_lock);

			if (packet == NULL) {
				e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
				    "No Tx SwPacket available\n");
				Adapter->tx_no_swpkt++;
				goto tx_send_failed;
			}
			QUEUE_PUSH_TAIL(&pending_list, &packet->Link);
		}

		ASSERT(packet);
		/*
		 * If the size of the fragment is less than the tx_bcopy_thresh
		 * we'll use bcopy; Otherwise, we'll use DMA binding.
		 */
		if ((len <= Adapter->tx_bcopy_thresh) || force_bcopy) {
			desc_count =
			    e1000g_tx_copy(Adapter, packet, nmp, force_bcopy);
			Adapter->tx_copy++;
		} else {
			desc_count =
			    e1000g_tx_bind(Adapter, packet, nmp);
			Adapter->tx_bind++;
		}

		if (desc_count < 0)
			goto tx_send_failed;

		if (desc_count > 0)
			desc_total += desc_count;

		nmp = tmp;
	}

	/* Assign the message to the last sw packet */
	ASSERT(packet);
	ASSERT(packet->mp == NULL);
	packet->mp = mp;

	/* Try to recycle the tx descriptors again */
	if (e1000g_tx_free_desc_num(tx_ring) < MAX_TX_DESC_PER_PACKET) {
		Adapter->tx_recycle_retry++;
		(void) e1000g_recycle(tx_ring);
	}

	mutex_enter(&tx_ring->tx_lock);

	/*
	 * If the number of available tx descriptors is not enough for transmit
	 * (one redundant descriptor and one hw checksum context descriptor are
	 * included), then return failure.
	 */
	if (e1000g_tx_free_desc_num(tx_ring) < (desc_total + 2)) {
		e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
		    "No Enough Tx descriptors\n");
		Adapter->tx_no_desc++;
		mutex_exit(&tx_ring->tx_lock);
		goto tx_send_failed;
	}

	desc_count = e1000g_fill_tx_ring(tx_ring, &pending_list,
	    cksum_flags, cksum_load);

	mutex_exit(&tx_ring->tx_lock);

	ASSERT(desc_count > 0);

	/* Update statistic counters */
	if (Adapter->ProfileJumboTraffic) {
		if ((msg_size > ETHERMAX) &&
		    (msg_size <= FRAME_SIZE_UPTO_4K))
			Adapter->JumboTx_4K++;

		if ((msg_size > FRAME_SIZE_UPTO_4K) &&
		    (msg_size <= FRAME_SIZE_UPTO_8K))
			Adapter->JumboTx_8K++;

		if ((msg_size > FRAME_SIZE_UPTO_8K) &&
		    (msg_size <= FRAME_SIZE_UPTO_16K))
			Adapter->JumboTx_16K++;
	}

	/* Send successful */
	return (B_TRUE);

tx_send_failed:
	/* Free pending TxSwPackets */
	packet = (PTX_SW_PACKET) QUEUE_GET_HEAD(&pending_list);
	while (packet) {
		packet->mp = NULL;
		FreeTxSwPacket(packet);
		packet = (PTX_SW_PACKET)
		    QUEUE_GET_NEXT(&pending_list, &packet->Link);
	}

	/* Return pending TxSwPackets to the "Free" list */
	mutex_enter(&tx_ring->freelist_lock);
	QUEUE_APPEND(&tx_ring->free_list, &pending_list);
	mutex_exit(&tx_ring->freelist_lock);

	Adapter->tx_send_fail++;

	freemsg(mp);

	/* Send failed, message dropped */
	return (B_TRUE);

tx_no_resource:
	/*
	 * Enable Transmit interrupts, so that the interrupt routine can
	 * call mac_tx_update() when transmit descriptors become available.
	 */
	Adapter->resched_needed = B_TRUE;
	if (!Adapter->tx_intr_enable)
		e1000g_EnableTxInterrupt(Adapter);

	/* Message will be scheduled for re-transmit */
	return (B_FALSE);
}

static int
e1000g_fill_tx_ring(e1000g_tx_ring_t *tx_ring, LIST_DESCRIBER *pending_list,
    uint_t cksum_flags, boolean_t cksum_load)
{
	struct e1000g *Adapter;
	PTX_SW_PACKET first_packet;
	PTX_SW_PACKET packet;
	struct e1000_context_desc *cksum_desc;
	struct e1000_tx_desc *first_data_desc;
	struct e1000_tx_desc *next_desc;
	struct e1000_tx_desc *descriptor;
	uint32_t sync_offset;
	int sync_len;
	int desc_count;
	int i;

	Adapter = tx_ring->adapter;

	desc_count = 0;
	cksum_desc = NULL;
	first_data_desc = NULL;
	descriptor = NULL;

	first_packet = (PTX_SW_PACKET) QUEUE_GET_HEAD(pending_list);
	ASSERT(first_packet);

	next_desc = tx_ring->tbd_next;

	/* IP Head/TCP/UDP checksum offload */
	if (cksum_load) {
		descriptor = next_desc;

		cksum_desc = (struct e1000_context_desc *)descriptor;

		e1000g_fill_context_descriptor(tx_ring, cksum_desc);

		/* Check the wrap-around case */
		if (descriptor == tx_ring->tbd_last)
			next_desc = tx_ring->tbd_first;
		else
			next_desc++;

		desc_count++;
	}

	if (cksum_desc == NULL)
		first_packet = NULL;

	first_data_desc = next_desc;

	packet = (PTX_SW_PACKET) QUEUE_GET_HEAD(pending_list);
	while (packet) {
		ASSERT(packet->num_desc);

		for (i = 0; i < packet->num_desc; i++) {
			ASSERT(e1000g_tx_free_desc_num(tx_ring) > 0);

			descriptor = next_desc;
#ifdef __sparc
			descriptor->buffer_addr =
			    DWORD_SWAP(packet->desc[i].Address);
#else
			descriptor->buffer_addr =
			    packet->desc[i].Address;
#endif
			descriptor->lower.data =
			    packet->desc[i].Length;

			/* Zero out status */
			descriptor->upper.data = 0;

			descriptor->lower.data |=
			    E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D;
			/* must set RS on every outgoing descriptor */
			descriptor->lower.data |=
			    E1000_TXD_CMD_RS;

			/* Check the wrap-around case */
			if (descriptor == tx_ring->tbd_last)
				next_desc = tx_ring->tbd_first;
			else
				next_desc++;

			desc_count++;
		}

		if (first_packet != NULL) {
			/*
			 * Count the checksum context descriptor for
			 * the first SwPacket.
			 */
			first_packet->num_desc++;
			first_packet = NULL;
		}

		packet = (PTX_SW_PACKET)
		    QUEUE_GET_NEXT(pending_list, &packet->Link);
	}

	ASSERT(descriptor);

	if (cksum_flags) {
		if (cksum_flags & HCK_IPV4_HDRCKSUM)
			((struct e1000_data_desc *)first_data_desc)->
				upper.fields.popts |= E1000_TXD_POPTS_IXSM;
		if (cksum_flags & HCK_PARTIALCKSUM)
			((struct e1000_data_desc *)first_data_desc)->
				upper.fields.popts |= E1000_TXD_POPTS_TXSM;
	}

	/*
	 * Last Descriptor of Packet needs End Of Packet (EOP), Report
	 * Status (RS) and append Ethernet CRC (IFCS) bits set.
	 */
	if (Adapter->TxInterruptDelay) {
		descriptor->lower.data |= E1000_TXD_CMD_IDE |
		    E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS;
	} else {
		descriptor->lower.data |=
		    E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS;
	}

	/*
	 * Sync the Tx descriptors DMA buffer
	 */
	sync_offset = tx_ring->tbd_next - tx_ring->tbd_first;
	sync_len = descriptor - tx_ring->tbd_next + 1;
	/* Check the wrap-around case */
	if (sync_len > 0) {
		(void) ddi_dma_sync(tx_ring->tbd_dma_handle,
		    sync_offset * sizeof (struct e1000_tx_desc),
		    sync_len * sizeof (struct e1000_tx_desc),
		    DDI_DMA_SYNC_FORDEV);
	} else {
		(void) ddi_dma_sync(tx_ring->tbd_dma_handle,
		    sync_offset * sizeof (struct e1000_tx_desc),
		    0,
		    DDI_DMA_SYNC_FORDEV);
		sync_len = descriptor - tx_ring->tbd_first + 1;
		(void) ddi_dma_sync(tx_ring->tbd_dma_handle,
		    0,
		    sync_len * sizeof (struct e1000_tx_desc),
		    DDI_DMA_SYNC_FORDEV);
	}

	tx_ring->tbd_next = next_desc;

	/*
	 * Advance the Transmit Descriptor Tail (Tdt), this tells the
	 * FX1000 that this frame is available to transmit.
	 */
	if (Adapter->Shared.mac_type == e1000_82547)
		e1000g_82547_tx_move_tail(tx_ring);
	else
		E1000_WRITE_REG(&Adapter->Shared, TDT,
		    (uint32_t)(next_desc - tx_ring->tbd_first));

	/* Put the pending SwPackets to the "Used" list */
	mutex_enter(&tx_ring->usedlist_lock);
	QUEUE_APPEND(&tx_ring->used_list, pending_list);
	mutex_exit(&tx_ring->usedlist_lock);

	return (desc_count);
}


/*
 * **********************************************************************
 * Name:	SetupTransmitStructures					*
 *									*
 * Description: This routine initializes all of the transmit related	*
 *	structures.  This includes the Transmit descriptors, the	*
 *	coalesce buffers, and the TX_SW_PACKETs structures.		*
 *									*
 *	NOTE -- The device must have been reset before this		*
 *		routine is called.					*
 *									*
 * Author:	Hari Seshadri						*
 * Functions Called : get_32bit_value					*
 *									*
 *									*
 *									*
 * Arguments:								*
 *	Adapter - A pointer to our context sensitive "Adapter"		*
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
SetupTransmitStructures(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	PTX_SW_PACKET packet;
	UINT i;
	uint32_t buf_high;
	uint32_t buf_low;
	uint32_t reg_tipg;
	uint32_t reg_tctl;
	uint32_t reg_tarc;
	uint16_t speed, duplex;
	int size;
	e1000g_tx_ring_t *tx_ring;

	hw = &Adapter->Shared;
	tx_ring = Adapter->tx_ring;

	/* init the lists */
	/*
	 * Here we don't need to protect the lists using the
	 * tx_usedlist_lock and tx_freelist_lock, for they have
	 * been protected by the chip_lock.
	 */
	QUEUE_INIT_LIST(&tx_ring->used_list);
	QUEUE_INIT_LIST(&tx_ring->free_list);

	/* Go through and set up each SW_Packet */
	packet = tx_ring->packet_area;
	for (i = 0; i < Adapter->NumTxSwPacket; i++, packet++) {
		/* Initialize this TX_SW_PACKET area */
		FreeTxSwPacket(packet);
		/* Add this TX_SW_PACKET to the free list */
		QUEUE_PUSH_TAIL(&tx_ring->free_list,
		    &packet->Link);
	}

	/* Setup TX descriptor pointers */
	tx_ring->tbd_next = tx_ring->tbd_first;
	tx_ring->tbd_oldest = tx_ring->tbd_first;

	/*
	 * Setup Hardware TX Registers
	 */
	/* Setup the Transmit Control Register (TCTL). */
	reg_tctl = E1000_TCTL_PSP | E1000_TCTL_EN |
	    (E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT) |
	    (E1000_FDX_COLLISION_DISTANCE << E1000_COLD_SHIFT);

	/* Enable the MULR bit */
	if (hw->bus_type == e1000_bus_type_pci_express)
		reg_tctl |= E1000_TCTL_MULR;

	E1000_WRITE_REG(hw, TCTL, reg_tctl);

	if ((hw->mac_type == e1000_82571) || (hw->mac_type == e1000_82572)) {
		e1000_get_speed_and_duplex(hw, &speed, &duplex);

		reg_tarc = E1000_READ_REG(hw, TARC0);
		reg_tarc |= (1 << 25);
		if (speed == SPEED_1000)
			reg_tarc |= (1 << 21);
		E1000_WRITE_REG(hw, TARC0, reg_tarc);

		reg_tarc = E1000_READ_REG(hw, TARC1);
		reg_tarc |= (1 << 25);
		if (reg_tctl & E1000_TCTL_MULR)
			reg_tarc &= ~(1 << 28);
		else
			reg_tarc |= (1 << 28);
		E1000_WRITE_REG(hw, TARC1, reg_tarc);

	} else if (hw->mac_type == e1000_80003es2lan) {
		reg_tarc = E1000_READ_REG(hw, TARC0);
		reg_tarc |= 1;
		if (hw->media_type == e1000_media_type_internal_serdes)
			reg_tarc |= (1 << 20);
		E1000_WRITE_REG(hw, TARC0, reg_tarc);

		reg_tarc = E1000_READ_REG(hw, TARC1);
		reg_tarc |= 1;
		E1000_WRITE_REG(hw, TARC1, reg_tarc);
	}

	/* Setup HW Base and Length of Tx descriptor area */
	size = (Adapter->NumTxDescriptors * sizeof (struct e1000_tx_desc));
	E1000_WRITE_REG(hw, TDLEN, size);
	size = E1000_READ_REG(hw, TDLEN);

	buf_low = (uint32_t)tx_ring->tbd_dma_addr;
	buf_high = (uint32_t)(tx_ring->tbd_dma_addr >> 32);

	E1000_WRITE_REG(hw, TDBAL, buf_low);
	E1000_WRITE_REG(hw, TDBAH, buf_high);

	/* Setup our HW Tx Head & Tail descriptor pointers */
	E1000_WRITE_REG(hw, TDH, 0);
	E1000_WRITE_REG(hw, TDT, 0);

	/* Set the default values for the Tx Inter Packet Gap timer */
	switch (hw->mac_type) {
	case e1000_82542_rev2_0:
	case e1000_82542_rev2_1:
		reg_tipg = DEFAULT_82542_TIPG_IPGT;
		reg_tipg |=
		    DEFAULT_82542_TIPG_IPGR1 << E1000_TIPG_IPGR1_SHIFT;
		reg_tipg |=
		    DEFAULT_82542_TIPG_IPGR2 << E1000_TIPG_IPGR2_SHIFT;
		break;
	default:
		if (hw->media_type == e1000_media_type_fiber)
			reg_tipg = DEFAULT_82543_TIPG_IPGT_FIBER;
		else
			reg_tipg = DEFAULT_82543_TIPG_IPGT_COPPER;
		reg_tipg |=
		    DEFAULT_82543_TIPG_IPGR1 << E1000_TIPG_IPGR1_SHIFT;
		reg_tipg |=
		    DEFAULT_82543_TIPG_IPGR2 << E1000_TIPG_IPGR2_SHIFT;
		break;
	}
	E1000_WRITE_REG(hw, TIPG, reg_tipg);

	/* Setup Transmit Interrupt Delay Value */
	if (Adapter->TxInterruptDelay) {
		E1000_WRITE_REG(hw, TIDV, Adapter->TxInterruptDelay);
	}

	/* For TCP/UDP checksum offload */
	tx_ring->cksum_stuff = 0;
	tx_ring->cksum_start = 0;
	tx_ring->cksum_flags = 0;

	/* Initialize tx parameters */
	Adapter->tx_bcopy_thresh = DEFAULTTXBCOPYTHRESHOLD;
	Adapter->tx_recycle_low_water = DEFAULTTXRECYCLELOWWATER;
	Adapter->tx_recycle_num = DEFAULTTXRECYCLENUM;
	Adapter->tx_intr_enable = B_TRUE;
	Adapter->tx_frags_limit =
	    (Adapter->Shared.max_frame_size / Adapter->tx_bcopy_thresh) + 2;
	if (Adapter->tx_frags_limit > (MAX_TX_DESC_PER_PACKET >> 1))
		Adapter->tx_frags_limit = (MAX_TX_DESC_PER_PACKET >> 1);
}

/*
 * **********************************************************************
 * Name:	e1000g_recycle						*
 *									*
 * Description: This routine cleans transmit packets.			*
 *									*
 *									*
 *									*
 * Arguments:								*
 *      Adapter - A pointer to our context sensitive "Adapter"		*
 *      structure.							*
 *									*
 * Returns:								*
 *      (none)								*
 * Functions Called:							*
 *	  None								*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  -----------------------------------------------------	*
 *									*
 * **********************************************************************
 */
int
e1000g_recycle(e1000g_tx_ring_t *tx_ring)
{
	struct e1000g *Adapter;
	LIST_DESCRIBER pending_list;
	PTX_SW_PACKET packet;
	e1000g_msg_chain_t *msg_chain;
	mblk_t *mp;
	mblk_t *nmp;
	struct e1000_tx_desc *descriptor;
	int desc_count;

	/*
	 * This function will examine each TxSwPacket in the 'used' queue
	 * if the e1000g is done with it then the associated resources (Tx
	 * Descriptors) will be "freed" and the TxSwPacket will be
	 * returned to the 'free' queue.
	 */
	Adapter = tx_ring->adapter;

	desc_count = 0;
	QUEUE_INIT_LIST(&pending_list);

	mutex_enter(&tx_ring->usedlist_lock);

	packet = (PTX_SW_PACKET) QUEUE_GET_HEAD(&tx_ring->used_list);
	if (packet == NULL) {
		mutex_exit(&tx_ring->usedlist_lock);
		Adapter->tx_recycle_fail = 0;
		Adapter->StallWatchdog = 0;
		return (0);
	}

	/*
	 * While there are still TxSwPackets in the used queue check them
	 */
	while (packet =
	    (PTX_SW_PACKET) QUEUE_GET_HEAD(&tx_ring->used_list)) {

		/*
		 * Get hold of the next descriptor that the e1000g will
		 * report status back to (this will be the last descriptor
		 * of a given TxSwPacket). We only want to free the
		 * TxSwPacket (and it resources) if the e1000g is done
		 * with ALL of the descriptors.  If the e1000g is done
		 * with the last one then it is done with all of them.
		 */
		ASSERT(packet->num_desc);
		descriptor = tx_ring->tbd_oldest +
		    (packet->num_desc - 1);

		/* Check for wrap case */
		if (descriptor > tx_ring->tbd_last)
			descriptor -= Adapter->NumTxDescriptors;

		/* Sync the Tx descriptor DMA buffer */
		(void) ddi_dma_sync(tx_ring->tbd_dma_handle,
		    (descriptor - tx_ring->tbd_first) *
		    sizeof (struct e1000_tx_desc),
		    sizeof (struct e1000_tx_desc),
		    DDI_DMA_SYNC_FORCPU);

		/*
		 * If the descriptor done bit is set free TxSwPacket and
		 * associated resources
		 */
		if (descriptor->upper.fields.status & E1000_TXD_STAT_DD) {
			QUEUE_POP_HEAD(&tx_ring->used_list);
			QUEUE_PUSH_TAIL(&pending_list, &packet->Link);

			if (descriptor == tx_ring->tbd_last)
				tx_ring->tbd_oldest =
				    tx_ring->tbd_first;
			else
				tx_ring->tbd_oldest =
				    descriptor + 1;

			desc_count += packet->num_desc;

			if (desc_count >= Adapter->tx_recycle_num)
				break;
		} else {
			/*
			 * Found a TxSwPacket that the e1000g is not done
			 * with then there is no reason to check the rest
			 * of the queue.
			 */
			break;
		}
	}

	mutex_exit(&tx_ring->usedlist_lock);

	if (desc_count == 0) {
		Adapter->tx_recycle_fail++;
		Adapter->tx_recycle_none++;
		return (0);
	}

	Adapter->tx_recycle_fail = 0;
	Adapter->StallWatchdog = 0;

	mp = NULL;
	nmp = NULL;
	packet = (PTX_SW_PACKET) QUEUE_GET_HEAD(&pending_list);
	ASSERT(packet != NULL);
	while (packet != NULL) {
		if (packet->mp != NULL) {
			ASSERT(packet->mp->b_next == NULL);
			/* Assemble the message chain */
			if (mp == NULL) {
				mp = packet->mp;
				nmp = packet->mp;
			} else {
				nmp->b_next = packet->mp;
				nmp = packet->mp;
			}
			/* Disconnect the message from the sw packet */
			packet->mp = NULL;
		}

		/* Free the TxSwPackets */
		FreeTxSwPacket(packet);

		packet = (PTX_SW_PACKET)
		    QUEUE_GET_NEXT(&pending_list, &packet->Link);
	}

	/* Save the message chain */
	if (mp != NULL) {
		msg_chain = Adapter->tx_msg_chain;
		mutex_enter(&msg_chain->lock);
		if (msg_chain->head == NULL) {
			msg_chain->head = mp;
			msg_chain->tail = nmp;
		} else {
			msg_chain->tail->b_next = mp;
			msg_chain->tail = nmp;
		}
		mutex_exit(&msg_chain->lock);

		/*
		 * If the tx interrupt is enabled, the messages will be freed
		 * in the tx interrupt; Otherwise, they are freed here by
		 * triggering a soft interrupt.
		 */
		if (!Adapter->tx_intr_enable)
			ddi_intr_trigger_softint(Adapter->tx_softint_handle,
			    NULL);
	}

	/* Return the TxSwPackets back to the FreeList */
	mutex_enter(&tx_ring->freelist_lock);
	QUEUE_APPEND(&tx_ring->free_list, &pending_list);
	mutex_exit(&tx_ring->freelist_lock);

	return (desc_count);
}

/*
 * 82544 Coexistence issue workaround:
 *    There are 2 issues.
 *    1. If a 32 bit split completion happens from P64H2 and another
 *	agent drives a 64 bit request/split completion after ONLY
 *	1 idle clock (BRCM/Emulex/Adaptec fiber channel cards) then
 *	82544 has a problem where in to clock all the data in, it
 *	looks at REQ64# signal and since it has changed so fast (i.e. 1
 *	idle clock turn around), it will fail to clock all the data in.
 *	Data coming from certain ending addresses has exposure to this issue.
 *
 * To detect this issue, following equation can be used...
 *	SIZE[3:0] + ADDR[2:0] = SUM[3:0].
 *	If SUM[3:0] is in between 1 to 4, we will have this issue.
 *
 * ROOT CAUSE:
 *	The erratum involves the 82544 PCIX elasticity FIFO implementations as
 *	64-bit FIFO's and flushing of the final partial-bytes corresponding
 *	to the end of a requested read burst. Under a specific burst condition
 *	of ending-data alignment and 32-byte split-completions, the final
 *	byte(s) of split-completion data require an extra clock cycle to flush
 *	into 64-bit FIFO orientation.  An incorrect logic dependency on the
 *	REQ64# signal occurring during during this clock cycle may cause the
 *	residual byte(s) to be lost, thereby rendering the internal DMA client
 *	forever awaiting the final byte(s) for an outbound data-fetch.  The
 *	erratum is confirmed to *only* occur if certain subsequent external
 *	64-bit PCIX bus transactions occur immediately (minimum possible bus
 *	turn- around) following the odd-aligned 32-bit split-completion
 *	containing the final byte(s).  Intel has confirmed that this has been
 *	seen only with chipset/bridges which have the capability to provide
 *	32-bit split-completion data, and in the presence of newer PCIX bus
 *	agents which fully-optimize the inter-transaction turn-around (zero
 *	additional initiator latency when pre-granted bus ownership).
 *
 *   	This issue does not exist in PCI bus mode, when any agent is operating
 *	in 32 bit only mode or on chipsets that do not do 32 bit split
 *	completions for 64 bit read requests (Serverworks chipsets). P64H2 does
 *	32 bit split completions for any read request that has bit 2 set to 1
 *	for the requested address and read request size is more than 8 bytes.
 *
 *   2. Another issue is related to 82544 driving DACs under the similar
 *	scenario (32 bit split completion followed by 64 bit transaction with
 *	only 1 cycle turnaround). This issue is still being root caused. We
 *	think that both of these issues can be avoided if following workaround
 *	is implemented. It seems DAC issues is related to ending addresses being
 *	0x9, 0xA, 0xB, 0xC and hence ending up at odd boundaries in elasticity
 *	FIFO which does not get flushed due to REQ64# dependency. We will only
 *	know the full story after it has been simulated successfully by HW team.
 *
 * WORKAROUND:
 *	Make sure we do not have ending address as 1,2,3,4(Hang) or 9,a,b,c(DAC)
 */
static uint32_t
e1000g_fill_82544_desc(uint64_t Address,
    size_t Length, PDESC_ARRAY desc_array)
{
	/*
	 * Since issue is sensitive to length and address.
	 * Let us first check the address...
	 */
	uint32_t safe_terminator;

	if (Length <= 4) {
		desc_array->Descriptor[0].Address = Address;
		desc_array->Descriptor[0].Length = Length;
		desc_array->Elements = 1;
		return (desc_array->Elements);
	}
	safe_terminator =
	    (uint32_t)((((uint32_t)Address & 0x7) +
		(Length & 0xF)) & 0xF);
	/*
	 * if it does not fall between 0x1 to 0x4 and 0x9 to 0xC then
	 * return
	 */
	if (safe_terminator == 0 ||
	    (safe_terminator > 4 &&
		safe_terminator < 9) ||
	    (safe_terminator > 0xC && safe_terminator <= 0xF)) {
		desc_array->Descriptor[0].Address = Address;
		desc_array->Descriptor[0].Length = Length;
		desc_array->Elements = 1;
		return (desc_array->Elements);
	}

	desc_array->Descriptor[0].Address = Address;
	desc_array->Descriptor[0].Length = Length - 4;
	desc_array->Descriptor[1].Address = Address + (Length - 4);
	desc_array->Descriptor[1].Length = 4;
	desc_array->Elements = 2;
	return (desc_array->Elements);
}

static int
e1000g_tx_copy(struct e1000g *Adapter, PTX_SW_PACKET packet,
    mblk_t *mp, uint32_t force_bcopy)
{
	size_t len;
	size_t len1;
	dma_buffer_t *tx_buf;
	mblk_t *nmp;
	boolean_t finished;
	int desc_count;

	desc_count = 0;
	tx_buf = packet->tx_buf;
	len = MBLKL(mp);

	ASSERT((tx_buf->len + len) <= tx_buf->size);

	if (len > 0) {
		bcopy(mp->b_rptr,
		    tx_buf->address + tx_buf->len,
		    len);
		tx_buf->len += len;

		packet->num_mblk_frag++;
	}

	nmp = mp->b_cont;
	if (nmp == NULL) {
		finished = B_TRUE;
	} else {
		len1 = MBLKL(nmp);
		if ((tx_buf->len + len1) > tx_buf->size)
			finished = B_TRUE;
		else if (force_bcopy)
			finished = B_FALSE;
		else if (len1 > Adapter->tx_bcopy_thresh)
			finished = B_TRUE;
		else
			finished = B_FALSE;
	}

	if (finished) {
		if (tx_buf->len > len)
			Adapter->tx_multi_copy++;

		/*
		 * If the packet is smaller than 64 bytes, which is the
		 * minimum ethernet packet size, pad the packet to make
		 * it at least 60 bytes. The hardware will add 4 bytes
		 * for CRC.
		 */
		if (force_bcopy & FORCE_BCOPY_UNDER_SIZE) {
			ASSERT(tx_buf->len < MINIMUM_ETHERNET_PACKET_SIZE);

			bzero(tx_buf->address + tx_buf->len,
			    MINIMUM_ETHERNET_PACKET_SIZE - tx_buf->len);
			tx_buf->len = MINIMUM_ETHERNET_PACKET_SIZE;
		}

		switch (packet->dma_type) {
#ifdef __sparc
		case USE_DVMA:
			dvma_sync(tx_buf->dma_handle, 0, DDI_DMA_SYNC_FORDEV);
			break;
#endif
		case USE_DMA:
			(void) ddi_dma_sync(tx_buf->dma_handle, 0,
			    tx_buf->len, DDI_DMA_SYNC_FORDEV);
			break;
		default:
			ASSERT(B_FALSE);
			break;
		}

		packet->data_transfer_type = USE_BCOPY;

		desc_count = e1000g_fill_tx_desc(Adapter,
		    packet,
		    tx_buf->dma_address,
		    tx_buf->len);

		if (desc_count <= 0)
			return (-1);
	}

	return (desc_count);
}

static int
e1000g_tx_bind(struct e1000g *Adapter, PTX_SW_PACKET packet, mblk_t *mp)
{
	int j;
	int mystat;
	size_t len;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	int desc_count;
	uint32_t desc_total;

	desc_total = 0;
	len = MBLKL(mp);

	/*
	 * ddi_dma_addr_bind_handle() allocates  DMA  resources  for  a
	 * memory  object such that a device can perform DMA to or from
	 * the object.  DMA resources  are  allocated  considering  the
	 * device's  DMA  attributes  as  expressed by ddi_dma_attr(9S)
	 * (see ddi_dma_alloc_handle(9F)).
	 *
	 * ddi_dma_addr_bind_handle() fills in  the  first  DMA  cookie
	 * pointed  to by cookiep with the appropriate address, length,
	 * and bus type. *ccountp is set to the number of DMA  cookies
	 * representing this DMA object. Subsequent DMA cookies must be
	 * retrieved by calling ddi_dma_nextcookie(9F)  the  number  of
	 * times specified by *countp - 1.
	 */
	switch (packet->dma_type) {
#ifdef __sparc
	case USE_DVMA:
		dvma_kaddr_load(packet->tx_dma_handle,
		    (caddr_t)mp->b_rptr, len, 0, &dma_cookie);

		dvma_sync(packet->tx_dma_handle, 0,
		    DDI_DMA_SYNC_FORDEV);

		ncookies = 1;
		packet->data_transfer_type = USE_DVMA;
		break;
#endif
	case USE_DMA:
		if ((mystat = ddi_dma_addr_bind_handle(
			packet->tx_dma_handle, NULL,
			(caddr_t)mp->b_rptr, len,
			DDI_DMA_WRITE | DDI_DMA_STREAMING,
			DDI_DMA_DONTWAIT, 0, &dma_cookie,
			&ncookies)) != DDI_DMA_MAPPED) {

			e1000g_log(Adapter, CE_WARN,
			    "Couldn't bind mblk buffer to Tx DMA handle: "
			    "return: %X, Pkt: %X\n",
			    mystat, packet);
			return (-1);
		}

		/*
		 * An implicit ddi_dma_sync() is done when the
		 * ddi_dma_addr_bind_handle() is called. So we
		 * don't need to explicitly call ddi_dma_sync()
		 * here any more.
		 */
		ASSERT(ncookies);
		if (ncookies > 1)
			Adapter->tx_multi_cookie++;

		/*
		 * The data_transfer_type value must be set after the handle
		 * has been bound, for it will be used in FreeTxSwPacket()
		 * to decide whether we need to unbind the handle.
		 */
		packet->data_transfer_type = USE_DMA;
		break;
	default:
		ASSERT(B_FALSE);
		break;
	}

	packet->num_mblk_frag++;

	/*
	 * Each address could span thru multpile cookie..
	 * Each cookie will have one descriptor
	 */
	for (j = ncookies; j != 0; j--) {

		desc_count = e1000g_fill_tx_desc(Adapter,
		    packet,
		    dma_cookie.dmac_laddress,
		    dma_cookie.dmac_size);

		if (desc_count <= 0)
			return (-1);

		desc_total += desc_count;

		/*
		 * ddi_dma_nextcookie() retrieves subsequent DMA
		 * cookies for a DMA object.
		 * ddi_dma_nextcookie() fills in the
		 * ddi_dma_cookie(9S) structure pointed to by
		 * cookiep.  The ddi_dma_cookie(9S) structure
		 * must be allocated prior to calling
		 * ddi_dma_nextcookie(). The DMA cookie count
		 * returned by ddi_dma_buf_bind_handle(9F),
		 * ddi_dma_addr_bind_handle(9F), or
		 * ddi_dma_getwin(9F) indicates the number of DMA
		 * cookies a DMA object consists of.  If the
		 * resulting cookie count, N, is larger than 1,
		 * ddi_dma_nextcookie() must be called N-1 times
		 * to retrieve all DMA cookies.
		 */
		if (j > 1) {
			ddi_dma_nextcookie(packet->tx_dma_handle,
			    &dma_cookie);
		}
	}

	return (desc_total);
}

static void
e1000g_fill_context_descriptor(e1000g_tx_ring_t *tx_ring,
    struct e1000_context_desc *cksum_desc)
{
	if (tx_ring->cksum_flags & HCK_IPV4_HDRCKSUM) {
		cksum_desc->lower_setup.ip_fields.ipcss =
		    tx_ring->ether_header_size;
		cksum_desc->lower_setup.ip_fields.ipcso =
		    tx_ring->ether_header_size +
		    offsetof(struct ip, ip_sum);
		cksum_desc->lower_setup.ip_fields.ipcse =
		    tx_ring->ether_header_size +
		    sizeof (struct ip) - 1;
	} else
		cksum_desc->lower_setup.ip_config = 0;

	if (tx_ring->cksum_flags & HCK_PARTIALCKSUM) {
		/*
		 * The packet with same protocol has the following
		 * stuff and start offset:
		 * |  Protocol  | Stuff  | Start  | Checksum
		 * |		| Offset | Offset | Enable
		 * | IPv4 + TCP |  0x24  |  0x14  |  Yes
		 * | IPv4 + UDP |  0x1A  |  0x14  |  Yes
		 * | IPv6 + TCP |  0x20  |  0x10  |  No
		 * | IPv6 + UDP |  0x14  |  0x10  |  No
		 */
		cksum_desc->upper_setup.tcp_fields.tucss =
		    tx_ring->cksum_start + tx_ring->ether_header_size;
		cksum_desc->upper_setup.tcp_fields.tucso =
		    tx_ring->cksum_stuff + tx_ring->ether_header_size;
		cksum_desc->upper_setup.tcp_fields.tucse = 0;
	} else
		cksum_desc->upper_setup.tcp_config = 0;

	cksum_desc->cmd_and_length = E1000_TXD_CMD_DEXT;

	/*
	 * Zero out the options for TCP Segmentation Offload,
	 * since we don't support it in this version
	 */
	cksum_desc->tcp_seg_setup.data = 0;
}

static int
e1000g_fill_tx_desc(struct e1000g *Adapter,
    PTX_SW_PACKET packet, uint64_t address, size_t size)
{
	PADDRESS_LENGTH_PAIR desc;
	int desc_count;

	desc_count = 0;

	if ((Adapter->Shared.bus_type == e1000_bus_type_pcix) &&
	    (Adapter->Shared.mac_type == e1000_82544)) {

		desc_count = e1000g_tx_workaround_PCIX_82544(Adapter,
		    packet, address, size);

	} else if ((Adapter->Shared.mac_type == e1000_82544) &&
	    (size > JUMBO_FRAG_LENGTH)) {

		desc_count = e1000g_tx_workaround_jumbo_82544(Adapter,
		    packet, address, size);

	} else {
		ASSERT(packet->num_desc < MAX_TX_DESC_PER_PACKET);

		desc = &packet->desc[packet->num_desc];

		desc->Address = address;
		desc->Length = size;

		packet->num_desc++;
		desc_count++;
	}

	return (desc_count);
}

static int
e1000g_tx_workaround_PCIX_82544(struct e1000g *Adapter,
    PTX_SW_PACKET packet, uint64_t address, size_t size)
{
	PADDRESS_LENGTH_PAIR desc;
	int desc_count;
	long size_left;
	size_t len;
	uint32_t counter;
	uint32_t array_elements;
	DESC_ARRAY desc_array;

	/*
	 * Coexist Workaround for cordova: RP: 07/04/03
	 *
	 * RP: ERRATA: Workaround ISSUE:
	 * 8kb_buffer_Lockup CONTROLLER: Cordova Breakup
	 * Eachbuffer in to 8kb pieces until the
	 * remainder is < 8kb
	 */
	size_left = size;
	desc_count = 0;

	while (size_left > 0) {
		if (size_left > MAX_TX_BUF_SIZE)
			len = MAX_TX_BUF_SIZE;
		else
			len = size_left;

		array_elements = e1000g_fill_82544_desc(address,
		    len, &desc_array);

		for (counter = 0; counter < array_elements; counter++) {
			ASSERT(packet->num_desc < MAX_TX_DESC_PER_PACKET);
			if (packet->num_desc >= MAX_TX_DESC_PER_PACKET) {
				e1000g_log(Adapter, CE_WARN,
				    "No enough preparing tx descriptors");
				return (-1);
			}
			/*
			 * Put in the buffer address
			 */
			desc = &packet->desc[packet->num_desc];

			desc->Address =
			    desc_array.Descriptor[counter].Address;
			desc->Length =
			    desc_array.Descriptor[counter].Length;

			packet->num_desc++;
			desc_count++;
		} /* for */

		/*
		 * Update the buffer address and length
		 */
		address += MAX_TX_BUF_SIZE;
		size_left -= MAX_TX_BUF_SIZE;
	} /* while */

	return (desc_count);
}

static int
e1000g_tx_workaround_jumbo_82544(struct e1000g *Adapter,
    PTX_SW_PACKET packet, uint64_t address, size_t size)
{
	PADDRESS_LENGTH_PAIR desc;
	int desc_count;
	long size_left;
	uint32_t offset;

	/*
	 * Workaround for Jumbo Frames on Cordova
	 * PSD 06/01/2001
	 */
	size_left = size;
	desc_count = 0;
	offset = 0;
	while (size_left > 0) {
		ASSERT(packet->num_desc < MAX_TX_DESC_PER_PACKET);
		if (packet->num_desc >= MAX_TX_DESC_PER_PACKET) {
			e1000g_log(Adapter, CE_WARN,
			    "No enough preparing tx descriptors");
			return (-1);
		}

		desc = &packet->desc[packet->num_desc];

		desc->Address = address + offset;

		if (size_left > JUMBO_FRAG_LENGTH)
			desc->Length = JUMBO_FRAG_LENGTH;
		else
			desc->Length = size_left;

		packet->num_desc++;
		desc_count++;

		offset += desc->Length;
		size_left -= JUMBO_FRAG_LENGTH;
	}

	return (desc_count);
}

static void
e1000g_82547_tx_move_tail_work(e1000g_tx_ring_t *tx_ring)
{
	uint16_t hw_tdt;
	uint16_t sw_tdt;
	struct e1000_tx_desc *tx_desc;
	uint16_t length = 0;
	boolean_t eop = B_FALSE;
	struct e1000g *Adapter;

	Adapter = tx_ring->adapter;

	hw_tdt = E1000_READ_REG(&Adapter->Shared, TDT);
	sw_tdt = tx_ring->tbd_next - tx_ring->tbd_first;

	while (hw_tdt != sw_tdt) {
		tx_desc = &(tx_ring->tbd_first[hw_tdt]);
		length += tx_desc->lower.flags.length;
		eop = tx_desc->lower.data & E1000_TXD_CMD_EOP;
		if (++hw_tdt == Adapter->NumTxDescriptors)
			hw_tdt = 0;

		if (eop) {
			if ((Adapter->link_duplex == HALF_DUPLEX) &&
			    e1000_82547_fifo_workaround(&Adapter->Shared,
				length) != E1000_SUCCESS) {
				if (tx_ring->timer_enable_82547) {
					ASSERT(tx_ring->timer_id_82547 == 0);
					tx_ring->timer_id_82547 =
					    timeout(e1000g_82547_timeout,
						(void *)Adapter,
						drv_usectohz(10000));
				}
				return;

			} else {
				E1000_WRITE_REG(&Adapter->Shared, TDT,
				    hw_tdt);
				e1000_update_tx_fifo_head(&Adapter->Shared,
				    length);
				length = 0;
			}
		}
	}
}

static void
e1000g_82547_timeout(void *arg)
{
	e1000g_tx_ring_t *tx_ring;

	tx_ring = (e1000g_tx_ring_t *)arg;

	mutex_enter(&tx_ring->tx_lock);

	tx_ring->timer_id_82547 = 0;
	e1000g_82547_tx_move_tail_work(tx_ring);

	mutex_exit(&tx_ring->tx_lock);
}

static void
e1000g_82547_tx_move_tail(e1000g_tx_ring_t *tx_ring)
{
	timeout_id_t tid;

	ASSERT(MUTEX_HELD(&tx_ring->tx_lock));

	tid = tx_ring->timer_id_82547;
	tx_ring->timer_id_82547 = 0;
	if (tid != 0) {
		tx_ring->timer_enable_82547 = B_FALSE;
		mutex_exit(&tx_ring->tx_lock);

		(void) untimeout(tid);

		mutex_enter(&tx_ring->tx_lock);
	}
	tx_ring->timer_enable_82547 = B_TRUE;
	e1000g_82547_tx_move_tail_work(tx_ring);
}
