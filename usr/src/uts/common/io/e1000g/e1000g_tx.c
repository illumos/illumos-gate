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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * **********************************************************************
 *									*
 * Module Name:								*
 *   e1000g_tx.c							*
 *									*
 * Abstract:								*
 *   This file contains some routines that take care of Transmit,	*
 *   make the hardware to send the data pointed by the packet out	*
 *   on to the physical medium.						*
 *									*
 * **********************************************************************
 */

#include "e1000g_sw.h"
#include "e1000g_debug.h"

static boolean_t e1000g_send(struct e1000g *, mblk_t *);
static int e1000g_tx_copy(e1000g_tx_ring_t *,
    p_tx_sw_packet_t, mblk_t *, uint32_t);
static int e1000g_tx_bind(e1000g_tx_ring_t *,
    p_tx_sw_packet_t, mblk_t *);
static boolean_t check_cksum_context(e1000g_tx_ring_t *, cksum_data_t *);
static int e1000g_fill_tx_ring(e1000g_tx_ring_t *, LIST_DESCRIBER *,
    cksum_data_t *);
static void e1000g_fill_context_descriptor(cksum_data_t *,
    struct e1000_context_desc *);
static int e1000g_fill_tx_desc(e1000g_tx_ring_t *,
    p_tx_sw_packet_t, uint64_t, size_t);
static uint32_t e1000g_fill_82544_desc(uint64_t Address, size_t Length,
    p_desc_array_t desc_array);
static int e1000g_tx_workaround_PCIX_82544(p_tx_sw_packet_t, uint64_t, size_t);
static int e1000g_tx_workaround_jumbo_82544(p_tx_sw_packet_t, uint64_t, size_t);
static void e1000g_82547_timeout(void *);
static void e1000g_82547_tx_move_tail(e1000g_tx_ring_t *);
static void e1000g_82547_tx_move_tail_work(e1000g_tx_ring_t *);

#ifndef E1000G_DEBUG
#pragma inline(e1000g_tx_copy)
#pragma inline(e1000g_tx_bind)
#pragma inline(check_cksum_context)
#pragma inline(e1000g_fill_tx_ring)
#pragma inline(e1000g_fill_context_descriptor)
#pragma inline(e1000g_fill_tx_desc)
#pragma inline(e1000g_fill_82544_desc)
#pragma inline(e1000g_tx_workaround_PCIX_82544)
#pragma inline(e1000g_tx_workaround_jumbo_82544)
#pragma inline(e1000g_free_tx_swpkt)
#endif

/*
 * e1000g_free_tx_swpkt	- free up the tx sw packet
 *
 * Unbind the previously bound DMA handle for a given
 * transmit sw packet. And reset the sw packet data.
 */
void
e1000g_free_tx_swpkt(register p_tx_sw_packet_t packet)
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

mblk_t *
e1000g_m_tx(void *arg, mblk_t *mp)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	mblk_t *next;

	rw_enter(&Adapter->chip_lock, RW_READER);

	if ((Adapter->chip_state != E1000G_START) ||
	    (Adapter->link_state != LINK_STATE_UP)) {
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
 * e1000g_send -  send packets onto the wire
 *
 * Called from e1000g_m_tx with an mblk ready to send. this
 * routine sets up the transmit descriptors and sends data to
 * the wire. It also pushes the just transmitted packet to
 * the used tx sw packet list.
 */
static boolean_t
e1000g_send(struct e1000g *Adapter, mblk_t *mp)
{
	struct e1000_hw *hw;
	p_tx_sw_packet_t packet;
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
	cksum_data_t cksum;

	hw = &Adapter->shared;
	tx_ring = Adapter->tx_ring;

	/* Get the total size and frags number of the message */
	force_bcopy = 0;
	frag_count = 0;
	msg_size = 0;
	for (nmp = mp; nmp; nmp = nmp->b_cont) {
		frag_count++;
		msg_size += MBLKL(nmp);
	}

	/* Make sure packet is less than the max frame size */
	if (msg_size > hw->mac.max_frame_size - ETHERFCSL) {
		/*
		 * For the over size packet, we'll just drop it.
		 * So we return B_TRUE here.
		 */
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Tx packet out of bound. length = %d \n", msg_size);
		E1000G_STAT(tx_ring->stat_over_size);
		freemsg(mp);
		return (B_TRUE);
	}

	/*
	 * Check and reclaim tx descriptors.
	 * This low water mark check should be done all the time as
	 * Transmit interrupt delay can produce Transmit interrupts little
	 * late and that may cause few problems related to reaping Tx
	 * Descriptors... As you may run short of them before getting any
	 * transmit interrupt...
	 */
	if (tx_ring->resched_needed ||
	    (tx_ring->tbd_avail < Adapter->tx_recycle_thresh)) {
		(void) e1000g_recycle(tx_ring);
		E1000G_DEBUG_STAT(tx_ring->stat_recycle);

		if (tx_ring->tbd_avail < DEFAULT_TX_NO_RESOURCE) {
			E1000G_DEBUG_STAT(tx_ring->stat_lack_desc);
			goto tx_no_resource;
		}
	}

	/*
	 * If there are many frags of the message, then bcopy them
	 * into one tx descriptor buffer will get better performance.
	 */
	if ((frag_count >= tx_ring->frags_limit) &&
	    (msg_size <= Adapter->tx_buffer_size)) {
		E1000G_DEBUG_STAT(tx_ring->stat_exceed_frags);
		force_bcopy |= FORCE_BCOPY_EXCEED_FRAGS;
	}

	/*
	 * If the message size is less than the minimum ethernet packet size,
	 * we'll use bcopy to send it, and padd it to 60 bytes later.
	 */
	if (msg_size < ETHERMIN) {
		E1000G_DEBUG_STAT(tx_ring->stat_under_size);
		force_bcopy |= FORCE_BCOPY_UNDER_SIZE;
	}

	/* Initialize variables */
	desc_count = 1;	/* The initial value should be greater than 0 */
	desc_total = 0;
	QUEUE_INIT_LIST(&pending_list);

	/* Retrieve checksum info */
	hcksum_retrieve(mp, NULL, NULL, &cksum.cksum_start, &cksum.cksum_stuff,
	    NULL, NULL, &cksum.cksum_flags);

	if (((struct ether_vlan_header *)mp->b_rptr)->ether_tpid ==
	    htons(ETHERTYPE_VLAN))
		cksum.ether_header_size = sizeof (struct ether_vlan_header);
	else
		cksum.ether_header_size = sizeof (struct ether_header);

	/* Process each mblk fragment and fill tx descriptors */
	packet = NULL;
	nmp = mp;
	while (nmp) {
		tmp = nmp->b_cont;

		len = MBLKL(nmp);
		/* Check zero length mblks */
		if (len == 0) {
			E1000G_DEBUG_STAT(tx_ring->stat_empty_frags);
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
			packet = (p_tx_sw_packet_t)
			    QUEUE_POP_HEAD(&tx_ring->free_list);
			mutex_exit(&tx_ring->freelist_lock);

			if (packet == NULL) {
				E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
				    "No Tx SwPacket available\n");
				E1000G_STAT(tx_ring->stat_no_swpkt);
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
			    e1000g_tx_copy(tx_ring, packet, nmp, force_bcopy);
			E1000G_DEBUG_STAT(tx_ring->stat_copy);
		} else {
			desc_count =
			    e1000g_tx_bind(tx_ring, packet, nmp);
			E1000G_DEBUG_STAT(tx_ring->stat_bind);
		}

		if (desc_count > 0)
			desc_total += desc_count;
		else if (desc_count < 0)
			goto tx_send_failed;

		nmp = tmp;
	}

	/* Assign the message to the last sw packet */
	ASSERT(packet);
	ASSERT(packet->mp == NULL);
	packet->mp = mp;

	/* Try to recycle the tx descriptors again */
	if (tx_ring->tbd_avail < (desc_total + 2)) {
		E1000G_DEBUG_STAT(tx_ring->stat_recycle_retry);
		(void) e1000g_recycle(tx_ring);
	}

	mutex_enter(&tx_ring->tx_lock);

	/*
	 * If the number of available tx descriptors is not enough for transmit
	 * (one redundant descriptor and one hw checksum context descriptor are
	 * included), then return failure.
	 */
	if (tx_ring->tbd_avail < (desc_total + 2)) {
		E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
		    "No Enough Tx descriptors\n");
		E1000G_STAT(tx_ring->stat_no_desc);
		mutex_exit(&tx_ring->tx_lock);
		goto tx_send_failed;
	}

	desc_count = e1000g_fill_tx_ring(tx_ring, &pending_list, &cksum);

	mutex_exit(&tx_ring->tx_lock);

	ASSERT(desc_count > 0);

	/* Send successful */
	return (B_TRUE);

tx_send_failed:
	/*
	 * Enable Transmit interrupts, so that the interrupt routine can
	 * call mac_tx_update() when transmit descriptors become available.
	 */
	tx_ring->resched_needed = B_TRUE;
	if (!Adapter->tx_intr_enable)
		e1000g_mask_tx_interrupt(Adapter);

	/* Free pending TxSwPackets */
	packet = (p_tx_sw_packet_t)QUEUE_GET_HEAD(&pending_list);
	while (packet) {
		packet->mp = NULL;
		e1000g_free_tx_swpkt(packet);
		packet = (p_tx_sw_packet_t)
		    QUEUE_GET_NEXT(&pending_list, &packet->Link);
	}

	/* Return pending TxSwPackets to the "Free" list */
	mutex_enter(&tx_ring->freelist_lock);
	QUEUE_APPEND(&tx_ring->free_list, &pending_list);
	mutex_exit(&tx_ring->freelist_lock);

	E1000G_STAT(tx_ring->stat_send_fail);

	/* Message will be scheduled for re-transmit */
	return (B_FALSE);

tx_no_resource:
	/*
	 * Enable Transmit interrupts, so that the interrupt routine can
	 * call mac_tx_update() when transmit descriptors become available.
	 */
	tx_ring->resched_needed = B_TRUE;
	if (!Adapter->tx_intr_enable)
		e1000g_mask_tx_interrupt(Adapter);

	/* Message will be scheduled for re-transmit */
	return (B_FALSE);
}

static boolean_t
check_cksum_context(e1000g_tx_ring_t *tx_ring, cksum_data_t *cksum)
{
	boolean_t cksum_load;
	cksum_data_t *last;

	cksum_load = B_FALSE;
	last = &tx_ring->cksum_data;

	if (cksum->cksum_flags != 0) {
		if ((cksum->ether_header_size != last->ether_header_size) ||
		    (cksum->cksum_flags != last->cksum_flags) ||
		    (cksum->cksum_stuff != last->cksum_stuff) ||
		    (cksum->cksum_start != last->cksum_start)) {

			cksum_load = B_TRUE;
		}
	}

	return (cksum_load);
}

static int
e1000g_fill_tx_ring(e1000g_tx_ring_t *tx_ring, LIST_DESCRIBER *pending_list,
    cksum_data_t *cksum)
{
	struct e1000g *Adapter;
	struct e1000_hw *hw;
	p_tx_sw_packet_t first_packet;
	p_tx_sw_packet_t packet;
	boolean_t cksum_load;
	struct e1000_tx_desc *first_data_desc;
	struct e1000_tx_desc *next_desc;
	struct e1000_tx_desc *descriptor;
	int desc_count;
	int i;

	Adapter = tx_ring->adapter;
	hw = &Adapter->shared;

	desc_count = 0;
	first_packet = NULL;
	first_data_desc = NULL;
	descriptor = NULL;

	next_desc = tx_ring->tbd_next;

	/* IP Head/TCP/UDP checksum offload */
	cksum_load = check_cksum_context(tx_ring, cksum);

	if (cksum_load) {
		first_packet = (p_tx_sw_packet_t)QUEUE_GET_HEAD(pending_list);

		descriptor = next_desc;

		e1000g_fill_context_descriptor(cksum,
		    (struct e1000_context_desc *)descriptor);

		/* Check the wrap-around case */
		if (descriptor == tx_ring->tbd_last)
			next_desc = tx_ring->tbd_first;
		else
			next_desc++;

		desc_count++;
	}

	first_data_desc = next_desc;

	packet = (p_tx_sw_packet_t)QUEUE_GET_HEAD(pending_list);
	while (packet) {
		ASSERT(packet->num_desc);

		for (i = 0; i < packet->num_desc; i++) {
			ASSERT(tx_ring->tbd_avail > 0);

			descriptor = next_desc;
			descriptor->buffer_addr =
			    packet->desc[i].address;
			descriptor->lower.data =
			    packet->desc[i].length;

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

		packet = (p_tx_sw_packet_t)
		    QUEUE_GET_NEXT(pending_list, &packet->Link);
	}

	ASSERT(descriptor);

	if (cksum->cksum_flags) {
		if (cksum->cksum_flags & HCK_IPV4_HDRCKSUM)
			((struct e1000_data_desc *)first_data_desc)->
			    upper.fields.popts |= E1000_TXD_POPTS_IXSM;
		if (cksum->cksum_flags & HCK_PARTIALCKSUM)
			((struct e1000_data_desc *)first_data_desc)->
			    upper.fields.popts |= E1000_TXD_POPTS_TXSM;
	}

	/*
	 * Last Descriptor of Packet needs End Of Packet (EOP), Report
	 * Status (RS) and append Ethernet CRC (IFCS) bits set.
	 */
	if (Adapter->tx_intr_delay) {
		descriptor->lower.data |= E1000_TXD_CMD_IDE |
		    E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS;
	} else {
		descriptor->lower.data |=
		    E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS;
	}

	/*
	 * Sync the Tx descriptors DMA buffer
	 */
	(void) ddi_dma_sync(tx_ring->tbd_dma_handle,
	    0, 0, DDI_DMA_SYNC_FORDEV);

	tx_ring->tbd_next = next_desc;

	/*
	 * Advance the Transmit Descriptor Tail (Tdt), this tells the
	 * FX1000 that this frame is available to transmit.
	 */
	if (hw->mac.type == e1000_82547)
		e1000g_82547_tx_move_tail(tx_ring);
	else
		E1000_WRITE_REG(hw, E1000_TDT,
		    (uint32_t)(next_desc - tx_ring->tbd_first));

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		Adapter->chip_state = E1000G_ERROR;
	}

	/* Put the pending SwPackets to the "Used" list */
	mutex_enter(&tx_ring->usedlist_lock);
	QUEUE_APPEND(&tx_ring->used_list, pending_list);
	tx_ring->tbd_avail -= desc_count;
	mutex_exit(&tx_ring->usedlist_lock);

	/* Store the cksum data */
	if (cksum_load)
		tx_ring->cksum_data = *cksum;

	return (desc_count);
}


/*
 * e1000g_tx_setup - setup tx data structures
 *
 * This routine initializes all of the transmit related
 * structures. This includes the Transmit descriptors,
 * and the tx_sw_packet structures.
 */
void
e1000g_tx_setup(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	p_tx_sw_packet_t packet;
	UINT i;
	uint32_t buf_high;
	uint32_t buf_low;
	uint32_t reg_tipg;
	uint32_t reg_tctl;
	uint32_t reg_tarc;
	uint16_t speed, duplex;
	int size;
	e1000g_tx_ring_t *tx_ring;

	hw = &Adapter->shared;
	tx_ring = Adapter->tx_ring;

	/* init the lists */
	/*
	 * Here we don't need to protect the lists using the
	 * usedlist_lock and freelist_lock, for they have
	 * been protected by the chip_lock.
	 */
	QUEUE_INIT_LIST(&tx_ring->used_list);
	QUEUE_INIT_LIST(&tx_ring->free_list);

	/* Go through and set up each SW_Packet */
	packet = tx_ring->packet_area;
	for (i = 0; i < Adapter->tx_freelist_num; i++, packet++) {
		/* Initialize this tx_sw_apcket area */
		e1000g_free_tx_swpkt(packet);
		/* Add this tx_sw_packet to the free list */
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
	    (E1000_COLLISION_DISTANCE << E1000_COLD_SHIFT) |
	    E1000_TCTL_RTLC;

	/* Enable the MULR bit */
	if (hw->bus.type == e1000_bus_type_pci_express)
		reg_tctl |= E1000_TCTL_MULR;

	E1000_WRITE_REG(hw, E1000_TCTL, reg_tctl);

	if ((hw->mac.type == e1000_82571) || (hw->mac.type == e1000_82572)) {
		e1000_get_speed_and_duplex(hw, &speed, &duplex);

		reg_tarc = E1000_READ_REG(hw, E1000_TARC0);
		reg_tarc |= (1 << 25);
		if (speed == SPEED_1000)
			reg_tarc |= (1 << 21);
		E1000_WRITE_REG(hw, E1000_TARC0, reg_tarc);

		reg_tarc = E1000_READ_REG(hw, E1000_TARC1);
		reg_tarc |= (1 << 25);
		if (reg_tctl & E1000_TCTL_MULR)
			reg_tarc &= ~(1 << 28);
		else
			reg_tarc |= (1 << 28);
		E1000_WRITE_REG(hw, E1000_TARC1, reg_tarc);

	} else if (hw->mac.type == e1000_80003es2lan) {
		reg_tarc = E1000_READ_REG(hw, E1000_TARC0);
		reg_tarc |= 1;
		if (hw->media_type == e1000_media_type_internal_serdes)
			reg_tarc |= (1 << 20);
		E1000_WRITE_REG(hw, E1000_TARC0, reg_tarc);

		reg_tarc = E1000_READ_REG(hw, E1000_TARC1);
		reg_tarc |= 1;
		E1000_WRITE_REG(hw, E1000_TARC1, reg_tarc);
	}

	/* Setup HW Base and Length of Tx descriptor area */
	size = (Adapter->tx_desc_num * sizeof (struct e1000_tx_desc));
	E1000_WRITE_REG(hw, E1000_TDLEN, size);
	size = E1000_READ_REG(hw, E1000_TDLEN);

	buf_low = (uint32_t)tx_ring->tbd_dma_addr;
	buf_high = (uint32_t)(tx_ring->tbd_dma_addr >> 32);

	E1000_WRITE_REG(hw, E1000_TDBAL, buf_low);
	E1000_WRITE_REG(hw, E1000_TDBAH, buf_high);

	/* Setup our HW Tx Head & Tail descriptor pointers */
	E1000_WRITE_REG(hw, E1000_TDH, 0);
	E1000_WRITE_REG(hw, E1000_TDT, 0);

	/* Set the default values for the Tx Inter Packet Gap timer */
	if ((hw->mac.type == e1000_82542) &&
	    ((hw->revision_id == E1000_REVISION_2) ||
	    (hw->revision_id == E1000_REVISION_3))) {
		reg_tipg = DEFAULT_82542_TIPG_IPGT;
		reg_tipg |=
		    DEFAULT_82542_TIPG_IPGR1 << E1000_TIPG_IPGR1_SHIFT;
		reg_tipg |=
		    DEFAULT_82542_TIPG_IPGR2 << E1000_TIPG_IPGR2_SHIFT;
	} else {
		if (hw->media_type == e1000_media_type_fiber)
			reg_tipg = DEFAULT_82543_TIPG_IPGT_FIBER;
		else
			reg_tipg = DEFAULT_82543_TIPG_IPGT_COPPER;
		reg_tipg |=
		    DEFAULT_82543_TIPG_IPGR1 << E1000_TIPG_IPGR1_SHIFT;
		reg_tipg |=
		    DEFAULT_82543_TIPG_IPGR2 << E1000_TIPG_IPGR2_SHIFT;
	}
	E1000_WRITE_REG(hw, E1000_TIPG, reg_tipg);

	/* Setup Transmit Interrupt Delay Value */
	E1000_WRITE_REG(hw, E1000_TIDV, Adapter->tx_intr_delay);
	E1000G_DEBUGLOG_1(Adapter, E1000G_INFO_LEVEL,
	    "E1000_TIDV: 0x%x\n", Adapter->tx_intr_delay);

	if (hw->mac.type >= e1000_82540) {
		E1000_WRITE_REG(&Adapter->shared, E1000_TADV,
		    Adapter->tx_intr_abs_delay);
		E1000G_DEBUGLOG_1(Adapter, E1000G_INFO_LEVEL,
		    "E1000_TADV: 0x%x\n", Adapter->tx_intr_abs_delay);
	}

	tx_ring->tbd_avail = Adapter->tx_desc_num;

	/* For TCP/UDP checksum offload */
	tx_ring->cksum_data.cksum_stuff = 0;
	tx_ring->cksum_data.cksum_start = 0;
	tx_ring->cksum_data.cksum_flags = 0;
	tx_ring->cksum_data.ether_header_size = 0;
}

/*
 * e1000g_recycle - recycle the tx descriptors and tx sw packets
 */
int
e1000g_recycle(e1000g_tx_ring_t *tx_ring)
{
	struct e1000g *Adapter;
	LIST_DESCRIBER pending_list;
	p_tx_sw_packet_t packet;
	mblk_t *mp;
	mblk_t *nmp;
	struct e1000_tx_desc *descriptor;
	int desc_count;
	int is_intr;

	/*
	 * This function will examine each TxSwPacket in the 'used' queue
	 * if the e1000g is done with it then the associated resources (Tx
	 * Descriptors) will be "freed" and the TxSwPacket will be
	 * returned to the 'free' queue.
	 */
	Adapter = tx_ring->adapter;

	packet = (p_tx_sw_packet_t)QUEUE_GET_HEAD(&tx_ring->used_list);
	if (packet == NULL) {
		tx_ring->recycle_fail = 0;
		tx_ring->stall_watchdog = 0;
		return (0);
	}

	is_intr = servicing_interrupt();

	if (is_intr)
		mutex_enter(&tx_ring->usedlist_lock);
	else if (mutex_tryenter(&tx_ring->usedlist_lock) == 0)
		return (0);

	desc_count = 0;
	QUEUE_INIT_LIST(&pending_list);

	/* Sync the Tx descriptor DMA buffer */
	(void) ddi_dma_sync(tx_ring->tbd_dma_handle,
	    0, 0, DDI_DMA_SYNC_FORKERNEL);
	if (e1000g_check_dma_handle(
	    tx_ring->tbd_dma_handle) != DDI_FM_OK) {
		mutex_exit(&tx_ring->usedlist_lock);
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		Adapter->chip_state = E1000G_ERROR;
		return (0);
	}

	/*
	 * While there are still TxSwPackets in the used queue check them
	 */
	while (packet =
	    (p_tx_sw_packet_t)QUEUE_GET_HEAD(&tx_ring->used_list)) {

		/*
		 * Get hold of the next descriptor that the e1000g will
		 * report status back to (this will be the last descriptor
		 * of a given sw packet). We only want to free the
		 * sw packet (and it resources) if the e1000g is done
		 * with ALL of the descriptors.  If the e1000g is done
		 * with the last one then it is done with all of them.
		 */
		ASSERT(packet->num_desc);
		descriptor = tx_ring->tbd_oldest + (packet->num_desc - 1);

		/* Check for wrap case */
		if (descriptor > tx_ring->tbd_last)
			descriptor -= Adapter->tx_desc_num;

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

			if (is_intr && (desc_count >= Adapter->tx_recycle_num))
				break;
		} else {
			/*
			 * Found a sw packet that the e1000g is not done
			 * with then there is no reason to check the rest
			 * of the queue.
			 */
			break;
		}
	}

	tx_ring->tbd_avail += desc_count;
	Adapter->tx_pkt_cnt += desc_count;

	mutex_exit(&tx_ring->usedlist_lock);

	if (desc_count == 0) {
		tx_ring->recycle_fail++;
		E1000G_DEBUG_STAT(tx_ring->stat_recycle_none);
		return (0);
	}

	tx_ring->recycle_fail = 0;
	tx_ring->stall_watchdog = 0;

	mp = NULL;
	nmp = NULL;
	packet = (p_tx_sw_packet_t)QUEUE_GET_HEAD(&pending_list);
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
		e1000g_free_tx_swpkt(packet);

		packet = (p_tx_sw_packet_t)
		    QUEUE_GET_NEXT(&pending_list, &packet->Link);
	}

	/* Return the TxSwPackets back to the FreeList */
	mutex_enter(&tx_ring->freelist_lock);
	QUEUE_APPEND(&tx_ring->free_list, &pending_list);
	mutex_exit(&tx_ring->freelist_lock);

	if (mp != NULL)
		freemsgchain(mp);

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
e1000g_fill_82544_desc(uint64_t address,
    size_t length, p_desc_array_t desc_array)
{
	/*
	 * Since issue is sensitive to length and address.
	 * Let us first check the address...
	 */
	uint32_t safe_terminator;

	if (length <= 4) {
		desc_array->descriptor[0].address = address;
		desc_array->descriptor[0].length = length;
		desc_array->elements = 1;
		return (desc_array->elements);
	}
	safe_terminator =
	    (uint32_t)((((uint32_t)address & 0x7) +
	    (length & 0xF)) & 0xF);
	/*
	 * if it does not fall between 0x1 to 0x4 and 0x9 to 0xC then
	 * return
	 */
	if (safe_terminator == 0 ||
	    (safe_terminator > 4 && safe_terminator < 9) ||
	    (safe_terminator > 0xC && safe_terminator <= 0xF)) {
		desc_array->descriptor[0].address = address;
		desc_array->descriptor[0].length = length;
		desc_array->elements = 1;
		return (desc_array->elements);
	}

	desc_array->descriptor[0].address = address;
	desc_array->descriptor[0].length = length - 4;
	desc_array->descriptor[1].address = address + (length - 4);
	desc_array->descriptor[1].length = 4;
	desc_array->elements = 2;
	return (desc_array->elements);
}

static int
e1000g_tx_copy(e1000g_tx_ring_t *tx_ring, p_tx_sw_packet_t packet,
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
		else if (len1 > tx_ring->adapter->tx_bcopy_thresh)
			finished = B_TRUE;
		else
			finished = B_FALSE;
	}

	if (finished) {
		E1000G_DEBUG_STAT_COND(tx_ring->stat_multi_copy,
		    (tx_buf->len > len));

		/*
		 * If the packet is smaller than 64 bytes, which is the
		 * minimum ethernet packet size, pad the packet to make
		 * it at least 60 bytes. The hardware will add 4 bytes
		 * for CRC.
		 */
		if (force_bcopy & FORCE_BCOPY_UNDER_SIZE) {
			ASSERT(tx_buf->len < ETHERMIN);

			bzero(tx_buf->address + tx_buf->len,
			    ETHERMIN - tx_buf->len);
			tx_buf->len = ETHERMIN;
		}

#ifdef __sparc
		if (packet->dma_type == USE_DVMA)
			dvma_sync(tx_buf->dma_handle, 0, DDI_DMA_SYNC_FORDEV);
		else
			(void) ddi_dma_sync(tx_buf->dma_handle, 0,
			    tx_buf->len, DDI_DMA_SYNC_FORDEV);
#else
		(void) ddi_dma_sync(tx_buf->dma_handle, 0,
		    tx_buf->len, DDI_DMA_SYNC_FORDEV);
#endif

		packet->data_transfer_type = USE_BCOPY;

		desc_count = e1000g_fill_tx_desc(tx_ring,
		    packet,
		    tx_buf->dma_address,
		    tx_buf->len);

		if (desc_count <= 0)
			return (-1);
	}

	return (desc_count);
}

static int
e1000g_tx_bind(e1000g_tx_ring_t *tx_ring, p_tx_sw_packet_t packet, mblk_t *mp)
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

			e1000g_log(tx_ring->adapter, CE_WARN,
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
		E1000G_DEBUG_STAT_COND(tx_ring->stat_multi_cookie,
		    (ncookies > 1));

		/*
		 * The data_transfer_type value must be set after the handle
		 * has been bound, for it will be used in e1000g_free_tx_swpkt()
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

		desc_count = e1000g_fill_tx_desc(tx_ring,
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
e1000g_fill_context_descriptor(cksum_data_t *cksum,
    struct e1000_context_desc *cksum_desc)
{
	if (cksum->cksum_flags & HCK_IPV4_HDRCKSUM) {
		cksum_desc->lower_setup.ip_fields.ipcss =
		    cksum->ether_header_size;
		cksum_desc->lower_setup.ip_fields.ipcso =
		    cksum->ether_header_size +
		    offsetof(struct ip, ip_sum);
		cksum_desc->lower_setup.ip_fields.ipcse =
		    cksum->ether_header_size +
		    sizeof (struct ip) - 1;
	} else
		cksum_desc->lower_setup.ip_config = 0;

	if (cksum->cksum_flags & HCK_PARTIALCKSUM) {
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
		    cksum->cksum_start + cksum->ether_header_size;
		cksum_desc->upper_setup.tcp_fields.tucso =
		    cksum->cksum_stuff + cksum->ether_header_size;
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
e1000g_fill_tx_desc(e1000g_tx_ring_t *tx_ring,
    p_tx_sw_packet_t packet, uint64_t address, size_t size)
{
	struct e1000_hw *hw = &tx_ring->adapter->shared;
	p_sw_desc_t desc;

	if (hw->mac.type == e1000_82544) {
		if (hw->bus.type == e1000_bus_type_pcix)
			return (e1000g_tx_workaround_PCIX_82544(packet,
			    address, size));

		if (size > JUMBO_FRAG_LENGTH)
			return (e1000g_tx_workaround_jumbo_82544(packet,
			    address, size));
	}

	ASSERT(packet->num_desc < MAX_TX_DESC_PER_PACKET);

	desc = &packet->desc[packet->num_desc];
	desc->address = address;
	desc->length = size;

	packet->num_desc++;

	return (1);
}

static int
e1000g_tx_workaround_PCIX_82544(p_tx_sw_packet_t packet,
    uint64_t address, size_t size)
{
	p_sw_desc_t desc;
	int desc_count;
	long size_left;
	size_t len;
	uint32_t counter;
	uint32_t array_elements;
	desc_array_t desc_array;

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
			/*
			 * Put in the buffer address
			 */
			desc = &packet->desc[packet->num_desc];

			desc->address =
			    desc_array.descriptor[counter].address;
			desc->length =
			    desc_array.descriptor[counter].length;

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
e1000g_tx_workaround_jumbo_82544(p_tx_sw_packet_t packet,
    uint64_t address, size_t size)
{
	p_sw_desc_t desc;
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

		desc = &packet->desc[packet->num_desc];

		desc->address = address + offset;

		if (size_left > JUMBO_FRAG_LENGTH)
			desc->length = JUMBO_FRAG_LENGTH;
		else
			desc->length = size_left;

		packet->num_desc++;
		desc_count++;

		offset += desc->length;
		size_left -= JUMBO_FRAG_LENGTH;
	}

	return (desc_count);
}

#pragma inline(e1000g_82547_tx_move_tail_work)

static void
e1000g_82547_tx_move_tail_work(e1000g_tx_ring_t *tx_ring)
{
	struct e1000_hw *hw;
	uint16_t hw_tdt;
	uint16_t sw_tdt;
	struct e1000_tx_desc *tx_desc;
	uint16_t length = 0;
	boolean_t eop = B_FALSE;
	struct e1000g *Adapter;

	Adapter = tx_ring->adapter;
	hw = &Adapter->shared;

	hw_tdt = E1000_READ_REG(hw, E1000_TDT);
	sw_tdt = tx_ring->tbd_next - tx_ring->tbd_first;

	while (hw_tdt != sw_tdt) {
		tx_desc = &(tx_ring->tbd_first[hw_tdt]);
		length += tx_desc->lower.flags.length;
		eop = tx_desc->lower.data & E1000_TXD_CMD_EOP;
		if (++hw_tdt == Adapter->tx_desc_num)
			hw_tdt = 0;

		if (eop) {
			if ((Adapter->link_duplex == HALF_DUPLEX) &&
			    (e1000_fifo_workaround_82547(hw, length)
			    != E1000_SUCCESS)) {
				if (tx_ring->timer_enable_82547) {
					ASSERT(tx_ring->timer_id_82547 == 0);
					tx_ring->timer_id_82547 =
					    timeout(e1000g_82547_timeout,
					    (void *)tx_ring,
					    drv_usectohz(10000));
				}
				return;

			} else {
				E1000_WRITE_REG(hw, E1000_TDT, hw_tdt);
				e1000_update_tx_fifo_head_82547(hw, length);
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
