/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2009 Intel Corporation. All rights reserved.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

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
    p_tx_sw_packet_t, mblk_t *, boolean_t);
static int e1000g_tx_bind(e1000g_tx_ring_t *,
    p_tx_sw_packet_t, mblk_t *);
static boolean_t e1000g_retrieve_context(mblk_t *, context_data_t *, size_t);
static boolean_t e1000g_check_context(e1000g_tx_ring_t *, context_data_t *);
static int e1000g_fill_tx_ring(e1000g_tx_ring_t *, LIST_DESCRIBER *,
    context_data_t *);
static void e1000g_fill_context_descriptor(context_data_t *,
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
#pragma inline(e1000g_retrieve_context)
#pragma inline(e1000g_check_context)
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
		(void) ddi_dma_unbind_handle(packet->tx_dma_handle);
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

	if ((Adapter->e1000g_state & E1000G_SUSPENDED) ||
	    !(Adapter->e1000g_state & E1000G_STARTED) ||
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
	p_tx_sw_packet_t packet;
	LIST_DESCRIBER pending_list;
	size_t len;
	size_t msg_size;
	uint32_t frag_count;
	int desc_count;
	uint32_t desc_total;
	uint32_t bcopy_thresh;
	uint32_t hdr_frag_len;
	boolean_t tx_undersize_flag;
	mblk_t *nmp;
	mblk_t *tmp;
	mblk_t *new_mp;
	mblk_t *pre_mp;
	mblk_t *next_mp;
	e1000g_tx_ring_t *tx_ring;
	context_data_t cur_context;

	tx_ring = Adapter->tx_ring;
	bcopy_thresh = Adapter->tx_bcopy_thresh;

	/* Get the total size and frags number of the message */
	tx_undersize_flag = B_FALSE;
	frag_count = 0;
	msg_size = 0;
	for (nmp = mp; nmp; nmp = nmp->b_cont) {
		frag_count++;
		msg_size += MBLKL(nmp);
	}

	/* retrieve and compute information for context descriptor */
	if (!e1000g_retrieve_context(mp, &cur_context, msg_size)) {
		freemsg(mp);
		return (B_TRUE);
	}

	/*
	 * Make sure the packet is less than the allowed size
	 */
	if (!cur_context.lso_flag &&
	    (msg_size > Adapter->max_frame_size - ETHERFCSL)) {
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
	if (tx_ring->tbd_avail < DEFAULT_TX_NO_RESOURCE) {
		(void) e1000g_recycle(tx_ring);
		E1000G_DEBUG_STAT(tx_ring->stat_recycle);

		if (tx_ring->tbd_avail < DEFAULT_TX_NO_RESOURCE) {
			E1000G_DEBUG_STAT(tx_ring->stat_lack_desc);
			goto tx_no_resource;
		}
	}

	/*
	 * If the message size is less than the minimum ethernet packet size,
	 * we'll use bcopy to send it, and padd it to 60 bytes later.
	 */
	if (msg_size < ETHERMIN) {
		E1000G_DEBUG_STAT(tx_ring->stat_under_size);
		tx_undersize_flag = B_TRUE;
	}

	/* Initialize variables */
	desc_count = 1;	/* The initial value should be greater than 0 */
	desc_total = 0;
	new_mp = NULL;
	QUEUE_INIT_LIST(&pending_list);

	/* Process each mblk fragment and fill tx descriptors */
	/*
	 * The software should guarantee LSO packet header(MAC+IP+TCP)
	 * to be within one descriptor. Here we reallocate and refill the
	 * the header if it's physical memory non-contiguous.
	 */
	if (cur_context.lso_flag) {
		/* find the last fragment of the header */
		len = MBLKL(mp);
		ASSERT(len > 0);
		next_mp = mp;
		pre_mp = NULL;
		while (len < cur_context.hdr_len) {
			pre_mp = next_mp;
			next_mp = next_mp->b_cont;
			len += MBLKL(next_mp);
		}
		/*
		 * If the header and the payload are in different mblks,
		 * we simply force the header to be copied into pre-allocated
		 * page-aligned buffer.
		 */
		if (len == cur_context.hdr_len)
			goto adjust_threshold;

		hdr_frag_len = cur_context.hdr_len - (len - MBLKL(next_mp));
		/*
		 * There are three cases we need to reallocate a mblk for the
		 * last header fragment:
		 *
		 * 1. the header is in multiple mblks and the last fragment
		 * share the same mblk with the payload
		 *
		 * 2. the header is in a single mblk shared with the payload
		 * and the header is physical memory non-contiguous
		 *
		 * 3. there is 4 KB boundary within the header and 64 bytes
		 * following the end of the header bytes. The case may cause
		 * TCP data corruption issue.
		 *
		 * The workaround for the case #2 and case #3 is:
		 *   Assuming standard Ethernet/IP/TCP headers of 54 bytes,
		 *   this means that the buffer(containing the headers) should
		 *   not start -118 bytes before a 4 KB boundary. For example,
		 *   128-byte alignment for this buffer could be used to fulfill
		 *   this condition.
		 */
		if ((next_mp != mp) ||
		    (P2NPHASE((uintptr_t)next_mp->b_rptr,
		    E1000_LSO_FIRST_DESC_ALIGNMENT_BOUNDARY_4K)
		    < E1000_LSO_FIRST_DESC_ALIGNMENT)) {
			E1000G_DEBUG_STAT(tx_ring->stat_lso_header_fail);
			/*
			 * reallocate the mblk for the last header fragment,
			 * expect to bcopy into pre-allocated page-aligned
			 * buffer
			 */
			new_mp = allocb(hdr_frag_len, NULL);
			if (!new_mp)
				return (B_FALSE);
			bcopy(next_mp->b_rptr, new_mp->b_rptr, hdr_frag_len);
			/* link the new header fragment with the other parts */
			new_mp->b_wptr = new_mp->b_rptr + hdr_frag_len;
			new_mp->b_cont = next_mp;
			if (pre_mp)
				pre_mp->b_cont = new_mp;
			else
				mp = new_mp;
			next_mp->b_rptr += hdr_frag_len;
			frag_count++;
		}
adjust_threshold:
		/*
		 * adjust the bcopy threshhold to guarantee
		 * the header to use bcopy way
		 */
		if (bcopy_thresh < cur_context.hdr_len)
			bcopy_thresh = cur_context.hdr_len;
	}

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
		if ((len <= bcopy_thresh) || tx_undersize_flag) {
			desc_count =
			    e1000g_tx_copy(tx_ring, packet, nmp,
			    tx_undersize_flag);
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
	if (tx_ring->tbd_avail < (desc_total + 3)) {
		E1000G_DEBUG_STAT(tx_ring->stat_recycle_retry);
		(void) e1000g_recycle(tx_ring);
	}

	mutex_enter(&tx_ring->tx_lock);

	/*
	 * If the number of available tx descriptors is not enough for transmit
	 * (one redundant descriptor and one hw checksum context descriptor are
	 * included), then return failure.
	 */
	if (tx_ring->tbd_avail < (desc_total + 3)) {
		E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
		    "No Enough Tx descriptors\n");
		E1000G_STAT(tx_ring->stat_no_desc);
		mutex_exit(&tx_ring->tx_lock);
		goto tx_send_failed;
	}

	desc_count = e1000g_fill_tx_ring(tx_ring, &pending_list, &cur_context);

	mutex_exit(&tx_ring->tx_lock);

	ASSERT(desc_count > 0);

	/* Send successful */
	return (B_TRUE);

tx_send_failed:
	/* Restore mp to original */
	if (new_mp) {
		if (pre_mp) {
			pre_mp->b_cont = next_mp;
		}
		new_mp->b_cont = NULL;
		freemsg(new_mp);

		next_mp->b_rptr -= hdr_frag_len;
	}

	/*
	 * Enable Transmit interrupts, so that the interrupt routine can
	 * call mac_tx_update() when transmit descriptors become available.
	 */
	tx_ring->resched_timestamp = ddi_get_lbolt();
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
	tx_ring->resched_timestamp = ddi_get_lbolt();
	tx_ring->resched_needed = B_TRUE;
	if (!Adapter->tx_intr_enable)
		e1000g_mask_tx_interrupt(Adapter);

	/* Message will be scheduled for re-transmit */
	return (B_FALSE);
}

static boolean_t
e1000g_retrieve_context(mblk_t *mp, context_data_t *cur_context,
    size_t msg_size)
{
	uintptr_t ip_start;
	uintptr_t tcp_start;
	mblk_t *nmp;
	uint32_t lsoflags;
	uint32_t mss;

	bzero(cur_context, sizeof (context_data_t));

	/* first check lso information */
	mac_lso_get(mp, &mss, &lsoflags);

	/* retrieve checksum info */
	mac_hcksum_get(mp, &cur_context->cksum_start,
	    &cur_context->cksum_stuff, NULL, NULL, &cur_context->cksum_flags);
	/* retrieve ethernet header size */
	if (((struct ether_vlan_header *)(uintptr_t)mp->b_rptr)->ether_tpid ==
	    htons(ETHERTYPE_VLAN))
		cur_context->ether_header_size =
		    sizeof (struct ether_vlan_header);
	else
		cur_context->ether_header_size =
		    sizeof (struct ether_header);

	if (lsoflags & HW_LSO) {
		ASSERT(mss != 0);

		/* free the invalid packet */
		if (mss == 0 ||
		    !((cur_context->cksum_flags & HCK_PARTIALCKSUM) &&
		    (cur_context->cksum_flags & HCK_IPV4_HDRCKSUM))) {
			return (B_FALSE);
		}
		cur_context->mss = (uint16_t)mss;
		cur_context->lso_flag = B_TRUE;

		/*
		 * Some fields are cleared for the hardware to fill
		 * in. We don't assume Ethernet header, IP header and
		 * TCP header are always in the same mblk fragment,
		 * while we assume each header is always within one
		 * mblk fragment and Ethernet header is always in the
		 * first mblk fragment.
		 */
		nmp = mp;
		ip_start = (uintptr_t)(nmp->b_rptr)
		    + cur_context->ether_header_size;
		if (ip_start >= (uintptr_t)(nmp->b_wptr)) {
			ip_start = (uintptr_t)nmp->b_cont->b_rptr
			    + (ip_start - (uintptr_t)(nmp->b_wptr));
			nmp = nmp->b_cont;
		}
		tcp_start = ip_start +
		    IPH_HDR_LENGTH((ipha_t *)ip_start);
		if (tcp_start >= (uintptr_t)(nmp->b_wptr)) {
			tcp_start = (uintptr_t)nmp->b_cont->b_rptr
			    + (tcp_start - (uintptr_t)(nmp->b_wptr));
			nmp = nmp->b_cont;
		}
		cur_context->hdr_len = cur_context->ether_header_size
		    + IPH_HDR_LENGTH((ipha_t *)ip_start)
		    + TCP_HDR_LENGTH((tcph_t *)tcp_start);
		((ipha_t *)ip_start)->ipha_length = 0;
		((ipha_t *)ip_start)->ipha_hdr_checksum = 0;
		/* calculate the TCP packet payload length */
		cur_context->pay_len = msg_size - cur_context->hdr_len;
	}
	return (B_TRUE);
}

static boolean_t
e1000g_check_context(e1000g_tx_ring_t *tx_ring, context_data_t *cur_context)
{
	boolean_t context_reload;
	context_data_t *pre_context;
	struct e1000g *Adapter;

	context_reload = B_FALSE;
	pre_context = &tx_ring->pre_context;
	Adapter = tx_ring->adapter;

	/*
	 * The following code determine if the context descriptor is
	 * needed to be reloaded. The sequence of the conditions is
	 * made by their possibilities of changing.
	 */
	/*
	 * workaround for 82546EB, context descriptor must be reloaded
	 * per LSO/hw_cksum packet if LSO is enabled.
	 */
	if (Adapter->lso_premature_issue &&
	    Adapter->lso_enable &&
	    (cur_context->cksum_flags != 0)) {

		context_reload = B_TRUE;
	} else if (cur_context->lso_flag) {
		if ((cur_context->lso_flag != pre_context->lso_flag) ||
		    (cur_context->cksum_flags != pre_context->cksum_flags) ||
		    (cur_context->pay_len != pre_context->pay_len) ||
		    (cur_context->mss != pre_context->mss) ||
		    (cur_context->hdr_len != pre_context->hdr_len) ||
		    (cur_context->cksum_stuff != pre_context->cksum_stuff) ||
		    (cur_context->cksum_start != pre_context->cksum_start) ||
		    (cur_context->ether_header_size !=
		    pre_context->ether_header_size)) {

			context_reload = B_TRUE;
		}
	} else if (cur_context->cksum_flags != 0) {
		if ((cur_context->lso_flag != pre_context->lso_flag) ||
		    (cur_context->cksum_flags != pre_context->cksum_flags) ||
		    (cur_context->cksum_stuff != pre_context->cksum_stuff) ||
		    (cur_context->cksum_start != pre_context->cksum_start) ||
		    (cur_context->ether_header_size !=
		    pre_context->ether_header_size)) {

			context_reload = B_TRUE;
		}
	}

	return (context_reload);
}

static int
e1000g_fill_tx_ring(e1000g_tx_ring_t *tx_ring, LIST_DESCRIBER *pending_list,
    context_data_t *cur_context)
{
	struct e1000g *Adapter;
	struct e1000_hw *hw;
	p_tx_sw_packet_t first_packet;
	p_tx_sw_packet_t packet;
	p_tx_sw_packet_t previous_packet;
	boolean_t context_reload;
	struct e1000_tx_desc *first_data_desc;
	struct e1000_tx_desc *next_desc;
	struct e1000_tx_desc *descriptor;
	struct e1000_data_desc zeroed;
	int desc_count;
	boolean_t buff_overrun_flag;
	int i;

	Adapter = tx_ring->adapter;
	hw = &Adapter->shared;

	desc_count = 0;
	first_packet = NULL;
	first_data_desc = NULL;
	descriptor = NULL;
	first_packet = NULL;
	packet = NULL;
	buff_overrun_flag = B_FALSE;
	zeroed.upper.data = 0;

	next_desc = tx_ring->tbd_next;

	/* Context descriptor reload check */
	context_reload = e1000g_check_context(tx_ring, cur_context);

	if (context_reload) {
		first_packet = (p_tx_sw_packet_t)QUEUE_GET_HEAD(pending_list);

		descriptor = next_desc;

		e1000g_fill_context_descriptor(cur_context,
		    (struct e1000_context_desc *)descriptor);

		/* Check the wrap-around case */
		if (descriptor == tx_ring->tbd_last)
			next_desc = tx_ring->tbd_first;
		else
			next_desc++;

		desc_count++;
	}

	first_data_desc = next_desc;

	/*
	 * According to the documentation, the packet options field (POPTS) is
	 * "ignored except on the first data descriptor of a packet."  However,
	 * there is a bug in QEMU (638955) whereby the POPTS field within a
	 * given data descriptor is used to interpret that data descriptor --
	 * regardless of whether or not the descriptor is the first in a packet
	 * or not.  For a packet that spans multiple descriptors, the (virtual)
	 * HW checksum (either TCP/UDP or IP or both) will therefore _not_ be
	 * performed on descriptors after the first, resulting in incorrect
	 * checksums and mysteriously dropped/retransmitted packets.  Other
	 * drivers do not have this issue because they (harmlessly) set the
	 * POPTS field on every data descriptor to be the intended options for
	 * the entire packet.  To circumvent this QEMU bug, we engage in this
	 * same behavior iff the subsystem vendor and device IDs indicate that
	 * this is an emulated QEMU device (1af4,1100).
	 */
	if (hw->subsystem_vendor_id == 0x1af4 &&
	    hw->subsystem_device_id == 0x1100 &&
	    cur_context->cksum_flags) {
		if (cur_context->cksum_flags & HCK_IPV4_HDRCKSUM)
			zeroed.upper.fields.popts |= E1000_TXD_POPTS_IXSM;

		if (cur_context->cksum_flags & HCK_PARTIALCKSUM)
			zeroed.upper.fields.popts |= E1000_TXD_POPTS_TXSM;
	}

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
			descriptor->upper.data = zeroed.upper.data;

			descriptor->lower.data |=
			    E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D;
			/* must set RS on every outgoing descriptor */
			descriptor->lower.data |=
			    E1000_TXD_CMD_RS;

			if (cur_context->lso_flag)
				descriptor->lower.data |= E1000_TXD_CMD_TSE;

			/* Check the wrap-around case */
			if (descriptor == tx_ring->tbd_last)
				next_desc = tx_ring->tbd_first;
			else
				next_desc++;

			desc_count++;

			/*
			 * workaround for 82546EB errata 33, hang in PCI-X
			 * systems due to 2k Buffer Overrun during Transmit
			 * Operation. The workaround applies to all the Intel
			 * PCI-X chips.
			 */
			if (hw->bus.type == e1000_bus_type_pcix &&
			    descriptor == first_data_desc &&
			    ((descriptor->lower.data & E1000G_TBD_LENGTH_MASK)
			    > E1000_TX_BUFFER_OEVRRUN_THRESHOLD)) {
				/* modified the first descriptor */
				descriptor->lower.data &=
				    ~E1000G_TBD_LENGTH_MASK;
				descriptor->lower.flags.length =
				    E1000_TX_BUFFER_OEVRRUN_THRESHOLD;

				/* insert a new descriptor */
				ASSERT(tx_ring->tbd_avail > 0);
				next_desc->buffer_addr =
				    packet->desc[0].address +
				    E1000_TX_BUFFER_OEVRRUN_THRESHOLD;
				next_desc->lower.data =
				    packet->desc[0].length -
				    E1000_TX_BUFFER_OEVRRUN_THRESHOLD;

				/* Zero out status */
				next_desc->upper.data = zeroed.upper.data;

				next_desc->lower.data |=
				    E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D;
				/* must set RS on every outgoing descriptor */
				next_desc->lower.data |=
				    E1000_TXD_CMD_RS;

				if (cur_context->lso_flag)
					next_desc->lower.data |=
					    E1000_TXD_CMD_TSE;

				descriptor = next_desc;

				/* Check the wrap-around case */
				if (next_desc == tx_ring->tbd_last)
					next_desc = tx_ring->tbd_first;
				else
					next_desc++;

				desc_count++;
				buff_overrun_flag = B_TRUE;
			}
		}

		if (buff_overrun_flag) {
			packet->num_desc++;
			buff_overrun_flag = B_FALSE;
		}

		if (first_packet != NULL) {
			/*
			 * Count the checksum context descriptor for
			 * the first SwPacket.
			 */
			first_packet->num_desc++;
			first_packet = NULL;
		}

		packet->tickstamp = ddi_get_lbolt64();

		previous_packet = packet;
		packet = (p_tx_sw_packet_t)
		    QUEUE_GET_NEXT(pending_list, &packet->Link);
	}

	/*
	 * workaround for 82546EB errata 21, LSO Premature Descriptor Write Back
	 */
	if (Adapter->lso_premature_issue && cur_context->lso_flag &&
	    ((descriptor->lower.data & E1000G_TBD_LENGTH_MASK) > 8)) {
		/* modified the previous descriptor */
		descriptor->lower.data -= 4;

		/* insert a new descriptor */
		ASSERT(tx_ring->tbd_avail > 0);
		/* the lower 20 bits of lower.data is the length field */
		next_desc->buffer_addr =
		    descriptor->buffer_addr +
		    (descriptor->lower.data & E1000G_TBD_LENGTH_MASK);
		next_desc->lower.data = 4;

		/* Zero out status */
		next_desc->upper.data = zeroed.upper.data;
		/* It must be part of a LSO packet */
		next_desc->lower.data |=
		    E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D |
		    E1000_TXD_CMD_RS | E1000_TXD_CMD_TSE;

		descriptor = next_desc;

		/* Check the wrap-around case */
		if (descriptor == tx_ring->tbd_last)
			next_desc = tx_ring->tbd_first;
		else
			next_desc++;

		desc_count++;
		/* update the number of descriptors */
		previous_packet->num_desc++;
	}

	ASSERT(descriptor);

	if (cur_context->cksum_flags) {
		if (cur_context->cksum_flags & HCK_IPV4_HDRCKSUM)
			((struct e1000_data_desc *)first_data_desc)->
			    upper.fields.popts |= E1000_TXD_POPTS_IXSM;
		if (cur_context->cksum_flags & HCK_PARTIALCKSUM)
			((struct e1000_data_desc *)first_data_desc)->
			    upper.fields.popts |= E1000_TXD_POPTS_TXSM;
	}

	/*
	 * Last Descriptor of Packet needs End Of Packet (EOP), Report
	 * Status (RS) set.
	 */
	if (Adapter->tx_intr_delay) {
		descriptor->lower.data |= E1000_TXD_CMD_IDE |
		    E1000_TXD_CMD_EOP;
	} else {
		descriptor->lower.data |= E1000_TXD_CMD_EOP;
	}

	/* Set append Ethernet CRC (IFCS) bits */
	if (cur_context->lso_flag) {
		first_data_desc->lower.data |= E1000_TXD_CMD_IFCS;
	} else {
		descriptor->lower.data |= E1000_TXD_CMD_IFCS;
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
		E1000_WRITE_REG(hw, E1000_TDT(0),
		    (uint32_t)(next_desc - tx_ring->tbd_first));

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		Adapter->e1000g_state |= E1000G_ERROR;
	}

	/* Put the pending SwPackets to the "Used" list */
	mutex_enter(&tx_ring->usedlist_lock);
	QUEUE_APPEND(&tx_ring->used_list, pending_list);
	tx_ring->tbd_avail -= desc_count;
	mutex_exit(&tx_ring->usedlist_lock);

	/* update LSO related data */
	if (context_reload)
		tx_ring->pre_context = *cur_context;

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
	uint32_t i;
	uint32_t buf_high;
	uint32_t buf_low;
	uint32_t reg_tipg;
	uint32_t reg_tctl;
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
	reg_tctl = E1000_READ_REG(hw, E1000_TCTL);
	reg_tctl |= E1000_TCTL_PSP | E1000_TCTL_EN |
	    (E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT) |
	    (E1000_COLLISION_DISTANCE << E1000_COLD_SHIFT) |
	    E1000_TCTL_RTLC;

	/* Enable the MULR bit */
	if (hw->bus.type == e1000_bus_type_pci_express)
		reg_tctl |= E1000_TCTL_MULR;

	E1000_WRITE_REG(hw, E1000_TCTL, reg_tctl);

	/* Setup HW Base and Length of Tx descriptor area */
	size = (Adapter->tx_desc_num * sizeof (struct e1000_tx_desc));
	E1000_WRITE_REG(hw, E1000_TDLEN(0), size);
	size = E1000_READ_REG(hw, E1000_TDLEN(0));

	buf_low = (uint32_t)tx_ring->tbd_dma_addr;
	buf_high = (uint32_t)(tx_ring->tbd_dma_addr >> 32);

	/*
	 * Write the highest location first and work backward to the lowest.
	 * This is necessary for some adapter types to
	 * prevent write combining from occurring.
	 */
	E1000_WRITE_REG(hw, E1000_TDBAH(0), buf_high);
	E1000_WRITE_REG(hw, E1000_TDBAL(0), buf_low);

	/* Setup our HW Tx Head & Tail descriptor pointers */
	E1000_WRITE_REG(hw, E1000_TDH(0), 0);
	E1000_WRITE_REG(hw, E1000_TDT(0), 0);

	/* Set the default values for the Tx Inter Packet Gap timer */
	if ((hw->mac.type == e1000_82542) &&
	    ((hw->revision_id == E1000_REVISION_2) ||
	    (hw->revision_id == E1000_REVISION_3))) {
		reg_tipg = DEFAULT_82542_TIPG_IPGT;
		reg_tipg |=
		    DEFAULT_82542_TIPG_IPGR1 << E1000_TIPG_IPGR1_SHIFT;
		reg_tipg |=
		    DEFAULT_82542_TIPG_IPGR2 << E1000_TIPG_IPGR2_SHIFT;
	} else if (hw->mac.type == e1000_80003es2lan) {
		reg_tipg = DEFAULT_82543_TIPG_IPGR1;
		reg_tipg |= DEFAULT_80003ES2LAN_TIPG_IPGR2 <<
		    E1000_TIPG_IPGR2_SHIFT;
	} else {
		if (hw->phy.media_type == e1000_media_type_fiber)
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

	/* Initialize stored context information */
	bzero(&(tx_ring->pre_context), sizeof (context_data_t));
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
	int64_t delta;

	/*
	 * This function will examine each TxSwPacket in the 'used' queue
	 * if the e1000g is done with it then the associated resources (Tx
	 * Descriptors) will be "freed" and the TxSwPacket will be
	 * returned to the 'free' queue.
	 */
	Adapter = tx_ring->adapter;
	delta = 0;

	packet = (p_tx_sw_packet_t)QUEUE_GET_HEAD(&tx_ring->used_list);
	if (packet == NULL) {
		Adapter->stall_flag = B_FALSE;
		return (0);
	}

	desc_count = 0;
	QUEUE_INIT_LIST(&pending_list);

	/* Sync the Tx descriptor DMA buffer */
	(void) ddi_dma_sync(tx_ring->tbd_dma_handle,
	    0, 0, DDI_DMA_SYNC_FORKERNEL);
	if (e1000g_check_dma_handle(
	    tx_ring->tbd_dma_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		Adapter->e1000g_state |= E1000G_ERROR;
		return (0);
	}

	/*
	 * While there are still TxSwPackets in the used queue check them
	 */
	mutex_enter(&tx_ring->usedlist_lock);
	while ((packet =
	    (p_tx_sw_packet_t)QUEUE_GET_HEAD(&tx_ring->used_list)) != NULL) {

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
		} else {
			/*
			 * Found a sw packet that the e1000g is not done
			 * with then there is no reason to check the rest
			 * of the queue.
			 */
			delta = ddi_get_lbolt64() - packet->tickstamp;
			break;
		}
	}

	tx_ring->tbd_avail += desc_count;
	Adapter->tx_pkt_cnt += desc_count;

	mutex_exit(&tx_ring->usedlist_lock);

	if (desc_count == 0) {
		E1000G_DEBUG_STAT(tx_ring->stat_recycle_none);
		/*
		 * If the packet hasn't been sent out for seconds and
		 * the transmitter is not under paused flowctrl condition,
		 * the transmitter is considered to be stalled.
		 */
		if ((delta > Adapter->stall_threshold) &&
		    !(E1000_READ_REG(&Adapter->shared,
		    E1000_STATUS) & E1000_STATUS_TXOFF)) {
			Adapter->stall_flag = B_TRUE;
		}
		return (0);
	}

	Adapter->stall_flag = B_FALSE;

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
		desc_array->descriptor[0].length = (uint32_t)length;
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
		desc_array->descriptor[0].length = (uint32_t)length;
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
    mblk_t *mp, boolean_t tx_undersize_flag)
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
		else if (tx_undersize_flag)
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
		if (tx_undersize_flag) {
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
e1000g_fill_context_descriptor(context_data_t *cur_context,
    struct e1000_context_desc *context_desc)
{
	if (cur_context->cksum_flags & HCK_IPV4_HDRCKSUM) {
		context_desc->lower_setup.ip_fields.ipcss =
		    cur_context->ether_header_size;
		context_desc->lower_setup.ip_fields.ipcso =
		    cur_context->ether_header_size +
		    offsetof(struct ip, ip_sum);
		context_desc->lower_setup.ip_fields.ipcse =
		    cur_context->ether_header_size +
		    cur_context->cksum_start - 1;
	} else
		context_desc->lower_setup.ip_config = 0;

	if (cur_context->cksum_flags & HCK_PARTIALCKSUM) {
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
		context_desc->upper_setup.tcp_fields.tucss =
		    cur_context->cksum_start + cur_context->ether_header_size;
		context_desc->upper_setup.tcp_fields.tucso =
		    cur_context->cksum_stuff + cur_context->ether_header_size;
		context_desc->upper_setup.tcp_fields.tucse = 0;
	} else
		context_desc->upper_setup.tcp_config = 0;

	if (cur_context->lso_flag) {
		context_desc->tcp_seg_setup.fields.mss = cur_context->mss;
		context_desc->tcp_seg_setup.fields.hdr_len =
		    cur_context->hdr_len;
		/*
		 * workaround for 82546EB errata 23, status-writeback
		 * reporting (RS) should not be set on context or
		 * Null descriptors
		 */
		context_desc->cmd_and_length = E1000_TXD_CMD_DEXT
		    | E1000_TXD_CMD_TSE | E1000_TXD_CMD_IP | E1000_TXD_CMD_TCP
		    | E1000_TXD_DTYP_C | cur_context->pay_len;
	} else {
		context_desc->cmd_and_length = E1000_TXD_CMD_DEXT
		    | E1000_TXD_DTYP_C;
		/*
		 * Zero out the options for TCP Segmentation Offload
		 */
		context_desc->tcp_seg_setup.data = 0;
	}
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
	desc->length = (uint32_t)size;

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
			desc->length = (uint32_t)size_left;

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

	hw_tdt = E1000_READ_REG(hw, E1000_TDT(0));
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
				E1000_WRITE_REG(hw, E1000_TDT(0), hw_tdt);
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

/*
 * This is part of a workaround for the I219, see e1000g_flush_desc_rings() for
 * more information.
 *
 * We need to clear any potential pending descriptors from the tx_ring.  As
 * we're about to reset the device, we don't care about the data that we give it
 * itself.
 */
void
e1000g_flush_tx_ring(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->shared;
	e1000g_tx_ring_t *tx_ring = &Adapter->tx_ring[0];
	uint32_t tctl, txd_lower = E1000_TXD_CMD_IFCS;
	uint16_t size = 512;
	struct e1000_tx_desc *desc;

	tctl = E1000_READ_REG(hw, E1000_TCTL);
	E1000_WRITE_REG(hw, E1000_TCTL, tctl | E1000_TCTL_EN);

	desc = tx_ring->tbd_next;
	if (tx_ring->tbd_next == tx_ring->tbd_last)
		tx_ring->tbd_next = tx_ring->tbd_first;
	else
		tx_ring->tbd_next++;

	/* We just need to set any valid address, so we use the ring itself */
	desc->buffer_addr = tx_ring->tbd_dma_addr;
	desc->lower.data = LE_32(txd_lower | size);
	desc->upper.data = 0;

	(void) ddi_dma_sync(tx_ring->tbd_dma_handle,
	    0, 0, DDI_DMA_SYNC_FORDEV);
	E1000_WRITE_REG(hw, E1000_TDT(0),
	    (uint32_t)(tx_ring->tbd_next - tx_ring->tbd_first));
	(void) E1000_READ_REG(hw, E1000_STATUS);
	usec_delay(250);
}
