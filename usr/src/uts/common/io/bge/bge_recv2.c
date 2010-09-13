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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "bge_impl.h"

#define	U32TOPTR(x)	((void *)(uintptr_t)(uint32_t)(x))
#define	PTRTOU32(x)	((uint32_t)(uintptr_t)(void *)(x))

/*
 * ========== RX side routines ==========
 */

#define	BGE_DBG		BGE_DBG_RECV	/* debug flag for this code	*/

static void bge_refill(bge_t *bgep, buff_ring_t *brp, sw_rbd_t *srbdp);
#pragma	inline(bge_refill)

/*
 * Return the specified buffer (srbdp) to the ring it came from (brp).
 *
 * Note:
 *	If the driver is compiled with only one buffer ring *and* one
 *	return ring, then the buffers must be returned in sequence.
 *	In this case, we don't have to consider anything about the
 *	buffer at all; we can simply advance the cyclic counter.  And
 *	we don't even need the refill mutex <rf_lock>, as the caller
 *	will already be holding the (one-and-only) <rx_lock>.
 *
 *	If the driver supports multiple buffer rings, but only one
 *	return ring, the same still applies (to each buffer ring
 *	separately).
 */
static void
bge_refill(bge_t *bgep, buff_ring_t *brp, sw_rbd_t *srbdp)
{
	uint64_t slot;

	_NOTE(ARGUNUSED(srbdp))

	slot = brp->rf_next;
	brp->rf_next = NEXT(slot, brp->desc.nslots);
	bge_mbx_put(bgep, brp->chip_mbx_reg, slot);
}

static mblk_t *bge_receive_packet(bge_t *bgep, bge_rbd_t *hw_rbd_p,
    recv_ring_t *rrp);
#pragma	inline(bge_receive_packet)

static mblk_t *
bge_receive_packet(bge_t *bgep, bge_rbd_t *hw_rbd_p, recv_ring_t *rrp)
{
	bge_rbd_t hw_rbd;
	buff_ring_t *brp;
	sw_rbd_t *srbdp;
	uchar_t *dp;
	mblk_t *mp;
	uint_t len;
	uint_t minsize;
	uint_t maxsize;
	uint32_t pflags;

	mp = NULL;
	hw_rbd = *hw_rbd_p;

	switch (hw_rbd.flags & (RBD_FLAG_MINI_RING|RBD_FLAG_JUMBO_RING)) {
	case RBD_FLAG_MINI_RING|RBD_FLAG_JUMBO_RING:
	default:
		/* error, this shouldn't happen */
		BGE_PKTDUMP((bgep, &hw_rbd, NULL, "bad ring flags!"));
		goto error;

	case RBD_FLAG_JUMBO_RING:
		brp = &bgep->buff[BGE_JUMBO_BUFF_RING];
		break;

#if	(BGE_BUFF_RINGS_USED > 2)
	case RBD_FLAG_MINI_RING:
		brp = &bgep->buff[BGE_MINI_BUFF_RING];
		break;
#endif	/* BGE_BUFF_RINGS_USED > 2 */

	case 0:
		brp = &bgep->buff[BGE_STD_BUFF_RING];
		break;
	}

	if (hw_rbd.index >= brp->desc.nslots) {
		/* error, this shouldn't happen */
		BGE_PKTDUMP((bgep, &hw_rbd, NULL, "bad ring index!"));
		goto error;
	}

	srbdp = &brp->sw_rbds[hw_rbd.index];
	if (hw_rbd.opaque != srbdp->pbuf.token) {
		/* bogus, drop the packet */
		BGE_PKTDUMP((bgep, &hw_rbd, srbdp, "bad ring token"));
		goto refill;
	}

	if ((hw_rbd.flags & RBD_FLAG_PACKET_END) == 0) {
		/* bogus, drop the packet */
		BGE_PKTDUMP((bgep, &hw_rbd, srbdp, "unterminated packet"));
		goto refill;
	}

	if (hw_rbd.flags & RBD_FLAG_FRAME_HAS_ERROR) {
		/* bogus, drop the packet */
		BGE_PKTDUMP((bgep, &hw_rbd, srbdp, "errored packet"));
		goto refill;
	}

	len = hw_rbd.len;

#ifdef BGE_IPMI_ASF
	/*
	 * When IPMI/ASF is enabled, VLAN tag must be stripped.
	 */
	if (bgep->asf_enabled && (hw_rbd.flags & RBD_FLAG_VLAN_TAG))
		maxsize = bgep->chipid.ethmax_size + ETHERFCSL;
	else
#endif
		/*
		 * H/W will not strip the VLAN tag from incoming packet
		 * now, as RECEIVE_MODE_KEEP_VLAN_TAG bit is set in
		 * RECEIVE_MAC_MODE_REG register.
		 */
		maxsize = bgep->chipid.ethmax_size + VLAN_TAGSZ + ETHERFCSL;
	if (len > maxsize) {
		/* bogus, drop the packet */
		BGE_PKTDUMP((bgep, &hw_rbd, srbdp, "oversize packet"));
		goto refill;
	}

#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled && (hw_rbd.flags & RBD_FLAG_VLAN_TAG))
		minsize = ETHERMIN + ETHERFCSL - VLAN_TAGSZ;
	else
#endif
		minsize = ETHERMIN + ETHERFCSL;
	if (len < minsize) {
		/* bogus, drop the packet */
		BGE_PKTDUMP((bgep, &hw_rbd, srbdp, "undersize packet"));
		goto refill;
	}

	/*
	 * Packet looks good; get a buffer to copy it into.
	 * We want to leave some space at the front of the allocated
	 * buffer in case any upstream modules want to prepend some
	 * sort of header.  This also has the side-effect of making
	 * the packet *contents* 4-byte aligned, as required by NCA!
	 */
#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled && (hw_rbd.flags & RBD_FLAG_VLAN_TAG)) {
		mp = allocb(BGE_HEADROOM + len + VLAN_TAGSZ, 0);
	} else {
#endif

		mp = allocb(BGE_HEADROOM + len, 0);
#ifdef BGE_IPMI_ASF
	}
#endif
	if (mp == NULL) {
		/* Nothing to do but drop the packet */
		goto refill;
	}

	/*
	 * Sync the data and copy it to the STREAMS buffer.
	 */
	DMA_SYNC(srbdp->pbuf, DDI_DMA_SYNC_FORKERNEL);
	if (bge_check_dma_handle(bgep, srbdp->pbuf.dma_hdl) != DDI_FM_OK) {
		bgep->bge_dma_error = B_TRUE;
		bgep->bge_chip_state = BGE_CHIP_ERROR;
		return (NULL);
	}
#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled && (hw_rbd.flags & RBD_FLAG_VLAN_TAG)) {
		/*
		 * As VLAN tag has been stripped from incoming packet in ASF
		 * scenario, we insert it into this packet again.
		 */
		struct ether_vlan_header *ehp;
		mp->b_rptr = dp = mp->b_rptr + BGE_HEADROOM - VLAN_TAGSZ;
		bcopy(DMA_VPTR(srbdp->pbuf), dp, 2 * ETHERADDRL);
		ehp = (void *)dp;
		ehp->ether_tpid = ntohs(ETHERTYPE_VLAN);
		ehp->ether_tci = ntohs(hw_rbd.vlan_tci);
		bcopy(((uchar_t *)(DMA_VPTR(srbdp->pbuf))) + 2 * ETHERADDRL,
		    dp + 2 * ETHERADDRL + VLAN_TAGSZ,
		    len - 2 * ETHERADDRL);
	} else {
#endif
		mp->b_rptr = dp = mp->b_rptr + BGE_HEADROOM;
		bcopy(DMA_VPTR(srbdp->pbuf), dp, len);
#ifdef BGE_IPMI_ASF
	}

	if (bgep->asf_enabled && (hw_rbd.flags & RBD_FLAG_VLAN_TAG)) {
		mp->b_wptr = dp + len + VLAN_TAGSZ - ETHERFCSL;
	} else
#endif
		mp->b_wptr = dp + len - ETHERFCSL;

	/*
	 * Special check for one specific type of data corruption;
	 * in a good packet, the first 8 bytes are *very* unlikely
	 * to be the same as the second 8 bytes ... but we let the
	 * packet through just in case.
	 */
	if (bcmp(dp, dp+8, 8) == 0)
		BGE_PKTDUMP((bgep, &hw_rbd, srbdp, "stuttered packet?"));

	pflags = 0;
	if (hw_rbd.flags & RBD_FLAG_TCP_UDP_CHECKSUM)
		pflags |= HCK_FULLCKSUM;
	if (hw_rbd.flags & RBD_FLAG_IP_CHECKSUM)
		pflags |= HCK_IPV4_HDRCKSUM_OK;
	if (pflags != 0)
		mac_hcksum_set(mp, 0, 0, 0, hw_rbd.tcp_udp_cksum, pflags);

	/* Update per-ring rx statistics */
	rrp->rx_pkts++;
	rrp->rx_bytes += len;

refill:
	/*
	 * Replace the buffer in the ring it came from ...
	 */
	bge_refill(bgep, brp, srbdp);
	return (mp);

error:
	/*
	 * We come here if the integrity of the ring descriptors
	 * (rather than merely packet data) appears corrupted.
	 * The factotum will attempt to reset-and-recover.
	 */
	bgep->bge_chip_state = BGE_CHIP_ERROR;
	bge_fm_ereport(bgep, DDI_FM_DEVICE_INVAL_STATE);
	return (NULL);
}

/*
 * Accept the packets received in the specified ring up to
 * (but not including) the producer index in the status block.
 *
 * Returns a chain of mblks containing the received data, to be
 * passed up to gld_recv() (we can't call gld_recv() from here,
 * 'cos we're holding the per-ring receive lock at this point).
 *
 * This function must advance (rrp->rx_next) and write it back to
 * the chip to indicate the packets it has accepted from the ring.
 */
static mblk_t *bge_receive_ring(bge_t *bgep, recv_ring_t *rrp);
#ifndef	DEBUG
#pragma	inline(bge_receive_ring)
#endif

static mblk_t *
bge_receive_ring(bge_t *bgep, recv_ring_t *rrp)
{
	bge_rbd_t *hw_rbd_p;
	uint64_t slot;
	mblk_t *head;
	mblk_t **tail;
	mblk_t *mp;
	int recv_cnt = 0;

	ASSERT(mutex_owned(rrp->rx_lock));

	/*
	 * Sync (all) the receive ring descriptors
	 * before accepting the packets they describe
	 */
	DMA_SYNC(rrp->desc, DDI_DMA_SYNC_FORKERNEL);
	if (*rrp->prod_index_p >= rrp->desc.nslots) {
		bgep->bge_chip_state = BGE_CHIP_ERROR;
		bge_fm_ereport(bgep, DDI_FM_DEVICE_INVAL_STATE);
		return (NULL);
	}
	if (bge_check_dma_handle(bgep, rrp->desc.dma_hdl) != DDI_FM_OK) {
		rrp->rx_next = *rrp->prod_index_p;
		bge_mbx_put(bgep, rrp->chip_mbx_reg, rrp->rx_next);
		bgep->bge_dma_error = B_TRUE;
		bgep->bge_chip_state = BGE_CHIP_ERROR;
		return (NULL);
	}

	hw_rbd_p = DMA_VPTR(rrp->desc);
	head = NULL;
	tail = &head;
	slot = rrp->rx_next;

	while ((slot != *rrp->prod_index_p) && /* Note: volatile	*/
	    (recv_cnt < BGE_MAXPKT_RCVED)) {
		if ((mp = bge_receive_packet(bgep, &hw_rbd_p[slot], rrp))
		    != NULL) {
			*tail = mp;
			tail = &mp->b_next;
			recv_cnt++;
		}
		rrp->rx_next = slot = NEXT(slot, rrp->desc.nslots);
	}

	bge_mbx_put(bgep, rrp->chip_mbx_reg, rrp->rx_next);
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
		bgep->bge_chip_state = BGE_CHIP_ERROR;
	return (head);
}

/*
 * XXX: Poll a particular ring. The implementation is incomplete.
 * Once the ring interrupts are disabled, we need to do bge_recyle()
 * for the ring as well and re enable the ring interrupt automatically
 * if the poll doesn't find any packets in the ring. We need to
 * have MSI-X interrupts support for this.
 *
 * The basic poll policy is that rings that are dealing with explicit
 * flows (like TCP or some service) and are marked as such should
 * have their own MSI-X interrupt per ring. bge_intr() should leave
 * that interrupt disabled after an upcall. The ring is in poll mode.
 * When a poll thread comes down and finds nothing, the MSI-X interrupt
 * is automatically enabled. Squeue needs to deal with the race of
 * a new interrupt firing and reaching before poll thread returns.
 */
mblk_t *
bge_poll_ring(void *arg, int bytes_to_pickup)
{
	recv_ring_t *rrp = arg;
	bge_t *bgep = rrp->bgep;
	bge_rbd_t *hw_rbd_p;
	uint64_t slot;
	mblk_t *head;
	mblk_t **tail;
	mblk_t *mp;
	size_t sz = 0;

	mutex_enter(rrp->rx_lock);

	/*
	 * Sync (all) the receive ring descriptors
	 * before accepting the packets they describe
	 */
	DMA_SYNC(rrp->desc, DDI_DMA_SYNC_FORKERNEL);
	if (*rrp->prod_index_p >= rrp->desc.nslots) {
		bgep->bge_chip_state = BGE_CHIP_ERROR;
		bge_fm_ereport(bgep, DDI_FM_DEVICE_INVAL_STATE);
		mutex_exit(rrp->rx_lock);
		return (NULL);
	}
	if (bge_check_dma_handle(bgep, rrp->desc.dma_hdl) != DDI_FM_OK) {
		rrp->rx_next = *rrp->prod_index_p;
		bge_mbx_put(bgep, rrp->chip_mbx_reg, rrp->rx_next);
		bgep->bge_dma_error = B_TRUE;
		bgep->bge_chip_state = BGE_CHIP_ERROR;
		mutex_exit(rrp->rx_lock);
		return (NULL);
	}

	hw_rbd_p = DMA_VPTR(rrp->desc);
	head = NULL;
	tail = &head;
	slot = rrp->rx_next;

	/* Note: volatile */
	while ((slot != *rrp->prod_index_p) && (sz <= bytes_to_pickup)) {
		if ((mp = bge_receive_packet(bgep, &hw_rbd_p[slot], rrp))
		    != NULL) {
			*tail = mp;
			sz += msgdsize(mp);
			tail = &mp->b_next;
		}
		rrp->rx_next = slot = NEXT(slot, rrp->desc.nslots);
	}

	bge_mbx_put(bgep, rrp->chip_mbx_reg, rrp->rx_next);
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
		bgep->bge_chip_state = BGE_CHIP_ERROR;
	mutex_exit(rrp->rx_lock);
	return (head);
}

/*
 * Receive all packets in all rings.
 */
void bge_receive(bge_t *bgep, bge_status_t *bsp);
#pragma	no_inline(bge_receive)

void
bge_receive(bge_t *bgep, bge_status_t *bsp)
{
	recv_ring_t *rrp;
	uint64_t index;
	mblk_t *mp;

	for (index = 0; index < bgep->chipid.rx_rings; index++) {
		/*
		 * Start from the first ring.
		 */
		rrp = &bgep->recv[index];

		/*
		 * For each ring, (rrp->prod_index_p) points to the
		 * proper index within the status block (which has
		 * already been sync'd by the caller)
		 */
		ASSERT(rrp->prod_index_p == RECV_INDEX_P(bsp, index));

		if (*rrp->prod_index_p == rrp->rx_next || rrp->poll_flag)
			continue;		/* no packets		*/
		if (mutex_tryenter(rrp->rx_lock) == 0)
			continue;		/* already in process	*/
		mp = bge_receive_ring(bgep, rrp);
		mutex_exit(rrp->rx_lock);

		if (mp != NULL)
			mac_rx_ring(bgep->mh, rrp->ring_handle, mp,
			    rrp->ring_gen_num);
	}
}
