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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rge.h"

#define	U32TOPTR(x)	((void *)(uintptr_t)(uint32_t)(x))
#define	PTRTOU32(x)	((uint32_t)(uintptr_t)(void *)(x))

/*
 * ========== RX side routines ==========
 */

#define	RGE_DBG		RGE_DBG_RECV	/* debug flag for this code	*/

static uint32_t rge_atomic_reserve(uint32_t *count_p, uint32_t n);
#pragma	inline(rge_atomic_reserve)

static uint32_t
rge_atomic_reserve(uint32_t *count_p, uint32_t n)
{
	uint32_t oldval;
	uint32_t newval;

	/* ATOMICALLY */
	do {
		oldval = *count_p;
		newval = oldval - n;
		if (oldval <= n)
			return (0);		/* no resources left	*/
	} while (cas32(count_p, oldval, newval) != oldval);

	return (newval);
}

/*
 * Atomically increment a counter
 */
static void rge_atomic_renounce(uint32_t *count_p, uint32_t n);
#pragma	inline(rge_atomic_renounce)

static void
rge_atomic_renounce(uint32_t *count_p, uint32_t n)
{
	uint32_t oldval;
	uint32_t newval;

	/* ATOMICALLY */
	do {
		oldval = *count_p;
		newval = oldval + n;
	} while (cas32(count_p, oldval, newval) != oldval);
}

/*
 * Callback code invoked from STREAMs when the recv data buffer is free
 * for recycling.
 */

void
rge_rx_recycle(caddr_t arg)
{
	rge_t *rgep;
	dma_buf_t *rx_buf;
	sw_rbd_t *free_rbdp;
	uint32_t slot_recy;

	rx_buf = (dma_buf_t *)arg;
	rgep = (rge_t *)rx_buf->private;

	/*
	 * If rge_unattach() is called, this callback function will also
	 * be called when we try to free the mp in rge_fini_rings().
	 * In such situation, we needn't do below desballoc(), otherwise,
	 * there'll be memory leak.
	 */
	if (rgep->rge_mac_state == RGE_MAC_UNATTACH)
		return;

	/*
	 * Recycle the data buffer again
	 * and fill them in free ring
	 */
	rx_buf->mp = desballoc(DMA_VPTR(rx_buf->pbuf),
	    rgep->rxbuf_size, 0, &rx_buf->rx_recycle);
	if (rx_buf->mp == NULL) {
		rge_problem(rgep, "rge_rx_recycle: desballoc() failed");
		return;
	}
	mutex_enter(rgep->rc_lock);
	slot_recy = rgep->rc_next;
	free_rbdp = &rgep->free_rbds[slot_recy];
	if (free_rbdp->rx_buf == NULL) {
		free_rbdp->rx_buf = rx_buf;
		rgep->rc_next = NEXT(slot_recy, RGE_BUF_SLOTS);
		rge_atomic_renounce(&rgep->rx_free, 1);
		if (rgep->rx_bcopy && rgep->rx_free == RGE_BUF_SLOTS)
			rgep->rx_bcopy = B_FALSE;
		ASSERT(rgep->rx_free <= RGE_BUF_SLOTS);
	} else {
		/*
		 * This situation shouldn't happen
		 */
		rge_problem(rgep, "rge_rx_recycle: buffer %d recycle error",
		    slot_recy);
		rgep->stats.recycle_err++;
	}
	mutex_exit(rgep->rc_lock);
}

static int rge_rx_refill(rge_t *rgep, uint32_t slot);
#pragma	inline(rge_rx_refill)

static int
rge_rx_refill(rge_t *rgep, uint32_t slot)
{
	dma_buf_t *free_buf;
	rge_bd_t *hw_rbd_p;
	sw_rbd_t *srbdp;
	uint32_t free_slot;

	srbdp = &rgep->sw_rbds[slot];
	hw_rbd_p = &rgep->rx_ring[slot];
	free_slot = rgep->rf_next;
	free_buf = rgep->free_rbds[free_slot].rx_buf;
	if (free_buf != NULL) {
		srbdp->rx_buf = free_buf;
		rgep->free_rbds[free_slot].rx_buf = NULL;
		hw_rbd_p->host_buf_addr = RGE_BSWAP_32(RGE_HEADROOM +
		    + free_buf->pbuf.cookie.dmac_laddress);
		hw_rbd_p->host_buf_addr_hi =
		    RGE_BSWAP_32(free_buf->pbuf.cookie.dmac_laddress >> 32);
		rgep->rf_next = NEXT(free_slot, RGE_BUF_SLOTS);
		return (1);
	} else {
		/*
		 * This situation shouldn't happen
		 */
		rge_problem(rgep, "rge_rx_refill: free buffer %d is NULL",
		    free_slot);
		rgep->rx_bcopy = B_TRUE;
		return (0);
	}
}

static mblk_t *rge_receive_packet(rge_t *rgep, uint32_t slot);
#pragma	inline(rge_receive_packet)

static mblk_t *
rge_receive_packet(rge_t *rgep, uint32_t slot)
{
	rge_bd_t *hw_rbd_p;
	sw_rbd_t *srbdp;
	uchar_t *dp;
	mblk_t *mp;
	uint8_t *rx_ptr;
	uint32_t rx_status;
	uint_t packet_len;
	uint_t minsize;
	uint_t maxsize;
	uint32_t proto;
	uint32_t pflags;
	struct ether_vlan_header *ehp;
	uint16_t vtag = 0;

	hw_rbd_p = &rgep->rx_ring[slot];
	srbdp = &rgep->sw_rbds[slot];
	packet_len = RGE_BSWAP_32(hw_rbd_p->flags_len) & RBD_LEN_MASK;

	/*
	 * Read receive status
	 */
	rx_status = RGE_BSWAP_32(hw_rbd_p->flags_len) & RBD_FLAGS_MASK;

	/*
	 * Handle error packet
	 */
	if (!(rx_status & BD_FLAG_PKT_END)) {
		RGE_DEBUG(("rge_receive_packet: not a complete packat"));
		return (NULL);
	}
	if (rx_status & RBD_FLAG_ERROR) {
		if (rx_status & RBD_FLAG_CRC_ERR)
			rgep->stats.crc_err++;
		if (rx_status & RBD_FLAG_RUNT)
			rgep->stats.in_short++;
		/*
		 * Set chip_error flag to reset chip:
		 * (suggested in Realtek programming guide.)
		 */
		RGE_DEBUG(("rge_receive_packet: error packet, status = %x",
		    rx_status));
		mutex_enter(rgep->genlock);
		rgep->rge_chip_state = RGE_CHIP_ERROR;
		mutex_exit(rgep->genlock);
		return (NULL);
	}

	/*
	 * Handle size error packet
	 */
	minsize = ETHERMIN  - VLAN_TAGSZ + ETHERFCSL;
	maxsize = rgep->ethmax_size + ETHERFCSL;

	if (packet_len < minsize || packet_len > maxsize) {
		RGE_DEBUG(("rge_receive_packet: len err = %d", packet_len));
		return (NULL);
	}

	DMA_SYNC(srbdp->rx_buf->pbuf, DDI_DMA_SYNC_FORKERNEL);
	if (packet_len <= RGE_RECV_COPY_SIZE || rgep->rx_bcopy ||
	    !rge_atomic_reserve(&rgep->rx_free, 1)) {
		/*
		 * Allocate buffer to receive this good packet
		 */
		mp = allocb(packet_len + RGE_HEADROOM, 0);
		if (mp == NULL) {
			RGE_DEBUG(("rge_receive_packet: allocate buffer fail"));
			rgep->stats.no_rcvbuf++;
			return (NULL);
		}

		/*
		 * Copy the data found into the new cluster
		 */
		rx_ptr = DMA_VPTR(srbdp->rx_buf->pbuf);
		mp->b_rptr = dp = mp->b_rptr + RGE_HEADROOM;
		bcopy(rx_ptr + RGE_HEADROOM, dp, packet_len);
		mp->b_wptr = dp + packet_len - ETHERFCSL;
	} else {
		mp = srbdp->rx_buf->mp;
		mp->b_rptr += RGE_HEADROOM;
		mp->b_wptr = mp->b_rptr + packet_len - ETHERFCSL;
		mp->b_next = mp->b_cont = NULL;
		/*
		 * Refill the current receive bd buffer
		 *   if fails, will just keep the mp.
		 */
		if (!rge_rx_refill(rgep, slot))
			return (NULL);
	}
	rgep->stats.rbytes += packet_len;

	/*
	 * VLAN packet ?
	 */
	pflags = RGE_BSWAP_32(hw_rbd_p->vlan_tag);
	if (pflags & RBD_VLAN_PKT)
		vtag = pflags & RBD_VLAN_TAG;
	if (vtag) {
		vtag = TCI_CHIP2OS(vtag);
		/*
		 * As h/w strips the VLAN tag from incoming packet, we need
		 * insert VLAN tag into this packet before send up here.
		 */
		(void) memmove(mp->b_rptr - VLAN_TAGSZ, mp->b_rptr,
		    2 * ETHERADDRL);
		mp->b_rptr -= VLAN_TAGSZ;
		ehp = (struct ether_vlan_header *)mp->b_rptr;
		ehp->ether_tpid = htons(VLAN_TPID);
		ehp->ether_tci = htons(vtag);
	}

	/*
	 * Check h/w checksum offload status
	 */
	pflags = 0;
	proto = rx_status & RBD_FLAG_PROTOCOL;
	if ((proto == RBD_FLAG_TCP && !(rx_status & RBD_TCP_CKSUM_ERR)) ||
	    (proto == RBD_FLAG_UDP && !(rx_status & RBD_UDP_CKSUM_ERR)))
		pflags |= HCK_FULLCKSUM | HCK_FULLCKSUM_OK;
	if (proto != RBD_FLAG_NONE_IP && !(rx_status & RBD_IP_CKSUM_ERR))
		pflags |= HCK_IPV4_HDRCKSUM;
	if (pflags != 0)  {
		(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, 0, pflags, 0);
	}

	return (mp);
}

/*
 * Accept the packets received in rx ring.
 *
 * Returns a chain of mblks containing the received data, to be
 * passed up to mac_rx().
 * The routine returns only when a complete scan has been performed
 * without finding any packets to receive.
 * This function must SET the OWN bit of BD to indicate the packets
 * it has accepted from the ring.
 */
static mblk_t *rge_receive_ring(rge_t *rgep);
#pragma	inline(rge_receive_ring)

static mblk_t *
rge_receive_ring(rge_t *rgep)
{
	rge_bd_t *hw_rbd_p;
	mblk_t *head;
	mblk_t **tail;
	mblk_t *mp;
	uint32_t slot;

	ASSERT(mutex_owned(rgep->rx_lock));

	/*
	 * Sync (all) the receive ring descriptors
	 * before accepting the packets they describe
	 */
	DMA_SYNC(rgep->rx_desc, DDI_DMA_SYNC_FORKERNEL);
	slot = rgep->rx_next;
	hw_rbd_p = &rgep->rx_ring[slot];
	head = NULL;
	tail = &head;

	while (!(hw_rbd_p->flags_len & RGE_BSWAP_32(BD_FLAG_HW_OWN))) {
		if ((mp = rge_receive_packet(rgep, slot)) != NULL) {
			*tail = mp;
			tail = &mp->b_next;
		}

		/*
		 * Clear RBD flags
		 */
		hw_rbd_p->flags_len =
		    RGE_BSWAP_32(rgep->rxbuf_size - RGE_HEADROOM);
		HW_RBD_INIT(hw_rbd_p, slot);
		slot = NEXT(slot, RGE_RECV_SLOTS);
		hw_rbd_p = &rgep->rx_ring[slot];
	}

	rgep->rx_next = slot;
	return (head);
}

/*
 * Receive all ready packets.
 */
void rge_receive(rge_t *rgep);
#pragma	no_inline(rge_receive)

void
rge_receive(rge_t *rgep)
{
	mblk_t *mp;

	mutex_enter(rgep->rx_lock);
	mp = rge_receive_ring(rgep);
	mutex_exit(rgep->rx_lock);

	if (mp != NULL)
		mac_rx(rgep->mh, rgep->handle, mp);
}


#undef	RGE_DBG
#define	RGE_DBG		RGE_DBG_SEND	/* debug flag for this code	*/


/*
 * ========== Send-side recycle routines ==========
 */
static uint32_t rge_send_claim(rge_t *rgep);
#pragma	inline(rge_send_claim)

static uint32_t
rge_send_claim(rge_t *rgep)
{
	uint32_t slot;
	uint32_t next;

	mutex_enter(rgep->tx_lock);
	slot = rgep->tx_next;
	next = NEXT(slot, RGE_SEND_SLOTS);
	rgep->tx_next = next;
	rgep->tx_flow++;
	mutex_exit(rgep->tx_lock);

	/*
	 * We check that our invariants still hold:
	 * +	the slot and next indexes are in range
	 * +	the slot must not be the last one (i.e. the *next*
	 *	index must not match the next-recycle index), 'cos
	 *	there must always be at least one free slot in a ring
	 */
	ASSERT(slot < RGE_SEND_SLOTS);
	ASSERT(next < RGE_SEND_SLOTS);
	ASSERT(next != rgep->tc_next);

	return (slot);
}

/*
 * We don't want to call this function every time after a successful
 * h/w transmit done in ISR.  Instead, we call this function in the
 * rge_send() when there're few or no free tx BDs remained.
 */
static void rge_send_recycle(rge_t *rgep);
#pragma	inline(rge_send_recycle)

static void
rge_send_recycle(rge_t *rgep)
{
	rge_bd_t *hw_sbd_p;
	uint32_t tc_tail;
	uint32_t tc_head;
	uint32_t n;

	if (rgep->tx_free == RGE_SEND_SLOTS)
		return;

	mutex_enter(rgep->tc_lock);
	tc_head = rgep->tc_next;
	tc_tail = rgep->tc_tail;

	do {
		tc_tail = LAST(tc_tail, RGE_SEND_SLOTS);
		hw_sbd_p = &rgep->tx_ring[tc_tail];
		if (tc_tail == tc_head) {
			if (hw_sbd_p->flags_len &
			    RGE_BSWAP_32(BD_FLAG_HW_OWN)) {
				/*
				 * Bump the watchdog counter, thus guaranteeing
				 * that it's nonzero (watchdog activated).
				 */
				rgep->watchdog += 1;
				mutex_exit(rgep->tc_lock);
				return;
			}
			break;
		}
	} while (hw_sbd_p->flags_len & RGE_BSWAP_32(BD_FLAG_HW_OWN));

	rgep->tc_next = NEXT(tc_tail, RGE_SEND_SLOTS);
	n = rgep->tc_next - tc_head;
	if (rgep->tc_next < tc_head)
		n += RGE_SEND_SLOTS;
	rge_atomic_renounce(&rgep->tx_free, n);
	rgep->watchdog = 0;
	mutex_exit(rgep->tc_lock);

	if (rgep->resched_needed) {
		rgep->resched_needed = 0;
		ddi_trigger_softintr(rgep->resched_id);
	}
}

/*
 * Send a message by copying it into a preallocated (and premapped) buffer
 */
static void rge_send_copy(rge_t *rgep, mblk_t *mp, uint16_t tci, uchar_t proto);
#pragma	inline(rge_send_copy)

static void
rge_send_copy(rge_t *rgep, mblk_t *mp, uint16_t tci, uchar_t proto)
{
	rge_bd_t *hw_sbd_p;
	sw_sbd_t *ssbdp;
	mblk_t *bp;
	char *txb;
	uint32_t slot;
	size_t totlen;
	size_t mblen;
	uint32_t pflags;

	/*
	 * IMPORTANT:
	 *	Up to the point where it claims a place, a send_msg()
	 *	routine can indicate failure by returning B_FALSE.  Once it's
	 *	claimed a place, it mustn't fail.
	 *
	 * In this version, there's no setup to be done here, and there's
	 * nothing that can fail, so we can go straight to claiming our
	 * already-reserved place on the train.
	 *
	 * This is the point of no return!
	 */
	slot = rge_send_claim(rgep);
	ssbdp = &rgep->sw_sbds[slot];

	/*
	 * Copy the data into a pre-mapped buffer, which avoids the
	 * overhead (and complication) of mapping/unmapping STREAMS
	 * buffers and keeping hold of them until the DMA has completed.
	 *
	 * Because all buffers are the same size, and larger than the
	 * longest single valid message, we don't have to bother about
	 * splitting the message across multiple buffers either.
	 */
	txb = DMA_VPTR(ssbdp->pbuf);
	for (totlen = 0, bp = mp; bp != NULL; bp = bp->b_cont) {
		mblen = bp->b_wptr - bp->b_rptr;
		if ((totlen += mblen) <= rgep->ethmax_size) {
			bcopy(bp->b_rptr, txb, mblen);
			txb += mblen;
		}
	}
	rgep->stats.obytes += totlen + ETHERFCSL;

	/*
	 * We'e reached the end of the chain; and we should have
	 * collected no more than ETHERMAX bytes into our buffer.
	 */
	ASSERT(bp == NULL);
	ASSERT(totlen <= rgep->ethmax_size);
	DMA_SYNC(ssbdp->pbuf, DDI_DMA_SYNC_FORDEV);

	/*
	 * Update the hardware send buffer descriptor; then we're done
	 * and return. The message can be freed right away in rge_send(),
	 * as we've already copied the contents ...
	 */
	hw_sbd_p = &rgep->tx_ring[slot];
	hw_sbd_p->flags_len = RGE_BSWAP_32(totlen & SBD_LEN_MASK);
	if (tci != 0) {
		tci = TCI_OS2CHIP(tci);
		hw_sbd_p->vlan_tag = RGE_BSWAP_32(tci);
		hw_sbd_p->vlan_tag |= RGE_BSWAP_32(SBD_VLAN_PKT);
	} else {
		hw_sbd_p->vlan_tag = 0;
	}

	hcksum_retrieve(mp, NULL, NULL, NULL, NULL, NULL, NULL, &pflags);
	if (pflags & HCK_FULLCKSUM) {
		switch (proto) {
		case IS_UDP_PKT:
			hw_sbd_p->flags_len |= RGE_BSWAP_32(SBD_FLAG_UDP_CKSUM);
			proto = IS_IPV4_PKT;
			break;
		case IS_TCP_PKT:
			hw_sbd_p->flags_len |= RGE_BSWAP_32(SBD_FLAG_TCP_CKSUM);
			proto = IS_IPV4_PKT;
			break;
		default:
			break;
		}
	}
	if ((pflags & HCK_IPV4_HDRCKSUM) && (proto == IS_IPV4_PKT))
		hw_sbd_p->flags_len |= RGE_BSWAP_32(SBD_FLAG_IP_CKSUM);

	HW_SBD_SET(hw_sbd_p, slot);
}

static boolean_t
rge_send(rge_t *rgep, mblk_t *mp)
{
	struct ether_vlan_header *ehp;
	boolean_t need_strip = B_FALSE;
	uint16_t tci = 0;
	uchar_t proto = UNKNOWN_PKT;
	struct ether_header *ethhdr;
	struct ip *ip_hdr;

	ASSERT(mp->b_next == NULL);

	/*
	 * Determine if the packet is VLAN tagged.
	 */
	ASSERT(MBLKL(mp) >= sizeof (struct ether_header));
	ehp = (struct ether_vlan_header *)mp->b_rptr;

	if (ehp->ether_tpid == htons(VLAN_TPID)) {
		if (MBLKL(mp) < sizeof (struct ether_vlan_header)) {
			uint32_t pflags;

			/*
			 * Need to preserve checksum flags across pullup.
			 */
			hcksum_retrieve(mp, NULL, NULL, NULL, NULL, NULL,
			    NULL, &pflags);

			if (!pullupmsg(mp,
			    sizeof (struct ether_vlan_header))) {
				RGE_DEBUG(("rge_send: pullup failure"));
				rgep->resched_needed = B_TRUE;
				return (B_FALSE);
			}

			(void) hcksum_assoc(mp, NULL, NULL, NULL, NULL, NULL,
			    NULL, pflags, KM_NOSLEEP);
		}

		ehp = (struct ether_vlan_header *)mp->b_rptr;
		need_strip = B_TRUE;
	}

	/*
	 * Try to reserve a place in the transmit ring.
	 */
	if (!rge_atomic_reserve(&rgep->tx_free, 1)) {
		RGE_DEBUG(("rge_send: no free slots"));
		rgep->stats.defer++;
		rgep->resched_needed = B_TRUE;
		rge_send_recycle(rgep);
		return (B_FALSE);
	}

	/*
	 * We've reserved a place :-)
	 * These ASSERTions check that our invariants still hold:
	 *	there must still be at least one free place
	 *	there must be at least one place NOT free (ours!)
	 */
	ASSERT(rgep->tx_free < RGE_SEND_SLOTS);

	/*
	 * Now that we know that there is space to transmit the packet
	 * strip any VLAN tag that is present.
	 */
	if (need_strip) {
		tci = ntohs(ehp->ether_tci);
		(void) memmove(mp->b_rptr + VLAN_TAGSZ, mp->b_rptr,
		    2 * ETHERADDRL);
		mp->b_rptr += VLAN_TAGSZ;
	}

	/*
	 * Check the packet protocol type for according h/w checksum offload
	 */
	if (MBLKL(mp) >= sizeof (struct ether_header) +
	    sizeof (struct ip)) {
		ethhdr = (struct ether_header *)(mp->b_rptr);
		/*
		 * Is the packet an IP(v4) packet?
		 */
		if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
			proto = IS_IPV4_PKT;
			ip_hdr = (struct ip *)(mp->b_rptr +
			    sizeof (struct ether_header));
			if (ip_hdr->ip_p == IPPROTO_TCP)
				proto = IS_TCP_PKT;
			else if (ip_hdr->ip_p == IPPROTO_UDP)
				proto = IS_UDP_PKT;
		}
	}

	rge_send_copy(rgep, mp, tci, proto);

	/*
	 * Trigger chip h/w transmit ...
	 */
	mutex_enter(rgep->tx_lock);
	if (--rgep->tx_flow == 0) {
		DMA_SYNC(rgep->tx_desc, DDI_DMA_SYNC_FORDEV);
		rge_tx_trigger(rgep);
		if (rgep->tx_free < RGE_SEND_SLOTS/32)
			rge_send_recycle(rgep);
		rgep->tc_tail = rgep->tx_next;
	}
	mutex_exit(rgep->tx_lock);

	freemsg(mp);
	return (B_TRUE);
}

uint_t
rge_reschedule(caddr_t arg)
{
	rge_t *rgep;
	uint_t rslt;

	rgep = (rge_t *)arg;
	rslt = DDI_INTR_UNCLAIMED;

	if (rgep->rge_mac_state == RGE_MAC_STARTED && rgep->resched_needed) {
		mac_tx_update(rgep->mh);
		rgep->resched_needed = B_FALSE;
		rslt = DDI_INTR_CLAIMED;
	}

	return (rslt);
}

/*
 * rge_m_tx() - send a chain of packets
 */
mblk_t *
rge_m_tx(void *arg, mblk_t *mp)
{
	rge_t *rgep = arg;		/* private device info	*/
	mblk_t *next;

	ASSERT(mp != NULL);
	ASSERT(rgep->rge_mac_state == RGE_MAC_STARTED);

	if (rgep->rge_chip_state != RGE_CHIP_RUNNING) {
		RGE_DEBUG(("rge_m_tx: chip not running"));
		return (mp);
	}

	rw_enter(rgep->errlock, RW_READER);
	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (!rge_send(rgep, mp)) {
			mp->b_next = next;
			break;
		}

		mp = next;
	}
	rw_exit(rgep->errlock);

	return (mp);
}
