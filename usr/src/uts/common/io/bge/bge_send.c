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
 * Copyright (c) 2010-2013, by Broadcom, Inc.
 * All Rights Reserved.
 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates.
 * All rights reserved.
 */

#include "bge_impl.h"


/*
 * The transmit-side code uses an allocation process which is similar
 * to some theme park roller-coaster rides, where riders sit in cars
 * that can go individually, but work better in a train.
 *
 * 1)	RESERVE a place - this doesn't refer to any specific car or
 *	seat, just that you will get a ride.  The attempt to RESERVE a
 *	place can fail if all spaces in all cars are already committed.
 *
 * 2)	Prepare yourself; this may take an arbitrary (but not unbounded)
 *	time, and you can back out at this stage, in which case you must
 *	give up (RENOUNCE) your place.
 *
 * 3)	CLAIM your space - a specific car (the next sequentially
 *	numbered one) is allocated at this stage, and is guaranteed
 *	to be part of the next train to depart.  Once you've done
 *	this, you can't back out, nor wait for any external event
 *	or resource.
 *
 * 4)	Occupy your car - when all CLAIMED cars are OCCUPIED, they
 *	all depart together as a single train!
 *
 * 5)	At the end of the ride, you climb out of the car and RENOUNCE
 *	your right to it, so that it can be recycled for another rider.
 *
 * For each rider, these have to occur in this order, but the riders
 * don't have to stay in the same order at each stage.  In particular,
 * they may overtake each other between RESERVING a place and CLAIMING
 * it, or between CLAIMING and OCCUPYING a space.
 *
 * Once a car is CLAIMED, the train currently being assembled can't go
 * without that car (this guarantees that the cars in a single train
 * make up a consecutively-numbered set).  Therefore, when any train
 * leaves, we know there can't be any riders in transit between CLAIMING
 * and OCCUPYING their cars.  There can be some who have RESERVED but
 * not yet CLAIMED their places.  That's OK, though, because they'll go
 * into the next train.
 */

#define	BGE_DBG		BGE_DBG_SEND	/* debug flag for this code	*/

/*
 * ========== Send-side recycle routines ==========
 */

/*
 * Recycle all the completed buffers in the specified send ring up to
 * (but not including) the consumer index in the status block.
 *
 * This function must advance (srp->tc_next) AND adjust (srp->tx_free)
 * to account for the packets it has recycled.
 *
 * This is a trivial version that just does that and nothing more, but
 * it suffices while there's only one method for sending messages (by
 * copying) and that method doesn't need any special per-buffer action
 * for recycling.
 */
static boolean_t bge_recycle_ring(bge_t *bgep, send_ring_t *srp);
#pragma	inline(bge_recycle_ring)

static boolean_t
bge_recycle_ring(bge_t *bgep, send_ring_t *srp)
{
	sw_sbd_t *ssbdp;
	bge_queue_item_t *buf_item;
	bge_queue_item_t *buf_item_head;
	bge_queue_item_t *buf_item_tail;
	bge_queue_t *txbuf_queue;
	uint64_t slot;
	uint64_t n;

	ASSERT(mutex_owned(srp->tc_lock));

	/*
	 * We're about to release one or more places :-)
	 * These ASSERTions check that our invariants still hold:
	 *	there must always be at least one free place
	 *	at this point, there must be at least one place NOT free
	 *	we're not about to free more places than were claimed!
	 */
	ASSERT(srp->tx_free <= srp->desc.nslots);

	buf_item_head = buf_item_tail = NULL;
	for (n = 0, slot = srp->tc_next; slot != *srp->cons_index_p;
	    slot = NEXT(slot, srp->desc.nslots)) {
		ssbdp = &srp->sw_sbds[slot];
		ASSERT(ssbdp->pbuf != NULL);
		buf_item = ssbdp->pbuf;
		if (buf_item_head == NULL)
			buf_item_head = buf_item_tail = buf_item;
		else {
			buf_item_tail->next = buf_item;
			buf_item_tail = buf_item;
		}
		ssbdp->pbuf = NULL;
		n++;
	}
	if (n == 0)
		return (B_FALSE);

	/*
	 * Reset the watchdog count: to 0 if all buffers are
	 * now free, or to 1 if some are still outstanding.
	 * Note: non-synchonised access here means we may get
	 * the "wrong" answer, but only in a harmless fashion
	 * (i.e. we deactivate the watchdog because all buffers
	 * are apparently free, even though another thread may
	 * have claimed one before we leave here; in this case
	 * the watchdog will restart on the next send() call).
	 */
	bgep->watchdog = (slot == srp->tx_next) ? 0 : 1;

	/*
	 * Update recycle index and free tx BD number
	 */
	srp->tc_next = slot;
	ASSERT(srp->tx_free + n <= srp->desc.nslots);
	bge_atomic_renounce(&srp->tx_free, n);

	/*
	 * Return tx buffers to buffer push queue
	 */
	txbuf_queue = srp->txbuf_push_queue;
	mutex_enter(txbuf_queue->lock);
	buf_item_tail->next = txbuf_queue->head;
	txbuf_queue->head = buf_item_head;
	txbuf_queue->count += n;
	mutex_exit(txbuf_queue->lock);

	/*
	 * Check if we need exchange the tx buffer push and pop queue
	 */
	if ((srp->txbuf_pop_queue->count < srp->tx_buffers_low) &&
	    (srp->txbuf_pop_queue->count < txbuf_queue->count)) {
		srp->txbuf_push_queue = srp->txbuf_pop_queue;
		srp->txbuf_pop_queue = txbuf_queue;
	}

	if (srp->tx_flow != 0 || bgep->tx_resched_needed)
		ddi_trigger_softintr(bgep->drain_id);

	return (B_TRUE);
}

/*
 * Recycle all returned slots in all rings.
 *
 * To give priority to low-numbered rings, whenever we have recycled any
 * slots in any ring except 0, we restart scanning again from ring 0.
 * Thus, for example, if rings 0, 3, and 10 are carrying traffic, the
 * pattern of recycles might go 0, 3, 10, 3, 0, 10, 0:
 *
 *	0	found some - recycle them
 *	1..2					none found
 *	3	found some - recycle them	and restart scan
 *	0..9					none found
 *	10	found some - recycle them	and restart scan
 *	0..2					none found
 *	3	found some more - recycle them	and restart scan
 *	0	found some more - recycle them
 *	0..9					none found
 *	10	found some more - recycle them	and restart scan
 *	0	found some more - recycle them
 *	1..15					none found
 *
 * The routine returns only when a complete scan has been performed
 * without finding any slots to recycle.
 *
 * Note: the expression (BGE_SEND_RINGS_USED > 1) yields a compile-time
 * constant and allows the compiler to optimise away the outer do-loop
 * if only one send ring is being used.
 */
boolean_t bge_recycle(bge_t *bgep, bge_status_t *bsp);
#pragma	no_inline(bge_recycle)

boolean_t
bge_recycle(bge_t *bgep, bge_status_t *bsp)
{
	send_ring_t *srp;
	uint64_t ring;
	uint64_t tx_rings = bgep->chipid.tx_rings;
	boolean_t tx_done = B_FALSE;

restart:
	ring = 0;
	srp = &bgep->send[ring];
	do {
		/*
		 * For each ring, (srp->cons_index_p) points to the
		 * proper index within the status block (which has
		 * already been sync'd by the caller).
		 */
		ASSERT(srp->cons_index_p == SEND_INDEX_P(bsp, ring));

		if (*srp->cons_index_p == srp->tc_next)
			continue;		/* no slots to recycle	*/
		if (mutex_tryenter(srp->tc_lock) == 0)
			continue;		/* already in process	*/
		tx_done |= bge_recycle_ring(bgep, srp);
		mutex_exit(srp->tc_lock);

		/*
		 * Restart from ring 0, if we're not on ring 0 already.
		 * As H/W selects send BDs totally based on priority and
		 * available BDs on the higher priority ring are always
		 * selected first, driver should keep consistence with H/W
		 * and gives lower-numbered ring with higher priority.
		 */
		if (tx_rings > 1 && ring > 0)
			goto restart;

		/*
		 * Loop over all rings (if there *are* multiple rings)
		 */
	} while (++srp, ++ring < tx_rings);

	return (tx_done);
}


/*
 * ========== Send-side transmit routines ==========
 */
#define	TCP_CKSUM_OFFSET	16
#define	UDP_CKSUM_OFFSET	6

static void
bge_pseudo_cksum(uint8_t *buf)
{
	uint32_t cksum;
	uint16_t iphl;
	uint16_t proto;

	/*
	 * Point it to the ip header.
	 */
	buf += sizeof (struct ether_header);

	/*
	 * Calculate the pseudo-header checksum.
	 */
	iphl = 4 * (buf[0] & 0xF);
	cksum = (((uint16_t)buf[2])<<8) + buf[3] - iphl;
	cksum += proto = buf[9];
	cksum += (((uint16_t)buf[12])<<8) + buf[13];
	cksum += (((uint16_t)buf[14])<<8) + buf[15];
	cksum += (((uint16_t)buf[16])<<8) + buf[17];
	cksum += (((uint16_t)buf[18])<<8) + buf[19];
	cksum = (cksum>>16) + (cksum & 0xFFFF);
	cksum = (cksum>>16) + (cksum & 0xFFFF);

	/*
	 * Point it to the TCP/UDP header, and
	 * update the checksum field.
	 */
	buf += iphl + ((proto == IPPROTO_TCP) ?
	    TCP_CKSUM_OFFSET : UDP_CKSUM_OFFSET);

	/*
	 * A real possibility that pointer cast is a problem.
	 * Should be fixed when we know the code better.
	 * E_BAD_PTR_CAST_ALIGN is added to make it temporarily clean.
	 */
	*(uint16_t *)buf = htons((uint16_t)cksum);
}

static bge_queue_item_t *
bge_get_txbuf(bge_t *bgep, send_ring_t *srp)
{
	bge_queue_item_t *txbuf_item;
	bge_queue_t *txbuf_queue;

	txbuf_queue = srp->txbuf_pop_queue;
	mutex_enter(txbuf_queue->lock);
	if (txbuf_queue->count == 0) {
		mutex_exit(txbuf_queue->lock);
		txbuf_queue = srp->txbuf_push_queue;
		mutex_enter(txbuf_queue->lock);
		if (txbuf_queue->count == 0) {
			mutex_exit(txbuf_queue->lock);
			/* Try to allocate more tx buffers */
			if (srp->tx_array < srp->tx_array_max) {
				mutex_enter(srp->tx_lock);
				txbuf_item = bge_alloc_txbuf_array(bgep, srp);
				mutex_exit(srp->tx_lock);
			} else
				txbuf_item = NULL;
			return (txbuf_item);
		}
	}
	txbuf_item = txbuf_queue->head;
	txbuf_queue->head = (bge_queue_item_t *)txbuf_item->next;
	txbuf_queue->count--;
	mutex_exit(txbuf_queue->lock);
	txbuf_item->next = NULL;

	return (txbuf_item);
}

/*
 * Send a message by copying it into a preallocated (and premapped) buffer
 */
static void bge_send_copy(bge_t *bgep, sw_txbuf_t *txbuf, mblk_t *mp);
#pragma	inline(bge_send_copy)

static void
bge_send_copy(bge_t *bgep, sw_txbuf_t *txbuf, mblk_t *mp)
{
	mblk_t *bp;
	uint32_t mblen;
	char *pbuf;

	txbuf->copy_len = 0;
	pbuf = DMA_VPTR(txbuf->buf);
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		if ((mblen = MBLKL(bp)) == 0)
			continue;
		ASSERT(txbuf->copy_len + mblen <=
		    bgep->chipid.snd_buff_size);
		bcopy(bp->b_rptr, pbuf, mblen);
		pbuf += mblen;
		txbuf->copy_len += mblen;
	}
}

/*
 * Fill the Tx buffer descriptors and trigger the h/w transmission
 */
static void
bge_send_serial(bge_t *bgep, send_ring_t *srp)
{
	send_pkt_t *pktp;
	uint64_t txfill_next;
	uint32_t count;
	uint32_t tx_next;
	sw_sbd_t *ssbdp;
	bge_status_t *bsp;
	bge_sbd_t *hw_sbd_p;
	bge_queue_item_t *txbuf_item;
	sw_txbuf_t *txbuf;

	/*
	 * Try to hold the tx lock:
	 *	If we are in an interrupt context, use mutex_enter() to
	 *	ensure quick response for tx in interrupt context;
	 *	Otherwise, use mutex_tryenter() to serialize this h/w tx
	 *	BD filling and transmission triggering task.
	 */
	if (servicing_interrupt() != 0)
		mutex_enter(srp->tx_lock);
	else if (mutex_tryenter(srp->tx_lock) == 0)
		return;		/* already in process	*/

	bsp = DMA_VPTR(bgep->status_block);
	txfill_next = srp->txfill_next;
	tx_next = srp->tx_next;
start_tx:
	for (count = 0; count < bgep->param_drain_max; ++count) {
		pktp = &srp->pktp[txfill_next];
		if (!pktp->tx_ready) {
			if (count == 0)
				srp->tx_block++;
			break;
		}

		/*
		 * If there are no enough BDs: try to recycle more
		 */
		if (srp->tx_free <= 1)
			(void) bge_recycle(bgep, bsp);

		/*
		 * Reserved required BDs: 1 is enough
		 */
		if (!bge_atomic_reserve(&srp->tx_free, 1)) {
			srp->tx_nobd++;
			break;
		}

		/*
		 * Filling the tx BD
		 */

		/*
		 * Go straight to claiming our already-reserved places
		 * on the train!
		 */
		ASSERT(pktp->txbuf_item != NULL);
		txbuf_item = pktp->txbuf_item;
		pktp->txbuf_item = NULL;
		pktp->tx_ready = B_FALSE;

		txbuf = txbuf_item->item;
		ASSERT(txbuf->copy_len != 0);
		(void) ddi_dma_sync(txbuf->buf.dma_hdl,  0,
		    txbuf->copy_len, DDI_DMA_SYNC_FORDEV);

		ssbdp = &srp->sw_sbds[tx_next];
		ASSERT(ssbdp->pbuf == NULL);
		ssbdp->pbuf = txbuf_item;

		/*
		 * Setting hardware send buffer descriptor
		 */
		hw_sbd_p = DMA_VPTR(ssbdp->desc);
		hw_sbd_p->flags = 0;
		hw_sbd_p->host_buf_addr = txbuf->buf.cookie.dmac_laddress;
		hw_sbd_p->len = txbuf->copy_len;
		if (pktp->vlan_tci != 0) {
			hw_sbd_p->vlan_tci = pktp->vlan_tci;
			hw_sbd_p->host_buf_addr += VLAN_TAGSZ;
			hw_sbd_p->flags |= SBD_FLAG_VLAN_TAG;
		}
		if (pktp->pflags & HCK_IPV4_HDRCKSUM)
			hw_sbd_p->flags |= SBD_FLAG_IP_CKSUM;
		if (pktp->pflags & HCK_FULLCKSUM)
			hw_sbd_p->flags |= SBD_FLAG_TCP_UDP_CKSUM;
		if (!(bgep->chipid.flags & CHIP_FLAG_NO_JUMBO) &&
		    (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
		     DEVICE_5725_SERIES_CHIPSETS(bgep)) &&
		    (txbuf->copy_len > ETHERMAX))
			hw_sbd_p->flags |= SBD_FLAG_JMB_PKT;
		hw_sbd_p->flags |= SBD_FLAG_PACKET_END;

		txfill_next = NEXT(txfill_next, BGE_SEND_BUF_MAX);
		tx_next = NEXT(tx_next, srp->desc.nslots);
	}

	/*
	 * Trigger h/w to start transmission.
	 */
	if (count != 0) {
		bge_atomic_sub64(&srp->tx_flow, count);
		srp->txfill_next = txfill_next;

		if (srp->tx_next > tx_next) {
			(void) ddi_dma_sync(ssbdp->desc.dma_hdl,  0,
			    (srp->desc.nslots - srp->tx_next) *
			    sizeof (bge_sbd_t),
			    DDI_DMA_SYNC_FORDEV);
			count -= srp->desc.nslots - srp->tx_next;
			ssbdp = &srp->sw_sbds[0];
		}
		(void) ddi_dma_sync(ssbdp->desc.dma_hdl,  0,
		    count*sizeof (bge_sbd_t), DDI_DMA_SYNC_FORDEV);
		bge_mbx_put(bgep, srp->chip_mbx_reg, tx_next);
		srp->tx_next = tx_next;
		atomic_or_32(&bgep->watchdog, 1);

		if (srp->tx_flow != 0 && srp->tx_free > 1)
			goto start_tx;
	}

	mutex_exit(srp->tx_lock);
}

mblk_t *
bge_ring_tx(void *arg, mblk_t *mp)
{
	send_ring_t *srp = arg;
	bge_t *bgep = srp->bgep;
	struct ether_vlan_header *ehp;
	bge_queue_item_t *txbuf_item;
	sw_txbuf_t *txbuf;
	send_pkt_t *pktp;
	uint64_t pkt_slot;
	uint16_t vlan_tci;
	uint32_t pflags;
	char *pbuf;

	ASSERT(mp->b_next == NULL);

	/*
	 * Get a s/w tx buffer first
	 */
	txbuf_item = bge_get_txbuf(bgep, srp);
	if (txbuf_item == NULL) {
		/* no tx buffer available */
		srp->tx_nobuf++;
		bgep->tx_resched_needed = B_TRUE;
		bge_send_serial(bgep, srp);
		return (mp);
	}

	/*
	 * Copy all mp fragments to the pkt buffer
	 */
	txbuf = txbuf_item->item;
	bge_send_copy(bgep, txbuf, mp);

	/*
	 * Determine if the packet is VLAN tagged.
	 */
	ASSERT(txbuf->copy_len >= sizeof (struct ether_header));
	pbuf = DMA_VPTR(txbuf->buf);

	ehp = (void *)pbuf;
	if (ehp->ether_tpid == htons(ETHERTYPE_VLAN)) {
		/* Strip the vlan tag */
		vlan_tci = ntohs(ehp->ether_tci);
		pbuf = memmove(pbuf + VLAN_TAGSZ, pbuf, 2 * ETHERADDRL);
		txbuf->copy_len -= VLAN_TAGSZ;
	} else
		vlan_tci = 0;

	/*
	 * Retrieve checksum offloading info.
	 */
	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &pflags);

	/*
	 * Calculate pseudo checksum if needed.
	 */
	if ((pflags & HCK_FULLCKSUM) &&
	    (bgep->chipid.flags & CHIP_FLAG_PARTIAL_CSUM))
		bge_pseudo_cksum((uint8_t *)pbuf);

	/*
	 * Packet buffer is ready to send: get and fill pkt info
	 */
	pkt_slot = bge_atomic_next(&srp->txpkt_next, BGE_SEND_BUF_MAX);
	pktp = &srp->pktp[pkt_slot];
	ASSERT(pktp->txbuf_item == NULL);
	pktp->txbuf_item = txbuf_item;
	pktp->vlan_tci = vlan_tci;
	pktp->pflags = pflags;
	atomic_inc_64(&srp->tx_flow);
	ASSERT(pktp->tx_ready == B_FALSE);
	pktp->tx_ready = B_TRUE;

	/*
	 * Filling the h/w bd and trigger the h/w to start transmission
	 */
	bge_send_serial(bgep, srp);

	srp->pushed_bytes += MBLKL(mp);

	/*
	 * We've copied the contents, the message can be freed right away
	 */
	freemsg(mp);
	return (NULL);
}

static mblk_t *
bge_send(bge_t *bgep, mblk_t *mp)
{
	send_ring_t *ring;

	ring = &bgep->send[0];	/* ring 0 */

	return (bge_ring_tx(ring, mp));
}

uint_t
bge_send_drain(caddr_t arg)
{
	uint_t ring = 0;	/* use ring 0 */
	bge_t *bgep;
	send_ring_t *srp;

	bgep = (void *)arg;
	BGE_TRACE(("bge_send_drain($%p)", (void *)bgep));

	srp = &bgep->send[ring];
	bge_send_serial(bgep, srp);

	if (bgep->tx_resched_needed &&
	    (srp->tx_flow < srp->tx_buffers_low) &&
	    (bgep->bge_mac_state == BGE_MAC_STARTED)) {
		mac_tx_update(bgep->mh);
		bgep->tx_resched_needed = B_FALSE;
		bgep->tx_resched++;
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * bge_m_tx() - send a chain of packets
 */
mblk_t *
bge_m_tx(void *arg, mblk_t *mp)
{
	bge_t *bgep = arg;		/* private device info	*/
	mblk_t *next;

	BGE_TRACE(("bge_m_tx($%p, $%p)", arg, (void *)mp));

	ASSERT(mp != NULL);
	ASSERT(bgep->bge_mac_state == BGE_MAC_STARTED);

	rw_enter(bgep->errlock, RW_READER);
	if ((bgep->bge_chip_state != BGE_CHIP_RUNNING) ||
	    !(bgep->param_link_up)) {
		BGE_DEBUG(("bge_m_tx: chip not running or link down"));
		freemsgchain(mp);
		mp = NULL;
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if ((mp = bge_send(bgep, mp)) != NULL) {
			mp->b_next = next;
			break;
		}

		mp = next;
	}
	rw_exit(bgep->errlock);

	return (mp);
}
