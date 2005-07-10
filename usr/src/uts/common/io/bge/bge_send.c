/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sys/bge_impl.h"


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
static void bge_recycle_ring(bge_t *bgep, send_ring_t *srp);
#pragma	inline(bge_recycle_ring)

static void
bge_recycle_ring(bge_t *bgep, send_ring_t *srp)
{
	uint64_t slot;
	uint64_t n;

	_NOTE(ARGUNUSED(bgep))

	ASSERT(mutex_owned(srp->tc_lock));

	slot = *srp->cons_index_p;			/* volatile	*/
	n = slot - srp->tc_next;
	if (slot < srp->tc_next)
		n += srp->desc.nslots;

	/*
	 * We're about to release one or more places :-)
	 * These ASSERTions check that our invariants still hold:
	 *	there must always be at least one free place
	 *	at this point, there must be at least one place NOT free
	 *	we're not about to free more places than were claimed!
	 */
	ASSERT(srp->tx_free > 0);
	ASSERT(srp->tx_free < srp->desc.nslots);
	ASSERT(srp->tx_free + n <= srp->desc.nslots);

	srp->tc_next = slot;
	bge_atomic_renounce(&srp->tx_free, n);

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
	bgep->watchdog = srp->tx_free == srp->desc.nslots ? 0 : 1;
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
void bge_recycle(bge_t *bgep, bge_status_t *bsp);
#pragma	no_inline(bge_recycle)

void
bge_recycle(bge_t *bgep, bge_status_t *bsp)
{
	send_ring_t *srp;
	uint64_t ring;
	uint64_t tx_rings = bgep->chipid.tx_rings;

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
		bge_recycle_ring(bgep, srp);
		mutex_exit(srp->tc_lock);

		if (bgep->resched_needed)
			ddi_trigger_softintr(bgep->resched_id);

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
}


/*
 * ========== Send-side transmit routines ==========
 */

/*
 * CLAIM an already-reserved place on the next train
 *
 * This is the point of no return!
 */
static uint64_t bge_send_claim(bge_t *bgep, send_ring_t *srp);
#pragma	inline(bge_send_claim)

static uint64_t
bge_send_claim(bge_t *bgep, send_ring_t *srp)
{
	uint64_t slot;

	rw_enter(srp->tx_lock, RW_READER);
	atomic_add_64(&srp->tx_flow, 1);
	slot = bge_atomic_claim(&srp->tx_next, srp->desc.nslots);
	rw_exit(srp->tx_lock);

	/*
	 * Bump the watchdog counter, thus guaranteeing that it's
	 * nonzero (watchdog activated).  Note that non-synchonised
	 * access here means we may race with the reclaim() code
	 * above, but the outcome will be harmless.  At worst, the
	 * counter may not get reset on a partial reclaim; but the
	 * large trigger threshold makes false positives unlikely
	 */
	bgep->watchdog += 1;

	return (slot);
}

/*
 * Send a message by copying it into a preallocated (and premapped) buffer
 */
static enum send_status bge_send_copy(bge_t *bgep, mblk_t *mp,
	send_ring_t *srp, uint16_t tci);
#pragma	inline(bge_send_copy)

static enum send_status
bge_send_copy(bge_t *bgep, mblk_t *mp, send_ring_t *srp, uint16_t tci)
{
	bge_sbd_t *hw_sbd_p;
	sw_sbd_t *ssbdp;
	mblk_t *bp;
	char *txb;
	uint64_t slot;
	size_t totlen;
	size_t mblen;
	uint32_t pflags;

	BGE_TRACE(("bge_send_copy($%p, $%p, $%p, 0x%x)",
		(void *)bgep, (void *)mp, (void *)srp));

	/*
	 * IMPORTANT:
	 *	Up to the point where it claims a place, a send_msg()
	 *	routine can indicate failure by returning SEND_FAIL.
	 *	Once it's claimed a place, it mustn't fail.
	 *
	 * In this version, there's no setup to be done here, and there's
	 * nothing that can fail, so we can go straight to claiming our
	 * already-reserved place on the train.
	 *
	 * This is the point of no return!
	 */
	slot = bge_send_claim(bgep, srp);
	ssbdp = &srp->sw_sbds[slot];

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
		if ((totlen += mblen) <= bgep->chipid.ethmax_size) {
			bcopy(bp->b_rptr, txb, mblen);
			txb += mblen;
		}
	}

	/*
	 * We'e reached the end of the chain; and we should have
	 * collected no more than ETHERMAX bytes into our buffer.
	 */
	ASSERT(bp == NULL);
	ASSERT(totlen <= bgep->chipid.ethmax_size);
	DMA_SYNC(ssbdp->pbuf, DDI_DMA_SYNC_FORDEV);

	/*
	 * Update the hardware send buffer descriptor; then we're done.
	 * The return status indicates that the message can be freed
	 * right away, as we've already copied the contents ...
	 */
	hw_sbd_p = DMA_VPTR(ssbdp->desc);
	hw_sbd_p->host_buf_addr = ssbdp->pbuf.cookie.dmac_laddress;
	hw_sbd_p->len = totlen;
	hw_sbd_p->flags = SBD_FLAG_PACKET_END;
	if (tci != 0) {
		hw_sbd_p->vlan_tci = tci;
		hw_sbd_p->flags |= SBD_FLAG_VLAN_TAG;
	}

	hcksum_retrieve(mp, NULL, NULL, NULL, NULL, NULL, NULL, &pflags);
	if (pflags & HCK_IPV4_HDRCKSUM)
		hw_sbd_p->flags |= SBD_FLAG_IP_CKSUM;
	if (pflags & HCK_FULLCKSUM)
		hw_sbd_p->flags |= SBD_FLAG_TCP_UDP_CKSUM;

	return (SEND_FREE);
}

static boolean_t
bge_send(bge_t *bgep, mblk_t *mp)
{
	send_ring_t *srp;
	enum send_status status;
	struct ether_vlan_header *ehp;
	boolean_t need_strip = B_FALSE;
	uint16_t tci;
	uint_t ring = 0;

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
				BGE_DEBUG(("bge_send: pullup failure"));
				bgep->resched_needed = B_TRUE;
				return (B_FALSE);
			}

			(void) hcksum_assoc(mp, NULL, NULL, NULL, NULL, NULL,
			    NULL, pflags, KM_NOSLEEP);
		}

		ehp = (struct ether_vlan_header *)mp->b_rptr;
		need_strip = B_TRUE;
	}

	/*
	 * Try to reserve a place in the chosen ring. Shouldn't try next
	 * higher-numbered (lower-priority) ring, if there aren't any
	 * available. Otherwise, packets with same priority may get
	 * transmission starvation.
	 */
	srp = &bgep->send[ring];
	if (!bge_atomic_reserve(&srp->tx_free, 1)) {
		BGE_DEBUG(("bge_send: no free slots"));
		bgep->resched_needed = B_TRUE;
		return (B_FALSE);
	}

	/*
	 * Now that we know that there is space to transmit the packet
	 * strip any VLAN tag that is present.
	 */
	if (need_strip) {
		tci = ntohs(ehp->ether_tci);

		(void) memmove(mp->b_rptr + VLAN_TAGSZ, mp->b_rptr,
		    2 * ETHERADDRL);
		mp->b_rptr += VLAN_TAGSZ;
	} else {
		tci = 0;
	}

	/*
	 * We've reserved a place :-)
	 * These ASSERTions check that our invariants still hold:
	 *	there must still be at least one free place
	 *	there must be at least one place NOT free (ours!)
	 */
	ASSERT(srp->tx_free > 0);
	ASSERT(srp->tx_free < srp->desc.nslots);

	if ((status = bge_send_copy(bgep, mp, srp, tci)) == SEND_FAIL) {
		/*
		 * The send routine failed :(  So we have to renounce
		 * our reservation before returning the error.
		 */
		bge_atomic_renounce(&srp->tx_free, 1);
		bgep->resched_needed = B_TRUE;
		return (B_FALSE);
	}

	/*
	 * The send routine succeeded; it will have updated the
	 * h/w ring descriptor, and the <tx_next> and <tx_flow>
	 * counters.
	 *
	 * Because there can be multiple concurrent threads in
	 * transit through this code, we only want to prod the
	 * hardware once the last one is departing ...
	 */
	rw_enter(srp->tx_lock, RW_WRITER);
	if (--srp->tx_flow == 0) {
		DMA_SYNC(srp->desc, DDI_DMA_SYNC_FORDEV);
		bge_mbx_put(bgep, srp->chip_mbx_reg, srp->tx_next);
	}
	rw_exit(srp->tx_lock);

	if (status == SEND_FREE)
		freemsg(mp);
	return (B_TRUE);
}

uint_t
bge_reschedule(caddr_t arg)
{
	bge_t *bgep;
	uint_t rslt;

	bgep = (bge_t *)arg;
	rslt = DDI_INTR_UNCLAIMED;

	BGE_TRACE(("bge_reschedule($%p)", (void *)bgep));

	if (bgep->bge_mac_state == BGE_MAC_STARTED && bgep->resched_needed) {
		mac_tx_update(bgep->macp);
		bgep->resched_needed = B_FALSE;
		rslt = DDI_INTR_CLAIMED;
	}

	return (rslt);
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

	if (bgep->bge_chip_state != BGE_CHIP_RUNNING) {
		BGE_DEBUG(("bge_m_tx: chip not running"));
		return (mp);
	}

	rw_enter(bgep->errlock, RW_READER);
	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (!bge_send(bgep, mp)) {
			mp->b_next = next;
			break;
		}

		mp = next;
	}
	rw_exit(bgep->errlock);

	return (mp);
}
