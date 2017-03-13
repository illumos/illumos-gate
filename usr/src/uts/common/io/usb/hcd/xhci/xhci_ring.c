/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

/*
 * -----------------------------
 * xHCI Ring Management Routines
 * -----------------------------
 *
 * There are three major different types of rings for xHCI, these are:
 *
 * 1) Command Rings
 * 2) Event Rings
 * 3) Transfer Rings
 *
 * Command and Transfer rings function in similar ways while the event rings are
 * different. The difference comes in who is the consumer and who is the
 * producer. In the case of command and transfer rings, the driver is the
 * producer. For the event ring the driver is the consumer.
 *
 * Each ring in xhci has a synthetic head and tail register. Each entry in a
 * ring has a bit that's often referred to as the 'Cycle bit'. The cycle bit is
 * toggled as a means of saying that a given entry needs to be consumed.
 *
 * When a ring is created, all of the data in it is initialized to zero and the
 * producer and consumer agree that when the cycle bit is toggled, the ownership
 * of the entry is transfered from the producer to the consumer.  For example,
 * the command ring defaults to saying that a cycle bit of one is what indicates
 * the command is owned by the hardware. So as the driver (the producer) fills
 * in entries, the driver toggles the cycle bit from 0->1 as part of writing out
 * the TRB.  When the command ring's doorbell is rung, the hardware (the
 * consumer) begins processing commands. It will process them until one of two
 * things happens:
 *
 * 1) The hardware encounters an entry with the old cycle bit (0 in this case)
 *
 * 2) The hardware hits the last entry in the ring which is a special kind of
 * entry called a LINK TRB.
 *
 * A LINK TRB has two purposes:
 *
 * 1) Indicate where processing should be redirected. This can potentially be to
 * another memory segment; however, this driver always programs LINK TRBs to
 * point back to the start of the ring.
 *
 * 2) Indicate whether or not the cycle bit should be changed. We always
 * indicate that the cycle bit should be toggled when a LINK TRB is processed.
 *
 * In this same example, whereas the driver (the producer) would be setting the
 * cycle to 1 to indicate that an entry is to be processed, the driver would now
 * set it to 0. Similarly, the hardware (the consumer) would be looking for a
 * 0 to determine whether or not it should process the entry.
 *
 * Currently, when the driver allocates rings, it always allocates a single page
 * for the ring. The entire page is dedicated to ring use, which is determined
 * based on the devices PAGESIZE register. The last entry in a given page is
 * always configured as a LINK TRB. As each entry in a ring is 16 bytes, this
 * gives us an average of 255 usable descriptors on x86 and 511 on SPARC, as
 * PAGESIZE is 4k and 8k respectively.
 *
 * The driver is always the producer for all rings except for the event ring,
 * where it is the consumer.
 *
 * ----------------------
 * Head and Tail Pointers
 * ----------------------
 *
 * Now, while we have the cycle bits for the ring explained, we still need to
 * keep track of what we consider the head and tail pointers, what the xHCI
 * specification calls enqueue (head) and dequeue (tail) pointers. Now, in all
 * the cases here, the actual tracking of the head pointer is basically done by
 * the cycle bit; however, we maintain an actual offset in the xhci_ring_t
 * structure. The tail is usually less synthetic; however, it's up for different
 * folks to maintain it.
 *
 * We handle the command and transfer rings the same way. The head pointer
 * indicates where we should insert the next TRB to transfer. The tail pointer
 * indicates the last thing that hardware has told us it has processed. If the
 * head and tail point to the same index, then we know the ring is empty.
 *
 * We increment the head pointer whenever we insert an entry. Note that we do
 * not tell hardware about this in any way, it's just maintained by the cycle
 * bit. Then, we keep track of what hardware has processed in our tail pointer,
 * incrementing it only when we have an interrupt that indicates that it's been
 * processed.
 *
 * One oddity here is that we only get notified of this via the event ring. So
 * when the event ring encounters this information, it needs to go back and
 * increment our command and transfer ring tails after processing events.
 *
 * For the event ring, we handle things differently. We still initialize
 * everything to zero; however, we start processing things and looking at cycle
 * bits only when we get an interrupt from hardware. With the event ring, we do
 * *not* maintain a head pointer (it's still in the structure, but unused).  We
 * always start processing at the tail pointer and use the cycle bit to indicate
 * what we should process. Once we're done incrementing things, we go and notify
 * the hardware of how far we got with this process by updating the tail for the
 * event ring via a memory mapped register.
 */

#include <sys/usb/hcd/xhci/xhci.h>

void
xhci_ring_free(xhci_ring_t *xrp)
{
	if (xrp->xr_trb != NULL) {
		xhci_dma_free(&xrp->xr_dma);
		xrp->xr_trb = NULL;
	}
	xrp->xr_ntrb = 0;
	xrp->xr_head = 0;
	xrp->xr_tail = 0;
	xrp->xr_cycle = 0;
}

/*
 * Initialize a ring that hasn't been used and set up its link pointer back to
 * it.
 */
int
xhci_ring_reset(xhci_t *xhcip, xhci_ring_t *xrp)
{
	xhci_trb_t *ltrb;

	ASSERT(xrp->xr_trb != NULL);

	bzero(xrp->xr_trb, sizeof (xhci_trb_t) * xrp->xr_ntrb);
	xrp->xr_head = 0;
	xrp->xr_tail = 0;
	xrp->xr_cycle = 1;

	/*
	 * Set up the link TRB back to ourselves.
	 */
	ltrb = &xrp->xr_trb[xrp->xr_ntrb - 1];
	ltrb->trb_addr = LE_64(xhci_dma_pa(&xrp->xr_dma));
	ltrb->trb_flags = LE_32(XHCI_TRB_TYPE_LINK | XHCI_TRB_LINKSEG);

	XHCI_DMA_SYNC(xrp->xr_dma, DDI_DMA_SYNC_FORDEV);
	if (xhci_check_dma_handle(xhcip, &xrp->xr_dma) != DDI_FM_OK) {
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	return (0);
}

int
xhci_ring_alloc(xhci_t *xhcip, xhci_ring_t *xrp)
{
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;

	/*
	 * We use a transfer attribute for the rings as they require 64-byte
	 * boundaries.
	 */
	xhci_dma_acc_attr(xhcip, &acc);
	xhci_dma_transfer_attr(xhcip, &attr, XHCI_DEF_DMA_SGL);
	bzero(xrp, sizeof (xhci_ring_t));
	if (xhci_dma_alloc(xhcip, &xrp->xr_dma, &attr, &acc, B_FALSE,
	    xhcip->xhci_caps.xcap_pagesize, B_FALSE) == B_FALSE)
		return (ENOMEM);
	xrp->xr_trb = (xhci_trb_t *)xrp->xr_dma.xdb_va;
	xrp->xr_ntrb = xhcip->xhci_caps.xcap_pagesize / sizeof (xhci_trb_t);
	return (0);
}

/*
 * Note, caller should have already synced our DMA memory. This should not be
 * used for the command ring, as its cycle is maintained by the cycling of the
 * head. This function is only used for managing the event ring.
 */
xhci_trb_t *
xhci_ring_event_advance(xhci_ring_t *xrp)
{
	xhci_trb_t *trb = &xrp->xr_trb[xrp->xr_tail];
	VERIFY(xrp->xr_tail < xrp->xr_ntrb);

	if (xrp->xr_cycle != (LE_32(trb->trb_flags) & XHCI_TRB_CYCLE))
		return (NULL);

	/*
	 * The event ring does not use a link TRB. It instead always uses
	 * information based on the table to wrap. That means that the last
	 * entry is in fact going to contain data, so we shouldn't wrap and
	 * toggle the cycle until after we've processed that, in other words the
	 * tail equals the total number of entries.
	 */
	xrp->xr_tail++;
	if (xrp->xr_tail == xrp->xr_ntrb) {
		xrp->xr_cycle ^= 1;
		xrp->xr_tail = 0;
	}

	return (trb);
}

/*
 * When processing the command ring, we're going to get a single event for each
 * entry in it. As we've submitted things in order, we need to make sure that
 * this address matches the DMA address that we'd expect of the current tail.
 */
boolean_t
xhci_ring_trb_tail_valid(xhci_ring_t *xrp, uint64_t dma)
{
	uint64_t tail;

	tail = xhci_dma_pa(&xrp->xr_dma) + xrp->xr_tail * sizeof (xhci_trb_t);
	return (dma == tail);
}

/*
 * A variant on the above that checks for a given message within a range of
 * entries and returns the offset to it from the tail.
 */
int
xhci_ring_trb_valid_range(xhci_ring_t *xrp, uint64_t dma, uint_t range)
{
	uint_t i;
	uint_t tail = xrp->xr_tail;
	uint64_t taddr;

	VERIFY(range < xrp->xr_ntrb);
	for (i = 0; i < range; i++) {
		taddr = xhci_dma_pa(&xrp->xr_dma) + tail * sizeof (xhci_trb_t);
		if (taddr == dma)
			return (i);

		tail++;
		if (tail == xrp->xr_ntrb - 1)
			tail = 0;
	}

	return (-1);
}

/*
 * Determine whether or not we have enough space for this request in a given
 * ring for the given request. Note, we have to be a bit careful here and ensure
 * that we properly handle cases where we cross the link TRB and that we don't
 * count it.
 *
 * To determine if we have enough space for a given number of trbs, we need to
 * logically advance the head pointer and make sure that we don't cross the tail
 * pointer. In other words, if after advancement, head == tail, we're in
 * trouble and don't have enough space.
 */
boolean_t
xhci_ring_trb_space(xhci_ring_t *xrp, uint_t ntrb)
{
	uint_t i;
	uint_t head = xrp->xr_head;

	VERIFY(ntrb > 0);
	/* We use < to ignore the link TRB */
	VERIFY(ntrb < xrp->xr_ntrb);

	for (i = 0; i < ntrb; i++) {
		head++;
		if (head == xrp->xr_ntrb - 1) {
			head = 0;
		}

		if (head == xrp->xr_tail)
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Fill in a TRB in the ring at offset trboff. If cycle is currently set to
 * B_TRUE, then we fill in the appropriate cycle bit to tell the system to
 * advance, otherwise we leave the existing cycle bit untouched so the system
 * doesn't accidentally advance until we have everything filled in.
 */
void
xhci_ring_trb_fill(xhci_ring_t *xrp, uint_t trboff, xhci_trb_t *host_trb,
    boolean_t put_cycle)
{
	uint_t i;
	uint32_t flags;
	uint_t ent = xrp->xr_head;
	uint8_t cycle = xrp->xr_cycle;
	xhci_trb_t *trb;

	for (i = 0; i < trboff; i++) {
		ent++;
		if (ent == xrp->xr_ntrb - 1) {
			ent = 0;
			cycle ^= 1;
		}
	}

	/*
	 * If we're being asked to not update the cycle for it to be valid to be
	 * produced, we need to xor this once again to get to the inappropriate
	 * value.
	 */
	if (put_cycle == B_FALSE)
		cycle ^= 1;

	trb = &xrp->xr_trb[ent];

	trb->trb_addr = host_trb->trb_addr;
	trb->trb_status = host_trb->trb_status;
	flags = host_trb->trb_flags;
	if (cycle == 0) {
		flags &= ~LE_32(XHCI_TRB_CYCLE);
	} else {
		flags |= LE_32(XHCI_TRB_CYCLE);
	}

	trb->trb_flags = flags;
}

/*
 * Update our metadata for the ring and verify the cycle bit is correctly set
 * for the first trb. It is expected that it is incorrectly set.
 */
void
xhci_ring_trb_produce(xhci_ring_t *xrp, uint_t ntrb)
{
	uint_t i, ohead;
	xhci_trb_t *trb;

	VERIFY(ntrb > 0);

	ohead = xrp->xr_head;

	/*
	 * As part of updating the head, we need to make sure we correctly
	 * update the cycle bit of the link TRB. So we always do this first
	 * before we update the old head, to try and get a consistent view of
	 * the cycle bit.
	 */
	for (i = 0; i < ntrb; i++) {
		xrp->xr_head++;
		/*
		 * If we're updating the link TRB, we also need to make sure
		 * that the Chain bit is set if we're in the middle of a TD
		 * comprised of multiple TRDs. Thankfully the algorithmn here is
		 * simple: set it to the value of the previous TRB.
		 */
		if (xrp->xr_head == xrp->xr_ntrb - 1) {
			trb = &xrp->xr_trb[xrp->xr_ntrb - 1];
			if (xrp->xr_trb[xrp->xr_ntrb - 2].trb_flags &
			    XHCI_TRB_CHAIN) {
				trb->trb_flags |= XHCI_TRB_CHAIN;
			} else {
				trb->trb_flags &= ~XHCI_TRB_CHAIN;

			}
			trb->trb_flags ^= LE_32(XHCI_TRB_CYCLE);
			xrp->xr_cycle ^= 1;
			xrp->xr_head = 0;
		}
	}

	trb = &xrp->xr_trb[ohead];
	trb->trb_flags ^= LE_32(XHCI_TRB_CYCLE);
}

/*
 * This is a convenience wrapper for the single TRB case to make callers less
 * likely to mess up some of the required semantics.
 */
void
xhci_ring_trb_put(xhci_ring_t *xrp, xhci_trb_t *trb)
{
	xhci_ring_trb_fill(xrp, 0U, trb, B_FALSE);
	xhci_ring_trb_produce(xrp, 1U);
}

/*
 * Update the tail pointer for a ring based on the DMA address of a consumed
 * entry. Note, this entry indicates what we just processed, therefore we should
 * bump the tail entry to the next one.
 */
boolean_t
xhci_ring_trb_consumed(xhci_ring_t *xrp, uint64_t dma)
{
	uint64_t pa = xhci_dma_pa(&xrp->xr_dma);
	uint64_t high = pa + xrp->xr_ntrb * sizeof (xhci_trb_t);

	if (dma < pa || dma >= high ||
	    dma % sizeof (xhci_trb_t) != 0)
		return (B_FALSE);

	dma -= pa;
	dma /= sizeof (xhci_trb_t);

	VERIFY(dma < xrp->xr_ntrb);

	xrp->xr_tail = dma + 1;
	if (xrp->xr_tail == xrp->xr_ntrb - 1)
		xrp->xr_tail = 0;

	return (B_TRUE);
}

/*
 * The ring represented here has been reset and we're being asked to basically
 * skip all outstanding entries. Note, this shouldn't be used for the event
 * ring. Because the cycle bit is toggled whenever the head moves past the link
 * trb, the cycle bit is already correct. So in this case, it's really just a
 * matter of setting the current tail equal to the head, at which point we
 * consider things empty.
 */
void
xhci_ring_skip(xhci_ring_t *xrp)
{
	xrp->xr_tail = xrp->xr_head;
}

/*
 * A variant on the normal skip. This basically just tells us to make sure that
 * that everything this transfer represents has been skipped. Callers need to
 * make sure that this is actually the first transfer in the ring. Like above,
 * we don't need to touch the cycle bit.
 */
void
xhci_ring_skip_transfer(xhci_ring_t *xrp, xhci_transfer_t *xt)
{
	uint_t i;

	for (i = 0; i < xt->xt_ntrbs; i++) {
		xrp->xr_tail++;
		if (xrp->xr_tail == xrp->xr_ntrb - 1)
			xrp->xr_tail = 0;
	}
}
