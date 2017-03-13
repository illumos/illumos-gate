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
 * Event Ring Management
 *
 * All activity in xHCI is reported to an event ring, which corresponds directly
 * with an interrupt. Whether a command is issued or an I/O is issued to a given
 * device endpoint, it will end up being acknowledged, positively or negatively,
 * on an event ring.
 *
 * Unlike other rings, the OS is a consumer of the event rings, not a producer.
 * For more information on how the ring is used, see xhci_ring.c. For more
 * information generally, see xhci.c.
 *
 * All of the rings are described in the ERST -- Event Ring Segment Table. As we
 * only have a single interrupt and a single event ring, we only write a single
 * entry here.
 */

#include <sys/usb/hcd/xhci/xhci.h>


void
xhci_event_fini(xhci_t *xhcip)
{
	xhci_event_ring_t *xev = &xhcip->xhci_event;
	xhci_ring_free(&xev->xev_ring);
	if (xev->xev_segs != NULL)
		xhci_dma_free(&xev->xev_dma);
	xev->xev_segs = NULL;
}

/*
 * Make sure that if we leave here we either have both the ring and table
 * addresses initialized or neither.
 */
static int
xhci_event_alloc(xhci_t *xhcip, xhci_event_ring_t *xev)
{
	int ret;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;

	/*
	 * This is allocating the segment table. It doesn't have any particular
	 * requirements. Though it could be larger, we can get away with our
	 * default data structure attributes unless we add a lot more entries.
	 */
	xhci_dma_acc_attr(xhcip, &acc);
	xhci_dma_dma_attr(xhcip, &attr);
	if (!xhci_dma_alloc(xhcip, &xev->xev_dma, &attr, &acc, B_FALSE,
	    sizeof (xhci_event_segment_t) * XHCI_EVENT_NSEGS, B_FALSE))
		return (ENOMEM);
	if ((ret = xhci_ring_alloc(xhcip, &xev->xev_ring)) != 0) {
		xhci_dma_free(&xev->xev_dma);
		return (ret);
	}

	xev->xev_segs = (void *)xev->xev_dma.xdb_va;
	return (0);
}

int
xhci_event_init(xhci_t *xhcip)
{
	int ret;
	uint32_t reg;
	xhci_event_ring_t *xev = &xhcip->xhci_event;

	if (xev->xev_segs == NULL) {
		if ((ret = xhci_event_alloc(xhcip, xev)) != 0)
			return (ret);
	}

	if ((ret = xhci_ring_reset(xhcip, &xev->xev_ring)) != 0) {
		xhci_event_fini(xhcip);
		return (ret);
	}

	bzero(xev->xev_segs, sizeof (xhci_event_segment_t) * XHCI_EVENT_NSEGS);
	xev->xev_segs[0].xes_addr = LE_64(xhci_dma_pa(&xev->xev_ring.xr_dma));
	xev->xev_segs[0].xes_size = LE_16(xev->xev_ring.xr_ntrb);

	reg = xhci_get32(xhcip, XHCI_R_RUN, XHCI_ERSTSZ(0));
	reg &= ~XHCI_ERSTS_MASK;
	reg |= XHCI_ERSTS_SET(XHCI_EVENT_NSEGS);
	xhci_put32(xhcip, XHCI_R_RUN, XHCI_ERSTSZ(0), reg);

	xhci_put64(xhcip, XHCI_R_RUN, XHCI_ERDP(0),
	    xhci_dma_pa(&xev->xev_ring.xr_dma));
	xhci_put64(xhcip, XHCI_R_RUN, XHCI_ERSTBA(0),
	    xhci_dma_pa(&xev->xev_dma));
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_event_fini(xhcip);
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	return (0);
}

static boolean_t
xhci_event_process_psc(xhci_t *xhcip, xhci_trb_t *trb)
{
	uint32_t port;

	if (XHCI_TRB_GET_CODE(LE_32(trb->trb_status)) != XHCI_CODE_SUCCESS) {
		return (B_TRUE);
	}

	port = XHCI_TRB_PORTID(LE_64(trb->trb_addr));
	if (port < 1 || port > xhcip->xhci_caps.xcap_max_ports) {
		/*
		 * At some point we may want to send a DDI_FM_DEVICE_INVAL_STATE
		 * ereport as part of this.
		 */
		return (B_FALSE);
	}

	xhci_root_hub_psc_callback(xhcip);
	return (B_TRUE);
}

/*
 * Process the event ring, note we're in interrupt context while doing this.
 */
boolean_t
xhci_event_process(xhci_t *xhcip)
{
	int nevents;
	uint64_t addr;
	xhci_ring_t *xrp = &xhcip->xhci_event.xev_ring;

	/*
	 * While it may be possible for us to transition to an error state at
	 * any time because we are reasonably not holding the xhci_t's lock
	 * during the entire interrupt (as it doesn't protect any of the event
	 * ring's data), we still do an initial test to ensure that we don't go
	 * too far down the path.
	 */
	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (B_FALSE);
	}
	mutex_exit(&xhcip->xhci_lock);

	/*
	 * We've seen a few cases, particularly when dealing with controllers
	 * where BIOS takeover is involved, that an interrupt gets injected into
	 * the system before we've actually finished setting things up. If for
	 * some reason that happens, and we don't actually have a ring yet,
	 * don't try and do anything.
	 */
	if (xhcip->xhci_event.xev_segs == NULL)
		return (B_TRUE);

	XHCI_DMA_SYNC(xrp->xr_dma, DDI_DMA_SYNC_FORKERNEL);
	if (xhci_check_dma_handle(xhcip, &xrp->xr_dma) != DDI_FM_OK) {
		xhci_error(xhcip, "encountered fatal FM error trying to "
		    "synchronize event ring: resetting device");
		xhci_fm_runtime_reset(xhcip);
		return (B_FALSE);
	}

	/*
	 * Process at most a full ring worth of events.
	 */
	for (nevents = 0; nevents < xrp->xr_ntrb; nevents++) {
		xhci_trb_t *trb;
		uint32_t type;

		if ((trb = xhci_ring_event_advance(xrp)) == NULL)
			break;

		type = LE_32(trb->trb_flags) & XHCI_TRB_TYPE_MASK;
		switch (type) {
		case XHCI_EVT_PORT_CHANGE:
			if (!xhci_event_process_psc(xhcip, trb))
				return (B_FALSE);
			break;
		case XHCI_EVT_CMD_COMPLETE:
			if (!xhci_command_event_callback(xhcip, trb))
				return (B_FALSE);
			break;
		case XHCI_EVT_DOORBELL:
			/*
			 * Because we don't have any VF hardware, this event
			 * should never happen. If it does, that probably means
			 * something bad has happened and we should reset the
			 * device.
			 */
			xhci_error(xhcip, "received xHCI VF interrupt even "
			    "though virtual functions are not supported, "
			    "resetting device");
			xhci_fm_runtime_reset(xhcip);
			return (B_FALSE);
		case XHCI_EVT_XFER:
			if (!xhci_endpoint_transfer_callback(xhcip, trb))
				return (B_FALSE);
			break;
		/*
		 * Ignore other events that come in.
		 */
		default:
			break;
		}
	}

	addr = xhci_dma_pa(&xrp->xr_dma) + sizeof (xhci_trb_t) * xrp->xr_tail;
	addr |= XHCI_ERDP_BUSY;
	xhci_put64(xhcip, XHCI_R_RUN, XHCI_ERDP(0), addr);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to write to event ring dequeue "
		    "pointer: encountered fatal FM error, resetting device");
		xhci_fm_runtime_reset(xhcip);
		return (B_FALSE);
	}

	return (B_TRUE);
}
