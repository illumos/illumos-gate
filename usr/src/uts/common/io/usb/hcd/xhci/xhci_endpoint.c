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
 * xHCI Endpoint Initialization and Management
 *
 * Please see the big theory statement in xhci.c for more information.
 */

#include <sys/usb/hcd/xhci/xhci.h>
#include <sys/sdt.h>

boolean_t
xhci_endpoint_is_periodic_in(xhci_endpoint_t *xep)
{
	usba_pipe_handle_data_t *ph;

	ASSERT(xep != NULL);
	ph = xep->xep_pipe;
	ASSERT(ph != NULL);

	return ((xep->xep_type == USB_EP_ATTR_INTR ||
	    xep->xep_type == USB_EP_ATTR_ISOCH) &&
	    (ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN);
}

/*
 * Endpoints are a bit weirdly numbered. Endpoint zero is the default control
 * endpoint, so the direction doesn't matter. For all the others, they're
 * arranged as ep 1 out, ep 1 in, ep 2 out, ep 2 in. This is based on the layout
 * of the Device Context Structure in xHCI 1.1 / 6.2.1. Therefore to go from the
 * endpoint and direction, we know that endpoint n starts at 2n - 1.  e.g.
 * endpoint 1 starts at entry 1, endpoint 2 at entry 3, etc. Finally, the OUT
 * direction comes first, followed by the IN direction. So if we're getting the
 * endpoint for one of those, then we have to deal with that.
 */
uint_t
xhci_endpoint_pipe_to_epid(usba_pipe_handle_data_t *ph)
{
	int ep;

	ep = ph->p_ep.bEndpointAddress & USB_EP_NUM_MASK;
	if (ep == 0)
		return (ep);
	ep = ep * 2 - 1;
	if ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN)
		ep++;

	VERIFY(ep < XHCI_NUM_ENDPOINTS);
	return (ep);
}

/*
 * The assumption is that someone calling this owns this endpoint / device and
 * that it's in a state where it's safe to zero out that information.
 */
void
xhci_endpoint_fini(xhci_device_t *xd, int endpoint)
{
	xhci_endpoint_t *xep = xd->xd_endpoints[endpoint];

	VERIFY(xep != NULL);
	xd->xd_endpoints[endpoint] = NULL;

	xhci_ring_free(&xep->xep_ring);
	cv_destroy(&xep->xep_state_cv);
	list_destroy(&xep->xep_transfers);
	kmem_free(xep, sizeof (xhci_endpoint_t));
}

/*
 * Set up the default control endpoint input context. This needs to be done
 * before we address the device. Note, we separate out the default endpoint from
 * others, as we must set this up before we have a pipe handle.
 */
int
xhci_endpoint_setup_default_context(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep)
{
	uint_t mps;
	xhci_endpoint_context_t *ectx;
	uint64_t deq;

	ectx = xd->xd_endin[xep->xep_num];
	VERIFY(ectx != NULL);

	/*
	 * We may or may not have a device descriptor. This should match the
	 * same initial sizes that are done in hubd_create_child().
	 *
	 * Note, since we don't necessarily have an endpoint descriptor yet to
	 * base this on we instead use the device's defaults if available. This
	 * is different from normal endpoints for which there's always a
	 * specific descriptor.
	 */
	switch (xd->xd_usbdev->usb_port_status) {
	case USBA_LOW_SPEED_DEV:
		if (xd->xd_usbdev->usb_dev_descr != NULL) {
			mps = xd->xd_usbdev->usb_dev_descr->bMaxPacketSize0;
		} else {
			mps = 8;
		}
		break;
	case USBA_FULL_SPEED_DEV:
	case USBA_HIGH_SPEED_DEV:
		if (xd->xd_usbdev->usb_dev_descr != NULL) {
			mps = xd->xd_usbdev->usb_dev_descr->bMaxPacketSize0;
		} else {
			mps = 64;
		}
		break;
	case USBA_SUPER_SPEED_DEV:
	default:
		if (xd->xd_usbdev->usb_dev_descr != NULL) {
			mps = xd->xd_usbdev->usb_dev_descr->bMaxPacketSize0;
			mps = 1 << mps;
		} else {
			mps = 512;
		}
		break;
	}

	bzero(ectx, sizeof (xhci_endpoint_context_t));
	ectx->xec_info = LE_32(0);
	ectx->xec_info2 = LE_32(XHCI_EPCTX_SET_CERR(3) |
	    XHCI_EPCTX_SET_EPTYPE(XHCI_EPCTX_TYPE_CTRL) |
	    XHCI_EPCTX_SET_MAXB(0) | XHCI_EPCTX_SET_MPS(mps));
	deq = xhci_dma_pa(&xep->xep_ring.xr_dma) + sizeof (xhci_trb_t) *
	    xep->xep_ring.xr_tail;
	ectx->xec_dequeue = LE_64(deq | xep->xep_ring.xr_cycle);
	ectx->xec_txinfo = LE_32(XHCI_EPCTX_MAX_ESIT_PAYLOAD(0) |
	    XHCI_EPCTX_AVG_TRB_LEN(XHCI_CONTEXT_DEF_CTRL_ATL));

	XHCI_DMA_SYNC(xd->xd_ictx, DDI_DMA_SYNC_FORDEV);
	if (xhci_check_dma_handle(xhcip, &xd->xd_ictx) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to initialize default device input "
		    "context on slot %d and port %d for endpoint %u:  "
		    "encountered fatal FM error synchronizing input context "
		    "DMA memory", xd->xd_slot, xd->xd_port, xep->xep_num);
		xhci_fm_runtime_reset(xhcip);
		return (EIO);
	}

	return (0);
}

/*
 * Determine if we need to update the maximum packet size of the default
 * control endpoint. This may happen because we start with the default size
 * before we have a descriptor and then it may change. For example, with
 * full-speed devices that may have either an 8 or 64 byte maximum packet size.
 */
int
xhci_endpoint_update_default(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep)
{
	int mps, desc, info, ret;
	ASSERT(xd->xd_usbdev != NULL);

	mps = XHCI_EPCTX_GET_MPS(xd->xd_endout[xep->xep_num]->xec_info2);
	desc = xd->xd_usbdev->usb_dev_descr->bMaxPacketSize0;
	if (xd->xd_usbdev->usb_port_status >= USBA_SUPER_SPEED_DEV) {
		desc = 1 << desc;
	}

	if (mps == desc)
		return (USB_SUCCESS);

	/*
	 * Update only the context for the default control endpoint.
	 */
	mutex_enter(&xd->xd_imtx);
	info = LE_32(xd->xd_endout[xep->xep_num]->xec_info2);
	info &= ~XHCI_EPCTX_SET_MPS(mps);
	info |= XHCI_EPCTX_SET_MPS(desc);
	xd->xd_endin[xep->xep_num]->xec_info2 = LE_32(info);
	xd->xd_input->xic_drop_flags = LE_32(0);
	xd->xd_input->xic_add_flags = LE_32(XHCI_INCTX_MASK_DCI(1));

	ret = xhci_command_evaluate_context(xhcip, xd);
	mutex_exit(&xd->xd_imtx);

	return (ret);
}

static uint_t
xhci_endpoint_epdesc_to_type(usb_ep_descr_t *ep)
{
	int type = ep->bmAttributes & USB_EP_ATTR_MASK;
	boolean_t in = (ep->bEndpointAddress & USB_EP_DIR_MASK) ==
	    USB_EP_DIR_IN;

	switch (type) {
	case USB_EP_ATTR_CONTROL:
		return (XHCI_EPCTX_TYPE_CTRL);
	case USB_EP_ATTR_ISOCH:
		if (in == B_TRUE)
			return (XHCI_EPCTX_TYPE_ISOCH_IN);
		return (XHCI_EPCTX_TYPE_ISOCH_OUT);
	case USB_EP_ATTR_BULK:
		if (in == B_TRUE)
			return (XHCI_EPCTX_TYPE_BULK_IN);
		return (XHCI_EPCTX_TYPE_BULK_OUT);
	case USB_EP_ATTR_INTR:
		if (in == B_TRUE)
			return (XHCI_EPCTX_TYPE_INTR_IN);
		return (XHCI_EPCTX_TYPE_INTR_OUT);
	default:
		panic("bad USB attribute type: %d", type);
	}

	/* LINTED: E_FUNC_NO_RET_VAL */
}

static uint_t
xhci_endpoint_determine_burst(xhci_device_t *xd, xhci_endpoint_t *xep)
{
	switch (xd->xd_usbdev->usb_port_status) {
	case USBA_LOW_SPEED_DEV:
	case USBA_FULL_SPEED_DEV:
		/*
		 * Per xHCI 1.1 / 6.2.3.4, burst is always zero for these
		 * devices.
		 */
		return (0);
	case USBA_HIGH_SPEED_DEV:
		if (xep->xep_type == USB_EP_ATTR_CONTROL ||
		    xep->xep_type == USB_EP_ATTR_BULK)
			return (0);
		return ((xep->xep_pipe->p_xep.uex_ep.wMaxPacketSize &
		    XHCI_CONTEXT_BURST_MASK) >> XHCI_CONTEXT_BURST_SHIFT);
	default:
		/*
		 * For these USB >= 3.0, this comes from the companion
		 * descriptor.
		 */
		ASSERT(xep->xep_pipe->p_xep.uex_flags & USB_EP_XFLAGS_SS_COMP);
		return (xep->xep_pipe->p_xep.uex_ep_ss.bMaxBurst);
	}
}

/*
 * Convert a linear mapping of values that are in in the range of 1-255 into a
 * 2^x value. Because we're supposed to round down for these calculations (see
 * the note in xHCI 1.1 / 6.2.3.6) we can do this simply with a fls() and
 * subtracting one.
 */
static uint_t
xhci_endpoint_linear_interval(usb_ep_descr_t *ep)
{
	int exp;
	int ival = ep->bInterval;
	if (ival < 1)
		ival = 1;
	if (ival > 255)
		ival = 255;
	exp = ddi_fls(ival) - 1;
	ASSERT(exp >= 0 && exp <= 7);
	return (exp);
}

/*
 * Convert the set of values that use a 2^(x-1) value for interval into a 2^x
 * range. Note the valid input range is 1-16, so we clamp values based on this.
 * See xHCI 1.1 / 6.2.3.6 for more information.
 */
static uint_t
xhci_endpoint_exponential_interval(usb_ep_descr_t *ep)
{
	int ival;

	ival = ep->bInterval;
	if (ival < 1)
		ival = 1;
	if (ival > 16)
		ival = 16;
	ival--;
	ASSERT(ival >= 0 && ival <= 15);
	return (ival);
}


/*
 * Determining the interval is unfortunately somewhat complicated as there are
 * many differnet forms that things can take. This is all summarized in a
 * somewhat helpful table, number 65, in xHCI 1.1 / 6.2.3.6. But here's
 * basically the six different cases we have to consider:
 *
 * Case 1: Non-High Speed Bulk and Control Endpoints
 * 	Always return 0.
 *
 * Case 2: Super Speed and High Speed Isoch and Intr endpoints
 * 	Convert from a 2^(x-1) range to a 2^x range.
 *
 * Case 3: Full Speed Isochronous Endpoints
 * 	As case 2, but add 3 as its values are in frames and we need to convert
 * 	to microframes. Adding three to the result is the same as multiplying
 * 	the initial value by 8.
 *
 * Case 4: Full speed and Low Speed Interrupt Endpoints
 * 	These have a 1-255 ms range that we need to convert to a 2^x * 128 us
 * 	range. We use the linear conversion and then add 3 to account for the
 * 	multiplying by 8 conversion from frames to microframes.
 *
 * Case 5: High Speed Interrupt and Bulk Output
 * 	These are a bit of a weird case. The spec and other implementations make
 * 	it seem that it's similar to case 4, but without the fixed addition as
 * 	its interpreted differently due to NAKs.
 *
 * Case 6: Low Speed Isochronous Endpoints
 * 	These are not actually defined; however, like other implementations we
 * 	treat them like case 4.
 */
static uint_t
xhci_endpoint_interval(xhci_device_t *xd, usb_ep_descr_t *ep)
{
	int type = ep->bmAttributes & USB_EP_ATTR_MASK;
	int speed = xd->xd_usbdev->usb_port_status;

	/*
	 * Handle Cases 1 and 5 first.
	 */
	if (type == USB_EP_ATTR_CONTROL || type == USB_EP_ATTR_BULK) {
		if (speed != USBA_HIGH_SPEED_DEV)
			return (0);
		return (xhci_endpoint_linear_interval(ep));
	}

	/*
	 * Handle Isoch and Intr cases next.
	 */
	switch (speed) {
	case USBA_LOW_SPEED_DEV:
		/*
		 * Interrupt endpoints at low speed are the same as full speed,
		 * hence the fall through.
		 */
		if (type == USB_EP_ATTR_ISOCH) {
			return (xhci_endpoint_exponential_interval(ep) + 3);
		}
		/* FALLTHROUGH */
	case USBA_FULL_SPEED_DEV:
		return (xhci_endpoint_linear_interval(ep) + 3);
	case USBA_HIGH_SPEED_DEV:
	case USBA_SUPER_SPEED_DEV:
	default:
		/*
		 * Case 2. Treat any newer and faster speeds as Super Speed by
		 * default as USB 3.1 is effectively treated the same here.
		 */
		return (xhci_endpoint_exponential_interval(ep));
	}
}

/*
 * The way to calculate the Maximum ESIT is described in xHCI 1.1 / 4.14.2.
 * First off, this only applies to Interrupt and Isochronous descriptors. For
 * Super Speed and newer things, it comes out of a descriptor. Otherwise we
 * calculate it by doing 'Max Packet Size' * ('Max Burst' + 1).
 */
static uint_t
xhci_endpoint_max_esit(xhci_device_t *xd, xhci_endpoint_t *xep, uint_t mps,
    uint_t burst)
{
	if (xep->xep_type == USB_EP_ATTR_CONTROL ||
	    xep->xep_type == USB_EP_ATTR_BULK) {
		return (0);
	}

	/*
	 * Note that this will need to be updated for SuperSpeedPlus ISOC
	 * devices to pull from the secondary companion descriptor they use.
	 */
	if (xd->xd_usbdev->usb_port_status >= USBA_SUPER_SPEED_DEV) {
		usb_ep_xdescr_t *ep_xdesc = &xep->xep_pipe->p_xep;
		ASSERT(xep->xep_pipe->p_xep.uex_flags & USB_EP_XFLAGS_SS_COMP);
		return (ep_xdesc->uex_ep_ss.wBytesPerInterval);
	}

	return (mps * (burst + 1));
}

/*
 * We've been asked to calculate and tell the xHCI controller an average TRB
 * data length. This is talked about in an implementation note in xHCI 1.1 /
 * 4.14.1.1. So, the reality is that it's hard to actually calculate this, as
 * we're supposed to take into account all of the TRBs that we use on that ring.
 *
 * Surveying other xHCI drivers, they all agree on using the default of 8 for
 * control endpoints; however, from there things get a little more fluid. For
 * interrupt and isochronous endpoints, many device use the minimum of the max
 * packet size and the device's pagesize. For bulk endpoints some folks punt and
 * don't set anything and others try and set it to the pagesize. The xHCI
 * implementation note suggests a 3k size here initially. For now, we'll just
 * guess for bulk endpoints and use our page size as a determining factor for
 * this and use the BSD style for others. Note Linux here only sets this value
 * for control devices.
 */
static uint_t
xhci_endpoint_avg_trb(xhci_t *xhcip, usb_ep_descr_t *ep, int mps)
{
	int type = ep->bmAttributes & USB_EP_ATTR_MASK;

	switch (type) {
	case USB_EP_ATTR_ISOCH:
	case USB_EP_ATTR_INTR:
		return (MIN(xhcip->xhci_caps.xcap_pagesize, mps));
	case USB_EP_ATTR_CONTROL:
		return (XHCI_CONTEXT_DEF_CTRL_ATL);
	case USB_EP_ATTR_BULK:
		return (xhcip->xhci_caps.xcap_pagesize);
	default:
		panic("bad USB endpoint type: %d", type);
	}

	/* LINTED: E_FUNC_NO_RET_VAL */
}

int
xhci_endpoint_setup_context(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep)
{
	uint_t eptype, burst, ival, max_esit, avgtrb, mps, mult, cerr;
	xhci_endpoint_context_t *ectx;
	uint64_t deq;

	/*
	 * For a USB >=3.0 device we should always have its companion descriptor
	 * provided for us by USBA. If it's not here, complain loudly and fail.
	 */
	if (xd->xd_usbdev->usb_port_status >= USBA_SUPER_SPEED_DEV &&
	    (xep->xep_pipe->p_xep.uex_flags & USB_EP_XFLAGS_SS_COMP) == 0) {
		const char *prod, *mfg;

		prod = xd->xd_usbdev->usb_product_str;
		if (prod == NULL)
			prod = "Unknown Device";
		mfg = xd->xd_usbdev->usb_mfg_str;
		if (mfg == NULL)
			mfg = "Unknown Manufacturer";

		xhci_log(xhcip, "Encountered USB >=3.0 device without endpoint "
		    "companion descriptor. Ensure driver %s is properly using "
		    "usb_pipe_xopen() for device %s %s",
		    ddi_driver_name(xd->xd_usbdev->usb_dip), prod, mfg);
		return (EINVAL);
	}

	ectx = xd->xd_endin[xep->xep_num];
	VERIFY(ectx != NULL);
	VERIFY(xd->xd_usbdev->usb_dev_descr != NULL);
	VERIFY(xep->xep_pipe != NULL);

	mps = xep->xep_pipe->p_ep.wMaxPacketSize & XHCI_CONTEXT_MPS_MASK;
	mult = XHCI_CONTEXT_DEF_MULT;
	cerr = XHCI_CONTEXT_DEF_CERR;

	switch (xep->xep_type) {
	case USB_EP_ATTR_ISOCH:
		/*
		 * When we have support for USB 3.1 SuperSpeedPlus devices,
		 * we'll need to make sure that we also check for its secondary
		 * endpoint companion descriptor here.
		 */
		/*
		 * Super Speed devices nominally have these xHCI super speed
		 * companion descriptors. We know that we're not properly
		 * grabbing them right now, so until we do, we should basically
		 * error about it.
		 */
		if (xd->xd_usbdev->usb_port_status >= USBA_SUPER_SPEED_DEV) {
			ASSERT(xep->xep_pipe->p_xep.uex_flags &
			    USB_EP_XFLAGS_SS_COMP);
			mult = xep->xep_pipe->p_xep.uex_ep_ss.bmAttributes &
			    USB_EP_SS_COMP_ISOC_MULT_MASK;
		}

		mps &= XHCI_CONTEXT_MPS_MASK;
		cerr = XHCI_CONTEXT_ISOCH_CERR;
		break;
	default:
		/*
		 * No explicit changes needed for CONTROL, INTR, and BULK
		 * endpoints. They've been handled already and don't have any
		 * differences.
		 */
		break;
	}

	eptype = xhci_endpoint_epdesc_to_type(&xep->xep_pipe->p_xep.uex_ep);
	burst = xhci_endpoint_determine_burst(xd, xep);
	ival = xhci_endpoint_interval(xd, &xep->xep_pipe->p_xep.uex_ep);
	max_esit = xhci_endpoint_max_esit(xd, xep, mps, burst);
	avgtrb = xhci_endpoint_avg_trb(xhcip, &xep->xep_pipe->p_xep.uex_ep,
	    mps);

	/*
	 * The multi field may be reserved as zero if the LEC feature flag is
	 * set. See the description of mult in xHCI 1.1 / 6.2.3.
	 */
	if (xhcip->xhci_caps.xcap_flags2 & XCAP2_LEC)
		mult = 0;

	bzero(ectx, sizeof (xhci_endpoint_context_t));

	ectx->xec_info = LE_32(XHCI_EPCTX_SET_MULT(mult) |
	    XHCI_EPCTX_SET_IVAL(ival));
	if (xhcip->xhci_caps.xcap_flags2 & XCAP2_LEC)
		ectx->xec_info |= LE_32(XHCI_EPCTX_SET_MAX_ESIT_HI(max_esit));

	ectx->xec_info2 = LE_32(XHCI_EPCTX_SET_CERR(cerr) |
	    XHCI_EPCTX_SET_EPTYPE(eptype) | XHCI_EPCTX_SET_MAXB(burst) |
	    XHCI_EPCTX_SET_MPS(mps));

	deq = xhci_dma_pa(&xep->xep_ring.xr_dma) + sizeof (xhci_trb_t) *
	    xep->xep_ring.xr_tail;
	ectx->xec_dequeue = LE_64(deq | xep->xep_ring.xr_cycle);

	ectx->xec_txinfo = LE_32(XHCI_EPCTX_MAX_ESIT_PAYLOAD(max_esit) |
	    XHCI_EPCTX_AVG_TRB_LEN(avgtrb));

	XHCI_DMA_SYNC(xd->xd_ictx, DDI_DMA_SYNC_FORDEV);
	if (xhci_check_dma_handle(xhcip, &xd->xd_ictx) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to initialize device input "
		    "context on slot %d and port %d for endpoint %u:  "
		    "encountered fatal FM error synchronizing input context "
		    "DMA memory", xd->xd_slot, xd->xd_port, xep->xep_num);
		xhci_fm_runtime_reset(xhcip);
		return (EIO);
	}

	return (0);
}

/*
 * Initialize the endpoint and its input context for a given device. This is
 * called from two different contexts:
 *
 *   1. Initializing a device
 *   2. Opening a USB pipe
 *
 * In the second case, we need to worry about locking around the device. We
 * don't need to worry about the locking in the first case because the USBA
 * doesn't know about it yet.
 */
int
xhci_endpoint_init(xhci_t *xhcip, xhci_device_t *xd,
    usba_pipe_handle_data_t *ph)
{
	int ret;
	uint_t epid;
	xhci_endpoint_t *xep;

	if (ph == NULL) {
		epid = XHCI_DEFAULT_ENDPOINT;
	} else {
		ASSERT(MUTEX_HELD(&xhcip->xhci_lock));
		epid = xhci_endpoint_pipe_to_epid(ph);
	}
	VERIFY(xd->xd_endpoints[epid] == NULL);

	xep = kmem_zalloc(sizeof (xhci_endpoint_t), KM_SLEEP);
	list_create(&xep->xep_transfers, sizeof (xhci_transfer_t),
	    offsetof(xhci_transfer_t, xt_link));
	cv_init(&xep->xep_state_cv, NULL, CV_DRIVER, NULL);
	xep->xep_xd = xd;
	xep->xep_xhci = xhcip;
	xep->xep_num = epid;
	if (ph == NULL) {
		xep->xep_pipe = NULL;
		xep->xep_type = USB_EP_ATTR_CONTROL;
	} else {
		xep->xep_pipe = ph;
		xep->xep_type = ph->p_ep.bmAttributes & USB_EP_ATTR_MASK;
	}

	if ((ret = xhci_ring_alloc(xhcip, &xep->xep_ring)) != 0) {
		cv_destroy(&xep->xep_state_cv);
		list_destroy(&xep->xep_transfers);
		kmem_free(xep, sizeof (xhci_endpoint_t));
		return (ret);
	}

	if ((ret = xhci_ring_reset(xhcip, &xep->xep_ring)) != 0) {
		xhci_ring_free(&xep->xep_ring);
		cv_destroy(&xep->xep_state_cv);
		list_destroy(&xep->xep_transfers);
		kmem_free(xep, sizeof (xhci_endpoint_t));
		return (ret);
	}

	xd->xd_endpoints[epid] = xep;
	if (ph == NULL) {
		ret = xhci_endpoint_setup_default_context(xhcip, xd, xep);
	} else {
		ret = xhci_endpoint_setup_context(xhcip, xd, xep);
	}
	if (ret != 0) {
		xhci_endpoint_fini(xd, xep->xep_num);
		return (ret);
	}

	return (0);
}

/*
 * Attempt to quiesce an endpoint. Depending on the state of the endpoint, we
 * may need to simply stop it. Alternatively, we may need to explicitly reset
 * the endpoint. Once done, this endpoint should be stopped and can be
 * manipulated.
 */
int
xhci_endpoint_quiesce(xhci_t *xhcip, xhci_device_t *xd, xhci_endpoint_t *xep)
{
	int ret = USB_SUCCESS;
	xhci_endpoint_context_t *epctx = xd->xd_endout[xep->xep_num];

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));
	ASSERT(xep->xep_state & XHCI_ENDPOINT_QUIESCE);

	/*
	 * First attempt to stop the endpoint, unless it's halted. We don't
	 * really care what state it is in. Note that because other activity
	 * could be going on, the state may change on us; however, if it's
	 * running, it will always transition to a stopped state and none of the
	 * other valid states will allow transitions without us taking an active
	 * action.
	 */
	if (!(xep->xep_state & XHCI_ENDPOINT_HALTED)) {
		mutex_exit(&xhcip->xhci_lock);
		ret = xhci_command_stop_endpoint(xhcip, xd, xep);
		mutex_enter(&xhcip->xhci_lock);

		if (ret == USB_INVALID_CONTEXT) {
			XHCI_DMA_SYNC(xd->xd_octx, DDI_DMA_SYNC_FORKERNEL);
		}
	}

	/*
	 * Now, if we had the HALTED flag set or we failed to stop it due to a
	 * context error and we're in the HALTED state now, reset the end point.
	 */
	if ((xep->xep_state & XHCI_ENDPOINT_HALTED) ||
	    (ret == USB_INVALID_CONTEXT &&
	    XHCI_EPCTX_STATE(LE_32(epctx->xec_info)) == XHCI_EP_HALTED)) {
		mutex_exit(&xhcip->xhci_lock);
		ret = xhci_command_reset_endpoint(xhcip, xd, xep);
		mutex_enter(&xhcip->xhci_lock);
	}

	/*
	 * Ideally, one of the two commands should have worked; however, we
	 * could have had a context error due to being in the wrong state.
	 * Verify that we're either in the ERROR or STOPPED state and treat both
	 * as success. All callers are assumed to be doing this so they can
	 * change the dequeue pointer.
	 */
	if (ret != USB_SUCCESS && ret != USB_INVALID_CONTEXT) {
		return (ret);
	}

	if (ret == USB_INVALID_CONTEXT) {
		XHCI_DMA_SYNC(xd->xd_octx, DDI_DMA_SYNC_FORKERNEL);

		switch (XHCI_EPCTX_STATE(LE_32(epctx->xec_info))) {
		case XHCI_EP_STOPPED:
		case XHCI_EP_ERROR:
			/*
			 * This is where we wanted to go, so let's just take it.
			 */
			ret = USB_SUCCESS;
			break;
		case XHCI_EP_DISABLED:
		case XHCI_EP_RUNNING:
		case XHCI_EP_HALTED:
		default:
			/*
			 * If we're in any of these, something really weird has
			 * happened and it's not worth trying to recover at this
			 * point.
			 */
			xhci_error(xhcip, "!asked to stop endpoint %u on slot "
			    "%d and port %d: ended up in unexpected state %d",
			    xep->xep_num, xd->xd_slot, xd->xd_port,
			    XHCI_EPCTX_STATE(LE_32(epctx->xec_info)));
			return (ret);
		}
	}

	/*
	 * Now that we're successful, we can clear any possible halted state
	 * tracking that we might have had.
	 */
	if (ret == USB_SUCCESS) {
		xep->xep_state &= ~XHCI_ENDPOINT_HALTED;
	}

	return (ret);
}

int
xhci_endpoint_ring(xhci_t *xhcip, xhci_device_t *xd, xhci_endpoint_t *xep)
{
	/*
	 * The doorbell ID's are offset by one from the endpoint numbers that we
	 * keep.
	 */
	xhci_put32(xhcip, XHCI_R_DOOR, XHCI_DOORBELL(xd->xd_slot),
	    xep->xep_num + 1);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to ring doorbell for slot %d and "
		    "endpoint %u: encountered fatal FM register access error",
		    xd->xd_slot, xep->xep_num);
		xhci_fm_runtime_reset(xhcip);
		return (USB_HC_HARDWARE_ERROR);
	}

	DTRACE_PROBE3(xhci__doorbell__ring, xhci_t *, xhcip, uint32_t,
	    XHCI_DOORBELL(xd->xd_slot), uint32_t, xep->xep_num + 1);

	return (USB_SUCCESS);
}

static void
xhci_endpoint_tick(void *arg)
{
	int ret;
	xhci_transfer_t *xt;
	xhci_endpoint_t *xep = arg;
	xhci_device_t *xd = xep->xep_xd;
	xhci_t *xhcip = xep->xep_xhci;

	mutex_enter(&xhcip->xhci_lock);

	/*
	 * If we have the teardown flag set, then this is going away, don't try
	 * to do anything. Also, if somehow a periodic endpoint has something
	 * scheduled, just quit now and don't bother.
	 */
	if (xep->xep_state & (XHCI_ENDPOINT_TEARDOWN |
	    XHCI_ENDPOINT_PERIODIC)) {
		xep->xep_timeout = 0;
		mutex_exit(&xhcip->xhci_lock);
		return;
	}

	/*
	 * If something else has already kicked off, something potentially
	 * dangerous, just don't bother waiting for it and reschedule.
	 */
	if (xep->xep_state & XHCI_ENDPOINT_DONT_SCHEDULE) {
		xep->xep_timeout = timeout(xhci_endpoint_tick, xep,
		    drv_usectohz(XHCI_TICK_TIMEOUT_US));
		mutex_exit(&xhcip->xhci_lock);
		return;
	}

	/*
	 * At this point, we have an endpoint that we need to consider. See if
	 * there are any transfers on it, if none, we're done. If so, check if
	 * we have exceeded the timeout. If we have, then we have some work to
	 * do.
	 */
	xt = list_head(&xep->xep_transfers);
	if (xt == NULL) {
		xep->xep_timeout = 0;
		mutex_exit(&xhcip->xhci_lock);
		return;
	}

	if (xt->xt_timeout > 0) {
		xt->xt_timeout--;
		xep->xep_timeout = timeout(xhci_endpoint_tick, xep,
		    drv_usectohz(XHCI_TICK_TIMEOUT_US));
		mutex_exit(&xhcip->xhci_lock);
		return;
	}

	/*
	 * This item has timed out. We need to stop the ring and take action.
	 */
	xep->xep_state |= XHCI_ENDPOINT_TIMED_OUT | XHCI_ENDPOINT_QUIESCE;
	ret = xhci_endpoint_quiesce(xhcip, xd, xep);
	if (ret != USB_SUCCESS) {
		/*
		 * If we fail to quiesce during the timeout, then remove the
		 * state flags and hopefully we'll be able to the next time
		 * around or if a reset or polling stop comes in, maybe it can
		 * deal with it.
		 */
		xep->xep_state &= ~(XHCI_ENDPOINT_QUIESCE |
		    XHCI_ENDPOINT_TIMED_OUT);
		xep->xep_timeout = timeout(xhci_endpoint_tick, xep,
		    drv_usectohz(XHCI_TICK_TIMEOUT_US));
		mutex_exit(&xhcip->xhci_lock);
		cv_broadcast(&xep->xep_state_cv);
		xhci_error(xhcip, "failed to successfully quiesce timed out "
		    "endpoint %u of device on slot %d and port %d: device "
		    "remains timed out", xep->xep_num, xd->xd_slot,
		    xd->xd_port);
		return;
	}

	xhci_ring_skip_transfer(&xep->xep_ring, xt);
	(void) list_remove_head(&xep->xep_transfers);
	mutex_exit(&xhcip->xhci_lock);

	/*
	 * At this point, we try and set the ring's dequeue pointer. If this
	 * fails, we're left in an awkward state. We've already adjusted the
	 * ring and removed the transfer. All we can really do is go through and
	 * return the transfer and hope that they perhaps attempt to reset the
	 * ring and that will succeed at this point. Based on everything we've
	 * done to set things up, it'd be odd if this did fail.
	 */
	ret = xhci_command_set_tr_dequeue(xhcip, xd, xep);
	mutex_enter(&xhcip->xhci_lock);
	xep->xep_state &= ~XHCI_ENDPOINT_QUIESCE;
	if (ret == USB_SUCCESS) {
		xep->xep_state &= ~XHCI_ENDPOINT_TIMED_OUT;
	} else {
		xhci_error(xhcip, "failed to successfully set transfer ring "
		    "dequeue pointer of timed out endpoint %u of "
		    "device on slot %d and port %d: device remains timed out, "
		    "please use cfgadm to recover", xep->xep_num, xd->xd_slot,
		    xd->xd_port);
	}
	xep->xep_timeout = timeout(xhci_endpoint_tick, xep,
	    drv_usectohz(XHCI_TICK_TIMEOUT_US));
	mutex_exit(&xhcip->xhci_lock);
	cv_broadcast(&xep->xep_state_cv);

	/*
	 * Because we never time out periodic related activity, we will always
	 * have the request on the transfer.
	 */
	ASSERT(xt->xt_usba_req != NULL);
	usba_hcdi_cb(xep->xep_pipe, xt->xt_usba_req, USB_CR_TIMEOUT);
	xhci_transfer_free(xhcip, xt);
}

/*
 * We've been asked to schedule a series of frames onto the specified endpoint.
 * We need to make sure that there is enough room, at which point we can queue
 * it and then ring the door bell. Note that we queue in reverse order to make
 * sure that if the ring moves on, it won't see the correct cycle bit.
 */
int
xhci_endpoint_schedule(xhci_t *xhcip, xhci_device_t *xd, xhci_endpoint_t *xep,
    xhci_transfer_t *xt, boolean_t ring)
{
	int i;
	xhci_ring_t *rp = &xep->xep_ring;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));
	ASSERT(xt->xt_ntrbs > 0);
	ASSERT(xt->xt_trbs != NULL);

	if ((xep->xep_state & XHCI_ENDPOINT_DONT_SCHEDULE) != 0)
		return (USB_FAILURE);

	if (xhci_ring_trb_space(rp, xt->xt_ntrbs) == B_FALSE)
		return (USB_NO_RESOURCES);

	for (i = xt->xt_ntrbs - 1; i > 0; i--) {
		xhci_ring_trb_fill(rp, i, &xt->xt_trbs[i], B_TRUE);
	}
	xhci_ring_trb_fill(rp, 0U, &xt->xt_trbs[0], B_FALSE);

	XHCI_DMA_SYNC(rp->xr_dma, DDI_DMA_SYNC_FORDEV);
	xhci_ring_trb_produce(rp, xt->xt_ntrbs);
	list_insert_tail(&xep->xep_transfers, xt);

	XHCI_DMA_SYNC(rp->xr_dma, DDI_DMA_SYNC_FORDEV);
	if (xhci_check_dma_handle(xhcip, &rp->xr_dma) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to write out TRB for device on slot "
		    "%d, port %d, and endpoint %u: encountered fatal FM error "
		    "synchronizing ring DMA memory", xd->xd_slot, xd->xd_port,
		    xep->xep_num);
		xhci_fm_runtime_reset(xhcip);
		return (USB_HC_HARDWARE_ERROR);
	}

	if (xep->xep_timeout == 0 &&
	    !(xep->xep_state & XHCI_ENDPOINT_PERIODIC)) {
		xep->xep_timeout = timeout(xhci_endpoint_tick, xep,
		    drv_usectohz(XHCI_TICK_TIMEOUT_US));
	}

	xt->xt_sched_time = gethrtime();

	if (ring == B_FALSE)
		return (USB_SUCCESS);

	return (xhci_endpoint_ring(xhcip, xd, xep));
}

static xhci_transfer_t *
xhci_endpoint_determine_transfer(xhci_t *xhcip, xhci_endpoint_t *xep,
    xhci_trb_t *trb, int *offp)
{
	xhci_transfer_t *xt;

	ASSERT(xhcip != NULL);
	ASSERT(offp != NULL);
	ASSERT(xep != NULL);
	ASSERT(trb != NULL);
	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	if ((xt = list_head(&xep->xep_transfers)) == NULL)
		return (NULL);

	*offp = xhci_ring_trb_valid_range(&xep->xep_ring, LE_64(trb->trb_addr),
	    xt->xt_ntrbs);
	if (*offp == -1)
		return (NULL);
	return (xt);
}

static void
xhci_endpoint_reschedule_periodic(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep, xhci_transfer_t *xt)
{
	int ret;
	xhci_pipe_t *xp = (xhci_pipe_t *)xep->xep_pipe->p_hcd_private;
	xhci_periodic_pipe_t *xpp = &xp->xp_periodic;

	ASSERT3U(xpp->xpp_tsize, >, 0);

	xt->xt_short = 0;
	xt->xt_cr = USB_CR_OK;

	mutex_enter(&xhcip->xhci_lock);

	/*
	 * If we don't have an active poll, then we shouldn't bother trying to
	 * reschedule it. This means that we're trying to stop or we ran out of
	 * memory.
	 */
	if (xpp->xpp_poll_state != XHCI_PERIODIC_POLL_ACTIVE) {
		mutex_exit(&xhcip->xhci_lock);
		return;
	}

	if (xep->xep_type == USB_EP_ATTR_ISOCH) {
		int i;
		for (i = 0; i < xt->xt_ntrbs; i++) {
			xt->xt_isoc[i].isoc_pkt_actual_length =
			    xt->xt_isoc[i].isoc_pkt_length;
			xt->xt_isoc[i].isoc_pkt_status = USB_CR_OK;
		}
	}

	/*
	 * In general, there should always be space on the ring for this. The
	 * only reason that rescheduling an existing transfer for a periodic
	 * endpoint wouldn't work is because we have a hardware error, at which
	 * point we're going to be going down hard anyways. We log and bump a
	 * stat here to make this case discoverable in case our assumptions our
	 * wrong.
	 */
	ret = xhci_endpoint_schedule(xhcip, xd, xep, xt, B_TRUE);
	if (ret != 0) {
		xhci_log(xhcip, "!failed to reschedule periodic endpoint %u "
		    "(type %u) on slot %d: %d\n", xep->xep_num, xep->xep_type,
		    xd->xd_slot, ret);
	}
	mutex_exit(&xhcip->xhci_lock);
}

/*
 * We're dealing with a message on a control endpoint. This may be a default
 * endpoint or otherwise. These usually come in groups of 3+ TRBs where you have
 * a setup stage, data stage (which may have one or more other TRBs) and then a
 * final status stage.
 *
 * We generally set ourselves up such that we get interrupted and notified only
 * on the status stage and for short transfers in the data stage. If we
 * encounter a short transfer in the data stage, then we need to go through and
 * check whether or not the short transfer is allowed. If it is, then there's
 * nothing to do. We'll update everything and call back the framework once we
 * get the status stage.
 */
static boolean_t
xhci_endpoint_control_callback(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep, xhci_transfer_t *xt, int off, xhci_trb_t *trb)
{
	int code;
	usb_ctrl_req_t *ucrp;
	xhci_transfer_t *rem;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	code = XHCI_TRB_GET_CODE(LE_32(trb->trb_status));
	ucrp = (usb_ctrl_req_t *)xt->xt_usba_req;

	/*
	 * Now that we know what this TRB is for, was it for a data/normal stage
	 * or is it the status stage. We cheat by looking at the last entry. If
	 * it's a data stage, then we must have gotten a short write. In that
	 * case, we should go through and check to make sure it's allowed. If
	 * not, we need to fail the transfer, try to stop the ring, and make
	 * callbacks. We'll clean up the xhci transfer at this time.
	 */
	if (off != xt->xt_ntrbs - 1) {
		uint_t remain;
		usb_ctrl_req_t *ucrp = (usb_ctrl_req_t *)xt->xt_usba_req;

		/*
		 * This is a data stage TRB. The only reason we should have
		 * gotten something for this is beacuse it was short. Make sure
		 * it's okay before we continue.
		 */
		VERIFY3S(code, ==, XHCI_CODE_SHORT_XFER);
		if (!(ucrp->ctrl_attributes & USB_ATTRS_SHORT_XFER_OK)) {
			xt->xt_cr = USB_CR_DATA_UNDERRUN;
			mutex_exit(&xhcip->xhci_lock);
			return (B_TRUE);
		}

		/*
		 * The value in the resulting trb is how much data remained to
		 * be transferred. Normalize that against the original buffer
		 * size.
		 */
		remain = XHCI_TRB_REMAIN(LE_32(trb->trb_status));
		xt->xt_short = xt->xt_buffer.xdb_len - remain;
		mutex_exit(&xhcip->xhci_lock);
		return (B_TRUE);
	}

	/*
	 * Okay, this is a status stage trb that's in good health. We should
	 * finally go ahead, sync data and try and finally do the callback. If
	 * we have short data, then xt->xt_short will be non-zero.
	 */
	if (xt->xt_data_tohost == B_TRUE) {
		size_t len;
		if (xt->xt_short != 0) {
			len = xt->xt_short;
		} else {
			len = xt->xt_buffer.xdb_len;
		}

		if (xhci_transfer_sync(xhcip, xt, DDI_DMA_SYNC_FORCPU) !=
		    DDI_FM_OK) {
			xhci_error(xhcip, "failed to process control transfer "
			    "callback for endpoint %u of device on slot %d and "
			    "port %d: encountered fatal FM error synchronizing "
			    "DMA memory, resetting device", xep->xep_num,
			    xd->xd_slot, xd->xd_port);
			xhci_fm_runtime_reset(xhcip);
			mutex_exit(&xhcip->xhci_lock);
			return (B_FALSE);
		}

		xhci_transfer_copy(xt, ucrp->ctrl_data->b_rptr, len, B_TRUE);
		ucrp->ctrl_data->b_wptr += len;
	}

	/*
	 * Now we're done. We can go ahead and bump the ring. Free the transfer
	 * outside of the lock and call back into the framework.
	 */
	VERIFY(xhci_ring_trb_consumed(&xep->xep_ring, LE_64(trb->trb_addr)));
	rem = list_remove_head(&xep->xep_transfers);
	VERIFY3P(rem, ==, xt);
	mutex_exit(&xhcip->xhci_lock);

	usba_hcdi_cb(xep->xep_pipe, (usb_opaque_t)ucrp, xt->xt_cr);
	xhci_transfer_free(xhcip, xt);

	return (B_TRUE);
}

/*
 * Cons up a new usb request for the periodic data transfer if we can. If there
 * isn't one available, change the return code to NO_RESOURCES and stop polling
 * on this endpoint, thus using and consuming the original request.
 */
static usb_opaque_t
xhci_endpoint_dup_periodic(xhci_endpoint_t *xep, xhci_transfer_t *xt,
    usb_cr_t *cr)
{
	usb_opaque_t urp;

	xhci_pipe_t *xp = (xhci_pipe_t *)xep->xep_pipe->p_hcd_private;
	xhci_periodic_pipe_t *xpp = &xp->xp_periodic;

	/*
	 * In general, transfers shouldn't have a usb request. However, oneshot
	 * Interrupt IN ones will, so we use this as a way to shortcut out of
	 * here.
	 */
	if (xt->xt_usba_req != NULL)
		return (xt->xt_usba_req);

	if (xep->xep_type == USB_EP_ATTR_INTR) {
		urp = (usb_opaque_t)usba_hcdi_dup_intr_req(xep->xep_pipe->p_dip,
		    (usb_intr_req_t *)xpp->xpp_usb_req, xpp->xpp_tsize, 0);
	} else {
		urp = (usb_opaque_t)usba_hcdi_dup_isoc_req(xep->xep_pipe->p_dip,
		    (usb_isoc_req_t *)xpp->xpp_usb_req, 0);
	}
	if (urp == NULL) {
		xpp->xpp_poll_state = XHCI_PERIODIC_POLL_NOMEM;
		urp = xpp->xpp_usb_req;
		xpp->xpp_usb_req = NULL;
		*cr = USB_CR_NO_RESOURCES;
	} else {
		mutex_enter(&xep->xep_pipe->p_mutex);
		xep->xep_pipe->p_req_count++;
		mutex_exit(&xep->xep_pipe->p_mutex);
	}

	return (urp);
}

static xhci_device_t *
xhci_device_lookup_by_slot(xhci_t *xhcip, int slot)
{
	xhci_device_t *xd;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	for (xd = list_head(&xhcip->xhci_usba.xa_devices); xd != NULL;
	    xd = list_next(&xhcip->xhci_usba.xa_devices, xd)) {
		if (xd->xd_slot == slot)
			return (xd);
	}

	return (NULL);
}

/*
 * Handle things which consist solely of normal tranfers, in other words, bulk
 * and interrupt transfers.
 */
static boolean_t
xhci_endpoint_norm_callback(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep, xhci_transfer_t *xt, int off, xhci_trb_t *trb)
{
	int code;
	usb_cr_t cr;
	xhci_transfer_t *rem;
	int attrs;
	mblk_t *mp;
	boolean_t periodic = B_FALSE;
	usb_opaque_t urp;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));
	ASSERT(xep->xep_type == USB_EP_ATTR_BULK ||
	    xep->xep_type == USB_EP_ATTR_INTR);

	code = XHCI_TRB_GET_CODE(LE_32(trb->trb_status));

	if (code == XHCI_CODE_SHORT_XFER) {
		int residue;
		residue = XHCI_TRB_REMAIN(LE_32(trb->trb_status));
		xt->xt_short = xt->xt_buffer.xdb_len - residue;
	}

	/*
	 * If we have an interrupt from something that's not the last entry,
	 * that must mean we had a short transfer, so there's nothing more for
	 * us to do at the moment. We won't call back until everything's
	 * finished for the general transfer.
	 */
	if (off < xt->xt_ntrbs - 1) {
		mutex_exit(&xhcip->xhci_lock);
		return (B_TRUE);
	}

	urp = xt->xt_usba_req;
	if (xep->xep_type == USB_EP_ATTR_BULK) {
		usb_bulk_req_t *ubrp = (usb_bulk_req_t *)xt->xt_usba_req;
		attrs = ubrp->bulk_attributes;
		mp = ubrp->bulk_data;
	} else {
		usb_intr_req_t *uirp = (usb_intr_req_t *)xt->xt_usba_req;

		if (uirp == NULL) {
			periodic = B_TRUE;
			urp = xhci_endpoint_dup_periodic(xep, xt, &cr);
			uirp = (usb_intr_req_t *)urp;

			/*
			 * If we weren't able to duplicate the interrupt, then
			 * we can't put any data in it.
			 */
			if (cr == USB_CR_NO_RESOURCES)
				goto out;
		}

		attrs = uirp->intr_attributes;
		mp = uirp->intr_data;
	}

	if (xt->xt_data_tohost == B_TRUE) {
		size_t len;
		if (xt->xt_short != 0) {
			if (!(attrs & USB_ATTRS_SHORT_XFER_OK)) {
				cr = USB_CR_DATA_UNDERRUN;
				goto out;
			}
			len = xt->xt_short;
		} else {
			len = xt->xt_buffer.xdb_len;
		}

		if (xhci_transfer_sync(xhcip, xt, DDI_DMA_SYNC_FORCPU) !=
		    DDI_FM_OK) {
			xhci_error(xhcip, "failed to process normal transfer "
			    "callback for endpoint %u of device on slot %d and "
			    "port %d: encountered fatal FM error synchronizing "
			    "DMA memory, resetting device", xep->xep_num,
			    xd->xd_slot, xd->xd_port);
			xhci_fm_runtime_reset(xhcip);
			mutex_exit(&xhcip->xhci_lock);
			return (B_FALSE);
		}

		xhci_transfer_copy(xt, mp->b_rptr, len, B_TRUE);
		mp->b_wptr += len;
	}
	cr = USB_CR_OK;

out:
	VERIFY(xhci_ring_trb_consumed(&xep->xep_ring, LE_64(trb->trb_addr)));
	rem = list_remove_head(&xep->xep_transfers);
	VERIFY3P(rem, ==, xt);
	mutex_exit(&xhcip->xhci_lock);

	usba_hcdi_cb(xep->xep_pipe, urp, cr);
	if (periodic == B_TRUE) {
		xhci_endpoint_reschedule_periodic(xhcip, xd, xep, xt);
	} else {
		xhci_transfer_free(xhcip, xt);
	}

	return (B_TRUE);
}

static boolean_t
xhci_endpoint_isoch_callback(xhci_t *xhcip, xhci_device_t *xd,
    xhci_endpoint_t *xep, xhci_transfer_t *xt, int off, xhci_trb_t *trb)
{
	int code;
	usb_cr_t cr;
	xhci_transfer_t *rem;
	usb_isoc_pkt_descr_t *desc;
	usb_isoc_req_t *usrp;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));
	ASSERT3S(xep->xep_type, ==, USB_EP_ATTR_ISOCH);

	code = XHCI_TRB_GET_CODE(LE_32(trb->trb_status));

	/*
	 * The descriptors that we copy the data from are set up to assume that
	 * everything was OK and we transferred all the requested data.
	 */
	desc = &xt->xt_isoc[off];
	if (code == XHCI_CODE_SHORT_XFER) {
		int residue = XHCI_TRB_REMAIN(LE_32(trb->trb_status));
		desc->isoc_pkt_actual_length -= residue;
	}

	/*
	 * We don't perform the callback until the very last TRB is returned
	 * here. If we have a TRB report on something else, that means that we
	 * had a short transfer.
	 */
	if (off < xt->xt_ntrbs - 1) {
		mutex_exit(&xhcip->xhci_lock);
		return (B_TRUE);
	}

	VERIFY(xhci_ring_trb_consumed(&xep->xep_ring, LE_64(trb->trb_addr)));
	rem = list_remove_head(&xep->xep_transfers);
	VERIFY3P(rem, ==, xt);
	mutex_exit(&xhcip->xhci_lock);

	cr = USB_CR_OK;

	if (xt->xt_data_tohost == B_TRUE) {
		usb_opaque_t urp;
		urp = xhci_endpoint_dup_periodic(xep, xt, &cr);
		usrp = (usb_isoc_req_t *)urp;

		if (cr == USB_CR_OK) {
			mblk_t *mp;
			size_t len;
			if (xhci_transfer_sync(xhcip, xt,
			    DDI_DMA_SYNC_FORCPU) != DDI_FM_OK) {
				xhci_error(xhcip, "failed to process "
				    "isochronous transfer callback for "
				    "endpoint %u of device on slot %d and port "
				    "%d: encountered fatal FM error "
				    "synchronizing DMA memory, resetting "
				    "device",
				    xep->xep_num, xd->xd_slot, xd->xd_port);
				xhci_fm_runtime_reset(xhcip);
				mutex_exit(&xhcip->xhci_lock);
				return (B_FALSE);
			}

			mp = usrp->isoc_data;
			len = xt->xt_buffer.xdb_len;
			xhci_transfer_copy(xt, mp->b_rptr, len, B_TRUE);
			mp->b_wptr += len;
		}
	} else {
		usrp = (usb_isoc_req_t *)xt->xt_usba_req;
	}

	if (cr == USB_CR_OK) {
		bcopy(xt->xt_isoc, usrp->isoc_pkt_descr,
		    sizeof (usb_isoc_pkt_descr_t) * usrp->isoc_pkts_count);
	}

	usba_hcdi_cb(xep->xep_pipe, (usb_opaque_t)usrp, cr);
	if (xt->xt_data_tohost == B_TRUE) {
		xhci_endpoint_reschedule_periodic(xhcip, xd, xep, xt);
	} else {
		xhci_transfer_free(xhcip, xt);
	}

	return (B_TRUE);
}

boolean_t
xhci_endpoint_transfer_callback(xhci_t *xhcip, xhci_trb_t *trb)
{
	boolean_t ret;
	int slot, endpoint, code, off;
	xhci_device_t *xd;
	xhci_endpoint_t *xep;
	xhci_transfer_t *xt;
	boolean_t transfer_done;

	endpoint = XHCI_TRB_GET_EP(LE_32(trb->trb_flags));
	slot = XHCI_TRB_GET_SLOT(LE_32(trb->trb_flags));
	code = XHCI_TRB_GET_CODE(LE_32(trb->trb_status));

	mutex_enter(&xhcip->xhci_lock);
	xd = xhci_device_lookup_by_slot(xhcip, slot);
	if (xd == NULL) {
		xhci_error(xhcip, "received transfer trb with code %d for "
		    "unknown slot %d and endpoint %d: resetting device", code,
		    slot, endpoint);
		mutex_exit(&xhcip->xhci_lock);
		xhci_fm_runtime_reset(xhcip);
		return (B_FALSE);
	}

	/*
	 * Endpoint IDs are indexed based on their Device Context Index, which
	 * means that we need to subtract one to get the actual ID that we use.
	 */
	xep = xd->xd_endpoints[endpoint - 1];
	if (xep == NULL) {
		xhci_error(xhcip, "received transfer trb with code %d, slot "
		    "%d, and unknown endpoint %d: resetting device", code,
		    slot, endpoint);
		mutex_exit(&xhcip->xhci_lock);
		xhci_fm_runtime_reset(xhcip);
		return (B_FALSE);
	}

	/*
	 * This TRB should be part of a transfer. If it's not, then we ignore
	 * it. We also check whether or not it's for the first transfer. Because
	 * the rings are serviced in order, it should be.
	 */
	if ((xt = xhci_endpoint_determine_transfer(xhcip, xep, trb, &off)) ==
	    NULL) {
		mutex_exit(&xhcip->xhci_lock);
		return (B_TRUE);
	}

	transfer_done = B_FALSE;

	switch (code) {
	case XHCI_CODE_SUCCESS:
	case XHCI_CODE_SHORT_XFER:
		/* Handled by endpoint logic */
		break;
	case XHCI_CODE_XFER_STOPPED:
	case XHCI_CODE_XFER_STOPINV:
	case XHCI_CODE_XFER_STOPSHORT:
		/*
		 * This causes us to transition the endpoint to a stopped state.
		 * Each of these indicate a different possible state that we
		 * have to deal with. Effectively we're going to drop it and
		 * leave it up to the consumers to figure out what to do. For
		 * the moment, that's generally okay because stops are only used
		 * in cases where we're cleaning up outstanding reqs, etc.
		 */
		mutex_exit(&xhcip->xhci_lock);
		return (B_TRUE);
	case XHCI_CODE_STALL:
		/*
		 * This causes us to transition to the halted state;
		 * however, downstream clients are able to handle this just
		 * fine.
		 */
		xep->xep_state |= XHCI_ENDPOINT_HALTED;
		xt->xt_cr = USB_CR_STALL;
		transfer_done = B_TRUE;
		break;
	case XHCI_CODE_BABBLE:
		transfer_done = B_TRUE;
		xt->xt_cr = USB_CR_DATA_OVERRUN;
		xep->xep_state |= XHCI_ENDPOINT_HALTED;
		break;
	case XHCI_CODE_TXERR:
	case XHCI_CODE_SPLITERR:
		transfer_done = B_TRUE;
		xt->xt_cr = USB_CR_DEV_NOT_RESP;
		xep->xep_state |= XHCI_ENDPOINT_HALTED;
		break;
	default:
		/*
		 * Treat these as general unspecified errors that don't cause a
		 * stop of the ring. Even if it does, a subsequent timeout
		 * should occur which causes us to end up dropping a pipe reset
		 * or at least issuing a reset of the device as part of
		 * quiescing.
		 */
		transfer_done = B_TRUE;
		break;
	}

	if (transfer_done == B_TRUE) {
		xhci_transfer_t *alt;

		alt = list_remove_head(&xep->xep_transfers);
		VERIFY3P(alt, ==, xt);
		mutex_exit(&xhcip->xhci_lock);
		if (xt->xt_usba_req == NULL) {
			usb_opaque_t urp;

			urp = xhci_endpoint_dup_periodic(xep, xt, &xt->xt_cr);
			usba_hcdi_cb(xep->xep_pipe, urp, xt->xt_cr);
		} else {
			usba_hcdi_cb(xep->xep_pipe,
			    (usb_opaque_t)xt->xt_usba_req, xt->xt_cr);
			xhci_transfer_free(xhcip, xt);
		}
		return (B_TRUE);
	}

	/*
	 * Process the transfer callback based on the type of endpoint. Each of
	 * these callback functions will end up calling back into USBA via
	 * usba_hcdi_cb() to return transfer information (whether successful or
	 * not). Because we can't hold any locks across a call to that function,
	 * all of these callbacks will drop the xhci_t`xhci_lock by the time
	 * they return. This is why there's no mutex_exit() call before we
	 * return.
	 */
	switch (xep->xep_type) {
	case USB_EP_ATTR_CONTROL:
		ret = xhci_endpoint_control_callback(xhcip, xd, xep, xt, off,
		    trb);
		break;
	case USB_EP_ATTR_BULK:
		ret = xhci_endpoint_norm_callback(xhcip, xd, xep, xt, off, trb);
		break;
	case USB_EP_ATTR_INTR:
		ret = xhci_endpoint_norm_callback(xhcip, xd, xep, xt, off,
		    trb);
		break;
	case USB_EP_ATTR_ISOCH:
		ret = xhci_endpoint_isoch_callback(xhcip, xd, xep, xt, off,
		    trb);
		break;
	default:
		panic("bad endpoint type: %u", xep->xep_type);
	}

	return (ret);
}
