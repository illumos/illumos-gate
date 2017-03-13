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
 * illumos USB framework endpoints and functions for xHCI.
 *
 * Please see the big theory statement in xhci.c for more information.
 */

#include <sys/usb/hcd/xhci/xhci.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>

static xhci_t *
xhci_hcdi_get_xhcip_from_dev(usba_device_t *ud)
{
	dev_info_t *dip = ud->usb_root_hub_dip;
	xhci_t *xhcip = ddi_get_soft_state(xhci_soft_state,
	    ddi_get_instance(dip));
	VERIFY(xhcip != NULL);
	return (xhcip);
}

static xhci_t *
xhci_hcdi_get_xhcip(usba_pipe_handle_data_t *ph)
{
	return (xhci_hcdi_get_xhcip_from_dev(ph->p_usba_device));
}

/*
 * While the xHCI hardware is capable of supporting power management, we don't
 * in the driver right now. Note, USBA doesn't seem to end up calling this entry
 * point.
 */
/* ARGSUSED */
static int
xhci_hcdi_pm_support(dev_info_t *dip)
{
	return (USB_FAILURE);
}

static int
xhci_hcdi_pipe_open(usba_pipe_handle_data_t *ph, usb_flags_t usb_flags)
{
	xhci_t *xhcip = xhci_hcdi_get_xhcip(ph);
	xhci_pipe_t *pipe;
	xhci_endpoint_t *xep;
	xhci_device_t *xd;
	int kmflags = usb_flags & USB_FLAGS_SLEEP ? KM_SLEEP : KM_NOSLEEP;
	int ret;
	uint_t epid;

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_HC_HARDWARE_ERROR);
	}
	mutex_exit(&xhcip->xhci_lock);

	/*
	 * If we're here, something must be trying to open an already-opened
	 * pipe which is bad news.
	 */
	if (ph->p_hcd_private != NULL) {
		return (USB_FAILURE);
	}

	pipe = kmem_zalloc(sizeof (xhci_pipe_t), kmflags);
	if (pipe == NULL) {
		return (USB_NO_RESOURCES);
	}
	pipe->xp_opentime = gethrtime();
	pipe->xp_pipe = ph;

	/*
	 * If this is the root hub, there's nothing special to do on open. Just
	 * go ahead and allow it to be opened. All we have to do is add this to
	 * the list of our tracking structures for open pipes.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		xep = NULL;
		goto add;
	}

	/*
	 * Now that we're here, we're being asked to open up an endpoint of some
	 * kind. Because we've already handled the case of the root hub,
	 * everything should have a device.
	 */
	epid = xhci_endpoint_pipe_to_epid(ph);
	xd = usba_hcdi_get_device_private(ph->p_usba_device);
	if (xd == NULL) {
		xhci_error(xhcip, "!encountered endpoint (%d) without device "
		    "during pipe open", epid);
		kmem_free(pipe, sizeof (xhci_pipe_t));
		return (USB_FAILURE);
	}

	/*
	 * See if this endpoint exists or not, in general endpoints should not
	 * exist except for the default control endpoint, which we don't tear
	 * down until the device itself is cleaned up. Otherwise, a given pipe
	 * can only be open once.
	 */
	mutex_enter(&xhcip->xhci_lock);
	if (epid == XHCI_DEFAULT_ENDPOINT) {
		xep = xd->xd_endpoints[epid];
		VERIFY(xep != NULL);
		VERIFY(xep->xep_pipe == NULL);
		xep->xep_pipe = ph;
		mutex_exit(&xhcip->xhci_lock);
		ret = xhci_endpoint_update_default(xhcip, xd, xep);
		if (ret != USB_SUCCESS) {
			kmem_free(pipe, sizeof (xhci_pipe_t));
			return (ret);
		}
		goto add;
	}

	if (xd->xd_endpoints[epid] != NULL) {
		mutex_exit(&xhcip->xhci_lock);
		kmem_free(pipe, sizeof (xhci_pipe_t));
		xhci_log(xhcip, "!asked to open endpoint %d on slot %d and "
		    "port %d, but endpoint already exists", epid, xd->xd_slot,
		    xd->xd_port);
		return (USB_FAILURE);
	}

	/*
	 * If we're opening an endpoint other than the default control endpoint,
	 * then the device should have had a USB address assigned by the
	 * controller. Sanity check that before continuing.
	 */
	if (epid != XHCI_DEFAULT_ENDPOINT) {
		VERIFY(xd->xd_addressed == B_TRUE);
	}

	/*
	 * Okay, at this point we need to go create and set up an endpoint.
	 * Once we're done, we'll try to install it and make sure that it
	 * doesn't conflict with something else going on.
	 */
	ret = xhci_endpoint_init(xhcip, xd, ph);
	if (ret != 0) {
		mutex_exit(&xhcip->xhci_lock);
		kmem_free(pipe, sizeof (xhci_pipe_t));
		if (ret == EIO) {
			xhci_error(xhcip, "failed to initialize endpoint %d "
			    "on device slot %d and port %d: encountered fatal "
			    "FM error, resetting device", epid, xd->xd_slot,
			    xd->xd_port);
			xhci_fm_runtime_reset(xhcip);
		}
		return (USB_HC_HARDWARE_ERROR);
	}
	xep = xd->xd_endpoints[epid];

	mutex_enter(&xd->xd_imtx);
	mutex_exit(&xhcip->xhci_lock);

	/*
	 * Update the slot and input context for this endpoint.
	 */
	xd->xd_input->xic_drop_flags = LE_32(0);
	xd->xd_input->xic_add_flags = LE_32(XHCI_INCTX_MASK_DCI(epid + 1));

	if (epid + 1 > XHCI_SCTX_GET_DCI(LE_32(xd->xd_slotin->xsc_info))) {
		uint32_t info;

		info = xd->xd_slotin->xsc_info;
		info &= ~XHCI_SCTX_DCI_MASK;
		info |= XHCI_SCTX_SET_DCI(epid + 1);
		xd->xd_slotin->xsc_info = info;
	}

	XHCI_DMA_SYNC(xd->xd_ictx, DDI_DMA_SYNC_FORDEV);
	if (xhci_check_dma_handle(xhcip, &xd->xd_ictx) != DDI_FM_OK) {
		mutex_exit(&xd->xd_imtx);
		xhci_endpoint_fini(xd, epid);
		kmem_free(pipe, sizeof (xhci_pipe_t));
		xhci_error(xhcip, "failed to open pipe on endpoint %d of "
		    "device with slot %d and port %d: encountered fatal FM "
		    "error syncing device input context, resetting device",
		    epid, xd->xd_slot, xd->xd_port);
		xhci_fm_runtime_reset(xhcip);
		return (USB_HC_HARDWARE_ERROR);
	}

	if ((ret = xhci_command_configure_endpoint(xhcip, xd)) != USB_SUCCESS) {
		mutex_exit(&xd->xd_imtx);
		xhci_endpoint_fini(xd, epid);
		kmem_free(pipe, sizeof (xhci_pipe_t));
		return (ret);
	}

	mutex_exit(&xd->xd_imtx);
add:
	pipe->xp_ep = xep;
	ph->p_hcd_private = (usb_opaque_t)pipe;
	mutex_enter(&xhcip->xhci_lock);
	list_insert_tail(&xhcip->xhci_usba.xa_pipes, pipe);
	mutex_exit(&xhcip->xhci_lock);

	return (USB_SUCCESS);
}

static void
xhci_hcdi_periodic_free(xhci_t *xhcip, xhci_pipe_t *xp)
{
	int i;
	xhci_periodic_pipe_t *xpp = &xp->xp_periodic;

	if (xpp->xpp_tsize == 0)
		return;

	for (i = 0; i < xpp->xpp_ntransfers; i++) {
		if (xpp->xpp_transfers[i] == NULL)
			continue;
		xhci_transfer_free(xhcip, xpp->xpp_transfers[i]);
		xpp->xpp_transfers[i] = NULL;
	}

	xpp->xpp_ntransfers = 0;
	xpp->xpp_tsize = 0;
}

/*
 * Iterate over all transfers and free everything on the pipe. Once done, update
 * the ring to basically 'consume' everything. For periodic IN endpoints, we
 * need to handle this somewhat differently and actually close the original
 * request and not deallocate the related pieces as those exist for the lifetime
 * of the endpoint and are constantly reused.
 */
static void
xhci_hcdi_pipe_flush(xhci_t *xhcip, xhci_endpoint_t *xep, int intr_code)
{
	xhci_transfer_t *xt;

	ASSERT(MUTEX_HELD(&xhcip->xhci_lock));

	while ((xt = list_remove_head(&xep->xep_transfers)) != NULL) {
		if (xhci_endpoint_is_periodic_in(xep) == B_FALSE) {
			usba_hcdi_cb(xep->xep_pipe, xt->xt_usba_req,
			    USB_CR_FLUSHED);
			xhci_transfer_free(xhcip, xt);
		}
	}

	if (xhci_endpoint_is_periodic_in(xep) == B_TRUE) {
		xhci_pipe_t *xp = (xhci_pipe_t *)xep->xep_pipe->p_hcd_private;
		xhci_periodic_pipe_t *xpp = &xp->xp_periodic;

		if (xpp->xpp_usb_req != NULL) {
			usba_hcdi_cb(xep->xep_pipe, xpp->xpp_usb_req,
			    intr_code);
			xpp->xpp_usb_req = NULL;
		}
	}
}

/*
 * We've been asked to terminate some set of regular I/O on an interrupt pipe.
 * If this is for the root device, e.g. the xhci driver itself, then we remove
 * our interrupt callback. Otherwise we stop the device for interrupt polling as
 * follows:
 *
 * 1. Issue a stop endpoint command
 * 2. Check to make sure that the endpoint stopped and reset it if needed.
 * 3. Any thing that gets resolved can callback in the interim.
 * 4. Ensure that nothing is scheduled on the ring
 * 5. Skip the contents of the ring and set the TR dequeue pointer.
 * 6. Return the original callback with a USB_CR_STOPPED_POLLING, NULL out the
 *    callback in the process.
 */
static int
xhci_hcdi_pipe_poll_fini(usba_pipe_handle_data_t *ph, boolean_t is_close)
{
	int ret;
	uint_t epid;
	xhci_t *xhcip = xhci_hcdi_get_xhcip(ph);
	xhci_device_t *xd;
	xhci_endpoint_t *xep;
	xhci_pipe_t *xp;
	xhci_periodic_pipe_t *xpp;
	usb_opaque_t urp;

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_HC_HARDWARE_ERROR);
	}

	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		xhci_root_hub_intr_root_disable(xhcip);
		ret = USB_SUCCESS;
		mutex_exit(&xhcip->xhci_lock);
		return (ret);
	}

	xd = usba_hcdi_get_device_private(ph->p_usba_device);
	epid = xhci_endpoint_pipe_to_epid(ph);
	if (xd->xd_endpoints[epid] == NULL) {
		mutex_exit(&xhcip->xhci_lock);
		xhci_error(xhcip, "asked to stop intr polling on slot %d, "
		    "port %d, endpoint: %d, but no endpoint structure",
		    xd->xd_slot, xd->xd_port, epid);
		return (USB_FAILURE);
	}
	xep = xd->xd_endpoints[epid];
	xp = (xhci_pipe_t *)ph->p_hcd_private;
	if (xp == NULL) {
		mutex_exit(&xhcip->xhci_lock);
		xhci_error(xhcip, "asked to do finish polling on slot %d, "
		    "port %d, endpoint: %d, but no pipe structure",
		    xd->xd_slot, xd->xd_port, epid);
		return (USB_FAILURE);
	}
	xpp = &xp->xp_periodic;

	/*
	 * Ensure that no other resets or time outs are going on right now.
	 */
	while ((xep->xep_state & (XHCI_ENDPOINT_SERIALIZE)) != 0) {
		cv_wait(&xep->xep_state_cv, &xhcip->xhci_lock);
	}

	if (xpp->xpp_poll_state == XHCI_PERIODIC_POLL_IDLE) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_SUCCESS);
	}

	if (xpp->xpp_poll_state == XHCI_PERIODIC_POLL_STOPPING) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_FAILURE);
	}

	xpp->xpp_poll_state = XHCI_PERIODIC_POLL_STOPPING;
	xep->xep_state |= XHCI_ENDPOINT_QUIESCE;
	ret = xhci_endpoint_quiesce(xhcip, xd, xep);
	if (ret != USB_SUCCESS) {
		xhci_error(xhcip, "!failed to quiesce endpoint on slot %d, "
		    "port %d, endpoint: %d, failed with %d.",
		    xd->xd_slot, xd->xd_port, epid, ret);
		xep->xep_state &= ~XHCI_ENDPOINT_QUIESCE;
		cv_broadcast(&xep->xep_state_cv);
		mutex_exit(&xhcip->xhci_lock);
		return (ret);
	}

	/*
	 * Okay, we've stopped this ring time to wrap it all up. Remove all the
	 * transfers, note they aren't freed like a pipe reset.
	 */
	while (list_is_empty(&xep->xep_transfers) == 0)
		(void) list_remove_head(&xep->xep_transfers);
	xhci_ring_skip(&xep->xep_ring);
	mutex_exit(&xhcip->xhci_lock);

	if ((ret = xhci_command_set_tr_dequeue(xhcip, xd, xep)) !=
	    USB_SUCCESS) {
		xhci_error(xhcip, "!failed to reset endpoint ring on slot %d, "
		    "port %d, endpoint: %d, failed with %d.",
		    xd->xd_slot, xd->xd_port, epid, ret);
		mutex_enter(&xhcip->xhci_lock);
		xep->xep_state &= ~XHCI_ENDPOINT_QUIESCE;
		cv_broadcast(&xep->xep_state_cv);
		mutex_exit(&xhcip->xhci_lock);
		return (ret);
	}

	mutex_enter(&xhcip->xhci_lock);
	urp = xpp->xpp_usb_req;
	xpp->xpp_usb_req = NULL;
	xpp->xpp_poll_state = XHCI_PERIODIC_POLL_IDLE;
	xep->xep_state &= ~XHCI_ENDPOINT_PERIODIC;
	mutex_exit(&xhcip->xhci_lock);

	/*
	 * It's possible that with a persistent pipe, we may not actually have
	 * anything left to call back on, because we already had.
	 */
	if (urp != NULL) {
		usba_hcdi_cb(ph, urp, is_close == B_TRUE ?
		    USB_CR_PIPE_CLOSING : USB_CR_STOPPED_POLLING);
	}

	/*
	 * Notify anything waiting for us that we're done quiescing this device.
	 */
	mutex_enter(&xhcip->xhci_lock);
	xep->xep_state &= ~XHCI_ENDPOINT_QUIESCE;
	cv_broadcast(&xep->xep_state_cv);
	mutex_exit(&xhcip->xhci_lock);

	return (USB_SUCCESS);

}

/*
 * Tear down everything that we did in open. After this, the consumer of this
 * USB device is done.
 */
/* ARGSUSED */
static int
xhci_hcdi_pipe_close(usba_pipe_handle_data_t *ph, usb_flags_t usb_flags)
{
	xhci_t *xhcip = xhci_hcdi_get_xhcip(ph);
	xhci_pipe_t *xp;
	xhci_device_t *xd;
	xhci_endpoint_t *xep;
	uint32_t info;
	int ret, i;
	uint_t epid;

	if ((ph->p_ep.bmAttributes & USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR &&
	    xhcip->xhci_usba.xa_intr_cb_ph != NULL) {
		if ((ret = xhci_hcdi_pipe_poll_fini(ph, B_TRUE)) !=
		    USB_SUCCESS) {
			return (ret);
		}
	}

	mutex_enter(&xhcip->xhci_lock);

	xp = (xhci_pipe_t *)ph->p_hcd_private;
	VERIFY(xp != NULL);

	/*
	 * The default endpoint is special. It is created and destroyed with the
	 * device. So like with open, closing it is just state tracking. The
	 * same is true for the root hub.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR)
		goto remove;

	xd = usba_hcdi_get_device_private(ph->p_usba_device);
	epid = xhci_endpoint_pipe_to_epid(ph);
	if (xd->xd_endpoints[epid] == NULL) {
		mutex_exit(&xhcip->xhci_lock);
		xhci_error(xhcip, "asked to do close pipe on slot %d, "
		    "port %d, endpoint: %d, but no endpoint structure",
		    xd->xd_slot, xd->xd_port, epid);
		return (USB_FAILURE);
	}
	xep = xd->xd_endpoints[epid];

	if (xp->xp_ep != NULL && xp->xp_ep->xep_num == XHCI_DEFAULT_ENDPOINT) {
		xep->xep_pipe = NULL;
		goto remove;
	}

	/*
	 * We need to clean up the endpoint. So the first thing we need to do is
	 * stop it with a configure endpoint command. Once it's stopped, we can
	 * free all associated resources.
	 */
	mutex_enter(&xd->xd_imtx);

	/*
	 * Potentially update the slot input context about the current max
	 * endpoint. While we don't update the slot context with this,
	 * surrounding code expects it to be updated to be consistent.
	 */
	xd->xd_input->xic_drop_flags = LE_32(XHCI_INCTX_MASK_DCI(epid + 1));
	xd->xd_input->xic_add_flags = LE_32(0);
	for (i = XHCI_NUM_ENDPOINTS - 1; i >= 0; i--) {
		if (xd->xd_endpoints[i] != NULL &&
		    xd->xd_endpoints[i] != xep)
			break;
	}
	info = xd->xd_slotin->xsc_info;
	info &= ~XHCI_SCTX_DCI_MASK;
	info |= XHCI_SCTX_SET_DCI(i + 1);
	xd->xd_slotin->xsc_info = info;

	/*
	 * Also zero out our context for this endpoint. Note that we don't
	 * bother with syncing DMA memory here as it's not required to be synced
	 * for this operation.
	 */
	bzero(xd->xd_endin[xep->xep_num], sizeof (xhci_endpoint_context_t));

	/*
	 * Stop the device and kill our timeout. Note, it is safe to hold the
	 * device's input mutex across the untimeout, this lock should never be
	 * referenced by the timeout code.
	 */
	xep->xep_state |= XHCI_ENDPOINT_TEARDOWN;
	mutex_exit(&xhcip->xhci_lock);
	(void) untimeout(xep->xep_timeout);

	ret = xhci_command_configure_endpoint(xhcip, xd);
	mutex_exit(&xd->xd_imtx);
	if (ret != USB_SUCCESS)
		return (ret);
	mutex_enter(&xhcip->xhci_lock);

	/*
	 * Now that we've unconfigured the endpoint. See if we need to flush any
	 * transfers.
	 */
	xhci_hcdi_pipe_flush(xhcip, xep, USB_CR_PIPE_CLOSING);
	if ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		xhci_hcdi_periodic_free(xhcip, xp);
	}

	xhci_endpoint_fini(xd, epid);

remove:
	ph->p_hcd_private = NULL;
	list_remove(&xhcip->xhci_usba.xa_pipes, xp);
	kmem_free(xp, sizeof (xhci_pipe_t));

	mutex_exit(&xhcip->xhci_lock);

	return (USB_SUCCESS);
}

/*
 * We've been asked to reset a pipe aka an endpoint. This endpoint may be in an
 * arbitrary state, it may be running or it may be halted. In this case, we go
 * through and check whether or not we know it's been halted or not. If it has
 * not, then we stop the endpoint.
 *
 * Once the endpoint has been stopped, walk all transfers and go ahead and
 * basically return them as being flushed. Then finally set the dequeue point
 * for this endpoint.
 */
/* ARGSUSED */
static int
xhci_hcdi_pipe_reset(usba_pipe_handle_data_t *ph, usb_flags_t usb_flags)
{
	xhci_t *xhcip = xhci_hcdi_get_xhcip(ph);
	xhci_device_t *xd;
	xhci_endpoint_t *xep;
	uint_t epid;
	int ret;

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_HC_HARDWARE_ERROR);
	}

	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_NOT_SUPPORTED);
	}

	xd = usba_hcdi_get_device_private(ph->p_usba_device);
	epid = xhci_endpoint_pipe_to_epid(ph);
	if (xd->xd_endpoints[epid] == NULL) {
		mutex_exit(&xhcip->xhci_lock);
		xhci_error(xhcip, "asked to do reset pipe on slot %d, "
		    "port %d, endpoint: %d, but no endpoint structure",
		    xd->xd_slot, xd->xd_port, epid);
		return (USB_FAILURE);
	}

	xep = xd->xd_endpoints[epid];

	/*
	 * Ensure that no other resets or time outs are going on right now.
	 */
	while ((xep->xep_state & (XHCI_ENDPOINT_SERIALIZE)) != 0) {
		cv_wait(&xep->xep_state_cv, &xhcip->xhci_lock);
	}

	xep->xep_state |= XHCI_ENDPOINT_QUIESCE;
	ret = xhci_endpoint_quiesce(xhcip, xd, xep);
	if (ret != USB_SUCCESS) {
		/*
		 * We failed to quiesce for some reason, remove the flag and let
		 * someone else give it a shot.
		 */
		xhci_error(xhcip, "!failed to quiesce endpoint on slot %d, "
		    "port %d, endpoint: %d, failed with %d.",
		    xd->xd_slot, xd->xd_port, epid, ret);
		xep->xep_state &= ~XHCI_ENDPOINT_QUIESCE;
		cv_broadcast(&xep->xep_state_cv);
		mutex_exit(&xhcip->xhci_lock);
		return (ret);
	}

	xhci_ring_skip(&xep->xep_ring);

	mutex_exit(&xhcip->xhci_lock);
	if ((ret = xhci_command_set_tr_dequeue(xhcip, xd, xep)) !=
	    USB_SUCCESS) {
		xhci_error(xhcip, "!failed to reset endpoint ring on slot %d, "
		    "port %d, endpoint: %d, failed setting ring dequeue with "
		    "%d.", xd->xd_slot, xd->xd_port, epid, ret);
		mutex_enter(&xhcip->xhci_lock);
		xep->xep_state &= ~XHCI_ENDPOINT_QUIESCE;
		cv_broadcast(&xep->xep_state_cv);
		mutex_exit(&xhcip->xhci_lock);
		return (ret);
	}

	mutex_enter(&xhcip->xhci_lock);
	xhci_hcdi_pipe_flush(xhcip, xep, USB_CR_PIPE_RESET);

	/*
	 * We need to remove the periodic flag as part of resetting, as if this
	 * was used for periodic activity, it no longer is and therefore can now
	 * be used for such purposes.
	 *
	 * Notify anything waiting for us that we're done quiescing this device.
	 */
	xep->xep_state &= ~(XHCI_ENDPOINT_QUIESCE | XHCI_ENDPOINT_PERIODIC);
	cv_broadcast(&xep->xep_state_cv);
	mutex_exit(&xhcip->xhci_lock);

	return (USB_SUCCESS);
}

/*
 * We're asked to reset or change the data toggle, which is used in a few cases.
 * However, there doesn't seem to be a good way to do this in xHCI as the data
 * toggle isn't exposed. It seems that dropping a reset endpoint would
 * theoretically do this; however, that can only be used when in the HALTED
 * state. As such, for now we just return.
 */
/* ARGSUSED */
void
xhci_hcdi_pipe_reset_data_toggle(usba_pipe_handle_data_t *pipe_handle)
{
}

/*
 * We need to convert the USB request to an 8-byte little endian value. If we
 * didn't have to think about big endian systems, this would be fine.
 * Unfortunately, with them, this is a bit confusing. The problem is that if you
 * think of this as a struct layout, the order that we or things together
 * represents their byte layout. e.g. ctrl_bRequest is at offset 1 in the SETUP
 * STAGE trb. However, when it becomes a part of a 64-bit big endian number, if
 * ends up at byte 7, where as it needs to be at one. Hence why we do a final
 * LE_64 at the end of this, to convert this into the byte order that it's
 * expected to be in.
 */
static uint64_t
xhci_hcdi_ctrl_req_to_trb(usb_ctrl_req_t *ucrp)
{
	uint64_t ret = ucrp->ctrl_bmRequestType |
	    (ucrp->ctrl_bRequest << 8) |
	    ((uint64_t)LE_16(ucrp->ctrl_wValue) << 16) |
	    ((uint64_t)LE_16(ucrp->ctrl_wIndex) << 32) |
	    ((uint64_t)LE_16(ucrp->ctrl_wLength) << 48);
	return (LE_64(ret));
}

/*
 * USBA calls us in order to make a specific control type request to a device,
 * potentially even the root hub. If the request is for the root hub, then we
 * need to intercept this and cons up the requested data.
 */
static int
xhci_hcdi_pipe_ctrl_xfer(usba_pipe_handle_data_t *ph, usb_ctrl_req_t *ucrp,
    usb_flags_t usb_flags)
{
	int ret, statusdir, trt;
	uint_t ep;
	xhci_device_t *xd;
	xhci_endpoint_t *xep;
	xhci_transfer_t *xt;
	boolean_t datain;

	xhci_t *xhcip = xhci_hcdi_get_xhcip(ph);

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_HC_HARDWARE_ERROR);
	}

	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		ret = xhci_root_hub_ctrl_req(xhcip, ph, ucrp);
		mutex_exit(&xhcip->xhci_lock);
		return (ret);
	}

	/*
	 * Determine the device and endpoint.
	 */
	xd = usba_hcdi_get_device_private(ph->p_usba_device);
	ep = xhci_endpoint_pipe_to_epid(ph);
	if (xd->xd_endpoints[ep] == NULL) {
		mutex_exit(&xhcip->xhci_lock);
		xhci_error(xhcip, "asked to do control transfer on slot %d, "
		    "port %d, endpoint: %d, but no endpoint structure",
		    xd->xd_slot, xd->xd_port, ep);
		return (USB_FAILURE);
	}
	xep = xd->xd_endpoints[ep];

	/*
	 * There are several types of requests that we have to handle in special
	 * ways in xHCI. If we have one of those requests, then we don't
	 * necessarily go through the normal path. These special cases are all
	 * documented in xHCI 1.1 / 4.5.4.
	 *
	 * Looking at that, you may ask why aren't SET_CONFIGURATION and SET_IF
	 * special cased here. This action is a little confusing by default. The
	 * xHCI specification requires that we may need to issue a configure
	 * endpoint command as part of this. However, the xHCI 1.1 / 4.5.4.2
	 * states that we don't actually need to if nothing in the endpoint
	 * configuration context has changed. Because nothing in it should have
	 * changed as part of this, we don't need to do anything and instead
	 * just can issue the request normally. We're also assuming in the
	 * USB_REQ_SET_IF case that if something's changing the interface, the
	 * non-default endpoint will have yet to be opened.
	 */
	if (ucrp->ctrl_bmRequestType == USB_DEV_REQ_HOST_TO_DEV &&
	    ucrp->ctrl_bRequest == USB_REQ_SET_ADDRESS) {
		/*
		 * As we've defined an explicit set-address endpoint, we should
		 * never call this function. If we get here, always fail.
		 */
		mutex_exit(&xhcip->xhci_lock);
		usba_hcdi_cb(ph, (usb_opaque_t)ucrp, USB_CR_NOT_SUPPORTED);
		return (USB_SUCCESS);
	}

	mutex_exit(&xhcip->xhci_lock);

	/*
	 * Allocate the transfer memory, etc.
	 */
	xt = xhci_transfer_alloc(xhcip, xep, ucrp->ctrl_wLength, 2, usb_flags);
	if (xt == NULL) {
		return (USB_NO_RESOURCES);
	}
	xt->xt_usba_req = (usb_opaque_t)ucrp;
	xt->xt_timeout = ucrp->ctrl_timeout;
	if (xt->xt_timeout == 0) {
		xt->xt_timeout = HCDI_DEFAULT_TIMEOUT;
	}

	if (ucrp->ctrl_wLength > 0) {
		if ((ucrp->ctrl_bmRequestType & USB_DEV_REQ_DEV_TO_HOST) != 0) {
			trt = XHCI_TRB_TRT_IN;
			datain = B_TRUE;
			statusdir = 0;
		} else {
			trt = XHCI_TRB_TRT_OUT;
			datain = B_FALSE;
			statusdir = XHCI_TRB_DIR_IN;

			xhci_transfer_copy(xt, ucrp->ctrl_data->b_rptr,
			    ucrp->ctrl_wLength, B_FALSE);
			if (xhci_transfer_sync(xhcip, xt,
			    DDI_DMA_SYNC_FORDEV) != DDI_FM_OK) {
				xhci_transfer_free(xhcip, xt);
				xhci_error(xhcip, "failed to synchronize ctrl "
				    "transfer DMA memory on endpoint %u of "
				    "device on slot %d and port %d: resetting "
				    "device", xep->xep_num, xd->xd_slot,
				    xd->xd_port);
				xhci_fm_runtime_reset(xhcip);
				return (USB_HC_HARDWARE_ERROR);
			}
		}
	} else {
		trt = 0;
		datain = B_FALSE;
		statusdir = XHCI_TRB_DIR_IN;
	}

	/*
	 * We always fill in the required setup and status TRBs ourselves;
	 * however, to minimize our knowledge about how the data has been split
	 * across multiple DMA cookies in an SGL, we leave that to the transfer
	 * logic to fill in.
	 */
	xt->xt_trbs[0].trb_addr = xhci_hcdi_ctrl_req_to_trb(ucrp);
	xt->xt_trbs[0].trb_status = LE_32(XHCI_TRB_LEN(8) | XHCI_TRB_INTR(0));
	xt->xt_trbs[0].trb_flags = LE_32(trt | XHCI_TRB_IDT |
	    XHCI_TRB_TYPE_SETUP);

	if (ucrp->ctrl_wLength > 0)
		xhci_transfer_trb_fill_data(xep, xt, 1, datain);

	xt->xt_trbs[xt->xt_ntrbs - 1].trb_addr = 0;
	xt->xt_trbs[xt->xt_ntrbs - 1].trb_status = LE_32(XHCI_TRB_INTR(0));
	xt->xt_trbs[xt->xt_ntrbs - 1].trb_flags = LE_32(XHCI_TRB_TYPE_STATUS |
	    XHCI_TRB_IOC | statusdir);

	mutex_enter(&xhcip->xhci_lock);

	/*
	 * Schedule the transfer, allocating resources in the process.
	 */
	if (xhci_endpoint_schedule(xhcip, xd, xep, xt, B_TRUE) != 0) {
		xhci_transfer_free(xhcip, xt);
		mutex_exit(&xhcip->xhci_lock);
		return (USB_NO_RESOURCES);
	}

	mutex_exit(&xhcip->xhci_lock);

	return (USB_SUCCESS);
}

/*
 * This request is trying to get the upper bound on the amount of data we're
 * willing transfer in one go. Note that this amount can be broken down into
 * multiple SGL entries, this interface doesn't particularly care about that.
 */
/* ARGSUSED */
static int
xhci_hcdi_bulk_transfer_size(usba_device_t *ud, size_t *sizep)
{
	if (sizep != NULL)
		*sizep = XHCI_MAX_TRANSFER;
	return (USB_SUCCESS);
}

/*
 * Perform a bulk transfer. This is a pretty straightforward action. We
 * basically just allocate the appropriate transfer and try to schedule it,
 * hoping there is enough space.
 */
static int
xhci_hcdi_pipe_bulk_xfer(usba_pipe_handle_data_t *ph, usb_bulk_req_t *ubrp,
    usb_flags_t usb_flags)
{
	uint_t epid;
	xhci_device_t *xd;
	xhci_endpoint_t *xep;
	xhci_transfer_t *xt;
	boolean_t datain;

	xhci_t *xhcip = xhci_hcdi_get_xhcip(ph);

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_HC_HARDWARE_ERROR);
	}

	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_NOT_SUPPORTED);
	}

	xd = usba_hcdi_get_device_private(ph->p_usba_device);
	epid = xhci_endpoint_pipe_to_epid(ph);
	if (xd->xd_endpoints[epid] == NULL) {
		mutex_exit(&xhcip->xhci_lock);
		xhci_error(xhcip, "asked to do control transfer on slot %d, "
		    "port %d, endpoint: %d, but no endpoint structure",
		    xd->xd_slot, xd->xd_port, epid);
		return (USB_FAILURE);
	}
	xep = xd->xd_endpoints[epid];
	mutex_exit(&xhcip->xhci_lock);

	if ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		datain = B_TRUE;
	} else {
		datain = B_FALSE;
	}

	xt = xhci_transfer_alloc(xhcip, xep, ubrp->bulk_len, 0, usb_flags);
	if (xt == NULL) {
		return (USB_NO_RESOURCES);
	}
	xt->xt_usba_req = (usb_opaque_t)ubrp;
	xt->xt_timeout = ubrp->bulk_timeout;
	if (xt->xt_timeout == 0) {
		xt->xt_timeout = HCDI_DEFAULT_TIMEOUT;
	}

	if (ubrp->bulk_len > 0 && datain == B_FALSE) {
		xhci_transfer_copy(xt, ubrp->bulk_data->b_rptr, ubrp->bulk_len,
		    B_FALSE);
		if (xhci_transfer_sync(xhcip, xt, DDI_DMA_SYNC_FORDEV) !=
		    DDI_FM_OK) {
			xhci_transfer_free(xhcip, xt);
			xhci_error(xhcip, "failed to synchronize bulk "
			    "transfer DMA memory on endpoint %u of "
			    "device on slot %d and port %d: resetting "
			    "device", xep->xep_num, xd->xd_slot,
			    xd->xd_port);
			xhci_fm_runtime_reset(xhcip);
			return (USB_HC_HARDWARE_ERROR);
		}
	}

	xhci_transfer_trb_fill_data(xep, xt, 0, datain);
	mutex_enter(&xhcip->xhci_lock);
	if (xhci_endpoint_schedule(xhcip, xd, xep, xt, B_TRUE) != 0) {
		xhci_transfer_free(xhcip, xt);
		mutex_exit(&xhcip->xhci_lock);
		return (USB_NO_RESOURCES);
	}
	mutex_exit(&xhcip->xhci_lock);

	return (USB_SUCCESS);
}

static void
xhci_hcdi_isoc_transfer_fill(xhci_device_t *xd, xhci_endpoint_t *xep,
    xhci_transfer_t *xt, usb_isoc_req_t *usrp)
{
	int i;
	uintptr_t buf;

	buf = xt->xt_buffer.xdb_cookies[0].dmac_laddress;
	for (i = 0; i < usrp->isoc_pkts_count; i++) {
		int flags;
		uint_t tbc, tlbpc;

		ushort_t len = usrp->isoc_pkt_descr[i].isoc_pkt_length;
		xhci_trb_t *trb = &xt->xt_trbs[i];

		trb->trb_addr = LE_64(buf);

		/*
		 * Beacuse we know that a single frame can have all of its data
		 * in a single instance, we know that we don't neeed to do
		 * anything special here.
		 */
		trb->trb_status = LE_32(XHCI_TRB_LEN(len) | XHCI_TRB_TDREM(0) |
		    XHCI_TRB_INTR(0));

		/*
		 * Always enable SIA to start the frame ASAP. We also always
		 * enable an interrupt on a short packet. If this is the last
		 * trb, then we will set IOC.
		 */
		flags = XHCI_TRB_SIA | XHCI_TRB_ISP | XHCI_TRB_SET_FRAME(0);
		flags |= XHCI_TRB_TYPE_ISOCH;

		if (i + 1 == usrp->isoc_pkts_count)
			flags |= XHCI_TRB_IOC;

		/*
		 * Now we need to calculate the TBC and the TLBPC.
		 */
		xhci_transfer_calculate_isoc(xd, xep, len, &tbc, &tlbpc);
		flags |= XHCI_TRB_SET_TBC(tbc);
		flags |= XHCI_TRB_SET_TLBPC(tlbpc);

		trb->trb_flags = LE_32(flags);
		buf += len;

		/*
		 * Go through and copy the required data to our local copy of
		 * the isoc descriptor. By default, we assume that all data will
		 * be copied and the status set to OK. This mirrors the fact
		 * that we won't get a notification unless there's been an
		 * error or short packet transfer.
		 */
		xt->xt_isoc[i].isoc_pkt_length = len;
		xt->xt_isoc[i].isoc_pkt_actual_length = len;
		xt->xt_isoc[i].isoc_pkt_status = USB_CR_OK;
	}
}

/*
 * Initialize periodic IN requests (both interrupt and isochronous)
 */
static int
xhci_hcdi_periodic_init(xhci_t *xhcip, usba_pipe_handle_data_t *ph,
    usb_opaque_t usb_req, size_t len, int usb_flags)
{
	int i, ret;
	uint_t epid;
	xhci_device_t *xd;
	xhci_endpoint_t *xep;
	xhci_pipe_t *xp;
	xhci_periodic_pipe_t *xpp;

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_HC_HARDWARE_ERROR);
	}

	xd = usba_hcdi_get_device_private(ph->p_usba_device);
	epid = xhci_endpoint_pipe_to_epid(ph);
	if (xd->xd_endpoints[epid] == NULL) {
		xhci_error(xhcip, "asked to do periodic transfer on slot %d, "
		    "port %d, endpoint: %d, but no endpoint structure",
		    xd->xd_slot, xd->xd_port, epid);
		mutex_exit(&xhcip->xhci_lock);
		return (USB_FAILURE);
	}
	xep = xd->xd_endpoints[epid];
	xp = (xhci_pipe_t *)ph->p_hcd_private;
	if (xp == NULL) {
		xhci_error(xhcip, "asked to do periodic transfer on slot %d, "
		    "port %d, endpoint: %d, but no pipe structure",
		    xd->xd_slot, xd->xd_port, epid);
		mutex_exit(&xhcip->xhci_lock);
		return (USB_FAILURE);
	}
	xpp = &xp->xp_periodic;

	/*
	 * Only allow a single polling request at any given time.
	 */
	if (xpp->xpp_usb_req != NULL) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_BUSY);
	}

	/*
	 * We keep allocations around in case we restart polling, which most
	 * devices do (not really caring about a lost event). However, we don't
	 * support a driver changing that size on us, which it probably won't.
	 * If we stumble across driver that does, then this will need to become
	 * a lot more complicated.
	 */
	if (xpp->xpp_tsize > 0 && xpp->xpp_tsize < len) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_INVALID_REQUEST);
	}

	if (xpp->xpp_tsize == 0) {
		int ntrbs;
		int ntransfers;

		/*
		 * What we allocate varies based on whether or not this is an
		 * isochronous or interrupt IN periodic.
		 */
		if (xep->xep_type == USB_EP_ATTR_INTR) {
			ntrbs = 0;
			ntransfers = XHCI_INTR_IN_NTRANSFERS;
		} else {
			usb_isoc_req_t *usrp;
			ASSERT(xep->xep_type == USB_EP_ATTR_ISOCH);

			usrp = (usb_isoc_req_t *)usb_req;
			ntrbs = usrp->isoc_pkts_count;
			ntransfers = XHCI_ISOC_IN_NTRANSFERS;
		}

		xpp->xpp_tsize = len;
		xpp->xpp_ntransfers = ntransfers;

		for (i = 0; i < xpp->xpp_ntransfers; i++) {
			xhci_transfer_t *xt = xhci_transfer_alloc(xhcip, xep,
			    len, ntrbs, usb_flags);
			if (xt == NULL) {
				xhci_hcdi_periodic_free(xhcip, xp);
				mutex_exit(&xhcip->xhci_lock);
				return (USB_NO_RESOURCES);
			}

			if (xep->xep_type == USB_EP_ATTR_INTR) {
				xhci_transfer_trb_fill_data(xep, xt, 0, B_TRUE);
			} else {
				usb_isoc_req_t *usrp;
				usrp = (usb_isoc_req_t *)usb_req;
				xhci_hcdi_isoc_transfer_fill(xd, xep, xt, usrp);
				xt->xt_data_tohost = B_TRUE;
			}
			xpp->xpp_transfers[i] = xt;
		}
	}

	/*
	 * Mark the endpoint as periodic so we don't have timeouts at play.
	 */
	xep->xep_state |= XHCI_ENDPOINT_PERIODIC;

	/*
	 * Now that we've allocated everything, go ahead and schedule them and
	 * kick off the ring.
	 */
	for (i = 0; i < xpp->xpp_ntransfers; i++) {
		int ret;
		ret = xhci_endpoint_schedule(xhcip, xd, xep,
		    xpp->xpp_transfers[i], B_FALSE);
		if (ret != 0) {
			(void) xhci_ring_reset(xhcip, &xep->xep_ring);
			xep->xep_state &= ~XHCI_ENDPOINT_PERIODIC;
			mutex_exit(&xhcip->xhci_lock);
			return (ret);
		}
	}

	/*
	 * Don't worry about freeing memory, it'll be done when the endpoint
	 * closes and the whole system is reset.
	 */
	xpp->xpp_usb_req = usb_req;
	xpp->xpp_poll_state = XHCI_PERIODIC_POLL_ACTIVE;

	ret = xhci_endpoint_ring(xhcip, xd, xep);
	mutex_exit(&xhcip->xhci_lock);
	return (ret);
}

static int
xhci_hcdi_intr_oneshot(xhci_t *xhcip, usba_pipe_handle_data_t *ph,
    usb_intr_req_t *uirp, usb_flags_t usb_flags)
{
	uint_t epid;
	xhci_device_t *xd;
	xhci_endpoint_t *xep;
	xhci_transfer_t *xt;
	boolean_t datain;
	mblk_t *mp = NULL;

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_HC_HARDWARE_ERROR);
	}

	xd = usba_hcdi_get_device_private(ph->p_usba_device);
	epid = xhci_endpoint_pipe_to_epid(ph);
	if (xd->xd_endpoints[epid] == NULL) {
		xhci_error(xhcip, "asked to do interrupt transfer on slot %d, "
		    "port %d, endpoint: %d, but no endpoint structure",
		    xd->xd_slot, xd->xd_port, epid);
		mutex_exit(&xhcip->xhci_lock);
		return (USB_FAILURE);
	}
	xep = xd->xd_endpoints[epid];

	mutex_exit(&xhcip->xhci_lock);

	if ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		datain = B_TRUE;
	} else {
		datain = B_FALSE;
	}

	xt = xhci_transfer_alloc(xhcip, xep, uirp->intr_len, 0, usb_flags);
	if (xt == NULL) {
		return (USB_NO_RESOURCES);
	}

	xt->xt_usba_req = (usb_opaque_t)uirp;
	xt->xt_timeout = uirp->intr_timeout;
	if (xt->xt_timeout == 0) {
		xt->xt_timeout = HCDI_DEFAULT_TIMEOUT;
	}

	/*
	 * Unlike other request types, USB Interrupt-IN requests aren't required
	 * to have allocated the message block for data. If they haven't, we
	 * take care of that now.
	 */
	if (uirp->intr_len > 0 && datain == B_TRUE && uirp->intr_data == NULL) {
		if (usb_flags & USB_FLAGS_SLEEP) {
			mp = allocb_wait(uirp->intr_len, BPRI_LO, STR_NOSIG,
			    NULL);
		} else {
			mp = allocb(uirp->intr_len, 0);
		}
		if (mp == NULL) {
			xhci_transfer_free(xhcip, xt);
			mutex_exit(&xhcip->xhci_lock);
			return (USB_NO_RESOURCES);
		}
		uirp->intr_data = mp;
	}

	if (uirp->intr_len > 0 && datain == B_FALSE) {
		xhci_transfer_copy(xt, uirp->intr_data->b_rptr, uirp->intr_len,
		    B_FALSE);
		if (xhci_transfer_sync(xhcip, xt, DDI_DMA_SYNC_FORDEV) !=
		    DDI_FM_OK) {
			xhci_transfer_free(xhcip, xt);
			xhci_error(xhcip, "failed to synchronize interrupt "
			    "transfer DMA memory on endpoint %u of "
			    "device on slot %d and port %d: resetting "
			    "device", xep->xep_num, xd->xd_slot,
			    xd->xd_port);
			xhci_fm_runtime_reset(xhcip);
			return (USB_HC_HARDWARE_ERROR);
		}
	}

	xhci_transfer_trb_fill_data(xep, xt, 0, datain);
	mutex_enter(&xhcip->xhci_lock);
	if (xhci_endpoint_schedule(xhcip, xd, xep, xt, B_TRUE) != 0) {
		if (mp != NULL) {
			uirp->intr_data = NULL;
			freemsg(mp);
		}
		xhci_transfer_free(xhcip, xt);
		mutex_exit(&xhcip->xhci_lock);
		return (USB_NO_RESOURCES);
	}
	mutex_exit(&xhcip->xhci_lock);

	return (USB_SUCCESS);
}

/*
 * We've been asked to perform an interrupt transfer. When this is an interrupt
 * IN endpoint, that means that the hcd is being asked to start polling on the
 * endpoint. When the endpoint is the root hub, it effectively becomes synthetic
 * polling.
 *
 * When we have an interrupt out endpoint, then this is just a single simple
 * interrupt request that we send out and there isn't much special to do beyond
 * the normal activity.
 */
static int
xhci_hcdi_pipe_intr_xfer(usba_pipe_handle_data_t *ph, usb_intr_req_t *uirp,
    usb_flags_t usb_flags)
{
	int ret;
	xhci_t *xhcip = xhci_hcdi_get_xhcip(ph);

	if ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
			ret = xhci_root_hub_intr_root_enable(xhcip, ph, uirp);
		} else if (uirp->intr_attributes & USB_ATTRS_ONE_XFER) {
			ret = xhci_hcdi_intr_oneshot(xhcip, ph, uirp,
			    usb_flags);
		} else {
			ret = xhci_hcdi_periodic_init(xhcip, ph,
			    (usb_opaque_t)uirp, uirp->intr_len, usb_flags);
		}
	} else {
		if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
			return (USB_NOT_SUPPORTED);
		}
		ret = xhci_hcdi_intr_oneshot(xhcip, ph, uirp, usb_flags);
	}

	return (ret);
}

/* ARGSUSED */
static int
xhci_hcdi_pipe_stop_intr_polling(usba_pipe_handle_data_t *ph,
    usb_flags_t usb_flags)
{
	return (xhci_hcdi_pipe_poll_fini(ph, B_FALSE));
}

static int
xhci_hcdi_isoc_periodic(xhci_t *xhcip, usba_pipe_handle_data_t *ph,
    usb_isoc_req_t *usrp, usb_flags_t usb_flags)
{
	int i;
	size_t count;

	count = 0;
	for (i = 0; i < usrp->isoc_pkts_count; i++) {
		count += usrp->isoc_pkt_descr[i].isoc_pkt_length;
	}

	return (xhci_hcdi_periodic_init(xhcip, ph, (usb_opaque_t)usrp, count,
	    usb_flags));
}

/*
 * This is used to create an isochronous request to send data out to the device.
 * This is a single one shot request, it is not something that we'll have to
 * repeat over and over.
 */
static int
xhci_hcdi_isoc_oneshot(xhci_t *xhcip, usba_pipe_handle_data_t *ph,
    usb_isoc_req_t *usrp, usb_flags_t usb_flags)
{
	int i, ret;
	uint_t epid;
	size_t count, mblen;
	xhci_device_t *xd;
	xhci_endpoint_t *xep;
	xhci_transfer_t *xt;

	count = 0;
	for (i = 0; i < usrp->isoc_pkts_count; i++) {
		count += usrp->isoc_pkt_descr[i].isoc_pkt_length;
	}
	mblen = MBLKL(usrp->isoc_data);

	if (count != mblen) {
		return (USB_INVALID_ARGS);
	}

	mutex_enter(&xhcip->xhci_lock);
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_HC_HARDWARE_ERROR);
	}

	xd = usba_hcdi_get_device_private(ph->p_usba_device);
	epid = xhci_endpoint_pipe_to_epid(ph);
	if (xd->xd_endpoints[epid] == NULL) {
		xhci_error(xhcip, "asked to do isochronous transfer on slot "
		    "%d, port %d, endpoint: %d, but no endpoint structure",
		    xd->xd_slot, xd->xd_port, epid);
		mutex_exit(&xhcip->xhci_lock);
		return (USB_FAILURE);
	}
	xep = xd->xd_endpoints[epid];
	mutex_exit(&xhcip->xhci_lock);

	xt = xhci_transfer_alloc(xhcip, xep, mblen, usrp->isoc_pkts_count,
	    usb_flags);
	if (xt == NULL) {
		return (USB_NO_RESOURCES);
	}
	xt->xt_usba_req = (usb_opaque_t)usrp;

	/*
	 * USBA doesn't provide any real way for a timeout to be defined for an
	 * isochronous event. However, since we technically aren't a periodic
	 * endpoint, go ahead and always set the default timeout. It's better
	 * than nothing.
	 */
	xt->xt_timeout = HCDI_DEFAULT_TIMEOUT;

	xhci_transfer_copy(xt, usrp->isoc_data->b_rptr, mblen, B_FALSE);
	if (xhci_transfer_sync(xhcip, xt, DDI_DMA_SYNC_FORDEV) != DDI_FM_OK) {
		xhci_transfer_free(xhcip, xt);
		xhci_error(xhcip, "failed to synchronize isochronous "
		    "transfer DMA memory on endpoint %u of "
		    "device on slot %d and port %d: resetting "
		    "device", xep->xep_num, xd->xd_slot,
		    xd->xd_port);
		xhci_fm_runtime_reset(xhcip);
		return (USB_HC_HARDWARE_ERROR);
	}

	/*
	 * Fill in the ISOC data. Note, that we always use ASAP scheduling and
	 * we don't support specifying the frame at this time, for better or
	 * worse.
	 */
	xhci_hcdi_isoc_transfer_fill(xd, xep, xt, usrp);

	mutex_enter(&xhcip->xhci_lock);
	ret = xhci_endpoint_schedule(xhcip, xd, xep, xt, B_TRUE);
	mutex_exit(&xhcip->xhci_lock);

	return (ret);
}

static int
xhci_hcdi_pipe_isoc_xfer(usba_pipe_handle_data_t *ph, usb_isoc_req_t *usrp,
    usb_flags_t usb_flags)
{
	int ret;
	xhci_t *xhcip;

	xhcip = xhci_hcdi_get_xhcip(ph);

	/*
	 * We don't support isochronous transactions on the root hub at all.
	 * Always fail them if for some reason we end up here.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {
		return (USB_NOT_SUPPORTED);
	}

	/*
	 * We do not support being asked to set the frame ID at this time. We
	 * require that everything specify the attribute
	 * USB_ATTRS_ISOC_XFER_ASAP.
	 */
	if (!(usrp->isoc_attributes & USB_ATTRS_ISOC_XFER_ASAP)) {
		return (USB_NOT_SUPPORTED);
	}

	if ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		/*
		 * Note, there is no such thing as a non-periodic isochronous
		 * incoming transfer.
		 */
		ret = xhci_hcdi_isoc_periodic(xhcip, ph, usrp, usb_flags);
	} else {
		ret = xhci_hcdi_isoc_oneshot(xhcip, ph, usrp, usb_flags);
	}

	return (ret);
}

/* ARGSUSED */
static int
xhci_hcdi_pipe_stop_isoc_polling(usba_pipe_handle_data_t *ph,
    usb_flags_t usb_flags)
{
	return (xhci_hcdi_pipe_poll_fini(ph, B_FALSE));
}

/*
 * This is asking us for the current frame number. The USBA expects this to
 * actually be a bit of a fiction, as it tries to maintain a frame number well
 * beyond what the hardware actually contains in its registers. Hardware
 * basically has a 14-bit counter, whereas we need to have a constant amount of
 * milliseconds.
 *
 * Today, no client drivers actually use this API and everyone specifies the
 * attribute to say that we should schedule things ASAP. So until we have some
 * real device that want this functionality, we're going to fail.
 */
/* ARGSUSED */
static int
xhci_hcdi_get_current_frame_number(usba_device_t *usba_device,
    usb_frame_number_t *frame_number)
{
	return (USB_FAILURE);
}

/*
 * See the comments around the XHCI_ISOC_MAX_TRB macro for more information.
 */
/* ARGSUSED */
static int
xhci_hcdi_get_max_isoc_pkts(usba_device_t *usba_device,
    uint_t *max_isoc_pkts_per_request)
{
	*max_isoc_pkts_per_request = XHCI_ISOC_MAX_TRB;
	return (USB_SUCCESS);
}

/*
 * The next series of routines is used for both the OBP console and general USB
 * console polled I/O. In general, we opt not to support any of that at this
 * time in xHCI. As we have the need of that, we can start plumbing that
 * through.
 */
/* ARGSUSED */
static int
xhci_hcdi_console_input_init(usba_pipe_handle_data_t *pipe_handle,
    uchar_t **obp_buf, usb_console_info_impl_t *console_input_info)
{
	return (USB_NOT_SUPPORTED);
}

/* ARGSUSED */
static int
xhci_hcdi_console_input_fini(usb_console_info_impl_t *console_input_info)
{
	return (USB_NOT_SUPPORTED);
}

/* ARGSUSED */
static int
xhci_hcdi_console_input_enter(usb_console_info_impl_t *console_input_info)
{
	return (USB_NOT_SUPPORTED);
}

/* ARGSUSED */
static int
xhci_hcdi_console_read(usb_console_info_impl_t *console_input_info,
    uint_t *num_characters)
{
	return (USB_NOT_SUPPORTED);
}

/* ARGSUSED */
static int
xhci_hcdi_console_input_exit(usb_console_info_impl_t *console_input_info)
{
	return (USB_NOT_SUPPORTED);
}

/* ARGSUSED */
static int
xhci_hcdi_console_output_init(usba_pipe_handle_data_t *pipe_handle,
    usb_console_info_impl_t *console_output_info)
{
	return (USB_NOT_SUPPORTED);
}

/* ARGSUSED */
static int
xhci_hcdi_console_output_fini(usb_console_info_impl_t *console_output_info)
{
	return (USB_NOT_SUPPORTED);
}

/* ARGSUSED */
static int
xhci_hcdi_console_output_enter(usb_console_info_impl_t *console_output_info)
{
	return (USB_NOT_SUPPORTED);
}

/* ARGSUSED */
static int
xhci_hcdi_console_write(usb_console_info_impl_t	*console_output_info,
    uchar_t *buf, uint_t num_characters, uint_t *num_characters_written)
{
	return (USB_NOT_SUPPORTED);
}

/* ARGSUSED */
static int
xhci_hcdi_console_output_exit(usb_console_info_impl_t *console_output_info)
{
	return (USB_NOT_SUPPORTED);
}

/*
 * VERSION 2 ops and helpers
 */

static void
xhci_hcdi_device_free(xhci_device_t *xd)
{
	xhci_dma_free(&xd->xd_ictx);
	xhci_dma_free(&xd->xd_octx);
	mutex_destroy(&xd->xd_imtx);
	kmem_free(xd, sizeof (xhci_device_t));
}

/*
 * Calculate the device's route string. In USB 3.0 the route string is a 20-bit
 * number. Each four bits represent a port number attached to a deeper hub.
 * Particularly it represents the port on that current hub that you need to go
 * down to reach the next device. Bits 0-3 represent the first *external* hub.
 * So a device connected to a root hub has a route string of zero. Imagine the
 * following set of devices:
 *
 *               . port 2      . port 5
 *               .             .
 *  +----------+ .  +--------+ .  +-------+
 *  | root hub |-*->| hub 1  |-*->| hub 2 |
 *  +----------+    +--------+    +-------+
 *       * . port 12    * . port 8    * . port 1
 *       v              v             v
 *   +-------+      +-------+     +-------+
 *   | dev a |      | dev b |     | dev c |
 *   +-------+      +-------+     +-------+
 *
 * So, based on the above diagram, device a should have a route string of 0,
 * because it's directly connected to the root port. Device b would simply have
 * a route string of 8. This is because it travels through one non-root hub, hub
 * 1, and it does so on port 8. The root ports basically don't matter. Device c
 * would then have a route string of 0x15, as it's first traversing through hub
 * 1 on port 2 and then hub 2 on port 5.
 *
 * Finally, it's worth mentioning that because it's a four bit field, if for
 * some reason a device has more than 15 ports, we just treat the value as 15.
 *
 * Note, as part of this, we also grab what port on the root hub this whole
 * chain is on, as we're required to store that information in the slot context.
 */
static void
xhci_hcdi_device_route(usba_device_t *ud, uint32_t *routep, uint32_t *root_port)
{
	uint32_t route = 0;
	usba_device_t *hub = ud->usb_parent_hub;
	usba_device_t *port_dev = ud;

	ASSERT(hub != NULL);

	/*
	 * Iterate over every hub, updating the route as we go. When we
	 * encounter a hub without a parent, then we're at the root hub. At
	 * which point, the port we want is on port_dev (the child of hub).
	 */
	while (hub->usb_parent_hub != NULL) {
		uint32_t p;

		p = port_dev->usb_port;
		if (p > 15)
			p = 15;
		route <<= 4;
		route |= p & 0xf;
		port_dev = hub;
		hub = hub->usb_parent_hub;
	}

	ASSERT(port_dev->usb_parent_hub == hub);
	*root_port = port_dev->usb_port;
	*routep = XHCI_ROUTE_MASK(route);
}

/*
 * If a low or full speed device is behind a high-speed device that is not a
 * root hub, then we must include the port and slot of that device. USBA already
 * stores this device in the usb_hs_hub_usba_dev member.
 */
static uint32_t
xhci_hcdi_device_tt(usba_device_t *ud)
{
	uint32_t ret;
	xhci_device_t *xd;

	if (ud->usb_port_status >= USBA_HIGH_SPEED_DEV)
		return (0);

	if (ud->usb_hs_hub_usba_dev == NULL)
		return (0);

	ASSERT(ud->usb_hs_hub_usba_dev != NULL);
	ASSERT(ud->usb_hs_hub_usba_dev->usb_parent_hub != NULL);
	xd = usba_hcdi_get_device_private(ud->usb_hs_hub_usba_dev);
	ASSERT(xd != NULL);

	ret = XHCI_SCTX_SET_TT_HUB_SID(xd->xd_slot);
	ret |= XHCI_SCTX_SET_TT_PORT_NUM(ud->usb_hs_hub_usba_dev->usb_port);

	return (ret);
}

/*
 * Initialize a new device. This allocates a device slot from the controller,
 * which tranfers it to our control.
 */
static int
xhci_hcdi_device_init(usba_device_t *ud, usb_port_t port, void **hcdpp)
{
	int ret, i;
	xhci_device_t *xd;
	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;
	xhci_t *xhcip = xhci_hcdi_get_xhcip_from_dev(ud);
	size_t isize, osize, incr;
	uint32_t route, rp, info, info2, tt;

	xd = kmem_zalloc(sizeof (xhci_device_t), KM_SLEEP);
	xd->xd_port = port;
	xd->xd_usbdev = ud;
	mutex_init(&xd->xd_imtx, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)xhcip->xhci_intr_pri);

	/*
	 * The size of the context structures is based upon the presence of the
	 * context flag which determines whether we have a 32-byte or 64-byte
	 * context. Note that the input context always has to account for the
	 * entire size of the xhci_input_contex_t, which is 32-bytes by default.
	 */
	if (xhcip->xhci_caps.xcap_flags & XCAP_CSZ) {
		incr = 64;
		osize = XHCI_DEVICE_CONTEXT_64;
		isize = XHCI_DEVICE_CONTEXT_64 + incr;
	} else {
		incr = 32;
		osize = XHCI_DEVICE_CONTEXT_32;
		isize = XHCI_DEVICE_CONTEXT_32 + incr;
	}

	xhci_dma_acc_attr(xhcip, &acc);
	xhci_dma_dma_attr(xhcip, &attr);
	if (xhci_dma_alloc(xhcip, &xd->xd_ictx, &attr, &acc, B_TRUE,
	    isize, B_FALSE) == B_FALSE) {
		xhci_hcdi_device_free(xd);
		return (USB_NO_RESOURCES);
	}

	xd->xd_input = (xhci_input_context_t *)xd->xd_ictx.xdb_va;
	xd->xd_slotin = (xhci_slot_context_t *)(xd->xd_ictx.xdb_va + incr);
	for (i = 0; i < XHCI_NUM_ENDPOINTS; i++) {
		xd->xd_endin[i] =
		    (xhci_endpoint_context_t *)(xd->xd_ictx.xdb_va +
		    (i + 2) * incr);
	}

	if (xhci_dma_alloc(xhcip, &xd->xd_octx, &attr, &acc, B_TRUE,
	    osize, B_FALSE) == B_FALSE) {
		xhci_hcdi_device_free(xd);
		return (USB_NO_RESOURCES);
	}
	xd->xd_slotout = (xhci_slot_context_t *)xd->xd_octx.xdb_va;
	for (i = 0; i < XHCI_NUM_ENDPOINTS; i++) {
		xd->xd_endout[i] =
		    (xhci_endpoint_context_t *)(xd->xd_octx.xdb_va +
		    (i + 1) * incr);
	}

	ret = xhci_command_enable_slot(xhcip, &xd->xd_slot);
	if (ret != USB_SUCCESS) {
		xhci_hcdi_device_free(xd);
		return (ret);
	}

	/*
	 * These are the default slot context and the endpoint zero context that
	 * we're enabling. See 4.3.3.
	 */
	xd->xd_input->xic_add_flags = LE_32(XHCI_INCTX_MASK_DCI(0) |
	    XHCI_INCTX_MASK_DCI(1));

	/*
	 * Note, we never need to set the MTT bit as illumos never enables the
	 * alternate MTT interface.
	 */
	xhci_hcdi_device_route(ud, &route, &rp);
	info = XHCI_SCTX_SET_ROUTE(route) | XHCI_SCTX_SET_DCI(1);
	switch (ud->usb_port_status) {
	case USBA_LOW_SPEED_DEV:
		info |= XHCI_SCTX_SET_SPEED(XHCI_SPEED_LOW);
		break;
	case USBA_HIGH_SPEED_DEV:
		info |= XHCI_SCTX_SET_SPEED(XHCI_SPEED_HIGH);
		break;
	case USBA_FULL_SPEED_DEV:
		info |= XHCI_SCTX_SET_SPEED(XHCI_SPEED_FULL);
		break;
	case USBA_SUPER_SPEED_DEV:
	default:
		info |= XHCI_SCTX_SET_SPEED(XHCI_SPEED_SUPER);
		break;
	}
	info2 = XHCI_SCTX_SET_RHPORT(rp);
	tt = XHCI_SCTX_SET_IRQ_TARGET(0);
	tt |= xhci_hcdi_device_tt(ud);

	xd->xd_slotin->xsc_info = LE_32(info);
	xd->xd_slotin->xsc_info2 = LE_32(info2);
	xd->xd_slotin->xsc_tt = LE_32(tt);

	if ((ret = xhci_endpoint_init(xhcip, xd, NULL)) != 0) {
		(void) xhci_command_disable_slot(xhcip, xd->xd_slot);
		xhci_hcdi_device_free(xd);
		return (USB_HC_HARDWARE_ERROR);
	}

	if (xhci_context_slot_output_init(xhcip, xd) != B_TRUE) {
		(void) xhci_command_disable_slot(xhcip, xd->xd_slot);
		xhci_endpoint_fini(xd, 0);
		xhci_hcdi_device_free(xd);
		return (USB_HC_HARDWARE_ERROR);
	}

	if ((ret = xhci_command_set_address(xhcip, xd, B_TRUE)) != 0) {
		(void) xhci_command_disable_slot(xhcip, xd->xd_slot);
		xhci_context_slot_output_fini(xhcip, xd);
		xhci_endpoint_fini(xd, 0);
		xhci_hcdi_device_free(xd);
		return (ret);
	}

	mutex_enter(&xhcip->xhci_lock);
	list_insert_tail(&xhcip->xhci_usba.xa_devices, xd);
	mutex_exit(&xhcip->xhci_lock);

	*hcdpp = xd;
	return (ret);
}

/*
 * We're tearing down a device now. That means that the only endpoint context
 * that's still valid would be endpoint zero.
 */
static void
xhci_hcdi_device_fini(usba_device_t *ud, void *hcdp)
{
	int ret;
	xhci_endpoint_t *xep;
	xhci_device_t *xd;
	xhci_t *xhcip;

	/*
	 * Right now, it's theoretically possible that USBA may try and call
	 * us here even if we hadn't successfully finished the device_init()
	 * endpoint. We should probably modify the USBA to make sure that this
	 * can't happen.
	 */
	if (hcdp == NULL)
		return;

	xd = hcdp;
	xhcip = xhci_hcdi_get_xhcip_from_dev(ud);

	/*
	 * Make sure we have no timeout running on the default endpoint still.
	 */
	xep = xd->xd_endpoints[XHCI_DEFAULT_ENDPOINT];
	mutex_enter(&xhcip->xhci_lock);
	xep->xep_state |= XHCI_ENDPOINT_TEARDOWN;
	mutex_exit(&xhcip->xhci_lock);
	(void) untimeout(xep->xep_timeout);

	/*
	 * Go ahead and disable the slot. There's no reason to do anything
	 * special about the default endpoint as it will be disabled as a part
	 * of the slot disabling. However, if this all fails, we'll leave this
	 * sitting here in a failed state, eating up a device slot. It is
	 * unlikely this will occur.
	 */
	ret = xhci_command_disable_slot(xhcip, xd->xd_slot);
	if (ret != USB_SUCCESS) {
		xhci_error(xhcip, "failed to disable slot %d: %d",
		    xd->xd_slot, ret);
		return;
	}

	xhci_context_slot_output_fini(xhcip, xd);
	xhci_endpoint_fini(xd, XHCI_DEFAULT_ENDPOINT);

	mutex_enter(&xhcip->xhci_lock);
	list_remove(&xhcip->xhci_usba.xa_devices, xd);
	mutex_exit(&xhcip->xhci_lock);

	xhci_hcdi_device_free(xd);
}

/*
 * Synchronously attempt to set the device address. For xHCI this involves it
 * deciding what address to use.
 */
static int
xhci_hcdi_device_address(usba_device_t *ud)
{
	int ret;
	xhci_t *xhcip = xhci_hcdi_get_xhcip_from_dev(ud);
	xhci_device_t *xd = usba_hcdi_get_device_private(ud);
	xhci_endpoint_t *xep;

	mutex_enter(&xhcip->xhci_lock);

	/*
	 * This device may already be addressed from the perspective of the xhci
	 * controller. For example, the device this represents may have been
	 * unconfigured, which does not actually remove the slot or other
	 * information, merely tears down all the active use of it and the child
	 * driver. In such cases, if we're already addressed, just return
	 * success. The actual USB address is a fiction for USBA anyways.
	 */
	if (xd->xd_addressed == B_TRUE) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_SUCCESS);
	}

	ASSERT(xd->xd_addressed == B_FALSE);
	xd->xd_addressed = B_TRUE;
	VERIFY3P(xd->xd_endpoints[XHCI_DEFAULT_ENDPOINT], !=, NULL);
	xep = xd->xd_endpoints[XHCI_DEFAULT_ENDPOINT];
	mutex_exit(&xhcip->xhci_lock);

	if ((ret = xhci_endpoint_setup_default_context(xhcip, xd, xep)) != 0) {
		ASSERT(ret == EIO);
		return (USB_HC_HARDWARE_ERROR);
	}

	ret = xhci_command_set_address(xhcip, xd, B_FALSE);

	if (ret != USB_SUCCESS) {
		mutex_enter(&xhcip->xhci_lock);
		xd->xd_addressed = B_FALSE;
		mutex_exit(&xhcip->xhci_lock);
	}

	return (ret);
}

/*
 * This is called relatively early on in a hub's life time. At this point, it's
 * descriptors have all been pulled and the default control pipe is still open.
 * What we need to do is go through and update the slot context to indicate that
 * this is a hub, otherwise, the controller will never let us speak to
 * downstream ports.
 */
static int
xhci_hcdi_hub_update(usba_device_t *ud, uint8_t nports, uint8_t tt)
{
	int ret;
	xhci_t *xhcip = xhci_hcdi_get_xhcip_from_dev(ud);
	xhci_device_t *xd = usba_hcdi_get_device_private(ud);

	if (xd == NULL)
		return (USB_FAILURE);

	if (ud->usb_hubdi == NULL) {
		return (USB_FAILURE);
	}

	mutex_enter(&xd->xd_imtx);

	/*
	 * Note, that usba never sets the interface of a hub to Multi TT. Hence
	 * why we're never setting the MTT bit in xsc_info.
	 */
	xd->xd_slotin->xsc_info |= LE_32(XHCI_SCTX_SET_HUB(1));
	xd->xd_slotin->xsc_info2 |= LE_32(XHCI_SCTX_SET_NPORTS(nports));
	if (ud->usb_port_status == USBA_HIGH_SPEED_DEV)
		xd->xd_slotin->xsc_tt |= LE_32(XHCI_SCTX_SET_TT_THINK_TIME(tt));

	/*
	 * We're only updating the slot context, no endpoint contexts should be
	 * touched.
	 */
	xd->xd_input->xic_drop_flags = LE_32(0);
	xd->xd_input->xic_add_flags = LE_32(XHCI_INCTX_MASK_DCI(0));

	ret = xhci_command_evaluate_context(xhcip, xd);
	mutex_exit(&xd->xd_imtx);
	return (ret);
}

void
xhci_hcd_fini(xhci_t *xhcip)
{
	usba_hcdi_unregister(xhcip->xhci_dip);
	usba_free_hcdi_ops(xhcip->xhci_usba.xa_ops);
	list_destroy(&xhcip->xhci_usba.xa_pipes);
	list_destroy(&xhcip->xhci_usba.xa_devices);
}

int
xhci_hcd_init(xhci_t *xhcip)
{
	usba_hcdi_register_args_t hreg;
	usba_hcdi_ops_t *ops;

	ops = usba_alloc_hcdi_ops();
	VERIFY(ops != NULL);

	ops->usba_hcdi_ops_version = HCDI_OPS_VERSION;
	ops->usba_hcdi_dip = xhcip->xhci_dip;

	ops->usba_hcdi_pm_support = xhci_hcdi_pm_support;
	ops->usba_hcdi_pipe_open = xhci_hcdi_pipe_open;
	ops->usba_hcdi_pipe_close = xhci_hcdi_pipe_close;
	ops->usba_hcdi_pipe_reset = xhci_hcdi_pipe_reset;
	ops->usba_hcdi_pipe_reset_data_toggle =
	    xhci_hcdi_pipe_reset_data_toggle;
	ops->usba_hcdi_pipe_ctrl_xfer = xhci_hcdi_pipe_ctrl_xfer;
	ops->usba_hcdi_bulk_transfer_size = xhci_hcdi_bulk_transfer_size;
	ops->usba_hcdi_pipe_bulk_xfer = xhci_hcdi_pipe_bulk_xfer;
	ops->usba_hcdi_pipe_intr_xfer = xhci_hcdi_pipe_intr_xfer;
	ops->usba_hcdi_pipe_stop_intr_polling =
	    xhci_hcdi_pipe_stop_intr_polling;
	ops->usba_hcdi_pipe_isoc_xfer = xhci_hcdi_pipe_isoc_xfer;
	ops->usba_hcdi_pipe_stop_isoc_polling =
	    xhci_hcdi_pipe_stop_isoc_polling;
	ops->usba_hcdi_get_current_frame_number =
	    xhci_hcdi_get_current_frame_number;
	ops->usba_hcdi_get_max_isoc_pkts = xhci_hcdi_get_max_isoc_pkts;
	ops->usba_hcdi_console_input_init = xhci_hcdi_console_input_init;
	ops->usba_hcdi_console_input_fini = xhci_hcdi_console_input_fini;
	ops->usba_hcdi_console_input_enter = xhci_hcdi_console_input_enter;
	ops->usba_hcdi_console_read = xhci_hcdi_console_read;
	ops->usba_hcdi_console_input_exit = xhci_hcdi_console_input_exit;

	ops->usba_hcdi_console_output_init = xhci_hcdi_console_output_init;
	ops->usba_hcdi_console_output_fini = xhci_hcdi_console_output_fini;
	ops->usba_hcdi_console_output_enter = xhci_hcdi_console_output_enter;
	ops->usba_hcdi_console_write = xhci_hcdi_console_write;
	ops->usba_hcdi_console_output_exit = xhci_hcdi_console_output_exit;

	ops->usba_hcdi_device_init = xhci_hcdi_device_init;
	ops->usba_hcdi_device_fini = xhci_hcdi_device_fini;
	ops->usba_hcdi_device_address = xhci_hcdi_device_address;
	ops->usba_hcdi_hub_update = xhci_hcdi_hub_update;

	hreg.usba_hcdi_register_version = HCDI_REGISTER_VERSION;
	hreg.usba_hcdi_register_dip = xhcip->xhci_dip;
	hreg.usba_hcdi_register_ops = ops;

	/*
	 * We're required to give xhci a set of DMA attributes that it may loan
	 * out to other devices. Therefore we'll be conservative with what we
	 * end up giving it.
	 */
	xhci_dma_dma_attr(xhcip, &xhcip->xhci_usba.xa_dma_attr);
	hreg.usba_hcdi_register_dma_attr = &xhcip->xhci_usba.xa_dma_attr;

	hreg.usba_hcdi_register_iblock_cookie =
	    (ddi_iblock_cookie_t)(uintptr_t)xhcip->xhci_intr_pri;

	if (usba_hcdi_register(&hreg, 0) != DDI_SUCCESS) {
		usba_free_hcdi_ops(ops);
		return (DDI_FAILURE);
	}

	xhcip->xhci_usba.xa_ops = ops;

	list_create(&xhcip->xhci_usba.xa_devices, sizeof (xhci_device_t),
	    offsetof(xhci_device_t, xd_link));
	list_create(&xhcip->xhci_usba.xa_pipes, sizeof (xhci_pipe_t),
	    offsetof(xhci_pipe_t, xp_link));


	return (DDI_SUCCESS);
}
