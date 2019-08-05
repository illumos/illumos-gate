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
 * Copyright (c) 2018, Joyent, Inc.
 *
 * Copyright (c) 2019 by Western Digital Corporation
 */

/*
 * This next series of routines is used for USB console polled I/O.
 */

#include <sys/usb/hcd/xhci/xhci.h>

#include <sys/cmn_err.h>

static void xhci_polled_panic(xhci_polled_t *xhci_polledp, const char *format,
    ...) __KVPRINTFLIKE(2) __NORETURN;

static void
xhci_polled_panic(xhci_polled_t *xhci_polledp, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vdev_err(xhci_polledp->xhci_polled_xhci->xhci_dip, CE_PANIC, format,
	    ap);

	/*
	 * We will not reach this call. However the compiler doesn't know
	 * that vdev_err(..., CE_PANIC, ...) will not return. So this call
	 * convinces it that this function does indeed never return.
	 */
	panic(__func__);
}

static void
xhci_polled_set_persistent_error(xhci_polled_t *xhci_polledp, int error)
{
	if (error != USB_SUCCESS &&
	    xhci_polledp->xhci_polled_persistent_error == USB_SUCCESS) {
		xhci_polledp->xhci_polled_persistent_error = error;
	}
}

/*
 * xhci_polled_init:
 *
 * Initialize generic information that is needed to provide USB/POLLED
 * support.
 */
static int
xhci_polled_init(usba_pipe_handle_data_t *input_pipe_handle, xhci_t *xhcip,
    usb_console_info_impl_t *console_info)
{
	xhci_pipe_t *xp;
	xhci_endpoint_t *xep;
	xhci_polled_t *xhci_polledp;

	ASSERT(mutex_owned(&xhcip->xhci_lock));

	/*
	 * We have already initialized this structure. If the structure
	 * has already been initialized, then we don't need to redo it.
	 */
	if (console_info->uci_private != NULL)
		return (USB_SUCCESS);

	xp = (xhci_pipe_t *)input_pipe_handle->p_hcd_private;
	if (xp == NULL)
		return (USB_FAILURE);

	/*
	 * We only support interrupt (keyboards) and not bulk (serial)
	 * endpoints at the moment.
	 */
	xep = xp->xp_ep;
	if (xep->xep_type != USB_EP_ATTR_INTR)
		return (USB_NOT_SUPPORTED);

	/* Allocate and initialize a state structure */
	xhci_polledp = kmem_zalloc(sizeof (xhci_polled_t), KM_SLEEP);

	xhci_polledp->xhci_polled_xhci = xhcip;
	xhci_polledp->xhci_polled_input_pipe_handle = input_pipe_handle;
	xhci_polledp->xhci_polled_endpoint = xep;

	console_info->uci_private = (usb_console_info_private_t)xhci_polledp;
	return (USB_SUCCESS);
}

static xhci_endpoint_t *
xhci_polled_get_endpoint(xhci_t *xhcip, xhci_trb_t *trb)
{
	int slot, endpoint;
	xhci_device_t *xd;

	endpoint = XHCI_TRB_GET_EP(LE_32(trb->trb_flags));
	slot = XHCI_TRB_GET_SLOT(LE_32(trb->trb_flags));

	xd = xhci_device_lookup_by_slot(xhcip, slot);
	if (xd == NULL)
		return (NULL);

	/*
	 * Endpoint IDs are indexed based on their Device Context Index, which
	 * means that we need to subtract one to get the actual ID that we use.
	 */
	return (xd->xd_endpoints[endpoint - 1]);
}

static int
xhci_polled_endpoint_transfer(xhci_polled_t *xhci_polledp, xhci_endpoint_t *xep,
    xhci_trb_t *trb, uint_t *num_characters)
{
	xhci_t *xhcip = xhci_polledp->xhci_polled_xhci;
	xhci_device_t *xd = xep->xep_xd;
	uint_t off;
	int code;
	xhci_transfer_t *xt;
	size_t len;
	xhci_transfer_t *rem;
	int sched_err;

	/*
	 * This TRB should be part of a transfer. If it's not, then we ignore
	 * it. We also check whether or not it's for the first transfer. Because
	 * the rings are serviced in order, it should be.
	 */
	if ((xt = xhci_endpoint_determine_transfer(xhcip, xep, trb, &off)) ==
	    NULL) {
		return (USB_FAILURE);
	}

	code = XHCI_TRB_GET_CODE(LE_32(trb->trb_status));
	if (code != XHCI_CODE_SUCCESS)
		return (USB_FAILURE);

	ASSERT(xep->xep_type == USB_EP_ATTR_INTR);

	if (!xt->xt_data_tohost)
		return (USB_SUCCESS);

	if (xt->xt_short != 0)
		return (USB_CR_DATA_UNDERRUN);

	if (xhci_transfer_sync(xhcip, xt, DDI_DMA_SYNC_FORCPU) != DDI_FM_OK) {
		xhci_polled_panic(xhci_polledp, "failed to process normal "
		    "transfer callback for endpoint %u of device on slot %d "
		    "and port %d: encountered fatal FM error synchronizing "
		    "DMA memory", xhcip, xep->xep_num, xd->xd_slot,
		    xd->xd_port);
	}

	len = xt->xt_buffer.xdb_len;
	if (len > sizeof (xhci_polledp->xhci_polled_buf))
		len = sizeof (xhci_polledp->xhci_polled_buf);
	xhci_transfer_copy(xt, xhci_polledp->xhci_polled_buf, len, B_TRUE);

	*num_characters = (uint_t)len;

	VERIFY(xhci_ring_trb_consumed(&xep->xep_ring, LE_64(trb->trb_addr)));
	rem = list_remove_head(&xep->xep_transfers);
	VERIFY3P(rem, ==, xt);

	xt->xt_short = 0;
	xt->xt_cr = USB_CR_OK;

	/*
	 * The call below can fail but there isn't much we can do other
	 * than panicing the machine. But that might only re-enter the
	 * kernel debugger with now broken keyboard input. So we are
	 * simply returning the keyboard input that we have succesfully
	 * received because it might enable some progress.
	 */
	sched_err = xhci_endpoint_schedule(xhcip, xd, xep, xt, B_TRUE);
	xhci_polled_set_persistent_error(xhci_polledp, sched_err);

	return (USB_SUCCESS);
}

/*
 * Process the event ring
 */
static int
xhci_polled_event_process(xhci_polled_t *xhci_polledp, uint_t *num_characters)
{
	xhci_t *xhcip = xhci_polledp->xhci_polled_xhci;
	xhci_ring_t *xrp = &xhcip->xhci_event.xev_ring;
	uint_t nevents;
	int ret;
	uint64_t addr;

	if (xhcip->xhci_state & XHCI_S_ERROR)
		return (USB_HC_HARDWARE_ERROR);

	VERIFY(xhcip->xhci_event.xev_segs != NULL);

	XHCI_DMA_SYNC(xrp->xr_dma, DDI_DMA_SYNC_FORKERNEL);

	/* Look for any transfer events */
	ret = USB_SUCCESS;
	for (nevents = 0; nevents < xrp->xr_ntrb; nevents++) {
		xhci_trb_t *trb;
		xhci_endpoint_t *xep;
		uint32_t type;

		if ((trb = xhci_ring_event_advance(xrp)) == NULL)
			break;

		xep = xhci_polled_get_endpoint(xhcip, trb);
		if (xep == NULL) {
			xhci_polled_set_persistent_error(xhci_polledp,
			    USB_HC_HARDWARE_ERROR);
			return (USB_HC_HARDWARE_ERROR);
		}
		type = LE_32(trb->trb_flags) & XHCI_TRB_TYPE_MASK;

		if (xep != xhci_polledp->xhci_polled_endpoint ||
		    type != XHCI_EVT_XFER) {
			/*
			 * We got an event which we are not prepared to
			 * handle here. Call into the normal driver code
			 * which should return here after dispatching a task.
			 */
			boolean_t processed;

			mutex_exit(&xhcip->xhci_lock);
			processed = xhci_event_process_trb(xhcip, trb);
			mutex_enter(&xhcip->xhci_lock);

			if (!processed && xhcip->xhci_state & XHCI_S_ERROR)
				return (USB_HC_HARDWARE_ERROR);
			continue;
		}

		ret = xhci_polled_endpoint_transfer(xhci_polledp, xep, trb,
		    num_characters);
		if (ret != USB_SUCCESS) {
			xhci_polled_set_persistent_error(xhci_polledp, ret);
			break;
		}
	}

	addr = xhci_dma_pa(&xrp->xr_dma) + sizeof (xhci_trb_t) * xrp->xr_tail;
	addr |= XHCI_ERDP_BUSY;
	xhci_put64(xhcip, XHCI_R_RUN, XHCI_ERDP(0), addr);

	return (ret);
}

int
xhci_hcdi_console_input_init(usba_pipe_handle_data_t *pipe_handle,
    uchar_t **polled_buf, usb_console_info_impl_t *console_input_info)
{
	xhci_t *xhcip;
	int ret;
	xhci_polled_t *xhci_polledp;

	xhcip = xhci_hcdi_get_xhcip_from_dev(pipe_handle->p_usba_device);

	mutex_enter(&xhcip->xhci_lock);

	ret = xhci_polled_init(pipe_handle, xhcip, console_input_info);
	if (ret != USB_SUCCESS) {
		mutex_exit(&xhcip->xhci_lock);
		return (ret);
	}

	xhci_polledp = (xhci_polled_t *)console_input_info->uci_private;
	*polled_buf = xhci_polledp->xhci_polled_buf;

	mutex_exit(&xhcip->xhci_lock);

	return (ret);
}

int
xhci_hcdi_console_input_fini(usb_console_info_impl_t *console_input_info)
{
	xhci_polled_t *xhci_polledp;

	xhci_polledp = (xhci_polled_t *)console_input_info->uci_private;
	if (xhci_polledp != NULL) {
		kmem_free(xhci_polledp, sizeof (xhci_polled_t));
		console_input_info->uci_private = NULL;
	}

	return (USB_SUCCESS);
}

int
xhci_hcdi_console_input_enter(usb_console_info_impl_t *console_input_info)
{
	xhci_polled_t *xhci_polledp;
	xhci_t *xhcip;
	xhci_endpoint_t *xep;
	uint32_t status;

	xhci_polledp = (xhci_polled_t *)console_input_info->uci_private;
	xhcip = xhci_polledp->xhci_polled_xhci;
	xep = xhci_polledp->xhci_polled_endpoint;

	if (mutex_tryenter(&xhcip->xhci_lock) == 0)
		return (USB_BUSY);

	/*
	 * If the controller is already switched over, just return
	 */
	if (xhci_polledp->xhci_polled_entry > 0) {
		xhci_polledp->xhci_polled_entry++;
		ASSERT(xep->xep_state & XHCI_ENDPOINT_POLLED);
		mutex_exit(&xhcip->xhci_lock);
		return (USB_SUCCESS);
	}

	/*
	 * Check to see if we have a fatal bit set. If this is the case the
	 * host controller is not working properly and we don't want to
	 * enter the kernel debugger and leave the system unresponsive.
	 */
	status = xhci_get32(xhcip, XHCI_R_OPER, XHCI_USBSTS);
	if ((status & (XHCI_STS_HSE | XHCI_STS_SRE | XHCI_STS_HCE)) != 0) {
		mutex_exit(&xhcip->xhci_lock);
		xhci_polled_set_persistent_error(xhci_polledp,
		    USB_HC_HARDWARE_ERROR);
		return (USB_HC_HARDWARE_ERROR);
	}

	/*
	 * We only support interrupt (keyboards) and not bulk (serial)
	 * endpoints at the moment.
	 */
	if (xhci_polledp->xhci_polled_endpoint->xep_type != USB_EP_ATTR_INTR) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_NOT_SUPPORTED);
	}

	xhci_polledp->xhci_polled_persistent_error = USB_SUCCESS;
	xhci_polledp->xhci_polled_entry++;

	ASSERT(!(xep->xep_state & XHCI_ENDPOINT_POLLED));
	xep->xep_state |= XHCI_ENDPOINT_POLLED;

	mutex_exit(&xhcip->xhci_lock);
	return (USB_SUCCESS);
}

int
xhci_hcdi_console_read(usb_console_info_impl_t *console_input_info,
    uint_t *num_characters)
{
	xhci_polled_t *xhci_polledp;
	xhci_t *xhcip;
	uint32_t status, iman;
	int ret;

	*num_characters = 0;

	xhci_polledp = (xhci_polled_t *)console_input_info->uci_private;
	VERIFY(xhci_polledp != NULL);

	if (xhci_polledp->xhci_polled_persistent_error != USB_SUCCESS)
		return (xhci_polledp->xhci_polled_persistent_error);

	xhcip = xhci_polledp->xhci_polled_xhci;
	if (mutex_tryenter(&xhcip->xhci_lock) == 0)
		return (USB_BUSY);

	/*
	 * Before we read the interrupt management register, check to see if we
	 * have a fatal bit set. As we cannot reset the host controller while
	 * the kernel debugger is running we give up.
	 */
	status = xhci_get32(xhcip, XHCI_R_OPER, XHCI_USBSTS);
	if ((status & (XHCI_STS_HSE | XHCI_STS_SRE | XHCI_STS_HCE)) != 0) {
		xhci_polled_panic(xhci_polledp, "found fatal error bit in "
		    "status register, value: 0x%x", xhcip, status);
	}

	iman = xhci_get32(xhcip, XHCI_R_RUN, XHCI_IMAN(0));

	ret = xhci_polled_event_process(xhci_polledp, num_characters);

	if (ret == USB_SUCCESS)
		xhci_put32(xhcip, XHCI_R_RUN, XHCI_IMAN(0), iman);

	mutex_exit(&xhcip->xhci_lock);
	return (ret);
}

int
xhci_hcdi_console_input_exit(usb_console_info_impl_t *console_input_info)
{
	xhci_polled_t *xhci_polledp;
	xhci_t *xhcip;
	xhci_endpoint_t *xep;

	xhci_polledp = (xhci_polled_t *)console_input_info->uci_private;
	VERIFY(xhci_polledp != NULL);

	xhcip = xhci_polledp->xhci_polled_xhci;
	mutex_enter(&xhcip->xhci_lock);

	xep = xhci_polledp->xhci_polled_endpoint;
	ASSERT(xep->xep_state & XHCI_ENDPOINT_POLLED);

	VERIFY(xhci_polledp->xhci_polled_entry > 0);
	xhci_polledp->xhci_polled_entry--;
	if (xhci_polledp->xhci_polled_entry > 0) {
		mutex_exit(&xhcip->xhci_lock);
		return (USB_SUCCESS);
	}

	xep->xep_state &= ~XHCI_ENDPOINT_POLLED;

	/*
	 * Initiate a reset of the host controller if we encountered problems
	 * or ignored events while in polled mode. The reset will not be
	 * performed in this context and instead be scheduled to a
	 * task queue. It will therefore only happen once the kernel is
	 * fully up and running again which should be perfectly safe.
	 */
	if (xhci_polledp->xhci_polled_persistent_error != USB_SUCCESS) {
		xhci_fm_runtime_reset(xhcip);
	}

	mutex_exit(&xhcip->xhci_lock);
	return (USB_SUCCESS);
}

int
xhci_hcdi_console_output_init(usba_pipe_handle_data_t *pipe_handle,
    usb_console_info_impl_t *console_output_info)
{
	return (USB_NOT_SUPPORTED);
}

int
xhci_hcdi_console_output_fini(usb_console_info_impl_t *console_output_info)
{
	return (USB_NOT_SUPPORTED);
}

int
xhci_hcdi_console_output_enter(usb_console_info_impl_t *console_output_info)
{
	return (USB_NOT_SUPPORTED);
}

int
xhci_hcdi_console_write(usb_console_info_impl_t	*console_output_info,
    uchar_t *buf, uint_t num_characters, uint_t *num_characters_written)
{
	return (USB_NOT_SUPPORTED);
}

int
xhci_hcdi_console_output_exit(usb_console_info_impl_t *console_output_info)
{
	return (USB_NOT_SUPPORTED);
}
