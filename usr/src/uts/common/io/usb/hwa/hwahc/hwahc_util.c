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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The Data Transfer Interface driver for Host Wire Adapter device
 *
 * This file mainly contains the entries for HCDI interfaces.
 */
#include <sys/usb/usba/usba_impl.h> /* usba_get_dip */
#include <sys/usb/hwa/hwahc/hwahc.h>
#include <sys/usb/hwa/hwahc/hwahc_util.h>
#include <sys/strsubr.h>
#include <sys/strsun.h> /* MBLKL */

#define	WUSB_GTK 1
#define	WUSB_PTK 2

/* function prototypes */
static int hwahc_state_is_operational(hwahc_state_t *hwahcp);
static hwahc_state_t *hwahc_obtain_state(dev_info_t *dip);
static void hwahc_wait_for_xfer_completion(hwahc_state_t *hwahcp,
	hwahc_pipe_private_t *pp);
static void hwahc_traverse_requests(hwahc_state_t *hwahcp,
	hwahc_pipe_private_t *pp);
static void hwahc_pipe_cleanup(hwahc_state_t *hwahcp,
	usba_pipe_handle_data_t *ph);
int hwahc_set_dev_encrypt(usb_pipe_handle_t ph, uint8_t ifc,
	usb_port_t index, wusb_secrt_data_t *secrt_data, uint8_t type);

static int hwahc_hcdi_pm_support(dev_info_t *dip);
static int hwahc_hcdi_pipe_open(usba_pipe_handle_data_t *ph,
	usb_flags_t flags);
static int hwahc_hcdi_pipe_close(usba_pipe_handle_data_t *ph,
	usb_flags_t flags);
static int hwahc_hcdi_pipe_reset(usba_pipe_handle_data_t *ph,
	usb_flags_t flags);
static void hwahc_hcdi_pipe_reset_data_toggle(usba_pipe_handle_data_t *ph);
static int hwahc_hcdi_pipe_ctrl_xfer(usba_pipe_handle_data_t *ph,
	usb_ctrl_req_t *ctrl_reqp, usb_flags_t usb_flags);
static int hwahc_hcdi_pipe_bulk_xfer(usba_pipe_handle_data_t *ph,
	usb_bulk_req_t *bulk_reqp, usb_flags_t usb_flags);
static int hwahc_hcdi_pipe_intr_xfer(usba_pipe_handle_data_t *ph,
	usb_intr_req_t *intr_reqp, usb_flags_t usb_flags);
static int hwahc_hcdi_pipe_isoc_xfer(usba_pipe_handle_data_t *ph,
	usb_isoc_req_t *isoc_reqp, usb_flags_t usb_flags);
static int hwahc_hcdi_bulk_transfer_size(usba_device_t *usba_device,
	size_t *size);
static int hwahc_hcdi_pipe_stop_intr_polling(usba_pipe_handle_data_t *ph,
	usb_flags_t flags);
static int hwahc_hcdi_pipe_stop_isoc_polling(usba_pipe_handle_data_t *ph,
	usb_flags_t flags);
static int hwahc_hcdi_get_current_frame_number(usba_device_t *usba_device,
	usb_frame_number_t *frame_number);
static int hwahc_hcdi_get_max_isoc_pkts(usba_device_t *usba_device,
	uint_t *max_pkts);
static int hwahc_hcdi_polled_input_init(usba_pipe_handle_data_t *ph,
	uchar_t **polled_buf, usb_console_info_impl_t *console_input_info);
static int hwahc_hcdi_polled_input_fini(usb_console_info_impl_t *info);
static int hwahc_hcdi_polled_input_enter(usb_console_info_impl_t *info);
static int hwahc_hcdi_polled_input_exit(usb_console_info_impl_t *info);
static int hwahc_hcdi_polled_read(usb_console_info_impl_t *info,
	uint_t *num_characters);
usba_hcdi_ops_t *hwahc_alloc_hcdi_ops(hwahc_state_t *hwahcp);

extern void *hwahc_statep;

/* Check the Host controller state and return proper values */
static int
hwahc_state_is_operational(hwahc_state_t *hwahcp)
{
	int	rval;

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));

	if (hwahcp->hwahc_dev_state != USB_DEV_ONLINE) {

		return (USB_FAILURE);
	}

	switch (hwahcp->hwahc_hc_soft_state) {
	case HWAHC_CTRL_INIT_STATE:
		rval = USB_FAILURE;
		break;
	case HWAHC_CTRL_OPERATIONAL_STATE:
		/* still need to check if channel is operational */
		if (hwahcp->hwahc_hw_state != HWAHC_HW_STARTED) {
			rval = USB_FAILURE;
		} else {
			rval = USB_SUCCESS;
		}

		break;
	case HWAHC_CTRL_ERROR_STATE:
		rval = USB_HC_HARDWARE_ERROR;
		break;
	default:
		rval = USB_FAILURE;
		break;
	}

	return (rval);
}

/* get soft state pointer */
hwahc_state_t *
hwahc_obtain_state(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);

	hwahc_state_t *hwahcp = ddi_get_soft_state(hwahc_statep, instance);

	ASSERT(hwahcp != NULL);

	return (hwahcp);
}


/*
 * Do not support wusb bus PM now
 */
/* ARGSUSED */
static int
hwahc_hcdi_pm_support(dev_info_t *dip)
{
	return (USB_FAILURE);
}

static void
/* ARGSUSED */
hwahc_hcdi_pipe_reset_data_toggle(usba_pipe_handle_data_t *ph)
{
	/* don't do anything now */
}

/* Wait for processing all completed transfers and to send results */
static void
hwahc_wait_for_xfer_completion(hwahc_state_t *hwahcp, hwahc_pipe_private_t *pp)
{
	wusb_wa_rpipe_hdl_t	*hdl = pp->pp_rp;
	clock_t			xfer_cmpl_time_wait;

	mutex_enter(&hdl->rp_mutex);
	if (hdl->rp_state != WA_RPIPE_STATE_ACTIVE) {
		mutex_exit(&hdl->rp_mutex);

		return;
	}
	mutex_exit(&hdl->rp_mutex);

	/* wait 3s */
	xfer_cmpl_time_wait = drv_usectohz(3000000);
	(void) cv_timedwait(&pp->pp_xfer_cmpl_cv, &hwahcp->hwahc_mutex,
	    ddi_get_lbolt() + xfer_cmpl_time_wait);

	mutex_enter(&hdl->rp_mutex);
	if (hdl->rp_state == WA_RPIPE_STATE_ACTIVE) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_wait_for_xfer_completion: no transfer completion "
		    "confirmation received");
	}
	mutex_exit(&hdl->rp_mutex);
}

/* remove all the unprocessed requests and do callback */
/* ARGSUSED */
static void
hwahc_traverse_requests(hwahc_state_t *hwahcp, hwahc_pipe_private_t *pp)
{
	wusb_wa_rpipe_hdl_t	*hdl = pp->pp_rp;
	wusb_wa_trans_wrapper_t	*wr;

	mutex_enter(&hdl->rp_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_traverse_requests: pp = 0x%p, wr=%p", (void*)pp,
	    (void *)hdl->rp_curr_wr);

	wr = hdl->rp_curr_wr;
	if (wr != NULL) {
		wusb_wa_stop_xfer_timer(wr);
		hdl->rp_state = WA_RPIPE_STATE_IDLE;
		hdl->rp_curr_wr = NULL;
		wr->wr_state = WR_ABORTED;
		mutex_exit(&hdl->rp_mutex);

		mutex_exit(&hwahcp->hwahc_mutex);

		/*
		 * This CR is to tell USBA to mark this pipe as IDLE,
		 * so that do not queue client requests at USBA. Requests
		 * sent after pipe close/reset will be handled by hwahc.
		 */
		wr->wr_cb(wr->wr_wa_data, wr, USB_CR_NOT_SUPPORTED, 0);

		mutex_enter(&hwahcp->hwahc_mutex);
		mutex_enter(&hdl->rp_mutex);
	}
	mutex_exit(&hdl->rp_mutex);
}

/* process periodic(INTR/ISOC) requests */
static void
hwahc_do_client_periodic_in_req_callback(hwahc_state_t *hwahcp,
	hwahc_pipe_private_t *pp, usb_cr_t completion_reason)
{
	usb_ep_descr_t	*eptd;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_do_client_periodic_in_req_callback: enter");

	/*
	 * Check for Interrupt/Isochronous IN, whether we need to do
	 * callback for the original client's periodic IN request.
	 */
	eptd = &(pp->pp_pipe_handle->p_ep);
	if (pp->pp_client_periodic_in_reqp) {
		if (WUSB_ISOC_ENDPOINT(eptd)) {
			/* not supported */
			USB_DPRINTF_L4(PRINT_MASK_HCDI,
			    hwahcp->hwahc_log_handle,
			    "hwahc_do_client_periodic_in_req_callback: "
			    "ISOC xfer not support");
		} else {
			/*
			 * NULL wr to tell the function that we're done and
			 * should clear pipe's pp_client_periodic_in_reqp
			 */
			wusb_wa_callback(&hwahcp->hwahc_wa_data,
			    pp->pp_pipe_handle, NULL, completion_reason);
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_do_client_periodic_in_req_callback: end");
}

/*
 * clean up the pipe, called by pipe_close/pipe_reset
 *	- Abort RPipe operation
 *	- Clean pending requests queueing on this pipe
 */
static void
hwahc_pipe_cleanup(hwahc_state_t *hwahcp, usba_pipe_handle_data_t *ph)
{
	hwahc_pipe_private_t	*pp;
	wusb_wa_rpipe_hdl_t	*hdl;
	int			rval;
	usb_ep_descr_t		*eptd;
	usb_cr_t		completion_reason;

	pp = (hwahc_pipe_private_t *)ph->p_hcd_private;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_pipe_cleanup: ph = 0x%p, p_req_cnt, ep=0x%02x,"
	    " state=%d", (void *) ph, ph->p_ep.bEndpointAddress,
	    pp->pp_state);

	ASSERT(mutex_owned(&hwahcp->hwahc_mutex));
	ASSERT(!servicing_interrupt());

	hdl = pp->pp_rp;

	if (hwahcp->hwahc_dev_state == USB_DEV_ONLINE) {
		/* abort rpipe */
		mutex_enter(&hdl->rp_mutex);

		/* if active, abort the requests */
		if (hdl->rp_state == WA_RPIPE_STATE_ACTIVE) {
			mutex_exit(&hdl->rp_mutex);
			mutex_exit(&hwahcp->hwahc_mutex);
			rval = wusb_wa_rpipe_abort(hwahcp->hwahc_dip,
			    hwahcp->hwahc_default_pipe, hdl);
			mutex_enter(&hwahcp->hwahc_mutex);
			mutex_enter(&hdl->rp_mutex);
		}
		mutex_exit(&hdl->rp_mutex);

		/* wait for transfers to complete */
		hwahc_wait_for_xfer_completion(hwahcp, pp);
	}

	/* remove all unprocessed requests on this pipe and do callback */
	hwahc_traverse_requests(hwahcp, pp);

	switch (pp->pp_state) {
	case HWAHC_PIPE_STATE_CLOSE:
		completion_reason = USB_CR_PIPE_CLOSING;

		mutex_exit(&hwahcp->hwahc_mutex);
		(void) wusb_wa_rpipe_reset(hwahcp->hwahc_dip, ph, hdl, 0);
		mutex_enter(&hwahcp->hwahc_mutex);

		break;
	case HWAHC_PIPE_STATE_RESET:
	case HWAHC_PIPE_STATE_ERROR:
		completion_reason = USB_CR_PIPE_RESET;
		if (hwahcp->hwahc_dev_state == USB_DEV_ONLINE) {
			mutex_exit(&hwahcp->hwahc_mutex);
			/*
			 * reset WA's RPipe.
			 * If this pipe is not bound to the default endpoint,
			 * also send a clear_feature request to that ep.
			 */
			rval = wusb_wa_rpipe_reset(hwahcp->hwahc_dip,
			    ph, hdl, 1);
			mutex_enter(&hwahcp->hwahc_mutex);

			USB_DPRINTF_L4(PRINT_MASK_HCDI,
			    hwahcp->hwahc_log_handle,
			    "hwahc_pipe_cleanup: rp reset, rv=%d",
			    rval);

			pp->pp_state = HWAHC_PIPE_STATE_IDLE;
		}

		break;
	case HWAHC_PIPE_STATE_STOP_POLLING:
		completion_reason = USB_CR_STOPPED_POLLING;
		pp->pp_state = HWAHC_PIPE_STATE_IDLE;

		break;
	}

	/*
	 * Do the callback for the original client
	 * periodic IN request.
	 */
	eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_pipe_cleanup: end");

	if ((WUSB_PERIODIC_ENDPOINT(eptd)) &&
	    ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) ==
	    USB_EP_DIR_IN)) {
		mutex_exit(&hwahcp->hwahc_mutex);

		hwahc_do_client_periodic_in_req_callback(
		    hwahcp, pp, completion_reason);

		mutex_enter(&hwahcp->hwahc_mutex);
	}
}

/*
 * set the pipe's parent device information
 */
static int
hwahc_set_pipe_dev_info(hwahc_state_t *hwahcp,
    usba_pipe_handle_data_t *ph, hwahc_pipe_private_t *pp)
{
	dev_info_t *dip = NULL;
	wusb_hc_data_t *hc_data;
	int i;

	dip = usba_get_dip((usb_pipe_handle_t)ph->p_ph_impl);
	if (dip == NULL) {

		return (USB_FAILURE);
	}

	hc_data = &hwahcp->hwahc_hc_data;

	mutex_enter(&hc_data->hc_mutex);
	for (i = 1; i <= hc_data->hc_num_ports; i++) {
		if ((dip == hc_data->hc_children_dips[i])) {
			pp->pp_wdev = hc_data->hc_dev_infos[i];

			USB_DPRINTF_L3(DPRINT_MASK_HCDI,
			    hwahcp->hwahc_log_handle,
			    "hwahc_set_pipe_dev_info: pp(%p) device(%p) set",
			    (void *) pp, (void *) pp->pp_wdev);

			break;
		}
	}

	mutex_exit(&hc_data->hc_mutex);

	if (pp->pp_wdev) {
		return (USB_SUCCESS);
	} else {
		return (USB_FAILURE);
	}
}

/*
 * HWA HCDI entry points
 *
 * The Host Controller Driver Interfaces (HCDI) are the software interfaces
 * between the Universal Serial Bus Layer (USBA) and the Host Controller
 * Driver (HCD). The HCDI interfaces or entry points are subject to change.
 */

/*
 * hwahc_hcdi_pipe_open:
 * Member of HCD Ops structure and called during client specific pipe open.
 * Assign rpipe for wireless transaction to work.
 * The rpipe is assigned to an endpoint until the endpoint is closed.
 */
static int
hwahc_hcdi_pipe_open(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	int			rval;
	hwahc_state_t		*hwahcp;
	int			kmflag;
	hwahc_pipe_private_t	*pp;
	usb_ep_descr_t		*epdt = &ph->p_ep;
	uint8_t			type;
	wusb_wa_data_t		*wa;

	hwahcp = hwahc_obtain_state(ph->p_usba_device->usb_root_hub_dip);
	wa = &hwahcp->hwahc_wa_data;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_open: hwahc=0x%p, ph=0x%p,"
	    " addr = 0x%x, ep=0x%02X", (void *) hwahcp, (void *) ph,
	    ph->p_usba_device->usb_addr, epdt->bEndpointAddress);

	kmflag = (flags & USB_FLAGS_SLEEP) ? KM_SLEEP : KM_NOSLEEP;

	if (ph->p_hcd_private) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_open: Pipe is already opened");

		return (USB_FAILURE);
	}

	pp = kmem_zalloc(sizeof (hwahc_pipe_private_t), kmflag);
	if (pp == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_open: alloc pp failed");

		return (USB_NO_RESOURCES);
	}

	mutex_enter(&hwahcp->hwahc_mutex);

	if (hwahc_set_pipe_dev_info(hwahcp, ph, pp) < 0) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_open: set pipe dev_info failed");
		mutex_exit(&hwahcp->hwahc_mutex);

		return (USB_FAILURE);
	}

	rval = hwahc_state_is_operational(hwahcp);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_open: state error: %d", rval);
		kmem_free(pp, sizeof (hwahc_pipe_private_t));
		mutex_exit(&hwahcp->hwahc_mutex);

		return (rval);
	}

	/* assign rpipe to the endpoint */
	type = epdt->bmAttributes & USB_EP_ATTR_MASK;
	rval = wusb_wa_get_rpipe(&hwahcp->hwahc_wa_data,
	    hwahcp->hwahc_default_pipe, type, &pp->pp_rp,
	    PRINT_MASK_HCDI, hwahcp->hwahc_log_handle);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_open: getting rpipe failed");
		kmem_free(pp, sizeof (hwahc_pipe_private_t));
		mutex_exit(&hwahcp->hwahc_mutex);

		return (USB_NO_RESOURCES);
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	/* target the rpipe to the endpoint */
	rval = wusb_wa_set_rpipe_target(hwahcp->hwahc_dip, wa,
	    hwahcp->hwahc_default_pipe, ph, pp->pp_rp);
	mutex_enter(&hwahcp->hwahc_mutex);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_open: set target for rpipe failed");
		(void) wusb_wa_release_rpipe(wa, pp->pp_rp);
		kmem_free(pp, sizeof (hwahc_pipe_private_t));
		mutex_exit(&hwahcp->hwahc_mutex);

		return (USB_FAILURE);
	}

	pp->pp_pipe_handle = ph;
	cv_init(&pp->pp_xfer_cmpl_cv, NULL, CV_DRIVER, NULL);

	mutex_enter(&ph->p_mutex);
	ph->p_hcd_private = (usb_opaque_t)pp;
	bcopy(&ph->p_policy, &pp->pp_policy, sizeof (usb_pipe_policy_t));
	mutex_exit(&ph->p_mutex);

	pp->pp_state = HWAHC_PIPE_STATE_IDLE;
	hwahcp->hwahc_open_pipe_count++;
	mutex_exit(&hwahcp->hwahc_mutex);

	return (USB_SUCCESS);
}


/*
 * hwahc_hcdi_pipe_close:
 * Member of HCD Ops structure and called during the client specific pipe
 * close.
 * Remove unprocessed transfers from the pipe and free rpipe resource.
 */
/* ARGSUSED */
static int
hwahc_hcdi_pipe_close(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	hwahc_state_t		*hwahcp;
	hwahc_pipe_private_t	*pp;
	usb_ep_descr_t		*epdt = &ph->p_ep;

	hwahcp = hwahc_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_close:ph=0x%p addr = 0x%x, ep = 0x%x",
	    (void *) ph, ph->p_usba_device->usb_addr,
	    epdt->bEndpointAddress);

	ASSERT(ph->p_hcd_private != NULL);
	pp = (hwahc_pipe_private_t *)ph->p_hcd_private;

	mutex_enter(&hwahcp->hwahc_mutex);

	pp->pp_state = HWAHC_PIPE_STATE_CLOSE;

	hwahc_pipe_cleanup(hwahcp, ph);

	mutex_exit(&hwahcp->hwahc_mutex);

	wusb_wa_clear_dev_ep(ph); /* clear the remote dev's endpoint */
	mutex_enter(&hwahcp->hwahc_mutex);

	(void) wusb_wa_release_rpipe(&hwahcp->hwahc_wa_data, pp->pp_rp);

	mutex_enter(&ph->p_mutex);
	cv_destroy(&pp->pp_xfer_cmpl_cv);
	kmem_free(pp, sizeof (hwahc_pipe_private_t));
	ph->p_hcd_private = NULL;
	mutex_exit(&ph->p_mutex);
	hwahcp->hwahc_open_pipe_count--;
	mutex_exit(&hwahcp->hwahc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_close: end");

	return (USB_SUCCESS);
}


/*
 * hwahc_hcdi_pipe_reset:
 *	- clean up this pipe and change its state
 */
/* ARGSUSED */
static int
hwahc_hcdi_pipe_reset(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	hwahc_state_t		*hwahcp;
	hwahc_pipe_private_t	*pp;

	hwahcp = hwahc_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_reset: ph = 0x%p, ep=0x%02x",
	    (void *) ph, ph->p_ep.bEndpointAddress);

	ASSERT(ph->p_hcd_private != NULL);
	pp = (hwahc_pipe_private_t *)ph->p_hcd_private;

	mutex_enter(&hwahcp->hwahc_mutex);
	pp->pp_state = HWAHC_PIPE_STATE_RESET;
	hwahc_pipe_cleanup(hwahcp, ph);
	mutex_exit(&hwahcp->hwahc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_reset: end");

	return (USB_SUCCESS);
}


/*
 * hwahc_hcdi_pipe_ctrl_xfer:
 *	- usba_hcdi_pipe_ctrl_xfer entry
 *	- check pipe state
 *	- call wa_xfer to do this request
 */
static int
hwahc_hcdi_pipe_ctrl_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_ctrl_req_t		*ctrl_reqp,
	usb_flags_t		usb_flags)
{
	hwahc_state_t		*hwahcp;
	hwahc_pipe_private_t	*pp;
	int			rval;
	uint8_t			ep_addr = ph->p_ep.bEndpointAddress;

	hwahcp = hwahc_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_ctrl_xfer: hwahcp=0x%p ph = 0x%p"
	    " reqp = 0x%p flags = %x", (void *) hwahcp, (void *) ph,
	    (void *) ctrl_reqp, usb_flags);

	ASSERT(ph->p_hcd_private != NULL);
	pp = (hwahc_pipe_private_t *)ph->p_hcd_private;

	mutex_enter(&hwahcp->hwahc_mutex);
	rval = hwahc_state_is_operational(hwahcp);
	if (rval != USB_SUCCESS) {
		mutex_exit(&hwahcp->hwahc_mutex);

		return (rval);
	}

	/*
	 * if doing ctrl transfer on non-zero pipe and its state is error
	 * The default endpoint is critical for any other operations.
	 * We should not depend on upper layer to reset it.
	 */
	if ((pp->pp_state == HWAHC_PIPE_STATE_ERROR)) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_ctrl_xfer: Pipe(%d) is in error"
		    " state, need pipe reset to continue", ep_addr);

		if (ep_addr == 0) {
			/*
			 * some error with the RPipe of EP 0,
			 * we need to reset this RPipe by ourself
			 */
			mutex_exit(&hwahcp->hwahc_mutex);
			(void) wusb_wa_rpipe_reset(hwahcp->hwahc_dip, ph,
			    pp->pp_rp, 1);
			mutex_enter(&hwahcp->hwahc_mutex);
			pp->pp_state = 0;
		} else {
		/* client driver should clear non-default endpoint's state */
			mutex_exit(&hwahcp->hwahc_mutex);

			return (USB_FAILURE);
		}
	} else if ((pp->pp_state != HWAHC_PIPE_STATE_IDLE) &&
	    (pp->pp_state != HWAHC_PIPE_STATE_ERROR)) {
			mutex_exit(&hwahcp->hwahc_mutex);

			return (USB_PIPE_ERROR);
	}

	mutex_exit(&hwahcp->hwahc_mutex);

	rval = wusb_wa_ctrl_xfer(&hwahcp->hwahc_wa_data, pp->pp_rp, ph,
	    ctrl_reqp, usb_flags);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_ctrl_xfer failed, rval = %d", rval);
	}


	return (rval);
}


/*
 * hwahc_hcdi_pipe_bulk_xfer:
 *	- usba_hcid_pipe_bulk_xfer entry
 *	- check the target pipe status first
 *	- process this request
 */
static int
hwahc_hcdi_pipe_bulk_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_bulk_req_t		*bulk_reqp,
	usb_flags_t		usb_flags)
{
	hwahc_state_t		*hwahcp;
	hwahc_pipe_private_t	*pp;
	int			rval;

	hwahcp = hwahc_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_bulk_xfer: hwahcp=0x%p ph = 0x%p reqp = 0x%p"
	    " flags = %x", (void *) hwahcp, (void *) ph,
	    (void *) bulk_reqp, usb_flags);

	ASSERT(ph->p_hcd_private != NULL);

	pp = (hwahc_pipe_private_t *)ph->p_hcd_private;

	mutex_enter(&hwahcp->hwahc_mutex);
	rval = hwahc_state_is_operational(hwahcp);
	if (rval != USB_SUCCESS) {
		mutex_exit(&hwahcp->hwahc_mutex);

		return (rval);
	}

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_bulk_xfer: pp = 0x%p state= %x", (void *) pp,
	    pp->pp_state);

	if (pp->pp_state == HWAHC_PIPE_STATE_ERROR) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_bulk_xfer: "
		    "Pipe is in error state, need pipe reset to continue");

		mutex_exit(&hwahcp->hwahc_mutex);

		return (USB_FAILURE);
	}

	mutex_exit(&hwahcp->hwahc_mutex);
	rval = wusb_wa_bulk_xfer(&hwahcp->hwahc_wa_data, pp->pp_rp, ph,
	    bulk_reqp, usb_flags);
	mutex_enter(&hwahcp->hwahc_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_bulk_xfer failed, rval = %d", rval);
	}
	mutex_exit(&hwahcp->hwahc_mutex);

	return (rval);
}

/*
 * hwahc_hcdi_pipe_intr_xfer:
 *	- usba_hcdi_pipe_intr_xfer entry
 *	- check pipe state
 *	- process this request
 */
static int
hwahc_hcdi_pipe_intr_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_intr_req_t		*intr_reqp,
	usb_flags_t		usb_flags)
{
	hwahc_state_t		*hwahcp;
	hwahc_pipe_private_t	*pp;
	int			rval, pipe_dir;

	hwahcp = hwahc_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_intr_xfer: hwahcp=0x%p ph = 0x%p"
	    " reqp = 0x%p flags = %x", (void *) hwahcp, (void *) ph,
	    (void *) intr_reqp, usb_flags);

	ASSERT(ph->p_hcd_private != NULL);
	pp = (hwahc_pipe_private_t *)ph->p_hcd_private;

	mutex_enter(&hwahcp->hwahc_mutex);
	rval = hwahc_state_is_operational(hwahcp);
	if (rval != USB_SUCCESS) {
		mutex_exit(&hwahcp->hwahc_mutex);

		return (rval);
	}

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_intr_xfer: pp = 0x%p state= %x", (void *) pp,
	    pp->pp_state);

	if (pp->pp_state == HWAHC_PIPE_STATE_ERROR) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_intr_xfer: "
		    "Pipe is in error state, need pipe reset to continue");

		mutex_exit(&hwahcp->hwahc_mutex);

		return (USB_FAILURE);
	}

	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;


	mutex_exit(&hwahcp->hwahc_mutex);
	rval = wusb_wa_intr_xfer(&hwahcp->hwahc_wa_data, pp->pp_rp, ph,
	    intr_reqp, usb_flags);
	mutex_enter(&hwahcp->hwahc_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_intr_xfer failed, rval = %d", rval);
	}

	if ((pipe_dir == USB_EP_DIR_IN) &&(rval == USB_SUCCESS)) {
		/*
		 * the request has been submitted successfully,
		 * save the original one; free this request when polling
		 * stopped
		 */
		pp->pp_client_periodic_in_reqp = (usb_opaque_t)intr_reqp;
		pp->pp_state = HWAHC_PIPE_STATE_ACTIVE;
	}

	mutex_exit(&hwahcp->hwahc_mutex);

	return (rval);
}

/*
 * hwahc_hcdi_pipe_isoc_xfer:
 */
/* ARGSUSED */
static int
hwahc_hcdi_pipe_isoc_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_isoc_req_t		*isoc_reqp,
	usb_flags_t		usb_flags)
{
	return (USB_NOT_SUPPORTED);
}


/*
 * hwahc_hcdi_bulk_transfer_size:
 *
 * Return maximum bulk transfer size
 */
/* ARGSUSED */
static int
hwahc_hcdi_bulk_transfer_size(
	usba_device_t	*usba_device,
	size_t		*size)
{
	hwahc_state_t		*hwahcp;
	int			rval;

	hwahcp = hwahc_obtain_state(usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_bulk_transfer_size:");

	mutex_enter(&hwahcp->hwahc_mutex);
	rval = hwahc_state_is_operational(hwahcp);
	mutex_exit(&hwahcp->hwahc_mutex);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	*size = WA_MAX_SEG_COUNT * 1024;

	return (USB_SUCCESS);
}

/*
 * hwahc_hcdi_pipe_stop_intr_polling()
 */
/* ARGSUSED */
static int
hwahc_hcdi_pipe_stop_intr_polling(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	hwahc_state_t		*hwahcp;
	hwahc_pipe_private_t	*pp;

	hwahcp = hwahc_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_hcdi_pipe_stop_intr_polling: hwahcp=0x%p ph = 0x%p"
	    " flags = %x", (void *) hwahcp, (void *) ph, flags);

	ASSERT(ph->p_hcd_private != NULL);

	mutex_enter(&hwahcp->hwahc_mutex);
	pp = (hwahc_pipe_private_t *)ph->p_hcd_private;

	if (pp->pp_state != HWAHC_PIPE_STATE_ACTIVE) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_hcdi_pipe_stop_intr_polling: "
		    "Polling already stopped");
		mutex_exit(&hwahcp->hwahc_mutex);

		return (USB_SUCCESS);
	}

	pp->pp_state = HWAHC_PIPE_STATE_STOP_POLLING;

	hwahc_pipe_cleanup(hwahcp, ph);

	mutex_exit(&hwahcp->hwahc_mutex);

	return (USB_SUCCESS);
}


/*
 * hwahc_hcdi_pipe_stop_isoc_polling()
 */
/*ARGSUSED*/
static int
hwahc_hcdi_pipe_stop_isoc_polling(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	return (USB_NOT_SUPPORTED);
}


/*
 * hwahc_hcdi_get_current_frame_number:
 *
 * Get the current usb frame number.
 * Return whether the request is handled successfully
 */
/* ARGSUSED */
static int
hwahc_hcdi_get_current_frame_number(
	usba_device_t		*usba_device,
	usb_frame_number_t	*frame_number)
{
	return (USB_NOT_SUPPORTED);
}


/*
 * hwahc_hcdi_get_max_isoc_pkts:
 *
 * Get maximum isochronous packets per usb isochronous request.
 * Return whether the request is handled successfully
 */
/* ARGSUSED */
static int
hwahc_hcdi_get_max_isoc_pkts(
	usba_device_t	*usba_device,
	uint_t		*max_pkts)
{
	return (USB_NOT_SUPPORTED);
}


/*
 * POLLED entry points
 *
 * These functions are entry points into the POLLED code.
 */
/*
 * hwahc_hcdi_polled_input_init:
 *
 * This is the initialization routine for handling the USB keyboard
 * in POLLED mode.  This routine is not called from POLLED mode, so
 * it is OK to acquire mutexes.
 */
/* ARGSUSED */
static int
hwahc_hcdi_polled_input_init(
	usba_pipe_handle_data_t	*ph,
	uchar_t			**polled_buf,
	usb_console_info_impl_t	*console_input_info)
{
	return (USB_FAILURE);
}


/*
 * hwahc_hcdi_polled_input_fini:
 */
/* ARGSUSED */
static int
hwahc_hcdi_polled_input_fini(usb_console_info_impl_t *info)
{
	return (USB_FAILURE);
}


/*
 * hwahc_hcdi_polled_input_enter:
 *
 * This is where we enter into POLLED mode.  This routine sets up
 * everything so that calls to	hwahc_hcdi_polled_read will return
 * characters.
 */
/* ARGSUSED */
static int
hwahc_hcdi_polled_input_enter(usb_console_info_impl_t *info)
{
	return (USB_FAILURE);
}


/*
 * hwahc_hcdi_polled_input_exit:
 *
 * This is where we exit POLLED mode. This routine restores
 * everything that is needed to continue operation.
 */
/* ARGSUSED */
static int
hwahc_hcdi_polled_input_exit(usb_console_info_impl_t *info)
{
	return (USB_FAILURE);
}


/*
 * hwahc_hcdi_polled_read:
 *
 * Get a key character
 */
/* ARGSUSED */
static int
hwahc_hcdi_polled_read(
	usb_console_info_impl_t	*info,
	uint_t			*num_characters)
{
	return (USB_FAILURE);
}


/*
 * hwahc_alloc_hcdi_ops:
 *
 * The HCDI interfaces or entry points are the software interfaces used by
 * the Universal Serial Bus Driver  (USBA) to  access the services of the
 * Host Controller Driver (HCD).  During HCD initialization, inform  USBA
 * about all available HCDI interfaces or entry points.
 */
usba_hcdi_ops_t *
hwahc_alloc_hcdi_ops(hwahc_state_t *hwahcp)
{
	usba_hcdi_ops_t			*usba_hcdi_ops;

	USB_DPRINTF_L2(PRINT_MASK_ATTA, hwahcp->hwahc_log_handle,
	    "hwahc_alloc_hcdi_ops:");

	usba_hcdi_ops = usba_alloc_hcdi_ops();

	usba_hcdi_ops->usba_hcdi_ops_version = HCDI_OPS_VERSION;

	usba_hcdi_ops->usba_hcdi_pm_support = hwahc_hcdi_pm_support;
	usba_hcdi_ops->usba_hcdi_pipe_open = hwahc_hcdi_pipe_open;
	usba_hcdi_ops->usba_hcdi_pipe_close = hwahc_hcdi_pipe_close;

	usba_hcdi_ops->usba_hcdi_pipe_reset = hwahc_hcdi_pipe_reset;
	usba_hcdi_ops->usba_hcdi_pipe_reset_data_toggle =
	    hwahc_hcdi_pipe_reset_data_toggle;

	usba_hcdi_ops->usba_hcdi_pipe_ctrl_xfer = hwahc_hcdi_pipe_ctrl_xfer;
	usba_hcdi_ops->usba_hcdi_pipe_bulk_xfer = hwahc_hcdi_pipe_bulk_xfer;
	usba_hcdi_ops->usba_hcdi_pipe_intr_xfer = hwahc_hcdi_pipe_intr_xfer;
	usba_hcdi_ops->usba_hcdi_pipe_isoc_xfer = hwahc_hcdi_pipe_isoc_xfer;

	usba_hcdi_ops->usba_hcdi_bulk_transfer_size =
	    hwahc_hcdi_bulk_transfer_size;

	usba_hcdi_ops->usba_hcdi_pipe_stop_intr_polling =
	    hwahc_hcdi_pipe_stop_intr_polling;
	usba_hcdi_ops->usba_hcdi_pipe_stop_isoc_polling =
	    hwahc_hcdi_pipe_stop_isoc_polling;

	usba_hcdi_ops->usba_hcdi_get_current_frame_number =
	    hwahc_hcdi_get_current_frame_number;
	usba_hcdi_ops->usba_hcdi_get_max_isoc_pkts =
	    hwahc_hcdi_get_max_isoc_pkts;

	usba_hcdi_ops->usba_hcdi_console_input_init =
	    hwahc_hcdi_polled_input_init;
	usba_hcdi_ops->usba_hcdi_console_input_enter =
	    hwahc_hcdi_polled_input_enter;
	usba_hcdi_ops->usba_hcdi_console_read =
	    hwahc_hcdi_polled_read;
	usba_hcdi_ops->usba_hcdi_console_input_exit =
	    hwahc_hcdi_polled_input_exit;
	usba_hcdi_ops->usba_hcdi_console_input_fini =
	    hwahc_hcdi_polled_input_fini;

	return (usba_hcdi_ops);
}


/*
 * Set cluster ID.
 * see 8.5.3.11
 */
int
hwahc_set_cluster_id(dev_info_t *dip, uint8_t cluster_id)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval;
	hwahc_state_t	*hwahcp;

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	if (hwahcp == NULL) {

		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, hwahcp->hwahc_default_pipe,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    HWA_REQ_SET_CLUSTER_ID,
	    cluster_id,
	    hwahcp->hwahc_wa_data.wa_ifno,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "Set_Cluster_ID fails: rval=%d cr=%d cb=0x%x",
		    rval, completion_reason, cb_flags);
	}

	return (rval);
}

/*
 * Set WUSB Stream Index. see 8.5.3.13
 */
int
hwahc_set_stream_idx(dev_info_t *dip, uint8_t stream_idx)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval;
	hwahc_state_t	*hwahcp;

	if ((dip == NULL))  {

		return (USB_INVALID_ARGS);
	}

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	if (hwahcp == NULL) {

		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, hwahcp->hwahc_default_pipe,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    HWA_REQ_SET_STREAM_IDX,
	    stream_idx,
	    hwahcp->hwahc_wa_data.wa_ifno,
	    0, NULL, 0, &completion_reason,
	    &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "Set_Stream_Idx fails: rval=%d cr=%d cb=0x%x",
		    rval, completion_reason, cb_flags);
	}

	return (rval);
}

/*
 * 8.5.3.12 - Set WUSB MAS
 *	Caller must ensure the data is WUSB_SET_WUSB_MAS_LEN long.
 */
int
hwahc_set_wusb_mas(dev_info_t *dip, uint8_t *data)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	mblk_t		*blk;
	int		rval, i;
	hwahc_state_t	*hwahcp;

	if ((dip == NULL))  {

		return (USB_INVALID_ARGS);
	}

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	if (hwahcp == NULL) {

		return (USB_INVALID_ARGS);
	}

	blk = allocb_wait(WUSB_SET_WUSB_MAS_LEN, BPRI_LO, STR_NOSIG, NULL);

	for (i = 0; i < WUSB_SET_WUSB_MAS_LEN; i++) {
		*blk->b_wptr++ = data[i];
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, hwahcp->hwahc_default_pipe,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    HWA_REQ_SET_WUSB_MAS,
	    0,
	    hwahcp->hwahc_wa_data.wa_ifno,
	    WUSB_SET_WUSB_MAS_LEN,
	    &blk, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "Set_WUSB_MAS fails: rval=%d cr=%d cb=0x%x",
		    rval, completion_reason, cb_flags);
	}
	freemsg(blk);

	return (rval);
}

/* 8.5.3.1 - Add MMC IE */
int
hwahc_add_mmc_ie(dev_info_t *dip, uint8_t interval, uint8_t rcnt,
	uint8_t iehdl, uint16_t len, uint8_t *data)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	mblk_t		*blk;
	int		i, rval;
	hwahc_state_t	*hwahcp;

	if (dip == NULL)  {

		return (USB_INVALID_ARGS);
	}

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	if (hwahcp == NULL) {

		return (USB_INVALID_ARGS);
	}

	blk = allocb_wait(len, BPRI_LO, STR_NOSIG, NULL);

	for (i = 0; i < len; i++) {
		*blk->b_wptr++ = data[i];
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, hwahcp->hwahc_default_pipe,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    HWA_REQ_ADD_MMC_IE,
	    (interval << 8) | rcnt,
	    (iehdl << 8) | hwahcp->hwahc_wa_data.wa_ifno,
	    len,
	    &blk, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "Add_MMC_IE fails: rval=%d cr=%d cb=0x%x",
		    rval, completion_reason, cb_flags);
	}

	freemsg(blk);

	return (rval);
}

/* 8.5.3.5 - Remove MMC IE */
int
hwahc_remove_mmc_ie(dev_info_t *dip, uint8_t iehdl)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval;
	hwahc_state_t	*hwahcp;

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	if (hwahcp == NULL) {
		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, hwahcp->hwahc_default_pipe,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    HWA_REQ_REMOVE_MMC_IE,
	    0,
	    (iehdl << 8) | hwahcp->hwahc_wa_data.wa_ifno,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "Remove_MMC_IE fails: rval=%d cr=%d cb=0x%x",
		    rval, completion_reason, cb_flags);
	}

	return (rval);
}

/* 8.5.3.14 - WUSB Channel Stop */
int
hwahc_stop_ch(dev_info_t *dip, uint32_t timeoff)
{
	int		rval;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	hwahc_state_t	*hwahcp;

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	if (hwahcp == NULL) {

		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, hwahcp->hwahc_default_pipe,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    HWA_REQ_CH_STOP,
	    timeoff & 0x00ffffff,
	    hwahcp->hwahc_wa_data.wa_ifno,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "WUSB_Ch_Stop fails: rval=%d cr=%d cb=0x%x",
		    rval, completion_reason, cb_flags);
	}

	return (rval);
}

/* 8.5. 3.10 - Set Num DNTS Slots */
int
hwahc_set_num_dnts(dev_info_t *dip, uint8_t interval, uint8_t nslots)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval;
	hwahc_state_t	*hwahcp;

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	if (hwahcp == NULL) {

		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, hwahcp->hwahc_default_pipe,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    HWA_REQ_SET_NUM_DNTS,
	    (interval << 8) | nslots,
	    hwahcp->hwahc_wa_data.wa_ifno,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "Set_Num_DNTS fails: rval=%d cr=%d cb=0x%x",
		    rval, completion_reason, cb_flags);
	}

	return (rval);
}

/* set encryptiion type for host */
int
hwahc_set_encrypt(dev_info_t *dip, usb_port_t port, uint8_t type)
{
	hwahc_state_t	*hwahcp;
	int		rval;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (USB_INVALID_ARGS);
	}
	/* DEVICE INDEX */
	rval = hwahc_set_dev_encrypt(hwahcp->hwahc_default_pipe,
	    hwahcp->hwahc_wa_data.wa_ifno, port - 1,
	    &hwahcp->hwahc_secrt_data, type);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_set_encrypt: set device encryption for port %d "
		    "failed", port);
	}

	return (rval);
}


/*
 * Set Device Key for WUSB host, refer to WUSB 1.0/8.5.3.8
 *
 * Set group/device key:
 * devindex = actual port number - 1, so it is zero based
 *
 */
int hwahc_set_keys(hwahc_state_t *hwahcp, usb_key_descr_t *key_descr,
    size_t klen, uint8_t devindex, uint8_t keydex, uint8_t flag)
{
	usb_ctrl_setup_t	setup;
	usb_cr_t		cr;
	usb_cb_flags_t		cb_flags;
	mblk_t			*pdata;
	int			rval;
	uint8_t			keyindex;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
	    "hwahc_set_keys: klen = %d, devindex = %d", (int)klen,
	    devindex);

	/* Table 7-21 and Errata 2005/07 */
	if (flag == WUSB_GTK) {
		if (devindex != 0) {
			return (USB_FAILURE);
		}

		/* See 7.3.2.4 for key index format */
		keyindex = (1 << 5) | keydex;
	} else if (flag == WUSB_PTK) {

		keyindex = keydex;
	} else {

		return (USB_FAILURE);
	}

	setup.bmRequestType = USB_DEV_REQ_HOST_TO_DEV |
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest = USB_REQ_SET_DESCR;
	setup.wValue = (USB_DESCR_TYPE_KEY << 8) | keyindex;
	setup.wIndex = devindex << 8 | hwahcp->hwahc_wa_data.wa_ifno;
	setup.wLength = (uint16_t)klen;
	setup.attrs = USB_ATTRS_NONE;

	if ((pdata = allocb(klen, BPRI_HI)) == NULL) {

		return (USB_FAILURE);
	}
	bcopy(key_descr, pdata->b_wptr, klen);
	pdata->b_wptr += klen;

	rval = usb_pipe_ctrl_xfer_wait(hwahcp->hwahc_default_pipe, &setup,
	    &pdata, &cr, &cb_flags, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L4(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "hwahc_set_keys:fail, rv=%d,cr=%d,cb=%d", rval, cr,
		    cb_flags);
	}

	freemsg(pdata);

	return (rval);
}

/* set PTK for host */
int
hwahc_set_ptk(dev_info_t *dip, usb_key_descr_t *key_descr, size_t klen,
	usb_port_t port)
{
	hwahc_state_t	*hwahcp;
	int		rval;
	uint8_t		keyindex = 1;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (USB_INVALID_ARGS);
	}
	/* DEVICE INDEX */
	rval = hwahc_set_keys(hwahcp, key_descr, klen, port - 1, keyindex,
	    WUSB_PTK);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_set_ptk: set device key descr for port %d "
		    "failed", port);
	}

	return (rval);
}

/* set GTK for host */
int
hwahc_set_gtk(dev_info_t *dip, usb_key_descr_t *key_descr, size_t klen)
{
	hwahc_state_t		*hwahcp;
	int			rval;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (USB_INVALID_ARGS);
	}

	rval = hwahc_set_keys(hwahcp, key_descr, klen, 0, 0, WUSB_GTK);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_CBOPS, hwahcp->hwahc_log_handle,
		    "hwahc_set_gtk: set group key descr failed");
	}

	return (rval);
}

/*
 * set device info for host
 * Section 8.5.3.7.
 */
int
hwahc_set_device_info(dev_info_t *dip, wusb_dev_info_t *dev_info,
	usb_port_t port)
{
	hwahc_state_t		*hwahcp;
	int			rval;
	hwa_dev_info_t		info;
	usb_ctrl_setup_t	setup;
	usb_cr_t		cr;
	usb_cb_flags_t		cb_flags;
	mblk_t			*pdata;

	if ((hwahcp = ddi_get_soft_state(hwahc_statep,
	    ddi_get_instance(dip))) == NULL) {

		return (USB_INVALID_ARGS);
	}

	/* the device can use all the host's reserved MASes to communicate */
	(void) memcpy(info.bmDeviceAvailablilityInfo,
	    hwahcp->hwahc_hc_data.hc_mas, WUSB_SET_WUSB_MAS_LEN);

	info.bDeviceAddress = dev_info->wdev_addr;

	/* To tell HWA device what data rates this child device supports */
	if (dev_info->wdev_uwb_descr == NULL) {
		/* bitmap, see7.4.1.1. Must support 53.3/106.7/200 Mbps */
		info.wPHYRates[0] = WUSB_DATA_RATE_BIT_53 |
		    WUSB_DATA_RATE_BIT_106 | WUSB_DATA_RATE_BIT_200;
		info.wPHYRates[1] = 0;
	} else {
		info.wPHYRates[0] =
		    dev_info->wdev_uwb_descr->wPHYRates && 0xff;
		info.wPHYRates[1] =
		    (dev_info->wdev_uwb_descr->wPHYRates >> 8) && 0xff;
	}
	info.bmDeviceAttribute = 0;

	setup.bmRequestType = USB_DEV_REQ_HOST_TO_DEV |
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest = HWA_REQ_SET_DEVICE_INFO;
	setup.wValue = 0;

	/* DEVICE INDEX */
	setup.wIndex = (port - 1) << 8 | hwahcp->hwahc_wa_data.wa_ifno;
	setup.wLength = WUSB_SET_DEV_INFO_LEN;
	setup.attrs = USB_ATTRS_NONE;

	if ((pdata = allocb(WUSB_SET_DEV_INFO_LEN, BPRI_HI)) == NULL) {

		return (USB_FAILURE);
	}
	bcopy(&info, pdata->b_wptr, WUSB_SET_DEV_INFO_LEN);
	pdata->b_wptr += WUSB_SET_DEV_INFO_LEN;

	rval = usb_pipe_ctrl_xfer_wait(hwahcp->hwahc_default_pipe, &setup,
	    &pdata, &cr, &cb_flags, USB_FLAGS_SLEEP);

	freemsg(pdata);

	return (rval);
}

/*
 * 8.5.3.2 - 8.5.3.4 Get Time
 * time_type:
 *	WUSB_TIME_ADJ	- Get BPST Adjustment
 *	WUSB_TIME_BPST	- Get BPST Time
 *	WUSB_TIME_WUSB	- Get WUSB Time
 */
int
hwahc_get_time(dev_info_t *dip, uint8_t time_type,
    uint16_t len, uint32_t *time)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	mblk_t		*blk = NULL;
	int		rval;
	uint8_t		*data;
	uint16_t	length;
	hwahc_state_t	*hwahcp = NULL;

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	hwahcp = ddi_get_soft_state(hwahc_statep, ddi_get_instance(dip));
	if (hwahcp == NULL) {

		return (USB_INVALID_ARGS);
	}

	/* according to WUSB 8.5.3, len is 1 or 3 */
	if ((len != 1) && (len != 3)) {

		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, hwahcp->hwahc_default_pipe,
	    WUSB_CLASS_IF_REQ_OUT_TYPE, HWA_REQ_GET_TIME,
	    time_type, hwahcp->hwahc_wa_data.wa_ifno,
	    len, &blk, 0, &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		freemsg(blk);

		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "Get_Time fails: rval=%d cr=%d cb=0x%x",
		    rval, completion_reason, cb_flags);

		return (rval);
	} else if (blk == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, hwahcp->hwahc_log_handle,
		    "Get_Time returns null data");

		return (USB_FAILURE);
	} else {
		length = MBLKL(blk);

		if (length < len) {
			freemsg(blk);

			USB_DPRINTF_L2(PRINT_MASK_HCDI,
			    hwahcp->hwahc_log_handle,
			    "Get_Time returns short length %d", length);

			return (USB_FAILURE);
		}

		data = blk->b_rptr;
		if (len == 1) {
			*time = *data;
		} else {
			*time = (data[2] << 16) | (data[1] << 8) | data[0];
		}
		freemsg(blk);

		return (USB_SUCCESS);
	}
}
