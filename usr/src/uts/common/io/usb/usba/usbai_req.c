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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2019 Joyent, Inc.
 */


/*
 * USBA: Solaris USB Architecture support
 *
 * functions that deal with allocation/free/data_xfers
 * for the  control/bulk/interrupt/isoch pipes:
 *	usb_alloc_ctrl_req()
 *	usb_free_ctrl_req()
 *	usb_pipe_ctrl_xfer()
 *	usb_pipe_sync_ctrl_xfer()
 *	usb_pipe_ctrl_xfer_wait()
 *
 *	usb_alloc_bulk_req()
 *	usb_free_bulk_req()
 *	usb_pipe_bulk_xfer()
 *	usb_pipe_bulk_transfer_size()
 *
 *	usb_alloc_intr_req()
 *	usb_free_intr_req()
 *	usb_pipe_intr_xfer()
 *	usb_pipe_stop_intr_polling()
 *
 *	usb_alloc_isoc_req()
 *	usb_free_isoc_req()
 *	usb_get_current_frame_number()
 *	usb_get_max_isoc_pkts()
 *	usb_pipe_isoc_xfer()
 *	usb_pipe_stop_isoc_polling()
 *
 * XXX to do:
 *	update return values where needed
 *	keep track of requests not freed
 *
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>

/* prototypes */
static int usba_flags_attr_check(usba_pipe_handle_data_t *,
			usb_req_attrs_t attrs, usb_flags_t);
static int _usba_check_req(usba_pipe_handle_data_t *, usb_opaque_t,
			usb_flags_t, uchar_t);

/*
 * usba_check_req:
 *	check pipe, request structure for validity
 *
 * Arguments:
 *	ph		- pipe handle pointer
 *	req		- opaque request pointer
 *	flags		- usb flags
 *
 * Returns:
 *	USB_SUCCESS		- valid request
 *	USB_INVALID_REQUEST	- request contains some invalid values
 *	USB_PIPE_ERROR		- pipe is in error state
 *	USB_INVALID_CONTEXT	- sleep in interrupt context
 *	USB_INVALID_PIPE	- zero pipe or wrong pipe
 */
static int
usba_check_req(usba_pipe_handle_data_t *ph_data, usb_opaque_t req,
		usb_flags_t flags, uchar_t pipe_type)
{
	int rval = _usba_check_req(ph_data, req, flags, pipe_type);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_check_req: ph_data=0x%p req=0x%p flags=0%x rval=%d",
		    (void *)ph_data, (void *)req, flags, rval);
	}

	return (rval);
}


static int
_usba_check_req(usba_pipe_handle_data_t *ph_data, usb_opaque_t req,
		usb_flags_t flags, uchar_t pipe_type)
{
	usb_ctrl_req_t		*ctrl_req = (usb_ctrl_req_t *)req;
	usb_bulk_req_t		*bulk_req = (usb_bulk_req_t *)req;
	usb_intr_req_t		*intr_req = (usb_intr_req_t *)req;
	usb_isoc_req_t		*isoc_req = (usb_isoc_req_t *)req;
	usba_req_wrapper_t	*wrp = USBA_REQ2WRP(req);
	mblk_t			*data;
	usb_cr_t		*cr;
	usb_req_attrs_t		attrs;
	usb_opaque_t		cb = NULL, exc_cb = NULL;
	uint_t			timeout = 0;
	uchar_t			direction = ph_data->p_ep.bEndpointAddress &
	    USB_EP_DIR_MASK;
	uchar_t			ep_attrs = ph_data->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK;
	int			n;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_check_req: ph_data=0x%p req=0x%p flags=0x%x",
	    (void *)ph_data, (void *)req, flags);

	if (req == NULL) {

		return (USB_INVALID_ARGS);
	}

	/* set completion reason first so it specifies an error */
	switch (ep_attrs) {
	case USB_EP_ATTR_CONTROL:
		cr = &ctrl_req->ctrl_completion_reason;
		break;
	case USB_EP_ATTR_BULK:
		cr = &bulk_req->bulk_completion_reason;
		break;
	case USB_EP_ATTR_INTR:
		cr = &intr_req->intr_completion_reason;
		break;
	case USB_EP_ATTR_ISOCH:
		cr = &isoc_req->isoc_completion_reason;
		break;
	default:
		return (USB_INVALID_REQUEST);
	}

	*cr = USB_CR_UNSPECIFIED_ERR;

	if (servicing_interrupt() && (flags & USB_FLAGS_SLEEP)) {

		return (USB_INVALID_CONTEXT);
	}

	if (pipe_type != ep_attrs) {

		return (USB_INVALID_PIPE);
	}

	/* we must have usba_device and default ph to do autoclearing */
	ASSERT(ph_data->p_usba_device);

	if (ph_data->p_usba_device->usb_ph_list[0].usba_ph_data == NULL) {

		return (USB_INVALID_PIPE);
	}

	/* check if this is a valid request packet, ie. not freed */
	if (usba_check_in_list(&(ph_data->p_usba_device->usb_allocated),
	    &wrp->wr_allocated_list) != USB_SUCCESS) {

		return (USB_INVALID_REQUEST);
	}

	/* copy over some members for easy checking later */
	switch (ep_attrs) {
	case USB_EP_ATTR_CONTROL:
		ctrl_req->ctrl_cb_flags = USB_CB_NO_INFO;
		data = ctrl_req->ctrl_data;
		attrs = ctrl_req->ctrl_attributes;
		timeout = ctrl_req->ctrl_timeout;
		cb = (usb_opaque_t)ctrl_req->ctrl_cb;
		exc_cb = (usb_opaque_t)ctrl_req->ctrl_exc_cb;
		if (flags & USB_FLAGS_SLEEP) {
			flags |= USBA_WRP_FLAGS_WAIT;
		}
		/* force auto clearing on the default pipe */
		if (USBA_IS_DEFAULT_PIPE(ph_data)) {
			attrs |= USB_ATTRS_AUTOCLEARING;
		}
		break;
	case USB_EP_ATTR_BULK:
		bulk_req->bulk_cb_flags = USB_CB_NO_INFO;
		data = bulk_req->bulk_data;
		attrs = bulk_req->bulk_attributes;
		timeout = bulk_req->bulk_timeout;
		cb = (usb_opaque_t)bulk_req->bulk_cb;
		exc_cb = (usb_opaque_t)bulk_req->bulk_exc_cb;
		if (flags & USB_FLAGS_SLEEP) {
			flags |= USBA_WRP_FLAGS_WAIT;
		}
		break;
	case USB_EP_ATTR_INTR:
		intr_req->intr_cb_flags = USB_CB_NO_INFO;
		data = intr_req->intr_data;
		attrs = intr_req->intr_attributes;
		timeout = intr_req->intr_timeout;
		cb = (usb_opaque_t)intr_req->intr_cb;
		exc_cb = (usb_opaque_t)intr_req->intr_exc_cb;
		if ((flags & USB_FLAGS_SLEEP) &&
		    (attrs & USB_ATTRS_ONE_XFER)) {
			flags |= USBA_WRP_FLAGS_WAIT;
		}
		break;
	case USB_EP_ATTR_ISOCH:
		isoc_req->isoc_cb_flags = USB_CB_NO_INFO;
		data = isoc_req->isoc_data;
		attrs = isoc_req->isoc_attributes;
		cb = (usb_opaque_t)isoc_req->isoc_cb;
		exc_cb = (usb_opaque_t)isoc_req->isoc_exc_cb;
		break;
	default:
		return (USB_INVALID_REQUEST);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_check_req: attrs = 0x%x flags=0x%x", attrs, flags);

	/* check flags and attr combinations */
	if (usba_flags_attr_check(ph_data, attrs, flags) !=
	    USB_SUCCESS) {

		return (USB_INVALID_REQUEST);
	}

	/* if no sleep, there must be callback ptrs */
	if ((flags & USB_FLAGS_SLEEP) == 0) {
		if (cb == NULL || exc_cb == NULL) {

			return (USB_INVALID_REQUEST);
		}
	}

	switch (ep_attrs) {
	case USB_EP_ATTR_CONTROL:
		if (ctrl_req->ctrl_wLength && (data == NULL)) {

			return (USB_INVALID_REQUEST);
		}
		break;
	case USB_EP_ATTR_BULK:
		if ((bulk_req->bulk_len) && (data == NULL)) {

			return (USB_INVALID_REQUEST);
		}
		break;
	case USB_EP_ATTR_INTR:
		if (direction == USB_EP_DIR_OUT) {
			if (intr_req->intr_len && data == NULL) {

				return (USB_INVALID_REQUEST);
			}
		}

		if (direction == USB_EP_DIR_IN) {
			if (!(intr_req->intr_attributes & USB_ATTRS_ONE_XFER)) {
				if (cb == NULL || exc_cb == NULL) {

					return (USB_INVALID_REQUEST);
				}
			}
			if (data != NULL) {

				return (USB_INVALID_REQUEST);
			}
			if (!(intr_req->intr_attributes & USB_ATTRS_ONE_XFER) &&
			    (timeout > 0)) {

				return (USB_INVALID_REQUEST);
			}
		}
		break;
	case USB_EP_ATTR_ISOCH:
		if (direction == USB_EP_DIR_IN) {
			if (cb == NULL || exc_cb == NULL) {

				return (USB_INVALID_REQUEST);
			}
		}

		if (data == NULL) {

			return (USB_INVALID_REQUEST);
		}

		/*
		 * Since ehci/ohci/uhci use (data->b_wptr - data->b_rptr) as
		 * real isoc_pkts_length, it should be checked.
		 */
		if (direction == USB_EP_DIR_OUT) {
			if (MBLKL(data) <= 0) {

				return (USB_INVALID_REQUEST);
			}
		}

		/* special isoc checks */
		if ((isoc_req->isoc_pkts_count == 0) ||
		    (isoc_req->isoc_pkt_descr == NULL)) {

			return (USB_INVALID_REQUEST);
		}

		/* check attributes for conflicts, one must be specified */
		if (!((isoc_req->isoc_attributes &
		    USB_ATTRS_ISOC_START_FRAME) ||
		    (isoc_req->isoc_attributes & USB_ATTRS_ISOC_XFER_ASAP))) {

			return (USB_NO_FRAME_NUMBER);
		}

		/* both may not be specified */
		if ((isoc_req->isoc_attributes &
		    (USB_ATTRS_ISOC_START_FRAME | USB_ATTRS_ISOC_XFER_ASAP)) ==
		    (USB_ATTRS_ISOC_START_FRAME | USB_ATTRS_ISOC_XFER_ASAP)) {

			return (USB_NO_FRAME_NUMBER);
		}

		/* no start frame may be specified for ASAP attribute */
		if (((isoc_req->isoc_attributes & USB_ATTRS_ISOC_XFER_ASAP)) &&
		    isoc_req->isoc_frame_no) {

			return (USB_INVALID_REQUEST);
		}

		/* start frame must be specified for START FRAME attribute */
		if (((isoc_req->isoc_attributes &
		    USB_ATTRS_ISOC_START_FRAME)) &&
		    (isoc_req->isoc_frame_no == 0)) {

			return (USB_NO_FRAME_NUMBER);
		}

		/* each packet must have initialized pkt length */
		for (n = 0; n < isoc_req->isoc_pkts_count; n++) {
			if (isoc_req->isoc_pkt_descr[n].isoc_pkt_length == 0) {

				return (USB_INVALID_REQUEST);
			}
		}
		break;
	}

	/* save pipe_handle/attrs/timeout/usb_flags */
	wrp->wr_ph_data		= ph_data;
	wrp->wr_usb_flags	= flags;
	wrp->wr_attrs		= attrs;

	/* zero some fields in case the request is reused */
	wrp->wr_done		= B_FALSE;
	wrp->wr_cr		= USB_CR_OK;

	/* this request looks good */
	*cr = USB_CR_OK;

	return (USB_SUCCESS);
}


/*
 * Table of invalid flags and attributes values. See "usbai.h"
 * for a complete table on valid usb_req_attrs_t
 */
#define	X	((uint_t)(-1))
#define	OUT	USB_EP_DIR_OUT
#define	IN	USB_EP_DIR_IN

struct	flags_attr {
	uint_t		ep_dir;
	uint_t		ep_attr;
	uint_t		usb_flags;	/* usb_flags SLEEP or none */
	uint_t		attrs;
} usb_invalid_flags_attrs[] = {
{ OUT,	USB_EP_ATTR_BULK,	X,	USB_ATTRS_SHORT_XFER_OK },
{ OUT,	USB_EP_ATTR_INTR,	X,	USB_ATTRS_SHORT_XFER_OK },
{ OUT,	USB_EP_ATTR_ISOCH,	X,	USB_ATTRS_SHORT_XFER_OK },

{ X,	USB_EP_ATTR_CONTROL,	X,	USB_ATTRS_ISOC_START_FRAME },
{ X,	USB_EP_ATTR_BULK,	X,	USB_ATTRS_ISOC_START_FRAME },
{ X,	USB_EP_ATTR_INTR,	X,	USB_ATTRS_ISOC_START_FRAME },

{ X,	USB_EP_ATTR_CONTROL,	X,	USB_ATTRS_ISOC_XFER_ASAP },
{ X,	USB_EP_ATTR_INTR,	X,	USB_ATTRS_ISOC_XFER_ASAP },
{ OUT,	USB_EP_ATTR_INTR,	X,	USB_ATTRS_ONE_XFER },
{ X,	USB_EP_ATTR_BULK,	X,	USB_ATTRS_ISOC_XFER_ASAP },

{ X,	USB_EP_ATTR_CONTROL,	X,	USB_ATTRS_ONE_XFER },
{ X,	USB_EP_ATTR_BULK,	X,	USB_ATTRS_ONE_XFER },
{ X,	USB_EP_ATTR_ISOCH,	X,	USB_ATTRS_ONE_XFER },
};

#define	N_INVALID_FLAGS_ATTRS	(sizeof (usb_invalid_flags_attrs))/ \
					sizeof (struct flags_attr)

/*
 * function to check flags and attribute combinations for a particular pipe
 * Arguments:
 *	ph	- pipe handle pointer
 *	attrs	- attributes of the request
 *	flags	- usb_flags
 */
static int
usba_flags_attr_check(usba_pipe_handle_data_t *ph_data,
		usb_req_attrs_t attrs,
		usb_flags_t flags)
{
	uchar_t i;
	uchar_t	ep_dir = ph_data->p_ep.bEndpointAddress & USB_EP_DIR_MASK;
	uchar_t ep_attr = ph_data->p_ep.bmAttributes & USB_EP_ATTR_MASK;

	flags &= USB_FLAGS_SLEEP; /* ignore other flags */

	/*
	 * Do some attributes validation checks here.
	 */
	for (i = 0; i < N_INVALID_FLAGS_ATTRS; i++) {
		if (((ep_dir == usb_invalid_flags_attrs[i].ep_dir) ||
		    (usb_invalid_flags_attrs[i].ep_dir == X)) &&
		    ((ep_attr == usb_invalid_flags_attrs[i].ep_attr) ||
		    (usb_invalid_flags_attrs[i].ep_attr == X)) &&
		    ((flags & usb_invalid_flags_attrs[i].usb_flags) ||
		    (usb_invalid_flags_attrs[i].usb_flags == X)) &&
		    ((attrs & usb_invalid_flags_attrs[i].attrs) ||
		    (usb_invalid_flags_attrs[i].attrs == X))) {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
			    "invalid (%d) : flags = 0x%x, attrs = 0x%x",
			    i, flags, attrs);

			return (USB_INVALID_REQUEST);
		}
	}

	return (USB_SUCCESS);
}


/*
 * usba_rval2cr:
 *	convert rval to meaningful completion reason
 * XXX extend completion reasons to get better mapping
 */
static struct {
	int	rval;
	usb_cr_t cr;
} rval2cr[] = {
	{USB_SUCCESS,		USB_CR_OK},
	{USB_FAILURE,		USB_CR_UNSPECIFIED_ERR},
	{USB_NO_RESOURCES,	USB_CR_NO_RESOURCES},
	{USB_NO_BANDWIDTH,	USB_CR_NO_RESOURCES},
	{USB_NOT_SUPPORTED,	USB_CR_UNSPECIFIED_ERR},
	{USB_PIPE_ERROR,	USB_CR_UNSPECIFIED_ERR},
	{USB_INVALID_PIPE,	USB_CR_UNSPECIFIED_ERR},
	{USB_NO_FRAME_NUMBER,	USB_CR_UNSPECIFIED_ERR},
	{USB_INVALID_START_FRAME, USB_CR_UNSPECIFIED_ERR},
	{USB_HC_HARDWARE_ERROR, USB_CR_UNSPECIFIED_ERR},
	{USB_INVALID_REQUEST,	USB_CR_UNSPECIFIED_ERR},
	{USB_INVALID_CONTEXT,	USB_CR_UNSPECIFIED_ERR},
	{USB_INVALID_VERSION,	USB_CR_UNSPECIFIED_ERR},
	{USB_INVALID_ARGS,	USB_CR_UNSPECIFIED_ERR},
	{USB_INVALID_PERM,	USB_CR_UNSPECIFIED_ERR},
	{USB_BUSY,		USB_CR_UNSPECIFIED_ERR},
	{0xffff,		0}
};

usb_cr_t
usba_rval2cr(int rval)
{
	int i;

	for (i = 0; rval2cr[i].rval != 0xffff; i++) {
		if (rval2cr[i].rval == rval) {

			return (rval2cr[i].cr);
		}
	}

	return (USB_CR_UNSPECIFIED_ERR);
}


/*
 * usba_start_next_req:
 *	Arguments:
 *	ph_data		- pointer to pipe handle
 *
 * Currently, only ctrl/bulk requests can be queued
 */
void
usba_start_next_req(usba_pipe_handle_data_t *ph_data)
{
	usb_ctrl_req_t		*ctrl_req;
	usb_bulk_req_t		*bulk_req;
	usba_req_wrapper_t	*wrp;
	uchar_t			ep_attrs = ph_data->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK;
	int			rval;
	usb_pipe_state_t	state;

	mutex_enter(&ph_data->p_mutex);
	switch (ep_attrs) {
	case USB_EP_ATTR_CONTROL:
	case USB_EP_ATTR_BULK:
		switch (usba_get_ph_state(ph_data)) {
		case USB_PIPE_STATE_IDLE:
		case USB_PIPE_STATE_CLOSING:

			break;

		default:
			mutex_exit(&ph_data->p_mutex);

			return;
		}

		break;
	case USB_EP_ATTR_ISOCH:
	case USB_EP_ATTR_INTR:
	default:
		mutex_exit(&ph_data->p_mutex);

		return;
	}

	while ((wrp = (usba_req_wrapper_t *)
	    usba_rm_first_pvt_from_list(&ph_data->p_queue)) != NULL) {

		/* only submit to HCD when idle/active */

		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_start_next_req: ph_data=0x%p state=%d",
		    (void *)ph_data, usba_get_ph_state(ph_data));

		if (ep_attrs == USB_EP_ATTR_CONTROL) {
			ph_data->p_active_cntrl_req_wrp = (usb_opaque_t)wrp;
		}

		if ((state = usba_get_ph_state(ph_data)) ==
		    USB_PIPE_STATE_IDLE) {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_ACTIVE);

			USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
			    "starting req = 0x%p",
			    (void *)USBA_WRP2CTRL_REQ(wrp));

			switch (ep_attrs) {
			case USB_EP_ATTR_CONTROL:
				mutex_exit(&ph_data->p_mutex);
				ctrl_req = USBA_WRP2CTRL_REQ(wrp);
				/* submit to hcd */
				rval = ph_data->p_usba_device->usb_hcdi_ops->
				    usba_hcdi_pipe_ctrl_xfer(ph_data,
				    ctrl_req, wrp->wr_usb_flags);
				mutex_enter(&ph_data->p_mutex);
				break;
			case USB_EP_ATTR_BULK:
				mutex_exit(&ph_data->p_mutex);
				bulk_req = USBA_WRP2BULK_REQ(wrp);
				/* submit to hcd */
				rval = ph_data->p_usba_device->usb_hcdi_ops->
				    usba_hcdi_pipe_bulk_xfer(ph_data,
				    bulk_req, wrp->wr_usb_flags);
				mutex_enter(&ph_data->p_mutex);
				break;
			default:
				/* there shouldn't be any requests */
				rval = USB_FAILURE;
				break;
			}

			if (rval != USB_SUCCESS) {
				mutex_exit(&ph_data->p_mutex);
				usba_do_req_exc_cb(wrp,
				    usba_rval2cr(rval),
				    USB_CB_SUBMIT_FAILED);
				mutex_enter(&ph_data->p_mutex);
			}
			/* we are done */
			break;

		} else {
			mutex_exit(&ph_data->p_mutex);
			switch (state) {
			case USB_PIPE_STATE_CLOSING:
				usba_do_req_exc_cb(wrp, USB_CR_PIPE_CLOSING, 0);
				break;
			case USB_PIPE_STATE_ERROR:
			default:
				usba_do_req_exc_cb(wrp, USB_CR_FLUSHED, 0);
				break;
			}
			mutex_enter(&ph_data->p_mutex);
		}
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_start_next_req done: ph_data=0x%p state=%d", (void *)ph_data,
	    usba_get_ph_state(ph_data));

	mutex_exit(&ph_data->p_mutex);
}


/*
 * usba_req_wrapper_alloc:
 *	Allocate + Initialize a usba_req_wrapper_t
 *
 * Arguments:
 *	dip	-  dev_info_t of the client driver
 *	req_len	-  sizeof request
 *	flags	-
 *		USB_FLAGS_SLEEP    - Sleep if resources are not available
 *		no USB_FLAGS_SLEEP - Don't Sleep if resources are not available
 *
 * Return Values:
 *	pointer to usba_req_wrapper_t on success; NULL on failure.
 *
 */
static usba_req_wrapper_t *
usba_req_wrapper_alloc(dev_info_t	*dip,
			size_t		req_len,
			usb_flags_t	flags)
{
	int		kmflag;
	usba_device_t	*usba_device = usba_get_usba_device(dip);
	usba_req_wrapper_t *wrp;
	size_t		wr_length = sizeof (usba_req_wrapper_t) + req_len;
	ddi_iblock_cookie_t iblock_cookie =
	    usba_hcdi_get_hcdi(usba_device->usb_root_hub_dip)->
	    hcdi_iblock_cookie;

	if (servicing_interrupt() && (flags & USB_FLAGS_SLEEP)) {

		return (NULL);
	}

	kmflag = (flags & USB_FLAGS_SLEEP) ? KM_SLEEP : KM_NOSLEEP;

	/* Allocate the usb_{c/b/i/i}_req + usba_req_wrapper_t structure */
	if ((wrp = kmem_zalloc(wr_length, kmflag)) != NULL) {
		wrp->wr_length	= wr_length;
		wrp->wr_dip	= dip;
		wrp->wr_req = (usb_opaque_t)USBA_SETREQ_ADDR(wrp);
		cv_init(&wrp->wr_cv, NULL, CV_DRIVER, NULL);

		/* initialize mutex for the queue */
		usba_init_list(&wrp->wr_queue, (usb_opaque_t)wrp,
		    iblock_cookie);
		usba_init_list(&wrp->wr_allocated_list, (usb_opaque_t)wrp,
		    iblock_cookie);

		usba_add_to_list(&usba_device->usb_allocated,
		    &wrp->wr_allocated_list);

		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_req_wrapper_alloc: wrp = 0x%p", (void *)wrp);
	}

	return (wrp);
}


/*
 * usba_req_wrapper_free:
 *	Frees a usba_req_wrapper_t. Get rid of lists if any.
 *
 * Arguments:
 *	wrp: request wrapper structure
 */
void
usba_req_wrapper_free(usba_req_wrapper_t *wrp)
{
	usba_device_t		*usba_device;
	usba_pipe_handle_data_t	*ph_data;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_req_wrapper_free: wrp=0x%p", (void *)wrp);

	if (wrp) {
		/* remove from	queues */
		ph_data = USBA_WRP2PH_DATA(wrp);
		if (ph_data) {
			(void) usba_rm_from_list(&ph_data->p_queue,
			    &wrp->wr_queue);
		}
		usba_device = usba_get_usba_device(wrp->wr_dip);
		if (usba_rm_from_list(&usba_device->usb_allocated,
		    &wrp->wr_allocated_list) != USB_SUCCESS) {
			cmn_err(CE_PANIC,
			    "usba_req_wrapper_free: data corruption");
		}
		usba_destroy_list(&wrp->wr_queue);
		usba_destroy_list(&wrp->wr_allocated_list);
		cv_destroy(&wrp->wr_cv);
		kmem_free(wrp, wrp->wr_length);
	}
}


/*
 * usba_check_intr_context
 *	Set USB_CB_INTR_CONTEXT callback flag if executing in interrupt context
 */
usb_cb_flags_t
usba_check_intr_context(usb_cb_flags_t cb_flags)
{
	if (servicing_interrupt() != 0) {
		cb_flags |= USB_CB_INTR_CONTEXT;
	}

	return (cb_flags);
}


/*
 * usba_req_normal_cb:
 *	perform normal callback depending on request type
 */
void
usba_req_normal_cb(usba_req_wrapper_t *req_wrp)
{
	usba_pipe_handle_data_t	*ph_data = req_wrp->wr_ph_data;
	usb_pipe_handle_t	pipe_handle;
	uint_t			direction = ph_data->p_ep.bEndpointAddress &
	    USB_EP_DIR_MASK;
	usb_pipe_state_t	pipe_state;

	pipe_handle = usba_get_pipe_handle(ph_data);

	mutex_enter(&ph_data->p_mutex);
	ASSERT(ph_data->p_req_count >= 0);
	pipe_state = usba_get_ph_state(ph_data);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_req_normal_cb: "
	    "ph_data=0x%p state=%d wrp=0x%p ref=%d req=%d",
	    (void *)ph_data, pipe_state, (void *)req_wrp,
	    usba_get_ph_ref_count(ph_data), ph_data->p_req_count);

	ASSERT((pipe_state == USB_PIPE_STATE_ACTIVE) ||
	    (pipe_state == USB_PIPE_STATE_CLOSING));

	/* set done to indicate that we will do callback or cv_signal */
	ASSERT(req_wrp->wr_done == B_FALSE);
	req_wrp->wr_done = B_TRUE;

	/* update the pipe state */
	switch (req_wrp->wr_ph_data->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
	case USB_EP_ATTR_BULK:
		usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
		break;
	case USB_EP_ATTR_INTR:
		if ((direction == USB_EP_DIR_IN) &&
		    (USBA_WRP2INTR_REQ(req_wrp)->intr_attributes &
		    USB_ATTRS_ONE_XFER)) {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
		} else if ((direction == USB_EP_DIR_OUT) &&
		    (ph_data->p_req_count == 0)) {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
		}
		break;
	case USB_EP_ATTR_ISOCH:
		if ((ph_data->p_req_count == 0) &&
		    (direction == USB_EP_DIR_OUT)) {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
		}
		break;
	}


	/* now complete the request */
	if (req_wrp->wr_usb_flags & USBA_WRP_FLAGS_WAIT) {
		ph_data->p_active_cntrl_req_wrp = NULL;
		cv_signal(&req_wrp->wr_cv);
		mutex_exit(&ph_data->p_mutex);
	} else {
		mutex_exit(&ph_data->p_mutex);

		/* This sets USB_CB_INTR_CONTEXT as needed. */
		usba_req_set_cb_flags(req_wrp, USB_CB_NO_INFO);

		switch (req_wrp->wr_ph_data->p_ep.bmAttributes &
		    USB_EP_ATTR_MASK) {
		case USB_EP_ATTR_CONTROL:
			USBA_WRP2CTRL_REQ(req_wrp)->ctrl_cb(pipe_handle,
			    USBA_WRP2CTRL_REQ(req_wrp));
			mutex_enter(&ph_data->p_mutex);
			ph_data->p_active_cntrl_req_wrp = NULL;
			mutex_exit(&ph_data->p_mutex);
			break;
		case USB_EP_ATTR_INTR:
			USBA_WRP2INTR_REQ(req_wrp)->intr_cb(pipe_handle,
			    USBA_WRP2INTR_REQ(req_wrp));
			break;
		case USB_EP_ATTR_BULK:
			USBA_WRP2BULK_REQ(req_wrp)->bulk_cb(pipe_handle,
			    USBA_WRP2BULK_REQ(req_wrp));
			break;
		case USB_EP_ATTR_ISOCH:
			USBA_WRP2ISOC_REQ(req_wrp)->isoc_cb(pipe_handle,
			    USBA_WRP2ISOC_REQ(req_wrp));
			break;
		}
	}

	/* we are done with this request */
	mutex_enter(&ph_data->p_mutex);
	ph_data->p_req_count--;
	ASSERT(ph_data->p_req_count >= 0);
	mutex_exit(&ph_data->p_mutex);
}


/*
 * usba_req_exc_cb:
 *	perform exception cb depending on request type.
 *	ensure the completion reason is non zero
 */
void
usba_req_exc_cb(usba_req_wrapper_t *req_wrp, usb_cr_t cr,
    usb_cb_flags_t cb_flags)
{
	usba_pipe_handle_data_t *ph_data = req_wrp->wr_ph_data;
	usb_pipe_handle_t pipe_handle = usba_get_pipe_handle(ph_data);

	mutex_enter(&req_wrp->wr_ph_data->p_mutex);
	USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_req_exc_cb: %s%d: ph_data=0x%p (ep%x) state=%d wrp=0x%p "
	    "ref=%d reqcnt=%d cr=%d",
	    ddi_driver_name(req_wrp->wr_dip),
	    ddi_get_instance(req_wrp->wr_dip),
	    (void *)ph_data, ph_data->p_ep.bEndpointAddress,
	    usba_get_ph_state(ph_data), (void *)req_wrp,
	    usba_get_ph_ref_count(ph_data), ph_data->p_req_count,
	    req_wrp->wr_cr);

	ASSERT(req_wrp->wr_ph_data->p_req_count >= 0);

	usba_req_set_cb_flags(req_wrp, cb_flags);

	/* if there was no CR set already, set it now */
	if (req_wrp->wr_cr == USB_CR_OK) {
		req_wrp->wr_cr = (cr != USB_CR_OK)  ?
		    cr : USB_CR_UNSPECIFIED_ERR;
	}

	ASSERT(req_wrp->wr_done == B_FALSE);
	req_wrp->wr_done = B_TRUE;

	switch (req_wrp->wr_ph_data->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		if (USBA_WRP2CTRL_REQ(req_wrp)->
		    ctrl_completion_reason == USB_CR_OK) {
			USBA_WRP2CTRL_REQ(req_wrp)->
			    ctrl_completion_reason = req_wrp->wr_cr;
		}
		break;
	case USB_EP_ATTR_INTR:
		if (USBA_WRP2INTR_REQ(req_wrp)->
		    intr_completion_reason == USB_CR_OK) {
			USBA_WRP2INTR_REQ(req_wrp)->
			    intr_completion_reason = req_wrp->wr_cr;
		}
		break;
	case USB_EP_ATTR_BULK:
		if (USBA_WRP2BULK_REQ(req_wrp)->
		    bulk_completion_reason == USB_CR_OK) {
			USBA_WRP2BULK_REQ(req_wrp)->
			    bulk_completion_reason = req_wrp->wr_cr;
		}
		break;
	case USB_EP_ATTR_ISOCH:
		if (USBA_WRP2ISOC_REQ(req_wrp)->
		    isoc_completion_reason == USB_CR_OK) {
			USBA_WRP2ISOC_REQ(req_wrp)->
			    isoc_completion_reason = req_wrp->wr_cr;
		}
		break;
	}

	if (req_wrp->wr_usb_flags & USBA_WRP_FLAGS_WAIT) {
		cv_signal(&req_wrp->wr_cv);
		if (ph_data->p_active_cntrl_req_wrp == (usb_opaque_t)req_wrp) {
			ph_data->p_active_cntrl_req_wrp = NULL;
		}
		mutex_exit(&ph_data->p_mutex);
	} else {
		mutex_exit(&ph_data->p_mutex);
		switch (req_wrp->wr_ph_data->p_ep.bmAttributes &
		    USB_EP_ATTR_MASK) {
		case USB_EP_ATTR_CONTROL:
			USBA_WRP2CTRL_REQ(req_wrp)->ctrl_exc_cb(pipe_handle,
			    USBA_WRP2CTRL_REQ(req_wrp));
			mutex_enter(&ph_data->p_mutex);
			if (ph_data->p_active_cntrl_req_wrp ==
			    (usb_opaque_t)req_wrp) {
				ph_data->p_active_cntrl_req_wrp = NULL;
			}
			mutex_exit(&ph_data->p_mutex);
			break;
		case USB_EP_ATTR_INTR:
			USBA_WRP2INTR_REQ(req_wrp)->intr_exc_cb(pipe_handle,
			    USBA_WRP2INTR_REQ(req_wrp));
			break;
		case USB_EP_ATTR_BULK:
			USBA_WRP2BULK_REQ(req_wrp)->bulk_exc_cb(pipe_handle,
			    USBA_WRP2BULK_REQ(req_wrp));
			break;
		case USB_EP_ATTR_ISOCH:
			USBA_WRP2ISOC_REQ(req_wrp)->isoc_exc_cb(pipe_handle,
			    USBA_WRP2ISOC_REQ(req_wrp));
			break;
		}
	}

	/* we are done with this request */
	mutex_enter(&ph_data->p_mutex);
	ph_data->p_req_count--;
	ASSERT(ph_data->p_req_count >= 0);
	mutex_exit(&ph_data->p_mutex);
}


/*
 * usba_do_req_exc_cb:
 *	called when flushing requests. rather than calling usba_req_exc_cb()
 *	directly, this function uses usba_hcdi_cb() which ensures callback
 *	order is preserved
 */
void
usba_do_req_exc_cb(usba_req_wrapper_t *req_wrp, usb_cr_t cr,
    usb_cb_flags_t cb_flags)
{
	req_wrp->wr_cb_flags |= cb_flags;
	usba_hcdi_cb(req_wrp->wr_ph_data, req_wrp->wr_req, cr);
}


/*
 * usba_req_set_cb_flags:
 * This function sets the request's callback flags to those stored in the
 * request wrapper ORed with those received as an argument.  Additionally
 * USB_CB_INTR_CONTEXT is set if called from interrupt context.
 *
 * NOTE: The xfer may have succeeded, which client driver can determine
 * by looking at usb_cr_t
 */
void
usba_req_set_cb_flags(usba_req_wrapper_t *req_wrp,
		usb_cb_flags_t cb_flags)
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_req_set_cb_flags: wrp=0x%p cb-flags=0x%x",
	    (void *)req_wrp, cb_flags);

	cb_flags |= req_wrp->wr_cb_flags;
	cb_flags = usba_check_intr_context(cb_flags);

	/* do the callback under taskq context */
	switch (req_wrp->wr_ph_data->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		USBA_WRP2CTRL_REQ(req_wrp)->ctrl_cb_flags |= cb_flags;
		break;
	case USB_EP_ATTR_INTR:
		USBA_WRP2INTR_REQ(req_wrp)->intr_cb_flags |= cb_flags;
		break;
	case USB_EP_ATTR_BULK:
		USBA_WRP2BULK_REQ(req_wrp)->bulk_cb_flags |= cb_flags;
		break;
	case USB_EP_ATTR_ISOCH:
		USBA_WRP2ISOC_REQ(req_wrp)->isoc_cb_flags |= cb_flags;
		break;
	}
}


/*
 * usba_pipe_sync_wait:
 *	wait for the request to finish.
 *	usba_hcdi_cb() does a cv_signal thru a soft intr
 *
 * Arguments:
 *	ph_data		- pointer to pipe handle data
 *	wrp		- pointer to usba_req_wrapper_structure.
 *
 * Return Values:
 *	USB_SUCCESS	- request successfully executed
 *	USB_FAILURE	- request failed
 */
static int
usba_pipe_sync_wait(usba_pipe_handle_data_t	*ph_data,
		usba_req_wrapper_t	*wrp)
{
	ASSERT(wrp->wr_usb_flags & USB_FLAGS_SLEEP);
	ASSERT(ph_data == wrp->wr_ph_data);

	mutex_enter(&ph_data->p_mutex);
	while (wrp->wr_done != B_TRUE) {
		cv_wait(&wrp->wr_cv, &ph_data->p_mutex);
	}

	mutex_exit(&ph_data->p_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_sync_wait: ph_data=0x%p cr=0x%x", (void *)ph_data,
	    wrp->wr_cr);

	/* XXX return something better than USB_FAILURE?? */

	return (wrp->wr_cr == USB_CR_OK ? USB_SUCCESS : USB_FAILURE);
}


/*
 * Allocate usb control request and a USB request wrapper
 *
 * Arguments:
 *	dip	- dev_info_t of the client driver
 *	len	- length of "data" for this control request
 *	flags:
 *		USB_FLAGS_SLEEP	- Sleep if resources are not available
 *		no USB_FLAGS_SLEEP - Don't Sleep if resources are not available
 *
 * Return Values:	usb_ctrl_req_t on success, NULL on failure
 */
usb_ctrl_req_t *
usb_alloc_ctrl_req(dev_info_t	*dip,
		size_t		len,
		usb_flags_t	flags)
{
	usb_ctrl_req_t	*ctrl_req = NULL;
	usba_req_wrapper_t	*wrp;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_alloc_ctrl_req: dip=0x%p, wlen=0x%lx, flags=0x%x",
	    (void *)dip, len, flags);

	/* Allocate + Initialize the usba_req_wrapper_t structure */
	if (dip &&
	    ((wrp = usba_req_wrapper_alloc(dip, sizeof (*ctrl_req), flags)) !=
	    NULL)) {
		ctrl_req = USBA_WRP2CTRL_REQ(wrp);

		/* Allocate the usb_ctrl_req data mblk */
		if (len) {
			if (flags & USB_FLAGS_SLEEP) {
				ctrl_req->ctrl_data = allocb_wait(len, BPRI_LO,
				    STR_NOSIG, NULL);
			} else	if ((ctrl_req->ctrl_data =
			    allocb(len, BPRI_HI)) == NULL) {
				usba_req_wrapper_free(wrp);
				ctrl_req = NULL;
			}
		}
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_alloc_ctrl_req: ctrl_req = 0x%p", (void *)ctrl_req);

	return (ctrl_req);
}


/*
 * usb_free_ctrl_req:
 *	free USB control request + wrapper
 *
 * Arguments:
 *	req - pointer to usb_ctrl_req_t
 */
void
usb_free_ctrl_req(usb_ctrl_req_t *req)
{
	if (req) {
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_free_ctrl_req: req = 0x%p", (void *)req);

		if (req->ctrl_data) {
			freemsg(req->ctrl_data);
		}
		usba_req_wrapper_free(USBA_REQ2WRP(req));
	}
}


/*
 * Client driver calls this function to issue the control
 * request to the USBA
 *
 * Arguments:
 *	pipe_handle:  control pipe pipehandle (obtained via usb_pipe_open()
 *	req: control request
 *	usb_flags:
 *		USB_FLAGS_SLEEP - wait for the request to complete
 *
 * Return Values:
 *	USB_SUCCESS	- request successfully executed
 *	USB_FAILURE	- request failed
 */
int
usb_pipe_ctrl_xfer(usb_pipe_handle_t	pipe_handle,
		usb_ctrl_req_t		*req,
		usb_flags_t		usb_flags)
{
	int			rval;
	usba_req_wrapper_t	*wrp = USBA_REQ2WRP(req);
	usba_pipe_handle_data_t	*ph_data = usba_hold_ph_data(pipe_handle);
	usba_device_t		*usba_device;
	usb_flags_t		wrp_usb_flags;
	usb_pipe_state_t	pipe_state;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_ctrl_xfer: req=0x%p, wrp=0x%p\n\t"
	    "setup = 0x%x 0x%x 0x%x 0x%x 0x%x uf=0x%x",
	    (void *)req, (void *)wrp, req->ctrl_bmRequestType,
	    req->ctrl_bRequest, req->ctrl_wValue, req->ctrl_wIndex,
	    req->ctrl_wLength, usb_flags);

	if (ph_data == NULL) {

		return (USB_INVALID_PIPE);
	}

	mutex_enter(&ph_data->p_mutex);
	usba_device = ph_data->p_usba_device;

	if ((rval = usba_check_req(ph_data, (usb_opaque_t)req, usb_flags,
	    USB_EP_ATTR_CONTROL)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "request rejected: rval=%d", rval);
		mutex_exit(&ph_data->p_mutex);

		usba_release_ph_data(ph_data->p_ph_impl);

		return (rval);
	}

	ASSERT(ph_data == wrp->wr_ph_data);

	/* we accepted the request, so increment the req count */
	ph_data->p_req_count++;

	wrp_usb_flags = wrp->wr_usb_flags;

	/* Get the current bulk pipe state */
	pipe_state = usba_get_ph_state(ph_data);

	/*
	 * if this is for the default pipe, and the pipe is in error,
	 * just queue the request. autoclearing will start this request
	 *
	 * if there is already an active request in the queue
	 * then just add this request to the queue.
	 */
	switch (pipe_state) {
	case USB_PIPE_STATE_IDLE:
		if (ph_data->p_queue.next ||
		    ph_data->p_active_cntrl_req_wrp) {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_pipe_ctrl_xfer: queue request 0x%p",
			    (void *)req);

			usba_add_to_list(&ph_data->p_queue, &wrp->wr_queue);
			rval = USB_SUCCESS;
			mutex_exit(&ph_data->p_mutex);
		} else {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_ACTIVE);
			ph_data->p_active_cntrl_req_wrp = (usb_opaque_t)wrp;
			mutex_exit(&ph_data->p_mutex);

			/* issue the request to HCD */
			rval = usba_device->usb_hcdi_ops->
			    usba_hcdi_pipe_ctrl_xfer(ph_data, req, usb_flags);
		}
		break;
	case USB_PIPE_STATE_ACTIVE:
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_ctrl_xfer: queue request 0x%p", (void *)req);

		usba_add_to_list(&ph_data->p_queue, &wrp->wr_queue);
		rval = USB_SUCCESS;
		mutex_exit(&ph_data->p_mutex);
		break;
	case USB_PIPE_STATE_ERROR:
		if (USBA_IS_DEFAULT_PIPE(ph_data)) {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_pipe_ctrl_xfer: queue request 0x%p on "
			    "pending def pipe error", (void *)req);

			usba_add_to_list(&ph_data->p_queue, &wrp->wr_queue);
			rval = USB_SUCCESS;
		} else {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_pipe_ctrl_xfer: pipe is in error state ");

			rval = USB_PIPE_ERROR;
		}
		mutex_exit(&ph_data->p_mutex);
		break;
	default:
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_ctrl_xfer: pipe state %d", pipe_state);

		rval = USB_PIPE_ERROR;
		mutex_exit(&ph_data->p_mutex);
		break;
	}

	/* if there has been a failure, decrement req count */
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_ctrl_xfer: hcd failed req 0x%p", (void *)req);

		if (req->ctrl_completion_reason == USB_CR_OK) {
			req->ctrl_completion_reason = usba_rval2cr(rval);
		}
		mutex_enter(&ph_data->p_mutex);
		ASSERT(wrp->wr_done == B_FALSE);
		ph_data->p_req_count--;
		ASSERT(ph_data->p_req_count >= 0);
		ph_data->p_active_cntrl_req_wrp = NULL;
		if ((ph_data->p_req_count == 0) &&
		    (usba_get_ph_state(ph_data) == USB_PIPE_STATE_ACTIVE)) {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
		}
		mutex_exit(&ph_data->p_mutex);

	/* if success and sleep specified, wait for completion */
	} else if (wrp_usb_flags & USBA_WRP_FLAGS_WAIT) {
		rval = usba_pipe_sync_wait(ph_data, wrp);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_ctrl_xfer: rval=0x%x", rval);

	usba_release_ph_data(ph_data->p_ph_impl);

	return (rval);
}


/*
 * usb_pipe_sync_ctrl_xfer():
 *	for simple synchronous control transactions this wrapper function
 *	will perform the allocation, xfer, and deallocation
 *	USB_ATTRS_AUTOCLEARING will be enabled
 *
 * Arguments:
 *	dip		- pointer to clients devinfo
 *	pipe_handle	- control pipe pipehandle (obtained via usb_pipe_open()
 *	bmRequestType	- characteristics of request
 *	bRequest	- specific request
 *	wValue		- varies according to request
 *	wIndex		- index or offset
 *	wLength		- number of bytes to xfer
 *	data		- pointer to pointer to data and may be NULL if
 *			  wLength is 0
 *	attrs		- required request attributes
 *	completion_reason - completion status
 *	cb_flags	- request completions flags
 *	flags		- none
 *
 * Return Values:
 *	USB_SUCCESS	- request successfully executed
 *	USB_*		- request failed
 *
 * Notes:
 * - in the case of failure, the client should check completion_reason and
 *	and cb_flags and determine further recovery action
 * - the client should check data and if non-zero, free the data on
 *	completion
 */
int
usb_pipe_sync_ctrl_xfer(dev_info_t *dip,
		usb_pipe_handle_t pipe_handle,
		uchar_t		bmRequestType,
		uchar_t		bRequest,
		uint16_t	wValue,
		uint16_t	wIndex,
		uint16_t	wLength,
		mblk_t		**data,
		usb_req_attrs_t	attributes,
		usb_cr_t	*completion_reason,
		usb_cb_flags_t	*cb_flags,
		usb_flags_t	flags)
{
	usba_pipe_handle_data_t	*ph_data;
	int			rval;
	usb_ctrl_req_t		*ctrl_req;
	size_t			length;
#ifdef DEBUG
#define	BUFSIZE	256
	char			*buf = kmem_alloc(BUFSIZE, KM_SLEEP);
#endif

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_sync_ctrl_xfer: ph=0x%p\n\t"
	    "setup = 0x%x 0x%x 0x%x 0x%x 0x%x uf = 0x%x", (void *)pipe_handle,
	    bmRequestType, bRequest, wValue, wIndex, wLength, flags);

	if ((ph_data = usba_hold_ph_data(pipe_handle)) == NULL) {
		rval = USB_INVALID_PIPE;

		goto done;
	}
	if (servicing_interrupt()) {
		rval = USB_INVALID_CONTEXT;

		goto done;
	}
	if (dip == NULL) {
		rval = USB_INVALID_ARGS;

		goto done;
	}

	length = ((data) && (*data)) ? 0: wLength;

	ctrl_req = usb_alloc_ctrl_req(dip,
	    length, flags | USB_FLAGS_SLEEP);

	/* Initialize the ctrl_req structure */
	ctrl_req->ctrl_bmRequestType	= bmRequestType;
	ctrl_req->ctrl_bRequest 	= bRequest;
	ctrl_req->ctrl_wValue		= wValue;
	ctrl_req->ctrl_wIndex		= wIndex;
	ctrl_req->ctrl_wLength		= wLength;
	ctrl_req->ctrl_data		= ctrl_req->ctrl_data ?
	    ctrl_req->ctrl_data : ((data) ? *data : NULL);
	ctrl_req->ctrl_timeout		= USB_PIPE_TIMEOUT;
	ctrl_req->ctrl_attributes	= attributes | USB_ATTRS_AUTOCLEARING;

	/* Issue control xfer to the HCD */
	rval = usb_pipe_ctrl_xfer(pipe_handle, ctrl_req,
	    flags | USB_FLAGS_SLEEP);

#ifdef DEBUG
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "req=0x%p, cr=%s cb_flags=%s data=0x%p rval=%s",
	    (void *)ctrl_req, usb_str_cr(ctrl_req->ctrl_completion_reason),
	    usb_str_cb_flags(ctrl_req->ctrl_cb_flags, buf, BUFSIZE),
	    (void *)ctrl_req->ctrl_data, usb_str_rval(rval));
#endif

	/* copy back ctrl_req values */
	if (data) {
		*data			= ctrl_req->ctrl_data;
	}
	if (completion_reason) {
		*completion_reason	= ctrl_req->ctrl_completion_reason;
	}
	if (cb_flags) {
		*cb_flags		= ctrl_req->ctrl_cb_flags;
	}

	/* Free up the control request now */
	ctrl_req->ctrl_data = NULL; /* leave to client to free */
	usb_free_ctrl_req(ctrl_req);

done:
#ifdef DEBUG
	kmem_free(buf, BUFSIZE);
#endif
	if (ph_data) {
		usba_release_ph_data(ph_data->p_ph_impl);
	}

	return (rval);
}


/*
 * usb_pipe_ctrl_xfer_wait():
 *	Easy-to-use wrapper around usb_pipe_sync_ctrl_xfer.
 *
 * ARGUMENTS:
 *	pipe_handle	- control pipe pipehandle (obtained via usb_pipe_open())
 *	setup		- setup descriptor params, attributes
 *	data		- pointer to pointer to data and may be NULL when
 *			  wLength is 0
 *	completion_reason - completion status.
 *	cb_flags	- request completions flags.
 *	flags		- none.
 *
 * RETURN VALUES:
 *	USB_SUCCESS	- request successfully executed.
 *	USB_*		- failure
 */
int
usb_pipe_ctrl_xfer_wait(
		usb_pipe_handle_t	pipe_handle,
		usb_ctrl_setup_t	*setup,
		mblk_t			**data,
		usb_cr_t		*completion_reason,
		usb_cb_flags_t		*cb_flags,
		usb_flags_t		flags)
{
	return (usb_pipe_sync_ctrl_xfer(
	    usba_get_dip(pipe_handle),
	    pipe_handle,
	    setup->bmRequestType,
	    setup->bRequest,
	    setup->wValue,
	    setup->wIndex,
	    setup->wLength,
	    data,
	    setup->attrs,
	    completion_reason,
	    cb_flags,
	    flags));
}


/*
 * usb_alloc_bulk_req:
 *	Allocate a usb bulk request + usba_req_wrapper_t
 *
 * Arguments:
 *	dip	- dev_info_t of the client driver
 *	len	- length of "data" for this bulk request
 *	flags:
 *		USB_FLAGS_SLEEP    - Sleep if resources are not available
 *
 * Return Values:
 *	usb_bulk_req_t on success, NULL on failure
 */
usb_bulk_req_t *
usb_alloc_bulk_req(dev_info_t	*dip,
		size_t		len,
		usb_flags_t	flags)
{
	usb_bulk_req_t		*bulk_req = NULL;
	usba_req_wrapper_t	*wrp;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_alloc_bulk_req: dip=0x%p wlen=0x%lx flags=0x%x",
	    (void *)dip, len, flags);

	/* Allocate + Initialize the usba_req_wrapper_t structure */
	if (dip &&
	    ((wrp = usba_req_wrapper_alloc(dip, sizeof (*bulk_req), flags)) !=
	    NULL)) {
		bulk_req = USBA_WRP2BULK_REQ(wrp);

		/* Allocate the usb_bulk_req data mblk */
		if (len) {
			if (flags & USB_FLAGS_SLEEP) {
				bulk_req->bulk_data = allocb_wait(len,
				    BPRI_LO, STR_NOSIG, NULL);
			} else	if ((bulk_req->bulk_data =
			    allocb(len, BPRI_HI)) == NULL) {
				usba_req_wrapper_free(wrp);
				bulk_req = NULL;
			}
		}

	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_alloc_bulk_req: bulk_req = 0x%p", (void *)bulk_req);

	return (bulk_req);
}


/*
 * usb_free_bulk_req:
 *	free USB bulk request + wrapper
 *
 * Arguments:
 *	req - pointer to usb_bulk_req_t
 */
void
usb_free_bulk_req(usb_bulk_req_t *req)
{
	if (req) {
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_free_bulk_req: req=0x%p", (void *)req);

		if (req->bulk_data) {
			freemsg(req->bulk_data);
		}
		usba_req_wrapper_free(USBA_REQ2WRP(req));
	}
}


/*
 * Client driver calls this function to issue the bulk xfer to the USBA
 *
 * Arguments:-
 *	pipe_handle - bulk pipe handle (obtained via usb_pipe_open()
 *	req	    - bulk data xfer request (IN or OUT)
 *	usb_flags   - USB_FLAGS_SLEEP - wait for the request to complete
 *
 * Return Values:
 *	USB_SUCCESS - success
 *	USB_FAILURE - unspecified failure
 */
int
usb_pipe_bulk_xfer(usb_pipe_handle_t	pipe_handle,
		usb_bulk_req_t		*req,
		usb_flags_t		usb_flags)
{
	int			rval;
	usba_req_wrapper_t	*wrp = USBA_REQ2WRP(req);
	usba_pipe_handle_data_t	*ph_data = usba_hold_ph_data(pipe_handle);
	usba_device_t		*usba_device;
	usb_flags_t		wrp_usb_flags;
	usb_pipe_state_t	pipe_state;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_bulk_xfer: req=0x%p uf=0x%x", (void *)req, usb_flags);

	if (ph_data == NULL) {

		return (USB_INVALID_PIPE);
	}

	mutex_enter(&ph_data->p_mutex);
	usba_device = ph_data->p_usba_device;

	if ((rval = usba_check_req(ph_data, (usb_opaque_t)req, usb_flags,
	    USB_EP_ATTR_BULK)) != USB_SUCCESS) {
		mutex_exit(&ph_data->p_mutex);

		usba_release_ph_data(ph_data->p_ph_impl);

		return (rval);
	}

	/* we accepted the request */
	ph_data->p_req_count++;
	wrp_usb_flags = wrp->wr_usb_flags;

	/* Get the current bulk pipe state */
	pipe_state = usba_get_ph_state(ph_data);

	/*
	 * if there is already an active request in the queue
	 * then just add this request to the queue.
	 */
	switch (pipe_state) {
	case USB_PIPE_STATE_IDLE:
		if (ph_data->p_queue.next) {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_pipe_bulk_xfer: queue request 0x%p",
			    (void *)req);

			usba_add_to_list(&ph_data->p_queue, &wrp->wr_queue);
			rval = USB_SUCCESS;
			mutex_exit(&ph_data->p_mutex);
		} else {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_ACTIVE);
			mutex_exit(&ph_data->p_mutex);

			/* issue the request to HCD */
			rval = usba_device->usb_hcdi_ops->
			    usba_hcdi_pipe_bulk_xfer(ph_data, req, usb_flags);
		}
		break;
	case USB_PIPE_STATE_ACTIVE:
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_bulk_xfer: queue request 0x%p", (void *)req);

		usba_add_to_list(&ph_data->p_queue, &wrp->wr_queue);
		rval = USB_SUCCESS;
		mutex_exit(&ph_data->p_mutex);
		break;
	default:
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_bulk_xfer: pipe state %d", pipe_state);

		rval = USB_PIPE_ERROR;
		mutex_exit(&ph_data->p_mutex);
		break;
	}

	if (rval != USB_SUCCESS) {
		if (req->bulk_completion_reason == USB_CR_OK) {
			req->bulk_completion_reason = usba_rval2cr(rval);
		}
		mutex_enter(&ph_data->p_mutex);
		ASSERT(wrp->wr_done == B_FALSE);
		ph_data->p_req_count--;
		ASSERT(ph_data->p_req_count >= 0);
		if ((ph_data->p_req_count == 0) &&
		    (usba_get_ph_state(ph_data) == USB_PIPE_STATE_ACTIVE)) {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
		}
		mutex_exit(&ph_data->p_mutex);
	} else if (wrp_usb_flags & USBA_WRP_FLAGS_WAIT) {
		rval = usba_pipe_sync_wait(ph_data, wrp);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_bulk_xfer: rval=%d", rval);

	usba_release_ph_data(ph_data->p_ph_impl);

	return (rval);
}


/*
 * usb_pipe_bulk_transfer_size:
 *	- request HCD to return bulk max transfer data size
 *
 * Arguments:
 *	dip	- pointer to dev_info_t
 *	size	- pointer to bulk_transfer_size
 *
 * Return Values:
 *	USB_SUCCESS	- request successfully executed
 *	USB_FAILURE	- request failed
 */
int
usb_pipe_bulk_transfer_size(dev_info_t	*dip,
			size_t		*size)
{
	return (usb_pipe_get_max_bulk_transfer_size(dip, size));
}


int
usb_pipe_get_max_bulk_transfer_size(dev_info_t	*dip,
			size_t		*size)
{
	usba_device_t	*usba_device;

	if ((dip == NULL) || (size == NULL)) {

		return (USB_INVALID_ARGS);
	}
	usba_device = usba_get_usba_device(dip);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_bulk_transfer_size: usba_device=0x%p",
	    (void *)usba_device);

	if ((usba_device) &&
	    (usba_device->usb_hcdi_ops->usba_hcdi_bulk_transfer_size)) {

		return (usba_device->usb_hcdi_ops->
		    usba_hcdi_bulk_transfer_size(usba_device, size));
	} else {
		*size = 0;

		return (USB_FAILURE);
	}
}


/*
 * usb_alloc_intr_req:
 *	Allocate usb interrupt request
 *
 * Arguments:
 *	dip	- dev_info_t of the client driver
 *	len	- length of "data" for this interrupt request
 *	flags	-
 *		USB_FLAGS_SLEEP    - Sleep if resources are not available
 *
 * Return Values:
 *		usb_intr_req_t on success, NULL on failure
 */
usb_intr_req_t *
usb_alloc_intr_req(dev_info_t	*dip,
		size_t		len,
		usb_flags_t	flags)
{
	usb_intr_req_t	*intr_req = NULL;
	usba_req_wrapper_t	*wrp;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_alloc_intr_req: dip=0x%p, len=0x%lx, flags=0x%x",
	    (void *)dip, len, flags);

	/* Allocate + Initialize the usba_req_wrapper_t structure */
	if ((dip &&
	    (wrp = usba_req_wrapper_alloc(dip, sizeof (*intr_req), flags)) !=
	    NULL)) {
		intr_req = (usb_intr_req_t *)USBA_WRP2INTR_REQ(wrp);

		/* Allocate the usb_intr_req data mblk */
		if (len) {
			if (flags & USB_FLAGS_SLEEP) {
				intr_req->intr_data = allocb_wait(len, BPRI_LO,
				    STR_NOSIG, NULL);
			} else	if ((intr_req->intr_data =
			    allocb(len, BPRI_HI)) == NULL) {
				usba_req_wrapper_free(wrp);
				intr_req = NULL;
			}
		}
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_alloc_intr_req: intr_req=0x%p", (void *)intr_req);

	return (intr_req);
}


/*
 * usba_hcdi_dup_intr_req:
 *	create duplicate of interrupt request
 *
 * Arguments:
 *	dip	- devinfo pointer
 *	reqp	- original requestp pointer
 *	len	- length of "data" for this interrupt request
 *	flags	-
 *		USB_FLAGS_SLEEP    - Sleep if resources are not available
 *
 * Return Values:
 *		usb_intr_req_t on success, NULL on failure
 */
usb_intr_req_t *
usba_hcdi_dup_intr_req(
		dev_info_t	*dip,
		usb_intr_req_t	*reqp,
		size_t		len,
		usb_flags_t	flags)
{
	usb_intr_req_t		*intr_reqp = NULL;
	usba_req_wrapper_t	*intr_wrp, *req_wrp;

	if (reqp == NULL) {

		return (NULL);
	}

	req_wrp	= USBA_REQ2WRP(reqp);

	if (((intr_reqp = usb_alloc_intr_req(dip, len, flags)) != NULL)) {
		intr_reqp->intr_client_private	= reqp->intr_client_private;
		intr_reqp->intr_timeout		= reqp->intr_timeout;
		intr_reqp->intr_attributes	= reqp->intr_attributes;
		intr_reqp->intr_len		= reqp->intr_len;
		intr_reqp->intr_cb		= reqp->intr_cb;
		intr_reqp->intr_exc_cb		= reqp->intr_exc_cb;

		intr_wrp		= USBA_REQ2WRP(intr_reqp);
		intr_wrp->wr_dip	= req_wrp->wr_dip;
		intr_wrp->wr_ph_data	= req_wrp->wr_ph_data;
		intr_wrp->wr_attrs	= req_wrp->wr_attrs;
		intr_wrp->wr_usb_flags	= req_wrp->wr_usb_flags;
	}

	return (intr_reqp);
}


/*
 * usb_free_intr_req:
 *	free USB intr request + wrapper
 *
 * Arguments:
 *	req - pointer to usb_intr_req_t
 */
void
usb_free_intr_req(usb_intr_req_t *req)
{
	if (req) {
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_free_intr_req: req = 0x%p", (void *)req);

		if (req->intr_data) {
			freemsg(req->intr_data);
		}

		usba_req_wrapper_free(USBA_REQ2WRP(req));
	}
}


/*
 * Client driver calls this function to issue the intr xfer to the USBA
 *
 * Arguments:-
 *	pipe_handle	- intr pipe handle (obtained via usb_pipe_open()
 *	req		- intr data xfer request (IN or OUT)
 *	flags		-
 *			   USB_FLAGS_SLEEP - wait for the request to complete
 * Return Values
 *	USB_SUCCESS	- success
 *	USB_FAILURE	- unspecified failure
 */
int
usb_pipe_intr_xfer(usb_pipe_handle_t	pipe_handle,
		usb_intr_req_t		*req,
		usb_flags_t		usb_flags)
{
	int			rval;
	usba_req_wrapper_t	*wrp = USBA_REQ2WRP(req);
	usba_ph_impl_t		*ph_impl = (usba_ph_impl_t *)pipe_handle;
	usba_pipe_handle_data_t	*ph_data = usba_hold_ph_data(pipe_handle);
	usba_device_t		*usba_device;
	uchar_t			direction;
	usb_flags_t		wrp_usb_flags;
	usb_pipe_state_t	pipe_state;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_intr_req: req=0x%p uf=0x%x",
	    (void *)req, usb_flags);

	if (ph_data == NULL) {

		return (USB_INVALID_PIPE);
	}
	usba_device = ph_data->p_usba_device;
	direction = ph_data->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	mutex_enter(&ph_data->p_mutex);
	if ((rval = usba_check_req(ph_data, (usb_opaque_t)req, usb_flags,
	    USB_EP_ATTR_INTR)) != USB_SUCCESS) {
		mutex_exit(&ph_data->p_mutex);

		usba_release_ph_data(ph_data->p_ph_impl);

		return (rval);
	}

	/* Get the current interrupt pipe state */
	pipe_state = usba_get_ph_state(ph_data);

	switch (pipe_state) {
	case USB_PIPE_STATE_IDLE:
		/*
		 * if the pipe state is in middle of transition,
		 * i.e. stop polling is in progress, fail any
		 * attempt to do a start polling
		 */
		mutex_enter(&ph_impl->usba_ph_mutex);
		if (ph_impl->usba_ph_state_changing > 0) {
			mutex_exit(&ph_impl->usba_ph_mutex);

			mutex_exit(&ph_data->p_mutex);
			usba_release_ph_data(ph_data->p_ph_impl);

			USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
			    "usb_pipe_intr_req: fail request - "
			    "stop polling in progress");

			return (USB_FAILURE);
		} else {
			mutex_exit(&ph_impl->usba_ph_mutex);
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_ACTIVE);
		}

		break;
	case USB_PIPE_STATE_ACTIVE:
		/*
		 * If this is interrupt IN pipe and if we are
		 * already polling, return failure.
		 */
		if (direction == USB_EP_DIR_IN) {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI,
			    usbai_log_handle,
			    "usb_pipe_intr_req: already polling");

			mutex_exit(&ph_data->p_mutex);
			usba_release_ph_data(ph_data->p_ph_impl);

			return (USB_FAILURE);
		}

		break;
	default:
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_intr_req: pipe state %d", pipe_state);

		mutex_exit(&ph_data->p_mutex);
		usba_release_ph_data(ph_data->p_ph_impl);

		return (USB_PIPE_ERROR);
	}

	/* we accept the request */
	wrp_usb_flags = wrp->wr_usb_flags;
	ph_data->p_req_count++;

	mutex_exit(&ph_data->p_mutex);

	/* issue the request out */
	if ((rval = usba_device->usb_hcdi_ops->usba_hcdi_pipe_intr_xfer(ph_data,
	    req, usb_flags)) != USB_SUCCESS) {

		/* the request failed, decrement the ref_count */
		if (req->intr_completion_reason == USB_CR_OK) {
			req->intr_completion_reason = usba_rval2cr(rval);
		}
		mutex_enter(&ph_data->p_mutex);
		ASSERT(wrp->wr_done == B_FALSE);
		ph_data->p_req_count--;
		ASSERT(ph_data->p_req_count >= 0);
		if ((ph_data->p_req_count == 0) &&
		    (usba_get_ph_state(ph_data) == USB_PIPE_STATE_ACTIVE)) {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
		}
		mutex_exit(&ph_data->p_mutex);

	/* if sleep specified, wait for completion */
	} else if (wrp_usb_flags & USBA_WRP_FLAGS_WAIT) {
		rval = usba_pipe_sync_wait(ph_data, wrp);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_intr_req: rval=0x%x", rval);

	usba_release_ph_data(ph_data->p_ph_impl);

	return (rval);
}


/*
 * usba_pipe_sync_stop_intr_polling:
 *	- set up for sync transport, if necessary
 *	- request HCD to stop polling
 *	- wait for draining of all callbacks
 */
/*ARGSUSED*/
static int
usba_pipe_sync_stop_intr_polling(dev_info_t	*dip,
		usba_ph_impl_t		*ph_impl,
		usba_pipe_async_req_t	*request,
		usb_flags_t		flags)
{
	int rval;
	usba_pipe_handle_data_t *ph_data;
	usba_device_t	*usba_device;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_sync_stop_intr_polling: flags=0x%x", flags);

	ph_data = usba_get_ph_data((usb_pipe_handle_t)ph_impl);
	if (ph_data == NULL) {
		usba_release_ph_data(ph_impl);
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_sync_stop_intr_polling: pipe closed");

		return (USB_INVALID_PIPE);
	}

	usba_device = ph_data->p_usba_device;

	mutex_enter(&ph_data->p_mutex);

	if (usba_get_ph_state(ph_data) == USB_PIPE_STATE_ERROR) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_sync_stop_intr_polling: pipe error");
		mutex_exit(&ph_data->p_mutex);

		usba_release_ph_data(ph_impl);

		return (USB_PIPE_ERROR);
	}

	if (usba_get_ph_state(ph_data) == USB_PIPE_STATE_IDLE) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_sync_stop_intr_polling: already idle");
		mutex_exit(&ph_data->p_mutex);

		usba_release_ph_data(ph_impl);

		return (USB_SUCCESS);
	}
	mutex_exit(&ph_data->p_mutex);

	mutex_enter(&ph_impl->usba_ph_mutex);
	ph_impl->usba_ph_state_changing++;
	mutex_exit(&ph_impl->usba_ph_mutex);

	flags |= USB_FLAGS_SLEEP;

	for (;;) {
		rval = usba_device->usb_hcdi_ops->
		    usba_hcdi_pipe_stop_intr_polling(ph_data, flags);

		/*
		 * The host controller has stopped polling of the endpoint.
		 * Now, drain the callbacks if there are any on the callback
		 * queue.
		 */
		if (rval == USB_SUCCESS) {
			mutex_enter(&ph_data->p_mutex);

			/*
			 * there is a tiny window that the client driver
			 * may still have restarted the polling and we
			 * have to let the stop polling win)
			 */
			rval = usba_drain_cbs(ph_data, 0,
			    USB_CR_STOPPED_POLLING);
			mutex_exit(&ph_data->p_mutex);
			if (rval != USB_SUCCESS) {

				continue;
			}
		}

		break;
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_sync_stop_intr_polling: rval=0x%x", rval);

	mutex_enter(&ph_impl->usba_ph_mutex);
	ph_impl->usba_ph_state_changing--;
	mutex_exit(&ph_impl->usba_ph_mutex);

	usba_release_ph_data(ph_impl);

	return (rval);
}


/*
 * dummy callback function for stop polling
 */
static void
usba_dummy_callback(
	usb_pipe_handle_t ph,
	usb_opaque_t arg,
	int rval,
	usb_cb_flags_t flags)
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_dummy_callback: "
	    "ph=0x%p rval=0x%x flags=0x%x cb_arg=0x%p",
	    (void *)ph, rval, flags, (void *)arg);
}


/*
 * usb_pipe_stop_intr_polling:
 *	stop polling for interrupt pipe IN data
 *	The HCD doesn't do a usba_hcdi_cb().
 *	It just returns success/failure
 * Arguments:
 *	pipe_handle	- pipe handle
 *	flags		-
 *			USB_FLAGS_SLEEP:	wait for completion
 */
void
usb_pipe_stop_intr_polling(usb_pipe_handle_t pipe_handle,
	usb_flags_t	flags)
{
	usba_pipe_handle_data_t *ph_data = usba_hold_ph_data(pipe_handle);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_stop_intr_polling: flags=0x%x", flags);

	if (ph_data == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_stop_intr_polling: pipe closed");

		return;
	}

	if ((ph_data->p_ep.bmAttributes &
	    USB_EP_ATTR_MASK) != USB_EP_ATTR_INTR) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_stop_intr_polling: wrong pipe type");

		usba_release_ph_data(ph_data->p_ph_impl);

		return;
	}

	if ((ph_data->p_ep.bEndpointAddress & USB_EP_DIR_IN) == 0) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_stop_intr_polling: wrong pipe direction");

		usba_release_ph_data(ph_data->p_ph_impl);

		return;
	}

	if (servicing_interrupt() && (flags & USB_FLAGS_SLEEP)) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_stop_intr_polling: invalid context");

		usba_release_ph_data(ph_data->p_ph_impl);

		return;
	}

	(void) usba_pipe_setup_func_call(ph_data->p_dip,
	    usba_pipe_sync_stop_intr_polling,
	    (usba_ph_impl_t *)pipe_handle, (usb_opaque_t)flags,
	    flags, usba_dummy_callback, NULL);
}


/*
 * usb_alloc_isoc_req:
 *	- Allocate usb isochronous resources that includes usb isochronous
 *	  request and array of packet descriptor structures and wrapper.
 *
 * Arguments:
 *	dip		- dev_info_t of the client driver
 *	isoc_pkts_count - number of isoc_pkt_descr_t's
 *	len		- length of "data" for this isochronous request
 *	flags		-
 *		USB_FLAGS_SLEEP    - Sleep if resources are not available
 *		no USB_FLAGS_SLEEP - Don't Sleep if resources are not available
 *
 * Return Values:
 *	usb_isoc_req_t on success, NULL on failure
 */
/*ARGSUSED*/
usb_isoc_req_t *
usb_alloc_isoc_req(dev_info_t		*dip,
		uint_t			isoc_pkts_count,
		size_t			len,
		usb_flags_t		flags)
{
	usb_isoc_req_t		*isoc_req = NULL;
	usba_req_wrapper_t	*wrp;
	size_t			length = sizeof (*isoc_req) +
	    (sizeof (usb_isoc_pkt_descr_t) * isoc_pkts_count);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_alloc_isoc_req: dip=0x%p pkt_cnt=%d len=%lu flags=0x%x",
	    (void *)dip, isoc_pkts_count, len, flags);

	/* client needs to set isoc_pks_count */
	if (dip && isoc_pkts_count) {
		/* Allocate + Initialize the usba_req_wrapper_t structure */
		if ((wrp = usba_req_wrapper_alloc(dip, length, flags)) !=
		    NULL) {
			isoc_req = (usb_isoc_req_t *)USBA_WRP2ISOC_REQ(wrp);

			/* Allocate the usb_isoc_req data mblk */
			if (len) {
				if ((isoc_req->isoc_data =
				    allocb(len, BPRI_HI)) == NULL) {
					usba_req_wrapper_free(wrp);
					isoc_req = NULL;
				}
			}
		}
	}

	if (isoc_req) {
		isoc_req->isoc_pkt_descr = (usb_isoc_pkt_descr_t *)
		    (((intptr_t)isoc_req) + (sizeof (usb_isoc_req_t)));

		/* Initialize all the fields of usb isochronous request */
		isoc_req->isoc_pkts_count = (ushort_t)isoc_pkts_count;
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_alloc_isoc_req: isoc_req = 0x%p", (void *)isoc_req);

	return (isoc_req);
}


/*
 * usba_hcdi_dup_isoc_req:
 *	create duplicate of isoc request
 *
 * Arguments:
 *	dip	- devinfo pointer
 *	reqp	- original request pointer
 *	len	- length of "data" for this isoc request
 *	flags	-
 *		USB_FLAGS_SLEEP    - Sleep if resources are not available
 *
 * Return Values:
 *		usb_isoc_req_t on success, NULL on failure
 */
usb_isoc_req_t *
usba_hcdi_dup_isoc_req(
		dev_info_t	*dip,
		usb_isoc_req_t	*reqp,
		usb_flags_t	flags)
{
	usb_isoc_req_t		*isoc_reqp = NULL;
	usba_req_wrapper_t	*isoc_wrp, *req_wrp;
	ushort_t		count;
	ushort_t		isoc_pkts_count;
	size_t			length;

	if (reqp == NULL) {

		return (isoc_reqp);
	}

	isoc_pkts_count = reqp->isoc_pkts_count;

	/* calculate total data length required in original request */
	for (count = length = 0; count < isoc_pkts_count; count++) {
		length += reqp->isoc_pkt_descr[count].isoc_pkt_length;
	}

	req_wrp	= USBA_REQ2WRP(reqp);

	if (((isoc_reqp = usb_alloc_isoc_req(dip,
	    isoc_pkts_count, length, flags)) != NULL)) {
		isoc_reqp->isoc_frame_no	= reqp->isoc_frame_no;
		isoc_reqp->isoc_pkts_count	= reqp->isoc_pkts_count;
		isoc_reqp->isoc_pkts_length	= reqp->isoc_pkts_length;
		isoc_reqp->isoc_attributes	= reqp->isoc_attributes;
		isoc_reqp->isoc_client_private	= reqp->isoc_client_private;
		isoc_reqp->isoc_cb		= reqp->isoc_cb;
		isoc_reqp->isoc_exc_cb		= reqp->isoc_exc_cb;

		isoc_wrp		= USBA_REQ2WRP(isoc_reqp);
		isoc_wrp->wr_dip	= req_wrp->wr_dip;
		isoc_wrp->wr_ph_data	= req_wrp->wr_ph_data;
		isoc_wrp->wr_attrs	= req_wrp->wr_attrs;
		isoc_wrp->wr_usb_flags	= req_wrp->wr_usb_flags;

		for (count = 0; count < isoc_pkts_count; count++) {
			isoc_reqp->isoc_pkt_descr[count].isoc_pkt_length =
			    reqp->isoc_pkt_descr[count].isoc_pkt_length;
		}
	}

	return (isoc_reqp);
}


/*
 * usb_free_isoc_req:
 *	- Deallocate usb isochronous resources that includes usb isochronous
 *	  request and array of packet descriptor strcutures.
 *
 * Arguments:
 *	req - pointer to usb_isoc_req_t
 */
void
usb_free_isoc_req(usb_isoc_req_t *req)
{
	if (req) {
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_free_isoc_req: req=0x%p", (void *)req);

		if (req->isoc_data) {
			freemsg(req->isoc_data);
		}

		usba_req_wrapper_free(USBA_REQ2WRP(req));
	}
}


/*
 * usb_get_current_frame_number:
 *	- request HCD to return current usb frame number
 *
 * Arguments:
 *	dip	- pointer to dev_info_t
 *
 * Return Values:
 *	current_frame_number	- request successfully executed
 *	0			- request failed
 */
usb_frame_number_t
usb_get_current_frame_number(dev_info_t	*dip)
{
	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_get_current_frame_number: dip=0x%p", (void *)dip);

	if (dip) {
		usba_device_t	*usba_device = usba_get_usba_device(dip);
		usb_frame_number_t	frame_number;

		if (usba_device->usb_hcdi_ops->
		    usba_hcdi_get_current_frame_number) {

			if (usba_device->usb_hcdi_ops->
			    usba_hcdi_get_current_frame_number(usba_device,
			    &frame_number) == USB_SUCCESS) {

				return (frame_number);
			}
		}
	}

	return (0);
}


/*
 * usb_get_max_isoc_pkts:
 *	- request HCD to return maximum isochronous packets per request
 *
 * Arguments:
 *	dip	- pointer to dev_info_t
 *
 * Return Values:
 *	isoc_pkt - request successfully executed
 *	0	 - request failed
 */
uint_t
usb_get_max_isoc_pkts(dev_info_t *dip)
{
	return (usb_get_max_pkts_per_isoc_request(dip));
}


uint_t
usb_get_max_pkts_per_isoc_request(dev_info_t *dip)
{
	if (dip) {
		usba_device_t	*usba_device = usba_get_usba_device(dip);
		uint_t		max_isoc_pkts_per_request;

		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_get_max_isoc_pkts: usba_device=0x%p",
		    (void *)usba_device);

		if (usba_device->usb_hcdi_ops->usba_hcdi_get_max_isoc_pkts) {

			if (usba_device->usb_hcdi_ops->
			    usba_hcdi_get_max_isoc_pkts(usba_device,
			    &max_isoc_pkts_per_request) == USB_SUCCESS) {

				return (max_isoc_pkts_per_request);
			}
		}
	}

	return (0);
}


/*
 * usb_pipe_isoc_xfer:
 *	- check for pipe stalled
 *	- request HCD to transport isoc data asynchronously
 *
 * Arguments:
 *	pipe_handle	- isoc pipe pipehandle (obtained via usb_pipe_open())
 *	req		- isochronous request
 *
 * Return Values:
 *	USB_SUCCESS	- request successfully executed
 *	USB_FAILURE	- request failed
 */
int
usb_pipe_isoc_xfer(usb_pipe_handle_t	pipe_handle,
		usb_isoc_req_t		*req,
		usb_flags_t		flags)
{
	int			rval;
	usba_req_wrapper_t	*wrp = USBA_REQ2WRP(req);
	usba_pipe_handle_data_t	*ph_data = usba_hold_ph_data(pipe_handle);
	usba_device_t		*usba_device;
	uchar_t			direction;
	usb_pipe_state_t	pipe_state;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_isoc_xfer: flags=0x%x", flags);

	if (ph_data == NULL) {

		return (USB_INVALID_PIPE);
	}

	usba_device = ph_data->p_usba_device;
	direction = ph_data->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	mutex_enter(&ph_data->p_mutex);
	if ((rval = usba_check_req(ph_data, (usb_opaque_t)req, flags,
	    USB_EP_ATTR_ISOCH)) != USB_SUCCESS) {
		mutex_exit(&ph_data->p_mutex);

		usba_release_ph_data(ph_data->p_ph_impl);

		return (rval);
	}

	req->isoc_error_count = 0;

	/* Get the current isoch pipe state */
	pipe_state = usba_get_ph_state(ph_data);

	switch (pipe_state) {
	case USB_PIPE_STATE_IDLE:
		usba_pipe_new_state(ph_data, USB_PIPE_STATE_ACTIVE);
		break;
	case USB_PIPE_STATE_ACTIVE:
		if (direction == USB_EP_DIR_IN) {
			USB_DPRINTF_L4(DPRINT_MASK_USBAI,
			    usbai_log_handle,
			    "usb_pipe_isoc_req: already polling");

			mutex_exit(&ph_data->p_mutex);
			usba_release_ph_data(ph_data->p_ph_impl);

			return (USB_FAILURE);
		}
		break;
	default:
		USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usb_pipe_isoc_req: pipe state %d", pipe_state);

		mutex_exit(&ph_data->p_mutex);
		usba_release_ph_data(ph_data->p_ph_impl);

		return (USB_PIPE_ERROR);
	}

	/* we accept the request */
	ph_data->p_req_count++;
	mutex_exit(&ph_data->p_mutex);

	if ((rval = usba_device->usb_hcdi_ops->usba_hcdi_pipe_isoc_xfer(
	    ph_data, req, flags)) != USB_SUCCESS) {
		if (req->isoc_completion_reason == USB_CR_OK) {
			req->isoc_completion_reason = usba_rval2cr(rval);
		}
		mutex_enter(&ph_data->p_mutex);
		ASSERT(wrp->wr_done == B_FALSE);
		ph_data->p_req_count--;
		if ((ph_data->p_req_count == 0) &&
		    (usba_get_ph_state(ph_data) == USB_PIPE_STATE_ACTIVE)) {
			usba_pipe_new_state(ph_data, USB_PIPE_STATE_IDLE);
		}
		mutex_exit(&ph_data->p_mutex);
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usb_pipe_isoc_req: rval=%x", rval);

	usba_release_ph_data(ph_data->p_ph_impl);

	return (rval);
}


/*
 * usba_pipe_sync_stop_isoc_polling:
 *	- set up for sync transport, if necessary
 *	- request HCD to stop polling
 *	- wait for draining of all callbacks
 *
 * Arguments:
 *	dip		- dev_info pointer
 *	pipe_handle	- pointer to pipe handle
 *	flags		- USB_FLAGS_SLEEP:	wait for completion
 */
/*ARGSUSED*/
static int
usba_pipe_sync_stop_isoc_polling(dev_info_t	*dip,
		usba_ph_impl_t		*ph_impl,
		usba_pipe_async_req_t	*request,
		usb_flags_t		flags)
{
	int rval;
	usba_pipe_handle_data_t *ph_data = usba_get_ph_data(
	    (usb_pipe_handle_t)ph_impl);
	usba_device_t	*usba_device;

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_sync_stop_isoc_polling: uf=0x%x", flags);

	if (ph_data == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_stop_isoc_polling: pipe closed");

		return (USB_INVALID_PIPE);
	}

	usba_device = ph_data->p_usba_device;

	mutex_enter(&ph_data->p_mutex);

	if (usba_get_ph_state(ph_data) == USB_PIPE_STATE_ERROR) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_sync_stop_isoc_polling: pipe error");
		mutex_exit(&ph_data->p_mutex);

		usba_release_ph_data(ph_impl);

		return (USB_PIPE_ERROR);
	}

	if (usba_get_ph_state(ph_data) == USB_PIPE_STATE_IDLE) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_sync_stop_isoc_polling: already stopped");
		mutex_exit(&ph_data->p_mutex);

		usba_release_ph_data(ph_impl);

		return (USB_SUCCESS);
	}


	mutex_exit(&ph_data->p_mutex);

	flags |= USB_FLAGS_SLEEP;

	for (;;) {
		rval = usba_device->usb_hcdi_ops->
		    usba_hcdi_pipe_stop_isoc_polling(ph_data, flags);

		/*
		 * The host controller has stopped polling of the endpoint.
		 * Now, drain the callbacks if there are any on the callback
		 * queue.
		 */
		if (rval == USB_SUCCESS) {
			mutex_enter(&ph_data->p_mutex);

			/*
			 * there is a tiny window that the client driver
			 * may still have restarted the polling and we
			 * let the stop polling win
			 */
			rval = usba_drain_cbs(ph_data, 0,
			    USB_CR_STOPPED_POLLING);
			mutex_exit(&ph_data->p_mutex);
			if (rval != USB_SUCCESS) {

				continue;
			}
		}

		break;
	}

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_sync_stop_isoc_polling: rval=0x%x", rval);

	usba_release_ph_data(ph_impl);

	return (rval);
}


/*
 * usb_pipe_stop_isoc_polling:
 *	stop polling for isoc IN data
 *
 * Arguments:
 *	pipe_handle	- pipe handle
 *	flags		-
 *			USB_FLAGS_SLEEP:	wait for completion
 */
void
usb_pipe_stop_isoc_polling(usb_pipe_handle_t pipe_handle,
		usb_flags_t	flags)
{
	usba_pipe_handle_data_t *ph_data = usba_hold_ph_data(pipe_handle);

	USB_DPRINTF_L4(DPRINT_MASK_USBAI, usbai_log_handle,
	    "usba_pipe_stop_isoc_polling: uf=0x%x", flags);

	if (ph_data == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_stop_isoc_polling: pipe closed");

		return;
	}

	if ((ph_data->p_ep.bmAttributes & USB_EP_ATTR_MASK) !=
	    USB_EP_ATTR_ISOCH) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_stop_isoc_polling: wrong pipe type");

		usba_release_ph_data(ph_data->p_ph_impl);

		return;
	}
	if ((ph_data->p_ep.bEndpointAddress & USB_EP_DIR_IN) == 0) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_stop_isoc_polling: wrong pipe direction");

		usba_release_ph_data(ph_data->p_ph_impl);

		return;
	}

	if (servicing_interrupt() && (flags & USB_FLAGS_SLEEP)) {
		USB_DPRINTF_L2(DPRINT_MASK_USBAI, usbai_log_handle,
		    "usba_pipe_stop_intr_polling: invalid context");

		usba_release_ph_data(ph_data->p_ph_impl);

		return;
	}

	(void) usba_pipe_setup_func_call(ph_data->p_dip,
	    usba_pipe_sync_stop_isoc_polling,
	    (usba_ph_impl_t *)pipe_handle, (usb_opaque_t)flags,
	    flags, usba_dummy_callback, NULL);
}
