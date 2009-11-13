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
 * Wire Adapter Operations
 * Both DWA and HWA have the same kind of functional components, the
 * Wire Adapter. Functions defined in this file are to handle WA's
 * class specific Descriptors, Requests, Notifications and Transfers.
 * DWA or HWA specific descriptors, requests are not handled here.
 */

#include <sys/usb/hwa/hwahc/hwahc.h>
#include <sys/usb/hwa/hwahc/hwahc_util.h>
#include <sys/usb/usba/wa.h>
#include <sys/usb/usba/wusba.h>
#include <sys/usb/usba/whcdi.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/usba_devdb.h>	/* usba_devdb_refresh */
#include <sys/usb/hubd/hubdvar.h>
#include <sys/usb/hubd/hubd_impl.h>	/* hubd_ioctl_data_t */
#include <sys/strsubr.h>	/* allocb_wait */
#include <sys/strsun.h>		/* MBLKL macro */

extern usb_log_handle_t whcdi_log_handle;

/* default rpipe PHY transfer speed */
static uint8_t rp_default_speed = WUSB_PHY_TX_RATE_106;

/* function prototypes */
static void wusb_wa_remove_wr_from_timeout_list(wusb_wa_rpipe_hdl_t *hdl,
	wusb_wa_trans_wrapper_t *tw);
static void wusb_wa_handle_error(wusb_wa_data_t *wa_data,
	wusb_wa_trans_wrapper_t *wr, usb_cr_t cr);

/*
 * Parse Wire Adapter class desriptor.
 *	- see 8.4.3.7 & 8.5.2.7
 *
 *	wa_descr - the parsed descriptors.
 *	altif_data - the passed in raw descriptor data.
 */
int
wusb_parse_wa_descr(usb_wa_descr_t *wa_descr, usb_alt_if_data_t *altif_data)
{
	usb_cvs_data_t	*cvs_data;
	int		i;
	size_t		count;

	if ((wa_descr == NULL) || (altif_data == NULL)) {
		return (USB_INVALID_ARGS);
	}

	for (i = 0; i < altif_data->altif_n_cvs; i++) {
		cvs_data = &altif_data->altif_cvs[i];
		if (cvs_data->cvs_buf == NULL) {
			continue;
		}
		if (cvs_data->cvs_buf[1] == USB_DESCR_TYPE_WA) {
			count = usb_parse_data("ccsccsscccc",
			    cvs_data->cvs_buf, cvs_data->cvs_buf_len,
			    (void *)wa_descr,
			    (size_t)USB_WA_DESCR_SIZE);
			if (count != USB_WA_DESCR_SIZE) {
				return (USB_FAILURE);
			} else {
				return (USB_SUCCESS);
			}
		}
	}

	return (USB_FAILURE);
}

/* initialize rpipe structures */
void
wusb_wa_rpipes_init(wusb_wa_data_t *wa_data)
{
	int			i;
	wusb_wa_rpipe_hdl_t	*hdl;

	for (i = 0; i < wa_data->wa_num_rpipes; i++) {
		hdl = &wa_data->wa_rpipe_hdl[i];
		mutex_init(&hdl->rp_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&hdl->rp_cv, NULL, CV_DRIVER, NULL);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*hdl));
		hdl->rp_state = WA_RPIPE_STATE_FREE;
		hdl->rp_refcnt = 0;
		hdl->rp_timeout_list = NULL;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*hdl));
	}
}

/* deinitialize rpipe structures */
void
wusb_wa_rpipes_fini(wusb_wa_data_t *wa_data)
{
	int			i;
	wusb_wa_rpipe_hdl_t	*hdl;

	for (i = 0; i < wa_data->wa_num_rpipes; i++) {
		hdl = &wa_data->wa_rpipe_hdl[i];
		mutex_destroy(&hdl->rp_mutex);
		cv_destroy(&hdl->rp_cv);
	}
}


/*
 * wusb_wa_data_init:
 *	WA interface validation
 *	Parse WA class descriptors
 *	Set up RPipes
 *	Set up callbacks
 */
int
wusb_wa_data_init(dev_info_t *dip, wusb_wa_data_t *wa_data, wusb_wa_cb_t *cbs,
	usb_client_dev_data_t *dev_data,
	uint_t mask, usb_log_handle_t handle)
{
	usb_alt_if_data_t	*altif_data;
	usb_ep_data_t		*ep_data;
	int			ifno;
	int			rval;

	if ((wa_data == NULL) || (dev_data == NULL)) {

		return (USB_INVALID_ARGS);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wa_data));

	/* get inf descr and ept descrs from altif data */
	altif_data = &dev_data->dev_curr_cfg->
	    cfg_if[dev_data->dev_curr_if].if_alt[0];

	/* T.8-44. Wire Adapter */
	if (altif_data->altif_descr.bInterfaceSubClass !=
	    USB_SUBCLS_WUSB_2) {
		USB_DPRINTF_L2(mask, handle,
		    "wusb_init_wa_data: invalid interface subclass (0x%x)",
		    altif_data->altif_descr.bInterfaceSubClass);

		return (USB_FAILURE);
	}

	/* at least 3 EPs, INTR IN + BULK IN + BULK OUT */
	if (altif_data->altif_n_ep < 3) {
		USB_DPRINTF_L2(mask, handle,
		    "wusb_init_wa_data: invalid alt 0 for interface %d",
		    dev_data->dev_curr_if);

		return (USB_FAILURE);
	}

	wa_data->wa_ifno = ifno = dev_data->dev_curr_if;
	wa_data->wa_if_descr = altif_data->altif_descr;

	if ((ep_data = usb_lookup_ep_data(dip, dev_data, ifno, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_OUT)) != NULL) {
		wa_data->wa_bulkout_ept = ep_data->ep_descr;
	}
	if ((ep_data = usb_lookup_ep_data(dip, dev_data, ifno, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_IN)) != NULL) {
		wa_data->wa_bulkin_ept = ep_data->ep_descr;
	}
	if ((ep_data = usb_lookup_ep_data(dip, dev_data, ifno, 0, 0,
	    USB_EP_ATTR_INTR, USB_EP_DIR_IN)) != NULL) {
		wa_data->wa_intr_ept = ep_data->ep_descr;
	}

	if ((wa_data->wa_bulkout_ept.bLength == 0) ||
	    (wa_data->wa_bulkin_ept.bLength == 0) ||
	    (wa_data->wa_intr_ept.bLength == 0)) {
		USB_DPRINTF_L2(mask, handle,
		    "wusb_init_wa_data: the minimum endpoint set is not "
		    "supported");

		return (USB_FAILURE);
	}

	/* parse the WA descriptor */
	if ((rval = wusb_parse_wa_descr(&wa_data->wa_descr, altif_data)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(mask, handle,
		    "wusb_init_wa_data: parse wire adapter class descr failed");

		return (rval);
	}
	wa_data->wa_avail_blocks = wa_data->wa_descr.wRPipeMaxBlock;

	wa_data->wa_dip = dip;

	/* initialize rpipe handlers */
	wa_data->wa_num_rpipes = wa_data->wa_descr.wNumRPipes;

	wa_data->wa_rpipe_hdl = kmem_zalloc((wa_data->wa_num_rpipes *
	    sizeof (wusb_wa_rpipe_hdl_t)), KM_SLEEP);

	/* init rpipes */
	wusb_wa_rpipes_init(wa_data);

	/* register callbacks */
	wa_data->pipe_periodic_req = cbs->pipe_periodic_req;
	wa_data->intr_cb = cbs->intr_cb;
	wa_data->intr_exc_cb = cbs->intr_exc_cb;
	wa_data->rpipe_xfer_cb = cbs->rpipe_xfer_cb;

	mutex_init(&wa_data->wa_mutex, NULL, MUTEX_DRIVER, NULL);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*wa_data));

	return (USB_SUCCESS);
}

/* deinitialize data transfer related resources */
void
wusb_wa_data_fini(wusb_wa_data_t *wa_data)
{
	mutex_enter(&wa_data->wa_mutex);
	if (wa_data->wa_rpipe_hdl) {
		wusb_wa_rpipes_fini(wa_data);
		kmem_free(wa_data->wa_rpipe_hdl, wa_data->wa_num_rpipes *
		    sizeof (wusb_wa_rpipe_hdl_t));
	}
	mutex_exit(&wa_data->wa_mutex);
	mutex_destroy(&wa_data->wa_mutex);
}

void wusb_wa_dump_rpipe_descr(usb_wa_rpipe_descr_t *pd, uint_t mask,
    usb_log_handle_t handle)
{
	USB_DPRINTF_L4(mask, handle, "RPipe Descriptor:\n"
	    "\tWRPipeIndex=%d wRequests=%d wBlocks=%d\n"
	    "\twMaxPacketSize=%d bHSHubAddress=%d\n"
	    "\tbHSHubPort=%d bSpeed=%d bDeviceAddress=%d\n"
	    "\tbEndpointAddress=0x%02x bDataSequence=%d\n"
	    "\tdwCurrentWindow=0x%08x bMaxDataSequence=%d",
	    pd->wRPipeIndex, pd->wRequests, pd->wBlocks, pd->wMaxPacketSize,
	    pd->wa_value.hwa_value.bMaxBurst,
	    pd->wa_value.hwa_value.bDeviceInfoIndex,
	    pd->bSpeed, pd->bDeviceAddress,
	    pd->bEndpointAddress, pd->bDataSequence, pd->dwCurrentWindow,
	    pd->bMaxDataSequence);

	USB_DPRINTF_L4(mask, handle,
	    "(cont'ed)bInterval=%d bOverTheAirInterval=%d\n"
	    "\tbmAttribute=0x%02x bmCharacter=0x%02x\n"
	    "\tbmRetryOptions=0x%02x wNumTransactionErrors=%d\n",
	    pd->bInterval, pd->bOverTheAirInterval,
	    pd->bmAttribute, pd->bmCharacteristics, pd->bmRetryOptions,
	    pd->wNumTransactionErrors);

}

/* get rpipe descr of a certain index, refer to WUSB 1.0/8.3.1.4 */
int
wusb_wa_get_rpipe_descr(dev_info_t *dip, usb_pipe_handle_t ph,
	uint16_t idx, usb_wa_rpipe_descr_t *descr,
	uint_t mask, usb_log_handle_t handle)
{
	mblk_t		*data = NULL;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	size_t		count;
	int		rval;

	/*
	 * This descriptor is critical for later operations to succeed.
	 * So, we must wait here.
	 */
	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    WA_CLASS_RPIPE_REQ_IN_TYPE,
	    USB_REQ_GET_DESCR,
	    USB_DESCR_TYPE_RPIPE << 8,
	    idx,
	    USB_RPIPE_DESCR_SIZE,
	    &data, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(mask, handle,
		    "wusb_wa_get_rpipe_descr: rval=%d, cr=%d, "
		    "cb=0x%x", rval, completion_reason, cb_flags);

		goto done;
	}

	if (MBLKL(data) != USB_RPIPE_DESCR_SIZE) {
		USB_DPRINTF_L2(mask, handle,
		    "wusb_wa_get_rpipe_descr: return size %d",
		    (int)MBLKL(data));
		rval = USB_FAILURE;

		goto done;
	}

	count = usb_parse_data("2c4s6cl6cs", data->b_rptr,
	    USB_RPIPE_DESCR_SIZE, descr, sizeof (usb_wa_rpipe_descr_t));

	if (count == USB_PARSE_ERROR) {
		USB_DPRINTF_L2(mask, handle,
		    "wusb_wa_get_rpipe_descr: parse error");
		rval = USB_FAILURE;

		goto done;
	}

	wusb_wa_dump_rpipe_descr(descr, mask, handle);

	freemsg(data);
	data = NULL;

	return (USB_SUCCESS);

done:
	if (data) {
		freemsg(data);
	}

	return (rval);
}

/*
 * Get All the RPipes' descriptors of an HWA
 *	- WA RPipe descriptor are not returned as part of the
 *	cofiguration descriptor. We have to get it separately.
 *	- See section 8.4.3.19 and 8.5.2.11
 */
int
wusb_wa_get_rpipe_descrs(wusb_wa_data_t *wa_data, usb_pipe_handle_t ph,
	uint_t mask, usb_log_handle_t handle)
{
	dev_info_t	*dip = wa_data->wa_dip;
	int		i, rval;

	if ((dip == NULL) || (ph == NULL)) {

		return (USB_INVALID_ARGS);
	}

	/* called at initialization, no other threads yet */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wa_data));

	for (i = 0; i < wa_data->wa_num_rpipes; i++) {
		rval = wusb_wa_get_rpipe_descr(dip, ph, i,
		    &wa_data->wa_rpipe_hdl[i].rp_descr, mask, handle);

		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(mask, handle,
			    "wusb_wa_get_rpipe_descrs: fail to get rpipe "
			    "descr for idx %d", i);

			return (rval);
		}
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*wa_data));

	return (USB_SUCCESS);
}

/*
 * Get Wire Adapter's Status
 *	See section 8.3.1.6
 */
int
wusb_get_wa_status(wusb_wa_data_t *wa_data, usb_pipe_handle_t ph,
	uint32_t *status)
{
	dev_info_t	*dip = wa_data->wa_dip;
	int		rval = USB_SUCCESS;
	mblk_t		*data = NULL;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;

	if ((dip == NULL) || (ph == NULL)) {

		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    WUSB_CLASS_IF_REQ_IN_TYPE,
	    USB_REQ_GET_STATUS,
	    0,
	    wa_data->wa_ifno,
	    WA_GET_WA_STATUS_LEN,
	    &data, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_get_wa_status: can't retrieve status");

		goto done;
	}

	*status = (*(data->b_rptr + 3) << 24) | (*(data->b_rptr + 2) << 16) |
	    (*(data->b_rptr + 1) << 8) | *(data->b_rptr);

done:
	if (data) {
		freemsg(data);
	}

	return (rval);
}

/*
 * Reset WA
 *	See 8.3.1.9
 */
int
wusb_wa_reset(wusb_wa_data_t *wa_data, usb_pipe_handle_t ph)
{
	dev_info_t	*dip = wa_data->wa_dip;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval, i;
	uint32_t	status;

	if ((dip == NULL) || (ph == NULL)) {

		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    USB_REQ_SET_FEATURE,
	    WA_DEV_RESET,
	    wa_data->wa_ifno,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_reset: can't reset wa, rval = %d, cr=%d", rval,
		    completion_reason);

		return (rval);
	}

	for (i = 0; i < 10; i++) {
		delay(drv_usectohz(50000));

		rval = wusb_get_wa_status(wa_data, ph, &status);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_reset: can't get status, rval = %d",
			    rval);

			return (rval);
		}

		if (!(status & WA_HC_RESET_IN_PROGRESS)) {

			return (USB_SUCCESS);
		}
	}

	return (USB_FAILURE);
}

/*
 * Enable wire adapter.
 *	See 8.3.1.9
 */
int
wusb_wa_enable(wusb_wa_data_t *wa_data, usb_pipe_handle_t ph)
{
	dev_info_t	*dip = wa_data->wa_dip;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval, i;
	uint32_t	status;

	if ((dip == NULL) || (ph == NULL)) {

		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    USB_REQ_SET_FEATURE,
	    WA_DEV_ENABLE,
	    wa_data->wa_ifno,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_enable: can't enable WA, rval = %d, cr=%d",
		    rval, completion_reason);

		return (rval);
	}

	for (i = 0; i < 10; i++) {
		delay(drv_usectohz(50000));

		rval = wusb_get_wa_status(wa_data, ph, &status);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_enable: can't get status, rval = %d",
			    rval);

			return (rval);
		}

		if (status & WA_HC_ENABLED) {

			return (USB_SUCCESS);
		}
	}

	return (USB_FAILURE);
}

/*
 * Disable WA. Clear a fearture.
 *	See Section 8.3.1.3
 */
int
wusb_wa_disable(wusb_wa_data_t *wa_data, usb_pipe_handle_t ph)
{
	dev_info_t	*dip = wa_data->wa_dip;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval, i;
	uint32_t	status;

	if ((dip == NULL) || (ph == NULL)) {

		return (USB_INVALID_ARGS);
	}

	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    WUSB_CLASS_IF_REQ_OUT_TYPE,
	    USB_REQ_CLEAR_FEATURE,
	    WA_DEV_ENABLE,
	    wa_data->wa_ifno,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_disable: can't disable wa, rval = %d, cr = %d",
		    rval, completion_reason);

		return (rval);
	}

	for (i = 0; i < 10; i++) {
		delay(drv_usectohz(50000));

		rval = wusb_get_wa_status(wa_data, ph, &status);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_disable: can't get status, rval = %d",
			    rval);

			return (rval);
		}

		if (!(status & WA_HC_ENABLED)) {

			return (USB_SUCCESS);
		}
	}

	return (USB_FAILURE);
}

/*
 * Open the two bulk endpoints and one interrupt IN endpoint, defined in
 * a WA's data transfer interface. See 8.1.2
 */
int
wusb_wa_open_pipes(wusb_wa_data_t *wa_data)
{
	int	rval;

	mutex_enter(&wa_data->wa_mutex);
	if (wa_data->wa_state & WA_PIPES_OPENED) {
		mutex_exit(&wa_data->wa_mutex);

		return (USB_SUCCESS);
	}
	wa_data->wa_pipe_policy.pp_max_async_reqs = 1;
	mutex_exit(&wa_data->wa_mutex);

	rval = usb_pipe_open(wa_data->wa_dip, &wa_data->wa_intr_ept,
	    &wa_data->wa_pipe_policy, USB_FLAGS_SLEEP,
	    &wa_data->wa_intr_ph);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_open_pipes: can't open intr pipe, rval = %d",
		    rval);

		return (rval);
	}

	rval = usb_pipe_open(wa_data->wa_dip, &wa_data->wa_bulkin_ept,
	    &wa_data->wa_pipe_policy, USB_FLAGS_SLEEP,
	    &wa_data->wa_bulkin_ph);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_open_pipes: can't open bulkin pipe, rval = %d",
		    rval);

		usb_pipe_close(wa_data->wa_dip, wa_data->wa_intr_ph,
		    USB_FLAGS_SLEEP, NULL, NULL);
		mutex_enter(&wa_data->wa_mutex);
		wa_data->wa_intr_ph = NULL;
		mutex_exit(&wa_data->wa_mutex);

		return (rval);
	}

	rval = usb_pipe_open(wa_data->wa_dip, &wa_data->wa_bulkout_ept,
	    &wa_data->wa_pipe_policy, USB_FLAGS_SLEEP,
	    &wa_data->wa_bulkout_ph);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_open_pipes: can't open bulkout pipe, rval = %d",
		    rval);

		usb_pipe_close(wa_data->wa_dip, wa_data->wa_intr_ph,
		    USB_FLAGS_SLEEP, NULL, NULL);
		usb_pipe_close(wa_data->wa_dip, wa_data->wa_bulkin_ph,
		    USB_FLAGS_SLEEP, NULL, NULL);
		mutex_enter(&wa_data->wa_mutex);
		wa_data->wa_intr_ph = NULL;
		wa_data->wa_bulkin_ph = NULL;
		mutex_exit(&wa_data->wa_mutex);

		return (rval);
	}

	mutex_enter(&wa_data->wa_mutex);
	/* mark the state stopped until listening is started on the pipes */
	wa_data->wa_intr_pipe_state = WA_PIPE_STOPPED;
	wa_data->wa_bulkin_pipe_state = WA_PIPE_STOPPED;
	/* no listening on this pipe, just mark it active */
	wa_data->wa_bulkout_pipe_state = WA_PIPE_ACTIVE;
	wa_data->wa_state |= WA_PIPES_OPENED;
	mutex_exit(&wa_data->wa_mutex);

	return (USB_SUCCESS);
}

/*
 * Close WA's pipes.
 */
void
wusb_wa_close_pipes(wusb_wa_data_t *wa_data)
{
	mutex_enter(&wa_data->wa_mutex);
	if ((wa_data->wa_state & WA_PIPES_OPENED) == 0) {
		mutex_exit(&wa_data->wa_mutex);

		return;
	}

	mutex_exit(&wa_data->wa_mutex);

	usb_pipe_close(wa_data->wa_dip, wa_data->wa_intr_ph,
	    USB_FLAGS_SLEEP, NULL, NULL);

	if (wa_data->wa_bulkin_ph != NULL) {
		usb_pipe_close(wa_data->wa_dip, wa_data->wa_bulkin_ph,
		    USB_FLAGS_SLEEP, NULL, NULL);
	}

	usb_pipe_close(wa_data->wa_dip, wa_data->wa_bulkout_ph,
	    USB_FLAGS_SLEEP, NULL, NULL);

	mutex_enter(&wa_data->wa_mutex);
	wa_data->wa_intr_ph = NULL;
	wa_data->wa_bulkin_ph = NULL;
	wa_data->wa_bulkout_ph = NULL;
	wa_data->wa_intr_pipe_state = WA_PIPE_CLOSED;
	wa_data->wa_bulkin_pipe_state = WA_PIPE_CLOSED;
	wa_data->wa_bulkout_pipe_state = WA_PIPE_CLOSED;
	wa_data->wa_state &= ~WA_PIPES_OPENED;
	mutex_exit(&wa_data->wa_mutex);
}

/*
 * start listening for transfer completion notifications or device
 * notifications on the notification ept
 */
int
wusb_wa_start_nep(wusb_wa_data_t *wa_data, usb_flags_t flag)
{
	int		rval;
	usb_intr_req_t	*reqp;

	mutex_enter(&wa_data->wa_mutex);
	if ((wa_data->wa_intr_ph == NULL) ||
	    (wa_data->wa_intr_pipe_state != WA_PIPE_STOPPED)) {
		mutex_exit(&wa_data->wa_mutex);

		return (USB_INVALID_PIPE);
	}

	reqp = usb_alloc_intr_req(wa_data->wa_dip, 0, flag);
	if (!reqp) {
		mutex_exit(&wa_data->wa_mutex);

		return (USB_NO_RESOURCES);
	}

	reqp->intr_client_private = (usb_opaque_t)wa_data;
	reqp->intr_attributes = USB_ATTRS_SHORT_XFER_OK |
	    USB_ATTRS_AUTOCLEARING;
	reqp->intr_len = wa_data->wa_intr_ept.wMaxPacketSize;
	reqp->intr_cb = wa_data->intr_cb;
	reqp->intr_exc_cb = wa_data->intr_exc_cb;
	mutex_exit(&wa_data->wa_mutex);

	if ((rval = usb_pipe_intr_xfer(wa_data->wa_intr_ph, reqp,
	    flag)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_start_nep: intr xfer fail, rval = %d",
		    rval);

		usb_free_intr_req(reqp);

		return (rval);
	}

	mutex_enter(&wa_data->wa_mutex);
	/* pipe state is active while the listening is on */
	wa_data->wa_intr_pipe_state = WA_PIPE_ACTIVE;
	mutex_exit(&wa_data->wa_mutex);

	return (USB_SUCCESS);
}

/*
 * stop the notification ept from listening
 */
void
wusb_wa_stop_nep(wusb_wa_data_t *wa_data)
{
	mutex_enter(&wa_data->wa_mutex);
	if ((wa_data->wa_intr_ph == NULL) ||
	    (wa_data->wa_intr_pipe_state != WA_PIPE_ACTIVE)) {
		mutex_exit(&wa_data->wa_mutex);

		return;
	}
	wa_data->wa_intr_pipe_state = WA_PIPE_STOPPED;
	mutex_exit(&wa_data->wa_mutex);
	/* stop intr in without closing the pipe */
	usb_pipe_stop_intr_polling(wa_data->wa_intr_ph, USB_FLAGS_SLEEP);
}

/*
 * allocate a rpipe for transfers on a pipe
 *	- Find a free RPipe
 *
 * For now, one rpipe is associated with only one usba pipe once
 * the pipe is opened. In the future, the rpipe needs to be
 * multiplexed between asynchronous endpoints
 * input:
 *	type: 0 - ctrl, 1 - isoc, 2 - bulk, 3 - intr
 *
 */
/* ARGSUSED */
int
wusb_wa_get_rpipe(wusb_wa_data_t *wa_data, usb_pipe_handle_t ph,
	uint8_t type, wusb_wa_rpipe_hdl_t **hdl,
	uint_t mask, usb_log_handle_t handle)
{
	int			i;
	wusb_wa_rpipe_hdl_t	*thdl;
	uint8_t			rp_type;
	uint8_t			ep_type = 1 << type;

	*hdl = NULL;

	mutex_enter(&wa_data->wa_mutex);
	for (i = 0; i < wa_data->wa_num_rpipes; i++) {
		/* find the first unused rpipe */
		thdl = &wa_data->wa_rpipe_hdl[i];
		mutex_enter(&thdl->rp_mutex);
		if (thdl->rp_state != WA_RPIPE_STATE_FREE) {
			mutex_exit(&thdl->rp_mutex);

			continue;
		}

		/* check if the rpipe supports the ept transfer type */
		rp_type = (thdl->rp_descr.bmCharacteristics &
		    USB_RPIPE_CHA_MASK);
		if (rp_type & ep_type) {
			thdl->rp_refcnt++;
			thdl->rp_state = WA_RPIPE_STATE_IDLE;
			thdl->rp_avail_reqs = thdl->rp_descr.wRequests;
			*hdl = thdl;
			mutex_exit(&thdl->rp_mutex);
			mutex_exit(&wa_data->wa_mutex);

			return (USB_SUCCESS);
		}
		mutex_exit(&thdl->rp_mutex);
	}

	USB_DPRINTF_L2(mask, handle,
	    "wusb_wa_get_rpipe: no matching rpipe is found");
	mutex_exit(&wa_data->wa_mutex);

	return (USB_FAILURE);
}

/*
 * Decrease a RPipe's reference count.
 *	- if count == 0, mark it as free RPipe.
 */
int
wusb_wa_release_rpipe(wusb_wa_data_t *wa, wusb_wa_rpipe_hdl_t *hdl)
{
	if (hdl == NULL) {

		return (USB_FAILURE);
	}

	mutex_enter(&wa->wa_mutex);
	mutex_enter(&hdl->rp_mutex);
	if (hdl->rp_refcnt == 0) {
		mutex_exit(&hdl->rp_mutex);
		mutex_exit(&wa->wa_mutex);

		return (USB_FAILURE);
	}

	if (--hdl->rp_refcnt == 0) {
		hdl->rp_state = WA_RPIPE_STATE_FREE;
	}

	if (hdl->rp_block_chg == 1) {
		wa->wa_avail_blocks += hdl->rp_descr.wBlocks;
		hdl->rp_descr.wBlocks = 0; /* to prevent misadd upon re-call */
		hdl->rp_block_chg = 0;
	}

	mutex_exit(&hdl->rp_mutex);
	mutex_exit(&wa->wa_mutex);

	return (USB_SUCCESS);
}

/*
 * Set a RPipe's Descriptor and make the rpipe configured
 *	See section 8.3.1.7
 */
int
wusb_wa_set_rpipe_descr(dev_info_t *dip, usb_pipe_handle_t ph,
	usb_wa_rpipe_descr_t *rp_descr)
{
	mblk_t		*data = NULL;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval;
	uint8_t		*p;

	data = allocb_wait(USB_RPIPE_DESCR_SIZE, BPRI_LO, STR_NOSIG, NULL);
	p = data->b_wptr;
	p[0] = rp_descr->bLength;
	p[1] = rp_descr->bDescriptorType;
	p[2] = rp_descr->wRPipeIndex;
	p[3] = rp_descr->wRPipeIndex >> 8;
	p[4] = rp_descr->wRequests;
	p[5] = rp_descr->wRequests >> 8;
	p[6] = rp_descr->wBlocks;
	p[7] = rp_descr->wBlocks >> 8;
	p[8] = rp_descr->wMaxPacketSize;
	p[9] = rp_descr->wMaxPacketSize >> 8;
	p[10] = rp_descr->wa_value.hwa_value.bMaxBurst;
	p[11] = rp_descr->wa_value.hwa_value.bDeviceInfoIndex;
	p[12] = rp_descr->bSpeed;
	p[13] = rp_descr->bDeviceAddress;
	p[14] = rp_descr->bEndpointAddress;
	p[15] = rp_descr->bDataSequence;
	p[16] = rp_descr->dwCurrentWindow;
	p[17] = rp_descr->dwCurrentWindow >> 8;
	p[18] = rp_descr->dwCurrentWindow >> 16;
	p[19] = rp_descr->dwCurrentWindow >> 24;
	p[20] = rp_descr->bMaxDataSequence;
	p[21] = rp_descr->bInterval;
	p[22] = rp_descr->bOverTheAirInterval;
	p[23] = rp_descr->bmAttribute;
	p[24] = rp_descr->bmCharacteristics;
	p[25] = rp_descr->bmRetryOptions;
	p[26] = rp_descr->wNumTransactionErrors;
	p[27] = rp_descr->wNumTransactionErrors >> 8;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_set_rpipe_descr: RPipe Descriptors");
	wusb_wa_dump_rpipe_descr(rp_descr, DPRINT_MASK_WHCDI, whcdi_log_handle);

	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    WA_CLASS_RPIPE_REQ_OUT_TYPE,
	    USB_REQ_SET_DESCR,
	    USB_DESCR_TYPE_RPIPE << 8,
	    rp_descr->wRPipeIndex,
	    USB_RPIPE_DESCR_SIZE,
	    &data, 0,
	    &completion_reason, &cb_flags, 0);

	freemsg(data);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_set_rpipe_descr: rval = %d", rval);

	return (rval);
}

/* ept companion descr for the default ctrl pipe, refer to WUSB 1.0/4.8.1 */
usb_ep_comp_descr_t ep_comp0 = {
	sizeof (usb_ep_comp_descr_t), USB_DESCR_TYPE_WIRELESS_EP_COMP,
	1, 2,
};

/*
 * Get the Endpoint Companion Descriptor for the pipe
 *	ph_data - the specified pipe
 *	ep_comp - the companion descriptor returned
 */
int
wusb_wa_get_ep_comp_descr(usba_pipe_handle_data_t *ph_data,
	usb_ep_comp_descr_t *ep_comp)
{
	usb_ep_descr_t		*ep = &ph_data->p_ep;
	usb_client_dev_data_t	*dev_data;
	usb_if_data_t		*if_data;
	usb_alt_if_data_t	*altif_data;
	usb_ep_data_t		*ep_data;
	int			i, j;

	/* default ctrl endpoint */
	if (ep->bEndpointAddress == 0) {
		*ep_comp = ep_comp0;

		return (USB_SUCCESS);
	}

	if (usb_get_dev_data(ph_data->p_dip, &dev_data,
	    USB_PARSE_LVL_IF, 0) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	/* retrieve ept companion descr from the dev data */
	if_data = &dev_data->dev_curr_cfg->cfg_if[dev_data->dev_curr_if];
	for (i = 0; i < if_data->if_n_alt; i++) {
		altif_data = &if_data->if_alt[i];
		for (j = 0; j < altif_data->altif_n_ep; j++) {
			ep_data = &altif_data->altif_ep[j];
			if (memcmp(&ep_data->ep_descr, ep,
			    sizeof (usb_ep_descr_t)) == 0) {
				*ep_comp = ep_data->ep_comp_descr;
				usb_free_dev_data(ph_data->p_dip, dev_data);

				return (USB_SUCCESS);
			}
		}
	}
	usb_free_dev_data(ph_data->p_dip, dev_data);

	return (USB_FAILURE);
}

/* to check if the specified PHY speed is supported by the device */
int
wusb_wa_is_speed_valid(usba_device_t *ud, uint8_t speed)
{
	usb_uwb_cap_descr_t *uwb_descr = ud->usb_wireless_data->uwb_descr;
	uint8_t valid_spd[WUSB_PHY_TX_RATE_RES] = {
	    WUSB_DATA_RATE_BIT_53, WUSB_DATA_RATE_BIT_106,
	    WUSB_DATA_RATE_BIT_160, WUSB_DATA_RATE_BIT_200,
	    WUSB_DATA_RATE_BIT_320, WUSB_DATA_RATE_BIT_400,
	    WUSB_DATA_RATE_BIT_480, 0
	};

	if (speed >= WUSB_PHY_TX_RATE_RES) {

		return (0);
	}

	/* this speed is not supported by the device */
	if (valid_spd[speed] != (uwb_descr->wPHYRates & valid_spd[speed])) {

		return (0);
	}

	return (1);
}

/*
 * Set up a RPipe
 *	- Associate a RPipe and a pipe handle. Hence, an endpoint has
 *	  RPipe to transfer data.
 *	- Set this RPipe to bDeviceAddress:bEndpointAddress
 *
 *  wa	- wa data
 *  ph	- wa's default control pipe
 *  ph_data - client driver's usba pipe to be opened
 *  hdl	- RPipe handle
 */
int
wusb_wa_set_rpipe_target(dev_info_t *dip, wusb_wa_data_t *wa,
	usb_pipe_handle_t ph, usba_pipe_handle_data_t *ph_data,
	wusb_wa_rpipe_hdl_t *hdl)
{
	int			rval;
	usb_ep_comp_descr_t	ep_comp;
	usb_ep_descr_t		*ep = &ph_data->p_ep;
	usba_device_t		*usba_device;
	uint8_t			rp_status;
	usb_wa_descr_t		*wa_desc = &wa->wa_descr;
	uint16_t		blockcnt;
	uint16_t		maxsize;
	uint16_t		seg_len;


	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_set_rpipe_target: ph_data = 0x%p rp_hdl = 0x%p",
	    (void*)ph_data, (void*)hdl);

	/* Get client device's Endpoint companion descriptor */
	if ((rval = wusb_wa_get_ep_comp_descr(ph_data, &ep_comp)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_set_rpipe_target: get companion ep descr failed,"
		    " rval = %d", rval);

		return (rval);
	}

	/* set the rpipe to unconfigured state */
	if ((rval = wusb_wa_rpipe_reset(dip, ph_data, hdl, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_set_rpipe_target: reset rpipe failed, rval = %d",
		    rval);

		return (rval);
	}

	if ((rval = wusb_wa_get_rpipe_status(dip, ph,
	    hdl->rp_descr.wRPipeIndex, &rp_status)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_set_rpipe_target: get rpipe status failed, "
		    "rval = %d", rval);

		return (rval);
	}

	if (rp_status & WA_RPIPE_CONFIGURED) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_set_rpipe_target: reset rpipe unsuccessful");

		return (USB_FAILURE);
	}

	mutex_enter(&wa->wa_mutex);
	usba_device = usba_get_usba_device(ph_data->p_dip);

	mutex_enter(&hdl->rp_mutex);

	/* should be 0x200 for default ctrl pipe, refer to wusb 1.0/4.8.1 */
	hdl->rp_descr.wMaxPacketSize = ep->wMaxPacketSize;

	/*
	 * set rpipe descr values
	 *
	 * Try to use an average block value first. If it's too small,
	 * then try to allocate the minimum block size to accomodate one
	 * packet. If the required number of block is not available, return
	 * failure.
	 */
	if (hdl->rp_descr.wBlocks == 0) {
		blockcnt = wa_desc->wRPipeMaxBlock/wa_desc->wNumRPipes;
		maxsize = 1 << (wa_desc->bRPipeBlockSize - 1);
		seg_len = blockcnt * maxsize;

		/* alloc enough blocks to accomodate one packet */
		if (ep->wMaxPacketSize > seg_len) {
			blockcnt = (ep->wMaxPacketSize + maxsize -1)/maxsize;
		}

		/* WA don't have so many blocks to fulfill this reqirement */
		if (wa->wa_avail_blocks < blockcnt) {
			mutex_exit(&hdl->rp_mutex);
			mutex_exit(&wa->wa_mutex);

			return (USB_FAILURE);
		}

		/* we're satisfied */
		hdl->rp_descr.wBlocks = blockcnt;
		hdl->rp_block_chg = 1; /* the wBlocks is changed */
		wa->wa_avail_blocks -= blockcnt;
	}
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_set_rpipe_target: wBlocks=%d, maxblock=%d, numR=%d, av=%d",
	    hdl->rp_descr.wBlocks, wa_desc->wRPipeMaxBlock, wa_desc->wNumRPipes,
	    wa->wa_avail_blocks);

	hdl->rp_descr.wa_value.hwa_value.bMaxBurst = ep_comp.bMaxBurst;

	/*
	 * DEVICE INDEX
	 * device info index should be zero based, refer
	 * to WUSB 1.0/8.5.3.7
	 */
	hdl->rp_descr.wa_value.hwa_value.bDeviceInfoIndex =
	    usba_device->usb_port - 1;

	/*
	 * default ctrl pipe uses PHY base signaling rate
	 * refer to wusb 1.0/4.8.1
	 */
	if (ep->bEndpointAddress == 0) {
		hdl->rp_descr.bSpeed = WUSB_PHY_TX_RATE_53;
	} else {
		if (wusb_wa_is_speed_valid(usba_device, rp_default_speed)) {
			hdl->rp_descr.bSpeed = rp_default_speed;
		} else {
			/* use a must-supported speed */
			hdl->rp_descr.bSpeed = WUSB_PHY_TX_RATE_106;
		}
	}
	hdl->rp_descr.bDeviceAddress = usba_device->usb_addr;
	hdl->rp_descr.bEndpointAddress = ep->bEndpointAddress;
	hdl->rp_descr.bDataSequence = 0;
	hdl->rp_descr.dwCurrentWindow = 1;
	hdl->rp_descr.bMaxDataSequence = ep_comp.bMaxSequence - 1;
	hdl->rp_descr.bInterval = ep->bInterval;
	hdl->rp_descr.bOverTheAirInterval = ep_comp.bOverTheAirInterval;
	hdl->rp_descr.bmAttribute = ep->bmAttributes & 0x03;
	hdl->rp_descr.bmRetryOptions = 0; /* keep retrying */
	hdl->rp_descr.wNumTransactionErrors = 0;
	mutex_exit(&hdl->rp_mutex);

	mutex_exit(&wa->wa_mutex);

	/* set rpipe descr */
	rval = wusb_wa_set_rpipe_descr(dip, ph, &hdl->rp_descr);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_set_rpipe_target: set rpipe descr failed, "
		    "rval = %d", rval);

		return (rval);
	}

	/* check rpipe status, must be configured and idle */
	if ((rval = wusb_wa_get_rpipe_status(dip, ph,
	    hdl->rp_descr.wRPipeIndex, &rp_status)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_set_rpipe_target: get rpipe status failed, "
		    "rval = %d", rval);

		return (rval);
	}

	if (rp_status != (WA_RPIPE_CONFIGURED | WA_RPIPE_IDLE)) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_set_rpipe_target: set rpipe descr unsuccessful");

		return (USB_FAILURE);
	}

	return (rval);
}

/*
 * Abort a RPipe
 *	- See Section 8.3.1.1
 *	- Aborts all transfers pending on the given pipe
 */
int
wusb_wa_rpipe_abort(dev_info_t *dip, usb_pipe_handle_t ph,
	wusb_wa_rpipe_hdl_t *hdl)
{
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval;

	mutex_enter(&hdl->rp_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_rpipe_abort: rp_hdl = 0x%p", (void *)hdl);

	/* only abort when there is active transfer */
	if (hdl->rp_state != WA_RPIPE_STATE_ACTIVE) {
		mutex_exit(&hdl->rp_mutex);

		return (USB_SUCCESS);
	}

	mutex_exit(&hdl->rp_mutex);
	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    WA_CLASS_RPIPE_REQ_OUT_TYPE,
	    WA_REQ_ABORT_RPIPE,
	    0,
	    hdl->rp_descr.wRPipeIndex,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_rpipe_abort: abort failed, rval = %d", rval);

		return (rval);
	}

	return (USB_SUCCESS);
}

/*
 * Clear status on the remote device's endpoint, specifically clear the
 * RPipe's target endpoint sequence number. See 4.5.3, 4.6.4 and Tab.8-49
 * for reference of data sequence.
 *
 * NOTE AGAIN:
 * The device endpoint will not respond to host request if the RPipe is
 * reset or re-targeted, while device endpoint is not reset!
 */
void
wusb_wa_clear_dev_ep(usba_pipe_handle_data_t *ph)
{
	uint8_t	ept_addr;

	if (ph == NULL) {
		return;
	}

	ept_addr = ph->p_ep.bEndpointAddress;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, whcdi_log_handle,
	    "wusb_wa_clear_dev_ep:clear endpoint = 0x%02x", ept_addr);
	if (ept_addr != 0) {
	/* only clear non-default endpoints */
		(void) usb_clr_feature(ph->p_dip, USB_DEV_REQ_RCPT_EP, 0,
		    ept_addr, USB_FLAGS_SLEEP, NULL, NULL);
	}
}

/*
 * Reset a RPipe
 *	- Reset a RPipe to a known state
 *	- Pending transfers must be drained or aborted before this
 *	  operation.
 *	- See Section 8.3.1.10
 *
 *  dip - the WA's devinfo
 *  ph	- RPipe's targeted remote device's endpoint pipe.
 *  hdl - RPipe's handle
 *
 *  flag = 1, reset the RPipe descriptor to its initial state and
 *	   also clear remote device endpoint
 *	 = 0, not reset the RPipe descriptor. Caller should use 0 flag
 *	  if it's the first time to open a pipe, because we don't have
 *	  a valid ph yet before successfully opening a pipe by using
 *	  usb_pipe_open().
 */
int
wusb_wa_rpipe_reset(dev_info_t *dip, usba_pipe_handle_data_t *ph,
    wusb_wa_rpipe_hdl_t *hdl, int flag)
{
	int		rval = 0;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags = 0;
	usb_pipe_handle_t	default_ph;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_rpipe_reset: rp_hdl = 0x%p, ep=0x%02x, flag = %d",
	    (void *)hdl, ph->p_ep.bEndpointAddress, flag);

	/* get WA's default pipe */
	default_ph = usba_get_dflt_pipe_handle(dip);

	rval = usb_pipe_sync_ctrl_xfer(dip, default_ph,
	    WA_CLASS_RPIPE_REQ_OUT_TYPE,
	    WA_REQ_RESET_RPIPE,
	    0,
	    hdl->rp_descr.wRPipeIndex,
	    0,
	    NULL, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_rpipe_reset: reset failed, rval=%d"
		    " cr=%d cb=0x%02x",
		    rval, (int)completion_reason, (int)cb_flags);

		return (rval);
	}

	if (flag == 0) {
		/* do nothing else, just return, the rpipe is unconfigured */
		return (USB_SUCCESS);
	}

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_rpipe_reset: need to clear dev pipe and reset RP descr");

	/* set rpipe descr and make the rpipe configured */
	rval = wusb_wa_set_rpipe_descr(dip, default_ph, &hdl->rp_descr);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_rpipe_reset: set descr failed, rval = %d", rval);

		return (rval);
	}

	mutex_enter(&hdl->rp_mutex);
	hdl->rp_avail_reqs = hdl->rp_descr.wRequests;
	if (hdl->rp_state == WA_RPIPE_STATE_ERROR) {
		hdl->rp_state = WA_RPIPE_STATE_IDLE;
	}
	mutex_exit(&hdl->rp_mutex);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_rpipe_reset: end");

	return (USB_SUCCESS);
}

/* get rpipe status, refer to WUSB 1.0/8.3.1.5 */
int
wusb_wa_get_rpipe_status(dev_info_t *dip, usb_pipe_handle_t ph, uint16_t idx,
	uint8_t	*status)
{
	mblk_t		*data = NULL;
	usb_cr_t	completion_reason;
	usb_cb_flags_t	cb_flags;
	int		rval;

	rval = usb_pipe_sync_ctrl_xfer(dip, ph,
	    WA_CLASS_RPIPE_REQ_IN_TYPE,
	    USB_REQ_GET_STATUS,
	    0,
	    idx,
	    1,
	    &data, 0,
	    &completion_reason, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_get_rpipe_status: fail, rval=%d, cr=%d, "
		    "cb=0x%x", rval, completion_reason, cb_flags);
	} else {
		*status = *data->b_rptr;
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_get_rpipe_status: status = %x", *status);
		freemsg(data);
	}

	return (rval);
}

/*
 * WA specific operations end
 */

/* Transfer related routines */
wusb_wa_trans_wrapper_t *
wusb_wa_alloc_tw(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t	*ph, uint32_t datalen, usb_flags_t usb_flags)
{
	uint_t			seg_count;
	uint32_t		seg_len, maxpktsize;
	wusb_wa_trans_wrapper_t	*wr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_alloc_tw: ph = 0x%p rp_hdl = 0x%p ",
	    (void*)ph, (void*)hdl);

	mutex_enter(&hdl->rp_mutex);

	/* compute the rpipe buffer size */
	seg_len = hdl->rp_descr.wBlocks *
	    (1 << (wa_data->wa_descr.bRPipeBlockSize - 1));
	maxpktsize = hdl->rp_descr.wMaxPacketSize;
	mutex_exit(&hdl->rp_mutex);

	if (seg_len < maxpktsize) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_alloc_tw: fail, segment len(%d) "
		    "< wMaxPacketSize(%d) ", seg_len, maxpktsize);

		return (NULL);
	}

	/*
	 * the transfer length for each segment is a multiple of the
	 * wMaxPacketSize except the last segment, and the length
	 * cannot exceed the rpipe buffer size
	 */
	seg_len = (seg_len / maxpktsize) * maxpktsize;
	if (datalen) {
		seg_count = (datalen + seg_len - 1) / seg_len;
	} else {
		seg_count = 1;
	}

	if (seg_count > WA_MAX_SEG_COUNT) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_alloc_tw: fail, seg count(%d)"
		    " > Max allowed number(%d) ", seg_count, WA_MAX_SEG_COUNT);

		return (NULL);
	}

	if ((wr = kmem_zalloc(sizeof (wusb_wa_trans_wrapper_t),
	    KM_NOSLEEP)) == NULL) {

		return (NULL);
	}

	/* allocation, not visible to other threads */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wr));

	if ((wr->wr_seg_array = kmem_zalloc(sizeof (wusb_wa_seg_t) * seg_count,
	    KM_NOSLEEP)) == NULL) {
		kmem_free(wr, sizeof (wusb_wa_trans_wrapper_t));

		return (NULL);
	}

	/* assign a unique ID for each transfer */
	wr->wr_id = WA_GET_ID(wr);
	if (wr->wr_id == 0) {
		kmem_free(wr->wr_seg_array, sizeof (wusb_wa_seg_t) *
		    seg_count);
		kmem_free(wr, sizeof (wusb_wa_trans_wrapper_t));

		return (NULL);
	}

	wr->wr_ph = ph;
	wr->wr_rp = hdl;
	wr->wr_wa_data = wa_data;
	wr->wr_flags = usb_flags;
	wr->wr_nsegs = (uint8_t)seg_count;
	wr->wr_max_seglen = seg_len;
	wr->wr_has_aborted = 0;

	cv_init(&wr->wr_cv, NULL, CV_DRIVER, NULL);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_alloc_tw: wr = 0x%p id = %x nseg = %d", (void*)wr,
	    wr->wr_id, wr->wr_nsegs);

	return (wr);
}

/* create transfer wrapper for a ctrl request, return NULL on failure */
wusb_wa_trans_wrapper_t *
wusb_wa_create_ctrl_wrapper(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t	*ph, usb_ctrl_req_t *ctrl_reqp,
	usb_flags_t usb_flags)
{
	wusb_wa_trans_wrapper_t	*wr = NULL;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_create_ctrl_wrapper: ph = 0x%p rp_hdl = 0x%p reqp = 0x%p",
	    (void *)ph, (void*)hdl, (void *)ctrl_reqp);

	wr = wusb_wa_alloc_tw(wa_data, hdl, ph, ctrl_reqp->ctrl_wLength,
	    usb_flags);
	if (wr == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_create_ctrl_wrapper: fail to create tw for %p",
		    (void *)ctrl_reqp);

		return (NULL);
	}

	/* not visible to other threads yet */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wr));

	if (ctrl_reqp->ctrl_bmRequestType & USB_DEV_REQ_DEV_TO_HOST) {
		wr->wr_dir = WA_DIR_IN;
	} else {
		wr->wr_dir = WA_DIR_OUT;
	}

	wr->wr_type = WA_XFER_REQ_TYPE_CTRL;
	wr->wr_reqp = (usb_opaque_t)ctrl_reqp;
	wr->wr_timeout = (ctrl_reqp->ctrl_timeout == 0) ?
	    WA_RPIPE_DEFAULT_TIMEOUT : ctrl_reqp->ctrl_timeout;
	wr->wr_cb = wusb_wa_handle_ctrl;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_create_ctrl_wrapper: wr = 0x%p nseg = %d", (void *)wr,
	    wr->wr_nsegs);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*wr));

	return (wr);
}

/*
 * create transfer wrapper for a bulk request, return NULL on failure
 *	- split the request into multiple segments
 *	- every segment is N * wMaxPacketSize
 *	- segment length <= bRPipeBlockSize * wBlocks
 */
wusb_wa_trans_wrapper_t *
wusb_wa_create_bulk_wrapper(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t *ph, usb_bulk_req_t *bulk_reqp,
	usb_flags_t usb_flags)
{
	wusb_wa_trans_wrapper_t	*wr = NULL;
	usb_ep_descr_t		*epdt = &ph->p_ep;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_create_bulk_wrapper: ph = 0x%p rp_hdl = 0x%p reqp = 0x%p",
	    (void *)ph, (void *)hdl, (void *)bulk_reqp);

	wr = wusb_wa_alloc_tw(wa_data, hdl, ph, bulk_reqp->bulk_len,
	    usb_flags);
	if (wr == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_create_bulk_wrapper: fail to create tw for %p",
		    (void *)bulk_reqp);

		return (NULL);
	}

	/* no locking needed */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wr));

	if ((epdt->bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		wr->wr_dir = WA_DIR_IN;
	} else {
		wr->wr_dir = WA_DIR_OUT;
	}

	wr->wr_type = WA_XFER_REQ_TYPE_BULK_INTR;
	wr->wr_reqp = (usb_opaque_t)bulk_reqp;
	wr->wr_timeout = (bulk_reqp->bulk_timeout == 0) ?
	    WA_RPIPE_DEFAULT_TIMEOUT : bulk_reqp->bulk_timeout;
	wr->wr_cb = wusb_wa_handle_bulk;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_create_bulk_wrapper: wr = 0x%p nseg = %d", (void *)wr,
	    wr->wr_nsegs);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*wr));

	return (wr);
}

/*
 * create transfer wrapper for a intr request, return NULL on failure
 *	- split the request into multiple segments
 *	- every segment is N * wMaxPacketSize
 *	- segment length <= bRPipeBlockSize * wBlocks
 */
wusb_wa_trans_wrapper_t *
wusb_wa_create_intr_wrapper(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t *ph, usb_intr_req_t *intr_reqp,
	usb_flags_t usb_flags)
{
	wusb_wa_trans_wrapper_t	*wr;
	usb_ep_descr_t		*epdt = &ph->p_ep;
	uint32_t		tw_len;
	usb_intr_req_t *curr_intr_reqp;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_create_intr_wrapper: ph = 0x%p rp_hdl = 0x%p reqp = 0x%p",
	    (void *)ph, (void *)hdl, (void *)intr_reqp);

	if ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		tw_len = (intr_reqp->intr_len) ? intr_reqp->intr_len :
		    ph->p_ep.wMaxPacketSize;

		/* duplicate client's intr request */
		curr_intr_reqp = usba_hcdi_dup_intr_req(ph->p_dip,
		    (usb_intr_req_t *)intr_reqp, tw_len, usb_flags);
		if (curr_intr_reqp == NULL) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_create_intr_wrapper: fail to create reqp");

			return (NULL);
		}

	} else { /* OUT */
		tw_len = intr_reqp->intr_len;
		curr_intr_reqp = intr_reqp;
	}

	wr = wusb_wa_alloc_tw(wa_data, hdl, ph, tw_len, usb_flags);
	if (wr == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_create_bulk_wrapper: fail to create tw for %p",
		    (void *)intr_reqp);

		return (NULL);
	}

	/* no locking needed */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wr));

	if ((epdt->bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		wr->wr_dir = WA_DIR_IN;
	} else {
		wr->wr_dir = WA_DIR_OUT;
	}

	wr->wr_type = WA_XFER_REQ_TYPE_BULK_INTR;

	wr->wr_reqp = (usb_opaque_t)curr_intr_reqp;

	wr->wr_timeout = (intr_reqp->intr_timeout == 0) ?
	    WA_RPIPE_DEFAULT_TIMEOUT : intr_reqp->intr_timeout;
	wr->wr_cb = wusb_wa_handle_intr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_create_intr_wrapper: wr = 0x%p nseg = %d", (void *)wr,
	    wr->wr_nsegs);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*wr));

	return (wr);
}

/*
 * Setup the transfer request structure for a segment
 * len = transfer request structure length
 *	- see section 8.3.3.1 and 8.3.3.2
 */
void
wusb_wa_setup_trans_req(wusb_wa_trans_wrapper_t *wr, wusb_wa_seg_t *seg,
	uint8_t len)
{
	mblk_t		*data = seg->seg_trans_reqp->bulk_data;
	uint8_t		*trans_req = data->b_wptr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_setup_trans_req: wr = 0x%p len = %d segnum = 0x%x",
	    (void*)wr, len, seg->seg_num);

	bzero(trans_req, len);
	trans_req[0] = len;
	trans_req[1] = wr->wr_type;
	trans_req[2] = wr->wr_rp->rp_descr.wRPipeIndex;
	trans_req[3] = wr->wr_rp->rp_descr.wRPipeIndex >> 8;
	trans_req[4] = seg->seg_id;	/* dwTransferID */
	trans_req[5] = seg->seg_id >> 8;
	trans_req[6] = seg->seg_id >> 16;
	trans_req[7] = seg->seg_id >> 24;
	trans_req[8] = seg->seg_len;
	trans_req[9] = seg->seg_len >> 8;
	trans_req[10] = seg->seg_len >> 16;
	trans_req[11] = seg->seg_len >> 24;
	trans_req[12] = seg->seg_num;

	/*
	 * 8-byte setupdata only for the first segment of a ctrl
	 * transfer request
	 */
	if (wr->wr_type == WA_XFER_REQ_TYPE_CTRL) {
		usb_ctrl_req_t *ctrl_req = (usb_ctrl_req_t *)wr->wr_reqp;

		/* what is the unsecured flag for ? */
		trans_req[13] = wr->wr_dir | WA_CTRL_SECRT_REGULAR;
		if ((seg->seg_num & 0x7f) == 0) {
			/* only send baSetupDate on the first segment */
			trans_req[16] = ctrl_req->ctrl_bmRequestType;
			trans_req[17] = ctrl_req->ctrl_bRequest;
			trans_req[18] = ctrl_req->ctrl_wValue;
			trans_req[19] = ctrl_req->ctrl_wValue >> 8;
			trans_req[20] = ctrl_req->ctrl_wIndex;
			trans_req[21] = ctrl_req->ctrl_wIndex >> 8;
			trans_req[22] = ctrl_req->ctrl_wLength;
			trans_req[23] = ctrl_req->ctrl_wLength >> 8;

		}
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_setup_trans_req: Ctrl segment = %02x",
		    seg->seg_num);

		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_setup_trans_req: Ctrl Setup Data: "
		    "%02x %02x %02x %02x %02x %02x %02x %02x",
		    trans_req[16], trans_req[17], trans_req[18],
		    trans_req[19], trans_req[20], trans_req[21],
		    trans_req[22], trans_req[23]);
	}
	data->b_wptr += len;
}

/*
 * WA bulk pipe callbacks
 *   wusb_wa_trans_bulk_cb: transfer request stage normal callback
 *   wusb_wa_trans_bulk_exc_cb: transfer request stage exceptional callback
 *
 *   wusb_wa_data_bulk_cb: transfer data stage normal callback
 *   wusb_wa_data_bulk_exc_cb: transfer data stage exceptional callback
 *
 * see WUSB1.0 8.3.3 for details
 */
void
wusb_wa_trans_bulk_cb(usb_pipe_handle_t ph, struct usb_bulk_req *req)
{
	wusb_wa_seg_t *seg = (wusb_wa_seg_t *)req->bulk_client_private;
	wusb_wa_trans_wrapper_t *wr = (wusb_wa_trans_wrapper_t *)seg->seg_wr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_trans_bulk_cb: ph=%p req=0x%p cr=%d", (void*)ph,
	    (void*)req, req->bulk_completion_reason);

	mutex_enter(&wr->wr_rp->rp_mutex);

	/* callback returned, this seg can be freed */
	seg->seg_trans_req_state = 0;

	cv_signal(&seg->seg_trans_cv);
	mutex_exit(&wr->wr_rp->rp_mutex);
}

void
wusb_wa_trans_bulk_exc_cb(usb_pipe_handle_t ph, struct usb_bulk_req *req)
{
	wusb_wa_seg_t *seg = (wusb_wa_seg_t *)req->bulk_client_private;
	wusb_wa_trans_wrapper_t *wr = (wusb_wa_trans_wrapper_t *)seg->seg_wr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_trans_bulk_exc_cb: ph=%p req=0x%p cr=%d", (void *)ph,
	    (void *)req, req->bulk_completion_reason);

	mutex_enter(&wr->wr_rp->rp_mutex);

	/* callback returned, this seg can be freed */
	seg->seg_trans_req_state = 0;

	cv_signal(&seg->seg_trans_cv);
	mutex_exit(&wr->wr_rp->rp_mutex);
}

void
wusb_wa_data_bulk_cb(usb_pipe_handle_t ph, struct usb_bulk_req *req)
{
	wusb_wa_seg_t *seg = (wusb_wa_seg_t *)req->bulk_client_private;
	wusb_wa_trans_wrapper_t *wr = (wusb_wa_trans_wrapper_t *)seg->seg_wr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_data_bulk_cb: ph=%p req=0x%p cr=%d", (void *)ph,
	    (void *)req, req->bulk_completion_reason);

	mutex_enter(&wr->wr_rp->rp_mutex);

	/* callback returned, this seg can be freed */
	seg->seg_data_req_state = 0;

	cv_signal(&seg->seg_data_cv);
	mutex_exit(&wr->wr_rp->rp_mutex);
}

void
wusb_wa_data_bulk_exc_cb(usb_pipe_handle_t ph, struct usb_bulk_req *req)
{
	wusb_wa_seg_t *seg = (wusb_wa_seg_t *)req->bulk_client_private;
	wusb_wa_trans_wrapper_t *wr = (wusb_wa_trans_wrapper_t *)seg->seg_wr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_data_bulk_exc_cb: ph=%p req=0x%p cr=%d", (void *)ph,
	    (void *)req, req->bulk_completion_reason);

	mutex_enter(&wr->wr_rp->rp_mutex);

	/* callback returned, this seg can be freed */
	seg->seg_data_req_state = 0;

	cv_signal(&seg->seg_data_cv);
	mutex_exit(&wr->wr_rp->rp_mutex);
}

/*
 * Setup all the transfer request segments, including the transfer request
 * stage and data stage for out transfer.
 * len = total size of payload data to transfer
 *	- for every segment, allocate a new bulk request for Transfer
 *	  Request. Fill the request with the segment and wrapper data.
 *	- for every segment, allocate a new bulk request for data stage.
 *
 */
int
wusb_wa_setup_segs(wusb_wa_data_t *wa_data, wusb_wa_trans_wrapper_t *wr,
	uint32_t len, mblk_t *data)
{
	int		i, rval;
	wusb_wa_seg_t	*seg;
	usb_bulk_req_t	*trans_req, *data_req;
	uint8_t		trans_req_len;
	uint8_t		*p;
	wusb_wa_rpipe_hdl_t *hdl = NULL;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_setup_segs: wr = 0x%p len = %d data = 0x%p", (void *)wr,
	    len, (void *)data);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wr));

	if (wr == NULL) {
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_setup_segs: invalid wr");

		return (USB_INVALID_ARGS);
	}

	if ((len != 0) && (data != NULL)) {
		p = data->b_rptr;
	}

	for (i = 0; i < wr->wr_nsegs; i++) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*seg));

		seg = &wr->wr_seg_array[i];
		cv_init(&seg->seg_trans_cv, NULL, CV_DRIVER, NULL);
		cv_init(&seg->seg_data_cv, NULL, CV_DRIVER, NULL);
		seg->seg_wr = wr;
		seg->seg_num = (uint8_t)i;	/* 0-based */
		seg->seg_len = wr->wr_max_seglen;
		if (i == (wr->wr_nsegs - 1)) {
			seg->seg_num |= 0x80;	/* last segment */
			seg->seg_len = len;
		} else {
			len -= seg->seg_len;
		}

		/*
		 * set seg_id, all segs are the same or unique ??
		 * now make all segs share the same id
		 */
		seg->seg_id = wr->wr_id;

		/* alloc transfer request and set values */
		switch (wr->wr_type) {
		case WA_XFER_REQ_TYPE_CTRL:
			trans_req_len = WA_CTRL_REQ_LEN;
			break;
		case WA_XFER_REQ_TYPE_BULK_INTR:
			trans_req_len = WA_BULK_INTR_REQ_LEN;

			break;
		default:
			trans_req_len = 0;
			break;
		}

		if (trans_req_len == 0) {
			rval = USB_NOT_SUPPORTED;
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_setup_segs: trans len error");

			goto error;
		}

		/* alloc transfer request for the ith seg */
		trans_req = usb_alloc_bulk_req(wa_data->wa_dip,
		    trans_req_len, USB_FLAGS_NOSLEEP);
		if (trans_req == NULL) {
			rval = USB_NO_RESOURCES;
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_setup_segs: can't alloc_bulk_req");

			goto error;
		}

		/* setup the ith transfer request */
		trans_req->bulk_len = trans_req_len;
		trans_req->bulk_timeout = WA_RPIPE_DEFAULT_TIMEOUT;
		trans_req->bulk_attributes = USB_ATTRS_AUTOCLEARING;
		trans_req->bulk_cb = wusb_wa_trans_bulk_cb;
		trans_req->bulk_exc_cb = wusb_wa_trans_bulk_exc_cb;
		trans_req->bulk_client_private = (usb_opaque_t)seg;

		seg->seg_trans_reqp = trans_req;
		wusb_wa_setup_trans_req(wr, seg, trans_req_len);

		if (seg->seg_len != 0) {
			/* alloc request for data stage */
			data_req = usb_alloc_bulk_req(wa_data->wa_dip,
			    seg->seg_len, USB_FLAGS_NOSLEEP);
			if (data_req == NULL) {
				rval = USB_NO_RESOURCES;
				USB_DPRINTF_L2(DPRINT_MASK_WHCDI,
				    whcdi_log_handle,
				    "wusb_wa_setup_segs: can't alloc_bulk_req"
				    " for data");

				goto error;
			}

			/* setup the ith data transfer */
			data_req->bulk_len = seg->seg_len;
			data_req->bulk_timeout = WA_RPIPE_DEFAULT_TIMEOUT;
			data_req->bulk_attributes = USB_ATTRS_AUTOCLEARING;

			data_req->bulk_cb = wusb_wa_data_bulk_cb;
			data_req->bulk_exc_cb = wusb_wa_data_bulk_exc_cb;
			data_req->bulk_client_private = (usb_opaque_t)seg;

			seg->seg_data_reqp = data_req;

			/*
			 * Copy data from client driver to bulk request for
			 * an OUT endpoint.
			 */
			if (wr->wr_dir == WA_DIR_OUT) {
				ASSERT(data != NULL);
				/*
				 * cannot increase data->b_rptr,
				 * or scsa2usb panic at bulk out
				 */
				ASSERT((intptr_t)((uintptr_t)data->b_wptr -
				    (uintptr_t)p) >= seg->seg_len);
				bcopy(p,
				    data_req->bulk_data->b_wptr,
				    seg->seg_len);
				p += seg->seg_len;

				data_req->bulk_data->b_wptr += seg->seg_len;
			}
		}

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*seg));
	}

	/* zero timeout means to wait infinitely */
	/*
	 * if this is the first time this WR to be transfered,
	 * we'll add it to its rpipe handle's timeout queue
	 */
	if (wr->wr_timeout > 0) {
		hdl = wr->wr_rp;

		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_setup_segs: timeout=%d", wr->wr_timeout);

		mutex_enter(&hdl->rp_mutex);

		/* Add this new wrapper to the head of RPipe's timeout list */
		if (hdl->rp_timeout_list) {
			wr->wr_timeout_next = hdl->rp_timeout_list;
		}

		hdl->rp_timeout_list = wr;

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*wr));

		mutex_exit(&hdl->rp_mutex);
	}

	return (USB_SUCCESS);

error:
	USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_setup_segs: fail, rval = %d", rval);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*wr));

	mutex_enter(&hdl->rp_mutex);
	wusb_wa_free_segs(wr);
	mutex_exit(&hdl->rp_mutex);

	return (rval);
}

/* allocate transfer wrapper and setup all transfer segments */
wusb_wa_trans_wrapper_t *
wusb_wa_alloc_ctrl_resources(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t *ph, usb_ctrl_req_t *ctrl_reqp,
	usb_flags_t usb_flags)
{
	wusb_wa_trans_wrapper_t	*wr;

	wr = wusb_wa_create_ctrl_wrapper(wa_data, hdl, ph, ctrl_reqp,
	    usb_flags);

	if (wr == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_alloc_ctrl_resources failed");

		return (NULL);
	}

	if (wusb_wa_setup_segs(wa_data, wr, ctrl_reqp->ctrl_wLength,
	    ctrl_reqp->ctrl_data) != USB_SUCCESS) {
		wusb_wa_free_trans_wrapper(wr);

		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_alloc_ctrl_resources failed to setup segs");

		return (NULL);
	}

	return (wr);
}

/* allocate transfer wrapper and setup all transfer segments */
wusb_wa_trans_wrapper_t *
wusb_wa_alloc_bulk_resources(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t *ph, usb_bulk_req_t *bulk_reqp,
	usb_flags_t usb_flags)
{
	wusb_wa_trans_wrapper_t	*wr;

	wr = wusb_wa_create_bulk_wrapper(wa_data, hdl, ph, bulk_reqp,
	    usb_flags);

	if (wr == NULL) {

		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_alloc_bulk_resources: failed to create wr");

		return (NULL);
	}

	if (wusb_wa_setup_segs(wa_data, wr, bulk_reqp->bulk_len,
	    bulk_reqp->bulk_data) != USB_SUCCESS) {
		wusb_wa_free_trans_wrapper(wr);

		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_alloc_bulk_resources:failed to setup segs");
		return (NULL);
	}

	return (wr);
}

/*
 * allocate transfer wrapper and setup all transfer segments
 * if it's an IN request, duplicate it.
 */
wusb_wa_trans_wrapper_t *
wusb_wa_alloc_intr_resources(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t *ph, usb_intr_req_t *intr_reqp,
	usb_flags_t usb_flags)
{
	wusb_wa_trans_wrapper_t	*wr;

	wr = wusb_wa_create_intr_wrapper(wa_data, hdl, ph, intr_reqp,
	    usb_flags);

	if (wr == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_alloc_intr_resources: failed to create wr");

		return (NULL);
	}

	if (wusb_wa_setup_segs(wa_data, wr, intr_reqp->intr_len,
	    intr_reqp->intr_data) != USB_SUCCESS) {
		wusb_wa_free_trans_wrapper(wr);

		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_alloc_intr_resources: failed to setup segs");

		return (NULL);
	}

	return (wr);
}

/* free the bulk request structures for all segments */
void
wusb_wa_free_segs(wusb_wa_trans_wrapper_t *wr)
{
	int		i;
	wusb_wa_seg_t	*seg;

	ASSERT(mutex_owned(&wr->wr_rp->rp_mutex));

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_free_segs: wr = 0x%p, segs=%p", (void *)wr,
	    (void *)wr->wr_seg_array);

	if (wr->wr_seg_array == NULL) {
		return;
	}


	for (i = 0; i < wr->wr_nsegs; i++) {
		seg = &wr->wr_seg_array[i];

		if (seg->seg_trans_reqp != NULL) {
			while (seg->seg_trans_req_state == 1) {
				cv_wait(&seg->seg_trans_cv,
				    &wr->wr_rp->rp_mutex);
			}
			/* free the bulk req for transfer request */
			usb_free_bulk_req(seg->seg_trans_reqp);
			seg->seg_trans_reqp = NULL;
		}

		if (seg->seg_data_reqp != NULL) {
			while (seg->seg_data_req_state == 1) {
				cv_wait(&seg->seg_data_cv,
				    &wr->wr_rp->rp_mutex);
			}
			/* free the bulk req for data transfer */
			usb_free_bulk_req(seg->seg_data_reqp);
			seg->seg_data_reqp = NULL;
		}

		cv_destroy(&seg->seg_trans_cv);
		cv_destroy(&seg->seg_data_cv);
	}

	kmem_free(wr->wr_seg_array, sizeof (wusb_wa_seg_t) * wr->wr_nsegs);

	wr->wr_seg_array = NULL;
	wr->wr_nsegs = 0;
}

/* free transfer wrapper */
void
wusb_wa_free_trans_wrapper(wusb_wa_trans_wrapper_t *wr)
{
	wusb_wa_rpipe_hdl_t *hdl = NULL;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_free_trans_wrapper: wr = 0x%p", (void *)wr);

	if (wr == NULL) {
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_free_trans_wrapper: NULL wrapper");
		return;
	}

	hdl = wr->wr_rp;

	mutex_enter(&hdl->rp_mutex);

	wusb_wa_remove_wr_from_timeout_list(hdl, wr);

	if (wr->wr_seg_array != NULL) {
		wusb_wa_free_segs(wr);
		kmem_free(wr->wr_seg_array,
		    sizeof (wusb_wa_seg_t) * wr->wr_nsegs);
	}

	if (wr->wr_id != 0) {
		WA_FREE_ID(wr->wr_id);
	}

	cv_destroy(&wr->wr_cv);

	kmem_free(wr, sizeof (wusb_wa_trans_wrapper_t));

	mutex_exit(&hdl->rp_mutex);
}

/* abort a transfer, refer to WUSB 1.0/8.3.3.5 */
void
wusb_wa_abort_req(wusb_wa_data_t *wa_data, wusb_wa_trans_wrapper_t *wr,
	uint32_t id)
{
	usb_bulk_req_t	*req;
	uint8_t		*p;
	int		rval;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_abort_req: wr = 0x%p", (void *)wr);

	req = usb_alloc_bulk_req(wa_data->wa_dip, WA_ABORT_REQ_LEN,
	    USB_FLAGS_NOSLEEP);
	if (req == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_abort_req: alloc bulk req failed");

		return;
	}

	req->bulk_len = WA_ABORT_REQ_LEN;
	req->bulk_timeout = WA_RPIPE_DEFAULT_TIMEOUT;
	req->bulk_attributes = USB_ATTRS_AUTOCLEARING;
	p = req->bulk_data->b_wptr;
	p[0] = WA_ABORT_REQ_LEN;
	p[1] = WA_XFER_REQ_TYPE_ABORT;
	p[2] = wr->wr_rp->rp_descr.wRPipeIndex;
	p[3] = wr->wr_rp->rp_descr.wRPipeIndex >> 8;
	p[4] = (uint8_t)id;
	p[5] = (uint8_t)(id >> 8);
	p[6] = (uint8_t)(id >> 16);
	p[7] = (uint8_t)(id >> 24);
	req->bulk_data->b_wptr += WA_ABORT_REQ_LEN;

	mutex_exit(&wr->wr_rp->rp_mutex);
	rval = usb_pipe_bulk_xfer(wa_data->wa_bulkout_ph, req,
	    USB_FLAGS_SLEEP);
	mutex_enter(&wr->wr_rp->rp_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_abort_req: send abort req failed, rval = %d",
		    rval);
	}
	usb_free_bulk_req(req);
}

static void
wusb_wa_remove_wr_from_timeout_list(wusb_wa_rpipe_hdl_t *hdl,
	wusb_wa_trans_wrapper_t *tw)
{
	wusb_wa_trans_wrapper_t *prev, *next;
	int ret = 0; /* debug only */

	USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "remove_wr_from_timeout_list: %p", (void *)tw);

	if (hdl->rp_timeout_list) {
		if (hdl->rp_timeout_list == tw) {
			hdl->rp_timeout_list = tw->wr_timeout_next;
			tw->wr_timeout_next = NULL;
			ret = 1;
		} else {
			prev = hdl->rp_timeout_list;
			next = prev->wr_timeout_next;

			while (next && (next != tw)) {
				prev = next;
				next = next->wr_timeout_next;
			}

			if (next == tw) {
				prev->wr_timeout_next = next->wr_timeout_next;
				tw->wr_timeout_next = NULL;
				ret = 1;
			}
		}
	}

	/* debug only */
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "remove_wr_from_timeout_list: %p, on the list:%d",
	    (void *)tw, ret);
}

/* start timer on a rpipe */
void
wusb_wa_start_xfer_timer(wusb_wa_rpipe_hdl_t *hdl)
{
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_start_xfer_timer: rpipe hdl = 0x%p", (void *)hdl);

	ASSERT(mutex_owned(&hdl->rp_mutex));

	/*
	 * wr_timeout is in Seconds
	 */
	/*
	 * Start the rpipe's timer only if currently timer is not
	 * running and if there are transfers on the rpipe.
	 * The timer will be per rpipe.
	 *
	 * The RPipe's timer expires every 1s. When this timer expires, the
	 * handler gets called and will decrease every pending transfer
	 * wrapper's timeout value.
	 */
	if ((!hdl->rp_timer_id) && (hdl->rp_timeout_list)) {
		hdl->rp_timer_id = timeout(wusb_wa_xfer_timeout_handler,
		    (void *)hdl, drv_usectohz(1000000));
	}
}

/* transfer timeout handler */
void
wusb_wa_xfer_timeout_handler(void *arg)
{
	wusb_wa_rpipe_hdl_t	*hdl = (wusb_wa_rpipe_hdl_t *)arg;
	wusb_wa_trans_wrapper_t	*wr = NULL;
	wusb_wa_trans_wrapper_t	*next = NULL;
	wusb_wa_data_t		*wa_data = NULL;
	int			rval;
	uint8_t			rp_status;
	wusb_wa_trans_wrapper_t	*expire_list = NULL;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_xfer_timeout_handler: rphdl = 0x%p ", (void *)hdl);

	mutex_enter(&hdl->rp_mutex);

	/*
	 * Check whether still timeout handler is valid.
	 */
	if (hdl->rp_timer_id != 0) {

		/* Reset the timer id to zero */
		hdl->rp_timer_id = 0;
	} else {
		mutex_exit(&hdl->rp_mutex);

		return;
	}

	/*
	 * Check each transfer wrapper on this RPipe's timeout queue
	 * Actually, due to USBA's limitation and queueing, there's only one
	 * usba_request submitted to HCD at a specific pipe. Hence, only one
	 * WR can be on this RPipe's list at any moment.
	 */
	wr = hdl->rp_timeout_list;
	while (wr) {
		next = wr->wr_timeout_next;

		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_xfer_timeout_handler: rhdl=0x%p"
		    " wr=0x%p(to=%d) nxt=0x%p", (void *)hdl, (void *)wr,
		    wr->wr_timeout, (void *)next);

		/*
		 * 1 second passed. Decrease every transfer wrapper's
		 * timeout value. If the timeout < 0 (expired), remove this
		 * wrapper from the timeout list and put it on the
		 * expire_list.
		 */
		wr->wr_timeout--;
		if (wr->wr_timeout <= 0) {
			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_xfer_timeout_handler: 0x%p time out",
			    (void *)wr);

			/* remove it from the rpipe's timeout list */
			wusb_wa_remove_wr_from_timeout_list(hdl, wr);

			/* put it on the expired list */
			wr->wr_timeout_next = expire_list;
			expire_list = wr;

		}

		wr = next;
	}

	/* Restart this RPipe's timer */
	wusb_wa_start_xfer_timer(hdl);

	/* timeout handling */
	wr = expire_list;
	while (wr) {
		next = wr->wr_timeout_next;

		/* other thread shouldn't continue processing it */
		wr->wr_state = WR_TIMEOUT;

		wa_data = wr->wr_wa_data;

		mutex_exit(&hdl->rp_mutex);
		rval = wusb_wa_get_rpipe_status(wa_data->wa_dip,
		    wa_data->wa_default_pipe, hdl->rp_descr.wRPipeIndex,
		    &rp_status);
		mutex_enter(&hdl->rp_mutex);

		if (rval != USB_SUCCESS) {
			/* reset WA perhaps? */
			hdl->rp_state = WA_RPIPE_STATE_ERROR;
			hdl->rp_curr_wr = NULL;
			mutex_exit(&hdl->rp_mutex);
			wr->wr_cb(wa_data, wr, USB_CR_TIMEOUT, 1);
			mutex_enter(&hdl->rp_mutex);

			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_xfer_timeout_handler: fail to get"
			    " rpipe status, rval = %d", rval);

			goto continuing;
		}
		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_xfer_timeout_handler: rpstat=0x%02x, wr=0x%p,"
		    " wr_state=%d", rp_status, (void *)wr, wr->wr_state);

		if (!(rp_status & WA_RPIPE_IDLE)) {
		/*
		 * If RP is not idle, then it must be processing this WR.
		 * Abort this request to make the RPipe idle.
		 */
			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_xfer_timeout_handler: rp not idle");

			mutex_exit(&hdl->rp_mutex);
			rval = wusb_wa_rpipe_abort(wa_data->wa_dip,
			    wa_data->wa_default_pipe, hdl);
			mutex_enter(&hdl->rp_mutex);

			USB_DPRINTF_L3(DPRINT_MASK_WHCDI,
			    whcdi_log_handle,
			    "wusb_wa_xfer_timeout_handler: abort rpipe"
			    " fail rval = %d", rval);

			if (rval == 0) {
				/*
				 * wait for the result thread to get
				 * Aborted result. If this wr hasn't been
				 * aborted, wait it.
				 */
				if ((wr->wr_has_aborted == 0) &&
				    (cv_reltimedwait(&wr->wr_cv, &hdl->rp_mutex,
				    drv_usectohz(100 * 1000), TR_CLOCK_TICK)
				    >= 0)) {
				    /* 100ms, random number, long enough? */

					/* the result thread has processed it */
					goto continuing;
				}

				USB_DPRINTF_L3(DPRINT_MASK_WHCDI,
				    whcdi_log_handle,
				    "wusb_wa_xfer_timeout_handler: result"
				    " thread can't get the aborted request");
			}
		}

		/*
		 * 1)The Rpipe is idle, OR,
		 * 2)rpipe_abort fails, OR,
		 * 3)The result thread hasn't got an aborted result in 100ms,
		 * most likely the result is lost. We can not depend on WA to
		 * return result for this aborted request. The WA seems not
		 * always returning such result. This will cause some hcdi
		 * ops hang.
		 */
		hdl->rp_state = WA_RPIPE_STATE_IDLE;
		hdl->rp_curr_wr = NULL;

		/* release this WR's occupied req */
		hdl->rp_avail_reqs += (wr->wr_curr_seg - wr->wr_seg_done);
		cv_signal(&hdl->rp_cv);

		mutex_exit(&hdl->rp_mutex);

		wr->wr_cb(wa_data, wr, USB_CR_TIMEOUT, 0);
		mutex_enter(&hdl->rp_mutex);

continuing:
		wr = next;
	}

	mutex_exit(&hdl->rp_mutex);
}

/* stop timer */
void
wusb_wa_stop_xfer_timer(wusb_wa_trans_wrapper_t *wr)
{
	wusb_wa_rpipe_hdl_t	*hdl = wr->wr_rp;
	timeout_id_t		timer_id;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_stop_xfer_timer: wr = 0x%p", (void *)wr);

	ASSERT(mutex_owned(&hdl->rp_mutex));

	if (hdl->rp_timer_id == 0) {

		return;
	}

	timer_id = hdl->rp_timer_id;
	hdl->rp_timer_id = 0;
	mutex_exit(&hdl->rp_mutex);

	(void) untimeout(timer_id);

	mutex_enter(&hdl->rp_mutex);
}


/*
 * send transfer request and data to the bulk out pipe
 *
 * General transfer function for WA transfer, see Section 8.3.3.
 */
/* ARGSUSED */
int
wusb_wa_wr_xfer(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
    wusb_wa_trans_wrapper_t *wr, usb_flags_t usb_flags)
{
	int		i, rval;
	uint8_t		curr_seg;
	usb_bulk_req_t	*req;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_wr_xfer: wr = 0x%p", (void *)wr);

	ASSERT(wr->wr_seg_array != NULL);

	ASSERT(mutex_owned(&hdl->rp_mutex));

	if (hdl->rp_state == WA_RPIPE_STATE_IDLE) {
		hdl->rp_state = WA_RPIPE_STATE_ACTIVE;
		hdl->rp_curr_wr = wr;
	}
	curr_seg = wr->wr_curr_seg;

	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_wr_xfer: curr_seg = %d, avail_req = %d", curr_seg,
	    hdl->rp_avail_reqs);

	/*
	 * For every segment,
	 *	Step 1: contruct a bulk req containing Transfer
	 *		Request(T8-12 and T8-10)
	 *	Step 2: alloc another bulk req if there's any data
	 *		for OUT endpoints.
	 *
	 *	For IN endpoints, the data is returned in the
	 *	GetResult thread.
	 * Just throw as many as maximum available requests to the RPipe.
	 * If the avail_req is zero, wait!
	 *
	 * When a request is finished, the avail_req will be increased
	 * in the result thread.
	 */
	for (i = curr_seg; i < wr->wr_nsegs; i++) {
		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_wr_xfer: wr=%p curr_seg = %d, avail_req = %d,"
		    " dir=%s", (void *)wr, curr_seg, hdl->rp_avail_reqs,
		    (wr->wr_dir == WA_DIR_IN)?"IN":"OUT");

		/* waiting for available requests if wr is still good */
		while ((hdl->rp_avail_reqs == 0) && (wr->wr_state == 0)) {
			rval = cv_wait_sig(&hdl->rp_cv, &hdl->rp_mutex);
		}

		if ((wr->wr_curr_seg - wr->wr_seg_done) >= 1) {
			/* send only one segment */

			break;
		}

		if (wr->wr_state != 0) {
		/* wr transfer error, don't continue */
			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_wr_xfer: wr_state!=0(%d)", wr->wr_state);

			break;
		}

		req = wr->wr_seg_array[i].seg_trans_reqp;
		ASSERT(req != NULL);

		mutex_exit(&hdl->rp_mutex);
		/* send ith transfer request */
		rval = usb_pipe_bulk_xfer(wa_data->wa_bulkout_ph, req, 0);
		mutex_enter(&hdl->rp_mutex);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_wr_xfer: send transfer request %d failed,"
			    "rv=%d", i, rval);

			wr->wr_seg_array[i].seg_trans_req_state = 0; /* clear */

			if (i == 0) {
				/* no xfer in processing */
				hdl->rp_state = WA_RPIPE_STATE_IDLE;
				hdl->rp_curr_wr = NULL;

				return (rval);
			}
			wusb_wa_abort_req(wa_data, wr, wr->wr_id);
			wr->wr_state = WR_SEG_REQ_ERR;	/* sending tr error */

			break;
		}
		wr->wr_seg_array[i].seg_trans_req_state = 1; /* submitted */

		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_wr_xfer: seg(%d) request(0x%p) sent,"
		    " avail_req = %d", i, (void*)req, hdl->rp_avail_reqs);

		hdl->rp_avail_reqs--;

		/* Get data in the GetResult thread for IN eps */
		if (wr->wr_dir == WA_DIR_IN) {
			wr->wr_curr_seg++;

			/* only send data for out request */
			continue;
		}

		req = wr->wr_seg_array[i].seg_data_reqp;
		if (req == NULL) {
			/* no data stage */
			wr->wr_curr_seg++;

			continue;
		}

		wr->wr_seg_array[i].seg_data_req_state = 1; /* submitted */
		mutex_exit(&hdl->rp_mutex);
		/* send ith data asynchronously */
		rval = usb_pipe_bulk_xfer(wa_data->wa_bulkout_ph, req, 0);
		mutex_enter(&hdl->rp_mutex);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_wr_xfer: send transfer data %d failed",
			    i);

			wr->wr_seg_array[i].seg_data_req_state = 0; /* clear */

			wusb_wa_abort_req(wa_data, wr, wr->wr_id);
			wr->wr_state = WR_SEG_DAT_ERR; /* sending data error */

			/* not inc rp_avail_reqs until callback */

			break;
		}

		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_wr_xfer: seg(%d) data(0x%p) sent, avail_req = %d",
		    i, (void*)req, hdl->rp_avail_reqs);

		wr->wr_curr_seg++;
	}

	/* start timer */
	wusb_wa_start_xfer_timer(hdl);
	/*
	 * return success even if the xfer is not complete, the callback
	 * will only continue sending segs when (wr_error_state = 0 &&
	 * wr_curr_seg < wr_nsegs)
	 */
	return (USB_SUCCESS);
}

/*
 * submit wr according to rpipe status
 *	- check RPipe state
 *	- call general WA transfer function to do transfer
 *
 * usba only submits one transfer to the host controller per pipe at a time
 * and starts next when the previous one completed. So the hwahc now
 * assumes one transfer per rpipe at a time. This won't be necessary to
 * change unless the usba scheme is changed.
 */
int
wusb_wa_submit_ctrl_wr(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	wusb_wa_trans_wrapper_t *wr, usb_ctrl_req_t *ctrl_reqp,
	usb_flags_t usb_flags)
{
	int		rval;

	mutex_enter(&hdl->rp_mutex);
	switch (hdl->rp_state) {
	case WA_RPIPE_STATE_IDLE:
		rval = wusb_wa_wr_xfer(wa_data, hdl, wr, usb_flags);
		break;
	case WA_RPIPE_STATE_ACTIVE:
		/* only allow one req at a time, this should not happen */
	default:
		rval = USB_PIPE_ERROR;
		break;
	}
	mutex_exit(&hdl->rp_mutex);

	if (rval != USB_SUCCESS) {
		if (ctrl_reqp->ctrl_completion_reason == USB_CR_OK) {
			ctrl_reqp->ctrl_completion_reason = usba_rval2cr(rval);
		}
		mutex_enter(&hdl->rp_mutex);
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_submit_ctrl_wr:fail, reqp=0x%p, rpstat=%d, rv=%d",
		    (void*)ctrl_reqp, hdl->rp_state, rval);

		mutex_exit(&hdl->rp_mutex);

		wusb_wa_free_trans_wrapper(wr);
	}

	/* In other cases, wr will be freed in callback */
	return (rval);
}

/*
 * Transfer a control request:
 *	- allocate a transfer wrapper(TW) for this request
 *	- submit this TW
 */
int
wusb_wa_ctrl_xfer(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t *ph, usb_ctrl_req_t *ctrl_reqp,
	usb_flags_t usb_flags)
{
	int			rval;
	wusb_wa_trans_wrapper_t	*wr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_ctrl_xfer: ph = 0x%p reqp = 0x%p",
	    (void*)ph, (void*)ctrl_reqp);

	wr = wusb_wa_alloc_ctrl_resources(wa_data, hdl, ph, ctrl_reqp,
	    usb_flags);
	if (wr == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_ctrl_req: alloc ctrl resource failed");

		return (USB_NO_RESOURCES);
	}

	rval = wusb_wa_submit_ctrl_wr(wa_data, hdl, wr, ctrl_reqp, usb_flags);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_submit_ctrl_wr: submit ctrl req failed, rval = %d",
		    rval);
	}

	return (rval);
}

/*
 * submit wr according to rpipe status
 *
 * usba only submits one transfer to the host controller per pipe at a time
 * and starts next when the previous one completed. So the hwahc now
 * assumes one transfer per rpipe at a time. This won't be necessary to
 * change unless the usba scheme is changed.
 */
int
wusb_wa_submit_bulk_wr(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	wusb_wa_trans_wrapper_t *wr, usb_bulk_req_t *bulk_reqp,
	usb_flags_t usb_flags)
{
	int		rval;

	mutex_enter(&hdl->rp_mutex);
	switch (hdl->rp_state) {
	case WA_RPIPE_STATE_IDLE:
		rval = wusb_wa_wr_xfer(wa_data, hdl, wr, usb_flags);
		break;
	case WA_RPIPE_STATE_ACTIVE:
		/* only allow one req at a time, this should not happen */
	default:
		rval = USB_PIPE_ERROR;
		break;
	}
	mutex_exit(&hdl->rp_mutex);

	if (rval != USB_SUCCESS) {
		if (bulk_reqp->bulk_completion_reason == USB_CR_OK) {
			bulk_reqp->bulk_completion_reason = usba_rval2cr(rval);
		}
		wusb_wa_free_trans_wrapper(wr);
	}

	/* In other cases, wr will be freed in callback */
	return (rval);
}

/*
 * WA general bulk transfer
 *	- allocate bulk resources
 *	- submit the bulk request
 */
int
wusb_wa_bulk_xfer(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t *ph, usb_bulk_req_t *bulk_reqp,
	usb_flags_t usb_flags)
{
	int			rval;
	wusb_wa_trans_wrapper_t	*wr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_bulk_xfer: ph = 0x%p reqp = 0x%p",
	    (void *)ph, (void *)bulk_reqp);

	wr = wusb_wa_alloc_bulk_resources(wa_data, hdl, ph, bulk_reqp,
	    usb_flags);
	if (wr == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_bulk_xfer: alloc bulk resource failed");

		return (USB_NO_RESOURCES);
	}

	rval = wusb_wa_submit_bulk_wr(wa_data, hdl, wr, bulk_reqp,
	    usb_flags);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_bulk_req: submit bulk req failed, rval = %d",
		    rval);
	}

	return (rval);
}

/*
 * submit wr according to rpipe status
 *
 * usba only submits one transfer to the host controller per pipe at a time
 * and starts next when the previous one completed. So the hwahc now
 * assumes one transfer per rpipe at a time. This won't be necessary to
 * change unless the usba scheme is changed.
 */
int
wusb_wa_submit_intr_wr(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	wusb_wa_trans_wrapper_t *wr, usb_intr_req_t *intr_reqp,
	usb_flags_t usb_flags)
{
	int		rval;

	mutex_enter(&hdl->rp_mutex);
	switch (hdl->rp_state) {
	case WA_RPIPE_STATE_IDLE:
		rval = wusb_wa_wr_xfer(wa_data, hdl, wr, usb_flags);
		break;
	case WA_RPIPE_STATE_ACTIVE:
		/* only allow one req at a time, this should not happen */
	default:
		rval = USB_PIPE_ERROR;
		break;
	}
	mutex_exit(&hdl->rp_mutex);

	if (rval != USB_SUCCESS) {
		if (intr_reqp->intr_completion_reason == USB_CR_OK) {
			intr_reqp->intr_completion_reason = usba_rval2cr(rval);
		}
		wusb_wa_free_trans_wrapper(wr);
	}

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_submit_intr_wr: submit intr req, rval = %d", rval);

	/* In other cases, wr will be freed in callback */
	return (rval);
}

/*
 * do intr xfer
 *
 * Now only one time intr transfer is supported. intr polling is not
 * supported.
 */
int
wusb_wa_intr_xfer(wusb_wa_data_t *wa_data, wusb_wa_rpipe_hdl_t *hdl,
	usba_pipe_handle_data_t *ph, usb_intr_req_t *intr_reqp,
	usb_flags_t usb_flags)
{
	int			rval;
	wusb_wa_trans_wrapper_t	*wr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_intr_xfer: ph = 0x%p reqp = 0x%p",
	    (void *)ph, (void *)intr_reqp);

	wr = wusb_wa_alloc_intr_resources(wa_data, hdl, ph, intr_reqp,
	    usb_flags);
	if (wr == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_intr_req: alloc intr resource failed");

		return (USB_NO_RESOURCES);
	}

	rval = wusb_wa_submit_intr_wr(wa_data, hdl, wr, intr_reqp,
	    usb_flags);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_intr_req: submit intr req failed, rval = %d",
		    rval);

		return (rval);
	}

	/*
	 * have successfully duplicate and queue one more request on
	 * the pipe. Increase the pipe request count.
	 */
	if ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		mutex_enter(&ph->p_mutex);

		/*
		 * this count will be decremented by usba_req_normal_cb
		 * or usba_req_exc_cb (called by hcdi_do_cb <-- usba_hcdi_cb)
		 */
		ph->p_req_count++;

		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_intr_req: p_req_cnt = %d", ph->p_req_count);

		mutex_exit(&ph->p_mutex);
	}

	return (rval);
}

/*
 * For an IN transfer request, receive transfer data on bulk-in ept
 * The bulk_req has been allocated when allocating transfer resources
 */
int
wusb_wa_get_data(wusb_wa_data_t *wa_data, wusb_wa_seg_t *seg, uint32_t len)
{
	usb_bulk_req_t		*req;
	int			rval;

	if (len == 0) {

		return (USB_SUCCESS);
	}

	USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_get_data: get data for wr: 0x%p", (void *)seg->seg_wr);

	req = seg->seg_data_reqp;
	ASSERT(req != NULL);

	/* adjust bulk in length to actual length */
	req->bulk_len = len;
	rval = usb_pipe_bulk_xfer(wa_data->wa_bulkin_ph, req,
	    USB_FLAGS_SLEEP);

	return (rval);
}

/*
 * to retrieve a transfer_wrapper by dwTransferID
 *
 * Though to search a list looks not so efficient, we have to give up
 * id32_lookup(). When a transfer segment is throwed to HWA device, we
 * can't anticipate when the result will be returned, even if we try to
 * abort it. If we have freed the transfer wrapper due to timeout, then
 * after a moment, that TW's segment is accomplished by hardware. If
 * id32_lookup() is used to look up corresponding TW, we'll get an invalid
 * address. Unfortunately, id32_lookup() can't judge validity of its
 * returned address.
 */
wusb_wa_trans_wrapper_t *
wusb_wa_retrieve_wr(wusb_wa_data_t *wa_data, uint32_t id)
{
	wusb_wa_rpipe_hdl_t *rph;
	uint16_t	i;
	wusb_wa_trans_wrapper_t *tw;

	for (i = 0; i < wa_data->wa_num_rpipes; i++) {
		rph = &wa_data->wa_rpipe_hdl[i];

		mutex_enter(&rph->rp_mutex);
		/* all outstanding TWs are put on the timeout list */
		tw = rph->rp_timeout_list;

		while (tw) {
			if (tw->wr_id == id) {
				mutex_exit(&rph->rp_mutex);
				return (tw);
			}
			tw = tw->wr_timeout_next;
		}
		mutex_exit(&rph->rp_mutex);
	}

	return (NULL);
}

/* endlessly wait for transfer result on bulk-in ept and handle the result */
int
wusb_wa_get_xfer_result(wusb_wa_data_t *wa_data)
{
	usb_bulk_req_t		*req;
	int			rval;
	mblk_t			*data;
	uint8_t			*p;
	wa_xfer_result_t	result;
	wusb_wa_trans_wrapper_t	*wr;
	wusb_wa_seg_t		*seg;
	uint8_t			status;
	uint_t			len;
	uint8_t			lastseg = 0;
	usb_cr_t		cr;
	uint32_t		act_len;
	wusb_wa_rpipe_hdl_t	*hdl;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_get_xfer_result: started, wa=0x%p", (void*)wa_data);

	/* grab lock before accessing wa_data */
	mutex_enter(&wa_data->wa_mutex);

	len = wa_data->wa_bulkin_ept.wMaxPacketSize;

	req = usb_alloc_bulk_req(wa_data->wa_dip, len,
	    USB_FLAGS_NOSLEEP);
	if (req == NULL) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_get_xfer_result: alloc bulk req failed");

		mutex_exit(&wa_data->wa_mutex);

		return (USB_NO_RESOURCES);
	}

	req->bulk_len = len;
	req->bulk_timeout = 0;
	req->bulk_attributes = USB_ATTRS_SHORT_XFER_OK |
	    USB_ATTRS_AUTOCLEARING;

	mutex_exit(&wa_data->wa_mutex);

	/* Get the Transfer Result head, see Table 8-14 */
	rval = usb_pipe_bulk_xfer(wa_data->wa_bulkin_ph, req,
	    USB_FLAGS_SLEEP);
	if ((rval != USB_SUCCESS) || (req->bulk_data == NULL)) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_get_xfer_result: bulk xfer failed or "
		    "null data returned, rval=%d, req->bulk_data = %p",
		    rval, (void*)req->bulk_data);
		usb_free_bulk_req(req);

		return (rval);
	}

	data = req->bulk_data;
	p = data->b_rptr;

	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_get_xfer_result: received data len = %d",
	    (int)MBLKL(data));

	if ((MBLKL(data) != WA_XFER_RESULT_LEN) ||
	    (p[1] != WA_RESULT_TYPE_TRANSFER)) {
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_get_xfer_result: invalid xfer result, "
		    "len = %d, p0 = 0x%x, p1 = 0x%x, p6 = 0x%x",
		    (int)MBLKL(data), p[0], p[1], p[6]);

		usb_free_bulk_req(req);

		return (USB_SUCCESS); /* don't stop this thread */
	}

	/* Transfer result. Section 8.3.3.4 */
	(void) usb_parse_data("ccllccl", p, WA_XFER_RESULT_LEN, &result,
	    sizeof (wa_xfer_result_t));


	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_get_xfer_result: id = 0x%x len = 0x%x nseg = 0x%02x"
	    " status = 0x%02x(0x%02x)", result.dwTransferID,
	    result.dwTransferLength, result.bTransferSegment,
	    result.bTransferStatus, p[11]&0x0f);

	req->bulk_data = NULL; /* don't free it. we still need it */
	usb_free_bulk_req(req);

	status = result.bTransferStatus;
	if ((status & 0x3f) == WA_STS_NOT_FOUND) {
		freemsg(data);
		/*
		 * The result is just ignored since the transfer request
		 * has completed
		 */
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_get_xfer_result: TransferID not found");

		return (USB_SUCCESS);
	}

	mutex_enter(&wa_data->wa_mutex);
	wr = wusb_wa_retrieve_wr(wa_data, result.dwTransferID);
	if ((wr == NULL)) {
	/* this id's corresponding WR may have been freed by timeout handler */
		USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_get_xfer_result: wr == deadbeef or NULL");

		mutex_exit(&wa_data->wa_mutex);
		freemsg(data);

		return (USB_SUCCESS);
	}

	/* bit 7 is last segment flag */
	if ((result.bTransferSegment & 0x7f) >= wr->wr_nsegs) {
		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_get_xfer_result: error - "
		    " bTransferSegment(%d) > segment coutnts(%d)",
		    (result.bTransferSegment & 0x7f), wr->wr_nsegs);

		goto err;
	}

	lastseg = result.bTransferSegment & 0x80;
	hdl = wr->wr_rp;

	mutex_enter(&hdl->rp_mutex);
	seg = &wr->wr_seg_array[result.bTransferSegment & 0x7f];
	seg->seg_status = result.bTransferStatus;
	act_len = seg->seg_actual_len = result.dwTransferLength;

	/*
	 * if this is the last segment, we should not continue.
	 * IMPT: we expect the WA deliver result sequentially.
	 */
	seg->seg_done = (result.bTransferSegment) & 0x80;

	wr->wr_seg_done++;
	hdl->rp_avail_reqs++;
	USB_DPRINTF_L2(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_get_xfer_result: wr = %p, rp=%p, avail_req=%d", (void*)wr,
	    (void*)wr->wr_rp, hdl->rp_avail_reqs);

	cv_broadcast(&hdl->rp_cv);

	if (status & 0x40) {
		status = 0; /* ignore warning, see Tab8-15 */
	}
	seg->seg_status = status;

	/* Error bit set */
	if (status & 0x80) {
		/* don't change timeout error */
		if (wr->wr_state != WR_TIMEOUT) {
			wr->wr_state = WR_XFER_ERR;
		}

		/*
		 * The timeout handler is waiting, but the result thread will
		 * process this wr.
		 */
		if ((wr->wr_state == WR_TIMEOUT) &&
		    (status & 0x3F) == WA_STS_ABORTED) {
			wr->wr_has_aborted = 1;
			cv_signal(&wr->wr_cv); /* to inform timeout hdler */
		}

		mutex_exit(&hdl->rp_mutex);
		/* seg error, don't proceed with this WR */
		goto err;
	}

	USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_get_xfer_result: status = 0x%02x dir=%s",
	    status, (wr->wr_dir == WA_DIR_IN)?"IN":"OUT");

	/*
	 * for an IN endpoint and data length > 0 and no error, read in
	 * the real data. Otherwise, for OUT EP, or data length = 0, or
	 * segment error, don't read.
	 */
	if ((wr->wr_dir == WA_DIR_IN) &&
	    (act_len > 0) &&
	    ((status & 0x3F) == 0)) { /* if segment error, don't read */
		/* receive data */
		mutex_exit(&hdl->rp_mutex);
		mutex_exit(&wa_data->wa_mutex);
		rval = wusb_wa_get_data(wa_data, seg, act_len);
		mutex_enter(&wa_data->wa_mutex);
		mutex_enter(&hdl->rp_mutex);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_get_xfer_result: can't get seg data:%d",
			    rval);

			mutex_exit(&hdl->rp_mutex);

			goto err;
		}

		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_get_xfer_result: get (%dB) data for IN ep",
		    act_len);
	}

	mutex_exit(&hdl->rp_mutex);

	mutex_exit(&wa_data->wa_mutex);

	/* check if the whole transfer has completed */
	wusb_wa_check_req_done(wa_data, wr, lastseg);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_get_xfer_result: ended");

	freemsg(data);

	return (USB_SUCCESS);

err:
	mutex_exit(&wa_data->wa_mutex);

	mutex_enter(&hdl->rp_mutex);
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_get_xfer_result: segment(%02x) error, abort wr 0x%p,"
	    "wr_state=%d", result.bTransferSegment, (void*)wr, wr->wr_state);

	/* if it's timeout, just return the TIMEOUT error */
	if (wr->wr_state == WR_TIMEOUT) {
		cr = USB_CR_TIMEOUT;
	} else {
		cr = wusb_wa_sts2cr(status);
	}

	mutex_exit(&hdl->rp_mutex);

	wusb_wa_handle_error(wa_data, wr, cr);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_get_xfer_result: error end, cr=%d",
	    cr);

	freemsg(data);

	return (USB_SUCCESS);
}


static void
wusb_wa_handle_error(wusb_wa_data_t *wa_data, wusb_wa_trans_wrapper_t *wr,
    usb_cr_t cr)
{
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_handle_error: start");

	mutex_enter(&wr->wr_rp->rp_mutex);
	if (wr->wr_seg_done != wr->wr_curr_seg) {
	/* still segments pending, abort them */
		USB_DPRINTF_L3(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_handle_error: segment err, abort other segs");

		wusb_wa_abort_req(wa_data, wr, wr->wr_id);
	}

	wusb_wa_stop_xfer_timer(wr);
	wr->wr_rp->rp_state = WA_RPIPE_STATE_IDLE;
	wr->wr_rp->rp_curr_wr = NULL;
	mutex_exit(&wr->wr_rp->rp_mutex);

	wr->wr_cb(wa_data, wr, cr, 1);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_handle_error: error end, cr=%d",
	    cr);
}

/*
 * Check if current request is done, if yes, do callback and move on to
 * next request; if there is any uncleared error, do callback to cleanup
 * the pipe
 */
void
wusb_wa_check_req_done(wusb_wa_data_t *wa_data,
    wusb_wa_trans_wrapper_t *wr, uint8_t lastseg)
{
	wusb_wa_rpipe_hdl_t	*hdl = wr->wr_rp;
	wusb_wa_seg_t		*seg;
	int			i, rval;
	usb_cr_t		cr;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_check_req_done: wr = 0x%p, lastseg=%02x",
	    (void*)wr, lastseg);

	mutex_enter(&hdl->rp_mutex);
	/* not done: submitted segs not finished and lastseg not set */
	if ((wr->wr_seg_done != wr->wr_curr_seg) && (!lastseg)) {
		mutex_exit(&hdl->rp_mutex);

		return;
	}

	if (wr->wr_state != 0) { /* abort somewhere */
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_check_req_done: tw(%p) aborted somewhere",
		    (void*)wr);
		cr = USB_CR_UNSPECIFIED_ERR;

		goto reset;
	}

	/* check if there is any error */
	for (i = 0; i < wr->wr_curr_seg; i++) {
		seg = &wr->wr_seg_array[i];
		if (seg->seg_status != WA_STS_SUCCESS) {
			/* what about short xfer? need to fix */
			cr = wusb_wa_sts2cr(seg->seg_status);
			USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_check_req_done: seg fail, status=%02x",
			    seg->seg_status);

			goto reset;
		}

		if (seg->seg_done == 0x80) {
		/* device has told this is the last segment, we're done */
			USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
			    "wusb_wa_check_req_done: last seg");

			goto done;
		}
	}

	/* check if current request has completed */
	/*
	 * Transfer another segment.
	 *
	 */
	if (wr->wr_curr_seg < wr->wr_nsegs) {
		/* send the remained segments */
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_check_req_done: req not completed, restart");

		rval = wusb_wa_wr_xfer(wa_data, hdl, wr, wr->wr_flags);
		if (rval != USB_SUCCESS) {
			cr = usba_rval2cr(rval);

			goto reset;
		}

		mutex_exit(&hdl->rp_mutex);

		return;
	}

done:
	wusb_wa_stop_xfer_timer(wr);

	/* release the occupied requests */
	hdl->rp_avail_reqs += (wr->wr_curr_seg - wr->wr_seg_done);
	cv_signal(&hdl->rp_cv);

	hdl->rp_state = WA_RPIPE_STATE_IDLE;
	hdl->rp_curr_wr = NULL;
	wr->wr_state = WR_FINISHED;
	mutex_exit(&hdl->rp_mutex);

	wr->wr_cb(wa_data, wr, USB_CR_OK, 0);

	/* Need to move on to next request? usba will do this */
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_check_req_done: ended");

	return;

reset:
	wusb_wa_stop_xfer_timer(wr);

	/* not necessary to reset the RPipe */
	hdl->rp_state = WA_RPIPE_STATE_IDLE;
	hdl->rp_curr_wr = NULL;

	hdl->rp_avail_reqs += (wr->wr_curr_seg - wr->wr_seg_done);
	cv_signal(&hdl->rp_cv);

	/* if it's timeout, just return the TIMEOUT error */
	if (wr->wr_state == WR_TIMEOUT)
		cr = USB_CR_TIMEOUT;

	mutex_exit(&hdl->rp_mutex);

	wr->wr_cb(wa_data, wr, cr, 1);
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_check_req_done: reset end");
}

/*
 * callback for ctrl transfer
 *
 * reset_flag: not support yet
 */
void
wusb_wa_handle_ctrl(wusb_wa_data_t *wa_data, wusb_wa_trans_wrapper_t *wr,
	usb_cr_t cr, uint_t reset_flag)
{
	usb_ctrl_req_t	*req;
	usb_bulk_req_t	*bulk_req;
	mblk_t		*data, *bulk_data;
	int		i;
	size_t		len;
	wusb_wa_seg_t	*seg;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_handle_ctrl: wr = 0x%p, cr = 0x%x, flag=%d",
	    (void*)wr, cr, reset_flag);

	req = (usb_ctrl_req_t *)wr->wr_reqp;

	if ((wr->wr_dir == WA_DIR_OUT) || (cr != USB_CR_OK)) {

		/* do callback */
		wusb_wa_callback(wa_data, wr->wr_ph, wr, cr);

		return;
	}

	mutex_enter(&wr->wr_rp->rp_mutex);
	data = req->ctrl_data;
	for (i = 0; i < wr->wr_nsegs; i++) {
		seg = &wr->wr_seg_array[i];
		/* copy received data to original req buffer */
		bulk_req = (usb_bulk_req_t *)
		    wr->wr_seg_array[i].seg_data_reqp;
		bulk_data = bulk_req->bulk_data;
		len = MBLKL(bulk_data);
		bcopy(bulk_data->b_rptr, data->b_wptr, len);
		data->b_wptr += len;
		if (len < wr->wr_seg_array[i].seg_len) {
			/* short xfer */
			break;
		}

		if (seg->seg_done == 0x80) {
		/* last segment, finish */
			break;
		}
	}

	mutex_exit(&wr->wr_rp->rp_mutex);
	/* do callback */
	wusb_wa_callback(wa_data, wr->wr_ph, wr, cr);
}

/*
 * callback for bulk transfer
 *
 * reset_flag: not support yet
 */
void
wusb_wa_handle_bulk(wusb_wa_data_t *wa_data, wusb_wa_trans_wrapper_t *wr,
	usb_cr_t cr, uint_t reset_flag)
{
	usb_bulk_req_t	*req;
	usb_bulk_req_t	*bulk_req;
	mblk_t		*data, *bulk_data;
	int		i;
	size_t		len;
	wusb_wa_seg_t	*seg;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_handle_bulk: wr = 0x%p, cr = 0x%x, flag=%d",
	    (void*)wr, cr, reset_flag);

	req = (usb_bulk_req_t *)wr->wr_reqp;

	if ((wr->wr_dir == WA_DIR_OUT) || (cr != USB_CR_OK)) {
		/* do callback */
		wusb_wa_callback(wa_data, wr->wr_ph, wr, cr);

		return;
	}

	mutex_enter(&wr->wr_rp->rp_mutex);
	data = req->bulk_data;
	for (i = 0; i < wr->wr_nsegs; i++) {
		seg = &wr->wr_seg_array[i];
		/* copy received data to original req buffer */
		bulk_req = (usb_bulk_req_t *)
		    wr->wr_seg_array[i].seg_data_reqp;
		bulk_data = bulk_req->bulk_data;
		len = MBLKL(bulk_data);
		bcopy(bulk_data->b_rptr, data->b_wptr, len);
		data->b_wptr += len;
		if (len < wr->wr_seg_array[i].seg_len) {
			/* short xfer */
			break;
		}

		if (seg->seg_done == 0x80) {
		/* last segment, finish */
			break;
		}
	}

	mutex_exit(&wr->wr_rp->rp_mutex);
	/* do callback */
	wusb_wa_callback(wa_data, wr->wr_ph, wr, cr);
}

int
wa_submit_periodic_req(wusb_wa_data_t *wa_data, usba_pipe_handle_data_t *ph)
{
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wa_submit_periodic_req: wa_data=0x%p, ph=0x%p",
	    (void*)wa_data, (void*)ph);

	return (wa_data->pipe_periodic_req(wa_data, ph));
}

/*
 * callback for intr transfer
 *
 * reset_flag: not support yet
 */
void
wusb_wa_handle_intr(wusb_wa_data_t *wa_data, wusb_wa_trans_wrapper_t *wr,
	usb_cr_t cr, uint_t reset_flag)
{
	usb_intr_req_t	*req;
	usb_req_attrs_t	attrs;
	usba_pipe_handle_data_t *ph = wr->wr_ph;
	usb_bulk_req_t	*bulk_req;
	mblk_t		*data, *bulk_data;
	int		i;
	size_t		len;
	int		rval;
	wusb_wa_seg_t	*seg;

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_handle_intr: wr = 0x%p, cr = 0x%x, flag=%d",
	    (void*)wr, cr, reset_flag);

	req = (usb_intr_req_t *)wr->wr_reqp;
	attrs = req->intr_attributes;

	if ((wr->wr_dir == WA_DIR_OUT) || (cr != USB_CR_OK)) {
		/* do callback */
		wusb_wa_callback(wa_data, wr->wr_ph, wr, cr);

		return;
	}

	mutex_enter(&wr->wr_rp->rp_mutex);
	/* copy data to client's buffer */
	data = req->intr_data;
	for (i = 0; i < wr->wr_nsegs; i++) {
		seg = &wr->wr_seg_array[i];
		/* copy received data to original req buffer */
		bulk_req = (usb_bulk_req_t *)
		    wr->wr_seg_array[i].seg_data_reqp;
		bulk_data = bulk_req->bulk_data;
		len = MBLKL(bulk_data);
		bcopy(bulk_data->b_rptr, data->b_wptr, len);
		data->b_wptr += len;
		if (len < wr->wr_seg_array[i].seg_len) {
			/* short xfer */
			break;
		}

		if (seg->seg_done & 0x80) {

			break;
		}
	}

	if (attrs & USB_ATTRS_ONE_XFER) {
	/* client requires ONE_XFER request, return */
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_handle_intr: ONE_XFER set");

		mutex_exit(&wr->wr_rp->rp_mutex);
		goto finish;
	}

	/* polling mode */
	mutex_exit(&wr->wr_rp->rp_mutex);
	rval = wa_submit_periodic_req(wa_data, ph);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
		    "wusb_wa_handle_intr: polling, fail to resubmit req");

		goto finish;
	}

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_handle_intr: polling, resubmit request, rv=%d", rval);

finish:
	/* do callback */
	wusb_wa_callback(wa_data, wr->wr_ph, wr, cr);

	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_handle_intr: end");
}

/*
 * free transfer wrapper
 * call host controller driver callback for completion handling
 *
 * This callback will call WA's specific callback function.
 * The callback functions should call usba_hcdi_cb() to pass request
 * back to client driver.
 */
void
wusb_wa_callback(wusb_wa_data_t *wa_data, usba_pipe_handle_data_t *ph,
    wusb_wa_trans_wrapper_t *wr, usb_cr_t cr)
{
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_callback: wr=0x%p, cr=0x%x, ph=0x%p, req = 0x%p",
	    (void*)wr, cr, (void*)ph, (void*)((wr == NULL)?0:wr->wr_reqp));

	if (cr == USB_CR_FLUSHED) {
		/*
		 * the wr is aborted. mark the rpipe as error,
		 * so that the periodic xfer callbacks will not submit
		 * further requests.
		 */
		mutex_enter(&wr->wr_rp->rp_mutex);
		wr->wr_rp->rp_state = WA_RPIPE_STATE_ERROR;
		mutex_exit(&wr->wr_rp->rp_mutex);
	}

	wa_data->rpipe_xfer_cb(wa_data->wa_dip, ph, wr, cr);

	/*
	 * need to consider carefully when to free wrapper
	 * if the rpipe is reset, what to do with current wr in processing?
	 */
	USB_DPRINTF_L4(DPRINT_MASK_WHCDI, whcdi_log_handle,
	    "wusb_wa_callback: hwahc callback finish for wr= 0x%p, free it",
	    (void*)wr);

	wusb_wa_free_trans_wrapper(wr);
}

static struct {
	uint8_t	status;
	usb_cr_t	cr;
} sts2cr[] = {
	{WA_STS_SUCCESS,	USB_CR_OK},
	{WA_STS_HALTED,		USB_CR_STALL},
	{WA_STS_DATA_BUFFER_ERROR,	USB_CR_DATA_OVERRUN},
	{WA_STS_BABBLE,		USB_CR_DATA_UNDERRUN},
	{WA_STS_NOT_FOUND,	USB_CR_NOT_ACCESSED},
	{WA_STS_INSUFFICIENT_RESOURCE,	USB_CR_NO_RESOURCES},
	{0x80 | WA_STS_TRANSACTION_ERROR,	USB_CR_STALL},
	{0x40 | WA_STS_TRANSACTION_ERROR,	USB_CR_OK},
	{WA_STS_ABORTED,	USB_CR_FLUSHED},
	{WA_STS_RPIPE_NOT_READY,	USB_CR_DEV_NOT_RESP},
	{WA_STS_INVALID_REQ_FORMAT,	USB_CR_CRC},
	{WA_STS_UNEXPECTED_SEGMENT_NUM,	USB_CR_UNEXP_PID},
	{WA_STS_RPIPE_TYPE_MISMATCH,	USB_CR_NOT_SUPPORTED},
	{WA_STS_PACKET_DISCARDED,	USB_CR_PID_CHECKFAILURE},
	{0xff,		0}	/* end */
};

/* translate transfer status to USB completion reason */
usb_cr_t
wusb_wa_sts2cr(uint8_t rawstatus)
{
	int	i;
	uint8_t	status;

	/* cares about bits5:0 in WUSB 1.0 */
	if ((rawstatus & 0x1f) == WA_STS_TRANSACTION_ERROR) {
		status = rawstatus;
	} else {
		status = rawstatus & 0x1f;
	}

	for (i = 0; sts2cr[i].status != 0xff; i++) {
		if (sts2cr[i].status == status) {

			return (sts2cr[i].cr);
		}
	}

	return (USB_CR_UNSPECIFIED_ERR);
}
