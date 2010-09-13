/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007 by  Lukas Turek <turek@ksvi.mff.cuni.cz>
 * Copyright (c) 2007 by  Jiri Svoboda <jirik.svoboda@seznam.cz>
 * Copyright (c) 2007 by  Martin Krulis <martin.krulis@matfyz.cz>
 * Copyright (c) 2006 by Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2006 by Florian Stoehr <ich@florian-stoehr.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/*
 * ZD1211 wLAN driver
 * USB communication
 *
 * Manage USB communication with the ZD-based device.
 */

#include <sys/byteorder.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/mac_provider.h>

#include "zyd.h"
#include "zyd_reg.h"

static int zyd_usb_disconnect(dev_info_t *dip);
static int zyd_usb_reconnect(dev_info_t *dip);
static zyd_res zyd_usb_data_in_start_request(struct zyd_usb *uc);

static zyd_usb_info_t usb_ids[] = {
	{0x53, 0x5301, ZYD_ZD1211B},
	{0x105, 0x145f, ZYD_ZD1211},
	{0x411, 0xda, ZYD_ZD1211B},
	{0x471, 0x1236, ZYD_ZD1211B},
	{0x471, 0x1237, ZYD_ZD1211B},
	{0x50d, 0x705c, ZYD_ZD1211B},
	{0x586, 0x3401, ZYD_ZD1211},
	{0x586, 0x3402, ZYD_ZD1211},
	{0x586, 0x3407, ZYD_ZD1211},
	{0x586, 0x3409, ZYD_ZD1211},
	{0x586, 0x3410, ZYD_ZD1211B},
	{0x586, 0x3412, ZYD_ZD1211B},
	{0x586, 0x3413, ZYD_ZD1211B},
	{0x586, 0x340a, ZYD_ZD1211B},
	{0x586, 0x340f, ZYD_ZD1211B},
	{0x79b, 0x4a, ZYD_ZD1211},
	{0x79b, 0x62, ZYD_ZD1211B},
	{0x7b8, 0x6001, ZYD_ZD1211},
	{0x83a, 0x4505, ZYD_ZD1211B},
	{0xace, 0x1211, ZYD_ZD1211},
	{0xace, 0x1215, ZYD_ZD1211B},
	{0xb05, 0x170c, ZYD_ZD1211},
	{0xb05, 0x171b, ZYD_ZD1211B},
	{0xb3b, 0x1630, ZYD_ZD1211},
	{0xb3b, 0x5630, ZYD_ZD1211},
	{0xbaf, 0x121, ZYD_ZD1211B},
	{0xcde, 0x1a, ZYD_ZD1211B},
	{0xdf6, 0x9071, ZYD_ZD1211},
	{0xdf6, 0x9075, ZYD_ZD1211},
	{0x126f, 0xa006, ZYD_ZD1211},
	{0x129b, 0x1666, ZYD_ZD1211},
	{0x129b, 0x1667, ZYD_ZD1211B},
	{0x13b1, 0x1e, ZYD_ZD1211},
	{0x13b1, 0x24, ZYD_ZD1211B},
	{0x1435, 0x711, ZYD_ZD1211},
	{0x14ea, 0xab13, ZYD_ZD1211},
	{0x157e, 0x300b, ZYD_ZD1211},
	{0x157e, 0x300d, ZYD_ZD1211B},
	{0x157e, 0x3204, ZYD_ZD1211},
	{0x1582, 0x6003, ZYD_ZD1211B},
	{0x1740, 0x2000, ZYD_ZD1211},
	{0x2019, 0x5303, ZYD_ZD1211B},
	{0x6891, 0xa727, ZYD_ZD1211}
};

/*
 * Get mac rev for usb vendor/product id.
 */
zyd_mac_rev_t
zyd_usb_mac_rev(uint16_t vendor, uint16_t product)
{
	int i;

	ZYD_DEBUG((ZYD_DBG_USB, "matching device usb%x,%x\n", vendor, product));
	for (i = 0; i < sizeof (usb_ids) / sizeof (zyd_usb_info_t); i++) {
		if (vendor == usb_ids[i].vendor_id &&
		    product == usb_ids[i].product_id)
			return (usb_ids[i].mac_rev);
	}

	ZYD_DEBUG((ZYD_DBG_USB, "assuming ZD1211B\n"));
	return (ZYD_ZD1211B);
}

/*
 * Vendor-specific write to the default control pipe.
 */
static zyd_res
zyd_usb_ctrl_send(struct zyd_usb *uc, uint8_t request, uint16_t value,
    uint8_t *data, uint16_t len)
{
	int err;
	int retry = 0;
	mblk_t *msg;
	usb_ctrl_setup_t setup;

	/* Always clean structures before use */
	bzero(&setup, sizeof (setup));
	setup.bmRequestType =
	    USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_HOST_TO_DEV;
	setup.bRequest = request;
	setup.wValue = value;
	setup.wIndex = 0;
	setup.wLength = len;
	setup.attrs = USB_ATTRS_NONE;

	if ((msg = allocb(len, BPRI_HI)) == NULL)
		return (ZYD_FAILURE);

	bcopy(data, msg->b_wptr, len);
	msg->b_wptr += len;

	while ((err = usb_pipe_ctrl_xfer_wait(uc->cdata->dev_default_ph,
	    &setup, &msg, NULL, NULL, 0)) != USB_SUCCESS) {
		if (retry++ > 3)
			break;
	}

	freemsg(msg);

	if (err != USB_SUCCESS) {
		ZYD_DEBUG((ZYD_DBG_USB,
		    "control pipe send failure (%d)\n", err));
		return (ZYD_FAILURE);
	}

	return (ZYD_SUCCESS);
}

/*
 * Vendor-specific read from the default control pipe.
 */
static zyd_res
zyd_usb_ctrl_recv(struct zyd_usb *uc, uint8_t request, uint16_t value,
    uint8_t *data, uint16_t len)
{
	int err;
	mblk_t *msg, *tmp_msg;
	usb_ctrl_setup_t setup;
	size_t msg_len;

	ASSERT(data != NULL);

	bzero(&setup, sizeof (setup));
	setup.bmRequestType =
	    USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_DEV_TO_HOST;
	setup.bRequest = request;
	setup.wValue = value;
	setup.wIndex = 0;
	setup.wLength = len;
	setup.attrs = USB_ATTRS_NONE;

	/* Pointer msg must be either set to NULL or point to a valid mblk! */
	msg = NULL;
	err = usb_pipe_ctrl_xfer_wait(uc->cdata->dev_default_ph,
	    &setup, &msg, NULL, NULL, 0);

	if (err != USB_SUCCESS) {
		ZYD_WARN("control pipe receive failure (%d)\n", err);
		return (ZYD_FAILURE);
	}

	msg_len = msgsize(msg);

	if (msg_len != len) {
		ZYD_WARN("control pipe failure: "
		    "received %d bytes, %d expected\n", (int)msg_len, len);
		return (ZYD_FAILURE);
	}

	if (msg->b_cont != NULL) {
		/* Fragmented message, concatenate */
		tmp_msg = msgpullup(msg, -1);
		freemsg(msg);
		msg = tmp_msg;
	}

	/*
	 * Now we can be sure the message is in a single block
	 * so we can copy it.
	 */
	bcopy(msg->b_rptr, data, len);
	freemsg(msg);

	return (ZYD_SUCCESS);
}

/*
 * Load firmware into the chip.
 */
zyd_res
zyd_usb_loadfirmware(struct zyd_usb *uc, uint8_t *fw, size_t size)
{
	uint16_t addr;
	uint8_t stat;

	ZYD_DEBUG((ZYD_DBG_FW, "firmware size: %lu\n", size));

	addr = ZYD_FIRMWARE_START_ADDR;
	while (size > 0) {
		const uint16_t mlen = (uint16_t)min(size, 4096);

		if (zyd_usb_ctrl_send(uc, ZYD_DOWNLOADREQ, addr, fw, mlen)
		    != USB_SUCCESS)
			return (ZYD_FAILURE);

		addr += mlen / 2;
		fw += mlen;
		size -= mlen;
	}

	/* check whether the upload succeeded */
	if (zyd_usb_ctrl_recv(uc, ZYD_DOWNLOADSTS, 0, &stat, sizeof (stat))
	    != ZYD_SUCCESS)
		return (ZYD_FAILURE);

	return ((stat & 0x80) ? ZYD_FAILURE : ZYD_SUCCESS);
}

/*
 * Return a specific alt_if from the device descriptor tree.
 */
static usb_alt_if_data_t *
usb_lookup_alt_if(usb_client_dev_data_t *cdd, uint_t config,
    uint_t interface, uint_t alt)
{
	usb_cfg_data_t *dcfg;
	usb_if_data_t *cfgif;
	usb_alt_if_data_t *ifalt;

	/*
	 * Assume everything is in the tree for now,
	 * (USB_PARSE_LVL_ALL)
	 * so we can directly index the array.
	 */

	/* Descend to configuration, configs are 1-based */
	if (config < 1 || config > cdd->dev_n_cfg)
		return (NULL);
	dcfg = &cdd->dev_cfg[config - 1];

	/* Descend to interface */
	if (interface > dcfg->cfg_n_if - 1)
		return (NULL);
	cfgif = &dcfg->cfg_if[interface];

	/* Descend to alt */
	if (alt > cfgif->if_n_alt - 1)
		return (NULL);
	ifalt = &cfgif->if_alt[alt];

	return (ifalt);
}

/*
 * Print all endpoints of an alt_if.
 */
static void
usb_list_all_endpoints(usb_alt_if_data_t *ifalt)
{
	usb_ep_data_t *ep_data;
	usb_ep_descr_t *ep_descr;
	int i;

	for (i = 0; i < ifalt->altif_n_ep; i++) {
		ep_data = &ifalt->altif_ep[i];
		ep_descr = &ep_data->ep_descr;
		cmn_err(CE_NOTE, "EP: %u\n", ep_descr->bEndpointAddress);
	}
}

/*
 * For the given alt_if, find an endpoint with the given
 * address and direction.
 *
 *      ep_direction    USB_EP_DIR_IN or USB_EP_DIR_OUT
 */
static usb_ep_data_t *
usb_find_endpoint(usb_alt_if_data_t *alt_if,
    uint_t ep_address, uint_t ep_direction)
{
	usb_ep_data_t *ep_data;
	usb_ep_descr_t *ep_descr;
	uint_t ep_addr, ep_dir;
	int i;

	for (i = 0; i < alt_if->altif_n_ep; i++) {
		ep_data = &alt_if->altif_ep[i];
		ep_descr = &ep_data->ep_descr;
		ep_addr = ep_descr->bEndpointAddress & USB_EP_NUM_MASK;
		ep_dir = ep_descr->bEndpointAddress & USB_EP_DIR_MASK;

		if (ep_addr == ep_address && ep_dir == ep_direction) {
			return (ep_data);
		}
	}

	ZYD_WARN("no endpoint with addr %u, dir %u\n", ep_address,
	    ep_direction);
	return (NULL);
}

enum zyd_usb_use_attr
{
	ZYD_USB_USE_ATTR = 1,
	ZYD_USB_NO_ATTR = 0
};

/*
 * Open a pipe to a given endpoint address/direction in the given
 * alt_if. Furthemore, if use_attr == ZYD_USB_USE_ATTR,
 * check whether the endpoint's transfer type is attr.
 */
static zyd_res
zyd_usb_open_pipe(struct zyd_usb *uc,
    usb_alt_if_data_t *alt_if,
    uint_t ep_address,
    uint_t ep_direction,
    uint_t attr,
    enum zyd_usb_use_attr use_attr,
    usb_pipe_handle_t *pipe, usb_ep_data_t *endpoint)
{
	usb_pipe_policy_t pipe_policy;

	*endpoint = *usb_find_endpoint(alt_if, ep_address, ep_direction);

	if ((use_attr == ZYD_USB_USE_ATTR) &&
	    (endpoint->ep_descr.bmAttributes & USB_EP_ATTR_MASK) != attr) {

		ZYD_WARN("endpoint %u/%s is not of type %s\n", ep_address,
		    (ep_direction == USB_EP_DIR_IN) ? "IN" : "OUT",
		    (attr == USB_EP_ATTR_BULK) ? "bulk" : "intr");
		return (ZYD_FAILURE);
	}

	bzero(&pipe_policy, sizeof (usb_pipe_policy_t));
	pipe_policy.pp_max_async_reqs = ZYD_USB_REQ_COUNT;

	if (usb_pipe_open(uc->dip, &endpoint->ep_descr,
	    &pipe_policy, USB_FLAGS_SLEEP, pipe) != USB_SUCCESS) {
		ZYD_WARN("failed to open pipe %u\n", ep_address);
		return (ZYD_FAILURE);
	}

	return (ZYD_SUCCESS);
}

/*
 * Open communication pipes.
 *
 * The following pipes are used by the ZD1211:
 *
 *      1/OUT BULK
 *      2/IN  BULK
 *      3/IN  INTR
 *      4/OUT BULK or INTR
 */
zyd_res
zyd_usb_open_pipes(struct zyd_usb *uc)
{
	usb_alt_if_data_t *alt_if;

	ZYD_DEBUG((ZYD_DBG_USB, "opening pipes\n"));

	alt_if = usb_lookup_alt_if(uc->cdata, ZYD_USB_CONFIG_NUMBER,
	    ZYD_USB_IFACE_INDEX, ZYD_USB_ALT_IF_INDEX);

	if (alt_if == NULL) {
		ZYD_WARN("alt_if not found\n");
		return (ZYD_FAILURE);
	}

#ifdef DEBUG
	if (zyd_dbg_flags & ZYD_DBG_USB)
		usb_list_all_endpoints(alt_if);
#endif

	if (zyd_usb_open_pipe(uc, alt_if, 1, USB_EP_DIR_OUT, USB_EP_ATTR_BULK,
	    ZYD_USB_USE_ATTR, &uc->pipe_data_out, &uc->ep_data_out) !=
	    ZYD_SUCCESS) {
		ZYD_WARN("failed to open data OUT pipe\n");
		goto fail;
	}

	if (zyd_usb_open_pipe(uc, alt_if, 2, USB_EP_DIR_IN, USB_EP_ATTR_BULK,
	    ZYD_USB_USE_ATTR, &uc->pipe_data_in, &uc->ep_data_in) !=
	    ZYD_SUCCESS) {
		ZYD_WARN("failed to open data IN pipe\n");
		goto fail;
	}

	if (zyd_usb_open_pipe(uc, alt_if, 3, USB_EP_DIR_IN, USB_EP_ATTR_INTR,
	    ZYD_USB_USE_ATTR, &uc->pipe_cmd_in, &uc->ep_cmd_in) !=
	    ZYD_SUCCESS) {
		ZYD_WARN("failed to open command IN pipe\n");
		goto fail;
	}

	/*
	 * Pipe 4/OUT is either a bulk or interrupt pipe.
	 */
	if (zyd_usb_open_pipe(uc, alt_if, 4, USB_EP_DIR_OUT, 0,
	    ZYD_USB_NO_ATTR, &uc->pipe_cmd_out, &uc->ep_cmd_out) !=
	    ZYD_SUCCESS) {
		ZYD_WARN("failed to open command OUT pipe\n");
		goto fail;
	}

	return (ZYD_SUCCESS);

fail:
	zyd_usb_close_pipes(uc);
	return (ZYD_FAILURE);
}

/*
 * Close communication pipes.
 */
void
zyd_usb_close_pipes(struct zyd_usb *uc)
{
	ZYD_DEBUG((ZYD_DBG_USB, "closing pipes\n"));

	if (uc->pipe_data_out != NULL) {
		usb_pipe_close(uc->dip, uc->pipe_data_out, USB_FLAGS_SLEEP,
		    NULL, NULL);
		uc->pipe_data_out = NULL;
	}

	if (uc->pipe_data_in != NULL) {
		usb_pipe_close(uc->dip, uc->pipe_data_in, USB_FLAGS_SLEEP,
		    NULL, NULL);
		uc->pipe_data_in = NULL;
	}

	if (uc->pipe_cmd_in != NULL) {
		usb_pipe_close(uc->dip, uc->pipe_cmd_in, USB_FLAGS_SLEEP,
		    NULL, NULL);
		uc->pipe_cmd_in = NULL;
	}

	if (uc->pipe_cmd_out != NULL) {
		usb_pipe_close(uc->dip, uc->pipe_cmd_out, USB_FLAGS_SLEEP,
		    NULL, NULL);
		uc->pipe_cmd_out = NULL;
	}
}

/*
 * Send a sequence of bytes to a bulk pipe.
 *
 *      uc      pointer to usb module state
 *      data    pointer to a buffer of bytes
 *      len     size of the buffer (bytes)
 */
/*ARGSUSED*/
static void
zyd_data_out_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct zyd_softc *sc = (struct zyd_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->ic;
	boolean_t resched;

	if (req->bulk_completion_reason != USB_CR_OK)
		ZYD_DEBUG((ZYD_DBG_USB, "data OUT exception\n"));

	(void) zyd_serial_enter(sc, ZYD_NO_SIG);
	if (sc->tx_queued > 0)
		sc->tx_queued--;
	else
		ZYD_DEBUG((ZYD_DBG_TX, "tx queue underrun\n"));

	if (sc->resched && (sc->tx_queued < ZYD_TX_LIST_COUNT)) {
		resched = sc->resched;
		sc->resched = B_FALSE;
	}
	zyd_serial_exit(sc);

	if (resched)
		mac_tx_update(ic->ic_mach);

	usb_free_bulk_req(req);
}

/*
 * Called when the transfer from zyd_usb_bulk_pipe_send() terminates
 * or an exception occurs on the pipe.
 */
/*ARGSUSED*/
static void
zyd_bulk_pipe_cb(usb_pipe_handle_t pipe, struct usb_bulk_req *req)
{
	struct zyd_cb_lock *lock;
	lock = (struct zyd_cb_lock *)req->bulk_client_private;

	/* Just signal that something happened */
	zyd_cb_lock_signal(lock);
}

static zyd_res
zyd_usb_bulk_pipe_send(struct zyd_usb *uc,
    usb_pipe_handle_t pipe, const void *data, size_t len)
{
	usb_bulk_req_t *send_req;
	mblk_t *mblk;
	int res;
	struct zyd_cb_lock lock;

	send_req = usb_alloc_bulk_req(uc->dip, len, USB_FLAGS_SLEEP);
	if (send_req == NULL) {
		ZYD_WARN("failed to allocate bulk request\n");
		return (ZYD_FAILURE);
	}
	send_req->bulk_len = (uint_t)len;
	send_req->bulk_client_private = (usb_opaque_t)&lock;
	send_req->bulk_attributes = USB_ATTRS_AUTOCLEARING;
	send_req->bulk_timeout = 5;
	send_req->bulk_cb = zyd_bulk_pipe_cb;
	send_req->bulk_exc_cb = zyd_bulk_pipe_cb;

	mblk = send_req->bulk_data;
	bcopy(data, mblk->b_wptr, len);
	mblk->b_wptr += len;

	zyd_cb_lock_init(&lock);

	res = usb_pipe_bulk_xfer(pipe, send_req, USB_FLAGS_NOSLEEP);
	if (res != USB_SUCCESS) {
		ZYD_DEBUG((ZYD_DBG_USB,
		    "failed writing to bulk OUT pipe (%d)\n", res));
		usb_free_bulk_req(send_req);
		zyd_cb_lock_destroy(&lock);
		return (ZYD_FAILURE);
	}

	if (zyd_cb_lock_wait(&lock, 1000000) != ZYD_SUCCESS) {
		ZYD_WARN("timeout - pipe reset\n");
		usb_pipe_reset(uc->dip, pipe, USB_FLAGS_SLEEP, NULL, 0);
		(void) zyd_cb_lock_wait(&lock, -1);
		res = ZYD_FAILURE;
	} else {
		res = (send_req->bulk_completion_reason == USB_CR_OK) ?
		    ZYD_SUCCESS : ZYD_FAILURE;
	}

	usb_free_bulk_req(send_req);
	zyd_cb_lock_destroy(&lock);
	return (res);
}

/*
 * Called when the transfer from zyd_usb_intr_pipe_send() terminates
 * or an exception occurs on the pipe.
 */
/*ARGSUSED*/
static void
zyd_intr_pipe_cb(usb_pipe_handle_t pipe, struct usb_intr_req *req)
{
	struct zyd_cb_lock *lock;
	lock = (struct zyd_cb_lock *)req->intr_client_private;

	/* Just signal that something happened */
	zyd_cb_lock_signal(lock);
}

/*
 * Send a sequence of bytes to an interrupt pipe.
 *
 *      uc      pointer to usb module state
 *      data    pointer to a buffer of bytes
 *      len     size of the buffer (bytes)
 */
static zyd_res
zyd_usb_intr_pipe_send(struct zyd_usb *uc,
    usb_pipe_handle_t pipe, const void *data, size_t len)
{
	usb_intr_req_t *send_req;
	mblk_t *mblk;
	int res;
	struct zyd_cb_lock lock;

	send_req = usb_alloc_intr_req(uc->dip, len, USB_FLAGS_SLEEP);
	if (send_req == NULL) {
		ZYD_WARN("failed to allocate interupt request\n");
		return (ZYD_FAILURE);
	}
	send_req->intr_len = (uint_t)len;
	send_req->intr_client_private = (usb_opaque_t)&lock;
	send_req->intr_attributes = USB_ATTRS_AUTOCLEARING;
	send_req->intr_timeout = 5;
	send_req->intr_cb = zyd_intr_pipe_cb;
	send_req->intr_exc_cb = zyd_intr_pipe_cb;

	mblk = send_req->intr_data;
	bcopy(data, mblk->b_wptr, len);
	mblk->b_wptr += len;

	zyd_cb_lock_init(&lock);

	res = usb_pipe_intr_xfer(pipe, send_req, 0);
	if (res != USB_SUCCESS) {
		ZYD_DEBUG((ZYD_DBG_USB,
		    "failed writing to intr/out pipe (%d)\n", res));
		usb_free_intr_req(send_req);
		zyd_cb_lock_destroy(&lock);
		return (ZYD_FAILURE);
	}

	if (zyd_cb_lock_wait(&lock, 1000000) != ZYD_SUCCESS) {
		ZYD_WARN("timeout - pipe reset\n");
		usb_pipe_reset(uc->dip, pipe, USB_FLAGS_SLEEP, NULL, 0);
		(void) zyd_cb_lock_wait(&lock, -1);
		res = ZYD_FAILURE;
	} else {
		res = (send_req->intr_completion_reason == USB_CR_OK) ?
		    ZYD_SUCCESS : ZYD_FAILURE;
	}

	usb_free_intr_req(send_req);
	zyd_cb_lock_destroy(&lock);
	return (res);
}

/*
 * Send a sequence of bytes to the cmd_out pipe. (in a single USB transfer)
 *
 *      uc      pointer to usb module state
 *      data    pointer to a buffer of bytes
 *      len     size of the buffer (bytes)
 */
static zyd_res
zyd_usb_cmd_pipe_send(struct zyd_usb *uc, const void *data, size_t len)
{
	zyd_res res;
	uint8_t type;

	/* Determine the type of cmd_out */
	type = uc->ep_cmd_out.ep_descr.bmAttributes & USB_EP_ATTR_MASK;
	if (type == USB_EP_ATTR_BULK)
		res = zyd_usb_bulk_pipe_send(uc, uc->pipe_cmd_out, data, len);
	else
		res = zyd_usb_intr_pipe_send(uc, uc->pipe_cmd_out, data, len);

	return (res);
}


/*
 * Format and send a command to the cmd_out pipe.
 *
 *      uc      pointer to usb module state
 *      code    ZD command code (16-bit)
 *      data    raw buffer containing command data
 *      len     size of the data buffer (bytes)
 */
zyd_res
zyd_usb_cmd_send(struct zyd_usb *uc,
    uint16_t code, const void *data, size_t len)
{
	zyd_res res;
	struct zyd_cmd cmd;

	cmd.cmd_code = LE_16(code);
	bcopy(data, cmd.data, len);

	res = zyd_usb_cmd_pipe_send(uc, &cmd, sizeof (uint16_t) + len);
	if (res != ZYD_SUCCESS) {
		ZYD_DEBUG((ZYD_DBG_USB, "failed writing command (%d)\n", res));
		return (ZYD_FAILURE);
	}

	return (ZYD_SUCCESS);
}

/*
 * Issue an ioread request.
 *
 * Issues a ZD ioread command (with a vector of addresses passed in raw
 * form as in_data) and blocks until the response is received
 * and filled into the response buffer.
 *
 *      uc              pointer to usb module state
 *      in_data         pointer to request data
 *      in_len          request data size (bytes)
 *      out_data        pointer to response buffer
 *      out_len         response buffer size (bytes)
 */
zyd_res
zyd_usb_ioread_req(struct zyd_usb *uc,
    const void *in_data, size_t in_len, void *out_data, size_t out_len)
{
	zyd_res res;
	int cnt;

	/* Initialise io_read structure */
	uc->io_read.done = B_FALSE;
	uc->io_read.buffer = out_data;
	uc->io_read.buf_len = (int)out_len;

	uc->io_read.pending = B_TRUE;

	res = zyd_usb_cmd_send(uc, ZYD_CMD_IORD, in_data, in_len);
	if (res != ZYD_SUCCESS) {
		ZYD_DEBUG((ZYD_DBG_USB, "IO read request: pipe failure(%d)\n"));
		return (ZYD_FAILURE);
	}

	cnt = 0;
	while (uc->io_read.done != B_TRUE && cnt < 500) {
		delay(drv_usectohz(10 * 1000));
		++cnt;
	}

	if (uc->io_read.done != B_TRUE) {
		ZYD_WARN("I/O read request: timeout\n");
		return (ZYD_FAILURE);
	}

	if (uc->io_read.exc != B_FALSE) {
		ZYD_DEBUG((ZYD_DBG_USB, "I/O read request: exception\n"));
		return (ZYD_FAILURE);
	}

	return (ZYD_SUCCESS);
}


/*
 * Called when data arrives from the cmd_in pipe.
 */
/*ARGSUSED*/
static void
zyd_cmd_in_cb(usb_pipe_handle_t pipe, usb_intr_req_t *req)
{
	struct zyd_usb *uc;
	struct zyd_ioread *rdp;
	mblk_t *mblk, *tmp_blk;
	unsigned char *data;
	size_t len;
	uint16_t code;

	uc = (struct zyd_usb *)req->intr_client_private;
	ASSERT(uc != NULL);
	rdp = &uc->io_read;
	mblk = req->intr_data;

	if (mblk->b_cont != NULL) {
		/* Fragmented message, concatenate */
		tmp_blk = msgpullup(mblk, -1);
		data = tmp_blk->b_rptr;
		len = MBLKL(tmp_blk);
	} else {
		/* Non-fragmented message, use directly */
		tmp_blk = NULL;
		data = mblk->b_rptr;
		len = MBLKL(mblk);
	}

	code = LE_16(*(uint16_t *)(uintptr_t)data);
	if (code != ZYD_RESPONSE_IOREAD) {
		/* Other response types not handled yet */
		usb_free_intr_req(req);
		return;
	}

	if (rdp->pending != B_TRUE) {
		ZYD_WARN("no ioread pending\n");
		usb_free_intr_req(req);
		return;
	}
	rdp->pending = B_FALSE;

	/* Now move on to the data part */
	data += sizeof (uint16_t);
	len -= sizeof (uint16_t);
	if (rdp->buf_len > len) {
		ZYD_WARN("too few bytes received\n");
	}

	bcopy(data, rdp->buffer, rdp->buf_len);

	if (tmp_blk != NULL)
		freemsg(tmp_blk);

	rdp->exc = B_FALSE;
	rdp->done = B_TRUE;
	usb_free_intr_req(req);
}

/*
 * Called when an exception occurs on the cmd_in pipe.
 */
/*ARGSUSED*/
static void
zyd_cmd_in_exc_cb(usb_pipe_handle_t pipe, usb_intr_req_t *req)
{
	struct zyd_usb *uc;
	struct zyd_ioread *rdp;

	ZYD_DEBUG((ZYD_DBG_USB, "command IN exception\n"));

	uc = (struct zyd_usb *)req->intr_client_private;
	ASSERT(uc != NULL);
	rdp = &uc->io_read;

	if (rdp->pending == B_TRUE) {
		rdp->exc = B_TRUE;
		rdp->done = B_TRUE;
	}
	usb_free_intr_req(req);
}

/*
 * Start interrupt polling on the cmd_in pipe.
 */
zyd_res
zyd_usb_cmd_in_start_polling(struct zyd_usb *uc)
{
	usb_intr_req_t *intr_req;
	int res;

	intr_req = usb_alloc_intr_req(uc->dip, 0, USB_FLAGS_SLEEP);
	if (intr_req == NULL) {
		ZYD_WARN("failed to allocate interrupt request\n");
		return (ZYD_FAILURE);
	}

	intr_req->intr_attributes = USB_ATTRS_SHORT_XFER_OK;
	intr_req->intr_len = uc->ep_cmd_in.ep_descr.wMaxPacketSize;
	intr_req->intr_cb = zyd_cmd_in_cb;
	intr_req->intr_exc_cb = zyd_cmd_in_exc_cb;
	intr_req->intr_client_private = (usb_opaque_t)uc;

	res = usb_pipe_intr_xfer(uc->pipe_cmd_in, intr_req, USB_FLAGS_NOSLEEP);
	if (res != USB_SUCCESS) {
		ZYD_WARN("failed starting command IN polling: pipe failure\n");
		usb_free_intr_req(intr_req);
		return (ZYD_FAILURE);
	}

	return (ZYD_SUCCESS);
}

/*
 * Stop interrupt polling on the cmd_in pipe.
 */
void
zyd_usb_cmd_in_stop_polling(struct zyd_usb *uc)
{
	ZYD_DEBUG((ZYD_DBG_USB, "stopping command IN polling\n"));

	usb_pipe_stop_intr_polling(uc->pipe_cmd_in, USB_FLAGS_SLEEP);
}

/*
 * Called when data arrives on the data_in pipe.
 */
/*ARGSUSED*/
static void
zyd_data_in_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct zyd_softc *sc;
	struct zyd_usb *uc;
	mblk_t *mblk, *tmp_blk;
	struct zyd_rx_desc *desc;
	unsigned char *data;
	size_t len;

	uc = (struct zyd_usb *)req->bulk_client_private;
	ASSERT(uc != NULL);
	sc = ZYD_USB_TO_SOFTC(uc);
	ASSERT(sc != NULL);
	mblk = req->bulk_data;

	/* Fragmented STREAMS message? */
	if (mblk->b_cont != NULL) {
		/* Fragmented, concatenate it into a single block */
		tmp_blk = msgpullup(mblk, -1);
		if (tmp_blk == NULL) {
			ZYD_WARN("failed to concatenate fragments\n");
			goto error;
		}
		data = tmp_blk->b_rptr;
		len = MBLKL(tmp_blk);
	} else {
		/* Not fragmented, use directly */
		tmp_blk = NULL;
		data = mblk->b_rptr;
		len = MBLKL(mblk);
	}

	if (len < 2) {
		ZYD_WARN("received usb transfer too short\n");
		goto error;
	}

	/*
	 * If this is a composite packet, the last two bytes contain
	 * two special signature bytes.
	 */
	desc = (struct zyd_rx_desc *)(data + len) - 1;
	/* multi-frame transfer */
	if (LE_16(desc->tag) == ZYD_TAG_MULTIFRAME) {
		const uint8_t *p = data, *end = data + len;
		int i;

		ZYD_DEBUG((ZYD_DBG_RX, "composite packet\n"));

		for (i = 0; i < ZYD_MAX_RXFRAMECNT; i++) {
			const uint16_t len16 = LE_16(desc->len[i]);
			if (len16 == 0 || p + len16 > end)
				break;
			zyd_receive(ZYD_USB_TO_SOFTC(uc), p, len16);
			/* next frame is aligned on a 32-bit boundary */
			p += (len16 + 3) & ~3;
		}
	} else {
		/* single-frame transfer */
		zyd_receive(ZYD_USB_TO_SOFTC(uc), data, MBLKL(mblk));
	}

error:
	if (tmp_blk != NULL)
		freemsg(tmp_blk);

	usb_free_bulk_req(req);

	if (!sc->running)
		return;

	if (zyd_usb_data_in_start_request(uc) != ZYD_SUCCESS) {
		ZYD_WARN("error restarting data_in transfer\n");
	}
}

/*
 * Called when an exception occurs on the data_in pipe.
 */
/*ARGSUSED*/
static void
zyd_data_in_exc_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct zyd_usb *uc;

	ZYD_DEBUG((ZYD_DBG_USB, "data IN exception\n"));

	uc = (struct zyd_usb *)req->bulk_client_private;
	ASSERT(uc != NULL);

	usb_free_bulk_req(req);
}

/*
 * Start a receive request on the data_in pipe.
 */
static zyd_res
zyd_usb_data_in_start_request(struct zyd_usb *uc)
{
	usb_bulk_req_t *req;
	int res;

	req = usb_alloc_bulk_req(uc->dip, ZYD_RX_BUF_SIZE, USB_FLAGS_SLEEP);
	if (req == NULL) {
		ZYD_WARN("failed to allocate bulk IN request\n");
		return (ZYD_FAILURE);
	}

	req->bulk_len = (uint_t)ZYD_RX_BUF_SIZE;
	req->bulk_timeout = 0;
	req->bulk_client_private = (usb_opaque_t)uc;
	req->bulk_attributes =
	    USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;
	req->bulk_cb = zyd_data_in_cb;
	req->bulk_exc_cb = zyd_data_in_exc_cb;

	res = usb_pipe_bulk_xfer(uc->pipe_data_in, req, USB_FLAGS_NOSLEEP);
	if (res != USB_SUCCESS) {
		ZYD_WARN("error starting receive request on data_in pipe\n");
		usb_free_bulk_req(req);
		return (ZYD_FAILURE);
	}

	return (ZYD_SUCCESS);
}


/*
 * Start receiving packets on the data_in pipe.
 */
zyd_res
zyd_usb_data_in_enable(struct zyd_usb *uc)
{
	for (int i = 0; i < ZYD_RX_LIST_COUNT; i++) {
		if (zyd_usb_data_in_start_request(uc) != ZYD_SUCCESS) {
			ZYD_WARN("failed to start data IN requests\n");
			return (ZYD_FAILURE);
		}
	}
	return (ZYD_SUCCESS);
}

/*
 * Stop receiving packets on the data_in pipe.
 */
void
zyd_usb_data_in_disable(struct zyd_usb *uc)
{
	usb_pipe_reset(uc->dip, uc->pipe_data_in, USB_FLAGS_SLEEP,
	    NULL, NULL);
}

/*
 * Send a packet to data_out.
 *
 * A packet consists of a zyd_tx_header + the IEEE802.11 frame.
 */
zyd_res
zyd_usb_send_packet(struct zyd_usb *uc, mblk_t *mp)
{
	usb_bulk_req_t *send_req;
	int res;

	send_req = usb_alloc_bulk_req(uc->dip, 0, USB_FLAGS_SLEEP);
	if (send_req == NULL) {
		ZYD_WARN("failed to allocate bulk request\n");
		return (ZYD_FAILURE);
	}

	send_req->bulk_len = msgdsize(mp);
	send_req->bulk_data = mp;
	send_req->bulk_timeout = 5;
	send_req->bulk_attributes = USB_ATTRS_AUTOCLEARING;
	send_req->bulk_client_private = (usb_opaque_t)ZYD_USB_TO_SOFTC(uc);
	send_req->bulk_cb = zyd_data_out_cb;
	send_req->bulk_exc_cb = zyd_data_out_cb;
	send_req->bulk_completion_reason = 0;
	send_req->bulk_cb_flags = 0;

	res = usb_pipe_bulk_xfer(uc->pipe_data_out, send_req, 0);
	if (res != USB_SUCCESS) {
		ZYD_DEBUG((ZYD_DBG_USB,
		    "failed writing to bulk/out pipe (%d)\n", res));
		usb_free_bulk_req(send_req);
		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}

/*
 * Initialize USB device communication and USB module state.
 *
 *      uc      pointer to usb module state
 *      dip     pointer to device info structure
 */
zyd_res
zyd_usb_init(struct zyd_softc *sc)
{
	struct zyd_usb *uc = &sc->usb;
	dev_info_t *dip = sc->dip;
	int ures;

	uc->dip = dip;

	ures = usb_client_attach(uc->dip, USBDRV_VERSION, 0);
	if (ures != USB_SUCCESS) {
		ZYD_WARN("usb_client_attach failed, error code: %d\n", ures);
		return (ZYD_FAILURE);
	}

	/*
	 * LVL_ALL is needed for later endpoint scanning,
	 * and the tree must not be freed before that.
	 */
	ures = usb_get_dev_data(uc->dip, &uc->cdata, USB_PARSE_LVL_ALL, 0);
	if (ures != USB_SUCCESS) {
		ZYD_WARN("usb_get_dev_data failed, error code: %d\n", ures);
		ASSERT(uc->cdata == NULL);
		goto fail;
	}

	ures = usb_reset_device(uc->dip, USB_RESET_LVL_DEFAULT);
	if (ures != USB_SUCCESS) {
		ZYD_WARN("usb_reset_device failed, error code: %d\n", ures);
		goto fail;
	}

	uc->connected = B_TRUE;

	ures = usb_register_hotplug_cbs(dip, zyd_usb_disconnect,
	    zyd_usb_reconnect);
	if (ures != USB_SUCCESS) {
		ZYD_WARN("usb_register_hotplug_cbs failed, error code: %d\n",
		    ures);
		goto fail;
	}

	return (ZYD_SUCCESS);
fail:
	usb_client_detach(uc->dip, uc->cdata);
	uc->cdata = NULL;
	return (ZYD_FAILURE);
}

/*
 * Deinitialize USB device communication.
 */
void
zyd_usb_deinit(struct zyd_softc *sc)
{
	struct zyd_usb *uc = &sc->usb;

	usb_unregister_hotplug_cbs(sc->dip);

	usb_client_detach(uc->dip, uc->cdata);
	uc->cdata = NULL;
	uc->connected = B_FALSE;
}

/*
 * Device connected
 */
static int
zyd_usb_reconnect(dev_info_t *dip)
{
	struct zyd_softc *sc;
	struct zyd_usb *uc;

	sc = ddi_get_soft_state(zyd_ssp, ddi_get_instance(dip));
	ASSERT(sc != NULL);
	uc = &sc->usb;
	ASSERT(!uc->connected);

	if (sc->suspended)
		ZYD_DEBUG((ZYD_DBG_RESUME | ZYD_DBG_USB,
		    "reconnect before resume\n"));

	/* check device changes after disconnect */
	if (usb_check_same_device(sc->dip, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC | USB_CHK_CFG, NULL) != USB_SUCCESS) {
		ZYD_DEBUG((ZYD_DBG_USB, "different device connected\n"));
		return (DDI_FAILURE);
	}

	(void) zyd_serial_enter(sc, ZYD_NO_SIG);
	if (zyd_hw_init(sc) != ZYD_SUCCESS) {
		ZYD_WARN("failed to reinit hardware\n");
		zyd_serial_exit(sc);
		return (DDI_FAILURE);
	}
	if (sc->running) {
		if (zyd_hw_start(sc) != ZYD_SUCCESS) {
			ZYD_WARN("failed to restart hardware\n");
			zyd_serial_exit(sc);
			goto fail;
		}
	}
	zyd_serial_exit(sc);

	uc->connected = B_TRUE;

	return (DDI_SUCCESS);
fail:
	usb_client_detach(uc->dip, uc->cdata);
	uc->cdata = NULL;
	return (DDI_FAILURE);
}

static int
zyd_usb_disconnect(dev_info_t *dip)
{
	struct zyd_softc *sc;
	struct zyd_usb *uc;

	sc = ddi_get_soft_state(zyd_ssp, ddi_get_instance(dip));
	ASSERT(sc != NULL);
	uc = &sc->usb;

	if (!uc->connected) {
		ZYD_DEBUG((ZYD_DBG_USB, "different device disconnected\n"));
		return (DDI_FAILURE);
	}
	uc->connected = B_FALSE;

	if (sc->suspended) {
		ZYD_DEBUG((ZYD_DBG_USB, "disconnect after suspend\n"));
		return (DDI_SUCCESS);
	}
	ieee80211_new_state(&sc->ic, IEEE80211_S_INIT, -1);

	(void) zyd_serial_enter(sc, ZYD_NO_SIG);
	zyd_hw_stop(sc);
	zyd_hw_deinit(sc);
	zyd_serial_exit(sc);

	return (DDI_SUCCESS);
}

int
zyd_suspend(struct zyd_softc *sc)
{
	struct zyd_usb *uc = &sc->usb;

	if (!uc->connected) {
		ZYD_DEBUG((ZYD_DBG_USB | ZYD_DBG_RESUME,
		    "suspend after disconnect\n"));
		sc->suspended = B_TRUE;
		return (DDI_SUCCESS);
	}
	ZYD_DEBUG((ZYD_DBG_RESUME, "suspend\n"));

	sc->suspended = B_TRUE;
	ieee80211_new_state(&sc->ic, IEEE80211_S_INIT, -1);

	(void) zyd_serial_enter(sc, ZYD_NO_SIG);
	zyd_hw_stop(sc);
	zyd_hw_deinit(sc);
	zyd_serial_exit(sc);

	ZYD_DEBUG((ZYD_DBG_RESUME, "suspend complete\n"));
	return (DDI_SUCCESS);
}

int
zyd_resume(struct zyd_softc *sc)
{
	struct zyd_usb *uc = &sc->usb;

	if (!uc->connected) {
		ZYD_DEBUG((ZYD_DBG_USB | ZYD_DBG_RESUME,
		    "resume after disconnect\n"));
		sc->suspended = B_FALSE;
		return (DDI_SUCCESS);
	}
	ZYD_DEBUG((ZYD_DBG_RESUME, "resume\n"));

	/* check device changes after disconnect */
	if (usb_check_same_device(sc->dip, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC | USB_CHK_CFG, NULL) != USB_SUCCESS) {
		ZYD_WARN("different device connected to same port\n");
		sc->suspended = B_FALSE;
		uc->connected = B_FALSE;
		return (DDI_SUCCESS);
	}

	(void) zyd_serial_enter(sc, ZYD_NO_SIG);
	if (zyd_hw_init(sc) != ZYD_SUCCESS) {
		ZYD_WARN("failed to reinit hardware\n");
		zyd_serial_exit(sc);
		return (DDI_FAILURE);
	}
	if (sc->running) {
		if (zyd_hw_start(sc) != ZYD_SUCCESS) {
			ZYD_WARN("failed to restart hardware\n");
			zyd_serial_exit(sc);
			return (DDI_FAILURE);
		}
	}
	zyd_serial_exit(sc);

	sc->suspended = B_FALSE;

	ZYD_DEBUG((ZYD_DBG_RESUME, "resume complete\n"));
	return (DDI_SUCCESS);
}
