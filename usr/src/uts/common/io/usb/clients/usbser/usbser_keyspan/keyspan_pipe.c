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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * keyspanport pipe routines (mostly device-neutral)
 *
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/termio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/usb/usba.h>
#include <sys/usb/clients/usbser/usbser_keyspan/keyspan_var.h>
#include <sys/usb/clients/usbser/usbser_keyspan/keyspan_pipe.h>

/*
 * initialize pipe structure with the given parameters
 */
static void
keyspan_init_one_pipe(keyspan_state_t *ksp, keyspan_port_t *kp,
    keyspan_pipe_t *pipe)
{
	usb_pipe_policy_t	*policy;

	USB_DPRINTF_L4(DPRINT_OPEN, ksp->ks_lh, "keyspan_init_one_pipe: "
	    "pipe = %p, pipe_stat %x", (void *)pipe, pipe->pipe_state);

	/* init sync primitives */
	mutex_init(&pipe->pipe_mutex, NULL, MUTEX_DRIVER, (void *)NULL);

	/* init pipe policy */
	policy = &pipe->pipe_policy;
	policy->pp_max_async_reqs = 2;

	pipe->pipe_ksp = ksp;
	if (kp == NULL) {
		/* globle pipes should have device log handle */
		pipe->pipe_lh = ksp->ks_lh;
	} else {
		/* port pipes should have port log handle */
		pipe->pipe_lh = kp->kp_lh;
	}

	pipe->pipe_state = KEYSPAN_PIPE_CLOSED;
}


static void
keyspan_fini_one_pipe(keyspan_pipe_t *pipe)
{
	USB_DPRINTF_L4(DPRINT_OPEN, pipe->pipe_ksp->ks_lh,
	    "keyspan_fini_one_pipe: pipe_stat %x", pipe->pipe_state);

	if (pipe->pipe_state != KEYSPAN_PIPE_NOT_INIT) {
		mutex_destroy(&pipe->pipe_mutex);
		pipe->pipe_state = KEYSPAN_PIPE_NOT_INIT;
	}
}

/*
 * Lookup the endpoints defined in the spec;
 * Allocate resources, initialize pipe structures.
 * All are bulk pipes, including data in/out, cmd/status pipes.
 */
int
keyspan_init_pipes(keyspan_state_t *ksp)
{
	usb_client_dev_data_t *dev_data = ksp->ks_dev_data;
	int		ifc, alt, i, j, k = 0;
	uint8_t		port_cnt = ksp->ks_dev_spec.port_cnt;
	uint8_t		ep_addr, ep_cnt;
	usb_ep_data_t	*dataout[KEYSPAN_MAX_PORT_NUM],
			*datain[KEYSPAN_MAX_PORT_NUM],
			*status = NULL, *ctrl = NULL, *tmp_ep;
	usb_alt_if_data_t *alt_data;
	usb_if_data_t *if_data;


	ifc = dev_data->dev_curr_if;
	alt = 0;
	if_data = &dev_data->dev_curr_cfg->cfg_if[ifc];
	alt_data = &if_data->if_alt[alt];

	/*
	 * The actual EP number (indicated by bNumEndpoints) is more than
	 * those defined in spec. We have to match those we need according
	 * to EP addresses. And we'll lookup In EPs and Out EPs separately.
	 */
	ep_cnt = (alt_data->altif_descr.bNumEndpoints + 1) / 2;

	/*
	 * get DIR_IN EP descriptors, and then match with EP addresses.
	 * Different keyspan devices may has different EP addresses.
	 */
	for (i = 0; i < ep_cnt; i++) {
		tmp_ep = usb_lookup_ep_data(ksp->ks_dip, dev_data, ifc, alt, i,
			    USB_EP_ATTR_BULK, USB_EP_DIR_IN);
		if (tmp_ep == NULL) {
			USB_DPRINTF_L3(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_init_pipes: can't find bulk in ep, i=%d,"
			    "ep_cnt=%d", i, ep_cnt);

			continue;
		}
		ep_addr = tmp_ep->ep_descr.bEndpointAddress;

		USB_DPRINTF_L3(DPRINT_ATTACH, ksp->ks_lh, "keyspan_init_pipes: "
		    "ep_addr =%x, stat_ep_addr=%x, i=%d", ep_addr,
		    ksp->ks_dev_spec.stat_ep_addr, i);

		/* match the status EP */
		if (ep_addr == ksp->ks_dev_spec.stat_ep_addr) {
			status = tmp_ep;

			continue;
		}

		/* match the EPs of the ports */
		for (j = 0; j < port_cnt; j++) {
			USB_DPRINTF_L3(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_init_pipes: try to match bulk in data ep,"
			    " j=%d", j);
			if (ep_addr == ksp->ks_dev_spec.datain_ep_addr[j]) {
				datain[j] = tmp_ep;
				k++;
				USB_DPRINTF_L3(DPRINT_ATTACH, ksp->ks_lh,
				    "keyspan_init_pipes: matched a bulk in"
				    " data ep");

				break;
			}
		}

		/* if have matched all the necessary endpoints, break out */
		if (k >= port_cnt && status != NULL) {

			break;
		}

		USB_DPRINTF_L4(DPRINT_ATTACH, ksp->ks_lh, "keyspan_init_pipes: "
		    "try to match bulk in data ep, j=%d", j);

		if (j == port_cnt) {
			/* this ep can't be matched by any addr */
			USB_DPRINTF_L4(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_init_pipes: can't match bulk in ep,"
			    " addr =%x,", ep_addr);
		}
	}

	if (k != port_cnt || status == NULL) {

		/* Some of the necessary IN endpoints are not matched */
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_init_pipes: matched %d data in endpoints,"
		    " not enough", k);

		return (USB_FAILURE);
	}

	k = 0;

	/*
	 * get DIR_OUT EP descriptors, and then match with ep addrs.
	 * different keyspan devices may has different ep addresses.
	 */
	for (i = 0; i < ep_cnt; i++) {
		tmp_ep = usb_lookup_ep_data(ksp->ks_dip, dev_data, ifc, alt, i,
			    USB_EP_ATTR_BULK, USB_EP_DIR_OUT);
		if (tmp_ep == NULL) {
			USB_DPRINTF_L3(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_init_pipes: can't find bulk out ep, i=%d,"
			    "ep_cnt=%d", i, ep_cnt);

			continue;
		}
		ep_addr = tmp_ep->ep_descr.bEndpointAddress;

		/* match the status ep */
		if (ep_addr == ksp->ks_dev_spec.ctrl_ep_addr) {
			ctrl = tmp_ep;

			continue;
		}

		/* match the ep of the ports */
		for (j = 0; j < port_cnt; j++) {
			if (ep_addr == ksp->ks_dev_spec.dataout_ep_addr[j]) {
				dataout[j] = tmp_ep;
				k++;

				break;
			}
		}
		/* if have matched all the necessary endpoints, break out */
		if (k >= port_cnt && ctrl != NULL) {

			break;
		}

		if (j == port_cnt) {

			/* this ep can't be matched by any addr */
			USB_DPRINTF_L4(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_init_pipes: can't match bulk out ep,"
			    " ep_addr =%x", ep_addr);

		}
	}

	if (k != port_cnt || ctrl == NULL) {
		/* Not all the necessary OUT endpoints are matched */
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_init_pipes: matched %d data in endpoints,"
		    " not enough", k);

		return (USB_FAILURE);
	}

	mutex_enter(&ksp->ks_mutex);

	/*
	 * Device globle pipes: a bulk in pipe for status and a bulk out
	 * pipe for controle cmd.
	 */
	ksp->ks_statin_pipe.pipe_ep_descr = status->ep_descr;
	keyspan_init_one_pipe(ksp, NULL, &ksp->ks_statin_pipe);

	ksp->ks_ctrlout_pipe.pipe_ep_descr = ctrl->ep_descr;
	keyspan_init_one_pipe(ksp, NULL, &ksp->ks_ctrlout_pipe);

	/* for data in/out pipes of each port */
	for (i = 0; i < port_cnt; i++) {

		ksp->ks_ports[i].kp_datain_pipe.pipe_ep_descr =
		    datain[i]->ep_descr;
		keyspan_init_one_pipe(ksp, &ksp->ks_ports[i],
		    &ksp->ks_ports[i].kp_datain_pipe);

		ksp->ks_ports[i].kp_dataout_pipe.pipe_ep_descr =
		    dataout[i]->ep_descr;
		keyspan_init_one_pipe(ksp, &ksp->ks_ports[i],
		    &ksp->ks_ports[i].kp_dataout_pipe);
	}

	mutex_exit(&ksp->ks_mutex);

	return (USB_SUCCESS);
}

void
keyspan_fini_pipes(keyspan_state_t *ksp)
{
	keyspan_port_t	*kp;
	int		i;

	for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
		kp = &ksp->ks_ports[i];
		keyspan_fini_one_pipe(&kp->kp_datain_pipe);
		keyspan_fini_one_pipe(&kp->kp_dataout_pipe);
	}

	/* fini global pipes */
	keyspan_fini_one_pipe(&ksp->ks_statin_pipe);
	keyspan_fini_one_pipe(&ksp->ks_ctrlout_pipe);
}


static int
keyspan_open_one_pipe(keyspan_state_t *ksp, keyspan_pipe_t *pipe)
{
	int	rval;

	/* don't open for the second time */
	mutex_enter(&pipe->pipe_mutex);
	ASSERT(pipe->pipe_state != KEYSPAN_PIPE_NOT_INIT);
	if (pipe->pipe_state != KEYSPAN_PIPE_CLOSED) {
		mutex_exit(&pipe->pipe_mutex);

		return (USB_SUCCESS);
	}
	mutex_exit(&pipe->pipe_mutex);

	rval = usb_pipe_open(ksp->ks_dip, &pipe->pipe_ep_descr,
	    &pipe->pipe_policy, USB_FLAGS_SLEEP, &pipe->pipe_handle);

	if (rval == USB_SUCCESS) {
		mutex_enter(&pipe->pipe_mutex);
		pipe->pipe_state = KEYSPAN_PIPE_OPEN;
		mutex_exit(&pipe->pipe_mutex);
	}

	return (rval);
}


/*
 * close one pipe if open
 */
static void
keyspan_close_one_pipe(keyspan_pipe_t *pipe)
{
	/*
	 * pipe may already be closed, e.g. if device has been physically
	 * disconnected and the driver immediately detached
	 */
	if (pipe->pipe_handle != NULL) {
		usb_pipe_close(pipe->pipe_ksp->ks_dip, pipe->pipe_handle,
				USB_FLAGS_SLEEP, NULL, NULL);
		mutex_enter(&pipe->pipe_mutex);
		pipe->pipe_handle = NULL;
		pipe->pipe_state = KEYSPAN_PIPE_CLOSED;
		mutex_exit(&pipe->pipe_mutex);
	}
}

/*
 * Open global pipes, a status pipe and a control pipe
 */
int
keyspan_open_dev_pipes(keyspan_state_t *ksp)
{
	int		rval;

	USB_DPRINTF_L4(DPRINT_OPEN, ksp->ks_lh, "keyspan_open_dev_pipes");

	rval = keyspan_open_one_pipe(ksp, &ksp->ks_ctrlout_pipe);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_OPEN, ksp->ks_lh,
		    "keyspan_open_dev_pipes: open ctrl pipe failed %d", rval);

		return (rval);
	}

	rval = keyspan_open_one_pipe(ksp, &ksp->ks_statin_pipe);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_OPEN, ksp->ks_lh,
		    "keyspan_open_dev_pipes: open status pipe failed %d", rval);

		/* close the first opened pipe here */
		keyspan_close_one_pipe(&ksp->ks_ctrlout_pipe);

		return (rval);
	}

	/* start receive device status */
	rval = keyspan_receive_status(ksp);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_OPEN, ksp->ks_lh,
		    "keyspan_open_dev_pipes: receive device status failed %d",
		    rval);

		/* close opened pipes here */
		keyspan_close_one_pipe(&ksp->ks_statin_pipe);
		keyspan_close_one_pipe(&ksp->ks_ctrlout_pipe);

		return (rval);
	}

	return (rval);
}


/*
 * Reopen all pipes if the port had them open
 */
int
keyspan_reopen_pipes(keyspan_state_t *ksp)
{
	keyspan_port_t	*kp;
	int		i;

	USB_DPRINTF_L4(DPRINT_OPEN, ksp->ks_lh, "keyspan_reopen_pipes");

	if (keyspan_open_dev_pipes(ksp) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
		kp = &ksp->ks_ports[i];
		mutex_enter(&kp->kp_mutex);
		if (kp->kp_state == KEYSPAN_PORT_OPEN) {
			USB_DPRINTF_L4(DPRINT_OPEN, ksp->ks_lh,
			    "keyspan_reopen_pipes() reopen pipe #%d", i);
			mutex_exit(&kp->kp_mutex);
			if (keyspan_open_port_pipes(kp) != USB_SUCCESS) {

				return (USB_FAILURE);
			}
			mutex_enter(&kp->kp_mutex);
			kp->kp_no_more_reads = B_FALSE;
		}
		mutex_exit(&kp->kp_mutex);
	}

	return (USB_SUCCESS);
}

void
keyspan_close_port_pipes(keyspan_port_t *kp)
{
	USB_DPRINTF_L4(DPRINT_CLOSE, kp->kp_lh, "keyspan_close_port_pipes");

	keyspan_close_one_pipe(&kp->kp_dataout_pipe);
	keyspan_close_one_pipe(&kp->kp_datain_pipe);
}

/*
 * Close IN and OUT bulk pipes of all ports
 */
void
keyspan_close_open_pipes(keyspan_state_t *ksp)
{
	keyspan_port_t	*kp;
	int		i;

	USB_DPRINTF_L4(DPRINT_CLOSE, ksp->ks_lh, "keyspan_close_open_pipes");

	for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
		kp = &ksp->ks_ports[i];
		mutex_enter(&kp->kp_mutex);
		if (kp->kp_state == KEYSPAN_PORT_OPEN) {
			kp->kp_no_more_reads = B_TRUE;
			mutex_exit(&kp->kp_mutex);
			usb_pipe_reset(ksp->ks_dip,
			    kp->kp_datain_pipe.pipe_handle, USB_FLAGS_SLEEP,
			    NULL, NULL);
			keyspan_close_port_pipes(kp);
		} else {
			mutex_exit(&kp->kp_mutex);
		}
	}
}


/*
 * Close global pipes
 */
void
keyspan_close_dev_pipes(keyspan_state_t *ksp)
{
	USB_DPRINTF_L4(DPRINT_CLOSE, ksp->ks_lh, "keyspan_close_dev_pipes");

	keyspan_close_one_pipe(&ksp->ks_statin_pipe);
	keyspan_close_one_pipe(&ksp->ks_ctrlout_pipe);
}


/*
 * Open bulk data IN and data OUT pipes for one port.
 * The status and control pipes are opened in attach because they are global.
 */
int
keyspan_open_port_pipes(keyspan_port_t *kp)
{
	keyspan_state_t	*ksp = kp->kp_ksp;
	int		rval;

	USB_DPRINTF_L4(DPRINT_OPEN, kp->kp_lh, "keyspan_open_port_pipes");

	rval = keyspan_open_one_pipe(ksp, &kp->kp_datain_pipe);
	if (rval != USB_SUCCESS) {

		goto fail;
	}

	rval = keyspan_open_one_pipe(ksp, &kp->kp_dataout_pipe);
	if (rval != USB_SUCCESS) {

		goto fail;
	}

	return (rval);

fail:
	USB_DPRINTF_L2(DPRINT_OPEN, kp->kp_lh,
	    "keyspan_open_port_pipes: failed %d", rval);
	keyspan_close_port_pipes(kp);

	return (rval);
}

void
keyspan_close_pipes(keyspan_state_t *ksp)
{
	USB_DPRINTF_L4(DPRINT_OPEN, ksp->ks_lh, "keyspan_close_pipes");

	/* close all ports' pipes first, and then device ctrl/status pipes. */
	keyspan_close_open_pipes(ksp);
	keyspan_close_dev_pipes(ksp);

}


/*
 * bulk out common callback
 */
/*ARGSUSED*/
void
keyspan_bulkout_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	keyspan_port_t	*kp = (keyspan_port_t *)req->bulk_client_private;
	keyspan_pipe_t	*bulkout = &kp->kp_dataout_pipe;
	mblk_t		*data = req->bulk_data;
	int		data_len;

	data_len = (data) ? MBLKL(data) : 0;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, bulkout->pipe_lh,
	    "keyspan_bulkout_cb: len=%d cr=%d cb_flags=%x",
	    data_len, req->bulk_completion_reason, req->bulk_cb_flags);

	if (req->bulk_completion_reason && data) {

		/*
		 * Data wasn't transfered successfully.
		 * Put data back on the queue.
		 */
		keyspan_put_head(&kp->kp_tx_mp, data, kp);

		/* don't release mem in usb_free_bulk_req */
		req->bulk_data = NULL;
	}

	usb_free_bulk_req(req);

	/* if more data available, kick off another transmit */
	mutex_enter(&kp->kp_mutex);
	if (kp->kp_tx_mp == NULL) {
		/*
		 * Attach a zero packet if data length is muliple of 64,
		 * due to the specification of keyspan_usa19hs.
		 */
		if ((kp->kp_ksp->ks_dev_spec.id_product ==
			KEYSPAN_USA19HS_PID) && (data_len == 64)) {
			kp->kp_tx_mp = allocb(0, BPRI_LO);
			if (kp->kp_tx_mp) {
				keyspan_tx_start(kp, NULL);
				mutex_exit(&kp->kp_mutex);

				return;
			}
		}

		/* no more data, notify waiters */
		cv_broadcast(&kp->kp_tx_cv);
		mutex_exit(&kp->kp_mutex);

		/* tx callback for this port */
		kp->kp_cb.cb_tx(kp->kp_cb.cb_arg);
	} else {
		keyspan_tx_start(kp, NULL);
		mutex_exit(&kp->kp_mutex);
	}
}


/* For incoming data only. Parse a status byte and return the err code */
void
keyspan_parse_status(uchar_t *status, uchar_t *err)
{
	if (*status & RXERROR_BREAK) {
		/*
		 * Parity and Framing errors only count if they
		 * occur exclusive of a break being received.
		 */
		*status &= (uint8_t)(RXERROR_OVERRUN | RXERROR_BREAK);
	}
	*err |= (*status & RXERROR_OVERRUN) ? DS_OVERRUN_ERR : 0;
	*err |= (*status & RXERROR_PARITY) ? DS_PARITY_ERR : 0;
	*err |= (*status & RXERROR_FRAMING) ? DS_FRAMING_ERR : 0;
	*err |= (*status & RXERROR_BREAK) ? DS_BREAK_ERR : 0;
}


/*
 * pipe callbacks
 * --------------
 *
 * bulk in common callback for usa19hs model
 */
/*ARGSUSED*/
int
keyspan_bulkin_cb_usa19hs(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	keyspan_port_t	*kp = (keyspan_port_t *)req->bulk_client_private;
	keyspan_pipe_t	*bulkin = &kp->kp_datain_pipe;
	mblk_t		*data = req->bulk_data;
	uint_t		cr = req->bulk_completion_reason;
	int		data_len;

	ASSERT(mutex_owned(&kp->kp_mutex));

	data_len = (data) ? MBLKL(data) : 0;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
	    "keyspan_bulkin_cb_usa19hs: len=%d"
	    " cr=%d flags=%x baud=%x",
	    data_len, cr, req->bulk_cb_flags, kp->kp_baud);

	/* put data on the read queue */
	if ((data_len > 0) && (kp->kp_state != KEYSPAN_PORT_CLOSED) &&
	    (cr == USB_CR_OK)) {
		uchar_t	status = data->b_rptr[0];
		uchar_t	err = 0;
		mblk_t	*mp;
		/*
		 * According to Keyspan spec, if 0x80 bit is clear, there is
		 * only one status byte at the head of the data buf; if 0x80 bit
		 * set, then data buf contains alternate status and data bytes;
		 * In the first case, only OVERRUN err can exist; In the second
		 * case, there are four kinds of err bits may appear in status.
		 */

		/* if 0x80 bit AND overrun bit are clear, just send up data */
		if (!(status & 0x80) && !(status & RXERROR_OVERRUN)) {
			USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
			    "keyspan_bulkin_cb_usa19hs: len=%d",
			    data_len);

			/* Get rid of the first status byte and send up data */
			data->b_rptr++;
			data_len--;
			if (data_len > 0) {
				keyspan_put_tail(&kp->kp_rx_mp, data);

				/*
				 * the data will not be freed and
				 * will be sent up later.
				 */
				req->bulk_data = NULL;
			}
		} else if (!(status & 0x80)) {
			/* If 0x80 bit is clear and overrun bit is set */
			USB_DPRINTF_L2(DPRINT_IN_PIPE, bulkin->pipe_lh,
			    "keyspan_bulkin_cb_usa19hs: usb xfer is OK,"
			    " but there is overrun err in serial xfer");

			keyspan_parse_status(&status, &err);
			mutex_exit(&kp->kp_mutex);
			if ((mp = allocb(2, BPRI_HI)) == NULL) {
				USB_DPRINTF_L2(DPRINT_IN_PIPE, kp->kp_lh,
				    "keyspan_bulkin_cb_usa19hs: allocb failed");
				mutex_enter(&kp->kp_mutex);

				return (0);
			}
			DB_TYPE(mp) = M_BREAK;
			*mp->b_wptr++ = err;
			*mp->b_wptr++ = status;
			mutex_enter(&kp->kp_mutex);

			/* Add to the received list; Send up the err code. */
			keyspan_put_tail(&kp->kp_rx_mp, mp);

			/*
			 * Don't send up the first byte because
			 * it is a status byte.
			 */
			data->b_rptr++;
			data_len--;
			if (data_len > 0) {
				keyspan_put_tail(&kp->kp_rx_mp, data);

				/*
				 * the data will not be freed and
				 * will be sent up later.
				 */
				req->bulk_data = NULL;
			}
		} else { /* 0x80 bit set, there are some errs in the data */
			USB_DPRINTF_L2(DPRINT_IN_PIPE, bulkin->pipe_lh,
			    "keyspan_bulkin_cb_usa19hs: usb xfer is OK,"
			    " but there are errs in serial xfer");
			/*
			 * Usually, there are at least two bytes,
			 * one status and one data.
			 */
			if (data_len > 1) {
				int i = 0;
				int j = 1;
				/*
				 * In this case, there might be multi status
				 * bytes. Parse each status byte and move the
				 * data bytes together.
				 */
				for (j = 1; j < data_len; j += 2) {
					status = data->b_rptr[j-1];
					keyspan_parse_status(&status, &err);

					/* move the data togeter */
					data->b_rptr[i] = data->b_rptr[j];
					i++;
				}
				data->b_wptr = data->b_rptr + i;
			} else { /* There are only one byte in incoming buf */
				keyspan_parse_status(&status, &err);
			}
			mutex_exit(&kp->kp_mutex);
			if ((mp = allocb(2, BPRI_HI)) == NULL) {
				USB_DPRINTF_L2(DPRINT_IN_PIPE, kp->kp_lh,
				    "keyspan_bulkin_cb_usa19hs: allocb failed");
				mutex_enter(&kp->kp_mutex);

				return (0);
			}
			DB_TYPE(mp) = M_BREAK;
			*mp->b_wptr++ = err;
			if (data_len > 2) {
				/*
				 * There are multiple status bytes in this case.
				 * Use err as status character since err is got
				 * by or in all status bytes.
				 */
				*mp->b_wptr++ = err;
			} else {
				*mp->b_wptr++ = status;
			}
			mutex_enter(&kp->kp_mutex);

			/* Add to the received list; Send up the err code. */
			keyspan_put_tail(&kp->kp_rx_mp, mp);

			if (data_len > 1) {
				data_len = data->b_wptr - data->b_rptr;
				keyspan_put_tail(&kp->kp_rx_mp, data);
				/*
				 * The data will not be freed and
				 * will be sent up later.
				 */
				req->bulk_data = NULL;
			}
		}
	} else { /* usb error happened, so don't send up data */
		data_len = 0;
		USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
		    "keyspan_bulkin_cb_usa19hs: error happened, len=%d, "
		    "cr=0x%x, cb_flags=0x%x", data_len, cr, req->bulk_cb_flags);
	}
	if (kp->kp_state != KEYSPAN_PORT_OPEN) {
		kp->kp_no_more_reads = B_TRUE;
	}

	return (data_len);
}


/*
 * pipe callbacks
 * --------------
 *
 * bulk in common callback for usa49 model
 */
/*ARGSUSED*/
int
keyspan_bulkin_cb_usa49(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	keyspan_port_t	*kp = (keyspan_port_t *)req->bulk_client_private;
	keyspan_pipe_t	*bulkin = &kp->kp_datain_pipe;
	mblk_t		*data = req->bulk_data;
	uint_t		cr = req->bulk_completion_reason;
	int		data_len;

	ASSERT(mutex_owned(&kp->kp_mutex));

	data_len = (data) ? MBLKL(data) : 0;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
	    "keyspan_bulkin_cb_usa49: len=%d"
	    " cr=%d flags=%x", data_len, cr, req->bulk_cb_flags);

	/* put data on the read queue */
	if ((data_len > 0) && (kp->kp_state != KEYSPAN_PORT_CLOSED) &&
	    (cr == USB_CR_OK)) {
		uchar_t	status = data->b_rptr[0];
		uchar_t	err = 0;
		mblk_t	*mp;
		/*
		 * According to Keyspan spec, if 0x80 bit is clear, there is
		 * only one status byte at the head of the data buf; if 0x80 bit
		 * set, then data buf contains alternate status and data bytes;
		 * In the first case, only OVERRUN err can exist; In the second
		 * case, there are four kinds of err bits may appear in status.
		 */

		/* if 0x80 bit AND overrun bit are clear, just send up data */
		if (!(status & 0x80) && !(status & RXERROR_OVERRUN)) {
			USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
			    "keyspan_bulkin_cb_usa49: len=%d",
			    data_len);

			/* Get rid of the first status byte and send up data */
			data->b_rptr++;
			data_len--;
			if (data_len > 0) {
				keyspan_put_tail(&kp->kp_rx_mp, data);

				/*
				 * the data will not be freed and
				 * will be sent up later.
				 */
				req->bulk_data = NULL;
			}
		} else if (!(status & 0x80)) {
			/* If 0x80 bit is clear and overrun bit is set */
			USB_DPRINTF_L2(DPRINT_IN_PIPE, bulkin->pipe_lh,
			    "keyspan_bulkin_cb_usa49: usb xfer is OK,"
			    " but there is overrun err in serial xfer");

			keyspan_parse_status(&status, &err);
			mutex_exit(&kp->kp_mutex);
			if ((mp = allocb(2, BPRI_HI)) == NULL) {
				USB_DPRINTF_L2(DPRINT_IN_PIPE, kp->kp_lh,
				    "keyspan_bulkin_cb_usa49: allocb failed");
				mutex_enter(&kp->kp_mutex);

				return (0);
			}
			DB_TYPE(mp) = M_BREAK;
			*mp->b_wptr++ = err;
			*mp->b_wptr++ = status;
			mutex_enter(&kp->kp_mutex);

			/* Add to the received list; Send up the err code. */
			keyspan_put_tail(&kp->kp_rx_mp, mp);

			/*
			 * Don't send up the first byte because
			 * it is a status byte.
			 */
			data->b_rptr++;
			data_len--;
			if (data_len > 0) {
				keyspan_put_tail(&kp->kp_rx_mp, data);

				/*
				 * the data will not be freed and
				 * will be sent up later.
				 */
				req->bulk_data = NULL;
			}
		} else { /* 0x80 bit set, there are some errs in the data */
			USB_DPRINTF_L2(DPRINT_IN_PIPE, bulkin->pipe_lh,
			    "keyspan_bulkin_cb_usa49: usb xfer is OK,"
			    " but there are errs in serial xfer");
			/*
			 * Usually, there are at least two bytes,
			 * one status and one data.
			 */
			if (data_len > 1) {
				int i = 0;
				int j = 1;
				/*
				 * In this case, there might be multi status
				 * bytes. Parse each status byte and move the
				 * data bytes together.
				 */
				for (j = 1; j < data_len; j += 2) {
					status = data->b_rptr[j-1];
					keyspan_parse_status(&status, &err);

					/* move the data togeter */
					data->b_rptr[i] = data->b_rptr[j];
					i++;
				}
				data->b_wptr = data->b_rptr + i;
			} else { /* There are only one byte in incoming buf */
				keyspan_parse_status(&status, &err);
			}
			mutex_exit(&kp->kp_mutex);
			if ((mp = allocb(2, BPRI_HI)) == NULL) {
				USB_DPRINTF_L2(DPRINT_IN_PIPE, kp->kp_lh,
				    "keyspan_bulkin_cb_usa49: allocb failed");
				mutex_enter(&kp->kp_mutex);

				return (0);
			}
			DB_TYPE(mp) = M_BREAK;
			*mp->b_wptr++ = err;
			if (data_len > 2) {
				/*
				 * There are multiple status bytes in this case.
				 * Use err as status character since err is got
				 * by or in all status bytes.
				 */
				*mp->b_wptr++ = err;
			} else {
				*mp->b_wptr++ = status;
			}
			mutex_enter(&kp->kp_mutex);

			/* Add to the received list; Send up the err code. */
			keyspan_put_tail(&kp->kp_rx_mp, mp);

			if (data_len > 1) {
				data_len = data->b_wptr - data->b_rptr;
				keyspan_put_tail(&kp->kp_rx_mp, data);
				/*
				 * The data will not be freed and
				 * will be sent up later.
				 */
				req->bulk_data = NULL;
			}
		}
	} else {
		/* usb error happened, so don't send up data */
		data_len = 0;
		USB_DPRINTF_L2(DPRINT_IN_PIPE, bulkin->pipe_lh,
		    "keyspan_bulkin_cb_usa49: port_state=%d"
		    " b_rptr[0]=%c", kp->kp_state, data->b_rptr[0]);
	}
	if (kp->kp_state != KEYSPAN_PORT_OPEN) {
		kp->kp_no_more_reads = B_TRUE;
	}

	return (data_len);
}


/*
 * pipe callbacks
 * --------------
 *
 * bulk in common callback
 */
/*ARGSUSED*/
void
keyspan_bulkin_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	keyspan_port_t	*kp = (keyspan_port_t *)req->bulk_client_private;
	keyspan_state_t	*ksp = kp->kp_ksp;
	int		data_len;
	boolean_t	no_more_reads = B_FALSE;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, (&kp->kp_datain_pipe)->pipe_lh,
	    "keyspan_bulkin_cb");

	mutex_enter(&kp->kp_mutex);

	/* put data on the read queue */
	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		data_len = keyspan_bulkin_cb_usa19hs(pipe, req);

		break;


	case KEYSPAN_USA49WLC_PID:
		data_len = keyspan_bulkin_cb_usa49(pipe, req);

		break;

	default:
		USB_DPRINTF_L2(DPRINT_IN_PIPE, (&kp->kp_datain_pipe)->pipe_lh,
		    "keyspan_bulkin_cb:"
		    "the device's product id can't be recognized");
		mutex_exit(&kp->kp_mutex);

		return;
	}

	no_more_reads = kp->kp_no_more_reads;

	mutex_exit(&kp->kp_mutex);

	usb_free_bulk_req(req);

	/* kick off another read unless indicated otherwise */
	if (!no_more_reads) {
		(void) keyspan_receive_data(&kp->kp_datain_pipe,
		    kp->kp_read_len, kp);
	}

	/* setup rx callback for this port */
	if (data_len > 0)  {
		kp->kp_cb.cb_rx(kp->kp_cb.cb_arg);
	}
}

/*
 * pipe callbacks
 * --------------
 *
 * bulk in status callback for usa19hs model
 */
/*ARGSUSED*/
void
keyspan_status_cb_usa19hs(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)req->bulk_client_private;
	keyspan_pipe_t	*bulkin = &ksp->ks_statin_pipe;
	mblk_t		*data = req->bulk_data;
	usb_cr_t	cr = req->bulk_completion_reason;
	int		data_len;

	data_len = (data) ? MBLKL(data) : 0;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
	    "keyspan_status_cb_usa19hs: len=%d"
	    " cr=%d flags=%x", data_len, cr, req->bulk_cb_flags);

	/* put data on the read queue */
	if ((data_len == 14) && (cr == USB_CR_OK)) {
		keyspan_port_t	*kp = &ksp->ks_ports[0];
		keyspan_usa19hs_port_status_msg_t *status_msg =
		    &(kp->kp_status_msg.usa19hs);

		mutex_enter(&kp->kp_mutex);
		bcopy(data->b_rptr, status_msg, data_len);

		if (status_msg->controlResponse) {
			kp->kp_status_flag |= KEYSPAN_PORT_CTRLRESP;
		} else {
			kp->kp_status_flag &= ~KEYSPAN_PORT_CTRLRESP;
		}

		if (status_msg->portState & PORTSTATE_ENABLED) {
			kp->kp_status_flag |= KEYSPAN_PORT_ENABLE;
		} else {
			kp->kp_status_flag &= ~KEYSPAN_PORT_ENABLE;
		}

		if (status_msg->portState & PORTSTATE_TXBREAK) {
			kp->kp_status_flag |= KEYSPAN_PORT_TXBREAK;
		} else {
			kp->kp_status_flag &= ~KEYSPAN_PORT_TXBREAK;
		}

		if (status_msg->rxBreak) {
			kp->kp_status_flag |= KEYSPAN_PORT_RXBREAK;
		} else {
			kp->kp_status_flag &= ~KEYSPAN_PORT_RXBREAK;
		}

		if (status_msg->portState & PORTSTATE_LOOPBACK) {
			kp->kp_status_flag |= KEYSPAN_PORT_LOOPBACK;
		} else {
			kp->kp_status_flag &= ~KEYSPAN_PORT_LOOPBACK;
		}

		/* if msr status changed, then invoke status callback */
		if (status_msg->msr & USA_MSR_dCTS ||
		    status_msg->msr & USA_MSR_dDSR ||
		    status_msg->msr & USA_MSR_dRI ||
		    status_msg->msr & USA_MSR_dDCD) {

			mutex_exit(&kp->kp_mutex);
			kp->kp_cb.cb_status(kp->kp_cb.cb_arg);
		} else {
			mutex_exit(&kp->kp_mutex);
		}
	} else {

		USB_DPRINTF_L2(DPRINT_IN_PIPE, bulkin->pipe_lh,
		    "keyspan_status_cb_usa19hs: get status failed, cr=%d"
		    " data_len=%d", cr, data_len);
	}
}


/*
 * pipe callbacks
 * --------------
 *
 * bulk in status callback for usa49 model
 */
/*ARGSUSED*/
void
keyspan_status_cb_usa49(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)req->bulk_client_private;
	keyspan_pipe_t	*bulkin = &ksp->ks_statin_pipe;
	mblk_t		*data = req->bulk_data;
	uint_t		cr = req->bulk_completion_reason;
	int		data_len;

	data_len = (data) ? MBLKL(data) : 0;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
	    "keyspan_status_cb_usa49: len=%d"
	    " cr=%d flags=%x", data_len, cr, req->bulk_cb_flags);

	/* put data on the read queue */
	if ((data_len == 11) && (cr == USB_CR_OK)) {
		keyspan_usa49_port_status_msg_t status_msg;
		keyspan_port_t *cur_kp;
		keyspan_usa49_port_status_msg_t *kp_status_msg;
		boolean_t need_cb = B_FALSE;

		bcopy(data->b_rptr, &status_msg, data_len);
		if (status_msg.portNumber >= ksp->ks_dev_spec.port_cnt) {

			return;
		}
		cur_kp = &ksp->ks_ports[status_msg.portNumber];
		kp_status_msg = &(cur_kp->kp_status_msg.usa49);

		mutex_enter(&cur_kp->kp_mutex);

		/* if msr status changed, then need invoke status callback */
		if (status_msg.cts !=  kp_status_msg->cts ||
		    status_msg.dsr != kp_status_msg->dsr ||
		    status_msg.ri != kp_status_msg->ri ||
		    status_msg.dcd != kp_status_msg->dcd) {

			need_cb = B_TRUE;
		}

		bcopy(&status_msg, kp_status_msg, data_len);

		if (kp_status_msg->controlResponse) {
			cur_kp->kp_status_flag |= KEYSPAN_PORT_CTRLRESP;
		} else {
			cur_kp->kp_status_flag &= ~KEYSPAN_PORT_CTRLRESP;
		}

		if (!kp_status_msg->rxEnabled) {
			cur_kp->kp_status_flag |= KEYSPAN_PORT_RXBREAK;
		} else {
			cur_kp->kp_status_flag &= ~KEYSPAN_PORT_RXBREAK;
		}

		mutex_exit(&cur_kp->kp_mutex);

		if (need_cb) {

			cur_kp->kp_cb.cb_status(cur_kp->kp_cb.cb_arg);
		}
	} else {

		USB_DPRINTF_L2(DPRINT_IN_PIPE, bulkin->pipe_lh,
		    "keyspan_status_cb_usa49: get status failed, cr=%d"
		    " data_len=%d", cr, data_len);
	}
}


/*
 * pipe callbacks
 * --------------
 *
 * bulk in callback for status receiving
 */
/*ARGSUSED*/
void
keyspan_status_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)req->bulk_client_private;
	usb_cr_t	cr = req->bulk_completion_reason;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, (&ksp->ks_statin_pipe)->pipe_lh,
	    "keyspan_status_cb");

	/* put data on the read queue */
	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		keyspan_status_cb_usa19hs(pipe, req);

		break;


	case KEYSPAN_USA49WLC_PID:
		keyspan_status_cb_usa49(pipe, req);

		break;

	default:
		USB_DPRINTF_L2(DPRINT_IN_PIPE,
		    (&ksp->ks_statin_pipe)->pipe_lh, "keyspan_status_cb:"
		    "the device's product id can't be recognized");

		return;
	}

	usb_free_bulk_req(req);

	/* kick off another read to receive status */
	if ((cr != USB_CR_FLUSHED) && (cr != USB_CR_DEV_NOT_RESP) &&
	    keyspan_dev_is_online(ksp)) {
		if (keyspan_receive_status(ksp) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_IN_PIPE,
			    (&ksp->ks_statin_pipe)->pipe_lh,
			    "keyspan_status_cb:"
			    "receive status can't be restarted.");
		}
	} else {
		USB_DPRINTF_L2(DPRINT_IN_PIPE,
		    (&ksp->ks_statin_pipe)->pipe_lh, "keyspan_status_cb:"
		    "get status failed: cr=%d", cr);
	}
}

/*
 * Submit data read request (asynchronous). If this function returns
 * USB_SUCCESS, pipe is acquired and request is sent, otherwise req is free.
 */
int
keyspan_receive_data(keyspan_pipe_t *bulkin, int len, void *cb_arg)
{
	keyspan_state_t	*ksp = bulkin->pipe_ksp;
	usb_bulk_req_t	*br;
	int		rval;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh, "keyspan_receive_data:"
	    "len=%d", len);

	ASSERT(!mutex_owned(&bulkin->pipe_mutex));

	br = usb_alloc_bulk_req(ksp->ks_dip, len, USB_FLAGS_SLEEP);
	br->bulk_len = len;

	/* No timeout, just wait for data */
	br->bulk_timeout = 0;
	br->bulk_client_private = cb_arg;
	br->bulk_attributes = USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;
	br->bulk_cb = keyspan_bulkin_cb;
	br->bulk_exc_cb = keyspan_bulkin_cb;

	rval = usb_pipe_bulk_xfer(bulkin->pipe_handle, br, 0);
	if (rval != USB_SUCCESS) {
		usb_free_bulk_req(br);
	}
	USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
	    "keyspan_receive_data: rval = %d", rval);
	return (rval);
}

/*
 * submit device status read request (asynchronous).
 */
int
keyspan_receive_status(keyspan_state_t	*ksp)
{
	keyspan_pipe_t *bulkin = &ksp->ks_statin_pipe;
	usb_bulk_req_t	*br;
	int		rval;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
	    "keyspan_receive_status");

	ASSERT(!mutex_owned(&bulkin->pipe_mutex));

	br = usb_alloc_bulk_req(ksp->ks_dip, 32, USB_FLAGS_SLEEP);
	br->bulk_len = KEYSPAN_STATIN_MAX_LEN;

	/* No timeout, just wait for data */
	br->bulk_timeout = 0;
	br->bulk_client_private = (void *)ksp;
	br->bulk_attributes = USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;
	br->bulk_cb = keyspan_status_cb;
	br->bulk_exc_cb = keyspan_status_cb;

	rval = usb_pipe_bulk_xfer(bulkin->pipe_handle, br, 0);
	if (rval != USB_SUCCESS) {
		usb_free_bulk_req(br);
	}
	USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh,
	    "keyspan_receive_status: rval = %d", rval);
	return (rval);
}

/*
 * submit data for transfer (asynchronous)
 *
 * if data was sent successfully, 'mpp' will be nulled to indicate
 * that mblk is consumed by USBA and no longer belongs to the caller.
 *
 * if this function returns USB_SUCCESS, pipe is acquired and request
 * is sent, otherwise pipe is free.
 */
int
keyspan_send_data(keyspan_pipe_t *bulkout, mblk_t **mpp, void *cb_arg)
{
	keyspan_state_t	*ksp = bulkout->pipe_ksp;
	usb_bulk_req_t	*br;
	int		rval;

	ASSERT(!mutex_owned(&bulkout->pipe_mutex));
	USB_DPRINTF_L4(DPRINT_OUT_PIPE, bulkout->pipe_lh,
	    "keyspan_send_data");

	br = usb_alloc_bulk_req(ksp->ks_dip, 0, USB_FLAGS_SLEEP);
	br->bulk_len = MBLKL(*mpp);
	br->bulk_data = *mpp;
	br->bulk_timeout = KEYSPAN_BULK_TIMEOUT;
	br->bulk_client_private = cb_arg;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING;
	br->bulk_cb = keyspan_bulkout_cb;
	br->bulk_exc_cb = keyspan_bulkout_cb;

	USB_DPRINTF_L3(DPRINT_OUT_PIPE, bulkout->pipe_lh, "keyspan_send_data:"
	    "bulk_len = %d", br->bulk_len);

	rval = usb_pipe_bulk_xfer(bulkout->pipe_handle, br, 0);
	if (rval == USB_SUCCESS) {

		/* data consumed. The mem will be released in bulkout_cb */
		*mpp = NULL;
	} else {

		/*
		 * Don't free it in usb_free_bulk_req because it will
		 * be linked in keyspan_put_head
		 */
		br->bulk_data = NULL;

		usb_free_bulk_req(br);
	}
	USB_DPRINTF_L4(DPRINT_OUT_PIPE, bulkout->pipe_lh,
	    "keyspan_send_data: rval = %d", rval);

	return (rval);
}
