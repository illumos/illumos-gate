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
 */


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
/*
 * For USA_49WG only.
 * Lookup the endpoints defined in the spec.
 * Allocate resources, initialize pipe structures.
 * There are 6 EPs, 3 bulk out Eps, 1 bulk in EP, 1 intr in EP, 1 intr out EP
 */
int
keyspan_init_pipes_usa49wg(keyspan_state_t *ksp)
{
	usb_client_dev_data_t *dev_data = ksp->ks_dev_data;
	int		ifc, alt, i, j = 0;
	uint8_t		port_cnt = ksp->ks_dev_spec.port_cnt;
	uint8_t		ep_addr;
	usb_ep_data_t	*dataout[KEYSPAN_MAX_PORT_NUM],
	    *datain[KEYSPAN_MAX_PORT_NUM],
	    *status = NULL, *tmp_ep;

	ifc = dev_data->dev_curr_if;
	alt = 0;

	/*
	 * get intr out EP descriptor as port0 data out EP, and then
	 * match with EP address.
	 * Different keyspan devices may has different EP addresses.
	 */
	tmp_ep = usb_lookup_ep_data(ksp->ks_dip, dev_data, ifc, alt, 0,
	    USB_EP_ATTR_INTR, USB_EP_DIR_OUT);
	if (tmp_ep == NULL) {
		USB_DPRINTF_L3(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_init_pipes: can't find port1 data out ep");

		return (USB_FAILURE);
		}
	ep_addr = tmp_ep->ep_descr.bEndpointAddress;

	/* match the port0 data out EP */
	if (ep_addr == ksp->ks_dev_spec.dataout_ep_addr[0]) {
		dataout[0] = tmp_ep;
	}

	/*
	 * get bulk out EP descriptors as other port data out EPs, and then
	 * match with EP addresses.
	 */
	for (j = 1; j < port_cnt; j++) {
		tmp_ep = usb_lookup_ep_data(ksp->ks_dip, dev_data, ifc, alt,
		    j-1, USB_EP_ATTR_BULK, USB_EP_DIR_OUT);
		if (tmp_ep == NULL) {
			USB_DPRINTF_L3(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_init_pipes: can't find port[%d] "
			    "data out ep",
			    j);
			return (USB_FAILURE);
		}

		ep_addr = tmp_ep->ep_descr.bEndpointAddress;

		/* match other port data out EPs */
		if (ep_addr == ksp->ks_dev_spec.dataout_ep_addr[j]) {
			dataout[j] = tmp_ep;
		}
	}

	/*
	 * get intr in EP descriptor as status EP, and then match with EP addrs
	 */
	tmp_ep = usb_lookup_ep_data(ksp->ks_dip, dev_data, ifc, alt, 0,
	    USB_EP_ATTR_INTR, USB_EP_DIR_IN);
	if (tmp_ep == NULL) {
		USB_DPRINTF_L3(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_init_pipes: can't find status in ep");

		return (USB_FAILURE);
	}
	ep_addr = tmp_ep->ep_descr.bEndpointAddress;

	/* match the status ep */
	if (ep_addr == ksp->ks_dev_spec.stat_ep_addr) {
		status = tmp_ep;
	}

	/*
	 * get bulk in EP descriptors as data in EP, All the ports share one
	 * data in EP.
	 */
	tmp_ep = usb_lookup_ep_data(ksp->ks_dip, dev_data, ifc, alt, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_IN);
	if (tmp_ep == NULL) {
		USB_DPRINTF_L3(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_init_pipes: can't find bulk in ep");

		return (USB_FAILURE);
	}
	ep_addr = tmp_ep->ep_descr.bEndpointAddress;

	/* match data in EPs */
	if (ep_addr == ksp->ks_dev_spec.datain_ep_addr[0]) {
		datain[0] = tmp_ep;
	}

	mutex_enter(&ksp->ks_mutex);

	/* intr in pipe for status */
	ksp->ks_statin_pipe.pipe_ep_descr = status->ep_descr;
	keyspan_init_one_pipe(ksp, NULL, &ksp->ks_statin_pipe);

	/* for data in/out pipes of each port */
	for (i = 0; i < port_cnt; i++) {
		ksp->ks_ports[i].kp_datain_pipe.pipe_ep_descr =
		    datain[0]->ep_descr;
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

	/* fini status pipe */
	keyspan_fini_one_pipe(&ksp->ks_statin_pipe);
	/*
	 * fini control pipe
	 * If USA_49WG, don't need fini control pipe
	 */
	switch (ksp->ks_dev_spec.id_product) {
		case KEYSPAN_USA19HS_PID:
		case KEYSPAN_USA49WLC_PID:
			keyspan_fini_one_pipe(&ksp->ks_ctrlout_pipe);

			break;
		case KEYSPAN_USA49WG_PID:

			break;
		default:
			USB_DPRINTF_L2(DPRINT_CTLOP, ksp->ks_lh,
			    "keyspan_fini_pipes: the device's product id"
			    "can't be recognized");
	}
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
 * Open shared datain pipe for USA_49WG
 */
static int
keyspan_open_pipe_datain_usa49wg(keyspan_state_t *ksp, keyspan_pipe_t *pipe)
{
	int	rval = USB_SUCCESS;

	/* don't open for the second time */
	mutex_enter(&pipe->pipe_mutex);
	ASSERT(pipe->pipe_state != KEYSPAN_PIPE_NOT_INIT);
	if (pipe->pipe_state != KEYSPAN_PIPE_CLOSED) {
		mutex_exit(&pipe->pipe_mutex);

		return (USB_SUCCESS);
	}
	mutex_exit(&pipe->pipe_mutex);

	mutex_enter(&ksp->ks_mutex);
	ksp->ks_datain_open_cnt++;
	if (ksp->ks_datain_open_cnt == 1) {
		mutex_exit(&ksp->ks_mutex);

		if ((rval = (usb_pipe_open(ksp->ks_dip, &pipe->pipe_ep_descr,
		    &pipe->pipe_policy, USB_FLAGS_SLEEP,
		    &pipe->pipe_handle))) == USB_SUCCESS) {
				mutex_enter(&pipe->pipe_mutex);
				pipe->pipe_state = KEYSPAN_PIPE_OPEN;
				mutex_exit(&pipe->pipe_mutex);

				mutex_enter(&ksp->ks_mutex);
				ksp->ks_datain_pipe_handle = pipe->pipe_handle;
				mutex_exit(&ksp->ks_mutex);
		} else {
				mutex_enter(&ksp->ks_mutex);
				ksp->ks_datain_open_cnt--;
				mutex_exit(&ksp->ks_mutex);
		}

		return (rval);
	} else {
		/* data in pipe has been opened by other port */
		ASSERT(ksp->ks_datain_pipe_handle != NULL);

		mutex_enter(&pipe->pipe_mutex);
		pipe->pipe_handle = ksp->ks_datain_pipe_handle;
		/* Set datain pipe state */
		pipe->pipe_state = KEYSPAN_PIPE_OPEN;
		mutex_exit(&pipe->pipe_mutex);
		mutex_exit(&ksp->ks_mutex);

		return (USB_SUCCESS);
	}
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
 * close shared datain pipe if open for USA_49WG
 */
static void
keyspan_close_pipe_datain_usa49wg(keyspan_pipe_t *pipe)
{
	keyspan_state_t *ksp = pipe->pipe_ksp;
	/*
	 * pipe may already be closed, e.g. if device has been physically
	 * disconnected and the driver immediately detached
	 */
	if (pipe->pipe_handle != NULL) {
		mutex_enter(&ksp->ks_mutex);
		ksp->ks_datain_open_cnt--;
		if (!ksp->ks_datain_open_cnt) {
			mutex_exit(&ksp->ks_mutex);
			usb_pipe_close(pipe->pipe_ksp->ks_dip,
			    pipe->pipe_handle, USB_FLAGS_SLEEP,
			    NULL, NULL);
		} else {
			mutex_exit(&ksp->ks_mutex);
		}

		mutex_enter(&pipe->pipe_mutex);
		pipe->pipe_handle = NULL;
		pipe->pipe_state = KEYSPAN_PIPE_CLOSED;
		mutex_exit(&pipe->pipe_mutex);
	}
}

/*
 * For USA19HS and USA49WLC:
 * Open global pipes, a status pipe and a control pipe
 */
int
keyspan_open_dev_pipes_usa49(keyspan_state_t *ksp)
{
	int		rval;

	USB_DPRINTF_L4(DPRINT_OPEN, ksp->ks_lh,
	    "keyspan_open_dev_pipes_usa49");

	rval = keyspan_open_one_pipe(ksp, &ksp->ks_ctrlout_pipe);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_OPEN, ksp->ks_lh,
		    "keyspan_open_dev_pipes_usa49: open ctrl pipe failed %d",
		    rval);
		return (rval);
	}

	rval = keyspan_open_one_pipe(ksp, &ksp->ks_statin_pipe);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_OPEN, ksp->ks_lh,
		    "keyspan_open_dev_pipes_usa49: open status pipe failed %d",
		    rval);

		/* close the first opened pipe here */
		keyspan_close_one_pipe(&ksp->ks_ctrlout_pipe);

		return (rval);
	}

	/* start receive device status */
	rval = keyspan_receive_status(ksp);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_OPEN, ksp->ks_lh,
		    "keyspan_open_dev_pipes_usa49: receive device status"
		    " failed %d", rval);

		/* close opened pipes here */
		keyspan_close_one_pipe(&ksp->ks_statin_pipe);
		keyspan_close_one_pipe(&ksp->ks_ctrlout_pipe);

		return (rval);
	}

	return (rval);
}

/*
 * For keyspan USA_49WG:
 * Open global pipes, a status pipe
 * Use default control pipe, don't need to open it.
 */
int
keyspan_open_dev_pipes_usa49wg(keyspan_state_t *ksp)
{
	int		rval;

	/* Open status pipe */
	rval = keyspan_open_one_pipe(ksp, &ksp->ks_statin_pipe);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_OPEN, ksp->ks_lh,
		    "keyspan_open_dev_pipes_usa49wg: "
		    "open status pipe failed %d",
		    rval);

		return (rval);
	}
	/* start device polling */
	keyspan_pipe_start_polling(&ksp->ks_statin_pipe);

	return (rval);
}

/*
 * Open global pipes, status pipe and control pipe,
 */
int
keyspan_open_dev_pipes(keyspan_state_t *ksp)
{
	int		rval = USB_SUCCESS;

	USB_DPRINTF_L4(DPRINT_OPEN, ksp->ks_lh, "keyspan_open_dev_pipes");

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
	case KEYSPAN_USA49WLC_PID:
		rval = keyspan_open_dev_pipes_usa49(ksp);

		break;
	case KEYSPAN_USA49WG_PID:
		rval = keyspan_open_dev_pipes_usa49wg(ksp);

		break;
	default:
		USB_DPRINTF_L2(DPRINT_OPEN, ksp->ks_lh,
		    "keyspan_open_dev_pipes: the device's product id can't"
		    "be recognized");

		return (USB_FAILURE);
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
	keyspan_state_t *ksp =	kp->kp_ksp;

	USB_DPRINTF_L4(DPRINT_CLOSE, kp->kp_lh, "keyspan_close_port_pipes");

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
	case KEYSPAN_USA49WLC_PID:
		keyspan_close_one_pipe(&kp->kp_datain_pipe);

		break;
	case KEYSPAN_USA49WG_PID:
		keyspan_close_pipe_datain_usa49wg(&kp->kp_datain_pipe);

		break;
	default:
		USB_DPRINTF_L2(DPRINT_CLOSE, kp->kp_lh,
		    "keyspan_close_port_pipes:"
		    "the device's product id can't be recognized");
	}
	keyspan_close_one_pipe(&kp->kp_dataout_pipe);
}

/*
 * Close IN and OUT bulk pipes of all ports
 */
void
keyspan_close_open_pipes(keyspan_state_t *ksp)
{
	keyspan_port_t	*kp;
	int		i;
	int		port_num = -1;

	USB_DPRINTF_L4(DPRINT_CLOSE, ksp->ks_lh, "keyspan_close_open_pipes");

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
	case KEYSPAN_USA49WLC_PID:
		for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
			kp = &ksp->ks_ports[i];
			mutex_enter(&kp->kp_mutex);
			if (kp->kp_state == KEYSPAN_PORT_OPEN) {
				kp->kp_no_more_reads = B_TRUE;
				mutex_exit(&kp->kp_mutex);
				usb_pipe_reset(ksp->ks_dip,
				    kp->kp_datain_pipe.pipe_handle,
				    USB_FLAGS_SLEEP, NULL, NULL);
				keyspan_close_port_pipes(kp);
			} else {
				mutex_exit(&kp->kp_mutex);
			}
		}

		break;

	case KEYSPAN_USA49WG_PID:
		for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
			kp = &ksp->ks_ports[i];
			mutex_enter(&kp->kp_mutex);
			if (kp->kp_state == KEYSPAN_PORT_OPEN) {
				kp->kp_no_more_reads = B_TRUE;
				port_num = i;
			}
			mutex_exit(&kp->kp_mutex);
		}
		if (port_num >= 0) {
			kp = &ksp->ks_ports[port_num];
			usb_pipe_reset(ksp->ks_dip,
			    kp->kp_datain_pipe.pipe_handle,
			    USB_FLAGS_SLEEP, NULL, NULL);
		}

		for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
			kp = &ksp->ks_ports[i];
			mutex_enter(&kp->kp_mutex);
			if (kp->kp_state == KEYSPAN_PORT_OPEN) {
				mutex_exit(&kp->kp_mutex);
				keyspan_close_port_pipes(kp);
			} else {
				mutex_exit(&kp->kp_mutex);
			}
		}

		break;
	default:
		USB_DPRINTF_L2(DPRINT_CLOSE, ksp->ks_lh,
		    "keyspan_close_open_pipes:"
		    "the device's product id can't be recognized");

	}
}

/*
 * Close global pipes
 */
void
keyspan_close_dev_pipes(keyspan_state_t *ksp)
{
	USB_DPRINTF_L4(DPRINT_CLOSE, ksp->ks_lh, "keyspan_close_dev_pipes");

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
	case KEYSPAN_USA49WLC_PID:
		keyspan_close_one_pipe(&ksp->ks_statin_pipe);
		keyspan_close_one_pipe(&ksp->ks_ctrlout_pipe);

		break;

	case KEYSPAN_USA49WG_PID:
		/*
		 * USA_49WG use default control pipe, don't need close it
		 * Stop polling before close status in pipe
		 */
		usb_pipe_stop_intr_polling(ksp->ks_statin_pipe.pipe_handle,
		    USB_FLAGS_SLEEP);
		keyspan_close_one_pipe(&ksp->ks_statin_pipe);

		break;
	default:
		USB_DPRINTF_L2(DPRINT_CLOSE, ksp->ks_lh,
		    "keyspan_close_dev_pipes:"
		    "the device's product id can't be recognized");
	}

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

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
	case KEYSPAN_USA49WLC_PID:
		rval = keyspan_open_one_pipe(ksp, &kp->kp_datain_pipe);

		break;
	case KEYSPAN_USA49WG_PID:
		rval = keyspan_open_pipe_datain_usa49wg(ksp,
		    &kp->kp_datain_pipe);

		break;
	default:
		USB_DPRINTF_L2(DPRINT_OPEN, kp->kp_lh,
		    "keyspan_open_port_pipes:"
		    "the device's product id can't be recognized");
	}

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

/*
 * intr out common callback for USA_49WG port0 only
 */
/*ARGSUSED*/
void
keyspan_introut_cb_usa49wg(usb_pipe_handle_t pipe, usb_intr_req_t *req)
{
	keyspan_port_t	*kp = (keyspan_port_t *)req->intr_client_private;
	keyspan_pipe_t	*introut = &kp->kp_dataout_pipe;
	mblk_t		*data = req->intr_data;
	int		data_len;

	data_len = (data) ? MBLKL(data) : 0;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, introut->pipe_lh,
	    "keyspan_introut_cb_usa49wg: len=%d cr=%d cb_flags=%x",
	    data_len, req->intr_completion_reason, req->intr_cb_flags);

	if (req->intr_completion_reason && (data_len > 0)) {

		/*
		 * Data wasn't transfered successfully.
		 * Put data back on the queue.
		 */
		keyspan_put_head(&kp->kp_tx_mp, data, kp);

		/* don't release mem in usb_free_bulk_req */
		req->intr_data = NULL;
	}

	usb_free_intr_req(req);

	/* if more data available, kick off another transmit */
	mutex_enter(&kp->kp_mutex);
	if (kp->kp_tx_mp == NULL) {

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

/* Bulk in data process function, used by all models */
int
keyspan_bulkin_cb_process(keyspan_port_t *kp,
		uint8_t data_len, uchar_t status, mblk_t *data)
{
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

		/* Get rid of the first status byte */
		data->b_rptr++;
		data_len--;

	} else if (!(status & 0x80)) {
		/* If 0x80 bit is clear and overrun bit is set */

		keyspan_parse_status(&status, &err);
		mutex_exit(&kp->kp_mutex);
		if ((mp = allocb(2, BPRI_HI)) == NULL) {
			USB_DPRINTF_L2(DPRINT_IN_PIPE, kp->kp_lh,
			    "keyspan_bulkin_cb_process: allocb failed");
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

	} else { /* 0x80 bit set, there are some errs in the data */
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
			    "keyspan_bulkin_cb_process: allocb failed");
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
		}
	}
	return (data_len);
}

/*
 * pipe callbacks
 * --------------
 *
 * bulk in common callback for USA19HS and USA49WLC model
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

		if ((data_len = keyspan_bulkin_cb_process(kp, data_len,
		    status, data)) > 0) {
			keyspan_put_tail(&kp->kp_rx_mp, data);
			/*
			 * the data will not be freed and
			 * will be sent up later.
			 */
			req->bulk_data = NULL;
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
 * bulk in common callback for USA_49WG model
 */
/*ARGSUSED*/
void
keyspan_bulkin_cb_usa49wg(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	keyspan_port_t	*kp = (keyspan_port_t *)req->bulk_client_private,
	    *kp_true;
	keyspan_state_t *ksp = (keyspan_state_t *)kp->kp_ksp;
	mblk_t		*data = req->bulk_data,
	    *mp_data;
	uint_t		cr = req->bulk_completion_reason,
	    port_data_len;
	int		data_len, copy_len;
	uint8_t		port_num,
	    port_cnt = 0,
	    port[4],
	    receive_flag = 1;
	uint16_t	status;
	unsigned char	*old_rptr;

	data_len = (data) ? MBLKL(data) : 0;

	USB_DPRINTF_L2(DPRINT_IN_PIPE, ksp->ks_lh,
	    "keyspan_bulkin_cb_usa49wg: len=%d"
	    " cr=%d flags=%x", data_len, cr, req->bulk_cb_flags);

	/* put data on the read queue */
	if ((data_len > 0) && (cr == USB_CR_OK)) {
		old_rptr = data->b_rptr;
		while (data->b_rptr < data->b_wptr) {
			port_num = data->b_rptr[0];
			port_data_len = data->b_rptr[1];
			status = data->b_rptr[2];
			data->b_rptr += 2;

			if (port_num > 3) {
				USB_DPRINTF_L2(DPRINT_IN_PIPE, ksp->ks_lh,
				    "keyspan_bulkin_cb_usa49wg,port num is not"
				    " correct: port=%d, len=%d, status=%x",
				    port_num, port_data_len, status);

				break;
			}

			kp_true = &ksp->ks_ports[port_num];
			port[++port_cnt] = port_num;
			mutex_enter(&kp_true->kp_mutex);

			if (kp_true->kp_state != KEYSPAN_PORT_OPEN) {
				mutex_exit(&kp_true->kp_mutex);

				USB_DPRINTF_L2(DPRINT_IN_PIPE, kp_true->kp_lh,
				    "keyspan_bulkin_cb_usa49wg, "
				    "port isn't opened");
				data->b_rptr += port_data_len;
				port_cnt--;

				continue;
			}

			USB_DPRINTF_L2(DPRINT_IN_PIPE, kp_true->kp_lh,
			    "keyspan_bulkin_cb_usa49wg: status=0x%x, len=%d",
			    status, port_data_len);

			if ((copy_len = keyspan_bulkin_cb_process(kp_true,
			    port_data_len, status, data)) > 0) {

				mutex_exit(&kp_true->kp_mutex);
				if ((mp_data = allocb(copy_len, BPRI_HI))
				    == NULL) {
					USB_DPRINTF_L2(DPRINT_IN_PIPE,
					    kp_true->kp_lh, "keyspan_bulkin_cb_"
					    "usa49wg: allocb failed");

					return;
				}
				mutex_enter(&kp_true->kp_mutex);
				DB_TYPE(mp_data) = M_DATA;
				bcopy(data->b_rptr, mp_data->b_wptr, copy_len);
				mp_data->b_wptr += copy_len;
				if (copy_len < port_data_len -1) {
					/*
					 * data has multi status bytes, b_wptr
					 * has changed by
					 * keyspan_bulkin_process(), need to
					 * be recovered to old one
					 */
					data->b_rptr += port_data_len;
					data->b_wptr = old_rptr + data_len;
				} else {
					data->b_rptr += copy_len;
				}

				keyspan_put_tail(&kp_true->kp_rx_mp, mp_data);
				mutex_exit(&kp_true->kp_mutex);
			} else {
				mutex_exit(&kp_true->kp_mutex);

				break;
			}
		} /* End of while loop */

		while (port_cnt) {
			port_num = port[port_cnt--];
			kp_true = &ksp->ks_ports[port_num];
			mutex_enter(&kp_true->kp_mutex);

			if (kp_true->kp_state != KEYSPAN_PORT_OPEN) {
				kp_true->kp_no_more_reads = B_TRUE;
			}
			if (receive_flag && (!kp_true->kp_no_more_reads)) {
				mutex_exit(&kp_true->kp_mutex);
				/* kick off another read */
				(void) keyspan_receive_data(
				    &kp_true->kp_datain_pipe,
				    kp_true->kp_read_len, kp_true);

				receive_flag = 0;
			} else {
				mutex_exit(&kp_true->kp_mutex);
			}
			/* setup rx callback for this port */
			kp_true->kp_cb.cb_rx(kp_true->kp_cb.cb_arg);
		}
	} else {
		/* cr != USB_CR_OK, usb error happened */
		USB_DPRINTF_L2(DPRINT_IN_PIPE, ksp->ks_lh,
		    "keyspan_bulkin_cb_usa49wg: port=%d, len=%d, status=%x",
		    data->b_rptr[0], data->b_rptr[1], data->b_rptr[2]);

		mutex_enter(&kp->kp_mutex);
		if (kp->kp_state != KEYSPAN_PORT_OPEN) {
			kp->kp_no_more_reads = B_TRUE;
		}
		if (!kp->kp_no_more_reads) {
			mutex_exit(&kp->kp_mutex);
			/* kick off another read */
			(void) keyspan_receive_data(&kp->kp_datain_pipe,
			    kp->kp_read_len, kp);
		} else {
			mutex_exit(&kp->kp_mutex);
		}
	}

	freemsg(data);
	req->bulk_data = NULL;
	usb_free_bulk_req(req);

}

/*
 * pipe callbacks
 * --------------
 *
 * bulk in common callback for USA19HS and USA49WLC
 */
/*ARGSUSED*/
void
keyspan_bulkin_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	keyspan_port_t	*kp = (keyspan_port_t *)req->bulk_client_private;
	int		data_len;
	boolean_t	no_more_reads = B_FALSE;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, (&kp->kp_datain_pipe)->pipe_lh,
	    "keyspan_bulkin_cb");

	mutex_enter(&kp->kp_mutex);

	/* put data on the read queue */
	data_len = keyspan_bulkin_cb_usa49(pipe, req);
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
	int		rval = USB_SUCCESS;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, bulkin->pipe_lh, "keyspan_receive_data:"
	    "len=%d", len);

	ASSERT(!mutex_owned(&bulkin->pipe_mutex));

	br = usb_alloc_bulk_req(ksp->ks_dip, len, USB_FLAGS_SLEEP);
	br->bulk_len = len;

	/* No timeout, just wait for data */
	br->bulk_timeout = 0;
	br->bulk_client_private = cb_arg;
	br->bulk_attributes = USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
	case KEYSPAN_USA49WLC_PID:
		br->bulk_cb = keyspan_bulkin_cb;
		br->bulk_exc_cb = keyspan_bulkin_cb;

		break;

	case KEYSPAN_USA49WG_PID:
		br->bulk_cb = keyspan_bulkin_cb_usa49wg;
		br->bulk_exc_cb = keyspan_bulkin_cb_usa49wg;

		break;

	default:
		usb_free_bulk_req(br);

		USB_DPRINTF_L2(DPRINT_IN_PIPE,
		    (&ksp->ks_statin_pipe)->pipe_lh, "keyspan_receive_data:"
		    "the device's product id can't be recognized");

		return (USB_FAILURE);
	}


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

/*
 * submit data for transfer (asynchronous) for USA_49WG Port0 only
 *
 * if data was sent successfully, 'mpp' will be nulled to indicate
 * that mblk is consumed by USBA and no longer belongs to the caller.
 *
 * if this function returns USB_SUCCESS, pipe is acquired and request
 * is sent, otherwise pipe is free.
 */
int
keyspan_send_data_port0(keyspan_pipe_t *introut, mblk_t **mpp, void *cb_arg)
{
	keyspan_state_t	*ksp = introut->pipe_ksp;
	usb_intr_req_t	*br;
	int		rval;

	ASSERT(!mutex_owned(&introut->pipe_mutex));
	USB_DPRINTF_L4(DPRINT_OUT_PIPE, introut->pipe_lh,
	    "keyspan_send_data_port0");

	br = usb_alloc_intr_req(ksp->ks_dip, 0, USB_FLAGS_SLEEP);
	br->intr_len = MBLKL(*mpp);
	br->intr_data = *mpp;
	br->intr_timeout = KEYSPAN_BULK_TIMEOUT;
	br->intr_client_private = cb_arg;
	br->intr_cb = keyspan_introut_cb_usa49wg;
	br->intr_exc_cb = keyspan_introut_cb_usa49wg;

	USB_DPRINTF_L3(DPRINT_OUT_PIPE, introut->pipe_lh,
	    "keyspan_send_data_port0: intr_len = %d",
	    br->intr_len);

	rval = usb_pipe_intr_xfer(introut->pipe_handle, br, 0);
	if (rval == USB_SUCCESS) {

		/*
		 * data consumed. The mem will be released in
		 * introut_cb_usa49wg
		 */
		*mpp = NULL;
	} else {
		br->intr_data = NULL;

		usb_free_intr_req(br);
	}
	USB_DPRINTF_L4(DPRINT_OUT_PIPE, introut->pipe_lh,
	    "keyspan_send_data_port0: rval = %d", rval);

	return (rval);
}

/*
 * pipe callbacks
 * --------------
 *
 * bulk in status callback for USA_49WG model
 */
/*ARGSUSED*/
void
keyspan_status_cb_usa49wg(usb_pipe_handle_t pipe, usb_intr_req_t *req)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)req->intr_client_private;
	keyspan_pipe_t	*intr = &ksp->ks_statin_pipe;
	mblk_t		*data = req->intr_data;
	uint_t		cr = req->intr_completion_reason;
	int		data_len;

	data_len = (data) ? MBLKL(data) : 0;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, intr->pipe_lh,
	    "keyspan_status_cb_usa49wg: len=%d"
	    " cr=%d flags=%x", data_len, cr, req->intr_cb_flags);

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

		USB_DPRINTF_L2(DPRINT_IN_PIPE, intr->pipe_lh,
		    "keyspan_status_cb_usa49wg: get status failed, cr=%d"
		    " data_len=%d", cr, data_len);
	}
}

/*
 * pipe callbacks
 * --------------
 *
 * intr in callback for status receiving for USA_49WG model only
 */
/*ARGSUSED*/
void
keyspan_intr_cb_usa49wg(usb_pipe_handle_t pipe, usb_intr_req_t *req)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)req->intr_client_private;
	usb_cr_t	cr = req->intr_completion_reason;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, (&ksp->ks_statin_pipe)->pipe_lh,
	    "keyspan_intr_cb_usa49wg: cr=%d", cr);

	/* put data on the read queue */
	(void) keyspan_status_cb_usa49wg(pipe, req);

	usb_free_intr_req(req);
}

/*
 * pipe callbacks
 * --------------
 *
 * intr in exception callback for status receiving for USA_49WG model only
 */
/*ARGSUSED*/
void
keyspan_intr_ex_cb_usa49wg(usb_pipe_handle_t pipe, usb_intr_req_t *req)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)req->intr_client_private;
	usb_cr_t	cr = req->intr_completion_reason;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, (&ksp->ks_statin_pipe)->pipe_lh,
	    "keyspan_intr_ex_cb_usa49wg: cr=%d", cr);

	usb_free_intr_req(req);

	if ((cr != USB_CR_PIPE_CLOSING) && (cr != USB_CR_STOPPED_POLLING) &&
	    (cr != USB_CR_FLUSHED) && (cr != USB_CR_DEV_NOT_RESP) &&
	    (cr != USB_CR_PIPE_RESET) && keyspan_dev_is_online(ksp)) {
		keyspan_pipe_start_polling(&ksp->ks_statin_pipe);
	} else {
		USB_DPRINTF_L2(DPRINT_IN_PIPE,
		    (&ksp->ks_statin_pipe)->pipe_lh,
		    "keyspan_intr_ex_cb_usa49wg:"
		    "get status failed: cr=%d", cr);
	}
}

/*
 * start polling on the interrupt pipe for USA_49WG model only
 */
void
keyspan_pipe_start_polling(keyspan_pipe_t *intr)
{
	usb_intr_req_t	*br;
	keyspan_state_t	*ksp = intr->pipe_ksp;
	int		rval;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, ksp->ks_lh,
	    "keyspan_pipe_start_polling");

	br = usb_alloc_intr_req(ksp->ks_dip, 0, USB_FLAGS_SLEEP);

	/*
	 * If it is in interrupt context, usb_alloc_intr_req will return NULL if
	 * called with SLEEP flag.
	 */
	if (!br) {
		USB_DPRINTF_L2(DPRINT_IN_PIPE, ksp->ks_lh,
		    "keyspan_pipe_start_polling: alloc req failed.");

		return;
	}
	br->intr_attributes = USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;
	br->intr_len = intr->pipe_ep_descr.wMaxPacketSize;
	br->intr_client_private = (void *)ksp;

	br->intr_cb = keyspan_intr_cb_usa49wg;
	br->intr_exc_cb = keyspan_intr_ex_cb_usa49wg;


	rval = usb_pipe_intr_xfer(intr->pipe_handle, br, USB_FLAGS_SLEEP);

	mutex_enter(&intr->pipe_mutex);
	if (rval != USB_SUCCESS) {
		usb_free_intr_req(br);
		intr->pipe_state = KEYSPAN_PIPE_CLOSED;

		USB_DPRINTF_L3(DPRINT_IN_PIPE, ksp->ks_lh,
		    "keyspan_pipe_start_polling: failed (%d)", rval);
	} else {
		intr->pipe_state = KEYSPAN_PIPE_OPEN;
	}

	mutex_exit(&intr->pipe_mutex);
}
