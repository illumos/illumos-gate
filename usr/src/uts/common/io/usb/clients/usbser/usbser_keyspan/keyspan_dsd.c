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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * DSD code for keyspan usb2serial adapters
 *
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/termio.h>
#include <sys/termiox.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#include <sys/usb/usba.h>

#include <sys/usb/clients/usbser/usbser_dsdi.h>
#include <sys/usb/clients/usbser/usbser_keyspan/keyspan_var.h>
#include <sys/usb/clients/usbser/usbser_keyspan/keyspan_pipe.h>

#include <sys/usb/clients/usbser/usbser_keyspan/usa90msg.h>
#include <sys/usb/clients/usbser/usbser_keyspan/usa49msg.h>

/*
 * DSD operations which are filled in ds_ops structure.
 */
static int	keyspan_attach(ds_attach_info_t *);
static void	keyspan_detach(ds_hdl_t);
static int	keyspan_register_cb(ds_hdl_t, uint_t, ds_cb_t *);
static void	keyspan_unregister_cb(ds_hdl_t, uint_t);
static int	keyspan_open_port(ds_hdl_t, uint_t);
static int	keyspan_close_port(ds_hdl_t, uint_t);

/* power management */
static int	keyspan_usb_power(ds_hdl_t, int, int, int *);
static int	keyspan_suspend(ds_hdl_t);
static int	keyspan_resume(ds_hdl_t);

/* hotplug */
static int	keyspan_disconnect(ds_hdl_t);
static int	keyspan_reconnect(ds_hdl_t);

/* standard UART operations */
static int	keyspan_set_port_params(ds_hdl_t, uint_t, ds_port_params_t *);
static int	keyspan_set_modem_ctl(ds_hdl_t, uint_t, int, int);
static int	keyspan_get_modem_ctl(ds_hdl_t, uint_t, int, int *);
static int	keyspan_break_ctl(ds_hdl_t, uint_t, int);
static int	keyspan_loopback(ds_hdl_t, uint_t, int);

/* data xfer */
static int	keyspan_tx(ds_hdl_t, uint_t, mblk_t *);
static mblk_t	*keyspan_rx(ds_hdl_t, uint_t);
static void	keyspan_stop(ds_hdl_t, uint_t, int);
static void	keyspan_start(ds_hdl_t, uint_t, int);
static int	keyspan_fifo_flush(ds_hdl_t, uint_t, int);
static int	keyspan_fifo_drain(ds_hdl_t, uint_t, int);

/*
 * Sub-routines
 */

/* configuration routines */
static void	keyspan_free_soft_state(keyspan_state_t *);
static void	keyspan_init_sync_objs(keyspan_state_t *);
static void	keyspan_fini_sync_objs(keyspan_state_t *);
static int	keyspan_usb_register(keyspan_state_t *);
static void	keyspan_usb_unregister(keyspan_state_t *);
static int	keyspan_attach_dev(keyspan_state_t *);
static void	keyspan_attach_ports(keyspan_state_t *);
static void	keyspan_detach_ports(keyspan_state_t *);
static void	keyspan_init_port_params(keyspan_state_t *);
static void	keyspan_free_descr_tree(keyspan_state_t *);
static int	keyspan_register_events(keyspan_state_t *);
static void	keyspan_unregister_events(keyspan_state_t *);
static void	keyspan_set_dev_state_online(keyspan_state_t *);

/* hotplug */
static int	keyspan_restore_device_state(keyspan_state_t *);
static int	keyspan_restore_ports_state(keyspan_state_t *);

/* power management */
static int	keyspan_create_pm_components(keyspan_state_t *);
static void	keyspan_destroy_pm_components(keyspan_state_t *);
static int	keyspan_pm_set_busy(keyspan_state_t *);
static void	keyspan_pm_set_idle(keyspan_state_t *);
static int	keyspan_pwrlvl0(keyspan_state_t *);
static int	keyspan_pwrlvl1(keyspan_state_t *);
static int	keyspan_pwrlvl2(keyspan_state_t *);
static int	keyspan_pwrlvl3(keyspan_state_t *);

/* pipe operations */
static int	keyspan_attach_pipes(keyspan_state_t *);
static void	keyspan_detach_pipes(keyspan_state_t *);
static void	keyspan_disconnect_pipes(keyspan_state_t *);
static int	keyspan_reconnect_pipes(keyspan_state_t *);

/* data transfer routines */
static int	keyspan_wait_tx_drain(keyspan_port_t *, int);

/* misc */
static void	keyspan_default_port_params(keyspan_port_t *);
static void	keyspan_build_cmd_msg(keyspan_port_t *, ds_port_params_t *);
static void	keyspan_save_port_params(keyspan_port_t	*);

/*
 * Model specific functions.
 */

/* usa19hs specific functions */
static void	keyspan_build_cmd_msg_usa19hs(keyspan_port_t *,
    ds_port_params_t *);
static void	keyspan_default_port_params_usa19hs(keyspan_port_t *);
static void	keyspan_save_port_params_usa19hs(keyspan_port_t	*);


/* usa49 specific functions */
static void	keyspan_build_cmd_msg_usa49(keyspan_port_t *,
    ds_port_params_t *);
static void	keyspan_default_port_params_usa49(keyspan_port_t *);
static void	keyspan_save_port_params_usa49(keyspan_port_t	*);


/*
 * DSD ops structure
 */
ds_ops_t ds_ops = {
	DS_OPS_VERSION,
	keyspan_attach,
	keyspan_detach,
	keyspan_register_cb,
	keyspan_unregister_cb,
	keyspan_open_port,
	keyspan_close_port,
	keyspan_usb_power,
	keyspan_suspend,
	keyspan_resume,
	keyspan_disconnect,
	keyspan_reconnect,
	keyspan_set_port_params,
	keyspan_set_modem_ctl,
	keyspan_get_modem_ctl,
	keyspan_break_ctl,
	keyspan_loopback,
	keyspan_tx,
	keyspan_rx,
	keyspan_stop,
	keyspan_start,
	keyspan_fifo_flush,
	keyspan_fifo_drain
};

/*
 *  For USA19HS baud speed, precalculated using the following algorithm:
 *
 *	speed = (uint16_t)(14769231L / baud);
 */
static uint16_t	keyspan_speedtab_usa19hs[] = {
	0x0,	/* B0 */
	0x481d,	/* B50 */
	0x3013,	/* B75 */
	0x20c7,	/* B110 */
	0x1ae8,	/* B134 */
	0x1809,	/* B150 */
	0x1207,	/* B200 */
	0xc04,	/* B300 */
	0x602,	/* B600 */
	0x301,	/* B1200 */
	0x200,	/* B1800 */
	0x180,	/* B2400 */
	0xc0,	/* B4800 */
	0x60,	/* B9600 */
	0x30,	/* B19200 */
	0x18,	/* B38400 */
	0x10,	/* B57600 */
	0xc,	/* B76800 */
	0x8,	/* B115200 */
	0x6,	/* B153600 */
	0x4,	/* B230400 */
};

/*
 *  For USA49WLC baud speed, precalculated.
 */
static uint16_t	keyspan_speedtab_usa49[] = {
	0x0,	/* B0 */
	0x7530,	/* B50 */
	0x4e20,	/* B75 */
	0x3544,	/* B110 */
	0x2bba,	/* B134 */
	0x2710,	/* B150 */
	0x1d4c,	/* B200 */
	0x1388,	/* B300 */
	0x9c4,	/* B600 */
	0x4e2,	/* B1200 */
	0x25e,	/* B1800 */
	0x271,	/* B2400 */
	0xfa,	/* B4800 */
	0x7d,	/* B9600 */
	0x19,	/* B19200 */
	0x27,	/* B38400 */
	0x1a,	/* B57600 */
	0xd,	/* B76800 */
	0xd,	/* B115200 */
	0x6,	/* B153600 */
	0x4,	/* B230400 */
};

/*
 *  For USA49WLC prescaler, precalculated.
 */
static uint8_t	keyspan_prescaler_49wlc[] = {
	0x0,	/* B0 */
	0x8,	/* B50 */
	0x8,	/* B75 */
	0x8,	/* B110 */
	0x8,	/* B134 */
	0x8,	/* B150 */
	0x8,	/* B200 */
	0x8,	/* B300 */
	0x8,	/* B600 */
	0x8,	/* B1200 */
	0xb,	/* B1800 */
	0x8,	/* B2400 */
	0xa,	/* B4800 */
	0xa,	/* B9600 */
	0x19,	/* B19200 */
	0x8,	/* B38400 */
	0x8,	/* B57600 */
	0xc,	/* B76800 */
	0x8,	/* B115200 */
	0xd,	/* B153600 */
	0xd,	/* B230400 */
};


/* convert baud code into baud rate */
static int keyspan_speed2baud[] = {
	0,	/* B0 */
	50,	/* B50 */
	75,	/* B75 */
	110,	/* B110 */
	134,	/* B134 */
	150,	/* B150 */
	200,	/* B200 */
	300,	/* B300 */
	600,	/* B600 */
	1200,	/* B1200 */
	1800,	/* B1800 */
	2400,	/* B2400 */
	4800,	/* B4800 */
	9600,	/* B9600 */
	19200,	/* B19200 */
	38400,	/* B38400 */
	57600,	/* B57600 */
	76800,	/* B76800 */
	115200,	/* B115200 */
	153600,	/* B153600 */
	230400,	/* B230400 */
};


/* debug support */
static uint_t	keyspan_errlevel = USB_LOG_L4;
static uint_t	keyspan_errmask = DPRINT_MASK_ALL;
static uint_t	keyspan_instance_debug = (uint_t)-1;

static int
keyspan_attach(ds_attach_info_t *aip)
{
	keyspan_state_t	*ksp;
	int	rval = USB_SUCCESS;

	ksp = (keyspan_state_t *)kmem_zalloc(sizeof (keyspan_state_t),
	    KM_SLEEP);
	ksp->ks_dip = aip->ai_dip;
	ksp->ks_usb_events = aip->ai_usb_events;
	*aip->ai_hdl = (ds_hdl_t)ksp;

	if (keyspan_usb_register(ksp) != USB_SUCCESS) {

		goto fail_register;
	}

	/* init mutex and semaphore */
	keyspan_init_sync_objs(ksp);

	/* get device specific parameters */
	if (keyspan_attach_dev(ksp) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh, "fail attach dev ");

		goto fail_attach_dev;
	}

	keyspan_attach_ports(ksp);

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
	case KEYSPAN_USA49WLC_PID:
		rval = keyspan_init_pipes(ksp);

		break;

	case KEYSPAN_USA49WG_PID:
		rval = keyspan_init_pipes_usa49wg(ksp);

		break;

	default:
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh, "keyspan_attach:"
		    "the device's product id can't be recognized");

		return (USB_FAILURE);
	}

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_init_pipes: failed.");

		goto fail_init_pipes;
	}

	keyspan_init_port_params(ksp);
	keyspan_free_descr_tree(ksp);
	keyspan_set_dev_state_online(ksp);

	if (keyspan_create_pm_components(ksp) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_create_pm_components: failed.");

		goto fail_pm;
	}

	if (keyspan_register_events(ksp) != USB_SUCCESS) {

		goto fail_events;
	}

	/* open the global pipes */
	if (keyspan_attach_pipes(ksp) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_attach_pipes: failed.");

		goto fail_attach_pipes;
	}

	*aip->ai_port_cnt = ksp->ks_dev_spec.port_cnt;

	return (USB_SUCCESS);

fail_attach_pipes:
	keyspan_unregister_events(ksp);
fail_events:
	keyspan_destroy_pm_components(ksp);
fail_pm:
	keyspan_fini_pipes(ksp);
fail_init_pipes:
	keyspan_detach_ports(ksp);
fail_attach_dev:
	keyspan_fini_sync_objs(ksp);
	keyspan_usb_unregister(ksp);
fail_register:
	keyspan_free_soft_state(ksp);

	return (USB_FAILURE);
}


/*
 * ds_detach
 */
static void
keyspan_detach(ds_hdl_t hdl)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;

	keyspan_detach_pipes(ksp);
	keyspan_unregister_events(ksp);
	keyspan_destroy_pm_components(ksp);
	keyspan_fini_pipes(ksp);
	keyspan_detach_ports(ksp);
	keyspan_fini_sync_objs(ksp);
	keyspan_usb_unregister(ksp);
	keyspan_free_soft_state(ksp);
}

/*
 * ds_register_cb
 */
static int
keyspan_register_cb(ds_hdl_t hdl, uint_t port_num, ds_cb_t *cb)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp;

	if (port_num >= ksp->ks_dev_spec.port_cnt) {

		return (USB_FAILURE);
	}
	kp = &ksp->ks_ports[port_num];
	kp->kp_cb = *cb;

	return (USB_SUCCESS);
}

/*
 * ds_unregister_cb
 */
static void
keyspan_unregister_cb(ds_hdl_t hdl, uint_t port_num)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp;

	if (port_num < ksp->ks_dev_spec.port_cnt) {
		kp = &ksp->ks_ports[port_num];
		bzero(&kp->kp_cb, sizeof (kp->kp_cb));
	}
}

/*
 * initialize hardware serial port
 *
 * 'open_pipes' specifies whether to open USB pipes or not
 */
int
keyspan_open_hw_port(keyspan_port_t *kp, boolean_t open_pipes)
{
	int		rval;
	keyspan_state_t	*ksp = kp->kp_ksp;

	USB_DPRINTF_L4(DPRINT_OPEN, kp->kp_lh,
	    "keyspan_open_hw_port: [%d]", kp->kp_port_num);

	if (open_pipes) {

		/* open r/w pipes for this port */
		if ((rval = keyspan_open_port_pipes(kp)) != USB_SUCCESS) {

			return (rval);
		}
	}

	mutex_enter(&kp->kp_mutex);
	kp->kp_state = KEYSPAN_PORT_OPEN;
	mutex_exit(&kp->kp_mutex);

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
	case KEYSPAN_USA49WLC_PID:
		if ((rval = keyspan_receive_data(&kp->kp_datain_pipe,
		    kp->kp_read_len, kp)) != USB_SUCCESS) {

				goto fail;
		}

		break;

	case KEYSPAN_USA49WG_PID:
		mutex_enter(&ksp->ks_mutex);
		/* open data in pipe the first time, start receiving data */
		if ((ksp->ks_datain_open_cnt == 1) && open_pipes) {
			mutex_exit(&ksp->ks_mutex);
			if ((rval = keyspan_receive_data(&kp->kp_datain_pipe,
			    kp->kp_read_len, kp)) != USB_SUCCESS) {

					goto fail;
			}
		/* the device is reconnected to host, restart receiving data */
		} else if ((ksp->ks_reconnect_flag) && (!open_pipes)) {
			mutex_exit(&ksp->ks_mutex);
			if ((rval = keyspan_receive_data(&kp->kp_datain_pipe,
			    kp->kp_read_len, kp)) != USB_SUCCESS) {

					goto fail;
			}
			mutex_enter(&ksp->ks_mutex);
			ksp->ks_reconnect_flag = 0;
			mutex_exit(&ksp->ks_mutex);

		} else {
			mutex_exit(&ksp->ks_mutex);
		}

		break;

	default:
		USB_DPRINTF_L2(DPRINT_OPEN, ksp->ks_lh, "keyspan_open_hw_port:"
		    "the device's product id can't be recognized");

		return (USB_FAILURE);
	}

	/* set the default port parameters and send cmd msg to enable port */
	mutex_enter(&kp->kp_mutex);
	keyspan_default_port_params(kp);
	mutex_exit(&kp->kp_mutex);

	(void) keyspan_send_cmd(kp);

	USB_DPRINTF_L4(DPRINT_OPEN, kp->kp_lh,
	    "keyspan_open_hw_port: [%d] finished", kp->kp_port_num);

	return (rval);

fail:

	mutex_enter(&kp->kp_mutex);
	kp->kp_state = KEYSPAN_PORT_CLOSED;
	mutex_exit(&kp->kp_mutex);

	if (open_pipes) {

		/* close all ports' data pipes */
		keyspan_close_port_pipes(kp);
	}

	USB_DPRINTF_L2(DPRINT_OPEN, kp->kp_lh,
	    "keyspan_open_hw_port: failed. This port can't be used.");

	return (rval);
}

/*
 * ds_open_port
 */
static int
keyspan_open_port(ds_hdl_t hdl, uint_t port_num)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];
	int		rval;

	if (port_num >= ksp->ks_dev_spec.port_cnt) {

		return (USB_FAILURE);
	}
	USB_DPRINTF_L4(DPRINT_OPEN, kp->kp_lh, "keyspan_open_port");

	mutex_enter(&ksp->ks_mutex);
	if (ksp->ks_dev_state == USB_DEV_DISCONNECTED) {
		mutex_exit(&ksp->ks_mutex);

		return (USB_FAILURE);
	}
	mutex_exit(&ksp->ks_mutex);

	if (keyspan_pm_set_busy(ksp) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	/*
	 * initialize state
	 */
	mutex_enter(&kp->kp_mutex);
	ASSERT(kp->kp_state == KEYSPAN_PORT_CLOSED);
	ASSERT((kp->kp_rx_mp == NULL) && (kp->kp_tx_mp == NULL));

	kp->kp_state = KEYSPAN_PORT_OPENING;
	kp->kp_flags = 0;
	mutex_exit(&kp->kp_mutex);

	/*
	 * initialize hardware serial port, B_TRUE means open pipes
	 */
	sema_p(&ksp->ks_pipes_sema);
	rval = keyspan_open_hw_port(kp, B_TRUE);
	if (rval != USB_SUCCESS) {
		keyspan_pm_set_idle(ksp);
	}
	sema_v(&ksp->ks_pipes_sema);

	return (rval);
}


/*
 * close hardware serial port
 */
void
keyspan_close_hw_port(keyspan_port_t *kp)
{
	keyspan_state_t	*ksp = kp->kp_ksp;

	ASSERT(!mutex_owned(&kp->kp_mutex));

	USB_DPRINTF_L4(DPRINT_CLOSE, kp->kp_lh,
	    "keyspan_close_hw_port");

	/*
	 * The bulk IN/OUT pipes might have got closed due to
	 * a device disconnect event. So its required to check the
	 * pipe handle and proceed if it is not NULL
	 */

	mutex_enter(&kp->kp_mutex);
	if ((kp->kp_datain_pipe.pipe_handle == NULL) &&
	    (kp->kp_dataout_pipe.pipe_handle == NULL)) {
		mutex_exit(&kp->kp_mutex);

		return;
	}

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		keyspan_build_cmd_msg_usa19hs(kp, NULL);
		kp->kp_ctrl_msg.usa19hs.portEnabled = 0;
		kp->kp_ctrl_msg.usa19hs.rxFlush = 0;
		kp->kp_ctrl_msg.usa19hs.txFlush = 0;
		kp->kp_ctrl_msg.usa19hs.returnStatus = 0;
		kp->kp_ctrl_msg.usa19hs.setRts = 1;
		kp->kp_ctrl_msg.usa19hs.rts = 0;
		kp->kp_ctrl_msg.usa19hs.setDtr = 1;
		kp->kp_ctrl_msg.usa19hs.dtr = 0;
		kp->kp_ctrl_msg.usa19hs.setTxFlowControl = 1;
		kp->kp_ctrl_msg.usa19hs.txFlowControl = 0;
		kp->kp_ctrl_msg.usa19hs.setRxFlowControl = 1;
		kp->kp_ctrl_msg.usa19hs.rxFlowControl = 0;
		kp->kp_ctrl_msg.usa19hs.rxForwardingTimeout = 0;
		kp->kp_ctrl_msg.usa19hs.rxForwardingLength = 0;

		break;


	case KEYSPAN_USA49WLC_PID:
	case KEYSPAN_USA49WG_PID:
		keyspan_build_cmd_msg_usa49(kp, NULL);
		kp->kp_ctrl_msg.usa49._txOn = 0;
		kp->kp_ctrl_msg.usa49._txOff = 1;
		kp->kp_ctrl_msg.usa49.txFlush = 0;
		kp->kp_ctrl_msg.usa49.txBreak = 0;
		kp->kp_ctrl_msg.usa49.rxOn = 0;
		kp->kp_ctrl_msg.usa49.rxOff = 1;
		kp->kp_ctrl_msg.usa49.rxFlush = 0;
		kp->kp_ctrl_msg.usa49.rxForward = 0;
		kp->kp_ctrl_msg.usa49.returnStatus = 0;
		kp->kp_ctrl_msg.usa49.resetDataToggle = 0;
		kp->kp_ctrl_msg.usa49.enablePort = 0;
		kp->kp_ctrl_msg.usa49.disablePort = 1;

		break;

	default:
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_close_hw_port:"
		    "the device's product id can't be recognized");
		mutex_exit(&kp->kp_mutex);

		return;
	}

	mutex_exit(&kp->kp_mutex);
	/* send close port cmd to this port */
	if (keyspan_send_cmd(kp) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh,
		    "keyspan_close_hw_port: closing hw port, send cmd FAILED");
	}

	/* blow away bulkin requests or pipe close will wait until timeout */
	switch (ksp->ks_dev_spec.id_product) {
		case KEYSPAN_USA19HS_PID:
		case KEYSPAN_USA49WLC_PID:
			usb_pipe_reset(ksp->ks_dip,
			    kp->kp_datain_pipe.pipe_handle,
			    USB_FLAGS_SLEEP, NULL, NULL);

			break;
		case KEYSPAN_USA49WG_PID:
			mutex_enter(&ksp->ks_mutex);
			/*
			 * if only this port is opened, shared data in pipe
			 * can be reset.
			 */
			if (ksp->ks_datain_open_cnt == 1) {
				mutex_exit(&ksp->ks_mutex);

				usb_pipe_reset(ksp->ks_dip,
				    kp->kp_datain_pipe.pipe_handle,
				    USB_FLAGS_SLEEP, NULL, NULL);
			} else {
				mutex_exit(&ksp->ks_mutex);
			}

			break;
		default:
			USB_DPRINTF_L2(DPRINT_CLOSE, kp->kp_lh,
			    "keyspan_close_hw_port: the device's"
			    " product id can't be recognized");
	}

	(void) keyspan_close_port_pipes(kp);
}

/*
 * ds_close_port
 */
static int
keyspan_close_port(ds_hdl_t hdl, uint_t port_num)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];

	if (port_num >= ksp->ks_dev_spec.port_cnt) {

		return (USB_FAILURE);
	}
	USB_DPRINTF_L4(DPRINT_CLOSE, kp->kp_lh, "keyspan_close_port");

	sema_p(&ksp->ks_pipes_sema);
	mutex_enter(&kp->kp_mutex);
	kp->kp_no_more_reads = B_TRUE;

	/* close hardware serial port */
	mutex_exit(&kp->kp_mutex);

	keyspan_close_hw_port(kp);
	mutex_enter(&kp->kp_mutex);

	/*
	 * free resources and finalize state
	 */
	if (kp->kp_rx_mp) {
		freemsg(kp->kp_rx_mp);
		kp->kp_rx_mp = NULL;
	}
	if (kp->kp_tx_mp) {
		freemsg(kp->kp_tx_mp);
		kp->kp_tx_mp = NULL;
	}

	kp->kp_no_more_reads = B_FALSE;
	kp->kp_state = KEYSPAN_PORT_CLOSED;
	mutex_exit(&kp->kp_mutex);

	keyspan_pm_set_idle(ksp);

	sema_v(&ksp->ks_pipes_sema);

	return (USB_SUCCESS);
}

/*
 * power management
 *
 * ds_usb_power
 */
/*ARGSUSED*/
static int
keyspan_usb_power(ds_hdl_t hdl, int comp, int level, int *new_state)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_pm_t	*pm = ksp->ks_pm;
	int		rval;

	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_usb_power");

	mutex_enter(&ksp->ks_mutex);

	/*
	 * check if we are transitioning to a legal power level
	 */
	if (USB_DEV_PWRSTATE_OK(pm->pm_pwr_states, level)) {
		USB_DPRINTF_L2(DPRINT_PM, ksp->ks_lh, "keyspan_usb_power:"
		    "illegal power level %d, pwr_states=%x",
		    level, pm->pm_pwr_states);
		mutex_exit(&ksp->ks_mutex);

		return (USB_FAILURE);
	}

	/*
	 * if we are about to raise power and asked to lower power, fail
	 */
	if (pm->pm_raise_power && (level < (int)pm->pm_cur_power)) {
		mutex_exit(&ksp->ks_mutex);

		return (USB_FAILURE);
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		rval = keyspan_pwrlvl0(ksp);

		break;
	case USB_DEV_OS_PWR_1:
		rval = keyspan_pwrlvl1(ksp);

		break;
	case USB_DEV_OS_PWR_2:
		rval = keyspan_pwrlvl2(ksp);

		break;
	case USB_DEV_OS_FULL_PWR:
		rval = keyspan_pwrlvl3(ksp);
		/*
		 * If usbser dev_state is DISCONNECTED or SUSPENDED, it shows
		 * that the usb serial device is disconnected/suspended while it
		 * is under power down state, now the device is powered up
		 * before it is reconnected/resumed. xxx_pwrlvl3() will set dev
		 * state to ONLINE, we need to set the dev state back to
		 * DISCONNECTED/SUSPENDED.
		 */
		if ((rval == USB_SUCCESS) &&
		    ((*new_state == USB_DEV_DISCONNECTED) ||
		    (*new_state == USB_DEV_SUSPENDED))) {
			ksp->ks_dev_state = *new_state;
		}

		break;
	default:
		ASSERT(0);	/* cannot happen */
	}

	*new_state = ksp->ks_dev_state;
	mutex_exit(&ksp->ks_mutex);

	return (rval);
}


/*
 * ds_suspend
 */
static int
keyspan_suspend(ds_hdl_t hdl)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	int		state = USB_DEV_SUSPENDED;

	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_suspend");

	/*
	 * If the device is suspended while it is under PWRED_DOWN state, we
	 * need to keep the PWRED_DOWN state so that it could be powered up
	 * later. In the mean while, usbser dev state will be changed to
	 * SUSPENDED state.
	 */
	mutex_enter(&ksp->ks_mutex);
	if (ksp->ks_dev_state != USB_DEV_PWRED_DOWN) {
		ksp->ks_dev_state = USB_DEV_SUSPENDED;
	}
	mutex_exit(&ksp->ks_mutex);

	keyspan_disconnect_pipes(ksp);

	return (state);
}


/*
 * ds_resume
 */
static int
keyspan_resume(ds_hdl_t hdl)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	int		current_state;
	int		rval;

	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_resume");

	mutex_enter(&ksp->ks_mutex);
	current_state = ksp->ks_dev_state;
	mutex_exit(&ksp->ks_mutex);

	if (current_state != USB_DEV_ONLINE) {
		rval = keyspan_restore_device_state(ksp);
	} else {
		rval = USB_SUCCESS;
	}

	return (rval);
}


/*
 * ds_disconnect
 */
static int
keyspan_disconnect(ds_hdl_t hdl)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	int		state = USB_DEV_DISCONNECTED;

	USB_DPRINTF_L4(DPRINT_HOTPLUG, ksp->ks_lh, "keyspan_disconnect");

	/*
	 * If the device is disconnected while it is under PWRED_DOWN state, we
	 * need to keep the PWRED_DOWN state so that it could be powered up
	 * later. In the mean while, usbser dev state will be changed to
	 * DISCONNECTED state.
	 */
	mutex_enter(&ksp->ks_mutex);
	if (ksp->ks_dev_state != USB_DEV_PWRED_DOWN) {
		ksp->ks_dev_state = USB_DEV_DISCONNECTED;
	}
	mutex_exit(&ksp->ks_mutex);

	keyspan_disconnect_pipes(ksp);

	return (state);
}


/*
 * ds_reconnect
 */
static int
keyspan_reconnect(ds_hdl_t hdl)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_HOTPLUG, ksp->ks_lh, "keyspan_reconnect");

	return (keyspan_restore_device_state(ksp));
}

/*
 * ds_set_port_params
 */
static int
keyspan_set_port_params(ds_hdl_t hdl, uint_t port_num, ds_port_params_t *tp)
{
	int		cnt = tp->tp_cnt;
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_set_port_params: port: %d params", cnt);

	if (cnt <= 0) {

		return (USB_SUCCESS);
	}

	mutex_enter(&kp->kp_mutex);
	ASSERT((kp->kp_state == KEYSPAN_PORT_OPENING) ||
	    (kp->kp_state == KEYSPAN_PORT_OPEN));
	keyspan_build_cmd_msg(kp, tp);
	mutex_exit(&kp->kp_mutex);

	if (keyspan_send_cmd(kp) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_send_cmd() FAILED");

			return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * ds_set_modem_ctl
 */
static int
keyspan_set_modem_ctl(ds_hdl_t hdl, uint_t port_num, int mask, int val)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);

	mutex_enter(&kp->kp_mutex);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh, "keyspan_set_modem_ctl: "
	    "mask=%x, val=%x", mask, val);

	keyspan_build_cmd_msg(kp, NULL);

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		if (mask & TIOCM_RTS) {

			kp->kp_ctrl_msg.usa19hs.setRts = 0x01;

			if (val & TIOCM_RTS) {
				kp->kp_ctrl_msg.usa19hs.rts = 0x1;
			} else {
				kp->kp_ctrl_msg.usa19hs.rts = 0x0;
			}

		} else {
			kp->kp_ctrl_msg.usa19hs.setRts = 0x0;
		}

		if (mask & TIOCM_DTR) {
			kp->kp_ctrl_msg.usa19hs.setDtr = 0x01;

			if (val & TIOCM_DTR) {
				kp->kp_ctrl_msg.usa19hs.dtr = 0x1;
			} else {
				kp->kp_ctrl_msg.usa19hs.dtr = 0x0;
			}

		} else {
			kp->kp_ctrl_msg.usa19hs.setDtr = 0x0;
		}

		break;


	case KEYSPAN_USA49WLC_PID:
	case KEYSPAN_USA49WG_PID:
		if (mask & TIOCM_RTS) {

			kp->kp_ctrl_msg.usa49.setRts = 0x1;

			if (val & TIOCM_RTS) {
				kp->kp_ctrl_msg.usa49.rts = 0x1;
			} else {
				kp->kp_ctrl_msg.usa49.rts = 0x0;
			}

		} else {
			kp->kp_ctrl_msg.usa49.setRts = 0x0;
		}

		if (mask & TIOCM_DTR) {
			kp->kp_ctrl_msg.usa49.setDtr = 0x1;

			if (val & TIOCM_DTR) {
				kp->kp_ctrl_msg.usa49.dtr = 0x1;
			} else {
				kp->kp_ctrl_msg.usa49.dtr = 0x0;
			}

		} else {
			kp->kp_ctrl_msg.usa49.setDtr = 0x0;
		}

		break;

	default:
		USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh,
		    "keyspan_get_modem_ctl:"
		    "the device's product id can't be recognized");
		mutex_exit(&kp->kp_mutex);

		return (USB_FAILURE);
	}

	mutex_exit(&kp->kp_mutex);

	if (keyspan_send_cmd(kp) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_send_cmd() FAILED");

			return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}

/*
 * ds_get_modem_ctl
 */
static int
keyspan_get_modem_ctl(ds_hdl_t hdl, uint_t port_num, int mask, int *valp)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];
	int	val = 0;

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);

	mutex_enter(&kp->kp_mutex);

	/*
	 * rts and dtr are not in status_msg, but we can get it from
	 * status_flag since it represents what we set the device last time.
	 */
	if (kp->kp_status_flag & KEYSPAN_PORT_RTS) {
		val |= TIOCM_RTS;
	}
	if (kp->kp_status_flag & KEYSPAN_PORT_DTR) {
		val |= TIOCM_DTR;
	}

	/* usbser don't deal with TIOCM_RI status */
	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		if (kp->kp_status_msg.usa19hs.dcd) {
			val |= TIOCM_CD;
		}
		if (kp->kp_status_msg.usa19hs.cts) {
			val |= TIOCM_CTS;
		}
		if (kp->kp_status_msg.usa19hs.dsr) {
			val |= TIOCM_DSR;
		}
		break;


	case KEYSPAN_USA49WLC_PID:
	case KEYSPAN_USA49WG_PID:
		if (kp->kp_status_msg.usa49.dcd) {
			val |= TIOCM_CD;
		}
		if (kp->kp_status_msg.usa49.cts) {
			val |= TIOCM_CTS;
		}
		if (kp->kp_status_msg.usa49.dsr) {
			val |= TIOCM_DSR;
		}
		break;

	default:
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_get_modem_ctl:"
		    "the device's product id can't be recognized");
		mutex_exit(&kp->kp_mutex);

		return (USB_FAILURE);
	}

	*valp = val & mask;

	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh, "keyspan_get_modem_ctl:"
	    "success. status_flag = %x, val=0%o",
	    kp->kp_status_flag, *valp);

	mutex_exit(&kp->kp_mutex);

	return (USB_SUCCESS);
}


/*
 * ds_break_ctl
 */
static int
keyspan_break_ctl(ds_hdl_t hdl, uint_t port_num, int ctl)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];
	int		is_break;
	int		rval = USB_SUCCESS;

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_break_ctl: ctl = %s", (ctl == DS_ON) ? "on" : "off");

	mutex_enter(&kp->kp_mutex);
	ASSERT(kp->kp_state == KEYSPAN_PORT_OPEN);
	ASSERT(ctl == DS_ON || ctl == DS_OFF);

	is_break = kp->kp_status_flag & KEYSPAN_PORT_TXBREAK;

	if ((ctl == DS_ON) && !is_break) {

		keyspan_build_cmd_msg(kp, NULL);

		switch (ksp->ks_dev_spec.id_product) {
		case KEYSPAN_USA19HS_PID:
			kp->kp_ctrl_msg.usa19hs.txBreak = 1;

			break;

		case KEYSPAN_USA49WLC_PID:
		case KEYSPAN_USA49WG_PID:
			kp->kp_ctrl_msg.usa49.txBreak = 1;

			break;

		default:
			mutex_exit(&kp->kp_mutex);
			USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_break_ctl:"
			    "the device's product id can't be recognized");

			return (USB_FAILURE);
		}

		mutex_exit(&kp->kp_mutex);
		rval = keyspan_send_cmd(kp);
		return (rval);
	}

	if ((ctl == DS_OFF) && is_break) {
		keyspan_build_cmd_msg(kp, NULL);

		switch (ksp->ks_dev_spec.id_product) {
		case KEYSPAN_USA19HS_PID:
			kp->kp_ctrl_msg.usa19hs.txBreak = 0;

			break;

		case KEYSPAN_USA49WLC_PID:
		case KEYSPAN_USA49WG_PID:
			kp->kp_ctrl_msg.usa49._txOn = 1;
			kp->kp_ctrl_msg.usa49.txBreak = 0;

			break;

		default:
			mutex_exit(&kp->kp_mutex);
			USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_break_ctl:"
			    "the device's product id can't be recognized");

			return (USB_FAILURE);
		}

		mutex_exit(&kp->kp_mutex);
		rval = keyspan_send_cmd(kp);
		if (rval == USB_SUCCESS) {
			mutex_enter(&kp->kp_mutex);

			/* resume transmit */
			keyspan_tx_start(kp, NULL);
			mutex_exit(&kp->kp_mutex);
		}

		return (rval);
	}

	mutex_exit(&kp->kp_mutex);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_break_ctl: not necessary to set break, is_break = %d",
	    is_break);

	return (rval);
}


/*
 * ds_loopback
 */
static int
keyspan_loopback(ds_hdl_t hdl, uint_t port_num, int ctl)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];
	int		is_loop;
	int		rval = USB_SUCCESS;

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_loopback: %s", (ctl == DS_ON) ? "on" : "off");

	mutex_enter(&kp->kp_mutex);
	ASSERT(kp->kp_state == KEYSPAN_PORT_OPEN);
	ASSERT(ctl == DS_ON || ctl == DS_OFF);

	/* check bit indicating internal loopback state */
	is_loop = kp->kp_status_flag & KEYSPAN_PORT_LOOPBACK;

	if ((ctl == DS_ON) && !is_loop) {

		keyspan_build_cmd_msg(kp, NULL);
		switch (ksp->ks_dev_spec.id_product) {
		case KEYSPAN_USA19HS_PID:
			kp->kp_ctrl_msg.usa19hs.loopbackMode = 0;

			break;

		case KEYSPAN_USA49WLC_PID:
		case KEYSPAN_USA49WG_PID:
			kp->kp_ctrl_msg.usa49.loopbackMode = 0;

			break;

		default:
			mutex_exit(&kp->kp_mutex);
			USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_loopback:"
			    "the device's product id can't be recognized");

			return (USB_FAILURE);
		}
		mutex_exit(&kp->kp_mutex);
		rval = keyspan_send_cmd(kp);
	} else if ((ctl == DS_OFF) && is_loop) {

		keyspan_build_cmd_msg(kp, NULL);
		switch (ksp->ks_dev_spec.id_product) {
		case KEYSPAN_USA19HS_PID:
			kp->kp_ctrl_msg.usa19hs.loopbackMode = 1;

			break;

		case KEYSPAN_USA49WLC_PID:
		case KEYSPAN_USA49WG_PID:
			kp->kp_ctrl_msg.usa49.loopbackMode = 1;

			break;

		default:
			mutex_exit(&kp->kp_mutex);
			USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_loopback:"
			    "the device's product id can't be recognized");

			return (USB_FAILURE);
		}
		mutex_exit(&kp->kp_mutex);
		rval = keyspan_send_cmd(kp);
	} else {
		mutex_exit(&kp->kp_mutex);
		USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh,
		    "keyspan_loopback: not necessary to set loopback,"
		    "is_loop = %d", is_loop);
	}

	return (rval);
}


/*
 * ds_tx
 */
static int
keyspan_tx(ds_hdl_t hdl, uint_t port_num, mblk_t *mp)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];
	int		xferd;

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh, "keyspan_tx");

	/*
	 * sanity checks
	 */
	if (mp == NULL) {
		USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh, "keyspan_tx: mp=NULL");

		return (USB_SUCCESS);
	}

	kp = &ksp->ks_ports[port_num];

	mutex_enter(&kp->kp_mutex);

	keyspan_put_tail(&kp->kp_tx_mp, mp);	/* add to the chain */

	keyspan_tx_start(kp, &xferd);		/* go! */

	mutex_exit(&kp->kp_mutex);

	return (USB_SUCCESS);
}


/*
 * ds_rx. the real data receiving is in keyspan_open_hw_port
 */
static mblk_t *
keyspan_rx(ds_hdl_t hdl, uint_t port_num)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];
	mblk_t		*mp;

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh, "keyspan_rx");

	mutex_enter(&kp->kp_mutex);
	mp = kp->kp_rx_mp;
	kp->kp_rx_mp = NULL;
	mutex_exit(&kp->kp_mutex);

	return (mp);
}


/*
 * ds_stop
 */
static void
keyspan_stop(ds_hdl_t hdl, uint_t port_num, int dir)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh, "keyspan_stop");

	if (dir & DS_TX) {
		mutex_enter(&kp->kp_mutex);
		kp->kp_flags |= KEYSPAN_PORT_TX_STOPPED;
		mutex_exit(&kp->kp_mutex);
	}
}


/*
 * ds_start
 */
static void
keyspan_start(ds_hdl_t hdl, uint_t port_num, int dir)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh, "keyspan_start");

	if (dir & DS_TX) {
		mutex_enter(&kp->kp_mutex);
		if (kp->kp_flags & KEYSPAN_PORT_TX_STOPPED) {
			kp->kp_flags &= ~KEYSPAN_PORT_TX_STOPPED;
			keyspan_tx_start(kp, NULL);
		}
		mutex_exit(&kp->kp_mutex);
	}
}


/*
 * ds_fifo_flush
 * send flush cmd and wait for completion, then turn off the flush.
 */
static int
keyspan_fifo_flush(ds_hdl_t hdl, uint_t port_num, int dir)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_fifo_flush: dir=%x", dir);

	mutex_enter(&kp->kp_mutex);
	ASSERT(kp->kp_state == KEYSPAN_PORT_OPEN);

	/* discard the data in DSD buffers */
	if ((dir & DS_TX) && kp->kp_tx_mp) {
		freemsg(kp->kp_tx_mp);
		kp->kp_tx_mp = NULL;
	}
	if ((dir & DS_RX) && kp->kp_rx_mp) {
		freemsg(kp->kp_rx_mp);
		kp->kp_rx_mp = NULL;
	}

	mutex_exit(&kp->kp_mutex);

	return (USB_SUCCESS);
}

/*
 * ds_fifo_drain
 *
 * it is the caller's responsibility to cease submitting new tx data
 * while this function executes
 */
static int
keyspan_fifo_drain(ds_hdl_t hdl, uint_t port_num, int timeout)
{
	keyspan_state_t	*ksp = (keyspan_state_t *)hdl;
	keyspan_port_t	*kp = &ksp->ks_ports[port_num];
	int		rval = USB_SUCCESS;

	ASSERT(port_num < ksp->ks_dev_spec.port_cnt);
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_fifo_drain, timeout = %d", timeout);

	mutex_enter(&kp->kp_mutex);
	ASSERT(kp->kp_state == KEYSPAN_PORT_OPEN);

	/* wait until local data drains */
	if (keyspan_wait_tx_drain(kp, 0) != USB_SUCCESS) {
		mutex_exit(&kp->kp_mutex);

		return (USB_FAILURE);
	}
	mutex_exit(&kp->kp_mutex);

	/* wait until hw fifo drains */
	delay(drv_usectohz(500*1000));

	return (rval);
}


/*
 * configuration routines
 * ----------------------
 *
 */

/*
 * free state structure
 */
static void
keyspan_free_soft_state(keyspan_state_t *ksp)
{
	kmem_free(ksp, sizeof (keyspan_state_t));
}


/*
 * register/unregister USBA client
 */
static int
keyspan_usb_register(keyspan_state_t *ksp)
{
	int	rval;

	rval = usb_client_attach(ksp->ks_dip, USBDRV_VERSION, 0);
	if (rval == USB_SUCCESS) {
		rval = usb_get_dev_data(ksp->ks_dip, &ksp->ks_dev_data,
		    USB_PARSE_LVL_IF, 0);
		if (rval == USB_SUCCESS) {
			ksp->ks_lh =
			    usb_alloc_log_hdl(ksp->ks_dip, "keyspan[*].",
			    &keyspan_errlevel, &keyspan_errmask,
			    &keyspan_instance_debug, 0);

			ksp->ks_def_pipe.pipe_handle =
			    ksp->ks_dev_data->dev_default_ph;
			ksp->ks_def_pipe.pipe_ksp = ksp;
			ksp->ks_def_pipe.pipe_lh = ksp->ks_lh;
		}
	}

	return (rval);
}


static void
keyspan_usb_unregister(keyspan_state_t *ksp)
{
	usb_free_log_hdl(ksp->ks_lh);
	ksp->ks_lh = NULL;
	usb_client_detach(ksp->ks_dip, ksp->ks_dev_data);
	ksp->ks_def_pipe.pipe_handle = NULL;
	ksp->ks_dev_data = NULL;
}


/*
 * init/fini soft state during attach
 */
static void
keyspan_init_sync_objs(keyspan_state_t *ksp)
{
	mutex_init(&ksp->ks_mutex, NULL, MUTEX_DRIVER,
	    ksp->ks_dev_data->dev_iblock_cookie);
	sema_init(&ksp->ks_pipes_sema, 1, NULL, SEMA_DRIVER, NULL);
}


static void
keyspan_fini_sync_objs(keyspan_state_t *ksp)
{
	mutex_destroy(&ksp->ks_mutex);
	sema_destroy(&ksp->ks_pipes_sema);
}


/*
 * device specific attributes
 */
static int
keyspan_attach_dev(keyspan_state_t *ksp)
{

	mutex_enter(&ksp->ks_mutex);
	switch (ksp->ks_dev_data->dev_descr->idProduct) {
	case KEYSPAN_USA19HS_PID:
		ksp->ks_dev_spec.id_product = KEYSPAN_USA19HS_PID;
		ksp->ks_dev_spec.port_cnt = 1;
		ksp->ks_dev_spec.ctrl_ep_addr = 0x02;
		ksp->ks_dev_spec.stat_ep_addr = 0x82;
		ksp->ks_dev_spec.dataout_ep_addr[0] = 0x01;
		ksp->ks_dev_spec.datain_ep_addr[0] = 0x81;

		break;

	case KEYSPAN_USA49WLC_PID:
		ksp->ks_dev_spec.id_product = KEYSPAN_USA49WLC_PID;
		ksp->ks_dev_spec.port_cnt = 4;
		ksp->ks_dev_spec.ctrl_ep_addr = 0x07;
		ksp->ks_dev_spec.stat_ep_addr = 0x87;
		ksp->ks_dev_spec.dataout_ep_addr[0] = 0x01;
		ksp->ks_dev_spec.dataout_ep_addr[1] = 0x02;
		ksp->ks_dev_spec.dataout_ep_addr[2] = 0x03;
		ksp->ks_dev_spec.dataout_ep_addr[3] = 0x04;
		ksp->ks_dev_spec.datain_ep_addr[0] = 0x81;
		ksp->ks_dev_spec.datain_ep_addr[1] = 0x82;
		ksp->ks_dev_spec.datain_ep_addr[2] = 0x83;
		ksp->ks_dev_spec.datain_ep_addr[3] = 0x84;

		break;

	case KEYSPAN_USA49WG_PID:
		ksp->ks_dev_spec.id_product = KEYSPAN_USA49WG_PID;
		ksp->ks_dev_spec.port_cnt = 4;
		ksp->ks_dev_spec.stat_ep_addr = 0x81;
		ksp->ks_dev_spec.dataout_ep_addr[0] = 0x01;
		ksp->ks_dev_spec.dataout_ep_addr[1] = 0x02;
		ksp->ks_dev_spec.dataout_ep_addr[2] = 0x04;
		ksp->ks_dev_spec.dataout_ep_addr[3] = 0x06;
		ksp->ks_dev_spec.datain_ep_addr[0] = 0x88;
		ksp->ks_dev_spec.datain_ep_addr[1] = 0x88;
		ksp->ks_dev_spec.datain_ep_addr[2] = 0x88;
		ksp->ks_dev_spec.datain_ep_addr[3] = 0x88;

		break;

	default:
		mutex_exit(&ksp->ks_mutex);
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_attach_dev:"
		    "the device's product id can't be recognized");

		return (USB_FAILURE);
	}

	mutex_exit(&ksp->ks_mutex);

	return (USB_SUCCESS);
}

/*
 * allocate and initialize per port resources.
 */
static void
keyspan_attach_ports(keyspan_state_t *ksp)
{
	int		i;
	keyspan_port_t	*kp;

	ksp->ks_ports = kmem_zalloc(ksp->ks_dev_spec.port_cnt *
	    sizeof (keyspan_port_t), KM_SLEEP);

	for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
		kp = &ksp->ks_ports[i];
		kp->kp_port_num = i;
		kp->kp_ksp = ksp;

		(void) sprintf(kp->kp_lh_name, "keyspan[%d].", i);
		kp->kp_lh = usb_alloc_log_hdl(ksp->ks_dip, kp->kp_lh_name,
		    &keyspan_errlevel, &keyspan_errmask,
		    &keyspan_instance_debug, 0);

		kp->kp_state = KEYSPAN_PORT_CLOSED;
		mutex_init(&kp->kp_mutex, NULL, MUTEX_DRIVER,
		    ksp->ks_dev_data->dev_iblock_cookie);
		cv_init(&kp->kp_tx_cv, NULL, CV_DRIVER, NULL);
	}
}


/*
 * free per port resources
 */
static void
keyspan_detach_ports(keyspan_state_t *ksp)
{
	int		i;
	keyspan_port_t	*kp;

	for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
		kp = &ksp->ks_ports[i];
		if (kp->kp_state != KEYSPAN_PORT_NOT_INIT) {
			ASSERT(kp->kp_state == KEYSPAN_PORT_CLOSED);

			mutex_destroy(&kp->kp_mutex);
			cv_destroy(&kp->kp_tx_cv);
			usb_free_log_hdl(kp->kp_lh);
		}
	}
	kmem_free(ksp->ks_ports,
	    ksp->ks_dev_spec.port_cnt * sizeof (keyspan_port_t));
}

static void
keyspan_init_port_params(keyspan_state_t *ksp)
{
	int		i;
	size_t		sz;
	uint_t		read_len;
	uint_t		write_len;

	/* the max data len of every bulk in req. */
	if (usb_pipe_get_max_bulk_transfer_size(ksp->ks_dip, &sz) ==
	    USB_SUCCESS) {
		if (ksp->ks_dev_spec.id_product == KEYSPAN_USA49WG_PID) {
			read_len = min(sz, KEYSPAN_BULKIN_MAX_LEN_49WG);
		} else {
			read_len = min(sz, KEYSPAN_BULKIN_MAX_LEN);
		}
	} else {
		if (ksp->ks_dev_spec.id_product == KEYSPAN_USA49WG_PID) {
			read_len = KEYSPAN_BULKIN_MAX_LEN_49WG;
		} else {
			read_len = KEYSPAN_BULKIN_MAX_LEN;
		}
	}

	for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
		ksp->ks_ports[i].kp_read_len = read_len;
		/* the max data len of every bulk out req. */
		switch (ksp->ks_dev_spec.id_product) {
		case KEYSPAN_USA19HS_PID:
			ksp->ks_ports[i].kp_write_len =
			    KEYSPAN_BULKOUT_MAX_LEN_19HS;

			break;
		case KEYSPAN_USA49WLC_PID:
			ksp->ks_ports[i].kp_write_len =
			    KEYSPAN_BULKOUT_MAX_LEN_49WLC;

			break;
		case KEYSPAN_USA49WG_PID:
			/*
			 * USA49WG port0 uses intr out pipe send data while
			 * other ports use bulk out pipes, so port0's max
			 * packet length for "bulk out" is different from other
			 * ports' while the same as USA49WLC.
			 */
			write_len = ((i == 0) ? KEYSPAN_BULKOUT_MAX_LEN_49WLC :
			    KEYSPAN_BULKOUT_MAX_LEN_49WG);
			ksp->ks_ports[i].kp_write_len = write_len;

			break;
		default:
			USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
			    "keyspan_init_port_params:"
			    "the device's product id can't be recognized");

			return;
		}
	}
}


/*
 * free descriptor tree
 */
static void
keyspan_free_descr_tree(keyspan_state_t *ksp)
{
	usb_free_descr_tree(ksp->ks_dip, ksp->ks_dev_data);

}


/*
 * register/unregister USB event callbacks
 */
static int
keyspan_register_events(keyspan_state_t *ksp)
{
	return (usb_register_event_cbs(ksp->ks_dip, ksp->ks_usb_events, 0));
}


static void
keyspan_unregister_events(keyspan_state_t *ksp)
{
	usb_unregister_event_cbs(ksp->ks_dip, ksp->ks_usb_events);
}


static void
keyspan_set_dev_state_online(keyspan_state_t *ksp)
{
	ksp->ks_dev_state = USB_DEV_ONLINE;
}

/*
 * send command to the port and save the params after its completion for
 * USA19HS and USA49WLC
 */
int
keyspan_send_cmd_usa49(keyspan_port_t *kp)
{
	keyspan_state_t	*ksp = kp->kp_ksp;
	mblk_t		*mp;
	int		rval = USB_SUCCESS;
	int	size;
	usb_bulk_req_t	*br;

	ASSERT(!mutex_owned(&kp->kp_mutex));
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh, "keyspan_send_cmd_usa49");

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		size = sizeof (keyspan_usa19hs_port_ctrl_msg_t);

		break;


	case KEYSPAN_USA49WLC_PID:
		size = sizeof (keyspan_usa49_port_ctrl_msg_t);

		break;

	default:
		USB_DPRINTF_L2(DPRINT_CTLOP, ksp->ks_lh,
		    "keyspan_send_cmd_usa49:"
		    "the device's product id can't be recognized");
		return (USB_FAILURE);
	}

	if ((mp = allocb(size, BPRI_LO)) == NULL) {

		return (USB_FAILURE);
	}
	bcopy(&kp->kp_ctrl_msg, mp->b_rptr, size);

	br = usb_alloc_bulk_req(ksp->ks_dip, 0, USB_FLAGS_SLEEP);
	br->bulk_len = size;
	br->bulk_data = mp;
	br->bulk_timeout = KEYSPAN_BULK_TIMEOUT;
	br->bulk_client_private = (void *)kp;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING;

	rval = usb_pipe_bulk_xfer(ksp->ks_ctrlout_pipe.pipe_handle, br,
	    USB_FLAGS_SLEEP);
	if (rval == USB_SUCCESS) {
		mutex_enter(&kp->kp_mutex);
		keyspan_save_port_params(kp);
		mutex_exit(&kp->kp_mutex);
	} else {
		USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh, "keyspan_send_cmd_usa49"
		    ": failure, rval=%d", rval);
	}

	usb_free_bulk_req(br);

	return (rval);
}

/*
 * send command to the port and save the params after its completion for
 * USA_49WG only
 */
int
keyspan_send_cmd_usa49wg(keyspan_port_t *kp)
{
	keyspan_state_t	*ksp = kp->kp_ksp;
	mblk_t		*mp;
	int		rval = USB_SUCCESS;
	int		size = sizeof (keyspan_usa49_port_ctrl_msg_t);
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	usb_ctrl_setup_t setup;

	ASSERT(!mutex_owned(&kp->kp_mutex));
	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh, "keyspan_send_cmd_usa49wg");

	if ((mp = allocb(size, BPRI_LO)) == NULL) {

		return (USB_FAILURE);
	}
	bcopy(&kp->kp_ctrl_msg, mp->b_rptr, size);

	setup.bmRequestType = USB_DEV_REQ_TYPE_VENDOR;
	setup.bRequest = KEYSPAN_SET_CONTROL_REQUEST;
	setup.wValue = 0;
	setup.wIndex = 0;
	setup.wLength = size;
	setup.attrs = 0;

	rval = usb_pipe_ctrl_xfer_wait(ksp->ks_def_pipe.pipe_handle, &setup,
	    &mp, &cr, &cb_flags, 0);

	if (rval == USB_SUCCESS) {
		mutex_enter(&kp->kp_mutex);
		keyspan_save_port_params(kp);
		mutex_exit(&kp->kp_mutex);
	} else {
		USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh,
		    "keyspan_send_cmd_usa49wg: failure, rval=%d", rval);
	}
	if (mp) {
		freemsg(mp);
	}

	return (rval);
}

/*
 * send command to the port and save the params after its completion
 */
int
keyspan_send_cmd(keyspan_port_t *kp)
{
	keyspan_state_t	*ksp = kp->kp_ksp;
	int		rval = USB_FAILURE;

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
	case KEYSPAN_USA49WLC_PID:
		rval = keyspan_send_cmd_usa49(kp);

		break;
	case KEYSPAN_USA49WG_PID:
		rval = keyspan_send_cmd_usa49wg(kp);

		break;
	default:
		USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh,
		    "keyspan_send_cmd: "
		    "the device's product id can't be recognized");
	}

	if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_send_cmd() FAILED");

			return (rval);
	}

	return (USB_SUCCESS);

}

/*
 * hotplug
 * -------
 *
 * restore device state after CPR resume or reconnect
 */
static int
keyspan_restore_device_state(keyspan_state_t *ksp)
{
	int	state;

	mutex_enter(&ksp->ks_mutex);
	state = ksp->ks_dev_state;
	mutex_exit(&ksp->ks_mutex);

	if ((state != USB_DEV_DISCONNECTED) && (state != USB_DEV_SUSPENDED)) {

		return (state);
	}

	if (usb_check_same_device(ksp->ks_dip, ksp->ks_lh, USB_LOG_L0,
	    DPRINT_MASK_ALL, USB_CHK_ALL, NULL) != USB_SUCCESS) {
		mutex_enter(&ksp->ks_mutex);
		state = ksp->ks_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&ksp->ks_mutex);

		return (state);
	}

	if (state == USB_DEV_DISCONNECTED) {
		USB_DPRINTF_L0(DPRINT_HOTPLUG, ksp->ks_lh,
		    "device has been reconnected but data may have been lost");
	}

	if (keyspan_reconnect_pipes(ksp) != USB_SUCCESS) {

		return (state);
	}

	/*
	 * init device state
	 */
	mutex_enter(&ksp->ks_mutex);
	state = ksp->ks_dev_state = USB_DEV_ONLINE;
	ksp->ks_reconnect_flag = 1;
	mutex_exit(&ksp->ks_mutex);

	/*
	 * now restore each open port
	 */
	(void) keyspan_restore_ports_state(ksp);

	return (state);
}

/*
 * restore ports state after CPR resume or reconnect
 */
static int
keyspan_restore_ports_state(keyspan_state_t *ksp)
{
	keyspan_port_t	*kp;
	int		rval = USB_SUCCESS;
	int		err;
	int		i;

	for (i = 0; i < ksp->ks_dev_spec.port_cnt; i++) {
		kp = &ksp->ks_ports[i];
		/*
		 * only care about open ports
		 */
		mutex_enter(&kp->kp_mutex);
		if (kp->kp_state != KEYSPAN_PORT_OPEN) {
			mutex_exit(&kp->kp_mutex);
			continue;
		}
		mutex_exit(&kp->kp_mutex);

		sema_p(&ksp->ks_pipes_sema);
		/* open hardware serial port */
		err = keyspan_open_hw_port(kp, B_FALSE);
		sema_v(&ksp->ks_pipes_sema);
		if (err != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_HOTPLUG, kp->kp_lh,
			    "keyspan_restore_ports_state: failed");
			rval = err;
		}
	}

	return (rval);
}


/*
 * power management
 * ----------------
 *
 *
 * create PM components
 */
static int
keyspan_create_pm_components(keyspan_state_t *ksp)
{
	dev_info_t	*dip = ksp->ks_dip;
	keyspan_pm_t	*pm;
	uint_t		pwr_states;

	pm = ksp->ks_pm = kmem_zalloc(sizeof (keyspan_pm_t), KM_SLEEP);
	pm->pm_cur_power = USB_DEV_OS_FULL_PWR;

	if (usb_create_pm_components(dip, &pwr_states) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_PM, ksp->ks_lh,
		    "keyspan_create_pm_components: failed");

		return (USB_SUCCESS);
	}

	pm->pm_wakeup_enabled = (usb_handle_remote_wakeup(dip,
	    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS);
	pm->pm_pwr_states = (uint8_t)pwr_states;

	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	return (USB_SUCCESS);
}


/*
 * destroy PM components
 */
static void
keyspan_destroy_pm_components(keyspan_state_t *ksp)
{
	keyspan_pm_t	*pm = ksp->ks_pm;
	dev_info_t	*dip = ksp->ks_dip;
	int		rval;

	if (ksp->ks_dev_state != USB_DEV_DISCONNECTED) {
		if (pm->pm_wakeup_enabled) {
			(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

			rval = usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE);
			if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_PM, ksp->ks_lh,
				    "keyspan_destroy_pm_components: disable "
				    "remote wakeup failed, rval=%d", rval);
			}
		}

		(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);
	}
	kmem_free(pm, sizeof (keyspan_pm_t));
	ksp->ks_pm = NULL;
}


/*
 * mark device busy and raise power
 */
static int
keyspan_pm_set_busy(keyspan_state_t *ksp)
{
	keyspan_pm_t	*pm = ksp->ks_pm;
	dev_info_t	*dip = ksp->ks_dip;

	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_pm_set_busy");

	mutex_enter(&ksp->ks_mutex);
	/* if already marked busy, just increment the counter */
	if (pm->pm_busy_cnt++ > 0) {
		USB_DPRINTF_L3(DPRINT_PM, ksp->ks_lh, "keyspan_pm_set_busy:"
		    "already busy, busy_cnt = %d", pm->pm_busy_cnt);
		mutex_exit(&ksp->ks_mutex);

		return (USB_SUCCESS);
	}

	(void) pm_busy_component(dip, 0);

	if (pm->pm_cur_power == USB_DEV_OS_FULL_PWR) {
		mutex_exit(&ksp->ks_mutex);

		return (USB_SUCCESS);
	}

	/* need to raise power	*/
	pm->pm_raise_power = B_TRUE;
	mutex_exit(&ksp->ks_mutex);

	USB_DPRINTF_L3(DPRINT_PM, ksp->ks_lh,
	    "keyspan_pm_set_busy: raise power");
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	mutex_enter(&ksp->ks_mutex);
	pm->pm_raise_power = B_FALSE;
	mutex_exit(&ksp->ks_mutex);

	return (USB_SUCCESS);
}


/*
 * mark device idle
 */
static void
keyspan_pm_set_idle(keyspan_state_t *ksp)
{
	keyspan_pm_t	*pm = ksp->ks_pm;
	dev_info_t	*dip = ksp->ks_dip;

	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_pm_set_idle");

	/*
	 * if more ports use the device, do not mark as yet
	 */
	mutex_enter(&ksp->ks_mutex);
	if (--pm->pm_busy_cnt > 0) {
		mutex_exit(&ksp->ks_mutex);

		return;
	}

	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_pm_set_idle: set idle");
	(void) pm_idle_component(dip, 0);

	mutex_exit(&ksp->ks_mutex);
}


/*
 * Functions to handle power transition for OS levels 0 -> 3
 */
static int
keyspan_pwrlvl0(keyspan_state_t *ksp)
{
	int	rval;
	keyspan_pipe_t *statin = &ksp->ks_statin_pipe;

	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_pwrlvl0");

	switch (ksp->ks_dev_state) {
	case USB_DEV_ONLINE:
		/* issue USB D3 command to the device */
		rval = usb_set_device_pwrlvl3(ksp->ks_dip);
		ASSERT(rval == USB_SUCCESS);

		if (ksp->ks_dev_spec.id_product == KEYSPAN_USA49WG_PID) {
			mutex_exit(&ksp->ks_mutex);
			usb_pipe_stop_intr_polling(statin->pipe_handle,
			    USB_FLAGS_SLEEP);
			mutex_enter(&ksp->ks_mutex);

			mutex_enter(&statin->pipe_mutex);
			statin->pipe_state = KEYSPAN_PIPE_CLOSED;
			mutex_exit(&statin->pipe_mutex);
		}
		ksp->ks_dev_state = USB_DEV_PWRED_DOWN;
		ksp->ks_pm->pm_cur_power = USB_DEV_OS_PWR_OFF;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnect/cpr'ed device to go to lower power */

		return (USB_SUCCESS);
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(DPRINT_PM, ksp->ks_lh,
		    "keyspan_pwrlvl0: illegal device state");

		return (USB_FAILURE);
	}
}


static int
keyspan_pwrlvl1(keyspan_state_t *ksp)
{
	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_pwrlvl1");

	/* issue USB D2 command to the device */
	(void) usb_set_device_pwrlvl2(ksp->ks_dip);

	return (USB_FAILURE);
}


static int
keyspan_pwrlvl2(keyspan_state_t *ksp)
{
	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_pwrlvl2");

	/* issue USB D1 command to the device */
	(void) usb_set_device_pwrlvl1(ksp->ks_dip);

	return (USB_FAILURE);
}


static int
keyspan_pwrlvl3(keyspan_state_t *ksp)
{
	int	rval;

	USB_DPRINTF_L4(DPRINT_PM, ksp->ks_lh, "keyspan_pwrlvl3");

	switch (ksp->ks_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(ksp->ks_dip);
		ASSERT(rval == USB_SUCCESS);

		if (ksp->ks_dev_spec.id_product == KEYSPAN_USA49WG_PID) {
			mutex_exit(&ksp->ks_mutex);
			keyspan_pipe_start_polling(&ksp->ks_statin_pipe);
			mutex_enter(&ksp->ks_mutex);
		}

		ksp->ks_dev_state = USB_DEV_ONLINE;
		ksp->ks_pm->pm_cur_power = USB_DEV_OS_FULL_PWR;

		/* FALLTHRU */
	case USB_DEV_ONLINE:
		/* we are already in full power */

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(DPRINT_PM, ksp->ks_lh,
		    "keyspan_pwrlvl3: illegal device state");

		return (USB_FAILURE);
	}
}


/*
 * pipe operations
 * ---------------
 *
 * XXX keyspan seem to malfunction after the pipes are closed
 * and reopened again (does not respond to OPEN_PORT command).
 * so we open them once in attach
 */
static int
keyspan_attach_pipes(keyspan_state_t *ksp)
{
	return (keyspan_open_dev_pipes(ksp));
}

void
keyspan_detach_pipes(keyspan_state_t *ksp)
{

	/*
	 * Blow away status bulk in requests or
	 * pipe close will wait until timeout.
	 */
	if (ksp->ks_statin_pipe.pipe_handle) {
		usb_pipe_stop_intr_polling(ksp->ks_statin_pipe.pipe_handle,
		    USB_FLAGS_SLEEP);
	}

	/* Close the globle pipes */
	keyspan_close_dev_pipes(ksp);
}


/*
 * during device disconnect/suspend, close pipes if they are open.
 */
static void
keyspan_disconnect_pipes(keyspan_state_t *ksp)
{
	sema_p(&ksp->ks_pipes_sema);
	keyspan_close_pipes(ksp);
	sema_v(&ksp->ks_pipes_sema);
}


/*
 * during device reconnect/resume, reopen pipes if they were open.
 */
static int
keyspan_reconnect_pipes(keyspan_state_t *ksp)
{
	int	rval = USB_SUCCESS;

	sema_p(&ksp->ks_pipes_sema);
	rval = keyspan_reopen_pipes(ksp);
	sema_v(&ksp->ks_pipes_sema);

	return (rval);
}

/*
 * data transfer routines
 * ----------------------
 *
 *
 * start data transmit
 */
void
keyspan_tx_start(keyspan_port_t *kp, int *xferd)
{
	keyspan_state_t	*ksp = kp->kp_ksp;
	int		len;		/* # of bytes we can transmit */
	mblk_t		*data;		/* data to be transmitted */
	int		data_len = 0;	/* # of bytes in 'data' */
	int		tran_len;
	int		rval;
	int		status_len = 0;

	ASSERT(!mutex_owned(&ksp->ks_mutex));
	ASSERT(mutex_owned(&kp->kp_mutex));
	ASSERT(kp->kp_state != KEYSPAN_PORT_CLOSED);

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, kp->kp_lh, "keyspan_tx_start");

	if (xferd) {
		*xferd = 0;
	}
	if ((kp->kp_flags & KEYSPAN_PORT_TX_STOPPED) ||
	    (kp->kp_tx_mp == NULL)) {

		return;
	}

	len = min(msgdsize(kp->kp_tx_mp), kp->kp_write_len);
	USB_DPRINTF_L4(DPRINT_OUT_PIPE, kp->kp_lh, "keyspan_tx_start:"
	    "len = %d, tx_mp_len = %d", len, (int)msgdsize(kp->kp_tx_mp));

	mutex_exit(&kp->kp_mutex);

	/*
	 * Some keyspan adapters, such as usa49wlc,
	 * need use the first byte as flag.
	 */
	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:

		if ((data = allocb(len, BPRI_LO)) == NULL) {
			mutex_enter(&kp->kp_mutex);

			return;
		}
		mutex_enter(&kp->kp_mutex);

		/* copy at most 'len' bytes from mblk chain for transmission */
		data_len = keyspan_tx_copy_data(kp, data, len);
		if (data_len <= 0) {
			USB_DPRINTF_L3(DPRINT_OUT_PIPE, kp->kp_lh,
			    "keyspan_tx_start:keyspan_tx_copy_data copied"
			    " zero bytes");
		}

		break;

	case KEYSPAN_USA49WLC_PID:
	case KEYSPAN_USA49WG_PID:
		status_len = len / 64 + 1;
		if ((data = allocb(len + status_len, BPRI_LO)) == NULL) {
			mutex_enter(&kp->kp_mutex);

			return;
		}
		mutex_enter(&kp->kp_mutex);
		/*
		 * the data format is [status byte][63 data bytes][...][status]
		 * byte][up to 63 bytes] according to keyspan spec
		 */
		while (data_len < len) {
			/* Add status byte per 63 data bytes */
			*(data->b_wptr++) = 0;
			/* copy at most 63 bytes from mblk chain for trans */
			tran_len = keyspan_tx_copy_data(kp, data, 63);
			if (tran_len <= 0) {
				USB_DPRINTF_L3(DPRINT_OUT_PIPE, kp->kp_lh,
				    "keyspan_tx_start:keyspan_tx_copy_data"
				    " copied zero bytes");

				break;
			}
			data_len += tran_len;
		}

		break;
	default:

		mutex_enter(&kp->kp_mutex);
		USB_DPRINTF_L2(DPRINT_OUT_PIPE, ksp->ks_lh, "keyspan_tx_start:"
		    "the device's product id can't be recognized");

		return;
	}

	mutex_exit(&kp->kp_mutex);

	/*
	 * For USA-49WG, the port0 uses intr out pipe as data out pipe, while
	 * other ports use bulk out pipe.
	 */

	if ((kp->kp_port_num == 0) &&
	    (ksp->ks_dev_spec.id_product == KEYSPAN_USA49WG_PID)) {
		rval = keyspan_send_data_port0(&kp->kp_dataout_pipe, &data, kp);
	} else {
		rval = keyspan_send_data(&kp->kp_dataout_pipe, &data, kp);
	}
	mutex_enter(&kp->kp_mutex);

	/*
	 * if send failed, put data back
	 */
	if (rval != USB_SUCCESS) {
		ASSERT(data);
		keyspan_put_head(&kp->kp_tx_mp, data, kp);
	} else if (xferd) {
		*xferd = data_len;
	}

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, kp->kp_lh, "keyspan_tx_start[%d]: over"
	    "(%d) rval=%d", kp->kp_port_num, data_len, rval);

}


/*
 * copy no more than 'len' bytes from mblk chain to transmit mblk 'data'.
 * return number of bytes copied
 */
int
keyspan_tx_copy_data(keyspan_port_t *kp, mblk_t *data, int len)
{
	mblk_t		*mp;	/* current msgblk */
	int		copylen; /* # of bytes to copy from 'mp' to 'data' */
	int		data_len = 0;

	ASSERT(mutex_owned(&kp->kp_mutex));

	if (msgdsize(kp->kp_tx_mp) == 0) {
		data->b_wptr = data->b_rptr;
		freeb(kp->kp_tx_mp);
		kp->kp_tx_mp = NULL;

		return (data_len);
	}

	while ((data_len < len) && kp->kp_tx_mp) {
		mp = kp->kp_tx_mp;
		copylen = min(MBLKL(mp), len - data_len);
		bcopy(mp->b_rptr, data->b_wptr, copylen);

		mp->b_rptr += copylen;
		data->b_wptr += copylen;
		data_len += copylen;

		if (MBLKL(mp) < 1) {
			kp->kp_tx_mp = unlinkb(mp);
			freeb(mp);
		} else {
			ASSERT(data_len == len);
		}
	}
	USB_DPRINTF_L3(DPRINT_OUT_DATA, kp->kp_lh, "keyspan_tx_copy_data:"
	    "copied data_len = %d", data_len);

	return (data_len);
}


/*
 * wait until local tx buffer drains.
 * 'timeout' is in seconds, zero means wait forever
 */
static int
keyspan_wait_tx_drain(keyspan_port_t *kp, int timeout)
{
	clock_t	until;
	int	over = 0;

	USB_DPRINTF_L4(DPRINT_OUT_DATA, kp->kp_lh, "keyspan_wait_tx_drain:"
	    "timeout = %d", timeout);
	until = ddi_get_lbolt() + drv_usectohz(1000000 * timeout);

	while (kp->kp_tx_mp && !over) {
		if (timeout > 0) {
			over = (cv_timedwait_sig(&kp->kp_tx_cv,
			    &kp->kp_mutex, until) <= 0);
		} else {
			over = (cv_wait_sig(&kp->kp_tx_cv, &kp->kp_mutex) == 0);
		}
	}

	return ((kp->kp_tx_mp == NULL) ? USB_SUCCESS : USB_FAILURE);
}

/*
 * returns 0 if device is not online, != 0 otherwise
 */
int
keyspan_dev_is_online(keyspan_state_t *ksp)
{
	int	rval;

	mutex_enter(&ksp->ks_mutex);
	rval = (ksp->ks_dev_state == USB_DEV_ONLINE);
	mutex_exit(&ksp->ks_mutex);

	return (rval);
}

/*
 * link a message block to tail of message
 * account for the case when message is null
 */
void
keyspan_put_tail(mblk_t **mpp, mblk_t *bp)
{
	if (*mpp) {
		linkb(*mpp, bp);
	} else {
		*mpp = bp;
	}
}

/*
 * put a message block at the head of the message
 * account for the case when message is null
 */
void
keyspan_put_head(mblk_t **mpp, mblk_t *bp, keyspan_port_t *kp)
{
	switch (kp->kp_ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		if (*mpp) {
			linkb(bp, *mpp);
		}
		*mpp = bp;

		break;


	case KEYSPAN_USA49WLC_PID:
	case KEYSPAN_USA49WG_PID:

		/* get rid of the first byte of the msg data which is a flag */
		if (*mpp) {
			linkb(bp, *mpp);
		}
		bp->b_rptr = bp->b_datap->db_base + 1;
		*mpp = bp;

		break;

	default:
		USB_DPRINTF_L2(DPRINT_OUT_DATA, kp->kp_lh, "keyspan_put_head:"
		    "the device's product id can't be recognized");

		return;
	}

}

/*
 * Set the port parameters to default values
 */
static void
keyspan_default_port_params(keyspan_port_t *kp)
{
	keyspan_state_t	*ksp = kp->kp_ksp;

	ASSERT(mutex_owned(&kp->kp_mutex));

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		keyspan_default_port_params_usa19hs(kp);

		break;


	case KEYSPAN_USA49WLC_PID:
	case KEYSPAN_USA49WG_PID:
		keyspan_default_port_params_usa49(kp);

		break;

	default:
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_default_port_params:"
		    "the device's product id can't be recognized");
	}

	USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_default_port_params: setted.");
}

/*
 * Build the command message according to the params from usbser.
 * The message will then be sent to deivce by keyspan_send_cmd.
 */
static void
keyspan_build_cmd_msg(keyspan_port_t *kp, ds_port_params_t *tp)
{
	keyspan_state_t	*ksp = kp->kp_ksp;

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		keyspan_build_cmd_msg_usa19hs(kp, tp);

		break;


	case KEYSPAN_USA49WLC_PID:
	case KEYSPAN_USA49WG_PID:
		keyspan_build_cmd_msg_usa49(kp, tp);

		break;

	default:
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_build_cmd_msg:"
		    "the device's product id can't be recognized");
	}
}

/* save the port params after send cmd successfully */
static void
keyspan_save_port_params(keyspan_port_t	*kp)
{
	keyspan_state_t	*ksp = kp->kp_ksp;

	ASSERT(mutex_owned(&kp->kp_mutex));

	switch (ksp->ks_dev_spec.id_product) {
	case KEYSPAN_USA19HS_PID:
		keyspan_save_port_params_usa19hs(kp);

		break;


	case KEYSPAN_USA49WLC_PID:
	case KEYSPAN_USA49WG_PID:
		keyspan_save_port_params_usa49(kp);

		break;

	default:
		USB_DPRINTF_L2(DPRINT_ATTACH, ksp->ks_lh,
		    "keyspan_save_port_params:"
		    "the device's product id can't be recognized");
	}

	USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_save_port_params: baud = %x, lcr = %x,"
	    "status_flag = %x", kp->kp_baud, kp->kp_lcr, kp->kp_status_flag);

}

/* save the port params after send cmd successfully */
static void
keyspan_save_port_params_usa19hs(keyspan_port_t	*kp)
{
	keyspan_usa19hs_port_ctrl_msg_t	*ctrl_msg = &(kp->kp_ctrl_msg.usa19hs);

	ASSERT(mutex_owned(&kp->kp_mutex));

	if (ctrl_msg->setClocking) {
		kp->kp_baud = ctrl_msg->baudHi;
		kp->kp_baud = (kp->kp_baud << 8);
		kp->kp_baud |= ctrl_msg->baudLo;
	}
	if (ctrl_msg->setLcr) {
		kp->kp_lcr = ctrl_msg->lcr;
	}
	if (ctrl_msg->setRts) {
		if (ctrl_msg->rts) {
			kp->kp_status_flag |= KEYSPAN_PORT_RTS;
		} else {
			kp->kp_status_flag &= ~KEYSPAN_PORT_RTS;
		}
	}
	if (ctrl_msg->setDtr) {
		if (ctrl_msg->dtr) {
			kp->kp_status_flag |= KEYSPAN_PORT_DTR;
		} else {
			kp->kp_status_flag &= ~KEYSPAN_PORT_DTR;
		}
	}

	if (ctrl_msg->portEnabled) {
		kp->kp_status_flag |= KEYSPAN_PORT_ENABLE;
	} else {
		kp->kp_status_flag &= ~KEYSPAN_PORT_ENABLE;
	}

	USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_save_port_params: baud = %x, lcr = %x,"
	    "status_flag = %x", kp->kp_baud, kp->kp_lcr, kp->kp_status_flag);

}

/*
 * Set the port parameters to default values
 */
static void
keyspan_default_port_params_usa19hs(keyspan_port_t *kp)
{
	keyspan_usa19hs_port_ctrl_msg_t	*ctrl_msg = &(kp->kp_ctrl_msg.usa19hs);
	ASSERT(mutex_owned(&kp->kp_mutex));

	keyspan_build_cmd_msg(kp, NULL);

	ctrl_msg->setRts = 0x01;
	ctrl_msg->rts = 0x1;
	ctrl_msg->setDtr = 0x01;
	ctrl_msg->dtr = 0x1;

	ctrl_msg->setClocking = 1;
	ctrl_msg->setRxMode = 1;
	ctrl_msg->setTxMode = 1;

	/* set baud rate to 9600 */
	ctrl_msg->baudLo = keyspan_speedtab_usa19hs[13] & 0xff;
	ctrl_msg->baudHi = (keyspan_speedtab_usa19hs[13] >> 8) & 0xff;
	ctrl_msg->rxMode = RXMODE_BYHAND;
	ctrl_msg->txMode = TXMODE_BYHAND;

	ctrl_msg->lcr = 0x3;
	ctrl_msg->setLcr = 0x1;

	ctrl_msg->xonChar = CSTART;
	ctrl_msg->xoffChar = CSTOP;
	ctrl_msg->setTxFlowControl = 1;
	ctrl_msg->txFlowControl = TXFLOW_CTS;
	ctrl_msg->setRxFlowControl = 1;
	ctrl_msg->rxFlowControl = RXFLOW_RTS;
	ctrl_msg->rxFlush = 0;

}

/*
 * Build the command message according to the params from usbser.
 * The message will then be sent to deivce by keyspan_send_cmd.
 */
static void
keyspan_build_cmd_msg_usa19hs(keyspan_port_t *kp, ds_port_params_t *tp)
{
	int		cnt, i;
	uint_t		ui;
	ds_port_param_entry_t *pe;
	keyspan_usa19hs_port_ctrl_msg_t	*ctrl_msg = &(kp->kp_ctrl_msg.usa19hs);

	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_build_cmd_msg_usa19hs: tp = %p", (void *)tp);

	ASSERT(mutex_owned(&kp->kp_mutex));
	ASSERT(kp->kp_state == KEYSPAN_PORT_OPEN ||
	    kp->kp_state == KEYSPAN_PORT_OPENING);

	/* bzero all elements */
	bzero(ctrl_msg, sizeof (keyspan_usa19hs_port_ctrl_msg_t));

	/* it is usaually 16, according to Keyspan spec */
	ctrl_msg->rxForwardingLength = 16;
	/* from 1ms to 31ms, according to Keyspan spec. */
	ctrl_msg->rxForwardingTimeout = 16;

	ctrl_msg->portEnabled = 1;
	ctrl_msg->returnStatus = 1;

	if (tp == NULL) {

		return;
	}

	cnt = tp->tp_cnt;
	pe = tp->tp_entries;

	/* translate tp parameters into cmd_msg elements */
	for (i = 0; i < cnt; i++, pe++) {
		switch (pe->param) {
		case DS_PARAM_BAUD:
			ui = pe->val.ui;

			/*
			 * if we don't support this speed,
			 * then return failure.
			 */
			if ((ui >= NELEM(keyspan_speedtab_usa19hs)) ||
			    ((ui > 0) && (keyspan_speedtab_usa19hs[ui] == 0))) {

				USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
				    "keyspan_build_cmd_msg_usa19hs:"
				    " bad baud %d", ui);

				break;
			}

			/* if the same as the old rate, need not set the rate */
			if (kp->kp_baud == keyspan_speedtab_usa19hs[ui]) {

				USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
				    "keyspan_build_cmd_msg_usa19hs:"
				    " same as old baud setting, baud = %d",
				    keyspan_speed2baud[ui]);

				break;
			}
			ctrl_msg->setClocking = 1; /* enable the setting */
			ctrl_msg->setRxMode = 1;
			ctrl_msg->setTxMode = 1;

			ctrl_msg->baudLo = keyspan_speedtab_usa19hs[ui] & 0xff;
			ctrl_msg->baudHi = (keyspan_speedtab_usa19hs[ui] >> 8)
			    & 0xff;

			ctrl_msg->rxMode = RXMODE_BYHAND;
			ctrl_msg->txMode = TXMODE_BYHAND;

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa19hs: baud=%d",
			    keyspan_speed2baud[ui]);

			break;
		case DS_PARAM_PARITY:
			if (pe->val.ui & PARENB) {

				/*
				 * Since USA_PARITY_NONE == 0, it's not
				 * necessary to or it in here.
				 */
				if (pe->val.ui & PARODD) {
					ctrl_msg->lcr |= USA_PARITY_ODD;
				} else {
					ctrl_msg->lcr |= USA_PARITY_EVEN;
				}
			}
			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa19hs: parity=%x,lcr = %x",
			    pe->val.ui, ctrl_msg->lcr);

			break;
		case DS_PARAM_STOPB:
			if (pe->val.ui & CSTOPB) {
				ctrl_msg->lcr |= STOPBITS_678_2;
			} else {

				/*
				 * STOPBITS_5678_1 equals zero,
				 * so it's not necessary to or it in.
				 */
				USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
				    "keyspan_build_cmd_msg_usa19hs:"
				    " STOPBITS_5678_1");
			}

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa19hs: stopb=%x, lcr = %x",
			    pe->val.ui, ctrl_msg->lcr);

			break;
		case DS_PARAM_CHARSZ:
			switch (pe->val.ui) {
			case CS5:

				/*
				 * USA_DATABITS_5 equals zero,
				 * not necessary to or it in.
				 */
				USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
				    "keyspan_build_cmd_msg_usa19hs:"
				    " USA_DATABITS_5");

				break;
			case CS6:
				ctrl_msg->lcr |= USA_DATABITS_6;

				break;
			case CS7:
				ctrl_msg->lcr |= USA_DATABITS_7;

				break;
			case CS8:
			default:
				/*
				 * The default value is USA_DATABITS_8. It is
				 * safe to set to the default one here.
				 */
				ctrl_msg->lcr |= USA_DATABITS_8;

				break;
			}

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa19hs: cs=%x, lcr = %x",
			    pe->val.ui, ctrl_msg->lcr);

			break;
		case DS_PARAM_XON_XOFF:
			ctrl_msg->xonChar = pe->val.uc[0]; /* init to CSTART */
			ctrl_msg->xoffChar = pe->val.uc[1]; /* init to CSTOP */

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa19hs: xonChar=%x, "
			    "xoffChar = %x", ctrl_msg->xonChar,
			    ctrl_msg->xoffChar);

			break;
		case DS_PARAM_FLOW_CTL:
			if (pe->val.ui & CTSXON) {
				ctrl_msg->txFlowControl = TXFLOW_CTS;
				ctrl_msg->setTxFlowControl = 1;
			} else {
				/* Clear the tx flow control setting */
				ctrl_msg->txFlowControl = 0;
				ctrl_msg->setTxFlowControl = 1;
			}
			if (pe->val.ui & RTSXOFF) {
				ctrl_msg->rxFlowControl = RXFLOW_RTS;
				ctrl_msg->setRxFlowControl = 1;
			} else {
				/* Clear the rx flow control setting */
				ctrl_msg->rxFlowControl = 0;
				ctrl_msg->setRxFlowControl = 1;
			}

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa19hs: txFlowControl = %x,"
			    "rxFlowControl = %x", ctrl_msg->txFlowControl,
			    ctrl_msg->rxFlowControl);

			break;
		default:
			USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa19hs: bad param %d",
			    pe->param);

			break;
		}

	}

	/*
	 * Enable the lcr settings only if they are different
	 * with the existing settings.
	 */
	ctrl_msg->setLcr =  (ctrl_msg->lcr == kp->kp_lcr) ? 0 : 1;

}


/*
 * Build the command message according to the params from usbser.
 * The message will then be sent to deivce by keyspan_send_cmd.
 */
static void
keyspan_build_cmd_msg_usa49(keyspan_port_t *kp, ds_port_params_t *tp)
{
	int		cnt, i;
	uint_t		ui;
	ds_port_param_entry_t *pe;
	keyspan_usa49_port_ctrl_msg_t	*ctrl_msg = &(kp->kp_ctrl_msg.usa49);

	USB_DPRINTF_L4(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_build_cmd_msg_usa49: tp = %p", (void *)tp);

	ASSERT(mutex_owned(&kp->kp_mutex));
	ASSERT(kp->kp_state == KEYSPAN_PORT_OPEN ||
	    kp->kp_state == KEYSPAN_PORT_OPENING);

	/* bzero all elements */
	bzero(ctrl_msg, sizeof (keyspan_usa49_port_ctrl_msg_t));

	ctrl_msg->portNumber = kp->kp_port_num;

	/* it is usaually 16, according to Keyspan spec */
	ctrl_msg->forwardingLength = 16;

	ctrl_msg->enablePort = 1;
	ctrl_msg->returnStatus = 1;

	if (tp == NULL) {

		return;
	}

	cnt = tp->tp_cnt;
	pe = tp->tp_entries;

	/* translate tp parameters into cmd_msg elements */
	for (i = 0; i < cnt; i++, pe++) {
		switch (pe->param) {
		case DS_PARAM_BAUD:
			ui = pe->val.ui;

			/*
			 * If we don't support this speed,
			 * then return failure.
			 */
			if ((ui >= NELEM(keyspan_speedtab_usa49)) ||
			    ((ui > 0) && (keyspan_speedtab_usa49[ui] == 0))) {

				USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
				    "keyspan_build_cmd_msg_usa49:"
				    " bad baud %d", ui);

				break;
			}

			/* if the same as the old rate, need not set the rate */
			if (kp->kp_baud == keyspan_speedtab_usa49[ui]) {

				USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
				    "keyspan_build_cmd_msg_usa49: "
				    "same as old baud setting, baud = %d",
				    keyspan_speed2baud[ui]);

				break;
			}
			ctrl_msg->setClocking = 0xff; /* enable the setting */
			ctrl_msg->baudLo = keyspan_speedtab_usa49[ui] & 0xff;
			ctrl_msg->baudHi = (keyspan_speedtab_usa49[ui] >> 8)
			    & 0xff;
			ctrl_msg->prescaler = keyspan_prescaler_49wlc[ui];

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa49: baud=%d",
			    keyspan_speed2baud[ui]);

			break;
		case DS_PARAM_PARITY:
			if (pe->val.ui & PARENB) {

				/*
				 * Since USA_PARITY_NONE == 0,
				 * it's not necessary to or it in here.
				 */
				if (pe->val.ui & PARODD) {
					ctrl_msg->lcr |= USA_PARITY_ODD;
				} else {
					ctrl_msg->lcr |= USA_PARITY_EVEN;
				}
			}
			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa49: parity=%x, lcr = %x",
			    pe->val.ui, ctrl_msg->lcr);

			break;
		case DS_PARAM_STOPB:
			if (pe->val.ui & CSTOPB) {
				ctrl_msg->lcr |= STOPBITS_678_2;
			} else {

				/*
				 * STOPBITS_5678_1 equals zero,
				 * not necessary to or it in.
				 */
				USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
				    "keyspan_build_cmd_msg_usa49: "
				    "STOPBITS_5678_1");
			}

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa49: stopb=%x, lcr = %x",
			    pe->val.ui, ctrl_msg->lcr);

			break;
		case DS_PARAM_CHARSZ:
			switch (pe->val.ui) {
			case CS5:

				/*
				 * USA_DATABITS_5 equals zero,
				 * not necessary to or it in.
				 */
				USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
				    "keyspan_build_cmd_msg_usa49:"
				    " USA_DATABITS_5");

				break;
			case CS6:
				ctrl_msg->lcr |= USA_DATABITS_6;

				break;
			case CS7:
				ctrl_msg->lcr |= USA_DATABITS_7;

				break;
			case CS8:
			default:
				ctrl_msg->lcr |= USA_DATABITS_8;

				break;
			}

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa49: cs=%x, lcr = %x",
			    pe->val.ui, ctrl_msg->lcr);

			break;
		case DS_PARAM_XON_XOFF:
			ctrl_msg->xonChar = pe->val.uc[0]; /* init to CSTART */
			ctrl_msg->xoffChar = pe->val.uc[1]; /* init to CSTOP */

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa49: xonChar=%x, "
			    "xoffChar = %x", ctrl_msg->xonChar,
			    ctrl_msg->xoffChar);

			break;
		case DS_PARAM_FLOW_CTL:
			if (pe->val.ui & CTSXON) {
				ctrl_msg->ctsFlowControl = 1;
				ctrl_msg->setFlowControl = 1;
			} else {
				ctrl_msg->ctsFlowControl = 0;
				ctrl_msg->setFlowControl = 1;
			}
			if (pe->val.ui & RTSXOFF) {
				USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
				    "keyspan_build_cmd_msg_usa49: "
				    "pe->val.ui = %x, flow_ctl: RTSXOFF, "
				    "no hardware support", pe->val.ui);
			}

			USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa49: ctsFlowControl = %x,"
			    "dsrFlowControl = %x", ctrl_msg->ctsFlowControl,
			    ctrl_msg->dsrFlowControl);

			break;
		default:
			USB_DPRINTF_L2(DPRINT_CTLOP, kp->kp_lh,
			    "keyspan_build_cmd_msg_usa49: bad param %d",
			    pe->param);

			break;
		}
	}

	/*
	 * enable the lcr settings only if they are different
	 * with the existing settings.
	 */
	ctrl_msg->setLcr =  (ctrl_msg->lcr == kp->kp_lcr) ? 0 : 1;

}


/*
 * Set the port parameters to default values
 */
static void
keyspan_default_port_params_usa49(keyspan_port_t *kp)
{
	keyspan_usa49_port_ctrl_msg_t	*ctrl_msg = &(kp->kp_ctrl_msg.usa49);
	ASSERT(mutex_owned(&kp->kp_mutex));

	keyspan_build_cmd_msg(kp, NULL);

	ctrl_msg->setRts = 1;
	ctrl_msg->rts = 1;
	ctrl_msg->setDtr = 1;
	ctrl_msg->dtr = 1;

	ctrl_msg->_txOn = 1;
	ctrl_msg->_txOff = 0;
	ctrl_msg->txFlush = 0;
	ctrl_msg->txBreak = 0;
	ctrl_msg->rxOn = 1;
	ctrl_msg->rxOff = 0;
	ctrl_msg->rxFlush = 0;
	ctrl_msg->rxForward = 0;
	ctrl_msg->returnStatus = 1;
	ctrl_msg->resetDataToggle = 0;
	ctrl_msg->enablePort = 1;
	ctrl_msg->disablePort = 0;

	/* set baud rate to 9600 */
	ctrl_msg->setClocking = 1;
	ctrl_msg->baudLo = keyspan_speedtab_usa49[13] & 0xff;
	ctrl_msg->baudHi = (keyspan_speedtab_usa49[13] >> 8) & 0xff;
	ctrl_msg->prescaler = keyspan_prescaler_49wlc[13];

	ctrl_msg->lcr = 0x3;
	ctrl_msg->setLcr = 1;

	ctrl_msg->xonChar = CSTART;
	ctrl_msg->xoffChar = CSTOP;
	ctrl_msg->ctsFlowControl = 1;
	ctrl_msg->setFlowControl = 1;

}


/* save the port params after send cmd successfully */
static void
keyspan_save_port_params_usa49(keyspan_port_t	*kp)
{
	keyspan_usa49_port_ctrl_msg_t	*ctrl_msg = &(kp->kp_ctrl_msg.usa49);

	ASSERT(mutex_owned(&kp->kp_mutex));

	if (ctrl_msg->setClocking) {
		kp->kp_baud = ctrl_msg->baudHi;
		kp->kp_baud = (kp->kp_baud << 8);
		kp->kp_baud |= ctrl_msg->baudLo;
	}
	if (ctrl_msg->setLcr) {
		kp->kp_lcr = ctrl_msg->lcr;
	}
	if (ctrl_msg->setRts) {
		if (ctrl_msg->rts) {
			kp->kp_status_flag |= KEYSPAN_PORT_RTS;
		} else {
			kp->kp_status_flag &= ~KEYSPAN_PORT_RTS;
		}
	}
	if (ctrl_msg->setDtr) {
		if (ctrl_msg->dtr) {
			kp->kp_status_flag |= KEYSPAN_PORT_DTR;
		} else {
			kp->kp_status_flag &= ~KEYSPAN_PORT_DTR;
		}
	}

	if (ctrl_msg->enablePort) {
		kp->kp_status_flag |= KEYSPAN_PORT_ENABLE;
	} else {
		kp->kp_status_flag &= ~KEYSPAN_PORT_ENABLE;
	}

	/*
	 * There are no flags in status msg (49wlc) can indicate the
	 * break status, so we make use of ctrl_msg->txBreak here.
	 */
	if (ctrl_msg->txBreak) {
		kp->kp_status_flag |= KEYSPAN_PORT_TXBREAK;
	} else {
		kp->kp_status_flag &= ~KEYSPAN_PORT_TXBREAK;
	}

	USB_DPRINTF_L3(DPRINT_CTLOP, kp->kp_lh,
	    "keyspan_save_port_params: baud = %x, lcr = %x,"
	    "status_flag = %x", kp->kp_baud, kp->kp_lcr, kp->kp_status_flag);

}
