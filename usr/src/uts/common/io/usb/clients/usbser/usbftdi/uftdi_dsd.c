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
 * Copyright 2013 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

/*
 * FTDI FT232R USB UART device-specific driver
 *
 * May work on the (many) devices based on earlier versions of the chip.
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
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/usba_impl.h>

#include <sys/usb/clients/usbser/usbser_dsdi.h>
#include <sys/usb/clients/usbser/usbftdi/uftdi_var.h>
#include <sys/usb/clients/usbser/usbftdi/uftdi_reg.h>

#include <sys/usb/usbdevs.h>

/*
 * DSD operations
 */
static int	uftdi_attach(ds_attach_info_t *);
static void	uftdi_detach(ds_hdl_t);
static int	uftdi_register_cb(ds_hdl_t, uint_t, ds_cb_t *);
static void	uftdi_unregister_cb(ds_hdl_t, uint_t);
static int	uftdi_open_port(ds_hdl_t, uint_t);
static int	uftdi_close_port(ds_hdl_t, uint_t);

/* power management */
static int	uftdi_usb_power(ds_hdl_t, int, int, int *);
static int	uftdi_suspend(ds_hdl_t);
static int	uftdi_resume(ds_hdl_t);
static int	uftdi_disconnect(ds_hdl_t);
static int	uftdi_reconnect(ds_hdl_t);

/* standard UART operations */
static int	uftdi_set_port_params(ds_hdl_t, uint_t, ds_port_params_t *);
static int	uftdi_set_modem_ctl(ds_hdl_t, uint_t, int, int);
static int	uftdi_get_modem_ctl(ds_hdl_t, uint_t, int, int *);
static int	uftdi_break_ctl(ds_hdl_t, uint_t, int);

/* data xfer */
static int	uftdi_tx(ds_hdl_t, uint_t, mblk_t *);
static mblk_t	*uftdi_rx(ds_hdl_t, uint_t);
static void	uftdi_stop(ds_hdl_t, uint_t, int);
static void	uftdi_start(ds_hdl_t, uint_t, int);
static int	uftdi_fifo_flush(ds_hdl_t, uint_t, int);
static int	uftdi_fifo_drain(ds_hdl_t, uint_t, int);

/* polled I/O support */
static usb_pipe_handle_t uftdi_out_pipe(ds_hdl_t, uint_t);
static usb_pipe_handle_t uftdi_in_pipe(ds_hdl_t, uint_t);

/*
 * Sub-routines
 */

/* configuration routines */
static void	uftdi_cleanup(uftdi_state_t *, int);
static int	uftdi_dev_attach(uftdi_state_t *);
static int	uftdi_open_hw_port(uftdi_state_t *, int);

/* hotplug */
static int	uftdi_restore_device_state(uftdi_state_t *);
static int	uftdi_restore_port_state(uftdi_state_t *);

/* power management */
static int	uftdi_create_pm_components(uftdi_state_t *);
static void	uftdi_destroy_pm_components(uftdi_state_t *);
static int	uftdi_pm_set_busy(uftdi_state_t *);
static void	uftdi_pm_set_idle(uftdi_state_t *);
static int	uftdi_pwrlvl0(uftdi_state_t *);
static int	uftdi_pwrlvl1(uftdi_state_t *);
static int	uftdi_pwrlvl2(uftdi_state_t *);
static int	uftdi_pwrlvl3(uftdi_state_t *);

/* pipe operations */
static int	uftdi_open_pipes(uftdi_state_t *);
static void	uftdi_close_pipes(uftdi_state_t *);
static void	uftdi_disconnect_pipes(uftdi_state_t *);
static int	uftdi_reconnect_pipes(uftdi_state_t *);

/* pipe callbacks */
static void	uftdi_bulkin_cb(usb_pipe_handle_t, usb_bulk_req_t *);
static void	uftdi_bulkout_cb(usb_pipe_handle_t, usb_bulk_req_t *);

/* data transfer routines */
static int	uftdi_rx_start(uftdi_state_t *);
static void	uftdi_tx_start(uftdi_state_t *, int *);
static int	uftdi_send_data(uftdi_state_t *, mblk_t *);
static int	uftdi_wait_tx_drain(uftdi_state_t *, int);

/* vendor-specific commands */
static int	uftdi_cmd_vendor_write0(uftdi_state_t *,
		    uint16_t, uint16_t, uint16_t);

/* misc */
static void	uftdi_put_tail(mblk_t **, mblk_t *);
static void	uftdi_put_head(mblk_t **, mblk_t *);


/*
 * DSD ops structure
 */
ds_ops_t uftdi_ds_ops = {
	DS_OPS_VERSION,
	uftdi_attach,
	uftdi_detach,
	uftdi_register_cb,
	uftdi_unregister_cb,
	uftdi_open_port,
	uftdi_close_port,
	uftdi_usb_power,
	uftdi_suspend,
	uftdi_resume,
	uftdi_disconnect,
	uftdi_reconnect,
	uftdi_set_port_params,
	uftdi_set_modem_ctl,
	uftdi_get_modem_ctl,
	uftdi_break_ctl,
	NULL,			/* no loopback support */
	uftdi_tx,
	uftdi_rx,
	uftdi_stop,
	uftdi_start,
	uftdi_fifo_flush,
	uftdi_fifo_drain,
	uftdi_out_pipe,
	uftdi_in_pipe
};

/* debug support */
static uint_t	uftdi_errlevel = USB_LOG_L4;
static uint_t	uftdi_errmask = DPRINT_MASK_ALL;
static uint_t	uftdi_instance_debug = (uint_t)-1;
static uint_t	uftdi_attach_unrecognized = B_FALSE;

/*
 * ds_attach
 */
static int
uftdi_attach(ds_attach_info_t *aip)
{
	uftdi_state_t *uf;
	usb_dev_descr_t *dd;
	int recognized;

	uf = kmem_zalloc(sizeof (*uf), KM_SLEEP);
	uf->uf_dip = aip->ai_dip;
	uf->uf_usb_events = aip->ai_usb_events;
	*aip->ai_hdl = (ds_hdl_t)uf;

	/* only one port */
	*aip->ai_port_cnt = 1;

	if (usb_client_attach(uf->uf_dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		uftdi_cleanup(uf, 1);
		return (USB_FAILURE);
	}

	if (usb_get_dev_data(uf->uf_dip,
	    &uf->uf_dev_data, USB_PARSE_LVL_IF, 0) != USB_SUCCESS) {
		uftdi_cleanup(uf, 2);
		return (USB_FAILURE);
	}

	uf->uf_hwport = FTDI_PIT_SIOA + uf->uf_dev_data->dev_curr_if;

	mutex_init(&uf->uf_lock, NULL, MUTEX_DRIVER,
	    uf->uf_dev_data->dev_iblock_cookie);

	cv_init(&uf->uf_tx_cv, NULL, CV_DRIVER, NULL);

	uf->uf_lh = usb_alloc_log_hdl(uf->uf_dip, "uftdi",
	    &uftdi_errlevel, &uftdi_errmask, &uftdi_instance_debug, 0);

	/*
	 * This device and its clones has numerous physical instantiations.
	 */
	recognized = B_TRUE;
	dd = uf->uf_dev_data->dev_descr;
	switch (dd->idVendor) {
	case USB_VENDOR_FTDI:
		switch (dd->idProduct) {
		case USB_PRODUCT_FTDI_SERIAL_2232C:
		case USB_PRODUCT_FTDI_SERIAL_8U232AM:
		case USB_PRODUCT_FTDI_SEMC_DSS20:
		case USB_PRODUCT_FTDI_CFA_631:
		case USB_PRODUCT_FTDI_CFA_632:
		case USB_PRODUCT_FTDI_CFA_633:
		case USB_PRODUCT_FTDI_CFA_634:
		case USB_PRODUCT_FTDI_CFA_635:
		case USB_PRODUCT_FTDI_USBSERIAL:
		case USB_PRODUCT_FTDI_MX2_3:
		case USB_PRODUCT_FTDI_MX4_5:
		case USB_PRODUCT_FTDI_LK202:
		case USB_PRODUCT_FTDI_LK204:
		case USB_PRODUCT_FTDI_TACTRIX_OPENPORT_13M:
		case USB_PRODUCT_FTDI_TACTRIX_OPENPORT_13S:
		case USB_PRODUCT_FTDI_TACTRIX_OPENPORT_13U:
		case USB_PRODUCT_FTDI_EISCOU:
		case USB_PRODUCT_FTDI_UOPTBR:
		case USB_PRODUCT_FTDI_EMCU2D:
		case USB_PRODUCT_FTDI_PCMSFU:
		case USB_PRODUCT_FTDI_EMCU2H:
			break;
		default:
			recognized = B_FALSE;
			break;
		}
		break;
	case USB_VENDOR_SIIG2:
		switch (dd->idProduct) {
		case USB_PRODUCT_SIIG2_US2308:
			break;
		default:
			recognized = B_FALSE;
			break;
		}
		break;
	case USB_VENDOR_INTREPIDCS:
		switch (dd->idProduct) {
		case USB_PRODUCT_INTREPIDCS_VALUECAN:
		case USB_PRODUCT_INTREPIDCS_NEOVI:
			break;
		default:
			recognized = B_FALSE;
			break;
		}
		break;
	case USB_VENDOR_BBELECTRONICS:
		switch (dd->idProduct) {
		case USB_PRODUCT_BBELECTRONICS_USOTL4:
			break;
		default:
			recognized = B_FALSE;
			break;
		}
		break;
	case USB_VENDOR_MELCO:
		switch (dd->idProduct) {
		case USB_PRODUCT_MELCO_PCOPRS1:
			break;
		default:
			recognized = B_FALSE;
			break;
		}
		break;
	case USB_VENDOR_MARVELL:
		switch (dd->idProduct) {
		case USB_PRODUCT_MARVELL_SHEEVAPLUG_JTAG:
			break;
		default:
			recognized = B_FALSE;
			break;
		}
		break;
	default:
		recognized = B_FALSE;
		break;
	}

	/*
	 * Set 'uftdi_attach_unrecognized' to non-zero to
	 * experiment with newer devices ..
	 */
	if (!recognized && !uftdi_attach_unrecognized) {
		uftdi_cleanup(uf, 3);
		return (USB_FAILURE);
	}

	USB_DPRINTF_L3(DPRINT_ATTACH, uf->uf_lh,
	    "uftdi: matched vendor 0x%x product 0x%x port %d",
	    dd->idVendor, dd->idProduct, uf->uf_hwport);

	uf->uf_def_ph = uf->uf_dev_data->dev_default_ph;

	mutex_enter(&uf->uf_lock);
	uf->uf_dev_state = USB_DEV_ONLINE;
	uf->uf_port_state = UFTDI_PORT_CLOSED;
	mutex_exit(&uf->uf_lock);

	if (uftdi_create_pm_components(uf) != USB_SUCCESS) {
		uftdi_cleanup(uf, 3);
		return (USB_FAILURE);
	}

	if (usb_register_event_cbs(uf->uf_dip,
	    uf->uf_usb_events, 0) != USB_SUCCESS) {
		uftdi_cleanup(uf, 4);
		return (USB_FAILURE);
	}

	if (uftdi_dev_attach(uf) != USB_SUCCESS) {
		uftdi_cleanup(uf, 5);
		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}

#define	FTDI_CLEANUP_LEVEL_MAX	6

/*
 * ds_detach
 */
static void
uftdi_detach(ds_hdl_t hdl)
{
	uftdi_cleanup((uftdi_state_t *)hdl, FTDI_CLEANUP_LEVEL_MAX);
}


/*
 * ds_register_cb
 */
/*ARGSUSED*/
static int
uftdi_register_cb(ds_hdl_t hdl, uint_t portno, ds_cb_t *cb)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;

	ASSERT(portno == 0);

	uf->uf_cb = *cb;
	return (USB_SUCCESS);
}


/*
 * ds_unregister_cb
 */
/*ARGSUSED*/
static void
uftdi_unregister_cb(ds_hdl_t hdl, uint_t portno)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;

	ASSERT(portno == 0);

	bzero(&uf->uf_cb, sizeof (uf->uf_cb));
}


/*
 * ds_open_port
 */
/*ARGSUSED*/
static int
uftdi_open_port(ds_hdl_t hdl, uint_t portno)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	int rval;

	USB_DPRINTF_L4(DPRINT_OPEN, uf->uf_lh, "uftdi_open_port %d", portno);

	ASSERT(portno == 0);

	mutex_enter(&uf->uf_lock);
	if (uf->uf_dev_state == USB_DEV_DISCONNECTED ||
	    uf->uf_port_state != UFTDI_PORT_CLOSED) {
		mutex_exit(&uf->uf_lock);
		return (USB_FAILURE);
	}
	mutex_exit(&uf->uf_lock);

	if ((rval = uftdi_pm_set_busy(uf)) != USB_SUCCESS)
		return (rval);

	/* initialize hardware serial port */
	rval = uftdi_open_hw_port(uf, 0);

	if (rval == USB_SUCCESS) {
		mutex_enter(&uf->uf_lock);

		/* start to receive data */
		if (uftdi_rx_start(uf) != USB_SUCCESS) {
			mutex_exit(&uf->uf_lock);
			return (USB_FAILURE);
		}
		uf->uf_port_state = UFTDI_PORT_OPEN;
		mutex_exit(&uf->uf_lock);
	} else
		uftdi_pm_set_idle(uf);

	return (rval);
}


/*
 * ds_close_port
 */
/*ARGSUSED*/
static int
uftdi_close_port(ds_hdl_t hdl, uint_t portno)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_CLOSE, uf->uf_lh, "uftdi_close_port %d", portno);

	ASSERT(portno == 0);

	mutex_enter(&uf->uf_lock);

	/* free resources and finalize state */
	freemsg(uf->uf_rx_mp);
	uf->uf_rx_mp = NULL;

	freemsg(uf->uf_tx_mp);
	uf->uf_tx_mp = NULL;

	uf->uf_port_state = UFTDI_PORT_CLOSED;
	mutex_exit(&uf->uf_lock);

	uftdi_pm_set_idle(uf);

	return (USB_SUCCESS);
}


/*
 * ds_usb_power
 */
/*ARGSUSED*/
static int
uftdi_usb_power(ds_hdl_t hdl, int comp, int level, int *new_state)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	uftdi_pm_t *pm = uf->uf_pm;
	int rval;

	USB_DPRINTF_L4(DPRINT_PM, uf->uf_lh, "uftdi_usb_power");

	if (!pm)
		return (USB_FAILURE);

	mutex_enter(&uf->uf_lock);

	/*
	 * check if we are transitioning to a legal power level
	 */
	if (USB_DEV_PWRSTATE_OK(pm->pm_pwr_states, level)) {
		USB_DPRINTF_L2(DPRINT_PM, uf->uf_lh, "uftdi_usb_power: "
		    "illegal power level %d, pwr_states=0x%x",
		    level, pm->pm_pwr_states);
		mutex_exit(&uf->uf_lock);
		return (USB_FAILURE);
	}

	/*
	 * if we are about to raise power and asked to lower power, fail
	 */
	if (pm->pm_raise_power && (level < (int)pm->pm_cur_power)) {
		mutex_exit(&uf->uf_lock);
		return (USB_FAILURE);
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		rval = uftdi_pwrlvl0(uf);
		break;
	case USB_DEV_OS_PWR_1:
		rval = uftdi_pwrlvl1(uf);
		break;
	case USB_DEV_OS_PWR_2:
		rval = uftdi_pwrlvl2(uf);
		break;
	case USB_DEV_OS_FULL_PWR:
		rval = uftdi_pwrlvl3(uf);
		/*
		 * If usbser dev_state is DISCONNECTED or SUSPENDED, it shows
		 * that the usb serial device is disconnected/suspended while it
		 * is under power down state, now the device is powered up
		 * before it is reconnected/resumed. xxx_pwrlvl3() will set dev
		 * state to ONLINE, we need to set the dev state back to
		 * DISCONNECTED/SUSPENDED.
		 */
		if (rval == USB_SUCCESS &&
		    (*new_state == USB_DEV_DISCONNECTED ||
		    *new_state == USB_DEV_SUSPENDED))
			uf->uf_dev_state = *new_state;
		break;
	default:
		ASSERT(0);	/* cannot happen */
	}

	*new_state = uf->uf_dev_state;
	mutex_exit(&uf->uf_lock);

	return (rval);
}


/*
 * ds_suspend
 */
static int
uftdi_suspend(ds_hdl_t hdl)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	int state = USB_DEV_SUSPENDED;

	USB_DPRINTF_L4(DPRINT_PM, uf->uf_lh, "uftdi_suspend");

	/*
	 * If the device is suspended while it is under PWRED_DOWN state, we
	 * need to keep the PWRED_DOWN state so that it could be powered up
	 * later. In the mean while, usbser dev state will be changed to
	 * SUSPENDED state.
	 */
	mutex_enter(&uf->uf_lock);
	if (uf->uf_dev_state != USB_DEV_PWRED_DOWN)
		uf->uf_dev_state = USB_DEV_SUSPENDED;
	mutex_exit(&uf->uf_lock);

	uftdi_disconnect_pipes(uf);
	return (state);
}


/*
 * ds_resume
 */
static int
uftdi_resume(ds_hdl_t hdl)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	int current_state;
	int rval;

	USB_DPRINTF_L4(DPRINT_PM, uf->uf_lh, "uftdi_resume");

	mutex_enter(&uf->uf_lock);
	current_state = uf->uf_dev_state;
	mutex_exit(&uf->uf_lock);

	if (current_state == USB_DEV_ONLINE)
		rval = USB_SUCCESS;
	else
		rval = uftdi_restore_device_state(uf);
	return (rval);
}


/*
 * ds_disconnect
 */
static int
uftdi_disconnect(ds_hdl_t hdl)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	int state = USB_DEV_DISCONNECTED;

	USB_DPRINTF_L4(DPRINT_HOTPLUG, uf->uf_lh, "uftdi_disconnect");

	/*
	 * If the device is disconnected while it is under PWRED_DOWN state, we
	 * need to keep the PWRED_DOWN state so that it could be powered up
	 * later. In the mean while, usbser dev state will be changed to
	 * DISCONNECTED state.
	 */
	mutex_enter(&uf->uf_lock);
	if (uf->uf_dev_state != USB_DEV_PWRED_DOWN)
		uf->uf_dev_state = USB_DEV_DISCONNECTED;
	mutex_exit(&uf->uf_lock);

	uftdi_disconnect_pipes(uf);
	return (state);
}


/*
 * ds_reconnect
 */
static int
uftdi_reconnect(ds_hdl_t hdl)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_HOTPLUG, uf->uf_lh, "uftdi_reconnect");
	return (uftdi_restore_device_state(uf));
}

/* translate parameters into device-specific bits */

static int
uftdi_param2regs(uftdi_state_t *uf, ds_port_params_t *tp, uftdi_regs_t *ur)
{
	ds_port_param_entry_t *pe;
	int i;

	ur->ur_data = 0;
	ur->ur_flowval = 0;
	ur->ur_flowidx = FTDI_SIO_DISABLE_FLOW_CTRL << 8;

	for (i = 0, pe = tp->tp_entries; i < tp->tp_cnt; i++, pe++) {
		switch (pe->param) {
		case DS_PARAM_BAUD:
			switch (pe->val.ui) {
			case B300:
				ur->ur_baud = ftdi_8u232am_b300;
				break;
			case B600:
				ur->ur_baud = ftdi_8u232am_b600;
				break;
			case B1200:
				ur->ur_baud = ftdi_8u232am_b1200;
				break;
			case B2400:
				ur->ur_baud = ftdi_8u232am_b2400;
				break;
			case B4800:
				ur->ur_baud = ftdi_8u232am_b4800;
				break;
			case B9600:
				ur->ur_baud = ftdi_8u232am_b9600;
				break;
			case B19200:
				ur->ur_baud = ftdi_8u232am_b19200;
				break;
			case B38400:
				ur->ur_baud = ftdi_8u232am_b38400;
				break;
			case B57600:
				ur->ur_baud = ftdi_8u232am_b57600;
				break;
			case B115200:
				ur->ur_baud = ftdi_8u232am_b115200;
				break;
			case B230400:
				ur->ur_baud = ftdi_8u232am_b230400;
				break;
			case B460800:
				ur->ur_baud = ftdi_8u232am_b460800;
				break;
			case B921600:
				ur->ur_baud = ftdi_8u232am_b921600;
				break;
			default:
				USB_DPRINTF_L3(DPRINT_CTLOP, uf->uf_lh,
				    "uftdi_param2regs: bad baud %d",
				    pe->val.ui);
				return (USB_FAILURE);
			}
			break;

		case DS_PARAM_PARITY:
			if (pe->val.ui & PARENB) {
				if (pe->val.ui & PARODD)
					ur->ur_data |=
					    FTDI_SIO_SET_DATA_PARITY_ODD;
				else
					ur->ur_data |=
					    FTDI_SIO_SET_DATA_PARITY_EVEN;
			} else {
				/* LINTED [E_EXPR_NULL_EFFECT] */
				ur->ur_data |= FTDI_SIO_SET_DATA_PARITY_NONE;
			}
			break;

		case DS_PARAM_STOPB:
			if (pe->val.ui & CSTOPB)
				ur->ur_data |= FTDI_SIO_SET_DATA_STOP_BITS_2;
			else {
				/* LINTED [E_EXPR_NULL_EFFECT] */
				ur->ur_data |= FTDI_SIO_SET_DATA_STOP_BITS_1;
			}
			break;

		case DS_PARAM_CHARSZ:
			switch (pe->val.ui) {
			case CS5:
				ur->ur_data |= FTDI_SIO_SET_DATA_BITS(5);
				break;
			case CS6:
				ur->ur_data |= FTDI_SIO_SET_DATA_BITS(6);
				break;
			case CS7:
				ur->ur_data |= FTDI_SIO_SET_DATA_BITS(7);
				break;
			case CS8:
			default:
				ur->ur_data |= FTDI_SIO_SET_DATA_BITS(8);
				break;
			}
			break;

		case DS_PARAM_XON_XOFF:		/* Software flow control */
			if ((pe->val.ui & IXON) || (pe->val.ui & IXOFF)) {
				uint8_t xonc = pe->val.uc[0];
				uint8_t xoffc = pe->val.uc[1];

				ur->ur_flowval = (xoffc << 8) | xonc;
				ur->ur_flowidx = FTDI_SIO_XON_XOFF_HS << 8;
			}
			break;

		case DS_PARAM_FLOW_CTL:		/* Hardware flow control */
			if (pe->val.ui & (RTSXOFF | CTSXON)) {
				ur->ur_flowval = 0;
				ur->ur_flowidx = FTDI_SIO_RTS_CTS_HS << 8;
			}
			if (pe->val.ui & DTRXOFF) {
				ur->ur_flowval = 0;
				ur->ur_flowidx = FTDI_SIO_DTR_DSR_HS << 8;
			}
			break;
		default:
			USB_DPRINTF_L2(DPRINT_CTLOP, uf->uf_lh,
			    "uftdi_param2regs: bad param %d", pe->param);
			break;
		}
	}
	return (USB_SUCCESS);
}

/*
 * Write the register set to the device and update the state structure.
 * If there are errors, return the device to its previous state.
 */
static int
uftdi_setregs(uftdi_state_t *uf, uftdi_regs_t *ur)
{
	int rval;
	uftdi_regs_t uold;

	mutex_enter(&uf->uf_lock);
	uold = uf->uf_softr;
	mutex_exit(&uf->uf_lock);

	if (ur == NULL)
		ur = &uold;	/* NULL => restore previous values */

	rval = uftdi_cmd_vendor_write0(uf, FTDI_SIO_SET_BAUD_RATE,
	    ur->ur_baud, uf->uf_hwport);
	if (rval != USB_SUCCESS) {
		(void) uftdi_cmd_vendor_write0(uf, FTDI_SIO_SET_BAUD_RATE,
		    uold.ur_baud, uf->uf_hwport);
		goto out;
	} else {
		mutex_enter(&uf->uf_lock);
		uf->uf_softr.ur_baud = ur->ur_baud;
		mutex_exit(&uf->uf_lock);
	}

	rval = uftdi_cmd_vendor_write0(uf, FTDI_SIO_SET_DATA,
	    ur->ur_data, uf->uf_hwport);
	if (rval != USB_SUCCESS) {
		(void) uftdi_cmd_vendor_write0(uf, FTDI_SIO_SET_DATA,
		    uold.ur_data, uf->uf_hwport);
		goto out;
	} else {
		mutex_enter(&uf->uf_lock);
		uf->uf_softr.ur_data = ur->ur_data;
		mutex_exit(&uf->uf_lock);
	}

	rval = uftdi_cmd_vendor_write0(uf, FTDI_SIO_SET_FLOW_CTRL,
	    ur->ur_flowval, ur->ur_flowidx | uf->uf_hwport);
	if (rval != USB_SUCCESS) {
		(void) uftdi_cmd_vendor_write0(uf, FTDI_SIO_SET_FLOW_CTRL,
		    uold.ur_flowval, uold.ur_flowidx | uf->uf_hwport);
		goto out;
	} else {
		mutex_enter(&uf->uf_lock);
		uf->uf_softr.ur_flowval = ur->ur_flowval;
		uf->uf_softr.ur_flowidx = ur->ur_flowidx;
		mutex_exit(&uf->uf_lock);
	}
out:
	return (rval);
}

/*
 * ds_set_port_params
 */
static int
uftdi_set_port_params(ds_hdl_t hdl, uint_t portno, ds_port_params_t *tp)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	int rval;
	uftdi_regs_t uregs;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh, "uftdi_set_port_params");

	rval = uftdi_param2regs(uf, tp, &uregs);
	if (rval == USB_SUCCESS)
		rval = uftdi_setregs(uf, &uregs);
	return (rval);
}

/*
 * ds_set_modem_ctl
 */
static int
uftdi_set_modem_ctl(ds_hdl_t hdl, uint_t portno, int mask, int val)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	int rval;
	uint16_t mctl;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh, "uftdi_set_modem_ctl");

	/*
	 * Note that we cannot set DTR and RTS simultaneously, so
	 * we do separate operations for each bit.
	 */

	if (mask & TIOCM_DTR) {
		mctl = (val & TIOCM_DTR) ?
		    FTDI_SIO_SET_DTR_HIGH : FTDI_SIO_SET_DTR_LOW;

		rval = uftdi_cmd_vendor_write0(uf,
		    FTDI_SIO_MODEM_CTRL, mctl, uf->uf_hwport);

		if (rval == USB_SUCCESS) {
			mutex_enter(&uf->uf_lock);
			uf->uf_mctl &= ~FTDI_SIO_SET_DTR_HIGH;
			uf->uf_mctl |= mctl & FTDI_SIO_SET_DTR_HIGH;
			mutex_exit(&uf->uf_lock);
		} else
			return (rval);
	}

	if (mask & TIOCM_RTS) {
		mctl = (val & TIOCM_RTS) ?
		    FTDI_SIO_SET_RTS_HIGH : FTDI_SIO_SET_RTS_LOW;

		rval = uftdi_cmd_vendor_write0(uf,
		    FTDI_SIO_MODEM_CTRL, mctl, uf->uf_hwport);

		if (rval == USB_SUCCESS) {
			mutex_enter(&uf->uf_lock);
			uf->uf_mctl &= ~FTDI_SIO_SET_RTS_HIGH;
			uf->uf_mctl |= mctl & FTDI_SIO_SET_RTS_HIGH;
			mutex_exit(&uf->uf_lock);
		}
	}

	return (rval);
}

/*
 * ds_get_modem_ctl
 */
static int
uftdi_get_modem_ctl(ds_hdl_t hdl, uint_t portno, int mask, int *valp)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	uint_t val = 0;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh, "uftdi_get_modem_ctl");

	mutex_enter(&uf->uf_lock);
	/*
	 * This status info is delivered to us at least every 40ms
	 * while the receive pipe is active
	 */
	if (uf->uf_msr & FTDI_MSR_STATUS_CTS)
		val |= TIOCM_CTS;
	if (uf->uf_msr & FTDI_MSR_STATUS_DSR)
		val |= TIOCM_DSR;
	if (uf->uf_msr & FTDI_MSR_STATUS_RI)
		val |= TIOCM_RI;
	if (uf->uf_msr & FTDI_MSR_STATUS_RLSD)
		val |= TIOCM_CD;

	/*
	 * Note, this status info is simply a replay of what we
	 * asked it to be in some previous "set" command, and
	 * is *not* directly sensed from the hardware.
	 */
	if ((uf->uf_mctl & FTDI_SIO_SET_RTS_HIGH) == FTDI_SIO_SET_RTS_HIGH)
		val |= TIOCM_RTS;
	if ((uf->uf_mctl & FTDI_SIO_SET_DTR_HIGH) == FTDI_SIO_SET_DTR_HIGH)
		val |= TIOCM_DTR;
	mutex_exit(&uf->uf_lock);

	*valp = val & mask;

	return (USB_SUCCESS);
}


/*
 * ds_break_ctl
 */
static int
uftdi_break_ctl(ds_hdl_t hdl, uint_t portno, int ctl)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	uftdi_regs_t *ur = &uf->uf_softr;
	uint16_t data;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh, "uftdi_break_ctl");

	mutex_enter(&uf->uf_lock);
	data = ur->ur_data | (ctl == DS_ON) ?  FTDI_SIO_SET_BREAK : 0;
	mutex_exit(&uf->uf_lock);

	return (uftdi_cmd_vendor_write0(uf, FTDI_SIO_SET_DATA,
	    data, uf->uf_hwport));
}


/*
 * ds_tx
 */
/*ARGSUSED*/
static int
uftdi_tx(ds_hdl_t hdl, uint_t portno, mblk_t *mp)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh, "uftdi_tx");

	ASSERT(mp != NULL && MBLKL(mp) >= 1);

	mutex_enter(&uf->uf_lock);
	uftdi_put_tail(&uf->uf_tx_mp, mp);	/* add to the chain */
	uftdi_tx_start(uf, NULL);
	mutex_exit(&uf->uf_lock);

	return (USB_SUCCESS);
}


/*
 * ds_rx
 */
/*ARGSUSED*/
static mblk_t *
uftdi_rx(ds_hdl_t hdl, uint_t portno)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	mblk_t *mp;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh, "uftdi_rx");

	mutex_enter(&uf->uf_lock);
	mp = uf->uf_rx_mp;
	uf->uf_rx_mp = NULL;
	mutex_exit(&uf->uf_lock);

	return (mp);
}


/*
 * ds_stop
 */
/*ARGSUSED*/
static void
uftdi_stop(ds_hdl_t hdl, uint_t portno, int dir)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh, "uftdi_stop");

	if (dir & DS_TX) {
		mutex_enter(&uf->uf_lock);
		uf->uf_port_flags |= UFTDI_PORT_TX_STOPPED;
		mutex_exit(&uf->uf_lock);
	}
}


/*
 * ds_start
 */
/*ARGSUSED*/
static void
uftdi_start(ds_hdl_t hdl, uint_t portno, int dir)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh, "uftdi_start");

	if (dir & DS_TX) {
		mutex_enter(&uf->uf_lock);
		if (uf->uf_port_flags & UFTDI_PORT_TX_STOPPED) {
			uf->uf_port_flags &= ~UFTDI_PORT_TX_STOPPED;
			uftdi_tx_start(uf, NULL);
		}
		mutex_exit(&uf->uf_lock);
	}
}


/*
 * ds_fifo_flush
 */
/*ARGSUSED*/
static int
uftdi_fifo_flush(ds_hdl_t hdl, uint_t portno, int dir)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh,
	    "uftdi_fifo_flush: dir=0x%x", dir);

	mutex_enter(&uf->uf_lock);
	ASSERT(uf->uf_port_state == UFTDI_PORT_OPEN);

	if (dir & DS_TX) {
		freemsg(uf->uf_tx_mp);
		uf->uf_tx_mp = NULL;
	}

	if (dir & DS_RX) {
		freemsg(uf->uf_rx_mp);
		uf->uf_rx_mp = NULL;
	}
	mutex_exit(&uf->uf_lock);

	if (dir & DS_TX)
		(void) uftdi_cmd_vendor_write0(uf,
		    FTDI_SIO_RESET, FTDI_SIO_RESET_PURGE_TX, uf->uf_hwport);

	if (dir & DS_RX)
		(void) uftdi_cmd_vendor_write0(uf,
		    FTDI_SIO_RESET, FTDI_SIO_RESET_PURGE_RX, uf->uf_hwport);

	return (USB_SUCCESS);
}


/*
 * ds_fifo_drain
 */
/*ARGSUSED*/
static int
uftdi_fifo_drain(ds_hdl_t hdl, uint_t portno, int timeout)
{
	uftdi_state_t *uf = (uftdi_state_t *)hdl;
	unsigned int count;
	const uint_t countmax = 50;	/* at least 500ms */
	const uint8_t txempty =
	    FTDI_LSR_STATUS_TEMT | FTDI_LSR_STATUS_THRE;

	ASSERT(portno == 0);

	USB_DPRINTF_L4(DPRINT_CTLOP, uf->uf_lh, "uftdi_fifo_drain");

	mutex_enter(&uf->uf_lock);
	ASSERT(uf->uf_port_state == UFTDI_PORT_OPEN);

	if (uftdi_wait_tx_drain(uf, 0) != USB_SUCCESS) {
		mutex_exit(&uf->uf_lock);
		return (USB_FAILURE);
	}

	/*
	 * Wait for the TX fifo to indicate empty.
	 *
	 * At all but the slowest baud rates, this is
	 * likely to be a one-shot test that instantly
	 * succeeds, but poll for at least 'countmax'
	 * tries before giving up.
	 */
	for (count = 0; count < countmax; count++) {
		if ((uf->uf_lsr & txempty) == txempty)
			break;
		mutex_exit(&uf->uf_lock);
		delay(drv_usectohz(10*1000));	/* 10ms */
		mutex_enter(&uf->uf_lock);
	}

	mutex_exit(&uf->uf_lock);

	return (count < countmax ? USB_SUCCESS : USB_FAILURE);
}


/*
 * configuration clean up
 */
static void
uftdi_cleanup(uftdi_state_t *uf, int level)
{
	ASSERT(level > 0 && level <= UFTDI_CLEANUP_LEVEL_MAX);

	switch (level) {
	default:
	case 6:
		uftdi_close_pipes(uf);
		/*FALLTHROUGH*/
	case 5:
		usb_unregister_event_cbs(uf->uf_dip, uf->uf_usb_events);
		/*FALLTHROUGH*/
	case 4:
		uftdi_destroy_pm_components(uf);
		/*FALLTHROUGH*/
	case 3:
		mutex_destroy(&uf->uf_lock);
		cv_destroy(&uf->uf_tx_cv);

		usb_free_log_hdl(uf->uf_lh);
		uf->uf_lh = NULL;

		usb_free_descr_tree(uf->uf_dip, uf->uf_dev_data);
		uf->uf_def_ph = NULL;
		/*FALLTHROUGH*/
	case 2:
		usb_client_detach(uf->uf_dip, uf->uf_dev_data);
		/*FALLTHROUGH*/
	case 1:
		kmem_free(uf, sizeof (*uf));
		break;
	}
}


/*
 * device specific attach
 */
static int
uftdi_dev_attach(uftdi_state_t *uf)
{
	return (uftdi_open_pipes(uf));
}


/*
 * restore device state after CPR resume or reconnect
 */
static int
uftdi_restore_device_state(uftdi_state_t *uf)
{
	int state;

	mutex_enter(&uf->uf_lock);
	state = uf->uf_dev_state;
	mutex_exit(&uf->uf_lock);

	if (state != USB_DEV_DISCONNECTED && state != USB_DEV_SUSPENDED)
		return (state);

	if (usb_check_same_device(uf->uf_dip, uf->uf_lh, USB_LOG_L0,
	    DPRINT_MASK_ALL, USB_CHK_ALL, NULL) != USB_SUCCESS) {
		mutex_enter(&uf->uf_lock);
		state = uf->uf_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&uf->uf_lock);
		return (state);
	}

	if (state == USB_DEV_DISCONNECTED) {
		USB_DPRINTF_L0(DPRINT_HOTPLUG, uf->uf_lh,
		    "Device has been reconnected but data may have been lost");
	}

	if (uftdi_reconnect_pipes(uf) != USB_SUCCESS)
		return (state);

	/*
	 * init device state
	 */
	mutex_enter(&uf->uf_lock);
	state = uf->uf_dev_state = USB_DEV_ONLINE;
	mutex_exit(&uf->uf_lock);

	if ((uftdi_restore_port_state(uf) != USB_SUCCESS)) {
		USB_DPRINTF_L2(DPRINT_HOTPLUG, uf->uf_lh,
		    "uftdi_restore_device_state: failed");
	}

	return (state);
}


/*
 * restore ports state after CPR resume or reconnect
 */
static int
uftdi_restore_port_state(uftdi_state_t *uf)
{
	int rval;

	mutex_enter(&uf->uf_lock);
	if (uf->uf_port_state != UFTDI_PORT_OPEN) {
		mutex_exit(&uf->uf_lock);
		return (USB_SUCCESS);
	}
	mutex_exit(&uf->uf_lock);

	/* open hardware serial port, restoring old settings */
	if ((rval = uftdi_open_hw_port(uf, 1)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_HOTPLUG, uf->uf_lh,
		    "uftdi_restore_port_state: failed");
	}

	return (rval);
}


/*
 * create PM components
 */
static int
uftdi_create_pm_components(uftdi_state_t *uf)
{
	dev_info_t	*dip = uf->uf_dip;
	uftdi_pm_t	*pm;
	uint_t		pwr_states;

	if (usb_create_pm_components(dip, &pwr_states) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_PM, uf->uf_lh,
		    "uftdi_create_pm_components: failed");
		return (USB_SUCCESS);
	}

	pm = uf->uf_pm = kmem_zalloc(sizeof (*pm), KM_SLEEP);

	pm->pm_pwr_states = (uint8_t)pwr_states;
	pm->pm_cur_power = USB_DEV_OS_FULL_PWR;
	pm->pm_wakeup_enabled = usb_handle_remote_wakeup(dip,
	    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS;

	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	return (USB_SUCCESS);
}


/*
 * destroy PM components
 */
static void
uftdi_destroy_pm_components(uftdi_state_t *uf)
{
	uftdi_pm_t *pm = uf->uf_pm;
	dev_info_t *dip = uf->uf_dip;
	int rval;

	if (!pm)
		return;

	if (uf->uf_dev_state != USB_DEV_DISCONNECTED) {
		if (pm->pm_wakeup_enabled) {
			rval = pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
			if (rval != DDI_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_PM, uf->uf_lh,
				    "uftdi_destroy_pm_components: "
				    "raising power failed, rval=%d", rval);
			}
			rval = usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE);
			if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_PM, uf->uf_lh,
				    "uftdi_destroy_pm_components: disable "
				    "remote wakeup failed, rval=%d", rval);
			}
		}
		(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);
	}
	kmem_free(pm, sizeof (*pm));
	uf->uf_pm = NULL;
}


/*
 * mark device busy and raise power
 */
static int
uftdi_pm_set_busy(uftdi_state_t *uf)
{
	uftdi_pm_t	*pm = uf->uf_pm;
	dev_info_t	*dip = uf->uf_dip;
	int		rval;

	USB_DPRINTF_L4(DPRINT_PM, uf->uf_lh, "uftdi_pm_set_busy");

	if (!pm)
		return (USB_SUCCESS);

	mutex_enter(&uf->uf_lock);
	/* if already marked busy, just increment the counter */
	if (pm->pm_busy_cnt++ > 0) {
		mutex_exit(&uf->uf_lock);
		return (USB_SUCCESS);
	}

	rval = pm_busy_component(dip, 0);
	ASSERT(rval == DDI_SUCCESS);

	if (pm->pm_cur_power == USB_DEV_OS_FULL_PWR) {
		mutex_exit(&uf->uf_lock);
		return (USB_SUCCESS);
	}

	/* need to raise power	*/
	pm->pm_raise_power = B_TRUE;
	mutex_exit(&uf->uf_lock);

	rval = pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	if (rval != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_PM, uf->uf_lh, "raising power failed");
	}

	mutex_enter(&uf->uf_lock);
	pm->pm_raise_power = B_FALSE;
	mutex_exit(&uf->uf_lock);

	return (USB_SUCCESS);
}


/*
 * mark device idle
 */
static void
uftdi_pm_set_idle(uftdi_state_t *uf)
{
	uftdi_pm_t *pm = uf->uf_pm;
	dev_info_t *dip = uf->uf_dip;

	USB_DPRINTF_L4(DPRINT_PM, uf->uf_lh, "uftdi_pm_set_idle");

	if (!pm)
		return;

	/*
	 * if more ports use the device, do not mark as yet
	 */
	mutex_enter(&uf->uf_lock);
	if (--pm->pm_busy_cnt > 0) {
		mutex_exit(&uf->uf_lock);
		return;
	}
	(void) pm_idle_component(dip, 0);
	mutex_exit(&uf->uf_lock);
}


/*
 * Functions to handle power transition for OS levels 0 -> 3
 * The same level as OS state, different from USB state
 */
static int
uftdi_pwrlvl0(uftdi_state_t *uf)
{
	int	rval;

	USB_DPRINTF_L4(DPRINT_PM, uf->uf_lh, "uftdi_pwrlvl0");

	switch (uf->uf_dev_state) {
	case USB_DEV_ONLINE:
		/* issue USB D3 command to the device */
		rval = usb_set_device_pwrlvl3(uf->uf_dip);
		ASSERT(rval == USB_SUCCESS);

		uf->uf_dev_state = USB_DEV_PWRED_DOWN;
		uf->uf_pm->pm_cur_power = USB_DEV_OS_PWR_OFF;

		/*FALLTHROUGH*/
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnect/cpr'ed device to go to lower power */
		return (USB_SUCCESS);
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(DPRINT_PM, uf->uf_lh,
		    "uftdi_pwrlvl0: illegal device state");
		return (USB_FAILURE);
	}
}


static int
uftdi_pwrlvl1(uftdi_state_t *uf)
{
	USB_DPRINTF_L4(DPRINT_PM, uf->uf_lh, "uftdi_pwrlvl1");

	/* issue USB D2 command to the device */
	(void) usb_set_device_pwrlvl2(uf->uf_dip);
	return (USB_FAILURE);
}


static int
uftdi_pwrlvl2(uftdi_state_t *uf)
{
	USB_DPRINTF_L4(DPRINT_PM, uf->uf_lh, "uftdi_pwrlvl2");

	/* issue USB D1 command to the device */
	(void) usb_set_device_pwrlvl1(uf->uf_dip);
	return (USB_FAILURE);
}


static int
uftdi_pwrlvl3(uftdi_state_t *uf)
{
	int rval;

	USB_DPRINTF_L4(DPRINT_PM, uf->uf_lh, "uftdi_pwrlvl3");

	switch (uf->uf_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(uf->uf_dip);
		ASSERT(rval == USB_SUCCESS);

		uf->uf_dev_state = USB_DEV_ONLINE;
		uf->uf_pm->pm_cur_power = USB_DEV_OS_FULL_PWR;

		/*FALLTHROUGH*/
	case USB_DEV_ONLINE:
		/* we are already in full power */

		/*FALLTHROUGH*/
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(DPRINT_PM, uf->uf_lh,
		    "uftdi_pwrlvl3: illegal device state");
		return (USB_FAILURE);
	}
}


/*
 * pipe operations
 */
static int
uftdi_open_pipes(uftdi_state_t *uf)
{
	int ifc, alt;
	usb_pipe_policy_t policy;
	usb_ep_data_t *in_data, *out_data;
	size_t max_xfer_sz;

	/* get max transfer size */
	if (usb_pipe_get_max_bulk_transfer_size(uf->uf_dip, &max_xfer_sz)
	    != USB_SUCCESS)
		return (USB_FAILURE);

	/* get ep data */
	ifc = uf->uf_dev_data->dev_curr_if;
	alt = 0;

	in_data = usb_lookup_ep_data(uf->uf_dip, uf->uf_dev_data, ifc, alt,
	    0, USB_EP_ATTR_BULK, USB_EP_DIR_IN);

	out_data = usb_lookup_ep_data(uf->uf_dip, uf->uf_dev_data, ifc, alt,
	    0, USB_EP_ATTR_BULK, USB_EP_DIR_OUT);

	if (in_data == NULL || out_data == NULL) {
		USB_DPRINTF_L2(DPRINT_ATTACH, uf->uf_lh,
		    "uftdi_open_pipes: can't get ep data");
		return (USB_FAILURE);
	}

	/*
	 * Set buffer sizes. Default to UFTDI_XFER_SZ_MAX.
	 * Use wMaxPacketSize from endpoint descriptor if it is nonzero.
	 * Cap at a max transfer size of host controller.
	 */
	uf->uf_ibuf_sz = uf->uf_obuf_sz = UFTDI_XFER_SZ_MAX;

	if (in_data->ep_descr.wMaxPacketSize)
		uf->uf_ibuf_sz = in_data->ep_descr.wMaxPacketSize;
	uf->uf_ibuf_sz = min(uf->uf_ibuf_sz, max_xfer_sz);

	if (out_data->ep_descr.wMaxPacketSize)
		uf->uf_obuf_sz = out_data->ep_descr.wMaxPacketSize;
	uf->uf_obuf_sz = min(uf->uf_obuf_sz, max_xfer_sz);

	/* open pipes */
	policy.pp_max_async_reqs = 2;

	if (usb_pipe_open(uf->uf_dip, &in_data->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &uf->uf_bulkin_ph) != USB_SUCCESS)
		return (USB_FAILURE);

	if (usb_pipe_open(uf->uf_dip, &out_data->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &uf->uf_bulkout_ph) != USB_SUCCESS) {
		usb_pipe_close(uf->uf_dip, uf->uf_bulkin_ph, USB_FLAGS_SLEEP,
		    NULL, NULL);
		return (USB_FAILURE);
	}

	mutex_enter(&uf->uf_lock);
	uf->uf_bulkin_state = UFTDI_PIPE_IDLE;
	uf->uf_bulkout_state = UFTDI_PIPE_IDLE;
	mutex_exit(&uf->uf_lock);

	return (USB_SUCCESS);
}


static void
uftdi_close_pipes(uftdi_state_t *uf)
{
	if (uf->uf_bulkin_ph)
		usb_pipe_close(uf->uf_dip, uf->uf_bulkin_ph,
		    USB_FLAGS_SLEEP, 0, 0);
	if (uf->uf_bulkout_ph)
		usb_pipe_close(uf->uf_dip, uf->uf_bulkout_ph,
		    USB_FLAGS_SLEEP, 0, 0);

	mutex_enter(&uf->uf_lock);
	uf->uf_bulkin_state = UFTDI_PIPE_CLOSED;
	uf->uf_bulkout_state = UFTDI_PIPE_CLOSED;
	mutex_exit(&uf->uf_lock);
}


static void
uftdi_disconnect_pipes(uftdi_state_t *uf)
{
	uftdi_close_pipes(uf);
}


static int
uftdi_reconnect_pipes(uftdi_state_t *uf)
{
	return (uftdi_open_pipes(uf));
}


static void
uftdi_rxerr_put(mblk_t **rx_mpp, mblk_t *data, uint8_t lsr)
{
	uchar_t errflg;

	if (lsr & FTDI_LSR_STATUS_BI) {
		/*
		 * parity and framing errors only "count" if they
		 * occur independently of a break being received.
		 */
		lsr &= ~(uint8_t)(FTDI_LSR_STATUS_PE | FTDI_LSR_STATUS_FE);
	}
	errflg =
	    ((lsr & FTDI_LSR_STATUS_OE) ? DS_OVERRUN_ERR : 0) |
	    ((lsr & FTDI_LSR_STATUS_PE) ? DS_PARITY_ERR : 0) |
	    ((lsr & FTDI_LSR_STATUS_FE) ? DS_FRAMING_ERR : 0) |
	    ((lsr & FTDI_LSR_STATUS_BI) ? DS_BREAK_ERR : 0);

	/*
	 * If there's no actual data, we send a NUL character along
	 * with the error flags.  Otherwise, the data mblk contains
	 * some number of highly questionable characters.
	 *
	 * According to FTDI tech support, there is no synchronous
	 * error reporting i.e. we cannot assume that only the
	 * first character in the mblk is bad -- so we treat all
	 * of them them as if they have the error noted in the LSR.
	 */
	do {
		mblk_t *mp;
		uchar_t c = (MBLKL(data) == 0) ? '\0' : *data->b_rptr++;

		if ((mp = allocb(2, BPRI_HI)) != NULL) {
			DB_TYPE(mp) = M_BREAK;
			*mp->b_wptr++ = errflg;
			*mp->b_wptr++ = c;
			uftdi_put_tail(rx_mpp, mp);
		} else {
			/*
			 * low memory - just discard the bad data
			 */
			data->b_rptr = data->b_wptr;
			break;
		}
	} while (MBLKL(data) > 0);
}


/*
 * bulk in pipe normal and exception callback handler
 */
/*ARGSUSED*/
static void
uftdi_bulkin_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	uftdi_state_t *uf = (uftdi_state_t *)req->bulk_client_private;
	mblk_t *data;
	int data_len;

	data = req->bulk_data;
	data_len = data ? MBLKL(data) : 0;

	/*
	 * The first two bytes of data are status register bytes
	 * that arrive with every packet from the device.  Process
	 * them here before handing the rest of the data on.
	 *
	 * When active, the device will send us these bytes at least
	 * every 40 milliseconds, even if there's no received data.
	 */
	if (req->bulk_completion_reason == USB_CR_OK && data_len >= 2) {
		uint8_t msr = FTDI_GET_MSR(data->b_rptr);
		uint8_t lsr = FTDI_GET_LSR(data->b_rptr);
		int new_rx_err;

		data->b_rptr += 2;

		mutex_enter(&uf->uf_lock);

		if (uf->uf_msr != msr) {
			/*
			 * modem status register changed
			 */
			USB_DPRINTF_L3(DPRINT_IN_PIPE, uf->uf_lh,
			    "uftdi_bulkin_cb: new msr: 0x%02x -> 0x%02x",
			    uf->uf_msr, msr);

			uf->uf_msr = msr;

			if (uf->uf_port_state == UFTDI_PORT_OPEN &&
			    uf->uf_cb.cb_status) {
				mutex_exit(&uf->uf_lock);
				uf->uf_cb.cb_status(uf->uf_cb.cb_arg);
				mutex_enter(&uf->uf_lock);
			}
		}

		if ((uf->uf_lsr & FTDI_LSR_MASK) != (lsr & FTDI_LSR_MASK)) {
			/*
			 * line status register *receive* bits changed
			 *
			 * (The THRE and TEMT (transmit) status bits are
			 * masked out above.)
			 */
			USB_DPRINTF_L3(DPRINT_IN_PIPE, uf->uf_lh,
			    "uftdi_bulkin_cb: new lsr: 0x%02x -> 0x%02x",
			    uf->uf_lsr, lsr);
			new_rx_err = B_TRUE;
		} else
			new_rx_err = B_FALSE;

		uf->uf_lsr = lsr;	/* THRE and TEMT captured here */

		if ((lsr & FTDI_LSR_MASK) != 0 &&
		    (MBLKL(data) > 0 || new_rx_err) &&
		    uf->uf_port_state == UFTDI_PORT_OPEN) {
			/*
			 * The current line status register value indicates
			 * that there's been some sort of unusual condition
			 * on the receive side.  We either received a break,
			 * or got some badly formed characters from the
			 * serial port - framing errors, overrun, parity etc.
			 * So there's either some new data to post, or a
			 * new error (break) to post, or both.
			 *
			 * Invoke uftdi_rxerr_put() to place the inbound
			 * characters as M_BREAK messages on the receive
			 * mblk chain, decorated with error flag(s) for
			 * upper-level modules (e.g. ldterm) to process.
			 */
			mutex_exit(&uf->uf_lock);
			uftdi_rxerr_put(&uf->uf_rx_mp, data, lsr);
			ASSERT(MBLKL(data) == 0);

			/*
			 * Since we've converted all the received
			 * characters into M_BREAK messages, we
			 * invoke the rx callback to shove the mblks
			 * up the STREAM.
			 */
			if (uf->uf_cb.cb_rx)
				uf->uf_cb.cb_rx(uf->uf_cb.cb_arg);
			mutex_enter(&uf->uf_lock);
		}

		mutex_exit(&uf->uf_lock);
		data_len = MBLKL(data);
	}

	USB_DPRINTF_L4(DPRINT_IN_PIPE, uf->uf_lh, "uftdi_bulkin_cb: "
	    "cr=%d len=%d", req->bulk_completion_reason, data_len);

	/* save data and notify GSD */
	if (data_len > 0 &&
	    uf->uf_port_state == UFTDI_PORT_OPEN &&
	    req->bulk_completion_reason == USB_CR_OK) {
		req->bulk_data = NULL;
		uftdi_put_tail(&uf->uf_rx_mp, data);
		if (uf->uf_cb.cb_rx)
			uf->uf_cb.cb_rx(uf->uf_cb.cb_arg);
	}

	usb_free_bulk_req(req);

	/* receive more */
	mutex_enter(&uf->uf_lock);
	uf->uf_bulkin_state = UFTDI_PIPE_IDLE;
	if (uf->uf_port_state == UFTDI_PORT_OPEN &&
	    uf->uf_dev_state == USB_DEV_ONLINE) {
		if (uftdi_rx_start(uf) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_IN_PIPE, uf->uf_lh,
			    "uftdi_bulkin_cb: restart rx fail");
		}
	}
	mutex_exit(&uf->uf_lock);
}


/*
 * bulk out common and exception callback
 */
/*ARGSUSED*/
static void
uftdi_bulkout_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	uftdi_state_t	*uf = (uftdi_state_t *)req->bulk_client_private;
	int		data_len;
	mblk_t		*data = req->bulk_data;

	data_len = data ? MBLKL(data) : 0;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, uf->uf_lh,
	    "uftdi_bulkout_cb: cr=%d len=%d",
	    req->bulk_completion_reason, data_len);

	if (uf->uf_port_state == UFTDI_PORT_OPEN &&
	    req->bulk_completion_reason && data_len > 0) {
		uftdi_put_head(&uf->uf_tx_mp, data);
		req->bulk_data = NULL;
	}

	usb_free_bulk_req(req);

	/* notify GSD */
	if (uf->uf_cb.cb_tx)
		uf->uf_cb.cb_tx(uf->uf_cb.cb_arg);

	/* send more */
	mutex_enter(&uf->uf_lock);
	uf->uf_bulkout_state = UFTDI_PIPE_IDLE;
	if (uf->uf_tx_mp == NULL)
		cv_broadcast(&uf->uf_tx_cv);
	else
		uftdi_tx_start(uf, NULL);
	mutex_exit(&uf->uf_lock);
}


/*
 * start receiving data
 */
static int
uftdi_rx_start(uftdi_state_t *uf)
{
	usb_bulk_req_t *br;
	int rval;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, uf->uf_lh, "uftdi_rx_start");

	ASSERT(mutex_owned(&uf->uf_lock));

	uf->uf_bulkin_state = UFTDI_PIPE_BUSY;
	mutex_exit(&uf->uf_lock);

	br = usb_alloc_bulk_req(uf->uf_dip, uf->uf_ibuf_sz, USB_FLAGS_SLEEP);
	br->bulk_len = uf->uf_ibuf_sz;
	br->bulk_timeout = UFTDI_BULKIN_TIMEOUT;
	br->bulk_cb = uftdi_bulkin_cb;
	br->bulk_exc_cb = uftdi_bulkin_cb;
	br->bulk_client_private = (usb_opaque_t)uf;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING | USB_ATTRS_SHORT_XFER_OK;

	rval = usb_pipe_bulk_xfer(uf->uf_bulkin_ph, br, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_IN_PIPE, uf->uf_lh,
		    "uftdi_rx_start: xfer failed %d", rval);
		usb_free_bulk_req(br);
	}

	mutex_enter(&uf->uf_lock);
	if (rval != USB_SUCCESS)
		uf->uf_bulkin_state = UFTDI_PIPE_IDLE;

	return (rval);
}


/*
 * start data transmit
 */
static void
uftdi_tx_start(uftdi_state_t *uf, int *xferd)
{
	int		len;		/* bytes we can transmit */
	mblk_t		*data;		/* data to be transmitted */
	int		data_len;	/* bytes in 'data' */
	mblk_t		*mp;		/* current msgblk */
	int		copylen;	/* bytes copy from 'mp' to 'data' */
	int		rval;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, uf->uf_lh, "uftdi_tx_start");
	ASSERT(mutex_owned(&uf->uf_lock));
	ASSERT(uf->uf_port_state != UFTDI_PORT_CLOSED);

	if (xferd)
		*xferd = 0;
	if ((uf->uf_port_flags & UFTDI_PORT_TX_STOPPED) ||
	    uf->uf_tx_mp == NULL) {
		return;
	}
	if (uf->uf_bulkout_state != UFTDI_PIPE_IDLE) {
		USB_DPRINTF_L4(DPRINT_OUT_PIPE, uf->uf_lh,
		    "uftdi_tx_start: pipe busy");
		return;
	}
	ASSERT(MBLKL(uf->uf_tx_mp) > 0);

	/* send as much data as port can receive */
	len = min(msgdsize(uf->uf_tx_mp), uf->uf_obuf_sz);

	if (len <= 0)
		return;
	if ((data = allocb(len, BPRI_LO)) == NULL)
		return;

	/*
	 * copy no more than 'len' bytes from mblk chain to transmit mblk 'data'
	 */
	data_len = 0;
	while (data_len < len && uf->uf_tx_mp) {
		mp = uf->uf_tx_mp;
		copylen = min(MBLKL(mp), len - data_len);
		bcopy(mp->b_rptr, data->b_wptr, copylen);
		mp->b_rptr += copylen;
		data->b_wptr += copylen;
		data_len += copylen;

		if (MBLKL(mp) < 1) {
			uf->uf_tx_mp = unlinkb(mp);
			freeb(mp);
		} else {
			ASSERT(data_len == len);
		}
	}

	ASSERT(data_len > 0);

	uf->uf_bulkout_state = UFTDI_PIPE_BUSY;
	mutex_exit(&uf->uf_lock);

	rval = uftdi_send_data(uf, data);
	mutex_enter(&uf->uf_lock);

	if (rval != USB_SUCCESS) {
		uf->uf_bulkout_state = UFTDI_PIPE_IDLE;
		uftdi_put_head(&uf->uf_tx_mp, data);
	} else {
		if (xferd)
			*xferd = data_len;
	}
}


static int
uftdi_send_data(uftdi_state_t *uf, mblk_t *data)
{
	usb_bulk_req_t *br;
	int len = MBLKL(data);
	int rval;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, uf->uf_lh,
	    "uftdi_send_data: %d 0x%x 0x%x 0x%x", len, data->b_rptr[0],
	    (len > 1) ? data->b_rptr[1] : 0, (len > 2) ? data->b_rptr[2] : 0);

	ASSERT(!mutex_owned(&uf->uf_lock));

	br = usb_alloc_bulk_req(uf->uf_dip, 0, USB_FLAGS_SLEEP);
	br->bulk_data = data;
	br->bulk_len = len;
	br->bulk_timeout = UFTDI_BULKOUT_TIMEOUT;
	br->bulk_cb = uftdi_bulkout_cb;
	br->bulk_exc_cb = uftdi_bulkout_cb;
	br->bulk_client_private = (usb_opaque_t)uf;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING;

	rval = usb_pipe_bulk_xfer(uf->uf_bulkout_ph, br, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_OUT_PIPE, uf->uf_lh,
		    "uftdi_send_data: xfer failed %d", rval);
		br->bulk_data = NULL;
		usb_free_bulk_req(br);
	}

	return (rval);
}


/*
 * wait until local tx buffer drains.
 * 'timeout' is in seconds, zero means wait forever
 */
static int
uftdi_wait_tx_drain(uftdi_state_t *uf, int timeout)
{
	clock_t	until;
	int over = 0;

	until = ddi_get_lbolt() + drv_usectohz(1000 * 1000 * timeout);

	while (uf->uf_tx_mp && !over) {
		if (timeout > 0) {
			/* whether timedout or signal pending */
			over = cv_timedwait_sig(&uf->uf_tx_cv,
			    &uf->uf_lock, until) <= 0;
		} else {
			/* whether a signal is pending */
			over = cv_wait_sig(&uf->uf_tx_cv,
			    &uf->uf_lock) == 0;
		}
	}

	return (uf->uf_tx_mp == NULL ? USB_SUCCESS : USB_FAILURE);
}

/*
 * initialize hardware serial port
 */
static int
uftdi_open_hw_port(uftdi_state_t *uf, int dorestore)
{
	int rval;

	/*
	 * Perform a full reset on the device
	 */
	rval = uftdi_cmd_vendor_write0(uf,
	    FTDI_SIO_RESET, FTDI_SIO_RESET_SIO, uf->uf_hwport);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_DEF_PIPE, uf->uf_lh,
		    "uftdi_open_hw_port: failed to reset!");
		return (rval);
	}

	if (dorestore) {
		/*
		 * Restore settings from our soft copy of HW registers
		 */
		(void) uftdi_setregs(uf, NULL);
	} else {
		/*
		 * 9600 baud, 2 stop bits, no parity, 8-bit, h/w flow control
		 */
		static ds_port_param_entry_t ents[] = {
#if defined(__lock_lint)
			/*
			 * (Sigh - wlcc doesn't understand this newer
			 * form of structure member initialization.)
			 */
			{ 0 }
#else
			{ DS_PARAM_BAUD,	.val.ui = B9600 },
			{ DS_PARAM_STOPB,	.val.ui = CSTOPB },
			{ DS_PARAM_PARITY,	.val.ui = 0 },
			{ DS_PARAM_CHARSZ,	.val.ui = CS8 },
			{ DS_PARAM_FLOW_CTL,	.val.ui = CTSXON }
#endif
		};
		static ds_port_params_t params = {
			ents,
			sizeof (ents) / sizeof (ents[0])
		};

		rval = uftdi_set_port_params(uf, 0, &params);
		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_DEF_PIPE, uf->uf_lh,
			    "uftdi_open_hw_port: failed 9600/2/n/8 rval %d",
			    rval);
		}
	}

	return (rval);
}

static int
uftdi_cmd_vendor_write0(uftdi_state_t *uf,
    uint16_t reqno, uint16_t val, uint16_t idx)
{
	usb_ctrl_setup_t req;
	usb_cb_flags_t cb_flags;
	usb_cr_t cr;
	int rval;

	ASSERT(!mutex_owned(&uf->uf_lock));

	req.bmRequestType =
	    USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_HOST_TO_DEV;
	req.bRequest = (uchar_t)reqno;
	req.wValue = val;
	req.wIndex = idx;
	req.wLength = 0;
	req.attrs = USB_ATTRS_NONE;

	if ((rval = usb_pipe_ctrl_xfer_wait(uf->uf_def_ph,
	    &req, NULL, &cr, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_DEF_PIPE, uf->uf_lh,
		    "uftdi_cmd_vendor_write0: 0x%x 0x%x 0x%x failed %d %d 0x%x",
		    reqno, val, idx, rval, cr, cb_flags);
	}

	return (rval);
}

/*
 * misc routines
 */

/*
 * link a message block to tail of message
 * account for the case when message is null
 */
static void
uftdi_put_tail(mblk_t **mpp, mblk_t *bp)
{
	if (*mpp)
		linkb(*mpp, bp);
	else
		*mpp = bp;
}

/*
 * put a message block at the head of the message
 * account for the case when message is null
 */
static void
uftdi_put_head(mblk_t **mpp, mblk_t *bp)
{
	if (*mpp)
		linkb(bp, *mpp);
	*mpp = bp;
}

/*ARGSUSED*/
static usb_pipe_handle_t
uftdi_out_pipe(ds_hdl_t hdl, uint_t portno)
{
	ASSERT(portno == 0);

	return (((uftdi_state_t *)hdl)->uf_bulkout_ph);
}

/*ARGSUSED*/
static usb_pipe_handle_t
uftdi_in_pipe(ds_hdl_t hdl, uint_t portno)
{
	ASSERT(portno == 0);

	return (((uftdi_state_t *)hdl)->uf_bulkin_ph);
}
