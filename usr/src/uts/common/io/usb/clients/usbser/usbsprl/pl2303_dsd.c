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
 * USB Prolific PL2303 device-specific driver (DSD)
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
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/usba_impl.h>

#include <sys/usb/clients/usbser/usbser_dsdi.h>
#include <sys/usb/clients/usbser/usbsprl/pl2303_var.h>
#include <sys/usb/clients/usbser/usbsprl/pl2303_vendor.h>


/*
 * DSD operations
 */
static int	pl2303_attach(ds_attach_info_t *);
static void	pl2303_detach(ds_hdl_t);
static int	pl2303_register_cb(ds_hdl_t, uint_t, ds_cb_t *);
static void	pl2303_unregister_cb(ds_hdl_t, uint_t);
static int	pl2303_open_port(ds_hdl_t, uint_t);
static int	pl2303_close_port(ds_hdl_t, uint_t);

/* power management */
static int	pl2303_usb_power(ds_hdl_t, int, int, int *);
static int	pl2303_suspend(ds_hdl_t);
static int	pl2303_resume(ds_hdl_t);
static int	pl2303_disconnect(ds_hdl_t);
static int	pl2303_reconnect(ds_hdl_t);

/* standard UART operations */
static int	pl2303_set_port_params(ds_hdl_t, uint_t, ds_port_params_t *);
static int	pl2303_set_modem_ctl(ds_hdl_t, uint_t, int, int);
static int	pl2303_get_modem_ctl(ds_hdl_t, uint_t, int, int *);
static int	pl2303_break_ctl(ds_hdl_t, uint_t, int);

/* data xfer */
static int	pl2303_tx(ds_hdl_t, uint_t, mblk_t *);
static mblk_t	*pl2303_rx(ds_hdl_t, uint_t);
static void	pl2303_stop(ds_hdl_t, uint_t, int);
static void	pl2303_start(ds_hdl_t, uint_t, int);
static int	pl2303_fifo_flush(ds_hdl_t, uint_t, int);
static int	pl2303_fifo_drain(ds_hdl_t, uint_t, int);

/* polled I/O support */
static usb_pipe_handle_t pl2303_out_pipe(ds_hdl_t, uint_t);
static usb_pipe_handle_t pl2303_in_pipe(ds_hdl_t, uint_t);

/*
 * Sub-routines
 */

/* configuration routines */
static void	pl2303_cleanup(pl2303_state_t *, int);
static int	pl2303_dev_attach(pl2303_state_t *);
static int	pl2303_open_hw_port(pl2303_state_t *);

/* hotplug */
static int	pl2303_restore_device_state(pl2303_state_t *);
static int	pl2303_restore_port_state(pl2303_state_t *);

/* power management */
static int	pl2303_create_pm_components(pl2303_state_t *);
static void	pl2303_destroy_pm_components(pl2303_state_t *);
static int	pl2303_pm_set_busy(pl2303_state_t *);
static void	pl2303_pm_set_idle(pl2303_state_t *);
static int	pl2303_pwrlvl0(pl2303_state_t *);
static int	pl2303_pwrlvl1(pl2303_state_t *);
static int	pl2303_pwrlvl2(pl2303_state_t *);
static int	pl2303_pwrlvl3(pl2303_state_t *);

/* pipe operations */
static int	pl2303_open_pipes(pl2303_state_t *);
static void	pl2303_close_pipes(pl2303_state_t *);
static void	pl2303_disconnect_pipes(pl2303_state_t *);
static int	pl2303_reconnect_pipes(pl2303_state_t *);

/* pipe callbacks */
void		pl2303_bulkin_cb(usb_pipe_handle_t, usb_bulk_req_t *);
void		pl2303_bulkout_cb(usb_pipe_handle_t, usb_bulk_req_t *);

/* data transfer routines */
static int	pl2303_rx_start(pl2303_state_t *);
static void	pl2303_tx_start(pl2303_state_t *, int *);
static int	pl2303_send_data(pl2303_state_t *, mblk_t *);
static int	pl2303_wait_tx_drain(pl2303_state_t *, int);

/* vendor-specific commands */
static int	pl2303_cmd_get_line(pl2303_state_t *, mblk_t **);
static int	pl2303_cmd_set_line(pl2303_state_t *, mblk_t *);
static int	pl2303_cmd_set_ctl(pl2303_state_t *, uint8_t);
static int	pl2303_cmd_vendor_write0(pl2303_state_t *, uint16_t, int16_t);
static int	pl2303_cmd_set_rtscts(pl2303_state_t *);
static int	pl2303_cmd_break(pl2303_state_t *, int);
static void	pl2303_mctl2reg(int mask, int val, uint8_t *);
static int	pl2303_reg2mctl(uint8_t);

/* misc */
static void	pl2303_put_tail(mblk_t **, mblk_t *);
static void	pl2303_put_head(mblk_t **, mblk_t *);


/*
 * DSD ops structure
 */
ds_ops_t ds_ops = {
	DS_OPS_VERSION,
	pl2303_attach,
	pl2303_detach,
	pl2303_register_cb,
	pl2303_unregister_cb,
	pl2303_open_port,
	pl2303_close_port,
	pl2303_usb_power,
	pl2303_suspend,
	pl2303_resume,
	pl2303_disconnect,
	pl2303_reconnect,
	pl2303_set_port_params,
	pl2303_set_modem_ctl,
	pl2303_get_modem_ctl,
	pl2303_break_ctl,
	NULL,			/* HW don't support loopback */
	pl2303_tx,
	pl2303_rx,
	pl2303_stop,
	pl2303_start,
	pl2303_fifo_flush,
	pl2303_fifo_drain,
	pl2303_out_pipe,
	pl2303_in_pipe
};


/*
 * baud code into baud rate
 * value 0 means not supported in hardware
 *
 */
static int pl2303_speedtab[] = {
	0,	/* B0 */
	0,	/* B50 */
	75,	/* B75 */
	0,	/* B110 */
	0,	/* B134 */
	150,	/* B150 */
	0,	/* B200 */
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
	0,	/* B76800 */
	115200,	/* B115200 */
	0,	/* B153600 */
	230400,	/* B230400 */
	0,	/* B307200 */
	460800	/* B460800 */
};


/* debug support */
static uint_t	pl2303_errlevel = USB_LOG_L4;
static uint_t	pl2303_errmask = DPRINT_MASK_ALL;
static uint_t	pl2303_instance_debug = (uint_t)-1;


/*
 * ds_attach
 */
static int
pl2303_attach(ds_attach_info_t *aip)
{
	pl2303_state_t	*plp;

	plp = (pl2303_state_t *)kmem_zalloc(sizeof (pl2303_state_t), KM_SLEEP);
	plp->pl_dip = aip->ai_dip;
	plp->pl_usb_events = aip->ai_usb_events;
	*aip->ai_hdl = (ds_hdl_t)plp;

	/* only one port */
	*aip->ai_port_cnt = 1;

	if (usb_client_attach(plp->pl_dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		pl2303_cleanup(plp, 1);

		return (USB_FAILURE);
	}

	if (usb_get_dev_data(plp->pl_dip, &plp->pl_dev_data,  USB_PARSE_LVL_IF,
	    0) != USB_SUCCESS) {
		pl2303_cleanup(plp, 2);

		return (USB_FAILURE);
	}

	mutex_init(&plp->pl_mutex, NULL, MUTEX_DRIVER,
	    plp->pl_dev_data->dev_iblock_cookie);

	cv_init(&plp->pl_tx_cv, NULL, CV_DRIVER, NULL);

	plp->pl_lh = usb_alloc_log_hdl(plp->pl_dip, "pl2303",
	    &pl2303_errlevel, &pl2303_errmask, &pl2303_instance_debug, 0);

	/*
	 * Check the chip type: pl2303_H, pl2303_X (or pl2303_HX(Chip A)),
	 * pl2303_HX(Chip D).
	 * pl2303_UNKNOWN means not supported chip type.
	 */
	if (plp->pl_dev_data->dev_descr->bcdDevice == PROLIFIC_REV_H) {
		mutex_enter(&plp->pl_mutex);
		plp->pl_chiptype = pl2303_H;
		mutex_exit(&plp->pl_mutex);
		USB_DPRINTF_L3(DPRINT_ATTACH, plp->pl_lh,
		    "Chip Type: pl2303_H");
	} else if (plp->pl_dev_data->dev_descr->bcdDevice == PROLIFIC_REV_X) {
		/*
		 * pl2303_HX(Chip A)and pl2303_X devices have different
		 * hardware, but from the view of device driver, they have
		 * the same software interface.
		 *
		 * So "pl2303_X" will stand for both pl2303_HX(Chip A)and
		 * pl2303_X devices in this driver.
		 */
		mutex_enter(&plp->pl_mutex);
		plp->pl_chiptype = pl2303_X;
		mutex_exit(&plp->pl_mutex);
		USB_DPRINTF_L3(DPRINT_ATTACH, plp->pl_lh,
		    "Chip Type: pl2303_HX(Chip A) or pl2303_X");
	} else if (plp->pl_dev_data->dev_descr->bcdDevice ==
	    PROLIFIC_REV_HX_CHIP_D) {
		mutex_enter(&plp->pl_mutex);
		plp->pl_chiptype = pl2303_HX_CHIP_D;
		mutex_exit(&plp->pl_mutex);
		USB_DPRINTF_L3(DPRINT_ATTACH, plp->pl_lh,
		    "Chip Type: pl2303_HX(Chip D)");
	} else if (plp->pl_dev_data->dev_descr->bcdDevice == PROLIFIC_REV_1) {
		/* IO DATA USB-RSAQ3(usb67b,aaa2) uses pl2303_X chip */
		mutex_enter(&plp->pl_mutex);
		plp->pl_chiptype = pl2303_X;
		mutex_exit(&plp->pl_mutex);
		USB_DPRINTF_L3(DPRINT_ATTACH, plp->pl_lh,
		    "Chip Type: pl2303_X with revison number=1");
	} else {
		mutex_enter(&plp->pl_mutex);
		plp->pl_chiptype = pl2303_UNKNOWN;
		mutex_exit(&plp->pl_mutex);
		USB_DPRINTF_L3(DPRINT_ATTACH, plp->pl_lh,
		    "Chip Type: Unknown");
	}

	plp->pl_def_ph = plp->pl_dev_data->dev_default_ph;

	mutex_enter(&plp->pl_mutex);
	plp->pl_dev_state = USB_DEV_ONLINE;
	plp->pl_port_state = PL2303_PORT_CLOSED;
	mutex_exit(&plp->pl_mutex);

	if (pl2303_create_pm_components(plp) != USB_SUCCESS) {
		pl2303_cleanup(plp, 3);

		return (USB_FAILURE);
	}

	if (usb_register_event_cbs(plp->pl_dip, plp->pl_usb_events, 0)
	    != USB_SUCCESS) {
		pl2303_cleanup(plp, 4);

		return (USB_FAILURE);
	}

	if (usb_pipe_get_max_bulk_transfer_size(plp->pl_dip,
	    &plp->pl_xfer_sz) != USB_SUCCESS) {
		pl2303_cleanup(plp, 5);

		return (USB_FAILURE);
	}

	if (plp->pl_xfer_sz > PL2303_XFER_SZ_MAX) {
		plp->pl_xfer_sz = PL2303_XFER_SZ_MAX;
	}

	if (pl2303_dev_attach(plp) != USB_SUCCESS) {
		pl2303_cleanup(plp, 5);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * ds_detach
 */
static void
pl2303_detach(ds_hdl_t hdl)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	pl2303_cleanup(plp, PL2303_CLEANUP_LEVEL_MAX);
}


/*
 * ds_register_cb
 */
/*ARGSUSED*/
static int
pl2303_register_cb(ds_hdl_t hdl, uint_t port_num, ds_cb_t *cb)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	plp->pl_cb = *cb;

	return (USB_SUCCESS);
}


/*
 * ds_unregister_cb
 */
/*ARGSUSED*/
static void
pl2303_unregister_cb(ds_hdl_t hdl, uint_t port_num)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	bzero(&plp->pl_cb, sizeof (plp->pl_cb));
}


/*
 * ds_open_port
 */
/*ARGSUSED*/
static int
pl2303_open_port(ds_hdl_t hdl, uint_t port_num)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	int		rval = USB_FAILURE;

	USB_DPRINTF_L4(DPRINT_OPEN, plp->pl_lh, "pl2303_open_port");

	mutex_enter(&plp->pl_mutex);
	if ((plp->pl_dev_state == USB_DEV_DISCONNECTED) ||
	    (plp->pl_port_state != PL2303_PORT_CLOSED)) {
		mutex_exit(&plp->pl_mutex);

		return (rval);
	}

	mutex_exit(&plp->pl_mutex);

	if ((rval = pl2303_pm_set_busy(plp)) != USB_SUCCESS) {

		return (rval);
	}

	/* initialize hardware serial port */
	rval = pl2303_open_hw_port(plp);

	if (rval == USB_SUCCESS) {
		mutex_enter(&plp->pl_mutex);

		/* start to receive data */
		if (pl2303_rx_start(plp) != USB_SUCCESS) {
			mutex_exit(&plp->pl_mutex);

			return (USB_FAILURE);
		}
		plp->pl_port_state = PL2303_PORT_OPEN;
		mutex_exit(&plp->pl_mutex);
	} else {
		pl2303_pm_set_idle(plp);
	}

	return (rval);
}


/*
 * ds_close_port
 */
/*ARGSUSED*/
static int
pl2303_close_port(ds_hdl_t hdl, uint_t port_num)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_CLOSE, plp->pl_lh, "pl2303_close_port");

	mutex_enter(&plp->pl_mutex);

	/* free resources and finalize state */
	if (plp->pl_rx_mp) {
		freemsg(plp->pl_rx_mp);
		plp->pl_rx_mp = NULL;
	}
	if (plp->pl_tx_mp) {
		freemsg(plp->pl_tx_mp);
		plp->pl_tx_mp = NULL;
	}

	plp->pl_port_state = PL2303_PORT_CLOSED;
	mutex_exit(&plp->pl_mutex);

	pl2303_pm_set_idle(plp);

	return (USB_SUCCESS);
}


/*
 * power management
 * ----------------
 *
 * ds_usb_power
 */
/*ARGSUSED*/
static int
pl2303_usb_power(ds_hdl_t hdl, int comp, int level, int *new_state)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	pl2303_pm_t	*pm = plp->pl_pm;
	int		rval;

	USB_DPRINTF_L4(DPRINT_PM, plp->pl_lh, "pl2303_usb_power");

	if (!pm) {

		return (USB_FAILURE);
	}

	mutex_enter(&plp->pl_mutex);
	/*
	 * check if we are transitioning to a legal power level
	 */
	if (USB_DEV_PWRSTATE_OK(pm->pm_pwr_states, level)) {
		USB_DPRINTF_L2(DPRINT_PM, plp->pl_lh, "pl2303_usb_power: "
		    "illegal power level %d, pwr_states=%x",
		    level, pm->pm_pwr_states);
		mutex_exit(&plp->pl_mutex);

		return (USB_FAILURE);
	}

	/*
	 * if we are about to raise power and asked to lower power, fail
	 */
	if (pm->pm_raise_power && (level < (int)pm->pm_cur_power)) {
		mutex_exit(&plp->pl_mutex);

		return (USB_FAILURE);
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		rval = pl2303_pwrlvl0(plp);

		break;
	case USB_DEV_OS_PWR_1:
		rval = pl2303_pwrlvl1(plp);

		break;
	case USB_DEV_OS_PWR_2:
		rval = pl2303_pwrlvl2(plp);

		break;
	case USB_DEV_OS_FULL_PWR:
		rval = pl2303_pwrlvl3(plp);
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
			plp->pl_dev_state = *new_state;
		}

		break;
	default:
		ASSERT(0);	/* cannot happen */
	}

	*new_state = plp->pl_dev_state;
	mutex_exit(&plp->pl_mutex);

	return (rval);
}


/*
 * ds_suspend
 */
static int
pl2303_suspend(ds_hdl_t hdl)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	int		state = USB_DEV_SUSPENDED;

	USB_DPRINTF_L4(DPRINT_PM, plp->pl_lh, "pl2303_suspend");

	/*
	 * If the device is suspended while it is under PWRED_DOWN state, we
	 * need to keep the PWRED_DOWN state so that it could be powered up
	 * later. In the mean while, usbser dev state will be changed to
	 * SUSPENDED state.
	 */
	mutex_enter(&plp->pl_mutex);
	if (plp->pl_dev_state != USB_DEV_PWRED_DOWN) {
		plp->pl_dev_state = USB_DEV_SUSPENDED;
	}
	mutex_exit(&plp->pl_mutex);

	pl2303_disconnect_pipes(plp);

	return (state);
}


/*
 * ds_resume
 */
static int
pl2303_resume(ds_hdl_t hdl)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	int		current_state;
	int		rval;

	USB_DPRINTF_L4(DPRINT_PM, plp->pl_lh, "pl2303_resume");

	mutex_enter(&plp->pl_mutex);
	current_state = plp->pl_dev_state;
	mutex_exit(&plp->pl_mutex);

	if (current_state != USB_DEV_ONLINE) {
		rval = pl2303_restore_device_state(plp);
	} else {
		rval = USB_SUCCESS;
	}

	return (rval);
}


/*
 * ds_disconnect
 */
static int
pl2303_disconnect(ds_hdl_t hdl)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	int		state = USB_DEV_DISCONNECTED;

	USB_DPRINTF_L4(DPRINT_HOTPLUG, plp->pl_lh, "pl2303_disconnect");

	/*
	 * If the device is disconnected while it is under PWRED_DOWN state, we
	 * need to keep the PWRED_DOWN state so that it could be powered up
	 * later. In the mean while, usbser dev state will be changed to
	 * DISCONNECTED state.
	 */
	mutex_enter(&plp->pl_mutex);
	if (plp->pl_dev_state != USB_DEV_PWRED_DOWN) {
		plp->pl_dev_state = USB_DEV_DISCONNECTED;
	}
	mutex_exit(&plp->pl_mutex);

	pl2303_disconnect_pipes(plp);

	return (state);
}


/*
 * ds_reconnect
 */
static int
pl2303_reconnect(ds_hdl_t hdl)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_HOTPLUG, plp->pl_lh, "pl2303_reconnect");

	return (pl2303_restore_device_state(plp));
}


/*
 * standard UART operations
 * ------------------------
 *
 *
 * ds_set_port_params
 */
/*ARGSUSED*/
static int
pl2303_set_port_params(ds_hdl_t hdl, uint_t port_num, ds_port_params_t *tp)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	int		rval = USB_FAILURE;
	mblk_t		*bp;
	int		i;
	uint_t		ui;
	int		baud;
	int		cnt;
	ds_port_param_entry_t *pe;
	uint16_t xonxoff_symbol;
	uint8_t xon_char;
	uint8_t xoff_char;

	if (tp == NULL) {

		return (rval);
	}

	cnt = tp->tp_cnt;
	pe = tp->tp_entries;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_set_port_params");

	/*
	 * get Line Coding Structure Request
	 * including: baud rate, stop bit, parity type and data bit
	 */
	if ((rval = pl2303_cmd_get_line(plp, &bp)) != USB_SUCCESS) {

		return (rval);
	}

	/* translate parameters into device-specific bits */
	for (i = 0; i < cnt; i++, pe++) {
		switch (pe->param) {
		case DS_PARAM_BAUD:
			ui = pe->val.ui;

			/* if we don't support this speed, return USB_FAILURE */
			if ((ui >= NELEM(pl2303_speedtab)) ||
			    ((ui > 0) && (pl2303_speedtab[ui] == 0))) {
				USB_DPRINTF_L3(DPRINT_CTLOP, plp->pl_lh,
				    "pl2303_set_port_params: bad baud %d", ui);

				freeb(bp);

				return (USB_FAILURE);
			}

			baud = pl2303_speedtab[ui];
			bp->b_rptr[0] = baud & 0xff;
			bp->b_rptr[1] = (baud >> 8) & 0xff;
			bp->b_rptr[2] = (baud >> 16) & 0xff;
			bp->b_rptr[3] = (baud >> 24) & 0xff;

			break;
		case DS_PARAM_PARITY:
			if (pe->val.ui & PARENB) {
				if (pe->val.ui & PARODD) {
					bp->b_rptr[5] = 1;
				} else {
					bp->b_rptr[5] = 2;
				}
			} else {
				bp->b_rptr[5] = 0;
			}

			break;
		case DS_PARAM_STOPB:
			if (pe->val.ui & CSTOPB) {
				bp->b_rptr[4] = 2;
			} else {
				bp->b_rptr[4] = 0;
			}

			break;
		case DS_PARAM_CHARSZ:
			switch (pe->val.ui) {
			case CS5:
				bp->b_rptr[6] = 5;

				break;
			case CS6:
				bp->b_rptr[6] = 6;

				break;
			case CS7:
				bp->b_rptr[6] = 7;

				break;
			case CS8:
			default:
				bp->b_rptr[6] = 8;

				break;
			}

			break;
		case DS_PARAM_XON_XOFF:
			/*
			 * Software flow control: XON/XOFF
			 * not supported by PL-2303H, HX chips
			 */
			if (pe->val.ui & IXON || pe->val.ui & IXOFF) {
				/* not supported by PL-2303H chip */
				switch (plp->pl_chiptype) {
				case pl2303_H:

					break;
				case pl2303_X:
				case pl2303_HX_CHIP_D:
					xon_char = pe->val.uc[0];
					xoff_char = pe->val.uc[1];
					xonxoff_symbol = (xoff_char << 8)
					    | xon_char;

					rval =	pl2303_cmd_vendor_write0(
					    plp, SET_XONXOFF,
					    xonxoff_symbol);

					if (rval != USB_SUCCESS) {
						USB_DPRINTF_L3(DPRINT_CTLOP,
						    plp->pl_lh,
						    "pl2303_set_port_params: "
						    "set XonXoff failed");
					}

					break;
				case pl2303_UNKNOWN:
				default:

					break;
				}
			}

			break;
		case DS_PARAM_FLOW_CTL:
			/* Hardware flow control */
			if (pe->val.ui & CTSXON) {
				if ((rval = pl2303_cmd_set_rtscts(plp))
				    != USB_SUCCESS) {

					USB_DPRINTF_L3(DPRINT_CTLOP,
					    plp->pl_lh,
					    "pl2303_set_port_params: "
					    "pl2303_cmd_set_rtscts failed");
				}
			}

			break;
		default:
			USB_DPRINTF_L2(DPRINT_CTLOP, plp->pl_lh,
			    "pl2303_set_port_params: bad param %d", pe->param);

			break;
		}
	}

	/* set new values for Line Coding Structure */
	rval = pl2303_cmd_set_line(plp, bp);

	freeb(bp);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	/* hardware need to get Line Coding Structure again */
	if ((rval = pl2303_cmd_get_line(plp, &bp)) != USB_SUCCESS) {

		return (rval);
	}

	freeb(bp);

	return (USB_SUCCESS);
}


/*
 * ds_set_modem_ctl
 */
/*ARGSUSED*/
static int
pl2303_set_modem_ctl(ds_hdl_t hdl, uint_t port_num, int mask, int val)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	int		rval = USB_FAILURE;
	uint8_t		new_mctl;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_set_modem_ctl");

	mutex_enter(&plp->pl_mutex);
	new_mctl = plp->pl_mctl;
	mutex_exit(&plp->pl_mutex);

	/* set RTS and DTR */
	pl2303_mctl2reg(mask, val, &new_mctl);

	if ((rval = pl2303_cmd_set_ctl(plp, new_mctl)) == USB_SUCCESS) {
		mutex_enter(&plp->pl_mutex);
		plp->pl_mctl = new_mctl;
		mutex_exit(&plp->pl_mutex);
	}

	return (rval);
}


/*
 * ds_get_modem_ctl
 */
/*ARGSUSED*/
static int
pl2303_get_modem_ctl(ds_hdl_t hdl, uint_t port_num, int mask, int *valp)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_get_modem_ctl");

	mutex_enter(&plp->pl_mutex);

	/* get RTS and DTR */
	*valp = pl2303_reg2mctl(plp->pl_mctl) & mask;
	*valp |= (mask & (TIOCM_CD | TIOCM_CTS | TIOCM_DSR | TIOCM_RI));
	mutex_exit(&plp->pl_mutex);

	return (USB_SUCCESS);
}


/*
 * ds_break_ctl
 */
/*ARGSUSED*/
static int
pl2303_break_ctl(ds_hdl_t hdl, uint_t port_num, int ctl)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_break_ctl");

	return (pl2303_cmd_break(plp, ctl));
}


/*
 * ds_tx
 */
/*ARGSUSED*/
static int
pl2303_tx(ds_hdl_t hdl, uint_t port_num, mblk_t *mp)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	int		xferd;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_tx");

	/*
	 * sanity checks
	 */
	if (mp == NULL) {
		USB_DPRINTF_L3(DPRINT_CTLOP, plp->pl_lh, "pl2303_tx: mp=NULL");

		return (USB_SUCCESS);
	}
	if (MBLKL(mp) < 1) {
		USB_DPRINTF_L3(DPRINT_CTLOP, plp->pl_lh, "pl2303_tx: len<=0");
		freemsg(mp);

		return (USB_SUCCESS);
	}

	mutex_enter(&plp->pl_mutex);

	pl2303_put_tail(&plp->pl_tx_mp, mp);	/* add to the chain */

	pl2303_tx_start(plp, &xferd);

	mutex_exit(&plp->pl_mutex);

	return (USB_SUCCESS);
}


/*
 * ds_rx
 * the real data receiving is in pl2303_open_port
 */
/*ARGSUSED*/
static mblk_t *
pl2303_rx(ds_hdl_t hdl, uint_t port_num)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	mblk_t		*mp;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_rx");

	mutex_enter(&plp->pl_mutex);
	mp = plp->pl_rx_mp;
	plp->pl_rx_mp = NULL;
	mutex_exit(&plp->pl_mutex);

	return (mp);
}


/*
 * ds_stop
 */
/*ARGSUSED*/
static void
pl2303_stop(ds_hdl_t hdl, uint_t port_num, int dir)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_stop");

	if (dir & DS_TX) {
		mutex_enter(&plp->pl_mutex);
		plp->pl_port_flags |= PL2303_PORT_TX_STOPPED;
		mutex_exit(&plp->pl_mutex);
	}
}


/*
 * ds_start
 */
/*ARGSUSED*/
static void
pl2303_start(ds_hdl_t hdl, uint_t port_num, int dir)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_start");

	if (dir & DS_TX) {
		mutex_enter(&plp->pl_mutex);
		if (plp->pl_port_flags & PL2303_PORT_TX_STOPPED) {
			plp->pl_port_flags &= ~PL2303_PORT_TX_STOPPED;
			pl2303_tx_start(plp, NULL);
		}
		mutex_exit(&plp->pl_mutex);
	}
}


/*
 * ds_fifo_flush
 */
/*ARGSUSED*/
static int
pl2303_fifo_flush(ds_hdl_t hdl, uint_t port_num, int dir)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_fifo_flush: dir=%x",
	    dir);

	mutex_enter(&plp->pl_mutex);
	ASSERT(plp->pl_port_state == PL2303_PORT_OPEN);

	if ((dir & DS_TX) && plp->pl_tx_mp) {
		freemsg(plp->pl_tx_mp);
		plp->pl_tx_mp = NULL;
	}
	if ((dir & DS_RX) && plp->pl_rx_mp) {
		freemsg(plp->pl_rx_mp);
		plp->pl_rx_mp = NULL;
	}
	mutex_exit(&plp->pl_mutex);

	return (USB_SUCCESS);
}


/*
 * ds_fifo_drain
 */
/*ARGSUSED*/
static int
pl2303_fifo_drain(ds_hdl_t hdl, uint_t port_num, int timeout)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;
	int		rval = USB_SUCCESS;

	USB_DPRINTF_L4(DPRINT_CTLOP, plp->pl_lh, "pl2303_fifo_drain");

	mutex_enter(&plp->pl_mutex);
	ASSERT(plp->pl_port_state == PL2303_PORT_OPEN);

	/*
	 * for the reason of hardware, set timeout 0
	 */
	if (pl2303_wait_tx_drain(plp, 0) != USB_SUCCESS) {

		mutex_exit(&plp->pl_mutex);

		return (USB_FAILURE);
	}

	mutex_exit(&plp->pl_mutex);

	/* wait 500 ms until hw fifo drains */
	delay(drv_usectohz(500*1000));

	return (rval);
}


/*
 * configuration routines
 * ----------------------
 *
 * clean up routine
 */
static void
pl2303_cleanup(pl2303_state_t *plp, int level)
{
	ASSERT((level > 0) && (level <= PL2303_CLEANUP_LEVEL_MAX));

	switch (level) {
	default:
		pl2303_close_pipes(plp);
		/* FALLTHRU */
	case 5:
		usb_unregister_event_cbs(plp->pl_dip, plp->pl_usb_events);
		/* FALLTHRU */
	case 4:
		pl2303_destroy_pm_components(plp);
		/* FALLTHRU */
	case 3:
		mutex_destroy(&plp->pl_mutex);
		cv_destroy(&plp->pl_tx_cv);

		usb_free_log_hdl(plp->pl_lh);
		plp->pl_lh = NULL;

		usb_free_descr_tree(plp->pl_dip, plp->pl_dev_data);
		plp->pl_def_ph = NULL;
		/* FALLTHRU */
	case 2:
		usb_client_detach(plp->pl_dip, plp->pl_dev_data);
		/* FALLTHRU */
	case 1:
		kmem_free(plp, sizeof (pl2303_state_t));
	}
}


/*
 * device specific attach
 */
static int
pl2303_dev_attach(pl2303_state_t *plp)
{
	if (pl2303_open_pipes(plp) != USB_SUCCESS) {
		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * hotplug
 * -------
 *
 *
 * restore device state after CPR resume or reconnect
 */
static int
pl2303_restore_device_state(pl2303_state_t *plp)
{
	int	state;

	mutex_enter(&plp->pl_mutex);
	state = plp->pl_dev_state;
	mutex_exit(&plp->pl_mutex);

	if ((state != USB_DEV_DISCONNECTED) && (state != USB_DEV_SUSPENDED)) {

		return (state);
	}

	if (usb_check_same_device(plp->pl_dip, plp->pl_lh, USB_LOG_L0,
	    DPRINT_MASK_ALL, USB_CHK_ALL, NULL) != USB_SUCCESS) {
		mutex_enter(&plp->pl_mutex);
		state = plp->pl_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&plp->pl_mutex);

		return (state);
	}

	if (state == USB_DEV_DISCONNECTED) {
		USB_DPRINTF_L0(DPRINT_HOTPLUG, plp->pl_lh,
		    "Device has been reconnected but data may have been lost");
	}

	if (pl2303_reconnect_pipes(plp) != USB_SUCCESS) {

		return (state);
	}

	/*
	 * init device state
	 */
	mutex_enter(&plp->pl_mutex);
	state = plp->pl_dev_state = USB_DEV_ONLINE;
	mutex_exit(&plp->pl_mutex);

	if ((pl2303_restore_port_state(plp) != USB_SUCCESS)) {
		USB_DPRINTF_L2(DPRINT_HOTPLUG, plp->pl_lh,
		    "pl2303_restore_device_state: failed");
	}

	return (state);
}


/*
 * restore ports state after CPR resume or reconnect
 */
static int
pl2303_restore_port_state(pl2303_state_t *plp)
{
	int		rval;

	mutex_enter(&plp->pl_mutex);
	if (plp->pl_port_state != PL2303_PORT_OPEN) {
		mutex_exit(&plp->pl_mutex);

		return (USB_SUCCESS);
	}
	mutex_exit(&plp->pl_mutex);

	/* open hardware serial port */
	if ((rval = pl2303_open_hw_port(plp)) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_HOTPLUG, plp->pl_lh,
		    "pl2303_restore_ports_state: failed");
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
pl2303_create_pm_components(pl2303_state_t *plp)
{
	dev_info_t	*dip = plp->pl_dip;
	pl2303_pm_t	*pm;
	uint_t		pwr_states;

	if (usb_create_pm_components(dip, &pwr_states) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_PM, plp->pl_lh,
		    "pl2303_create_pm_components: failed");

		return (USB_SUCCESS);
	}

	pm = plp->pl_pm = kmem_zalloc(sizeof (pl2303_pm_t), KM_SLEEP);

	pm->pm_pwr_states = (uint8_t)pwr_states;
	pm->pm_cur_power = USB_DEV_OS_FULL_PWR;
	pm->pm_wakeup_enabled = (usb_handle_remote_wakeup(dip,
	    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS);

	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	return (USB_SUCCESS);
}


/*
 * destroy PM components
 */
static void
pl2303_destroy_pm_components(pl2303_state_t *plp)
{
	pl2303_pm_t	*pm = plp->pl_pm;
	dev_info_t	*dip = plp->pl_dip;
	int		rval;

	if (!pm)

		return;

	if (plp->pl_dev_state != USB_DEV_DISCONNECTED) {
		if (pm->pm_wakeup_enabled) {
			rval = pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
			if (rval != DDI_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_PM, plp->pl_lh,
				    "pl2303_destroy_pm_components:"
				    "raising power failed, rval=%d", rval);
			}

			rval = usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE);
			if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(DPRINT_PM, plp->pl_lh,
				    "pl2303_destroy_pm_components: disable "
				    "remote wakeup failed, rval=%d", rval);
			}
		}

		(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);
	}
	kmem_free(pm, sizeof (pl2303_pm_t));
	plp->pl_pm = NULL;
}


/*
 * mark device busy and raise power
 */
static int
pl2303_pm_set_busy(pl2303_state_t *plp)
{
	pl2303_pm_t	*pm = plp->pl_pm;
	dev_info_t	*dip = plp->pl_dip;
	int		rval;

	USB_DPRINTF_L4(DPRINT_PM, plp->pl_lh, "pl2303_pm_set_busy");

	if (!pm) {

		return (USB_SUCCESS);
	}

	mutex_enter(&plp->pl_mutex);
	/* if already marked busy, just increment the counter */
	if (pm->pm_busy_cnt++ > 0) {
		mutex_exit(&plp->pl_mutex);

		return (USB_SUCCESS);
	}

	rval = pm_busy_component(dip, 0);
	ASSERT(rval == DDI_SUCCESS);

	if (pm->pm_cur_power == USB_DEV_OS_FULL_PWR) {
		mutex_exit(&plp->pl_mutex);

		return (USB_SUCCESS);
	}

	/* need to raise power	*/
	pm->pm_raise_power = B_TRUE;
	mutex_exit(&plp->pl_mutex);

	rval = pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	if (rval != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_PM, plp->pl_lh, "raising power failed");
	}

	mutex_enter(&plp->pl_mutex);
	pm->pm_raise_power = B_FALSE;
	mutex_exit(&plp->pl_mutex);

	return (USB_SUCCESS);
}


/*
 * mark device idle
 */
static void
pl2303_pm_set_idle(pl2303_state_t *plp)
{
	pl2303_pm_t	*pm = plp->pl_pm;
	dev_info_t	*dip = plp->pl_dip;

	USB_DPRINTF_L4(DPRINT_PM, plp->pl_lh, "pl2303_pm_set_idle");

	if (!pm) {

		return;
	}

	/*
	 * if more ports use the device, do not mark as yet
	 */
	mutex_enter(&plp->pl_mutex);
	if (--pm->pm_busy_cnt > 0) {
		mutex_exit(&plp->pl_mutex);

		return;
	}

	if (pm) {
		(void) pm_idle_component(dip, 0);
	}
	mutex_exit(&plp->pl_mutex);
}


/*
 * Functions to handle power transition for OS levels 0 -> 3
 * The same level as OS state, different from USB state
 */
static int
pl2303_pwrlvl0(pl2303_state_t *plp)
{
	int	rval;

	USB_DPRINTF_L4(DPRINT_PM, plp->pl_lh, "pl2303_pwrlvl0");

	switch (plp->pl_dev_state) {
	case USB_DEV_ONLINE:
		/* issue USB D3 command to the device */
		rval = usb_set_device_pwrlvl3(plp->pl_dip);
		ASSERT(rval == USB_SUCCESS);

		plp->pl_dev_state = USB_DEV_PWRED_DOWN;
		plp->pl_pm->pm_cur_power = USB_DEV_OS_PWR_OFF;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnect/cpr'ed device to go to lower power */

		return (USB_SUCCESS);
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(DPRINT_PM, plp->pl_lh,
		    "pl2303_pwrlvl0: illegal device state");

		return (USB_FAILURE);
	}
}


static int
pl2303_pwrlvl1(pl2303_state_t *plp)
{
	USB_DPRINTF_L4(DPRINT_PM, plp->pl_lh, "pl2303_pwrlvl1");

	/* issue USB D2 command to the device */
	(void) usb_set_device_pwrlvl2(plp->pl_dip);

	return (USB_FAILURE);
}


static int
pl2303_pwrlvl2(pl2303_state_t *plp)
{
	USB_DPRINTF_L4(DPRINT_PM, plp->pl_lh, "pl2303_pwrlvl2");

	/* issue USB D1 command to the device */
	(void) usb_set_device_pwrlvl1(plp->pl_dip);

	return (USB_FAILURE);
}


static int
pl2303_pwrlvl3(pl2303_state_t *plp)
{
	int	rval;

	USB_DPRINTF_L4(DPRINT_PM, plp->pl_lh, "pl2303_pwrlvl3");

	switch (plp->pl_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(plp->pl_dip);
		ASSERT(rval == USB_SUCCESS);

		plp->pl_dev_state = USB_DEV_ONLINE;
		plp->pl_pm->pm_cur_power = USB_DEV_OS_FULL_PWR;

		/* FALLTHRU */
	case USB_DEV_ONLINE:
		/* we are already in full power */

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(DPRINT_PM, plp->pl_lh,
		    "pl2303_pwrlvl3: illegal device state");

		return (USB_FAILURE);
	}
}


/*
 * pipe operations
 * ---------------
 *
 *
 */
static int
pl2303_open_pipes(pl2303_state_t *plp)
{
	int		ifc, alt;
	usb_pipe_policy_t policy;
	usb_ep_data_t	*in_data, *out_data;

	/* get ep data */
	ifc = plp->pl_dev_data->dev_curr_if;
	alt = 0;

	in_data = usb_lookup_ep_data(plp->pl_dip, plp->pl_dev_data, ifc, alt,
	    0, USB_EP_ATTR_BULK, USB_EP_DIR_IN);

	out_data = usb_lookup_ep_data(plp->pl_dip, plp->pl_dev_data, ifc, alt,
	    0, USB_EP_ATTR_BULK, USB_EP_DIR_OUT);

	if ((in_data == NULL) || (out_data == NULL)) {
		USB_DPRINTF_L2(DPRINT_ATTACH, plp->pl_lh,
		    "pl2303_open_pipes: can't get ep data");

		return (USB_FAILURE);
	}

	/* open pipes */
	policy.pp_max_async_reqs = 2;

	if (usb_pipe_open(plp->pl_dip, &in_data->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &plp->pl_bulkin_ph) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	if (usb_pipe_open(plp->pl_dip, &out_data->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &plp->pl_bulkout_ph) != USB_SUCCESS) {
		usb_pipe_close(plp->pl_dip, plp->pl_bulkin_ph, USB_FLAGS_SLEEP,
		    NULL, NULL);

		return (USB_FAILURE);
	}

	mutex_enter(&plp->pl_mutex);
	plp->pl_bulkin_state = PL2303_PIPE_IDLE;
	plp->pl_bulkout_state = PL2303_PIPE_IDLE;
	mutex_exit(&plp->pl_mutex);

	return (USB_SUCCESS);
}


static void
pl2303_close_pipes(pl2303_state_t *plp)
{
	if (plp->pl_bulkin_ph) {
		usb_pipe_close(plp->pl_dip, plp->pl_bulkin_ph,
		    USB_FLAGS_SLEEP, 0, 0);
	}
	if (plp->pl_bulkout_ph) {
		usb_pipe_close(plp->pl_dip, plp->pl_bulkout_ph,
		    USB_FLAGS_SLEEP, 0, 0);
	}

	mutex_enter(&plp->pl_mutex);
	plp->pl_bulkin_state = PL2303_PIPE_CLOSED;
	plp->pl_bulkout_state = PL2303_PIPE_CLOSED;
	mutex_exit(&plp->pl_mutex);
}


static void
pl2303_disconnect_pipes(pl2303_state_t *plp)
{
	pl2303_close_pipes(plp);
}


static int
pl2303_reconnect_pipes(pl2303_state_t *plp)
{
	if ((pl2303_open_pipes(plp) != USB_SUCCESS)) {

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * pipe callbacks
 * --------------
 *
 *
 * bulk in common and exeception callback
 *
 */
/*ARGSUSED*/
void
pl2303_bulkin_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	pl2303_state_t	*plp = (pl2303_state_t *)req->bulk_client_private;
	mblk_t		*data;
	int		data_len;

	data = req->bulk_data;
	data_len = (data) ? MBLKL(data) : 0;

	USB_DPRINTF_L4(DPRINT_IN_PIPE, plp->pl_lh, "pl2303_bulkin_cb: "
	    "cr=%d len=%d",
	    req->bulk_completion_reason,
	    data_len);

	/* save data and notify GSD */
	if ((plp->pl_port_state == PL2303_PORT_OPEN) && (data_len) &&
	    (req->bulk_completion_reason == USB_CR_OK)) {
		req->bulk_data = NULL;
		pl2303_put_tail(&plp->pl_rx_mp, data);
		if (plp->pl_cb.cb_rx) {
			plp->pl_cb.cb_rx(plp->pl_cb.cb_arg);
		}
	}

	usb_free_bulk_req(req);

	/* receive more */
	mutex_enter(&plp->pl_mutex);
	plp->pl_bulkin_state = PL2303_PIPE_IDLE;
	if ((plp->pl_port_state == PL2303_PORT_OPEN) &&
	    (plp->pl_dev_state == USB_DEV_ONLINE)) {
		if (pl2303_rx_start(plp) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_IN_PIPE, plp->pl_lh,
			    "pl2303_bulkin_cb: restart rx fail");
		}
	}
	mutex_exit(&plp->pl_mutex);
}


/*
 * bulk out common and exeception callback
 */
/*ARGSUSED*/
void
pl2303_bulkout_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	pl2303_state_t	*plp = (pl2303_state_t *)req->bulk_client_private;
	int		data_len;
	mblk_t		*data = req->bulk_data;

	data_len = (req->bulk_data) ? MBLKL(req->bulk_data) : 0;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, plp->pl_lh,
	    "pl2303_bulkout_cb: cr=%d len=%d",
	    req->bulk_completion_reason,
	    data_len);

	if (req->bulk_completion_reason && (data_len > 0)) {
		pl2303_put_head(&plp->pl_tx_mp, data);
		req->bulk_data = NULL;
	}

	usb_free_bulk_req(req);

	/* notify GSD */
	if (plp->pl_cb.cb_tx) {
		plp->pl_cb.cb_tx(plp->pl_cb.cb_arg);
	}

	/* send more */
	mutex_enter(&plp->pl_mutex);
	plp->pl_bulkout_state = PL2303_PIPE_IDLE;
	if (plp->pl_tx_mp == NULL) {
		cv_broadcast(&plp->pl_tx_cv);
	} else {
		pl2303_tx_start(plp, NULL);
	}
	mutex_exit(&plp->pl_mutex);
}


/*
 * data transfer routines
 * ----------------------
 *
 *
 * start data receipt
 */
static int
pl2303_rx_start(pl2303_state_t *plp)
{
	usb_bulk_req_t	*br;
	int		rval = USB_FAILURE;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, plp->pl_lh, "pl2303_rx_start");

	ASSERT(mutex_owned(&plp->pl_mutex));

	plp->pl_bulkin_state = PL2303_PIPE_BUSY;
	mutex_exit(&plp->pl_mutex);

	br = usb_alloc_bulk_req(plp->pl_dip, plp->pl_xfer_sz, USB_FLAGS_SLEEP);
	br->bulk_len = plp->pl_xfer_sz;
	br->bulk_timeout = PL2303_BULKIN_TIMEOUT;
	br->bulk_cb = pl2303_bulkin_cb;
	br->bulk_exc_cb = pl2303_bulkin_cb;
	br->bulk_client_private = (usb_opaque_t)plp;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING | USB_ATTRS_SHORT_XFER_OK;

	rval = usb_pipe_bulk_xfer(plp->pl_bulkin_ph, br, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_IN_PIPE, plp->pl_lh,
		    "pl2303_rx_start: xfer failed %d", rval);
		usb_free_bulk_req(br);
	}

	mutex_enter(&plp->pl_mutex);
	if (rval != USB_SUCCESS) {
		plp->pl_bulkin_state = PL2303_PIPE_IDLE;
	}

	return (rval);
}


/*
 * start data transmit
 */
static void
pl2303_tx_start(pl2303_state_t *plp, int *xferd)
{
	int		len;		/* bytes we can transmit */
	mblk_t		*data;		/* data to be transmitted */
	int		data_len;	/* bytes in 'data' */
	mblk_t		*mp;		/* current msgblk */
	int		copylen;	/* bytes copy from 'mp' to 'data' */
	int		rval;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, plp->pl_lh, "pl2303_tx_start");
	ASSERT(mutex_owned(&plp->pl_mutex));
	ASSERT(plp->pl_port_state != PL2303_PORT_CLOSED);

	if (xferd) {
		*xferd = 0;
	}
	if ((plp->pl_port_flags & PL2303_PORT_TX_STOPPED) ||
	    (plp->pl_tx_mp == NULL)) {

		return;
	}
	if (plp->pl_bulkout_state != PL2303_PIPE_IDLE) {
		USB_DPRINTF_L4(DPRINT_OUT_PIPE, plp->pl_lh,
		    "pl2303_tx_start: pipe busy");

		return;
	}
	ASSERT(MBLKL(plp->pl_tx_mp) > 0);

	/* send as much data as port can receive */
	len = min(msgdsize(plp->pl_tx_mp), plp->pl_xfer_sz);

	if (len == 0) {

		return;
	}

	if ((data = allocb(len, BPRI_LO)) == NULL) {

		return;
	}

	/*
	 * copy no more than 'len' bytes from mblk chain to transmit mblk 'data'
	 */
	data_len = 0;

	while ((data_len < len) && plp->pl_tx_mp) {
		mp = plp->pl_tx_mp;
		copylen = min(MBLKL(mp), len - data_len);
		bcopy(mp->b_rptr, data->b_wptr, copylen);
		mp->b_rptr += copylen;
		data->b_wptr += copylen;
		data_len += copylen;

		if (MBLKL(mp) < 1) {
			plp->pl_tx_mp = unlinkb(mp);
			freeb(mp);
		} else {
			ASSERT(data_len == len);
		}
	}

	if (data_len <= 0) {
		USB_DPRINTF_L3(DPRINT_OUT_PIPE, plp->pl_lh,
		    "pl2303_tx_start: copied zero bytes");
		freeb(data);

		return;
	}

	plp->pl_bulkout_state = PL2303_PIPE_BUSY;
	mutex_exit(&plp->pl_mutex);

	rval = pl2303_send_data(plp, data);
	mutex_enter(&plp->pl_mutex);

	if (rval != USB_SUCCESS) {
		plp->pl_bulkout_state = PL2303_PIPE_IDLE;
		pl2303_put_head(&plp->pl_tx_mp, data);
	} else {
		if (xferd) {
			*xferd = data_len;
		}
	}
}


static int
pl2303_send_data(pl2303_state_t *plp, mblk_t *data)
{
	usb_bulk_req_t	*br;
	int		len = MBLKL(data);
	int		rval;

	USB_DPRINTF_L4(DPRINT_OUT_PIPE, plp->pl_lh, "pl2303_send_data: %d "
	    "%x %x %x", len, data->b_rptr[0],
	    (len > 1) ? data->b_rptr[1] : 0,
	    (len > 2) ? data->b_rptr[2] : 0);
	ASSERT(!mutex_owned(&plp->pl_mutex));

	br = usb_alloc_bulk_req(plp->pl_dip, 0, USB_FLAGS_SLEEP);
	br->bulk_data = data;
	br->bulk_len = len;
	br->bulk_timeout = PL2303_BULKOUT_TIMEOUT;
	br->bulk_cb = pl2303_bulkout_cb;
	br->bulk_exc_cb = pl2303_bulkout_cb;
	br->bulk_client_private = (usb_opaque_t)plp;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING;

	rval = usb_pipe_bulk_xfer(plp->pl_bulkout_ph, br, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_OUT_PIPE, plp->pl_lh,
		    "pl2303_send_data: xfer failed %d", rval);

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
pl2303_wait_tx_drain(pl2303_state_t *plp, int timeout)
{
	clock_t	until;
	int	over = 0;

	until = ddi_get_lbolt() + drv_usectohz(1000 * 1000 * timeout);

	while (plp->pl_tx_mp && !over) {
		if (timeout > 0) {
			/* whether timedout or signal pending */
			over = (cv_timedwait_sig(&plp->pl_tx_cv,
			    &plp->pl_mutex, until) <= 0);
		} else {
			/* whether a signal is pending */
			over = (cv_wait_sig(&plp->pl_tx_cv,
			    &plp->pl_mutex) == 0);
		}
	}

	return ((plp->pl_tx_mp == NULL) ? USB_SUCCESS : USB_FAILURE);
}


/*
 * device operations
 * -----------------
 *
 *
 * initialize hardware serial port
 */
static int
pl2303_open_hw_port(pl2303_state_t *plp)
{
	int		rval = USB_SUCCESS;

	/*
	 * initialize three Device Configuration Registers (DCR):
	 * DCR0, DCR1, and DCR2
	 */

	switch (plp->pl_chiptype) {
	case (pl2303_H):
		/* Set DCR0 */
		if ((rval = pl2303_cmd_vendor_write0(plp, SET_DCR0,
		    DCR0_INIT_H)) != USB_SUCCESS) {

			return (rval);
		}

		/* Set DCR1 */
		if ((rval = pl2303_cmd_vendor_write0(plp, SET_DCR1,
		    DCR1_INIT_H)) != USB_SUCCESS) {

			return (rval);
		}

		/* Set DCR2 */
		if ((rval = pl2303_cmd_vendor_write0(plp, SET_DCR2,
		    DCR2_INIT_H)) != USB_SUCCESS) {

			return (rval);
		}

		break;
	case (pl2303_X):
	case (pl2303_HX_CHIP_D):

		/* Set DCR0 */
		if ((rval = pl2303_cmd_vendor_write0(plp, SET_DCR0,
		    DCR0_INIT)) != USB_SUCCESS) {

			return (rval);
		}

		/* Set DCR1 */
		if ((rval = pl2303_cmd_vendor_write0(plp, SET_DCR1,
		    DCR1_INIT_X)) != USB_SUCCESS) {

			return (rval);
		}

		/* Set DCR2 */
		if ((rval = pl2303_cmd_vendor_write0(plp, SET_DCR2,
		    DCR2_INIT_X)) != USB_SUCCESS) {

			return (rval);
		}

		/* reset Downstream data pipes */
		if ((rval = pl2303_cmd_vendor_write0(plp,
		    RESET_DOWNSTREAM_DATA_PIPE, 0)) != USB_SUCCESS) {

			return (rval);
		}

		/* reset Upstream data pipes */
		if ((rval = pl2303_cmd_vendor_write0(plp,
		    RESET_UPSTREAM_DATA_PIPE, 0)) != USB_SUCCESS) {

			return (rval);
		}

		break;
	case (pl2303_UNKNOWN):
	default:
		USB_DPRINTF_L2(DPRINT_OPEN, plp->pl_lh,
		    "pl2303_open_hw_port: unknown chiptype");

		rval = USB_FAILURE;
	}

	return (rval);
}


/*
 * vendor-specific commands
 * ------------------------
 *
 *
 * Get_Line_Coding Request
 */
static int
pl2303_cmd_get_line(pl2303_state_t *plp, mblk_t **data)
{
	usb_ctrl_setup_t setup = { PL2303_GET_LINE_CODING_REQUEST_TYPE,
	    PL2303_GET_LINE_CODING_REQUEST, 0, 0,
	    PL2303_GET_LINE_CODING_LENGTH, 0 };
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	int		rval;

	*data = NULL;

	rval = usb_pipe_ctrl_xfer_wait(plp->pl_def_ph, &setup, data,
	    &cr, &cb_flags, 0);

	if ((rval == USB_SUCCESS) && (*data != NULL)) {
		USB_DPRINTF_L4(DPRINT_DEF_PIPE, plp->pl_lh,
		    "pl2303_cmd_get_line: %x %x %x %x %x %x %x",
		    (*data)->b_rptr[0], (*data)->b_rptr[1], (*data)->b_rptr[2],
		    (*data)->b_rptr[3], (*data)->b_rptr[4], (*data)->b_rptr[5],
		    (*data)->b_rptr[6]);
	} else {
		USB_DPRINTF_L2(DPRINT_DEF_PIPE, plp->pl_lh,
		    "pl2303_cmd_get_line: failed %d %d %x",
		    rval, cr, cb_flags);

		if (*data != NULL) {
			freeb(*data);
		}
	}

	return (rval);
}


/*
 * Set_Line_Coding Request
 */
static int
pl2303_cmd_set_line(pl2303_state_t *plp, mblk_t *data)
{
	usb_ctrl_setup_t setup = { PL2303_SET_LINE_CODING_REQUEST_TYPE,
	    PL2303_SET_LINE_CODING_REQUEST, 0, 0,
	    PL2303_SET_LINE_CODING_LENGTH, 0 };
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	int		rval;

	USB_DPRINTF_L4(DPRINT_DEF_PIPE, plp->pl_lh,
	    "pl2303_cmd_set_line: %x %x %x %x %x %x %x",
	    data->b_rptr[0], data->b_rptr[1], data->b_rptr[2],
	    data->b_rptr[3], data->b_rptr[4], data->b_rptr[5], data->b_rptr[6]);

	rval = usb_pipe_ctrl_xfer_wait(plp->pl_def_ph, &setup, &data,
	    &cr, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_DEF_PIPE, plp->pl_lh,
		    "pl2303_cmd_set_line: failed %d %d %x",
		    rval, cr, cb_flags);
	}

	return (rval);
}


/*
 * Set_Control_Line_State Request to RTS and DTR
 */
static int
pl2303_cmd_set_ctl(pl2303_state_t *plp, uint8_t val)
{
	usb_ctrl_setup_t setup = { PL2303_SET_CONTROL_REQUEST_TYPE,
	    PL2303_SET_CONTROL_REQUEST, 0, 0,
	    PL2303_SET_CONTROL_LENGTH, 0 };
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	int		rval;

	setup.wValue = val;

	rval = usb_pipe_ctrl_xfer_wait(plp->pl_def_ph, &setup, NULL,
	    &cr, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_DEF_PIPE, plp->pl_lh,
		    "pl2303_cmd_set_ctl: failed %d %d %x",
		    rval, cr, cb_flags);
	}

	return (rval);
}


/*
 * Vendor_Specific_Write Request
 * wLength: 0
 */
static int
pl2303_cmd_vendor_write0(pl2303_state_t *plp, uint16_t value, int16_t index)
{
	usb_ctrl_setup_t setup = { PL2303_VENDOR_WRITE_REQUEST_TYPE,
	    PL2303_VENDOR_WRITE_REQUEST, 0, 0,
	    PL2303_VENDOR_WRITE_LENGTH, 0 };
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	int		rval;

	setup.wValue = value;
	setup.wIndex = index;

	rval = usb_pipe_ctrl_xfer_wait(plp->pl_def_ph, &setup, NULL,
	    &cr, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_DEF_PIPE, plp->pl_lh,
		    "pl2303_cmd_vendor_write0: %x %x failed %d %d %x",
		    value, index, rval, cr, cb_flags);
	}

	return (rval);
}


/*
 * For Hardware flow control
 */
static int
pl2303_cmd_set_rtscts(pl2303_state_t *plp)
{
	/* Set DCR0 */
	switch (plp->pl_chiptype) {
	case pl2303_H:

		return (pl2303_cmd_vendor_write0(plp, SET_DCR0, DCR0_INIT_H));
	case pl2303_X:
	case pl2303_HX_CHIP_D:

		return (pl2303_cmd_vendor_write0(plp, SET_DCR0, DCR0_INIT_X));
	case pl2303_UNKNOWN:
	default:

		return (USB_FAILURE);
	}
}


/*
 * Set TxD BREAK_ON or BREAK_OFF
 */
static int
pl2303_cmd_break(pl2303_state_t *plp, int ctl)
{
	usb_ctrl_setup_t setup = { PL2303_BREAK_REQUEST_TYPE,
	    PL2303_BREAK_REQUEST, 0, 0,
	    PL2303_BREAK_LENGTH, 0 };
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	int		rval;

	setup.wValue = (ctl == DS_ON) ? PL2303_BREAK_ON : PL2303_BREAK_OFF;

	rval = usb_pipe_ctrl_xfer_wait(plp->pl_def_ph, &setup, NULL,
	    &cr, &cb_flags, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_DEF_PIPE, plp->pl_lh,
		    "pl2303_cmd_break: failed rval=%d,cr=%d,cb_flags=0x%x",
		    rval, cr, cb_flags);
	}

	return (rval);
}


/*
 * for set_mod_ctl
 */
static void
pl2303_mctl2reg(int mask, int val, uint8_t *line_ctl)
{
	if (mask & TIOCM_RTS) {
		if (val & TIOCM_RTS) {
			*line_ctl |= PL2303_CONTROL_RTS;
		} else {
			*line_ctl &= ~PL2303_CONTROL_RTS;
		}
	}
	if (mask & TIOCM_DTR) {
		if (val & TIOCM_DTR) {
			*line_ctl |= PL2303_CONTROL_DTR;
		} else {
			*line_ctl &= ~PL2303_CONTROL_DTR;
		}
	}
}


/*
 * for get_mod_ctl
 */
static int
pl2303_reg2mctl(uint8_t line_ctl)
{
	int	val = 0;

	if (line_ctl & PL2303_CONTROL_RTS) {
		val |= TIOCM_RTS;
	}
	if (line_ctl & PL2303_CONTROL_DTR) {
		val |= TIOCM_DTR;
	}

	return (val);
}


/*
 * misc routines
 * -------------
 *
 */

/*
 * link a message block to tail of message
 * account for the case when message is null
 */
static void
pl2303_put_tail(mblk_t **mpp, mblk_t *bp)
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
static void
pl2303_put_head(mblk_t **mpp, mblk_t *bp)
{
	if (*mpp) {
		linkb(bp, *mpp);
	}
	*mpp = bp;
}

/*ARGSUSED*/
static usb_pipe_handle_t
pl2303_out_pipe(ds_hdl_t hdl, uint_t port_num)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	return (plp->pl_bulkout_ph);
}

/*ARGSUSED*/
static usb_pipe_handle_t
pl2303_in_pipe(ds_hdl_t hdl, uint_t port_num)
{
	pl2303_state_t	*plp = (pl2303_state_t *)hdl;

	return (plp->pl_bulkin_ph);
}
