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

#ifndef _SYS_USB_USBSER_DSDI_H
#define	_SYS_USB_USBSER_DSDI_H


/*
 * USB-to-serial device-specific driver interface (DSDI)
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usbai_private.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef void	*ds_hdl_t;	/* DSD device handler */

/*
 * interrupt emulation callbacks
 */
typedef struct ds_cb {
	void		(*cb_tx)(caddr_t);	/* transmit callback */
	void		(*cb_rx)(caddr_t);	/* receive callback */
	void		(*cb_status)(caddr_t);	/* status change callback */
	caddr_t		cb_arg;			/* callback argument */
} ds_cb_t;

typedef struct ds_port_params ds_port_params_t;	/* see below */

typedef struct ds_attach_info {
	/*
	 * passed to DSD:
	 */
	dev_info_t	*ai_dip;	/* devinfo */
	/*
	 * these event callbacks should be registered by DSD
	 * using usb_register_event_cbs()
	 */
	usb_event_t	*ai_usb_events;
	/*
	 * returned by DSD:
	 */
	ds_hdl_t	*ai_hdl; /* handle to be used by GSD in other calls */
	uint_t		*ai_port_cnt;	/* number of ports */
} ds_attach_info_t;

/*
 * device operations used by Generic Serial Driver (GSD)
 *
 * ops returning int should return USB_SUCCESS on successful completion
 * or appropriate USB_* error code in case of failure
 *
 * ops can block unless otherwise indicated
 */
typedef struct ds_ops {
	int	ds_version;	/* structure version */

	/*
	 * configuration operations
	 * ------------------------
	 *
	 * attach/detach device instance, called from GSD attach(9E)/detach(9E)
	 */
	int	(*ds_attach)(ds_attach_info_t *aip);
	void	(*ds_detach)(ds_hdl_t);

	/*
	 * register/unregister interrupt callbacks for the given port
	 */
	int	(*ds_register_cb)(ds_hdl_t, uint_t port_num, ds_cb_t *cb);
	void	(*ds_unregister_cb)(ds_hdl_t, uint_t port_num);

	/*
	 * open/close port
	 */
	int	(*ds_open_port)(ds_hdl_t, uint_t port_num);
	int	(*ds_close_port)(ds_hdl_t, uint_t port_num);

	/*
	 * power management
	 * ----------------
	 *
	 * set power level of the component;
	 * DSD should set new_state to the resulting USB device state
	 */
	int	(*ds_usb_power)(ds_hdl_t, int comp, int level, int *new_state);

	/*
	 * CPR suspend/resume
	 */
	int	(*ds_suspend)(ds_hdl_t);
	int	(*ds_resume)(ds_hdl_t);

	/*
	 * USB device disconnect/reconnect
	 */
	int	(*ds_disconnect)(ds_hdl_t);
	int	(*ds_reconnect)(ds_hdl_t);

	/*
	 * standard UART operations
	 * ------------------------
	 *
	 * set one or more port parameters: baud rate, parity,
	 * stop bits, character size, xon/xoff char, flow control
	 */
	int	(*ds_set_port_params)(ds_hdl_t, uint_t port_num,
			ds_port_params_t *tp);

	/*
	 * set modem controls: each bit set to 1 in 'mask' will be set to the
	 * value of corresponding bit in 'val'; other bits are not affected
	 */
	int	(*ds_set_modem_ctl)(ds_hdl_t, uint_t port_num,
			int mask, int val);

	/*
	 * get modem control/status: values of bits that correspond
	 * to those set to 1 in 'mask' are returned in 'valp'
	 */
	int	(*ds_get_modem_ctl)(ds_hdl_t, uint_t port_num,
			int mask, int *valp);

	/*
	 * set/clear break ('ctl' is DS_ON/DS_OFF)
	 */
	int	(*ds_break_ctl)(ds_hdl_t, uint_t port_num, int ctl);

	/*
	 * set/clear internal loopback ('ctl' is DS_ON/DS_OFF)
	 */
	int	(*ds_loopback)(ds_hdl_t, uint_t port_num, int ctl);

	/*
	 * data xfer
	 * ---------
	 *
	 * data transmit: DSD is *required* to accept mblk for transfer and
	 * return USB_SUCCESS; after which GSD no longer owns the mblk
	 */
	int	(*ds_tx)(ds_hdl_t, uint_t port_num, mblk_t *mp);

	/*
	 * data receipt: DSD returns either received data mblk or NULL
	 * if no data available. this op must not block as it is intended
	 * to be called from is usually called GSD receive callback
	 */
	mblk_t	*(*ds_rx)(ds_hdl_t, uint_t port_num);

	/*
	 * stop/start data transmit or/and receive:
	 * 'dir' can be an OR of DS_TX and DS_RX; must succeed.
	 */
	void	(*ds_stop)(ds_hdl_t, uint_t port_num, int dir);
	void	(*ds_start)(ds_hdl_t, uint_t port_num, int dir);

	/*
	 * flush FIFOs: 'dir' can be an OR of DS_TX and DS_RX,
	 * affecting transmit and received FIFO respectively
	 */
	int	(*ds_fifo_flush)(ds_hdl_t, uint_t port_num, int dir);

	/*
	 * drain (wait until empty) output FIFO
	 *
	 * return failure if the FIFO does not get empty after at least
	 * 'timeout' seconds (zero timeout means wait forever)
	 */
	int	(*ds_fifo_drain)(ds_hdl_t, uint_t port_num, int timeout);

	/* V1 ops for polled I/O */
	usb_pipe_handle_t (*ds_out_pipe)(ds_hdl_t, uint_t port_num);
	usb_pipe_handle_t (*ds_in_pipe)(ds_hdl_t, uint_t port_num);
} ds_ops_t;

/*
 * ds_version
 */
enum {
	DS_OPS_VERSION_V0	= 0,
	DS_OPS_VERSION_V1	= 1,
	DS_OPS_VERSION		= DS_OPS_VERSION_V1
};

/*
 * parameter type
 */
typedef enum {
	DS_PARAM_BAUD,		/* baud rate */
	DS_PARAM_PARITY,	/* parity */
	DS_PARAM_STOPB,		/* stop bits */
	DS_PARAM_CHARSZ,	/* char size */
	DS_PARAM_XON_XOFF,	/* xon/xoff chars */
	DS_PARAM_FLOW_CTL	/* flow control */
} ds_port_param_type_t;

/*
 * a single param entry, union used to pass various data types
 */
typedef struct ds_port_param_entry {
	ds_port_param_type_t	param;	 /* parameter */
	union {
		uint_t		ui;
		uchar_t		uc[4];
	} val;			/* parameter value(s) */
} ds_port_param_entry_t;

/*
 * port parameter array
 */
struct ds_port_params {
	ds_port_param_entry_t	*tp_entries;	/* entry array */
	int			tp_cnt;		/* entry count */
};

/*
 * direction (ds_fifo_flush, ds_fifo_drain)
 */
enum {
	DS_TX		= 0x01,	/* transmit direction */
	DS_RX		= 0x02	/* receive direction */
};

/*
 * on/off (ds_break_ctl, ds_loopback)
 */
enum {
	DS_OFF,
	DS_ON
};

/*
 * input error codes, returned by DSD in an M_BREAK message
 */
enum {
	DS_PARITY_ERR	= 0x01,	/* parity error */
	DS_FRAMING_ERR	= 0x02,	/* framing error */
	DS_OVERRUN_ERR	= 0x03,	/* data overrun */
	DS_BREAK_ERR	= 0x04	/* break detected */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSER_DSDI_H */
