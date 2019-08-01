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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * USB Serial CDC ACM driver
 *
 * 1. General Concepts
 * -------------------
 *
 * 1.1 Overview
 * ------------
 * This driver supports devices that comply with the USB Communication
 * Device Class Abstract Control Model (USB CDC ACM) specification,
 * which is available at http://www.usb.org. Given the broad nature
 * of communication equipment, this driver supports the following
 * types of devices:
 *	+ Telecommunications devices: analog modems, mobile phones;
 *	+ Networking devices: cable modems;
 * Except the above mentioned acm devices, this driver also supports
 * some devices which provide modem-like function and have pairs of
 * bulk in/out pipes.
 *
 * There are three classes that make up the definition for communication
 * devices: the Communication Device Class, the Communication Interface
 * Class and the Data Interface Class. The Communication Device Class
 * is a device level definition and is used by the host to properly
 * identify a communication device that may present several different
 * types of interfaces. The Communication Interface Class defines a
 * general-purpose mechanism that can be used to enable all types of
 * communication services on the Universal Serial Bus (USB). The Data
 * Interface Class defines a general-purpose mechanism to enable bulk
 * transfer on the USB when the data does not meet the requirements
 * for any other class.
 *
 * 1.2 Interface Definitions
 * -------------------------
 * Communication Class Interface is used for device management and,
 * optionally, call management. Device management includes the requests
 * that manage the operational state of a device, the device responses,
 * and event notifications. In Abstract Control Model, the device can
 * provide an internal implementation of call management over the Data
 * Class interface or the Communication Class interface.
 *
 * The Data Class defines a data interface as an interface with a class
 * type of Data Class. Data transmission on a communication device is
 * not restricted to interfaces using the Data Class. Rather, a data
 * interface is used to transmit and/or receive data that is not
 * defined by any other class. The data could be:
 *	+ Some form of raw data from a communication line.
 *	+ Legacy modem data.
 *	+ Data using a proprietary format.
 *
 * 1.3 Endpoint Requirements
 * -------------------------
 * The Communication Class interface requires one endpoint, the management
 * element. Optionally, it can have an additional endpoint, the notification
 * element. The management element uses the default endpoint for all
 * standard and Communication Class-specific requests. The notification
 * element normally uses an interrupt endpoint.
 *
 * The type of endpoints belonging to a Data Class interface are restricted
 * to bulk, and are expected to exist in pairs of the same type (one In and
 * one Out).
 *
 * 1.4 ACM Function Characteristics
 * --------------------------------
 * With Abstract Control Model, the USB device understands standard
 * V.25ter (AT) commands. The device contains a Datapump and micro-
 * controller that handles the AT commands and relay controls. The
 * device uses both a Data Class interface and a Communication Class.
 * interface.
 *
 * A Communication Class interface of type Abstract Control Model will
 * consist of a minimum of two pipes; one is used to implement the
 * management element and the other to implement a notification element.
 * In addition, the device can use two pipes to implement channels over
 * which to carry unspecified data, typically over a Data Class interface.
 *
 * 1.5 ACM Serial Emulation
 * ------------------------
 * The Abstract Control Model can bridge the gap between legacy modem
 * devices and USB devices. To support certain types of legacy applications,
 * two problems need to be addressed. The first is supporting specific
 * legacy control signals and state variables which are addressed
 * directly by the various carrier modulation standards. To support these
 * requirement, additional requests and notifications have been created.
 * Please refer to macro, beginning with USB_CDC_REQ_* and
 * USB_CDC_NOTIFICATION_*.
 *
 * The second significant item which is needed to bridge the gap between
 * legacy modem designs and the Abstract Control Model is a means to
 * multiplex call control (AT commands) on the Data Class interface.
 * Legacy modem designs are limited by only supporting one channel for
 * both "AT" commands and the actual data. To allow this type of
 * functionality, the device must have a means to specify this limitation
 * to the host.
 *
 * When describing this type of device, the Communication Class interface
 * would still specify a Abstract Control Model, but call control would
 * actually occur over the Data Class interface. To describe this
 * particular characteristic, the Call Management Functional Descriptor
 * would have bit D1 of bmCapabilities set.
 *
 * 1.6 Other Bulk In/Out Devices
 * -----------------------------
 * Some devices don't conform to USB CDC specification, but they provide
 * modem-like function and have pairs of bulk in/out pipes. This driver
 * supports this kind of device and exports term nodes by their pipes.
 *
 * 2. Implementation
 * -----------------
 *
 * 2.1 Overview
 * ------------
 * It is a device-specific driver (DSD) working with USB generic serial
 * driver (GSD). It implements the USB-to-serial device-specific driver
 * interface (DSDI) which is offered by GSD. The interface is defined
 * by ds_ops_t structure.
 *
 * 2.2 Port States
 * ---------------
 * For USB CDC ACM devices, this driver is attached to its interface,
 * and exports one port for each interface. For other modem-like devices,
 * this driver can dynamically find the ports in the current device,
 * and export one port for each pair bulk in/out pipes. Each port can
 * be operated independently.
 *
 * port_state:
 *
 *		attach_ports
 *		    |
 *		    |
 *		    |
 *		    v
 *	    USBSACM_PORT_CLOSED
 *		|	    ^
 *		|	    |
 *		V	    |
 *	   open_port	close_port
 *		|	    ^
 *		|	    |
 *		V	    |
 *	      USBSACM_PORT_OPEN
 *
 *
 * 2.3 Pipe States
 * ---------------
 * Each port has its own bulk in/out pipes and some ports could also have
 * its own interrupt pipes (traced by usbsacm_port structure), which are
 * opened during attach. The pipe status is as following:
 *
 * pipe_state:
 *
 *		usbsacm_init_alloc_ports  usbsacm_free_ports
 *				|		^
 *				v		|
 *		  |---->------ USBSACM_PORT_CLOSED ------>------+
 *		  ^						|
 *		  |				reconnect/resume/open_port
 *		  |						|
 *    disconnect/suspend/close_port				|
 *		  |						v
 *		  +------<------ USBSACM_PIPE_IDLE ------<------|
 *				    |		|
 *				    V		^
 *				    |		|
 *		  +-----------------+		+-----------+
 *		  |					    |
 *		  V					    ^
 *		  |					    |
 *	rx_start/tx_start----->------failed------->---------|
 *		  |					    |
 *		  |				bulkin_cb/bulkout_cb
 *		  V					    |
 *		  |					    ^
 *		  |					    |
 *		  +----->----- USBSACM_PIPE_BUSY ---->------+
 *
 *
 * To get its status in a timely way, acm driver can get the status
 * of the device by polling the interrupt pipe.
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
#include <sys/byteorder.h>
#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0
#include <sys/usb/usba.h>
#include <sys/usb/usbdevs.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/clients/usbser/usbser.h>
#include <sys/usb/clients/usbser/usbser_dsdi.h>
#include <sys/usb/clients/usbcdc/usb_cdc.h>
#include <sys/usb/clients/usbser/usbsacm/usbsacm.h>

/* devops entry points */
static int	usbsacm_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usbsacm_detach(dev_info_t *, ddi_detach_cmd_t);
static int	usbsacm_getinfo(dev_info_t *, ddi_info_cmd_t, void *,
		void **);
static int	usbsacm_open(queue_t *, dev_t *, int, int, cred_t *);

/* DSD operations */
static int	usbsacm_ds_attach(ds_attach_info_t *);
static void	usbsacm_ds_detach(ds_hdl_t);
static int	usbsacm_ds_register_cb(ds_hdl_t, uint_t, ds_cb_t *);
static void	usbsacm_ds_unregister_cb(ds_hdl_t, uint_t);
static int	usbsacm_ds_open_port(ds_hdl_t, uint_t);
static int	usbsacm_ds_close_port(ds_hdl_t, uint_t);

/* standard UART operations */
static int	usbsacm_ds_set_port_params(ds_hdl_t, uint_t,
		ds_port_params_t *);
static int	usbsacm_ds_set_modem_ctl(ds_hdl_t, uint_t, int, int);
static int	usbsacm_ds_get_modem_ctl(ds_hdl_t, uint_t, int, int *);
static int	usbsacm_ds_break_ctl(ds_hdl_t, uint_t, int);

/* data xfer */
static int	usbsacm_ds_tx(ds_hdl_t, uint_t, mblk_t *);
static mblk_t	*usbsacm_ds_rx(ds_hdl_t, uint_t);
static void	usbsacm_ds_stop(ds_hdl_t, uint_t, int);
static void	usbsacm_ds_start(ds_hdl_t, uint_t, int);

/* fifo operations */
static int	usbsacm_ds_fifo_flush(ds_hdl_t, uint_t, int);
static int	usbsacm_ds_fifo_drain(ds_hdl_t, uint_t, int);
static int	usbsacm_wait_tx_drain(usbsacm_port_t *, int);
static int	usbsacm_fifo_flush_locked(usbsacm_state_t *, uint_t, int);

/* power management and CPR */
static int	usbsacm_ds_suspend(ds_hdl_t);
static int	usbsacm_ds_resume(ds_hdl_t);
static int	usbsacm_ds_disconnect(ds_hdl_t);
static int	usbsacm_ds_reconnect(ds_hdl_t);
static int	usbsacm_ds_usb_power(ds_hdl_t, int, int, int *);
static int	usbsacm_create_pm_components(usbsacm_state_t *);
static void	usbsacm_destroy_pm_components(usbsacm_state_t *);
static void	usbsacm_pm_set_busy(usbsacm_state_t *);
static void	usbsacm_pm_set_idle(usbsacm_state_t *);
static int	usbsacm_pwrlvl0(usbsacm_state_t *);
static int	usbsacm_pwrlvl1(usbsacm_state_t *);
static int	usbsacm_pwrlvl2(usbsacm_state_t *);
static int	usbsacm_pwrlvl3(usbsacm_state_t *);

/* event handling */
/* pipe callbacks */
static void	usbsacm_bulkin_cb(usb_pipe_handle_t, usb_bulk_req_t *);
static void	usbsacm_bulkout_cb(usb_pipe_handle_t, usb_bulk_req_t *);

/* interrupt pipe */
static void	usbsacm_pipe_start_polling(usbsacm_port_t *acmp);
static void	usbsacm_intr_cb(usb_pipe_handle_t ph, usb_intr_req_t *req);
static void	usbsacm_intr_ex_cb(usb_pipe_handle_t ph, usb_intr_req_t *req);
static void	usbsacm_parse_intr_data(usbsacm_port_t *acmp, mblk_t *data);

/* Utility functions */
/* data transfer routines */
static int	usbsacm_rx_start(usbsacm_port_t *);
static void	usbsacm_tx_start(usbsacm_port_t *);
static int	usbsacm_send_data(usbsacm_port_t *, mblk_t *);

/* Initialize or release resources */
static int	usbsacm_init_alloc_ports(usbsacm_state_t *);
static void	usbsacm_free_ports(usbsacm_state_t *);
static void	usbsacm_cleanup(usbsacm_state_t *);

/* analysis functional descriptors */
static int	usbsacm_get_descriptors(usbsacm_state_t *);

/* hotplug */
static int	usbsacm_restore_device_state(usbsacm_state_t *);
static int	usbsacm_restore_port_state(usbsacm_state_t *);

/* pipe operations */
static int	usbsacm_open_port_pipes(usbsacm_port_t *);
static void	usbsacm_close_port_pipes(usbsacm_port_t *);
static void	usbsacm_close_pipes(usbsacm_state_t *);
static void	usbsacm_disconnect_pipes(usbsacm_state_t *);
static int	usbsacm_reconnect_pipes(usbsacm_state_t *);

/* vendor-specific commands */
static int	usbsacm_req_write(usbsacm_port_t *, uchar_t, uint16_t,
		mblk_t **);
static int	usbsacm_set_line_coding(usbsacm_port_t *,
		usb_cdc_line_coding_t *);
static void	usbsacm_mctl2reg(int mask, int val, uint8_t *);
static int	usbsacm_reg2mctl(uint8_t);

/* misc */
static void	usbsacm_put_tail(mblk_t **, mblk_t *);
static void	usbsacm_put_head(mblk_t **, mblk_t *);


/*
 * Standard STREAMS driver definitions
 */
struct module_info usbsacm_modinfo = {
	0,			/* module id */
	"usbsacm",		/* module name */
	USBSER_MIN_PKTSZ,	/* min pkt size */
	USBSER_MAX_PKTSZ,	/* max pkt size */
	USBSER_HIWAT,		/* hi watermark */
	USBSER_LOWAT		/* low watermark */
};

static struct qinit usbsacm_rinit = {
	NULL,
	usbser_rsrv,
	usbsacm_open,
	usbser_close,
	NULL,
	&usbsacm_modinfo,
	NULL
};

static struct qinit usbsacm_winit = {
	usbser_wput,
	usbser_wsrv,
	NULL,
	NULL,
	NULL,
	&usbsacm_modinfo,
	NULL
};


struct streamtab usbsacm_str_info = {
	&usbsacm_rinit, &usbsacm_winit, NULL, NULL
};

/* cb_ops structure */
static struct cb_ops usbsacm_cb_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&usbsacm_str_info,	/* cb_stream */
	(int)(D_64BIT | D_NEW | D_MP | D_HOTPLUG)	/* cb_flag */
};

/* dev_ops structure */
struct dev_ops usbsacm_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	usbsacm_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	usbsacm_attach,		/* devo_attach */
	usbsacm_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&usbsacm_cb_ops,	/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	usbser_power,		/* devo_power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

extern struct mod_ops mod_driverops;
/* modldrv structure */
static struct modldrv modldrv = {
	&mod_driverops,		/* type of module - driver */
	"USB Serial CDC ACM driver",
	&usbsacm_ops,
};

/* modlinkage structure */
static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

static void	*usbsacm_statep;	/* soft state */

/*
 * DSD definitions
 */
static ds_ops_t usbsacm_ds_ops = {
	DS_OPS_VERSION,
	usbsacm_ds_attach,
	usbsacm_ds_detach,
	usbsacm_ds_register_cb,
	usbsacm_ds_unregister_cb,
	usbsacm_ds_open_port,
	usbsacm_ds_close_port,
	usbsacm_ds_usb_power,
	usbsacm_ds_suspend,
	usbsacm_ds_resume,
	usbsacm_ds_disconnect,
	usbsacm_ds_reconnect,
	usbsacm_ds_set_port_params,
	usbsacm_ds_set_modem_ctl,
	usbsacm_ds_get_modem_ctl,
	usbsacm_ds_break_ctl,
	NULL,			/* NULL if h/w doesn't support loopback */
	usbsacm_ds_tx,
	usbsacm_ds_rx,
	usbsacm_ds_stop,
	usbsacm_ds_start,
	usbsacm_ds_fifo_flush,
	usbsacm_ds_fifo_drain
};

/*
 * baud code -> baud rate (0 means unsupported rate)
 */
static int usbsacm_speedtab[] = {
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
	307200,	/* B307200 */
	460800,	/* B460800 */
	921600	/* B921600 */
};


static uint_t	usbsacm_errlevel = USB_LOG_L4;
static uint_t	usbsacm_errmask = 0xffffffff;
static uint_t	usbsacm_instance_debug = (uint_t)-1;


/*
 * usbsacm driver's entry points
 * -----------------------------
 */
/*
 * Module-wide initialization routine.
 */
int
_init(void)
{
	int    error;

	if ((error = mod_install(&modlinkage)) == 0) {

		error = ddi_soft_state_init(&usbsacm_statep,
		    usbser_soft_state_size(), 1);
	}

	return (error);
}


/*
 * Module-wide tear-down routine.
 */
int
_fini(void)
{
	int    error;

	if ((error = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&usbsacm_statep);
	}

	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Device configuration entry points
 */
static int
usbsacm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	return (usbser_attach(dip, cmd, usbsacm_statep, &usbsacm_ds_ops));
}


static int
usbsacm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (usbser_detach(dip, cmd, usbsacm_statep));
}


int
usbsacm_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	return (usbser_getinfo(dip, infocmd, arg, result, usbsacm_statep));
}


static int
usbsacm_open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	return (usbser_open(rq, dev, flag, sflag, cr, usbsacm_statep));
}

/*
 * usbsacm_ds_detach:
 *	attach device instance, called from GSD attach
 *	initialize state and device, including:
 *		state variables, locks, device node
 *		device registration with system
 *		power management
 */
static int
usbsacm_ds_attach(ds_attach_info_t *aip)
{
	usbsacm_state_t	*acmp;

	acmp = (usbsacm_state_t *)kmem_zalloc(sizeof (usbsacm_state_t),
	    KM_SLEEP);
	acmp->acm_dip = aip->ai_dip;
	acmp->acm_usb_events = aip->ai_usb_events;
	acmp->acm_ports = NULL;
	*aip->ai_hdl = (ds_hdl_t)acmp;

	/* registers usbsacm with the USBA framework */
	if (usb_client_attach(acmp->acm_dip, USBDRV_VERSION,
	    0) != USB_SUCCESS) {

		goto fail;
	}

	/* Get the configuration information of device */
	if (usb_get_dev_data(acmp->acm_dip, &acmp->acm_dev_data,
	    USB_PARSE_LVL_CFG, 0) != USB_SUCCESS) {

		goto fail;
	}
	acmp->acm_def_ph = acmp->acm_dev_data->dev_default_ph;
	acmp->acm_dev_state = USB_DEV_ONLINE;
	mutex_init(&acmp->acm_mutex, NULL, MUTEX_DRIVER,
	    acmp->acm_dev_data->dev_iblock_cookie);

	acmp->acm_lh = usb_alloc_log_hdl(acmp->acm_dip, "usbsacm",
	    &usbsacm_errlevel, &usbsacm_errmask, &usbsacm_instance_debug, 0);

	/* Create power management components */
	if (usbsacm_create_pm_components(acmp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_ds_attach: create pm components failed.");

		goto fail;
	}

	/* Register to get callbacks for USB events */
	if (usb_register_event_cbs(acmp->acm_dip, acmp->acm_usb_events, 0)
	    != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_ds_attach: register event callback failed.");

		goto fail;
	}

	/*
	 * If devices conform to acm spec, driver will attach using class id;
	 * if not, using device id.
	 */
	if ((strcmp(DEVI(acmp->acm_dip)->devi_binding_name,
	    "usbif,class2.2") == 0) ||
	    ((strcmp(DEVI(acmp->acm_dip)->devi_binding_name,
	    "usb,class2.2.0") == 0))) {

		acmp->acm_compatibility = B_TRUE;
	} else {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_ds_attach: A nonstandard device is attaching to "
		    "usbsacm driver. This device doesn't conform to "
		    "usb cdc spec.");

		acmp->acm_compatibility = B_FALSE;
	}

	/* initialize state variables */
	if (usbsacm_init_alloc_ports(acmp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_ds_attach: initialize port structure failed.");

		goto fail;
	}
	*aip->ai_port_cnt = acmp->acm_port_cnt;

	/* Get max data size of bulk transfer */
	if (usb_pipe_get_max_bulk_transfer_size(acmp->acm_dip,
	    &acmp->acm_xfer_sz) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_ds_attach: get max size of transfer failed.");

		goto fail;
	}

	return (USB_SUCCESS);
fail:
	usbsacm_cleanup(acmp);

	return (USB_FAILURE);
}


/*
 * usbsacm_ds_detach:
 *	detach device instance, called from GSD detach
 */
static void
usbsacm_ds_detach(ds_hdl_t hdl)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_ds_detach:");

	usbsacm_close_pipes(acmp);
	usbsacm_cleanup(acmp);
}


/*
 * usbsacm_ds_register_cb:
 *	GSD routine call ds_register_cb to register interrupt callbacks
 *	for the given port
 */
/*ARGSUSED*/
static int
usbsacm_ds_register_cb(ds_hdl_t hdl, uint_t port_num, ds_cb_t *cb)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port;

	USB_DPRINTF_L4(PRINT_MASK_OPEN, acmp->acm_lh,
	    "usbsacm_ds_register_cb: acmp = 0x%p port_num = %d",
	    (void *)acmp, port_num);

	/* Check if port number is greater than actual port number. */
	if (port_num >= acmp->acm_port_cnt) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_ds_register_cb: port number is wrong.");

		return (USB_FAILURE);
	}
	acm_port = &acmp->acm_ports[port_num];
	acm_port->acm_cb = *cb;

	return (USB_SUCCESS);
}


/*
 * usbsacm_ds_unregister_cb:
 *	GSD routine call ds_unregister_cb to unregister
 *	interrupt callbacks for the given port
 */
/*ARGSUSED*/
static void
usbsacm_ds_unregister_cb(ds_hdl_t hdl, uint_t port_num)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_ds_unregister_cb: ");

	if (port_num < acmp->acm_port_cnt) {
		/* Release callback function */
		acm_port = &acmp->acm_ports[port_num];
		bzero(&acm_port->acm_cb, sizeof (acm_port->acm_cb));
	}
}


/*
 * usbsacm_ds_open_port:
 *	GSD routine call ds_open_port
 *	to open the given port
 */
/*ARGSUSED*/
static int
usbsacm_ds_open_port(ds_hdl_t hdl, uint_t port_num)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];

	USB_DPRINTF_L4(PRINT_MASK_OPEN, acmp->acm_lh,
	    "usbsacm_ds_open_port: port_num = %d", port_num);

	mutex_enter(&acm_port->acm_port_mutex);
	/* Check the status of the given port and device */
	if ((acmp->acm_dev_state == USB_DEV_DISCONNECTED) ||
	    (acm_port->acm_port_state != USBSACM_PORT_CLOSED)) {
		mutex_exit(&acm_port->acm_port_mutex);

		return (USB_FAILURE);
	}
	mutex_exit(&acm_port->acm_port_mutex);

	usbsacm_pm_set_busy(acmp);

	/* open pipes of port */
	if (usbsacm_open_port_pipes(acm_port) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_ds_open_port: open pipes failed.");

		return (USB_FAILURE);
	}

	mutex_enter(&acm_port->acm_port_mutex);
	/* data receipt */
	if (usbsacm_rx_start(acm_port) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_ds_open_port: start receive data failed.");
		mutex_exit(&acm_port->acm_port_mutex);

		return (USB_FAILURE);
	}
	acm_port->acm_port_state = USBSACM_PORT_OPEN;

	mutex_exit(&acm_port->acm_port_mutex);

	return (USB_SUCCESS);
}


/*
 * usbsacm_ds_close_port:
 *	GSD routine call ds_close_port
 *	to close the given port
 */
/*ARGSUSED*/
static int
usbsacm_ds_close_port(ds_hdl_t hdl, uint_t port_num)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];
	int		rval = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_ds_close_port: acmp = 0x%p", (void *)acmp);

	mutex_enter(&acm_port->acm_port_mutex);
	acm_port->acm_port_state = USBSACM_PORT_CLOSED;
	mutex_exit(&acm_port->acm_port_mutex);

	usbsacm_close_port_pipes(acm_port);

	mutex_enter(&acm_port->acm_port_mutex);
	rval = usbsacm_fifo_flush_locked(acmp, port_num, DS_TX | DS_RX);
	mutex_exit(&acm_port->acm_port_mutex);

	usbsacm_pm_set_idle(acmp);

	return (rval);
}


/*
 * usbsacm_ds_usb_power:
 *	GSD routine call ds_usb_power
 *	to set power level of the component
 */
/*ARGSUSED*/
static int
usbsacm_ds_usb_power(ds_hdl_t hdl, int comp, int level, int *new_state)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_pm_t	*pm = acmp->acm_pm;
	int		rval = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_PM, acmp->acm_lh,
	    "usbsacm_ds_usb_power: ");

	/* check if pm is NULL */
	if (pm == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_PM, acmp->acm_lh,
		    "usbsacm_ds_usb_power: pm is NULL.");

		return (USB_FAILURE);
	}

	mutex_enter(&acmp->acm_mutex);
	/*
	 * check if we are transitioning to a legal power level
	 */
	if (USB_DEV_PWRSTATE_OK(pm->pm_pwr_states, level)) {
		USB_DPRINTF_L2(PRINT_MASK_PM, acmp->acm_lh,
		    "usbsacm_ds_usb_power: "
		    "illegal power level %d, pwr_states=%x",
		    level, pm->pm_pwr_states);
		mutex_exit(&acmp->acm_mutex);

		return (USB_FAILURE);
	}

	/*
	 * if we are about to raise power and asked to lower power, fail
	 */
	if (pm->pm_raise_power && (level < (int)pm->pm_cur_power)) {
		USB_DPRINTF_L2(PRINT_MASK_PM, acmp->acm_lh,
		    "usbsacm_ds_usb_power: wrong condition.");
		mutex_exit(&acmp->acm_mutex);

		return (USB_FAILURE);
	}

	/*
	 * Set the power status of device by request level.
	 */
	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		rval = usbsacm_pwrlvl0(acmp);

		break;
	case USB_DEV_OS_PWR_1:
		rval = usbsacm_pwrlvl1(acmp);

		break;
	case USB_DEV_OS_PWR_2:
		rval = usbsacm_pwrlvl2(acmp);

		break;
	case USB_DEV_OS_FULL_PWR:
		rval = usbsacm_pwrlvl3(acmp);
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
			acmp->acm_dev_state = *new_state;
		}

		break;
	}

	*new_state = acmp->acm_dev_state;
	mutex_exit(&acmp->acm_mutex);

	return (rval);
}


/*
 * usbsacm_ds_suspend:
 *	GSD routine call ds_suspend
 *	during CPR suspend
 */
static int
usbsacm_ds_suspend(ds_hdl_t hdl)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	int		state = USB_DEV_SUSPENDED;

	USB_DPRINTF_L4(PRINT_MASK_PM, acmp->acm_lh,
	    "usbsacm_ds_suspend: ");
	/*
	 * If the device is suspended while it is under PWRED_DOWN state, we
	 * need to keep the PWRED_DOWN state so that it could be powered up
	 * later. In the mean while, usbser dev state will be changed to
	 * SUSPENDED state.
	 */
	mutex_enter(&acmp->acm_mutex);
	if (acmp->acm_dev_state != USB_DEV_PWRED_DOWN) {
		/* set device status to suspend */
		acmp->acm_dev_state = USB_DEV_SUSPENDED;
	}
	mutex_exit(&acmp->acm_mutex);

	usbsacm_disconnect_pipes(acmp);

	return (state);
}

/*
 * usbsacm_ds_resume:
 *	GSD routine call ds_resume
 *	during CPR resume
 */
/*ARGSUSED*/
static int
usbsacm_ds_resume(ds_hdl_t hdl)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	int		current_state;
	int		ret;

	USB_DPRINTF_L4(PRINT_MASK_PM, acmp->acm_lh,
	    "usbsacm_ds_resume: ");

	mutex_enter(&acmp->acm_mutex);
	current_state = acmp->acm_dev_state;
	mutex_exit(&acmp->acm_mutex);

	/* restore the status of device */
	if (current_state != USB_DEV_ONLINE) {
		ret = usbsacm_restore_device_state(acmp);
	} else {
		ret = USB_DEV_ONLINE;
	}

	return (ret);
}

/*
 * usbsacm_ds_disconnect:
 *	GSD routine call ds_disconnect
 *	to disconnect USB device
 */
static int
usbsacm_ds_disconnect(ds_hdl_t hdl)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	int		state = USB_DEV_DISCONNECTED;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_ds_disconnect: ");

	/*
	 * If the device is disconnected while it is under PWRED_DOWN state, we
	 * need to keep the PWRED_DOWN state so that it could be powered up
	 * later. In the mean while, usbser dev state will be changed to
	 * DISCONNECTED state.
	 */
	mutex_enter(&acmp->acm_mutex);
	if (acmp->acm_dev_state != USB_DEV_PWRED_DOWN) {
		/* set device status to disconnected */
		acmp->acm_dev_state = USB_DEV_DISCONNECTED;
	}
	mutex_exit(&acmp->acm_mutex);

	usbsacm_disconnect_pipes(acmp);

	return (state);
}


/*
 * usbsacm_ds_reconnect:
 *	GSD routine call ds_reconnect
 *	to reconnect USB device
 */
/*ARGSUSED*/
static int
usbsacm_ds_reconnect(ds_hdl_t hdl)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;

	USB_DPRINTF_L4(PRINT_MASK_OPEN, acmp->acm_lh,
	    "usbsacm_ds_reconnect: ");

	return (usbsacm_restore_device_state(acmp));
}


/*
 * usbsacm_ds_set_port_params:
 *	GSD routine call ds_set_port_params
 *	to set one or more port parameters
 */
/*ARGSUSED*/
static int
usbsacm_ds_set_port_params(ds_hdl_t hdl, uint_t port_num, ds_port_params_t *tp)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];
	int		i;
	uint_t		ui;
	ds_port_param_entry_t *pe;
	usb_cdc_line_coding_t lc;
	int		ret;

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_ds_set_port_params: acmp = 0x%p", (void *)acmp);

	mutex_enter(&acm_port->acm_port_mutex);
	/*
	 * If device conform to acm spec, check if it support to set port param.
	 */
	if ((acm_port->acm_cap & USB_CDC_ACM_CAP_SERIAL_LINE) == 0 &&
	    acmp->acm_compatibility == B_TRUE) {

		mutex_exit(&acm_port->acm_port_mutex);
		USB_DPRINTF_L2(PRINT_MASK_ALL, acmp->acm_lh,
		    "usbsacm_ds_set_port_params: "
		    "don't support Set_Line_Coding.");

		return (USB_FAILURE);
	}

	lc = acm_port->acm_line_coding;
	mutex_exit(&acm_port->acm_port_mutex);
	pe = tp->tp_entries;
	/* Get parameter information from ds_port_params_t */
	for (i = 0; i < tp->tp_cnt; i++, pe++) {
		switch (pe->param) {
		case DS_PARAM_BAUD:
			/* Data terminal rate, in bits per second. */
			ui = pe->val.ui;

			/* if we don't support this speed, return USB_FAILURE */
			if ((ui >= NELEM(usbsacm_speedtab)) ||
			    ((ui > 0) && (usbsacm_speedtab[ui] == 0))) {
				USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
				    "usbsacm_ds_set_port_params: "
				    " error baud rate");

				return (USB_FAILURE);
			}
			lc.dwDTERate = LE_32(usbsacm_speedtab[ui]);

			break;
		case DS_PARAM_PARITY:
			/* Parity Type */
			if (pe->val.ui & PARENB) {
				if (pe->val.ui & PARODD) {
					lc.bParityType = USB_CDC_PARITY_ODD;
				} else {
					lc.bParityType = USB_CDC_PARITY_EVEN;
				}
			} else {
				lc.bParityType = USB_CDC_PARITY_NO;
			}

			break;
		case DS_PARAM_STOPB:
			/* Stop bit */
			if (pe->val.ui & CSTOPB) {
				lc.bCharFormat = USB_CDC_STOP_BITS_2;
			} else {
				lc.bCharFormat = USB_CDC_STOP_BITS_1;
			}

			break;
		case DS_PARAM_CHARSZ:
			/* Data Bits */
			switch (pe->val.ui) {
			case CS5:
				lc.bDataBits = 5;
				break;
			case CS6:
				lc.bDataBits = 6;
				break;
			case CS7:
				lc.bDataBits = 7;
				break;
			case CS8:
			default:
				lc.bDataBits = 8;
				break;
			}

			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
			    "usbsacm_ds_set_port_params: "
			    "parameter 0x%x isn't supported",
			    pe->param);

			break;
		}
	}

	if ((ret = usbsacm_set_line_coding(acm_port, &lc)) == USB_SUCCESS) {
		mutex_enter(&acm_port->acm_port_mutex);
		acm_port->acm_line_coding = lc;
		mutex_exit(&acm_port->acm_port_mutex);
	}

	/*
	 * If device don't conform to acm spec, return success directly.
	 */
	if (acmp->acm_compatibility != B_TRUE) {
		ret = USB_SUCCESS;
	}

	return (ret);
}


/*
 * usbsacm_ds_set_modem_ctl:
 *	GSD routine call ds_set_modem_ctl
 *	to set modem control of the given port
 */
/*ARGSUSED*/
static int
usbsacm_ds_set_modem_ctl(ds_hdl_t hdl, uint_t port_num, int mask, int val)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];
	uint8_t		new_mctl;
	int		ret;

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_ds_set_modem_ctl: mask = 0x%x val = 0x%x",
	    mask, val);

	mutex_enter(&acm_port->acm_port_mutex);
	/*
	 * If device conform to acm spec, check if it support to set modem
	 * controls.
	 */
	if ((acm_port->acm_cap & USB_CDC_ACM_CAP_SERIAL_LINE) == 0 &&
	    acmp->acm_compatibility == B_TRUE) {

		mutex_exit(&acm_port->acm_port_mutex);
		USB_DPRINTF_L2(PRINT_MASK_ALL, acmp->acm_lh,
		    "usbsacm_ds_set_modem_ctl: "
		    "don't support Set_Control_Line_State.");

		return (USB_FAILURE);
	}

	new_mctl = acm_port->acm_mctlout;
	mutex_exit(&acm_port->acm_port_mutex);

	usbsacm_mctl2reg(mask, val, &new_mctl);

	if ((acmp->acm_compatibility == B_FALSE) || ((ret =
	    usbsacm_req_write(acm_port, USB_CDC_REQ_SET_CONTROL_LINE_STATE,
	    new_mctl, NULL)) == USB_SUCCESS)) {
		mutex_enter(&acm_port->acm_port_mutex);
		acm_port->acm_mctlout = new_mctl;
		mutex_exit(&acm_port->acm_port_mutex);
	}

	/*
	 * If device don't conform to acm spec, return success directly.
	 */
	if (acmp->acm_compatibility != B_TRUE) {
		ret = USB_SUCCESS;
	}

	return (ret);
}


/*
 * usbsacm_ds_get_modem_ctl:
 *	GSD routine call ds_get_modem_ctl
 *	to get modem control/status of the given port
 */
/*ARGSUSED*/
static int
usbsacm_ds_get_modem_ctl(ds_hdl_t hdl, uint_t port_num, int mask, int *valp)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];

	mutex_enter(&acm_port->acm_port_mutex);
	*valp = usbsacm_reg2mctl(acm_port->acm_mctlout) & mask;
	/*
	 * If device conform to acm spec, polling function can modify the value
	 * of acm_mctlin; else set to default value.
	 */
	if (acmp->acm_compatibility) {
		*valp |= usbsacm_reg2mctl(acm_port->acm_mctlin) & mask;
		*valp |= (mask & (TIOCM_CD | TIOCM_CTS));
	} else {
		*valp |= (mask & (TIOCM_CD | TIOCM_CTS | TIOCM_DSR | TIOCM_RI));
	}
	mutex_exit(&acm_port->acm_port_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_ds_get_modem_ctl: val = 0x%x", *valp);

	return (USB_SUCCESS);
}


/*
 * usbsacm_ds_tx:
 *	GSD routine call ds_break_ctl
 *	to set/clear break
 */
/*ARGSUSED*/
static int
usbsacm_ds_break_ctl(ds_hdl_t hdl, uint_t port_num, int ctl)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_ds_break_ctl: ");

	mutex_enter(&acm_port->acm_port_mutex);
	/*
	 * If device conform to acm spec, check if it support to send break.
	 */
	if ((acm_port->acm_cap & USB_CDC_ACM_CAP_SEND_BREAK) == 0 &&
	    acmp->acm_compatibility == B_TRUE) {

		mutex_exit(&acm_port->acm_port_mutex);
		USB_DPRINTF_L2(PRINT_MASK_ALL, acmp->acm_lh,
		    "usbsacm_ds_break_ctl: don't support send break.");

		return (USB_FAILURE);
	}
	mutex_exit(&acm_port->acm_port_mutex);

	return (usbsacm_req_write(acm_port, USB_CDC_REQ_SEND_BREAK,
	    ((ctl == DS_ON) ? 0xffff : 0), NULL));
}


/*
 * usbsacm_ds_tx:
 *	GSD routine call ds_tx
 *	to data transmit
 */
/*ARGSUSED*/
static int
usbsacm_ds_tx(ds_hdl_t hdl, uint_t port_num, mblk_t *mp)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_ds_tx: mp = 0x%p acmp = 0x%p", (void *)mp, (void *)acmp);

	/* sanity checks */
	if (mp == NULL) {

		return (USB_SUCCESS);
	}
	if (MBLKL(mp) < 1) {
		freemsg(mp);

		return (USB_SUCCESS);
	}

	mutex_enter(&acm_port->acm_port_mutex);
	/* put mblk to tail of mblk chain */
	usbsacm_put_tail(&acm_port->acm_tx_mp, mp);
	usbsacm_tx_start(acm_port);
	mutex_exit(&acm_port->acm_port_mutex);

	return (USB_SUCCESS);
}


/*
 * usbsacm_ds_rx:
 *	GSD routine call ds_rx;
 *	to data receipt
 */
/*ARGSUSED*/
static mblk_t *
usbsacm_ds_rx(ds_hdl_t hdl, uint_t port_num)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];
	mblk_t		*mp;

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_ds_rx: acmp = 0x%p", (void *)acmp);

	mutex_enter(&acm_port->acm_port_mutex);

	mp = acm_port->acm_rx_mp;
	acm_port->acm_rx_mp = NULL;
	mutex_exit(&acm_port->acm_port_mutex);

	return (mp);
}


/*
 * usbsacm_ds_stop:
 *	GSD routine call ds_stop;
 *	but acm spec don't define this function
 */
/*ARGSUSED*/
static void
usbsacm_ds_stop(ds_hdl_t hdl, uint_t port_num, int dir)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;

	USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
	    "usbsacm_ds_stop: don't support!");
}


/*
 * usbsacm_ds_start:
 *	GSD routine call ds_start;
 *	but acm spec don't define this function
 */
/*ARGSUSED*/
static void
usbsacm_ds_start(ds_hdl_t hdl, uint_t port_num, int dir)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;

	USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
	    "usbsacm_ds_start: don't support!");
}


/*
 * usbsacm_ds_fifo_flush:
 *	GSD routine call ds_fifo_flush
 *	to flush FIFOs
 */
/*ARGSUSED*/
static int
usbsacm_ds_fifo_flush(ds_hdl_t hdl, uint_t port_num, int dir)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];
	int		ret = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_ds_fifo_flush: ");

	mutex_enter(&acm_port->acm_port_mutex);
	ret = usbsacm_fifo_flush_locked(acmp, port_num, dir);
	mutex_exit(&acm_port->acm_port_mutex);

	return (ret);
}


/*
 * usbsacm_ds_fifo_drain:
 *	GSD routine call ds_fifo_drain
 *	to wait until empty output FIFO
 */
/*ARGSUSED*/
static int
usbsacm_ds_fifo_drain(ds_hdl_t hdl, uint_t port_num, int timeout)
{
	usbsacm_state_t	*acmp = (usbsacm_state_t *)hdl;
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];
	int		rval = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, acmp->acm_lh,
	    "usbsacm_ds_fifo_drain: ");

	mutex_enter(&acm_port->acm_port_mutex);
	ASSERT(acm_port->acm_port_state == USBSACM_PORT_OPEN);

	if (usbsacm_wait_tx_drain(acm_port, timeout) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
		    "usbsacm_ds_fifo_drain: fifo drain failed.");
		mutex_exit(&acm_port->acm_port_mutex);

		return (USB_FAILURE);
	}

	mutex_exit(&acm_port->acm_port_mutex);

	return (rval);
}


/*
 * usbsacm_fifo_flush_locked:
 *	flush FIFOs of the given ports
 */
/*ARGSUSED*/
static int
usbsacm_fifo_flush_locked(usbsacm_state_t *acmp, uint_t port_num, int dir)
{
	usbsacm_port_t	*acm_port = &acmp->acm_ports[port_num];

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, acmp->acm_lh,
	    "usbsacm_fifo_flush_locked: ");

	/* flush transmit FIFO if DS_TX is set */
	if ((dir & DS_TX) && acm_port->acm_tx_mp) {
		freemsg(acm_port->acm_tx_mp);
		acm_port->acm_tx_mp = NULL;
	}
	/* flush received FIFO if DS_RX is set */
	if ((dir & DS_RX) && acm_port->acm_rx_mp) {
		freemsg(acm_port->acm_rx_mp);
		acm_port->acm_rx_mp = NULL;
	}

	return (USB_SUCCESS);
}


/*
 * usbsacm_get_bulk_pipe_number:
 *	Calculate the number of bulk in or out pipes in current device.
 */
static int
usbsacm_get_bulk_pipe_number(usbsacm_state_t *acmp, uint_t dir)
{
	int		count = 0;
	int		i, skip;
	usb_if_data_t	*cur_if;
	int		ep_num;
	int		if_num;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, acmp->acm_lh,
	    "usbsacm_get_bulk_pipe_number: ");

	cur_if = acmp->acm_dev_data->dev_curr_cfg->cfg_if;
	if_num = acmp->acm_dev_data->dev_curr_cfg->cfg_n_if;

	/* search each interface which have bulk endpoint */
	for (i = 0; i < if_num; i++) {
		ep_num = cur_if->if_alt->altif_n_ep;

		/*
		 * search endpoints in current interface,
		 * which type is input parameter 'dir'
		 */
		for (skip = 0; skip < ep_num; skip++) {
			if (usb_lookup_ep_data(acmp->acm_dip,
			    acmp->acm_dev_data, i, 0, skip,
			    USB_EP_ATTR_BULK, dir) == NULL) {

				/*
				 * If not found, skip the internal loop
				 * and search the next interface.
				 */
				break;
			}
			count++;
		}

		cur_if++;
	}

	return (count);
}


/*
 * port management
 * ---------------
 *	initialize, release port.
 *
 *
 * usbsacm_init_ports_status:
 *	Initialize the port status for the current device.
 */
static int
usbsacm_init_ports_status(usbsacm_state_t *acmp)
{
	usbsacm_port_t	*cur_port;
	int		i, skip;
	int		if_num;
	int		intr_if_no = 0;
	int		ep_num;
	usb_if_data_t	*cur_if;

	USB_DPRINTF_L4(PRINT_MASK_OPEN, acmp->acm_lh,
	    "usbsacm_init_ports_status: acmp = 0x%p", (void *)acmp);

	/* Initialize the port status to default value */
	for (i = 0; i < acmp->acm_port_cnt; i++) {
		cur_port = &acmp->acm_ports[i];

		cv_init(&cur_port->acm_tx_cv, NULL, CV_DRIVER, NULL);

		cur_port->acm_port_state = USBSACM_PORT_CLOSED;

		cur_port->acm_line_coding.dwDTERate = LE_32((uint32_t)9600);
		cur_port->acm_line_coding.bCharFormat = 0;
		cur_port->acm_line_coding.bParityType = USB_CDC_PARITY_NO;
		cur_port->acm_line_coding.bDataBits = 8;
		cur_port->acm_device = acmp;
		mutex_init(&cur_port->acm_port_mutex, NULL, MUTEX_DRIVER,
		    acmp->acm_dev_data->dev_iblock_cookie);
	}

	/*
	 * If device conform to cdc acm spec, parse function descriptors.
	 */
	if (acmp->acm_compatibility == B_TRUE) {

		if (usbsacm_get_descriptors(acmp) != USB_SUCCESS) {

			return (USB_FAILURE);
		}

		return (USB_SUCCESS);
	}

	/*
	 * If device don't conform to spec, search pairs of bulk in/out
	 * endpoints and fill port structure.
	 */
	cur_if = acmp->acm_dev_data->dev_curr_cfg->cfg_if;
	if_num = acmp->acm_dev_data->dev_curr_cfg->cfg_n_if;
	cur_port = acmp->acm_ports;

	/* search each interface which have bulk in and out */
	for (i = 0; i < if_num; i++) {
		ep_num = cur_if->if_alt->altif_n_ep;

		for (skip = 0; skip < ep_num; skip++) {

		/* search interrupt pipe. */
		if ((usb_lookup_ep_data(acmp->acm_dip, acmp->acm_dev_data,
		    i, 0, skip, USB_EP_ATTR_INTR, USB_EP_DIR_IN) != NULL)) {

			intr_if_no = i;
		}

		/* search pair of bulk in/out endpoints. */
		if ((usb_lookup_ep_data(acmp->acm_dip, acmp->acm_dev_data,
		    i, 0, skip, USB_EP_ATTR_BULK, USB_EP_DIR_IN) == NULL) ||
		    (usb_lookup_ep_data(acmp->acm_dip, acmp->acm_dev_data,
		    i, 0, skip, USB_EP_ATTR_BULK, USB_EP_DIR_OUT) == NULL)) {

			continue;
		}

		cur_port->acm_data_if_no = i;
		cur_port->acm_ctrl_if_no = intr_if_no;
		cur_port->acm_data_port_no = skip;
		cur_port++;
		intr_if_no = 0;
		}

		cur_if++;
	}

	return (USB_SUCCESS);
}


/*
 * usbsacm_init_alloc_ports:
 *	Allocate memory and initialize the port state for the current device.
 */
static int
usbsacm_init_alloc_ports(usbsacm_state_t *acmp)
{
	int		rval = USB_SUCCESS;
	int		count_in = 0, count_out = 0;

	if (acmp->acm_compatibility) {
		acmp->acm_port_cnt = 1;
	} else {
		/* Calculate the number of the bulk in/out endpoints */
		count_in = usbsacm_get_bulk_pipe_number(acmp, USB_EP_DIR_IN);
		count_out = usbsacm_get_bulk_pipe_number(acmp, USB_EP_DIR_OUT);

		USB_DPRINTF_L3(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_init_alloc_ports: count_in = %d, count_out = %d",
		    count_in, count_out);

		acmp->acm_port_cnt = min(count_in, count_out);
	}

	/* return if not found any pair of bulk in/out endpoint. */
	if (acmp->acm_port_cnt == 0) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_init_alloc_ports: port count is zero.");

		return (USB_FAILURE);
	}

	/* allocate memory for ports */
	acmp->acm_ports = (usbsacm_port_t *)kmem_zalloc(acmp->acm_port_cnt *
	    sizeof (usbsacm_port_t), KM_SLEEP);
	if (acmp->acm_ports == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_init_alloc_ports: allocate memory failed.");

		return (USB_FAILURE);
	}

	/* fill the status of port structure. */
	rval = usbsacm_init_ports_status(acmp);
	if (rval != USB_SUCCESS) {
		usbsacm_free_ports(acmp);
	}

	return (rval);
}


/*
 * usbsacm_free_ports:
 *	Release ports and deallocate memory.
 */
static void
usbsacm_free_ports(usbsacm_state_t *acmp)
{
	int		i;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_free_ports: ");

	/* Release memory and data structure for each port */
	for (i = 0; i < acmp->acm_port_cnt; i++) {
		cv_destroy(&acmp->acm_ports[i].acm_tx_cv);
		mutex_destroy(&acmp->acm_ports[i].acm_port_mutex);
	}
	kmem_free((caddr_t)acmp->acm_ports, sizeof (usbsacm_port_t) *
	    acmp->acm_port_cnt);
	acmp->acm_ports = NULL;
}


/*
 * usbsacm_get_descriptors:
 *	analysis functional descriptors of acm device
 */
static int
usbsacm_get_descriptors(usbsacm_state_t *acmp)
{
	int			i;
	usb_cfg_data_t		*cfg;
	usb_alt_if_data_t	*altif;
	usb_cvs_data_t		*cvs;
	int			mgmt_cap = 0;
	int			master_if = -1, slave_if = -1;
	usbsacm_port_t		*acm_port = acmp->acm_ports;
	usb_dev_descr_t		*dd;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, acmp->acm_lh,
	    "usbsacm_get_descriptors: ");

	dd = acmp->acm_dev_data->dev_descr;
	cfg = acmp->acm_dev_data->dev_curr_cfg;
	/* set default control and data interface */
	acm_port->acm_ctrl_if_no = acm_port->acm_data_if_no = 0;

	/* get current interfaces */
	acm_port->acm_ctrl_if_no = acmp->acm_dev_data->dev_curr_if;
	if (cfg->cfg_if[acm_port->acm_ctrl_if_no].if_n_alt == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_get_descriptors: elements in if_alt is %d",
		    cfg->cfg_if[acm_port->acm_ctrl_if_no].if_n_alt);

		return (USB_FAILURE);
	}

	altif = &cfg->cfg_if[acm_port->acm_ctrl_if_no].if_alt[0];

	/*
	 * Based on CDC specification, ACM devices usually include the
	 * following function descriptors: Header, ACM, Union and Call
	 * Management function descriptors. This loop search tree data
	 * structure for each acm class descriptor.
	 */
	for (i = 0; i < altif->altif_n_cvs; i++) {

		cvs = &altif->altif_cvs[i];

		if ((cvs->cvs_buf == NULL) ||
		    (cvs->cvs_buf[1] != USB_CDC_CS_INTERFACE)) {
			continue;
		}

		switch (cvs->cvs_buf[2]) {
		case USB_CDC_DESCR_TYPE_CALL_MANAGEMENT:
			/* parse call management functional descriptor. */
			if (cvs->cvs_buf_len >= 5) {
				mgmt_cap = cvs->cvs_buf[3];
				acm_port->acm_data_if_no = cvs->cvs_buf[4];
			}
			break;
		case USB_CDC_DESCR_TYPE_ACM:
			/* parse ACM functional descriptor. */
			if (cvs->cvs_buf_len >= 4) {
				acm_port->acm_cap = cvs->cvs_buf[3];
			}

			/*
			 * The Sigma Designs, Inc. USB device does not report
			 * itself as implementing the full ACM spec. However,
			 * it does function as a usb serial modem, so we opt to
			 * scribble in the reported functionality if we
			 * determine the USB device matches this vendor
			 * and product ID.
			 */
			if (dd->idVendor == USB_VENDOR_SIGMADESIGNS &&
			    dd->idProduct == USB_PRODUCT_SIGMADESIGNS_ZW090) {
				acm_port->acm_cap |=
				    USB_CDC_ACM_CAP_SERIAL_LINE;
			}
			break;
		case USB_CDC_DESCR_TYPE_UNION:
			/* parse Union functional descriptor. */
			if (cvs->cvs_buf_len >= 5) {
				master_if = cvs->cvs_buf[3];
				slave_if = cvs->cvs_buf[4];
			}
			break;
		default:
			break;
		}
	}

	/* For usb acm devices, it must satisfy the following options. */
	if (cfg->cfg_n_if < 2) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_get_descriptors: # of interfaces %d < 2",
		    cfg->cfg_n_if);

		return (USB_FAILURE);
	}

	if (acm_port->acm_data_if_no == 0 &&
	    slave_if != acm_port->acm_data_if_no) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_get_descriptors: Device hasn't call management "
		    "descriptor and use Union Descriptor.");

		acm_port->acm_data_if_no = slave_if;
	}

	if ((master_if != acm_port->acm_ctrl_if_no) ||
	    (slave_if != acm_port->acm_data_if_no)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_get_descriptors: control interface or "
		    "data interface don't match.");

		return (USB_FAILURE);
	}

	/*
	 * We usually need both call and data capabilities, but
	 * some devices, such as Nokia mobile phones, don't provide
	 * call management descriptor, so we just give a warning
	 * message.
	 */
	if (((mgmt_cap & USB_CDC_CALL_MGMT_CAP_CALL_MGMT) == 0) ||
	    ((mgmt_cap & USB_CDC_CALL_MGMT_CAP_DATA_INTERFACE) == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_get_descriptors: "
		    "insufficient mgmt capabilities %x",
		    mgmt_cap);
	}

	if ((acm_port->acm_ctrl_if_no >= cfg->cfg_n_if) ||
	    (acm_port->acm_data_if_no >= cfg->cfg_n_if)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_get_descriptors: control interface %d or "
		    "data interface %d out of range.",
		    acm_port->acm_ctrl_if_no, acm_port->acm_data_if_no);

		return (USB_FAILURE);
	}

	/* control interface must have interrupt endpoint */
	if (usb_lookup_ep_data(acmp->acm_dip, acmp->acm_dev_data,
	    acm_port->acm_ctrl_if_no, 0, 0, USB_EP_ATTR_INTR,
	    USB_EP_DIR_IN) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_get_descriptors: "
		    "ctrl interface %d has no interrupt endpoint",
		    acm_port->acm_data_if_no);

		return (USB_FAILURE);
	}

	/* data interface must have bulk in and out */
	if (usb_lookup_ep_data(acmp->acm_dip, acmp->acm_dev_data,
	    acm_port->acm_data_if_no, 0, 0, USB_EP_ATTR_BULK,
	    USB_EP_DIR_IN) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_get_descriptors: "
		    "data interface %d has no bulk in endpoint",
		    acm_port->acm_data_if_no);

		return (USB_FAILURE);
	}
	if (usb_lookup_ep_data(acmp->acm_dip, acmp->acm_dev_data,
	    acm_port->acm_data_if_no, 0, 0, USB_EP_ATTR_BULK,
	    USB_EP_DIR_OUT) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_get_descriptors: "
		    "data interface %d has no bulk out endpoint",
		    acm_port->acm_data_if_no);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * usbsacm_cleanup:
 *	Release resources of current device during detach.
 */
static void
usbsacm_cleanup(usbsacm_state_t *acmp)
{
	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_cleanup: ");

	if (acmp != NULL) {
		/* free ports */
		if (acmp->acm_ports != NULL) {
			usbsacm_free_ports(acmp);
		}

		/* unregister callback function */
		if (acmp->acm_usb_events != NULL) {
			usb_unregister_event_cbs(acmp->acm_dip,
			    acmp->acm_usb_events);
		}

		/* destroy power management components */
		if (acmp->acm_pm != NULL) {
			usbsacm_destroy_pm_components(acmp);
		}

		/* free description of device tree. */
		if (acmp->acm_def_ph != NULL) {
			mutex_destroy(&acmp->acm_mutex);

			usb_free_descr_tree(acmp->acm_dip, acmp->acm_dev_data);
			acmp->acm_def_ph = NULL;
		}

		if (acmp->acm_lh != NULL) {
			usb_free_log_hdl(acmp->acm_lh);
			acmp->acm_lh = NULL;
		}

		/* detach client device */
		if (acmp->acm_dev_data != NULL) {
			usb_client_detach(acmp->acm_dip, acmp->acm_dev_data);
		}

		kmem_free((caddr_t)acmp, sizeof (usbsacm_state_t));
	}
}


/*
 * usbsacm_restore_device_state:
 *	restore device state after CPR resume or reconnect
 */
static int
usbsacm_restore_device_state(usbsacm_state_t *acmp)
{
	int	state;

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_restore_device_state: ");

	mutex_enter(&acmp->acm_mutex);
	state = acmp->acm_dev_state;
	mutex_exit(&acmp->acm_mutex);

	/* Check device status */
	if ((state != USB_DEV_DISCONNECTED) && (state != USB_DEV_SUSPENDED)) {

		return (state);
	}

	/* Check if we are talking to the same device */
	if (usb_check_same_device(acmp->acm_dip, acmp->acm_lh, USB_LOG_L0,
	    -1, USB_CHK_ALL, NULL) != USB_SUCCESS) {
		mutex_enter(&acmp->acm_mutex);
		state = acmp->acm_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&acmp->acm_mutex);

		return (state);
	}

	if (state == USB_DEV_DISCONNECTED) {
		USB_DPRINTF_L1(PRINT_MASK_ALL, acmp->acm_lh,
		    "usbsacm_restore_device_state: Device has been reconnected "
		    "but data may have been lost");
	}

	/* reconnect pipes */
	if (usbsacm_reconnect_pipes(acmp) != USB_SUCCESS) {

		return (state);
	}

	/*
	 * init device state
	 */
	mutex_enter(&acmp->acm_mutex);
	state = acmp->acm_dev_state = USB_DEV_ONLINE;
	mutex_exit(&acmp->acm_mutex);

	if ((usbsacm_restore_port_state(acmp) != USB_SUCCESS)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
		    "usbsacm_restore_device_state: failed");
	}

	return (state);
}


/*
 * usbsacm_restore_port_state:
 *	restore ports state after CPR resume or reconnect
 */
static int
usbsacm_restore_port_state(usbsacm_state_t *acmp)
{
	int		i, ret = USB_SUCCESS;
	usbsacm_port_t	*cur_port;

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_restore_port_state: ");

	/* restore status of all ports */
	for (i = 0; i < acmp->acm_port_cnt; i++) {
		cur_port = &acmp->acm_ports[i];
		mutex_enter(&cur_port->acm_port_mutex);
		if (cur_port->acm_port_state != USBSACM_PORT_OPEN) {
			mutex_exit(&cur_port->acm_port_mutex);

			continue;
		}
		mutex_exit(&cur_port->acm_port_mutex);

		if ((ret = usbsacm_set_line_coding(cur_port,
		    &cur_port->acm_line_coding)) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, acmp->acm_lh,
			    "usbsacm_restore_port_state: failed.");
		}
	}

	return (ret);
}


/*
 * pipe management
 * ---------------
 *
 *
 * usbsacm_open_port_pipes:
 *	Open pipes of one port and set port structure;
 *	Each port includes three pipes: bulk in, bulk out and interrupt.
 */
static int
usbsacm_open_port_pipes(usbsacm_port_t *acm_port)
{
	int		rval = USB_SUCCESS;
	usbsacm_state_t	*acmp = acm_port->acm_device;
	usb_ep_data_t	*in_data, *out_data, *intr_pipe;
	usb_pipe_policy_t policy;

	USB_DPRINTF_L4(PRINT_MASK_OPEN, acmp->acm_lh,
	    "usbsacm_open_port_pipes: acmp = 0x%p", (void *)acmp);

	/* Get bulk and interrupt endpoint data */
	intr_pipe = usb_lookup_ep_data(acmp->acm_dip, acmp->acm_dev_data,
	    acm_port->acm_ctrl_if_no, 0, 0,
	    USB_EP_ATTR_INTR, USB_EP_DIR_IN);
	in_data = usb_lookup_ep_data(acmp->acm_dip, acmp->acm_dev_data,
	    acm_port->acm_data_if_no, 0, acm_port->acm_data_port_no,
	    USB_EP_ATTR_BULK, USB_EP_DIR_IN);
	out_data = usb_lookup_ep_data(acmp->acm_dip, acmp->acm_dev_data,
	    acm_port->acm_data_if_no, 0, acm_port->acm_data_port_no,
	    USB_EP_ATTR_BULK, USB_EP_DIR_OUT);

	/* Bulk in and out must exist meanwhile. */
	if ((in_data == NULL) || (out_data == NULL)) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_open_port_pipes: look up bulk pipe failed in "
		    "interface %d port %d",
		    acm_port->acm_data_if_no, acm_port->acm_data_port_no);

		return (USB_FAILURE);
	}

	/*
	 * If device conform to acm spec, it must have an interrupt pipe
	 * for this port.
	 */
	if (acmp->acm_compatibility == B_TRUE && intr_pipe == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_open_port_pipes: look up interrupt pipe failed in "
		    "interface %d", acm_port->acm_ctrl_if_no);

		return (USB_FAILURE);
	}

	policy.pp_max_async_reqs = 2;

	/* Open bulk in endpoint */
	if (usb_pipe_open(acmp->acm_dip, &in_data->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &acm_port->acm_bulkin_ph) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_open_port_pipes: open bulkin pipe failed!");

		return (USB_FAILURE);
	}

	/* Open bulk out endpoint */
	if (usb_pipe_open(acmp->acm_dip, &out_data->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &acm_port->acm_bulkout_ph) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_open_port_pipes: open bulkout pipe failed!");

		usb_pipe_close(acmp->acm_dip, acm_port->acm_bulkin_ph,
		    USB_FLAGS_SLEEP, NULL, NULL);

		return (USB_FAILURE);
	}

	/* Open interrupt endpoint if found. */
	if (intr_pipe != NULL) {

		if (usb_pipe_open(acmp->acm_dip, &intr_pipe->ep_descr, &policy,
		    USB_FLAGS_SLEEP, &acm_port->acm_intr_ph) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
			    "usbsacm_open_port_pipes: "
			    "open control pipe failed");

			usb_pipe_close(acmp->acm_dip, acm_port->acm_bulkin_ph,
			    USB_FLAGS_SLEEP, NULL, NULL);
			usb_pipe_close(acmp->acm_dip, acm_port->acm_bulkout_ph,
			    USB_FLAGS_SLEEP, NULL, NULL);

			return (USB_FAILURE);
		}
	}

	/* initialize the port structure. */
	mutex_enter(&acm_port->acm_port_mutex);
	acm_port->acm_bulkin_size = in_data->ep_descr.wMaxPacketSize;
	acm_port->acm_bulkin_state = USBSACM_PIPE_IDLE;
	acm_port->acm_bulkout_state = USBSACM_PIPE_IDLE;
	if (acm_port->acm_intr_ph != NULL) {
		acm_port->acm_intr_state = USBSACM_PIPE_IDLE;
		acm_port->acm_intr_ep_descr = intr_pipe->ep_descr;
	}
	mutex_exit(&acm_port->acm_port_mutex);

	if (acm_port->acm_intr_ph != NULL) {

		usbsacm_pipe_start_polling(acm_port);
	}

	return (rval);
}


/*
 * usbsacm_close_port_pipes:
 *	Close pipes of one port and reset port structure to closed;
 *	Each port includes three pipes: bulk in, bulk out and interrupt.
 */
static void
usbsacm_close_port_pipes(usbsacm_port_t	*acm_port)
{
	usbsacm_state_t	*acmp = acm_port->acm_device;

	mutex_enter(&acm_port->acm_port_mutex);
	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_close_port_pipes: acm_bulkin_state = %d",
	    acm_port->acm_bulkin_state);

	/*
	 * Check the status of the given port. If port is closing or closed,
	 * return directly.
	 */
	if ((acm_port->acm_bulkin_state == USBSACM_PIPE_CLOSED) ||
	    (acm_port->acm_bulkin_state == USBSACM_PIPE_CLOSING)) {
		USB_DPRINTF_L2(PRINT_MASK_CLOSE, acmp->acm_lh,
		    "usbsacm_close_port_pipes: port is closing or has closed");
		mutex_exit(&acm_port->acm_port_mutex);

		return;
	}

	acm_port->acm_bulkin_state = USBSACM_PIPE_CLOSING;
	mutex_exit(&acm_port->acm_port_mutex);

	/* Close pipes */
	usb_pipe_reset(acmp->acm_dip, acm_port->acm_bulkin_ph,
	    USB_FLAGS_SLEEP, 0, 0);
	usb_pipe_close(acmp->acm_dip, acm_port->acm_bulkin_ph,
	    USB_FLAGS_SLEEP, 0, 0);
	usb_pipe_close(acmp->acm_dip, acm_port->acm_bulkout_ph,
	    USB_FLAGS_SLEEP, 0, 0);
	if (acm_port->acm_intr_ph != NULL) {
		usb_pipe_stop_intr_polling(acm_port->acm_intr_ph,
		    USB_FLAGS_SLEEP);
		usb_pipe_close(acmp->acm_dip, acm_port->acm_intr_ph,
		    USB_FLAGS_SLEEP, 0, 0);
	}

	mutex_enter(&acm_port->acm_port_mutex);
	/* Reset the status of pipes to closed */
	acm_port->acm_bulkin_state = USBSACM_PIPE_CLOSED;
	acm_port->acm_bulkin_ph = NULL;
	acm_port->acm_bulkout_state = USBSACM_PIPE_CLOSED;
	acm_port->acm_bulkout_ph = NULL;
	if (acm_port->acm_intr_ph != NULL) {
		acm_port->acm_intr_state = USBSACM_PIPE_CLOSED;
		acm_port->acm_intr_ph = NULL;
	}

	mutex_exit(&acm_port->acm_port_mutex);

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_close_port_pipes: port has been closed.");
}


/*
 * usbsacm_close_pipes:
 *	close all opened pipes of current devices.
 */
static void
usbsacm_close_pipes(usbsacm_state_t *acmp)
{
	int		i;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_close_pipes: ");

	/* Close all ports */
	for (i = 0; i < acmp->acm_port_cnt; i++) {
		usbsacm_close_port_pipes(&acmp->acm_ports[i]);
	}
}


/*
 * usbsacm_disconnect_pipes:
 *	this function just call usbsacm_close_pipes.
 */
static void
usbsacm_disconnect_pipes(usbsacm_state_t *acmp)
{
	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_disconnect_pipes: ");

	usbsacm_close_pipes(acmp);
}


/*
 * usbsacm_reconnect_pipes:
 *	reconnect pipes in CPR resume or reconnect
 */
static int
usbsacm_reconnect_pipes(usbsacm_state_t *acmp)
{
	usbsacm_port_t	*cur_port = acmp->acm_ports;
	int		i;

	USB_DPRINTF_L4(PRINT_MASK_OPEN, acmp->acm_lh,
	    "usbsacm_reconnect_pipes: ");

	/* reopen all ports of current device. */
	for (i = 0; i < acmp->acm_port_cnt; i++) {
		cur_port = &acmp->acm_ports[i];

		mutex_enter(&cur_port->acm_port_mutex);
		/*
		 * If port status is open, reopen it;
		 * else retain the current status.
		 */
		if (cur_port->acm_port_state == USBSACM_PORT_OPEN) {

			mutex_exit(&cur_port->acm_port_mutex);
			if (usbsacm_open_port_pipes(cur_port) != USB_SUCCESS) {
				USB_DPRINTF_L4(PRINT_MASK_OPEN, acmp->acm_lh,
				    "usbsacm_reconnect_pipes: "
				    "open port %d failed.", i);

				return (USB_FAILURE);
			}
			mutex_enter(&cur_port->acm_port_mutex);
		}
		mutex_exit(&cur_port->acm_port_mutex);
	}

	return (USB_SUCCESS);
}

/*
 * usbsacm_bulkin_cb:
 *	Bulk In regular and exeception callback;
 *	USBA framework will call this callback
 *	after deal with bulkin request.
 */
/*ARGSUSED*/
static void
usbsacm_bulkin_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	usbsacm_port_t	*acm_port = (usbsacm_port_t *)req->bulk_client_private;
	usbsacm_state_t	*acmp = acm_port->acm_device;
	mblk_t		*data;
	int		data_len;

	data = req->bulk_data;
	data_len = (data) ? MBLKL(data) : 0;

	mutex_enter(&acm_port->acm_port_mutex);
	USB_DPRINTF_L4(PRINT_MASK_EVENTS, acmp->acm_lh,
	    "usbsacm_bulkin_cb: "
	    "acm_bulkin_state = %d acm_port_state = %d data_len = %d",
	    acm_port->acm_bulkin_state, acm_port->acm_port_state, data_len);

	if ((acm_port->acm_port_state == USBSACM_PORT_OPEN) && (data_len) &&
	    (req->bulk_completion_reason == USB_CR_OK)) {
		mutex_exit(&acm_port->acm_port_mutex);
		/* prevent USBA from freeing data along with the request */
		req->bulk_data = NULL;

		/* save data on the receive list */
		usbsacm_put_tail(&acm_port->acm_rx_mp, data);

		/* invoke GSD receive callback */
		if (acm_port->acm_cb.cb_rx) {
			acm_port->acm_cb.cb_rx(acm_port->acm_cb.cb_arg);
		}
		mutex_enter(&acm_port->acm_port_mutex);
	}
	mutex_exit(&acm_port->acm_port_mutex);

	usb_free_bulk_req(req);

	/* receive more */
	mutex_enter(&acm_port->acm_port_mutex);
	if (((acm_port->acm_bulkin_state == USBSACM_PIPE_BUSY) ||
	    (acm_port->acm_bulkin_state == USBSACM_PIPE_IDLE)) &&
	    (acm_port->acm_port_state == USBSACM_PORT_OPEN) &&
	    (acmp->acm_dev_state == USB_DEV_ONLINE)) {
		if (usbsacm_rx_start(acm_port) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
			    "usbsacm_bulkin_cb: restart rx fail "
			    "acm_port_state = %d", acm_port->acm_port_state);
		}
	} else if (acm_port->acm_bulkin_state == USBSACM_PIPE_BUSY) {
		acm_port->acm_bulkin_state = USBSACM_PIPE_IDLE;
	}
	mutex_exit(&acm_port->acm_port_mutex);
}


/*
 * usbsacm_bulkout_cb:
 *	Bulk Out regular and exeception callback;
 *	USBA framework will call this callback function
 *	after deal with bulkout request.
 */
/*ARGSUSED*/
static void
usbsacm_bulkout_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	usbsacm_port_t	*acm_port = (usbsacm_port_t *)req->bulk_client_private;
	usbsacm_state_t	*acmp = acm_port->acm_device;
	int		data_len;
	mblk_t		*data = req->bulk_data;

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, acmp->acm_lh,
	    "usbsacm_bulkout_cb: acmp = 0x%p", (void *)acmp);

	data_len = (req->bulk_data) ? MBLKL(req->bulk_data) : 0;

	/* put untransferred residue back on the transfer list */
	if (req->bulk_completion_reason && (data_len > 0)) {
		usbsacm_put_head(&acm_port->acm_tx_mp, data);
		req->bulk_data = NULL;
	}

	usb_free_bulk_req(req);

	/* invoke GSD transmit callback */
	if (acm_port->acm_cb.cb_tx) {
		acm_port->acm_cb.cb_tx(acm_port->acm_cb.cb_arg);
	}

	/* send more */
	mutex_enter(&acm_port->acm_port_mutex);
	acm_port->acm_bulkout_state = USBSACM_PIPE_IDLE;
	if (acm_port->acm_tx_mp == NULL) {
		cv_broadcast(&acm_port->acm_tx_cv);
	} else {
		usbsacm_tx_start(acm_port);
	}
	mutex_exit(&acm_port->acm_port_mutex);
}


/*
 * usbsacm_rx_start:
 *	start data receipt
 */
static int
usbsacm_rx_start(usbsacm_port_t *acm_port)
{
	usbsacm_state_t	*acmp = acm_port->acm_device;
	usb_bulk_req_t	*br;
	int		rval = USB_FAILURE;
	int		data_len;

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, acmp->acm_lh,
	    "usbsacm_rx_start: acm_xfer_sz = 0x%lx acm_bulkin_size = 0x%lx",
	    acmp->acm_xfer_sz, acm_port->acm_bulkin_size);

	acm_port->acm_bulkin_state = USBSACM_PIPE_BUSY;
	/*
	 * Qualcomm CDMA card won't response the first request,
	 * if the following code don't multiply by 2.
	 */
	data_len = min(acmp->acm_xfer_sz, acm_port->acm_bulkin_size * 2);
	mutex_exit(&acm_port->acm_port_mutex);

	br = usb_alloc_bulk_req(acmp->acm_dip, data_len, USB_FLAGS_SLEEP);
	if (br == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
		    "usbsacm_rx_start: allocate bulk request failed");

		mutex_enter(&acm_port->acm_port_mutex);

		return (USB_FAILURE);
	}
	/* initialize bulk in request. */
	br->bulk_len = data_len;
	br->bulk_timeout = USBSACM_BULKIN_TIMEOUT;
	br->bulk_cb = usbsacm_bulkin_cb;
	br->bulk_exc_cb = usbsacm_bulkin_cb;
	br->bulk_client_private = (usb_opaque_t)acm_port;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING
	    | USB_ATTRS_SHORT_XFER_OK;

	rval = usb_pipe_bulk_xfer(acm_port->acm_bulkin_ph, br, 0);

	mutex_enter(&acm_port->acm_port_mutex);
	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
		    "usbsacm_rx_start: bulk transfer failed %d", rval);
		usb_free_bulk_req(br);
		acm_port->acm_bulkin_state = USBSACM_PIPE_IDLE;
	}

	return (rval);
}


/*
 * usbsacm_tx_start:
 *	start data transmit
 */
static void
usbsacm_tx_start(usbsacm_port_t *acm_port)
{
	int		len;		/* bytes we can transmit */
	mblk_t		*data;		/* data to be transmitted */
	int		data_len;	/* bytes in 'data' */
	mblk_t		*mp;		/* current msgblk */
	int		copylen;	/* bytes copy from 'mp' to 'data' */
	int		rval;
	usbsacm_state_t	*acmp = acm_port->acm_device;

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_tx_start: ");

	/* check the transmitted data. */
	if (acm_port->acm_tx_mp == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
		    "usbsacm_tx_start: acm_tx_mp is NULL");

		return;
	}

	/* check pipe status */
	if (acm_port->acm_bulkout_state != USBSACM_PIPE_IDLE) {

		USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
		    "usbsacm_tx_start: error state in bulkout endpoint");

		return;
	}
	ASSERT(MBLKL(acm_port->acm_tx_mp) > 0);

	/* send as much data as port can receive */
	len = min(msgdsize(acm_port->acm_tx_mp), acmp->acm_xfer_sz);

	if (len == 0) {
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
		    "usbsacm_tx_start: data len is 0");

		return;
	}

	/* allocate memory for sending data. */
	if ((data = allocb(len, BPRI_LO)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
		    "usbsacm_tx_start: failure in allocate memory");

		return;
	}

	/*
	 * copy no more than 'len' bytes from mblk chain to transmit mblk 'data'
	 */
	data_len = 0;
	while ((data_len < len) && acm_port->acm_tx_mp) {
		/* Get the first mblk from chain. */
		mp = acm_port->acm_tx_mp;
		copylen = min(MBLKL(mp), len - data_len);
		bcopy(mp->b_rptr, data->b_wptr, copylen);
		mp->b_rptr += copylen;
		data->b_wptr += copylen;
		data_len += copylen;

		if (MBLKL(mp) < 1) {
			acm_port->acm_tx_mp = unlinkb(mp);
			freeb(mp);
		} else {
			ASSERT(data_len == len);
		}
	}

	if (data_len <= 0) {
		freeb(data);

		return;
	}

	acm_port->acm_bulkout_state = USBSACM_PIPE_BUSY;

	mutex_exit(&acm_port->acm_port_mutex);
	/* send request. */
	rval = usbsacm_send_data(acm_port, data);
	mutex_enter(&acm_port->acm_port_mutex);

	/*
	 * If send failed, retransmit data when acm_tx_mp is null.
	 */
	if (rval != USB_SUCCESS) {
		acm_port->acm_bulkout_state = USBSACM_PIPE_IDLE;
		if (acm_port->acm_tx_mp == NULL) {
			usbsacm_put_head(&acm_port->acm_tx_mp, data);
		}
	}
}


/*
 * usbsacm_send_data:
 *	data transfer
 */
static int
usbsacm_send_data(usbsacm_port_t *acm_port, mblk_t *data)
{
	usbsacm_state_t	*acmp = acm_port->acm_device;
	usb_bulk_req_t	*br;
	int		rval;
	int		data_len = MBLKL(data);

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, acmp->acm_lh,
	    "usbsacm_send_data: data address is 0x%p, length = %d",
	    (void *)data, data_len);

	br = usb_alloc_bulk_req(acmp->acm_dip, 0, USB_FLAGS_SLEEP);
	if (br == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_send_data: alloc req failed.");

		return (USB_FAILURE);
	}

	/* initialize the bulk out request */
	br->bulk_data = data;
	br->bulk_len = data_len;
	br->bulk_timeout = USBSACM_BULKOUT_TIMEOUT;
	br->bulk_cb = usbsacm_bulkout_cb;
	br->bulk_exc_cb = usbsacm_bulkout_cb;
	br->bulk_client_private = (usb_opaque_t)acm_port;
	br->bulk_attributes = USB_ATTRS_AUTOCLEARING;

	rval = usb_pipe_bulk_xfer(acm_port->acm_bulkout_ph, br, 0);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_EVENTS, acmp->acm_lh,
		    "usbsacm_send_data: Send Data failed.");

		/*
		 * Don't free it in usb_free_bulk_req because it will
		 * be linked in usbsacm_put_head
		 */
		br->bulk_data = NULL;

		usb_free_bulk_req(br);
	}

	return (rval);
}

/*
 * usbsacm_wait_tx_drain:
 *	wait until local tx buffer drains.
 *	'timeout' is in seconds, zero means wait forever
 */
static int
usbsacm_wait_tx_drain(usbsacm_port_t *acm_port, int timeout)
{
	clock_t		until;
	int		over = 0;

	until = ddi_get_lbolt() + drv_usectohz(1000 * 1000 * timeout);

	while (acm_port->acm_tx_mp && !over) {
		if (timeout > 0) {
			over = (cv_timedwait_sig(&acm_port->acm_tx_cv,
			    &acm_port->acm_port_mutex, until) <= 0);
		} else {
			over = (cv_wait_sig(&acm_port->acm_tx_cv,
			    &acm_port->acm_port_mutex) == 0);
		}
	}

	return ((acm_port->acm_tx_mp == NULL) ? USB_SUCCESS : USB_FAILURE);
}


/*
 * usbsacm_req_write:
 *	send command over control pipe
 */
static int
usbsacm_req_write(usbsacm_port_t *acm_port, uchar_t request, uint16_t value,
    mblk_t **data)
{
	usbsacm_state_t	*acmp = acm_port->acm_device;
	usb_ctrl_setup_t setup;
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_req_write: ");

	/* initialize the control request. */
	setup.bmRequestType = USBSACM_REQ_WRITE_IF;
	setup.bRequest = request;
	setup.wValue = value;
	setup.wIndex = acm_port->acm_ctrl_if_no;
	setup.wLength = ((data != NULL) && (*data != NULL)) ? MBLKL(*data) : 0;
	setup.attrs = 0;

	return (usb_pipe_ctrl_xfer_wait(acmp->acm_def_ph, &setup, data,
	    &cr, &cb_flags, 0));
}


/*
 * usbsacm_set_line_coding:
 *	Send USB_CDC_REQ_SET_LINE_CODING request
 */
static int
usbsacm_set_line_coding(usbsacm_port_t *acm_port, usb_cdc_line_coding_t *lc)
{
	mblk_t		*bp;
	int		ret;

	/* allocate mblk and copy supplied structure into it */
	if ((bp = allocb(USB_CDC_LINE_CODING_LEN, BPRI_HI)) == NULL) {

		return (USB_NO_RESOURCES);
	}

#ifndef __lock_lint /* warlock gets confused here */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	*((usb_cdc_line_coding_t *)bp->b_wptr) = *lc;
	bp->b_wptr += USB_CDC_LINE_CODING_LEN;
#endif

	ret = usbsacm_req_write(acm_port, USB_CDC_REQ_SET_LINE_CODING, 0, &bp);

	if (bp != NULL) {
		freeb(bp);
	}

	return (ret);
}



/*
 * usbsacm_mctl2reg:
 *	Set Modem control status
 */
static void
usbsacm_mctl2reg(int mask, int val, uint8_t *line_ctl)
{
	if (mask & TIOCM_RTS) {
		if (val & TIOCM_RTS) {
			*line_ctl |= USB_CDC_ACM_CONTROL_RTS;
		} else {
			*line_ctl &= ~USB_CDC_ACM_CONTROL_RTS;
		}
	}
	if (mask & TIOCM_DTR) {
		if (val & TIOCM_DTR) {
			*line_ctl |= USB_CDC_ACM_CONTROL_DTR;
		} else {
			*line_ctl &= ~USB_CDC_ACM_CONTROL_DTR;
		}
	}
}


/*
 * usbsacm_reg2mctl:
 *	Get Modem control status
 */
static int
usbsacm_reg2mctl(uint8_t line_ctl)
{
	int	val = 0;

	if (line_ctl & USB_CDC_ACM_CONTROL_RTS) {
		val |= TIOCM_RTS;
	}
	if (line_ctl & USB_CDC_ACM_CONTROL_DTR) {
		val |= TIOCM_DTR;
	}
	if (line_ctl & USB_CDC_ACM_CONTROL_DSR) {
		val |= TIOCM_DSR;
	}
	if (line_ctl & USB_CDC_ACM_CONTROL_RNG) {
		val |= TIOCM_RI;
	}

	return (val);
}


/*
 * misc routines
 * -------------
 *
 */

/*
 * usbsacm_put_tail:
 *	link a message block to tail of message
 *	account for the case when message is null
 */
static void
usbsacm_put_tail(mblk_t **mpp, mblk_t *bp)
{
	if (*mpp) {
		linkb(*mpp, bp);
	} else {
		*mpp = bp;
	}
}


/*
 * usbsacm_put_head:
 *	put a message block at the head of the message
 *	account for the case when message is null
 */
static void
usbsacm_put_head(mblk_t **mpp, mblk_t *bp)
{
	if (*mpp) {
		linkb(bp, *mpp);
	}
	*mpp = bp;
}


/*
 * power management
 * ----------------
 *
 * usbsacm_create_pm_components:
 *	create PM components
 */
static int
usbsacm_create_pm_components(usbsacm_state_t *acmp)
{
	dev_info_t	*dip = acmp->acm_dip;
	usbsacm_pm_t	*pm;
	uint_t		pwr_states;
	usb_dev_descr_t *dev_descr;

	USB_DPRINTF_L4(PRINT_MASK_PM, acmp->acm_lh,
	    "usbsacm_create_pm_components: ");

	if (usb_create_pm_components(dip, &pwr_states) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_PM, acmp->acm_lh,
		    "usbsacm_create_pm_components: failed");

		return (USB_SUCCESS);
	}

	pm = acmp->acm_pm =
	    (usbsacm_pm_t *)kmem_zalloc(sizeof (usbsacm_pm_t), KM_SLEEP);

	pm->pm_pwr_states = (uint8_t)pwr_states;
	pm->pm_cur_power = USB_DEV_OS_FULL_PWR;
	/*
	 * Qualcomm CDMA card won't response the following control commands
	 * after receive USB_REMOTE_WAKEUP_ENABLE. So we just set
	 * pm_wakeup_enable to 0 for this specific device.
	 */
	dev_descr = acmp->acm_dev_data->dev_descr;
	if (dev_descr->idVendor == 0x5c6 && dev_descr->idProduct == 0x3100) {
		pm->pm_wakeup_enabled = 0;
	} else {
		pm->pm_wakeup_enabled = (usb_handle_remote_wakeup(dip,
		    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS);
	}

	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	return (USB_SUCCESS);
}


/*
 * usbsacm_destroy_pm_components:
 *	destroy PM components
 */
static void
usbsacm_destroy_pm_components(usbsacm_state_t *acmp)
{
	usbsacm_pm_t	*pm = acmp->acm_pm;
	dev_info_t	*dip = acmp->acm_dip;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, acmp->acm_lh,
	    "usbsacm_destroy_pm_components: ");

	if (acmp->acm_dev_state != USB_DEV_DISCONNECTED) {
		if (pm->pm_wakeup_enabled) {
			rval = pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
			if (rval != DDI_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_PM, acmp->acm_lh,
				    "usbsacm_destroy_pm_components: "
				    "raising power failed (%d)", rval);
			}

			rval = usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE);
			if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_PM, acmp->acm_lh,
				    "usbsacm_destroy_pm_components: "
				    "disable remote wakeup failed (%d)", rval);
			}
		}

		(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);
	}
	kmem_free((caddr_t)pm, sizeof (usbsacm_pm_t));
	acmp->acm_pm = NULL;
}


/*
 * usbsacm_pm_set_busy:
 *	mark device busy and raise power
 */
static void
usbsacm_pm_set_busy(usbsacm_state_t *acmp)
{
	usbsacm_pm_t	*pm = acmp->acm_pm;
	dev_info_t	*dip = acmp->acm_dip;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, acmp->acm_lh,
	    "usbsacm_pm_set_busy: pm = 0x%p", (void *)pm);

	if (pm == NULL) {

		return;
	}

	mutex_enter(&acmp->acm_mutex);
	/* if already marked busy, just increment the counter */
	if (pm->pm_busy_cnt++ > 0) {
		mutex_exit(&acmp->acm_mutex);

		return;
	}

	(void) pm_busy_component(dip, 0);

	if (pm->pm_cur_power == USB_DEV_OS_FULL_PWR) {
		mutex_exit(&acmp->acm_mutex);

		return;
	}

	/* need to raise power	*/
	pm->pm_raise_power = B_TRUE;
	mutex_exit(&acmp->acm_mutex);

	rval = pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	if (rval != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_PM, acmp->acm_lh,
		    "usbsacm_pm_set_busy: raising power failed");
	}

	mutex_enter(&acmp->acm_mutex);
	pm->pm_raise_power = B_FALSE;
	mutex_exit(&acmp->acm_mutex);
}


/*
 * usbsacm_pm_set_idle:
 *	mark device idle
 */
static void
usbsacm_pm_set_idle(usbsacm_state_t *acmp)
{
	usbsacm_pm_t	*pm = acmp->acm_pm;
	dev_info_t	*dip = acmp->acm_dip;

	USB_DPRINTF_L4(PRINT_MASK_PM, acmp->acm_lh,
	    "usbsacm_pm_set_idle: ");

	if (pm == NULL) {

		return;
	}

	/*
	 * if more ports use the device, do not mark as yet
	 */
	mutex_enter(&acmp->acm_mutex);
	if (--pm->pm_busy_cnt > 0) {
		mutex_exit(&acmp->acm_mutex);

		return;
	}

	if (pm) {
		(void) pm_idle_component(dip, 0);
	}
	mutex_exit(&acmp->acm_mutex);
}


/*
 * usbsacm_pwrlvl0:
 *	Functions to handle power transition for OS levels 0 -> 3
 *	The same level as OS state, different from USB state
 */
static int
usbsacm_pwrlvl0(usbsacm_state_t *acmp)
{
	int		rval;
	int		i;
	usbsacm_port_t	*cur_port = acmp->acm_ports;

	USB_DPRINTF_L4(PRINT_MASK_PM, acmp->acm_lh,
	    "usbsacm_pwrlvl0: ");

	switch (acmp->acm_dev_state) {
	case USB_DEV_ONLINE:
		/* issue USB D3 command to the device */
		rval = usb_set_device_pwrlvl3(acmp->acm_dip);
		ASSERT(rval == USB_SUCCESS);

		if (cur_port != NULL) {
			for (i = 0; i < acmp->acm_port_cnt; i++) {
				cur_port = &acmp->acm_ports[i];
				if (cur_port->acm_intr_ph != NULL &&
				    cur_port->acm_port_state !=
				    USBSACM_PORT_CLOSED) {

					mutex_exit(&acmp->acm_mutex);
					usb_pipe_stop_intr_polling(
					    cur_port->acm_intr_ph,
					    USB_FLAGS_SLEEP);
					mutex_enter(&acmp->acm_mutex);

					mutex_enter(&cur_port->acm_port_mutex);
					cur_port->acm_intr_state =
					    USBSACM_PIPE_IDLE;
					mutex_exit(&cur_port->acm_port_mutex);
				}
			}
		}

		acmp->acm_dev_state = USB_DEV_PWRED_DOWN;
		acmp->acm_pm->pm_cur_power = USB_DEV_OS_PWR_OFF;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnect/cpr'ed device to go to lower power */

		return (USB_SUCCESS);
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, acmp->acm_lh,
		    "usbsacm_pwrlvl0: illegal device state");

		return (USB_FAILURE);
	}
}


/*
 * usbsacm_pwrlvl1:
 *	Functions to handle power transition for OS levels 1 -> 2
 */
static int
usbsacm_pwrlvl1(usbsacm_state_t *acmp)
{
	/* issue USB D2 command to the device */
	(void) usb_set_device_pwrlvl2(acmp->acm_dip);

	return (USB_FAILURE);
}


/*
 * usbsacm_pwrlvl2:
 *	Functions to handle power transition for OS levels 2 -> 1
 */
static int
usbsacm_pwrlvl2(usbsacm_state_t *acmp)
{
	/* issue USB D1 command to the device */
	(void) usb_set_device_pwrlvl1(acmp->acm_dip);

	return (USB_FAILURE);
}


/*
 * usbsacm_pwrlvl3:
 *	Functions to handle power transition for OS levels 3 -> 0
 *	The same level as OS state, different from USB state
 */
static int
usbsacm_pwrlvl3(usbsacm_state_t *acmp)
{
	int		rval;
	int		i;
	usbsacm_port_t	*cur_port = acmp->acm_ports;

	USB_DPRINTF_L4(PRINT_MASK_PM, acmp->acm_lh,
	    "usbsacm_pwrlvl3: ");

	switch (acmp->acm_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(acmp->acm_dip);
		ASSERT(rval == USB_SUCCESS);

		if (cur_port != NULL) {
			for (i = 0; i < acmp->acm_port_cnt; i++) {
				cur_port = &acmp->acm_ports[i];
				if (cur_port->acm_intr_ph != NULL &&
				    cur_port->acm_port_state !=
				    USBSACM_PORT_CLOSED) {

					mutex_exit(&acmp->acm_mutex);
					usbsacm_pipe_start_polling(cur_port);
					mutex_enter(&acmp->acm_mutex);
				}
			}
		}

		acmp->acm_dev_state = USB_DEV_ONLINE;
		acmp->acm_pm->pm_cur_power = USB_DEV_OS_FULL_PWR;

		/* FALLTHRU */
	case USB_DEV_ONLINE:
		/* we are already in full power */

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, acmp->acm_lh,
		    "usbsacm_pwrlvl3: illegal device state");

		return (USB_FAILURE);
	}
}


/*
 * usbsacm_pipe_start_polling:
 *	start polling on the interrupt pipe
 */
static void
usbsacm_pipe_start_polling(usbsacm_port_t *acm_port)
{
	usb_intr_req_t	*intr;
	int		rval;
	usbsacm_state_t	*acmp = acm_port->acm_device;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, acmp->acm_lh,
	    "usbsacm_pipe_start_polling: ");

	if (acm_port->acm_intr_ph == NULL) {

		return;
	}

	intr = usb_alloc_intr_req(acmp->acm_dip, 0, USB_FLAGS_SLEEP);

	/*
	 * If it is in interrupt context, usb_alloc_intr_req will return NULL if
	 * called with SLEEP flag.
	 */
	if (!intr) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_pipe_start_polling: alloc req failed.");

		return;
	}

	/* initialize the interrupt request. */
	intr->intr_attributes = USB_ATTRS_SHORT_XFER_OK |
	    USB_ATTRS_AUTOCLEARING;
	mutex_enter(&acm_port->acm_port_mutex);
	intr->intr_len = acm_port->acm_intr_ep_descr.wMaxPacketSize;
	mutex_exit(&acm_port->acm_port_mutex);
	intr->intr_client_private = (usb_opaque_t)acm_port;
	intr->intr_cb = usbsacm_intr_cb;
	intr->intr_exc_cb = usbsacm_intr_ex_cb;

	rval = usb_pipe_intr_xfer(acm_port->acm_intr_ph, intr, USB_FLAGS_SLEEP);

	mutex_enter(&acm_port->acm_port_mutex);
	if (rval == USB_SUCCESS) {
		acm_port->acm_intr_state = USBSACM_PIPE_BUSY;
	} else {
		usb_free_intr_req(intr);
		acm_port->acm_intr_state = USBSACM_PIPE_IDLE;
		USB_DPRINTF_L3(PRINT_MASK_OPEN, acmp->acm_lh,
		    "usbsacm_pipe_start_polling: failed (%d)", rval);
	}
	mutex_exit(&acm_port->acm_port_mutex);
}


/*
 * usbsacm_intr_cb:
 *	interrupt pipe normal callback
 */
/*ARGSUSED*/
static void
usbsacm_intr_cb(usb_pipe_handle_t ph, usb_intr_req_t *req)
{
	usbsacm_port_t	*acm_port = (usbsacm_port_t *)req->intr_client_private;
	usbsacm_state_t	*acmp = acm_port->acm_device;
	mblk_t		*data = req->intr_data;
	int		data_len;

	USB_DPRINTF_L4(PRINT_MASK_CB, acmp->acm_lh,
	    "usbsacm_intr_cb: ");

	data_len = (data) ? MBLKL(data) : 0;

	/* check data length */
	if (data_len < 8) {
		USB_DPRINTF_L2(PRINT_MASK_CB, acmp->acm_lh,
		    "usbsacm_intr_cb: %d packet too short", data_len);
		usb_free_intr_req(req);

		return;
	}
	req->intr_data = NULL;
	usb_free_intr_req(req);

	mutex_enter(&acm_port->acm_port_mutex);
	/* parse interrupt data. */
	usbsacm_parse_intr_data(acm_port, data);
	mutex_exit(&acm_port->acm_port_mutex);
}


/*
 * usbsacm_intr_ex_cb:
 *	interrupt pipe exception callback
 */
/*ARGSUSED*/
static void
usbsacm_intr_ex_cb(usb_pipe_handle_t ph, usb_intr_req_t *req)
{
	usbsacm_port_t	*acm_port = (usbsacm_port_t *)req->intr_client_private;
	usbsacm_state_t	*acmp = acm_port->acm_device;
	usb_cr_t	cr = req->intr_completion_reason;

	USB_DPRINTF_L4(PRINT_MASK_CB, acmp->acm_lh,
	    "usbsacm_intr_ex_cb: ");

	usb_free_intr_req(req);

	/*
	 * If completion reason isn't USB_CR_PIPE_CLOSING and
	 * USB_CR_STOPPED_POLLING, restart polling.
	 */
	if ((cr != USB_CR_PIPE_CLOSING) && (cr != USB_CR_STOPPED_POLLING)) {
		mutex_enter(&acmp->acm_mutex);

		if (acmp->acm_dev_state != USB_DEV_ONLINE) {

			USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
			    "usbsacm_intr_ex_cb: state = %d",
			    acmp->acm_dev_state);

			mutex_exit(&acmp->acm_mutex);

			return;
		}
		mutex_exit(&acmp->acm_mutex);

		usbsacm_pipe_start_polling(acm_port);
	}
}


/*
 * usbsacm_parse_intr_data:
 *	Parse data received from interrupt callback
 */
static void
usbsacm_parse_intr_data(usbsacm_port_t *acm_port, mblk_t *data)
{
	usbsacm_state_t	*acmp = acm_port->acm_device;
	uint8_t		bmRequestType;
	uint8_t		bNotification;
	uint16_t	wValue;
	uint16_t	wLength;
	uint16_t	wData;

	USB_DPRINTF_L4(PRINT_MASK_ALL, acmp->acm_lh,
	    "usbsacm_parse_intr_data: ");

	bmRequestType = data->b_rptr[0];
	bNotification = data->b_rptr[1];
	/*
	 * If Notification type is NETWORK_CONNECTION, wValue is 0 or 1,
	 * mLength is 0. If Notification type is SERIAL_TYPE, mValue is 0,
	 * mLength is 2. So we directly get the value from the byte.
	 */
	wValue = data->b_rptr[2];
	wLength = data->b_rptr[6];

	if (bmRequestType != USB_CDC_NOTIFICATION_REQUEST_TYPE) {
		USB_DPRINTF_L2(PRINT_MASK_CB, acmp->acm_lh,
		    "usbsacm_parse_intr_data: unknown request type - 0x%x",
		    bmRequestType);

		freemsg(data);

		return;
	}

	/*
	 * Check the return value of device
	 */
	switch (bNotification) {
	case USB_CDC_NOTIFICATION_NETWORK_CONNECTION:
		USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
		    "usbsacm_parse_intr_data: %s network!",
		    wValue ? "connected to" :"disconnected from");

		break;
	case USB_CDC_NOTIFICATION_RESPONSE_AVAILABLE:
		USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
		    "usbsacm_parse_intr_data: A response is a available.");

		break;
	case USB_CDC_NOTIFICATION_SERIAL_STATE:
		/* check the parameter's length. */
		if (wLength != 2) {

			USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
			    "usbsacm_parse_intr_data: error data length.");
		} else {
			/*
			 * The Data field is a bitmapped value that contains
			 * the current state of carrier detect, transmission
			 * carrier, break, ring signal and device overrun
			 * error.
			 */
			wData = data->b_rptr[8];
			/*
			 * Check the serial state of the current port.
			 */
			if (wData & USB_CDC_ACM_CONTROL_DCD) {

				USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
				    "usbsacm_parse_intr_data: "
				    "receiver carrier is set.");
			}
			if (wData & USB_CDC_ACM_CONTROL_DSR) {

				USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
				    "usbsacm_parse_intr_data: "
				    "transmission carrier is set.");

				acm_port->acm_mctlin |= USB_CDC_ACM_CONTROL_DSR;
			}
			if (wData & USB_CDC_ACM_CONTROL_BREAK) {

				USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
				    "usbsacm_parse_intr_data: "
				    "break detection mechanism is set.");
			}
			if (wData & USB_CDC_ACM_CONTROL_RNG) {

				USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
				    "usbsacm_parse_intr_data: "
				    "ring signal detection is set.");

				acm_port->acm_mctlin |= USB_CDC_ACM_CONTROL_RNG;
			}
			if (wData & USB_CDC_ACM_CONTROL_FRAMING) {

				USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
				    "usbsacm_parse_intr_data: "
				    "A framing error has occurred.");
			}
			if (wData & USB_CDC_ACM_CONTROL_PARITY) {

				USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
				    "usbsacm_parse_intr_data: "
				    "A parity error has occurred.");
			}
			if (wData & USB_CDC_ACM_CONTROL_OVERRUN) {

				USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
				    "usbsacm_parse_intr_data: "
				    "Received data has been discarded "
				    "due to overrun.");
			}
		}

		break;
	default:
		USB_DPRINTF_L3(PRINT_MASK_CB, acmp->acm_lh,
		    "usbsacm_parse_intr_data: unknown notification - 0x%x!",
		    bNotification);

		break;
	}

	freemsg(data);
}
