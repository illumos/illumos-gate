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
 * This driver includes code for Keyspan USA49WG/USA49WLC/USA19HS adapters. It
 * is a device-specific driver (DSD) working with USB generic serial driver
 * (GSD). It implements the USB-to-serial device-specific driver interface
 * (DSDI) which is offered by GSD. The interface is defined by ds_ops_t
 * structure.
 *
 * For USA49WLC, it's necessary to download firmware every time the device is
 * plugged. Before the firmware is downloaded, we say that the device is in
 * "firmware mode", and the attach routin is keyspan_pre_attach(). After
 * downloading, the device's product id will change to 0x12a. Then the device
 * will be enumerated again and another attach for the new product id will
 * begin. No firmware is included in the driver. The functions of USA49WLC is
 * disabled.
 *
 * For USA49WG and USA19HS, no need to download firmware since it can be kept
 * in the device's memory.
 *
 * For USA49WLC and USA19HS, it's necessary to check and switch their
 * configrations at the beginning of attach, since each of them has two
 * configrations. This driver uses the one whose endpoints are all bulk.
 *
 * For USA49WG, this driver uses the third configuration which has 6 endpoints,
 * 3 bulk out eps, 1 bulk in ep, 1 intr in ep, 1 intr out ep. Bulk in ep is
 * shared by 4 ports for receiving data.
 *
 * Some of Keyspan adapters have only one port, some have two or four ports.
 * This driver supports up to four ports. Each port has its own states (traced
 * by keyspan_port structure) and can be operated independently.
 *
 * port_state:
 *
 *   KEYSPAN_PORT_NOT_INIT
 *	    |
 *	    |
 *     attach_ports
 *	    |
 *	    |
 *	    |
 *	    v
 *   KEYSPAN_PORT_CLOSED <-----close-------<---- +
 *	|					 |
 *	|					 |
 *	|					 |
 *  open_port					 |
 *	|					 |
 *	|					 |
 *	v					 |
 * KEYSPAN_PORT_OPENING ---open_hw_port---> USBSER_PORT_OPEN
 *
 * Each port has its own data in/out pipes and each pipe also has its own states
 * (traced by keyspan_pipe structure). The pipe states is as following:
 *
 * pipe_state:
 *
 *	  KEYSPAN_PIPE_NOT_INIT
 *		|	^
 *		|	|
 * keyspan_init_pipes  keyspan_fini_pipes
 *		|	|
 *		v	|
 *	   KEYSPAN_PIPE_CLOSED ------------->-----------+
 *		  ^					|
 *		  |			  reconnect/resume/open_port
 *		  |					|
 *    disconnect/suspend/close_port			|
 *		  |					v
 *		  +---------<------------------ KEYSPAN_PIPE_OPEN
 *
 * To control the device and get its status in a timely way, this driver makes
 * use of two global bulk endpoints for cmd and status on the device. The pipes
 * for cmd/status will be opened during attach. For multi-port devices, one of
 * the cmd/status message fields will designate which port this message is for.
 *
 * This driver can be easily extended to support more Keyspan adapter models.
 * You need the following steps to reach the aim:
 * 1. Add the model specific data structures, like cmd/status message structure.
 * 2. If the device need firmware downloaded, add the firmware code as a header
 * file, and add code to keyspan_pre_attach() as what were done for USA49WLC.
 * 3. Add several model specific functions, like keyspan_build_cmd_msg_*,
 * keyspan_default_port_params_*, keyspan_save_port_params_*, etc. The functions
 * for USA19HS and USA49WLC can be taken as examples.
 * 4. Add model specific code to the "switch (id_product) {...}" sentences.
 */

/*
 *
 * keyspan driver glue code
 *
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#include <sys/usb/usba.h>

#include <sys/usb/clients/usbser/usbser.h>
#include <sys/usb/clients/usbser/usbser_keyspan/keyspan_var.h>

#include <sys/byteorder.h>
#include <sys/strsun.h>

/* configuration entry points */
static int	usbser_keyspan_getinfo(dev_info_t *, ddi_info_cmd_t, void *,
		void **);
static int	usbser_keyspan_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usbser_keyspan_detach(dev_info_t *, ddi_detach_cmd_t);
static int	usbser_keyspan_open(queue_t *, dev_t *, int, int, cred_t *);

/* functions related with set config or firmware download */
static int	keyspan_pre_attach(dev_info_t *, ddi_attach_cmd_t, void *);
static int	keyspan_set_cfg(dev_info_t *, uint8_t);
static int	keyspan_pre_detach(dev_info_t *, ddi_detach_cmd_t, void *);
static boolean_t keyspan_need_fw(usb_client_dev_data_t *);
static int	keyspan_set_reg(keyspan_pipe_t *, uchar_t);
static int	keyspan_write_memory(keyspan_pipe_t *, uint16_t, uchar_t *,
		uint16_t, uint8_t);
static int	keyspan_download_firmware(keyspan_pre_state_t *);

static void    *usbser_keyspan_statep;	/* soft state */

extern ds_ops_t ds_ops;		/* DSD operations */

/*
 * STREAMS structures
 */
struct module_info usbser_keyspan_modinfo = {
	0,			/* module id */
	"usbsksp",		/* module name */
	USBSER_MIN_PKTSZ,	/* min pkt size */
	USBSER_MAX_PKTSZ,	/* max pkt size */
	USBSER_HIWAT,		/* hi watermark */
	USBSER_LOWAT		/* low watermark */
};

static struct qinit usbser_keyspan_rinit = {
	putq,
	usbser_rsrv,
	usbser_keyspan_open,
	usbser_close,
	NULL,
	&usbser_keyspan_modinfo,
	NULL
};

static struct qinit usbser_keyspan_winit = {
	usbser_wput,
	usbser_wsrv,
	NULL,
	NULL,
	NULL,
	&usbser_keyspan_modinfo,
	NULL
};

struct streamtab usbser_keyspan_str_info = {
	&usbser_keyspan_rinit, &usbser_keyspan_winit, NULL, NULL
};

static struct cb_ops usbser_keyspan_cb_ops = {
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
	&usbser_keyspan_str_info,	/* cb_stream */
	(int)(D_64BIT | D_NEW | D_MP | D_HOTPLUG)	/* cb_flag */
};

/*
 * auto configuration ops
 */
struct dev_ops usbser_keyspan_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	usbser_keyspan_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	usbser_keyspan_attach,	/* devo_attach */
	usbser_keyspan_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&usbser_keyspan_cb_ops,	/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	usbser_power,		/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* type of module - driver */
	"USB keyspan usb2serial driver",
	&usbser_keyspan_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, 0
};

/* debug support */
static uint_t	keyspan_pre_errlevel = USB_LOG_L4;
static uint_t	keyspan_pre_errmask = DPRINT_MASK_ALL;
static uint_t	keyspan_pre_instance_debug = (uint_t)-1;

/* firmware support for usa49wlc model */
extern usbser_keyspan_fw_record_t *keyspan_usa49wlc_fw(void);
#pragma weak keyspan_usa49wlc_fw

/*
 * configuration entry points
 * --------------------------
 */
int
_init(void)
{
	int    error;

	if ((error = mod_install(&modlinkage)) == 0) {
		error = ddi_soft_state_init(&usbser_keyspan_statep,
		    max(usbser_soft_state_size(),
		    sizeof (keyspan_pre_state_t)), 1);
	}

	return (error);
}


int
_fini(void)
{
	int    error;

	if ((error = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&usbser_keyspan_statep);
	}

	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*ARGSUSED*/
int
usbser_keyspan_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result)
{
	return (usbser_getinfo(dip, infocmd, arg, result,
	    usbser_keyspan_statep));
}


static int
usbser_keyspan_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	rval;

	/*
	 * Once the device is plugged, we need set its cfg. And need download
	 * firmware for some of them.
	 */
	rval = keyspan_pre_attach(dip, cmd, usbser_keyspan_statep);

	/*
	 * After the cfg is set, and the firmware is downloaded,
	 * do the real attach.
	 */
	if (rval == DDI_ECONTEXT) {

		return (usbser_attach(dip, cmd, usbser_keyspan_statep,
		    &ds_ops));
	} else {

		return (rval);
	}
}


static int
usbser_keyspan_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{

	if (ddi_get_driver_private(dip) == NULL) {

		return (keyspan_pre_detach(dip, cmd, usbser_keyspan_statep));
	} else {


		return (usbser_detach(dip, cmd, usbser_keyspan_statep));


	}

}


static int
usbser_keyspan_open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	return (usbser_open(rq, dev, flag, sflag, cr, usbser_keyspan_statep));
}

/*
 * Switch config or download firmware
 */
/*ARGSUSED*/
static int
keyspan_pre_attach(dev_info_t *dip, ddi_attach_cmd_t cmd, void *statep)
{

	int			instance = ddi_get_instance(dip);
	keyspan_pre_state_t	*kbp = NULL;
	usb_client_dev_data_t	*dev_data = NULL;
	int			rval = DDI_FAILURE;

	switch (cmd) {
	case DDI_ATTACH:

		break;
	case DDI_RESUME:

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}

	/* attach driver to USBA */
	if (usb_client_attach(dip, USBDRV_VERSION, 0) == USB_SUCCESS) {
		(void) usb_get_dev_data(dip, &dev_data, USB_PARSE_LVL_IF, 0);
	}
	if (dev_data == NULL) {

		goto fail;
	}

	/*
	 * If 19HS or 49WG, needn't download firmware, but need check the
	 * current cfg.
	 * If 49WLC, need check the current cfg before download fw. And after
	 * download, the product id will change to KEYSPAN_USA49WLC_PID.
	 */
	if (dev_data->dev_descr->idProduct == KEYSPAN_USA19HS_PID ||
	    dev_data->dev_descr->idProduct == KEYSPAN_USA49WLC_PID) {
		if (keyspan_set_cfg(dip, 1) == USB_SUCCESS) {
			/* Go to keyspan_attach() by return DDI_ECONTEXT. */
			rval =	DDI_ECONTEXT;
		}

		goto fail;
	} else if (dev_data->dev_descr->idProduct == KEYSPAN_USA49WG_PID) {
		if (keyspan_set_cfg(dip, 2) == USB_SUCCESS) {
			/* Go to keyspan_attach() by return DDI_ECONTEXT. */
			rval =	DDI_ECONTEXT;
		}

		goto fail;
	}


	/*
	 * By checking KEYSPAN_FW_FLAG,  we can check whether the firmware
	 * has been downloaded.
	 * If firmware is already there, then do normal attach.
	 */
	if (!keyspan_need_fw(dev_data)) {
		/* Go to keyspan_attach() by return DDI_ECONTEXT. */
		rval =	DDI_ECONTEXT;

		goto fail;
	}

	/* Go on to download firmware. */

	if (ddi_soft_state_zalloc(statep, instance) == DDI_SUCCESS) {
		kbp = ddi_get_soft_state(statep, instance);
	}
	if (kbp) {
		kbp->kb_dip = dip;
		kbp->kb_instance = instance;
		kbp->kb_dev_data = dev_data;
		kbp->kb_def_pipe.pipe_handle = kbp->kb_dev_data->dev_default_ph;
		kbp->kb_lh = usb_alloc_log_hdl(kbp->kb_dip, "keyspan[*].",
		    &keyspan_pre_errlevel, &keyspan_pre_errmask,
		    &keyspan_pre_instance_debug, 0);

		kbp->kb_def_pipe.pipe_lh = kbp->kb_lh;

		if (keyspan_download_firmware(kbp) == USB_SUCCESS) {
			USB_DPRINTF_L4(DPRINT_ATTACH, kbp->kb_lh,
			    "keyspan_pre_attach: completed.");

			/* keyspan download firmware done. */

			return (DDI_SUCCESS);
		}
	}
fail:
	if (kbp) {
		usb_free_log_hdl(kbp->kb_lh);
		ddi_soft_state_free(statep, instance);
	}
	usb_client_detach(dip, dev_data);

	return (rval);
}


static int
keyspan_pre_detach(dev_info_t *dip, ddi_detach_cmd_t cmd, void *statep)
{
	int		instance = ddi_get_instance(dip);
	keyspan_pre_state_t	*kbp;

	kbp = ddi_get_soft_state(statep, instance);

	switch (cmd) {
	case DDI_DETACH:

		break;
	case DDI_SUSPEND:

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}

	usb_free_log_hdl(kbp->kb_lh);
	usb_client_detach(dip, kbp->kb_dev_data);
	ddi_soft_state_free(statep, instance);

	return (DDI_SUCCESS);
}


/* Set cfg for the device which has more than one cfg */
static int
keyspan_set_cfg(dev_info_t *dip, uint8_t cfg_num)
{

	if (usb_set_cfg(dip, cfg_num, USB_FLAGS_SLEEP,
	    NULL, NULL) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/* Return TRUE if need download firmware to the device. */
static boolean_t
keyspan_need_fw(usb_client_dev_data_t *dev_data)
{
	uint16_t	bcd_descr;
	uint16_t	bcd_descr_change;

	/* need to convert to Little-Endian */
	bcd_descr = dev_data->dev_descr->bcdDevice;

	/*
	 * According to Keyspan's interface spec, this flag indicates
	 * if need download fw.
	 */
	bcd_descr_change = bcd_descr & KEYSPAN_FW_FLAG;

	return (bcd_descr_change == KEYSPAN_FW_FLAG);
}

/* Set the device's register. */
static int
keyspan_set_reg(keyspan_pipe_t *pipe, uchar_t bit)
{
	int	rval;

	/*
	 * (0x7f92) is the reg addr we want to set.
	 * We set this reg before/after downloading firmware.
	 */
	rval = keyspan_write_memory(pipe, 0x7f92, &bit, 1, KEYSPAN_REQ_SET);

	return (rval);
}

/*
 * Download firmware or set register to the device by default ctrl pipe
 */
static int
keyspan_write_memory(keyspan_pipe_t *pipe, uint16_t addr, uchar_t *buf,
    uint16_t len, uint8_t bRequest)
{
	mblk_t *data;
	usb_ctrl_setup_t setup;

	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	uint8_t		retry = 0;

	/* reuse previous mblk if possible */
	if ((data = allocb(len, BPRI_HI)) == NULL) {

		return (USB_FAILURE);
	}

	bcopy(buf, data->b_rptr, len);

	setup.bmRequestType = USB_DEV_REQ_TYPE_VENDOR;

	/* This is a req defined by hardware vendor. */
	setup.bRequest = bRequest;
	setup.wValue = addr;
	setup.wIndex = 0;
	setup.wLength = len;
	setup.attrs = 0;

	while (usb_pipe_ctrl_xfer_wait(pipe->pipe_handle, &setup, &data,
	    &cr, &cb_flags, 0) != USB_SUCCESS) {

		/* KEYSPAN_RETRY */
		if (++retry > 3) {
			if (data) {
				freemsg(data);
			}

			return (USB_FAILURE);
		}
	}

	if (data) {
		freemsg(data);
	}

	return (USB_SUCCESS);
}

/* Download firmware into device */
static int
keyspan_download_firmware(keyspan_pre_state_t *kbp)
{
	usbser_keyspan_fw_record_t *record = NULL;

	/* If the firmware module exists, then download it to device. */
	if (&keyspan_usa49wlc_fw) {

		record = keyspan_usa49wlc_fw();
	}

	if (!record) {
		USB_DPRINTF_L1(DPRINT_ATTACH, kbp->kb_lh,
		    "No firmware available for Keyspan usa49wlc"
		    " usb-to-serial adapter. Refer to usbsksp(7D)"
		    " for details.");

		return (USB_FAILURE);
	}

	/* Set bit 1 before downloading firmware. */
	if (keyspan_set_reg(&kbp->kb_def_pipe, 1) != USB_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_ATTACH, kbp->kb_lh,
		    "keyspan_pre_attach: Set register failed.");

		return (USB_FAILURE);
	}

	/* Write until the last record of the firmware */
	while (record->address != 0xffff) {
		if (keyspan_write_memory(&kbp->kb_def_pipe,
		    record->address, (uchar_t *)record->data,
		    record->data_len, KEYSPAN_REQ_SET) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_ATTACH, kbp->kb_lh,
			    "keyspan_pre_attach: download firmware failed.");

			return (USB_FAILURE);
		}
		record++;
	}

	/*
	 * Set bit 0, device will be enumerated again after a while,
	 * and then go to keyspan_attach()
	 */
	if (keyspan_set_reg(&kbp->kb_def_pipe, 0) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}
