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
 * This driver supports FTDI FT232R USB-to-serial adapters. It is a
 * device-specific driver (DSD) working with the USB generic serial
 * driver (GSD) usbser.
 *
 * It implements the USB-to-serial device-specific driver interface (DSDI)
 * which is exported by GSD. The DSDI is defined by ds_ops_t structure.
 *
 * Also may work with the older FTDI 8U232AM devices.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/usb/clients/usbser/usbser.h>
#include <sys/usb/clients/usbser/usbftdi/uftdi_var.h>

static void *usbser_uftdi_statep;	/* soft state handle for usbser */

extern ds_ops_t uftdi_ds_ops;	/* DSD operations */

static int
usbser_uftdi_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	return (usbser_getinfo(dip, infocmd, arg, result, usbser_uftdi_statep));
}


static int
usbser_uftdi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	return (usbser_attach(dip, cmd, usbser_uftdi_statep, &uftdi_ds_ops));
}


static int
usbser_uftdi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (usbser_detach(dip, cmd, usbser_uftdi_statep));
}


static int
usbser_uftdi_open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	return (usbser_open(rq, dev, flag, sflag, cr, usbser_uftdi_statep));
}

/*
 * Several linked data structures to tie it together ..
 */
struct module_info uftdi_modinfo = {
	0,			/* module id */
	"uftdi",		/* module name */
	USBSER_MIN_PKTSZ,	/* min pkt size */
	USBSER_MAX_PKTSZ,	/* max pkt size */
	USBSER_HIWAT,		/* hi watermark */
	USBSER_LOWAT		/* low watermark */
};

static struct qinit uftdi_rinit = {
	putq,
	usbser_rsrv,
	usbser_uftdi_open,
	usbser_close,
	NULL,
	&uftdi_modinfo,
};

static struct qinit uftdi_winit = {
	usbser_wput,
	usbser_wsrv,
	NULL,
	NULL,
	NULL,
	&uftdi_modinfo,
};

static struct streamtab uftdi_str_info = {
	&uftdi_rinit,
	&uftdi_winit,
};

static struct cb_ops uftdi_cb_ops = {
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
	&uftdi_str_info,	/* cb_stream */
	(int)(D_64BIT | D_NEW | D_MP | D_HOTPLUG)	/* cb_flag */
};

static struct dev_ops uftdi_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	usbser_uftdi_getinfo,
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	usbser_uftdi_attach,
	usbser_uftdi_detach,
	nodev,			/* devo_reset */
	&uftdi_cb_ops,
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	usbser_power,		/* devo_power */
	ddi_quiesce_not_needed
};

static struct modldrv modldrv = {
	&mod_driverops,
	"FTDI FT232R USB UART driver",
	&uftdi_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv
};

int
_init(void)
{
	int error;

	if ((error = mod_install(&modlinkage)) != 0)
		return (error);
	if ((error = ddi_soft_state_init(&usbser_uftdi_statep,
	    usbser_soft_state_size(), 1)) != 0)
		(void) mod_remove(&modlinkage);
	return (error);
}


int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&usbser_uftdi_statep);
	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
