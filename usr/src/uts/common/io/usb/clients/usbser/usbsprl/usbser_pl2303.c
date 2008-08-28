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
 * This driver supports Prolific PL-2303H/HX/X USB-to-serial adapters. It is a
 * device-specific driver (DSD) working with USB generic serial driver (GSD). It
 * implements the USB-to-serial device-specific driver interface (DSDI) which is
 * offered by GSD. The interface is defined by ds_ops_t structure.
 *
 *
 * PL-2303HX and PL-2303X devices have different hardware, but from the
 * perspective of device driver, they have the same software interface.
 */

/*
 *
 * USB Prolific PL2303 driver glue code
 *
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/usb/clients/usbser/usbser.h>
#include <sys/usb/clients/usbser/usbsprl/pl2303_var.h>


/* configuration entry points */
static int	usbser_pl2303_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usbser_pl2303_detach(dev_info_t *, ddi_detach_cmd_t);
static int 	usbser_pl2303_getinfo(dev_info_t *, ddi_info_cmd_t, void *,
		void **);
static int	usbser_pl2303_open(queue_t *, dev_t *, int, int, cred_t *);
static void	*usbser_pl2303_statep;	/* soft state */

extern		ds_ops_t ds_ops;	/* DSD operations */


/*
 * STREAMS structures
 */
struct module_info usbser_pl2303_modinfo = {
	0,			/* module id */
	"usbsprl",		/* module name */
	USBSER_MIN_PKTSZ,	/* min pkt size */
	USBSER_MAX_PKTSZ,	/* max pkt size */
	USBSER_HIWAT,		/* hi watermark */
	USBSER_LOWAT		/* low watermark */
};


static struct qinit usbser_pl2303_rinit = {
	putq,
	usbser_rsrv,
	usbser_pl2303_open,
	usbser_close,
	NULL,
	&usbser_pl2303_modinfo,
	NULL
};


static struct qinit usbser_pl2303_winit = {
	usbser_wput,
	usbser_wsrv,
	NULL,
	NULL,
	NULL,
	&usbser_pl2303_modinfo,
	NULL
};


struct streamtab usbser_pl2303_str_info = {
	&usbser_pl2303_rinit, &usbser_pl2303_winit, NULL, NULL
};


static struct cb_ops usbser_pl2303_cb_ops = {
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
	&usbser_pl2303_str_info,			/* cb_stream */
	(int)(D_64BIT | D_NEW | D_MP | D_HOTPLUG)	/* cb_flag */
};


/*
 * auto configuration ops
 */
struct dev_ops usbser_pl2303_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	usbser_pl2303_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	usbser_pl2303_attach,	/* devo_attach */
	usbser_pl2303_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&usbser_pl2303_cb_ops,	/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	usbser_power		/* devo_power */
};


extern struct mod_ops mod_driverops;


static struct modldrv modldrv = {
	&mod_driverops,		/* type of module - driver */
	"USB Prolific PL2303 driver 1.1",
	&usbser_pl2303_ops,
};


static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, 0
};


/*
 * entry points
 * ------------
 *
 */
int
_init(void)
{
	int    error;

	if ((error = mod_install(&modlinkage)) == 0) {
		error = ddi_soft_state_init(&usbser_pl2303_statep,
		    usbser_soft_state_size(), 1);
	}

	return (error);
}


int
_fini(void)
{
	int    error;

	if ((error = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&usbser_pl2303_statep);
	}

	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


int
usbser_pl2303_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result)
{
	return (usbser_getinfo(dip, infocmd, arg, result,
	    usbser_pl2303_statep));
}


static int
usbser_pl2303_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	return (usbser_attach(dip, cmd, usbser_pl2303_statep, &ds_ops));
}


static int
usbser_pl2303_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (usbser_detach(dip, cmd, usbser_pl2303_statep));
}


static int
usbser_pl2303_open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	return (usbser_open(rq, dev, flag, sflag, cr, usbser_pl2303_statep));
}
