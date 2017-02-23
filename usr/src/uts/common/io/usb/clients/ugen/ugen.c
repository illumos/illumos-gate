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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */


/*
 * UGEN: USB Generic Driver
 *
 * The "Universal Generic Driver"  (UGEN) for USB devices provides interfaces
 * to  talk to	USB  devices.  This is	very  useful for  Point of Sale sale
 * devices and other simple  devices like  USB	scanner, USB palm  pilot.
 * The UGEN provides a system call interface to USB  devices  enabling
 * a USB device vendor to write an application for their
 * device instead of  writing a driver. This facilitates the vendor to write
 * device management s/w quickly in userland.
 *
 * UGEN supports read/write/poll entry points. An application can be written
 * using  read/write/aioread/aiowrite/poll  system calls to communicate
 * with the device.
 */
#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_ugen.h>
#include <sys/usb/clients/ugen/ugend.h>

/* Global variables */
static void	*ugen_skel_statep;

/* Prototypes declarations for the entry points */
static int	ugen_skel_getinfo(dev_info_t *, ddi_info_cmd_t,
						void *, void **);
static int	ugen_skel_open(dev_t *, int, int, cred_t *);
static int	ugen_skel_close(dev_t, int, int, cred_t *);
static int	ugen_skel_attach(dev_info_t *, ddi_attach_cmd_t);
static int	ugen_skel_detach(dev_info_t *, ddi_detach_cmd_t);
static int	ugen_skel_power(dev_info_t *, int, int);
static int	ugen_skel_read(dev_t, struct uio *, cred_t *);
static int	ugen_skel_write(dev_t, struct uio *, cred_t *);
static int	ugen_skel_poll(dev_t, short, int,  short *,
						struct pollhead **);

static int	ugen_skel_disconnect_ev_cb(dev_info_t *);
static int	ugen_skel_reconnect_ev_cb(dev_info_t *);

/* event support */
static usb_event_t ugen_skel_events = {
	ugen_skel_disconnect_ev_cb,
	ugen_skel_reconnect_ev_cb,
	NULL, NULL
};

/* Driver cb_ops structure */
static struct cb_ops ugen_skel_cb_ops = {
	ugen_skel_open,			/* open */
	ugen_skel_close,		/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	ugen_skel_read,			/* read */
	ugen_skel_write,		/* write */
	nodev,				/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	ugen_skel_poll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab  */
	D_MP,				/* Driver compatibility flag */
	CB_REV,				/* revision */
	nodev,				/* aread */
	nodev				/* awrite */
};

/*
 * Modloading support
 *	driver dev_ops structure
 */
static struct dev_ops ugen_skel_ops = {
	DEVO_REV,			/* devo_rev, */
	0,				/* refct  */
	ugen_skel_getinfo,		/* info */
	nulldev,			/* indetify */
	nulldev,			/* probe */
	ugen_skel_attach,		/* attach */
	ugen_skel_detach,		/* detach */
	nodev,				/* reset */
	&ugen_skel_cb_ops,		/* driver operations */
	NULL,				/* bus operations */
	ugen_skel_power,		/* power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* Module type */
	"USB Generic driver",	/* Name of the module. */
	&ugen_skel_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};


int
_init()
{
	int	rval;

	if ((rval = ddi_soft_state_init(&ugen_skel_statep,
	    sizeof (ugen_skel_state_t), UGEN_INSTANCES)) != 0) {

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&ugen_skel_statep);

		return (rval);
	}

	return (rval);
}


int
_fini()
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) != 0) {

		return (rval);
	}
	ddi_soft_state_fini(&ugen_skel_statep);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*ARGSUSED*/
static int
ugen_skel_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int		rval = DDI_FAILURE;
	int		instance =
	    UGEN_MINOR_TO_INSTANCE(getminor((dev_t)arg));
	ugen_skel_state_t *ugen_skelp;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		ugen_skelp = ddi_get_soft_state(ugen_skel_statep, instance);
		if (ugen_skelp != NULL) {
			*result = ugen_skelp->ugen_skel_dip;
			if (*result != NULL) {
				rval = DDI_SUCCESS;
			}
		} else {
			*result = NULL;
		}

		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		rval = DDI_SUCCESS;

		break;
	default:

		break;
	}

	return (rval);
}


/*
 * ugen_skel_attach()
 */
static int
ugen_skel_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ugen_skel_state_t	*ugen_skelp;
	int			instance;	/* Driver instance number */
	int			rval;
	usb_ugen_info_t		usb_ugen_info;

	/* Get instance number */
	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:

		break;
	case DDI_RESUME:
		ugen_skelp = ddi_get_soft_state(ugen_skel_statep, instance);
		if (ugen_skelp == NULL) {

			return (DDI_FAILURE);
		}

		rval = usb_ugen_attach(ugen_skelp->ugen_skel_hdl, cmd);

		return (rval == USB_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
	default:

		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(ugen_skel_statep, instance) ==
	    DDI_SUCCESS) {
		ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
		    instance);
	}
	if (ugen_skelp == NULL) {

		return (DDI_FAILURE);
	}

	if ((rval = usb_client_attach(dip, USBDRV_VERSION, 0)) !=
	    USB_SUCCESS) {

		goto fail;
	}

	ugen_skelp->ugen_skel_dip	= dip;
	ugen_skelp->ugen_skel_instance	= instance;

	/* get a ugen handle */
	bzero(&usb_ugen_info, sizeof (usb_ugen_info));
	usb_ugen_info.usb_ugen_flags =
	    USB_UGEN_ENABLE_PM | USB_UGEN_REMOVE_CHILDREN;
	usb_ugen_info.usb_ugen_minor_node_ugen_bits_mask =
	    (dev_t)UGEN_MINOR_UGEN_BITS_MASK;
	usb_ugen_info.usb_ugen_minor_node_instance_mask =
	    (dev_t)~UGEN_MINOR_UGEN_BITS_MASK;
	ugen_skelp->ugen_skel_hdl = usb_ugen_get_hdl(dip,
	    &usb_ugen_info);

	if (usb_ugen_attach(ugen_skelp->ugen_skel_hdl, cmd) != USB_SUCCESS) {

		goto fail;
	}

	/* register for hotplug events */
	if (usb_register_event_cbs(dip, &ugen_skel_events, 0) != USB_SUCCESS) {

		goto fail;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	if (ugen_skelp) {
		usb_unregister_event_cbs(dip, &ugen_skel_events);
		usb_ugen_release_hdl(ugen_skelp->
		    ugen_skel_hdl);
		ddi_soft_state_free(ugen_skel_statep,
		    ugen_skelp->ugen_skel_instance);
		usb_client_detach(dip, NULL);
	}

	return (DDI_FAILURE);
}


/*
 * ugen_skel_detach()
 */
static int
ugen_skel_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		rval = USB_FAILURE;
	ugen_skel_state_t *ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
	    ddi_get_instance(dip));

	if (ugen_skelp) {
		switch (cmd) {
		case DDI_DETACH:
			rval = usb_ugen_detach(ugen_skelp->ugen_skel_hdl, cmd);
			if (rval == USB_SUCCESS) {
				usb_unregister_event_cbs(dip,
				    &ugen_skel_events);
				usb_ugen_release_hdl(ugen_skelp->
				    ugen_skel_hdl);
				ddi_soft_state_free(ugen_skel_statep,
				    ugen_skelp->ugen_skel_instance);
				usb_client_detach(dip, NULL);
			}

			break;
		case DDI_SUSPEND:
			rval = usb_ugen_detach(ugen_skelp->ugen_skel_hdl, cmd);

			break;
		default:

			break;
		}
	}

	return (rval == USB_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * ugen_skel_disconnect_ev_cb:
 */
static int
ugen_skel_disconnect_ev_cb(dev_info_t *dip)
{
	ugen_skel_state_t *ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
	    ddi_get_instance(dip));

	return (usb_ugen_disconnect_ev_cb(ugen_skelp->ugen_skel_hdl));
}


/*
 * ugen_skel_reconnect_ev_cb:
 */
static int
ugen_skel_reconnect_ev_cb(dev_info_t *dip)
{
	ugen_skel_state_t *ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
	    ddi_get_instance(dip));

	return (usb_ugen_reconnect_ev_cb(ugen_skelp->ugen_skel_hdl));
}


/*
 * ugen_skel_open:
 */
static int
ugen_skel_open(dev_t *devp, int flag, int sflag, cred_t *cr)
{
	ugen_skel_state_t *ugen_skelp;

	if ((ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
	    UGEN_MINOR_TO_INSTANCE(getminor(*devp)))) == NULL) {
		/* deferred detach */

		return (ENXIO);
	}

	return (usb_ugen_open(ugen_skelp->ugen_skel_hdl, devp, flag,
	    sflag, cr));
}


/*
 * ugen_skel_close()
 */
static int
ugen_skel_close(dev_t dev, int flag, int otype, cred_t *cr)
{
	ugen_skel_state_t *ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
	    UGEN_MINOR_TO_INSTANCE(getminor(dev)));

	return (usb_ugen_close(ugen_skelp->ugen_skel_hdl, dev, flag,
	    otype, cr));
}


/*
 * ugen_skel_read/write()
 */
static int
ugen_skel_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	ugen_skel_state_t *ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
	    UGEN_MINOR_TO_INSTANCE(getminor(dev)));
	if (ugen_skelp == NULL) {

		return (ENXIO);
	}

	return (usb_ugen_read(ugen_skelp->ugen_skel_hdl, dev,
	    uiop, credp));
}


static int
ugen_skel_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	ugen_skel_state_t *ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
	    UGEN_MINOR_TO_INSTANCE(getminor(dev)));
	if (ugen_skelp == NULL) {

		return (ENXIO);
	}
	return (usb_ugen_write(ugen_skelp->ugen_skel_hdl,
	    dev, uiop, credp));
}


/*
 * ugen_skel_poll
 */
static int
ugen_skel_poll(dev_t dev, short events,
    int anyyet,  short *reventsp, struct pollhead **phpp)
{
	ugen_skel_state_t *ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
	    UGEN_MINOR_TO_INSTANCE(getminor(dev)));
	if (ugen_skelp == NULL) {

		return (ENXIO);
	}

	return (usb_ugen_poll(ugen_skelp->ugen_skel_hdl, dev, events,
	    anyyet, reventsp, phpp));
}


/*
 * ugen_skel_power:
 *	PM entry point
 */
static int
ugen_skel_power(dev_info_t *dip, int comp, int level)
{
	int rval;

	ugen_skel_state_t *ugen_skelp = ddi_get_soft_state(ugen_skel_statep,
	    ddi_get_instance(dip));
	if (ugen_skelp == NULL) {

		return (DDI_FAILURE);
	}
	rval = usb_ugen_power(ugen_skelp->ugen_skel_hdl, comp, level);

	return (rval == USB_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
}
