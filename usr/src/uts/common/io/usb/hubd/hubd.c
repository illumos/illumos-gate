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
 * skeleton hub driver, the actual code is in hubdi.c
 * as it is shared between the root hub and the other hub instances
 */
#if defined(lint) && !defined(DEBUG)
#define	DEBUG	1
#endif

#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/hubdi.h>
#include <sys/usb/hubd/hub.h>
#include <sys/usb/hubd/hubdvar.h>

static int hubd_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int hubd_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int hubd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *credp, int *rvalp);
static int hubd_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result);
extern int usba_hubdi_power(dev_info_t *dip, int comp, int level);


static struct cb_ops hubd_cb_ops = {
	hubd_open,			/* open */
	hubd_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	hubd_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_MP				/* Driver compatibility flag */
};

static struct dev_ops hubd_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	hubd_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	usba_hubdi_attach,	/* attach */
	usba_hubdi_detach,	/* detach */
	nodev,			/* reset */
	&hubd_cb_ops,		/* driver operations */
	&usba_hubdi_busops,	/* bus operations */
	usba_hubdi_power,	/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module. This one is a driver */
	"USB Hub Driver", /* Name of the module. */
	&hubd_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};


extern void *hubd_statep;

int
_init(void)
{
	int rval;

	/* Initialize the soft state structures */
	if ((rval = ddi_soft_state_init(&hubd_statep,
	    sizeof (hubd_t), HUBD_INITIAL_SOFT_SPACE)) != 0) {
		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&hubd_statep);

		return (rval);
	}

	return (rval);
}


int
_fini(void)
{
	int rval = mod_remove(&modlinkage);
	if (rval == 0) {
		ddi_soft_state_fini(&hubd_statep);
	}

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static dev_info_t *
hubd_get_dip(dev_t dev)
{
	minor_t minor = getminor(dev);
	int instance = (int)minor & ~HUBD_IS_ROOT_HUB;
	hubd_t *hubd = ddi_get_soft_state(hubd_statep, instance);

	if (hubd) {
		return (hubd->h_dip);
	} else {
		return (NULL);
	}
}

/*
 * info handler
 */
/*ARGSUSED*/
int
hubd_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result)
{
	dev_t dev;
	int instance;
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)hubd_get_dip((dev_t)arg);
		if (*result != NULL) {
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = HUBD_UNIT(dev);
		*result = (void *)(intptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}
	return (error);
}

static int
hubd_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	dev_info_t *dip = hubd_get_dip(*devp);

	return (usba_hubdi_open(dip, devp, flags, otyp, credp));
}


static int
hubd_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	dev_info_t *dip = hubd_get_dip(dev);

	return (usba_hubdi_close(dip, dev, flag, otyp, credp));
}


static int
hubd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *credp, int *rvalp)
{
	dev_info_t *dip = hubd_get_dip(dev);

	return (usba_hubdi_ioctl(dip, dev, cmd, arg, mode,
	    credp, rvalp));
}
