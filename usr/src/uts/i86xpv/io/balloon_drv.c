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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * A simple wrapper around the balloon kernel thread to allow userland
 * programs access to the balloon status.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/hypervisor.h>
#include <sys/sysmacros.h>
#include <sys/balloon_impl.h>

static dev_info_t *balloon_devi;

/*ARGSUSED*/
static int
balloon_getinfo(dev_info_t *devi, ddi_info_cmd_t cmd, void *arg, void **result)
{
	if (getminor((dev_t)arg) != BALLOON_MINOR)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = balloon_devi;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
balloon_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, ddi_get_name(devi), S_IFCHR,
	    ddi_get_instance(devi), DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	balloon_devi = devi;
	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

static int
balloon_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	ddi_remove_minor_node(devi, NULL);
	balloon_devi = NULL;
	return (DDI_SUCCESS);
}

/*ARGSUSED1*/
static int
balloon_open(dev_t *dev, int flag, int otyp, cred_t *cr)
{
	return (getminor(*dev) == BALLOON_MINOR ? 0 : ENXIO);
}

/*
 * When asked for one of the balloon values, we simply query the balloon thread.
 */
/*ARGSUSED*/
static int
balloon_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval_p)
{
	int rval = 0;
	size_t value;

	switch (cmd) {
	case BLN_IOCTL_CURRENT:
	case BLN_IOCTL_TARGET:
	case BLN_IOCTL_LOW:
	case BLN_IOCTL_HIGH:
	case BLN_IOCTL_LIMIT:
		value = balloon_values(cmd);
		if (ddi_copyout((void *)&value, (void *)arg, sizeof (value),
		    mode))
			return (EFAULT);
		break;
	default:
		rval = EINVAL;
		break;
	}
	return (rval);
}

static struct cb_ops balloon_cb_ops = {
	balloon_open,
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	balloon_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_64BIT | D_MP,
	CB_REV,
	NULL,
	NULL
};

static struct dev_ops balloon_dv_ops = {
	DEVO_REV,
	0,
	balloon_getinfo,
	nulldev,	/* identify */
	nulldev,	/* probe */
	balloon_attach,
	balloon_detach,
	nodev,		/* reset */
	&balloon_cb_ops,
	NULL,		/* struct bus_ops */
	NULL		/* power */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"balloon driver 1.1",
	&balloon_dv_ops
};

static struct modlinkage modl = {
	MODREV_1,
	{
		(void *)&modldrv,
		NULL		/* null termination */
	}
};

int
_init(void)
{
	return (mod_install(&modl));
}

int
_fini(void)
{
	return (mod_remove(&modl));
}

int
_info(struct modinfo *modinfo)
{
	return (mod_info(&modl, modinfo));
}
