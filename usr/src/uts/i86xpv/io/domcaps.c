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
 * This rather uninspiring device enables userland to discover if
 * the current kernel is actually a dom0 or other domain e.g. domU.
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

#include <sys/domcaps_impl.h>

static dev_info_t *domcaps_devi;

/*ARGSUSED*/
static int
domcaps_getinfo(dev_info_t *devi, ddi_info_cmd_t cmd, void *arg, void **result)
{
	if (getminor((dev_t)arg) != DOMCAPS_MINOR)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = domcaps_devi;
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
domcaps_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, ddi_get_name(devi), S_IFCHR,
	    ddi_get_instance(devi), DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	domcaps_devi = devi;
	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

static int
domcaps_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	ddi_remove_minor_node(devi, NULL);
	domcaps_devi = NULL;
	return (DDI_SUCCESS);
}

/*ARGSUSED1*/
static int
domcaps_open(dev_t *dev, int flag, int otyp, cred_t *cr)
{
	return (getminor(*dev) == DOMCAPS_MINOR ? 0 : ENXIO);
}

/*ARGSUSED*/
static int
domcaps_read(dev_t dev, uio_t *uio, cred_t *cr)
{
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		static char data[] = "control_d\n";
		size_t nbytes;

		if (uio->uio_loffset > sizeof (data))
			return (0);
		nbytes = MIN(uio->uio_resid, sizeof (data) - uio->uio_loffset);

		return (uiomove(data + uio->uio_loffset, nbytes,
		    UIO_READ, uio));
	}

	return (0);
}

static struct cb_ops domcaps_cb_ops = {
	domcaps_open,
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	domcaps_read,
	nodev,		/* write */
	nodev,		/* ioctl */
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

static struct dev_ops domcaps_dv_ops = {
	DEVO_REV,
	0,
	domcaps_getinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	domcaps_attach,
	domcaps_detach,
	nodev,			/* reset */
	&domcaps_cb_ops,
	NULL,			/* struct bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"hypervisor capabilities driver",
	&domcaps_dv_ops
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
