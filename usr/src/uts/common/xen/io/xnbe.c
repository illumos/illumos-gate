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
 * Xen network backend - ioemu version.
 *
 * HVM guest domains use an emulated network device (typically the
 * rtl8139) to access the physical network via IO emulation running in
 * a backend domain (generally domain 0).
 *
 * The IO emulation code sends and receives packets using DLPI, usually
 * through a virtual NIC (vnic).
 *
 * The creation of the relevant vnic to correspond to the network interface
 * in the guest domain requires the use of 'hotplug' scripts in the backend
 * domain. This driver ensures that the hotplug scripts are run when
 * such guest domains are created.
 *
 * It is used as a result of the 'compatible' property associated with
 * IO emulated devices. See /etc/driver_aliases and common/xen/os/xvdi.c.
 */

#ifdef DEBUG
#define	XNBE_DEBUG 1
#endif /* DEBUG */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <xen/sys/xendev.h>
#ifdef XNBE_DEBUG
#include <sys/cmn_err.h>
#endif /* XNBE_DEBUG */

#ifdef XNBE_DEBUG
int xnbe_debug = 0;
#endif /* XNBE_DEBUG */

static int
xnbe_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
#ifdef XNBE_DEBUG
	if (xnbe_debug > 0)
		cmn_err(CE_NOTE, "xnbe_attach: dip 0x%p, cmd %d",
		    (void *)dip, cmd);
#endif /* XNBE_DEBUG */

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	(void) xvdi_post_event(dip, XEN_HP_ADD);

	return (DDI_SUCCESS);
}

static int
xnbe_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
#ifdef XNBE_DEBUG
	if (xnbe_debug > 0)
		cmn_err(CE_NOTE, "detach: dip 0x%p, cmd %d",
		    (void *)dip, cmd);
#endif /* XNBE_DEBUG */

	switch (cmd) {
	case DDI_DETACH:
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static struct cb_ops cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP | D_64BIT	/* Driver compatibility flag */
};

static struct dev_ops ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt  */
	nulldev,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	xnbe_attach,		/* devo_attach */
	xnbe_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)0,	/* devo_bus_ops */
	NULL			/* devo_power */
};

static struct modldrv modldrv = {
	&mod_driverops, "xnbe driver %I%", &ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
