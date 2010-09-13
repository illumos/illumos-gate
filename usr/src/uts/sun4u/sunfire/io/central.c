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


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/autoconf.h>
#include <sys/modctl.h>

/*
 * module central.c
 *
 * This module is a nexus driver designed to support the fhc nexus driver
 * and all children below it. This driver does not handle any of the
 * DDI functions passed up to it by the fhc driver, but instead allows
 * them to bubble up to the root node. A consequence of this is that
 * the maintainer of this code must watch for changes in the sun4u
 * rootnexus driver to make sure they do not break this driver or any
 * of its children.
 */

/*
 * Function Prototypes
 */
static int
central_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);

static int
central_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

/*
 * Configuration Data Structures
 */
static struct bus_ops central_bus_ops = {
	BUSO_REV,
	ddi_bus_map,		/* map */
	0,			/* get_intrspec */
	0,			/* add_intrspec */
	0,			/* remove_intrspec */
	i_ddi_map_fault,	/* map_fault */
	ddi_no_dma_map,		/* dma_map */
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,
	ddi_no_dma_bindhdl,
	ddi_no_dma_unbindhdl,
	ddi_no_dma_flush,
	ddi_no_dma_win,
	ddi_dma_mctl,		/* dma_ctl */
	ddi_ctlops,		/* ctl */
	ddi_bus_prop_op,	/* prop_op */
	0,			/* (*bus_get_eventcookie)();	*/
	0,			/* (*bus_add_eventcall)();	*/
	0,			/* (*bus_remove_eventcall)();	*/
	0,			/* (*bus_post_event)();		*/
	0,			/* (*bus_intr_ctl)();		*/
	0,			/* (*bus_config)();		*/
	0,			/* (*bus_unconfig)();		*/
	0,			/* (*bus_fm_init)();		*/
	0,			/* (*bus_fm_fini)();		*/
	0,			/* (*bus_fm_access_enter)();	*/
	0,			/* (*bus_fm_access_exit)();	*/
	0,			/* (*bus_power)();		*/
	i_ddi_intr_ops		/* (*bus_intr_op)();		*/
};

static struct dev_ops central_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	ddi_no_info,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	central_attach,		/* attach */
	central_detach,		/* detach */
	nulldev,		/* reset */
	(struct cb_ops *)0,	/* cb_ops */
	&central_bus_ops,	/* bus_ops */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Central Nexus",	/* Name of module. */
	&central_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	(void *)&modldrv,
	NULL
};

/*
 * These are the module initialization routines.
 */

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
central_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* nothing to suspend/resume here */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "pm-hardware-state", "no-suspend-resume");

	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
central_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_SUSPEND:
	case DDI_DETACH:
	default:
		return (DDI_FAILURE);
	}
}
