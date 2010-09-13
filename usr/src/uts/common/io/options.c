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
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * Configuration information
 */

static int options_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int options_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int options_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static dev_info_t *options_devi;

struct dev_ops	options_ops = {

	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	options_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	options_attach,		/* attach */
	options_detach,		/* detach */
	nodev,			/* reset */
	(struct cb_ops *)0,	/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */

};

/*
 * Autoload Data and Autoload Entry
 */

#include <sys/modctl.h>

extern struct mod_ops mod_driverops;
static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module. This one is a driver */
	"options driver",	/* Name of the module. */
	&options_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv
};

/*
 * This is the driver initialization routine.
 */

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (EBUSY);
}

int
_info(modinfop)
	struct modinfo *modinfop;
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
options_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	register int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (options_devi == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *) options_devi;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

static int
options_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		options_devi = devi;
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
options_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_DETACH:
	default:
		return (DDI_FAILURE);
	}
}
