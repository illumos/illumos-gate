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
 * nulldriver - null device driver
 *
 * The nulldriver is used to associate a solaris driver with a specific
 * device without enabling external device access.
 *
 * The driver can be used to:
 *
 * o Prevent external access to specific devices/hardware by associating a
 *   high-precedence 'compatible' binding, including a path-oriented alias,
 *   with nulldriver.
 *
 * o Enable a nexus bus_config implementation to perform dynamic child
 *   discovery by creating a child 'probe' devinfo node, bound to
 *   nulldriver, at the specific child @unit-addresses associated with
 *   discovery.  With a nulldriver bound 'probe' node, nexus driver
 *   bus_config discovery code can use the same devinfo node oriented
 *   transport services for both discovery and normal-operation: which
 *   is a significant simplification.  While nulldriver prevents external
 *   device access, a nexus driver can still internally use the transport
 *   services.
 *
 *   A scsi(4) example of this type of use is SCSA enumeration services
 *   issuing a scsi REPORT_LUN command to a lun-0 'probe' node bound to
 *   nulldriver in order to discover all luns supported by a target.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>

static int nulldriver_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int nulldriver_probe(dev_info_t *);
static int nulldriver_attach(dev_info_t *, ddi_attach_cmd_t);
static int nulldriver_detach(dev_info_t *, ddi_detach_cmd_t);

static struct cb_ops nulldriver_cb_ops = {
	nodev,				/* open */
	nodev,				/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	nodev,				/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab  */
	D_MP | D_NEW | D_HOTPLUG	/* Driver compatibility flag */
};

static struct dev_ops nulldriver_dev_ops = {
	DEVO_REV,			/* devo_rev, */
	0,				/* refcnt  */
	nulldriver_getinfo,		/* info */
	nodev,				/* identify */
	nulldriver_probe,		/* probe */
	nulldriver_attach,		/* attach */
	nulldriver_detach,		/* detach */
	nodev,				/* reset */
	&nulldriver_cb_ops,		/* driver operations */
	(struct bus_ops *)0,		/* bus operations */
	NULL,				/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, "nulldriver 1.1", &nulldriver_dev_ops
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
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
nulldriver_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
nulldriver_probe(dev_info_t *dip)
{
	/*
	 * We want to succeed probe so that the node gets assigned a unit
	 * address "@addr".
	 */
	if (ddi_dev_is_sid(dip) == DDI_SUCCESS)
		return (DDI_PROBE_DONTCARE);
	return (DDI_PROBE_DONTCARE);
}

/*
 * nulldriver_attach()
 *	attach(9e) entrypoint.
 */
/* ARGSUSED */
static int
nulldriver_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
	case DDI_RESUME:
		return (DDI_SUCCESS);

	case DDI_PM_RESUME:
	default:
		return (DDI_FAILURE);
	}
}

/*
 * nulldriver_detach()
 *	detach(9E) entrypoint
 */
/* ARGSUSED */
static int
nulldriver_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_PM_SUSPEND:
	default:
		return (DDI_FAILURE);
	}
}
