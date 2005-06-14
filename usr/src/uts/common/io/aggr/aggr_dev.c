/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IEEE 802.3ad Link Aggregation.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/list.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/stat.h>

#include <sys/aggr.h>
#include <sys/aggr_impl.h>

/* module description */
#define	AGGR_LINKINFO	"Link Aggregation MAC"

/* device info ptr, only one for instance 0 */
dev_info_t *aggr_dip;

static void aggr_dev_init(void);
static int aggr_dev_fini(void);
static int aggr_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int aggr_attach(dev_info_t *, ddi_attach_cmd_t);
static int aggr_detach(dev_info_t *, ddi_detach_cmd_t);

static struct cb_ops aggr_cb_ops = {
	aggr_open,		/* open */
	aggr_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	aggr_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* driver compatibility flag */
};

static struct dev_ops aggr_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	aggr_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	aggr_attach,		/* attach */
	aggr_detach,		/* detach */
	nodev,			/* reset */
	&aggr_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev			/* dev power */
};

static struct modldrv modldrv = {
	&mod_driverops,
	AGGR_LINKINFO,
	&aggr_ops
};

static struct modlinkage	modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int err;

	aggr_dev_init();

	if ((err = mod_install(&modlinkage)) != 0) {
		(void) aggr_dev_fini();
		return (err);
	}

	aggr_dip = NULL;

	return (0);
}

int
_fini(void)
{
	int err;

	if ((err = aggr_dev_fini()) != 0)
		return (err);

	if ((err = mod_remove(&modlinkage)) != 0) {
		aggr_dev_init();
		return (err);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
aggr_dev_init(void)
{
	aggr_port_init();
	aggr_grp_init();
}

static int
aggr_dev_fini(void)
{
	int err;

	if ((err = aggr_grp_fini()) != 0)
		return (err);
	if ((err = aggr_port_fini()) != 0) {
		/*
		 * re-initialize the groups to keep a consistent
		 * state.
		 */
		aggr_grp_init();
	}

	return (err);
}

/*ARGSUSED*/
static int
aggr_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = aggr_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
aggr_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_get_instance(dip) != 0) {
			/* we only allow instance 0 to attach */
			return (DDI_FAILURE);
		}

		/* create minor node for control interface */
		if (ddi_create_minor_node(dip, AGGR_DEVNAME_CTL, S_IFCHR,
		    AGGR_MINOR_CTL, DDI_PSEUDO, 0) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		aggr_dip = dip;
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
aggr_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		aggr_dip = NULL;
		ddi_remove_minor_node(dip, NULL);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}
