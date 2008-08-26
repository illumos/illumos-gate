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
 * IEEE 802.3ad Link Aggregation.
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/aggr.h>
#include <sys/aggr_impl.h>

/* module description */
#define	AGGR_LINKINFO	"Link Aggregation MAC"

/* device info ptr, only one for instance 0 */
dev_info_t *aggr_dip = NULL;

static int aggr_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int aggr_attach(dev_info_t *, ddi_attach_cmd_t);
static int aggr_detach(dev_info_t *, ddi_detach_cmd_t);

static struct cb_ops aggr_cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
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
	D_MP			/* Driver compatibility flag */
};

static struct dev_ops aggr_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	aggr_getinfo,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	aggr_attach,		/* attach */
	aggr_detach,		/* detach */
	nodev,			/* reset */
	&aggr_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev			/* dev power */
};

static struct modldrv aggr_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	AGGR_LINKINFO,		/* short description */
	&aggr_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&aggr_modldrv,
	NULL
};

int
_init(void)
{
	int	err;

	mac_init_ops(&aggr_dev_ops, "aggr");
	if ((err = mod_install(&modlinkage)) != 0)
		mac_fini_ops(&aggr_dev_ops);
	return (err);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) == 0)
		mac_fini_ops(&aggr_dev_ops);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
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
		*result = 0;
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
		if (aggr_ioc_init() != 0)
			return (DDI_FAILURE);
		aggr_dip = dip;
		aggr_port_init();
		aggr_grp_init();
		aggr_lacp_init();
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
		if (aggr_grp_count() > 0)
			return (DDI_FAILURE);

		aggr_dip = NULL;
		aggr_port_fini();
		aggr_grp_fini();
		aggr_lacp_fini();
		aggr_ioc_fini();
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}
