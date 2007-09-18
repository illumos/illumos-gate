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
 * CPU nexus driver
 */

#include	<sys/types.h>
#include	<sys/param.h>
#include	<sys/conf.h>
#include	<sys/devops.h>
#include	<sys/modctl.h>
#include	<sys/cmn_err.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/sunndi.h>

static int cpunex_attach(dev_info_t *, ddi_attach_cmd_t);
static int cpunex_detach(dev_info_t *, ddi_detach_cmd_t);
static int cpunex_bus_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
    void *, void *);

static struct bus_ops cpunex_bus_ops = {
	BUSO_REV,
	nullbusmap,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	ddi_no_dma_map,
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,
	ddi_no_dma_bindhdl,
	ddi_no_dma_unbindhdl,
	ddi_no_dma_flush,
	ddi_no_dma_win,
	ddi_no_dma_mctl,
	cpunex_bus_ctl,
	ddi_bus_prop_op,
};

static struct dev_ops cpunex_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,
	nulldev,
	cpunex_attach,
	cpunex_detach,
	nodev,
	NULL,
	&cpunex_bus_ops,
	NULL
};

static struct modldrv modldrv = {
	&mod_driverops,
	"cpu nexus driver v1.0",
	&cpunex_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * cpunex_bus_ctl()
 *    This routine implements nexus bus ctl operations. Of importance are
 *    DDI_CTLOPS_REPORTDEV, DDI_CTLOPS_INITCHILD, DDI_CTLOPS_UNINITCHILD
 *    and DDI_CTLOPS_POWER. For DDI_CTLOPS_INITCHILD, it tries to lookup
 *    reg property on the child node and builds and sets the name.
 */
static int
cpunex_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op, void *arg,
    void *result)
{
	switch (op) {
		case DDI_CTLOPS_REPORTDEV: {
			dev_info_t *pdip = ddi_get_parent(rdip);
			cmn_err(CE_CONT, "?%s%d at %s%d",
			    ddi_node_name(rdip), ddi_get_instance(rdip),
			    ddi_node_name(pdip), ddi_get_instance(pdip));
			return (DDI_SUCCESS);
		}

		case DDI_CTLOPS_INITCHILD: {
			dev_info_t *cdip = (dev_info_t *)arg;
			int i;
			char caddr[MAXNAMELEN];

			i = ddi_prop_get_int(DDI_DEV_T_ANY, cdip,
			    DDI_PROP_DONTPASS, "reg", -1);

			if (i == -1) {
				cmn_err(CE_NOTE, "!%s(%d): \"reg\" property "
				    "not found", ddi_node_name(cdip),
				    ddi_get_instance(cdip));
				return (DDI_NOT_WELL_FORMED);
			}

			(void) sprintf(caddr, "%d", i);
			ddi_set_name_addr(cdip, caddr);

			return (DDI_SUCCESS);
		}

		case DDI_CTLOPS_UNINITCHILD: {
			ddi_prop_remove_all((dev_info_t *)arg);
			ddi_set_name_addr((dev_info_t *)arg, NULL);
			return (DDI_SUCCESS);
		}

		default: {
			return (ddi_ctlops(dip, rdip, op, arg, result));
		}
	}
}

/*ARGSUSED*/
static int
cpunex_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
	case DDI_RESUME:
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
cpunex_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
	case DDI_SUSPEND:
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
_init(void)
{
	int error;

	error = mod_install(&modlinkage);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
