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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

int pcs_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
int pcs_attach(dev_info_t *, ddi_attach_cmd_t);
int pcs_detach(dev_info_t *, ddi_detach_cmd_t);
dev_info_t *pcs_dip;

static struct dev_ops pcs_devops = {
	DEVO_REV,
	0,
	pcs_getinfo,
	nulldev,
	nulldev,
	pcs_attach,
	pcs_detach,
	nulldev,
	NULL,
	NULL
};
/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"PCMCIA Socket Driver %I%",	/* Name of the module. */
	&pcs_devops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

struct pcs_inst {
	dev_info_t *dip;
} *pcs_instances;

int
_init()
{
	int ret;
	if ((ret = ddi_soft_state_init((void **)&pcs_instances,
					sizeof (struct pcs_inst), 1)) != 0)
		return (ret);
	if ((ret = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini((void **)&pcs_instances);
	}
	return (ret);
}

int
_fini()
{
	int ret;
	ret = mod_remove(&modlinkage);
	if (ret == 0) {
		ddi_soft_state_fini((void **)&pcs_instances);
	}
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
pcs_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error = DDI_SUCCESS;
	int inum;
	struct pcs_inst *inst;
#ifdef lint
	dip = dip;
#endif

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		inum = getminor((dev_t)arg);
		inst = (struct pcs_inst *)ddi_get_soft_state(pcs_instances,
								inum);
		if (inst == NULL)
			error = DDI_FAILURE;
		else
			*result = inst->dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		inum = getminor((dev_t)arg);
		inst = (struct pcs_inst *)ddi_get_soft_state(pcs_instances,
								inum);
		if (inst == NULL)
			error = DDI_FAILURE;
		else
			*result = (void *)(uintptr_t)inum;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

int
pcs_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret = DDI_SUCCESS;
	int inum;
	struct pcs_inst *inst;

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_SUCCESS);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	inum = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(pcs_instances, inum) == DDI_SUCCESS) {
		inst = (struct pcs_inst *)ddi_get_soft_state(pcs_instances,
								inum);
		if (inst == NULL)
			ret = DDI_FAILURE;
		else
			inst->dip = dip;
	}

	return (ret);
}

int
pcs_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		ddi_soft_state_free(pcs_instances, ddi_get_instance(dip));
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		return (DDI_SUCCESS);
	default:
		break;
	}
	return (DDI_FAILURE);
}
