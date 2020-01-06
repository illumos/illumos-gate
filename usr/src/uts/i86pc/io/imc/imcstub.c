/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * This is a stub driver that is used by the main imcstub driver to attach
 * component PCI devices so that it can access their dev_info_t.
 */

#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "imc.h"


static int
imcstub_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	return (imc_attach_stub(dip, cmd));
}

static int
imcstub_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (imc_detach_stub(dip, cmd));
}

static struct dev_ops imcstub_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nodev,
	.devo_identify = nodev,
	.devo_probe = nulldev,
	.devo_attach = imcstub_attach,
	.devo_detach = imcstub_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv imcstub_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "IMC Stub driver",
	.drv_dev_ops = &imcstub_dev_ops
};

static struct modlinkage imcstub_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &imcstub_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&imcstub_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&imcstub_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&imcstub_modlinkage));
}
