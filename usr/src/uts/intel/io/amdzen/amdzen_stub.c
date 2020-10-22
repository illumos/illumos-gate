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
 * Copyright 2020 Oxide Computer Company
 */

/*
 * A stub driver for the AMD Zen Nexus. This is used to help us get all the
 * relevant PCI devices into one place. See uts/intel/io/amdzen/amdzen.c for
 * more details.
 */

#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "amdzen.h"

static int
amdzen_stub_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	return (amdzen_attach_stub(dip, cmd));
}

static int
amdzen_stub_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (amdzen_detach_stub(dip, cmd));
}

static struct dev_ops amdzen_stub_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nodev,
	.devo_identify = nodev,
	.devo_probe = nulldev,
	.devo_attach = amdzen_stub_attach,
	.devo_detach = amdzen_stub_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv amdzen_stub_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AMD Zen Nexus Stub driver",
	.drv_dev_ops = &amdzen_stub_dev_ops
};

static struct modlinkage amdzen_stub_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &amdzen_stub_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&amdzen_stub_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&amdzen_stub_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&amdzen_stub_modlinkage));
}
