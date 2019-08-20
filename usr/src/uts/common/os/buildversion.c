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
 * This kernel module carries the contents of the file $SRC/buildversion
 * in such a way that it will be included in kernel crash dumps.  It will be
 * forceloaded at boot, will refuse to detach, and has no other moving parts.
 *
 * The git information can be read back with "mdb", either on the live system
 * or from a crash dump; e.g.,
 *
 *	# mdb -ke buildversion_start/s
 *
 * or with
 *
 *	# mdb -ke ::status
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

int buildversion_no_detach = 1;

static int
buildversion_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
buildversion_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{

	switch (cmd) {
	case DDI_DETACH:
		if (buildversion_no_detach) {
			return (DDI_FAILURE);
		}
		/* FALLTHRU */
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static struct dev_ops buildversion_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		nodev,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,

	.devo_attach =		buildversion_attach,
	.devo_detach =		buildversion_detach,

	.devo_reset =		nodev,
	.devo_cb_ops =		NULL,
	.devo_bus_ops =		NULL,
	.devo_power =		nodev,
	.devo_quiesce =		ddi_quiesce_not_needed,
};

static struct modldrv buildversion_md = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"illumos buildversion",
	.drv_dev_ops =		&buildversion_dev_ops,
};

static struct modlinkage buildversion_ml = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ &buildversion_md, NULL }
};

int
_init(void)
{
	return (mod_install(&buildversion_ml));
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&buildversion_ml, mi));
}

int
_fini(void)
{
	return (mod_remove(&buildversion_ml));
}
