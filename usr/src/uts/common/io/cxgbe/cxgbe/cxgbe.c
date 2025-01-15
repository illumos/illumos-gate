/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/mac_provider.h>

/*
 * NOTE:  The "real" NIC driver is in the nexus.  This is just a thin wrapper
 * whose only purpose is to register the mac.
 */
#include "shared.h"
#include "version.h"

static struct cb_ops cxgbe_cb_ops = {
	.cb_open =		nulldev,
	.cb_close =		nulldev,
	.cb_strategy =		nodev,
	.cb_print = 		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_ioctl =		nodev,
	.cb_devmap =		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_flag =		D_MP,
	.cb_rev =		CB_REV,
	.cb_aread =		nodev,
	.cb_awrite =		nodev
};

static int cxgbe_devo_attach(dev_info_t *, ddi_attach_cmd_t);
static int cxgbe_devo_detach(dev_info_t *, ddi_detach_cmd_t);
static struct dev_ops cxgbe_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		cxgbe_devo_attach,
	.devo_detach =		cxgbe_devo_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&cxgbe_cb_ops,
};

static struct modldrv cxgbe_modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"Chelsio T4-T6 NIC " DRV_VERSION,
	.drv_dev_ops =		&cxgbe_dev_ops
};

static struct modlinkage cxgbe_modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{&cxgbe_modldrv, NULL},
};

int
_init(void)
{
	int rc;

	mac_init_ops(&cxgbe_dev_ops, T4_PORT_NAME);
	rc = mod_install(&cxgbe_modlinkage);
	if (rc != 0)
		mac_fini_ops(&cxgbe_dev_ops);

	return (rc);
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&cxgbe_modlinkage);
	if (rc != 0)
		return (rc);

	mac_fini_ops(&cxgbe_dev_ops);
	return (0);
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&cxgbe_modlinkage, mi));
}

static int
cxgbe_devo_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	struct port_info *pi = ddi_get_parent_data(dip);
	if (pi == NULL) {
		return (DDI_FAILURE);
	}

	const int rc = t4_cxgbe_attach(pi, dip);
	if (rc == DDI_SUCCESS) {
		ddi_report_dev(dip);
	}
	return (rc);
}

static int
cxgbe_devo_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	struct port_info *pi = ddi_get_parent_data(dip);
	if (pi == NULL) {
		return (DDI_FAILURE);
	}

	return (t4_cxgbe_detach(pi));
}
