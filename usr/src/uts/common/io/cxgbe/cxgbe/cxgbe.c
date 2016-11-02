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

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/atomic.h>
#include <sys/ethernet.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

/*
 * NOTE:  The "real" NIC driver is in the nexus.  This is just a thin wrapper
 * whose only purpose is to register the mac.
 */
#include "shared.h"
#include "version.h"

struct port_info_stub {
	PORT_INFO_HDR;
};

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
struct dev_ops cxgbe_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		cxgbe_devo_attach,
	.devo_detach =		cxgbe_devo_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&cxgbe_cb_ops,
};

static struct modldrv modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"Chelsio T4/T5 NIC " DRV_VERSION,
	.drv_dev_ops =		&cxgbe_dev_ops
};

static struct modlinkage modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{&modldrv, NULL},
};

int
_init(void)
{
	int rc;

	mac_init_ops(&cxgbe_dev_ops, T4_PORT_NAME);
	rc = mod_install(&modlinkage);
	if (rc != 0)
		mac_fini_ops(&cxgbe_dev_ops);

	return (rc);
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&modlinkage);
	if (rc != 0)
		return (rc);

	mac_fini_ops(&cxgbe_dev_ops);
	return (0);
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&modlinkage, mi));
}

static int
cxgbe_devo_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct port_info_stub *pi;
	mac_register_t *mac;
	mac_handle_t mh;
	int rc;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	pi = ddi_get_parent_data(dip);
	if (pi == NULL)
		return (DDI_FAILURE);

	mac = mac_alloc(MAC_VERSION);
	if (mac == NULL) {
		cmn_err(CE_WARN, "%s%d: failed to allocate version %d mac.",
		    ddi_driver_name(pi->dip), ddi_get_instance(pi->dip),
		    MAC_VERSION);
		return (DDI_FAILURE);
	}

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = pi;
	mac->m_dip = dip;
	mac->m_src_addr = pi->hw_addr;
	mac->m_callbacks = pi->mc;
	mac->m_max_sdu = pi->mtu;
	mac->m_priv_props = pi->props;
	mac->m_margin = 22; /* TODO: mac_register(9s) and onnv code disagree */

	rc = mac_register(mac, &mh);
	mac_free(mac);
	if (rc != 0) {
		cmn_err(CE_WARN, "%s%d: failed to register version %d mac.",
		    ddi_driver_name(pi->dip), ddi_get_instance(pi->dip),
		    MAC_VERSION);
		return (DDI_FAILURE);
	}
	pi->mh = mh;

	/*
	 * Link state from this point onwards to the time interface is plumbed,
	 * should be set to LINK_STATE_UNKNOWN. The mac should be updated about
	 * the link state as either LINK_STATE_UP or LINK_STATE_DOWN based on
	 * the actual link state detection after interface plumb.
	 */
	mac_link_update(mh, LINK_STATE_UNKNOWN);

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
cxgbe_devo_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct port_info_stub *pi;
	mac_handle_t mh;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	pi = ddi_get_parent_data(dip);
	if (pi == NULL)
		return (DDI_FAILURE);

	mh = pi->mh;
	pi->mh = NULL;

	return (mac_unregister(mh));
}
