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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Device-specific nexus functions.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/stddef.h>
#include <sys/fs/dv_node.h>

#include "i2cnex.h"

i2c_dev_t *
i2c_device_find_by_addr(i2c_txn_t *txn, i2c_port_t *port,
    const i2c_addr_t *addr)
{
	i2c_dev_t d;

	VERIFY(i2c_txn_held(txn));
	VERIFY3P(txn->txn_ctrl, ==, port->ip_nex->in_ctrl);
	(void) memset(&d, 0, sizeof (i2c_dev_t));
	d.id_addr = *addr;

	return (avl_find(&port->ip_devices, &d, NULL));
}

static void
i2c_device_free(i2c_dev_t *dev)
{
	VERIFY3P(dev->id_mux, ==, NULL);
	if (dev->id_nucompat > 0) {
		VERIFY3P(dev->id_ucompat, !=, NULL);
		for (uint_t i = 0; i < dev->id_nucompat; i++) {
			strfree(dev->id_ucompat[i]);
		}
		kmem_free(dev->id_ucompat, sizeof (char *) * dev->id_nucompat);
	}
	i2cnex_nex_free(dev->id_nex);
	list_destroy(&dev->id_clients);
	kmem_free(dev, sizeof (i2c_dev_t));
}

static bool
i2c_device_parent_rm(i2c_port_t *port, void *arg)
{
	VERIFY3U(port->ip_ndevs_ds, >, 0);
	port->ip_ndevs_ds--;
	return (true);
}

static bool
i2c_device_parent_add(i2c_port_t *port, void *arg)
{
	port->ip_ndevs_ds++;
	return (true);
}

void
i2c_device_fini(i2c_txn_t *txn, i2c_port_t *port, i2c_dev_t *dev)
{
	VERIFY(i2c_txn_held(txn));
	VERIFY3P(txn->txn_ctrl, ==, port->ip_nex->in_ctrl);
	VERIFY3P(dev->id_nex->in_pnex, ==, port->ip_nex);

	i2c_port_parent_iter(port, i2c_device_parent_rm, NULL);
	avl_remove(&port->ip_devices, dev);
	i2c_addr_free(port, &dev->id_addr);
	i2c_device_free(dev);
}

/*
 * Attempt to allocate the address specified and return the allocated device.
 * The device will not be visible in the port until i2c_device_config() has been
 * called on it.
 */
i2c_dev_t *
i2c_device_init(i2c_txn_t *txn, i2c_port_t *port, const i2c_addr_t *addr,
    const char *name, char *const *compat, uint_t ncompat, i2c_error_t *err)
{
	char ua[I2C_NAME_MAX];
	i2c_dev_t *dev;
	i2c_ctrl_t *ctrl = port->ip_nex->in_ctrl;

	VERIFY(i2c_txn_held(txn));
	VERIFY3P(txn->txn_ctrl, ==, ctrl);

	/*
	 * First attempt to grab the address. If we can't grab it, then that's
	 * that.
	 */
	if (!i2c_addr_alloc(port, addr, err)) {
		return (NULL);
	}

	dev = kmem_zalloc(sizeof (i2c_dev_t), KM_SLEEP);
	list_create(&dev->id_clients, sizeof (i2c_client_t),
	    offsetof(i2c_client_t, icli_dev_link));
	dev->id_addr = *addr;
	if (ncompat > 0) {
		dev->id_nucompat = ncompat;
		dev->id_ucompat = kmem_alloc(sizeof (char *) * ncompat,
		    KM_SLEEP);
		for (uint_t i = 0; i < ncompat; i++) {
			dev->id_ucompat[i] = strdup(compat[i]);
		}
	}

	(void) snprintf(ua, sizeof (ua), "%x,%x", addr->ia_type, addr->ia_addr);
	dev->id_nex = i2cnex_nex_alloc(I2C_NEXUS_T_DEV, port->ip_nex->in_dip,
	    port->ip_nex, name, ua, ctrl);
	if (dev->id_nex == NULL) {
		i2c_addr_free(port, &dev->id_addr);
		i2c_device_free(dev);
		return (NULL);
	}
	dev->id_nex->in_data.in_dev = dev;

	/*
	 * Finish by adding it to the list such that it can be discovered by
	 * device configuration logic. Then walk our parents so they can update
	 * their device count metrics.
	 */
	avl_add(&port->ip_devices, dev);
	i2c_port_parent_iter(port, i2c_device_parent_add, NULL);

	return (dev);
}

/*
 * We are going to attempt to unconfigure a node. This normally would be a
 * straightforward request based on the unit address; however, our node in
 * question may never have been attached and therefore may not have an address
 * assigned. The NDI doesn't give us a good way to deal with this, therefore we
 * need to look at the node state ourselves and figure out what to do.
 *
 * This seems unfortunate, especially as we have the dip at our disposal. We
 * should make this the NDI's problem. It'd be nice if we had an
 * ndi_devi_unconfig_dip() or similar.
 */
bool
i2c_device_unconfig(i2c_port_t *port, i2c_dev_t *dev)
{
	int ret;

	VERIFY(DEVI_BUSY_OWNED(port->ip_nex->in_dip));

	/*
	 * This node may already have been detached and torn down for some
	 * reason say due to a BUS_UNCONFIG_ALL of the port. If there is no dip,
	 * then we're done. This also means that this device should not be in
	 * the AVL tree.
	 */
	if (dev->id_nex->in_dip == NULL) {
		return (true);
	}

	/*
	 * The fundamental problem here is that if we're not initialized, then
	 * we can't actually be found by ndi_devi_unconfig_one. This is an
	 * unfortuante NDI wart which means that we don't actually get uniform
	 * clean up and teardown that we need. So we have to basically cheat
	 * here. This should be solved with improvements to the NDI.
	 */
	if (i_ddi_node_state(dev->id_nex->in_dip) < DS_INITIALIZED) {
		i2c_nex_dev_cleanup(dev->id_nex);
		ret = ddi_remove_child(dev->id_nex->in_dip, 0);
		if (ret == NDI_SUCCESS) {
			dev->id_nex->in_dip = NULL;
		}
	} else {
		char ua[I2C_NAME_MAX * 4];
		(void) snprintf(ua, sizeof (ua), "%s@%s", dev->id_nex->in_name,
		    dev->id_nex->in_addr);
		(void) devfs_clean(port->ip_nex->in_dip, ua, DV_CLEAN_FORCE);
		ret = ndi_devi_unconfig_one(port->ip_nex->in_dip, ua, NULL,
		    NDI_DEVI_REMOVE | NDI_UNCONFIG);
	}

	if (ret != NDI_SUCCESS) {
		return (false);
	}

	return (true);
}

bool
i2c_device_config(i2c_port_t *port, i2c_dev_t *dev)
{
	int ret;
	char ua[I2C_NAME_MAX * 4];
	dev_info_t *child;

	VERIFY(DEVI_BUSY_OWNED(port->ip_nex->in_dip));

	/*
	 * Ask the system to go ahead and configure this node. As long as a
	 * dev_info_t is successfully created, then we consider this a success.
	 * If it is created successfully, we will be given a reference count on
	 * the node that we need to decrement.
	 *
	 * It is possible that ndi_devi_config_one() will fail, but that's
	 * because if it fails to bind a driver to the node (which may not
	 * exist), then it will fail the call. Instead we use the existence of
	 * our dev_info_t in the nexus as the true sign of success.
	 */

	(void) snprintf(ua, sizeof (ua), "%s@%s", dev->id_nex->in_name,
	    dev->id_nex->in_addr);
	ret = ndi_devi_config_one(port->ip_nex->in_dip, ua, &child, NDI_CONFIG |
	    NDI_ONLINE_ATTACH);
	if (ret == NDI_SUCCESS) {
		ndi_rele_devi(child);
	}

	return (dev->id_nex->in_dip != NULL);
}
