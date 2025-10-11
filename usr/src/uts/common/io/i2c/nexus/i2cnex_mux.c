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
 * Multiplexor-specific nexus functions.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#include "i2cnex.h"

#define	I2C_MUX_PORT_NONE	UINT32_MAX

void
i2c_mux_mod_fini(struct dev_ops *ops)
{
	ops->devo_bus_ops = NULL;
}

/*
 * Currently we assume that the only way we are instantiating i2c muxes is by
 * attaching it to an i2c_dev_t. These bus ops will work as long as that holds
 * true. If we end up supporting muxes that are not managed by i2cnex directly
 * then we will need to transform this around to handle those cases and this
 * will need to look more like the I2C controller bus ops. This constraints is
 * currently enforced as part of mux registration.
 */
void
i2c_mux_mod_init(struct dev_ops *ops)
{
	ops->devo_bus_ops = &i2c_nex_bus_ops;
}

void
i2c_mux_register_free(i2c_mux_register_t *reg)
{
	if (reg == NULL)
		return;
	kmem_free(reg, sizeof (i2c_mux_register_t));
}

static void
i2c_mux_free(i2c_mux_t *mux)
{
	i2cnex_nex_free(mux->im_nex);
	mux->im_nex = NULL;

	kmem_free(mux, sizeof (i2c_mux_t));
}

i2c_mux_reg_error_t
i2c_mux_register_alloc(uint32_t vers, i2c_mux_register_t **regp)
{
	i2c_mux_register_t *reg;

	if (vers != I2C_MUX_PROVIDER_V0) {
		return (I2C_MUX_REG_E_BAD_VERS);
	}

	reg = kmem_zalloc(sizeof (i2c_mux_register_t), KM_SLEEP);
	reg->mr_vers = I2C_MUX_PROVIDER_V0;
	*regp = reg;
	return (I2C_MUX_REG_E_OK);
}

/*
 * To unregister a mux, we must verify that the corresponding mux is no longer
 * attached.
 */
i2c_mux_reg_error_t
i2c_mux_unregister(i2c_mux_hdl_t *hdl)
{
	if (hdl == NULL) {
		return (I2C_MUX_REG_E_OK);
	}

	i2c_mux_t *mux = (i2c_mux_t *)hdl;
	i2c_nexus_t *pnex = mux->im_nex->in_pnex;
	VERIFY3U(pnex->in_type, ==, I2C_NEXUS_T_DEV);
	i2c_dev_t *dev = pnex->in_data.in_dev;
	VERIFY3P(dev->id_mux, ==, mux);
	i2c_ctrl_t *ctrl = mux->im_nex->in_ctrl;

	/*
	 * Enter the parent and take a controller lock so we can verify that the
	 * device is gone.
	 */
	ndi_devi_enter(dev->id_nex->in_dip);
	i2c_txn_t *txn = i2c_txn_alloc(ctrl, I2C_LOCK_TAG_MUX_UNREG, mux);
	if (i2c_txn_ctrl_lock(txn, true) != I2C_CORE_E_OK) {
		i2c_txn_free(txn);
		ndi_devi_exit(dev->id_nex->in_dip);
		return (I2C_MUX_REG_E_NEXUS);
	}

	if (mux->im_nex->in_dip != NULL) {
		i2c_txn_free(txn);
		ndi_devi_exit(dev->id_nex->in_dip);
		return (I2C_MUX_REG_E_BUSY);
	}

	dev->id_mux = NULL;
	i2c_txn_ctrl_unlock(txn);
	i2c_txn_free(txn);
	ndi_devi_exit(dev->id_nex->in_dip);

	i2cnex_nex_free(mux->im_nex);
	kmem_free(mux, sizeof (i2c_mux_t));
	return (I2C_MUX_REG_E_OK);
}

/*
 * The current i2c_mux_register() design assumes that the calling thread
 * basically can assert the liveness of the passed in dev_info_t. This usually
 * holds as this is only expected to be called by a driver from either
 * attach(9E) or some other character / device operation which guarantees
 * there's a hold on its dev_info_t.
 */
i2c_mux_reg_error_t
i2c_mux_register(const i2c_mux_register_t *reg, i2c_mux_hdl_t **muxp)
{
	i2c_mux_reg_error_t err;
	char name[I2C_NAME_MAX];

	if (reg->mr_vers != I2C_MUX_PROVIDER_V0) {
		return (I2C_MUX_REG_E_BAD_VERS);
	}

	if (reg->mr_nports == 0 || reg->mr_nports > I2C_MAX_PORTS) {
		return (I2C_MUX_REG_E_BAD_PORTS);
	}

	if (reg->mr_dip == NULL) {
		return (I2C_MUX_REG_E_BAD_DEVI);
	}

	if (devopsp[ddi_driver_major(reg->mr_dip)]->devo_bus_ops !=
	    &i2c_nex_bus_ops) {
		return (I2C_MUX_REG_E_BAD_DEVI_BUS);
	}

	if (reg->mr_ops == NULL ||
	    reg->mr_ops->mux_port_name_f == NULL ||
	    reg->mr_ops->mux_port_enable_f == NULL ||
	    reg->mr_ops->mux_port_disable_f == NULL) {
		return (I2C_MUX_REG_E_BAD_OPS);
	}

	if (snprintf(name, sizeof (name), "%s%d", ddi_driver_name(reg->mr_dip),
	    ddi_get_instance(reg->mr_dip)) >= sizeof (name)) {
		return (I2C_MUX_REG_E_NEXUS);
	}

	/*
	 * Currently, we only support a single in-band mux being enumerated
	 * under a child and assume that this is tied to an i2c device. This
	 * will need to change at some point in the future when we want to
	 * control analog muxes via GPIOs or other interfaces. Until we know
	 * what that looks like, we don't want to assume this one way or the
	 * other. See the definition of struct i2c_mux for more musings on this.
	 */
	if (!i2c_dip_is_dev(reg->mr_dip)) {
		return (I2C_MUX_REG_E_UNSUP_DEVI);
	}

	i2c_nexus_t *nex = i2c_dev_to_nexus(reg->mr_dip);
	i2c_dev_t *dev = nex->in_data.in_dev;
	i2c_ctrl_t *ctrl = nex->in_ctrl;
	i2c_txn_t *txn = i2c_txn_alloc(ctrl, I2C_LOCK_TAG_MUX_REG, reg->mr_dip);
	if (i2c_txn_ctrl_lock(txn, true) != I2C_CORE_E_OK) {
		i2c_txn_free(txn);
		return (I2C_MUX_REG_E_NEXUS);
	}

	if (dev->id_mux != NULL) {
		err = I2C_MUX_REG_E_EXISTS;
		goto out;
	}

	i2c_mux_t *mux = kmem_zalloc(sizeof (i2c_mux_t), KM_SLEEP);
	mux->im_drv = reg->mr_drv;
	mux->im_ops = reg->mr_ops;
	mux->im_nports = reg->mr_nports;
	mux->im_curport = I2C_MUX_PORT_NONE;
	mux->im_nex = i2cnex_nex_alloc(I2C_NEXUS_T_MUX, nex->in_dip, nex, NULL,
	    name, ctrl);
	if (mux->im_nex == NULL) {
		i2c_mux_free(mux);
		err = I2C_MUX_REG_E_NEXUS;
		goto out;
	}
	mux->im_nex->in_data.in_mux = mux;

	dev->id_mux = mux;
	*muxp = (i2c_mux_hdl_t *)mux;
	err = I2C_MUX_REG_E_OK;

out:
	i2c_txn_ctrl_unlock(txn);
	i2c_txn_free(txn);
	return (err);
}

/*
 * These pair of functions are convenience functions for drivers where they
 * basically have zero or one indexed port names.
 */
bool
i2c_mux_port_name_portno(void *drv, uint32_t port, char *buf, size_t buflen)
{
	return (snprintf(buf, buflen, "%u", port) < sizeof (buf));
}

bool
i2c_mux_port_name_portno_1s(void *drv, uint32_t port, char *buf, size_t buflen)
{
	VERIFY3U(port, !=, UINT32_MAX);
	return (snprintf(buf, buflen, "%u", port + 1) < sizeof (buf));
}

static bool
i2c_mux_select_build_list(i2c_port_t *port, void *arg)
{
	i2c_ctrl_t *ctrl = arg;

	VERIFY0(list_link_active(&port->ip_ctrl_link));
	list_insert_head(&ctrl->ic_mux_plan, port);
	return (true);
}

/*
 * We've been asked to deactivate the current set of ports until we reach the
 * one named. The one named may not be in the current list at all.
 */
static bool
i2c_mux_deselect(i2c_txn_t *txn, i2c_ctrl_t *ctrl, i2c_port_t *targ,
    i2c_error_t *errp)
{
	i2c_port_t *port;

	VERIFY(i2c_txn_held(txn));
	VERIFY3P(txn->txn_ctrl, ==, ctrl);

	while ((port = list_tail(&ctrl->ic_mux_active)) != NULL) {
		if (port == targ) {
			return (true);
		}

		if (port->ip_nex->in_pnex->in_type == I2C_NEXUS_T_MUX) {
			i2c_mux_t *mux = port->ip_nex->in_pnex->in_data.in_mux;
			if (!mux->im_ops->mux_port_disable_f(mux->im_drv, txn,
			    I2C_MUX_PORT_ALL, 0, errp)) {
				return (false);
			}

			mux->im_curport = I2C_MUX_PORT_NONE;
		}

		list_remove(&ctrl->ic_mux_active, port);
	}

	return (true);
}

/*
 * We've been asked to change the currently active port. This may mean that
 * muxes need to change. First, we see if the current port is active or not. If
 * it is, then we simply pop off the tail, disabling entries until we reach the
 * target port. Otherwise, we remove everything.
 */
bool
i2c_mux_update(i2c_txn_t *txn, i2c_ctrl_t *ctrl, i2c_port_t *port,
    i2c_error_t *errp)
{
	VERIFY(i2c_txn_held(txn));
	VERIFY3P(txn->txn_ctrl, ==, ctrl);

	/*
	 * First see if we're already in progress performing some mux operation.
	 * We can end up back here again and need to handle that appropriately.
	 */
	switch (ctrl->ic_mux_state) {
	case I2C_CTRL_MA_DESELECT:
		/*
		 * If we're deselecting something, then this port should already
		 * be active in the list and therefore there is nothing we need
		 * to do.
		 */
		VERIFY3U(list_link_active(&port->ip_ctrl_link), !=, 0);
#ifdef	DEBUG
		{
			i2c_port_t *check = list_tail(&ctrl->ic_mux_active);
			ASSERT3U(check->ip_nex->in_pnex->in_type, ==,
			    I2C_NEXUS_T_MUX);
			ASSERT3P(list_prev(&ctrl->ic_mux_active, check), ==,
			    port);
		}
#endif	/* DEBUG */
		return (true);
	case I2C_CTRL_MA_UPDATE:
		/*
		 * We got back here where we're performing an update. The only
		 * legal case is that the port we're trying to select is active
		 * in the tree and is the last entry in the list.
		 */
		VERIFY3P(list_tail(&ctrl->ic_mux_active), ==, port);
		return (true);
	case I2C_CTRL_MA_NONE:
		break;
	}

	ctrl->ic_mux_state = I2C_CTRL_MA_DESELECT;
	bool ret = i2c_mux_deselect(txn, ctrl, port, errp);
	ctrl->ic_mux_state = I2C_CTRL_MA_NONE;

	if (!ret) {
		return (false);
	}

	if (list_link_active(&port->ip_ctrl_link)) {
		VERIFY3P(list_tail(&ctrl->ic_mux_active), ==, port);
		return (true);
	}

	/*
	 * We need to build up the list of ports that need to be activated.
	 * First we walk up the tree to build the list of ports that we need to
	 * care about. Then we walk it from the head down to the tail,
	 * performing all activations.
	 */
	VERIFY(list_is_empty(&ctrl->ic_mux_plan));

	list_insert_tail(&ctrl->ic_mux_plan, port);
	i2c_port_parent_iter(port, i2c_mux_select_build_list, ctrl);
	ctrl->ic_mux_state = I2C_CTRL_MA_UPDATE;

	/*
	 * Walk each port and activate it if required. We do not add the port to
	 * the active list until we have successfully set the mux.
	 */
	while ((port = list_remove_head(&ctrl->ic_mux_plan)) != NULL) {

		/*
		 * This isn't a mux. Simply add it and we're done.
		 */
		if (port->ip_nex->in_pnex->in_type != I2C_NEXUS_T_MUX) {
			list_insert_tail(&ctrl->ic_mux_active, port);
			continue;
		}

		/*
		 * Attempt to set the mux. If this fails, we must undo
		 * everything and clear out the rest of the plan.
		 */
		i2c_mux_t *mux = port->ip_nex->in_pnex->in_data.in_mux;
		if (!mux->im_ops->mux_port_enable_f(mux->im_drv, txn,
		    port->ip_portno, 0, errp)) {
			ctrl->ic_mux_state = I2C_CTRL_MA_NONE;
			while (list_remove_head(&ctrl->ic_mux_plan) != NULL)
				;
			return (false);
		}

		mux->im_curport = port->ip_portno;
		list_insert_tail(&ctrl->ic_mux_active, port);
	}

	ctrl->ic_mux_state = I2C_CTRL_MA_NONE;
	return (true);
}

/*
 * This is called by the detach methods of a controller or a mux when it is
 * being torn down. The port in question may or may not be currently used by the
 * controller. We need to check and verify if it is and if so clean up. If
 * something that we're removing is actually active, then it should only be the
 * last element otherwise we're in trouble and something has gone wrong as a
 * port shouldn't be able to be removed if its children are still valid.
 */
void
i2c_mux_remove_port(i2c_txn_t *txn, i2c_ctrl_t *ctrl, i2c_port_t *port)
{
	VERIFY(i2c_txn_held(txn));
	VERIFY3P(txn->txn_ctrl, ==, ctrl);
	VERIFY3U(ctrl->ic_mux_state, ==, I2C_CTRL_MA_NONE);

	/*
	 * If our link on the list is not active, then there's nothing to be
	 * done.
	 */
	if (list_link_active(&port->ip_ctrl_link) == 0)
		return;

	VERIFY3P(list_tail(&ctrl->ic_mux_active), ==, port);
	list_remove(&ctrl->ic_mux_active, port);
}
