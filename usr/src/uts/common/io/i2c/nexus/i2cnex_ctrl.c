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
 * Portions of the i2c nexus that directly interface with the parent controller
 * that we create.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/stddef.h>
#include <sys/mkdev.h>
#include <sys/ctype.h>

#include "i2cnex.h"

/*
 * These are kept as non-static const values so that they can be tuned. This is
 * not a committed interface and if we need to, these timeout values should
 * instead be transformed into standard framework properties.
 *
 * We have selected a 100ms wait for the bus to be free. This is greater than
 * the time that sending 512 bytes should take at 100 kHz. At 100 kHz, you can
 * send 1 bit in 10us, or a byte in 80 us. To send 512 bytes (the largest I/O we
 * do in one go), is 40.96 ms. Doubling that gets us to 100ms.
 *
 * For an entire I/O operation, we increase that to 500ms for now to give device
 * drivers and other things a bit of leeway. This should be refined in the
 * future. For an abort, we increase that to 1s.
 *
 * For polling, we use this minimal time of 15us. This value means 1 bit will be
 * transferred, which usually isn't enough time at 100 kHz, but does a bit
 * better at faster speeds. Some controllers also wait for say an empty status
 * to be set to determine if they even do anything.
 *
 * These could be dependent on the controller's actual speed in the future.
 */
uint32_t i2c_ctrl_to_bus_act_count = 100;
uint32_t i2c_ctrl_to_bus_act_delay_us = 1000;

uint32_t i2c_ctrl_to_io_count = 1;
uint32_t i2c_ctrl_to_io_delay_us = 500 * (MICROSEC / MILLISEC);

uint32_t i2c_ctrl_to_abort_count = 1;
uint32_t i2c_ctrl_to_abort_delay_us = 1000 * (MICROSEC / MILLISEC);

uint32_t i2c_ctrl_to_poll_ctrl_count = 1;
uint32_t i2c_ctrl_to_poll_ctrl_delay_us = 15;

static int
i2c_nex_ctrl_bus_config(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **childp)
{
	i2c_nex_bus_config_t conf;
	i2c_root_t *root = i2c_dip_to_root(pdip);

	if (root == NULL) {
		return (NDI_BADHANDLE);
	}

	switch (op) {
	case BUS_CONFIG_ONE:
	case BUS_CONFIG_ALL:
	case BUS_CONFIG_DRIVER:
		ndi_devi_enter(pdip);
		break;
	default:
		return (NDI_FAILURE);
	}

	if (!i2c_nex_bus_config_init(&conf, op, arg)) {
		ndi_devi_exit(pdip);
		return (NDI_EINVAL);
	}
	mutex_enter(&root->ir_mutex);
	for (i2c_ctrl_t *ctrl = list_head(&root->ir_ctrls); ctrl != NULL;
	    ctrl = list_next(&root->ir_ctrls, ctrl)) {
		i2c_nex_bus_config_one(ctrl->ic_nexus, &conf);
	}
	mutex_exit(&root->ir_mutex);
	i2c_nex_bus_config_fini(&conf);
	ndi_devi_exit(pdip);

	if (op == BUS_CONFIG_ONE) {
		if (!conf.inbc_matched) {
			return (NDI_EINVAL);
		}

		if (conf.inbc_ret != NDI_SUCCESS) {
			return (conf.inbc_ret);
		}
	}

	flags |= NDI_ONLINE_ATTACH;
	return (ndi_busop_bus_config(pdip, flags, op, arg, childp, 0));
}

static int
i2c_nex_ctrl_bus_unconfig(dev_info_t *pdip, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	int ret;
	i2c_nex_bus_config_t conf;
	i2c_root_t *root = i2c_dip_to_root(pdip);

	if (root == NULL) {
		return (NDI_BADHANDLE);
	}

	switch (op) {
	case BUS_UNCONFIG_ONE:
	case BUS_UNCONFIG_ALL:
	case BUS_UNCONFIG_DRIVER:
		ndi_devi_enter(pdip);
		flags |= NDI_UNCONFIG;
		ret = ndi_busop_bus_unconfig(pdip, flags, op, arg);
		if (ret != 0) {
			ndi_devi_exit(pdip);
			return (ret);
		}
		break;
	default:
		return (NDI_FAILURE);
	}

	if (!i2c_nex_bus_config_init(&conf, op, arg)) {
		ndi_devi_exit(pdip);
		return (NDI_EINVAL);
	}

	mutex_enter(&root->ir_mutex);
	for (i2c_ctrl_t *ctrl = list_head(&root->ir_ctrls); ctrl != NULL;
	    ctrl = list_next(&root->ir_ctrls, ctrl)) {
		i2c_nex_bus_unconfig_one(ctrl->ic_nexus, &conf);
	}
	mutex_exit(&root->ir_mutex);
	i2c_nex_bus_config_fini(&conf);
	ndi_devi_exit(pdip);

	if (op == BUS_CONFIG_ONE) {

		if (!conf.inbc_matched) {
			return (NDI_EINVAL);
		}

		if (conf.inbc_ret != NDI_SUCCESS) {
			return (conf.inbc_ret);
		}
	}

	return (NDI_SUCCESS);
}

/*
 * The controller's bus ops need to generally call into the parent for all DMA
 * activity. The main things that we need to define here are the bus_ctl,
 * bus_config, and bus_unconfig.
 */
static struct bus_ops i2c_nex_ctrl_bus_ops = {
	.busops_rev = BUSO_REV,
	.bus_dma_map = ddi_no_dma_map,
	.bus_dma_allochdl = ddi_dma_allochdl,
	.bus_dma_freehdl = ddi_dma_freehdl,
	.bus_dma_bindhdl = ddi_dma_bindhdl,
	.bus_dma_unbindhdl = ddi_dma_unbindhdl,
	.bus_dma_flush = ddi_dma_flush,
	.bus_dma_win = ddi_dma_win,
	.bus_dma_ctl = ddi_dma_mctl,
	.bus_prop_op = ddi_bus_prop_op,
	.bus_ctl = i2c_nex_bus_ctl,
	.bus_config = i2c_nex_ctrl_bus_config,
	.bus_unconfig = i2c_nex_ctrl_bus_unconfig
};

void
i2c_ctrl_mod_fini(struct dev_ops *ops)
{
	ops->devo_bus_ops = NULL;
}

void
i2c_ctrl_mod_init(struct dev_ops *ops)
{
	ops->devo_bus_ops = &i2c_nex_ctrl_bus_ops;
}

void
i2c_ctrl_register_free(i2c_ctrl_register_t *reg)
{
	if (reg == NULL)
		return;
	kmem_free(reg, sizeof (i2c_ctrl_register_t));
}

i2c_ctrl_reg_error_t
i2c_ctrl_register_alloc(uint32_t vers, i2c_ctrl_register_t **regp)
{
	i2c_ctrl_register_t *reg;

	if (vers != I2C_CTRL_PROVIDER_V0) {
		return (I2C_CTRL_REG_E_BAD_VERS);
	}

	reg = kmem_zalloc(sizeof (i2c_ctrl_register_t), KM_SLEEP);
	reg->ic_vers = I2C_CTRL_PROVIDER_V0;

	*regp = reg;
	return (I2C_CTRL_REG_E_OK);
}

static void
i2c_ctrl_lock_fini(i2c_ctrl_lock_t *lock)
{
	VERIFY3P(lock->cl_owner, ==, NULL);
	VERIFY3U(list_is_empty(&lock->cl_stack), !=, 0);
	VERIFY3U(list_is_empty(&lock->cl_waiters), !=, 0);

	list_destroy(&lock->cl_stack);
	list_destroy(&lock->cl_waiters);
	mutex_destroy(&lock->cl_mutex);
}

static void
i2c_ctrl_lock_init(i2c_ctrl_lock_t *lock)
{
	mutex_init(&lock->cl_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&lock->cl_waiters, sizeof (i2c_txn_t),
	    offsetof(i2c_txn_t, txn_wait_link));
	list_create(&lock->cl_stack, sizeof (i2c_txn_t),
	    offsetof(i2c_txn_t, txn_stack_link));
}

/*
 * Port cleanup is part of the actual attach/detach of the i2cnex. We don't do
 * that in register/unregister.
 */
static void
i2c_ctrl_cleanup(i2c_ctrl_t *ctrl)
{
	i2cnex_nex_free(ctrl->ic_nexus);
	ctrl->ic_nexus = NULL;

	mutex_destroy(&ctrl->ic_txn_lock);
	list_destroy(&ctrl->ic_txns);

	/*
	 * As this is tearing down, we may need to remove any remnants of a plan
	 * or active mux.
	 */
	while (list_remove_head(&ctrl->ic_mux_plan) != NULL)
		;
	while (list_remove_head(&ctrl->ic_mux_active) != NULL)
		;

	list_destroy(&ctrl->ic_mux_plan);
	list_destroy(&ctrl->ic_mux_active);
	i2c_ctrl_lock_fini(&ctrl->ic_lock);
	kmem_free(ctrl, sizeof (i2c_ctrl_t));
}

i2c_ctrl_reg_error_t
i2c_ctrl_unregister(i2c_ctrl_hdl_t *hdl)
{
	i2c_ctrl_t *ctrl;
	i2c_root_t *root;

	if (hdl == NULL) {
		return (I2C_CTRL_REG_E_OK);
	}

	ctrl = (i2c_ctrl_t *)hdl;

	/*
	 * If we made it here, by definition we have no children and there are
	 * no open file descriptors on the controller. Therefore it should be
	 * safe to allow this to be torn down.
	 */

	root = ctrl->ic_root;

	mutex_enter(&i2cnex_minors.im_mutex);
	mutex_enter(&root->ir_mutex);
	list_remove(&ctrl->ic_root->ir_ctrls, ctrl);
	ctrl->ic_root = NULL;

	/*
	 * If this was the last controller that was present here, then we need
	 * to clean up the root entry potentially. If we are the last one,
	 * because we hold the globals lock, then there's no way anyone else can
	 * find this and we are the last mapping to it.
	 */
	bool fini = list_is_empty(&root->ir_ctrls) != 0;
	mutex_exit(&root->ir_mutex);

	/*
	 * By definition we had the last hold on this root therefore it's safe
	 * for us to have dropped the lock above and do the rest of the cleanup
	 * that's required.
	 */
	if (fini) {
		i2c_root_fini(root);
	}
	mutex_exit(&i2cnex_minors.im_mutex);

	i2c_ctrl_cleanup(ctrl);
	return (I2C_CTRL_REG_E_OK);
}

/*
 * Ask the controller for its various limits and supported ops. An I2C
 * controller and SMBus controller have optional and required limit properies.
 *
 * I2C_PROP_MAX_READ and I2C_PROP_MAX_WRITE:
 *  - required for I2C
 *  - optional for SMBus, queried if an I2C I/O op or I2C SMBus op present.
 *    Defaults to the value of SMBUS_PROP_BLOCK_SIZE.
 *
 * SMBUS_PROP_SUP_OPS and SMBUS_PROP_BLOCK_SIZE:
 *  - optional for I2C, but required if an SMBus I/O op specified
 *  - required for SMBus
 */
static i2c_ctrl_reg_error_t
i2c_ctrl_init_limits(i2c_ctrl_t *ctrl)
{
	bool smbus = ctrl->ic_type == I2C_CTRL_TYPE_SMBUS;
	dev_info_t *dip = ctrl->ic_nexus->in_pdip;
	const smbus_prop_op_t i2c_block = SMBUS_PROP_OP_I2C_WRITE_BLOCK |
	    SMBUS_PROP_OP_I2C_READ_BLOCK;

	if (ctrl->ic_ops->i2c_io_smbus_f != NULL) {
		i2c_error_t err;
		uint32_t len = sizeof (uint32_t);
		if (!i2c_prop_get(ctrl, SMBUS_PROP_SUP_OPS,
		    &ctrl->ic_limit.lim_smbus_ops, &len, &err)) {
			dev_err(dip, CE_WARN, "failed to get property %s: "
			    "0x%x/0x%x", i2c_prop_name(SMBUS_PROP_SUP_OPS),
			    err.i2c_error, err.i2c_ctrl);
			return (I2C_CTRL_REG_E_REQ_PROP);
		}

		VERIFY3U(len, ==, sizeof (uint32_t));
		if (ctrl->ic_limit.lim_smbus_ops == 0) {
			dev_err(dip, CE_WARN, "controller cannot specify "
			    "support for no SMBus ops");
			return (I2C_CTLR_REG_E_BAD_PROP_VAL);
		}

		len = sizeof (uint32_t);
		if (!i2c_prop_get(ctrl, SMBUS_PROP_MAX_BLOCK,
		    &ctrl->ic_limit.lim_smbus_block, &len, &err)) {
			dev_err(dip, CE_WARN, "failed to get property %s: "
			    "0x%x/0x%x", i2c_prop_name(SMBUS_PROP_MAX_BLOCK),
			    err.i2c_error, err.i2c_ctrl);
			return (I2C_CTRL_REG_E_REQ_PROP);
		}

		VERIFY3U(len, ==, sizeof (uint32_t));
		if (ctrl->ic_limit.lim_smbus_block < SMBUS_V2_MAX_BLOCK ||
		    ctrl->ic_limit.lim_smbus_block > SMBUS_V3_MAX_BLOCK) {
			dev_err(dip, CE_WARN, "unsupported SMBus maximum "
			    "block size: %u", ctrl->ic_limit.lim_smbus_block);
			return (I2C_CTLR_REG_E_BAD_PROP_VAL);
		}
	}

	if (ctrl->ic_ops->i2c_io_i2c_f != NULL ||
	    (ctrl->ic_limit.lim_smbus_ops & i2c_block) != 0) {
		i2c_error_t err;
		uint32_t len = sizeof (uint32_t);
		if (!i2c_prop_get(ctrl, I2C_PROP_MAX_READ,
		    &ctrl->ic_limit.lim_i2c_read, &len, &err)) {
			if (smbus && err.i2c_error == I2C_PROP_E_UNSUP) {
				ctrl->ic_limit.lim_i2c_read =
				    ctrl->ic_limit.lim_smbus_block;
			} else {
				dev_err(dip, CE_WARN, "failed to get property "
				    "%s: 0x%x/0x%x",
				    i2c_prop_name(I2C_PROP_MAX_READ),
				    err.i2c_error, err.i2c_ctrl);
				return (I2C_CTRL_REG_E_REQ_PROP);
			}
		}

		VERIFY3U(len, ==, sizeof (uint32_t));
		if (ctrl->ic_limit.lim_i2c_read == 0 ||
		    ctrl->ic_limit.lim_i2c_read > I2C_REQ_MAX) {
			dev_err(dip, CE_WARN, "unsupported %s value",
			    i2c_prop_name(I2C_PROP_MAX_READ));
			return (I2C_CTLR_REG_E_BAD_PROP_VAL);
		}

		len = sizeof (uint32_t);
		if (!i2c_prop_get(ctrl, I2C_PROP_MAX_WRITE,
		    &ctrl->ic_limit.lim_i2c_write, &len, &err)) {
			if (smbus && err.i2c_error == I2C_PROP_E_UNSUP) {
				ctrl->ic_limit.lim_i2c_write =
				    ctrl->ic_limit.lim_smbus_block;
			} else {
				dev_err(dip, CE_WARN, "failed to get property "
				    "%s: 0x%x/0x%x",
				    i2c_prop_name(I2C_PROP_MAX_WRITE),
				    err.i2c_error, err.i2c_ctrl);
				return (I2C_CTRL_REG_E_REQ_PROP);
			}
		}

		VERIFY3U(len, ==, sizeof (uint32_t));
		if (ctrl->ic_limit.lim_i2c_write == 0 ||
		    ctrl->ic_limit.lim_i2c_write > I2C_REQ_MAX) {
			dev_err(dip, CE_WARN, "unsupported %s value",
			    i2c_prop_name(I2C_PROP_MAX_WRITE));
			return (I2C_CTLR_REG_E_BAD_PROP_VAL);
		}
	}

	return (I2C_CTRL_REG_E_OK);
}

i2c_ctrl_reg_error_t
i2c_ctrl_register(const i2c_ctrl_register_t *reg, i2c_ctrl_hdl_t **hdlp)
{
	i2c_ctrl_t *ctrl;
	char name[I2C_NAME_MAX];
	const char *namep;

	if (reg == NULL || hdlp == NULL) {
		return (I2C_CTRL_REG_E_NULL_ARG);
	}

	if (reg->ic_vers != I2C_CTRL_PROVIDER_V0) {
		return (I2C_CTRL_REG_E_BAD_VERS);
	}

	if (reg->ic_ops == NULL) {
		return (I2C_CTRL_REG_E_BAD_OPS);
	}

	if (reg->ic_ops->i2c_port_name_f == NULL) {
		return (I2C_CTRL_REG_E_NEED_PORT_NAME_FUNC);
	}

	if (reg->ic_ops->i2c_prop_info_f == NULL) {
		return (I2C_CTRL_REG_E_NEED_PROP_INFO_FUNC);
	}

	if (reg->ic_ops->i2c_prop_get_f == NULL) {
		return (I2C_CTRL_REG_E_NEED_PROP_GET_FUNC);
	}

	switch (reg->ic_type) {
	case I2C_CTRL_TYPE_I2C:
		if (reg->ic_ops->i2c_io_i2c_f == NULL) {
			return (EINVAL);
		}
		break;
	case I2C_CTRL_TYPE_SMBUS:
		if (reg->ic_ops->i2c_io_smbus_f == NULL) {
			return (EINVAL);
		}
		break;
	case I2C_CTRL_TYPE_I3C:
		return (I2C_CTRL_REG_E_UNSUP_CTRL_TYPE);
	default:
		return (I2C_CTRL_REG_E_BAD_CTRL_TYPE);
	}

	if (reg->ic_dip == NULL) {
		return (I2C_CTRL_REG_E_BAD_DIP);
	}

	if (reg->ic_nports == 0 || reg->ic_nports > I2C_MAX_PORTS) {
		return (I2C_CTRL_REG_E_BAD_NPORTS);
	}

	if (reg->ic_name != NULL) {
		size_t len = strnlen(reg->ic_name, I2C_NAME_MAX);

		if (len >= I2C_NAME_MAX) {
			return (I2C_CTRL_REG_E_BAD_NAME);
		}

		if (len == 0 || reg->ic_name[len] != '\0') {
			return (I2C_CTRL_REG_E_BAD_NAME);
		}

		for (size_t i = 0; i < len; i++) {
			if (!ISALNUM(reg->ic_name[i])) {
				return (I2C_CTRL_REG_E_BAD_NAME);
			}
		}
		namep = reg->ic_name;
	} else {
		if (snprintf(name, sizeof (name), "%s%d",
		    ddi_driver_name(reg->ic_dip),
		    ddi_get_instance(reg->ic_dip)) >= sizeof (name)) {
			return (I2C_CTRL_REG_E_INTERNAL);
		}

		namep = name;
	}

	if (devopsp[ddi_driver_major(reg->ic_dip)]->devo_bus_ops !=
	    &i2c_nex_ctrl_bus_ops) {
		return (I2C_CTRL_REG_E_BAD_MOD_TYPE);
	}

	/*
	 * Now that everything has been validated, attempt to create the
	 * controller and the nexus information.
	 */
	ctrl = kmem_zalloc(sizeof (i2c_ctrl_t), KM_SLEEP);
	i2c_ctrl_lock_init(&ctrl->ic_lock);
	list_create(&ctrl->ic_mux_plan, sizeof (i2c_port_t),
	    offsetof(i2c_port_t, ip_ctrl_link));
	list_create(&ctrl->ic_mux_active, sizeof (i2c_port_t),
	    offsetof(i2c_port_t, ip_ctrl_link));
	list_create(&ctrl->ic_txns, sizeof (i2c_txn_t),
	    offsetof(i2c_txn_t, txn_link));
	mutex_init(&ctrl->ic_txn_lock, NULL, MUTEX_DRIVER, NULL);
	ctrl->ic_drv = reg->ic_drv;
	ctrl->ic_ops = reg->ic_ops;
	ctrl->ic_type = reg->ic_type;
	ctrl->ic_nexus = i2cnex_nex_alloc(I2C_NEXUS_T_CTRL, reg->ic_dip, NULL,
	    NULL, namep, ctrl);
	if (ctrl->ic_nexus == NULL) {
		i2c_ctrl_cleanup(ctrl);
		return (I2C_CTRL_REG_E_NEXUS);
	}

	/*
	 * Verify we can get the various limit properties that we expect.
	 */
	i2c_ctrl_reg_error_t ret = i2c_ctrl_init_limits(ctrl);
	if (ret != I2C_CTRL_REG_E_OK) {
		i2c_ctrl_cleanup(ctrl);
		return (ret);
	}

	ctrl->ic_nports = reg->ic_nports;
	i2c_root_t *root = i2c_root_init(reg->ic_dip);

	/*
	 * We currently require global uniqueness for controller names otherwise
	 * userland is going to have a very bad day.
	 */
	mutex_enter(&root->ir_mutex);
	for (i2c_ctrl_t *c = list_head(&root->ir_ctrls); c != NULL;
	    c = list_next(&root->ir_ctrls, c)) {
		if (bcmp(c->ic_nexus->in_addr, ctrl->ic_nexus->in_addr,
		    sizeof (c->ic_nexus->in_addr)) == 0) {
			i2c_ctrl_cleanup(ctrl);
			return (I2C_CTRL_REG_E_NOT_UNIQUE);
		}
	}

	ctrl->ic_root = root;
	list_insert_tail(&root->ir_ctrls, ctrl);
	mutex_exit(&root->ir_mutex);

	*hdlp = (i2c_ctrl_hdl_t *)ctrl;
	return (0);
}

/*
 * The timeout count and delay in hertz functions are used to allow controllers
 * to query values to use. Currently these are just globals in the i2c nexus;
 * however, we don't want drivers to encode their own and this gives us a future
 * path where this can be a tunable on a per-controller basis. Right now the
 * controller arguments are unused, but are here to make it easier to adjust to
 * that possible future.
 */
uint32_t
i2c_ctrl_timeout_count(i2c_ctrl_hdl_t *hdl, i2c_ctrl_timeout_t to)
{
	switch (to) {
	case I2C_CTRL_TO_IO:
		return (i2c_ctrl_to_io_count);
	case I2C_CTRL_TO_ABORT:
		return (i2c_ctrl_to_abort_count);
	case I2C_CTRL_TO_POLL_CTRL:
		return (i2c_ctrl_to_poll_ctrl_count);
	case I2C_CTRL_TO_BUS_ACT:
		return (i2c_ctrl_to_bus_act_count);
	default:
		panic("programmer error: requested invalid timeout 0x%x", to);
	}
}

uint32_t
i2c_ctrl_timeout_delay_us(i2c_ctrl_hdl_t *hdl, i2c_ctrl_timeout_t to)
{
	switch (to) {
	case I2C_CTRL_TO_IO:
		return (i2c_ctrl_to_io_delay_us);
	case I2C_CTRL_TO_ABORT:
		return (i2c_ctrl_to_abort_delay_us);
	case I2C_CTRL_TO_POLL_CTRL:
		return (i2c_ctrl_to_poll_ctrl_delay_us);
	case I2C_CTRL_TO_BUS_ACT:
		return (i2c_ctrl_to_bus_act_delay_us);
	default:
		panic("programmer error: requested invalid timeout 0x%x", to);
	}
}

/*
 * Translate a write-only request. We try to stick to SMBus 2.0 class requests
 * for the time being that we expect most devices to be able to implement. For
 * pure writes we can write up to the SMBus 2.0 max request size plus 1 bytes.
 * In other words 33. Requests of up to 3 bytes will use the standard operations
 * while others will need to use the I2C block write operation.
 */
static bool
i2c_ctrl_io_i2c_xlate_wo(i2c_ctrl_t *ctrl, const i2c_req_t *req,
    smbus_req_t *smbus)
{
	if (req->ir_wlen == 1) {
		smbus->smbr_op = SMBUS_OP_SEND_BYTE;
		smbus->smbr_wdata[0] = req->ir_wdata[0];
		return (true);
	}

	if (req->ir_wlen == 2) {
		smbus->smbr_op = SMBUS_OP_WRITE_BYTE;
		smbus->smbr_cmd = req->ir_wdata[0];
		smbus->smbr_wdata[0] = req->ir_wdata[1];
		return (true);
	}

	if (req->ir_wlen == 3) {
		smbus->smbr_op = SMBUS_OP_WRITE_WORD;
		smbus->smbr_cmd = req->ir_wdata[0];
		smbus->smbr_wdata[0] = req->ir_wdata[1];
		smbus->smbr_wdata[1] = req->ir_wdata[2];
		return (true);
	}

	/*
	 * The SMBus controller maximum block size does not include the command
	 * code that is sent, hence the +1 below.
	 */
	if (req->ir_wlen > ctrl->ic_limit.lim_smbus_block + 1) {
		return (false);
	}

	smbus->smbr_op = SMBUS_OP_I2C_WRITE_BLOCK;
	smbus->smbr_cmd = req->ir_wdata[0];
	bcopy(req->ir_wdata + 1, smbus->smbr_wdata, req->ir_wlen - 1);
	return (true);
}

/*
 * The only read-only request that doesn't require a repeated start for SMBus is
 * a single byte read. All other reads want to write a command in the form of a
 * repeated start. Sorry I2C.
 */
static bool
i2c_ctrl_io_i2c_xlate_ro(const i2c_req_t *req, smbus_req_t *smbus)
{
	if (req->ir_rlen == 1) {
		smbus->smbr_op = SMBUS_OP_RECV_BYTE;
		return (true);
	}

	return (false);
}

/*
 * We have a mixed read/write request. There are still limitations here. We can
 * easily translate a single byte write into an SMBus command code, allowing us
 * to get a wide variety of read lengths here. However, if we are writing more
 * than one byte, then need to perform a fixed size read, the only way we can do
 * that is with a procedure call which requires a three byte write to do a two
 * byte read.
 */
static bool
i2c_ctrl_io_i2c_xlate_rw(i2c_ctrl_t *ctrl, const i2c_req_t *req,
    smbus_req_t *smbus)
{
	if (req->ir_wlen == 3 && req->ir_rlen == 2) {
		smbus->smbr_op = SMBUS_OP_PROCESS_CALL;
		smbus->smbr_cmd = req->ir_wdata[0];
		smbus->smbr_wdata[0] = req->ir_wdata[1];
		smbus->smbr_wdata[1] = req->ir_wdata[2];
	} else if (req->ir_wlen != 1) {
		return (false);
	}

	smbus->smbr_cmd = req->ir_wdata[0];
	if (req->ir_rlen == 1) {
		smbus->smbr_op = SMBUS_OP_READ_BYTE;
		return (true);
	}

	if (req->ir_rlen == 2) {
		smbus->smbr_op = SMBUS_OP_READ_WORD;
		return (true);
	}

	if (req->ir_rlen > ctrl->ic_limit.lim_smbus_block) {
		return (false);
	}

	smbus->smbr_op = SMBUS_OP_I2C_READ_BLOCK;
	smbus->smbr_rlen = req->ir_rlen;
	return (true);
}

static bool
i2c_ctrl_io_i2c_xlate(i2c_txn_t *txn, i2c_ctrl_t *ctrl, i2c_port_t *port,
    i2c_req_t *req)
{
	smbus_req_t *smbus = &ctrl->ic_reqs.req_smbus;

	bzero(smbus, sizeof (smbus_req_t));
	smbus->smbr_addr = req->ir_addr;
	smbus->smbr_flags = req->ir_flags;

	/*
	 * First look at write-only requests, then read-only requests.
	 */
	if (req->ir_rlen == 0 && req->ir_wlen == 0) {
		goto xlate_fail;
	}

	if (req->ir_rlen == 0) {
		if (!i2c_ctrl_io_i2c_xlate_wo(ctrl, req, smbus))
			goto xlate_fail;
	} else if (req->ir_wlen == 0) {
		if (!i2c_ctrl_io_i2c_xlate_ro(req, smbus))
			goto xlate_fail;
	} else {
		if (!i2c_ctrl_io_i2c_xlate_rw(ctrl, req, smbus))
			goto xlate_fail;
	}

	bool ret = i2c_ctrl_io_smbus(txn, ctrl, port, smbus);
	req->ir_error = smbus->smbr_error;
	bcopy(smbus->smbr_rdata, req->ir_rdata, sizeof (smbus->smbr_rdata));

	return (ret);

xlate_fail:
	/*
	 * Ultimately, we couldn't translate this command. The world of I2C is
	 * much richer than the world of SMBus.
	 */
	i2c_ctrl_io_error(&req->ir_error, I2C_CORE_E_CANT_XLATE_REQ, 0);
	return (false);
}

bool
i2c_ctrl_io_i2c(i2c_txn_t *txn, i2c_ctrl_t *ctrl, i2c_port_t *port,
    i2c_req_t *req)
{
	VERIFY(i2c_txn_held(txn));
	VERIFY3P(txn->txn_ctrl, ==, ctrl);

	if (ctrl->ic_ops->i2c_io_i2c_f == NULL) {
		return (i2c_ctrl_io_i2c_xlate(txn, ctrl, port, req));
	}

	/*
	 * Verify that muxes are set up as required to do I/O to this port.
	 */
	if (!i2c_mux_update(txn, ctrl, port, &req->ir_error)) {
		return (false);
	}

	req->ir_error.i2c_error = INT32_MAX;
	req->ir_error.i2c_ctrl = INT32_MAX;

	/*
	 * At this point, go ahead and perform the actual I/O request via the
	 * controller.
	 */
	const i2c_port_t *ctrl_port = list_head(&ctrl->ic_mux_active);
	VERIFY3P(ctrl_port, !=, NULL);
	ctrl->ic_ops->i2c_io_i2c_f(ctrl->ic_drv, ctrl_port->ip_portno, req);

	if (req->ir_error.i2c_error == INT32_MAX ||
	    req->ir_error.i2c_ctrl == INT32_MAX) {
		dev_err(ctrl->ic_nexus->in_pdip, CE_WARN, "controller "
		    "failed to properly set error information");
		req->ir_error.i2c_error = I2C_CORE_E_CONTROLLER;
		req->ir_error.i2c_ctrl = I2C_CTRL_E_DRIVER;
	}

	return (req->ir_error.i2c_error == I2C_CORE_E_OK);
}

/*
 * Translate I/O into an I2C request and then back into the corresponding
 * results for SMBus. Most of these are straightforward. Unfortunately, the
 * variable size requests require controller support and we don't handle them
 * right now.
 */
static bool
i2c_ctrl_io_smbus_xlate(i2c_txn_t *txn, i2c_ctrl_t *ctrl, i2c_port_t *port,
    smbus_req_t *req)
{
	i2c_req_t *i2c = &ctrl->ic_reqs.req_i2c;

	bzero(i2c, sizeof (i2c_req_t));

	i2c->ir_addr = req->smbr_addr;
	i2c->ir_flags = req->smbr_flags;

	switch (req->smbr_op) {
	case SMBUS_OP_SEND_BYTE:
		i2c->ir_wlen = 1;
		i2c->ir_wdata[0] = req->smbr_wdata[0];
		break;
	case SMBUS_OP_WRITE_BYTE:
		i2c->ir_wlen = 2;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_wdata[1] = req->smbr_wdata[0];
		break;
	case SMBUS_OP_WRITE_WORD:
		i2c->ir_wlen = 3;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_wdata[1] = req->smbr_wdata[0];
		i2c->ir_wdata[2] = req->smbr_wdata[1];
		break;
	case SMBUS_OP_WRITE_U32:
		i2c->ir_wlen = 5;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_wdata[1] = req->smbr_wdata[0];
		i2c->ir_wdata[2] = req->smbr_wdata[1];
		i2c->ir_wdata[3] = req->smbr_wdata[2];
		i2c->ir_wdata[4] = req->smbr_wdata[3];
		break;
	case SMBUS_OP_WRITE_U64:
		i2c->ir_wlen = 9;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_wdata[1] = req->smbr_wdata[0];
		i2c->ir_wdata[2] = req->smbr_wdata[1];
		i2c->ir_wdata[3] = req->smbr_wdata[2];
		i2c->ir_wdata[4] = req->smbr_wdata[3];
		i2c->ir_wdata[5] = req->smbr_wdata[4];
		i2c->ir_wdata[6] = req->smbr_wdata[5];
		i2c->ir_wdata[7] = req->smbr_wdata[6];
		i2c->ir_wdata[8] = req->smbr_wdata[7];
		break;
	case SMBUS_OP_RECV_BYTE:
		i2c->ir_rlen = 1;
		break;
	case SMBUS_OP_READ_BYTE:
		i2c->ir_wlen = 1;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_rlen = sizeof (uint8_t);
		break;
	case SMBUS_OP_READ_WORD:
		i2c->ir_wlen = 1;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_rlen = sizeof (uint16_t);
		break;
	case SMBUS_OP_READ_U32:
		i2c->ir_wlen = 1;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_rlen = sizeof (uint32_t);
		break;
	case SMBUS_OP_READ_U64:
		i2c->ir_wlen = 1;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_rlen = sizeof (uint64_t);
		break;
	case SMBUS_OP_PROCESS_CALL:
		i2c->ir_wlen = 3;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_wdata[1] = req->smbr_wdata[0];
		i2c->ir_wdata[2] = req->smbr_wdata[1];
		i2c->ir_rlen = sizeof (uint16_t);
		break;
	case SMBUS_OP_WRITE_BLOCK:
		/*
		 * If we don't have space for this, the command code, and length
		 * then we're in trouble.
		 */
		if (req->smbr_wlen + 2 > ctrl->ic_limit.lim_i2c_write) {
			i2c_ctrl_io_error(&req->smbr_error,
			    I2C_CORE_E_CANT_XLATE_REQ, 0);
			return (false);
		}

		i2c->ir_wlen = req->smbr_wlen + 2;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_wdata[1] = req->smbr_wlen;
		bcopy(req->smbr_wdata, i2c->ir_wdata + 2, req->smbr_wlen);
		break;
	case SMBUS_OP_I2C_WRITE_BLOCK:
		if (req->smbr_wlen + 1 > ctrl->ic_limit.lim_i2c_write) {
			i2c_ctrl_io_error(&req->smbr_error,
			    I2C_CORE_E_CANT_XLATE_REQ, 0);
			return (false);
		}

		i2c->ir_wlen = req->smbr_wlen + 1;
		i2c->ir_wdata[0] = req->smbr_cmd;
		bcopy(req->smbr_wdata, i2c->ir_wdata + 1, req->smbr_wlen);
		break;
	case SMBUS_OP_I2C_READ_BLOCK:
		i2c->ir_wlen = 1;
		i2c->ir_wdata[0] = req->smbr_cmd;
		i2c->ir_rlen = req->smbr_rlen;
		break;
	/*
	 * Host notify is not supported here. While it is a valid operation, it
	 * is not meant for the controller to issue.
	 */
	case SMBUS_OP_HOST_NOTIFY:
		i2c_ctrl_io_error(&req->smbr_error,
		    I2C_CORE_E_UNSUP_SMBUS_OP, 0);
		return (false);
	/*
	 * The block reads require the ability to usefully describe how to get
	 * variable length operations to controllers. We can add this emulation
	 * when required, but for now do not.
	 */
	case SMBUS_OP_READ_BLOCK:
	case SMBUS_OP_BLOCK_PROCESS_CALL:
		i2c_ctrl_io_error(&req->smbr_error,
		    I2C_CORE_E_CANT_XLATE_REQ, 0);
		return (false);
	/*
	 * We should be able to translate a quick command. However, the main
	 * problem is that right now we don't have a good way of indicating
	 * read vs. write in the controller API for a zero-byte I/O in the
	 * controller API where we indicate the direction. This is something
	 * that should be remedied.
	 */
	case SMBUS_OP_QUICK_COMMAND:
	default:
		i2c_ctrl_io_error(&req->smbr_error,
		    I2C_CORE_E_CANT_XLATE_REQ, 0);
		return (false);
	}

	/*
	 * Copy error and data information back unconditionally. When we support
	 * variable length block I/O then we will need to update smbr_rlen with
	 * the actual length.
	 */
	bool ret = i2c_ctrl_io_i2c(txn, ctrl, port, i2c);
	req->smbr_error = i2c->ir_error;
	bcopy(i2c->ir_rdata, req->smbr_rdata, sizeof (i2c->ir_rdata));

	return (ret);
}

/*
 * Submit SMBus-style I/O, translating it as required into an I2C-specific
 * operation.
 */
bool
i2c_ctrl_io_smbus(i2c_txn_t *txn, i2c_ctrl_t *ctrl, i2c_port_t *port,
    smbus_req_t *req)
{
	VERIFY(i2c_txn_held(txn));
	VERIFY3P(txn->txn_ctrl, ==, ctrl);

	if (ctrl->ic_ops->i2c_io_smbus_f == NULL) {
		VERIFY3P(ctrl->ic_ops->i2c_io_i2c_f, !=, NULL);
		return (i2c_ctrl_io_smbus_xlate(txn, ctrl, port, req));
	}

	/*
	 * Verify that the requested operation is actually supported. If it is
	 * not, see if we can perform an I2C translation operation.  Otherwise,
	 * there's nothing more for us to do.
	 */
	if ((ctrl->ic_limit.lim_smbus_ops & (1 << req->smbr_op)) == 0) {
		if (ctrl->ic_ops->i2c_io_i2c_f != NULL) {
			return (i2c_ctrl_io_smbus_xlate(txn, ctrl, port, req));
		}
		i2c_ctrl_io_error(&req->smbr_error, I2C_CORE_E_CONTROLLER,
		    I2C_CTRL_E_UNSUP_CMD);
		return (false);
	}

	/*
	 * Verify that muxes are set up as required to do I/O to this port.
	 */
	if (!i2c_mux_update(txn, ctrl, port, &req->smbr_error)) {
		return (false);
	}

	req->smbr_error.i2c_error = INT32_MAX;
	req->smbr_error.i2c_ctrl = INT32_MAX;

	/*
	 * At this point, go ahead and perform the actual I/O request via the
	 * controller.
	 */
	const i2c_port_t *ctrl_port = list_head(&ctrl->ic_mux_active);
	VERIFY3P(ctrl_port, !=, NULL);
	ctrl->ic_ops->i2c_io_smbus_f(ctrl->ic_drv, ctrl_port->ip_portno, req);

	if (req->smbr_error.i2c_error == INT32_MAX ||
	    req->smbr_error.i2c_ctrl == INT32_MAX) {
		dev_err(ctrl->ic_nexus->in_pdip, CE_WARN, "controller "
		    "failed to properly set error information");
		req->smbr_error.i2c_error = I2C_CORE_E_CONTROLLER;
		req->smbr_error.i2c_ctrl = I2C_CTRL_E_DRIVER;
	}

	return (req->smbr_error.i2c_error == I2C_CORE_E_OK);
}

bool
i2c_ctrl_port_name_portno(void *arg, uint32_t port, char *buf, size_t buflen)
{
	return (snprintf(buf, buflen, "%u", port) < sizeof (buf));
}
