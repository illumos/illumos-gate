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
 * I2C Controller that is used for userland simulation. This is designd for
 * testing purposes. The main instance creates a character device that is used
 * to communicate with userland. A single dev_info_t is created which we
 * register with the controller framework multiple times to represent a few
 * different devices. Userland is responsible for reading and replying to I/O
 * requests. Property requests are instead handled in the kernel.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>

#include <sys/i2c/controller.h>
#include "i2csim.h"

/*
 * We currently have three controllers. One that is pure i2c. One that is a
 * 2-port pure SMBus. One that is a hybrid SMBus and I2C controller.
 */
#define	I2CSIM_NCTRLS	2u

/*
 * This is an arbitrary and odd size to try to trigger some edge conditions in
 * drivers.
 */
#define	I2CSIM_I2C_MAX	77

typedef struct i2csim_ctrl {
	const char *isc_name;
	uint32_t isc_nports;
	i2c_ctrl_type_t isc_type;
	const i2c_ctrl_ops_t *isc_ops;
	smbus_prop_op_t isc_smbus_ops;
	uint32_t isc_max_read;
	uint32_t isc_max_write;
	uint32_t isc_max_block;
} i2csim_ctrl_t;

typedef enum i2csim_state {
	/*
	 * Indicates that there is currently no request.
	 */
	I2CSIM_S_IDLE,
	/*
	 * Indicates that a request is currently assigned and we are waiting for
	 * userland to process it.
	 */
	I2CSIM_S_REQ,
	/*
	 * Indicates that we have received a reply from userland.
	 */
	I2CSIM_S_REPLY
} i2csim_state_t;

typedef struct i2csim {
	dev_info_t *sim_dip;
	bool sim_open;
	uint64_t sim_seq;
	i2c_ctrl_hdl_t *sim_hdls[I2CSIM_NCTRLS];
	/*
	 * Request-related data.
	 */
	kmutex_t sim_mutex;
	kcondvar_t sim_cv;
	i2csim_state_t sim_state;
	i2c_req_t *sim_i2c_req;
	smbus_req_t *sim_smbus_req;
	const i2csim_ctrl_t *sim_ctrl_req;
	uint32_t sim_port_req;
	struct pollhead sim_ph;
} i2csim_t;

i2csim_t i2csim;

static void
i2csim_io_no_userland(i2csim_t *sim)
{
	VERIFY(MUTEX_HELD(&sim->sim_mutex));
	if (sim->sim_i2c_req != NULL) {
		i2c_ctrl_io_error(&sim->sim_i2c_req->ir_error,
		    I2C_CORE_E_CONTROLLER, I2C_CTRL_E_DRIVER);
	}

	if (sim->sim_smbus_req != NULL) {
		i2c_ctrl_io_error(&sim->sim_smbus_req->smbr_error,
		    I2C_CORE_E_CONTROLLER, I2C_CTRL_E_DRIVER);
	}

	sim->sim_state = I2CSIM_S_REPLY;
	cv_broadcast(&sim->sim_cv);
}

static void
i2csim_io_request(i2csim_t *sim, const i2csim_ctrl_t *ctrl, uint32_t port,
    i2c_req_t *i2c_req, smbus_req_t *smbus_req)
{
	VERIFY((i2c_req != NULL && smbus_req == NULL) ||
	    (i2c_req == NULL && smbus_req != NULL));

	mutex_enter(&sim->sim_mutex);
	while (sim->sim_state != I2CSIM_S_IDLE) {
		cv_wait(&sim->sim_cv, &sim->sim_mutex);
	}

	VERIFY3P(sim->sim_i2c_req, ==, NULL);
	VERIFY3P(sim->sim_smbus_req, ==, NULL);
	VERIFY3P(sim->sim_ctrl_req, ==, NULL);
	sim->sim_i2c_req = i2c_req;
	sim->sim_smbus_req = smbus_req;
	sim->sim_ctrl_req = ctrl;
	sim->sim_port_req = port;
	sim->sim_seq++;
	sim->sim_state = I2CSIM_S_REQ;
	pollwakeup(&sim->sim_ph, POLLIN);
	cv_broadcast(&sim->sim_cv);

	if (!sim->sim_open) {
		i2csim_io_no_userland(sim);
	}

	while (sim->sim_state != I2CSIM_S_REPLY) {
		cv_wait(&sim->sim_cv, &sim->sim_mutex);
	}

	sim->sim_i2c_req = NULL;
	sim->sim_smbus_req = NULL;
	sim->sim_ctrl_req = NULL;
	sim->sim_port_req = 0;
	sim->sim_state = I2CSIM_S_IDLE;
	cv_broadcast(&sim->sim_cv);

	mutex_exit(&sim->sim_mutex);
}

static void
i2csim_io_i2c(void *arg, uint32_t port, i2c_req_t *req)
{
	const i2csim_ctrl_t *ctrl = arg;

	i2csim_io_request(&i2csim, ctrl, port, req, NULL);
}

static void
i2csim_io_smbus(void *arg, uint32_t port, smbus_req_t *req)
{
	const i2csim_ctrl_t *ctrl = arg;

	i2csim_io_request(&i2csim, ctrl, port, NULL, req);
}

static i2c_errno_t
i2csim_prop_info(void *arg, i2c_prop_t prop, i2c_prop_info_t *info)
{
	const i2csim_ctrl_t *ctrl = arg;

	switch (prop) {
	case I2C_PROP_BUS_SPEED:
		i2c_prop_info_set_pos_bit32(info, I2C_SPEED_STD);
		break;
	case SMBUS_PROP_SUP_OPS:
	case SMBUS_PROP_MAX_BLOCK:
		if (ctrl->isc_type != I2C_CTRL_TYPE_SMBUS) {
			return (I2C_PROP_E_UNSUP);
		}
		break;
	case I2C_PROP_MAX_READ:
	case I2C_PROP_MAX_WRITE:
		if (ctrl->isc_type != I2C_CTRL_TYPE_I2C) {
			return (I2C_PROP_E_UNSUP);
		}
		break;
	default:
		return (I2C_PROP_E_UNSUP);

	}

	i2c_prop_info_set_perm(info, I2C_PROP_PERM_RO);

	return (I2C_CORE_E_OK);
}

static i2c_errno_t
i2csim_prop_get(void *arg, i2c_prop_t prop, void *buf, size_t buflen)
{
	uint32_t val;
	const i2csim_ctrl_t *ctrl = arg;

	/*
	 * First determine if this is a property this type of controller should
	 * support or not.
	 */
	switch (prop) {
	case I2C_PROP_MAX_READ:
	case I2C_PROP_MAX_WRITE:
		if (ctrl->isc_type != I2C_CTRL_TYPE_I2C) {
			return (I2C_PROP_E_UNSUP);
		}
		break;
	case SMBUS_PROP_MAX_BLOCK:
	case SMBUS_PROP_SUP_OPS:
		if (ctrl->isc_type != I2C_CTRL_TYPE_SMBUS) {
			return (I2C_PROP_E_UNSUP);
		}
		break;
	default:
		break;
	}

	switch (prop) {
	case I2C_PROP_BUS_SPEED:
		val = I2C_SPEED_STD;
		break;
	case SMBUS_PROP_SUP_OPS:
		val = ctrl->isc_smbus_ops;
		break;
	case I2C_PROP_MAX_READ:
		val = ctrl->isc_max_read;
		break;
	case I2C_PROP_MAX_WRITE:
		val = ctrl->isc_max_write;
		break;
	case SMBUS_PROP_MAX_BLOCK:
		val = ctrl->isc_max_block;
		break;
	default:
		return (I2C_PROP_E_UNSUP);
	}

	VERIFY3U(buflen, >=, sizeof (val));
	bcopy(&val, buf, sizeof (val));
	return (I2C_CORE_E_OK);
}

static const i2c_ctrl_ops_t i2csim_i2c_ops = {
	.i2c_port_name_f = i2c_ctrl_port_name_portno,
	.i2c_io_i2c_f = i2csim_io_i2c,
	.i2c_prop_info_f = i2csim_prop_info,
	.i2c_prop_get_f = i2csim_prop_get
};

static const i2c_ctrl_ops_t i2csim_smbus_ops = {
	.i2c_port_name_f = i2c_ctrl_port_name_portno,
	.i2c_io_smbus_f = i2csim_io_smbus,
	.i2c_prop_info_f = i2csim_prop_info,
	.i2c_prop_get_f = i2csim_prop_get
};

static const i2csim_ctrl_t i2csim_ctrls[I2CSIM_NCTRLS] = { {
	.isc_name = "i2csim0",
	.isc_nports = 1,
	.isc_type = I2C_CTRL_TYPE_I2C,
	.isc_ops = &i2csim_i2c_ops,
	.isc_max_read = I2CSIM_I2C_MAX,
	.isc_max_write = I2CSIM_I2C_MAX
}, {
	.isc_name = "smbussim1",
	.isc_nports = 2,
	.isc_type = I2C_CTRL_TYPE_SMBUS,
	.isc_ops = &i2csim_smbus_ops,
	.isc_smbus_ops = SMBUS_PROP_OP_QUICK_COMMAND | SMBUS_PROP_OP_SEND_BYTE |
	    SMBUS_PROP_OP_RECV_BYTE | SMBUS_PROP_OP_WRITE_BYTE |
	    SMBUS_PROP_OP_READ_BYTE | SMBUS_PROP_OP_WRITE_WORD |
	    SMBUS_PROP_OP_READ_WORD | SMBUS_PROP_OP_PROCESS_CALL |
	    SMBUS_PROP_OP_WRITE_BLOCK | SMBUS_PROP_OP_READ_BLOCK |
	    SMBUS_PROP_OP_BLOCK_PROCESS_CALL | SMBUS_PROP_OP_I2C_WRITE_BLOCK |
	    SMBUS_PROP_OP_I2C_READ_BLOCK,
	.isc_max_block = SMBUS_V2_MAX_BLOCK
} };

static int
i2csim_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	i2csim_t *sim = &i2csim;

	if (drv_priv(credp) != 0)
		return (EPERM);

	if (otype != OTYP_CHR)
		return (ENOTSUP);

	if ((flags & (FREAD | FWRITE)) == 0)
		return (EINVAL);

	if (getminor(*devp) != 0)
		return (ENXIO);

	mutex_enter(&sim->sim_mutex);
	if (sim->sim_open) {
		mutex_exit(&sim->sim_mutex);
		return (EBUSY);
	}

	sim->sim_open = true;
	mutex_exit(&sim->sim_mutex);
	return (0);
}

static uint32_t
i2csim_ctrl_index(i2csim_t *sim)
{
	VERIFY(MUTEX_HELD(&sim->sim_mutex));

	for (uint32_t i = 0; i < I2CSIM_NCTRLS; i++) {
		if (sim->sim_ctrl_req == &i2csim_ctrls[i]) {
			return (i);
		}
	}

	panic("programming error: invalid i2csim_ctrl_t");
}

static int
i2csim_ioctl_request(i2csim_t *sim, intptr_t arg, int mode)
{
	mutex_enter(&sim->sim_mutex);
	while (sim->sim_state != I2CSIM_S_REQ) {
		if ((mode & (FNONBLOCK | FNDELAY)) != 0) {
			mutex_exit(&sim->sim_mutex);
			return (EAGAIN);
		}

		if (cv_wait_sig(&sim->sim_cv, &sim->sim_mutex) == 0) {
			mutex_exit(&sim->sim_mutex);
			return (EINTR);
		}
	}


	i2csim_req_t req;
	bzero(&req, sizeof (req));
	req.i2csim_seq = sim->sim_seq;
	req.i2csim_ctrl = i2csim_ctrl_index(sim);
	req.i2csim_port = sim->sim_port_req;
	req.i2csim_type = sim->sim_ctrl_req->isc_type;
	if (sim->sim_i2c_req != NULL) {
		bcopy(sim->sim_i2c_req, &req.i2csim_i2c, sizeof (i2c_req_t));
	}

	if (sim->sim_smbus_req != NULL) {
		bcopy(sim->sim_smbus_req, &req.i2csim_smbus,
		    sizeof (smbus_req_t));
	}

	int ret = ddi_copyout(&req, (void *)arg, sizeof (i2csim_req_t),
	    mode & FKIOCTL);
	mutex_exit(&sim->sim_mutex);
	if (ret != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
i2csim_ioctl_reply(i2csim_t *sim, intptr_t arg, int mode)
{
	i2csim_req_t req;

	mutex_enter(&sim->sim_mutex);
	if (sim->sim_state != I2CSIM_S_REQ) {
		mutex_exit(&sim->sim_mutex);
		return (EAGAIN);
	}

	if (ddi_copyin((void *)arg, &req, sizeof (i2csim_req_t),
	    mode & FKIOCTL) != 0) {
		mutex_exit(&sim->sim_mutex);
		return (EFAULT);
	}

	/*
	 * We ignore the controller and port ID and rely on the sequence number
	 * for checking that this makes sense. We do check the type to ensure
	 * that the structure we're going to copy data from makes sense.
	 */
	if (req.i2csim_seq != sim->sim_seq ||
	    req.i2csim_type != sim->sim_ctrl_req->isc_type) {
		mutex_exit(&sim->sim_mutex);
		return (EINVAL);
	}

	switch (req.i2csim_type) {
	case I2C_CTRL_TYPE_I2C:
		sim->sim_i2c_req->ir_error = req.i2csim_i2c.ir_error;
		bcopy(req.i2csim_i2c.ir_rdata, sim->sim_i2c_req->ir_rdata,
		    sizeof (sim->sim_i2c_req->ir_rdata));
		break;
	case I2C_CTRL_TYPE_SMBUS:
		sim->sim_smbus_req->smbr_error = req.i2csim_smbus.smbr_error;
		sim->sim_smbus_req->smbr_rlen = req.i2csim_smbus.smbr_rlen;
		bcopy(req.i2csim_smbus.smbr_rdata,
		    sim->sim_smbus_req->smbr_rdata,
		    sizeof (sim->sim_smbus_req->smbr_rdata));
		break;
	default:
		mutex_exit(&sim->sim_mutex);
		return (EINVAL);
	}

	sim->sim_state = I2CSIM_S_REPLY;
	cv_broadcast(&sim->sim_cv);
	mutex_exit(&sim->sim_mutex);

	return (0);
}

static int
i2csim_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	i2csim_t *sim = &i2csim;

	if (getminor(dev) != 0) {
		return (ENXIO);
	}

	switch (cmd) {
	case I2CSIM_REQUEST:
		return (i2csim_ioctl_request(sim, arg, mode));
	case I2CSIM_REPLY:
		return (i2csim_ioctl_reply(sim, arg, mode));
	default:
		return (ENOTTY);
	}
}

static int
i2csim_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	i2csim_t *sim = &i2csim;
	short ready = 0;

	if (getminor(dev) != 0) {
		return (ENXIO);
	}

	mutex_enter(&sim->sim_mutex);
	if (sim->sim_state == I2CSIM_S_REQ) {
		ready |= POLLIN;
	}

	*reventsp = ready & events;
	if ((*reventsp == 0 && !anyyet) || (events & POLLET)) {
		*phpp = &sim->sim_ph;
	}
	mutex_exit(&sim->sim_mutex);

	return (0);
}

static int
i2csim_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	i2csim_t *sim = &i2csim;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&sim->sim_mutex);
	sim->sim_open = false;
	if (sim->sim_state == I2CSIM_S_REQ) {
		i2csim_io_no_userland(sim);
	}
	pollwakeup(&sim->sim_ph, POLLERR);
	pollhead_clean(&sim->sim_ph);
	mutex_exit(&sim->sim_mutex);
	return (0);
}

static struct cb_ops i2csim_cb_ops = {
	.cb_open = i2csim_open,
	.cb_close = i2csim_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = i2csim_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = i2csim_chpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

/*
 * We allow controller unregistration to fail during detach. However, if we are
 * trying to do this during attach, we require that it succeed.
 */
static bool
i2csim_unregister(i2csim_t *sim, bool detach)
{
	for (uint32_t i = 0; i < I2CSIM_NCTRLS; i++) {
		i2c_ctrl_reg_error_t ret;

		ret = i2c_ctrl_unregister(sim->sim_hdls[i]);
		if (detach && ret != I2C_CTRL_REG_E_OK) {
			dev_err(sim->sim_dip, CE_WARN, "failed to unregister "
			    "controller %u", i);
			return (false);
		}

		VERIFY3U(ret, ==, I2C_CTRL_REG_E_OK);
	}

	return (true);
}

static void
i2csim_cleanup(i2csim_t *sim)
{
	ddi_remove_minor_node(sim->sim_dip, NULL);
	cv_destroy(&sim->sim_cv);
	mutex_destroy(&sim->sim_mutex);
	sim->sim_dip = NULL;
}

static int
i2csim_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_get_instance(dip) != 0) {
		dev_err(dip, CE_WARN, "only a single instance of i2csim is "
		    "supported");
		return (DDI_FAILURE);
	}

	VERIFY3P(i2csim.sim_dip, ==, NULL);
	i2csim.sim_dip = dip;
	mutex_init(&i2csim.sim_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&i2csim.sim_cv, NULL, CV_DRIVER, NULL);
	if (ddi_create_minor_node(i2csim.sim_dip, "ctrl", S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to create control minor node");
		goto err;
	}

	for (size_t i = 0; i < I2CSIM_NCTRLS; i++) {
		i2c_ctrl_reg_error_t ret;
		i2c_ctrl_register_t *reg;

		ret = i2c_ctrl_register_alloc(I2C_CTRL_PROVIDER, &reg);
		if (ret != 0) {
			dev_err(i2csim.sim_dip, CE_WARN, "failed to allocate "
			    "i2c controller registration structure: 0x%x", ret);
			goto err;
		}

		reg->ic_type = i2csim_ctrls[i].isc_type;
		reg->ic_nports = i2csim_ctrls[i].isc_nports;
		reg->ic_name =  i2csim_ctrls[i].isc_name;
		reg->ic_dip = i2csim.sim_dip;
		reg->ic_drv = (void *)&i2csim_ctrls[i];
		reg->ic_ops = i2csim_ctrls[i].isc_ops;

		ret = i2c_ctrl_register(reg, &i2csim.sim_hdls[i]);
		i2c_ctrl_register_free(reg);
		if (ret != 0) {
			dev_err(i2csim.sim_dip, CE_WARN, "failed to register "
			    "controller %zu with i2c framework: 0x%x", i, ret);
			(void) i2csim_unregister(&i2csim, false);
			goto err;
		}

	}

	return (DDI_SUCCESS);

err:
	i2csim_cleanup(&i2csim);
	return (DDI_FAILURE);
}

static int
i2csim_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **outp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		VERIFY3P(i2csim.sim_dip, !=, NULL);
		*outp = i2csim.sim_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		VERIFY3P(i2csim.sim_dip, !=, NULL);
		*outp = i2csim.sim_dip;
		*outp = (void *)(uintptr_t)ddi_get_instance(i2csim.sim_dip);
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
i2csim_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_SUSPEND) {
		return (DDI_FAILURE);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	VERIFY3P(dip, ==, i2csim.sim_dip);

	if (!i2csim_unregister(&i2csim, true)) {
		return (DDI_FAILURE);
	}

	i2csim_cleanup(&i2csim);
	VERIFY3P(i2csim.sim_dip, ==, NULL);
	return (DDI_SUCCESS);
}

static struct dev_ops i2csim_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_getinfo = i2csim_getinfo,
	.devo_probe = nulldev,
	.devo_attach = i2csim_attach,
	.devo_detach = i2csim_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_supported,
	.devo_cb_ops = &i2csim_cb_ops
};

static struct modldrv i2csim_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "I2C Simulation Controller",
	.drv_dev_ops = &i2csim_dev_ops
};

static struct modlinkage i2csim_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &i2csim_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	i2c_ctrl_mod_init(&i2csim_dev_ops);
	if ((ret = mod_install(&i2csim_modlinkage)) != 0) {
		i2c_ctrl_mod_fini(&i2csim_dev_ops);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&i2csim_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&i2csim_modlinkage)) == 0) {
		i2c_ctrl_mod_fini(&i2csim_dev_ops);
	}

	return (ret);
}
