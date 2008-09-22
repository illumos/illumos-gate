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


/*
 * The max1617 I2C is a temp acquisition device.  As implemented on some
 * processor modules, it contains both a local and a remote temp.  The
 * local temp measures the ambient (room) temperature, while the remote
 * sensor is connected to the processor die.  There are ioctl's for retrieving
 * temperatures, and setting temperature alarm ranges.
 */

#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/note.h>

#include <sys/i2c/misc/i2c_svc.h>
#include <sys/i2c/clients/i2c_client.h>
#include <sys/i2c/clients/max1617.h>
#include <sys/i2c/clients/max1617_impl.h>

/*
 * cb ops (only need ioctl)
 */
static int max1617_open(dev_t *, int, int, cred_t *);
static int max1617_close(dev_t, int, int, cred_t *);
static int max1617_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * dev ops
 */
static int max1617_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int max1617_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int max1617_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct cb_ops max1617_cbops = {
	max1617_open,			/* open */
	max1617_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	max1617_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static struct dev_ops max1617_ops = {
	DEVO_REV,
	0,
	max1617_info,
	nulldev,
	nulldev,
	max1617_attach,
	max1617_detach,
	nodev,
	&max1617_cbops,
	NULL,
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv max1617_modldrv = {
	&mod_driverops,		/* type of module - driver */
	"max1617 device driver",
	&max1617_ops,
};

static struct modlinkage max1617_modlinkage = {
	MODREV_1,
	&max1617_modldrv,
	0
};

static int max1617_debug = 0;

static void *max1617_soft_statep;

int
_init(void)
{
	int error;

	error = mod_install(&max1617_modlinkage);
	if (error == 0) {
		(void) ddi_soft_state_init(&max1617_soft_statep,
		    sizeof (struct max1617_unit), 1);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&max1617_modlinkage);
	if (error == 0) {
		ddi_soft_state_fini(&max1617_soft_statep);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&max1617_modlinkage, modinfop));
}

/* ARGSUSED */
static int
max1617_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = MAX1617_MINOR_TO_INST(getminor(dev));
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
max1617_do_attach(dev_info_t *dip)
{
	struct max1617_unit *unitp;
	int instance;
	char minor_name[MAXNAMELEN];
	minor_t minor_number;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(max1617_soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to zalloc softstate",
		    ddi_get_name(dip), instance);

		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(max1617_soft_statep, instance);

	(void) snprintf(unitp->max1617_name, sizeof (unitp->max1617_name),
	    "%s%d", ddi_node_name(dip), instance);

	(void) sprintf(minor_name, "die_temp");
	minor_number = MAX1617_INST_TO_MINOR(instance) |
	    MAX1617_FCN_TO_MINOR(MAX1617_CPU_TEMP);

	if (ddi_create_minor_node(dip, minor_name, S_IFCHR,
	    minor_number, MAX1617_NODE_TYPE, NULL) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed for minor "
		    " name '%s'", unitp->max1617_name, minor_name);
			ddi_soft_state_free(max1617_soft_statep, instance);

		return (DDI_FAILURE);
	}

	(void) sprintf(minor_name, "amb_temp");
	minor_number = MAX1617_INST_TO_MINOR(instance) |
	    MAX1617_FCN_TO_MINOR(MAX1617_AMB_TEMP);

	if (ddi_create_minor_node(dip, minor_name, S_IFCHR,
	    minor_number, MAX1617_NODE_TYPE, NULL) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed for %s",
		    unitp->max1617_name, minor_name);
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(max1617_soft_statep, instance);

		return (DDI_FAILURE);
	}

	if (i2c_client_register(dip, &unitp->max1617_hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(max1617_soft_statep, instance);

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->max1617_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&unitp->max1617_cv, NULL, CV_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
max1617_do_resume(dev_info_t *dip)
{
	int ret = DDI_SUCCESS;
	int instance = ddi_get_instance(dip);
	i2c_transfer_t *i2ctp;
	struct max1617_unit *unitp;

	if ((unitp = ddi_get_soft_state(max1617_soft_statep, instance)) ==
	    NULL) {
		return (DDI_FAILURE);
	}

	(void) i2c_transfer_alloc(unitp->max1617_hdl,
	    &i2ctp, 2, 0, I2C_SLEEP);
	i2ctp->i2c_version = I2C_XFER_REV;
	i2ctp->i2c_flags = I2C_WR;


	i2ctp->i2c_wbuf[0] = MAX1617_CONFIG_WR_REG;
	i2ctp->i2c_wbuf[1] = unitp->max1617_cpr_state.max1617_config;

	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}

	i2ctp->i2c_wbuf[0] = MAX1617_CONV_RATE_WR_REG;
	i2ctp->i2c_wbuf[1] = unitp->max1617_cpr_state.max1617_conv_rate;
	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}

	i2ctp->i2c_wbuf[0] = MAX1617_LOCALTEMP_HIGH_WR_REG;
	i2ctp->i2c_wbuf[1] =  unitp->max1617_cpr_state.max1617_lcl_hlimit;

	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}

	i2ctp->i2c_wbuf[0] = MAX1617_REMOTETEMP_HIGH_WR_REG;
	i2ctp->i2c_wbuf[1] =  unitp->max1617_cpr_state.max1617_remote_hlimit;

	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}

	i2ctp->i2c_wbuf[0] = MAX1617_LOCALTEMP_LOW_REG;
	i2ctp->i2c_wbuf[1] = unitp->max1617_cpr_state.max1617_lcl_llimit;

	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}

	i2ctp->i2c_wbuf[0] = MAX1617_REMOTETEMP_LOW_REG;
	i2ctp->i2c_wbuf[1] = unitp->max1617_cpr_state.max1617_remote_llimit;

	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}

	done:
	mutex_enter(&unitp->max1617_mutex);
	unitp->max1617_flags = 0;
	cv_signal(&unitp->max1617_cv);
	mutex_exit(&unitp->max1617_mutex);

	i2c_transfer_free(unitp->max1617_hdl, i2ctp);
	return (ret);
}

static int
max1617_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:

		return (max1617_do_attach(dip));
	case DDI_RESUME:

		return (max1617_do_resume(dip));
	default:

		return (DDI_FAILURE);
	}
}

static int
max1617_do_detach(dev_info_t *dip)
{
	struct max1617_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	unitp = ddi_get_soft_state(max1617_soft_statep, instance);

	if (unitp == NULL) {
		return (DDI_FAILURE);
	}

	i2c_client_unregister(unitp->max1617_hdl);

	ddi_remove_minor_node(dip, NULL);

	mutex_destroy(&unitp->max1617_mutex);
	cv_destroy(&unitp->max1617_cv);
	ddi_soft_state_free(max1617_soft_statep, instance);

	return (DDI_SUCCESS);
}

static int
max1617_do_suspend(dev_info_t *dip)
{
	int ret = DDI_SUCCESS;
	int instance = ddi_get_instance(dip);
	i2c_transfer_t *i2ctp;
	struct max1617_unit *unitp;

	if ((unitp = ddi_get_soft_state(max1617_soft_statep, instance)) ==
	    NULL) {
		return (DDI_FAILURE);
	}

	(void) i2c_transfer_alloc(unitp->max1617_hdl,
	    &i2ctp, 1, 1, I2C_SLEEP);


	/*
	 * Block new transactions during CPR
	 */
	mutex_enter(&unitp->max1617_mutex);
	while (unitp->max1617_flags == MAX1617_BUSY) {
		cv_wait(&unitp->max1617_cv, &unitp->max1617_mutex);
	}
	unitp->max1617_flags = MAX1617_BUSY;
	mutex_exit(&unitp->max1617_mutex);

	i2ctp->i2c_version = I2C_XFER_REV;
	i2ctp->i2c_flags = I2C_WR_RD;
	i2ctp->i2c_wbuf[0] = MAX1617_CONFIG_REG;
	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}
	unitp->max1617_cpr_state.max1617_config = i2ctp->i2c_rbuf[0];

	i2ctp->i2c_wbuf[0] = MAX1617_CONV_RATE_REG;
	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}
	unitp->max1617_cpr_state.max1617_conv_rate = i2ctp->i2c_rbuf[0];

	i2ctp->i2c_wbuf[0] = MAX1617_LOCALTEMP_HIGH_REG;
	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}
	unitp->max1617_cpr_state.max1617_lcl_hlimit = i2ctp->i2c_rbuf[0];

	i2ctp->i2c_wbuf[0] = MAX1617_REMOTETEMP_HIGH_REG;
	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}
	unitp->max1617_cpr_state.max1617_remote_hlimit = i2ctp->i2c_rbuf[0];

	i2ctp->i2c_wbuf[0] = MAX1617_LOCALTEMP_LOW_REG;
	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}
	unitp->max1617_cpr_state.max1617_lcl_llimit = i2ctp->i2c_rbuf[0];

	i2ctp->i2c_wbuf[0] = MAX1617_REMOTETEMP_LOW_REG;
	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		ret = DDI_FAILURE;
		goto done;
	}
	unitp->max1617_cpr_state.max1617_remote_llimit = i2ctp->i2c_rbuf[0];

	done:
	i2c_transfer_free(unitp->max1617_hdl, i2ctp);

	if (ret == DDI_FAILURE) {
		mutex_enter(&unitp->max1617_mutex);
		unitp->max1617_flags = 0;
		cv_broadcast(&unitp->max1617_cv);
		mutex_exit(&unitp->max1617_mutex);
	}
	return (ret);
}

static int
max1617_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:

		return (max1617_do_detach(dip));
	case DDI_SUSPEND:

		return (max1617_do_suspend(dip));

	default:

		return (DDI_FAILURE);
	}
}

static int
max1617_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	struct max1617_unit *unitp;
	int instance;
	int err = 0;

	instance = MAX1617_MINOR_TO_INST(getminor(*devp));

	if (instance < 0) {

		return (ENXIO);
	}

	unitp = (struct max1617_unit *)
	    ddi_get_soft_state(max1617_soft_statep, instance);

	if (unitp == NULL) {

		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {

		return (EINVAL);
	}

	mutex_enter(&unitp->max1617_mutex);

	if (flags & FEXCL) {
		if (unitp->max1617_oflag != 0) {
			err = EBUSY;
		} else {
			unitp->max1617_oflag = FEXCL;
		}
	} else {
		if (unitp->max1617_oflag == FEXCL) {
			err = EBUSY;
		} else {
			unitp->max1617_oflag = (uint16_t)FOPEN;
		}
	}

done:
	mutex_exit(&unitp->max1617_mutex);

	return (err);
}

static int
max1617_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))

	struct max1617_unit *unitp;
	int instance = MAX1617_MINOR_TO_INST(getminor(dev));

	if (instance < 0) {

		return (ENXIO);
	}

	unitp = (struct max1617_unit *)
	    ddi_get_soft_state(max1617_soft_statep, instance);

	if (unitp == NULL) {

		return (ENXIO);
	}

	mutex_enter(&unitp->max1617_mutex);

	unitp->max1617_oflag = 0;

	mutex_exit(&unitp->max1617_mutex);

	return (DDI_SUCCESS);
}

int
set_temp_limit(struct max1617_unit *unitp,
		uchar_t device_reg,
		caddr_t arg,
		int mode)
{
	int err = 0;
	i2c_transfer_t *i2ctp;
	int16_t temp;

	(void) i2c_transfer_alloc(unitp->max1617_hdl, &i2ctp, 2, 0, I2C_SLEEP);
	i2ctp->i2c_version = I2C_XFER_REV;
	i2ctp->i2c_flags = I2C_WR;
	i2ctp->i2c_wbuf[0] = device_reg;

	if (ddi_copyin(arg, (caddr_t)&temp, sizeof (int16_t), mode) !=
	    DDI_SUCCESS) {
		i2c_transfer_free(unitp->max1617_hdl, i2ctp);

		return (EFAULT);
	}

	i2ctp->i2c_wbuf[1] = (int8_t)temp;

	if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
		err = EIO;
	}

	i2c_transfer_free(unitp->max1617_hdl, i2ctp);

	return (err);
}

int
get_temp_limit(struct max1617_unit *unitp,
		uchar_t reg,
		caddr_t arg,
		int mode)
{
	int err = 0;
	i2c_transfer_t *i2ctp;
	int16_t temp16;

	(void) i2c_transfer_alloc(unitp->max1617_hdl, &i2ctp, 1, 1, I2C_SLEEP);
	i2ctp->i2c_version = I2C_XFER_REV;
	i2ctp->i2c_flags = I2C_WR_RD;
	i2ctp->i2c_wbuf[0] = reg;
	if (i2c_transfer(unitp->max1617_hdl, i2ctp) == I2C_SUCCESS) {
		/*
		 * This double cast is required so that the sign is preserved
		 * when expanding the 8 bit value to 16.
		 */
		temp16 = (int16_t)((int8_t)i2ctp->i2c_rbuf[0]);
		if (ddi_copyout((caddr_t)&temp16, arg, sizeof (int16_t),
		    mode) != DDI_SUCCESS) {
			err = EFAULT;
		}
	} else {
		err = EIO;
	}
	i2c_transfer_free(unitp->max1617_hdl, i2ctp);

	return (err);
}

static int
max1617_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
		cred_t *credp, int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))
	struct max1617_unit *unitp;
	int err = 0;
	i2c_transfer_t *i2ctp;
	int fcn = MAX1617_MINOR_TO_FCN(getminor(dev));
	int instance = MAX1617_MINOR_TO_INST(getminor(dev));
	uchar_t reg;

	unitp = (struct max1617_unit *)
	    ddi_get_soft_state(max1617_soft_statep, instance);

	if (max1617_debug) {
		printf("max1617_ioctl: fcn=%d instance=%d\n", fcn, instance);
	}

	/*
	 * Serialize here, in order to block transacations during CPR.
	 * This is not a bottle neck since i2c_transfer would serialize
	 * anyway.
	 */
	mutex_enter(&unitp->max1617_mutex);
	while (unitp->max1617_flags == MAX1617_BUSY) {
		if (cv_wait_sig(&unitp->max1617_cv,
		    &unitp->max1617_mutex) <= 0) {
			mutex_exit(&unitp->max1617_mutex);
			return (EINTR);
		}
	}
	unitp->max1617_flags = MAX1617_BUSY;
	mutex_exit(&unitp->max1617_mutex);

	switch (cmd) {

	/*
	 * I2C_GET_TEMPERATURE reads a temperature from the device and
	 * copies a single byte representing the celcius temp
	 * to user space.
	 */
	case I2C_GET_TEMPERATURE:
		switch (fcn) {
		case MAX1617_AMB_TEMP:
			reg = MAX1617_LOCAL_TEMP_REG;
			break;
		case MAX1617_CPU_TEMP:
			reg = MAX1617_REMOTE_TEMP_REG;
			break;
		default:
			err = EINVAL;
			goto done;
		}

		(void) i2c_transfer_alloc(unitp->max1617_hdl, &i2ctp,
		    1, 1, I2C_SLEEP);
		i2ctp->i2c_version = I2C_XFER_REV;
		i2ctp->i2c_flags = I2C_WR_RD;
		i2ctp->i2c_wbuf[0] = reg;

		if (i2c_transfer(unitp->max1617_hdl, i2ctp) == I2C_SUCCESS) {

			/*
			 * This double cast is needed so that the sign bit
			 * is preserved when casting from unsigned char to
			 * signed 16 bit value.
			 */
			int16_t temp = (int16_t)((int8_t)i2ctp->i2c_rbuf[0]);
			if (ddi_copyout((caddr_t)&temp, (caddr_t)arg,
			    sizeof (int16_t), mode) != DDI_SUCCESS) {
				err = EFAULT;
			}
		} else {
			err = EIO;
		}
		i2c_transfer_free(unitp->max1617_hdl, i2ctp);
		break;

	case MAX1617_GET_STATUS:
		(void) i2c_transfer_alloc(unitp->max1617_hdl, &i2ctp,
		    1, 1, I2C_SLEEP);
		i2ctp->i2c_version = I2C_XFER_REV;
		i2ctp->i2c_flags = I2C_WR_RD;
		i2ctp->i2c_wbuf[0] = MAX1617_STATUS_REG;

		if (i2c_transfer(unitp->max1617_hdl, i2ctp) == I2C_SUCCESS) {
			if (ddi_copyout((caddr_t)i2ctp->i2c_rbuf, (caddr_t)arg,
			    sizeof (uint8_t), mode) != DDI_SUCCESS) {
				err = EFAULT;
			}
		} else {
			err = EIO;
		}
		i2c_transfer_free(unitp->max1617_hdl, i2ctp);
		break;
	case MAX1617_GET_CONFIG:
		(void) i2c_transfer_alloc(unitp->max1617_hdl, &i2ctp, 1, 1,
		    I2C_SLEEP);
		i2ctp->i2c_version = I2C_XFER_REV;
		i2ctp->i2c_flags = I2C_WR_RD;
		i2ctp->i2c_wbuf[0] = MAX1617_CONFIG_REG;
		if (i2c_transfer(unitp->max1617_hdl, i2ctp) == I2C_SUCCESS) {
			if (ddi_copyout((caddr_t)i2ctp->i2c_rbuf, (caddr_t)arg,
			    sizeof (uint8_t), mode) != DDI_SUCCESS) {
				err = EFAULT;
			}
		} else {
			err = EIO;
		}
		i2c_transfer_free(unitp->max1617_hdl, i2ctp);
		break;
	case MAX1617_GET_CONV_RATE:
		(void) i2c_transfer_alloc(unitp->max1617_hdl, &i2ctp,
		    1, 1, I2C_SLEEP);
		i2ctp->i2c_version = I2C_XFER_REV;
		i2ctp->i2c_flags = I2C_WR_RD;
		i2ctp->i2c_wbuf[0] = MAX1617_CONV_RATE_REG;
		if (i2c_transfer(unitp->max1617_hdl, i2ctp) == I2C_SUCCESS) {
			if (ddi_copyout((caddr_t)i2ctp->i2c_rbuf, (caddr_t)arg,
			    sizeof (uint8_t), mode) != DDI_SUCCESS) {
				err = EFAULT;
			}
		} else {
			err = EIO;
		}
		i2c_transfer_free(unitp->max1617_hdl, i2ctp);
		break;

	case MAX1617_GET_HIGH_LIMIT:
		switch (fcn) {
		case MAX1617_AMB_TEMP:
			err = get_temp_limit(unitp, MAX1617_LOCALTEMP_HIGH_REG,
			    (caddr_t)arg, mode);
			break;
		case MAX1617_CPU_TEMP:
			err = get_temp_limit(unitp, MAX1617_REMOTETEMP_HIGH_REG,
			    (caddr_t)arg, mode);
			break;
		default:
			err = EINVAL;
			break;
		}
		break;

	case MAX1617_GET_LOW_LIMIT:

		switch (fcn) {
		case MAX1617_AMB_TEMP:
			err = get_temp_limit(unitp, MAX1617_LOCALTEMP_LOW_REG,
			    (caddr_t)arg, mode);
			break;
		case MAX1617_CPU_TEMP:
			err = get_temp_limit(unitp, MAX1617_REMOTETEMP_LOW_REG,
			    (caddr_t)arg, mode);
			break;
		default:
			err = EINVAL;
		}
		break;

	case MAX1617_SET_CONV_RATE:
		(void) i2c_transfer_alloc(unitp->max1617_hdl, &i2ctp,
		    2, 0, I2C_SLEEP);
		i2ctp->i2c_version = I2C_XFER_REV;
		i2ctp->i2c_flags = I2C_WR;
		i2ctp->i2c_wbuf[0] = MAX1617_CONV_RATE_WR_REG;
		if (ddi_copyin((caddr_t)arg, (caddr_t)&i2ctp->i2c_wbuf[1],
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}
		if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
			err = EIO;
		}
		i2c_transfer_free(unitp->max1617_hdl, i2ctp);
		break;

	case MAX1617_SET_CONFIG:
		(void) i2c_transfer_alloc(unitp->max1617_hdl, &i2ctp,
		    2, 0, I2C_SLEEP);
		i2ctp->i2c_version = I2C_XFER_REV;
		i2ctp->i2c_flags = I2C_WR;
		i2ctp->i2c_wbuf[0] = MAX1617_CONFIG_WR_REG;
		if (ddi_copyin((caddr_t)arg, (caddr_t)&i2ctp->i2c_wbuf[1],
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}
		if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
			err = EIO;
		}

		i2c_transfer_free(unitp->max1617_hdl, i2ctp);
		break;

	case MAX1617_SET_HIGH_LIMIT:
		switch (fcn) {
		case MAX1617_AMB_TEMP:
			err = set_temp_limit(unitp,
			    MAX1617_LOCALTEMP_HIGH_WR_REG, (caddr_t)arg, mode);
			break;
		case MAX1617_CPU_TEMP:
			err = set_temp_limit(unitp,
			    MAX1617_REMOTETEMP_HIGH_WR_REG, (caddr_t)arg, mode);
			break;
		default:
			err = EINVAL;
		}
		break;

	case MAX1617_SET_LOW_LIMIT:
		switch (fcn) {
		case MAX1617_AMB_TEMP:
			err = set_temp_limit(unitp,
			    MAX1617_LOCALTEMP_LOW_WR_REG, (caddr_t)arg, mode);
			break;
		case MAX1617_CPU_TEMP:
			err = set_temp_limit(unitp,
			    MAX1617_REMOTETEMP_LOW_WR_REG, (caddr_t)arg, mode);
			break;
		default:
			err = EINVAL;
		}
		break;

	case MAX1617_ONE_SHOT_CMD:
		(void) i2c_transfer_alloc(unitp->max1617_hdl, &i2ctp, 1, 0,
		    I2C_SLEEP);
		i2ctp->i2c_version = I2C_XFER_REV;
		i2ctp->i2c_flags = I2C_WR;
		i2ctp->i2c_wbuf[0] = MAX1617_ONE_SHOT_CMD_REG;
		if (i2c_transfer(unitp->max1617_hdl, i2ctp) != I2C_SUCCESS) {
			err = EIO;
		}

		i2c_transfer_free(unitp->max1617_hdl, i2ctp);
		break;

	default:
		err = EINVAL;
	}

	done:

	mutex_enter(&unitp->max1617_mutex);
	unitp->max1617_flags = 0;
	cv_signal(&unitp->max1617_cv);
	mutex_exit(&unitp->max1617_mutex);

	return (err);
}
