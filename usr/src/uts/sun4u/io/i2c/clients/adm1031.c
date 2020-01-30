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


#include <sys/stat.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/mode.h>
#include <sys/promif.h>
#include <sys/note.h>
#include <sys/i2c/misc/i2c_svc.h>
#include <sys/i2c/clients/i2c_client.h>
#include <sys/i2c/clients/adm1031.h>
#include <sys/i2c/clients/adm1031_impl.h>

/*
 * ADM1031 is an Intelligent Temperature Monitor and Dual PWM Fan Controller.
 * The functions supported by the driver are:
 *	Reading sensed temperatures.
 *	Setting temperature limits which control fan speeds.
 *	Reading fan speeds.
 *	Setting fan outputs.
 *	Reading internal registers.
 *	Setting internal registers.
 */

/*
 * A pointer to an int16_t is expected as an ioctl argument for all temperature
 * related commands and a pointer to a uint8_t is expected for all other
 * commands.  If the  parameter is to be read the value is copied into it and
 * if it is to be written, the integer referred to should have the appropriate
 * value.
 *
 * For all temperature related commands, a temperature minor node should be
 * passed as the argument to open(2) and correspondingly, a fan minor node
 * should be used for all fan related commands. Commands which do not fall in
 * either of the two categories are control commands and involve
 * reading/writing to the internal registers of the device or switching from
 * automatic monitoring mode to manual mode and vice-versa. A control minor
 * node is created by the driver which has to be used for control commands.
 *
 * Fan Speed in RPM = (frequency * 60)/Count * N, where Count is the value
 * received in the fan speed register and N is Speed Range.
 */

/*
 * cb ops
 */
static int adm1031_open(dev_t *, int, int, cred_t *);
static int adm1031_close(dev_t, int, int, cred_t *);
static int adm1031_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * dev ops
 */
static int adm1031_s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int adm1031_s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct cb_ops adm1031_cb_ops = {
	adm1031_open,			/* open */
	adm1031_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	adm1031_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
};

static struct dev_ops adm1031_dev_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,
	nulldev,
	adm1031_s_attach,
	adm1031_s_detach,
	nodev,
	&adm1031_cb_ops,
	NULL,
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static uint8_t adm1031_control_regs[] = {
	0x00,
	ADM1031_STAT_1_REG,
	ADM1031_STAT_2_REG,
	ADM1031_DEVICE_ID_REG,
	ADM1031_CONFIG_REG_1,
	ADM1031_CONFIG_REG_2,
	ADM1031_FAN_CHAR_1_REG,
	ADM1031_FAN_CHAR_2_REG,
	ADM1031_FAN_SPEED_CONFIG_REG,
	ADM1031_FAN_HIGH_LIMIT_1_REG,
	ADM1031_FAN_HIGH_LIMIT_2_REG,
	ADM1031_LOCAL_TEMP_RANGE_REG,
	ADM1031_REMOTE_TEMP_RANGE_1_REG,
	ADM1031_REMOTE_TEMP_RANGE_2_REG,
	ADM1031_EXTD_TEMP_RESL_REG,
	ADM1031_LOCAL_TEMP_OFFSET_REG,
	ADM1031_REMOTE_TEMP_OFFSET_1_REG,
	ADM1031_REMOTE_TEMP_OFFSET_2_REG,
	ADM1031_LOCAL_TEMP_HIGH_LIMIT_REG,
	ADM1031_REMOTE_TEMP_HIGH_LIMIT_1_REG,
	ADM1031_REMOTE_TEMP_HIGH_LIMIT_2_REG,
	ADM1031_LOCAL_TEMP_LOW_LIMIT_REG,
	ADM1031_REMOTE_TEMP_LOW_LIMIT_1_REG,
	ADM1031_REMOTE_TEMP_LOW_LIMIT_2_REG,
	ADM1031_LOCAL_TEMP_THERM_LIMIT_REG,
	ADM1031_REMOTE_TEMP_THERM_LIMIT_1_REG,
	ADM1031_REMOTE_TEMP_THERM_LIMIT_2_REG
};

static  minor_info	temperatures[ADM1031_TEMP_CHANS] = {
	{"local", ADM1031_LOCAL_TEMP_INST_REG }, /* Local Temperature */
	{"remote_1", ADM1031_REMOTE_TEMP_INST_REG_1 }, /* Remote 1 */
	{"remote_2", ADM1031_REMOTE_TEMP_INST_REG_2 }  /* Remote 2 */
};

static	minor_info	fans[ADM1031_FAN_SPEED_CHANS] = {
	{"fan_1", ADM1031_FAN_SPEED_INST_REG_1},
	{"fan_2", ADM1031_FAN_SPEED_INST_REG_2}
};

static struct modldrv adm1031_modldrv = {
	&mod_driverops,		/* type of module - driver */
	"adm1031 device driver",
	&adm1031_dev_ops,
};

static struct modlinkage adm1031_modlinkage = {
	MODREV_1,
	&adm1031_modldrv,
	0
};

static void *adm1031_soft_statep;
int	adm1031_pil = ADM1031_PIL;


int
_init(void)
{
	int    err;

	err = mod_install(&adm1031_modlinkage);
	if (err == 0) {
		(void) ddi_soft_state_init(&adm1031_soft_statep,
		    sizeof (adm1031_unit_t), 1);
	}
	return (err);
}

int
_fini(void)
{
	int    err;

	err = mod_remove(&adm1031_modlinkage);
	if (err == 0) {
		ddi_soft_state_fini(&adm1031_soft_statep);
	}
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&adm1031_modlinkage, modinfop));
}

static int
adm1031_resume(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	adm1031_unit_t	*admp;
	int		err = DDI_SUCCESS;

	admp = (adm1031_unit_t *)
	    ddi_get_soft_state(adm1031_soft_statep, instance);

	if (admp == NULL) {
		return (DDI_FAILURE);
	}

	/*
	 * Restore registers to state existing before cpr
	 */
	admp->adm1031_transfer->i2c_flags = I2C_WR;
	admp->adm1031_transfer->i2c_wlen = 2;
	admp->adm1031_transfer->i2c_rlen = 0;

	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_CONFIG_REG_1;
	admp->adm1031_transfer->i2c_wbuf[1] =
	    admp->adm1031_cpr_state.config_reg_1;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    DDI_SUCCESS) {
		err = DDI_FAILURE;
		goto done;
	}
	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_CONFIG_REG_2;
	admp->adm1031_transfer->i2c_wbuf[1] =
	    admp->adm1031_cpr_state.config_reg_2;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    DDI_SUCCESS) {
		err = DDI_FAILURE;
		goto done;
	}
	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_FAN_SPEED_CONFIG_REG;
	admp->adm1031_transfer->i2c_wbuf[1] =
	    admp->adm1031_cpr_state.fan_speed_reg;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    DDI_SUCCESS) {
		err = DDI_FAILURE;
		goto done;
	}

	/*
	 * Clear busy flag so that transactions may continue
	 */
	mutex_enter(&admp->adm1031_mutex);
	admp->adm1031_flags = admp->adm1031_flags & ~ADM1031_BUSYFLAG;
	cv_signal(&admp->adm1031_cv);
	mutex_exit(&admp->adm1031_mutex);

done:
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s:%d Registers not restored correctly",
		    admp->adm1031_name, instance);
	}
	return (err);
}

static void
adm1031_detach(dev_info_t *dip)
{
	adm1031_unit_t	*admp;
	int		instance = ddi_get_instance(dip);

	admp = ddi_get_soft_state(adm1031_soft_statep, instance);

	if (admp->adm1031_flags & ADM1031_REGFLAG) {
		i2c_client_unregister(admp->adm1031_hdl);
	}
	if (admp->adm1031_flags & ADM1031_TBUFFLAG) {
		i2c_transfer_free(admp->adm1031_hdl, admp->adm1031_transfer);
	}
	if (admp->adm1031_flags & ADM1031_INTRFLAG) {
		ddi_remove_intr(dip, 0, admp->adm1031_icookie);
		cv_destroy(&admp->adm1031_icv);
		mutex_destroy(&admp->adm1031_imutex);
	}

	(void) ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);
	cv_destroy(&admp->adm1031_cv);
	mutex_destroy(&admp->adm1031_mutex);
	ddi_soft_state_free(adm1031_soft_statep, instance);

}

static uint_t
adm1031_intr(caddr_t arg)
{
	adm1031_unit_t	*admp = (adm1031_unit_t *)arg;


	if (admp->adm1031_cvwaiting == 0)
		return (DDI_INTR_CLAIMED);

	mutex_enter(&admp->adm1031_imutex);
	cv_broadcast(&admp->adm1031_icv);
	admp->adm1031_cvwaiting = 0;
	mutex_exit(&admp->adm1031_imutex);

	return (DDI_INTR_CLAIMED);
}

static int
adm1031_attach(dev_info_t *dip)
{
	adm1031_unit_t		*admp;
	int			instance = ddi_get_instance(dip);
	minor_t			minor;
	int			i;
	char			*minor_name;
	int			err = 0;

	if (ddi_soft_state_zalloc(adm1031_soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s:%d failed to zalloc softstate",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}
	admp = ddi_get_soft_state(adm1031_soft_statep, instance);
	if (admp == NULL) {
		return (DDI_FAILURE);
	}
	admp->adm1031_dip = dip;
	mutex_init(&admp->adm1031_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&admp->adm1031_cv, NULL, CV_DRIVER, NULL);

	(void) snprintf(admp->adm1031_name, sizeof (admp->adm1031_name),
	    "%s_%d", ddi_driver_name(dip), instance);

	/*
	 * Create minor node for all temperature functions.
	 */
	for (i = 0; i < ADM1031_TEMP_CHANS; i++) {

		minor_name = temperatures[i].minor_name;
		minor = ADM1031_INST_TO_MINOR(instance) |
		    ADM1031_FCN_TO_MINOR(ADM1031_TEMPERATURES) |
		    ADM1031_FCNINST_TO_MINOR(i);

		if (ddi_create_minor_node(dip, minor_name, S_IFCHR, minor,
		    ADM1031_NODE_TYPE, 0) == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s:%d ddi_create_minor_node failed",
			    admp->adm1031_name, instance);
			adm1031_detach(dip);
			return (DDI_FAILURE);
		}
	}

	/*
	 * Create minor node for all fan functions.
	 */
	for (i = 0; i < ADM1031_FAN_SPEED_CHANS; i++) {

		minor_name = fans[i].minor_name;
		minor = ADM1031_INST_TO_MINOR(instance) |
		    ADM1031_FCN_TO_MINOR(ADM1031_FANS) |
		    ADM1031_FCNINST_TO_MINOR(i);

		if (ddi_create_minor_node(dip, minor_name, S_IFCHR, minor,
		    ADM1031_NODE_TYPE, 0) == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s:%d ddi_create_minor_node failed",
			    admp->adm1031_name, instance);
			adm1031_detach(dip);
			return (DDI_FAILURE);
		}
	}

	/*
	 * Create minor node for all control functions.
	 */
	minor = ADM1031_INST_TO_MINOR(instance) |
	    ADM1031_FCN_TO_MINOR(ADM1031_CONTROL) |
	    ADM1031_FCNINST_TO_MINOR(0);

	if (ddi_create_minor_node(dip, "control", S_IFCHR, minor,
	    ADM1031_NODE_TYPE, 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s:%d ddi_create_minor_node failed",
		    admp->adm1031_name, instance);
		adm1031_detach(dip);
		return (DDI_FAILURE);
	}

	/*
	 * preallocate a single buffer for all reads and writes
	 */
	if (i2c_transfer_alloc(admp->adm1031_hdl, &admp->adm1031_transfer,
	    ADM1031_MAX_XFER, ADM1031_MAX_XFER, I2C_SLEEP) != I2C_SUCCESS) {
		cmn_err(CE_WARN, "%s:%d i2c_transfer_alloc failed",
		    admp->adm1031_name, instance);
		adm1031_detach(dip);
		return (DDI_FAILURE);
	}
	admp->adm1031_flags |= ADM1031_TBUFFLAG;
	admp->adm1031_transfer->i2c_version = I2C_XFER_REV;

	if (i2c_client_register(dip, &admp->adm1031_hdl) != I2C_SUCCESS) {
		cmn_err(CE_WARN, "%s:%d i2c_client_register failed",
		    admp->adm1031_name, instance);
		adm1031_detach(dip);
		return (DDI_FAILURE);
	}
	admp->adm1031_flags |= ADM1031_REGFLAG;

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    "interrupt-priorities") != 1) {
		(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
		    DDI_PROP_CANSLEEP, "interrupt-priorities",
		    (void *)&adm1031_pil, sizeof (adm1031_pil));
	}
	err = ddi_get_iblock_cookie(dip, 0, &admp->adm1031_icookie);
	if (err == DDI_SUCCESS) {
		mutex_init(&admp->adm1031_imutex, NULL, MUTEX_DRIVER,
		    (void *)admp->adm1031_icookie);
		cv_init(&admp->adm1031_icv, NULL, CV_DRIVER, NULL);
		if (ddi_add_intr(dip, 0, NULL, NULL, adm1031_intr,
		    (caddr_t)admp) == DDI_SUCCESS) {
			admp->adm1031_flags |= ADM1031_INTRFLAG;
		} else {
			cmn_err(CE_WARN, "%s:%d failed to add interrupt",
			    admp->adm1031_name, instance);
		}
	}

	/*
	 * The system comes up in Automatic Monitor Mode.
	 */
	admp->adm1031_flags |= ADM1031_AUTOFLAG;

	return (DDI_SUCCESS);
}

static int
adm1031_s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (adm1031_attach(dip));
	case DDI_RESUME:
		return (adm1031_resume(dip));
	default:
		return (DDI_FAILURE);
	}
}

static int
adm1031_suspend(dev_info_t *dip)
{
	adm1031_unit_t	*admp;
	int		instance = ddi_get_instance(dip);
	int		err = DDI_SUCCESS;

	admp = ddi_get_soft_state(adm1031_soft_statep, instance);

	/*
	 * Set the busy flag so that future transactions block
	 * until resume.
	 */
	mutex_enter(&admp->adm1031_mutex);
	while (admp->adm1031_flags & ADM1031_BUSYFLAG) {
		if (cv_wait_sig(&admp->adm1031_cv,
		    &admp->adm1031_mutex) <= 0) {
			mutex_exit(&admp->adm1031_mutex);
			return (DDI_FAILURE);
		}
	}
	admp->adm1031_flags |= ADM1031_BUSYFLAG;
	mutex_exit(&admp->adm1031_mutex);

	/*
	 * Save the state of the threshold registers.
	 */
	admp->adm1031_transfer->i2c_flags = I2C_WR_RD;
	admp->adm1031_transfer->i2c_wlen = 1;
	admp->adm1031_transfer->i2c_rlen = 1;

	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_CONFIG_REG_1;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    DDI_SUCCESS) {
		err = DDI_FAILURE;
		goto done;
	}
	admp->adm1031_cpr_state.config_reg_1 =
	    admp->adm1031_transfer->i2c_rbuf[0];

	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_CONFIG_REG_2;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    DDI_SUCCESS) {
		err = DDI_FAILURE;
		goto done;
	}
	admp->adm1031_cpr_state.config_reg_2 =
	    admp->adm1031_transfer->i2c_rbuf[0];

	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_FAN_SPEED_CONFIG_REG;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    DDI_SUCCESS) {
		err = DDI_FAILURE;
		goto done;
	}
	admp->adm1031_cpr_state.fan_speed_reg =
	    admp->adm1031_transfer->i2c_rbuf[0];
done:
	if (err != DDI_SUCCESS) {
		mutex_enter(&admp->adm1031_mutex);
		admp->adm1031_flags = admp->adm1031_flags & ~ADM1031_BUSYFLAG;
		cv_broadcast(&admp->adm1031_cv);
		mutex_exit(&admp->adm1031_mutex);
		cmn_err(CE_WARN, "%s:%d Suspend failed,\
		    unable to save registers", admp->adm1031_name, instance);
	}
	return (err);

}

static int
adm1031_s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		adm1031_detach(dip);
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (adm1031_suspend(dip));
	default:
		return (DDI_FAILURE);
	}
}

static int
adm1031_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int			instance;
	adm1031_unit_t		*admp;
	int			err = EBUSY;

	/* must be root to access this device */
	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	/*
	 * Make sure the open is for the right file type
	 */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}
	instance = ADM1031_MINOR_TO_INST(getminor(*devp));
	admp = (adm1031_unit_t *)
	    ddi_get_soft_state(adm1031_soft_statep, instance);
	if (admp == NULL) {
		return (ENXIO);
	}

	/*
	 * Enforce exclusive access if required.
	 */
	mutex_enter(&admp->adm1031_mutex);
	if (flags & FEXCL) {
		if (admp->adm1031_oflag == 0) {
			admp->adm1031_oflag = FEXCL;
			err = 0;
		}
	} else if (admp->adm1031_oflag != FEXCL) {
		admp->adm1031_oflag = FOPEN;
		err = 0;
	}
	mutex_exit(&admp->adm1031_mutex);
	return (err);
}

static int
adm1031_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	int		instance;
	adm1031_unit_t	*admp;

	_NOTE(ARGUNUSED(flags, otyp, credp))

	instance = ADM1031_MINOR_TO_INST(getminor(dev));
	admp = (adm1031_unit_t *)
	    ddi_get_soft_state(adm1031_soft_statep, instance);
	if (admp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&admp->adm1031_mutex);
	admp->adm1031_oflag = 0;
	mutex_exit(&admp->adm1031_mutex);
	return (0);
}

static int
adm1031_s_ioctl(dev_t dev, int cmd, intptr_t arg, int mode)
{
	adm1031_unit_t	*admp;
	int		err = 0, cmd_c = 0;
	uint8_t		speed = 0, f_set = 0, temp = 0, write_value = 0;
	int16_t		temp16 = 0, write_value16 = 0;
	minor_t		minor = getminor(dev);
	int		instance = ADM1031_MINOR_TO_INST(minor);
	int		fcn = ADM1031_MINOR_TO_FCN(minor);
	int		fcn_inst = ADM1031_MINOR_TO_FCNINST(minor);

	admp = (adm1031_unit_t *)
	    ddi_get_soft_state(adm1031_soft_statep, instance);

	/*
	 * We serialize here and block pending transactions.
	 */
	mutex_enter(&admp->adm1031_mutex);
	while (admp->adm1031_flags & ADM1031_BUSYFLAG) {
		if (cv_wait_sig(&admp->adm1031_cv,
		    &admp->adm1031_mutex) <= 0) {
			mutex_exit(&admp->adm1031_mutex);
			return (EINTR);
		}
	}
	admp->adm1031_flags |= ADM1031_BUSYFLAG;
	mutex_exit(&admp->adm1031_mutex);

	switch (fcn) {
	case ADM1031_TEMPERATURES:
		if (cmd == I2C_GET_TEMPERATURE) {
			admp->adm1031_transfer->i2c_wbuf[0] =
			    temperatures[fcn_inst].reg;
			goto copyout;
		} else {
			cmd = cmd - ADM1031_PVT_BASE_IOCTL;
			cmd_c = ADM1031_CHECK_FOR_WRITES(cmd) ?
			    (cmd - ADM1031_WRITE_COMMAND_BASE) + fcn_inst :
			    cmd + fcn_inst;
			if (!ADM1031_CHECK_TEMPERATURE_CMD(cmd_c)) {
				err = EINVAL;
				goto done;
			}
			admp->adm1031_transfer->i2c_wbuf[0] =
			    adm1031_control_regs[cmd_c];
			if (ADM1031_CHECK_FOR_WRITES(cmd))
				goto writes;
			else
				goto copyout;
		}
	case ADM1031_FANS:
		if (cmd == I2C_GET_FAN_SPEED) {
			admp->adm1031_transfer->i2c_wbuf[0] =
			    fans[fcn_inst].reg;
			goto copyout;
		} else if (cmd == ADM1031_GET_FAN_CONFIG) {
			admp->adm1031_transfer->i2c_wbuf[0] =
			    ADM1031_FAN_SPEED_CONFIG_REG;
			goto copyout;
		} else if (cmd == I2C_SET_FAN_SPEED) {
			if (ddi_copyin((void *)arg, &write_value,
			    sizeof (write_value), mode) != DDI_SUCCESS) {

				err = EFAULT;
				goto done;
			}
			speed = write_value;
			if ((admp->adm1031_flags & ADM1031_AUTOFLAG)) {
				err = EBUSY;
				goto done;
			}
			if (ADM1031_CHECK_INVALID_SPEED(speed)) {
				err = EINVAL;
				goto done;
			}
			admp->adm1031_transfer->i2c_wbuf[0] =
			    ADM1031_FAN_SPEED_CONFIG_REG;
			admp->adm1031_transfer->i2c_flags = I2C_WR_RD;
			admp->adm1031_transfer->i2c_wlen = 1;
			admp->adm1031_transfer->i2c_rlen = 1;
			if (i2c_transfer(admp->adm1031_hdl,
			    admp->adm1031_transfer) != I2C_SUCCESS) {
				err = EIO;
				goto done;
			}
			f_set = admp->adm1031_transfer->i2c_rbuf[0];
			f_set = (fcn_inst == 0) ? (MLSN(f_set) | speed):
			    (MMSN(f_set) | (speed << 4));

			admp->adm1031_transfer->i2c_wbuf[1] = f_set;
			admp->adm1031_transfer->i2c_flags = I2C_WR;
			admp->adm1031_transfer->i2c_wlen = 2;
			if (i2c_transfer(admp->adm1031_hdl,
			    admp->adm1031_transfer) != I2C_SUCCESS) {
				err = EIO;
			}
			goto done;
		}
		cmd = cmd - ADM1031_PVT_BASE_IOCTL;
		cmd_c = ADM1031_CHECK_FOR_WRITES(cmd) ?
		    (cmd - ADM1031_WRITE_COMMAND_BASE) + fcn_inst :
		    cmd + fcn_inst;
		if (!ADM1031_CHECK_FAN_CMD(cmd_c)) {
			err = EINVAL;
			goto done;
		}
		admp->adm1031_transfer->i2c_wbuf[0] =
		    adm1031_control_regs[cmd_c];
		if (ADM1031_CHECK_FOR_WRITES(cmd))
			goto writes;
		else
			goto copyout;
	case ADM1031_CONTROL:

		/*
		 * Read the primary configuration register in advance.
		 */
		admp->adm1031_transfer->i2c_wbuf[0] =
		    ADM1031_CONFIG_REG_1;
		admp->adm1031_transfer->i2c_flags = I2C_WR_RD;
		admp->adm1031_transfer->i2c_wlen = 1;
		admp->adm1031_transfer->i2c_rlen = 1;
		if (i2c_transfer(admp->adm1031_hdl,
		    admp->adm1031_transfer) != I2C_SUCCESS) {
			err = EIO;
			goto done;
		}
		switch (cmd) {
		case ADM1031_GET_MONITOR_MODE:
			temp = ADM1031_AUTOFLAG &
			    admp->adm1031_transfer->i2c_rbuf[0];
			temp = temp >> 7;
			if (ddi_copyout((void *)&temp, (void *)arg,
			    sizeof (temp), mode) != DDI_SUCCESS) {
				err = EFAULT;
			}
			goto done;
		case ADM1031_SET_MONITOR_MODE:
			if (ddi_copyin((void *)arg, &write_value,
			    sizeof (write_value), mode) != DDI_SUCCESS) {
				err = EFAULT;
				goto done;
			}
			if (write_value == ADM1031_AUTO_MODE) {
				temp = ADM1031_AUTOFLAG |
				    admp->adm1031_transfer->i2c_rbuf[0];
				admp->adm1031_flags |= ADM1031_AUTOFLAG;
			} else if (write_value == ADM1031_MANUAL_MODE) {
				temp = admp->adm1031_transfer->i2c_rbuf[0] &
				    (~ADM1031_AUTOFLAG);
				admp->adm1031_flags &= ~ADM1031_AUTOFLAG;
			} else {
				err = EINVAL;
				goto done;
			}
			admp->adm1031_transfer->i2c_wbuf[1] = temp;
			admp->adm1031_transfer->i2c_flags = I2C_WR;
			admp->adm1031_transfer->i2c_wlen = 2;
			if (i2c_transfer(admp->adm1031_hdl,
			    admp->adm1031_transfer) != I2C_SUCCESS) {
				err = EIO;
			}
			goto done;
		default:
			goto control;
		}
	default:
		err = EINVAL;
		goto done;
	}

control:
	cmd = cmd - ADM1031_PVT_BASE_IOCTL;

	if (ADM1031_CHECK_FOR_WRITES(cmd)) {
		cmd_c = (cmd - ADM1031_WRITE_COMMAND_BASE) + fcn_inst;
		admp->adm1031_transfer->i2c_wbuf[0] =
		    adm1031_control_regs[cmd_c];

		goto writes;
	}
	cmd_c = cmd  + fcn_inst;
	admp->adm1031_transfer->i2c_wbuf[0] = adm1031_control_regs[cmd_c];
	goto copyout;

writes:
	if (fcn == ADM1031_TEMPERATURES) {
		if (ddi_copyin((void *)arg, &write_value16,
		    sizeof (write_value16), mode) != DDI_SUCCESS) {

			err = EFAULT;
			goto done;
		}
		write_value = (uint8_t)((int8_t)(write_value16));
	} else {
		if (ddi_copyin((void *)arg, &write_value,
		    sizeof (write_value), mode) != DDI_SUCCESS) {

			err = EFAULT;
			goto done;
		}
	}
	admp->adm1031_transfer->i2c_flags = I2C_WR;
	admp->adm1031_transfer->i2c_wlen = 2;
	admp->adm1031_transfer->i2c_rlen = 0;
	admp->adm1031_transfer->i2c_wbuf[1] = write_value;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    I2C_SUCCESS) {

		err = EIO;
	}
	goto done;

copyout:
	admp->adm1031_transfer->i2c_flags = I2C_WR_RD;
	admp->adm1031_transfer->i2c_wlen = 1;
	admp->adm1031_transfer->i2c_rlen = 1;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    I2C_SUCCESS) {

		err = EIO;
		goto done;
	}
	temp = admp->adm1031_transfer->i2c_rbuf[0];
	if (fcn == ADM1031_TEMPERATURES) {
		/*
		 * Workaround for bug in ADM1031 which reports -128 (0x80)
		 * when the temperature transitions from 0C to -1C.
		 * All other -ve temperatures are not affected. We map
		 * 0x80 to 0xFF(-1) since we don't ever expect to see -128C on a
		 * sensor.
		 */
		if (temp == 0x80) {
			temp = 0xFF;
		}
		temp16 = (int16_t)((int8_t)temp);
		if (ddi_copyout((void *)&temp16, (void *)arg, sizeof (temp16),
		    mode) != DDI_SUCCESS)
			err = EFAULT;
	} else {
		if (ddi_copyout((void *)&temp, (void *)arg, sizeof (temp),
		    mode) != DDI_SUCCESS)
			err = EFAULT;
	}

done:
	mutex_enter(&admp->adm1031_mutex);
	admp->adm1031_flags = admp->adm1031_flags & (~ADM1031_BUSYFLAG);
	cv_signal(&admp->adm1031_cv);
	mutex_exit(&admp->adm1031_mutex);
	return (err);
}

/*
 * The interrupt ioctl is a private handshake between the user and the driver
 * and is a mechanism to asynchronously inform the user of a system event such
 * as a fan fault or a temperature limit being exceeded.
 *
 * Step 1):
 *	User(or environmental monitoring software) calls the ioctl routine
 *	which blocks as it waits on a condition. The open(2) call has to be
 *	called with the _control minor node. The ioctl routine requires
 *	ADM1031_INTERRUPT_WAIT as the command and a pointer to an array of
 *	uint8_t as the third argument.
 * Step 2):
 *	A system event occurs which unblocks the ioctl and returns the call
 *	to the user.
 * Step 3):
 *	User reads the contents of the array (which actually contains the values
 *	of the devices' status registers) to determine the exact nature of the
 *	event.
 */
static int
adm1031_i_ioctl(dev_t dev, int cmd, intptr_t arg, int mode)
{
	_NOTE(ARGUNUSED(cmd))
	adm1031_unit_t	*admp;
	uint8_t		i = 0;
	minor_t		minor = getminor(dev);
	int		fcn = ADM1031_MINOR_TO_FCN(minor);
	int		instance = ADM1031_MINOR_TO_INST(minor);
	int		err = 0;
	uint8_t		temp[2];
	uint8_t		temp1;


	if (fcn != ADM1031_CONTROL)
		return (EINVAL);

	admp = (adm1031_unit_t *)
	    ddi_get_soft_state(adm1031_soft_statep, instance);

	if (!(admp->adm1031_flags & ADM1031_INTRFLAG)) {
		cmn_err(CE_WARN, "%s:%d No interrupt handler registered\n",
		    admp->adm1031_name, instance);
		return (EBUSY);
	}

	admp->adm1031_transfer->i2c_flags = I2C_WR_RD;
	admp->adm1031_transfer->i2c_wlen = 1;
	admp->adm1031_transfer->i2c_rlen = 1;

	/*
	 * The register has to be read to clear the previous status.
	 */

	for (i = 0; i < 2; i++) {
		admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_STAT_1_REG;
		if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer)
		    != I2C_SUCCESS) {
			return (EIO);
		}
		temp[0] = admp->adm1031_transfer->i2c_rbuf[0];
		admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_STAT_2_REG;
		if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer)
		    != I2C_SUCCESS) {
			return (EIO);
		}
	}
	temp[1] = admp->adm1031_transfer->i2c_rbuf[0];

	if ((temp[0] != 0) || (temp[1] != 0)) {
		goto copyout;
	}

	/*
	 * Enable the interrupt and fan fault alert.
	 */
	mutex_enter(&admp->adm1031_mutex);
	while (admp->adm1031_flags & ADM1031_BUSYFLAG) {
		if (cv_wait_sig(&admp->adm1031_cv,
		    &admp->adm1031_mutex) <= 0) {
			mutex_exit(&admp->adm1031_mutex);
			return (EINTR);
		}
	}
	admp->adm1031_flags |= ADM1031_BUSYFLAG;

	mutex_exit(&admp->adm1031_mutex);

	admp->adm1031_transfer->i2c_flags = I2C_WR_RD;
	admp->adm1031_transfer->i2c_wlen = 1;
	admp->adm1031_transfer->i2c_rlen = 1;
	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_CONFIG_REG_1;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    I2C_SUCCESS) {
		err = EIO;
		goto err;
	}

	temp1 = admp->adm1031_transfer->i2c_rbuf[0];

	admp->adm1031_transfer->i2c_flags = I2C_WR;
	admp->adm1031_transfer->i2c_wlen = 2;
	admp->adm1031_transfer->i2c_wbuf[1] = (temp1 | 0x12);

	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    I2C_SUCCESS) {
		err = EIO;
		goto err;
	}


	mutex_enter(&admp->adm1031_mutex);
	admp->adm1031_flags = admp->adm1031_flags & (~ADM1031_BUSYFLAG);
	cv_signal(&admp->adm1031_cv);
	mutex_exit(&admp->adm1031_mutex);



	mutex_enter(&admp->adm1031_imutex);
	admp->adm1031_cvwaiting = 1;
	(void) cv_wait_sig(&admp->adm1031_icv, &admp->adm1031_imutex);
	mutex_exit(&admp->adm1031_imutex);


	/*
	 * Disable the interrupt and fan fault alert.
	 */
	mutex_enter(&admp->adm1031_mutex);

	while (admp->adm1031_flags & ADM1031_BUSYFLAG) {
		if (cv_wait_sig(&admp->adm1031_cv,
		    &admp->adm1031_mutex) <= 0) {
			mutex_exit(&admp->adm1031_mutex);
			return (EINTR);
		}
	}
	admp->adm1031_flags |= ADM1031_BUSYFLAG;

	admp->adm1031_transfer->i2c_flags = I2C_WR_RD;
	admp->adm1031_transfer->i2c_wlen = 1;
	admp->adm1031_transfer->i2c_rlen = 1;
	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_CONFIG_REG_1;

	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    I2C_SUCCESS) {
		err = EIO;
		goto err;
	}


	temp1 = admp->adm1031_transfer->i2c_rbuf[0];
	admp->adm1031_transfer->i2c_flags = I2C_WR;
	admp->adm1031_transfer->i2c_wlen = 2;
	admp->adm1031_transfer->i2c_wbuf[1] = (temp1 & (~0x12));

	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    I2C_SUCCESS) {
		err = (EIO);
		goto err;
	}

	admp->adm1031_flags = admp->adm1031_flags & (~ADM1031_BUSYFLAG);
	cv_signal(&admp->adm1031_cv);
	mutex_exit(&admp->adm1031_mutex);

	admp->adm1031_transfer->i2c_flags = I2C_WR_RD;
	admp->adm1031_transfer->i2c_wlen = 1;
	admp->adm1031_transfer->i2c_rlen = 1;
	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_STAT_1_REG;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    I2C_SUCCESS) {

		return (EIO);
	}
	temp[0] = admp->adm1031_transfer->i2c_rbuf[0];

	admp->adm1031_transfer->i2c_wbuf[0] = ADM1031_STAT_2_REG;
	if (i2c_transfer(admp->adm1031_hdl, admp->adm1031_transfer) !=
	    I2C_SUCCESS) {

		return (EIO);
	}
	temp[1] = admp->adm1031_transfer->i2c_rbuf[0];

copyout:
	if (ddi_copyout((void *)&temp, (void *)arg, sizeof (temp),
	    mode) != DDI_SUCCESS) {

		return (EFAULT);
	}

	return (0);

err:
	mutex_enter(&admp->adm1031_mutex);
	admp->adm1031_flags = admp->adm1031_flags & (~ADM1031_BUSYFLAG);
	cv_signal(&admp->adm1031_cv);
	mutex_exit(&admp->adm1031_mutex);

	return (err);
}

static int
adm1031_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	if (cmd == ADM1031_INTERRUPT_WAIT) {
		return (adm1031_i_ioctl(dev, cmd, arg, mode));
	} else {
		return (adm1031_s_ioctl(dev, cmd, arg, mode));
	}
}
