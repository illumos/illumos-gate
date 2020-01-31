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

#include <sys/stat.h>		/* ddi_create_minor_node S_IFCHR */
#include <sys/modctl.h>		/* for modldrv */
#include <sys/open.h>		/* for open params.	 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/conf.h>		/* req. by dev_ops flags MTSAFE etc. */
#include <sys/ddi.h>
#include <sys/file.h>
#include <sys/note.h>
#include <sys/i2c/clients/lm75.h>
#include <sys/i2c/clients/lm75_impl.h>

static void *lm75soft_statep;

static int lm75_do_attach(dev_info_t *);
static int lm75_do_detach(dev_info_t *);
static int lm75_do_resume(void);
static int lm75_do_suspend(void);
static int lm75_get16(intptr_t, int, struct lm75_unit *, int);
static int lm75_set16(intptr_t, int, struct lm75_unit *, int);

/*
 * cb ops (only need ioctl)
 */
static int lm75_open(dev_t *, int, int, cred_t *);
static int lm75_close(dev_t, int, int, cred_t *);
static int lm75_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops lm75_cbops = {
	lm75_open,			/* open  */
	lm75_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	lm75_ioctl,			/* ioctl */
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

/*
 * dev ops
 */
static int lm75_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int lm75_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops lm75_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,
	nulldev,
	lm75_attach,
	lm75_detach,
	nodev,
	&lm75_cbops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv lm75_modldrv = {
	&mod_driverops,			/* type of module - driver */
	"LM75 i2c device driver",
	&lm75_ops
};

static struct modlinkage lm75_modlinkage = {
	MODREV_1,
	&lm75_modldrv,
	0
};


int
_init(void)
{
	int error;

	error = mod_install(&lm75_modlinkage);

	if (!error)
		(void) ddi_soft_state_init(&lm75soft_statep,
		    sizeof (struct lm75_unit), 1);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&lm75_modlinkage);
	if (!error)
		ddi_soft_state_fini(&lm75soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&lm75_modlinkage, modinfop));
}

static int
lm75_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	struct lm75_unit *unitp;
	int instance;
	int error = 0;

	instance = getminor(*devp);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct lm75_unit *)
	    ddi_get_soft_state(lm75soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->lm75_mutex);

	if (flags & FEXCL) {
		if (unitp->lm75_oflag != 0) {
			error = EBUSY;
		} else {
			unitp->lm75_oflag = FEXCL;
		}
	} else {
		if (unitp->lm75_oflag == FEXCL) {
			error = EBUSY;
		} else {
			unitp->lm75_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->lm75_mutex);

	return (error);
}

static int
lm75_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))

	struct lm75_unit *unitp;
	int instance;

	instance = getminor(dev);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct lm75_unit *)
	    ddi_get_soft_state(lm75soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->lm75_mutex);

	unitp->lm75_oflag = 0;

	mutex_exit(&unitp->lm75_mutex);
	return (DDI_SUCCESS);
}

static int
lm75_get16(intptr_t arg, int reg, struct lm75_unit *unitp, int mode)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int err = DDI_SUCCESS;
	int16_t			temp16;
	int8_t			holder;

	(void) i2c_transfer_alloc(unitp->lm75_hdl, &i2c_tran_pointer,
	    1, 2, I2C_SLEEP);
	if (i2c_tran_pointer == NULL) {
		D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_TEMPERATURE "
		    "i2c_tran_pointer not allocated\n", unitp->lm75_name));
		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = I2C_WR_RD;
	i2c_tran_pointer->i2c_wbuf[0] = (uchar_t)reg;

	err = i2c_transfer(unitp->lm75_hdl, i2c_tran_pointer);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_TEMPERATURE "
		    "i2c_transfer routine\n", unitp->lm75_name));
		i2c_transfer_free(unitp->lm75_hdl, i2c_tran_pointer);
		return (err);
	}

	D1CMN_ERR((CE_NOTE, "%s: rbuf[0] =  %x rbuf[1] = %x\n",
	    unitp->lm75_name, i2c_tran_pointer->i2c_rbuf[0],
	    i2c_tran_pointer->i2c_rbuf[0]));
	temp16 = i2c_tran_pointer->i2c_rbuf[0];
	temp16 = (temp16 << 1);
	temp16 = (temp16 | ((i2c_tran_pointer->i2c_rbuf[1] & 0x80) >> 7));


	if (temp16 & LM75_COMP_MASK) {
		holder = (temp16 & LM75_COMP_MASK_UPPER);
		holder = -holder;
		holder = holder/2;
		temp16 = 0 - holder;
	} else {
		temp16 = temp16 / 2;
	}
	if (ddi_copyout((caddr_t)&temp16, (caddr_t)arg,
	    sizeof (int16_t), mode) != DDI_SUCCESS) {
		D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_TEMPERATURE "
		    "ddi_copyout routine\n", unitp->lm75_name));
		err = EFAULT;
	}
	i2c_transfer_free(unitp->lm75_hdl, i2c_tran_pointer);
	return (err);
}

static int
lm75_set16(intptr_t arg, int reg, struct lm75_unit *unitp, int mode)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int err = DDI_SUCCESS;
	int16_t			temp16;

	if (ddi_copyin((caddr_t)arg, (caddr_t)&temp16,
	    sizeof (int16_t), mode) != DDI_SUCCESS) {
		D2CMN_ERR((CE_WARN, "%s: Failed in LM74_SET_HYST "
		    "ddi_copyin routine\n", unitp->lm75_name));
		return (EFAULT);
	}

	(void) i2c_transfer_alloc(unitp->lm75_hdl, &i2c_tran_pointer,
	    3, 0, I2C_SLEEP);
	if (i2c_tran_pointer == NULL) {
		D2CMN_ERR((CE_WARN, "%s: Failed in LM75_SET_HYST "
		    "i2c_tran_pointer not allocated\n", unitp->lm75_name));
		return (ENOMEM);
	}

	/* BEGIN CSTYLED */
	/*
	 * The temperature is 16bits where the top 9 are a twos-complement
	 * word with the the least significant bit used to indicate 0.5C
	 *
	 * |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
	 * |-----------------------------------------------|
	 * |+-|	     Temperature      |	      Unused       |
	 */
	/* END CSTYLED */
	i2c_tran_pointer->i2c_flags = I2C_WR;
	i2c_tran_pointer->i2c_wbuf[0] = (uchar_t)reg;
	i2c_tran_pointer->i2c_wbuf[1] = ((temp16 >> 1) & 0xff);
	i2c_tran_pointer->i2c_wbuf[2] = ((temp16 & 0x1) << 7);

	err = i2c_transfer(unitp->lm75_hdl, i2c_tran_pointer);
	i2c_transfer_free(unitp->lm75_hdl, i2c_tran_pointer);
	return (err);
}

static int
lm75_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	struct lm75_unit	*unitp;
	int			instance;
	int			err = 0;
	i2c_transfer_t		*i2c_tran_pointer;
	uchar_t			passin_byte;

	if (arg == (intptr_t)NULL) {
		D2CMN_ERR((CE_WARN, "LM75: ioctl: arg passed in to ioctl "
		    "= NULL\n"));
		err = EINVAL;
		return (err);
	}
	instance = getminor(dev);
	unitp = (struct lm75_unit *)
	    ddi_get_soft_state(lm75soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "LM75: ioctl: unitp = NULL\n");
		err = ENOMEM;
		return (err);
	}

	mutex_enter(&unitp->lm75_mutex);

	switch (cmd) {
	case I2C_GET_TEMPERATURE:
		err = lm75_get16(arg, LM75_TEMPERATURE_REG, unitp, mode);
		break;

	case LM75_GET_HYST:
		err = lm75_get16(arg, LM75_HYST_REG, unitp, mode);
		break;

	case LM75_SET_HYST:
		err = lm75_set16(arg, LM75_HYST_REG, unitp, mode);
		break;

	case LM75_GET_OVERTEMP_SHUTDOWN:
		err = lm75_get16(arg, LM75_OVERTEMP_REG, unitp, mode);
		break;

	case LM75_SET_OVERTEMP_SHUTDOWN:
		err = lm75_set16(arg, LM75_OVERTEMP_REG, unitp, mode);
		break;

	case LM75_GET_CONFIG:
		(void) i2c_transfer_alloc(unitp->lm75_hdl, &i2c_tran_pointer,
		    1, 1, I2C_SLEEP);
		if (i2c_tran_pointer == NULL) {
			D2CMN_ERR((CE_WARN, "%s: Failed in LM75_GET_CONFIG "
			    "i2c_tran_pointer not allocated\n",
			    unitp->lm75_name));
			err = ENOMEM;
			break;
		}
		i2c_tran_pointer->i2c_flags = I2C_WR_RD;
		i2c_tran_pointer->i2c_wbuf[0] = LM75_CONFIGURATION_REG;

		err = i2c_transfer(unitp->lm75_hdl, i2c_tran_pointer);
		if (err) {
			D2CMN_ERR((CE_WARN, "%s: Failed in LM75_GET_CONFIG "
			    "i2c_transfer routine\n",
			    unitp->lm75_name));
			i2c_transfer_free(unitp->lm75_hdl, i2c_tran_pointer);
			break;
		}
		if (ddi_copyout((caddr_t)i2c_tran_pointer->i2c_rbuf,
		    (caddr_t)arg,
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in LM75_GET_CONFIG "
			    "ddi_copyout routine\n",
			    unitp->lm75_name));
			err = EFAULT;
		}
		i2c_transfer_free(unitp->lm75_hdl, i2c_tran_pointer);
		break;

	case LM75_SET_CONFIG:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&passin_byte,
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in LM75_SET_CONFIG "
			    "ddi_copyin routine\n",
			    unitp->lm75_name));
			err = EFAULT;
			break;
		}
		(void) i2c_transfer_alloc(unitp->lm75_hdl, &i2c_tran_pointer,
		    2, 0, I2C_SLEEP);
		if (i2c_tran_pointer == NULL) {
			D2CMN_ERR((CE_WARN, "%s: Failed in LM75_SET_CONFIG "
			    "i2c_tran_pointer not allocated\n",
			    unitp->lm75_name));
			err = ENOMEM;
			break;
		}
		i2c_tran_pointer->i2c_flags = I2C_WR;
		i2c_tran_pointer->i2c_wbuf[0] = LM75_CONFIGURATION_REG;
		i2c_tran_pointer->i2c_wbuf[1] = passin_byte;

		err = i2c_transfer(unitp->lm75_hdl, i2c_tran_pointer);
		i2c_transfer_free(unitp->lm75_hdl, i2c_tran_pointer);
		break;

	default:
		D2CMN_ERR((CE_WARN, "%s: Invalid IOCTL cmd %x\n",
		    unitp->lm75_name, cmd));
		err = EINVAL;
	}

	mutex_exit(&unitp->lm75_mutex);
	return (err);
}

static int
lm75_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (lm75_do_attach(dip));
	case DDI_RESUME:
		return (lm75_do_resume());
	default:
		return (DDI_FAILURE);
	}
}

static int
lm75_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (lm75_do_detach(dip));
	case DDI_SUSPEND:
		return (lm75_do_suspend());
	default:
		return (DDI_FAILURE);
	}
}

static int
lm75_do_attach(dev_info_t *dip)
{
	struct lm75_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(lm75soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to zalloc softstate\n",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(lm75soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "LM75: ioctl: unitp = NULL\n");
		return (ENOMEM);
	}

	(void) snprintf(unitp->lm75_name, sizeof (unitp->lm75_name),
	    "%s%d", ddi_node_name(dip), instance);

	if (ddi_create_minor_node(dip, "lm75", S_IFCHR, instance,
	    "ddi_i2c:temperature_sensor", 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed for "
		    "%s\n", unitp->lm75_name, "lm75");
		ddi_soft_state_free(lm75soft_statep, instance);

		return (DDI_FAILURE);
	}

	if (i2c_client_register(dip, &unitp->lm75_hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(lm75soft_statep, instance);

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->lm75_mutex, NULL, MUTEX_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
lm75_do_resume(void)
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
lm75_do_suspend()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
lm75_do_detach(dev_info_t *dip)
{
	struct lm75_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	unitp = ddi_get_soft_state(lm75soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "LM75: ioctl: unitp = NULL\n");
		return (ENOMEM);
	}

	i2c_client_unregister(unitp->lm75_hdl);

	ddi_remove_minor_node(dip, NULL);

	mutex_destroy(&unitp->lm75_mutex);
	ddi_soft_state_free(lm75soft_statep, instance);

	return (DDI_SUCCESS);
}
