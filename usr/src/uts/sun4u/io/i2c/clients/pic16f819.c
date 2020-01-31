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

#include <sys/i2c/clients/pic16f819_impl.h>

static void *pic16f819soft_statep;

static int pic16f819_set(struct pic16f819_unit *, int, uchar_t);
static int pic16f819_get(struct pic16f819_unit *, int, uchar_t *, int);


static int pic16f819_do_attach(dev_info_t *);
static int pic16f819_do_detach(dev_info_t *);
static int pic16f819_do_resume(void);
static int pic16f819_do_suspend(void);

/*
 * cb ops (only need ioctl)
 */
static int pic16f819_open(dev_t *, int, int, cred_t *);
static int pic16f819_close(dev_t, int, int, cred_t *);
static int pic16f819_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops pic16f819_cbops = {
	pic16f819_open,			/* open  */
	pic16f819_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pic16f819_ioctl,			/* ioctl */
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
static int pic16f819_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pic16f819_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops pic16f819_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,
	nulldev,
	pic16f819_attach,
	pic16f819_detach,
	nodev,
	&pic16f819_cbops,
	NULL,			/* bus ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv pic16f819_modldrv = {
	&mod_driverops,			/* type of module - driver */
	"PIC16F819 i2c device driver",
	&pic16f819_ops
};

static struct modlinkage pic16f819_modlinkage = {
	MODREV_1,
	&pic16f819_modldrv,
	0
};


int
_init(void)
{
	int error;

	error = mod_install(&pic16f819_modlinkage);

	if (!error)
		(void) ddi_soft_state_init(&pic16f819soft_statep,
		    sizeof (struct pic16f819_unit), 1);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&pic16f819_modlinkage);
	if (!error)
		ddi_soft_state_fini(&pic16f819soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pic16f819_modlinkage, modinfop));
}

static int
pic16f819_get(struct pic16f819_unit *unitp, int reg, uchar_t *byte, int flags)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int			err;

	(void) i2c_transfer_alloc(unitp->pic16f819_hdl, &i2c_tran_pointer,
	    1, 1, flags);
	if (i2c_tran_pointer == NULL) {
		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = I2C_WR_RD;
	i2c_tran_pointer->i2c_wbuf[0] = (uchar_t)reg;
	err = i2c_transfer(unitp->pic16f819_hdl, i2c_tran_pointer);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: pic16f819_get failed reg=%x",
		    unitp->pic16f819_name, reg));
	} else {
		*byte = i2c_tran_pointer->i2c_rbuf[0];
	}

	i2c_transfer_free(unitp->pic16f819_hdl, i2c_tran_pointer);
	return (err);
}

static int
pic16f819_set(struct pic16f819_unit *unitp, int reg, uchar_t byte)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int			err;

	(void) i2c_transfer_alloc(unitp->pic16f819_hdl, &i2c_tran_pointer,
	    2, 0, I2C_SLEEP);
	if (i2c_tran_pointer == NULL) {
		D2CMN_ERR((CE_WARN, "%s: Failed in pic16f819_set "
		"i2c_tran_pointer not allocated", unitp->pic16f819_name));
		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = I2C_WR;
	i2c_tran_pointer->i2c_wbuf[0] = (uchar_t)reg;
	i2c_tran_pointer->i2c_wbuf[1] = byte;
	D1CMN_ERR((CE_NOTE, "%s: set reg %x to %x",
	    unitp->pic16f819_name, reg, byte));

	err = i2c_transfer(unitp->pic16f819_hdl, i2c_tran_pointer);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: Failed in the pic16f819_set"
		    " i2c_transfer routine", unitp->pic16f819_name));
	}
	i2c_transfer_free(unitp->pic16f819_hdl, i2c_tran_pointer);
	return (err);
}

static int
pic16f819_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	struct pic16f819_unit *unitp;
	int instance;
	int error = 0;

	instance = getminor(*devp);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pic16f819_unit *)
	    ddi_get_soft_state(pic16f819soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->pic16f819_mutex);

	if (flags & FEXCL) {
		if (unitp->pic16f819_oflag != 0) {
			error = EBUSY;
		} else {
			unitp->pic16f819_oflag = FEXCL;
		}
	} else {
		if (unitp->pic16f819_oflag == FEXCL) {
			error = EBUSY;
		} else {
			unitp->pic16f819_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->pic16f819_mutex);

	return (error);
}

static int
pic16f819_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))

	struct pic16f819_unit *unitp;
	int instance;

	instance = getminor(dev);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pic16f819_unit *)
	    ddi_get_soft_state(pic16f819soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->pic16f819_mutex);

	unitp->pic16f819_oflag = 0;

	mutex_exit(&unitp->pic16f819_mutex);
	return (DDI_SUCCESS);
}

static int
pic16f819_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	struct pic16f819_unit	*unitp;
	int		instance;
	int			err = 0;
	i2c_reg_t		ioctl_reg;
	uchar_t			val8;

	if (arg == (intptr_t)NULL) {
		D2CMN_ERR((CE_WARN, "PIC16F819: ioctl: arg passed in to ioctl "
		    "= NULL\n"));
		err = EINVAL;
		return (err);
	}
	instance = getminor(dev);
	unitp = (struct pic16f819_unit *)
	    ddi_get_soft_state(pic16f819soft_statep, instance);

	mutex_enter(&unitp->pic16f819_mutex);

	switch (cmd) {

	case I2C_GET_REG:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_reg,
		    sizeof (i2c_reg_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}
		err = pic16f819_get(unitp, ioctl_reg.reg_num, &val8,
		    I2C_SLEEP);
		if (err != I2C_SUCCESS) {
			break;
		}

		ioctl_reg.reg_value = val8;
		if (ddi_copyout((caddr_t)&ioctl_reg, (caddr_t)arg,
		    sizeof (i2c_reg_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
		}
		break;

	case I2C_SET_REG:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_reg,
		    sizeof (i2c_reg_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}
		err = pic16f819_set(unitp, ioctl_reg.reg_num,
		    ioctl_reg.reg_value);
		break;
	default:
		D2CMN_ERR((CE_WARN, "%s: Invalid IOCTL cmd: %x\n",
		    unitp->pic16f819_name, cmd));
		err = EINVAL;
	}

	mutex_exit(&unitp->pic16f819_mutex);
	return (err);
}

static int
pic16f819_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (pic16f819_do_attach(dip));
	case DDI_RESUME:
		return (pic16f819_do_resume());
	default:
		return (DDI_FAILURE);
	}
}

static int
pic16f819_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (pic16f819_do_detach(dip));
	case DDI_SUSPEND:
		return (pic16f819_do_suspend());
	default:
		return (DDI_FAILURE);
	}
}

static int
pic16f819_do_attach(dev_info_t *dip)
{
	struct pic16f819_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(pic16f819soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to zalloc softstate\n",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(pic16f819soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: unitp not filled\n",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	(void) snprintf(unitp->pic16f819_name, sizeof (unitp->pic16f819_name),
	    "%s%d", ddi_node_name(dip), instance);

	if (ddi_create_minor_node(dip, "fan_1", S_IFCHR, instance,
	    "ddi_i2c:pic", 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed for "
		    "%s\n", unitp->pic16f819_name, "pic16f819");
		ddi_soft_state_free(pic16f819soft_statep, instance);

		return (DDI_FAILURE);
	}

	if (i2c_client_register(dip, &unitp->pic16f819_hdl) != I2C_SUCCESS) {
		cmn_err(CE_WARN, "%s i2c_client_register failed\n",
		    unitp->pic16f819_name);
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(pic16f819soft_statep, instance);

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->pic16f819_mutex, NULL, MUTEX_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
pic16f819_do_resume()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
pic16f819_do_suspend()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
pic16f819_do_detach(dev_info_t *dip)
{
	struct pic16f819_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	unitp = ddi_get_soft_state(pic16f819soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: unitp not filled\n",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	i2c_client_unregister(unitp->pic16f819_hdl);

	ddi_remove_minor_node(dip, NULL);

	mutex_destroy(&unitp->pic16f819_mutex);

	ddi_soft_state_free(pic16f819soft_statep, instance);

	return (DDI_SUCCESS);
}
