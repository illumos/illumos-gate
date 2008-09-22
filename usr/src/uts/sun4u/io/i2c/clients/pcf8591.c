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

#include <sys/i2c/clients/pcf8591.h>
#include <sys/i2c/clients/pcf8591_impl.h>

static void *pcf8591soft_statep;

static uint8_t ipmode = PCF8591_4SINGLE;
static int32_t current_value = 0;
static int current_set_flag = 0;

static int pcf8591_do_attach(dev_info_t *);
static int pcf8591_do_detach(dev_info_t *);
static int pcf8591_do_resume(void);
static int pcf8591_do_suspend(void);

/*
 * cb ops (only need ioctl)
 */
static int pcf8591_open(dev_t *, int, int, cred_t *);
static int pcf8591_close(dev_t, int, int, cred_t *);
static int pcf8591_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops pcf8591_cbops = {
	pcf8591_open,			/* open  */
	pcf8591_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pcf8591_ioctl,			/* ioctl */
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
static int pcf8591_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int pcf8591_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pcf8591_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops pcf8591_ops = {
	DEVO_REV,
	0,
	pcf8591_info,
	nulldev,
	nulldev,
	pcf8591_attach,
	pcf8591_detach,
	nodev,
	&pcf8591_cbops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv pcf8591_modldrv = {
	&mod_driverops,			/* type of module - driver */
	"PCF8591 i2c device driver: v1.8",
	&pcf8591_ops
};

static struct modlinkage pcf8591_modlinkage = {
	MODREV_1,
	&pcf8591_modldrv,
	0
};


int
_init(void)
{
	int error;

	error = mod_install(&pcf8591_modlinkage);
	if (!error)
		(void) ddi_soft_state_init(&pcf8591soft_statep,
		    sizeof (struct pcf8591_unit), 1);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&pcf8591_modlinkage);
	if (!error)
		ddi_soft_state_fini(&pcf8591soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pcf8591_modlinkage, modinfop));
}

static int
pcf8591_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	struct pcf8591_unit *unitp;
	int instance;
	int error = 0;

	instance = MINOR_TO_INST(getminor(*devp));

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pcf8591_unit *)
	    ddi_get_soft_state(pcf8591soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->pcf8591_mutex);

	if (flags & FEXCL) {
		if (unitp->pcf8591_oflag != 0) {
			error = EBUSY;
		} else {
			unitp->pcf8591_oflag = FEXCL;
		}
	} else {
		if (unitp->pcf8591_oflag == FEXCL) {
			error = EBUSY;
		} else {
			unitp->pcf8591_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->pcf8591_mutex);

	return (error);
}

static int
pcf8591_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))

	struct pcf8591_unit *unitp;
	int instance;

	instance = MINOR_TO_INST(getminor(dev));

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pcf8591_unit *)
	    ddi_get_soft_state(pcf8591soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->pcf8591_mutex);

	unitp->pcf8591_oflag = 0;

	mutex_exit(&unitp->pcf8591_mutex);
	return (DDI_SUCCESS);
}

static int
pcf8591_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
		cred_t *credp, int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	struct pcf8591_unit	*unitp;
	int			err = 0;
	i2c_transfer_t		*i2c_tran_pointer;
	int port = MINOR_TO_PORT(getminor(dev));
	int instance = MINOR_TO_INST(getminor(dev));
	int autoincr = 0;
	uchar_t control, reg;
	int32_t value;
	uint8_t uvalue;

	if (arg == NULL) {
		D2CMN_ERR((CE_WARN, "PCF8591: ioctl: arg passed in to ioctl "
		    "= NULL\n"));
		err = EINVAL;
		return (err);
	}
	unitp = (struct pcf8591_unit *)
	    ddi_get_soft_state(pcf8591soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "PCF8591: ioctl: unitp not filled\n");
		return (ENOMEM);
	}

	mutex_enter(&unitp->pcf8591_mutex);

	D1CMN_ERR((CE_NOTE, "%s: ioctl: port = %d  instance = %d\n",
	    unitp->pcf8591_name, port, instance));

	switch (cmd) {
	case I2C_GET_INPUT:
		(void) i2c_transfer_alloc(unitp->pcf8591_hdl, &i2c_tran_pointer,
		    1, 2, I2C_SLEEP);
		if (i2c_tran_pointer == NULL) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_INPUT "
			    "i2c_tran_pointer not allocated\n",
			    unitp->pcf8591_name));
			err = ENOMEM;
			break;
		}
		reg = (uchar_t)port;
		if ((reg == 0x02) && (ipmode == PCF8591_2DIFF)) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_INPUT "
			    "cannot use port 2 when ipmode is "
			    "0x03\n", unitp->pcf8591_name));
			err = EIO;
			i2c_transfer_free(unitp->pcf8591_hdl, i2c_tran_pointer);
			break;
		}

		if ((reg == 0x03) && (ipmode != PCF8591_4SINGLE)) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_INPUT "
			    "cannot use port 3 when ipmode is not "
			    "0x00\n", unitp->pcf8591_name));
			err = EIO;
			i2c_transfer_free(unitp->pcf8591_hdl, i2c_tran_pointer);
			break;
		}
		control = ((0 << PCF8591_ANALOG_OUTPUT_SHIFT) |
		    (ipmode << PCF8591_ANALOG_INPUT_SHIFT) |
		    (autoincr << PCF8591_AUTOINCR_SHIFT) | reg);

		i2c_tran_pointer->i2c_flags = I2C_WR_RD;
		i2c_tran_pointer->i2c_wbuf[0] = control;

		err = i2c_transfer(unitp->pcf8591_hdl, i2c_tran_pointer);
		if (err) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_INPUT"
			    " i2c_transfer routine\n",
			    unitp->pcf8591_name));
			i2c_transfer_free(unitp->pcf8591_hdl, i2c_tran_pointer);
			break;
		}
		i2c_tran_pointer->i2c_rbuf[0] = i2c_tran_pointer->i2c_rbuf[1];
		value = i2c_tran_pointer->i2c_rbuf[0];
		D1CMN_ERR((CE_NOTE, "%s: Back from transfer result is %x\n",
		    unitp->pcf8591_name, value));
		if (ddi_copyout((caddr_t)&value,
		    (caddr_t)arg,
		    sizeof (int32_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed I2C_GET_INPUT"
			    " ddi_copyout routine\n",
			    unitp->pcf8591_name));
			err = EFAULT;
		}
		i2c_transfer_free(unitp->pcf8591_hdl, i2c_tran_pointer);
		break;

	case I2C_SET_OUTPUT:
		reg = (uchar_t)port;
		if (ipmode != PCF8591_4SINGLE) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_SET_OUTPUT "
			    "cannot set output when ipmode is not "
			    "0x00\n", unitp->pcf8591_name));
			err = EIO;
			break;
		}

		(void) i2c_transfer_alloc(unitp->pcf8591_hdl, &i2c_tran_pointer,
		    2, 0, I2C_SLEEP);
		if (i2c_tran_pointer == NULL) {
			D2CMN_ERR((CE_WARN, "%s: Failed in "
			    "I2C_SET_OUTPUT "
			    "i2c_tran_pointer not allocated\n",
			    unitp->pcf8591_name));
			err = ENOMEM;
			break;
		}
		if (ddi_copyin((caddr_t)arg, (caddr_t)&value,
		    sizeof (int32_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_SET_OUTPUT"
			    " ddi_copyout routine\n",
			    unitp->pcf8591_name));
			err = EFAULT;
			i2c_transfer_free(unitp->pcf8591_hdl, i2c_tran_pointer);
			break;
		}
		control = ((1 << PCF8591_ANALOG_OUTPUT_SHIFT) |
		    (0 << PCF8591_ANALOG_INPUT_SHIFT) |
		    (autoincr << PCF8591_AUTOINCR_SHIFT) | reg);

		i2c_tran_pointer->i2c_flags = I2C_WR;
		i2c_tran_pointer->i2c_wbuf[0] = control;
		i2c_tran_pointer->i2c_wbuf[1] = (uchar_t)value;

		err = i2c_transfer(unitp->pcf8591_hdl, i2c_tran_pointer);
		if (!err) {
			current_value = value;
			current_set_flag = 1;
		}
		i2c_transfer_free(unitp->pcf8591_hdl, i2c_tran_pointer);
		break;

	case I2C_GET_OUTPUT:
		if (current_set_flag == 0) {
			err = EIO;
			break;
		} else {
			if (ddi_copyout((caddr_t)(uintptr_t)current_value,
			    (caddr_t)arg, sizeof (int32_t), mode)
			    != DDI_SUCCESS) {
				D2CMN_ERR((CE_WARN, "%s: Failed in "
				    "I2C_GET_OUTPUT ddi_copyout routine\n",
				    unitp->pcf8591_name));
				err = EFAULT;
				break;
			}
		}
		break;

	case PCF8591_SET_IPMODE:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&uvalue,
		    sizeof (uint_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in PCF8591_SET_IPMODE"
			    " ddi_copyout routine\n",
			    unitp->pcf8591_name));
			err = EFAULT;
			break;
		}

		if (uvalue > 0x03) {
			D2CMN_ERR((CE_WARN, "%s: Failed in PCF8591_SET_IPMODE"
			    " value is not a valid mode\n",
			    unitp->pcf8591_name));
			err = EIO;
			break;
		}

		ipmode = uvalue;
		break;

	default:
		D2CMN_ERR((CE_WARN, "%s: Invalid IOCTL cmd: %x\n",
		    unitp->pcf8591_name, cmd));
		err = EINVAL;
	}

	mutex_exit(&unitp->pcf8591_mutex);
	return (err);

}

/* ARGSUSED */
static int
pcf8591_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = MINOR_TO_INST(getminor(dev));
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
pcf8591_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (pcf8591_do_attach(dip));
	case DDI_RESUME:
		return (pcf8591_do_resume());
	default:
		return (DDI_FAILURE);
	}
}

static int
pcf8591_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (pcf8591_do_detach(dip));
	case DDI_SUSPEND:
		return (pcf8591_do_suspend());
	default:
		return (DDI_FAILURE);
	}
}

static int
pcf8591_do_attach(dev_info_t *dip)
{
	struct pcf8591_unit *unitp;
	int instance;
	char name[MAXNAMELEN];
	minor_t minor_number;
	int i;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(pcf8591soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to zalloc softstate\n",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(pcf8591soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: unitp not filled\n",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	(void) snprintf(unitp->pcf8591_name, sizeof (unitp->pcf8591_name),
	    "%s%d", ddi_node_name(dip), instance);

	for (i = 0; i < 4; i++) {
		(void) sprintf(name, "port_%d", i);

		minor_number = INST_TO_MINOR(instance) |
		    PORT_TO_MINOR(I2C_PORT(i));

		if (ddi_create_minor_node(dip, name, S_IFCHR, minor_number,
		    "ddi_i2c:adio", NULL) == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s ddi_create_minor_node failed for "
			    "%s\n", unitp->pcf8591_name, name);
			ddi_soft_state_free(pcf8591soft_statep, instance);

			return (DDI_FAILURE);
		}
	}

	if (i2c_client_register(dip, &unitp->pcf8591_hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(pcf8591soft_statep, instance);

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->pcf8591_mutex, NULL, MUTEX_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
pcf8591_do_resume()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
pcf8591_do_suspend()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
pcf8591_do_detach(dev_info_t *dip)
{
	struct pcf8591_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	unitp = ddi_get_soft_state(pcf8591soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: unitp not filled\n",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	i2c_client_unregister(unitp->pcf8591_hdl);

	ddi_remove_minor_node(dip, NULL);

	mutex_destroy(&unitp->pcf8591_mutex);

	ddi_soft_state_free(pcf8591soft_statep, instance);

	return (DDI_SUCCESS);
}
