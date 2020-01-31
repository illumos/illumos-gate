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

#include <sys/i2c/clients/pcf8574_impl.h>

static void *pcf8574soft_statep;

static int pcf8574_do_attach(dev_info_t *);
static int pcf8574_do_detach(dev_info_t *);
static int pcf8574_do_resume(void);
static int pcf8574_do_suspend(void);
static int pcf8574_get(struct pcf8574_unit *, uchar_t *);
static int pcf8574_set(struct pcf8574_unit *, uchar_t);

/*
 * cb ops (only need ioctl)
 */
static int pcf8574_open(dev_t *, int, int, cred_t *);
static int pcf8574_close(dev_t, int, int, cred_t *);
static int pcf8574_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops pcf8574_cbops = {
	pcf8574_open,			/* open  */
	pcf8574_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pcf8574_ioctl,			/* ioctl */
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
static int pcf8574_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pcf8574_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops pcf8574_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,
	nulldev,
	pcf8574_attach,
	pcf8574_detach,
	nodev,
	&pcf8574_cbops,
	NULL,			/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv pcf8574_modldrv = {
	&mod_driverops,			/* type of module - driver */
	"PCF8574 i2c device driver",
	&pcf8574_ops
};

static struct modlinkage pcf8574_modlinkage = {
	MODREV_1,
	&pcf8574_modldrv,
	0
};


int
_init(void)
{
	int error;

	error = mod_install(&pcf8574_modlinkage);

	if (!error)
		(void) ddi_soft_state_init(&pcf8574soft_statep,
		    sizeof (struct pcf8574_unit), 1);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&pcf8574_modlinkage);
	if (!error)
		ddi_soft_state_fini(&pcf8574soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pcf8574_modlinkage, modinfop));
}

static int
pcf8574_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	struct pcf8574_unit *unitp;
	int instance;
	int error = 0;

	D1CMN_ERR((CE_WARN, "Opening the PCF8574 device\n"));

	instance = getminor(*devp);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct pcf8574_unit *)
	    ddi_get_soft_state(pcf8574soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->pcf8574_mutex);

	if (flags & FEXCL) {
		if (unitp->pcf8574_oflag != 0) {
			error = EBUSY;
		} else {
			unitp->pcf8574_oflag = FEXCL;
		}
	} else {
		if (unitp->pcf8574_oflag == FEXCL) {
			error = EBUSY;
		} else {
			unitp->pcf8574_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->pcf8574_mutex);

	return (error);
}

static int
pcf8574_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))

	struct pcf8574_unit *unitp;
	int instance;

	instance = getminor(dev);

	if (instance < 0) {
		return (ENXIO);
	}
	unitp = (struct pcf8574_unit *)
	    ddi_get_soft_state(pcf8574soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->pcf8574_mutex);

	unitp->pcf8574_oflag = 0;

	mutex_exit(&unitp->pcf8574_mutex);
	return (DDI_SUCCESS);
}

static int
pcf8574_get(struct pcf8574_unit *unitp, uchar_t *byte)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int			err = I2C_SUCCESS;

	D1CMN_ERR((CE_WARN, "Entered the pcf8574_get routine\n"));

	(void) i2c_transfer_alloc(unitp->pcf8574_hdl, &i2c_tran_pointer,
	    0, 1, I2C_SLEEP);
	if (i2c_tran_pointer == NULL) {
		D2CMN_ERR((CE_WARN, "%s: Failed in pcf8574_get "
		    "i2c_tran_pointer not allocated\n",
		    unitp->pcf8574_name));
		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = I2C_RD;
	err = i2c_transfer(unitp->pcf8574_hdl, i2c_tran_pointer);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: Failed in the i2c_transfer routine\n",
		    unitp->pcf8574_name));
		i2c_transfer_free(unitp->pcf8574_hdl, i2c_tran_pointer);
		return (err);
	}

	D1CMN_ERR((CE_WARN, "Back from a transfer value is %x\n",
	    i2c_tran_pointer->i2c_rbuf[0]));
	*byte = i2c_tran_pointer->i2c_rbuf[0];

	i2c_transfer_free(unitp->pcf8574_hdl, i2c_tran_pointer);
	return (err);
}

static int
pcf8574_set(struct pcf8574_unit *unitp, uchar_t byte)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int			err = I2C_SUCCESS;

	(void) i2c_transfer_alloc(unitp->pcf8574_hdl, &i2c_tran_pointer,
	    1, 0, I2C_SLEEP);
	if (i2c_tran_pointer == NULL) {
		D2CMN_ERR((CE_WARN, "%s: Failed in pcf8574_set "
		    "i2c_tran_pointer not allocated\n",
		    unitp->pcf8574_name));
		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = I2C_WR;
	i2c_tran_pointer->i2c_wbuf[0] = byte;
	D1CMN_ERR((CE_NOTE, "%s: contains %x\n", unitp->pcf8574_name,
	    i2c_tran_pointer->i2c_wbuf[0]));

	err = i2c_transfer(unitp->pcf8574_hdl, i2c_tran_pointer);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: Failed in the pcf8574_set"
		    " i2c_transfer routine\n",
		    unitp->pcf8574_name));
		i2c_transfer_free(unitp->pcf8574_hdl, i2c_tran_pointer);
		return (err);
	}
	i2c_transfer_free(unitp->pcf8574_hdl, i2c_tran_pointer);
	return (err);
}

static int
pcf8574_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	struct pcf8574_unit	*unitp;
	int		instance;
	int			err = 0;
	i2c_bit_t		ioctl_bit;
	i2c_port_t		ioctl_port;
	uchar_t			byte;

	if (arg == (intptr_t)NULL) {
		D2CMN_ERR((CE_WARN, "PCF8574: ioctl: arg passed in to ioctl "
		    "= NULL\n"));
		err = EINVAL;
		return (err);
	}

	instance = getminor(dev);
	unitp = (struct pcf8574_unit *)
	    ddi_get_soft_state(pcf8574soft_statep, instance);
	if (unitp == NULL) {
		cmn_err(CE_WARN, "PCF8574: ioctl: unitp not filled\n");
		return (ENOMEM);
	}

	mutex_enter(&unitp->pcf8574_mutex);

	switch (cmd) {
	case I2C_GET_PORT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_port,
		    sizeof (i2c_port_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_GET_PORT"
			    " ddi_copyin routine\n",
			    unitp->pcf8574_name));
			err = EFAULT;
			break;
		}

		err = pcf8574_get(unitp, &byte);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_GET_PORT"
			    " pcf8574_get routine\n",
			    unitp->pcf8574_name));
			break;
		}

		ioctl_port.value = byte;
		if (ddi_copyout((caddr_t)&ioctl_port, (caddr_t)arg,
		    sizeof (i2c_port_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_PORT "
			    "ddi_copyout routine\n",
			    unitp->pcf8574_name));
			err = EFAULT;
		}

		D1CMN_ERR((CE_NOTE, "%s: contains %x\n", unitp->pcf8574_name,
		    byte));
		break;

	case I2C_SET_PORT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_port,
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_SET_PORT"
			    "ddi_cpoyin routine\n",
			    unitp->pcf8574_name));
			err = EFAULT;
			break;
		}

		err = pcf8574_set(unitp, ioctl_port.value);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_SET_PORT"
			    " pcf8574_set routine\n",
			    unitp->pcf8574_name));
			break;
		}
		break;

	case I2C_GET_BIT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_bit,
		    sizeof (i2c_bit_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_GET_BIT"
			    " ddi_copyin routine\n",
			    unitp->pcf8574_name));
			err = EFAULT;
			break;
		}

		if (ioctl_bit.bit_num > 7) {
			D2CMN_ERR((CE_WARN, "%s: In I2C_GET_BIT bit num"
			    " was not between 0 and 7\n",
			    unitp->pcf8574_name));
			err = EIO;
			break;
		}

		err = pcf8574_get(unitp, &byte);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_GET_BIT"
			    " pcf8574_get routine\n",
			    unitp->pcf8574_name));
			break;
		}

		D1CMN_ERR((CE_NOTE, "%s: byte returned from device is %x\n",
		    unitp->pcf8574_name, byte));
		ioctl_bit.bit_value = (boolean_t)PCF8574_BIT_READ_MASK(byte,
		    ioctl_bit.bit_num);
		D1CMN_ERR((CE_NOTE, "%s: byte now contains %x\n",
		    unitp->pcf8574_name, byte));

		if (ddi_copyout((caddr_t)&ioctl_bit, (caddr_t)arg,
		    sizeof (i2c_bit_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_BIT"
			    " ddi_copyout routine\n",
			    unitp->pcf8574_name));
			err = EFAULT;
		}
		break;

	case I2C_SET_BIT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_bit,
		    sizeof (i2c_bit_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_SET_BIT"
			    " ddi_copyin routine\n",
			    unitp->pcf8574_name));
			err = EFAULT;
			break;
		}

		if (ioctl_bit.bit_num > 7) {
			D2CMN_ERR((CE_WARN, "%s: I2C_SET_BIT: bit_num sent"
			    " in was not between 0 and 7",
			    unitp->pcf8574_name));
			err = EIO;
			break;
		}

		err = pcf8574_get(unitp, &byte);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_SET_BIT"
			    " pcf8574_get routine\n",
			    unitp->pcf8574_name));
			break;
		}

		D1CMN_ERR((CE_NOTE, "%s: byte returned from device is %x\n",
		    unitp->pcf8574_name, byte));
		byte = PCF8574_BIT_WRITE_MASK(byte, ioctl_bit.bit_num,
		    ioctl_bit.bit_value);
		D1CMN_ERR((CE_NOTE, "%s: byte after shifting is %x\n",
		    unitp->pcf8574_name, byte));

		err = pcf8574_set(unitp, byte);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_SET_BIT"
			    " pcf8574_set routine\n",
			    unitp->pcf8574_name));
			break;
		}
		break;

	default:
		D2CMN_ERR((CE_WARN, "%s: Invalid IOCTL cmd: %x\n",
		    unitp->pcf8574_name, cmd));
		err = EINVAL;
	}

	mutex_exit(&unitp->pcf8574_mutex);
	return (err);
}

static int
pcf8574_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (pcf8574_do_attach(dip));
	case DDI_RESUME:
		return (pcf8574_do_resume());
	default:
		return (DDI_FAILURE);
	}
}

static int
pcf8574_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (pcf8574_do_detach(dip));
	case DDI_SUSPEND:
		return (pcf8574_do_suspend());
	default:
		return (DDI_FAILURE);
	}
}

static int
pcf8574_do_attach(dev_info_t *dip)
{
	struct pcf8574_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(pcf8574soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to zalloc softstate\n",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(pcf8574soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: unitp not filled\n",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	(void) snprintf(unitp->pcf8574_name, sizeof (unitp->pcf8574_name),
	    "%s%d", ddi_node_name(dip), instance);


	if (ddi_create_minor_node(dip, "pcf8574", S_IFCHR, instance,
	    "ddi_i2c:ioexp", 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed for "
		    "%s\n", unitp->pcf8574_name, "pcf8574");
		ddi_soft_state_free(pcf8574soft_statep, instance);

		return (DDI_FAILURE);
	}

	if (i2c_client_register(dip, &unitp->pcf8574_hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(pcf8574soft_statep, instance);

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->pcf8574_mutex, NULL, MUTEX_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
pcf8574_do_resume()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
pcf8574_do_suspend()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
pcf8574_do_detach(dev_info_t *dip)
{
	struct pcf8574_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	unitp = ddi_get_soft_state(pcf8574soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: unitp not filled\n",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	i2c_client_unregister(unitp->pcf8574_hdl);

	ddi_remove_minor_node(dip, NULL);

	mutex_destroy(&unitp->pcf8574_mutex);

	ddi_soft_state_free(pcf8574soft_statep, instance);

	return (DDI_SUCCESS);

}
