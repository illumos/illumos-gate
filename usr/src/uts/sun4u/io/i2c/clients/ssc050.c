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
#include <sys/sunddi.h>
#include <sys/conf.h>		/* req. by dev_ops flags MTSAFE etc. */
#include <sys/ddi.h>
#include <sys/file.h>
#include <sys/note.h>
#include <sys/i2c/clients/i2c_client.h>
#include <sys/i2c/clients/ssc050.h>

#define	SSC050_NUM_PORTS		5
#define	SSC050_DATADIRECTION_REG(port)	(0x10 | (port))
#define	SSC050_COUNT_REG(port)		(0x32 | ((port) << 2))
#define	SSC050_GP_REG(port)		(port)
#define	SSC050_BIT_REG(port, bit)	(SSC050_PORT_BIT_REG(port) | (bit))

#define	SSC050_FAN_SPEED(div, count)	(1200000 / ((count) * (1<<(div))))
#define	SSC050_FAN_CONTROL_ENABLE	0x80
#define	SSC050_FAN_CONTROL_DIVISOR	0x03

#define	SSC050_DATADIRECTION_BIT	0x02

struct ssc050_unit {
	kmutex_t		mutex;
	int			oflag;
	i2c_client_hdl_t	hdl;
	char			name[12];
};

#ifdef DEBUG

static int ssc050debug = 0;
#define	D1CMN_ERR(ARGS) if (ssc050debug & 0x01) cmn_err ARGS;
#define	D2CMN_ERR(ARGS) if (ssc050debug & 0x02) cmn_err ARGS;
#define	D3CMN_ERR(ARGS) if (ssc050debug & 0x04) cmn_err ARGS;

#else

#define	D1CMN_ERR(ARGS)
#define	D2CMN_ERR(ARGS)
#define	D3CMN_ERR(ARGS)

#endif

static void *ssc050soft_statep;

static int ssc050_do_attach(dev_info_t *);
static int ssc050_do_detach(dev_info_t *);
static int ssc050_set(struct ssc050_unit *, int, uchar_t);
static int ssc050_get(struct ssc050_unit *, int, uchar_t *, int);

/*
 * cb ops
 */
static int ssc050_open(dev_t *, int, int, cred_t *);
static int ssc050_close(dev_t, int, int, cred_t *);
static int ssc050_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);


static struct cb_ops ssc050_cbops = {
	ssc050_open,			/* open  */
	ssc050_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	ssc050_ioctl,			/* ioctl */
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
static int ssc050_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int ssc050_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int ssc050_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops ssc050_ops = {
	DEVO_REV,
	0,
	ssc050_info,
	nulldev,
	nulldev,
	ssc050_attach,
	ssc050_detach,
	nodev,
	&ssc050_cbops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv ssc050_modldrv = {
	&mod_driverops,			/* type of module - driver */
	"SSC050 i2c device driver",
	&ssc050_ops
};

static struct modlinkage ssc050_modlinkage = {
	MODREV_1,
	&ssc050_modldrv,
	0
};


int
_init(void)
{
	int error;

	error = mod_install(&ssc050_modlinkage);

	if (!error)
		(void) ddi_soft_state_init(&ssc050soft_statep,
		    sizeof (struct ssc050_unit), 1);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&ssc050_modlinkage);
	if (!error)
		ddi_soft_state_fini(&ssc050soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ssc050_modlinkage, modinfop));
}

static int
ssc050_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	struct ssc050_unit *unitp;
	int instance;
	int error = 0;

	instance = MINOR_TO_INST(getminor(*devp));

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct ssc050_unit *)
	    ddi_get_soft_state(ssc050soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->mutex);

	if (flags & FEXCL) {
		if (unitp->oflag != 0) {
			error = EBUSY;
		} else {
			unitp->oflag = FEXCL;
		}
	} else {
		if (unitp->oflag == FEXCL) {
			error = EBUSY;
		} else {
			unitp->oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->mutex);

	return (error);
}

static int
ssc050_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))

	struct ssc050_unit *unitp;
	int instance;

	instance = MINOR_TO_INST(getminor(dev));

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct ssc050_unit *)
	    ddi_get_soft_state(ssc050soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->mutex);

	unitp->oflag = 0;

	mutex_exit(&unitp->mutex);
	return (DDI_SUCCESS);
}

static int
ssc050_get(struct ssc050_unit *unitp, int reg, uchar_t *byte, int flags)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int			err;

	(void) i2c_transfer_alloc(unitp->hdl, &i2c_tran_pointer,
	    1, 1, flags);
	if (i2c_tran_pointer == NULL) {
		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = I2C_WR_RD;
	i2c_tran_pointer->i2c_wbuf[0] = (uchar_t)reg;
	err = i2c_transfer(unitp->hdl, i2c_tran_pointer);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: ssc050_get failed reg=%x",
		    unitp->name, reg));
	} else {
		*byte = i2c_tran_pointer->i2c_rbuf[0];
	}

	i2c_transfer_free(unitp->hdl, i2c_tran_pointer);
	return (err);
}

static int
ssc050_set(struct ssc050_unit *unitp, int reg, uchar_t byte)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int			err;

	(void) i2c_transfer_alloc(unitp->hdl, &i2c_tran_pointer,
	    2, 0, I2C_SLEEP);
	if (i2c_tran_pointer == NULL) {
		D2CMN_ERR((CE_WARN, "%s: Failed in ssc050_set "
		    "i2c_tran_pointer not allocated", unitp->name));
		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = I2C_WR;
	i2c_tran_pointer->i2c_wbuf[0] = (uchar_t)reg;
	i2c_tran_pointer->i2c_wbuf[1] = byte;
	D1CMN_ERR((CE_NOTE, "%s: set reg %x to %x", unitp->name, reg, byte));

	err = i2c_transfer(unitp->hdl, i2c_tran_pointer);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: Failed in the ssc050_set"
		    " i2c_transfer routine", unitp->name));
	}
	i2c_transfer_free(unitp->hdl, i2c_tran_pointer);
	return (err);
}

static int
ssc050_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	struct ssc050_unit	*unitp;
	int			err = 0;
	i2c_bit_t		ioctl_bit;
	i2c_port_t		ioctl_port;
	i2c_reg_t		ioctl_reg;
	int port = MINOR_TO_PORT(getminor(dev));
	int instance = MINOR_TO_INST(getminor(dev));
	uchar_t			reg, val8;
	uchar_t			control;
	uchar_t			fan_count;
	int			divisor;
	int32_t			fan_speed;
	uint8_t			inverted_mask;

	if (arg == (intptr_t)NULL) {
		D2CMN_ERR((CE_WARN, "SSC050: ioctl: arg passed in to ioctl "
		    "= NULL"));
		return (EINVAL);
	}
	unitp = (struct ssc050_unit *)
	    ddi_get_soft_state(ssc050soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->mutex);

	D3CMN_ERR((CE_NOTE, "%s: ioctl: port = %d", unitp->name, port));

	switch (cmd) {
	case I2C_GET_PORT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_port,
		    sizeof (i2c_port_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}

		if (ioctl_port.direction == DIR_INPUT) {
			reg = SSC050_DATADIRECTION_REG(port);

			err = ssc050_get(unitp, reg, &val8, I2C_SLEEP);
			if (err != I2C_SUCCESS) {
				break;
			}

			if (val8 != ioctl_port.dir_mask) {
				D2CMN_ERR((CE_NOTE, "GET_PORT sleeping! "
				    "wanted %x, had %x",
				    ioctl_port.dir_mask, val8));
				err = ssc050_set(unitp, reg,
				    ioctl_port.dir_mask);
				if (err != I2C_SUCCESS) {
					break;
				}
				delay(10);
			}
		}

		err = ssc050_get(unitp, port, &val8, I2C_SLEEP);
		if (err != I2C_SUCCESS) {
			break;
		}
		ioctl_port.value = val8;
		if (ddi_copyout((caddr_t)&ioctl_port, (caddr_t)arg,
		    sizeof (i2c_port_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
		}
		break;

	case I2C_SET_PORT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_port,
		    sizeof (i2c_port_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}

		reg = SSC050_DATADIRECTION_REG(port);

		err = ssc050_get(unitp, reg, &val8, I2C_SLEEP);
		if (err != I2C_SUCCESS) {
			break;
		}

		D1CMN_ERR((CE_NOTE, "%s: ioctl: Data Direction Register "
		    "contains %x", unitp->name, val8));

		inverted_mask = ioctl_port.dir_mask ^ 0xff;
		val8 = val8 & inverted_mask;

		D1CMN_ERR((CE_NOTE, "%s: ioctl: Data Direction Register "
		    "NOW contains %x", unitp->name, val8));

		err = ssc050_set(unitp, reg, val8);
		if (err != I2C_SUCCESS) {
			break;
		}

		err = ssc050_get(unitp, port, &val8, I2C_SLEEP);
		if (err != I2C_SUCCESS) {
			break;
		}

		D1CMN_ERR((CE_NOTE, "%s: ioctl: GP Register "
		    "contains %x", unitp->name, val8));

		val8 = val8 & inverted_mask;
		val8 = val8 | ioctl_port.value;

		D1CMN_ERR((CE_NOTE, "%s: ioctl: GP Register "
		    "NOW contains %x", unitp->name, val8));

		err = ssc050_set(unitp, SSC050_GP_REG(port), val8);
		break;

	case I2C_GET_FAN_SPEED:
		err = ssc050_get(unitp, SSC050_FAN_CONTROL_REG(port),
		    &control, I2C_SLEEP);
		if (err != I2C_SUCCESS) {
			break;
		}

		D1CMN_ERR((CE_NOTE, "%s: port %d: control = %x", unitp->name,
		    port, control));

		if (!(control & SSC050_FAN_CONTROL_ENABLE)) {
			err = EIO;
			break;
		}

		err = ssc050_get(unitp, SSC050_COUNT_REG(port), &fan_count,
		    I2C_SLEEP);
		if (err != I2C_SUCCESS) {
			break;
		}

		if (fan_count == 0) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_FAN_SPEED "
			    "i2c_rbuf = 0", unitp->name));
			err = EIO;
			break;
		}
		if (fan_count == 0xff) {
			fan_speed = 0;
			if (ddi_copyout((caddr_t)&fan_speed, (caddr_t)arg,
			    sizeof (int32_t), mode) != DDI_SUCCESS) {
				err = EFAULT;
				break;
			}
			break;
		}

		divisor = control & SSC050_FAN_CONTROL_DIVISOR;
		fan_speed = SSC050_FAN_SPEED(divisor, fan_count);
		if (ddi_copyout((caddr_t)&fan_speed, (caddr_t)arg,
		    sizeof (int32_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
		}
		break;

	case I2C_GET_BIT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_bit,
		    sizeof (i2c_bit_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}

		if (ioctl_bit.bit_num > 7) {
			err = EINVAL;
			break;
		}

		reg = (uchar_t)SSC050_BIT_REG(port, ioctl_bit.bit_num);
		D3CMN_ERR((CE_NOTE, "%s: reg = %x", unitp->name, reg));

		if (ioctl_bit.direction == DIR_INPUT) {
			err = ssc050_get(unitp, reg, &val8, I2C_SLEEP);
			if (err != I2C_SUCCESS) {
				break;
			}

			if (!(val8 & SSC050_DATADIRECTION_BIT)) {
				D2CMN_ERR((CE_NOTE, "GET_PORT sleeping! "
				    "wanted %x, had %x",
				    val8 | SSC050_DATADIRECTION_BIT,
				    val8));
				err = ssc050_set(unitp, reg,
				    val8 | SSC050_DATADIRECTION_BIT);
				if (err != I2C_SUCCESS) {
					break;
				}
				delay(10);
			}
		}

		err = ssc050_get(unitp, reg, &val8, I2C_SLEEP);
		if (err != I2C_SUCCESS) {
			break;
		}
		D3CMN_ERR((CE_NOTE, "byte back from device = %x", val8));
		val8 = val8 & 0x01;
		ioctl_bit.bit_value = (boolean_t)val8;
		if (ddi_copyout((caddr_t)&ioctl_bit, (caddr_t)arg,
		    sizeof (i2c_bit_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
		}
		break;

	case I2C_SET_BIT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_bit,
		    sizeof (i2c_bit_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}

		if (ioctl_bit.bit_num > 7) {
			err = EINVAL;
			break;
		}

		reg = (uchar_t)SSC050_BIT_REG(port, ioctl_bit.bit_num);
		D3CMN_ERR((CE_NOTE, "%s: reg = %x", unitp->name, reg));

		val8 = (uchar_t)ioctl_bit.bit_value;
		err = ssc050_set(unitp, reg, val8);
		break;

	case I2C_GET_REG:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_reg,
		    sizeof (i2c_reg_t), mode) != DDI_SUCCESS) {
			err = EFAULT;
			break;
		}
		err = ssc050_get(unitp, ioctl_reg.reg_num, &val8,
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
		err = ssc050_set(unitp, ioctl_reg.reg_num,
		    ioctl_reg.reg_value);
		break;

	default:
		D2CMN_ERR((CE_WARN, "%s: Invalid IOCTL cmd: %x",
		    unitp->name, cmd));
		err = EINVAL;
	}

	mutex_exit(&unitp->mutex);
	return (err);
}

/* ARGSUSED */
static int
ssc050_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
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
ssc050_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (ssc050_do_attach(dip));
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
ssc050_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (ssc050_do_detach(dip));

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
ssc050_do_attach(dev_info_t *dip)
{
	struct ssc050_unit	*unitp;
	int			instance;
	char			name[MAXNAMELEN];
	minor_t			minor_number;
	int			i;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(ssc050soft_statep, instance) != 0) {
		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(ssc050soft_statep, instance);

	(void) snprintf(unitp->name, sizeof (unitp->name),
	    "%s%d", ddi_node_name(dip), instance);

	for (i = 0; i < SSC050_NUM_PORTS; i++) {
		(void) sprintf(name, "port_%d", i);

		minor_number = INST_TO_MINOR(instance) |
		    PORT_TO_MINOR(I2C_PORT(i));

		if (ddi_create_minor_node(dip, name, S_IFCHR, minor_number,
		"ddi_i2c:ioexp", 0) == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s: failed to create node for %s",
			    unitp->name, name);
			ddi_soft_state_free(ssc050soft_statep, instance);
			return (DDI_FAILURE);
		}
	}

	if (i2c_client_register(dip, &unitp->hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(ssc050soft_statep, instance);
		return (DDI_FAILURE);
	}

	mutex_init(&unitp->mutex, NULL, MUTEX_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
ssc050_do_detach(dev_info_t *dip)
{
	struct ssc050_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);
	unitp = ddi_get_soft_state(ssc050soft_statep, instance);
	i2c_client_unregister(unitp->hdl);
	ddi_remove_minor_node(dip, NULL);
	mutex_destroy(&unitp->mutex);
	ddi_soft_state_free(ssc050soft_statep, instance);

	return (DDI_SUCCESS);
}

int
ssc050_get_port_bit(dev_info_t *dip, int port, int bit, uchar_t *rval,
    int flags)
{
	struct ssc050_unit	*unitp;
	int			instance;
	int			reg = (uchar_t)SSC050_BIT_REG(port, bit);

	if (rval == NULL || dip == NULL)
		return (EINVAL);

	instance = ddi_get_instance(dip);
	unitp = ddi_get_soft_state(ssc050soft_statep, instance);
	if (unitp == NULL) {
		return (ENXIO);
	}
	return (ssc050_get(unitp, reg, rval, flags));
}
