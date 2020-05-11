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

#include <sys/i2c/clients/ssc100_impl.h>

static void *ssc100soft_statep;

static int ssc100_do_attach(dev_info_t *);
static int ssc100_do_detach(dev_info_t *);
static int ssc100_do_resume(void);
static int ssc100_do_suspend(void);
static int ssc100_get(struct ssc100_unit *, uchar_t *);
static int ssc100_set(struct ssc100_unit *, uchar_t);
static int ssc100_get_reg(struct ssc100_unit *, uchar_t *, uchar_t);
static int ssc100_common(struct ssc100_unit *, uchar_t *, uchar_t, int8_t);
static int ssc100_read(dev_t, struct uio *, cred_t *);
static int ssc100_write(dev_t, struct uio *, cred_t *);
static int ssc100_io(dev_t, struct uio *, int);

/*
 * cb ops (only need ioctl)
 */
static int ssc100_open(dev_t *, int, int, cred_t *);
static int ssc100_close(dev_t, int, int, cred_t *);
static int ssc100_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops ssc100_cbops = {
	ssc100_open,			/* open  */
	ssc100_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	ssc100_read,			/* read */
	ssc100_write,			/* write */
	ssc100_ioctl,			/* ioctl */
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
static int ssc100_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int ssc100_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops ssc100_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,
	nulldev,
	ssc100_attach,
	ssc100_detach,
	nodev,
	&ssc100_cbops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv ssc100_modldrv = {
	&mod_driverops,			/* type of module - driver */
	"SSC100 i2c device driver",
	&ssc100_ops
};

static struct modlinkage ssc100_modlinkage = {
	MODREV_1,
	&ssc100_modldrv,
	0
};


int
_init(void)
{
	int error;

	error = mod_install(&ssc100_modlinkage);

	if (!error)
		(void) ddi_soft_state_init(&ssc100soft_statep,
		    sizeof (struct ssc100_unit), 1);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&ssc100_modlinkage);
	if (!error)
		ddi_soft_state_fini(&ssc100soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ssc100_modlinkage, modinfop));
}

static int
ssc100_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	struct ssc100_unit *unitp;
	int instance;
	int error = 0;

	instance = getminor(*devp);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct ssc100_unit *)
	    ddi_get_soft_state(ssc100soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->ssc100_mutex);

	if (flags & FEXCL) {
		if (unitp->ssc100_oflag != 0) {
			error = EBUSY;
		} else {
			unitp->ssc100_oflag = FEXCL;
		}
	} else {
		if (unitp->ssc100_oflag == FEXCL) {
			error = EBUSY;
		} else {
			unitp->ssc100_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->ssc100_mutex);

	return (error);
}

static int
ssc100_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))

	struct ssc100_unit *unitp;
	int instance;

	instance = getminor(dev);

	if (instance < 0) {
		return (ENXIO);
	}
	unitp = (struct ssc100_unit *)
	    ddi_get_soft_state(ssc100soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->ssc100_mutex);

	unitp->ssc100_oflag = 0;

	mutex_exit(&unitp->ssc100_mutex);
	return (DDI_SUCCESS);
}

static int
ssc100_common(struct ssc100_unit *unitp, uchar_t *byte, uchar_t input,
    int8_t flag)
{
	i2c_transfer_t		*i2c_tran_pointer;
	int			err = I2C_SUCCESS;

	(void) i2c_transfer_alloc(unitp->ssc100_hdl, &i2c_tran_pointer,
	    1, 1, I2C_SLEEP);
	if (i2c_tran_pointer == NULL) {
		D2CMN_ERR((CE_WARN, "%s: Failed in SSC100_COMMON "
		    "i2c_tran_pointer not allocated",
		    unitp->ssc100_name));
		return (ENOMEM);
	}

	i2c_tran_pointer->i2c_flags = flag;
	if (flag != I2C_RD) {
		i2c_tran_pointer->i2c_wbuf[0] = input;
	}

	err = i2c_transfer(unitp->ssc100_hdl, i2c_tran_pointer);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: Failed in SSC100_COMMON "
		    "i2c_transfer routine", unitp->ssc100_name));
	} else if (flag != I2C_WR) {
		*byte = i2c_tran_pointer->i2c_rbuf[0];
	}

	i2c_transfer_free(unitp->ssc100_hdl, i2c_tran_pointer);
	return (err);
}

static int
ssc100_get_reg(struct ssc100_unit *unitp, uchar_t *byte, uchar_t reg)
{
	int			err = I2C_SUCCESS;

	err = ssc100_common(unitp, byte, reg, I2C_WR_RD);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: Failed in SSC100_GET_REG "
		    "i2c_common routine", unitp->ssc100_name));
	}
	return (err);
}

static int
ssc100_get(struct ssc100_unit *unitp, uchar_t *byte)
{
	int			err = I2C_SUCCESS;

	err = ssc100_common(unitp, byte, 0, I2C_RD);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: Failed in SSC100_GET "
		    "i2c_common routine", unitp->ssc100_name));
	}
	return (err);
}

static int
ssc100_set(struct ssc100_unit *unitp, uchar_t byte)
{
	int			err = I2C_SUCCESS;

	err = ssc100_common(unitp, NULL, byte, I2C_WR);
	if (err) {
		D2CMN_ERR((CE_WARN, "%s: Failed in SSC100_SET "
		    "i2c_common routine", unitp->ssc100_name));
	}
	return (err);
}

static int
ssc100_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	struct ssc100_unit	*unitp;
	int		instance;
	int			err = 0;
	i2c_bit_t		ioctl_bit;
	i2c_port_t		ioctl_port;
	i2c_reg_t ioctl_reg;
	uchar_t			byte;

	if (arg == (intptr_t)NULL) {
		D2CMN_ERR((CE_WARN, "SSC100: ioctl: arg passed in to ioctl "
		    "= NULL"));
		err = EINVAL;
		return (err);
	}

	instance = getminor(dev);
	unitp = (struct ssc100_unit *)
	    ddi_get_soft_state(ssc100soft_statep, instance);
	if (unitp == NULL) {
		cmn_err(CE_WARN, "SSC100: ioctl: unitp not filled");
		return (ENOMEM);
	}

	mutex_enter(&unitp->ssc100_mutex);

	switch (cmd) {
	case I2C_GET_PORT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_port,
		    sizeof (i2c_port_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_GET_PORT"
			    " ddi_copyin routine", unitp->ssc100_name));
			err = EFAULT;
			break;
		}

		err = ssc100_get(unitp, &byte);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_GET_PORT"
			    " ssc100_get routine", unitp->ssc100_name));
			break;
		}

		ioctl_port.value = byte;
		if (ddi_copyout((caddr_t)&ioctl_port, (caddr_t)arg,
		    sizeof (i2c_port_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_PORT "
			    "ddi_copyout routine", unitp->ssc100_name));
			err = EFAULT;
		}

		D1CMN_ERR((CE_NOTE, "%s: contains %x", unitp->ssc100_name,
		    byte));
		break;

	case I2C_SET_PORT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_port,
		    sizeof (uint8_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_SET_PORT"
			    "ddi_cpoyin routine", unitp->ssc100_name));
			err = EFAULT;
			break;
		}

		err = ssc100_set(unitp, ioctl_port.value);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_SET_PORT"
			    " ssc100_set routine", unitp->ssc100_name));
			break;
		}
		break;

	case I2C_GET_BIT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_bit,
		    sizeof (i2c_bit_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_GET_BIT"
			    " ddi_copyin routine", unitp->ssc100_name));
			err = EFAULT;
			break;
		}

		if (ioctl_bit.bit_num > 7) {
			D2CMN_ERR((CE_WARN, "%s: In I2C_GET_BIT bit num"
			    " was not between 0 and 7",
			    unitp->ssc100_name));
			err = EIO;
			break;
		}

		err = ssc100_get(unitp, &byte);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_GET_BIT"
			    " ssc100_get routine", unitp->ssc100_name));
			break;
		}

		D1CMN_ERR((CE_NOTE, "%s: byte returned from device is %x",
		    unitp->ssc100_name, byte));
		ioctl_bit.bit_value = (boolean_t)SSC100_BIT_READ_MASK(byte,
		    ioctl_bit.bit_num);
		D1CMN_ERR((CE_NOTE, "%s: byte now contains %x",
		    unitp->ssc100_name, byte));

		if (ddi_copyout((caddr_t)&ioctl_bit, (caddr_t)arg,
		    sizeof (i2c_bit_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_BIT"
			    " ddi_copyout routine", unitp->ssc100_name));
			err = EFAULT;
		}
		break;

	case I2C_SET_BIT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_bit,
		    sizeof (i2c_bit_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_SET_BIT"
			    " ddi_copyin routine", unitp->ssc100_name));
			err = EFAULT;
			break;
		}

		if (ioctl_bit.bit_num > 7) {
			D2CMN_ERR((CE_WARN, "%s: I2C_SET_BIT: bit_num sent"
			    " in was not between 0 and 7",
			    unitp->ssc100_name));
			err = EIO;
			break;
		}

		err = ssc100_get(unitp, &byte);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_SET_BIT"
			    " ssc100_get routine", unitp->ssc100_name));
			break;
		}

		D1CMN_ERR((CE_NOTE, "%s: byte returned from device is %x",
		    unitp->ssc100_name, byte));
		byte = SSC100_BIT_WRITE_MASK(byte, ioctl_bit.bit_num,
		    ioctl_bit.bit_value);
		D1CMN_ERR((CE_NOTE, "%s: byte after shifting is %x",
		    unitp->ssc100_name, byte));

		err = ssc100_set(unitp, byte);
		if (err != I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in the I2C_SET_BIT"
			    " ssc100_set routine", unitp->ssc100_name));
			break;
		}
		break;

	case I2C_GET_REG:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ioctl_reg,
		    sizeof (i2c_reg_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_REG "
			    "ddi_copyin routine", unitp->ssc100_name));
			err = EFAULT;
			break;
		}

		err = ssc100_get_reg(unitp, &byte, ioctl_reg.reg_num);

		ioctl_reg.reg_value = byte;
		if (ddi_copyout((caddr_t)&ioctl_reg, (caddr_t)arg,
		    sizeof (i2c_reg_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in I2C_GET_REG "
			    "ddi_copyout routine", unitp->ssc100_name));
			err = EFAULT;
		}
		break;

	default:
		D2CMN_ERR((CE_WARN, "%s: Invalid IOCTL cmd: %x",
		    unitp->ssc100_name, cmd));
		err = EINVAL;
	}

	mutex_exit(&unitp->ssc100_mutex);
	return (err);
}

static int
ssc100_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (ssc100_do_attach(dip));
	case DDI_RESUME:
		return (ssc100_do_resume());
	default:
		return (DDI_FAILURE);
	}
}

static int
ssc100_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (ssc100_do_detach(dip));
	case DDI_SUSPEND:
		return (ssc100_do_suspend());
	default:
		return (DDI_FAILURE);
	}
}

static int
ssc100_do_attach(dev_info_t *dip)
{
	struct ssc100_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(ssc100soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to zalloc softstate",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(ssc100soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: unitp not filled",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	(void) snprintf(unitp->ssc100_name, sizeof (unitp->ssc100_name),
	    "%s%d", ddi_node_name(dip), instance);

	if (ddi_create_minor_node(dip, "ssc100", S_IFCHR, instance,
	    "ddi_i2c:ioexp", 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed for "
		    "%s", unitp->ssc100_name, "ssc100");
		ddi_soft_state_free(ssc100soft_statep, instance);

		return (DDI_FAILURE);
	}

	/*
	 * If we had different sizes in the future, this could be read
	 * from a property.
	 */
	unitp->ssc100_size = SSC100_SIZE;

	(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
	    DDI_PROP_CANSLEEP, "size",
	    (caddr_t)&unitp->ssc100_size, sizeof (unitp->ssc100_size));

	if (i2c_client_register(dip, &unitp->ssc100_hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(ssc100soft_statep, instance);

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->ssc100_mutex, NULL, MUTEX_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
ssc100_do_resume()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
ssc100_do_suspend()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
ssc100_do_detach(dev_info_t *dip)
{
	struct ssc100_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	unitp = ddi_get_soft_state(ssc100soft_statep, instance);

	i2c_client_unregister(unitp->ssc100_hdl);

	ddi_remove_minor_node(dip, NULL);

	mutex_destroy(&unitp->ssc100_mutex);

	ddi_soft_state_free(ssc100soft_statep, instance);

	return (DDI_SUCCESS);

}

static int
ssc100_read(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	_NOTE(ARGUNUSED(cred_p))

	return (ssc100_io(dev, uiop, B_READ));
}

static int
ssc100_write(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	_NOTE(ARGUNUSED(cred_p))

	return (ssc100_io(dev, uiop, B_WRITE));
}

static int
ssc100_io(dev_t dev, struct uio *uiop, int rw)
{
	struct ssc100_unit *unitp;
	int instance = getminor(dev);
	int	ssc100_addr;
	int	bytes_to_rw;
	int	err = 0;
	int	current_xfer_len;
	i2c_transfer_t *i2ctp = NULL;

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct ssc100_unit *)
	    ddi_get_soft_state(ssc100soft_statep, instance);


	if (unitp == NULL) {
		return (ENXIO);
	}

	if (uiop->uio_offset >= unitp->ssc100_size) {
		/*
		 * Exceeded ssc100 size.
		 */
		if (rw == B_WRITE) {

			return (ENOSPC);
		}
		return (0);
	}

	ssc100_addr = uiop->uio_offset;

	if (uiop->uio_resid == 0) {
		return (0);
	}

	bytes_to_rw = min(uiop->uio_resid,
	    unitp->ssc100_size - uiop->uio_offset);
	current_xfer_len = bytes_to_rw;

	if (rw == B_WRITE) {
		(void) i2c_transfer_alloc(unitp->ssc100_hdl, &i2ctp,
		    current_xfer_len+1, 0, I2C_SLEEP);
		if (i2ctp == NULL) {
			D2CMN_ERR((CE_WARN, "%s: Failed in ssc100_io WRITE "
			    "i2c_tran_pointer not allocated",
			    unitp->ssc100_name));
			return (ENOMEM);
		}
		i2ctp->i2c_version = I2C_XFER_REV;
		i2ctp->i2c_flags = I2C_WR;
		i2ctp->i2c_wbuf[0] = (uchar_t)ssc100_addr;
		if ((err = uiomove(&i2ctp->i2c_wbuf[1], current_xfer_len,
		    UIO_WRITE, uiop)) != 0) {
			D2CMN_ERR((CE_WARN, "%s: Failed in ssc100_io WRITE "
			    "uiomove failed", unitp->ssc100_name));
			goto end;
		}

		if ((err = i2c_transfer(unitp->ssc100_hdl, i2ctp)) !=
		    I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in ssc100_io WRITE "
			    "i2c_transfer failed", unitp->ssc100_name));
			goto end;
		}
	} else {
		/*
		 * SSC100 read.  We need to first write out the address
		 * that we wish to read.
		 */
		(void) i2c_transfer_alloc(unitp->ssc100_hdl, &i2ctp, 1,
		    current_xfer_len, I2C_SLEEP);
		if (i2ctp == NULL) {
			D2CMN_ERR((CE_WARN, "%s: Failed in ssc100_io READ "
			    "i2c_tran_pointer not allocated",
			    unitp->ssc100_name));
			return (ENOMEM);
		}
		i2ctp->i2c_version = I2C_XFER_REV;
		i2ctp->i2c_wbuf[0] = (uchar_t)ssc100_addr;
		i2ctp->i2c_flags = I2C_WR_RD;

		if ((err = i2c_transfer(unitp->ssc100_hdl, i2ctp)) !=
		    I2C_SUCCESS) {
			D2CMN_ERR((CE_WARN, "%s: Failed in ssc100_io READ "
			    "i2c_transfer failed", unitp->ssc100_name));
			goto end;
		}

		if ((err = uiomove(i2ctp->i2c_rbuf, current_xfer_len,
		    UIO_READ, uiop)) != 0) {
			D2CMN_ERR((CE_WARN, "%s: Failed in ssc100_io READ "
			    "uiomove failed", unitp->ssc100_name));
			goto end;
		}
	}

end:
	i2c_transfer_free(unitp->ssc100_hdl, i2ctp);
	return (err);
}
