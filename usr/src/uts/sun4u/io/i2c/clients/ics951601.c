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
#include <sys/note.h>
#include <sys/i2c/misc/i2c_svc.h>
#include <sys/i2c/clients/ics951601.h>
#include <sys/i2c/clients/ics951601_impl.h>

/*
 * This is the client driver for the ics951601 device which is a general
 * purpose clock generator.  Setting a clock to 1 enables the clock while
 * setting it to 0 disables it.  All clocks are enabled by default by
 * the driver.  The user can read a clock, enable it or disable it.
 * The command sent as an ioctl argument should be the bitwise OR of the
 * clock number and the action upon it.  The supported clock numbers and
 * actions are defined in ics951601.h.  A pointer to an integer is sent
 * as the third  ioctl argument.  If the clock is to be read the value of the
 * clock is copied into it and if it is to be modified the integer referred
 * to should have the appropriate value of either 1 or 0.
 */

/*
 * cb ops
 */
static int ics951601_open(dev_t *, int, int, cred_t *);
static int ics951601_close(dev_t, int, int, cred_t *);
static int ics951601_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * dev ops
 */
static int ics951601_s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int ics951601_s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int ics951601_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

static struct cb_ops ics951601_cb_ops = {
	ics951601_open,			/* open */
	ics951601_close,		/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	ics951601_ioctl,		/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
};

static struct dev_ops ics951601_dev_ops = {
	DEVO_REV,
	0,
	ics951601_info,
	nulldev,
	nulldev,
	ics951601_s_attach,
	ics951601_s_detach,
	nodev,
	&ics951601_cb_ops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv ics951601_modldrv = {
	&mod_driverops,		/* type of module - driver */
	"ics951601 device driver",
	&ics951601_dev_ops,
};

static struct modlinkage ics951601_modlinkage = {
	MODREV_1,
	&ics951601_modldrv,
	0
};

/*
 * Writes to the clock generator involve sending the dummy command code, the
 * dummy byte count followed by byte 0 through byte 5. The dummy command code
 * and the dummy byte count are ignored by the ICS clock but must be sent.
 *
 * On reading from the clock generator, the controller will first receive a
 * byte count followed by byte 0 through byte 5.
 */

/*
 * The array for initializing the internal registers at attach time.
 */
static uchar_t init_clock_regs[8] = {
	0x0,	/* Dummy command code */
	0x7,	/* Dummy byte count */
	0x0,	/* Initial value for functionality register */
	0xff,	/* Initial value for PCI1A stop clocks register */
	0xff,	/* Initial value for PCI2A stop clocks register */
	0xff,	/* Initial value for PCI2B stop clocks register */
	0xff,	/* Default value for reserved register */
	0xef	/* Default value for latched input read back register */
};

static void *ics951601_soft_statep;
int ics951601_debug = 0;

int
_init(void)
{
	int    err;

	err = mod_install(&ics951601_modlinkage);
	if (err == 0) {
		(void) ddi_soft_state_init(&ics951601_soft_statep,
		    sizeof (ics951601_unit_t), 1);
	}
	return (err);
}

int
_fini(void)
{
	int    err;

	err = mod_remove(&ics951601_modlinkage);
	if (err == 0) {
		ddi_soft_state_fini(&ics951601_soft_statep);
	}
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ics951601_modlinkage, modinfop));
}

static int
ics951601_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int			instance;
	ics951601_unit_t	*icsp;
	int			err = EBUSY;

	/*
	 * Make sure the open is for the right file type
	 */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	instance = getminor(*devp);
	if (instance < 0) {
		return (ENXIO);
	}
	icsp = (ics951601_unit_t *)ddi_get_soft_state(ics951601_soft_statep,
	    instance);
	if (icsp == NULL) {
		return (ENXIO);
	}

	/* must be privileged to access this device */
	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	/*
	 * Enforce exclusive access if required
	 */
	mutex_enter(&icsp->ics951601_mutex);
	if (flags & FEXCL) {
		if (icsp->ics951601_oflag == 0) {
			icsp->ics951601_oflag = FEXCL;
			err = DDI_SUCCESS;
		}
	} else if (icsp->ics951601_oflag != FEXCL) {
		icsp->ics951601_oflag = (uint16_t)FOPEN;
		err = DDI_SUCCESS;
	}
	mutex_exit(&icsp->ics951601_mutex);
	return (err);
}

static int
ics951601_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, credp))

	int		instance;
	ics951601_unit_t 	*icsp;

	/*
	 * 	Make sure the close is for the right file type
	 */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	instance = getminor(dev);
	icsp = (ics951601_unit_t *)ddi_get_soft_state(ics951601_soft_statep,
	    instance);
	if (icsp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&icsp->ics951601_mutex);
	icsp->ics951601_oflag = 0;
	mutex_exit(&icsp->ics951601_mutex);
	return (DDI_SUCCESS);
}

static int
ics951601_attach(dev_info_t *dip)
{
	ics951601_unit_t 	*icsp;
	int 			instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(ics951601_soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d failed to zalloc softstate",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	icsp = ddi_get_soft_state(ics951601_soft_statep, instance);

	if (icsp == NULL) {
		return (DDI_FAILURE);
	}

	mutex_init(&icsp->ics951601_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&icsp->ics951601_cv, NULL, CV_DRIVER, NULL);

	(void) snprintf(icsp->ics951601_name, sizeof (icsp->ics951601_name),
	    "%s_%d", ddi_driver_name(dip), instance);


	if (ddi_create_minor_node(dip, icsp->ics951601_name, S_IFCHR,
	    instance, ICS951601_NODE_TYPE, NULL) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed",
		    icsp->ics951601_name);
		goto ATTACH_ERR;
	}

	/*
	 * preallocate a single buffer for all reads and writes
	 */
	if (i2c_transfer_alloc(icsp->ics951601_hdl, &icsp->ics951601_transfer,
	    0, 0, I2C_SLEEP) != I2C_SUCCESS) {
		cmn_err(CE_WARN, "%s i2c_transfer_alloc failed",
		    icsp->ics951601_name);
		goto CREATE_NODE_ERR;
	}
	icsp->ics951601_cpr_state[0] = 0x0;
	icsp->ics951601_transfer->i2c_version = I2C_XFER_REV;

	if (i2c_client_register(dip, &icsp->ics951601_hdl) != I2C_SUCCESS) {
		cmn_err(CE_WARN, "%s i2c_client_register failed",
		    icsp->ics951601_name);
		goto ALLOC_ERR;
	}

	/* Enable all clocks */
	icsp->ics951601_transfer->i2c_flags = I2C_WR;
	icsp->ics951601_transfer->i2c_wlen = ICS951601_I2C_WRITE_TRANS_SIZE;
	icsp->ics951601_transfer->i2c_rlen = 0;
	icsp->ics951601_transfer->i2c_wbuf = init_clock_regs;

	if (i2c_transfer(icsp->ics951601_hdl, icsp->ics951601_transfer)
	    != I2C_SUCCESS) {
		goto REG_ERR;
	}

	/*
	 * Store the dip for future use
	 */
	icsp->ics951601_dip = dip;

	return (DDI_SUCCESS);
REG_ERR:
	i2c_client_unregister(icsp->ics951601_hdl);

ALLOC_ERR:
	i2c_transfer_free(icsp->ics951601_hdl, icsp->ics951601_transfer);

CREATE_NODE_ERR:
	ddi_remove_minor_node(dip, NULL);

ATTACH_ERR:
	cv_destroy(&icsp->ics951601_cv);
	mutex_destroy(&icsp->ics951601_mutex);
	ddi_soft_state_free(ics951601_soft_statep, instance);

	return (DDI_FAILURE);
}


static void
ics951601_detach(dev_info_t *dip)
{
	ics951601_unit_t *icsp;
	int 		instance;

	instance = ddi_get_instance(dip);
	icsp = ddi_get_soft_state(ics951601_soft_statep, instance);
	cv_destroy(&icsp->ics951601_cv);
	mutex_destroy(&icsp->ics951601_mutex);
	i2c_client_unregister(icsp->ics951601_hdl);
	i2c_transfer_free(icsp->ics951601_hdl, icsp->ics951601_transfer);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(ics951601_soft_statep, instance);
}

static int
ics951601_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip))

	ics951601_unit_t	*icsp;
	int			instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		icsp = ddi_get_soft_state(ics951601_soft_statep, instance);
		if (icsp == NULL) {
			return (DDI_FAILURE);
		}
		*result = (void *)icsp->ics951601_dip;

		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;

		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
ics951601_suspend(dev_info_t *dip)
{
	ics951601_unit_t 	*icsp;
	int		instance = ddi_get_instance(dip);

	icsp = ddi_get_soft_state(ics951601_soft_statep, instance);

	/*
	 * Set the busy flag so that future transactions block
	 * until resume.
	 */
	mutex_enter(&icsp->ics951601_mutex);
	while ((icsp->ics951601_flags & ICS951601_BUSYFLAG) ==
	    ICS951601_BUSYFLAG) {
		if (cv_wait_sig(&icsp->ics951601_cv,
		    &icsp->ics951601_mutex) <= 0) {
			mutex_exit(&icsp->ics951601_mutex);
			return (DDI_FAILURE);
		}
	}
	icsp->ics951601_flags |= ICS951601_BUSYFLAG;
	mutex_exit(&icsp->ics951601_mutex);

	icsp->ics951601_transfer->i2c_flags = I2C_RD;
	icsp->ics951601_transfer->i2c_wlen = 0;
	icsp->ics951601_transfer->i2c_rlen = ICS951601_I2C_READ_TRANS_SIZE;
	icsp->ics951601_transfer->i2c_rbuf = icsp->ics951601_cpr_state + 1;

	if (i2c_transfer(icsp->ics951601_hdl, icsp->ics951601_transfer)
	    != I2C_SUCCESS) {
		cmn_err(CE_WARN, "%s Suspend failed, unable to save registers",
		    icsp->ics951601_name);
		return (EIO);
	}
	return (DDI_SUCCESS);
}


static int
ics951601_resume(dev_info_t *dip)
{
	int 		instance = ddi_get_instance(dip);
	ics951601_unit_t	*icsp;
	int 		err = DDI_SUCCESS;

	icsp = (ics951601_unit_t *)
	    ddi_get_soft_state(ics951601_soft_statep, instance);

	if (icsp == NULL) {
		return (ENXIO);
	}

	/*
	 * Restore registers to status existing before cpr
	 */
	icsp->ics951601_transfer->i2c_flags = I2C_WR;
	icsp->ics951601_transfer->i2c_rlen = 0;
	icsp->ics951601_transfer->i2c_wlen = ICS951601_I2C_WRITE_TRANS_SIZE;

	icsp->ics951601_transfer->i2c_wbuf = icsp->ics951601_cpr_state;

	if (i2c_transfer(icsp->ics951601_hdl, icsp->ics951601_transfer)
	    != I2C_SUCCESS) {
		err = EIO;
		cmn_err(CE_WARN, " %s Unable to restore registers",
		    icsp->ics951601_name);
	}

	/*
	 * Clear busy flag so that transactions may continue
	 */
	mutex_enter(&icsp->ics951601_mutex);
	icsp->ics951601_flags = icsp->ics951601_flags & ~ICS951601_BUSYFLAG;
	cv_signal(&icsp->ics951601_cv);
	mutex_exit(&icsp->ics951601_mutex);
	return (err);
}

static int
ics951601_s_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (ics951601_attach(dip));
	case DDI_RESUME:
		return (ics951601_resume(dip));
	default:
		return (DDI_FAILURE);
	}
}

static int
ics951601_s_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		ics951601_detach(dip);
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (ics951601_suspend(dip));
	default:
		return (DDI_FAILURE);
	}
}

static int
ics951601_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	ics951601_unit_t		*icsp;
	int			err = 0;
	uchar_t			temp_arr[ICS951601_I2C_WRITE_TRANS_SIZE];
	int			reg_no;
	uint8_t			clock_bit;
	int			ics_temp;
	int			instance = getminor(dev);

	temp_arr[0] = 0x0;

	icsp = (ics951601_unit_t *)
	    ddi_get_soft_state(ics951601_soft_statep, instance);

	if (ics951601_debug) {
		printf("ics951601_ioctl: instance=%d\n", instance);
	}

	/*
	 * We serialize here and  block if there are pending transacations .
	 */
	mutex_enter(&icsp->ics951601_mutex);
	while ((icsp->ics951601_flags & ICS951601_BUSYFLAG) ==
	    ICS951601_BUSYFLAG) {
		if (cv_wait_sig(&icsp->ics951601_cv,
		    &icsp->ics951601_mutex) <= 0) {
			mutex_exit(&icsp->ics951601_mutex);
			return (EINTR);
		}
	}
	icsp->ics951601_flags |= ICS951601_BUSYFLAG;
	mutex_exit(&icsp->ics951601_mutex);

	reg_no	= ICS951601_CMD_TO_CLOCKREG(cmd);
	clock_bit = ICS951601_CMD_TO_CLOCKBIT(cmd);

	icsp->ics951601_transfer->i2c_flags = I2C_RD;
	icsp->ics951601_transfer->i2c_wlen = 0;
	icsp->ics951601_transfer->i2c_rlen = ICS951601_I2C_READ_TRANS_SIZE;
	icsp->ics951601_transfer->i2c_rbuf = temp_arr + 1;

	if (i2c_transfer(icsp->ics951601_hdl, icsp->ics951601_transfer)
	    != I2C_SUCCESS) {

		err = DDI_FAILURE;
		goto cleanup;
	}
	switch (ICS951601_CMD_TO_ACTION(cmd)) {
	case ICS951601_READ_CLOCK:
		temp_arr[reg_no] &= clock_bit;
		ics_temp = temp_arr[reg_no] ? ICS951601_CLOCK_SET:
		    ICS951601_CLOCK_CLEAR;
		err = ddi_copyout((caddr_t)&ics_temp, (caddr_t)arg,
		    sizeof (int), mode);
		goto cleanup;
	case ICS951601_MODIFY_CLOCK:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ics_temp,
		    sizeof (int), mode) != DDI_SUCCESS) {
			err = EIO;
			goto cleanup;
		}
		if (ics_temp == ICS951601_CLOCK_SET) {
			temp_arr[reg_no] |= clock_bit;
		} else if (ics_temp == ICS951601_CLOCK_CLEAR) {
			temp_arr[reg_no] &= ~clock_bit;
		} else {
			cmn_err(CE_WARN, "%s Clock can only be set to 1 or 0",
			    icsp->ics951601_name);
			err = EINVAL;
			goto cleanup;
		}
		break;
	default:
		err = EINVAL;
		goto cleanup;
	}

	icsp->ics951601_transfer->i2c_flags = I2C_WR;
	icsp->ics951601_transfer->i2c_wlen = ICS951601_I2C_WRITE_TRANS_SIZE;
	icsp->ics951601_transfer->i2c_rlen = 0;
	icsp->ics951601_transfer->i2c_wbuf = temp_arr;

	if (i2c_transfer(icsp->ics951601_hdl, icsp->ics951601_transfer)
	    != I2C_SUCCESS) {

		err = DDI_FAILURE;
		goto cleanup;
	}
cleanup:
	mutex_enter(&icsp->ics951601_mutex);
	icsp->ics951601_flags  = icsp->ics951601_flags & ~ICS951601_BUSYFLAG;
	cv_signal(&icsp->ics951601_cv);
	mutex_exit(&icsp->ics951601_mutex);
	return (err);
}
