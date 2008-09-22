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

#include <sys/i2c/clients/ltc1427_impl.h>

static void *ltc1427soft_statep;


static int ltc1427_do_attach(dev_info_t *);
static int ltc1427_do_detach(dev_info_t *);
static int ltc1427_do_resume(void);
static int ltc1427_do_suspend(void);

/*
 * cb ops (only need ioctl)
 */
static int ltc1427_open(dev_t *, int, int, cred_t *);
static int ltc1427_close(dev_t, int, int, cred_t *);
static int ltc1427_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops ltc1427_cbops = {
	ltc1427_open,			/* open  */
	ltc1427_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	ltc1427_ioctl,			/* ioctl */
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
static int ltc1427_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int ltc1427_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops ltc1427_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,
	nulldev,
	ltc1427_attach,
	ltc1427_detach,
	nodev,
	&ltc1427_cbops,
	NULL,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv ltc1427_modldrv = {
	&mod_driverops,			/* type of module - driver */
	"LTC1427 i2c device driver: v1.8",
	&ltc1427_ops
};

static struct modlinkage ltc1427_modlinkage = {
	MODREV_1,
	&ltc1427_modldrv,
	0
};


int
_init(void)
{
	int error;

	error = mod_install(&ltc1427_modlinkage);

	if (!error)
		(void) ddi_soft_state_init(&ltc1427soft_statep,
		    sizeof (struct ltc1427_unit), 1);
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&ltc1427_modlinkage);
	if (!error)
		ddi_soft_state_fini(&ltc1427soft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ltc1427_modlinkage, modinfop));
}

static int
ltc1427_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))

	struct ltc1427_unit *unitp;
	int instance;
	int error = 0;

	instance = getminor(*devp);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct ltc1427_unit *)
	    ddi_get_soft_state(ltc1427soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&unitp->ltc1427_mutex);

	if (flags & FEXCL) {
		if (unitp->ltc1427_oflag != 0) {
			error = EBUSY;
		} else {
			unitp->ltc1427_oflag = FEXCL;
		}
	} else {
		if (unitp->ltc1427_oflag == FEXCL) {
			error = EBUSY;
		} else {
			unitp->ltc1427_oflag = FOPEN;
		}
	}

	mutex_exit(&unitp->ltc1427_mutex);

	return (error);
}

static int
ltc1427_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))

	struct ltc1427_unit *unitp;
	int instance;

	instance = getminor(dev);

	if (instance < 0) {
		return (ENXIO);
	}

	unitp = (struct ltc1427_unit *)
	    ddi_get_soft_state(ltc1427soft_statep, instance);

	if (unitp == NULL) {
		return (ENXIO);
	}

	mutex_enter(&unitp->ltc1427_mutex);

	unitp->ltc1427_oflag = 0;

	mutex_exit(&unitp->ltc1427_mutex);
	return (DDI_SUCCESS);
}

static int
ltc1427_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
		cred_t *credp, int *rvalp)
{
	_NOTE(ARGUNUSED(credp, rvalp))

	struct ltc1427_unit 	*unitp;
	int 		instance;
	int 			err = 0;
	i2c_transfer_t		*i2c_tran_pointer;
	int32_t			fan_speed;

	if (arg == NULL) {
		D2CMN_ERR((CE_WARN, "LTC1427: ioctl: arg passed in to ioctl "
		    "= NULL\n"));
		err = EINVAL;
		return (err);
	}
	instance = getminor(dev);
	unitp = (struct ltc1427_unit *)
	    ddi_get_soft_state(ltc1427soft_statep, instance);

	mutex_enter(&unitp->ltc1427_mutex);

	switch (cmd) {
	case I2C_GET_OUTPUT:
		D1CMN_ERR((CE_NOTE, "current_set_flag = %d\n",
		    unitp->current_set_flag));
		if (unitp->current_set_flag == 0) {
			err = EIO;
			break;
		} else {
			if (ddi_copyout((caddr_t)&unitp->current_value,
			    (caddr_t)arg, sizeof (int32_t),
			    mode) != DDI_SUCCESS) {
				D2CMN_ERR((CE_WARN,
				"%s: Failed in I2C_GET_OUTPUT "
				"ddi_copyout routine\n",
				    unitp->ltc1427_name));
				err = EFAULT;
				break;
			}
		}
		break;

	case I2C_SET_OUTPUT:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&fan_speed,
		    sizeof (int32_t), mode) != DDI_SUCCESS) {
			D2CMN_ERR((CE_WARN,
			    "%s: Failed in I2C_SET_OUTPUT "
			    "ioctl before switch\n",
			    unitp->ltc1427_name));
			err = EFAULT;
			break;
		}

		(void) i2c_transfer_alloc(unitp->ltc1427_hdl,
		    &i2c_tran_pointer, 2, 0, I2C_SLEEP);
		if (i2c_tran_pointer == NULL) {
			D2CMN_ERR((CE_WARN,
			    "%s: Failed in I2C_SET_OUTPUT "
			    "i2c_transfer_pointer not allocated\n",
			    unitp->ltc1427_name));
			err = ENOMEM;
			break;
		}
		i2c_tran_pointer->i2c_flags = I2C_WR;
		i2c_tran_pointer->i2c_wbuf[0] =
		    (uchar_t)((fan_speed >> 8) & 0x03);
		i2c_tran_pointer->i2c_wbuf[1] =
		    (uchar_t)((fan_speed) & 0x000000ff);

		err = i2c_transfer(unitp->ltc1427_hdl, i2c_tran_pointer);
		if (!err) {
			unitp->current_value = fan_speed;
			unitp->current_set_flag = 1;
		}
		i2c_transfer_free(unitp->ltc1427_hdl, i2c_tran_pointer);
		break;

	default:
		D2CMN_ERR((CE_WARN, "%s: Invalid IOCTL cmd: %x\n",
		    unitp->ltc1427_name, cmd));
		err = EINVAL;
	}

	mutex_exit(&unitp->ltc1427_mutex);
	return (err);
}

static int
ltc1427_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (ltc1427_do_attach(dip));
	case DDI_RESUME:
		return (ltc1427_do_resume());
	default:
		return (DDI_FAILURE);
	}
}

static int
ltc1427_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (ltc1427_do_detach(dip));
	case DDI_SUSPEND:
		return (ltc1427_do_suspend());
	default:
		return (DDI_FAILURE);
	}
}

static int
ltc1427_do_attach(dev_info_t *dip)
{
	struct ltc1427_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(ltc1427soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to zalloc softstate\n",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(ltc1427soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: unitp not filled\n",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	(void) snprintf(unitp->ltc1427_name, sizeof (unitp->ltc1427_name),
	    "%s%d", ddi_node_name(dip), instance);

	if (ddi_create_minor_node(dip, "ltc1427", S_IFCHR, instance,
	    "ddi_i2c:adio",	NULL) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed for "
		    "%s\n", unitp->ltc1427_name, "ltc1427");
		ddi_soft_state_free(ltc1427soft_statep, instance);

		return (DDI_FAILURE);
	}

	if (i2c_client_register(dip, &unitp->ltc1427_hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(ltc1427soft_statep, instance);

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->ltc1427_mutex, NULL, MUTEX_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
ltc1427_do_resume()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
ltc1427_do_suspend()
{
	int ret = DDI_SUCCESS;

	return (ret);
}

static int
ltc1427_do_detach(dev_info_t *dip)
{
	struct ltc1427_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);

	unitp = ddi_get_soft_state(ltc1427soft_statep, instance);

	if (unitp == NULL) {
		cmn_err(CE_WARN, "%s%d: unitp not filled\n",
		    ddi_get_name(dip), instance);
		return (ENOMEM);
	}

	i2c_client_unregister(unitp->ltc1427_hdl);

	ddi_remove_minor_node(dip, NULL);

	mutex_destroy(&unitp->ltc1427_mutex);

	ddi_soft_state_free(ltc1427soft_statep, instance);

	return (DDI_SUCCESS);
}
