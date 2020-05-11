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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/policy.h>

#include <sys/grfans.h>

/*
 * cb ops
 */
static int grfans_open(dev_t *, int, int, cred_t *);
static int grfans_close(dev_t, int, int, cred_t *);
static int grfans_read(dev_t dev, struct uio *uiop, cred_t *cred_p);
static int grfans_write(dev_t dev, struct uio *uiop, cred_t *cred_p);
static int grfans_io(dev_t dev, struct uio *uiop, int rw);
/*
 * dev ops
 */
static int grfans_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int grfans_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int grfans_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct cb_ops grfans_cbops = {
	grfans_open,		/* open */
	grfans_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	grfans_read,		/* read */
	grfans_write,		/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab */
	D_NEW | D_MP | D_HOTPLUG, /* Driver compatibility flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

static struct dev_ops grfans_ops = {
	DEVO_REV,
	0,
	grfans_info,
	nulldev,
	nulldev,
	grfans_attach,
	grfans_detach,
	nodev,
	&grfans_cbops,
	NULL,			/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv grfans_modldrv = {
	&mod_driverops,		/* type of module - driver */
	"grfans device driver",
	&grfans_ops,
};

static struct modlinkage grfans_modlinkage = {
	MODREV_1,
	&grfans_modldrv,
	0
};

static void *grfans_soft_statep;
static int grfans_debug = 0;

int
_init(void)
{
	int    error;

	error = mod_install(&grfans_modlinkage);
	if (error == 0) {
		(void) ddi_soft_state_init(&grfans_soft_statep,
		    sizeof (struct grfans_unit), 1);
	}

	return (error);
}

int
_fini(void)
{
	int    error;

	error = mod_remove(&grfans_modlinkage);
	if (error == 0) {
		ddi_soft_state_fini(&grfans_soft_statep);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&grfans_modlinkage, modinfop));
}

/* ARGSUSED */
static int
grfans_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = MINOR_TO_DEVINST(dev);
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
grfans_do_attach(dev_info_t *dip)
{
	struct grfans_unit *unitp;
	int instance;
	ddi_device_acc_attr_t attr;
	int nregs;
	char name[32];

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(grfans_soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d failed to zalloc softstate",
		    ddi_get_name(dip), instance);

		return (DDI_FAILURE);
	}

	if (grfans_debug) {
		printf("attached instance number %d\n", instance);
	}

	unitp = ddi_get_soft_state(grfans_soft_statep, instance);
	if (unitp == NULL)
		return (DDI_FAILURE);

	(void) snprintf(name, sizeof (name), "%s%d", ddi_driver_name(dip),
	    instance);

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (grfans_debug) {
		printf("number of registers is %d\n",
		    ddi_dev_nregs(dip, &nregs));
	}

	if (ddi_regs_map_setup(dip, 0,
	    (caddr_t *)&unitp->cpufan_reg,
	    3, 1, &attr, &unitp->cpufan_rhandle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s ddi_regs_map_setup failed for regset "
		    "0", name);
		ddi_soft_state_free(grfans_soft_statep, instance);
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(dip, 1,
	    (caddr_t *)&unitp->sysfan_reg,
	    0, 1, &attr, &unitp->sysfan_rhandle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s ddi_regs_map_setup failed for regset "
		    "1", name);
		ddi_regs_map_free(&unitp->cpufan_rhandle);
		ddi_soft_state_free(grfans_soft_statep, instance);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, "cpu_fan", S_IFCHR,
	    DEVINST_TO_MINOR(instance) | CHANNEL_TO_MINOR(CPU_FAN_CHANNEL),
	    FANS_NODE_TYPE, 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed"
		    " for cpu fan", name);
		ddi_regs_map_free(&unitp->cpufan_rhandle);
		ddi_regs_map_free(&unitp->sysfan_rhandle);
		ddi_soft_state_free(grfans_soft_statep, instance);
		ddi_remove_minor_node(dip, NULL);

		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, "sys_fan", S_IFCHR,
	    DEVINST_TO_MINOR(instance) | CHANNEL_TO_MINOR(SYSTEM_FAN_CHANNEL),
	    FANS_NODE_TYPE, 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s ddi_create_minor_node failed"
		    " for system fan", name);
		ddi_regs_map_free(&unitp->cpufan_rhandle);
		ddi_regs_map_free(&unitp->sysfan_rhandle);
		ddi_soft_state_free(grfans_soft_statep, instance);
		ddi_remove_minor_node(dip, NULL);

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->mutex, NULL, MUTEX_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
grfans_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (grfans_do_attach(dip));

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
grfans_do_detach(dev_info_t *dip)
{
	struct grfans_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);
	unitp = ddi_get_soft_state(grfans_soft_statep, instance);
	ddi_remove_minor_node(dip, NULL);

	ddi_regs_map_free(&unitp->cpufan_rhandle);
	ddi_regs_map_free(&unitp->sysfan_rhandle);

	mutex_destroy(&unitp->mutex);

	ddi_soft_state_free(grfans_soft_statep, instance);

	return (DDI_SUCCESS);
}

static int
grfans_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (grfans_do_detach(dip));

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
grfans_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	struct grfans_unit *unitp;
	int err = 0;
	int instance = MINOR_TO_DEVINST(*devp);
	int channel;

	/*
	 * must be privileged to access this device
	 */
	if (secpolicy_sys_config(credp, B_FALSE) != 0)
		return (EPERM);

	if (instance < 0) {
		cmn_err(CE_WARN, "grfan: instance less than 0:  %d\n",
		    instance);

		return (ENXIO);
	}

	unitp = ddi_get_soft_state(grfans_soft_statep, instance);
	if (unitp == NULL) {
		cmn_err(CE_WARN, "grfan: no soft state for instance %d\n",
		    instance);

		return (ENXIO);
	}

	if (otyp != OTYP_CHR)
		return (EINVAL);

	channel = MINOR_TO_CHANNEL(getminor(*devp));

	mutex_enter(&unitp->mutex);

	if (flags & FEXCL) {
		if (unitp->oflag[channel] != 0)
			err = EBUSY;
		else
			unitp->oflag[channel] = FEXCL;
	} else {
		if (unitp->oflag[channel] == FEXCL)
			err = EBUSY;
		else
			unitp->oflag[channel] = (uint16_t)FOPEN;
	}

	mutex_exit(&unitp->mutex);

	return (err);
}

/*ARGSUSED*/
static int
grfans_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	struct grfans_unit *unitp;
	int instance = MINOR_TO_DEVINST(dev);
	int channel;

	if (instance < 0)
		return (ENXIO);

	unitp = ddi_get_soft_state(grfans_soft_statep, instance);
	if (unitp == NULL)
		return (ENXIO);

	channel = MINOR_TO_CHANNEL(getminor(dev));

	unitp->oflag[channel] = 0;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
grfans_read(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	return (grfans_io(dev, uiop, B_READ));
}

/*ARGSUSED*/
static int
grfans_write(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	return (grfans_io(dev, uiop, B_WRITE));
}

static int
grfans_io(dev_t dev, struct uio *uiop, int rw)
{
	struct grfans_unit *unitp;
	int instance = MINOR_TO_DEVINST(getminor(dev));
	int ret = 0;
	size_t len = uiop->uio_resid;
	int8_t out_value, req_value, reg_value;
	caddr_t outputaddr;

	if (instance < 0)
		return (ENXIO);

	if (len == 0)
		return (0);

	unitp = ddi_get_soft_state(grfans_soft_statep, instance);

	if (unitp == NULL)
		return (ENXIO);

	if (MINOR_TO_CHANNEL(getminor(dev)) == CPU_FAN_CHANNEL)
		outputaddr = &unitp->cpufan_output;
	else
		outputaddr = &unitp->sysfan_output;

	if (rw == B_READ) {
		if (*outputaddr == UNKNOWN_OUT)
			return (EIO);
		return (uiomove(outputaddr, 1, UIO_READ, uiop));
	}

	/*
	 * rw == B_WRITE.
	 */
	if ((ret = uiomove(&req_value, sizeof (req_value), UIO_WRITE,
	    uiop)) == 0) {
		if (MINOR_TO_CHANNEL(dev) == CPU_FAN_CHANNEL) {
			/*
			 * Check bounds for cpu fan
			 */
			if (req_value == 0) {
				reg_value = CPU_FAN_0;
				out_value = 0;
			} else if (req_value <= 25) {
				reg_value = CPU_FAN_25;
				out_value = 25;
			} else if (req_value <= 50) {
				reg_value = CPU_FAN_50;
				out_value = 50;
			} else if (req_value <= 75) {
				reg_value = CPU_FAN_75;
				out_value = 75;
			} else if (req_value <= 100) {
				reg_value = CPU_FAN_100;
				out_value = 100;
			} else
				ret = EINVAL;

			if (ret != EINVAL) {
				uint8_t reg;

				*outputaddr = out_value;

				reg = ddi_get8(unitp->cpufan_rhandle,
				    unitp->cpufan_reg);
				reg = (reg & ~CPU_FAN_MASK) | reg_value;
				ddi_put8(unitp->cpufan_rhandle,
				    unitp->cpufan_reg, reg);
				(void) ddi_get8(unitp->cpufan_rhandle,
				    unitp->cpufan_reg);

				if (grfans_debug) {
					printf("set output to %d at addr %p\n",
					    out_value,
					    (void *)unitp->cpufan_reg);
				}
			}
		} else {
			if (req_value == 0) {
				reg_value = SYS_FAN_OFF;
				out_value = 0;
			} else if (req_value > 0) {
				reg_value = SYS_FAN_ON;
				out_value = 100;
			} else {
				ret = EINVAL;
			}

			if (ret != EINVAL) {
				*outputaddr = out_value;

				ddi_put8(unitp->sysfan_rhandle,
				    unitp->sysfan_reg,
				    reg_value);
				(void) ddi_get8(unitp->sysfan_rhandle,
				    unitp->sysfan_reg);
				if (grfans_debug) {
					printf("set SYSFAN output to %d at "
					    "addr %p\n", out_value,
					    (void *)unitp->sysfan_reg);
				}
			}
		}
	} else {
		ret = EFAULT;
	}

	return (ret);
}
