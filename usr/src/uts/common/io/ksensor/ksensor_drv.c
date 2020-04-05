/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Oxide Computer Company
 */

/*
 * This pseudo-device driver implements access to kernel sensors. See
 * uts/common/os/ksensor.c for more information on the framework and how this
 * driver fits in.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/zone.h>
#include <sys/ksensor_impl.h>

static dev_info_t *ksensor_dip;

static int
ksensor_create_cb(id_t id, const char *class, const char *name)
{
	if (ddi_create_minor_node(ksensor_dip, name, S_IFCHR, (minor_t)id,
	    class, 0) != 0) {
		dev_err(ksensor_dip, CE_WARN, "!failed to create ksensor node "
		    "for %s:%s (minor %d)", class, name, id);
		return (EIO);
	}

	return (0);
}

static void
ksensor_remove_cb(id_t id, const char *name)
{
	ddi_remove_minor_node(ksensor_dip, (char *)name);
}

static int
ksensor_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	if (crgetzoneid(credp) != GLOBAL_ZONEID || drv_priv(credp) != 0) {
		return (EPERM);
	}

	if ((flags & (FEXCL | FNDELAY | FNONBLOCK | FWRITE)) != 0) {
		return (EINVAL);
	}

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	return (0);
}

static int
ksensor_ioctl_kind(minor_t min, intptr_t arg, int mode)
{
	int ret;
	sensor_ioctl_kind_t kind;

	bzero(&kind, sizeof (kind));
	ret = ksensor_op_kind((id_t)min, &kind);
	if (ret == 0) {
		if (ddi_copyout(&kind, (void *)arg, sizeof (kind),
		    mode & FKIOCTL) != 0) {
			ret = EFAULT;
		}
	}
	return (ret);
}

static int
ksensor_ioctl_temp(minor_t min, intptr_t arg, int mode)
{
	int ret;
	sensor_ioctl_temperature_t temp;

	bzero(&temp, sizeof (temp));
	ret = ksensor_op_temperature((id_t)min, &temp);
	if (ret == 0) {
		if (ddi_copyout(&temp, (void *)arg, sizeof (temp),
		    mode & FKIOCTL) != 0) {
			ret = EFAULT;
		}
	}
	return (ret);
}

static int
ksensor_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	minor_t m;

	if ((mode & FREAD) == 0) {
		return (EINVAL);
	}

	m = getminor(dev);
	switch (cmd) {
	case SENSOR_IOCTL_TYPE:
		return (ksensor_ioctl_kind(m, arg, mode));
	case SENSOR_IOCTL_TEMPERATURE:
		return (ksensor_ioctl_temp(m, arg, mode));
	default:
		return (ENOTTY);
	}
}

static int
ksensor_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	return (0);
}

static int
ksensor_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_RESUME:
		return (DDI_SUCCESS);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	if (ksensor_dip != NULL) {
		dev_err(dip, CE_WARN, "ksensor driver already attatched");
		return (DDI_FAILURE);
	}

	ksensor_dip = dip;
	if (ksensor_register(dip, ksensor_create_cb, ksensor_remove_cb) != 0) {
		ksensor_dip = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * All minors always maps to a single instance. Don't worry about minor validity
 * here.
 */
static int
ksensor_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp)
{
	if (cmd != DDI_INFO_DEVT2DEVINFO && cmd != DDI_INFO_DEVT2INSTANCE) {
		return (DDI_FAILURE);
	}

	if (cmd == DDI_INFO_DEVT2DEVINFO) {
		*resultp = ksensor_dip;
	} else {
		int inst = ddi_get_instance(ksensor_dip);
		*resultp = (void *)(uintptr_t)inst;
	}

	return (DDI_SUCCESS);
}

static int
ksensor_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ksensor_dip == NULL) {
		dev_err(dip, CE_WARN, "asked to detach ksensor driver when no "
		    "dip is attached");
		return (DDI_FAILURE);
	}

	if (ksensor_dip != dip) {
		dev_err(dip, CE_WARN, "asked to detach ksensor driver, but dip "
		    "doesn't match");
		return (DDI_FAILURE);
	}

	ksensor_unregister(dip);
	ddi_remove_minor_node(dip, NULL);
	ksensor_dip = NULL;
	return (DDI_SUCCESS);
}

static struct cb_ops ksensor_cb_ops = {
	.cb_open = ksensor_open,
	.cb_close = ksensor_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = ksensor_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops ksensor_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = ksensor_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ksensor_attach,
	.devo_detach = ksensor_detach,
	.devo_reset = nodev,
	.devo_power = ddi_power,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &ksensor_cb_ops
};

static struct modldrv ksensor_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Kernel Sensor driver",
	.drv_dev_ops = &ksensor_dev_ops
};

static struct modlinkage ksensor_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ksensor_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&ksensor_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ksensor_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&ksensor_modlinkage));
}
