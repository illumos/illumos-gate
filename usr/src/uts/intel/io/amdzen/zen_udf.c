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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * A companion to zen_udf(4D) that allows user access to read the data fabric
 * for development purposes.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>
#include <amdzen_client.h>

#include <zen_udf.h>

typedef struct zen_udf {
	dev_info_t *zudf_dip;
	uint_t zudf_ndfs;
} zen_udf_t;

static zen_udf_t zen_udf_data;

static int
zen_udf_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	minor_t m;
	zen_udf_t *zen_udf = &zen_udf_data;

	if (crgetzoneid(credp) != GLOBAL_ZONEID ||
	    secpolicy_hwmanip(credp) != 0) {
		return (EPERM);
	}

	if ((flags & (FEXCL | FNDELAY | FNONBLOCK)) != 0) {
		return (EINVAL);
	}

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	m = getminor(*devp);
	if (m >= zen_udf->zudf_ndfs) {
		return (ENXIO);
	}

	return (0);
}

static int
zen_udf_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	uint_t dfno;
	zen_udf_t *zen_udf = &zen_udf_data;
	zen_udf_io_t zui;
	df_reg_def_t def;
	boolean_t bcast, do64;

	if (cmd != ZEN_UDF_READ) {
		return (ENOTTY);
	}

	dfno = getminor(dev);
	if (dfno >= zen_udf->zudf_ndfs) {
		return (ENXIO);
	}

	if (crgetzoneid(credp) != GLOBAL_ZONEID ||
	    secpolicy_hwmanip(credp) != 0) {
		return (EPERM);
	}

	if (ddi_copyin((void *)arg, &zui, sizeof (zui), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if ((zui.zui_flags & ~(ZEN_UDF_F_BCAST | ZEN_UDF_F_64)) != 0) {
		return (EINVAL);
	}

	bcast = (zui.zui_flags & ZEN_UDF_F_BCAST) != 0;
	do64 = (zui.zui_flags & ZEN_UDF_F_64) != 0;

	/*
	 * Cons up a register definition based on the user request. We set the
	 * gen to our current one.
	 */
	def.drd_gens = amdzen_c_df_rev();
	def.drd_func = zui.zui_func;
	def.drd_reg = zui.zui_reg;

	if (!do64) {
		int ret;
		uint32_t data;

		ret = bcast ?
		    amdzen_c_df_read32_bcast(dfno, def, &data) :
		    amdzen_c_df_read32(dfno, zui.zui_inst, def, &data);
		if (ret != 0) {
			return (ret);
		}

		zui.zui_data = data;
	} else {
		int ret;

		ret = bcast ?
		    amdzen_c_df_read64_bcast(dfno, def, &zui.zui_data) :
		    amdzen_c_df_read64(dfno, zui.zui_inst, def, &zui.zui_data);
		if (ret != 0) {
			return (ret);
		}
	}

	if (ddi_copyout(&zui, (void *)arg, sizeof (zui), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
zen_udf_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

static void
zen_udf_cleanup(zen_udf_t *zen_udf)
{
	ddi_remove_minor_node(zen_udf->zudf_dip, NULL);
	zen_udf->zudf_ndfs = 0;
	zen_udf->zudf_dip = NULL;
}

static int
zen_udf_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	zen_udf_t *zen_udf = &zen_udf_data;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (zen_udf->zudf_dip != NULL) {
		dev_err(dip, CE_WARN, "!zen_udf is already attached to a "
		    "dev_info_t: %p", zen_udf->zudf_dip);
		return (DDI_FAILURE);
	}

	zen_udf->zudf_dip = dip;
	zen_udf->zudf_ndfs = amdzen_c_df_count();
	for (uint_t i = 0; i < zen_udf->zudf_ndfs; i++) {
		char buf[32];

		(void) snprintf(buf, sizeof (buf), "zen_udf.%u", i);
		if (ddi_create_minor_node(dip, buf, S_IFCHR, i, DDI_PSEUDO,
		    0) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "!failed to create minor %s",
			    buf);
			goto err;
		}
	}

	return (DDI_SUCCESS);

err:
	zen_udf_cleanup(zen_udf);
	return (DDI_FAILURE);
}

static int
zen_udf_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	zen_udf_t *zen_udf = &zen_udf_data;
	minor_t m;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		m = getminor((dev_t)arg);
		if (m >= zen_udf->zudf_ndfs) {
			return (DDI_FAILURE);
		}
		*resultp = (void *)zen_udf->zudf_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		m = getminor((dev_t)arg);
		if (m >= zen_udf->zudf_ndfs) {
			return (DDI_FAILURE);
		}
		*resultp = (void *)(uintptr_t)ddi_get_instance(
		    zen_udf->zudf_dip);
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
zen_udf_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	zen_udf_t *zen_udf = &zen_udf_data;

	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (zen_udf->zudf_dip != dip) {
		dev_err(dip, CE_WARN, "!asked to detach zen_udf, but dip "
		    "doesn't match");
		return (DDI_FAILURE);
	}

	zen_udf_cleanup(zen_udf);
	return (DDI_SUCCESS);
}

static struct cb_ops zen_udf_cb_ops = {
	.cb_open = zen_udf_open,
	.cb_close = zen_udf_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = zen_udf_ioctl,
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

static struct dev_ops zen_udf_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = zen_udf_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = zen_udf_attach,
	.devo_detach = zen_udf_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &zen_udf_cb_ops
};

static struct modldrv zen_udf_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AMD User DF Access",
	.drv_dev_ops = &zen_udf_dev_ops
};

static struct modlinkage zen_udf_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &zen_udf_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&zen_udf_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&zen_udf_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&zen_udf_modlinkage));
}
