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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * A device driver that provides user access to the AMD System Management
 * Network for debugging purposes.
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

#include "usmn.h"

typedef struct usmn {
	dev_info_t *usmn_dip;
	uint_t usmn_ndfs;
} usmn_t;

static usmn_t usmn_data;

static int
usmn_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	minor_t m;
	usmn_t *usmn = &usmn_data;

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
	if (m >= usmn->usmn_ndfs) {
		return (ENXIO);
	}

	return (0);
}

static int
usmn_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	uint_t dfno;
	usmn_t *usmn = &usmn_data;
	usmn_reg_t usr;

	if (cmd != USMN_READ && cmd != USMN_WRITE) {
		return (ENOTTY);
	}

	dfno = getminor(dev);
	if (dfno >= usmn->usmn_ndfs) {
		return (ENXIO);
	}

	if (crgetzoneid(credp) != GLOBAL_ZONEID ||
	    secpolicy_hwmanip(credp) != 0) {
		return (EPERM);
	}

	if (ddi_copyin((void *)arg, &usr, sizeof (usr), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	/*
	 * We don't need to check size and alignment here; the client access
	 * routines do so for us and return EINVAL if violated.  The same goes
	 * for the value to be written in the USMN_WRITE case below.
	 */
	const smn_reg_t reg = SMN_MAKE_REG_SIZED(usr.usr_addr, usr.usr_size);

	if (cmd == USMN_READ) {
		int ret;

		if ((mode & FREAD) == 0) {
			return (EINVAL);
		}

		ret = amdzen_c_smn_read(dfno, reg, &usr.usr_data);
		if (ret != 0) {
			return (ret);
		}
	} else if (cmd == USMN_WRITE) {
		int ret;

		if ((mode & FWRITE) == 0) {
			return (EINVAL);
		}

		ret = amdzen_c_smn_write(dfno, reg, usr.usr_data);
		if (ret != 0) {
			return (ret);
		}
	} else {
		return (ENOTSUP);
	}

	if (cmd == USMN_READ &&
	    ddi_copyout(&usr, (void *)arg, sizeof (usr), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
usmn_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

static void
usmn_cleanup(usmn_t *usmn)
{
	ddi_remove_minor_node(usmn->usmn_dip, NULL);
	usmn->usmn_ndfs = 0;
	usmn->usmn_dip = NULL;
}

static int
usmn_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	usmn_t *usmn = &usmn_data;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (usmn->usmn_dip != NULL) {
		dev_err(dip, CE_WARN, "!usmn is already attached to a "
		    "dev_info_t: %p", usmn->usmn_dip);
		return (DDI_FAILURE);
	}

	usmn->usmn_dip = dip;
	usmn->usmn_ndfs = amdzen_c_df_count();
	for (uint_t i = 0; i < usmn->usmn_ndfs; i++) {
		char buf[32];

		(void) snprintf(buf, sizeof (buf), "usmn.%u", i);
		if (ddi_create_minor_node(dip, buf, S_IFCHR, i, DDI_PSEUDO,
		    0) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "!failed to create minor %s",
			    buf);
			goto err;
		}
	}

	return (DDI_SUCCESS);

err:
	usmn_cleanup(usmn);
	return (DDI_FAILURE);
}

static int
usmn_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	usmn_t *usmn = &usmn_data;
	minor_t m;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		m = getminor((dev_t)arg);
		if (m >= usmn->usmn_ndfs) {
			return (DDI_FAILURE);
		}
		*resultp = (void *)usmn->usmn_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		m = getminor((dev_t)arg);
		if (m >= usmn->usmn_ndfs) {
			return (DDI_FAILURE);
		}
		*resultp = (void *)(uintptr_t)ddi_get_instance(usmn->usmn_dip);
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
usmn_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	usmn_t *usmn = &usmn_data;

	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (usmn->usmn_dip != dip) {
		dev_err(dip, CE_WARN, "!asked to detach usmn, but dip doesn't "
		    "match");
		return (DDI_FAILURE);
	}

	usmn_cleanup(usmn);
	return (DDI_SUCCESS);
}

static struct cb_ops usmn_cb_ops = {
	.cb_open = usmn_open,
	.cb_close = usmn_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = usmn_ioctl,
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

static struct dev_ops usmn_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = usmn_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = usmn_attach,
	.devo_detach = usmn_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &usmn_cb_ops
};

static struct modldrv usmn_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AMD User SMN Access",
	.drv_dev_ops = &usmn_dev_ops
};

static struct modlinkage usmn_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &usmn_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&usmn_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&usmn_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&usmn_modlinkage));
}
