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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * The ufm(7D) pseudo driver provides an ioctl interface for DDI UFM
 * information.  See ddi_ufm.h.
 *
 * Most of the test cases depend on the ufmtest driver being loaded.
 * On SmartOS, this driver will need to be manually installed, as it is not
 * part of the platform image.
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/ddi_ufm.h>
#include <sys/ddi_ufm_impl.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/stat.h>

#define	UFMTEST_IOC		('u' << 24) | ('f' << 16) | ('t' << 8)
#define	UFMTEST_IOC_SETFW	(UFMTEST_IOC | 1)

static dev_info_t *ufm_devi = NULL;

static int ufm_open(dev_t *, int, int, cred_t *);
static int ufm_close(dev_t, int, int, cred_t *);
static int ufm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops ufm_cb_ops = {
	.cb_open =	ufm_open,
	.cb_close =	ufm_close,
	.cb_strategy =	nodev,
	.cb_print =	nodev,
	.cb_dump =	nodev,
	.cb_read =	nodev,
	.cb_write =	nodev,
	.cb_ioctl =	ufm_ioctl,
	.cb_devmap =	nodev,
	.cb_mmap =	nodev,
	.cb_segmap =	nodev,
	.cb_chpoll =	nochpoll,
	.cb_prop_op =	ddi_prop_op,
	.cb_str =	NULL,
	.cb_flag =	D_NEW | D_MP,
	.cb_rev =	CB_REV,
	.cb_aread =	nodev,
	.cb_awrite =	nodev
};

static int ufm_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ufm_attach(dev_info_t *, ddi_attach_cmd_t);
static int ufm_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops ufm_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		ufm_info,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		ufm_attach,
	.devo_detach =		ufm_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&ufm_cb_ops,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
	.devo_quiesce =		ddi_quiesce_not_needed
};

static struct modldrv modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"Upgradeable FW Module driver",
	.drv_dev_ops =		&ufm_ops
};

static struct modlinkage modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ (void *)&modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
ufm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = ufm_devi;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
ufm_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH || ufm_devi != NULL)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, "ufm", S_IFCHR, 0, DDI_PSEUDO, 0) ==
	    DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	ufm_devi = devi;
	return (DDI_SUCCESS);
}

static int
ufm_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (devi != NULL)
		ddi_remove_minor_node(devi, NULL);

	return (DDI_SUCCESS);
}

static int
ufm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	const int inv_flags = FWRITE | FEXCL | FNDELAY | FNONBLOCK;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (flag & inv_flags)
		return (EINVAL);

	if (drv_priv(credp) != 0)
		return (EPERM);

	return (0);
}

static int
ufm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

static boolean_t
ufm_driver_ready(ddi_ufm_handle_t *ufmh)
{
	VERIFY(ufmh != NULL);

	if (ufmh->ufmh_state & DDI_UFM_STATE_SHUTTING_DOWN ||
	    !(ufmh->ufmh_state & DDI_UFM_STATE_READY)) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

static int
ufm_do_getcaps(intptr_t data, int mode)
{
	ddi_ufm_handle_t *ufmh;
	ddi_ufm_cap_t caps;
	ufm_ioc_getcaps_t ugc;
	dev_info_t *dip;
	int ret;
	char devpath[MAXPATHLEN];

	if (ddi_copyin((void *)data, &ugc, sizeof (ufm_ioc_getcaps_t),
	    mode) != 0)
		return (EFAULT);

	if (strlcpy(devpath, ugc.ufmg_devpath, MAXPATHLEN) >= MAXPATHLEN)
		return (EOVERFLOW);

	if ((dip = e_ddi_hold_devi_by_path(devpath, 0)) == NULL) {
		return (ENOTSUP);
	}
	if ((ufmh = ufm_find(devpath)) == NULL) {
		ddi_release_devi(dip);
		return (ENOTSUP);
	}
	ASSERT(MUTEX_HELD(&ufmh->ufmh_lock));

	if (!ufm_driver_ready(ufmh)) {
		ddi_release_devi(dip);
		mutex_exit(&ufmh->ufmh_lock);
		return (EAGAIN);
	}

	if (ugc.ufmg_version != ufmh->ufmh_version) {
		ddi_release_devi(dip);
		mutex_exit(&ufmh->ufmh_lock);
		return (ENOTSUP);
	}

	if ((ret = ufm_cache_fill(ufmh)) != 0) {
		ddi_release_devi(dip);
		mutex_exit(&ufmh->ufmh_lock);
		return (ret);
	}

	ret = ufmh->ufmh_ops->ddi_ufm_op_getcaps(ufmh, ufmh->ufmh_arg, &caps);
	mutex_exit(&ufmh->ufmh_lock);
	ddi_release_devi(dip);

	if (ret != 0)
		return (ret);

	ugc.ufmg_caps = caps;

	if (ddi_copyout(&ugc, (void *)data, sizeof (ufm_ioc_getcaps_t),
	    mode) != 0)
		return (EFAULT);

	return (0);
}

static int
ufm_do_reportsz(intptr_t data, int mode)
{
	ddi_ufm_handle_t *ufmh;
	dev_info_t *dip;
	uint_t model;
	size_t sz;
	int ret;
	char devpath[MAXPATHLEN];
	ufm_ioc_bufsz_t ufbz;
#ifdef _MULTI_DATAMODEL
	ufm_ioc_bufsz32_t ufbz32;
#endif

	model = ddi_model_convert_from(mode);

	switch (model) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)data, &ufbz32,
		    sizeof (ufm_ioc_bufsz32_t), mode) != 0)
			return (EFAULT);
		ufbz.ufbz_version = ufbz32.ufbz_version;
		if (strlcpy(ufbz.ufbz_devpath, ufbz32.ufbz_devpath,
		    MAXPATHLEN) >= MAXPATHLEN) {
			return (EOVERFLOW);
		}
		break;
#endif /* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
	default:
		if (ddi_copyin((void *)data, &ufbz,
		    sizeof (ufm_ioc_bufsz_t), mode) != 0)
			return (EFAULT);
	}

	if (strlcpy(devpath, ufbz.ufbz_devpath, MAXPATHLEN) >= MAXPATHLEN)
		return (EOVERFLOW);

	if ((dip = e_ddi_hold_devi_by_path(devpath, 0)) == NULL) {
		return (ENOTSUP);
	}
	if ((ufmh = ufm_find(devpath)) == NULL) {
		ddi_release_devi(dip);
		return (ENOTSUP);
	}
	ASSERT(MUTEX_HELD(&ufmh->ufmh_lock));

	if (!ufm_driver_ready(ufmh)) {
		ddi_release_devi(dip);
		mutex_exit(&ufmh->ufmh_lock);
		return (EAGAIN);
	}

	if (ufbz.ufbz_version != ufmh->ufmh_version) {
		ddi_release_devi(dip);
		mutex_exit(&ufmh->ufmh_lock);
		return (ENOTSUP);
	}

	/*
	 * Note - ufm_cache_fill() also takes care of verifying that the driver
	 * supports the DDI_UFM_CAP_REPORT capability and will return non-zero,
	 * if not supported.
	 */
	if ((ret = ufm_cache_fill(ufmh)) != 0) {
		ddi_release_devi(dip);
		mutex_exit(&ufmh->ufmh_lock);
		return (ret);
	}
	ddi_release_devi(dip);

	ret = nvlist_size(ufmh->ufmh_report, &sz, NV_ENCODE_NATIVE);
	mutex_exit(&ufmh->ufmh_lock);
	if (ret != 0)
		return (ret);

	switch (model) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		ufbz32.ufbz_size = sz;
		if (ddi_copyout(&ufbz32, (void *)data,
		    sizeof (ufm_ioc_bufsz32_t), mode) != 0)
			return (EFAULT);
		break;
#endif /* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
	default:
		ufbz.ufbz_size = sz;
		if (ddi_copyout(&ufbz, (void *)data,
		    sizeof (ufm_ioc_bufsz_t), mode) != 0)
			return (EFAULT);
	}
	return (0);
}

static int
ufm_do_report(intptr_t data, int mode)
{
	ddi_ufm_handle_t *ufmh;
	uint_t model;
	int ret = 0;
	char *buf;
	size_t sz;
	dev_info_t *dip;
	char devpath[MAXPATHLEN];
	ufm_ioc_report_t ufmr;
#ifdef _MULTI_DATAMODEL
	ufm_ioc_report32_t ufmr32;
#endif

	model = ddi_model_convert_from(mode);

	switch (model) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)data, &ufmr32,
		    sizeof (ufm_ioc_report32_t), mode) != 0)
			return (EFAULT);
		ufmr.ufmr_version = ufmr32.ufmr_version;
		if (strlcpy(ufmr.ufmr_devpath, ufmr32.ufmr_devpath,
		    MAXPATHLEN) >= MAXPATHLEN) {
			return (EOVERFLOW);
		}
		ufmr.ufmr_bufsz = ufmr32.ufmr_bufsz;
		ufmr.ufmr_buf = (caddr_t)(uintptr_t)ufmr32.ufmr_buf;
		break;
#endif /* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
	default:
		if (ddi_copyin((void *)data, &ufmr,
		    sizeof (ufm_ioc_report_t), mode) != 0)
			return (EFAULT);
	}

	if (strlcpy(devpath, ufmr.ufmr_devpath, MAXPATHLEN) >= MAXPATHLEN)
		return (EOVERFLOW);

	if ((dip = e_ddi_hold_devi_by_path(devpath, 0)) == NULL) {
			return (ENOTSUP);
	}
	if ((ufmh = ufm_find(devpath)) == NULL) {
		ddi_release_devi(dip);
		return (ENOTSUP);
	}
	ASSERT(MUTEX_HELD(&ufmh->ufmh_lock));

	if (!ufm_driver_ready(ufmh)) {
		ddi_release_devi(dip);
		mutex_exit(&ufmh->ufmh_lock);
		return (EAGAIN);
	}

	if (ufmr.ufmr_version != ufmh->ufmh_version) {
		ddi_release_devi(dip);
		mutex_exit(&ufmh->ufmh_lock);
		return (ENOTSUP);
	}

	/*
	 * Note - ufm_cache_fill() also takes care of verifying that the driver
	 * supports the DDI_UFM_CAP_REPORT capability and will return non-zero,
	 * if not supported.
	 */
	if ((ret = ufm_cache_fill(ufmh)) != 0) {
		ddi_release_devi(dip);
		mutex_exit(&ufmh->ufmh_lock);
		return (ret);
	}
	ddi_release_devi(dip);

	if ((ret = nvlist_size(ufmh->ufmh_report, &sz, NV_ENCODE_NATIVE)) !=
	    0) {
		mutex_exit(&ufmh->ufmh_lock);
		return (ret);
	}
	if (sz > ufmr.ufmr_bufsz) {
		mutex_exit(&ufmh->ufmh_lock);
		return (EOVERFLOW);
	}

	buf = fnvlist_pack(ufmh->ufmh_report, &sz);
	mutex_exit(&ufmh->ufmh_lock);

	if (ddi_copyout(buf, ufmr.ufmr_buf, sz, mode) != 0) {
		kmem_free(buf, sz);
		return (EFAULT);
	}
	kmem_free(buf, sz);

	switch (model) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		ufmr32.ufmr_bufsz = sz;
		if (ddi_copyout(&ufmr32, (void *)data,
		    sizeof (ufm_ioc_report32_t), mode) != 0)
			return (EFAULT);
		break;
#endif /* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
	default:
		ufmr.ufmr_bufsz = sz;
		if (ddi_copyout(&ufmr, (void *)data,
		    sizeof (ufm_ioc_report_t), mode) != 0)
			return (EFAULT);
	}

	return (0);
}

static int
ufm_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp,
    int *rvalp)
{
	int ret = 0;

	if (drv_priv(credp) != 0)
		return (EPERM);

	switch (cmd) {
	case UFM_IOC_GETCAPS:
		ret = ufm_do_getcaps(data, mode);
		break;

	case UFM_IOC_REPORTSZ:
		ret = ufm_do_reportsz(data, mode);
		break;

	case UFM_IOC_REPORT:
		ret = ufm_do_report(data, mode);
		break;
	default:
		return (ENOTTY);
	}
	return (ret);

}
