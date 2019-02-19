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
 * This is a test driver used for exercising the DDI UFM subsystem.
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/ddi_ufm.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/zone.h>

#include "ufmtest.h"

typedef struct ufmtest {
	dev_info_t 		*ufmt_devi;
	nvlist_t		*ufmt_nvl;
	ddi_ufm_handle_t	*ufmt_ufmh;
	uint32_t		ufmt_failflags;
} ufmtest_t;

static ufmtest_t ufmt = { 0 };

static int ufmtest_open(dev_t *, int, int, cred_t *);
static int ufmtest_close(dev_t, int, int, cred_t *);
static int ufmtest_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops ufmtest_cb_ops = {
	.cb_open =	ufmtest_open,
	.cb_close =	ufmtest_close,
	.cb_strategy =	nodev,
	.cb_print =	nodev,
	.cb_dump =	nodev,
	.cb_read =	nodev,
	.cb_write =	nodev,
	.cb_ioctl =	ufmtest_ioctl,
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

static int ufmtest_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ufmtest_attach(dev_info_t *, ddi_attach_cmd_t);
static int ufmtest_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops ufmtest_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		ufmtest_info,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		ufmtest_attach,
	.devo_detach =		ufmtest_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&ufmtest_cb_ops,
	.devo_bus_ops =		NULL,
	.devo_power =		NULL,
	.devo_quiesce =		ddi_quiesce_not_needed
};

static struct modldrv modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"DDI UFM test driver",
	.drv_dev_ops =		&ufmtest_ops
};

static struct modlinkage modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ (void *)&modldrv, NULL }
};

static int ufmtest_nimages(ddi_ufm_handle_t *, void *, uint_t *);
static int ufmtest_fill_image(ddi_ufm_handle_t *, void *, uint_t,
    ddi_ufm_image_t *);
static int ufmtest_fill_slot(ddi_ufm_handle_t *, void *, uint_t, uint_t,
    ddi_ufm_slot_t *);
static int ufmtest_getcaps(ddi_ufm_handle_t *, void *, ddi_ufm_cap_t *);

static ddi_ufm_ops_t ufmtest_ufm_ops = {
	ufmtest_nimages,
	ufmtest_fill_image,
	ufmtest_fill_slot,
	ufmtest_getcaps
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
ufmtest_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = ufmt.ufmt_devi;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)ddi_get_instance(dip);
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
ufmtest_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH || ufmt.ufmt_devi != NULL)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, "ufmtest", S_IFCHR, 0, DDI_PSEUDO,
	    0) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	ufmt.ufmt_devi = devi;

	if (ddi_ufm_init(ufmt.ufmt_devi, DDI_UFM_CURRENT_VERSION,
	    &ufmtest_ufm_ops, &ufmt.ufmt_ufmh, NULL) != 0) {
		dev_err(ufmt.ufmt_devi, CE_WARN, "failed to initialize UFM "
		    "subsystem");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
ufmtest_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (devi != NULL)
		ddi_remove_minor_node(devi, NULL);

	ddi_ufm_fini(ufmt.ufmt_ufmh);
	if (ufmt.ufmt_nvl != NULL) {
		nvlist_free(ufmt.ufmt_nvl);
		ufmt.ufmt_nvl = NULL;
	}

	return (DDI_SUCCESS);
}

static int
ufmtest_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	const int inv_flags = FWRITE | FEXCL | FNDELAY | FNONBLOCK;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (flag & inv_flags)
		return (EINVAL);

	if (drv_priv(credp) != 0)
		return (EPERM);

	if (getzoneid() != GLOBAL_ZONEID)
		return (EPERM);

	return (0);
}

static int
ufmtest_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/*
 * By default, this pseudo test driver contains no hardcoded UFM data to
 * report.  This ioctl takes a packed nvlist, representing a UFM report.
 * This data is then used as a source for firmware information by this
 * driver when it's UFM callback are called.
 *
 * External test programs can use this ioctl to effectively seed this
 * driver with arbitrary firmware information which it will report up to the
 * DDI UFM subsystem.
 */
static int
ufmtest_do_setfw(intptr_t data, int mode)
{
	int ret;
	uint_t model;
	ufmtest_ioc_setfw_t setfw;
	char *nvlbuf = NULL;
#ifdef _MULTI_DATAMODEL
	ufmtest_ioc_setfw32_t setfw32;
#endif
	model = ddi_model_convert_from(mode);

	switch (model) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)data, &setfw32,
		    sizeof (ufmtest_ioc_setfw32_t), mode) != 0)
			return (EFAULT);
		setfw.utsw_bufsz = setfw32.utsw_bufsz;
		setfw.utsw_buf = (caddr_t)(uintptr_t)setfw32.utsw_buf;
		break;
#endif /* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
	default:
		if (ddi_copyin((void *)data, &setfw,
		    sizeof (ufmtest_ioc_setfw_t), mode) != 0)
			return (EFAULT);
	}

	if (ufmt.ufmt_nvl != NULL) {
		nvlist_free(ufmt.ufmt_nvl);
		ufmt.ufmt_nvl = NULL;
	}

	nvlbuf = kmem_zalloc(setfw.utsw_bufsz, KM_NOSLEEP | KM_NORMALPRI);
	if (nvlbuf == NULL)
		return (ENOMEM);

	if (ddi_copyin(setfw.utsw_buf, nvlbuf, setfw.utsw_bufsz, mode) != 0) {
		kmem_free(nvlbuf, setfw.utsw_bufsz);
		return (EFAULT);
	}

	ret = nvlist_unpack(nvlbuf, setfw.utsw_bufsz, &ufmt.ufmt_nvl,
	    NV_ENCODE_NATIVE);
	kmem_free(nvlbuf, setfw.utsw_bufsz);

	if (ret != 0)
		return (ret);

	/*
	 * Notify the UFM subsystem that our firmware information has changed.
	 */
	ddi_ufm_update(ufmt.ufmt_ufmh);

	return (0);
}

static int
ufmtest_do_toggle_fails(intptr_t data, int mode)
{
	ufmtest_ioc_fails_t fails;

	if (ddi_copyin((void *)data, &fails, sizeof (ufmtest_ioc_fails_t),
	    mode) != 0)
		return (EFAULT);

	if (fails.utfa_flags > UFMTEST_MAX_FAILFLAGS)
		return (EINVAL);

	ufmt.ufmt_failflags = fails.utfa_flags;

	return (0);
}

/* ARGSUSED */
static int
ufmtest_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp,
    int *rvalp)
{
	int ret = 0;

	if (drv_priv(credp) != 0)
		return (EPERM);

	switch (cmd) {
	case UFMTEST_IOC_SET_FW:
		ret = ufmtest_do_setfw(data, mode);
		break;
	case UFMTEST_IOC_TOGGLE_FAILS:
		ret = ufmtest_do_toggle_fails(data, mode);
		break;
	case UFMTEST_IOC_DO_UPDATE:
		ddi_ufm_update(ufmt.ufmt_ufmh);
		break;
	default:
		return (ENOTTY);
	}
	return (ret);
}

static int
ufmtest_nimages(ddi_ufm_handle_t *ufmh, void *arg, uint_t *nimgs)
{
	nvlist_t **imgs;
	uint_t ni;

	if (ufmt.ufmt_failflags & UFMTEST_FAIL_NIMAGES ||
	    ufmt.ufmt_nvl == NULL)
		return (EINVAL);

	if (nvlist_lookup_nvlist_array(ufmt.ufmt_nvl, DDI_UFM_NV_IMAGES, &imgs,
	    &ni) != 0)
		return (EINVAL);

	*nimgs = ni;
	return (0);
}

static int
ufmtest_fill_image(ddi_ufm_handle_t *ufmh, void *arg, uint_t imgno,
    ddi_ufm_image_t *img)
{
	nvlist_t **images, *misc, *miscdup = NULL, **slots;
	char *desc;
	uint_t ni, ns;

	if (ufmt.ufmt_failflags & UFMTEST_FAIL_FILLIMAGE ||
	    ufmt.ufmt_nvl == NULL ||
	    nvlist_lookup_nvlist_array(ufmt.ufmt_nvl, DDI_UFM_NV_IMAGES,
	    &images, &ni) != 0)
		goto err;

	if (imgno >= ni)
		goto err;

	if (nvlist_lookup_string(images[imgno], DDI_UFM_NV_IMAGE_DESC,
	    &desc) != 0 ||
	    nvlist_lookup_nvlist_array(images[imgno], DDI_UFM_NV_IMAGE_SLOTS,
	    &slots, &ns) != 0)
		goto err;

	ddi_ufm_image_set_desc(img, desc);
	ddi_ufm_image_set_nslots(img, ns);

	if (nvlist_lookup_nvlist(images[imgno], DDI_UFM_NV_IMAGE_MISC, &misc)
	    == 0) {
		if (nvlist_dup(misc, &miscdup, 0) != 0)
			return (ENOMEM);

		ddi_ufm_image_set_misc(img, miscdup);
	}
	return (0);
err:
	return (EINVAL);
}

static int
ufmtest_fill_slot(ddi_ufm_handle_t *ufmh, void *arg, uint_t imgno,
    uint_t slotno, ddi_ufm_slot_t *slot)
{
	nvlist_t **images, *misc, *miscdup = NULL, **slots;
	char *vers;
	uint32_t attrs;
	uint_t ni, ns;

	if (ufmt.ufmt_failflags & UFMTEST_FAIL_FILLSLOT ||
	    ufmt.ufmt_nvl == NULL ||
	    nvlist_lookup_nvlist_array(ufmt.ufmt_nvl, DDI_UFM_NV_IMAGES,
	    &images, &ni) != 0)
		goto err;

	if (imgno >= ni)
		goto err;

	if (nvlist_lookup_nvlist_array(images[imgno], DDI_UFM_NV_IMAGE_SLOTS,
	    &slots, &ns) != 0)
		goto err;

	if (slotno >= ns)
		goto err;

	if (nvlist_lookup_uint32(slots[slotno], DDI_UFM_NV_SLOT_ATTR,
	    &attrs) != 0)
		goto err;

	ddi_ufm_slot_set_attrs(slot, attrs);
	if (attrs & DDI_UFM_ATTR_EMPTY)
		return (0);

	if (nvlist_lookup_string(slots[slotno], DDI_UFM_NV_SLOT_VERSION,
	    &vers) != 0)
		goto err;

	ddi_ufm_slot_set_version(slot, vers);

	if (nvlist_lookup_nvlist(slots[slotno], DDI_UFM_NV_SLOT_MISC, &misc) ==
	    0) {
		if (nvlist_dup(misc, &miscdup, 0) != 0)
			return (ENOMEM);

		ddi_ufm_slot_set_misc(slot, miscdup);
	}
	return (0);
err:
	return (EINVAL);
}

static int
ufmtest_getcaps(ddi_ufm_handle_t *ufmh, void *arg, ddi_ufm_cap_t *caps)
{
	if (ufmt.ufmt_failflags & UFMTEST_FAIL_GETCAPS)
		return (EINVAL);

	*caps = DDI_UFM_CAP_REPORT;

	return (0);
}
