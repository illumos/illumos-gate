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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * I915 DRM Driver for Solaris
 *
 * This driver provides the hardware 3D acceleration support for Intel
 * integrated video devices (e.g. i8xx/i915/i945 series chipsets), under the
 * DRI (Direct Rendering Infrastructure). DRM (Direct Rendering Manager) here
 * means the kernel device driver in DRI.
 *
 * I915 driver is a device dependent driver only, it depends on a misc module
 * named drm for generic DRM operations.
 *
 * This driver also calls into gfx and agpmaster misc modules respectively for
 * generic graphics operations and AGP master device support.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/visual_io.h>
#include <sys/font.h>
#include <sys/fbio.h>

#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/vgareg.h>
#include <sys/vgasubr.h>
#include <sys/pci.h>
#include <sys/kd.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunldi.h>
#include <sys/mkdev.h>
#include <sys/agpgart.h>
#include <sys/agp/agpdefs.h>
#include <sys/agp/agpmaster_io.h>
#include <gfx_private.h>
#include <drmP.h>

/*
 * Macros used only in this file
 */

/*
 * dev_t of this driver looks consists of:
 *
 * major number with NBITSMAJOR bits
 * instance node number with NBITSINST bits
 * minor node number with NBITSMINOR - NBITSINST bits
 *
 * Each instance has at most 2^(NBITSMINOR - NBITSINST) minor nodes, the first
 * three are:
 * 0: gfx<instance number>, graphics common node
 * 1: agpmaster<instance number>, agpmaster node
 * 2: drm<instance number>, drm node
 */
#define	GFX_MINOR		0
#define	AGPMASTER_MINOR		1
#define	DRM_MINOR		2

/*
 * Number of bits occupied by instance number in dev_t, currently maximum 8
 * instances are supported.
 */
#define	NBITSINST		3

/* Number of bits occupied in dev_t by minor node */
#define	NBITSMNODE		(NBITSMINOR - NBITSINST)

/*
 * DRM use a "cloning" minor node mechanism to release lock on every close(2),
 * thus there will be a minor node for every open(2) operation. Here we give
 * the maximum DRM cloning minor node number.
 */
#define	MAX_CLONE_MINOR		(1 << (NBITSMNODE) - 1)
#define	DEV2MINOR(dev)		(getminor(dev) & ((1 << (NBITSMNODE)) - 1))
#define	DEV2INST(dev)		(getminor(dev) >> NBITSMNODE)
#define	INST2NODE0(inst)	((inst) << NBITSMNODE)
#define	INST2NODE1(inst)	(((inst) << NBITSMNODE) + AGPMASTER_MINOR)
#define	INST2NODE2(inst)	(((inst) << NBITSMNODE) + DRM_MINOR)

/* graphics name for the common graphics minor node */
#define	GFX_NAME		"gfx"

#define	getsoftc(instance) ((drm_i915_state_t *) \
    ddi_get_soft_state(i915_softc_head, (instance)))

/* i915 extern declarations */
extern int i915_attach(dev_info_t *, ddi_attach_cmd_t,
    struct drm_softstate **, ddi_acc_handle_t, minor_t);
extern int i915_detach(dev_info_t *, ddi_detach_cmd_t,
    struct drm_softstate **);
extern int i915_open(dev_t *, int, int, cred_t *, struct drm_softstate *);
extern int i915_close(dev_t, int, int, cred_t *, struct drm_softstate *);
extern int i915_ioctl(dev_t dev, int cmd, intptr_t intarg, int flags,
    cred_t *credp, int *rvalp, struct drm_softstate *softstate);
extern int i915_devmap(dev_t dev, devmap_cookie_t cookie, offset_t offset,
    size_t len, size_t *maplen, uint_t model, struct drm_softstate *softstate,
    ddi_device_acc_attr_t *accattrp);

/*
 * Driver entry points prototypes
 */
static int i915_sun_open(dev_t *, int, int, cred_t *);
static int i915_sun_close(dev_t, int, int, cred_t *);
static int i915_sun_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int i915_sun_devmap(dev_t, devmap_cookie_t, offset_t,
    size_t, size_t *, uint_t);
static int i915_sun_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result);
static int i915_sun_attach(dev_info_t *, ddi_attach_cmd_t);
static int i915_sun_detach(dev_info_t *, ddi_detach_cmd_t);

/* Softstate */
typedef struct drm_i915_state {
	dev_info_t		*devi;		/* devi here */
	ddi_acc_handle_t	*pci_cfg_hdlp;	/* PCI conf handle */
	gfxp_vgatext_softc_ptr_t	ds_gfx;		/* gfx softstate */
	agp_master_softc_t	*agp_master;	/* agpmaster softstate ptr */
	drm_softstate_t		*ds_drm;	/* drm softstate ptr */
} drm_i915_state_t;

/* Entry points structure */
static 	struct cb_ops cb_i915_sun_ops = {
	i915_sun_open,		/* cb_open */
	i915_sun_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	i915_sun_ioctl,		/* cb_ioctl */
	i915_sun_devmap,		/* cb_devmap */
	nodev,			/* cb_mmap */
	ddi_devmap_segmap,	/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* cb_stream */
	D_NEW | D_MTSAFE	/* cb_flag */
};

/* Device operations structure */
static struct dev_ops i915_sun_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	i915_sun_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	i915_sun_attach,	/* devo_attach */
	i915_sun_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&cb_i915_sun_ops,	/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL			/* power */
};

/* Anchor of soft state structures */
static void	*i915_softc_head;

/* Loadable Driver stuff */

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"I915 DRM driver v%I%",	/* Name of the module. */
	&i915_sun_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *) &modldrv, NULL
};

static ddi_device_acc_attr_t dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
};

/* Identifier of this driver */
static struct vis_identifier text_ident = { "SUNWdrm" };

int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init(&i915_softc_head,
		    sizeof (drm_i915_state_t), DRM_MAX_INSTANCES)) != 0) {
	    return (e);
	}

	e = mod_install(&modlinkage);

	if (e) {
	    ddi_soft_state_fini(&i915_softc_head);
	}
	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0)
	    return (e);

	ddi_soft_state_fini(&i915_softc_head);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
i915_sun_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	drm_i915_state_t *softc;
	int	unit = ddi_get_instance(devi);
	int	error;
	char	buf[80];


	switch (cmd) {
	case DDI_ATTACH:
	    break;

	case DDI_RESUME:
	    return (DDI_FAILURE);
	default:
	    return (DDI_FAILURE);
	}

	/* DDI_ATTACH */

	/* allocate softc struct */
	if (ddi_soft_state_zalloc(i915_softc_head, unit) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	softc = getsoftc(unit);

	/* link it in */
	softc->devi = devi;
	ddi_set_driver_private(devi, softc);

	/* common graphics initialization works */
	softc->ds_gfx = gfxp_vgatext_softc_alloc();
	error = gfxp_vgatext_attach(devi, cmd, softc->ds_gfx);
	if (error != DDI_SUCCESS)
		goto fail;

	/* create a minor node for common graphics ops */
	(void) sprintf(buf, "%s%d", GFX_NAME, unit);
	error = ddi_create_minor_node(devi, buf, S_IFCHR,
	    INST2NODE0(unit), DDI_NT_DISPLAY, NULL);
	if (error != DDI_SUCCESS)
		goto fail;

	/* setup mapping for later PCI config space access */
	softc->pci_cfg_hdlp = (ddi_acc_handle_t *)
	    kmem_zalloc(sizeof (ddi_acc_handle_t), KM_SLEEP);
	error = pci_config_setup(devi, softc->pci_cfg_hdlp);
	if (error != DDI_SUCCESS) {
		DRM_ERROR("i915_sun_attach: "
		    "PCI configuration space setup failed");
		goto fail;
	}

	/* AGP master attach */
	error = agpmaster_attach(softc->devi, &softc->agp_master,
	    *softc->pci_cfg_hdlp, INST2NODE1(unit));
	if (error != DDI_SUCCESS) {
		DRM_ERROR("i915_sun_attach: "
		    "AGP master support not available");
	}

	/* DRM driver (i915) attach */
	error = i915_attach(devi, cmd, &softc->ds_drm,
	    *softc->pci_cfg_hdlp, INST2NODE2(unit));

	if (error != DDI_SUCCESS) {
		DRM_ERROR("i915_sun_attach: DRM support not available\n");
	}

	return (DDI_SUCCESS);

fail:
	DRM_ERROR("i915_sun_attach: failed, invoke detach\n");
	(void) i915_sun_detach(devi, DDI_DETACH);
	return (error);
}

static int
i915_sun_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	drm_i915_state_t *softc = getsoftc(instance);


	switch (cmd) {
	case DDI_DETACH:
		/* i915 DRM detach */
		if (softc->ds_drm != NULL)
			(void) i915_detach(devi, cmd, &softc->ds_drm);

		/* AGP master detach */
		if (softc->agp_master != NULL)
			agpmaster_detach(&softc->agp_master);

		if (softc->pci_cfg_hdlp) {
			/* free PCI config access handle */
			pci_config_teardown(softc->pci_cfg_hdlp);

			/* free PCI configuration handle */
			kmem_free((void *)softc->pci_cfg_hdlp,
			    (sizeof (ddi_acc_handle_t)));
		}

		/* graphics misc module detach */
		(void) gfxp_vgatext_detach(devi, DDI_DETACH, softc->ds_gfx);
		gfxp_vgatext_softc_free(softc->ds_gfx);

		/* remove all minor nodes */
		ddi_remove_minor_node(devi, NULL);
		(void) ddi_soft_state_free(i915_softc_head, instance);
		return (DDI_SUCCESS);

	default:
		DRM_ERROR("i915_sun_detach: unknown command 0x%x\n", cmd);
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
i915_sun_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev;
	int error;
	int instance;
	drm_i915_state_t *softc;

	error = DDI_SUCCESS;

	dev = (dev_t)arg;
	instance = DEV2INST(dev);
	softc = getsoftc(instance);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (softc == NULL || softc->devi == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *) softc->devi;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}


/*ARGSUSED*/
static int
i915_sun_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	drm_i915_state_t *softc = getsoftc(DEV2INST(*devp));
	minor_t minor = DEV2MINOR(*devp);
	int err;

	if (softc == NULL || otyp == OTYP_BLK)
		return (ENXIO);

	if ((minor == GFX_MINOR) || (minor == AGPMASTER_MINOR))
		return (0);

	ASSERT(softc->ds_drm->cloneopens <= MAX_CLONE_MINOR);

	err = i915_open(devp, flag, otyp, cred, softc->ds_drm);

	return (err);
}

/*ARGSUSED*/
static int
i915_sun_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	drm_i915_state_t *softc = getsoftc(DEV2INST(dev));
	minor_t minor = DEV2MINOR(dev);
	int err;

	if ((minor == GFX_MINOR) || (minor == AGPMASTER_MINOR))
		return (0);

	if ((minor > MAX_CLONE_MINOR) || (softc == NULL))
		return (EBADF);

	err = i915_close(dev, flag, otyp, cred, softc->ds_drm);
	return (err);
}

/*ARGSUSED*/
static int
i915_sun_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *cred,
    int *rval)
{
	drm_i915_state_t *softc = getsoftc(DEV2INST(dev));
	minor_t minor;
	int err;

	if (cmd == VIS_GETIDENTIFIER) {
		if (ddi_copyout(&text_ident, (void *)data,
		    sizeof (struct vis_identifier), mode))
			return (EFAULT);
	}

	switch (DEV2MINOR(dev)) {
	case GFX_MINOR:
		err = gfxp_vgatext_ioctl(dev, cmd, data, mode, cred, rval,
		    softc->ds_gfx);
		break;

	case AGPMASTER_MINOR:
		err = agpmaster_ioctl(dev, cmd, data, mode, cred, rval,
		    softc->agp_master);
		break;

	case DRM_MINOR:
	default:	/* DRM cloning minor nodes */
		/* check if it's a valide cloning minor node */
		minor = DEV2MINOR(dev);
		if (minor > MAX_CLONE_MINOR)
			return (EBADF);
		err = i915_ioctl(dev, cmd, data, mode, cred, rval,
		    softc->ds_drm);
		break;
	}

	return (err);
}

/*ARGSUSED*/
static int
i915_sun_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
		size_t *maplen, uint_t model)
{
	drm_i915_state_t *softc;
	minor_t minor;
	int err;

	softc = getsoftc(DEV2INST(dev));
	if (softc == NULL)
		return (-1);

	switch (DEV2MINOR(dev)) {
	case GFX_MINOR:
		err = gfxp_vgatext_devmap(dev, dhp, off, len, maplen, model,
		    softc->ds_gfx);
		break;

	case DRM_MINOR:
	default:	/* DRM cloning minor nodes */
		/* check if it's a valide cloning minor node */
		minor = DEV2MINOR(dev);
		if (minor > MAX_CLONE_MINOR)
			return (EBADF);
		err = i915_devmap(dev, dhp, off, len, maplen, model,
		    softc->ds_drm, &dev_attr);
		break;
	}

	return (err);
}
