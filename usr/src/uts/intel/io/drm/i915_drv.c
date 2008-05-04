/* BEGIN CSTYLED */

/*
 * i915_drv.c -- Intel i915 driver -*- linux-c -*-
 * Created: Wed Feb 14 17:10:04 2001 by gareth@valinux.com
 */

/*
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"
#include "i915_drm.h"
#include "i915_drv.h"
#include "drm_pciids.h"

#define	i915_max_ioctl  0x20 /* changed from 15 */


/*
 * cb_ops entrypoint
 */
extern struct cb_ops drm_cb_ops;

/*
 * module entrypoint
 */
static int i915_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int i915_attach(dev_info_t *, ddi_attach_cmd_t);
static int i915_detach(dev_info_t *, ddi_detach_cmd_t);


/* drv_PCI_IDs comes from drm_pciids.h */
static drm_pci_id_list_t i915_pciidlist[] = {
	i915_PCI_IDS
};

drm_ioctl_desc_t i915_ioctls[i915_max_ioctl];

extern void i915_init_ioctl_arrays(void);

/*
 * Local routines
 */
static void i915_configure(drm_driver_t *);

/*
 * DRM driver
 */
static drm_driver_t	i915_driver = {0};


static struct dev_ops i915_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	i915_info,			/* devo_getinfo */
	nulldev,			/* devo_identify */
	nulldev,			/* devo_probe */
	i915_attach,			/* devo_attach */
	i915_detach,			/* devo_detach */
	nodev,				/* devo_reset */
	&drm_cb_ops,		/* devo_cb_ops */
	NULL,				/* devo_bus_ops */
	NULL				/* power */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* drv_modops */
	"I915 DRM driver %I%",	/* drv_linkinfo */
	&i915_dev_ops,			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *) &modldrv, NULL
};


/*
 * softstate head
 */
static void 	*i915_statep;

int
_init(void)
{
	int error;

	i915_configure(&i915_driver);

	if ((error = ddi_soft_state_init(&i915_statep,
	    sizeof (drm_device_t), DRM_MAX_INSTANCES)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&i915_statep);
		return (error);
	}

	return (error);

}	/* _init() */

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	(void) ddi_soft_state_fini(&i915_statep);
	
	return (0);

}	/* _fini() */

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));

}	/* _info() */

static int
i915_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{	
	drm_device_t		*statep;
	void		*handle;
	int			unit;

	if (cmd != DDI_ATTACH) {
		DRM_ERROR("i915_attach: only attach op supported");
		return (DDI_FAILURE);
	}

	unit =  ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(i915_statep, unit) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "i915_attach: failed to alloc softstate");
		return (DDI_FAILURE);
	}
	statep = ddi_get_soft_state(i915_statep, unit);
	statep->dip = dip;
	statep->driver = &i915_driver;

	/*
	 * Call drm_supp_register to create minor nodes for us
	 */
	handle = drm_supp_register(dip, statep);
	if ( handle == NULL) {
		DRM_ERROR("i915_attach: drm_supp_register failed");
		goto err_exit1;
	}
	statep->drm_handle = handle;

	/*
	 * After drm_supp_register, we can call drm_xxx routine
	 */
	statep->drm_supported = DRM_UNSUPPORT;
	if (drm_probe(statep, i915_pciidlist) != DDI_SUCCESS) {
		DRM_ERROR("i915_open: "
		    "DRM current don't support this graphics card");
		goto err_exit2;
	}
	statep->drm_supported = DRM_SUPPORT;

	/* call common attach code */
	if (drm_attach(statep) != DDI_SUCCESS) {
		DRM_ERROR("i915_attach: drm_attach failed");
		goto err_exit2;
	}
	return (DDI_SUCCESS);
	
err_exit2:
	(void) drm_supp_unregister(handle);
err_exit1:
	(void) ddi_soft_state_free(i915_statep, unit);
	return (DDI_FAILURE);

}	/* i915_attach() */

static int
i915_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)    
{
	drm_device_t		*statep;
	int		unit;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	unit =  ddi_get_instance(dip);
	statep = ddi_get_soft_state(i915_statep, unit);
	if (statep == NULL)
		return (DDI_FAILURE);

	(void) drm_detach(statep);
	(void) drm_supp_unregister(statep->drm_handle);
	(void) ddi_soft_state_free(i915_statep, unit);

	return (DDI_SUCCESS);

}	/* i915_detach() */


/*ARGSUSED*/
static int
i915_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	drm_device_t		*statep;
	int 	error = DDI_SUCCESS;
	int 	unit;

	unit = drm_dev_to_instance((dev_t)arg);
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		statep = ddi_get_soft_state(i915_statep, unit);
		if (statep == NULL || statep->dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *) statep->dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)unit;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);

}	/* i915_info() */


static void i915_configure(drm_driver_t *driver)
{
	i915_init_ioctl_arrays();

	driver->buf_priv_size	=	1;	/* No dev_priv */
	driver->load	=	i915_driver_load;
	driver->unload	=	i915_driver_unload;
	driver->preclose	=	i915_driver_preclose;
	driver->lastclose	=	i915_driver_lastclose;
	driver->device_is_agp	=	i915_driver_device_is_agp;
	driver->vblank_wait		=	i915_driver_vblank_wait;
	driver->vblank_wait2		=	i915_driver_vblank_wait2;
	driver->irq_preinstall	=	i915_driver_irq_preinstall;
	driver->irq_postinstall	=	i915_driver_irq_postinstall;
	driver->irq_uninstall	=	i915_driver_irq_uninstall;
	driver->irq_handler 		=	i915_driver_irq_handler;

	driver->driver_ioctls	=	i915_ioctls;
	driver->max_driver_ioctl	=	i915_max_ioctl;

	driver->driver_name	=	DRIVER_NAME;
	driver->driver_desc	=	DRIVER_DESC;
	driver->driver_date	=	DRIVER_DATE;
	driver->driver_major	=	DRIVER_MAJOR;
	driver->driver_minor	=	DRIVER_MINOR;
	driver->driver_patchlevel	=	DRIVER_PATCHLEVEL;

	driver->use_agp	=	1;
	driver->require_agp	=	1;
	driver->use_irq	=	1;
	driver->use_vbl_irq	=	1;
	driver->use_vbl_irq2	=	1;
}
