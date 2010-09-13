/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * radeon_drv.c -- ATI Radeon driver -*- linux-c -*-
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

#include "drmP.h"
#include "drm.h"
#include "radeon_drm.h"
#include "radeon_drv.h"
#include "drm_pciids.h"

int radeon_no_wb = 1;

/*
 * cb_ops entrypoint
 */
extern struct cb_ops drm_cb_ops;

/* drv_PCI_IDs comes from drm_pciids.h */
static drm_pci_id_list_t radeon_pciidlist[] = {
	radeon_PCI_IDS
};

/*
 * module entrypoint
 */
static int radeon_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int radeon_attach(dev_info_t *, ddi_attach_cmd_t);
static int radeon_detach(dev_info_t *, ddi_detach_cmd_t);

extern void radeon_init_ioctl_arrays(void);
extern uint_t radeon_driver_irq_handler(caddr_t);
extern int drm_get_pci_index_reg(dev_info_t *, uint_t, uint_t, off_t *);

/*
 * Local routines
 */
static void radeon_configure(drm_driver_t *);

/*
 * DRM driver
 */
static drm_driver_t	radeon_driver = {0};

static struct dev_ops radeon_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	radeon_info,			/* devo_getinfo */
	nulldev,			/* devo_identify */
	nulldev,			/* devo_probe */
	radeon_attach,			/* devo_attach */
	radeon_detach,			/* devo_detach */
	nodev,				/* devo_reset */
	&drm_cb_ops,			/* devo_cb_ops */
	NULL,				/* devo_bus_ops */
	NULL,				/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* drv_modops */
	"radeon DRM driver",		/* drv_linkinfo */
	&radeon_dev_ops,			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *) &modldrv, NULL
};


/*
 * softstate head
 */
static void 	*radeon_statep;

int
_init(void)
{
	int error;

	radeon_configure(&radeon_driver);

	if ((error = ddi_soft_state_init(&radeon_statep,
	    sizeof (drm_device_t), DRM_MAX_INSTANCES)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&radeon_statep);
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

	(void) ddi_soft_state_fini(&radeon_statep);

	return (0);

}	/* _fini() */

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));

}	/* _info() */


static int
radeon_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	drm_device_t	*statep;
	void		*handle;
	int		unit;

	if (cmd != DDI_ATTACH) {
		DRM_ERROR("radeon_attach: only attach op supported");
		return (DDI_FAILURE);
	}

	unit =  ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(radeon_statep, unit) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "radeon_attach: alloc softstate failed unit=%d", unit);
		return (DDI_FAILURE);
	}
	statep = ddi_get_soft_state(radeon_statep, unit);
	statep->dip = dip;
	statep->driver = &radeon_driver;

	/*
	 * Call drm_supp_register to create minor nodes for us
	 */
	handle = drm_supp_register(dip, statep);
	if (handle == NULL) {
		DRM_ERROR("radeon_attach: drm_supp_register failed");
		goto err_exit1;
	}
	statep->drm_handle = handle;

	/*
	 * After drm_supp_register, we can call drm_xxx routine
	 */
	statep->drm_supported = DRM_UNSUPPORT;
	if (drm_probe(statep, radeon_pciidlist) != DDI_SUCCESS) {
		DRM_ERROR("radeon_open: "
		    "DRM current don't support this graphics card");
		goto err_exit2;
	}
	statep->drm_supported = DRM_SUPPORT;

	/* call common attach code */
	if (drm_attach(statep) != DDI_SUCCESS) {
		DRM_ERROR("radeon_attach: drm_attach failed");
		goto err_exit2;
	}
	return (DDI_SUCCESS);

err_exit2:
	(void) drm_supp_unregister(handle);
err_exit1:
	(void) ddi_soft_state_free(radeon_statep, unit);
	return (DDI_FAILURE);

}	/* radeon_attach() */

static int
radeon_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	drm_device_t	*statep;
	int			unit;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	unit =  ddi_get_instance(dip);
	statep = ddi_get_soft_state(radeon_statep, unit);
	if (statep == NULL)
		return (DDI_FAILURE);

	(void) drm_detach(statep);
	(void) drm_supp_unregister(statep->drm_handle);
	(void) ddi_soft_state_free(radeon_statep, unit);

	return (DDI_SUCCESS);

}	/* radeon_detach() */

/*ARGSUSED*/
static int
radeon_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	drm_device_t	*statep;
	int 		error = DDI_SUCCESS;
	int 		unit;

	unit = drm_dev_to_instance((dev_t)arg);
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		statep = ddi_get_soft_state(radeon_statep, unit);
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

}	/* radeon_info() */

static void
radeon_configure(drm_driver_t *driver)
{
	driver->buf_priv_size = sizeof (drm_radeon_buf_priv_t);
	driver->load			= radeon_driver_load;
	driver->unload		= radeon_driver_unload;
	driver->firstopen		= radeon_driver_firstopen;
	driver->open			= radeon_driver_open;
	driver->preclose		= radeon_driver_preclose;
	driver->postclose		= radeon_driver_postclose;
	driver->lastclose		= radeon_driver_lastclose;
	driver->vblank_wait		= radeon_driver_vblank_wait;
	driver->vblank_wait2		= radeon_driver_vblank_wait2;
	driver->irq_preinstall	= radeon_driver_irq_preinstall;
	driver->irq_postinstall	= radeon_driver_irq_postinstall;
	driver->irq_uninstall	= radeon_driver_irq_uninstall;
	driver->irq_handler		= radeon_driver_irq_handler;
	driver->dma_ioctl		= radeon_cp_buffers;

	driver->driver_ioctls	= radeon_ioctls;
	driver->max_driver_ioctl	= radeon_max_ioctl;

	driver->driver_name		= DRIVER_NAME;
	driver->driver_desc		= DRIVER_DESC;
	driver->driver_date		= DRIVER_DATE;
	driver->driver_major		= DRIVER_MAJOR;
	driver->driver_minor		= DRIVER_MINOR;
	driver->driver_patchlevel	= DRIVER_PATCHLEVEL;

	driver->use_agp		= 1;
	driver->use_mtrr		= 1;
	driver->use_pci_dma		= 1;
	driver->use_sg		= 1;
	driver->use_dma		= 1;
	driver->use_irq		= 1;
	driver->use_vbl_irq		= 1;
	driver->use_vbl_irq2		= 1;

}	/* radeon_configure() */
