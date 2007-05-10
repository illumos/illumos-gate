/*
 * drm_irq.c -- IRQ IOCTL and function support
 * Created: Fri Oct 18 2003 by anholt@FreeBSD.org
 */
/*
 * Copyright 2003 Eric Anholt
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
 * ERIC ANHOLT BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Eric Anholt <anholt@FreeBSD.org>
 *
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"
#include "drm.h"

/*ARGSUSED*/
int
drm_irq_by_busid(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_irq_busid_t irq;

	DRM_COPY_FROM_USER_IOCTL(irq, (drm_irq_busid_t *)data, sizeof (irq));

	if ((irq.busnum >> 8) != dev->pci_domain ||
	    (irq.busnum & 0xff) != dev->pci_bus ||
	    irq.devnum != dev->pci_slot ||
	    irq.funcnum != dev->pci_func)
		return (DRM_ERR(EINVAL));

	irq.irq = dev->irq;

	DRM_DEBUG("%x:%x:%x => IRQ %x\n",
	    irq.busnum, irq.devnum, irq.funcnum, irq.irq);

	DRM_COPY_TO_USER_IOCTL((drm_irq_busid_t *)data, irq, sizeof (irq));

	return (0);
}

/*ARGSUSED*/
static int
drm_install_irq_handle(drm_softstate_t *dev)
{
	dev_info_t *dip = NULL;

	dip = dev->dip;
	if (dip == NULL) {
		DRM_ERROR("drm_install_irq_handle: cannot get vgatext's dip");
		return (DDI_FAILURE);
	}

	if (ddi_intr_hilevel(dip, 0) != 0) {
		DRM_ERROR("drm_install_irq_handle: "
			"high-level interrupts are not supported");
		return (DDI_FAILURE);
	}

	if (ddi_get_iblock_cookie(dip, (uint_t)0,
	    &dev->intr_block) != DDI_SUCCESS) {
		DRM_ERROR("drm_install_irq_handle: cannot get iblock cookie");
		return (DDI_FAILURE);
	}

	mutex_init(&dev->irq_lock, NULL, MUTEX_DRIVER, (void *)dev->intr_block);

	/* setup the interrupt handler */

	if (ddi_add_intr(dip, 0, &dev->intr_block,
	    (ddi_idevice_cookie_t *)NULL, dev->irq_handler,
		(caddr_t)dev) != DDI_SUCCESS) {
		DRM_ERROR("drm_install_irq_handle: ddi_add_intr failed");
		return (DDI_FAILURE);
	}
	DRM_DEBUG("drm_install_irq_handle: add the intr handle successful");


	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
drm_irq_install(drm_softstate_t *dev)
{
	int ret;

	if (dev->dev_private == NULL) {
		DRM_ERROR("drm_irq_install: dev_private is NULL");
		return (DRM_ERR(EINVAL));
	}

	if (dev->irq_enabled) {
		DRM_ERROR("drm_irq_install: irq already enabled");
		return (DRM_ERR(EBUSY));
	}

	dev->context_flag = 0;

	mutex_init(&dev->tasklet_lock, NULL, MUTEX_DRIVER, NULL);

	/* before installing handler */
	dev->irq_preinstall(dev);

	/* install handler */
	ret  = drm_install_irq_handle(dev);
	if (ret != DDI_SUCCESS) {
		DRM_ERROR("drm_irq_install: drm_install_irq_handle failed");
		return (ret);
	}

	/* after installing handler */
	dev->irq_postinstall(dev);

	dev->irq_enabled = 1;

	return (DDI_SUCCESS);
}

static void
drm_uninstall_irq_handle(drm_device_t *dev)
{
	ASSERT(dev->dip);
	ddi_remove_intr(dev->dip, 0, dev->intr_block);
}


/*ARGSUSED*/
int
drm_irq_uninstall(drm_softstate_t *dev)
{
	if (!dev->irq_enabled) {
		return (DRM_ERR(EINVAL));
	}

	dev->irq_enabled = 0;

	dev->irq_uninstall(dev);

	drm_uninstall_irq_handle(dev);

	dev->locked_tasklet_func = NULL;

	mutex_destroy(&dev->tasklet_lock);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
drm_control(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_control_t ctl;
	int err;

	DRM_DEBUG("drm_control: install irq = %x\n", dev->irq);
	DRM_COPY_FROM_USER_IOCTL(ctl, (drm_control_t *)data, sizeof (ctl));

	switch (ctl.func) {
	case DRM_INST_HANDLER:
		/*
		 * Handle drivers whose DRM used to require IRQ setup but the
		 * no longer does.
		 */
		return (drm_irq_install(dev));
	case DRM_UNINST_HANDLER:
		err = drm_irq_uninstall(dev);
		return (err);
	default:
		return (DRM_ERR(EINVAL));
	}
}

/*ARGSUSED*/
int
drm_wait_vblank(DRM_IOCTL_ARGS)
{
	return (0);
}

/*ARGSUSED*/
void
drm_vbl_send_signals(drm_device_t *dev)
{
}

void
drm_locked_tasklet(drm_device_t *dev, void (*func)(drm_device_t *))
{
	mutex_enter(&dev->tasklet_lock);

	if (dev->locked_tasklet_func) {
		mutex_exit(&dev->tasklet_lock);
		return;
	}

	dev->locked_tasklet_func = func;

	mutex_exit(&dev->tasklet_lock);
}
