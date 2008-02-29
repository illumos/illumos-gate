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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"
#include "drm.h"
#include "drm_io32.h"

/*ARGSUSED*/
int
drm_irq_by_busid(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_irq_busid_t irq;

	DRM_COPYFROM_WITH_RETURN(&irq, (void *)data, sizeof (irq));

	if ((irq.busnum >> 8) != dev->pci_domain ||
	    (irq.busnum & 0xff) != dev->pci_bus ||
	    irq.devnum != dev->pci_slot ||
	    irq.funcnum != dev->pci_func)
		return (EINVAL);

	irq.irq = dev->irq;

	DRM_COPYTO_WITH_RETURN((void *)data, &irq, sizeof (irq));

	return (0);
}


static irqreturn_t
drm_irq_handler_wrap(DRM_IRQ_ARGS)
{
	drm_device_t *dev = (void *)arg;
	int	ret;

	mutex_enter(&dev->irq_lock);
	ret = dev->driver->irq_handler(arg);
	mutex_exit(&dev->irq_lock);

	return (ret);
}


/*ARGSUSED*/
static int
drm_install_irq_handle(drm_device_t *dev)
{
	dev_info_t *dip = dev->dip;

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
	    (ddi_idevice_cookie_t *)NULL, drm_irq_handler_wrap,
	    (caddr_t)dev) != DDI_SUCCESS) {
		DRM_ERROR("drm_install_irq_handle: ddi_add_intr failed");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
drm_irq_install(drm_device_t *dev)
{
	int ret;

	if (dev->dev_private == NULL) {
		DRM_ERROR("drm_irq_install: dev_private is NULL");
		return (EINVAL);
	}

	if (dev->irq_enabled) {
		DRM_ERROR("drm_irq_install: irq already enabled");
		return (EBUSY);
	}

	dev->context_flag = 0;
	mutex_init(&dev->tasklet_lock, NULL, MUTEX_DRIVER, NULL);


	/* before installing handler */
	dev->driver->irq_preinstall(dev);

	/* install handler */
	ret  = drm_install_irq_handle(dev);
	if (ret != DDI_SUCCESS) {
		DRM_ERROR("drm_irq_install: drm_install_irq_handle failed");
		return (ret);
	}

	if (dev->driver->use_vbl_irq) {
		DRM_INIT_WAITQUEUE(&dev->vbl_queue, DRM_INTR_PRI(dev));
	}

	/* after installing handler */
	dev->driver->irq_postinstall(dev);

	dev->irq_enabled = 1;

	return (0);
}

static void
drm_uninstall_irq_handle(drm_device_t *dev)
{
	ASSERT(dev->dip);
	ddi_remove_intr(dev->dip, 0, dev->intr_block);
	mutex_destroy(&dev->irq_lock);
}


/*ARGSUSED*/
int
drm_irq_uninstall(drm_device_t *dev)
{

	if (!dev->irq_enabled) {
		return (EINVAL);
	}
	dev->irq_enabled = 0;
	dev->driver->irq_uninstall(dev);
	drm_uninstall_irq_handle(dev);
	dev->locked_tasklet_func = NULL;
	if (dev->driver->use_vbl_irq) {
		DRM_FINI_WAITQUEUE(&dev->vbl_queue);
	}
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

	DRM_COPYFROM_WITH_RETURN(&ctl, (void *)data, sizeof (ctl));

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
		return (EINVAL);
	}
}

/*ARGSUSED*/
int
drm_wait_vblank(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_wait_vblank_t vblwait;
	struct timeval now;
	int ret, flags;
	unsigned int	sequence;

	if (!dev->irq_enabled)
		return (EINVAL);

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_wait_vblank_32_t vblwait32;
		DRM_COPYFROM_WITH_RETURN(&vblwait32, (void *)data,
		    sizeof (vblwait32));
		vblwait.request.type = vblwait32.request.type;
		vblwait.request.sequence = vblwait32.request.sequence;
		vblwait.request.signal = vblwait32.request.signal;
	} else {
#endif
		DRM_COPYFROM_WITH_RETURN(&vblwait, (void *)data,
		    sizeof (vblwait));
#ifdef _MULTI_DATAMODEL
	}
#endif

	if (vblwait.request.type &
	    ~(_DRM_VBLANK_TYPES_MASK | _DRM_VBLANK_FLAGS_MASK)) {
		cmn_err(CE_WARN, "drm_wait_vblank: wrong request type 0x%x",
		    vblwait.request.type);
		return (EINVAL);
	}

	flags = vblwait.request.type & _DRM_VBLANK_FLAGS_MASK;
	if (flags & _DRM_VBLANK_SECONDARY) {
		if (dev->driver->use_vbl_irq2 != 1)
			return (ENOTSUP);
	} else {
		if (dev->driver->use_vbl_irq != 1)
			return (ENOTSUP);
	}

	sequence = atomic_read((flags & _DRM_VBLANK_SECONDARY) ?
	    &dev->vbl_received2 : &dev->vbl_received);

	if (vblwait.request.type & _DRM_VBLANK_RELATIVE) {
		vblwait.request.sequence += sequence;
		vblwait.request.type &= ~_DRM_VBLANK_RELATIVE;
	}
#ifdef DEBUG
	else if ((vblwait.request.type & _DRM_VBLANK_ABSOLUTE) == 0) {
		cmn_err(CE_WARN, "vblank_wait: unkown request type");
		return (EINVAL);
	}
#endif

	if ((flags & _DRM_VBLANK_NEXTONMISS) &&
	    (sequence - vblwait.request.sequence) <= (1<<23)) {
		vblwait.request.sequence = sequence + 1;
	}

	if (flags & _DRM_VBLANK_SIGNAL) {
		/*
		 * Don't block process, send signal when vblank interrupt
		 */

		cmn_err(CE_WARN, "NOT SUPPORT YET, SHOULD BE ADDED");
		ret = EINVAL;
	} else {
		/* block until vblank interupt */

		if (flags & _DRM_VBLANK_SECONDARY) {
			ret = dev->driver->vblank_wait2(dev,
			    &vblwait.request.sequence);
		} else {
			ret = dev->driver->vblank_wait(dev,
			    &vblwait.request.sequence);
		}

		(void) uniqtime(&now);
		vblwait.reply.tval_sec = now.tv_sec;
		vblwait.reply.tval_usec = now.tv_usec;
	}

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_wait_vblank_32_t vblwait32;
		vblwait32.reply.type = vblwait.reply.type;
		vblwait32.reply.sequence = vblwait.reply.sequence;
		vblwait32.reply.tval_sec = vblwait.reply.tval_sec;
		vblwait32.reply.tval_usec = vblwait.reply.tval_usec;
		DRM_COPYTO_WITH_RETURN((void *)data, &vblwait32,
		    sizeof (vblwait32));
	} else {
#endif
		DRM_COPYTO_WITH_RETURN((void *)data, &vblwait,
		    sizeof (vblwait));
#ifdef _MULTI_DATAMODEL
	}
#endif
	return (ret);
}


/*ARGSUSED*/
void
drm_vbl_send_signals(drm_device_t *dev)
{
	drm_vbl_sig_t *vbl_sig;
	unsigned int vbl_seq = atomic_read(&dev->vbl_received);
	proc_t *pp;

	vbl_sig = TAILQ_FIRST(&dev->vbl_sig_list);
	while (vbl_sig != NULL) {
		drm_vbl_sig_t *next = TAILQ_NEXT(vbl_sig, link);

		if ((vbl_seq - vbl_sig->sequence) <= (1<<23)) {
			pp = prfind(vbl_sig->pid);
			if (pp != NULL)
				psignal(pp, vbl_sig->signo);

			TAILQ_REMOVE(&dev->vbl_sig_list, vbl_sig, link);
			drm_free(vbl_sig, sizeof (*vbl_sig), DRM_MEM_DRIVER);
		}
		vbl_sig = next;
	}
}

/*
 * Schedule a tasklet to call back a driver hook with the HW lock held.
 *
 * \param dev DRM device.
 * \param func Driver callback.
 *
 * This is intended for triggering actions that require the HW lock from an
 * interrupt handler. The lock will be grabbed ASAP after the interrupt handler
 * completes. Note that the callback may be called from interrupt or process
 * context, it must not make any assumptions about this. Also, the HW lock will
 * be held with the kernel context or any client context.
 */

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
