/*
 * drm_irq.c -- IRQ IOCTL and function support
 * Created: Fri Oct 18 2003 by anholt@FreeBSD.org
 */
/*
 * Copyright 2003 Eric Anholt
 * Copyright (c) 2009, Intel Corporation.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

	DRM_DEBUG("%d:%d:%d => IRQ %d\n",
	    irq.busnum, irq.devnum, irq.funcnum, irq.irq);

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

static void vblank_disable_fn(void *arg)
{
	struct drm_device *dev = (struct drm_device *)arg;
	int i;

	if (!dev->vblank_disable_allowed)
		return;

	for (i = 0; i < dev->num_crtcs; i++) {
		if (atomic_read(&dev->vblank_refcount[i]) == 0 &&
		    atomic_read(&dev->vblank_enabled[i]) == 1) {
			dev->last_vblank[i] =
			    dev->driver->get_vblank_counter(dev, i);
			dev->driver->disable_vblank(dev, i);
			atomic_set(&dev->vblank_enabled[i], 0);
			DRM_DEBUG("disable vblank");
		}
	}
}

void
drm_vblank_cleanup(struct drm_device *dev)
{

	/* Bail if the driver didn't call drm_vblank_init() */
	if (dev->num_crtcs == 0)
		return;

	vblank_disable_fn((void *)dev);

	drm_free(dev->vbl_queues, sizeof (wait_queue_head_t) * dev->num_crtcs,
	    DRM_MEM_DRIVER);
	drm_free(dev->vbl_sigs, sizeof (struct drm_vbl_sig) * dev->num_crtcs,
	    DRM_MEM_DRIVER);
	drm_free(dev->_vblank_count, sizeof (atomic_t) *
	    dev->num_crtcs, DRM_MEM_DRIVER);
	drm_free(dev->vblank_refcount, sizeof (atomic_t) *
	    dev->num_crtcs, DRM_MEM_DRIVER);
	drm_free(dev->vblank_enabled, sizeof (int) *
	    dev->num_crtcs, DRM_MEM_DRIVER);
	drm_free(dev->last_vblank, sizeof (u32) * dev->num_crtcs,
	    DRM_MEM_DRIVER);
	drm_free(dev->vblank_inmodeset, sizeof (*dev->vblank_inmodeset) *
	    dev->num_crtcs, DRM_MEM_DRIVER);
	dev->num_crtcs = 0;
}

int
drm_vblank_init(struct drm_device *dev, int num_crtcs)
{
	int i, ret = ENOMEM;

	atomic_set(&dev->vbl_signal_pending, 0);
	dev->num_crtcs = num_crtcs;


	dev->vbl_queues = drm_alloc(sizeof (wait_queue_head_t) * num_crtcs,
	    DRM_MEM_DRIVER);
	if (!dev->vbl_queues)
		goto err;

	dev->vbl_sigs = drm_alloc(sizeof (struct drm_vbl_sig) * num_crtcs,
	    DRM_MEM_DRIVER);
	if (!dev->vbl_sigs)
		goto err;

	dev->_vblank_count = drm_alloc(sizeof (atomic_t) * num_crtcs,
	    DRM_MEM_DRIVER);
	if (!dev->_vblank_count)
		goto err;

	dev->vblank_refcount = drm_alloc(sizeof (atomic_t) * num_crtcs,
	    DRM_MEM_DRIVER);
	if (!dev->vblank_refcount)
		goto err;

	dev->vblank_enabled = drm_alloc(num_crtcs * sizeof (int),
	    DRM_MEM_DRIVER);
	if (!dev->vblank_enabled)
		goto err;

	dev->last_vblank = drm_alloc(num_crtcs * sizeof (u32), DRM_MEM_DRIVER);
	if (!dev->last_vblank)
		goto err;

	dev->vblank_inmodeset = drm_alloc(num_crtcs * sizeof (int),
	    DRM_MEM_DRIVER);
	if (!dev->vblank_inmodeset)
		goto err;

	/* Zero per-crtc vblank stuff */
	for (i = 0; i < num_crtcs; i++) {
		DRM_INIT_WAITQUEUE(&dev->vbl_queues[i], DRM_INTR_PRI(dev));
		TAILQ_INIT(&dev->vbl_sigs[i]);
		atomic_set(&dev->_vblank_count[i], 0);
		atomic_set(&dev->vblank_refcount[i], 0);
	}

	dev->vblank_disable_allowed = 1;
	return (0);

err:
	DRM_ERROR("drm_vblank_init: alloc error");
	drm_vblank_cleanup(dev);
	return (ret);
}

/*ARGSUSED*/
static int
drm_install_irq_handle(drm_device_t *dev)
{
	dev_info_t *dip = dev->dip;

	if (dip == NULL) {
		DRM_ERROR("drm_install_irq_handle: cannot get gfxp_fb's dip");
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

	DRM_DEBUG("drm_irq_install irq=%d\n", dev->irq);

	/* before installing handler */
	ret = dev->driver->irq_preinstall(dev);
	if (ret)
		return (EINVAL);

	/* install handler */
	ret  = drm_install_irq_handle(dev);
	if (ret != DDI_SUCCESS) {
		DRM_ERROR("drm_irq_install: drm_install_irq_handle failed");
		return (ret);
	}

	/* after installing handler */
	dev->driver->irq_postinstall(dev);

	dev->irq_enabled = 1;
	dev->context_flag = 0;

	return (0);
}

static void
drm_uninstall_irq_handle(drm_device_t *dev)
{
	ASSERT(dev->dip);
	ddi_remove_intr(dev->dip, 0, dev->intr_block);
}


/*ARGSUSED*/
int
drm_irq_uninstall(drm_device_t *dev)
{
	int i;
	if (!dev->irq_enabled) {
		return (EINVAL);
	}
	dev->irq_enabled = 0;

	/*
	 * Wake up any waiters so they don't hang.
	 */
	DRM_SPINLOCK(&dev->vbl_lock);
	for (i = 0; i < dev->num_crtcs; i++) {
		DRM_WAKEUP(&dev->vbl_queues[i]);
		dev->vblank_enabled[i] = 0;
	}
	DRM_SPINUNLOCK(&dev->vbl_lock);

	dev->driver->irq_uninstall(dev);
	drm_uninstall_irq_handle(dev);
	dev->locked_tasklet_func = NULL;

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

u32
drm_vblank_count(struct drm_device *dev, int crtc)
{
	return (atomic_read(&dev->_vblank_count[crtc]));
}

static void drm_update_vblank_count(struct drm_device *dev, int crtc)
{
	u32 cur_vblank, diff;
	/*
	 * Interrupts were disabled prior to this call, so deal with counter
	 * wrap if needed.
	 * NOTE!  It's possible we lost a full dev->max_vblank_count events
	 * here if the register is small or we had vblank interrupts off for
	 * a long time.
	 */
	cur_vblank = dev->driver->get_vblank_counter(dev, crtc);
	diff = cur_vblank - dev->last_vblank[crtc];
	if (cur_vblank < dev->last_vblank[crtc]) {
		diff += dev->max_vblank_count;
	DRM_DEBUG("last_vblank[%d]=0x%x, cur_vblank=0x%x => diff=0x%x\n",
	    crtc, dev->last_vblank[crtc], cur_vblank, diff);
	}

	atomic_add(diff, &dev->_vblank_count[crtc]);
}

static timeout_id_t timer_id = NULL;

int
drm_vblank_get(struct drm_device *dev, int crtc)
{
	int ret = 0;

	DRM_SPINLOCK(&dev->vbl_lock);

	if (timer_id != NULL) {
		(void) untimeout(timer_id);
		timer_id = NULL;
	}

	/* Going from 0->1 means we have to enable interrupts again */
	atomic_add(1, &dev->vblank_refcount[crtc]);
	if (dev->vblank_refcount[crtc] == 1 &&
	    atomic_read(&dev->vblank_enabled[crtc]) == 0) {
		ret = dev->driver->enable_vblank(dev, crtc);
		if (ret)
			atomic_dec(&dev->vblank_refcount[crtc]);
		else {
			atomic_set(&dev->vblank_enabled[crtc], 1);
			drm_update_vblank_count(dev, crtc);
		}
	}
	DRM_SPINUNLOCK(&dev->vbl_lock);

	return (ret);
}

void
drm_vblank_put(struct drm_device *dev, int crtc)
{
	DRM_SPINLOCK(&dev->vbl_lock);
	/* Last user schedules interrupt disable */
	atomic_dec(&dev->vblank_refcount[crtc]);

	if (dev->vblank_refcount[crtc] == 0)
		timer_id = timeout(vblank_disable_fn, (void *) dev, 5*DRM_HZ);

	DRM_SPINUNLOCK(&dev->vbl_lock);
}

/*
 * drm_modeset_ctl - handle vblank event counter changes across mode switch
 * @DRM_IOCTL_ARGS: standard ioctl arguments
 *
 * Applications should call the %_DRM_PRE_MODESET and %_DRM_POST_MODESET
 * ioctls around modesetting so that any lost vblank events are accounted for.
 *
 * Generally the counter will reset across mode sets.  If interrupts are
 * enabled around this call, we don't have to do anything since the counter
 * will have already been incremented.
 */
/*ARGSUSED*/
int
drm_modeset_ctl(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	struct drm_modeset_ctl modeset;
	int crtc, ret = 0;

	/* If drm_vblank_init() hasn't been called yet, just no-op */
	if (!dev->num_crtcs)
		goto out;

	DRM_COPYFROM_WITH_RETURN(&modeset, (void *)data,
	    sizeof (modeset));

	crtc = modeset.crtc;
	if (crtc >= dev->num_crtcs) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * To avoid all the problems that might happen if interrupts
	 * were enabled/disabled around or between these calls, we just
	 * have the kernel take a reference on the CRTC (just once though
	 * to avoid corrupting the count if multiple, mismatch calls occur),
	 * so that interrupts remain enabled in the interim.
	 */
	switch (modeset.cmd) {
	case _DRM_PRE_MODESET:
		if (!dev->vblank_inmodeset[crtc]) {
			dev->vblank_inmodeset[crtc] = 1;
			ret = drm_vblank_get(dev, crtc);
		}
		break;
	case _DRM_POST_MODESET:
		if (dev->vblank_inmodeset[crtc]) {
			DRM_SPINLOCK(&dev->vbl_lock);
			dev->vblank_disable_allowed = 1;
			dev->vblank_inmodeset[crtc] = 0;
			DRM_SPINUNLOCK(&dev->vbl_lock);
			drm_vblank_put(dev, crtc);
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	return (ret);
}

/*ARGSUSED*/
int
drm_wait_vblank(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_wait_vblank_t vblwait;
	int ret, flags, crtc;
	unsigned int	sequence;

	if (!dev->irq_enabled) {
		DRM_ERROR("wait vblank, EINVAL");
		return (EINVAL);
	}
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
		DRM_ERROR("drm_wait_vblank: wrong request type 0x%x",
		    vblwait.request.type);
		return (EINVAL);
	}

	flags = vblwait.request.type & _DRM_VBLANK_FLAGS_MASK;
	crtc = flags & _DRM_VBLANK_SECONDARY ? 1 : 0;
	if (crtc >= dev->num_crtcs) {
		DRM_ERROR("wait vblank operation not support");
		return (ENOTSUP);
	}
	ret = drm_vblank_get(dev, crtc);
	if (ret) {
		DRM_ERROR("can't get drm vblank %d", ret);
		return (ret);
	}
	sequence = drm_vblank_count(dev, crtc);

	switch (vblwait.request.type & _DRM_VBLANK_TYPES_MASK) {
	case _DRM_VBLANK_RELATIVE:
		vblwait.request.sequence += sequence;
		vblwait.request.type &= ~_DRM_VBLANK_RELATIVE;
		/*FALLTHROUGH*/
	case _DRM_VBLANK_ABSOLUTE:
		break;
	default:
		DRM_DEBUG("wait vblank return EINVAL");
		return (EINVAL);
	}

	if ((flags & _DRM_VBLANK_NEXTONMISS) &&
	    (sequence - vblwait.request.sequence) <= (1<<23)) {
		vblwait.request.sequence = sequence + 1;
	}

	if (flags & _DRM_VBLANK_SIGNAL) {
		/*
		 * Don't block process, send signal when vblank interrupt
		 */
		DRM_ERROR("NOT SUPPORT YET, SHOULD BE ADDED");
		cmn_err(CE_WARN, "NOT SUPPORT YET, SHOULD BE ADDED");
		ret = EINVAL;
		goto done;
	} else {
		/* block until vblank interupt */
		/* shared code returns -errno */
		DRM_WAIT_ON(ret, &dev->vbl_queues[crtc], 3 * DRM_HZ,
		    (((drm_vblank_count(dev, crtc)
		    - vblwait.request.sequence) <= (1 << 23)) ||
		    !dev->irq_enabled));
		if (ret != EINTR) {
			struct timeval now;
			(void) uniqtime(&now);
			vblwait.reply.tval_sec = now.tv_sec;
			vblwait.reply.tval_usec = now.tv_usec;
			vblwait.reply.sequence = drm_vblank_count(dev, crtc);
		}
	}

done:
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_wait_vblank_32_t vblwait32;
		vblwait32.reply.type = vblwait.reply.type;
		vblwait32.reply.sequence = vblwait.reply.sequence;
		vblwait32.reply.tval_sec = (int32_t)vblwait.reply.tval_sec;
		vblwait32.reply.tval_usec = (int32_t)vblwait.reply.tval_usec;
		DRM_COPYTO_WITH_RETURN((void *)data, &vblwait32,
		    sizeof (vblwait32));
	} else {
#endif
		DRM_COPYTO_WITH_RETURN((void *)data, &vblwait,
		    sizeof (vblwait));
#ifdef _MULTI_DATAMODEL
	}
#endif

	drm_vblank_put(dev, crtc);
	return (ret);
}


/*ARGSUSED*/
void
drm_vbl_send_signals(drm_device_t *dev)
{
	DRM_DEBUG("drm_vbl_send_signals");
}

void
drm_handle_vblank(struct drm_device *dev, int crtc)
{
	atomic_inc(&dev->_vblank_count[crtc]);
	DRM_WAKEUP(&dev->vbl_queues[crtc]);
}
