/* BEGIN CSTYLED */

/* i915_irq.c -- IRQ support for the I915 -*- linux-c -*-
 */
/*
 * Copyright 2003 Tungsten Graphics, Inc., Cedar Park, Texas.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
 * IN NO EVENT SHALL TUNGSTEN GRAPHICS AND/OR ITS SUPPLIERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"
#include "drm.h"
#include "i915_drm.h"
#include "i915_drv.h"

#define USER_INT_FLAG (1<<1)
#define VSYNC_PIPEB_FLAG (1<<5)
#define VSYNC_PIPEA_FLAG (1<<7)

#define MAX_NOPID ((u32)~0)

/**
 * Emit blits for scheduled buffer swaps.
 *
 * This function will be called with the HW lock held.
 */
static void i915_vblank_tasklet(drm_device_t *dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	/* LINTED E_FUNC_VAR_UNUSED */
	unsigned long irqflags;
	struct list_head *list, *tmp, hits, *hit;
	int nhits, slice[2], upper[2], lower[2], i;
	unsigned counter[2] = { atomic_read(&dev->vbl_received),
				atomic_read(&dev->vbl_received2) };
	drm_drawable_info_t *drw;
	drm_i915_sarea_t *sarea_priv = dev_priv->sarea_priv;
	u32 cpp = dev_priv->cpp;
	u32 cmd = (cpp == 4) ? (XY_SRC_COPY_BLT_CMD |
				XY_SRC_COPY_BLT_WRITE_ALPHA |
				XY_SRC_COPY_BLT_WRITE_RGB)
			     : XY_SRC_COPY_BLT_CMD;
	u32 pitchropcpp = (sarea_priv->pitch * cpp) | (0xcc << 16) |
			  (cpp << 23) | (1 << 24);
	RING_LOCALS;

	DRM_DEBUG("%s\n", __FUNCTION__);

	INIT_LIST_HEAD(&hits);

	nhits = 0;
	spin_lock_irqsave(&dev_priv->swaps_lock, irqflags);

	/* Find buffer swaps scheduled for this vertical blank */
	list_for_each_safe(list, tmp, &dev_priv->vbl_swaps.head) {
		drm_i915_vbl_swap_t *vbl_swap =
			list_entry(list, drm_i915_vbl_swap_t, head);

		if ((counter[vbl_swap->pipe] - vbl_swap->sequence) > (1<<23))
			continue;

		list_del(list);
		dev_priv->swaps_pending--;

		spin_unlock(&dev_priv->swaps_lock);
		spin_lock(&dev->drw_lock);

		drw = drm_get_drawable_info(dev, vbl_swap->drw_id);

		if (!drw) {
			spin_unlock(&dev->drw_lock);
			drm_free(vbl_swap, sizeof(*vbl_swap), DRM_MEM_DRIVER);
			spin_lock(&dev_priv->swaps_lock);
			continue;
		}

		list_for_each(hit, &hits) {
			drm_i915_vbl_swap_t *swap_cmp =
				list_entry(hit, drm_i915_vbl_swap_t, head);
			drm_drawable_info_t *drw_cmp =
				drm_get_drawable_info(dev, swap_cmp->drw_id);

			if (drw_cmp &&
			    drw_cmp->rects[0].y1 > drw->rects[0].y1) {
				list_add_tail(list, hit);
				break;
			}
		}

		spin_unlock(&dev->drw_lock);

		/* List of hits was empty, or we reached the end of it */
		if (hit == &hits)
			list_add_tail(list, hits.prev);

		nhits++;

		spin_lock(&dev_priv->swaps_lock);
	}

	if (nhits == 0) {
		spin_unlock_irqrestore(&dev_priv->swaps_lock, irqflags);
		return;
	}

	spin_unlock(&dev_priv->swaps_lock);

	i915_kernel_lost_context(dev);

	BEGIN_LP_RING(6);

	OUT_RING(GFX_OP_DRAWRECT_INFO);
	OUT_RING(0);
	OUT_RING(0);
	OUT_RING(sarea_priv->width | sarea_priv->height << 16);
	OUT_RING(sarea_priv->width | sarea_priv->height << 16);
	OUT_RING(0);

	ADVANCE_LP_RING();

	sarea_priv->ctxOwner = DRM_KERNEL_CONTEXT;

	upper[0] = upper[1] = 0;
	slice[0] = max(sarea_priv->pipeA_h / nhits, 1);
	slice[1] = max(sarea_priv->pipeB_h / nhits, 1);
	lower[0] = sarea_priv->pipeA_y + slice[0];
	lower[1] = sarea_priv->pipeB_y + slice[0];

	spin_lock(&dev->drw_lock);

	/* Emit blits for buffer swaps, partitioning both outputs into as many
	 * slices as there are buffer swaps scheduled in order to avoid tearing
	 * (based on the assumption that a single buffer swap would always
	 * complete before scanout starts).
	 */
	for (i = 0; i++ < nhits;
	     upper[0] = lower[0], lower[0] += slice[0],
	     upper[1] = lower[1], lower[1] += slice[1]) {
		if (i == nhits)
			lower[0] = lower[1] = sarea_priv->height;

		list_for_each(hit, &hits) {
			drm_i915_vbl_swap_t *swap_hit =
				list_entry(hit, drm_i915_vbl_swap_t, head);
			drm_clip_rect_t *rect;
			int num_rects, pipe;
			unsigned short top, bottom;

			drw = drm_get_drawable_info(dev, swap_hit->drw_id);

			if (!drw)
				continue;

			rect = drw->rects;
			pipe = swap_hit->pipe;
			top = upper[pipe];
			bottom = lower[pipe];

			for (num_rects = drw->num_rects; num_rects--; rect++) {
				int y1 = max(rect->y1, top);
				int y2 = min(rect->y2, bottom);

				if (y1 >= y2)
					continue;

				BEGIN_LP_RING(8);

				OUT_RING(cmd);
				OUT_RING(pitchropcpp);
				OUT_RING((y1 << 16) | rect->x1);
				OUT_RING((y2 << 16) | rect->x2);
				OUT_RING(sarea_priv->front_offset);
				OUT_RING((y1 << 16) | rect->x1);
				OUT_RING(pitchropcpp & 0xffff);
				OUT_RING(sarea_priv->back_offset);

				ADVANCE_LP_RING();
			}
		}
	}

	spin_unlock_irqrestore(&dev->drw_lock, irqflags);

	list_for_each_safe(hit, tmp, &hits) {
		drm_i915_vbl_swap_t *swap_hit =
			list_entry(hit, drm_i915_vbl_swap_t, head);

		list_del(hit);

		drm_free(swap_hit, sizeof(*swap_hit), DRM_MEM_DRIVER);
	}
}

irqreturn_t i915_driver_irq_handler(DRM_IRQ_ARGS)
{
	drm_device_t *dev = (drm_device_t *) arg;
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	u16 temp;
	u32 pipea_stats, pipeb_stats;

	pipea_stats = I915_READ(I915REG_PIPEASTAT);
	pipeb_stats = I915_READ(I915REG_PIPEBSTAT);
		
	temp = I915_READ16(I915REG_INT_IDENTITY_R);
	temp &= (dev_priv->irq_enable_reg | USER_INT_FLAG);

#if 0
	DRM_DEBUG("%s flag=%08x\n", __FUNCTION__, temp);
#endif
        if (temp == 0)
                return IRQ_NONE;

	I915_WRITE16(I915REG_INT_IDENTITY_R, temp);

	dev_priv->sarea_priv->last_dispatch = READ_BREADCRUMB(dev_priv);

	if (temp & USER_INT_FLAG) {
		DRM_WAKEUP(&dev_priv->irq_queue);
#ifdef I915_HAVE_FENCE
		i915_fence_handler(dev);
#endif
	}

	if (temp & (VSYNC_PIPEA_FLAG | VSYNC_PIPEB_FLAG)) {
		int vblank_pipe = dev_priv->vblank_pipe;

		if ((vblank_pipe &
		     (DRM_I915_VBLANK_PIPE_A | DRM_I915_VBLANK_PIPE_B))
		    == (DRM_I915_VBLANK_PIPE_A | DRM_I915_VBLANK_PIPE_B)) {
			if (temp & VSYNC_PIPEA_FLAG)
				atomic_inc(&dev->vbl_received);
			if (temp & VSYNC_PIPEB_FLAG)
				atomic_inc(&dev->vbl_received2);
		} else if (((temp & VSYNC_PIPEA_FLAG) &&
			    (vblank_pipe & DRM_I915_VBLANK_PIPE_A)) ||
			   ((temp & VSYNC_PIPEB_FLAG) &&
			    (vblank_pipe & DRM_I915_VBLANK_PIPE_B)))
			atomic_inc(&dev->vbl_received);

		DRM_WAKEUP(&dev->vbl_queue);
		drm_vbl_send_signals(dev);

		if (dev_priv->swaps_pending > 0)
			drm_locked_tasklet(dev, i915_vblank_tasklet);
		I915_WRITE(I915REG_PIPEASTAT, 
			pipea_stats|I915_VBLANK_INTERRUPT_ENABLE|
			I915_VBLANK_CLEAR);
		I915_WRITE(I915REG_PIPEBSTAT,
			pipeb_stats|I915_VBLANK_INTERRUPT_ENABLE|
			I915_VBLANK_CLEAR);
	}

        return IRQ_HANDLED;
}

int i915_emit_irq(drm_device_t * dev)
{

	drm_i915_private_t *dev_priv = dev->dev_private;
	RING_LOCALS;

	i915_kernel_lost_context(dev);

	DRM_DEBUG("%s\n", __FUNCTION__);

	dev_priv->sarea_priv->last_enqueue = ++dev_priv->counter;

	if (dev_priv->counter > 0x7FFFFFFFUL)
		 dev_priv->sarea_priv->last_enqueue = dev_priv->counter = 1;

	BEGIN_LP_RING(6);
	OUT_RING(CMD_STORE_DWORD_IDX);
	OUT_RING(20);
	OUT_RING(dev_priv->counter);

	OUT_RING(0);
	OUT_RING(0);
	OUT_RING(GFX_OP_USER_INTERRUPT);
	ADVANCE_LP_RING();

	return dev_priv->counter;


}

void i915_user_irq_on(drm_i915_private_t *dev_priv)
{
	spin_lock(&dev_priv->user_irq_lock);
	if (dev_priv->irq_enabled && (++dev_priv->user_irq_refcount == 1)){
		dev_priv->irq_enable_reg |= USER_INT_FLAG;
		I915_WRITE16(I915REG_INT_ENABLE_R, dev_priv->irq_enable_reg);
	}
	spin_unlock(&dev_priv->user_irq_lock);

}
		
void i915_user_irq_off(drm_i915_private_t *dev_priv)
{
	spin_lock(&dev_priv->user_irq_lock);
	if (dev_priv->irq_enabled && (--dev_priv->user_irq_refcount == 0)) {
		/*EMPTY*/;
		//		dev_priv->irq_enable_reg &= ~USER_INT_FLAG;
		//		I915_WRITE16(I915REG_INT_ENABLE_R, dev_priv->irq_enable_reg);
	}
	spin_unlock(&dev_priv->user_irq_lock);
}


static int i915_wait_irq(drm_device_t * dev, int irq_nr)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	int ret = 0;

	DRM_DEBUG("%s irq_nr=%d breadcrumb=%d\n", __FUNCTION__, irq_nr,
		  READ_BREADCRUMB(dev_priv));

	if (READ_BREADCRUMB(dev_priv) >= irq_nr)
		return 0;

	dev_priv->sarea_priv->perf_boxes |= I915_BOX_WAIT;

	i915_user_irq_on(dev_priv);
	DRM_WAIT_ON(ret, &dev_priv->irq_queue, 3 * DRM_HZ,
		    READ_BREADCRUMB(dev_priv) >= irq_nr);
	i915_user_irq_off(dev_priv);

	if (ret == EBUSY) {
		DRM_ERROR("%s: EBUSY -- rec: %d emitted: %d\n",
			  __FUNCTION__,
			  READ_BREADCRUMB(dev_priv), (int)dev_priv->counter);
	}

	dev_priv->sarea_priv->last_dispatch = READ_BREADCRUMB(dev_priv);
	return ret;
}

static int i915_driver_vblank_do_wait(drm_device_t *dev, unsigned int *sequence,
				      atomic_t *counter)
{
	drm_i915_private_t *dev_priv = dev->dev_private;
	unsigned int cur_vblank;
	int ret = 0;

	if (!dev_priv) {
		DRM_ERROR("%s called with no initialization\n", __FUNCTION__);
		return (EINVAL);
	}

	DRM_WAIT_ON(ret, &dev->vbl_queue, 3 * DRM_HZ,
		    (((cur_vblank = atomic_read(counter))
			- *sequence) <= (1<<23)));
	
	*sequence = cur_vblank;

	return ret;
}

int i915_driver_vblank_wait(drm_device_t *dev, unsigned int *sequence)
{
	return i915_driver_vblank_do_wait(dev, sequence, &dev->vbl_received);
}

int i915_driver_vblank_wait2(drm_device_t *dev, unsigned int *sequence)
{
	return i915_driver_vblank_do_wait(dev, sequence, &dev->vbl_received2);
}

/* Needs the lock as it touches the ring.
 */
/*ARGSUSED*/
int i915_irq_emit(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_i915_private_t *dev_priv = dev->dev_private;
	drm_i915_irq_emit_t emit;
	int result;

	LOCK_TEST_WITH_RETURN(dev, fpriv);

	if (!dev_priv) {
		DRM_ERROR("%s called with no initialization\n", __FUNCTION__);
		return (EINVAL);
	}

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_i915_irq_emit32_t irq_emit32;

		DRM_COPYFROM_WITH_RETURN(&irq_emit32,
			(drm_i915_irq_emit32_t __user *) data,
			sizeof (drm_i915_irq_emit32_t));
		emit.irq_seq = (int __user *)(uintptr_t)irq_emit32.irq_seq;
	} else
		DRM_COPYFROM_WITH_RETURN(&emit,
		    (drm_i915_irq_emit_t __user *) data, sizeof(emit));

	result = i915_emit_irq(dev);

	if (DRM_COPY_TO_USER(emit.irq_seq, &result, sizeof(int))) {
		DRM_ERROR("copy_to_user\n");
		return (EFAULT);
	}

	return 0;
}

/* Doesn't need the hardware lock.
 */
/*ARGSUSED*/
int i915_irq_wait(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_i915_private_t *dev_priv = dev->dev_private;
	drm_i915_irq_wait_t irqwait;

	if (!dev_priv) {
		DRM_ERROR("%s called with no initialization\n", __FUNCTION__);
		return (EINVAL);
	}

	DRM_COPYFROM_WITH_RETURN(&irqwait,
	    (drm_i915_irq_wait_t __user *) data, sizeof(irqwait));

	return i915_wait_irq(dev, irqwait.irq_seq);
}

static void i915_enable_interrupt (drm_device_t *dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	
	dev_priv->irq_enable_reg = USER_INT_FLAG; 
	if (dev_priv->vblank_pipe & DRM_I915_VBLANK_PIPE_A)
		dev_priv->irq_enable_reg |= VSYNC_PIPEA_FLAG;
	if (dev_priv->vblank_pipe & DRM_I915_VBLANK_PIPE_B)
		dev_priv->irq_enable_reg |= VSYNC_PIPEB_FLAG;

	I915_WRITE16(I915REG_INT_ENABLE_R, dev_priv->irq_enable_reg);
	dev_priv->irq_enabled = 1;
}

/* drm_dma.h hooks
*/
void i915_driver_irq_preinstall(drm_device_t * dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;

	I915_WRITE16(I915REG_HWSTAM, 0xeffe);
	I915_WRITE16(I915REG_INT_MASK_R, 0x0);
	I915_WRITE16(I915REG_INT_ENABLE_R, 0x0);
}

void i915_driver_irq_postinstall(drm_device_t * dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;

	mutex_init(&dev_priv->swaps_lock, NULL, MUTEX_DRIVER, NULL);
	INIT_LIST_HEAD(&dev_priv->vbl_swaps.head);
	dev_priv->swaps_pending = 0;

	if (!dev_priv->vblank_pipe)
		dev_priv->vblank_pipe = DRM_I915_VBLANK_PIPE_A;

	mutex_init(&dev_priv->user_irq_lock, NULL, MUTEX_DRIVER, NULL);
	dev_priv->user_irq_refcount = 0;

	if (!dev_priv->vblank_pipe)
		dev_priv->vblank_pipe = DRM_I915_VBLANK_PIPE_A;

	DRM_INIT_WAITQUEUE(&dev_priv->irq_queue, DRM_INTR_PRI(dev));

	i915_enable_interrupt(dev);


	/*
	 * Initialize the hardware status page IRQ location.
	 */

	I915_WRITE(I915REG_INSTPM, (1 << 5) | (1 << 21));
}

void i915_driver_irq_uninstall(drm_device_t * dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	u16 temp;
	if (!dev_priv)
		return;

	dev_priv->irq_enabled = 0;
	I915_WRITE16(I915REG_HWSTAM, 0xffff);
	I915_WRITE16(I915REG_INT_MASK_R, 0xffff);
	I915_WRITE16(I915REG_INT_ENABLE_R, 0x0);

	temp = I915_READ16(I915REG_INT_IDENTITY_R);
	I915_WRITE16(I915REG_INT_IDENTITY_R, temp);

	DRM_FINI_WAITQUEUE(&dev_priv->irq_queue);
	mutex_destroy(&dev_priv->swaps_lock);
	mutex_destroy(&dev_priv->user_irq_lock);

}
