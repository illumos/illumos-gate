/* BEGIN CSTYLED */

/* i915_irq.c -- IRQ support for the I915 -*- linux-c -*-
 */
/*
 * Copyright 2003 Tungsten Graphics, Inc., Cedar Park, Texas.
 * Copyright (c) 2009, Intel Corporation.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "drmP.h"
#include "drm.h"
#include "i915_drm.h"
#include "i915_drv.h"


#define MAX_NOPID ((u32)~0)

/**
 * Interrupts that are always left unmasked.
 *
 * Since pipe events are edge-triggered from the PIPESTAT register to IIR,
 * we leave them always unmasked in IMR and then control enabling them through
 * PIPESTAT alone.
 */

#define I915_INTERRUPT_ENABLE_FIX (I915_ASLE_INTERRUPT |		 \
				   I915_DISPLAY_PIPE_A_EVENT_INTERRUPT | \
				   I915_DISPLAY_PIPE_B_EVENT_INTERRUPT | \
				   I915_RENDER_COMMAND_PARSER_ERROR_INTERRUPT)

/** Interrupts that we mask and unmask at runtime. */
#define I915_INTERRUPT_ENABLE_VAR (I915_USER_INTERRUPT)

/** These are all of the interrupts used by the driver */
#define I915_INTERRUPT_ENABLE_MASK (I915_INTERRUPT_ENABLE_FIX | \
				    I915_INTERRUPT_ENABLE_VAR)

void
igdng_enable_irq(drm_i915_private_t *dev_priv, u32 mask, int gfx_irq)
{
	if (gfx_irq && ((dev_priv->gt_irq_mask_reg & mask) != 0)) {
		dev_priv->gt_irq_mask_reg &= ~mask;
		I915_WRITE(GTIMR, dev_priv->gt_irq_mask_reg);
		(void) I915_READ(GTIMR);
	} else if ((dev_priv->irq_mask_reg & mask) != 0) {
		dev_priv->irq_mask_reg &= ~mask;
		I915_WRITE(DEIMR, dev_priv->irq_mask_reg);
		(void) I915_READ(DEIMR);

	}
}

static inline void
igdng_disable_irq(drm_i915_private_t *dev_priv, u32 mask, int gfx_irq)
{
	if (gfx_irq && ((dev_priv->gt_irq_mask_reg & mask) != mask)) {
		dev_priv->gt_irq_mask_reg |= mask;
		I915_WRITE(GTIMR, dev_priv->gt_irq_mask_reg);
		(void) I915_READ(GTIMR);
	} else if ((dev_priv->irq_mask_reg & mask) != mask) {
		dev_priv->irq_mask_reg |= mask;
		I915_WRITE(DEIMR, dev_priv->irq_mask_reg);
		(void) I915_READ(DEIMR);
	}
}

/* For display hotplug interrupt */
void
igdng_enable_display_irq(drm_i915_private_t *dev_priv, u32 mask)
{
       if ((dev_priv->irq_mask_reg & mask) != 0) {
               dev_priv->irq_mask_reg &= ~mask;
               I915_WRITE(DEIMR, dev_priv->irq_mask_reg);
               (void) I915_READ(DEIMR);
       }
}

#if 0
static inline void
igdng_disable_display_irq(drm_i915_private_t *dev_priv, u32 mask)
{
       if ((dev_priv->irq_mask_reg & mask) != mask) {
               dev_priv->irq_mask_reg |= mask;
               I915_WRITE(DEIMR, dev_priv->irq_mask_reg);
               (void) I915_READ(DEIMR);
       }
}
#endif

static inline void
i915_enable_irq(drm_i915_private_t *dev_priv, uint32_t mask)
{
        if ((dev_priv->irq_mask_reg & mask) != 0) {
                dev_priv->irq_mask_reg &= ~mask;
                I915_WRITE(IMR, dev_priv->irq_mask_reg);
                (void) I915_READ(IMR);
        }
}

static inline void
i915_disable_irq(drm_i915_private_t *dev_priv, uint32_t mask)
{
	if ((dev_priv->irq_mask_reg & mask) != mask) {
                dev_priv->irq_mask_reg |= mask;
                I915_WRITE(IMR, dev_priv->irq_mask_reg);
                (void) I915_READ(IMR);
        }
}

static inline uint32_t
i915_pipestat(int pipe)
{
	if (pipe == 0)
		return PIPEASTAT;
	if (pipe == 1)
		return PIPEBSTAT;
	return 0;
}

void
i915_enable_pipestat(drm_i915_private_t *dev_priv, int pipe, uint32_t mask)
{
	if ((dev_priv->pipestat[pipe] & mask) != mask) {
		u32 reg = i915_pipestat(pipe);

		dev_priv->pipestat[pipe] |= mask;
		/* Enable the interrupt, clear any pending status */
		I915_WRITE(reg, dev_priv->pipestat[pipe] | (mask >> 16));
		(void) I915_READ(reg);
	}
}

void
i915_disable_pipestat(drm_i915_private_t *dev_priv, int pipe, u32 mask)
{
	if ((dev_priv->pipestat[pipe] & mask) != 0) {
		u32 reg = i915_pipestat(pipe);

		dev_priv->pipestat[pipe] &= ~mask;
		I915_WRITE(reg, dev_priv->pipestat[pipe]);
		(void) I915_READ(reg);
	}
}

/**
 * i915_pipe_enabled - check if a pipe is enabled
 * @dev: DRM device
 * @pipe: pipe to check
 *
 * Reading certain registers when the pipe is disabled can hang the chip.
 * Use this routine to make sure the PLL is running and the pipe is active
 * before reading such registers if unsure.
 */
static int
i915_pipe_enabled(struct drm_device *dev, int pipe)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	unsigned long pipeconf = pipe ? PIPEBCONF : PIPEACONF;

	if (I915_READ(pipeconf) & PIPEACONF_ENABLE)
		return 1;

	return 0;
}

u32 i915_get_vblank_counter(struct drm_device *dev, int pipe)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	unsigned long high_frame;
	unsigned long low_frame;
	u32 high1, high2, low, count;

	high_frame = pipe ? PIPEBFRAMEHIGH : PIPEAFRAMEHIGH;
	low_frame = pipe ? PIPEBFRAMEPIXEL : PIPEAFRAMEPIXEL;

	if (!i915_pipe_enabled(dev, pipe)) {
	    DRM_ERROR("trying to get vblank count for disabled pipe %d\n", pipe);
	    return 0;
	}

	/*
	 * High & low register fields aren't synchronized, so make sure
	 * we get a low value that's stable across two reads of the high
	 * register.
	 */
	do {
		high1 = ((I915_READ(high_frame) & PIPE_FRAME_HIGH_MASK) >>
			 PIPE_FRAME_HIGH_SHIFT);
		low =  ((I915_READ(low_frame) & PIPE_FRAME_LOW_MASK) >>
			PIPE_FRAME_LOW_SHIFT);
		high2 = ((I915_READ(high_frame) & PIPE_FRAME_HIGH_MASK) >>
			 PIPE_FRAME_HIGH_SHIFT);
	} while (high1 != high2);

	count = (high1 << 8) | low;

	return count;
}

/**
 * i915_capture_error_state - capture an error record for later analysis
 * @dev: drm device
 *
 * Should be called when an error is detected (either a hang or an error
 * interrupt) to capture error state from the time of the error.  Fills
 * out a structure which becomes available in debugfs for user level tools
 * to pick up.
 */
static void i915_capture_error_state(struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	struct drm_i915_error_state *error;

	spin_lock_irqsave(&dev_priv->error_lock, flags);
#if 0
	if (dev_priv->first_error)
		goto out;
#endif
	error = drm_alloc(sizeof(*error), DRM_MEM_DRIVER);
	if (!error) {
		DRM_DEBUG("out ot memory, not capturing error state\n");
		goto out;
	}

	error->eir = I915_READ(EIR);
	error->pgtbl_er = I915_READ(PGTBL_ER);
	error->pipeastat = I915_READ(PIPEASTAT);
	error->pipebstat = I915_READ(PIPEBSTAT);
	error->instpm = I915_READ(INSTPM);
	if (!IS_I965G(dev)) {
		error->ipeir = I915_READ(IPEIR);
		error->ipehr = I915_READ(IPEHR);
		error->instdone = I915_READ(INSTDONE);
		error->acthd = I915_READ(ACTHD);
	} else {
		error->ipeir = I915_READ(IPEIR_I965);
		error->ipehr = I915_READ(IPEHR_I965);
		error->instdone = I915_READ(INSTDONE_I965);
		error->instps = I915_READ(INSTPS);
		error->instdone1 = I915_READ(INSTDONE1);
		error->acthd = I915_READ(ACTHD_I965);
	}

	(void) uniqtime(&error->time);

	dev_priv->first_error = error;
	
	DRM_DEBUG("Time: %ld s %ld us\n", error->time.tv_sec,
		   error->time.tv_usec);
	DRM_DEBUG("EIR: 0x%08x\n", error->eir);
	DRM_DEBUG("  PGTBL_ER: 0x%08x\n", error->pgtbl_er);
	DRM_DEBUG("  INSTPM: 0x%08x\n", error->instpm);
	DRM_DEBUG("  IPEIR: 0x%08x\n", error->ipeir);
	DRM_DEBUG("  IPEHR: 0x%08x\n", error->ipehr);
	DRM_DEBUG("  INSTDONE: 0x%08x\n", error->instdone);
	DRM_DEBUG("  ACTHD: 0x%08x\n", error->acthd);
	DRM_DEBUG("  DMA_FADD_P: 0x%08x\n", I915_READ(0x2078));
	if (IS_I965G(dev)) {
		DRM_DEBUG("  INSTPS: 0x%08x\n", error->instps);
		DRM_DEBUG("  INSTDONE1: 0x%08x\n", error->instdone1);
	}
	drm_free(error, sizeof(*error), DRM_MEM_DRIVER);
out:
	spin_unlock_irqrestore(&dev_priv->error_lock, flags);
}

/**
 * i915_handle_error - handle an error interrupt
 * @dev: drm device
 *
 * Do some basic checking of regsiter state at error interrupt time and
 * dump it to the syslog.  Also call i915_capture_error_state() to make
 * sure we get a record and make it available in debugfs.  Fire a uevent
 * so userspace knows something bad happened (should trigger collection
 * of a ring dump etc.).
 */
void i915_handle_error(struct drm_device *dev)
{
	struct drm_i915_private *dev_priv = dev->dev_private;
	u32 eir = I915_READ(EIR);
	u32 pipea_stats = I915_READ(PIPEASTAT);
	u32 pipeb_stats = I915_READ(PIPEBSTAT);

	i915_capture_error_state(dev);

	DRM_DEBUG("render error detected, EIR: 0x%08x\n",
	       eir);

	if (IS_G4X(dev)) {
		if (eir & (GM45_ERROR_MEM_PRIV | GM45_ERROR_CP_PRIV)) {
			u32 ipeir = I915_READ(IPEIR_I965);

			DRM_DEBUG("  IPEIR: 0x%08x\n",
			       I915_READ(IPEIR_I965));
			DRM_DEBUG("  IPEHR: 0x%08x\n",
			       I915_READ(IPEHR_I965));
			DRM_DEBUG("  INSTDONE: 0x%08x\n",
			       I915_READ(INSTDONE_I965));
			DRM_DEBUG("  INSTPS: 0x%08x\n",
			       I915_READ(INSTPS));
			DRM_DEBUG("  INSTDONE1: 0x%08x\n",
			       I915_READ(INSTDONE1));
			DRM_DEBUG("  ACTHD: 0x%08x\n",
			       I915_READ(ACTHD_I965));
			I915_WRITE(IPEIR_I965, ipeir);
			(void)I915_READ(IPEIR_I965);
		}
		if (eir & GM45_ERROR_PAGE_TABLE) {
			u32 pgtbl_err = I915_READ(PGTBL_ER);
			DRM_DEBUG("page table error\n");
			DRM_DEBUG("  PGTBL_ER: 0x%08x\n",
			       pgtbl_err);
			I915_WRITE(PGTBL_ER, pgtbl_err);
			(void)I915_READ(PGTBL_ER);
		}
	}

	if (IS_I9XX(dev)) {
		if (eir & I915_ERROR_PAGE_TABLE) {
			u32 pgtbl_err = I915_READ(PGTBL_ER);
			DRM_DEBUG("page table error\n");
			DRM_DEBUG("PGTBL_ER: 0x%08x\n",
			       pgtbl_err);
			I915_WRITE(PGTBL_ER, pgtbl_err);
			(void)I915_READ(PGTBL_ER);
		}
	}

	if (eir & I915_ERROR_MEMORY_REFRESH) {
		DRM_DEBUG("memory refresh error\n");
		DRM_DEBUG("PIPEASTAT: 0x%08x\n",
		       pipea_stats);
		DRM_DEBUG("PIPEBSTAT: 0x%08x\n",
		       pipeb_stats);
		/* pipestat has already been acked */
	}
	if (eir & I915_ERROR_INSTRUCTION) {
		DRM_DEBUG("instruction error\n");
		DRM_DEBUG("  INSTPM: 0x%08x\n",
		       I915_READ(INSTPM));
		if (!IS_I965G(dev)) {
			u32 ipeir = I915_READ(IPEIR);

			DRM_DEBUG("  IPEIR: 0x%08x\n",
			       I915_READ(IPEIR));
			DRM_DEBUG("  IPEHR: 0x%08x\n",
			       I915_READ(IPEHR));
			DRM_DEBUG("  INSTDONE: 0x%08x\n",
			       I915_READ(INSTDONE));
			DRM_DEBUG("  ACTHD: 0x%08x\n",
			       I915_READ(ACTHD));
			I915_WRITE(IPEIR, ipeir);
			(void)I915_READ(IPEIR);
		} else {
			u32 ipeir = I915_READ(IPEIR_I965);

			DRM_DEBUG("  IPEIR: 0x%08x\n",
			       I915_READ(IPEIR_I965));
			DRM_DEBUG("  IPEHR: 0x%08x\n",
			       I915_READ(IPEHR_I965));
			DRM_DEBUG("  INSTDONE: 0x%08x\n",
			       I915_READ(INSTDONE_I965));
			DRM_DEBUG("  INSTPS: 0x%08x\n",
			       I915_READ(INSTPS));
			DRM_DEBUG("  INSTDONE1: 0x%08x\n",
			       I915_READ(INSTDONE1));
			DRM_DEBUG("  ACTHD: 0x%08x\n",
			       I915_READ(ACTHD_I965));
			I915_WRITE(IPEIR_I965, ipeir);
			(void)I915_READ(IPEIR_I965);
		}
	}

	I915_WRITE(EIR, eir);
	(void)I915_READ(EIR);
	eir = I915_READ(EIR);
	if (eir) {
		/*
		 * some errors might have become stuck,
		 * mask them.
		 */
		DRM_DEBUG("EIR stuck: 0x%08x, masking\n", eir);
		I915_WRITE(EMR, I915_READ(EMR) | eir);
		I915_WRITE(IIR, I915_RENDER_COMMAND_PARSER_ERROR_INTERRUPT);
	}

}

u32 gm45_get_vblank_counter(struct drm_device *dev, int pipe)
{
       drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
       int reg = pipe ? PIPEB_FRMCOUNT_GM45 : PIPEA_FRMCOUNT_GM45;

       if (!i915_pipe_enabled(dev, pipe)) {
		DRM_ERROR("trying to get vblank count for disabled pipe %d\n", pipe);
               return 0;
       }

       return I915_READ(reg);
}

irqreturn_t igdng_irq_handler(struct drm_device *dev)
{
       drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
       int ret = IRQ_NONE;
       u32 de_iir, gt_iir, de_ier;
       u32 new_de_iir, new_gt_iir;
       int vblank = 0;

	/* disable master interrupt before clearing iir  */
	de_ier = I915_READ(DEIER);
	I915_WRITE(DEIER, de_ier & ~DE_MASTER_IRQ_CONTROL);
	(void)I915_READ(DEIER);

       de_iir = I915_READ(DEIIR);
       gt_iir = I915_READ(GTIIR);

       for (;;) {
               if (de_iir == 0 && gt_iir == 0)
                       break;

               ret = IRQ_HANDLED;

               I915_WRITE(DEIIR, de_iir);
               new_de_iir = I915_READ(DEIIR);
               I915_WRITE(GTIIR, gt_iir);
               new_gt_iir = I915_READ(GTIIR);

        if (dev_priv->sarea_priv) {
            dev_priv->sarea_priv->last_dispatch = READ_BREADCRUMB(dev_priv);

	}

               if (gt_iir & GT_USER_INTERRUPT) {
                       dev_priv->mm.irq_gem_seqno = i915_get_gem_seqno(dev);
                       DRM_WAKEUP(&dev_priv->irq_queue);
               }
               if (de_iir & DE_PIPEA_VBLANK) {
                       vblank++;
                       drm_handle_vblank(dev, 0);
               }

               if (de_iir & DE_PIPEB_VBLANK) {
                       vblank++;
                       drm_handle_vblank(dev, 1);
               }

               de_iir = new_de_iir;
               gt_iir = new_gt_iir;
       }

	I915_WRITE(DEIER, de_ier);
	(void)I915_READ(DEIER);

       return ret;
}

irqreturn_t i915_driver_irq_handler(DRM_IRQ_ARGS)
{
        drm_device_t *dev = (drm_device_t *) (void *) arg;
        drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
        u32 iir;
        u32 pipea_stats = 0, pipeb_stats = 0;
	int vblank = 0;

	if (IS_IGDNG(dev))
		return igdng_irq_handler(dev);

	iir = I915_READ(IIR);

	if (iir == 0) {
		return IRQ_NONE;
	}
start:

	if (dev_priv->sarea_priv) {
		if (dev_priv->hw_status_page)
	    		dev_priv->sarea_priv->last_dispatch = READ_BREADCRUMB(dev_priv);
	}

	I915_WRITE(IIR, iir);

	(void) I915_READ(IIR); /* Flush posted writes */


	if (iir & I915_RENDER_COMMAND_PARSER_ERROR_INTERRUPT)
		i915_handle_error(dev);

        if (iir & I915_USER_INTERRUPT) {
		dev_priv->mm.irq_gem_seqno = i915_get_gem_seqno(dev);
                DRM_WAKEUP(&dev_priv->irq_queue);
        }

        if (iir & I915_DISPLAY_PIPE_A_EVENT_INTERRUPT) {
                pipea_stats = I915_READ(PIPEASTAT);

                /* The vblank interrupt gets enabled even if we didn't ask for
                   it, so make sure it's shut down again */
                if (!(dev_priv->vblank_pipe & DRM_I915_VBLANK_PIPE_A))
                        pipea_stats &= ~(PIPE_START_VBLANK_INTERRUPT_ENABLE |
                                         PIPE_VBLANK_INTERRUPT_ENABLE);
                else if (pipea_stats & (PIPE_START_VBLANK_INTERRUPT_STATUS|
                                        PIPE_VBLANK_INTERRUPT_STATUS))
                {
                        vblank++;
                        drm_handle_vblank(dev, 0);
                }

                I915_WRITE(PIPEASTAT, pipea_stats);
        }
        if (iir & I915_DISPLAY_PIPE_B_EVENT_INTERRUPT) {
                pipeb_stats = I915_READ(PIPEBSTAT);

                /* The vblank interrupt gets enabled even if we didn't ask for
                   it, so make sure it's shut down again */
                if (!(dev_priv->vblank_pipe & DRM_I915_VBLANK_PIPE_B))
                        pipeb_stats &= ~(PIPE_START_VBLANK_INTERRUPT_ENABLE |
                                         PIPE_VBLANK_INTERRUPT_ENABLE);
                else if (pipeb_stats & (PIPE_START_VBLANK_INTERRUPT_STATUS|
                                        PIPE_VBLANK_INTERRUPT_STATUS))
                {
                        vblank++;
                        drm_handle_vblank(dev, 1);
                }

                I915_WRITE(PIPEBSTAT, pipeb_stats);
        }
       return IRQ_HANDLED;

}

int i915_emit_irq(drm_device_t * dev)
{

	drm_i915_private_t *dev_priv = dev->dev_private;
	RING_LOCALS;

	i915_kernel_lost_context(dev);
	
	dev_priv->counter++;
	if (dev_priv->counter > 0x7FFFFFFFUL)
		dev_priv->counter = 1;
	if (dev_priv->sarea_priv)
		dev_priv->sarea_priv->last_enqueue = dev_priv->counter;

#if defined(__i386)
	if (IS_GM45(dev)) {
		BEGIN_LP_RING(3);
		OUT_RING(MI_STORE_DWORD_INDEX);
		OUT_RING(I915_BREADCRUMB_INDEX << MI_STORE_DWORD_INDEX_SHIFT);
		OUT_RING(dev_priv->counter);
		ADVANCE_LP_RING();

		(void) READ_BREADCRUMB(dev_priv);
		BEGIN_LP_RING(2);
		OUT_RING(0);
		OUT_RING(MI_USER_INTERRUPT);
		ADVANCE_LP_RING();
	} else {
#endif  /* __i386 */
	BEGIN_LP_RING(4);
	OUT_RING(MI_STORE_DWORD_INDEX);
	OUT_RING(I915_BREADCRUMB_INDEX << MI_STORE_DWORD_INDEX_SHIFT);
	OUT_RING(dev_priv->counter);
	OUT_RING(MI_USER_INTERRUPT);
	ADVANCE_LP_RING();
#if defined(__i386)
	}
#endif  /* __i386 */

#if defined(__i386)
	if (IS_I965GM(dev) || IS_IGDNG(dev) || IS_GM45(dev))
#else
	if (IS_I965GM(dev) || IS_IGDNG(dev))
#endif  /* __i386 */
	{
		(void) READ_BREADCRUMB(dev_priv);
		BEGIN_LP_RING(2);
		OUT_RING(0);
		OUT_RING(0);
		ADVANCE_LP_RING();
		(void) READ_BREADCRUMB(dev_priv);
	}

	return dev_priv->counter;
}

void i915_user_irq_on(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	spin_lock(&dev_priv->user_irq_lock);
	if (dev->irq_enabled && (++dev_priv->user_irq_refcount == 1)){
               if (IS_IGDNG(dev))
                       igdng_enable_irq(dev_priv, GT_USER_INTERRUPT, 1);
               else
                       i915_enable_irq(dev_priv, I915_USER_INTERRUPT);
	}
	spin_unlock(&dev_priv->user_irq_lock);

}
		
void i915_user_irq_off(struct drm_device *dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	spin_lock(&dev_priv->user_irq_lock);
	if (dev->irq_enabled && (--dev_priv->user_irq_refcount == 0)) {
               if (IS_IGDNG(dev))
                       igdng_disable_irq(dev_priv, GT_USER_INTERRUPT, 1);
               else
                       i915_disable_irq(dev_priv, I915_USER_INTERRUPT);
	}
	spin_unlock(&dev_priv->user_irq_lock);
}


static int i915_wait_irq(drm_device_t * dev, int irq_nr)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	int ret = 0;
	int wait_time = 0;

	if (!dev_priv) {
		DRM_ERROR("called with no initialization\n");
		return -EINVAL;
	}

waitmore:
	wait_time++;
	if (READ_BREADCRUMB(dev_priv) >= irq_nr) {
		if (dev_priv->sarea_priv) {
			dev_priv->sarea_priv->last_dispatch =
				READ_BREADCRUMB(dev_priv);
		}
		return 0;
	}
	DRM_DEBUG("i915_wait_irq: irq_nr=%d breadcrumb=%d\n", irq_nr, READ_BREADCRUMB(dev_priv));
	i915_user_irq_on(dev);
	DRM_WAIT_ON(ret, &dev_priv->irq_queue, 3 * DRM_HZ,
		    READ_BREADCRUMB(dev_priv) >= irq_nr);
	i915_user_irq_off(dev);

	if (ret == EBUSY) {
		if (wait_time > 5) {
		DRM_DEBUG("%d: EBUSY -- rec: %d emitted: %d\n",
			  ret,
			  READ_BREADCRUMB(dev_priv), (int)dev_priv->counter);
			return ret;
		}
		goto waitmore;
	}

	if (dev_priv->sarea_priv)
		dev_priv->sarea_priv->last_dispatch = READ_BREADCRUMB(dev_priv);

	if (ret == EINTR) {
		if (wait_time > 5) {
			DRM_DEBUG("EINTR wait %d now %d", dev_priv->counter, READ_BREADCRUMB(dev_priv));
			return ret;
		}
		goto waitmore;
	}

	return ret;
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

	spin_lock(&dev->struct_mutex);
	result = i915_emit_irq(dev);
	spin_unlock(&dev->struct_mutex);

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

static void igdng_enable_vblank(struct drm_device *dev, int pipe)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	u32 vblank;

	if (pipe == 0)
		vblank = DE_PIPEA_VBLANK;
	else
		vblank = DE_PIPEB_VBLANK;

	if ((dev_priv->de_irq_enable_reg & vblank) == 0) {
		igdng_enable_irq(dev_priv, vblank, 0);
		dev_priv->de_irq_enable_reg |= vblank;
		I915_WRITE(DEIER, dev_priv->de_irq_enable_reg);
		(void) I915_READ(DEIER);
	}
}

static void igdng_disable_vblank(struct drm_device *dev, int pipe)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	u32 vblank;

	if (pipe == 0)
		vblank = DE_PIPEA_VBLANK;
	else
		vblank = DE_PIPEB_VBLANK;

	if ((dev_priv->de_irq_enable_reg & vblank) != 0) {
		igdng_disable_irq(dev_priv, vblank, 0);
		dev_priv->de_irq_enable_reg &= ~vblank;
		I915_WRITE(DEIER, dev_priv->de_irq_enable_reg);
		(void) I915_READ(DEIER);
	}
}

int i915_enable_vblank(struct drm_device *dev, int pipe)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	int pipeconf_reg = (pipe == 0) ? PIPEACONF : PIPEBCONF;
	u32 pipeconf;

	pipeconf = I915_READ(pipeconf_reg);
	if (!(pipeconf & PIPEACONF_ENABLE))
		return -EINVAL;

	spin_lock_irqsave(&dev_priv->user_irq_lock, irqflags);
	if (IS_IGDNG(dev))
		igdng_enable_vblank(dev, pipe);
	else if (IS_I965G(dev))
		i915_enable_pipestat(dev_priv, pipe,
				     PIPE_START_VBLANK_INTERRUPT_ENABLE);
	else
		i915_enable_pipestat(dev_priv, pipe,
				     PIPE_VBLANK_INTERRUPT_ENABLE);
	spin_unlock_irqrestore(&dev_priv->user_irq_lock, irqflags);

	return 0;
}

void i915_disable_vblank(struct drm_device *dev, int pipe)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;

	spin_lock_irqsave(&dev_priv->user_irq_lock, irqflags);
	if (IS_IGDNG(dev))
		igdng_disable_vblank(dev, pipe);
	else
	i915_disable_pipestat(dev_priv, pipe,
			      PIPE_VBLANK_INTERRUPT_ENABLE |
			      PIPE_START_VBLANK_INTERRUPT_ENABLE);
	spin_unlock_irqrestore(&dev_priv->user_irq_lock, irqflags);
}

/* Set the vblank monitor pipe
 */
/*ARGSUSED*/
int i915_vblank_pipe_set(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_i915_private_t *dev_priv = dev->dev_private;

	if (!dev_priv) {
		DRM_ERROR("called with no initialization\n");
		return (-EINVAL);
	}

	return (0);
}

/*ARGSUSED*/
int i915_vblank_pipe_get(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_i915_private_t *dev_priv = dev->dev_private;
	drm_i915_vblank_pipe_t pipe;

	if (!dev_priv) {
		DRM_ERROR("called with no initialization\n");
		return -EINVAL;
	}

	DRM_COPYFROM_WITH_RETURN(&pipe, (drm_i915_vblank_pipe_t __user *)data, sizeof (pipe));

	pipe.pipe = DRM_I915_VBLANK_PIPE_A | DRM_I915_VBLANK_PIPE_B;

	return 0;
}

/**
 * Schedule buffer swap at given vertical blank.
 */
/*ARGSUSED*/
int i915_vblank_swap(DRM_IOCTL_ARGS)
{
        /* The delayed swap mechanism was fundamentally racy, and has been
        * removed.  The model was that the client requested a delayed flip/swap
        * from the kernel, then waited for vblank before continuing to perform
        * rendering.  The problem was that the kernel might wake the client
        * up before it dispatched the vblank swap (since the lock has to be
        * held while touching the ringbuffer), in which case the client would
        * clear and start the next frame before the swap occurred, and
        * flicker would occur in addition to likely missing the vblank.
        *
        * In the absence of this ioctl, userland falls back to a correct path
        * of waiting for a vblank, then dispatching the swap on its own.
        * Context switching to userland and back is plenty fast enough for
        * meeting the requirements of vblank swapping.
        */
	return -EINVAL;

}

/* drm_dma.h hooks
*/

static void igdng_irq_preinstall(struct drm_device *dev)
{
       drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;

       I915_WRITE(HWSTAM, 0xeffe);

      /* XXX hotplug from PCH */

       I915_WRITE(DEIMR, 0xffffffff);
       I915_WRITE(DEIER, 0x0);
       (void) I915_READ(DEIER);

       /* and GT */
       I915_WRITE(GTIMR, 0xffffffff);
       I915_WRITE(GTIER, 0x0);
       (void) I915_READ(GTIER);
}

static int igdng_irq_postinstall(struct drm_device *dev)
{
       drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
       /* enable kind of interrupts always enabled */
       u32 display_mask = DE_MASTER_IRQ_CONTROL /*| DE_PCH_EVENT */;
       u32 render_mask = GT_USER_INTERRUPT;

       dev_priv->irq_mask_reg = ~display_mask;
       dev_priv->de_irq_enable_reg = display_mask;

       /* should always can generate irq */
       I915_WRITE(DEIIR, I915_READ(DEIIR));
       (void) I915_READ(DEIIR);
       I915_WRITE(DEIMR, dev_priv->irq_mask_reg);
       I915_WRITE(DEIER, dev_priv->de_irq_enable_reg);
       (void) I915_READ(DEIER);

       /* user interrupt should be enabled, but masked initial */
       dev_priv->gt_irq_mask_reg = 0xffffffff;
       dev_priv->gt_irq_enable_reg = render_mask;

       I915_WRITE(GTIIR, I915_READ(GTIIR));
       (void) I915_READ(GTIIR);
       I915_WRITE(GTIMR, dev_priv->gt_irq_mask_reg);
       I915_WRITE(GTIER, dev_priv->gt_irq_enable_reg);
       (void) I915_READ(GTIER);

       return 0;
}

static void igdng_irq_uninstall(struct drm_device *dev)
{
       drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
       I915_WRITE(HWSTAM, 0xffffffff);

       I915_WRITE(DEIMR, 0xffffffff);
       I915_WRITE(DEIER, 0x0);
       I915_WRITE(DEIIR, I915_READ(DEIIR));

       I915_WRITE(GTIMR, 0xffffffff);
       I915_WRITE(GTIER, 0x0);
       I915_WRITE(GTIIR, I915_READ(GTIIR));
}

int i915_driver_irq_preinstall(drm_device_t * dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;

	if (!dev_priv->mmio_map)
		return -EINVAL;

	if (IS_IGDNG(dev)) {
               igdng_irq_preinstall(dev);
               return 0;
	}

	I915_WRITE16(HWSTAM, 0xeffe);
	I915_WRITE(PIPEASTAT, 0);
	I915_WRITE(PIPEBSTAT, 0);
	I915_WRITE(IMR, 0xffffffff);
	I915_WRITE16(IER, 0x0);
	(void) I915_READ(IER);

	return 0;
}

void i915_driver_irq_postinstall(drm_device_t * dev)
{
	int error_mask;
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;

	dev_priv->vblank_pipe = DRM_I915_VBLANK_PIPE_A | DRM_I915_VBLANK_PIPE_B;

	if (IS_IGDNG(dev)) {
		(void) igdng_irq_postinstall(dev);
		DRM_INIT_WAITQUEUE(&dev_priv->irq_queue, DRM_INTR_PRI(dev));
		return;
	}

	/* Unmask the interrupts that we always want on. */
	dev_priv->irq_mask_reg = ~I915_INTERRUPT_ENABLE_FIX;

	dev_priv->pipestat[0] = 0;
	dev_priv->pipestat[1] = 0;

	/*
	 * Enable some error detection, note the instruction error mask
	 * bit is reserved, so we leave it masked.
	 */
	if (IS_G4X(dev)) {
		error_mask = ~(GM45_ERROR_PAGE_TABLE |
			       GM45_ERROR_MEM_PRIV |
			       GM45_ERROR_CP_PRIV |
			       I915_ERROR_MEMORY_REFRESH);
	} else {
		error_mask = ~(I915_ERROR_PAGE_TABLE |
			       I915_ERROR_MEMORY_REFRESH);
	}
	I915_WRITE(EMR, error_mask);

	/* Disable pipe interrupt enables, clear pending pipe status */
	I915_WRITE(PIPEASTAT, I915_READ(PIPEASTAT) & 0x8000ffff);
	I915_WRITE(PIPEBSTAT, I915_READ(PIPEBSTAT) & 0x8000ffff);
	(void) I915_READ(PIPEASTAT);
        (void) I915_READ(PIPEBSTAT);
	/* Clear pending interrupt status */
	I915_WRITE(IIR, I915_READ(IIR));

	(void) I915_READ(IIR);
	I915_WRITE(IMR, dev_priv->irq_mask_reg);
	I915_WRITE(IER, I915_INTERRUPT_ENABLE_MASK);
	(void) I915_READ(IER);

	DRM_INIT_WAITQUEUE(&dev_priv->irq_queue, DRM_INTR_PRI(dev));

	return;
}

void i915_driver_irq_uninstall(drm_device_t * dev)
{
	drm_i915_private_t *dev_priv = (drm_i915_private_t *) dev->dev_private;
	if ((!dev_priv) || (dev->irq_enabled == 0))
		return;

	dev_priv->vblank_pipe = 0;

	if (IS_IGDNG(dev)) {
		igdng_irq_uninstall(dev);
		DRM_FINI_WAITQUEUE(&dev_priv->irq_queue);
		return;
	}

	I915_WRITE(HWSTAM, 0xffffffff);
	I915_WRITE(PIPEASTAT, 0);
	I915_WRITE(PIPEBSTAT, 0);
	I915_WRITE(IMR, 0xffffffff);
	I915_WRITE(IER, 0x0);

	I915_WRITE(PIPEASTAT, I915_READ(PIPEASTAT) & 0x8000ffff);
	I915_WRITE(PIPEBSTAT, I915_READ(PIPEBSTAT) & 0x8000ffff);
	I915_WRITE(IIR, I915_READ(IIR));

	DRM_FINI_WAITQUEUE(&dev_priv->irq_queue);
}
