/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * drm_context.h -- IOCTLs for generic contexts -*- linux-c -*-
 * Created: Fri Nov 24 18:31:37 2000 by gareth@valinux.com
 */
/*
 * Copyright 1999, 2000 Precision Insight, Inc., Cedar Park, Texas.
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
 *    Rickard E. (Rik) Faith <faith@valinux.com>
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"
#include "drm_io32.h"

static inline int
find_first_zero_bit(volatile void *p, int max)
{
	int b;
	volatile int *ptr = (volatile int *)p;

	for (b = 0; b < max; b += 32) {
		if (ptr[b >> 5] != ~0) {
			for (;;) {
				if ((ptr[b >> 5] & (1 << (b & 0x1f))) == 0)
					return (b);
				b++;
			}
		}
	}
	return (max);
}

/*
 * Context bitmap support
 */
void
drm_ctxbitmap_free(drm_device_t *dev, int ctx_handle)
{
	if (ctx_handle < 0 || ctx_handle >= DRM_MAX_CTXBITMAP ||
	    dev->ctx_bitmap == NULL) {
		DRM_ERROR("drm_ctxbitmap_free: Attempt to free\
		    invalid context handle: %d\n",
		    ctx_handle);
		return;
	}

	DRM_LOCK();
	clear_bit(ctx_handle, dev->ctx_bitmap);
	dev->context_sareas[ctx_handle] = NULL;
	DRM_UNLOCK();
}

/* Is supposed to return -1 if  any error by calling functions */
int
drm_ctxbitmap_next(drm_device_t *dev)
{
	int bit;

	if (dev->ctx_bitmap == NULL)
		return (-1);

	DRM_LOCK();
	bit = find_first_zero_bit(dev->ctx_bitmap, DRM_MAX_CTXBITMAP);
	if (bit >= DRM_MAX_CTXBITMAP) {
		DRM_UNLOCK();
		return (-1);
	}

	set_bit(bit, dev->ctx_bitmap);
	DRM_DEBUG("drm_ctxbitmap_next: bit : %d", bit);
	if ((bit+1) > dev->max_context) {
		dev->max_context = (bit+1);
		if (dev->context_sareas != NULL) {
			drm_local_map_t **ctx_sareas;
			ctx_sareas = drm_realloc(dev->context_sareas,
			    (dev->max_context - 1) *
			    sizeof (*dev->context_sareas),
			    dev->max_context *
			    sizeof (*dev->context_sareas),
			    DRM_MEM_MAPS);
			if (ctx_sareas == NULL) {
				clear_bit(bit, dev->ctx_bitmap);
				DRM_UNLOCK();
				return (-1);
			}
			dev->context_sareas = ctx_sareas;
			dev->context_sareas[bit] = NULL;
		} else {
			/* max_context == 1 at this point */
			dev->context_sareas = drm_alloc(dev->max_context *
			    sizeof (*dev->context_sareas), KM_NOSLEEP);
			if (dev->context_sareas == NULL) {
				clear_bit(bit, dev->ctx_bitmap);
				DRM_UNLOCK();
				return (-1);
			}
			dev->context_sareas[bit] = NULL;
		}
	}
	DRM_UNLOCK();
	DRM_DEBUG("drm_ctxbitmap_next: return %d", bit);
	return (bit);
}

int
drm_ctxbitmap_init(drm_device_t *dev)
{
	int i;
	int temp;

	DRM_LOCK();
	dev->ctx_bitmap = drm_calloc(1, DRM_PAGE_SIZE, DRM_MEM_CTXBITMAP);
	if (dev->ctx_bitmap == NULL) {
		DRM_UNLOCK();
		return (ENOMEM);
	}
	dev->context_sareas = NULL;
	dev->max_context = -1;
	DRM_UNLOCK();

	for (i = 0; i < DRM_RESERVED_CONTEXTS; i++) {
		temp = drm_ctxbitmap_next(dev);
		DRM_DEBUG("drm_ctxbitmap_init : %d", temp);
	}
	return (0);
}

void
drm_ctxbitmap_cleanup(drm_device_t *dev)
{
	DRM_LOCK();
	if (dev->context_sareas != NULL)
		drm_free(dev->context_sareas,
		    sizeof (*dev->context_sareas) *
		    dev->max_context,
		    DRM_MEM_MAPS);
	drm_free(dev->ctx_bitmap, DRM_PAGE_SIZE, DRM_MEM_CTXBITMAP);
	DRM_UNLOCK();
}

/*
 * Per Context SAREA Support
 */
/*ARGSUSED*/
int
drm_getsareactx(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_ctx_priv_map_t request;
	drm_local_map_t *map;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_ctx_priv_map_32_t request32;
		DRM_COPYFROM_WITH_RETURN(&request32, (void *)data,
		    sizeof (drm_ctx_priv_map_32_t));
		request.ctx_id = request32.ctx_id;
		request.handle = (void *)(uintptr_t)request32.handle;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&request, (void *)data,
		    sizeof (request));

	DRM_LOCK();
	if (dev->max_context < 0 || request.ctx_id >= (unsigned)
	    dev->max_context) {
		DRM_UNLOCK();
		return (EINVAL);
	}

	map = dev->context_sareas[request.ctx_id];
	DRM_UNLOCK();

	if (!map)
		return (EINVAL);

	request.handle = map->handle;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_ctx_priv_map_32_t request32;
		request32.ctx_id = request.ctx_id;
		request32.handle = (caddr32_t)(uintptr_t)request.handle;
		DRM_COPYTO_WITH_RETURN((void *)data, &request32,
		    sizeof (drm_ctx_priv_map_32_t));
	} else
#endif
		DRM_COPYTO_WITH_RETURN((void *)data,
		    &request, sizeof (request));

	return (0);
}

/*ARGSUSED*/
int
drm_setsareactx(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_ctx_priv_map_t request;
	drm_local_map_t *map = NULL;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_ctx_priv_map_32_t request32;

		DRM_COPYFROM_WITH_RETURN(&request32, (void *)data,
		    sizeof (drm_ctx_priv_map_32_t));
		request.ctx_id = request32.ctx_id;
		request.handle = (void *)(uintptr_t)request32.handle;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&request,
		    (void *)data, sizeof (request));

	DRM_LOCK();
	TAILQ_FOREACH(map, &dev->maplist, link) {
		if (map->handle == request.handle) {
			if (dev->max_context < 0)
				goto bad;
			if (request.ctx_id >= (unsigned)dev->max_context)
				goto bad;
			dev->context_sareas[request.ctx_id] = map;
			DRM_UNLOCK();
			return (0);
		}
	}

bad:
	DRM_UNLOCK();
	return (EINVAL);
}

/*
 * The actual DRM context handling routines
 */
int
drm_context_switch(drm_device_t *dev, int old, int new)
{
	if (test_and_set_bit(0, &dev->context_flag)) {
		DRM_ERROR("drm_context_switch: Reentering -- FIXME");
		return (EBUSY);
	}

	DRM_DEBUG("drm_context_switch: Context switch from %d to %d",
	    old, new);

	if (new == dev->last_context) {
		clear_bit(0, &dev->context_flag);
		return (0);
	}

	return (0);
}

int
drm_context_switch_complete(drm_device_t *dev, int new)
{
	dev->last_context = new;  /* PRE/POST: This is the _only_ writer. */

	if (!_DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock)) {
		DRM_ERROR(
		    "drm_context_switch_complete: Lock not held");
	}
	/*
	 * If a context switch is ever initiated
	 * when the kernel holds the lock, release
	 * that lock here.
	 */
	clear_bit(0, &dev->context_flag);

	return (0);
}

/*ARGSUSED*/
int
drm_resctx(DRM_IOCTL_ARGS)
{
	drm_ctx_res_t res;
	drm_ctx_t ctx;
	int i;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_ctx_res_32_t res32;
		DRM_COPYFROM_WITH_RETURN(&res32, (void *)data, sizeof (res32));
		res.count = res32.count;
		res.contexts = (drm_ctx_t *)(uintptr_t)res32.contexts;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&res, (void *)data, sizeof (res));

	if (res.count >= DRM_RESERVED_CONTEXTS) {
		bzero(&ctx, sizeof (ctx));
		for (i = 0; i < DRM_RESERVED_CONTEXTS; i++) {
			ctx.handle = i;
			DRM_COPYTO_WITH_RETURN(&res.contexts[i],
			    &ctx, sizeof (ctx));
		}
	}
	res.count = DRM_RESERVED_CONTEXTS;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_ctx_res_32_t res32;
		res32.count = res.count;
		res32.contexts = (caddr32_t)(uintptr_t)res.contexts;

		DRM_COPYTO_WITH_RETURN((void *)data, &res32,
		    sizeof (drm_ctx_res_32_t));
	} else
#endif
		DRM_COPYTO_WITH_RETURN((void *)data, &res, sizeof (res));

	return (0);
}

/*ARGSUSED*/
int
drm_addctx(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_ctx_t ctx;

	DRM_COPYFROM_WITH_RETURN(&ctx, (void *)data, sizeof (ctx));

	ctx.handle = drm_ctxbitmap_next(dev);
	if (ctx.handle == DRM_KERNEL_CONTEXT) {
		/* Skip kernel's context and get a new one. */
		ctx.handle = drm_ctxbitmap_next(dev);
	}
	if (ctx.handle == (drm_context_t)-1) {
		return (ENOMEM);
	}

	if (dev->driver->context_ctor && ctx.handle != DRM_KERNEL_CONTEXT) {
		dev->driver->context_ctor(dev, ctx.handle);
	}

	DRM_COPYTO_WITH_RETURN((void *)data, &ctx, sizeof (ctx));

	return (0);
}

/*ARGSUSED*/
int
drm_modctx(DRM_IOCTL_ARGS)
{
	/* This does nothing */
	return (0);
}

/*ARGSUSED*/
int
drm_getctx(DRM_IOCTL_ARGS)
{
	drm_ctx_t ctx;

	DRM_COPYFROM_WITH_RETURN(&ctx, (void *)data, sizeof (ctx));

	/* This is 0, because we don't handle any context flags */
	ctx.flags = 0;

	DRM_COPYTO_WITH_RETURN((void *)data, &ctx, sizeof (ctx));

	return (0);
}

/*ARGSUSED*/
int
drm_switchctx(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_ctx_t ctx;

	DRM_COPYFROM_WITH_RETURN(&ctx, (void *)data, sizeof (ctx));

	DRM_DEBUG("drm_switchctx: %d", ctx.handle);
	return (drm_context_switch(dev, dev->last_context, ctx.handle));
}

/*ARGSUSED*/
int
drm_newctx(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_ctx_t ctx;

	DRM_COPYFROM_WITH_RETURN(&ctx, (void *)data, sizeof (ctx));

	DRM_DEBUG("drm_newctx: %d", ctx.handle);
	(void) drm_context_switch_complete(dev, ctx.handle);

	return (0);
}

/*ARGSUSED*/
int
drm_rmctx(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_ctx_t ctx;

	DRM_COPYFROM_WITH_RETURN(&ctx, (void *)data, sizeof (ctx));

	DRM_DEBUG("drm_rmctx : %d", ctx.handle);
	if (ctx.handle != DRM_KERNEL_CONTEXT) {
		if (dev->driver->context_dtor) {
			DRM_LOCK();
			dev->driver->context_dtor(dev, ctx.handle);
			DRM_UNLOCK();
		}

		drm_ctxbitmap_free(dev, ctx.handle);
	}

	return (0);
}
