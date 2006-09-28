/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* BEGIN CSTYLED */

/* drm_scatter.h -- IOCTLs to manage scatter/gather memory -*- linux-c -*-
 * Created: Mon Dec 18 23:20:54 2000 by gareth@valinux.com */
/*-
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
 * PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Gareth Hughes <gareth@valinux.com>
 *   Eric Anholt <anholt@FreeBSD.org>
 *
 */
/* END CSTYLED */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"

#define	DEBUG_SCATTER 0

void
drm_sg_cleanup(drm_sg_mem_t *entry)
{
	if (entry->busaddr) {
		drm_free(entry->busaddr,
		    entry->pages * sizeof (entry->busaddr),
		    DRM_MEM_PAGES);
		entry->busaddr = NULL;
	}
	if (entry->virtual) {
		ddi_umem_free(entry->sg_umem_cookie);
		entry->virtual = NULL;
	}
	if (entry) {
		drm_free(entry, sizeof (drm_sg_mem_t), DRM_MEM_SGLISTS);
	}

}

/*ARGSUSED*/
int
drm_sg_alloc(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_scatter_gather_t request;
	drm_sg_mem_t *entry;
	unsigned long pages;

	DRM_DEBUG("%s\n", "drm_sg_alloc");

	if (dev->sg)
		return (DRM_ERR(EINVAL));

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_scatter_gather32_t request32;

		DRM_COPY_FROM_USER_IOCTL(request32,
			(drm_scatter_gather32_t *)data,
			sizeof (drm_scatter_gather32_t));
		request.size = request32.size;
		request.handle = request32.handle;
	} else
		DRM_COPY_FROM_USER_IOCTL(request, (drm_scatter_gather_t *)data,
			sizeof (request));

	entry = drm_alloc(sizeof (*entry), DRM_MEM_SGLISTS);
	if (!entry)
		return (DRM_ERR(ENOMEM));

	pages = (request.size + PAGE_SIZE - 1) / PAGE_SIZE;
	DRM_DEBUG("sg size=%ld pages=%ld\n", request.size, pages);

	entry->pages = pages;

	entry->busaddr = drm_alloc(pages * sizeof (*entry->busaddr),
			DRM_MEM_PAGES);

	if (!entry->busaddr) {
		drm_sg_cleanup(entry);
		return (DRM_ERR(ENOMEM));
	}

	(void) memset((void *)entry->busaddr, 0,
	    pages * sizeof (*entry->busaddr));

	entry->virtual = ddi_umem_alloc((size_t)(pages << PAGE_SHIFT),
			DDI_UMEM_SLEEP, &entry->sg_umem_cookie);
	if (!entry->virtual) {
		drm_sg_cleanup(entry);
		return (DRM_ERR(ENOMEM));
	}

	entry->handle = (unsigned long)entry->virtual;

	DRM_DEBUG("drm_sg_alloc: handle  = %08lx\n", entry->handle);
	DRM_DEBUG("drm_sg_alloc: virtual = %p\n", entry->virtual);

	request.handle = entry->handle;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_scatter_gather32_t data32;

		data32.size = request.size;
		data32.handle = request.handle;

		DRM_COPY_TO_USER_IOCTL((drm_scatter_gather32_t *)data,
			data32,	sizeof (drm_scatter_gather32_t));
	} else
		DRM_COPY_TO_USER_IOCTL((drm_scatter_gather_t *)data,
			request,
			sizeof (request));

	DRM_LOCK();
	if (dev->sg) {
		DRM_UNLOCK();
		drm_sg_cleanup(entry);
		return (DRM_ERR(EINVAL));
	}
	dev->sg = entry;
	DRM_UNLOCK();

	return (0);
}

/*ARGSUSED*/
int
drm_sg_free(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_scatter_gather_t request;
	drm_sg_mem_t *entry;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_scatter_gather32_t request32;

		DRM_COPY_FROM_USER_IOCTL(request32,
			(drm_scatter_gather32_t *)data,
			sizeof (drm_scatter_gather32_t));
		request.size = request32.size;
		request.handle = request32.handle;
	} else
		DRM_COPY_FROM_USER_IOCTL(request, (drm_scatter_gather_t *)data,
			sizeof (request));

	DRM_LOCK();
	entry = dev->sg;
	dev->sg = NULL;
	DRM_UNLOCK();

	if (!entry || entry->handle != request.handle)
		return (DRM_ERR(EINVAL));

	DRM_DEBUG("drm_sg_free: virtual  = %p\n", entry->virtual);

	drm_sg_cleanup(entry);

	return (0);
}
