/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

#include "drmP.h"
#include <sys/gfx_private.h>
#include "drm_io32.h"

#define	DEBUG_SCATTER 0

#ifdef	_LP64
#define	ScatterHandle(x) (unsigned int)((x >> 32) + (x & ((1L << 32) - 1)))
#else
#define	ScatterHandle(x) (unsigned int)(x)
#endif

void
drm_sg_cleanup(drm_device_t *dev, drm_sg_mem_t *entry)
{
	int	pages = entry->pages;

	if (entry->busaddr) {
		kmem_free(entry->busaddr, sizeof (*entry->busaddr) * pages);
		entry->busaddr = NULL;
	}

	ASSERT(entry->umem_cookie == NULL);

	if (entry->dmah_sg) {
		drm_pci_free(dev, entry->dmah_sg);
		entry->dmah_sg = NULL;
	}

	if (entry->dmah_gart) {
		drm_pci_free(dev, entry->dmah_gart);
		entry->dmah_gart = NULL;
	}

	if (entry) {
		drm_free(entry, sizeof (drm_sg_mem_t), DRM_MEM_SGLISTS);
		entry = NULL;
	}
}

/*ARGSUSED*/
int
drm_sg_alloc(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	unsigned long pages;
	drm_sg_mem_t		*entry;
	drm_dma_handle_t	*dmah;
	drm_scatter_gather_t request;

	DRM_DEBUG("%s\n", "drm_sg_alloc");

	if (dev->sg)
		return (EINVAL);

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_scatter_gather_32_t request32;

		DRM_COPYFROM_WITH_RETURN(&request32, (void *)data,
		    sizeof (request32));
		request.size = request32.size;
		request.handle = request32.handle;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&request, (void *)data,
		    sizeof (request));

	pages = btopr(request.size);
	DRM_DEBUG("sg size=%ld pages=%ld\n", request.size, pages);
	entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
	entry->pages = (int)pages;
	dmah = drm_pci_alloc(dev, ptob(pages), 4096, 0xfffffffful, pages);
	if (dmah == NULL)
		goto err_exit;
	entry->busaddr = (void *)kmem_zalloc(sizeof (*entry->busaddr) *
	    pages, KM_SLEEP);

	entry->handle = ScatterHandle((unsigned long)dmah->vaddr);
	entry->virtual = (void *)dmah->vaddr;
	request.handle = entry->handle;
	entry->dmah_sg = dmah;
#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_scatter_gather_32_t data32;

		data32.size = (uint32_t)request.size;
		data32.handle = (uint32_t)request.handle;

		DRM_COPYTO_WITH_RETURN((void *)data, &data32,
		    sizeof (data32));
	} else
#endif
		DRM_COPYTO_WITH_RETURN((void *)data, &request,
		    sizeof (request));

	DRM_LOCK();
	if (dev->sg) {
		DRM_UNLOCK();
		drm_sg_cleanup(dev, entry);
		return (EINVAL);
	}
	dev->sg = entry;
	DRM_UNLOCK();

	return (0);

err_exit:
	drm_sg_cleanup(dev, entry);
	return (ENOMEM);
}

/*ARGSUSED*/
int
drm_sg_free(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_scatter_gather_t request;
	drm_sg_mem_t *entry;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_scatter_gather_32_t request32;

		DRM_COPYFROM_WITH_RETURN(&request32, (void *)data,
		    sizeof (request32));
		request.size = request32.size;
		request.handle = request32.handle;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&request, (void *)data,
		    sizeof (request));

	DRM_LOCK();
	entry = dev->sg;
	dev->sg = NULL;
	DRM_UNLOCK();

	if (!entry || entry->handle != request.handle)
		return (EINVAL);

	drm_sg_cleanup(dev, entry);

	return (0);
}
