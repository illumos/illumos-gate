/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * drm_agpsupport.h -- DRM support for AGP/GART backend -*- linux-c -*-
 * Created: Mon Dec 13 09:56:45 1999 by faith@precisioninsight.com
 */
/*
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
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
 * Author:
 *    Rickard E. (Rik) Faith <faith@valinux.com>
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drm.h"
#include "drmP.h"

#ifndef	AGP_PAGE_SIZE
#define	AGP_PAGE_SIZE 4096
#define	AGP_PAGE_SHIFT 12
#endif

/*ARGSUSED*/
int
drm_device_is_agp(drm_softstate_t *dev)
{
	return (1);
}

/*ARGSUSED*/
int
drm_device_is_pcie(drm_softstate_t *dev)
{
	return (0);
}


/*ARGSUSED*/
int
drm_agp_info(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	agp_info_t agpinf;
	drm_agp_info_t info;
	int ret, rval;

	if (!dev->agp || !dev->agp->acquired)
		return (-1);
	ret = ldi_ioctl(dev->agpgart_hdl, AGPIOC_INFO,
		    (intptr_t)&agpinf, FKIOCTL, kcred,
		    &rval);
	if (ret) {
		DRM_ERROR("drm_agp_info: AGPIOC_INFO failed");
		return (-1);
	}
	dev->agp->agp_info = agpinf;
	info.agp_version_major	= agpinf.agpi_version.agpv_major;
	info.agp_version_minor	= agpinf.agpi_version.agpv_minor;
	info.mode		= agpinf.agpi_mode;
	info.aperture_base	= agpinf.agpi_aperbase;
	info.aperture_size	= agpinf.agpi_apersize;
	info.memory_allowed	= agpinf.agpi_pgtotal;
	info.memory_used	= agpinf.agpi_pgused;
	info.id_vendor		= agpinf.agpi_devid & 0xffff;
	info.id_device		= agpinf.agpi_devid >> 16;

	DRM_COPY_TO_USER_IOCTL((drm_agp_info_t *)data,
		info, sizeof (info));
	return (0);
}

/*ARGSUSED*/
int
drm_agp_acquire(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	int	ret, rval;

	DRM_DEBUG("drm_agp_acquire\n");
	if (!dev->agp) {
		DRM_ERROR(" drm_agp_acquire : dev->agp=NULL");
		return (-1);
	}

	if (ldi_open_by_name(AGP_DEVICE, FEXCL, kcred,
	    &dev->agpgart_hdl, dev->agpgart_li)) {
		DRM_DEBUG("drm_agp_acquired: open /dev/agpgart failed");
		return (DDI_FAILURE);
	}
	ret = ldi_ioctl(dev->agpgart_hdl, AGPIOC_ACQUIRE,
	    (uintptr_t)0, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_acquired: AGPIOC_ACQUIRE failed\n");
		(void) ldi_close(dev->agpgart_hdl, FEXCL, kcred);
		return (DDI_FAILURE);
	}
	DRM_DEBUG("drm_agp_acquired: Acquired\n");
	dev->agp->acquired = 1;

	return (0);
}

/*ARGSUSED*/
int
drm_agp_release(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	int ret;

	ret = drm_agp_do_release(dev);
	return (ret);
}

/*ARGSUSED*/
int
drm_agp_do_release(drm_softstate_t *dev)
{
	int ret, rval;

	if (!dev->agp)
	    return (ENODEV);
	if (!dev->agp->acquired)
	    return (EBUSY);

	if (dev->agpgart_hdl) {
		ret = ldi_ioctl(dev->agpgart_hdl, AGPIOC_RELEASE,
		    (intptr_t)0, FKIOCTL, kcred, &rval);
		if (ret) {
			DRM_ERROR("drm_agp_release: AGPIOC_RELEASE failed\n");
			(void) ldi_close(dev->agpgart_hdl, FEXCL, kcred);
			dev->agpgart_hdl = NULL;
			return (ENXIO);
		}
	}
	(void) ldi_close(dev->agpgart_hdl, FEXCL, kcred);
	dev->agpgart_hdl = NULL;
	dev->agp->acquired = 0;

	return (0);
}

/*ARGSUSED*/
int
drm_agp_enable(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_agp_mode_t modes;
	agp_setup_t setup;
	int ret, rval;

	if (!dev->agp)
	    return (ENODEV);
	if (!dev->agp->acquired)
	    return (EBUSY);

	DRM_COPY_FROM_USER_IOCTL(modes, (drm_agp_mode_t *)data,
	    sizeof (modes));

	dev->agp->mode = modes.mode;
	setup.agps_mode = modes.mode;

	DRM_DEBUG("drm_agp_enable: dev->agp->mode=%lx", modes.mode);

	ret = ldi_ioctl(dev->agpgart_hdl, AGPIOC_SETUP,
		    (intptr_t)&setup, FKIOCTL,
		    kcred, &rval);
	if (ret) {
		DRM_DEBUG("drm_agp_enable: failed");
		return (-1);
	}

	dev->agp->base = dev->agp->agp_info.agpi_aperbase;
	dev->agp->enabled = 1;

	DRM_DEBUG("drm_agp_enable: successful");
	return (0);
}

/*ARGSUSED*/
int
drm_agp_alloc(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_agp_mem_t    	*entry;
	agp_allocate_t		alloc;
	drm_agp_buffer_t	request;
	int pages;
	int ret, rval;

	if (!dev->agp || !dev->agp->acquired)
		return (DRM_ERR(EINVAL));

	DRM_COPY_FROM_USER_IOCTL(request,
	    (drm_agp_buffer_t *)data, sizeof (request));

	if (!(entry = drm_calloc(1, sizeof (*entry), DRM_MEM_AGPLISTS)))
		return (DRM_ERR(ENOMEM));

	alloc.agpa_type = _DRM_AGP_UMEM;
	pages = btopr(request.size);
	alloc.agpa_pgcount = pages;
	ret = ldi_ioctl(dev->agpgart_hdl, AGPIOC_ALLOCATE,
		    (intptr_t)&alloc, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_alloc: AGPIOC_ALLOCATE failed");
		return (DDI_FAILURE);
	}

	entry->bound = 0;
	entry->pages = pages;
	entry->key = (unsigned int)alloc.agpa_key;
	entry->prev = NULL;
	entry->next = dev->agp->memory;
	if (dev->agp->memory)
	    dev->agp->memory->prev = entry;
	dev->agp->memory = entry;

	request.handle = (unsigned long)entry->handle;
	request.physical = alloc.agpa_physical;
	DRM_DEBUG("drm_agp_alloc: virtual address is %lx physical is %lx\n",
	    entry->handle,
	    request.physical);

	/* not used */
	/* dev->agp_umem_kvaddr = (unsigned long)alloc.agpa_kvaddr; */

	DRM_COPY_TO_USER_IOCTL((drm_agp_buffer_t *)data,
	    request, sizeof (request));

	return (0);
}

/*ARGSUSED*/
static drm_agp_mem_t *
drm_agp_lookup_entry(drm_softstate_t *dev, void *handle)
{
	drm_agp_mem_t *entry;

	DRM_DEBUG("drm_agp_lookup_entry");
	for (entry = dev->agp->memory; entry; entry = entry->next) {
		if (entry->handle == handle)
			return (entry);
	}

	return (NULL);
}

/*ARGSUSED*/
int
drm_agp_unbind(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	agp_unbind_t unbind;
	drm_agp_binding_t request;
	drm_agp_mem_t *entry;
	int ret, rval;

	if (!dev->agp || !dev->agp->acquired)
		return (DRM_ERR(EINVAL));
	DRM_COPY_FROM_USER_IOCTL(request,
	    (drm_agp_binding_t *)data, sizeof (request));

	if (!(entry = drm_agp_lookup_entry(dev, (void *)request.handle)))
		return (DRM_ERR(EINVAL));
	if (!entry->bound)
		return (DRM_ERR(EINVAL));

	unbind.agpu_pri = 0;
	unbind.agpu_key = entry->key;

	ret = ldi_ioctl(dev->agpgart_hdl, AGPIOC_UNBIND,
	    (intptr_t)&unbind, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_unbind: AGPIOC_UNBIND failed");
		return (-1);
	}
	entry->bound = 0;
	return (0);
}

/*ARGSUSED*/
int
drm_agp_bind(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_agp_binding_t request;
	drm_agp_mem_t   *entry;
	int page;

	if (!dev->agp || !dev->agp->acquired)
		return (DRM_ERR(EINVAL));

	DRM_COPY_FROM_USER_IOCTL(request,
	    (drm_agp_binding_t *)data, sizeof (request));
	if (!(entry = drm_agp_lookup_entry(dev, (void *)request.handle)))
		return (DRM_ERR(EINVAL));
	if (entry->bound)
		return (DRM_ERR(EINVAL));

	page = btopr(request.offset);
	if ((drm_agp_bind_memory(entry->key, page, dev)) < 0)
		return (-1);
	entry->bound = dev->agp->base + (page << AGP_PAGE_SHIFT);

	DRM_DEBUG("drm_agp_bind: base = 0x%lx, entry->bound = 0x%lx",
	    dev->agp->base, entry->bound);

	return (0);
}

/*ARGSUSED*/
int
drm_agp_free(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_agp_buffer_t request;
	drm_agp_mem_t	*entry;
	int	ret, rval;

	DRM_COPY_FROM_USER_IOCTL(request, (drm_agp_buffer_t *)data,
	    sizeof (request));
	if (!dev->agp || !dev->agp->acquired)
		return (DRM_ERR(EINVAL));
	if (!(entry = drm_agp_lookup_entry(dev, (void *)request.handle)))
		return (DRM_ERR(EINVAL));
	if (entry->bound)
		(void) drm_agp_unbind_memory(request.handle, entry->key, dev);

	if (entry->prev)
		entry->prev->next = entry->next;
	if (entry->next)
		entry->next->prev = entry->prev;

	drm_free(entry, sizeof (*entry), DRM_MEM_AGPLISTS);
	entry = NULL;

	ret = ldi_ioctl(dev->agpgart_hdl, AGPIOC_DEALLOCATE,
		    (intptr_t)&(request.handle), FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_free: AGPIOC_DEALLOCATE failed");
		return (-1);
	}
	return (0);
}

/*ARGSUSED*/
drm_agp_head_t *
drm_agp_init(void)
{
	drm_agp_head_t *head   = NULL;

	DRM_DEBUG("drm_agp_init\n");
	if (!(head = drm_alloc(sizeof (drm_agp_head_t), DRM_MEM_AGPLISTS)))
		return (NULL);
	head->memory = NULL;
	return (head);
error:
	return (NULL);
}

/*ARGSUSED*/
void
drm_agp_uninit(drm_agp_head_t *agp)
{
	drm_free(agp, sizeof (drm_agp_head_t), DRM_MEM_AGPLISTS);
	agp = NULL;
}


/*ARGSUSED*/
void *
drm_agp_allocate_memory(size_t pages, uint32_t type)
{
	return (NULL);
}

/*ARGSUSED*/
int
drm_agp_free_memory(void *handle)
{
	return (1);
}

/*ARGSUSED*/
int
drm_agp_bind_memory(unsigned int key, uint32_t start, drm_device_t *dev)
{
	agp_bind_t bind;
	int	ret, rval;

	DRM_DEBUG("drm_agp_bind_memory");

	bind.agpb_pgstart = start;
	bind.agpb_key = key;
	ret = ldi_ioctl(dev->agpgart_hdl, AGPIOC_BIND,
	    (intptr_t)&bind, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_DEBUG("drm_agp_bind_meory: AGPIOC_BIND failed");
		return (-1);
	}
	return (0);
}

/*ARGSUSED*/
int
drm_agp_unbind_memory(unsigned long handle, uint32_t key, drm_device_t *dev)
{
	agp_unbind_t unbind;
	drm_agp_mem_t   *entry;
	int ret, rval;

	if (!dev->agp || !dev->agp->acquired)
		return (DRM_ERR(EINVAL));

	if (!(entry = drm_agp_lookup_entry(dev, (void *)handle)))
		return (DRM_ERR(EINVAL));
	if (!entry->bound)
		return (DRM_ERR(EINVAL));

	unbind.agpu_pri = 0;
	unbind.agpu_key = entry->key;

	ret = ldi_ioctl(dev->agpgart_hdl, AGPIOC_UNBIND, (intptr_t)&unbind,
	    FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_unbind: AGPIO_UNBIND failed");
		goto error;
	}
	entry->bound = 0;
	return (0);
error:
	return (-1);
}
