/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * The agpa_key field of struct agp_allocate_t actually is
 * an index to an array. It can be zero. But we will use
 * this agpa_key as a handle returned to userland. Generally,
 * 0 is not a valid value for a handle, so we add an offset
 * to the key to get a handle.
 */
#define	DRM_AGP_KEY_OFFSET	8

extern int drm_supp_device_capability(void *handle, int capid);

/*ARGSUSED*/
int
drm_device_is_agp(drm_device_t *dev)
{
	int ret;

	if (dev->driver->device_is_agp != NULL) {
		/*
		 * device_is_agp returns a tristate:
		 * 	0 = not AGP;
		 * 	1 = definitely AGP;
		 * 	2 = fall back to PCI capability
		 */
		ret = (*dev->driver->device_is_agp)(dev);
		if (ret != DRM_MIGHT_BE_AGP)
			return (ret);
	}

	return (drm_supp_device_capability(dev->drm_handle, PCIY_AGP));

}

/*ARGSUSED*/
int
drm_device_is_pcie(drm_device_t *dev)
{
	return (drm_supp_device_capability(dev->drm_handle, PCIY_EXPRESS));
}


/*ARGSUSED*/
int
drm_agp_info(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	agp_info_t		*agpinfo;
	drm_agp_info_t		info;

	if (!dev->agp || !dev->agp->acquired)
		return (EINVAL);

	agpinfo = &dev->agp->agp_info;
	info.agp_version_major	= agpinfo->agpi_version.agpv_major;
	info.agp_version_minor	= agpinfo->agpi_version.agpv_minor;
	info.mode		= agpinfo->agpi_mode;
	info.aperture_base	= agpinfo->agpi_aperbase;
	info.aperture_size	= agpinfo->agpi_apersize* 1024 * 1024;
	info.memory_allowed	= agpinfo->agpi_pgtotal << PAGE_SHIFT;
	info.memory_used	= agpinfo->agpi_pgused << PAGE_SHIFT;
	info.id_vendor		= agpinfo->agpi_devid & 0xffff;
	info.id_device		= agpinfo->agpi_devid >> 16;

	DRM_COPYTO_WITH_RETURN((void *)data, &info, sizeof (info));
	return (0);
}

/*ARGSUSED*/
int
drm_agp_acquire(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	int	ret, rval;

	if (!dev->agp) {
		DRM_ERROR("drm_agp_acquire : agp isn't initialized yet");
		return (ENODEV);
	}
	ret = ldi_ioctl(dev->agp->agpgart_lh, AGPIOC_ACQUIRE,
	    (uintptr_t)0, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_acquired: AGPIOC_ACQUIRE failed\n");
		return (EIO);
	}
	dev->agp->acquired = 1;

	return (0);
}

/*ARGSUSED*/
int
drm_agp_release(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	int ret, rval;

	if (!dev->agp)
		return (ENODEV);
	if (!dev->agp->acquired)
		return (EBUSY);

	ret = ldi_ioctl(dev->agp->agpgart_lh, AGPIOC_RELEASE,
	    (intptr_t)0, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_release: AGPIOC_RELEASE failed\n");
		return (ENXIO);
	}
	dev->agp->acquired = 0;

	return (ret);
}


int
drm_agp_do_release(drm_device_t *dev)
{
	int ret, rval;

	ret = ldi_ioctl(dev->agp->agpgart_lh, AGPIOC_RELEASE,
	    (intptr_t)0, FKIOCTL, kcred, &rval);

	if (ret == 0)
		dev->agp->acquired = 0;

	return (ret);
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

	DRM_COPYFROM_WITH_RETURN(&modes, (void *)data, sizeof (modes));

	dev->agp->mode = modes.mode;
	setup.agps_mode = (uint32_t)modes.mode;

	DRM_DEBUG("drm_agp_enable: dev->agp->mode=%lx", modes.mode);

	ret = ldi_ioctl(dev->agp->agpgart_lh, AGPIOC_SETUP,
	    (intptr_t)&setup, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_enable: failed");
		return (EIO);
	}

	dev->agp->base = dev->agp->agp_info.agpi_aperbase;
	dev->agp->enabled = 1;

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
		return (EINVAL);

	DRM_COPYFROM_WITH_RETURN(&request, (void *)data, sizeof (request));

	entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);

	pages = btopr(request.size);
	alloc.agpa_pgcount = pages;
	alloc.agpa_type = AGP_NORMAL;
	ret = ldi_ioctl(dev->agp->agpgart_lh, AGPIOC_ALLOCATE,
	    (intptr_t)&alloc, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_alloc: AGPIOC_ALLOCATE failed, ret=%d", ret);
		kmem_free(entry, sizeof (*entry));
		return (ret);
	}

	entry->bound = 0;
	entry->pages = pages;
	entry->handle = (void*)(uintptr_t)(alloc.agpa_key + DRM_AGP_KEY_OFFSET);
	entry->prev = NULL;
	entry->phys_addr = (void*)(uintptr_t)alloc.agpa_physical;
	entry->next = dev->agp->memory;
	if (dev->agp->memory)
		dev->agp->memory->prev = entry;
	dev->agp->memory = entry;

	/* physical is used only by i810 driver */
	request.physical = alloc.agpa_physical;
	request.handle = (unsigned long)entry->handle;

	/*
	 * If failed to ddi_copyout(), we will free allocated AGP memory
	 * when closing drm
	 */
	DRM_COPYTO_WITH_RETURN((void *)data, &request, sizeof (request));

	return (0);
}

/*ARGSUSED*/
static drm_agp_mem_t *
drm_agp_lookup_entry(drm_device_t *dev, void *handle)
{
	drm_agp_mem_t *entry;

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
		return (EINVAL);

	DRM_COPYFROM_WITH_RETURN(&request, (void *)data, sizeof (request));

	if (!(entry = drm_agp_lookup_entry(dev, (void *)request.handle)))
		return (EINVAL);
	if (!entry->bound)
		return (EINVAL);

	unbind.agpu_pri = 0;
	unbind.agpu_key = (uintptr_t)entry->handle - DRM_AGP_KEY_OFFSET;

	ret = ldi_ioctl(dev->agp->agpgart_lh, AGPIOC_UNBIND,
	    (intptr_t)&unbind, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_unbind: AGPIOC_UNBIND failed");
		return (EIO);
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
	int			start;
	uint_t		key;

	if (!dev->agp || !dev->agp->acquired)
		return (EINVAL);

	DRM_COPYFROM_WITH_RETURN(&request, (void *)data, sizeof (request));

	entry = drm_agp_lookup_entry(dev, (void *)request.handle);
	if (!entry || entry->bound)
		return (EINVAL);

	key = (uintptr_t)entry->handle - DRM_AGP_KEY_OFFSET;
	start = btopr(request.offset);
	if (drm_agp_bind_memory(key, start, dev)) {
		DRM_ERROR("drm_agp_bind: failed key=%x, start=0x%x, "
		    "agp_base=0x%lx", key, start, dev->agp->base);
		return (EIO);
	}

	entry->bound = dev->agp->base + (start << AGP_PAGE_SHIFT);

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
	int	agpu_key;

	DRM_COPYFROM_WITH_RETURN(&request, (void *)data, sizeof (request));
	if (!dev->agp || !dev->agp->acquired)
		return (EINVAL);
	if (!(entry = drm_agp_lookup_entry(dev, (void *)request.handle)))
		return (EINVAL);
	if (entry->bound)
		(void) drm_agp_unbind_memory(request.handle, dev);

	if (entry == dev->agp->memory)
		dev->agp->memory = entry->next;
	if (entry->prev)
		entry->prev->next = entry->next;
	if (entry->next)
		entry->next->prev = entry->prev;

	agpu_key = (uintptr_t)entry->handle - DRM_AGP_KEY_OFFSET;
	ret = ldi_ioctl(dev->agp->agpgart_lh, AGPIOC_DEALLOCATE,
	    (intptr_t)agpu_key, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_free: AGPIOC_DEALLOCATE failed,"
		    "akey=%d, ret=%d", agpu_key, ret);
		return (EIO);
	}
	drm_free(entry, sizeof (*entry), DRM_MEM_AGPLISTS);
	return (0);
}

/*ARGSUSED*/
drm_agp_head_t *
drm_agp_init(drm_device_t *dev)
{
	drm_agp_head_t *agp   = NULL;
	int	retval, rval;

	DRM_DEBUG("drm_agp_init\n");
	agp = kmem_zalloc(sizeof (drm_agp_head_t), KM_SLEEP);

	retval = ldi_ident_from_dip(dev->dip, &agp->agpgart_li);
	if (retval != 0) {
		DRM_ERROR("drm_agp_init: failed to get layerd ident, retval=%d",
		    retval);
		goto err_1;
	}

	retval = ldi_open_by_name(AGP_DEVICE, FEXCL, kcred,
	    &agp->agpgart_lh, agp->agpgart_li);
	if (retval != 0) {
		DRM_ERROR("drm_agp_init: failed to open %s, retval=%d",
		    AGP_DEVICE, retval);
		goto err_2;
	}

	retval = ldi_ioctl(agp->agpgart_lh, AGPIOC_INFO,
	    (intptr_t)&agp->agp_info, FKIOCTL, kcred, &rval);

	if (retval != 0) {
		DRM_ERROR("drm_agp_init: failed to get agpinfo, retval=%d",
		    retval);
		goto err_3;
	}

	return (agp);

err_3:
	(void) ldi_close(agp->agpgart_lh, FEXCL, kcred);

err_2:
	ldi_ident_release(agp->agpgart_li);

err_1:
	kmem_free(agp, sizeof (drm_agp_head_t));
	return (NULL);
}

/*ARGSUSED*/
void
drm_agp_fini(drm_device_t *dev)
{
	drm_agp_head_t *agp = dev->agp;
	(void) ldi_close(agp->agpgart_lh, FEXCL, kcred);
	ldi_ident_release(agp->agpgart_li);
	kmem_free(agp, sizeof (drm_agp_head_t));
	dev->agp = NULL;
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

	bind.agpb_pgstart = start;
	bind.agpb_key = key;
	ret = ldi_ioctl(dev->agp->agpgart_lh, AGPIOC_BIND,
	    (intptr_t)&bind, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_DEBUG("drm_agp_bind_meory: AGPIOC_BIND failed");
		return (EIO);
	}
	return (0);
}

/*ARGSUSED*/
int
drm_agp_unbind_memory(unsigned long handle, drm_device_t *dev)
{
	agp_unbind_t unbind;
	drm_agp_mem_t   *entry;
	int ret, rval;

	if (!dev->agp || !dev->agp->acquired)
		return (EINVAL);

	entry = drm_agp_lookup_entry(dev, (void *)handle);
	if (!entry || !entry->bound)
		return (EINVAL);

	unbind.agpu_pri = 0;
	unbind.agpu_key = (uintptr_t)entry->handle - DRM_AGP_KEY_OFFSET;

	ret = ldi_ioctl(dev->agp->agpgart_lh, AGPIOC_UNBIND,
	    (intptr_t)&unbind, FKIOCTL, kcred, &rval);
	if (ret) {
		DRM_ERROR("drm_agp_unbind: AGPIO_UNBIND failed");
		return (EIO);
	}
	entry->bound = 0;
	return (0);
}
